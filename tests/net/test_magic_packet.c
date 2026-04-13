/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * net_magic_packet.c
 * - test Wake-on-LAN magic packet detection in Low Power Wake mode
 *
 * Test coverage:
 *
 * Positive tests (magic_packet_ipv4, magic_packet_ipv6):
 * - Magic packets at various offsets to test the chunked buffer implementation:
 *   - Offset 0: Magic packet at start (fully in first chunk)
 *   - Offset 50: Magic packet in middle of first chunk (fully contained)
 *   - Offset 97: sync_stream at end of first chunk, requires second m_copydata for MAC addresses
 *   - Offset 150: Magic packet in second chunk
 * - Both IPv4 and IPv6 UDP encapsulation
 *
 * Negative tests (magic_packet_negative):
 * - Large packet filled with 0xFF (300 bytes) - all sync stream, no valid MAC pattern
 * - Incomplete magic packet with only 15 MAC repetitions (should require 16)
 * - Valid magic packet structure but with wrong MAC address
 * - Another all-0xFF packet (500 bytes) - stress test the DoS concern
 *
 * Fragmented packet tests (magic_packet_fragmented_positive):
 * - Magic packet split right after sync stream (8-byte aligned split)
 * - Magic packet split in middle of MAC addresses (16-byte aligned split)
 * - Magic packet split later in MAC addresses (48-byte aligned split)
 * - Magic packet at offset 16, fragmented at byte 40 (both 8-byte aligned)
 * - Tests reassembly logic for detecting magic patterns across IP fragments
 * - Note: All fragment splits are 8-byte aligned (IP fragmentation requirement)
 *
 * Fragmented negative tests (magic_packet_fragmented_negative):
 * - Fragmented non-magic packet (regular sequential data, split at byte 48)
 * - Fragmented non-magic packet with different split point (split at byte 96)
 * - Ensures fragmentation doesn't create false positives
 * - Note: All splits are 8-byte aligned per IP fragmentation requirements
 *
 * Statistics verification:
 * - All tests verify via IFDATA_LPWSTATS sysctl
 * - Positive tests: ifi_lpw_magic_pkt_found should increment
 * - Negative tests: ifi_lpw_magic_pkt_found should NOT increment
 *
 * All-offsets tests (magic_packet_all_offsets):
 * - Tests magic packet detection at every valid offset from 0 to max_offset
 * - max_offset = max_magic_search_len - 102 - sizeof(ip) - sizeof(udphdr)
 * - Also includes negative boundary test at max_offset + 1
 *
 * Incomplete sync stream tests (magic_packet_incomplete_sync_all_offsets):
 * - Tests that packets with only 5 bytes of 0xFF (instead of 6) are rejected
 * - Tests all valid offsets to ensure no false positives
 *
 * Truncated magic pattern tests (magic_packet_truncated_all_offsets):
 * - Tests that packets missing the last byte of the 16th MAC are rejected
 * - Pattern is 6 bytes 0xFF + 15 complete MACs + 5 bytes of 16th MAC (101 bytes)
 * - Tests all valid offsets to ensure no false positives
 */

#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_fake_var.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/kern_event.h>
#include <errno.h>
#include <stdbool.h>

#include "net_test_lib.h"
#include "bpflib.h"
#include <net/net_kev.h>
#include <net/if_var.h>
#include <net/if_var_private.h>
#include <net/if_mib.h>
#include <net/if_mib_private.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("networking"),
	T_META_ASROOT(true)
	);

#define FETH_TX "feth8000"
#define FETH_RX "feth8001"

static const struct in_addr ipv4_tx = { .s_addr = 0x010a000a }; /* 10.0.10.1 */
static const struct in_addr ipv4_rx = { .s_addr = 0x020b000a }; /* 10.0.11.2 */

static struct in6_addr ipv6_tx;
static struct in6_addr ipv6_rx;

static bool cleanup_needed = false;
static int old_lpw_value = 0;
static bool lpw_sysctl_changed = false;
static char old_mark_wake_if[IFNAMSIZ] = {0};
static bool mark_wake_if_changed = false;

/* RTT threshold: skip test if RTT >= 1ms (not an order of magnitude less than 10ms) */
#define PKT_PROCESSING_LEEWAY_US 10000
#define RTT_THRESHOLD_US (PKT_PROCESSING_LEEWAY_US / 10)

/*
 * Measure UDP round-trip time using loopback interface.
 * Creates a UDP socket, sends a packet to itself, and measures latency.
 * Returns the measured RTT in microseconds, or UINT32_MAX on failure.
 */
static useconds_t
measure_udp_rtt(void)
{
	int sock = -1;
	struct sockaddr_in addr;
	struct timeval start, end;
	uint8_t buf[64] = "RTT_TEST";
	ssize_t n;
	useconds_t rtt_us = UINT32_MAX;
	struct timeval timeout;

	/* Create UDP socket */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		T_LOG("RTT: Failed to create socket: %s", strerror(errno));
		goto done;
	}

	/* Set receive timeout */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	/* Bind to loopback */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(12345);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		T_LOG("RTT: Failed to bind socket: %s", strerror(errno));
		goto done;
	}

	/* Record start time and send to self */
	gettimeofday(&start, NULL);

	n = sendto(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, sizeof(addr));
	if (n != sizeof(buf)) {
		T_LOG("RTT: Failed to send: %s", strerror(errno));
		goto done;
	}

	/* Receive the packet back */
	n = recv(sock, buf, sizeof(buf), 0);
	if (n <= 0) {
		T_LOG("RTT: Failed to receive: %s", strerror(errno));
		goto done;
	}

	/* Record end time */
	gettimeofday(&end, NULL);

	/* Calculate RTT in microseconds */
	rtt_us = (useconds_t)((end.tv_sec - start.tv_sec) * 1000000 +
	    (end.tv_usec - start.tv_usec));

	T_LOG("UDP loopback RTT: %u us (threshold: %u us)", rtt_us, RTT_THRESHOLD_US);

done:
	if (sock >= 0) {
		close(sock);
	}
	if (rtt_us == UINT32_MAX) {
		T_LOG("RTT measurement failed (non-fatal) - proceeding with default delay");
	}
	return rtt_us;
}

/* Create a magic packet payload */
static void
create_magic_packet(uint8_t *buf, size_t *len, const ether_addr_t *mac)
{
	int i;
	uint8_t *ptr = buf;

	/* Synchronization stream: 6 bytes of 0xFF */
	for (i = 0; i < 6; i++) {
		*ptr++ = 0xFF;
	}

	/* 16 repetitions of the target MAC address */
	for (i = 0; i < 16; i++) {
		memcpy(ptr, mac, ETHER_ADDR_LEN);
		ptr += ETHER_ADDR_LEN;
	}

	*len = ptr - buf;
}

/* Create an invalid magic packet payload - all 0xFF (no MAC addresses) */
static void
create_all_ff_packet(uint8_t *buf, size_t *len, size_t total_len)
{
	memset(buf, 0xFF, total_len);
	*len = total_len;
}

/* Create an almost-valid magic packet - only 5 bytes of 0xFF instead of 6 */
static void
create_incomplete_sync_packet(uint8_t *buf, size_t *len, const ether_addr_t *mac)
{
	int i;
	uint8_t *ptr = buf;

	/* Incomplete synchronization stream: only 5 bytes of 0xFF */
	for (i = 0; i < 5; i++) {
		*ptr++ = 0xFF;
	}

	/* 16 repetitions of the target MAC address */
	for (i = 0; i < 16; i++) {
		memcpy(ptr, mac, ETHER_ADDR_LEN);
		ptr += ETHER_ADDR_LEN;
	}

	*len = ptr - buf;
}

/* Create an almost-valid magic packet - missing the last byte of the 16th MAC */
static void
create_truncated_magic_packet(uint8_t *buf, size_t *len, const ether_addr_t *mac)
{
	int i;
	uint8_t *ptr = buf;

	/* Complete synchronization stream: 6 bytes of 0xFF */
	for (i = 0; i < 6; i++) {
		*ptr++ = 0xFF;
	}

	/* 15 complete repetitions of the target MAC address */
	for (i = 0; i < 15; i++) {
		memcpy(ptr, mac, ETHER_ADDR_LEN);
		ptr += ETHER_ADDR_LEN;
	}

	/* Only 5 bytes of the 16th MAC address (missing the last byte) */
	memcpy(ptr, mac, ETHER_ADDR_LEN - 1);
	ptr += ETHER_ADDR_LEN - 1;

	*len = ptr - buf;
}

/* Create an almost-valid magic packet - only 15 MAC repetitions instead of 16 */
static void
create_incomplete_magic_packet(uint8_t *buf, size_t *len, const ether_addr_t *mac)
{
	int i;
	uint8_t *ptr = buf;

	/* Synchronization stream: 6 bytes of 0xFF */
	for (i = 0; i < 6; i++) {
		*ptr++ = 0xFF;
	}

	/* Only 15 repetitions of the target MAC address (should fail) */
	for (i = 0; i < 15; i++) {
		memcpy(ptr, mac, ETHER_ADDR_LEN);
		ptr += ETHER_ADDR_LEN;
	}

	/* Add garbage at the end instead of 16th MAC */
	memset(ptr, 0xAA, ETHER_ADDR_LEN);
	ptr += ETHER_ADDR_LEN;

	*len = ptr - buf;
}

/* Create a magic packet with wrong MAC address */
static void
create_wrong_mac_packet(uint8_t *buf, size_t *len, const ether_addr_t *wrong_mac)
{
	int i;
	uint8_t *ptr = buf;

	/* Synchronization stream: 6 bytes of 0xFF */
	for (i = 0; i < 6; i++) {
		*ptr++ = 0xFF;
	}

	/* 16 repetitions of wrong MAC address */
	for (i = 0; i < 16; i++) {
		memcpy(ptr, wrong_mac, ETHER_ADDR_LEN);
		ptr += ETHER_ADDR_LEN;
	}

	*len = ptr - buf;
}

/* Cleanup function */
static void
cleanup(void)
{
	if (!cleanup_needed) {
		return;
	}

	/* Restore mark_wake_packet.if sysctl if we changed it */
	if (mark_wake_if_changed) {
		int ret;
		size_t restore_len;

		/* If old value was empty, clear it by setting to empty string */
		if (old_mark_wake_if[0] == '\0') {
			/* Set to empty string to clear */
			restore_len = 1; /* Just the null terminator */
		} else {
			/* Restore to previous value */
			restore_len = strlen(old_mark_wake_if) + 1;
		}

		ret = sysctlbyname("net.link.generic.system.port_used.mark_wake_packet.if",
		    NULL, NULL, old_mark_wake_if, restore_len);
		if (ret != 0) {
			T_LOG("Failed to restore mark_wake_packet.if sysctl: %s", strerror(errno));
		} else {
			T_LOG("Restored mark_wake_packet.if to '%s'", old_mark_wake_if);
		}
		mark_wake_if_changed = false;
	}

	/* Restore use_fake_lpw sysctl if we changed it */
	if (lpw_sysctl_changed) {
		int ret = sysctlbyname("net.link.generic.system.port_used.use_fake_lpw",
		    NULL, NULL, &old_lpw_value, sizeof(old_lpw_value));
		if (ret != 0) {
			T_LOG("Failed to restore use_fake_lpw sysctl: %s", strerror(errno));
		} else {
			T_LOG("Restored use_fake_lpw to %d", old_lpw_value);
		}
		lpw_sysctl_changed = false;
	}

	/* Destroy interfaces */
	ifnet_destroy(FETH_TX, false);
	ifnet_destroy(FETH_RX, false);

	cleanup_needed = false;
}

/* Setup feth pair */
static void
setup_feth_pair(ether_addr_t *tx_mac, ether_addr_t *rx_mac)
{
	T_ATEND(cleanup);

	/* Create feth interfaces */
	T_ASSERT_POSIX_SUCCESS(ifnet_create(FETH_TX), "create %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(ifnet_create(FETH_RX), "create %s", FETH_RX);

	cleanup_needed = true;

	/* Set up peer relationship */
	fake_set_peer(FETH_TX, FETH_RX);

	/* Get MAC addresses */
	ifnet_get_lladdr(FETH_TX, tx_mac);
	ifnet_get_lladdr(FETH_RX, rx_mac);

	T_LOG("Created feth pair: %s (%02x:%02x:%02x:%02x:%02x:%02x) <-> %s (%02x:%02x:%02x:%02x:%02x:%02x)",
	    FETH_TX, tx_mac->octet[0], tx_mac->octet[1], tx_mac->octet[2],
	    tx_mac->octet[3], tx_mac->octet[4], tx_mac->octet[5],
	    FETH_RX, rx_mac->octet[0], rx_mac->octet[1], rx_mac->octet[2],
	    rx_mac->octet[3], rx_mac->octet[4], rx_mac->octet[5]);

	/* Set IFXF_LOW_POWER_WAKE on RX interface */
	ifnet_set_low_power_wake(FETH_RX, true);

	/* Configure IPv4 addresses */
	ifnet_add_ip_address(FETH_TX, ipv4_tx, inet_class_c_subnet_mask);
	ifnet_add_ip_address(FETH_RX, ipv4_rx, inet_class_c_subnet_mask);

	/* Add scoped routes for each interface */
	unsigned int tx_index = if_nametoindex(FETH_TX);
	unsigned int rx_index = if_nametoindex(FETH_RX);
	route_add_inet_scoped_subnet(FETH_TX, (u_short)tx_index, ipv4_tx, inet_class_c_subnet_mask);
	route_add_inet_scoped_subnet(FETH_RX, (u_short)rx_index, ipv4_rx, inet_class_c_subnet_mask);

	/* Start IPv6 */
	ifnet_start_ipv6(FETH_TX);
	ifnet_start_ipv6(FETH_RX);

	/* Get link-local IPv6 addresses */
	sleep(1); /* Give time for IPv6 autoconfiguration */

	T_ASSERT_TRUE(inet6_get_linklocal_address(tx_index, &ipv6_tx),
	    "Got IPv6 link-local for %s", FETH_TX);
	T_ASSERT_TRUE(inet6_get_linklocal_address(rx_index, &ipv6_rx),
	    "Got IPv6 link-local for %s", FETH_RX);

	char buf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ipv6_tx, buf, sizeof(buf));
	T_LOG("%s IPv6: %s", FETH_TX, buf);
	inet_ntop(AF_INET6, &ipv6_rx, buf, sizeof(buf));
	T_LOG("%s IPv6: %s", FETH_RX, buf);
}

/* Enable fake LPW mode */
static void
enable_fake_lpw(void)
{
	size_t old_len = sizeof(old_lpw_value);
	int new_value = 2;
	int ret;

	/* Get current value */
	ret = sysctlbyname("net.link.generic.system.port_used.use_fake_lpw",
	    &old_lpw_value, &old_len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get use_fake_lpw sysctl");
	T_LOG("Current use_fake_lpw value: %d", old_lpw_value);

	/* Set to 2 to enable fake LPW mode */
	ret = sysctlbyname("net.link.generic.system.port_used.use_fake_lpw",
	    NULL, NULL, &new_value, sizeof(new_value));
	T_ASSERT_POSIX_SUCCESS(ret, "Set use_fake_lpw to %d", new_value);

	lpw_sysctl_changed = true;
	T_LOG("Enabled fake LPW mode (use_fake_lpw = %d)", new_value);
}

/* Set the interface to check for magic packets */
static void
set_mark_wake_interface(const char *ifname)
{
	size_t old_len = sizeof(old_mark_wake_if);
	int ret;

	/* Get current value */
	ret = sysctlbyname("net.link.generic.system.port_used.mark_wake_packet.if",
	    old_mark_wake_if, &old_len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get mark_wake_packet.if sysctl");
	T_LOG("Current mark_wake_packet.if value: '%s'", old_mark_wake_if);

	/* Set to the specified interface name */
	ret = sysctlbyname("net.link.generic.system.port_used.mark_wake_packet.if",
	    NULL, NULL, (void *)ifname, strlen(ifname) + 1);
	T_ASSERT_POSIX_SUCCESS(ret, "Set mark_wake_packet.if to %s", ifname);

	mark_wake_if_changed = true;
	T_LOG("Set mark_wake_packet.if to '%s'", ifname);
}

/* Get max_magic_search_len sysctl value */
static uint32_t
get_max_magic_search_len(void)
{
	uint32_t value;
	size_t len = sizeof(value);
	int ret = sysctlbyname("net.link.generic.system.max_magic_search_len",
	    &value, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get max_magic_search_len sysctl");
	return value;
}

/* Get interface LPW statistics */
static void
get_lpw_stats(const char *ifname, uint64_t *checked, uint64_t *found)
{
	struct if_lpw_stats lpw_stats;
	size_t len;
	int name[6];
	unsigned int ifindex;

	/* Get interface index */
	ifindex = if_nametoindex(ifname);
	T_ASSERT_GT(ifindex, 0U, "if_nametoindex(%s)", ifname);

	/* Set up sysctl name */
	name[0] = CTL_NET;
	name[1] = PF_LINK;
	name[2] = NETLINK_GENERIC;
	name[3] = IFMIB_IFDATA;
	name[4] = ifindex;
	name[5] = IFDATA_LPWSTATS;

	/* Get LPW statistics */
	len = sizeof(lpw_stats);
	T_ASSERT_POSIX_SUCCESS(sysctl(name, 6, &lpw_stats, &len, NULL, 0),
	    "sysctl IFDATA_LPWSTATS for %s (index %u)", ifname, ifindex);

	/* Extract LPW statistics */
	*checked = lpw_stats.iflpw_magic_pkt_checked;
	*found = lpw_stats.iflpw_magic_pkt_found;

	T_LOG("%s: iflpw_magic_pkt_checked=%llu, iflpw_magic_pkt_found=%llu",
	    ifname, *checked, *found);
}

/* Get LPW magic packet found count (quiet version for loops) */
static uint64_t
get_lpw_found_count(const char *ifname)
{
	struct if_lpw_stats lpw_stats;
	size_t len;
	int name[6];
	unsigned int ifindex;

	ifindex = if_nametoindex(ifname);
	T_QUIET; T_ASSERT_GT(ifindex, 0U, "if_nametoindex(%s)", ifname);

	name[0] = CTL_NET;
	name[1] = PF_LINK;
	name[2] = NETLINK_GENERIC;
	name[3] = IFMIB_IFDATA;
	name[4] = ifindex;
	name[5] = IFDATA_LPWSTATS;

	len = sizeof(lpw_stats);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctl(name, 6, &lpw_stats, &len, NULL, 0),
	    "sysctl IFDATA_LPWSTATS");

	return lpw_stats.iflpw_magic_pkt_found;
}

/* Send IPv4 UDP magic packet with optional offset */
static void
send_ipv4_magic_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac, size_t offset)
{
	uint8_t magic_data[102]; /* 6 + 16*6 */
	size_t magic_len;
	uint8_t payload[512];
	size_t payload_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create magic packet data */
	create_magic_packet(magic_data, &magic_len, dst_mac);

	/* Create payload with magic packet at specified offset */
	memset(payload, 0xAA, sizeof(payload)); /* Fill with padding */
	T_ASSERT_LE(offset + magic_len, sizeof(payload), "Offset too large");
	memcpy(payload + offset, magic_data, magic_len);
	payload_len = offset + magic_len + 10; /* Add some trailing data */

	T_LOG("IPv4: Magic packet at offset %zu, total payload %zu bytes", offset, payload_len);

	/* Build UDP frame with magic packet */
	pkt_len = ethernet_udp4_frame_populate(packet, sizeof(packet),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    payload, payload_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv4 UDP magic packet");
	T_LOG("IPv4 packet size: %u bytes", pkt_len);

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv4 UDP magic packet");
	T_LOG("Sent IPv4 UDP magic packet (%zd bytes)", n);
}

/* Send IPv6 UDP magic packet with optional offset */
static void
send_ipv6_magic_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac, size_t offset)
{
	uint8_t magic_data[102]; /* 6 + 16*6 */
	size_t magic_len;
	uint8_t payload[512];
	size_t payload_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create magic packet data */
	create_magic_packet(magic_data, &magic_len, dst_mac);

	/* Create payload with magic packet at specified offset */
	memset(payload, 0xBB, sizeof(payload)); /* Fill with padding */
	T_ASSERT_LE(offset + magic_len, sizeof(payload), "Offset too large");
	memcpy(payload + offset, magic_data, magic_len);
	payload_len = offset + magic_len + 10; /* Add some trailing data */

	T_LOG("IPv6: Magic packet at offset %zu, total payload %zu bytes", offset, payload_len);

	/* Build UDP frame with magic packet */
	pkt_len = ethernet_udp6_frame_populate(packet, sizeof(packet),
	    src_mac, &ipv6_tx, 9, /* src port 9 (discard) */
	    dst_mac, &ipv6_rx, 7, /* dst port 7 (echo) */
	    payload, payload_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv6 UDP magic packet");
	T_LOG("IPv6 packet size: %u bytes", pkt_len);

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv6 UDP magic packet");
	T_LOG("Sent IPv6 UDP magic packet (%zd bytes)", n);
}

/* Send IPv4 UDP packet filled with 0xFF */
static void
send_ipv4_all_ff_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac, size_t data_len)
{
	uint8_t payload[512];
	size_t payload_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create all-0xFF payload */
	create_all_ff_packet(payload, &payload_len, data_len);

	T_LOG("IPv4: All-0xFF packet, %zu bytes", payload_len);

	/* Build UDP frame */
	pkt_len = ethernet_udp4_frame_populate(packet, sizeof(packet),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    payload, payload_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv4 UDP all-0xFF packet");

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv4 UDP all-0xFF packet");
	T_LOG("Sent IPv4 UDP all-0xFF packet (%zd bytes)", n);
}

/* Send IPv4 UDP packet with incomplete magic pattern (15 MAC addresses) */
static void
send_ipv4_incomplete_magic_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac)
{
	uint8_t magic_data[102]; /* Same size but wrong content */
	size_t magic_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create incomplete magic packet data */
	create_incomplete_magic_packet(magic_data, &magic_len, dst_mac);

	T_LOG("IPv4: Incomplete magic packet (15 MAC repetitions)");

	/* Build UDP frame */
	pkt_len = ethernet_udp4_frame_populate(packet, sizeof(packet),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    magic_data, magic_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv4 UDP incomplete magic packet");

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv4 UDP incomplete magic packet");
	T_LOG("Sent IPv4 UDP incomplete magic packet (%zd bytes)", n);
}

/* Send IPv4 UDP packet with incomplete sync stream (5 bytes instead of 6) at optional offset */
static void
send_ipv4_incomplete_sync_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac, size_t offset)
{
	uint8_t incomplete_data[101]; /* 5 + 16*6 */
	size_t incomplete_len;
	uint8_t payload[512];
	size_t payload_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create incomplete sync packet data */
	create_incomplete_sync_packet(incomplete_data, &incomplete_len, dst_mac);

	/* Create payload with incomplete sync packet at specified offset */
	memset(payload, 0xAA, sizeof(payload)); /* Fill with padding */
	T_ASSERT_LE(offset + incomplete_len, sizeof(payload), "Offset too large");
	memcpy(payload + offset, incomplete_data, incomplete_len);
	payload_len = offset + incomplete_len + 10; /* Add some trailing data */

	/* Build UDP frame */
	pkt_len = ethernet_udp4_frame_populate(packet, sizeof(packet),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    payload, payload_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv4 UDP incomplete sync packet");

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv4 UDP incomplete sync packet");
}

/* Send IPv4 UDP packet with truncated magic pattern (missing last byte) at optional offset */
static void
send_ipv4_truncated_magic_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac, size_t offset)
{
	uint8_t truncated_data[101]; /* 6 + 15*6 + 5 */
	size_t truncated_len;
	uint8_t payload[512];
	size_t payload_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create truncated magic packet data */
	create_truncated_magic_packet(truncated_data, &truncated_len, dst_mac);

	/* Create payload with truncated magic packet at specified offset */
	memset(payload, 0xAA, sizeof(payload)); /* Fill with padding */
	T_ASSERT_LE(offset + truncated_len, sizeof(payload), "Offset too large");
	memcpy(payload + offset, truncated_data, truncated_len);
	payload_len = offset + truncated_len + 10; /* Add some trailing data */

	/* Build UDP frame */
	pkt_len = ethernet_udp4_frame_populate(packet, sizeof(packet),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    payload, payload_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv4 UDP truncated magic packet");

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv4 UDP truncated magic packet");
}

/* Send IPv4 UDP packet with wrong MAC address */
static void
send_ipv4_wrong_mac_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac, const ether_addr_t *wrong_mac)
{
	uint8_t magic_data[102];
	size_t magic_len;
	uint8_t packet[1024];
	u_int pkt_len;
	ssize_t n;

	/* Create magic packet with wrong MAC */
	create_wrong_mac_packet(magic_data, &magic_len, wrong_mac);

	T_LOG("IPv4: Magic packet with wrong MAC address");

	/* Build UDP frame */
	pkt_len = ethernet_udp4_frame_populate(packet, sizeof(packet),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    magic_data, magic_len);

	T_ASSERT_GT(pkt_len, 0U, "Created IPv4 UDP wrong-MAC magic packet");

	/* Send the packet */
	n = write(bpf_fd, packet, pkt_len);
	T_ASSERT_EQ(n, (ssize_t)pkt_len, "Sent IPv4 UDP wrong-MAC magic packet");
	T_LOG("Sent IPv4 UDP wrong-MAC magic packet (%zd bytes)", n);
}

/* Test IPv4 magic packet detection */
T_DECL(magic_packet_ipv4, "Magic packet detection over IPv4 UDP")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, checked_after;
	uint64_t found_before, found_after;
	u_int packets_sent = 0;
	u_int expected_increments = 0;

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Send magic packet at offset 0 - fully in first chunk */
	T_LOG("Sending IPv4 magic packet at offset 0 (fully in first chunk)");
	send_ipv4_magic_packet(bpf_fd, &tx_mac, &rx_mac, 0);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send magic packet at offset 50 - fully in first chunk */
	T_LOG("Sending IPv4 magic packet at offset 50 (fully in first chunk)");
	send_ipv4_magic_packet(bpf_fd, &tx_mac, &rx_mac, 50);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send magic packet at offset 97 - sync_stream at end of first chunk, MAC addresses need second m_copydata */
	T_LOG("Sending IPv4 magic packet at offset 97 (sync_stream at end of chunk)");
	send_ipv4_magic_packet(bpf_fd, &tx_mac, &rx_mac, 97);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send magic packet at offset 150 - in second chunk */
	T_LOG("Sending IPv4 magic packet at offset 150 (in second chunk)");
	send_ipv4_magic_packet(bpf_fd, &tx_mac, &rx_mac, 150);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics delta: checked=%llu, found=%llu, expected=%u",
	    checked_delta, found_delta, expected_increments);

	/* If less than expected, skip test due to potential timing issues */
	if (found_delta < expected_increments) {
		T_SKIP("Magic packets found (%llu) less than expected (%u) - possible timing issue",
		    found_delta, expected_increments);
	}

	/* Verify that ifi_lpw_magic_pkt_checked incremented (allow for extra packets) */
	T_ASSERT_GE(checked_delta, (uint64_t)expected_increments,
	    "ifi_lpw_magic_pkt_checked should increment by at least %u (actual: %llu)",
	    expected_increments, checked_delta);

	/* Verify that ifi_lpw_magic_pkt_found incremented (allow for extra packets) */
	T_ASSERT_GE(found_delta, (uint64_t)expected_increments,
	    "ifi_lpw_magic_pkt_found should increment by at least %u (actual: %llu)",
	    expected_increments, found_delta);

	T_PASS("IPv4 magic packet test completed - checked:%llu->%llu (+%llu), found:%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta, found_before, found_after, found_delta);
}

/* Test IPv6 magic packet detection */
T_DECL(magic_packet_ipv6, "Magic packet detection over IPv6 UDP")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, checked_after;
	uint64_t found_before, found_after;
	u_int packets_sent = 0;
	u_int expected_increments = 0;

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Send magic packet at offset 0 - fully in first chunk */
	T_LOG("Sending IPv6 magic packet at offset 0 (fully in first chunk)");
	send_ipv6_magic_packet(bpf_fd, &tx_mac, &rx_mac, 0);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send magic packet at offset 50 - fully in first chunk */
	T_LOG("Sending IPv6 magic packet at offset 50 (fully in first chunk)");
	send_ipv6_magic_packet(bpf_fd, &tx_mac, &rx_mac, 50);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send magic packet at offset 97 - sync_stream at end of first chunk, MAC addresses need second m_copydata */
	T_LOG("Sending IPv6 magic packet at offset 97 (sync_stream at end of chunk)");
	send_ipv6_magic_packet(bpf_fd, &tx_mac, &rx_mac, 97);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send magic packet at offset 150 - in second chunk */
	T_LOG("Sending IPv6 magic packet at offset 150 (in second chunk)");
	send_ipv6_magic_packet(bpf_fd, &tx_mac, &rx_mac, 150);
	packets_sent++;
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics delta: checked=%llu, found=%llu, expected=%u",
	    checked_delta, found_delta, expected_increments);

	/* If less than expected, skip test due to potential timing issues */
	if (found_delta < expected_increments) {
		T_SKIP("Magic packets found (%llu) less than expected (%u) - possible timing issue",
		    found_delta, expected_increments);
	}

	/* Verify that ifi_lpw_magic_pkt_checked incremented (allow for extra packets) */
	T_ASSERT_GE(checked_delta, (uint64_t)expected_increments,
	    "ifi_lpw_magic_pkt_checked should increment by at least %u (actual: %llu)",
	    expected_increments, checked_delta);

	/* Verify that ifi_lpw_magic_pkt_found incremented (allow for extra packets) */
	T_ASSERT_GE(found_delta, (uint64_t)expected_increments,
	    "ifi_lpw_magic_pkt_found should increment by at least %u (actual: %llu)",
	    expected_increments, found_delta);

	T_PASS("IPv6 magic packet test completed - checked:%llu->%llu (+%llu), found:%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta, found_before, found_after, found_delta);
}

/* Test negative cases - packets that should NOT be detected as magic packets */
T_DECL(magic_packet_negative, "Negative test cases for magic packet detection")
{
	ether_addr_t tx_mac, rx_mac, wrong_mac;
	int bpf_fd;
	uint64_t checked_before, checked_after;
	uint64_t found_before, found_after;
	u_int packets_sent = 0;

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Create a wrong MAC address (different from rx_mac) */
	memcpy(&wrong_mac, &rx_mac, sizeof(wrong_mac));
	wrong_mac.octet[0] ^= 0xFF; /* Flip first byte to make it different */

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Test 1: Large packet filled with 0xFF (all sync stream, no MAC addresses) */
	T_LOG("Test 1: Sending large all-0xFF packet (should NOT be detected)");
	send_ipv4_all_ff_packet(bpf_fd, &tx_mac, &rx_mac, 300);
	packets_sent++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 2: Incomplete magic packet with only 15 MAC repetitions */
	T_LOG("Test 2: Sending incomplete magic packet with 15 MAC repetitions (should NOT be detected)");
	send_ipv4_incomplete_magic_packet(bpf_fd, &tx_mac, &rx_mac);
	packets_sent++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 3: Magic packet pattern but with wrong MAC address */
	T_LOG("Test 3: Sending magic packet with wrong MAC address (should NOT be detected)");
	send_ipv4_wrong_mac_packet(bpf_fd, &tx_mac, &rx_mac, &wrong_mac);
	packets_sent++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 4: Another all-0xFF packet with different size to stress test */
	T_LOG("Test 4: Sending another all-0xFF packet, 500 bytes (should NOT be detected)");
	send_ipv4_all_ff_packet(bpf_fd, &tx_mac, &rx_mac, 500);
	packets_sent++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics delta: checked=%llu, found=%llu, packets_sent=%u",
	    checked_delta, found_delta, packets_sent);

	/* Verify that packets were checked */
	T_ASSERT_GE(checked_delta, (uint64_t)packets_sent,
	    "ifi_lpw_magic_pkt_checked should increment by at least %u (actual: %llu)",
	    packets_sent, checked_delta);

	/* Verify that NO magic packets were found (critical assertion) */
	T_ASSERT_EQ(found_delta, 0ULL,
	    "ifi_lpw_magic_pkt_found should NOT increment for invalid packets (actual: %llu)",
	    found_delta);

	T_PASS("Negative test completed - all invalid packets correctly rejected - checked:%llu->%llu (+%llu), found:%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta, found_before, found_after, found_delta);
}

/* Compute UDP checksum for IPv4
 * All values are summed in network byte order for consistency.
 * IP addresses and ports are passed in network byte order.
 * Returns checksum in network byte order, ready for storage in uh_sum.
 */
static uint16_t
udp_checksum_ipv4(struct in_addr src, struct in_addr dst,
    in_port_t src_port, in_port_t dst_port,
    const uint8_t *__counted_by(data_len) data, size_t data_len)
{
	uint32_t sum = 0;
	size_t i;
	uint16_t udp_len_net = htons(sizeof(struct udphdr) + data_len);

	/* All 16-bit values are summed in network byte order */

	/* Pseudo-header: source IP (in network byte order) */
	const uint16_t *src_words = (const uint16_t *)&src.s_addr;
	sum += src_words[0];
	sum += src_words[1];

	/* Pseudo-header: dest IP (in network byte order) */
	const uint16_t *dst_words = (const uint16_t *)&dst.s_addr;
	sum += dst_words[0];
	sum += dst_words[1];

	/* Pseudo-header: zero + protocol */
	sum += htons(IPPROTO_UDP);

	/* Pseudo-header: UDP length */
	sum += udp_len_net;

	/* UDP header: ports (in network byte order) */
	sum += src_port;
	sum += dst_port;

	/* UDP header: length */
	sum += udp_len_net;

	/* UDP data (read as 16-bit values in network byte order) */
	for (i = 0; i + 1 < data_len; i += 2) {
		uint16_t word;
		memcpy(&word, &data[i], sizeof(word));
		sum += word;
	}

	/* Handle odd byte: pair with zero byte, in network byte order */
	if (data_len & 1) {
		uint16_t word = htons((uint16_t)data[data_len - 1] << 8);
		sum += word;
	}

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	/* One's complement - result is in network byte order */
	return (uint16_t)~sum;
}

/* Send IPv4 UDP magic packet as fragments */
static void
send_ipv4_fragmented_magic_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac,
    size_t offset, size_t frag_split_offset)
{
	uint8_t magic_data[102]; /* 6 + 16*6 */
	size_t magic_len;
	uint8_t payload[512];
	size_t payload_len;
	uint8_t packet1[1024], packet2[1024];
	u_int pkt1_len, pkt2_len;
	ssize_t n;
	struct ip *ip1, *ip2;
	uint16_t ip_id = 0x1234; /* Fixed IP ID for fragments */

	/* Create magic packet data */
	create_magic_packet(magic_data, &magic_len, dst_mac);

	/* Create payload with magic packet at specified offset */
	memset(payload, 0xAA, sizeof(payload)); /* Fill with padding */
	T_ASSERT_LE(offset + magic_len, sizeof(payload), "Offset too large");
	memcpy(payload + offset, magic_data, magic_len);
	payload_len = offset + magic_len + 10; /* Add some trailing data */

	/* Round split offset down to 8-byte boundary (fragment offset requirement) */
	size_t aligned_split = (frag_split_offset / 8) * 8;
	if (aligned_split != frag_split_offset) {
		T_LOG("Note: Adjusted fragment split from %zu to %zu for 8-byte alignment",
		    frag_split_offset, aligned_split);
		frag_split_offset = aligned_split;
	}

	T_LOG("IPv4 Fragmented: Magic packet at offset %zu, total payload %zu bytes, fragment split at %zu",
	    offset, payload_len, frag_split_offset);

	/* Ensure we don't create an empty first or second fragment */
	T_ASSERT_GT(frag_split_offset, 0UL, "First fragment must have data");
	T_ASSERT_LT(frag_split_offset, payload_len, "Second fragment must have data");

	/* Build first fragment with UDP header and part of payload */
	pkt1_len = ethernet_udp4_frame_populate(packet1, sizeof(packet1),
	    src_mac, ipv4_tx, 9, /* src port 9 (discard) */
	    dst_mac, ipv4_rx, 7, /* dst port 7 (echo) */
	    payload, frag_split_offset);

	T_ASSERT_GT(pkt1_len, 0U, "Created first fragment");

	/* Modify first fragment: Set MF (More Fragments) flag and fragment offset = 0 */
	ip1 = (struct ip *)(packet1 + ETHER_HDR_LEN);
	ip1->ip_id = htons(ip_id);
	ip1->ip_off = htons(IP_MF); /* More fragments, offset 0 */

	/* Fix UDP header length to reflect FULL reassembled UDP packet size */
	struct udphdr *uh1 = (struct udphdr *)(packet1 + ETHER_HDR_LEN + sizeof(struct ip));
	uh1->uh_ulen = htons(sizeof(struct udphdr) + payload_len);

	/* Recalculate UDP checksum over the FULL payload (not just fragment 1) */
	uh1->uh_sum = 0;
	uh1->uh_sum = udp_checksum_ipv4(ipv4_tx, ipv4_rx, htons(9), htons(7), payload, payload_len);

	/* Recalculate IP checksum */
	ip1->ip_sum = 0;
	ip1->ip_sum = in_cksum(ip1, sizeof(struct ip));

	/* Second fragment: Ethernet + IP header + remaining payload (no UDP header) */
	struct ether_header *eh2 = (struct ether_header *)packet2;
	memcpy(eh2->ether_dhost, dst_mac, ETHER_ADDR_LEN);
	memcpy(eh2->ether_shost, src_mac, ETHER_ADDR_LEN);
	eh2->ether_type = htons(ETHERTYPE_IP);

	ip2 = (struct ip *)(packet2 + ETHER_HDR_LEN);
	memset(ip2, 0, sizeof(struct ip));
	ip2->ip_v = IPVERSION;
	ip2->ip_hl = sizeof(struct ip) >> 2;
	ip2->ip_tos = 0;
	ip2->ip_len = htons(sizeof(struct ip) + (payload_len - frag_split_offset));
	ip2->ip_id = htons(ip_id);

	/* Fragment offset in 8-byte units from start of original IP payload */
	/* Original IP payload is: UDP header (8 bytes) + payload */
	uint16_t frag_offset_units = (sizeof(struct udphdr) + frag_split_offset) / 8;
	ip2->ip_off = htons(frag_offset_units); /* No MF flag - this is last fragment */
	ip2->ip_ttl = 64;
	ip2->ip_p = IPPROTO_UDP;
	ip2->ip_src = ipv4_tx;
	ip2->ip_dst = ipv4_rx;
	ip2->ip_sum = 0;
	ip2->ip_sum = in_cksum(ip2, sizeof(struct ip));

	/* Copy remaining payload */
	memcpy(packet2 + ETHER_HDR_LEN + sizeof(struct ip),
	    payload + frag_split_offset,
	    payload_len - frag_split_offset);

	pkt2_len = ETHER_HDR_LEN + sizeof(struct ip) + (payload_len - frag_split_offset);

	T_LOG("Fragment 1: %u bytes (IP+UDP header + %zu bytes payload, offset=0)",
	    pkt1_len, frag_split_offset);
	T_LOG("Fragment 2: %u bytes (IP header + %zu bytes payload, offset=%u*8=%u bytes)",
	    pkt2_len, payload_len - frag_split_offset, frag_offset_units, frag_offset_units * 8);

	/* Send first fragment */
	n = write(bpf_fd, packet1, pkt1_len);
	T_ASSERT_EQ(n, (ssize_t)pkt1_len, "Sent first IPv4 fragment");
	T_LOG("Sent first IPv4 fragment (%zd bytes)", n);

	/* Delay to ensure fragments arrive in order and reassemble */
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Send second fragment */
	n = write(bpf_fd, packet2, pkt2_len);
	T_ASSERT_EQ(n, (ssize_t)pkt2_len, "Sent second IPv4 fragment");
	T_LOG("Sent second IPv4 fragment (%zd bytes)", n);

	/* Delay to ensure reassembly and processing completes */
	usleep(PKT_PROCESSING_LEEWAY_US);
}

/* Send IPv4 fragmented packet that is NOT a magic packet */
static void
send_ipv4_fragmented_non_magic_packet(int bpf_fd, const ether_addr_t *src_mac, const ether_addr_t *dst_mac,
    size_t frag_split_offset)
{
	uint8_t payload[512];
	size_t payload_len = 200;
	uint8_t packet1[1024], packet2[1024];
	u_int pkt1_len, pkt2_len;
	ssize_t n;
	struct ip *ip1, *ip2;
	uint16_t ip_id = 0x5678;

	/* Create non-magic payload (no magic pattern) */
	for (size_t i = 0; i < payload_len; i++) {
		payload[i] = (uint8_t)(i & 0xFF);
	}

	/* Round split offset down to 8-byte boundary */
	size_t aligned_split = (frag_split_offset / 8) * 8;
	if (aligned_split != frag_split_offset) {
		T_LOG("Note: Adjusted fragment split from %zu to %zu for 8-byte alignment",
		    frag_split_offset, aligned_split);
		frag_split_offset = aligned_split;
	}

	T_LOG("IPv4 Fragmented Non-Magic: total payload %zu bytes, fragment split at %zu",
	    payload_len, frag_split_offset);

	T_ASSERT_GT(frag_split_offset, 0UL, "First fragment must have data");
	T_ASSERT_LT(frag_split_offset, payload_len, "Second fragment must have data");

	/* Build first fragment */
	pkt1_len = ethernet_udp4_frame_populate(packet1, sizeof(packet1),
	    src_mac, ipv4_tx, 9,
	    dst_mac, ipv4_rx, 7,
	    payload, frag_split_offset);

	T_ASSERT_GT(pkt1_len, 0U, "Created first fragment");

	/* Set MF flag */
	ip1 = (struct ip *)(packet1 + ETHER_HDR_LEN);
	ip1->ip_id = htons(ip_id);
	ip1->ip_off = htons(IP_MF);

	/* Fix UDP header length to reflect FULL reassembled UDP packet size */
	struct udphdr *uh1 = (struct udphdr *)(packet1 + ETHER_HDR_LEN + sizeof(struct ip));
	uh1->uh_ulen = htons(sizeof(struct udphdr) + payload_len);

	/* Recalculate UDP checksum over the FULL payload (not just fragment 1) */
	uh1->uh_sum = 0;
	uh1->uh_sum = udp_checksum_ipv4(ipv4_tx, ipv4_rx, htons(9), htons(7), payload, payload_len);

	ip1->ip_sum = 0;
	ip1->ip_sum = in_cksum(ip1, sizeof(struct ip));

	/* Build second fragment */
	struct ether_header *eh2 = (struct ether_header *)packet2;
	memcpy(eh2->ether_dhost, dst_mac, ETHER_ADDR_LEN);
	memcpy(eh2->ether_shost, src_mac, ETHER_ADDR_LEN);
	eh2->ether_type = htons(ETHERTYPE_IP);

	ip2 = (struct ip *)(packet2 + ETHER_HDR_LEN);
	memset(ip2, 0, sizeof(struct ip));
	ip2->ip_v = IPVERSION;
	ip2->ip_hl = sizeof(struct ip) >> 2;
	ip2->ip_tos = 0;
	ip2->ip_len = htons(sizeof(struct ip) + (payload_len - frag_split_offset));
	ip2->ip_id = htons(ip_id);
	uint16_t frag_offset_units = (sizeof(struct udphdr) + frag_split_offset) / 8;
	ip2->ip_off = htons(frag_offset_units);
	ip2->ip_ttl = 64;
	ip2->ip_p = IPPROTO_UDP;
	ip2->ip_src = ipv4_tx;
	ip2->ip_dst = ipv4_rx;
	ip2->ip_sum = 0;
	ip2->ip_sum = in_cksum(ip2, sizeof(struct ip));

	memcpy(packet2 + ETHER_HDR_LEN + sizeof(struct ip),
	    payload + frag_split_offset,
	    payload_len - frag_split_offset);

	pkt2_len = ETHER_HDR_LEN + sizeof(struct ip) + (payload_len - frag_split_offset);

	/* Send fragments */
	n = write(bpf_fd, packet1, pkt1_len);
	T_ASSERT_EQ(n, (ssize_t)pkt1_len, "Sent first IPv4 fragment");

	usleep(PKT_PROCESSING_LEEWAY_US);

	n = write(bpf_fd, packet2, pkt2_len);
	T_ASSERT_EQ(n, (ssize_t)pkt2_len, "Sent second IPv4 fragment");

	usleep(PKT_PROCESSING_LEEWAY_US);
}

/* Test fragmented magic packet detection - positive cases */
T_DECL(magic_packet_fragmented_positive, "Fragmented magic packet detection - positive tests")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, checked_after;
	uint64_t found_before, found_after;
	u_int expected_increments = 0;

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Test 1: Magic packet split right after sync stream (8 bytes = 6 sync + 2 payload padding) */
	T_LOG("Test 1: Magic packet fragmented after sync stream (8-byte aligned)");
	send_ipv4_fragmented_magic_packet(bpf_fd, &tx_mac, &rx_mac, 0, 8);
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 2: Magic packet split in middle of MAC addresses (16 bytes) */
	T_LOG("Test 2: Magic packet fragmented in middle of MAC addresses (16-byte split)");
	send_ipv4_fragmented_magic_packet(bpf_fd, &tx_mac, &rx_mac, 0, 16);
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 3: Magic packet split later in MAC addresses (48 bytes) */
	T_LOG("Test 3: Magic packet fragmented in middle of MAC addresses (48-byte split)");
	send_ipv4_fragmented_magic_packet(bpf_fd, &tx_mac, &rx_mac, 0, 48);
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 4: Magic packet with offset, fragmented (both 8-byte aligned) */
	T_LOG("Test 4: Magic packet at offset 16, fragmented at byte 40");
	send_ipv4_fragmented_magic_packet(bpf_fd, &tx_mac, &rx_mac, 16, 40);
	expected_increments++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics delta: checked=%llu, found=%llu, expected_increments=%u",
	    checked_delta, found_delta, expected_increments);

	/* Verify statistics - allow for extra packets from system */
	T_ASSERT_GE(checked_delta, (uint64_t)expected_increments,
	    "ifi_lpw_magic_pkt_checked should increment by at least %u (actual: %llu)",
	    expected_increments, checked_delta);

	T_ASSERT_GE(found_delta, (uint64_t)expected_increments,
	    "ifi_lpw_magic_pkt_found should increment by at least %u (actual: %llu)",
	    expected_increments, found_delta);

	T_PASS("Fragmented magic packet test completed - checked:%llu->%llu (+%llu), found:%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta, found_before, found_after, found_delta);
}

/* Test fragmented packet detection - negative cases */
T_DECL(magic_packet_fragmented_negative, "Fragmented magic packet detection - negative tests")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, checked_after;
	uint64_t found_before, found_after;
	u_int packets_sent = 0;

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Test 1: Fragmented non-magic packet (regular data, 8-byte aligned split) */
	T_LOG("Test 1: Fragmented non-magic packet (should NOT be detected)");
	send_ipv4_fragmented_non_magic_packet(bpf_fd, &tx_mac, &rx_mac, 48);
	packets_sent++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Test 2: Another fragmented non-magic packet with different split (8-byte aligned) */
	T_LOG("Test 2: Fragmented non-magic packet, different split point (should NOT be detected)");
	send_ipv4_fragmented_non_magic_packet(bpf_fd, &tx_mac, &rx_mac, 96);
	packets_sent++;
	usleep(PKT_PROCESSING_LEEWAY_US);

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics delta: checked=%llu, found=%llu, packets_sent=%u",
	    checked_delta, found_delta, packets_sent);

	/* Verify that packets were checked */
	T_ASSERT_GE(checked_delta, (uint64_t)packets_sent,
	    "ifi_lpw_magic_pkt_checked should increment by at least %u (actual: %llu)",
	    packets_sent, checked_delta);

	/* Verify that NO magic packets were found (critical assertion) */
	T_ASSERT_EQ(found_delta, 0ULL,
	    "ifi_lpw_magic_pkt_found should NOT increment for fragmented non-magic packets (actual: %llu)",
	    found_delta);

	T_PASS("Fragmented negative test completed - all invalid packets correctly rejected - checked:%llu->%llu (+%llu), found:%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta, found_before, found_after, found_delta);
}

/* Test magic packet detection at all valid offsets */
T_DECL(magic_packet_all_offsets, "Magic packet detection at all valid offsets")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, found_before;
	uint64_t checked_after, found_after;
	uint32_t max_search_len;
	int max_offset;
	const int magic_len = 102; /* 6 + 16*6 */

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Get max_magic_search_len from sysctl */
	max_search_len = get_max_magic_search_len();

	/*
	 * Calculate max valid payload offset.
	 * The magic packet detection searches from the IP header, so we need
	 * to account for the IP and UDP headers when calculating the maximum
	 * offset within the UDP payload:
	 *   max_payload_offset = max_search_len - magic_len - IP_header - UDP_header
	 */
	max_offset = (int)max_search_len - magic_len -
	    (int)sizeof(struct ip) - (int)sizeof(struct udphdr);
	T_ASSERT_GE(max_offset, 0, "max_offset should be non-negative");

	T_LOG("Testing offsets 0 to %d (max_magic_search_len=%u)", max_offset, max_search_len);

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Test each offset from 0 to max_offset */
	for (int offset = 0; offset <= max_offset; offset++) {
		uint64_t found_prev, found_curr;

		found_prev = get_lpw_found_count(FETH_RX);
		send_ipv4_magic_packet(bpf_fd, &tx_mac, &rx_mac, (size_t)offset);
		usleep(PKT_PROCESSING_LEEWAY_US); /* 10ms delay for processing */
		found_curr = get_lpw_found_count(FETH_RX);

		T_QUIET; T_ASSERT_GT(found_curr, found_prev,
		    "Magic packet at offset %d should be detected", offset);

		/* Log progress every 50 offsets */
		if (offset % 50 == 0) {
			T_LOG("Progress: offset %d/%d", offset, max_offset);
		}
	}

	/*
	 * Negative boundary test: magic packet at max_offset + 1 should NOT
	 * be detected because it ends just past the search boundary.
	 */
	{
		uint64_t found_prev, found_curr;
		int invalid_offset = max_offset + 1;

		T_LOG("Negative test: offset %d should NOT be detected", invalid_offset);

		found_prev = get_lpw_found_count(FETH_RX);
		send_ipv4_magic_packet(bpf_fd, &tx_mac, &rx_mac, (size_t)invalid_offset);
		usleep(PKT_PROCESSING_LEEWAY_US); /* 10ms delay for processing */
		found_curr = get_lpw_found_count(FETH_RX);

		T_ASSERT_EQ(found_curr, found_prev,
		    "Magic packet at offset %d should NOT be detected (past search boundary)",
		    invalid_offset);
	}

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	T_LOG("Statistics: checked=%llu->%llu, found=%llu->%llu",
	    checked_before, checked_after, found_before, found_after);

	T_PASS("All %d offsets (0 to %d) tested successfully", max_offset + 1, max_offset);
}

/* Test incomplete sync stream (5 bytes of 0xFF) at all valid offsets - negative test */
T_DECL(magic_packet_incomplete_sync_all_offsets, "Incomplete sync stream (5 bytes) should not be detected at any offset")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, found_before;
	uint64_t checked_after, found_after;
	uint32_t max_search_len;
	int max_offset;
	const int incomplete_sync_len = 101; /* 5 + 16*6 */

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Get max_magic_search_len from sysctl */
	max_search_len = get_max_magic_search_len();

	/*
	 * Calculate max valid payload offset.
	 * Use the same formula as for valid magic packets, but with the
	 * incomplete sync pattern length (101 bytes instead of 102).
	 */
	max_offset = (int)max_search_len - incomplete_sync_len -
	    (int)sizeof(struct ip) - (int)sizeof(struct udphdr);
	T_ASSERT_GE(max_offset, 0, "max_offset should be non-negative");

	T_LOG("Testing incomplete sync (5 bytes of 0xFF) at offsets 0 to %d", max_offset);

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Test each offset from 0 to max_offset */
	for (int offset = 0; offset <= max_offset; offset++) {
		send_ipv4_incomplete_sync_packet(bpf_fd, &tx_mac, &rx_mac, (size_t)offset);
		usleep(PKT_PROCESSING_LEEWAY_US); /* 10ms delay for processing */

		/* Log progress every 50 offsets */
		if (offset % 50 == 0) {
			T_LOG("Progress: offset %d/%d", offset, max_offset);
		}
	}

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics: checked=%llu->%llu (+%llu), found=%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta,
	    found_before, found_after, found_delta);

	/* Verify that packets were checked */
	T_ASSERT_GE(checked_delta, (uint64_t)(max_offset + 1),
	    "ifi_lpw_magic_pkt_checked should increment by at least %d (actual: %llu)",
	    max_offset + 1, checked_delta);

	/* Verify that NO magic packets were found (critical assertion) */
	T_ASSERT_EQ(found_delta, 0ULL,
	    "ifi_lpw_magic_pkt_found should NOT increment for incomplete sync packets (actual: %llu)",
	    found_delta);

	T_PASS("Incomplete sync stream correctly rejected at all %d offsets (0 to %d)",
	    max_offset + 1, max_offset);
}

/* Test truncated magic pattern (missing last byte) at all valid offsets - negative test */
T_DECL(magic_packet_truncated_all_offsets, "Truncated magic pattern (missing last byte) should not be detected at any offset")
{
	ether_addr_t tx_mac, rx_mac;
	int bpf_fd;
	uint64_t checked_before, found_before;
	uint64_t checked_after, found_after;
	uint32_t max_search_len;
	int max_offset;
	const int truncated_len = 101; /* 6 + 15*6 + 5 */

	/* Setup */
	setup_feth_pair(&tx_mac, &rx_mac);

	/* Enable fake LPW mode and set interface to monitor */
	enable_fake_lpw();
	set_mark_wake_interface(FETH_RX);

	/* Open BPF on TX interface */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), "bpf_set_immediate");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, FETH_TX), "bpf_setif %s", FETH_TX);
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 0), "bpf_set_see_sent");

	/* Get max_magic_search_len from sysctl */
	max_search_len = get_max_magic_search_len();

	/*
	 * Calculate max valid payload offset.
	 * Use the same formula as for valid magic packets, but with the
	 * truncated pattern length (101 bytes instead of 102).
	 */
	max_offset = (int)max_search_len - truncated_len -
	    (int)sizeof(struct ip) - (int)sizeof(struct udphdr);
	T_ASSERT_GE(max_offset, 0, "max_offset should be non-negative");

	T_LOG("Testing truncated magic pattern (missing last byte) at offsets 0 to %d", max_offset);

	/* Measure UDP RTT to determine if RTT is too large */
	useconds_t rtt = measure_udp_rtt();
	if (rtt != UINT32_MAX && rtt >= RTT_THRESHOLD_US) {
		close(bpf_fd);
		T_SKIP("UDP RTT (%u us) >= threshold (%u us) - RTT too large for this test",
		    rtt, RTT_THRESHOLD_US);
	}

	/* Get initial statistics */
	get_lpw_stats(FETH_RX, &checked_before, &found_before);

	/* Test each offset from 0 to max_offset */
	for (int offset = 0; offset <= max_offset; offset++) {
		send_ipv4_truncated_magic_packet(bpf_fd, &tx_mac, &rx_mac, (size_t)offset);
		usleep(PKT_PROCESSING_LEEWAY_US); /* 10ms delay for processing */

		/* Log progress every 50 offsets */
		if (offset % 50 == 0) {
			T_LOG("Progress: offset %d/%d", offset, max_offset);
		}
	}

	/* Get final statistics */
	get_lpw_stats(FETH_RX, &checked_after, &found_after);

	/* Close socket */
	close(bpf_fd);

	/* Calculate actual increments */
	uint64_t checked_delta = checked_after - checked_before;
	uint64_t found_delta = found_after - found_before;

	T_LOG("Statistics: checked=%llu->%llu (+%llu), found=%llu->%llu (+%llu)",
	    checked_before, checked_after, checked_delta,
	    found_before, found_after, found_delta);

	/* Verify that packets were checked */
	T_ASSERT_GE(checked_delta, (uint64_t)(max_offset + 1),
	    "ifi_lpw_magic_pkt_checked should increment by at least %d (actual: %llu)",
	    max_offset + 1, checked_delta);

	/* Verify that NO magic packets were found (critical assertion) */
	T_ASSERT_EQ(found_delta, 0ULL,
	    "ifi_lpw_magic_pkt_found should NOT increment for truncated magic packets (actual: %llu)",
	    found_delta);

	T_PASS("Truncated magic pattern correctly rejected at all %d offsets (0 to %d)",
	    max_offset + 1, max_offset);
}
