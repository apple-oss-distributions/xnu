/*
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
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

#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <net/if_utun.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <darwintest.h>

#include "skywalk_test_common.h"
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"

#define NX_PORT 3
#define BUF_SIZE 8192
#define MAX_FRAMES 8

typedef size_t (*reass_packet_builder_fn)(uint8_t *buf);
typedef int (*reass_packet_matcher_fn)(uint8_t *pkt_out, size_t len_out,
    uint8_t *pkt_in, size_t len_in);

static int utun_fd;
static struct sktc_nexus_handles nexus;
static channel_port port;

static char utun_ifname[IFNAMSIZ + 1];

// to select one of the following global/linklocal addr
static char *utun_addr_str = NULL;
static char *peer_addr_str = NULL;

static char *our_ip_str = "192.168.255.2";
static char *dst_ip_str = "10.0.0.1";
static char *broad_ip_str = "192.168.255.255";

static char *utun_global_addr_str = "2607:1111::1111";
static char *peer_global_addr_str = "2607:2222::2222";

static char *utun_linklocal_addr_str = "fe80::1111";
static char *peer_linklocal_addr_str = "fe80::2222";

static int addr_prefix_length = 128;    // 128 for POINTOPOINT UTUN

struct timeval timeout = {
	.tv_sec = 10,
	.tv_usec = 0,
};

static void
die_perror(const char *str)
{
	perror(str);
	assert(0);
}

void
reass_init()
{
	int error;

	utun_fd = sktu_create_interface(SKTU_IFT_UTUN, SKTU_IFF_ENABLE_NETIF);

	sktu_get_interface_name(SKTU_IFT_UTUN, utun_fd, utun_ifname);

	error = fcntl(utun_fd, F_SETFD, FD_CLOEXEC);
	if (error != 0) {
		die_perror("FD_CLOEXEC");
	}

	struct in6_addr utun_addr, dst_addr;
	inet_pton(AF_INET6, utun_addr_str, &utun_addr);
	inet_pton(AF_INET6, peer_addr_str, &dst_addr);
	error = sktc_ifnet_add_addr6(utun_ifname, &utun_addr, &dst_addr,
	    addr_prefix_length, 0);
	assert(error == 0);
}

void
reass_fini(void)
{
	close(utun_fd);
}

void
reass_interface_send(reass_packet_builder_fn builder)
{
	uint8_t pkt_in[BUF_SIZE];

	size_t len_in = builder(pkt_in);

	T_LOG("sending to utun, len %ld\n", len_in);
	sktu_dump_buffer(stderr, NULL, pkt_in, len_in);
	int i = 0;
	while (i++ < 1000) {
		write(utun_fd, pkt_in, len_in);
	}
}

void
reass_interface_send_rece(reass_packet_builder_fn builder,
    reass_packet_matcher_fn matcher, struct timeval *allowed)
{
	struct timeval start, now, elapsed, left;
	fd_set readfds, errorfds;
	uint8_t pkt_in[BUF_SIZE];
	uint8_t pkt_out[BUF_SIZE];
	size_t len_in, len_out;
	int retval;

	len_in = builder(pkt_in);

	T_LOG("sending to utun, len %ld\n", len_in);
	sktu_dump_buffer(stderr, NULL, pkt_in, len_in);
	write(utun_fd, pkt_in, len_in);

	if (gettimeofday(&start, NULL) != 0) {
		die_perror("gettimeofday");
	}
	left = *allowed;

	while (1) {
		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(utun_fd, &readfds);
		FD_SET(utun_fd, &errorfds);

		retval = select(utun_fd + 1, &readfds, NULL, &errorfds, &left);
		if (retval == -1) {
			die_perror("select()");
		}

		if (!FD_ISSET(utun_fd, &readfds) && retval == 0) { // timeout
			T_LOG("recv timeout\n");
			assert(0);
		}

		assert(!FD_ISSET(utun_fd, &errorfds));
		assert(retval == 1);

		if (FD_ISSET(utun_fd, &readfds)) {
			len_out = read(utun_fd, pkt_out, BUF_SIZE);
			if (len_out < 1) {
				T_LOG("utun read error\n");
				assert(0);
			}
		}

		T_LOG("read from utun, len %ld\n", len_out);
		sktu_dump_buffer(stderr, NULL, pkt_out, len_out);

		if (matcher(pkt_out, len_out, pkt_in, len_in) == 0) {
			break;
		}

		if (gettimeofday(&now, NULL) != 0) {
			die_perror("gettimeofday");
		}

		timersub(&now, &start, &elapsed);
		timersub(allowed, &elapsed, &left);
	}
}

void
reass_common(channel_port *ch_port, struct sktu_flow *flow, void *data,
    size_t data_len)
{
	struct sktu_frame *rx_frames[MAX_FRAMES];
	struct sktu_frame *tx_frames[MAX_FRAMES];
	size_t n_rx_frames;
	size_t n_tx_frames;

	n_tx_frames = flow->create_input_frames(flow, tx_frames, MAX_FRAMES,
	    data, data_len);

	sktu_utun_fd_tx_burst(utun_fd, tx_frames, n_tx_frames);

	n_rx_frames = sktu_channel_port_rx_burst(ch_port, rx_frames, MAX_FRAMES);

	// verify rx_frames == tx_frames
	assert(n_rx_frames == n_tx_frames);
	assert(rx_frames[0]->len == tx_frames[0]->len);
	assert(memcmp(rx_frames[0]->bytes, tx_frames[0]->bytes,
	    tx_frames[0]->len) == 0);
	assert(rx_frames[1]->len == tx_frames[1]->len);
	assert(memcmp(rx_frames[1]->bytes, tx_frames[1]->bytes,
	    tx_frames[1]->len) == 0);

	sktu_frames_free(rx_frames, n_rx_frames);
	sktu_frames_free(tx_frames, n_tx_frames);
}

size_t
bad_fraglen_build(uint8_t *buf)
{
	size_t i, len = 0;
	size_t plen = 35;
	uint32_t address_family = htonl(AF_INET6);

	bcopy(&address_family, buf, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	len += sizeof(uint32_t);

	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_FRAGMENT;
	ip6->ip6_hlim = IPV6_DEFHLIM;
	ip6->ip6_plen = htons(sizeof(struct ip6_frag) + plen);

	inet_pton(AF_INET6, utun_addr_str, &ip6->ip6_dst);
	inet_pton(AF_INET6, peer_addr_str, &ip6->ip6_src);

	buf += sizeof(struct ip6_hdr);
	len += sizeof(struct ip6_hdr);

	struct ip6_frag *ip6f = (struct ip6_frag *)buf;
	ip6f->ip6f_ident = 0xee;
	ip6f->ip6f_nxt = IPPROTO_UDP;
	ip6f->ip6f_offlg = 0;
	ip6f->ip6f_offlg |= IP6F_MORE_FRAG;

	buf += sizeof(struct ip6_frag);
	len += sizeof(struct ip6_frag);

	for (i = 0; i < plen; i++) {
		buf[i] = 'f';
	}

	buf += plen;
	len += plen;

	return len;
}

int
bad_fraglen_match(uint8_t *pkt_out, size_t len_out, uint8_t *pkt_in, size_t len_in)
{
	uint8_t *scan = pkt_out;
	uint32_t af = ntohl(*(uint32_t *)pkt_out);

	if (af != AF_INET6) {
		T_LOG("%s fails: af != AF_INET6", __func__);
		return -1;
	}

	scan += sizeof(af);
	struct ip6_hdr *ip6 = (struct ip6_hdr *)scan;

	//TODO check src/dst, etc.

	if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
		T_LOG("%s fails: ip6_nxt != IPPROTO_ICMPV6", __func__);
		return -1;
	}

	scan += sizeof(struct ip6_hdr);
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)scan;

	assert(icmp6->icmp6_type == ICMP6_PARAM_PROB);
	assert(icmp6->icmp6_code == ICMP6_PARAMPROB_HEADER);
	assert(icmp6->icmp6_pptr == htonl(__builtin_offsetof(struct ip6_hdr,
	    ip6_plen)));

	return 0;
}

size_t
timeout_build(uint8_t *buf)
{
	size_t i, len = 0;
	size_t plen = 128;
	uint32_t address_family = htonl(AF_INET6);

	bcopy(&address_family, buf, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	len += sizeof(uint32_t);

	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_FRAGMENT;
	ip6->ip6_hlim = IPV6_DEFHLIM;
	ip6->ip6_plen = htons(sizeof(struct ip6_frag) + plen);

	inet_pton(AF_INET6, utun_addr_str, &ip6->ip6_dst);
	inet_pton(AF_INET6, peer_addr_str, &ip6->ip6_src);

	buf += sizeof(struct ip6_hdr);
	len += sizeof(struct ip6_hdr);

	struct ip6_frag *ip6f = (struct ip6_frag *)buf;
	ip6f->ip6f_ident = 0xee;
	ip6f->ip6f_nxt = IPPROTO_UDP;
	ip6f->ip6f_offlg = 0;
	ip6f->ip6f_offlg |= IP6F_MORE_FRAG;

	buf += sizeof(struct ip6_frag);
	len += sizeof(struct ip6_frag);

	for (i = 0; i < plen; i++) {
		buf[i] = 'f';
	}

	buf += plen;
	len += plen;

	return len;
}

int
timeout_match(uint8_t *pkt_out, size_t len_out, uint8_t *pkt_in, size_t len_in)
{
	uint8_t *scan = pkt_out;
	uint32_t af = ntohl(*(uint32_t *)pkt_out);

	if (af != AF_INET6) {
		T_LOG("%s fails: af != AF_INET6", __func__);
		return -1;
	}

	scan += sizeof(af);
	struct ip6_hdr *ip6 = (struct ip6_hdr *)scan;

	//TODO check src/dst, etc.

	if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
		T_LOG("%s fails: ip6_nxt != IPPROTO_ICMPV6", __func__);
		return -1;
	}

	scan += sizeof(struct ip6_hdr);
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)scan;

	assert(icmp6->icmp6_type == ICMP6_TIME_EXCEEDED);
	assert(icmp6->icmp6_code == ICMP6_TIME_EXCEED_REASSEMBLY);
	assert(icmp6->icmp6_pptr == 0);

	return 0;
}

#define ADDCARRY(_x)  do {                                              \
	while (((_x) >> 16) != 0)                                       \
	        (_x) = ((_x) >> 16) + ((_x) & 0xffff);                  \
} while (0)

size_t
atomic_build(uint8_t *buf)
{
	size_t i, len = 0;
	size_t plen, dlen = 16;
	struct in6_addr src, dst;
	uint32_t address_family = htonl(AF_INET6);

	bzero(buf, BUF_SIZE);

	bcopy(&address_family, buf, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	len += sizeof(uint32_t);

	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_FRAGMENT;
	ip6->ip6_hlim = IPV6_DEFHLIM;
	plen = sizeof(struct ip6_frag) + sizeof(struct icmp6_hdr) + dlen;
	ip6->ip6_plen = htons(plen);

	inet_pton(AF_INET6, peer_addr_str, &src);
	bcopy(&src, &ip6->ip6_src, sizeof(src));
	inet_pton(AF_INET6, utun_addr_str, &dst);
	bcopy(&dst, &ip6->ip6_dst, sizeof(dst));

	buf += sizeof(struct ip6_hdr);
	len += sizeof(struct ip6_hdr);

	struct ip6_frag *ip6f = (struct ip6_frag *)buf;
	ip6f->ip6f_ident = 0xee;
	ip6f->ip6f_nxt = IPPROTO_ICMPV6;
	ip6f->ip6f_offlg = 0;

	buf += sizeof(struct ip6_frag);
	len += sizeof(struct ip6_frag);

	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;

	buf += sizeof(struct icmp6_hdr);
	len += sizeof(struct icmp6_hdr);

	for (i = 0; i < dlen; i++) {
		buf[i] = 'f';
	}

	uint16_t csum;
	icmp6->icmp6_cksum = in6_pseudo(&src, &dst,
	    htonl(IPPROTO_ICMPV6 + sizeof(struct icmp6_hdr) + dlen));
	csum = os_inet_checksum(icmp6, sizeof(struct icmp6_hdr) + dlen, 0);
	csum = ~csum;
	if (csum == 0) {
		csum = 0xffff;
	}
	icmp6->icmp6_cksum = csum;

	buf += dlen;
	len += dlen;

	return len;
}

int
atomic_match(uint8_t *pkt_out, size_t len_out, uint8_t *pkt_in, size_t len_in)
{
	uint8_t *scan = pkt_out;
	uint32_t af = ntohl(*(uint32_t *)pkt_out);

	if (af != AF_INET6) {
		T_LOG("%s fails: af != AF_INET6", __func__);
		return -1;
	}

	scan += sizeof(af);
	struct ip6_hdr *ip6 = (struct ip6_hdr *)scan;

	//TODO check src/dst, etc.

	if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
		T_LOG("%s fails: ip6_nxt != IPPROTO_ICMPV6", __func__);
		return -1;
	}

	scan += sizeof(struct ip6_hdr);
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)scan;

	assert(icmp6->icmp6_type == ICMP6_ECHO_REPLY);
	assert(icmp6->icmp6_code == 0);

	return 0;
}

size_t
queue_limit_build(uint8_t *buf)
{
	size_t len = 0;
	struct in6_addr src, dst;
	uint32_t address_family = htonl(AF_INET6);

	bzero(buf, BUF_SIZE);

	bcopy(&address_family, buf, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	len += sizeof(uint32_t);

	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_FRAGMENT;
	ip6->ip6_hlim = IPV6_DEFHLIM;
	ip6->ip6_plen = htons(sizeof(struct ip6_frag));

	inet_pton(AF_INET6, peer_addr_str, &src);
	bcopy(&src, &ip6->ip6_src, sizeof(src));
	inet_pton(AF_INET6, utun_addr_str, &dst);
	bcopy(&dst, &ip6->ip6_dst, sizeof(dst));

	buf += sizeof(struct ip6_hdr);
	len += sizeof(struct ip6_hdr);

	struct ip6_frag *ip6f = (struct ip6_frag *)buf;
	ip6f->ip6f_ident = 0xee;
	ip6f->ip6f_nxt = IPPROTO_NONE;
	ip6f->ip6f_offlg = htons((u_short)((2048) & ~7));

	buf += sizeof(struct ip6_frag);
	len += sizeof(struct ip6_frag);

	return len;
}

void
reass_lower_timeout(int *old_timeout, int new_timeout)
{
	size_t old_size = sizeof(*old_timeout);
	int error;

	error = sysctlbyname("kern.skywalk.flowswitch.ipfm_frag_ttl",
	    old_timeout, &old_size, &new_timeout, sizeof(int));
	if (error) {
		die_perror("kern.skywalk.flowswitch.ipfm_frag_ttl");
	}
}

void
reass_restore_timeout(int old_timeout)
{
	int error;

	error = sysctlbyname("kern.skywalk.flowswitch.ipfm_frag_ttl",
	    NULL, NULL, &old_timeout, sizeof(int));
	if (error) {
		die_perror("kern.skywalk.flowswitch.ipfm_frag_ttl");
	}
}

int
skt_reass_main(int argc, char *argv[])
{
	int error;

	// setup full interface
	utun_fd = sktu_create_interface(SKTU_IFT_UTUN,
	    SKTU_IFF_ENABLE_NETIF | SKTU_IFF_NO_ATTACH_FSW);

	sktu_get_interface_name(SKTU_IFT_UTUN, utun_fd, utun_ifname);

	struct in_addr our_ip, mask, broad_ip, dst_ip;
	struct in6_addr our_ip_v6, dst_ip_v6;

	inet_pton(AF_INET, our_ip_str, &our_ip);
	inet_pton(AF_INET, dst_ip_str, &dst_ip);
	inet_pton(AF_INET, broad_ip_str, &broad_ip);
	mask = sktc_make_in_addr(IN_CLASSC_NET);
	sktc_config_fsw_rx_agg_tcp(0);

	if (sktc_ifnet_add_addr(utun_ifname, &our_ip, &mask, &broad_ip) != 0) {
		err(EX_OSERR, "Failed to add address for %s", utun_ifname);
	}

	inet_pton(AF_INET6, utun_global_addr_str, &our_ip_v6);
	inet_pton(AF_INET6, peer_global_addr_str, &dst_ip_v6);
	error = sktc_ifnet_add_addr6(utun_ifname, &our_ip_v6, &dst_ip_v6,
	    addr_prefix_length, 0);

	if (sktc_ifnet_add_scoped_default_route(utun_ifname, our_ip) != 0) {
		err(EX_OSERR, "Failed to add default route: %s\n", utun_ifname);
	}

	bzero(&nexus, sizeof(nexus));
	strlcpy(nexus.netif_ifname, utun_ifname, sizeof(nexus.netif_ifname));
	nexus.netif_addr = our_ip;
	nexus.netif_mask = mask;
	sktc_create_flowswitch_no_address(&nexus, -1, -1, -1, -1, 0);

	error = os_nexus_controller_bind_provider_instance(nexus.controller,
	    nexus.fsw_nx_uuid, NX_PORT, getpid(), NULL, NULL, 0,
	    NEXUS_BIND_PID);
	SKTC_ASSERT_ERR(error == 0);

	struct sktu_flow *flow_ipv4, *flow_ipv6;

	flow_ipv4 = sktu_create_nexus_flow_with_nx_port(&nexus, NX_PORT,
	    AF_INET, &our_ip, &dst_ip, IPPROTO_UDP, 0, 1234);
	assert(flow_ipv4);

	flow_ipv6 = sktu_create_nexus_flow_with_nx_port(&nexus, NX_PORT,
	    AF_INET6, &our_ip_v6, &dst_ip_v6, IPPROTO_UDP, 0, 1234);
	assert(flow_ipv4);

	assert(flow_ipv4->nfr.nfr_nx_port == flow_ipv6->nfr.nfr_nx_port);

	sktu_channel_port_init(&port, nexus.fsw_nx_uuid,
	    flow_ipv4->nfr.nfr_nx_port, true, false, false);
	assert(port.chan != NULL);

	uint8_t buf[8192];
	// test both 8-byte-multiple and non 8-byte-multple sizes
	reass_common(&port, flow_ipv4, buf, 2000);
	reass_common(&port, flow_ipv4, buf, 2001);
	reass_common(&port, flow_ipv4, buf, 8000);
	reass_common(&port, flow_ipv4, buf, 8001);
	reass_common(&port, flow_ipv6, buf, 2000);
	reass_common(&port, flow_ipv6, buf, 2001);
	reass_common(&port, flow_ipv6, buf, 8000);
	reass_common(&port, flow_ipv6, buf, 8001);

	sktu_destroy_nexus_flow(flow_ipv4);
	sktu_destroy_nexus_flow(flow_ipv6);

	reass_fini();

	return 0;
}

int
skt_reass_main_default_setting(int argc, char *argv[])
{
	if (!sktc_is_netagent_enabled()) {
		T_LOG("netagent not enabled on this platform, skip\n");
		return 0;
	}

	if (!sktc_is_ip_reass_enabled()) {
		T_LOG("ip reass not enabled on this platform, skip\n");
		return 0;
	}

	return skt_reass_main(argc, argv);
}

#define REASS_TEST_GLOBAL(builder, matcher, timeout)    \
	utun_addr_str = utun_global_addr_str;           \
	peer_addr_str = peer_global_addr_str;           \
	reass_init();                                   \
	reass_interface_send_rece(builder, matcher, &timeout);    \
	reass_fini();

#define REASS_TEST_LINKLOCAL(builder, matcher, timeout) \
	utun_addr_str = utun_linklocal_addr_str;        \
	peer_addr_str = peer_linklocal_addr_str;        \
	reass_init();                                   \
	reass_interface_send_rece(builder, matcher, &timeout);    \
	reass_fini();

#define REASS_TEST_ALL(builder, matcher, timeout)       \
	REASS_TEST_GLOBAL(builder, matcher, timeout)    \
	sleep(1);                                       \
	REASS_TEST_LINKLOCAL(builder, matcher, timeout)


#define REASS_FUZZ_GLOBAL(builder)                      \
	utun_addr_str = utun_global_addr_str;           \
	peer_addr_str = peer_global_addr_str;           \
	reass_init();                                   \
	reass_interface_send(builder);                            \
	reass_fini();

#define REASS_FUZZ_LINKLOCAL(builder)                   \
	utun_addr_str = utun_linklocal_addr_str;        \
	peer_addr_str = peer_linklocal_addr_str;        \
	reass_init();                                   \
	reass_interface_send(builder);                            \
	reass_fini();

#define REASS_FUZZ_ALL(builder)                         \
	REASS_FUZZ_GLOBAL(builder)                      \
	sleep(1);                                       \
	REASS_FUZZ_LINKLOCAL(builder)

int
skt_reass_timeout_main(int argc, char *argv[])
{
	int old_timeout;
	int new_timeout = 5;

	reass_lower_timeout(&old_timeout, new_timeout);

	REASS_TEST_ALL(timeout_build, timeout_match, timeout);

	reass_restore_timeout(old_timeout);

	return 0;
}

int
skt_reass_bad_fraglen_main(int argc, char *argv[])
{
	REASS_TEST_ALL(bad_fraglen_build, bad_fraglen_match, timeout);
	return 0;
}

int
skt_reass_atomic_main(int argc, char *argv[])
{
	REASS_TEST_ALL(atomic_build, atomic_match, timeout);
	return 0;
}

int
skt_reass_fuzz_queue_limit_main(int argc, char *argv[])
{
	REASS_FUZZ_ALL(queue_limit_build);
	return 0;
}

struct skywalk_test skt_reass_default_setting = {
	"reass_default_setting",
	"UDP fragmentation reassembly (channel flow Rx) (without forcing ip_reass sysctl)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reass_main_default_setting, { NULL },
	NULL, NULL,
};

struct skywalk_test skt_reass = {
	"reass",
	"UDP fragmentation reassembly (channel flow Rx)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reass_main, { NULL },
	sktc_enable_ip_reass, sktc_restore_ip_reass,
};

struct skywalk_test skt_reass_timeout = {
	"reass_timeout",
	"send partial fragment to flowswitch and check for ICMPv6 time exceeded reply",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reass_timeout_main, { NULL },
	sktc_enable_ip_reass, sktc_restore_ip_reass,
};

struct skywalk_test skt_reass_bad_fraglen = {
	"reass_bad_fraglen",
	"send fragment with bad fragment length (!= 8*) to flowswitch and check for ICMPv6 param header reply",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reass_bad_fraglen_main, { NULL },
	sktc_enable_ip_reass, sktc_restore_ip_reass,
};

struct skywalk_test skt_reass_atomic = {
	"reass_atomic",
	"send atomic ICMP echo fragment to flowswitch and check for reply",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reass_atomic_main, { NULL },
	sktc_enable_ip_reass, sktc_restore_ip_reass,
};

struct skywalk_test skt_reass_fuzz_queue_limit = {
	"reass_fuzz_queue_limit",
	"fuzz flowswitch to hit fragment limit",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reass_fuzz_queue_limit_main, { NULL },
	sktc_enable_ip_reass, sktc_restore_ip_reass,
};
