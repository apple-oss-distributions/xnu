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
#include "skywalk_test_common.h"
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"

#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
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
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

#define NX_PORT 3

static int utun_fd;
static char utun_ifname[IFNAMSIZ + 1];

static struct sktc_nexus_handles handles;
static channel_port port;

static struct in_addr our_ip, dst_ip, broad_ip, zero_ip;
static struct in_addr mask;

uint16_t sport = 0;
uint16_t dport = 4321;

static char *utun_addr_str = "10.0.250.1";
static char *peer_addr_str = "10.0.250.2";
static char *broad_addr_str = "10.0.250.255";

static char *utun_addr_str_v6 = "2607:1111::1111";
static char *peer_addr_str_v6 = "2607:2222::2222";
static char *zero_addr_str_v6 = "::";
static int addr_prefix_length = 128;    // 128 for POINTOPOINT UTUN
struct in6_addr our_ip_v6, dst_ip_v6, zero_ip_v6;

typedef int (^test_block_t)();
static int
test_block_with_leeway(int sec_leeway, test_block_t test_block)
{
	int ret;
	struct timeval start, now;
	gettimeofday(&start, NULL);

	do {
		ret = test_block();
		if (ret == 0) {
			break;
		}
		gettimeofday(&now, NULL);
	} while (now.tv_sec - start.tv_sec < sec_leeway);

	return ret;
}

static void
test_tcp_flow_send()
{
	struct sktu_flow *flow;
	my_payload tx_payload;
	struct sktu_frame *tx_frame;

	flow = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, 0, dport);
	sport = ntohs(flow->nfr.nfr_saddr.sin.sin_port);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "tcp_flow_send", sizeof(tx_payload.data));
	flow->create_output_frames(flow, &tx_frame, 1, &tx_payload, sizeof(tx_payload), NO_CSUM_OFFLOAD);

	sktu_dump_buffer(stderr, NULL, &tx_frame->bytes[0], tx_frame->len);

	sktu_channel_port_tx_burst(&port, &tx_frame, 1);

	test_block_with_leeway(10, ^(void) {
		struct sktu_frame *rx_frame;
		int ret = sktu_utun_fd_rx_burst(utun_fd, &rx_frame, 1);
		assert(ret == 1);

		sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
		my_payload rx_payload;
		uint32_t rx_payload_len = 0;
		ret = sktu_parse_tcp4_frame(rx_frame, &rx_payload, &rx_payload_len);
		if (ret != 0) {
		        return ret;
		}
		assert(rx_payload.packet_number == 0);
		assert(strcmp(rx_payload.data, tx_payload.data) == 0);

		sktu_frame_free(rx_frame);

		return 0;
	});

	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(flow);
}

static void
test_tcp_flow_receive()
{
	struct sktu_flow *flow;
	struct sktu_frame *tx_frame, *rx_frame;
	my_payload tx_payload;

	T_LOG("%s\n", __func__);
	flow = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, 0, dport);
	sport = ntohs(flow->nfr.nfr_saddr.sin.sin_port);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "tcp_flow_receive", sizeof(tx_payload.data));
	flow->create_input_frames(flow, &tx_frame, 1, &tx_payload, sizeof(tx_payload));

	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	int ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);

	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, flow->nfr.nfr_flow_uuid) == 0);
	my_payload rx_payload;
	uint32_t rx_payload_len = 0;
	ret = sktu_parse_tcp4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == 0);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	sktu_frame_free(rx_frame);
	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(flow);
}

static void
test_tcp_flow_listen(bool any_src_ip)
{
	struct sktu_flow *listener, *connection;
	my_payload rx_payload, tx_payload;
	struct sktu_frame *rx_frame, *tx_frame;

	T_LOG("%s\n", __func__);
	listener = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, any_src_ip ? &zero_ip : &our_ip, &zero_ip, IPPROTO_TCP, 0, 0);
	assert(listener);
	sport = listener->sport;
	dport = 1234;

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = __LINE__;
	strlcpy(tx_payload.data, "tcp_flow_connect", sizeof(tx_payload.data));
	sktu_create_tcp_frames(&tx_frame, 1, IPVERSION, &dst_ip, &our_ip, dport, sport, &tx_payload, sizeof(tx_payload), 1500, NO_CSUM_OFFLOAD);
	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	int ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);
	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, listener->nfr.nfr_flow_uuid) == 0);
	uint32_t rx_payload_len = 0;
	ret = sktu_parse_tcp4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == tx_payload.packet_number);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	// connect a new flow based on the listener flow
	connection = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, sport, dport);
	assert(connection);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 1;
	strlcpy(tx_payload.data, "tcp_flow_conected", sizeof(tx_payload.data));
	connection->create_input_frames(connection, &tx_frame, 1, &tx_payload, sizeof(tx_payload));
	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);
	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, connection->nfr.nfr_flow_uuid) == 0);
	ret = sktu_parse_tcp4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == 1);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	sktu_frame_free(rx_frame);
	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(connection);
	sktu_destroy_nexus_flow(listener);
}

static void
test_tcp_flow_listen_v6()
{
	struct sktu_flow *listener, *connection;
	my_payload rx_payload, tx_payload;
	struct sktu_frame *rx_frame, *tx_frame;

	T_LOG("%s\n", __func__);
	listener = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET6, &zero_ip_v6, &zero_ip_v6, IPPROTO_TCP, 0, 0);
	assert(listener);
	sport = listener->sport;
	dport = 1234;

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "tcp_flow_connect", sizeof(tx_payload.data));
	sktu_create_tcp_frames(&tx_frame, 1, IPVERSION, &dst_ip, &our_ip, dport, sport, &tx_payload, sizeof(tx_payload), 1500, NO_CSUM_OFFLOAD);
	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	int ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);
	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, listener->nfr.nfr_flow_uuid) == 0);
	uint32_t rx_payload_len = 0;
	ret = sktu_parse_tcp4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == 0);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	// connect a new flow based on the listener flow
	connection = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, sport, dport);
	assert(connection);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 1;
	strlcpy(tx_payload.data, "tcp_flow_conected", sizeof(tx_payload.data));
	connection->create_input_frames(connection, &tx_frame, 1, &tx_payload, sizeof(tx_payload));

	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);
	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, connection->nfr.nfr_flow_uuid) == 0);
	ret = sktu_parse_tcp4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == 1);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	sktu_frame_free(rx_frame);
	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(connection);
	sktu_destroy_nexus_flow(listener);
}

static void
test_ip_flow_send()
{
	struct sktu_flow *ip_flow;
	my_payload tx_payload;
	struct sktu_frame *rx_frame, *tx_frame;

	T_LOG("%s\n", __func__);
	ip_flow = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_IPEIP, 0, 0);
	assert(ip_flow);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "ip_send", sizeof(tx_payload.data));
	ip_flow->create_output_frames(ip_flow, &tx_frame, 1, &tx_payload, sizeof(tx_payload), false);

	sktu_channel_port_tx_burst(&port, &tx_frame, 1);

	int ret = sktu_utun_fd_rx_burst(utun_fd, &rx_frame, 1);
	assert(ret == 1);

	sktu_frame_free(rx_frame);
	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(ip_flow);
}

static void
test_ip_flow_receive()
{
	struct sktu_flow *ip_flow;
	my_payload tx_payload;
	struct sktu_frame *rx_frame, *tx_frame;

	T_LOG("%s\n", __func__);
	ip_flow = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_IPEIP, 0, 0);
	assert(ip_flow);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "ip_receive", sizeof(tx_payload.data));
	ip_flow->create_input_frames(ip_flow, &tx_frame, 1, &tx_payload, sizeof(tx_payload));

	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	int ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);

	sktu_frame_free(rx_frame);
	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(ip_flow);
}

static void
test_ip_flow_listen(bool any_src_ip)
{
	struct sktu_flow *ip_listener, *ip_connection;
	my_payload rx_payload, tx_payload;
	struct sktu_frame *rx_frame, *tx_frame;

	T_LOG("%s\n", __func__);
	ip_listener = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, any_src_ip ? &zero_ip : &our_ip, &zero_ip, IPPROTO_IPEIP, 0, 0);
	assert(ip_listener);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "ip_flow_connect", sizeof(tx_payload.data));
	ip_listener->create_input_frames(ip_listener, &tx_frame, 1, &tx_payload, sizeof(tx_payload));

	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	int ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);

	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, ip_listener->nfr.nfr_flow_uuid) == 0);
	uint32_t rx_payload_len = 0;
	ret = sktu_parse_ipv4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == 0);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	// connect a new flow based on the listener flow
	ip_connection = sktu_create_nexus_flow_with_nx_port(&handles, NX_PORT, AF_INET, &our_ip, &dst_ip, IPPROTO_IPEIP, 0, 0);
	assert(ip_connection);

	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 1;
	strlcpy(tx_payload.data, "ip_flow_conected", sizeof(tx_payload.data));
	ip_connection->create_input_frames(ip_connection, &tx_frame, 1, &tx_payload, sizeof(tx_payload));

	sktu_utun_fd_tx_burst(utun_fd, &tx_frame, 1);

	ret = sktu_channel_port_rx_burst(&port, &rx_frame, 1);
	assert(ret == 1);
	sktu_dump_buffer(stderr, "Received", &rx_frame->bytes, rx_frame->len);
	assert(uuid_compare(rx_frame->flow_uuid, ip_connection->nfr.nfr_flow_uuid) == 0);
	ret = sktu_parse_ipv4_frame(rx_frame, &rx_payload, &rx_payload_len);
	assert(ret == 0);
	assert(rx_payload.packet_number == 1);
	assert(strcmp(rx_payload.data, tx_payload.data) == 0);

	sktu_frame_free(rx_frame);
	sktu_frame_free(tx_frame);
	sktu_destroy_nexus_flow(ip_connection);
	sktu_destroy_nexus_flow(ip_listener);
}

static void
dev_init()
{
	int error;

	inet_pton(AF_INET, utun_addr_str, &our_ip);
	inet_pton(AF_INET, peer_addr_str, &dst_ip);
	inet_pton(AF_INET, broad_addr_str, &broad_ip);
	zero_ip = (struct in_addr){.s_addr = htonl(INADDR_ANY)};
	mask = sktc_make_in_addr(IN_CLASSC_NET);
	sktc_config_fsw_rx_agg_tcp(0);

	utun_fd = sktu_create_interface(SKTU_IFT_UTUN,
	    SKTU_IFF_ENABLE_NETIF | SKTU_IFF_NO_ATTACH_FSW);
	sktu_get_interface_name(SKTU_IFT_UTUN, utun_fd, utun_ifname);

	if (sktc_ifnet_add_addr(utun_ifname, &our_ip, &mask, &broad_ip) != 0) {
		err(EX_OSERR, "Failed to add address for %s", utun_ifname);
	}

	inet_pton(AF_INET6, utun_addr_str_v6, &our_ip_v6);
	inet_pton(AF_INET6, peer_addr_str_v6, &dst_ip_v6);
	inet_pton(AF_INET6, zero_addr_str_v6, &zero_ip_v6);
	error = sktc_ifnet_add_addr6(utun_ifname, &dst_ip_v6, &dst_ip_v6,
	    addr_prefix_length, 0);

	if (sktc_ifnet_add_scoped_default_route(utun_ifname, our_ip) != 0) {
		err(EX_OSERR, "Failed to add default route for %s\n", utun_ifname);
	}

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, utun_ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	error = os_nexus_controller_bind_provider_instance(handles.controller,
	    handles.fsw_nx_uuid, NX_PORT, getpid(), NULL, NULL, 0,
	    NEXUS_BIND_PID);
	SKTC_ASSERT_ERR(error == 0);

	sktu_channel_port_init(&port, handles.fsw_nx_uuid, NX_PORT, true, false,
	    false);
	assert(port.chan != NULL);
}

void
dev_fini(void)
{
	sktc_cleanup_flowswitch(&handles);
	close(utun_fd);
	sktc_restore_fsw_rx_agg_tcp();
}

int
skt_flowlookup_main(int argc, char *argv[])
{
	atexit(dev_fini);
	dev_init();

	test_tcp_flow_send();
	test_tcp_flow_receive();
	test_tcp_flow_listen(true);
	test_tcp_flow_listen(false);
	test_tcp_flow_listen_v6();
	test_ip_flow_send();
	test_ip_flow_receive();
	test_ip_flow_listen(true);
	test_ip_flow_listen(false);

	return 0;
}

struct skywalk_test skt_flowlookup = {
	.skt_testname = "flowlookup",
	.skt_testdesc = "test flow lookup by send/receive of packets",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	.skt_main = skt_flowlookup_main,
};
