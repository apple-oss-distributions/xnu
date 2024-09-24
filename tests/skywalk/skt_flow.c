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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

#define MULTICAST_IP "239.0.0.1"

const char * ifname;
struct in_addr our_ip, dst_ip, zero_ip, nowhere_ip, multicast_ip, lo_ip;
struct in_addr our_mask;
struct sktc_nexus_handles handles;
uuid_t ipflow;

static void
skt_flow_add_del(bool expect_success, sa_family_t af,
    void *src, void *dst, uint8_t protocol, uint16_t sport, uint16_t dport)
{
	struct sktu_flow *flow;

	flow = sktu_create_nexus_flow(&handles, af, src, dst, protocol, sport, dport);

	if (expect_success) {
		assert(flow);
		sktu_destroy_nexus_flow(flow);
	} else {
		assert(!flow);
	}
}

static void
skt_flow_req_should_success(sa_family_t af, void *src, void *dst,
    uint8_t protocol, uint16_t sport, uint16_t dport)
{
	skt_flow_add_del(true, af, src, dst, protocol, sport, dport);
}

static void
skt_flow_req_should_fail(sa_family_t af, void *src, void *dst,
    uint8_t protocol, uint16_t sport, uint16_t dport)
{
	skt_flow_add_del(false, af, src, dst, protocol, sport, dport);
}

static void
skt_flow_req_low_latency(sa_family_t af, void *src, void *dst,
    uint8_t protocol, uint16_t sport, uint16_t dport)
{
	struct sktu_flow *regular_flow_0, *regular_flow_1;
	struct sktu_flow *low_latency_flow_0, *low_latency_flow_1;

	/* add a regular flow */
	regular_flow_0 = sktu_create_nexus_flow(&handles, af, src, dst,
	    protocol, sport, dport);
	assert(regular_flow_0);

	/* add another regular flow */
	sport++;
	dport++;
	regular_flow_1 = sktu_create_nexus_flow(&handles, af, src, dst,
	    protocol, sport, dport);
	assert(regular_flow_1);

	/* Both regular flows should get the same fsw port */
	assert(regular_flow_0->nfr.nfr_nx_port ==
	    regular_flow_1->nfr.nfr_nx_port);

	/* add a low-latency flow */
	sport++;
	dport++;
	low_latency_flow_0 = sktu_create_nexus_low_latency_flow(&handles,
	    af, src, dst, protocol, sport, dport);
	assert(low_latency_flow_0);

	/* low-latency flow should get a different fsw port */
	assert(low_latency_flow_0->nfr.nfr_nx_port !=
	    regular_flow_0->nfr.nfr_nx_port);

	/* add another low-latency flow */
	sport++;
	dport++;
	low_latency_flow_1 = sktu_create_nexus_low_latency_flow(&handles,
	    af, src, dst, protocol, sport, dport);
	assert(low_latency_flow_1);

	/* Both low-latency flows should get the same fsw port */
	assert(low_latency_flow_0->nfr.nfr_nx_port ==
	    low_latency_flow_1->nfr.nfr_nx_port);

	sktu_destroy_nexus_flow(regular_flow_0);
	sktu_destroy_nexus_flow(regular_flow_1);
	sktu_destroy_nexus_flow(low_latency_flow_0);
	sktu_destroy_nexus_flow(low_latency_flow_1);
}

int
skt_flow_req_ll_main(int argc, char *argv[])
{
	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	dst_ip = sktc_feth1_in_addr();

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	// Low latency requests
	T_LOG("\nTesting with low latency flow requests\n\n");
	skt_flow_req_low_latency(AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, 1234, 1234);

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

int
skt_flow_config_main(int argc, char *argv[])
{
	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	dst_ip = sktc_feth1_in_addr();

	T_LOG("\nTesting flow config API\n");

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	T_LOG("add a flow\n");
	struct sktu_flow *flow;
	flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, 1234, 1234);
	assert(flow);

	T_LOG("verify flow default (negative) NOWAKEFROMSLEEP flag\n");
	struct sk_stats_flow sf;
	int ret = sktu_get_nexus_flow_stats(flow->uuid, &sf);
	assert(ret == 0);
	assert((sf.sf_flags & SFLOWF_NOWAKEFROMSLEEP) == 0);

	uuid_t rand_uuid;
	do {
		uuid_generate(rand_uuid);
	} while (uuid_compare(rand_uuid, flow->uuid) == 0);

	// should return ENOENT with mismatching flow uuid
	T_LOG("verify ENOENT with INVALID flow\n");
	ret = os_nexus_flow_set_wake_from_sleep(handles.fsw_nx_uuid, rand_uuid, false);
	assert(ret != 0);
	assert(errno == ENOENT);

	/* should fail with EPERM from another PID */
	T_LOG("verify EPERM with INVALID PID\n");
	int child_pid;
	if ((child_pid = fork()) == -1) {
		SKT_LOG("fork: %s\n", strerror(errno));
		exit(1);
	}
	if (child_pid == 0) {
		ret = os_nexus_flow_set_wake_from_sleep(handles.fsw_nx_uuid, flow->uuid, false);
		exit(errno);
	} else {
		int child_status;
		wait(&child_status);
		assert(WIFEXITED(child_status));
		assert(WEXITSTATUS(child_status) == EPERM);
	}

	T_LOG("verify setting flow NOWAKEFROMSLEEP\n");
	ret = os_nexus_flow_set_wake_from_sleep(handles.fsw_nx_uuid, flow->uuid, false);
	assert(ret == 0);

	ret = sktu_get_nexus_flow_stats(flow->uuid, &sf);
	assert(ret == 0);
	assert((sf.sf_flags & SFLOWF_NOWAKEFROMSLEEP) != 0);

	T_LOG("verify clearing flow NOWAKEFROMSLEEP\n");
	ret = os_nexus_flow_set_wake_from_sleep(handles.fsw_nx_uuid, flow->uuid, true);
	assert(ret == 0);

	ret = sktu_get_nexus_flow_stats(flow->uuid, &sf);
	assert(ret == 0);
	assert((sf.sf_flags & SFLOWF_NOWAKEFROMSLEEP) == 0);

	T_LOG("verify EPERM with netif nexus\n");
	ret = os_nexus_flow_set_wake_from_sleep(handles.netif_nx_uuid, flow->uuid, true);
	assert(ret != 0);
	assert(errno == EPERM);

	T_LOG("\n");

	return 0;
}

int
skt_flow_req_main(int argc, char *argv[])
{
	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	dst_ip = sktc_feth1_in_addr();
	zero_ip = (struct in_addr){.s_addr = htonl(INADDR_ANY)};
	nowhere_ip = sktc_nowhere_in_addr();
	multicast_ip.s_addr = inet_addr(MULTICAST_IP);
	inet_pton(AF_INET, "127.0.0.1", &lo_ip.s_addr);

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	// Valid requests
	T_LOG("\nTesting with valid flow requests\n\n");

	// 5 tuple nexus chosen src ip/port
	skt_flow_req_should_success(AF_INET, &zero_ip, &dst_ip, IPPROTO_TCP, 0, 1234);
	// 5 tuple fully specified
	skt_flow_req_should_success(AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, 1234, 1234);
	// Custom IP protocol (connect mode)
	skt_flow_req_should_success(AF_INET, &our_ip, &dst_ip, IPPROTO_IPEIP, 0, 0);
	// Custom IP protocol (listen mode)
	skt_flow_req_should_success(AF_INET, &our_ip, &zero_ip, IPPROTO_IPEIP, 0, 0);
	// 3 tuple TCP listener with specified local ip
	skt_flow_req_should_success(AF_INET, &our_ip, &zero_ip, IPPROTO_TCP, 1234, 0);
	// 2 tuple TCP listener
	skt_flow_req_should_success(AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, 1234, 0);

	// Invalid requests
	T_LOG("\nTesting with INVALID flow requests, should fail them\n\n");

	// 5 tuple zero dst ip
	skt_flow_req_should_fail(AF_INET, &our_ip, &zero_ip, IPPROTO_TCP, 1234, 1234);
	// 5 tuple multicast src ip
	skt_flow_req_should_fail(AF_INET, &multicast_ip, &dst_ip, IPPROTO_TCP, 1234, 1234);
	// 5 tuple loopback
	skt_flow_req_should_fail(AF_INET, &our_ip, &lo_ip, IPPROTO_TCP, 1234, 1234);
	// 3 tuple invalid src ip
	skt_flow_req_should_fail(AF_INET, &nowhere_ip, &zero_ip, IPPROTO_TCP, 1234, 0);
	// 3 tuple multicast src ip
	skt_flow_req_should_fail(AF_INET, &multicast_ip, &zero_ip, IPPROTO_TCP, 1234, 0);

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

void
skt_flow_req_net_init(void)
{
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART);
}

void
skt_flow_req_net_fini(void)
{
	sktc_ifnet_feth_pair_destroy();
}

struct skywalk_test skt_flow_req = {
	"flowreq", "test skywalk flow request api",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_flow_req_main, { NULL },
	skt_flow_req_net_init, skt_flow_req_net_fini,
};

struct skywalk_test skt_flow_req_ll = {
	"flowreqll", "test skywalk flow request api for low latency flows",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS | SK_FEATURE_DEV_OR_DEBUG,
	skt_flow_req_ll_main, { NULL },
	skt_flow_req_net_init, skt_flow_req_net_fini,
};

struct skywalk_test skt_flow_config = {
	"flowconfig", "test skywalk flow config api",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_flow_config_main, { NULL },
	skt_flow_req_net_init, skt_flow_req_net_fini,
};
