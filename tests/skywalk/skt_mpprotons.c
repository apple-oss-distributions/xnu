/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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

#include <err.h>
#include <assert.h>
#include <errno.h>
#include <semaphore.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

static const char * ifname;
static struct in_addr our_ip, dst_ip, zero_ip, nowhere_ip;
static struct in_addr our_mask;
static struct sktc_nexus_handles handles;

#define SEM_1ST_FLOW_CREATED "/skt_mpprotons_1FC"
#define SEM_2ND_FLOW_FAILED "/skt_mpprotons_2FF"

static void
skt_flow_req_should_succeed(sa_family_t af, void *src, void *dst,
    uint8_t protocol, uint16_t sport, uint16_t dport)
{
	struct sktu_flow *flow;

	flow = sktu_create_nexus_flow(&handles, af, src, dst, protocol, sport, dport);
	assert(flow);
}

static void
skt_flow_req_should_fail(sa_family_t af, void *src, void *dst,
    uint8_t protocol, uint16_t sport, uint16_t dport)
{
	struct sktu_flow *flow;

	flow = sktu_create_nexus_flow(&handles, af, src, dst, protocol, sport, dport);
	assert(!flow);
}

static int
skt_protons_main(int argc, char *argv[])
{
	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	dst_ip = sktc_feth1_in_addr();
	zero_ip = (struct in_addr){.s_addr = htonl(INADDR_ANY)};
	nowhere_ip = sktc_nowhere_in_addr();

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_TCP, 0, 0);
	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_UDP, 0, 0);
	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_TTP, 1, 0);
	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_TTP, 0, 1);
	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_TTP, 1, 1);
	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_RAW, 0, 0);

	skt_flow_req_should_succeed(AF_INET, &our_ip, &dst_ip, IPPROTO_TTP, 0, 0);
	skt_flow_req_should_succeed(AF_INET, &our_ip, &nowhere_ip, IPPROTO_TTP, 0, 0);
	skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_TTP, 0, 0);

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

static void
skt_protons_net_init(void)
{
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART);
}

static void
skt_protons_net_fini(void)
{
	sktc_ifnet_feth_pair_destroy();

	// cleanup any leftovers
	sem_unlink(SEM_1ST_FLOW_CREATED);
	sem_unlink(SEM_2ND_FLOW_FAILED);
}

struct skywalk_test skt_protons = {
	.skt_testname = "protons",
	.skt_testdesc = "test skywalk protocol namespace",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	.skt_main = skt_protons_main,
	.skt_argv = { NULL },
	.skt_init = skt_protons_net_init,
	.skt_fini = skt_protons_net_fini,
};

/****************************************************************/

static int
skt_mpprotons_main(int argc, char *argv[])
{
	char buf[1] = { 0 };
	const char * ifname;
	struct in_addr our_ip, peer_ip;
	struct in_addr our_mask;
	ssize_t ret;

	assert(!strcmp(argv[3], "--child"));
	int child = atoi(argv[4]);
	T_LOG("in child %d\n", child);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
	} else {
		child = 1;
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
	}
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	sem_t *sem_flow_created = sem_open(SEM_1ST_FLOW_CREATED, O_CREAT, 0660, 0);
	sem_t *sem_dup_flow_failed = sem_open(SEM_2ND_FLOW_FAILED, O_CREAT, 0660, 0);
	if (sem_flow_created == SEM_FAILED || sem_dup_flow_failed == SEM_FAILED) {
		err(EX_OSERR, "sem open failed");
	}

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);

	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);

	if (child == 0) {
		skt_flow_req_should_succeed(AF_INET, &our_ip, &dst_ip, IPPROTO_IPEIP, 0, 0);
		sem_post(sem_flow_created);
		sem_wait(sem_dup_flow_failed);
		sem_post(sem_dup_flow_failed);
	}

	if (child == 1) {
		sem_wait(sem_flow_created);
		skt_flow_req_should_fail(AF_INET, &our_ip, &dst_ip, IPPROTO_IPEIP, 0, 0);
		sem_post(sem_flow_created);
		sem_post(sem_dup_flow_failed);
	}

	sem_close(sem_flow_created);
	sem_close(sem_dup_flow_failed);

	return 0;
}

struct skywalk_mptest skt_mpprotons = {
	.skt_testname = "mpprotons",
	.skt_testdesc = "test skywalk protocol namespace with two process doing conflicting reservation",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	.skt_nchildren = 2,
	.skt_main = skt_mpprotons_main,
	.skt_init = skt_protons_net_init,
	.skt_fini = skt_protons_net_fini,
};
