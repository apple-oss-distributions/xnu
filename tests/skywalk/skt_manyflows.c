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

/*
 * Try to create many flows on many ports, part of:
 * <rdar://problem/29003665> need to control skywalk behavior at limit of too many flows
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

static void
do_flows(nexus_controller_t ncd, const uuid_t fsw, nexus_port_t nx_port_start, int nports, int nflows_per_port, uuid_t flows[])
{
	for (int i = 0; i < nports; i++) {
		for (int j = 0; j < nflows_per_port; j++) {
			int error;
			uuid_generate_random(flows[i * nflows_per_port + j]);

			error = sktc_bind_tcp4_flow(ncd, fsw, 0, nx_port_start + i, flows[i * nflows_per_port + j]);
			SKTC_ASSERT_ERR(!error); // XXX some of these are expected
		}
	}
}

static void
undo_flows(nexus_controller_t ncd, const uuid_t fsw, int nflows, const uuid_t flows[])
{
	for (int i = 0; i < nflows; i++) {
		int error;
		uuid_string_t uuidstr;
		uuid_unparse_upper(flows[i], uuidstr);
		//T_LOG("Destroying flow %s\n", uuidstr);
		error = sktc_unbind_flow(ncd, fsw, flows[i]);
		SKTC_ASSERT_ERR(!error);
	}
}

static int
skt_manyflows_common(int nports, int nflows_per_port)
{
	struct sktc_nexus_handles handles;
	sktc_create_flowswitch(&handles, 0);

	uuid_t flows[nports * nflows_per_port];

	do_flows(handles.controller, handles.fsw_nx_uuid, NEXUS_PORT_FLOW_SWITCH_CLIENT, nports, nflows_per_port, flows);
	undo_flows(handles.controller, handles.fsw_nx_uuid, sizeof(flows) / sizeof(flows[0]), flows);

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

static int
skt_mf10x10_main(int argc, char *argv[])
{
	return skt_manyflows_common(10, 10);
}

static int
skt_mf10x100_main(int argc, char *argv[])
{
	return skt_manyflows_common(10, 100);
}

static int
skt_mf100x10_main(int argc, char *argv[])
{
	return skt_manyflows_common(100, 10);
}

static int
skt_mf100x100_main(int argc, char *argv[])
{
	return skt_manyflows_common(100, 100);
}

struct skywalk_test skt_mf10x10 = {
	"mf10x10", "test binds 10 ports with 10 flows per port",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_mf10x10_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_mf10x100 = {
	"mf10x100", "test binds 10 ports with 100 flows per port",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_mf10x100_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_mf100x10 = {
	"mf100x10", "test binds 100 ports with 10 flows per port",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_mf100x10_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_mf100x100 = {
	"mf100x100", "test binds 100 ports with 100 flows per port",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_mf100x100_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

/****************************************************************/

static int
skt_mf1xall_common(bool stop_on_error)
{
	int error;
	int first, last;
	size_t size;
	int i, nports, count;

	size = sizeof(first);
	error = sysctlbyname("net.inet.ip.portrange.first", &first, &size, NULL, 0);
	SKTC_ASSERT_ERR(!error);
	assert(size == sizeof(first));

	size = sizeof(last);
	error = sysctlbyname("net.inet.ip.portrange.last", &last, &size, NULL, 0);
	SKTC_ASSERT_ERR(!error);
	assert(size == sizeof(last));

	if (last < first) {
		nports = first - last + 1;
	} else {
		nports = last - first + 1;
	}

	/* Check that there are at least 512 ephemeral ports in the range
	 * so that we can fill up our flows
	 */
	assert(nports >= 512);

	struct sktc_nexus_handles handles;
	sktc_create_flowswitch(&handles, 0);

	uuid_t flows[nports];
	uuid_t extraflow;

	count = 0;
	/* Bind all the ephemeral ports */
	for (i = 0; i < nports; i++) {
		uuid_generate_random(flows[i]);
		error = sktc_bind_tcp4_flow(handles.controller, handles.fsw_nx_uuid,
		    0, NEXUS_PORT_FLOW_SWITCH_CLIENT, flows[i]);
		if (error) {
			/* flow_entry_alloc currently returns ENOMEM
			 * flow_namespace_create returns EADDRNOTAVAIL
			 */
			SKTC_ASSERT_ERR(errno == ENOMEM);
			uuid_clear(flows[i]);
			if (stop_on_error) {
				break;
			}
		} else {
			count++;
		}
	}

	T_LOG("bound %d flows out of %d\n", count, nports);

	assert(count == 512); /* The default number of flows is currently 512 */

	T_LOG("try one more and verify it fails\n");
	/* Now try one more and verify it fails */
	uuid_generate_random(extraflow);
	error = sktc_bind_tcp4_flow(handles.controller, handles.fsw_nx_uuid,
	    0, NEXUS_PORT_FLOW_SWITCH_CLIENT, extraflow);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENOMEM);
	uuid_clear(extraflow);

	/* Unbind all the flows */
	for (i = 0; i < nports; i++) {
		if (!uuid_is_null(flows[i])) {
			error = sktc_unbind_flow(handles.controller, handles.fsw_nx_uuid, flows[i]);
			SKTC_ASSERT_ERR(!error);
		}
	}

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

int
skt_mf1xall_main(int argc, char *argv[])
{
	return skt_mf1xall_common(true);
}

int
skt_mf1xallslow_main(int argc, char *argv[])
{
	return skt_mf1xall_common(false);
}


struct skywalk_test skt_mf1xall = {
	"mf1xall", "test binds all the ephemeral port flows on a single port until it hits failure",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_mf1xall_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_mf1xallslow = {
	"mf1xallslow", "test binds all the ephemeral port flows on a single port ",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_mf1xallslow_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

/****************************************************************/

uuid_t mcflows[100 * 100];
struct sktc_nexus_handles mchandles;

static uuid_string_t fsw_uuid_string;

static void
skt_mc10x10_init(void)
{
	sktc_ifnet_feth0_create();
	sktc_create_flowswitch(&mchandles, 0);
	do_flows(mchandles.controller, mchandles.fsw_nx_uuid, NEXUS_PORT_FLOW_SWITCH_CLIENT, 10, 10, mcflows);
	uuid_unparse(mchandles.fsw_nx_uuid, fsw_uuid_string);
}

static void
skt_mc10x100_init(void)
{
	sktc_ifnet_feth0_create();
	sktc_create_flowswitch(&mchandles, 0);
	do_flows(mchandles.controller, mchandles.fsw_nx_uuid, NEXUS_PORT_FLOW_SWITCH_CLIENT, 10, 100, mcflows);
	uuid_unparse(mchandles.fsw_nx_uuid, fsw_uuid_string);
}

static void
skt_mc100x10_init(void)
{
	sktc_ifnet_feth0_create();
	sktc_create_flowswitch(&mchandles, 0);
	do_flows(mchandles.controller, mchandles.fsw_nx_uuid, NEXUS_PORT_FLOW_SWITCH_CLIENT, 100, 10, mcflows);
	uuid_unparse(mchandles.fsw_nx_uuid, fsw_uuid_string);
}

static void
skt_mc100x100_init(void)
{
	sktc_ifnet_feth0_create();
	sktc_create_flowswitch(&mchandles, 0);
	do_flows(mchandles.controller, mchandles.fsw_nx_uuid, NEXUS_PORT_FLOW_SWITCH_CLIENT, 100, 100, mcflows);
	uuid_unparse(mchandles.fsw_nx_uuid, fsw_uuid_string);
}

static void
skt_mc100_fini(void)
{
	undo_flows(mchandles.controller, mchandles.fsw_nx_uuid, 100, mcflows);
	sktc_cleanup_flowswitch(&mchandles);
	sktc_ifnet_feth0_destroy();
}

static void
skt_mc1000_fini(void)
{
	undo_flows(mchandles.controller, mchandles.fsw_nx_uuid, 10 * 100, mcflows);
	sktc_cleanup_flowswitch(&mchandles);
	sktc_ifnet_feth0_destroy();
}

static void
skt_mc10000_fini(void)
{
	undo_flows(mchandles.controller, mchandles.fsw_nx_uuid, 100 * 100, mcflows);
	sktc_cleanup_flowswitch(&mchandles);
	sktc_ifnet_feth0_destroy();
}

int
skt_mcflows_main(int argc, char *argv[])
{
	char buf[1] = { 0 };
	ssize_t ret;
	int error;
	uuid_t fsw_uuid;
	channel_t channel;
	assert(argc == 6);
	assert(!strcmp(argv[3], "--child"));
	int child = atoi(argv[4]);
	error = uuid_parse(argv[5], fsw_uuid);
	SKTC_ASSERT_ERR(!error);

	T_LOG("opening channel %d on fsw %s\n",
	    NEXUS_PORT_FLOW_SWITCH_CLIENT + child, argv[5]);

	channel = sktu_channel_create_extended(fsw_uuid, NEXUS_PORT_FLOW_SWITCH_CLIENT + child,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

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

	os_channel_destroy(channel);

	return 0;
}

struct skywalk_mptest skt_mc10x10 = {
	"mc10x10", "test forks 10 processes each opening a channel with 10 flows",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	10, skt_mcflows_main, {NULL, NULL, NULL, NULL, NULL, fsw_uuid_string}, skt_mc10x10_init, skt_mc100_fini,
};

struct skywalk_mptest skt_mc10x100 = {
	"mc10x100", "test forks 10 processes each opening a channel with 100 flows",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	10, skt_mcflows_main, {NULL, NULL, NULL, NULL, NULL, fsw_uuid_string}, skt_mc10x100_init, skt_mc1000_fini,
};

struct skywalk_mptest skt_mc100x10 = {
	"mc100x10", "test forks 100 processes each opening a channel with 10 flows",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	100, skt_mcflows_main, {NULL, NULL, NULL, NULL, NULL, fsw_uuid_string}, skt_mc100x10_init, skt_mc1000_fini,
};

struct skywalk_mptest skt_mc100x100 = {
	"mc100x100", "test forks 100 processes each opening a channel with 100 flows",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	100, skt_mcflows_main, {NULL, NULL, NULL, NULL, NULL, fsw_uuid_string}, skt_mc100x100_init, skt_mc10000_fini,
};
