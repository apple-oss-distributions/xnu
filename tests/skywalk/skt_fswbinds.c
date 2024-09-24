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
 * I discovered a couple of issues with __os_nexus_flow_add, so here's some tests
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <arpa/inet.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

int
skt_fswbind_common(nexus_port_t nx_port1, nexus_port_t nx_port2, bool use_port2)
{
	struct nx_flow_req nfr;
	struct sktc_nexus_handles handles;
	uuid_t flow1, flow2;
	int error;
	char buf[31];
	uuid_string_t uuidstr;

	sktc_create_flowswitch(&handles, 0);

	uuid_generate_random(flow1);

	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = IPPROTO_TCP;
	nfr.nfr_nx_port = nx_port1;
	nfr.nfr_saddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_saddr.sa.sa_family = AF_INET;
	nfr.nfr_saddr.sin.sin_port = htons(0);
	nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
	uuid_copy(nfr.nfr_flow_uuid, flow1);

	uuid_unparse(nfr.nfr_flow_uuid, uuidstr);
	inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr.s_addr, buf, sizeof(buf));
	T_LOG("before: nx_port %3d Flow %s %s addr %s port %d\n",
	    nfr.nfr_nx_port, uuidstr, (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
	    buf, ntohs(nfr.nfr_saddr.sin.sin_port));

	error = __os_nexus_flow_add(handles.controller, handles.fsw_nx_uuid, &nfr);
	if (error) {
		return error;
	}

	uuid_unparse(nfr.nfr_flow_uuid, uuidstr);
	inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr.s_addr, buf, sizeof(buf));
	T_LOG("after:  nx_port %3d Flow %s %s addr %s port %d\n",
	    nfr.nfr_nx_port, uuidstr, (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
	    buf, ntohs(nfr.nfr_saddr.sin.sin_port));

	assert(nfr.nfr_nx_port == nx_port1 || nx_port1 == NEXUS_PORT_ANY);
	assert(!uuid_compare(nfr.nfr_flow_uuid, flow1));

	if (use_port2) {
		uuid_generate_random(flow2);

		memset(&nfr, 0, sizeof(nfr));
		nfr.nfr_ip_protocol = IPPROTO_TCP;
		nfr.nfr_nx_port = nx_port2;
		nfr.nfr_saddr.sa.sa_len = sizeof(struct sockaddr_in);
		nfr.nfr_saddr.sa.sa_family = AF_INET;
		nfr.nfr_saddr.sin.sin_port = htons(0);
		nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		uuid_copy(nfr.nfr_flow_uuid, flow2);

		uuid_unparse(nfr.nfr_flow_uuid, uuidstr);
		inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr.s_addr, buf, sizeof(buf));
		T_LOG("before: nx_port %3d Flow %s %s addr %s port %d\n",
		    nfr.nfr_nx_port, uuidstr, (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
		    buf, ntohs(nfr.nfr_saddr.sin.sin_port));

		error = __os_nexus_flow_add(handles.controller, handles.fsw_nx_uuid, &nfr);
		if (error) {
			return error;
		}

		uuid_unparse(nfr.nfr_flow_uuid, uuidstr);
		inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr.s_addr, buf, sizeof(buf));
		T_LOG("after:  nx_port %3d Flow %s %s addr %s port %d\n",
		    nfr.nfr_nx_port, uuidstr, (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
		    buf, ntohs(nfr.nfr_saddr.sin.sin_port));

		assert(nfr.nfr_nx_port == nx_port2);
		assert(!uuid_compare(nfr.nfr_flow_uuid, flow2));
	}

	memset(&nfr, 0, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow1);

	error = __os_nexus_flow_del(handles.controller, handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(!error);

	if (use_port2) {
		memset(&nfr, 0, sizeof(nfr));
		uuid_copy(nfr.nfr_flow_uuid, flow2);

		error = __os_nexus_flow_del(handles.controller, handles.fsw_nx_uuid, &nfr);
		SKTC_ASSERT_ERR(!error);
	}

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

int
skt_fswbindany_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(NEXUS_PORT_ANY, 0, false);
	SKTC_ASSERT_ERR(!error); /* Expected to pass */
	return 0;
}

int
skt_fswbind0_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(0, 0, false);
	SKTC_ASSERT_ERR(error); /* Expected to fail */
	return 0;
}

int
skt_fswbind1_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(1, 0, false);
	SKTC_ASSERT_ERR(error); /* Expected to fail */
	return 0;
}

int
skt_fswbind512_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(512, 0, false);
	SKTC_ASSERT_ERR(error); /* Expected to fail */
	return 0;
}

int
skt_fswbind2_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(2, 0, false);
	SKTC_ASSERT_ERR(!error);
	return 0;
}

int
skt_fswbind5_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(5, 0, false);
	SKTC_ASSERT_ERR(!error);
	return 0;
}

int
skt_fswbind25_main(int argc, char *argv[])
{
	int error = skt_fswbind_common(2, 5, true);
	SKTC_ASSERT_ERR(!error);
	return 0;
}

struct skywalk_test skt_fswbindany = {
	"fswbindany", "attempts to bind to port -1 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswbindany_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fswbind0 = {
	"fswbind0", "attempts to bind to port 0 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswbind0_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fswbind1 = {
	"fswbind1", "attempts to bind to port 1 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswbind1_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fswbind512 = {
	"fswbind512", "attempts to bind to port 512 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswbind512_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fswbind2 = {
	"fswbind2", "attempts to bind to port 2 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_fswbind2_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fswbind5 = {
	"fswbind5", "attempts to bind to port 5 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_fswbind5_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fswbind25 = {
	"fswbind25", "attempts to bind to port 2 and 5 of flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_fswbind25_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};
