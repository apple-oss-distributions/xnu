/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "net_test_lib.h"


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("rpaulo")
	);

network_interface interface;

static void
cleanup(void)
{
	network_interface_destroy(&interface);
}

T_DECL(multicast_igmp_ssm, "IGMP SSM test", T_META_ASROOT(true))
{
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	T_ATEND(cleanup);
	network_interface_create(&interface, FETH_NAME);
	struct in_addr addr;
	addr.s_addr = inet_addr("192.168.55.1");
	struct in_addr mask;
	mask.s_addr = inet_addr("255.255.255.0");
	ifnet_add_ip_address(interface.if_name, addr, mask);

	struct ip_mreq_source mr = {};
	mr.imr_sourceaddr.s_addr = inet_addr("192.168.55.2");
	mr.imr_multiaddr.s_addr = inet_addr("239.1.2.3");
	mr.imr_interface.s_addr = INADDR_ANY;

	for (int i = 0; i < 20; i++) {
		mr.imr_sourceaddr.s_addr += i;
		T_ASSERT_POSIX_SUCCESS(setsockopt(s, IPPROTO_IP,
		    IP_ADD_SOURCE_MEMBERSHIP, &mr,
		    sizeof(mr)),
		    "IP_ADD_SOURCE_MEMBERSHIP");
	}
	close(s);
}

T_DECL(multicast_mld_ssm, "MLD SSM test", T_META_ASROOT(true))
{
	int s6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	T_ATEND(cleanup);
	network_interface_create(&interface, FETH_NAME);
	ifnet_start_ipv6(interface.if_name);

	struct sockaddr_storage group_storage = {}, source_storage = {};

	struct sockaddr_in6 *group = (struct sockaddr_in6 *)&group_storage;

	group->sin6_family = AF_INET6;
	group->sin6_len = sizeof(*group);
	char address[128] = {};
	snprintf(address, sizeof(address), "ff02::1234%%%s", interface.if_name);
	inet_pton(AF_INET6, address, &group->sin6_addr);

	struct sockaddr_in6 *source = (struct sockaddr_in6 *)&source_storage;
	source->sin6_family = AF_INET6;
	source->sin6_len = sizeof(*source);
	inet_pton(AF_INET6, "2001:db8::1", &source->sin6_addr);

	struct group_source_req gr = {};
	gr.gsr_interface = interface.if_index;
	gr.gsr_group = group_storage;
	gr.gsr_source = source_storage;

	for (int i = 0; i < 20; i++) {
		((struct sockaddr_in6 *)&gr.gsr_source)->sin6_addr.__u6_addr.__u6_addr8[15] += i;
		T_ASSERT_POSIX_SUCCESS(setsockopt(s6, IPPROTO_IPV6,
		    MCAST_JOIN_SOURCE_GROUP, &gr,
		    sizeof(gr)),
		    "MCAST_JOIN_SOURCE_GROUP");
	}
}
