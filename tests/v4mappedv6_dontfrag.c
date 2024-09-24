/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#define __APPLE_USE_RFC_3542 1

#include <darwintest.h>

#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <arpa/inet.h>

#include <netinet/ip.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));

/* need something greater than default MTU */
#define MAX_BUFFER_SIZE 2048

// 169.254
#define LL_NET                 0xa9fe0000 //0x0a000000
// 169.254.1
#define LL_1_NET               (LL_NET | 0x000100)

static void
get_ipv4_address(u_int unit, u_int addr_index, struct in_addr *ip)
{
	/* up to 255 units, 255 addresses */
	ip->s_addr = htonl(LL_1_NET | (unit << 8) | addr_index);
	return;
}

static void
network_interface_init(network_interface_t netif,
    const char * name, unsigned int unit,
    unsigned int address_index)
{
	network_interface_create(netif, name);
	get_ipv4_address(unit, address_index, &netif->ip);
	ifnet_add_ip_address(netif->if_name, netif->ip,
	    inet_class_c_subnet_mask);
	route_add_inet_scoped_subnet(netif->if_name, netif->if_index,
	    netif->ip, inet_class_c_subnet_mask);
}

static network_interface if_one = {0};
static network_interface if_two = {0};

static void
cleanup(void)
{
	network_interface_destroy(&if_one);
	network_interface_destroy(&if_two);
}

T_DECL(v4mappedv6_dontfrag_sockopt, "Tests setting IPV6_DONTFRAG on an IPv4-mapped IPv6 address")
{
	int sockfd = 0;
	ssize_t n;
	char buf[MAX_BUFFER_SIZE] = {0};
	struct sockaddr_in6 sin6 = {0};

	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(12345);

	T_ATEND(cleanup);

	network_interface_init(&if_one, FETH_NAME, 0, 1);
	network_interface_init(&if_two, FETH_NAME, 0, 2);
	fake_set_peer(if_one.if_name, if_two.if_name);
	ifnet_set_mtu(if_one.if_name, 1500);

	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:169.254.1.2", &sin6.sin6_addr), 1, "inet_pton");

	T_ASSERT_POSIX_SUCCESS(sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), "create socket");

	// This send should succeed (and fragment)
	n = sendto(sockfd, buf, MAX_BUFFER_SIZE, 0,
	    (struct sockaddr *)&sin6, sizeof(sin6));
	T_EXPECT_EQ(n, (ssize_t)MAX_BUFFER_SIZE, "Ensure we wrote MAX_BUFFER_SIZE");

	int Option = 1;
	T_ASSERT_POSIX_SUCCESS(setsockopt(sockfd, IPPROTO_IPV6, IPV6_DONTFRAG, &Option, sizeof(Option)), "setsockopt IPV6_DONTFRAG to 1");

	// This send should fail because MAX_BUFFER_SIZE > MTU and we enabled DONTFRAG
	n = sendto(sockfd, buf, MAX_BUFFER_SIZE, 0,
	    (struct sockaddr *)&sin6, sizeof(sin6));
	T_EXPECT_EQ(errno, EMSGSIZE, "errno should be EMSGSIZE");
	T_EXPECT_EQ(n, (ssize_t)-1, "Expect n of a certain size");

	Option = 0;
	T_ASSERT_POSIX_SUCCESS(setsockopt(sockfd, IPPROTO_IPV6, IPV6_DONTFRAG, &Option, sizeof(Option)), "setsockopt IPV6_DONTFRAG back to 0");

	// This send should succeeed (and fragment) because we turned the option back off
	n = sendto(sockfd, buf, MAX_BUFFER_SIZE, 0,
	    (struct sockaddr *)&sin6, sizeof(sin6));
	T_EXPECT_EQ(n, (ssize_t)MAX_BUFFER_SIZE, "Ensure we wrote MAX_BUFFER_SIZE");
}
