/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true)
	);

static void
test_so_bindtodevice(int domain, int type, int proto)
{
#ifndef SO_BINDTODEVICE
	T_SKIP("SO_BINDTODEVICE not defined")
#else
	int fd;
	int boundif_level = domain == PF_INET ? IPPROTO_IP : IPPROTO_IPV6;
	int boundif_name = domain == PF_INET ? IP_BOUND_IF : IPV6_BOUND_IF;
	const char *boundif_str = domain == PF_INET ? "IP_BOUND_IF" : "IPV6_BOUND_IF";
	char ifname[IFNAMSIZ + 1] = { 0 };
	int intval;
	socklen_t len;
	unsigned int ifindex = if_nametoindex("lo0");

	T_LOG("test_so_bindtodevice(%d, %d, %d)", domain, type, proto);

	T_ASSERT_POSIX_SUCCESS(fd = socket(domain, type, proto), NULL);

	/*
	 * First test the default values
	 */
	intval = -1;
	len = sizeof(int);
	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, boundif_level, boundif_name, &intval, &len),
	    "get default  %s, intval %d", boundif_str, intval);

	T_ASSERT_EQ_INT(intval, 0, "default interface index 0");

	len = sizeof(ifname);
	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &len),
	    "get default SO_BINDTODEVICE: \"%s\"", ifname);

	T_ASSERT_EQ_STR(ifname, "", "default interface name empty");

	/*
	 * Verify that SO_BINDTODEVICE can get the interface set by xxx_BOUND_IF
	 */
	intval = (int)ifindex;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, boundif_level, boundif_name, &intval, len),
	    "set lo0 %s, intval %d", boundif_str, intval);

	intval = -1;
	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, boundif_level, boundif_name, &intval, &len),
	    "get %s, intval %d", boundif_str, intval);

	T_ASSERT_EQ_INT(intval, (int)ifindex, "loopback interface index");

	len = sizeof(ifname);
	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &len),
	    "get SO_BINDTODEVICE: \"%s\", len %u", ifname, len);

	T_ASSERT_EQ_STR(ifname, "lo0", "loopback interface name");

	/*
	 * Verify that an empty string clears the bound interface
	 */
	strlcpy(ifname, "", sizeof(ifname));
	len = IFNAMSIZ;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, len), NULL);
	T_LOG("set SO_BINDTODEVICE `\"\"` %s: len %d", boundif_str, intval);

	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, boundif_level, boundif_name, &intval, &len), NULL);
	T_LOG("cleared %s, intval %d", boundif_str, intval);

	T_ASSERT_EQ_INT(intval, 0, "default interface index 0");

	/*
	 * Verify interface set by SO_BINDTODEVICE is gotten by xxx_BOUND_IF
	 */
	strlcpy(ifname, "lo0", sizeof(ifname));
	len = (socklen_t)strlen(ifname);
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, len),
	    "set SO_BINDTODEVICE: \"%s\", len %u", ifname, len);

	len = sizeof(ifname);
	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &len),
	    "lo0 SO_BINDTODEVICE: \"%s\"", ifname);

	T_ASSERT_EQ_STR(ifname, "lo0", "loopback interface name");

	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, boundif_level, boundif_name, &intval, &len),
	    "lo0 %s, intval %d", boundif_str, intval);

	T_ASSERT_EQ_INT(intval, (int)ifindex, "loopback interface index");

	/*
	 * Verify that a NULL string clears the bound interface
	 */
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NULL, 0),
	    "set SO_BINDTODEVICE: NULL, len 0");

	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, boundif_level, boundif_name, &intval, &len), NULL);
	T_LOG("cleared \"%s\", intval %d", boundif_str, intval);

	T_ASSERT_EQ_INT(intval, 0, "default interface index 0");

	/*
	 * Verify bounds
	 */
	strlcpy(ifname, "lo0", sizeof(ifname));

	len = IFNAMSIZ;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, len),
	    "set SO_BINDTODEVICE: \"%s\", len %u (IFNAMSIZ) OK", ifname, len);

	len = IFNAMSIZ + 1;
	T_ASSERT_POSIX_FAILURE(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, len), EINVAL,
	    "set SO_BINDTODEVICE: \"%s\", len %u (IFNAMSIZ + 1) expected EINVAL", ifname, len);
#endif
}

T_DECL(so_bindtodevice_tcp_ipv4, "SO_BINDTODEVICE TCP IPv4")
{
	test_so_bindtodevice(PF_INET, SOCK_STREAM, 0);
}

T_DECL(so_bindtodevice_tcp_ipv6, "SO_BINDTODEVICE TCP IPv6")
{
	test_so_bindtodevice(PF_INET6, SOCK_STREAM, 0);
}

T_DECL(so_bindtodevice_udp_ipv4, "SO_BINDTODEVICE UDP IPv4")
{
	test_so_bindtodevice(PF_INET, SOCK_DGRAM, 0);
}

T_DECL(so_bindtodevice_udp_ipv6, "SO_BINDTODEVICE UDP IPv6")
{
	test_so_bindtodevice(PF_INET6, SOCK_DGRAM, 0);
}

T_DECL(so_bindtodevice_icmp_ipv4, "SO_BINDTODEVICE ICMP IPv4")
{
	test_so_bindtodevice(PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
}

T_DECL(so_bindtodevice_icmp_ipv6, "SO_BINDTODEVICE ICMP IPv6")
{
	test_so_bindtodevice(PF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
}

T_DECL(so_bindtodevice_raw_ipv4, "SO_BINDTODEVICE RAW IPv4")
{
	test_so_bindtodevice(PF_INET, SOCK_RAW, 0);
}

T_DECL(so_bindtodevice_raw_ipv6, "SO_BINDTODEVICE RAW IPv6")
{
	test_so_bindtodevice(PF_INET6, SOCK_RAW, 0);
}
