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

/*
 * sockopt_ipv6.c
 *
 * Tests for IPPROTO_IPV6 level socket options.
 * Tests IPv6-specific options like IPV6_V6ONLY, IPV6_UNICAST_HOPS,
 * IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS, etc.
 */

#define __APPLE_USE_RFC_3542

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net.sockopt"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * Helper to test basic integer IPv6 option round-trip
 */
static void
test_ipv6_int_option_roundtrip(int fd, int optname, const char *optname_str,
    int setval, int expected_getval)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, optname, &getval, &optlen),
		"getsockopt %s", optname_str);

	T_EXPECT_EQ(getval, expected_getval,
	    "%s value matches (expected %d, got %d)",
	    optname_str, expected_getval, getval);
}

/*
 * Helper to test boolean IPv6 options
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_ipv6_bool_option(int fd, int optname, const char *optname_str,
    int setval, bool expect_enabled)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, optname, &getval, &optlen),
		"getsockopt %s", optname_str);

	if (expect_enabled) {
		T_EXPECT_NE(getval, 0,
		    "%s is enabled (set %d, got non-zero %d)",
		    optname_str, setval, getval);
	} else {
		T_EXPECT_EQ(getval, 0,
		    "%s is disabled (set %d, got %d)",
		    optname_str, setval, getval);
	}
}

/*
 * Test IPV6_V6ONLY - IPv6 only (disable IPv4-mapped addresses)
 */
T_DECL(ipv6_v6only_inet6_tcp, "IPV6_V6ONLY on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_ipv6_bool_option(fd, IPV6_V6ONLY, "IPV6_V6ONLY", 1, true);
	test_ipv6_bool_option(fd, IPV6_V6ONLY, "IPV6_V6ONLY", 0, false);

	close(fd);
}

T_DECL(ipv6_v6only_inet6_udp, "IPV6_V6ONLY on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_bool_option(fd, IPV6_V6ONLY, "IPV6_V6ONLY", 1, true);
	test_ipv6_bool_option(fd, IPV6_V6ONLY, "IPV6_V6ONLY", 0, false);

	close(fd);
}

T_DECL(ipv6_v6only_on_inet, "IPV6_V6ONLY fails on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int optval = 1;
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));

	T_ASSERT_EQ(ret, -1, "IPV6_V6ONLY should fail on AF_INET socket");
	T_EXPECT_TRUE(errno == ENOPROTOOPT || errno == EINVAL,
	    "errno should be ENOPROTOOPT or EINVAL (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

/*
 * Test IPV6_UNICAST_HOPS - Hop limit for unicast packets
 */
T_DECL(ipv6_unicast_hops_inet6_tcp, "IPV6_UNICAST_HOPS on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Test various hop limit values */
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 64, 64);
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 128, 128);
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 255, 255);
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 1, 1);

	close(fd);
}

T_DECL(ipv6_unicast_hops_inet6_udp, "IPV6_UNICAST_HOPS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 32, 32);
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 255, 255);

	close(fd);
}

T_DECL(ipv6_unicast_hops_invalid_values, "IPV6_UNICAST_HOPS rejects invalid values")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Test value > 255 */
	int toolarge = 256;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &toolarge, sizeof(toolarge)),
		EINVAL,
		"IPV6_UNICAST_HOPS should reject value > 255");

	close(fd);
}

/*
 * Test IPV6_RECVPKTINFO - Receive packet information
 */
T_DECL(ipv6_recvpktinfo_inet6_udp, "IPV6_RECVPKTINFO on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_bool_option(fd, IPV6_RECVPKTINFO, "IPV6_RECVPKTINFO", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVPKTINFO, "IPV6_RECVPKTINFO", 0, false);

	close(fd);
}

/*
 * Test IPV6_RECVHOPLIMIT - Receive hop limit
 */
T_DECL(ipv6_recvhoplimit_inet6_udp, "IPV6_RECVHOPLIMIT on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_bool_option(fd, IPV6_RECVHOPLIMIT, "IPV6_RECVHOPLIMIT", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVHOPLIMIT, "IPV6_RECVHOPLIMIT", 0, false);

	close(fd);
}

/*
 * Test IPV6_RECVTCLASS - Receive traffic class
 */
T_DECL(ipv6_recvtclass_inet6_udp, "IPV6_RECVTCLASS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_bool_option(fd, IPV6_RECVTCLASS, "IPV6_RECVTCLASS", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVTCLASS, "IPV6_RECVTCLASS", 0, false);

	close(fd);
}

/*
 * Test IPV6_TCLASS - Traffic class
 */
T_DECL(ipv6_tclass_inet6_tcp, "IPV6_TCLASS on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Test various traffic class values */
	test_ipv6_int_option_roundtrip(fd, IPV6_TCLASS, "IPV6_TCLASS", 0x10, 0x10);
	test_ipv6_int_option_roundtrip(fd, IPV6_TCLASS, "IPV6_TCLASS", 0x20, 0x20);
	test_ipv6_int_option_roundtrip(fd, IPV6_TCLASS, "IPV6_TCLASS", 0, 0);

	close(fd);
}

T_DECL(ipv6_tclass_inet6_udp, "IPV6_TCLASS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_int_option_roundtrip(fd, IPV6_TCLASS, "IPV6_TCLASS", 0x10, 0x10);
	test_ipv6_int_option_roundtrip(fd, IPV6_TCLASS, "IPV6_TCLASS", 0, 0);

	close(fd);
}

/*
 * Test IPV6_DONTFRAG - Don't fragment packets
 */
T_DECL(ipv6_dontfrag_inet6_udp, "IPV6_DONTFRAG on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_ipv6_bool_option(fd, IPV6_DONTFRAG, "IPV6_DONTFRAG", 1, true);
	test_ipv6_bool_option(fd, IPV6_DONTFRAG, "IPV6_DONTFRAG", 0, false);

	close(fd);
}

T_DECL(ipv6_dontfrag_inet6_tcp, "IPV6_DONTFRAG ignored on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* IPV6_DONTFRAG is ignored for TCP sockets (RFC3542 leaves this unspecified) */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &enable, sizeof(enable)),
		"setsockopt IPV6_DONTFRAG = 1");

	/* Verify it's not actually set - should return 0 */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &getval, &optlen),
		"getsockopt IPV6_DONTFRAG");

	T_EXPECT_EQ(getval, 0, "IPV6_DONTFRAG ignored on TCP (got %d)", getval);

	/* Explicitly setting to 0 should also work */
	int disable = 0;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &disable, sizeof(disable)),
		"setsockopt IPV6_DONTFRAG = 0");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &getval, &optlen),
		"getsockopt IPV6_DONTFRAG");

	T_EXPECT_EQ(getval, 0, "IPV6_DONTFRAG still 0 on TCP");

	close(fd);
}

/*
 * Test IPV6_BOUND_IF - Bind socket to interface
 */
T_DECL(ipv6_bound_if_inet6_udp, "IPV6_BOUND_IF on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Get loopback interface index */
	unsigned int lo_idx = if_nametoindex("lo0");
	T_ASSERT_GT(lo_idx, 0U, "if_nametoindex(lo0)");

	test_ipv6_int_option_roundtrip(fd, IPV6_BOUND_IF, "IPV6_BOUND_IF", (int)lo_idx, (int)lo_idx);

	/* Unbind */
	test_ipv6_int_option_roundtrip(fd, IPV6_BOUND_IF, "IPV6_BOUND_IF", 0, 0);

	close(fd);
}

/*
 * Test IPV6_NO_IFT_CELLULAR - Disallow cellular interface
 * Note: This is a write-once option - once set, it cannot be cleared
 */
T_DECL(ipv6_no_ift_cellular_inet6_tcp, "IPV6_NO_IFT_CELLULAR on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Initially should be disabled */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_NO_IFT_CELLULAR, &getval, &optlen),
		"getsockopt IPV6_NO_IFT_CELLULAR");
	T_EXPECT_EQ(getval, 0, "IPV6_NO_IFT_CELLULAR initially disabled");

	/* Enable it */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_NO_IFT_CELLULAR, &enable, sizeof(enable)),
		"setsockopt IPV6_NO_IFT_CELLULAR = 1");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_NO_IFT_CELLULAR, &getval, &optlen),
		"getsockopt IPV6_NO_IFT_CELLULAR");
	T_EXPECT_NE(getval, 0, "IPV6_NO_IFT_CELLULAR is enabled (got %d)", getval);

	/* Attempting to clear it should fail */
	int disable = 0;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_NO_IFT_CELLULAR, &disable, sizeof(disable)),
		EINVAL,
		"setsockopt IPV6_NO_IFT_CELLULAR = 0 should fail (write-once option)");

	/* Verify it's still enabled */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_NO_IFT_CELLULAR, &getval, &optlen),
		"getsockopt IPV6_NO_IFT_CELLULAR");
	T_EXPECT_NE(getval, 0, "IPV6_NO_IFT_CELLULAR still enabled (got %d)", getval);

	close(fd);
}

/*
 * Test IPV6_PREFER_TEMPADDR - Prefer temporary addresses
 */
T_DECL(ipv6_prefer_tempaddr_inet6_tcp, "IPV6_PREFER_TEMPADDR on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_ipv6_bool_option(fd, IPV6_PREFER_TEMPADDR, "IPV6_PREFER_TEMPADDR", 1, true);
	test_ipv6_bool_option(fd, IPV6_PREFER_TEMPADDR, "IPV6_PREFER_TEMPADDR", 0, false);

	close(fd);
}

/*
 * Test multiple IPv6 options on same socket
 */
T_DECL(ipv6_multiple_options, "Multiple IPv6 options on same socket")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Set multiple options */
	int v6only = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)),
		"setsockopt IPV6_V6ONLY");

	int hops = 64;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)),
		"setsockopt IPV6_UNICAST_HOPS");

	int recvpktinfo = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &recvpktinfo, sizeof(recvpktinfo)),
		"setsockopt IPV6_RECVPKTINFO");

	int dontfrag = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &dontfrag, sizeof(dontfrag)),
		"setsockopt IPV6_DONTFRAG");

	/* Verify all options */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	/* IPV6_V6ONLY is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &getval, &optlen),
		"getsockopt IPV6_V6ONLY");
	T_EXPECT_NE(getval, 0, "IPV6_V6ONLY still enabled (got %d)", getval);

	/* IPV6_UNICAST_HOPS is integer value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &getval, &optlen),
		"getsockopt IPV6_UNICAST_HOPS");
	T_EXPECT_EQ(getval, 64, "IPV6_UNICAST_HOPS still set");

	/* IPV6_RECVPKTINFO is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &getval, &optlen),
		"getsockopt IPV6_RECVPKTINFO");
	T_EXPECT_NE(getval, 0, "IPV6_RECVPKTINFO still enabled (got %d)", getval);

	/* IPV6_DONTFRAG is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &getval, &optlen),
		"getsockopt IPV6_DONTFRAG");
	T_EXPECT_NE(getval, 0, "IPV6_DONTFRAG still enabled (got %d)", getval);

	close(fd);
}

/*
 * Test IPv6 options on bound socket
 */
T_DECL(ipv6_options_bound_socket, "IPv6 options work on bound socket")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = 0, /* Let kernel choose port */
		.sin6_addr = IN6ADDR_LOOPBACK_INIT
	};

	T_ASSERT_POSIX_SUCCESS(
		bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"bind to localhost");

	/* Options should still work after binding */
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 128, 128);
	test_ipv6_bool_option(fd, IPV6_RECVPKTINFO, "IPV6_RECVPKTINFO", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVHOPLIMIT, "IPV6_RECVHOPLIMIT", 1, true);

	close(fd);
}

/*
 * Test IPv6 options on connected UDP socket
 */
T_DECL(ipv6_options_connected_socket, "IPv6 options work on connected UDP socket")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(9999),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT
	};

	T_ASSERT_POSIX_SUCCESS(
		connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"connect to [::1]:9999");

	/* Options should still work after connecting */
	test_ipv6_int_option_roundtrip(fd, IPV6_UNICAST_HOPS, "IPV6_UNICAST_HOPS", 255, 255);
	test_ipv6_bool_option(fd, IPV6_DONTFRAG, "IPV6_DONTFRAG", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVTCLASS, "IPV6_RECVTCLASS", 1, true);

	close(fd);
}

/*
 * Test invalid option lengths
 */
T_DECL(ipv6_v6only_invalid_optlen, "IPV6_V6ONLY with invalid optlen")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Too small */
	char smallval = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &smallval, sizeof(smallval)),
		EINVAL,
		"setsockopt IPV6_V6ONLY with too small optlen should fail");

	/* NULL pointer with non-zero length */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, NULL, sizeof(int)),
		EFAULT,
		"setsockopt IPV6_V6ONLY with NULL optval should fail");

	close(fd);
}

/*
 * Test IPV6_USE_MIN_MTU - Use minimum MTU
 */
T_DECL(ipv6_use_min_mtu_inet6_udp, "IPV6_USE_MIN_MTU on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_USE_MIN_MTU: -1 = kernel default, 0 = disable, 1 = enable */
	test_ipv6_int_option_roundtrip(fd, IPV6_USE_MIN_MTU, "IPV6_USE_MIN_MTU", 1, 1);
	test_ipv6_int_option_roundtrip(fd, IPV6_USE_MIN_MTU, "IPV6_USE_MIN_MTU", 0, 0);
	test_ipv6_int_option_roundtrip(fd, IPV6_USE_MIN_MTU, "IPV6_USE_MIN_MTU", -1, -1);

	close(fd);
}

/*
 * Test IPV6_CHECKSUM - Checksum offset for raw sockets
 * For ICMPv6 sockets, the checksum offset is fixed at 2
 */
T_DECL(ipv6_checksum_raw, "IPV6_CHECKSUM on RAW socket",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");

	/* For ICMPv6, checksum offset is fixed at 2 (offsetof(struct icmp6_hdr, icmp6_cksum)) */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	/* Should be able to get the current value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &getval, &optlen),
		"getsockopt IPV6_CHECKSUM");
	T_LOG("IPV6_CHECKSUM default value: %d", getval);

	/* For ICMPv6, can only set it to the same value (2) */
	int icmp6_cksum_offset = 2;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &icmp6_cksum_offset, sizeof(icmp6_cksum_offset)),
		"setsockopt IPV6_CHECKSUM = 2 (ICMPv6 offset)");

	/* Verify it's still 2 */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &getval, &optlen),
		"getsockopt IPV6_CHECKSUM");
	T_EXPECT_EQ(getval, 2, "IPV6_CHECKSUM is 2");

	/* Attempting to set it to a different value should fail for ICMPv6 */
	int different_offset = 4;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &different_offset, sizeof(different_offset)),
		EINVAL,
		"setsockopt IPV6_CHECKSUM with different offset should fail for ICMPv6");

	/* Attempting to set it to an odd value should fail (must be even) */
	int odd_offset = 3;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &odd_offset, sizeof(odd_offset)),
		EINVAL,
		"setsockopt IPV6_CHECKSUM with odd offset should fail");

	close(fd);
}

/*
 * Test IPV6_PORTRANGE - Port range for bind
 */
T_DECL(ipv6_portrange_inet6_udp, "IPV6_PORTRANGE on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Test different port ranges */
	test_ipv6_int_option_roundtrip(fd, IPV6_PORTRANGE, "IPV6_PORTRANGE",
	    IPV6_PORTRANGE_DEFAULT, IPV6_PORTRANGE_DEFAULT);
	test_ipv6_int_option_roundtrip(fd, IPV6_PORTRANGE, "IPV6_PORTRANGE",
	    IPV6_PORTRANGE_HIGH, IPV6_PORTRANGE_HIGH);
	test_ipv6_int_option_roundtrip(fd, IPV6_PORTRANGE, "IPV6_PORTRANGE",
	    IPV6_PORTRANGE_LOW, IPV6_PORTRANGE_LOW);

	close(fd);
}

T_DECL(ipv6_portrange_inet6_tcp, "IPV6_PORTRANGE on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_ipv6_int_option_roundtrip(fd, IPV6_PORTRANGE, "IPV6_PORTRANGE",
	    IPV6_PORTRANGE_DEFAULT, IPV6_PORTRANGE_DEFAULT);
	test_ipv6_int_option_roundtrip(fd, IPV6_PORTRANGE, "IPV6_PORTRANGE",
	    IPV6_PORTRANGE_HIGH, IPV6_PORTRANGE_HIGH);

	close(fd);
}

/* IPv6 Extension Header Options */

T_DECL(ipv6_hoplimit_not_sticky, "IPV6_HOPLIMIT setsockopt not supported (RFC 3542)")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* RFC 3542 deprecated sticky IPV6_HOPLIMIT (setsockopt)
	 * It's only supported as ancillary data (cmsg) for per-packet control
	 * Use IPV6_UNICAST_HOPS for setting default hop limit instead
	 */
	int hlim = 64;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &hlim, sizeof(hlim)),
		ENOPROTOOPT,
		"setsockopt IPV6_HOPLIMIT should fail (deprecated for sticky use)");

	close(fd);
}

T_DECL(ipv6_hopopts_requires_root, "IPV6_HOPOPTS requires root privilege",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_HOPOPTS requires root privilege to prevent non-privileged users
	 * from setting arbitrary hop-by-hop options
	 */
	unsigned char hopopts[8] = {
		IPPROTO_UDP,  /* next header */
		0,            /* length (0 = 8 bytes total) */
		0x01, 0x04, 0x00, 0x00, 0x00, 0x00  /* PadN option */
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_HOPOPTS, hopopts, sizeof(hopopts)),
		"setsockopt IPV6_HOPOPTS");

	close(fd);
}

T_DECL(ipv6_dstopts_requires_root, "IPV6_DSTOPTS requires root privilege",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_DSTOPTS requires root privilege */
	unsigned char dstopts[8] = {
		IPPROTO_UDP,  /* next header */
		0,            /* length (0 = 8 bytes total) */
		0x01, 0x04, 0x00, 0x00, 0x00, 0x00  /* PadN option */
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_DSTOPTS, dstopts, sizeof(dstopts)),
		"setsockopt IPV6_DSTOPTS");

	close(fd);
}

T_DECL(ipv6_rthdr_type0_validation, "IPV6_RTHDR validates Type 0 routing header")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_RTHDR only accepts Type 0 routing headers with specific validation
	 * Type 0 routing must contain at least one address and proper formatting
	 * Note: Type 0 routing is deprecated by RFC 5095 but the option still exists
	 */
	unsigned char rthdr[8] = {
		IPPROTO_UDP,  /* next header */
		0,            /* length (0 = 8 bytes total) */
		0,            /* routing type 0 */
		0,            /* segments left */
		0, 0, 0, 0    /* reserved */
	};

	/* This should fail with EINVAL because Type 0 must contain at least one address */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, rthdr, sizeof(rthdr)),
		EINVAL,
		"setsockopt IPV6_RTHDR should fail (Type 0 requires at least one address)");

	close(fd);
}

T_DECL(ipv6_rthdrdstopts_requires_root, "IPV6_RTHDRDSTOPTS requires root privilege",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_RTHDRDSTOPTS requires root privilege - destination options before routing header */
	unsigned char dstopts[8] = {
		IPPROTO_ROUTING,  /* next header (routing) */
		0,                /* length (0 = 8 bytes total) */
		0x01, 0x04, 0x00, 0x00, 0x00, 0x00  /* PadN option */
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDRDSTOPTS, dstopts, sizeof(dstopts)),
		"setsockopt IPV6_RTHDRDSTOPTS");

	close(fd);
}

T_DECL(ipv6_nexthop_requires_root, "IPV6_NEXTHOP requires root privilege",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_NEXTHOP requires root privilege */
	struct sockaddr_in6 nexthop = {
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_family = AF_INET6,
		.sin6_port = 0,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_NEXTHOP, &nexthop, sizeof(nexthop)),
		"setsockopt IPV6_NEXTHOP");

	close(fd);
}

T_DECL(ipv6_recvhopopts_requires_root, "IPV6_RECVHOPOPTS requires root privilege",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_RECVHOPOPTS requires root privilege - KAME prevents non-privileged
	 * users from receiving hop-by-hop options to avoid kernel parsing overhead
	 */
	test_ipv6_bool_option(fd, IPV6_RECVHOPOPTS, "IPV6_RECVHOPOPTS", 0, false);
	test_ipv6_bool_option(fd, IPV6_RECVHOPOPTS, "IPV6_RECVHOPOPTS", 1, true);

	close(fd);
}

T_DECL(ipv6_recvdstopts_requires_root, "IPV6_RECVDSTOPTS requires root privilege",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_RECVDSTOPTS requires root privilege */
	test_ipv6_bool_option(fd, IPV6_RECVDSTOPTS, "IPV6_RECVDSTOPTS", 0, false);
	test_ipv6_bool_option(fd, IPV6_RECVDSTOPTS, "IPV6_RECVDSTOPTS", 1, true);

	close(fd);
}

T_DECL(ipv6_recvrthdr_inet6_udp, "IPV6_RECVRTHDR on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Test receiving routing header (boolean) */
	test_ipv6_bool_option(fd, IPV6_RECVRTHDR, "IPV6_RECVRTHDR", 0, false);
	test_ipv6_bool_option(fd, IPV6_RECVRTHDR, "IPV6_RECVRTHDR", 1, true);

	close(fd);
}

T_DECL(ipv6_recvpathmtu_inet6_udp, "IPV6_RECVPATHMTU on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Test receiving path MTU updates (boolean) */
	test_ipv6_bool_option(fd, IPV6_RECVPATHMTU, "IPV6_RECVPATHMTU", 0, false);
	test_ipv6_bool_option(fd, IPV6_RECVPATHMTU, "IPV6_RECVPATHMTU", 1, true);

	close(fd);
}

T_DECL(ipv6_pathmtu_inet6_udp, "IPV6_PATHMTU on AF_INET6 UDP (read-only)")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_PATHMTU is read-only - returns struct ip6_mtuinfo */
	struct ip6_mtuinfo mtuinfo;
	socklen_t optlen = sizeof(mtuinfo);

	/* getsockopt may succeed or fail depending on whether socket is connected */
	/* We just verify the option exists */
	int ret = getsockopt(fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &optlen);
	if (ret < 0) {
		/* Expected to fail on unconnected socket */
		T_EXPECT_EQ(errno, ENOTCONN, "IPV6_PATHMTU should fail with ENOTCONN on unconnected socket");
	}

	/* Verify setsockopt fails (read-only) */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, sizeof(mtuinfo)),
		ENOPROTOOPT,
		"setsockopt IPV6_PATHMTU should fail (read-only)");

	close(fd);
}

T_DECL(ipv6_autoflowlabel_inet6_udp, "IPV6_AUTOFLOWLABEL on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Test automatic flow label generation (boolean) */
	test_ipv6_bool_option(fd, IPV6_AUTOFLOWLABEL, "IPV6_AUTOFLOWLABEL", 0, false);
	test_ipv6_bool_option(fd, IPV6_AUTOFLOWLABEL, "IPV6_AUTOFLOWLABEL", 1, true);

	close(fd);
}

T_DECL(ipv6_out_if_inet6_udp, "IPV6_OUT_IF on AF_INET6 UDP (read-only)")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_OUT_IF is read-only - returns the last output interface index
	 * On a new unconnected socket, this should be 0
	 */
	int ifindex = -1;
	socklen_t optlen = sizeof(ifindex);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_OUT_IF, &ifindex, &optlen),
		"getsockopt IPV6_OUT_IF");

	T_EXPECT_EQ(ifindex, 0,
	    "IPV6_OUT_IF should be 0 on new socket (no packets sent yet)");

	/* Verify setsockopt fails (read-only) */
	ifindex = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_OUT_IF, &ifindex, sizeof(ifindex)),
		EINVAL,
		"setsockopt IPV6_OUT_IF should fail (read-only)");

	close(fd);
}

T_DECL(ipv6_extension_headers_multi, "Multiple IPv6 extension header receive options")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Enable receiving multiple extension headers (non-privileged options) */
	test_ipv6_bool_option(fd, IPV6_RECVRTHDR, "IPV6_RECVRTHDR", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVPATHMTU, "IPV6_RECVPATHMTU", 1, true);
	test_ipv6_bool_option(fd, IPV6_AUTOFLOWLABEL, "IPV6_AUTOFLOWLABEL", 1, true);

	close(fd);
}

T_DECL(ipv6_extension_headers_privileged, "Multiple privileged IPv6 extension header options",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Enable receiving extension headers that require root privilege */
	test_ipv6_bool_option(fd, IPV6_RECVHOPOPTS, "IPV6_RECVHOPOPTS", 1, true);
	test_ipv6_bool_option(fd, IPV6_RECVDSTOPTS, "IPV6_RECVDSTOPTS", 1, true);

	close(fd);
}

/*
 * IPv6 Multicast Options
 */

T_DECL(ipv6_join_group_inet6_udp, "IPV6_JOIN_GROUP on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_JOIN_GROUP joins an IPv6 multicast group
	 * Test joining and then leaving a multicast group
	 */
	struct ipv6_mreq mreq6;
	memset(&mreq6, 0, sizeof(mreq6));

	/* Use a valid IPv6 multicast address (ff02::1 - all nodes link-local)
	 * For link-local multicast, we need to specify an interface
	 */
	inet_pton(AF_INET6, "ff02::1", &mreq6.ipv6mr_multiaddr);

	/* Get loopback interface index for testing */
	unsigned int lo_idx = if_nametoindex("lo0");
	T_ASSERT_GT(lo_idx, 0U, "if_nametoindex(lo0)");
	mreq6.ipv6mr_interface = lo_idx;

	/* Join the multicast group */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)),
		"setsockopt IPV6_JOIN_GROUP");

	/* Leave the multicast group */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6)),
		"setsockopt IPV6_LEAVE_GROUP");

	/* Trying to join the same group again should succeed */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)),
		"setsockopt IPV6_JOIN_GROUP (second time)");

	/* Clean up - leave the group */
	setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6));

	close(fd);
}

T_DECL(ipv6_leave_group_inet6_udp, "IPV6_LEAVE_GROUP on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_LEAVE_GROUP leaves a multicast group
	 * This should fail if we haven't joined the group first
	 */
	struct ipv6_mreq mreq6;
	memset(&mreq6, 0, sizeof(mreq6));

	/* Use a valid IPv6 multicast address (ff02::1 - all nodes link-local) */
	inet_pton(AF_INET6, "ff02::1", &mreq6.ipv6mr_multiaddr);

	/* Get loopback interface index for testing */
	unsigned int lo_idx = if_nametoindex("lo0");
	T_ASSERT_GT(lo_idx, 0U, "if_nametoindex(lo0)");
	mreq6.ipv6mr_interface = lo_idx;

	/* Should fail since we never joined */
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6));
	T_EXPECT_EQ(ret, -1, "IPV6_LEAVE_GROUP should fail without prior join");
	if (ret == -1) {
		T_LOG("IPV6_LEAVE_GROUP failed as expected: %d (%s)", errno, strerror(errno));
	}

	close(fd);
}

T_DECL(ipv6_multicast_loop_inet6_udp, "IPV6_MULTICAST_LOOP on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_MULTICAST_LOOP controls whether multicast packets loop back */
	test_ipv6_bool_option(fd, IPV6_MULTICAST_LOOP, "IPV6_MULTICAST_LOOP", 1, true);
	test_ipv6_bool_option(fd, IPV6_MULTICAST_LOOP, "IPV6_MULTICAST_LOOP", 0, false);

	close(fd);
}

T_DECL(ipv6_msfilter_inet6_udp, "IPV6_MSFILTER on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_MSFILTER sets the multicast source filter
	 * Test with an empty filter (no sources)
	 */
	struct group_filter {
		uint32_t gf_interface;          /* Interface index */
		struct sockaddr_storage gf_group; /* Multicast group address */
		uint32_t gf_fmode;              /* Filter mode (MCAST_INCLUDE or MCAST_EXCLUDE) */
		uint32_t gf_numsrc;             /* Number of sources */
		struct sockaddr_storage gf_slist[1]; /* Source addresses */
	} gsf;

	memset(&gsf, 0, sizeof(gsf));
	gsf.gf_interface = 0; /* Default interface */

	/* Set up IPv6 multicast group address */
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&gsf.gf_group;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	inet_pton(AF_INET6, "ff02::1", &sin6->sin6_addr);

	gsf.gf_fmode = 1; /* MCAST_INCLUDE */
	gsf.gf_numsrc = 0; /* No sources */

	/* This will likely fail without group membership, which is expected */
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_MSFILTER, &gsf, sizeof(gsf));
	if (ret == -1) {
		T_LOG("IPV6_MSFILTER failed (expected without membership): %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("IPV6_MSFILTER succeeded");
	}

	close(fd);
}

T_DECL(ipv6_multicast_hops_inet6_udp, "IPV6_MULTICAST_HOPS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_MULTICAST_HOPS controls the hop limit for multicast packets
	 * Default is 1 (link-local only), valid range is 0-255
	 */

	/* Test setting various hop limits */
	test_ipv6_int_option_roundtrip(fd, IPV6_MULTICAST_HOPS, "IPV6_MULTICAST_HOPS", 1, 1);
	test_ipv6_int_option_roundtrip(fd, IPV6_MULTICAST_HOPS, "IPV6_MULTICAST_HOPS", 32, 32);
	test_ipv6_int_option_roundtrip(fd, IPV6_MULTICAST_HOPS, "IPV6_MULTICAST_HOPS", 64, 64);
	test_ipv6_int_option_roundtrip(fd, IPV6_MULTICAST_HOPS, "IPV6_MULTICAST_HOPS", 255, 255);
	test_ipv6_int_option_roundtrip(fd, IPV6_MULTICAST_HOPS, "IPV6_MULTICAST_HOPS", 0, 0);

	/* Test invalid value > 255 */
	int invalid = 256;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &invalid, sizeof(invalid)),
		EINVAL,
		"IPV6_MULTICAST_HOPS should reject value > 255");

	close(fd);
}

T_DECL(ipv6_multicast_if_inet6_udp, "IPV6_MULTICAST_IF on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_MULTICAST_IF sets the outgoing interface for multicast packets
	 * Value is an interface index (unsigned int)
	 */

	/* Get loopback interface index */
	unsigned int lo_idx = if_nametoindex("lo0");
	T_ASSERT_GT(lo_idx, 0U, "if_nametoindex(lo0)");

	/* Test setting to loopback interface */
	test_ipv6_int_option_roundtrip(fd, IPV6_MULTICAST_IF, "IPV6_MULTICAST_IF", (int)lo_idx, (int)lo_idx);

	/* Verify we can read back the current interface */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &getval, &optlen),
		"getsockopt IPV6_MULTICAST_IF");
	T_EXPECT_EQ(getval, (int)lo_idx, "IPV6_MULTICAST_IF is loopback interface");

	/* Test invalid interface index (0 is not valid) */
	unsigned int invalid_idx = 0;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &invalid_idx, sizeof(invalid_idx)),
		EINVAL,
		"IPV6_MULTICAST_IF should reject interface index 0");

	/* Test invalid interface index (999999 doesn't exist) */
	invalid_idx = 999999;
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &invalid_idx, sizeof(invalid_idx));
	T_EXPECT_EQ(ret, -1, "IPV6_MULTICAST_IF should reject invalid interface index");
	if (ret == -1) {
		/* May return EINVAL or ENXIO depending on implementation */
		T_EXPECT_TRUE(errno == EINVAL || errno == ENXIO,
		    "errno should be EINVAL or ENXIO (got %d: %s)", errno, strerror(errno));
	}

	close(fd);
}

T_DECL(ipv6_pktinfo_inet6_udp, "IPV6_PKTINFO on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* IPV6_PKTINFO is a sticky option (RFC 3542) that sets the source address
	 * and outgoing interface for packets sent on this socket.
	 * This is different from IPV6_RECVPKTINFO which receives packet info.
	 *
	 * Note: Setting IPV6_PKTINFO requires the socket to be connected or
	 * the address to be unspecified, otherwise it may fail with EINVAL.
	 */

	struct in6_pktinfo pktinfo;
	memset(&pktinfo, 0, sizeof(pktinfo));

	/* Set to unspecified address (in6addr_any) and interface 0 (default) */
	pktinfo.ipi6_addr = in6addr_any;
	pktinfo.ipi6_ifindex = 0;

	/* Try to set IPV6_PKTINFO */
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &pktinfo, sizeof(pktinfo));
	if (ret == -1) {
		/* May fail with EINVAL on unconnected socket, which is acceptable */
		T_LOG("IPV6_PKTINFO setsockopt failed (may require connected socket): %d (%s)",
		    errno, strerror(errno));
	} else {
		T_LOG("IPV6_PKTINFO setsockopt succeeded");

		/* Try to get IPV6_PKTINFO back */
		struct in6_pktinfo get_pktinfo;
		socklen_t optlen = sizeof(get_pktinfo);
		ret = getsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &get_pktinfo, &optlen);
		if (ret == 0) {
			T_LOG("IPV6_PKTINFO getsockopt succeeded");
		} else {
			T_LOG("IPV6_PKTINFO getsockopt failed: %d (%s)", errno, strerror(errno));
		}
	}

	close(fd);
}
