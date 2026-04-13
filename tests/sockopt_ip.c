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
 * sockopt_ip.c
 *
 * Tests for IPPROTO_IP level socket options.
 * Tests IPv4-specific options like IP_TOS, IP_TTL, IP_HDRINCL,
 * IP_RECVOPTS, IP_RECVDSTADDR, IP_RECVIF, etc.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <darwintest.h>
#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net.sockopt"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * Helper to test basic integer IP option round-trip
 */
static void
test_ip_int_option_roundtrip(int fd, int optname, const char *optname_str,
    int setval, int expected_getval)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, optname, &getval, &optlen),
		"getsockopt %s", optname_str);

	T_EXPECT_EQ(getval, expected_getval,
	    "%s value matches (expected %d, got %d)",
	    optname_str, expected_getval, getval);
}

/*
 * Helper to test boolean IP options
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_ip_bool_option(int fd, int optname, const char *optname_str,
    int setval, bool expect_enabled)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, optname, &getval, &optlen),
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
 * Test IP_TOS - Type of Service
 */
T_DECL(ip_tos_inet_tcp, "IP_TOS on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test various TOS values */
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", IPTOS_LOWDELAY, IPTOS_LOWDELAY);
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", IPTOS_THROUGHPUT, IPTOS_THROUGHPUT);
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", IPTOS_RELIABILITY, IPTOS_RELIABILITY);
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", 0, 0);

	close(fd);
}

T_DECL(ip_tos_inet_udp, "IP_TOS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", IPTOS_LOWDELAY, IPTOS_LOWDELAY);
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", 0, 0);

	close(fd);
}

T_DECL(ip_tos_on_inet6, "IP_TOS fails on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	int optval = IPTOS_LOWDELAY;
	int ret = setsockopt(fd, IPPROTO_IP, IP_TOS, &optval, sizeof(optval));

	T_ASSERT_EQ(ret, -1, "IP_TOS should fail on AF_INET6 socket");
	T_EXPECT_TRUE(errno == ENOPROTOOPT || errno == EINVAL,
	    "errno should be ENOPROTOOPT or EINVAL (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

/*
 * Test IP_TTL - Time to Live
 */
T_DECL(ip_ttl_inet_tcp, "IP_TTL on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test various TTL values */
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 64, 64);
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 128, 128);
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 255, 255);
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 1, 1);

	close(fd);
}

T_DECL(ip_ttl_inet_udp, "IP_TTL on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 32, 32);
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 255, 255);

	close(fd);
}

T_DECL(ip_ttl_invalid_values, "IP_TTL rejects values > 255")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test value > 255 */
	int toolarge = 256;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IP, IP_TTL, &toolarge, sizeof(toolarge)),
		EINVAL,
		"IP_TTL should reject value > 255");

	close(fd);
}

/*
 * Test IP_RECVOPTS - Receive all IP options with datagram
 */
T_DECL(ip_recvopts_inet_udp, "IP_RECVOPTS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVOPTS, "IP_RECVOPTS", 1, true);
	test_ip_bool_option(fd, IP_RECVOPTS, "IP_RECVOPTS", 0, false);

	close(fd);
}

/*
 * Test IP_RECVRETOPTS - Receive IP options for response
 */
T_DECL(ip_recvretopts_inet_udp, "IP_RECVRETOPTS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVRETOPTS, "IP_RECVRETOPTS", 1, true);
	test_ip_bool_option(fd, IP_RECVRETOPTS, "IP_RECVRETOPTS", 0, false);

	close(fd);
}

/*
 * Test IP_RECVDSTADDR - Receive destination address
 */
T_DECL(ip_recvdstaddr_inet_udp, "IP_RECVDSTADDR on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVDSTADDR, "IP_RECVDSTADDR", 1, true);
	test_ip_bool_option(fd, IP_RECVDSTADDR, "IP_RECVDSTADDR", 0, false);

	close(fd);
}

/*
 * Test IP_RECVIF - Receive interface information
 */
T_DECL(ip_recvif_inet_udp, "IP_RECVIF on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVIF, "IP_RECVIF", 1, true);
	test_ip_bool_option(fd, IP_RECVIF, "IP_RECVIF", 0, false);

	close(fd);
}

/*
 * Test IP_RECVTTL - Receive TTL
 */
T_DECL(ip_recvttl_inet_udp, "IP_RECVTTL on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVTTL, "IP_RECVTTL", 1, true);
	test_ip_bool_option(fd, IP_RECVTTL, "IP_RECVTTL", 0, false);

	close(fd);
}

/*
 * Test IP_RECVTOS - Receive TOS
 */
T_DECL(ip_recvtos_inet_udp, "IP_RECVTOS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVTOS, "IP_RECVTOS", 1, true);
	test_ip_bool_option(fd, IP_RECVTOS, "IP_RECVTOS", 0, false);

	close(fd);
}

/*
 * Test IP_RECVPKTINFO - Receive packet information
 */
T_DECL(ip_recvpktinfo_inet_udp, "IP_RECVPKTINFO on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_RECVPKTINFO, "IP_RECVPKTINFO", 1, true);
	test_ip_bool_option(fd, IP_RECVPKTINFO, "IP_RECVPKTINFO", 0, false);

	close(fd);
}

/*
 * Test IP_HDRINCL - Include IP header (RAW sockets only)
 */
T_DECL(ip_hdrincl_raw, "IP_HDRINCL on RAW socket",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_RAW)");

	test_ip_bool_option(fd, IP_HDRINCL, "IP_HDRINCL", 1, true);
	test_ip_bool_option(fd, IP_HDRINCL, "IP_HDRINCL", 0, false);

	close(fd);
}

/*
 * Test IP_DONTFRAG - Don't fragment packets
 */
T_DECL(ip_dontfrag_inet_udp, "IP_DONTFRAG on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_ip_bool_option(fd, IP_DONTFRAG, "IP_DONTFRAG", 1, true);
	test_ip_bool_option(fd, IP_DONTFRAG, "IP_DONTFRAG", 0, false);

	close(fd);
}

T_DECL(ip_dontfrag_inet_tcp, "IP_DONTFRAG on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_ip_bool_option(fd, IP_DONTFRAG, "IP_DONTFRAG", 1, true);
	test_ip_bool_option(fd, IP_DONTFRAG, "IP_DONTFRAG", 0, false);

	close(fd);
}

/*
 * Test IP_BOUND_IF - Bind socket to interface
 */
T_DECL(ip_bound_if_inet_udp, "IP_BOUND_IF on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Get loopback interface index */
	unsigned int lo_idx = if_nametoindex("lo0");
	T_ASSERT_GT(lo_idx, 0U, "if_nametoindex(lo0)");

	test_ip_int_option_roundtrip(fd, IP_BOUND_IF, "IP_BOUND_IF", (int)lo_idx, (int)lo_idx);

	/* Unbind */
	test_ip_int_option_roundtrip(fd, IP_BOUND_IF, "IP_BOUND_IF", 0, 0);

	close(fd);
}

/*
 * Test IP_NO_IFT_CELLULAR - Disallow cellular interface
 * Note: This is a write-once option - once set, it cannot be cleared
 */
T_DECL(ip_no_ift_cellular_inet_tcp, "IP_NO_IFT_CELLULAR on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Initially should be disabled */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_NO_IFT_CELLULAR, &getval, &optlen),
		"getsockopt IP_NO_IFT_CELLULAR");
	T_EXPECT_EQ(getval, 0, "IP_NO_IFT_CELLULAR initially disabled");

	/* Enable it */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_NO_IFT_CELLULAR, &enable, sizeof(enable)),
		"setsockopt IP_NO_IFT_CELLULAR = 1");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_NO_IFT_CELLULAR, &getval, &optlen),
		"getsockopt IP_NO_IFT_CELLULAR");
	T_EXPECT_NE(getval, 0, "IP_NO_IFT_CELLULAR is enabled (got %d)", getval);

	/* Attempting to clear it should fail */
	int disable = 0;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IP, IP_NO_IFT_CELLULAR, &disable, sizeof(disable)),
		EINVAL,
		"setsockopt IP_NO_IFT_CELLULAR = 0 should fail (write-once option)");

	/* Verify it's still enabled */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_NO_IFT_CELLULAR, &getval, &optlen),
		"getsockopt IP_NO_IFT_CELLULAR");
	T_EXPECT_NE(getval, 0, "IP_NO_IFT_CELLULAR still enabled (got %d)", getval);

	close(fd);
}

/*
 * Test multiple IP options on same socket
 */
T_DECL(ip_multiple_options, "Multiple IP options on same socket")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Set multiple options */
	int tos = IPTOS_LOWDELAY;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)),
		"setsockopt IP_TOS");

	int ttl = 64;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)),
		"setsockopt IP_TTL");

	int recvdstaddr = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &recvdstaddr, sizeof(recvdstaddr)),
		"setsockopt IP_RECVDSTADDR");

	int dontfrag = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &dontfrag, sizeof(dontfrag)),
		"setsockopt IP_DONTFRAG");

	/* Verify all options */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	/* IP_TOS is integer value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_TOS, &getval, &optlen),
		"getsockopt IP_TOS");
	T_EXPECT_EQ(getval, IPTOS_LOWDELAY, "IP_TOS still set");

	/* IP_TTL is integer value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_TTL, &getval, &optlen),
		"getsockopt IP_TTL");
	T_EXPECT_EQ(getval, 64, "IP_TTL still set");

	/* IP_RECVDSTADDR is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &getval, &optlen),
		"getsockopt IP_RECVDSTADDR");
	T_EXPECT_NE(getval, 0, "IP_RECVDSTADDR still enabled (got %d)", getval);

	/* IP_DONTFRAG is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &getval, &optlen),
		"getsockopt IP_DONTFRAG");
	T_EXPECT_NE(getval, 0, "IP_DONTFRAG still enabled (got %d)", getval);

	close(fd);
}

/*
 * Test IP options on bound socket
 */
T_DECL(ip_options_bound_socket, "IP options work on bound socket")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0, /* Let kernel choose port */
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	T_ASSERT_POSIX_SUCCESS(
		bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"bind to localhost");

	/* Options should still work after binding */
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", IPTOS_THROUGHPUT, IPTOS_THROUGHPUT);
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 128, 128);
	test_ip_bool_option(fd, IP_RECVIF, "IP_RECVIF", 1, true);

	close(fd);
}

/*
 * Test IP options on connected UDP socket
 */
T_DECL(ip_options_connected_socket, "IP options work on connected UDP socket")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9999),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	T_ASSERT_POSIX_SUCCESS(
		connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"connect to localhost:9999");

	/* Options should still work after connecting */
	test_ip_int_option_roundtrip(fd, IP_TOS, "IP_TOS", IPTOS_RELIABILITY, IPTOS_RELIABILITY);
	test_ip_int_option_roundtrip(fd, IP_TTL, "IP_TTL", 255, 255);
	test_ip_bool_option(fd, IP_DONTFRAG, "IP_DONTFRAG", 1, true);

	close(fd);
}

/*
 * Test invalid option lengths
 */
T_DECL(ip_tos_invalid_optlen, "IP_TOS with invalid optlen")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Too small */
	char smallval = IPTOS_LOWDELAY;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IP, IP_TOS, &smallval, sizeof(smallval)),
		EINVAL,
		"setsockopt IP_TOS with too small optlen should fail");

	/* NULL pointer with non-zero length */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IP, IP_TOS, NULL, sizeof(int)),
		EFAULT,
		"setsockopt IP_TOS with NULL optval should fail");

	close(fd);
}

/*
 * Test IP_PORTRANGE - Port range for bind
 */
T_DECL(ip_portrange_inet_udp, "IP_PORTRANGE on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Test different port ranges */
	test_ip_int_option_roundtrip(fd, IP_PORTRANGE, "IP_PORTRANGE",
	    IP_PORTRANGE_DEFAULT, IP_PORTRANGE_DEFAULT);
	test_ip_int_option_roundtrip(fd, IP_PORTRANGE, "IP_PORTRANGE",
	    IP_PORTRANGE_HIGH, IP_PORTRANGE_HIGH);
	test_ip_int_option_roundtrip(fd, IP_PORTRANGE, "IP_PORTRANGE",
	    IP_PORTRANGE_LOW, IP_PORTRANGE_LOW);

	close(fd);
}

T_DECL(ip_portrange_inet_tcp, "IP_PORTRANGE on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_ip_int_option_roundtrip(fd, IP_PORTRANGE, "IP_PORTRANGE",
	    IP_PORTRANGE_DEFAULT, IP_PORTRANGE_DEFAULT);
	test_ip_int_option_roundtrip(fd, IP_PORTRANGE, "IP_PORTRANGE",
	    IP_PORTRANGE_HIGH, IP_PORTRANGE_HIGH);

	close(fd);
}

/*
 * Test IP_STRIPHDR - Strip IP header from received raw IP packets
 * This option is only valid for SOCK_RAW sockets
 */
T_DECL(ip_striphdr_raw, "IP_STRIPHDR on SOCK_RAW",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");

	test_ip_bool_option(fd, IP_STRIPHDR, "IP_STRIPHDR", 1, true);
	test_ip_bool_option(fd, IP_STRIPHDR, "IP_STRIPHDR", 0, false);

	close(fd);
}

T_DECL(ip_striphdr_on_stream, "IP_STRIPHDR fails on non-raw socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* IP_STRIPHDR only works on raw sockets */
	int enable = 1;
	int ret = setsockopt(fd, IPPROTO_IP, IP_STRIPHDR, &enable, sizeof(enable));

	/* Should either fail or be silently ignored */
	if (ret == -1) {
		T_LOG("IP_STRIPHDR failed on SOCK_STREAM as expected: %d (%s)",
		    errno, strerror(errno));
	} else {
		T_LOG("IP_STRIPHDR accepted on SOCK_STREAM (may be ignored)");
	}

	close(fd);
}

/*
 * Multicast Options
 */

T_DECL(ip_multicast_loop_inet_udp, "IP_MULTICAST_LOOP on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_MULTICAST_LOOP controls whether multicast packets loop back */
	test_ip_bool_option(fd, IP_MULTICAST_LOOP, "IP_MULTICAST_LOOP", 1, true);
	test_ip_bool_option(fd, IP_MULTICAST_LOOP, "IP_MULTICAST_LOOP", 0, false);

	close(fd);
}

T_DECL(ip_multicast_ifindex_inet_udp, "IP_MULTICAST_IFINDEX on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_MULTICAST_IFINDEX sets the outgoing multicast interface by index
	 * Setting to 0 means use default interface
	 */
	unsigned int ifindex = 0;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IFINDEX, &ifindex, sizeof(ifindex)),
		"setsockopt IP_MULTICAST_IFINDEX = 0");

	/* Verify it was set */
	unsigned int getval = 999;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_MULTICAST_IFINDEX, &getval, &optlen),
		"getsockopt IP_MULTICAST_IFINDEX");
	T_EXPECT_EQ(getval, 0, "IP_MULTICAST_IFINDEX should be 0");

	close(fd);
}

T_DECL(ip_drop_source_membership_inet_udp, "IP_DROP_SOURCE_MEMBERSHIP on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_DROP_SOURCE_MEMBERSHIP leaves a source-specific multicast group
	 * This should fail if we haven't joined the group first
	 */
	struct ip_mreq_source mreqs;
	memset(&mreqs, 0, sizeof(mreqs));

	/* Use a valid multicast address (239.255.255.250) */
	inet_pton(AF_INET, "239.255.255.250", &mreqs.imr_multiaddr);
	inet_pton(AF_INET, "192.0.2.1", &mreqs.imr_sourceaddr);
	mreqs.imr_interface.s_addr = INADDR_ANY;

	/* Should fail since we never joined */
	int ret = setsockopt(fd, IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, &mreqs, sizeof(mreqs));
	T_EXPECT_EQ(ret, -1, "IP_DROP_SOURCE_MEMBERSHIP should fail without prior join");
	if (ret == -1) {
		T_LOG("IP_DROP_SOURCE_MEMBERSHIP failed as expected: %d (%s)", errno, strerror(errno));
	}

	close(fd);
}

T_DECL(ip_block_source_inet_udp, "IP_BLOCK_SOURCE on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_BLOCK_SOURCE blocks a multicast source
	 * This should fail if we haven't joined the group first
	 */
	struct ip_mreq_source mreqs;
	memset(&mreqs, 0, sizeof(mreqs));

	inet_pton(AF_INET, "239.255.255.250", &mreqs.imr_multiaddr);
	inet_pton(AF_INET, "192.0.2.1", &mreqs.imr_sourceaddr);
	mreqs.imr_interface.s_addr = INADDR_ANY;

	/* Should fail since we never joined the group */
	int ret = setsockopt(fd, IPPROTO_IP, IP_BLOCK_SOURCE, &mreqs, sizeof(mreqs));
	T_EXPECT_EQ(ret, -1, "IP_BLOCK_SOURCE should fail without group membership");
	if (ret == -1) {
		T_LOG("IP_BLOCK_SOURCE failed as expected: %d (%s)", errno, strerror(errno));
	}

	close(fd);
}

T_DECL(ip_unblock_source_inet_udp, "IP_UNBLOCK_SOURCE on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_UNBLOCK_SOURCE unblocks a previously blocked multicast source
	 * This should fail if we haven't blocked the source first
	 */
	struct ip_mreq_source mreqs;
	memset(&mreqs, 0, sizeof(mreqs));

	inet_pton(AF_INET, "239.255.255.250", &mreqs.imr_multiaddr);
	inet_pton(AF_INET, "192.0.2.1", &mreqs.imr_sourceaddr);
	mreqs.imr_interface.s_addr = INADDR_ANY;

	/* Should fail since we never blocked the source */
	int ret = setsockopt(fd, IPPROTO_IP, IP_UNBLOCK_SOURCE, &mreqs, sizeof(mreqs));
	T_EXPECT_EQ(ret, -1, "IP_UNBLOCK_SOURCE should fail without prior block");
	if (ret == -1) {
		T_LOG("IP_UNBLOCK_SOURCE failed as expected: %d (%s)", errno, strerror(errno));
	}

	close(fd);
}

T_DECL(ip_msfilter_inet_udp, "IP_MSFILTER on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_MSFILTER sets the multicast source filter
	 * Test with an empty filter (no sources)
	 */
	struct ip_msfilter {
		struct in_addr imsf_multiaddr;  /* Multicast group address */
		struct in_addr imsf_interface;  /* Local interface address */
		uint32_t imsf_fmode;            /* Filter mode (MCAST_INCLUDE or MCAST_EXCLUDE) */
		uint32_t imsf_numsrc;           /* Number of sources */
		struct in_addr imsf_slist[1];   /* Source addresses */
	} msf;

	memset(&msf, 0, sizeof(msf));
	inet_pton(AF_INET, "239.255.255.250", &msf.imsf_multiaddr);
	msf.imsf_interface.s_addr = INADDR_ANY;
	msf.imsf_fmode = 1; /* MCAST_INCLUDE */
	msf.imsf_numsrc = 0; /* No sources */

	/* This will likely fail without group membership, which is expected */
	int ret = setsockopt(fd, IPPROTO_IP, IP_MSFILTER, &msf, sizeof(msf));
	if (ret == -1) {
		T_LOG("IP_MSFILTER failed (expected without membership): %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("IP_MSFILTER succeeded");
	}

	close(fd);
}

/*
 * IPv4 Multicast Core Options - using feth interface pair
 */

#define MCAST_TEST_NET          0x0a010000  /* 10.1.0.0 */
#define MCAST_TEST_ADDR_1       (MCAST_TEST_NET | 0x01)  /* 10.1.0.1 */
#define MCAST_TEST_ADDR_2       (MCAST_TEST_NET | 0x02)  /* 10.1.0.2 */
#define MCAST_TEST_MASK         0xffffff00  /* 255.255.255.0 */

static char g_feth1_name[IFNAMSIZ];
static char g_feth2_name[IFNAMSIZ];

static void
cleanup_feth_pair(void)
{
	if (g_feth1_name[0]) {
		ifnet_destroy(g_feth1_name, false);
		g_feth1_name[0] = '\0';
	}
	if (g_feth2_name[0]) {
		ifnet_destroy(g_feth2_name, false);
		g_feth2_name[0] = '\0';
	}
	/* Allow time for interfaces to be fully torn down */
	usleep(100000);
}

static void
setup_feth_pair(char *feth1_name, size_t name1_len,
    char *feth2_name, size_t name2_len,
    struct in_addr *addr1, struct in_addr *addr2)
{
	struct in_addr mask;

	/* Create first feth interface */
	strlcpy(feth1_name, "feth", name1_len);
	T_ASSERT_POSIX_SUCCESS(ifnet_create_2(feth1_name, name1_len),
	    "create %s", feth1_name);

	/* Create second feth interface */
	strlcpy(feth2_name, "feth", name2_len);
	T_ASSERT_POSIX_SUCCESS(ifnet_create_2(feth2_name, name2_len),
	    "create %s", feth2_name);

	/* Set them as peers */
	fake_set_peer(feth1_name, feth2_name);

	/* Assign IP addresses */
	addr1->s_addr = htonl(MCAST_TEST_ADDR_1);
	addr2->s_addr = htonl(MCAST_TEST_ADDR_2);
	mask.s_addr = htonl(MCAST_TEST_MASK);

	ifnet_add_ip_address(feth1_name, *addr1, mask);
	ifnet_add_ip_address(feth2_name, *addr2, mask);

	T_LOG("Created feth pair: %s (%s) <-> %s (%s)",
	    feth1_name, inet_ntoa(*addr1),
	    feth2_name, inet_ntoa(*addr2));
}

T_DECL(ip_add_membership_inet_udp, "IP_ADD_MEMBERSHIP on AF_INET UDP",
    T_META_ASROOT(true))
{
	struct in_addr feth1_addr, feth2_addr;
	int fd;

	/* Setup feth pair */
	setup_feth_pair(g_feth1_name, sizeof(g_feth1_name),
	    g_feth2_name, sizeof(g_feth2_name),
	    &feth1_addr, &feth2_addr);

	T_ATEND(cleanup_feth_pair);

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Bind to feth1 address */
	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = feth1_addr
	};
	T_ASSERT_POSIX_SUCCESS(
		bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)),
		"bind socket to %s", inet_ntoa(feth1_addr));

	/* IP_ADD_MEMBERSHIP joins an IPv4 multicast group
	 * Test joining and then leaving a multicast group
	 */
	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	/* Use a valid IPv4 multicast address (239.255.255.250 - SSDP) */
	inet_pton(AF_INET, "239.255.255.250", &mreq.imr_multiaddr);
	mreq.imr_interface = feth1_addr; /* Use feth1 interface */

	/* Join the multicast group */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)),
		"setsockopt IP_ADD_MEMBERSHIP");

	/* Leave the multicast group */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)),
		"setsockopt IP_DROP_MEMBERSHIP");

	/* Trying to join the same group again should succeed */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)),
		"setsockopt IP_ADD_MEMBERSHIP (second time)");

	/* Clean up - leave the group */
	setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

	close(fd);
}

T_DECL(ip_drop_membership_inet_udp, "IP_DROP_MEMBERSHIP on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_DROP_MEMBERSHIP leaves a multicast group
	 * This should fail if we haven't joined the group first
	 */
	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	/* Use a valid IPv4 multicast address (239.255.255.250 - SSDP) */
	inet_pton(AF_INET, "239.255.255.250", &mreq.imr_multiaddr);
	mreq.imr_interface.s_addr = INADDR_ANY; /* Default interface */

	/* Should fail since we never joined */
	int ret = setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
	T_EXPECT_EQ(ret, -1, "IP_DROP_MEMBERSHIP should fail without prior join");
	if (ret == -1) {
		T_LOG("IP_DROP_MEMBERSHIP failed as expected: %d (%s)", errno, strerror(errno));
	}

	close(fd);
}

T_DECL(ip_multicast_if_inet_udp, "IP_MULTICAST_IF on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_MULTICAST_IF sets the outgoing interface for multicast packets
	 * Value is a struct in_addr specifying the local interface
	 */

	/* Test setting to INADDR_ANY (default) */
	struct in_addr ifaddr;
	ifaddr.s_addr = INADDR_ANY;

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)),
		"setsockopt IP_MULTICAST_IF = INADDR_ANY");

	/* Verify the setting */
	struct in_addr get_ifaddr;
	socklen_t optlen = sizeof(get_ifaddr);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &get_ifaddr, &optlen),
		"getsockopt IP_MULTICAST_IF");
	T_EXPECT_EQ(get_ifaddr.s_addr, INADDR_ANY, "IP_MULTICAST_IF is INADDR_ANY");

	/* Test setting to loopback address */
	inet_pton(AF_INET, "127.0.0.1", &ifaddr);
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)),
		"setsockopt IP_MULTICAST_IF = 127.0.0.1");

	/* Verify the setting */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &get_ifaddr, &optlen),
		"getsockopt IP_MULTICAST_IF");
	T_EXPECT_EQ(get_ifaddr.s_addr, ifaddr.s_addr, "IP_MULTICAST_IF is 127.0.0.1");

	close(fd);
}

T_DECL(ip_multicast_ttl_inet_udp, "IP_MULTICAST_TTL on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_MULTICAST_TTL controls the TTL for multicast packets
	 * Default is 1 (subnet-local only), valid range is 0-255
	 */

	/* Test setting various TTL values */
	test_ip_int_option_roundtrip(fd, IP_MULTICAST_TTL, "IP_MULTICAST_TTL", 1, 1);
	test_ip_int_option_roundtrip(fd, IP_MULTICAST_TTL, "IP_MULTICAST_TTL", 32, 32);
	test_ip_int_option_roundtrip(fd, IP_MULTICAST_TTL, "IP_MULTICAST_TTL", 64, 64);
	test_ip_int_option_roundtrip(fd, IP_MULTICAST_TTL, "IP_MULTICAST_TTL", 255, 255);
	test_ip_int_option_roundtrip(fd, IP_MULTICAST_TTL, "IP_MULTICAST_TTL", 0, 0);

	/* Test invalid value > 255 */
	int invalid = 256;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &invalid, sizeof(invalid)),
		EINVAL,
		"IP_MULTICAST_TTL should reject value > 255");

	close(fd);
}

/*
 * IPv4 Header Options
 */

T_DECL(ip_options_inet_udp, "IP_OPTIONS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_OPTIONS sets IP header options for outgoing packets
	 * These are the actual IP header options bytes (RFC 791)
	 *
	 * Testing with a simple no-op option to verify the interface works
	 */

	/* Create a simple IP options structure with padding
	 * Option format: type (1 byte), length (1 byte), data
	 * Type 0x01 = NOP (No Operation), used for alignment
	 */
	unsigned char options[4] = {
		0x01, /* NOP */
		0x01, /* NOP */
		0x01, /* NOP */
		0x01  /* NOP */
	};

	/* Set the IP options */
	int ret = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, sizeof(options));
	if (ret == -1) {
		/* May fail with EINVAL or EPERM depending on security policy */
		T_LOG("IP_OPTIONS setsockopt failed (may be restricted): %d (%s)",
		    errno, strerror(errno));
	} else {
		T_LOG("IP_OPTIONS setsockopt succeeded");

		/* Try to retrieve the options */
		unsigned char get_options[40]; /* Max IP options size */
		socklen_t optlen = sizeof(get_options);
		ret = getsockopt(fd, IPPROTO_IP, IP_OPTIONS, get_options, &optlen);
		if (ret == 0) {
			T_LOG("IP_OPTIONS getsockopt succeeded, length=%u", optlen);
		} else {
			T_LOG("IP_OPTIONS getsockopt failed: %d (%s)", errno, strerror(errno));
		}
	}

	/* Clear the options by setting empty buffer */
	ret = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0);
	if (ret == -1) {
		T_LOG("IP_OPTIONS clear failed: %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("IP_OPTIONS cleared successfully");
	}

	close(fd);
}

T_DECL(ip_retopts_inet_udp, "IP_RETOPTS on AF_INET UDP (read-only)")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* IP_RETOPTS is typically read-only and returns the options from
	 * the last received packet. On a new unconnected socket, this
	 * should either fail or return empty.
	 */

	unsigned char options[40]; /* Max IP options size */
	socklen_t optlen = sizeof(options);

	int ret = getsockopt(fd, IPPROTO_IP, IP_RETOPTS, options, &optlen);
	if (ret == -1) {
		/* Expected on unconnected socket or if no packets received */
		T_LOG("IP_RETOPTS getsockopt failed (expected): %d (%s)",
		    errno, strerror(errno));
	} else {
		T_LOG("IP_RETOPTS getsockopt succeeded, length=%u", optlen);
		if (optlen == 0) {
			T_LOG("IP_RETOPTS is empty (no received options)");
		}
	}

	/* Verify setsockopt fails (read-only option) */
	unsigned char set_options[4] = { 0x01, 0x01, 0x01, 0x01 };
	ret = setsockopt(fd, IPPROTO_IP, IP_RETOPTS, set_options, sizeof(set_options));
	if (ret == -1) {
		T_LOG("IP_RETOPTS setsockopt failed as expected (read-only): %d (%s)",
		    errno, strerror(errno));
		T_EXPECT_TRUE(errno == ENOPROTOOPT || errno == EINVAL,
		    "errno should be ENOPROTOOPT or EINVAL for read-only option");
	} else {
		T_LOG("IP_RETOPTS setsockopt unexpectedly succeeded");
	}

	close(fd);
}
