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
 * sockopt_udp.c
 *
 * Tests for IPPROTO_UDP level socket options.
 * Tests UDP-specific options: UDP_NOCKSUM and UDP_KEEPALIVE_OFFLOAD.
 * Both are boolean options where any non-zero value means enabled.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/udp.h>
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
 * Helper to test boolean UDP option
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_udp_bool_option(int fd, int optname, const char *optname_str,
    int setval, bool expect_enabled)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_UDP, optname, &getval, &optlen),
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
 * Test UDP_NOCKSUM - Disable UDP checksums (boolean option)
 */
T_DECL(udp_nocksum_inet, "UDP_NOCKSUM on AF_INET")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Boolean: any non-zero enables, 0 disables */
	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 1, true);
	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 0, false);
	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 42, true); /* Any non-zero */

	close(fd);
}

T_DECL(udp_nocksum_inet6, "UDP_NOCKSUM on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 1, true);
	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 0, false);

	close(fd);
}

T_DECL(udp_nocksum_on_tcp, "UDP_NOCKSUM fails on TCP socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int optval = 1;
	int ret = setsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &optval, sizeof(optval));

	T_ASSERT_EQ(ret, -1, "UDP_NOCKSUM should fail on TCP socket");
	T_EXPECT_TRUE(errno == ENOPROTOOPT || errno == EINVAL,
	    "errno should be ENOPROTOOPT or EINVAL (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

/*
 * Test UDP_KEEPALIVE_OFFLOAD - Enable keepalive offload (private option)
 * This option takes a struct udp_keepalive_offload parameter
 * Note: This is a write-only option - getsockopt is not supported
 */
T_DECL(udp_keepalive_offload_inet, "UDP_KEEPALIVE_OFFLOAD on AF_INET")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* UDP_KEEPALIVE_OFFLOAD requires socket to be connected */
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9999),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	T_ASSERT_POSIX_SUCCESS(
		connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"connect to localhost:9999");

	/* Setup keepalive offload structure */
	struct udp_keepalive_offload ka_offload = {
		.ka_interval = 30,  /* 30 second interval */
		.ka_data_len = 4,   /* 4 bytes of data */
		.ka_type = UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY,
		.ka_data = {0x01, 0x02, 0x03, 0x04}
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		&ka_offload, sizeof(ka_offload)),
		"setsockopt UDP_KEEPALIVE_OFFLOAD");

	/* getsockopt is not supported for UDP_KEEPALIVE_OFFLOAD - verify it fails */
	struct udp_keepalive_offload get_ka = {0};
	socklen_t optlen = sizeof(get_ka);

	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		&get_ka, &optlen),
		ENOPROTOOPT,
		"getsockopt UDP_KEEPALIVE_OFFLOAD should fail (write-only option)");

	close(fd);
}

T_DECL(udp_keepalive_offload_inet6, "UDP_KEEPALIVE_OFFLOAD on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* UDP_KEEPALIVE_OFFLOAD requires socket to be connected */
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(9999),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT
	};

	T_ASSERT_POSIX_SUCCESS(
		connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"connect to [::1]:9999");

	/* Setup keepalive offload structure */
	struct udp_keepalive_offload ka_offload = {
		.ka_interval = 60,  /* 60 second interval */
		.ka_data_len = 8,   /* 8 bytes of data */
		.ka_type = UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY,
		.ka_data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		&ka_offload, sizeof(ka_offload)),
		"setsockopt UDP_KEEPALIVE_OFFLOAD");

	/* getsockopt is not supported for UDP_KEEPALIVE_OFFLOAD - verify it fails */
	struct udp_keepalive_offload get_ka = {0};
	socklen_t optlen = sizeof(get_ka);

	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		&get_ka, &optlen),
		ENOPROTOOPT,
		"getsockopt UDP_KEEPALIVE_OFFLOAD should fail (write-only option)");

	close(fd);
}

T_DECL(udp_keepalive_offload_unconnected, "UDP_KEEPALIVE_OFFLOAD fails on unconnected socket")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	struct udp_keepalive_offload ka_offload = {
		.ka_interval = 30,
		.ka_data_len = 4,
		.ka_type = UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY,
		.ka_data = {0x01, 0x02, 0x03, 0x04}
	};

	int ret = setsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
	    &ka_offload, sizeof(ka_offload));

	T_ASSERT_EQ(ret, -1, "UDP_KEEPALIVE_OFFLOAD should fail on unconnected socket");
	T_EXPECT_EQ(errno, EINVAL,
	    "errno should be EINVAL (got %d: %s)", errno, strerror(errno));

	close(fd);
}

T_DECL(udp_keepalive_offload_on_tcp, "UDP_KEEPALIVE_OFFLOAD fails on TCP socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct udp_keepalive_offload ka_offload = {
		.ka_interval = 30,
		.ka_data_len = 4,
		.ka_type = UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY,
		.ka_data = {0x01, 0x02, 0x03, 0x04}
	};

	int ret = setsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
	    &ka_offload, sizeof(ka_offload));

	T_ASSERT_EQ(ret, -1, "UDP_KEEPALIVE_OFFLOAD should fail on TCP socket");
	T_EXPECT_TRUE(errno == ENOPROTOOPT || errno == EINVAL,
	    "errno should be ENOPROTOOPT or EINVAL (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

/*
 * Test UDP options work on both bound and unbound sockets
 */
T_DECL(udp_nocksum_bound_socket, "UDP_NOCKSUM on bound socket")
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

	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 1, true);
	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 0, false);

	close(fd);
}

T_DECL(udp_nocksum_connected_socket, "UDP_NOCKSUM on connected socket")
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

	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 1, true);
	test_udp_bool_option(fd, UDP_NOCKSUM, "UDP_NOCKSUM", 0, false);

	close(fd);
}

/*
 * Test invalid option values
 */
T_DECL(udp_nocksum_invalid_optlen, "UDP_NOCKSUM with invalid optlen")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Too small */
	char smallval = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &smallval, sizeof(smallval)),
		EINVAL,
		"setsockopt UDP_NOCKSUM with too small optlen should fail");

	/* NULL pointer with non-zero length */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, NULL, sizeof(int)),
		EFAULT,
		"setsockopt UDP_NOCKSUM with NULL optval should fail");

	close(fd);
}

/*
 * Test UDP option persistence across connect
 */
T_DECL(udp_options_persist_across_connect, "UDP options persist across connect")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Set UDP_NOCKSUM before connecting */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &enable, sizeof(enable)),
		"setsockopt UDP_NOCKSUM before connect");

	/* Verify UDP_NOCKSUM is set before connect */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &getval, &optlen),
		"getsockopt UDP_NOCKSUM before connect");
	T_EXPECT_NE(getval, 0, "UDP_NOCKSUM enabled before connect (got %d)", getval);

	/* Connect the socket */
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9999),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	T_ASSERT_POSIX_SUCCESS(
		connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"connect to localhost:9999");

	/* Verify UDP_NOCKSUM still set after connect - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &getval, &optlen),
		"getsockopt UDP_NOCKSUM after connect");
	T_EXPECT_NE(getval, 0, "UDP_NOCKSUM still enabled after connect (got %d)", getval);

	close(fd);
}

/*
 * Test multiple UDP options on same socket
 */
T_DECL(udp_multiple_options, "Multiple UDP options on same socket")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Connect first for UDP_KEEPALIVE_OFFLOAD */
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9999),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	T_ASSERT_POSIX_SUCCESS(
		connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"connect to localhost:9999");

	/* Set UDP_NOCKSUM (boolean) */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &enable, sizeof(enable)),
		"setsockopt UDP_NOCKSUM");

	/* Set UDP_KEEPALIVE_OFFLOAD (structure) */
	struct udp_keepalive_offload ka_offload = {
		.ka_interval = 45,
		.ka_data_len = 6,
		.ka_type = UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY,
		.ka_data = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		&ka_offload, sizeof(ka_offload)),
		"setsockopt UDP_KEEPALIVE_OFFLOAD");

	/* Verify UDP_NOCKSUM (boolean - check for non-zero) */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &getval, &optlen),
		"getsockopt UDP_NOCKSUM");
	T_EXPECT_NE(getval, 0, "UDP_NOCKSUM still enabled (got %d)", getval);

	/* UDP_KEEPALIVE_OFFLOAD is write-only - verify getsockopt fails */
	struct udp_keepalive_offload get_ka = {0};
	optlen = sizeof(get_ka);

	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		&get_ka, &optlen),
		ENOPROTOOPT,
		"getsockopt UDP_KEEPALIVE_OFFLOAD should fail (write-only option)");

	close(fd);
}

/*
 * Test that UDP options don't interfere with SOL_SOCKET options
 */
T_DECL(udp_with_sol_socket_options, "UDP options work with SOL_SOCKET options")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Set some SOL_SOCKET options */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)),
		"setsockopt SO_REUSEADDR");

	int bufsize = 65536;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)),
		"setsockopt SO_RCVBUF");

	/* Set UDP option */
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &enable, sizeof(enable)),
		"setsockopt UDP_NOCKSUM");

	/* Verify all options - use correct checks for boolean vs integer */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	/* SO_REUSEADDR is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &getval, &optlen),
		"getsockopt SO_REUSEADDR");
	T_EXPECT_NE(getval, 0, "SO_REUSEADDR still enabled (got %d)", getval);

	/* SO_RCVBUF is integer - kernel may adjust, check >= */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &getval, &optlen),
		"getsockopt SO_RCVBUF");
	T_EXPECT_GE(getval, bufsize, "SO_RCVBUF >= requested size (got %d)", getval);

	/* UDP_NOCKSUM is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_UDP, UDP_NOCKSUM, &getval, &optlen),
		"getsockopt UDP_NOCKSUM");
	T_EXPECT_NE(getval, 0, "UDP_NOCKSUM still enabled (got %d)", getval);

	close(fd);
}
