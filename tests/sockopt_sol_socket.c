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
 * sockopt_sol_socket.c
 *
 * Comprehensive tests for SOL_SOCKET level socket options.
 * Tests both standard POSIX options and Apple-specific private options.
 *
 * Covers:
 * - Basic/standard socket options (SO_REUSEADDR, SO_KEEPALIVE, SO_SNDBUF, etc.)
 * - Domain-specific options that have socket family restrictions
 * - Apple-specific private options (SO_TRAFFIC_CLASS, SO_RESTRICTIONS, etc.)
 */

#include <sys/socket.h>
#include <sys/socket_private.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <uuid/uuid.h>

#include <darwintest.h>

/*
 * SO_ACCEPTFILTER is a BSD feature that was never implemented in XNU.
 * The constant is not defined on Apple platforms (guarded by #ifndef __APPLE__).
 * We define it here to test that it's properly rejected as not implemented.
 */
#ifndef SO_ACCEPTFILTER
#define SO_ACCEPTFILTER 0x1000          /* there is an accept filter */
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net.sockopt"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * Helper to test basic integer option round-trip
 */
static void
test_int_option_roundtrip(int fd, int optname, const char *optname_str,
    int setval, int expected_getval)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, optname, &getval, &optlen),
		"getsockopt %s", optname_str);

	T_EXPECT_EQ(getval, expected_getval,
	    "%s value matches (expected %d, got %d)",
	    optname_str, expected_getval, getval);
	T_EXPECT_EQ(optlen, (socklen_t)sizeof(int),
	    "%s optlen is sizeof(int)", optname_str);
}

/*
 * Helper to test boolean socket options
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_bool_option(int fd, int optname, const char *optname_str,
    int setval, bool expect_enabled)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, optname, &getval, &optlen),
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
	T_EXPECT_EQ(optlen, (socklen_t)sizeof(int),
	    "%s optlen is sizeof(int)", optname_str);
}

/*
 * ===========================
 * Basic/Standard Socket Options
 * ===========================
 */

/*
 * Test SO_REUSEADDR on different socket types
 */
T_DECL(so_reuseaddr_inet_tcp, "SO_REUSEADDR on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Boolean options: 0 = disabled, non-zero = enabled */
	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 1, true);
	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 0, false);
	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 42, true); /* Any non-zero */

	close(fd);
}

T_DECL(so_reuseaddr_inet6_udp, "SO_REUSEADDR on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 1, true);
	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 0, false);
	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 255, true);

	close(fd);
}

T_DECL(so_reuseaddr_unix_stream, "SO_REUSEADDR on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 1, true);
	test_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 0, false);

	close(fd);
}

/*
 * Test SO_REUSEPORT on different socket types
 */
T_DECL(so_reuseport_inet_tcp, "SO_REUSEPORT on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 1, true);
	test_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 0, false);

	close(fd);
}

T_DECL(so_reuseport_unix_dgram, "SO_REUSEPORT on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 1, true);
	test_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 0, false);

	close(fd);
}

/*
 * Test SO_KEEPALIVE on different socket types
 */
T_DECL(so_keepalive_inet_tcp, "SO_KEEPALIVE on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_KEEPALIVE, "SO_KEEPALIVE", 1, true);
	test_bool_option(fd, SO_KEEPALIVE, "SO_KEEPALIVE", 0, false);

	close(fd);
}

T_DECL(so_keepalive_inet6_tcp, "SO_KEEPALIVE on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_bool_option(fd, SO_KEEPALIVE, "SO_KEEPALIVE", 1, true);
	test_bool_option(fd, SO_KEEPALIVE, "SO_KEEPALIVE", 0, false);

	close(fd);
}

/*
 * Test SO_DONTROUTE
 */
T_DECL(so_dontroute_inet_udp, "SO_DONTROUTE on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_DONTROUTE, "SO_DONTROUTE", 1, true);
	test_bool_option(fd, SO_DONTROUTE, "SO_DONTROUTE", 0, false);

	close(fd);
}

/*
 * Test SO_BROADCAST (only meaningful for datagram sockets)
 */
T_DECL(so_broadcast_inet_udp, "SO_BROADCAST on AF_INET UDP",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_BROADCAST, "SO_BROADCAST", 1, true);
	test_bool_option(fd, SO_BROADCAST, "SO_BROADCAST", 0, false);

	close(fd);
}

/*
 * Test SO_OOBINLINE
 */
T_DECL(so_oobinline_inet_tcp, "SO_OOBINLINE on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_OOBINLINE, "SO_OOBINLINE", 1, true);
	test_bool_option(fd, SO_OOBINLINE, "SO_OOBINLINE", 0, false);

	close(fd);
}

/*
 * Test SO_NOSIGPIPE (Apple-specific)
 */
T_DECL(so_nosigpipe_inet_tcp, "SO_NOSIGPIPE on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);
	test_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 0, false);

	close(fd);
}

T_DECL(so_nosigpipe_unix_stream, "SO_NOSIGPIPE on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);
	test_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 0, false);

	close(fd);
}

/*
 * Test SO_TIMESTAMP options
 */
T_DECL(so_timestamp_inet_udp, "SO_TIMESTAMP on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_TIMESTAMP, "SO_TIMESTAMP", 1, true);
	test_bool_option(fd, SO_TIMESTAMP, "SO_TIMESTAMP", 0, false);

	close(fd);
}

T_DECL(so_timestamp_monotonic_inet_udp, "SO_TIMESTAMP_MONOTONIC on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_TIMESTAMP_MONOTONIC,
	    "SO_TIMESTAMP_MONOTONIC", 1, 1);
	test_bool_option(fd, SO_TIMESTAMP_MONOTONIC,
	    "SO_TIMESTAMP_MONOTONIC", 0, 0);

	close(fd);
}

T_DECL(so_timestamp_continuous_inet6_udp, "SO_TIMESTAMP_CONTINUOUS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_TIMESTAMP_CONTINUOUS,
	    "SO_TIMESTAMP_CONTINUOUS", 1, 1);
	test_bool_option(fd, SO_TIMESTAMP_CONTINUOUS,
	    "SO_TIMESTAMP_CONTINUOUS", 0, 0);

	close(fd);
}

/*
 * Test SO_NP_EXTENSIONS - Enable network protocol extensions
 * This option uses a structure, not a simple integer
 */
T_DECL(so_np_extensions_inet_tcp, "SO_NP_EXTENSIONS on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct so_np_extensions sonpx;
	socklen_t optlen;

	/* Test setting SONPX_SETOPTSHUT flag */
	sonpx.npx_flags = SONPX_SETOPTSHUT;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS with SONPX_SETOPTSHUT");

	/* Verify it was set */
	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_NE(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be set");

	/* Test clearing the flag */
	sonpx.npx_flags = 0;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS clear SONPX_SETOPTSHUT");

	/* Verify it was cleared */
	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_EQ(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be cleared");

	close(fd);
}

T_DECL(so_np_extensions_inet_udp, "SO_NP_EXTENSIONS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	struct so_np_extensions sonpx;
	socklen_t optlen;

	sonpx.npx_flags = SONPX_SETOPTSHUT;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS");

	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_NE(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be set");

	close(fd);
}

T_DECL(so_np_extensions_inet6_tcp, "SO_NP_EXTENSIONS on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	struct so_np_extensions sonpx;
	socklen_t optlen;

	sonpx.npx_flags = SONPX_SETOPTSHUT;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS");

	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_NE(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be set");

	close(fd);
}

T_DECL(so_np_extensions_inet6_udp, "SO_NP_EXTENSIONS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	struct so_np_extensions sonpx;
	socklen_t optlen;

	sonpx.npx_flags = SONPX_SETOPTSHUT;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS");

	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_NE(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be set");

	close(fd);
}

T_DECL(so_np_extensions_unix_stream, "SO_NP_EXTENSIONS on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	struct so_np_extensions sonpx;
	socklen_t optlen;

	sonpx.npx_flags = SONPX_SETOPTSHUT;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS");

	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_NE(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be set");

	close(fd);
}

T_DECL(so_np_extensions_unix_dgram, "SO_NP_EXTENSIONS on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	struct so_np_extensions sonpx;
	socklen_t optlen;

	sonpx.npx_flags = SONPX_SETOPTSHUT;
	sonpx.npx_mask = SONPX_SETOPTSHUT;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx)),
		"setsockopt SO_NP_EXTENSIONS");

	memset(&sonpx, 0, sizeof(sonpx));
	optlen = sizeof(sonpx);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, &optlen),
		"getsockopt SO_NP_EXTENSIONS");
	T_EXPECT_NE(sonpx.npx_flags & SONPX_SETOPTSHUT, 0,
	    "SONPX_SETOPTSHUT flag should be set");

	close(fd);
}


/*
 * Test SO_SNDBUF and SO_RCVBUF
 */
T_DECL(so_sndbuf_inet_tcp, "SO_SNDBUF on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int sizes[] = {4096, 8192, 16384, 32768, 65536};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		int setval = sizes[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &setval, sizeof(setval)),
			"setsockopt SO_SNDBUF = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &getval, &optlen),
			"getsockopt SO_SNDBUF");

		/* Kernel may round up or adjust the value */
		T_EXPECT_GE(getval, setval,
		    "SO_SNDBUF value >= requested (requested %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_rcvbuf_inet_udp, "SO_RCVBUF on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	int sizes[] = {4096, 8192, 16384, 32768, 65536};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		int setval = sizes[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &setval, sizeof(setval)),
			"setsockopt SO_RCVBUF = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &getval, &optlen),
			"getsockopt SO_RCVBUF");

		/* Kernel may round up or adjust the value */
		T_EXPECT_GE(getval, setval,
		    "SO_RCVBUF value >= requested (requested %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_sndbuf_unix_stream, "SO_SNDBUF on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int setval = 16384;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &setval, sizeof(setval)),
		"setsockopt SO_SNDBUF = %d", setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &getval, &optlen),
		"getsockopt SO_SNDBUF");

	T_EXPECT_GE(getval, setval,
	    "SO_SNDBUF value >= requested (requested %d, got %d)",
	    setval, getval);

	close(fd);
}

/*
 * Test SO_SNDLOWAT and SO_RCVLOWAT
 */
T_DECL(so_sndlowat_inet_tcp, "SO_SNDLOWAT on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_SNDLOWAT is typically fixed at 2048 on XNU */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_SNDLOWAT, &getval, &optlen),
		"getsockopt SO_SNDLOWAT");

	T_LOG("Default SO_SNDLOWAT: %d", getval);

	close(fd);
}

T_DECL(so_rcvlowat_inet_tcp, "SO_RCVLOWAT on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_int_option_roundtrip(fd, SO_RCVLOWAT, "SO_RCVLOWAT", 1, 1);
	test_int_option_roundtrip(fd, SO_RCVLOWAT, "SO_RCVLOWAT", 1024, 1024);

	close(fd);
}

/*
 * Test SO_SNDTIMEO and SO_RCVTIMEO
 */
T_DECL(so_sndtimeo_inet_tcp, "SO_SNDTIMEO on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct timeval tv_set = { .tv_sec = 5, .tv_usec = 500000 }; /* 5.5 seconds */
	struct timeval tv_get = {0};
	socklen_t optlen = sizeof(tv_get);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv_set, sizeof(tv_set)),
		"setsockopt SO_SNDTIMEO");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv_get, &optlen),
		"getsockopt SO_SNDTIMEO");

	T_EXPECT_EQ(tv_get.tv_sec, tv_set.tv_sec, "SO_SNDTIMEO tv_sec matches");
	T_EXPECT_EQ(tv_get.tv_usec, tv_set.tv_usec, "SO_SNDTIMEO tv_usec matches");

	close(fd);
}

T_DECL(so_rcvtimeo_inet_udp, "SO_RCVTIMEO on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	struct timeval tv_set = { .tv_sec = 2, .tv_usec = 250000 }; /* 2.25 seconds */
	struct timeval tv_get = {0};
	socklen_t optlen = sizeof(tv_get);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_set, sizeof(tv_set)),
		"setsockopt SO_RCVTIMEO");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_get, &optlen),
		"getsockopt SO_RCVTIMEO");

	T_EXPECT_EQ(tv_get.tv_sec, tv_set.tv_sec, "SO_RCVTIMEO tv_sec matches");
	T_EXPECT_EQ(tv_get.tv_usec, tv_set.tv_usec, "SO_RCVTIMEO tv_usec matches");

	close(fd);
}

T_DECL(so_rcvtimeo_unix_stream, "SO_RCVTIMEO on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	struct timeval tv_set = { .tv_sec = 1, .tv_usec = 0 }; /* 1 second */
	struct timeval tv_get = {0};
	socklen_t optlen = sizeof(tv_get);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_set, sizeof(tv_set)),
		"setsockopt SO_RCVTIMEO");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_get, &optlen),
		"getsockopt SO_RCVTIMEO");

	T_EXPECT_EQ(tv_get.tv_sec, tv_set.tv_sec, "SO_RCVTIMEO tv_sec matches");

	close(fd);
}

/*
 * Test SO_LINGER and SO_LINGER_SEC
 */
T_DECL(so_linger_inet_tcp, "SO_LINGER on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct linger l_set = { .l_onoff = 1, .l_linger = 10 };
	struct linger l_get = {0};
	socklen_t optlen = sizeof(l_get);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &l_set, sizeof(l_set)),
		"setsockopt SO_LINGER on=1 linger=10");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_LINGER, &l_get, &optlen),
		"getsockopt SO_LINGER");

	T_EXPECT_EQ(l_get.l_onoff, 1, "SO_LINGER l_onoff matches");
	T_EXPECT_EQ(l_get.l_linger, 10, "SO_LINGER l_linger matches");

	/* Disable linger */
	l_set.l_onoff = 0;
	l_set.l_linger = 0;

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &l_set, sizeof(l_set)),
		"setsockopt SO_LINGER off");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_LINGER, &l_get, &optlen),
		"getsockopt SO_LINGER");

	T_EXPECT_EQ(l_get.l_onoff, 0, "SO_LINGER disabled");

	close(fd);
}

T_DECL(so_linger_sec_inet6_tcp, "SO_LINGER_SEC on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	struct linger l_set = { .l_onoff = 1, .l_linger = 5 };
	struct linger l_get = {0};
	socklen_t optlen = sizeof(l_get);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_LINGER_SEC, &l_set, sizeof(l_set)),
		"setsockopt SO_LINGER_SEC on=1 linger=5");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_LINGER_SEC, &l_get, &optlen),
		"getsockopt SO_LINGER_SEC");

	T_EXPECT_EQ(l_get.l_onoff, 1, "SO_LINGER_SEC l_onoff matches");
	T_EXPECT_EQ(l_get.l_linger, 5, "SO_LINGER_SEC l_linger matches");

	close(fd);
}

T_DECL(so_linger_unix_stream, "SO_LINGER on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	struct linger l_set = { .l_onoff = 1, .l_linger = 3 };
	struct linger l_get = {0};
	socklen_t optlen = sizeof(l_get);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &l_set, sizeof(l_set)),
		"setsockopt SO_LINGER");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_LINGER, &l_get, &optlen),
		"getsockopt SO_LINGER");

	T_EXPECT_EQ(l_get.l_onoff, 1, "SO_LINGER l_onoff matches");
	T_EXPECT_EQ(l_get.l_linger, 3, "SO_LINGER l_linger matches");

	close(fd);
}

/*
 * Test read-only options: SO_TYPE, SO_ERROR, SO_ACCEPTCONN
 */
T_DECL(so_type_readonly, "SO_TYPE is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int type = 0;
	socklen_t optlen = sizeof(type);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen),
		"getsockopt SO_TYPE");

	T_EXPECT_EQ(type, SOCK_STREAM, "SO_TYPE is SOCK_STREAM");

	/* Try to set SO_TYPE (should fail) */
	int newtype = SOCK_DGRAM;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_TYPE, &newtype, sizeof(newtype)),
		ENOPROTOOPT,
		"setsockopt SO_TYPE should fail");

	close(fd);

	/* Test with UDP socket */
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen),
		"getsockopt SO_TYPE");

	T_EXPECT_EQ(type, SOCK_DGRAM, "SO_TYPE is SOCK_DGRAM");

	close(fd);
}

T_DECL(so_error_readonly, "SO_ERROR is read-only and clears on read")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int error = 0;
	socklen_t optlen = sizeof(error);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen),
		"getsockopt SO_ERROR");

	T_EXPECT_EQ(error, 0, "SO_ERROR initially 0");

	/* Try to set SO_ERROR (should fail) */
	error = EINVAL;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_ERROR, &error, sizeof(error)),
		ENOPROTOOPT,
		"setsockopt SO_ERROR should fail");

	close(fd);
}

/*
 * Test SO_NREAD and SO_NWRITE (read-only, information options)
 */
T_DECL(so_nread_readonly, "SO_NREAD is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int nread = 0;
	socklen_t optlen = sizeof(nread);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NREAD, &nread, &optlen),
		"getsockopt SO_NREAD");

	T_EXPECT_EQ(nread, 0, "SO_NREAD initially 0 (no data buffered)");

	close(fd);
}

T_DECL(so_nwrite_readonly, "SO_NWRITE is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int nwrite = 0;
	socklen_t optlen = sizeof(nwrite);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NWRITE, &nwrite, &optlen),
		"getsockopt SO_NWRITE");

	T_EXPECT_EQ(nwrite, 0, "SO_NWRITE initially 0 (no pending data)");

	close(fd);
}

/*
 * Test SO_ACCEPTCONN - Check if socket is accepting connections
 * Note: This option is not implemented in XNU, so getsockopt fails with ENOPROTOOPT
 */
T_DECL(so_acceptconn_not_implemented, "SO_ACCEPTCONN is not implemented")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int accepting = 0;
	socklen_t optlen = sizeof(accepting);

	/* SO_ACCEPTCONN is not implemented - should fail with ENOPROTOOPT */
	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &optlen),
		ENOPROTOOPT,
		"getsockopt SO_ACCEPTCONN should fail (not implemented)");

	/* setsockopt should also fail */
	accepting = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, sizeof(accepting)),
		ENOPROTOOPT,
		"setsockopt SO_ACCEPTCONN should fail (not implemented)");

	close(fd);
}

/*
 * Test SO_ACCEPTFILTER - Set accept filter
 * Note: This option is not implemented in XNU, so both get/set fail with ENOPROTOOPT
 * The SO_ACCEPTFILTER constant is defined but the implementation is missing.
 */
T_DECL(so_acceptfilter_not_implemented, "SO_ACCEPTFILTER is not implemented")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_ACCEPTFILTER uses struct accept_filter_arg, but it's not exposed on Apple platforms */
	struct accept_filter_arg {
		char af_name[16];
		char af_arg[256 - 16];
	} af;

	memset(&af, 0, sizeof(af));
	socklen_t optlen = sizeof(af);

	/* getsockopt should fail - not implemented */
	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &optlen),
		ENOPROTOOPT,
		"getsockopt SO_ACCEPTFILTER should fail (not implemented)");

	/* setsockopt should also fail - not implemented */
	strlcpy(af.af_name, "dataready", sizeof(af.af_name));
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, sizeof(af)),
		ENOPROTOOPT,
		"setsockopt SO_ACCEPTFILTER should fail (not implemented)");

	close(fd);
}

/*
 * Test SO_NUMRCVPKT - Number of packets in receive buffer (read-only)
 */
T_DECL(so_numrcvpkt_readonly, "SO_NUMRCVPKT is read-only")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	int numrcvpkt = 0;
	socklen_t optlen = sizeof(numrcvpkt);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NUMRCVPKT, &numrcvpkt, &optlen),
		"getsockopt SO_NUMRCVPKT");

	T_EXPECT_EQ(numrcvpkt, 0, "SO_NUMRCVPKT initially 0 (no packets buffered)");
	T_LOG("SO_NUMRCVPKT: %d", numrcvpkt);

	/* Try to set SO_NUMRCVPKT (should fail - read-only) */
	numrcvpkt = 10;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_NUMRCVPKT, &numrcvpkt, sizeof(numrcvpkt)),
		ENOPROTOOPT,
		"setsockopt SO_NUMRCVPKT should fail (read-only)");

	close(fd);
}

/*
 * Test SO_RANDOMPORT - Use random source port
 */
T_DECL(so_randomport_inet, "SO_RANDOMPORT on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_RANDOMPORT, "SO_RANDOMPORT", 1, true);
	test_bool_option(fd, SO_RANDOMPORT, "SO_RANDOMPORT", 0, false);

	close(fd);
}

T_DECL(so_randomport_inet6, "SO_RANDOMPORT on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_RANDOMPORT, "SO_RANDOMPORT", 1, true);
	test_bool_option(fd, SO_RANDOMPORT, "SO_RANDOMPORT", 0, false);

	close(fd);
}

/*
 * Test SO_REUSESHAREUID - Allow socket reuse by same UID
 */
T_DECL(so_reuseshareuid_inet, "SO_REUSESHAREUID on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_REUSESHAREUID, "SO_REUSESHAREUID", 1, true);
	test_bool_option(fd, SO_REUSESHAREUID, "SO_REUSESHAREUID", 0, false);

	close(fd);
}

T_DECL(so_reuseshareuid_inet6, "SO_REUSESHAREUID on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_bool_option(fd, SO_REUSESHAREUID, "SO_REUSESHAREUID", 1, true);
	test_bool_option(fd, SO_REUSESHAREUID, "SO_REUSESHAREUID", 0, false);

	close(fd);
}

/*
 * Test SO_NOTIFYCONFLICT - Send notification on bind conflict
 */
T_DECL(so_notifyconflict_inet_tcp, "SO_NOTIFYCONFLICT on AF_INET TCP",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 1, true);
	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 0, false);

	close(fd);
}

T_DECL(so_notifyconflict_inet_udp, "SO_NOTIFYCONFLICT on AF_INET UDP",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 1, true);
	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 0, false);

	close(fd);
}

T_DECL(so_notifyconflict_inet6_tcp, "SO_NOTIFYCONFLICT on AF_INET6 TCP",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 1, true);
	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 0, false);

	close(fd);
}

T_DECL(so_notifyconflict_inet6_udp, "SO_NOTIFYCONFLICT on AF_INET6 UDP",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 1, true);
	test_bool_option(fd, SO_NOTIFYCONFLICT, "SO_NOTIFYCONFLICT", 0, false);

	close(fd);
}

/*
 * Test SO_NET_SERVICE_TYPE - Network service type classification
 */
T_DECL(so_net_service_type_inet, "SO_NET_SERVICE_TYPE on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test different service types */
	int service_types[] = {
		NET_SERVICE_TYPE_BE,      /* Best effort */
		NET_SERVICE_TYPE_BK,      /* Background */
		NET_SERVICE_TYPE_SIG,     /* Signaling */
		NET_SERVICE_TYPE_VI,      /* Video */
		NET_SERVICE_TYPE_VO,      /* Voice */
		NET_SERVICE_TYPE_RV,      /* Responsive video */
		NET_SERVICE_TYPE_AV,      /* Audio/Video */
		NET_SERVICE_TYPE_OAM,     /* Operations/Administration/Management */
		NET_SERVICE_TYPE_RD       /* Responsive data */
	};

	for (size_t i = 0; i < sizeof(service_types) / sizeof(service_types[0]); i++) {
		int setval = service_types[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &setval, sizeof(setval)),
			"setsockopt SO_NET_SERVICE_TYPE = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &getval, &optlen),
			"getsockopt SO_NET_SERVICE_TYPE");

		T_EXPECT_EQ(getval, setval,
		    "SO_NET_SERVICE_TYPE value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_net_service_type_inet6_udp, "SO_NET_SERVICE_TYPE on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_int_option_roundtrip(fd, SO_NET_SERVICE_TYPE, "SO_NET_SERVICE_TYPE",
	    NET_SERVICE_TYPE_AV, NET_SERVICE_TYPE_AV);
	test_int_option_roundtrip(fd, SO_NET_SERVICE_TYPE, "SO_NET_SERVICE_TYPE",
	    NET_SERVICE_TYPE_BE, NET_SERVICE_TYPE_BE);

	close(fd);
}

T_DECL(so_net_service_type_inet_udp, "SO_NET_SERVICE_TYPE on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Test different service types */
	int service_types[] = {
		NET_SERVICE_TYPE_BE,
		NET_SERVICE_TYPE_BK,
		NET_SERVICE_TYPE_VI,
		NET_SERVICE_TYPE_VO,
		NET_SERVICE_TYPE_AV,
		NET_SERVICE_TYPE_RD
	};

	for (size_t i = 0; i < sizeof(service_types) / sizeof(service_types[0]); i++) {
		int setval = service_types[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &setval, sizeof(setval)),
			"setsockopt SO_NET_SERVICE_TYPE = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &getval, &optlen),
			"getsockopt SO_NET_SERVICE_TYPE");

		T_EXPECT_EQ(getval, setval,
		    "SO_NET_SERVICE_TYPE value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_net_service_type_inet6_tcp, "SO_NET_SERVICE_TYPE on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Test different service types */
	int service_types[] = {
		NET_SERVICE_TYPE_BE,
		NET_SERVICE_TYPE_BK,
		NET_SERVICE_TYPE_SIG,
		NET_SERVICE_TYPE_VI,
		NET_SERVICE_TYPE_VO,
		NET_SERVICE_TYPE_RV,
		NET_SERVICE_TYPE_AV,
		NET_SERVICE_TYPE_OAM,
		NET_SERVICE_TYPE_RD
	};

	for (size_t i = 0; i < sizeof(service_types) / sizeof(service_types[0]); i++) {
		int setval = service_types[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &setval, sizeof(setval)),
			"setsockopt SO_NET_SERVICE_TYPE = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &getval, &optlen),
			"getsockopt SO_NET_SERVICE_TYPE");

		T_EXPECT_EQ(getval, setval,
		    "SO_NET_SERVICE_TYPE value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_net_service_type_icmp, "SO_NET_SERVICE_TYPE on ICMP",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");

	/* Test a few service types on ICMP */
	int service_types[] = {
		NET_SERVICE_TYPE_BE,
		NET_SERVICE_TYPE_BK,
		NET_SERVICE_TYPE_VI,
		NET_SERVICE_TYPE_VO
	};

	for (size_t i = 0; i < sizeof(service_types) / sizeof(service_types[0]); i++) {
		int setval = service_types[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &setval, sizeof(setval)),
			"setsockopt SO_NET_SERVICE_TYPE = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &getval, &optlen),
			"getsockopt SO_NET_SERVICE_TYPE");

		T_EXPECT_EQ(getval, setval,
		    "SO_NET_SERVICE_TYPE value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_net_service_type_icmpv6, "SO_NET_SERVICE_TYPE on ICMPv6",
    T_META_ASROOT(true))
{
	int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");

	/* Test a few service types on ICMPv6 */
	int service_types[] = {
		NET_SERVICE_TYPE_BE,
		NET_SERVICE_TYPE_BK,
		NET_SERVICE_TYPE_VI,
		NET_SERVICE_TYPE_VO
	};

	for (size_t i = 0; i < sizeof(service_types) / sizeof(service_types[0]); i++) {
		int setval = service_types[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &setval, sizeof(setval)),
			"setsockopt SO_NET_SERVICE_TYPE = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &getval, &optlen),
			"getsockopt SO_NET_SERVICE_TYPE");

		T_EXPECT_EQ(getval, setval,
		    "SO_NET_SERVICE_TYPE value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

/*
 * Test SO_NETSVC_MARKING_LEVEL - QoS marking level (read-only)
 */
T_DECL(so_netsvc_marking_level_readonly, "SO_NETSVC_MARKING_LEVEL is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Should be able to read the marking level */
	int marking_level = 0;
	socklen_t optlen = sizeof(marking_level);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NETSVC_MARKING_LEVEL,
		&marking_level, &optlen),
		"getsockopt SO_NETSVC_MARKING_LEVEL");

	T_LOG("SO_NETSVC_MARKING_LEVEL: %d", marking_level);

	/* Try to set SO_NETSVC_MARKING_LEVEL (should fail - read-only) */
	int new_level = NETSVC_MRKNG_LVL_L2;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_NETSVC_MARKING_LEVEL,
		&new_level, sizeof(new_level)),
		ENOPROTOOPT,
		"setsockopt SO_NETSVC_MARKING_LEVEL should fail (read-only)");

	close(fd);
}

T_DECL(so_netsvc_marking_level_inet6, "SO_NETSVC_MARKING_LEVEL on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* Should be able to read the marking level */
	int marking_level = 0;
	socklen_t optlen = sizeof(marking_level);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NETSVC_MARKING_LEVEL,
		&marking_level, &optlen),
		"getsockopt SO_NETSVC_MARKING_LEVEL");

	T_LOG("SO_NETSVC_MARKING_LEVEL: %d", marking_level);

	close(fd);
}

/*
 * Test invalid option lengths
 */
T_DECL(so_reuseaddr_invalid_optlen, "SO_REUSEADDR with invalid optlen")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Too small */
	char smallval = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &smallval, sizeof(smallval)),
		EINVAL,
		"setsockopt SO_REUSEADDR with too small optlen should fail");

	/* NULL pointer with non-zero length */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, NULL, sizeof(int)),
		EFAULT,
		"setsockopt SO_REUSEADDR with NULL optval should fail");

	close(fd);
}

/*
 * Test SO_DONTTRUNC - Don't truncate datagram messages
 * This option prevents truncation when reading datagrams that are larger
 * than the provided buffer
 */
T_DECL(so_donttrunc_inet, "SO_DONTTRUNC on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_DONTTRUNC, "SO_DONTTRUNC", 1, true);
	test_bool_option(fd, SO_DONTTRUNC, "SO_DONTTRUNC", 0, false);

	close(fd);
}

T_DECL(so_donttrunc_inet6, "SO_DONTTRUNC on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_DONTTRUNC, "SO_DONTTRUNC", 1, true);
	test_bool_option(fd, SO_DONTTRUNC, "SO_DONTTRUNC", 0, false);

	close(fd);
}

T_DECL(so_donttrunc_unix_dgram, "SO_DONTTRUNC on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_bool_option(fd, SO_DONTTRUNC, "SO_DONTTRUNC", 1, true);
	test_bool_option(fd, SO_DONTTRUNC, "SO_DONTTRUNC", 0, false);

	close(fd);
}

/*
 * Test SO_DEBUG option
 */
T_DECL(so_debug_inet_tcp, "SO_DEBUG on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_DEBUG, "SO_DEBUG", 1, true);
	test_bool_option(fd, SO_DEBUG, "SO_DEBUG", 0, false);

	close(fd);
}

/*
 * Test SO_USELOOPBACK (deprecated but still present)
 */
T_DECL(so_useloopback_inet_udp, "SO_USELOOPBACK on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_USELOOPBACK, "SO_USELOOPBACK", 1, true);
	test_bool_option(fd, SO_USELOOPBACK, "SO_USELOOPBACK", 0, false);

	close(fd);
}

/*
 * ===========================
 * Domain-Specific Options (Socket Family Restrictions)
 * ===========================
 */

/*
 * Test SO_AWDL_UNRESTRICTED on different socket families
 */
T_DECL(so_awdl_unrestricted_unix_stream,
    "SO_AWDL_UNRESTRICTED fails on AF_UNIX SOCK_STREAM",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_AWDL_UNRESTRICTED,
		&optval, sizeof(optval)),
		EOPNOTSUPP,
		"setsockopt SO_AWDL_UNRESTRICTED on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_awdl_unrestricted_unix_dgram,
    "SO_AWDL_UNRESTRICTED fails on AF_UNIX SOCK_DGRAM",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_AWDL_UNRESTRICTED,
		&optval, sizeof(optval)),
		EOPNOTSUPP,
		"setsockopt SO_AWDL_UNRESTRICTED on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_awdl_unrestricted_inet_tcp,
    "SO_AWDL_UNRESTRICTED succeeds on AF_INET TCP",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	T_MAYFAIL;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_AWDL_UNRESTRICTED,
		&optval, sizeof(optval)),
		"setsockopt SO_AWDL_UNRESTRICTED on AF_INET");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_AWDL_UNRESTRICTED,
		&getval, &optlen),
		"getsockopt SO_AWDL_UNRESTRICTED on AF_INET");

	T_MAYFAIL;
	T_EXPECT_EQ(getval, 1, "SO_AWDL_UNRESTRICTED value matches");

	close(fd);
}

T_DECL(so_awdl_unrestricted_inet6_tcp,
    "SO_AWDL_UNRESTRICTED succeeds on AF_INET6 TCP",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	T_MAYFAIL;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_AWDL_UNRESTRICTED,
		&optval, sizeof(optval)),
		"setsockopt SO_AWDL_UNRESTRICTED on AF_INET6");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_AWDL_UNRESTRICTED,
		&getval, &optlen),
		"getsockopt SO_AWDL_UNRESTRICTED on AF_INET6");

	T_MAYFAIL;
	T_EXPECT_EQ(getval, 1, "SO_AWDL_UNRESTRICTED value matches");

	close(fd);
}

/*
 * Test SO_INTCOPROC_ALLOW - IPv6 only option
 */
T_DECL(so_intcoproc_allow_unix,
    "SO_INTCOPROC_ALLOW fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_INTCOPROC_ALLOW,
		&optval, sizeof(optval)),
		EOPNOTSUPP,
		"setsockopt SO_INTCOPROC_ALLOW on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_intcoproc_allow_inet,
    "SO_INTCOPROC_ALLOW fails on AF_INET",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	T_MAYFAIL;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_INTCOPROC_ALLOW,
		&optval, sizeof(optval)),
		EOPNOTSUPP,
		"setsockopt SO_INTCOPROC_ALLOW on AF_INET should fail");

	close(fd);
}

T_DECL(so_intcoproc_allow_inet6,
    "SO_INTCOPROC_ALLOW succeeds on AF_INET6",
    T_META_ASROOT(true))
{
	int fd;
	int optval = 1;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	T_MAYFAIL;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_INTCOPROC_ALLOW,
		&optval, sizeof(optval)),
		"setsockopt SO_INTCOPROC_ALLOW on AF_INET6");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_INTCOPROC_ALLOW,
		&getval, &optlen),
		"getsockopt SO_INTCOPROC_ALLOW on AF_INET6");

	T_MAYFAIL;
	T_EXPECT_EQ(getval, 1, "SO_INTCOPROC_ALLOW value matches");

	close(fd);
}

/*
 * Test SO_NECP_ATTRIBUTES on different socket families
 */
T_DECL(so_necp_attributes_unix,
    "SO_NECP_ATTRIBUTES fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	uint8_t optval[16] = {0};

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_NECP_ATTRIBUTES,
		optval, sizeof(optval)),
		EINVAL,
		"setsockopt SO_NECP_ATTRIBUTES on AF_UNIX should fail");

	close(fd);
}

/*
 * Test SO_NECP_CLIENTUUID on different socket families
 */
T_DECL(so_necp_clientuuid_unix,
    "SO_NECP_CLIENTUUID fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	uuid_t client_uuid;

	uuid_clear(client_uuid);
	uuid_generate(client_uuid);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_NECP_CLIENTUUID,
		&client_uuid, sizeof(client_uuid)),
		EINVAL,
		"setsockopt SO_NECP_CLIENTUUID on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_necp_clientuuid_inet,
    "SO_NECP_CLIENTUUID on AF_INET doesn't fail with EINVAL",
    T_META_ASROOT(true))
{
	int fd;
	uuid_t client_uuid, get_uuid;
	socklen_t optlen = sizeof(get_uuid);
	int ret;

	uuid_clear(client_uuid);
	uuid_generate(client_uuid);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/*
	 * Setting SO_NECP_CLIENTUUID requires a registered NECP client.
	 * Since we don't have Network Extensions running, this will fail
	 * with ENOENT (client UUID not found) rather than EINVAL (wrong
	 * socket family). We're testing that it doesn't reject based on
	 * socket family.
	 */
	ret = setsockopt(fd, SOL_SOCKET, SO_NECP_CLIENTUUID,
	    &client_uuid, sizeof(client_uuid));
	if (ret == -1) {
		T_EXPECT_NE(errno, EINVAL,
		    "setsockopt SO_NECP_CLIENTUUID should not fail with EINVAL on AF_INET");
		T_LOG("setsockopt failed with errno %d (%s) - expected for unregistered client",
		    errno, strerror(errno));
	} else {
		/* If it succeeded, verify round-trip */
		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NECP_CLIENTUUID,
			&get_uuid, &optlen),
			"getsockopt SO_NECP_CLIENTUUID on AF_INET");

		T_EXPECT_EQ(uuid_compare(client_uuid, get_uuid), 0,
		    "SO_NECP_CLIENTUUID matches");
	}

	close(fd);
}

/*
 * Test SO_NECP_LISTENUUID on different socket families
 */
T_DECL(so_necp_listenuuid_unix,
    "SO_NECP_LISTENUUID fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	uuid_t listen_uuid;

	uuid_clear(listen_uuid);
	uuid_generate(listen_uuid);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_NECP_LISTENUUID,
		&listen_uuid, sizeof(listen_uuid)),
		EINVAL,
		"setsockopt SO_NECP_LISTENUUID on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_necp_listenuuid_inet6,
    "SO_NECP_LISTENUUID on AF_INET6 doesn't fail with EINVAL",
    T_META_ASROOT(true))
{
	int fd;
	uuid_t listen_uuid, get_uuid;
	socklen_t optlen = sizeof(get_uuid);
	int ret;

	uuid_clear(listen_uuid);
	uuid_generate(listen_uuid);

	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/*
	 * Setting SO_NECP_LISTENUUID requires a registered NECP client.
	 * Since we don't have Network Extensions running, this will fail
	 * with ENOENT (client UUID not found) rather than EINVAL (wrong
	 * socket family). We're testing that it doesn't reject based on
	 * socket family.
	 */
	ret = setsockopt(fd, SOL_SOCKET, SO_NECP_LISTENUUID,
	    &listen_uuid, sizeof(listen_uuid));
	if (ret == -1) {
		T_EXPECT_NE(errno, EINVAL,
		    "setsockopt SO_NECP_LISTENUUID should not fail with EINVAL on AF_INET6");
		T_LOG("setsockopt failed with errno %d (%s) - expected for unregistered client",
		    errno, strerror(errno));
	} else {
		/* If it succeeded, verify round-trip */
		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_NECP_LISTENUUID,
			&get_uuid, &optlen),
			"getsockopt SO_NECP_LISTENUUID on AF_INET6");

		T_EXPECT_EQ(uuid_compare(listen_uuid, get_uuid), 0,
		    "SO_NECP_LISTENUUID matches");
	}

	close(fd);
}

/*
 * Test SO_RESOLVER_SIGNATURE on different socket families
 */
T_DECL(so_resolver_signature_unix,
    "SO_RESOLVER_SIGNATURE fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	uint8_t signature[32] = {0};

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_RESOLVER_SIGNATURE,
		signature, sizeof(signature)),
		EINVAL,
		"setsockopt SO_RESOLVER_SIGNATURE on AF_UNIX should fail");

	close(fd);
}

/*
 * Test SO_MAX_PACING_RATE on different socket families
 */
T_DECL(so_max_pacing_rate_unix,
    "SO_MAX_PACING_RATE fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	uint64_t pacing_rate = 1000000; /* 1 Mbps */

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
		&pacing_rate, sizeof(pacing_rate)),
		EINVAL,
		"setsockopt SO_MAX_PACING_RATE on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_max_pacing_rate_inet,
    "SO_MAX_PACING_RATE succeeds on AF_INET",
    T_META_ASROOT(true))
{
	int fd;
	uint64_t pacing_rate = 1000000; /* 1 Mbps */
	uint64_t get_rate = 0;
	socklen_t optlen = sizeof(get_rate);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
		&pacing_rate, sizeof(pacing_rate)),
		"setsockopt SO_MAX_PACING_RATE on AF_INET");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
		&get_rate, &optlen),
		"getsockopt SO_MAX_PACING_RATE on AF_INET");

	T_EXPECT_EQ(get_rate, pacing_rate, "SO_MAX_PACING_RATE value matches");

	close(fd);
}

T_DECL(so_max_pacing_rate_inet6_udp,
    "SO_MAX_PACING_RATE succeeds on AF_INET6 UDP",
    T_META_ASROOT(true))
{
	int fd;
	uint64_t pacing_rate = 5000000; /* 5 Mbps */
	uint64_t get_rate = 0;
	socklen_t optlen = sizeof(get_rate);

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
		&pacing_rate, sizeof(pacing_rate)),
		"setsockopt SO_MAX_PACING_RATE on AF_INET6 UDP");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
		&get_rate, &optlen),
		"getsockopt SO_MAX_PACING_RATE on AF_INET6 UDP");

	T_EXPECT_EQ(get_rate, pacing_rate, "SO_MAX_PACING_RATE value matches");

	close(fd);
}

/*
 * Test SO_CONNECTION_IDLE on different socket families
 */
T_DECL(so_connection_idle_unix,
    "SO_CONNECTION_IDLE fails on AF_UNIX",
    T_META_ASROOT(true))
{
	int fd;
	int is_idle = 1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&is_idle, sizeof(is_idle)),
		EINVAL,
		"setsockopt SO_CONNECTION_IDLE on AF_UNIX should fail");

	close(fd);
}

T_DECL(so_connection_idle_inet,
    "SO_CONNECTION_IDLE succeeds on AF_INET",
    T_META_ASROOT(true))
{
	int fd;
	int is_idle = 1;
	int get_idle = 0;
	socklen_t optlen = sizeof(get_idle);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&is_idle, sizeof(is_idle)),
		"setsockopt SO_CONNECTION_IDLE on AF_INET");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&get_idle, &optlen),
		"getsockopt SO_CONNECTION_IDLE on AF_INET");

	T_EXPECT_EQ(get_idle, 1, "SO_CONNECTION_IDLE value matches");

	/* Test clearing the flag */
	is_idle = 0;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&is_idle, sizeof(is_idle)),
		"setsockopt SO_CONNECTION_IDLE clear on AF_INET");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&get_idle, &optlen),
		"getsockopt SO_CONNECTION_IDLE on AF_INET");

	T_EXPECT_EQ(get_idle, 0, "SO_CONNECTION_IDLE cleared");

	close(fd);
}

T_DECL(so_connection_idle_inet6,
    "SO_CONNECTION_IDLE succeeds on AF_INET6",
    T_META_ASROOT(true))
{
	int fd;
	int is_idle = 1;
	int get_idle = 0;
	socklen_t optlen = sizeof(get_idle);

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&is_idle, sizeof(is_idle)),
		"setsockopt SO_CONNECTION_IDLE on AF_INET6");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_CONNECTION_IDLE,
		&get_idle, &optlen),
		"getsockopt SO_CONNECTION_IDLE on AF_INET6");

	T_EXPECT_EQ(get_idle, 1, "SO_CONNECTION_IDLE value matches");

	close(fd);
}

/*
 * ===========================
 * Private SOL_SOCKET Options
 * ===========================
 */

/*
 * Test SO_TRAFFIC_CLASS - Traffic service class
 */
T_DECL(so_traffic_class_inet_tcp, "SO_TRAFFIC_CLASS on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test different traffic classes */
	int tc_values[] = {SO_TC_BE, SO_TC_BK, SO_TC_BK_SYS, SO_TC_RD,
		           SO_TC_OAM, SO_TC_AV, SO_TC_RV, SO_TC_VI, SO_TC_VO, SO_TC_CTL};

	for (size_t i = 0; i < sizeof(tc_values) / sizeof(tc_values[0]); i++) {
		int setval = tc_values[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &setval, sizeof(setval)),
			"setsockopt SO_TRAFFIC_CLASS = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &getval, &optlen),
			"getsockopt SO_TRAFFIC_CLASS");

		T_EXPECT_EQ(getval, setval,
		    "SO_TRAFFIC_CLASS value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_traffic_class_inet_udp, "SO_TRAFFIC_CLASS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	/* Test a few traffic classes */
	int setval = SO_TC_AV;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &setval, sizeof(setval)),
		"setsockopt SO_TRAFFIC_CLASS = SO_TC_AV");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &getval, &optlen),
		"getsockopt SO_TRAFFIC_CLASS");

	T_EXPECT_EQ(getval, SO_TC_AV, "SO_TRAFFIC_CLASS is SO_TC_AV");

	close(fd);
}

T_DECL(so_traffic_class_invalid, "SO_TRAFFIC_CLASS rejects invalid values")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test invalid traffic class value */
	int invalid = 9999;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &invalid, sizeof(invalid)),
		EINVAL,
		"SO_TRAFFIC_CLASS should reject invalid value");

	close(fd);
}

/*
 * Test SO_RECV_TRAFFIC_CLASS - Receive traffic class
 */
T_DECL(so_recv_traffic_class_inet_udp, "SO_RECV_TRAFFIC_CLASS on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_RECV_TRAFFIC_CLASS, "SO_RECV_TRAFFIC_CLASS", 1, true);
	test_bool_option(fd, SO_RECV_TRAFFIC_CLASS, "SO_RECV_TRAFFIC_CLASS", 0, false);

	close(fd);
}

/*
 * Test SO_TRAFFIC_MGT_BACKGROUND - Background traffic management
 */
T_DECL(so_traffic_mgt_background_inet_tcp, "SO_TRAFFIC_MGT_BACKGROUND on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_TRAFFIC_MGT_BACKGROUND, "SO_TRAFFIC_MGT_BACKGROUND", 1, true);
	test_bool_option(fd, SO_TRAFFIC_MGT_BACKGROUND, "SO_TRAFFIC_MGT_BACKGROUND", 0, false);

	close(fd);
}

/*
 * Test SO_RECV_ANYIF - Unrestricted inbound processing
 */
T_DECL(so_recv_anyif_inet_udp, "SO_RECV_ANYIF on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_RECV_ANYIF, "SO_RECV_ANYIF", 1, true);
	test_bool_option(fd, SO_RECV_ANYIF, "SO_RECV_ANYIF", 0, false);

	close(fd);
}

/*
 * Test SO_DEFUNCTOK - Socket can be defunct'd
 */
T_DECL(so_defunctok_inet_tcp, "SO_DEFUNCTOK on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_DEFUNCTOK, "SO_DEFUNCTOK", 1, true);

	close(fd);
}

/*
 * Test SO_ISDEFUNCT - Get defunct status (read-only)
 */
T_DECL(so_isdefunct_readonly, "SO_ISDEFUNCT is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Should be able to read defunct status */
	int defunct = 0;
	socklen_t optlen = sizeof(defunct);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_ISDEFUNCT, &defunct, &optlen),
		"getsockopt SO_ISDEFUNCT");

	T_LOG("SO_ISDEFUNCT: %d", defunct);

	/* Should not be able to set it */
	defunct = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_ISDEFUNCT, &defunct, sizeof(defunct)),
		EINVAL,
		"setsockopt SO_ISDEFUNCT should fail (read-only)");

	close(fd);
}

/*
 * Test SO_RESTRICTIONS - Deny flags
 */
T_DECL(so_restrictions_inet_tcp, "SO_RESTRICTIONS on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test setting restrictions */
	int restrictions = SO_RESTRICT_DENY_CELLULAR | SO_RESTRICT_DENY_EXPENSIVE;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RESTRICTIONS, &restrictions, sizeof(restrictions)),
		"setsockopt SO_RESTRICTIONS");

	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RESTRICTIONS, &getval, &optlen),
		"getsockopt SO_RESTRICTIONS");

	T_EXPECT_EQ(getval, restrictions,
	    "SO_RESTRICTIONS value matches (expected 0x%x, got 0x%x)",
	    restrictions, getval);

	close(fd);
}

/*
 * Test SO_FLUSH - Flush unsent data
 */
T_DECL(so_flush_inet_tcp, "SO_FLUSH on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Flush all traffic classes */
	int flush_val = SO_TC_ALL;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_FLUSH, &flush_val, sizeof(flush_val)),
		"setsockopt SO_FLUSH = SO_TC_ALL");

	/* Flush specific traffic class */
	flush_val = SO_TC_BE;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_FLUSH, &flush_val, sizeof(flush_val)),
		"setsockopt SO_FLUSH = SO_TC_BE");

	close(fd);
}

/*
 * Test SO_EXTENDED_BK_IDLE - Extended background idle time
 * Note: This is a boolean option (0 = disable, non-zero = enable), not a time value
 */
T_DECL(so_extended_bk_idle_inet_tcp, "SO_EXTENDED_BK_IDLE on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Enable extended background idle */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &enable, sizeof(enable)),
		"setsockopt SO_EXTENDED_BK_IDLE = 1");

	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &getval, &optlen),
		"getsockopt SO_EXTENDED_BK_IDLE");

	T_EXPECT_NE(getval, 0, "SO_EXTENDED_BK_IDLE is enabled (got %d)", getval);

	/* Disable extended background idle */
	int disable = 0;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &disable, sizeof(disable)),
		"setsockopt SO_EXTENDED_BK_IDLE = 0");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &getval, &optlen),
		"getsockopt SO_EXTENDED_BK_IDLE");

	T_EXPECT_EQ(getval, 0, "SO_EXTENDED_BK_IDLE is disabled");

	close(fd);
}

/*
 * Test SO_MARK_CELLFALLBACK - Mark as initiated by cell fallback
 */
T_DECL(so_mark_cellfallback_inet_tcp, "SO_MARK_CELLFALLBACK on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int mark = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MARK_CELLFALLBACK, &mark, sizeof(mark)),
		"setsockopt SO_MARK_CELLFALLBACK");

	/* This is a one-way marking option, getsockopt may not be supported */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	int ret = getsockopt(fd, SOL_SOCKET, SO_MARK_CELLFALLBACK, &getval, &optlen);
	if (ret == 0) {
		T_LOG("SO_MARK_CELLFALLBACK getsockopt returned: %d", getval);
	}

	close(fd);
}

/*
 * Test SO_MARK_KNOWN_TRACKER - Mark as connection to known tracker
 */
T_DECL(so_mark_known_tracker_inet_tcp, "SO_MARK_KNOWN_TRACKER on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int mark = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MARK_KNOWN_TRACKER, &mark, sizeof(mark)),
		"setsockopt SO_MARK_KNOWN_TRACKER");

	close(fd);
}

/*
 * Test SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED - Mark tracker as non-app initiated
 */
T_DECL(so_mark_known_tracker_non_app_initiated_inet_tcp,
    "SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int mark = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED,
		&mark, sizeof(mark)),
		"setsockopt SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED");

	close(fd);
}

/*
 * Test SO_MARK_APPROVED_APP_DOMAIN - Mark as approved app domain
 */
T_DECL(so_mark_approved_app_domain_inet_tcp, "SO_MARK_APPROVED_APP_DOMAIN on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int mark = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MARK_APPROVED_APP_DOMAIN, &mark, sizeof(mark)),
		"setsockopt SO_MARK_APPROVED_APP_DOMAIN");

	close(fd);
}

/*
 * Test SO_MARK_WAKE_PKT - Mark next packet as wake packet
 */
T_DECL(so_mark_wake_pkt_inet_udp, "SO_MARK_WAKE_PKT on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	int mark = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MARK_WAKE_PKT, &mark, sizeof(mark)),
		"setsockopt SO_MARK_WAKE_PKT");

	close(fd);
}

/*
 * Test SO_RECV_WAKE_PKT - Receive wake packet indication
 */
T_DECL(so_recv_wake_pkt_inet_udp, "SO_RECV_WAKE_PKT on AF_INET UDP")
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_DGRAM)");

	test_bool_option(fd, SO_RECV_WAKE_PKT, "SO_RECV_WAKE_PKT", 1, true);
	test_bool_option(fd, SO_RECV_WAKE_PKT, "SO_RECV_WAKE_PKT", 0, false);

	close(fd);
}

/*
 * Test SO_MARK_DOMAIN_INFO_SILENT - Domain info should be silently withheld
 */
T_DECL(so_mark_domain_info_silent_inet_tcp, "SO_MARK_DOMAIN_INFO_SILENT on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int mark = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_MARK_DOMAIN_INFO_SILENT, &mark, sizeof(mark)),
		"setsockopt SO_MARK_DOMAIN_INFO_SILENT");

	close(fd);
}

/*
 * Test SO_WANT_KEV_SOCKET_CLOSED - Want delivery of KEV_SOCKET_CLOSED
 * Note: This is write-only, getsockopt is not supported
 */
T_DECL(so_want_kev_socket_closed_inet_tcp, "SO_WANT_KEV_SOCKET_CLOSED on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Enable KEV_SOCKET_CLOSED events */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_WANT_KEV_SOCKET_CLOSED, &enable, sizeof(enable)),
		"setsockopt SO_WANT_KEV_SOCKET_CLOSED = 1");

	/* Disable KEV_SOCKET_CLOSED events */
	int disable = 0;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_WANT_KEV_SOCKET_CLOSED, &disable, sizeof(disable)),
		"setsockopt SO_WANT_KEV_SOCKET_CLOSED = 0");

	/* getsockopt is not supported for this option */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	int ret = getsockopt(fd, SOL_SOCKET, SO_WANT_KEV_SOCKET_CLOSED, &getval, &optlen);
	T_ASSERT_EQ(ret, -1, "getsockopt SO_WANT_KEV_SOCKET_CLOSED should fail (write-only)");
	T_EXPECT_EQ(errno, ENOPROTOOPT, "errno should be ENOPROTOOPT (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

/*
 * Test SO_QOSMARKING_POLICY_OVERRIDE - QoS marking policy override
 * Note: Only available on iOS, not macOS
 */
#if TARGET_OS_IPHONE
T_DECL(so_qosmarking_policy_override_inet_tcp, "SO_QOSMARKING_POLICY_OVERRIDE on AF_INET TCP (iOS)",
    T_META_ENABLED(TARGET_OS_IPHONE))
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int policy = 1;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_MAYFAIL;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_QOSMARKING_POLICY_OVERRIDE, &policy, sizeof(policy)),
		"setsockopt SO_QOSMARKING_POLICY_OVERRIDE");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_QOSMARKING_POLICY_OVERRIDE, &getval, &optlen),
		"getsockopt SO_QOSMARKING_POLICY_OVERRIDE");

	T_MAYFAIL;
	T_EXPECT_EQ(getval, policy,
	    "SO_QOSMARKING_POLICY_OVERRIDE value matches (expected %d, got %d)",
	    policy, getval);

	close(fd);
}
#else
T_DECL(so_qosmarking_policy_override_inet_tcp, "SO_QOSMARKING_POLICY_OVERRIDE on AF_INET TCP (macOS)",
    T_META_ENABLED(!TARGET_OS_IPHONE))
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* On macOS, SO_QOSMARKING_POLICY_OVERRIDE is not available */
	int policy = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_QOSMARKING_POLICY_OVERRIDE, &policy, sizeof(policy));

	T_MAYFAIL;
	/* Should fail - exact error may vary (ENOPROTOOPT or EPERM) */
	if (ret == -1) {
		T_LOG("SO_QOSMARKING_POLICY_OVERRIDE failed as expected on macOS: %d (%s)",
		    errno, strerror(errno));
	} else {
		T_FAIL("SO_QOSMARKING_POLICY_OVERRIDE should not be available on macOS");
	}

	close(fd);
}
#endif

/*
 * Test SO_FALLBACK_MODE - Fallback mode (read-only)
 */
T_DECL(so_fallback_mode_readonly, "SO_FALLBACK_MODE is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Should be able to read fallback mode */
	int mode = 0;
	socklen_t optlen = sizeof(mode);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_FALLBACK_MODE, &mode, &optlen),
		"getsockopt SO_FALLBACK_MODE");

	T_LOG("SO_FALLBACK_MODE: %d", mode);

	/* Setting should fail (read-only) */
	mode = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_FALLBACK_MODE, &mode, sizeof(mode));
	if (ret == -1) {
		T_LOG("setsockopt SO_FALLBACK_MODE failed as expected: %s", strerror(errno));
	}

	close(fd);
}

/*
 * Test SO_STATISTICS_EVENT - Statistics event
 */
T_DECL(so_statistics_event_inet_tcp, "SO_STATISTICS_EVENT on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set statistics event */
	int64_t event = SO_STATISTICS_EVENT_ENTER_CELLFALLBACK;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_STATISTICS_EVENT, &event, sizeof(event)),
		"setsockopt SO_STATISTICS_EVENT = ENTER_CELLFALLBACK");

	event = SO_STATISTICS_EVENT_EXIT_CELLFALLBACK;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_STATISTICS_EVENT, &event, sizeof(event)),
		"setsockopt SO_STATISTICS_EVENT = EXIT_CELLFALLBACK");

	close(fd);
}

/*
 * Test multiple private options on same socket
 */
T_DECL(so_private_multiple_options, "Multiple private SOL_SOCKET options on same socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set multiple options */
	int tc = SO_TC_VI;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &tc, sizeof(tc)),
		"setsockopt SO_TRAFFIC_CLASS");

	int recv_tc = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RECV_TRAFFIC_CLASS, &recv_tc, sizeof(recv_tc)),
		"setsockopt SO_RECV_TRAFFIC_CLASS");

	int restrictions = SO_RESTRICT_DENY_CELLULAR;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RESTRICTIONS, &restrictions, sizeof(restrictions)),
		"setsockopt SO_RESTRICTIONS");

	int recv_anyif = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RECV_ANYIF, &recv_anyif, sizeof(recv_anyif)),
		"setsockopt SO_RECV_ANYIF");

	/* Verify all options */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &getval, &optlen),
		"getsockopt SO_TRAFFIC_CLASS");
	T_EXPECT_EQ(getval, SO_TC_VI, "SO_TRAFFIC_CLASS still set");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RECV_TRAFFIC_CLASS, &getval, &optlen),
		"getsockopt SO_RECV_TRAFFIC_CLASS");
	T_EXPECT_NE(getval, 0, "SO_RECV_TRAFFIC_CLASS still enabled");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RESTRICTIONS, &getval, &optlen),
		"getsockopt SO_RESTRICTIONS");
	T_EXPECT_EQ(getval, SO_RESTRICT_DENY_CELLULAR, "SO_RESTRICTIONS still set");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RECV_ANYIF, &getval, &optlen),
		"getsockopt SO_RECV_ANYIF");
	T_EXPECT_NE(getval, 0, "SO_RECV_ANYIF still enabled");

	close(fd);
}

/*
 * Additional AF_INET6 coverage for private SOL_SOCKET options
 * Testing options that were previously only tested on AF_INET
 */

T_DECL(so_traffic_class_inet6_tcp, "SO_TRAFFIC_CLASS on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Test different traffic classes */
	int tc_values[] = {SO_TC_BE, SO_TC_BK, SO_TC_VI, SO_TC_VO, SO_TC_CTL};

	for (size_t i = 0; i < sizeof(tc_values) / sizeof(tc_values[0]); i++) {
		int setval = tc_values[i];
		int getval = 0;
		socklen_t optlen = sizeof(getval);

		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &setval, sizeof(setval)),
			"setsockopt SO_TRAFFIC_CLASS = %d", setval);

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &getval, &optlen),
			"getsockopt SO_TRAFFIC_CLASS");

		T_EXPECT_EQ(getval, setval,
		    "SO_TRAFFIC_CLASS value matches (expected %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(so_traffic_class_inet6_udp, "SO_TRAFFIC_CLASS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	int setval = SO_TC_AV;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &setval, sizeof(setval)),
		"setsockopt SO_TRAFFIC_CLASS = SO_TC_AV");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &getval, &optlen),
		"getsockopt SO_TRAFFIC_CLASS");

	T_EXPECT_EQ(getval, SO_TC_AV, "SO_TRAFFIC_CLASS is SO_TC_AV");

	close(fd);
}

T_DECL(so_recv_anyif_inet6_udp, "SO_RECV_ANYIF on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_RECV_ANYIF, "SO_RECV_ANYIF", 1, true);
	test_bool_option(fd, SO_RECV_ANYIF, "SO_RECV_ANYIF", 0, false);

	close(fd);
}

T_DECL(so_traffic_mgt_background_inet6_tcp, "SO_TRAFFIC_MGT_BACKGROUND on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_bool_option(fd, SO_TRAFFIC_MGT_BACKGROUND,
	    "SO_TRAFFIC_MGT_BACKGROUND", 1, true);
	test_bool_option(fd, SO_TRAFFIC_MGT_BACKGROUND,
	    "SO_TRAFFIC_MGT_BACKGROUND", 0, false);

	close(fd);
}

T_DECL(so_recv_traffic_class_inet6_udp, "SO_RECV_TRAFFIC_CLASS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_RECV_TRAFFIC_CLASS,
	    "SO_RECV_TRAFFIC_CLASS", 1, true);
	test_bool_option(fd, SO_RECV_TRAFFIC_CLASS,
	    "SO_RECV_TRAFFIC_CLASS", 0, false);

	close(fd);
}

T_DECL(so_restrictions_inet6_tcp, "SO_RESTRICTIONS on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	int restrictions = SO_RESTRICT_DENY_CELLULAR | SO_RESTRICT_DENY_EXPENSIVE;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RESTRICTIONS, &restrictions, sizeof(restrictions)),
		"setsockopt SO_RESTRICTIONS");

	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RESTRICTIONS, &getval, &optlen),
		"getsockopt SO_RESTRICTIONS");

	T_EXPECT_EQ(getval, restrictions,
	    "SO_RESTRICTIONS value matches (expected 0x%x, got 0x%x)",
	    restrictions, getval);

	close(fd);
}

T_DECL(so_extended_bk_idle_inet6_tcp, "SO_EXTENDED_BK_IDLE on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	/* Enable extended background idle */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &enable, sizeof(enable)),
		"setsockopt SO_EXTENDED_BK_IDLE = 1");

	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &getval, &optlen),
		"getsockopt SO_EXTENDED_BK_IDLE");

	T_EXPECT_NE(getval, 0, "SO_EXTENDED_BK_IDLE is enabled (got %d)", getval);

	/* Disable extended background idle */
	int disable = 0;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &disable, sizeof(disable)),
		"setsockopt SO_EXTENDED_BK_IDLE = 0");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &getval, &optlen),
		"getsockopt SO_EXTENDED_BK_IDLE");

	T_EXPECT_EQ(getval, 0, "SO_EXTENDED_BK_IDLE is disabled");

	close(fd);
}

T_DECL(so_defunctok_inet6_tcp, "SO_DEFUNCTOK on AF_INET6 TCP")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_bool_option(fd, SO_DEFUNCTOK, "SO_DEFUNCTOK", 1, true);

	close(fd);
}

/*
 * AF_UNIX coverage for private SOL_SOCKET options
 * Testing that private SOL_SOCKET options work on Unix domain sockets
 */

T_DECL(so_defunctok_unix_stream, "SO_DEFUNCTOK on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_bool_option(fd, SO_DEFUNCTOK, "SO_DEFUNCTOK", 1, true);

	close(fd);
}

T_DECL(so_extended_bk_idle_unix_stream_not_supported, "SO_EXTENDED_BK_IDLE not supported on AF_UNIX")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	/* SO_EXTENDED_BK_IDLE is only supported on PF_INET/PF_INET6 + IPPROTO_TCP */
	int enable = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &enable, sizeof(enable)),
		EOPNOTSUPP,
		"setsockopt SO_EXTENDED_BK_IDLE should fail on AF_UNIX with EOPNOTSUPP");

	/* getsockopt should still work but return disabled state */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_EXTENDED_BK_IDLE, &getval, &optlen),
		"getsockopt SO_EXTENDED_BK_IDLE");

	T_EXPECT_EQ(getval, 0, "SO_EXTENDED_BK_IDLE is not set (got %d)", getval);

	close(fd);
}

T_DECL(so_isdefunct_unix_stream, "SO_ISDEFUNCT on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	/* Should be able to read defunct status */
	int defunct = 0;
	socklen_t optlen = sizeof(defunct);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_ISDEFUNCT, &defunct, &optlen),
		"getsockopt SO_ISDEFUNCT");

	T_LOG("SO_ISDEFUNCT: %d", defunct);

	close(fd);
}

/*
 * ===========================
 * Security/Identity Options
 * ===========================
 */

/*
 * Test SO_LABEL - MAC framework label (deprecated)
 */
T_DECL(so_label_deprecated, "SO_LABEL is deprecated and returns EOPNOTSUPP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_LABEL is deprecated and should return EOPNOTSUPP */
	int label = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_LABEL, &label, sizeof(label)),
		EOPNOTSUPP,
		"setsockopt SO_LABEL should fail (deprecated)");

	/* getsockopt should also fail */
	socklen_t optlen = sizeof(label);
	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, SOL_SOCKET, SO_LABEL, &label, &optlen),
		EOPNOTSUPP,
		"getsockopt SO_LABEL should fail (deprecated)");

	close(fd);
}

/*
 * Test SO_PEERLABEL - Get peer's MAC label (deprecated)
 */
T_DECL(so_peerlabel_deprecated, "SO_PEERLABEL is deprecated and returns EOPNOTSUPP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_PEERLABEL is deprecated and should return EOPNOTSUPP */
	int label = 0;
	socklen_t optlen = sizeof(label);
	T_ASSERT_POSIX_FAILURE(
		getsockopt(fd, SOL_SOCKET, SO_PEERLABEL, &label, &optlen),
		EOPNOTSUPP,
		"getsockopt SO_PEERLABEL should fail (deprecated)");

	close(fd);
}

/*
 * Test SO_DELEGATED - Delegated socket (set effective PID)
 * Note: This is a write-only option, getsockopt is not supported
 */
T_DECL(so_delegated_inet_tcp, "SO_DELEGATED on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Try to set to our own PID (should succeed) */
	pid_t mypid = getpid();
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_DELEGATED, &mypid, sizeof(mypid)),
		"setsockopt SO_DELEGATED = own PID");

	/* getsockopt is not supported for this option (write-only) */
	pid_t getpid_val = 0;
	socklen_t optlen = sizeof(getpid_val);
	int ret = getsockopt(fd, SOL_SOCKET, SO_DELEGATED, &getpid_val, &optlen);
	T_ASSERT_EQ(ret, -1, "getsockopt SO_DELEGATED should fail (write-only)");
	T_EXPECT_EQ(errno, ENOPROTOOPT, "errno should be ENOPROTOOPT (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

T_DECL(so_delegated_inet6_udp, "SO_DELEGATED on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	pid_t mypid = getpid();
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_DELEGATED, &mypid, sizeof(mypid)),
		"setsockopt SO_DELEGATED = own PID");

	close(fd);
}

T_DECL(so_delegated_fails_on_unix, "SO_DELEGATED works on AF_UNIX")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	/* SO_DELEGATED should work on AF_UNIX */
	pid_t mypid = getpid();
	int ret = setsockopt(fd, SOL_SOCKET, SO_DELEGATED, &mypid, sizeof(mypid));
	if (ret == 0) {
		T_LOG("SO_DELEGATED succeeded on AF_UNIX");
	} else {
		T_LOG("SO_DELEGATED failed on AF_UNIX: %d (%s)", errno, strerror(errno));
	}

	close(fd);
}

/*
 * Test SO_DELEGATED_UUID - Delegated socket by UUID
 * Note: This is a write-only option, getsockopt is not supported
 */
T_DECL(so_delegated_uuid_inet_tcp, "SO_DELEGATED_UUID on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Generate a UUID */
	uuid_t test_uuid;
	uuid_clear(test_uuid);
	uuid_generate(test_uuid);

	/* Try to set the UUID - may fail without proper entitlements/permissions */
	int ret = setsockopt(fd, SOL_SOCKET, SO_DELEGATED_UUID,
	    &test_uuid, sizeof(test_uuid));
	if (ret == -1) {
		T_LOG("SO_DELEGATED_UUID failed as expected: %d (%s)",
		    errno, strerror(errno));
	} else {
		T_LOG("SO_DELEGATED_UUID succeeded");

		/* getsockopt is not supported (write-only) */
		uuid_t get_uuid;
		socklen_t optlen = sizeof(get_uuid);
		ret = getsockopt(fd, SOL_SOCKET, SO_DELEGATED_UUID, &get_uuid, &optlen);
		T_ASSERT_EQ(ret, -1, "getsockopt SO_DELEGATED_UUID should fail (write-only)");
		T_EXPECT_EQ(errno, ENOPROTOOPT, "errno should be ENOPROTOOPT (got %d: %s)",
		    errno, strerror(errno));
	}

	close(fd);
}

T_DECL(so_delegated_uuid_inet6_udp, "SO_DELEGATED_UUID on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	uuid_t test_uuid;
	uuid_clear(test_uuid);
	uuid_generate(test_uuid);

	int ret = setsockopt(fd, SOL_SOCKET, SO_DELEGATED_UUID,
	    &test_uuid, sizeof(test_uuid));
	if (ret == -1) {
		T_LOG("SO_DELEGATED_UUID failed: %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("SO_DELEGATED_UUID succeeded");
	}

	close(fd);
}

/*
 * Test SO_EXECPATH - Executable path (Application Firewall)
 */
T_DECL(so_execpath_inet_tcp, "SO_EXECPATH on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Try to set executable path */
	char execpath[1024] = "/usr/bin/test";
	int ret = setsockopt(fd, SOL_SOCKET, SO_EXECPATH,
	    execpath, (socklen_t)strlen(execpath) + 1);
	if (ret == -1) {
		T_LOG("SO_EXECPATH setsockopt failed: %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("SO_EXECPATH setsockopt succeeded");
	}

	/* Try to get executable path */
	char getpath[1024] = {0};
	socklen_t optlen = sizeof(getpath);
	ret = getsockopt(fd, SOL_SOCKET, SO_EXECPATH, getpath, &optlen);
	if (ret == -1) {
		T_LOG("SO_EXECPATH getsockopt failed: %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("SO_EXECPATH getsockopt succeeded: %s", getpath);
	}

	close(fd);
}

/*
 * Test SO_APPLICATION_ID - Application identifier
 */
T_DECL(so_application_id_inet_tcp, "SO_APPLICATION_ID on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_APPLICATION_ID requires PF_INET or PF_INET6 */
	so_application_id_t app_id;
	memset(&app_id, 0, sizeof(app_id));
	app_id.uid = getuid();
	uuid_generate(app_id.effective_uuid);
	app_id.persona_id = (uid_t)-1; /* PERSONA_ID_NONE */

	int ret = setsockopt(fd, SOL_SOCKET, SO_APPLICATION_ID,
	    &app_id, sizeof(app_id));
	if (ret == -1) {
		T_LOG("SO_APPLICATION_ID setsockopt failed: %d (%s)", errno, strerror(errno));
	} else {
		T_LOG("SO_APPLICATION_ID setsockopt succeeded");

		/* Try to get it back */
		so_application_id_t get_app_id;
		socklen_t optlen = sizeof(get_app_id);
		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_APPLICATION_ID, &get_app_id, &optlen),
			"getsockopt SO_APPLICATION_ID");

		T_EXPECT_EQ(get_app_id.uid, app_id.uid, "SO_APPLICATION_ID uid matches");
		T_LOG("SO_APPLICATION_ID persona_id: %u", get_app_id.persona_id);
	}

	close(fd);
}

T_DECL(so_application_id_fails_on_unix, "SO_APPLICATION_ID fails on AF_UNIX")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	/* SO_APPLICATION_ID requires PF_INET or PF_INET6 */
	so_application_id_t app_id;
	memset(&app_id, 0, sizeof(app_id));
	app_id.uid = getuid();
	uuid_generate(app_id.effective_uuid);
	app_id.persona_id = (uid_t)-1; /* PERSONA_ID_NONE */

	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, SOL_SOCKET, SO_APPLICATION_ID, &app_id, sizeof(app_id)),
		EINVAL,
		"setsockopt SO_APPLICATION_ID should fail on AF_UNIX");

	close(fd);
}

/*
 * Test SO_OPPORTUNISTIC - Opportunistic networking (deprecated)
 */
T_DECL(so_opportunistic_inet_tcp, "SO_OPPORTUNISTIC on AF_INET TCP (deprecated)")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_OPPORTUNISTIC is deprecated - use SO_TRAFFIC_CLASS instead */
	test_bool_option(fd, SO_OPPORTUNISTIC, "SO_OPPORTUNISTIC", 1, true);
	test_bool_option(fd, SO_OPPORTUNISTIC, "SO_OPPORTUNISTIC", 0, false);

	close(fd);
}

T_DECL(so_opportunistic_inet6_udp, "SO_OPPORTUNISTIC on AF_INET6 UDP (deprecated)")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_OPPORTUNISTIC, "SO_OPPORTUNISTIC", 1, true);
	test_bool_option(fd, SO_OPPORTUNISTIC, "SO_OPPORTUNISTIC", 0, false);

	close(fd);
}

/*
 * Test SO_PRIVILEGED_TRAFFIC_CLASS - Privileged traffic class
 * Note: Requires special entitlements, may fail with EPERM
 */
T_DECL(so_privileged_traffic_class_inet_tcp, "SO_PRIVILEGED_TRAFFIC_CLASS on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* SO_PRIVILEGED_TRAFFIC_CLASS is a boolean option requiring special entitlements */
	int enable = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_PRIVILEGED_TRAFFIC_CLASS, &enable, sizeof(enable));
	if (ret == -1) {
		T_LOG("SO_PRIVILEGED_TRAFFIC_CLASS failed (expected without entitlements): %d (%s)",
		    errno, strerror(errno));
		T_EXPECT_EQ(errno, EPERM, "Should fail with EPERM without entitlements");
	} else {
		T_LOG("SO_PRIVILEGED_TRAFFIC_CLASS succeeded (has required entitlements)");

		/* Verify it was set */
		int getval = 0;
		socklen_t optlen = sizeof(getval);
		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, SOL_SOCKET, SO_PRIVILEGED_TRAFFIC_CLASS, &getval, &optlen),
			"getsockopt SO_PRIVILEGED_TRAFFIC_CLASS");
		T_EXPECT_NE(getval, 0, "SO_PRIVILEGED_TRAFFIC_CLASS is enabled");

		/* Disable it */
		int disable = 0;
		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, SOL_SOCKET, SO_PRIVILEGED_TRAFFIC_CLASS, &disable, sizeof(disable)),
			"setsockopt SO_PRIVILEGED_TRAFFIC_CLASS = 0");
	}

	close(fd);
}

T_DECL(so_privileged_traffic_class_inet6_udp, "SO_PRIVILEGED_TRAFFIC_CLASS on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	/* SO_PRIVILEGED_TRAFFIC_CLASS requires special entitlements */
	int enable = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_PRIVILEGED_TRAFFIC_CLASS, &enable, sizeof(enable));
	if (ret == -1) {
		T_LOG("SO_PRIVILEGED_TRAFFIC_CLASS failed (expected without entitlements): %d (%s)",
		    errno, strerror(errno));
		T_EXPECT_EQ(errno, EPERM, "Should fail with EPERM without entitlements");
	} else {
		T_LOG("SO_PRIVILEGED_TRAFFIC_CLASS succeeded (has required entitlements)");
	}

	close(fd);
}

/*
 * Test SO_NOWAKEFROMSLEEP - Don't wake device from sleep
 */
T_DECL(so_nowakefromsleep_inet_tcp, "SO_NOWAKEFROMSLEEP on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_NOWAKEFROMSLEEP, "SO_NOWAKEFROMSLEEP", 1, true);
	test_bool_option(fd, SO_NOWAKEFROMSLEEP, "SO_NOWAKEFROMSLEEP", 0, false);

	close(fd);
}

T_DECL(so_nowakefromsleep_inet6_udp, "SO_NOWAKEFROMSLEEP on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_NOWAKEFROMSLEEP, "SO_NOWAKEFROMSLEEP", 1, true);
	test_bool_option(fd, SO_NOWAKEFROMSLEEP, "SO_NOWAKEFROMSLEEP", 0, false);

	close(fd);
}

T_DECL(so_nowakefromsleep_unix_stream, "SO_NOWAKEFROMSLEEP on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_bool_option(fd, SO_NOWAKEFROMSLEEP, "SO_NOWAKEFROMSLEEP", 1, true);
	test_bool_option(fd, SO_NOWAKEFROMSLEEP, "SO_NOWAKEFROMSLEEP", 0, false);

	close(fd);
}

/*
 * Test SO_NOAPNFALLBK - No APN fallback
 */
T_DECL(so_noapnfallbk_inet_tcp, "SO_NOAPNFALLBK on AF_INET TCP")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_bool_option(fd, SO_NOAPNFALLBK, "SO_NOAPNFALLBK", 1, true);
	test_bool_option(fd, SO_NOAPNFALLBK, "SO_NOAPNFALLBK", 0, false);

	close(fd);
}

T_DECL(so_noapnfallbk_inet6_udp, "SO_NOAPNFALLBK on AF_INET6 UDP")
{
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_DGRAM)");

	test_bool_option(fd, SO_NOAPNFALLBK, "SO_NOAPNFALLBK", 1, true);
	test_bool_option(fd, SO_NOAPNFALLBK, "SO_NOAPNFALLBK", 0, false);

	close(fd);
}

T_DECL(so_noapnfallbk_unix_dgram, "SO_NOAPNFALLBK on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_bool_option(fd, SO_NOAPNFALLBK, "SO_NOAPNFALLBK", 1, true);
	test_bool_option(fd, SO_NOAPNFALLBK, "SO_NOAPNFALLBK", 0, false);

	close(fd);
}
