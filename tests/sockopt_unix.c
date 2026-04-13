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
 * sockopt_unix.c
 *
 * Tests for AF_UNIX/AF_LOCAL socket options.
 * Tests SOL_SOCKET options that work on Unix domain sockets,
 * including both SOCK_STREAM and SOCK_DGRAM types.
 */

#include <sys/socket.h>
#include <sys/un.h>
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
 * Helper to test boolean socket options
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_unix_bool_option(int fd, int optname, const char *optname_str,
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
}

/*
 * Test SO_REUSEADDR on Unix domain sockets
 */
T_DECL(unix_so_reuseaddr_stream, "SO_REUSEADDR on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_unix_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 1, true);
	test_unix_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 0, false);
	test_unix_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 42, true);

	close(fd);
}

T_DECL(unix_so_reuseaddr_dgram, "SO_REUSEADDR on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_unix_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 1, true);
	test_unix_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 0, false);

	close(fd);
}

/*
 * Test SO_REUSEPORT on Unix domain sockets
 */
T_DECL(unix_so_reuseport_stream, "SO_REUSEPORT on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_unix_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 1, true);
	test_unix_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 0, false);

	close(fd);
}

T_DECL(unix_so_reuseport_dgram, "SO_REUSEPORT on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_unix_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 1, true);
	test_unix_bool_option(fd, SO_REUSEPORT, "SO_REUSEPORT", 0, false);

	close(fd);
}

/*
 * Test SO_KEEPALIVE on Unix domain sockets
 */
T_DECL(unix_so_keepalive_stream, "SO_KEEPALIVE on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_unix_bool_option(fd, SO_KEEPALIVE, "SO_KEEPALIVE", 1, true);
	test_unix_bool_option(fd, SO_KEEPALIVE, "SO_KEEPALIVE", 0, false);

	close(fd);
}

/*
 * Test SO_OOBINLINE on Unix domain sockets
 */
T_DECL(unix_so_oobinline_stream, "SO_OOBINLINE on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_unix_bool_option(fd, SO_OOBINLINE, "SO_OOBINLINE", 1, true);
	test_unix_bool_option(fd, SO_OOBINLINE, "SO_OOBINLINE", 0, false);

	close(fd);
}

/*
 * Test SO_NOSIGPIPE on Unix domain sockets
 */
T_DECL(unix_so_nosigpipe_stream, "SO_NOSIGPIPE on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_unix_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);
	test_unix_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 0, false);

	close(fd);
}

T_DECL(unix_so_nosigpipe_dgram, "SO_NOSIGPIPE on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_unix_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);
	test_unix_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 0, false);

	close(fd);
}

/*
 * Test SO_SNDBUF on Unix domain sockets
 */
T_DECL(unix_so_sndbuf_stream, "SO_SNDBUF on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int sizes[] = {4096, 8192, 16384, 32768};
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

		/* Kernel may adjust the value */
		T_EXPECT_GE(getval, setval,
		    "SO_SNDBUF value >= requested (requested %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(unix_so_sndbuf_dgram, "SO_SNDBUF on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	int setval = 8192;
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
 * Test SO_RCVBUF on Unix domain sockets
 */
T_DECL(unix_so_rcvbuf_stream, "SO_RCVBUF on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int sizes[] = {4096, 8192, 16384, 32768};
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

		T_EXPECT_GE(getval, setval,
		    "SO_RCVBUF value >= requested (requested %d, got %d)",
		    setval, getval);
	}

	close(fd);
}

T_DECL(unix_so_rcvbuf_dgram, "SO_RCVBUF on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	int setval = 8192;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &setval, sizeof(setval)),
		"setsockopt SO_RCVBUF = %d", setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &getval, &optlen),
		"getsockopt SO_RCVBUF");

	T_EXPECT_GE(getval, setval,
	    "SO_RCVBUF value >= requested (requested %d, got %d)",
	    setval, getval);

	close(fd);
}

/*
 * Test SO_SNDLOWAT on Unix domain sockets
 */
T_DECL(unix_so_sndlowat_stream, "SO_SNDLOWAT on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_SNDLOWAT, &getval, &optlen),
		"getsockopt SO_SNDLOWAT");

	T_LOG("Default SO_SNDLOWAT: %d", getval);

	close(fd);
}

/*
 * Test SO_RCVLOWAT on Unix domain sockets
 */
T_DECL(unix_so_rcvlowat_stream, "SO_RCVLOWAT on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int setval = 1;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &setval, sizeof(setval)),
		"setsockopt SO_RCVLOWAT = %d", setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &getval, &optlen),
		"getsockopt SO_RCVLOWAT");

	T_EXPECT_EQ(getval, setval, "SO_RCVLOWAT value matches");

	close(fd);
}

/*
 * Test SO_SNDTIMEO on Unix domain sockets
 */
T_DECL(unix_so_sndtimeo_stream, "SO_SNDTIMEO on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	struct timeval tv_set = { .tv_sec = 5, .tv_usec = 500000 };
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

/*
 * Test SO_RCVTIMEO on Unix domain sockets
 */
T_DECL(unix_so_rcvtimeo_stream, "SO_RCVTIMEO on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	struct timeval tv_set = { .tv_sec = 2, .tv_usec = 250000 };
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

T_DECL(unix_so_rcvtimeo_dgram, "SO_RCVTIMEO on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	struct timeval tv_set = { .tv_sec = 1, .tv_usec = 0 };
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
 * Test SO_LINGER on Unix domain sockets
 */
T_DECL(unix_so_linger_stream, "SO_LINGER on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

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

/*
 * Test SO_TYPE on Unix domain sockets (read-only)
 */
T_DECL(unix_so_type_stream, "SO_TYPE on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int type = 0;
	socklen_t optlen = sizeof(type);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen),
		"getsockopt SO_TYPE");

	T_EXPECT_EQ(type, SOCK_STREAM, "SO_TYPE is SOCK_STREAM");

	close(fd);
}

T_DECL(unix_so_type_dgram, "SO_TYPE on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	int type = 0;
	socklen_t optlen = sizeof(type);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen),
		"getsockopt SO_TYPE");

	T_EXPECT_EQ(type, SOCK_DGRAM, "SO_TYPE is SOCK_DGRAM");

	close(fd);
}

/*
 * Test SO_ERROR on Unix domain sockets (read-only)
 */
T_DECL(unix_so_error_stream, "SO_ERROR on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int error = 0;
	socklen_t optlen = sizeof(error);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen),
		"getsockopt SO_ERROR");

	T_EXPECT_EQ(error, 0, "SO_ERROR initially 0");

	close(fd);
}

/*
 * Test SO_NREAD on Unix domain sockets (read-only)
 */
T_DECL(unix_so_nread_stream, "SO_NREAD on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int nread = 0;
	socklen_t optlen = sizeof(nread);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NREAD, &nread, &optlen),
		"getsockopt SO_NREAD");

	T_EXPECT_EQ(nread, 0, "SO_NREAD initially 0 (no data buffered)");

	close(fd);
}

/*
 * Test SO_NWRITE on Unix domain sockets (read-only)
 */
T_DECL(unix_so_nwrite_stream, "SO_NWRITE on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	int nwrite = 0;
	socklen_t optlen = sizeof(nwrite);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NWRITE, &nwrite, &optlen),
		"getsockopt SO_NWRITE");

	T_EXPECT_EQ(nwrite, 0, "SO_NWRITE initially 0 (no pending data)");

	close(fd);
}

/*
 * Test multiple socket options on same Unix domain socket
 */
T_DECL(unix_multiple_options_stream, "Multiple options on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	/* Set multiple options */
	int reuseaddr = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)),
		"setsockopt SO_REUSEADDR");

	int nosigpipe = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe)),
		"setsockopt SO_NOSIGPIPE");

	int sndbuf = 8192;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)),
		"setsockopt SO_SNDBUF");

	struct linger linger_val = { .l_onoff = 1, .l_linger = 5 };
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger_val, sizeof(linger_val)),
		"setsockopt SO_LINGER");

	/* Verify all options */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &getval, &optlen),
		"getsockopt SO_REUSEADDR");
	T_EXPECT_NE(getval, 0, "SO_REUSEADDR still enabled (got %d)", getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &getval, &optlen),
		"getsockopt SO_NOSIGPIPE");
	T_EXPECT_NE(getval, 0, "SO_NOSIGPIPE still enabled (got %d)", getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &getval, &optlen),
		"getsockopt SO_SNDBUF");
	T_EXPECT_GE(getval, sndbuf, "SO_SNDBUF >= requested (got %d)", getval);

	struct linger get_linger = {0};
	optlen = sizeof(get_linger);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, SOL_SOCKET, SO_LINGER, &get_linger, &optlen),
		"getsockopt SO_LINGER");
	T_EXPECT_EQ(get_linger.l_onoff, 1, "SO_LINGER still enabled");
	T_EXPECT_EQ(get_linger.l_linger, 5, "SO_LINGER value still 5");

	close(fd);
}

/*
 * Test options on bound Unix domain socket
 */
T_DECL(unix_options_bound_socket, "Options work on bound AF_UNIX socket")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	/* Create temporary socket path */
	char path[108];
	snprintf(path, sizeof(path), "/tmp/sockopt_unix_test.%d", getpid());

	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

	/* Remove any existing socket file */
	unlink(path);

	T_ASSERT_POSIX_SUCCESS(
		bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"bind to %s", path);

	/* Options should still work after binding */
	test_unix_bool_option(fd, SO_REUSEADDR, "SO_REUSEADDR", 1, true);
	test_unix_bool_option(fd, SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);

	close(fd);
	unlink(path);
}

/*
 * Test options on connected Unix domain socket pair
 */
T_DECL(unix_options_socketpair, "Options work on socketpair")
{
	int sv[2];
	T_ASSERT_POSIX_SUCCESS(
		socketpair(AF_UNIX, SOCK_STREAM, 0, sv),
		"socketpair(AF_UNIX, SOCK_STREAM)");

	/* Test options on both sides */
	test_unix_bool_option(sv[0], SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);
	test_unix_bool_option(sv[1], SO_NOSIGPIPE, "SO_NOSIGPIPE", 1, true);

	int sndbuf = 4096;
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)),
		"setsockopt SO_SNDBUF on sv[0]");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &getval, &optlen),
		"getsockopt SO_SNDBUF on sv[0]");

	T_EXPECT_GE(getval, sndbuf, "SO_SNDBUF >= requested");

	close(sv[0]);
	close(sv[1]);
}

/*
 * Test SO_DEBUG on Unix domain sockets
 */
T_DECL(unix_so_debug_stream, "SO_DEBUG on AF_UNIX STREAM")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

	test_unix_bool_option(fd, SO_DEBUG, "SO_DEBUG", 1, true);
	test_unix_bool_option(fd, SO_DEBUG, "SO_DEBUG", 0, false);

	close(fd);
}

/*
 * Test SO_USELOOPBACK on Unix domain sockets
 */
T_DECL(unix_so_useloopback_dgram, "SO_USELOOPBACK on AF_UNIX DGRAM")
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_DGRAM)");

	test_unix_bool_option(fd, SO_USELOOPBACK, "SO_USELOOPBACK", 1, true);
	test_unix_bool_option(fd, SO_USELOOPBACK, "SO_USELOOPBACK", 0, false);

	close(fd);
}

/*
 * Test invalid option lengths on Unix domain sockets
 */
T_DECL(unix_so_reuseaddr_invalid_optlen, "SO_REUSEADDR with invalid optlen")
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_UNIX, SOCK_STREAM)");

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
