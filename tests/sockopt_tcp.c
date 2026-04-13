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
 * sockopt_tcp.c
 *
 * Tests for IPPROTO_TCP level socket options.
 * Tests TCP-specific options like TCP_NODELAY, TCP_KEEPALIVE, TCP_MAXSEG,
 * TCP_CONNECTIONTIMEOUT, TCP_NOOPT, TCP_NOPUSH, etc.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp_private.h>
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
 * Helper to test basic integer TCP option round-trip
 */
static void
test_tcp_int_option_roundtrip(int fd, int optname, const char *optname_str,
    int setval, int expected_getval)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, optname, &getval, &optlen),
		"getsockopt %s", optname_str);

	T_EXPECT_EQ(getval, expected_getval,
	    "%s value matches (expected %d, got %d)",
	    optname_str, expected_getval, getval);
}

/*
 * Helper to test boolean TCP options
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_tcp_bool_option(int fd, int optname, const char *optname_str,
    int setval, bool expect_enabled)
{
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, optname, &setval, sizeof(setval)),
		"setsockopt %s = %d", optname_str, setval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, optname, &getval, &optlen),
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
 * Test TCP_NODELAY - Disable Nagle's algorithm
 */
T_DECL(tcp_nodelay_inet, "TCP_NODELAY on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NODELAY, "TCP_NODELAY", 1, true);
	test_tcp_bool_option(fd, TCP_NODELAY, "TCP_NODELAY", 0, false);

	close(fd);
}

T_DECL(tcp_nodelay_inet6, "TCP_NODELAY on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NODELAY, "TCP_NODELAY", 1, true);
	test_tcp_bool_option(fd, TCP_NODELAY, "TCP_NODELAY", 0, false);

	close(fd);
}

/*
 * Test TCP_MAXSEG - Maximum segment size (read-only after connection)
 */
T_DECL(tcp_maxseg_readonly, "TCP_MAXSEG is readable")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int mss = 0;
	socklen_t optlen = sizeof(mss);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &optlen),
		"getsockopt TCP_MAXSEG");

	T_EXPECT_GT(mss, 0, "TCP_MAXSEG > 0 (got %d)", mss);
	T_LOG("TCP_MAXSEG: %d", mss);

	close(fd);
}

/*
 * Test TCP_NOOPT - Disable TCP options
 */
T_DECL(tcp_noopt_inet, "TCP_NOOPT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NOOPT, "TCP_NOOPT", 1, true);
	test_tcp_bool_option(fd, TCP_NOOPT, "TCP_NOOPT", 0, false);

	close(fd);
}

/*
 * Test TCP_NOPUSH - Don't push last partial segment
 */
T_DECL(tcp_nopush_inet, "TCP_NOPUSH on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NOPUSH, "TCP_NOPUSH", 1, true);
	test_tcp_bool_option(fd, TCP_NOPUSH, "TCP_NOPUSH", 0, false);

	close(fd);
}

/*
 * Test TCP_KEEPALIVE - Keepalive idle time in seconds
 */
T_DECL(tcp_keepalive_inet, "TCP_KEEPALIVE on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Enable SO_KEEPALIVE first */
	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)),
		"setsockopt SO_KEEPALIVE");

	/* Set TCP_KEEPALIVE to 60 seconds */
	test_tcp_int_option_roundtrip(fd, TCP_KEEPALIVE, "TCP_KEEPALIVE", 60, 60);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPALIVE, "TCP_KEEPALIVE", 120, 120);

	close(fd);
}

T_DECL(tcp_keepalive_inet6, "TCP_KEEPALIVE on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	int enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)),
		"setsockopt SO_KEEPALIVE");

	test_tcp_int_option_roundtrip(fd, TCP_KEEPALIVE, "TCP_KEEPALIVE", 30, 30);

	close(fd);
}

/*
 * Test TCP_KEEPINTVL - Keepalive probe interval
 */
T_DECL(tcp_keepintvl_inet, "TCP_KEEPINTVL on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_KEEPINTVL, "TCP_KEEPINTVL", 10, 10);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPINTVL, "TCP_KEEPINTVL", 30, 30);

	close(fd);
}

/*
 * Test TCP_KEEPCNT - Keepalive probe count
 */
T_DECL(tcp_keepcnt_inet, "TCP_KEEPCNT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_KEEPCNT, "TCP_KEEPCNT", 5, 5);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPCNT, "TCP_KEEPCNT", 10, 10);

	close(fd);
}

/*
 * Test TCP_CONNECTIONTIMEOUT - Connection timeout
 */
T_DECL(tcp_connectiontimeout_inet, "TCP_CONNECTIONTIMEOUT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set timeout to 30 seconds */
	test_tcp_int_option_roundtrip(fd, TCP_CONNECTIONTIMEOUT,
	    "TCP_CONNECTIONTIMEOUT", 30, 30);

	close(fd);
}

T_DECL(tcp_connectiontimeout_inet6, "TCP_CONNECTIONTIMEOUT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_CONNECTIONTIMEOUT,
	    "TCP_CONNECTIONTIMEOUT", 60, 60);

	close(fd);
}

/*
 * Test TCP_RXT_CONNDROPTIME - Retransmit timeout for connection drop
 */
T_DECL(tcp_rxt_conndroptime_inet, "TCP_RXT_CONNDROPTIME on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set to 60 seconds */
	test_tcp_int_option_roundtrip(fd, TCP_RXT_CONNDROPTIME,
	    "TCP_RXT_CONNDROPTIME", 60, 60);

	close(fd);
}

/*
 * Test TCP_RXT_FINDROP - Enable/disable FIN drop behavior
 */
T_DECL(tcp_rxt_findrop_inet, "TCP_RXT_FINDROP on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_RXT_FINDROP, "TCP_RXT_FINDROP", 1, true);
	test_tcp_bool_option(fd, TCP_RXT_FINDROP, "TCP_RXT_FINDROP", 0, false);

	close(fd);
}

/*
 * Test TCP_SENDMOREACKS - Send more ACKs
 */
T_DECL(tcp_sendmoreacks_inet, "TCP_SENDMOREACKS on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_SENDMOREACKS, "TCP_SENDMOREACKS", 1, true);
	test_tcp_bool_option(fd, TCP_SENDMOREACKS, "TCP_SENDMOREACKS", 0, false);

	close(fd);
}

/*
 * Test TCP_ENABLE_ECN - Enable Explicit Congestion Notification
 */
T_DECL(tcp_enable_ecn_inet, "TCP_ENABLE_ECN on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_ENABLE_ECN, "TCP_ENABLE_ECN", 1, true);
	test_tcp_bool_option(fd, TCP_ENABLE_ECN, "TCP_ENABLE_ECN", 0, false);

	close(fd);
}

/*
 * Test TCP_FASTOPEN - Enable TCP Fast Open
 * Note: TCP_FASTOPEN requires socket to be in LISTEN state
 */
T_DECL(tcp_fastopen_inet, "TCP_FASTOPEN on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Bind and listen to make socket eligible for TCP_FASTOPEN */
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0, /* Let kernel choose port */
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};

	T_ASSERT_POSIX_SUCCESS(
		bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
		"bind to localhost");

	T_ASSERT_POSIX_SUCCESS(
		listen(fd, 5),
		"listen");

	/* Now TCP_FASTOPEN should work (if system supports it) */
	int enable = 1;
	int ret = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable));
	if (ret == -1) {
		if (errno == ENOTSUP) {
			T_LOG("TCP_FASTOPEN not supported on this system (server mode disabled)");
		} else {
			T_ASSERT_POSIX_SUCCESS(ret, "setsockopt TCP_FASTOPEN = 1");
		}
	} else {
		T_LOG("TCP_FASTOPEN enabled successfully");

		/* Verify it's enabled */
		int getval = 0;
		socklen_t optlen = sizeof(getval);
		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &getval, &optlen),
			"getsockopt TCP_FASTOPEN");
		T_EXPECT_NE(getval, 0, "TCP_FASTOPEN is enabled (got %d)", getval);

		/* Disable it */
		int disable = 0;
		T_ASSERT_POSIX_SUCCESS(
			setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &disable, sizeof(disable)),
			"setsockopt TCP_FASTOPEN = 0");

		T_ASSERT_POSIX_SUCCESS(
			getsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &getval, &optlen),
			"getsockopt TCP_FASTOPEN");
		T_EXPECT_EQ(getval, 0, "TCP_FASTOPEN is disabled");
	}

	close(fd);
}

T_DECL(tcp_fastopen_not_listening, "TCP_FASTOPEN fails on non-listening socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Try to enable TCP_FASTOPEN without listen() */
	int enable = 1;
	int ret = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable));

	T_ASSERT_EQ(ret, -1, "TCP_FASTOPEN should fail on non-listening socket");
	T_EXPECT_TRUE(errno == EINVAL || errno == ENOTSUP,
	    "errno should be EINVAL or ENOTSUP (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

/*
 * Test TCP_NOTSENT_LOWAT - Unsent data low water mark
 */
T_DECL(tcp_notsent_lowat_inet, "TCP_NOTSENT_LOWAT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_NOTSENT_LOWAT,
	    "TCP_NOTSENT_LOWAT", 4096, 4096);
	test_tcp_int_option_roundtrip(fd, TCP_NOTSENT_LOWAT,
	    "TCP_NOTSENT_LOWAT", 8192, 8192);

	close(fd);
}

/*
 * Test TCP_CONNECTION_INFO - Get connection information (read-only)
 */
T_DECL(tcp_connection_info_readonly, "TCP_CONNECTION_INFO is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct tcp_connection_info conninfo = {0};
	socklen_t optlen = sizeof(conninfo);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &conninfo, &optlen),
		"getsockopt TCP_CONNECTION_INFO");

	T_LOG("TCP connection state: %u", conninfo.tcpi_state);
	T_LOG("TCP options: 0x%x", conninfo.tcpi_options);

	/* Try to set TCP_CONNECTION_INFO (should fail) */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO,
		&conninfo, sizeof(conninfo)),
		ENOPROTOOPT,
		"setsockopt TCP_CONNECTION_INFO should fail");

	close(fd);
}

/*
 * Test multiple TCP options can be set on the same socket
 */
T_DECL(tcp_multiple_options, "Multiple TCP options on same socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set multiple options */
	int nodelay = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)),
		"setsockopt TCP_NODELAY");

	int nopush = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &nopush, sizeof(nopush)),
		"setsockopt TCP_NOPUSH");

	int keepalive = 60;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &keepalive, sizeof(keepalive)),
		"setsockopt TCP_KEEPALIVE");

	/* Verify all options are set correctly */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	/* TCP_NODELAY and TCP_NOPUSH are boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &getval, &optlen),
		"getsockopt TCP_NODELAY");
	T_EXPECT_NE(getval, 0, "TCP_NODELAY still enabled (got %d)", getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &getval, &optlen),
		"getsockopt TCP_NOPUSH");
	T_EXPECT_NE(getval, 0, "TCP_NOPUSH still enabled (got %d)", getval);

	/* TCP_KEEPALIVE is integer value - check exact value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &getval, &optlen),
		"getsockopt TCP_KEEPALIVE");
	T_EXPECT_EQ(getval, 60, "TCP_KEEPALIVE still 60");

	close(fd);
}

/*
 * Test TCP options on unconnected socket
 */
T_DECL(tcp_options_unconnected, "TCP options work on unconnected socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* These should all work on unconnected socket */
	test_tcp_bool_option(fd, TCP_NODELAY, "TCP_NODELAY", 1, true);
	test_tcp_bool_option(fd, TCP_NOOPT, "TCP_NOOPT", 1, true);
	test_tcp_bool_option(fd, TCP_NOPUSH, "TCP_NOPUSH", 1, true);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPALIVE, "TCP_KEEPALIVE", 30, 30);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPINTVL, "TCP_KEEPINTVL", 15, 15);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPCNT, "TCP_KEEPCNT", 8, 8);

	close(fd);
}

/*
 * Test invalid TCP option values
 */
T_DECL(tcp_keepalive_negative, "TCP_KEEPALIVE rejects negative values")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int negative = -1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &negative, sizeof(negative)),
		EINVAL,
		"TCP_KEEPALIVE should reject negative value");

	close(fd);
}

/*
 * Test TCP option invalid lengths
 */
T_DECL(tcp_nodelay_invalid_optlen, "TCP_NODELAY with invalid optlen")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Too small */
	char smallval = 1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &smallval, sizeof(smallval)),
		EINVAL,
		"setsockopt TCP_NODELAY with too small optlen should fail");

	/* NULL pointer with non-zero length */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, NULL, sizeof(int)),
		EFAULT,
		"setsockopt TCP_NODELAY with NULL optval should fail");

	close(fd);
}

/*
 * Private TCP Options Tests
 * Testing options from netinet/tcp_private.h
 */

/*
 * Test TCP_INFO - Read-only option that returns tcp_info structure
 */
T_DECL(tcp_info_readonly, "TCP_INFO is read-only")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct tcp_info info = {0};
	socklen_t optlen = sizeof(info);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &optlen),
		"getsockopt TCP_INFO");

	T_LOG("TCP_INFO state: %u, options: 0x%x, snd_mss: %u, rcv_mss: %u",
	    info.tcpi_state, info.tcpi_options, info.tcpi_snd_mss, info.tcpi_rcv_mss);

	/* Try to set TCP_INFO (should fail) */
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, sizeof(info)),
		ENOPROTOOPT,
		"setsockopt TCP_INFO should fail (read-only option)");

	close(fd);
}

T_DECL(tcp_info_inet6, "TCP_INFO on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	struct tcp_info info = {0};
	socklen_t optlen = sizeof(info);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &optlen),
		"getsockopt TCP_INFO");

	T_EXPECT_GE(optlen, (socklen_t)sizeof(struct tcp_info), "optlen >= sizeof(tcp_info)");

	close(fd);
}

/*
 * Test TCP_MEASURE_SND_BW - Measure sender's bandwidth
 */
T_DECL(tcp_measure_snd_bw_inet, "TCP_MEASURE_SND_BW on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_MEASURE_SND_BW, "TCP_MEASURE_SND_BW", 1, true);
	test_tcp_bool_option(fd, TCP_MEASURE_SND_BW, "TCP_MEASURE_SND_BW", 0, false);

	close(fd);
}

/*
 * Test TCP_MEASURE_BW_BURST - Burst size for bandwidth measurement
 */
T_DECL(tcp_measure_bw_burst_inet, "TCP_MEASURE_BW_BURST on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	struct tcp_measure_bw_burst burst = {
		.min_burst_size = 4,
		.max_burst_size = 16
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_MEASURE_BW_BURST,
		&burst, sizeof(burst)),
		"setsockopt TCP_MEASURE_BW_BURST");

	struct tcp_measure_bw_burst get_burst = {0};
	socklen_t optlen = sizeof(get_burst);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_MEASURE_BW_BURST,
		&get_burst, &optlen),
		"getsockopt TCP_MEASURE_BW_BURST");

	T_EXPECT_EQ(get_burst.min_burst_size, burst.min_burst_size,
	    "min_burst_size matches");
	T_EXPECT_EQ(get_burst.max_burst_size, burst.max_burst_size,
	    "max_burst_size matches");

	close(fd);
}

/*
 * Test TCP_PEER_PID - Lookup pid of connected process (read-only)
 */
T_DECL(tcp_peer_pid_unconnected, "TCP_PEER_PID on unconnected socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	pid_t peer_pid = 0;
	socklen_t optlen = sizeof(peer_pid);

	/* On unconnected socket, should return 0 or fail */
	int ret = getsockopt(fd, IPPROTO_TCP, TCP_PEER_PID, &peer_pid, &optlen);
	if (ret == 0) {
		T_LOG("TCP_PEER_PID on unconnected socket: %d", peer_pid);
		T_EXPECT_EQ(peer_pid, 0, "peer_pid should be 0 on unconnected socket");
	} else {
		T_LOG("getsockopt TCP_PEER_PID failed (expected on unconnected): %d (%s)",
		    errno, strerror(errno));
	}

	/* Try to set TCP_PEER_PID (should fail - read-only) */
	peer_pid = 1234;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_PEER_PID, &peer_pid, sizeof(peer_pid)),
		ENOPROTOOPT,
		"setsockopt TCP_PEER_PID should fail (read-only option)");

	close(fd);
}

/*
 * Test TCP_ADAPTIVE_READ_TIMEOUT - Read timeout as multiple of RTT
 */
T_DECL(tcp_adaptive_read_timeout_inet, "TCP_ADAPTIVE_READ_TIMEOUT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set timeout to 5 RTTs */
	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_READ_TIMEOUT,
	    "TCP_ADAPTIVE_READ_TIMEOUT", 5, 5);

	/* Set to 0 to disable */
	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_READ_TIMEOUT,
	    "TCP_ADAPTIVE_READ_TIMEOUT", 0, 0);

	close(fd);
}

/*
 * Test TCP_ADAPTIVE_WRITE_TIMEOUT - Write timeout as multiple of RTT
 */
T_DECL(tcp_adaptive_write_timeout_inet, "TCP_ADAPTIVE_WRITE_TIMEOUT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set timeout to 10 RTTs */
	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_WRITE_TIMEOUT,
	    "TCP_ADAPTIVE_WRITE_TIMEOUT", 10, 10);

	/* Set to 0 to disable */
	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_WRITE_TIMEOUT,
	    "TCP_ADAPTIVE_WRITE_TIMEOUT", 0, 0);

	close(fd);
}

/*
 * Test TCP_NOTIMEWAIT - Avoid TIME_WAIT state
 */
T_DECL(tcp_notimewait_inet, "TCP_NOTIMEWAIT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NOTIMEWAIT, "TCP_NOTIMEWAIT", 1, true);
	test_tcp_bool_option(fd, TCP_NOTIMEWAIT, "TCP_NOTIMEWAIT", 0, false);

	close(fd);
}

T_DECL(tcp_notimewait_inet6, "TCP_NOTIMEWAIT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NOTIMEWAIT, "TCP_NOTIMEWAIT", 1, true);
	test_tcp_bool_option(fd, TCP_NOTIMEWAIT, "TCP_NOTIMEWAIT", 0, false);

	close(fd);
}

/*
 * Test TCP_DISABLE_BLACKHOLE_DETECTION - Disable PMTU blackhole detection
 */
T_DECL(tcp_disable_blackhole_detection_inet, "TCP_DISABLE_BLACKHOLE_DETECTION on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_DISABLE_BLACKHOLE_DETECTION,
	    "TCP_DISABLE_BLACKHOLE_DETECTION", 1, true);
	test_tcp_bool_option(fd, TCP_DISABLE_BLACKHOLE_DETECTION,
	    "TCP_DISABLE_BLACKHOLE_DETECTION", 0, false);

	close(fd);
}

/*
 * Test TCP_ECN_MODE - Fine grain ECN control
 */
T_DECL(tcp_ecn_mode_inet, "TCP_ECN_MODE on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test different ECN modes */
	test_tcp_int_option_roundtrip(fd, TCP_ECN_MODE, "TCP_ECN_MODE",
	    ECN_MODE_DEFAULT, ECN_MODE_DEFAULT);
	test_tcp_int_option_roundtrip(fd, TCP_ECN_MODE, "TCP_ECN_MODE",
	    ECN_MODE_ENABLE, ECN_MODE_ENABLE);
	test_tcp_int_option_roundtrip(fd, TCP_ECN_MODE, "TCP_ECN_MODE",
	    ECN_MODE_DISABLE, ECN_MODE_DISABLE);

	close(fd);
}

T_DECL(tcp_ecn_mode_inet6, "TCP_ECN_MODE on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_ECN_MODE, "TCP_ECN_MODE",
	    ECN_MODE_ENABLE, ECN_MODE_ENABLE);

	close(fd);
}

/*
 * Test TCP_KEEPALIVE_OFFLOAD - Offload keepalive to firmware
 * Note: Requires com.apple.developer.networking.tcp_ka_offload entitlement (iOS only)
 */
#if TARGET_OS_OSX
T_DECL(tcp_keepalive_offload_inet, "TCP_KEEPALIVE_OFFLOAD on AF_INET (macOS)",
    T_META_ENABLED(TARGET_OS_OSX))
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	T_MAYFAIL;
	test_tcp_bool_option(fd, TCP_KEEPALIVE_OFFLOAD, "TCP_KEEPALIVE_OFFLOAD", 1, true);

	T_MAYFAIL;
	test_tcp_bool_option(fd, TCP_KEEPALIVE_OFFLOAD, "TCP_KEEPALIVE_OFFLOAD", 0, false);

	close(fd);
}
#else
T_DECL(tcp_keepalive_offload_inet, "TCP_KEEPALIVE_OFFLOAD on AF_INET (iOS)",
    T_META_ENABLED(!TARGET_OS_OSX))
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* On macOS, PRIV_NETINET_TCP_KA_OFFLOAD is not available, so setting should fail with EPERM */
	int enable = 1;
	int ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE_OFFLOAD, &enable, sizeof(enable));
	T_ASSERT_EQ(ret, -1, "TCP_KEEPALIVE_OFFLOAD should fail on macOS");
	T_EXPECT_EQ(errno, EPERM, "errno should be EPERM (got %d: %s)", errno, strerror(errno));

	/* getsockopt should still work and return disabled state */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE_OFFLOAD, &getval, &optlen),
		"getsockopt TCP_KEEPALIVE_OFFLOAD");
	T_EXPECT_EQ(getval, 0, "TCP_KEEPALIVE_OFFLOAD is disabled (got %d)", getval);

	close(fd);
}
#endif

/*
 * Test TCP_NOTIFY_ACKNOWLEDGEMENT - Notify when data is acknowledged
 * Note: Requires socket to have data in send buffer (ENOBUFS otherwise)
 */
T_DECL(tcp_notify_acknowledgement_no_data, "TCP_NOTIFY_ACKNOWLEDGEMENT requires send data")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Try to set a marker ID without any send data - should fail with ENOBUFS */
	tcp_notify_ack_id_t marker_id = 12345;
	int ret = setsockopt(fd, IPPROTO_TCP, TCP_NOTIFY_ACKNOWLEDGEMENT,
	    &marker_id, sizeof(marker_id));

	T_ASSERT_EQ(ret, -1, "TCP_NOTIFY_ACKNOWLEDGEMENT should fail without send data");
	T_EXPECT_EQ(errno, ENOBUFS, "errno should be ENOBUFS (got %d: %s)",
	    errno, strerror(errno));

	close(fd);
}

T_DECL(tcp_notify_acknowledgement_get, "TCP_NOTIFY_ACKNOWLEDGEMENT can be queried")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Query for completed notifications on unconnected socket */
	struct tcp_notify_ack_complete complete = {0};
	socklen_t optlen = sizeof(complete);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_NOTIFY_ACKNOWLEDGEMENT,
		&complete, &optlen),
		"getsockopt TCP_NOTIFY_ACKNOWLEDGEMENT");

	T_LOG("notify_pending: %u, notify_complete_count: %u",
	    complete.notify_pending, complete.notify_complete_count);

	/* Should have no pending or completed notifications */
	T_EXPECT_EQ(complete.notify_pending, 0U, "No pending notifications");
	T_EXPECT_EQ(complete.notify_complete_count, 0U, "No completed notifications");

	close(fd);
}

/*
 * Test TCP_RXT_MINIMUM_TIMEOUT - Minimum retransmit timeout
 */
T_DECL(tcp_rxt_minimum_timeout_inet, "TCP_RXT_MINIMUM_TIMEOUT on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set timeout to 30 seconds */
	test_tcp_int_option_roundtrip(fd, TCP_RXT_MINIMUM_TIMEOUT,
	    "TCP_RXT_MINIMUM_TIMEOUT", 30, 30);

	/* Test maximum allowed value (5 minutes) */
	test_tcp_int_option_roundtrip(fd, TCP_RXT_MINIMUM_TIMEOUT,
	    "TCP_RXT_MINIMUM_TIMEOUT", TCP_RXT_MINIMUM_TIMEOUT_LIMIT,
	    TCP_RXT_MINIMUM_TIMEOUT_LIMIT);

	close(fd);
}

T_DECL(tcp_rxt_minimum_timeout_invalid, "TCP_RXT_MINIMUM_TIMEOUT value handling")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Test value exceeding limit - should be clamped to limit */
	int toolarge = TCP_RXT_MINIMUM_TIMEOUT_LIMIT + 100;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_RXT_MINIMUM_TIMEOUT,
		&toolarge, sizeof(toolarge)),
		"setsockopt TCP_RXT_MINIMUM_TIMEOUT with value > limit");

	/* Verify it was clamped to the limit */
	int getval = 0;
	socklen_t optlen = sizeof(getval);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_RXT_MINIMUM_TIMEOUT, &getval, &optlen),
		"getsockopt TCP_RXT_MINIMUM_TIMEOUT");
	T_EXPECT_EQ(getval, TCP_RXT_MINIMUM_TIMEOUT_LIMIT,
	    "Value clamped to limit (set %d, got %d, limit %d)",
	    toolarge, getval, TCP_RXT_MINIMUM_TIMEOUT_LIMIT);

	/* Test negative value - should fail */
	int negative = -1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, TCP_RXT_MINIMUM_TIMEOUT,
		&negative, sizeof(negative)),
		EINVAL,
		"TCP_RXT_MINIMUM_TIMEOUT should reject negative value");

	close(fd);
}

/*
 * Test TCP_FASTOPEN_FORCE_ENABLE - Force enable TCP Fast Open
 */
T_DECL(tcp_fastopen_force_enable_inet, "TCP_FASTOPEN_FORCE_ENABLE on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_FASTOPEN_FORCE_ENABLE,
	    "TCP_FASTOPEN_FORCE_ENABLE", 1, true);
	test_tcp_bool_option(fd, TCP_FASTOPEN_FORCE_ENABLE,
	    "TCP_FASTOPEN_FORCE_ENABLE", 0, false);

	close(fd);
}

/*
 * Test TCP_ENABLE_L4S - Enable L4S (Low Latency, Low Loss, Scalable throughput)
 */
T_DECL(tcp_enable_l4s_inet, "TCP_ENABLE_L4S on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_ENABLE_L4S, "TCP_ENABLE_L4S", 1, true);
	test_tcp_bool_option(fd, TCP_ENABLE_L4S, "TCP_ENABLE_L4S", 0, false);

	close(fd);
}

T_DECL(tcp_enable_l4s_inet6, "TCP_ENABLE_L4S on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_ENABLE_L4S, "TCP_ENABLE_L4S", 1, true);
	test_tcp_bool_option(fd, TCP_ENABLE_L4S, "TCP_ENABLE_L4S", 0, false);

	close(fd);
}

/*
 * Test multiple private TCP options on same socket
 */
T_DECL(tcp_private_multiple_options, "Multiple private TCP options on same socket")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	/* Set multiple options */
	int notimewait = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_NOTIMEWAIT, &notimewait, sizeof(notimewait)),
		"setsockopt TCP_NOTIMEWAIT");

	int ecn_mode = ECN_MODE_ENABLE;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_ECN_MODE, &ecn_mode, sizeof(ecn_mode)),
		"setsockopt TCP_ECN_MODE");

	int adaptive_read_timeout = 5;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_ADAPTIVE_READ_TIMEOUT,
		&adaptive_read_timeout, sizeof(adaptive_read_timeout)),
		"setsockopt TCP_ADAPTIVE_READ_TIMEOUT");

	int measure_bw = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_MEASURE_SND_BW, &measure_bw, sizeof(measure_bw)),
		"setsockopt TCP_MEASURE_SND_BW");

	/* Verify all options are still set */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	/* TCP_NOTIMEWAIT is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_NOTIMEWAIT, &getval, &optlen),
		"getsockopt TCP_NOTIMEWAIT");
	T_EXPECT_NE(getval, 0, "TCP_NOTIMEWAIT still enabled (got %d)", getval);

	/* TCP_ECN_MODE is integer value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_ECN_MODE, &getval, &optlen),
		"getsockopt TCP_ECN_MODE");
	T_EXPECT_EQ(getval, ECN_MODE_ENABLE, "TCP_ECN_MODE still set");

	/* TCP_ADAPTIVE_READ_TIMEOUT is integer value */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_ADAPTIVE_READ_TIMEOUT, &getval, &optlen),
		"getsockopt TCP_ADAPTIVE_READ_TIMEOUT");
	T_EXPECT_EQ(getval, 5, "TCP_ADAPTIVE_READ_TIMEOUT still set");

	/* TCP_MEASURE_SND_BW is boolean - check for non-zero */
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_MEASURE_SND_BW, &getval, &optlen),
		"getsockopt TCP_MEASURE_SND_BW");
	T_EXPECT_NE(getval, 0, "TCP_MEASURE_SND_BW still enabled (got %d)", getval);

	close(fd);
}

/*
 * Additional AF_INET6 coverage for TCP private options
 * Testing options that were previously only tested on AF_INET
 */

T_DECL(tcp_measure_snd_bw_inet6, "TCP_MEASURE_SND_BW on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_MEASURE_SND_BW, "TCP_MEASURE_SND_BW", 1, true);
	test_tcp_bool_option(fd, TCP_MEASURE_SND_BW, "TCP_MEASURE_SND_BW", 0, false);

	close(fd);
}

T_DECL(tcp_measure_bw_burst_inet6, "TCP_MEASURE_BW_BURST on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	struct tcp_measure_bw_burst burst = {
		.min_burst_size = 4,
		.max_burst_size = 16
	};

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, TCP_MEASURE_BW_BURST,
		&burst, sizeof(burst)),
		"setsockopt TCP_MEASURE_BW_BURST");

	struct tcp_measure_bw_burst get_burst = {0};
	socklen_t optlen = sizeof(get_burst);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, TCP_MEASURE_BW_BURST,
		&get_burst, &optlen),
		"getsockopt TCP_MEASURE_BW_BURST");

	T_EXPECT_EQ(get_burst.min_burst_size, burst.min_burst_size,
	    "min_burst_size matches");
	T_EXPECT_EQ(get_burst.max_burst_size, burst.max_burst_size,
	    "max_burst_size matches");

	close(fd);
}

T_DECL(tcp_adaptive_read_timeout_inet6, "TCP_ADAPTIVE_READ_TIMEOUT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_READ_TIMEOUT,
	    "TCP_ADAPTIVE_READ_TIMEOUT", 5, 5);
	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_READ_TIMEOUT,
	    "TCP_ADAPTIVE_READ_TIMEOUT", 0, 0);

	close(fd);
}

T_DECL(tcp_adaptive_write_timeout_inet6, "TCP_ADAPTIVE_WRITE_TIMEOUT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_WRITE_TIMEOUT,
	    "TCP_ADAPTIVE_WRITE_TIMEOUT", 10, 10);
	test_tcp_int_option_roundtrip(fd, TCP_ADAPTIVE_WRITE_TIMEOUT,
	    "TCP_ADAPTIVE_WRITE_TIMEOUT", 0, 0);

	close(fd);
}

T_DECL(tcp_disable_blackhole_detection_inet6, "TCP_DISABLE_BLACKHOLE_DETECTION on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_DISABLE_BLACKHOLE_DETECTION,
	    "TCP_DISABLE_BLACKHOLE_DETECTION", 1, true);
	test_tcp_bool_option(fd, TCP_DISABLE_BLACKHOLE_DETECTION,
	    "TCP_DISABLE_BLACKHOLE_DETECTION", 0, false);

	close(fd);
}

T_DECL(tcp_fastopen_force_enable_inet6, "TCP_FASTOPEN_FORCE_ENABLE on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_FASTOPEN_FORCE_ENABLE,
	    "TCP_FASTOPEN_FORCE_ENABLE", 1, true);
	test_tcp_bool_option(fd, TCP_FASTOPEN_FORCE_ENABLE,
	    "TCP_FASTOPEN_FORCE_ENABLE", 0, false);

	close(fd);
}

T_DECL(tcp_rxt_minimum_timeout_inet6, "TCP_RXT_MINIMUM_TIMEOUT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_RXT_MINIMUM_TIMEOUT,
	    "TCP_RXT_MINIMUM_TIMEOUT", 30, 30);
	test_tcp_int_option_roundtrip(fd, TCP_RXT_MINIMUM_TIMEOUT,
	    "TCP_RXT_MINIMUM_TIMEOUT", TCP_RXT_MINIMUM_TIMEOUT_LIMIT,
	    TCP_RXT_MINIMUM_TIMEOUT_LIMIT);

	close(fd);
}

T_DECL(tcp_noopt_inet6, "TCP_NOOPT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NOOPT, "TCP_NOOPT", 1, true);
	test_tcp_bool_option(fd, TCP_NOOPT, "TCP_NOOPT", 0, false);

	close(fd);
}

T_DECL(tcp_nopush_inet6, "TCP_NOPUSH on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_NOPUSH, "TCP_NOPUSH", 1, true);
	test_tcp_bool_option(fd, TCP_NOPUSH, "TCP_NOPUSH", 0, false);

	close(fd);
}

T_DECL(tcp_keepintvl_inet6, "TCP_KEEPINTVL on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_KEEPINTVL, "TCP_KEEPINTVL", 10, 10);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPINTVL, "TCP_KEEPINTVL", 30, 30);

	close(fd);
}

T_DECL(tcp_keepcnt_inet6, "TCP_KEEPCNT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_KEEPCNT, "TCP_KEEPCNT", 5, 5);
	test_tcp_int_option_roundtrip(fd, TCP_KEEPCNT, "TCP_KEEPCNT", 10, 10);

	close(fd);
}

T_DECL(tcp_rxt_conndroptime_inet6, "TCP_RXT_CONNDROPTIME on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_RXT_CONNDROPTIME,
	    "TCP_RXT_CONNDROPTIME", 60, 60);

	close(fd);
}

T_DECL(tcp_rxt_findrop_inet6, "TCP_RXT_FINDROP on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_RXT_FINDROP, "TCP_RXT_FINDROP", 1, true);
	test_tcp_bool_option(fd, TCP_RXT_FINDROP, "TCP_RXT_FINDROP", 0, false);

	close(fd);
}

T_DECL(tcp_sendmoreacks_inet6, "TCP_SENDMOREACKS on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_SENDMOREACKS, "TCP_SENDMOREACKS", 1, true);
	test_tcp_bool_option(fd, TCP_SENDMOREACKS, "TCP_SENDMOREACKS", 0, false);

	close(fd);
}

T_DECL(tcp_enable_ecn_inet6, "TCP_ENABLE_ECN on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_bool_option(fd, TCP_ENABLE_ECN, "TCP_ENABLE_ECN", 1, true);
	test_tcp_bool_option(fd, TCP_ENABLE_ECN, "TCP_ENABLE_ECN", 0, false);

	close(fd);
}

T_DECL(tcp_notsent_lowat_inet6, "TCP_NOTSENT_LOWAT on AF_INET6")
{
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_STREAM)");

	test_tcp_int_option_roundtrip(fd, TCP_NOTSENT_LOWAT,
	    "TCP_NOTSENT_LOWAT", 4096, 4096);
	test_tcp_int_option_roundtrip(fd, TCP_NOTSENT_LOWAT,
	    "TCP_NOTSENT_LOWAT", 8192, 8192);

	close(fd);
}
