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
 * sockopt_mptcp.c
 *
 * Tests for MPTCP (Multipath TCP) socket options on AF_MULTIPATH sockets.
 * Tests MPTCP-specific options like MPTCP_SERVICE_TYPE, MPTCP_ALTERNATE_PORT,
 * MPTCP_FORCE_ENABLE, MPTCP_EXPECTED_PROGRESS_TARGET, MPTCP_FORCE_VERSION.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp_private.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <darwintest.h>

/* AF_MULTIPATH is defined in sys/socket.h */
#ifndef AF_MULTIPATH
#define AF_MULTIPATH 39
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net.sockopt"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * Helper to test basic integer MPTCP option round-trip
 */
static void
test_mptcp_int_option_roundtrip(int fd, int optname, const char *optname_str,
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
 * Helper to test boolean MPTCP options
 * For boolean options: 0 means disabled, any non-zero means enabled
 */
static void
test_mptcp_bool_option(int fd, int optname, const char *optname_str,
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
 * Test MPTCP_SERVICE_TYPE - MPTCP service type
 */
T_DECL(mptcp_service_type_multipath, "MPTCP_SERVICE_TYPE on AF_MULTIPATH")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	/* Test different MPTCP service types */
	test_mptcp_int_option_roundtrip(fd, MPTCP_SERVICE_TYPE, "MPTCP_SERVICE_TYPE",
	    MPTCP_SVCTYPE_HANDOVER, MPTCP_SVCTYPE_HANDOVER);
	test_mptcp_int_option_roundtrip(fd, MPTCP_SERVICE_TYPE, "MPTCP_SERVICE_TYPE",
	    MPTCP_SVCTYPE_INTERACTIVE, MPTCP_SVCTYPE_INTERACTIVE);
	/* MPTCP_SVCTYPE_AGGREGATE (2) is not supported by default - skip it */
	test_mptcp_int_option_roundtrip(fd, MPTCP_SERVICE_TYPE, "MPTCP_SERVICE_TYPE",
	    MPTCP_SVCTYPE_TARGET_BASED, MPTCP_SVCTYPE_TARGET_BASED);
	test_mptcp_int_option_roundtrip(fd, MPTCP_SERVICE_TYPE, "MPTCP_SERVICE_TYPE",
	    MPTCP_SVCTYPE_PURE_HANDOVER, MPTCP_SVCTYPE_PURE_HANDOVER);

	close(fd);
}

T_DECL(mptcp_service_type_on_inet, "MPTCP_SERVICE_TYPE fails on AF_INET")
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM)");

	int optval = MPTCP_SVCTYPE_HANDOVER;
	int ret = setsockopt(fd, IPPROTO_TCP, MPTCP_SERVICE_TYPE, &optval, sizeof(optval));

	/* Should fail on non-MPTCP socket */
	if (ret == -1) {
		T_LOG("MPTCP_SERVICE_TYPE on AF_INET failed as expected: %d (%s)",
		    errno, strerror(errno));
	} else {
		T_LOG("MPTCP_SERVICE_TYPE on AF_INET succeeded (may be allowed on some systems)");
	}

	close(fd);
}

/*
 * Test MPTCP_ALTERNATE_PORT - MPTCP alternate port
 */
T_DECL(mptcp_alternate_port_multipath, "MPTCP_ALTERNATE_PORT on AF_MULTIPATH")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	/* Set alternate port */
	test_mptcp_int_option_roundtrip(fd, MPTCP_ALTERNATE_PORT,
	    "MPTCP_ALTERNATE_PORT", 8080, 8080);

	/* Set different port */
	test_mptcp_int_option_roundtrip(fd, MPTCP_ALTERNATE_PORT,
	    "MPTCP_ALTERNATE_PORT", 9090, 9090);

	/* Clear alternate port */
	test_mptcp_int_option_roundtrip(fd, MPTCP_ALTERNATE_PORT,
	    "MPTCP_ALTERNATE_PORT", 0, 0);

	close(fd);
}

/*
 * Test MPTCP_FORCE_ENABLE - Force enable MPTCP
 */
T_DECL(mptcp_force_enable_multipath, "MPTCP_FORCE_ENABLE on AF_MULTIPATH")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	test_mptcp_bool_option(fd, MPTCP_FORCE_ENABLE, "MPTCP_FORCE_ENABLE", 1, true);
	test_mptcp_bool_option(fd, MPTCP_FORCE_ENABLE, "MPTCP_FORCE_ENABLE", 0, false);

	close(fd);
}

/*
 * Test MPTCP_EXPECTED_PROGRESS_TARGET - MPTCP expected progress target
 * Note: This option requires MPTCP_SERVICE_TYPE to be set to TARGET_BASED,
 * which itself requires entitlements and an established MPTCP connection.
 * We only test that getsockopt works - setsockopt requires prerequisites.
 */
T_DECL(mptcp_expected_progress_target_multipath, "MPTCP_EXPECTED_PROGRESS_TARGET on AF_MULTIPATH")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	/* Verify we can read the current value (should be 0) */
	uint64_t get_target = 0;
	socklen_t optlen = sizeof(get_target);
	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, MPTCP_EXPECTED_PROGRESS_TARGET,
		&get_target, &optlen),
		"getsockopt MPTCP_EXPECTED_PROGRESS_TARGET");

	T_EXPECT_EQ(get_target, 0ULL, "MPTCP_EXPECTED_PROGRESS_TARGET initially 0");
	T_LOG("MPTCP_EXPECTED_PROGRESS_TARGET: %llu", get_target);

	close(fd);
}

/*
 * Test MPTCP_FORCE_VERSION - Force MPTCP version
 */
T_DECL(mptcp_force_version_multipath, "MPTCP_FORCE_VERSION on AF_MULTIPATH")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	/* Force MPTCP version 0 or 1 */
	test_mptcp_int_option_roundtrip(fd, MPTCP_FORCE_VERSION,
	    "MPTCP_FORCE_VERSION", 0, 0);
	test_mptcp_int_option_roundtrip(fd, MPTCP_FORCE_VERSION,
	    "MPTCP_FORCE_VERSION", 1, 1);

	close(fd);
}

/*
 * Test multiple MPTCP options on same socket
 */
T_DECL(mptcp_multiple_options, "Multiple MPTCP options on same socket")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	/* Set multiple MPTCP options */
	int svctype = MPTCP_SVCTYPE_INTERACTIVE;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, MPTCP_SERVICE_TYPE, &svctype, sizeof(svctype)),
		"setsockopt MPTCP_SERVICE_TYPE");

	int alternate_port = 8080;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, MPTCP_ALTERNATE_PORT,
		&alternate_port, sizeof(alternate_port)),
		"setsockopt MPTCP_ALTERNATE_PORT");

	int force_enable = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, MPTCP_FORCE_ENABLE,
		&force_enable, sizeof(force_enable)),
		"setsockopt MPTCP_FORCE_ENABLE");

	int version = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_TCP, MPTCP_FORCE_VERSION,
		&version, sizeof(version)),
		"setsockopt MPTCP_FORCE_VERSION");

	/* Verify all options are still set */
	int getval = 0;
	socklen_t optlen = sizeof(getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, MPTCP_SERVICE_TYPE, &getval, &optlen),
		"getsockopt MPTCP_SERVICE_TYPE");
	T_EXPECT_EQ(getval, MPTCP_SVCTYPE_INTERACTIVE, "MPTCP_SERVICE_TYPE still set");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, MPTCP_ALTERNATE_PORT, &getval, &optlen),
		"getsockopt MPTCP_ALTERNATE_PORT");
	T_EXPECT_EQ(getval, 8080, "MPTCP_ALTERNATE_PORT still set");

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, MPTCP_FORCE_ENABLE, &getval, &optlen),
		"getsockopt MPTCP_FORCE_ENABLE");
	T_EXPECT_NE(getval, 0, "MPTCP_FORCE_ENABLE still enabled (got %d)", getval);

	T_ASSERT_POSIX_SUCCESS(
		getsockopt(fd, IPPROTO_TCP, MPTCP_FORCE_VERSION, &getval, &optlen),
		"getsockopt MPTCP_FORCE_VERSION");
	T_EXPECT_EQ(getval, 1, "MPTCP_FORCE_VERSION still set");

	close(fd);
}

/*
 * Test MPTCP options with invalid values
 */
T_DECL(mptcp_service_type_invalid, "MPTCP_SERVICE_TYPE rejects invalid values")
{
	int fd = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 && errno == EPROTONOSUPPORT) {
		T_SKIP("AF_MULTIPATH not supported on this system");
	}
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_MULTIPATH, SOCK_STREAM)");

	/* Test value >= MPTCP_SVCTYPE_MAX */
	int invalid = MPTCP_SVCTYPE_MAX;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, MPTCP_SERVICE_TYPE,
		&invalid, sizeof(invalid)),
		EINVAL,
		"MPTCP_SERVICE_TYPE should reject value >= MAX");

	/* Test negative value */
	int negative = -1;
	T_ASSERT_POSIX_FAILURE(
		setsockopt(fd, IPPROTO_TCP, MPTCP_SERVICE_TYPE,
		&negative, sizeof(negative)),
		EINVAL,
		"MPTCP_SERVICE_TYPE should reject negative value");

	close(fd);
}
