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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>

#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"));

// NOTE: 17.253.144.10 is an anycast address run by AppleCDN.
// At the time of this test, this address is apple.com
static char *test_ip = "17.253.144.10";

static int
run_ping(char *dest, char *payload_size)
{
	int ping_ret, pid;
	// eg ping -t 3 -c 2 -s 120 17.253.144.10
	char *ping_args[]  = {"/sbin/ping", "-t", "3", "-c", "2", "-s", payload_size, dest, NULL};
	ping_ret = posix_spawn(&pid, ping_args[0], NULL, NULL, ping_args, NULL);
	if (ping_ret < 0) {
		return ping_ret;
	}
	waitpid(pid, &ping_ret, 0);
	return ping_ret;
}

static void
require_internet(void)
{
	int ret;

	ret = run_ping(test_ip, "128");
	if (ret == 0 || (WIFEXITED(ret) && !WEXITSTATUS(ret))) {
		T_PASS("Initial ping to %s passed, continuing test", test_ip);
	} else {
		T_SKIP("Initial ping to %s failed, skipping.", test_ip);
	}
}

T_DECL(icmp_internet_root, "test small Internet pings as root",
    T_META_ASROOT(true),
    T_META_REQUIRES_NETWORK(true))
{
	int ret;

	require_internet();

	ret = run_ping(test_ip, "10");
	if (ret == 0 || (WIFEXITED(ret) && !WEXITSTATUS(ret))) {
		T_PASS("ping completed");
	} else {
		T_FAIL("ping %s failed", test_ip);
	}
}

T_DECL(icmp_internet_non_root, "test small Internet pings as non-root",
    T_META_ASROOT(false),
    T_META_REQUIRES_NETWORK(true))
{
	int ret;

	require_internet();

	ret = run_ping(test_ip, "10");
	if (ret == 0 || (WIFEXITED(ret) && !WEXITSTATUS(ret))) {
		// And we did not crash
		T_PASS("ping completed");
	} else {
		T_FAIL("ping %s failed", test_ip);
	}
}

T_DECL(icmp_localhost_non_root, "test small localhost pings as non-root",
    T_META_ASROOT(false))
{
	int ret;
	ret = run_ping("127.0.0.1", "10");
	if (ret == 0 || (WIFEXITED(ret) && !WEXITSTATUS(ret))) {
		// And we did not crash
		T_PASS("ping completed");
	} else {
		T_FAIL("ping failed");
	}
}

T_DECL(icmp_localhost_root, "test small localhost pings as root",
    T_META_ASROOT(true))
{
	int ret;
	ret = run_ping("127.0.0.1", "10");
	if (ret == 0 || (WIFEXITED(ret) && !WEXITSTATUS(ret))) {
		T_PASS("ping completed");
	} else {
		T_FAIL("ping failed");
	}
}
