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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(false)
	);

static void
test_sysctl(const char* name)
{
	int value, previous_value = 0, current_value = 0;
	size_t len = sizeof(value);

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(name, &value, &len, NULL, 0), "Get current value of sysctl %s", name);
	previous_value = value;
	value = 66;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(name, NULL, NULL, &value, sizeof(value)), "Set value of sysctl %s, prev=%d new=%d", name, previous_value, value);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(name, &current_value, &len, NULL, 0), "Get new value of sysctl %s", name);
	T_ASSERT_EQ(value, current_value, "Verify value was actually set");
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(name, NULL, NULL, &previous_value, sizeof(previous_value)), "Restore value of sysctl %s to %d", name, previous_value);
}

T_DECL(nework_elevated_logging, "Tests enforcement of entitlement as non-root")
{
	test_sysctl("net.route.verbose");
	test_sysctl("net.inet6.icmp6.nd6_debug");
}
