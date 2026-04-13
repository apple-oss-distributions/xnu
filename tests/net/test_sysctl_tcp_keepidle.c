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

#include <darwintest.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

T_DECL(test_sysctl_tcp_keepidle,
    "Test TCP keepalive sysctl variables",
    T_META_ASROOT(true))
{
	int original_keepidle;
	int new_keepidle = 3600000;
	size_t size = sizeof(original_keepidle);
	int ret;

	/* Test net.inet.tcp.keepidle */
	ret = sysctlbyname("net.inet.tcp.keepidle", &original_keepidle, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get net.inet.tcp.keepidle");
	T_LOG("Original keepidle value: %d", original_keepidle);

	/* Set new value */
	ret = sysctlbyname("net.inet.tcp.keepidle", NULL, NULL, &new_keepidle, sizeof(new_keepidle));
	T_ASSERT_POSIX_SUCCESS(ret, "Set net.inet.tcp.keepidle to %d", new_keepidle);

	/* Restore original value */
	ret = sysctlbyname("net.inet.tcp.keepidle", NULL, NULL, &original_keepidle, sizeof(original_keepidle));
	T_ASSERT_POSIX_SUCCESS(ret, "Restore net.inet.tcp.keepidle to %d", original_keepidle);

	/* Test net.inet.tcp.keepinit */
	int keepinit;
	size = sizeof(keepinit);
	ret = sysctlbyname("net.inet.tcp.keepinit", &keepinit, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get net.inet.tcp.keepinit");
	T_LOG("keepinit value: %d", keepinit);

	/* Test net.inet.tcp.keepintvl */
	int keepintvl;
	size = sizeof(keepintvl);
	ret = sysctlbyname("net.inet.tcp.keepintvl", &keepintvl, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get net.inet.tcp.keepintvl");
	T_LOG("keepintvl value: %d", keepintvl);

	/* Test net.inet.tcp.keepcnt */
	int keepcnt;
	size = sizeof(keepcnt);
	ret = sysctlbyname("net.inet.tcp.keepcnt", &keepcnt, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get net.inet.tcp.keepcnt");
	T_LOG("keepcnt value: %d", keepcnt);

	/* Test net.inet.tcp.msl */
	int msl;
	size = sizeof(msl);
	ret = sysctlbyname("net.inet.tcp.msl", &msl, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "Get net.inet.tcp.msl");
	T_LOG("msl value: %d", msl);

	T_PASS("All TCP keepalive sysctls exist and are accessible");
}
