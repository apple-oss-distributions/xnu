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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_RUN_CONCURRENTLY(false),
	T_META_ASROOT(true)
	);

#define LOWFIRST "net.inet.ip.portrange.lowfirst"

static int
get_lowfirst(void)
{
	int n = 0;
	size_t nsz = sizeof(n);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(LOWFIRST, &n, &nsz, NULL, 0),
	    "sysctlbyname get " LOWFIRST);

	return n;
}

T_DECL(ipport_range, "test sysctl portrange.lowfirst with partially mapped memory")
{
	void *b;
	int *n;
	int before, after, ret;

	before = get_lowfirst();
	T_LOG("%s before: %d", LOWFIRST, before);

	/* Map a single page; memory beyond it is unmapped */
	b = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	T_ASSERT_NE(b, MAP_FAILED, "mmap");

	memset(b, 0xff, PAGE_SIZE);

	/* Pointer spans the page boundary: last 3 bytes of first page + 1 byte in unmapped page */
	n = (int *)(b + PAGE_SIZE - sizeof(int) + 1);

	ret = sysctlbyname(LOWFIRST, NULL, NULL, n, sizeof(int));

	if (ret == -1) {
		after = get_lowfirst();
		T_LOG("%s after: %d", LOWFIRST, after);

		T_EXPECT_EQ(before, after, "lowfirst should not have changed");
	} else {
		T_LOG("sysctlbyname unexpectedly succeeded (returned %d)", ret);
	}

	/* Restore original value */
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(LOWFIRST, NULL, NULL, &before, sizeof(before)),
	    "restore " LOWFIRST);

	munmap(b, PAGE_SIZE);
}
