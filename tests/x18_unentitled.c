/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include "context_helpers.h"
#include <darwintest.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdbool.h>
#include <unistd.h>

#include <os/arch/arm64.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("joster"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG_VM_PREFERRED);

T_DECL(x18_unentitled,
    "Test that x18 is trashed when unentitled.")
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	bool did_csw = false;
	uint64_t x18_val;

	uint64_t const tpidr = __builtin_arm_rsr64("TPIDR_EL0");
	printf("tpidr: %#16llx\n", tpidr);

	T_ASSERT_FALSE(os_custom_x18_abi_enabled(), "custom x18 ABI should be disabled without entitlement");

	for (uint64_t i = 0xFEEDB0B000000000ULL; i < 0xFEEDB0B000000000ULL + 10000; ++i) {
		asm volatile ("mov x18, %0" : : "r"(i));
		int32_t const nr_csw = get_csw_count();
		int const rc = usleep(10);
		int32_t const nr_csw_after = get_csw_count();

		// There isn't any guarantee usleep() will actually context switch so this is a best effort way
		// to see if we've switched at least once in all these iterations.
		did_csw = did_csw || (nr_csw_after > nr_csw);
		T_QUIET; T_ASSERT_EQ(0, rc, "usleep");
		asm volatile ("mov %0, x18" : "=r"(x18_val));
		T_QUIET; T_ASSERT_EQ(x18_val, 0ULL, "check that x18 is cleared after yield");
	}

	T_QUIET; T_ASSERT_TRUE(did_csw, "did not context switch, but should have.");
#endif
}
