/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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
/**
 * On devices that support it, this test ensures that PSTATE.SSBS is set by
 * default and is writeable by userspace.
 */
#include <darwintest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <sys/sysctl.h>
#include <inttypes.h>


T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("dmitry_grinberg"),
	T_META_RUN_CONCURRENTLY(true));


#define PSR64_SSBS              (0x1000)
#define REG_SSBS                "S3_3_C4_C2_6" /* clang will not emit MRS/MSR to "SSBS" itself since it doesnt always exist */

T_DECL(armv85_ssbs,
    "Test that ARMv8.5 SSBS is off by default (PSTATE.SSBS==1, don't ask!) and can be enabled by userspace.")
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	uint32_t ssbs_support = 19180;
	size_t ssbs_support_len = sizeof(ssbs_support);
	if (sysctlbyname("hw.optional.arm.FEAT_SSBS", &ssbs_support, &ssbs_support_len, NULL, 0)) {
		T_SKIP("Could not get SSBS support sysctl, skipping...");
	} else if (!ssbs_support) {
		T_SKIP("HW has no SSBS support, skipping...");
	} else if (ssbs_support != 1) {
		T_FAIL("SSBS support sysctl contains garbage: %u!", ssbs_support);
	} else {
		uint64_t ssbs_state = __builtin_arm_rsr64(REG_SSBS);

		if (!(ssbs_state & PSR64_SSBS)) {
			T_FAIL("SSBS does not default to off (value seen: 0x%" PRIx64 ")!", ssbs_state);
		}

		__builtin_arm_wsr64(REG_SSBS, 0);
		ssbs_state = __builtin_arm_rsr64(REG_SSBS);

		if (ssbs_state & PSR64_SSBS) {
			T_FAIL("SSBS did not turn on (value seen: 0x%" PRIx64 ")!", ssbs_state);
		}

		__builtin_arm_wsr64(REG_SSBS, PSR64_SSBS);
		ssbs_state = __builtin_arm_rsr64(REG_SSBS);

		if (!(ssbs_state & PSR64_SSBS)) {
			T_FAIL("SSBS did not turn off (value seen: 0x%" PRIx64 ")!", ssbs_state);
		}

		T_PASS("SSBS test passes");
	}
#endif /* __arm64__ */
}
