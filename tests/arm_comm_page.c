/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
#include <pthread.h>
#include <machine/cpu_capabilities.h>
#include <sys/types.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("jharmening"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(arm_comm_page_sanity,
    "Test that arm comm page values are sane.")
{
#if !defined(__arm64__)
	T_SKIP("Running on non-arm target, skipping...");
#else
	uint8_t page_shift = COMM_PAGE_READ(uint8_t, KERNEL_PAGE_SHIFT_LEGACY);
	T_QUIET; T_ASSERT_NE(page_shift, 0, "check that legacy kernel page shift is non-zero");
	T_QUIET; T_ASSERT_EQ(COMM_PAGE_READ(uint8_t, KERNEL_PAGE_SHIFT), page_shift,
	    "check that 'new' and 'legacy' page shifts are identical");
	T_QUIET; T_ASSERT_EQ(COMM_PAGE_READ(uint32_t, DEV_FIRM_LEGACY), COMM_PAGE_READ(uint32_t, DEV_FIRM),
	    "check that 'new' and 'legacy' DEV_FIRM fields are identical");
#endif
}
