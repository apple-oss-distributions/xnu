/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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
#include <vm/vm_kern_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.mach_vm_range_contains"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("tgal2"),
	T_META_RUN_CONCURRENTLY(true)
	);

T_DECL(prevent_overflow_with_large_address, "make sure false is returned for addr causing overflow (if !DEBUG && !DEVELOPMENT, it will panic)")
{
	const struct mach_vm_range r = {0x1000, 0x2000};
	mach_vm_offset_t addr = 0xFFFFFFFFFFFFFF00;
	mach_vm_offset_t size = 0x1100;

	T_ASSERT_FALSE(mach_vm_range_contains(&r, addr, size),
	    "got true for overflow (exploit exploit)");

	T_PASS("false returned for address overflow as expected");
}

T_DECL(prevent_overflow_with_large_size, "make sure false is returned for size causing overflow (if !DEBUG && !DEVELOPMENT, it will panic)")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x2000;
	mach_vm_offset_t size = 0xFFFFFFFFFFFFFFF0;

	T_ASSERT_FALSE(mach_vm_range_contains(&r, addr, size),
	    "got true for overflow (exploit exploit)");

	T_PASS("false returned for size overflow as expected");
}

T_DECL(allow_valid_range, "make sure true is returned for a valid range")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x1500;
	mach_vm_offset_t size = 0x500;

	T_ASSERT_TRUE(mach_vm_range_contains(&r, addr, size),
	    "got false for valid range");

	T_PASS("true returned for valid range as expected");
}

T_DECL(dont_allow_out_of_bounds_start, "make sure false is returned for address out of bounds")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x500;
	mach_vm_offset_t size = 0x500;

	T_ASSERT_FALSE(mach_vm_range_contains(&r, addr, size),
	    "got true for out-of-bounds start address");

	T_PASS("false returned for out-of-bounds start address as expected");
}

T_DECL(dont_allow_out_of_bounds_end, "make sure false is returned for size extending out of bounds")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x2000;
	mach_vm_offset_t size = 0x2000;

	T_ASSERT_FALSE(mach_vm_range_contains(&r, addr, size),
	    "got true for out-of-bounds end address");

	T_PASS("false returned for out-of-bounds end address as expected");
}

T_DECL(allow_exact_range_match_start, "make sure true is returned for exact range match - start of range")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x1000;
	mach_vm_offset_t size = 0x0;

	T_ASSERT_TRUE(mach_vm_range_contains(&r, addr, size),
	    "got false for exact range match");

	T_PASS("true returned for exact range match as expected");
}

T_DECL(allow_exact_range_match_end, "make sure true is returned for exact range match - end of range")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x1000;
	mach_vm_offset_t size = 0x2000;

	T_ASSERT_TRUE(mach_vm_range_contains(&r, addr, size),
	    "got false for exact range match");

	T_PASS("true returned for exact range match as expected");
}

T_DECL(prevent_invalid_size_zero, "make sure false is returned for size == 0")
{
	const struct mach_vm_range r = {0x1000, 0x3000};
	mach_vm_offset_t addr = 0x1500;
	mach_vm_offset_t size = 0x0;

	T_ASSERT_TRUE(mach_vm_range_contains(&r, addr, size),
	    "got false for size == 0 with addr in range");

	T_PASS("true returned for size == 0 with addr in range as expected");
}
