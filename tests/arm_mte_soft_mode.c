/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

#if __arm64__
#include <arm_acle.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(
	XNU_T_META_SOC_SPECIFIC
	);

/*
 * This binary is code signed with the signing ID com.apple.internal.arm_mte_soft_mode_test.
 * On internal builds, AMFI contains this ID on the MTE soft mode list.
 */
T_DECL(mte_soft_mode_enabled,
    "Test that soft mode is enabled on binaries in the AMFI soft mode list",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL,
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(false) /* rdar://142784868 */)
{
	/* verify that the process is running with MTE enabled */
	T_SETUPBEGIN;
	validate_proc_pidinfo_mte_soft_mode_status(getpid(), true);
	T_END_IF_FAILED;

	vm_size_t alloc_size = 16 * 1024;
	vm_address_t address = allocate_and_tag_range(alloc_size, TAG_RANDOM);
	T_SETUPEND;

	char *ptr = (char*)address;
	char *incorrectly_tagged_ptr = __arm_mte_increment_tag(ptr, 1);

	*ptr = 'a';
	T_LOG("wrote with correct tag");
	T_EXPECT_EQ(*incorrectly_tagged_ptr, 'a', "read with incorrect tag");

	*incorrectly_tagged_ptr = 'b';
	T_EXPECT_EQ(*ptr, 'b', "write with incorrect tag");
	T_LOG("read with correct tag");
}
#endif /* __arm64__ */
