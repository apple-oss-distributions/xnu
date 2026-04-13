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

#include "exc_guard_helper.h"
#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <kern/exc_guard.h>
#include <mach/vm_statistics.h>
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.guard_objects_telemetry"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

#ifndef kGUARD_EXC_LARGE_ALLOCATION_TELEMETRY
#define kGUARD_EXC_LARGE_ALLOCATION_TELEMETRY (13)
#endif

#define SIZE_LIMIT (1ull << 30)

/*
 * This test is signed with com.apple.security.hardened-process.guard-objects,
 * so it will run with guard objects enabled.
 */
T_DECL(test_allocation_denied_under_guard_objects,
    "Ensure simulated crash occurs when violating guard objects allocation limit",
    T_META_ENABLED(!TARGET_OS_OSX)) {
	exc_guard_helper_info_t exc_info;

	exc_guard_helper_init();
	enable_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY);

	bool caught_exception = block_raised_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		kern_return_t     kr;
		mach_vm_address_t addr;
		mach_vm_size_t    size  = SIZE_LIMIT + PAGE_SIZE;

		/*
		 * Only the first iteration should generate an exception.
		 */
		for (int i = 0; i < 4; i++) {
		        addr = 0;

		        kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
		        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");

		        kr = mach_vm_deallocate(mach_task_self(), addr, size);
		        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		}
	});

	T_QUIET; T_ASSERT_TRUE(caught_exception, "guard exception received for large allocation");
	T_QUIET; T_ASSERT_EQ(exc_info.catch_count, 1, "only a single exception should be received");
	T_QUIET; T_ASSERT_EQ(exc_info.guard_type, GUARD_TYPE_VIRT_MEMORY, "exception should be type GUARD_TYPE_VIRT_MEMORY");
	T_QUIET; T_ASSERT_EQ(exc_info.guard_flavor, kGUARD_EXC_LARGE_ALLOCATION_TELEMETRY, "exception should be flavor kGUARD_EXC_LARGE_ALLOCATION_TELEMETRY");

	T_PASS("Successfully raised a single guard exception of the expected type");
}

T_DECL(test_allocation_allowed_if_optout,
    "Ensure no telemetry if VM_FLAGS_GUARD_OBJECT_OPTOUT is specified",
    T_META_ENABLED(!TARGET_OS_OSX)) {
	exc_guard_helper_info_t exc_info;

	exc_guard_helper_init();
	enable_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY);

	bool caught_exception = block_raised_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		kern_return_t     kr;
		mach_vm_address_t addr  = 0;
		mach_vm_size_t    size  = SIZE_LIMIT + PAGE_SIZE;

		kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_GUARD_OBJECT_OPTOUT);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");

		kr = mach_vm_deallocate(mach_task_self(), addr, size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
	});

	T_QUIET; T_ASSERT_FALSE(caught_exception, "no guard exception should occur when VM_FLAGS_GUARD_OBJECT_OPTOUT is specified");

	T_PASS("Verified that VM_FLAGS_GUARD_OBJECT_OPTOUT exempts allocation from telemetry");
}
