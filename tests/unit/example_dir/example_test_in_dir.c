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
#include "mocks/osfmk/unit_test_utils.h"
#include <vm/vm_object_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.example_test_in_dir"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("misc"),
	T_META_OWNER("s_shalom"),
	T_META_RUN_CONCURRENTLY(true)
	);

PMOCKS_START

// this function is mocked both here and in libmocks. This one should win
// because it appears later in OTHER_LDFLAGS in the makefile
T_MOCK_PRIVATE(int, kernel_func11, (int a, char b), (a, b), {
	return 5;
});

PMOCKS_END
// test the pmocks mechanism works from a sub-folder
T_DECL(test_private_mocks_work_in_dir, "test the the PMOCKS mechanism works")
{
	int r = kernel_func11(1, 2);
	T_ASSERT_EQ(r, 5, "value should come from private mock");
}



// If this test fails to build or run to success it means that something broke
// with the unit-test harness.

T_DECL(xnu_example_test_in_dir, "an example test in a directory")
{
	T_EXPECT_MACH_SUCCESS(0, "hello");
}
