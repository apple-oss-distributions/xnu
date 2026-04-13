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

/*
 * vm/configurator_vm_inherit.c
 *
 * Test vm_inherit with many different VM states.
 */

#include "configurator/vm_configurator_tests.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.configurator"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),  /* required for vm submap sysctls */
	T_META_ALL_VALID_ARCHS(true)
	);


/*
 * Update the checker state to mirror a vm_inherit call.
 */
static void
checker_perform_vm_inherit(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	vm_inherit_t inheritance)
{
	/* vm_inherit allows unallocated holes */
	entry_checker_range_t limit =
	    checker_list_find_range_including_holes(checker_list, start, size);
	if (limit.head->kind != Hole) {
		checker_clip_left(checker_list, limit.head, start);
	}
	if (limit.tail->kind != Hole) {
		checker_clip_right(checker_list, limit.tail, start + size);
	}

	FOREACH_CHECKER(checker, limit) {
		if (checker->kind == Allocation) {
			checker->inheritance = inheritance;
		}
	}
}


/*
 *  Perform and check a call to vm_inherit that is expected to succeed.
 */
static test_result_t
successful_vm_inherit(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	vm_inherit_t inherit = VM_INHERIT_SHARE;

	checker_perform_vm_inherit(checker_list, start, size, inherit);
	kr = mach_vm_inherit(mach_task_self(), start, size, inherit);
	if (kr != 0) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_inherit");
}


T_DECL(vm_inherit,
    "run vm_inherit with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = successful_vm_inherit,
		.single_entry_2 = successful_vm_inherit,
		.single_entry_3 = successful_vm_inherit,
		.single_entry_4 = successful_vm_inherit,

		.single_entry_nonnull_1 = successful_vm_inherit,
		.single_entry_nonnull_2 = successful_vm_inherit,
		.single_entry_nonnull_3 = successful_vm_inherit,
		.single_entry_nonnull_4 = successful_vm_inherit,

		.multiple_entries_1 = successful_vm_inherit,
		.multiple_entries_2 = successful_vm_inherit,
		.multiple_entries_3 = successful_vm_inherit,
		.multiple_entries_4 = successful_vm_inherit,
		.multiple_entries_5 = successful_vm_inherit,
		.multiple_entries_6 = successful_vm_inherit,

		.some_holes_1 = successful_vm_inherit,
		.some_holes_2 = successful_vm_inherit,
		.some_holes_3 = successful_vm_inherit,
		.some_holes_4 = successful_vm_inherit,
		.some_holes_5 = successful_vm_inherit,
		.some_holes_6 = successful_vm_inherit,
		.some_holes_7 = successful_vm_inherit,
		.some_holes_8 = successful_vm_inherit,
		.some_holes_9 = successful_vm_inherit,
		.some_holes_10 = successful_vm_inherit,
		.some_holes_11 = successful_vm_inherit,
		.some_holes_12 = successful_vm_inherit,

		.all_holes_1 = successful_vm_inherit,
		.all_holes_2 = successful_vm_inherit,
		.all_holes_3 = successful_vm_inherit,
		.all_holes_4 = successful_vm_inherit,

		.null_entry = successful_vm_inherit,
		.nonresident_entry = successful_vm_inherit,
		.resident_entry = successful_vm_inherit,

		.shared_entry = successful_vm_inherit,
		.shared_entry_discontiguous = successful_vm_inherit,
		.shared_entry_partial = successful_vm_inherit,
		.shared_entry_pairs = successful_vm_inherit,
		.shared_entry_x1000 = successful_vm_inherit,

		.cow_entry = successful_vm_inherit,
		.cow_unreferenced = successful_vm_inherit,
		.cow_nocow = successful_vm_inherit,
		.nocow_cow = successful_vm_inherit,
		.cow_unreadable = successful_vm_inherit,
		.cow_unwriteable = successful_vm_inherit,

		.permanent_entry = successful_vm_inherit,
		.permanent_before_permanent = successful_vm_inherit,
		.permanent_before_allocation = successful_vm_inherit,
		.permanent_before_allocation_2 = successful_vm_inherit,
		.permanent_before_hole = successful_vm_inherit,
		.permanent_after_allocation = successful_vm_inherit,
		.permanent_after_hole = successful_vm_inherit,

		.single_submap_single_entry = successful_vm_inherit,
		.single_submap_single_entry_first_pages = successful_vm_inherit,
		.single_submap_single_entry_last_pages = successful_vm_inherit,
		.single_submap_single_entry_middle_pages = successful_vm_inherit,
		.single_submap_oversize_entry_at_start = successful_vm_inherit,
		.single_submap_oversize_entry_at_end = successful_vm_inherit,
		.single_submap_oversize_entry_at_both = successful_vm_inherit,

		.submap_before_allocation = successful_vm_inherit,
		.submap_after_allocation = successful_vm_inherit,
		.submap_before_hole = successful_vm_inherit,
		.submap_after_hole = successful_vm_inherit,
		.submap_allocation_submap_one_entry = successful_vm_inherit,
		.submap_allocation_submap_two_entries = successful_vm_inherit,
		.submap_allocation_submap_three_entries = successful_vm_inherit,

		.submap_before_allocation_ro = successful_vm_inherit,
		.submap_after_allocation_ro = successful_vm_inherit,
		.submap_before_hole_ro = successful_vm_inherit,
		.submap_after_hole_ro = successful_vm_inherit,
		.submap_allocation_submap_one_entry_ro = successful_vm_inherit,
		.submap_allocation_submap_two_entries_ro = successful_vm_inherit,
		.submap_allocation_submap_three_entries_ro = successful_vm_inherit,

		.protection_single_000_000 = successful_vm_inherit,
		.protection_single_000_r00 = successful_vm_inherit,
		.protection_single_000_0w0 = successful_vm_inherit,
		.protection_single_000_rw0 = successful_vm_inherit,
		.protection_single_r00_r00 = successful_vm_inherit,
		.protection_single_r00_rw0 = successful_vm_inherit,
		.protection_single_0w0_0w0 = successful_vm_inherit,
		.protection_single_0w0_rw0 = successful_vm_inherit,
		.protection_single_rw0_rw0 = successful_vm_inherit,

		.protection_pairs_000_000 = successful_vm_inherit,
		.protection_pairs_000_r00 = successful_vm_inherit,
		.protection_pairs_000_0w0 = successful_vm_inherit,
		.protection_pairs_000_rw0 = successful_vm_inherit,
		.protection_pairs_r00_000 = successful_vm_inherit,
		.protection_pairs_r00_r00 = successful_vm_inherit,
		.protection_pairs_r00_0w0 = successful_vm_inherit,
		.protection_pairs_r00_rw0 = successful_vm_inherit,
		.protection_pairs_0w0_000 = successful_vm_inherit,
		.protection_pairs_0w0_r00 = successful_vm_inherit,
		.protection_pairs_0w0_0w0 = successful_vm_inherit,
		.protection_pairs_0w0_rw0 = successful_vm_inherit,
		.protection_pairs_rw0_000 = successful_vm_inherit,
		.protection_pairs_rw0_r00 = successful_vm_inherit,
		.protection_pairs_rw0_0w0 = successful_vm_inherit,
		.protection_pairs_rw0_rw0 = successful_vm_inherit,
	};

	run_vm_tests("vm_inherit", __FILE__, &tests, argc, argv);
}
