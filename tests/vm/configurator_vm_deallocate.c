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
 * vm/configurator_vm_deallocate.c
 *
 * Test vm_deallocate with many different VM states.
 */

#include "configurator/vm_configurator_tests.h"
#include "configurator/vm_configurator_helpers.h"
#include "exc_guard_helper.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.configurator"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),  /* required for vm submap sysctls */
	T_META_ALL_VALID_ARCHS(true)
	);

static bool
do_successful_vm_deallocate_guarded(mach_vm_address_t start, mach_vm_size_t size)
{
	__block kern_return_t kr;
	exc_guard_helper_info_t exc_info;
	bool caught_exception;

	caught_exception =
	    block_raised_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		kr = mach_vm_deallocate(mach_task_self(), start, size);
	});

	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return false;
	}
	if (caught_exception) {
		T_FAIL("unexpected EXC_GUARD during mach_vm_deallocate");
		return false;
	}

	return true;
}

static bool
do_vm_deallocate_holes_guarded(mach_vm_address_t start, mach_vm_size_t size)
{
	__block kern_return_t kr;
	exc_guard_helper_info_t exc_info;
	bool caught_exception;

	caught_exception =
	    block_raised_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		kr = mach_vm_deallocate(mach_task_self(), start, size);
	});

	/* non-fatal EXC_GUARD returns success */
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate guarded");
		return false;
	}
	if (!caught_exception) {
		T_FAIL("expected EXC_GUARD during mach_vm_deallocate");
		return false;
	}
	if (exc_info.catch_count != 1) {
		T_EXPECT_EQ(exc_info.catch_count, 1, "caught exception count");
		return false;
	}
	if (exc_info.guard_flavor != kGUARD_EXC_DEALLOC_GAP) {
		T_EXPECT_EQ(exc_info.guard_flavor, kGUARD_EXC_DEALLOC_GAP, "caught exception flavor");
		return false;
	}

	return true;
}

static test_result_t
successful_vm_deallocate(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	checker_perform_successful_vm_deallocate(checker_list, start, size);
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
successful_vm_deallocate_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_successful_vm_deallocate(checker_list, start, size);
	if (!do_successful_vm_deallocate_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_holes_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_successful_vm_deallocate(checker_list, start, size);
	if (!do_vm_deallocate_holes_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_entry(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	checker_perform_vm_deallocate_permanent(checker_list, start, size);
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_before_permanent(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_before_allocation(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_before_hole(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no changes to checkers in [start + size / 2, start + size) */
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_after_allocation(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_after_hole(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	/* no changes to checkers in [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);
	kr = mach_vm_deallocate(mach_task_self(), start, size);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "mach_vm_deallocate");
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}


static test_result_t
vm_deallocate_permanent_entry_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_vm_deallocate_permanent(checker_list, start, size);
	if (!do_successful_vm_deallocate_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_before_permanent_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);
	if (!do_successful_vm_deallocate_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_before_allocation_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);
	if (!do_successful_vm_deallocate_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_before_hole_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no changes to checkers in [start + size / 2, start + size) */
	if (!do_vm_deallocate_holes_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_after_allocation_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);
	if (!do_successful_vm_deallocate_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}

static test_result_t
vm_deallocate_permanent_after_hole_guarded(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	/* no changes to checkers in [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);
	if (!do_vm_deallocate_holes_guarded(start, size)) {
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_deallocate");
}


T_DECL(vm_deallocate_unguarded,
    "run vm_deallocate with various vm configurations; EXC_GUARD disabled")
{
	vm_tests_t tests = {
		.single_entry_1 = successful_vm_deallocate,
		.single_entry_2 = successful_vm_deallocate,
		.single_entry_3 = successful_vm_deallocate,
		.single_entry_4 = successful_vm_deallocate,

		.single_entry_nonnull_1 = successful_vm_deallocate,
		.single_entry_nonnull_2 = successful_vm_deallocate,
		.single_entry_nonnull_3 = successful_vm_deallocate,
		.single_entry_nonnull_4 = successful_vm_deallocate,

		.multiple_entries_1 = successful_vm_deallocate,
		.multiple_entries_2 = successful_vm_deallocate,
		.multiple_entries_3 = successful_vm_deallocate,
		.multiple_entries_4 = successful_vm_deallocate,
		.multiple_entries_5 = successful_vm_deallocate,
		.multiple_entries_6 = successful_vm_deallocate,

		.some_holes_1 = successful_vm_deallocate,
		.some_holes_2 = successful_vm_deallocate,
		.some_holes_3 = successful_vm_deallocate,
		.some_holes_4 = successful_vm_deallocate,
		.some_holes_5 = successful_vm_deallocate,
		.some_holes_6 = successful_vm_deallocate,
		.some_holes_7 = successful_vm_deallocate,
		.some_holes_8 = successful_vm_deallocate,
		.some_holes_9 = successful_vm_deallocate,
		.some_holes_10 = successful_vm_deallocate,
		.some_holes_11 = successful_vm_deallocate,
		.some_holes_12 = successful_vm_deallocate,

		.all_holes_1 = successful_vm_deallocate,
		.all_holes_2 = successful_vm_deallocate,
		.all_holes_3 = successful_vm_deallocate,
		.all_holes_4 = successful_vm_deallocate,

		.null_entry = successful_vm_deallocate,
		.nonresident_entry = successful_vm_deallocate,
		.resident_entry = successful_vm_deallocate,

		.shared_entry = successful_vm_deallocate,
		.shared_entry_discontiguous = successful_vm_deallocate,
		.shared_entry_partial = successful_vm_deallocate,
		.shared_entry_pairs = successful_vm_deallocate,
		.shared_entry_x1000 = successful_vm_deallocate,

		.cow_entry = successful_vm_deallocate,
		.cow_unreferenced = successful_vm_deallocate,
		.cow_nocow = successful_vm_deallocate,
		.nocow_cow = successful_vm_deallocate,
		.cow_unreadable = successful_vm_deallocate,
		.cow_unwriteable = successful_vm_deallocate,

		.permanent_entry = vm_deallocate_permanent_entry,
		.permanent_before_permanent = vm_deallocate_permanent_before_permanent,
		.permanent_before_allocation = vm_deallocate_permanent_before_allocation,
		.permanent_before_allocation_2 = vm_deallocate_permanent_before_allocation,
		.permanent_before_hole = vm_deallocate_permanent_before_hole,
		.permanent_after_allocation = vm_deallocate_permanent_after_allocation,
		.permanent_after_hole = vm_deallocate_permanent_after_hole,

		.single_submap_single_entry = successful_vm_deallocate,
		.single_submap_single_entry_first_pages = successful_vm_deallocate,
		.single_submap_single_entry_last_pages = successful_vm_deallocate,
		.single_submap_single_entry_middle_pages = successful_vm_deallocate,
		.single_submap_oversize_entry_at_start = successful_vm_deallocate,
		.single_submap_oversize_entry_at_end = successful_vm_deallocate,
		.single_submap_oversize_entry_at_both = successful_vm_deallocate,

		.submap_before_allocation = successful_vm_deallocate,
		.submap_after_allocation = successful_vm_deallocate,
		.submap_before_hole = successful_vm_deallocate,
		.submap_after_hole = successful_vm_deallocate,
		.submap_allocation_submap_one_entry = successful_vm_deallocate,
		.submap_allocation_submap_two_entries = successful_vm_deallocate,
		.submap_allocation_submap_three_entries = successful_vm_deallocate,

		.submap_before_allocation_ro = successful_vm_deallocate,
		.submap_after_allocation_ro = successful_vm_deallocate,
		.submap_before_hole_ro = successful_vm_deallocate,
		.submap_after_hole_ro = successful_vm_deallocate,
		.submap_allocation_submap_one_entry_ro = successful_vm_deallocate,
		.submap_allocation_submap_two_entries_ro = successful_vm_deallocate,
		.submap_allocation_submap_three_entries_ro = successful_vm_deallocate,

		.protection_single_000_000 = successful_vm_deallocate,
		.protection_single_000_r00 = successful_vm_deallocate,
		.protection_single_000_0w0 = successful_vm_deallocate,
		.protection_single_000_rw0 = successful_vm_deallocate,
		.protection_single_r00_r00 = successful_vm_deallocate,
		.protection_single_r00_rw0 = successful_vm_deallocate,
		.protection_single_0w0_0w0 = successful_vm_deallocate,
		.protection_single_0w0_rw0 = successful_vm_deallocate,
		.protection_single_rw0_rw0 = successful_vm_deallocate,

		.protection_pairs_000_000 = successful_vm_deallocate,
		.protection_pairs_000_r00 = successful_vm_deallocate,
		.protection_pairs_000_0w0 = successful_vm_deallocate,
		.protection_pairs_000_rw0 = successful_vm_deallocate,
		.protection_pairs_r00_000 = successful_vm_deallocate,
		.protection_pairs_r00_r00 = successful_vm_deallocate,
		.protection_pairs_r00_0w0 = successful_vm_deallocate,
		.protection_pairs_r00_rw0 = successful_vm_deallocate,
		.protection_pairs_0w0_000 = successful_vm_deallocate,
		.protection_pairs_0w0_r00 = successful_vm_deallocate,
		.protection_pairs_0w0_0w0 = successful_vm_deallocate,
		.protection_pairs_0w0_rw0 = successful_vm_deallocate,
		.protection_pairs_rw0_000 = successful_vm_deallocate,
		.protection_pairs_rw0_r00 = successful_vm_deallocate,
		.protection_pairs_rw0_0w0 = successful_vm_deallocate,
		.protection_pairs_rw0_rw0 = successful_vm_deallocate,
	};

	disable_vm_exc_guard();
	run_vm_tests("vm_deallocate_unguarded", __FILE__, &tests, argc, argv);
}  /* T_DECL(vm_deallocate_unguarded) */


T_DECL(vm_deallocate_guarded,
    "run vm_deallocate with various vm configurations; EXC_GUARD enabled")
{
	if (isRosetta()) {
		/* Rosetta doesn't deliver VM guard exceptions to the test's exception handler. */
		T_PASS("can't test VM guard exceptions on Rosetta");
		return;
	}

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_deallocate_guarded,
		.single_entry_2 = successful_vm_deallocate_guarded,
		.single_entry_3 = successful_vm_deallocate_guarded,
		.single_entry_4 = successful_vm_deallocate_guarded,

		.single_entry_nonnull_1 = successful_vm_deallocate_guarded,
		.single_entry_nonnull_2 = successful_vm_deallocate_guarded,
		.single_entry_nonnull_3 = successful_vm_deallocate_guarded,
		.single_entry_nonnull_4 = successful_vm_deallocate_guarded,

		.multiple_entries_1 = successful_vm_deallocate_guarded,
		.multiple_entries_2 = successful_vm_deallocate_guarded,
		.multiple_entries_3 = successful_vm_deallocate_guarded,
		.multiple_entries_4 = successful_vm_deallocate_guarded,
		.multiple_entries_5 = successful_vm_deallocate_guarded,
		.multiple_entries_6 = successful_vm_deallocate_guarded,

		.some_holes_1 = vm_deallocate_holes_guarded,
		.some_holes_2 = vm_deallocate_holes_guarded,
		.some_holes_3 = vm_deallocate_holes_guarded,
		.some_holes_4 = vm_deallocate_holes_guarded,
		.some_holes_5 = vm_deallocate_holes_guarded,
		.some_holes_6 = vm_deallocate_holes_guarded,
		.some_holes_7 = vm_deallocate_holes_guarded,
		.some_holes_8 = vm_deallocate_holes_guarded,
		.some_holes_9 = vm_deallocate_holes_guarded,
		.some_holes_10 = vm_deallocate_holes_guarded,
		.some_holes_11 = vm_deallocate_holes_guarded,
		.some_holes_12 = vm_deallocate_holes_guarded,

		.all_holes_1 = vm_deallocate_holes_guarded,
		.all_holes_2 = vm_deallocate_holes_guarded,
		.all_holes_3 = vm_deallocate_holes_guarded,
		.all_holes_4 = vm_deallocate_holes_guarded,

		.null_entry = successful_vm_deallocate_guarded,
		.nonresident_entry = successful_vm_deallocate_guarded,
		.resident_entry = successful_vm_deallocate_guarded,

		.shared_entry = successful_vm_deallocate_guarded,
		.shared_entry_discontiguous = successful_vm_deallocate_guarded,
		.shared_entry_partial = successful_vm_deallocate_guarded,
		.shared_entry_pairs = successful_vm_deallocate_guarded,
		.shared_entry_x1000 = successful_vm_deallocate_guarded,

		.cow_entry = successful_vm_deallocate_guarded,
		.cow_unreferenced = successful_vm_deallocate_guarded,
		.cow_nocow = successful_vm_deallocate_guarded,
		.nocow_cow = successful_vm_deallocate_guarded,
		.cow_unreadable = successful_vm_deallocate_guarded,
		.cow_unwriteable = successful_vm_deallocate_guarded,

		.permanent_entry = vm_deallocate_permanent_entry_guarded,
		.permanent_before_permanent = vm_deallocate_permanent_before_permanent_guarded,
		.permanent_before_allocation = vm_deallocate_permanent_before_allocation_guarded,
		.permanent_before_allocation_2 = vm_deallocate_permanent_before_allocation_guarded,
		.permanent_before_hole = vm_deallocate_permanent_before_hole_guarded,
		.permanent_after_allocation = vm_deallocate_permanent_after_allocation_guarded,
		.permanent_after_hole = vm_deallocate_permanent_after_hole_guarded,

		.single_submap_single_entry = successful_vm_deallocate_guarded,
		.single_submap_single_entry_first_pages = successful_vm_deallocate_guarded,
		.single_submap_single_entry_last_pages = successful_vm_deallocate_guarded,
		.single_submap_single_entry_middle_pages = successful_vm_deallocate_guarded,
		.single_submap_oversize_entry_at_start = successful_vm_deallocate_guarded,
		.single_submap_oversize_entry_at_end = successful_vm_deallocate_guarded,
		.single_submap_oversize_entry_at_both = successful_vm_deallocate_guarded,

		.submap_before_allocation = successful_vm_deallocate_guarded,
		.submap_after_allocation = successful_vm_deallocate_guarded,
		.submap_before_hole = vm_deallocate_holes_guarded,
		.submap_after_hole = vm_deallocate_holes_guarded,
		.submap_allocation_submap_one_entry = successful_vm_deallocate_guarded,
		.submap_allocation_submap_two_entries = successful_vm_deallocate_guarded,
		.submap_allocation_submap_three_entries = successful_vm_deallocate_guarded,

		.submap_before_allocation_ro = successful_vm_deallocate_guarded,
		.submap_after_allocation_ro = successful_vm_deallocate_guarded,
		.submap_before_hole_ro = vm_deallocate_holes_guarded,
		.submap_after_hole_ro = vm_deallocate_holes_guarded,
		.submap_allocation_submap_one_entry_ro = successful_vm_deallocate_guarded,
		.submap_allocation_submap_two_entries_ro = successful_vm_deallocate_guarded,
		.submap_allocation_submap_three_entries_ro = successful_vm_deallocate_guarded,

		.protection_single_000_000 = successful_vm_deallocate_guarded,
		.protection_single_000_r00 = successful_vm_deallocate_guarded,
		.protection_single_000_0w0 = successful_vm_deallocate_guarded,
		.protection_single_000_rw0 = successful_vm_deallocate_guarded,
		.protection_single_r00_r00 = successful_vm_deallocate_guarded,
		.protection_single_r00_rw0 = successful_vm_deallocate_guarded,
		.protection_single_0w0_0w0 = successful_vm_deallocate_guarded,
		.protection_single_0w0_rw0 = successful_vm_deallocate_guarded,
		.protection_single_rw0_rw0 = successful_vm_deallocate_guarded,

		.protection_pairs_000_000 = successful_vm_deallocate_guarded,
		.protection_pairs_000_r00 = successful_vm_deallocate_guarded,
		.protection_pairs_000_0w0 = successful_vm_deallocate_guarded,
		.protection_pairs_000_rw0 = successful_vm_deallocate_guarded,
		.protection_pairs_r00_000 = successful_vm_deallocate_guarded,
		.protection_pairs_r00_r00 = successful_vm_deallocate_guarded,
		.protection_pairs_r00_0w0 = successful_vm_deallocate_guarded,
		.protection_pairs_r00_rw0 = successful_vm_deallocate_guarded,
		.protection_pairs_0w0_000 = successful_vm_deallocate_guarded,
		.protection_pairs_0w0_r00 = successful_vm_deallocate_guarded,
		.protection_pairs_0w0_0w0 = successful_vm_deallocate_guarded,
		.protection_pairs_0w0_rw0 = successful_vm_deallocate_guarded,
		.protection_pairs_rw0_000 = successful_vm_deallocate_guarded,
		.protection_pairs_rw0_r00 = successful_vm_deallocate_guarded,
		.protection_pairs_rw0_0w0 = successful_vm_deallocate_guarded,
		.protection_pairs_rw0_rw0 = successful_vm_deallocate_guarded,
	};

	enable_non_fatal_vm_exc_guard();
	run_vm_tests("vm_deallocate_guarded", __FILE__, &tests, argc, argv);
}  /* T_DECL(vm_deallocate_guarded) */
