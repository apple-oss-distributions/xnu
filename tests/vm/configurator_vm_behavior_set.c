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
 * vm/configurator_vm_behavior_set.c
 *
 * Test vm_behavior_set with many different VM states.
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

static void
write_one_memory(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker)
{
	if (checker->kind == Allocation &&
	    prot_contains_all(checker->protection, VM_PROT_READ | VM_PROT_WRITE)) {
		checker_write_new_fill_pattern(checker_list, checker);
	}
}

static void
write_memory(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	entry_checker_range_t limit =
	    checker_list_find_range_including_holes(checker_list, start, size);
	/*
	 * TODO page modeling: this writes beyond [start, size), need page
	 * modeling to be more precise about the expected contents of the memory
	 */
	FOREACH_CHECKER(checker, limit) {
		write_one_memory(checker_list, checker);
	}
}

/* Test vm_behavior_set(behavior). This supports several behaviors. */
static test_result_t
vm_behavior_common_no_cow(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	vm_behavior_t behavior,
	bool has_holes,
	const char *message_suffix)
{
	kern_return_t kr;
	test_result_t test_results[1];
	bool clip_start, clip_end, reject_submaps;

	kern_return_t expected_kr = KERN_SUCCESS;
	if (has_holes) {
		expected_kr = KERN_INVALID_ADDRESS;
	}

	switch (behavior) {
	case VM_BEHAVIOR_DEFAULT:
		clip_start = clip_end = true;
		reject_submaps = false;
		break;
	case VM_BEHAVIOR_FREE:
		clip_start = clip_end = false;
		reject_submaps = false;
		break;
	case VM_BEHAVIOR_CAN_REUSE:
		clip_start = clip_end = false;
		reject_submaps = true;
		break;
	default:
		T_FAIL("don't know whether to clip for behavior %s",
		    name_for_behavior(behavior));
		return TestFailed;
	}

	entry_checker_range_t limit;
	if (has_holes) {
		limit = checker_list_find_range_including_holes(checker_list, start, size);
		if (!is_new_vm()) {
			/* old vm: hole failures do not clip */
			clip_start = clip_end = false;
		} else {
			/* new vm: hole failures can still clip at start */
			if (!checker_contains_address(limit.head, start)) {
				clip_start = false;
			}
			if (!checker_contains_address(limit.head, start + size)) {
				clip_end = false;
			}
		}
	} else {
		limit = checker_list_find_range(checker_list, start, size);
	}
	if (clip_start) {
		checker_clip_left(checker_list, limit.head, start);
	}
	if (reject_submaps) {
		FOREACH_CHECKER(checker, limit) {
			if (checker->kind == Submap) {
				expected_kr = KERN_INVALID_ADDRESS;
				break;
			}
		}
	}
	if (clip_end) {
		checker_clip_right(checker_list, limit.tail, start + size);
	}

	kr = mach_vm_behavior_set(mach_task_self(), start, size, behavior);
	if (kr != expected_kr) {
		T_FAIL("mach_vm_behavior_set(%s) failed (%s)",
		    name_for_behavior(behavior), name_for_kr(kr));
		return TestFailed;
	}

	/* Some behaviors destroy the pages, which affects the fill. */
	if (behavior == VM_BEHAVIOR_FREE) {
		FOREACH_CHECKER(checker, limit) {
			if (checker->object && checker->object->fill_pattern.mode == Fill) {
				checker->object->fill_pattern.pattern = 0;
				checker->object->fill_pattern.mode = DontFill;
			}
		}
	}

	TEMP_CSTRING(when, "after vm_behavior_set(%s) %s",
	    name_for_behavior(behavior), message_suffix);
	test_results[0] = verify_vm_state(checker_list, when);

	return worst_result(test_results, countof(test_results));
}

static test_result_t
vm_behavior_no_cow_maybe_rw_maybe_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	vm_behavior_t behavior,
	bool rw,
	bool has_holes)
{
	test_result_t result;

	result = vm_behavior_common_no_cow(checker_list, start, size,
	    behavior, has_holes, "first time");
	if (result != TestSucceeded) {
		return result;
	}

	if (rw) {
		/* write to the memory and do it again */
		write_memory(checker_list, start, size);
		result = verify_vm_state(checker_list, "after write_memory");
		if (result != TestSucceeded) {
			return result;
		}

		result = vm_behavior_common_no_cow(checker_list, start, size,
		    behavior, has_holes, "second time");
		if (result != TestSucceeded) {
			return result;
		}
	}

	return result;
}

static test_result_t
vm_behavior_default_no_cow_rw_no_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_DEFAULT,
		true /* rw */, false /* holes */);
}

static test_result_t
vm_behavior_default_no_cow_rw_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_DEFAULT,
		true /* rw */, true /* holes */);
}

static test_result_t
vm_behavior_default_no_cow_ro_no_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_DEFAULT,
		false /* rw */, false /* holes */);
}

static test_result_t
vm_behavior_default_no_cow_ro_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_DEFAULT,
		false /* rw */, true /* holes */);
}


static test_result_t
vm_behavior_free_no_cow_rw_no_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_FREE,
		true /* rw */, false /* holes */);
}

static test_result_t
vm_behavior_free_no_cow_rw_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_FREE,
		true /* rw */, true /* holes */);
}

static test_result_t
vm_behavior_free_no_cow_ro_no_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_FREE,
		false /* rw */, false /* holes */);
}

static test_result_t
vm_behavior_free_no_cow_ro_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_FREE,
		false /* rw */, true /* holes */);
}


static test_result_t
vm_behavior_can_reuse_no_cow_rw_no_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_CAN_REUSE,
		true /* rw */, false /* holes */);
}

static test_result_t
vm_behavior_can_reuse_no_cow_rw_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_CAN_REUSE,
		true /* rw */, true /* holes */);
}

static test_result_t
vm_behavior_can_reuse_no_cow_ro_no_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_CAN_REUSE,
		false /* rw */, false /* holes */);
}

static test_result_t
vm_behavior_can_reuse_no_cow_ro_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return vm_behavior_no_cow_maybe_rw_maybe_holes(
		checker_list, start, size, VM_BEHAVIOR_CAN_REUSE,
		false /* rw */, true /* holes */);
}


static test_result_t
vm_behavior_zero_once(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	const char *message_suffix)
{
	kern_return_t expected_kr = KERN_SUCCESS;
	kern_return_t kr;
	entry_checker_range_t limit =
	    checker_list_find_range_including_holes(checker_list, start, size);

	/*
	 * vm_behavior_set(ZERO) stops at un-writeable pages
	 * so we can't use the common code from other behaviors
	 */

	if (PAGE_SIZE < xnu_vm_page_size()) {
		/*
		 * VM_BEHAVIOR_ZERO does nothing and returns KERN_NO_ACCESS
		 * if the map's page size is less than the VM's page size.
		 */
		T_LOG("note: VM_BEHAVIOR_ZERO does nothing on this platform");
		expected_kr = KERN_NO_ACCESS;
		goto checker_update_done;
	}

	/* Old VM checks for holes first. New VM checks for holes as it proceeds. */
	if (!is_new_vm()) {
		FOREACH_CHECKER(checker, limit) {
			if (checker->kind == Hole) {
				expected_kr = KERN_INVALID_ADDRESS;
				goto checker_update_done;
			}
		}
	}

	/* Zero the checkers' fill patterns, stopping if we hit an unacceptable entry */
	FOREACH_CHECKER(checker, limit) {
		if (checker->kind == Hole) {
			expected_kr = KERN_INVALID_ADDRESS;
			goto checker_update_done;
		}
		if (!prot_contains_all(checker->protection, VM_PROT_WRITE)) {
			/* stop after the first unwriteable entry */
			expected_kr = KERN_PROTECTION_FAILURE;
			goto checker_update_done;
		}
		if (checker->kind == Submap) {
			/* stop at submaps */
			expected_kr = KERN_NO_ACCESS;
			goto checker_update_done;
		}

		/* writeable allocation: memory is now zeros */
		if (checker->object && checker->object->fill_pattern.mode == Fill) {
			checker->object->fill_pattern.pattern = 0;
			checker->object->fill_pattern.mode = DontFill;
		}
	}

checker_update_done:
	kr = mach_vm_behavior_set(mach_task_self(), start, size, VM_BEHAVIOR_ZERO);
	if (kr != expected_kr) {
		T_EXPECT_MACH_ERROR(kr, expected_kr, "mach_vm_behavior_set(VM_BEHAVIOR_ZERO)");
		return TestFailed;
	}

	TEMP_CSTRING(when, "after vm_behavior_set(VM_BEHAVIOR_ZERO) %s", message_suffix);
	return verify_vm_state(checker_list, when);
}

static test_result_t
vm_behavior_zero(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	test_result_t result;

	result = vm_behavior_zero_once(checker_list, start, size, "first time");
	if (result != TestSucceeded) {
		return result;
	}

	/* write to the memory and do it again */
	bool any_written = false;
	entry_checker_range_t limit = checker_list_find_range_including_holes(checker_list, start, size);
	/*
	 * TODO page modeling: this writes beyond [start, size), need page
	 * modeling to be more precise about the expected contents of the memory
	 */
	FOREACH_CHECKER(checker, limit) {
		if (checker->kind != Allocation) {
			continue;
		}
		if (prot_contains_all(checker->protection, VM_PROT_READ | VM_PROT_WRITE)) {
			any_written = true;
			write_one_memory(checker_list, checker);
		} else {
			/* stop after first unwriteable entry */
			break;
		}
	}

	if (any_written) {
		result = verify_vm_state(checker_list, "after write_memory");
		if (result != TestSucceeded) {
			return result;
		}

		result = vm_behavior_zero_once(checker_list, start, size, "second time");
		if (result != TestSucceeded) {
			return result;
		}
	}

	return result;
}


T_DECL(vm_behavior_set_default,
    "run vm_behavior_set(DEFAULT) with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = vm_behavior_default_no_cow_rw_no_holes,
		.single_entry_2 = vm_behavior_default_no_cow_rw_no_holes,
		.single_entry_3 = vm_behavior_default_no_cow_rw_no_holes,
		.single_entry_4 = vm_behavior_default_no_cow_rw_no_holes,

		.single_entry_nonnull_1 = vm_behavior_default_no_cow_rw_no_holes,
		/* TODO need page modeling for the rw test of these */
		.single_entry_nonnull_2 = vm_behavior_default_no_cow_ro_no_holes,
		.single_entry_nonnull_3 = vm_behavior_default_no_cow_ro_no_holes,
		.single_entry_nonnull_4 = vm_behavior_default_no_cow_ro_no_holes,

		.multiple_entries_1 = vm_behavior_default_no_cow_rw_no_holes,
		.multiple_entries_2 = vm_behavior_default_no_cow_rw_no_holes,
		.multiple_entries_3 = vm_behavior_default_no_cow_rw_no_holes,
		.multiple_entries_4 = vm_behavior_default_no_cow_rw_no_holes,
		.multiple_entries_5 = vm_behavior_default_no_cow_rw_no_holes,
		.multiple_entries_6 = vm_behavior_default_no_cow_rw_no_holes,

		.some_holes_1 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_2 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_3 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_4 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_5 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_6 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_7 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_8 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_9 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_10 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_11 = vm_behavior_default_no_cow_rw_with_holes,
		.some_holes_12 = vm_behavior_default_no_cow_rw_with_holes,

		.all_holes_1 = vm_behavior_default_no_cow_rw_with_holes,
		.all_holes_2 = vm_behavior_default_no_cow_rw_with_holes,
		.all_holes_3 = vm_behavior_default_no_cow_rw_with_holes,
		.all_holes_4 = vm_behavior_default_no_cow_rw_with_holes,

		.null_entry        = vm_behavior_default_no_cow_rw_no_holes,
		.nonresident_entry = vm_behavior_default_no_cow_rw_no_holes,
		.resident_entry    = vm_behavior_default_no_cow_rw_no_holes,

		.shared_entry               = test_is_unimplemented,
		.shared_entry_discontiguous = test_is_unimplemented,
		.shared_entry_partial       = test_is_unimplemented,
		.shared_entry_pairs         = test_is_unimplemented,
		.shared_entry_x1000         = test_is_unimplemented,

		.cow_entry = test_is_unimplemented,
		.cow_unreferenced = test_is_unimplemented,
		.cow_nocow = test_is_unimplemented,
		.nocow_cow = test_is_unimplemented,
		.cow_unreadable = test_is_unimplemented,
		.cow_unwriteable = test_is_unimplemented,

		.permanent_entry = vm_behavior_default_no_cow_rw_no_holes,
		.permanent_before_permanent = vm_behavior_default_no_cow_rw_no_holes,
		.permanent_before_allocation = vm_behavior_default_no_cow_rw_no_holes,
		.permanent_before_allocation_2 = vm_behavior_default_no_cow_rw_no_holes,
		.permanent_before_hole = vm_behavior_default_no_cow_rw_with_holes,
		.permanent_after_allocation = vm_behavior_default_no_cow_rw_no_holes,
		.permanent_after_hole = vm_behavior_default_no_cow_rw_with_holes,

		.single_submap_single_entry = vm_behavior_default_no_cow_rw_no_holes,
		.single_submap_single_entry_first_pages = vm_behavior_default_no_cow_rw_no_holes,
		.single_submap_single_entry_last_pages = vm_behavior_default_no_cow_rw_no_holes,
		.single_submap_single_entry_middle_pages = vm_behavior_default_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_start = vm_behavior_default_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_end = vm_behavior_default_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_both = vm_behavior_default_no_cow_rw_no_holes,

		.submap_before_allocation = vm_behavior_default_no_cow_rw_no_holes,
		.submap_after_allocation = vm_behavior_default_no_cow_rw_no_holes,
		.submap_before_hole = vm_behavior_default_no_cow_rw_with_holes,
		.submap_after_hole = vm_behavior_default_no_cow_rw_with_holes,
		.submap_allocation_submap_one_entry = vm_behavior_default_no_cow_rw_no_holes,
		.submap_allocation_submap_two_entries = vm_behavior_default_no_cow_rw_no_holes,
		.submap_allocation_submap_three_entries = vm_behavior_default_no_cow_rw_no_holes,

		.submap_before_allocation_ro = vm_behavior_default_no_cow_ro_no_holes,
		.submap_after_allocation_ro = vm_behavior_default_no_cow_ro_no_holes,
		.submap_before_hole_ro = vm_behavior_default_no_cow_ro_with_holes,
		.submap_after_hole_ro = vm_behavior_default_no_cow_ro_with_holes,
		.submap_allocation_submap_one_entry_ro = vm_behavior_default_no_cow_ro_no_holes,
		.submap_allocation_submap_two_entries_ro = vm_behavior_default_no_cow_ro_no_holes,
		.submap_allocation_submap_three_entries_ro = vm_behavior_default_no_cow_ro_no_holes,

		.protection_single_000_000 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_000_r00 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_r00_r00 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_000_0w0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_0w0_0w0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_000_rw0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_r00_rw0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_0w0_rw0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_single_rw0_rw0 = vm_behavior_default_no_cow_rw_no_holes,

		.protection_pairs_000_000 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_000_r00 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_000_0w0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_000_rw0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_r00_000 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_r00_r00 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_r00_0w0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_r00_rw0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_0w0_000 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_0w0_r00 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_0w0_0w0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_0w0_rw0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_rw0_000 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_rw0_r00 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_rw0_0w0 = vm_behavior_default_no_cow_ro_no_holes,
		.protection_pairs_rw0_rw0 = vm_behavior_default_no_cow_rw_no_holes,
	};

	run_vm_tests("vm_behavior_set_default", __FILE__, &tests, argc, argv);
}


T_DECL(vm_behavior_set_free,
    "run vm_behavior_set(FREE) with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = vm_behavior_free_no_cow_rw_no_holes,
		.single_entry_2 = vm_behavior_free_no_cow_rw_no_holes,
		.single_entry_3 = vm_behavior_free_no_cow_rw_no_holes,
		.single_entry_4 = vm_behavior_free_no_cow_rw_no_holes,

		.single_entry_nonnull_1 = vm_behavior_free_no_cow_rw_no_holes,
		/* TODO need page modeling for the rw test of these */
		.single_entry_nonnull_2 = vm_behavior_free_no_cow_ro_no_holes,
		.single_entry_nonnull_3 = vm_behavior_free_no_cow_ro_no_holes,
		.single_entry_nonnull_4 = vm_behavior_free_no_cow_ro_no_holes,

		.multiple_entries_1 = vm_behavior_free_no_cow_rw_no_holes,
		.multiple_entries_2 = vm_behavior_free_no_cow_rw_no_holes,
		.multiple_entries_3 = vm_behavior_free_no_cow_rw_no_holes,
		.multiple_entries_4 = vm_behavior_free_no_cow_rw_no_holes,
		.multiple_entries_5 = vm_behavior_free_no_cow_rw_no_holes,
		.multiple_entries_6 = vm_behavior_free_no_cow_rw_no_holes,

		.some_holes_1 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_2 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_3 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_4 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_5 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_6 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_7 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_8 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_9 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_10 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_11 = vm_behavior_free_no_cow_rw_with_holes,
		.some_holes_12 = vm_behavior_free_no_cow_rw_with_holes,

		.all_holes_1 = vm_behavior_free_no_cow_rw_with_holes,
		.all_holes_2 = vm_behavior_free_no_cow_rw_with_holes,
		.all_holes_3 = vm_behavior_free_no_cow_rw_with_holes,
		.all_holes_4 = vm_behavior_free_no_cow_rw_with_holes,

		.null_entry        = vm_behavior_free_no_cow_rw_no_holes,
		.nonresident_entry = vm_behavior_free_no_cow_rw_no_holes,
		.resident_entry    = vm_behavior_free_no_cow_rw_no_holes,

		.shared_entry               = test_is_unimplemented,
		.shared_entry_discontiguous = test_is_unimplemented,
		.shared_entry_partial       = test_is_unimplemented,
		.shared_entry_pairs         = test_is_unimplemented,
		.shared_entry_x1000         = test_is_unimplemented,

		.cow_entry = test_is_unimplemented,
		.cow_unreferenced = test_is_unimplemented,
		.cow_nocow = test_is_unimplemented,
		.nocow_cow = test_is_unimplemented,
		.cow_unreadable = test_is_unimplemented,
		.cow_unwriteable = test_is_unimplemented,

		.permanent_entry = vm_behavior_free_no_cow_rw_no_holes,
		.permanent_before_permanent = vm_behavior_free_no_cow_rw_no_holes,
		.permanent_before_allocation = vm_behavior_free_no_cow_rw_no_holes,
		.permanent_before_allocation_2 = vm_behavior_free_no_cow_rw_no_holes,
		.permanent_before_hole = vm_behavior_free_no_cow_rw_with_holes,
		.permanent_after_allocation = vm_behavior_free_no_cow_rw_no_holes,
		.permanent_after_hole = vm_behavior_free_no_cow_rw_with_holes,

		.single_submap_single_entry = vm_behavior_free_no_cow_rw_no_holes,
		.single_submap_single_entry_first_pages = vm_behavior_free_no_cow_rw_no_holes,
		.single_submap_single_entry_last_pages = vm_behavior_free_no_cow_rw_no_holes,
		.single_submap_single_entry_middle_pages = vm_behavior_free_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_start = vm_behavior_free_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_end = vm_behavior_free_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_both = vm_behavior_free_no_cow_rw_no_holes,

		.submap_before_allocation = vm_behavior_free_no_cow_rw_no_holes,
		.submap_after_allocation = vm_behavior_free_no_cow_rw_no_holes,
		.submap_before_hole = vm_behavior_free_no_cow_rw_with_holes,
		.submap_after_hole = vm_behavior_free_no_cow_rw_with_holes,
		.submap_allocation_submap_one_entry = vm_behavior_free_no_cow_rw_no_holes,
		.submap_allocation_submap_two_entries = vm_behavior_free_no_cow_rw_no_holes,
		.submap_allocation_submap_three_entries = vm_behavior_free_no_cow_rw_no_holes,

		.submap_before_allocation_ro = vm_behavior_free_no_cow_ro_no_holes,
		.submap_after_allocation_ro = vm_behavior_free_no_cow_ro_no_holes,
		.submap_before_hole_ro = vm_behavior_free_no_cow_ro_with_holes,
		.submap_after_hole_ro = vm_behavior_free_no_cow_ro_with_holes,
		.submap_allocation_submap_one_entry_ro = vm_behavior_free_no_cow_ro_no_holes,
		.submap_allocation_submap_two_entries_ro = vm_behavior_free_no_cow_ro_no_holes,
		.submap_allocation_submap_three_entries_ro = vm_behavior_free_no_cow_ro_no_holes,

		.protection_single_000_000 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_000_r00 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_r00_r00 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_000_0w0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_0w0_0w0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_000_rw0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_r00_rw0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_0w0_rw0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_single_rw0_rw0 = vm_behavior_free_no_cow_rw_no_holes,

		.protection_pairs_000_000 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_000_r00 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_000_0w0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_000_rw0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_r00_000 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_r00_r00 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_r00_0w0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_r00_rw0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_0w0_000 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_0w0_r00 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_0w0_0w0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_0w0_rw0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_rw0_000 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_rw0_r00 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_rw0_0w0 = vm_behavior_free_no_cow_ro_no_holes,
		.protection_pairs_rw0_rw0 = vm_behavior_free_no_cow_rw_no_holes,
	};

	run_vm_tests("vm_behavior_set_free", __FILE__, &tests, argc, argv);
}


T_DECL(vm_behavior_set_can_reuse,
    "run vm_behavior_set(CAN_REUSE) with various vm configurations")
{
	if (isRosetta()) {
		/*
		 * CAN_REUSE requires vm_object page alignment,
		 * but Rosetta is less aligned than that and
		 * these tests don't yet have a way to adapt.
		 */
		T_PASS("warning: TODO wrong alignment for vm_behavior_set(CAN_REUSE) "
		    "on Rosetta; just passing instead");
		return;
	}

	vm_tests_t tests = {
		.single_entry_1 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_entry_2 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_entry_3 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_entry_4 = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.single_entry_nonnull_1 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_entry_nonnull_2 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_entry_nonnull_3 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_entry_nonnull_4 = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.multiple_entries_1 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.multiple_entries_2 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.multiple_entries_3 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.multiple_entries_4 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.multiple_entries_5 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.multiple_entries_6 = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.some_holes_1 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_2 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_3 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_4 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_5 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_6 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_7 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_8 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_9 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_10 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_11 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.some_holes_12 = vm_behavior_can_reuse_no_cow_rw_with_holes,

		.all_holes_1 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.all_holes_2 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.all_holes_3 = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.all_holes_4 = vm_behavior_can_reuse_no_cow_rw_with_holes,

		.null_entry        = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.nonresident_entry = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.resident_entry    = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.shared_entry               = test_is_unimplemented,
		.shared_entry_discontiguous = test_is_unimplemented,
		.shared_entry_partial       = test_is_unimplemented,
		.shared_entry_pairs         = test_is_unimplemented,
		.shared_entry_x1000         = test_is_unimplemented,

		.cow_entry = test_is_unimplemented,
		.cow_unreferenced = test_is_unimplemented,
		.cow_nocow = test_is_unimplemented,
		.nocow_cow = test_is_unimplemented,
		.cow_unreadable = test_is_unimplemented,
		.cow_unwriteable = test_is_unimplemented,

		.permanent_entry = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.permanent_before_permanent = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.permanent_before_allocation = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.permanent_before_allocation_2 = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.permanent_before_hole = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.permanent_after_allocation = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.permanent_after_hole = vm_behavior_can_reuse_no_cow_rw_with_holes,

		.single_submap_single_entry = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_submap_single_entry_first_pages = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_submap_single_entry_last_pages = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_submap_single_entry_middle_pages = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_start = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_end = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.single_submap_oversize_entry_at_both = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.submap_before_allocation = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.submap_after_allocation = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.submap_before_hole = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.submap_after_hole = vm_behavior_can_reuse_no_cow_rw_with_holes,
		.submap_allocation_submap_one_entry = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.submap_allocation_submap_two_entries = vm_behavior_can_reuse_no_cow_rw_no_holes,
		.submap_allocation_submap_three_entries = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.submap_before_allocation_ro = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.submap_after_allocation_ro = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.submap_before_hole_ro = vm_behavior_can_reuse_no_cow_ro_with_holes,
		.submap_after_hole_ro = vm_behavior_can_reuse_no_cow_ro_with_holes,
		.submap_allocation_submap_one_entry_ro = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.submap_allocation_submap_two_entries_ro = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.submap_allocation_submap_three_entries_ro = vm_behavior_can_reuse_no_cow_ro_no_holes,

		.protection_single_000_000 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_000_r00 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_r00_r00 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_000_0w0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_0w0_0w0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_000_rw0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_r00_rw0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_0w0_rw0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_single_rw0_rw0 = vm_behavior_can_reuse_no_cow_rw_no_holes,

		.protection_pairs_000_000 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_000_r00 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_000_0w0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_000_rw0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_r00_000 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_r00_r00 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_r00_0w0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_r00_rw0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_0w0_000 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_0w0_r00 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_0w0_0w0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_0w0_rw0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_rw0_000 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_rw0_r00 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_rw0_0w0 = vm_behavior_can_reuse_no_cow_ro_no_holes,
		.protection_pairs_rw0_rw0 = vm_behavior_can_reuse_no_cow_rw_no_holes,
	};

	run_vm_tests("vm_behavior_set_can_reuse", __FILE__, &tests, argc, argv);
}


T_DECL(vm_behavior_set_zero,
    "run vm_behavior_set(ZERO) with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = vm_behavior_zero,
		.single_entry_2 = vm_behavior_zero,
		.single_entry_3 = vm_behavior_zero,
		.single_entry_4 = vm_behavior_zero,

		.single_entry_nonnull_1 = vm_behavior_zero,
		.single_entry_nonnull_2 = vm_behavior_zero,
		.single_entry_nonnull_3 = vm_behavior_zero,
		.single_entry_nonnull_4 = vm_behavior_zero,

		.multiple_entries_1 = vm_behavior_zero,
		.multiple_entries_2 = vm_behavior_zero,
		.multiple_entries_3 = vm_behavior_zero,
		.multiple_entries_4 = vm_behavior_zero,
		.multiple_entries_5 = vm_behavior_zero,
		.multiple_entries_6 = vm_behavior_zero,

		.some_holes_1 = vm_behavior_zero,
		.some_holes_2 = vm_behavior_zero,
		.some_holes_3 = vm_behavior_zero,
		.some_holes_4 = vm_behavior_zero,
		.some_holes_5 = vm_behavior_zero,
		.some_holes_6 = vm_behavior_zero,
		.some_holes_7 = vm_behavior_zero,
		.some_holes_8 = vm_behavior_zero,
		.some_holes_9 = vm_behavior_zero,
		.some_holes_10 = vm_behavior_zero,
		.some_holes_11 = vm_behavior_zero,
		.some_holes_12 = vm_behavior_zero,

		.all_holes_1 = vm_behavior_zero,
		.all_holes_2 = vm_behavior_zero,
		.all_holes_3 = vm_behavior_zero,
		.all_holes_4 = vm_behavior_zero,

		.null_entry        = vm_behavior_zero,
		.nonresident_entry = vm_behavior_zero,
		.resident_entry    = vm_behavior_zero,

		.shared_entry               = test_is_unimplemented,
		.shared_entry_discontiguous = test_is_unimplemented,
		.shared_entry_partial       = test_is_unimplemented,
		.shared_entry_pairs         = test_is_unimplemented,
		.shared_entry_x1000         = test_is_unimplemented,

		.cow_entry = test_is_unimplemented,
		.cow_unreferenced = test_is_unimplemented,
		.cow_nocow = test_is_unimplemented,
		.nocow_cow = test_is_unimplemented,
		.cow_unreadable = test_is_unimplemented,
		.cow_unwriteable = test_is_unimplemented,

		.permanent_entry = vm_behavior_zero,
		.permanent_before_permanent = vm_behavior_zero,
		.permanent_before_allocation = vm_behavior_zero,
		.permanent_before_allocation_2 = vm_behavior_zero,
		.permanent_before_hole = vm_behavior_zero,
		.permanent_after_allocation = vm_behavior_zero,
		.permanent_after_hole = vm_behavior_zero,

		.single_submap_single_entry = vm_behavior_zero,
		.single_submap_single_entry_first_pages = vm_behavior_zero,
		.single_submap_single_entry_last_pages = vm_behavior_zero,
		.single_submap_single_entry_middle_pages = vm_behavior_zero,
		.single_submap_oversize_entry_at_start = vm_behavior_zero,
		.single_submap_oversize_entry_at_end = vm_behavior_zero,
		.single_submap_oversize_entry_at_both = vm_behavior_zero,

		.submap_before_allocation = vm_behavior_zero,
		.submap_after_allocation = vm_behavior_zero,
		.submap_before_hole = vm_behavior_zero,
		.submap_after_hole = vm_behavior_zero,
		.submap_allocation_submap_one_entry = vm_behavior_zero,
		.submap_allocation_submap_two_entries = vm_behavior_zero,
		.submap_allocation_submap_three_entries = vm_behavior_zero,

		.submap_before_allocation_ro = vm_behavior_zero,
		.submap_after_allocation_ro = vm_behavior_zero,
		.submap_before_hole_ro = vm_behavior_zero,
		.submap_after_hole_ro = vm_behavior_zero,
		.submap_allocation_submap_one_entry_ro = vm_behavior_zero,
		.submap_allocation_submap_two_entries_ro = vm_behavior_zero,
		.submap_allocation_submap_three_entries_ro = vm_behavior_zero,

		.protection_single_000_000 = vm_behavior_zero,
		.protection_single_000_r00 = vm_behavior_zero,
		.protection_single_r00_r00 = vm_behavior_zero,
		.protection_single_000_0w0 = vm_behavior_zero,
		.protection_single_0w0_0w0 = vm_behavior_zero,
		.protection_single_000_rw0 = vm_behavior_zero,
		.protection_single_r00_rw0 = vm_behavior_zero,
		.protection_single_0w0_rw0 = vm_behavior_zero,
		.protection_single_rw0_rw0 = vm_behavior_zero,

		.protection_pairs_000_000 = vm_behavior_zero,
		.protection_pairs_000_r00 = vm_behavior_zero,
		.protection_pairs_000_0w0 = vm_behavior_zero,
		.protection_pairs_000_rw0 = vm_behavior_zero,
		.protection_pairs_r00_000 = vm_behavior_zero,
		.protection_pairs_r00_r00 = vm_behavior_zero,
		.protection_pairs_r00_0w0 = vm_behavior_zero,
		.protection_pairs_r00_rw0 = vm_behavior_zero,
		.protection_pairs_0w0_000 = vm_behavior_zero,
		.protection_pairs_0w0_r00 = vm_behavior_zero,
		.protection_pairs_0w0_0w0 = vm_behavior_zero,
		.protection_pairs_0w0_rw0 = vm_behavior_zero,
		.protection_pairs_rw0_000 = vm_behavior_zero,
		.protection_pairs_rw0_r00 = vm_behavior_zero,
		.protection_pairs_rw0_0w0 = vm_behavior_zero,
		.protection_pairs_rw0_rw0 = vm_behavior_zero,
	};

	run_vm_tests("vm_behavior_set_zero", __FILE__, &tests, argc, argv);
}
