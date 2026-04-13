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
 * vm/configurator_vm_allocate.c
 *
 * Test vm_allocate(FIXED and FIXED|OVERWRITE) with many different VM states.
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

/*
 * Update the checker list after a successful call to vm_allocate().
 * Any pre-existing checkers inside this range are deleted and replaced.
 */
static void
checker_perform_successful_vm_allocate(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	uint16_t user_tag)
{
	/* Make a new checker for the allocation. */
	vm_entry_checker_t *new_checker = make_checker_for_vm_allocate(
		checker_list, start, size, VM_MAKE_TAG(user_tag));
	entry_checker_range_t new_range = { new_checker, new_checker };

	/* Find existing checkers in the address range. */
	entry_checker_range_t old_range =
	    checker_list_find_and_clip_including_holes(checker_list, start, size);

	/* Free the old checkers and insert the new checker. */
	checker_list_replace_range(checker_list, old_range, new_range);
}

static bool
call_vm_allocate_and_expect_result(
	mach_vm_address_t start,
	mach_vm_size_t size,
	int flags_and_tag,
	kern_return_t expected_kr)
{
#if workaround_rdar_143341561
	__block mach_vm_address_t allocated = start;
	__block kern_return_t kr;
	exc_guard_helper_info_t exc_info;
	bool caught_exception =
	    block_raised_exc_guard_of_type_ignoring_translated(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		kr = mach_vm_allocate(mach_task_self(), &allocated, size, flags_and_tag);
	});
	if (caught_exception) {
		if (is_fixed_overwrite(flags_and_tag)) {
			T_LOG("warning: rdar://143341561 mmap(FIXED) should work "
			    "regardless of whether a mapping exists at the addr");
		} else {
			T_FAIL("unexpected EXC_GUARD during vm_allocate");
			return false;
		}
	}
#else  /* not workaround_rdar_143341561 */
	mach_vm_address_t allocated = start;
	kern_return_t kr =
	    mach_vm_allocate(mach_task_self(), &allocated, size, flags_and_tag);
#endif /* not workaround_rdar_143341561 */

	if (kr != expected_kr) {
		T_EXPECT_MACH_ERROR(kr, expected_kr, "mach_vm_allocate(flags 0x%x)", flags_and_tag);
		return false;
	}
	if (allocated != start) {
		T_FAIL("mach_vm_allocate(flags 0x%x) returned address 0x%llx (expected 0x%llx)",
		    flags_and_tag, allocated, start);
		return false;
	}

	return true;
}

static bool
call_vm_allocate_and_expect_success(
	mach_vm_address_t start,
	mach_vm_size_t size,
	int flags_and_tag)
{
	return call_vm_allocate_and_expect_result(start, size, flags_and_tag, KERN_SUCCESS);
}

static bool
call_vm_allocate_and_expect_no_space(
	mach_vm_address_t start,
	mach_vm_size_t size,
	int flags_and_tag)
{
	return call_vm_allocate_and_expect_result(start, size, flags_and_tag, KERN_NO_SPACE);
}

/*
 * For FIXED | OVERWRITE atop permanent entries.
 * old VM: expect KERN_NO_SPACE
 * new VM: expect KERN_PROTECTION_FAILURE
 */
static bool
call_vm_allocate_overwriting_permanent(
	mach_vm_address_t start,
	mach_vm_size_t size,
	int flags_and_tag)
{
	return call_vm_allocate_and_expect_result(start, size, flags_and_tag,
	           overwrite_permanent_error());
}

static test_result_t
successful_vm_allocate_fixed(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	if (!call_vm_allocate_and_expect_success(start, size, VM_FLAGS_FIXED)) {
		return TestFailed;
	}
	checker_perform_successful_vm_allocate(checker_list, start, size, 0);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED)");
}



static test_result_t
test_permanent_entry_fixed_overwrite_rangelocked(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	assert(is_new_vm());

#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/*
	 * No checker updates. Any fixed|overwrite atop a permanent entry
	 * fails during preflight.
	 */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/*
	 * No checker updates. Any fixed|overwrite atop a permanent entry
	 * fails during preflight.
	 */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}


static test_result_t
test_permanent_entry_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/* one permanent entry, it becomes inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_permanent_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/* two permanent entries, both become inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_allocation_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* [start + size/2, start + size) unchanged */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_allocation_fixed_overwrite_rdar144128567(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, becomes deallocated (rdar://144128567)
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_hole_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one hole, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no change for addresses [start + size / 2, start + size) */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_after_allocation_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/*
	 * one nonpermanent allocation, becomes deallocated
	 * one permanent entry, becomes inaccessible
	 */
	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_after_hole_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)) {
		return TestFailed;
	}

	/*
	 * one hole, unchanged
	 * one permanent entry, becomes inaccessible
	 */
	/* no change for addresses [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}


static test_result_t
test_permanent_entry_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/* one permanent entry, it becomes inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_permanent_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/* two permanent entries, both become inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_allocation_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* [start + size/2, start + size) unchanged */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_allocation_fixed_overwrite_with_neighbor_tags_rdar144128567(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, becomes deallocated (rdar://144128567)
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_before_hole_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one hole, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no change for addresses [start + size / 2, start + size) */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_after_allocation_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/*
	 * one nonpermanent allocation, becomes deallocated
	 * one permanent entry, becomes inaccessible
	 */
	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
test_permanent_after_hole_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if workaround_rdar_143341561
	if (isRosetta()) {
		T_LOG("warning: can't work around rdar://143341561 on Rosetta; just passing instead");
		return TestSucceeded;
	}
#endif

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (!call_vm_allocate_overwriting_permanent(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}

	/*
	 * one hole, unchanged
	 * one permanent entry, becomes inaccessible
	 */
	/* no change for addresses [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
fixed_no_space(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	if (!call_vm_allocate_and_expect_no_space(start, size, VM_FLAGS_FIXED)) {
		return TestFailed;
	}

	/* no checker update here, call should have no side effects */

	return verify_vm_state(checker_list, "after vm_allocate(FIXED)");
}


static test_result_t
successful_vm_allocate_fixed_overwrite_with_tag(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	uint16_t tag)
{
	if (!call_vm_allocate_and_expect_success(
		    start, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(tag))) {
		return TestFailed;
	}
	checker_perform_successful_vm_allocate(checker_list, start, size, tag);

	return verify_vm_state(checker_list, "after vm_allocate(FIXED | OVERWRITE)");
}

static test_result_t
successful_vm_allocate_fixed_overwrite(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	return successful_vm_allocate_fixed_overwrite_with_tag(
		checker_list, start, size, 0);
}

static test_result_t
successful_vm_allocate_fixed_overwrite_with_neighbor_tags(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 * to probe simplify behavior.
	 */
	tag = get_app_specific_user_tag_for_address(start - 1);
	if (TestFailed == successful_vm_allocate_fixed_overwrite_with_tag(
		    checker_list, start, size, tag)) {
		return TestFailed;
	}

	/*
	 * Allocate again, with a tag matching the entry to the right,
	 * to probe simplify behavior.
	 */
	tag = get_app_specific_user_tag_for_address(start + size);
	if (TestFailed == successful_vm_allocate_fixed_overwrite_with_tag(
		    checker_list, start, size, tag)) {
		return TestFailed;
	}

	return TestSucceeded;
}


T_DECL(vm_allocate_fixed,
    "run vm_allocate(FIXED) with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = fixed_no_space,
		.single_entry_2 = fixed_no_space,
		.single_entry_3 = fixed_no_space,
		.single_entry_4 = fixed_no_space,

		.single_entry_nonnull_1 = fixed_no_space,
		.single_entry_nonnull_2 = fixed_no_space,
		.single_entry_nonnull_3 = fixed_no_space,
		.single_entry_nonnull_4 = fixed_no_space,

		.multiple_entries_1 = fixed_no_space,
		.multiple_entries_2 = fixed_no_space,
		.multiple_entries_3 = fixed_no_space,
		.multiple_entries_4 = fixed_no_space,
		.multiple_entries_5 = fixed_no_space,
		.multiple_entries_6 = fixed_no_space,

		.some_holes_1 = fixed_no_space,
		.some_holes_2 = fixed_no_space,
		.some_holes_3 = fixed_no_space,
		.some_holes_4 = fixed_no_space,
		.some_holes_5 = fixed_no_space,
		.some_holes_6 = fixed_no_space,
		.some_holes_7 = fixed_no_space,
		.some_holes_8 = fixed_no_space,
		.some_holes_9 = fixed_no_space,
		.some_holes_10 = fixed_no_space,
		.some_holes_11 = fixed_no_space,
		.some_holes_12 = fixed_no_space,

		.all_holes_1 = successful_vm_allocate_fixed,
		.all_holes_2 = successful_vm_allocate_fixed,
		.all_holes_3 = successful_vm_allocate_fixed,
		.all_holes_4 = successful_vm_allocate_fixed,

		.null_entry = fixed_no_space,
		.nonresident_entry = fixed_no_space,
		.resident_entry = fixed_no_space,

		.shared_entry = fixed_no_space,
		.shared_entry_discontiguous = fixed_no_space,
		.shared_entry_partial = fixed_no_space,
		.shared_entry_pairs = fixed_no_space,
		.shared_entry_x1000 = fixed_no_space,

		.cow_entry = fixed_no_space,
		.cow_unreferenced = fixed_no_space,
		.cow_nocow = fixed_no_space,
		.nocow_cow = fixed_no_space,
		.cow_unreadable = fixed_no_space,
		.cow_unwriteable = fixed_no_space,

		.permanent_entry = fixed_no_space,
		.permanent_before_permanent = fixed_no_space,
		.permanent_before_allocation = fixed_no_space,
		.permanent_before_allocation_2 = fixed_no_space,
		.permanent_before_hole = fixed_no_space,
		.permanent_after_allocation = fixed_no_space,
		.permanent_after_hole = fixed_no_space,

		.single_submap_single_entry = fixed_no_space,
		.single_submap_single_entry_first_pages = fixed_no_space,
		.single_submap_single_entry_last_pages = fixed_no_space,
		.single_submap_single_entry_middle_pages = fixed_no_space,
		.single_submap_oversize_entry_at_start = fixed_no_space,
		.single_submap_oversize_entry_at_end = fixed_no_space,
		.single_submap_oversize_entry_at_both = fixed_no_space,

		.submap_before_allocation = fixed_no_space,
		.submap_after_allocation = fixed_no_space,
		.submap_before_hole = fixed_no_space,
		.submap_after_hole = fixed_no_space,
		.submap_allocation_submap_one_entry = fixed_no_space,
		.submap_allocation_submap_two_entries = fixed_no_space,
		.submap_allocation_submap_three_entries = fixed_no_space,

		.submap_before_allocation_ro = fixed_no_space,
		.submap_after_allocation_ro = fixed_no_space,
		.submap_before_hole_ro = fixed_no_space,
		.submap_after_hole_ro = fixed_no_space,
		.submap_allocation_submap_one_entry_ro = fixed_no_space,
		.submap_allocation_submap_two_entries_ro = fixed_no_space,
		.submap_allocation_submap_three_entries_ro = fixed_no_space,

		.protection_single_000_000 = fixed_no_space,
		.protection_single_000_r00 = fixed_no_space,
		.protection_single_000_0w0 = fixed_no_space,
		.protection_single_000_rw0 = fixed_no_space,
		.protection_single_r00_r00 = fixed_no_space,
		.protection_single_r00_rw0 = fixed_no_space,
		.protection_single_0w0_0w0 = fixed_no_space,
		.protection_single_0w0_rw0 = fixed_no_space,
		.protection_single_rw0_rw0 = fixed_no_space,

		.protection_pairs_000_000 = fixed_no_space,
		.protection_pairs_000_r00 = fixed_no_space,
		.protection_pairs_000_0w0 = fixed_no_space,
		.protection_pairs_000_rw0 = fixed_no_space,
		.protection_pairs_r00_000 = fixed_no_space,
		.protection_pairs_r00_r00 = fixed_no_space,
		.protection_pairs_r00_0w0 = fixed_no_space,
		.protection_pairs_r00_rw0 = fixed_no_space,
		.protection_pairs_0w0_000 = fixed_no_space,
		.protection_pairs_0w0_r00 = fixed_no_space,
		.protection_pairs_0w0_0w0 = fixed_no_space,
		.protection_pairs_0w0_rw0 = fixed_no_space,
		.protection_pairs_rw0_000 = fixed_no_space,
		.protection_pairs_rw0_r00 = fixed_no_space,
		.protection_pairs_rw0_0w0 = fixed_no_space,
		.protection_pairs_rw0_rw0 = fixed_no_space,
	};

	run_vm_tests("vm_allocate_fixed", __FILE__, &tests, argc, argv);
}


T_DECL(vm_allocate_fixed_overwrite,
    "run vm_allocate(FIXED|OVERWRITE) with various vm configurations")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_allocate_fixed_overwrite,
		.single_entry_2 = successful_vm_allocate_fixed_overwrite,
		.single_entry_3 = successful_vm_allocate_fixed_overwrite,
		.single_entry_4 = successful_vm_allocate_fixed_overwrite,

		.single_entry_nonnull_1 = successful_vm_allocate_fixed_overwrite,
		.single_entry_nonnull_2 = successful_vm_allocate_fixed_overwrite,
		.single_entry_nonnull_3 = successful_vm_allocate_fixed_overwrite,
		.single_entry_nonnull_4 = successful_vm_allocate_fixed_overwrite,

		.multiple_entries_1 = successful_vm_allocate_fixed_overwrite,
		.multiple_entries_2 = successful_vm_allocate_fixed_overwrite,
		.multiple_entries_3 = successful_vm_allocate_fixed_overwrite,
		.multiple_entries_4 = successful_vm_allocate_fixed_overwrite,
		.multiple_entries_5 = successful_vm_allocate_fixed_overwrite,
		.multiple_entries_6 = successful_vm_allocate_fixed_overwrite,

		.some_holes_1 = successful_vm_allocate_fixed_overwrite,
		.some_holes_2 = successful_vm_allocate_fixed_overwrite,
		.some_holes_3 = successful_vm_allocate_fixed_overwrite,
		.some_holes_4 = successful_vm_allocate_fixed_overwrite,
		.some_holes_5 = successful_vm_allocate_fixed_overwrite,
		.some_holes_6 = successful_vm_allocate_fixed_overwrite,
		.some_holes_7 = successful_vm_allocate_fixed_overwrite,
		.some_holes_8 = successful_vm_allocate_fixed_overwrite,
		.some_holes_9 = successful_vm_allocate_fixed_overwrite,
		.some_holes_10 = successful_vm_allocate_fixed_overwrite,
		.some_holes_11 = successful_vm_allocate_fixed_overwrite,
		.some_holes_12 = successful_vm_allocate_fixed_overwrite,

		.all_holes_1 = successful_vm_allocate_fixed_overwrite,
		.all_holes_2 = successful_vm_allocate_fixed_overwrite,
		.all_holes_3 = successful_vm_allocate_fixed_overwrite,
		.all_holes_4 = successful_vm_allocate_fixed_overwrite,

		.null_entry = successful_vm_allocate_fixed_overwrite,
		.nonresident_entry = successful_vm_allocate_fixed_overwrite,
		.resident_entry = successful_vm_allocate_fixed_overwrite,

		.shared_entry = successful_vm_allocate_fixed_overwrite,
		.shared_entry_discontiguous = successful_vm_allocate_fixed_overwrite,
		.shared_entry_partial = successful_vm_allocate_fixed_overwrite,
		.shared_entry_pairs = successful_vm_allocate_fixed_overwrite,
		.shared_entry_x1000 = successful_vm_allocate_fixed_overwrite,

		.cow_entry = successful_vm_allocate_fixed_overwrite,
		.cow_unreferenced = successful_vm_allocate_fixed_overwrite,
		.cow_nocow = successful_vm_allocate_fixed_overwrite,
		.nocow_cow = successful_vm_allocate_fixed_overwrite,
		.cow_unreadable = successful_vm_allocate_fixed_overwrite,
		.cow_unwriteable = successful_vm_allocate_fixed_overwrite,

		.permanent_entry = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_entry_fixed_overwrite,
		.permanent_before_permanent = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_before_permanent_fixed_overwrite,
		.permanent_before_allocation = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_before_allocation_fixed_overwrite,
		.permanent_before_allocation_2 = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_before_allocation_fixed_overwrite_rdar144128567,
		.permanent_before_hole = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_before_hole_fixed_overwrite,
		.permanent_after_allocation = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_after_allocation_fixed_overwrite,
		.permanent_after_hole = is_new_vm() ? test_permanent_entry_fixed_overwrite_rangelocked : test_permanent_after_hole_fixed_overwrite,

		.single_submap_single_entry = successful_vm_allocate_fixed_overwrite,
		.single_submap_single_entry_first_pages = successful_vm_allocate_fixed_overwrite,
		.single_submap_single_entry_last_pages = successful_vm_allocate_fixed_overwrite,
		.single_submap_single_entry_middle_pages = successful_vm_allocate_fixed_overwrite,
		.single_submap_oversize_entry_at_start = successful_vm_allocate_fixed_overwrite,
		.single_submap_oversize_entry_at_end = successful_vm_allocate_fixed_overwrite,
		.single_submap_oversize_entry_at_both = successful_vm_allocate_fixed_overwrite,

		.submap_before_allocation = successful_vm_allocate_fixed_overwrite,
		.submap_after_allocation = successful_vm_allocate_fixed_overwrite,
		.submap_before_hole = successful_vm_allocate_fixed_overwrite,
		.submap_after_hole = successful_vm_allocate_fixed_overwrite,
		.submap_allocation_submap_one_entry = successful_vm_allocate_fixed_overwrite,
		.submap_allocation_submap_two_entries = successful_vm_allocate_fixed_overwrite,
		.submap_allocation_submap_three_entries = successful_vm_allocate_fixed_overwrite,

		.submap_before_allocation_ro = successful_vm_allocate_fixed_overwrite,
		.submap_after_allocation_ro = successful_vm_allocate_fixed_overwrite,
		.submap_before_hole_ro = successful_vm_allocate_fixed_overwrite,
		.submap_after_hole_ro = successful_vm_allocate_fixed_overwrite,
		.submap_allocation_submap_one_entry_ro = successful_vm_allocate_fixed_overwrite,
		.submap_allocation_submap_two_entries_ro = successful_vm_allocate_fixed_overwrite,
		.submap_allocation_submap_three_entries_ro = successful_vm_allocate_fixed_overwrite,

		.protection_single_000_000 = successful_vm_allocate_fixed_overwrite,
		.protection_single_000_r00 = successful_vm_allocate_fixed_overwrite,
		.protection_single_000_0w0 = successful_vm_allocate_fixed_overwrite,
		.protection_single_000_rw0 = successful_vm_allocate_fixed_overwrite,
		.protection_single_r00_r00 = successful_vm_allocate_fixed_overwrite,
		.protection_single_r00_rw0 = successful_vm_allocate_fixed_overwrite,
		.protection_single_0w0_0w0 = successful_vm_allocate_fixed_overwrite,
		.protection_single_0w0_rw0 = successful_vm_allocate_fixed_overwrite,
		.protection_single_rw0_rw0 = successful_vm_allocate_fixed_overwrite,

		.protection_pairs_000_000 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_000_r00 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_000_0w0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_000_rw0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_r00_000 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_r00_r00 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_r00_0w0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_r00_rw0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_0w0_000 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_0w0_r00 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_0w0_0w0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_0w0_rw0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_rw0_000 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_rw0_r00 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_rw0_0w0 = successful_vm_allocate_fixed_overwrite,
		.protection_pairs_rw0_rw0 = successful_vm_allocate_fixed_overwrite,
	};

	run_vm_tests("vm_allocate_fixed_overwrite", __FILE__, &tests, argc, argv);
}

T_DECL(vm_allocate_fixed_overwrite_with_neighbor_tags,
    "run vm_allocate(FIXED|OVERWRITE|tag) with various vm configurations "
    "and tags copied from neighboring entries")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_entry_2 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_entry_3 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_entry_4 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.single_entry_nonnull_1 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_entry_nonnull_2 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_entry_nonnull_3 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_entry_nonnull_4 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.multiple_entries_1 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.multiple_entries_2 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.multiple_entries_3 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.multiple_entries_4 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.multiple_entries_5 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.multiple_entries_6 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.some_holes_1 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_2 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_3 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_4 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_5 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_6 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_7 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_8 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_9 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_10 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_11 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.some_holes_12 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.all_holes_1 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.all_holes_2 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.all_holes_3 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.all_holes_4 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.null_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.nonresident_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.resident_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.shared_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.shared_entry_discontiguous = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.shared_entry_partial = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.shared_entry_pairs = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.shared_entry_x1000 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.cow_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.cow_unreferenced = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.cow_nocow = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.nocow_cow = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.cow_unreadable = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.cow_unwriteable = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.permanent_entry = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_entry_fixed_overwrite_with_neighbor_tags,
		.permanent_before_permanent = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_before_permanent_fixed_overwrite_with_neighbor_tags,
		.permanent_before_allocation = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_before_allocation_fixed_overwrite_with_neighbor_tags,
		.permanent_before_allocation_2 = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_before_allocation_fixed_overwrite_with_neighbor_tags_rdar144128567,
		.permanent_before_hole = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_before_hole_fixed_overwrite_with_neighbor_tags,
		.permanent_after_allocation = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_after_allocation_fixed_overwrite_with_neighbor_tags,
		.permanent_after_hole = is_new_vm() ? test_permanent_entry_fixed_overwrite_with_neighbor_tags_rangelocked : test_permanent_after_hole_fixed_overwrite_with_neighbor_tags,

		.single_submap_single_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_submap_single_entry_first_pages = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_submap_single_entry_last_pages = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_submap_single_entry_middle_pages = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_submap_oversize_entry_at_start = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_submap_oversize_entry_at_end = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.single_submap_oversize_entry_at_both = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.submap_before_allocation = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_after_allocation = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_before_hole = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_after_hole = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_allocation_submap_one_entry = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_allocation_submap_two_entries = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_allocation_submap_three_entries = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.submap_before_allocation_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_after_allocation_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_before_hole_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_after_hole_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_allocation_submap_one_entry_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_allocation_submap_two_entries_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.submap_allocation_submap_three_entries_ro = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.protection_single_000_000 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_000_r00 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_000_0w0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_000_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_r00_r00 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_r00_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_0w0_0w0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_0w0_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_single_rw0_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,

		.protection_pairs_000_000 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_000_r00 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_000_0w0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_000_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_r00_000 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_r00_r00 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_r00_0w0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_r00_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_0w0_000 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_0w0_r00 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_0w0_0w0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_0w0_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_rw0_000 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_rw0_r00 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_rw0_0w0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
		.protection_pairs_rw0_rw0 = successful_vm_allocate_fixed_overwrite_with_neighbor_tags,
	};

	run_vm_tests("vm_allocate_fixed_overwrite_with_neighbor_tags", __FILE__, &tests, argc, argv);
}
