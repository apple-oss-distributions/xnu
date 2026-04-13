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
#include <sys/mman.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.configurator"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),  /* required for vm submap sysctls */
	T_META_ALL_VALID_ARCHS(true)
	);

static int
overwrite_permanent_errno(void)
{
	switch (overwrite_permanent_error()) {
	case KERN_PROTECTION_FAILURE:
		return EACCES;
	case KERN_NO_SPACE:
		return ENOMEM;
	default:
		T_FAIL("unrecognized value from overwrite_permanent_error()");
		T_END;
	}
}

static void
checker_perform_successful_mmap_anon(
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

static test_result_t
successful_mmap_anon_fixed(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	void *ret = mmap((void *)start, size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
	mach_vm_address_t allocated = (mach_vm_address_t)ret;
	if (ret == MAP_FAILED) {
		T_WITH_ERRNO; T_FAIL("mmap(ANON | FIXED)");
		return TestFailed;
	}
	if (allocated != start) {
		T_FAIL("mmap(ANON | FIXED) returned address 0x%llx (expected 0x%llx)", allocated, start);
		return TestFailed;
	}
	checker_perform_successful_mmap_anon(checker_list, start, size, 0);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}


static test_result_t
successful_mmap_anon_fixed_with_tag(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	uint16_t tag)
{
	void *ret = mmap((void *)start, size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_FIXED, VM_MAKE_TAG(tag), 0);
	mach_vm_address_t allocated = (mach_vm_address_t)ret;
	if (ret == MAP_FAILED) {
		T_WITH_ERRNO; T_FAIL("mmap(ANON | FIXED, tag)");
		return TestFailed;
	}
	if (allocated != start) {
		T_FAIL("mmap(ANON | FIXED, tag) returned address 0x%llx (expected 0x%llx)", allocated, start);
		return TestFailed;
	}
	checker_perform_successful_mmap_anon(checker_list, start, size, tag);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED, tag)");
}

static test_result_t
successful_mmap_anon_fixed_with_neighbor_tags(
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
	if (TestFailed == successful_mmap_anon_fixed_with_tag(
		    checker_list, start, size, tag)) {
		return TestFailed;
	}

	/*
	 * Allocate again, with a tag matching the entry to the right,
	 * to probe simplify behavior.
	 */
	tag = get_app_specific_user_tag_for_address(start + size);
	if (TestFailed == successful_mmap_anon_fixed_with_tag(
		    checker_list, start, size, tag)) {
		return TestFailed;
	}

	return TestSucceeded;
}

static bool
call_mmap_anon_fixed_overwriting_permanent(
	mach_vm_address_t start,
	mach_vm_size_t size,
	uint16_t tag)
{
#if workaround_rdar_143341561
	__block void *ret;
	__block int saved_errno;
	exc_guard_helper_info_t exc_info;
	/* BEGIN IGNORE CODESTYLE */
	bool caught_exception = block_raised_exc_guard_of_type(GUARD_TYPE_VIRT_MEMORY, &exc_info, ^{
		ret = mmap((void *)start, size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON | MAP_FIXED, VM_MAKE_TAG(tag), 0);
		    saved_errno = errno;
	});
	/* END IGNORE CODESTYLE */
	if (caught_exception) {
		T_LOG("warning: rdar://143341561 mmap(fixed) should work "
		    "regardless of whether a mapping exists at the addr");
	}
	errno = saved_errno;
#else  /* not workaround_rdar_143341561 */
	void *ret = mmap((void *)start, size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_FIXED, VM_MAKE_TAG(tag), 0);
#endif /* not workaround_rdar_143341561 */

	T_EXPECT_POSIX_FAILURE((uintptr_t)ret, overwrite_permanent_errno(), "mmap");
	return ret == MAP_FAILED && errno == overwrite_permanent_errno();
}


static test_result_t
test_permanent_entry_fixed_rangelocked(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/*
	 * No checker updates. Any fixed|overwrite atop a permanent entry
	 * fails during preflight.
	 */

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_entry_fixed_with_neighbor_tags_rangelocked(
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

	uint16_t tag;

	/*
	 * Allocate with a tag matching the entry to the left,
	 */
	tag = get_user_tag_for_address(start - 1);
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/*
	 * No checker updates. Any fixed|overwrite atop a permanent entry
	 * fails during preflight.
	 */

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}


static test_result_t
test_permanent_entry_fixed(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/* one permanent entry, it becomes inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_permanent_fixed(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/* two permanent entries, both become inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_allocation_fixed(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* [start + size/2, start + size) unchanged */

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_allocation_fixed_rdar144128567(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/*
	 * old vm:
	 *   one permanent entry, becomes inaccessible
	 *   one nonpermanent allocation, becomes deallocated (rdar://144128567)
	 * new vm:
	 *   rejected by preflight, everything untouched
	 */
	if (!is_new_vm()) {
		checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
		checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);
	}

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_hole_fixed(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one hole, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no change for addresses [start + size / 2, start + size) */

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_after_allocation_fixed(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/*
	 * one nonpermanent allocation, becomes deallocated
	 * one permanent entry, becomes inaccessible
	 */
	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_after_hole_fixed(
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

	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, 0)) {
		return TestFailed;
	}

	/*
	 * one hole, unchanged
	 * one permanent entry, becomes inaccessible
	 */
	/* no change for addresses [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}


static test_result_t
test_permanent_entry_fixed_with_neighbor_tags(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/* one permanent entry, it becomes inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_permanent_fixed_with_neighbor_tags(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/* two permanent entries, both become inaccessible */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_allocation_fixed_with_neighbor_tags(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one nonpermanent allocation, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* [start + size/2, start + size) unchanged */

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_allocation_fixed_with_neighbor_tags_rdar144128567(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/*
	 * old vm:
	 *   one permanent entry, becomes inaccessible
	 *   one nonpermanent allocation, becomes deallocated (rdar://144128567)
	 * new vm:
	 *   rejected by preflight, everything untouched
	 */
	if (!is_new_vm()) {
		checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
		checker_perform_successful_vm_deallocate(checker_list, start + size / 2, size / 2);
	}

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_before_hole_fixed_with_neighbor_tags(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/*
	 * one permanent entry, becomes inaccessible
	 * one hole, unchanged
	 */
	checker_perform_vm_deallocate_permanent(checker_list, start, size / 2);
	/* no change for addresses [start + size / 2, start + size) */

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_after_allocation_fixed_with_neighbor_tags(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/*
	 * one nonpermanent allocation, becomes deallocated
	 * one permanent entry, becomes inaccessible
	 */
	checker_perform_successful_vm_deallocate(checker_list, start, size / 2);
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}

static test_result_t
test_permanent_after_hole_fixed_with_neighbor_tags(
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
	if (!call_mmap_anon_fixed_overwriting_permanent(start, size, tag)) {
		return TestFailed;
	}

	/*
	 * one hole, unchanged
	 * one permanent entry, becomes inaccessible
	 */
	/* no change for addresses [start, start + size / 2) */
	checker_perform_vm_deallocate_permanent(checker_list, start + size / 2, size / 2);

	return verify_vm_state(checker_list, "after mmap(ANON | FIXED)");
}


T_DECL(mmap_anon_fixed,
    "run mmap(ANON | FIXED) with various vm configurations")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_mmap_anon_fixed,
		.single_entry_2 = successful_mmap_anon_fixed,
		.single_entry_3 = successful_mmap_anon_fixed,
		.single_entry_4 = successful_mmap_anon_fixed,

		.single_entry_nonnull_1 = successful_mmap_anon_fixed,
		.single_entry_nonnull_2 = successful_mmap_anon_fixed,
		.single_entry_nonnull_3 = successful_mmap_anon_fixed,
		.single_entry_nonnull_4 = successful_mmap_anon_fixed,

		.multiple_entries_1 = successful_mmap_anon_fixed,
		.multiple_entries_2 = successful_mmap_anon_fixed,
		.multiple_entries_3 = successful_mmap_anon_fixed,
		.multiple_entries_4 = successful_mmap_anon_fixed,
		.multiple_entries_5 = successful_mmap_anon_fixed,
		.multiple_entries_6 = successful_mmap_anon_fixed,

		.some_holes_1 = successful_mmap_anon_fixed,
		.some_holes_2 = successful_mmap_anon_fixed,
		.some_holes_3 = successful_mmap_anon_fixed,
		.some_holes_4 = successful_mmap_anon_fixed,
		.some_holes_5 = successful_mmap_anon_fixed,
		.some_holes_6 = successful_mmap_anon_fixed,
		.some_holes_7 = successful_mmap_anon_fixed,
		.some_holes_8 = successful_mmap_anon_fixed,
		.some_holes_9 = successful_mmap_anon_fixed,
		.some_holes_10 = successful_mmap_anon_fixed,
		.some_holes_11 = successful_mmap_anon_fixed,
		.some_holes_12 = successful_mmap_anon_fixed,

		.all_holes_1 = successful_mmap_anon_fixed,
		.all_holes_2 = successful_mmap_anon_fixed,
		.all_holes_3 = successful_mmap_anon_fixed,
		.all_holes_4 = successful_mmap_anon_fixed,

		.null_entry = successful_mmap_anon_fixed,
		.nonresident_entry = successful_mmap_anon_fixed,
		.resident_entry = successful_mmap_anon_fixed,

		.shared_entry = successful_mmap_anon_fixed,
		.shared_entry_discontiguous = successful_mmap_anon_fixed,
		.shared_entry_partial = successful_mmap_anon_fixed,
		.shared_entry_pairs = successful_mmap_anon_fixed,
		.shared_entry_x1000 = successful_mmap_anon_fixed,

		.cow_entry = successful_mmap_anon_fixed,
		.cow_unreferenced = successful_mmap_anon_fixed,
		.cow_nocow = successful_mmap_anon_fixed,
		.nocow_cow = successful_mmap_anon_fixed,
		.cow_unreadable = successful_mmap_anon_fixed,
		.cow_unwriteable = successful_mmap_anon_fixed,

		.permanent_entry = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_entry_fixed,
		.permanent_before_permanent = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_before_permanent_fixed,
		.permanent_before_allocation = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_before_allocation_fixed,
		.permanent_before_allocation_2 = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_before_allocation_fixed_rdar144128567,
		.permanent_before_hole = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_before_hole_fixed,
		.permanent_after_allocation = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_after_allocation_fixed,
		.permanent_after_hole = is_new_vm() ? test_permanent_entry_fixed_rangelocked : test_permanent_after_hole_fixed,

		.single_submap_single_entry = successful_mmap_anon_fixed,
		.single_submap_single_entry_first_pages = successful_mmap_anon_fixed,
		.single_submap_single_entry_last_pages = successful_mmap_anon_fixed,
		.single_submap_single_entry_middle_pages = successful_mmap_anon_fixed,
		.single_submap_oversize_entry_at_start = successful_mmap_anon_fixed,
		.single_submap_oversize_entry_at_end = successful_mmap_anon_fixed,
		.single_submap_oversize_entry_at_both = successful_mmap_anon_fixed,

		.submap_before_allocation = successful_mmap_anon_fixed,
		.submap_after_allocation = successful_mmap_anon_fixed,
		.submap_before_hole = successful_mmap_anon_fixed,
		.submap_after_hole = successful_mmap_anon_fixed,
		.submap_allocation_submap_one_entry = successful_mmap_anon_fixed,
		.submap_allocation_submap_two_entries = successful_mmap_anon_fixed,
		.submap_allocation_submap_three_entries = successful_mmap_anon_fixed,

		.submap_before_allocation_ro = successful_mmap_anon_fixed,
		.submap_after_allocation_ro = successful_mmap_anon_fixed,
		.submap_before_hole_ro = successful_mmap_anon_fixed,
		.submap_after_hole_ro = successful_mmap_anon_fixed,
		.submap_allocation_submap_one_entry_ro = successful_mmap_anon_fixed,
		.submap_allocation_submap_two_entries_ro = successful_mmap_anon_fixed,
		.submap_allocation_submap_three_entries_ro = successful_mmap_anon_fixed,

		.protection_single_000_000 = successful_mmap_anon_fixed,
		.protection_single_000_r00 = successful_mmap_anon_fixed,
		.protection_single_000_0w0 = successful_mmap_anon_fixed,
		.protection_single_000_rw0 = successful_mmap_anon_fixed,
		.protection_single_r00_r00 = successful_mmap_anon_fixed,
		.protection_single_r00_rw0 = successful_mmap_anon_fixed,
		.protection_single_0w0_0w0 = successful_mmap_anon_fixed,
		.protection_single_0w0_rw0 = successful_mmap_anon_fixed,
		.protection_single_rw0_rw0 = successful_mmap_anon_fixed,

		.protection_pairs_000_000 = successful_mmap_anon_fixed,
		.protection_pairs_000_r00 = successful_mmap_anon_fixed,
		.protection_pairs_000_0w0 = successful_mmap_anon_fixed,
		.protection_pairs_000_rw0 = successful_mmap_anon_fixed,
		.protection_pairs_r00_000 = successful_mmap_anon_fixed,
		.protection_pairs_r00_r00 = successful_mmap_anon_fixed,
		.protection_pairs_r00_0w0 = successful_mmap_anon_fixed,
		.protection_pairs_r00_rw0 = successful_mmap_anon_fixed,
		.protection_pairs_0w0_000 = successful_mmap_anon_fixed,
		.protection_pairs_0w0_r00 = successful_mmap_anon_fixed,
		.protection_pairs_0w0_0w0 = successful_mmap_anon_fixed,
		.protection_pairs_0w0_rw0 = successful_mmap_anon_fixed,
		.protection_pairs_rw0_000 = successful_mmap_anon_fixed,
		.protection_pairs_rw0_r00 = successful_mmap_anon_fixed,
		.protection_pairs_rw0_0w0 = successful_mmap_anon_fixed,
		.protection_pairs_rw0_rw0 = successful_mmap_anon_fixed,
	};

	run_vm_tests("mmap_anon_fixed", __FILE__, &tests, argc, argv);
}


T_DECL(mmap_anon_fixed_with_neighbor_tags,
    "run mmap(ANON | FIXED, tag) with various vm configurations "
    "and tags copied from neighboring entries")
{
#if workaround_rdar_143341561
	enable_non_fatal_vm_exc_guard();
#endif

	vm_tests_t tests = {
		.single_entry_1 = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_entry_2 = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_entry_3 = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_entry_4 = successful_mmap_anon_fixed_with_neighbor_tags,

		.single_entry_nonnull_1 = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_entry_nonnull_2 = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_entry_nonnull_3 = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_entry_nonnull_4 = successful_mmap_anon_fixed_with_neighbor_tags,

		.multiple_entries_1 = successful_mmap_anon_fixed_with_neighbor_tags,
		.multiple_entries_2 = successful_mmap_anon_fixed_with_neighbor_tags,
		.multiple_entries_3 = successful_mmap_anon_fixed_with_neighbor_tags,
		.multiple_entries_4 = successful_mmap_anon_fixed_with_neighbor_tags,
		.multiple_entries_5 = successful_mmap_anon_fixed_with_neighbor_tags,
		.multiple_entries_6 = successful_mmap_anon_fixed_with_neighbor_tags,

		.some_holes_1 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_2 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_3 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_4 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_5 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_6 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_7 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_8 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_9 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_10 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_11 = successful_mmap_anon_fixed_with_neighbor_tags,
		.some_holes_12 = successful_mmap_anon_fixed_with_neighbor_tags,

		.all_holes_1 = successful_mmap_anon_fixed_with_neighbor_tags,
		.all_holes_2 = successful_mmap_anon_fixed_with_neighbor_tags,
		.all_holes_3 = successful_mmap_anon_fixed_with_neighbor_tags,
		.all_holes_4 = successful_mmap_anon_fixed_with_neighbor_tags,

		.null_entry = successful_mmap_anon_fixed_with_neighbor_tags,
		.nonresident_entry = successful_mmap_anon_fixed_with_neighbor_tags,
		.resident_entry = successful_mmap_anon_fixed_with_neighbor_tags,

		.shared_entry = successful_mmap_anon_fixed_with_neighbor_tags,
		.shared_entry_discontiguous = successful_mmap_anon_fixed_with_neighbor_tags,
		.shared_entry_partial = successful_mmap_anon_fixed_with_neighbor_tags,
		.shared_entry_pairs = successful_mmap_anon_fixed_with_neighbor_tags,
		.shared_entry_x1000 = successful_mmap_anon_fixed_with_neighbor_tags,

		.cow_entry = successful_mmap_anon_fixed_with_neighbor_tags,
		.cow_unreferenced = successful_mmap_anon_fixed_with_neighbor_tags,
		.cow_nocow = successful_mmap_anon_fixed_with_neighbor_tags,
		.nocow_cow = successful_mmap_anon_fixed_with_neighbor_tags,
		.cow_unreadable = successful_mmap_anon_fixed_with_neighbor_tags,
		.cow_unwriteable = successful_mmap_anon_fixed_with_neighbor_tags,

		.permanent_entry = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_entry_fixed_with_neighbor_tags,
		.permanent_before_permanent = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_before_permanent_fixed_with_neighbor_tags,
		.permanent_before_allocation = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_before_allocation_fixed_with_neighbor_tags,
		.permanent_before_allocation_2 = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_before_allocation_fixed_with_neighbor_tags_rdar144128567,
		.permanent_before_hole = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_before_hole_fixed_with_neighbor_tags,
		.permanent_after_allocation = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_after_allocation_fixed_with_neighbor_tags,
		.permanent_after_hole = is_new_vm() ? test_permanent_entry_fixed_with_neighbor_tags_rangelocked : test_permanent_after_hole_fixed_with_neighbor_tags,

		.single_submap_single_entry = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_submap_single_entry_first_pages = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_submap_single_entry_last_pages = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_submap_single_entry_middle_pages = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_submap_oversize_entry_at_start = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_submap_oversize_entry_at_end = successful_mmap_anon_fixed_with_neighbor_tags,
		.single_submap_oversize_entry_at_both = successful_mmap_anon_fixed_with_neighbor_tags,

		.submap_before_allocation = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_after_allocation = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_before_hole = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_after_hole = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_allocation_submap_one_entry = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_allocation_submap_two_entries = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_allocation_submap_three_entries = successful_mmap_anon_fixed_with_neighbor_tags,

		.submap_before_allocation_ro = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_after_allocation_ro = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_before_hole_ro = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_after_hole_ro = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_allocation_submap_one_entry_ro = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_allocation_submap_two_entries_ro = successful_mmap_anon_fixed_with_neighbor_tags,
		.submap_allocation_submap_three_entries_ro = successful_mmap_anon_fixed_with_neighbor_tags,

		.protection_single_000_000 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_000_r00 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_000_0w0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_000_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_r00_r00 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_r00_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_0w0_0w0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_0w0_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_single_rw0_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,

		.protection_pairs_000_000 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_000_r00 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_000_0w0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_000_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_r00_000 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_r00_r00 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_r00_0w0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_r00_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_0w0_000 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_0w0_r00 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_0w0_0w0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_0w0_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_rw0_000 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_rw0_r00 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_rw0_0w0 = successful_mmap_anon_fixed_with_neighbor_tags,
		.protection_pairs_rw0_rw0 = successful_mmap_anon_fixed_with_neighbor_tags,
	};

	run_vm_tests("mmap_anon_fixed_with_neighbor_tags", __FILE__, &tests, argc, argv);
}
