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
 * vm/configurator_vm_protect.c
 *
 * Test vm_protect with many different VM states.
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
 * Update checker state to mirror a successful call to vm_protect.
 */
static void
checker_perform_vm_protect(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	bool set_max,
	vm_prot_t prot)
{
	entry_checker_range_t limit =
	    checker_list_find_and_clip(checker_list, start, size);
	FOREACH_CHECKER(checker, limit) {
		if (set_max) {
			checker->max_protection = prot;
			checker->protection &= checker->max_protection;
		} else {
			checker->protection = prot;
		}
	}
	checker_list_simplify(checker_list, start, size);
}

/*
 * Perform and check a call to mach_vm_protect that is expected to succeed.
 */
static test_result_t
vm_protect_successfully(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	vm_prot_t prot)
{
	kern_return_t kr;

	bool set_max = false;

	checker_perform_vm_protect(checker_list, start, size, set_max, prot);
	kr = mach_vm_protect(mach_task_self(), start, size, set_max, prot);
	if (kr != 0) {
		T_FAIL("mach_vm_protect(%s) failed (%s)",
		    name_for_prot(prot), name_for_kr(kr));
		return TestFailed;
	}

	TEMP_CSTRING(name, "after vm_protect(%s)", name_for_prot(prot));
	return verify_vm_state(checker_list, name);
}

/*
 * Perform and check mach_vm_protect that is expected to fail due to holes.
 */
static test_result_t
vm_protect_with_holes(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	kern_return_t kr;

	if (is_new_vm()) {
		/*
		 * Range-locking VM clips the start and
		 * does not simplify after the failure.
		 */
		vm_entry_checker_t *checker =
		    checker_list_find_checker(checker_list, start);
		if (checker && checker->kind == Allocation) {
			checker_clip_left(checker_list, checker, start);
		}
	} else {
		/*
		 * No checker updates here. vm_map_protect preflights its checks,
		 * so it fails with no side effects when the address range has holes.
		 */
	}

	kr = mach_vm_protect(mach_task_self(), start, size, false, VM_PROT_READ);
	if (kr != KERN_INVALID_ADDRESS) {
		T_FAIL("mach_vm_protect(holes) expected %s, got %s\n",
		    name_for_kr(KERN_INVALID_ADDRESS), name_for_kr(kr));
		return TestFailed;
	}

	return verify_vm_state(checker_list, "after vm_protect");
}

/*
 * Perform and check mach_vm_protect that is expected to fail because
 * the requested protections are more permissive than max_protection.
 */
static test_result_t
vm_protect_beyond_max_prot(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size,
	vm_prot_t prot)
{
	kern_return_t kr;

	/*
	 * No checker updates here. vm_map_protect preflights its checks,
	 * so it fails with no effect.
	 */

	kr = mach_vm_protect(mach_task_self(), start, size, false /*set max*/, prot);
	if (kr != KERN_PROTECTION_FAILURE) {
		T_FAIL("mach_vm_protect(%s which is beyond max) expected %s, got %s\n",
		    name_for_prot(prot),
		    name_for_kr(KERN_PROTECTION_FAILURE), name_for_kr(kr));
		return TestFailed;
	}

	TEMP_CSTRING(name, "after vm_protect(%s)", name_for_prot(prot));
	return verify_vm_state(checker_list, name);
}


/*
 * Perform multiple successful and unsuccessful vm_protect operations
 * on a region whose max_protections are VM_PROT_NONE
 */
static test_result_t
vm_protect_max_000(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	test_result_t results[4];

	results[0] = vm_protect_successfully(checker_list, start, size, VM_PROT_NONE);
	results[1] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_READ);
	results[2] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_WRITE);
	results[3] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_READ | VM_PROT_WRITE);

	return worst_result(results, countof(results));
}

/*
 * Perform multiple successful and unsuccessful vm_protect operations
 * on a region whose max_protections are VM_PROT_READ
 */
static test_result_t
vm_protect_max_r00(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	test_result_t results[4];

	results[0] = vm_protect_successfully(checker_list, start, size, VM_PROT_NONE);
	results[1] = vm_protect_successfully(checker_list, start, size, VM_PROT_READ);
	results[2] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_WRITE);
	results[3] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_READ | VM_PROT_WRITE);

	return worst_result(results, countof(results));
}

/*
 * Perform multiple successful and unsuccessful vm_protect operations
 * on a region whose max_protections are VM_PROT_WRITE
 */
static test_result_t
vm_protect_max_0w0(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	test_result_t results[4];

	results[0] = vm_protect_successfully(checker_list, start, size, VM_PROT_NONE);
	results[1] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_READ);
	results[2] = vm_protect_successfully(checker_list, start, size, VM_PROT_WRITE);
	results[3] = vm_protect_beyond_max_prot(checker_list, start, size, VM_PROT_READ | VM_PROT_WRITE);

	return worst_result(results, countof(results));
}


/*
 * Perform multiple successful and unsuccessful vm_protect operations
 * on a region whose max_protections are VM_PROT_READ | VM_PROT_WRITE
 */
static test_result_t
vm_protect_max_rw0(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	test_result_t results[4];

	results[0] = vm_protect_successfully(checker_list, start, size, VM_PROT_NONE);
	results[1] = vm_protect_successfully(checker_list, start, size, VM_PROT_READ);
	results[2] = vm_protect_successfully(checker_list, start, size, VM_PROT_WRITE);
	results[3] = vm_protect_successfully(checker_list, start, size, VM_PROT_READ | VM_PROT_WRITE);

	return worst_result(results, countof(results));
}

#if __x86_64__
/*
 * Perform multiple successful and unsuccessful vm_protect operations
 * on a region whose max_protections are VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC
 */
static test_result_t
vm_protect_max_rwx(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	/* TODO VM_PROT_EXEC */
	return vm_protect_max_rw0(checker_list, start, size);
}
#endif  /* __x86_64__ */

/*
 * Perform multiple successful and unsuccessful vm_protect operations
 * on a region whose max_protections are VM_PROT_READ
 * OR whose max protections are READ|WRITE|EXEC due to Intel submap unnesting.
 */
static test_result_t
vm_protect_max_r00_or_unnested_submap(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
#if __x86_64__
	return vm_protect_max_rwx(checker_list, start, size);
#else  /* not __x86_64__ */
	return vm_protect_max_r00(checker_list, start, size);
#endif /* not __x86_64__ */
}

T_DECL(vm_protect,
    "run vm_protect with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = vm_protect_max_rw0,
		.single_entry_2 = vm_protect_max_rw0,
		.single_entry_3 = vm_protect_max_rw0,
		.single_entry_4 = vm_protect_max_rw0,

		.single_entry_nonnull_1 = vm_protect_max_rw0,
		.single_entry_nonnull_2 = vm_protect_max_rw0,
		.single_entry_nonnull_3 = vm_protect_max_rw0,
		.single_entry_nonnull_4 = vm_protect_max_rw0,

		.multiple_entries_1 = vm_protect_max_rw0,
		.multiple_entries_2 = vm_protect_max_rw0,
		.multiple_entries_3 = vm_protect_max_rw0,
		.multiple_entries_4 = vm_protect_max_rw0,
		.multiple_entries_5 = vm_protect_max_rw0,
		.multiple_entries_6 = vm_protect_max_rw0,

		.some_holes_1 = vm_protect_with_holes,
		.some_holes_2 = vm_protect_with_holes,
		.some_holes_3 = vm_protect_with_holes,
		.some_holes_4 = vm_protect_with_holes,
		.some_holes_5 = vm_protect_with_holes,
		.some_holes_6 = vm_protect_with_holes,
		.some_holes_7 = vm_protect_with_holes,
		.some_holes_8 = vm_protect_with_holes,
		.some_holes_9 = vm_protect_with_holes,
		.some_holes_10 = vm_protect_with_holes,
		.some_holes_11 = vm_protect_with_holes,
		.some_holes_12 = vm_protect_with_holes,

		.all_holes_1 = vm_protect_with_holes,
		.all_holes_2 = vm_protect_with_holes,
		.all_holes_3 = vm_protect_with_holes,
		.all_holes_4 = vm_protect_with_holes,

		.null_entry        = vm_protect_max_rw0,
		.nonresident_entry = vm_protect_max_rw0,
		.resident_entry    = vm_protect_max_rw0,

		.shared_entry               = vm_protect_max_rw0,
		.shared_entry_discontiguous = vm_protect_max_rw0,
		.shared_entry_partial       = vm_protect_max_rw0,
		.shared_entry_pairs         = vm_protect_max_rw0,
		.shared_entry_x1000         = vm_protect_max_rw0,

		.cow_entry = vm_protect_max_rw0,
		.cow_unreferenced = vm_protect_max_rw0,
		.cow_nocow = vm_protect_max_rw0,
		.nocow_cow = vm_protect_max_rw0,
		.cow_unreadable = vm_protect_max_rw0,
		.cow_unwriteable = vm_protect_max_rw0,

		.permanent_entry = vm_protect_max_rw0,
		.permanent_before_permanent = vm_protect_max_rw0,
		.permanent_before_allocation = vm_protect_max_rw0,
		.permanent_before_allocation_2 = vm_protect_max_rw0,
		.permanent_before_hole = vm_protect_with_holes,
		.permanent_after_allocation = vm_protect_max_rw0,
		.permanent_after_hole = vm_protect_with_holes,

		/*
		 * vm_protect without VM_PROT_COPY does not descend into submaps.
		 * The parent map's submap entry is r--/r--.
		 */
		.single_submap_single_entry = vm_protect_max_r00_or_unnested_submap,
		.single_submap_single_entry_first_pages = vm_protect_max_r00_or_unnested_submap,
		.single_submap_single_entry_last_pages = vm_protect_max_r00_or_unnested_submap,
		.single_submap_single_entry_middle_pages = vm_protect_max_r00_or_unnested_submap,
		.single_submap_oversize_entry_at_start = vm_protect_max_r00_or_unnested_submap,
		.single_submap_oversize_entry_at_end = vm_protect_max_r00_or_unnested_submap,
		.single_submap_oversize_entry_at_both = vm_protect_max_r00_or_unnested_submap,

		.submap_before_allocation = vm_protect_max_r00_or_unnested_submap,
		.submap_after_allocation = vm_protect_max_r00_or_unnested_submap,
		.submap_before_hole = vm_protect_with_holes,
		.submap_after_hole = vm_protect_with_holes,
		.submap_allocation_submap_one_entry = vm_protect_max_r00_or_unnested_submap,
		.submap_allocation_submap_two_entries = vm_protect_max_r00_or_unnested_submap,
		.submap_allocation_submap_three_entries = vm_protect_max_r00_or_unnested_submap,

		.submap_before_allocation_ro = vm_protect_max_r00_or_unnested_submap,
		.submap_after_allocation_ro = vm_protect_max_r00_or_unnested_submap,
		.submap_before_hole_ro = vm_protect_with_holes,
		.submap_after_hole_ro = vm_protect_with_holes,
		.submap_allocation_submap_one_entry_ro = vm_protect_max_r00_or_unnested_submap,
		.submap_allocation_submap_two_entries_ro = vm_protect_max_r00_or_unnested_submap,
		.submap_allocation_submap_three_entries_ro = vm_protect_max_r00_or_unnested_submap,

		.protection_single_000_000 = vm_protect_max_000,
		.protection_single_000_r00 = vm_protect_max_r00,
		.protection_single_r00_r00 = vm_protect_max_r00,
		.protection_single_000_0w0 = vm_protect_max_0w0,
		.protection_single_0w0_0w0 = vm_protect_max_0w0,
		.protection_single_000_rw0 = vm_protect_max_rw0,
		.protection_single_r00_rw0 = vm_protect_max_rw0,
		.protection_single_0w0_rw0 = vm_protect_max_rw0,
		.protection_single_rw0_rw0 = vm_protect_max_rw0,

		.protection_pairs_000_000 = vm_protect_max_rw0,
		.protection_pairs_000_r00 = vm_protect_max_rw0,
		.protection_pairs_000_0w0 = vm_protect_max_rw0,
		.protection_pairs_000_rw0 = vm_protect_max_rw0,
		.protection_pairs_r00_000 = vm_protect_max_rw0,
		.protection_pairs_r00_r00 = vm_protect_max_rw0,
		.protection_pairs_r00_0w0 = vm_protect_max_rw0,
		.protection_pairs_r00_rw0 = vm_protect_max_rw0,
		.protection_pairs_0w0_000 = vm_protect_max_rw0,
		.protection_pairs_0w0_r00 = vm_protect_max_rw0,
		.protection_pairs_0w0_0w0 = vm_protect_max_rw0,
		.protection_pairs_0w0_rw0 = vm_protect_max_rw0,
		.protection_pairs_rw0_000 = vm_protect_max_rw0,
		.protection_pairs_rw0_r00 = vm_protect_max_rw0,
		.protection_pairs_rw0_0w0 = vm_protect_max_rw0,
		.protection_pairs_rw0_rw0 = vm_protect_max_rw0,
	};

	run_vm_tests("vm_protect", __FILE__, &tests, argc, argv);
}
