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
 * vm/configurator_mincore.c
 *
 * Test mincore with many different VM states.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>

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
 * This implementation can model any successful call to mincore.
 */
static test_result_t
successful_mincore_nested(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	/* mincore returns one byte per page of address range */
	assert(size % PAGE_SIZE == 0);
	mach_vm_size_t page_count = size / PAGE_SIZE;
	uint8_t *page_infos = calloc(size / PAGE_SIZE, 1);

	/* No checker updates. mincore has no VM side effects. */
	int err = mincore((void *)start, size, (char *)page_infos);
	if (err != 0) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(err, "mincore");
		free(page_infos);
		return TestFailed;
	}

	/* Verify that mincore's result matches the checker's expectation. */
	for (mach_vm_size_t page_index = 0;
	    page_index < page_count;
	    page_index++) {
		mach_vm_address_t page_address = start + page_index * PAGE_SIZE;
		uint8_t page_info = page_infos[page_index];
		vm_entry_checker_t *checker =
		    checker_list_find_checker(checker_list, page_address);

		/* descend into submaps */
		if (checker != NULL && checker->kind == Submap) {
			checker_list_t *submap_checkers DEFER_UNSLIDE =
			    checker_get_and_slide_submap_checkers(checker);
			test_result_t result = successful_mincore_nested(submap_checkers, page_address, PAGE_SIZE);
			if (result != TestSucceeded) {
				return result;
			}
			continue;
		}

		/* mappedness */
		if (checker == NULL) {
			/* fixme mincore sets MINCORE_ANONYMOUS in unallocated space? */
			T_QUIET; T_EXPECT_EQ((page_info & ~MINCORE_ANONYMOUS), 0,
			    "empty space should have zero mincore state");
			continue;
		}

		/* resident */
		bool mincore_resident = (page_info & MINCORE_INCORE);
		bool checker_resident = checker_page_at_address_is_resident(checker, page_address);
		if (mincore_resident != checker_resident) {
			T_LOG("page residency mismatch, address 0x%llx: expected %s, "
			    "mincore reported %s (0x%02hhx & MINCORE_INCORE)",
			    page_address, name_for_bool(checker_resident),
			    name_for_bool(mincore_resident), page_info);

			entry_checker_range_t range = { .head = checker, .tail = checker };
			T_LOG("*** mincore expected ***");
			dump_checker_range(range);
			T_LOG("*** actual ***");
			dump_region_info_for_entries(range);

			free(page_infos);
			return TestFailed;
		}
	}

	free(page_infos);
	return TestSucceeded;
}

static test_result_t
successful_mincore(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	test_result_t result = successful_mincore_nested(checker_list, start, size);
	if (result != TestSucceeded) {
		return result;
	}
	return verify_vm_state(checker_list, "after mincore");
}


T_DECL(mincore,
    "run mincore with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = successful_mincore,
		.single_entry_2 = successful_mincore,
		.single_entry_3 = successful_mincore,
		.single_entry_4 = successful_mincore,

		.single_entry_nonnull_1 = successful_mincore,
		.single_entry_nonnull_2 = successful_mincore,
		.single_entry_nonnull_3 = successful_mincore,
		.single_entry_nonnull_4 = successful_mincore,

		.multiple_entries_1 = successful_mincore,
		.multiple_entries_2 = successful_mincore,
		.multiple_entries_3 = successful_mincore,
		.multiple_entries_4 = successful_mincore,
		.multiple_entries_5 = successful_mincore,
		.multiple_entries_6 = successful_mincore,

		.some_holes_1 = successful_mincore,
		.some_holes_2 = successful_mincore,
		.some_holes_3 = successful_mincore,
		.some_holes_4 = successful_mincore,
		.some_holes_5 = successful_mincore,
		.some_holes_6 = successful_mincore,
		.some_holes_7 = successful_mincore,
		.some_holes_8 = successful_mincore,
		.some_holes_9 = successful_mincore,
		.some_holes_10 = successful_mincore,
		.some_holes_11 = successful_mincore,
		.some_holes_12 = successful_mincore,

		.all_holes_1 = successful_mincore,
		.all_holes_2 = successful_mincore,
		.all_holes_3 = successful_mincore,
		.all_holes_4 = successful_mincore,

		.null_entry                 = successful_mincore,
		.nonresident_entry          = successful_mincore,
		.resident_entry             = successful_mincore,

		.shared_entry               = successful_mincore,
		.shared_entry_discontiguous = successful_mincore,
		.shared_entry_partial       = successful_mincore,
		.shared_entry_pairs         = successful_mincore,
		.shared_entry_x1000         = successful_mincore,

		.cow_entry = successful_mincore,
		.cow_unreferenced = successful_mincore,
		.cow_nocow = successful_mincore,
		.nocow_cow = successful_mincore,
		.cow_unreadable = successful_mincore,
		.cow_unwriteable = successful_mincore,

		.permanent_entry = successful_mincore,
		.permanent_before_permanent = successful_mincore,
		.permanent_before_allocation = successful_mincore,
		.permanent_before_allocation_2 = successful_mincore,
		.permanent_before_hole = successful_mincore,
		.permanent_after_allocation = successful_mincore,
		.permanent_after_hole = successful_mincore,

		.single_submap_single_entry = successful_mincore,
		.single_submap_single_entry_first_pages = successful_mincore,
		.single_submap_single_entry_last_pages = successful_mincore,
		.single_submap_single_entry_middle_pages = successful_mincore,
		.single_submap_oversize_entry_at_start = successful_mincore,
		.single_submap_oversize_entry_at_end = successful_mincore,
		.single_submap_oversize_entry_at_both = successful_mincore,

		.submap_before_allocation = successful_mincore,
		.submap_after_allocation = successful_mincore,
		.submap_before_hole = successful_mincore,
		.submap_after_hole = successful_mincore,
		.submap_allocation_submap_one_entry = successful_mincore,
		.submap_allocation_submap_two_entries = successful_mincore,
		.submap_allocation_submap_three_entries = successful_mincore,

		.submap_before_allocation_ro = successful_mincore,
		.submap_after_allocation_ro = successful_mincore,
		.submap_before_hole_ro = successful_mincore,
		.submap_after_hole_ro = successful_mincore,
		.submap_allocation_submap_one_entry_ro = successful_mincore,
		.submap_allocation_submap_two_entries_ro = successful_mincore,
		.submap_allocation_submap_three_entries_ro = successful_mincore,

		.protection_single_000_000 = successful_mincore,
		.protection_single_000_r00 = successful_mincore,
		.protection_single_000_0w0 = successful_mincore,
		.protection_single_000_rw0 = successful_mincore,
		.protection_single_r00_r00 = successful_mincore,
		.protection_single_r00_rw0 = successful_mincore,
		.protection_single_0w0_0w0 = successful_mincore,
		.protection_single_0w0_rw0 = successful_mincore,
		.protection_single_rw0_rw0 = successful_mincore,

		.protection_pairs_000_000 = successful_mincore,
		.protection_pairs_000_r00 = successful_mincore,
		.protection_pairs_000_0w0 = successful_mincore,
		.protection_pairs_000_rw0 = successful_mincore,
		.protection_pairs_r00_000 = successful_mincore,
		.protection_pairs_r00_r00 = successful_mincore,
		.protection_pairs_r00_0w0 = successful_mincore,
		.protection_pairs_r00_rw0 = successful_mincore,
		.protection_pairs_0w0_000 = successful_mincore,
		.protection_pairs_0w0_r00 = successful_mincore,
		.protection_pairs_0w0_0w0 = successful_mincore,
		.protection_pairs_0w0_rw0 = successful_mincore,
		.protection_pairs_rw0_000 = successful_mincore,
		.protection_pairs_rw0_r00 = successful_mincore,
		.protection_pairs_rw0_0w0 = successful_mincore,
		.protection_pairs_rw0_rw0 = successful_mincore,
	};

	run_vm_tests("mincore", __FILE__, &tests, argc, argv);
}
