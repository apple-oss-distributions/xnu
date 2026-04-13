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
 * vm/configurator_fault_read.c
 *
 * Test read and write faults with many different VM states.
 */

#include <ptrauth.h>
#include "configurator/vm_configurator_tests.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.configurator"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),  /* required for vm submap sysctls */
	T_META_ALL_VALID_ARCHS(true)
	);


static bool
test_fault_one_checker_in_address_range(
	vm_entry_checker_t *checker,
	bool is_write_fault,
	bool in_submap,
	mach_vm_address_t checked_address,
	mach_vm_size_t checked_size)
{
	TEMP_CSTRING(message, "after %s 0x%llx..0x%llx%s",
	    is_write_fault ? "writing" : "reading",
	    checked_address, checked_address + checked_size,
	    in_submap ? " (in submap)" : "");
	bool verify_reads = !is_write_fault;
	bool verify_writes = is_write_fault;
	bool good = verify_checker_faultability_in_address_range(checker,
	    message, verify_reads, verify_writes, checked_address, checked_size);
	return good;
}

/*
 * Call verify_checker_faultability() for one checker.
 * Advance *inout_next_address_to_fault past it.
 */
static bool
test_fault_one_checker(
	vm_entry_checker_t *checker,
	bool is_write_fault,
	bool in_submap,
	mach_vm_address_t * const inout_next_address_to_fault)
{
	bool good = test_fault_one_checker_in_address_range(checker,
	    is_write_fault, in_submap, checker->address, checker->size);
	*inout_next_address_to_fault = checker_end_address(checker);
	return good;
}

/*
 * Call verify_checker_faultability() for one allocation checker.
 * Advance *inout_next_address_to_fault past it.
 */
static bool
test_fault_one_allocation(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	bool is_write_fault,
	bool in_submap,
	mach_vm_address_t *const inout_next_address_to_fault)
{
	checker_fault_all(checker_list, checker,
	    is_write_fault ? VM_PROT_WRITE : VM_PROT_READ);
	return test_fault_one_checker(checker, is_write_fault, in_submap, inout_next_address_to_fault);
}

/*
 * Call verify_checker_faultability() for one parent map submap checker,
 * or some portion thereof.
 * Advance *inout_next_address_to_fault past the verified range.
 */
static bool
test_fault_one_submap(
	checker_list_t *checker_list,
	vm_entry_checker_t *submap_parent,
	bool is_write_fault,
	mach_vm_address_t *const inout_next_address_to_fault)
{
	mach_vm_address_t next_address_to_fault = *inout_next_address_to_fault;

	/*
	 * Verify up to one entry in the submap.
	 * The caller's loop will proceed through all entries in the submap.
	 */

	/* Write fault unnests up to one entry in the submap, if necessary. */
	if (is_write_fault) {
		mach_vm_address_t unnest_address = next_address_to_fault;
		vm_entry_checker_t *unnested_checker =
		    checker_list_try_unnest_one_entry_in_submap(checker_list, submap_parent,
		    true /* unnest_readonly */, &unnest_address);
		if (unnested_checker != NULL) {
			/*
			 * Unnest occurred. Don't change *inout_next_address_to_fault
			 * and instead let the caller test this unnested entry's
			 * faultability in its next iteration.
			 */
			return true;
		}
	}

	/*
	 * Did not unnest. Fault the nested entry (allocation or hole).
	 * Don't fault outside the parent map's view of the submap.
	 */

	/* Find the checker for the submap's entry at this address. */
	checker_list_t *submap_checkers DEFER_UNSLIDE =
	    checker_get_and_slide_submap_checkers(submap_parent);
	vm_entry_checker_t *checker =
	    checker_list_find_checker(submap_checkers, next_address_to_fault);

	/* Compute the extent of the submap content checker that is visible to the parent map. */
	mach_vm_address_t clamped_checker_address = checker->address;
	mach_vm_size_t clamped_checker_size = checker->size;
	clamp_address_size_to_checker(&clamped_checker_address, &clamped_checker_size, submap_parent);

	assert(checker->kind == Allocation || checker->kind == Hole);
	*inout_next_address_to_fault = clamped_checker_address + clamped_checker_size;
	return test_fault_one_checker_in_address_range(checker, is_write_fault, true,
	           clamped_checker_address, clamped_checker_size);
}

static test_result_t
test_fault_common(
	checker_list_t *checker_list,
	mach_vm_address_t range_start,
	mach_vm_size_t range_size,
	bool is_write_fault, /* true for write fault, false for read fault */
	bool in_submap)
{
	/*
	 * Read or write all pages in one checker, then verify the VM state. Repeat for all checkers.
	 * Reading or writing in holes must provoke EXC_BAD_ACCESS (KERN_INVALID_ADDRESS).
	 * Reading or writing unreadable regions must provoke EXC_BAD_ACCESS (KERN_PROTECTION_FAILURE).
	 * Writing unwriteable regions must provoke EXC_BAD_ACCESS (KERN_PROTECTION_FAILURE).
	 *
	 * (TODO page modeling) this accesses outside [range_start, range_size)
	 * when the range starts or ends inside an entry
	 * need more precise page tracking to do better
	 */

	/* not FOREACH_CHECKER because submap unnesting breaks it */
	mach_vm_address_t next_address_to_fault = range_start;
	while (next_address_to_fault < range_start + range_size) {
		vm_entry_checker_t *checker = checker_list_find_checker(checker_list, next_address_to_fault);
		switch (checker->kind) {
		case Allocation:
			if (!test_fault_one_allocation(
				    checker_list, checker, is_write_fault,
				    in_submap, &next_address_to_fault)) {
				goto failed;
			}
			break;
		case Hole:
			if (!test_fault_one_checker(
				    checker, is_write_fault,
				    in_submap, &next_address_to_fault)) {
				goto failed;
			}
			break;
		case Submap:
			assert(!in_submap && "nested submaps not allowed");
			if (!test_fault_one_submap(
				    checker_list, checker, is_write_fault,
				    &next_address_to_fault)) {
				goto failed;
			}
			break;
		default:
			assert(0);
		}
	}

	return TestSucceeded;

failed:
	T_LOG("*** after incomplete verification of faults: all expected ***");
	dump_checker_range(checker_list->entries);
	T_LOG("*** after incomplete verification of faults: all actual ***");
	dump_region_info_for_entries(checker_list->entries);
	return TestFailed;
}

static test_result_t
test_fault_read(
	checker_list_t *checker_list,
	mach_vm_address_t range_start,
	mach_vm_size_t range_size)
{
	return test_fault_common(checker_list, range_start, range_size,
	           false /* is_write_fault */, false /* in_submap */);
}

static test_result_t
test_fault_write(
	checker_list_t *checker_list,
	mach_vm_address_t range_start,
	mach_vm_size_t range_size)
{
	return test_fault_common(checker_list, range_start, range_size,
	           true /* is_write_fault */, false /* in_submap */);
}


/*
 * Resolves COW. Assumes the write operation writes to the entire object,
 * so there are no shared pages remaining and the new object's shadow
 * chain collapses.
 */
static void
checker_make_cow_private_with_collapsed_shadow_chain(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker)
{
	assert(checker->needs_copy);

	if (checker->object->self_ref_count == 1) {
		/*
		 * COW but not shared with anything else.
		 * VM resolves COW by using the same object.
		 */
		checker->needs_copy = false;
		return;
	}

	/* make new object */
	vm_object_checker_t *obj_checker = object_checker_clone(checker->object);
	checker_list_append_object(checker_list, obj_checker);

	/* change object and entry to private */
	checker->needs_copy = false;

	/* set new object (decreasing previous object's self_ref_count) */
	checker_set_object(checker, obj_checker);
}

static test_result_t
test_fault_write_cow_1st(
	checker_list_t *checker_list,
	mach_vm_address_t range_start,
	mach_vm_size_t range_size)
{
	/*
	 * 1st entry is COW.
	 * Resolve COW because we're writing to it.
	 * We write to the entire entry so no shadow chain remains.
	 */
	checker_make_cow_private_with_collapsed_shadow_chain(
		checker_list, checker_list_nth(checker_list, 0));
	return test_fault_write(checker_list, range_start, range_size);
}

static test_result_t
test_fault_write_cow_2nd(
	checker_list_t *checker_list,
	mach_vm_address_t range_start,
	mach_vm_size_t range_size)
{
	/*
	 * 2nd entry is COW.
	 * Resolve COW because we're writing to it.
	 * We write to the entire entry so no shadow chain remains.
	 */
	checker_make_cow_private_with_collapsed_shadow_chain(
		checker_list, checker_list_nth(checker_list, 1));
	return test_fault_write(checker_list, range_start, range_size);
}

static test_result_t
test_fault_write_cow_1st_inaccessible(
	checker_list_t *checker_list,
	mach_vm_address_t range_start,
	mach_vm_size_t range_size)
{
	/* 1st entry is COW but inaccessible. */
	if (is_new_vm()) {
		/*
		 * New VM resolves COW but then performs no writes.
		 * Shadow chain does not collapse.
		 */
		vm_entry_checker_t *checker = checker_list_nth(checker_list, 0);
		checker_make_shadow_object(checker_list, checker);
	} else {
		/* Old VM does not resolve COW. */
	}
	return test_fault_write(checker_list, range_start, range_size);
}

T_DECL(fault_read,
    "perform read faults with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = test_fault_read,
		.single_entry_2 = test_fault_read,
		.single_entry_3 = test_fault_read,
		.single_entry_4 = test_fault_read,

		.single_entry_nonnull_1 = test_fault_read,
		.single_entry_nonnull_2 = test_fault_read,
		.single_entry_nonnull_3 = test_fault_read,
		.single_entry_nonnull_4 = test_fault_read,

		.multiple_entries_1 = test_fault_read,
		.multiple_entries_2 = test_fault_read,
		.multiple_entries_3 = test_fault_read,
		.multiple_entries_4 = test_fault_read,
		.multiple_entries_5 = test_fault_read,
		.multiple_entries_6 = test_fault_read,

		.some_holes_1 = test_fault_read,
		.some_holes_2 = test_fault_read,
		.some_holes_3 = test_fault_read,
		.some_holes_4 = test_fault_read,
		.some_holes_5 = test_fault_read,
		.some_holes_6 = test_fault_read,
		.some_holes_7 = test_fault_read,
		.some_holes_8 = test_fault_read,
		.some_holes_9 = test_fault_read,
		.some_holes_10 = test_fault_read,
		.some_holes_11 = test_fault_read,
		.some_holes_12 = test_fault_read,

		.all_holes_1 = test_fault_read,
		.all_holes_2 = test_fault_read,
		.all_holes_3 = test_fault_read,
		.all_holes_4 = test_fault_read,

		.null_entry        = test_fault_read,
		.nonresident_entry = test_fault_read,
		.resident_entry    = test_fault_read,

		/* TODO move pages_resident from entry checker to object checker */
		.shared_entry               = test_is_unimplemented,
		.shared_entry_discontiguous = test_is_unimplemented,
		.shared_entry_partial       = test_is_unimplemented,
		.shared_entry_pairs         = test_is_unimplemented,
		.shared_entry_x1000         = test_is_unimplemented,

		.cow_entry = test_fault_read,
		.cow_unreferenced = test_fault_read,
		.cow_nocow = test_fault_read,
		.nocow_cow = test_fault_read,
		.cow_unreadable = test_fault_read,
		.cow_unwriteable = test_fault_read,

		.permanent_entry = test_fault_read,
		.permanent_before_permanent = test_fault_read,
		.permanent_before_allocation = test_fault_read,
		.permanent_before_allocation_2 = test_fault_read,
		.permanent_before_hole = test_fault_read,
		.permanent_after_allocation = test_fault_read,
		.permanent_after_hole = test_fault_read,

		.single_submap_single_entry = test_fault_read,
		.single_submap_single_entry_first_pages = test_fault_read,
		.single_submap_single_entry_last_pages = test_fault_read,
		.single_submap_single_entry_middle_pages = test_fault_read,
		.single_submap_oversize_entry_at_start = test_fault_read,
		.single_submap_oversize_entry_at_end = test_fault_read,
		.single_submap_oversize_entry_at_both = test_fault_read,

		.submap_before_allocation = test_fault_read,
		.submap_after_allocation = test_fault_read,
		.submap_before_hole = test_fault_read,
		.submap_after_hole = test_fault_read,
		.submap_allocation_submap_one_entry = test_fault_read,
		.submap_allocation_submap_two_entries = test_fault_read,
		.submap_allocation_submap_three_entries = test_fault_read,

		.submap_before_allocation_ro = test_fault_read,
		.submap_after_allocation_ro = test_fault_read,
		.submap_before_hole_ro = test_fault_read,
		.submap_after_hole_ro = test_fault_read,
		.submap_allocation_submap_one_entry_ro = test_fault_read,
		.submap_allocation_submap_two_entries_ro = test_fault_read,
		.submap_allocation_submap_three_entries_ro = test_fault_read,

		.protection_single_000_000 = test_fault_read,
		.protection_single_000_r00 = test_fault_read,
		.protection_single_r00_r00 = test_fault_read,
		.protection_single_000_0w0 = test_fault_read,
		.protection_single_0w0_0w0 = test_fault_read,
		.protection_single_000_rw0 = test_fault_read,
		.protection_single_r00_rw0 = test_fault_read,
		.protection_single_0w0_rw0 = test_fault_read,
		.protection_single_rw0_rw0 = test_fault_read,

		.protection_pairs_000_000 = test_fault_read,
		.protection_pairs_000_r00 = test_fault_read,
		.protection_pairs_000_0w0 = test_fault_read,
		.protection_pairs_000_rw0 = test_fault_read,
		.protection_pairs_r00_000 = test_fault_read,
		.protection_pairs_r00_r00 = test_fault_read,
		.protection_pairs_r00_0w0 = test_fault_read,
		.protection_pairs_r00_rw0 = test_fault_read,
		.protection_pairs_0w0_000 = test_fault_read,
		.protection_pairs_0w0_r00 = test_fault_read,
		.protection_pairs_0w0_0w0 = test_fault_read,
		.protection_pairs_0w0_rw0 = test_fault_read,
		.protection_pairs_rw0_000 = test_fault_read,
		.protection_pairs_rw0_r00 = test_fault_read,
		.protection_pairs_rw0_0w0 = test_fault_read,
		.protection_pairs_rw0_rw0 = test_fault_read,
	};

	run_vm_tests("fault_read", __FILE__, &tests, argc, argv);
}


T_DECL(fault_write,
    "perform write faults with various vm configurations")
{
	vm_tests_t tests = {
		.single_entry_1 = test_fault_write,
		.single_entry_2 = test_fault_write,
		.single_entry_3 = test_fault_write,
		.single_entry_4 = test_fault_write,

		.single_entry_nonnull_1 = test_fault_write,
		.single_entry_nonnull_2 = test_fault_write,
		.single_entry_nonnull_3 = test_fault_write,
		.single_entry_nonnull_4 = test_fault_write,

		.multiple_entries_1 = test_fault_write,
		.multiple_entries_2 = test_fault_write,
		.multiple_entries_3 = test_fault_write,
		.multiple_entries_4 = test_fault_write,
		.multiple_entries_5 = test_fault_write,
		.multiple_entries_6 = test_fault_write,

		.some_holes_1 = test_fault_write,
		.some_holes_2 = test_fault_write,
		.some_holes_3 = test_fault_write,
		.some_holes_4 = test_fault_write,
		.some_holes_5 = test_fault_write,
		.some_holes_6 = test_fault_write,
		.some_holes_7 = test_fault_write,
		.some_holes_8 = test_fault_write,
		.some_holes_9 = test_fault_write,
		.some_holes_10 = test_fault_write,
		.some_holes_11 = test_fault_write,
		.some_holes_12 = test_fault_write,

		.all_holes_1 = test_fault_write,
		.all_holes_2 = test_fault_write,
		.all_holes_3 = test_fault_write,
		.all_holes_4 = test_fault_write,

		.null_entry        = test_fault_write,
		.nonresident_entry = test_fault_write,
		.resident_entry    = test_fault_write,

		/* TODO move pages_resident from entry checker to object checker */
		.shared_entry               = test_is_unimplemented,
		.shared_entry_discontiguous = test_is_unimplemented,
		.shared_entry_partial       = test_is_unimplemented,
		.shared_entry_pairs         = test_is_unimplemented,
		.shared_entry_x1000         = test_is_unimplemented,

		.cow_entry = test_fault_write_cow_1st,
		.cow_unreferenced = test_fault_write_cow_1st,
		.cow_nocow = test_fault_write_cow_1st,
		.nocow_cow = test_fault_write_cow_2nd,
		.cow_unreadable = test_fault_write_cow_1st_inaccessible,
		.cow_unwriteable = test_fault_write_cow_1st_inaccessible,

		.permanent_entry = test_fault_write,
		.permanent_before_permanent = test_fault_write,
		.permanent_before_allocation = test_fault_write,
		.permanent_before_allocation_2 = test_fault_write,
		.permanent_before_hole = test_fault_write,
		.permanent_after_allocation = test_fault_write,
		.permanent_after_hole = test_fault_write,

		.single_submap_single_entry = test_fault_write,
		.single_submap_single_entry_first_pages = test_fault_write,
		.single_submap_single_entry_last_pages = test_fault_write,
		.single_submap_single_entry_middle_pages = test_fault_write,
		.single_submap_oversize_entry_at_start = test_fault_write,
		.single_submap_oversize_entry_at_end = test_fault_write,
		.single_submap_oversize_entry_at_both = test_fault_write,

		/* TODO: fix submap_allocation_submap tests */
		.submap_before_allocation = test_fault_write,
		.submap_after_allocation = test_fault_write,
		.submap_before_hole = test_fault_write,
		.submap_after_hole = test_fault_write,
		.submap_allocation_submap_one_entry = test_is_unimplemented,
		.submap_allocation_submap_two_entries = test_is_unimplemented,
		.submap_allocation_submap_three_entries = test_is_unimplemented,

		.submap_before_allocation_ro = test_fault_write,
		.submap_after_allocation_ro = test_fault_write,
		.submap_before_hole_ro = test_fault_write,
		.submap_after_hole_ro = test_fault_write,
		.submap_allocation_submap_one_entry_ro = test_is_unimplemented,
		.submap_allocation_submap_two_entries_ro = test_is_unimplemented,
		.submap_allocation_submap_three_entries_ro = test_is_unimplemented,

		.protection_single_000_000 = test_fault_write,
		.protection_single_000_r00 = test_fault_write,
		.protection_single_r00_r00 = test_fault_write,
		.protection_single_000_0w0 = test_fault_write,
		.protection_single_0w0_0w0 = test_fault_write,
		.protection_single_000_rw0 = test_fault_write,
		.protection_single_r00_rw0 = test_fault_write,
		.protection_single_0w0_rw0 = test_fault_write,
		.protection_single_rw0_rw0 = test_fault_write,

		.protection_pairs_000_000 = test_fault_write,
		.protection_pairs_000_r00 = test_fault_write,
		.protection_pairs_000_0w0 = test_fault_write,
		.protection_pairs_000_rw0 = test_fault_write,
		.protection_pairs_r00_000 = test_fault_write,
		.protection_pairs_r00_r00 = test_fault_write,
		.protection_pairs_r00_0w0 = test_fault_write,
		.protection_pairs_r00_rw0 = test_fault_write,
		.protection_pairs_0w0_000 = test_fault_write,
		.protection_pairs_0w0_r00 = test_fault_write,
		.protection_pairs_0w0_0w0 = test_fault_write,
		.protection_pairs_0w0_rw0 = test_fault_write,
		.protection_pairs_rw0_000 = test_fault_write,
		.protection_pairs_rw0_r00 = test_fault_write,
		.protection_pairs_rw0_0w0 = test_fault_write,
		.protection_pairs_rw0_rw0 = test_fault_write,
	};

	run_vm_tests("fault_write", __FILE__, &tests, argc, argv);
}
