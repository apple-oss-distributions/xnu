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
 * vm_configurator_tests.h
 *
 * Virtual memory configurations and a test wrapper
 * available for use by tests that use vm_configurator.
 */

#ifndef VM_CONFIGURATOR_TESTS_H
#define VM_CONFIGURATOR_TESTS_H

#include "vm_configurator.h"

/*
 * Tests
 *
 * To add a new configuration for all VM API to be tested with:
 * 1. Add a function definition `configure_<testname>`
 *    that returns a vm_config_t representing the VM state
 *    and address range to be tested.
 * 2. Add a field named `<testname>` to struct vm_tests_t.
 * 3. Add a call to `RUN_TEST(<testname>)` in run_vm_tests() below.
 *
 * To help debug failing tests:
 * - Run a test executable with environment variable VERBOSE=1
 *   to print the checker and VM state frequently.
 * - Run a test executable with only a single VM configuration
 *   by naming that configuration on the command line.
 * Example of verbosely running only one read fault test:
 *   env VERBOSE=1 /path/to/configurator_fault -n fault_read permanent_before_allocation
 */

typedef vm_config_t *(*configure_fn_t)(void);

typedef test_result_t (*test_fn_t)(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/* single entry, null object */

static inline vm_config_t *
configure_single_entry_1(void)
{
	/* one entry, tested address range is the entire entry */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("single entry > entire entry", templates);
}

static inline vm_config_t *
configure_single_entry_2(void)
{
	/* one entry, tested address range includes only the first part of it */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("single entry > first pages", templates,
	           0, -DEFAULT_PARTIAL_ENTRY_SIZE);
}

static inline vm_config_t *
configure_single_entry_3(void)
{
	/* one entry, tested address range includes only the last part of it */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("single entry > last pages", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE, 0);
}

static inline vm_config_t *
configure_single_entry_4(void)
{
	/* one entry, tested address range includes only the middle part of it */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("single entry > middle pages", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE / 2, -(DEFAULT_PARTIAL_ENTRY_SIZE / 2));
}

/* single entry, non-null object */

static inline vm_config_t *
configure_single_entry_nonnull_1(void)
{
	/* one entry, tested address range is the entire entry */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("single entry > entire entry, nonnull object",
	           templates, object_templates);
}

static inline vm_config_t *
configure_single_entry_nonnull_2(void)
{
	/* one entry, tested address range includes only the first part of it */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("single entry > first pages, nonnull object",
	           templates, object_templates,
	           0, -DEFAULT_PARTIAL_ENTRY_SIZE);
}

static inline vm_config_t *
configure_single_entry_nonnull_3(void)
{
	/* one entry, tested address range includes only the last part of it */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("single entry > last pages, nonnull object",
	           templates, object_templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE, 0);
}

static inline vm_config_t *
configure_single_entry_nonnull_4(void)
{
	/* one entry, tested address range includes only the middle part of it */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("single entry > middle pages, nonnull object",
	           templates, object_templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE / 2, -(DEFAULT_PARTIAL_ENTRY_SIZE / 2));
}

/* multiple entries */

static inline vm_config_t *
configure_multiple_entries_1(void)
{
	/* two entries, tested address range includes both */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("multiple entries > two entries", templates);
}

static inline vm_config_t *
configure_multiple_entries_2(void)
{
	/* three entries, tested address range includes all of them */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("multiple entries > three entries", templates);
}

static inline vm_config_t *
configure_multiple_entries_3(void)
{
	/* many entries, tested address range includes all of them */
	vm_entry_template_t templates[] = {
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		vm_entry_template(), vm_entry_template(), vm_entry_template(), vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("multiple entries > many entries", templates);
}

static inline vm_config_t *
configure_multiple_entries_4(void)
{
	/* three entries, tested address range excludes the end of the last one */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("multiple entries > three entries, except the last pages", templates,
	           0, -DEFAULT_PARTIAL_ENTRY_SIZE);
}

static inline vm_config_t *
configure_multiple_entries_5(void)
{
	/* three entries, tested address range excludes the start of the first one */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("multiple entries > three entries, except the first pages", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE, 0);
}

static inline vm_config_t *
configure_multiple_entries_6(void)
{
	/*
	 * three entries, tested address range excludes both
	 * the start of the first one and the end of the last one
	 */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	assert(DEFAULT_PARTIAL_ENTRY_SIZE / 2 > 0);
	return make_vm_config("multiple entries > three entries, except the first and last pages", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE / 2, -(DEFAULT_PARTIAL_ENTRY_SIZE / 2));
}

/* some holes but not entirely holes */

static inline vm_config_t *
configure_some_holes_1(void)
{
	/* test address range begins in a hole and ends in an allocation */
	vm_entry_template_t templates[] = {
		hole_template,
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > hole then one entry", templates);
}

static inline vm_config_t *
configure_some_holes_2(void)
{
	/* test address range begins in a hole and ends in three allocation */
	vm_entry_template_t templates[] = {
		hole_template,
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > hole then multiple entries", templates);
}

static inline vm_config_t *
configure_some_holes_3(void)
{
	/* test address range begins in a hole and ends in the middle of an allocation */
	vm_entry_template_t templates[] = {
		hole_template,
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > hole then partial entry", templates,
	           0, -DEFAULT_PARTIAL_ENTRY_SIZE);
}

static inline vm_config_t *
configure_some_holes_4(void)
{
	/*
	 * test address range begins in a hole, covers two allocations,
	 * and ends in the middle of a third allocation
	 */
	vm_entry_template_t templates[] = {
		hole_template,
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > hole then multiple entries then partial entry", templates,
	           0, -DEFAULT_PARTIAL_ENTRY_SIZE);
}

static inline vm_config_t *
configure_some_holes_5(void)
{
	/* test address range begins at an allocation and ends in a hole */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("some holes > one entry then hole", templates);
}

static inline vm_config_t *
configure_some_holes_6(void)
{
	/*
	 * test address range begins at an allocation, covers two more allocations,
	 * and ends in a hole
	 */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("some holes > multiple entries then hole", templates);
}

static inline vm_config_t *
configure_some_holes_7(void)
{
	/* test address range begins in the middle of an allocation and ends in a hole */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("some holes > partial entry then hole", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE, 0);
}

static inline vm_config_t *
configure_some_holes_8(void)
{
	/*
	 * test address range begins in the middle of an allocation, covers
	 * two more allocations, and ends in a hole
	 */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("some holes > partial entry then multiple entries then hole", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE, 0);
}

static inline vm_config_t *
configure_some_holes_9(void)
{
	/* test address range is an allocation, then a hole, then an allocation */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > hole in the middle", templates);
}

static inline vm_config_t *
configure_some_holes_10(void)
{
	/* test address range is allocation-hole-allocation-hole-allocation */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > two holes, three entries", templates);
}

static inline vm_config_t *
configure_some_holes_11(void)
{
	/*
	 * test address range is
	 * two allocations-hole-two allocations-hole-two allocations
	 */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > two holes, six entries", templates);
}

static inline vm_config_t *
configure_some_holes_12(void)
{
	/*
	 * test address range is
	 * three allocations-hole-three allocations-hole-three allocations
	 */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("some holes > two holes, nine entries", templates);
}

/* all holes */

static inline vm_config_t *
configure_all_holes_1(void)
{
	/* test address range is unallocated, with allocations on both sides */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		hole_template,
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("all holes > hole with entries on both sides", templates,
	           DEFAULT_ENTRY_SIZE, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_all_holes_2(void)
{
	/*
	 * test address range is unallocated, with an allocation before
	 * and more unallocated space after
	 */
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("all holes > hole with entry before and hole after", templates,
	           DEFAULT_ENTRY_SIZE, -DEFAULT_PARTIAL_ENTRY_SIZE);
}

static inline vm_config_t *
configure_all_holes_3(void)
{
	/*
	 * test address range is unallocated, with more unallocated space before
	 * and an allocation after
	 */
	vm_entry_template_t templates[] = {
		hole_template,
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("all holes > hole with hole before and entry after", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_all_holes_4(void)
{
	/* test address range is unallocated, with more unallocated space before and after */
	vm_entry_template_t templates[] = {
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("all holes > hole with holes on both sides", templates,
	           DEFAULT_PARTIAL_ENTRY_SIZE / 2, -(DEFAULT_PARTIAL_ENTRY_SIZE / 2));
}

/* residency and sharing */

static inline vm_config_t *
configure_null_entry(void)
{
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_EMPTY),
		END_ENTRIES
	};
	return make_vm_config("residency > null entry", templates);
}

static inline vm_config_t *
configure_nonresident_entry(void)
{
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_PRIVATE),
		END_ENTRIES
	};
	return make_vm_config("residency > nonresident entry", templates);
}

static inline vm_config_t *
configure_resident_entry(void)
{
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_PRIVATE, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("residency > resident entry", templates, object_templates);
}

static inline vm_config_t *
configure_shared_entry(void)
{
	/*
	 * Two entries sharing the same object.
	 * The address range covers only the left entry
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0]),
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("sharing > simple shared entry", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_shared_entry_discontiguous(void)
{
	/*
	 * Two entries sharing the same object,
	 * but not the same range inside that object.
	 * The address range covers only the left entry.
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0],
	    .offset = 0),
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0],
	    .offset = DEFAULT_ENTRY_SIZE),
		END_ENTRIES
	};
	return make_vm_config("sharing > discontiguous shared entry", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_shared_entry_partial(void)
{
	/*
	 * Two entries sharing the same object,
	 * but only partly overlap inside that object.
	 * The address range covers only the left entry.
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0],
	    .offset = 0),
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0],
	    .offset = DEFAULT_PARTIAL_ENTRY_SIZE),
		END_ENTRIES
	};
	return make_vm_config("sharing > partial shared entry", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_shared_entry_pairs(void)
{
	/*
	 * Four entries. The first and last are shared. The middle two are
	 * also shared, independently.
	 * The address range covers all four entries.
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		vm_object_template(.fill_pattern = {Fill, 0x2222222222222222}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0]),
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[1]),
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[1]),
		vm_entry_template(.share_mode = SM_SHARED, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("sharing > two pairs of shared entries", templates, object_templates);
}

static inline vm_config_t *
configure_shared_entry_x1000(void)
{
	/*
	 * Many entries, all shared.
	 * The address range covers all entries.
	 * Each entry is xnu PAGE_SIZE bytes to accommodate Rosetta Intel on ARM.
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(.size = xnu_vm_page_size()),
		END_OBJECTS
	};

	const unsigned count = 1000;  /* 1000 shared entries */
	vm_entry_template_t *templates = calloc(sizeof(templates[0]), count + 1);  /* ... plus 1 END_ENTRIES entry */
	for (unsigned i = 0; i < count; i++) {
		templates[i] = vm_entry_template(
			.share_mode = SM_SHARED,
			.object = &object_templates[0],
			.size = xnu_vm_page_size());
	}
	templates[count] = END_ENTRIES;
	vm_config_t *result = make_vm_config("sharing > 1000 shared entries", templates, object_templates);
	free(templates);
	return result;
}

static inline vm_config_t *
configure_cow_entry(void)
{
	/*
	 * two entries that are COW copies of the same underlying object
	 * Operating range includes only the first entry.
	 */
	vm_object_template_t object_templates[] = {
		/* fixme must use a fill pattern to get a non-null object to copy */
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("cow > one COW entry", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_cow_unreferenced(void)
{
	/*
	 * one COW entry but the memory being copied has no other references
	 */
	vm_object_template_t object_templates[] = {
		/* fixme must use a fill pattern to get a non-null object to copy */
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("cow > COW with no other references", templates, object_templates);
}

static inline vm_config_t *
configure_cow_nocow(void)
{
	/*
	 * one entry that is COW, then one ordinary entry.
	 * Additional out-of-range entry is a second reference to the COW memory.
	 */
	vm_object_template_t object_templates[] = {
		/* fixme must use a fill pattern to get a non-null object to copy */
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		vm_entry_template(.share_mode = SM_PRIVATE),
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("cow > COW then not-COW", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_nocow_cow(void)
{
	/*
	 * one ordinary entry, then one entry that is COW.
	 * Additional out-of-range entry is a second reference to the COW memory.
	 */
	vm_object_template_t object_templates[] = {
		/* fixme must use a fill pattern to get a non-null object to copy */
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_PRIVATE),
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("cow > not-COW then COW", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_cow_unreadable(void)
{
	/*
	 * COW entry that is unreadable.
	 * Additional out-of-range entry is a second reference to the COW memory.
	 */
	vm_object_template_t object_templates[] = {
		/* fixme must use a fill pattern to get a non-null object to copy */
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0],
	    .protection = VM_PROT_NONE),
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("cow > COW but unreadable", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_cow_unwriteable(void)
{
	/*
	 * COW entry that is readable but unwriteable.
	 * Additional out-of-range entry is a second reference to the COW memory.
	 */
	vm_object_template_t object_templates[] = {
		/* fixme must use a fill pattern to get a non-null object to copy */
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0],
	    .protection = VM_PROT_READ),
		vm_entry_template(.share_mode = SM_COW, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("cow > COW but unwriteable", templates, object_templates,
	           0, -DEFAULT_ENTRY_SIZE);
}


static inline vm_config_t *
configure_permanent_entry(void)
{
	/* one permanent entry */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("permanent > one permanent entry",
	           templates, object_templates);
}

static inline vm_config_t *
configure_permanent_before_permanent(void)
{
	/* two permanent entries, both in-range */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		vm_entry_template(.permanent = true, .share_mode = SM_EMPTY),
		END_ENTRIES
	};
	return make_vm_config("permanent > two permanent entries",
	           templates, object_templates);
}

static inline vm_config_t *
configure_permanent_before_allocation(void)
{
	/*
	 * permanent entry followed by allocation
	 * The third entry, outside the tested address range,
	 * is an unallocated hole. This tests rdar://144128567
	 * along with test configure_permanent_before_allocation_2
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		vm_entry_template(),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("permanent > permanent entry before allocation, hole outside",
	           templates, object_templates, 0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_permanent_before_allocation_2(void)
{
	/*
	 * permanent entry followed by allocation
	 * The third entry, outside the tested address range,
	 * is an allocation to provoke rdar://144128567.
	 * Other than that bug the behavior should be
	 * identical to configure_permanent_before_allocation.
	 */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		vm_entry_template(),
		vm_entry_template(),
		END_ENTRIES
	};
	return make_vm_config("permanent > permanent entry before allocation, allocation outside",
	           templates, object_templates, 0, -DEFAULT_ENTRY_SIZE);
}

static inline vm_config_t *
configure_permanent_before_hole(void)
{
	/* permanent entry followed by a hole */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		hole_template,
		END_ENTRIES
	};
	return make_vm_config("permanent > permanent entry before hole",
	           templates, object_templates);
}

static inline vm_config_t *
configure_permanent_after_allocation(void)
{
	/* allocation followed by a permanent entry */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		vm_entry_template(),
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("permanent > permanent entry after allocation",
	           templates, object_templates);
}

static inline vm_config_t *
configure_permanent_after_hole(void)
{
	/* hole followed by a permanent entry */
	vm_object_template_t object_templates[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1234567890abcdef}),
		END_OBJECTS
	};
	vm_entry_template_t templates[] = {
		hole_template,
		vm_entry_template(.permanent = true, .object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config("permanent > permanent entry after hole",
	           templates, object_templates);
}


static inline vm_config_t *
configure_protection_single_common(vm_prot_t prot, vm_prot_t max)
{
	vm_entry_template_t templates[] = {
		vm_entry_template(.protection = prot, .max_protection = max),
		END_ENTRIES
	};

	TEMP_CSTRING(name, "protection > single entry prot/max %s/%s",
	    name_for_prot(prot), name_for_prot(max));
	return make_vm_config(name, templates);
}

static inline vm_config_t *
configure_protection_pairs_common(vm_prot_t prot_left, vm_prot_t prot_right)
{
	vm_prot_t max_prot = VM_PROT_READ | VM_PROT_WRITE;
	vm_entry_template_t templates[] = {
		vm_entry_template(.protection = prot_left, .max_protection = max_prot),
		vm_entry_template(.protection = prot_right, .max_protection = max_prot),
		END_ENTRIES
	};

	TEMP_CSTRING(name, "protection > two entries prot/max %s/%s and %s/%s",
	    name_for_prot(prot_left), name_for_prot(max_prot),
	    name_for_prot(prot_right), name_for_prot(max_prot));
	return make_vm_config(name, templates);
}

/* single entry with every prot/max combination (fixme no PROT_EXEC) */

/* prot/max ---/--- */
static inline vm_config_t *
configure_protection_single_000_000(void)
{
	return configure_protection_single_common(VM_PROT_NONE, VM_PROT_NONE);
}

/* prot/max r--/--- is disallowed */

/* prot/max -w-/--- is disallowed */

/* prot/max rw-/--- is disallowed */


/* prot/max ---/r-- */
static inline vm_config_t *
configure_protection_single_000_r00(void)
{
	return configure_protection_single_common(VM_PROT_NONE, VM_PROT_READ);
}

/* prot/max r--/r-- */
static inline vm_config_t *
configure_protection_single_r00_r00(void)
{
	return configure_protection_single_common(VM_PROT_READ, VM_PROT_READ);
}

/* prot/max -w-/r-- is disallowed */

/* prot/max rw-/r-- is disallowed */


/* prot/max ---/w-- */
static inline vm_config_t *
configure_protection_single_000_0w0(void)
{
	return configure_protection_single_common(VM_PROT_NONE, VM_PROT_WRITE);
}

/* prot/max r--/-w- is disallowed */

/* prot/max -w-/-w- */
static inline vm_config_t *
configure_protection_single_0w0_0w0(void)
{
	return configure_protection_single_common(VM_PROT_WRITE, VM_PROT_WRITE);
}

/* prot/max rw-/-w- is disallowed */


/* prot/max ---/rw- */
static inline vm_config_t *
configure_protection_single_000_rw0(void)
{
	return configure_protection_single_common(VM_PROT_NONE, VM_PROT_READ | VM_PROT_WRITE);
}

/* prot/max r--/rw- */
static inline vm_config_t *
configure_protection_single_r00_rw0(void)
{
	return configure_protection_single_common(VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE);
}

/* prot/max -w-/rw- */
static inline vm_config_t *
configure_protection_single_0w0_rw0(void)
{
	return configure_protection_single_common(VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE);
}

/* prot/max rw-/rw- */
static inline vm_config_t *
configure_protection_single_rw0_rw0(void)
{
	return configure_protection_single_common(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE);
}


/* two entries with every pair of protections (fixme no PROT_EXEC) */

static inline vm_config_t *
configure_protection_pairs_000_000(void)
{
	return configure_protection_pairs_common(VM_PROT_NONE, VM_PROT_NONE);
}

static inline vm_config_t *
configure_protection_pairs_000_r00(void)
{
	return configure_protection_pairs_common(VM_PROT_NONE, VM_PROT_READ);
}

static inline vm_config_t *
configure_protection_pairs_000_0w0(void)
{
	return configure_protection_pairs_common(VM_PROT_NONE, VM_PROT_WRITE);
}

static inline vm_config_t *
configure_protection_pairs_000_rw0(void)
{
	return configure_protection_pairs_common(VM_PROT_NONE, VM_PROT_READ | VM_PROT_WRITE);
}


static inline vm_config_t *
configure_protection_pairs_r00_000(void)
{
	return configure_protection_pairs_common(VM_PROT_READ, VM_PROT_NONE);
}

static inline vm_config_t *
configure_protection_pairs_r00_r00(void)
{
	return configure_protection_pairs_common(VM_PROT_READ, VM_PROT_READ);
}

static inline vm_config_t *
configure_protection_pairs_r00_0w0(void)
{
	return configure_protection_pairs_common(VM_PROT_READ, VM_PROT_WRITE);
}

static inline vm_config_t *
configure_protection_pairs_r00_rw0(void)
{
	return configure_protection_pairs_common(VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE);
}


static inline vm_config_t *
configure_protection_pairs_0w0_000(void)
{
	return configure_protection_pairs_common(VM_PROT_WRITE, VM_PROT_NONE);
}

static inline vm_config_t *
configure_protection_pairs_0w0_r00(void)
{
	return configure_protection_pairs_common(VM_PROT_WRITE, VM_PROT_READ);
}

static inline vm_config_t *
configure_protection_pairs_0w0_0w0(void)
{
	return configure_protection_pairs_common(VM_PROT_WRITE, VM_PROT_WRITE);
}

static inline vm_config_t *
configure_protection_pairs_0w0_rw0(void)
{
	return configure_protection_pairs_common(VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE);
}


static inline vm_config_t *
configure_protection_pairs_rw0_000(void)
{
	return configure_protection_pairs_common(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE);
}

static inline vm_config_t *
configure_protection_pairs_rw0_r00(void)
{
	return configure_protection_pairs_common(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ);
}

static inline vm_config_t *
configure_protection_pairs_rw0_0w0(void)
{
	return configure_protection_pairs_common(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_WRITE);
}

static inline vm_config_t *
configure_protection_pairs_rw0_rw0(void)
{
	return configure_protection_pairs_common(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE);
}


/* submaps */

/*
 * Common code for tests that are a single submap whose contents are a single entry
 * but test at different start and end offsets within that entry.
 */
static inline vm_config_t *
configure_single_submap_single_entry_common(
	const char *testname,
	mach_vm_size_t start_offset,
	mach_vm_size_t end_offset)
{
	vm_object_template_t submap_objects[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		END_OBJECTS
	};
	vm_entry_template_t submap_entries[] = {
		vm_entry_template(.object = &submap_objects[0]),
		END_ENTRIES
	};
	vm_object_template_t object_templates[] = {
		submap_object_template(
			.submap.entries = submap_entries,
			.submap.objects = submap_objects),
		END_OBJECTS
	};
	vm_entry_template_t entry_templates[] = {
		submap_entry_template(.object = &object_templates[0]),
		END_ENTRIES
	};
	return make_vm_config(testname,
	           entry_templates, object_templates, submap_entries, submap_objects,
	           start_offset, end_offset);
}

static inline vm_config_t *
configure_single_submap_single_entry(void)
{
	/*
	 * test range consists of a single submap mapping
	 * which in turn contains a single entry
	 */
	return configure_single_submap_single_entry_common(
		"submap > single entry > entire entry",
		0, 0 /* start and end offsets */);
}

static inline vm_config_t *
configure_single_submap_single_entry_first_pages(void)
{
	/*
	 * test range consists of a single submap mapping
	 * which in turn contains a single entry
	 * and the address range to be tested
	 * excludes the end of that entry
	 */
	return configure_single_submap_single_entry_common(
		"submap > single entry > first pages",
		0, -DEFAULT_PARTIAL_ENTRY_SIZE /* start and end offsets */);
}

static inline vm_config_t *
configure_single_submap_single_entry_last_pages(void)
{
	/*
	 * test range consists of a single submap mapping
	 * which in turn contains a single entry
	 * and the address range to be tested
	 * excludes the start of that entry
	 */
	return configure_single_submap_single_entry_common(
		"submap > single entry > last pages",
		DEFAULT_PARTIAL_ENTRY_SIZE, 0 /* start and end offsets */);
}

static inline vm_config_t *
configure_single_submap_single_entry_middle_pages(void)
{
	/*
	 * test range consists of a single submap mapping
	 * which in turn contains a single entry
	 * and the address range to be tested
	 * excludes the start and end of that entry
	 */
	return configure_single_submap_single_entry_common(
		"submap > single entry > middle pages",
		DEFAULT_PARTIAL_ENTRY_SIZE / 2, -(DEFAULT_PARTIAL_ENTRY_SIZE / 2) /* start and end offsets */);
}


static inline vm_config_t *
configure_single_submap_oversize_entry_common(
	const char *testname,
	mach_vm_address_t parent_offset,
	mach_vm_size_t parent_size)
{
	/*
	 * submap contains a single entry of default size,
	 * parent map's view of the submap excludes some part of that entry
	 */
	assert(parent_offset < DEFAULT_ENTRY_SIZE);
	assert(parent_offset + parent_size <= DEFAULT_ENTRY_SIZE);

	vm_object_template_t submap_objects[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		END_OBJECTS
	};
	vm_entry_template_t submap_entries[] = {
		vm_entry_template(.object = &submap_objects[0]),
		END_ENTRIES
	};
	vm_object_template_t object_templates[] = {
		submap_object_template(
			.submap.entries = submap_entries,
			.submap.objects = submap_objects),
		END_OBJECTS
	};
	vm_entry_template_t entry_templates[] = {
		submap_entry_template(
			.object = &object_templates[0],
			.offset = parent_offset,
			.size = parent_size),
		END_ENTRIES
	};
	return make_vm_config(testname,
	           entry_templates, object_templates,
	           submap_entries, submap_objects,
	           0, 0);
}

static inline vm_config_t *
configure_single_submap_oversize_entry_at_start(void)
{
	/*
	 * submap contains a single entry,
	 * parent map's view of the submap excludes the start of that entry
	 */
	return configure_single_submap_oversize_entry_common(
		"submap > oversize entry > oversize at start",
		DEFAULT_ENTRY_SIZE / 2 /* parent_offset */,
		DEFAULT_ENTRY_SIZE / 2 /* parent_size */);
}

static inline vm_config_t *
configure_single_submap_oversize_entry_at_end(void)
{
	/*
	 * submap contains a single entry,
	 * parent map's view of the submap excludes the end of that entry
	 */
	return configure_single_submap_oversize_entry_common(
		"submap > oversize entry > oversize at end",
		0 /* parent_offset */,
		DEFAULT_ENTRY_SIZE / 2 /* parent_size */);
}

static inline vm_config_t *
configure_single_submap_oversize_entry_at_both(void)
{
	/*
	 * submap contains a single entry,
	 * parent map's view of the submap excludes the start and end of that entry
	 */
	return configure_single_submap_oversize_entry_common(
		"submap > oversize entry > oversize at both start and end",
		DEFAULT_ENTRY_SIZE / 4 /* parent_offset */,
		DEFAULT_ENTRY_SIZE / 2 /* parent_size */);
}


/*
 * Common code for tests of a submap before or after a hole or allocation.
 */
static inline vm_config_t *
configure_submap_beafterfore_entry(
	const char *testname,
	vm_entry_template_kind_t first,
	vm_entry_template_kind_t second,
	int submap_protection)
{
	vm_object_template_t submap_objects[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		END_OBJECTS
	};
	vm_entry_template_t submap_entries[] = {
		vm_entry_template(
			.object = &submap_objects[0],
			.protection = submap_protection,
			.max_protection = submap_protection),
		END_ENTRIES
	};
	vm_object_template_t object_templates[] = {
		submap_object_template(
			.submap.entries = submap_entries,
			.submap.objects = submap_objects),
		END_OBJECTS
	};
	vm_entry_template_t template_options[] = {
		[Hole] = hole_template,
		[Allocation] = vm_entry_template(),
		[Submap] = submap_entry_template(.object = &object_templates[0])
	};
	/* entries must be Hole or Allocation or Submap */
	assert(first == Hole || first == Allocation || first == Submap);
	assert(second == Hole || second == Allocation || second == Submap);
	/* exactly one entry must be Submap */
	assert((first == Submap && second != Submap) ||
	    (first != Submap && second == Submap));
	vm_entry_template_t entry_templates[] = {
		template_options[first],
		template_options[second],
		END_ENTRIES
	};
	return make_vm_config(testname,
	           entry_templates, object_templates, submap_entries, submap_objects,
	           0, 0);
}

static inline vm_config_t *
configure_submap_before_allocation(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap before allocation", Submap, Allocation,
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_before_allocation_ro(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap before allocation, read-only", Submap, Allocation,
		VM_PROT_READ);
}

static inline vm_config_t *
configure_submap_after_allocation(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap after allocation", Allocation, Submap,
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_after_allocation_ro(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap after allocation, read-only", Allocation, Submap,
		VM_PROT_READ);
}

static inline vm_config_t *
configure_submap_before_hole(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap before hole", Submap, Hole,
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_before_hole_ro(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap before hole, read-only", Submap, Hole,
		VM_PROT_READ);
}

static inline vm_config_t *
configure_submap_after_hole(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap after hole", Hole, Submap,
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_after_hole_ro(void)
{
	return configure_submap_beafterfore_entry(
		"submap > submap after hole, read-only", Hole, Submap,
		VM_PROT_READ);
}

static inline vm_config_t *
configure_submap_allocation_submap_one_entry_common(
	const char *testname,
	int submap_protection)
{
	/*
	 * submap has a single entry, but parent map entries are
	 * submap-allocation-submap, as if part of the submap mapping
	 * had been deallocated or unnested
	 */

	vm_object_template_t submap_objects[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		END_OBJECTS
	};
	vm_entry_template_t submap_entries[] = {
		vm_entry_template(
			.object = &submap_objects[0],
			.size = DEFAULT_ENTRY_SIZE * 3,
			.protection = submap_protection,
			.max_protection = submap_protection),
		END_ENTRIES
	};
	vm_object_template_t object_templates[] = {
		submap_object_template(
			.submap.entries = submap_entries,
			.submap.objects = submap_objects),
		END_OBJECTS
	};
	vm_entry_template_t entry_templates[] = {
		submap_entry_template(
			.object = &object_templates[0],
			.offset = 0),
		vm_entry_template(),
		submap_entry_template(
			.object = &object_templates[0],
			.offset = DEFAULT_ENTRY_SIZE * 2),
		END_ENTRIES
	};
	return make_vm_config(testname,
	           entry_templates, object_templates,
	           submap_entries, submap_objects,
	           0, 0);
}

static inline vm_config_t *
configure_submap_allocation_submap_one_entry(void)
{
	return configure_submap_allocation_submap_one_entry_common(
		"submap > submap-allocation-submap, one entry in submap",
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_allocation_submap_one_entry_ro(void)
{
	return configure_submap_allocation_submap_one_entry_common(
		"submap > submap-allocation-submap, one entry in submap, read-only",
		VM_PROT_READ);
}

static inline vm_config_t *
configure_submap_allocation_submap_two_entries_common(
	const char *testname,
	int submap_protection)
{
	/*
	 * submap has two entries, but parent map entries are
	 * submap-allocation-submap, as if part of the submap mapping
	 * had been deallocated or unnested (not matching the submap
	 * entry boundaries)
	 */

	const mach_vm_size_t parent_entry_size = DEFAULT_ENTRY_SIZE;
	const mach_vm_size_t total_size = parent_entry_size * 3;
	const mach_vm_size_t submap_entry_size = total_size / 2;
	assert(parent_entry_size * 3 == submap_entry_size * 2);

	vm_object_template_t submap_objects[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		vm_object_template(.fill_pattern = {Fill, 0x2222222222222222}),
		END_OBJECTS
	};
	vm_entry_template_t submap_entries[] = {
		vm_entry_template(
			.object = &submap_objects[0],
			.size = submap_entry_size,
			.protection = submap_protection,
			.max_protection = submap_protection),
		vm_entry_template(
			.object = &submap_objects[1],
			.size = submap_entry_size,
			.protection = submap_protection,
			.max_protection = submap_protection),
		END_ENTRIES
	};
	vm_object_template_t object_templates[] = {
		submap_object_template(
			.submap.entries = submap_entries,
			.submap.objects = submap_objects),
		END_OBJECTS
	};
	vm_entry_template_t entry_templates[] = {
		submap_entry_template(
			.object = &object_templates[0],
			.offset = 0,
			.size = parent_entry_size),
		vm_entry_template(),
		submap_entry_template(
			.object = &object_templates[0],
			.offset = parent_entry_size * 2,
			.size = parent_entry_size),
		END_ENTRIES
	};
	return make_vm_config(testname,
	           entry_templates, object_templates,
	           submap_entries, submap_objects,
	           0, 0);
}

static inline vm_config_t *
configure_submap_allocation_submap_two_entries(void)
{
	return configure_submap_allocation_submap_two_entries_common(
		"submap > submap-allocation-submap, two entries in submap",
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_allocation_submap_two_entries_ro(void)
{
	return configure_submap_allocation_submap_two_entries_common(
		"submap > submap-allocation-submap, two entries in submap, read-only",
		VM_PROT_READ);
}

static inline vm_config_t *
configure_submap_allocation_submap_three_entries_common(
	const char *testname,
	int submap_protection)
{
	/*
	 * submap has three entries, parent map entries are
	 * submap-allocation-submap, as if part of the submap mapping
	 * had been deallocated or unnested on the submap entry boundaries
	 */

	vm_object_template_t submap_objects[] = {
		vm_object_template(.fill_pattern = {Fill, 0x1111111111111111}),
		vm_object_template(.fill_pattern = {Fill, 0x2222222222222222}),
		vm_object_template(.fill_pattern = {Fill, 0x3333333333333333}),
		END_OBJECTS
	};
	vm_entry_template_t submap_entries[] = {
		vm_entry_template(
			.object = &submap_objects[0],
			.protection = submap_protection,
			.max_protection = submap_protection),
		vm_entry_template(
			.object = &submap_objects[1],
			.protection = submap_protection,
			.max_protection = submap_protection),
		vm_entry_template(
			.object = &submap_objects[2],
			.protection = submap_protection,
			.max_protection = submap_protection),
		END_ENTRIES
	};
	vm_object_template_t object_templates[] = {
		submap_object_template(
			.submap.entries = submap_entries,
			.submap.objects = submap_objects),
		END_OBJECTS
	};
	vm_entry_template_t entry_templates[] = {
		submap_entry_template(
			.object = &object_templates[0],
			.offset = 0),
		vm_entry_template(),
		submap_entry_template(
			.object = &object_templates[0],
			.offset = DEFAULT_ENTRY_SIZE * 2),
		END_ENTRIES
	};
	return make_vm_config(testname,
	           entry_templates, object_templates,
	           submap_entries, submap_objects,
	           0, 0);
}

static inline vm_config_t *
configure_submap_allocation_submap_three_entries(void)
{
	return configure_submap_allocation_submap_three_entries_common(
		"submap > submap-allocation-submap, three entries in submap",
		VM_PROT_READ | VM_PROT_WRITE);
}

static inline vm_config_t *
configure_submap_allocation_submap_three_entries_ro(void)
{
	return configure_submap_allocation_submap_three_entries_common(
		"submap > submap-allocation-submap, three entries in submap, read-only",
		VM_PROT_READ);
}


/* add new tests here (configure_<testname> functions) */


typedef struct {
	test_fn_t single_entry_1;
	test_fn_t single_entry_2;
	test_fn_t single_entry_3;
	test_fn_t single_entry_4;

	test_fn_t single_entry_nonnull_1;
	test_fn_t single_entry_nonnull_2;
	test_fn_t single_entry_nonnull_3;
	test_fn_t single_entry_nonnull_4;

	test_fn_t multiple_entries_1;
	test_fn_t multiple_entries_2;
	test_fn_t multiple_entries_3;
	test_fn_t multiple_entries_4;
	test_fn_t multiple_entries_5;
	test_fn_t multiple_entries_6;

	test_fn_t some_holes_1;
	test_fn_t some_holes_2;
	test_fn_t some_holes_3;
	test_fn_t some_holes_4;
	test_fn_t some_holes_5;
	test_fn_t some_holes_6;
	test_fn_t some_holes_7;
	test_fn_t some_holes_8;
	test_fn_t some_holes_9;
	test_fn_t some_holes_10;
	test_fn_t some_holes_11;
	test_fn_t some_holes_12;

	test_fn_t all_holes_1;
	test_fn_t all_holes_2;
	test_fn_t all_holes_3;
	test_fn_t all_holes_4;

	test_fn_t null_entry;
	test_fn_t nonresident_entry;
	test_fn_t resident_entry;

	test_fn_t shared_entry;
	test_fn_t shared_entry_discontiguous;
	test_fn_t shared_entry_partial;
	test_fn_t shared_entry_pairs;
	test_fn_t shared_entry_x1000;

	test_fn_t cow_entry;
	test_fn_t cow_unreferenced;
	test_fn_t cow_nocow;
	test_fn_t nocow_cow;
	test_fn_t cow_unreadable;
	test_fn_t cow_unwriteable;

	test_fn_t permanent_entry;
	test_fn_t permanent_before_permanent;
	test_fn_t permanent_before_allocation;
	test_fn_t permanent_before_allocation_2;
	test_fn_t permanent_before_hole;
	test_fn_t permanent_after_allocation;
	test_fn_t permanent_after_hole;

	test_fn_t single_submap_single_entry;
	test_fn_t single_submap_single_entry_first_pages;
	test_fn_t single_submap_single_entry_last_pages;
	test_fn_t single_submap_single_entry_middle_pages;
	test_fn_t single_submap_oversize_entry_at_start;
	test_fn_t single_submap_oversize_entry_at_end;
	test_fn_t single_submap_oversize_entry_at_both;

	test_fn_t single_submap_single_entry_ro;
	test_fn_t single_submap_single_entry_first_pages_ro;
	test_fn_t single_submap_single_entry_last_pages_ro;
	test_fn_t single_submap_single_entry_middle_pages_ro;
	test_fn_t single_submap_oversize_entry_at_start_ro;
	test_fn_t single_submap_oversize_entry_at_end_ro;
	test_fn_t single_submap_oversize_entry_at_both_ro;

	test_fn_t submap_before_allocation;
	test_fn_t submap_after_allocation;
	test_fn_t submap_before_hole;
	test_fn_t submap_after_hole;
	test_fn_t submap_allocation_submap_one_entry;
	test_fn_t submap_allocation_submap_two_entries;
	test_fn_t submap_allocation_submap_three_entries;

	test_fn_t submap_before_allocation_ro;
	test_fn_t submap_after_allocation_ro;
	test_fn_t submap_before_hole_ro;
	test_fn_t submap_after_hole_ro;
	test_fn_t submap_allocation_submap_one_entry_ro;
	test_fn_t submap_allocation_submap_two_entries_ro;
	test_fn_t submap_allocation_submap_three_entries_ro;

	test_fn_t protection_single_000_000;
	test_fn_t protection_single_000_r00;
	test_fn_t protection_single_000_0w0;
	test_fn_t protection_single_000_rw0;
	test_fn_t protection_single_r00_r00;
	test_fn_t protection_single_r00_rw0;
	test_fn_t protection_single_0w0_0w0;
	test_fn_t protection_single_0w0_rw0;
	test_fn_t protection_single_rw0_rw0;

	test_fn_t protection_pairs_000_000;
	test_fn_t protection_pairs_000_r00;
	test_fn_t protection_pairs_000_0w0;
	test_fn_t protection_pairs_000_rw0;
	test_fn_t protection_pairs_r00_000;
	test_fn_t protection_pairs_r00_r00;
	test_fn_t protection_pairs_r00_0w0;
	test_fn_t protection_pairs_r00_rw0;
	test_fn_t protection_pairs_0w0_000;
	test_fn_t protection_pairs_0w0_r00;
	test_fn_t protection_pairs_0w0_0w0;
	test_fn_t protection_pairs_0w0_rw0;
	test_fn_t protection_pairs_rw0_000;
	test_fn_t protection_pairs_rw0_r00;
	test_fn_t protection_pairs_rw0_0w0;
	test_fn_t protection_pairs_rw0_rw0;

	/* add new tests here */
} vm_tests_t;


/*
 * test_is_unimplemented is used by test files
 * as a value in struct vm_tests_t to indicate that
 * a particular test case is deliberately not implemented.
 */
extern test_result_t
test_is_unimplemented(
	checker_list_t *checker_list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/*
 * Return true if the process is running under Rosetta translation
 * https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment#Determine-Whether-Your-App-Is-Running-as-a-Translated-Binary
 */
static bool
isRosetta(void)
{
#if KERNEL
	return false;
#else
	int out_value = 0;
	size_t io_size = sizeof(out_value);
	if (sysctlbyname("sysctl.proc_translated", &out_value, &io_size, NULL, 0) == 0) {
		assert(io_size >= sizeof(out_value));
		return out_value;
	}
	return false;
#endif
}

extern void
run_one_vm_test(
	const char *filename,
	const char *funcname,
	const char *testname,
	configure_fn_t configure_fn,
	test_fn_t test_fn);

static inline void
run_vm_tests(
	const char *funcname,
	const char *filename,
	vm_tests_t *tests,
	int argc,
	char * const *argv)
{
	/* Allow naming a single test to run on the command line. */
	const char *test_to_run = NULL;
	bool ran_a_test = false;
	if (argc == 1) {
		test_to_run = argv[0];
		T_LOG("RUNNING ONLY ONE TEST: %s %s", funcname, test_to_run);
	}

	/*
	 * rdar://138495830 tests fail on Rosetta because of allocation holes
	 * We run tests that don't have holes and skip those that do.
	 */
	bool test_holes = true;
	if (isRosetta()) {
		T_LOG("SKIPPING TESTS of allocation holes on Rosetta (rdar://138495830)");
		test_holes = false;
	}

#define RUN_TEST(testname)                                      \
	({                                                              \
	    if (test_to_run == NULL || 0 == strcmp(#testname, test_to_run)) { \
	            ran_a_test = true;                                  \
	            run_one_vm_test(filename, funcname, #testname,      \
	                configure_##testname, tests->testname);         \
	    }                                                           \
	})

	/* single vm map entry and parts thereof, no holes, nonnull object */
	RUN_TEST(single_entry_nonnull_1);
	RUN_TEST(single_entry_nonnull_2);
	RUN_TEST(single_entry_nonnull_3);
	RUN_TEST(single_entry_nonnull_4);

	/* single vm map entry and parts thereof, no holes */
	RUN_TEST(single_entry_1);
	RUN_TEST(single_entry_2);
	RUN_TEST(single_entry_3);
	RUN_TEST(single_entry_4);

	/* multiple map entries and parts thereof, no holes */
	RUN_TEST(multiple_entries_1);
	RUN_TEST(multiple_entries_2);
	RUN_TEST(multiple_entries_3);
	RUN_TEST(multiple_entries_4);
	RUN_TEST(multiple_entries_5);
	RUN_TEST(multiple_entries_6);

	/* ranges with holes */
	if (test_holes) {
		RUN_TEST(some_holes_1);
		RUN_TEST(some_holes_2);
		RUN_TEST(some_holes_3);
		RUN_TEST(some_holes_4);
		RUN_TEST(some_holes_5);
		RUN_TEST(some_holes_6);
		RUN_TEST(some_holes_7);
		RUN_TEST(some_holes_8);
		RUN_TEST(some_holes_9);
		RUN_TEST(some_holes_10);
		RUN_TEST(some_holes_11);
		RUN_TEST(some_holes_12);
	}

	/* ranges that are nothing but holes */
	if (test_holes) {
		RUN_TEST(all_holes_1);
		RUN_TEST(all_holes_2);
		RUN_TEST(all_holes_3);
		RUN_TEST(all_holes_4);
	}

	/* residency */
	RUN_TEST(null_entry);
	RUN_TEST(nonresident_entry);  // fixme broken in create_vm_state
	RUN_TEST(resident_entry);

	/* sharing */
	RUN_TEST(shared_entry);
	RUN_TEST(shared_entry_discontiguous);
	RUN_TEST(shared_entry_partial);
	RUN_TEST(shared_entry_pairs);
	RUN_TEST(shared_entry_x1000);

	/* cow */
	RUN_TEST(cow_entry);
	RUN_TEST(cow_unreferenced);
	RUN_TEST(cow_nocow);
	RUN_TEST(nocow_cow);
	RUN_TEST(cow_unreadable);
	RUN_TEST(cow_unwriteable);

	/* permanent */
	RUN_TEST(permanent_entry);
	RUN_TEST(permanent_before_permanent);
	if (test_holes) {
		/* this test does have a required hole, after the other allocations */
		RUN_TEST(permanent_before_allocation);
	}
	RUN_TEST(permanent_before_allocation_2);
	if (test_holes) {
		RUN_TEST(permanent_before_hole);
	}
	RUN_TEST(permanent_after_allocation);
	if (test_holes) {
		RUN_TEST(permanent_after_hole);
	}

	/* submaps */
	RUN_TEST(single_submap_single_entry);
	RUN_TEST(single_submap_single_entry_first_pages);
	RUN_TEST(single_submap_single_entry_last_pages);
	RUN_TEST(single_submap_single_entry_middle_pages);
	RUN_TEST(single_submap_oversize_entry_at_start);
	RUN_TEST(single_submap_oversize_entry_at_end);
	RUN_TEST(single_submap_oversize_entry_at_both);

	RUN_TEST(submap_before_allocation);
	RUN_TEST(submap_before_allocation_ro);
	RUN_TEST(submap_after_allocation);
	RUN_TEST(submap_after_allocation_ro);
	if (test_holes) {
		RUN_TEST(submap_before_hole);
		RUN_TEST(submap_before_hole_ro);
		RUN_TEST(submap_after_hole);
		RUN_TEST(submap_after_hole_ro);
	}
	RUN_TEST(submap_allocation_submap_one_entry);
	RUN_TEST(submap_allocation_submap_one_entry_ro);
	RUN_TEST(submap_allocation_submap_two_entries);
	RUN_TEST(submap_allocation_submap_two_entries_ro);
	RUN_TEST(submap_allocation_submap_three_entries);
	RUN_TEST(submap_allocation_submap_three_entries_ro);

	/* protection */
	RUN_TEST(protection_single_000_000);
	RUN_TEST(protection_single_000_r00);
	RUN_TEST(protection_single_r00_r00);
	RUN_TEST(protection_single_000_0w0);
	RUN_TEST(protection_single_0w0_0w0);
	RUN_TEST(protection_single_000_rw0);
	RUN_TEST(protection_single_r00_rw0);
	RUN_TEST(protection_single_0w0_rw0);
	RUN_TEST(protection_single_rw0_rw0);

	RUN_TEST(protection_pairs_000_000);
	RUN_TEST(protection_pairs_000_r00);
	RUN_TEST(protection_pairs_000_0w0);
	RUN_TEST(protection_pairs_000_rw0);
	RUN_TEST(protection_pairs_r00_000);
	RUN_TEST(protection_pairs_r00_r00);
	RUN_TEST(protection_pairs_r00_0w0);
	RUN_TEST(protection_pairs_r00_rw0);
	RUN_TEST(protection_pairs_0w0_000);
	RUN_TEST(protection_pairs_0w0_r00);
	RUN_TEST(protection_pairs_0w0_0w0);
	RUN_TEST(protection_pairs_0w0_rw0);
	RUN_TEST(protection_pairs_rw0_000);
	RUN_TEST(protection_pairs_rw0_r00);
	RUN_TEST(protection_pairs_rw0_0w0);
	RUN_TEST(protection_pairs_rw0_rw0);

	/* add new tests here */

#undef RUN_TEST

	if (test_to_run != NULL && !ran_a_test) {
		T_FAIL("no test named '%s'", test_to_run);
	}
}

#endif  /* VM_CONFIGURATOR_TESTS_H */
