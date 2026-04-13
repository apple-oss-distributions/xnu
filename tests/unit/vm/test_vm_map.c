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
#include <stdint.h>
#include "mocks/osfmk/unit_test_utils.h"
#include <mocks/osfmk/mock_vm.h>
#include <mocks/osfmk/mock_pmap.h>

#include <vm/vm_map_lock_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_test_utils_internal.h>

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.test_vm_map"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

/* the functions being tested */

extern void vm_map_simplify_range(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

/* the tests */

#define expect_free_space(map, start, end, name) \
	T_EXPECT_LE((vm_map_size_t)((end) - (start)), vm_map_store_lookup_hole(map, start, vm_map_max(map)), \
	    "hole exists and is large enough: %s", name);

#define expect_not_free_space(map, start, end, name) \
	T_EXPECT_GT((vm_map_size_t)((end) - (start)), vm_map_store_lookup_hole(map, start, vm_map_max(map)), \
	    "allocation within [0x%016llx, 0x%016llx) exists: %s", \
	    (uint64_t)(start), (uint64_t)(end), name)

T_DECL(is_free_space, "test vm_map_store_lookup_hole()")
{
	vm_map_offset_t max_addr = -(vm_map_offset_t)PAGE_SIZE;
	vm_map_t map;
	vm_map_entry_t entry;
	bool is_free;

	/* EMPTY MAP */

	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, max_addr, 0);
	vm_map_ilk_lock(map);

	/* free space in empty map */

	expect_free_space(map, 0, max_addr,
	    "empty map, entire range");

	expect_free_space(map, 0, 10 * PAGE_SIZE,
	    "empty map, at start");

	expect_free_space(map, 10 * PAGE_SIZE, 20 * PAGE_SIZE,
	    "empty map, middle");

	expect_free_space(map, 20 * PAGE_SIZE, max_addr,
	    "empty map, at end");

	/* MAP WITH ONE ENTRY, NO FREE SPACE */

	vm_map_ilk_unlock(map);
	(void)vm_test_add_map_entry(map, 0, max_addr);
	vm_map_ilk_lock(map);

	/* start and end inside one entry */

	expect_not_free_space(map, 0, max_addr, "single entry no free space map, not free inside entry");
	expect_not_free_space(map, 0, 2 * PAGE_SIZE, "single entry no free space map, not free inside entry start");
	expect_not_free_space(map, PAGE_SIZE, max_addr, "single entry no free space map, not free inside entry end");
	expect_not_free_space(map, PAGE_SIZE, 2 * PAGE_SIZE, "single entry no free space map, not free inside entry middle");

	/* MAP WITH ONE ENTRY (hole - #1 - hole) */

	vm_map_ilk_unlock(map);
	vm_map_deallocate(map);
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, max_addr, 0);

	vm_map_offset_t start1 = 10 * PAGE_SIZE;
	vm_map_offset_t end1   = 20 * PAGE_SIZE;

	vm_map_entry_t entry1 = vm_test_add_map_entry(map, start1, end1);
	vm_map_ilk_lock(map);

	/* start and end inside one entry */

	expect_not_free_space(map, start1, end1, "single entry map, not free inside entry");
	expect_not_free_space(map, start1, end1 - PAGE_SIZE, "single entry map, not free inside entry start");
	expect_not_free_space(map, start1 + PAGE_SIZE, end1, "single entry map, not free inside entry end");
	expect_not_free_space(map, start1 + PAGE_SIZE, end1 - PAGE_SIZE, "single entry map, not free inside entry middle");

	/* start in free space before first entry, end inside an entry */

	expect_not_free_space(map, 0, end1, "single entry map, zero to end of entry");
	expect_not_free_space(map, 0, end1 - PAGE_SIZE, "single entry map, zero to middle of entry");
	expect_not_free_space(map, PAGE_SIZE, end1, "single entry map, nonzero to end of entry");
	expect_not_free_space(map, PAGE_SIZE, end1 - PAGE_SIZE, "single entry map, nonzero to middle of entry");

	/* start inside an entry, end in free space after last entry  */

	expect_not_free_space(map, start1, max_addr, "single entry map, start of last entry to map end");
	expect_not_free_space(map, start1, max_addr - PAGE_SIZE, "single entry map, start of last entry to before map end");
	expect_not_free_space(map, start1 + PAGE_SIZE, max_addr, "single entry map, middle of last entry to map end");
	expect_not_free_space(map, start1 + PAGE_SIZE, max_addr - PAGE_SIZE, "single entry map, middle of last entry to before map end");

	/* free space before first entry */

	expect_free_space(map, 0, start1,
	    "single entry map, zero to first entry start");

	expect_free_space(map, 0, 1 * PAGE_SIZE,
	    "single entry map, zero to nonzero before first entry");

	expect_free_space(map, 5 * PAGE_SIZE, start1,
	    "single entry map, nonzero to first entry start");

	expect_free_space(map, 5 * PAGE_SIZE, 6 * PAGE_SIZE,
	    "single entry map, nonzero to nonzero before first entry");

	/* free space after last entry */

	expect_free_space(map, end1, max_addr,
	    "single entry map, last entry end to max");

	expect_free_space(map, end1, max_addr - PAGE_SIZE,
	    "single entry map, last entry end to before max");

	expect_free_space(map, end1 + PAGE_SIZE, max_addr,
	    "single entry map, after last entry end to max");

	expect_free_space(map, end1 + PAGE_SIZE, max_addr - PAGE_SIZE,
	    "single entry map, after last entry end to before max");

	/* MAP WITH SOME ENTRIES (hole - #1 - hole - #2 - #3 - #4 - hole) */

	vm_map_offset_t start2 = 30 * PAGE_SIZE;
	vm_map_offset_t end2   = 40 * PAGE_SIZE;
	vm_map_offset_t start3 = end2;
	vm_map_offset_t end3   = 50 * PAGE_SIZE;
	vm_map_offset_t start4 = end3;
	vm_map_offset_t end4   = 60 * PAGE_SIZE;

	vm_map_ilk_unlock(map);
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, start2, end2);
	vm_map_entry_t entry3 = vm_test_add_map_entry(map, start3, end3);
	vm_map_entry_t entry4 = vm_test_add_map_entry(map, start4, end4);
	vm_map_ilk_lock(map);

	/* free space before first entry */

	expect_free_space(map, 0, start1,
	    "zero to first entry start");

	expect_free_space(map, 0, 1 * PAGE_SIZE,
	    "zero to before first entry");

	expect_free_space(map, 5 * PAGE_SIZE, start1,
	    "nonzero to first entry start");

	expect_free_space(map, 5 * PAGE_SIZE, 6 * PAGE_SIZE,
	    "nonzero to before first entry");

	/* free space after last entry */

	expect_free_space(map, end4, max_addr, "last entry end to max");

	expect_free_space(map, end4, max_addr - PAGE_SIZE,
	    "last entry end to before max");

	expect_free_space(map, end4 + PAGE_SIZE, max_addr,
	    "after last entry end to max");

	expect_free_space(map, end4 + PAGE_SIZE, max_addr - PAGE_SIZE,
	    "after last entry end to before max");

	/* free space between two entries (#1 - hole - #2) */

	expect_free_space(map, end1, start2, "entry end to next start");

	expect_free_space(map, end1, start2 - PAGE_SIZE,
	    "entry end to before next start");

	expect_free_space(map, end1 + PAGE_SIZE, start2,
	    "after entry end to next start");

	expect_free_space(map, end1 + PAGE_SIZE, start2 - PAGE_SIZE,
	    "after entry end to before next start");

	/* start inside one entry, end inside a second entry, hole between (#1 - hole - #2) */

	expect_not_free_space(map, start1, end2, "start of entry to end of next entry, hole between");
	expect_not_free_space(map, start1, end2 - PAGE_SIZE, "start of entry to middle of next entry, hole between");
	expect_not_free_space(map, start1 + PAGE_SIZE, end2, "middle of entry to end of next entry, hole between");
	expect_not_free_space(map, start1 + PAGE_SIZE, end2 - PAGE_SIZE, "middle of entry to middle of next entry, hole between");

	/* start inside one entry, end inside a second entry, nothing between (#2 - #3) */

	expect_not_free_space(map, start2, end3, "start of entry to end of next entry, nothing between");
	expect_not_free_space(map, start2, end3 - PAGE_SIZE, "start of entry to middle of next entry, nothing between");
	expect_not_free_space(map, start2 + PAGE_SIZE, end3, "middle of entry to end of next entry, nothing between");
	expect_not_free_space(map, start2 + PAGE_SIZE, end3 - PAGE_SIZE, "middle of entry to middle of next entry, nothing between");

	/* start inside one entry, end inside a second entry, another entry between (#2 - #3 - #4) */

	expect_not_free_space(map, start2, end4, "start of entry to end of another entry, third entry between");
	expect_not_free_space(map, start2, end4 - PAGE_SIZE, "start of entry to middle of another entry, third entry between");
	expect_not_free_space(map, start2 + PAGE_SIZE, end4, "middle of entry to end of another entry, third entry between");
	expect_not_free_space(map, start2 + PAGE_SIZE, end4 - PAGE_SIZE, "middle of entry to middle of another entry, third entry between");

	/* start in free space after an entry, end inside another entry (#1 - hole - #2) */

	expect_not_free_space(map, end1, end2, "free space at end of entry to end of next entry");
	expect_not_free_space(map, end1, end2 - PAGE_SIZE, "free space at end of entry to middle of next entry");
	expect_not_free_space(map, end1 + PAGE_SIZE, end2, "free space after end of entry to end of next entry");
	expect_not_free_space(map, end1 + PAGE_SIZE, end2 - PAGE_SIZE, "free space after end of entry to middle of next entry");

	/* start inside an entry, end in free space before another entry (#1 - hole - #2) */

	expect_not_free_space(map, start1, start2, "start of an entry to free space at start of next entry");
	expect_not_free_space(map, start1, start2 - PAGE_SIZE, "start of an entry to free space before start of next entry");
	expect_not_free_space(map, start1 + PAGE_SIZE, start2, "middle of an entry to free space at start of next entry");
	expect_not_free_space(map, start1 + PAGE_SIZE, start2 - PAGE_SIZE, "middle of an entry to free space before start of next entry");

	vm_map_ilk_unlock(map);
	vm_map_deallocate(map);
}


static void
set_entry_obj_and_offset_unlocked(vm_map_t map, vm_map_entry_t entry, vm_object_t object, vm_object_offset_t offset)
{
	T_ASSERT_TRUE_(vm_entry_try_lock_exclusive(entry), "trylock");
	VME_OBJECT_SET(entry, object, false, 0);
	VME_OFFSET_SET(entry, offset);
	vm_entry_unlock_exclusive(map, entry);
}

T_DECL(vm_map_simplify_range, "test vm_map_simplify_range")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_object_t obj = vm_object_allocate(PAGE_SIZE * 2, VM_MAP_SERIAL_NONE);

	vm_map_offset_t entry_start = PAGE_SIZE;
	vm_map_offset_t last_end = PAGE_SIZE * 3;

	vm_map_entry_t first = vm_test_add_map_entry(map, entry_start, entry_start + PAGE_SIZE);
	vm_map_entry_t second = vm_test_add_map_entry(map, entry_start + PAGE_SIZE, last_end);
	set_entry_obj_and_offset_unlocked(map, first, obj, 0);
	vm_object_reference(obj);
	set_entry_obj_and_offset_unlocked(map, second, obj, PAGE_SIZE);


	vm_map_simplify_range(map, entry_start, last_end);
	T_ASSERT_EQ_INT(map->hdr.nentries, 1, "simplified");

	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	first = vm_test_add_map_entry(map, entry_start, entry_start + PAGE_SIZE);
	second = vm_test_add_map_entry(map, entry_start + PAGE_SIZE, last_end);
	set_entry_obj_and_offset_unlocked(map, first, obj, 0);

	vm_map_simplify_range(map, entry_start, last_end);
	T_ASSERT_EQ_INT(map->hdr.nentries, 2, "didn't simplify");
}

kern_return_t    vm_map_zero(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end);

T_DECL(vm_map_zero, "test vm_map_zero")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_object_t object = vm_object_allocate(PAGE_SIZE * 3, VM_MAP_SERIAL_NONE);

	vm_map_offset_t entry_start = PAGE_SIZE;
	vm_map_offset_t entry_end = PAGE_SIZE * 3;
	kern_return_t kr;
	vm_map_entry_t entry = vm_test_add_map_entry(map, entry_start, entry_end);

	/* Call on no object, verify no obj */
	kr = vm_map_zero(map, entry_start, entry_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(no object) works");
	T_ASSERT_EQ_PTR(VM_OBJECT_NULL, VME_OBJECT(entry), "still no obj");

	/* Call on object with no pages, verify no pages. */
	vm_map_ilk_lock(map);
	assert3u(KERN_SUCCESS, ==, vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry_start, THREAD_UNINT));
	VME_OBJECT_SET(entry, object, false, 0);
	vm_entry_unlock_exclusive(map, entry);
	vm_map_ilk_unlock(map);

	kr = vm_map_zero(map, entry_start, entry_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(empty object) works");
	T_ASSERT_EQ_INT(object->resident_page_count, 0, "no pages resident");

	/* Call on object with a page, verify the zero func was called */
	vm_page_t m = vm_page_grab_options(0);
	T_ASSERT_NOTNULL(m, "page");
	m->vmp_busy = FALSE;
	vm_object_lock(object);
	vm_page_insert(m, object, vm_object_trunc_page(0));
	vm_object_unlock(object);

	__block int num_pmap_zero_calls = 0;
	T_MOCK_SET_CALLBACK(
		pmap_zero_page,
		void,
		(ppnum_t pn),
	{
		num_pmap_zero_calls++;
		return;
	});
	kr = vm_map_zero(map, entry_start, entry_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(empty object) works");
	T_ASSERT_EQ_INT(object->resident_page_count, 1, "one pages resident");
	T_ASSERT_EQ_INT(num_pmap_zero_calls, 1, "correct # zeros");

	/* Call on object with a busy page and a normal page after. Verify zero was called on both */
	num_pmap_zero_calls = 0;
	vm_page_t m2 = vm_page_grab_options(0);
	T_ASSERT_NOTNULL(m2, "page");
	m2->vmp_busy = FALSE;
	vm_object_lock(object);
	m->vmp_busy = TRUE; /* busy prior page */
	vm_page_insert(m2, object, vm_object_trunc_page(PAGE_SIZE));
	vm_object_unlock(object);

	T_MOCK_SET_CALLBACK(vm_page_sleep, wait_result_t, (
		    vm_object_t        object,
		    vm_page_t          m,
		    wait_interrupt_t   interruptible,
		    lck_sleep_action_t action), {
		m->vmp_busy = false;
		return THREAD_NOT_WAITING;
	});

	kr = vm_map_zero(map, entry_start, entry_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(empty object) works");
	T_ASSERT_EQ_INT(object->resident_page_count, 2, "two pages resident");
	T_ASSERT_EQ_INT(num_pmap_zero_calls, 2, "correct # zeros");

	/* and same thing as above, but let's add a second entry. */
	vm_object_lock(object);
	m->vmp_busy = TRUE; /* busy prior page */
	vm_object_unlock(object);

	vm_object_t object2 = vm_object_allocate(PAGE_SIZE, map->serial_id);
	vm_map_address_t entry2_start = entry_end;
	vm_map_address_t entry2_end = entry2_start + PAGE_SIZE;
	vm_map_entry_t entry2 = vm_test_add_map_entry(map, entry_end, entry2_end);

	num_pmap_zero_calls = 0;
	/* Second obj NULL */
	kr = vm_map_zero(map, entry_start, entry2_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(two entries) works");
	T_ASSERT_EQ_PTR(VM_OBJECT_NULL, VME_OBJECT(entry2), "still no obj");
	T_ASSERT_EQ_INT(num_pmap_zero_calls, 2, "correct # zeros");

	/* Second obj has busy page */
	vm_map_ilk_lock(map);
	assert3u(KERN_SUCCESS, ==, vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry2, entry2_start, THREAD_UNINT));
	VME_OBJECT_SET(entry2, object2, false, 0);
	vm_entry_unlock_exclusive(map, entry2);
	vm_map_ilk_unlock(map);
	vm_page_t m3 = vm_page_grab_options(0);
	T_ASSERT_NOTNULL(m3, "page");
	vm_object_lock(object2);
	vm_page_insert(m3, object2, vm_object_trunc_page(0));
	vm_object_unlock(object2);

	num_pmap_zero_calls = 0;
	kr = vm_map_zero(map, entry_start, entry2_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(empty object) works");
	T_ASSERT_EQ_INT(num_pmap_zero_calls, 3, "correct # zeros");

	/* Now let's test first obj NULL */
	vm_map_ilk_lock(map);
	assert3u(KERN_SUCCESS, ==, vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, entry_start, THREAD_UNINT));
	VME_OBJECT_SET(entry, VM_OBJECT_NULL, false, 0);
	vm_entry_unlock_exclusive(map, entry);
	vm_map_ilk_unlock(map);

	num_pmap_zero_calls = 0;
	kr = vm_map_zero(map, entry_start, entry2_end);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "zero(empty object) works");
	T_ASSERT_EQ_INT(num_pmap_zero_calls, 1, "correct # zeros");
}
