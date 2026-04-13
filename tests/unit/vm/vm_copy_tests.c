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
#include <mocks/osfmk/unit_test_utils.h>
#include "mocks/osfmk/mock_pmap.h"
#include <mocks/mock_mem.h>

#include <vm/vm_map_internal.h>
#include <vm/vm_fault_internal.h>

#include "vm/vm_map_lock_internal.h"

#include "mach/mach.h"
#include "mach/mach_vm.h"
#include "mach/vm_map.h"
#include "kern/ipc_kobject.h"
#include "vm/vm_memory_entry_xnu.h"


#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_copy"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("s_shalom"),
	T_META_RUN_CONCURRENTLY(true)
	);

#pragma clang attribute push(__attribute__((noinline, optnone)), apply_to=function)


static __attribute__((overloadable)) void
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot,
    bool needs_copy, vm_object_t obj, vm_object_offset_t offset)
{
	kern_return_t kr = vm_map_enter(map, &start, size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    obj, offset, needs_copy, cur_prot, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
	if (needs_copy && !obj->shadowed) {
		obj->shadowed = true;
	}
}

static __attribute__((overloadable)) void
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot,
    bool needs_copy, vm_object_t obj)
{
	enter_obj_entry(map, start, size, cur_prot, needs_copy, obj, 0);
}

static __attribute__((overloadable)) void
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot,
    bool needs_copy)
{
	/* non NULL obj to avoid coalesce */
	enter_obj_entry(map, start, size, cur_prot, needs_copy, vm_object_allocate(size, map->serial_id));
}

static void
enter_copy_none_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot)
{
	vm_object_t obj = vm_object_allocate(size, map->serial_id);
	obj->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	enter_obj_entry(map, start, size, cur_prot, false, obj);
}


vm_map_address_t MAP_BASE = 0x010000000; // avoid the pmap_shared_region


__attribute__((overloadable))
static void
setup_sealed_map(vm_map_t *parent_map, vm_map_t *submap, bool submap_needs_copy)
{
	kern_return_t kr;
	pmap_t pmap_nested = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_NESTED);
#if defined(__arm64__)
	pmap_set_nested(pmap_nested);
#endif
	*submap = vm_map_create_options(pmap_nested, 0, 0xfffffffffffff, 0);
	(*submap)->is_nested_map = TRUE;
	(*submap)->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	vm_map_address_t submap_start = MAP_BASE + 0x10000;
	vm_map_address_t offset = submap_start;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, true);
	offset += PAGE_SIZE * 2;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_READ, true);
	offset += PAGE_SIZE * 2;
	enter_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_READ, true);
	vm_map_seal(*submap, true);
	T_QUIET; T_ASSERT_EQ((*submap)->hdr.nentries, 5, "submap entries"); // 3 added entries, 2 padding the start and end of the map

	// parent map has obj-entry (2 pages), submap-entry (2+2+2 pages), obj-entry (2 pages)
	*parent_map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	offset = MAP_BASE + 0x50000;
	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, true);
	offset += PAGE_SIZE * 2;

	kr = vm_map_enter(*parent_map, &offset, PAGE_SIZE * 2 * 3, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmkf_nested_pmap =  TRUE), (vm_object_t)(uintptr_t) *submap,
	    submap_start, /*needs_copy=*/ submap_needs_copy, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter submap");
	offset += PAGE_SIZE * 2 * 3; // submap is 3 entries of 2 pages

	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, true);
	T_QUIET; T_ASSERT_EQ((*parent_map)->hdr.nentries, 3, "parent entries");
}

__attribute__((overloadable))
static void
setup_sealed_map(vm_map_t *parent_map, vm_map_t *submap)
{
	// needs_copy in the entry that points to the constant submap is
	// true for shared-cache, false for x86 comm page
	setup_sealed_map(parent_map, submap, true);
}

static void
setup_transparent_map(vm_map_t *parent_map, vm_map_t *submap)
{
	kern_return_t kr;
	pmap_t pmap_nested = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);

	vm_map_address_t submap_start;
	vm_map_kernel_flags_t submap_enter_flags;

	*submap = vm_map_create_options(pmap_nested, 0, PAGE_SIZE * 2 * 3, 0);
	vm_map_reference(*submap);
	// offset matches parent
	submap_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE;
	submap_enter_flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmf_permanent = true, .vmkf_submap_atomic = true);

	// parent map has obj-entry (2 pages), submap-entry (2+2+2 pages), obj-entry (2 pages)
	*parent_map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, true);
	offset += PAGE_SIZE * 2;

	kr = vm_map_enter(*parent_map, &offset, PAGE_SIZE * 2 * 3, 0,
	    submap_enter_flags, (vm_object_t)(uintptr_t) *submap,
	    submap_start, /*needs_copy=*/ false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter submap");
	offset += PAGE_SIZE * 2 * 3; // submap is 3 entries of 2 pages

	enter_obj_entry(*parent_map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, true);

	// populate submap
	offset = submap_start;
	enter_copy_none_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT);
	offset += PAGE_SIZE * 2;
	enter_copy_none_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_READ);
	offset += PAGE_SIZE * 2;
	enter_copy_none_obj_entry(*submap, offset, PAGE_SIZE * 2, VM_PROT_READ);

	T_QUIET; T_ASSERT_EQ((*submap)->hdr.nentries, 3, "submap entries");

	T_QUIET; T_ASSERT_EQ((*parent_map)->hdr.nentries, 3, "parent entries");
}

static void
setup_map_with_submap(vm_map_t *parent_map, vm_map_t *submap, bool sealed_submap)
{
	if (sealed_submap) {
		setup_sealed_map(parent_map, submap);
	} else {
		setup_transparent_map(parent_map, submap);
	}
}

T_DECL(alloc_dealloc_map, "alloc_dealloc_map")
{
	// single empty map
	{
		T_MOCK_ZALLOC_LEAK_CHECK();
		vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
		vm_map_destroy(map);
	}

	// parent map and sealed submap
	{
		T_MOCK_ZALLOC_LEAK_CHECK();
		vm_map_t parent, submap;
		setup_sealed_map(&parent, &submap);
		vm_map_destroy(parent);
		// submap should be destroyed since it's only reference is from the parent
	}

	// parent map and transparent submap
	{
		T_MOCK_ZALLOC_LEAK_CHECK();
		vm_map_t parent, submap;
		setup_transparent_map(&parent, &submap);
		vm_map_destroy_options(parent, VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP);
		// submap should be destroyed since it's only reference is from the parent
	}
}

static vm_map_entry_t
first_entry(struct vm_map_header* hdr)
{
	if (hdr->is_vm_map_copy) {
		vm_map_copy_t c = vm_map_copy_from_hdr(hdr);
		T_QUIET; T_ASSERT_EQ(c->type, VM_MAP_COPY_ENTRY_LIST, "type is entry-list");
		return vm_map_copy_first_entry(c);
	} else {
		return vm_map_first_entry(vm_map_from_hdr(hdr));
	}
}

static bool
entry_is_end(struct vm_map_header* hdr, vm_map_entry_t entry)
{
	if (hdr->is_vm_map_copy) {
		return entry == vm_map_copy_to_entry(vm_map_copy_from_hdr(hdr));
	} else {
		return entry == vm_map_to_entry(vm_map_from_hdr(hdr));
	}
}

struct copy_check_s {
	vm_map_size_t size;
	vm_object_offset_t offset;
	vm_prot_t prot;
	bool needs_copy;
	bool hole;
	bool is_submap;
	bool ignore;
	vm_object_offset_t shadow_offset;
};

// verify that a map is what it should be
static void
_check_entries(struct vm_map_header *map_or_copy_hdr, vm_map_address_t r_start, vm_map_address_t r_end,
    struct copy_check_s expected[], int expected_len, const char *desc)
{
	int idx = 0;
	vm_map_entry_t entry = first_entry(map_or_copy_hdr);
	vm_map_address_t addr = entry->vme_start;
	T_QUIET; T_ASSERT_EQ(addr, r_start, "entry %d end (first)", idx);
	vm_map_address_t start = addr;
	while (!entry_is_end(map_or_copy_hdr, entry)) {
		if (expected[idx].ignore) {
			T_LOG("%s-ignore", desc);
			entry = entry->vme_next;
			++idx;
			continue;
		}
		if (expected[idx].hole) {
			T_LOG("%s-hole %d  size=%llx", desc, idx, expected[idx].size);
			addr += expected[idx].size;
			++idx;
			continue;
		}
		T_QUIET; T_EXPECT_EQ((bool)entry->is_sub_map, expected[idx].is_submap, "entry %d is_submap", idx);
		T_LOG("%s-entry %d  start=%llx  end=%llx  offset=%llx  prot=%x  needs_copy=%d  sz=%llx  %s=%p", desc, idx,
		    entry->vme_start, entry->vme_end, VME_OFFSET(entry), entry->protection, entry->needs_copy,
		    entry->vme_end - entry->vme_start,
		    entry->is_sub_map ? "submap" : "obj",
		    entry->is_sub_map ? (void*)VME_SUBMAP(entry) : (void*)VME_OBJECT(entry));

		T_QUIET; T_ASSERT_LT(idx, expected_len, "too many entries");
		T_QUIET; T_EXPECT_EQ(entry->vme_start, addr, "entry %d start", idx);
		addr += expected[idx].size;
		T_QUIET; T_EXPECT_EQ(entry->vme_end, addr, "entry %d end", idx);
		T_QUIET; T_EXPECT_EQ(VME_OFFSET(entry), expected[idx].offset, "entry %d offset", idx);
		T_QUIET; T_EXPECT_EQ((vm_prot_t)entry->protection, expected[idx].prot, "entry %d protection", idx);
		T_QUIET; T_EXPECT_EQ((bool)entry->needs_copy, expected[idx].needs_copy, "entry %d needs_copy", idx);
		if (expected[idx].shadow_offset != 0) {
			T_QUIET; T_EXPECT_NOTNULL(VME_OBJECT(entry), "entry %d has object", idx);
			T_QUIET; T_EXPECT_EQ(VME_OBJECT(entry)->vo_shadow_offset, expected[idx].shadow_offset, "entry %d shadow_offset", idx);
		}

		// entry invariants about null object
		if (!entry->is_sub_map && VME_OBJECT(entry) == VM_OBJECT_NULL) {
			// some places have an invariant that null obj means offset = 0, but not all so this is not asserted
			T_QUIET; T_EXPECT_FALSE(entry->needs_copy, "entry %d null obj needs_copy", idx);
		}

		entry = entry->vme_next;
		++idx;
	}
	T_QUIET; T_ASSERT_EQ(idx, expected_len, "not enough entries");
	T_QUIET; T_ASSERT_EQ(addr, r_end, "entry %d end (last)", idx);
	T_PASS("check-%s-ok %llx %llx", desc, start, addr);
}

#define check_entries(hdr, r_start, r_end, expected_arr, desc) \
	_check_entries(hdr, r_start, r_end, expected_arr, countof(expected_arr), desc)

__enum_closed_decl(copy_func_t, int, {
	COPYIN_INTERNAL = 0x1,
	COPY_EXTRACT    = 0x2,
	_COPY_METHOD_MASK = 0x3,
	COPY_NO_DISCARD = 0x4
});

// call vm_map_copyin_internal and verify the copy we get is as expected
static void
_test_copyin(vm_map_t map, vm_map_address_t r_start, vm_map_address_t r_end,
    struct copy_check_s expected[], int expected_len, copy_func_t func)
{
	uint32_t copy_count_before = mock_mem_count_allocated(MEM_POOL_VM_MAP_COPIES);
	vm_map_copy_t result_copy = NULL;
	kern_return_t kr;
	if ((func & _COPY_METHOD_MASK) == COPYIN_INTERNAL) {
		kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	} else if ((func & _COPY_METHOD_MASK) == COPY_EXTRACT) {
		vm_prot_t cur_protection = VM_PROT_NONE, max_protection = VM_PROT_NONE;
		vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = true };
		kr = vm_map_copy_extract(map, r_start, r_end - r_start, true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_NONE, flags);
		// the copy here starts at 0 so move it so the checks do the right thing
		r_end = r_end - r_start;
		r_start = 0;
	} else {
		T_FAIL("unknown func");
	}
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm-copy call");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
	T_LOG("calling _check_entries");
	_check_entries(&result_copy->cpy_hdr, r_start, r_end, expected, expected_len, "copy");

	uint32_t expected_alloc_diff = 1;
	if ((func & COPY_NO_DISCARD) == 0) {
		vm_map_copy_discard(result_copy);
		expected_alloc_diff = 0;
	} // else it is leaked
	uint32_t alloc_diff = mock_mem_count_allocated(MEM_POOL_VM_MAP_COPIES) - copy_count_before;
	T_QUIET; T_ASSERT_EQ(alloc_diff, expected_alloc_diff, "discard deallocated copy");

	T_PASS("copy-ok %llx %llx", r_start, r_end);
}

#define test_copyin(map, r_start, r_end, expected_arr, func) \
	_test_copyin((map), (r_start), (r_end), (expected_arr), countof((expected_arr)), func)

static void
check_sealed_map_unchanged(vm_map_t parent_map, vm_map_t submap, bool was_clipped)
{
	T_LOG("checking submap unchanged...");
	check_entries(&submap->hdr, 0, MAP_BASE + 0x10000 + 6 * PAGE_SIZE, ((struct copy_check_s[]){
		{ .size = MAP_BASE + 0x10000, .prot = VM_PROT_NONE },
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = false },
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = false },
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = false },
		{ .ignore = true }
	}), "submap");
	T_LOG("checking parent map");
	if (!was_clipped) {
		check_entries(&parent_map->hdr, MAP_BASE + 0x50000, MAP_BASE + 0x50000 + 10 * PAGE_SIZE, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },
			{ .size = 6 * PAGE_SIZE, .offset = MAP_BASE + 0x10000, .prot = VM_PROT_DEFAULT, .needs_copy = true, .is_submap = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },
		}), "parent map");
	}
}

static void
copyin_inside_submap(bool sealead_submap, copy_func_t func)
{
	vm_map_t parent_map, submap;
	setup_map_with_submap(&parent_map, &submap, sealead_submap);
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();

	if (sealead_submap) {
		check_sealed_map_unchanged(parent_map, submap, false);
	}

	T_LOG("case 1");
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 3 * PAGE_SIZE; // middle of the first entry of the submap
		vm_map_address_t r_end =   r_start + 4 * PAGE_SIZE; // middle of the third entry of the submap

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_DEFAULT, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);

		if (sealead_submap) {
			check_sealed_map_unchanged(parent_map, submap, true);
		}
	}
	/* reset the map after each test because pmap unnesting may change it */
	setup_map_with_submap(&parent_map, &submap, sealead_submap);

	T_LOG("case 2");
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of the first entry of the submap
		vm_map_address_t r_end =   r_start + 5 * PAGE_SIZE; // middle of the third entry of the submap

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}
	setup_map_with_submap(&parent_map, &submap, sealead_submap);

	T_LOG("case 3");
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 3 * PAGE_SIZE; // middle of the first entry of the submap
		vm_map_address_t r_end =   r_start + 5 * PAGE_SIZE; // end of the third entry of the submap

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_DEFAULT, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}

	setup_map_with_submap(&parent_map, &submap, sealead_submap);

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of the first entry of the submap
		vm_map_address_t r_end =   r_start + 6 * PAGE_SIZE; // end of the third entry of the submap

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}
}

// test that copy-in creates the correct copy entries when operating on a sealed (sub)map
T_DECL(copyin_inside_submap, "copyin inside sealed submap")
{
	T_LOG("sealed submap - copyin_internal");
	copyin_inside_submap(true, COPYIN_INTERNAL);
	T_LOG("transparent submap - copyin_internal");
	copyin_inside_submap(false, COPYIN_INTERNAL);
}

T_DECL(copyex_inside_submap, "copy_extract inside sealed submap")
{
	T_LOG("sealed submap - copy_extract");
	copyin_inside_submap(true, COPY_EXTRACT);
	T_LOG("transparent submap - copy_extract");
	copyin_inside_submap(false, COPY_EXTRACT);
}

void
copyin_cross_to_sealed_map(copy_func_t func)
{
	vm_map_t parent_map, submap;
	setup_sealed_map(&parent_map, &submap);
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();
	/* reset the map after each test because pmap unnesting may change it */

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry of the parent
		vm_map_address_t r_end =   r_start + 6 * PAGE_SIZE; // middle of the third entry in the submap

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_DEFAULT, .needs_copy = true },   // from parent_map
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },       // from submap
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}
	setup_sealed_map(&parent_map, &submap);

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000; // start of the first entry of the parent_map
		vm_map_address_t r_end =   r_start + 7 * PAGE_SIZE; // middle of the third entry in the submap

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true }, // from parent_map
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true }, // from submap
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}
	setup_sealed_map(&parent_map, &submap);

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 3 * PAGE_SIZE; // middle of the first entry in the submap
		vm_map_address_t r_end =   r_start + 6 * PAGE_SIZE; // middle of the third entry in the parent_map

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_DEFAULT, .needs_copy = true },   // from submap
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },          // from submap
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },           // from parent_map
		}), func);
	}
	setup_sealed_map(&parent_map, &submap);

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the parent_map
		vm_map_address_t r_end =   r_start + 8 * PAGE_SIZE; // middle of the third entry in the parent_map

		test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_DEFAULT, .needs_copy = true },   // from parent_map
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },       // from submap
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },          // from submap
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },           // from parent_map
		}), func);
	}
}

T_DECL(copyin_cross_to_sealed_map, "copyin cross to sealed map") {
	copyin_cross_to_sealed_map(COPYIN_INTERNAL);
}
T_DECL(copyex_cross_to_sealed_map, "copy_extract cross to sealed map"){
	copyin_cross_to_sealed_map(COPY_EXTRACT);
}

static void
setup_flat_map(vm_map_t *map)
{
	// map has obj-entry (2 pages), NULL-obj-entry (2 pages), obj-entry (2 pages)
	*map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(*map, offset, PAGE_SIZE * 2, VM_PROT_READ, true);
	offset += PAGE_SIZE * 2;

	// this one needs a different protection, otherwise it will be coalesced with the previous one
	enter_obj_entry(*map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, false, NULL);
	offset += PAGE_SIZE * 2;

	enter_obj_entry(*map, offset, PAGE_SIZE * 2, VM_PROT_READ, true);
	T_QUIET; T_ASSERT_EQ((*map)->hdr.nentries, 3, "parent entries");
}

void
copyin_null_object(copy_func_t func)
{
	vm_map_t map;
	setup_flat_map(&map);
	bool expect_needs_copy = (func == COPYIN_INTERNAL) ? false : true;

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the map
		vm_map_address_t r_end =   r_start + 4 * PAGE_SIZE; // middle of the third entry in the map

		test_copyin(map, r_start, r_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = expect_needs_copy },
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 3 * PAGE_SIZE; // middle of the second entry in the map
		vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE; // middle of the third entry in the map

		vm_map_offset_t expected_offset = PAGE_SIZE;
		test_copyin(map, r_start, r_end, ((struct copy_check_s[]){
			// entry with NULL object should have offset==PAGE_SIZE and needs_copy if remap was called
			{ .size = PAGE_SIZE, .offset = expected_offset, .prot = VM_PROT_DEFAULT, .needs_copy = expect_needs_copy },
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), func);
	}
}
T_DECL(copyin_null_object, "copyin null object") {
	copyin_null_object(COPYIN_INTERNAL);
}
T_DECL(copyex_null_object, "copyex null object") {
	copyin_null_object(COPY_EXTRACT);
}


T_DECL(copyin_src_destroy, "copyin src_destroy")
{
	kern_return_t kr;
	vm_map_t map;
	setup_flat_map(&map);

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the map
		vm_map_address_t r_end =   r_start + 4 * PAGE_SIZE; // middle of the third entry in the map

		vm_map_copy_t result_copy = NULL;
		kr = vm_map_copyin_internal(map, r_start, r_end - r_start,
		    VM_MAP_COPYIN_ENTRY_LIST | VM_MAP_COPYIN_SRC_DESTROY, &result_copy);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
		// TODO check the copy

		check_entries(&map->hdr, MAP_BASE + 0x50000, MAP_BASE + 0x50000 + 6 * PAGE_SIZE, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 4 * PAGE_SIZE, .hole = true },
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = true },
		}), "map");

		vm_map_copy_discard(result_copy);
	}
}


T_DECL(copyin_beyond_range, "copyin beyond range")
{
	// map has 1 obj-entry (2 pages)
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_READ, true);

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the first entry in the map
		vm_map_address_t r_end =   r_start + 7 * PAGE_SIZE; // beyond the last entry

		vm_map_copy_t result_copy = NULL;
		kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_copyin_internal");
		T_QUIET; T_ASSERT_NULL(result_copy, "null result");
	}
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 - 1 * PAGE_SIZE; // before first entry of the map
		vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE; // middle of the first entry in the map

		vm_map_copy_t result_copy = NULL;
		kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_copyin_internal");
		T_QUIET; T_ASSERT_NULL(result_copy, "null result");
	}
}


T_DECL(copyin_lookup_after_copy, "copyin lookup after copy")
{
	// map has 1 obj-entry (2 pages)
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_READ | VM_PROT_WRITE, false, NULL);

	vm_map_address_t r_start = MAP_BASE + 0x50000; // start of the first entry in the map
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // beyond the last entry

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal");

	{
		// simulate what's going to happen in a fault immediately after the copy
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		vm_object_t object = NULL;
		vm_map_entry_t entry = VM_MAP_ENTRY_NULL;
		vm_object_offset_t lookup_offset = 0;
		vm_prot_t prot = 0;
		boolean_t wired = false;
		vm_map_t real_map = NULL;

		kr = vm_map_lookup_object_and_lock_entry(&map, r_start,
		    VM_PROT_READ | VM_PROT_WRITE, &object, &entry, &lookup_offset,
		    &prot, &wired, NULL, &real_map, ctx, NULL, false);
		T_ASSERT_MACH_SUCCESS(kr, "vm_map_lookup_and_lock_object");

		vm_map_range_sh_unlock(ctx, NULL);
	}
}

// start map with single entry with needs_copy == false and a non-null object
// copy the middle, then check that it was clipped/not-clipped and setup for COW
void
copyin_setup_cow_with_obj(copy_func_t func, bool expect_clip)
{
	// map with single 3-page entry
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_size_t m_size = 3 * PAGE_SIZE;
	vm_map_address_t m_end = m_start + m_size;
	vm_map_address_t offset = m_start;
	vm_object_t obj = vm_object_allocate(m_size, map->serial_id);
	enter_obj_entry(map, offset, m_size, VM_PROT_READ, false, obj);
	T_QUIET; T_ASSERT_EQ(obj->ref_count, 1, "obj ref-count");

	vm_map_address_t r_start = m_start + 1 * PAGE_SIZE; // middle of the entry
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of the entry

	test_copyin(map, r_start, r_end, ((struct copy_check_s[]){
		{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = true }
	}), func | COPY_NO_DISCARD);
	// don't discard copy since we want to count references

	if (expect_clip) {
		check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
			{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = false },
			{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = PAGE_SIZE, .offset = 2 * PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = false },
		}), "map");
		// 3 entries in the existing map each holding an obj reference, 1 in the new copy
		T_ASSERT_EQ(obj->ref_count, 4, "obj ref-count");
	} else {
		// the original entry in the map is not clipped
		check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
			{ .size = 3 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), "map");
		// 1 entry in the existing map each holding an obj reference, 1 in the new copy
		T_ASSERT_EQ(obj->ref_count, 2, "obj ref-count");
	}
}

T_DECL(copyin_setup_cow_with_obj, "copyin setup cow with obj") {
	copyin_setup_cow_with_obj(COPYIN_INTERNAL, /*expect_clip=*/ true);
}
T_DECL(copyex_setup_cow_with_obj, "copyin setup cow with obj") {
	copyin_setup_cow_with_obj(COPY_EXTRACT, /*expect_clip=*/ false);
}

// start map with single entry with needs_copy == false, with a null obj
// copy the middle, it should not be clipped and needs_copy remain false (because obj is NULL)
void
copyin_setup_cow_with_null_obj(copy_func_t func)
{
	// map with single 3-page entry
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_size_t m_size = PAGE_SIZE * 3;
	vm_map_address_t m_end = m_start + m_size;
	vm_map_address_t offset = m_start;
	enter_obj_entry(map, offset, m_size, VM_PROT_READ, false, NULL);

	vm_map_address_t r_start = m_start + PAGE_SIZE; // middle of the entry
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of entry

	// in copyin/remap entry with null object would have offset!=0
	vm_map_offset_t expected_null_obj_offset = PAGE_SIZE;
	bool expect_needs_copy;
	if (func == COPY_EXTRACT) {
		expect_needs_copy = true;
	} else {
		expect_needs_copy = false;
	}
	test_copyin(map, r_start, r_end, ((struct copy_check_s[]){
		{ .size = PAGE_SIZE, .offset = expected_null_obj_offset, .prot = VM_PROT_READ, .needs_copy = expect_needs_copy }
	}), func);
	check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
		{ .size = 3 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = expect_needs_copy },
	}), "map");
}

T_DECL(copyin_setup_cow_with_null_obj, "copyin setup cow with null obj") {
	copyin_setup_cow_with_null_obj(COPYIN_INTERNAL);
}
T_DECL(copyex_setup_cow_with_null_obj, "copyin setup cow with null obj") {
	copyin_setup_cow_with_null_obj(COPY_EXTRACT);
}

// start map with single entry with needs_copy == false, with a null obj
// copy the middle, and destroy source. There should be a hole in the middle of the source map
// (only copyin_internal, copy_extracty doesn't do DESTROY)
T_DECL(copyin_setup_cow_with_null_obj_and_destroy, "copyin setup cow with null obj and destroy")
{
	// map with single 3-page entry
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_size_t m_size = PAGE_SIZE * 3;
	vm_map_address_t m_end = m_start + m_size;
	vm_map_address_t offset = m_start;
	enter_obj_entry(map, offset, m_size, VM_PROT_READ, false, NULL);

	vm_map_address_t r_start = m_start + PAGE_SIZE; // middle of the entry
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of entry

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start,
	    VM_MAP_COPYIN_ENTRY_LIST | VM_MAP_COPYIN_SRC_DESTROY,
	    &result_copy);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

	check_entries(&result_copy->cpy_hdr, r_start, r_end, ((struct copy_check_s[]){
		// entry with null object may have offset!=0
		{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = false }
	}), "copy");
	check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
		{ .size = PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = false },
		{ .size = PAGE_SIZE, .hole = true },
		{ .size = PAGE_SIZE, .offset = 2 * PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = false },
	}), "map");

	vm_map_copy_discard(result_copy);
}

// transparent submap entry may have COPY_SYMMETRIC entry so it needs to get needs_copy
T_DECL(copyin_setup_cow_in_transparent_submap, "setup cow in transparent submap")
{
	vm_map_t parent_map, submap;
	setup_transparent_map(&parent_map, &submap);
	// change the first entry of the submap
	vm_map_entry_t entry = vm_map_first_entry(submap);
	{
		entry->protection = VM_PROT_WRITE | VM_PROT_READ;
		vm_object_t object = VME_OBJECT(entry);
		T_QUIET; T_ASSERT_EQ(object->ref_count, 1, "object has one owner");
		object->copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC;
		T_QUIET; T_ASSERT_FALSE(entry->needs_copy, "stays false from initialization");
	}

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_address_t r_start = m_start + 2 * PAGE_SIZE; // start of the first entry of the submap
	vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE; // end of the first entry of the submap

	test_copyin(parent_map, r_start, r_end, ((struct copy_check_s[]){
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_WRITE | VM_PROT_READ, .needs_copy = true },
	}), COPYIN_INTERNAL);
	// needs_copy of the original entry turned to true
	T_ASSERT_TRUE(entry->needs_copy, "turned to true");
	T_ASSERT_EQ((int)entry->protection, VM_PROT_WRITE | VM_PROT_READ, "prot didn't change");
}


// map with originally 2 entries the differ in "needs_copy", after copy gets simplified to 1 entry
// due to simplification that occurs after the copy
// (only copyin_internal, copy_extract doesn't do simplify currently)
T_DECL(copyin_simplify_needs_copy, "simplify needs copy")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_size_t m_size = PAGE_SIZE * 2;
	vm_map_address_t m_end = m_start + m_size;

	vm_object_t obj = vm_object_allocate(m_size, map->serial_id);
	vm_map_address_t offset = m_start;
	enter_obj_entry(map, offset, PAGE_SIZE, VM_PROT_READ, true, obj);
	offset += PAGE_SIZE;
	enter_obj_entry(map, offset, PAGE_SIZE, VM_PROT_READ, false, obj, PAGE_SIZE);
	T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 2, "parent entries");

	vm_map_address_t r_start = m_start + 1 * PAGE_SIZE; // start of the second entry
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // end of the second entry

	test_copyin(map, r_start, r_end, ((struct copy_check_s[]){
		{ .size = PAGE_SIZE, .offset = PAGE_SIZE, .prot = VM_PROT_READ, .needs_copy = true },
	}), COPYIN_INTERNAL);
	// the 2 entries coalesced to 1
	check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
	}), "map");
}

// copyin_internal with a range that includes a hole should fail gracefully
T_DECL(copyin_over_hole, "copyin over hole")
{
	// map has obj-entry (2 pages), hole (2 pages), obj-entry (2 pages)
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_READ, true);
	offset += PAGE_SIZE * 2;
	// hole
	offset += PAGE_SIZE * 2;
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_READ, true);
	T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 2, "parent entries");

	vm_map_address_t r_start = MAP_BASE + 0x50000 + PAGE_SIZE; // middle of the first entry in the map
	vm_map_address_t r_end =   r_start + 4 * PAGE_SIZE; // middle of second entry in the map, after the hole

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_copyin_internal");
}

T_DECL(copyin_fail_phys_contiguous, "copyin fail phys_contiguous")
{
	// map with single 3-page entry
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t offset = MAP_BASE + 0x50000;
	vm_map_size_t size = PAGE_SIZE * 3;
	vm_object_t obj = vm_object_allocate(size, map->serial_id);
	obj->phys_contiguous = true;
	enter_obj_entry(map, offset, size, VM_PROT_READ, true, obj);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + PAGE_SIZE; // middle of the entry
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of entry

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copyin_internal");
}

// copyin fails due to protection check on a flat map
T_DECL(copyin_fail_no_read, "copyin fail no read")
{
	// map with single 3-page entry
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(map, offset, PAGE_SIZE * 3, VM_PROT_NONE, true);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + PAGE_SIZE; // middle of the entry
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of entry

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copyin_internal");
}

// copyin fails due to protection check in a submap
static void
copyin_fail_no_read_from_submap(bool sealed_submap)
{
	vm_map_t parent_map, submap;
	setup_map_with_submap(&parent_map, &submap, sealed_submap);
	vm_map_entry_t entry = vm_map_first_entry(submap);
	if (sealed_submap) { // first entry of a constant submap is padding from the 0 so we need the second
		entry = entry->vme_next;
	}
	entry->protection = VM_PROT_NONE;

	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of the first entry of submap
		vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of first entry of the submap (the one with VM_PROT_NONE)

		vm_map_copy_t result_copy = NULL;
		kern_return_t kr = vm_map_copyin_internal(parent_map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
		T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copyin_internal");
	}
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + PAGE_SIZE; // middle of the first entry of parent_map
		vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE; // middle of first entry of the submap (the one with VM_PROT_NONE)

		vm_map_copy_t result_copy = NULL;
		kern_return_t kr = vm_map_copyin_internal(parent_map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
		T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copyin_internal");
	}
}

T_DECL(copyin_fail_no_read_from_submap, "copyin fail no read from constant submap")
{
	copyin_fail_no_read_from_submap(true);
	copyin_fail_no_read_from_submap(false);
}

// if the start address is not aligned to page alignment, the copy needs to have the offset
T_DECL(copyin_unaligned_start, "copyin unaligned start")
{
	vm_map_t map;
	setup_flat_map(&map);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE + 0x99; // middle of the first entry in the map
	vm_map_address_t r_end =   r_start + 4 * PAGE_SIZE; // middle of the third entry in the map

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_end - r_start, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

	T_ASSERT_EQ(result_copy->offset, r_start, "copy offset");
	vm_map_copy_discard(result_copy);
}

T_DECL(copyin_sanitize_bad_address, "copyin sanitize bad address")
{
	vm_map_t map;
	setup_flat_map(&map);

	vm_map_address_t r_start = 0xfffffffffff10000;
	vm_map_address_t r_len =             0x100000;

	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copyin_internal(map, r_start, r_len, VM_MAP_COPYIN_ENTRY_LIST, &result_copy);
	T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_copyin_internal");
	T_QUIET; T_ASSERT_NULL(result_copy, "null result");
}


// check the required_cur_prot enforcement in _new mode
void
copyex_new_protection_req(bool sealed_submap)
{
	vm_map_t parent_map, submap;

	vm_map_address_t r_start = MAP_BASE + 0x50000; // start of the first entry in the parent-map
	vm_map_address_t r_end =   r_start + 10 * PAGE_SIZE; // end of the third entry in the parent-map
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };

	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_NONE; // doesn't matter
	vm_prot_t max_protection = VM_PROT_NONE; // doesn't matter
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();

	T_LOG("sealed-submap: %d", (int)sealed_submap);
	// happy case, copy
	{
		setup_map_with_submap(&parent_map, &submap, sealed_submap);

		kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
		    /* copy= */ true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "not-null result");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_NONE, "cur_prot shouldn't change");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_NONE, "max_prot shouldn't change");
	}
	result_copy = NULL; // reset for next

	// top_copy=true, not allowed to copy due to source max_protection in parent-map
	{
		setup_map_with_submap(&parent_map, &submap, sealed_submap);
		vm_map_first_entry(parent_map)->max_protection = VM_PROT_NONE;
		kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
		    /* copy= */ true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "not-null result");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_NONE, "cur_prot shouldn't change");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_NONE, "max_prot shouldn't change");
	}

	// top_copy=true, not allowed to copy due to source max_protection in submap
	{
		setup_map_with_submap(&parent_map, &submap, sealed_submap);
		// first entry of the submap is the filler from the space start, so we need to second
		vm_map_first_entry(submap)->vme_next->max_protection = VM_PROT_NONE;
		kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
		    /* copy= */ true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "not-null result");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_NONE, "cur_prot shouldn't change");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_NONE, "max_prot shouldn't change");
	}

	// top_copy=false (share), but submap has needs_copy=true, not allowed to copy due to source max_protection in submap
	// (needs to be PROT_READ for copy)
	if (sealed_submap) { // only sealed submap has needs_copy=true
		setup_map_with_submap(&parent_map, &submap, sealed_submap);
		// first entry of the submap is the filler from the space start, so we need to second
		vm_map_first_entry(submap)->vme_next->max_protection = VM_PROT_NONE;
		kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "not-null result");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_NONE, "cur_prot shouldn't change");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_NONE, "max_prot shouldn't change");
	}

	// share, happy case, needs only READ
	{
		setup_map_with_submap(&parent_map, &submap, sealed_submap);
		cur_protection = VM_PROT_READ;
		max_protection = VM_PROT_READ;
		kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "not-null result");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_READ, "cur_prot shouldn't change");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_READ, "max_prot shouldn't change");
	}
	result_copy = NULL; // reset for next

	// share, argument requires WRITE, but parent entry has only READ
	{
		setup_map_with_submap(&parent_map, &submap, sealed_submap);
		vm_map_first_entry(parent_map)->max_protection = VM_PROT_READ;
		cur_protection = VM_PROT_WRITE;
		max_protection = VM_PROT_WRITE;
		kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "not-null result");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_WRITE, "cur_prot shouldn't change");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_WRITE, "max_prot shouldn't change");
	}

	// can't test share from a submap since both constant and transparent
	// submaps have needs_copy on the entry that points to the submap

	T_PASS("all ok");
}

T_DECL(copyex_new_protection_req, "copyex_new_protection_req")
{
	copyex_new_protection_req(true);
	copyex_new_protection_req(false);
}



// Try to create a share copy of a top-level map entry that's RO
// fails because we're trying to explicitly bypass RO
T_DECL(copyex_new_topmap_ro_to_rw_share, "copyex_new_topmap_ro_to_rw_share")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_address_t offset = MAP_BASE + 0x50000;
	enter_obj_entry(map, offset, PAGE_SIZE * 3, VM_PROT_READ, false);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + 1 * PAGE_SIZE; // middle of the only entry in the map
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // middle of the only entry in the map

	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_prot_t max_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

	T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NULL(result_copy, "null result");
}


// Try to create a share copy of an entry in a constant-submap (shared-cache) that's RO
// since the submap-entry has needs_copy=true, this succeeds and created a COW copy (instead of share)
// see also vm_test_mach_map.c:shared_region_share_writable
T_DECL(copyex_new_const_submap_ro_to_rw_share, "copyex_new_const_submap_ro_to_rw_share")
{
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();
	vm_map_t parent_map, submap;
	setup_sealed_map(&parent_map, &submap);

	vm_map_address_t r_start = MAP_BASE + 0x50000 + 5 * PAGE_SIZE; // middle of the second entry in the submap that is PROT_READ
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // same entry

	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_prot_t max_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

	check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
		{ .size = 1 * PAGE_SIZE, .shadow_offset = 1 * PAGE_SIZE, .prot = VM_PROT_READ | VM_PROT_WRITE, .needs_copy = false },
	}), "copy");
}

const char*
copy_sttgy_name(memory_object_copy_strategy_t s)
{
	switch (s) {
	case MEMORY_OBJECT_COPY_DELAY: return "DELAY";
	case MEMORY_OBJECT_COPY_SYMMETRIC: return "SYMMETRIC";
	case MEMORY_OBJECT_COPY_NONE: return "NONE";
	default: return "other";
	}
}
void
show_entry(const char* desc, vm_map_entry_t entry)
{
	T_LOG("%s Entry %p  needs_copy=%d, Objects chain:", desc, entry, entry->needs_copy);
	vm_object_t obj = VME_OBJECT(entry);
	while (obj != NULL) {
		T_LOG("    %p : %s   vo_copy=%p", obj, copy_sttgy_name(obj->copy_strategy), obj->vo_copy);
		obj = obj->shadow;
	}
}

// create a "share" copy from an entry in a constant-submap that has needs_copy=true
// check that it is create with DELAY object as the top object
static void
copyex_share_from_constant_needs_copy_submap(bool single_object)
{
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();

	T_LOG("single-object: %d", (int)single_object);
	vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of the first entry in the submap
	vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE; // end of the first entry in the submap

	// setup the submap
	vm_map_t parent_map, submap;
	setup_sealed_map(&parent_map, &submap, /*needs_copy=*/ true);
	vm_map_entry_t submap_entry = first_entry(&submap->hdr)->vme_next; // first is a dummy in a constant submap
	show_entry("Submap", submap_entry);

	// make the call to create the copy
	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_prot_t max_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false, .vmkf_copy_single_object = single_object };
	kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

	// verify object chain
	vm_map_entry_t entry = first_entry(&result_copy->cpy_hdr);
	show_entry("Copy", entry);
	// the top object should be DELAY since that's the standard for sharable copies
	vm_object_t obj1 = VME_OBJECT(entry);
	T_QUIET; T_ASSERT_EQ((bool)entry->needs_copy, false, "share entry should not have needs_copy");
	T_QUIET; T_ASSERT_NOTNULL(obj1, "share entry must have object");
	T_QUIET; T_ASSERT_EQ(obj1->copy_strategy, MEMORY_OBJECT_COPY_DELAY, "share entry should have DELAY sttgy");

	// the shadow of the first object should be SYMMETRIC since it was a product of the CoW
	// due to needs_copy on the submap
	vm_object_t obj2 = obj1->shadow;
	T_QUIET; T_ASSERT_NOTNULL(obj2, "share entry object shadow null");
	T_QUIET; T_ASSERT_EQ(obj2->copy_strategy, MEMORY_OBJECT_COPY_SYMMETRIC, "share shadow should be CoW");

	vm_object_t obj3 = obj2->shadow;
	T_QUIET; T_ASSERT_EQ_PTR(obj3, VME_OBJECT(submap_entry), "share shadow-shadow points to submap");
}

T_DECL(copyex_share_from_constant_needs_copy_submap, "copyex_share_from_constant_needs_copy_submap")
{
	copyex_share_from_constant_needs_copy_submap(false);
	copyex_share_from_constant_needs_copy_submap(true);
}

static void
copyex_share_from_constant_non_needs_copy_submap(bool single_object)
{
	T_MOCK_pmap_shared_region_size_min_RET_PAGE_SIZE();

	T_LOG("single-object: %d", (int)single_object);
	vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of the first entry in the submap
	vm_map_address_t r_end =   r_start + 2 * PAGE_SIZE; // end of the first entry in the submap

	// setup the submap
	vm_map_t parent_map, submap;
	setup_sealed_map(&parent_map, &submap, /*needs_copy=*/ false);
	vm_map_entry_t submap_entry = first_entry(&submap->hdr)->vme_next; // first is a dummy in a constant submap
	show_entry("Submap", submap_entry);

	// make the call to create the copy
	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_prot_t max_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false, .vmkf_copy_single_object = single_object };
	kern_return_t kr = vm_map_copy_extract(parent_map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

	vm_map_entry_t entry = first_entry(&result_copy->cpy_hdr);
	show_entry("Copy", entry);

	// share copy without CoW intermediate copy, point as the same object as the submap
	vm_object_t obj1 = VME_OBJECT(entry);
	T_QUIET; T_ASSERT_EQ((bool)entry->needs_copy, false, "share entry should not have needs_copy");
	T_QUIET; T_ASSERT_EQ_PTR(obj1, VME_OBJECT(submap_entry), "share object is the same as submap");
	T_QUIET; T_ASSERT_EQ(obj1->copy_strategy, MEMORY_OBJECT_COPY_DELAY, "share entry should have DELAY sttgy");
}

T_DECL(copyex_share_from_constant_non_needs_copy_submap, "copyex_share_from_constant_non_needs_copy_submap")
{
	copyex_share_from_constant_non_needs_copy_submap(false);
	copyex_share_from_constant_non_needs_copy_submap(true);
}

// check that a protection failure in a later entry doesn't cause an obj-ref
// leak of the first entries that succeeded sharing
T_DECL(copyex_share_failure_doesnt_change_objref, "copyex_share_failure_doesnt_change_objref")
{
	vm_map_t map;
	setup_flat_map(&map);

	vm_map_address_t r_start = MAP_BASE + 0x50000;  // start of first entry of the map
	vm_map_address_t r_end =   r_start + 6 * PAGE_SIZE; // end of last entry of the map

	vm_map_first_entry(map)->protection = VM_PROT_DEFAULT;
	// first 2 entries have VM_PROT_DEFAULT (READ | WRITE), 3rd remains VM_PROT_READ

	// require every entry to be PROT_DEFAULT
	vm_prot_t cur_protection = VM_PROT_DEFAULT;
	vm_prot_t max_protection = VM_PROT_DEFAULT;

	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	vm_map_copy_t result_copy = NULL;
	kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

	T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NULL(result_copy, "null result");

	for (vm_map_entry_t e = vm_map_first_entry(map); !entry_is_map_end(map, e); e = e->vme_next) {
		// only 1 reference, from the map entries
		vm_object_t object = VME_OBJECT(e);
		T_QUIET; T_ASSERT_EQ(object->ref_count, 1, "object ref_count");
	}
}

// test "case 3" of vm_map_create_private_symmetric_object()
T_DECL(copyex_share_entry_on_partial_object, "copyex_share_entry_on_partial_object")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_address_t m_end = m_start + 4 * PAGE_SIZE;

	// with with 2 entries:  exact_obj entry (2 pages), big_obj entry (2 pages entry, into object of 4 pages)
	vm_map_address_t offset = m_start;
	vm_object_t exact_obj = vm_object_allocate(2 * PAGE_SIZE, map->serial_id);
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, false, exact_obj, 0);
	offset += PAGE_SIZE * 2;

	vm_object_t big_obj = vm_object_allocate(4 * PAGE_SIZE, map->serial_id);
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, false, big_obj, 0);
	T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 2, "map entries");

	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_DEFAULT;
	vm_prot_t max_protection = VM_PROT_DEFAULT;

	// (control test) make a share copy of first entry where none of the cases vm_map_create_private_symmetric_object() apply
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000; // start of first entry
		vm_map_address_t r_end = r_start + 2 * PAGE_SIZE; // end of first entry

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
		T_QUIET; T_ASSERT_EQ(result_copy->cpy_hdr.nentries, 1, "copy size");

		// check original object was not shadowed
		vm_map_entry_t e = vm_map_copy_first_entry(result_copy);
		vm_object_t obj = VME_OBJECT(e);
		T_QUIET; T_ASSERT_EQ_PTR(obj, exact_obj, "same as input object");
		T_QUIET; T_ASSERT_NULL(obj->shadow, "object not shadowed");
		T_QUIET; T_ASSERT_FALSE(e->needs_copy, "entry needs_copy");
	}

	// make a share copy of the second entry where the entry is shorter than the object where "case 3" of
	// vm_map_create_private_symmetric_object() applies and causes the creation of a shadow object
	{
		vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of second entry
		vm_map_address_t r_end = r_start + 2 * PAGE_SIZE; // end of second entry

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
		T_QUIET; T_ASSERT_EQ(result_copy->cpy_hdr.nentries, 1, "copy size");

		// object in the entry is shadowed
		vm_map_entry_t e = vm_map_copy_first_entry(result_copy);
		vm_object_t obj = VME_OBJECT(e);
		T_QUIET; T_ASSERT_NE_PTR(obj, big_obj, "same as input object");
		T_QUIET; T_ASSERT_EQ_PTR(obj->shadow, big_obj, "object is shadowed");
		T_QUIET; T_ASSERT_NULL(obj->shadow->shadow, "object is shadowed once");
		T_QUIET; T_ASSERT_NULL(obj->shadow->vo_copy, "object shadow vo_copy");
		T_QUIET; T_ASSERT_FALSE(e->needs_copy, "entry needs_copy");
	}
}

// test way protection arguments work in legacy mode and in prot_copy mode
T_DECL(copyex_legacy_mode_protection, "copyex_legacy_mode_protection")
{
	vm_map_t map;
	setup_flat_map(&map);
	vm_map_first_entry(map)->protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
	// first entry: RWX, second entry RW-, third entry: R--

	vm_map_address_t r_start = MAP_BASE + 0x50000; // start of first entry
	vm_map_address_t r_end = r_start + 6 * PAGE_SIZE; // end of third entry
	vm_map_copy_t result_copy = NULL;

	// normal legacy mode
	{
		vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = true };
		vm_prot_t cur_protection = VM_PROT_NONE;
		vm_prot_t max_protection = VM_PROT_NONE;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start, true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_NONE, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
		// the copy gets the same protection as the map
		check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true /* obj was null */ },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), "copy");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_READ, "cur_prot get the least protection from the range");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_DEFAULT, "max_prot get the least protection from the range");
	}

	// prot_copy mode - copy entries protection are masked by the input max_protection
	{
		vm_map_kernel_flags_t flags = { .vmkf_remap_prot_copy = true };
		vm_prot_t cur_protection = VM_PROT_NONE;
		vm_prot_t max_protection = VM_PROT_READ;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start, true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_NONE, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
		// the copy gets the same protection as the map
		check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true /* obj was null */ },
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		}), "copy");
		T_QUIET; T_ASSERT_EQ(cur_protection, VM_PROT_READ, "cur_prot get the least protection from the range");
		T_QUIET; T_ASSERT_EQ(max_protection, VM_PROT_DEFAULT, "max_prot get the least protection from the range");
	}
}

// start with a map that does't have any copy, create a cow copy, then create a share copy
T_DECL(copyex_copy_then_share, "copyex_copy_then_share")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_address_t m_end = m_start + 2 * PAGE_SIZE;

	vm_map_address_t offset = m_start;
	vm_object_t obj = vm_object_allocate(2 * PAGE_SIZE, map->serial_id);
	enter_obj_entry(map, offset, PAGE_SIZE * 2, VM_PROT_DEFAULT, /* needs_copy= */ false, obj, 0);
	T_QUIET; T_ASSERT_EQ(obj->copy_strategy, MEMORY_OBJECT_COPY_SYMMETRIC, "map obj strategy");

	vm_map_address_t r_start = MAP_BASE + 0x50000; // start of only entry
	vm_map_address_t r_end = r_start + 2 * PAGE_SIZE; // end of only entry

	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	vm_prot_t cur_protection = VM_PROT_DEFAULT;
	vm_prot_t max_protection = VM_PROT_DEFAULT;
	vm_map_copy_t result_copy = NULL;

	T_LOG("CoW copy stage");
	{
		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start, /*copy=*/ true, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_NONE, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
		// copy got needs_copy=true
		check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },
		}), "copy");
		vm_map_entry_t cp_e = vm_map_copy_first_entry(result_copy);
		vm_object_t cp_obj = VME_OBJECT(cp_e);
		T_QUIET; T_ASSERT_EQ_PTR(cp_obj, obj, "copy has same obj");
		T_QUIET; T_ASSERT_NULL(cp_obj->shadow, "obj in copy has no shadow");
		T_QUIET; T_ASSERT_EQ(cp_obj->copy_strategy, MEMORY_OBJECT_COPY_SYMMETRIC, "copy obj strategy");
		T_QUIET; T_ASSERT_FALSE(cp_e->is_shared, "copy entry marked as shared");
		T_QUIET; T_ASSERT_EQ(cp_obj->ref_count, 2, "obj ref-count"); // copy and map reference the same obj

		// map entry changed to needs_copy=true
		check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = true },
		}), "map");
		vm_map_entry_t m_e = vm_map_first_entry(map);
		vm_object_t m_obj = VME_OBJECT(m_e);
		T_QUIET; T_ASSERT_EQ_PTR(m_obj, obj, "map has same obj");
		T_QUIET; T_ASSERT_NULL(m_obj->shadow, "obj in map has no shadow");
		T_QUIET; T_ASSERT_FALSE(m_e->is_shared, "copy entry marked as shared");
	}
	result_copy = NULL; // reset for next

	T_LOG("share copy stage");
	{
		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start, /*copy=*/ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_NONE, flags);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

		// copy has a shadow object created
		check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = false },
		}), "copy");
		vm_map_entry_t cp_e = vm_map_copy_first_entry(result_copy);
		vm_object_t cp_obj = VME_OBJECT(cp_e);
		T_QUIET; T_ASSERT_NE_PTR(cp_obj, obj, "copy has a different obj");
		T_QUIET; T_ASSERT_EQ_PTR(cp_obj->shadow, obj, "obj in copy is the shadow");
		T_QUIET; T_ASSERT_EQ(cp_obj->copy_strategy, MEMORY_OBJECT_COPY_DELAY, "copy obj strategy");
		T_QUIET; T_ASSERT_TRUE(cp_e->is_shared, "copy entry marked as shared");
		T_QUIET; T_ASSERT_EQ(cp_obj->ref_count, 2, "copy obj ref-count"); // this copy and map reference the new obj
		T_QUIET; T_ASSERT_EQ(obj->ref_count, 2, "original obj ref-count"); // original object reference from the new obj and above copy

		// map entry is stabilized to the same object
		check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = false },
		}), "map");
		vm_map_entry_t m_e = vm_map_first_entry(map);
		vm_object_t m_obj = VME_OBJECT(m_e);
		T_QUIET; T_ASSERT_EQ_PTR(m_obj, cp_obj, "map has same obj");
		T_QUIET; T_ASSERT_TRUE(m_e->is_shared, "copy entry marked as shared");
	}
}

T_DECL(copyex_misuse_range_outside_allocation, "copyex_misuse_range_outside_allocation")
{
	vm_map_t map;
	setup_flat_map(&map);

	vm_map_address_t r_start = MAP_BASE + 0x40000; // outside any allocation
	vm_map_address_t r_end =   r_start + 1 * PAGE_SIZE; // still outside

	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_prot_t max_protection = VM_PROT_READ | VM_PROT_WRITE;
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

	T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NULL(result_copy, "null result");
}

// create a share copy from an entry with a null object
T_DECL(copyex_share_from_null_obj, "copy_ex_share_from_null_obj")
{
	vm_map_t map;
	setup_flat_map(&map);

	vm_map_address_t m_start = MAP_BASE + 0x50000;
	vm_map_address_t m_end = m_start + 6 * PAGE_SIZE;

	vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of second entry
	vm_map_address_t r_end = r_start + 2 * PAGE_SIZE; // end of second entry

	vm_map_copy_t result_copy = NULL;
	vm_prot_t cur_protection = VM_PROT_DEFAULT;
	vm_prot_t max_protection = VM_PROT_DEFAULT;
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };

	kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
	    /* copy= */ false, &result_copy,
	    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
	T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

	// copy entry now has object
	check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = false },
	}), "copy");
	vm_map_entry_t cp_e = vm_map_copy_first_entry(result_copy);
	vm_object_t cp_obj = VME_OBJECT(cp_e);
	T_QUIET; T_ASSERT_NOTNULL(cp_obj, "copy entry has non null object");
	T_QUIET; T_ASSERT_NULL(cp_obj->shadow, "copy entry object has no shadow");
	// share always creates a stable DELAY object
	T_QUIET; T_ASSERT_EQ(cp_obj->copy_strategy, MEMORY_OBJECT_COPY_DELAY, "copy obj strategy");
	// this was a share call so both copy and map should have is_shared
	T_QUIET; T_ASSERT_TRUE(cp_e->is_shared, "copy entry marked as shared");
	T_QUIET; T_ASSERT_EQ(cp_obj->ref_count, 2, "copy obj ref-count");

	// map entry now has the same object
	check_entries(&map->hdr, m_start, m_end, ((struct copy_check_s[]){
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_DEFAULT, .needs_copy = false },
		{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = true },
	}), "map");
	vm_map_entry_t m_e = vm_map_first_entry(map)->vme_next; // go to second entry, the one we mapped
	vm_object_t m_obj = VME_OBJECT(m_e);
	T_QUIET; T_ASSERT_EQ_PTR(m_obj, cp_obj, "map has same obj");
	T_QUIET; T_ASSERT_TRUE(m_e->is_shared, "copy entry marked as shared");
}

// test flow that has flags.vmkf_copy_single_object, this comes from mach_make_memory_entry_64()
T_DECL(copyex_single_entry_flow, "copyex_single_entry_flow")
{
	vm_map_t map;
	setup_flat_map(&map);

	// range has all 3 entries, but copy would only have 1
	vm_map_address_t r_start = MAP_BASE + 0x50000; // start of first entry
	vm_map_address_t r_end = r_start + 6 * PAGE_SIZE; // end of third entry
	vm_map_kernel_flags_t flags = { .vmkf_copy_single_object = true, .vmkf_remap_legacy_mode = false };
	vm_map_copy_t result_copy = NULL;
	// happy case
	{
		vm_prot_t cur_protection = VM_PROT_READ;
		vm_prot_t max_protection = VM_PROT_READ;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");

		// copy has 1 entry
		check_entries(&result_copy->cpy_hdr, 0, 2 * PAGE_SIZE, ((struct copy_check_s[]){
			{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_READ, .needs_copy = false },
		}), "copy");
	}
	result_copy = NULL; // reset for next

	// protection fail case
	{
		// try to give map R-- as RW-
		vm_prot_t cur_protection = VM_PROT_DEFAULT;
		vm_prot_t max_protection = VM_PROT_DEFAULT;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* copy= */ false, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "null result");
	}
}

// remap of VM_PROT_NONE region doesn't create an object and remains is_shared=false
// and other cases from rdar://123312205
void
copyex_prot_none(bool do_copy)
{
	vm_map_t map;
	setup_flat_map(&map);
	// set prot=NONE on second entry which has object=NULL
	vm_map_entry_t second_entry = vm_map_first_entry(map)->vme_next;
	second_entry->protection = VM_PROT_NONE;
	second_entry->max_protection = VM_PROT_NONE;

	vm_map_address_t r_start = MAP_BASE + 0x50000 + 2 * PAGE_SIZE; // start of second entry (with null object)
	vm_map_address_t r_end = r_start + 2 * PAGE_SIZE; // end of second entry
	vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
	vm_map_copy_t result_copy = NULL;

	// assert if max_prot is lower than cur_prot
	{
		vm_prot_t cur_protection = VM_PROT_WRITE;
		vm_prot_t max_protection = VM_PROT_NONE;
		T_ASSERT_PANIC({
			kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
			/* do_copy= */ do_copy, &result_copy,
			&cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		}, "wrong cur-max protection");
	}

	// fail to remap protection --- as -W-
	{
		vm_prot_t cur_protection = VM_PROT_WRITE;
		vm_prot_t max_protection = VM_PROT_WRITE;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* do_copy= */ do_copy, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "null result");
	}

	// fail to remap max_protection --- as -W-
	{
		vm_prot_t cur_protection = VM_PROT_NONE;
		vm_prot_t max_protection = VM_PROT_WRITE;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* do_copy= */ do_copy, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
		T_QUIET; T_ASSERT_NULL(result_copy, "null result");
	}

	// ok to remap a NONE region to another NONE region
	{
		vm_prot_t cur_protection = VM_PROT_NONE;
		vm_prot_t max_protection = VM_PROT_NONE;

		kern_return_t kr = vm_map_copy_extract(map, r_start, r_end - r_start,
		    /* do_copy= */ do_copy, &result_copy,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);

		if (do_copy) {
			// do_copy fails to copy NONE entries altogether in _new mode
			T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "vm_map_copy_extract");
			T_QUIET; T_ASSERT_NULL(result_copy, "null result");
		} else {
			T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
			T_QUIET; T_ASSERT_NOTNULL(result_copy, "null result");
			check_entries(&result_copy->cpy_hdr, 0, r_end - r_start, ((struct copy_check_s[]){
				{ .size = 2 * PAGE_SIZE, .offset = 0, .prot = VM_PROT_NONE, .needs_copy = false },
			}), "copy");
			vm_map_entry_t cp_e = vm_map_copy_first_entry(result_copy);
			vm_object_t cp_obj = VME_OBJECT(cp_e);
			T_ASSERT_FALSE(cp_e->is_shared, "not is_shared");
			T_ASSERT_NULL(cp_obj, "copy object null");
		}
	}
}

T_DECL(copyex_prot_none, "copyex_prot_none") {
	copyex_prot_none(false);
	copyex_prot_none(true);
}


static void
print_map(vm_map_t map)
{
	vm_map_entry_t e = vm_map_first_entry(map);
	while (e != vm_map_to_entry(map)) {
		vm_object_t obj = VME_OBJECT(e);
		T_LOG("  entry start=%llx end=%llx  obj=%p  ref_count=%d", e->vme_start, e->vme_end, obj,
		    (obj != NULL) ? (int)obj->ref_count : 0);
		e = e->vme_next;
	}
}


/* - Allocate a buffer
 * - create 2 share entries for 2 disjoint parts of it and remap them
 * - deallocate the original buffer
 * - since vm_map_remap_extract does not clip, the two entries will have the same object
 * This was a case from configurator test that assumed the two mappings would have the same object */
T_DECL(alloc_to_entry_to_map, "alloc_to_entry_to_map")
{
	kern_return_t kr;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	// arena is the destination of the remaps
	__block mach_vm_address_t arena = 0;
	mach_vm_size_t arena_size = 0x400000;
	vm_map_kernel_flags_t vmk_flags_arena = VM_MAP_KERNEL_FLAGS_NONE;
	vm_map_kernel_flags_set_vmflags(&vmk_flags_arena, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
	kr = mach_vm_map_kernel(map, &arena, arena_size, /*mask*/ 0, vmk_flags_arena, 0, 0, 0, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_vm_map_kernel arena");
	T_ASSERT_NE(arena, (mach_vm_address_t)0, "arena address=%llx", arena);

	mach_vm_address_t alloc_addr = 0;
	mach_vm_size_t alloc_size = 0x200000;

	// allocate
	kr = mach_vm_allocate_kernel(map, &alloc_addr, alloc_size, (vm_map_kernel_flags_t){.vmf_fixed = false});
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_vm_allocate");
	T_QUIET; T_ASSERT_NE(alloc_addr, (mach_vm_address_t)0, "first address 0");
	T_LOG("alloc address=%llx", alloc_addr);
	T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 2, "original allocation and arena");

	{
		vm_map_entry_t e_alloc = vm_map_first_entry(map);
		vm_object_t obj_alloc = VME_OBJECT(e_alloc);
		T_LOG("alloc start=%llx  obj=%p", e_alloc->vme_start, obj_alloc);
		T_QUIET; T_ASSERT_NULL(obj_alloc, "alloc obj null");

		print_map(map);
	}

	void (^do_remap)(int, mach_vm_address_t, uint8_t) = ^(int i, mach_vm_address_t from_addr, uint8_t tag)
	{
		T_LOG("share %d", i);
		// create a named-entry from the allocation
		mach_vm_size_t copy_size = 0x100000;
		ipc_port_t named_entry_port = NULL;
		kern_return_t kr = mach_make_memory_entry_64(map, &copy_size, from_addr,
		    VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_SHARE,
		    &named_entry_port, /*parent=*/ IPC_PORT_NULL);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_make_memory_entry_64");
		T_QUIET; T_ASSERT_NOTNULL(named_entry_port, "named_entry_port null");
		vm_named_entry_t named_entry = (vm_named_entry_t)ipc_kobject_get_raw(named_entry_port, IKOT_NAMED_ENTRY); // un-PAC
		T_QUIET; T_ASSERT_NOTNULL(named_entry, "named_entry null");
		T_QUIET; T_ASSERT_TRUE(named_entry->is_copy, "named_entry is a copy");
		vm_map_copy_t copy = named_entry->backing.copy;
		T_QUIET; T_ASSERT_NOTNULL(copy, "copy null");
		T_QUIET; T_ASSERT_EQ(copy->size, copy_size, "copy size");
		T_QUIET; T_ASSERT_EQ(copy_size, (mach_vm_size_t)0x100000, "returned size");
		T_LOG("  copy size=%llx  of addr=%llx", copy->size, alloc_addr);

		// map it again in a different address
		mach_vm_address_t second_addr_req = arena;
		mach_vm_address_t second_addr = second_addr_req;
		vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		vm_map_kernel_flags_set_vmflags(&vmk_flags, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, /*tag=*/ tag);
		kr = mach_vm_map_kernel(map, &second_addr, copy_size,
		    0,                                                /* alignment mask */
		    vmk_flags,
		    named_entry_port,                                               /* src */
		    0,                                               /* offset */
		    false,                                               /* copy */
		    VM_PROT_READ | VM_PROT_WRITE,                                               /* protection */
		    VM_PROT_READ | VM_PROT_WRITE,                                               /* max_protection */
		    VM_INHERIT_DEFAULT);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_vm_map_kernel");
		T_QUIET; T_ASSERT_EQ(second_addr, second_addr_req, "second address 0");
		T_LOG("   map %d address=%llx", i, second_addr);

		arena += copy_size;

		// deallocate the named-entry to let go of it's object reference
		mach_memory_entry_port_release(named_entry_port);

		print_map(map);
	};

	mach_vm_address_t first_remap_addr = arena;
	do_remap(1, alloc_addr, 240);
	mach_vm_address_t second_remap_addr = arena;
	do_remap(2, alloc_addr + 0x100000, 241);

	// the original (unclipped) allocation, the 2 remaps and rest of the arena
	T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 4, "original allocation and arena");

	T_LOG("dealloc %llx", alloc_addr);
	// use vm_deallocate() since mach_vm_allocate() is explicitly unexported in xnu_lib.unexport
	kr = vm_deallocate(map, alloc_addr, alloc_size);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_vm_deallocate");


	T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 3, "map entries count");
	vm_map_entry_t e1 = vm_map_first_entry(map);
	T_QUIET; T_ASSERT_EQ(e1->links.start, first_remap_addr, "first remap expected address");
	vm_object_t obj1 = VME_OBJECT(e1);
	T_LOG("e1.start=%llx  obj1=%p ref_count=%d  shadow=%p", e1->links.start, obj1, (int)obj1->ref_count, obj1->shadow);

	vm_map_entry_t e2 = e1->vme_next;
	T_QUIET; T_ASSERT_EQ(e2->links.start, second_remap_addr, "first remap expected address");
	vm_object_t obj2 = VME_OBJECT(e2);
	T_LOG("e2.start=%llx  obj2=%p ref_count=%d  shadow=%p", e2->links.start, obj2, (int)obj2->ref_count, obj2->shadow);


	T_QUIET; T_ASSERT_EQ_PTR(obj1, obj2, "same object");
	T_QUIET; T_ASSERT_EQ(obj1->ref_count, 2, "correct ref-count");
}

// This call passes a specially crafted huge size to mach_make_memory_entry_64()
// It is similar to calls done in vm_parameter_validation. It passes due to the
// use of VMRL_SH_NO_MIN_MAX_CHECK in vm_map_copy_extract()
T_DECL(param_valid_new, "param_valid_new")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);

	mach_vm_address_t allocated_base = 0x80000000;
	mach_vm_size_t allocated_size = 0x20000;
	vm_map_kernel_flags_t vmk_flags_alloc = VM_MAP_KERNEL_FLAGS_NONE;
	vm_map_kernel_flags_set_vmflags(&vmk_flags_alloc, VM_FLAGS_ANYWHERE);
	kern_return_t kr = mach_vm_map_kernel(map, &allocated_base, allocated_size, 0,
	    vmk_flags_alloc, 0, 0, 0,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "start mach_vm_map_kernel");

	T_LOG("base=%llx", allocated_base);

	mach_port_t parent_handle;
	kr = mach_memory_object_memory_entry_64((host_t)0x1234, 1, (4 * 16 * 1024) + 1, VM_PROT_READ | VM_PROT_WRITE, 0, &parent_handle);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_memory_object_memory_entry_64");

	mach_vm_address_t start = allocated_base;
	mach_vm_size_t sz = -start + (uint64_t)0xffffffffffffbffe;
	T_LOG("start=%llx  size=%llx  end=%llx", start, sz, start + sz);
	mach_port_t out_handle = ((mach_port_t) 0xbabababa);
	kr = mach_make_memory_entry_64(map, &sz, allocated_base,
	    VM_PROT_READ | MAP_MEM_NAMED_REUSE,
	    &out_handle, parent_handle);
	T_LOG("kr=%d", kr);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_make_memory_entry_64");
}

// the x86_64 commpage is a submap that is entered above the min_offset, max_offset bounds
// mach_vm_remap() and mach_vm_read() are expected to work on this range. see also test "remap_comm_page"
// This works thanks to VMRL_SH_NO_MIN_MAX_CHECK in the lock call
T_DECL(copyin_beyond_map_bounds, "copyin_beyond_map_bounds")
{
	vm_map_offset_t max_offs = 0x1000000000ULL - PAGE_SIZE;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, max_offs, 0);

	kern_return_t kr;
	mach_vm_size_t size = 10 * PAGE_SIZE;
	// add an entry outside the bounds of the map
	vm_object_t obj = vm_object_allocate(size, map->serial_id);
	vm_map_address_t commpage_addr = 0x00007FFFFFE00000ULL;
	vm_map_address_t addr = commpage_addr;

	// see vm_commpage_enter()
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED();
	vmk_flags.vmkf_beyond_max = TRUE;

	kr = vm_map_enter(map, &addr, size, /*mask=*/ 0, vmk_flags,
	    obj, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
	T_ASSERT_EQ(addr, commpage_addr, "got requested address");

	// sanity check the bounds did not change
	T_ASSERT_EQ(map->min_offset, (vm_map_offset_t)0, "min_offset did not change");
	T_ASSERT_EQ(map->max_offset, max_offs, "max_offset did not change");

	{ // copyin_internal
		// check different options of the vm_map_copyin_kernel_buffer optimization check (which should be skipped)
		// big, with ENTRY_LIST flag
		{
			vm_map_copy_t result_copyin = NULL;
			kr = vm_map_copyin_internal(map, addr, size, VM_MAP_COPYIN_ENTRY_LIST, &result_copyin);
			T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal case 1");
		}

		// big, no ENTRY_LIST flag
		{
			vm_map_copy_t result_copyin = NULL;
			kr = vm_map_copyin_internal(map, addr, size, 0, &result_copyin);
			T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal case 2");
		}

		// small, no ENTRY_LIST flag
		{
			vm_map_copy_t result_copyin = NULL;
			kr = vm_map_copyin_internal(map, addr, 1 * PAGE_SIZE, 0, &result_copyin);
			T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_map_copyin_internal case 3");
		}
	}

	{ // copy_extract
		vm_map_copy_t result_copyex = NULL;
		vm_map_kernel_flags_t flags = { .vmkf_remap_legacy_mode = false };
		vm_prot_t cur_protection = VM_PROT_NONE; // doesn't matter
		vm_prot_t max_protection = VM_PROT_NONE; // doesn't matter
		kr = vm_map_copy_extract(map, addr, size,
		    /* copy= */ true, &result_copyex,
		    &cur_protection, &max_protection, VM_INHERIT_DEFAULT, flags);
		T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_map_copy_extract");
	}
}

#pragma clang attribute pop
