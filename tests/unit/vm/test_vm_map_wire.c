/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
#include <kern/locks.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_internal.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_vm.h"

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_wire"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

T_MOCK_SET_PERM_FUNC(
	kern_return_t,
	vm_fault_enter_prepare, (
		vm_page_t m,
		pmap_t pmap,
		vm_map_offset_t vaddr,
		vm_prot_t * prot,
		vm_prot_t caller_prot,
		vm_map_size_t fault_page_size,
		vm_map_offset_t fault_phys_offset,
		vm_prot_t fault_type,
		vm_object_fault_info_t fault_info,
		int *type_of_fault,
		bool *page_needs_data_sync))
{
	return KERN_SUCCESS;
}

T_MOCK_SET_PERM_FUNC(
	kern_return_t,
	vm_fault_attempt_pmap_enter, (
		pmap_t pmap,
		vm_map_offset_t vaddr,
		vm_map_size_t fault_page_size,
		vm_map_offset_t fault_phys_offset,
		vm_page_t m,
		vm_prot_t * prot,
		vm_prot_t caller_prot,
		vm_prot_t fault_type,
		bool wired,
		int pmap_options))
{
	return KERN_SUCCESS;
}

T_MOCK_SET_PERM_FUNC(
	bool,
	pmap_is_page_free,
	(pmap_paddr_t paddr))
{
	return true;
}

void
dump_vm_map(vm_map_t map)
{
	printf("Map: %p %i entries", map, map->hdr.nentries);
	vm_map_entry_t entry = vm_map_first_entry(map);
	while (entry != vm_map_to_entry(map)) {
		if (!entry->is_sub_map) {
			printf("Entry %p:[%llx, %llx) prot = %i object = %p", entry, entry->vme_start, entry->vme_end, entry->protection, VME_OBJECT(entry));
		} else {
			printf("Entry %p:[%llx, %llx) prot = %i submap = %p", entry, entry->vme_start, entry->vme_end, entry->protection, VME_SUBMAP(entry));
		}
		entry = entry->vme_next;
	}
}

vm_map_address_t submap_start = 0x200000;
vm_map_address_t submap_end = 0x400000;

void
setup_map(vm_map_t * submap_out, vm_map_t * parent_map)
{
	kern_return_t kr;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	pmap_t submap_pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t submap = vm_map_create_options(submap_pmap, 0, 0xfffffffffffff, 0);
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	vm_map_address_t address = PAGE_SIZE;
	T_SETUPBEGIN;
	kr = vm_map_enter(submap, &address, PAGE_SIZE * 2, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, VM_PROT_READ, VM_PROT_READ, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the submap");

	vm_map_address_t address2 = address + (2 * PAGE_SIZE);
	kr = vm_map_enter(submap, &address2, PAGE_SIZE * 50, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the submap");

	vm_map_seal(submap, false /* no nested pmap */);

	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true), (vm_object_t)submap, 0, true, VM_PROT_READ, VM_PROT_READ, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A submap can be added to a map");
	T_SETUPEND;


	/* needed to make sure we don't wire executable memory */
	map->cs_enforcement = true;

	*submap_out = submap;
	*parent_map = map;
}

T_DECL(submaps, "Wiring Submaps") {
	kern_return_t kr;

	/* set wire limits to be high enough for this test */
	vm_per_task_user_wire_limit = 0xfffffffffffff;
	vm_global_user_wire_limit = 0xfffffffffffff;

	vm_map_t submap, map;
	vm_map_address_t ro_entry_start = submap_start + PAGE_SIZE;
	vm_map_address_t exec_entry_start = submap_start + PAGE_SIZE * 3;

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, submap_start, submap_end, VM_PROT_NONE, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_NE(kr, KERN_SUCCESS, "Wire should fail if submap range has holes");
	lck_rw_assert(&map->ilock, LCK_RW_ASSERT_NOT_OWNED);

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, submap_start, submap_start + PAGE_SIZE, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS, "Wire where we don't have a meaningful entry in the submap should fail. This is at address 0, in the submap, before we put our entries");

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, ro_entry_start, ro_entry_start + PAGE_SIZE, VM_PROT_DEFAULT, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Wire should fail if we ask for too many perms");

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, ro_entry_start, ro_entry_start + PAGE_SIZE, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Wire should work for needs_copy submap assuming default perms");

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, ro_entry_start, ro_entry_start + PAGE_SIZE * 3, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Wire should fail if we go past the first entry into one with bad perms");

	/* wiring should fail if one is executable */
	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, exec_entry_start, exec_entry_start + PAGE_SIZE, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Wiring executable memory in submap should fail (even if it's only a small range)");

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, exec_entry_start, exec_entry_start + PAGE_SIZE * 50, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Wiring executable memory in submap should fail");

	setup_map(&submap, &map);
	kr = vm_map_wire_kernel(map, exec_entry_start + PAGE_SIZE, exec_entry_start + PAGE_SIZE * 49, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, TRUE);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Wiring executable memory in submap should fail (even if start != entry_start)");
}


T_DECL(wire_accounting, "Wire Accounting") {
	T_MOCK_SET_CALLBACK(vm_page_grab_options,
	    vm_page_t, (vm_grab_options_t grab_options), {
		vm_page_t result = T_MOCK_CALL_ORIGINAL(vm_page_grab_options, grab_options);
		result->vmp_canonical = true;
		return result;
	});

	kern_return_t kr;

	vm_map_offset_t start_address = 0x4000;
	vm_map_size_t   entry_size = 0x10000;
	unsigned int    n_entries = 256;
	vm_map_size_t   total_size = entry_size * n_entries;
	vm_map_offset_t end_address = start_address + total_size;

	/* set wire limits to be high enough for this test */
	vm_per_task_user_wire_limit = total_size;
	vm_global_user_wire_limit = total_size;

	vm_page_wire_count = 0; // Reset to zero for the tests

	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	for (unsigned int i = 0; i < n_entries; i++) {
		vm_map_offset_t address = start_address + entry_size * i;
		kr = vm_map_enter(map, &address, entry_size, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, VM_PROT_READ, VM_PROT_READ, 0);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "We should be able to allocate memory in the map under test");
	}
	T_ASSERT_EQ(vm_page_wire_count, 0, "We're expecting no global wirings to start");

	kr = vm_map_wire_kernel(map, start_address, end_address, VM_PROT_READ, VM_KERN_MEMORY_MLOCK, true);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We should be able to wire memory to the limit");

	T_ASSERT_EQ(vm_page_wire_count, (unsigned int)(total_size / PAGE_SIZE), "We're expecting the global wirings to exactly match our wired entries");

	vm_map_destroy(map);
}
