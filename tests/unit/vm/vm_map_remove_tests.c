/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_internal.h>
#include <kern/zalloc_internal.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_internal.h"
#include "mocks/osfmk/mock_internal.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_thread.h"
#include "mocks/osfmk/mock_vm.h"

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_remove"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

typedef struct {
	vm_map_offset_t         start;
	vm_map_offset_t         end;
	vm_map_kernel_flags_t   flags;
	vm_prot_t               cur_protection;
	vm_prot_t               max_protection;
} test_entry_t;

static void
verify_test_map(vm_map_t map, test_entry_t *entries, unsigned int n_entries)
{
	__block vm_map_offset_t last_end = 0;
	__block unsigned int entry_count = 0;

	// Confirm that the map still looks like the requested map
	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		entry_count++;

		vm_map_entry_t vme = entry;
		T_QUIET; T_ASSERT_GE(vme->vme_start, last_end, "Expecting monotonically increasing addresses");
		last_end = vme->vme_end;

		for (unsigned int i = 0; i < n_entries; i++) {
		        if (vme->vme_start >= entries[i].start &&
		        vme->vme_end <= entries[i].end) {
		                T_QUIET; T_ASSERT_EQ((bool)vme->vme_permanent, (bool)entries[i].flags.vmf_permanent, "Entry maintained permanent flag");
		                T_QUIET; T_ASSERT_EQ((int)vme->protection, (int)entries[i].cur_protection, "Entry preserved current protection");
		                T_QUIET; T_ASSERT_EQ((int)vme->max_protection, (int)entries[i].max_protection, "Entry preserved max protection");
		                return KERN_SUCCESS;
			}
		}
		T_FAIL("Unknown map entry [0x%llx, 0x%llx)", vme->vme_start, vme->vme_end);
		return KERN_FAILURE;
	});

	// Entries may split but we're not expecting fewer entries
	T_QUIET; T_ASSERT_GE(entry_count, n_entries, "Unexpected number of entries");
}

static void
setup_test_map(vm_map_t map, test_entry_t *entries, unsigned int n_entries)
{
	for (unsigned int i = 0; i < n_entries; i++) {
		vm_map_offset_t address = entries[i].start;
		vm_map_offset_t size = entries[i].end - entries[i].start;

		kern_return_t kr = vm_map_enter(map, &address, size, 0, entries[i].flags, VM_OBJECT_NULL, 0, false, entries[i].cur_protection, entries[i].max_protection, 0);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Test map setup");
	}

	verify_test_map(map, entries, n_entries);
}

T_DECL(remove_nothing, "Remove a zero sized entry")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_remove_guard(map, 0, 0, 0, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Removing a zero sized entry will succeed");
	assert_vm_map_ilk_not_owned(map);
}

T_DECL(defer_corpse_cleanup, "Defer Corpse Cleanup")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_address_t start = 0x200000ULL;

	test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 2 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = countof(entries);

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	map->corpse_source = true;

	kr = vm_map_remove_guard(map, start, start + 2 * PAGE_SIZE, 0, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "When a map has corpse_source set entries will not be removed but success will be reported");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, entries, n_entries);
}

T_DECL(deletes_entries, "Deletes entries")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_address_t start = 0x200000ULL;

	test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 2 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
		{
			.start = start + 4 * PAGE_SIZE,
			.end = start + 6 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
		{
			.start = start + 8 * PAGE_SIZE,
			.end = start + 10 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = countof(entries);

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	kr = vm_map_remove_guard(map, start + PAGE_SIZE, start + 9 * PAGE_SIZE, 0, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Deleting a simple entry will succeed");
	assert_vm_map_ilk_not_owned(map);

	test_entry_t final_entries[] = {
		{
			.start = start,
			.end = start + PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
		{
			.start = start + 9 * PAGE_SIZE,
			.end = start + 10 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};

	verify_test_map(map, final_entries, countof(final_entries));
}

T_DECL(wait_for_space, "Wait For Space")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_address_t start = 0x200000ULL;

	test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 2 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = countof(entries);

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	map->wait_for_space = true;

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	__block bool called = false;
	T_MOCK_SET_CALLBACK(thread_wakeup_prim,
	    kern_return_t,
	    (event_t       event,
	    boolean_t     one_thread,
	    __unused wait_result_t result), {
		T_QUIET; T_ASSERT_EQ(event, (event_t)map, "Check that we are waking waiters on the correct map");
		T_QUIET; T_ASSERT_EQ(one_thread, false, "Check that we are waking all waiting threads");
		called = true;
		return KERN_SUCCESS;
	});

	kr = vm_map_remove_guard(map, start, start + 2 * PAGE_SIZE, 0, KMEM_GUARD_NONE);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Deleting a simple entry will succeed");
	assert_vm_map_ilk_not_owned(map);
	T_QUIET; T_ASSERT_EQ(called, true, "If wait_for_space was requested thread_wakeup will have been called");

	verify_test_map(map, NULL, 0);
}

T_DECL(panics, "Check panickable conditions") {
	kern_return_t kr;
	vm_map_t map;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_ASSERT_PANIC({
		(void)vm_map_remove_guard(map, 0x200000 + (PAGE_SIZE - 1), 0x400000, VM_MAP_REMOVE_GAPS_FAIL, KMEM_GUARD_NONE);
	}, "Passing a start address that is not page aligned will panic");
}

T_DECL(remove_gap_fail, "Remove Gap Fail")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_address_t start = 0x200000ULL;

	test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 2 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
		{
			.start = start + 4 * PAGE_SIZE,
			.end = start + 6 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = countof(entries);

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_remove_guard(map, start, start + 6 * PAGE_SIZE, VM_MAP_REMOVE_GAPS_FAIL, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_INVALID_VALUE, "Cannot remove anything from an empty map if VM_MAP_REMOVE_GAPS_FAIL is requested");
	assert_vm_map_ilk_not_owned(map);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	kr = vm_map_remove_guard(map, start, start + 6 * PAGE_SIZE, VM_MAP_REMOVE_GAPS_FAIL, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_INVALID_VALUE, "Cannot remove entries separated by a gap if VM_MAP_REMOVE_GAPS_FAIL is requested");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, entries, n_entries);

	kr = vm_map_remove_guard(map, start, start + 2 * PAGE_SIZE, VM_MAP_REMOVE_GAPS_FAIL, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Contiguous entries can be removed if VM_MAP_REMOVE_GAPS_FAIL is requested");
	assert_vm_map_ilk_not_owned(map);

	__block unsigned int entry_count = 0;
	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		entry_count++;
		vm_map_entry_t vme = entry;
		T_QUIET; T_ASSERT_EQ(vme->vme_start, start + 4 * PAGE_SIZE, "Checking the start address of the remaining entry");
		T_QUIET; T_ASSERT_EQ(vme->vme_end, start + 6 * PAGE_SIZE, "Checking the end address of the remaining entry");
		return KERN_SUCCESS;
	}
	    );
	T_QUIET; T_ASSERT_EQ(entry_count, 1, "The map be left with a single entry");
}

T_DECL(map_terminate, "Map Temination") {
	kern_return_t kr;
	vm_map_t map;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	map->terminated = true;

	kr = vm_map_remove_guard(map, 0x20000, 0x40000, VM_MAP_REMOVE_GAPS_FAIL, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_INVALID_VALUE, "Cannot remove anything from an empty map if we are terminating and VM_MAP_REMOVE_GAPS_FAIL is requested");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	kr = vm_map_remove_guard(map, 0x20000, 0x40000, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Removing anything from an empty map will succeed if terminating");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);
}

T_DECL(permanent_entries, "Deleting Permanent Entries") {
	kern_return_t kr;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	vm_map_address_t start = 0x200000;
	vm_map_address_t end = 0x400000;
	vm_map_address_t address = start;

	test_entry_t entries[] = {
		{
			.start = start,
			.end = end,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true),
			.cur_protection = VM_PROT_DEFAULT,
			.max_protection = VM_PROT_DEFAULT,
		},
	};
	const unsigned n_entries = countof(entries);

	test_entry_t executable_entries[] = {
		{
			.start = start,
			.end = end,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true),
			.cur_protection = VM_PROT_READ | VM_PROT_EXECUTE,
			.max_protection = VM_PROT_READ | VM_PROT_EXECUTE,
		},
	};
	const unsigned n_executable_entries = countof(executable_entries);

	// Removal or permanent entries can result in an entry with no permissions
	test_entry_t dead_entries[] = {
		{
			.start = start,
			.end = end,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_dead_entries = countof(dead_entries);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We are told that permanent entries are successfully deleted");

	T_MOCK_SET_RETVAL(developer_mode_state, bool, true);
	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_IMMUTABLE_CODE, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We are told that permanent entries are successfully deleted");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, dead_entries, n_dead_entries);

	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_IMMUTABLE, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We should be able to remove permanent entries with VM_MAP_REMOVE_IMMUTABLE");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	setup_test_map(map, executable_entries, n_executable_entries);
	T_SETUPEND;

	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_IMMUTABLE_CODE, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We should be able to remove permanent executable entries with VM_MAP_REMOVE_IMMUTABLE_CODE");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	setup_test_map(map, executable_entries, n_executable_entries);
	T_SETUPEND;

	T_MOCK_SET_RETVAL(csm_enabled, bool, false);
	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We should be able to remove permanent executable entries if code signing is disabled");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, NULL, 0);
}

T_DECL(submaps, "Deleting Submaps") {
	kern_return_t kr;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	vm_map_address_t submap_start = 0x200000;
	vm_map_address_t submap_end = 0x400000;
	pmap_t submap_pmap = NULL; // pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t submap = vm_map_create_options(submap_pmap, 0, 0xfffffffffffff, 0);
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	vm_map_address_t address = PAGE_SIZE;
	T_SETUPBEGIN;
	kr = vm_map_enter(submap, &address, PAGE_SIZE, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the submap");

	vm_map_seal(submap, false /* no nested pmap */);

	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A submap can be added to a map");
	T_SETUPEND;

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Non-permanent submaps can be removed");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A submap can be added to a map");

	vm_map_entry_t entry = map->hdr.links.next;
	entry->use_pmap = true;
	T_SETUPEND;

	__block bool unnest_called = false;

	T_MOCK_SET_CALLBACK(pmap_unnest_options, kern_return_t, (
		    pmap_t grand,
		    addr64_t vaddr,
		    uint64_t size,
		    unsigned int option), {
		T_ASSERT_EQ(vaddr, submap_start, "Check the start address of the unmap");
		T_ASSERT_EQ(size, submap_end - submap_start, "Check the size of the unmap");
		T_ASSERT_EQ(option, 0, "Check for default options");
		unnest_called = true;
		return KERN_SUCCESS;
	});

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Non-permanent submaps can be removed and will be unnested prior to removal");
	T_ASSERT_EQ(unnest_called, true, "pmap_unnest_options should have been called");

	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);


	T_SETUPBEGIN;
	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A submap can be added to a map");

	entry = map->hdr.links.next;
	entry->use_pmap = true;
	unnest_called = false;
	map->terminated = true;
	T_SETUPEND;


	T_MOCK_SET_CALLBACK(pmap_unnest_options, kern_return_t, (
		    pmap_t grand,
		    addr64_t vaddr,
		    uint64_t size,
		    unsigned int option), {
		T_ASSERT_EQ(vaddr, submap_start, "Check the start address of the unmap");
		T_ASSERT_EQ(size, submap_end - submap_start, "Check the size of the unmap");
		T_ASSERT_EQ(option, PMAP_UNNEST_CLEAN, "Check for default options");
		unnest_called = true;
		return KERN_SUCCESS;
	});

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Non-permanent submaps can be removed and will be unnested prior to removal with special handling if the map is terminated");
	T_ASSERT_EQ(unnest_called, true, "pmap_unnest_options should have been called");

	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmf_permanent = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A permanent submap entry can be added to a map");
	map->terminated = false;
	T_SETUPEND;

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Permanent submap entries can be removed if they contain no permanent entries themselves");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	vm_map_deallocate(submap);
	submap = vm_map_create_options(submap_pmap, 0, 0xfffffffffffff, 0);
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	T_SETUPBEGIN;
	address = 3 * PAGE_SIZE;
	kr = vm_map_enter(submap, &address, PAGE_SIZE, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Permanent entries can be added to a map");

	vm_map_seal(submap, false /* no nested pmap */);

	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmf_permanent = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A permanent submap entry can be added to a map");
	T_SETUPEND;

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Permanent submap entries with permanent entries cannot be removed");
	assert_vm_map_ilk_not_owned(map);

	__block int entry_count = 0;
	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		entry_count++;
		T_QUIET; T_ASSERT_EQ(entry_count, 1, "We expect a single entry to be remaining");
		vm_map_entry_t vme = entry;

		T_QUIET; T_ASSERT_EQ(vme->vme_start, submap_start, "Check that the remaining entry has the correct start address");
		T_QUIET; T_ASSERT_EQ(vme->vme_end, submap_end, "Check that the remaining entry has the correct end address");
		return KERN_SUCCESS;
	});

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_IMMUTABLE, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Permanent submap entries with permanent entries can be removed if VM_MAP_REMOVE_IMMUTABLE is requested");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	vm_map_reference(submap); // Hold on to a reference so that we can reuse the submap
	kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmf_permanent = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "A permanent submap entry can be added to a map");
	T_SETUPEND;

	map->terminated = true;

	kr = vm_map_remove_guard(map, submap_start, submap_end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Permanent submap entries with permanent entries can be removed if this map is being terminated");
	assert_vm_map_ilk_not_owned(map);
}

T_DECL(kernel_entries, "Deleting Kernel Entries") {
	kern_return_t kr;

	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	map->pmap = kernel_pmap;
	vm_map_address_t address;

	T_MOCK_SET_RETVAL(vm_map_entry_cs_associate, kern_return_t, KERN_SUCCESS);

	T_SETUPBEGIN;
	address  = 0x20000;
	kr = vm_map_enter(map, &address, 0x20000, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Permanent entries can be added to the map");

	address  = 0x60000;
	kr = vm_map_enter(map, &address, 0x20000, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the map");
	T_SETUPEND;

	kr = vm_map_remove_guard(map, 0x60000, 0x80000, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Non-permanent entries can be deleted from the kernel map");

	T_ASSERT_PANIC({
		(void)vm_map_remove_guard(map, 0x20000, 0x40000, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	}, "Attempting to remove a permanent entry from the kernel map will result in a panic");
}

T_DECL(wired_entries, "Deleting Wired Entries") {
	kern_return_t kr;
	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	vm_map_t kernel_map = vm_map_create_options(kernel_pmap, 0, 0xfffffffffffff, 0);

	vm_map_address_t start = 0x200000;
	vm_map_address_t end = 0x400000;
	vm_map_address_t address = start;

	__block vm_map_entry_t entry = NULL;
	__block bool tried_to_block = false;
	__block bool did_unwire = false;
	__block unsigned int reset_wired_count_to = 1;

	T_MOCK_SET_RETVAL(vm_map_entry_cs_associate, kern_return_t, KERN_SUCCESS);

	T_MOCK_SET_CALLBACK(thread_block_reason, wait_result_t, (thread_continue_t continuation, void *parameter, ast_t reason), {
		// Unwire
		entry->wired_count = reset_wired_count_to;
		tried_to_block = true;

		// Manually clear the waitq
		current_thread()->waitq.wq_q = NULL;
		current_thread()->state = 0;
		current_thread()->block_hint = 0;

		return THREAD_RESTART;
	});

	__block vm_map_address_t expected_end_address = end;
	T_MOCK_SET_CALLBACK(vm_fault_unwire, void,
	    (vm_map_t                unwire_map,
	    vm_map_entry_t          unwire_entry,
	    bool                    unwire_deallocate,
	    pmap_t                  unwire_pmap,
	    vm_map_offset_t         unwire_pmap_addr,
	    vm_map_offset_t         unwire_end_addr), {
		T_QUIET; T_ASSERT_EQ(unwire_end_addr, expected_end_address, "Verify vm_fault_unwire end address");
		did_unwire = true;
	});

	T_SETUPBEGIN;
	kr = vm_map_enter(map, &address, end - start, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the map");
	entry = map->hdr.links.next;
	entry->user_wired_count = 100;
	entry->wired_count = 1;
	map->user_wire_size = end - start;
	T_SETUPEND;

	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "An entry with any user_wired_count and a wired_count of 1 can be removed without waiting");
	T_QUIET; T_ASSERT_EQ(tried_to_block, false, "Should not have blocked");
	T_QUIET; T_ASSERT_EQ(did_unwire, true, "Should have called vm_fault_unwire");
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	kr = vm_map_enter(map, &address, end - start, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the map");
	entry = map->hdr.links.next;
	entry->user_wired_count = 100;
	entry->wired_count = 2;
	map->user_wire_size = end - start;
	reset_wired_count_to = 1;
	tried_to_block = false;
	did_unwire = false;
	T_SETUPEND;

	kr = vm_map_remove_guard(map, start, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "An entry with any user_wire_count and a wired_count of 2 can be removed by waiting for the wire count to drop to 1.");
	T_QUIET; T_ASSERT_EQ(tried_to_block, true, "Should have blocked");
	T_QUIET; T_ASSERT_EQ(did_unwire, true, "Should have called vm_fault_unwire");
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	kr = vm_map_enter(kernel_map, &address, end - start, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Permanent entries can be added to the map");
	entry = kernel_map->hdr.links.next;
	entry->wired_count = 1;
	tried_to_block = false;
	did_unwire = false;
	T_SETUPEND;

	kr = vm_map_remove_guard(kernel_map, start, end, VM_MAP_REMOVE_KUNWIRE, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "An entry with a wire_count of 1 can be removed from the kernel map without blocking if VM_MAP_REMOVE_KUNWIRE is requested");
	T_QUIET; T_ASSERT_EQ(tried_to_block, false, "should not have blocked");
	T_QUIET; T_ASSERT_EQ(did_unwire, true, "Should have called vm_fault_unwire");
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	kr = vm_map_enter(kernel_map, &address, end - start, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the map");
	entry = kernel_map->hdr.links.next;
	entry->wired_count = 2;
	reset_wired_count_to = 1;
	tried_to_block = false;
	did_unwire = false;
	T_SETUPEND;

	kr = vm_map_remove_guard(kernel_map, start, end, VM_MAP_REMOVE_KUNWIRE, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Any entry with a wire_count of 2 can be removed from the kernel map by requesting VM_MAP_REMOVE_KUNWIRE and waiting for the wire_count to drop to 1");
	T_QUIET; T_ASSERT_EQ(tried_to_block, true, "Should have blocked");
	T_QUIET; T_ASSERT_EQ(did_unwire, true, "Should have called vm_fault_unwire");
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	kr = vm_map_enter(kernel_map, &address, end - start, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the map");
	entry = kernel_map->hdr.links.next;
	entry->wired_count = 1;
	tried_to_block = false;
	did_unwire = false;
	reset_wired_count_to = 0;
	T_SETUPEND;

	kr = vm_map_remove_guard(kernel_map, start, end, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "An entry with a wire_count of 1 can be removed from the kernel map by waiting for the wire_count to reach 0");
	T_QUIET; T_ASSERT_EQ(tried_to_block, true, "Should have blocked");
	T_QUIET; T_ASSERT_EQ(did_unwire, false, "Should not have called vm_fault_unwire because VM_MAP_REMOVE_KUNWIRE was not requested");
	verify_test_map(map, NULL, 0);

	T_SETUPBEGIN;
	kr = vm_map_enter(kernel_map, &address, end - start, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Entries can be added to the map");
	entry = kernel_map->hdr.links.next;
	entry->wired_count = 2;
	tried_to_block = false;
	did_unwire = false;
	T_SETUPEND;

	reset_wired_count_to = 1; // Allow VM_MAP_REMOVE_KUNWIRE to remove an entry
	expected_end_address = end - PAGE_SIZE;
	kr = vm_map_remove_guard(kernel_map, start, end, VM_MAP_REMOVE_KUNWIRE | VM_MAP_REMOVE_NOKUNWIRE_LAST, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "An entry with a wire_count of 2 can be removed from the kernel map by waiting for the wire_count to reach 1. The last page will not be unwired if VM_MAP_REMOVE_NOKUNWIRE_LAST is requested ");
	T_QUIET; T_ASSERT_EQ(tried_to_block, true, "Should have blocked");
	T_QUIET; T_ASSERT_EQ(did_unwire, true, "Should have called vm_fault_unwire");
	verify_test_map(map, NULL, 0);
}

T_MOCK_DECLARE(void, zfree_ext,
(zone_t zone, zone_stats_t stats, void *addr, uint64_t combined_size));

T_DECL(map_terminate_go, "Map termination with guard objects") {
	kern_return_t kr;
	vm_map_t map;
	pmap_t pmap;
	vm_map_offset_t size = KiB(128);
	const unsigned num_chunks = 4;
	/* 16 slots per chunk, but 25% are guards */
	const unsigned num_go = num_chunks * 12;
	vm_map_address_t addr = 0;

	T_SETUPBEGIN;

	__block unsigned num_freed_chunks = 0;

	T_MOCK_SET_CALLBACK(zfree_ext, void,
	    (zone_t zone, zone_stats_t zstats, void *addr, uint64_t combined_size), {
		if (zone_index(zone) == ZONE_ID_VM_GO_CHUNKS) {
		        num_freed_chunks++;
		}
		T_MOCK_CALL_ORIGINAL(zfree_ext, zone, zstats, addr, combined_size);
	});

	pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);
	vm_map_guard_object_slab_init(map);

	for (unsigned i = 0; i < num_go; i++) {
		vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
		kr = vm_map_enter(map, &addr, size, 0, vmk_flags,
		    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT,
		    VM_PROT_DEFAULT, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map_enter");
	}
	T_SETUPEND;

	map->terminated = true;
	kr = vm_map_remove_guard(map, 0, -PAGE_SIZE, VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Removal in terminated map succeeds");
	assert_vm_map_ilk_not_owned(map);
	T_ASSERT_EQ(num_freed_chunks, num_chunks, "Removal in terminated map frees chunks");

	verify_test_map(map, NULL, 0);
}
