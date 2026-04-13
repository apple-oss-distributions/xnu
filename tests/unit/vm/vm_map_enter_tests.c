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

#include "mocks/osfmk/mock_internal.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_vm.h"
#include "mocks/osfmk/unit_test_utils.h"
#include <darwintest.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_object_internal.h>

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_enter"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * The allocated pages will actually be iterated over so we need our mock to return pages that are
 * linked together.  The other fields are ignored by mocks for these tests.
 */
T_MOCK_SET_PERM_FUNC(
	kern_return_t,
	cpm_allocate, (
		vm_size_t size,
		vm_page_t * list,
		ppnum_t max_pnum,
		ppnum_t pnum_mask,
		boolean_t wire,
		int flags))
{
	vm_page_t last = NULL;
	for (; size >= PAGE_SIZE; size -= PAGE_SIZE) {
		vm_page_t new_page = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
		bzero(new_page, PAGE_SIZE);
		new_page->vmp_snext = last;
		last = new_page;
	}
	*list = last;
	return KERN_SUCCESS;
}

// We don't actually care if pages are zeroed
T_MOCK_SET_PERM_FUNC(void, bzero_phys, (addr64_t src, vm_size_t bytes)) {
}

T_DECL(empty_size, "Enter a zero sized entry")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_enter(map, &address, 0, 0, VM_MAP_KERNEL_FLAGS_NONE, VM_OBJECT_NULL, 0, false, 0, 0, 0);

	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "A size of zero should be rejected");
	T_ASSERT_EQ(address, (vm_map_offset_t)0, "and the resulting address should be cleared");
	assert_vm_map_ilk_not_owned(map);
}

T_DECL(simple, "A simple passing request")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_enter(map, &address, PAGE_SIZE, 0, VM_MAP_KERNEL_FLAGS_NONE, VM_OBJECT_NULL, 0, false, 0, 0, 0);

	T_ASSERT_EQ(kr, KERN_SUCCESS, "A simple call to vm_map_enter should succeed");
	assert_vm_map_ilk_not_owned(map);
}

T_DECL(large_allocation, "Enter an allocation larger than available space")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = 1ull << 30;

	map = vm_map_create_options(NULL, 0, (0x1ull << 29) - 1, 0);

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_NONE, VM_OBJECT_NULL, 0, false, 0, 0, 0);

	T_ASSERT_EQ(kr, KERN_NO_SPACE, "An allocation larger than the available VM space is rejected");
	assert_vm_map_ilk_not_owned(map);
}

T_DECL(overlapping_allocation, "Repeated allocation")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_NONE, VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "A simple allocation should succeed");
	assert_vm_map_ilk_not_owned(map);

	// Request the same address we just got back
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_NO_SPACE, "Trying to use the same space without requesting overwrite should fail");
	assert_vm_map_ilk_not_owned(map);

	// Request the same address we just got back
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "We are allowed to use the same space when overwrite is explicitly requested");
	assert_vm_map_ilk_not_owned(map);
}

typedef struct {
	vm_map_offset_t         start;
	vm_map_offset_t         end;
	vm_map_kernel_flags_t   flags;
	vm_prot_t               cur_protection;
	vm_prot_t               max_protection;
} test_entry_t;

static void
verify_test_map(vm_map_t map, const test_entry_t *entries, unsigned int n_entries)
{
	__block vm_map_offset_t last_end = 0;
	__block unsigned int entry_count = 0;

	// Confirm that the map still looks like the requested map
	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		entry_count++;

		vm_map_entry_t vme = entry;
		T_QUIET; T_ASSERT_GE(vme->vme_start, last_end, "Expecting monotonic entries for these tests");
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
setup_test_map(vm_map_t map, const test_entry_t *entries, unsigned int n_entries)
{
	for (unsigned int i = 0; i < n_entries; i++) {
		vm_map_offset_t address = entries[i].start;
		vm_map_offset_t size = entries[i].end - entries[i].start;

		kern_return_t kr = vm_map_enter(map, &address, size, 0, entries[i].flags, VM_OBJECT_NULL, 0, false, entries[i].cur_protection, entries[i].max_protection, 0);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Test map setup");
	}

	verify_test_map(map, entries, n_entries);
}

T_DECL(rejected_overwrite, "Rejected Overwrite")
{
	kern_return_t kr;
	vm_map_offset_t start = 0x2000000;

	test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 2 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
		{
			.start = start + 3 * PAGE_SIZE,
			.end = start + 5 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = sizeof(entries) / sizeof(entries[0]);

	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	// Request a range that divides the first entry, covers the gap, and splits the permanent entry
	vm_map_offset_t address = 0x2000000 + PAGE_SIZE;
	vm_map_size_t size = 3 * PAGE_SIZE;
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Should not have been able to delete the permanent entry");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, entries, n_entries);
}

T_DECL(purgeable_restrictions, "Purgeable restrictions")
{
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_purgeable = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "First allocation should succeed");

	assert_vm_map_ilk_not_owned(map);

	test_entry_t entries[] = {
		{
			.start = address,
			.end = address + 2 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_purgeable = true),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};

	verify_test_map(map, entries, sizeof(entries) / sizeof(entries[0]));
}

T_DECL(tpro_mapping, "TPRO") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t start = 0x200000;
	vm_map_offset_t address = start;
	vm_map_size_t size = PAGE_SIZE;

	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	T_MOCK_SET_RETVAL(pmap_get_tpro, bool, false);
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_tpro = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "Cannot create a TPRO entry in an non TPRO map");
	assert_vm_map_ilk_not_owned(map);

#if __arm64e__
	T_MOCK_SET_RETVAL(pmap_get_tpro, bool, true);
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_tpro = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "TPRO entry will fail if protections are incorrect");
	assert_vm_map_ilk_not_owned(map);

	T_MOCK_SET_RETVAL(pmap_get_tpro, bool, true);
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_tpro = true), VM_OBJECT_NULL, 0, false, VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "TPRO entry will succeed if protections are correct");
	assert_vm_map_ilk_not_owned(map);

	test_entry_t entries[] = {
		{
			.start = start,
			.end = start +  PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = true),
			.cur_protection = VM_PROT_READ,
			.max_protection = VM_PROT_READ | VM_PROT_WRITE,
		},
	};

	verify_test_map(map, entries, sizeof(entries) / sizeof(entries[0]));
#endif
}

kern_return_t vm_map_exec_lockdown(vm_map_t map);

T_DECL(disallow_new_exec, "Disallow New Executable Regions") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = PAGE_SIZE;

	T_SETUPBEGIN;
	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	kr = vm_map_exec_lockdown(map);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Disallow new executable entries");
	T_SETUPEND;

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(), VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Cannot create a new executable entry once locked down");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, NULL, 0);
}

T_DECL(resilient_codesign, "Resilient Codesign") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_resilient_codesign = true), VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Cannot request resilient codesign if VM_PROT_READ | VM_PROT_WRITE is requested");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_resilient_codesign = true), VM_OBJECT_NULL, 0, false, VM_PROT_READ, VM_PROT_READ, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Should succeed if read-only");
	assert_vm_map_ilk_not_owned(map);

	test_entry_t entries[] = {
		{
			.start = address,
			.end = address +  PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_resilient_codesign = true),
			.cur_protection = VM_PROT_READ,
			.max_protection = VM_PROT_READ,
		}
	};
	verify_test_map(map, entries, sizeof(entries) / sizeof(entries[0]));
}

T_DECL(resilient_media, "Resilient Media") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = PAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	vm_object_t object = vm_object_allocate(PAGE_SIZE, map->serial_id);
	object->internal = false;

	os_ref_retain_internal(&object->ref_count, NULL); // Artificially inflate refcount to prevent over-release
	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 2, "Expecting a single owner to this object ");

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_resilient_media = true), object, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "Resilient media is not allowed if a non-internal object is provided");
	assert_vm_map_ilk_not_owned(map);
	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 2, "The object should still be singly owned after failure");
	verify_test_map(map, NULL, 0);

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_resilient_media = true), VM_OBJECT_NULL, 0, false, VM_PROT_READ, VM_PROT_READ, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Resilient media is allowed if no object is provided");
	assert_vm_map_ilk_not_owned(map);

	test_entry_t entries[] = {
		{
			.start = address,
			.end = address +  PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_resilient_media = true),
			.cur_protection = VM_PROT_READ,
			.max_protection = VM_PROT_READ,
		}
	};
	verify_test_map(map, entries, sizeof(entries) / sizeof(entries[0]));
}

T_DECL(with_pager, "vm_map_enter with Pager") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = PAGE_SIZE;

	struct memory_object pager = {
		0
	};
	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	vm_object_t object = vm_object_allocate(PAGE_SIZE, map->serial_id);
	object->named = true;
	object->pager = &pager;
	object->pager_ready = true;

	os_ref_retain_internal(&object->ref_count, NULL); // Artificially inflate refcount to prevent over-release
	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 2, "Expecting a single owner to this object ");

	T_MOCK_SET_RETVAL(memory_object_map, kern_return_t, KERN_SUCCESS);
	T_MOCK_SET_CALLBACK(memory_object_last_unmap, void, (__unused memory_object_t memory_object), {});

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(), object, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Should succeed when a pager is provided");
	assert_vm_map_ilk_not_owned(map);

	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 2, "The object should still be singly owned after success, just not by us");

	test_entry_t entries[] = {
		{
			.start = address,
			.end = address +  PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_ANYWHERE(),
			.cur_protection = VM_PROT_READ | VM_PROT_EXECUTE,
			.max_protection = VM_PROT_READ | VM_PROT_EXECUTE,
		}
	};
	verify_test_map(map, entries, sizeof(entries) / sizeof(entries[0]));
}

T_DECL(superpage_cpm_allocate_failure, "Superpage cpm_allocate Failure") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = SUPERPAGE_SIZE;

	map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_MOCK_SET_RETVAL(cpm_allocate, kern_return_t, KERN_NO_SPACE);

	T_MOCK_SET_CALLBACK(vm_superpage_size, kern_return_t, (unsigned int superpage_size, vm_map_size_t * size), {
		T_QUIET; T_ASSERT_EQ(superpage_size, SUPERPAGE_SIZE_ANY, "Sanity check args");
		T_QUIET; T_ASSERT_EQ(*size, (vm_map_size_t)SUPERPAGE_SIZE, "Sanity check args");
		*size = SUPERPAGE_SIZE;
		return KERN_SUCCESS;
	});

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_superpage_size = SUPERPAGE_SIZE_ANY), VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_NO_SPACE, "Expecting failures from cpm_allocate to propagate through if superpages are selected.");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);
}

T_DECL(superpage_wire_failure, "Superpage Wire Failure") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = SUPERPAGE_SIZE;

	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	T_MOCK_SET_RETVAL(pmap_cache_attributes, unsigned int, 0);
	T_MOCK_SET_RETVAL(vm_map_wire_kernel, kern_return_t, KERN_PROTECTION_FAILURE);

	T_MOCK_SET_CALLBACK(vm_superpage_size, kern_return_t, (unsigned int superpage_size, vm_map_size_t * size), {
		T_QUIET; T_ASSERT_EQ(superpage_size, SUPERPAGE_SIZE_ANY, "Sanity check args");
		T_QUIET; T_ASSERT_EQ(*size, (vm_map_size_t)SUPERPAGE_SIZE, "Sanity check args");
		*size = SUPERPAGE_SIZE;
		return KERN_SUCCESS;
	});

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_superpage_size = SUPERPAGE_SIZE_ANY), VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "Expecting a failure to wire a superpage to propagate out");
	assert_vm_map_ilk_not_owned(map);
	verify_test_map(map, NULL, 0);
}

T_DECL(superpage_success, "Superpage Success") {
	kern_return_t kr;
	vm_map_t map;
	vm_map_offset_t address = 0x0badadd5ull * PAGE_SIZE;
	vm_map_size_t size = SUPERPAGE_SIZE;

	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	T_MOCK_SET_RETVAL(pmap_cache_attributes, unsigned int, 0);
	T_MOCK_SET_RETVAL(vm_map_wire_kernel, kern_return_t, KERN_SUCCESS);

	T_MOCK_SET_CALLBACK(vm_superpage_size, kern_return_t, (unsigned int superpage_size, vm_map_size_t * size), {
		T_QUIET; T_ASSERT_EQ(superpage_size, SUPERPAGE_SIZE_ANY, "Sanity check args");
		T_QUIET; T_ASSERT_EQ(*size, (vm_map_size_t)SUPERPAGE_SIZE, "Sanity check args");
		*size = SUPERPAGE_SIZE;
		return KERN_SUCCESS;
	});

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_superpage_size = SUPERPAGE_SIZE_ANY), VM_OBJECT_NULL, 0, false, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to request a superpage");
	assert_vm_map_ilk_not_owned(map);

	test_entry_t entries[] = {
		{
			.start = address,
			.end = address +  SUPERPAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_ANYWHERE(),
			.cur_protection = VM_PROT_READ | VM_PROT_EXECUTE,
			.max_protection = VM_PROT_READ | VM_PROT_EXECUTE,
		}
	};
	verify_test_map(map, entries, sizeof(entries) / sizeof(entries[0]));
}

T_DECL(zap_list_restore_rlimit,
    "zap list restoration after fixed-overwrite allocation failure due to rlimit")
{
	/*
	 * Allocate fixed-overwrite, fail due to rlimit, and restore the
	 * overwritten entries from the zap list.
	 */

	/* set by vm_map_enter */
	extern unsigned int vm_map_enter_restore_successes;
	extern unsigned int vm_map_enter_restore_failures;

	kern_return_t kr;
	vm_map_offset_t address;
	vm_map_size_t size;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	/* use protection to detect if fixed-overwrite succeeded */
	vm_prot_t overwriteable_prot = VM_PROT_READ;
	vm_prot_t replacement_prot = VM_PROT_READ | VM_PROT_WRITE;

	test_entry_t overwriteable_entry;
	test_entry_t entries[2];

	/* Allocate space to be overwritten. */
	vm_map_offset_t overwriteable = 0;
	vm_map_size_t overwriteable_size = 50 * PAGE_SIZE;
	kr = vm_map_enter(map, &overwriteable, overwriteable_size, 0 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    overwriteable_prot, overwriteable_prot, VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "allocate to be overwritten");

	overwriteable_entry = (test_entry_t){
		.start = overwriteable,
		.end = overwriteable + overwriteable_size,
		.flags = VM_MAP_KERNEL_FLAGS_ANYWHERE(.vm_tag = VM_MEMORY_APPLICATION_SPECIFIC_1),
		.cur_protection = VM_PROT_READ,
		.max_protection = VM_PROT_READ,
	};
	verify_test_map(map, &overwriteable_entry, 1);

	/*
	 * Set a fake rlimit so the allocations below fail after deleting
	 * and are forced to restore from the zap list.
	 */
	map->size_limit = 0;

	/*
	 * Test both with and without an allocation following
	 * the fixed-overwrite address range (rdar://151817362).
	 */

	/* replace the entire overwriteable entry; following address is unallocated */
	vm_map_enter_restore_successes = 0;
	vm_map_enter_restore_failures = 0;
	address = overwriteable;
	kr = vm_map_enter(map, &address, overwriteable_size, 0 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    replacement_prot, replacement_prot, VM_INHERIT_DEFAULT);
	T_EXPECT_EQ(kr, KERN_NO_SPACE,
	    "fixed-overwrite restore, next is unallocated, kr");
	T_EXPECT_EQ(vm_map_enter_restore_successes, 1,
	    "fixed-overwrite restore, next is unallocated, restore should succeed");
	T_EXPECT_EQ(vm_map_enter_restore_failures, 0,
	    "fixed-overwrite restore, next is unallocated, restore should not fail");
	verify_test_map(map, &overwriteable_entry, 1);
	T_EXPECT_EQ(map->hdr.nentries, 1, "vm_map_enter did not clip");

	/* replace only part of the overwriteable entry; following address is allocated */
	vm_map_enter_restore_successes = 0;
	vm_map_enter_restore_failures = 0;
	address = overwriteable;
	kr = vm_map_enter(map, &address, overwriteable_size - PAGE_SIZE, 0 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    replacement_prot, replacement_prot, VM_INHERIT_DEFAULT);
	T_EXPECT_EQ(kr, KERN_NO_SPACE,
	    "fixed-overwrite restore, next is allocated, kr");
	T_EXPECT_EQ(vm_map_enter_restore_successes, 1,
	    "fixed-overwrite restore, next is allocated, restore should succeed");
	T_EXPECT_EQ(vm_map_enter_restore_failures, 0,
	    "fixed-overwrite restore, next is allocated, restore should not fail");
	verify_test_map(map, &overwriteable_entry, 1);
	T_EXPECT_EQ(map->hdr.nentries, 2, "vm_map_enter restore did not simplify");
}

T_DECL(zap_list_restore_race,
    "zap list restoration after fixed-overwrite allocation failure due to thread race")
{
	/*
	 * Fixed-overwrite allocation can fail and be forced to restore the
	 * overwritten entries from a zap list. When the failed allocation
	 * is a superpage the map interlock is dropped to wire the superpage,
	 * which means that a second thread can deallocate and reallocate
	 * in that space. Then zap list restore will fail because the
	 * space is not empty.
	 */

	/* set by vm_map_enter */
	extern unsigned int vm_map_enter_restore_successes;
	extern unsigned int vm_map_enter_restore_failures;

	kern_return_t kr;
	vm_map_offset_t address;
	vm_map_size_t size;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	/* use protection to detect if fixed-overwrite succeeded */
	vm_prot_t overwriteable_prot = VM_PROT_READ;
	vm_prot_t replacement_prot = VM_PROT_READ | VM_PROT_WRITE;
	vm_prot_t race_prot = VM_PROT_NONE;

	test_entry_t overwriteable_entry;
	test_entry_t entries[2];

	/* Allocate space to be overwritten. */
	vm_map_offset_t overwriteable = 0;
	vm_map_size_t overwriteable_size = SUPERPAGE_SIZE;
	kr = vm_map_enter(map, &overwriteable, overwriteable_size,
	    SUPERPAGE_SIZE - 1 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    overwriteable_prot, overwriteable_prot, VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "allocate to be overwritten");

	overwriteable_entry = (test_entry_t){
		.start = overwriteable,
		.end = overwriteable + overwriteable_size,
		.flags = 0,
		.cur_protection = VM_PROT_READ,
		.max_protection = VM_PROT_READ,
	};
	verify_test_map(map, &overwriteable_entry, 1);

	/* Description of the entry that the "thread race" will allocate. */
	test_entry_t race_entry = overwriteable_entry;
	race_entry.cur_protection = race_prot;
	race_entry.max_protection = race_prot;

	/* set mocks to allow superpages (except vm_map_wire_kernel) */
	T_MOCK_SET_RETVAL(pmap_cache_attributes, unsigned int, 0);
	T_MOCK_SET_CALLBACK(vm_superpage_size, kern_return_t, (unsigned int superpage_size, vm_map_size_t * size), {
		T_QUIET; T_ASSERT_EQ(superpage_size, SUPERPAGE_SIZE_ANY, "Sanity check args");
		T_QUIET; T_ASSERT_EQ(*size, (vm_map_size_t)SUPERPAGE_SIZE, "Sanity check args");
		*size = SUPERPAGE_SIZE;
		return KERN_SUCCESS;
	});

	/*
	 * vm_map_enter calls vm_map_wire_kernel on the new superpage allocation
	 * with the lock dropped. Intercept that call to (1) deallocate
	 * the new allocation and (2) fail, as if there were a thread race.
	 * vm_map_enter will respond by deleting its new allocation
	 * and attempting to restore from the zap list.
	 */
	__block vm_object_t wired_object = NULL;
	__block bool race_allocates_permanent;
	T_MOCK_SET_CALLBACK(vm_map_wire_kernel, kern_return_t,
	    (vm_map_t map, vm_map_offset_t start_u, vm_map_offset_t end_u, vm_prot_t prot_u, vm_tag_t tag, boolean_t user_wire), {
		/* Look up the newly-allocated entry and its object */
		VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_find_entry_sh_locked(ctx, &map, overwriteable, VMRL_FIND_SH_DEFAULT);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "find wire entry");

		wired_object = VME_OBJECT(vm_map_found_entry_get_entry(ctx));
		T_ASSERT_NE_PTR(wired_object, NULL, "wire entry should have an object");
		vm_object_reference(wired_object);      /* save for verification later */

		vm_map_found_entry_sh_unlock(ctx, &map);

		/* Now deallocate that entry and allocate a new one. */
		kr = vm_map_remove_guard(map, overwriteable, overwriteable + overwriteable_size, 0, KMEM_GUARD_NONE);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "race deallocate");

		vm_map_offset_t race_addr = race_entry.start;
		kr = vm_map_enter(map, &race_addr, race_entry.end - race_entry.start,
		0 /* alignment mask */,
		VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = race_allocates_permanent),
		VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
		race_entry.cur_protection, race_entry.max_protection, VM_INHERIT_DEFAULT);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "race allocate");

		return KERN_INVALID_PROCESSOR_SET;     /* non sequitur to detect below */
	});

	/*
	 * Allocate a superpage, fixed-overwrite,
	 * with a race that deallocates it while wiring.
	 * Zap list restoration should succeed.
	 */
	race_allocates_permanent = false;
	vm_map_enter_restore_successes = 0;
	vm_map_enter_restore_failures = 0;
	address = overwriteable;
	kr = vm_map_enter(map, &address, overwriteable_size, 0 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true, .vmf_superpage_size = SUPERPAGE_SIZE_ANY),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    replacement_prot, replacement_prot, VM_INHERIT_DEFAULT);
	T_EXPECT_EQ(kr, KERN_INVALID_PROCESSOR_SET,
	    "fixed-overwrite restore after race, kr");
	T_EXPECT_EQ(vm_map_enter_restore_successes, 1,
	    "fixed-overwrite restore after race, restore should succeed");
	T_EXPECT_EQ(vm_map_enter_restore_failures, 0,
	    "fixed-overwrite restore after race, restore should not fail");
	race_entry.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = race_allocates_permanent);
	verify_test_map(map, &overwriteable_entry, 1);

	/*
	 * The object backing the superpage should have become unreferenced by now.
	 * Its only surviving reference is our own.
	 */
	T_ASSERT_NE_PTR(wired_object, NULL, "should have saved wired object during race");
	T_ASSERT_EQ(wired_object->ref_count, 1, "wired object should be unreferenced");
	vm_object_deallocate(wired_object);
	wired_object = NULL;

	/*
	 * Allocate a superpage, fixed-overwrite,
	 * with a race that deallocates it while wiring
	 * and allocates a permanent entry in its place.
	 * Zap list restoration should fail.
	 */
	race_allocates_permanent = true;
	vm_map_enter_restore_successes = 0;
	vm_map_enter_restore_failures = 0;
	address = overwriteable;

	kr = vm_map_enter(map, &address, overwriteable_size, 0 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true, .vmf_superpage_size = SUPERPAGE_SIZE_ANY),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    replacement_prot, replacement_prot, VM_INHERIT_DEFAULT);
	T_EXPECT_EQ(kr, KERN_INVALID_PROCESSOR_SET,
	    "fixed-overwrite restore after race with permanent, kr");
	T_EXPECT_EQ(vm_map_enter_restore_successes, 0,
	    "fixed-overwrite restore after race with permanent, restore should fail");
	T_EXPECT_EQ(vm_map_enter_restore_failures, 1,
	    "fixed-overwrite restore after race with permanent, restore should not succeed");
	race_entry.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_permanent = race_allocates_permanent);
	verify_test_map(map, &race_entry, 1);

	/*
	 * The object backing the superpage should have become unreferenced by now.
	 * Its only surviving reference is our own.
	 */
	T_ASSERT_NE_PTR(wired_object, NULL, "should have saved wired object during race");
	T_ASSERT_EQ(wired_object->ref_count, 1, "wired object should be unreferenced");
	vm_object_deallocate(wired_object);
	wired_object = NULL;

	vm_map_deallocate(map);
}

T_DECL(new_entry_coalesce, "New Entry Coalesce") {
	kern_return_t kr;
	vm_map_offset_t start = 0x2000000;
	test_entry_t entries[] = {
		{
			.start = start - PAGE_SIZE,
			.end = start,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = sizeof(entries) / sizeof(entries[0]);

	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	vm_map_offset_t address = start;
	vm_map_size_t size = PAGE_SIZE;
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "The new entry should be entered successfully");
	assert_vm_map_ilk_not_owned(map);

	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		vm_map_entry_t vme = entry;
		T_ASSERT_EQ(vme->vme_start, start - PAGE_SIZE, "The entry will start at the original entry");
		T_ASSERT_EQ(vme->vme_end, start + PAGE_SIZE, "The entry will extend to the new bounds");
		return KERN_SUCCESS;
	});
}

T_DECL(exceed_rlimit_as, "Exceed Address Space Limit") {
	kern_return_t kr;

	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;
	kr = vm_map_set_size_limit(map, PAGE_SIZE);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Setting size limit should succeed");
	T_SETUPEND;

	vm_map_offset_t address = 0;
	vm_map_size_t size = 2 * PAGE_SIZE;
	vm_object_t object = vm_object_allocate(size, map->serial_id);

	os_ref_retain_internal(&object->ref_count, NULL); // Artificially inflate refcount to prevent over-release
	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 2, "Expecting a single owner to this object ");

	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(), object, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_NO_SPACE, "Expecting adding entry to fail because it exceeds the address space size limit");
	assert_vm_map_ilk_not_owned(map);
	T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), 2, "Still expecting a single owner to this object ");

	verify_test_map(map, NULL, 0);
}

T_DECL(exceed_rlimit_data, "Exceed Data Size Limit") {
	kern_return_t kr;

	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;
	kr = vm_map_set_data_limit(map, PAGE_SIZE);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Setting data limit should succeed");
	T_SETUPEND;

	vm_map_offset_t address = 0;
	vm_map_size_t size = 2 * PAGE_SIZE;
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_ANYWHERE(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_NO_SPACE, "Expecting adding entry to fail because it exceeds the data size limit");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, NULL, 0);
}

T_DECL(new_entry_coalesce_with_failure, "New Entry Coalesce With Failure") {
	kern_return_t kr;
	vm_map_offset_t start = 0x2000000;
	test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 2 * PAGE_SIZE,
			// vm_map_enter just trusts the size we enter if we say it's 2MB
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = sizeof(entries) / sizeof(entries[0]);

	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	T_SETUPBEGIN;

	setup_test_map(map, entries, n_entries);

	kr = vm_map_set_size_limit(map, 2 * PAGE_SIZE);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Setting size limit should succeed");

	T_SETUPEND;

	vm_map_offset_t address = start + PAGE_SIZE;
	vm_map_size_t size = 2 * PAGE_SIZE;
	kr = vm_map_enter(map, &address, size, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_NO_SPACE, "Expecting adding entry to fail because it exceeds the size limit");
	assert_vm_map_ilk_not_owned(map);

	verify_test_map(map, entries, n_entries);
}

T_DECL(submap_entry_nesting_failure, "Submap Entry PMAP Nesting Failure") {
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	vm_map_address_t submap_start = 0x200000ull;
	vm_map_address_t submap_end = 0x400000ull;
	vm_map_t submap = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	T_MOCK_SET_RETVAL(pmap_nest, kern_return_t, KERN_FAILURE);
	kern_return_t kr = vm_map_enter(map, &submap_start, submap_end - submap_start, 0, VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmkf_nested_pmap = true), (vm_object_t)submap, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Failure to complete pmap_nest still results in success");

	test_entry_t entries[] = {
		{
			.start = submap_start,
			.end = submap_end,
			// vm_map_enter just trusts the size we enter if we say it's 2MB
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = 0,
			.max_protection = 0,
		},
	};
	const unsigned n_entries = sizeof(entries) / sizeof(entries[0]);
	verify_test_map(map, entries, n_entries);
}

/*
 * Test to verify that sentinel entries are not restored from zap lists in
 * vm_map_enter. This test creates a scenario where we delete a range that
 * contains a gap, then restore from our zap list. This will fail if the
 * sentinel entry was added to the zap list and restored to the map.
 */
T_DECL(test_vm_map_sentinel_restore, "Test that sentinel entries are not restored from zap lists") {
	kern_return_t kr;
	vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
	/* set by vm_map_enter */
	extern unsigned int vm_map_enter_restore_successes;
	extern unsigned int vm_map_enter_restore_failures;

	/* Create two non-contiguous entries with a gap between them */
	const vm_map_offset_t start = 0x10000;
	const test_entry_t entries[] = {
		{
			.start = start,
			.end = start + 10 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = VM_PROT_DEFAULT,
			.max_protection = VM_PROT_DEFAULT,
		},
		{
			.start = start + 15 * PAGE_SIZE, /* 5-page gap */
			.end = start + 25 * PAGE_SIZE,
			.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
			.cur_protection = VM_PROT_DEFAULT,
			.max_protection = VM_PROT_DEFAULT,
		},
	};
	const unsigned n_entries = sizeof(entries) / sizeof(entries[0]);

	T_SETUPBEGIN;
	setup_test_map(map, entries, n_entries);
	T_SETUPEND;

	/* Set a fake rlimit so the allocation below fails after deleting */
	map->size_limit = 0;

	/*
	 * Attempt a fixed-overwrite allocation that spans both entries and the gap.
	 * This will cause entries to be saved in the zap list and then restored.
	 * A sentinel entry would be created for the gap and added to the zap list.
	 */
	vm_map_enter_restore_successes = 0;
	vm_map_enter_restore_failures = 0;
	vm_map_offset_t address = entries[0].start;
	const vm_map_size_t range_size = entries[1].end - entries[0].start;
	kr = vm_map_enter(map, &address, range_size, 0 /* alignment mask */,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true),
	    VM_OBJECT_NULL, 0 /* object offset */, false /* needs_copy */,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_EXPECT_EQ(kr, KERN_NO_SPACE, "fixed-overwrite should fail due to rlimit");
	T_EXPECT_EQ(vm_map_enter_restore_successes, 1, "restore should succeed");
	T_EXPECT_EQ(vm_map_enter_restore_failures, 0, "restore should not fail");

	/* Check if any sentinel entries were incorrectly restored to the map. */
	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		T_EXPECT_FALSE(VME_IS_SENTINEL(entry), "No sentinel entries should be in the map after restoration");
		return KERN_SUCCESS;
	});

	verify_test_map(map, entries, n_entries);

	vm_map_deallocate(map);
}

static void
test_submap_insertion_checks(vm_map_kernel_flags_t bad_flags, unsigned submap_sealing)
{
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t parent_map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	/* Define a range in the parent map for the submap entry */
	const vm_map_address_t submap_start = 0x200000ull;
	const vm_map_address_t submap_end = 0x400000ull;
	const vm_map_size_t submap_size = submap_end - submap_start;
	vm_map_t submap = vm_map_create_options(NULL, 0, submap_size, 0);
	submap->vmmap_sealed = submap_sealing;

	/* Attempt to enter the submap into the parent map with bad flags. */
	vm_map_address_t address = submap_start;
	vm_map_reference(submap); /* Required by vm_map_adjust_offsets */
	vm_map_enter(
		parent_map, &address, submap_size, 0,
		bad_flags,
		(vm_object_t)submap, 0, false,
		VM_PROT_DEFAULT, VM_PROT_DEFAULT, 0);
	T_FAIL("Caller of helper function should assert panic");
}

T_DECL(transparent_submap_insertion_permanent_checks, "Transparent submap permanence should be enforced") {
	T_ASSERT_PANIC({
		test_submap_insertion_checks(
			VM_MAP_KERNEL_FLAGS_FIXED(
				.vmkf_submap = TRUE, .vmkf_submap_atomic = true,
				),
			VM_MAP_NOT_SEALED);
	}, "Expect panic when entering a transparent submap that isn't permanent");
}

T_DECL(constant_submap_insertion_sealing_checks, "Cosntant submap sealing should be enforced") {
	T_ASSERT_PANIC({
		test_submap_insertion_checks(
			VM_MAP_KERNEL_FLAGS_FIXED(
				.vmkf_submap = TRUE,
				),
			VM_MAP_NOT_SEALED);
	}, "Expect panic when entering a constant submap without appropriate sealing");
}

T_DECL(transparent_submap_insertion_offset, "Transparent submap entry offset should match start addr") {
	/*
	 * This verifies that transparent submap entries have the same offset and start address.
	 * This is a core property of transparent submaps that allows us to avoid address translation
	 * between the parent view and the submap view.
	 * This property is implemented by vmkf_submap_atomic.
	 */
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t parent_map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);

	/* Define a range in the parent map for the submap entry */
	const vm_map_address_t submap_start = 0x200000ull;
	const vm_map_address_t submap_end = 0x300000ull;
	const vm_map_size_t submap_size = submap_end - submap_start;
	vm_map_t submap = vm_map_create_options(NULL, 0, submap_size, 0);

	vm_map_address_t address = submap_start;
	vm_map_reference(submap); /* Required by vm_map_adjust_offsets */
	kern_return_t kr = vm_map_enter(
		parent_map, &address, submap_size, 0,
		VM_MAP_KERNEL_FLAGS_FIXED(
			.vmkf_submap = TRUE, .vmf_permanent = true,
			.vmkf_submap_atomic = true,
			),
		(vm_object_t)submap, 0, false,
		VM_PROT_DEFAULT, VM_PROT_DEFAULT, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Entry entered successfully.");
	T_ASSERT_EQ(parent_map->hdr.nentries, 1, "Parent map has just that entry.");
	vm_map_entry_t entry = parent_map->hdr.links.next;
	T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "Entry is not null.");
	T_ASSERT_EQ_ULLONG(entry->vme_start, address, "Fixed mapping at expected address.");
	T_ASSERT_EQ_ULLONG(entry->vme_start, VME_OFFSET(entry),
	    "Transparent submap entry should have matching start and offset.");
}

T_DECL(fixed_mapping_through_transparent_submap_errors,
    "Fixed mapping into transparent submap from parent should fail")
{
	kern_return_t kr;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t parent_map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);
	vm_map_t submap = vm_map_create_options(NULL, 0, PAGE_SIZE, 0);

	/* Add the submap to the parent map */
	vm_map_address_t submap_start = 0x200000ull;
	vm_map_reference(submap);
	kr = vm_map_enter(parent_map, &submap_start, PAGE_SIZE, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmf_permanent = true,
	    .vmkf_submap_atomic = true),
	    (vm_object_t)submap, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Adding transparent submap to parent map should succeed");

	/* Attempt to enter entry from parent map */
	kr = vm_map_enter(parent_map, &submap_start, PAGE_SIZE, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(), VM_OBJECT_NULL, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_NO_SPACE,
	    "Fixed mapping into transparent submap through parent map should fail with KERN_NO_SPACE");
}

/*
 * If you're attempting to change this behavior and add support for
 * fixed overwrite in transparent submaps through the parent, make sure
 * you fix the zap list restore path to restore to the right map.
 * See rdar://145771769
 */
T_DECL(fixed_mapping_through_transparent_submap_panic,
    "Fixed overwrite mapping into transparent submap from parent should panic")
{
	kern_return_t kr;
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	vm_map_t parent_map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);
	vm_map_t submap = vm_map_create_options(NULL, 0, PAGE_SIZE, 0);

	/* Add the submap to the parent map */
	vm_map_address_t submap_start = 0x200000ull;
	vm_map_reference(submap);
	kr = vm_map_enter(parent_map, &submap_start, PAGE_SIZE, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmf_permanent = true,
	    .vmkf_submap_atomic = true),
	    (vm_object_t)submap, 0, false, 0, 0, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "Adding transparent submap to parent map should succeed");

	/* Attempt to enter entry from parent map */
	T_ASSERT_PANIC({
		vm_map_enter(parent_map, &submap_start, PAGE_SIZE, 0,
		VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true),
		VM_OBJECT_NULL, 0, false, 0, 0, 0);
	}, "Fixed overwrite mapping into transparent submap through parent map should panic");
}
