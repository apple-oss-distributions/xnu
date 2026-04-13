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
#include <mach/dyld_pager.h>
#include <mach/vm_map.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_dyld_pager_internal.h>
#include <vm/vm_fault.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_internal.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_vm.h"

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_with_linking"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

static void
fault_addr(vm_map_t map, mach_vm_address_t addr)
{
	kern_return_t kr;
	kr = vm_fault(map, addr, VM_PROT_READ, false, VM_KERN_MEMORY_NONE, 0, NULL, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "read fault map %p address 0x%llx", map, addr);
}

static void
set_object(vm_map_t map, vm_map_entry_t entry, vm_object_t object)
{
	vm_map_ilk_lock(map);
	(void)vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
	    entry, entry->vme_start, THREAD_UNINT);
	VME_OBJECT_SET(entry, object, false, 0);
	vm_entry_unlock_exclusive(map, entry);
	vm_map_ilk_unlock(map);
}

/*
 * vm_map_with_linking() checks some preconditions,
 * then creates a pager with dyld_pager_setup(),
 * then performs the requested mappings.
 *
 * This test mocks out dyld_pager_setup() and
 * exercises the early-exit paths before it.
 */
T_DECL(test_before_pager_setup,
    "test paths through vm_map_with_linking before it creates a pager")
{
	/* Mock dyld_pager_setup() to return NULL */
	T_MOCK_SET_RETVAL(dyld_pager_setup, memory_object_t, MEMORY_OBJECT_NULL);

	kern_return_t kr;
	mach_vm_address_t addr;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT),
	    PAGE_SIZE, -(vm_map_offset_t)PAGE_SIZE, 0);
	T_QUIET; T_ASSERT_NOTNULL(map, "allocate test map");

	current_task()->map = map;
	current_thread()->map = map;
	vm_map_setup(map, current_task());

	void *null_link_info = NULL;

	/* test: no regions */
	kr = vm_map_with_linking(current_task(), NULL, 0, NULL, 0, NULL);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	    "region_cnt == 0");

	/* test: file_object is NULL */
	struct mwl_region region;
	region.mwlr_address = PAGE_SIZE;

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, NULL);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	    "file_control == NULL ('invalid object for provided file')");

	/* test: file_object is internal */
	vm_object_t internal_object = vm_object_allocate(PAGE_SIZE, map->serial_id);
	T_QUIET; T_ASSERT_NOTNULL(internal_object, "allocate vm_object");
	T_QUIET; T_ASSERT_TRUE(internal_object->internal, "allocated vm_object is internal");

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, internal_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	    "file_control->internal == true ('invalid object for provided file')");

	/* test: region->mwlr_address is unmapped */
	vm_object_t external_object = vm_object_allocate(PAGE_SIZE, map->serial_id);
	external_object->internal = false;

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS,
	    "mwlr_address is unmapped");

	/* test: region->mwlr_address is a submap */
	vm_map_t submap = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT),
	    PAGE_SIZE, -(vm_map_offset_t)PAGE_SIZE, 0);
	T_QUIET; T_ASSERT_NOTNULL(submap, "allocate test submap");
	submap->is_nested_map = true;
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
	addr = region.mwlr_address;
	kr = vm_map_enter(map, &addr, PAGE_SIZE, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmkf_nested_pmap = true),
	    (vm_object_t) submap,
	    0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert test submap");

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS,
	    "mwlr_address is a submap");

	/* test: region->mwlr_address is mapped but has no backing object */
	addr = region.mwlr_address;
	kr = mach_vm_allocate_kernel(map, (mach_vm_offset_ut *)&addr, PAGE_SIZE,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true));
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate in test map");
	T_QUIET; T_ASSERT_EQ(addr, region.mwlr_address, "allocate at mwlr_address");
	vm_map_entry_t allocation_entry = vm_map_first_entry(map);
	T_QUIET; T_ASSERT_EQ(allocation_entry->vme_start, addr, "first map entry is new allocation");
	T_QUIET; T_ASSERT_NULL(VME_OBJECT(allocation_entry), "new allocation has null object");

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS,
	    "mwlr_address is mapped with no object");

	/* test: object backing mwlr_address is not equal to file_object */
	fault_addr(map, addr);
	vm_object_t allocation_object = VME_OBJECT(allocation_entry);
	T_QUIET; T_ASSERT_NOTNULL(allocation_object, "fault in test allocation");
	vm_object_reference(allocation_object);  /* keep object alive when we detach it later */

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	    "mwlr_address has the wrong object ('mapping at ... is not backed by the expected file')");

	/* test: object backing mwlr_address has a shadow that is not equal to file_object */
	vm_object_t shadow_object = vm_object_allocate(PAGE_SIZE, map->serial_id);
	allocation_object->shadow = shadow_object;
	shadow_object->vo_copy = allocation_object;

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	    "mwlr_address has the wrong shadow object ('mapping at ... is not backed by the expected file')");

	/* test: object backing mwlr_address is equal to file_object */
	set_object(map, allocation_entry, external_object);

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
	    "mwlr_address is backed by file_object ('mapping at ... not a proper copy-on-write mapping')");

	/* test: object backing mwlr_address has a shadow equal to file_object */
	/* This one finally reaches the mocked dyld_pager_setup()
	 * and gets KERN_RESOURCE_SHORTAGE back. */
	set_object(map, allocation_entry, allocation_object);
	allocation_entry->needs_copy = true;
	allocation_object->shadow = external_object;
	external_object->vo_copy = allocation_object;

	kr = vm_map_with_linking(current_task(), &region, 1, &null_link_info, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_RESOURCE_SHORTAGE,
	    "mwlr_address shadow object is file_object");

	/* test: map region is not writable */
	kr = mach_vm_protect(map, addr, PAGE_SIZE, TRUE, VM_PROT_READ);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_protect(R)");

	kr = vm_map_with_linking(current_task(), &region, 1, NULL, 0, external_object);
	T_ASSERT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE,
	    "mwlr_address is not writable");

	/* No attempt to clean up here. The map's state at this point is too fake. */
}
