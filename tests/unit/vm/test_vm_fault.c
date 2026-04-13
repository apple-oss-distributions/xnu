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

#include <stdint.h>
#include "mocks/osfmk/unit_test_utils.h"

#include <vm/vm_object_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_fault_internal.h>
#include <vm/vm_test_utils_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_misc_api_tests"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);


vm_map_address_t MAP_BASE = 0x010000000; // avoid the pmap_shared_region

static kern_return_t
call_vm_map_lookup_object_and_lock_entry_try_lock(vm_map_t map)
{
	kern_return_t kr;
	vm_map_t real_map;
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	vm_map_entry_t entry;
	vm_object_t object;
	vm_prot_t prot;
	boolean_t wired;
	struct vm_object_fault_info fault_info;
	vm_map_offset_t offset;
	kr = vm_map_lookup_object_and_lock_entry(&map, MAP_BASE, VM_PROT_WRITE,
	    &object, &entry, &offset, &prot, &wired,
	    &fault_info,
	    &real_map, ctx, NULL, true /* try_lock_entry */);

	if (kr == KERN_SUCCESS) {
		vm_map_range_sh_unlock(ctx, NULL);
	}

	return kr;
}

T_DECL(try_lock_test, "test try lock in vm_map_lookup_object_and_lock_entry")
{
	kern_return_t kr;
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	vm_map_entry_t entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	kr = call_vm_map_lookup_object_and_lock_entry_try_lock(map);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "try lock with nothing locked");

	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	entry = vm_test_add_map_entry(map, MAP_BASE, MAP_BASE + PAGE_SIZE);

	T_ASSERT_EQ_INT(vm_entry_try_lock_shared(entry), true, "try_lock");

	kr = call_vm_map_lookup_object_and_lock_entry_try_lock(map);
	T_ASSERT_EQ_INT(kr, VMRL_ERR_LOCK_ALREADY_HELD, "try lock with already locked entry");

	vm_entry_unlock_shared(map, entry);
}
