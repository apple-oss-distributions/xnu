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
#include <vm/vm_map_internal.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_map_store_internal.h>
#include <kern/zalloc.h>
#include <mach/vm_param.h>
#include <sys/mman.h>
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/unit_test_utils.h"

// Helper function to add VM map entries using vm_map_enter
static void
enter_obj_entry(vm_map_t map, vm_map_address_t start, vm_map_size_t size, vm_prot_t cur_prot, bool needs_copy)
{
	/* Create a non-NULL object to avoid coalescing */
	vm_object_t obj = vm_object_allocate(size, map->serial_id);
	kern_return_t kr = vm_map_enter(map, &start, size, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(),
	    obj, 0, needs_copy, cur_prot, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_map_enter");
}

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vmmap_summary"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(false)
	);


T_DECL(test_showmap_summary_basic, "Test showmap with basic setup of a vm_map struct") {
	// Create a pmap and vm_map using the mock infrastructure
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	T_ASSERT_NOTNULL(pmap, "pmap should be created");

	vm_map_t map = vm_map_create_options(pmap, 0, 0x100000000ULL, 0);
	T_ASSERT_NOTNULL(map, "vm_map should be created");

	vm_map_address_t offset = 0x10000;

	// Add 6 entries with different sizes and protections to create a realistic map
	enter_obj_entry(map, offset, PAGE_SIZE * 15, VM_PROT_READ, true);  // Entry 1: 60KB
	offset += PAGE_SIZE * 15;

	enter_obj_entry(map, offset, PAGE_SIZE * 240, VM_PROT_DEFAULT, false); // Entry 2: 960KB
	offset += PAGE_SIZE * 240;

	enter_obj_entry(map, offset, PAGE_SIZE * 256, VM_PROT_READ | VM_PROT_WRITE, true); // Entry 3: 1MB
	offset += PAGE_SIZE * 256;

	// Set the page shift for testing
	map->hdr.page_shift = 10;

	ut_lldb_check_point("checkpoint1");

	map->hdr.page_shift = 3;

	ut_lldb_check_point("checkpoint2");
}
