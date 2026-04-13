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
#include "mocks/osfmk/unit_test_utils.h"

#include <vm/vm_fault.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_test_utils_internal.h>
#include "mocks/osfmk/mock_vm.h"

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.test_vm_map_msync"),
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

T_MOCK_CALL_QUEUE(obj_sync, {
	vm_object_t object;
	vm_object_offset_t offset;
	vm_object_size_t size;
	bool should_flush;
	bool should_return;
	bool should_iosync;
});

static void
make_sync_call(vm_object_t obj, vm_sync_t flags)
{
	bool inval = flags & VM_SYNC_INVALIDATE;
	bool sync = flags & VM_SYNC_SYNCHRONOUS;
	bool async = flags & VM_SYNC_ASYNCHRONOUS;

	enqueue_obj_sync((obj_sync){
		.object = obj,
		.offset = 0,
		.size = PAGE_SIZE,
		.should_flush = inval,
		.should_return = sync | async,
		.should_iosync = sync,
	});
}

T_MOCK_SET_PERM_FUNC(boolean_t,
    vm_object_sync,
    (vm_object_t             object,
    vm_object_offset_t      offset,
    vm_object_size_t        size,
    boolean_t               should_flush,
    boolean_t               should_return,
    boolean_t               should_iosync))
{
	obj_sync call = dequeue_obj_sync();

	T_ASSERT_EQ_PTR(call.object, object, "unexpected object");

#define VALIDATE_CALL_PROPERTY(prop) assert3u(!!call.prop, ==, !!prop)
	VALIDATE_CALL_PROPERTY(offset);  // BUG
	VALIDATE_CALL_PROPERTY(size);
	VALIDATE_CALL_PROPERTY(should_flush);
	VALIDATE_CALL_PROPERTY(should_return);
	VALIDATE_CALL_PROPERTY(should_iosync);

	return true;
}



#pragma mark Prepare map with entries and objects

const mach_vm_address_t addr1 = PAGE_SIZE * 0x4000;
const mach_vm_address_t addr2 = addr1 + PAGE_SIZE;
const mach_vm_address_t addr3 = addr2 + PAGE_SIZE;
const mach_vm_address_t addr4 = addr3 + PAGE_SIZE;
const mach_vm_address_t addr5 = addr4 + PAGE_SIZE;

typedef struct {
	mach_vm_address_t start;
	mach_vm_address_t end;
} msync_range_t;

// Layout of the test map
msync_range_t entry1 = {.start = addr1, .end = addr2};
msync_range_t entry2 = {.start = addr2, .end = addr3};
msync_range_t gap1   = {.start = addr3, .end = addr4};
msync_range_t entry3 = {.start = addr4, .end = addr5};

msync_range_t one_entry       = {.start = addr1, .end = addr2};
msync_range_t two_entries     = {.start = addr1, .end = addr3};
msync_range_t one_gap         = {.start = addr3, .end = addr4};
msync_range_t entries_and_gap = {.start = addr1, .end = addr5};

// Remember object pointers for call interception
static vm_object_t obj1;
static vm_object_t obj2;
static vm_object_t obj3;

vm_map_t map = VM_MAP_NULL;

static void
fault_addr(mach_vm_address_t addr)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, vm_fault(map, addr, VM_PROT_READ, false, VM_KERN_MEMORY_NONE, 0, NULL, 0), "Faulting");
}

static void
prepare_entry(msync_range_t range, bool fault, vm_object_t *object)
{
	vm_map_entry_t entry = vm_test_add_map_entry(map, range.start, range.end);
	if (!fault) {
		return;
	}
	fault_addr(range.start);
	vm_object_t obj = VME_OBJECT(entry);
	// Fake that the object is backed by a pager
	obj->pager = (memory_object_t)1; // not MEMORY_OBJECT_NULL
	obj->private = false;
	obj->internal = false;
	*object = obj;
}

static void
prepare_map(bool fault)
{
	map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	prepare_entry(entry1, fault, &obj1);
	prepare_entry(entry2, fault, &obj2);
	prepare_entry(entry3, fault, &obj3);
}

#pragma mark Tests

T_DECL(test_vm_map_msync_bag_args, "vm_map_msync incorrect args")
{
	prepare_map(false);

	clear_obj_sync();
	T_ASSERT_EQ(KERN_INVALID_TASK, vm_map_msync(VM_MAP_NULL, 0, 0, 0), "Passing VM_MAP_NULL");
	assert_empty_obj_sync();

	T_ASSERT_EQ(KERN_INVALID_ARGUMENT, vm_map_msync(map, 0, 0, VM_SYNC_ASYNCHRONOUS | VM_SYNC_SYNCHRONOUS), "Passing async and sync");
	assert_empty_obj_sync();

	T_ASSERT_EQ(KERN_INVALID_ADDRESS, vm_map_msync(map, PAGE_SIZE, UINT64_MAX, 0), "Overflow");
	assert_empty_obj_sync();
}

void
msync_range(kern_return_t expected_kr, msync_range_t range, vm_sync_t flags, char *str)
{
	T_ASSERT_EQ(expected_kr, vm_map_msync(map, range.start, range.end - range.start, flags), "%s", str);
	assert_empty_obj_sync();
}

T_DECL(test_vm_map_msync_no_obj, "vm_map_msync no object")
{
	prepare_map(false);

	clear_obj_sync();
	msync_range(KERN_SUCCESS, one_entry, 0, "One entry with no object");
}

T_DECL(test_vm_map_msync_default, "vm_map_msync no flags")
{
	prepare_map(true);

	make_sync_call(obj1, 0);
	msync_range(KERN_SUCCESS, one_entry, 0, "One entry");

	make_sync_call(obj1, 0);
	make_sync_call(obj2, 0);
	msync_range(KERN_SUCCESS, two_entries, 0, "msync two entries");

	assert_empty_obj_sync();
	msync_range(KERN_SUCCESS, one_gap, 0, "No memory there");

	make_sync_call(obj1, 0);
	make_sync_call(obj2, 0);
	make_sync_call(obj3, 0);
	msync_range(KERN_SUCCESS, entries_and_gap, 0, "msync full range");
}

T_DECL(test_vm_map_msync_contiguous, "vm_map_msync contiguous")
{
	prepare_map(true);
	vm_sync_t flags = VM_SYNC_CONTIGUOUS;

	make_sync_call(obj1, flags);
	msync_range(KERN_SUCCESS, one_entry, flags, "One entry");

	make_sync_call(obj1, flags);
	make_sync_call(obj2, flags);
	msync_range(KERN_SUCCESS, two_entries, flags, "msync two entries");

	clear_obj_sync();
	msync_range(KERN_INVALID_ADDRESS, one_gap, flags, "No memory there");

	make_sync_call(obj1, flags);
	make_sync_call(obj2, flags);
	msync_range(KERN_INVALID_ADDRESS, entries_and_gap, flags, "msync full range");
}

T_DECL(test_vm_map_msync_killpages, "vm_map_msync kill pages")
{
	prepare_map(true);
	vm_sync_t flags = VM_SYNC_KILLPAGES;

	clear_obj_sync();
	msync_range(KERN_SUCCESS, one_entry, flags, "One entry");

	clear_obj_sync();
	msync_range(KERN_SUCCESS, two_entries, flags, "msync two entries");

	clear_obj_sync();
	msync_range(KERN_SUCCESS, one_gap, flags, "No memory there");

	clear_obj_sync();
	msync_range(KERN_SUCCESS, entries_and_gap, flags, "msync full range");
}

T_DECL(test_vm_map_msync_more_flags, "vm_map_msync more flags")
{
	prepare_map(true);

	vm_sync_t flags = VM_SYNC_DEACTIVATE;
	clear_obj_sync();
	msync_range(KERN_SUCCESS, one_entry, flags, "Deactivate one entry");

	flags = VM_SYNC_INVALIDATE;
	obj1->resident_page_count = 0;
	obj1->sequential = 0xed0u;
	make_sync_call(obj1, flags);
	msync_range(KERN_SUCCESS, one_entry, flags, "Invalidate pages in one entry");
	T_ASSERT_EQ(obj1->sequential, 0x0, "`sequential` value expected to be clear by vm_map_msync");
}

T_DECL(test_vm_map_msync_misc, "vm_map_msync miscelanous cases")
{
	prepare_map(true);
	vm_sync_t flags = 0;

	obj1->pager = MEMORY_OBJECT_NULL;
	clear_obj_sync();
	msync_range(KERN_SUCCESS, one_entry, flags, "Object with no pager");
}
