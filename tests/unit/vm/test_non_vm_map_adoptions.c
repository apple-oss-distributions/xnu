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

/*
 * Tests for range lock adoption of functions outside of vm_map.c or other
 * notable clusters.
 */

#include <darwintest.h>
#include "mocks/osfmk/mock_thread.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_vm.h"
#include "mocks/osfmk/mock_vnode_pager.h"

#include <mach/vm32_map_server.h>
#include <sys/bsdtask_info.h>
#include <vm/vm_fault.h>
#include <vm/vm_iokit.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_protos.h>
#include <vm/vm_test_utils_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.test_non_vm_map_adoptions"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

#pragma mark Declarations


#pragma mark Mocks

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

#pragma mark Utils

vm_map_t map;
vm_map_t submap;
vm_map_entry_t entry;
vm_map_entry_t entry2;
vm_map_entry_t parent_entry;
vm_map_entry_t child_entry;
const vm_map_address_t entry_start = 0x10000;
const vm_map_address_t entry_end = 0x20000;
const vm_map_address_t entry2_start = 0x40000;
const vm_map_address_t entry2_end = 0x50000;
const vm_map_address_t submap_start = 0x180000000ULL;
const vm_map_address_t submap_end = 0x300000000ULL;
const vm_map_address_t child_entry_start = 0x0;
const vm_map_address_t child_entry_end = 0x20000;

// Global mock values for vnode-related tests
const uintptr_t mock_vnode_addr = 0xabcd1234;
const uint32_t mock_vnode_id = 0xed0u;

T_MOCK_CALL_QUEUE(fill_vnodeinfo_call, {
	vm_map_entry_t expected_entry;
	int return_value;
});

T_MOCK_SET_PERM_FUNC(int, fill_vnodeinfoforaddr,
    (vm_map_entry_t entry, uintptr_t * vnodeaddr, uint32_t * vid, bool *is_map_shared)) {
	fill_vnodeinfo_call call = dequeue_fill_vnodeinfo_call();

	T_QUIET; T_ASSERT_EQ_PTR(call.expected_entry, entry, "fill_vnodeinfoforaddr called with expected entry");

	*vnodeaddr = mock_vnode_addr;
	*vid = mock_vnode_id;
	if (is_map_shared) {
		*is_map_shared = true;
	}

	return call.return_value;
}

T_MOCK_SET_PERM_FUNC(int, vnode_get, (struct vnode *vp)) {
	T_QUIET; T_ASSERT_EQ_PTR(vp, (void *)mock_vnode_addr, "vnode_get called with expected address");
	return 0;
}

static vm_map_entry_t
prepare_entry(vm_map_t m, vm_map_address_t start, vm_map_address_t end)
{
	vm_map_entry_t e = vm_test_add_map_entry(m, start, end);
	vm_map_ilk_lock(m);
	assert3u(KERN_SUCCESS, ==, vm_entry_lock_exclusive(m, LCK_RW_TYPE_EXCLUSIVE,
	    e, entry_start, THREAD_UNINT));
	VME_OBJECT_SET(e, vm_object_allocate(end - start, m->serial_id), false, 0);
	vm_entry_unlock_exclusive(m, e);
	vm_map_ilk_unlock(m);
	return e;
}

static vm_map_t
create_map()
{
	return vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
}

static void
prepare_submap(bool seal)
{
	kern_return_t kr;
	submap = create_map();
	submap->is_nested_map = true;
	submap->vmmap_sealed = VM_MAP_WILL_BE_SEALED;
	vm_map_address_t start = submap_start;
	kr = vm_map_enter(map, &start, submap_end - submap_start, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = true, .vmkf_nested_pmap = true), (vm_object_t) submap,
	    0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	assert(submap_start == start);
	vm_map_ilk_lock(map);
	parent_entry = vm_map_lookup(map, submap_start);
	assert(parent_entry && parent_entry->is_sub_map);
	vm_map_ilk_unlock(map);

	child_entry = prepare_entry(submap, child_entry_start, child_entry_end);
	VME_OBJECT(child_entry)->copy_strategy = MEMORY_OBJECT_COPY_DELAY;

	vm_map_entry_t other_entry = prepare_entry(submap, child_entry_end, submap_end - submap_start - child_entry_start);
	VME_OBJECT(other_entry)->copy_strategy = MEMORY_OBJECT_COPY_DELAY;

	if (seal) {
		vm_map_seal(submap, true);
	}
}

__attribute__((overloadable))
static void
prepare_map(bool seal_submap)
{
	map = create_map();
	entry = prepare_entry(map, entry_start, entry_end);
	entry2 = prepare_entry(map, entry2_start, entry2_end);
	prepare_submap(seal_submap);
}

__attribute__((overloadable))
static void
prepare_map(void)
{
	prepare_map(true);
}

static void
fault_addr(mach_vm_address_t addr)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, vm_fault(map, addr, VM_PROT_READ, false, VM_KERN_MEMORY_NONE, 0, NULL, 0), "Faulting");
}

#pragma mark Test vm_kern_allocation_info

T_DECL(test_vm_kern_allocation_info, "Call vm_kern_allocation_info")
{
	kern_return_t kr;
	vm_size_t size, zsize;
	vm_tag_t tag;
	uintptr_t addr = (uintptr_t)entry_start;

	prepare_map();

	/*
	 * vm_kern_allocation_info works on kernel_map always, so point it at our
	 * custom map for testing.
	 */
	kernel_map = map;

	zsize = 1;
	size = 1;
	tag = 1;
	VME_ALIAS_SET(entry, 0xed0u);

	kr = vm_kern_allocation_info(addr, &size, &tag, &zsize);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "Info from start of entry.");
	T_ASSERT_EQ(zsize, (vm_size_t)0, "zsize path not taken.");
	T_ASSERT_EQ((vm_map_address_t)size, entry_end - entry_start, "size correctly computed.");
	T_ASSERT_EQ(tag, 0xed0u, "tag correctly retrieved.");

	kr = vm_kern_allocation_info(addr + PAGE_SIZE, &size, &tag, &zsize);
	T_ASSERT_EQ(KERN_INVALID_ADDRESS, kr, "Request in the middle of the entry fails.");

	kr = vm_kern_allocation_info(addr - PAGE_SIZE, &size, &tag, &zsize);
	T_ASSERT_EQ(KERN_INVALID_ADDRESS, kr, "Request on empty range fails.");


	T_LOG("Update map bounds to test NO_MIN_MAX_CHECK behavior.");
	const vm_map_address_t map_start = entry2_start, map_end = map->max_offset;
	map->min_offset = map_start;
	map->max_offset = map_end;

	kr = vm_kern_allocation_info(addr, &size, &tag, &zsize);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "Request succeeds on entry outside of map.");
	T_ASSERT_EQ(zsize, (vm_size_t)0, "zsize path not taken.");
	T_ASSERT_EQ((vm_map_address_t)size, entry_end - entry_start, "size correctly computed.");
	T_ASSERT_EQ(tag, 0xed0u, "tag correctly retrieved.");
}

#pragma mark Test move_pages_to_queue

extern kern_return_t
move_pages_to_queue(
	vm_map_t map,
	user_addr_t start_addr,
	size_t buffer_size,
	vm_page_queue_head_t *queue,
	size_t *pages_moved);

T_DECL(test_move_pages_to_queue, "Call move_pages_to_queue")
{
	kern_return_t kr;
	vm_page_queue_head_t page_queue VM_PAGE_PACKED_ALIGNED;
	size_t moved;

	prepare_map();

	vm_page_queue_init(&page_queue);

	kr = move_pages_to_queue(map, entry_start, entry_end - entry_start, &page_queue, &moved);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "Simple request succeeds.");
	T_ASSERT_EQ((size_t)0, moved, "No pages populated, nothing happens.");

	fault_addr(entry_start);
	kr = move_pages_to_queue(map, entry_start, entry_end - entry_start, &page_queue, &moved);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "Simple request succeeds.");
	T_ASSERT_EQ((size_t)1, moved, "Faulted page populated.");

	kr = move_pages_to_queue(map, entry_start - PAGE_SIZE, PAGE_SIZE, &page_queue, &moved);
	T_ASSERT_EQ(KERN_INVALID_ADDRESS, kr, "Error on address with no entry.");

	entry->wired_count = 1;
	kr = move_pages_to_queue(map, entry_start, entry_end - entry_start, &page_queue, &moved);
	T_ASSERT_EQ(KERN_INVALID_ARGUMENT, kr, "Error on wired entry.");
}

#pragma mark Test fill_procregioninfo_onlymappedvnodes

T_DECL(test_fill_procregioninfo_onlymappedvnodes, "Call fill_procregioninfo_onlymappedvnodes")
{
	int ret;
	struct proc_regioninfo_internal pinfo;
	uintptr_t vnodeaddr;
	uint32_t vid;
	const task_t task = fake_alloc_init_task_and_proc();

	prepare_map();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "Map references are as expected.");

	task->map = map;

	// Return failure on all entries. Don't expect a call on parent_entry because it's a submap.
	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 0 });
	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry2, 0 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)entry_start, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(0, ret, "Simple call fails because objects have no associated vnode.");
	assert_empty_fill_vnodeinfo_call();

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)entry_start, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "Simple call succeeds.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vnodeaddr, "vnodeaddr matches expectations.");
	T_ASSERT_EQ(entry_start, pinfo.pri_address, "pri_address matches expectations.");
	T_ASSERT_EQ(entry_end - entry_start, pinfo.pri_size, "pri_size matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)entry_start + PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "Call in the middle of the entry succeeds.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vnodeaddr, "vnodeaddr matches expectations.");
	T_ASSERT_EQ(entry_start, pinfo.pri_address, "pri_address matches expectations.");
	T_ASSERT_EQ(entry_end - entry_start, pinfo.pri_size, "pri_size matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)entry_start - PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "Call before entry succeeds and goes to next entry.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vnodeaddr, "vnodeaddr matches expectations.");
	T_ASSERT_EQ(entry_start, pinfo.pri_address, "pri_address matches expectations.");
	T_ASSERT_EQ(entry_end - entry_start, pinfo.pri_size, "pri_size matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)submap_end + PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(0, ret, "Call after last entry fails.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)submap_start, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(0, ret, "Call on submap fails.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	T_LOG("Update map bounds to test NO_MIN_MAX_CHECK behavior.");
	const vm_map_address_t map_start = entry2_start, map_end = 0xffffffff00000;
	map->min_offset = map_start;
	map->max_offset = map_end;

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry2, 1 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)map_start - PAGE_SIZE, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "Starting before the map->min_offset is ok.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)entry_start, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "Can find entries that are before the map->min_offset.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	vm_map_entry_t entry3 = prepare_entry(map, map_end, map_end + PAGE_SIZE);

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry3, 1 });
	ret = fill_procregioninfo_onlymappedvnodes(task, (uint64_t)map_end, &pinfo, &vnodeaddr, &vid);
	T_ASSERT_EQ(1, ret, "Can find entries that are after the map->max_offset.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");
}

#pragma mark Test task_find_region_details

extern int
task_find_region_details(
	task_t task,
	vm_map_offset_t offset,
	find_region_details_options_t options,
	uintptr_t *vp_p,
	uint32_t *vid_p,
	bool *is_map_shared_p,
	uint64_t *start_p,
	uint64_t *len_p);
T_DECL(test_task_find_region_details, "Call task_find_region_details")
{
	int ret;
	uintptr_t vp;
	uint32_t vid;
	bool is_map_shared;
	uint64_t start;
	uint64_t len;
	const task_t task = fake_alloc_init_task_and_proc();

	prepare_map();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "Map references are as expected.");

	task->map = map;

	// FIND_REGION_DETAILS_AT_OFFSET | FIND_REGION_DETAILS_GET_VNODE

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 0 });
	ret = task_find_region_details(task, (vm_map_offset_t)entry_start,
	    FIND_REGION_DETAILS_AT_OFFSET | FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(0, ret, "Simple call fails because object has no pager.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)entry_start,
	    FIND_REGION_DETAILS_AT_OFFSET | FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Simple call succeeds.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vp, "vp matches expectations.");
	T_ASSERT_EQ(entry_start, start, "start matches expectations.");
	T_ASSERT_EQ(entry_end - entry_start, len, "len matches expectations.");
	T_ASSERT_EQ(true, is_map_shared, "is_map_shared matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)entry_start + PAGE_SIZE,
	    FIND_REGION_DETAILS_AT_OFFSET | FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Call in the middle of the entry succeeds.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vp, "vnodeaddr matches expectations.");
	T_ASSERT_EQ(entry_start, start, "start matches expectations.");
	T_ASSERT_EQ(entry_end - entry_start, len, "len matches expectations.");
	T_ASSERT_EQ(true, is_map_shared, "is_map_shared matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	ret = task_find_region_details(task, (vm_map_offset_t)entry_start - PAGE_SIZE,
	    FIND_REGION_DETAILS_AT_OFFSET | FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(0, ret, "Call on empty region fails.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	ret = task_find_region_details(task, (vm_map_offset_t)submap_start,
	    FIND_REGION_DETAILS_AT_OFFSET | FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(0, ret, "Call on submap fails.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	// FIND_REGION_DETAILS_GET_VNODE

	ret = task_find_region_details(task, (vm_map_offset_t)submap_start,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(0, ret, "Call on submap fails.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)entry_start - PAGE_SIZE,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Call before first entry finds the first entry and succeeds.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vp, "vnodeaddr matches expectations.");
	T_ASSERT_EQ(entry_start, start, "start matches expectations.");
	T_ASSERT_EQ(entry_end - entry_start, len, "len matches expectations.");
	T_ASSERT_EQ(true, is_map_shared, "is_map_shared matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	ret = task_find_region_details(task, (vm_map_offset_t)submap_end + PAGE_SIZE,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(0, ret, "Call on empty region at the end fails.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	vm_map_entry_t e = prepare_entry(map, submap_end, submap_end + PAGE_SIZE);

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ e, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)submap_start,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Call on submap looks for next entry, finds one and succeeds.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(mock_vnode_id, vid, "vid matches expectations.");
	T_ASSERT_EQ(mock_vnode_addr, vp, "vnodeaddr matches expectations.");
	T_ASSERT_EQ(submap_end, start, "start matches expectations.");
	T_ASSERT_EQ((uint64_t)PAGE_SIZE, len, "len matches expectations.");
	T_ASSERT_EQ(true, is_map_shared, "is_map_shared matches expectations.");
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	T_LOG("Update map bounds to test NO_MIN_MAX_CHECK behavior.");
	const vm_map_address_t map_start = entry2_start, map_end = 0xffffffff00000;
	map->min_offset = map_start;
	map->max_offset = map_end;

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry2, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)map_start - PAGE_SIZE,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Starting before the map->min_offset is ok.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)entry_start,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Can find entries that are before the map->min_offset.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");

	vm_map_entry_t entry3 = prepare_entry(map, map_end, map_end + PAGE_SIZE);

	enqueue_fill_vnodeinfo_call((fill_vnodeinfo_call){ entry3, 1 });
	ret = task_find_region_details(task, (vm_map_offset_t)map_end,
	    FIND_REGION_DETAILS_GET_VNODE,
	    &vp, &vid, &is_map_shared, &start, &len);
	T_ASSERT_EQ(1, ret, "Can find entries that are after the map->max_offset.");
	assert_empty_fill_vnodeinfo_call();
	T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "No map leak");
}

#pragma mark Test find_mapping_to_slide

extern kern_return_t
find_mapping_to_slide(vm_map_t map, vm_map_address_t addr, vm_map_entry_t entry);

void
find_mapping_to_slide_test(bool sealed)
{
	kern_return_t kr;
	vm_object_t object;
	struct vm_map_entry found = { 0 };

	prepare_map(sealed);

	object = VME_OBJECT(child_entry);
	T_ASSERT_EQ(1, object->ref_count, "Check initial ref count.");

	kr = find_mapping_to_slide(submap, child_entry_start, &found);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "Simple request succeeds.");
	T_ASSERT_EQ(child_entry->vme_start, found.vme_start, "Entry start is as expected.");
	T_ASSERT_EQ(child_entry->vme_end, found.vme_end, "Entry end is as expected.");
	T_ASSERT_EQ(2, object->ref_count, "Function added one ref.");
	vm_object_deallocate(object); // clear ref
	memset(&found, 0, sizeof(found)); // clear result

	kr = find_mapping_to_slide(submap, child_entry_start + PAGE_SIZE, &found);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "Request in middle of entry succeeds.");
	T_ASSERT_EQ(child_entry->vme_start, found.vme_start, "Entry start is as expected.");
	T_ASSERT_EQ(child_entry->vme_end, found.vme_end, "Entry end is as expected.");
	T_ASSERT_EQ(2, object->ref_count, "Function added one ref.");
	vm_object_deallocate(object); // clear ref

	kr = find_mapping_to_slide(submap, child_entry_start - PAGE_SIZE, &found);
	T_ASSERT_EQ(KERN_INVALID_ADDRESS, kr, "Request on addr with no entry fails.");
	T_ASSERT_EQ(1, object->ref_count, "No ref added on failure.");
}

T_DECL(test_find_mapping_to_slide, "Call find_mapping_to_slide")
{
	find_mapping_to_slide_test(false);
	find_mapping_to_slide_test(true);
}

#pragma mark Test task_info

T_DECL(test_task_vm_info, "Call task_info with TASK_VM_INFO/TASK_VM_INFO_PURGEABLE")
{
	kern_return_t kr;
	task_vm_info_data_t info;
	vm_object_t object;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	const task_t task = fake_alloc_init_task_and_proc();

	prepare_map();
	init_task_ledgers();

	task->map = map;
	object = VME_OBJECT(entry);
	object->purgable = VM_PURGABLE_VOLATILE;
	object->resident_page_count = 13;

	kr = task_info(task, TASK_VM_INFO, (task_info_t)&info, &count);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "TASK_VM_INFO request succeeds.");
	T_ASSERT_EQ(TASK_VM_INFO_COUNT, count, "Unchanged count.");
	T_ASSERT_EQ(3, info.region_count, "Excepted entry count.");
	T_ASSERT_EQ(0ULL, info.purgeable_volatile_pmap, "Expected purgeable volatile bytes.");
	T_ASSERT_EQ(0ULL, info.purgeable_volatile_resident, "Expected purgeable volatile resident bytes.");
	T_ASSERT_EQ(0ULL, info.purgeable_volatile_virtual, "Expected purgeable volatile virtual bytes.");

	kr = task_info(task, TASK_VM_INFO_PURGEABLE, (task_info_t)&info, &count);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "TASK_VM_INFO_PURGEABLE request succeeds.");
	T_ASSERT_EQ(TASK_VM_INFO_COUNT, count, "Unchanged count.");
	T_ASSERT_EQ(3, info.region_count, "Excepted entry count.");
	T_ASSERT_EQ(entry_end - entry_start, info.purgeable_volatile_pmap, "Expected purgeable volatile bytes.");
	T_ASSERT_EQ((mach_vm_size_t)13 * PAGE_SIZE, info.purgeable_volatile_resident, "Expected purgeable volatile resident bytes.");
	T_ASSERT_EQ(entry_end - entry_start, info.purgeable_volatile_virtual, "Expected purgeable volatile virtual bytes.");

	T_LOG("Update map bounds to test NO_MIN_MAX_CHECK behavior.");
	const vm_map_address_t map_start = entry2_start, map_end = map->max_offset;
	map->min_offset = map_start;
	map->max_offset = map_end;

	kr = task_info(task, TASK_VM_INFO, (task_info_t)&info, &count);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "TASK_VM_INFO request succeeds.");
	T_ASSERT_EQ(TASK_VM_INFO_COUNT, count, "Unchanged count.");
	T_ASSERT_EQ(3, info.region_count, "Excepted entry count.");
	T_ASSERT_EQ(0ULL, info.purgeable_volatile_pmap, "Expected purgeable volatile bytes.");
	T_ASSERT_EQ(0ULL, info.purgeable_volatile_resident, "Expected purgeable volatile resident bytes.");
	T_ASSERT_EQ(0ULL, info.purgeable_volatile_virtual, "Expected purgeable volatile virtual bytes.");

	kr = task_info(task, TASK_VM_INFO_PURGEABLE, (task_info_t)&info, &count);
	T_ASSERT_EQ(KERN_SUCCESS, kr, "TASK_VM_INFO_PURGEABLE request succeeds.");
	T_ASSERT_EQ(TASK_VM_INFO_COUNT, count, "Unchanged count.");
	T_ASSERT_EQ(3, info.region_count, "Excepted entry count.");
	T_ASSERT_EQ(entry_end - entry_start, info.purgeable_volatile_pmap, "Expected purgeable volatile bytes.");
	T_ASSERT_EQ((mach_vm_size_t)13 * PAGE_SIZE, info.purgeable_volatile_resident, "Expected purgeable volatile resident bytes.");
	T_ASSERT_EQ(entry_end - entry_start, info.purgeable_volatile_virtual, "Expected purgeable volatile virtual bytes.");
}

#pragma mark Test mach_make_memory_entry_share

extern kern_return_t
mach_make_memory_entry_share(
	vm_map_t                      target_map,
	memory_object_size_t         *size_u,
	vm_map_offset_t               offset_u,
	vm_prot_t                     permission,
	vm_named_entry_kernel_flags_t vmne_kflags,
	ipc_port_t                    *object_handle,
	ipc_port_t                    parent_handle,
	vm_named_entry_t              parent_entry);

static void
test_mach_make_memory_entry_share_helper(
	/* Params for function under test. */
	vm_map_offset_t addr,
	memory_object_size_t size,
	vm_prot_t prot,
	/* Return expectations. */
	kern_return_t ex_kr,
	memory_object_size_t ex_size,
	/* Named entry expectations. */
	vm_prot_t ex_prot,
	bool ex_is_object,
	bool ex_internal,
	bool ex_is_copy,
	/* Copy entry expectations. */
	uint32_t ex_entry_count,
	vm_prot_t ex_copy_prot,
	vm_prot_t ex_copy_max_prot,
	bool ex_needs_copy,
	bool ex_is_shared,
	/* Object expectations. */
	uint32_t ex_shadow_chain_length,
	vm_object_t ex_shadow_chain_bottom,
	uint32_t ex_ref_count,
	memory_object_copy_strategy_t ex_copy_strategy,
	bool ex_shadowed,
	bool ex_true_share)
{
	kern_return_t kr;
	vm_named_entry_kernel_flags_t flags;
	ipc_port_t handle;
	vm_named_entry_t named_entry;
	memory_object_size_t sz = size;
	vm_map_copy_t copy;
	vm_map_entry_t copy_entry;
	vm_object_t object;

	kr = mach_make_memory_entry_share(map, &sz, addr, prot, flags, &handle, NULL, NULL);

	/* Check return expectations. */
	T_QUIET; T_ASSERT_EQ(ex_kr, kr, "mach_make_memory_entry_share returns as expected.");
	if (kr == KERN_SUCCESS) {
		T_QUIET; T_ASSERT_EQ(ex_size, sz, "Out size is as expected.");

		/* Check named entry expectations. */
		named_entry = ipc_kobject_get_raw(handle, IKOT_NAMED_ENTRY);
		T_QUIET; T_ASSERT_NE(NULL, named_entry, "Got non-null entry.");
		T_QUIET; T_ASSERT_EQ((vm_object_offset_t)0, named_entry->offset, "Offset is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_size, named_entry->size, "Size is as expected.");
		T_QUIET; T_ASSERT_EQ((vm_object_offset_t)0, named_entry->data_offset, "Data offset is as expected.");
		T_QUIET; T_ASSERT_EQ(0, (unsigned int)named_entry->access, "Access is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_prot, (vm_prot_t)named_entry->protection, "Protection is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_is_object, (bool)named_entry->is_object, "is_object is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_internal, (bool)named_entry->internal, "internal is as expected.");
		T_QUIET; T_ASSERT_EQ(false, (bool)named_entry->is_sub_map, "is_sub_map is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_is_copy, (bool)named_entry->is_copy, "is_copy is as expected.");
		T_QUIET; T_ASSERT_EQ(false, (bool)named_entry->is_fully_owned, "is_fully_owned is as expected.");

		/* Check copy entry expectations. */
		copy = named_entry->backing.copy;
		T_QUIET; T_ASSERT_NE(NULL, copy, "Got non-null copy.");
		copy_entry = vm_map_copy_first_entry(copy);
		T_QUIET; T_ASSERT_NE(NULL, copy_entry, "Got non-null entry.");
		T_QUIET; T_ASSERT_NE_PTR(vm_map_copy_to_entry(copy), copy_entry, "Got valid entry.");
		T_QUIET; T_ASSERT_EQ((vm_map_offset_t)0, copy_entry->vme_start, "Entry start is as expected.");
		assert3u(ex_entry_count, !=, 0);
		for (uint32_t i = 0; i < ex_entry_count; i++) {
			if (i == ex_entry_count - 1) {
				T_QUIET; T_ASSERT_EQ_PTR(vm_map_copy_to_entry(copy), copy_entry->vme_next, "Got last entry.");
				T_QUIET; T_ASSERT_EQ(ex_size, copy_entry->vme_end, "Entry end is as expected.");
			} else {
				T_QUIET; T_ASSERT_NE_PTR(vm_map_copy_to_entry(copy), copy_entry->vme_next, "Entry has next.");
			}
			T_QUIET; T_ASSERT_EQ(ex_copy_prot, (vm_prot_t)copy_entry->protection, "Entry prot is as expected.");
			T_QUIET; T_ASSERT_EQ(ex_copy_max_prot, (vm_prot_t)copy_entry->max_protection, "Entry max prot is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->is_sub_map, "Submapness is as expected.");
			T_QUIET; T_ASSERT_EQ(ex_needs_copy, (bool)copy_entry->needs_copy, "Needs copy is as expected.");
			T_QUIET; T_ASSERT_EQ(VM_INHERIT_SHARE, (vm_inherit_t)copy_entry->inheritance, "Inheritance is as expected.");
			T_QUIET; T_ASSERT_EQ(VM_BEHAVIOR_DEFAULT, (vm_behavior_t)copy_entry->behavior, "Behavior is as expected.");
			T_QUIET; T_ASSERT_EQ(ex_is_shared, (bool)copy_entry->is_shared, "Sharedness is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->used_for_tpro, "TPRO is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->used_for_jit, "JIT is as expected.");
			T_QUIET; T_ASSERT_EQ(true, (bool)copy_entry->use_pmap, "pmap use is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->no_cache, "Cache use is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->vme_permanent, "Permanence is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->superpage_size, "Superpage use is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->zero_wired_pages, "Wired page zero'ing is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->csm_associated, "CSM association is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->iokit_acct, "IOKit accounting use is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->vme_resilient_codesign, "Codesigning resilient bit is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->vme_resilient_media, "Resilient media bit is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->vme_xnu_user_debug, "User debug bit is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->vme_no_copy_on_read, "No CoR bit is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->translated_allow_execute, "Translated allow execute bit is as expected.");
			T_QUIET; T_ASSERT_EQ(false, (bool)copy_entry->vme_kernel_object, "Kernel object status is as expected.");
			T_QUIET; T_ASSERT_EQ(0, (unsigned short)copy_entry->wired_count, "Kernel wire count is as expected.");
			T_QUIET; T_ASSERT_EQ(0, (unsigned short)copy_entry->user_wired_count, "User wire count is as expected.");

			copy_entry = copy_entry->vme_next;
		}
		/* Check object expectations. */
		copy_entry = vm_map_copy_first_entry(copy); /* Only check for the first object in the copy. */
		object = VME_OBJECT(copy_entry);
		T_QUIET; T_ASSERT_NOTNULL(object, "Got non-null object."); // We always expect a non-NULL object.
		vm_object_t iter = object;
		for (int i = 0; i < ex_shadow_chain_length; i++) {
			T_QUIET; T_ASSERT_NOTNULL(iter, "Iterator isn't NULL.");
			T_QUIET; T_ASSERT_NOTNULL(iter->shadow, "Iterator has shadow.");
			iter = iter->shadow;
		}
		T_QUIET; T_ASSERT_EQ_PTR(iter, ex_shadow_chain_bottom, "Got expected object at bottom of chain.");
		T_QUIET; T_ASSERT_NULL(iter->shadow, "Expected null shadow at the bottom of chain");

		T_QUIET; T_ASSERT_EQ(ex_ref_count, object->ref_count, "Ref count is as expected.");
		T_QUIET; T_ASSERT_EQ(0, object->resident_page_count, "Resident page count is as expected.");
		T_QUIET; T_ASSERT_EQ(NULL, object->vo_copy, "No vo_copy.");
		T_QUIET; T_ASSERT_EQ(NULL, object->pager, "No pager.");
		T_QUIET; T_ASSERT_EQ(ex_copy_strategy, object->copy_strategy, "Copy strategy is as expected.");
		T_QUIET; T_ASSERT_EQ(true, (bool)object->internal, "Internal is as expected.");
		T_QUIET; T_ASSERT_EQ(false, (bool)object->private, "Private is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_shadowed, (bool)object->shadowed, "Shadowed is as expected.");
		T_QUIET; T_ASSERT_EQ(ex_true_share, (bool)object->true_share, "True share is as expected.");
		T_QUIET; T_ASSERT_EQ(false, (bool)object->named, "Named is as expected.");
	}
}

typedef struct {
	vm_prot_t prot;
	char *name;
} printable_prot;

#define PPROT(p) {.prot = p, #p}

static void
test_mach_make_memory_entry_share_for_prots(
	vm_map_entry_t *parent_p,
	vm_map_entry_t *child_p,
	bool set_read_only,
	bool set_needs_copy)
{
	vm_map_offset_t addr;
	memory_object_size_t size;
	bool is_submap;
	memory_object_size_t ex_size;
	vm_map_entry_t parent, child;
	vm_prot_t parent_entry_prot;
	vm_prot_t parent_entry_max_prot;
	vm_prot_t child_entry_prot;
	vm_prot_t child_entry_max_prot;

	printable_prot base_prots[] = {
		PPROT(VM_PROT_NONE),
		PPROT(VM_PROT_READ),
		PPROT(VM_PROT_READ | VM_PROT_WRITE),
	};
	printable_prot mask_prots[] = {
		PPROT(0),
		PPROT(VM_PROT_IS_MASK),
	};
	printable_prot map_mem_prots[] = {
		PPROT(0),
		PPROT(MAP_MEM_NAMED_REUSE),
		PPROT(MAP_MEM_VM_SHARE),
	};

	for (int i = 0; i < countof(base_prots); i++) {
		for (int j = 0; j < countof(mask_prots); j++) {
			for (int k = 0; k < countof(map_mem_prots); k++) {
				/* Reset the map to avoid interference from previous tests. */
				prepare_map();

				parent = *parent_p;

				is_submap = (parent->is_sub_map);
				if (is_submap) {
					assert(child_p != NULL);
					child = *child_p;
				} else {
					child = parent;
				}

				/* Adjust entry as requested. */
				if (set_read_only) {
					parent->protection = VM_PROT_READ;
					parent->max_protection = VM_PROT_READ;
				}
				if (set_needs_copy) {
					parent->needs_copy = true;
				}

				/* Prepare params to pass to function. */
				addr = parent->vme_start;
				size = parent->vme_end - parent->vme_start;

				printable_prot base = base_prots[i];
				printable_prot mask = mask_prots[j];
				printable_prot map_mem = map_mem_prots[k];
				vm_prot_t prot = base.prot | mask.prot | map_mem.prot;

				T_LOG("Testing at 0x%llx (size 0x%llx) %s%s%swith (%s | %s | %s).",
				    addr, size,
				    is_submap ? "(submap) " : "",
				    set_read_only ? "(ro) " : "",
				    set_needs_copy ? "(nc) " : "",
				    base.name, mask.name, map_mem.name);

				/* Build prot expectations on existing map. */
				parent_entry_prot = VM_PROT_DEFAULT;
				parent_entry_max_prot = is_submap ? VM_PROT_DEFAULT : VM_PROT_ALL;
				child_entry_prot = VM_PROT_DEFAULT;
				child_entry_max_prot = VM_PROT_ALL;
				if (set_read_only) {
					parent_entry_prot = VM_PROT_READ;
					parent_entry_max_prot = VM_PROT_READ;
					if (!is_submap) {
						child_entry_prot = VM_PROT_READ;
						child_entry_max_prot = VM_PROT_READ;
					}
				}
				T_QUIET; T_ASSERT_EQ((vm_prot_t)parent->protection, parent_entry_prot, "Input protection is as expected");
				T_QUIET; T_ASSERT_EQ((vm_prot_t)parent->max_protection, parent_entry_max_prot, "Input max protection is as expected");
				T_QUIET; T_ASSERT_EQ((vm_prot_t)child->protection, child_entry_prot, "Child input protection is as expected");
				T_QUIET; T_ASSERT_EQ((vm_prot_t)child->max_protection, child_entry_max_prot, "Child input max protection is as expected");

				/* Build return expectations. */
				kern_return_t ex_kr = KERN_SUCCESS;
				if ((base.prot == VM_PROT_NONE) && (prot & VM_PROT_IS_MASK)) {
					ex_kr = KERN_PROTECTION_FAILURE;
				}
				if (((base.prot & child_entry_prot) != base.prot) && !(prot & VM_PROT_IS_MASK)) {
					ex_kr = KERN_PROTECTION_FAILURE;
				}
				ex_size = child->vme_end - child->vme_start;
				if (is_submap && (prot & MAP_MEM_VM_SHARE)) {
					ex_size = parent->vme_end - parent->vme_start;
				}

				/* Build named entry expectations */
				vm_prot_t ex_prot = base.prot;
				bool ex_is_object = !(prot & MAP_MEM_VM_SHARE);
				bool ex_internal = !(prot & MAP_MEM_VM_SHARE);
				bool ex_is_copy = prot & MAP_MEM_VM_SHARE;

				if (prot & VM_PROT_IS_MASK) {
					ex_prot &= child_entry_prot;
				}

				T_QUIET; T_ASSERT_TRUE(ex_is_object ^ ex_is_copy, "Check consistency of expectations.");

				/* Build copy entry expectations */
				uint32_t ex_entry_count = 1;
				vm_prot_t ex_copy_prot = (prot & VM_PROT_IS_MASK) ? child_entry_prot : base.prot;
				vm_prot_t ex_copy_max_prot = (prot & VM_PROT_IS_MASK) ? child_entry_max_prot : base.prot;
				bool ex_needs_copy = false;

				if (is_submap && (prot & MAP_MEM_VM_SHARE)) {
					ex_entry_count = 2;
				}

				bool ex_is_shared = true;
				if (is_submap && set_needs_copy) {
					ex_is_shared = (prot & VM_PROT_WRITE) && (!(prot & MAP_MEM_VM_SHARE));
				}

				/* Build object expectations */
				uint32_t ex_shadow_chain_length = 0;
				vm_object_t ex_shadow_chain_bottom = VME_OBJECT(child);
				uint32_t ex_ref_count = 2;
				memory_object_copy_strategy_t ex_copy_strategy = MEMORY_OBJECT_COPY_DELAY;
				bool ex_shadowed = false;
				bool ex_true_share = !is_submap || set_needs_copy;

				if (is_submap && set_needs_copy) {
					ex_shadow_chain_length += 2;
					if (!(prot & VM_PROT_WRITE) || (prot & MAP_MEM_VM_SHARE)) {
						ex_ref_count = 1;
					}
				}

				test_mach_make_memory_entry_share_helper(
					addr, size, prot, /* Params for function under test. */
					ex_kr, ex_size, /* Return expectations. */
					ex_prot, ex_is_object, ex_internal, ex_is_copy, /* Named entry expectations. */
					ex_entry_count, ex_copy_prot, ex_copy_max_prot, ex_needs_copy, ex_is_shared, /* Copy entry expectations. */
					ex_shadow_chain_length, ex_shadow_chain_bottom, ex_ref_count, ex_copy_strategy, ex_shadowed, ex_true_share); /* Object expectations. */
			}
		}
	}
}

T_DECL(test_mach_make_memory_entry_share, "Call mach_make_memory_entry_share")
{
	test_mach_make_memory_entry_share_for_prots(
		&entry,
		NULL,
		false,
		false);
	test_mach_make_memory_entry_share_for_prots(
		&entry,
		NULL,
		false,
		true);
	test_mach_make_memory_entry_share_for_prots(
		&entry,
		NULL,
		true,
		false);

	test_mach_make_memory_entry_share_for_prots(
		&entry2,
		NULL,
		false,
		false);
	test_mach_make_memory_entry_share_for_prots(
		&entry2,
		NULL,
		false,
		true);
	test_mach_make_memory_entry_share_for_prots(
		&entry2,
		NULL,
		true,
		false);

	test_mach_make_memory_entry_share_for_prots(
		&parent_entry,
		&child_entry,
		false,
		false);
	test_mach_make_memory_entry_share_for_prots(
		&parent_entry,
		&child_entry,
		false,
		true);
	test_mach_make_memory_entry_share_for_prots(
		&parent_entry,
		&child_entry,
		true,
		false);
	T_PASS("All mach_make_memory_entry_share tests pass.");
}

#pragma mark Test vm_task_evict_shared_cache

T_MOCK_CALL_QUEUE(obj_sync, {
	vm_object_t object;
});

static void
enqueue_sync_call(vm_object_t obj)
{
	enqueue_obj_sync((obj_sync){
		.object = obj,
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

	T_QUIET; T_ASSERT_EQ_PTR(object, call.object, "unexpected object");
	T_QUIET; T_ASSERT_EQ(offset, 0ULL, "unexpected offset");
	T_QUIET; T_ASSERT_EQ(size, child_entry_end - child_entry_start, "unexpected size");
	T_QUIET; T_ASSERT_EQ(should_flush, true, "unexpected should_flush");
	T_QUIET; T_ASSERT_EQ(should_return, false, "unexpected should_return");
	T_QUIET; T_ASSERT_EQ(should_iosync, false, "unexpected should_iosync");

	return true;
}

T_DECL(test_vm_task_evict_shared_cache, "Call vm_task_evict_shared_cache")
{
	kern_return_t kr;
	uint64_t ret;
	const task_t task = fake_alloc_init_task_and_proc();

	*(task->pageins) = 0xed0ull;

	/* Empty map */
	task->map = create_map();

	ret = vm_task_evict_shared_cache(task);

	T_ASSERT_EQ(0xed0ull, ret, "Return value is as expected.");

	prepare_map();
	task->map = map; /* Switch to default map. */

	/* Default map has no rx entries in submaps. */
	ret = vm_task_evict_shared_cache(task);

	T_ASSERT_EQ(0xed0ull, ret, "Return value is as expected.");

	/* Make one entry interesting. */
	child_entry->protection = VM_PROT_READ | VM_PROT_EXECUTE;

	enqueue_sync_call(VME_OBJECT(child_entry));
	ret = vm_task_evict_shared_cache(task);
	assert_empty_obj_sync();

	T_ASSERT_EQ(0xed0ull, ret, "Return value is as expected.");

	/* Force code to take the shadow chain walk path. */
	prepare_map(false); /* don't seal the submap yet so we can shadow the child entry */
	task->map = map;
	child_entry->protection = VM_PROT_READ | VM_PROT_EXECUTE;

	vm_object_t orig_obj = VME_OBJECT(child_entry);
	vm_map_ilk_lock(map);
	kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
	    child_entry, child_entry_start, THREAD_UNINT);
	assert3u(kr, ==, KERN_SUCCESS);
	orig_obj->copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC;
	orig_obj->shadowed = true;
	VME_OBJECT_SHADOW(child_entry, PAGE_SIZE, true);
	vm_entry_unlock_exclusive(map, child_entry);
	vm_map_ilk_unlock(map);

	vm_map_seal(submap, true);

	enqueue_sync_call(orig_obj);
	ret = vm_task_evict_shared_cache(task);
	assert_empty_obj_sync();

	T_ASSERT_EQ(0xed0ull, ret, "Return value is as expected.");
}

#pragma mark Test get_vmmap_entries

T_DECL(test_get_vmmap_entries, "Call get_vmmap_entries")
{
	kern_return_t kr;
	int count;

	vm_map_t empty_map = create_map();

	T_ASSERT_EQ(0, get_vmmap_entries(empty_map), "Empty map has 0 entries.");

	prepare_map();

	T_ASSERT_EQ(4, get_vmmap_entries(map), "Correctly counted entries in map.");

	VME_OFFSET_SET(parent_entry, child_entry_end);
	parent_entry->vme_end -= child_entry_end;
	T_ASSERT_EQ(3, get_vmmap_entries(map), "Correctly ignored entries in submap out of view.");
}

#pragma mark Test fill_procregioninfo
