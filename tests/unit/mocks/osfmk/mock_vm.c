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

#include "mocks/std_safe.h"
#include "mocks/dt_proxy.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mock_vm.h"
#include "mocks/mock_mem.h"

#include <vm/vm_page_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_map_xnu.h>
#include <mach/dyld_pager.h>
#include <vm/vm_kern_xnu.h>

T_MOCK(
	vm_page_t,
	vm_page_find_canonical,
	(ppnum_t pnum),
	(pnum));

vm_page_t vm_page_grab_finalize(vm_grab_options_t grab_options, vm_page_t mem);

T_MOCK_F(vm_page_t,
vm_page_grab_options,
(vm_grab_options_t grab_options),
(grab_options)) {
	vm_page_t ret = aligned_alloc(64, 64);
	leakchecker_add_allocation(ret, 64);
	static_assert(sizeof(struct vm_page) <= 64, "struct vm_page is too large");

	assert(ret != VM_PAGE_NULL);
	memset(ret, 0, 64);
	ret->vmp_busy = TRUE;

	return vm_page_grab_finalize(grab_options, ret);
}

T_MOCK(kern_return_t,
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
	bool *page_needs_data_sync), (
	m, pmap, vaddr, prot, caller_prot, fault_page_size, fault_phys_offset, fault_type, fault_info, type_of_fault, page_needs_data_sync));

T_MOCK_F(void,
vm_page_zero_fill, (vm_page_t m), (m))
{
	return;
}

T_MOCK(kern_return_t,
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
	int pmap_options), (
	pmap, vaddr, fault_page_size, fault_phys_offset,
	m, prot, caller_prot, fault_type, wired, pmap_options));

T_MOCK(boolean_t,
vm_object_sync, (
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	boolean_t               should_flush,
	boolean_t               should_return,
	boolean_t               should_iosync),
(object, offset, size, should_flush, should_return, should_iosync))

T_MOCK_F(mach_vm_size_t,
pmap_query_resident_internal, (
	pmap_t                  pmap,
	vm_map_address_t        start,
	vm_map_address_t        end,
	mach_vm_size_t          *compressed_bytes_p), (pmap, start, end, compressed_bytes_p))
{
	*compressed_bytes_p = PAGE_SIZE;
	return end - start;
}

T_MOCK_F(void,
vm_page_copy, (
	vm_page_t       src_m,
	vm_page_t       dest_m), (src_m, dest_m))
{
}

T_MOCK(void,
vm_page_wakeup_done, (
	vm_object_t object, vm_page_t m),
(object, m));

T_MOCK(
	kern_return_t,
	cpm_allocate, (
		vm_size_t       size,
		vm_page_t       * list,
		ppnum_t         max_pnum,
		ppnum_t         pnum_mask,
		boolean_t       wire,
		int             flags),
	(size, list, max_pnum, pnum_mask, wire, flags));

T_MOCK(
	void,
	vm_fault_unwire, (
		vm_map_t                map,
		vm_map_entry_t          entry,
		bool                    deallocate,
		pmap_t                  pmap,
		vm_map_offset_t         pmap_addr,
		vm_map_offset_t         end_addr),
	(map, entry, deallocate, pmap, pmap_addr, end_addr));

T_MOCK(
	kern_return_t,
	vm_map_wire_kernel, (
		vm_map_t                map,
		vm_map_offset_ut        start_u,
		vm_map_offset_ut        end_u,
		vm_prot_ut              prot_u,
		vm_tag_t                tag,
		boolean_t               user_wire),
	(map, start_u, end_u, prot_u, tag, user_wire));

T_MOCK(
	kern_return_t,
	vm_map_entry_cs_associate, (
		vm_map_t                map,
		vm_map_entry_t          entry,
		vm_map_kernel_flags_t   vmk_flags
		),
	(map, entry, vmk_flags));

T_MOCK(
	kern_return_t,
	memory_object_map, (
		memory_object_t memory_object,
		vm_prot_t prot
		),
	(memory_object, prot));

T_MOCK(
	void,
	memory_object_last_unmap,
	(memory_object_t memory_object),
	(memory_object));

T_MOCK(
	kern_return_t,
	vm_superpage_size, (
		unsigned int superpage_size,
		vm_map_size_t * size
		),
	(superpage_size, size));

T_MOCK(
	memory_object_t,
	dyld_pager_setup, (
		task_t            task,
		vm_object_t       backing_object,
		struct mwl_region *regions,
		uint32_t          region_cnt,
		void              *link_info,
		uint32_t          link_info_size),
	(task, backing_object, regions, region_cnt, link_info, link_info_size));

T_MOCK_F(vm_offset_t,
vm_kernel_addrhash_internal, (vm_offset_t addr, uint64_t salt __unused), (addr, salt))
{
	return addr;
}

T_MOCK(
	kern_return_t,
	vm_object_zero, (
		vm_object_t                     object,
		vm_object_offset_t              * cur_offset_p,
		vm_object_offset_t              end_offset),
	(object, cur_offset_p, end_offset));


T_MOCK(
	wait_result_t,
	vm_page_sleep, (
		vm_object_t        object,
		vm_page_t          m,
		wait_interrupt_t   interruptible,
		lck_sleep_action_t action),
	(object, m, interruptible, action));

T_MOCK(kern_return_t,
mach_vm_deallocate_kernel,
(
	vm_map_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
),
(target, address, size));

T_MOCK(kern_return_t,
mach_vm_protect,
(
	vm_map_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection
),
(target_task, address, size, set_maximum, new_protection));

T_MOCK(
	kern_return_t,
	mach_vm_remap_new_kernel,
	(
		vm_map_t                target_map,
		mach_vm_offset_ut      * address,
		mach_vm_size_ut         size,
		mach_vm_offset_ut       mask,
		vm_map_kernel_flags_t   vmk_flags,
		vm_map_t                src_map,
		mach_vm_offset_ut       memory_address,
		boolean_t               copy,
		vm_prot_ut             * cur_protection,
		vm_prot_ut             * max_protection,
		vm_inherit_ut           inheritance
	), (target_map, address, size, mask, vmk_flags, src_map, memory_address, copy, cur_protection,
	max_protection, inheritance));

T_MOCK(
	kern_return_t,
	vm_map_unwire,
	(
		vm_map_t                map,
		vm_map_offset_ut        start_u,
		vm_map_offset_ut        end_u,
		boolean_t               user_wire
	), (map, start_u, end_u, user_wire));

T_MOCK(
	boolean_t,
	vm_object_coalesce,
	(
		vm_object_t                     prev_object,
		vm_object_t                     next_object,
		vm_object_offset_t              prev_offset,
		vm_object_offset_t              next_offset,
		vm_object_size_t                prev_size,
		vm_object_size_t                next_size
	), (prev_object, next_object, prev_offset, next_offset, prev_size, next_size));

T_MOCK(
	uint32_t,
	vmgo_chunk_select_random_slot,
	(
		vm_guard_object_chunk_t chunk
	), (chunk));
