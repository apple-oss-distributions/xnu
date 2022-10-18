/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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
#ifndef __KDP_COMMON_H
#define __KDP_COMMON_H

#ifdef XNU_KERNEL_PRIVATE

#include <kern/task.h>
#include <vm/vm_map.h>

/*
 * Wrapper around memcpy.
 * This copies individual bytes if running in the panic context. Otherwise, this
 * calls the standard memcpy function.
 */
void kdp_memcpy(void *dst, const void *src, size_t len);

/*
 * A version of strlcpy that is safe to run from the panic context. This calls
 * kdp_memcpy() internally, which copies individual bytes if running in the panic context.
 */
size_t kdp_strlcpy(char *dst, const char *src, size_t maxlen);

/*
 * Get the page size from the specified vm map. This correctly handles K16/U4 (Rosetta) and
 * K4/U16 (armv7k) environments.
 */
size_t kdp_vm_map_get_page_size(vm_map_t map, size_t *effective_page_mask);

__options_closed_decl(kdp_fault_result_flags_t, uint32_t, {
	KDP_FAULT_RESULT_PAGED_OUT = 0x1, /* some data was unable to be retrieved */
	KDP_FAULT_RESULT_TRIED_FAULT = 0x2, /* tried to fault in data */
	KDP_FAULT_RESULT_FAULTED_IN = 0x3, /* successfully faulted in data */
});

struct kdp_fault_result {
	kdp_fault_result_flags_t flags;
	uint64_t time_spent_faulting;
};

__options_closed_decl(kdp_fault_flags_t, uint32_t, {
	KDP_FAULT_FLAGS_NONE = 0x0,
	KDP_FAULT_FLAGS_ENABLE_FAULTING = 0x1, /* try faulting if pages are not resident */
});

__options_closed_decl(kdp_traverse_mappings_flags_t, uint32_t, {
	KDP_TRAVERSE_MAPPINGS_FLAGS_NONE = 0x0,
	KDP_TRAVERSE_MAPPINGS_FLAGS_PHYSICAL = 0x1 /* Use physical addresses instead of virtual addresses */
});

typedef int (*kdp_traverse_mappings_callback)(vm_offset_t start, vm_offset_t end, void *context);

/*
 * Traverse mappings in the specified task.
 *
 * - task                      The task
 * - fault_flags               Controls whether to fault in pages that are not resident.
 * - traverse_mappings_flags   Controls whether the callback is called with physical addresses
 * - callback                  The callback is called for each memory region.
 * - context                   Context passed to the callback.
 */
kern_return_t
kdp_traverse_mappings(
	task_t task,
	kdp_fault_flags_t fault_flags,
	kdp_traverse_mappings_flags_t traverse_mappings_flags,
	kdp_traverse_mappings_callback callback,
	void * context);

/*
 * Get dyld information from the specified task
 *
 * - task               The task
 * - fault_flags        Controls whether to fault in pages that are not resident.
 * - dyld_load_address  The dyld load address is stored here.
 * - dyld_uuid          The dyld uuid is stored here.
 * - task_page_size     The task's page size is stored here.
 */
kern_return_t
kdp_task_dyld_info(task_t task, kdp_fault_flags_t fault_flags, uint64_t * dyld_load_address, uuid_t dyld_uuid, size_t * task_page_size);

/*
 * Returns the physical address of the specified map:target address,
 * using the kdp fault path if requested and the page is not resident.
 */
vm_offset_t kdp_find_phys(vm_map_t map, vm_offset_t target_addr, kdp_fault_flags_t fault_flags, struct kdp_fault_result *fault_results);

/*
 * Generic function to find a physical page for the specified map:target_addr.
 */
typedef vm_offset_t (*find_phys_fn_t)(vm_map_t map, vm_offset_t target_addr, kdp_fault_flags_t fault_flags, void * context);

/*
 * Generic copyin from userspace vm map.
 *
 * - map             The vm map to use
 * - uaddr           Userspace VA to copy bytes from
 * - dest            Destination address
 * - size            Number of bytes to copy
 * - fault_flags     Controls whether to fault in pages that are not resident. This is passed to `find_phys_fn`.
 * - find_phys_fn    The function to use to return a physical address given a map and target address.
 *                   If additional filtering/handling is not required, use `(find_phys_fn_t)kdp_find_phys`
 *                   for this parameter.
 * - context         Reference context passed to find_phys_fn
 *
 * Copies in `size` bytes from `map:uaddr` to `dest`, using the specified function to find a physical address.
 * Returns 0 if successful, an errno otherwise.
 */
int kdp_generic_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context);

/*
 * Copies in a word from the specified task and address.
 *
 * - task            The task to use
 * - addr            Address to copy from
 * - result          Where to store result
 * - fault_flags     Controls whether to fault in pages that are not resident. This is passed to `find_phys_fn`
 * - find_phys_fn    The function to use to return a physical address given a map and target address.
 *                   If additional filtering/handling is not required, use `(find_phys_fn_t)kdp_find_phys`
 *                   for this parameter.
 * - context         Reference context passed to find_phys_fn
 *
 * Returns 0 if successful, an errno otherwise.
 */
int kdp_generic_copyin_word(task_t task, uint64_t addr, uint64_t *result, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context);

/*
 * Copies in a string from the specified task and address.
 *
 * - task            The task to use
 * - addr            Address to copy from
 * - buf             Where to store result
 * - buf_sz          Size of destination buffer
 * - fault_flags     Controls whether to fault in pages that are not resident. This is passed to `find_phys_fn`
 * - find_phys_fn    The function to use to return a physical address given a map and target address.
 *                   If additional filtering/handling is not required, use `(find_phys_fn_t)kdp_find_phys`
 *                   for this parameter.
 * - context         Reference context passed to find_phys_fn
 *
 * Returns number of bytes copied if successful, -1 otherwise.
 */
int kdp_generic_copyin_string(task_t task, uint64_t addr, char *buf, int buf_sz, kdp_fault_flags_t fault_flags, find_phys_fn_t find_phys_fn, void *context);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* __KDP_COMMON_H */
