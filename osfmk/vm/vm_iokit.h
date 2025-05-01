/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_IOKIT_H_
#define _VM_VM_IOKIT_H_

#include <sys/cdefs.h>
#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <vm/vm_options.h>

__BEGIN_DECLS

extern kern_return_t memory_object_iopl_request(
	ipc_port_t              port,
	memory_object_offset_t  offset,
	upl_size_t              *upl_size,
	upl_t                   *upl_ptr,
	upl_page_info_array_t   user_page_list,
	unsigned int            *page_list_count,
	upl_control_flags_t     *flags,
	vm_tag_t                tag);

extern uint32_t         vm_tag_get_kext(vm_tag_t tag, char * name, vm_size_t namelen);


extern void iopl_valid_data(
	upl_t                   upl_ptr,
	vm_tag_t        tag);


#ifdef  MACH_KERNEL_PRIVATE
#include <vm/vm_page.h>
#else
typedef struct vm_page  *vm_page_t;
#endif


extern void               vm_page_set_offset(vm_page_t page, vm_object_offset_t offset);
extern vm_object_offset_t vm_page_get_offset(vm_page_t page);
extern ppnum_t            vm_page_get_phys_page(vm_page_t page);
extern vm_page_t          vm_page_get_next(vm_page_t page);


/*
 * device_data_action and device_close are exported symbols
 */
extern kern_return_t device_data_action(
	uintptr_t               device_handle,
	ipc_port_t              device_pager,
	vm_prot_t               protection,
	vm_object_offset_t      offset,
	vm_size_t               size);

extern kern_return_t device_close(
	uintptr_t     device_handle);

extern boolean_t vm_swap_files_pinned(void);

extern kern_return_t device_pager_populate_object(
	memory_object_t         device,
	memory_object_offset_t  offset,
	ppnum_t                 page_num,
	vm_size_t               size);
extern memory_object_t device_pager_setup(
	memory_object_t,
	uintptr_t,
	vm_size_t,
	int);

extern kern_return_t vm_map_range_physical_size(
	vm_map_t         map,
	vm_map_address_t start,
	mach_vm_size_t   size,
	mach_vm_size_t * phys_size);


#if defined(__arm64__)
extern void vm_panic_hibernate_write_image_failed(
	int err,
	uint64_t file_size_min,
	uint64_t file_size_max,
	uint64_t file_size);
#endif /* __arm64__ */


extern kern_return_t mach_make_memory_entry_internal(
	vm_map_t                target_map,
	memory_object_size_ut  *size,
	memory_object_offset_ut offset,
	vm_prot_ut              permission,
	vm_named_entry_kernel_flags_t vmne_kflags,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_handle);

extern kern_return_t
memory_entry_check_for_adjustment(
	vm_map_t                        src_map,
	ipc_port_t                      port,
	vm_map_offset_t         *overmap_start,
	vm_map_offset_t         *overmap_end);

extern kern_return_t memory_entry_purgeable_control_internal(
	ipc_port_t      entry_port,
	vm_purgable_t   control,
	int             *state);

extern kern_return_t mach_memory_entry_get_page_counts(
	ipc_port_t      entry_port,
	unsigned int    *resident_page_count,
	unsigned int    *dirty_page_count);

extern kern_return_t mach_memory_entry_phys_page_offset(
	ipc_port_t              entry_port,
	vm_object_offset_t      *offset_p);

extern kern_return_t mach_memory_entry_map_size(
	ipc_port_t                 entry_port,
	vm_map_t                   map,
	memory_object_offset_ut    offset,
	memory_object_size_ut      size,
	mach_vm_size_t            *map_size);

/* Enter a mapping of a memory object */
extern kern_return_t vm_map_enter_mem_object_prefault(
	vm_map_t                map,
	vm_map_offset_ut       *address,
	vm_map_size_ut          size,
	vm_map_offset_ut        mask,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	vm_object_offset_ut     offset,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	upl_page_list_ptr_t     page_list,
	unsigned int            page_list_count);


__END_DECLS

#endif  /* _VM_VM_IOKIT_H_ */
