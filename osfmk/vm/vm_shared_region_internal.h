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

#ifndef _VM_SHARED_REGION_INTERNAL_H_
#define _VM_SHARED_REGION_INTERNAL_H_

#include <sys/cdefs.h>
#include <vm/vm_shared_region_xnu.h>

__BEGIN_DECLS

#ifdef MACH_KERNEL_PRIVATE
extern kern_return_t vm_shared_region_slide_page(
	vm_shared_region_slide_info_t si,
	vm_offset_t                   vaddr,
	mach_vm_offset_t              uservaddr,
	uint32_t                      pageIndex,
	uint64_t                      jop_key);

#endif /* MACH_KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE
extern kern_return_t vm_shared_region_enter(
	struct _vm_map          *map,
	struct task             *task,
	boolean_t               is_64bit,
	void                    *fsroot,
	cpu_type_t              cpu,
	cpu_subtype_t           cpu_subtype,
	boolean_t               reslide,
	boolean_t               is_driverkit,
	uint32_t                rsr_version);
extern void vm_shared_region_remove(
	struct task             *task,
	struct vm_shared_region *sr);
extern vm_map_t vm_shared_region_vm_map(
	struct vm_shared_region *shared_region);
extern vm_shared_region_t vm_shared_region_lookup(
	void                    *root_dir,
	cpu_type_t              cpu,
	cpu_subtype_t           cpu_subtype,
	boolean_t               is_64bit,
	int                     target_page_shift,
	boolean_t               reslide,
	boolean_t               is_driverkit,
	uint32_t                rsr_version);
extern kern_return_t vm_shared_region_start_address(
	struct vm_shared_region *shared_region,
	mach_vm_offset_t        *start_address,
	task_t                  task);
extern void vm_shared_region_undo_mappings(
	vm_map_t sr_map,
	mach_vm_offset_t sr_base_address,
	struct _sr_file_mappings *srf_mappings,
	struct _sr_file_mappings *srf_mappings_count,
	unsigned int mappings_count);
__attribute__((noinline))
extern kern_return_t vm_shared_region_map_file(
	struct vm_shared_region *shared_region,
	int                     sr_mappings_count,
	struct _sr_file_mappings *sr_mappings);
extern void *vm_shared_region_root_dir(
	struct vm_shared_region *shared_region);
extern kern_return_t vm_commpage_enter(
	struct _vm_map          *map,
	struct task             *task,
	boolean_t               is64bit);
int vm_shared_region_slide(uint32_t,
    mach_vm_offset_t,
    mach_vm_size_t,
    mach_vm_offset_t,
    mach_vm_size_t,
    mach_vm_offset_t,
    memory_object_control_t,
    vm_prot_t);
extern void vm_shared_region_pivot(void);
#if __has_feature(ptrauth_calls)
__attribute__((noinline))
extern kern_return_t vm_shared_region_auth_remap(vm_shared_region_t sr);
#endif /* __has_feature(ptrauth_calls) */
extern void vm_shared_region_reference(vm_shared_region_t sr);

#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS

#endif  /* _VM_SHARED_REGION_INTERNAL_H_ */
