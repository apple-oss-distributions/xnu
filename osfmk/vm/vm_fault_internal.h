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

#ifndef _VM_VM_FAULT_INTERNAL_H_
#define _VM_VM_FAULT_INTERNAL_H_


#include <sys/cdefs.h>
#include <vm/vm_fault_xnu.h>
#include <vm/vm_map_lock_internal.h>

__BEGIN_DECLS

#ifdef  MACH_KERNEL_PRIVATE

/*
 *	Page fault handling based on vm_object only.
 */

extern vm_fault_return_t vm_fault_page(
	/* Arguments: */
	vm_object_t     first_object,           /* Object to begin search */
	vm_object_offset_t first_offset,        /* Offset into object */
	vm_prot_t       fault_type,             /* What access is requested */
	boolean_t       must_be_resident,        /* Must page be resident? */
	boolean_t       caller_lookup,          /* caller looked up page */
	/* Modifies in place: */
	vm_prot_t       *protection,            /* Protection for mapping */
	vm_page_t       *result_page,           /* Page found, if successful */
	/* Returns: */
	vm_page_t       *top_page,              /* Page in top object, if
                                                 * not result_page.  */
	int             *type_of_fault,         /* if non-zero, return COW, zero-filled, etc...
                                                 * used by kernel trace point in vm_fault */
	/* More arguments: */
	kern_return_t   *error_code,            /* code if page is in error */
	boolean_t       no_zero_fill,           /* don't fill absent pages */
	vm_object_fault_info_t fault_info,
	vm_map_lock_ctx_t vml_ctx_for_vaddr);

extern void vm_fault_cleanup(
	vm_object_t     object,
	vm_page_t       top_page);

extern kern_return_t vm_fault_wire_resident_pages(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_prot_t               prot,
	vm_tag_t                wire_tag,
	ppnum_t                *physpage_p,
	vm_map_lock_ctx_t       ctx);

kern_return_t
vm_fault_wire_object_pages(
	vm_map_t                map,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_map_size_t           wire_size,
	vm_tag_t                tag,
	int                     interruptible);

void
vm_fault_unwire_object_pages(
	vm_map_t                map,
	vm_object_t             object,
	vm_object_offset_t      start_offset,
	vm_map_size_t           unwire_size);

extern void vm_fault_unwire(
	vm_map_t                map,
	vm_map_entry_t          entry,
	bool                    deallocate,
	pmap_t                  pmap,
	vm_map_offset_t         pmap_addr,
	vm_map_offset_t         end_addr);

extern kern_return_t    vm_fault_copy(
	vm_map_lock_ctx_t       ctx,
	vm_object_t             src_object,
	vm_object_offset_t      src_offset,
	vm_map_size_t          *copy_size,             /* INOUT */
	vm_map_entry_t         *dst_entry,             /* OUT */
	vm_object_t             dst_object,
	vm_object_offset_t      dst_offset,
	int                     interruptible);

extern kern_return_t vm_fault_enter(
	vm_page_t m,
	pmap_t pmap,
	vm_map_offset_t vaddr,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset,
	vm_prot_t prot,
	vm_prot_t fault_type,
	boolean_t wired,
	vm_tag_t  wire_tag,             /* if wiring must pass tag != VM_KERN_MEMORY_NONE */
	vm_object_fault_info_t fault_info,
	bool *need_retry,
	int *type_of_fault,
	uint8_t *object_lock_type,
	bool *page_sleep_needed);

extern kern_return_t vm_pre_fault_with_info(
	vm_map_t                map,
	vm_map_offset_t         offset,
	vm_prot_t               prot,
	vm_object_fault_info_t  fault_info);

extern kern_return_t vm_map_lookup_object_and_lock_entry(
	vm_map_t                *var_map,       /* IN/OUT */
	vm_map_offset_t         vaddr,
	vm_prot_t               fault_type,
	vm_object_t             *object,        /* OUT */
	vm_map_entry_t          *entry,         /* OUT */
	vm_object_offset_t      *offset,        /* OUT */
	vm_prot_t               *out_prot,      /* OUT */
	boolean_t               *wired,         /* OUT */
	vm_object_fault_info_t  fault_info,     /* OUT */
	vm_map_t                *real_map,      /* OUT */
	vm_map_lock_ctx_t        ctx,
	vm_map_lock_ctx_t        vml_ctx_for_vaddr,
	bool                     try_lock_entry);

#endif /* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _VM_VM_FAULT_INTERNAL_H_ */
