/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifdef  XNU_KERNEL_PRIVATE

#ifndef _VM_UPL_
#define _VM_UPL_

#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/kern_return.h>
#include <mach/memory_object_types.h>

__BEGIN_DECLS
/*
 * VM routines that used to be published to
 * user space, and are now restricted to the kernel.
 *
 * They should eventually go away entirely -
 * to be replaced with standard vm_map() and
 * vm_deallocate() calls.
 */
extern kern_return_t vm_upl_map
(
	vm_map_t target_task,
	upl_t upl,
	vm_address_t *address
);

extern kern_return_t vm_upl_unmap
(
	vm_map_t target_task,
	upl_t upl
);

extern kern_return_t vm_upl_map_range
(
	vm_map_t target_task,
	upl_t upl,
	vm_offset_t offset,
	vm_size_t size,
	vm_prot_t prot,
	vm_address_t *address
);

extern kern_return_t vm_upl_unmap_range
(
	vm_map_t target_task,
	upl_t upl,
	vm_offset_t offset,
	vm_size_t size
);

/* Support for UPLs from vm_maps */
extern kern_return_t vm_map_get_upl(
	vm_map_t                target_map,
	vm_map_offset_t         map_offset,
	upl_size_t              *size,
	upl_t                   *upl,
	upl_page_info_array_t   page_info,
	unsigned int            *page_infoCnt,
	upl_control_flags_t     *flags,
	vm_tag_t                tag,
	int                     force_data_sync);

__END_DECLS

#endif /* _VM_UPL_ */
#endif /* XNU_KERNEL_PRIVATE */
