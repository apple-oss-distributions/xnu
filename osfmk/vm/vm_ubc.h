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

#ifndef _VM_VM_UBC_H_
#define _VM_VM_UBC_H_

#include <sys/cdefs.h>
#include <mach/memory_object_types.h>
#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <vm/vm_options.h>

/*
 * The upl declarations are all usable by ubc
 */
#include <vm/vm_upl.h>
__BEGIN_DECLS

struct vnode;

extern struct vnode * upl_lookup_vnode(upl_t upl);

extern upl_t vector_upl_create(vm_offset_t, uint32_t);
extern upl_size_t vector_upl_get_size(const upl_t);
extern boolean_t vector_upl_is_valid(upl_t);
extern boolean_t vector_upl_set_subupl(upl_t, upl_t, u_int32_t);
extern void vector_upl_set_pagelist(upl_t);
uint32_t vector_upl_max_upls(const upl_t upl);


extern kern_return_t    memory_object_pages_resident(
	memory_object_control_t         control,
	boolean_t                       *               has_pages_resident);

extern kern_return_t    memory_object_signed(
	memory_object_control_t         control,
	boolean_t                       is_signed);

extern boolean_t        memory_object_is_signed(
	memory_object_control_t control);

extern void             memory_object_mark_used(
	memory_object_control_t         control);

extern void             memory_object_mark_unused(
	memory_object_control_t         control,
	boolean_t                       rage);

extern void             memory_object_mark_io_tracking(
	memory_object_control_t         control);

extern void             memory_object_mark_trusted(
	memory_object_control_t         control);


extern memory_object_t vnode_pager_setup(
	struct vnode *, memory_object_t);

extern void vnode_pager_deallocate(
	memory_object_t);
extern void vnode_pager_vrele(
	struct vnode *vp);

extern kern_return_t memory_object_create_named(
	memory_object_t pager,
	memory_object_offset_t  size,
	memory_object_control_t         *control);

typedef int pager_return_t;
extern pager_return_t   vnode_pagein(
	struct vnode *, upl_t,
	upl_offset_t, vm_object_offset_t,
	upl_size_t, int, int *);
extern pager_return_t   vnode_pageout(
	struct vnode *, upl_t,
	upl_offset_t, vm_object_offset_t,
	upl_size_t, int, int *);

__END_DECLS

#endif /* _VM_VM_UBC_H_ */
