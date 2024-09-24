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

#ifndef _VM_VM_KERN_INTERNAL_H_
#define _VM_VM_KERN_INTERNAL_H_

#include <sys/cdefs.h>
#include <vm/vm_kern_xnu.h>

__BEGIN_DECLS

#ifdef MACH_KERNEL_PRIVATE

#pragma mark kmem range methods

extern struct mach_vm_range kmem_ranges[KMEM_RANGE_COUNT];
extern struct mach_vm_range kmem_large_ranges[KMEM_RANGE_COUNT];
#define KMEM_RANGE_MASK       0x3fff
#define KMEM_HASH_SET         0x4000
#define KMEM_DIRECTION_MASK   0x8000

__stateful_pure
extern mach_vm_size_t mach_vm_range_size(
	const struct mach_vm_range *r);

__attribute__((overloadable, pure))
extern bool mach_vm_range_contains(
	const struct mach_vm_range *r,
	mach_vm_offset_t        addr);

__attribute__((overloadable, pure))
extern bool mach_vm_range_contains(
	const struct mach_vm_range *r,
	mach_vm_offset_t        addr,
	mach_vm_offset_t        size);

__attribute__((overloadable, pure))
extern bool mach_vm_range_intersects(
	const struct mach_vm_range *r1,
	const struct mach_vm_range *r2);

__attribute__((overloadable, pure))
extern bool mach_vm_range_intersects(
	const struct mach_vm_range *r1,
	mach_vm_offset_t        addr,
	mach_vm_offset_t        size);

/*
 * @function kmem_range_id_contains
 *
 * @abstract Return whether the region of `[addr, addr + size)` is completely
 * within the memory range.
 */
__pure2
extern bool kmem_range_id_contains(
	kmem_range_id_t         range_id,
	vm_map_offset_t         addr,
	vm_map_size_t           size);

__pure2
extern kmem_range_id_t kmem_addr_get_range(
	vm_map_offset_t         addr,
	vm_map_size_t           size);

extern kmem_range_id_t kmem_adjust_range_id(
	uint32_t                hash);



__startup_func
extern uint16_t kmem_get_random16(
	uint16_t                upper_limit);

__startup_func
extern void kmem_shuffle(
	uint16_t               *shuffle_buf,
	uint16_t                count);

#endif /* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _VM_VM_KERN_INTERNAL_H_ */
