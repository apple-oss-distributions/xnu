/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	vm/vm_kern.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Kernel memory management definitions.
 */

#ifndef _VM_VM_KERN_H_
#define _VM_VM_KERN_H_

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/vm_types.h>
#ifdef XNU_KERNEL_PRIVATE
#include <kern/locks.h>
#endif /* XNU_KERNEL_PRIVATE */


__BEGIN_DECLS

#ifdef KERNEL_PRIVATE

/*!
 * @brief
 * The VM map for the kernel.
 *
 * @discussion
 * This represents the VM-managed portion of the address space.
 *
 * The actual address space of the kernel is larger but is managed
 * by the pmap directly and the VM is oblivious to it. Unmanaged regions
 * of that kind include the physical aperture or the KASAN shadow map.
 */
extern vm_map_t kernel_map;


/*!
 * @brief
 * The IPC VM submap.
 *
 * @discussion
 * The IPC submap is used by the Mach IPC subsystem in order to stage
 * allocations for IPC kmsgs or to throttle debugging interfaces.
 *
 * This submap doesn't zero on page fault, and clients must properly
 * erase memory or risk memory disclosures.
 */
extern vm_map_t ipc_kernel_map;

#if XNU_KERNEL_PRIVATE

/*!
 * @brief
 * The Kext VM submap
 *
 * @discussion
 * This submap is used to support unloading and paging out kexts.
 */
extern vm_map_t g_kext_map __XNU_PRIVATE_EXTERN;

#else

#pragma mark - the kmem subsystem

/*!
 * @function kmem_alloc()
 *
 * @brief
 * Allocate anonymous wired memory from the kernel map or a kernel submap.
 *
 * @discussion
 * The memory allocated is wired and must be deallocated with @c kmem_free()
 * or @c mach_vm_deallocate().
 *
 * Kernel extensions are discouraged from using this function:
 * consider @c IOMallocType() instead.
 *
 * Per kernel allocation security policies (see doc/allocators/api-basics.md),
 * this allocation cannot be used to store pure data, @c IOMallocData()
 * must be used instead.
 *
 * @param [in]  map     the map to allocate from, this must be the kernel map
 *                      or one of its submaps.
 * @param [out] addrp   a non-NULL pointer used to return the newly allocated
 *                      memory.
 * @param [in]  size    the size of the memory to allocate.
 *
 * @returns
 * KERN_SUCCESS         the allocation succeeded,
 *                      the returned address will be non-zero.
 * KERN_INVALID_ARGUMENT
 *                      the allocation failed because @c size was 0.
 * KERN_NO_SPACE        the allocation failed because the specified map
 *                      is out of address space.
 * KERN_RESOURCE_SHORTAGE
 *                      the allocation failed because the kernel
 *                      was out of pages and couldn't satisfy the demand.
 */
extern kern_return_t kmem_alloc(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size);


/*!
 * @function kmem_alloc_pageable()
 *
 * @brief
 * Allocate anonymous pageable memory from the kernel map or a kernel submap.
 *
 * @discussion
 * This call is equivalent to @c mach_vm_allocate(map, addr, size, VM_FLAGS_ANYWHERE)
 * which should be preferred to this legacy call.
 *
 * The memory allocated is wired and must be deallocated with @c kmem_free()
 * or @c mach_vm_deallocate().
 *
 * Per kernel allocation security policies (see doc/allocators/api-basics.md),
 * this allocation must not be used to store kernel pointers.
 *
 * @param [in]  map     the map to allocate from, this must be the kernel map
 *                      or one of its submaps.
 * @param [out] addrp   a non-NULL pointer used to return the newly allocated
 *                      memory.
 * @param [in]  size    the size of the memory to allocate.
 *
 * @returns
 * KERN_SUCCESS         the allocation succeeded,
 *                      the returned address will be non-zero.
 * KERN_NO_SPACE        the allocation failed because the specified map
 *                      is out of address space.
 */
extern kern_return_t kmem_alloc_pageable(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size);


/*!
 * @function kmem_alloc_kobject()
 *
 * @brief
 * Allocate kobject wired memory from the kernel map or a kernel submap.
 *
 * @discussion
 * The memory allocated is wired and must be deallocated with @c kmem_free()
 * or @c mach_vm_deallocate().
 *
 * Memory allocated by this function is added to the VM kernel object rather
 * than a new VM object. This makes it possible to avoid the cost of that extra
 * VM object, but forgoes any advanced VM features such as unwiring memory, or
 * sharing it (whether it be to an IOMMU or another address space).
 *
 * Kernel extensions are discouraged from using this function:
 * consider @c IOMallocType() instead.
 *
 * Per kernel allocation security policies (see doc/allocators/api-basics.md),
 * this allocation cannot be used to store pure data, @c IOMallocData()
 * must be used instead.
 *
 * @param [in]  map     the map to allocate from, this must be the kernel map
 *                      or one of its submaps.
 * @param [out] addrp   a non-NULL pointer used to return the newly allocated
 *                      memory.
 * @param [in]  size    the size of the memory to allocate.
 *
 * @returns
 * KERN_SUCCESS         the allocation succeeded,
 *                      the returned address will be non-zero.
 * KERN_INVALID_ARGUMENT
 *                      the allocation failed because @c size was 0.
 * KERN_NO_SPACE        the allocation failed because the specified map
 *                      is out of address space.
 * KERN_RESOURCE_SHORTAGE
 *                      the allocation failed because the kernel
 *                      was out of pages and couldn't satisfy the demand.
 */
extern kern_return_t kmem_alloc_kobject(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size);

/*!
 * @function kmem_free()
 *
 * @brief
 * Deallocates a range of memory.
 *
 * @discussion
 * This call is roughly equivalent to @c mach_vm_deallocate(map, addr, size).
 *
 * It is possible to deallocate an allocation in several steps provided that
 * the deallocations form a partition of the range allocated with one of
 * the functions from the @c kmem_alloc*() family.
 *
 * Unlike @c mach_vm_deallocate(), this function will panic for invalid
 * arguments, in particular for invalid sizes or a @c map argument
 * not matching the one used for allocating.
 *
 * @param map           the map to allocate from, this must be the kernel map
 *                      or one of its submaps.
 * @param addr          the address to deallocate.
 * @param size          the size of the address to deallocate.
 */
extern void kmem_free(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size);

#endif /* !XNU_KERNEL_PRIVATE */
#endif /* KERNEL_PRIVATE */

#pragma mark - kernel address obfuscation / hashing for logging

/*!
 * @function vm_kernel_addrhide()
 *
 * @brief
 * Unslides a kernel pointer.
 *
 * @discussion
 * This is exporting the VM_KERNEL_ADDRHIDE() functionality to kernel
 * extensions.
 *
 * @param addr          the kernel address to unslide
 * @param hide_addr     the unslid value of @c addr if it was part of a slid
 *                      region of the kernel.
 *
 *                      0 on release kernels if @c addr is not part of a slid
 *                      region of the kernel.
 *
 *                      @c addr on development kernels if @c addr is not part of
 *                      a slid region of the kernel.
 */
extern void vm_kernel_addrhide(
	vm_offset_t             addr,
	vm_offset_t            *hide_addr);


/*!
 * @function vm_kernel_addrperm_external()
 *
 * @brief
 * Unslides or "permutate" a kernel pointer.
 *
 * @discussion
 * This is exporting the VM_KERNEL_ADDRPERM() functionality to kernel
 * extensions.
 *
 * The level of "hiding" of heap kernel pointers done by this function is
 * insufficient. Using @c vm_kernel_addrhash() is preferred when possible.
 *
 * Note that this function might cause lazy allocation to preserve the floating
 * point register state on Intel and is generally unsafe to call under lock.
 *
 * @param addr          the kernel address to unslide
 * @param perm_addr     the unslid value of @c addr if it was part of a slid
 *                      region of the kernel.
 */
extern void vm_kernel_addrperm_external(
	vm_offset_t             addr,
	vm_offset_t            *perm_addr);


/*!
 * @function vm_kernel_unslide_or_perm_external()
 *
 * @brief
 * Equivalent to vm_kernel_addrperm_external().
 */
extern void vm_kernel_unslide_or_perm_external(
	vm_offset_t             addr,
	vm_offset_t            *perm_addr);

#if !XNU_KERNEL_PRIVATE

/*!
 * @function vm_kernel_addrhash()
 *
 * @brief
 * Unslides or hashes a kernel pointer.
 *
 * @discussion
 * This is exporting the VM_KERNEL_ADDRHASH() functionality to kernel
 * extensions.
 *
 * @param addr          the kernel address to unslide
 * @returns             the unslid value of @c addr if it was part of a slid
 *                      region of the kernel.
 *
 *                      a hashed value of @c addr otherwise.
 */
extern vm_offset_t vm_kernel_addrhash(
	vm_offset_t             addr);

#else /* XNU_KERNEL_PRIVATE */
#pragma GCC visibility push(hidden)

/*!
 * @brief
 * The quantity @c vm_kernel_addrhide() uses to slide heap pointers.
 */
extern vm_offset_t vm_kernel_addrperm_ext;


/*!
 * @brief
 * The quantity @c vm_kernel_addrhash() uses to hash heap pointers inside XNU.
 */
extern uint64_t vm_kernel_addrhash_salt;


/*!
 * @brief
 * The quantity @c vm_kernel_addrhash() uses to hash heap pointers for kernel
 * extensions.
 */
extern uint64_t vm_kernel_addrhash_salt_ext;


/*!
 * @function vm_kernel_addrhash_internal()
 *
 * @brief
 * Internal function used to implement the @c vm_kernel_addrhash*() functions.
 */
extern vm_offset_t vm_kernel_addrhash_internal(
	vm_offset_t             addr,
	uint64_t                salt);


/*!
 * @function vm_kernel_addrhash()
 *
 * @brief
 * Unslides or hashes a kernel pointer.
 *
 * @discussion
 * This is exporting the VM_KERNEL_ADDRHASH() functionality to kernel
 * extensions.
 *
 * @param addr          the kernel address to unslide
 * @returns             the unslid value of @c addr if it was part of a slid
 *                      region of the kernel.
 *
 *                      a hashed value of @c addr otherwise.
 */
static inline vm_offset_t
vm_kernel_addrhash(vm_offset_t addr)
{
	return vm_kernel_addrhash_internal(addr, vm_kernel_addrhash_salt);
}

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */
#ifdef KERNEL_PRIVATE

#pragma mark - kern allocation names

/*!
 * @typedef kern_allocation_name_t
 *
 * @brief
 * This type is used to perform different kinds of accounting
 * in the Mach VM subsystem.
 */
#ifdef XNU_KERNEL_PRIVATE
typedef struct vm_allocation_site       kern_allocation_name;
typedef kern_allocation_name           *kern_allocation_name_t;
#else
typedef struct kern_allocation_name    *kern_allocation_name_t;
#endif


/*!
 * @brief
 * Allocate a kernel allocation accounting structure.
 *
 * @param name          a symbolic name for this accounting group.
 * @param suballocs     how many subtotals will be used for accounting.
 *                      see @c kern_allocation_update_subtotal().
 * @returns             the new allocated accounting structure,
 *                      this function never fails.
 */
extern kern_allocation_name_t kern_allocation_name_allocate(
	const char             *name,
	uint16_t                suballocs);

/*!
 * @brief
 * Frees a kernel allocation accounting structure.
 *
 * @param allocation    a structure made with @c kern_allocation_name_allocate().
 */
extern void kern_allocation_name_release(
	kern_allocation_name_t  allocation);


/*!
 * @brief
 * Returns the name associated with an allocation accounting structure.
 *
 * @returns             the name associated with that accounting structure,
 *                      when made with @c kern_allocation_name_allocate().
 */
extern const char *kern_allocation_get_name(
	kern_allocation_name_t  allocation);

#endif  /* KERNEL_PRIVATE */

__END_DECLS

#endif  /* _VM_VM_KERN_H_ */
