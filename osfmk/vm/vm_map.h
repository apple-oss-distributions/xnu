/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_map.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Virtual memory map module definitions.
 *
 * Contributors:
 *	avie, dlb, mwyoung
 */

#ifndef _VM_VM_MAP_H_
#define _VM_VM_MAP_H_

#include <sys/cdefs.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/boolean.h>
#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/vm_behavior.h>
#include <mach/vm_param.h>
#include <mach/sdt.h>
#include <vm/pmap.h>
#include <os/overflow.h>
#ifdef XNU_KERNEL_PRIVATE
#include <vm/vm_protos.h>
#endif /* XNU_KERNEL_PRIVATE */
#ifdef  MACH_KERNEL_PRIVATE
#include <mach_assert.h>
#include <vm/vm_map_store_internal.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_page.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/macro_help.h>

#include <kern/thread.h>
#include <os/refcnt.h>
#endif /* MACH_KERNEL_PRIVATE */


__BEGIN_DECLS

#ifdef KERNEL_PRIVATE

#pragma mark - VM map basics

/*!
 * @function vm_map_create()
 *
 * @brief
 * Creates an empty VM map.
 *
 * @discussion
 * A VM map represents an address space or sub-address space that is managed
 * by the Mach VM.
 *
 * It consists of a complex data structure which represents all the VM regions
 * as configured by the address space client, which supports fast lookup
 * by address or range.
 *
 * In the Mach VM, the VM map is the source of truth for all the configuration
 * of regions, and the machine dependent physical map layer is used as a cache
 * of that information.
 *
 * Most of the kernel clients never have to make VM maps themselves
 * and will instead interact with:
 * - the @c current_map() (or a given task map),
 * - the @c kernel_map (which is the kernel's own map) or one of its submaps.
 *
 #ifdef XNU_KERNEL_PRIVATE
 * Inside XNU, using @c vm_map_create_options() is preferred.
 *
 #endif XNU_KERNEL_PRIVATE
 * @param pmap          the physical map to associated with this map
 * @param min_off       the lower address bound of this map
 * @param max_off       the upper address bound of this map
 * @param pageable      whether the map will support paging.
 */
extern vm_map_t         vm_map_create(
	pmap_t                  pmap,
	vm_map_offset_t         min_off,
	vm_map_offset_t         max_off,
	boolean_t               pageable);


/*!
 * @function vm_map_deallocate()
 *
 * @brief
 * Deallocates a VM map.
 *
 * @discussion
 * VM maps are refcounted objects, however most clients will instead
 * hold references to the owning task, or manipulate them via Mach ports.
 *
 * @param map           the map to deallocate.
 */
extern void             vm_map_deallocate(
	vm_map_t                map);


/*!
 * @function vm_map_page_shift()
 *
 * @brief
 * Returns the page shift for a given map.
 *
 * @param map           the specified map
 * @returns             the page shift for this map
 */
extern int              vm_map_page_shift(
	vm_map_t                map) __pure2;


/*!
 * @function vm_map_page_mask()
 *
 * @brief
 * Returns the page mask for a given map.
 *
 * @discussion
 * This is equivalent to @c ((1ull << vm_page_shift(mask)) - 1).
 *
 * @param map           the specified map
 * @returns             the page mask for this map
 */
extern vm_map_offset_t  vm_map_page_mask(
	vm_map_t                map) __pure2;


/*!
 * @function vm_map_page_size()
 *
 * @brief
 * Returns the page size for a given map.
 *
 * @discussion
 * This is equivalent to @c ((1 << vm_page_shift(mask)))
 *
 * @param map           the specified map
 * @returns             the page size for this map
 */
extern int              vm_map_page_size(
	vm_map_t                map) __pure2;


/*!
 * @function vm_map_round_page()
 *
 * @brief
 * Rounds up a given address to the next page boundary for a given page mask.
 *
 * @discussion
 * @warning
 * This function doesn't check for overflow,
 * clients are expected to verify the returned value wasn't 0.
 *
 * @param offset        the address to round to a page boundary
 * @param mask          the page mask to use for the operation
 * @returns             @c offset rounded up to the next page boundary
 */
#define vm_map_round_page(x, pgmask) \
	(((vm_map_offset_t)(x) + (pgmask)) & ~((signed)(pgmask)))

/*!
 * @function vm_map_round_page_mask()
 *
 * @brief
 * Rounds up a given address to the next page boundary for a given page mask.
 *
 * @discussion
 * This is equivalent to @c vm_map_round_page(offset, mask)
 *
 * @warning
 * This function doesn't check for overflow,
 * clients are expected to verify the returned value wasn't 0.
 *
 * @param offset        the address to round to a page boundary
 * @param mask          the page mask to use for the operation
 * @returns             @c offset rounded up to the next page boundary
 */
extern vm_map_offset_t  vm_map_round_page_mask(
	vm_map_offset_t         offset,
	vm_map_offset_t         mask) __pure2;


/*!
 * @function vm_map_trunc_page()
 *
 * @brief
 * Truncates a given address to the previous page boundary for a given page mask.
 *
 * @discussion
 * This is equivalent to @c vm_map_trunc_page(offset, mask)
 *
 * @param offset        the address to truncate to a page boundary
 * @param mask          the page mask to use for the operation
 * @returns             @c offset truncated to the previous page boundary
 */
#define vm_map_trunc_page(offset, pgmask) \
	((vm_map_offset_t)(offset) & ~((signed)(pgmask)))

/*!
 * @function vm_map_trunc_page_mask()
 *
 * @brief
 * Truncates a given address to the previous page boundary for a given page mask.
 *
 * @discussion
 * This is equivalent to @c vm_map_trunc_page(offset, mask)
 *
 * @param offset        the address to truncate to a page boundary
 * @param mask          the page mask to use for the operation
 * @returns             @c offset truncated to the previous page boundary
 */
extern vm_map_offset_t  vm_map_trunc_page_mask(
	vm_map_offset_t         offset,
	vm_map_offset_t         mask) __pure2;


/*!
 * @function vm_map_disable_hole_optimization()
 *
 * @brief
 * Disables hole list optimization
 *
 * @discussion
 * This function disables the hole list optimization and deallocates all
 * associated resources.
 *
 * @param map           the map to disable hole list for.
 */
extern void vm_map_disable_hole_optimization(
	vm_map_t                map);

#ifdef MACH_KERNEL_PRIVATE

#pragma mark - MIG helpers
#pragma GCC visibility push(hidden)

/*!
 * @function convert_port_entry_to_map()
 *
 * @brief
 * MIG intran for the @c vm_task_entry_t type, do not use directly.
 */
extern vm_map_t         convert_port_entry_to_map(
	ipc_port_t              port) __exported;

/*!
 * @function vm_map_inspect_deallocate()
 *
 * @brief
 * MIG destructor function for the @c vm_map_inspect_t type,
 * do not use directly.
 */
extern void             vm_map_inspect_deallocate(
	vm_map_inspect_t        map);


/*!
 * @function vm_map_read_deallocate()
 *
 * @brief
 * MIG destructor function for the @c vm_map_read_t type,
 * do not use directly.
 */
extern void             vm_map_read_deallocate(
	vm_map_read_t           map);

#pragma GCC visibility pop
#endif /* MACH_KERNEL_PRIVATE */

#pragma mark - vm map wiring
#if !XNU_KERNEL_PRIVATE

/*!
 * @function vm_map_wire()
 *
 * @brief
 * Sets the pageability of the specified address range in the
 * target map as wired.
 *
 * @discussion
 * Regions specified as not pageable require locked-down physical memory
 * and physical page maps.
 *
 * The prot_u variable indicates types of accesses that must not
 * generate page faults. This is checked against protection of memory
 * being locked-down.
 *
 * The map must not be locked, but a reference must remain
 * to the map throughout the call.
 *
 *
 * @param map           the target VM map (the call will recurse in submaps).
 * @param start_u       the lower bound of the address range to wire
 * @param end_u         the upper bound of the address range to wire
 * @param prot_u        the access for which to perform the wiring
 * @param user_wire     whether the wiring is on behalf of userspace.
 *                      userspace wiring is equivalent to an mlock() call from
 *                      userspace and will be undone at process death unlike
 *                      kernel wiring which must always be undone explicitly.
 *
 * @returns
 * - KERN_SUCCESS       the operation was successful
 * - KERN_INVALID_ARGUMENT
 *                      @c [start_u, end_u) didn't form a valid region
 * - KERN_RESOURCE_SHORTAGE
 *                      the kernel was out of physical memory to perform
 *                      the operation.
 * - KERN_INVALID_ADDRESS
 *                      some address in the range wasn't mapped.
 * - KERN_PROTECTION_FAILURE
 *                      the region doesn't support wiring for this access.
 * - KERN_MEMORY_ERROR  faulting failed.
 * - MACH_SEND_INTERRUPTED
 *                      a signal was received during the wiring
 *
 * User wirings:
 * - KERN_FAILURE       the process was terminated during the wiring.
 * - KERN_FAILURE       the user wire counts would overflow @c MAX_WIRE_COUNT
 *                      for this region.
 * - KERN_RESOURCE_SHORTAGE
 *                      the process would overflow its user wiring limits.
 */
extern kern_return_t    vm_map_wire(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	boolean_t               user_wire);

#endif /* !XNU_KERNEL_PRIVATE */

/*!
 * @function vm_map_unwire()
 *
 * @brief
 * Sets the pageability of the specified address range in the target
 * as pageable.
 *
 * @discussion
 * Regions specified must have been wired previously.
 *
 * The map must not be locked, but a reference must remain to the map
 * throughout the call.
 *
 * User unwire ignores holes and unwired and intransition entries to avoid
 * losing memory by leaving it unwired. Kernel unwires will panic on failures.
 *
 *
 * @param map           the target VM map (the call will recurse in submaps).
 * @param start_u       the lower bound of the address range to wire
 * @param end_u         the upper bound of the address range to wire
 * @param user_wire     whether the wiring is on behalf of userspace.
 */
extern kern_return_t    vm_map_unwire(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	boolean_t               user_wire);


#if XNU_PLATFORM_MacOSX

/*!
 * @function vm_map_wire_and_extract()
 *
 * @brief
 * Sets the pageability of the specified page in the target map,
 * and returns the resulting physical page number for it.
 *
 * @discussion
 * This function should not be called by kernel extensions and is only here
 * for backward compatibility of macOS kernels.
 *
 *
 * @param map           the target VM map (the call will recurse in submaps).
 * @param address       the address of the page to wire
 * @param access_type   the access for which to perform the wiring
 * @param user_wire     whether the wiring is on behalf of userspace.
 *                      userspace wiring is equivalent to an mlock() call from
 *                      userspace and will be undone at process death unlike
 *                      kernel wiring which must always be undone explicitly.
 * @param physpage_p    a pointer filled with the page number for the wired down
 *                      physical page, or 0 in case of failure.
 *
 * @returns             @c KERN_SUCCESS or an error denoting the reason for
 *                      failure.
 */
extern kern_return_t    vm_map_wire_and_extract(
	vm_map_t                map,
	vm_map_offset_ut        address,
	vm_prot_ut              access_type,
	boolean_t               user_wire,
	ppnum_t                *physpage_p);

#endif /* XNU_PLATFORM_MacOSX */

#pragma mark - vm map copy

/*!
 * @const VM_MAP_COPY_OVERWRITE_OPTIMIZATION_THRESHOLD_PAGES
 * Number of pages under which the VM will copy by content rather
 * than trying to do a copy-on-write mapping to form a vm_map_copy_t.
 *
 * Note: this constant has unfortunately been exposed historically
 *       but should not be considered ABI.
 */
#define VM_MAP_COPY_OVERWRITE_OPTIMIZATION_THRESHOLD_PAGES      (3)


/*!
 * @function vm_map_copyin()
 *
 * @brief
 * Copy the specified region from the source address space.
 *
 * @description
 * The source map should not be locked on entry.
 *
 *
 * @param [in] src_map       the source address space to copy from.
 * @param [in] src_addr      the address at which to start copying memory.
 * @param [in] len           the size of the region to copy.
 * @param [in] src_destroy   whether the copy also removes the region
 *                           from the source address space.
 * @param [out] copy_result  the out parameter, to be filled with the created
 *                           vm map copy on success.
 * @returns
 * - KERN_SUCCESS       the operation was successful
 * - KERN_INVALID_ARGUMENT
 *                      @c (src_addr, len) didn't form a valid region
 * - KERN_RESOURCE_SHORTAGE
 *                      the kernel was out of physical memory to perform
 *                      the operation.
 * - KERN_INVALID_ADDRESS
 *                      some address in the range wasn't mapped
 * - KERN_PROTECTION_FAILURE
 *                      the region isn't readable (it doesn't have
 *                      @c VM_PROT_READ set).
 * - KERN_PROTECTION_FAILURE
 *                      the memory range contains a physically contiguous
 *                      object
 * - KERN_MEMORY_ERROR  faulting failed.
 * - MACH_SEND_INTERRUPTED
 *                      a signal was received during the copy
 *
 */
extern kern_return_t    vm_map_copyin(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr,
	vm_map_size_ut          len,
	boolean_t               src_destroy,
	vm_map_copy_t          *copy_result); /* OUT */


/*!
 * @function vm_map_copyout()
 *
 * @brief
 * Place a VM map copy made with @c vm_map_copyin() into a destination map.
 *
 * @description
 * The specified VM map copy is consumed on success,
 * otherwise the caller is responsible for it.
 * @see @c vm_map_copy_discard below.
 *
 * @param [in]  dst_map the destination address space to insert into.
 * @param [out] addr    the address at which the data was inserted.
 * @param [in]  copy    the VM map copy to place.
 * @returns
 * - KERN_SUCCESS       the operation succeeded, @c copy has been consumed.
 * - KERN_NO_SPACE      the destination map was out of address space.
 * - KERN_NOT_SUPPORTED the vm map copy can't be mapped in this address space.
 *                      This can for example happen for certain cases of a VM
 *                      map copy using a 4k page size into a space that is 16k
 *                      aligned, requiring different physical pages within the
 *                      same 16k page boundary.
 */
extern kern_return_t    vm_map_copyout(
	vm_map_t                dst_map,
	vm_map_address_t       *addr, /* OUT */
	vm_map_copy_t           copy);

/*!
 * @function vm_map_copy_discard()
 *
 * @brief
 * Dispose of a @c vm_map_copy_t object made by @c vm_map_copyin().
 *
 * @description
 * VM map copies are typically placed in an address space using
 * @c vm_map_copyout(), but when that has not happened, this function must be
 * used to dispose of it.
 *
 * @param copy          the VM map copy object to dispose of.
 */
extern void             vm_map_copy_discard(
	vm_map_copy_t           copy);

#endif  /* KERNEL_PRIVATE */

__END_DECLS

#endif  /* _VM_VM_MAP_H_ */
