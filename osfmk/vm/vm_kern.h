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
extern vm_map_t kernel_map;
extern vm_map_t ipc_kernel_map;
extern vm_map_t g_kext_map;
#endif /* KERNEL_PRIVATE */

#pragma mark - the kmem subsystem
#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

/*
 * "kmem" is a set of methods that provide interfaces suitable
 * to allocate memory from the VM in the kernel map or submaps.
 *
 * It provide leaner alternatives to some of the VM functions,
 * closer to a typical allocator.
 */

struct vm_page;
struct vm_map_entry;

/*!
 * @typedef
 *
 * @brief
 * Pair of a return code and size/address/... used by kmem interfaces.
 *
 * @discussion
 * Using a pair of integers allows the compiler to return everything
 * through registers, and doesn't need to use stack values to get results,
 * which yields significantly better codegen.
 *
 * If @c kmr_return is not @c KERN_SUCCESS, then the other field
 * of the union is always supposed to be 0.
 */
typedef struct {
	kern_return_t           kmr_return;
	union {
		vm_address_t    kmr_address;
		vm_size_t       kmr_size;
		void           *kmr_ptr;
		vm_map_t        kmr_submap;
	};
} kmem_return_t;

/*!
 * @typedef kmem_guard_t
 *
 * @brief
 * KMEM guards are used by the kmem_* subsystem to secure atomic allocations.
 *
 * @discussion
 * This parameter is used to transmit the tag for the allocation.
 *
 * If @c kmg_atomic is set, then the other fields are also taken into account
 * and will affect the allocation behavior for this allocation.
 *
 * @field kmg_tag               The VM_KERN_MEMORY_* tag for this entry.
 * @field kmg_type_hash         Some hash related to the type of the allocation.
 * @field kmg_atomic            Whether the entry is atomic.
 * @field kmg_submap            Whether the entry is for a submap.
 * @field kmg_context           A use defined 30 bits that will be stored
 *                              on the entry on allocation and checked
 *                              on other operations.
 */
typedef struct {
	uint16_t                kmg_tag;
	uint16_t                kmg_type_hash;
	uint32_t                kmg_atomic : 1;
	uint32_t                kmg_submap : 1;
	uint32_t                kmg_context : 30;
} kmem_guard_t;
#define KMEM_GUARD_NONE         (kmem_guard_t){ }
#define KMEM_GUARD_SUBMAP       (kmem_guard_t){ .kmg_atomic = 0, .kmg_submap = 1 }


/*!
 * @typedef kmem_flags_t
 *
 * @brief
 * Sets of flags taken by several of the @c kmem_* family of functions.
 *
 * @discussion
 * This type is not used directly by any function, it is an underlying raw
 * type that is re-vended under different namespaces for each @c kmem_*
 * interface.
 *
 * - @c kmem_alloc    uses @c kma_flags_t / @c KMA_* namespaced values.
 * - @c kmem_suballoc uses @c kms_flags_t / @c KMS_* namespaced values.
 * - @c kmem_realloc  uses @c kmr_flags_t / @c KMR_* namespaced values.
 * - @c kmem_free     uses @c kmf_flags_t / @c KMF_* napespaced values.
 *
 *
 * <h2>Call behavior</h2>
 *
 * @const KMEM_NONE (all)
 *	Pass this when no special options is to be used.
 *
 * @const KMEM_NOFAIL (alloc, suballoc)
 *	When this flag is passed, any allocation failure results into a panic().
 *	Using this flag should really be limited to cases when failure is not
 *	recoverable and possibly during early boot only.
 *
 * @const KMEM_NOPAGEWAIT (alloc, realloc)
 *	Pass this flag if the system should not wait in VM_PAGE_WAIT().
 *
 * @const KMEM_FREEOLD (realloc)
 *	Pass this flag if @c kmem_realloc should free the old mapping
 *	(when the address changed) as part of the call.
 *
 * @const KMEM_REALLOCF (realloc)
 *	Similar to @c Z_REALLOCF: if the call is failing,
 *	then free the old allocation too.
 *
 *
 * <h2>How the entry is populated</h2>
 *
 * @const KMEM_VAONLY (alloc)
 *	By default memory allocated by the kmem subsystem is wired and mapped.
 *	Passing @c KMEM_VAONLY will cause the range to still be wired,
 *	but no page is actually mapped.
 *
 * @const KMEM_PAGEABLE (alloc)
 *	By default memory allocated by the kmem subsystem is wired and mapped.
 *	Passing @c KMEM_PAGEABLE makes the entry non wired, and pages will be
 *	added to the entry as it faults.
 *
 * @const KMEM_ZERO (alloc, realloc)
 *	Any new page added is zeroed.
 *
 *
 * <h2>VM object to use for the entry</h2>
 *
 * @const KMEM_KOBJECT (alloc, realloc)
 *	The entry will be made for the @c kernel_object.
 *
 *	Note that the @c kernel_object is just a "collection of pages".
 *	Pages in that object can't be remaped or present in several VM maps
 *	like traditional objects.
 *
 *	If neither @c KMEM_KOBJECT nor @c KMEM_COMPRESSOR is passed,
 *	the a new fresh VM object will be made for this allocation.
 *	This is expensive and should be limited to allocations that
 *	need the features associated with a VM object.
 *
 * @const KMEM_COMPRESSOR (alloc)
 *	The entry is allocated for the @c compressor_object.
 *	Pages belonging to the compressor are not on the paging queues,
 *	nor are they counted as wired.
 *
 *	Only the VM Compressor subsystem should use this.
 *
 *
 * <h2>How to look for addresses</h2>
 *
 * @const KMEM_LOMEM (alloc, realloc)
 *	The physical memory allocated must be in the first 4G of memory,
 *	in order to support hardware controllers incapable of generating DMAs
 *	with more than 32bits of physical address.
 *
 * @const KMEM_LAST_FREE (alloc, suballoc, realloc)
 *	When looking for space in the specified map,
 *	start scanning for addresses from the end of the map
 *	rather than the start.
 *
 * @const KMEM_DATA (alloc, suballoc, realloc)
 *	The memory must be allocated from the "Data" range.
 *
 * @const KMEM_SPRAYQTN (alloc, realloc)
 *	The memory must be allocated from the "spray quarantine" range. For more
 *	details on what allocations qualify to use this flag see
 *	@c KMEM_RANGE_ID_SPRAYQTN.
 *
 * @const KMEM_GUESS_SIZE (free)
 *	When freeing an atomic entry (requires a valid kmem guard),
 *	then look up the entry size because the caller didn't
 *	preserve it.
 *
 *	This flag is only here in order to support kfree_data_addr(),
 *	and shall not be used by any other clients.
 *
 * <h2>Entry properties</h2>
 *
 * @const KMEM_PERMANENT (alloc, suballoc)
 *	The entry is made permanent.
 *
 *	In the kernel maps, permanent entries can never be deleted.
 *	Calling @c kmem_free() on such a range will panic.
 *
 *	In user maps, permanent entries will only be deleted
 *	whenthe map is terminated.
 *
 * @const KMEM_GUARD_FIRST (alloc, realloc)
 * @const KMEM_GUARD_LAST (alloc, realloc)
 *	Asks @c kmem_* to put a guard page at the beginning (resp. end)
 *	of the allocation.
 *
 *	The allocation size will not be extended to accomodate for guards,
 *	and the client of this interface must take them into account.
 *	Typically if a usable range of 3 pages is needed with both guards,
 *	then 5 pages must be asked.
 *
 *	Alignment constraints take guards into account (the aligment applies
 *	to the address right after the first guard page).
 *
 *	The returned address for allocation will pointing at the entry start,
 *	which is the address of the left guard page if any.
 *
 *	Note that if @c kmem_realloc* is called, the *exact* same
 *	guard flags must be passed for this entry. The KMEM subsystem
 *	is generally oblivious to guards, and passing inconsistent flags
 *	will cause pages to be moved incorrectly.
 *
 * @const KMEM_KSTACK (alloc)
 *	This flag must be passed when the allocation is for kernel stacks.
 *	This only has an effect on Intel.
 *
 * @const KMEM_NOENCRYPT (alloc)
 *	Obsolete, will be repurposed soon.
 *
 * @const KMEM_KASAN_GUARD (alloc, realloc, free)
 *	Under KASAN_CLASSIC add guards left and right to this allocation
 *	in order to detect out of bounds.
 *
 *	This can't be passed if any of @c KMEM_GUARD_FIRST
 *	or @c KMEM_GUARD_LAST is used.
 *
 * @const KMEM_TAG (alloc, realloc, free)
 *	Under KASAN_TBI, this allocation is tagged non canonically.
 */
__options_decl(kmem_flags_t, uint32_t, {
	KMEM_NONE           = 0x00000000,

	/* Call behavior */
	KMEM_NOFAIL         = 0x00000001,
	KMEM_NOPAGEWAIT     = 0x00000002,
	KMEM_FREEOLD        = 0x00000004,
	KMEM_REALLOCF       = 0x00000008,

	/* How the entry is populated */
	KMEM_VAONLY         = 0x00000010,
	KMEM_PAGEABLE       = 0x00000020,
	KMEM_ZERO           = 0x00000040,

	/* VM object to use for the entry */
	KMEM_KOBJECT        = 0x00000100,
	KMEM_COMPRESSOR     = 0x00000200,

	/* How to look for addresses */
	KMEM_LOMEM          = 0x00001000,
	KMEM_LAST_FREE      = 0x00002000,
	KMEM_GUESS_SIZE     = 0x00004000,
	KMEM_DATA           = 0x00008000,
	KMEM_SPRAYQTN       = 0x00010000,

	/* Entry properties */
	KMEM_PERMANENT      = 0x00100000,
	KMEM_GUARD_FIRST    = 0x00200000,
	KMEM_GUARD_LAST     = 0x00400000,
	KMEM_KSTACK         = 0x00800000,
	KMEM_NOENCRYPT      = 0x01000000,
	KMEM_KASAN_GUARD    = 0x02000000,
	KMEM_TAG            = 0x04000000,
});


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

/*
 * @function kmem_range_id_size
 *
 * @abstract Return the addressable size of the memory range.
 */
__pure2
extern vm_map_size_t kmem_range_id_size(
	kmem_range_id_t         range_id);

__pure2
extern kmem_range_id_t kmem_addr_get_range(
	vm_map_offset_t         addr,
	vm_map_size_t           size);

extern kmem_range_id_t kmem_adjust_range_id(
	uint32_t                hash);


/**
 * @enum kmem_claims_flags_t
 *
 * @abstract
 * Set of flags used in the processing of kmem_range claims
 *
 * @discussion
 * These flags are used by the kmem subsytem while processing kmem_range
 * claims and are not explicitly passed by the caller registering the claim.
 *
 * @const KC_NO_ENTRY
 * A vm map entry should not be created for the respective claim.
 *
 * @const KC_NO_MOVE
 * The range shouldn't be moved once it has been placed as it has constraints.
 */
__options_decl(kmem_claims_flags_t, uint32_t, {
	KC_NONE         = 0x00000000,
	KC_NO_ENTRY     = 0x00000001,
	KC_NO_MOVE      = 0x00000002,
});

/*
 * Security config that creates the additional splits in non data part of
 * kernel_map
 */
#if KASAN || (__arm64__ && !defined(KERNEL_INTEGRITY_KTRR) && !defined(KERNEL_INTEGRITY_CTRR))
#   define ZSECURITY_CONFIG_KERNEL_PTR_SPLIT        OFF
#else
#   define ZSECURITY_CONFIG_KERNEL_PTR_SPLIT        ON
#endif

#define ZSECURITY_NOT_A_COMPILE_TIME_CONFIG__OFF() 0
#define ZSECURITY_NOT_A_COMPILE_TIME_CONFIG__ON()  1
#define ZSECURITY_CONFIG2(v)     ZSECURITY_NOT_A_COMPILE_TIME_CONFIG__##v()
#define ZSECURITY_CONFIG1(v)     ZSECURITY_CONFIG2(v)
#define ZSECURITY_CONFIG(opt)    ZSECURITY_CONFIG1(ZSECURITY_CONFIG_##opt)

struct kmem_range_startup_spec {
	const char             *kc_name;
	struct mach_vm_range   *kc_range;
	vm_map_size_t           kc_size;
	vm_map_size_t           (^kc_calculate_sz)(void);
	kmem_claims_flags_t     kc_flags;
};

extern void kmem_range_startup_init(
	struct kmem_range_startup_spec *sp);

/*!
 * @macro KMEM_RANGE_REGISTER_*
 *
 * @abstract
 * Register a claim for kmem range or submap.
 *
 * @discussion
 * Claims are shuffled during startup to randomize the layout of the kernel map.
 * Temporary entries are created in place of the claims, therefore the caller
 * must provide the start of the assigned range as a hint and
 * @c{VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE} to kmem_suballoc to replace the mapping.
 *
 * Min/max constraints can be provided in the range when the claim is
 * registered.
 *
 * This macro comes in 2 flavors:
 * - STATIC : When the size of the range/submap is known at compile time
 * - DYNAMIC: When the size of the range/submap needs to be computed
 * Temporary entries are create
 * The start of the
 *
 * @param name          the name of the claim
 * @param range         the assigned range for the claim
 * @param size          the size of submap/range (if known at compile time)
 * @param calculate_sz  a block that returns the computed size of submap/range
 */
#define KMEM_RANGE_REGISTER_STATIC(name, range, size)                    \
	static __startup_data struct kmem_range_startup_spec                       \
	__startup_kmem_range_spec_ ## name = { #name, range, size, NULL, KC_NONE}; \
	STARTUP_ARG(KMEM, STARTUP_RANK_SECOND, kmem_range_startup_init,            \
	    &__startup_kmem_range_spec_ ## name)

#define KMEM_RANGE_REGISTER_DYNAMIC(name, range, calculate_sz)           \
	static __startup_data struct kmem_range_startup_spec                       \
	__startup_kmem_range_spec_ ## name = { #name, range, 0, calculate_sz,      \
	    KC_NONE};                                                              \
	STARTUP_ARG(KMEM, STARTUP_RANK_SECOND, kmem_range_startup_init,            \
	    &__startup_kmem_range_spec_ ## name)

__startup_func
extern uint16_t kmem_get_random16(
	uint16_t                upper_limit);

__startup_func
extern void kmem_shuffle(
	uint16_t               *shuffle_buf,
	uint16_t                count);


#pragma mark kmem entry parameters

/*!
 * @function kmem_entry_validate_guard()
 *
 * @brief
 * Validates that the entry matches the input parameters, panic otherwise.
 *
 * @discussion
 * If the guard has a zero @c kmg_guard value,
 * then the entry must be non atomic.
 *
 * The guard tag is not used for validation as the VM subsystems
 * (particularly in IOKit) might decide to substitute it in ways
 * that are difficult to predict for the programmer.
 *
 * @param entry         the entry to validate
 * @param addr          the supposed start address
 * @param size          the supposed size of the entry
 * @param guard         the guard to use to "authenticate" the allocation.
 */
extern void kmem_entry_validate_guard(
	vm_map_t                map,
	struct vm_map_entry    *entry,
	vm_offset_t             addr,
	vm_size_t               size,
	kmem_guard_t            guard);

/*!
 * @function kmem_size_guard()
 *
 * @brief
 * Returns the size of an atomic kalloc allocation made in the specified map,
 * according to the guard.
 *
 * @param map           a kernel map to lookup the entry into.
 * @param addr          the kernel address to lookup.
 * @param guard         the guard to use to "authenticate" the allocation.
 */
extern vm_size_t kmem_size_guard(
	vm_map_t                map,
	vm_offset_t             addr,
	kmem_guard_t            guard);

#pragma mark kmem allocations

/*!
 * @typedef kma_flags_t
 *
 * @brief
 * Flags used by the @c kmem_alloc* family of flags.
 */
__options_decl(kma_flags_t, uint32_t, {
	KMA_NONE            = KMEM_NONE,

	/* Call behavior */
	KMA_NOFAIL          = KMEM_NOFAIL,
	KMA_NOPAGEWAIT      = KMEM_NOPAGEWAIT,

	/* How the entry is populated */
	KMA_VAONLY          = KMEM_VAONLY,
	KMA_PAGEABLE        = KMEM_PAGEABLE,
	KMA_ZERO            = KMEM_ZERO,

	/* VM object to use for the entry */
	KMA_KOBJECT         = KMEM_KOBJECT,
	KMA_COMPRESSOR      = KMEM_COMPRESSOR,

	/* How to look for addresses */
	KMA_LOMEM           = KMEM_LOMEM,
	KMA_LAST_FREE       = KMEM_LAST_FREE,
	KMA_DATA            = KMEM_DATA,
	KMA_SPRAYQTN        = KMEM_SPRAYQTN,

	/* Entry properties */
	KMA_PERMANENT       = KMEM_PERMANENT,
	KMA_GUARD_FIRST     = KMEM_GUARD_FIRST,
	KMA_GUARD_LAST      = KMEM_GUARD_LAST,
	KMA_KSTACK          = KMEM_KSTACK,
	KMA_NOENCRYPT       = KMEM_NOENCRYPT,
	KMA_KASAN_GUARD     = KMEM_KASAN_GUARD,
	KMA_TAG             = KMEM_TAG,
});


/*!
 * @function kmem_alloc_guard()
 *
 * @brief
 * Master entry point for allocating kernel memory.
 *
 * @param map           map to allocate into, must be a kernel map.
 * @param size          the size of the entry to allocate, must not be 0.
 * @param mask          an alignment mask that the returned allocation
 *                      will be aligned to (ignoring guards, see @const
 *                      KMEM_GUARD_FIRST).
 * @param flags         a set of @c KMA_* flags, (@see @c kmem_flags_t)
 * @param guard         how to guard the allocation.
 *
 * @returns
 *     - the non zero address of the allocaation on success in @c kmr_address.
 *     - @c KERN_NO_SPACE if the target map is out of address space.
 *     - @c KERN_RESOURCE_SHORTAGE if the kernel is out of pages.
 */
extern kmem_return_t kmem_alloc_guard(
	vm_map_t                map,
	vm_size_t               size,
	vm_offset_t             mask,
	kma_flags_t             flags,
	kmem_guard_t            guard) __result_use_check;

static inline kern_return_t
kernel_memory_allocate(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size,
	vm_offset_t             mask,
	kma_flags_t             flags,
	vm_tag_t                tag)
{
	kmem_guard_t guard = {
		.kmg_tag = tag,
	};
	kmem_return_t kmr;

	kmr = kmem_alloc_guard(map, size, mask, flags, guard);
	if (kmr.kmr_return == KERN_SUCCESS) {
		__builtin_assume(kmr.kmr_address != 0);
	} else {
		__builtin_assume(kmr.kmr_address == 0);
	}
	*addrp = kmr.kmr_address;
	return kmr.kmr_return;
}

static inline kern_return_t
kmem_alloc(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size,
	kma_flags_t             flags,
	vm_tag_t                tag)
{
	return kernel_memory_allocate(map, addrp, size, 0, flags, tag);
}

/*!
 * @function kmem_alloc_contig_guard()
 *
 * @brief
 * Variant of kmem_alloc_guard() that allocates a contiguous range
 * of physical memory.
 *
 * @param map           map to allocate into, must be a kernel map.
 * @param size          the size of the entry to allocate, must not be 0.
 * @param mask          an alignment mask that the returned allocation
 *                      will be aligned to (ignoring guards, see @const
 *                      KMEM_GUARD_FIRST).
 * @param max_pnum      The maximum page number to allocate, or 0.
 * @param pnum_mask     A page number alignment mask for the first allocated
 *                      page, or 0.
 * @param flags         a set of @c KMA_* flags, (@see @c kmem_flags_t)
 * @param guard         how to guard the allocation.
 *
 * @returns
 *     - the non zero address of the allocaation on success in @c kmr_address.
 *     - @c KERN_NO_SPACE if the target map is out of address space.
 *     - @c KERN_RESOURCE_SHORTAGE if the kernel is out of pages.
 */
extern kmem_return_t kmem_alloc_contig_guard(
	vm_map_t                map,
	vm_size_t               size,
	vm_offset_t             mask,
	ppnum_t                 max_pnum,
	ppnum_t                 pnum_mask,
	kma_flags_t             flags,
	kmem_guard_t            guard);

static inline kern_return_t
kmem_alloc_contig(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size,
	vm_offset_t             mask,
	ppnum_t                 max_pnum,
	ppnum_t                 pnum_mask,
	kma_flags_t             flags,
	vm_tag_t                tag)
{
	kmem_guard_t guard = {
		.kmg_tag = tag,
	};
	kmem_return_t kmr;

	kmr = kmem_alloc_contig_guard(map, size, mask,
	    max_pnum, pnum_mask, flags, guard);
	if (kmr.kmr_return == KERN_SUCCESS) {
		__builtin_assume(kmr.kmr_address != 0);
	} else {
		__builtin_assume(kmr.kmr_address == 0);
	}
	*addrp = kmr.kmr_address;
	return kmr.kmr_return;
}


/*!
 * @typedef kms_flags_t
 *
 * @brief
 * Flags used by @c kmem_suballoc.
 */
__options_decl(kms_flags_t, uint32_t, {
	KMS_NONE            = KMEM_NONE,

	/* Call behavior */
	KMS_NOFAIL          = KMEM_NOFAIL,

	/* How to look for addresses */
	KMS_LAST_FREE       = KMEM_LAST_FREE,
	KMS_DATA            = KMEM_DATA,

	/* Entry properties */
	KMS_PERMANENT       = KMEM_PERMANENT,
});

/*!
 * @function kmem_suballoc()
 *
 * @brief
 * Create a kernel submap, in an atomic entry guarded with KMEM_GUARD_SUBMAP.
 *
 * @param parent        map to allocate into, must be a kernel map.
 * @param addr          (in/out) the address for the map (see vm_map_enter)
 * @param size          the size of the entry to allocate, must not be 0.
 * @param vmc_options   the map creation options
 * @param vm_flags      a set of @c VM_FLAGS_* flags
 * @param flags         a set of @c KMS_* flags, (@see @c kmem_flags_t)
 * @param tag           the tag for this submap's entry.
 */
extern kmem_return_t kmem_suballoc(
	vm_map_t                parent,
	mach_vm_offset_t       *addr,
	vm_size_t               size,
	vm_map_create_options_t vmc_options,
	int                     vm_flags,
	kms_flags_t             flags,
	vm_tag_t                tag);


#pragma mark kmem reallocation

/*!
 * @typedef kmr_flags_t
 *
 * @brief
 * Flags used by the @c kmem_realloc* family of flags.
 */
__options_decl(kmr_flags_t, uint32_t, {
	KMR_NONE            = KMEM_NONE,

	/* Call behavior */
	KMR_NOPAGEWAIT      = KMEM_NOPAGEWAIT,
	KMR_FREEOLD         = KMEM_FREEOLD,
	KMR_REALLOCF        = KMEM_REALLOCF,

	/* How the entry is populated */
	KMR_ZERO            = KMEM_ZERO,

	/* VM object to use for the entry */
	KMR_KOBJECT         = KMEM_KOBJECT,

	/* How to look for addresses */
	KMR_LOMEM           = KMEM_LOMEM,
	KMR_LAST_FREE       = KMEM_LAST_FREE,
	KMR_DATA            = KMEM_DATA,
	KMR_SPRAYQTN        = KMEM_SPRAYQTN,

	/* Entry properties */
	KMR_GUARD_FIRST     = KMEM_GUARD_FIRST,
	KMR_GUARD_LAST      = KMEM_GUARD_LAST,
	KMR_KASAN_GUARD     = KMEM_KASAN_GUARD,
	KMR_TAG             = KMEM_TAG,
});

#define KMEM_REALLOC_FLAGS_VALID(flags) \
	(((flags) & (KMR_KOBJECT | KMEM_GUARD_LAST | KMEM_KASAN_GUARD)) == 0 || ((flags) & KMR_FREEOLD))

/*!
 * @function kmem_realloc_guard()
 *
 * @brief
 * Reallocates memory allocated with kmem_alloc_guard()
 *
 * @discussion
 * @c kmem_realloc_guard() either mandates a guard with atomicity set,
 * or must use KMR_DATA (this is not an implementation limitation but
 * but a security policy).
 *
 * If kmem_realloc_guard() is called for the kernel object
 * (with @c KMR_KOBJECT) or with any trailing guard page,
 * then the use of @c KMR_FREEOLD is mandatory.
 *
 * When @c KMR_FREEOLD isn't used, if the allocation was relocated
 * as opposed to be extended or truncated in place, the caller
 * must free its old mapping manually by calling @c kmem_free_guard().
 *
 * Note that if the entry is truncated, it will always be done in place.
 *
 *
 * @param map           map to allocate into, must be a kernel map.
 * @param oldaddr       the address to reallocate,
 *                      passing 0 means @c kmem_alloc_guard() will be called.
 * @param oldsize       the current size of the entry
 * @param newsize       the new size of the entry,
 *                      0 means kmem_free_guard() will be called.
 * @param flags         a set of @c KMR_* flags, (@see @c kmem_flags_t)
 *                      the exact same set of @c KMR_GUARD_* flags must
 *                      be passed for all calls (@see kmem_flags_t).
 * @param guard         the allocation guard.
 *
 * @returns
 *     - the newly allocated address on success in @c kmr_address
 *       (note that if newsize is 0, then address will be 0 too).
 *     - @c KERN_NO_SPACE if the target map is out of address space.
 *     - @c KERN_RESOURCE_SHORTAGE if the kernel is out of pages.
 */
extern kmem_return_t kmem_realloc_guard(
	vm_map_t                map,
	vm_offset_t             oldaddr,
	vm_size_t               oldsize,
	vm_size_t               newsize,
	kmr_flags_t             flags,
	kmem_guard_t            guard) __result_use_check
__attribute__((diagnose_if(!KMEM_REALLOC_FLAGS_VALID(flags),
    "invalid realloc flags passed", "error")));

/*!
 * @function kmem_realloc_should_free()
 *
 * @brief
 * Returns whether the old address passed to a @c kmem_realloc_guard()
 * call without @c KMR_FREEOLD must be freed.
 *
 * @param oldaddr       the "oldaddr" passed to @c kmem_realloc_guard().
 * @param kmr           the result of that @c kmem_realloc_should_free() call.
 */
static inline bool
kmem_realloc_should_free(
	vm_offset_t             oldaddr,
	kmem_return_t           kmr)
{
	return oldaddr && oldaddr != kmr.kmr_address;
}


#pragma mark kmem free

/*!
 * @typedef kmf_flags_t
 *
 * @brief
 * Flags used by the @c kmem_free* family of flags.
 */
__options_decl(kmf_flags_t, uint32_t, {
	KMF_NONE            = KMEM_NONE,

	/* Call behavior */

	/* How the entry is populated */

	/* How to look for addresses */
	KMF_GUESS_SIZE      = KMEM_GUESS_SIZE,
	KMF_KASAN_GUARD     = KMEM_KASAN_GUARD,
	KMF_TAG             = KMEM_TAG,
});


/*!
 * @function kmem_free_guard()
 *
 * @brief
 * Frees memory allocated with @c kmem_alloc or @c kmem_realloc.
 *
 * @param map           map to free from, must be a kernel map.
 * @param addr          the address to free
 * @param size          the size of the memory to free
 * @param flags         a set of @c KMF_* flags, (@see @c kmem_flags_t)
 * @param guard         the allocation guard.
 *
 * @returns             the size of the entry that was deleted.
 *                      (useful when @c KMF_GUESS_SIZE was used)
 */
extern vm_size_t kmem_free_guard(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size,
	kmf_flags_t             flags,
	kmem_guard_t            guard);

static inline void
kmem_free(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size)
{
	kmem_free_guard(map, addr, size, KMF_NONE, KMEM_GUARD_NONE);
}

#pragma mark kmem population

extern void kernel_memory_populate_object_and_unlock(
	vm_object_t             object, /* must be locked */
	vm_address_t            addr,
	vm_offset_t             offset,
	vm_size_t               size,
	struct vm_page         *page_list,
	kma_flags_t             flags,
	vm_tag_t                tag,
	vm_prot_t               prot);

extern kern_return_t kernel_memory_populate(
	vm_offset_t             addr,
	vm_size_t               size,
	kma_flags_t             flags,
	vm_tag_t                tag);

extern void kernel_memory_depopulate(
	vm_offset_t             addr,
	vm_size_t               size,
	kma_flags_t             flags,
	vm_tag_t                tag);

#pragma GCC visibility pop
#elif KERNEL_PRIVATE /* XNU_KERNEL_PRIVATE */

extern kern_return_t kmem_alloc(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size);

extern kern_return_t kmem_alloc_pageable(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size);

extern kern_return_t kmem_alloc_kobject(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size);

extern void kmem_free(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size);

#endif /* KERNEL_PRIVATE */

#pragma mark - kernel address obfuscation / hashhing for logging

extern vm_offset_t vm_kernel_addrperm_ext;

extern void vm_kernel_addrhide(
	vm_offset_t             addr,
	vm_offset_t            *hide_addr);

extern void vm_kernel_addrperm_external(
	vm_offset_t             addr,
	vm_offset_t            *perm_addr);

extern void vm_kernel_unslide_or_perm_external(
	vm_offset_t             addr,
	vm_offset_t            *up_addr);

#if !XNU_KERNEL_PRIVATE

extern vm_offset_t vm_kernel_addrhash(
	vm_offset_t             addr);

#else /* XNU_KERNEL_PRIVATE */
#pragma GCC visibility push(hidden)

extern uint64_t vm_kernel_addrhash_salt;
extern uint64_t vm_kernel_addrhash_salt_ext;

extern vm_offset_t vm_kernel_addrhash_internal(
	vm_offset_t             addr,
	uint64_t                salt);

static inline vm_offset_t
vm_kernel_addrhash(vm_offset_t addr)
{
	return vm_kernel_addrhash_internal(addr, vm_kernel_addrhash_salt);
}

#pragma mark - kernel variants of the Mach VM interfaces

/*!
 * @function vm_map_kernel_flags_vmflags()
 *
 * @brief
 * Return the vmflags set in the specified @c vmk_flags.
 */
extern int vm_map_kernel_flags_vmflags(
	vm_map_kernel_flags_t    vmk_flags);

/*!
 * @function vm_map_kernel_flags_set_vmflags()
 *
 * @brief
 * Populates the @c vmf_* and @c vm_tag fields of the vmk flags,
 * with the specified vm flags (@c VM_FLAG_* from <mach/vm_statistics.h>).
 */
__attribute__((overloadable))
extern void vm_map_kernel_flags_set_vmflags(
	vm_map_kernel_flags_t  *vmk_flags,
	int                     vm_flags,
	vm_tag_t                vm_tag);

/*!
 * @function vm_map_kernel_flags_set_vmflags()
 *
 * @brief
 * Populates the @c vmf_* and @c vm_tag fields of the vmk flags,
 * with the specified vm flags (@c VM_FLAG_* from <mach/vm_statistics.h>).
 *
 * @discussion
 * This variant takes the tag from the top byte of the flags.
 */
__attribute__((overloadable))
extern void vm_map_kernel_flags_set_vmflags(
	vm_map_kernel_flags_t  *vmk_flags,
	int                     vm_flags_and_tag);

/*!
 * @function vm_map_kernel_flags_and_vmflags()
 *
 * @brief
 * Apply a mask to the vmflags.
 */
extern void vm_map_kernel_flags_and_vmflags(
	vm_map_kernel_flags_t   *vmk_flags,
	int                      vm_flags_mask);

/*!
 * @function vm_map_kernel_flags_check_vmflags()
 *
 * @brief
 * Returns whether the @c vmk_flags @c vmf_* fields
 * are limited to the specified mask.
 */
extern bool vm_map_kernel_flags_check_vmflags(
	vm_map_kernel_flags_t   vmk_flags,
	int                     vm_flags_mask);


extern kern_return_t    mach_vm_allocate_kernel(
	vm_map_t                map,
	mach_vm_offset_t        *addr,
	mach_vm_size_t          size,
	int                     flags,
	vm_tag_t                tag);

extern kern_return_t mach_vm_map_kernel(
	vm_map_t                target_map,
	mach_vm_offset_t        *address,
	mach_vm_size_t          initial_size,
	mach_vm_offset_t        mask,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	vm_object_offset_t      offset,
	boolean_t               copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);


extern kern_return_t mach_vm_remap_kernel(
	vm_map_t                target_map,
	mach_vm_offset_t        *address,
	mach_vm_size_t          size,
	mach_vm_offset_t        mask,
	int                     flags,
	vm_tag_t                tag,
	vm_map_t                src_map,
	mach_vm_offset_t        memory_address,
	boolean_t               copy,
	vm_prot_t               *cur_protection,
	vm_prot_t               *max_protection,
	vm_inherit_t            inheritance);

extern kern_return_t mach_vm_remap_new_kernel(
	vm_map_t                target_map,
	mach_vm_offset_t        *address,
	mach_vm_size_t          size,
	mach_vm_offset_t        mask,
	int                     flags,
	vm_tag_t                tag,
	vm_map_t                src_map,
	mach_vm_offset_t        memory_address,
	boolean_t               copy,
	vm_prot_t               *cur_protection,
	vm_prot_t               *max_protection,
	vm_inherit_t            inheritance);

extern kern_return_t mach_vm_wire_kernel(
	vm_map_t                map,
	mach_vm_offset_t        start,
	mach_vm_size_t          size,
	vm_prot_t               access,
	vm_tag_t                tag);

extern kern_return_t vm_map_wire_kernel(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_prot_t               caller_prot,
	vm_tag_t                tag,
	boolean_t               user_wire);

extern kern_return_t memory_object_iopl_request(
	ipc_port_t              port,
	memory_object_offset_t  offset,
	upl_size_t              *upl_size,
	upl_t                   *upl_ptr,
	upl_page_info_array_t   user_page_list,
	unsigned int            *page_list_count,
	upl_control_flags_t     *flags,
	vm_tag_t                tag);

#ifdef MACH_KERNEL_PRIVATE

extern kern_return_t copyinmap(
	vm_map_t                map,
	vm_map_offset_t         fromaddr,
	void                    *todata,
	vm_size_t               length);

extern kern_return_t copyoutmap(
	vm_map_t                map,
	void                    *fromdata,
	vm_map_offset_t         toaddr,
	vm_size_t               length);

extern kern_return_t copyoutmap_atomic32(
	vm_map_t                map,
	uint32_t                value,
	vm_map_offset_t         toaddr);

extern kern_return_t copyoutmap_atomic64(
	vm_map_t                map,
	uint64_t                value,
	vm_map_offset_t         toaddr);

#endif /* MACH_KERNEL_PRIVATE */
#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */
#ifdef KERNEL_PRIVATE
#pragma mark - unsorted interfaces

#ifdef XNU_KERNEL_PRIVATE
typedef struct vm_allocation_site kern_allocation_name;
typedef kern_allocation_name * kern_allocation_name_t;
#else /* XNU_KERNEL_PRIVATE */
struct kern_allocation_name;
typedef struct kern_allocation_name * kern_allocation_name_t;
#endif /* !XNU_KERNEL_PRIVATE */

extern kern_allocation_name_t   kern_allocation_name_allocate(const char * name, uint16_t suballocs);
extern void                     kern_allocation_name_release(kern_allocation_name_t allocation);
extern const char *             kern_allocation_get_name(kern_allocation_name_t allocation);

#endif  /* KERNEL_PRIVATE */
#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

extern void                     kern_allocation_update_size(kern_allocation_name_t allocation, int64_t delta, vm_object_t object);
extern void                     kern_allocation_update_subtotal(kern_allocation_name_t allocation, uint32_t subtag, int64_t delta);
extern vm_tag_t                 kern_allocation_name_get_vm_tag(kern_allocation_name_t allocation);

struct mach_memory_info;
extern kern_return_t    vm_page_diagnose(
	struct mach_memory_info *info,
	unsigned int            num_info,
	uint64_t                zones_collectable_bytes,
	bool                    redact_info);

extern uint32_t         vm_page_diagnose_estimate(void);

extern void vm_init_before_launchd(void);

typedef enum {
	PMAP_FEAT_UEXEC = 1
} pmap_feature_flags_t;

#if defined(__x86_64__)
extern bool             pmap_supported_feature(pmap_t pmap, pmap_feature_flags_t feat);
#endif

#if DEBUG || DEVELOPMENT
typedef struct {
	vm_map_size_t meta_sz;
	vm_map_size_t pte_sz;
	vm_map_size_t total_va;
	vm_map_size_t total_used;
} kmem_gobj_stats;

extern kern_return_t    vm_kern_allocation_info(uintptr_t addr, vm_size_t * size, vm_tag_t * tag, vm_size_t * zone_size);
extern kmem_gobj_stats  kmem_get_gobj_stats(void);

#endif /* DEBUG || DEVELOPMENT */

#if HIBERNATION
extern void             hibernate_rebuild_vm_structs(void);
#endif /* HIBERNATION */

extern vm_tag_t         vm_tag_bt(void);

extern vm_tag_t         vm_tag_alloc(vm_allocation_site_t * site);

extern void             vm_tag_alloc_locked(vm_allocation_site_t * site, vm_allocation_site_t ** releasesiteP);

extern void             vm_tag_update_size(vm_tag_t tag, int64_t size, vm_object_t object);

extern uint64_t         vm_tag_get_size(vm_tag_t tag);

#if VM_TAG_SIZECLASSES

extern void             vm_allocation_zones_init(void);
extern vm_tag_t         vm_tag_will_update_zone(vm_tag_t tag, uint32_t zidx, uint32_t zflags);
extern void             vm_tag_update_zone_size(vm_tag_t tag, uint32_t zidx, long delta);

#endif /* VM_TAG_SIZECLASSES */

extern vm_tag_t         vm_tag_bt_debug(void);

extern uint32_t         vm_tag_get_kext(vm_tag_t tag, char * name, vm_size_t namelen);

extern boolean_t        vm_kernel_map_is_kernel(vm_map_t map);

extern ppnum_t          kernel_pmap_present_mapping(uint64_t vaddr, uint64_t * pvincr, uintptr_t * pvphysaddr);

#pragma GCC visibility pop
#endif  /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _VM_VM_KERN_H_ */
