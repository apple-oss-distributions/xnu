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

#ifndef _VM_VM_KERN_XNU_H_
#define _VM_VM_KERN_XNU_H_

#include <sys/cdefs.h>
#include <vm/vm_kern.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)
#ifdef XNU_KERNEL_PRIVATE


#pragma mark - the kmem subsystem

/*
 * "kmem" is a set of methods that provide interfaces suitable
 * to allocate memory from the VM in the kernel map or submaps.
 *
 * It provide leaner alternatives to some of the VM functions,
 * closer to a typical allocator.
 */

struct mach_memory_info;
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
 * @const KMEM_NOSOFTLIMIT (alloc, realloc)
 *  Kernel private.
 *  Override soft allocation size limits and attempt to make the allocation
 *  anyways.
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
 * @const KMEM_GUARD_FIRST (alloc, realloc, free)
 * @const KMEM_GUARD_LAST (alloc, realloc, free)
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
 *	Note that if @c kmem_realloc* or @c kmem_free* is called, the *exact*
 *	same guard flags must be passed for this entry. The KMEM subsystem
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
	KMEM_NOSOFTLIMIT    = 0x00000010,

	/* How the entry is populated */
	KMEM_VAONLY         = 0x00000020,
	KMEM_PAGEABLE       = 0x00000040,
	KMEM_ZERO           = 0x00000080,

	/* VM object to use for the entry */
	KMEM_KOBJECT        = 0x00000100,
	KMEM_COMPRESSOR     = 0x00000200,

	/* How to look for addresses */
	KMEM_LOMEM          = 0x00001000,
	KMEM_LAST_FREE      = 0x00002000,
	KMEM_GUESS_SIZE     = 0x00004000,
	KMEM_DATA           = 0x00008000,
	KMEM_DATA_SHARED    = 0x00010000,
	KMEM_SPRAYQTN       = 0x00020000,

	/* Entry properties */
	KMEM_PERMANENT      = 0x00200000,
	KMEM_GUARD_FIRST    = 0x00400000,
	KMEM_GUARD_LAST     = 0x00800000,
	KMEM_KSTACK         = 0x01000000,
	KMEM_NOENCRYPT      = 0x02000000,
	KMEM_KASAN_GUARD    = 0x04000000,
	KMEM_TAG            = 0x08000000,
});


/*
 * @function kmem_range_id_size
 *
 * @abstract Return the addressable size of the memory range.
 */
__pure2
extern vm_map_size_t kmem_range_id_size(
	kmem_range_id_t         range_id);

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
	KMA_NOSOFTLIMIT     = KMEM_NOSOFTLIMIT,

	/* VM object to use for the entry */
	KMA_KOBJECT         = KMEM_KOBJECT,
	KMA_COMPRESSOR      = KMEM_COMPRESSOR,

	/* How to look for addresses */
	KMA_LOMEM           = KMEM_LOMEM,
	KMA_LAST_FREE       = KMEM_LAST_FREE,
	KMA_DATA            = KMEM_DATA,
	KMA_DATA_SHARED     = KMEM_DATA_SHARED,
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
	KMS_NOSOFTLIMIT     = KMEM_NOSOFTLIMIT,

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
	KMR_DATA_SHARED     = KMEM_DATA_SHARED,
	KMR_SPRAYQTN        = KMEM_SPRAYQTN,

	/* Entry properties */
	KMR_GUARD_FIRST     = KMEM_GUARD_FIRST,
	KMR_GUARD_LAST      = KMEM_GUARD_LAST,
	KMR_KASAN_GUARD     = KMEM_KASAN_GUARD,
	KMR_TAG             = KMEM_TAG,
});

#define KMEM_REALLOC_FLAGS_VALID(flags) \
	(((flags) & (KMR_KOBJECT | KMEM_GUARD_LAST | KMEM_KASAN_GUARD | KMR_DATA)) == KMR_DATA \
	|| ((flags) & (KMR_KOBJECT | KMEM_GUARD_LAST | KMEM_KASAN_GUARD | KMR_DATA_SHARED)) == KMR_DATA_SHARED \
	|| ((flags) & KMR_FREEOLD))

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

	/* Entry properties */
	KMF_GUARD_FIRST     = KMEM_GUARD_FIRST,
	KMF_GUARD_LAST      = KMEM_GUARD_LAST,
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

__attribute__((overloadable))
static inline void
kmem_free(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size,
	kmf_flags_t             flags)
{
	kmem_free_guard(map, addr, size, flags, KMEM_GUARD_NONE);
}

__attribute__((overloadable))
static inline void
kmem_free(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size)
{
	kmem_free(map, addr, size, KMF_NONE);
}


#pragma mark kmem population

/*!
 * @function kernel_memory_populate()
 *
 * @brief
 * Populate pages for a given kernel map allocation.
 *
 * @discussion
 * Allocations made against the kernel object (@c KMEM_KOBJECT)
 * or the compressor object (@c KMEM_COMPRESSOR) must have their
 * backing store explicitly managed by clients.
 *
 * This function will cause pages in the specified range to be allocated
 * explicitly. No page must have been allocated for that range at this time,
 * either because the allocation was done with @c KMEM_VAONLY or because pages
 * were explicitly depopulated.
 *
 * @param addr          the aligned starting address to populate.
 * @param size          the aligned size of the region to populate.
 * @param flags         a set flags that must match the flags passed at
 *                      @c kmem_alloc*() time.  In particular, one of
 *                      @c KMA_KOBJECT or @c KMA_COMPRESSOR must be passed.
 * @param tag           the kernel memory tag to use for accounting purposes.
 * @returns
 * - KERN_SUCCESS       the operation succeeded.
 * - KERN_RESOURCE_SHORTAGE
 *                      the kernel was out of physical pages.
 */
extern kern_return_t kernel_memory_populate(
	vm_offset_t             addr,
	vm_size_t               size,
	kma_flags_t             flags,
	vm_tag_t                tag);


/*!
 * @function kernel_memory_depopulate()
 *
 * @brief
 * Depopulate pages for a given kernel map allocation.
 *
 * @discussion
 * Allocations made against the kernel object (@c KMEM_KOBJECT)
 * or the compressor object (@c KMEM_COMPRESSOR) must have their
 * backing store explicitly managed by clients.
 *
 * This function will cause pages in the specified range to be deallocated
 * explicitly. This range must be populated at the time of the call, either
 * because the @c kmem_alloc*() call asked for pages, or because
 * @c kernel_memory_populate() has been called explicitly.
 *
 * It is not necessary to explicitly depopulate ranges prior to calling
 * @c kmem_free*(), even if populating the range was made explicitly with
 * @c kernel_memory_populate() rather than implicitly at allocation time.
 *
 *
 * @param addr          the aligned starting address to depopulate.
 * @param size          the aligned size of the region to depopulate.
 * @param flags         a set flags that must match the flags passed at
 *                      @c kmem_alloc*() time.  In particular, one of
 *                      @c KMA_KOBJECT or @c KMA_COMPRESSOR must be passed.
 * @param tag           the kernel memory tag to use for accounting purposes,
 *                      which must match the tag used for population.
 */
extern void kernel_memory_depopulate(
	vm_offset_t             addr,
	vm_size_t               size,
	kma_flags_t             flags,
	vm_tag_t                tag);


#pragma mark - VM_FLAGS_* / vm_map_kernel_flags_t conversions

/*!
 * @function vm_map_kernel_flags_vmflags()
 *
 * @return The vmflags set in the specified @c vmk_flags.
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
 * @return
 * Whether the @c vmk_flags @c vmf_* fields
 * are limited to the specified mask.
 */
extern bool vm_map_kernel_flags_check_vmflags(
	vm_map_kernel_flags_t   vmk_flags,
	int                     vm_flags_mask);

/*!
 * @function vm_map_kernel_flags_check_vm_and_kflags()
 *
 * @return
 * Whether the @c vmk_flags @c vmf_* fields
 * are limited to the specified mask.
 */
extern bool vm_map_kernel_flags_check_vm_and_kflags(
	vm_map_kernel_flags_t   vmk_flags,
	int                     vm_flags_mask);


#pragma mark - kernel variants of the Mach VM interfaces

/*!
 * @function mach_vm_allocate_kernel()
 *
 * @brief
 * Allocate memory in the specified map.
 *
 * @discussion
 * This is the in-kernel equivalent to the @c mach_vm_allocate() MIG call,
 * except that it takes a full set of @c vm_map_kernel_flags_t rather than
 * @c VM_FLAGS_.
 *
 * Memory will not be pre-faulted and touching it will cause page faults.
 *
 * Memory will be zero-filled when faulted, unless the map's @c no_zero_fill
 * property is set (only the @c ipc_kernel_map is marked this way).
 *
 * The allocation being made will have:
 * - @c VM_PROT_DEFAULT (rw-) current protections,
 * - @c VM_PROT_ALL (rwx) max protections,
 * - @c VM_INHERIT_COPY inheritance.
 *
 *
 * @param map           the map to allocate memory into.
 *
 * @param addr_u        [in]  when @c vmk_flags.vmf_fixed is set, @c *addr
 *                            is used as the address at which the allocation
 *                            must be made. If it is misaligned for the map's
 *                            page size, its low bits are truncated and ignored.
 *
 *                            when @c vmk_flags.vmf_fixed is not set,
 *                            the value of @c *addrp is ignored.
 *
 *                      [out] filled with the address at which the allocation
 *                            was made on success, unmodified otherwise.
 *
 *                            @c vmk_flags.vmf_return_data_addr has no effect
 *                            on the returned address.
 *
 * @param size_u        the size of the allocation to make. zero sizes are
 *                      allowed and result in @c *addr being zero.
 *
 *                      misaligned sizes for the page size of the target map
 *                      will be rounded up to the nearest page size.
 *
 * @param vmk_flags     a set of flags that influence the properties of the
 *                      allocation being made.
 *
 * @returns             KERN_SUCCESS when the operation succeeds,
 *                      or an error denoting the reason for failure.
 */
extern kern_return_t    mach_vm_allocate_kernel(
	vm_map_t                map,
	mach_vm_offset_ut      *addr_u,
	mach_vm_size_ut         size_u,
	vm_map_kernel_flags_t   vmk_flags);


/*!
 * @function mach_vm_map_kernel()
 *
 * @brief
 * Map some range of an object into an address space.
 *
 * @discussion
 * This is the in-kernel equivalent to the @c mach_vm_map() MIG call,
 * except that it takes a full set of @c vm_map_kernel_flags_t rather than
 * @c VM_FLAGS_.
 *
 *
 * @param target_map    the target address space.
 *
 * @param address       [in]  when @c vmk_flags.vmf_fixed is set, @c *address
 *                            is used as the address at which the allocation
 *                            must be made. If it is misaligned for the map's
 *                            page size, its low bits are truncated and ignored.
 *
 *                            when @c vmk_flags.vmf_fixed is not set,
 *                            the value of @c *address is used as a starting
 *                            point from which to scan for memory in the direction
 *                            specified by @c vmk_flags.vmkf_last_free.
 *
 *                      [out] filled with the address at which the allocation
 *                            was made on success, unmodified otherwise.
 *
 *                            if @c vmk_flags.vmf_return_data_addr is
 *                            specified, @c *address will maintain
 *                            "misalignment" from the requested @c offset
 *                            inside the object, otherwise it will be page
 *                            aligned for the target map.
 *
 * @param size          the size of the allocation to make.
 *                      zero sizes are disallowed.
 *
 * @param mask          a mask to specify the allocation alignment.
 *                      this value should be of the form (2^n-1).
 *
 *                      allocations will always at least be page aligned
 *                      for the specified target map, but this can be used to
 *                      require larger alignments.
 *
 * @param vmk_flags     a set of flags that influence the properties of the
 *                      allocation being made.
 *
 * @param port          the object to map into the target address space:
 *                      - @c IP_NULL means anonymous memory, and this call
 *                        behaves like a more versatile
 *                        mach_vm_allocate_kernel(),
 *                      - a kobject port of type @c IKOT_NAMED_ENTRY,
 *                        pointing to a @c vm_named_entry_t,
 *                      - a naked @c memory_object_t (a VM pager).
 *
 * @param offset        an offset within the specified object to map.
 *
 * @param copy          whether to make a copy-on-write (true) mapping
 *                      or a shared (false) mapping.
 *
 * @param cur_prot      the effective protections for the mapping.
 *
 * @param max_prot      the maximum protections for the mapping,
 *                      which must at least cover @c cur_prot.
 *
 * @param inheritance   the inheritance policy for the mapping.
 *
 * @returns             KERN_SUCCESS when the operation succeeds,
 *                      or an error denoting the reason for failure.
 */
extern kern_return_t    mach_vm_map_kernel(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_prot,
	vm_prot_ut              max_prot,
	vm_inherit_ut           inheritance);


/*!
 * @function mach_vm_remap_new_kernel()
 *
 * @brief
 * Remap a range of memory from one address space to another.
 *
 * @discussion
 * This is the in-kernel equivalent to the @c mach_vm_remap() MIG call,
 * except that it takes a full set of @c vm_map_kernel_flags_t rather than
 * @c VM_FLAGS_.
 *
 * This call forces vmk_flags.vmf_return_data_addr to true regardless
 * of what the caller specified.
 *
 *
 * @param target_map    the target address space.
 *
 * @param address       [in]  when @c vmk_flags.vmf_fixed is set, @c *address
 *                            is used as the address at which the allocation
 *                            must be made. If it is misaligned for the map's
 *                            page size, its low bits are truncated and ignored.
 *
 *                            when @c vmk_flags.vmf_fixed is not set,
 *                            the value of @c *address is used as a starting
 *                            point from which to scan for memory in the direction
 *                            specified by @c vmk_flags.vmkf_last_free.
 *
 *                      [out] filled with the address at which the allocation
 *                            was made on success, unmodified otherwise.
 *                            @c *address has the same "misalignment"
 *                            as @c src_address.
 *
 * @param size          the size of the region to remap.
 *
 * @param mask          a mask to specify the allocation alignment.
 *                      this value should be of the form (2^n-1).
 *
 *                      allocations will always at least be page aligned
 *                      for the specified target map, but this can be used to
 *                      require larger alignments.
 *
 * @param vmk_flags     a set of flags that influence the properties of the
 *                      allocation being made.
 *
 * @param src_map       the address space to remap the memory from.
 *
 * @param src_address   the start address within @c src_map to remap.
 *
 * @param copy          whether to make a copy-on-write (true) mapping
 *                      or a shared (false) mapping.
 *
 * @param cur_prot      [in]  for shared mappings, the minimum set of effective
 *                            permissions the source mapping must have
 *
 *                      [out] the resulting effective permissions for the mapping
 *
 * @param max_prot      [in]  for shared mappings, the minimum set of maximum
 *                            permissions the source mappings must have.
 *
 *                      [out] the resulting maximum permissions for the mapping
 *
 * @param inheritance   the inheritance policy for the mapping.
 *
 * @returns             KERN_SUCCESS when the operation succeeds,
 *                      or an error denoting the reason for failure.
 */
extern kern_return_t    mach_vm_remap_new_kernel(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_t                src_map,
	mach_vm_offset_ut       src_address,
	boolean_t               copy,
	vm_prot_ut             *cur_prot,
	vm_prot_ut             *max_prot,
	vm_inherit_ut           inheritance);

/*!
 * @function vm_map_wire_kernel()
 *
 * @brief
 * Sets the pageability of the specified address range in the
 * target map as wired.
 *
 * @discussion
 * This call is the kernel version of @c vm_map_wire(). The main difference
 * is that the caller must specify a valid @c VM_KERN_MEMORY_* tag for kernel
 * wirings, or a valid @c VM_MEMORY_* tag for user wirings.
 *
 * Consult the documentation of @c vm_map_wire() in @c <vm/vm_map.h> for details.
 */
extern kern_return_t    vm_map_wire_kernel(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	vm_tag_t                tag,
	boolean_t               user_wire);

/*!
 * @function vm_map_purgable_control()
 *
 * @brief
 * Perform a purgeability operation on a VM object at a given address
 * in an address space.
 *
 * @discussion
 * This is the in-kernel equivalent to the @c mach_vm_map_purgable_control()
 * MIG call, except that it allows all operations, including
 * @c VM_PURGABLE_*_FROM_KERNEL ones).
 *
 * Valid @c control operations and the meaning of @c state is documented
 * in @c <mach/vm_purgable.h>.
 *
 *
 * @param map           the target address space
 * @param address       the address to use to find the VM object to target
 * @param control       a purgeability operation to perform.
 * @param state         an in/out parameter that is operation dependent.
 */
extern kern_return_t vm_map_purgable_control(
	vm_map_t                map,
	vm_map_offset_ut        address,
	vm_purgable_t           control,
	int                    *state);

extern kern_return_t mach_vm_purgable_control(
	vm_map_t                map,
	mach_vm_offset_ut       address_u,
	vm_purgable_t           control,
	int                    *state);


#ifdef MACH_KERNEL_PRIVATE
#pragma mark - map copyio


/*!
 * @function copyinmap()
 *
 * @brief
 * Like copyin, except that @c fromaddr is an address in the specified VM map.
 *
 * @param map           the map @c fromaddr is relative to.
 * @param fromaddr      the address to copy from within @c map.
 * @param todata        the kernel buffer to write into.
 * @param length        the number of bytes to copy.
 * @returns
 * - KERN_SUCCESS       the copy was successful
 * - KERN_INVALID_ADDRESS
 *                      a fault occurred during copyio and couldn't be resolved
 *                      (similar to copyin returning EFAULT).
 */
extern kern_return_t     copyinmap(
	vm_map_t                map,
	vm_map_offset_t         fromaddr,
	void                   *todata __sized_by(length),
	vm_size_t               length);


/*!
 * @function copyoutmap()
 *
 * @brief
 * Like copyout, except that @c toaddr is an address in the specified VM map.
 *
 * @param map           the map @c toaddr is relative to
 * @param fromdata      the kernel buffer to copy from.
 * @param toaddr        the address within @c map to copy into
 * @param length        the number of bytes to copy.
 * @returns
 * - KERN_SUCCESS       the copy was successful
 * - KERN_INVALID_ADDRESS
 *                      a fault occurred during copyio and couldn't be resolved
 *                      (similar to copyin returning EFAULT).
 */
extern kern_return_t     copyoutmap(
	vm_map_t                map,
	void                   *fromdata __sized_by(length),
	vm_map_offset_t         toaddr,
	vm_size_t               length);


/*!
 * @function copyoutmap_atomic32()
 *
 * @brief
 * Copies out a 32bit value atomically at a given address in a specified VM map.
 *
 * @param map           the specified map.
 * @param value         the 32 bit value to write at @c toaddr.
 * @param toaddr        the address within @c map to copy into
 * @returns
 * - KERN_SUCCESS       the copy was successful
 * - KERN_INVALID_ADDRESS
 *                      a fault occurred during copyio and couldn't be resolved
 *                      (similar to copyin returning EFAULT).
 */
extern kern_return_t     copyoutmap_atomic32(
	vm_map_t                map,
	uint32_t                value,
	vm_map_offset_t         toaddr);


/*!
 * @function copyoutmap_atomic64()
 *
 * @brief
 * Copies out a 64bit value atomically at a given address in a specified VM map.
 *
 * @param map           the specified map.
 * @param value         the 64 bit value to write at @c toaddr.
 * @param toaddr        the address within @c map to copy into
 * @returns
 * - KERN_SUCCESS       the copy was successful
 * - KERN_INVALID_ADDRESS
 *                      a fault occurred during copyio and couldn't be resolved
 *                      (similar to copyin returning EFAULT).
 */
extern kern_return_t     copyoutmap_atomic64(
	vm_map_t                map,
	uint64_t                value,
	vm_map_offset_t         toaddr);


#endif /* MACH_KERNEL_PRIVATE */
#pragma mark - accounting

#pragma mark accounting: kern allocation name

/*!
 * @function kern_allocation_update_size()
 *
 * @brief
 * Update accounting for a specified kern allocation name.
 *
 * @discussion
 * This is to be called when memory gets wired/unwired in order
 * to update accounting information.
 *
 * [development kernels] If the @c vmtaglog boot-arg is used,
 * and its value matches the VM tag of this allocation name, then VM tag
 * log entries will be added on the specified object.
 *
 *
 * @param allocation    a @c kern_allocation_name_t made with
 *                      @c kern_allocation_name_allocate().
 * @param delta         the amount to update the accounting with,
 *                      positive values increment,
 *                      negative values decrement.
 * @param object        an optional object this wiring/unwiring applies to.
 */
extern void             kern_allocation_update_size(
	kern_allocation_name_t  allocation,
	int64_t                 delta,
	vm_object_t             object);


/*!
 * @function kern_allocation_update_subtotal()
 *
 * @brief
 * Update subtotal accounting for a specified kern allocation name.
 *
 * @discussion
 * IOKit uses global kern allocation names that cover the VM tags
 * (@see @c vm_tag_bt()) of several kexts and uses this to perform
 * accounting per kext within these meta accounting data structures.
 *
 * @param allocation    a @c kern_allocation_name_t made with
 *                      @c kern_allocation_name_allocate()
 *                      and a non 0 "subtotalscount".
 * @param subtag        a @c vm_tag_t subtag to update accounting for.
 * @param delta         the amount to update the accounting with,
 *                      positive values increment,
 *                      negative values decrement.
 */
extern void             kern_allocation_update_subtotal(
	kern_allocation_name_t  allocation,
	vm_tag_t                subtag,
	int64_t                 delta);


#pragma mark accounting: vm tags

/*
 * VM Tags come in 3 flavors:
 *
 * - static user VM tags, defined by the @c VM_MEMORY_* constants
 *   (@see <mach/vm_statistics.h>),
 *
 * - static kernel VM tags, defined by the @c VM_KERN_MEMORY_* constants
 *   (@see <mach/vm_statistics.h>),
 *
 * - dynamically allocated kernel VM tags typically associated with kexts
 *   lazily (as kexts wire down memory and accounting needs to be made).
 *
 * By default, kernel VM tags track wired memory at the VM layer,
 * but no insight is given to allocations done by @c kalloc*()
 * and its wrappers like @c IOMalloc*(), when backed by zone memory
 * (for sizes below @c KHEAP_MAX_SIZE).
 *
 *
 * Implementation details
 * ~~~~~~~~~~~~~~~~~~~~~~
 *
 * Static tags are limited to values from 0 to 255, as they are passed
 * in the bits reserved by the @c VM_FLAGS_ALIAS_MASK of VM flags.
 *
 * However, dynamic flags are an internal kernel concept which is limited
 * by the size of the storage in VM map entries, which reserves
 * @c VME_ALIAS_BITS (12) for this, effectively limiting dynamic
 * tags to about 4000.
 *
 * @c [VM_KERN_MEMORY_FIRST_DYNAMIC, VM_MAX_TAG_VALUE) defines the range of
 * possible values for dynamic tags.
 *
 *
 * Zone accounting [development kernels]
 * ~~~~~~~~~~~~~~~
 *
 * On development kernels the "-zt" boot-arg can be used, in which case
 * precise accounting of @c kalloc*() allocations is enabled per bucket,
 * which can be observed by the @c zprint(1) command.
 *
 * This effectively makes accounting a vector composed of @c VM_TAG_SIZECLASSES
 * possible zone size classes in addition to the regular VM wired memory
 * accounting that is always performed.
 *
 * The tag for which an allocation is recorded will be (in first hit order):
 *
 * - the tag specified as part of the @c zalloc_flags_t explicitly
 *   (@see @c kalloc_*_tag() or @c Z_VM_TAG()). In core XNU, non @c _tag
 *   variants of @c kalloc*() will generate a per-call site dynamic VM tag,
 *   using the @c VM_ALLOC_SITE_TAG() macro,
 *
 * - if the allocation was made by a kernel extension, the dynamic VM tag
 *   for this extension (@see @c vm_tag_bt()),
 *
 * - as a fallback:
 *     o @c VM_KERN_MEMORY_KALLOC_DATA for @c kalloc_data() calls,
 *     o @c VM_KERN_MEMORY_KALLOC_TYPE for @c kalloc_type() calls,
 *     o @c VM_KERN_MEMORY_KALLOC for legacy @c kalloc() calls.
 */

/*!
 * @brief
 * Lock used to serialize the @c vm_tag_alloc() operation, used by IOKit.
 */
extern lck_ticket_t     vm_allocation_sites_lock;


/*!
 * @function vm_tag_bt()
 *
 * @brief
 * Returns the dynamic kernel extension tag based on backtracing from this call.
 *
 * @discussion
 * This function will lazily allocate a dynamic tag for the current kernel
 * extension based on the backtrace, and then return a stable identifier.
 *
 * This might fail for cases where the kernel is out of dynamic tags.
 *
 *
 * @returns             A dynamic kernel extension tag within
 *                      @c [VM_KERN_MEMORY_FIRST_DYNAMIC, VM_MAX_TAG_VALUE),
 *                      or @c VM_KERN_MEMORY_NONE if the call was not made
 *                      from a kernel extension, or allocating a dynamic tag
 *                      for it failed.
 */
extern vm_tag_t         vm_tag_bt(void);


/*!
 * @function vm_tag_alloc()
 *
 * @brief
 * Lazily allocates a dynamic VM tag for a given allocation site.
 *
 * @description
 * This is used by IOKit and the zalloc subsystem to generate dynamic VM tags
 * for kernel extensions (@see vm_tag_bt()) or core kernel @c kalloc*()
 * call sites (@see VM_ALLOC_SITE_TAG()).
 *
 *
 * @param site          the allocation site to generate a tag for.
 * @returns             A dynamic kernel extension tag within
 *                      @c [VM_KERN_MEMORY_FIRST_DYNAMIC, VM_MAX_TAG_VALUE),
 *                      or @c VM_KERN_MEMORY_NONE if the kernel
 *                      is out of dynamic tags.
 */
extern vm_tag_t         vm_tag_alloc(
	vm_allocation_site_t   *site);

/*!
 * @function vm_tag_alloc_locked()
 *
 * @brief
 * Lazily allocates a dynamic VM tag for a given allocation site,
 * while the caller holds the @c vm_allocation_sites_lock lock.
 *
 * @description
 * This is used by IOKit to generate dynamic VM tags for kernel extensions
 * (@see vm_tag_bt()).
 *
 *
 * @param site          the allocation site to generate a tag for.
 * @param releasesiteP  an optional allocation site data structure
 *                      that the caller is responsible for releasing
 *                      with @c kern_allocation_name_release().
 */
extern void             vm_tag_alloc_locked(
	vm_allocation_site_t   *site,
	vm_allocation_site_t  **releasesiteP);


/*!
 * @function vm_tag_update_size()
 *
 * @brief
 * Update accounting for a specified VM kernel tag (static or dynamic).
 *
 * @discussion
 * This is to be called when memory gets wired/unwired in order
 * to update accounting information for a given tag.
 *
 * [development kernels] If the @c vmtaglog boot-arg is used,
 * and its value matches the VM tag of this allocation name, then VM tag
 * log entries will be added on the specified object.
 *
 *
 * @param tag           A non @c VM_KERN_MEMORY_NONE VM kernel tag.
 * @param delta         the amount to update the accounting with,
 *                      positive values increment,
 *                      negative values decrement.
 * @param object        an optional object this wiring/unwiring applies to.
 */
extern void             vm_tag_update_size(
	vm_tag_t                tag,
	int64_t                 delta,
	vm_object_t             object);


/*!
 * @function vm_tag_get_size()
 *
 * @brief
 * Returns how much wired memory is accounted for the specified VM kernel tag.
 *
 *
 * @param tag           A non @c VM_KERN_MEMORY_NONE VM kernel tag.
 * @returns             the amount of wired memory for the specified tag.
 */
extern uint64_t         vm_tag_get_size(
	vm_tag_t                tag);

#if VM_TAG_SIZECLASSES

/*!
 * @function vm_tag_will_update_zone()
 *
 * @brief
 * Lazily allocate the vector of zone-level accounting for a given VM tag.
 *
 * @discussion
 * This is to be called when memory gets wired/unwired in order
 * to update accounting information for a given tag.
 *
 * This function might fail when the first time it is called is
 * for a @c Z_NOWAIT allocation. However this is transient and
 * will always eventually resolve. Once the data structure is allocated,
 * this function always succeeds. The consequence is a slight misaccounting
 * of a few allocations.
 *
 * This call will never fail for the following tags that are always
 * pre-allocated:
 * - @c VM_KERN_MEMORY_DIAG,
 * - @c VM_KERN_MEMORY_KALLOC,
 * - @c VM_KERN_MEMORY_KALLOC_DATA,
 * - @c VM_KERN_MEMORY_KALLOC_TYPE,
 * - @c VM_KERN_MEMORY_LIBKERN,
 * - @c VM_KERN_MEMORY_OSFMK,
 * - @c VM_KERN_MEMORY_RECOUNT.
 *
 * Note that this function isn't called if the "-zt" boot-arg isn't set.
 *
 * @param tag           A non @c VM_KERN_MEMORY_NONE VM kernel tag.
 * @param zflags        the @c zalloc_flags_t passed to the current
 *                      @c kalloc*() call.
 *
 * @returns             @c tag if the allocation was successful,
 *                      @c VM_KERN_MEMORY_NONE if the accounting
 *                      data structure couldn't be allocated.
 */
extern vm_tag_t         vm_tag_will_update_zone(
	vm_tag_t                tag,
	uint32_t                zflags);


/*!
 * @function vm_tag_update_zone_size()
 *
 * @brief
 * Update the per size class zone level accounting for a given kernel VM tag.
 *
 * @discussion
 * Note that this function isn't called if the "-zt" boot-arg isn't set.
 *
 * @param tag           A non @c VM_KERN_MEMORY_NONE VM kernel tag.
 * @param size_class    the zone size class index to account against
 *                      (@see zone_t::z_tags_sizeclass).
 * @param delta         the amount to update the accounting with,
 *                      positive values increment,
 *                      negative values decrement.
 */
extern void             vm_tag_update_zone_size(
	vm_tag_t                tag,
	uint32_t                size_class,
	long                    delta);

#endif /* VM_TAG_SIZECLASSES */

#pragma mark accounting: diagnostics and query interfaces

/*!
 * @function vm_page_diagnose_estimate()
 *
 * @brief
 * Estimate how many @c mach_memory_info_t structures
 * are needed in order to return information about VM kernel tags,
 * and per size class zone level accounting when enabled.
 */
extern uint32_t         vm_page_diagnose_estimate(void);


/*!
 * @function vm_page_diagnose()
 *
 * @brief
 * Fills out a @c mach_memory_info_t array of information about VM tags
 * and per size class zone level information.
 *
 * @param info          a pointer to an array of @c num_info Mach memory
 *                      info data structures to fill.
 * @param num_info      the number of entries in the @c info array.
 * @param zones_collectable_bytes
 *                      how much memory is collectable in the zone subsystem
 *                      if a @c zone_gc() was running right now.
 * @param redact_info   whether information that could leak the type to bucket
 *                      mapping in @c kalloc_type() can be returned or not.
 *
 * @returns
 * - KERN_SUCCESS       the call was successful.
 * - KERN_ABORTED       the accounting subsytem isn't inititalized yet.
 */
extern kern_return_t    vm_page_diagnose(
	struct mach_memory_info *info __counted_by(num_info),
	unsigned int            num_info,
	uint64_t                zones_collectable_bytes,
	bool                    redact_info);

#if DEBUG || DEVELOPMENT

/*!
 * @typedef kmem_gobj_stats
 *
 * @brief
 * Statistics about the "guard objects" allocator for the pointer ranges
 * of kmem.
 */
typedef struct {
	vm_map_size_t meta_sz;        /**< total faulted size of metadata */
	vm_map_size_t pte_sz;         /**< total faulted leaf PTE size    */
	vm_map_size_t total_va;       /**< total amount of VA ever used   */
	vm_map_size_t total_used;     /**< current amount of VA allocated */
} kmem_gobj_stats;


/*!
 * @function kmem_get_gobj_stats()
 *
 * @brief
 * Returns statistics about the guard objects allocator.
 *
 * @description
 * This is the backend of the @c vm.kmem_gobj_stats sysctl.
 */
extern kmem_gobj_stats  kmem_get_gobj_stats(void);


/*!
 * @function vm_kern_allocation_info()
 *
 * @brief
 * Returns information about a given kernel heap allocation.
 *
 *
 * @param [in]  addr    the heap allocation pointer.
 * @param [out] size    a guess at the size of this allocation.
 * @param [out] tag     the kernel VM tag for this allocation
 *                      (only filled if the "-zt" boot-arg is set
 *                      for zone allocations)
 * @param [out] zone_size
 *                      the zone size class if the allocation
 *                      is from a zone, 0 for VM.
 *
 * @returns
 * - KERN_SUCCESS       if a guess could be made about this pointer.
 * - KERN_INVALID_ADDRESS
 *                      if the address couldn't be resolved in the kernel heap.
 */
extern kern_return_t    vm_kern_allocation_info(
	uintptr_t               addr,
	vm_size_t              *size,
	vm_tag_t               *tag,
	vm_size_t              *zone_size);

#endif /* DEBUG || DEVELOPMENT */

#pragma mark - init methods

/*!
 * @function vm_init_before_launchd()
 *
 * @brief
 * Memorize how many wired pages were used at boot before launchd starts.
 *
 * @discussion
 * The captured number can be seen as the @c VM_KERN_COUNT_WIRED_BOOT value
 * in the output of @c zprint(1).
 */
extern void             vm_init_before_launchd(void);

#if VM_TAG_SIZECLASSES

/*!
 * @function vm_allocation_zones_init()
 *
 * @brief
 * Initialize the per-zone accounting tags subsystem
 * if the "-zt" boot-arg is present.
 */
extern void             vm_allocation_zones_init(void);

#endif /* VM_TAG_SIZECLASSES */

extern memory_object_t device_pager_setup(memory_object_t, uintptr_t, vm_size_t, int);

extern kern_return_t device_pager_populate_object( memory_object_t device,
    memory_object_offset_t offset, ppnum_t page_num, vm_size_t size);

#endif /* XNU_KERNEL_PRIVATE */
#pragma GCC visibility pop
__END_DECLS

#endif  /* _VM_VM_KERN_XNU_H_ */
