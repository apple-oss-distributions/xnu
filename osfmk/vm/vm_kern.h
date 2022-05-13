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
 * @typedef
 *
 * @brief
 * Pair of a min/max address used to denote a memory region.
 */
typedef struct kmem_range {
	vm_offset_t min_address;
	vm_offset_t max_address;
} __attribute__((aligned(2 * sizeof(vm_offset_t)))) * kmem_range_t;

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
 * @const KMEM_NOPAGEWAIT (alloc)
 *	Pass this flag if the system should not wait in VM_PAGE_WAIT().
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
 * @const KMEM_ZERO (alloc)
 *	Any new page added is zeroed.
 *
 *
 * <h2>VM object to use for the entry</h2>
 *
 * @const KMEM_KOBJECT (alloc)
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
 * @const KMEM_LOMEM (alloc)
 *	The physical memory allocated must be in the first 4G of memory,
 *	in order to support hardware controllers incapable of generating DMAs
 *	with more than 32bits of physical address.
 *
 * @const KMEM_LAST_FREE (alloc, suballoc)
 *	When looking for space in the specified map,
 *	start scanning for addresses from the end of the map
 *	rather than the start.
 *
 * @const KMEM_DATA (alloc, suballoc)
 *	The memory must be allocated from the "Data" range.
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
 * @const KMEM_GUARD_FIRST (alloc)
 * @const KMEM_GUARD_LAST (alloc)
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
 * @const KMEM_KSTACK (alloc)
 *	This flag must be passed when the allocation is for kernel stacks.
 *	This only has an effect on Intel.
 *
 * @const KMEM_NOENCRYPT (alloc)
 *	Obsolete, will be repurposed soon.
 */
__options_decl(kmem_flags_t, uint32_t, {
	KMEM_NONE           = 0x00000000,

	/* Call behavior */
	KMEM_NOFAIL         = 0x00000001,
	KMEM_NOPAGEWAIT     = 0x00000002,

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
	KMEM_DATA           = 0x00008000,

	/* Entry properties */
	KMEM_PERMANENT      = 0x00010000,
	KMEM_GUARD_FIRST    = 0x00020000,
	KMEM_GUARD_LAST     = 0x00040000,
	KMEM_KSTACK         = 0x00080000,
	KMEM_NOENCRYPT      = 0x00100000,
	KMEM_ATOMIC         = 0x40000000, /* temporary */
});


#pragma mark kmem range methods

extern struct kmem_range kmem_ranges[KMEM_RANGE_COUNT];
extern struct kmem_range kmem_large_ranges[KMEM_RANGE_COUNT];

__attribute__((overloadable))
extern bool kmem_range_contains(
	const struct kmem_range *r,
	vm_offset_t             addr);

__attribute__((overloadable))
extern bool kmem_range_contains(
	const struct kmem_range *r,
	vm_offset_t             addr,
	vm_offset_t             size);

extern vm_size_t kmem_range_size(
	const struct kmem_range *r);

extern bool kmem_range_id_contains(
	kmem_range_id_t         range_id,
	vm_map_offset_t         addr,
	vm_map_size_t           size);

extern kmem_range_id_t kmem_addr_get_range(
	vm_map_offset_t         addr,
	vm_map_size_t           size);

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
 * Security config that creates the data split in kernel_map
 */
#if !defined(__LP64__)
#   define ZSECURITY_CONFIG_KERNEL_DATA_SPLIT       OFF
#else
#   define ZSECURITY_CONFIG_KERNEL_DATA_SPLIT       ON
#endif

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
	struct kmem_range      *kc_range;
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
 * @c VM_FLAGS_FIXED_RANGE_SUBALLOC to kmem_suballoc to replace the mapping.
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

#if XNU_KERNEL_PRIVATE
#if ZSECURITY_CONFIG(KERNEL_DATA_SPLIT)
#define VM_FLAGS_FIXED_RANGE_SUBALLOC   (VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)
#else /* ZSECURITY_CONFIG(KERNEL_DATA_SPLIT) */
#define VM_FLAGS_FIXED_RANGE_SUBALLOC   (VM_FLAGS_ANYWHERE)
#endif /* !ZSECURITY_CONFIG(KERNEL_DATA_SPLIT) */
#endif /* XNU_KERNEL_PRIVATE */

__startup_func
extern uint16_t kmem_get_random16(
	uint16_t                upper_limit);

__startup_func
extern void kmem_shuffle(
	uint16_t               *shuffle_buf,
	uint16_t                count);


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

	/* Entry properties */
	KMA_PERMANENT       = KMEM_PERMANENT,
	KMA_GUARD_FIRST     = KMEM_GUARD_FIRST,
	KMA_GUARD_LAST      = KMEM_GUARD_LAST,
	KMA_KSTACK          = KMEM_KSTACK,
	KMA_NOENCRYPT       = KMEM_NOENCRYPT,
	KMA_ATOMIC          = KMEM_ATOMIC,
});

#define KMEM_ALLOC_CONTIG_FLAGS ( \
	/* Call behavior */ \
	KMA_NOPAGEWAIT | \
        \
	/* How the entry is populated */ \
	KMA_ZERO | \
        \
	/* VM object to use for the entry */ \
	KMA_KOBJECT | \
        \
	/* How to look for addresses */ \
	KMA_LOMEM | \
	KMA_DATA | \
        \
	/* Entry properties */ \
	KMA_PERMANENT | \
        \
	KMA_NONE)



extern kern_return_t    kernel_memory_allocate(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size,
	vm_offset_t             mask,
	kma_flags_t             flags,
	vm_tag_t                tag);

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

extern kern_return_t kmem_alloc_contig(
	vm_map_t                map,
	vm_offset_t            *addrp,
	vm_size_t               size,
	vm_offset_t             mask,
	ppnum_t                 max_pnum,
	ppnum_t                 pnum_mask,
	kma_flags_t             flags,
	vm_tag_t                tag)
__attribute__((diagnose_if(flags & ~KMEM_ALLOC_CONTIG_FLAGS,
    "invalid alloc_contig flags passed", "error")));


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
	vm_offset_t            *addr,
	vm_size_t               size,
	vm_map_create_options_t vmc_options,
	int                     vm_flags,
	kms_flags_t             flags,
	vm_tag_t                tag);


#pragma mark kmem reallocation

extern kern_return_t    kmem_realloc(
	vm_map_t                map,
	vm_offset_t             oldaddr,
	vm_size_t               oldsize,
	vm_offset_t             *newaddrp,
	vm_size_t               newsize,
	vm_tag_t                tag);

extern void kmem_realloc_down(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       oldsize,
	vm_size_t       newsize);

__exported
extern void             kmem_free(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               size);

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
	int                     flags,
	vm_map_kernel_flags_t   vmk_flags,
	vm_tag_t                tag,
	ipc_port_t              port,
	vm_object_offset_t      offset,
	boolean_t               copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);


extern kern_return_t vm_map_kernel(
	vm_map_t                target_map,
	vm_offset_t             *address,
	vm_size_t               size,
	vm_offset_t             mask,
	int                     flags,
	vm_map_kernel_flags_t   vmk_flags,
	vm_tag_t                tag,
	ipc_port_t              port,
	vm_offset_t             offset,
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

extern kern_return_t vm_remap_kernel(
	vm_map_t                target_map,
	vm_offset_t             *address,
	vm_size_t               size,
	vm_offset_t             mask,
	int                     flags,
	vm_tag_t                tag,
	vm_map_t                src_map,
	vm_offset_t             memory_address,
	boolean_t               copy,
	vm_prot_t               *cur_protection,
	vm_prot_t               *max_protection,
	vm_inherit_t            inheritance);

extern kern_return_t vm_map_64_kernel(
	vm_map_t                target_map,
	vm_offset_t             *address,
	vm_size_t               size,
	vm_offset_t             mask,
	int                     flags,
	vm_map_kernel_flags_t   vmk_flags,
	vm_tag_t                tag,
	ipc_port_t              port,
	vm_object_offset_t      offset,
	boolean_t               copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);

extern kern_return_t mach_vm_wire_kernel(
	host_priv_t             host_priv,
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

extern kern_return_t vm_map_wire_and_extract_kernel(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_prot_t               caller_prot,
	vm_tag_t                tag,
	boolean_t               user_wire,
	ppnum_t                 *physpage_p);

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

extern void                     kern_allocation_update_size(kern_allocation_name_t allocation, int64_t delta);
extern void                     kern_allocation_update_subtotal(kern_allocation_name_t allocation, uint32_t subtag, int64_t delta);
extern vm_tag_t                 kern_allocation_name_get_vm_tag(kern_allocation_name_t allocation);

struct mach_memory_info;
extern kern_return_t    vm_page_diagnose(
	struct mach_memory_info *info,
	unsigned int            num_info,
	uint64_t                zones_collectable_bytes);

extern uint32_t         vm_page_diagnose_estimate(void);

extern void vm_init_before_launchd(void);

typedef enum {
	PMAP_FEAT_UEXEC = 1
} pmap_feature_flags_t;

#if defined(__x86_64__)
extern bool             pmap_supported_feature(pmap_t pmap, pmap_feature_flags_t feat);
#endif

#if DEBUG || DEVELOPMENT

extern kern_return_t    vm_kern_allocation_info(uintptr_t addr, vm_size_t * size, vm_tag_t * tag, vm_size_t * zone_size);

#endif /* DEBUG || DEVELOPMENT */

#if HIBERNATION
extern void             hibernate_rebuild_vm_structs(void);
#endif /* HIBERNATION */

extern vm_tag_t         vm_tag_bt(void);

extern vm_tag_t         vm_tag_alloc(vm_allocation_site_t * site);

extern void             vm_tag_alloc_locked(vm_allocation_site_t * site, vm_allocation_site_t ** releasesiteP);

extern void             vm_tag_update_size(vm_tag_t tag, int64_t size);

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
