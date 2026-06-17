/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_kern.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Kernel memory management.
 */

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_kern_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_compressor_xnu.h>
#include <vm/vm_pageout_xnu.h>
#include <vm/vm_init_xnu.h>
#include <vm/vm_fault.h>
#include <vm/vm_memtag.h>
#if HAS_MTE
#include <vm/vm_mteinfo_internal.h>
#endif /* HAS_MTE */
#include <vm/vm_far.h>
#include <kern/misc_protos.h>
#include <vm/cpm_internal.h>
#include <kern/ledger.h>
#include <kern/bits.h>
#include <kern/startup.h>
#include <kern/telemetry.h>

#include <string.h>

#include <libkern/OSDebug.h>
#include <libkern/crypto/sha2.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>
#include <sys/kdebug_triage.h>

#include <san/kasan.h>
#include <kern/kext_alloc.h>
#include <kern/backtrace.h>
#include <os/hash.h>
#include <kern/zalloc_internal.h>

#if CONFIG_SPTM
#include <arm64/sptm/sptm.h>
#endif

/*
 *	Variables exported by this module.
 */

__enum_closed_decl(kmem_direction_t, uint32_t, {
	KMEM_DIRECTION_FORWARDS,
	KMEM_DIRECTION_BACKWARDS,
	KMEM_DIRECTION_COUNT,
});

SECURITY_READ_ONLY_LATE(vm_map_t) kernel_map;
static SECURITY_READ_ONLY_LATE(struct mach_vm_range) kmem_ranges[KMEM_RANGE_COUNT - 1];
static struct vm_guard_object_slab kmem_slabs[KMEM_RANGE_ID_MAX][KMEM_DIRECTION_COUNT];

__startup_data static vm_map_size_t data_range_size;
__startup_data static vm_map_size_t shared_data_range_size;
__startup_data static vm_map_size_t ptr_range_size;

#pragma mark helpers

__attribute__((overloadable))
__header_always_inline kmem_flags_t
ANYF(kma_flags_t flags)
{
	return (kmem_flags_t)flags;
}

__attribute__((overloadable))
__header_always_inline kmem_flags_t
ANYF(kmr_flags_t flags)
{
	return (kmem_flags_t)flags;
}

__attribute__((overloadable))
__header_always_inline kmem_flags_t
ANYF(kmf_flags_t flags)
{
	return (kmem_flags_t)flags;
}

__abortlike
static void
__kmem_invalid_size_panic(
	vm_map_t        map,
	vm_size_t       size,
	uint32_t        flags)
{
	panic("kmem(map=%p, flags=0x%x): invalid size %zd",
	    map, flags, (size_t)size);
}

__abortlike
static void
__kmem_invalid_arguments_panic(
	const char     *what,
	vm_map_t        map,
	vm_address_t    address,
	vm_size_t       size,
	uint32_t        flags)
{
	panic("kmem_%s(map=%p, addr=%p, size=%zd, flags=0x%x): "
	    "invalid arguments passed",
	    what, map, (void *)address, (size_t)size, flags);
}

__abortlike
static void
__kmem_failed_panic(
	vm_map_t        map,
	vm_size_t       size,
	uint32_t        flags,
	kern_return_t   kr,
	const char     *what)
{
	panic("kmem_%s(%p, %zd, 0x%x): failed with %d",
	    what, map, (size_t)size, flags, kr);
}

__abortlike
static void
__kmem_entry_not_found_panic(
	vm_map_t        map,
	vm_offset_t     addr)
{
	panic("kmem(map=%p) no entry found at %p", map, (void *)addr);
}

static inline vm_object_t
__kmem_object(kmem_flags_t flags)
{
	if (flags & KMEM_COMPRESSOR) {
		if (flags & KMEM_KOBJECT) {
			panic("both KMEM_KOBJECT and KMEM_COMPRESSOR specified");
		}
		return compressor_object;
	}
	if (!(flags & KMEM_KOBJECT)) {
		panic("KMEM_KOBJECT or KMEM_COMPRESSOR is required");
	}
#if HAS_MTE
	if (flags & KMEM_TAG) {
		return kernel_object_tagged;
	}
#endif /* HAS_MTE */
	return kernel_object_default;
}

static inline pmap_mapping_type_t
__kmem_mapping_type(kmem_flags_t flags)
{
	if (flags & (KMEM_COMPRESSOR | KMEM_DATA_SHARED)) {
		return PMAP_MAPPING_TYPE_DEFAULT;
	} else if (flags & KMEM_DATA) {
		return kalloc_is_restricted_data_mode_enforced() ?
		       PMAP_MAPPING_TYPE_RESTRICTED : PMAP_MAPPING_TYPE_DEFAULT;
	} else {
		return PMAP_MAPPING_TYPE_RESTRICTED;
	}
}

static inline vm_size_t
__kmem_guard_left(kmem_flags_t flags)
{
	vm_size_t size = 0;
	if (flags & KMEM_GUARD_FIRST) {
		size += PAGE_SIZE;
	}
	if (flags & KMEM_GUARD_STACK) {
		assert(flags & KMEM_GUARD_FIRST);
		size += PAGE_SIZE;
	}
	return size;
}

static inline vm_size_t
__kmem_guard_right(kmem_flags_t flags)
{
	return (flags & KMEM_GUARD_LAST) ? PAGE_SIZE : 0;
}

static inline vm_size_t
__kmem_guard_size(kmem_flags_t flags)
{
	return __kmem_guard_left(flags) + __kmem_guard_right(flags);
}

/*
 * Computes the original size of the object underlying the entry. Adjusts for
 * deltas used by KASAN. See declaration of vme_object_or_delta for more
 * details.
 */
__pure2
static inline vm_size_t
__kmem_entry_orig_size(vm_map_entry_t entry)
{
	vm_object_t object = VME_OBJECT(entry);

#if KASAN
	if (entry->vme_kernel_object) {
		return entry->vme_end - entry->vme_start -
		       entry->vme_object_or_delta;
	} else {
		return object->vo_size - object->vo_size_delta;
	}
#else
	if (entry->vme_kernel_object) {
		return entry->vme_end - entry->vme_start;
	} else {
		return object->vo_size;
	}
#endif
}


#pragma mark kmem range methods

#define mach_vm_range_load(r, rmin, rmax) \
	({ (rmin) = (r)->min_address; (rmax) = (r)->max_address; })

__abortlike
static void
__mach_vm_range_overflow(
	mach_vm_offset_t        addr,
	mach_vm_offset_t        size)
{
	panic("invalid vm range: [0x%llx, 0x%llx + 0x%llx) wraps around",
	    addr, addr, size);
}

__abortlike
static void
__mach_vm_range_invalid(
	mach_vm_offset_t        min_address,
	mach_vm_offset_t        max_address)
{
	panic("invalid vm range: [0x%llx, 0x%llx) wraps around",
	    min_address, max_address);
}

__header_always_inline mach_vm_size_t
mach_vm_range_size(const struct mach_vm_range *r)
{
	mach_vm_offset_t rmin, rmax;

	mach_vm_range_load(r, rmin, rmax);
	return rmax - rmin;
}

__attribute__((overloadable))
__header_always_inline bool
mach_vm_range_contains(const struct mach_vm_range *r, mach_vm_offset_t addr)
{
	mach_vm_offset_t rmin, rmax;
	/*
	 * The `&` is not a typo: we really expect the check to pass,
	 * so encourage the compiler to eagerly load and test without branches
	 */
	mach_vm_range_load(r, rmin, rmax);
	return (addr >= rmin) & (addr < rmax);
}

__attribute__((overloadable))
__header_always_inline bool
mach_vm_range_contains(
	const struct mach_vm_range *r,
	mach_vm_offset_t        addr,
	mach_vm_offset_t        size)
{
	mach_vm_offset_t rmin, rmax;
	mach_vm_offset_t end;

	if (__improbable(os_add_overflow(addr, size, &end))) {
		return false;
	}

	/*
	 *	 The `&` is not a typo: we really expect the check to pass,
	 *   so encourage the compiler to eagerly load and test without branches
	 */
	mach_vm_range_load(r, rmin, rmax);
	return (addr >= rmin) & (end >= rmin) & (end <= rmax);
}

__attribute__((overloadable))
__header_always_inline bool
mach_vm_range_intersects(
	const struct mach_vm_range *r1,
	const struct mach_vm_range *r2)
{
	mach_vm_offset_t r1_min, r1_max;
	mach_vm_offset_t r2_min, r2_max;

	mach_vm_range_load(r1, r1_min, r1_max);
	r2_min = r2->min_address;
	r2_max = r2->max_address;

	if (r1_min > r1_max) {
		__mach_vm_range_invalid(r1_min, r1_max);
	}

	if (r2_min > r2_max) {
		__mach_vm_range_invalid(r2_min, r2_max);
	}

	return r1_max > r2_min && r1_min < r2_max;
}

__attribute__((overloadable))
__header_always_inline bool
mach_vm_range_intersects(
	const struct mach_vm_range *r1,
	mach_vm_offset_t        addr,
	mach_vm_offset_t        size)
{
	struct mach_vm_range r2;

	r2.min_address = addr;
	if (os_add_overflow(addr, size, &r2.max_address)) {
		__mach_vm_range_overflow(addr, size);
	}

	return mach_vm_range_intersects(r1, &r2);
}

bool
kmem_range_id_contains(
	kmem_range_id_t         range_id,
	vm_map_offset_t         addr,
	vm_map_size_t           size)
{
	addr = vm_memtag_canonicalize_kernel(addr);
	return mach_vm_range_contains(kmem_range(range_id), addr, size);
}

__abortlike
static void
kmem_range_invalid_panic(
	kmem_range_id_t         range_id,
	vm_map_offset_t         addr,
	vm_map_size_t           size)
{
	const struct mach_vm_range *r = kmem_range(range_id);
	mach_vm_offset_t rmin, rmax;

	mach_vm_range_load(r, rmin, rmax);
	if (addr + size < rmin) {
		panic("addr %p + size %llu overflows %p", (void *)addr, size,
		    (void *)(addr + size));
	}
	panic("addr %p + size %llu doesnt fit in one range (id: %u min: %p max: %p)",
	    (void *)addr, size, range_id, (void *)rmin, (void *)rmax);
}

/*
 * Return whether the entire allocation is contained in the given range
 */
static bool
kmem_range_contains_fully(
	kmem_range_id_t         range_id,
	vm_map_offset_t         addr,
	vm_map_size_t           size)
{
	const struct mach_vm_range *r = kmem_range(range_id);
	mach_vm_offset_t rmin, rmax;
	bool result = false;

	if (VM_KERNEL_ADDRESS(addr)) {
		addr = vm_memtag_canonicalize_kernel(addr);
	}

	/*
	 * The `&` is not a typo: we really expect the check to pass,
	 * so encourage the compiler to eagerly load and test without branches
	 */
	mach_vm_range_load(r, rmin, rmax);
	result = (addr >= rmin) & (addr < rmax);
	if (__improbable(result
	    && ((addr + size < rmin) || (addr + size > rmax)))) {
		kmem_range_invalid_panic(range_id, addr, size);
	}
	return result;
}

__attribute__((always_inline))
struct mach_vm_range *
kmem_range(vm_map_range_id_t range_id)
{
	return &kmem_ranges[range_id - 1];
}

vm_map_size_t
kmem_range_id_size(kmem_range_id_t range_id)
{
	return mach_vm_range_size(kmem_range(range_id));
}


vm_guard_object_slab_t
kmem_slab(vm_map_kernel_flags_t vmk_flags)
{
	kmem_direction_t dir;
	release_assert(vmk_flags.vmkf_range_id > KMEM_RANGE_ID_NONE &&
	    vmk_flags.vmkf_range_id <= KMEM_RANGE_ID_MAX);
	if (vmk_flags.vmkf_last_free) {
		dir = KMEM_DIRECTION_BACKWARDS;
	} else {
		dir = KMEM_DIRECTION_FORWARDS;
	}
	return &kmem_slabs[vmk_flags.vmkf_range_id - 1][dir];
}

kmem_range_id_t
kmem_addr_get_range(vm_map_offset_t addr, vm_map_size_t size)
{
	kmem_range_id_t range_id = KMEM_RANGE_ID_FIRST;

	for (; range_id < KMEM_RANGE_COUNT; range_id++) {
		if (kmem_range_contains_fully(range_id, addr, size)) {
			return range_id;
		}
	}
	return KMEM_RANGE_ID_NONE;
}

bool
kmem_is_ptr_range(vm_map_range_id_t range_id)
{
	return (range_id >= KMEM_RANGE_ID_FIRST) &&
	       (range_id <= KMEM_RANGE_ID_NUM_PTR);
}

__abortlike
static void
kmem_range_invalid_for_overwrite(vm_map_offset_t addr)
{
	panic("Can't overwrite mappings (addr: %p) in kmem ptr ranges",
	    (void *)addr);
}

mach_vm_range_t
kmem_validate_range_for_overwrite(
	vm_map_offset_t         addr,
	vm_map_size_t           size)
{
	vm_map_range_id_t range_id = kmem_addr_get_range(addr, size);

	if (kmem_is_ptr_range(range_id)) {
		kmem_range_invalid_for_overwrite(addr);
	}

	return kmem_range(range_id);
}


#pragma mark entry parameters


__abortlike
static void
__kmem_entry_validate_panic(
	vm_map_t        map,
	vm_map_entry_t  entry,
	vm_offset_t     addr,
	vm_size_t       size,
	uint32_t        flags,
	kmem_guard_t    guard)
{
	const char *what = "???";

	if (entry->vme_atomic != guard.kmg_atomic) {
		what = "atomicity";
	} else if (entry->is_sub_map != guard.kmg_submap) {
		what = "objectness";
	} else if (addr != entry->vme_start) {
		what = "left bound";
	} else if ((flags & KMF_GUESS_SIZE) == 0 && addr + size != entry->vme_end) {
		what = "right bound";
	} else if (guard.kmg_context != entry->vme_context) {
		what = "guard";
	}

	panic("kmem(map=%p, addr=%p, size=%zd, flags=0x%x): "
	    "entry:%p %s mismatch guard(0x%08x)",
	    map, (void *)addr, size, flags, entry,
	    what, guard.kmg_context);
}

static bool
__kmem_entry_validate_guard(
	vm_map_entry_t  entry,
	vm_offset_t     addr,
	vm_size_t       size,
	kmem_flags_t    flags,
	kmem_guard_t    guard)
{
	if (entry->vme_atomic != guard.kmg_atomic) {
		return false;
	}

	if (!guard.kmg_atomic) {
		return true;
	}

	if (entry->is_sub_map != guard.kmg_submap) {
		return false;
	}

	if (addr != entry->vme_start) {
		return false;
	}

	if ((flags & KMEM_GUESS_SIZE) == 0 && addr + size != entry->vme_end) {
		return false;
	}

	if (!guard.kmg_submap && guard.kmg_context != entry->vme_context) {
		return false;
	}

	return true;
}

void
kmem_entry_validate_guard(
	vm_map_t        map,
	vm_map_entry_t  entry,
	vm_offset_t     addr,
	vm_size_t       size,
	kmem_guard_t    guard)
{
	if (!__kmem_entry_validate_guard(entry, addr, size, KMEM_NONE, guard)) {
		__kmem_entry_validate_panic(map, entry, addr, size, KMEM_NONE, guard);
	}
}

__abortlike
static void
__kmem_entry_validate_object_panic(
	vm_map_t        map,
	vm_map_entry_t  entry,
	kmem_flags_t    flags)
{
	const char *what;
	const char *verb;

	if (entry->is_sub_map) {
		panic("kmem(map=%p) entry %p is a submap", map, entry);
	}

	if (flags & KMEM_KOBJECT) {
		what = "kernel";
		verb = "isn't";
	} else if (flags & KMEM_COMPRESSOR) {
		what = "compressor";
		verb = "isn't";
	} else if (entry->vme_kernel_object) {
		what = "kernel";
		verb = "is unexpectedly";
	} else {
		what = "compressor";
		verb = "is unexpectedly";
	}

	panic("kmem(map=%p, flags=0x%x): entry %p %s for the %s object",
	    map, flags, entry, verb, what);
}

static void
__kmem_realloc_validate_object(
	vm_map_t                map,
	vm_map_entry_t          entry,
	kmem_flags_t            flags)
{
	if (entry->is_sub_map) {
		__kmem_entry_validate_object_panic(map, entry, flags);
	}
	if ((bool)(flags & KMEM_KOBJECT) != entry->vme_kernel_object) {
		__kmem_entry_validate_object_panic(map, entry, flags);
	}
	if ((bool)(flags & KMEM_COMPRESSOR) !=
	    (VME_OBJECT(entry) == compressor_object)) {
		__kmem_entry_validate_object_panic(map, entry, flags);
	}
}

vm_size_t
kmem_size_guard(
	vm_map_t        map,
	vm_offset_t     addr,
	kmem_guard_t    guard)
{
	kmem_flags_t flags = KMEM_GUESS_SIZE;
	vm_map_entry_t entry;
	vm_size_t size;

	vmlp_api_start(KMEM_SIZE_GUARD);

	vm_map_ilk_lock(map);

#if KASAN_CLASSIC
	addr -= PAGE_SIZE;
#endif /* KASAN_CLASSIC */
	addr  = vm_memtag_canonicalize_kernel(addr);
	entry = vm_map_lookup(map, addr);

	if (entry == VM_MAP_ENTRY_NULL) {
		__kmem_entry_not_found_panic(map, addr);
	}

	vmlp_range_event_entry(map, entry);

	if (!__kmem_entry_validate_guard(entry, addr, 0, flags, guard)) {
		__kmem_entry_validate_panic(map, entry, addr, 0, flags, guard);
	}

	size = __kmem_entry_orig_size(entry);

	vm_map_ilk_unlock(map);

	vmlp_api_end(KMEM_SIZE_GUARD, 0);
	return size;
}

static inline uint16_t
kmem_hash_backtrace(
	void                     *fp)
{
	uint64_t  bt_count;
	uintptr_t bt[8] = {};

	struct backtrace_control ctl = {
		.btc_frame_addr = (uintptr_t)fp,
	};

	bt_count = backtrace(bt, sizeof(bt) / sizeof(bt[0]), &ctl, NULL);
	return (uint16_t) os_hash_jenkins(bt, bt_count * sizeof(bt[0]));
}

static_assert(KMEM_RANGE_ID_DATA_SHARED - 1 <= KMEM_RANGE_MASK,
    "Insufficient bits to represent ptr ranges");

kmem_range_id_t
kmem_adjust_range_id(
	uint32_t                  hash)
{
#if ZSECURITY_CONFIG(KERNEL_PTR_SPLIT)
	return (kmem_range_id_t) (KMEM_RANGE_ID_PTR_0 +
	       (hash & KMEM_RANGE_MASK) % KMEM_RANGE_ID_NUM_PTR);
#else
	(void)hash;
	return KMEM_RANGE_ID_PTR_0;
#endif
}

static void
kmem_apply_security_policy(
	vm_map_t                  map,
	kma_flags_t               kma_flags,
	kmem_guard_t              guard,
	vm_map_kernel_flags_t    *vmk_flags)
{
	uint16_t type_hash = guard.kmg_type_hash;

	if (startup_phase < STARTUP_SUB_KMEM || map != kernel_map) {
		vmk_flags->vmkf_range_id  = KMEM_RANGE_ID_NONE;
		vmk_flags->vmkf_last_free = false;
		return;
	}

	if (kma_flags & KMA_DATA_SHARED) {
		vmk_flags->vmkf_range_id = KMEM_RANGE_ID_DATA_SHARED;
	} else if (kma_flags & KMA_DATA) {
		vmk_flags->vmkf_range_id = KMEM_RANGE_ID_DATA_PRIVATE;
	} else if (kma_flags & KMA_IO) {
		vmk_flags->vmkf_range_id = KMEM_RANGE_ID_IO;
	} else if (type_hash) {
		vmk_flags->vmkf_range_id = type_hash & KMEM_RANGE_MASK;
	} else {
		/*
		 * Range id needs to correspond to one of the PTR ranges
		 */
		type_hash = (uint16_t)kmem_hash_backtrace(__builtin_frame_address(0));
		vmk_flags->vmkf_range_id = kmem_adjust_range_id(type_hash);
	}

	/*
	 * As an optimization in KMA_DATA, KMA_DATA_SHARED,
	 * to avoid fragmentation, allocate static carveouts at the end.
	 */
	if (kma_flags & (KMA_DATA | KMA_DATA_SHARED | KMR_IO)) {
		vmk_flags->vmkf_last_free = (bool)(kma_flags & KMA_PERMANENT);
	} else {
		vmk_flags->vmkf_last_free = (bool)(type_hash & KMEM_DIRECTION_MASK);
	}
}

#pragma mark allocation

/*!
 * @brief
 * Allocate a range in the specified virtual address map, returning the entry
 * allocated for that range.
 *
 * @discussion
 * The map interlock must be held. It will be returned held, though it may be
 * dropped while the function runs.
 *
 * If an entry is allocated, the object/offset fields are initialized to zero.
 */
static kern_return_t
kmem_find_space(
	vm_map_t                map,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_entry_t         *entry_out)
{
	vm_map_store_rsv_t rsv = { };
	vm_map_entry_t     new_entry;
	kern_return_t      kr;

	vmlp_api_start(VM_MAP_FIND_SPACE);

	if (size == 0) {
		vmlp_api_end(VM_MAP_FIND_SPACE, KERN_INVALID_ARGUMENT);
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_locate_space_anywhere(map, 0, size, mask, vmk_flags, &rsv);
	if (kr != KERN_SUCCESS) {
		vmlp_api_end(VM_MAP_FIND_SPACE, kr);
		return kr;
	}

	new_entry = vm_map_entry_create_locked(map,
	    vmsr_start(rsv), vmsr_start(rsv) + size);
	new_entry->use_pmap = true;
	new_entry->protection = VM_PROT_DEFAULT;
	new_entry->max_protection = VM_PROT_ALL;
	new_entry->vme_permanent = vmk_flags.vmf_permanent;
#if HAS_MTE
	if (vmk_flags.vmf_mte) {
		vm_map_mark_has_sec_access_ilocked(map);
	}
#endif /* HAS_MTE */

	/*
	 *	At this point,
	 *
	 *	- new_entry's "vme_start" and "vme_end" should define
	 *	  the endpoints of the available new range,
	 *
	 *	- and the map should still be locked.
	 */

	vm_map_store_insert(map, new_entry, rsv, vmk_flags);
	vmlp_range_event_entry(map, new_entry);

	*entry_out = new_entry;
	vmlp_api_end(VM_MAP_FIND_SPACE, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static kmem_return_t
kmem_alloc_guard_internal(
	vm_map_t                map,
	vm_size_t               size,
	vm_offset_t             mask,
	kma_flags_t             flags,
	kmem_guard_t            guard,
	kern_return_t         (^alloc_pages)(vm_size_t, kma_flags_t, vm_page_t *))
{
	vm_object_t             object;
	vm_offset_t             delta = 0;
	vm_map_entry_t          entry = NULL;
	vm_map_offset_t         map_addr, fill_start;
	vm_map_size_t           map_size, fill_size;
	vm_page_t               guard_left = VM_PAGE_NULL;
	vm_page_t               guard_stack = VM_PAGE_NULL;
	vm_page_t               guard_right = VM_PAGE_NULL;
	vm_page_t               wired_page_list = VM_PAGE_NULL;
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
	bool                    skip_guards;
	kmem_return_t           kmr = { };

	vmlp_api_start(KMEM_ALLOC_GUARD_INTERNAL);

	assert(kernel_map && map->pmap == kernel_pmap);

	/* DATA and DATA_SHARED are mutually exclusive */
	assert((flags & (KMA_DATA | KMA_DATA_SHARED)) != (KMA_DATA | KMA_DATA_SHARED));

#if defined(__arm64__)
	/*
	 * Pageable allocations should be marked as shared.
	 *
	 * Only assert this on arm64 architectures, since we do not
	 * adopt the shared heap on older ones.
	 */
	assert((flags & (KMA_PAGEABLE | KMA_DATA)) != (KMA_PAGEABLE | KMA_DATA));
#endif /* defined(__arm64__) */

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#endif

#if HAS_MTE
	if (!mte_kern_enabled()) {
		flags &= ~KMA_TAG;
	}
#endif /* HAS_MTE */

	if (size == 0 ||
	    (size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS) ||
	    (size < __kmem_guard_size(ANYF(flags)))) {
		__kmem_invalid_size_panic(map, size, flags);
	}

	/*
	 * limit the size of a single extent of wired memory
	 * to try and limit the damage to the system if
	 * too many pages get wired down
	 * limit raised to 2GB with 128GB max physical limit,
	 * but scaled by installed memory above this
	 *
	 * Note: kmem_alloc_contig_guard() is immune to this check.
	 */
	if (__improbable(!(flags & (KMA_VAONLY | KMA_PAGEABLE)) &&
	    alloc_pages == NULL &&
	    size > MAX(1ULL << 31, sane_size / 64))) {
		kmr.kmr_return = KERN_RESOURCE_SHORTAGE;
		goto out_error;
	}

	/*
	 * Guard pages:
	 *
	 * Guard pages are implemented as fictitious pages.
	 *
	 * However, some maps, and some objects are known
	 * to manage their memory explicitly, and do not need
	 * those to be materialized, which saves memory.
	 *
	 * By placing guard pages on either end of a stack,
	 * they can help detect cases where a thread walks
	 * off either end of its stack.
	 *
	 * They are allocated and set up here and attempts
	 * to access those pages are trapped in vm_fault_page().
	 *
	 * The map_size we were passed may include extra space for
	 * guard pages. fill_size represents the actual size to populate.
	 * Similarly, fill_start indicates where the actual pages
	 * will begin in the range.
	 */

	map_size   = round_page(size);
	fill_start = 0;
	fill_size  = map_size - __kmem_guard_size(ANYF(flags));

#if KASAN_CLASSIC
	if (flags & KMA_KASAN_GUARD) {
		assert((flags & (KMA_GUARD_FIRST | KMA_GUARD_LAST)) == 0);
		flags |= KMA_GUARD_FIRST | KMEM_GUARD_LAST;
		delta     = ptoa(2);
		map_size += delta;
	}
#else
	(void)delta;
#endif /* KASAN_CLASSIC */

	skip_guards = (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) ||
	    map->never_faults;

	if (flags & KMA_GUARD_FIRST) {
		vmk_flags.vmkf_guard_before = true;
		fill_start += PAGE_SIZE;
	}
	if (flags & KMA_GUARD_STACK) {
		fill_start += PAGE_SIZE;
	}
	if (flags & KMA_NOSOFTLIMIT) {
		vmk_flags.vmkf_no_soft_limit = true;
	}
	if ((flags & KMA_GUARD_FIRST) && !skip_guards) {
		guard_left = vm_page_create_guard((flags & KMA_NOPAGEWAIT) == 0);
		if (__improbable(guard_left == VM_PAGE_NULL)) {
			kmr.kmr_return = KERN_RESOURCE_SHORTAGE;
			goto out_error;
		}
	}
	if ((flags & KMA_GUARD_STACK) && !skip_guards) {
		guard_stack = vm_page_create_guard((flags & KMA_NOPAGEWAIT) == 0);
		if (__improbable(guard_stack == VM_PAGE_NULL)) {
			kmr.kmr_return = KERN_RESOURCE_SHORTAGE;
			goto out_error;
		}
	}
	if ((flags & KMA_GUARD_LAST) && !skip_guards) {
		guard_right = vm_page_create_guard((flags & KMA_NOPAGEWAIT) == 0);
		if (__improbable(guard_right == VM_PAGE_NULL)) {
			kmr.kmr_return = KERN_RESOURCE_SHORTAGE;
			goto out_error;
		}
	}

	if (!(flags & (KMA_VAONLY | KMA_PAGEABLE))) {
		if (alloc_pages) {
			kmr.kmr_return = alloc_pages(fill_size, flags,
			    &wired_page_list);
		} else {
			kmr.kmr_return = vm_page_alloc_list(atop(fill_size), flags,
			    &wired_page_list);
		}
		if (__improbable(kmr.kmr_return != KERN_SUCCESS)) {
			goto out_error;
		}
	}

	/*
	 *	Allocate a new object (if necessary).  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if (flags & KMA_KOBJECT) {
#if HAS_MTE
		if (flags & KMA_TAG) {
			object = kernel_object_tagged;
			vmk_flags.vmf_mte = true;
		} else
#endif /* HAS_MTE */
		{
			object = kernel_object_default;
		}
		vm_object_reference(object);
	} else if (flags & KMA_COMPRESSOR) {
		object = compressor_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size, map->serial_id);
		vm_object_lock(object);
		vm_object_set_size(object, map_size, size);
		/* stabilize the object to prevent shadowing */
		object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		VM_OBJECT_SET_TRUE_SHARE(object, TRUE);
		/* There's no real sharing, just setting true_share */
#if HAS_MTE
		if (flags & KMA_TAG) {
			object->wimg_bits = VM_WIMG_MTE;
			object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
			VM_OBJECT_SET_TRUE_SHARE(object, FALSE);
		}
#endif /* HAS_MTE */
		vm_object_unlock(object);
	}

	if (flags & KMA_LAST_FREE) {
		vmk_flags.vmkf_last_free = true;
	}
	if (flags & KMA_PERMANENT) {
		vmk_flags.vmf_permanent = true;
	}
	kmem_apply_security_policy(map, flags, guard, &vmk_flags);

	vm_map_ilk_lock(map);
	kmr.kmr_return = kmem_find_space(map, map_size, mask, vmk_flags, &entry);
	vm_map_ilk_unlock(map);

	if (__improbable(KERN_SUCCESS != kmr.kmr_return)) {
		vm_object_deallocate(object);
		goto out_error;
	}

	vmlp_range_event_entry(map, entry);

	map_addr = entry->vme_start;
	VME_OBJECT_SET(entry, object, guard.kmg_atomic, guard.kmg_context);
	VME_ALIAS_SET(entry, guard.kmg_tag);
	if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
		VME_OFFSET_SET(entry, map_addr);
	}

#if KASAN
	if ((flags & KMA_KOBJECT) && guard.kmg_atomic) {
		entry->vme_object_or_delta = (-size & PAGE_MASK) + delta;
	}
#endif /* KASAN */

	if (!(flags & (KMA_COMPRESSOR | KMA_PAGEABLE))) {
		entry->wired_count = 1;
		vme_btref_consider_and_set(entry, __builtin_frame_address(0));
	}

	if (guard_left || guard_stack || guard_right || wired_page_list) {
		vm_object_offset_t offset = 0ull;

		vm_object_lock(object);

		if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
			offset = map_addr;
		}

		if (guard_left) {
			vm_page_insert(guard_left, object, offset);
			guard_left->vmp_busy = FALSE;
			guard_left = VM_PAGE_NULL;
		}

		if (guard_stack) {
			vm_page_insert(guard_stack, object, offset + PAGE_SIZE);
			guard_stack->vmp_busy = FALSE;
			guard_stack = VM_PAGE_NULL;
		}

		if (guard_right) {
			vm_page_insert(guard_right, object,
			    offset + fill_start + fill_size);
			guard_right->vmp_busy = FALSE;
			guard_right = VM_PAGE_NULL;
		}

		if (wired_page_list) {
			kernel_memory_populate_object_and_unlock(object,
			    map_addr + fill_start, offset + fill_start, fill_size,
			    wired_page_list, flags, guard.kmg_tag, VM_PROT_DEFAULT,
			    __kmem_mapping_type(ANYF(flags)));
		} else {
			vm_object_unlock(object);
		}
	}

	/*
	 * now that the pages are wired, we no longer have to fear coalesce
	 */
	if ((flags & (KMA_KOBJECT | KMA_COMPRESSOR)) && !guard.kmg_atomic) {
		entry = vm_map_locked_entry_simplify(map, entry);
	}

	/*
	 * entry was returned locked by kmem_find_space. We don't need it
	 * anymore, so we can unlock it.
	 */
	vm_entry_unlock_exclusive(map, entry);

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_END,
	    atop(fill_size), 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
	kmr.kmr_address = CAST_DOWN(vm_offset_t, map_addr);

#if KASAN
	if (flags & (KMA_KASAN_GUARD | KMA_PAGEABLE)) {
		/*
		 * We need to allow the range for pageable memory,
		 * or faulting will not be allowed.
		 */
		kasan_notify_address(map_addr, map_size);
	}
#endif /* KASAN */
#if KASAN_CLASSIC
	if (flags & KMA_KASAN_GUARD) {
		kmr.kmr_address += PAGE_SIZE;
		kasan_alloc_large(kmr.kmr_address, size);
	}
#endif /* KASAN_CLASSIC */
#if CONFIG_KERNEL_TAGGING
	if (!(flags & KMA_VAONLY) && (flags & KMA_TAG)) {
		kmr.kmr_ptr = vm_memtag_generate_and_store_tag((caddr_t)kmr.kmr_address + fill_start, fill_size);
		kmr.kmr_ptr = (caddr_t)kmr.kmr_ptr - fill_start;
#if KASAN_TBI
		kasan_tbi_retag_unused_space(kmr.kmr_ptr, map_size, size);
#endif /* KASAN_TBI */
	}
#endif /* CONFIG_KERNEL_TAGGING */
	vmlp_api_end(KMEM_ALLOC_GUARD_INTERNAL, kmr.kmr_return);
	return kmr;

out_error:
	if (flags & KMA_NOFAIL) {
		__kmem_failed_panic(map, size, flags, kmr.kmr_return, "alloc");
	}
	if (guard_left) {
		guard_left->vmp_snext = wired_page_list;
		wired_page_list = guard_left;
	}
	if (guard_stack) {
		guard_stack->vmp_snext = wired_page_list;
		wired_page_list = guard_stack;
	}
	if (guard_right) {
		guard_right->vmp_snext = wired_page_list;
		wired_page_list = guard_right;
	}
	if (wired_page_list) {
		vm_page_free_list(wired_page_list, FALSE);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_END,
	    0, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */

	vmlp_api_end(KMEM_ALLOC_GUARD_INTERNAL, kmr.kmr_return);
	return kmr;
}

__mockable kmem_return_t
kmem_alloc_guard(
	vm_map_t        map,
	vm_size_t       size,
	vm_offset_t     mask,
	kma_flags_t     flags,
	kmem_guard_t    guard)
{
	return kmem_alloc_guard_internal(map, size, mask, flags, guard, NULL);
}

kmem_return_t
kmem_alloc_contig_guard(
	vm_map_t                map,
	vm_size_t               size,
	vm_offset_t             mask,
	ppnum_t                 max_pnum,
	ppnum_t                 pnum_mask,
	kma_flags_t             flags,
	kmem_guard_t            guard)
{
	__auto_type alloc_pages = ^(vm_size_t fill_size, kma_flags_t kma_flags, vm_page_t *pages) {
		return cpm_allocate(fill_size, pages, max_pnum, pnum_mask, FALSE, kma_flags);
	};

	return kmem_alloc_guard_internal(map, size, mask, flags, guard, alloc_pages);
}

kmem_return_t
kmem_suballoc(
	vm_map_t                parent,
	mach_vm_offset_t       *addr,
	vm_size_t               size,
	vm_map_create_options_t vmc_options,
	int                     vm_flags,
	kms_flags_t             flags,
	vm_tag_t                tag)
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vm_map_offset_t map_addr = 0;
	kmem_return_t kmr = { };
	vm_map_t map;

	assert(page_aligned(size));
	assert(parent->pmap == kernel_pmap);

	vm_map_kernel_flags_set_vmflags(&vmk_flags, vm_flags, tag);

	if (parent == kernel_map) {
		assert(vmk_flags.vmf_overwrite || (flags & (KMS_DATA | KMS_DATA_SHARED)));
	}

	if (vmk_flags.vmf_fixed) {
		map_addr = trunc_page(*addr);
	}

	pmap_reference(vm_map_pmap(parent));
	map = vm_map_create_options(vm_map_pmap(parent), 0, size, vmc_options);

	/*
	 * 1. vm_map_enter() will consume one ref on success.
	 *
	 * 2. make the entry atomic as kernel submaps should never be split.
	 *
	 * 3. instruct vm_map_enter() that it is a fresh submap
	 *    that needs to be taught its bounds as it inserted.
	 */
	vm_map_reference(map);

	vmk_flags.vmf_permanent = true;
	vmk_flags.vmkf_submap = true;
	vmk_flags.vmkf_submap_atomic = true;
	if (flags & KMS_LAST_FREE) {
		vmk_flags.vmkf_last_free = true;
	}

	/* If this is a data allocation, set the appropriate data range */
	if (flags & KMS_DATA_SHARED) {
		vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA_SHARED;
	} else if (flags & KMS_DATA) {
		vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA_PRIVATE;
	}

	if (flags & KMS_NOSOFTLIMIT) {
		vmk_flags.vmkf_no_soft_limit = true;
	}

	kmr.kmr_return = vm_map_enter(parent, &map_addr, size, 0,
	    vmk_flags, (vm_object_t)map, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kmr.kmr_return != KERN_SUCCESS) {
		if (flags & KMS_NOFAIL) {
			panic("kmem_suballoc(map=%p, size=%zd) failed with %d",
			    parent, size, kmr.kmr_return);
		}
		assert(os_ref_get_count_raw(&map->map_refcnt) == 2);
		vm_map_deallocate(map);
		vm_map_deallocate(map); /* also removes ref to pmap */
		return kmr;
	}

	/*
	 * For kmem_suballocs that register a claim and are assigned a range, ensure
	 * that the exact same range is returned.
	 */
	if (*addr != 0 && parent == kernel_map &&
	    startup_phase > STARTUP_SUB_KMEM) {
		assert(CAST_DOWN(vm_offset_t, map_addr) == *addr);
	} else {
		*addr = map_addr;
	}

	kmr.kmr_submap = map;
	return kmr;
}

/*
 *	kmem_alloc:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 */

__exported kern_return_t
kmem_alloc_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size);
kern_return_t
kmem_alloc_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	if (size && (size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS) == 0) {
		return kmem_alloc(map, addrp, size, KMA_NONE, vm_tag_bt());
	}
	/* Maintain ABI compatibility: invalid sizes used to be allowed */
	return size ? KERN_NO_SPACE: KERN_INVALID_ARGUMENT;
}


/*
 *	kmem_alloc_kobject:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 *
 *	The memory is allocated in the kernel_object.
 *	It may not be copied with vm_map_copy, and
 *	it may not be reallocated with kmem_realloc.
 */

__exported kern_return_t
kmem_alloc_kobject_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size);
kern_return_t
kmem_alloc_kobject_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	if (size && (size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS) == 0) {
		return kmem_alloc(map, addrp, size, KMA_KOBJECT, vm_tag_bt());
	}
	/* Maintain ABI compatibility: invalid sizes used to be allowed */
	return size ? KERN_NO_SPACE: KERN_INVALID_ARGUMENT;
}

/*
 *	kmem_alloc_pageable:
 *
 *	Allocate pageable memory in the kernel's address map.
 */

__exported kern_return_t
kmem_alloc_pageable_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size);
kern_return_t
kmem_alloc_pageable_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	if (size && (size >> VM_KERNEL_POINTER_SIGNIFICANT_BITS) == 0) {
		return kmem_alloc(map, addrp, size, KMA_PAGEABLE | KMA_DATA_SHARED, vm_tag_bt());
	}
	/* Maintain ABI compatibility: invalid sizes used to be allowed */
	return size ? KERN_NO_SPACE: KERN_INVALID_ARGUMENT;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_vm_allocate_kernel_sanitize(
	vm_map_t                map,
	mach_vm_offset_ut       addr_u,
	mach_vm_size_ut         size_u,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_offset_t        *map_addr,
	vm_map_size_t          *map_size)
{
	kern_return_t   result;
	vm_map_offset_t map_end;

	if (vmk_flags.vmf_fixed) {
		result = vm_sanitize_addr_size(addr_u, size_u,
		    VM_SANITIZE_CALLER_VM_ALLOCATE_FIXED,
		    map,
		    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS | VM_SANITIZE_FLAGS_REALIGN_START,
		    map_addr, &map_end, map_size);
		if (__improbable(result != KERN_SUCCESS)) {
			return result;
		}
	} else {
		*map_addr = 0;
		result = vm_sanitize_size(0, size_u,
		    VM_SANITIZE_CALLER_VM_ALLOCATE_ANYWHERE, map,
		    VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS,
		    map_size);
		if (__improbable(result != KERN_SUCCESS)) {
			return result;
		}
	}

	return KERN_SUCCESS;
}

kern_return_t
mach_vm_allocate_kernel(
	vm_map_t                map,
	mach_vm_offset_ut      *addr_u,
	mach_vm_size_ut         size_u,
	vm_map_kernel_flags_t   vmk_flags)
{
	vm_map_offset_t map_addr;
	vm_map_size_t   map_size;
	kern_return_t   result;

	if (map == VM_MAP_NULL) {
		ktriage_record(thread_tid(current_thread()),
		    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
		    KDBG_TRIAGE_RESERVED,
		    KDBG_TRIAGE_VM_ALLOCATE_KERNEL_BADMAP_ERROR),
		    KERN_INVALID_ARGUMENT /* arg */);
		return KERN_INVALID_ARGUMENT;
	}

	if (!vm_map_kernel_flags_check_vm_and_kflags(vmk_flags,
	    VM_FLAGS_USER_ALLOCATE)) {
		return KERN_INVALID_ARGUMENT;
	}

	result = mach_vm_allocate_kernel_sanitize(map,
	    *addr_u,
	    size_u,
	    vmk_flags,
	    &map_addr,
	    &map_size);
	if (__improbable(result != KERN_SUCCESS)) {
		result = vm_sanitize_get_kr(result);
		if (result == KERN_SUCCESS) {
			*addr_u = vm_sanitize_wrap_addr(0);
		} else {
			ktriage_record(thread_tid(current_thread()),
			    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
			    KDBG_TRIAGE_RESERVED,
			    KDBG_TRIAGE_VM_ALLOCATE_KERNEL_BADSIZE_ERROR),
			    KERN_INVALID_ARGUMENT /* arg */);
		}
		return result;
	}

	vm_map_kernel_flags_update_range_id(&vmk_flags, map, map_size);

	result = vm_map_enter(
		map,
		&map_addr,
		map_size,
		(vm_map_offset_t)0,
		vmk_flags,
		VM_OBJECT_NULL,
		(vm_object_offset_t)0,
		FALSE,
		VM_PROT_DEFAULT,
		VM_PROT_ALL,
		VM_INHERIT_DEFAULT);

	if (result == KERN_SUCCESS) {
#if KASAN
		if (map->pmap == kernel_pmap) {
			kasan_notify_address(map_addr, map_size);
		}
#endif
		*addr_u = vm_sanitize_wrap_addr(map_addr);
	} else {
		ktriage_record(thread_tid(current_thread()),
		    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
		    KDBG_TRIAGE_RESERVED,
		    KDBG_TRIAGE_VM_ALLOCATE_KERNEL_VMMAPENTER_ERROR),
		    result /* arg */);
	}
	return result;
}

__static_testable __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_vm_deallocate_kernel_sanitize(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u,
	mach_vm_offset_t       *start,
	mach_vm_offset_t       *end,
	mach_vm_size_t         *size)
{
#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	kern_return_t err = vm_sanitize_validate_non_canonical_ut_addr(map, start_u);
	if (err != KERN_SUCCESS) {
		return err;
	}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

	return vm_sanitize_addr_size(start_u, size_u,
	           VM_SANITIZE_CALLER_VM_DEALLOCATE, map, VM_SANITIZE_FLAGS_SIZE_ZERO_SUCCEEDS,
	           start, end, size);
}

kern_return_t
mach_vm_deallocate_kernel(
	vm_map_t                map,
	mach_vm_offset_ut       start_u,
	mach_vm_size_ut         size_u)
{
	mach_vm_offset_t start, end;
	mach_vm_size_t   size;
	kern_return_t    kr;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = mach_vm_deallocate_kernel_sanitize(map,
	    start_u,
	    size_u,
	    &start,
	    &end,
	    &size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	return vm_map_remove_guard(map, start, end,
	           VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
}

#pragma mark population

static void
kernel_memory_populate_pmap_enter(
	vm_object_t             object,
	vm_address_t            addr,
	vm_object_offset_t      offset,
	vm_page_t               mem,
	vm_prot_t               prot,
	int                     pe_flags,
	pmap_mapping_type_t     mapping_type)
{
	kern_return_t   pe_result;
	int             pe_options;

	if (VMP_ERROR_GET(mem)) {
		panic("VM page %p should not have an error", mem);
	}

	pe_options = PMAP_OPTIONS_NOWAIT;
	if (object->internal) {
		pe_options |= PMAP_OPTIONS_INTERNAL;
	}
	if (mem->vmp_reusable || object->all_reusable) {
		pe_options |= PMAP_OPTIONS_REUSABLE;
	}

	pe_result = pmap_enter_options(kernel_pmap, addr + offset,
	    VM_PAGE_GET_PHYS_PAGE(mem), prot, VM_PROT_NONE,
	    pe_flags, /* wired */ TRUE, pe_options, NULL, mapping_type);

	if (pe_result == KERN_RESOURCE_SHORTAGE) {
		vm_object_unlock(object);

		pe_options &= ~PMAP_OPTIONS_NOWAIT;

		pe_result = pmap_enter_options(kernel_pmap, addr + offset,
		    VM_PAGE_GET_PHYS_PAGE(mem), prot, VM_PROT_NONE,
		    pe_flags, /* wired */ TRUE, pe_options, NULL, mapping_type);

		vm_object_lock(object);
	}

	assert(pe_result == KERN_SUCCESS);
}

void
kernel_memory_populate_object_and_unlock(
	vm_object_t             object, /* must be locked */
	vm_address_t            addr,
	vm_offset_t             offset,
	vm_size_t               size,
	vm_page_t               page_list,
	kma_flags_t             flags,
	vm_tag_t                tag,
	vm_prot_t               prot,
	pmap_mapping_type_t     mapping_type)
{
	vm_page_t        mem;
	int              pe_flags;
	bool             gobbled_list = page_list && page_list->vmp_gobbled;
	struct vmpi_acct delayed_acct = { };

	assert(((flags & KMA_KOBJECT) != 0) == (is_kernel_object(object) != 0));
	assert3u((bool)(flags & KMA_COMPRESSOR), ==, object == compressor_object);
#if HAS_MTE
	assert(mte_kern_enabled() || (flags & KMA_TAG) == 0);
#endif /* HAS_MTE */

	if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
		assert3u(offset, ==, addr);
	} else {
		/*
		 * kernel_memory_populate_pmap_enter() might drop the object
		 * lock, and the caller might not own a reference anymore
		 * and rely on holding the vm object lock for liveness.
		 */
		vm_object_reference_locked(object);
	}

	if (flags & KMA_KSTACK) {
		pe_flags = VM_MEM_STACK;
	} else {
		pe_flags = 0;
	}

#if HAS_MTE
	/* Inform the PMAP layer that we want an MTE backed page. */
	if (flags & KMA_TAG) {
		pe_flags |= VM_MEM_MAP_MTE;
		assert((object->wimg_bits & VM_WIMG_MTE) != 0);
	} else {
		assert((object->wimg_bits & VM_WIMG_MTE) == 0);
	}
#endif /* HAS_MTE */

	for (vm_object_offset_t pg_offset = 0;
	    pg_offset < size;
	    pg_offset += PAGE_SIZE_64) {
		if (page_list == NULL) {
			panic("%s: page_list too short", __func__);
		}

		mem = page_list;
		page_list = mem->vmp_snext;
		mem->vmp_snext = NULL;

		assert(mem->vmp_wire_count == 0);
		assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);
		assert(vm_page_is_canonical(mem));

		if (flags & KMA_COMPRESSOR) {
			mem->vmp_q_state = VM_PAGE_USED_BY_COMPRESSOR;
			/*
			 * Background processes doing I/O accounting can call
			 * into NVME driver to do some work which results in
			 * an allocation here and so we want to make sure
			 * that the pages used by compressor, regardless of
			 * process context, are never on the special Q.
			 */
			mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;

			vm_page_insert_internal(mem, object, offset + pg_offset,
			    VM_KERN_MEMORY_NONE, VMPI_NONE, &delayed_acct);
		} else {
			mem->vmp_q_state = VM_PAGE_IS_WIRED;
			mem->vmp_wire_count = 1;

#if HAS_MTE
			mteinfo_increment_wire_count(mem);
#endif /* HAS_MTE */

			vm_page_insert_internal(mem, object, offset + pg_offset,
			    tag, VMPI_NONE, &delayed_acct);
		}

		mem->vmp_gobbled = false;
		mem->vmp_busy = false;
		mem->vmp_pmapped = true;
		mem->vmp_wpmapped = true;

		/*
		 * Manual PMAP_ENTER_OPTIONS() with shortcuts
		 * for the kernel and compressor objects.
		 */
		kernel_memory_populate_pmap_enter(object, addr, pg_offset,
		    mem, prot, pe_flags, mapping_type);

		if (flags & KMA_NOENCRYPT) {
			pmap_set_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
		}
	}

	if (page_list) {
		panic("%s: page_list too long", __func__);
	}

	vm_page_insert_flush_accounting(object, &delayed_acct);
	vm_object_unlock(object);
	if ((flags & (KMA_KOBJECT | KMA_COMPRESSOR)) == 0) {
		vm_object_deallocate(object);
	}

	/*
	 * Update the accounting:
	 * - the compressor "wired" pages don't really count as wired
	 * - kmem_alloc_contig_guard() gives gobbled pages,
	 *   which already count as wired but need to be ungobbled.
	 */
	if (gobbled_list) {
		vm_page_lockspin_queues();
		if (flags & KMA_COMPRESSOR) {
			vm_page_wire_count -= atop(size);
		}
		vm_page_gobble_count -= atop(size);
		vm_page_unlock_queues();
	} else if ((flags & KMA_COMPRESSOR) == 0) {
		vm_page_lockspin_queues();
		vm_page_wire_count += atop(size);
		vm_page_unlock_queues();
	}

	if (flags & KMA_KOBJECT) {
		/* vm_page_insert_wired() handles regular objects already */
		vm_tag_update_size(tag, size, NULL);
	}

#if KASAN
	if (flags & KMA_COMPRESSOR) {
		kasan_notify_address_nopoison(addr, size);
	} else {
		kasan_notify_address(addr, size);
	}
#endif /* KASAN */
}


kern_return_t
kernel_memory_populate(
	vm_offset_t     addr,
	vm_size_t       size,
	kma_flags_t     flags,
	vm_tag_t        tag)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_page_t       page_list = NULL;
	vm_size_t       page_count = atop_64(size);
	vm_object_t     object = __kmem_object(ANYF(flags));

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */

#if HAS_MTE
	assert(mte_kern_enabled() || (flags & KMA_TAG) == 0);
#endif /* HAS_MTE */

	kr = vm_page_alloc_list(page_count, flags, &page_list);
	if (kr == KERN_SUCCESS) {
		vm_object_lock(object);
		kernel_memory_populate_object_and_unlock(object, addr,
		    addr, size, page_list, flags, tag, VM_PROT_DEFAULT,
		    __kmem_mapping_type(ANYF(flags)));
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_END,
	    page_count, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
	return kr;
}

void
kernel_memory_depopulate(
	vm_offset_t        addr,
	vm_size_t          size,
	kma_flags_t        flags,
	vm_tag_t           tag)
{
	vm_object_t        object = __kmem_object(ANYF(flags));
	vm_object_offset_t offset = addr;
	vm_page_t          mem;
	vm_page_t          local_freeq = NULL;
	unsigned int       pages_unwired = 0;

	vm_object_lock(object);

	pmap_protect(kernel_pmap, offset, offset + size, VM_PROT_NONE);

	for (vm_object_offset_t pg_offset = 0;
	    pg_offset < size;
	    pg_offset += PAGE_SIZE_64) {
		mem = vm_page_lookup(object, offset + pg_offset);

		assert(mem);

		if (flags & KMA_COMPRESSOR) {
			assert(mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR);
		} else {
			assert(VM_PAGE_WIRED(mem));
			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));
			pages_unwired++;
		}

		mem->vmp_busy = TRUE;

		assert(mem->vmp_tabled);
		vm_page_remove(mem);
		assert(mem->vmp_busy);

		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);

		mem->vmp_q_state = VM_PAGE_NOT_ON_Q;
		mem->vmp_snext = local_freeq;
		local_freeq = mem;
	}

	vm_object_unlock(object);

	vm_page_free_list(local_freeq, TRUE);

	if (!(flags & KMA_COMPRESSOR)) {
		vm_page_lockspin_queues();
		vm_page_wire_count -= pages_unwired;
		vm_page_unlock_queues();
	}

	if (flags & KMA_KOBJECT) {
		/* vm_page_remove() handles regular objects already */
		vm_tag_update_size(tag, -ptoa_64(pages_unwired), NULL);
	}
}

#pragma mark reallocation

__abortlike
static void
__kmem_realloc_invalid_object_panic(
	vm_map_t                map,
	vm_address_t            address,
	vm_size_t               size,
	vm_map_entry_t          entry)
{
	vm_object_t object     = VME_OBJECT(entry);
	vm_size_t   objsize    = __kmem_entry_orig_size(entry);
	memory_object_t pager  = object->pager;
	bool pager_created     = object->pager_created;
	bool pager_initialized = object->pager_initialized;
	bool pager_ready       = object->pager_ready;

	if (pager_created || pager) {
		panic("kmem_realloc(map=%p, addr=%p, size=%zd, entry=%p): "
		    "object %p has unexpected pager %p (%d,%d,%d)",
		    map, (void *)address, (size_t)size, entry, object,
		    pager, pager_created, pager_initialized, pager_ready);
	}

	panic("kmem_realloc(map=%p, addr=%p, size=%zd, entry=%p): "
	    "object %p has unexpected size %ld",
	    map, (void *)address, (size_t)size, entry, object, objsize);
}

static kmem_return_t
kmem_realloc_shrink_guard_and_iunlock(
	vm_map_find_lock_ctx_t  ctx,
	vm_offset_t             req_oldaddr,
	vm_size_t               req_oldsize,
	vm_size_t               req_newsize,
	kmr_flags_t             flags,
	kmem_guard_t            guard)
{
	vm_map_entry_t          del_entry;
	vm_object_t             object;
	vm_offset_t             delta = 0;
	kmem_return_t           kmr;
	bool                    was_atomic;
	vm_size_t               oldsize = round_page(req_oldsize);
	vm_size_t               newsize = round_page(req_newsize);
	vm_address_t            oldaddr = req_oldaddr;

	vm_map_t map = ctx->vmlc_map;
	vm_map_entry_t entry = vm_map_found_entry_get_entry(ctx);
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		assert((flags & (KMR_GUARD_FIRST | KMR_GUARD_LAST)) == 0);
		flags   |= KMR_GUARD_FIRST | KMR_GUARD_LAST;
		oldaddr -= PAGE_SIZE;
		delta    = ptoa(2);
		oldsize += delta;
		newsize += delta;
	}
#endif /* KASAN_CLASSIC */

	if (flags & KMR_TAG) {
		oldaddr = vm_memtag_canonicalize_kernel(req_oldaddr);
	}

	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_EXCLUSIVE);

	if ((flags & KMR_KOBJECT) == 0) {
		object = VME_OBJECT(entry);
		vm_object_reference(object);
	}

	/*
	 *	Shrinking an atomic entry starts with splitting it,
	 *	and removing the second half.
	 */
	was_atomic = entry->vme_atomic;
	entry->vme_atomic = false;
	del_entry = vm_map_found_entry_clip_end_ilocked(ctx, entry->vme_start + newsize);
	vm_map_ilk_unlock(map);
	entry->vme_atomic = was_atomic;

#if KASAN
	if (entry->vme_kernel_object && was_atomic) {
		entry->vme_object_or_delta = (-req_newsize & PAGE_MASK) + delta;
	}
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		kasan_poison_range(oldaddr + newsize, oldsize - newsize,
		    ASAN_VALID);
	}
#endif
#if KASAN_TBI
	if (flags & KMR_TAG) {
		kasan_tbi_mark_free_space((caddr_t)req_oldaddr + newsize, oldsize - newsize);
	}
#endif /* KASAN_TBI */
#endif /* KASAN */
	vm_map_found_entry_ex_unlock(ctx, NULL);

	vm_map_remove_entry(map, del_entry, VM_MAP_REMOVE_KUNWIRE);
	vm_map_entry_free_locked(map, del_entry);

	/*
	 *	Lastly, if there are guard pages, deal with them.
	 *
	 *	The kernel object just needs to depopulate,
	 *	regular objects require freeing the last page
	 *	and replacing it with a guard.
	 */
	if (flags & KMR_KOBJECT) {
		if (flags & KMR_GUARD_LAST) {
			kma_flags_t dflags = KMA_KOBJECT;
#if HAS_MTE
			dflags |= (ANYF(flags) & KMEM_TAG);
#endif
			kernel_memory_depopulate(oldaddr + newsize - PAGE_SIZE,
			    PAGE_SIZE, dflags, guard.kmg_tag);
		}
	} else {
		vm_page_t guard_right = VM_PAGE_NULL;
		vm_offset_t remove_start = newsize;

		if (flags & KMR_GUARD_LAST) {
			if (!map->never_faults) {
				guard_right = vm_page_create_guard(true);
			}
			remove_start -= PAGE_SIZE;
		}

		vm_object_lock(object);

		if (object->vo_size != oldsize) {
			__kmem_realloc_invalid_object_panic(map,
			    req_oldaddr, req_oldsize + delta, entry);
		}
		vm_object_set_size(object, newsize, req_newsize);

		vm_object_page_remove(object, remove_start, oldsize);

		if (guard_right) {
			vm_page_insert(guard_right, object, newsize - PAGE_SIZE);
			guard_right->vmp_busy = false;
		}
		vm_object_unlock(object);
		vm_object_deallocate(object);
	}

	kmr.kmr_address = req_oldaddr;
	kmr.kmr_return  = 0;
#if KASAN_CLASSIC
	if (flags & KMA_KASAN_GUARD) {
		kasan_alloc_large(kmr.kmr_address, req_newsize);
	}
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
	if ((flags & KMR_TAG) && (flags & KMR_FREEOLD)) {
		kmr.kmr_ptr = vm_memtag_generate_and_store_tag(kmr.kmr_ptr, req_newsize);
		kasan_tbi_retag_unused_space(kmr.kmr_ptr, newsize, req_newsize);
	}
#endif /* KASAN_TBI */

	return kmr;
}

__mockable kmem_return_t
kmem_realloc_guard(
	vm_map_t                map,
	vm_offset_t             req_oldaddr,
	vm_size_t               req_oldsize,
	vm_size_t               req_newsize,
	kmr_flags_t             flags,
	kmem_guard_t            guard)
{
	vm_object_t             object;
	vm_size_t               oldsize;
	vm_size_t               newsize;
	vm_offset_t             delta = 0;
	vm_map_offset_t         oldaddr;
	vm_map_offset_t         newaddr;
	vm_object_offset_t      newoffs;
	vm_map_entry_t          oldentry;
	vm_map_entry_t          newentry;
	vm_page_t               page_list = NULL;
	kmem_return_t           kmr = { };
	vm_map_kernel_flags_t   vmk_flags = {
		.vmkf_last_free = (bool)(flags & KMR_LAST_FREE),
	};
	kern_return_t kr;

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	vmlp_api_start(KMEM_REALLOC_GUARD);

	assert(KMEM_REALLOC_FLAGS_VALID(flags));

	if (!guard.kmg_atomic) {
		if (!(flags & (KMR_DATA | KMR_DATA_SHARED))) {
			__kmem_invalid_arguments_panic("realloc", map, req_oldaddr,
			    req_oldsize, flags);
		}

		if (flags & KMR_KOBJECT) {
			__kmem_invalid_arguments_panic("realloc", map, req_oldaddr,
			    req_oldsize, flags);
		}
	}

	if (req_oldaddr == 0ul) {
		kmem_return_t ret = kmem_alloc_guard(map, req_newsize, 0, (kma_flags_t)flags, guard);
		vmlp_api_end(KMEM_REALLOC_GUARD, ret.kmr_return);
		return ret;
	}

	if (req_newsize == 0ul) {
		kmem_free_guard(map, req_oldaddr, req_oldsize,
		    (kmf_flags_t)flags, guard);
		vmlp_api_end(KMEM_REALLOC_GUARD, kmr.kmr_return);
		return kmr;
	}

	if (req_newsize >> VM_KERNEL_POINTER_SIGNIFICANT_BITS) {
		__kmem_invalid_size_panic(map, req_newsize, flags);
	}
	if (req_newsize < __kmem_guard_size(ANYF(flags))) {
		__kmem_invalid_size_panic(map, req_newsize, flags);
	}

	oldsize = round_page(req_oldsize);
	newsize = round_page(req_newsize);
	oldaddr = req_oldaddr;
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		flags   |= KMR_GUARD_FIRST | KMR_GUARD_LAST;
		oldaddr -= PAGE_SIZE;
		delta    = ptoa(2);
		oldsize += delta;
		newsize += delta;
	}
#endif /* KASAN_CLASSIC */
#if HAS_MTE
	if (!mte_kern_enabled()) {
		flags &= ~KMR_TAG;
	}
#endif /* HAS_MTE */
#if CONFIG_KERNEL_TAGGING
	if (flags & KMR_TAG) {
		vm_memtag_verify_tag(req_oldaddr + __kmem_guard_left(ANYF(flags)));
		oldaddr = vm_memtag_canonicalize_kernel(req_oldaddr);
#if HAS_MTE
		vmk_flags.vmf_mte = true;
#endif /* HAS_MTE */
	}
#endif /* CONFIG_KERNEL_TAGGING */

#if !KASAN
	/*
	 *	If not on a KASAN variant and no difference in requested size,
	 *	just return.
	 *
	 *	Otherwise we want to validate the size and re-tag for KASAN_TBI.
	 */
	if (oldsize == newsize) {
		kmr.kmr_address = req_oldaddr;
		vmlp_api_end(KMEM_REALLOC_GUARD, kmr.kmr_return);
		return kmr;
	}
#endif /* !KASAN */

	/*
	 *	If we're growing the allocation,
	 *	then reserve the pages we'll need,
	 *	and find a spot for its new place.
	 */
	if (oldsize < newsize) {
#if DEBUG || DEVELOPMENT
		VM_DEBUG_CONSTANT_EVENT(vm_kern_request,
		    DBG_VM_KERN_REQUEST, DBG_FUNC_START,
		    newsize - oldsize, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
		kmr.kmr_return = vm_page_alloc_list(atop(newsize - oldsize),
		    (kma_flags_t)flags, &page_list);
		if (kmr.kmr_return != KERN_SUCCESS) {
			goto alloc_fail;
		}
	}

	kr = vm_map_find_entry_ex_locked(ctx, &map, oldaddr, VMRL_FIND_EX_DEFAULT);
	if (kr != KERN_SUCCESS) {
		__kmem_entry_not_found_panic(map, req_oldaddr);
	}
	assert(!vm_map_lock_ctx_is_descended(ctx));
	oldentry = vm_map_found_entry_get_entry(ctx);

	vm_map_ilk_lock(vm_map_lock_ctx_get_map(ctx));

	kmem_entry_validate_guard(vm_map_lock_ctx_get_map(ctx), oldentry,
	    oldaddr, oldsize, guard);
	__kmem_realloc_validate_object(vm_map_lock_ctx_get_map(ctx),
	    oldentry, ANYF(flags));
	if (oldentry->vme_start != oldaddr ||
	    oldentry->vme_end - oldentry->vme_start != oldsize) {
		__kmem_realloc_invalid_object_panic(vm_map_lock_ctx_get_map(ctx),
		    req_oldaddr, req_oldsize + delta, oldentry);
	}

#if KASAN
	if (oldsize == newsize) {
		kmr.kmr_address = req_oldaddr;
		if (oldentry->vme_kernel_object) {
			oldentry->vme_object_or_delta = delta +
			    (-req_newsize & PAGE_MASK);
		} else {
			object = VME_OBJECT(oldentry);
			vm_object_lock(object);
			vm_object_set_size(object, newsize, req_newsize);
			vm_object_unlock(object);
		}

#if KASAN_CLASSIC
		if (flags & KMA_KASAN_GUARD) {
			kasan_alloc_large(kmr.kmr_address, req_newsize);
		}
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
		if ((flags & KMR_TAG) && (flags & KMR_FREEOLD)) {
			kmr.kmr_ptr = vm_memtag_generate_and_store_tag(kmr.kmr_ptr, req_newsize);
			kasan_tbi_retag_unused_space(kmr.kmr_ptr, newsize, req_newsize);
		}
#endif /* KASAN_TBI */
		vmlp_api_end(KMEM_REALLOC_GUARD, kmr.kmr_return);
		vm_map_ilk_unlock(vm_map_lock_ctx_get_map(ctx));
		vm_map_found_entry_ex_unlock(ctx, &map);
		return kmr;
	}
#endif /* KASAN */

	guard.kmg_tag = VME_ALIAS(oldentry);

	if (newsize < oldsize) {
		kmem_return_t ret = kmem_realloc_shrink_guard_and_iunlock(ctx, req_oldaddr,
		    req_oldsize, req_newsize, flags, guard);
		vmlp_api_end(KMEM_REALLOC_GUARD, kmr.kmr_return);
		return ret;
	}

	assert((flags & (KMR_DATA | KMR_DATA_SHARED | KMR_IO)) || guard.kmg_type_hash != 0);
	kmem_apply_security_policy(vm_map_lock_ctx_get_map(ctx),
	    (kma_flags_t)flags, guard, &vmk_flags);
	kmr.kmr_return = kmem_find_space(vm_map_lock_ctx_get_map(ctx),
	    newsize, 0, vmk_flags, &newentry);

	vm_map_ilk_unlock(vm_map_lock_ctx_get_map(ctx));

	if (__improbable(kmr.kmr_return != KERN_SUCCESS)) {
		vm_map_found_entry_ex_unlock(ctx, &map);
		goto alloc_fail;
	}

	/*
	 *	We are growing the entry
	 *
	 *	For regular objects we use the object `vo_size` updates
	 *	as a guarantee that no 2 kmem_realloc() can happen
	 *	concurrently (by doing it before the map is unlocked.
	 */

	object = VME_OBJECT(oldentry);
	vm_object_lock(object);
	vm_object_reference_locked(object);

	newaddr = newentry->vme_start;
	newoffs = oldsize;

	vmlp_range_event_entry(vm_map_lock_ctx_get_map(ctx), newentry);

	VME_OBJECT_SET(newentry, object, guard.kmg_atomic, guard.kmg_context);
	VME_ALIAS_SET(newentry, guard.kmg_tag);
	if (flags & KMR_KOBJECT) {
		VME_OFFSET_SET(newentry, newaddr);
		newentry->wired_count = 1;
		vme_btref_consider_and_set(newentry, __builtin_frame_address(0));
		newoffs = newaddr + oldsize;
#if KASAN
		newentry->vme_object_or_delta = delta +
		    (-req_newsize & PAGE_MASK);
#endif /* KASAN */
	} else {
		if (object->pager_created || object->pager ||
		    object->vo_size != oldsize) {
			/*
			 * We can't "realloc/grow" the pager, so pageable
			 * allocations should not go through this path.
			 */
			__kmem_realloc_invalid_object_panic(vm_map_lock_ctx_get_map(ctx),
			    req_oldaddr, req_oldsize + delta, oldentry);
		}
		vm_object_set_size(object, newsize, req_newsize);
	}


	/*
	 *	Now proceed with the population of pages.
	 *
	 *	Kernel objects can use the kmem population helpers.
	 *
	 *	Regular objects will insert pages manually,
	 *	then wire the memory into the new range.
	 */

	vm_size_t guard_right_size = __kmem_guard_right(ANYF(flags));

	if (flags & KMR_KOBJECT) {
		pmap_mapping_type_t mapping_type = __kmem_mapping_type(ANYF(flags));

		pmap_protect(kernel_pmap,
		    oldaddr, oldaddr + oldsize - guard_right_size,
		    VM_PROT_NONE);

		for (vm_object_offset_t offset = 0;
		    offset < oldsize - guard_right_size;
		    offset += PAGE_SIZE_64) {
			vm_page_t mem;

			mem = vm_page_lookup(object, oldaddr + offset);
			if (mem == VM_PAGE_NULL) {
				continue;
			}

			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));

			mem->vmp_busy = true;
			vm_page_remove(mem);
			vm_page_insert_wired(mem, object, newaddr + offset,
			    guard.kmg_tag);
			mem->vmp_busy = false;

			kernel_memory_populate_pmap_enter(object, newaddr,
			    offset, mem, VM_PROT_DEFAULT, 0, mapping_type);
		}

		kernel_memory_populate_object_and_unlock(object,
		    newaddr + oldsize - guard_right_size,
		    newoffs - guard_right_size,
		    newsize - oldsize,
		    page_list, (kma_flags_t)flags,
		    guard.kmg_tag, VM_PROT_DEFAULT, mapping_type);
	} else {
		vm_page_t guard_right = VM_PAGE_NULL;

		/*
		 *	Note: we are borrowing the new entry reference
		 *	on the object for the duration of this code,
		 *	which works because we keep the object locked
		 *	throughout.
		 */
		if ((flags & KMR_GUARD_LAST) && !vm_map_lock_ctx_get_map(ctx)->never_faults) {
			guard_right = vm_page_lookup(object, oldsize - PAGE_SIZE);
			assert(vm_page_is_guard(guard_right));
			guard_right->vmp_busy = true;
			vm_page_remove(guard_right);
		}

		if (flags & KMR_FREEOLD) {
			uint32_t  wires = 0;
			vm_page_t mem;

			/*
			 * Freeing the old mapping will make
			 * the old pages become pageable until
			 * the new mapping makes them wired again.
			 * Let's take an extra "wire_count" to
			 * prevent any accidental "page out".
			 * We'll have to undo that after wiring
			 * the new mapping.
			 */
			vm_object_reference_locked(object); /* keep object alive */

			vm_page_queue_iterate(&object->memq, mem, vmp_listq) {
				if (vm_page_is_guard(mem)) {
					continue;
				}
				assertf(VM_PAGE_WIRED(mem) &&
				    mem->vmp_wire_count >= 1,
				    "mem %p qstate %d wirecount %d",
				    mem, mem->vmp_q_state, mem->vmp_wire_count);
				mem->vmp_wire_count++;
				wires++;
			}

			assert3u(wires, ==, atop(oldsize -
			    __kmem_guard_right(ANYF(flags)) -
			    __kmem_guard_left(ANYF(flags))));
		}

		for (vm_object_offset_t offset = oldsize - guard_right_size;
		    offset < newsize - guard_right_size;
		    offset += PAGE_SIZE_64) {
			vm_page_t mem = page_list;

			page_list = mem->vmp_snext;
			mem->vmp_snext = VM_PAGE_NULL;
			assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);
			assert(!VM_PAGE_PAGEABLE(mem));

			vm_page_insert(mem, object, offset);
			mem->vmp_busy = false;
		}

		if (guard_right) {
			vm_page_insert(guard_right, object, newsize - PAGE_SIZE);
			guard_right->vmp_busy = false;
		}

		vm_object_unlock(object);
	}

	vm_entry_unlock_exclusive(vm_map_lock_ctx_get_map(ctx), newentry);

	/*
	 *	Unlock the entry and honor KMR_FREEOLD if needed.
	 */
	if (flags & KMR_FREEOLD) {
		vmr_flags_t vmr_flags = VM_MAP_REMOVE_KUNWIRE;

#if KASAN_CLASSIC
		if (flags & KMR_KASAN_GUARD) {
			kasan_poison_range(oldaddr, oldsize, ASAN_VALID);
		}
#endif
#if KASAN_TBI
		if (flags & KMR_TAG) {
			kasan_tbi_mark_free_space((caddr_t)req_oldaddr, oldsize);
		}
#endif /* KASAN_TBI */
		if (flags & KMR_GUARD_LAST) {
			vmr_flags |= VM_MAP_REMOVE_NOKUNWIRE_LAST;
		}

		vm_map_found_entry_ex_pop_curr(ctx);
		vm_map_remove_entry(vm_map_lock_ctx_get_map(ctx), oldentry, vmr_flags);
		vm_map_entry_free_locked(vm_map_lock_ctx_get_map(ctx), oldentry);
	}
	vm_map_found_entry_ex_unlock(ctx, &map);

	if ((flags & KMR_KOBJECT) == 0) {
		/*
		 * This must happen _after_ we do the KMR_FREEOLD,
		 * because wiring the pages will call into the pmap,
		 * and if the pages are typed XNU_KERNEL_RESTRICTED,
		 * this would cause a second mapping of the page and panic.
		 */
		kr = vm_map_wire_kernel(map,
		    vm_sanitize_wrap_addr(newaddr),
		    vm_sanitize_wrap_addr(newaddr + newsize),
		    vm_sanitize_wrap_prot(VM_PROT_DEFAULT),
		    guard.kmg_tag, FALSE);
		assert(kr == KERN_SUCCESS);

		if (flags & KMR_FREEOLD) {
			uint32_t  unwires = 0;
			vm_page_t mem;

			/*
			 * Undo the extra "wiring" we made above
			 * and release the extra reference we took
			 * on the object.
			 */
			vm_object_lock(object);

			vm_page_queue_iterate(&object->memq, mem, vmp_listq) {
				if (vm_page_is_guard(mem)) {
					continue;
				}
				if (mem->vmp_offset >= oldsize - guard_right_size) {
					continue;
				}
				assertf(VM_PAGE_WIRED(mem) &&
				    mem->vmp_wire_count >= 2,
				    "mem %p qstate %d wirecount %d",
				    mem, mem->vmp_q_state, mem->vmp_wire_count);
				mem->vmp_wire_count--;
				unwires++;
			}

			assert3u(unwires, ==, atop(oldsize -
			    __kmem_guard_right(ANYF(flags)) -
			    __kmem_guard_left(ANYF(flags))));

			vm_object_unlock(object);
			vm_object_deallocate(object); /* release extra ref */
		}
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_END,
	    atop(newsize - oldsize), 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
	kmr.kmr_address = newaddr;

#if KASAN
	kasan_notify_address(kmr.kmr_address, newsize);
#endif /* KASAN */
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		kmr.kmr_address += PAGE_SIZE;
		kasan_alloc_large(kmr.kmr_address, req_newsize);
	}
#endif /* KASAN_CLASSIC */
#if CONFIG_KERNEL_TAGGING
	if (flags & KMR_TAG) {
#if HAS_MTE
		kmr.kmr_address = vm_memtag_insert_tag(kmr.kmr_address,
		    vm_memtag_extract_tag(req_oldaddr));
		vm_memtag_store_tag((caddr_t)kmr.kmr_ptr + oldsize - guard_right_size,
		    newsize - oldsize);
#elif KASAN_TBI
		/*
		 * Validate the current buffer, then generate a new tag,
		 * even if the address is stable, it's a "new" allocation.
		 */
		__asan_loadN((vm_offset_t)kmr.kmr_address, oldsize);
		kmr.kmr_ptr = vm_memtag_generate_and_store_tag(kmr.kmr_ptr, req_newsize);
		kasan_tbi_retag_unused_space(kmr.kmr_ptr, newsize, req_newsize);
#endif /* KASAN_TBI */
	}
#endif /* CONFIG_KERNEL_TAGGING */

	vmlp_api_end(KMEM_REALLOC_GUARD, kmr.kmr_return);
	return kmr;

alloc_fail:
	if (page_list) {
		vm_page_free_list(page_list, FALSE);
	}
	if (flags & KMR_REALLOCF) {
		kmem_free_guard(map, req_oldaddr, req_oldsize,
		    flags & (KMF_TAG | KMF_GUARD_FIRST |
		    KMF_GUARD_LAST | KMF_KASAN_GUARD), guard);
	}
#if DEBUG || DEVELOPMENT
	if (oldsize < newsize) {
		VM_DEBUG_CONSTANT_EVENT(vm_kern_request,
		    DBG_VM_KERN_REQUEST, DBG_FUNC_END,
		    0, 0, 0, 0);
	}
#endif /* DEBUG || DEVELOPMENT */
	vmlp_api_end(KMEM_REALLOC_GUARD, kmr.kmr_return);
	return kmr;
}

#pragma mark map/remap/wire

kern_return_t
mach_vm_map_kernel(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         initial_size,
	mach_vm_offset_ut       mask,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	memory_object_offset_ut offset,
	boolean_t               copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance)
{
	/* range_id is set by vm_map_enter_mem_object */
	return vm_map_enter_mem_object(target_map,
	           address,
	           initial_size,
	           mask,
	           vmk_flags,
	           port,
	           offset,
	           copy,
	           cur_protection,
	           max_protection,
	           inheritance,
	           NULL,
	           0);
}

kern_return_t
mach_vm_remap_new_kernel(
	vm_map_t                target_map,
	mach_vm_offset_ut      *address,
	mach_vm_size_ut         size,
	mach_vm_offset_ut       mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_t                src_map,
	mach_vm_offset_ut       memory_address,
	boolean_t               copy,
	vm_prot_ut             *cur_protection,   /* IN/OUT */
	vm_prot_ut             *max_protection,   /* IN/OUT */
	vm_inherit_ut           inheritance)
{
	if (!vm_map_kernel_flags_check_vm_and_kflags(vmk_flags,
	    VM_FLAGS_USER_REMAP)) {
		return KERN_INVALID_ARGUMENT;
	}


	vmk_flags.vmf_return_data_addr = true;

	/* range_id is set by vm_map_remap */
	return vm_map_remap(target_map,
	           address,
	           size,
	           mask,
	           vmk_flags,
	           src_map,
	           memory_address,
	           copy,
	           cur_protection,
	           max_protection,
	           inheritance);
}

#pragma mark free

#if KASAN

__abortlike
static void
__kmem_free_invalid_object_size_panic(
	vm_map_t                map,
	vm_address_t            address,
	vm_size_t               size,
	vm_map_entry_t          entry)
{
	vm_object_t object  = VME_OBJECT(entry);
	vm_size_t   objsize = __kmem_entry_orig_size(entry);

	panic("kmem_free(map=%p, addr=%p, size=%zd, entry=%p): "
	    "object %p has unexpected size %ld",
	    map, (void *)address, (size_t)size, entry, object, objsize);
}

#endif /* KASAN */

__mockable vm_size_t
kmem_free_guard(
	vm_map_t        map,
	vm_offset_t     req_addr,
	vm_size_t       req_size,
	kmf_flags_t     flags,
	kmem_guard_t    guard)
{
	vm_map_entry_t  entry = VM_MAP_ENTRY_NULL;
	vm_address_t    addr  = req_addr;
	vm_offset_t     delta = 0;
	vm_size_t       size;

	vmlp_api_start(KMEM_FREE_GUARD);

	assert(map->pmap == kernel_pmap);

#if KASAN_CLASSIC
	if (flags & KMF_KASAN_GUARD) {
		addr  -= PAGE_SIZE;
		delta  = ptoa(2);
	}
#endif /* KASAN_CLASSIC */
#if CONFIG_KERNEL_TAGGING
	if (flags & KMF_TAG) {
		vm_memtag_verify_tag(req_addr + __kmem_guard_left(ANYF(flags)));
		addr = vm_memtag_canonicalize_kernel(req_addr);
	}
#endif /* CONFIG_KERNEL_TAGGING */

	vm_map_ilk_lock(map);

	if (flags & KMF_GUESS_SIZE) {
		entry = vm_map_lookup(map, addr);
		if (entry == VM_MAP_ENTRY_NULL) {
			__kmem_entry_not_found_panic(map, req_addr);
		}
		req_size = __kmem_entry_orig_size(entry);
		size = round_page(req_size);
	} else if (req_size == 0) {
		__kmem_invalid_size_panic(map, req_size, flags);
	} else {
		size = round_page(req_size);
#if KASAN
		entry = vm_map_lookup(map, addr);
		if (entry == VM_MAP_ENTRY_NULL) {
			__kmem_entry_not_found_panic(map, req_addr);
		}
#endif /* KASAN */
	}

#if KASAN
	if (guard.kmg_atomic && entry->vme_kernel_object &&
	    __kmem_entry_orig_size(entry) != req_size) {
		/*
		 * We can't make a strict check for regular
		 * VM objects because it could be:
		 *
		 * - the kmem_guard_free() of a kmem_realloc_guard() without
		 *   KMR_FREEOLD, and in that case the object size won't match.
		 *
		 * - a submap, in which case there is no "orig size".
		 */
		__kmem_free_invalid_object_size_panic(map,
		    req_addr, req_size + delta, entry);
	}
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		kasan_poison_range(addr, size + delta, ASAN_VALID);
	}
#endif
#if KASAN_TBI
	if (flags & KMF_TAG) {
		kasan_tbi_mark_free_space((caddr_t)req_addr, size + delta);
	}
#endif /* KASAN_TBI */
#endif /* KASAN */

	/*
	 * vm_map_remove_and_unlock is called with VM_MAP_REMOVE_KUNWIRE, which
	 * unwires the kernel mapping. The page won't be mapped any longer so
	 * there is no extra step that is required for memory tagging to "clear"
	 * it -- the page will be later laundered when reused.
	 */
	vmlp_range_event(map, addr, size);
	vmlp_api_end(KMEM_FREE_GUARD, 0);
	(void)vm_map_remove_and_iunlock(map, addr, addr + size + delta,
	    VM_MAP_REMOVE_KUNWIRE, guard);
	return size;
}

__exported void
kmem_free_external(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       size);
void
kmem_free_external(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       size)
{
	if (size) {
		kmem_free(map, trunc_page(addr), size);
#if MACH_ASSERT
	} else {
		printf("kmem_free(map=%p, addr=%p) called with size=0, lr: %p\n",
		    map, (void *)addr, __builtin_return_address(0));
#endif
	}
}

/*
 * Returns a 16bit random number between 0 and
 * upper_limit (inclusive)
 */
__startup_func
uint16_t
kmem_get_random16(
	uint16_t                upper_limit)
{
	static uint64_t random_entropy;
	assert(upper_limit < UINT16_MAX);
	if (random_entropy == 0) {
		random_entropy = early_random();
	}
	uint32_t result = random_entropy & UINT32_MAX;
	random_entropy >>= 32;
	return (uint16_t)(result % (upper_limit + 1));
}

#pragma mark kmem init

/*
 * The default percentage of memory that can be mlocked is scaled based on the total
 * amount of memory in the system. These percentages are caclulated
 * offline and stored in this table. We index this table by
 * log2(max_mem) - VM_USER_WIREABLE_MIN_CONFIG. We clamp this index in the range
 * [0, sizeof(wire_limit_percents) / sizeof(vm_map_size_t))
 *
 * Note that these values were picked for mac.
 * If we ever have very large memory config arm devices, we may want to revisit
 * since the kernel overhead is smaller there due to the larger page size.
 */

/* Start scaling iff we're managing > 2^32 = 4GB of RAM. */
#define VM_USER_WIREABLE_MIN_CONFIG 32
#if CONFIG_JETSAM
/* Systems with jetsam can wire a bit more b/c the system can relieve wired
 * pressure.
 */
static vm_map_size_t wire_limit_percents[] =
{ 80, 80, 80, 80, 82, 85, 88, 91, 94, 97};
#else
static vm_map_size_t wire_limit_percents[] =
{ 70, 73, 76, 79, 82, 85, 88, 91, 94, 97};
#endif /* CONFIG_JETSAM */

/* Set limit to 95% of DRAM if serverperfmode=1 */
#define VM_USER_SERVERPERF_WIRE_LIMIT_PERCENT 95
/* Use special serverperfmode behavior iff DRAM > 2^35 = 32GiB of RAM. */
#define VM_USER_SERVERPERF_WIREABLE_MIN_CONFIG 35

/*
 * Sets the default global user wire limit which limits the amount of
 * memory that can be locked via mlock() based on the above algorithm..
 * This can be overridden via a sysctl.
 */
static void
kmem_set_user_wire_limits(void)
{
	uint64_t available_mem_log;
	uint64_t max_wire_percent;
	size_t wire_limit_percents_length = sizeof(wire_limit_percents) /
	    sizeof(vm_map_size_t);
	vm_map_size_t limit;
	uint64_t config_memsize = max_mem;
#if defined(XNU_TARGET_OS_OSX)
	config_memsize = max_mem_actual;
#endif /* defined(XNU_TARGET_OS_OSX) */

	available_mem_log = bit_floor(config_memsize);

	if (serverperfmode &&
	    (available_mem_log >= VM_USER_SERVERPERF_WIREABLE_MIN_CONFIG)) {
		max_wire_percent = VM_USER_SERVERPERF_WIRE_LIMIT_PERCENT;
	} else {
		if (available_mem_log < VM_USER_WIREABLE_MIN_CONFIG) {
			available_mem_log = 0;
		} else {
			available_mem_log -= VM_USER_WIREABLE_MIN_CONFIG;
		}
		if (available_mem_log >= wire_limit_percents_length) {
			available_mem_log = wire_limit_percents_length - 1;
		}
		max_wire_percent = wire_limit_percents[available_mem_log];
	}

	limit = config_memsize * max_wire_percent / 100;
	/* Cap the number of non lockable bytes at VM_NOT_USER_WIREABLE_MAX */
	if (config_memsize - limit > VM_NOT_USER_WIREABLE_MAX) {
		limit = config_memsize - VM_NOT_USER_WIREABLE_MAX;
	}

	vm_global_user_wire_limit = limit;
	/* the default per task limit is the same as the global limit */
	vm_per_task_user_wire_limit = limit;
	vm_add_wire_count_over_global_limit = 0;
	vm_add_wire_count_over_user_limit = 0;
}

#define KMEM_MAX_CLAIMS 50
__startup_data
struct kmem_range_startup_spec kmem_claims[KMEM_MAX_CLAIMS] = {};

#if !MACH_ASSERT
__startup_data
#endif /* !MACH_ASSERT */
uint32_t kmem_claim_count = 0;

#if MACH_ASSERT
/**
 * Save off some minimal information about the ranges for consumption by
 * post-lockdown tests.
 */
static struct mach_vm_range kmem_test_saved_ranges[KMEM_MAX_CLAIMS];
#endif /* MACH_ASSERT */

/**
 * For a requested claim size (i.e. kc_size), get the number of bytes which
 * should actually be allocated for a region in order to be able to properly
 * provide the requested size (the allocation size).
 *
 * This allocation size is always greater or equal to the claim size. It can,
 * for example, include additional space as required by the kernel memory
 * configuration.
 *
 * @param known_last Is the claim in question known to be the last region after
 * all placing has completed? The size for a known_last allocation is always
 * less than or equal to a non-known_last allocation of the same size.
 */
__startup_func
static vm_map_size_t
kmem_claim_to_allocation_size(vm_map_size_t claim_size, bool known_last)
{
	(void)known_last;
	/*
	 * Allocation size and claim size are identical.
	 */
	return claim_size;
}

/**
 * Compute the largest claim which can be made from a given allocation size.
 */
static vm_map_size_t
kmem_allocation_to_claim_size(vm_map_size_t allocation_size)
{
	/*
	 * Allocation size and claim size are identical.
	 */
	return allocation_size;
}

__startup_func
void
kmem_range_startup_init(
	struct kmem_range_startup_spec *sp)
{
	assert(kmem_claim_count < KMEM_MAX_CLAIMS - KMEM_RANGE_COUNT);
	if (sp->kc_calculate_sz) {
		sp->kc_size = (sp->kc_calculate_sz)();
	}
	if (sp->kc_size) {
		kmem_claims[kmem_claim_count] = *sp;
		kmem_claim_count++;
	}
}

__attribute__((always_inline))
static void
kmem_insert_entry(vm_map_address_t start, vm_map_address_t end, bool guard)
{
	vm_map_entry_t entry;

	entry = vm_map_entry_create_locked(kernel_map, start, end);
	if (guard) {
		entry->vme_atomic = true;
		entry->vme_permanent = true;
		entry->protection = VM_PROT_NONE;
		entry->max_protection = VM_PROT_NONE;
	} else {
		entry->use_pmap = true;
		entry->protection = VM_PROT_DEFAULT;
		entry->max_protection = VM_PROT_DEFAULT;
		vm_object_reference(kernel_object_default);
		VME_OBJECT_SET(entry, kernel_object_default, false, 0);
		VME_OFFSET_SET(entry, entry->vme_start);
	}
	vm_map_store_insert(kernel_map, entry);
	vm_entry_unlock_exclusive(kernel_map, entry);
}

__attribute__((always_inline))
static struct mach_vm_range
kmem_fuzz_start(void)
{
	vm_map_store_rsv_t   rsv  = { };
	struct mach_vm_range hole = { };
	struct mach_vm_range range = {
		vm_map_min(kernel_map),
		vm_map_max(kernel_map),
	};
	uint32_t kmapoff_pgcnt;

	kmapoff_pgcnt = (early_random() & 0x1ff) + 1; /* 9 bits */

	vm_map_size_t kmapoff_size = ptoa(kmapoff_pgcnt);

	vm_map_ilk_lock(kernel_map);

	/*
	 * Only keep the largest hole, fill the others
	 */
	while (vm_map_store_find_space(kernel_map, range,
	    VM_MAP_KERNEL_FLAGS_NONE, PAGE_SIZE, 0, &rsv) == KERN_SUCCESS) {
		vm_map_size_t hole_size;

		hole_size = vm_map_store_lookup_hole(kernel_map,
		    vmsr_start(rsv), vm_map_max(kernel_map));
		if (mach_vm_range_size(&hole) < hole_size) {
			if (hole.min_address) {
				kmem_insert_entry(hole.min_address,
				    hole.max_address, true);
			}
			hole.min_address = vmsr_start(rsv);
			hole.max_address = vmsr_start(rsv) + hole_size;
		} else {
			kmem_insert_entry(vmsr_start(rsv),
			    vmsr_start(rsv) + hole_size, true);
		}

		range.min_address = vmsr_start(rsv) + hole_size;
	}
	assert(mach_vm_range_size(&hole));

	kmem_insert_entry(hole.min_address, hole.min_address + kmapoff_size, true);
	vm_map_ilk_unlock(kernel_map);

	hole.min_address += kmapoff_size;
	return hole;
}

/*
 * Generate a randomly shuffled array of indices from 0 to count - 1
 */
__startup_func
void
kmem_shuffle(uint16_t *shuffle_buf, uint16_t count)
{
	for (uint16_t i = 0; i < count; i++) {
		uint16_t j = kmem_get_random16(i);
		if (j != i) {
			shuffle_buf[i] = shuffle_buf[j];
		}
		shuffle_buf[j] = i;
	}
}

__startup_func
static void
kmem_shuffle_claims(void)
{
	uint16_t shuffle_buf[KMEM_MAX_CLAIMS] = {};
	uint16_t limit = (uint16_t)kmem_claim_count;

	kmem_shuffle(&shuffle_buf[0], limit);
	for (uint16_t i = 0; i < limit; i++) {
		struct kmem_range_startup_spec tmp = kmem_claims[i];
		kmem_claims[i] = kmem_claims[shuffle_buf[i]];
		kmem_claims[shuffle_buf[i]] = tmp;
	}
}

__startup_func
static void
kmem_readjust_ranges(
	uint32_t        cur_idx)
{
	assert(cur_idx != 0);
	uint32_t j = cur_idx - 1, random;
	struct kmem_range_startup_spec sp = kmem_claims[cur_idx];
	struct mach_vm_range *sp_range = sp.kc_range;
	/*
	 * Even if sp is currently last, it will never be last after it is moved.
	 * As such, we want to bump other claims over it and include any necessary
	 * padding for a non-last claim.
	 *
	 * While changing which claim is last can impact the total VA usage, since a
	 * known_last allocation size is guaranteed to always be less-than-or-equal
	 * to a non-known_last allocation (which is used for pre-placement sizing),
	 * we will always have enough space so long as the pre-placement sizing had
	 * enough space.
	 */
	vm_map_offset_t sp_allocation_size =
	    kmem_claim_to_allocation_size(sp.kc_size, /* known_last */ false);

	/*
	 * Find max index where restriction is met
	 */
	for (; j > 0; j--) {
		struct kmem_range_startup_spec spj = kmem_claims[j];
		vm_map_offset_t max_start = spj.kc_range->min_address;
		if (spj.kc_flags & KC_NO_MOVE) {
			panic("kmem_range_init: Can't scramble with multiple constraints");
		}
		if (max_start <= sp_range->min_address) {
			break;
		}
	}

	/*
	 * Pick a random index from 0 to max index and shift claims to the right
	 * to make room for restricted claim
	 */
	random = kmem_get_random16((uint16_t)j);
	assert(random <= j);

	sp_range->min_address = kmem_claims[random].kc_range->min_address;
	sp_range->max_address = sp_range->min_address + sp.kc_size;

	for (j = cur_idx - 1; j >= random && j != UINT32_MAX; j--) {
		struct kmem_range_startup_spec spj = kmem_claims[j];
		struct mach_vm_range *range = spj.kc_range;
		range->min_address += sp_allocation_size;
		range->max_address += sp_allocation_size;
		kmem_claims[j + 1] = spj;
	}

	sp.kc_flags |= KC_NO_MOVE;
	kmem_claims[random] = sp;
}

__startup_func
static void
kmem_add_extra_claims(struct mach_vm_range km_range)
{
	vm_map_size_t free_size = mach_vm_range_size(&km_range);
	vm_map_size_t total_claims = 0;
	vm_map_size_t ptr_total_allocation_size = 0;
	uint32_t      kmem_ptr_ranges = KMEM_RANGE_ID_NUM_PTR;

	/*
	 * kasan and configs w/o *TRR need to have just one ptr range due to
	 * resource constraints.
	 */
#if !ZSECURITY_CONFIG(KERNEL_PTR_SPLIT)
	kmem_ptr_ranges = 1;
#endif

	kmem_claims[kmem_claim_count++] = (struct kmem_range_startup_spec){
		.kc_name  = "kmem_io",
		.kc_range = kmem_range(KMEM_RANGE_ID_IO),
		.kc_size  = (1u << 30),
		.kc_flags = KC_NO_ENTRY,
	};

	/*
	 * Determine size of data and pointer kmem_ranges
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp_i = kmem_claims[i];

		total_claims += kmem_claim_to_allocation_size(
			sp_i.kc_size, /* known_last */ false);
	}
	assert((total_claims & PAGE_MASK) == 0);


	free_size -= total_claims;

	/*
	 * Use a little less than half the total available VA for
	 * all pointer allocations. Given that we have 3 total ranges
	 * divide the available VA by 7.
	 */
	ptr_range_size = free_size / (kmem_ptr_ranges * 2 + 1);
	ptr_range_size = round_page(ptr_range_size);

	/* Less any necessary allocation padding... */
	ptr_range_size = kmem_allocation_to_claim_size(ptr_range_size);

	/*
	 * Add the pointer and metadata claims
	 * Note: this call modifies ptr_range_size and may, depending on the padding
	 * requirements, slightly increase or decrease the overall allocation size
	 * of the pointer+metadata region.
	 */
	kmem_claims[kmem_claim_count++] = (struct kmem_range_startup_spec){
		.kc_name  = "kmem_ptr_range_0",
		.kc_range = kmem_range(KMEM_RANGE_ID_PTR_0),
		.kc_size  = ptr_range_size,
		.kc_flags = KC_NO_ENTRY,
	};
	if (kmem_ptr_ranges == KMEM_RANGE_ID_NUM_PTR) {
		kmem_claims[kmem_claim_count++] = (struct kmem_range_startup_spec){
			.kc_name  = "kmem_ptr_range_1",
			.kc_range = kmem_range(KMEM_RANGE_ID_PTR_1),
			.kc_size  = ptr_range_size,
			.kc_flags = KC_NO_ENTRY,
		};
		kmem_claims[kmem_claim_count++] = (struct kmem_range_startup_spec){
			.kc_name  = "kmem_ptr_range_2",
			.kc_range = kmem_range(KMEM_RANGE_ID_PTR_2),
			.kc_size  = ptr_range_size,
			.kc_flags = KC_NO_ENTRY,
		};
	}

	ptr_total_allocation_size = kmem_ptr_ranges *
	    kmem_claim_to_allocation_size(ptr_range_size, /* known_last */ false);

	/*
	 * Check: ptr_range are minimally valid.
	 * This is a useful assert as it should catch us if we were to end up
	 * with a "negative" (or extremely large) data_range_size.
	 */
	assert(ptr_total_allocation_size < free_size);

	/*
	 * Finally, give any remaining allocable space to the data region.
	 */
	data_range_size = free_size - ptr_total_allocation_size;

	/*
	 * Divide the size for the data range between PRIVATE and SHARED.
	 *
	 * Round down the size, because our kmem ranges logic round
	 * these sizes to page size, and we need to make sure we never
	 * exceed the remaining allocable space we divided.
	 */
	shared_data_range_size = data_range_size =
	    trunc_page(data_range_size / 2);

	/* Less any necessary allocation padding... */
	data_range_size = kmem_allocation_to_claim_size(data_range_size);
	shared_data_range_size = shared_data_range_size ?
	    kmem_allocation_to_claim_size(shared_data_range_size) : 0;

	/* Check: our allocations should all still fit in the free space */
	assert(ptr_total_allocation_size +
	    kmem_claim_to_allocation_size(data_range_size, /* known_last */ false) +
	    kmem_claim_to_allocation_size(shared_data_range_size, /* known_last */ false) <=
	    free_size);

	kmem_claims[kmem_claim_count++] = (struct kmem_range_startup_spec) {
		.kc_name  = "kmem_data_private_range",
		.kc_range = kmem_range(KMEM_RANGE_ID_DATA_PRIVATE),
		.kc_size  = data_range_size,
		.kc_flags = KC_NO_ENTRY,
	};

	kmem_claims[kmem_claim_count++] = (struct kmem_range_startup_spec){
		.kc_name  = "kmem_data_shared_range",
		.kc_range = kmem_range(KMEM_RANGE_ID_DATA_SHARED),
		.kc_size  = shared_data_range_size,
		.kc_flags = KC_NO_ENTRY,
	};
}

__startup_func
static void
kmem_scramble_ranges(void)
{
	struct mach_vm_range km_range;

	/*
	 * Allocating the g_kext_map prior to randomizing the remaining submaps as
	 * this map is 2G in size and starts at the end of kernel_text on x86. It
	 * could overflow into the heap.
	 */
	kext_alloc_init();

	/*
	 * Eat a random amount of kernel_map to fuzz subsequent heap, zone and
	 * stack addresses. (With a 4K page and 9 bits of randomness, this
	 * eats about 2M of VA from the map)
	 *
	 * Note that we always need to slide by at least one page because the VM
	 * pointer packing schemes using KERNEL_PMAP_HEAP_RANGE_START as a base
	 * do not admit this address to be part of any zone submap.
	 */
	km_range = kmem_fuzz_start();

	/*
	 * Add claims for ptr and data kmem ranges
	 */
	kmem_add_extra_claims(km_range);

	/*
	 * Minimally verify that our placer will be able to resolve the constraints
	 * of all claims
	 */
	bool has_min_address = false;
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp_i = kmem_claims[i];

		/* Verify that we have only one claim with a min address constraint */
		if (sp_i.kc_range->min_address) {
			if (has_min_address) {
				panic("Cannot place with multiple min_address constraints");
			} else {
				has_min_address = true;
			}
		}

		if (sp_i.kc_range->max_address) {
			panic("Cannot place with a max_address constraint");
		}
	}


	/*
	 * Shuffle registered claims
	 */
	assert(kmem_claim_count < UINT16_MAX);
	kmem_shuffle_claims();

	vm_map_ilk_lock(kernel_map);

	/*
	 * Apply restrictions and determine range for each claim
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp = kmem_claims[i];
		struct mach_vm_range *sp_range = sp.kc_range;

		/*
		 * Find space using the allocation size (rather than the claim size) in
		 * order to ensure we provide any applicable padding.
		 */
		bool is_last = (i == kmem_claim_count - 1);
		vm_map_offset_t hole_size, sp_size;

		hole_size = vm_map_store_lookup_hole(kernel_map,
		    km_range.min_address, vm_map_max(kernel_map));
		sp_size   = kmem_claim_to_allocation_size(sp.kc_size, is_last);

		if (hole_size < sp_size) {
			panic("kmem_range_init: vm_map_store_lookup_hole() "
			    "failing for claim %s, hole %#llx < size %#llx",
			    sp.kc_name, hole_size, sp_size);
		}

		/*
		 * Re-adjust ranges if restriction not met
		 */
		if (sp_range->min_address &&
		    sp_range->min_address < km_range.min_address) {
			kmem_readjust_ranges(i);
		} else {
			/*
			 * Though the actual allocated space may be larger, provide only the
			 * size requested by the original claim.
			 */
			sp_range->min_address = km_range.min_address;
			sp_range->max_address = km_range.min_address + sp.kc_size;
		}

		km_range.min_address += sp_size;
	}

	/*
	 * We have settled on the ranges, now create temporary entries for the
	 * claims
	 */

	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp = kmem_claims[i];
		bool is_last = (i == kmem_claim_count - 1);
		vm_map_address_t start;
		vm_map_offset_t  sp_full_size;

		/*
		 * We reserve the full allocation size (rather than the claim size) so
		 * that nothing ends up placed in the padding space (if applicable).
		 */
		start        = sp.kc_range->min_address;
		sp_full_size = kmem_claim_to_allocation_size(sp.kc_size, is_last);
		if ((sp.kc_flags & KC_NO_ENTRY) == 0) {
			kmem_insert_entry(start, start + sp.kc_size, false);
		}
		if (sp.kc_size < sp_full_size) {
			kmem_insert_entry(start + sp.kc_size,
			    start + sp_full_size, true);
		}
	}

	vm_map_ilk_unlock(kernel_map);

#if DEBUG || DEVELOPMENT
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp = kmem_claims[i];

		printf("%-24s: %p - %p (%u%c)\n", sp.kc_name,
		    (void *)sp.kc_range->min_address,
		    (void *)sp.kc_range->max_address,
		    mach_vm_size_pretty(sp.kc_size),
		    mach_vm_size_unit(sp.kc_size));
	}
#endif /* DEBUG || DEVELOPMENT */

#if MACH_ASSERT
	/*
	 * Since many parts of the claim infrastructure are marked as startup data
	 * (and are thus unavailable post-lockdown), save off information our tests
	 * need now.
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		kmem_test_saved_ranges[i] = *(kmem_claims[i].kc_range);
	}
#endif /* MACH_ASSERT */
}

__startup_func
static void
kmem_range_init(void)
{
	kmem_scramble_ranges();
	pmap_init();

	for (uint32_t i = 0; i < ARRAY_COUNT(kmem_slabs); i++) {
		vm_guard_object_slab_init(&kmem_slabs[i][KMEM_DIRECTION_FORWARDS]);
		vm_guard_object_slab_init(&kmem_slabs[i][KMEM_DIRECTION_BACKWARDS]);
	}
}
STARTUP(KMEM, STARTUP_RANK_THIRD, kmem_range_init);

/*
 *	kmem_init:
 *
 *	Initialize the kernel's virtual memory map, taking
 *	into account all memory allocated up to this time.
 */
__startup_func
void
kmem_init(
	vm_offset_t     start,
	vm_offset_t     end)
{
	vm_map_offset_t map_start;
	vm_map_offset_t map_end;

	map_start = vm_map_trunc_page(start,
	    VM_MAP_PAGE_MASK(kernel_map));
	map_end = vm_map_round_page(end,
	    VM_MAP_PAGE_MASK(kernel_map));

	vm_map_will_allocate_early_map(&kernel_map);
#if defined(__arm64__)
	_Static_assert(VM_MAX_KERNEL_ADDRESS <= (UINTPTR_MAX - ARM_PGBYTES),
	    "VM_MAX_KERNEL_ADDRESS will overflow if page-rounded");
	kernel_map = vm_map_create_options(pmap_kernel(),
	    VM_MIN_KERNEL_AND_KEXT_ADDRESS,
	    vm_map_round_page(VM_MAX_KERNEL_ADDRESS, VM_MAP_PAGE_MASK(kernel_map)),
	    VM_MAP_CREATE_DEFAULT);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	{
		unsigned int    region_select = 0;
		vm_map_offset_t region_start;
		vm_map_size_t   region_size;
		vm_map_offset_t map_addr;
		kern_return_t kr;

		while (pmap_virtual_region(region_select, &region_start, &region_size)) {
			map_addr = region_start;
			kr = vm_map_enter(kernel_map, &map_addr,
			    vm_map_round_page(region_size,
			    VM_MAP_PAGE_MASK(kernel_map)),
			    (vm_map_offset_t) 0,
			    VM_MAP_KERNEL_FLAGS_FIXED_PERMANENT(
				    .vmkf_no_soft_limit = true),
			    VM_OBJECT_NULL,
			    (vm_object_offset_t) 0, FALSE, VM_PROT_NONE, VM_PROT_NONE,
			    VM_INHERIT_DEFAULT);

			if (kr != KERN_SUCCESS) {
				panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x",
				    (uint64_t) start, (uint64_t) end, (uint64_t) region_start,
				    (uint64_t) region_size, kr);
			}

			region_select++;
		}
	}
#else
	kernel_map = vm_map_create_options(pmap_kernel(),
	    VM_MIN_KERNEL_AND_KEXT_ADDRESS, map_end,
	    VM_MAP_CREATE_DEFAULT);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	if (start != VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		vm_map_offset_t map_addr;
		kern_return_t kr;

		map_addr = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
		kr = vm_map_enter(kernel_map,
		    &map_addr,
		    (vm_map_size_t)(map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
		    (vm_map_offset_t) 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(),
		    VM_OBJECT_NULL,
		    (vm_object_offset_t) 0, FALSE,
		    VM_PROT_NONE, VM_PROT_NONE,
		    VM_INHERIT_DEFAULT);

		if (kr != KERN_SUCCESS) {
			panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x",
			    (uint64_t) start, (uint64_t) end,
			    (uint64_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			    (uint64_t) (map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
			    kr);
		}
	}
#endif

	kmem_set_user_wire_limits();
}


#pragma mark map copyio

/*
 * Note: semantic types aren't used as `copyio` already validates.
 */

kern_return_t
copyinmap(
	vm_map_t                map,
	vm_map_offset_t         fromaddr,
	void                   *todata,
	vm_size_t               length)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_switch_context_t switch_ctx;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(todata, CAST_DOWN(void *, fromaddr), length);
	} else if (current_map() == map) {
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		switch_ctx = vm_map_switch_with_sec_override(map, TRUE);
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}
	return kr;
}

kern_return_t
copyoutmap(
	vm_map_t                map,
	void                   *fromdata,
	vm_map_address_t        toaddr,
	vm_size_t               length)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_switch_context_t switch_ctx;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(CAST_DOWN(void *, toaddr), fromdata, length);
	} else if (current_map() == map) {
		if (copyout(fromdata, toaddr, length) != 0) {
			ktriage_record(thread_tid(current_thread()),
			    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
			    KDBG_TRIAGE_RESERVED,
			    KDBG_TRIAGE_VM_COPYOUTMAP_SAMEMAP_ERROR),
			    KERN_INVALID_ADDRESS /* arg */);
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		switch_ctx = vm_map_switch_with_sec_override(map, TRUE);
		if (copyout(fromdata, toaddr, length) != 0) {
			ktriage_record(thread_tid(current_thread()),
			    KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
			    KDBG_TRIAGE_RESERVED,
			    KDBG_TRIAGE_VM_COPYOUTMAP_DIFFERENTMAP_ERROR),
			    KERN_INVALID_ADDRESS /* arg */);
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}
	return kr;
}

kern_return_t
copyoutmap_atomic32(
	vm_map_t                map,
	uint32_t                value,
	vm_map_address_t        toaddr)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_switch_context_t switch_ctx;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct toaddr */
		*(uint32_t *)toaddr = value;
	} else if (current_map() == map) {
		if (copyout_atomic32(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		switch_ctx = vm_map_switch_with_sec_override(map, TRUE);
		if (copyout_atomic32(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}
	return kr;
}

kern_return_t
copyoutmap_atomic64(
	vm_map_t                map,
	uint64_t                value,
	vm_map_address_t        toaddr)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_switch_context_t switch_ctx;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct toaddr */
		*(uint64_t *)toaddr = value;
	} else if (current_map() == map) {
		if (copyout_atomic64(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		switch_ctx = vm_map_switch_with_sec_override(map, TRUE);
		if (copyout_atomic64(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch_back(switch_ctx);
		vm_map_deallocate(map);
	}
	return kr;
}


#pragma mark pointer obfuscation / packing

/*
 *
 *	The following two functions are to be used when exposing kernel
 *	addresses to userspace via any of the various debug or info
 *	facilities that exist. These are basically the same as VM_KERNEL_ADDRPERM()
 *	and VM_KERNEL_UNSLIDE_OR_PERM() except they use a different random seed and
 *	are exported to KEXTs.
 *
 *	NOTE: USE THE MACRO VERSIONS OF THESE FUNCTIONS (in vm_param.h) FROM WITHIN THE KERNEL
 */

vm_offset_t
vm_kernel_addrhash_internal(vm_offset_t addr, uint64_t salt)
{
	assert(salt != 0);

	if (addr == 0) {
		return 0ul;
	}

	if (VM_KERNEL_IS_SLID(addr)) {
		return VM_KERNEL_UNSLIDE(addr);
	}

#if HAS_MTE
	/*
	 * Remove traces of MTE tags or PAC signatures, to prevent observers from seeing
	 * identical repeated values.
	 */
#endif /* HAS_MTE */
	addr = VM_KERNEL_STRIP_PTR(addr);

	vm_offset_t sha_digest[SHA256_DIGEST_LENGTH / sizeof(vm_offset_t)];
	SHA256_CTX sha_ctx;

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, &salt, sizeof(salt));
	SHA256_Update(&sha_ctx, &addr, sizeof(addr));
	SHA256_Final(sha_digest, &sha_ctx);

	return sha_digest[0];
}

__exported vm_offset_t
vm_kernel_addrhash_external(vm_offset_t addr);
vm_offset_t
vm_kernel_addrhash_external(vm_offset_t addr)
{
	return vm_kernel_addrhash_internal(addr, vm_kernel_addrhash_salt_ext);
}

void
vm_kernel_addrhide(
	vm_offset_t addr,
	vm_offset_t *hide_addr)
{
	*hide_addr = VM_KERNEL_ADDRHIDE(addr);
}

void
vm_kernel_addrperm_external(
	vm_offset_t addr,
	vm_offset_t *perm_addr)
{
	addr = VM_KERNEL_STRIP_UPTR(addr);

	if (VM_KERNEL_IS_SLID(addr)) {
		*perm_addr = VM_KERNEL_UNSLIDE(addr);
	} else if (VM_KERNEL_ADDRESS(addr)) {
		*perm_addr = ML_ADDRPERM(addr, vm_kernel_addrperm_ext);
	} else {
		*perm_addr = addr;
	}
}

void
vm_kernel_unslide_or_perm_external(
	vm_offset_t addr,
	vm_offset_t *up_addr)
{
	vm_kernel_addrperm_external(addr, up_addr);
}

void
vm_packing_pointer_invalid(vm_offset_t ptr, vm_packing_params_t params)
{
	if (ptr & ((1ul << params.vmpp_shift) - 1)) {
		panic("pointer %p can't be packed: low %d bits aren't 0",
		    (void *)ptr, params.vmpp_shift);
	} else if (ptr <= params.vmpp_base) {
		panic("pointer %p can't be packed: below base %p",
		    (void *)ptr, (void *)params.vmpp_base);
	} else {
		panic("pointer %p can't be packed: maximum encodable pointer is %p",
		    (void *)ptr, (void *)vm_packing_max_packable(params));
	}
}

void
vm_packing_verify_range(
	const char *subsystem,
	vm_offset_t min_address,
	vm_offset_t max_address,
	vm_packing_params_t params)
{
	if (min_address > max_address) {
		panic("%s: %s range invalid min:%p > max:%p",
		    __func__, subsystem, (void *)min_address, (void *)max_address);
	}

	if (!params.vmpp_base_relative) {
		return;
	}

	if (min_address <= params.vmpp_base) {
		panic("%s: %s range invalid min:%p <= base:%p",
		    __func__, subsystem, (void *)min_address, (void *)params.vmpp_base);
	}

	if (max_address > vm_packing_max_packable(params)) {
		panic("%s: %s range invalid max:%p >= max packable:%p",
		    __func__, subsystem, (void *)max_address,
		    (void *)vm_packing_max_packable(params));
	}
}

#pragma mark tests
#if MACH_ASSERT
#include <sys/errno.h>

static void
kmem_test_for_entry(
	vm_map_t                map,
	vm_offset_t             addr,
	void                  (^block)(vm_map_entry_t))
{
	vm_map_ilk_lock(map);
	block(vm_map_lookup(map, addr));
	vm_map_ilk_unlock(map);
}

#define kmem_test_assert_map(map, pg, entries) ({ \
	assert3u((map)->size, ==, ptoa(pg)); \
	assert3u((map)->hdr.nentries, ==, entries); \
})

static bool
can_write_at(vm_offset_t offs, uint32_t page)
{
	static const int zero;

	return verify_write(&zero, (void *)(offs + ptoa(page) + 128), 1) == 0;
}
#define assert_writeable(offs, page) \
	assertf(can_write_at(offs, page), \
	    "can write at %p + ptoa(%d)", (void *)offs, page)

#define assert_faults(offs, page) \
	assertf(!can_write_at(offs, page), \
	    "can write at %p + ptoa(%d)", (void *)offs, page)

#define peek(offs, page) \
	(*(uint32_t *)((offs) + ptoa(page)))

#define poke(offs, page, v) \
	(*(uint32_t *)((offs) + ptoa(page)) = (v))

#if CONFIG_SPTM
__attribute__((noinline))
static void
kmem_test_verify_type_policy(vm_offset_t addr, kmem_flags_t flags)
{
	extern bool use_xnu_restricted;
	pmap_mapping_type_t expected_type = PMAP_MAPPING_TYPE_RESTRICTED;

	/* Explicitly state the expected policy */
	if (flags & (KMEM_COMPRESSOR | KMEM_DATA_SHARED)) {
		expected_type = PMAP_MAPPING_TYPE_DEFAULT;
	} else if ((flags & KMEM_DATA) &&
	    !kalloc_is_restricted_data_mode_enforced()) {
		expected_type = PMAP_MAPPING_TYPE_DEFAULT;
	}

	/* If X_K_R is disabled, DEFAULT is the only possible mapping */
	if (!use_xnu_restricted) {
		expected_type = PMAP_MAPPING_TYPE_DEFAULT;
	}

	/* Verify if derived correctly */
	assert3u(expected_type, ==, __kmem_mapping_type(flags));

	pmap_paddr_t pa = kvtophys(addr);
	if (pa == 0) {
		return;
	}

	/* Verify if the mapped address actually got the expected type */
	assert3u(expected_type, ==, sptm_get_frame_type(pa));
}
#endif /* CONFIG_SPTM */

__attribute__((noinline))
static void
kmem_alloc_basic_test(vm_map_t map)
{
	kmem_guard_t guard = {
		.kmg_tag       = VM_KERN_MEMORY_DIAG,
		.kmg_type_hash = KMEM_RANGE_ID_PTR_0, /* else kmem_realloc_guard() asserts */
	};
	vm_offset_t addr;

	/*
	 * Test wired basics:
	 * - KMA_KOBJECT
	 * - KMA_GUARD_FIRST, KMA_GUARD_LAST
	 * - allocation alignment
	 */
	addr = kmem_alloc_guard(map, ptoa(10), ptoa(2) - 1,
	    KMA_KOBJECT | KMA_GUARD_FIRST | KMA_GUARD_LAST, guard).kmr_address;
	assertf(addr != 0ull, "kma(%p, 10p, 0, KO | GF | GL)", map);
	assert3u((addr + PAGE_SIZE) % ptoa(2), ==, 0);
	kmem_test_assert_map(map, 10, 1);

	kmem_test_for_entry(map, addr, ^(__assert_only vm_map_entry_t e){
		assertf(e, "unable to find address %p in map %p", (void *)addr, map);
		assert(e->vme_kernel_object);
		assert(!e->vme_atomic);
		assert3u(e->vme_start, <=, addr);
		assert3u(addr + ptoa(10), <=, e->vme_end);
	});

	assert_faults(addr, 0);
	for (int i = 1; i < 9; i++) {
		assert_writeable(addr, i);
	}
	assert_faults(addr, 9);

	kmem_free(map, addr, ptoa(10));
	kmem_test_assert_map(map, 0, 0);

	/*
	 * Test pageable basics.
	 */
	addr = kmem_alloc_guard(map, ptoa(10), 0,
	    KMA_PAGEABLE, guard).kmr_address;
	assertf(addr != 0ull, "kma(%p, 10p, 0, KO | PG)", map);
	kmem_test_assert_map(map, 10, 1);

	for (int i = 0; i < 9; i++) {
		assert_faults(addr, i);
		poke(addr, i, 42);
		assert_writeable(addr, i);
	}

	kmem_free_guard(map, addr, ptoa(10),
	    KMF_GUARD_FIRST | KMF_GUARD_LAST, guard);
	kmem_test_assert_map(map, 0, 0);
}

__attribute__((noinline))
static void
kmem_realloc_basic_test(vm_map_t map, kmr_flags_t kind)
{
	kmem_guard_t guard = {
		.kmg_atomic    = !(kind & (KMR_DATA | KMR_DATA_SHARED)),
		.kmg_tag       = VM_KERN_MEMORY_DIAG,
		.kmg_context   = 0xefface,
		.kmg_type_hash = KMEM_RANGE_ID_PTR_0, /* else kmem_realloc_guard() asserts */
	};
	vm_offset_t addr, newaddr;
	const int N = 10;

	/*
	 *	This isn't something kmem_realloc_guard() _needs_ to do,
	 *	we could conceive an implementation where it grows in place
	 *	if there's space after it.
	 *
	 *	However, this is what the implementation does today.
	 */
	bool realloc_growth_changes_address = true;
	bool GF = (kind & KMR_GUARD_FIRST);
	bool GL = (kind & KMR_GUARD_LAST);

	/*
	 *	Initial N page allocation
	 */
	addr = kmem_alloc_guard(map, ptoa(N), 0,
	    (kind & ~KMEM_FREEOLD) | KMA_ZERO, guard).kmr_address;
	assert3u(addr, !=, 0);

	kmem_test_assert_map(map, N, 1);
	for (int pg = GF; pg < N - GL; pg++) {
		poke(addr, pg, 42 + pg);
	}
	for (int pg = N - GL; pg < N; pg++) {
		assert_faults(addr, pg);
	}

#if CONFIG_SPTM
	kmem_test_verify_type_policy(addr, ANYF(kind));
#endif /* CONFIG_SPTM */
	/*
	 *	Grow to N + 3 pages
	 */
	newaddr = kmem_realloc_guard(map, addr, ptoa(N), ptoa(N + 3),
	    kind | KMR_ZERO, guard).kmr_address;
	assert3u(newaddr, !=, 0);
	if (realloc_growth_changes_address) {
		assert3u(addr, !=, newaddr);
	}
	if ((kind & KMR_FREEOLD) || (addr == newaddr)) {
		kmem_test_assert_map(map, N + 3, 1);
	} else {
		kmem_test_assert_map(map, 2 * N + 3, 2);
	}
	for (int pg = GF; pg < N - GL; pg++) {
		assert3u(peek(newaddr, pg), ==, 42 + pg);
	}
	if ((kind & KMR_FREEOLD) == 0) {
		for (int pg = GF; pg < N - GL; pg++) {
			assert3u(peek(addr, pg), ==, 42 + pg);
		}
		/* check for tru-share */
		poke(addr + 16, 0, 1234);
		assert3u(peek(newaddr + 16, 0), ==, 1234);
		kmem_free_guard(map, addr, ptoa(N),
		    kind & (KMF_TAG | KMF_GUARD_FIRST | KMF_GUARD_LAST), guard);
		kmem_test_assert_map(map, N + 3, 1);
	}
	if (addr != newaddr) {
		for (int pg = GF; pg < N - GL; pg++) {
			assert_faults(addr, pg);
		}
	}
	for (int pg = N - GL; pg < N + 3 - GL; pg++) {
		assert3u(peek(newaddr, pg), ==, 0);
	}
	for (int pg = N + 3 - GL; pg < N + 3; pg++) {
		assert_faults(newaddr, pg);
	}
	addr = newaddr;


	/*
	 *	Shrink to N - 2 pages
	 */
	newaddr = kmem_realloc_guard(map, addr, ptoa(N + 3), ptoa(N - 2),
	    kind | KMR_ZERO, guard).kmr_address;
	assert3u(map->size, ==, ptoa(N - 2));
	assert3u(newaddr, ==, addr);
	kmem_test_assert_map(map, N - 2, 1);

	for (int pg = GF; pg < N - 2 - GL; pg++) {
		assert3u(peek(addr, pg), ==, 42 + pg);
	}
	for (int pg = N - 2 - GL; pg < N + 3; pg++) {
		assert_faults(addr, pg);
	}

	kmem_free_guard(map, addr, ptoa(N - 2),
	    kind & (KMF_TAG | KMF_GUARD_FIRST | KMF_GUARD_LAST), guard);
	kmem_test_assert_map(map, 0, 0);
}

static int
kmem_basic_test(__unused int64_t in, int64_t *out)
{
	vm_map_t map;
	vm_map_address_t addr;
	printf("%s: test running\n", __func__);

	map = kmem_suballoc(kernel_map, &addr, 64U << 20,
	        VM_MAP_CREATE_DEFAULT, VM_FLAGS_ANYWHERE,
	        KMS_NOFAIL | KMS_DATA_SHARED, VM_KERN_MEMORY_DIAG).kmr_submap;

	printf("%s: kmem_alloc ...\n", __func__);
	kmem_alloc_basic_test(map);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_KOBJECT | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_KOBJECT | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_FREEOLD | KMR_GUARD_FIRST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_FREEOLD | KMR_GUARD_FIRST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_FREEOLD | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_FREEOLD | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

#if HAS_MTE
	printf("%s: kmem_realloc (KMR_TAG | KMR_KOBJECT | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_KOBJECT | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_FREEOLD | KMR_GUARD_FIRST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_FREEOLD | KMR_GUARD_FIRST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_FREEOLD | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_FREEOLD | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_TAG | KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_TAG | KMR_FREEOLD | KMR_GUARD_FIRST | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);
#endif /* HAS_MTE */

	/* using KMR_DATA signals to test the non atomic realloc path */
	printf("%s: kmem_realloc (KMR_DATA | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_DATA | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	/*
	 * Using KMR_DATA without KMR_FREEOLD violates the
	 * single-mappability of RESTRICTED pages.
	 */

	/* test KMR_SHARED_DATA for the new shared kheap */
	printf("%s: kmem_realloc (KMR_DATA_SHARED | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_DATA_SHARED | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	/* test KMR_SHARED_DATA for the new shared kheap */
	printf("%s: kmem_realloc (KMR_DATA_SHARED) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_DATA_SHARED);
	printf("%s:     PASS\n", __func__);

	printf("%s: test passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kmem_basic, kmem_basic_test);


#endif /* MACH_ASSERT */
