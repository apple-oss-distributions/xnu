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
#include <vm/vm_kern.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_compressor.h>
#include <vm/vm_pageout.h>
#include <vm/vm_init.h>
#include <vm/vm_fault.h>
#include <kern/misc_protos.h>
#include <vm/cpm.h>
#include <kern/ledger.h>
#include <kern/bits.h>
#include <kern/startup.h>

#include <string.h>

#include <libkern/OSDebug.h>
#include <libkern/crypto/sha2.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>

#include <san/kasan.h>
#include <kern/kext_alloc.h>
#include <kern/backtrace.h>
#include <os/hash.h>
#include <kern/zalloc_internal.h>
#include <libkern/crypto/rand.h>

/*
 *	Variables exported by this module.
 */

SECURITY_READ_ONLY_LATE(vm_map_t) kernel_map;
SECURITY_READ_ONLY_LATE(struct mach_vm_range) kmem_ranges[KMEM_RANGE_COUNT];
SECURITY_READ_ONLY_LATE(struct mach_vm_range) kmem_large_ranges[KMEM_RANGE_COUNT];

static TUNABLE(uint32_t, kmem_ptr_ranges, "kmem_ptr_ranges",
    KMEM_RANGE_ID_NUM_PTR);
#define KMEM_GOBJ_THRESHOLD   (32ULL << 20)
#if DEBUG || DEVELOPMENT
#define KMEM_OUTLIER_LOG_SIZE (16ULL << 10)
#define KMEM_OUTLIER_SIZE      0
#define KMEM_OUTLIER_ALIGN     1
btlog_t kmem_outlier_log;
#endif /* DEBUG || DEVELOPMENT */

__startup_data static vm_map_size_t data_range_size;
__startup_data static vm_map_size_t ptr_range_size;
__startup_data static vm_map_size_t sprayqtn_range_size;

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

__abortlike
static void
__kmem_invalid_object_panic(uint32_t flags)
{
	if (flags == 0) {
		panic("KMEM_KOBJECT or KMEM_COMPRESSOR is required");
	}
	panic("more than one of KMEM_KOBJECT or KMEM_COMPRESSOR specified");
}

static inline vm_object_t
__kmem_object(kmem_flags_t flags)
{
	flags &= (KMEM_KOBJECT | KMEM_COMPRESSOR);
	if (flags == 0 || (flags & (flags - 1))) {
		__kmem_invalid_object_panic(flags);
	}

	return (flags & KMEM_KOBJECT) ? kernel_object : compressor_object;
}

static inline vm_size_t
__kmem_guard_left(kmem_flags_t flags)
{
	return (flags & KMEM_GUARD_FIRST) ? PAGE_SIZE : 0;
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

__pure2
static inline vm_size_t
__kmem_entry_orig_size(vm_map_entry_t entry)
{
	vm_object_t object = VME_OBJECT(entry);

	if (entry->vme_kernel_object) {
		return entry->vme_end - entry->vme_start -
		       entry->vme_object_or_delta;
	} else {
		return object->vo_size - object->vo_size_delta;
	}
}


#pragma mark kmem range methods

#if __arm64__
// <rdar://problem/48304934> arm64 doesn't use ldp when I'd expect it to
#define mach_vm_range_load(r, r_min, r_max) \
	asm("ldp %[rmin], %[rmax], [%[range]]" \
	    : [rmin] "=r"(r_min), [rmax] "=r"(r_max) \
	    : [range] "r"(r), "m"((r)->min_address), "m"((r)->max_address))
#else
#define mach_vm_range_load(r, rmin, rmax) \
	({ rmin = (r)->min_address; rmax = (r)->max_address; })
#endif

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

#if CONFIG_KERNEL_TBI
	if (VM_KERNEL_ADDRESS(addr)) {
		addr = VM_KERNEL_TBI_FILL(addr);
	}
#endif /* CONFIG_KERNEL_TBI */

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

#if CONFIG_KERNEL_TBI
	if (VM_KERNEL_ADDRESS(addr)) {
		addr = VM_KERNEL_TBI_FILL(addr);
	}
#endif /* CONFIG_KERNEL_TBI */

	/*
	 * The `&` is not a typo: we really expect the check to pass,
	 * so encourage the compiler to eagerly load and test without branches
	 */
	mach_vm_range_load(r, rmin, rmax);
	return (addr >= rmin) & (addr + size >= rmin) & (addr + size <= rmax);
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

#if CONFIG_KERNEL_TBI
	addr = VM_KERNEL_STRIP_UPTR(addr);
#endif /* CONFIG_KERNEL_TBI */
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
	return mach_vm_range_contains(&kmem_ranges[range_id], addr, size);
}

__abortlike
static void
kmem_range_invalid_panic(
	kmem_range_id_t         range_id,
	vm_map_offset_t         addr,
	vm_map_size_t           size)
{
	const struct mach_vm_range *r = &kmem_ranges[range_id];
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
	const struct mach_vm_range *r = &kmem_ranges[range_id];
	mach_vm_offset_t rmin, rmax;
	bool result = false;

#if CONFIG_KERNEL_TBI
	if (VM_KERNEL_ADDRESS(addr)) {
		addr = VM_KERNEL_TBI_FILL(addr);
	}
#endif /* CONFIG_KERNEL_TBI */

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

vm_map_size_t
kmem_range_id_size(kmem_range_id_t range_id)
{
	return mach_vm_range_size(&kmem_ranges[range_id]);
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

	return &kmem_ranges[range_id];
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

static bool
__kmem_entry_validate_object(
	vm_map_entry_t  entry,
	kmem_flags_t    flags)
{
	if (entry->is_sub_map) {
		return false;
	}
	if ((bool)(flags & KMEM_KOBJECT) != entry->vme_kernel_object) {
		return false;
	}

	return (bool)(flags & KMEM_COMPRESSOR) ==
	       (VME_OBJECT(entry) == compressor_object);
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

	vm_map_lock_read(map);

#if KASAN_CLASSIC
	addr -= PAGE_SIZE;
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
	addr = VM_KERNEL_TBI_FILL(addr);
#endif /* KASAN_TBI */

	if (!vm_map_lookup_entry(map, addr, &entry)) {
		__kmem_entry_not_found_panic(map, addr);
	}

	if (!__kmem_entry_validate_guard(entry, addr, 0, flags, guard)) {
		__kmem_entry_validate_panic(map, entry, addr, 0, flags, guard);
	}

	size = __kmem_entry_orig_size(entry);

	vm_map_unlock_read(map);

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

static_assert(KMEM_RANGE_ID_DATA - 1 <= KMEM_RANGE_MASK,
    "Insufficient bits to represent ptr ranges");

kmem_range_id_t
kmem_adjust_range_id(
	uint32_t                  hash)
{
	return (kmem_range_id_t) (KMEM_RANGE_ID_PTR_0 +
	       (hash & KMEM_RANGE_MASK) % kmem_ptr_ranges);
}

static bool
kmem_use_sprayqtn(
	kma_flags_t               kma_flags,
	vm_map_size_t             map_size,
	vm_offset_t               mask)
{
	/*
	 * Pointer allocations that are above the guard objects threshold or have
	 * leading guard pages with non standard alignment requests are redirected
	 * to the sprayqtn range.
	 */
#if DEBUG || DEVELOPMENT
	btref_get_flags_t flags = (kma_flags & KMA_NOPAGEWAIT) ?
	    BTREF_GET_NOWAIT : 0;

	if ((kma_flags & KMA_SPRAYQTN) == 0) {
		if (map_size > KMEM_GOBJ_THRESHOLD) {
			btlog_record(kmem_outlier_log, (void *)map_size, KMEM_OUTLIER_SIZE,
			    btref_get(__builtin_frame_address(0), flags));
		} else if ((kma_flags & KMA_GUARD_FIRST) && (mask > PAGE_MASK)) {
			btlog_record(kmem_outlier_log, (void *)mask, KMEM_OUTLIER_ALIGN,
			    btref_get(__builtin_frame_address(0), flags));
		}
	}
#endif /* DEBUG || DEVELOPMENT */

	return (kma_flags & KMA_SPRAYQTN) ||
	       (map_size > KMEM_GOBJ_THRESHOLD) ||
	       ((kma_flags & KMA_GUARD_FIRST) && (mask > PAGE_MASK));
}

static void
kmem_apply_security_policy(
	vm_map_t                  map,
	kma_flags_t               kma_flags,
	kmem_guard_t              guard,
	vm_map_size_t             map_size,
	vm_offset_t               mask,
	vm_map_kernel_flags_t    *vmk_flags,
	bool                      assert_dir __unused)
{
	kmem_range_id_t range_id;
	bool from_right;
	uint16_t type_hash = guard.kmg_type_hash;

	if (startup_phase < STARTUP_SUB_KMEM || map != kernel_map) {
		return;
	}

	/*
	 * A non-zero type-hash must be passed by krealloc_type
	 */
#if (DEBUG || DEVELOPMENT)
	if (assert_dir && !(kma_flags & KMA_DATA)) {
		assert(type_hash != 0);
	}
#endif

	if (kma_flags & KMA_DATA) {
		range_id  = KMEM_RANGE_ID_DATA;
		/*
		 * As an optimization in KMA_DATA to avoid fragmentation,
		 * allocate static carveouts at the end of the DATA range.
		 */
		from_right = (bool)(kma_flags & KMA_PERMANENT);
	} else if (kmem_use_sprayqtn(kma_flags, map_size, mask)) {
		range_id = KMEM_RANGE_ID_SPRAYQTN;
		from_right = (bool)(kma_flags & KMA_PERMANENT);
	} else if (type_hash) {
		range_id  = (kmem_range_id_t)(type_hash & KMEM_RANGE_MASK);
		from_right = type_hash & KMEM_DIRECTION_MASK;
	} else {
		/*
		 * Range id needs to correspond to one of the PTR ranges
		 */
		type_hash = (uint16_t) kmem_hash_backtrace(__builtin_frame_address(0));
		range_id  = kmem_adjust_range_id(type_hash);
		from_right = type_hash & KMEM_DIRECTION_MASK;
	}

	vmk_flags->vmkf_range_id = range_id;
	vmk_flags->vmkf_last_free = from_right;
}

#pragma mark allocation

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
	vm_page_t               guard_right = VM_PAGE_NULL;
	vm_page_t               wired_page_list = VM_PAGE_NULL;
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
	bool                    skip_guards;
	kmem_return_t           kmr = { };

	assert(kernel_map && map->pmap == kernel_pmap);

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#endif

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
	if ((flags & KMA_GUARD_FIRST) && !skip_guards) {
		guard_left = vm_page_grab_guard((flags & KMA_NOPAGEWAIT) == 0);
		if (__improbable(guard_left == VM_PAGE_NULL)) {
			kmr.kmr_return = KERN_RESOURCE_SHORTAGE;
			goto out_error;
		}
	}
	if ((flags & KMA_GUARD_LAST) && !skip_guards) {
		guard_right = vm_page_grab_guard((flags & KMA_NOPAGEWAIT) == 0);
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
		object = kernel_object;
		vm_object_reference(object);
	} else if (flags & KMA_COMPRESSOR) {
		object = compressor_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
		vm_object_set_size(object, map_size, size);
		/* stabilize the object to prevent shadowing */
		object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		object->true_share = TRUE;
	}

	if (flags & KMA_LAST_FREE) {
		vmk_flags.vmkf_last_free = true;
	}
	if (flags & KMA_PERMANENT) {
		vmk_flags.vmf_permanent = true;
	}
	kmem_apply_security_policy(map, flags, guard, map_size, mask, &vmk_flags,
	    false);

	kmr.kmr_return = vm_map_find_space(map, 0, map_size, mask,
	    vmk_flags, &entry);
	if (__improbable(KERN_SUCCESS != kmr.kmr_return)) {
		vm_object_deallocate(object);
		goto out_error;
	}

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
	}

	if (guard_left || guard_right || wired_page_list) {
		vm_object_offset_t offset = 0ull;

		vm_object_lock(object);
		vm_map_unlock(map);

		if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
			offset = map_addr;
		}

		if (guard_left) {
			vm_page_insert(guard_left, object, offset);
			guard_left->vmp_busy = FALSE;
			guard_left = VM_PAGE_NULL;
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
			    wired_page_list, flags, guard.kmg_tag, VM_PROT_DEFAULT);
		} else {
			vm_object_unlock(object);
		}
	} else {
		vm_map_unlock(map);
	}

	/*
	 * now that the pages are wired, we no longer have to fear coalesce
	 */
	if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
		vm_map_simplify(map, map_addr);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
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
#if KASAN_TBI
	if (flags & KMA_TAG) {
		kmr.kmr_address = kasan_tbi_tag_large_alloc(kmr.kmr_address,
		    map_size, size);
	}
#endif /* KASAN_TBI */
	return kmr;

out_error:
	if (flags & KMA_NOFAIL) {
		__kmem_failed_panic(map, size, flags, kmr.kmr_return, "alloc");
	}
	if (guard_left) {
		guard_left->vmp_snext = wired_page_list;
		wired_page_list = guard_left;
	}
	if (guard_right) {
		guard_right->vmp_snext = wired_page_list;
		wired_page_list = guard_right;
	}
	if (wired_page_list) {
		vm_page_free_list(wired_page_list, FALSE);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
	    0, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */

	return kmr;
}

kmem_return_t
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
		assert(vmk_flags.vmf_overwrite || (flags & KMS_DATA));
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

	vmk_flags.vmkf_submap = true;
	if ((flags & KMS_DATA) == 0) {
		/* FIXME: IOKit submaps get fragmented and can't be atomic */
		vmk_flags.vmkf_submap_atomic = true;
	}
	vmk_flags.vmkf_submap_adjust = true;
	if (flags & KMS_LAST_FREE) {
		vmk_flags.vmkf_last_free = true;
	}
	if (flags & KMS_PERMANENT) {
		vmk_flags.vmf_permanent = true;
	}
	if (flags & KMS_DATA) {
		vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA;
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
		return kmem_alloc(map, addrp, size, KMA_PAGEABLE | KMA_DATA, vm_tag_bt());
	}
	/* Maintain ABI compatibility: invalid sizes used to be allowed */
	return size ? KERN_NO_SPACE: KERN_INVALID_ARGUMENT;
}


#pragma mark population

static void
kernel_memory_populate_pmap_enter(
	vm_object_t             object,
	vm_address_t            addr,
	vm_object_offset_t      offset,
	vm_page_t               mem,
	vm_prot_t               prot,
	int                     pe_flags)
{
	kern_return_t   pe_result;
	int             pe_options;

	PMAP_ENTER_CHECK(kernel_pmap, mem);

	pe_options = PMAP_OPTIONS_NOWAIT;
	if (object->internal) {
		pe_options |= PMAP_OPTIONS_INTERNAL;
	}
	if (mem->vmp_reusable || object->all_reusable) {
		pe_options |= PMAP_OPTIONS_REUSABLE;
	}

	pe_result = pmap_enter_options(kernel_pmap, addr + offset,
	    VM_PAGE_GET_PHYS_PAGE(mem), prot, VM_PROT_NONE,
	    pe_flags, /* wired */ TRUE, pe_options, NULL);

	if (pe_result == KERN_RESOURCE_SHORTAGE) {
		vm_object_unlock(object);

		pe_options &= ~PMAP_OPTIONS_NOWAIT;

		pe_result = pmap_enter_options(kernel_pmap, addr + offset,
		    VM_PAGE_GET_PHYS_PAGE(mem), prot, VM_PROT_NONE,
		    pe_flags, /* wired */ TRUE, pe_options, NULL);

		vm_object_lock(object);
	}

	assert(pe_result == KERN_SUCCESS);
}

void
kernel_memory_populate_object_and_unlock(
	vm_object_t     object, /* must be locked */
	vm_address_t    addr,
	vm_offset_t     offset,
	vm_size_t       size,
	vm_page_t       page_list,
	kma_flags_t     flags,
	vm_tag_t        tag,
	vm_prot_t       prot)
{
	vm_page_t       mem;
	int             pe_flags;
	bool            gobbled_list = page_list && page_list->vmp_gobbled;

	assert3u((bool)(flags & KMA_KOBJECT), ==, object == kernel_object);
	assert3u((bool)(flags & KMA_COMPRESSOR), ==, object == compressor_object);
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
		assert(!mem->vmp_fictitious && !mem->vmp_private);

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

			vm_page_insert(mem, object, offset + pg_offset);
		} else {
			mem->vmp_q_state = VM_PAGE_IS_WIRED;
			mem->vmp_wire_count = 1;

			vm_page_insert_wired(mem, object, offset + pg_offset, tag);
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
		    mem, prot, pe_flags);

		if (flags & KMA_NOENCRYPT) {
			pmap_set_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
		}
	}

	if (page_list) {
		panic("%s: page_list too long", __func__);
	}

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
		vm_tag_update_size(tag, size);
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
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */

	kr = vm_page_alloc_list(page_count, flags, &page_list);
	if (kr == KERN_SUCCESS) {
		vm_object_lock(object);
		kernel_memory_populate_object_and_unlock(object, addr,
		    addr, size, page_list, flags, tag, VM_PROT_DEFAULT);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
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
			assert(mem->vmp_q_state == VM_PAGE_IS_WIRED);
			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));
			pages_unwired++;
		}

		mem->vmp_busy = TRUE;

		assert(mem->vmp_tabled);
		vm_page_remove(mem, TRUE);
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
		vm_tag_update_size(tag, -ptoa_64(pages_unwired));
	}
}

#pragma mark reallocation

__abortlike
static void
__kmem_realloc_invalid_object_size_panic(
	vm_map_t                map,
	vm_address_t            address,
	vm_size_t               size,
	vm_map_entry_t          entry)
{
	vm_object_t object  = VME_OBJECT(entry);
	vm_size_t   objsize = __kmem_entry_orig_size(entry);

	panic("kmem_realloc(map=%p, addr=%p, size=%zd, entry=%p): "
	    "object %p has unexpected size %ld",
	    map, (void *)address, (size_t)size, entry, object, objsize);
}

static kmem_return_t
kmem_realloc_shrink_guard(
	vm_map_t                map,
	vm_offset_t             req_oldaddr,
	vm_size_t               req_oldsize,
	vm_size_t               req_newsize,
	kmr_flags_t             flags,
	kmem_guard_t            guard,
	vm_map_entry_t          entry)
{
	vmr_flags_t             vmr_flags = VM_MAP_REMOVE_KUNWIRE;
	vm_object_t             object;
	vm_offset_t             delta = 0;
	kmem_return_t           kmr;
	bool                    was_atomic;
	vm_size_t               oldsize = round_page(req_oldsize);
	vm_size_t               newsize = round_page(req_newsize);
	vm_address_t            oldaddr = req_oldaddr;

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
#if KASAN_TBI
	if (flags & KMR_TAG) {
		oldaddr = VM_KERNEL_TBI_FILL(req_oldaddr);
	}
#endif /* KASAN_TBI */

	vm_map_lock_assert_exclusive(map);

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
	vm_map_clip_end(map, entry, entry->vme_start + newsize);
	entry->vme_atomic = was_atomic;

#if KASAN
	if (entry->vme_kernel_object && was_atomic) {
		entry->vme_object_or_delta = (-req_newsize & PAGE_MASK) + delta;
	}
#endif /* KASAN */
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		kasan_poison_range(oldaddr + newsize, oldsize - newsize,
		    ASAN_VALID);
	}
#endif
#if KASAN_TBI
	if (flags & KMR_TAG) {
		kasan_tbi_tag_large_free(req_oldaddr + newsize,
		    oldsize - newsize);
	}
#endif /* KASAN_TBI */
	(void)vm_map_remove_and_unlock(map,
	    oldaddr + newsize, oldaddr + oldsize,
	    vmr_flags, KMEM_GUARD_NONE);


	/*
	 *	Lastly, if there are guard pages, deal with them.
	 *
	 *	The kernel object just needs to depopulate,
	 *	regular objects require freeing the last page
	 *	and replacing it with a guard.
	 */
	if (flags & KMR_KOBJECT) {
		if (flags & KMR_GUARD_LAST) {
			kernel_memory_depopulate(oldaddr + newsize - PAGE_SIZE,
			    PAGE_SIZE, KMA_KOBJECT, guard.kmg_tag);
		}
	} else {
		vm_page_t guard_right = VM_PAGE_NULL;
		vm_offset_t remove_start = newsize;

		if (flags & KMR_GUARD_LAST) {
			if (!map->never_faults) {
				guard_right = vm_page_grab_guard(true);
			}
			remove_start -= PAGE_SIZE;
		}

		vm_object_lock(object);

		if (object->vo_size != oldsize) {
			__kmem_realloc_invalid_object_size_panic(map,
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
		kmr.kmr_address = kasan_tbi_tag_large_alloc(kmr.kmr_address,
		    newsize, req_newsize);
	}
#endif /* KASAN_TBI */

	return kmr;
}

kmem_return_t
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
	bool                    needs_wakeup = false;
	kmem_return_t           kmr = { };
	unsigned int            last_timestamp;
	vm_map_kernel_flags_t   vmk_flags = {
		.vmkf_last_free = (bool)(flags & KMR_LAST_FREE),
	};

	assert(KMEM_REALLOC_FLAGS_VALID(flags));
	if (!guard.kmg_atomic && (flags & (KMR_DATA | KMR_KOBJECT)) != KMR_DATA) {
		__kmem_invalid_arguments_panic("realloc", map, req_oldaddr,
		    req_oldsize, flags);
	}

	if (req_oldaddr == 0ul) {
		return kmem_alloc_guard(map, req_newsize, 0, (kma_flags_t)flags, guard);
	}

	if (req_newsize == 0ul) {
		kmem_free_guard(map, req_oldaddr, req_oldsize,
		    (kmf_flags_t)flags, guard);
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
#if KASAN_TBI
	if (flags & KMR_TAG) {
		__asan_load1(req_oldaddr);
		oldaddr = VM_KERNEL_TBI_FILL(req_oldaddr);
	}
#endif /* KASAN_TBI */

#if !KASAN
	/*
	 *	If not on a KASAN variant, just return.
	 *
	 *	Otherwise we want to validate the size
	 *	and re-tag for KASAN_TBI.
	 */
	if (oldsize == newsize) {
		kmr.kmr_address = req_oldaddr;
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
		    VM_KERN_REQUEST, DBG_FUNC_START,
		    newsize - oldsize, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
		kmr.kmr_return = vm_page_alloc_list(atop(newsize - oldsize),
		    (kma_flags_t)flags, &page_list);
		if (kmr.kmr_return == KERN_SUCCESS) {
			kmem_apply_security_policy(map, (kma_flags_t)flags, guard,
			    newsize, 0, &vmk_flags, true);
			kmr.kmr_return = vm_map_find_space(map, 0, newsize, 0,
			    vmk_flags, &newentry);
		}
		if (__improbable(kmr.kmr_return != KERN_SUCCESS)) {
			if (flags & KMR_REALLOCF) {
				kmem_free_guard(map, req_oldaddr, req_oldsize,
				    KMF_NONE, guard);
			}
			if (page_list) {
				vm_page_free_list(page_list, FALSE);
			}
#if DEBUG || DEVELOPMENT
			VM_DEBUG_CONSTANT_EVENT(vm_kern_request,
			    VM_KERN_REQUEST, DBG_FUNC_END,
			    0, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
			return kmr;
		}

		/* map is locked */
	} else {
		vm_map_lock(map);
	}


	/*
	 *	Locate the entry:
	 *	- wait for it to quiesce.
	 *	- validate its guard,
	 *	- learn its correct tag,
	 */
again:
	if (!vm_map_lookup_entry(map, oldaddr, &oldentry)) {
		__kmem_entry_not_found_panic(map, req_oldaddr);
	}
	if ((flags & KMR_KOBJECT) && oldentry->in_transition) {
		oldentry->needs_wakeup = true;
		vm_map_entry_wait(map, THREAD_UNINT);
		goto again;
	}
	kmem_entry_validate_guard(map, oldentry, oldaddr, oldsize, guard);
	if (!__kmem_entry_validate_object(oldentry, ANYF(flags))) {
		__kmem_entry_validate_object_panic(map, oldentry, ANYF(flags));
	}
	/*
	 *	TODO: We should validate for non atomic entries that the range
	 *	      we are acting on is what we expect here.
	 */
#if KASAN
	if (__kmem_entry_orig_size(oldentry) != req_oldsize) {
		__kmem_realloc_invalid_object_size_panic(map,
		    req_oldaddr, req_oldsize + delta, oldentry);
	}

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
		vm_map_unlock(map);

#if KASAN_CLASSIC
		if (flags & KMA_KASAN_GUARD) {
			kasan_alloc_large(kmr.kmr_address, req_newsize);
		}
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
		if ((flags & KMR_TAG) && (flags & KMR_FREEOLD)) {
			kmr.kmr_address = kasan_tbi_tag_large_alloc(kmr.kmr_address,
			    newsize, req_newsize);
		}
#endif /* KASAN_TBI */
		return kmr;
	}
#endif /* KASAN */

	guard.kmg_tag = VME_ALIAS(oldentry);

	if (newsize < oldsize) {
		return kmem_realloc_shrink_guard(map, req_oldaddr,
		           req_oldsize, req_newsize, flags, guard, oldentry);
	}


	/*
	 *	We are growing the entry
	 *
	 *	For regular objects we use the object `vo_size` updates
	 *	as a guarantee that no 2 kmem_realloc() can happen
	 *	concurrently (by doing it before the map is unlocked.
	 *
	 *	For the kernel object, prevent the entry from being
	 *	reallocated or changed by marking it "in_transition".
	 */

	object = VME_OBJECT(oldentry);
	vm_object_lock(object);
	vm_object_reference_locked(object);

	newaddr = newentry->vme_start;
	newoffs = oldsize;

	VME_OBJECT_SET(newentry, object, guard.kmg_atomic, guard.kmg_context);
	VME_ALIAS_SET(newentry, guard.kmg_tag);
	if (flags & KMR_KOBJECT) {
		oldentry->in_transition = true;
		VME_OFFSET_SET(newentry, newaddr);
		newentry->wired_count = 1;
		newoffs = newaddr + oldsize;
	} else {
		if (object->vo_size != oldsize) {
			__kmem_realloc_invalid_object_size_panic(map,
			    req_oldaddr, req_oldsize + delta, oldentry);
		}
		vm_object_set_size(object, newsize, req_newsize);
	}

	last_timestamp = map->timestamp;
	vm_map_unlock(map);


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
			vm_page_remove(mem, true);
			vm_page_insert_wired(mem, object, newaddr + offset,
			    guard.kmg_tag);
			mem->vmp_busy = false;

			kernel_memory_populate_pmap_enter(object, newaddr,
			    offset, mem, VM_PROT_DEFAULT, 0);
		}

		kernel_memory_populate_object_and_unlock(object,
		    newaddr + oldsize - guard_right_size,
		    newoffs - guard_right_size,
		    newsize - oldsize,
		    page_list, (kma_flags_t)flags,
		    guard.kmg_tag, VM_PROT_DEFAULT);
	} else {
		vm_page_t guard_right = VM_PAGE_NULL;
		kern_return_t kr;

		/*
		 *	Note: we are borrowing the new entry reference
		 *	on the object for the duration of this code,
		 *	which works because we keep the object locked
		 *	throughout.
		 */
		if ((flags & KMR_GUARD_LAST) && !map->never_faults) {
			guard_right = vm_page_lookup(object, oldsize - PAGE_SIZE);
			assert(guard_right->vmp_fictitious);
			guard_right->vmp_busy = true;
			vm_page_remove(guard_right, true);
		}

		for (vm_object_offset_t offset = oldsize - guard_right_size;
		    offset < newsize - guard_right_size;
		    offset += PAGE_SIZE_64) {
			vm_page_t mem = page_list;

			page_list = mem->vmp_snext;
			mem->vmp_snext = VM_PAGE_NULL;

			vm_page_insert(mem, object, offset);
			mem->vmp_busy = false;
		}

		if (guard_right) {
			vm_page_insert(guard_right, object, newsize - PAGE_SIZE);
			guard_right->vmp_busy = false;
		}

		vm_object_unlock(object);

		kr = vm_map_wire_kernel(map, newaddr, newaddr + newsize,
		    VM_PROT_DEFAULT, guard.kmg_tag, FALSE);
		assert(kr == KERN_SUCCESS);
	}

	/*
	 *	Mark the entry as idle again,
	 *	and honor KMR_FREEOLD if needed.
	 */

	vm_map_lock(map);
	if (last_timestamp + 1 != map->timestamp &&
	    !vm_map_lookup_entry(map, oldaddr, &oldentry)) {
		__kmem_entry_not_found_panic(map, req_oldaddr);
	}

	if (flags & KMR_KOBJECT) {
		assert(oldentry->in_transition);
		oldentry->in_transition = false;
		if (oldentry->needs_wakeup) {
			needs_wakeup = true;
			oldentry->needs_wakeup = false;
		}
	}

	if (flags & KMR_FREEOLD) {
		vmr_flags_t vmr_flags = VM_MAP_REMOVE_KUNWIRE;

#if KASAN_CLASSIC
		if (flags & KMR_KASAN_GUARD) {
			kasan_poison_range(oldaddr, oldsize, ASAN_VALID);
		}
#endif
#if KASAN_TBI
		if (flags & KMR_TAG) {
			kasan_tbi_tag_large_free(req_oldaddr, oldsize);
		}
#endif /* KASAN_TBI */
		if (flags & KMR_GUARD_LAST) {
			vmr_flags |= VM_MAP_REMOVE_NOKUNWIRE_LAST;
		}
		(void)vm_map_remove_and_unlock(map,
		    oldaddr, oldaddr + oldsize,
		    vmr_flags, guard);
	} else {
		vm_map_unlock(map);
	}

	if (needs_wakeup) {
		vm_map_entry_wakeup(map);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
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
#if KASAN_TBI
	if (flags & KMR_TAG) {
		kmr.kmr_address = kasan_tbi_tag_large_alloc(kmr.kmr_address,
		    newsize, req_newsize);
	}
#endif /* KASAN_TBI */

	return kmr;
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

vm_size_t
kmem_free_guard(
	vm_map_t        map,
	vm_offset_t     req_addr,
	vm_size_t       req_size,
	kmf_flags_t     flags,
	kmem_guard_t    guard)
{
	vmr_flags_t     vmr_flags = VM_MAP_REMOVE_KUNWIRE;
	vm_address_t    addr      = req_addr;
	vm_offset_t     delta     = 0;
	vm_size_t       size;
#if KASAN
	vm_map_entry_t  entry;
#endif /* KASAN */

	assert(map->pmap == kernel_pmap);

#if KASAN_CLASSIC
	if (flags & KMF_KASAN_GUARD) {
		addr  -= PAGE_SIZE;
		delta  = ptoa(2);
	}
#endif /* KASAN_CLASSIC */
#if KASAN_TBI
	if (flags & KMF_TAG) {
		__asan_load1(req_addr);
		addr = VM_KERNEL_TBI_FILL(req_addr);
	}
#endif /* KASAN_TBI */

	if (flags & KMF_GUESS_SIZE) {
		vmr_flags |= VM_MAP_REMOVE_GUESS_SIZE;
		size = PAGE_SIZE;
	} else if (req_size == 0) {
		__kmem_invalid_size_panic(map, req_size, flags);
	} else {
		size = round_page(req_size) + delta;
	}

	vm_map_lock(map);

#if KASAN
	if (!vm_map_lookup_entry(map, addr, &entry)) {
		__kmem_entry_not_found_panic(map, req_addr);
	}
	if (flags & KMF_GUESS_SIZE) {
		vmr_flags &= ~VM_MAP_REMOVE_GUESS_SIZE;
		req_size = __kmem_entry_orig_size(entry);
		size = round_page(req_size + delta);
	} else if (guard.kmg_atomic && entry->vme_kernel_object &&
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
#endif /* KASAN */
#if KASAN_CLASSIC
	if (flags & KMR_KASAN_GUARD) {
		kasan_poison_range(addr, size, ASAN_VALID);
	}
#endif
#if KASAN_TBI
	if (flags & KMF_TAG) {
		kasan_tbi_tag_large_free(req_addr, size);
	}
#endif /* KASAN_TBI */
	return vm_map_remove_and_unlock(map, addr, addr + size,
	           vmr_flags, guard).kmr_size - delta;
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

#pragma mark kmem metadata

/*
 * Guard objects for kmem pointer allocation:
 *
 * Guard objects introduce size slabs to kmem pointer allocations that are
 * allocated in chunks of n * sizeclass. When an allocation of a specific
 * sizeclass is requested a random slot from [0, n) is returned.
 * Allocations are returned from that chunk until m slots are left. The
 * remaining m slots are referred to as guard objects. They don't get
 * allocated and the chunk is now considered full. When an allocation is
 * freed to the chunk 1 slot is now available from m + 1 for the next
 * allocation of that sizeclass.
 *
 * Guard objects are intended to make exploitation of use after frees harder
 * as allocations that are freed can no longer be reliable reallocated.
 * They also make exploitation of OOBs harder as overflowing out of an
 * allocation can no longer be safe even with sufficient spraying.
 */

#define KMEM_META_PRIMARY    UINT8_MAX
#define KMEM_META_START     (UINT8_MAX - 1)
#define KMEM_META_FREE      (UINT8_MAX - 2)
#if __ARM_16K_PG__
#define KMEM_MIN_SIZE        PAGE_SIZE
#define KMEM_CHUNK_SIZE_MIN (KMEM_MIN_SIZE * 16)
#else /* __ARM_16K_PG__ */
/*
 * PAGE_SIZE isn't a compile time constant on some arm64 devices. Those
 * devices use 4k page size when their RAM is <= 1GB and 16k otherwise.
 * Therefore populate sizeclasses from 4k for those devices.
 */
#define KMEM_MIN_SIZE       (4 * 1024)
#define KMEM_CHUNK_SIZE_MIN (KMEM_MIN_SIZE * 32)
#endif /* __ARM_16K_PG__ */
#define KMEM_MAX_SIZE       (32ULL << 20)
#define KMEM_START_IDX      (kmem_log2down(KMEM_MIN_SIZE))
#define KMEM_LAST_IDX       (kmem_log2down(KMEM_MAX_SIZE))
#define KMEM_NUM_SIZECLASS  (KMEM_LAST_IDX - KMEM_START_IDX + 1)
#define KMEM_FRONTS         (KMEM_RANGE_ID_NUM_PTR * 2)
#define KMEM_NUM_GUARDS      2

struct kmem_page_meta {
	union {
		/*
		 * On primary allocated chunk with KMEM_META_PRIMARY marker
		 */
		uint32_t km_bitmap;
		/*
		 * On start and end of free chunk with KMEM_META_FREE marker
		 */
		uint32_t km_free_chunks;
	};
	/*
	 * KMEM_META_PRIMARY: Start meta of allocated chunk
	 * KMEM_META_FREE   : Start and end meta of free chunk
	 * KMEM_META_START  : Meta region start and end
	 */
	uint8_t  km_page_marker;
	uint8_t  km_sizeclass;
	union {
		/*
		 * On primary allocated chunk with KMEM_META_PRIMARY marker
		 */
		uint16_t km_chunk_len;
		/*
		 * On secondary allocated chunks
		 */
		uint16_t km_page_idx;
	};
	LIST_ENTRY(kmem_page_meta) km_link;
} kmem_page_meta_t;

typedef LIST_HEAD(kmem_list_head, kmem_page_meta) kmem_list_head_t;
struct kmem_sizeclass {
	vm_map_size_t                   ks_size;
	uint32_t                        ks_num_chunk;
	uint32_t                        ks_num_elem;
	crypto_random_ctx_t __zpercpu   ks_rng_ctx;
	kmem_list_head_t                ks_allfree_head[KMEM_FRONTS];
	kmem_list_head_t                ks_partial_head[KMEM_FRONTS];
	kmem_list_head_t                ks_full_head[KMEM_FRONTS];
};

static struct kmem_sizeclass kmem_size_array[KMEM_NUM_SIZECLASS];

/*
 * Locks to synchronize metadata population
 */
static LCK_GRP_DECLARE(kmem_locks_grp, "kmem_locks");
static LCK_MTX_DECLARE(kmem_meta_region_lck, &kmem_locks_grp);
#define kmem_meta_lock()   lck_mtx_lock(&kmem_meta_region_lck)
#define kmem_meta_unlock() lck_mtx_unlock(&kmem_meta_region_lck)

static SECURITY_READ_ONLY_LATE(struct mach_vm_range)
kmem_meta_range[KMEM_RANGE_ID_NUM_PTR + 1];
static SECURITY_READ_ONLY_LATE(struct kmem_page_meta *)
kmem_meta_base[KMEM_RANGE_ID_NUM_PTR + 1];
/*
 * Keeps track of metadata high water mark for each front
 */
static struct kmem_page_meta *kmem_meta_hwm[KMEM_FRONTS];
static SECURITY_READ_ONLY_LATE(vm_map_t)
kmem_meta_map[KMEM_RANGE_ID_NUM_PTR + 1];
static vm_map_size_t kmem_meta_size;

static uint32_t
kmem_get_front(
	kmem_range_id_t         range_id,
	bool                    from_right)
{
	assert((range_id >= KMEM_RANGE_ID_FIRST) &&
	    (range_id <= KMEM_RANGE_ID_NUM_PTR));
	return (range_id - KMEM_RANGE_ID_FIRST) * 2 + from_right;
}

static inline uint32_t
kmem_slot_idx_to_bit(
	uint32_t                slot_idx,
	uint32_t                size_idx __unused)
{
	assert(slot_idx < kmem_size_array[size_idx].ks_num_elem);
	return 1ull << slot_idx;
}

static uint32_t
kmem_get_idx_from_size(vm_map_size_t size)
{
	assert(size >= KMEM_MIN_SIZE && size <= KMEM_MAX_SIZE);
	return kmem_log2down(size - 1) - KMEM_START_IDX + 1;
}

__abortlike
static void
kmem_invalid_size_idx(uint32_t idx)
{
	panic("Invalid sizeclass idx %u", idx);
}

static vm_map_size_t
kmem_get_size_from_idx(uint32_t idx)
{
	if (__improbable(idx >= KMEM_NUM_SIZECLASS)) {
		kmem_invalid_size_idx(idx);
	}
	return 1ul << (idx + KMEM_START_IDX);
}

static inline uint16_t
kmem_get_page_idx(struct kmem_page_meta *meta)
{
	uint8_t page_marker = meta->km_page_marker;

	return (page_marker == KMEM_META_PRIMARY) ? 0 : meta->km_page_idx;
}

__abortlike
static void
kmem_invalid_chunk_len(struct kmem_page_meta *meta)
{
	panic("Reading free chunks for meta %p where marker != KMEM_META_PRIMARY",
	    meta);
}

static inline uint16_t
kmem_get_chunk_len(struct kmem_page_meta *meta)
{
	if (__improbable(meta->km_page_marker != KMEM_META_PRIMARY)) {
		kmem_invalid_chunk_len(meta);
	}

	return meta->km_chunk_len;
}

__abortlike
static void
kmem_invalid_free_chunk_len(struct kmem_page_meta *meta)
{
	panic("Reading free chunks for meta %p where marker != KMEM_META_FREE",
	    meta);
}

static inline uint32_t
kmem_get_free_chunk_len(struct kmem_page_meta *meta)
{
	if (__improbable(meta->km_page_marker != KMEM_META_FREE)) {
		kmem_invalid_free_chunk_len(meta);
	}

	return meta->km_free_chunks;
}

/*
 * Return the metadata corresponding to the specified address
 */
static struct kmem_page_meta *
kmem_addr_to_meta(
	vm_map_offset_t         addr,
	vm_map_range_id_t       range_id,
	vm_map_offset_t        *range_start,
	uint64_t               *meta_idx)
{
	struct kmem_page_meta *meta_base = kmem_meta_base[range_id];

	*range_start = kmem_ranges[range_id].min_address;
	*meta_idx = (addr - *range_start) / KMEM_CHUNK_SIZE_MIN;
	return &meta_base[*meta_idx];
}

/*
 * Return the metadata start of the chunk that the address belongs to
 */
static struct kmem_page_meta *
kmem_addr_to_meta_start(
	vm_address_t            addr,
	vm_map_range_id_t       range_id,
	vm_map_offset_t        *chunk_start)
{
	vm_map_offset_t range_start;
	uint64_t meta_idx;
	struct kmem_page_meta *meta;

	meta = kmem_addr_to_meta(addr, range_id, &range_start, &meta_idx);
	meta_idx -= kmem_get_page_idx(meta);
	meta -= kmem_get_page_idx(meta);
	assert(meta->km_page_marker == KMEM_META_PRIMARY);
	*chunk_start = range_start + (meta_idx * KMEM_CHUNK_SIZE_MIN);
	return meta;
}

__startup_func
static void
kmem_init_meta_front(
	struct kmem_page_meta  *meta,
	kmem_range_id_t         range_id,
	bool                    from_right)
{
	kernel_memory_populate(trunc_page((vm_map_offset_t) meta), PAGE_SIZE,
	    KMA_KOBJECT | KMA_ZERO | KMA_NOFAIL, VM_KERN_MEMORY_OSFMK);
	meta->km_page_marker = KMEM_META_START;
	if (!from_right) {
		meta++;
		kmem_meta_base[range_id] = meta;
	}
	kmem_meta_hwm[kmem_get_front(range_id, from_right)] = meta;
}

__startup_func
static void
kmem_metadata_init(void)
{
	for (kmem_range_id_t i = KMEM_RANGE_ID_FIRST; i <= kmem_ptr_ranges; i++) {
		vm_map_offset_t addr = kmem_meta_range[i].min_address;
		struct kmem_page_meta *meta;
		uint64_t meta_idx;

		vm_map_will_allocate_early_map(&kmem_meta_map[i]);
		kmem_meta_map[i] = kmem_suballoc(kernel_map, &addr, kmem_meta_size,
		    VM_MAP_CREATE_NEVER_FAULTS | VM_MAP_CREATE_DISABLE_HOLELIST,
		    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, KMS_PERMANENT | KMS_NOFAIL,
		    VM_KERN_MEMORY_OSFMK).kmr_submap;

		kmem_meta_range[i].min_address = addr;
		kmem_meta_range[i].max_address = addr + kmem_meta_size;

		meta = (struct kmem_page_meta *) kmem_meta_range[i].min_address;
		kmem_init_meta_front(meta, i, 0);

		meta = kmem_addr_to_meta(kmem_ranges[i].max_address, i, &addr,
		    &meta_idx);
		kmem_init_meta_front(meta, i, 1);
	}
}

__startup_func
static void
kmem_init_front_head(
	struct kmem_sizeclass  *ks,
	uint32_t                front)
{
	LIST_INIT(&ks->ks_allfree_head[front]);
	LIST_INIT(&ks->ks_partial_head[front]);
	LIST_INIT(&ks->ks_full_head[front]);
}

__startup_func
static void
kmem_sizeclass_init(void)
{
	for (uint32_t i = 0; i < KMEM_NUM_SIZECLASS; i++) {
		struct kmem_sizeclass *ks = &kmem_size_array[i];
		kmem_range_id_t range_id = KMEM_RANGE_ID_FIRST;

		ks->ks_size = kmem_get_size_from_idx(i);
		ks->ks_num_chunk = roundup(8 * ks->ks_size, KMEM_CHUNK_SIZE_MIN) /
		    KMEM_CHUNK_SIZE_MIN;
		ks->ks_num_elem = (ks->ks_num_chunk * KMEM_CHUNK_SIZE_MIN) / ks->ks_size;
		assert(ks->ks_num_elem <=
		    (sizeof(((struct kmem_page_meta *)0)->km_bitmap) * 8));
		for (; range_id <= KMEM_RANGE_ID_NUM_PTR; range_id++) {
			kmem_init_front_head(ks, kmem_get_front(range_id, 0));
			kmem_init_front_head(ks, kmem_get_front(range_id, 1));
		}
	}
}

/*
 * This is done during EARLY_BOOT as it needs the corecrypto module to be
 * set up.
 */
__startup_func
static void
kmem_crypto_init(void)
{
	vm_size_t ctx_size = crypto_random_kmem_ctx_size();

	for (uint32_t i = 0; i < KMEM_NUM_SIZECLASS; i++) {
		struct kmem_sizeclass *ks = &kmem_size_array[i];

		ks->ks_rng_ctx = zalloc_percpu_permanent(ctx_size, ZALIGN_PTR);
		zpercpu_foreach(ctx, ks->ks_rng_ctx) {
			crypto_random_kmem_init(ctx);
		}
	}
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, kmem_crypto_init);

__abortlike
static void
kmem_validate_slot_panic(
	vm_map_offset_t         addr,
	struct kmem_page_meta  *meta,
	uint32_t                slot_idx,
	uint32_t                size_idx)
{
	if (meta->km_page_marker != KMEM_META_PRIMARY) {
		panic("Metadata (%p) for addr (%p) not primary", meta, (void *)addr);
	}
	if (meta->km_sizeclass != size_idx) {
		panic("Metadata's (%p) sizeclass (%u != %u) changed during deletion",
		    meta, meta->km_sizeclass, size_idx);
	}
	panic("Double free detected: Slot (%u) in meta (%p) for addr %p marked free",
	    slot_idx, meta, (void *)addr);
}

__abortlike
static void
kmem_invalid_slot_for_addr(
	mach_vm_range_t         slot,
	vm_map_offset_t         start,
	vm_map_offset_t         end)
{
	panic("Invalid kmem ptr slot [%p:%p] for allocation [%p:%p]",
	    (void *)slot->min_address, (void *)slot->max_address,
	    (void *)start, (void *)end);
}

void
kmem_validate_slot(
	vm_map_offset_t         addr,
	struct kmem_page_meta  *meta,
	uint32_t                size_idx,
	uint32_t                slot_idx)
{
	if ((meta->km_page_marker != KMEM_META_PRIMARY) ||
	    (meta->km_sizeclass != size_idx) ||
	    ((meta->km_bitmap & kmem_slot_idx_to_bit(slot_idx, size_idx)) != 0)) {
		kmem_validate_slot_panic(addr, meta, size_idx, slot_idx);
	}
}

static void
kmem_validate_slot_initial(
	mach_vm_range_t         slot,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	struct kmem_page_meta  *meta,
	uint32_t                size_idx,
	uint32_t                slot_idx)
{
	if ((slot->min_address == 0) || (slot->max_address == 0) ||
	    (start < slot->min_address) || (start >= slot->max_address) ||
	    (end > slot->max_address)) {
		kmem_invalid_slot_for_addr(slot, start, end);
	}

	kmem_validate_slot(start, meta, size_idx, slot_idx);
}

uint32_t
kmem_addr_get_slot_idx(
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_map_range_id_t       range_id,
	struct kmem_page_meta **meta,
	uint32_t               *size_idx,
	mach_vm_range_t         slot)
{
	vm_map_offset_t chunk_start;
	vm_map_size_t slot_size;
	uint32_t slot_idx;

	*meta = kmem_addr_to_meta_start(start, range_id, &chunk_start);
	*size_idx = (*meta)->km_sizeclass;
	slot_size = kmem_get_size_from_idx(*size_idx);
	slot_idx = (start - chunk_start) / slot_size;
	slot->min_address = chunk_start + slot_idx * slot_size;
	slot->max_address = slot->min_address + slot_size;

	kmem_validate_slot_initial(slot, start, end, *meta, *size_idx, slot_idx);

	return slot_idx;
}

static bool
kmem_populate_needed(vm_offset_t from, vm_offset_t to)
{
#if KASAN
#pragma unused(from, to)
	return true;
#else
	vm_offset_t page_addr = trunc_page(from);

	for (; page_addr < to; page_addr += PAGE_SIZE) {
		/*
		 * This can race with another thread doing a populate on the same metadata
		 * page, where we see an updated pmap but unmapped KASan shadow, causing a
		 * fault in the shadow when we first access the metadata page. Avoid this
		 * by always synchronizing on the kmem_meta_lock with KASan.
		 */
		if (!pmap_find_phys(kernel_pmap, page_addr)) {
			return true;
		}
	}

	return false;
#endif /* !KASAN */
}

static void
kmem_populate_meta_locked(vm_offset_t from, vm_offset_t to)
{
	vm_offset_t page_addr = trunc_page(from);

	vm_map_unlock(kernel_map);

	for (; page_addr < to; page_addr += PAGE_SIZE) {
		for (;;) {
			kern_return_t ret = KERN_SUCCESS;

			/*
			 * All updates to kmem metadata are done under the kmem_meta_lock
			 */
			kmem_meta_lock();
			if (0 == pmap_find_phys(kernel_pmap, page_addr)) {
				ret = kernel_memory_populate(page_addr,
				    PAGE_SIZE, KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_ZERO,
				    VM_KERN_MEMORY_OSFMK);
			}
			kmem_meta_unlock();

			if (ret == KERN_SUCCESS) {
				break;
			}

			/*
			 * We can't pass KMA_NOPAGEWAIT under a global lock as it leads
			 * to bad system deadlocks, so if the allocation failed,
			 * we need to do the VM_PAGE_WAIT() outside of the lock.
			 */
			VM_PAGE_WAIT();
		}
	}

	vm_map_lock(kernel_map);
}

__abortlike
static void
kmem_invalid_meta_panic(
	struct kmem_page_meta  *meta,
	uint32_t                slot_idx,
	struct kmem_sizeclass   sizeclass)
{
	uint32_t size_idx = kmem_get_idx_from_size(sizeclass.ks_size);

	if (slot_idx >= sizeclass.ks_num_elem) {
		panic("Invalid slot idx %u [0:%u] for meta %p", slot_idx,
		    sizeclass.ks_num_elem, meta);
	}
	if (meta->km_sizeclass != size_idx) {
		panic("Invalid size_idx (%u != %u) in meta %p", size_idx,
		    meta->km_sizeclass, meta);
	}
	panic("page_marker %u not primary in meta %p", meta->km_page_marker, meta);
}

__abortlike
static void
kmem_slot_has_entry_panic(
	vm_map_entry_t          entry,
	vm_map_offset_t         addr)
{
	panic("Entry (%p) already exists for addr (%p) being returned",
	    entry, (void *)addr);
}

__abortlike
static void
kmem_slot_not_found(
	struct kmem_page_meta  *meta,
	uint32_t                slot_idx)
{
	panic("%uth free slot not found for meta %p bitmap %u", slot_idx, meta,
	    meta->km_bitmap);
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

static uint32_t
kmem_get_nth_free_slot(
	struct kmem_page_meta  *meta,
	uint32_t                n,
	uint32_t                bitmap)
{
	uint32_t zeros_seen = 0, ones_seen = 0;

	while (bitmap) {
		uint32_t count = __builtin_ctz(bitmap);

		zeros_seen += count;
		bitmap >>= count;
		if (__probable(~bitmap)) {
			count = __builtin_ctz(~bitmap);
		} else {
			count = 32;
		}
		if (count + ones_seen > n) {
			return zeros_seen + n;
		}
		ones_seen += count;
		bitmap >>= count;
	}

	kmem_slot_not_found(meta, n);
}


static uint32_t
kmem_get_next_slot(
	struct kmem_page_meta  *meta,
	struct kmem_sizeclass   sizeclass,
	uint32_t                bitmap)
{
	uint32_t num_slots = __builtin_popcount(bitmap);
	uint64_t slot_idx = 0;

	assert(num_slots > 0);
	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		/*
		 * Use early random prior to early boot as the ks_rng_ctx requires
		 * the corecrypto module to be setup before it is initialized and
		 * used.
		 *
		 * num_slots can't be 0 as we take this path when we have more than
		 * one slot left.
		 */
		slot_idx = kmem_get_random16((uint16_t)num_slots - 1);
	} else {
		crypto_random_uniform(zpercpu_get(sizeclass.ks_rng_ctx), num_slots,
		    &slot_idx);
	}

	return kmem_get_nth_free_slot(meta, slot_idx, bitmap);
}

/*
 * Returns an unallocated slot from the given metadata
 */
static vm_map_offset_t
kmem_get_addr_from_meta(
	struct kmem_page_meta  *meta,
	vm_map_range_id_t       range_id,
	struct kmem_sizeclass   sizeclass,
	vm_map_entry_t         *entry)
{
	vm_map_offset_t addr;
	vm_map_size_t size = sizeclass.ks_size;
	uint32_t size_idx = kmem_get_idx_from_size(size);
	uint64_t meta_idx = meta - kmem_meta_base[range_id];
	mach_vm_offset_t range_start = kmem_ranges[range_id].min_address;
	uint32_t slot_bit;
	uint32_t slot_idx = kmem_get_next_slot(meta, sizeclass, meta->km_bitmap);

	if ((slot_idx >= sizeclass.ks_num_elem) ||
	    (meta->km_sizeclass != size_idx) ||
	    (meta->km_page_marker != KMEM_META_PRIMARY)) {
		kmem_invalid_meta_panic(meta, slot_idx, sizeclass);
	}

	slot_bit = kmem_slot_idx_to_bit(slot_idx, size_idx);
	meta->km_bitmap &= ~slot_bit;

	addr = range_start + (meta_idx * KMEM_CHUNK_SIZE_MIN) + (slot_idx * size);
	assert(kmem_range_contains_fully(range_id, addr, size));
	if (vm_map_lookup_entry(kernel_map, addr, entry)) {
		kmem_slot_has_entry_panic(*entry, addr);
	}
	if ((*entry != vm_map_to_entry(kernel_map)) &&
	    ((*entry)->vme_next != vm_map_to_entry(kernel_map)) &&
	    ((*entry)->vme_next->vme_start < (addr + size))) {
		kmem_slot_has_entry_panic(*entry, addr);
	}
	return addr;
}

__abortlike
static void
kmem_range_out_of_va(
	kmem_range_id_t         range_id,
	uint32_t                num_chunks)
{
	panic("No more VA to allocate %u chunks in range %u", num_chunks, range_id);
}

static void
kmem_init_allocated_chunk(
	struct kmem_page_meta  *meta,
	struct kmem_sizeclass   sizeclass,
	uint32_t                size_idx)
{
	uint32_t meta_num = sizeclass.ks_num_chunk;
	uint32_t num_elem = sizeclass.ks_num_elem;

	meta->km_bitmap = (1ull << num_elem) - 1;
	meta->km_chunk_len = (uint16_t)meta_num;
	assert(LIST_NEXT(meta, km_link) == NULL);
	assert(meta->km_link.le_prev == NULL);
	meta->km_sizeclass = (uint8_t)size_idx;
	meta->km_page_marker = KMEM_META_PRIMARY;
	meta++;
	for (uint32_t i = 1; i < meta_num; i++) {
		meta->km_page_idx = (uint16_t)i;
		meta->km_sizeclass = (uint8_t)size_idx;
		meta->km_page_marker = 0;
		meta->km_bitmap = 0;
		meta++;
	}
}

static uint32_t
kmem_get_additional_meta(
	struct kmem_page_meta  *meta,
	uint32_t                meta_req,
	bool                    from_right,
	struct kmem_page_meta **adj_free_meta)
{
	struct kmem_page_meta *meta_prev = from_right ? meta : (meta - 1);

	if (meta_prev->km_page_marker == KMEM_META_FREE) {
		uint32_t chunk_len = kmem_get_free_chunk_len(meta_prev);

		*adj_free_meta = from_right ? meta_prev : (meta_prev - chunk_len + 1);
		meta_req -= chunk_len;
	} else {
		*adj_free_meta = NULL;
	}

	return meta_req;
}


static struct kmem_page_meta *
kmem_get_new_chunk(
	vm_map_range_id_t       range_id,
	bool                    from_right,
	uint32_t                size_idx)
{
	struct kmem_sizeclass sizeclass = kmem_size_array[size_idx];
	struct kmem_page_meta *start, *end, *meta_update;
	struct kmem_page_meta *adj_free_meta = NULL;
	uint32_t meta_req = sizeclass.ks_num_chunk;

	for (;;) {
		struct kmem_page_meta *metaf = kmem_meta_hwm[kmem_get_front(range_id, 0)];
		struct kmem_page_meta *metab = kmem_meta_hwm[kmem_get_front(range_id, 1)];
		struct kmem_page_meta *meta;
		vm_offset_t start_addr, end_addr;
		uint32_t meta_num;

		meta = from_right ? metab : metaf;
		meta_num = kmem_get_additional_meta(meta, meta_req, from_right,
		    &adj_free_meta);

		if (metaf + meta_num >= metab) {
			kmem_range_out_of_va(range_id, meta_num);
		}

		start = from_right ? (metab - meta_num) : metaf;
		end = from_right ? metab : (metaf + meta_num);

		start_addr = (vm_offset_t)start;
		end_addr   = (vm_offset_t)end;

		/*
		 * If the new high watermark stays on the same page,
		 * no need to populate and drop the lock.
		 */
		if (!page_aligned(from_right ? end_addr : start_addr) &&
		    trunc_page(start_addr) == trunc_page(end_addr - 1)) {
			break;
		}
		if (!kmem_populate_needed(start_addr, end_addr)) {
			break;
		}

		kmem_populate_meta_locked(start_addr, end_addr);

		/*
		 * Since we dropped the lock, reassess conditions still hold:
		 * - the HWM we are changing must not have moved
		 * - the other HWM must not intersect with ours
		 * - in case of coalescing, the adjacent free meta must still
		 *   be free and of the same size.
		 *
		 * If we failed to grow, reevaluate whether freelists have
		 * entries now by returning NULL.
		 */
		metaf = kmem_meta_hwm[kmem_get_front(range_id, 0)];
		metab = kmem_meta_hwm[kmem_get_front(range_id, 1)];
		if (meta != (from_right ? metab : metaf)) {
			return NULL;
		}
		if (metaf + meta_num >= metab) {
			kmem_range_out_of_va(range_id, meta_num);
		}
		if (adj_free_meta) {
			if (adj_free_meta->km_page_marker != KMEM_META_FREE ||
			    kmem_get_free_chunk_len(adj_free_meta) !=
			    meta_req - meta_num) {
				return NULL;
			}
		}

		break;
	}

	/*
	 * If there is an adjacent free chunk remove it from free list
	 */
	if (adj_free_meta) {
		LIST_REMOVE(adj_free_meta, km_link);
		LIST_NEXT(adj_free_meta, km_link) = NULL;
		adj_free_meta->km_link.le_prev = NULL;
	}

	/*
	 * Update hwm
	 */
	meta_update = from_right ? start : end;
	kmem_meta_hwm[kmem_get_front(range_id, from_right)] = meta_update;

	/*
	 * Initialize metadata
	 */
	start = from_right ? start : (end - meta_req);
	kmem_init_allocated_chunk(start, sizeclass, size_idx);

	return start;
}

static void
kmem_requeue_meta(
	struct kmem_page_meta  *meta,
	struct kmem_list_head  *head)
{
	LIST_REMOVE(meta, km_link);
	LIST_INSERT_HEAD(head, meta, km_link);
}

/*
 * Return corresponding sizeclass to stash free chunks in
 */
__abortlike
static void
kmem_invalid_chunk_num(uint32_t chunks)
{
	panic("Invalid number of chunks %u\n", chunks);
}

static uint32_t
kmem_get_size_idx_for_chunks(uint32_t chunks)
{
	for (uint32_t i = KMEM_NUM_SIZECLASS - 1; i > 0; i--) {
		if (chunks >= kmem_size_array[i].ks_num_chunk) {
			return i;
		}
	}
	kmem_invalid_chunk_num(chunks);
}

static void
kmem_clear_meta_range(struct kmem_page_meta *meta, uint32_t count)
{
	bzero(meta, count * sizeof(struct kmem_page_meta));
}

static void
kmem_check_meta_range_is_clear(struct kmem_page_meta *meta, uint32_t count)
{
#if MACH_ASSERT
	size_t size = count * sizeof(struct kmem_page_meta);

	assert(memcmp_zero_ptr_aligned(meta, size) == 0);
#else
#pragma unused(meta, count)
#endif
}

/*!
 * @function kmem_init_free_chunk()
 *
 * @discussion
 * This function prepares a range of chunks to be put on a free list.
 * The first and last metadata might be dirty, but the "inner" ones
 * must be zero filled by the caller prior to calling this function.
 */
static void
kmem_init_free_chunk(
	struct kmem_page_meta  *meta,
	uint32_t                num_chunks,
	uint32_t                front)
{
	struct kmem_sizeclass *sizeclass;
	uint32_t size_idx = kmem_get_size_idx_for_chunks(num_chunks);

	if (num_chunks > 2) {
		kmem_check_meta_range_is_clear(meta + 1, num_chunks - 2);
	}

	meta[0] = (struct kmem_page_meta){
		.km_free_chunks = num_chunks,
		.km_page_marker = KMEM_META_FREE,
		.km_sizeclass   = (uint8_t)size_idx,
	};
	if (num_chunks > 1) {
		meta[num_chunks - 1] = (struct kmem_page_meta){
			.km_free_chunks = num_chunks,
			.km_page_marker = KMEM_META_FREE,
			.km_sizeclass   = (uint8_t)size_idx,
		};
	}

	sizeclass = &kmem_size_array[size_idx];
	LIST_INSERT_HEAD(&sizeclass->ks_allfree_head[front], meta, km_link);
}

static struct kmem_page_meta *
kmem_get_free_chunk_from_list(
	struct kmem_sizeclass  *org_sizeclass,
	uint32_t                size_idx,
	uint32_t                front)
{
	struct kmem_sizeclass *sizeclass;
	uint32_t num_chunks = org_sizeclass->ks_num_chunk;
	struct kmem_page_meta *meta;
	uint32_t idx = size_idx;

	while (idx < KMEM_NUM_SIZECLASS) {
		sizeclass = &kmem_size_array[idx];
		meta = LIST_FIRST(&sizeclass->ks_allfree_head[front]);
		if (meta) {
			break;
		}
		idx++;
	}

	/*
	 * Trim if larger in size
	 */
	if (meta) {
		uint32_t num_chunks_free = kmem_get_free_chunk_len(meta);

		assert(meta->km_page_marker == KMEM_META_FREE);
		LIST_REMOVE(meta, km_link);
		LIST_NEXT(meta, km_link) = NULL;
		meta->km_link.le_prev = NULL;
		if (num_chunks_free > num_chunks) {
			num_chunks_free -= num_chunks;
			kmem_init_free_chunk(meta + num_chunks, num_chunks_free, front);
		}

		kmem_init_allocated_chunk(meta, *org_sizeclass, size_idx);
	}

	return meta;
}

kern_return_t
kmem_locate_space(
	vm_map_size_t           size,
	vm_map_range_id_t       range_id,
	bool                    from_right,
	vm_map_offset_t        *start_inout,
	vm_map_entry_t         *entry_out)
{
	vm_map_entry_t entry;
	uint32_t size_idx = kmem_get_idx_from_size(size);
	uint32_t front = kmem_get_front(range_id, from_right);
	struct kmem_sizeclass *sizeclass = &kmem_size_array[size_idx];
	struct kmem_page_meta *meta;

	assert(size <= sizeclass->ks_size);
again:
	if ((meta = LIST_FIRST(&sizeclass->ks_partial_head[front])) != NULL) {
		*start_inout = kmem_get_addr_from_meta(meta, range_id, *sizeclass, &entry);
		/*
		 * Requeue to full if necessary
		 */
		assert(meta->km_page_marker == KMEM_META_PRIMARY);
		if (__builtin_popcount(meta->km_bitmap) == KMEM_NUM_GUARDS) {
			kmem_requeue_meta(meta, &sizeclass->ks_full_head[front]);
		}
	} else if ((meta = kmem_get_free_chunk_from_list(sizeclass, size_idx,
	    front)) != NULL) {
		*start_inout = kmem_get_addr_from_meta(meta, range_id, *sizeclass, &entry);
		/*
		 * Queue to partial
		 */
		assert(meta->km_page_marker == KMEM_META_PRIMARY);
		assert(__builtin_popcount(meta->km_bitmap) > KMEM_NUM_GUARDS);
		LIST_INSERT_HEAD(&sizeclass->ks_partial_head[front], meta, km_link);
	} else {
		meta = kmem_get_new_chunk(range_id, from_right, size_idx);
		if (meta == NULL) {
			goto again;
		}
		*start_inout = kmem_get_addr_from_meta(meta, range_id, *sizeclass, &entry);
		assert(meta->km_page_marker == KMEM_META_PRIMARY);
		LIST_INSERT_HEAD(&sizeclass->ks_partial_head[front], meta, km_link);
	}

	if (entry_out) {
		*entry_out = entry;
	}

	return KERN_SUCCESS;
}

/*
 * Determine whether the given metadata was allocated from the right
 */
static bool
kmem_meta_is_from_right(
	kmem_range_id_t         range_id,
	struct kmem_page_meta  *meta)
{
	struct kmem_page_meta *metaf = kmem_meta_hwm[kmem_get_front(range_id, 0)];
#if DEBUG || DEVELOPMENT
	struct kmem_page_meta *metab = kmem_meta_hwm[kmem_get_front(range_id, 1)];
#endif
	struct kmem_page_meta *meta_base = kmem_meta_base[range_id];
	struct kmem_page_meta *meta_end;

	meta_end = (struct kmem_page_meta *)kmem_meta_range[range_id].max_address;

	if ((meta >= meta_base) && (meta < metaf)) {
		return false;
	}

	assert(meta >= metab && meta < meta_end);
	return true;
}

static void
kmem_free_chunk(
	kmem_range_id_t         range_id,
	struct kmem_page_meta  *meta,
	bool                    from_right)
{
	struct kmem_page_meta *meta_coalesce = meta - 1;
	struct kmem_page_meta *meta_start = meta;
	uint32_t num_chunks = kmem_get_chunk_len(meta);
	uint32_t add_chunks;
	struct kmem_page_meta *meta_end = meta + num_chunks;
	struct kmem_page_meta *meta_hwm_l, *meta_hwm_r;
	uint32_t front = kmem_get_front(range_id, from_right);

	meta_hwm_l = kmem_meta_hwm[kmem_get_front(range_id, 0)];
	meta_hwm_r = kmem_meta_hwm[kmem_get_front(range_id, 1)];

	LIST_REMOVE(meta, km_link);
	kmem_clear_meta_range(meta, num_chunks);

	/*
	 * Coalesce left
	 */
	if (((from_right && (meta_coalesce >= meta_hwm_r)) || !from_right) &&
	    (meta_coalesce->km_page_marker == KMEM_META_FREE)) {
		meta_start = meta_coalesce - kmem_get_free_chunk_len(meta_coalesce) + 1;
		add_chunks = kmem_get_free_chunk_len(meta_start);
		num_chunks += add_chunks;
		LIST_REMOVE(meta_start, km_link);
		kmem_clear_meta_range(meta_start + add_chunks - 1, 1);
	}

	/*
	 * Coalesce right
	 */
	if (((!from_right && (meta_end < meta_hwm_l)) || from_right) &&
	    (meta_end->km_page_marker == KMEM_META_FREE)) {
		add_chunks = kmem_get_free_chunk_len(meta_end);
		LIST_REMOVE(meta_end, km_link);
		kmem_clear_meta_range(meta_end, 1);
		meta_end = meta_end + add_chunks;
		num_chunks += add_chunks;
	}

	kmem_init_free_chunk(meta_start, num_chunks, front);
}

static void
kmem_free_slot(
	kmem_range_id_t         range_id,
	mach_vm_range_t         slot)
{
	struct kmem_page_meta *meta;
	vm_map_offset_t chunk_start;
	uint32_t size_idx, chunk_elem, slot_idx, num_elem;
	struct kmem_sizeclass *sizeclass;
	vm_map_size_t slot_size;

	meta = kmem_addr_to_meta_start(slot->min_address, range_id, &chunk_start);
	size_idx = meta->km_sizeclass;
	slot_size = kmem_get_size_from_idx(size_idx);
	slot_idx = (slot->min_address - chunk_start) / slot_size;
	assert((meta->km_bitmap & kmem_slot_idx_to_bit(slot_idx, size_idx)) == 0);
	meta->km_bitmap |= kmem_slot_idx_to_bit(slot_idx, size_idx);

	sizeclass = &kmem_size_array[size_idx];
	chunk_elem = sizeclass->ks_num_elem;
	num_elem = __builtin_popcount(meta->km_bitmap);

	if (num_elem == chunk_elem) {
		/*
		 * If entire chunk empty add to emtpy list
		 */
		bool from_right = kmem_meta_is_from_right(range_id, meta);

		kmem_free_chunk(range_id, meta, from_right);
	} else if (num_elem == KMEM_NUM_GUARDS + 1) {
		/*
		 * If we freed to full chunk move it to partial
		 */
		uint32_t front = kmem_get_front(range_id,
		    kmem_meta_is_from_right(range_id, meta));

		kmem_requeue_meta(meta, &sizeclass->ks_partial_head[front]);
	}
}

void
kmem_free_space(
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_map_range_id_t       range_id,
	mach_vm_range_t         slot)
{
	bool entry_present = false;
	vm_map_entry_t prev_entry;
	vm_map_entry_t next_entry;

	if ((slot->min_address == start) && (slot->max_address == end)) {
		/*
		 * Entire slot is being freed at once
		 */
		return kmem_free_slot(range_id, slot);
	}

	entry_present = vm_map_lookup_entry(kernel_map, start, &prev_entry);
	assert(!entry_present);
	next_entry = prev_entry->vme_next;

	if (((prev_entry == vm_map_to_entry(kernel_map) ||
	    prev_entry->vme_end <= slot->min_address)) &&
	    (next_entry == vm_map_to_entry(kernel_map) ||
	    (next_entry->vme_start >= slot->max_address))) {
		/*
		 * Free entire slot
		 */
		kmem_free_slot(range_id, slot);
	}
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

	if (available_mem_log < VM_USER_WIREABLE_MIN_CONFIG) {
		available_mem_log = 0;
	} else {
		available_mem_log -= VM_USER_WIREABLE_MIN_CONFIG;
	}
	if (available_mem_log >= wire_limit_percents_length) {
		available_mem_log = wire_limit_percents_length - 1;
	}
	max_wire_percent = wire_limit_percents[available_mem_log];

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
__startup_data
uint32_t kmem_claim_count = 0;

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

static vm_offset_t
kmem_fuzz_start(void)
{
	vm_offset_t kmapoff_kaddr = 0;
	uint32_t kmapoff_pgcnt = (early_random() & 0x1ff) + 1; /* 9 bits */
	vm_map_size_t kmapoff_size = ptoa(kmapoff_pgcnt);

	kmem_alloc(kernel_map, &kmapoff_kaddr, kmapoff_size,
	    KMA_NOFAIL | KMA_KOBJECT | KMA_PERMANENT | KMA_VAONLY,
	    VM_KERN_MEMORY_OSFMK);
	return kmapoff_kaddr + kmapoff_size;
}

/*
 * Generate a randomly shuffled array of indices from 0 to count - 1
 */
__startup_func
void
kmem_shuffle(
	uint16_t       *shuffle_buf,
	uint16_t        count)
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
		range->min_address += sp.kc_size;
		range->max_address += sp.kc_size;
		kmem_claims[j + 1] = spj;
	}

	sp.kc_flags = KC_NO_MOVE;
	kmem_claims[random] = sp;
}

__startup_func
static vm_map_size_t
kmem_add_ptr_claims(void)
{
	uint64_t kmem_meta_num, kmem_ptr_chunks;
	vm_map_size_t org_ptr_range_size = ptr_range_size;

	ptr_range_size -= PAGE_SIZE;
	ptr_range_size *= KMEM_CHUNK_SIZE_MIN;
	ptr_range_size /= (KMEM_CHUNK_SIZE_MIN + sizeof(struct kmem_page_meta));

	kmem_ptr_chunks = ptr_range_size / KMEM_CHUNK_SIZE_MIN;
	ptr_range_size = kmem_ptr_chunks * KMEM_CHUNK_SIZE_MIN;

	kmem_meta_num = kmem_ptr_chunks + 2;
	kmem_meta_size = round_page(kmem_meta_num * sizeof(struct kmem_page_meta));

	assert(kmem_meta_size + ptr_range_size <= org_ptr_range_size);
	/*
	 * Add claims for kmem's ranges
	 */
	for (uint32_t i = 0; i < kmem_ptr_ranges; i++) {
		struct kmem_range_startup_spec kmem_spec = {
			.kc_name = "kmem_ptr_range",
			.kc_range = &kmem_ranges[KMEM_RANGE_ID_PTR_0 + i],
			.kc_size = ptr_range_size,
			.kc_flags = KC_NO_ENTRY,
		};
		kmem_claims[kmem_claim_count++] = kmem_spec;

		struct kmem_range_startup_spec kmem_meta_spec = {
			.kc_name = "kmem_ptr_range_meta",
			.kc_range = &kmem_meta_range[KMEM_RANGE_ID_PTR_0 + i],
			.kc_size = kmem_meta_size,
			.kc_flags = KC_NONE,
		};
		kmem_claims[kmem_claim_count++] = kmem_meta_spec;
	}
	return (org_ptr_range_size - ptr_range_size - kmem_meta_size) *
	       kmem_ptr_ranges;
}

__startup_func
static void
kmem_add_extra_claims(void)
{
	vm_map_size_t largest_free_size = 0, total_claims = 0;

	vm_map_sizes(kernel_map, NULL, NULL, &largest_free_size);
	largest_free_size = trunc_page(largest_free_size);

	/*
	 * kasan and configs w/o *TRR need to have just one ptr range due to
	 * resource constraints.
	 */
#if !ZSECURITY_CONFIG(KERNEL_PTR_SPLIT)
	kmem_ptr_ranges = 1;
#endif
	/*
	 * Determine size of data and pointer kmem_ranges
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		total_claims += kmem_claims[i].kc_size;
	}
	assert((total_claims & PAGE_MASK) == 0);
	largest_free_size -= total_claims;

	/*
	 * Use half the total available VA for all pointer allocations (this
	 * includes the kmem_sprayqtn range). Given that we have 4 total
	 * ranges divide the available VA by 8.
	 */
	ptr_range_size = largest_free_size / ((kmem_ptr_ranges + 1) * 2);
	sprayqtn_range_size = ptr_range_size;

	if (sprayqtn_range_size > (sane_size / 2)) {
		sprayqtn_range_size = sane_size / 2;
	}

	ptr_range_size = round_page(ptr_range_size);
	sprayqtn_range_size = round_page(sprayqtn_range_size);


	data_range_size = largest_free_size
	    - (ptr_range_size * kmem_ptr_ranges)
	    - sprayqtn_range_size;

	/*
	 * Add claims for kmem's ranges
	 */
	data_range_size += kmem_add_ptr_claims();
	assert(data_range_size + sprayqtn_range_size +
	    ((ptr_range_size + kmem_meta_size) * kmem_ptr_ranges) <=
	    largest_free_size);

	struct kmem_range_startup_spec kmem_spec_sprayqtn = {
		.kc_name = "kmem_sprayqtn_range",
		.kc_range = &kmem_ranges[KMEM_RANGE_ID_SPRAYQTN],
		.kc_size = sprayqtn_range_size,
		.kc_flags = KC_NO_ENTRY,
	};
	kmem_claims[kmem_claim_count++] = kmem_spec_sprayqtn;

	struct kmem_range_startup_spec kmem_spec_data = {
		.kc_name = "kmem_data_range",
		.kc_range = &kmem_ranges[KMEM_RANGE_ID_DATA],
		.kc_size = data_range_size,
		.kc_flags = KC_NO_ENTRY,
	};
	kmem_claims[kmem_claim_count++] = kmem_spec_data;
}

__startup_func
static void
kmem_scramble_ranges(void)
{
	vm_map_offset_t start = 0;

	/*
	 * Initiatize KMEM_RANGE_ID_NONE range to use the entire map so that
	 * the vm can find the requested ranges.
	 */
	kmem_ranges[KMEM_RANGE_ID_NONE].min_address = MAX(kernel_map->min_offset,
	    VM_MAP_PAGE_SIZE(kernel_map));
	kmem_ranges[KMEM_RANGE_ID_NONE].max_address = kernel_map->max_offset;

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
	start = kmem_fuzz_start();

	/*
	 * Add claims for ptr and data kmem_ranges
	 */
	kmem_add_extra_claims();

	/*
	 * Shuffle registered claims
	 */
	assert(kmem_claim_count < UINT16_MAX);
	kmem_shuffle_claims();

	/*
	 * Apply restrictions and determine range for each claim
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		vm_map_offset_t end = 0;
		struct kmem_range_startup_spec sp = kmem_claims[i];
		struct mach_vm_range *sp_range = sp.kc_range;
		if (vm_map_locate_space(kernel_map, sp.kc_size, 0,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(), &start, NULL) != KERN_SUCCESS) {
			panic("kmem_range_init: vm_map_locate_space failing for claim %s",
			    sp.kc_name);
		}

		end = start + sp.kc_size;
		/*
		 * Re-adjust ranges if restriction not met
		 */
		if (sp_range->min_address && start > sp_range->min_address) {
			kmem_readjust_ranges(i);
		} else {
			sp_range->min_address = start;
			sp_range->max_address = end;
		}
		start = end;
	}

	/*
	 * We have settled on the ranges, now create temporary entries for the
	 * claims
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp = kmem_claims[i];
		vm_map_entry_t entry = NULL;
		if (sp.kc_flags & KC_NO_ENTRY) {
			continue;
		}
		if (vm_map_find_space(kernel_map, sp.kc_range->min_address, sp.kc_size, 0,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(), &entry) != KERN_SUCCESS) {
			panic("kmem_range_init: vm_map_find_space failing for claim %s",
			    sp.kc_name);
		}
		vm_object_reference(kernel_object);
		VME_OBJECT_SET(entry, kernel_object, false, 0);
		VME_OFFSET_SET(entry, entry->vme_start);
		vm_map_unlock(kernel_map);
	}
	/*
	 * Now that we are done assigning all the ranges, reset
	 * kmem_ranges[KMEM_RANGE_ID_NONE]
	 */
	kmem_ranges[KMEM_RANGE_ID_NONE] = (struct mach_vm_range) {};

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
}

__startup_func
static void
kmem_range_init(void)
{
	vm_size_t range_adjustment;

	kmem_scramble_ranges();

	range_adjustment = sprayqtn_range_size >> 3;
	kmem_large_ranges[KMEM_RANGE_ID_SPRAYQTN].min_address =
	    kmem_ranges[KMEM_RANGE_ID_SPRAYQTN].min_address + range_adjustment;
	kmem_large_ranges[KMEM_RANGE_ID_SPRAYQTN].max_address =
	    kmem_ranges[KMEM_RANGE_ID_SPRAYQTN].max_address;

	range_adjustment = data_range_size >> 3;
	kmem_large_ranges[KMEM_RANGE_ID_DATA].min_address =
	    kmem_ranges[KMEM_RANGE_ID_DATA].min_address + range_adjustment;
	kmem_large_ranges[KMEM_RANGE_ID_DATA].max_address =
	    kmem_ranges[KMEM_RANGE_ID_DATA].max_address;

	pmap_init();
	kmem_metadata_init();
	kmem_sizeclass_init();

#if DEBUG || DEVELOPMENT
	for (kmem_range_id_t i = 1; i < KMEM_RANGE_COUNT; i++) {
		vm_size_t range_size = mach_vm_range_size(&kmem_large_ranges[i]);
		printf("kmem_large_ranges[%d]    : %p - %p (%u%c)\n", i,
		    (void *)kmem_large_ranges[i].min_address,
		    (void *)kmem_large_ranges[i].max_address,
		    mach_vm_size_pretty(range_size),
		    mach_vm_size_unit(range_size));
	}
#endif
}
STARTUP(KMEM, STARTUP_RANK_THIRD, kmem_range_init);

#if DEBUG || DEVELOPMENT
__startup_func
static void
kmem_log_init(void)
{
	/*
	 * Log can only be created after the the kmem subsystem is initialized as
	 * btlog creation uses kmem
	 */
	kmem_outlier_log = btlog_create(BTLOG_LOG, KMEM_OUTLIER_LOG_SIZE, 0);
}
STARTUP(ZALLOC, STARTUP_RANK_FIRST, kmem_log_init);

kmem_gobj_stats
kmem_get_gobj_stats(void)
{
	kmem_gobj_stats stats = {};

	vm_map_lock(kernel_map);
	for (uint32_t i = 0; i < kmem_ptr_ranges; i++) {
		kmem_range_id_t range_id = KMEM_RANGE_ID_FIRST + i;
		struct mach_vm_range range = kmem_ranges[range_id];
		struct kmem_page_meta *meta = kmem_meta_hwm[kmem_get_front(range_id, 0)];
		struct kmem_page_meta *meta_end;
		uint64_t meta_idx = meta - kmem_meta_base[range_id];
		vm_map_size_t used = 0, va = 0, meta_sz = 0, pte_sz = 0;
		vm_map_offset_t addr;
		vm_map_entry_t entry;

		/*
		 * Left front
		 */
		va = (meta_idx * KMEM_CHUNK_SIZE_MIN);
		meta_sz = round_page(meta_idx * sizeof(struct kmem_page_meta));

		/*
		 * Right front
		 */
		meta = kmem_meta_hwm[kmem_get_front(range_id, 1)];
		meta_end = kmem_addr_to_meta(range.max_address, range_id, &addr,
		    &meta_idx);
		meta_idx = meta_end - meta;
		meta_sz += round_page(meta_idx * sizeof(struct kmem_page_meta));
		va += (meta_idx * KMEM_CHUNK_SIZE_MIN);

		/*
		 * Compute VA allocated in entire range
		 */
		if (vm_map_lookup_entry(kernel_map, range.min_address, &entry) == false) {
			entry = entry->vme_next;
		}
		while (entry != vm_map_to_entry(kernel_map) &&
		    entry->vme_start < range.max_address) {
			used += (entry->vme_end - entry->vme_start);
			entry = entry->vme_next;
		}

		pte_sz = round_page(atop(va - used) * 8);

		stats.total_used += used;
		stats.total_va += va;
		stats.pte_sz += pte_sz;
		stats.meta_sz += meta_sz;
	}
	vm_map_unlock(kernel_map);

	return stats;
}

#endif /* DEBUG || DEVELOPMENT */

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
	kernel_map = vm_map_create_options(pmap_kernel(),
	    VM_MIN_KERNEL_AND_KEXT_ADDRESS,
	    VM_MAX_KERNEL_ADDRESS,
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
			    VM_MAP_KERNEL_FLAGS_FIXED_PERMANENT(.vmkf_no_pmap_check = true),
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
		    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_no_pmap_check = true),
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
 *	Routine:	copyinmap
 *	Purpose:
 *		Like copyin, except that fromaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
kern_return_t
copyinmap(
	vm_map_t                map,
	vm_map_offset_t         fromaddr,
	void                    *todata,
	vm_size_t               length)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(todata, CAST_DOWN(void *, fromaddr), length);
	} else if (current_map() == map) {
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	copyoutmap
 *	Purpose:
 *		Like copyout, except that toaddr is an address
 *		in the specified VM map.
 */
kern_return_t
copyoutmap(
	vm_map_t                map,
	void                    *fromdata,
	vm_map_address_t        toaddr,
	vm_size_t               length)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t        oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(CAST_DOWN(void *, toaddr), fromdata, length);
	} else if (current_map() == map) {
		if (copyout(fromdata, toaddr, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout(fromdata, toaddr, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	copyoutmap_atomic{32, 64}
 *	Purpose:
 *		Like copyoutmap, except that the operation is atomic.
 *      Takes in value rather than *fromdata pointer.
 */
kern_return_t
copyoutmap_atomic32(
	vm_map_t                map,
	uint32_t                value,
	vm_map_address_t        toaddr)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t        oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct toaddr */
		*(uint32_t *)toaddr = value;
	} else if (current_map() == map) {
		if (copyout_atomic32(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout_atomic32(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
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
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t        oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct toaddr */
		*(uint64_t *)toaddr = value;
	} else if (current_map() == map) {
		if (copyout_atomic64(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout_atomic64(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
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

/*
 *	vm_kernel_addrperm_external:
 *	vm_kernel_unslide_or_perm_external:
 *
 *	Use these macros when exposing an address to userspace that could come from
 *	either kernel text/data *or* the heap.
 */
void
vm_kernel_addrperm_external(
	vm_offset_t addr,
	vm_offset_t *perm_addr)
{
	if (VM_KERNEL_IS_SLID(addr)) {
		*perm_addr = VM_KERNEL_UNSLIDE(addr);
	} else if (VM_KERNEL_ADDRESS(addr)) {
		*perm_addr = addr + vm_kernel_addrperm_ext;
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
#if DEBUG || DEVELOPMENT
#include <sys/errno.h>

static void
kmem_test_for_entry(
	vm_map_t                map,
	vm_offset_t             addr,
	void                  (^block)(vm_map_entry_t))
{
	vm_map_entry_t entry;

	vm_map_lock(map);
	block(vm_map_lookup_entry(map, addr, &entry) ? entry : NULL);
	vm_map_unlock(map);
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

__attribute__((noinline))
static void
kmem_alloc_basic_test(vm_map_t map)
{
	kmem_guard_t guard = {
		.kmg_tag = VM_KERN_MEMORY_DIAG,
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

	kmem_test_for_entry(map, addr, ^(vm_map_entry_t e){
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

	kmem_free(map, addr, ptoa(10));
	kmem_test_assert_map(map, 0, 0);
}

__attribute__((noinline))
static void
kmem_realloc_basic_test(vm_map_t map, kmr_flags_t kind)
{
	kmem_guard_t guard = {
		.kmg_atomic  = !(kind & KMR_DATA),
		.kmg_tag     = VM_KERN_MEMORY_DIAG,
		.kmg_context = 0xefface,
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
	bool GL = (kind & KMR_GUARD_LAST);

	/*
	 *	Initial N page allocation
	 */
	addr = kmem_alloc_guard(map, ptoa(N), 0,
	    (kind & (KMA_KOBJECT | KMA_GUARD_LAST)) | KMA_ZERO,
	    guard).kmr_address;
	assert3u(addr, !=, 0);
	kmem_test_assert_map(map, N, 1);
	for (int pg = 0; pg < N - GL; pg++) {
		poke(addr, pg, 42 + pg);
	}
	for (int pg = N - GL; pg < N; pg++) {
		assert_faults(addr, pg);
	}


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
	for (int pg = 0; pg < N - GL; pg++) {
		assert3u(peek(newaddr, pg), ==, 42 + pg);
	}
	if ((kind & KMR_FREEOLD) == 0) {
		for (int pg = 0; pg < N - GL; pg++) {
			assert3u(peek(addr, pg), ==, 42 + pg);
		}
		/* check for tru-share */
		poke(addr + 16, 0, 1234);
		assert3u(peek(newaddr + 16, 0), ==, 1234);
		kmem_free_guard(map, addr, ptoa(N), KMF_NONE, guard);
		kmem_test_assert_map(map, N + 3, 1);
	}
	if (addr != newaddr) {
		for (int pg = 0; pg < N - GL; pg++) {
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

	for (int pg = 0; pg < N - 2 - GL; pg++) {
		assert3u(peek(addr, pg), ==, 42 + pg);
	}
	for (int pg = N - 2 - GL; pg < N + 3; pg++) {
		assert_faults(addr, pg);
	}

	kmem_free_guard(map, addr, ptoa(N - 2), KMF_NONE, guard);
	kmem_test_assert_map(map, 0, 0);
}

static int
kmem_basic_test(__unused int64_t in, int64_t *out)
{
	mach_vm_offset_t addr;
	vm_map_t map;

	printf("%s: test running\n", __func__);

	map = kmem_suballoc(kernel_map, &addr, 64U << 20,
	        VM_MAP_CREATE_DEFAULT, VM_FLAGS_ANYWHERE,
	        KMS_NOFAIL | KMS_DATA, VM_KERN_MEMORY_DIAG).kmr_submap;

	printf("%s: kmem_alloc ...\n", __func__);
	kmem_alloc_basic_test(map);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_KOBJECT | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_KOBJECT | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_NONE) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_NONE);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_KOBJECT | KMR_FREEOLD | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_FREEOLD | KMR_GUARD_LAST) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_FREEOLD | KMR_GUARD_LAST);
	printf("%s:     PASS\n", __func__);

	/* using KMR_DATA signals to test the non atomic realloc path */
	printf("%s: kmem_realloc (KMR_DATA | KMR_FREEOLD) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_DATA | KMR_FREEOLD);
	printf("%s:     PASS\n", __func__);

	printf("%s: kmem_realloc (KMR_DATA) ...\n", __func__);
	kmem_realloc_basic_test(map, KMR_DATA);
	printf("%s:     PASS\n", __func__);

	kmem_free_guard(kernel_map, addr, 64U << 20, KMF_NONE, KMEM_GUARD_SUBMAP);
	vm_map_deallocate(map);

	printf("%s: test passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kmem_basic, kmem_basic_test);

static void
kmem_test_get_size_idx_for_chunks(uint32_t chunks)
{
	uint32_t idx = kmem_get_size_idx_for_chunks(chunks);

	assert(chunks >= kmem_size_array[idx].ks_num_chunk);
}

__attribute__((noinline))
static void
kmem_test_get_size_idx_for_all_chunks()
{
	for (uint32_t i = 0; i < KMEM_NUM_SIZECLASS; i++) {
		uint32_t chunks = kmem_size_array[i].ks_num_chunk;

		if (chunks != 1) {
			kmem_test_get_size_idx_for_chunks(chunks - 1);
		}
		kmem_test_get_size_idx_for_chunks(chunks);
		kmem_test_get_size_idx_for_chunks(chunks + 1);
	}
}

static int
kmem_guard_obj_test(__unused int64_t in, int64_t *out)
{
	printf("%s: test running\n", __func__);

	printf("%s: kmem_get_size_idx_for_chunks\n", __func__);
	kmem_test_get_size_idx_for_all_chunks();
	printf("%s:     PASS\n", __func__);

	printf("%s: test passed\n", __func__);
	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(kmem_guard_obj, kmem_guard_obj_test);
#endif /* DEBUG || DEVELOPMENT */
