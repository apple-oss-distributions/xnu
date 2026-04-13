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

#define VM_MAP_LOCK_PRIVATE 1
#include <vm/vm_map_lock_internal.h>
#include <kern/block_hint.h>
#include <kern/sched_prim.h>
#include <kern/lock_group.h>
#include <kern/mach_param.h>
#include <sys/errno.h>
#include <sys/code_signing.h>
#include <os/atomic_private.h>
#include <vm/vm_protos_internal.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_kern_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_stackshot_utils_xnu.h>

uint64_t vm_map_lookup_and_lock_object_copy_slowly_count = 0;
uint64_t vm_map_lookup_and_lock_object_copy_slowly_size = 0;
uint64_t vm_map_lookup_and_lock_object_copy_slowly_max = 0;
uint64_t vm_map_lookup_and_lock_object_copy_slowly_restart = 0;
uint64_t vm_map_lookup_and_lock_object_copy_slowly_error = 0;
uint64_t vm_map_lookup_and_lock_object_copy_strategically_count = 0;
uint64_t vm_map_lookup_and_lock_object_copy_strategically_size = 0;
uint64_t vm_map_lookup_and_lock_object_copy_strategically_max = 0;
uint64_t vm_map_lookup_and_lock_object_copy_strategically_restart = 0;
uint64_t vm_map_lookup_and_lock_object_copy_strategically_error = 0;
uint64_t vm_map_lookup_and_lock_object_copy_shadow_count = 0;
uint64_t vm_map_lookup_and_lock_object_copy_shadow_size = 0;
uint64_t vm_map_lookup_and_lock_object_copy_shadow_max = 0;

extern int   proc_selfpid(void);
extern char *proc_name_address(void *p);

/*
 * This is used a sentinel value such that any accesses to this map should crash.
 * It is set by the range lock on the passed in map, as clients should use
 * vm_map_lock_ctx_get_map() instead.
 */
#define BAD_MAP_VALUE ((vm_map_t) 0xbad)

#pragma mark enums

__options_closed_decl(vmrl_clip_reason_t, uint8_t, {
	VMRL_CLIP_EXTERNAL = 1,
	VMRL_CLIP_COW_SETUP,
	VMRL_CLIP_PREPARE_FOR_SHARE,
	VMRL_CLIP_TO_RANGE,
	VMRL_CLIP_RESOLVE_SUBMAP_COW,
	VMRL_CLIP_PMAP_UNNEST,
});

__options_decl(vmrl_clip_flags_t, uint32_t, {
	VMRL_CLIP_NONE          = 0x0000,
	VMRL_CLIP_UNLOCK_SPLITS = 0x0001,
	VMRL_CLIP_UNNESTING     = 0x0002
});


#pragma mark panics

__abortlike
static void
__vm_map_gap_panic(vm_map_lock_ctx_t vml_ctx, vm_map_offset_t where)
{
	panic("vm_map_range_lock(%p,0x%llx,0x%llx): "
	    "no map entry at 0x%llx", vml_ctx->vmlc_map,
	    vml_ctx->vmlc_req_start, vml_ctx->vmlc_req_end, where);
}

__abortlike
static void
__vm_map_atomic_panic(vm_map_lock_ctx_t vml_ctx, vm_map_entry_t entry)
{
	panic("vm_map_range_lock(%p,0x%llx,0x%llx): "
	    "operation not contained within atomic entry %p spanning [%llx, %llx)",
	    vml_ctx->vmlc_map, vml_ctx->vmlc_req_start, vml_ctx->vmlc_req_end,
	    entry, entry->vme_start, entry->vme_end);
}

__abortlike
static void
__vm_map_transparent_submap_panic(vm_map_lock_ctx_t vml_ctx, vm_map_entry_t vme)
{
	panic("vm_map_range_lock(%p,%llx,%llx): "
	    "operation not contained within submap %p spanning [%llx, %llx)",
	    vml_ctx->vmlc_map, vml_ctx->vmlc_req_start, vml_ctx->vmlc_req_end,
	    VME_SUBMAP(vme), vme->vme_start, vme->vme_end);
}

__abortlike
static void
__vm_map_clip_atomic_entry_panic(
	vm_map_t        map,
	vm_map_entry_t  entry,
	vm_map_offset_t where)
{
	panic("vm_map_clip(%p): Attempting to clip an atomic VM map entry "
	    "%p [0x%llx:0x%llx] at 0x%llx", map, entry,
	    (uint64_t)entry->vme_start,
	    (uint64_t)entry->vme_end,
	    (uint64_t)where);
}

__abortlike
static void
__vm_map_range_stream_panic(vm_map_lock_ctx_t vml_ctx, kern_return_t kr)
{
	panic("streaming of context %p hit an unexpected error %d", vml_ctx, kr);
}


#pragma mark utilities

/*!
 * @brief
 * Whether we should clip the entry based on the provided range.
 * Locking for a single entry at a fixed address sets context bounds that
 * should generally not be used for clipping, though some code paths do
 * need to clip even in those cases.
 */
#define vmrl_should_clip_to_range(x) \
	((__vmrl_flags(x) & _VMRL_SINGLE_ENTRY) == 0)

/*
 * Flags funcs
 */
inline void
vm_map_entry_lock_allocate_object(vm_map_entry_t entry, vm_map_serial_t provenance)
{
	RANGE_LOCK_ASSERT(VME_OBJECT(entry) == VM_OBJECT_NULL && entry->use_pmap);
	VME_OBJECT_SET(entry,
	    vm_object_allocate(
		    (vm_map_size_t)(entry->vme_end -
		    entry->vme_start), provenance), false, 0);
	VME_OFFSET_SET(entry, 0);
}

/*
 * Resolve SYMMETRIC CoW on an entry.
 * needs_copy should be set on the entry.
 *
 * The entry should be exclusively locked.
 */
inline void
vm_map_entry_lock_resolve_symmetric_cow(vm_map_t map, vm_map_entry_t entry)
{
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map) && entry->needs_copy);

	if (VME_OBJECT(entry)->shadowed == FALSE) {
		vm_object_lock(VME_OBJECT(entry));
		VM_OBJECT_SET_SHADOWED(VME_OBJECT(entry), TRUE);
		vm_object_unlock(VME_OBJECT(entry));
	}
	VME_OBJECT_SHADOW(entry,
	    (vm_map_size_t) (entry->vme_end -
	    entry->vme_start),
	    vm_map_always_shadow(map));
	entry->needs_copy = FALSE;
}


static inline vm_map_address_t
vm_map_parent_address_to_submap_address(vm_map_address_t parent_address, vm_map_entry_t parent_entry)
{
	return parent_address - parent_entry->vme_start + VME_OFFSET(parent_entry);
}

__attribute__((always_inline))
static bool
vm_map_entry_is_transparent_submap(vm_map_entry_t entry)
{
	if (entry->is_sub_map && entry->vme_atomic) {
		/*
		 * transparent submaps do not require any address transformation,
		 * so the offset is always that of the entry's start
		 */
		RANGE_LOCK_ASSERT(VME_SUBMAP(entry)->vmmap_sealed == VM_MAP_NOT_SEALED &&
		    VME_OFFSET(entry) == entry->vme_start &&
		    entry->vme_permanent);
		return true;
	}

	return false;
}

__attribute__((always_inline))
static bool
vm_map_entry_is_constant_submap(vm_map_entry_t entry)
{
	if (entry->is_sub_map && !entry->vme_atomic) {
		RANGE_LOCK_ASSERT(VME_SUBMAP(entry)->vmmap_sealed != VM_MAP_NOT_SEALED);
		return true;
	}

	return false;
}

__attribute__((always_inline))
static inline lck_rw_type_t
__vmrl_ilk_atomic_mode(vmrl_flags_t flags)
{
	if (__improbable(vmrl_mode(flags) == VMRL_ATOMIC_ALLOW_HOLES)) {
		return LCK_RW_TYPE_EXCLUSIVE;
	} else {
		return LCK_RW_TYPE_SHARED;
	}
}

/*!
 * @abstract
 * Chose the right mode for the map interlock depending on the lock flags.
 *
 * @discussion
 * When the map is streaming, because the interlock is only held by the range
 * lock itself, and that we typically do not block under these holds, we chose
 * shared-spin in order to reduce effects of priority inversions due to stale
 * readers.
 */
__attribute__((always_inline))
static inline lck_rw_type_t
__vmrl_ilk_mode(vmrl_flags_t flags)
{
	if (vmrl_is_streaming(flags)) {
		return LCK_RW_TYPE_SHARED_SPIN;
	}
	return __vmrl_ilk_atomic_mode(flags);
}

__attribute__((always_inline))
static void
__vmrl_ilk_lock_exclusive(vm_map_t map)
{
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));
	lck_rw_lock_exclusive(&map->ilock);
	vm_map_debug_after_lock_fast(map);
}

__attribute__((always_inline))
static void
__vmrl_ilk_unlock_exclusive(vm_map_t map)
{
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));
	vm_map_debug_before_unlock_fast(map);
	lck_rw_unlock_exclusive(&map->ilock);
}

__attribute__((always_inline))
static void
__vmrl_ilk_lock_shared(vm_map_t map)
{
	lck_rw_lock_shared(&map->ilock);
}
__attribute__((always_inline))
static void
__vmrl_ilk_unlock_shared(vm_map_t map)
{
	lck_rw_unlock_shared(&map->ilock);
}

__attribute__((always_inline))
static void
__vmrl_ilk_lock_shared_spin(vm_map_t map)
{
	lck_rw_lock_shared_spin(&map->ilock);
}
__attribute__((always_inline))
static void
__vmrl_ilk_unlock_shared_spin(vm_map_t map)
{
	lck_rw_unlock_shared_spin(&map->ilock);
}

__attribute__((always_inline))
static void
__vmrl_ilk_lock(vm_map_t map, lck_rw_type_t mode)
{
	if (mode == LCK_RW_TYPE_EXCLUSIVE) {
		__vmrl_ilk_lock_exclusive(map);
		vm_map_debug_after_lock_fast(map);
	} else if (mode == LCK_RW_TYPE_SHARED) {
		__vmrl_ilk_lock_shared(map);
	} else {
		RANGE_LOCK_ASSERT(mode == LCK_RW_TYPE_SHARED_SPIN);
		__vmrl_ilk_lock_shared_spin(map);
	}
}
__attribute__((always_inline))
static void
__vmrl_ilk_unlock(vm_map_t map, lck_rw_type_t mode)
{
	if (mode == LCK_RW_TYPE_EXCLUSIVE) {
		vm_map_debug_before_unlock_fast(map);
		__vmrl_ilk_unlock_exclusive(map);
	} else if (mode == LCK_RW_TYPE_SHARED) {
		__vmrl_ilk_unlock_shared(map);
	} else {
		RANGE_LOCK_ASSERT(mode == LCK_RW_TYPE_SHARED_SPIN);
		__vmrl_ilk_unlock_shared_spin(map);
	}
}

__attribute__((always_inline))
static lck_rw_type_t
__vmrl_ilk_convert_nospin(vm_map_t map, lck_rw_type_t mode)
{
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));

	if (mode == LCK_RW_TYPE_SHARED_SPIN) {
		lck_rw_convert_nospin(&map->ilock);
		mode = LCK_RW_TYPE_SHARED;
	}
	return mode;
}

static lck_rw_type_t
__vmrl_ilk_downgrade(vm_map_t map, lck_rw_type_t to_mode)
{
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));

	if (to_mode != LCK_RW_TYPE_EXCLUSIVE) {
		if (to_mode == LCK_RW_TYPE_SHARED_SPIN) {
			lck_rw_convert_spin(&map->ilock);
		}
		vm_map_debug_before_unlock_fast(map);
		lck_rw_lock_exclusive_to_shared(&map->ilock);
	}
	return to_mode;
}
static lck_rw_type_t
__vmrl_ilk_upgrade(vm_map_t map, lck_rw_type_t from_mode)
{
	/*
	 * This is an optimization to upgrade in place: for all callers,
	 * the invariants are about entries that are exlusively locked,
	 * so there is nothing to reevaluate.
	 */

	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));

	if (from_mode != LCK_RW_TYPE_EXCLUSIVE) {
		if (from_mode == LCK_RW_TYPE_SHARED_SPIN) {
			lck_rw_convert_nospin(&map->ilock);
		}
		if (!lck_rw_lock_shared_to_exclusive(&map->ilock)) {
			lck_rw_lock_exclusive(&map->ilock);
		}
		vm_map_debug_after_lock_fast(map);
	}
	return LCK_RW_TYPE_EXCLUSIVE;
}


#pragma mark vm map entry modifications

/**
 * @abstract
 * Helper function for figuring out whether a clip is both allowed and required.
 *
 * @param entry         the entry that would be clipped (locked)
 * @param start         the start address for clipping
 * @param end           the end address for clipping
 * @param flags         the locking context flags.
 * @param reason        the clipping reason
 */
static bool
__vmrl_clip_needed(
	vm_map_entry_t          entry,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmrl_flags_t            flags,
	vmrl_clip_reason_t      reason)
{
	VM_ENTRY_ASSERT_OWNER(entry);

	switch (reason) {
	case VMRL_CLIP_TO_RANGE:
	case VMRL_CLIP_COW_SETUP:
	case VMRL_CLIP_PREPARE_FOR_SHARE:
		/*
		 * The above cases are trying to make the entry match the request,
		 * they're only relevant to locking a range.
		 */
		if (!vmrl_should_clip_to_range(flags)) {
			return false;
		}
		break;
	/* Lock clients may request clips on single entries. */
	case VMRL_CLIP_EXTERNAL:
	/* Submap unnesting clips for performance, which we want. */
	case VMRL_CLIP_RESOLVE_SUBMAP_COW:
	case VMRL_CLIP_PMAP_UNNEST:
		break;
	}

	return entry->vme_start < start || end < entry->vme_end;
}

/*
 * Returns the new entry which was added before the given entry and starts at a lesser address
 * The given entry's start is moved to the given start offset which needs to be inside it.
 */
static vm_map_entry_t
__vmrl_clip_start_ilocked(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_offset_t         start,
	vmrl_clip_flags_t       flags)
{
	vm_map_entry_t   new_entry;

	if (entry->vme_atomic) {
		__vm_map_clip_atomic_entry_panic(map, entry, start);
	}

	if ((flags & VMRL_CLIP_UNNESTING) == 0) {
		DTRACE_VM5(vm_map_range_lock_clip_start,
		    vm_map_t, map,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    vm_map_offset_t, start,
		    int, VME_ALIAS(entry));
	}

	new_entry = vm_map_store_clip_start(map, entry, start);

	if (flags & VMRL_CLIP_UNLOCK_SPLITS) {
		vm_entry_unlock_exclusive(map, new_entry);
		vm_entry_invalidate_waiters(map, entry);
	}

	return new_entry;
}

/*
 * Returns the new entry which was added after the given entry and starts at a greater address
 * The given entry's end is moved to the given end offset which needs to be inside it.
 */
static vm_map_entry_t
__vmrl_clip_end_ilocked(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_offset_t         end,
	vmrl_clip_flags_t       flags)
{
	vm_map_entry_t new_entry;

	if (entry->vme_atomic) {
		__vm_map_clip_atomic_entry_panic(map, entry, end);
	}

	if ((flags & VMRL_CLIP_UNNESTING) == 0) {
		DTRACE_VM5(vm_map_range_lock_clip_end,
		    vm_map_t, map,
		    vm_map_offset_t, entry->vme_start,
		    vm_map_offset_t, entry->vme_end,
		    vm_map_offset_t, end,
		    int, VME_ALIAS(entry));
	}

	new_entry = vm_map_store_clip_end(map, entry, end);

	if (flags & VMRL_CLIP_UNLOCK_SPLITS) {
		vm_entry_unlock_exclusive(map, new_entry);
		vm_entry_invalidate_waiters(map, entry);
	}

	return new_entry;
}

/*
 * Clips an entry to the specified bounds.
 *
 * The entry passed in will be set to start at the given start address,
 * and end at the given end address, and clipped entries will be inserted
 * before and after it.
 *
 * pmap unnesting must have happened prior.
 *
 * callers should check for clipping being needed prior to this call
 * using __vmrl_clip_needed() (there is no correctness problem in not doing so,
 * only performance costs).
 */
__attribute__((noinline))
static void
__vmrl_clip_ilocked(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_offset_t         startaddr,
	vm_map_offset_t         endaddr,
	vmrl_clip_flags_t       flags)
{
	/* Double check unnest has already happened */
	if (entry->is_sub_map) {
		assert((flags & VMRL_CLIP_UNNESTING) || !entry->use_pmap);
	}
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));
	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (!entry->is_sub_map &&
	    VME_OBJECT(entry) &&
	    VME_OBJECT(entry)->phys_contiguous) {
		pmap_remove(map->pmap, entry->vme_start, entry->vme_end);
	}

	if (entry->vme_start < startaddr) {
		__vmrl_clip_start_ilocked(map, entry, startaddr, flags);
	}

	if (endaddr < entry->vme_end) {
		__vmrl_clip_end_ilocked(map, entry, endaddr, flags);
	}
}

void
vm_map_range_lock_clip_start(
	vm_map_lock_ctx_t       ctx,
	vm_map_entry_t          entry,
	vm_map_offset_t         startaddr)
{
	vmrl_clip_flags_t flags = VMRL_CLIP_NONE;
	vm_map_t          map   = ctx->vmlc_map;

	if (vmrl_is_streaming(ctx)) {
		flags |= VMRL_CLIP_UNLOCK_SPLITS;
	}

	if (__vmrl_clip_needed(entry, startaddr, ~0ull, __vmrl_flags(ctx),
	    VMRL_CLIP_EXTERNAL)) {
		__vmrl_ilk_lock_exclusive(map);
		__vmrl_clip_ilocked(map, entry, startaddr, ~0ull, flags);
		__vmrl_ilk_unlock_exclusive(map);

		if (vmrl_is_atomic(ctx) &&
		    entry == ctx->__vmlc_atomic.first_entry) {
			/*
			 * We were the first entry, but now,
			 * the newly created one is
			 */
			ctx->__vmlc_atomic.first_entry = VME_PREV(entry);
		}
	}
}

void
vm_map_range_lock_clip_end(
	vm_map_lock_ctx_t       ctx,
	vm_map_entry_t          entry,
	vm_map_offset_t         endaddr)
{
	vmrl_clip_flags_t flags = VMRL_CLIP_NONE;
	vm_map_t          map   = ctx->vmlc_map;

	if (vmrl_is_streaming(ctx)) {
		flags |= VMRL_CLIP_UNLOCK_SPLITS;
	}

	if (__vmrl_clip_needed(entry, 0, endaddr, __vmrl_flags(ctx),
	    VMRL_CLIP_EXTERNAL)) {
		__vmrl_ilk_lock_exclusive(map);
		__vmrl_clip_ilocked(map, entry, 0, endaddr, flags);
		__vmrl_ilk_unlock_exclusive(map);

		if (vmrl_is_streaming(ctx)) {
			ctx->__vmlc_streaming.last_processed_addr = entry->vme_end;
		}
	}
}

static bool
vm_map_entry_needs_submap_cow_resolved(vmrl_flags_t flags, vm_map_entry_t entry)
{
	VM_ENTRY_ASSERT_OWNER(entry);

	if (flags & VMRL_RESOLVE_COW_AND_OBJ) {
		return entry->needs_copy && entry->is_sub_map;
	}
	return false;
}

vm_map_entry_t
vm_map_found_entry_clip_end_ilocked(
	vm_map_find_lock_ctx_t  ctx,
	vm_map_offset_t         endaddr)
{
	vm_map_entry_t entry = ctx->vmlc_vme;

	RANGE_LOCK_ASSERT(entry);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);
	RANGE_LOCK_ASSERT(endaddr < entry->vme_end);

	__vmrl_clip_ilocked(ctx->vmlc_map, entry, 0, endaddr, VMRL_CLIP_NONE);
	ctx->vmlc_req_end = endaddr;

	return entry->vme_next;
}

/*
 * This function does entry level unnesting of a submap's entries
 * into a parent map.
 *
 * An example of when this is needed is if a process tried to write to the
 * shared region. The process would need a new vm_object_t associated with its
 * entry that is private to that process. To do that, this entry level unnesting
 * creates a copy object of the submap's object and associates it with the top
 * level entry
 *
 * The entry passed in must be exclusively locked
 * It must be called without the ilock, as it does copy_strategically, which
 * can fall through to copy_slowly.
 */
__attribute__((noinline))
static kern_return_t
vm_map_entry_resolve_submap_cow(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t                old_map,
	vm_map_entry_t          top_entry,
	vm_map_address_t        top_addr)
{
	LCK_RW_ASSERT(&old_map->ilock, LCK_RW_ASSERT_NOT_OWNED);
	RANGE_LOCK_ASSERT(!entry_is_map_end(old_map, top_entry));
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(old_map));
	RANGE_LOCK_ASSERT(top_entry->is_sub_map && top_entry->needs_copy);
	VM_ENTRY_ASSERT_EXCL_OWNER(top_entry);

	vm_map_size_t fault_page_mask;
	kern_return_t kr;
	vm_map_address_t top_entry_start, top_entry_end, submap_addr, top_entry_offset,
	    start_delta, end_delta, local_start, local_end, submap_entry_offset, submap_entry_size, copy_offset;
	vm_map_entry_t submap_entry;
	vm_object_t sub_object, copy_object;
	vm_map_t submap;
	vm_object_offset_t object_copied_offset = 0;
	boolean_t object_copied_needs_copy = false;

	fault_page_mask = MIN(VM_MAP_PAGE_MASK(old_map), PAGE_MASK);
	top_addr = VM_MAP_TRUNC_PAGE(top_addr, fault_page_mask);

	top_entry_offset = VME_OFFSET(top_entry);
	top_entry_start = top_entry->vme_start;
	top_entry_end = top_entry->vme_end;

	submap = VME_SUBMAP(top_entry);
	submap_addr = vm_map_parent_address_to_submap_address(top_addr, top_entry);
	submap_entry = vm_map_lookup(submap, submap_addr);

	RANGE_LOCK_ASSERT(vm_map_is_sealed(submap));

	if (submap_entry == VM_MAP_ENTRY_NULL) {
		return KERN_INVALID_ADDRESS;
	}

	sub_object = VME_OBJECT(submap_entry);

	if (sub_object == VM_OBJECT_NULL) {
		/* we hit what would have been a hole in a sealed submap */
		return KERN_INVALID_ADDRESS;
	}
	assert(!submap_entry->is_sub_map);

	/* If the submap entry starts later than the offset asks, adjust with the difference. */
	start_delta = submap_entry->vme_start > top_entry_offset ?
	    submap_entry->vme_start - top_entry_offset : 0;

	/* If the submap entry ends sooner than the top entry would view, adjust by that difference */
	if (top_entry_offset + start_delta + (top_entry_end - top_entry_start) <= submap_entry->vme_end) {
		end_delta = 0;
	} else {
		end_delta = top_entry_offset + (top_entry_end - top_entry_start) - submap_entry->vme_end;
	}

	top_entry_start += start_delta;
	top_entry_end -= end_delta;

	local_start =  submap_addr - (top_addr - top_entry_start);
	local_end = submap_addr + (top_entry_end - top_addr);

	submap_entry_offset = VME_OFFSET(submap_entry);
	submap_entry_size = submap_entry->vme_end - submap_entry->vme_start;


	/* This is the COW case, lets connect */
	/* an entry in our space to the underlying */
	/* object in the submap, bypassing the  */
	/* submap. */

	/* adjust to our local range */
	if (submap_entry->vme_start < local_start) {
		vm_map_offset_t clip_start;
		clip_start = local_start - submap_entry->vme_start;
		submap_entry_offset += clip_start;
		submap_entry_size -= clip_start;
	}
	if (local_end < submap_entry->vme_end) {
		vm_map_offset_t clip_end;
		clip_end = submap_entry->vme_end - local_end;
		submap_entry_size -= clip_end;
	}
	assert(!submap_entry->wired_count);
	assert(sub_object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC);

	copy_object = VM_OBJECT_NULL;
	object_copied_offset = submap_entry_offset;
	object_copied_needs_copy = false;
	DTRACE_VM6(submap_copy_strategically,
	    vm_map_t, old_map,
	    vm_map_offset_t, submap_addr,
	    vm_map_t, submap,
	    vm_object_size_t, submap_entry_size,
	    int, submap_entry->wired_count,
	    int, sub_object->copy_strategy);
	kr = vm_object_copy_strategically(
		sub_object,
		submap_entry_offset,
		submap_entry_size,
		false, /* forking */
		&copy_object,
		&object_copied_offset,
		&object_copied_needs_copy);
	assert(kr != KERN_MEMORY_RESTART_COPY);

	if (kr != KERN_SUCCESS) {
		vm_object_deallocate(copy_object);
		copy_object = VM_OBJECT_NULL;
		ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_SUBMAP_COPY_STRAT_FAILED), 0 /* arg */);
		DTRACE_VM4(submap_copy_error_strategically,
		    vm_object_t, sub_object,
		    vm_object_offset_t, submap_entry_offset,
		    vm_object_size_t, submap_entry_size,
		    int, kr);
		vm_map_lookup_and_lock_object_copy_strategically_error++;
		return kr;
	}
	assert(copy_object != VM_OBJECT_NULL);
	assert(copy_object != sub_object);
	vm_map_lookup_and_lock_object_copy_strategically_count++;
	vm_map_lookup_and_lock_object_copy_strategically_size += submap_entry_size;
	if (submap_entry_size > vm_map_lookup_and_lock_object_copy_strategically_max) {
		vm_map_lookup_and_lock_object_copy_strategically_max = submap_entry_size;
	}

	/*
	 * Adjust the fault offset to the submap entry.
	 */
	copy_offset = (submap_addr - submap_entry->vme_start + VME_OFFSET(submap_entry));

	/*
	 * Clip (and unnest) the smallest nested chunk
	 * possible around the faulting address...
	 */
	local_start = top_addr & ~(pmap_shared_region_size_min(old_map->pmap) - 1);
	local_end = local_start + pmap_shared_region_size_min(old_map->pmap);

	/*
	 * ... but don't go beyond the "old_start" to "old_end"
	 * range, to avoid spanning over another VM region
	 * with a possibly different VM object and/or offset.
	 */
	if (local_start < top_entry_start) {
		local_start = top_entry_start;
	}
	if (local_end > top_entry_end) {
		local_end = top_entry_end;
	}

	/*
	 * Adjust copy_offset to the start of the range.
	 */
	copy_offset -= (top_addr - local_start);

	if (__vmrl_clip_needed(top_entry, local_start, local_end,
	    __vmrl_flags(vml_ctx), VMRL_CLIP_RESOLVE_SUBMAP_COW)) {
		__vmrl_ilk_lock_exclusive(old_map);
		__vmrl_clip_ilocked(old_map, top_entry, local_start, local_end,
		    VMRL_CLIP_UNLOCK_SPLITS);
		__vmrl_ilk_unlock_exclusive(old_map);
	}

	/*
	 * top_entry's bounds now match the requested unnesting exactly.
	 * Change top_entry into a copy of the submap's contents
	 * by copying values from submap_entry to top_entry.
	 */

	/* pmap unnesting should already be done */
	assert(!top_entry->use_pmap);
	assert(!top_entry->iokit_acct);
	top_entry->use_pmap = true;

	/* propagate the submap entry's protections */
	if (top_entry->protection != VM_PROT_READ) {
		/*
		 * Someone has already altered the top entry's
		 * protections via vm_protect(VM_PROT_COPY).
		 * Respect these new values and ignore the
		 * submap entry's protections.
		 */
	} else {
		/*
		 * Regular copy-on-write: propagate the submap
		 * entry's protections to the top map entry.
		 */
		top_entry->protection |= submap_entry->protection;
	}
	top_entry->max_protection |= submap_entry->max_protection;

	/* propagate some attributes from subentry */
	top_entry->vme_no_copy_on_read = submap_entry->vme_no_copy_on_read;
	top_entry->vme_permanent = submap_entry->vme_permanent;
	top_entry->csm_associated = submap_entry->csm_associated;
#if __arm64e__
	/* propagate TPRO iff the destination map has TPRO enabled */
	if (submap_entry->used_for_tpro && vm_map_tpro(old_map)) {
		top_entry->used_for_tpro = submap_entry->used_for_tpro;
	}
#endif /* __arm64e */
	if ((top_entry->protection & VM_PROT_WRITE) &&
	    (top_entry->protection & VM_PROT_EXECUTE) &&
#if XNU_TARGET_OS_OSX
	    old_map->pmap != kernel_pmap &&
	    (vm_map_cs_enforcement(old_map)
#if __arm64__
	    || !VM_MAP_IS_EXOTIC(old_map)
#endif /* __arm64__ */
	    ) &&
#endif /* XNU_TARGET_OS_OSX */
#if CODE_SIGNING_MONITOR
	    (csm_address_space_exempt(old_map->pmap) != KERN_SUCCESS) &&
#endif
	    !(top_entry->used_for_jit) &&
	    VM_MAP_POLICY_WX_STRIP_X(old_map)) {
		DTRACE_VM3(cs_wx,
		    uint64_t, (uint64_t)top_entry->vme_start,
		    uint64_t, (uint64_t)top_entry->vme_end,
		    vm_prot_t, top_entry->protection);
		printf("CODE SIGNING: %d[%s] %s:%d(0x%llx,0x%llx,0x%x) can't have both write and exec at the same time\n",
		    proc_selfpid(),
		    (get_bsdtask_info(current_task())
		    ? proc_name_address(get_bsdtask_info(current_task()))
		    : "?"),
		    __FUNCTION__, __LINE__,
#if DEVELOPMENT || DEBUG
		    (uint64_t)top_entry->vme_start,
		    (uint64_t)top_entry->vme_end,
#else /* DEVELOPMENT || DEBUG */
		    (uint64_t)0,
		    (uint64_t)0,
#endif /* DEVELOPMENT || DEBUG */
		    top_entry->protection);
		top_entry->protection &= ~VM_PROT_EXECUTE;
	}

	top_entry->needs_copy = object_copied_needs_copy;
	top_entry->is_shared = false;

	if (top_entry->inheritance == VM_INHERIT_SHARE) {
		top_entry->inheritance = VM_INHERIT_COPY;
	}

	/*
	 * top_entry currently points to the submap.
	 * Change it to point to the vm_object copied from the submap's contents.
	 * Do this last. Deallocating top_entry's submap reference invalidates
	 * submap and submap_entry.
	 */
	assert(submap == VME_SUBMAP(top_entry));
	VME_OBJECT_SET(top_entry, copy_object, false, 0);
	VME_OFFSET_SET(top_entry, local_start - top_entry_start + object_copied_offset);
	vm_map_deallocate(submap);
	submap = NULL;
	submap_entry = NULL;

	return KERN_SUCCESS;
}

/*
 * Unnesting a range allows the parent pmap to have different information about a memory range
 * than the pmap that was nested there. For example if an mprotect() was done on
 * the shared region, the pmap unnest is required so the PTEs of the relevant process
 * can have their protections changed without every shared region having that happen.
 *
 * Adapted from clip_start
 */
__attribute__((noinline))
static void
vm_range_lock_pmap_unnest_and_clip(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vmrl_flags_t            flags,
	vm_map_entry_t          entry,
	const vm_map_address_t  start,
	const vm_map_address_t  end)
{
	vm_map_offset_t unnest_start, unnest_end, unnest_mask;
	vm_map_offset_t old_start, old_end;
	bool            needs_clip;
	vm_map_t        submap = VME_SUBMAP(entry);

	assert(entry->is_sub_map && submap != NULL && entry->use_pmap);
	assert(!vm_map_is_sealed(map) && !map->mapped_in_other_pmaps);

	/*
	 * Make sure "start" is no longer in a nested range before we clip.
	 * Unnest only the minimum range the platform can handle.
	 */
	unnest_mask  = (pmap_shared_region_size_min(map->pmap) - 1);
	unnest_start = old_start = (start & ~unnest_mask);
	unnest_end   = old_end   = (end + unnest_mask) & ~unnest_mask;

	/*
	 * Query the platform for the optimal unnest range.
	 * DRK: There's some duplication of effort here, since
	 * callers may have adjusted the range to some extent. This
	 * routine was introduced to support 1GiB subtree nesting
	 * for x86 platforms, which can also nest on 2MiB boundaries
	 * depending on size/alignment.
	 */
	if (pmap_adjust_unnest_parameters(map->pmap, &unnest_start, &unnest_end) &&
	    !map->terminated) {
		assert(submap->is_nested_map);
		assert(!submap->disable_vmentry_reuse);
		log_unnest_badness(map, old_start, old_end,
		    submap->is_nested_map,
		    (entry->vme_start +
		    submap->lowest_unnestable_start -
		    VME_OFFSET(entry)));
	}

	if (entry->vme_start > unnest_start || entry->vme_end < unnest_end) {
		panic("vm_map_clip_unnest(0x%llx,0x%llx): "
		    "bad nested entry: start=0x%llx end=0x%llx\n",
		    (long long)unnest_start, (long long)unnest_end,
		    (long long)entry->vme_start, (long long)entry->vme_end);
	}

	needs_clip = __vmrl_clip_needed(entry, unnest_start, unnest_end,
	    flags, VMRL_CLIP_PMAP_UNNEST);
	if (needs_clip) {
		__vmrl_ilk_upgrade(map, map_held);

		__vmrl_clip_ilocked(map, entry, unnest_start, unnest_end,
		    VMRL_CLIP_UNLOCK_SPLITS | VMRL_CLIP_UNNESTING);

		__vmrl_ilk_downgrade(map, map_held);
	}

	/*
	 * Mark the entry as un-nested.
	 */
	entry->use_pmap = false;
	if (!vmrl_is_kernel_pmap(flags) &&
	    (VME_ALIAS(entry) == VM_MEMORY_SHARED_PMAP)) {
		VME_ALIAS_SET(entry, VM_MEMORY_UNSHARED_PMAP);
	}

	/*
	 * Avoid trying to do any clipping here, as we would want
	 * to unlock splits.
	 * Unlocking an entry, which unlocking splits would do,
	 * would allow another thread to observe the case where we
	 * changed entry->use_pmap without having called pmap_unnest.
	 */
	KDBG(VMDBG_CODE(DBG_VM_PMAP_UNNEST) | DBG_FUNC_NONE, start, end);

	pmap_unnest(map->pmap, unnest_start, unnest_end - unnest_start);
}

__attribute__((noinline)) /* This path is not called often, so keep it out of the common flow */
static void
vm_map_entry_setup_symmetric_cow(vm_map_t map, vm_map_entry_t entry)
{
	vm_object_t object = VME_OBJECT(entry);
	/* preflights that return VMRL_ERR_SETUP_SYMMETRIC_COW or VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP
	 * should have checked that there's an object and that it's COPY_SYMMETRIC */
	assert3p(object, !=, VM_OBJECT_NULL);
	assert3u(object->copy_strategy, ==, MEMORY_OBJECT_COPY_SYMMETRIC);

	/* Preflight hooks should check for needs_copy,
	 * and sealed maps shouldn't have any objects with a MEMORY_OBJECT_COPY_SYMMETRIC strategy. */
	assert(!entry->needs_copy && !vm_map_is_sealed(map));

	vm_prot_t prot;

	if (pmap_has_prot_policy(map->pmap, entry->translated_allow_execute,
	    entry->protection)) {
		panic("prot_policy check1: map %p pmap %p entry %p 0x%llx:0x%llx prot 0x%x",
		    map, map->pmap, entry, entry->vme_start, entry->vme_end, entry->protection);
	}

	prot = entry->protection & ~VM_PROT_WRITE;
	if (override_nx(map, VME_ALIAS(entry)) && prot) {
		prot |= VM_PROT_EXECUTE;
	}

	if (pmap_has_prot_policy(map->pmap, entry->translated_allow_execute, prot)) {
		panic("prot_policy check2: map %p pmap %p entry %p 0x%llx:0x%llx prot 0x%x",
		    map, map->pmap, entry, entry->vme_start, entry->vme_end, prot);
	}

	vm_object_pmap_protect(object, VME_OFFSET(entry),
	    entry->vme_end - entry->vme_start,
	    entry->is_shared ? PMAP_NULL : map->pmap,
	    VM_MAP_PAGE_SIZE(map),
	    entry->vme_start,
	    prot);

	assert(entry->wired_count == 0);
	entry->needs_copy = true;
	if (!object->shadowed) {
		vm_object_lock(object);
		VM_OBJECT_SET_SHADOWED(object, TRUE);
		vm_object_unlock(object);
	}
}

static void
vm_map_entry_update_is_shared(vm_map_t map, vm_map_entry_t entry)
{
	vm_object_t object = VME_OBJECT(entry);

	if (object == VM_OBJECT_NULL) {
		/* sealed submaps should not have entries with null objects */
		assert(!vm_map_is_sealed(map));
		/*
		 * The only case when vm_map_stabilize_object_for_share()
		 * allows a null object is the PROT_NONE case.
		 */
		assert(entry->protection == VM_PROT_NONE);
		assert(entry->max_protection == VM_PROT_NONE);
		entry->is_shared = FALSE;
	} else {
		if (vm_map_is_sealed(map)) {
			/* vm_map_seal() sets is_shared to true */
			assert(entry->is_shared);
		} else {
			entry->is_shared = TRUE;
		}
	}
}


__attribute__((noinline)) /* no-inline so that it doesn't take space in the fast-path of locking an entry */
static void
vm_map_entry_prepare_for_share(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t    entry,
	bool              share_with_upl)
{
	vm_map_stabilize_object_for_share(ctx, entry, true, share_with_upl);

	if (!share_with_upl) {
		vm_map_entry_update_is_shared(vm_map_lock_ctx_get_map(ctx), entry);
	}
}

/*!
 * @abstract
 * Helper function for running the preflight on an entry.
 *
 *
 * @param vml_ctx       the locking context.
 * @param entry         the entry to preflight
 *
 * @returns The preflight return code.
 */
static kern_return_t
__vmrl_run_entry_preflight_internal(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	bool                    allow_actions)
{
	kern_return_t kr;

	RANGE_LOCK_ASSERT(vml_ctx->vmlc_preflight != NULL);

	/* so that vm_map_lock_ctx_bounds(ctx, ...) works */
	vml_ctx->vmlc_vme = entry;
	kr = vml_ctx->vmlc_preflight(vml_ctx, entry);
	vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;

	RANGE_LOCK_ASSERT(kr != VMRL_ERR_RELOOKUP);
	RANGE_LOCK_ASSERT(kr != VMRL_ERR_ABORTED);
	RANGE_LOCK_ASSERT(kr != VMRL_ERR_NOT_FOUND);
	RANGE_LOCK_ASSERT(kr != VMRL_ERR_LOCK_ALREADY_HELD);

	if (!allow_actions) {
		RANGE_LOCK_ASSERT(kr != VMRL_ERR_WAIT_FOR_KUNWIRE);
		RANGE_LOCK_ASSERT(kr != VMRL_ERR_SETUP_SYMMETRIC_COW);
		RANGE_LOCK_ASSERT(kr != VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP);
		RANGE_LOCK_ASSERT(kr != VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP);
	}
	return kr;
}

/*!
 * @abstract
 * Create a sentinel entry.
 *
 *
 * @param vml_ctx       the locking context.
 * @param map           map in which to create the sentinel entry
 * @param next_entry    entry before which to create the sentinel
 * @param start         start addr of the sentinel entry to be created
 * @param end           addr denoting the end of the range of interest to the
 *                      caller. it acts as an upper bound on the end addr of
 *                      the resulting entry, which may have a lower end addr
 *                      than @c end if @c next_entry overlaps with the range.
 * @param sentinel      pointer which will be set to the newly created
 *                      sentinel entry
 *
 * @returns The preflight return code, if any, or @c KERN_SUCCESS.
 */
__cold
static kern_return_t
vm_map_make_sentinel_ilocked(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t                map,
	vm_map_entry_t          next_entry,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vm_map_entry_t         *sentinel)
{
	vm_map_entry_t new_entry;
	kern_return_t  kr = KERN_SUCCESS;

	if (!entry_is_map_end(map, next_entry) &&
	    next_entry->vme_start < end) {
		end = next_entry->vme_start;
	}

	new_entry = vm_map_entry_create_sentinel_locked(map, start, end);

	vm_map_store_insert(map, new_entry);

	if (vml_ctx->vmlc_preflight) {
		kr = __vmrl_run_entry_preflight_internal(vml_ctx, new_entry, false);

		/*
		 * The preflight requested that we not call
		 * __vmrl_entry_prepare_ilocked on the entry, but this isn't
		 * done on sentinel entries anyway.
		 */
		if (kr == VMRL_ERR_SKIP_PREPARE) {
			kr = KERN_SUCCESS;
		}
	}

	*sentinel = new_entry;

	return kr;
}


#pragma mark simplify


/*
 * Test if we should try to simplify a given entry.
 * For now, we're only supporting simplify if the lock is exclusive.
 *
 * If simplify succeeds it always removes the entry with the lower address
 */
static bool
__vmrl_should_try_simplify(vmrl_flags_t flags, vm_map_entry_t entry)
{
	if (vmrl_is_exclusive(flags)) {
		return (flags & VMRL_SIMPLIFY) || vm_entry_needs_coalesce(entry);
	}
	return false;
}

/**
 * Simplify an entry with the previous entry.
 * Both the passed entry and the previous entry should be locked.
 * If the simplification happens, the previous entry is deleted and the current
 * entry's bounds are expanded to cover the bounds of the previous entry.
 *
 * @return true if the entry is simplified with its previous one.
 */
static bool
vm_map_simplify_entry_with_prev_locked(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          this_entry)
{
	vm_map_entry_t  prev_entry = VME_PREV(this_entry);

	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));
	vm_entry_assert_excl_owner(this_entry);
	vm_entry_assert_excl_owner(prev_entry);

	if (!entry_is_map_end(map, this_entry) &&
	    !entry_is_map_end(map, prev_entry) &&

	    vms_equal(prev_entry->vme_chunk, this_entry->vme_chunk) &&

	    (prev_entry->vme_end == this_entry->vme_start) &&

	    (prev_entry->is_sub_map == this_entry->is_sub_map) &&
	    (prev_entry->vme_object_value == this_entry->vme_object_value) &&
	    (prev_entry->vme_kernel_object == this_entry->vme_kernel_object) &&
	    ((VME_OFFSET(prev_entry) + (prev_entry->vme_end -
	    prev_entry->vme_start))
	    == VME_OFFSET(this_entry)) &&
	    (prev_entry->behavior == this_entry->behavior) &&
	    (prev_entry->needs_copy == this_entry->needs_copy) &&
	    (prev_entry->protection == this_entry->protection) &&
	    (prev_entry->max_protection == this_entry->max_protection) &&
	    (prev_entry->inheritance == this_entry->inheritance) &&
	    (prev_entry->use_pmap == this_entry->use_pmap) &&
	    (VME_ALIAS(prev_entry) == VME_ALIAS(this_entry)) &&
	    (prev_entry->no_cache == this_entry->no_cache) &&
	    (prev_entry->vme_permanent == this_entry->vme_permanent) &&
	    (prev_entry->zero_wired_pages == this_entry->zero_wired_pages) &&
	    (prev_entry->used_for_jit == this_entry->used_for_jit) &&
#if __arm64e__
	    (prev_entry->used_for_tpro == this_entry->used_for_tpro) &&
#endif
#if HAS_MTE
	    (prev_entry->vme_is_tagged == this_entry->vme_is_tagged) &&
#endif /* HAS_MTE */
	    (prev_entry->csm_associated == this_entry->csm_associated) &&
	    (prev_entry->vme_xnu_user_debug == this_entry->vme_xnu_user_debug) &&
	    (prev_entry->iokit_acct == this_entry->iokit_acct) &&
	    (prev_entry->vme_resilient_codesign ==
	    this_entry->vme_resilient_codesign) &&
	    (prev_entry->vme_resilient_media ==
	    this_entry->vme_resilient_media) &&
	    (prev_entry->vme_no_copy_on_read == this_entry->vme_no_copy_on_read) &&
	    (prev_entry->translated_allow_execute == this_entry->translated_allow_execute) &&

	    (prev_entry->wired_count == this_entry->wired_count) &&
	    (prev_entry->user_wired_count == this_entry->user_wired_count) &&

	    ((prev_entry->vme_atomic == FALSE) && (this_entry->vme_atomic == FALSE)) &&
	    (prev_entry->is_shared == this_entry->is_shared) &&
	    (prev_entry->superpage_size == FALSE) &&
	    (this_entry->superpage_size == FALSE)) {
		if (prev_entry->vme_permanent) {
			assert(this_entry->vme_permanent);
			prev_entry->vme_permanent = false;
		}

		__vmrl_ilk_upgrade(map, map_held);
		vm_map_store_merge_right(map, prev_entry, this_entry);

		/*
		 * TODO: deallocating this under the map lock is a performance
		 *       problem, we should use a delayed zap list.
		 *
		 *       It's especially bad because we can't do that after
		 *       downgrade as it disables preemption.
		 */
		vm_map_entry_free_locked(map, prev_entry);
		__vmrl_ilk_downgrade(map, map_held);
		return true;
	}

	return false;
}

/*
 * Simplify a locked entry with an unlocked previous entry.
 * If the simplification does happen, the previous entry is freed and the
 * passed entry pointer is expanded to cover that range as well.
 */
static void
vmrl_simplify_entry_with_unlocked_prev(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vmrl_flags_t            flags)
{
	RANGE_LOCK_ASSERT(!entry_is_map_end(map, entry));
	assert_vm_map_ilk_owned_ignore_sealed(map, map_held);

	if (__vmrl_should_try_simplify(flags, entry)) {
		vm_entry_assert_excl_owner(entry);

		if (entry_is_map_end(map, VME_PREV(entry))) {
			/* Prev is map_end, can't coalesce with it */
			vm_entry_update_needs_coalesce(entry, false);
			return;
		}

		/*
		 * Try to exclusively lock this entry and the previous one.
		 * If we can, try to simplify them and clear needs_coalesce
		 * Otherwise, set needs_coalesce on this entry.
		 */
		vm_map_entry_t prev = VME_PREV(entry);

		if (vm_entry_try_lock_exclusive(prev)) {
			if (!vm_map_simplify_entry_with_prev_locked(map, map_held, entry)) {
				vm_entry_unlock_exclusive(map, prev);
			}
			/* otherwise that entry was deleted during simplifcation */
			vm_entry_update_needs_coalesce(entry, false);
		} else {
			vm_entry_update_needs_coalesce(entry, true);
		}
	}
}

/**
 * Simplify a locked entry with an unlocked next entry.
 * If the simplification does happen, the passed entry is freed.
 *
 * @param entry the locked entry to try to simplify with the next entry
 *
 * @returns
 * The entry pointer that covers the range of the passed entry pointer. It may
 * or may not be different than the passed pointer.
 * The returned entry is still locked.
 */
__result_use_check
static vm_map_entry_t
vmrl_simplify_entry_with_unlocked_next(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vmrl_flags_t            flags)
{
	vm_map_entry_t next = entry->vme_next;

	assert_vm_map_ilk_owned_ignore_sealed(map, map_held);
	RANGE_LOCK_ASSERT(!entry_is_map_end(map, entry));

	if (__vmrl_should_try_simplify(flags, entry)) {
		vm_entry_assert_excl_owner(entry);
		if (entry_is_map_end(map, next)) {
			/* next is map_end, can't coalesce with it */
			vm_entry_update_needs_coalesce(entry, false);
			return entry;
		}

		if (!vm_entry_try_lock_exclusive(next)) {
			vm_entry_update_needs_coalesce(entry, true);
		} else if (vm_map_simplify_entry_with_prev_locked(map,
		    map_held, next)) {
			/*
			 * We simplified, what was the next entry is now the
			 * entry we should be working of off.
			 * That entry still remains locked.
			 */
			entry = next;
			vm_entry_update_needs_coalesce(entry, false);
		} else {
			vm_entry_unlock_exclusive(map, next);
			vm_entry_update_needs_coalesce(entry, false);
		}
	}

	return entry;
}

/*
 * Simplify a locked entry with an locked previous entry.
 * If the simplification does happen, the previous entry is freed and the
 * passed entry pointer is expanded to cover that range as well.
 */
__result_use_check
static bool
vmrl_simplify_entry_with_locked_prev(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vmrl_flags_t            flags)
{
	vm_map_entry_t prev = VME_PREV(entry);
	bool result = false;

	assert_vm_map_ilk_owned_ignore_sealed(map, map_held);
	RANGE_LOCK_ASSERT(!entry_is_map_end(map, entry));
	RANGE_LOCK_ASSERT(!entry_is_map_end(map, prev));
	vm_entry_assert_excl_owner(entry);
	vm_entry_assert_excl_owner(prev);

	if (__vmrl_should_try_simplify(flags, entry)) {
		/* If we think it's worth it, we could try a shared to exclusive upgrade as well. */
		result = vm_map_simplify_entry_with_prev_locked(map, map_held, entry);
		vm_entry_update_needs_coalesce(entry, false);
	}

	return result;
}

/*
 * Simplify an atomic range where every entry within that range is locked.
 * This tries to simplify the entries on the edge of the range with their
 * respective unlocked neighbors.
 * It also simplifies every locked entry in the range with their locked neighbors.
 */
static void
__vmrl_simplify_atomic_range_ilocked(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_t         map   = vml_ctx->vmlc_map;
	vmrl_flags_t     flags = __vmrl_flags(vml_ctx);
	vm_map_entry_t   entry = vml_ctx->__vmlc_atomic.first_entry;
	vm_map_address_t end   = vml_ctx->vmlc_req_end;
	vm_map_entry_t   last_entry = entry;
	vm_map_entry_t   saved_last_entry;

	/*
	 * First, try to simplify the first entry.
	 * It's special because the prior entry isn't locked
	 */
	vmrl_simplify_entry_with_unlocked_prev(map,
	    LCK_RW_TYPE_EXCLUSIVE, entry, flags);

	/* And simplify all the entries in between. */
	entry = entry->vme_next;
	while (!entry_is_map_end(map, entry) && entry->vme_start < end) {
		vm_map_entry_t prev = VME_PREV(entry);

		if (vmrl_simplify_entry_with_locked_prev(map,
		    LCK_RW_TYPE_EXCLUSIVE, entry, flags)) {
			/* If we deleted the prev entry, update the first entry */
			if (vml_ctx->__vmlc_atomic.first_entry == prev) {
				vml_ctx->__vmlc_atomic.first_entry = entry;
			}
		}

		last_entry = entry;
		entry = entry->vme_next;
	}

	/*
	 * And then simplify the last one, special because the next isn't locked.
	 */
	saved_last_entry = last_entry;
	last_entry = vmrl_simplify_entry_with_unlocked_next(map,
	    LCK_RW_TYPE_EXCLUSIVE, last_entry, flags);

	/* If we deleted the entry, update the first entry */
	if (vml_ctx->__vmlc_atomic.first_entry == saved_last_entry) {
		vml_ctx->__vmlc_atomic.first_entry = last_entry;
	}
}

__result_use_check
vm_map_entry_t
vm_map_locked_entry_simplify(
	vm_map_t                map,
	vm_map_entry_t          entry)
{
	/*
	 * Simplification APIs expect vmrl_flags_t. Craft flags that will always
	 * attempt to simplify.
	 */
	vmrl_flags_t flags = VMRL_EXCLUSIVE | VMRL_SIMPLIFY;

	vm_entry_assert_excl_owner(entry);

	__vmrl_ilk_lock_exclusive(map);

	vmrl_simplify_entry_with_unlocked_prev(map,
	    LCK_RW_TYPE_EXCLUSIVE, entry, flags);

	entry = vmrl_simplify_entry_with_unlocked_next(map,
	    LCK_RW_TYPE_EXCLUSIVE, entry, flags);

	__vmrl_ilk_unlock_exclusive(map);

	return entry;
}

static bool
vm_map_entry_needs_symmetric_cow_resolved(vmrl_flags_t flags, vm_map_entry_t entry)
{
	VM_ENTRY_ASSERT_OWNER(entry);

	if (entry->is_sub_map || !entry->needs_copy) {
		return false;
	}
	if (flags & VMRL_RESOLVE_COW_AND_OBJ) {
		return true;
	}
	return false;
}

static bool
vm_map_entry_needs_object(vmrl_flags_t flags, vm_map_entry_t entry)
{
	VM_ENTRY_ASSERT_OWNER(entry);

	if (entry->is_sub_map ||
	    entry->max_protection == VM_PROT_NONE ||
	    (VME_OBJECT(entry) != VM_OBJECT_NULL)) {
		return false;
	}
	if (flags & (VMRL_VMO_ALLOCATE | VMRL_RESOLVE_COW_AND_OBJ)) {
		return true;
	}
	return false;
}

static bool
vm_map_entry_needs_pmap_unnest(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        addr_to_lock)
{
	vmrl_flags_t flags = __vmrl_flags(vml_ctx);

	VM_ENTRY_ASSERT_OWNER(entry);

	if (entry->is_sub_map && entry->use_pmap) {
		if (vmrl_is_exclusive(flags) || (flags & VMRL_RESOLVE_COW_AND_OBJ)) {
			if (flags & VMRL_NO_PMAP_UNNEST) {
				/*
				 * We've been asked not to pmap unnest unless
				 * needed.
				 * But if we're going to clip, we still need to
				 * pmap unnest.
				 */
				bool would_clip_end = vml_ctx->vmlc_req_end < entry->vme_end;
				bool would_clip_start = addr_to_lock > entry->vme_start;

				return would_clip_end || would_clip_start;
			} else {
				return true;
			}
		}
	}

	return false;
}


/*!
 * Advance vmlc_req_start to a given address.
 * This is used by streaming locks to make the vm_map_lock_ctx_bounds() never
 * return addresses before the range already processed.
 *
 * vmlc_req_start can theoretically go backwards if we're ascending/descending
 * in or out of a submap.
 */
static void __attribute__((always_inline))
__vmrl_set_vmlc_req_start(vm_map_lock_ctx_t vml_ctx, vm_map_address_t addr)
{
	if (addr != vml_ctx->__original_req_start) {
		/* We only advance for streaming, atomic doesn't change it */
		assert(vmrl_is_streaming(vml_ctx));
	}
	vml_ctx->vmlc_req_start = addr;
}

#pragma mark map recursion

/*
 * Transform the variables in the lock context to make sense within the context
 * of the submap referred to by entry
 *
 * This adjusts the start and end address of the range, along with the map being operated on
 */
static void
__vmrl_descend(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        current_addr,
	vmlc_descend_t          how)
{
	vm_map_offset_t  offset;
	vm_map_address_t new_end;

	RANGE_LOCK_ASSERT(current_addr >= entry->vme_start);
	RANGE_LOCK_ASSERT(current_addr < entry->vme_end);

	/*
	 * The address we end at in the submap is the minimum of the
	 * window the parent entry gives or the requested end
	 */
	offset  = entry->vme_start - VME_OFFSET(entry);
	new_end = MIN(vml_ctx->__original_req_end, entry->vme_end);

	/* Transform all our variables to be in submap context */
	vml_ctx->vmlc_req_start   = current_addr - offset;
	vml_ctx->vmlc_req_end     = new_end - offset;
	vml_ctx->vmlc_map         = VME_SUBMAP(entry);
	vml_ctx->vmlc_vme         = VM_MAP_ENTRY_NULL;

	vml_ctx->__vmlc_descended = how;
	vml_ctx->__parent_offset  = offset;
	vml_ctx->__parent_entry   = entry;

	if (vmrl_is_streaming(vml_ctx)) {
		vml_ctx->__vmlc_streaming.last_processed_addr = current_addr - offset;
	}
}

/*
 * Ascend out from a submap, updating vml_ctx with the bounds/entry of the parent map
 */
static vm_map_t
__vmrl_ascend(vm_map_lock_ctx_t vml_ctx)
{
	RANGE_LOCK_ASSERT(vm_map_lock_ctx_is_descended(vml_ctx));

	if (vmrl_is_streaming(vml_ctx)) {
		mach_vm_address_t next_parent_addr;
		/*
		 * Ascending, but next_address is in the coordinate of the
		 * submap. Fix that.
		 */
		next_parent_addr =
		    vm_map_lock_ctx_to_parent_address(vml_ctx,
		    vml_ctx->__vmlc_streaming.last_processed_addr);

		assert(next_parent_addr <= vml_ctx->__original_req_end);
		assert(next_parent_addr <= vml_ctx->__parent_entry->vme_end);
		vml_ctx->__vmlc_streaming.last_processed_addr = next_parent_addr;

		/* For streaming, we move the req_start forward */
		__vmrl_set_vmlc_req_start(vml_ctx, vm_map_lock_ctx_to_parent_address(vml_ctx, vml_ctx->vmlc_req_start));
	} else {
		/* Atomic lock, we don't ever change req_start */
		__vmrl_set_vmlc_req_start(vml_ctx, vml_ctx->__original_req_start);
	}

	vml_ctx->vmlc_map         = vml_ctx->__original_map;
	vml_ctx->vmlc_vme         = vml_ctx->__parent_entry;
	vml_ctx->vmlc_req_end     = vml_ctx->__original_req_end;

	vml_ctx->__vmlc_descended = VMLC_NOT_DESCENDED;
	vml_ctx->__parent_offset  = 0;
	vml_ctx->__parent_entry   = VM_MAP_ENTRY_NULL;

	return vml_ctx->vmlc_map;
}


static bool
__vmrl_descend_in_transparent_submap(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        addr)
{
	VM_ENTRY_ASSERT_NOT_OWNER(entry);
	assert(vm_map_entry_is_transparent_submap(entry));
	assert(!vm_map_lock_ctx_is_descended(vml_ctx));

	/* We descend into transparent submaps by default. */
	bool descend = !(__vmrl_flags(vml_ctx) & VMRL_NO_DESCEND_TRANSPARENT);
	bool exclusive = vmrl_is_exclusive(vml_ctx);
	bool stream = vmrl_is_streaming(vml_ctx);

	if (descend) {
		/* Verify the range consists only of the transparent submap */
		if (exclusive && !stream) {
			if (vml_ctx->vmlc_req_start < entry->vme_start ||
			    entry->vme_end < vml_ctx->vmlc_req_end) {
				__vm_map_transparent_submap_panic(vml_ctx, entry);
			}
			if (vml_ctx->vmlc_vme != NULL) {
				__vm_map_transparent_submap_panic(vml_ctx,
				    vml_ctx->vmlc_vme);
			}
		}

		__vmrl_descend(vml_ctx, entry, addr, VMLC_IN_TRANSPARENT_SUBMAP);
		return true;
	}
	return false;
}

/*
 * This function descends into a constant submap at a given address.
 * It transforms lock ctx variables to mark that it descended.
 */
static vm_map_entry_t
__vmrl_descend_in_constant_submap(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        addr)
{
	RANGE_LOCK_ASSERT(!vm_map_lock_ctx_is_descended(vml_ctx));
	__vmrl_descend(vml_ctx, entry, addr, VMLC_IN_CONSTANT_SUBMAP);
	entry = vm_map_lookup(vml_ctx->vmlc_map,
	    vm_map_lock_ctx_from_parent_address(vml_ctx, addr));
	RANGE_LOCK_ASSERT(entry);

	return entry;
}

static bool
__vmrl_should_descend_in_constant_submap(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry)
{
	if (__vmrl_flags(vml_ctx) & VMRL_DESCEND_INTO_CONSTANT) {
		return vm_map_entry_is_constant_submap(entry);
	}
	return false;
}

#pragma mark range context


static void
__vmrl_context_set_flags(
	vm_map_lock_ctx_t       vml_ctx,
	vmrl_flags_t            flags)
{
	RANGE_LOCK_ASSERT(vmrl_mode(flags) != VMRL_INVALID);
	RANGE_LOCK_ASSERT(vmrl_is_streaming(flags) ^ vmrl_is_atomic(flags));
	RANGE_LOCK_ASSERT(vmrl_is_shared(flags) ^ vmrl_is_exclusive(flags));
	RANGE_LOCK_ASSERT(((bool)(flags & _VMRL_NO_HOLES)) ^ ((bool)(flags & _VMRL_ALLOW_HOLES)));

	if (flags & VMRL_NO_PMAP_UNNEST) {
		/* submap unnesting requires a pmap unnest */
		RANGE_LOCK_ASSERT(!(flags & VMRL_RESOLVE_COW_AND_OBJ));
	}

	if (flags & VMRL_SIMPLIFY) {
		RANGE_LOCK_ASSERT(vmrl_is_exclusive(flags));
	}

	if (flags & VMRL_NO_DESCEND_TRANSPARENT) {
		/*
		 * We have no reason to believe atomic is needed and thus
		 * haven't meaningfully tested it.
		 */
		RANGE_LOCK_ASSERT(vmrl_is_streaming(flags));
		/*
		 * Similarly, it seems confusing to ask for descension except
		 * for descension into transparent submaps
		 */
		RANGE_LOCK_ASSERT(!(flags & VMRL_DESCEND_INTO_CONSTANT));

		/*
		 * exclusive lockers should never want this,
		 * as the transparent submap entry itself should not be modified.
		 * (by the lock's clipping or by client code)
		 */
		RANGE_LOCK_ASSERT(vmrl_is_shared(flags));
	}

	vml_ctx->__vmlc_flags = flags;
}

static void
__vmrl_add_flags(
	vm_map_lock_ctx_t       vml_ctx,
	vmrl_flags_t            flags)
{
	/* The lock doesn't currently support adding ilocked */
	RANGE_LOCK_ASSERT(!(flags & VMRL_ILK_LOCKED));
	RANGE_LOCK_ASSERT(vmrl_is_shared(flags) == vmrl_is_shared(vml_ctx));

	__vmrl_context_set_flags(vml_ctx, vml_ctx->__vmlc_flags | flags);
}

static void
__vmrl_remove_flags(
	vm_map_lock_ctx_t       vml_ctx,
	vmrl_flags_t            flags)
{
	vmrl_ex_flags_t mask = ~flags;

	RANGE_LOCK_ASSERT((vml_ctx->__vmlc_flags & flags) != 0);
	RANGE_LOCK_ASSERT(vmrl_is_shared(flags) == vmrl_is_shared(vml_ctx));

	__vmrl_context_set_flags(vml_ctx, vml_ctx->__vmlc_flags & mask);
}


void
vm_map_range_ex_lock_add_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_ex_flags_t flags)
{
	__vmrl_add_flags(vml_ctx, (vmrl_flags_t)flags);
}

void
vm_map_range_ex_lock_remove_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_ex_flags_t flags)
{
	__vmrl_remove_flags(vml_ctx, (vmrl_flags_t)flags);
}

extern void
vm_map_range_sh_lock_add_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_sh_flags_t flags)
{
	__vmrl_add_flags(vml_ctx, (vmrl_flags_t)flags);
}

extern void
vm_map_range_sh_lock_remove_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_sh_flags_t flags)
{
	__vmrl_remove_flags(vml_ctx, (vmrl_flags_t)flags);
}

/*!
 * @abstract
 * Make the current thread know about the ctx that is currently being worked on
 *
 * @discussion
 * thread->vm_map_lock_ctx_held is used by stackshot to range locks that are
 * currently active in the system.
 * When stackshot find a thread that has non-NULL vm_map_lock_ctx_held it also
 * assumes that:
 * - The context is valid and allocated on the stack of that thread
 * - If the lock is a stream lock and ctx->vmlc_vme is non-NULL, then it points
 *   to a valid entry
 */
__attribute__((always_inline))
static void
__vmrl_context_register_in_cur_thread(vm_map_lock_ctx_t vml_ctx)
{
	os_atomic_store(&current_thread()->vm_map_lock_ctx_held, vml_ctx, compiler_acq_rel);
}

__attribute__((always_inline))
static void
__vmrl_context_unregister_in_cur_thread(void)
{
	os_atomic_store(&current_thread()->vm_map_lock_ctx_held, NULL, compiler_acq_rel);
}


/*!
 * @abstract
 * Reset the context for unlock paths.
 *
 * @discussion
 * Clear fields that only make sense while the lock is held.
 * The only fields we want to maintain are:
 * - the start/end of the current range being queried,
 * - the flags that were passed (some clients want to be able to query them
 *   past unlock which is viable).
 */
static void
__vmrl_context_clear_unsafe(vm_map_lock_ctx_t vml_ctx)
{
	struct vm_map_lock_ctx tmp = {
		.vmlc_req_start = vml_ctx->vmlc_req_start,
		.vmlc_req_end   = vml_ctx->vmlc_req_end,
		.vmlc_preflight = vml_ctx->vmlc_preflight,
		.__vmlc_flags   = vml_ctx->__vmlc_flags,
	};
	*vml_ctx = tmp;
}

/*!
 * @abstract
 * Initializes a context given a map, start, end and flags.
 */
__result_use_check
static kern_return_t
__vmrl_context_init(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_flags_t            flags)
{
	/* make sure that the context was clean and not reused */
	RANGE_LOCK_ASSERT(!vml_ctx->__vmlc_locked && !vml_ctx->vmlc_map);

	if (map->pmap == kernel_pmap) {
		flags |= _VMRL_KERNEL_PMAP;
	}

	if (flags & VMRL_WHOLE_MAP) {
		/* shouldn't have both this and NO_MIN_MAX_CHECK flags since they mean similar but slightly different things */
		RANGE_LOCK_ASSERT((flags & VMRL_NO_MIN_MAX_CHECK) == 0);
		/* WHOLE_MAP and NO_HOLES don't make sense together since a hole would be encountered when iterating
		 * on the range from 0 to the first entry and from the last entry to END_VA. That would cause
		 * either an unexpected error or an unexpected sentinel creation */
		RANGE_LOCK_ASSERT((flags & _VMRL_NO_HOLES) == 0);
		release_assert(start == VMRL_WHOLE_MAP_START && end == VMRL_WHOLE_MAP_END);
		start = VMRL_START_VA(map);
		end = VMRL_END_VA(map);
	}

#if KASAN_TBI
	if (VM_KERNEL_ADDRESS(start)) {
		start = vm_memtag_canonicalize_kernel(start);
	}
	if (VM_KERNEL_ADDRESS(end)) {
		end = vm_memtag_canonicalize_kernel(end);
	}
#endif /* KASAN_TBI */

	/*
	 * Set the same state that __vmrl_context_clear_unsafe()
	 * leaves alone: flags are important, some clients need them set.
	 */
	*vml_ctx = (struct vm_map_lock_ctx){
		.vmlc_req_start       = start,
		.vmlc_req_end         = end,
		.vmlc_map             = map,

		.vmlc_preflight       = vml_ctx->vmlc_preflight,

		.__vmlc_locked        = true,
		.__vmlc_first         = true,

		.__original_req_start = start,
		.__original_req_end   = end,
		.__original_map       = map,
	};
	__vmrl_context_set_flags(vml_ctx, flags);

	if (vmrl_is_streaming(flags)) {
		vml_ctx->__vmlc_streaming.last_processed_addr = start;
	}


	if (flags & VMRL_NO_MIN_MAX_CHECK || flags & VMRL_WHOLE_MAP) {
		/* any range is allowed */
	} else if (start < map->min_offset || end > map->max_offset) {
		return KERN_INVALID_ADDRESS;
	}

	if (start >= end) {
		return KERN_INVALID_ADDRESS;
	}

	__vmrl_context_register_in_cur_thread(vml_ctx);

	return KERN_SUCCESS;
}

/*!
 * @abstract
 * Configures a context to manage a series of already-exclusive-locked entries.
 */
kern_return_t
vm_map_lock_ctx_from_locked_entries(
	vm_map_lock_ctx_t   vml_ctx,
	vm_map_t           *map,
	vm_map_address_t    start,
	vm_map_size_t       size)
{
	kern_return_t    kr;
	vm_map_address_t end = start + size;

	assert(!vml_ctx->vmlc_preflight); /* Not yet implemented. */

	/* Verify the first entry exists where we expect and is locked. */
	__vmrl_ilk_lock_shared_spin(*map);
	vm_map_entry_t first_entry = vm_map_store_lookup_entry(*map, start, false);
	if (!first_entry || first_entry->vme_start != start) {
		panic("expected an excl-locked entry to exist for vaddr=0x%llx", start);
	}

	/* Set up the lock context. */
	kr = __vmrl_context_init(vml_ctx, *map, start, end, VMRL_EXCLUSIVE | VMRL_ATOMIC);
	if (kr != KERN_SUCCESS) {
		__vmrl_ilk_unlock_shared_spin(*map);
		return kr;
	}
	vml_ctx->__vmlc_atomic.first_entry = first_entry;

	/* Verify there are no holes and that the entries are excl-locked. */
	vm_map_entry_t cur = VM_MAP_ENTRY_NULL;
	vm_map_entry_t prev = VM_MAP_ENTRY_NULL;
	while ((cur = vm_map_range_atomic_next(vml_ctx)) != VM_MAP_ENTRY_NULL) {
		assert(cur == first_entry || cur->vme_start == prev->vme_end);
		vm_entry_assert_excl_owner(cur);
		prev = cur;
	}
	vm_map_range_atomic_reset(vml_ctx);
	assert(prev->vme_end == end); /* Now prev is the final entry in the range. */

	__vmrl_ilk_unlock_shared_spin(*map);
	*map = BAD_MAP_VALUE;

	return KERN_SUCCESS;
}

/*!
 * @abstract
 * Update the cursor on a context to the given entry.
 * @returns
 * The entry that will be returned to the lock clients.
 * This is the same as vmlc_vme
 */
static vm_map_entry_t
__vmrl_context_set_vme(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	vmrl_flags_t            how)
{
	if (vmrl_is_streaming(how)) {
		/* in streaming, vmlc_req_start is updated before each iteration returns to the user
		 * so that vm_map_lock_ctx_bounds() works correctly. The lock iterated up to addr
		 * so we want to not return entries "starting" before that addr */
		__vmrl_set_vmlc_req_start(vml_ctx, addr);
	}
	if (__vmrl_should_descend_in_constant_submap(vml_ctx, entry)) {
		entry = __vmrl_descend_in_constant_submap(vml_ctx, entry, addr);
	}
	vml_ctx->vmlc_vme = entry;
	if (vmrl_is_streaming(how)) {
		/*
		 * The next address should be the end of the entry we're
		 * processing, but it shouldn't go past the end of the range.
		 */
		vml_ctx->__vmlc_streaming.last_processed_addr =
		    MIN(entry->vme_end, vml_ctx->vmlc_req_end);
	}
	return entry;
}


#pragma mark range lock

/*!
 * @abstract
 * Helper to unlock an entry in the right mode.
 */
__attribute__((always_inline))
static void
__vmrl_unlock_entry(vm_map_t map, vm_map_entry_t entry, vmrl_flags_t flags)
{
#if MACH_ASSERT
	/*
	 * Make sure we're not unlocking an entry stackshot thinks we still hold
	 * the lock for.
	 */
	if (current_thread()->vm_map_lock_ctx_held) {
		if (vmrl_is_streaming(flags)) {
			RANGE_LOCK_ASSERT(current_thread()->vm_map_lock_ctx_held->vmlc_vme == VM_MAP_ENTRY_NULL);
		} else {
			vm_map_address_t locked_range_start = current_thread()->vm_map_lock_ctx_held->__vmlc_atomic.locked_range_start;
			vm_map_address_t locked_range_end = current_thread()->vm_map_lock_ctx_held->__vmlc_atomic.locked_range_end;

			// The entry should have no parts of it contained within the locked range
			RANGE_LOCK_ASSERT(entry->vme_start >= locked_range_end || entry->vme_end <= locked_range_start);
		}
	}
#endif

	if (__improbable(vm_map_entry_is_transparent_submap(entry))) {
		/*
		 * for transparent submaps we descend into submaps
		 * and don't lock the submap entry itself.
		 */
	} else if (vmrl_is_exclusive(flags)) {
		vm_entry_unlock_exclusive(map, entry);
	} else {
		vm_entry_unlock_shared(map, entry);
	}
}

/*!
 * @abstract
 * Unlock a range from a given entry to a given end address goal.
 */
__attribute__((noinline))
static void
__vmrl_unlock_range_ilocked(
	vm_map_lock_ctx_t       vml_ctx,
	vmrl_flags_t            flags,
	vm_map_entry_t          entry,
	vm_map_offset_t         end)
{
	vm_map_t map = vml_ctx->vmlc_map;

	/* We're about to unlock entries, so make sure we have no stackshot context */
	__vmrl_context_unregister_in_cur_thread();

	if (vmrl_mode(flags) == VMRL_ATOMIC_ALLOW_HOLES) {
		assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_EXCLUSIVE);
	} else {
		assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_ANY);
	}

	while (!entry_is_map_end(map, entry) && entry->vme_start < end) {
		vm_map_entry_t next = entry->vme_next;

		if (__improbable(VME_IS_SENTINEL(entry))) {
			RANGE_LOCK_ASSERT(vmrl_mode(flags) ==
			    VMRL_ATOMIC_ALLOW_HOLES);
			/*
			 * This path is only expected to be hit when we hit an
			 * error during the process of locking.
			 *
			 * In the normal case, vm_map_delete uses pop() which
			 * would update the first entry past the sentinel,
			 * so unlock would unlock an empty range containing
			 * no sentinels.
			 */
			vm_map_store_remove(map, entry, VMS_REMOVE_FREE_ENTRY);
		} else {
			if (!entry->is_sub_map && VME_OBJECT(entry)) {
				/*
				 * Atomic locks take the interlock on unlock to
				 * simplify. We take the object lock under the
				 * interlock normally, which means it's invalid
				 * to take the interlock under the object lock.
				 *
				 * That means any atomic APIs must not hold
				 * object locks while unlocking.
				 */
				vm_object_assert_not_owned(VME_OBJECT(entry));
			}
			__vmrl_unlock_entry(map, entry, flags);
		}

		entry = next;
	}
}

static bool
vm_map_entry_needs_symmetric_cow_setup(vmrl_flags_t flags, vm_map_entry_t entry)
{
	vm_object_t object;
	if (!((flags & _VMRL_SETUP_COW) || (flags & _VMRL_SETUP_COW_NOCLIP))) {
		/* Flags don't ask to do it. */
		return false;
	}

	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL) {
		/*
		 * We've been asked to setup symmetric CoW, but there is no
		 * vm_object. Preflights should generally either check that
		 * object is not NULL before passing SETUP_COW or
		 * pass the VMO_ALLOCATE flag.
		 * VMO_ALLOCATE doesn't allocate objects if the entry's
		 * max_prot==VM_PROT_NONE as security hardening because that
		 * memory should theoretically never be used.
		 * Given that the memory won't actually be used and we have
		 * no object, we don't actually need to setup CoW.
		 */
		assert(flags & VMRL_VMO_ALLOCATE);
		assert3u(entry->max_protection, ==, VM_PROT_NONE);
		return false;
	}
	return true;
}


/*!
 * @abstract
 * Prepare an entry for the requested operation.
 *
 * @discussion
 * In order to respect the caller's wishes, entries might:
 * - need to be clipped,
 * - need to be resolved,
 * - cause pmap unnesting,
 * - cause copy of vm entries from a constant submap.
 *
 * This function handles these according to the caller's needs.
 *
 * This function may drop/reacquire the interlock.
 *
 * @param vml_ctx       the locking context.
 * @param entry         the entry to prepare, it must be exclusively locked.
 * @param addr_to_lock  the address the caller is interested in
 *                      (must be contained in the entry)
 * @param ilocked_out   on exit, whether the interlock is held
 */
static kern_return_t
__vmrl_entry_prepare_ilocked(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t                map,
	vmrl_flags_t            flags,
	vm_map_entry_t          entry,
	vm_map_address_t        addr_to_lock,
	bool                   *ilocked_out)
{
	lck_rw_type_t   mode = __vmrl_ilk_mode(flags);
	vm_map_offset_t end  = MIN(entry->vme_end, vml_ctx->vmlc_req_end);
	kern_return_t   kr   = KERN_SUCCESS;
	__assert_only bool did_symmetric_cow_setup = false;

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	/*
	 * Apply various operations/flags to the entry.
	 * 1) We pmap_unnest. This is because unnesting does clipping.
	 * That clipping must also be done before submap entry unnesting.
	 * 2) We clip if we want to do so for COW setup or share preparation.
	 * We do this now as we hold the interlock.
	 * 3) We allocate an object. This needs to happen now so that symmetric
	 * CoW setup can properly apply to all objects.
	 * 4) We setup symmetric CoW. This must happen before any later CoW
	 * resolution.
	 * 5) We do submap entry unnesting. This must happen after the
	 * pmap_unnest and before any CoW resolution as well. This may do further
	 * clipping than the pmap_unnest already did. It can also result in new
	 * CoW.
	 * 6/7) we do CoW resolution and preparing for share.
	 * 8) We do our final clip to the relevant range.
	 */

	if (vm_map_entry_needs_pmap_unnest(vml_ctx, entry, addr_to_lock)) {
		mode = __vmrl_ilk_convert_nospin(map, mode);
		vm_range_lock_pmap_unnest_and_clip(map, mode, flags,
		    entry, addr_to_lock, end);
	}

	if ((flags & _VMRL_SETUP_COW) &&
	    __vmrl_clip_needed(entry, addr_to_lock, end, flags,
	    VMRL_CLIP_COW_SETUP)) {
		mode = __vmrl_ilk_upgrade(map, mode);
		__vmrl_clip_ilocked(map, entry, addr_to_lock, end,
		    VMRL_CLIP_UNLOCK_SPLITS);
	}

	if (((flags & _VMRL_PREPARE_FOR_SHARE_WITH_UPL) &&
	    __vmrl_clip_needed(entry, addr_to_lock, end, flags,
	    VMRL_CLIP_PREPARE_FOR_SHARE))) {
		/*
		 * This recreates the old clipping behavior of vm_map_create_upl
		 * Clip entries if we would shadow to do our copy_strategy change,
		 * but not if the entry is already needs_copy or a submap.
		 */

		/* so that vm_map_lock_ctx_bounds(ctx, ...) works */
		vml_ctx->vmlc_vme = entry;
		if (!entry->needs_copy && !entry->is_sub_map &&
		    vm_map_should_shadow_to_change_copy_strategy(vml_ctx, entry, true)) {
			mode = __vmrl_ilk_upgrade(map, mode);
			__vmrl_clip_ilocked(map, entry, addr_to_lock, end,
			    VMRL_CLIP_UNLOCK_SPLITS);
		}
		vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
	}

	__vmrl_ilk_unlock(map, mode);

	if (vm_map_entry_needs_object(flags, entry)) {
		vm_map_entry_lock_allocate_object(entry, vml_ctx->vmlc_map->serial_id);
	}

	if (vm_map_entry_needs_symmetric_cow_setup(flags, entry)) {
		vm_map_entry_setup_symmetric_cow(map, entry);
		did_symmetric_cow_setup = true;
	}

	if (vm_map_entry_needs_submap_cow_resolved(flags, entry)) {
		kr = vm_map_entry_resolve_submap_cow(vml_ctx, map, entry, addr_to_lock);
		if (kr != KERN_SUCCESS) {
			/* If we couldn't unnest, just return out an error */
			*ilocked_out = false;
			return kr;
		}
	}

	if (vm_map_entry_needs_symmetric_cow_resolved(flags, entry)) {
		vm_map_entry_lock_resolve_symmetric_cow(map, entry);
	}

	if ((flags & _VMRL_PREPARE_FOR_SHARE_NOCLIP) ||
	    (flags & _VMRL_PREPARE_FOR_SHARE_WITH_UPL)) {
		bool share_with_upl = flags & _VMRL_PREPARE_FOR_SHARE_WITH_UPL;

		/*
		 * It doesn't make sense to both prepare for share and do
		 * symmetric cow setup, they're both preflight return codes
		 */
		RANGE_LOCK_ASSERT(!did_symmetric_cow_setup);

		/* so that vm_map_lock_ctx_bounds(ctx, ...) works */
		vml_ctx->vmlc_vme = entry;
		vm_map_entry_prepare_for_share(vml_ctx, entry, share_with_upl);
		vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
	}

	if (vmrl_is_exclusive(flags) &&
	    __vmrl_clip_needed(entry, addr_to_lock, end, flags,
	    VMRL_CLIP_TO_RANGE)) {
		__vmrl_ilk_lock_exclusive(map);
		__vmrl_clip_ilocked(map, entry, addr_to_lock, end,
		    VMRL_CLIP_UNLOCK_SPLITS);
		__vmrl_ilk_downgrade(map, __vmrl_ilk_mode(flags));
		*ilocked_out = true;
	} else {
		*ilocked_out = false;
	}

	return kr;
}

static kern_return_t
__vmrl_entry_lock_exclusive_ilocked(
	vm_map_t         map,
	lck_rw_type_t    map_held,
	vm_map_entry_t   entry,
	vm_map_address_t addr_to_lock,
	vmrl_flags_t     flags)
{
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(map));
	if (flags & VMRL_TRY_LOCK_ENTRY) {
		if (!vm_entry_try_lock_exclusive(entry)) {
			return VMRL_ERR_LOCK_ALREADY_HELD;
		}
		return KERN_SUCCESS;
	}
	return vm_entry_lock_exclusive(map, map_held, entry, addr_to_lock,
	           vmrl_wait_interrupt(flags));
}

static kern_return_t
__vmrl_entry_lock_shared_ilocked(
	vm_map_t         map,
	lck_rw_type_t    map_held,
	vm_map_entry_t   entry,
	vm_map_address_t addr_to_lock,
	vmrl_flags_t     flags)
{
	if (flags & VMRL_TRY_LOCK_ENTRY) {
		if (!vm_entry_try_lock_shared(entry)) {
			return VMRL_ERR_LOCK_ALREADY_HELD;
		}
		return KERN_SUCCESS;
	}
	return vm_entry_lock_shared(map, map_held, entry, addr_to_lock,
	           vmrl_wait_interrupt(flags));
}

/*!
 * Preflight the entry passed in, or relevant entries inside if it is a constant
 * submap.
 *
 * @param vml_ctx        the lock context
 * @param entry          the entry we just locked which we want to preflight
 * @param addr_to_lock   the address we are locking at
 * @param allow_actions  whether the preflight is allowed to return a
 *                       special preflight code asking to modify the entry
 */
static kern_return_t
__vmrl_run_entry_preflight(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        addr_to_lock,
	bool                    allow_actions)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_entry_t child_entry;

	if (!vml_ctx->vmlc_preflight) {
		/* no preflight to run, nothing to do */
		return KERN_SUCCESS;
	}
	if (!__vmrl_should_descend_in_constant_submap(vml_ctx, entry)) {
		/*
		 * Preflight this entry which we are going to return to the
		 * client. The preflight here may be allowed to return a special
		 * preflight value.
		 */
		kr = __vmrl_run_entry_preflight_internal(vml_ctx, entry, allow_actions);
		return kr;
	}

	/*
	 * The entry is a constant submap we will descend into.
	 * We want to preflight the entries within it, as they're the entries we
	 * will return to clients of the lock.
	 */
	assert(!vm_map_lock_ctx_is_descended(vml_ctx));

	child_entry = __vmrl_descend_in_constant_submap(vml_ctx,
	    entry, addr_to_lock);

	if (vmrl_is_atomic(vml_ctx)) {
		/*
		 * Atomic lock. We need to preflight all the
		 * entries within the submap now.
		 */
		while (child_entry->vme_start < vml_ctx->vmlc_req_end &&
		    !entry_is_map_end(vml_ctx->vmlc_map, child_entry)) {
			kr = __vmrl_run_entry_preflight_internal(
				vml_ctx, child_entry, false);
			if (kr != KERN_SUCCESS) {
				break;
			}
			child_entry = child_entry->vme_next;
		}
	} else {
		/*
		 * Streaming lock. We only need to preflight the first entry.
		 * Subsequent calls to stream_next() will call into this
		 * function and preflight later entries at that point.
		 */
		kr = __vmrl_run_entry_preflight_internal(vml_ctx, child_entry, false);
	}

	/* Ascend from the descension we did earlier. */
	__vmrl_ascend(vml_ctx);

	return kr;
}

/*!
 * @abstract
 * Locks the specified entry if it contains an address of interest.
 *
 * @discussion
 * This function is called with the interlock held,
 * and returns in @c ilocked_out whether it is still held.
 *
 * Even when @c *ilocked_out is true, the function might have slept
 * and dropped the interlock.
 *
 * On success the only guarantee is that the address the caller is interested
 * into falls into that entry. Other properties might have changed.
 *
 * @param vml_ctx       the locking context.
 * @param entry         the entry to try to lock.
 * @param addr_to_lock  the address the caller is interested into
 *                      (must be contained in the entry)
 * @param mode          how the map lock is currently being held.
 * @param skip_lock     whether the entry should actually be locked and prepared
 *                      or if that should be skipped
 * @param ilocked_out   out parameter that indicates whether the interlock is held
 *
 * @returns
 * - KERN_SUCCESS       the entry lock was acquired.
 *
 * - VMRL_ERR_RELOOKUP  the entry was modified or deleted concurrently,
 *                      and the caller must re-lookup the entry.
 *
 * - VMRL_ERR_ABORTED   the lock was not acquired due to the wait being aborted
 *
 * - VMRL_ERR_LOCK_ALREADY_HELD the lock was not acquired due to it already being held
 *
 * - other              any error returned by the preflight hook.
 *                      the entry lock was acquired.
 */
__attribute__((always_inline))
static kern_return_t
__vmrl_entry_lock_ilocked(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_entry_t          entry,
	vm_map_address_t        addr_to_lock,
	lck_rw_type_t           mode,
	bool                    skip_lock,
	bool                   *ilocked_out)
{
	vmrl_flags_t  flags   = __vmrl_flags(vml_ctx);
	vm_map_t      map     = vml_ctx->vmlc_map;
	bool          xlocked = false;
	bool          slocked = false;
	kern_return_t kr;

	RANGE_LOCK_ASSERT(!entry_is_map_end(map, entry));

retry_lock_entry:
	/*
	 * These lock calls may sleep and drop/retake the interlock
	 */

	if (skip_lock) {
		kr = KERN_SUCCESS;
		slocked = false;
		xlocked = false;
	} else if (vmrl_is_exclusive(flags)) {
retry_lock_entry_exclusive:
		/*
		 * If we need to unnest or resolve the entry,
		 * we must always take the exclusive lock,
		 * we will downgrade it before we return to the caller.
		 */
		kr = __vmrl_entry_lock_exclusive_ilocked(map, mode, entry,
		    addr_to_lock, flags);
		slocked = false;
		xlocked = (kr == KERN_SUCCESS);
	} else {
		kr = __vmrl_entry_lock_shared_ilocked(map, mode, entry,
		    addr_to_lock, flags);
		slocked = (kr == KERN_SUCCESS);
		xlocked = false;
	}

	if (kr != KERN_SUCCESS) {
		/* Callers will relookup */
		*ilocked_out = true;
		return kr;
	}

	/*
	 * In some cases we will need to upgrade a shared lock to exclusive to
	 * honor flags passed by the clients.
	 */
	if (slocked && (vm_map_entry_needs_symmetric_cow_resolved(flags, entry) ||
	    vm_map_entry_needs_pmap_unnest(vml_ctx, entry, addr_to_lock) ||
	    vm_map_entry_needs_submap_cow_resolved(flags, entry) ||
	    vm_map_entry_needs_object(flags, entry))) {
		if (!vm_entry_lock_try_shared_to_exclusive(entry)) {
			goto retry_lock_entry_exclusive;
		}
		slocked = false;
		xlocked = true;
	}

	kr = __vmrl_run_entry_preflight(vml_ctx, entry, addr_to_lock, !skip_lock);

	/*
	 * This value is returned by preflight if it determines
	 * that the entry needs to wait for unwire.
	 *
	 * The range lock should be exclusive to do this.
	 *
	 * We do not need to clip the entry, whoever will unwire
	 * it will do the clipping and invalidate our wait.
	 */
	if (kr == VMRL_ERR_WAIT_FOR_KUNWIRE) {
		RANGE_LOCK_ASSERT(!(flags & _VMRL_SINGLE_ENTRY));
		RANGE_LOCK_ASSERT(vmrl_is_exclusive(flags));

		kr = vm_entry_unlock_and_wait_for_kunwire(map, mode,
		    entry, addr_to_lock, vmrl_wait_interrupt(flags));

		if (kr == VMRL_ERR_ABORTED || kr == VMRL_ERR_RELOOKUP) {
			*ilocked_out = true;
			return kr;
		}

		RANGE_LOCK_ASSERT(kr == KERN_SUCCESS);
		goto retry_lock_entry;
	}

	/*
	 * This value is returned by preflight if it determines
	 * that symmetric COW needs to be setup
	 *
	 * We need an exclusive lock since we're going to be modifying the entry
	 * (setting needs_copy) and downgrading its pmap protection.
	 */
	if ((kr == VMRL_ERR_SETUP_SYMMETRIC_COW ||
	    kr == VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP ||
	    kr == VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP ||
	    kr == VMRL_ERR_PREPARE_FOR_SHARE_WITH_UPL) && !xlocked) {
		if (!vm_entry_lock_try_shared_to_exclusive(entry)) {
			goto retry_lock_entry_exclusive;
		}
		slocked = false;
		xlocked = true;
	}
	/*
	 * We now have the right mode (shared/exclusive) of lock. Transform any
	 * special preflight codes to KERN_SUCCESS and set the flags for prepare.
	 */
	if (kr == VMRL_ERR_SETUP_SYMMETRIC_COW) {
		flags |= _VMRL_SETUP_COW;
		kr = KERN_SUCCESS;
	} else if (kr == VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP) {
		flags |= _VMRL_SETUP_COW_NOCLIP;
		kr = KERN_SUCCESS;
	} else if (kr == VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP) {
		flags |= _VMRL_PREPARE_FOR_SHARE_NOCLIP;
		kr = KERN_SUCCESS;
	} else if (kr == VMRL_ERR_PREPARE_FOR_SHARE_WITH_UPL) {
		flags |= _VMRL_PREPARE_FOR_SHARE_WITH_UPL;
		kr = KERN_SUCCESS;
	}

	if (xlocked && kr == KERN_SUCCESS) {
		kr = __vmrl_entry_prepare_ilocked(vml_ctx, map, flags, entry,
		    addr_to_lock, ilocked_out);
	} else {
		if (kr == VMRL_ERR_SKIP_PREPARE) {
			kr = KERN_SUCCESS;
		}
		*ilocked_out = true;
	}

	if (slocked && (kr == KERN_SUCCESS)) {
		assert(!vm_map_entry_needs_symmetric_cow_resolved(flags, entry));
		assert(!vm_map_entry_needs_pmap_unnest(vml_ctx, entry, addr_to_lock));
		assert(!vm_map_entry_needs_submap_cow_resolved(flags, entry));
		assert(!vm_map_entry_needs_object(flags, entry));
	}

	if (xlocked && vmrl_is_shared(flags)) {
		vm_entry_lock_exclusive_to_shared(entry);
	}

	return kr;
}

/*!
 * @abstract
 * Core implementation of the map range atomic lock.
 *
 * @discussion
 * On success, the __vmlc_atomic structure of the context is filled:
 * - first_entry corresponds to the first locked entry,
 * - last_entry corresponds to the last locked entry.
 */
__attribute__((always_inline))
static kern_return_t
__vmrl_atomic_lock_and_iunlock(vm_map_lock_ctx_t vml_ctx)
{
	vmrl_flags_t      flags = __vmrl_flags(vml_ctx);
	lck_rw_type_t     mode  = __vmrl_ilk_atomic_mode(flags);
	vm_map_t          map   = vml_ctx->vmlc_map;
	vm_map_address_t  start = vml_ctx->vmlc_req_start;
	vm_map_address_t  cur   = start;
	vm_map_address_t  end   = vml_ctx->vmlc_req_end;

	vm_map_entry_t    first_entry = VM_MAP_ENTRY_NULL;
	vm_map_entry_t    last_entry  = VM_MAP_ENTRY_NULL;
	bool              ilocked     = true;
	vm_map_entry_t    entry;
	kern_return_t     kr;

	/*
	 * Lookup the first entry at "start", or the one after, and descend in
	 * transparent submaps once.
	 */
	if (vm_map_lookup_or_next(map, start, &entry) &&
	    vm_map_entry_is_transparent_submap(entry) &&
	    __vmrl_descend_in_transparent_submap(vml_ctx, entry, start)) {
		__vmrl_ilk_unlock(map, mode);
		map = vml_ctx->vmlc_map;
		__vmrl_ilk_lock(map, mode);
		vm_map_lookup_or_next(map, start, &entry);
	}

	while (cur < end) {
		/*
		 * Step 1: handle operations crossing guard object slots or
		 * inside unallocated slots.
		 */
		if (!entry_is_map_end(map, entry) &&
		    VME_IN_CHUNK(entry) &&
		    vmgo_chunk_start(vms_chunk(entry->vme_chunk)) < end &&
		    !vm_guard_object_check_op_range(entry, start, end)) {
			kr = KERN_INVALID_GUARD_OBJECT_SLOT;
			release_assert(!vmrl_is_kernel_pmap(flags));
			break;
		}
		/*
		 * Step 2: detect gaps.
		 */
		if (entry_is_map_end(map, entry) || cur < entry->vme_start) {
			vm_map_entry_t sentinel;

			/*
			 * If our hole is in a slot, there are two cases:
			 * 1. The next entry is in a slot that extends back
			 *    into this hole (covered by the previous check).
			 * 2. The previous entry is in a slot that extends into
			 *    this hole. We need to account for this.
			 *
			 * There is no third case due to the fact that there
			 * are no completely empty guard object chunks
			 * observable under the interlock.
			 */
			if (!entry_is_map_end(map, VME_PREV(entry)) &&
			    VME_IN_CHUNK(VME_PREV(entry)) &&
			    vmgo_chunk_end(vms_chunk(VME_PREV(entry)->vme_chunk)) > start &&
			    !vm_guard_object_check_op_range(VME_PREV(entry), start, end)) {
				kr = KERN_INVALID_GUARD_OBJECT_SLOT;
				release_assert(!vmrl_is_kernel_pmap(flags));
				break;
			}

			if (vmrl_is_kernel_pmap(flags)) {
				__vm_map_gap_panic(vml_ctx, cur);
			}

			if (vmrl_mode(flags) != VMRL_ATOMIC_ALLOW_HOLES) {
				kr = KERN_INVALID_ADDRESS;
				break;
			}

			/*
			 * If the caller wants sentinels made, oblige.
			 *
			 * We will still pass it to the preflight hooks, which
			 * gives clients the opportunity to have custom behavior
			 * for gaps.
			 */
			kr = vm_map_make_sentinel_ilocked(vml_ctx, map, entry, cur, end, &sentinel);

			entry = sentinel;
		} else {
			/*
			 * Step 3: detect operation crossing atomic boundaries.
			 */
			if (vm_map_entry_is_transparent_submap(entry)) {
				RANGE_LOCK_ASSERT(vmrl_is_kernel_pmap(flags));
				__vm_map_transparent_submap_panic(vml_ctx, entry);
			}
			if (entry->vme_atomic &&
			    (start < entry->vme_start || entry->vme_end < end)) {
				RANGE_LOCK_ASSERT(vmrl_is_kernel_pmap(flags));
				__vm_map_atomic_panic(vml_ctx, entry);
			}

			/*
			 * Step 4: Lock the entry
			 */
			kr = __vmrl_entry_lock_ilocked(vml_ctx, entry, cur,
			    mode, false, &ilocked);

			if (kr == VMRL_ERR_RELOOKUP) {
				RANGE_LOCK_ASSERT(ilocked);
				if (last_entry == VM_MAP_ENTRY_NULL) {
					vm_map_lookup_or_next(map, cur, &entry);
				} else {
					entry = last_entry->vme_next;
				}
				continue;
			}
		}

		if (kr != VMRL_ERR_ABORTED && kr != VMRL_ERR_LOCK_ALREADY_HELD) {
			last_entry = entry;
			cur = last_entry->vme_end;
			vml_ctx->__vmlc_atomic.locked_range_end = cur;
			if (first_entry == VM_MAP_ENTRY_NULL) {
				first_entry = last_entry;
				vml_ctx->__vmlc_atomic.locked_range_start = first_entry->vme_start;
			}
		}

		if (cur >= end || kr != KERN_SUCCESS) {
			break;
		}

		if (!ilocked) {
			__vmrl_ilk_lock(map, mode);
			ilocked = true;
		}
		entry = last_entry->vme_next;
	}

	if (kr == KERN_SUCCESS) {
		vml_ctx->__vmlc_atomic.first_entry = first_entry;
	} else if (first_entry) {
		if (!ilocked) {
			__vmrl_ilk_lock(map, mode);
		}
		__vmrl_unlock_range_ilocked(vml_ctx, flags, first_entry, cur);
		ilocked = true;
	}

	if (__improbable(kr == VMRL_ERR_ABORTED)) {
		kr = KERN_ABORTED;
	}

	if (ilocked) {
		__vmrl_ilk_unlock(map, mode);
	}
	return kr;
}


/*!
 * @abstract
 * Core implementation of the map lock streaming lock.
 *
 * @discussion
 * This function does the following:
 * 1) Unlock the previous entry.
 * 2) try to ascend/descend submaps.
 * 3) Try to lock the next entry.
 *
 * On success, the __vmlc_streaming structure of the context is filled:
 * - next_address contains the end of the currently locked entry.
 *
 * On success, the currently locked entry is set in vmlc_vme.
 *
 * @returns
 * - KERN_SUCCESS       if an entry was found and locked
 * - KERN_INVALID_ADDRESS
 *                      if no entry was found at the first round,
 *                      or there was a gap and VMRL_STREAM_NO_HOLES was passed.
 * - other              any error returned by __vmrl_entry_prepare_ilocked()
 */
__attribute__((always_inline))
static kern_return_t
__vmrl_stream_next_and_iunlock_internal(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_t         map         = vml_ctx->vmlc_map;
	vmrl_flags_t     flags       = __vmrl_flags(vml_ctx);
	vm_map_address_t end         = vml_ctx->vmlc_req_end;
	vm_map_entry_t   prev_entry  = vml_ctx->vmlc_vme;
	bool             ilocked, skip_lock;
	vm_map_entry_t   next_entry;
	kern_return_t    kr;

	/*
	 * vml_ctx->__vmlc_streaming.last_processed_addr points to the end of
	 * the range we've already processed, or the start of the overall range
	 * if we haven't locked anything yet.
	 *
	 * next_address is the address we want to lock next. Generally, these
	 * are the same, but may be different in submap ascension or hole
	 * cases.
	 */
	vm_map_address_t next_address = vml_ctx->__vmlc_streaming.last_processed_addr;

restart:
	RANGE_LOCK_ASSERT(current_thread()->vm_map_lock_ctx_held == NULL);
	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_SHARED_SPIN);
	ilocked = true;

	/*
	 *	Step 1: lookup or get to the next entry.
	 *
	 *	"prev_entry" if set is locked or stable.
	 */
	if (prev_entry == VM_MAP_ENTRY_NULL) {
		vm_map_lookup_or_next(map, next_address, &next_entry);
	} else {
		next_entry = prev_entry->vme_next;

		/*
		 * We don't lock entries in a constant submap, so don't unlock.
		 */
		if (!vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
			/*
			 * Try to simplify with our neighbors. Notably these
			 * calls may drop/retake the interlock.
			 */
			vmrl_simplify_entry_with_unlocked_prev(map,
			    LCK_RW_TYPE_SHARED_SPIN, prev_entry, flags);
			prev_entry = vmrl_simplify_entry_with_unlocked_next(map,
			    LCK_RW_TYPE_SHARED_SPIN, prev_entry, flags);

			/*
			 * Re-lookup the next entry because the locks may have dropped.
			 */
			if (prev_entry->vme_end > next_address) {
				/*
				 * If we simplified forward prev_entry is the one we want.
				 */
				next_entry = prev_entry;
			} else {
				next_entry = prev_entry->vme_next;
			}

			__vmrl_unlock_entry(map, prev_entry, flags);
		}

		prev_entry = VM_MAP_ENTRY_NULL; /* Already unlocked so no longer valid */
	}

	/*
	 *	Step 2: handle out of bounds entries.
	 *
	 *      Check the next entry is valid, within the requested range
	 *      !(end <= next_entry->vme_start), and the next address is within
	 *      the requested range !(end <= next_address)
	 *
	 *	If we are descended, ascend, else we're done.
	 */
	if (entry_is_map_end(map, next_entry) ||
	    end <= next_address ||
	    end <= next_entry->vme_start) {
		if (vm_map_lock_ctx_is_descended(vml_ctx)) {
			if (!vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
				__vmrl_ilk_unlock_shared_spin(vml_ctx->vmlc_map);
			}
			map        = __vmrl_ascend(vml_ctx);
			end        = vml_ctx->vmlc_req_end;
			prev_entry = vml_ctx->vmlc_vme;
			/*
			 * If we ascended prior to the end of a transparent
			 * submap, __vmlc_streaming.last_processed_addr points
			 * to the end of the last entry within the submap that
			 * we actually locked.
			 *
			 * However, we don't want to re-descend, so we should
			 * make our next_address variable point to the end of
			 * the top-level submap entry.
			 */
			next_address = prev_entry->vme_end;
			__vmrl_ilk_lock_shared_spin(map);
			goto restart;
		}

		if (vml_ctx->__vmlc_first) {
			kr = KERN_INVALID_ADDRESS;
		} else if (next_address < vml_ctx->vmlc_req_end &&
		    (flags & _VMRL_NO_HOLES)) {
			kr = KERN_INVALID_ADDRESS;
		} else {
			kr = KERN_SUCCESS;
		}
		goto out_abort;
	}

	/*
	 * If next_address is before the next entry, we want to look ahead to
	 * the next entry. It's also possible that next_address is after the
	 * beginning of the next entry, if we dropped our lock on the previous
	 * entry.
	 */
	next_address = MAX(next_address, next_entry->vme_start);

	RANGE_LOCK_ASSERT(next_address >= next_entry->vme_start);
	RANGE_LOCK_ASSERT(next_address < next_entry->vme_end);

	if (flags & _VMRL_NO_HOLES) {
		/*
		 * We've potentially advanced next_address;
		 * if so, we have to handle any holes appropriately.
		 */
		if (vml_ctx->__vmlc_streaming.last_processed_addr < next_entry->vme_start) {
			kr = KERN_INVALID_ADDRESS;
			goto out_abort;
		}

		if (VME_IN_CHUNK(next_entry) &&
		    !vm_guard_object_check_op_range(next_entry,
		    vml_ctx->__original_req_start, end)) {
			kr = KERN_INVALID_GUARD_OBJECT_SLOT;
			release_assert(!vmrl_is_kernel_pmap(flags));
			goto out_abort;
		}
	}

	/*
	 *	Step 3: handle transparent submaps.
	 *
	 *	Entries pointing to transparent submaps are all permanent and atomic.
	 *	Those entries are immutable (excluding the next/prev/rbtree pointers).
	 *	So we do not need to lock entries pointing to transparent submaps.
	 *
	 *	Just descend, and restart iteration.
	 */
	if (vm_map_entry_is_transparent_submap(next_entry) &&
	    __vmrl_descend_in_transparent_submap(
		    vml_ctx, next_entry, next_address)) {
		__vmrl_ilk_unlock_shared_spin(map);
		map = vml_ctx->vmlc_map;
		end = vml_ctx->vmlc_req_end;
		__vmrl_ilk_lock_shared_spin(map);
		goto restart;
	}

	/*
	 *	Step 4: validate the entry we found.
	 *
	 *	If we're not in a constant submap, we need to lock
	 *	and give a chance to preflight hooks to skip/reject the entry.
	 */

	skip_lock = vm_map_lock_ctx_in_constant_submap(vml_ctx) ||
	    vm_map_entry_is_transparent_submap(next_entry);

	kr = __vmrl_entry_lock_ilocked(vml_ctx, next_entry, next_address,
	    LCK_RW_TYPE_SHARED_SPIN, skip_lock, &ilocked);

	if (kr == VMRL_ERR_RELOOKUP) {
		RANGE_LOCK_ASSERT(ilocked);
		/*
		 * We want to restart our relookup from the last place we
		 * successfully locked, as new entries may have appeared since
		 * then.
		 */
		next_address = vml_ctx->__vmlc_streaming.last_processed_addr;
		goto restart;
	}

	/*
	 *	Step 5: we found an entry and could lock it, return it.
	 *
	 *	If the entry is a constant submap, we need to descend.
	 *	We don't need any locks and we are guaranteed constant
	 *	submaps have no gaps, so there is an entry at this address.
	 */
	if (kr == KERN_SUCCESS) {
		if (ilocked && !vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
			__vmrl_ilk_unlock_shared_spin(map);
		}
		__vmrl_context_set_vme(vml_ctx, next_entry, next_address, VMRL_STREAM);
		return kr;
	}

	/*
	 *	We might have returned with an entry locked, but with an error.
	 *	Unlock the entry to respect invariants.
	 */
	if (__improbable(kr == VMRL_ERR_ABORTED)) {
		kr = KERN_ABORTED;
		/* nothing to do, didn't lock the entry */
	} else if (kr == VMRL_ERR_LOCK_ALREADY_HELD) {
		/* nothing to do, didn't lock the entry */
	} else if (vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
		/* in a constant submap, didn't lock next_entry. */
	} else {
		__vmrl_unlock_entry(map, next_entry, flags);
	}

	/*
	 *	For streaming locks, also do not return errors at
	 *	lock() time, defer it to the first "next()" call,
	 *	the only error vm_map_range_*_lock() for streaming should
	 *	return, is KERN_INVALID_ADDRESS for an empty set of entries.
	 */
	if (vml_ctx->__vmlc_first) {
		vml_ctx->__vmlc_streaming.first_error = kr;
		kr = KERN_SUCCESS;
	}

out_abort:
	/*
	 *	At this point, we have no entry locks and are giving up on
	 *	locking an entry. That could be for two reasons:
	 *	1) an error was encountered (kr is some error value).
	 *	2) a try lock failed.
	 *	Unlock the ilock, unlock any parent entry we may have locked,
	 *	and return out.
	 *
	 */
	if (ilocked && !vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
		__vmrl_ilk_unlock_shared_spin(map);
	}
	ilocked = false;

	if (vm_map_lock_ctx_is_descended(vml_ctx)) {
		map = __vmrl_ascend(vml_ctx);
		__vmrl_unlock_entry(map, vml_ctx->vmlc_vme, flags);
	}

	RANGE_LOCK_ASSERT(!ilocked && !vm_map_lock_ctx_is_descended(vml_ctx));
	vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
	return kr;
}

__attribute__((always_inline))
static kern_return_t
__vmrl_stream_next_and_iunlock(vm_map_lock_ctx_t vml_ctx)
{
	kern_return_t kr;

	/*
	 * We can unlock entries in __vmrl_stream_next_and_iunlock_internal
	 * We need to have no stackshot context then, so we temporarily unregister it and
	 * re-register it if we actually succeeded to lock something.
	 */
	__vmrl_context_unregister_in_cur_thread();

	kr = __vmrl_stream_next_and_iunlock_internal(vml_ctx);

	if (kr == KERN_SUCCESS) {
		__vmrl_context_register_in_cur_thread(vml_ctx);
	}

	return kr;
}

__attribute__((noinline))
static kern_return_t
__vmrl_lock_streaming(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_flags_t            flags)
{
	kern_return_t kr;

	kr = __vmrl_context_init(vml_ctx, map, start, end, flags);

	if (__improbable(kr != KERN_SUCCESS)) {
		__vmrl_ilk_unlock_shared_spin(map);
		return kr;
	}

	return __vmrl_stream_next_and_iunlock(vml_ctx);
}

__attribute__((noinline))
static kern_return_t
__vmrl_lock_atomic(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_flags_t            flags)
{
	kern_return_t kr;

	kr = __vmrl_context_init(vml_ctx, map, start, end, flags);

	if (__improbable(kr != KERN_SUCCESS)) {
		__vmrl_ilk_unlock(map, __vmrl_ilk_atomic_mode(flags));
		return kr;
	}

	return __vmrl_atomic_lock_and_iunlock(vml_ctx);
}

__attribute__((always_inline))
static kern_return_t
__vmrl_lock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t        * const orig_map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_flags_t            flags)
{
	lck_rw_type_t mode = __vmrl_ilk_mode(flags);
	kern_return_t kr;
	vm_map_t map = *orig_map;

	/*
	 * We don't support range-locking a sealed map, as you're not permitted
	 * to lock those entries, and we always lock entries in the original map.
	 */
	RANGE_LOCK_ASSERT(!vm_map_is_sealed(*orig_map));

	/* placeholder annotation to enable analysis, remove at rdar://143409845 ([Mach VM Remodel] Update VM Lock Perf work for range locking)*/
	vmlp_range_event(map, 0x0, 0x4000);

	if (flags & VMRL_ILK_LOCKED) {
		__vmrl_ilk_downgrade(map, mode);
	} else {
		__vmrl_ilk_lock(map, mode);
	}

	if (vmrl_is_streaming(flags)) {
		kr = __vmrl_lock_streaming(vml_ctx, map, start, end, flags);
	} else {
		kr = __vmrl_lock_atomic(vml_ctx, map, start, end, flags);
	}

	if (__probable(kr == KERN_SUCCESS)) {
		assert(orig_map != &kernel_map);
		*orig_map = BAD_MAP_VALUE;
	} else {
		/* undo the registration done in __vmrl_lock_X() */
		__vmrl_context_unregister_in_cur_thread();
		__vmrl_context_clear_unsafe(vml_ctx);
	}
	return kr;
}

__attribute__((always_inline))
kern_return_t
vm_map_range_ex_lock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_ex_flags_t         flags)
{
	RANGE_LOCK_ASSERT(vmrl_is_exclusive(flags));

	return __vmrl_lock(vml_ctx, map, start, end, __vmrl_flags(flags));
}

__attribute__((always_inline))
kern_return_t
vm_map_range_sh_lock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_sh_flags_t         flags)
{
	RANGE_LOCK_ASSERT(vmrl_is_shared(flags));

	return __vmrl_lock(vml_ctx, map, start, end, __vmrl_flags(flags));
}


#pragma mark range iteration

static vm_map_entry_t
__vmrl_atomic_next(vm_map_lock_ctx_t vml_ctx, bool peek)
{
	struct vm_map_lock_ctx saved_ctx;
	vm_map_t               map   = vml_ctx->vmlc_map;
	vm_map_entry_t         prev  = vml_ctx->vmlc_vme;
	vm_map_entry_t         entry = VM_MAP_ENTRY_NULL;
	vm_map_address_t       addr  = 0;

	RANGE_LOCK_ASSERT(vmrl_is_atomic(vml_ctx));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);

	if (peek) {
		saved_ctx = *vml_ctx;
	}

	if (prev == VM_MAP_ENTRY_NULL) {
		RANGE_LOCK_ASSERT(vml_ctx->__vmlc_first);
		vml_ctx->__vmlc_first = false;
		entry = vml_ctx->__vmlc_atomic.first_entry;
		addr  = vml_ctx->vmlc_req_start;
		RANGE_LOCK_ASSERT(entry != VM_MAP_ENTRY_NULL || peek); /* Allow peeking into an empty context. */
	} else {
		/* If we're in a constant submap, check if we're done */
		if (vm_map_lock_ctx_in_constant_submap(vml_ctx) &&
		    prev->vme_end >= vml_ctx->vmlc_req_end) {
			map  = __vmrl_ascend(vml_ctx);
			prev = vml_ctx->vmlc_vme;
		}

		/*
		 * Note: accessing the next pointer usually requires the interlock
		 * However as we have a range locked in non-streaming mode,
		 * stability for entries in that range is guaranteed.
		 *
		 * That means so long as our entry is not the last entry we
		 * can follow the next pointer. An entry is the last one
		 * if the end of that entry is >= the end requested
		 */
		if (prev->vme_end >= vml_ctx->vmlc_req_end) {
			vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
			return VM_MAP_ENTRY_NULL;
		}
		entry = prev->vme_next;
		addr  = prev->vme_end;
	}

	if (peek) {
		/*
		 * Peeking shouldn't have side effects, so we restore the saved context.
		 */
		*vml_ctx = saved_ctx;
		return entry;
	}

	return __vmrl_context_set_vme(vml_ctx, entry, addr, VMRL_ATOMIC);
}

__attribute__((always_inline))
vm_map_entry_t
vm_map_range_atomic_next(vm_map_lock_ctx_t vml_ctx)
{
	return __vmrl_atomic_next(vml_ctx, false);
}

__attribute__((always_inline))
vm_map_entry_t
vm_map_range_atomic_peek(vm_map_lock_ctx_t vml_ctx)
{
	return __vmrl_atomic_next(vml_ctx, true);
}

vm_map_entry_t
vm_map_range_ex_atomic_pop(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_entry_t entry;

	RANGE_LOCK_ASSERT(vmrl_is_atomic(vml_ctx));
	RANGE_LOCK_ASSERT(vmrl_is_exclusive(vml_ctx));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);
	RANGE_LOCK_ASSERT(!(__vmrl_flags(vml_ctx) & VMRL_DESCEND_INTO_CONSTANT));
	RANGE_LOCK_ASSERT(!(__vmrl_flags(vml_ctx) & VMRL_SIMPLIFY));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_first);
	RANGE_LOCK_ASSERT(vml_ctx->vmlc_vme == VM_MAP_ENTRY_NULL);

	entry = vml_ctx->__vmlc_atomic.first_entry;
	if (entry != VM_MAP_ENTRY_NULL) {
		/* see vm_map_lock_ctx_atomic_next() */
		if (entry->vme_end < vml_ctx->vmlc_req_end) {
			vml_ctx->__vmlc_atomic.first_entry = entry->vme_next;
		} else {
			vml_ctx->__vmlc_atomic.first_entry = VM_MAP_ENTRY_NULL;
		}
	}

	return entry;
}

void
vm_map_range_atomic_reset(vm_map_lock_ctx_t vml_ctx)
{
	RANGE_LOCK_ASSERT(vmrl_is_atomic(vml_ctx));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);

	if (vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
		__vmrl_ascend(vml_ctx);
	}

	vml_ctx->__vmlc_first = true;
	vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
}

static vm_map_entry_t
vm_map_range_stream_next_internal(
	vm_map_lock_ctx_t       vml_ctx,
	kern_return_t          *kr_out)
{
	kern_return_t kr;

	RANGE_LOCK_ASSERT(vmrl_is_streaming(vml_ctx));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);

	if (vml_ctx->__vmlc_first) {
		kr = vml_ctx->__vmlc_streaming.first_error;
		vml_ctx->__vmlc_first = false;
		vml_ctx->__vmlc_streaming.first_error = KERN_SUCCESS;
	} else {
		if (!vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
			__vmrl_ilk_lock_shared_spin(vml_ctx->vmlc_map);
		}
		kr = __vmrl_stream_next_and_iunlock(vml_ctx);
	}
	if (kr_out) {
		*kr_out = kr;
	} else if (kr != KERN_SUCCESS) {
		__vm_map_range_stream_panic(vml_ctx, kr);
	}

	return vml_ctx->vmlc_vme;
}

vm_map_entry_t
vm_map_range_stream_next_with_error(vm_map_lock_ctx_t vml_ctx, kern_return_t *kr_out)
{
	return vm_map_range_stream_next_internal(vml_ctx, kr_out);
}

vm_map_entry_t
vm_map_range_stream_next(vm_map_lock_ctx_t vml_ctx)
{
	return vm_map_range_stream_next_internal(vml_ctx, NULL);
}

static void
__vmrl_pop_curr(vm_map_lock_ctx_t vml_ctx)
{
	RANGE_LOCK_ASSERT(vmrl_is_streaming(vml_ctx));
	/*
	 * pop() APIs are used to make modifications to the entry without confusing the range lock.
	 * Shared lockers should not be modifying their entries.
	 */
	RANGE_LOCK_ASSERT(vmrl_is_exclusive(vml_ctx));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);
	RANGE_LOCK_ASSERT(!(__vmrl_flags(vml_ctx) & VMRL_SIMPLIFY)); /* Not handled today. */
	/*
	 * Clear vmlc_vme so that the next call to
	 * vm_map_range_stream_next_with_error (which calls into
	 * __vmrl_stream_next_and_iunlock) does not unlock the entry we return.
	 */
	RANGE_LOCK_ASSERT(vml_ctx->vmlc_vme != VM_MAP_ENTRY_NULL);
	vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
}

vm_map_entry_t
vm_map_range_ex_stream_pop_with_error(vm_map_lock_ctx_t vml_ctx, kern_return_t *kr_out)
{
	vm_map_entry_t entry;

	entry = vm_map_range_stream_next_with_error(vml_ctx, kr_out);
	if (entry) {
		RANGE_LOCK_ASSERT((*kr_out) == KERN_SUCCESS);
		__vmrl_pop_curr(vml_ctx);
	}

	return entry;
}

vm_map_entry_t
vm_map_range_ex_stream_pop(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_entry_t entry;
	kern_return_t kr;

	entry = vm_map_range_ex_stream_pop_with_error(vml_ctx, &kr);
	if (kr != KERN_SUCCESS) {
		__vm_map_range_stream_panic(vml_ctx, kr);
	}

	return entry;
}

void
vm_map_found_entry_ex_pop_curr(vm_map_find_lock_ctx_t vml_ctx)
{
	__vmrl_pop_curr(vml_ctx);
}

static void
vm_map_range_stream_drop_internal(vm_map_lock_ctx_t vml_ctx, bool do_not_advance)
{
	vmrl_flags_t   flags = __vmrl_flags(vml_ctx);
	vm_map_entry_t entry;
	vm_map_t       map = vml_ctx->vmlc_map;

	RANGE_LOCK_ASSERT(vmrl_is_streaming(flags));
	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);
	RANGE_LOCK_ASSERT(vml_ctx->vmlc_vme != VM_MAP_ENTRY_NULL); /* can't drop the same entry twice */
	__vmrl_context_unregister_in_cur_thread();

	entry = vml_ctx->vmlc_vme;
	RANGE_LOCK_ASSERT(MIN(entry->vme_end, vml_ctx->vmlc_req_end)
	    == vml_ctx->__vmlc_streaming.last_processed_addr);

	if (do_not_advance) {
		/*
		 * Set next_address back to the start of our entry (within the
		 * range we care about).
		 * We advanced the cursor in __vmrl_context_set_vme, but it turns
		 * out we don't really want the cursor advanced.
		 */
		vm_map_address_t start;
		vm_map_lock_ctx_bounds(vml_ctx, &start, NULL, NULL);
		vml_ctx->__vmlc_streaming.last_processed_addr = start;
	}

	if (!vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
		/*
		 * We don't try to simplify because simplification will
		 * end up trying to take the object lock which we may hold.
		 */

		/*
		 * Not in a constant submap.
		 * Unlock the entry we're looking at without ascension.
		 * No interlock is needed.
		 */
		__vmrl_unlock_entry(map, entry, flags);
	} else {
		/*
		 * We're in a constant submap.
		 * We want to drop our entry lock, but we lock the parent entry
		 * in constant submaps.
		 * Ascend before unlocking the parent entry. stream_next will
		 * then descend again when we ask for the next entry.
		 */
		map = __vmrl_ascend(vml_ctx);

		entry = vml_ctx->vmlc_vme;
		__vmrl_unlock_entry(map, entry, flags);
	}

	vml_ctx->vmlc_vme = VM_MAP_ENTRY_NULL;
}

void
vm_map_range_stream_drop(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_range_stream_drop_internal(vml_ctx, false);
}

void
vm_map_range_stream_drop_without_advance(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_range_stream_drop_internal(vml_ctx, true);
}

vm_map_entry_t
vm_map_range_next_with_error(vm_map_lock_ctx_t vml_ctx, kern_return_t *kr_out)
{
	if (vmrl_is_streaming(vml_ctx)) {
		return vm_map_range_stream_next_with_error(vml_ctx, kr_out);
	}
	*kr_out = KERN_SUCCESS;
	return vm_map_range_atomic_next(vml_ctx);
}

vm_map_entry_t
vm_map_range_next(vm_map_lock_ctx_t vml_ctx)
{
	if (vmrl_is_streaming(vml_ctx)) {
		return vm_map_range_stream_next(vml_ctx);
	}
	return vm_map_range_atomic_next(vml_ctx);
}

vm_map_entry_t
vm_map_range_ex_pop_with_error(vm_map_lock_ctx_t vml_ctx, kern_return_t *kr_out)
{
	if (vmrl_is_streaming(vml_ctx)) {
		return vm_map_range_ex_stream_pop_with_error(vml_ctx, kr_out);
	}
	*kr_out = KERN_SUCCESS;
	return vm_map_range_ex_atomic_pop(vml_ctx);
}

vm_map_entry_t
vm_map_range_ex_pop(vm_map_lock_ctx_t vml_ctx)
{
	if (vmrl_is_streaming(vml_ctx)) {
		return vm_map_range_ex_stream_pop(vml_ctx);
	}
	return vm_map_range_ex_atomic_pop(vml_ctx);
}


#pragma mark range unlock

/*!
 * @abstract
 * Backend for the higher level vm_map_range_{ex,sh}_unlock functions.
 */
__attribute__((noinline))
static void
__vmrl_unlock_atomic(vm_map_lock_ctx_t vml_ctx)
{
	vm_map_t     map   = vml_ctx->vmlc_map;
	vmrl_flags_t flags = __vmrl_flags(vml_ctx);

	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);

	if (vml_ctx->__vmlc_atomic.first_entry) {
		vm_map_address_t end = vml_ctx->vmlc_req_end;
		vm_map_entry_t   entry;

		__vmrl_ilk_lock_exclusive(map);

		if (vmrl_is_exclusive(vml_ctx)) {
			__vmrl_simplify_atomic_range_ilocked(vml_ctx);
		}

		entry = vml_ctx->__vmlc_atomic.first_entry;
		__vmrl_unlock_range_ilocked(vml_ctx, flags, entry, end);

		__vmrl_ilk_unlock_exclusive(map);
	}
}

__attribute__((always_inline))
static void
__vmrl_unlock(
	vm_map_lock_ctx_t       vml_ctx,
	vmrl_flags_t            flags,
	vm_map_t * const        map_out)
{
	vm_map_t map;

	RANGE_LOCK_ASSERT(vml_ctx->__vmlc_locked);

	/* clearing the ctx from current_thread() needs to happen before we unlock anything
	 * since the unlock flow may temporarily have the ctx in an invalid state.
	 * For instance the entry pointed to by ctx->vmlc_vme can be unlocked and freed by another thread */
	__vmrl_context_unregister_in_cur_thread();

	if (vm_map_lock_ctx_in_constant_submap(vml_ctx)) {
		map = __vmrl_ascend(vml_ctx);
	} else {
		map = vml_ctx->vmlc_map;
	}

	if (vmrl_is_streaming(flags)) {
		if (vml_ctx->vmlc_vme) {
			__vmrl_unlock_entry(map, vml_ctx->vmlc_vme, flags);
		}
	} else {
		__vmrl_unlock_atomic(vml_ctx);
	}

	if (map_out) {
		/* Check it's the same map that was passed in. */
		assert(*map_out == BAD_MAP_VALUE);

		/* Reset the map to the original one */
		*map_out = vml_ctx->__original_map;
	}
	__vmrl_context_clear_unsafe(vml_ctx);
}

__attribute__((always_inline))
void
vm_map_range_ex_unlock(vm_map_lock_ctx_t vml_ctx, vm_map_t * const map)
{
	vmrl_flags_t flags = __vmrl_flags(vml_ctx);

	RANGE_LOCK_ASSERT(vmrl_is_exclusive(flags));

	/* help the optimizer inline __vmrl_unlock() properly */
	__builtin_assume(vmrl_is_exclusive(flags));
	__vmrl_unlock(vml_ctx, flags, map);
}

__attribute__((always_inline))
void
vm_map_range_sh_unlock(vm_map_lock_ctx_t vml_ctx, vm_map_t * const map)
{
	vmrl_flags_t flags = __vmrl_flags(vml_ctx);

	RANGE_LOCK_ASSERT(vmrl_is_shared(flags));

	/* help the optimizer inline __vmrl_unlock() properly */
	__builtin_assume(vmrl_is_shared(flags));
	__vmrl_unlock(vml_ctx, flags, map);
}

__attribute__((noinline))
void
vm_map_range_ex_to_sh(vm_map_lock_ctx_t vml_ctx)
{
	vmrl_flags_t     flags       = __vmrl_flags(vml_ctx);
	vm_map_t         map         = vml_ctx->vmlc_map;
	vm_map_entry_t   first_entry = vml_ctx->__vmlc_atomic.first_entry;
	vm_map_offset_t  end         = vml_ctx->vmlc_req_end;

	RANGE_LOCK_ASSERT(vmrl_is_exclusive(flags));
	RANGE_LOCK_ASSERT(vmrl_is_atomic(flags));
	RANGE_LOCK_ASSERT(!(flags & VMRL_DESCEND_INTO_CONSTANT));

	RANGE_LOCK_ASSERT(!entry_is_map_end(vml_ctx->vmlc_map, first_entry));
	RANGE_LOCK_ASSERT(first_entry != VM_MAP_ENTRY_NULL);
	RANGE_LOCK_ASSERT(first_entry->vme_start == vml_ctx->__original_req_start);

	/*
	 * It's important to not downgrade a range to or from streaming mode.
	 * This is because we don't hold locks for the entirety of the range in
	 * streaming mode, which means some operation done during the exclusive
	 * phase could be undone before the shared phase iterates to that entry.
	 *
	 * VMRL_DESCEND_INTO_CONSTANT is not supported here so that we don't
	 * need to handle submap descend/ascend in this function. The exclusive
	 * lock done before would need to be entirely in or not in a transparent
	 * submap.
	 *
	 * This function is not implemented as a loop of {unlock_excl(); lock_shared(); }
	 * because that would have race conditions where another writer comes in when we unlock_excl.
	 * As a result, this operation needs to do its own downgrades atomically.
	 */

	/*
	 * Only allow downgrades if the whole range was iterated
	 * This isn't inherently a limitation of the lock, but it makes no sense today
	 * and the implementation doesn't currently support it.
	 */
	RANGE_LOCK_ASSERT(vml_ctx->vmlc_vme == NULL);

	/*
	 * Iterate all entries until we hit one that ends where the range ends.
	 * Exclusive locks clip, so we are guaranteed there is an entry that ends there.
	 */
	vm_map_entry_t entry = first_entry;

	while (!entry_is_map_end(map, entry) && entry->vme_start < end) {
		vm_entry_lock_exclusive_to_shared(entry);
		entry = entry->vme_next;
	}

	flags &= ~VMRL_EXCLUSIVE;
	flags |= VMRL_SHARED;
	vml_ctx->__vmlc_flags = flags;

	vm_map_range_atomic_reset(vml_ctx);
}

static kern_return_t
__find_entry_locked_impl(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map_in,
	vm_map_address_t        addr,
	vmrl_flags_t            flags)
{
	kern_return_t kr;

	flags |= VMRL_STREAM_NO_HOLES | _VMRL_SINGLE_ENTRY;

	kr = __vmrl_lock(vml_ctx, map_in,
	    addr, addr + vm_map_page_size(*map_in),
	    __vmrl_flags(flags));

	if (kr == KERN_SUCCESS) {
		vm_map_range_stream_next_internal(vml_ctx, &kr);
		if (kr != KERN_SUCCESS) {
			__vmrl_unlock(vml_ctx, flags, map_in);
		}
	}

	return kr;
}

kern_return_t
vm_map_find_entry_sh_locked(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        addr,
	vmrl_find_sh_flags_t    flags)
{
	return __find_entry_locked_impl(
		vml_ctx, map, addr, __vmrl_flags(flags) | VMRL_SHARED);
}

kern_return_t
vm_map_find_entry_ex_locked(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        addr,
	vmrl_find_ex_flags_t    flags)
{
	return __find_entry_locked_impl(
		vml_ctx, map, addr, __vmrl_flags(flags) | VMRL_EXCLUSIVE);
}

static void
__found_entry_unlock_impl(
	vm_map_find_lock_ctx_t    vml_ctx,
	vm_map_t                 *map)
{
	__vmrl_unlock(vml_ctx, __vmrl_flags(vml_ctx), map);
}

void
vm_map_found_entry_sh_unlock(
	vm_map_find_lock_ctx_t    vml_ctx,
	vm_map_t                 *map)
{
	__found_entry_unlock_impl(vml_ctx, map);
}

void
vm_map_found_entry_ex_unlock(
	vm_map_find_lock_ctx_t    vml_ctx,
	vm_map_t                 *map)
{
	__found_entry_unlock_impl(vml_ctx, map);
}

/*
 * vm_map_lock_tests need to be able to call into static helpers. So, instead
 * of linking them normally, just insert them here on builds where those tests
 * are used.
 */
#if DEVELOPMENT || DEBUG
#include <vm/vm_map_lock_tests.c>
#endif /* DEVELOPMENT || DEBUG */
