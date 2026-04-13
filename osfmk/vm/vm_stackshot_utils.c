/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <vm/vm_stackshot_utils_xnu.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_map_lock_internal.h>

/*!
 * @file vm_stackshot_utilities.c
 *
 * @discussion
 * This module implements VM-related routines called from stackshot.
 *
 * It's meant to act as a bridge between VM and stackshot.
 */

extern bool kdp_vm_entry_lock_is_acquired_exclusive(vm_map_entry_t vme);

/* Tells if this context has already locked some range during streaming */
static bool
is_streaming_range_owner(vm_map_lock_ctx_t ctx)
{
	if (vmrl_is_streaming(ctx)) {
		return ctx->vmlc_vme != VM_MAP_ENTRY_NULL;
	}
	return false;
}

/* Tells if we've already locked some range atomically (might be in the process of locking a wider range) */
static bool
is_atomic_range_owner(vm_map_lock_ctx_t ctx)
{
	return vmrl_is_atomic(ctx) &&
	       (ctx->__vmlc_atomic.locked_range_start > 0) &&
	       (ctx->__vmlc_atomic.locked_range_end > ctx->__vmlc_atomic.locked_range_start);
}

/* This does the opposite to __vm_entry_event (from vm_entry_lock.c) */
static vm_map_entry_t
__vmrl_stackshot_get_blocking_vme(thread_t thread)
{
	block_hint_t th_bl_hint = thread->block_hint;
	vm_map_entry_t entry = VM_MAP_ENTRY_NULL;

	if (th_bl_hint == kThreadWaitVMEntryExclEvent ||
	    th_bl_hint == kThreadWaitVMEntrySharedEvent) {
		entry = kdp_vm_entry_from_event(thread->wait_event, th_bl_hint);
	}

	return entry;
}

static bool
__vmrl_stackshot_is_range_overlapping(
	vm_offset_t waiter_start,
	vm_offset_t waiter_end,
	vm_offset_t owner_start,
	vm_offset_t owner_end)
{
	assert3u(owner_start, <, owner_end);
	if (waiter_start >= owner_end ||
	    waiter_end <= owner_start) {
		return false;
	} else {
		return true;
	}
}

static void
__vmrl_stackshot_initialize_held_range_bounds(vm_map_lock_ctx_t ctx, vm_offset_t *start, vm_offset_t *end)
{
	if (vmrl_is_streaming(ctx)) {
		vm_map_entry_t curr_streaming_entry = VM_MAP_ENTRY_NULL;
		curr_streaming_entry = ctx->vmlc_vme;
		/* Already checked that so it should be safe, see caller of is_streaming_range_owner() */
		assert3p(curr_streaming_entry, !=, VM_MAP_ENTRY_NULL);
		*start = curr_streaming_entry->vme_start;
		*end = curr_streaming_entry->vme_end;
	} else {
		*start = ctx->__vmlc_atomic.locked_range_start;
		*end = ctx->__vmlc_atomic.locked_range_end;
	}
}

/* Check if this owner_info denotes an owner of the range that Waiter requested for */
static bool
__vmrl_stackshot_is_range_owner(
	uint64_t waiter_tid,
	thread_vmrl_owner_info_t *suspect,
	vm_map_t waiter_map,
	bool waiter_is_shared,
	vm_offset_t waiter_start,
	vm_offset_t waiter_end)
{
	if (suspect->owner_tid == waiter_tid || suspect->map != waiter_map) {
		return false;
	}

	/* If a thread was blocked when it was trying to acquire non-exclusively, owner must be exclusive */
	if (waiter_is_shared) {
		if (!(suspect->flags & STACKSHOT_BLOCKER_VMRL_EXCLUSIVE)) {
			return false;
		}
	}

	if (__vmrl_stackshot_is_range_overlapping(waiter_start, waiter_end, suspect->start, suspect->end)) {
		return true;
	}

	return false;
}

static bool
__vmrl_stackshot_is_some_range_owner(thread_t thread)
{
	vm_map_lock_ctx_t ctx = thread->vm_map_lock_ctx_held;
	if (!ctx) {
		return false;
	}

	return is_streaming_range_owner(ctx) ||
	       is_atomic_range_owner(ctx);
}

static void
__vmrl_stackshot_flags_mode(vm_map_lock_ctx_t ctx, uint32_t *flags_out, bool is_blocker)
{
#define shift_if_blocker(flag) (is_blocker ? (flag) << 1 : (flag))

	if (vmrl_is_streaming(ctx)) {
		*flags_out |= shift_if_blocker(STACKSHOT_WAITER_VMRL_STREAMING);
	}
	if (vmrl_is_atomic(ctx)) {
		*flags_out |= shift_if_blocker(STACKSHOT_WAITER_VMRL_ATOMIC);
	}

#undef shift_if_blocker
}

static uint32_t
__vmrl_stackshot_waiter_flags(thread_t waiter)
{
	uint32_t flags = 0;
	if (waiter->block_hint == kThreadWaitVMEntryExclEvent) {
		flags |= STACKSHOT_WAITER_VMRL_EXCLUSIVE;
	} else {
		flags |= STACKSHOT_WAITER_VMRL_SHARED;
	}

	vm_map_lock_ctx_t ctx = waiter->vm_map_lock_ctx_held;
	if (ctx) {
		__vmrl_stackshot_flags_mode(ctx, &flags, false);
	}

	return flags;
}

static uint32_t
__vmrl_stackshot_blocker_flags(vm_map_lock_ctx_t ctx)
{
	uint32_t flags = 0;
	if (vmrl_is_exclusive(ctx)) {
		flags |= STACKSHOT_BLOCKER_VMRL_EXCLUSIVE;
	} else {
		flags |= STACKSHOT_BLOCKER_VMRL_SHARED;
	}

	__vmrl_stackshot_flags_mode(ctx, &flags, true);

	return flags;
}


__static_testable void
__vmrl_stackshot_collect_owner_info(thread_t owner_thread, struct stackshot_vmrl_state *state)
{
	/* This is fine, because num_owners is "monotonically" increasing (besides the decrement if we overflow) */
	uint32_t num_owners = os_atomic_inc_orig(&state->num_owners, relaxed);
	if (num_owners >= STACKSHOT_VMRL_MAX_OWNERS) {
		os_atomic_dec(&state->num_owners, relaxed);
		return;
	}

	vm_map_lock_ctx_t ctx = owner_thread->vm_map_lock_ctx_held;
	assert3p(ctx, !=, NULL);

	thread_vmrl_owner_info_t *curr_vmrl_owner_info = &state->owners[num_owners];
	curr_vmrl_owner_info->owner_tid = thread_tid(owner_thread);
	curr_vmrl_owner_info->map = ctx->vmlc_map;
	curr_vmrl_owner_info->flags = __vmrl_stackshot_blocker_flags(ctx);
	__vmrl_stackshot_initialize_held_range_bounds(ctx, &curr_vmrl_owner_info->start, &curr_vmrl_owner_info->end);
}

__static_testable int
__vmrl_stackshot_collect_waiter_info(thread_t waiter_thread, struct stackshot_vmrl_state *state)
{
	/* This is fine, because num_waiters is "monotonically" increasing (besides the decrement if we overflow) */
	uint32_t num_waiters = os_atomic_inc_orig(&state->num_waiters, relaxed);
	if (num_waiters >= STACKSHOT_VMRL_MAX_WAITERS) {
		os_atomic_dec(&state->num_waiters, relaxed);
		return -1;
	}
	vm_map_lock_ctx_t ctx = waiter_thread->vm_map_lock_ctx_held;
	if (!ctx) {
		return -1;
	}
	vm_map_entry_t blocking_vme = __vmrl_stackshot_get_blocking_vme(waiter_thread);
	if (!blocking_vme) {
		return -1;
	}
	uint32_t blocker_count = kdp_vm_entry_lock_is_acquired_exclusive(blocking_vme) ? 1 :
	    kdp_vm_entry_lock_read_count(blocking_vme);
	if (blocker_count == 0) {
		/*
		 * This sometimes happens when stackshot is taken in the time window between 'all other threads
		 * finished releasing the entry' and 'this waiting thread (waiter_thread) wakes up and
		 * aquires the entry'. waiter_thread is essentially about to wake up after the stackshot debugger
		 * trap and with high probability take the entry. No actual owners to report and therefore skip:
		 */
		return -1;
	}

	thread_vmrl_waiter_info_t *curr_waiter = &state->waiters[num_waiters];
	curr_waiter->waiter_tid = thread_tid(waiter_thread);
	curr_waiter->map = ctx->vmlc_map;
	curr_waiter->start = blocking_vme->vme_start;
	curr_waiter->end = blocking_vme->vme_end;
	curr_waiter->flags = __vmrl_stackshot_waiter_flags(waiter_thread);
	curr_waiter->num_blockers = blocker_count;
	curr_waiter->entry_hash = vm_kernel_addrhash((vm_offset_t)blocking_vme);

	return MIN(curr_waiter->num_blockers, STACKSHOT_VMRL_MAX_OWNERS);
}

void
vmrl_stackshot_collect_intermediary_info(
	thread_t                      thread,
	struct stackshot_vmrl_state  *state)
{
	/* Ensure we are in a stackshot debugger trap context */
	assert(!not_in_kdp);

	block_hint_t block_hint = thread->block_hint;
	if (block_hint == kThreadWaitVMEntryExclEvent || block_hint == kThreadWaitVMEntrySharedEvent) {
		if (os_atomic_load(&state->exp_num_relationships, relaxed) >= STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS) {
			goto collect_owner;
		}

		int curr_num_blockers = __vmrl_stackshot_collect_waiter_info(thread, state);
		if (curr_num_blockers > 0) {
			os_atomic_inc(&state->exp_num_relationships, relaxed);
		}
	}
collect_owner:
	if (__vmrl_stackshot_is_some_range_owner(thread)) {
		__vmrl_stackshot_collect_owner_info(thread, state);
	}
}

/* Per-waiter loop */
static uint32_t
__vmrl_stackshot_collect_waiter_blockers(
	thread_vmrl_waiter_info_t     *curr_waiter_info,
	vmrl_blocking_relationship_t  *rels,
	thread_vmrl_owner_info_t      *owner_info,
	size_t                         total_num_owners,
	size_t                         rels_index)
{
	uint32_t found = 0;
	uint32_t waiter_flags = curr_waiter_info->flags;
	bool waiter_is_shared = waiter_flags & STACKSHOT_WAITER_VMRL_SHARED;
	vmrl_blocking_relationship_t *curr_rel = rels + rels_index;

	/* Look through all the blockers we know of until we found all of those who are blocking this waiter */
	for (int i = 0; i < total_num_owners; i++) {
		if (__vmrl_stackshot_is_range_owner(curr_waiter_info->waiter_tid,
		    owner_info + i, curr_waiter_info->map, waiter_is_shared,
		    curr_waiter_info->start, curr_waiter_info->end)) {
			curr_rel->waiter_tid = curr_waiter_info->waiter_tid;
			curr_rel->blocker_tid = owner_info[i].owner_tid;
			curr_rel->entry_hash = curr_waiter_info->entry_hash;
			curr_rel->flags = waiter_flags | owner_info[i].flags;
			curr_rel++;
			found++;
			/* We found all the blockers we were looiking for, or we don't have enough memory to record more dependencies. */
			if (found == curr_waiter_info->num_blockers || found + rels_index >= STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS) {
				break;
			}
		}
	}
	return found;
}

uint32_t
vmrl_stackshot_collect_final_blocking_rels(struct stackshot_vmrl_state *state)
{
	uint32_t rels_index = 0;
	uint32_t num_owners = os_atomic_load(&state->num_owners, relaxed);
	uint32_t num_waiters = os_atomic_load(&state->num_waiters, relaxed);
	assert3u(num_owners, <=, STACKSHOT_VMRL_MAX_OWNERS);
	assert3u(num_waiters, <=, STACKSHOT_VMRL_MAX_WAITERS);
	for (int i = 0; i < num_waiters; i++) {
		if (state->waiters[i].waiter_tid == 0) {
			continue;
		}
		/* Search for all of this waiter's blockers, and record those relationships. */
		rels_index += __vmrl_stackshot_collect_waiter_blockers(state->waiters + i, state->relationships,
		    state->owners, num_owners, rels_index);
		if (rels_index >= STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS) {
			break;
		}
	}
	return rels_index;
}
