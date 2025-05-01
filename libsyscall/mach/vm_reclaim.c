/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#if defined(__LP64__)
/*
 * Userspace functions for manipulating the reclaim buffer.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <mach/error.h>
#include <mach/kern_return.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_reclaim_private.h>
#undef _mach_vm_user_
#include <mach/mach_vm_internal.h>
#include <mach/vm_map.h>
#include <os/atomic_private.h>
#include <os/overflow.h>
#include <mach/vm_page_size.h>
#include <TargetConditionals.h>


#pragma mark Utilities
#define _assert(__op, __condition, __cause) \
	do { \
	        if (!(__condition)) { \
	                __builtin_trap(); \
	        } \
	} while (false)
#define _abort(__op, __cause) \
	do { \
	        __builtin_trap(); \
	} while(false)

_Static_assert(VM_RECLAIM_MAX_CAPACITY <= UINT32_MAX, "Max capacity must fit in mach_vm_reclaim_count_t");

static uint64_t kAccountingThreshold;

static bool
update_accounting(mach_vm_reclaim_ring_t ring_buffer, int64_t size)
{
	ring_buffer->va_in_buffer += size;
	if ((ring_buffer->va_in_buffer > ring_buffer->last_accounting_given_to_kernel &&
	    ring_buffer->va_in_buffer - ring_buffer->last_accounting_given_to_kernel > kAccountingThreshold) ||
	    (ring_buffer->last_accounting_given_to_kernel > ring_buffer->va_in_buffer &&
	    ring_buffer->last_accounting_given_to_kernel - ring_buffer->va_in_buffer > kAccountingThreshold)) {
		/*
		 * The caller should call mach_vm_reclaim_update_kernel_accounting.
		 * We store the value that they will give to the kernel here while we hold the lock.
		 * Technically it's out of sync with what the kernel has seen, but
		 * that will be rectified once the caller makes the mach_vm_reclaim_update_kernel_accounting call.
		 * If we forced this value to be in sync with the kernel's value
		 * all callers would start calling mach_vm_reclaim_update_kernel_accounting until one of them
		 * finishes & we'd have to take the ringbuffer lock again in
		 * mach_vm_reclaim_update_kernel_accounting.
		 */
		ring_buffer->last_accounting_given_to_kernel = ring_buffer->va_in_buffer;
		return true;
	}
	return false;
}

static inline struct mach_vm_reclaim_entry_s
construct_entry(
	mach_vm_address_t start_addr,
	uint32_t size,
	mach_vm_reclaim_action_t behavior)
{
	struct mach_vm_reclaim_entry_s entry = {0ULL};
	entry.address = start_addr;
	entry.size = size;
	entry.behavior = behavior;
	return entry;
}

static uint64_t
max_buffer_len_for_size(mach_vm_size_t size)
{
	mach_vm_size_t entries_size = size - offsetof(struct mach_vm_reclaim_ring_s, entries);
	return entries_size / sizeof(struct mach_vm_reclaim_entry_s);
}

static mach_vm_reclaim_count_t
round_buffer_len(mach_vm_reclaim_count_t count)
{
	mach_vm_reclaim_count_t rounded_count;
	mach_vm_size_t buffer_size =
	    offsetof(struct mach_vm_reclaim_ring_s, entries) +
	    (count * sizeof(struct mach_vm_reclaim_entry_s));
	mach_vm_size_t rounded_size = mach_vm_round_page(buffer_size);
	uint64_t num_entries = max_buffer_len_for_size(rounded_size);
	if (os_convert_overflow(num_entries, &rounded_count)) {
		return UINT32_MAX;
	}
	return rounded_count;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_ring_allocate(
	mach_vm_reclaim_ring_t *ring_out,
	mach_vm_reclaim_count_t initial_capacity,
	mach_vm_reclaim_count_t max_capacity)
{
	kAccountingThreshold = vm_page_size;
	kern_return_t kr;
	mach_vm_address_t vm_addr = 0;
	if (ring_out == NULL || max_capacity < initial_capacity ||
	    initial_capacity == 0 || max_capacity == 0) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}
	if (max_capacity > VM_RECLAIM_MAX_CAPACITY) {
		return VM_RECLAIM_INVALID_CAPACITY;
	}

	*ring_out = NULL;
	kr = mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(),
	    &vm_addr, initial_capacity, max_capacity);
	if (kr == ERR_SUCCESS) {
		mach_vm_reclaim_ring_t ringbuffer =
		    (mach_vm_reclaim_ring_t)vm_addr;

		ringbuffer->va_in_buffer = 0;
		ringbuffer->last_accounting_given_to_kernel = 0;
		ringbuffer->len = initial_capacity;
		ringbuffer->max_len = max_capacity;
		*ring_out = ringbuffer;
	}
	return kr;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_ring_resize(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_count_t capacity)
{
	kern_return_t kr;
	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (capacity == 0 || capacity > ring->max_len) {
		return VM_RECLAIM_INVALID_CAPACITY;
	}
	kr = mach_vm_deferred_reclamation_buffer_resize(mach_task_self(),
	    capacity);
	if (kr == KERN_SUCCESS) {
		ring->len = capacity;
	}
	return kr;
}

mach_vm_reclaim_count_t
mach_vm_reclaim_round_capacity(
	mach_vm_reclaim_count_t count)
{
	if (count > VM_RECLAIM_MAX_CAPACITY) {
		return VM_RECLAIM_MAX_CAPACITY;
	}
	return round_buffer_len(count);
}

mach_vm_reclaim_error_t
mach_vm_reclaim_try_enter(
	mach_vm_reclaim_ring_t ring,
	mach_vm_address_t region_start,
	mach_vm_size_t region_size,
	mach_vm_reclaim_action_t action,
	mach_vm_reclaim_id_t *id,
	bool *should_update_kernel_accounting)
{
	mach_vm_reclaim_id_t tail = 0, head = 0, original_tail = 0, busy = 0;
	mach_vm_reclaim_indices_t indices = &ring->indices;
	mach_vm_reclaim_entry_t entries = ring->entries;
	uint64_t buffer_len = (uint64_t)ring->len;
	*should_update_kernel_accounting = false;

	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (id == NULL) {
		return VM_RECLAIM_INVALID_ID;
	}

	uint32_t size32;
	if (os_convert_overflow(region_size, &size32)) {
		/* regions must fit in 32-bits */
		*id = VM_RECLAIM_ID_NULL;
		return VM_RECLAIM_INVALID_REGION_SIZE;
	}

	mach_vm_reclaim_id_t requested_id = *id;
	*id = VM_RECLAIM_ID_NULL;

	if (requested_id == VM_RECLAIM_ID_NULL) {
		tail = os_atomic_load_wide(&indices->tail, relaxed);
		head = os_atomic_load_wide(&indices->head, relaxed);

		if (tail % buffer_len == head % buffer_len && tail > head) {
			/* Buffer is full */
			return VM_RECLAIM_SUCCESS;
		}

		/*
		 * idx must be >= head & the buffer is not full so it's not possible for the kernel to be acting on the entry at (tail + 1) % size.
		 * Thus we don't need to check the busy pointer here.
		 */
		struct mach_vm_reclaim_entry_s entry = construct_entry(region_start, size32, action);
		entries[tail % buffer_len] = entry;
		os_atomic_thread_fence(seq_cst); // tail increment can not be seen before the entry is cleared in the buffer
		os_atomic_inc(&indices->tail, relaxed);
		*id = tail;
	} else {
		head = os_atomic_load_wide(&indices->head, relaxed);
		if (requested_id < head) {
			/*
			 * This is just a fast path for the case where the buffer has wrapped.
			 * It's not strictly necessary beacuse idx must also be < busy.
			 * That's why we can use a relaxed load for the head ptr.
			 */
			return VM_RECLAIM_SUCCESS;
		}
		/* Attempt to move tail to idx */
		original_tail = os_atomic_load_wide(&indices->tail, relaxed);
		_assert("mach_vm_reclaim_mark_free_with_id",
		    requested_id < original_tail, original_tail);

		os_atomic_store_wide(&indices->tail, requested_id, relaxed);
		os_atomic_thread_fence(seq_cst); // Our write to tail must happen before our read of busy
		busy = os_atomic_load_wide(&indices->busy, relaxed);
		if (requested_id < busy) {
			/* Kernel is acting on this entry. Undo. */
			os_atomic_store_wide(&indices->tail, original_tail, relaxed);
			return VM_RECLAIM_SUCCESS;
		}

		mach_vm_reclaim_entry_t entry = &entries[requested_id % buffer_len];
		_assert("mach_vm_reclaim_try_enter",
		    entry->address == 0 && entry->size == 0, entry->address);

		/* Sucessfully moved tail back. Can now overwrite the entry */
		*entry = construct_entry(region_start, size32, action);

		/* Tail increment can not be seen before the entry is set in the buffer */
		os_atomic_thread_fence(seq_cst);
		/* Reset tail. */
		os_atomic_store_wide(&indices->tail, original_tail, relaxed);
		*id = requested_id;
	}
	*should_update_kernel_accounting = update_accounting(ring, region_size);
	return VM_RECLAIM_SUCCESS;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_try_cancel(
	mach_vm_reclaim_ring_t ring_buffer,
	mach_vm_reclaim_id_t id,
	mach_vm_address_t region_start,
	mach_vm_size_t region_size,
	mach_vm_reclaim_action_t behavior,
	mach_vm_reclaim_state_t *state,
	bool *should_update_kernel_accounting)
{
	mach_vm_reclaim_indices_t indices = &ring_buffer->indices;
	mach_vm_reclaim_entry_t entries = ring_buffer->entries;
	uint64_t buffer_len = (uint64_t)ring_buffer->len;
	uint64_t head = 0, busy = 0, original_tail = 0;

	if (ring_buffer == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (id == VM_RECLAIM_ID_NULL) {
		/* The entry was never put in the reclaim ring buffer */
		return VM_RECLAIM_INVALID_ID;
	}
	if (state == NULL || should_update_kernel_accounting == NULL) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}

	*should_update_kernel_accounting = false;

	uint32_t size32;
	if (os_convert_overflow(region_size, &size32)) {
		/* Regions must fit in 32-bits */
		return VM_RECLAIM_INVALID_REGION_SIZE;
	}

	head = os_atomic_load_wide(&indices->head, relaxed);
	if (id < head) {
		/*
		 * This is just a fast path for the case where the buffer has wrapped.
		 * It's not strictly necessary beacuse idx must also be < busy.
		 * That's why we can use a relaxed load for the head ptr.
		 */
		switch (behavior) {
		case VM_RECLAIM_DEALLOCATE:
			/* Entry has been deallocated and is not safe to re-use */
			*state = VM_RECLAIM_DEALLOCATED;
			break;
		case VM_RECLAIM_FREE:
			/* Entry has been freed, the virtual region is now safe to re-use */
			*state = VM_RECLAIM_FREED;
			break;
		default:
			return VM_RECLAIM_INVALID_ARGUMENT;
		}
		return VM_RECLAIM_SUCCESS;
	}

	/* Attempt to move tail to idx */
	original_tail = os_atomic_load_wide(&indices->tail, relaxed);
	_assert("mach_vm_reclaim_mark_used", id < original_tail, original_tail);

	os_atomic_store_wide(&indices->tail, id, relaxed);
	/* Our write to tail must happen before our read of busy */
	os_atomic_thread_fence(seq_cst);
	busy = os_atomic_load_wide(&indices->busy, relaxed);
	if (id < busy) {
		/*
		 * This entry is in the process of being reclaimed. It is
		 * never safe to re-use while in this state.
		 */
		os_atomic_store_wide(&indices->tail, original_tail, relaxed);
		*state = VM_RECLAIM_BUSY;
		return VM_RECLAIM_SUCCESS;
	}
	mach_vm_reclaim_entry_t entry = &entries[id % buffer_len];
	_assert("mach_vm_reclaim_mark_used", entry->size == region_size, entry->size);
	_assert("mach_vm_reclaim_mark_used", entry->address == region_start, entry->address);
	_assert("mach_vm_reclaim_mark_used", entry->behavior == behavior, entry->behavior);

	/* Sucessfully moved tail back. Can now overwrite the entry */
	memset(entry, 0, sizeof(struct mach_vm_reclaim_entry_s));
	/* tail increment can not be seen before the entry is cleared in the buffer */
	os_atomic_thread_fence(seq_cst);
	/* Reset tail. */
	os_atomic_store_wide(&indices->tail, original_tail, relaxed);

	*should_update_kernel_accounting = update_accounting(ring_buffer, -(int64_t)region_size);
	*state = VM_RECLAIM_UNRECLAIMED;
	return VM_RECLAIM_SUCCESS;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_query_state(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_id_t id,
	mach_vm_reclaim_action_t action,
	mach_vm_reclaim_state_t *state)
{
	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (id == VM_RECLAIM_ID_NULL) {
		return VM_RECLAIM_INVALID_ID;
	}
	mach_vm_reclaim_indices_t indices = &ring->indices;

	mach_vm_reclaim_id_t head = os_atomic_load_wide(&indices->head, relaxed);
	if (id < head) {
		switch (action) {
		case VM_RECLAIM_FREE:
			*state = VM_RECLAIM_FREED;
			break;
		case VM_RECLAIM_DEALLOCATE:
			*state = VM_RECLAIM_DEALLOCATED;
			break;
		default:
			return VM_RECLAIM_INVALID_ARGUMENT;
		}
		return VM_RECLAIM_SUCCESS;
	}

	mach_vm_reclaim_id_t busy = os_atomic_load_wide(&indices->busy, relaxed);
	if (id < busy) {
		*state = VM_RECLAIM_BUSY;
	} else {
		*state = VM_RECLAIM_UNRECLAIMED;
	}
	return VM_RECLAIM_SUCCESS;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_update_kernel_accounting(const mach_vm_reclaim_ring_t ring)
{
	return mach_vm_deferred_reclamation_buffer_update_reclaimable_bytes(current_task(),
	           ring->va_in_buffer);
}

bool
mach_vm_reclaim_is_reusable(
	mach_vm_reclaim_state_t state)
{
	return state == VM_RECLAIM_FREED || state == VM_RECLAIM_UNRECLAIMED;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_ring_capacity(mach_vm_reclaim_ring_t ring, mach_vm_reclaim_count_t *capacity)
{
	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (capacity == NULL) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}
	*capacity = ring->len;
	return VM_RECLAIM_SUCCESS;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_ring_flush(
	mach_vm_reclaim_ring_t ring_buffer,
	mach_vm_reclaim_count_t num_entries_to_reclaim)
{
	if (ring_buffer == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (num_entries_to_reclaim == 0) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}

	return mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), num_entries_to_reclaim);
}

#endif /* defined(__LP64__) */
