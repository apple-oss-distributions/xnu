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
#include <mach/mach_time.h>
#include <mach/mach_traps.h>
#include <mach/mach_vm.h>
#include <mach/vm_reclaim_private.h>
#undef _mach_vm_user_
#include <mach/mach_vm_internal.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>
#include <os/atomic_private.h>
#include <os/overflow.h>
#include <sys/param.h>
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
	kern_return_t kr;
	mach_vm_address_t vm_addr = 0;
	uint64_t next_deadline = 0, now;

	if (ring_out == NULL || max_capacity < initial_capacity ||
	    initial_capacity == 0 || max_capacity == 0) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}
	if (max_capacity > VM_RECLAIM_MAX_CAPACITY) {
		return VM_RECLAIM_INVALID_CAPACITY;
	}

	*ring_out = NULL;
	now = mach_absolute_time();
	kr = mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(),
	    &vm_addr, &next_deadline, initial_capacity, max_capacity);
	if (kr == ERR_SUCCESS) {
		mach_vm_reclaim_ring_t ring =
		    (mach_vm_reclaim_ring_t)vm_addr;
		ring->len = initial_capacity;
		ring->max_len = max_capacity;
		os_atomic_store(&ring->last_sample_abs, now, relaxed);
		os_atomic_store(&ring->reclaimable_bytes, 0, relaxed);
		os_atomic_store(&ring->reclaimable_bytes_min, 0, relaxed);
		os_atomic_store(&ring->next_sample_deadline_abs, next_deadline, relaxed);
		*ring_out = ring;
	}
	return kr;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_ring_resize(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_count_t capacity)
{
	mach_error_t err;
	mach_vm_size_t bytes_reclaimed = 0;
	uint64_t next_deadline;

	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (capacity == 0 || capacity > ring->max_len) {
		return VM_RECLAIM_INVALID_CAPACITY;
	}

	err = mach_vm_deferred_reclamation_buffer_resize(mach_task_self(),
	    capacity, &bytes_reclaimed, &next_deadline);
	if (err == ERR_SUCCESS) {
		ring->len = capacity;
		size_t reclaimable_bytes = os_atomic_sub(&ring->reclaimable_bytes, bytes_reclaimed, relaxed);
		os_atomic_min(&ring->reclaimable_bytes_min, reclaimable_bytes, relaxed);
		os_atomic_max(&ring->next_sample_deadline_abs, next_deadline, relaxed);
	}
	return err;
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
		tail = os_atomic_load_wide(&ring->tail, relaxed);
		head = os_atomic_load_wide(&ring->head, relaxed);

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
		os_atomic_inc(&ring->tail, relaxed);
		*id = tail;
	} else {
		head = os_atomic_load_wide(&ring->head, relaxed);
		if (requested_id < head) {
			/*
			 * This is just a fast path for the case where the buffer has wrapped.
			 * It's not strictly necessary beacuse idx must also be < busy.
			 * That's why we can use a relaxed load for the head ptr.
			 */
			return VM_RECLAIM_SUCCESS;
		}
		/* Attempt to move tail to idx */
		original_tail = os_atomic_load_wide(&ring->tail, relaxed);
		_assert("mach_vm_reclaim_mark_free_with_id",
		    requested_id < original_tail, original_tail);

		os_atomic_store_wide(&ring->tail, requested_id, relaxed);
		os_atomic_thread_fence(seq_cst); // Our write to tail must happen before our read of busy
		busy = os_atomic_load_wide(&ring->busy, relaxed);
		if (requested_id < busy) {
			/* Kernel is acting on this entry. Undo. */
			os_atomic_store_wide(&ring->tail, original_tail, relaxed);
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
		os_atomic_store_wide(&ring->tail, original_tail, relaxed);
		*id = requested_id;
	}

	size_t reclaimable_bytes = os_atomic_add(&ring->reclaimable_bytes, region_size, relaxed);
	os_atomic_min(&ring->reclaimable_bytes_min, reclaimable_bytes, relaxed);

	uint64_t now = mach_absolute_time();
	if (now >= os_atomic_load(&ring->next_sample_deadline_abs, relaxed)) {
		*should_update_kernel_accounting = true;
	}
	return VM_RECLAIM_SUCCESS;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_try_cancel(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_id_t id,
	mach_vm_address_t region_start,
	mach_vm_size_t region_size,
	mach_vm_reclaim_action_t behavior,
	mach_vm_reclaim_state_t *state,
	bool *should_update_kernel_accounting)
{
	mach_vm_reclaim_entry_t entries = ring->entries;
	uint64_t buffer_len = (uint64_t)ring->len;
	uint64_t head = 0, busy = 0, original_tail = 0;

	if (ring == NULL) {
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

	head = os_atomic_load_wide(&ring->head, relaxed);
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
	original_tail = os_atomic_load_wide(&ring->tail, relaxed);
	_assert("mach_vm_reclaim_mark_used", id < original_tail, original_tail);

	os_atomic_store_wide(&ring->tail, id, relaxed);
	/* Our write to tail must happen before our read of busy */
	os_atomic_thread_fence(seq_cst);
	busy = os_atomic_load_wide(&ring->busy, relaxed);
	if (id < busy) {
		/*
		 * This entry is in the process of being reclaimed. It is
		 * never safe to re-use while in this state.
		 */
		os_atomic_store_wide(&ring->tail, original_tail, relaxed);
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
	os_atomic_store_wide(&ring->tail, original_tail, relaxed);

	size_t reclaimable_bytes = os_atomic_sub(&ring->reclaimable_bytes, region_size, relaxed);
	os_atomic_min(&ring->reclaimable_bytes_min, reclaimable_bytes, relaxed);

	uint64_t now = mach_absolute_time();
	if (now >= os_atomic_load(&ring->next_sample_deadline_abs, relaxed)) {
		*should_update_kernel_accounting = true;
	}
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

	mach_vm_reclaim_id_t head = os_atomic_load_wide(&ring->head, relaxed);
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

	mach_vm_reclaim_id_t busy = os_atomic_load_wide(&ring->busy, relaxed);
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
	/*
	 * The rmw on last_sample is an optimization to prevent a herd of threads
	 * all calling into the kernel and contending on the kernel lock after the
	 * deadline has expired and before any (potentially slow) reclamation
	 * operations have completed
	 */
	uint64_t last_sample;
	uint64_t now = mach_absolute_time();
	uint64_t prev_deadline = os_atomic_load(&ring->next_sample_deadline_abs, relaxed);
	os_atomic_rmw_loop(&ring->last_sample_abs, last_sample, now, relaxed, {
		if (last_sample >= prev_deadline) {
		        /* Another thread beat us to taking a sample */
		        os_atomic_rmw_loop_give_up(return VM_RECLAIM_SUCCESS; );
		}
	});

	mach_error_t err;
	uint64_t bytes_reclaimed = 0;
	uint64_t next_deadline = 0;
	err = mach_vm_reclaim_update_kernel_accounting_trap(current_task(),
	    &bytes_reclaimed, &next_deadline);

	mach_vm_size_t reclaimable_bytes = os_atomic_sub(&ring->reclaimable_bytes,
	    bytes_reclaimed, relaxed);
	os_atomic_min(&ring->reclaimable_bytes_min, reclaimable_bytes, relaxed);

	if (err == ERR_SUCCESS) {
		os_atomic_max(&ring->next_sample_deadline_abs, next_deadline, relaxed);
	}

	return err;
}

bool
mach_vm_reclaim_is_reusable(
	mach_vm_reclaim_state_t state)
{
	switch (state) {
	case VM_RECLAIM_FREED:
	case VM_RECLAIM_UNRECLAIMED:
		return true;
	case VM_RECLAIM_DEALLOCATED:
	case VM_RECLAIM_BUSY:
		return false;
	default:
		return false;
	}
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
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_count_t num_entries_to_reclaim)
{
	mach_vm_size_t bytes_reclaimed;
	uint64_t next_deadline;
	mach_error_t err;

	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}
	if (num_entries_to_reclaim == 0) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}

	err = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(),
	    num_entries_to_reclaim, &bytes_reclaimed, &next_deadline);
	if (err == ERR_SUCCESS) {
		size_t reclaimable_bytes = os_atomic_sub(&ring->reclaimable_bytes, bytes_reclaimed, relaxed);
		os_atomic_min(&ring->reclaimable_bytes_min, reclaimable_bytes, relaxed);
		os_atomic_max(&ring->next_sample_deadline_abs, next_deadline, relaxed);
	}
	return err;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_get_rings_for_task(
	task_read_t task,
	mach_vm_reclaim_ring_ref_t refs_out,
	mach_vm_reclaim_count_t *count_inout)
{
	/*
	 * Technically, we could support multiple rings per task. But for now, we
	 * only have one - so this is kind of a weird-looking shim that fakes that
	 * behavior at the libsyscall layer to make things easier in case anything
	 * changes.
	 */

	kern_return_t kr;
	mach_vm_address_t addr;
	mach_vm_size_t size;

	if (count_inout == NULL) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}

	kr = mach_vm_deferred_reclamation_buffer_query(task, &addr, &size);

	if (kr != KERN_SUCCESS) {
		switch (kr) {
		case KERN_NOT_SUPPORTED:
			return VM_RECLAIM_NOT_SUPPORTED;
		case KERN_INVALID_ARGUMENT:
		case KERN_INVALID_TASK:
		case KERN_INVALID_ADDRESS:
			return VM_RECLAIM_INVALID_ARGUMENT;
		default:
			return kr;
		}
	}

	/* Size query. If addr == NULL, it doesn't have a ring */
	if (refs_out == NULL) {
		*count_inout = addr ? 1 : 0;
		return KERN_SUCCESS;
	}

	if (addr) {
		if (*count_inout >= 1) {
			refs_out->addr = addr;
			refs_out->size = size;
		}
		*count_inout = 1;
	} else {
		*count_inout = 0;
	}

	return KERN_SUCCESS;
}

static mach_vm_reclaim_error_t
verify_ring_allocation_size(mach_vm_address_t addr, mach_vm_size_t size)
{
	if (size < offsetof(struct mach_vm_reclaim_ring_s, entries)) {
		return VM_RECLAIM_INVALID_RING;
	}

	mach_vm_reclaim_ring_t ring = (mach_vm_reclaim_ring_t) addr;
	mach_vm_size_t supposed_size =
	    offsetof(struct mach_vm_reclaim_ring_s, entries) +
	    (ring->max_len * sizeof(struct mach_vm_reclaim_entry_s));

	/* store allocation size in ring->_unused so that we can free it later */
	ring->_unused = size;

	return (supposed_size <= size) ? VM_RECLAIM_SUCCESS : VM_RECLAIM_INVALID_RING;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_ring_copy(
	task_read_t task,
	mach_vm_reclaim_ring_ref_t ref,
	mach_vm_reclaim_ring_copy_t *ring_out)
{
	mach_vm_address_t address;
	vm_prot_t curprot = VM_PROT_DEFAULT;
	vm_prot_t maxprot = VM_PROT_DEFAULT;
	kern_return_t kr = mach_vm_remap(
		mach_task_self(),
		&address,
		ref->size,
		0,
		VM_FLAGS_ANYWHERE,
		task,
		ref->addr,
		TRUE,
		&curprot,
		&maxprot,
		VM_INHERIT_DEFAULT);

	switch (kr) {
	case KERN_INVALID_TASK:
	case KERN_INVALID_ADDRESS:
	case KERN_INVALID_ARGUMENT:
		return VM_RECLAIM_INVALID_ARGUMENT;
	case KERN_SUCCESS:
		break;
	default:
		return kr;
	}

	kr = verify_ring_allocation_size(address, ref->size);
	if (kr != VM_RECLAIM_SUCCESS) {
		return kr;
	}

	*ring_out = address;
	return VM_RECLAIM_SUCCESS;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_copied_ring_free(
	mach_vm_reclaim_ring_copy_t *cring)
{
	kern_return_t kr;
	mach_vm_reclaim_ring_t ring = (mach_vm_reclaim_ring_t) *cring;

	kr = mach_vm_deallocate(
		mach_task_self(),
		(mach_vm_address_t) *cring,
		ring->_unused);

	if (kr == KERN_SUCCESS) {
		*cring = NULL;
	}

	return kr;
}

mach_vm_reclaim_error_t
mach_vm_reclaim_copied_ring_query(
	mach_vm_reclaim_ring_copy_t *ring_copy,
	mach_vm_reclaim_region_t regions_out,
	mach_vm_reclaim_count_t *count_inout)
{
	mach_vm_reclaim_id_t head, tail, idx, entry_idx;
	mach_vm_reclaim_entry_t entry;
	mach_vm_reclaim_count_t count;
	mach_vm_reclaim_ring_t ring = (mach_vm_reclaim_ring_t) *ring_copy;

	if (ring == NULL) {
		return VM_RECLAIM_INVALID_RING;
	}

	if (count_inout == NULL) {
		return VM_RECLAIM_INVALID_ARGUMENT;
	}

	head = os_atomic_load_wide(&ring->head, relaxed);
	tail = os_atomic_load_wide(&ring->tail, relaxed);

	if (tail < head) {
		*count_inout = 0;
		return VM_RECLAIM_SUCCESS;
	}

	count = (mach_vm_reclaim_count_t) (tail - head);

	/* Query size */
	if (regions_out == NULL) {
		*count_inout = count;
		return VM_RECLAIM_SUCCESS;
	}

	count = (count < *count_inout) ? count : *count_inout;

	for (idx = 0; idx < count; idx++) {
		entry_idx = (head + idx) % ring->len;
		if (entry_idx > ring->max_len) {
			/*
			 * Make sure we don't accidentally read outside of the mapped region
			 * due to a malformed ring
			 */
			*count_inout = (mach_vm_reclaim_count_t) idx;
			return VM_RECLAIM_INVALID_CAPACITY;
		}
		entry = &ring->entries[entry_idx];
		regions_out->vmrr_addr = entry->address;
		regions_out->vmrr_size = entry->size;
		regions_out->vmrr_behavior = entry->behavior;
		regions_out++;
	}

	*count_inout = count;

	return VM_RECLAIM_SUCCESS;
}

#endif /* defined(__LP64__) */
