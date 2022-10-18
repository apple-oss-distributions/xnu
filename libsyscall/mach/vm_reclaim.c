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
#include <mach/vm_reclaim.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#undef _mach_vm_user_
#include <mach/mach_vm_internal.h>
#include <mach/vm_map.h>
#include <os/atomic_private.h>
#include <mach/vm_page_size.h>


#pragma mark Utilities
#define _assert(__op, __condition, __cause) \
	do { \
	        if (!(__condition)) { \
	                __builtin_trap(); \
	        } \
	} while (0)

static uint64_t kAccountingThreshold;

static bool
update_accounting(mach_vm_reclaim_ringbuffer_v1_t ring_buffer, int64_t size)
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

static inline
mach_vm_reclaim_entry_v1_t
construct_entry(mach_vm_address_t start_addr, uint32_t size)
{
	mach_vm_reclaim_entry_v1_t entry = {0ULL};
	entry.address = start_addr;
	entry.size = size;
	return entry;
}

kern_return_t
mach_vm_reclaim_ringbuffer_init(mach_vm_reclaim_ringbuffer_v1_t ring_buffer)
{
	kAccountingThreshold = vm_page_size;
	kern_return_t kr;
	mach_vm_size_t buffer_size = vm_page_size;
	bzero(ring_buffer, sizeof(struct mach_vm_reclaim_ringbuffer_v1_s));
	ring_buffer->buffer_len = buffer_size / sizeof(mach_vm_reclaim_entry_v1_t);
	kr = mach_vm_map(mach_task_self(), (mach_vm_address_t *)&ring_buffer->buffer,
	    buffer_size, 0, VM_FLAGS_ANYWHERE, MEMORY_OBJECT_NULL, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = mach_vm_deferred_reclamation_buffer_init(mach_task_self(),
	    (mach_vm_address_t) ring_buffer->buffer, buffer_size, &ring_buffer->indices);

	if (kr != KERN_SUCCESS) {
		mach_vm_deallocate(current_task(), (mach_vm_address_t) ring_buffer->buffer,
		    buffer_size);
		return kr;
	}

	return KERN_SUCCESS;
}

uint64_t
mach_vm_reclaim_mark_free(
	mach_vm_reclaim_ringbuffer_v1_t ring_buffer, mach_vm_address_t start_addr, uint32_t size,
	bool *should_update_kernel_accounting)
{
	uint64_t idx = 0, head = 0;
	mach_vm_reclaim_entry_v1_t entry = construct_entry(start_addr, size);
	mach_vm_reclaim_indices_v1_t *indices = &ring_buffer->indices;
	mach_vm_reclaim_entry_v1_t *buffer = ring_buffer->buffer;
	mach_vm_size_t buffer_len = ring_buffer->buffer_len;
	*should_update_kernel_accounting = false;

	idx = os_atomic_load_wide(&indices->tail, relaxed);
	head = os_atomic_load_wide(&indices->head, relaxed);

	// This leaves one entry empty at the end of the buffer to differentiate an empty buffer from a full one
	while ((idx + 1) % buffer_len == head % buffer_len) {
		/*
		 * Buffer is full. Ask the kernel to reap it.
		 */
		mach_vm_deferred_reclamation_buffer_synchronize(mach_task_self(), buffer_len - 1);
		head = os_atomic_load_wide(&indices->head, relaxed);
		/* kernel had to march head forward at least kNumEntriesToReclaim. We hold the buffer lock so tail couldn't have changed */
		_assert("mach_vm_reclaim_mark_free", os_atomic_load_wide(&indices->tail, relaxed) % size != head % buffer_len, head);
	}

	/*
	 * idx must be >= head & the buffer is not full so it's not possible for the kernel to be acting on the entry at (tail + 1) % size.
	 * Thus we don't need to check the busy pointer here.
	 */
	buffer[idx % buffer_len] = entry;
	os_atomic_thread_fence(seq_cst); // tail increment can not be seen before the entry is cleared in the buffer
	os_atomic_inc(&indices->tail, relaxed);
	*should_update_kernel_accounting = update_accounting(ring_buffer, size);

	return idx;
}

bool
mach_vm_reclaim_mark_used(
	mach_vm_reclaim_ringbuffer_v1_t ring_buffer, uint64_t id, mach_vm_address_t start_addr, uint32_t size)
{
	mach_vm_reclaim_indices_v1_t *indices = &ring_buffer->indices;
	mach_vm_reclaim_entry_v1_t *buffer = ring_buffer->buffer;
	mach_vm_size_t buffer_len = ring_buffer->buffer_len;
	uint64_t head = 0, busy = 0, original_tail = 0;
	if (id == VM_RECLAIM_INDEX_NULL) {
		// entry was never put in the reclaim ring buffer, so it's safe to re-use.
		return true;
	}

	head = os_atomic_load_wide(&indices->head, relaxed);
	if (id < head) {
		/*
		 * This is just a fast path for the case where the buffer has wrapped.
		 * It's not strictly necessary beacuse idx must also be < busy.
		 * That's why we can use a relaxed load for the head ptr.
		 */
		return false;
	}

	/* Attempt to move tail to idx */
	original_tail = os_atomic_load_wide(&indices->tail, relaxed);
	_assert("mach_vm_reclaim_mark_used", id < original_tail, original_tail);

	os_atomic_store_wide(&indices->tail, id, relaxed);
	os_atomic_thread_fence(seq_cst); // Our write to tail must happen before our read of busy
	busy = os_atomic_load_wide(&indices->busy, relaxed);
	if (id < busy) {
		/* Kernel is acting on this entry. Undo. */
		os_atomic_store_wide(&indices->tail, original_tail, relaxed);
		return false;
	}
	mach_vm_reclaim_entry_v1_t *entry = &buffer[id % buffer_len];
	_assert("mach_vm_reclaim_mark_used", entry->size == size && entry->address == start_addr, entry->address);

	/* Sucessfully moved tail back. Can now overwrite the entry */
	memset(entry, 0, sizeof(mach_vm_reclaim_entry_v1_t));
	os_atomic_thread_fence(seq_cst); // tail increment can not be seen before the entry is cleared in the buffer
	/* Reset tail. */
	os_atomic_store_wide(&indices->tail, original_tail, relaxed);

	update_accounting(ring_buffer, -(int64_t) size);

	return true;
}

kern_return_t
mach_vm_reclaim_update_kernel_accounting(const mach_vm_reclaim_ringbuffer_v1_t ring_buffer)
{
	return mach_vm_deferred_reclamation_buffer_update_reclaimable_bytes(current_task(),
	           ring_buffer->va_in_buffer);
}

bool
mach_vm_reclaim_is_available(const mach_vm_reclaim_ringbuffer_v1_t ring_buffer, uint64_t id)
{
	const mach_vm_reclaim_indices_v1_t *indices = &ring_buffer->indices;
	if (id == VM_RECLAIM_INDEX_NULL) {
		// entry was never put in the reclaim ring buffer, so it's safe to re-use.
		return true;
	}

	/*
	 * If the kernel has marched its busy pointer past this entry, consider it reclaimed.
	 * It's possible that the kernel will not reclaim this entry yet b/c we're racing with it on
	 * another thread via mach_vm_reclaim_mark_used.
	 */
	uint64_t busy = os_atomic_load_wide(&indices->busy, relaxed);

	return id >= busy;
}

kern_return_t
mach_vm_reclaim_synchronize(mach_vm_reclaim_ringbuffer_v1_t ringbuffer, mach_vm_size_t num_entries_to_reclaim)
{
	if (ringbuffer == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return mach_vm_deferred_reclamation_buffer_synchronize(mach_task_self(), num_entries_to_reclaim);
}

#endif /* defined(__LP64__) */
