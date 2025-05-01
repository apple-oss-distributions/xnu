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

#include "kpc.h"
#include <kern/mpsc_ring.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <os/atomic_private.h>

/*
 * This ringbuffer has the following constraints:
 *
 * - Multiple-producer: More than one thread will need to write into the buffer
 *   at once.
 * - Single-consumer: Only the single reader under the global lock will consume
 *   and send samples to user space.
 * - Bounded: Writers will drop their data if there's no space left to write.
 * - Known-parallelism: A fixed number of writers.
 *
 * The ringbuffer that stores the kernel samples has a region of allocated
 * memory and offsets that are maintained by the reader and writers. The
 * offsets are 32-bits but typically updated atomically as a single 64-bit
 * value. "Head" refers to an offset used for writing and "tail" is the offset
 * for reading.
 *
 * Writers follow a reserve-commit scheme to ensure that no other writer can
 * interfere with their view into the region and the reader only sees
 * fully-written data.  To get a view that can store their data, the writers do
 * a relaxed load of the offsets and determine how to update the next writer
 * offset.  The next operations happen in a loop:
 *
 * - Add the size of the data to be written to a local copy of the `head`
 *   offset.
 * - Reserve their interest in the write offset by updating a per-CPU "holds"
 *   list with the current `head` value.
 * - Do a compare-exchange on the offsets to attempt with the updated `head`
 *   offset.
 * - If this fails, continue the loop with updated values of the offsets.
 * - Otherwise, exit the loop.
 *
 * The reader will do an atomic load of the offsets with an acquire barrier and
 * remember the writer's offset.  Then it will loop through the per-CPU holds
 * and look for the one with the earliest offset.  That value, combined with
 * the writer's offset, is the furthest it can safely read samples.
 *
 * Here's a typical ringbuffer in use:
 *
 *                                                hold by 2
 *                                                ●       hold by 0
 *                                                │       ●
 *                                                │       │
 *  ┌─────────────────────────────────────────────▼───────▼─────────────┐
 *  │        █████████████████████████████████████░░░░░░░░░░░░          │
 *  └────────▲────────────────────────────────────────────────▲─────────┘
 *  0        │                                                │         capacity
 *           ●                                                ●
 *           tail                                             head
 *
 * The filled region after `tail` has been written and is ready to be read.  The
 * unfilled region has already been read and is available for writing.  There
 * are two concurrent writers (with IDs 2 and 0) with holds outstanding, marked
 * by the shaded region.  Here's a different configuration, after the `head`
 * has wrapped and with the reader "caught up" to the writers:
 *
 *                                                            hold by 3
 *                                                            ●
 *                                                            │
 *  ┌─────────────────────────────────────────────────────────▼─────────┐
 *  │░░░░                                                     ░░░░░░░░░░│
 *  └────▲────────────────────────────────────────────────────▲─────────┘
 *  0    │                                                    │         capacity
 *       ●                                                    ●
 *       head                                                 tail
 *
 * There's one writer active (ID 3), so `tail` can't advance past it. And
 * finally, here's a configuration where there's no more buffer space available
 * for writing:
 *
 *  ┌───────────────────────────────────────────────────────────────────┐
 *  │█████████████████████████████████████████████████████****██████████│
 *  └─────────────────────────────────────────────────────▲───▲─────────┘
 *  0                                                     │   │         capacity
 *                                                        ●   ●
 *                                                     head   tail
 *
 * Almost the entire buffer is waiting to be read.  The `*` between `head` and
 * `tail` is "wasted" space because writers need a contiguous region of memory
 * to write into. In this case, there's not enough of it before running into
 * `tail`.
 */

#define HOLD_EMPTY (~0)

void
mpsc_ring_init(
	struct mpsc_ring *buf,
	uint8_t capacity_pow_2,
	uint8_t writers_max)
{
	/*
	 * Check that this ringbuffer hasn't already been initialized.
	 */
	assert3p(buf->mr_buffer, ==, NULL);
	assert3u(buf->mr_capacity, ==, 0);

	/*
	 * Check for reasonable capacity values.
	 */
	assert3u(capacity_pow_2, <, 30);
	assert3u(capacity_pow_2, >, 0);

	/*
	 * Must be more than one potential writer.
	 */
	assert3u(writers_max, >, 0);

	*buf = (struct mpsc_ring){ 0 };

	/*
	 * Allocate the data buffer to the specified capacity.
	 */
	uint32_t capacity = 1U << capacity_pow_2;
	buf->mr_buffer = kalloc_data_tag(
		capacity,
		Z_WAITOK | Z_ZERO,
		VM_KERN_MEMORY_DIAG);
	if (!buf->mr_buffer) {
		panic(
			"mpsc_ring_init: failed to allocate %u bytes for buffer",
			capacity);
	}
	buf->mr_capacity = capacity;

	/*
	 * Allocate the per-writer holds array.
	 */
	size_t holds_size = writers_max * sizeof(buf->mr_writer_holds[0]);
	buf->mr_writer_holds = kalloc_data_tag(
		holds_size,
		Z_WAITOK | Z_ZERO,
		VM_KERN_MEMORY_DIAG);
	if (!buf->mr_writer_holds) {
		panic(
			"mpsc_ring_init: failed to allocate %zu bytes for holds",
			holds_size);
	}
	buf->mr_writer_count = writers_max;

	/*
	 * Initialize the holds to be empty.
	 */
	for (uint8_t i = 0; i < writers_max; i++) {
		buf->mr_writer_holds[i] = HOLD_EMPTY;
	}
	buf->mr_head_tail = (union mpsc_ring_head_tail){ 0 };
	/*
	 * Publish these updates.
	 */
	os_atomic_thread_fence(release);
}

/**
 * Copy to or from the ringbuffer, taking wrap around at the end into account.
 *
 * @discussion
 * This function does not enforce any bounds checking on the head or tail
 * offsets and is a helper for higher-level interfaces.
 *
 * @param buf
 * The ringbuffer to copy into or out of.
 *
 * @param offset
 * The offset to start the copy operation at.
 *
 * @param data
 * The input or output buffer.
 *
 * @param size
 * The amount of bytes to copy.
 *
 * @param in
 * The direction of the copy. True to treat @link data @/link as a source and
 * copy into the ringbuffer and false to tread @link data @/link as a
 * destination and copy out of the ringbuffer.
 */
OS_ALWAYS_INLINE
static void
_mpsc_ring_copy(
	const struct mpsc_ring *buf,
	uint32_t offset,
	void *data,
	uint32_t size,
	bool in)
{
	/*
	 * Find the offset into the ringbuffer's memory.
	 */
	uint32_t const offset_trunc = offset % buf->mr_capacity;

	/*
	 * Determine how much contiguous space is left in the ringbuffer for a
	 * single memcpy.
	 */
	uint32_t const left_contig = buf->mr_capacity - offset_trunc;
	uint32_t const size_contig = MIN(left_contig, size);
	memcpy(in ? &buf->mr_buffer[offset_trunc] : data,
	    in ? data : &buf->mr_buffer[offset_trunc],
	    size_contig);
	if (size_contig != size) {
		/*
		 * If there's any leftover data uncopied, copy it at the start of the
		 * ringbuffer.
		 */
		uint32_t const size_left = size - size_contig;
		void * const data_left = (char *)data + size_contig;
		memcpy(in ? buf->mr_buffer : data_left,
		    in ? data_left : buf->mr_buffer,
		    size_left);
	}
}

uint32_t
mpsc_ring_write(
	struct mpsc_ring *buf,
	uint8_t writer_id,
	const void *data,
	uint32_t size)
{
	/*
	 * Get an initial guess at where to write.
	 */
	union mpsc_ring_head_tail head_tail = os_atomic_load(
		&buf->mr_head_tail,
		relaxed);
	union mpsc_ring_head_tail new_head_tail = { 0 };

	os_atomic_rmw_loop(
		&buf->mr_head_tail.mrht_head_tail,
		head_tail.mrht_head_tail /* old */,
		new_head_tail.mrht_head_tail /* new */,
		release,
	{
		/*
		 * Check for empty space in the buffer.
		 */
		uint32_t const leftover = head_tail.mrht_head + size - head_tail.mrht_tail;
		if (leftover >= buf->mr_capacity) {
		        /*
		         * Not enough space available for all the data, so give up.
		         */
		        os_atomic_rmw_loop_give_up(goto out);
		}

		/*
		 * Compute a new head offset based on the size being written.
		 */
		new_head_tail = head_tail;
		new_head_tail.mrht_head += size;

		/*
		 * Reserve the start of the space with a hold.
		 */
		os_atomic_store(
			&buf->mr_writer_holds[writer_id],
			head_tail.mrht_head,
			relaxed);
	});

	_mpsc_ring_copy(buf, head_tail.mrht_head, (void *)(uintptr_t)data, size, true);

out:
	/*
	 * Release the hold value so it can synchronize with acquires on the read
	 * side.
	 */
	os_atomic_store(&buf->mr_writer_holds[writer_id], HOLD_EMPTY, release);
	return buf->mr_capacity - (head_tail.mrht_head - head_tail.mrht_tail);
}

mpsc_ring_cursor_t
mpsc_ring_read_start(struct mpsc_ring *buf)
{
	/*
	 * Acquire to ensure that any holds updated are visible.
	 */
	union mpsc_ring_head_tail head_tail = os_atomic_load(&buf->mr_head_tail, acquire);
	for (uint8_t i = 0; i < buf->mr_writer_count; i++) {
		/*
		 * Check for any earlier holds to avoid reading past writes-in-progress.
		 */
		uint32_t hold = os_atomic_load(&buf->mr_writer_holds[i], relaxed);
		if (hold != ~0) {
			head_tail.mrht_head = MIN(head_tail.mrht_head, hold);
		}
	}

	return (mpsc_ring_cursor_t){
		       .mrc_commit_pos = head_tail.mrht_tail,
		       .mrc_pos = head_tail.mrht_tail,
		       .mrc_limit = head_tail.mrht_head,
	};
}

bool
mpsc_ring_cursor_advance(
	const struct mpsc_ring *buf,
	mpsc_ring_cursor_t *cursor,
	void *target,
	uint32_t size)
{
	if (size > cursor->mrc_limit - cursor->mrc_pos) {
		return false;
	}
	_mpsc_ring_copy(buf, cursor->mrc_pos, target, size, false);
	cursor->mrc_pos += size;
	return true;
}

void
mpsc_ring_cursor_commit(
	const struct mpsc_ring * __unused buf,
	mpsc_ring_cursor_t *cursor)
{
	cursor->mrc_commit_pos = cursor->mrc_pos;
}

void
mpsc_ring_read_finish(
	struct mpsc_ring *buf,
	mpsc_ring_cursor_t cursor)
{
	/*
	 * Relaxed, as there's no need to synchronize with any other readers: this
	 * ringbuffer is single-consumer.
	 */
	os_atomic_store(&buf->mr_head_tail.mrht_tail, cursor.mrc_commit_pos, relaxed);
}

void
mpsc_ring_read_cancel(
	struct mpsc_ring * __unused buf,
	mpsc_ring_cursor_t __unused cursor)
{
	/*
	 * Nothing to do; just "consume" the cursor.
	 */
}
