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

#ifndef KERN_MPSC_RING_H
#define KERN_MPSC_RING_H

/**
 * @header
 * This is an atomic multi-producer, single-consumer ringbuffer.  Producers do
 * not need to synchronize with each other, but only a single consumer can be
 * active at one time.
 *
 * @discussion
 * The data structures are defined here to allow them to be stored intrusively
 * in other structures.  Their fields are only documented to aid in
 * understanding; do not manipulate them outside of the function interfaces
 * declared below.
 */

#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * The data structure for an MPSC ringbuffer.
 *
 * @field mr_buffer
 * The buffer that stores data, @link mr_capacity @/link in size.  Field is
 * constant after initialization but contents will be updated by writers.
 *
 * @field mr_capacity
 * The size of the buffer to store data.  Field is constant after
 * initialization.
 *
 * @field mr_writer_holds
 * Any pending reservations on the buffer, sized by @link mr_writer_count
 * @/link.  Field is constant after initialization but array elements will be
 * updated by writers.
 *
 * @field mr_writer_count
 * The number of concurrent potential writers.  Field is constant after
 * initialization.
 *
 * @field mr_head_tail
 * A 64-bit value that holds the head and tail of the ringbuffer.
 */
struct mpsc_ring {
	char *mr_buffer;
	uint32_t *mr_writer_holds;

	/**
	 * A view into the head, tail, and both offsets in the ringbuffer.
	 *
	 * @field mrht_head
	 * The head offset into the ringbuffer data, where writers will write new
	 * data.
	 *
	 * @field mrht_tail
	 * The tail offset into the ringbuffer data, where the reader has read up
	 * to.
	 *
	 * @field mrht_head_tail
	 * A combined view of head and tail for atomic updates.
	 */
	union mpsc_ring_head_tail {
		struct {
			uint32_t mrht_head;
			uint32_t mrht_tail;
		};
		uint64_t mrht_head_tail;
	} mr_head_tail;

	uint32_t mr_capacity;
	uint8_t mr_writer_count;
};

/**
 * Initialize the ringbuffer.
 *
 * @discussion
 * This must be called from a preemptible context, as it allocates memory.
 *
 * @param buf
 * The ringbuffer to initialize.
 *
 * @param capacity_pow_2
 * The size of the ringbuffer as a power of 2.  For example, passing 10 here
 * would allocate 2^10 (1KiB) bytes.
 *
 * @param writers_max
 * The maximum number of writers that will be active at once.
 */
void mpsc_ring_init(
	struct mpsc_ring *buf,
	uint8_t capacity_pow_2,
	uint8_t writers_max);

/**
 * Write data to the ringbuffer.
 *
 * @discussion
 * No external synchronization or mutual exclusion is necessary.
 *
 * @param buf
 * The ringbuffer to write data to.
 *
 * @param writer_id
 * The identity of the writer, must be less than the maximum writer count passed
 * to @link mpsc_ring_init @/link.
 *
 * @param data
 * The memory location to data to write to the ringbuffer.
 *
 * @param size
 * The size of the memory location to write.
 *
 * @return
 * Returns how much space was available before trying to write.
 * Compare this to the requested write size to determine if the data was
 * written.
 */
uint32_t mpsc_ring_write(
	struct mpsc_ring *buf,
	uint8_t writer_id,
	const void *data,
	uint32_t size);

/**
 * A cursor to read data out of a ringbuffer.
 *
 * @discussion
 * This structure is defined in the header to allow it to be treated as a value.
 * Do not manipulate its fields manually.
 *
 * @field mrc_commit_pos
 * The position of the cursor that will be written back to the ringbuffer when
 * the read finishes.
 *
 * @field mrc_pos
 * The position of the cursor to read data from in @link
 * mpsc_ring_cursor_advance @/link.
 *
 * @field mrc_limit
 * The maximum position that the cursor can advance.
 */
typedef struct {
	uint32_t mrc_commit_pos;
	uint32_t mrc_pos;
	uint32_t mrc_limit;
} mpsc_ring_cursor_t;

/**
 * Read data from the ringbuffer, consuming it.
 *
 * @discussion
 * Only one thread may call this function at a time for the same buffer.
 * This function must be paired with @link mpsc_ring_read_finish @/link or
 * @link mpsc_ring_read_cancel @/link.
 *
 * @param buf
 * The ringbuffer to start reading from.
 *
 * @return
 * Returns a cursor to consume data from the ringbuffer.
 */
mpsc_ring_cursor_t mpsc_ring_read_start(struct mpsc_ring *buf);

/**
 * Advance the cursor, copying it out of the ringbuffer and updating the next
 * position to advance from.
 *
 * @param buf
 * The ringbuffer the cursor is associated with.
 *
 * @param cursor
 * The cursor to advance.
 *
 * @param destination
 * The memory to write the ringbuffer contents into.
 *
 * @param size
 * The amount of ringbuffer contents to read.
 *
 * @return
 * True iff all the requested memory can be read, false otherwise.
 */
bool mpsc_ring_cursor_advance(
	const struct mpsc_ring *buf,
	mpsc_ring_cursor_t *cursor,
	void *destination,
	uint32_t size);

/**
 * Commit any advancements in the cursor, ensuring that @link
 * mpsc_ring_read_finish @/link will consume the memory up to the last call to
 * @link mpsc_ring_cursor_advance @/link.
 *
 * @param buf
 * The ringbuffer the cursor is associated with.
 *
 * @param cursor
 * The cursor to commit advancements on.
 */
void mpsc_ring_cursor_commit(
	const struct mpsc_ring *buf,
	mpsc_ring_cursor_t *cursor);

/**
 * Complete a read operation on the ringbuffer after manipulating a cursor.
 *
 * @discussion
 * This function msut only be called after a previous call to @link
 * mpsc_ring_read_start @/link.  This call consumes the cursor and no further
 * operations can be called on it.
 *
 * @param buf
 * The ringbuffer to end reading on.
 *
 * @param cursor
 * The cursor provided by @link mpsc_ring_read_start @/link.
 */
void mpsc_ring_read_finish(
	struct mpsc_ring *buf,
	mpsc_ring_cursor_t cursor);

/**
 * Cancel a read operation on the ringbuffer, destroying the cursor and rolling
 * back any advancement into the buffer.
 *
 * @discussion
 * This function must only be called after a previous call to @link
 * mpsc_ring_read_start @/link.  This call consumes the cursor and no further
 * operations can be called on it.
 *
 * @param buf
 * The ringbuffer to cancel a read from.
 *
 * @param cursor
 * The cursor provided by @link mpsc_ring_read_start @/link.
 */
void
mpsc_ring_read_cancel(
	struct mpsc_ring *buf,
	mpsc_ring_cursor_t cursor);

__END_DECLS

#endif /* !defined(KERN_MPSC_RING_H) */
