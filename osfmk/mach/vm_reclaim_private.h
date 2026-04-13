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
#pragma once
#if defined(__LP64__)
#include <mach/mach_types.h>
#include <mach/vm_reclaim.h>
#include <ptrcheck.h>

#define VM_RECLAIM_MAX_BUFFER_SIZE (128ull << 20)
#define VM_RECLAIM_MAX_CAPACITY ((VM_RECLAIM_MAX_BUFFER_SIZE - \
	offsetof(struct mach_vm_reclaim_ring_s, entries)) / \
	sizeof(struct mach_vm_reclaim_entry_s))

__BEGIN_DECLS

typedef struct mach_vm_reclaim_entry_s {
	mach_vm_address_t address;
	uint32_t size;
	mach_vm_reclaim_action_t behavior;
	uint8_t _unused[3];
} *mach_vm_reclaim_entry_t;

/* This struct is no longer used () */
typedef struct mach_vm_reclaim_indices_s {
	_Atomic mach_vm_reclaim_id_t head;
	_Atomic mach_vm_reclaim_id_t tail;
	_Atomic mach_vm_reclaim_id_t busy;
} *mach_vm_reclaim_indices_t;

/*
 * Contains the data used for synchronization with the kernel
 */
struct mach_vm_reclaim_ring_s {
	/* no longer used () */
	mach_vm_size_t va_in_buffer;
	/* no longer used () */
	mach_vm_size_t last_accounting_given_to_kernel;
	/* The current length of the ringbuffer */
	mach_vm_reclaim_count_t len;
	/* The maximum length of the ringbuffer */
	mach_vm_reclaim_count_t max_len;
	/* no longer used () */
	struct mach_vm_reclaim_indices_s indices;
	/* UNUSED */
	uint64_t sampling_period_abs;
	/* timestamp (MAS) of the last kernel accounting update */
	uint64_t last_sample_abs;
	/* The deadline (MAS) for the next kernel accounting update */
	_Atomic uint64_t next_sample_deadline_abs;
	/*
	 * An estimate for the number of reclaimable bytes currently in the ring. This
	 * is updating atomically after entering a new reclaimable region, after
	 * successfully cancelling a region, and after reclaiming regions.
	 */
	_Atomic mach_vm_size_t reclaimable_bytes;
	/*
	 * The minimum amount of reclaimable memory in this buffer for the current
	 * sampling interval.
	 */
	_Atomic mach_vm_size_t reclaimable_bytes_min;
	/* Marks IDs which have been reclaimed */
	_Atomic mach_vm_reclaim_id_t head;
	/* Marks IDs which are in the process of being reclaimed */
	_Atomic mach_vm_reclaim_id_t busy;
	/* The ID of the most recent entry */
	_Atomic mach_vm_reclaim_id_t tail;
	/* Pad to a multiple of the entry size */
	uint64_t _unused;
	uint64_t _unused2;
	/*
	 * The ringbuffer entries themselves populate the remainder of this
	 * buffer's vm allocation.
	 * NB: the fields preceding `entries` should be aligned to a multiple of
	 * the entry size.
	 */
	struct mach_vm_reclaim_entry_s entries[] __counted_by(len);
};

/*
 * The above definitions exist for the internal implementation in libsyscall /
 * xnu and for observability with debugging tools. They should _NOT_ be used by
 * clients.
 */

#if !KERNEL

/*
 * The below interfaces are intended for observing a task's reclaim ring(s) and
 * querying which regions are reclaimable. General usage would look something
 * like the following:
 *
 * - Use `mach_vm_reclaim_get_rings_for_task` to get a list of reclaim rings
 *   for a task.
 * - Use `mach_vm_reclaim_ring_copy` for each ring to map a copy of the
 *   reclaim ring into your address space.
 * - Use `mach_vm_reclaim_copied_ring_query` to query a list of reclaimable
 *   regions in the ring.
 * - Use `mach_vm_reclaim_copied_ring_free` to free the copied reclaim ring.
 */

/// A descriptor for a reclaimable region
typedef struct mach_vm_reclaim_region_s {
	mach_vm_address_t        vmrr_addr;
	mach_vm_size_t           vmrr_size;
	mach_vm_reclaim_action_t vmrr_behavior;
	uint8_t                  _vmrr_unused[3];
} *mach_vm_reclaim_region_t;

/// A reference to a task's reclaim ring
typedef struct mach_vm_reclaim_ring_ref_s {
	mach_vm_address_t addr;
	mach_vm_size_t size;
} *mach_vm_reclaim_ring_ref_t;

/// A reclaim ring copied from another task
typedef void *mach_vm_reclaim_ring_copy_t;

/// Get references to another task's reclaim rings.
///
/// - Parameters:
///   - task: The target task
///   - refs_out: A buffer to store the references in. If NULL, only the number
///     of rings will be queried.
///   - count_inout: A pointer to the count of the buffer, which will be
///     overwritten with the number of rings in the target task.
///
/// - Returns: `VM_RECLAIM_SUCCESS` upon success.
__SPI_AVAILABLE(macos(16.0), ios(19.0), tvos(19.0), visionos(3.0))
mach_vm_reclaim_error_t mach_vm_reclaim_get_rings_for_task(
	task_read_t task,
	mach_vm_reclaim_ring_ref_t refs_out,
	mach_vm_reclaim_count_t *count_inout);

/// Copy another task's reclaim ring into this task's VA.
///
/// - Parameters:
///   - task: The task to copy the ring from
///   - ref: The reference to the ring to copy
///     (obtained via mach_vm_reclaim_get_rings_for_task).
///   - ring_out: The pointer to the copied ring to be written out upon success
///
/// - Returns: `VM_RECLAIM_SUCCESS` upon success.
__SPI_AVAILABLE(macos(16.0), ios(19.0), tvos(19.0), visionos(3.0))
mach_vm_reclaim_error_t mach_vm_reclaim_ring_copy(
	task_read_t task,
	mach_vm_reclaim_ring_ref_t ref,
	mach_vm_reclaim_ring_copy_t *ring_out);

/// Free a reclaim ring copied from another task.
///
/// - Parameters:
///   - ring: The copied ring to free.
///
/// - Returns: `VM_RECLAIM_SUCCESS` upon success.
__SPI_AVAILABLE(macos(16.0), ios(19.0), tvos(19.0), visionos(3.0))
mach_vm_reclaim_error_t mach_vm_reclaim_copied_ring_free(
	mach_vm_reclaim_ring_copy_t *ring);

/// Query the reclaimable regions in a copied reclaim ring.
///
/// - Parameters:
///   - ring: The ring to query
///   - regions_out: A buffer of `mach_vm_reclaim_region_s` to copy the query
///     results into. If NULL, only the size of the ring will be queried.
///   - count_inout: A pointer to the size, in regions, of the buffer. Will
///     be overwritten with the count of regions in the ring upon success.
///
/// - Returns: `VM_RECLAIM_SUCCESS` on success.
///   `KERN_NO_SPACE` if there is insufficient space in the buffer to store
///   the queried ring's regions.
///   `VM_RECLAIM_INVALID_CAPACITY` if the ringbuffer structure was malformed
///   and had a buffer too small for its reported size. The entries that were
///   able to be queried and the count will still be written out.
__SPI_AVAILABLE(macos(16.0), ios(19.0), tvos(19.0), visionos(3.0))
mach_vm_reclaim_error_t mach_vm_reclaim_copied_ring_query(
	mach_vm_reclaim_ring_copy_t *ring,
	mach_vm_reclaim_region_t regions_out,
	mach_vm_reclaim_count_t *count_inout);

#endif /* !KERNEL */

__END_DECLS
#endif /* __LP64__ */
