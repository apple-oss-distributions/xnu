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

#ifndef _VM_RECLAIM_H_
#define _VM_RECLAIM_H_

#if defined(__LP64__)

#include <Availability.h>
#include <mach/error.h>
#include <mach/mach_types.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/// The action to be performed by the kernel on reclamation of an entry
///  - `VM_RECLAIM_FREE` - Free the backing memory contents but preserve the
///    mapping (analagous to `madvise(MADV_FREE_REUSABLE)`)
///  - `VM_RECLAIM_DEALLOCATE` - Deallocate the virtual mapping and
///    its backing memory (analagous to `munmap()`)
__enum_decl(mach_vm_reclaim_action_t, uint8_t, {
	VM_RECLAIM_FREE       = 1,
	VM_RECLAIM_DEALLOCATE = 2,
});

/// Describes the state of a memory region in the ring
__enum_decl(mach_vm_reclaim_state_t, uint32_t, {
	VM_RECLAIM_UNRECLAIMED = 1,
	VM_RECLAIM_FREED       = 2,
	VM_RECLAIM_DEALLOCATED = 3,
	VM_RECLAIM_BUSY        = 4,
});

#define err_vm_reclaim(e) (err_vm | err_sub(1) | e)

__enum_decl(mach_vm_reclaim_error_t, mach_error_t, {
	VM_RECLAIM_SUCCESS             = ERR_SUCCESS,
	VM_RECLAIM_INVALID_ARGUMENT    = err_vm_reclaim(1),
	VM_RECLAIM_NOT_SUPPORTED       = err_vm_reclaim(2),
	VM_RECLAIM_INVALID_REGION_SIZE = err_vm_reclaim(3),
	VM_RECLAIM_INVALID_CAPACITY    = err_vm_reclaim(4),
	VM_RECLAIM_INVALID_ID          = err_vm_reclaim(5),
	VM_RECLAIM_RESOURCE_SHORTAGE   = err_vm_reclaim(6),
	VM_RECLAIM_INVALID_RING        = err_vm_reclaim(7),
});

/// The handle for a deferred reclamation ring
typedef struct mach_vm_reclaim_ring_s *mach_vm_reclaim_ring_t;

/// Counts a number of memory regions ("entries") that can be represented in a
/// ring
typedef uint32_t mach_vm_reclaim_count_t;

/// A unique id representing a memory region ("entry") placed into a
/// reclamation ring
typedef uint64_t mach_vm_reclaim_id_t;

#if !KERNEL
/// A null-value reclaim ID. May be used to distinguish regions that have not
/// yet been entered into a ring from those that have.
#define VM_RECLAIM_ID_NULL UINT64_MAX

/// The maximum virtual size supported for an individual region to be marked free.
#define VM_RECLAIM_REGION_SIZE_MAX ((mach_vm_size_t)UINT32_MAX)

/// Allocate & initialize a deferred reclamation ring.
///
/// Will allocate and initialize a ring to be shared with the kernel.
/// Only one ring may be initialized per task. Not all platforms/devices
/// support deferred reclamation.
///
/// It is recommended that callers start with a modestly sized initial capacity
/// and resize as the capacity is exhausted to minimize unneeded memory usage.
/// Callers should pass capacities that have been rounded via
/// ``mach_vm_reclaim_round_capacity()``.
///
/// - Parameters:
///   - ring: a handle to the newly allocated reclaim ring (out)
///   - initial_capacity: The initial capacity (in number of regions) of the
///     reclaim ring to allocate
///   - max_capacity: The maximum capacity that the ring may eventually grow
///     to with ``mach_vm_reclaim_ring_resize()``.
///
/// - Returns: If the current device does not support deferred reclamation,
///   returns `VM_RECLAIM_UNSUPPORTED`. If the provided max_capacity is not
///   properly rounded and exceeds system limits, returns
///   `VM_RECLAIM_INVALID_CAPACITY`. If a ring has already been instantiaed,
///   returns `VM_RECLAIM_RESOURCE_SHORTAGE`.
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_ring_allocate(
	mach_vm_reclaim_ring_t *ring,
	mach_vm_reclaim_count_t initial_capacity,
	mach_vm_reclaim_count_t max_capacity);

/// Re-size a deferred reclamation ring.
///
/// Note that all outstanding reclamation requests will be completed as part of
/// the resize operation.
///
/// `mach_vm_reclaim_resize()` is *not* thread-safe w.r.t. itself and other
/// reclamation operations (i.e. ``mach_vm_reclaim_try_enter()``,
/// ``mach_vm_reclaim_try_cancel()``). Callers must provide their own
/// synchronization.
///
/// - Parameters:
///   - ring: The ring to resize.
///   - capacity: The new capacity (in number of regions). Must be <= the max
///     capacity specified during ring allocation.
///
/// - Returns: If the requested capacity exceeds the maximum capacity specified
///   when the ring was allocated, returns `VM_RECLAIM_INVALID_CAPACITY`.
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_ring_resize(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_count_t capacity);

/// Get the maximum number of memory regions that can be simultaneously placed
/// (i.e. marked free) in the ring.
///
/// - Parameters:
///   - ring: a reclaim ring
///   - capacity: the capacity of the specified ring (out)
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_ring_capacity(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_count_t *capacity);

/// Round the given ring capacity to the maximum size that could fit
/// within the closest vm page size multiple. Will round down if the requested
/// capacity exceeds the maximum allowable capacity.
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_count_t mach_vm_reclaim_round_capacity(
	mach_vm_reclaim_count_t capacity);

/// Force the kernel to reclaim at least num_entries_to_reclaim entries from
/// the ring (if present).
///
/// ``mach_vm_reclaim_synchronize()`` _is_ thread-safe w.r.t. all other
/// mach_vm_reclaim operations.
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_ring_flush(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_count_t num_entries_to_reclaim);

/// Attempt to enter a reclamation request into the ring.
///
/// This will update the userspace reclaim ring accounting, but will not
/// inform the kernel about the new bytes in the ring. If the kernel should be informed,
/// should_update_kernel_accounting will be set to true and the caller should call
/// ``mach_vm_reclaim_update_kernel_accounting()``.
/// ``mach_vm_reclaim_update_kernel_accounting()`` may result in synchronous
/// reclamation operations, so this gives the caller an opportunity to first
/// drop any locks.
///
/// The `id` in/out parameter may be used to place the memory region in an
/// otherwise unused entry in the ring previously associated with a request
/// that has been cancelled. This interface will provide a maximally compact
/// ring, minimizing the likelihood of exhausting the ring's capacity. This
/// efficiency comes at the cost of LRU approximation because reclamations will
/// always occur in ascending order of ID. If a non-null ID is specified, the
/// caller must ensure it is not currently occupied by another memory region
/// (i.e. the caller must have called ``mach_vm_reclaim_mark_used()`` on this
/// ID since the last free operation).
///
/// If the ring is full, the caller may wish to synchronously reclaim part
/// of the ring via ``mach_vm_reclaim_flush()`` or attempt to grow the ring
/// via ``mach_vm_reclaim_ring_resize()``.
///
/// `mach_vm_reclaim_try_enter()` is *not* thread-safe w.r.t. itself and other
/// reclamation operations (i.e. ``mach_vm_reclaim_resize()``,
/// ``mach_vm_reclaim_try_cancel()``). Callers must provide their own
/// synchronization.
///
/// - Parameters:
///   - ring: The ring in which to place the memory region
///   - region_start: The starting address of the memory region to be freed
///   - region_size: The size of the memory region to be freed (in bytes) --
///     must be <= ``MACH_VM_RECLAIM_REGION_SIZE_MAX``.
///   - action: How to reclaim the entry. See ``mach_vm_reclaim_action_t``.
///   - id: (in/out) The desired ID of the reclaim entry for later re-use. If the
///     requested ID is ``VM_RECLAIM_ID_NULL``, then an new ID will be
///     chosen and written out on success. If the specified ID is unavailable
///     or no ID was specified and the ring is at capacity, then
///     ``VM_RECLAIM_ID_NULL`` will be written out.
///   - should_update_kernel_accounting: Out-parameter indicating if kernel
///     accounting should be updated via
///     ``mach_vm_reclaim_update_kernel_accounting()``
///
/// - Returns: If region_size` is greater than ``VM_RECLAIM_REGION_SIZE_MAX``,
///   returns `VM_RECLAIM_INVALID_REGION_SIZE`.
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_try_enter(
	mach_vm_reclaim_ring_t ring,
	mach_vm_address_t region_start,
	mach_vm_size_t region_size,
	mach_vm_reclaim_action_t action,
	mach_vm_reclaim_id_t *id,
	bool *should_update_kernel_accounting);

/// Attempt to cancel a previously entered reclamation request.
///
/// This operation will attempt to remove the request from the ring, ensuring
/// the memory region will not be reclaimed. The state of the memory region after the
/// cancellation attempt will be written out to `state` on success. Callers
/// should check if the memory region is safe to re-use via
/// ``mach_vm_reclaim_is_reusable()``.
///
/// Subsequent calls to ``mach_vm_reclaim_try_cancel()`` with the same id will
/// result in undefined behavior.
///
/// This will update the userspace reclaim ring accounting, but will not
/// inform the kernel about the new bytes in the ring. If the kernel should be informed,
/// should_update_kernel_accounting will be set to true and the caller should call
/// ``mach_vm_reclaim_update_kernel_accounting()``. That syscall might reclaim the ring, so
/// this gives the caller an opportunity to first drop any locks.
///
/// `mach_vm_reclaim_try_cancel()` is *not* thread-safe w.r.t. itself and other
/// reclamation operations (i.e. ``mach_vm_reclaim_resize()``,
/// ``mach_vm_reclaim_try_enter()``. Callers must provide their own
/// synchronization.
///
///  - Parameters:
///    - ring: The ring to re-use the entry from
///    - id: The unique id of the entry to re-use
///    - region_start: The virtual address of the memory region to re-use. Used to
///      assert that the entry is the same one originally placed in the ring
///    - region_size: The virtual size of the region to re-use. Used to assert that
///      the re-used entry is the same one the caller expects
///    - action: The reclamation action requested when the reclamation request was entered.
///    - state: The state of the memory region after the cancellation request (out).
///    - should_update_kernel_accounting: Out-parameter indicating if kernel
///      accounting should be updated via
///      ``mach_vm_reclaim_update_kernel_accounting()``
///
///  - Returns: `VM_RECLAIM_SUCCESS` on success
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_try_cancel(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_id_t id,
	mach_vm_address_t region_start,
	mach_vm_size_t region_size,
	mach_vm_reclaim_action_t action,
	mach_vm_reclaim_state_t *state,
	bool *should_update_kernel_accounting);

/// Query the current state of region specified by a given reclaim ID.
///
/// Note that this a read-only, thread-safe operation that may race with other
/// threads. For example, a state of `VM_RECLAIM_UNRECLAIMED` does not
/// guarantee that the region will not be immediately reclaimed or busied by
/// another thread.
///
/// - Parameters:
///   - ring: The reclaim ring containing the memory region
///   - id: The ID of the region whose state to query
///   - action: The reclaim action specified when the memory region was freed
///     to the ring
///   - state: The state of the memory region will be written out on success
///
/// - Returns: `VM_RECLAIM_SUCCESS` on success.
mach_vm_reclaim_error_t mach_vm_reclaim_query_state(
	mach_vm_reclaim_ring_t ring,
	mach_vm_reclaim_id_t id,
	mach_vm_reclaim_action_t action,
	mach_vm_reclaim_state_t *state);

/// Return whether the given memory region state is safe for re-use.
bool mach_vm_reclaim_is_reusable(
	mach_vm_reclaim_state_t state);

/// Let the kernel know how much VA is in the ring.
///
/// The kernel may choose to reclaim from the ring on this thread.
/// This should be called whenever `mach_vm_reclaim_mark_[free|used]()` returns true in
/// `should_update_kernel_accounting`. It may be called at any other time
/// if the caller wants to update the kernel's accounting and is
/// thread safe w.r.t. all other mach_vm_reclaim calls.
__SPI_AVAILABLE(macos(15.4), ios(18.4), tvos(18.4), visionos(2.4))
mach_vm_reclaim_error_t mach_vm_reclaim_update_kernel_accounting(
	mach_vm_reclaim_ring_t ring);

#endif // !KERNEL

__END_DECLS

#endif // __LP64__

#endif // _VM_RECLAIM_H_
