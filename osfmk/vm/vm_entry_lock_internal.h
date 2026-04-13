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

#ifndef _VM_VM_ENTRY_RW_LOCK_H_
#define _VM_VM_ENTRY_RW_LOCK_H_

#include <stdbool.h>
#include <kern/kern_types.h>
#include <vm/vm_map_xnu.h>

/*!
 * @file vm_entry_lock_internal.h
 *
 * @discussion
 * This module implements locking for VM map entries.
 *
 * This implements a reader-writer like lock whose interlock is that of the map
 * the entry belongs to.
 *
 * This reader-writer lock is writer-biased, and supports invalidation making
 * it suitable for integration with SMR.
 */

__BEGIN_DECLS
__exported_push_hidden

/*!
 * @abstract
 * Initialize the VM entry lock for the specified entry, as an invalid lock.
 * Use this when initializing an entry that should never be locked
 * (e.g. because it's going into a copy map). This will cause any lock
 * operations to panic.
 *
 * @param entry the entry whose lock should be initialized as invalid
 * @param reason the reason the lock is invalid
 */
extern void vm_entry_lock_init_invalid(
	vm_map_entry_t          entry,
	vmel_invalid_reason_t   reason);

/*!
 * @abstract
 * Initialize the VM entry lock for a map header to be invalid. Because map
 * headers contain links structures, they technically have entry locks, but
 * these locks should never be used as the links structure doesn't actually
 * represent the links corresponding to an entry.
 *
 * @param hdr the header whose lock should be initialized as invalid
 */
void
vm_map_header_init_invalid_lock(
	struct vm_map_header *hdr);


/*!
 * @abstract
 * Initialize the VM entry lock for the specified entry,
 * with it exclusively held.
 */
extern void vm_entry_lock_init_locked_exclusive(
	vm_map_t                map,
	vm_map_entry_t          entry);


/*!
 * @abstract
 * Destroy a lock previously initialized with @c vm_entry_lock_init_invalid()
 * function or invalidated with @c vm_entry_lock_invalidate, and never
 * reinitialized since.
 *
 * @discussion
 * This call will panic if the lock is valid.
 */
extern void vm_entry_lock_destroy_invalid(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Invalidate a lock that was previously marked as valid, e.g. because it
 * belongs to a constant submap which is now being sealed. The entry must
 * currently be locked, and there must not be any waiters (to avoid deadlock).
 *
 * @param entry the entry whose lock should be invalidated
 * @param reason the reason the lock is invalid
 */
extern void vm_entry_lock_invalidate(
	vm_map_entry_t          entry,
	vmel_invalid_reason_t   reason);

/*!
 * @abstract
 * Variant of @c vm_entry_lock_invalidate which re-invalidates a lock previously
 * marked as invalid, changing the invalidation reason.
 *
 * @param entry the entry whose lock should be re-invalidated
 * @param allowed_reasons a bitmask of reasons the lock may have previously been marked invalid
 * @param new_reason the new reason the lock is invalid
 */
extern void vm_entry_lock_reinvalidate(
	vm_map_entry_t          entry,
	vmel_invalid_reason_t   allowed_reasons,
	vmel_invalid_reason_t   new_reason);

/*!
 * @abstract
 * Returns whether or not this entry's lock is valid.
 *
 * @param entry The entry whose lock to check.
 */
extern bool
vm_entry_lock_is_valid(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Returns the reason an entry's lock was invalidated.
 *
 * @param entry The entry whose lock to check.
 */
extern vmel_invalid_reason_t
vm_entry_lock_invalid_reason(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Tries to acquire the entry lock in shared mode.
 *
 * @discussion
 * This function never sleeps and is adequate to call in preemption disabled
 * contexts.
 *
 * Note that @c vm_entry_try_lock_shared() will fail if the lock has been
 * destroyed by any @c vm_entry_lock_*destroy() call.
 *
 * It is required for the caller to hold the map interlock,
 * otherwise priority inversions are possible.
 *
 * @returns             @c true if the lock was acquired,
 *                      @c false otherwise.
 */
extern bool vm_entry_try_lock_shared(
	vm_map_entry_t          entry) __result_use_check;

/*!
 * @abstract
 * Tries to acquire the entry lock in exclusive mode.
 *
 * @discussion
 * This function never sleeps and is adequate to call in preemption disabled
 * contexts.
 *
 * Note that @c vm_entry_try_lock_exclusive() will fail if the lock has been
 * destroyed by any @c vm_entry_lock_*destroy() call.
 *
 * It is required for the caller to hold the map interlock,
 * otherwise priority inversions are possible.
 *
 * @returns             @c true if the lock was acquired,
 *                      @c false otherwise.
 */
extern bool vm_entry_try_lock_exclusive(
	vm_map_entry_t          entry) __result_use_check;

/*
 * Entry lock upgrade/downgrade functions are involved in complex locking
 * operations which should stay centralized in the range lock and not
 * used by clients.
 */
#ifdef VM_MAP_LOCK_PRIVATE
/*!
 * @abstract
 * Converts an entry lock from exclusive to shared mode.
 *
 * @discussion
 * The lock must be held exclusively by the current thread,
 * otherwise this function will panic.
 */
extern void vm_entry_lock_exclusive_to_shared(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Attempts to convert an entry lock from shared to exclusive mode.
 *
 * @discussion
 * The lock must be held shared by the current thread,
 * otherwise this function will panic.
 *
 * On failure, the lock is unlocked.
 */
extern bool vm_entry_lock_try_shared_to_exclusive(
	vm_map_entry_t          entry);
#endif /* VM_MAP_LOCK_PRIVATE */

/*!
 * @abstract
 * Acquires a lock for the specified entry in shared mode.
 *
 * @discussion
 * Acquiring an entry lock might fail if the entry is being deleted,
 * or no longer contains the address the caller means to acquire
 * the lock for.
 *
 * This function must be called with the VM map interlock held, as its rwlock
 * boost is borrowed while acquiring the entry lock.
 *
 * This function might sleep.
 *
 * @param map           The map this entry belongs to.
 *                      This map interlock must be held.
 *
 * @param map_held      How the map interlock is being held.
 *
 * @param entry         The entry to lock.
 *
 * @param addr          The address the caller is interested in.
 *
 * @param how           How to wait/sleep.
 *
 * @returns
 * - KERN_SUCCESS       the lock was acquired,
 * - VMRL_ERR_ABORTED   if the sleep was interruptible and the wait aborted.
 * - VMRL_ERR_RELOOKUP  if the entry was deleted, or its address range modified,
 *                      and the caller needs to look it up again.
 */
extern kern_return_t vm_entry_lock_shared(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how) __result_use_check;

/*!
 * @abstract
 * Acquires a lock for the specified entry in exclusive mode.
 *
 * @discussion
 * Acquiring an entry lock might fail if the entry is being deleted,
 * or no longer contains the address the caller means to acquire
 * the lock for.
 *
 * This function must be called with the VM map interlock held, as its rwlock
 * boost is borrowed while acquiring the entry lock.
 *
 * This function might sleep.
 *
 * @param map           The map this entry belongs to.
 *                      This map interlock must be held.
 *
 * @param map_held      How the map interlock is being held.
 *
 * @param entry         The entry to lock.
 *
 * @param addr          The address the caller is interested in.
 *
 * @param how           How to wait/sleep.
 *
 * @returns
 * - KERN_SUCCESS       the lock was acquired,
 * - VMRL_ERR_ABORTED   if the sleep was interruptible and the wait aborted.
 * - VMRL_ERR_RELOOKUP  if the entry was deleted, or its address range modified,
 *                      and the caller needs to look it up again.
 */
extern kern_return_t vm_entry_lock_exclusive(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how) __result_use_check;


/*!
 * @abstract
 * Unlocks an entry that was locked in shared mode.
 *
 * @discussion
 * This function never sleeps and is safe to call from preemption disabled
 * contexts.
 *
 * The entry must have been locked successfully with @c vm_entry_lock_shared()
 * or @c vm_entry_try_lock_shared() by the current thread, otherwise this
 * call might panic.
 *
 * @param map           The map this entry belongs to.
 *
 * @param entry         The entry to unlock.
 */
extern void vm_entry_unlock_shared(
	vm_map_t                map,
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Unlocks an entry that was locked in exclusive mode.
 *
 * @discussion
 * This function never sleeps and is safe to call from preemption disabled
 * contexts.
 *
 * The entry must have been locked successfully with @c vm_entry_lock_exclusive()
 * or @c vm_entry_try_lock_exclusive() by the current thread, otherwise this
 * call will panic.
 *
 * @param map           The map this entry belongs to.
 *
 * @param entry         The entry to unlock.
 */
extern void vm_entry_unlock_exclusive(
	vm_map_t                map,
	vm_map_entry_t          entry);


/*!
 * @abstract
 * Invalidate all waiters because the bounds of the entry changed.
 *
 * @discussion
 * This function never sleeps and is safe to call from preemption disabled
 * contexts.
 *
 * The entry must have been locked successfully with @c vm_entry_lock_exclusive()
 * or @c vm_entry_try_lock_exclusive() by the current thread, otherwise this
 * call will panic.
 *
 * This function should be called with the interlock held.
 *
 * @param map           The map this entry belongs to.
 *
 * @param entry         The entry to invalidate.
 */
extern void vm_entry_invalidate_waiters(
	vm_map_t                map,
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Unlock and destroys a vm entry lock.
 *
 * @discussion
 * This function never sleeps and is safe to call from preemption disabled
 * contexts.
 *
 * The entry must have been locked successfully with @c vm_entry_lock_exclusive()
 * or @c vm_entry_try_lock_exclusive() by the current thread, otherwise this
 * call will panic.
 *
 * The lock will become destroyed, and all possible waiters woken up.  The state
 * of the lock will be as if @c vm_entry_lock_destroy() had been called.
 *
 * @param map           The map this entry belongs to.
 *
 * @param entry         The entry to unlock.
 */
extern void vm_entry_unlock_exclusive_and_destroy(
	vm_map_t                map,
	vm_map_entry_t          entry);

/*
 * These operations involve relatively complex locking to implement correctly.
 * Clients should rely on the range lock behavior (potentially with the
 * VMRL_SIMPLIFY flag or VMRL_ERR_WAIT_FOR_KUNWIRE preflight return code) to
 * handle these operations as appropriate.
 */
#ifdef VM_MAP_LOCK_PRIVATE
/*!
 * @abstract
 * Returns whether an entry has the needs-coalesce bit set.
 *
 * @param entry         The entry to query.
 * @returns             Whether needs-coalesce is set (true) or not (false).
 */
extern bool vm_entry_needs_coalesce(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Sets/clears the needs-coalesce bit on the entry.
 *
 * @param entry         The entry to modify.
 * @param value         Whether to set (true) or clear (false) the bit.
 */
extern void vm_entry_update_needs_coalesce(
	vm_map_entry_t          entry,
	bool                    value);


/*!
 * @abstract
 * Sleeps on an entry until vm_entry_wakeup_kunwire_waiters() is called,
 * or it is destroyed.
 *
 * @param map           The map this entry belongs to.
 *                      This map interlock must be held,
 *                      and will be unlocked on return.
 *
 * @param map_held      How the map interlock is being held.
 *
 * @param entry         The specified entry.
 *
 * @param addr          The address the caller is interested in.
 *
 * @param how           How to wait/sleep.
 *
 * @returns
 * - KERN_SUCCESS       the wait ended, and the entry is stable.
 * - VMRL_ERR_ABORTED   if the sleep was interruptible and the wait aborted.
 * - VMRL_ERR_RELOOKUP  the wait ended, and the entry was deleted, or its
 *                      address range modified, and the caller needs
 *                      to look it up again.
 */
extern kern_return_t vm_entry_unlock_and_wait_for_kunwire(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how) __result_use_check;
#endif /* VM_MAP_LOCK_PRIVATE */

/*!
 * @abstract
 * Wake up all threads waiting in @c vm_entry_unlock_and_wait_for_kunwire() for
 * this entry.
 *
 * @discussion
 * This function never sleeps and is adequate to call in preemption disabled
 * contexts.
 */
extern void vm_entry_wakeup_kunwire_waiters(
	vm_map_entry_t          entry);


/*!
 * @abstract
 * Asserts that the current entry lock is valid.
 */
extern void vm_entry_assert_lock_is_valid(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Asserts that the current entry lock is invalid, and that the invalidation
 * reason matches one of the provided reasons.
 */
extern void vm_entry_assert_lock_is_invalid(
	vm_map_entry_t          entry,
	vmel_invalid_reason_t   allowed_reasons);


/*!
 * @abstract
 * Asserts that the current thread owns the lock on this entry in some form
 * (shared or exclusive), i.e. the assert may pass even though the lock is not
 * held by this thread.
 *
 * @discussion
 * Note that asserting the lock is held shared or exclusively is approximate and
 * has false positives.
 */
extern void vm_entry_assert_owner(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Asserts that the current thread owns the lock on this entry exclusively.
 *
 * @discussion
 * Note that asserting the lock is held exclusively is approximate and has false
 * positives, i.e. the assert may pass even though the lock is not held
 * exclusively by this thread. This is because (when MAP_ENTRY_LOCK_DEBUG is
 * not set), the entry lock bits do not encode the actual owner of the lock.
 */
extern void vm_entry_assert_excl_owner(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Asserts that the current thread owns the lock on this entry exclusively,
 * or that the current thread is otherwise permitted to make modification
 * to the entry's fields.
 *
 * @discussion
 * Note that asserting the lock is held exclusively is approximate and has false
 * positives, i.e. the assert may pass even though the lock is not held
 * exclusively by this thread.
 */
extern void vm_entry_assert_fields_writable(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Asserts that the current thread owns the lock on this entry in shared mode.
 *
 * @discussion
 * Note that asserting the lock is held shared is approximate and has false
 * positives, i.e. the assert may pas even though the lock is not held shared
 * by this thread. This is because the entry lock bits only encode the reader
 * count, not the list of shared owners.
 */
extern void vm_entry_assert_shared_owner(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Asserts that the entry lock on this entry is valid and that the current thread
 * doesn't owns the lock on this entry in any form (shared or exclusive).
 *
 * @discussion
 * Note that this assertion actually can't tell if the current thread
 * owns the lock in shared or exclusive mode and will have false positives.
 */
extern void vm_entry_assert_not_owner(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Returns whether the entry lock is held exclusively for the sake
 * of stackshots.
 */
extern bool kdp_vm_entry_lock_is_acquired_exclusive(
	vm_map_entry_t          entry);

/*!
 * @abstract
 * Returns the vm_map_entry associated with a kThreadWaitVMEntry* event.
 */
extern vm_map_entry_t kdp_vm_entry_from_event(
	event64_t               event,
	block_hint_t            hint);


#if MACH_ASSERT
#define VM_ENTRY_ASSERT_LOCK_VALID(entry) vm_entry_assert_lock_is_valid(entry)
#define VM_ENTRY_ASSERT_LOCK_INVALID(entry, allowed_reasons) vm_entry_assert_lock_is_invalid(entry, allowed_reasons)
#define VM_ENTRY_ASSERT_OWNER(entry) vm_entry_assert_owner(entry)
#define VM_ENTRY_ASSERT_EXCL_OWNER(entry) vm_entry_assert_excl_owner(entry)
#define VM_ENTRY_ASSERT_FIELDS_WRITABLE(entry) vm_entry_assert_fields_writable(entry)
#define VM_ENTRY_ASSERT_SHARED_OWNER(entry) vm_entry_assert_shared_owner(entry)
#define VM_ENTRY_ASSERT_NOT_OWNER(entry) vm_entry_assert_not_owner(entry)
#else /* !MACH_ASSERT */
#define VM_ENTRY_ASSERT_LOCK_VALID(entry) ((void)(entry))
#define VM_ENTRY_ASSERT_LOCK_INVALID(entry, allowed_reasons) ({(void)(entry);(void)(allowed_reasons);})
#define VM_ENTRY_ASSERT_OWNER(entry) ((void)(entry))
#define VM_ENTRY_ASSERT_EXCL_OWNER(entry) ((void)(entry))
#define VM_ENTRY_ASSERT_FIELDS_WRITABLE(entry) ((void)(entry))
#define VM_ENTRY_ASSERT_SHARED_OWNER(entry) ((void)(entry))
#define VM_ENTRY_ASSERT_NOT_OWNER(entry) ((void)(entry))
#endif /* !MACH_ASSERT */

__exported_pop
__END_DECLS

#endif /*  _VM_VM_ENTRY_RW_LOCK_H_ */
