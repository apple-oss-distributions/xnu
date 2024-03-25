/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <kern/thread.h>

#include <os/atomic.h>

#include <stdint.h>
#include <stdbool.h>

/*
 * Epoch WAIT/WAKE blocking.
 *
 * Epoch WAIT/WAKE provides a generic means to block and unblock on a turnstile
 * wait queue with minimal knowledge of the underlying synchronization
 * implementation. This is useful in environments where it's not possible to
 * block (like exclaves). No direct access to the memory backing the
 * synchronization primitive is required (in fact, the exclaves security model
 * explicitly forbids this).
 * Instead, an epoch is passed which provides an ordering and hence a means to
 * detect out-of-order WAITs/WAKEs.
 *
 * An epoch is a counter value. The epoch is incremented before calling WAKE
 * (for example when releasing a lock). Each ID maps to an associated counter.
 * Counters may be shared by multiple IDs. To avoid blocking when an owner has
 * already released its resource, the epoch is checked for freshness. A stale
 * epoch causes WAIT to immediately return without blocking. Too much sharing of
 * counters can cause waiters to return when they could have blocked.
 *
 * There are two major constraints for callers of these APIs:
 *
 * 1. The kernel's idea of the owning thread must be kept up-to-date
 *
 * - On WAIT, the owner becomes the thread described by 'owner'.
 * - On WAKE, the owner is the woken thread (iff it's not the last waiter)
 *
 * If the owning thread doesn't call back into WAIT or WAKE again it may run
 * with elevated privileges when it shouldn't.
 *
 * 2. WAITs which result in a thread blocking must be woken with WAKE
 * This one is somewhat obvious. The only way for a thread blocked in WAIT to
 * come back is to be woken with a WAKE. Pre-posted wakes (wakes when there is
 * no waiter) or stale waits (out of date epoch) return immediately.
 *
 */

__BEGIN_DECLS

struct ht;

/*
 * @struct esync_queue_ht
 *
 * @abstract Identifies the epoch sync space of synchronization objects
 * associated with "queues".
 */
extern struct ht esync_queue_ht;

/*
 * @struct esync_thread_ht
 *
 * @abstract Identifies the epoch sync space of synchronization objects
 * associated with "threads".
 */
extern struct ht esync_thread_ht;

/*!
 * @enum esync_policy_t
 *
 * @abstract Constants defining the policy associated with a synchronization
 * object.
 *
 * @constant ESYNC_POLICY_NONE
 * Unspecified.
 *
 * @constant ESYNC_POLICY_USER
 * User.
 *
 * @constant ESYNC_POLICY_KERNEL
 * Kernel.
 */
typedef enum __enum_closed {
	ESYNC_POLICY_NONE                = 0,
	ESYNC_POLICY_USER                = 1,
	ESYNC_POLICY_KERNEL              = 2,
} esync_policy_t;

/*!
 * @function esync_wait
 *
 * @abstract
 * Wait on a turnstile associated with the specified id
 *
 * @param ns
 * Namespace in which 'id' lives
 *
 * @param id
 * Synchronization object identifier
 *
 * @param epoch
 * Latest epoch of the synchronization object
 *
 * @param owner_ctid
 * Owner of the synchronization object
 *
 * @param interruptible
 * Interruptible flag
 *
 * @param policy
 * A user or kernel synchronization object
 *
 * @return
 * Result of blocking call (or THREAD_NOT_WAITING for pre-posted waits)
 */
extern wait_result_t esync_wait(struct ht *ns, uint64_t id, uint64_t epoch,
    os_atomic(uint64_t) * counter, ctid_t owner_ctid, esync_policy_t policy,
    wait_interrupt_t interruptible);

/*!
 * @enum esync_wake_mode_t
 *
 * @abstract Constants defining modes for esync_wake
 *
 * @constant ESYNC_WAKE_ONE
 * Wake a single waiter
 *
 * @constant ESYNC_WAKE_ALL
 * Wake all waiters
 *
 * @constant ESYNC_WAKE_ONE_WITH_OWNER
 * Wake a single owner and identify the new owner
 *
 * @constant ESYNC_WAKE_THREAD
 * Wake the specified thread. There is no new owner.
 */
typedef enum __enum_closed {
	ESYNC_WAKE_ONE            = 1,
	ESYNC_WAKE_ALL            = 2,
	ESYNC_WAKE_ONE_WITH_OWNER = 3,
	ESYNC_WAKE_THREAD         = 4,
} esync_wake_mode_t;

/*!
 * @function esync_wake
 *
 * @abstract
 * Wake one or more threads which have blocked on the specified id in esync_wait
 *
 * @param ns
 * Namespace in which 'id' lives
 *
 * @param id
 * Synchronization object identifier
 *
 * @param epoch
 * Latest epoch of the synchronization object
 *
 * @param mode
 * Type of wake to perform. All, one or one with specified owner (new
 * inheritor).
 *
 * @param ctid
 * Thread identifier. Can identifier the new owner (ESYNC_WAKE_ONE_WITH_OWNER)
 * or the thread to be woken (ESYNC_WAKE_THREAD).
 *
 * @return
 * KERN_SUCCESS or KERN_NOT_WAITING if no thread was woken
 */
extern kern_return_t esync_wake(struct ht *ns, uint64_t id, uint64_t epoch,
    os_atomic(uint64_t) * counter, esync_wake_mode_t mode,
    ctid_t ctid);

__END_DECLS
