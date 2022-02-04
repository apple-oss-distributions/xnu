/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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
#ifndef _KERN_LOCK_TYPES_H
#define _KERN_LOCK_TYPES_H

#include <kern/kern_types.h>

__BEGIN_DECLS

#ifdef  XNU_KERNEL_PRIVATE
#if __x86_64__
/*
 * Extended mutexes are only implemented on x86_64
 */
#define HAS_EXT_MUTEXES 1
#endif /* __x86_64__ */
#endif /* XNU_KERNEL_PRIVATE */

/*!
 * @enum lck_sleep_action_t
 *
 * @abstract
 * An action to pass to the @c lck_*_sleep* family of functions.
 */
__options_decl(lck_sleep_action_t, unsigned int, {
	LCK_SLEEP_DEFAULT      = 0x00,    /**< Release the lock while waiting for the event, then reclaim */
	LCK_SLEEP_UNLOCK       = 0x01,    /**< Release the lock and return unheld */
	LCK_SLEEP_SHARED       = 0x02,    /**< Reclaim the lock in shared mode (RW only) */
	LCK_SLEEP_EXCLUSIVE    = 0x04,    /**< Reclaim the lock in exclusive mode (RW only) */
	LCK_SLEEP_SPIN         = 0x08,    /**< Reclaim the lock in spin mode (mutex only) */
	LCK_SLEEP_PROMOTED_PRI = 0x10,    /**< Sleep at a promoted priority */
	LCK_SLEEP_SPIN_ALWAYS  = 0x20,    /**< Reclaim the lock in spin-always mode (mutex only) */
});

#define LCK_SLEEP_MASK           0x3f     /* Valid actions */

__options_decl(lck_wake_action_t, unsigned int, {
	LCK_WAKE_DEFAULT                = 0x00,  /* If waiters are present, transfer their push to the wokenup thread */
	LCK_WAKE_DO_NOT_TRANSFER_PUSH   = 0x01,  /* Do not transfer waiters push when waking up */
});

#if MACH_KERNEL_PRIVATE

/*!
 * @enum hw_lock_status_t
 *
 * @abstract
 * Used to pass information about very low level locking primitives.
 *
 */
__enum_closed_decl(hw_lock_status_t, int, {
	/**
	 * The lock was not taken because it is in an invalid state,
	 * or the memory was unmapped.
	 *
	 * This is only valid for @c *_allow_invalid() variants.
	 *
	 * Preemption is preserved to the caller level for all variants.
	 */
	HW_LOCK_INVALID    = -1,

	/**
	 * the lock wasn't acquired and is contended / timed out.
	 *
	 * - @c *_nopreempt() variants: preemption level preserved
	 * - @c *_trylock() variants: preemption level preserved
	 * - other variants: preemption is disabled
	 */
	HW_LOCK_CONTENDED  =  0,

	/**
	 * the lock was acquired successfully
	 *
	 * - @c *_nopreempt() variants: preemption level preserved
	 * - other variants: preemption is disabled
	 */
	HW_LOCK_ACQUIRED   =  1,
});

/*!
 * @enum hw_lock_timeout_status_t
 *
 * @abstract
 * Used by spinlock timeout handlers.
 *
 * @const HW_LOCK_TIMEOUT_RETURN
 * Tell the @c hw_lock*_to* caller to break out of the wait
 * and return HW_LOCK_CONTENDED.
 *
 * @const HW_LOCK_TIMEOUT_CONTINUE
 * Keep spinning for another "timeout".
 */
__enum_closed_decl(hw_lock_timeout_status_t, _Bool, {
	HW_LOCK_TIMEOUT_RETURN,         /**< return without taking the lock */
	HW_LOCK_TIMEOUT_CONTINUE,       /**< keep spinning                  */
});

/*!
 * @typedef hw_lock_timeout_handler_t
 *
 * @abstract
 * The type of the timeout handlers for low level locking primitives.
 *
 * @discussion
 * Typical handlers are written to just panic and not return
 * unless some very specific conditions are met (debugging, ...).
 */
typedef hw_lock_timeout_status_t (*hw_lock_timeout_handler_t)(void *lock,
    uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time);

#endif /* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_TYPES_H */
