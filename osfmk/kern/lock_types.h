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

#define LCK_SLEEP_MASK           0x3f     /* Valid actions */

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

__options_decl(lck_wake_action_t, unsigned int, {
	LCK_WAKE_DEFAULT                = 0x00,  /* If waiters are present, transfer their push to the wokenup thread */
	LCK_WAKE_DO_NOT_TRANSFER_PUSH   = 0x01,  /* Do not transfer waiters push when waking up */
});

typedef const struct hw_spin_policy *hw_spin_policy_t;

#if XNU_KERNEL_PRIVATE

/*!
 * @enum lck_option_t
 *
 * @abstract
 * Lock options to pass to "lcks=" boot-arg
 */
__options_decl(lck_option_t, unsigned int, {
	LCK_OPTION_ENABLE_DEBUG     = 0x01, /**< Request debug in default attribute */
	LCK_OPTION_ENABLE_STAT      = 0x02, /**< Request lock group statistics in default attribute */
	LCK_OPTION_DISABLE_RW_PRIO  = 0x04, /**< Disable RW lock priority promotion */
	LCK_OPTION_ENABLE_TIME_STAT = 0x08, /**< Request time lock group statistics in default attribute */
	LCK_OPTION_DISABLE_RW_DEBUG = 0x10, /**< Disable RW lock best-effort debugging. */
});

#endif // XNU_KERNEL_PRIVATE

#if MACH_KERNEL_PRIVATE

/*
 *	The "hardware lock".  Low-level locking primitives that
 *	MUST be exported by machine-dependent code; this abstraction
 *	must provide atomic, non-blocking mutual exclusion that
 *	is invulnerable to uniprocessor or SMP races, interrupts,
 *	traps or any other events.
 *
 *		hw_lock_data_t		machine-specific lock data structure
 *		hw_lock_t		pointer to hw_lock_data_t
 *
 *	An implementation must export these data types and must
 *	also provide routines to manipulate them (see prototypes,
 *	below).  These routines may be external, inlined, optimized,
 *	or whatever, based on the kernel configuration.  In the event
 *	that the implementation wishes to define its own prototypes,
 *	macros, or inline functions, it may define LOCK_HW_PROTOS
 *	to disable the definitions below.
 *
 *	Mach does not expect these locks to support statistics,
 *	debugging, tracing or any other complexity.  In certain
 *	configurations, Mach will build other locking constructs
 *	on top of this one.  A correctly functioning Mach port need
 *	only implement these locks to be successful.  However,
 *	greater efficiency may be gained with additional machine-
 *	dependent optimizations for the locking constructs defined
 *	later in kern/lock.h..
 */
struct hslock {
	uintptr_t       lock_data __kernel_data_semantics;
};
typedef struct hslock hw_lock_data_t, *hw_lock_t;

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
 * @enum hw_spin_timeout_status_t
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
__enum_closed_decl(hw_spin_timeout_status_t, _Bool, {
	HW_LOCK_TIMEOUT_RETURN,         /**< return without taking the lock */
	HW_LOCK_TIMEOUT_CONTINUE,       /**< keep spinning                  */
});


/*!
 * @typedef hw_spin_timeout_t
 *
 * @abstract
 * Describes the timeout used for a given spinning session.
 */
typedef struct {
	uint64_t                hwst_timeout;
#if SCHED_HYGIENE_DEBUG
	bool                    hwst_in_ppl;
	bool                    hwst_interruptible;
#endif /* SCHED_HYGIENE_DEBUG */
} hw_spin_timeout_t;


/*!
 * @typedef hw_spin_state_t
 *
 * @abstract
 * Keeps track of the various timings used for spinning
 */
typedef struct {
	uint64_t                hwss_start;
	uint64_t                hwss_now;
	uint64_t                hwss_deadline;
#if SCHED_HYGIENE_DEBUG
	uint64_t                hwss_irq_start;
	uint64_t                hwss_irq_end;
#endif /* SCHED_HYGIENE_DEBUG */
} hw_spin_state_t;


/*!
 * @typedef hw_spin_timeout_fn_t
 *
 * @abstract
 * The type of the timeout handlers for low level locking primitives.
 *
 * @discussion
 * Typical handlers are written to just panic and not return
 * unless some very specific conditions are met (debugging, ...).
 *
 * For formatting purposes, we provide HW_SPIN_TIMEOUT{,_DETAILS}{_FMT,_ARG}
 *
 * Those are meant to be used inside an hw_spin_timeout_fn_t function
 * to form informative panic strings, like this:
 *
 *    panic("MyLock[%p] " HW_SPIN_TIMEOUT_FMT "; "
 *         "<lock specific things> " HW_SPIN_TIMEOUT_DETAILS_FMT,
 *         lock_address, HW_SPIN_TIMEOUT_ARG(to, st),
 *         <lock specific args>, HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
 *
 * This ensures consistent panic string style, and transparent adoption
 * for any new diagnostic/debugging features at all call-sites.
 */
typedef hw_spin_timeout_status_t (hw_spin_timeout_fn_t)(void *lock,
    hw_spin_timeout_t to, hw_spin_state_t st);

#define HW_SPIN_TIMEOUT_FMT \
	"timeout after %llu ticks"
#define HW_SPIN_TIMEOUT_ARG(to, st) \
	((st).hwss_now - (st).hwss_start)

#if SCHED_HYGIENE_DEBUG
#define HW_SPIN_TIMEOUT_SCHED_HYGIENE_FMT \
	", irq time: %llu"
#define HW_SPIN_TIMEOUT_SCHED_HYGIENE_ARG(to, st) \
	, ((st).hwss_irq_end - (st).hwss_irq_start)
#else
#define HW_SPIN_TIMEOUT_SCHED_HYGIENE_FMT
#define HW_SPIN_TIMEOUT_SCHED_HYGIENE_ARG(to, st)
#endif

#define HW_SPIN_TIMEOUT_DETAILS_FMT \
	"start time: %llu, now: %llu, timeout: %llu" \
	HW_SPIN_TIMEOUT_SCHED_HYGIENE_FMT
#define HW_SPIN_TIMEOUT_DETAILS_ARG(to, st) \
	(st).hwss_start, (st).hwss_now, (to).hwst_timeout \
	HW_SPIN_TIMEOUT_SCHED_HYGIENE_ARG(to, st)

/*!
 * @struct hw_spin_policy
 *
 * @abstract
 * Describes the spinning policy for a given lock.
 */
struct hw_spin_policy {
	const char             *hwsp_name;
	union {
		const uint64_t *hwsp_timeout;
		const _Atomic uint64_t *hwsp_timeout_atomic;
	};
	uint16_t                hwsp_timeout_shift;
	uint16_t                hwsp_lock_offset;

	hw_spin_timeout_fn_t   *hwsp_op_timeout;
};

#if __x86_64__
#define LCK_MTX_USE_ARCH 1
#else
#define LCK_MTX_USE_ARCH 0
#endif
#endif /* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_TYPES_H */
