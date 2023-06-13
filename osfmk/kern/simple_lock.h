/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (C) 1998 Apple Computer
 * All Rights Reserved
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 *	File:	kern/simple_lock.h (derived from kern/lock.h)
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Atomic primitives and Simple Locking primitives definitions
 */

#ifdef  KERNEL_PRIVATE

#ifndef _KERN_SIMPLE_LOCK_H_
#define _KERN_SIMPLE_LOCK_H_

#include <mach/boolean.h>
#include <kern/lock_types.h>
#include <kern/lock_group.h>
#include <machine/simple_lock.h>

#ifdef XNU_KERNEL_PRIVATE

#if MACH_KERNEL_PRIVATE
#include <machine/atomic.h>
#include <mach_ldebug.h>
#endif

__BEGIN_DECLS

#pragma GCC visibility push(hidden)

#ifdef MACH_KERNEL_PRIVATE

#define HW_LOCK_STATE_TO_THREAD(state)  ((thread_t)(state))
#define HW_LOCK_THREAD_TO_STATE(thread) ((uintptr_t)(thread))

extern void                     hw_lock_init(
	hw_lock_t);

extern void                     hw_lock_lock(
	hw_lock_t
	LCK_GRP_ARG(lck_grp_t*));

extern void                     hw_lock_lock_nopreempt(
	hw_lock_t
	LCK_GRP_ARG(lck_grp_t*));

extern unsigned int             hw_lock_to(
	hw_lock_t,
	hw_spin_policy_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

extern unsigned int             hw_lock_to_nopreempt(
	hw_lock_t,
	hw_spin_policy_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

extern unsigned int             hw_lock_try(
	hw_lock_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

extern unsigned int             hw_lock_try_nopreempt(
	hw_lock_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

#if !LCK_GRP_USE_ARG
#define hw_lock_lock(lck, grp) \
	hw_lock_lock(lck)

#define hw_lock_lock_nopreempt(lck, grp) \
	hw_lock_lock_nopreempt(lck)

#define hw_lock_to(lck, spec, grp) \
	hw_lock_to(lck, spec)

#define hw_lock_to_nopreempt(lck, spec, grp) \
	hw_lock_to_nopreempt(lck, spec)

#define hw_lock_try(lck, grp) \
	hw_lock_try(lck)

#define hw_lock_try_nopreempt(lck, grp) \
	hw_lock_try_nopreempt(lck)
#endif /* !LCK_GRP_USE_ARG */

extern void                     hw_lock_unlock(
	hw_lock_t);

extern void                     hw_lock_unlock_nopreempt(
	hw_lock_t);

extern void                     hw_lock_assert(
	hw_lock_t lock,
	unsigned int type);

extern unsigned int             hw_lock_held(
	hw_lock_t) __result_use_check;

extern boolean_t                hw_atomic_test_and_set32(
	uint32_t *target,
	uint32_t test_mask,
	uint32_t set_mask,
	enum memory_order ord,
	boolean_t wait);

extern boolean_t                atomic_test_and_set32(
	uint32_t *target,
	uint32_t test_mask,
	uint32_t set_mask,
	enum memory_order ord,
	boolean_t wait);

extern void                     atomic_exchange_abort(
	void);

extern boolean_t                atomic_exchange_complete32(
	uint32_t *target,
	uint32_t previous,
	uint32_t newval,
	enum memory_order ord);

extern uint32_t                 atomic_exchange_begin32(
	uint32_t *target,
	uint32_t *previous,
	enum memory_order ord);

#if defined(__arm__) || defined(__arm64__)
uint32_t                        load_exclusive32(
	uint32_t *target,
	enum memory_order ord);
boolean_t                       store_exclusive32(
	uint32_t *target,
	uint32_t value,
	enum memory_order ord);
#endif /* defined(__arm__)||defined(__arm64__) */

extern void                     usimple_unlock_nopreempt(
	usimple_lock_t);

extern hw_spin_timeout_t hw_spin_compute_timeout(
	hw_spin_policy_t         policy);

extern bool hw_spin_in_ppl(
	hw_spin_timeout_t       to) __pure2;

extern bool hw_spin_should_keep_spinning(
	void                   *lock,
	hw_spin_policy_t        policy,
	hw_spin_timeout_t       to,
	hw_spin_state_t        *state);

#endif /* MACH_KERNEL_PRIVATE */

struct usimple_lock_startup_spec {
	usimple_lock_t  lck;
	unsigned short  lck_init_arg;
};

extern void                     usimple_lock_startup_init(
	struct usimple_lock_startup_spec *spec);

#define SIMPLE_LOCK_DECLARE(var, arg) \
	decl_simple_lock_data(, var); \
	static __startup_data struct usimple_lock_startup_spec \
	__startup_usimple_lock_spec_ ## var = { &var, arg }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_FOURTH, usimple_lock_startup_init, \
	    &__startup_usimple_lock_spec_ ## var)

extern uint32_t hw_wait_while_equals32(
	uint32_t               *address,
	uint32_t                current);

extern uint64_t hw_wait_while_equals64(
	uint64_t               *address,
	uint64_t                current);

#if __LP64__
#define hw_wait_while_equals_long(ptr, cur) ({ \
	static_assert(sizeof(*(ptr)) == sizeof(long)); \
	(typeof(cur))hw_wait_while_equals64(__DEVOLATILE(uint64_t *, ptr), (uint64_t)(cur)); \
})
#else
#define hw_wait_while_equals_long(ptr, cur) ({ \
	static_assert(sizeof(*(ptr)) == sizeof(long)); \
	(typeof(cur))hw_wait_while_equals32(__DEVOLATILE(uint32_t *, ptr), (uint32_t)(cur)); \
})
#endif


extern void                     usimple_lock_init(
	usimple_lock_t,
	unsigned short);

extern void                     usimple_lock(
	usimple_lock_t
	LCK_GRP_ARG(lck_grp_t*));

extern unsigned int             usimple_lock_try(
	usimple_lock_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

extern void            usimple_lock_assert(
	usimple_lock_t lock,
	unsigned int type);

extern void             usimple_lock_try_lock_loop(
	usimple_lock_t
	LCK_GRP_ARG(lck_grp_t*));

#if defined(__x86_64__)
extern unsigned int     usimple_lock_try_lock_mp_signal_safe_loop_deadline(
	usimple_lock_t,
	uint64_t
	LCK_GRP_ARG(lck_grp_t*)) /* __result_use_check */;

extern unsigned int     usimple_lock_try_lock_mp_signal_safe_loop_duration(
	usimple_lock_t,
	uint64_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;
#endif

extern void                     usimple_unlock(
	usimple_lock_t);

#if !LCK_GRP_USE_ARG
#define usimple_lock(lck, grp) \
	usimple_lock(lck)

#define usimple_lock_try(lck, grp) \
	usimple_lock_try(lck)

#define usimple_lock_try_lock_loop(lck, grp) \
	usimple_lock_try_lock_loop(lck)

#if defined(__x86_64__)
#define usimple_lock_try_lock_mp_signal_safe_loop_deadline(lck, ddl, grp) \
	usimple_lock_try_lock_mp_signal_safe_loop_deadline(lck, ddl)
#define usimple_lock_try_lock_mp_signal_safe_loop_duration(lck, dur, grp) \
	usimple_lock_try_lock_mp_signal_safe_loop_duration(lck, dur)
#endif
#endif /* !LCK_GRP_USE_ARG */


/*
 * If we got to here and we still don't have simple_lock_init
 * defined, then we must either be outside the osfmk component,
 * running on a true SMP, or need debug.
 */
#if !defined(simple_lock_init)
#define simple_lock_init(l, t)               usimple_lock_init(l,t)
#define simple_lock(l, grp)                  usimple_lock(l, grp)
#define simple_unlock(l)                     usimple_unlock(l)
#define simple_lock_assert(l, x)             usimple_lock_assert((l), (x))
#define simple_lock_try(l, grp)              usimple_lock_try(l, grp)
#define simple_lock_try_lock_loop(l, grp)    usimple_lock_try_lock_loop(l, grp)
#define simple_lock_try_lock_mp_signal_safe_loop_deadline(l, ddl, grp) \
	usimple_lock_try_lock_mp_signal_safe_loop_deadline(l, ddl, grp)
#define simple_lock_try_lock_mp_signal_safe_loop_duration(l, dur, grp) \
	usimple_lock_try_lock_mp_signal_safe_loop_duration(l, dur, grp)
#define simple_lock_addr(l)     (&(l))
#endif /* !defined(simple_lock_init) */

#ifdef MACH_KERNEL_PRIVATE

typedef uint32_t hw_lock_bit_t;

#if __arm64__
extern const struct hw_spin_policy hw_lock_bit_policy_2s;
#endif
extern const struct hw_spin_policy hw_lock_spin_policy;
extern const struct hw_spin_policy hw_lock_spin_panic_policy;
#if DEBUG || DEVELOPMENT
extern const struct hw_spin_policy hw_lock_test_give_up_policy;
#endif /* DEBUG || DEVELOPMENT */

extern void     hw_lock_bit(
	hw_lock_bit_t *,
	unsigned int
	LCK_GRP_ARG(lck_grp_t*));

extern void     hw_lock_bit_nopreempt(
	hw_lock_bit_t *,
	unsigned int
	LCK_GRP_ARG(lck_grp_t*));


extern unsigned int hw_lock_bit_try(
	hw_lock_bit_t *,
	unsigned int
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

extern unsigned int hw_lock_bit_to(
	hw_lock_bit_t *,
	unsigned int,
	hw_spin_policy_t
	LCK_GRP_ARG(lck_grp_t*)) __result_use_check;

extern void     hw_unlock_bit(
	hw_lock_bit_t *,
	unsigned int);

extern void     hw_unlock_bit_nopreempt(
	hw_lock_bit_t *,
	unsigned int);

#define hw_lock_bit_held(l, b) \
	(((*(l)) & (1 << (b))) != 0)

#if !LCK_GRP_USE_ARG
#define hw_lock_bit(lck, bit, grp) \
	hw_lock_bit(lck, bit)

#define hw_lock_bit_nopreempt(lck, bit, grp) \
	hw_lock_bit_nopreempt(lck, bit)


#define hw_lock_bit_try(lck, bit, grp) \
	hw_lock_bit_try(lck, bit)

#define hw_lock_bit_to(lck, bit, spec, grp) \
	hw_lock_bit_to(lck, bit, spec)

#endif /* !LCK_GRP_USE_ARG */
#endif  /* MACH_KERNEL_PRIVATE */

__END_DECLS

#pragma GCC visibility pop

#endif /* XNU_KERNEL_PRIVATE */
#endif /*!_KERN_SIMPLE_LOCK_H_*/

#endif  /* KERNEL_PRIVATE */
