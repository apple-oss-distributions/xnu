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

#ifndef _KERN_TICKET_LOCK_H_
#define _KERN_TICKET_LOCK_H_

#ifndef __ASSEMBLER__
#include <kern/lock_types.h>
#include <kern/lock_group.h>
#if XNU_KERNEL_PRIVATE
#include <kern/counter.h>
#endif /* XNU_KERNEL_PRIVATE */
#endif /* __ASSEMBLER__ */

#ifndef __ASSEMBLER__

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

#ifdef MACH_KERNEL_PRIVATE

/*!
 * @typedef hw_lck_ticket_t
 *
 * @discussion
 * This type describes the low level type for a ticket lock.
 * @c lck_ticket_t provides a higher level abstraction
 * that also provides thread ownership information.
 *
 * This is a low level lock meant to be part of data structures
 * that are very constrained on space, or is part of a larger lock.
 *
 * This lower level interface supports an @c *_allow_invalid()
 * to implement advanced memory reclamation schemes using sequestering.
 * Do note that when @c CONFIG_PROB_GZALLOC is engaged, and the target lock
 * comes from a zone, PGZ must be handled manually.
 * See ipc_object_lock_allow_invalid() for an example of that.
 *
 * @c hw_lck_ticket_invalidate() must be used on locks
 * that will be used this way: in addition to make subsequent calls to
 * @c hw_lck_ticket_lock_allow_invalid() to fail, it allows for
 * @c hw_lck_ticket_destroy() to synchronize with callers to
 * @c hw_lck_ticket_lock_allow_invalid() who successfully reserved
 * a ticket but will fail, ensuring the memory can't be freed too early.
 *
 *
 * @c hw_lck_ticket_reserve() can be used to pre-reserve a ticket.
 * When this function returns @c true, then the lock was acquired.
 * When it returns @c false, then @c hw_lck_ticket_wait() must
 * be called to wait for this ticket.
 *
 * This can be used to resolve certain lock inversions: assuming
 * two locks, @c L (a mutex or any kind of lock) and @c T (a ticket lock),
 * where @c L can be taken when @c T is held but not the other way around,
 * then the following can be done to take both locks in "the wrong order",
 * with a guarantee of forward progress:
 *
 * <code>
 *     // starts with L held
 *     uint32_t ticket;
 *
 *     if (!hw_lck_ticket_reserve(T, &ticket)) {
 *         unlock(L);
 *         hw_lck_ticket_wait(T, ticket):
 *         lock(L);
 *         // possibly validate what might have changed
 *         // due to dropping L
 *     }
 *
 *     // both L and T are held
 * </code>
 *
 * This pattern above is safe even for a case when the protected
 * resource contains the ticket lock @c T, provided that it is
 * guaranteed that both @c T and @c L (in the proper order) will
 * be taken before that resource death. In that case, in the resource
 * destructor, when @c hw_lck_ticket_destroy() is called, it will
 * wait for the reservation to be released.
 *
 * See @c waitq_pull_thread_locked() for an example of this where:
 * - @c L is the thread lock of a thread waiting on a given waitq,
 * - @c T is the lock for that waitq,
 * - the waitq can't be destroyed before the thread is unhooked from it,
 *   which happens under both @c L and @c T.
 *
 *
 * @note:
 * At the moment, this construct only supports up to 255 CPUs.
 * Supporting more CPUs requires losing the `lck_type` field,
 * and burning the low bit of the cticket/nticket
 * for the "invalidation" feature.
 */
typedef union {
	struct {
		uint8_t         lck_type;
		uint8_t         lck_valid  : 1;
		uint8_t         lck_is_pv  : 1;
		uint8_t         lck_unused : 6;
		union {
			struct {
				uint8_t cticket;
				uint8_t nticket;
			};
			uint16_t tcurnext;
		};
	};
	uint32_t lck_value;
} hw_lck_ticket_t;

/*!
 * @typedef lck_ticket_t
 *
 * @discussion
 * A higher level construct than hw_lck_ticket_t in 2 words
 * like other kernel locks, which admits thread ownership information.
 */
typedef struct {
	uint32_t                __lck_ticket_unused : 24;
	uint32_t                lck_ticket_type     :  8;
	uint32_t                lck_ticket_padding;
	hw_lck_ticket_t         tu;
	uint32_t                lck_ticket_owner;
} lck_ticket_t;

#else /* !MACH_KERNEL_PRIVATE */

typedef struct {
	uint32_t                opaque0;
	uint32_t                opaque1;
	uint32_t                opaque2;
	uint32_t                opaque3;
} lck_ticket_t;

#endif /* !MACH_KERNEL_PRIVATE */
#if MACH_KERNEL_PRIVATE

#if !LCK_GRP_USE_ARG
#define hw_lck_ticket_init(lck, grp)             hw_lck_ticket_init(lck)
#define hw_lck_ticket_init_locked(lck, grp)      hw_lck_ticket_init_locked(lck)
#define hw_lck_ticket_destroy(lck, grp)          hw_lck_ticket_destroy(lck)
#define hw_lck_ticket_lock(lck, grp)             hw_lck_ticket_lock(lck)
#define hw_lck_ticket_lock_nopreempt(lck, grp)   hw_lck_ticket_lock_nopreempt(lck)
#define hw_lck_ticket_lock_to(lck, pol, grp)     hw_lck_ticket_lock_to(lck, pol)
#define hw_lck_ticket_lock_nopreempt_to(lck, pol, grp) \
	hw_lck_ticket_lock_nopreempt_to(lck, pol)
#define hw_lck_ticket_lock_try(lck, grp)         hw_lck_ticket_lock_try(lck)
#define hw_lck_ticket_lock_try_nopreempt(lck, grp) \
	hw_lck_ticket_lock_try_nopreempt(lck)
#define hw_lck_ticket_lock_allow_invalid(lck, pol, grp) \
	hw_lck_ticket_lock_allow_invalid(lck, pol)
#define hw_lck_ticket_reserve(lck, t, grp)       hw_lck_ticket_reserve(lck, t)
#define hw_lck_ticket_reserve_nopreempt(lck, t, grp) \
	hw_lck_ticket_reserve_nopreempt(lck, t)
#define hw_lck_ticket_reserve_allow_invalid(lck, t, grp) \
	hw_lck_ticket_reserve_allow_invalid(lck, t)
#define hw_lck_ticket_wait(lck, ticket, pol, grp) \
	hw_lck_ticket_wait(lck, ticket, pol)
#endif /* !LCK_GRP_USE_ARG */


/* init/destroy */

extern void hw_lck_ticket_init(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp);

extern void hw_lck_ticket_init_locked(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp);

extern void hw_lck_ticket_destroy(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp);

extern void hw_lck_ticket_invalidate(
	hw_lck_ticket_t        *tlock);

extern bool hw_lck_ticket_held(
	hw_lck_ticket_t        *tlock) __result_use_check;


/* lock */

extern void hw_lck_ticket_lock(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp);

extern void hw_lck_ticket_lock_nopreempt(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp);

extern hw_lock_status_t hw_lck_ticket_lock_to(
	hw_lck_ticket_t        *tlock,
	hw_spin_policy_t        policy,
	lck_grp_t              *grp);

extern hw_lock_status_t hw_lck_ticket_lock_nopreempt_to(
	hw_lck_ticket_t        *tlock,
	hw_spin_policy_t        policy,
	lck_grp_t              *grp);


/* lock_try */

extern bool hw_lck_ticket_lock_try(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp) __result_use_check;

extern bool hw_lck_ticket_lock_try_nopreempt(
	hw_lck_ticket_t        *tlock,
	lck_grp_t              *grp) __result_use_check;


/* unlock */

extern void hw_lck_ticket_unlock(
	hw_lck_ticket_t        *tlock);

extern void hw_lck_ticket_unlock_nopreempt(
	hw_lck_ticket_t        *tlock);


/* reserve/wait */

extern bool hw_lck_ticket_reserve(
	hw_lck_ticket_t        *tlock,
	uint32_t               *ticket,
	lck_grp_t              *grp) __result_use_check;

extern bool hw_lck_ticket_reserve_nopreempt(
	hw_lck_ticket_t        *tlock,
	uint32_t               *ticket,
	lck_grp_t              *grp) __result_use_check;

extern hw_lock_status_t hw_lck_ticket_reserve_allow_invalid(
	hw_lck_ticket_t        *tlock,
	uint32_t               *ticket,
	lck_grp_t              *grp) __result_use_check;

extern hw_lock_status_t hw_lck_ticket_wait(
	hw_lck_ticket_t        *tlock,
	uint32_t                ticket,
	hw_spin_policy_t        policy,
	lck_grp_t             *grp);

extern hw_lock_status_t hw_lck_ticket_lock_allow_invalid(
	hw_lck_ticket_t        *tlock,
	hw_spin_policy_t        policy,
	lck_grp_t              *grp);

/* pv */

extern void hw_lck_ticket_unlock_kick_pv(
	hw_lck_ticket_t        *tlock,
	uint8_t                 value);

extern void hw_lck_ticket_lock_wait_pv(
	hw_lck_ticket_t         *tlock,
	uint8_t                  value);

#endif /* MACH_KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE

extern bool kdp_lck_ticket_is_acquired(
	lck_ticket_t            *tlock) __result_use_check;

extern void lck_ticket_lock_nopreempt(
	lck_ticket_t            *tlock,
	lck_grp_t               *grp);

extern bool lck_ticket_lock_try(
	lck_ticket_t            *tlock,
	lck_grp_t               *grp) __result_use_check;

extern bool lck_ticket_lock_try_nopreempt(
	lck_ticket_t            *tlock,
	lck_grp_t               *grp) __result_use_check;

extern void lck_ticket_unlock_nopreempt(
	lck_ticket_t            *tlock);

#endif /* XNU_KERNEL_PRIVATE */

extern __exported void lck_ticket_init(
	lck_ticket_t            *tlock,
	lck_grp_t               *grp);

extern __exported void lck_ticket_destroy(
	lck_ticket_t            *tlock,
	lck_grp_t               *grp);

extern __exported void lck_ticket_lock(
	lck_ticket_t            *tlock,
	lck_grp_t               *grp);

extern __exported void lck_ticket_unlock(
	lck_ticket_t            *tlock);

extern __exported void lck_ticket_assert_owned(
	lck_ticket_t            *tlock);

extern __exported void lck_ticket_assert_not_owned(
	lck_ticket_t            *tlock);

#if MACH_ASSERT
#define LCK_TICKET_ASSERT_OWNED(tlock)     lck_ticket_assert_owned(tlock)
#define LCK_TICKET_ASSERT_NOT_OWNED(tlock) lck_ticket_assert_owned(tlock)
#else
#define LCK_TICKET_ASSERT_OWNED(tlock)     (void)(tlock)
#define LCK_TICKET_ASSERT_NOT_OWNED(tlock) (void)(tlock)
#endif

#pragma GCC visibility pop
__END_DECLS

#endif /* __ASSEMBLER__ */
#if XNU_KERNEL_PRIVATE

#define HW_LCK_TICKET_LOCK_VALID_BIT  8

#if CONFIG_PV_TICKET

/*
 * For the PV case, the lsbit of cticket is treated as as wait flag,
 * and the ticket counters are incremented by 2
 */
#define HW_LCK_TICKET_LOCK_PVWAITFLAG ((uint8_t)1)
#define HW_LCK_TICKET_LOCK_INCREMENT  ((uint8_t)2)
#define HW_LCK_TICKET_LOCK_INC_WORD   0x02000000

#if !defined(__ASSEMBLER__) && (DEBUG || DEVELOPMENT)
/* counters for sysctls */
SCALABLE_COUNTER_DECLARE(ticket_wflag_cleared);
SCALABLE_COUNTER_DECLARE(ticket_wflag_still);
SCALABLE_COUNTER_DECLARE(ticket_just_unlock);
SCALABLE_COUNTER_DECLARE(ticket_kick_count);
SCALABLE_COUNTER_DECLARE(ticket_wait_count);
SCALABLE_COUNTER_DECLARE(ticket_already_count);
SCALABLE_COUNTER_DECLARE(ticket_spin_count);
#define PVTICKET_STATS_ADD(var, i)    counter_add_preemption_disabled(&ticket_##var, (i))
#define PVTICKET_STATS_INC(var)       counter_inc_preemption_disabled(&ticket_##var)
#else
#define PVTICKET_STATS_ADD(var, i)    /* empty */
#define PVTICKET_STATS_INC(var)       /* empty */
#endif

#else /* CONFIG_PV_TICKET */

#define HW_LCK_TICKET_LOCK_PVWAITFLAG ((uint8_t)0)
#define HW_LCK_TICKET_LOCK_INCREMENT  ((uint8_t)1)
#define HW_LCK_TICKET_LOCK_INC_WORD   0x01000000

#endif /* CONFIG_PV_TICKET */
#endif /* XNU_KERNEL_PRIVATE */
#endif /* _KERN_TICKET_LOCK_H_ */
