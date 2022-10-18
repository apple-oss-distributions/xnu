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

#ifndef _KERN_LOCK_MTX_H_
#define _KERN_LOCK_MTX_H_

#include <kern/lock_types.h>
#include <kern/lock_group.h>
#include <kern/lock_attr.h>

#ifdef  XNU_KERNEL_PRIVATE
#include <kern/startup.h>
#endif /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS

#if MACH_KERNEL_PRIVATE
#if !LCK_MTX_USE_ARCH

typedef union lck_mtx_state {
	struct {
		uint32_t        owner        : 28;
		uint32_t        ilocked      :  1;
		uint32_t        spin_mode    :  1;
		uint32_t        needs_wakeup :  1;
		uint32_t        profile      :  1;
#define LCK_MTX_CTID_MASK       0x0fffffffu
#define LCK_MTX_BITS_MASK       0xf0000000u
#define LCK_MTX_ILOCK           0x10000000u
#define LCK_MTX_SPIN_MODE       0x20000000u
#define LCK_MTX_NEEDS_WAKEUP    0x40000000u
#if CONFIG_DTRACE
#define LCK_MTX_PROFILE         0x80000000u
#else
#define LCK_MTX_PROFILE         0x00000000u
#endif
		uint16_t        ilk_tail;
		uint16_t        as_tail;
	};
	uint32_t                data;
	uint64_t                val;
} lck_mtx_state_t;

typedef struct _lck_mtx_ {
	uint32_t                lck_mtx_tsid : 24;      /* turnstile ID */
	uint8_t                 lck_mtx_type :  8;      /* Type */
	uint32_t                lck_mtx_grp;
	lck_mtx_state_t         lck_mtx;
} lck_mtx_t;

/* lock marked as destroyed, sets ILOCK | WAITERS */
#define LCK_MTX_TAG_DESTROYED   0xf0fe2007

/*
 * for historical reasons the lck_mtx_t definition for the KDK
 * are in <machine/locks.h> headers.
 */
#endif /* !LCK_MTX_USE_ARCH */
#endif

#define decl_lck_mtx_data(class, name)     class lck_mtx_t name

extern lck_mtx_t        *lck_mtx_alloc_init(
	lck_grp_t               *grp,
	lck_attr_t              *attr);

extern void             lck_mtx_init(
	lck_mtx_t               *lck,
	lck_grp_t               *grp,
	lck_attr_t              *attr);
extern void             lck_mtx_lock(
	lck_mtx_t               *lck);

extern void             lck_mtx_unlock(
	lck_mtx_t               *lck);

extern void             lck_mtx_destroy(
	lck_mtx_t               *lck,
	lck_grp_t               *grp);

extern void             lck_mtx_free(
	lck_mtx_t               *lck,
	lck_grp_t               *grp);

extern wait_result_t    lck_mtx_sleep(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible);

extern wait_result_t    lck_mtx_sleep_deadline(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

#define LCK_MTX_ASSERT_OWNED    LCK_ASSERT_OWNED
#define LCK_MTX_ASSERT_NOTOWNED LCK_ASSERT_NOTOWNED

extern void             lck_mtx_assert(
	lck_mtx_t               *lck,
	unsigned                int    type);

#if MACH_ASSERT
#define LCK_MTX_ASSERT(lck, type) lck_mtx_assert((lck),(type))
#else /* MACH_ASSERT */
#define LCK_MTX_ASSERT(lck, type)
#endif /* MACH_ASSERT */

#if DEBUG
#define LCK_MTX_ASSERT_DEBUG(lck, type) lck_mtx_assert((lck),(type))
#else /* DEBUG */
#define LCK_MTX_ASSERT_DEBUG(lck, type)
#endif /* DEBUG */

#if KERNEL_PRIVATE

extern boolean_t        lck_mtx_try_lock(
	lck_mtx_t               *lck);

extern void             mutex_pause(uint32_t);

extern boolean_t        lck_mtx_yield(
	lck_mtx_t               *lck);

extern boolean_t        lck_mtx_try_lock_spin(
	lck_mtx_t               *lck);

extern void             lck_mtx_lock_spin(
	lck_mtx_t               *lck);

extern boolean_t        kdp_lck_mtx_lock_spin_is_acquired(
	lck_mtx_t               *lck);

extern void             lck_mtx_convert_spin(
	lck_mtx_t               *lck);

extern void             lck_mtx_lock_spin_always(
	lck_mtx_t               *lck);

extern boolean_t        lck_mtx_try_lock_spin_always(
	lck_mtx_t               *lck);

#define lck_mtx_unlock_always(l)        lck_mtx_unlock(l)

#endif /* KERNEL_PRIVATE */
#if  XNU_KERNEL_PRIVATE

struct lck_mtx_startup_spec {
	lck_mtx_t               *lck;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

extern void             lck_mtx_startup_init(
	struct lck_mtx_startup_spec *spec);

#define LCK_MTX_DECLARE_ATTR(var, grp, attr) \
	lck_mtx_t var; \
	static __startup_data struct lck_mtx_startup_spec \
	__startup_lck_mtx_spec_ ## var = { &var, grp, attr }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_FOURTH, lck_mtx_startup_init, \
	    &__startup_lck_mtx_spec_ ## var)

#define LCK_MTX_DECLARE(var, grp) \
	LCK_MTX_DECLARE_ATTR(var, grp, LCK_ATTR_NULL)

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_RW_H_ */
