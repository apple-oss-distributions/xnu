/*
 * Copyright (c) 2004-2012 Apple Inc. All rights reserved.
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

#ifndef _I386_LOCKS_H_
#define _I386_LOCKS_H_

#include <sys/appleapiopts.h>
#include <kern/lock_types.h>
#include <kern/assert.h>

#ifdef  MACH_KERNEL_PRIVATE

#define enaLkDeb                0x00000001      /* Request debug in default attribute */
#define enaLkStat               0x00000002      /* Request statistic in default attribute */
#define disLkRWPrio             0x00000004      /* Disable RW lock priority promotion */
#define enaLkTimeStat           0x00000008      /* Request time statistics in default attribute */
#define disLkRWDebug            0x00000010      /* Disable RW lock best-effort debugging */

#endif /* MACH_KERNEL_PRIVATE */

#ifdef MACH_KERNEL_PRIVATE
typedef struct {
	volatile uintptr_t      interlock __kernel_data_semantics;
#if MACH_LDEBUG
	unsigned long           lck_spin_pad[9];        /* XXX - usimple_lock_data_t */
#endif
} lck_spin_t;

#define LCK_SPIN_TAG_DESTROYED 0x00002007      /* lock marked as Destroyed */

#if LCK_MTX_USE_ARCH

typedef struct _lck_mtx_ {
	union {
		struct {
			volatile uint32_t
			    lck_mtx_waiters:16,
			    lck_mtx_pri:8, // unused
			    lck_mtx_ilocked:1,
			    lck_mtx_mlocked:1,
			    lck_mtx_spin:1,
			    lck_mtx_profile:1,
			    lck_mtx_pad3:4;
		};
		uint32_t        lck_mtx_state;
	};
	volatile uint32_t       lck_mtx_owner; /* a ctid_t */
	uint32_t                lck_mtx_grp;
	uint32_t                lck_mtx_padding;
} lck_mtx_t;

#define LCK_MTX_WAITERS_MSK             0x0000ffff
#define LCK_MTX_WAITER                  0x00000001
#define LCK_MTX_PRIORITY_MSK            0x00ff0000
#define LCK_MTX_ILOCKED_MSK             0x01000000
#define LCK_MTX_MLOCKED_MSK             0x02000000
#define LCK_MTX_SPIN_MSK                0x04000000
#define LCK_MTX_PROFILE_MSK             0x08000000

/* This pattern must subsume the interlocked, mlocked and spin bits */
#define LCK_MTX_TAG_DESTROYED           0x07fe2007      /* lock marked as Destroyed */

#endif /* LCK_MTX_USE_ARCH */
#elif KERNEL_PRIVATE

typedef struct {
	unsigned long opaque[10] __kernel_data_semantics;
} lck_spin_t;

typedef struct {
	unsigned long opaque[2] __kernel_data_semantics;
} lck_mtx_t;

typedef struct {
	unsigned long opaque[10];
} lck_mtx_ext_t;

#else /* KERNEL_PRIVATE */

typedef struct __lck_spin_t__           lck_spin_t;
typedef struct __lck_mtx_t__            lck_mtx_t;
typedef struct __lck_mtx_ext_t__        lck_mtx_ext_t;

#endif /* !KERNEL_PRIVATE */
#ifdef  MACH_KERNEL_PRIVATE

/*
 * static panic deadline, in timebase units, for
 * hw_lock_{bit,lock}{,_nopreempt} and hw_wait_while_equals()
 */
extern uint64_t _Atomic lock_panic_timeout;

/* Adaptive spin before blocking */
extern uint64_t         MutexSpin;
extern uint64_t         low_MutexSpin;
extern int64_t          high_MutexSpin;

#if CONFIG_PV_TICKET
extern bool             has_lock_pv;
#endif
#if LCK_MTX_USE_ARCH

typedef enum lck_mtx_spinwait_ret_type {
	LCK_MTX_SPINWAIT_ACQUIRED = 0,

	LCK_MTX_SPINWAIT_SPUN_HIGH_THR = 1,
	LCK_MTX_SPINWAIT_SPUN_OWNER_NOT_CORE = 2,
	LCK_MTX_SPINWAIT_SPUN_NO_WINDOW_CONTENTION = 3,
	LCK_MTX_SPINWAIT_SPUN_SLIDING_THR = 4,

	LCK_MTX_SPINWAIT_NO_SPIN = 5,
} lck_mtx_spinwait_ret_type_t;

extern lck_mtx_spinwait_ret_type_t              lck_mtx_lock_spinwait_x86(lck_mtx_t *mutex);
struct turnstile;
extern void             lck_mtx_lock_wait_x86(lck_mtx_t *mutex, struct turnstile **ts);
extern void             lck_mtx_lock_acquire_x86(lck_mtx_t *mutex);

extern void             lck_mtx_lock_slow(lck_mtx_t *lock);
extern boolean_t        lck_mtx_try_lock_slow(lck_mtx_t *lock);
extern void             lck_mtx_unlock_slow(lck_mtx_t *lock);
extern void             lck_mtx_lock_spin_slow(lck_mtx_t *lock);
extern boolean_t        lck_mtx_try_lock_spin_slow(lck_mtx_t *lock);

#endif /* LCK_MTX_USE_ARCH */

extern void             hw_lock_byte_init(volatile uint8_t *lock_byte);
extern void             hw_lock_byte_lock(volatile uint8_t *lock_byte);
extern void             hw_lock_byte_unlock(volatile uint8_t *lock_byte);
extern void             kernel_preempt_check(void);

#ifdef LOCK_PRIVATE

#if LCK_MTX_USE_ARCH
#define LCK_MTX_EVENT(lck)      CAST_EVENT64_T(&(lck)->lck_mtx_owner)
#define LCK_EVENT_TO_MUTEX(e)   __container_of((uint32_t *)(event), lck_mtx_t, lck_mtx_owner)
#define LCK_MTX_HAS_WAITERS(l)  ((l)->lck_mtx_waiters != 0)
#endif /* LCK_MTX_USE_ARCH */

#define LOCK_SNOOP_SPINS        1000
#define LOCK_PRETEST            1

#define lock_disable_preemption_for_thread(t)   disable_preemption_internal()
#define lock_preemption_level_for_thread(t)     get_preemption_level()
#define lock_preemption_disabled_for_thread(t)  (get_preemption_level() > 0)
#define lock_enable_preemption()                enable_preemption_internal()
#define current_thread()                        current_thread_fast()

#define __hw_spin_wait_load(ptr, load_var, cond_result, cond_expr) ({ \
	load_var = os_atomic_load(ptr, relaxed);                                \
	cond_result = (cond_expr);                                              \
	if (!(cond_result)) {                                                   \
	        cpu_pause();                                                    \
	}                                                                       \
})

#endif /* LOCK_PRIVATE */
#endif /* MACH_KERNEL_PRIVATE */
#endif /* _I386_LOCKS_H_ */
