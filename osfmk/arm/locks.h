/*
 * Copyright (c) 2007-2017 Apple Inc. All rights reserved.
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

#ifndef _ARM_LOCKS_H_
#define _ARM_LOCKS_H_

#ifdef  MACH_KERNEL_PRIVATE
#ifndef LCK_SPIN_IS_TICKET_LOCK
#define LCK_SPIN_IS_TICKET_LOCK 0
#endif
#endif /* MACH_KERNEL_PRIVATE */

#include <kern/lock_types.h>
#ifdef  MACH_KERNEL_PRIVATE
#include <kern/sched_hygiene.h>
#include <kern/startup.h>
#if LCK_SPIN_IS_TICKET_LOCK
#include <kern/ticket_lock.h>
#endif
#endif

#ifdef  MACH_KERNEL_PRIVATE
#if LCK_SPIN_IS_TICKET_LOCK
typedef lck_ticket_t lck_spin_t;
#else
typedef struct {
	struct hslock   hwlock;
	unsigned long   type;
} lck_spin_t;

#define lck_spin_data hwlock.lock_data

#define LCK_SPIN_TAG_DESTROYED  0xdead  /* lock marked as Destroyed */

#define LCK_SPIN_TYPE           0x00000011
#define LCK_SPIN_TYPE_DESTROYED 0x000000ee
#endif

#elif KERNEL_PRIVATE

typedef struct {
	uintptr_t opaque[2] __kernel_data_semantics;
} lck_spin_t;

typedef struct {
	uintptr_t opaque[2] __kernel_data_semantics;
} lck_mtx_t;

typedef struct {
	uintptr_t opaque[16];
} lck_mtx_ext_t;

#else

typedef struct __lck_spin_t__           lck_spin_t;
typedef struct __lck_mtx_t__            lck_mtx_t;
typedef struct __lck_mtx_ext_t__        lck_mtx_ext_t;

#endif  /* !KERNEL_PRIVATE */
#ifdef  MACH_KERNEL_PRIVATE

/*
 * static panic deadline, in timebase units, for
 * hw_lock_{bit,lock}{,_nopreempt} and hw_wait_while_equals()
 */
extern uint64_t _Atomic lock_panic_timeout;

/* Adaptive spin before blocking */
extern machine_timeout_t   MutexSpin;
extern uint64_t            low_MutexSpin;
extern int64_t             high_MutexSpin;

#if CONFIG_PV_TICKET
extern bool                has_lock_pv;
#endif

#ifdef LOCK_PRIVATE

#define LOCK_SNOOP_SPINS        100
#define LOCK_PRETEST            0

#define wait_for_event()        __builtin_arm_wfe()

#if SCHED_HYGIENE_DEBUG
#define lock_disable_preemption_for_thread(t) ({                                \
	thread_t __dpft_thread = (t);                                           \
	uint32_t *__dpft_countp = &__dpft_thread->machine.preemption_count;     \
	uint32_t __dpft_count;                                                  \
                                                                                \
	__dpft_count = *__dpft_countp;                                          \
	os_atomic_store(__dpft_countp, __dpft_count + 1, compiler_acq_rel);     \
                                                                                \
	if (__dpft_count == 0 && sched_preemption_disable_debug_mode) {         \
	        _prepare_preemption_disable_measurement();                      \
	}                                                                       \
})
#else /* SCHED_HYGIENE_DEBUG */
#define lock_disable_preemption_for_thread(t) ({                                \
	uint32_t *__dpft_countp = &(t)->machine.preemption_count;               \
                                                                                \
	os_atomic_store(__dpft_countp, *__dpft_countp + 1, compiler_acq_rel);   \
})
#endif /* SCHED_HYGIENE_DEBUG */
#define lock_enable_preemption()                enable_preemption()
#define lock_preemption_level_for_thread(t)     get_preemption_level_for_thread(t)
#define lock_preemption_disabled_for_thread(t)  (get_preemption_level_for_thread(t) != 0)
#define current_thread()                        current_thread_fast()

#define __hw_spin_wait_load(ptr, load_var, cond_result, cond_expr) ({ \
	load_var = os_atomic_load_exclusive(ptr, relaxed);                      \
	cond_result = (cond_expr);                                              \
	if (__probable(cond_result)) {                                          \
	        os_atomic_clear_exclusive();                                    \
	} else {                                                                \
	        wait_for_event();                                               \
	}                                                                       \
})

#endif /* LOCK_PRIVATE */
#endif /* MACH_KERNEL_PRIVATE */
#endif /* _ARM_LOCKS_H_ */
