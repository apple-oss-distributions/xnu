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
#include <kern/kern_types.h>
#include <kern/assert.h>

#ifdef  MACH_KERNEL_PRIVATE
#define LOCKS_INDIRECT_ALLOW    1

#include <i386/hw_lock_types.h>

#define enaLkDeb                0x00000001      /* Request debug in default attribute */
#define enaLkStat               0x00000002      /* Request statistic in default attribute */
#define disLkRWPrio             0x00000004      /* Disable RW lock priority promotion */
#define enaLkTimeStat           0x00000008      /* Request time statistics in default attribute */
#define disLkRWDebug            0x00000010      /* Disable RW lock best-effort debugging */

#endif /* MACH_KERNEL_PRIVATE */

#if     defined(MACH_KERNEL_PRIVATE)
typedef struct {
	volatile uintptr_t      interlock __kernel_data_semantics;
#if     MACH_LDEBUG
	unsigned long   lck_spin_pad[9];        /* XXX - usimple_lock_data_t */
#endif
} lck_spin_t;

#define LCK_SPIN_TAG_DESTROYED          0x00002007      /* lock marked as Destroyed */

#else /* MACH_KERNEL_PRIVATE */
#ifdef  KERNEL_PRIVATE
typedef struct {
	unsigned long    opaque[10];
} lck_spin_t;
#else /* KERNEL_PRIVATE */
typedef struct __lck_spin_t__   lck_spin_t;
#endif /* KERNEL_PRIVATE */
#endif /* MACH_KERNEL_PRIVATE */

#ifdef  MACH_KERNEL_PRIVATE
/* The definition of this structure, including the layout of the
 * state bitfield, is tailored to the asm implementation in i386_lock.s
 */
typedef struct _lck_mtx_ {
	/*
	 * The mtx_owner which holds a thread_t can be "data semantics"
	 * because any dereference of it that leads to mutation
	 * will zone_id_require() that it is indeed a proper thread
	 * from the thread zone.
	 *
	 * This allows us to leave pure data with a lock into
	 * the kalloc data heap.
	 */
	union {
		struct {
			volatile uintptr_t              lck_mtx_owner __kernel_data_semantics;
			union {
				struct {
					volatile uint32_t
					    lck_mtx_waiters:16,
					    lck_mtx_pri:8, // unused
					    lck_mtx_ilocked:1,
					    lck_mtx_mlocked:1,
					    lck_mtx_promoted:1, // unused
					    lck_mtx_spin:1,
					    lck_mtx_is_ext:1,
					    lck_mtx_pad3:3;
				};
				uint32_t        lck_mtx_state;
			};
			/* Pad field used as a canary, initialized to ~0 */
			uint32_t                        lck_mtx_pad32;
		};
		struct {
			/* Marked as data as it is only dereferenced under LCK_ATTR_DEBUG */
			struct _lck_mtx_ext_            *lck_mtx_ptr __kernel_data_semantics;
			uint32_t                        lck_mtx_tag;
			uint32_t                        lck_mtx_pad32_2;
		};
	};
} lck_mtx_t;

#define LCK_MTX_WAITERS_MSK             0x0000ffff
#define LCK_MTX_WAITER                  0x00000001
#define LCK_MTX_PRIORITY_MSK            0x00ff0000
#define LCK_MTX_ILOCKED_MSK             0x01000000
#define LCK_MTX_MLOCKED_MSK             0x02000000
#define LCK_MTX_SPIN_MSK                0x08000000

/* This pattern must subsume the interlocked, mlocked and spin bits */
#define LCK_MTX_TAG_INDIRECT                    0x07ff1007      /* lock marked as Indirect  */
#define LCK_MTX_TAG_DESTROYED                   0x07fe2007      /* lock marked as Destroyed */

/* Adaptive spin before blocking */
extern uint64_t         MutexSpin;
extern uint64_t         low_MutexSpin;
extern int64_t         high_MutexSpin;

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
extern void                                     lck_mtx_lock_wait_x86(lck_mtx_t *mutex, struct turnstile **ts);
extern void                                     lck_mtx_lock_acquire_x86(lck_mtx_t *mutex);

extern void                                     lck_mtx_lock_slow(lck_mtx_t *lock);
extern boolean_t                                lck_mtx_try_lock_slow(lck_mtx_t *lock);
extern void                                     lck_mtx_unlock_slow(lck_mtx_t *lock);
extern void                                     lck_mtx_lock_spin_slow(lck_mtx_t *lock);
extern boolean_t                                lck_mtx_try_lock_spin_slow(lck_mtx_t *lock);
extern void                                     hw_lock_byte_init(volatile uint8_t *lock_byte);
extern void                                     hw_lock_byte_lock(volatile uint8_t *lock_byte);
extern void                                     hw_lock_byte_unlock(volatile uint8_t *lock_byte);

typedef struct {
	unsigned int            type;
	unsigned int            pad4;
	vm_offset_t             pc;
	vm_offset_t             thread;
} lck_mtx_deb_t;

#define MUTEX_TAG       0x4d4d

typedef struct {
	unsigned int            lck_mtx_stat_data;
} lck_mtx_stat_t;

typedef struct _lck_mtx_ext_ {
	lck_mtx_t               lck_mtx;
	struct _lck_grp_        *lck_mtx_grp;
	unsigned int            lck_mtx_attr;
	unsigned int            lck_mtx_pad1;
	lck_mtx_deb_t           lck_mtx_deb;
	uint64_t                lck_mtx_stat;
	unsigned int            lck_mtx_pad2[2];
} lck_mtx_ext_t;

#define LCK_MTX_ATTR_DEBUG      0x1
#define LCK_MTX_ATTR_DEBUGb     0
#define LCK_MTX_ATTR_STAT       0x2
#define LCK_MTX_ATTR_STATb      1

#define LCK_MTX_EVENT(lck)        ((event_t)(((unsigned int*)(lck))+(sizeof(lck_mtx_t)-1)/sizeof(unsigned int)))
#define LCK_EVENT_TO_MUTEX(event) ((lck_mtx_t *)(uintptr_t)(((unsigned int *)(event)) - ((sizeof(lck_mtx_t)-1)/sizeof(unsigned int))))

#else /* MACH_KERNEL_PRIVATE */
#ifdef  XNU_KERNEL_PRIVATE
typedef struct {
	unsigned long           opaque[2];
} lck_mtx_t;

typedef struct {
	unsigned long           opaque[10];
} lck_mtx_ext_t;
#else /* XNU_KERNEL_PRIVATE */
#ifdef  KERNEL_PRIVATE
typedef struct {
	unsigned long           opaque[2];
} lck_mtx_t;

typedef struct {
	unsigned long           opaque[10];
} lck_mtx_ext_t;

#else /* KERNEL_PRIVATE */
typedef struct __lck_mtx_t__            lck_mtx_t;
typedef struct __lck_mtx_ext_t__        lck_mtx_ext_t;
#endif /* KERNEL_PRIVATE */
#endif /* XNU_KERNEL_PRIVATE */
#endif /* MACH_KERNEL_PRIVATE */

#ifdef  MACH_KERNEL_PRIVATE

/*
 * static panic deadline, in timebase units, for
 * hw_lock_{bit,lock}{,_nopreempt} and hw_wait_while_equals()
 */
extern uint64_t _Atomic lock_panic_timeout;

#if LOCK_PRIVATE

#define lock_disable_preemption_for_thread(t)   disable_preemption_internal()
#define lock_preemption_disabled_for_thread(t)  (get_preemption_level() > 0)

#define LCK_MTX_THREAD_TO_STATE(t)      ((uintptr_t)t)
#define PLATFORM_LCK_ILOCK              0

#define LOCK_SNOOP_SPINS        1000
#define LOCK_PRETEST            1

#endif  // LOCK_PRIVATE

extern void             kernel_preempt_check(void);

#endif /* MACH_KERNEL_PRIVATE */
#endif  /* _I386_LOCKS_H_ */
