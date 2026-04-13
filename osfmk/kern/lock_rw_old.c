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
#define LOCK_PRIVATE 1
#include <debug.h>
#include <kern/locks_internal.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>

#define lck_rw_word_t                   lck_rw_word_old_t
#define lck_rw_t                        lck_rw_old_t

#if !XNU_LCK_RW_DEFAULT_TO_NEW
KALLOC_TYPE_DEFINE(KT_LCK_RW, lck_rw_t, KT_PRIV_ACCT);
#endif /* !XNU_LCK_RW_DEFAULT_TO_NEW */

#define LCK_RW_WRITER_EVENT(lck)                (event_t)((uintptr_t)(lck)+1)
#define LCK_RW_READER_EVENT(lck)                (event_t)((uintptr_t)(lck)+2)

#define LCK_RW_SHARED_READER_OFFSET      0
#define LCK_RW_INTERLOCK_BIT            16
#define LCK_RW_PRIV_EXCL_BIT            17
#define LCK_RW_WANT_UPGRADE_BIT         18
#define LCK_RW_WANT_EXCL_BIT            19
#define LCK_RW_R_WAITING_BIT            20
#define LCK_RW_W_WAITING_BIT            21
#define LCK_RW_CAN_SLEEP_BIT            22
//                                      23-30
#define LCK_RW_TAG_VALID_BIT            31

#define LCK_RW_INTERLOCK                (1U << LCK_RW_INTERLOCK_BIT)
#define LCK_RW_R_WAITING                (1U << LCK_RW_R_WAITING_BIT)
#define LCK_RW_W_WAITING                (1U << LCK_RW_W_WAITING_BIT)
#define LCK_RW_WANT_UPGRADE             (1U << LCK_RW_WANT_UPGRADE_BIT)
#define LCK_RW_WANT_EXCL                (1U << LCK_RW_WANT_EXCL_BIT)
#define LCK_RW_TAG_VALID                (1U << LCK_RW_TAG_VALID_BIT)
#define LCK_RW_PRIV_EXCL                (1U << LCK_RW_PRIV_EXCL_BIT)
#define LCK_RW_SHARED_MASK              (0xffff << LCK_RW_SHARED_READER_OFFSET)
#define LCK_RW_SHARED_READER            (0x1 << LCK_RW_SHARED_READER_OFFSET)

#define LCK_RW_TAG_DESTROYED            ((LCK_RW_TAG_VALID | 0xdddddeadu))      /* lock marked as Destroyed */

#define LCK_RW_LCK_EXCLUSIVE_CODE       0x100
#define LCK_RW_LCK_EXCLUSIVE1_CODE      0x101
#define LCK_RW_LCK_SHARED_CODE          0x102
#define LCK_RW_LCK_SH_TO_EX_CODE        0x103
#define LCK_RW_LCK_SH_TO_EX1_CODE       0x104
#define LCK_RW_LCK_EX_TO_SH_CODE        0x105

#if __x86_64__
#define LCK_RW_LCK_EX_WRITER_SPIN_CODE  0x106
#define LCK_RW_LCK_EX_WRITER_WAIT_CODE  0x107
#define LCK_RW_LCK_EX_READER_SPIN_CODE  0x108
#define LCK_RW_LCK_EX_READER_WAIT_CODE  0x109
#define LCK_RW_LCK_SHARED_SPIN_CODE     0x110
#define LCK_RW_LCK_SHARED_WAIT_CODE     0x111
#define LCK_RW_LCK_SH_TO_EX_SPIN_CODE   0x112
#define LCK_RW_LCK_SH_TO_EX_WAIT_CODE   0x113
#endif

#define lck_rw_ilk_lock(lock)   hw_lock_bit  ((hw_lock_bit_t*)(&(lock)->lck_rw_tag), LCK_RW_INTERLOCK_BIT, LCK_GRP_NULL)
#define lck_rw_ilk_unlock(lock) hw_unlock_bit((hw_lock_bit_t*)(&(lock)->lck_rw_tag), LCK_RW_INTERLOCK_BIT)

#define ordered_load_rw(lock)                   os_atomic_load(&(lock)->lck_rw_data, compiler_acq_rel)
#define ordered_store_rw(lock, value)           os_atomic_store(&(lock)->lck_rw_data, (value), compiler_acq_rel)
#define ordered_store_rw_owner(lock, value)     os_atomic_store(&(lock)->lck_rw_owner, (value), compiler_acq_rel)

#if !XNU_LCK_RW_DEFAULT_TO_NEW

/*!
 * @function lck_rw_alloc_init
 *
 * @abstract
 * Allocates and initializes a rw_lock_t.
 *
 * @discussion
 * The function can block. See lck_rw_init() for initialization details.
 *
 * @param grp           lock group to associate with the lock.
 * @param attr          lock attribute to initialize the lock.
 *
 * @returns             NULL or the allocated lock
 */
lck_rw_t *
lck_rw_alloc_init(
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	lck_rw_t *lck;

	lck = zalloc_flags(KT_LCK_RW, Z_WAITOK | Z_ZERO);
	lck_rw_init(lck, grp, attr);
	return lck;
}

/*!
 * @function lck_rw_free
 *
 * @abstract
 * Frees a rw_lock previously allocated with lck_rw_alloc_init().
 *
 * @discussion
 * The lock must be not held by any thread.
 *
 * @param lck           rw_lock to free.
 */
void
lck_rw_free(
	lck_rw_t        *lck,
	lck_grp_t       *grp)
{
	lck_rw_destroy(lck, grp);
	zfree(KT_LCK_RW, lck);
}

#endif /* !XNU_LCK_RW_DEFAULT_TO_NEW */

/*!
 * @function lck_rw_init
 *
 * @abstract
 * Initializes a rw_lock_t.
 *
 * @discussion
 * Usage statistics for the lock are going to be added to the lock group provided.
 *
 * The lock attribute can be used to specify the lock contention behaviour.
 * RW_WRITER_PRIORITY is the default behaviour (LCK_ATTR_NULL defaults to RW_WRITER_PRIORITY)
 * and lck_attr_rw_shared_priority() can be used to set the behaviour to RW_SHARED_PRIORITY.
 *
 * RW_WRITER_PRIORITY gives priority to the writers upon contention with the readers;
 * if the lock is held and a writer starts waiting for the lock, readers will not be able
 * to acquire the lock until all writers stop contending. Readers could
 * potentially starve.
 * RW_SHARED_PRIORITY gives priority to the readers upon contention with the writers:
 * unleass the lock is held in exclusive mode, readers will always be able to acquire the lock.
 * Readers can lock a shared lock even if there are writers waiting. Writers could potentially
 * starve.
 *
 * @param lck           lock to initialize.
 * @param grp           lock group to associate with the lock.
 * @param attrp         lock attribute to initialize the lock.
 *
 */
__lck_rw_old_func
void
lck_rw_init(
	lck_rw_t        *lck,
	lck_grp_t       *grp,
	lck_attr_t      *attrp)
{
	/* keep this so that the lck_type_t type is referenced for lldb */
	lck_type_t type = LCK_TYPE_RW_LEGACY;
	uint32_t   attr = (attrp ?: &lck_attr_default)->lck_attr_val;

	*lck = (lck_rw_t){
		.lck_rw_type      = type,
		.lck_rw_priv_excl = !(attr & LCK_ATTR_RW_SHARED_PRIORITY),
		.lck_rw_can_sleep = !(attr & LCK_ATTR_RW_NO_SLEEP),
	};
	lck_grp_reference(grp, &grp->lck_grp_rwcnt);
}

/*!
 * @function lck_rw_destroy
 *
 * @abstract
 * Destroys a rw_lock previously initialized with lck_rw_init().
 *
 * @discussion
 * The lock must be not held by any thread.
 *
 * @param lck           rw_lock to destroy.
 */
__lck_rw_old_func
void
lck_rw_destroy(
	lck_rw_t        *lck,
	lck_grp_t       *grp)
{
	if (lck->lck_rw_type != LCK_TYPE_RW_LEGACY ||
	    lck->lck_rw_tag == LCK_RW_TAG_DESTROYED) {
		panic("Destroying previously destroyed lock %p", lck);
	}
	lck_rw_assert(lck, LCK_RW_ASSERT_NOTHELD);

	lck->lck_rw_type = LCK_TYPE_NONE;
	lck->lck_rw_tag = LCK_RW_TAG_DESTROYED;
	lck_grp_deallocate(grp, &grp->lck_grp_rwcnt);
}

#if MACH_ASSERT
#define __lck_rw_caller         ptrauth_nop_cast(uintptr_t, __builtin_return_address(0))
#else
#define __lck_rw_caller         0
#endif /* MACH_ASSERT */

/*
 * We disable interrupts while holding the RW interlock to prevent an
 * interrupt from exacerbating hold time.
 * Hence, local helper functions lck_interlock_lock()/lck_interlock_unlock().
 */
static inline boolean_t
lck_interlock_lock(
	lck_rw_t        *lck)
{
	boolean_t       istate;

	istate = ml_set_interrupts_enabled(FALSE);
	lck_rw_ilk_lock(lck);
	return istate;
}

static inline void
lck_interlock_unlock(
	lck_rw_t        *lck,
	boolean_t       istate)
{
	lck_rw_ilk_unlock(lck);
	ml_set_interrupts_enabled(istate);
}

/*
 * compute the deadline to spin against when
 * waiting for a change of state on a lck_rw_t
 */
static inline uint64_t
lck_rw_deadline_for_spin(
	lck_rw_t        *lck)
{
	lck_rw_word_t   word;

	word.data = ordered_load_rw(lck);
	if (word.can_sleep) {
		if (word.r_waiting || word.w_waiting || (word.shared_count > machine_info.max_cpus)) {
			/*
			 * there are already threads waiting on this lock... this
			 * implies that they have spun beyond their deadlines waiting for
			 * the desired state to show up so we will not bother spinning at this time...
			 *   or
			 * the current number of threads sharing this lock exceeds our capacity to run them
			 * concurrently and since all states we're going to spin for require the rw_shared_count
			 * to be at 0, we'll not bother spinning since the latency for this to happen is
			 * unpredictable...
			 */
			return mach_absolute_time();
		}
		return mach_absolute_time() + os_atomic_load(&MutexSpin, relaxed);
	} else {
		return mach_absolute_time() + (100000LL * 1000000000LL);
	}
}

/*
 * This inline is used when busy-waiting for an rw lock.
 * If interrupts were disabled when the lock primitive was called,
 * we poll the IPI handler for pending tlb flushes in x86.
 */
static inline void
lck_rw_lock_pause(
	boolean_t       interrupts_enabled)
{
#if X86_64
	if (!interrupts_enabled) {
		handle_pending_TLB_flushes();
	}
	cpu_pause();
#else
	(void) interrupts_enabled;
	wait_for_event();
#endif
}

typedef enum __enum_closed {
	LCK_RW_DRAIN_S_DRAINED       = 0,
	LCK_RW_DRAIN_S_NOT_DRAINED   = 1,
	LCK_RW_DRAIN_S_EARLY_RETURN  = 2,
	LCK_RW_DRAIN_S_TIMED_OUT     = 3,
} lck_rw_drain_state_t;

static lck_rw_drain_state_t
lck_rw_drain_status(
	lck_rw_t        *lock,
	uint32_t        status_mask,
	boolean_t       wait,
	bool            (^lock_pause)(void))
{
	uint64_t        deadline = 0;
	uint32_t        data;
	boolean_t       istate = FALSE;

	if (wait) {
		deadline = lck_rw_deadline_for_spin(lock);
#if __x86_64__
		istate = ml_get_interrupts_enabled();
#endif
	}

	for (;;) {
#if __x86_64__
		data = os_atomic_load(&lock->lck_rw_data, relaxed);
#else
		data = load_exclusive32(&lock->lck_rw_data, memory_order_acquire_smp);
#endif
		if ((data & status_mask) == 0) {
			atomic_exchange_abort();
			return LCK_RW_DRAIN_S_DRAINED;
		}

		if (!wait) {
			atomic_exchange_abort();
			return LCK_RW_DRAIN_S_NOT_DRAINED;
		}

		lck_rw_lock_pause(istate);

		if (mach_absolute_time() >= deadline) {
			return LCK_RW_DRAIN_S_TIMED_OUT;
		}

		if (lock_pause && lock_pause()) {
			return LCK_RW_DRAIN_S_EARLY_RETURN;
		}
	}
}

/*
 * Spin while interlock is held.
 */
static inline void
lck_rw_interlock_spin(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_relaxed);
		if (data & LCK_RW_INTERLOCK) {
#if __x86_64__
			cpu_pause();
#else
			wait_for_event();
#endif
		} else {
			atomic_exchange_abort();
			return;
		}
	}
}

#define LCK_RW_GRAB_WANT        0
#define LCK_RW_GRAB_SHARED      1

typedef enum __enum_closed __enum_options {
	LCK_RW_GRAB_F_SHARED    = 0x0,  // Not really a flag obviously but makes call sites more readable.
	LCK_RW_GRAB_F_WANT_EXCL = 0x1,
	LCK_RW_GRAB_F_WAIT      = 0x2,
} lck_rw_grab_flags_t;

typedef enum __enum_closed {
	LCK_RW_GRAB_S_NOT_LOCKED    = 0,
	LCK_RW_GRAB_S_LOCKED        = 1,
	LCK_RW_GRAB_S_EARLY_RETURN  = 2,
	LCK_RW_GRAB_S_TIMED_OUT     = 3,
} lck_rw_grab_state_t;

static lck_rw_grab_state_t
lck_rw_grab(
	lck_rw_t            *lock,
	lck_rw_grab_flags_t flags,
	bool                (^lock_pause)(void))
{
	uint64_t        deadline = 0;
	uint32_t        data, prev;
	boolean_t       do_exch, istate = FALSE;

	assert3u(flags & ~(LCK_RW_GRAB_F_WANT_EXCL | LCK_RW_GRAB_F_WAIT), ==, 0);

	if ((flags & LCK_RW_GRAB_F_WAIT) != 0) {
		deadline = lck_rw_deadline_for_spin(lock);
#if __x86_64__
		istate = ml_get_interrupts_enabled();
#endif
	}

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		do_exch = FALSE;
		if ((flags & LCK_RW_GRAB_F_WANT_EXCL) != 0) {
			if ((data & LCK_RW_WANT_EXCL) == 0) {
				data |= LCK_RW_WANT_EXCL;
				do_exch = TRUE;
			}
		} else {        // LCK_RW_GRAB_SHARED
			if (((data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) == 0) ||
			    (((data & LCK_RW_SHARED_MASK)) && ((data & LCK_RW_PRIV_EXCL) == 0))) {
				data += LCK_RW_SHARED_READER;
				do_exch = TRUE;
			}
		}
		if (do_exch) {
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				return LCK_RW_GRAB_S_LOCKED;
			}
		} else {
			if ((flags & LCK_RW_GRAB_F_WAIT) == 0) {
				atomic_exchange_abort();
				return LCK_RW_GRAB_S_NOT_LOCKED;
			}

			lck_rw_lock_pause(istate);

			if (mach_absolute_time() >= deadline) {
				return LCK_RW_GRAB_S_TIMED_OUT;
			}
			if (lock_pause && lock_pause()) {
				return LCK_RW_GRAB_S_EARLY_RETURN;
			}
		}
	}
}

/*
 * The inverse of lck_rw_grab - drops either the LCK_RW_WANT_EXCL bit or
 * decrements the reader count. Doesn't deal with waking up waiters - i.e.
 * should only be called when can_sleep is false.
 */
static void
lck_rw_drop(lck_rw_t *lock, lck_rw_grab_flags_t flags)
{
	uint32_t data, prev;

	assert3u(flags & ~(LCK_RW_GRAB_F_WANT_EXCL | LCK_RW_GRAB_F_WAIT), ==, 0);
	assert(!lock->lck_rw_can_sleep);

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);

		/* Interlock should never be taken when can_sleep is false. */
		assert3u(data & LCK_RW_INTERLOCK, ==, 0);

		if ((flags & LCK_RW_GRAB_F_WANT_EXCL) != 0) {
			data &= ~LCK_RW_WANT_EXCL;
		} else {
			data -= LCK_RW_SHARED_READER;
		}

		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}

		cpu_pause();
	}

	return;
}

static boolean_t
lck_rw_lock_exclusive_gen(
	lck_rw_t        *lock,
	bool            (^lock_pause)(void))
{
	__assert_only thread_t self = current_thread();
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	lck_rw_word_t           word;
	int                     slept = 0;
	lck_rw_grab_state_t     grab_state = LCK_RW_GRAB_S_NOT_LOCKED;
	lck_rw_drain_state_t    drain_state = LCK_RW_DRAIN_S_NOT_DRAINED;
	wait_result_t           res = 0;
	boolean_t               istate;

#if     CONFIG_DTRACE
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_excl_spin, dtrace_rwl_excl_block, dtrace_ls_enabled = FALSE;
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
#endif

	assertf(lock->lck_rw_owner != self->ctid,
	    "Lock already held state=0x%x, owner=%p",
	    ordered_load_rw(lock), self);

	/*
	 * Best effort attempt to check that this thread
	 * is not already holding the lock (this checks read mode too).
	 */
	lck_rw_dbg_assert_canlock(lock, LCK_RW_TYPE_EXCLUSIVE);

	/*
	 *	Try to acquire the lck_rw_want_excl bit.
	 */
	while (lck_rw_grab(lock, LCK_RW_GRAB_F_WANT_EXCL, NULL) != LCK_RW_GRAB_S_LOCKED) {
#if     CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] != 0);
			dtrace_rwl_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_excl_spin || dtrace_rwl_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lock->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, 0, 0, 0, 0);

		grab_state = lck_rw_grab(lock, LCK_RW_GRAB_F_WANT_EXCL | LCK_RW_GRAB_F_WAIT, lock_pause);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, 0, 0, grab_state, 0);

		if (grab_state == LCK_RW_GRAB_S_LOCKED ||
		    grab_state == LCK_RW_GRAB_S_EARLY_RETURN) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		word.data = ordered_load_rw(lock);
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);
			word.data = ordered_load_rw(lock);

			if (word.want_excl) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);
				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				word.want_excl = 1;
				ordered_store_rw(lock, word.data);
				lck_interlock_unlock(lock, istate);
				break;
			}
		}
	}

	if (grab_state == LCK_RW_GRAB_S_EARLY_RETURN) {
		assert(lock_pause);
		return FALSE;
	}

	/*
	 * Wait for readers (and upgrades) to finish...
	 */
	while (lck_rw_drain_status(lock, LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE, FALSE, NULL) != LCK_RW_DRAIN_S_DRAINED) {
#if     CONFIG_DTRACE
		/*
		 * Either sleeping or spinning is happening, start
		 * a timing of our delay interval now.  If we set it
		 * to -1 we don't have accurate data so we cannot later
		 * decide to record a dtrace spin or sleep event.
		 */
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] != 0);
			dtrace_rwl_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_excl_spin || dtrace_rwl_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lock->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		drain_state = lck_rw_drain_status(lock, LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE, TRUE, lock_pause);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, drain_state, 0);

		if (drain_state == LCK_RW_DRAIN_S_DRAINED ||
		    drain_state == LCK_RW_DRAIN_S_EARLY_RETURN) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		word.data = ordered_load_rw(lock);
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);
			word.data = ordered_load_rw(lock);

			if (word.shared_count != 0 || word.want_upgrade) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lock, istate);
				/*
				 * must own the lock now, since we checked for
				 * readers or upgrade owner behind the interlock
				 * no need for a call to 'lck_rw_drain_status'
				 */
				break;
			}
		}
	}

#if     CONFIG_DTRACE
	/*
	 * Decide what latencies we suffered that are Dtrace events.
	 * If we have set wait_interval, then we either spun or slept.
	 * At least we get out from under the interlock before we record
	 * which is the best we can do here to minimize the impact
	 * of the tracing.
	 * If we have set wait_interval to -1, then dtrace was not enabled when we
	 * started sleeping/spinning so we don't record this event.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_SPIN, lock,
			    mach_absolute_time() - wait_interval, 1);
		} else {
			/*
			 * For the blocking case, we also record if when we blocked
			 * it was held for read or write, and how many readers.
			 * Notice that above we recorded this before we dropped
			 * the interlock so the count is accurate.
			 */
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_BLOCK, lock,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
#endif /* CONFIG_DTRACE */

	if (drain_state == LCK_RW_DRAIN_S_EARLY_RETURN) {
		lck_rw_drop(lock, LCK_RW_GRAB_F_WANT_EXCL);
		assert(lock_pause);
		return FALSE;
	}

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, 1);
#endif  /* CONFIG_DTRACE */

	return TRUE;
}

static inline void
lck_rw_lock_check_preemption(lck_rw_t *lock __unused)
{
	assertf((get_preemption_level() == 0 && ml_get_interrupts_enabled()) ||
	    startup_phase < STARTUP_SUB_EARLY_BOOT ||
	    current_cpu_datap()->cpu_hibernate ||
	    ml_is_quiescing() ||
	    !not_in_kdp,
	    "%s: attempt to take rwlock %p in non-preemptible or interrupt context: "
	    "preemption level = %d, interruptible = %d", __func__, lock,
	    get_preemption_level(), (int)ml_get_interrupts_enabled());
}

#define LCK_RW_LOCK_EXCLUSIVE_TAS(lck) (atomic_test_and_set32(&(lck)->lck_rw_data, \
	    (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK), \
	    LCK_RW_WANT_EXCL, memory_order_acquire_smp, FALSE))

__attribute__((always_inline))
static boolean_t
lck_rw_lock_exclusive_internal_inline(
	lck_rw_t        *lock,
	uintptr_t        caller,
	bool            (^lock_pause)(void))
{
#pragma unused(caller)
	thread_t        thread = current_thread();

	if (lock->lck_rw_can_sleep) {
		lck_rw_lock_check_preemption(lock);
		lck_rw_lock_count_inc(thread, lock);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	if (LCK_RW_LOCK_EXCLUSIVE_TAS(lock)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */
	} else if (!lck_rw_lock_exclusive_gen(lock, lock_pause)) {
		/*
		 * lck_rw_lock_exclusive_gen() should only return
		 * early if lock_pause has been passed and
		 * returns FALSE. lock_pause is exclusive with
		 * lck_rw_can_sleep().
		 */
		assert(!lock->lck_rw_can_sleep);
		return FALSE;
	}

	assertf(lock->lck_rw_owner == 0, "state=0x%x, owner=%p",
	    ordered_load_rw(lock), ctid_get_thread_unsafe(lock->lck_rw_owner));
	ordered_store_rw_owner(lock, thread->ctid);

	lck_rw_dbg_add(lock, LCK_RW_TYPE_EXCLUSIVE, caller);
	return TRUE;
}

__attribute__((noinline))
static void
lck_rw_lock_exclusive_internal(lck_rw_t *lock, uintptr_t caller)
{
	(void) lck_rw_lock_exclusive_internal_inline(lock, caller, NULL);
}

/*!
 * @function lck_rw_lock_exclusive
 *
 * @abstract
 * Locks a rw_lock in exclusive mode.
 *
 * @discussion
 * This function can block.
 * Multiple threads can acquire the lock in shared mode at the same time, but only one thread at a time
 * can acquire it in exclusive mode.
 * NOTE: the thread cannot return to userspace while the lock is held. Recursive locking is not supported.
 *
 * @param lock           rw_lock to lock.
 */
__mockable
__lck_rw_old_func
void
lck_rw_lock_exclusive(
	lck_rw_t        *lock)
{
	(void) lck_rw_lock_exclusive_internal_inline(lock, __lck_rw_caller, NULL);
}

/*!
 * @function lck_rw_lock_exclusive_b
 *
 * @abstract
 * Locks a rw_lock in exclusive mode. Returns early if the lock can't be acquired
 * and the specified block returns true.
 *
 * @discussion
 * Identical to lck_rw_lock_exclusive() but can return early if the lock can't be
 * acquired and the specified block returns true. The block is called
 * repeatedly when waiting to acquire the lock.
 * Should only be called when the lock cannot sleep (i.e. when
 * lock->lck_rw_can_sleep is false).
 *
 * @param lock           rw_lock to lock.
 * @param lock_pause     block invoked while waiting to acquire lock
 *
 * @returns              Returns TRUE if the lock is successfully taken,
 *                       FALSE if the block returns true and the lock has
 *                       not been acquired.
 */
boolean_t
lck_rw_lock_exclusive_b(
	lck_rw_t        *lock,
	bool            (^lock_pause)(void))
{
	assert(!lock->lck_rw_can_sleep);

	return lck_rw_lock_exclusive_internal_inline(lock, __lck_rw_caller, lock_pause);
}

/*
 *	Routine:	lck_rw_lock_shared_gen
 *	Function:
 *		Fast path code has determined that this lock
 *		is held exclusively... this is where we spin/block
 *		until we can acquire the lock in the shared mode
 */
static boolean_t
lck_rw_lock_shared_gen(
	lck_rw_t        *lck,
	bool            (^lock_pause)(void))
{
	__assert_only thread_t  self = current_thread();
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	lck_rw_word_t           word;
	lck_rw_grab_state_t     grab_state = LCK_RW_GRAB_S_NOT_LOCKED;
	int                     slept = 0;
	wait_result_t           res = 0;
	boolean_t               istate;

#if     CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_shared_spin, dtrace_rwl_shared_block, dtrace_ls_enabled = FALSE;
#endif /* CONFIG_DTRACE */

	assertf(lck->lck_rw_owner != self->ctid,
	    "Lock already held state=0x%x, owner=%p",
	    ordered_load_rw(lck), self);

	/*
	 * Best effort attempt to check that this thread
	 * is not already holding the lock in shared mode.
	 */
	lck_rw_dbg_assert_canlock(lck, LCK_RW_TYPE_SHARED);

	while (lck_rw_grab(lck, LCK_RW_GRAB_F_SHARED, NULL) != LCK_RW_GRAB_S_LOCKED) {
#if     CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_shared_spin = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_SPIN] != 0);
			dtrace_rwl_shared_block = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_shared_spin || dtrace_rwl_shared_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lck->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, 0, 0);

		grab_state = lck_rw_grab(lck, LCK_RW_GRAB_F_SHARED | LCK_RW_GRAB_F_WAIT, lock_pause);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, grab_state, 0);

		if (grab_state == LCK_RW_GRAB_S_LOCKED ||
		    grab_state == LCK_RW_GRAB_S_EARLY_RETURN) {
			break;
		}

		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock for read
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {
			istate = lck_interlock_lock(lck);

			word.data = ordered_load_rw(lck);
			if ((word.want_excl || word.want_upgrade) &&
			    ((word.shared_count == 0) || word.priv_excl)) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_START,
				    trace_lck, word.want_excl, word.want_upgrade, 0, 0);

				word.r_waiting = 1;
				ordered_store_rw(lck, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockRead);
				res = assert_wait(LCK_RW_READER_EVENT(lck),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_END,
				    trace_lck, res, slept, 0, 0);
			} else {
				word.shared_count++;
				ordered_store_rw(lck, word.data);
				lck_interlock_unlock(lck, istate);
				break;
			}
		}
	}

#if     CONFIG_DTRACE
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 0,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
#endif /* CONFIG_DTRACE */

	if (grab_state == LCK_RW_GRAB_S_EARLY_RETURN) {
		assert(lock_pause);
		return FALSE;
	}

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lck, 0);
#endif  /* CONFIG_DTRACE */

	return TRUE;
}

__attribute__((always_inline))
static boolean_t
lck_rw_lock_shared_internal_inline(
	lck_rw_t        *lock,
	uintptr_t        caller,
	bool            (^lock_pause)(void))
{
#pragma unused(caller)

	uint32_t        data, prev;
	thread_t        thread = current_thread();
	boolean_t       check_canlock = TRUE;

	if (lock->lck_rw_can_sleep) {
		lck_rw_lock_check_preemption(lock);
		lck_rw_lock_count_inc(thread, lock);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK)) {
			atomic_exchange_abort();
			if (!lck_rw_lock_shared_gen(lock, lock_pause)) {
				/*
				 * lck_rw_lock_shared_gen() should only return
				 * early if lock_pause has been passed and
				 * returns FALSE. lock_pause is exclusive with
				 * lck_rw_can_sleep().
				 */
				assert(!lock->lck_rw_can_sleep);
				return FALSE;
			}

			goto locked;
		}
		if ((data & LCK_RW_SHARED_MASK) == 0) {
			/*
			 * If the lock is uncontended,
			 * we do not need to check if we can lock it
			 */
			check_canlock = FALSE;
		}
		data += LCK_RW_SHARED_READER;
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
	if (check_canlock) {
		/*
		 * Best effort attempt to check that this thread
		 * is not already holding the lock (this checks read mode too).
		 */
		lck_rw_dbg_assert_canlock(lock, LCK_RW_TYPE_SHARED);
	}
locked:
	assertf(lock->lck_rw_owner == 0, "state=0x%x, owner=%p",
	    ordered_load_rw(lock), ctid_get_thread_unsafe(lock->lck_rw_owner));

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif  /* CONFIG_DTRACE */

	lck_rw_dbg_add(lock, LCK_RW_TYPE_SHARED, caller);
	return TRUE;
}

__attribute__((noinline))
static void
lck_rw_lock_shared_internal(lck_rw_t *lock, uintptr_t caller)
{
	(void) lck_rw_lock_shared_internal_inline(lock, caller, NULL);
}

/*!
 * @function lck_rw_lock_shared
 *
 * @abstract
 * Locks a rw_lock in shared mode.
 *
 * @discussion
 * This function can block.
 * Multiple threads can acquire the lock in shared mode at the same time, but only one thread at a time
 * can acquire it in exclusive mode.
 * If the lock is held in shared mode and there are no writers waiting, a reader will be able to acquire
 * the lock without waiting.
 * If the lock is held in shared mode and there is at least a writer waiting, a reader will wait
 * for all the writers to make progress if the lock was initialized with the default settings. Instead if
 * RW_SHARED_PRIORITY was selected at initialization time, a reader will never wait if the lock is held
 * in shared mode.
 * NOTE: the thread cannot return to userspace while the lock is held. Recursive locking is not supported.
 *
 * @param lock           rw_lock to lock.
 */
__mockable
__lck_rw_old_func
void
lck_rw_lock_shared(
	lck_rw_t        *lock)
{
	(void) lck_rw_lock_shared_internal_inline(lock, __lck_rw_caller, NULL);
}

/*!
 * @function lck_rw_lock_shared_b
 *
 * @abstract
 * Locks a rw_lock in shared mode. Returns early if the lock can't be acquired
 * and the specified block returns true.
 *
 * @discussion
 * Identical to lck_rw_lock_shared() but can return early if the lock can't be
 * acquired and the specified block returns true. The block is called
 * repeatedly when waiting to acquire the lock.
 * Should only be called when the lock cannot sleep (i.e. when
 * lock->lck_rw_can_sleep is false).
 *
 * @param lock           rw_lock to lock.
 * @param lock_pause     block invoked while waiting to acquire lock
 *
 * @returns              Returns TRUE if the lock is successfully taken,
 *                       FALSE if the block returns true and the lock has
 *                       not been acquired.
 */
boolean_t
lck_rw_lock_shared_b(
	lck_rw_t        *lock,
	bool            (^lock_pause)(void))
{
	assert(!lock->lck_rw_can_sleep);

	return lck_rw_lock_shared_internal_inline(lock, __lck_rw_caller, lock_pause);
}

/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_failure
 *	Function:
 *		Fast path code has already dropped our read
 *		count and determined that someone else owns 'lck_rw_want_upgrade'
 *		if 'lck_rw_shared_count' == 0, its also already dropped 'lck_w_waiting'
 *		all we need to do here is determine if a wakeup is needed
 */
static boolean_t
lck_rw_lock_shared_to_exclusive_failure(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	thread_t        thread = current_thread();

	if ((prior_lock_state & LCK_RW_W_WAITING) &&
	    ((prior_lock_state & LCK_RW_SHARED_MASK) == LCK_RW_SHARED_READER)) {
		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released the read lock, wake
		 *	him up if he's blocked waiting
		 */
		thread_wakeup(LCK_RW_WRITER_EVENT(lck));
	}

	/* Check if dropping the lock means that we need to unpromote */
	if (lck->lck_rw_can_sleep) {
		lck_rw_lock_count_dec(thread, lck);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), lck->lck_rw_shared_count, lck->lck_rw_want_upgrade, 0, 0);

	lck_rw_dbg_remove(lck, LCK_RW_TYPE_SHARED);
	return FALSE;
}

/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_success
 *	Function:
 *		the fast path code has already dropped our read
 *		count and successfully acquired 'lck_rw_want_upgrade'
 *		we just need to wait for the rest of the readers to drain
 *		and then we can return as the exclusive holder of this lock
 */
static void
lck_rw_lock_shared_to_exclusive_success(
	lck_rw_t        *lock)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	int                     slept = 0;
	lck_rw_word_t           word;
	wait_result_t           res;
	boolean_t               istate;
	lck_rw_drain_state_t    drain_state;

#if     CONFIG_DTRACE
	uint64_t                wait_interval = 0;
	int                     readers_at_sleep = 0;
	boolean_t               dtrace_ls_initialized = FALSE;
	boolean_t               dtrace_rwl_shared_to_excl_spin, dtrace_rwl_shared_to_excl_block, dtrace_ls_enabled = FALSE;
#endif

	while (lck_rw_drain_status(lock, LCK_RW_SHARED_MASK, FALSE, NULL) != LCK_RW_DRAIN_S_DRAINED) {
		word.data = ordered_load_rw(lock);
#if     CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_shared_to_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN] != 0);
			dtrace_rwl_shared_to_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_shared_to_excl_spin || dtrace_rwl_shared_to_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = word.shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, word.shared_count, 0, 0, 0);

		drain_state = lck_rw_drain_status(lock, LCK_RW_SHARED_MASK, TRUE, NULL);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, lock->lck_rw_shared_count, 0, 0, 0);

		if (drain_state == LCK_RW_DRAIN_S_DRAINED) {
			break;
		}

		/*
		 * if we get here, the spin deadline in lck_rw_wait_on_status()
		 * has expired w/o the rw_shared_count having drained to 0
		 * check to see if we're allowed to do a thread_block
		 */
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);

			word.data = ordered_load_rw(lock);
			if (word.shared_count != 0) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_START,
				    trace_lck, word.shared_count, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockUpgrade);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_END,
				    trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lock, istate);
				break;
			}
		}
	}
#if     CONFIG_DTRACE
	/*
	 * We infer whether we took the sleep/spin path above by checking readers_at_sleep.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, lock, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, lock,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 1);
#endif
}

/*!
 * @function lck_rw_lock_shared_to_exclusive
 *
 * @abstract
 * Upgrades a rw_lock held in shared mode to exclusive.
 *
 * @discussion
 * This function can block.
 * Only one reader at a time can upgrade to exclusive mode. If the upgrades fails the function will
 * return with the lock not held.
 * The caller needs to hold the lock in shared mode to upgrade it.
 *
 * @param lock           rw_lock already held in shared mode to upgrade.
 *
 * @returns TRUE if the lock was upgraded, FALSE if it was not possible.
 *          If the function was not able to upgrade the lock, the lock will be dropped
 *          by the function.
 */
__mockable
__lck_rw_old_func
boolean_t
lck_rw_lock_shared_to_exclusive(
	lck_rw_t        *lock)
{
	thread_t thread = current_thread();
	uint32_t data, prev;

	assertf(lock->lck_rw_priv_excl != 0, "lock %p thread %p", lock, current_thread());

	lck_rw_dbg_assert_held(lock, LCK_RW_TYPE_SHARED);

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_WANT_UPGRADE) {
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0) {         /* we were the last reader */
				data &= ~(LCK_RW_W_WAITING);            /* so clear the wait indicator */
			}
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				return lck_rw_lock_shared_to_exclusive_failure(lock, prev);
			}
		} else {
			data |= LCK_RW_WANT_UPGRADE;            /* ask for WANT_UPGRADE */
			data -= LCK_RW_SHARED_READER;           /* and shed our read count */
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				break;
			}
		}
		cpu_pause();
	}
	/* we now own the WANT_UPGRADE */
	if (data & LCK_RW_SHARED_MASK) {        /* check to see if all of the readers are drained */
		lck_rw_lock_shared_to_exclusive_success(lock);  /* if not, we need to go wait */
	}

	assertf(lock->lck_rw_owner == 0, "state=0x%x, owner=%p",
	    ordered_load_rw(lock), ctid_get_thread_unsafe(lock->lck_rw_owner));

	ordered_store_rw_owner(lock, thread->ctid);
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 0);
#endif  /* CONFIG_DTRACE */

	lck_rw_dbg_modify(lock, LCK_RW_TYPE_SHARED, __lck_rw_caller);
	return TRUE;
}

/*
 *      Routine:        lck_rw_lock_exclusive_to_shared_gen
 *      Function:
 *		Fast path has already dropped
 *		our exclusive state and bumped lck_rw_shared_count
 *		all we need to do here is determine if anyone
 *		needs to be awakened.
 */
static void
lck_rw_lock_exclusive_to_shared_gen(
	lck_rw_t       *lck,
	uint32_t        prior_lock_state,
	uintptr_t       caller)
{
#pragma unused(caller)
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	lck_rw_word_t   fake_lck;

	/*
	 * prior_lock state is a snapshot of the 1st word of the
	 * lock in question... we'll fake up a pointer to it
	 * and carefully not access anything beyond whats defined
	 * in the first word of a lck_rw_t
	 */
	fake_lck.data = prior_lock_state;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_START,
	    trace_lck, fake_lck->want_excl, fake_lck->want_upgrade, 0, 0);

	/*
	 * don't wake up anyone waiting to take the lock exclusively
	 * since we hold a read count... when the read count drops to 0,
	 * the writers will be woken.
	 *
	 * wake up any waiting readers if we don't have any writers waiting,
	 * or the lock is NOT marked as rw_priv_excl (writers have privilege)
	 */
	if (!(fake_lck.priv_excl && fake_lck.w_waiting) && fake_lck.r_waiting) {
		thread_wakeup(LCK_RW_READER_EVENT(lck));
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_END,
	    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, lck->lck_rw_shared_count, 0);

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck, 0);
#endif

	lck_rw_dbg_modify(lck, LCK_RW_TYPE_EXCLUSIVE, __lck_rw_caller);
}

/*!
 * @function lck_rw_lock_exclusive_to_shared
 *
 * @abstract
 * Downgrades a rw_lock held in exclusive mode to shared.
 *
 * @discussion
 * The caller needs to hold the lock in exclusive mode to be able to downgrade it.
 *
 * @param lock           rw_lock already held in exclusive mode to downgrade.
 */
__mockable
__lck_rw_old_func
void
lck_rw_lock_exclusive_to_shared(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;

	assertf(lock->lck_rw_owner == current_thread()->ctid,
	    "state=0x%x, owner=%p", lock->lck_rw_data,
	    ctid_get_thread_unsafe(lock->lck_rw_owner));
	ordered_store_rw_owner(lock, 0);

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);    /* wait for interlock to clear */
			continue;
		}
		data += LCK_RW_SHARED_READER;
		if (data & LCK_RW_WANT_UPGRADE) {
			data &= ~(LCK_RW_WANT_UPGRADE);
		} else {
			data &= ~(LCK_RW_WANT_EXCL);
		}
		if (!((prev & LCK_RW_W_WAITING) && (prev & LCK_RW_PRIV_EXCL))) {
			data &= ~(LCK_RW_W_WAITING);
		}
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_release_smp)) {
			break;
		}
		cpu_pause();
	}
	lck_rw_lock_exclusive_to_shared_gen(lock, prev, __lck_rw_caller);
}

/*
 * Very sad hack, but the codegen for lck_rw_lock
 * is very unhappy with the combination of __builtin_return_address()
 * and a noreturn function. For some reason it adds more frames
 * than it should. rdar://76570684
 */
void
_lck_rw_lock_type_panic(lck_rw_t *lck, lck_rw_type_t lck_rw_type);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
__attribute__((noinline, weak))
void
_lck_rw_lock_type_panic(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	panic("lck_rw_lock(): Invalid RW lock type: %x for lock %p", lck_rw_type, lck);
}
#pragma clang diagnostic pop

/*!
 * @function lck_rw_lock
 *
 * @abstract
 * Locks a rw_lock with the specified type.
 *
 * @discussion
 * See lck_rw_lock_shared() or lck_rw_lock_exclusive() for more details.
 *
 * @param lck           rw_lock to lock.
 * @param lck_rw_type   LCK_RW_TYPE_SHARED or LCK_RW_TYPE_EXCLUSIVE
 */
__mockable
__lck_rw_old_func
void
lck_rw_lock(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		return lck_rw_lock_shared_internal(lck, __lck_rw_caller);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_lock_exclusive_internal(lck, __lck_rw_caller);
	}
	_lck_rw_lock_type_panic(lck, lck_rw_type);
}

__attribute__((always_inline))
static boolean_t
lck_rw_try_lock_shared_internal_inline(lck_rw_t *lock, uintptr_t caller)
{
#pragma unused(caller)

	uint32_t        data, prev;
	thread_t        thread = current_thread();
	boolean_t       check_canlock = TRUE;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;             /* lock is busy */
		}
		if ((data & LCK_RW_SHARED_MASK) == 0) {
			/*
			 * If the lock is uncontended,
			 * we do not need to check if we can lock it
			 */
			check_canlock = FALSE;
		}
		data += LCK_RW_SHARED_READER;     /* Increment reader refcount */
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
	if (check_canlock) {
		/*
		 * Best effort attempt to check that this thread
		 * is not already holding the lock (this checks read mode too).
		 */
		lck_rw_dbg_assert_canlock(lock, LCK_RW_TYPE_SHARED);
	}
	assertf(lock->lck_rw_owner == 0, "state=0x%x, owner=%p",
	    ordered_load_rw(lock), ctid_get_thread_unsafe(lock->lck_rw_owner));

	if (lock->lck_rw_can_sleep) {
		lck_rw_lock_count_inc(thread, lock);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif  /* CONFIG_DTRACE */

	lck_rw_dbg_add(lock, LCK_RW_TYPE_SHARED, caller);
	return TRUE;
}

__attribute__((noinline))
static boolean_t
lck_rw_try_lock_shared_internal(lck_rw_t *lock, uintptr_t caller)
{
	return lck_rw_try_lock_shared_internal_inline(lock, caller);
}

/*!
 * @function lck_rw_try_lock_shared
 *
 * @abstract
 * Tries to locks a rw_lock in read mode.
 *
 * @discussion
 * This function will return and not block in case the lock is already held.
 * See lck_rw_lock_shared for more details.
 *
 * @param lock           rw_lock to lock.
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
__mockable
__lck_rw_old_func
boolean_t
lck_rw_try_lock_shared(
	lck_rw_t        *lock)
{
	return lck_rw_try_lock_shared_internal_inline(lock, __lck_rw_caller);
}

__attribute__((always_inline))
static boolean_t
lck_rw_try_lock_exclusive_internal_inline(lck_rw_t *lock, uintptr_t caller)
{
#pragma unused(caller)
	uint32_t        data, prev;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;
		}
		data |= LCK_RW_WANT_EXCL;
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
	thread_t thread = current_thread();

	if (lock->lck_rw_can_sleep) {
		lck_rw_lock_count_inc(thread, lock);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	assertf(lock->lck_rw_owner == 0, "state=0x%x, owner=%p",
	    ordered_load_rw(lock), ctid_get_thread_unsafe(lock->lck_rw_owner));

	ordered_store_rw_owner(lock, thread->ctid);
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */

	lck_rw_dbg_add(lock, LCK_RW_TYPE_EXCLUSIVE, caller);
	return TRUE;
}

__attribute__((noinline))
static boolean_t
lck_rw_try_lock_exclusive_internal(lck_rw_t *lock, uintptr_t caller)
{
	return lck_rw_try_lock_exclusive_internal_inline(lock, caller);
}

/*!
 * @function lck_rw_try_lock_exclusive
 *
 * @abstract
 * Tries to locks a rw_lock in write mode.
 *
 * @discussion
 * This function will return and not block in case the lock is already held.
 * See lck_rw_lock_exclusive for more details.
 *
 * @param lock           rw_lock to lock.
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
__mockable
__lck_rw_old_func
boolean_t
lck_rw_try_lock_exclusive(lck_rw_t *lock)
{
	return lck_rw_try_lock_exclusive_internal_inline(lock, __lck_rw_caller);
}

/*
 * Very sad hack, but the codegen for lck_rw_try_lock
 * is very unhappy with the combination of __builtin_return_address()
 * and a noreturn function. For some reason it adds more frames
 * than it should. rdar://76570684
 */
boolean_t
_lck_rw_try_lock_type_panic(lck_rw_t *lck, lck_rw_type_t lck_rw_type);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
__attribute__((noinline, weak))
boolean_t
_lck_rw_try_lock_type_panic(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	panic("lck_rw_lock(): Invalid RW lock type: %x for lock %p", lck_rw_type, lck);
}
#pragma clang diagnostic pop

/*!
 * @function lck_rw_try_lock
 *
 * @abstract
 * Tries to locks a rw_lock with the specified type.
 *
 * @discussion
 * This function will return and not wait/block in case the lock is already held.
 * See lck_rw_try_lock_shared() or lck_rw_try_lock_exclusive() for more details.
 *
 * @param lck           rw_lock to lock.
 * @param lck_rw_type   LCK_RW_TYPE_SHARED or LCK_RW_TYPE_EXCLUSIVE
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
__mockable
__lck_rw_old_func
boolean_t
lck_rw_try_lock(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		return lck_rw_try_lock_shared_internal(lck, __lck_rw_caller);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_try_lock_exclusive_internal(lck, __lck_rw_caller);
	}
	return _lck_rw_try_lock_type_panic(lck, lck_rw_type);
}

/*
 *      Routine:        lck_rw_done_gen
 *
 *	prior_lock_state is the value in the 1st
 *      word of the lock at the time of a successful
 *	atomic compare and exchange with the new value...
 *      it represents the state of the lock before we
 *	decremented the rw_shared_count or cleared either
 *      rw_want_upgrade or rw_want_write and
 *	the lck_x_waiting bits...  since the wrapper
 *      routine has already changed the state atomically,
 *	we just need to decide if we should
 *	wake up anyone and what value to return... we do
 *	this by examining the state of the lock before
 *	we changed it
 */
static lck_rw_type_t
lck_rw_done_gen(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	lck_rw_word_t   fake_lck;
	lck_rw_type_t   lock_type;
	thread_t        thread;

	/*
	 * prior_lock state is a snapshot of the 1st word of the
	 * lock in question... we'll fake up a pointer to it
	 * and carefully not access anything beyond whats defined
	 * in the first word of a lck_rw_t
	 */
	fake_lck.data = prior_lock_state;

	if (fake_lck.shared_count <= 1) {
		if (fake_lck.w_waiting) {
			thread_wakeup(LCK_RW_WRITER_EVENT(lck));
		}

		if (!(fake_lck.priv_excl && fake_lck.w_waiting) && fake_lck.r_waiting) {
			thread_wakeup(LCK_RW_READER_EVENT(lck));
		}
	}
	if (fake_lck.shared_count) {
		lock_type = LCK_RW_TYPE_SHARED;
	} else {
		lock_type = LCK_RW_TYPE_EXCLUSIVE;
	}

	/* Check if dropping the lock means that we need to unpromote */
	thread = current_thread();
	if (fake_lck.can_sleep) {
		lck_rw_lock_count_dec(thread, lck);
	}

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, lock_type == LCK_RW_TYPE_SHARED ? 0 : 1);
#endif

	lck_rw_dbg_remove(lck, lock_type);
	return lock_type;
}

/*!
 * @function lck_rw_done
 *
 * @abstract
 * Force unlocks a rw_lock without consistency checks.
 *
 * @discussion
 * Do not use unless sure you can avoid consistency checks.
 *
 * @param lock           rw_lock to unlock.
 */
__mockable
__lck_rw_old_func
lck_rw_type_t
lck_rw_done(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;
	boolean_t       once = FALSE;

	/*
	 * Best effort attempt to check that this thread
	 * is holding the lock.
	 */
	lck_rw_dbg_assert_held(lock, LCK_RW_TYPE_ANY);

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {          /* wait for interlock to clear */
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_SHARED_MASK) {        /* lock is held shared */
			assertf(lock->lck_rw_owner == 0,
			    "state=0x%x, owner=%p", lock->lck_rw_data,
			    ctid_get_thread_unsafe(lock->lck_rw_owner));
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0) { /* if reader count has now gone to 0, check for waiters */
				goto check_waiters;
			}
		} else {                                        /* if reader count == 0, must be exclusive lock */
			if (data & LCK_RW_WANT_UPGRADE) {
				data &= ~(LCK_RW_WANT_UPGRADE);
			} else {
				if (data & LCK_RW_WANT_EXCL) {
					data &= ~(LCK_RW_WANT_EXCL);
				} else {                                /* lock is not 'owned', panic */
					panic("Releasing non-exclusive RW lock without a reader refcount!");
				}
			}
			if (!once) {
				// Only check for holder and clear it once
				assertf(lock->lck_rw_owner == current_thread()->ctid,
				    "state=0x%x, owner=%p", lock->lck_rw_data,
				    ctid_get_thread_unsafe(lock->lck_rw_owner));
				ordered_store_rw_owner(lock, 0);
				once = TRUE;
			}
check_waiters:
			/*
			 * test the original values to match what
			 * lck_rw_done_gen is going to do to determine
			 * which wakeups need to happen...
			 *
			 * if !(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting)
			 */
			if (prev & LCK_RW_W_WAITING) {
				data &= ~(LCK_RW_W_WAITING);
				if ((prev & LCK_RW_PRIV_EXCL) == 0) {
					data &= ~(LCK_RW_R_WAITING);
				}
			} else {
				data &= ~(LCK_RW_R_WAITING);
			}
		}
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_release_smp)) {
			break;
		}
		cpu_pause();
	}
	return lck_rw_done_gen(lock, prev);
}

/*!
 * @function lck_rw_unlock_shared
 *
 * @abstract
 * Unlocks a rw_lock previously locked in shared mode.
 *
 * @discussion
 * The same thread that locked the lock needs to unlock it.
 *
 * @param lck           rw_lock held in shared mode to unlock.
 */
__mockable
__lck_rw_old_func
void
lck_rw_unlock_shared(
	lck_rw_t        *lck)
{
	lck_rw_type_t   ret;

	assertf(lck->lck_rw_owner == 0,
	    "state=0x%x, owner=%p", lck->lck_rw_data,
	    ctid_get_thread_unsafe(lck->lck_rw_owner));
	assertf(lck->lck_rw_shared_count > 0, "shared_count=0x%x", lck->lck_rw_shared_count);
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_SHARED) {
		panic("lck_rw_unlock_shared(): lock %p held in mode: %d", lck, ret);
	}
}

/*!
 * @function lck_rw_unlock_exclusive
 *
 * @abstract
 * Unlocks a rw_lock previously locked in exclusive mode.
 *
 * @discussion
 * The same thread that locked the lock needs to unlock it.
 *
 * @param lck           rw_lock held in exclusive mode to unlock.
 */
__mockable
__lck_rw_old_func
void
lck_rw_unlock_exclusive(
	lck_rw_t        *lck)
{
	lck_rw_type_t   ret;

	assertf(lck->lck_rw_owner == current_thread()->ctid,
	    "state=0x%x, owner=%p", lck->lck_rw_data,
	    ctid_get_thread_unsafe(lck->lck_rw_owner));
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_EXCLUSIVE) {
		panic("lck_rw_unlock_exclusive(): lock %p held in mode: %d", lck, ret);
	}
}

/*!
 * @function lck_rw_unlock
 *
 * @abstract
 * Unlocks a rw_lock previously locked with lck_rw_type.
 *
 * @discussion
 * The lock must be unlocked by the same thread it was locked from.
 * The type of the lock/unlock have to match, unless an upgrade/downgrade was performed while
 * holding the lock.
 *
 * @param lck           rw_lock to unlock.
 * @param lck_rw_type   LCK_RW_TYPE_SHARED or LCK_RW_TYPE_EXCLUSIVE
 */
__mockable
__lck_rw_old_func
void
lck_rw_unlock(
	lck_rw_t         *lck,
	lck_rw_type_t    lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		lck_rw_unlock_shared(lck);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		lck_rw_unlock_exclusive(lck);
	} else {
		panic("lck_rw_unlock(): Invalid RW lock type: %d", lck_rw_type);
	}
}

/*!
 * @function lck_rw_assert
 *
 * @abstract
 * Asserts the rw_lock is held.
 *
 * @discussion
 * read-write locks do not have a concept of ownership when held in shared mode,
 * so this function merely asserts that someone is holding the lock, not necessarily the caller.
 * However if rw_lock_debug is on, a best effort mechanism to track the owners is in place, and
 * this function can be more accurate.
 * Type can be LCK_RW_ASSERT_SHARED, LCK_RW_ASSERT_EXCLUSIVE, LCK_RW_ASSERT_HELD
 * LCK_RW_ASSERT_NOTHELD.
 *
 * @param lck   rw_lock to check.
 * @param type  assert type
 */
__mockable
__lck_rw_old_func
void
lck_rw_assert(
	lck_rw_t        *lck,
	unsigned int    type)
{
	thread_t thread = current_thread();

	switch (type) {
	case LCK_RW_ASSERT_SHARED:
		if ((lck->lck_rw_shared_count != 0) &&
		    (lck->lck_rw_owner == 0)) {
			lck_rw_dbg_assert_held(lck, LCK_RW_TYPE_SHARED);
			return;
		}
		break;
	case LCK_RW_ASSERT_EXCLUSIVE:
		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_shared_count == 0) &&
		    (lck->lck_rw_owner == thread->ctid)) {
			lck_rw_dbg_assert_held(lck, LCK_RW_TYPE_EXCLUSIVE);
			return;
		}
		break;
	case LCK_RW_ASSERT_HELD:
		if (lck->lck_rw_shared_count != 0) {
			lck_rw_dbg_assert_held(lck, LCK_RW_TYPE_SHARED);
			return;         // Held shared
		}
		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_owner == thread->ctid)) {
			lck_rw_dbg_assert_held(lck, LCK_RW_TYPE_EXCLUSIVE);
			return;         // Held exclusive
		}
		break;
	case LCK_RW_ASSERT_NOTHELD:
		if ((lck->lck_rw_shared_count == 0) &&
		    !(lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_owner == 0)) {
			lck_rw_dbg_assert_canlock(lck, LCK_RW_TYPE_EXCLUSIVE);
			return;
		}
		break;
	case LCK_RW_ASSERT_NOT_OWNED:
		if (lck->lck_rw_owner != thread->ctid) {
			return;
		}
		break;
	default:
		break;
	}
	panic("rw lock (%p)%s held (mode=%u)", lck,
	    (type == LCK_RW_ASSERT_NOTHELD || type == LCK_RW_ASSERT_NOT_OWNED ? "" : " not"), type);
}

/*!
 * @function kdp_lck_rw_lock_is_acquired_exclusive
 *
 * @abstract
 * Checks if a rw_lock is held exclusevely.
 *
 * @discussion
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *
 * @param lck   lock to check
 *
 * @returns TRUE if the lock is held exclusevely
 */
__lck_rw_old_func
boolean_t
kdp_lck_rw_lock_is_acquired_exclusive(
	lck_rw_t        *lck)
{
	if (not_in_kdp) {
		panic("panic: rw lock exclusive check done outside of kernel debugger");
	}
	return ((lck->lck_rw_want_upgrade || lck->lck_rw_want_excl) && (lck->lck_rw_shared_count == 0)) ? TRUE : FALSE;
}

/*!
 * @function lck_rw_lock_would_yield_shared
 *
 * @abstract
 * Check whether a rw_lock currently held in shared mode would be yielded
 *
 * @discussion
 * This function can be used when lck_rw_lock_yield_shared() would be
 * inappropriate due to the need to perform additional housekeeping
 * prior to any yield or when the caller may wish to prematurely terminate
 * an operation rather than resume it after regaining the lock.
 *
 * @param lck           rw_lock already held in shared mode to yield.
 *
 * @returns TRUE if the lock would yield, FALSE otherwise
 */
__mockable
__lck_rw_old_func
bool
lck_rw_lock_would_yield_shared(
	lck_rw_t        *lck)
{
	lck_rw_word_t   word;

	lck_rw_assert(lck, LCK_RW_ASSERT_SHARED);

	word.data = ordered_load_rw(lck);
	if (word.want_excl || word.want_upgrade) {
		return true;
	}

	return false;
}

/*!
 * @function lck_rw_lock_yield_shared
 *
 * @abstract
 * Yields a rw_lock held in shared mode.
 *
 * @discussion
 * This function can block.
 * Yields the lock in case there are writers waiting.
 * The yield will unlock, block, and re-lock the lock in shared mode.
 *
 * @param lck           rw_lock already held in shared mode to yield.
 * @param force_yield   if set to true it will always yield irrespective of the lock status
 *
 * @returns TRUE if the lock was yield, FALSE otherwise
 */
__lck_rw_old_func
bool
lck_rw_lock_yield_shared(
	lck_rw_t        *lck,
	boolean_t       force_yield)
{
	if (lck_rw_lock_would_yield_shared(lck) || force_yield) {
		lck_rw_unlock_shared(lck);
		mutex_pause(2);
		lck_rw_lock_shared(lck);
		return true;
	}

	return false;
}

/*!
 * @function lck_rw_lock_would_yield_exclusive
 *
 * @abstract
 * Check whether a rw_lock currently held in exclusive mode would be yielded
 *
 * @discussion
 * This function can be used when lck_rw_lock_yield_exclusive would be
 * inappropriate due to the need to perform additional housekeeping
 * prior to any yield or when the caller may wish to prematurely terminate
 * an operation rather than resume it after regaining the lock.
 *
 * @param lck           rw_lock already held in exclusive mode to yield.
 * @param mode          when to yield.
 *
 * @returns TRUE if the lock would yield, FALSE otherwise
 */
__mockable
__lck_rw_old_func
bool
lck_rw_lock_would_yield_exclusive(
	lck_rw_t        *lck,
	lck_rw_yield_t  mode)
{
	lck_rw_word_t word;
	bool yield = false;

	lck_rw_assert(lck, LCK_RW_ASSERT_EXCLUSIVE);

	if (mode == LCK_RW_YIELD_ALWAYS) {
		yield = true;
	} else {
		word.data = ordered_load_rw(lck);
		if (word.w_waiting) {
			yield = true;
		} else if (mode == LCK_RW_YIELD_ANY_WAITER) {
			yield = (word.r_waiting != 0);
		}
	}

	return yield;
}

/*!
 * @function lck_rw_lock_yield_exclusive
 *
 * @abstract
 * Yields a rw_lock held in exclusive mode.
 *
 * @discussion
 * This function can block.
 * Yields the lock in case there are writers waiting.
 * The yield will unlock, block, and re-lock the lock in exclusive mode.
 *
 * @param lck           rw_lock already held in exclusive mode to yield.
 * @param mode          when to yield.
 *
 * @returns TRUE if the lock was yield, FALSE otherwise
 */
__lck_rw_old_func
bool
lck_rw_lock_yield_exclusive(
	lck_rw_t        *lck,
	lck_rw_yield_t  mode)
{
	bool yield = lck_rw_lock_would_yield_exclusive(lck, mode);

	if (yield) {
		lck_rw_unlock_exclusive(lck);
		mutex_pause(2);
		lck_rw_lock_exclusive(lck);
	}

	return yield;
}

/*!
 * @function lck_rw_sleep
 *
 * @abstract
 * Assert_wait on an event while holding the rw_lock.
 *
 * @discussion
 * the flags can decide how to re-acquire the lock upon wake up
 * (LCK_SLEEP_SHARED, or LCK_SLEEP_EXCLUSIVE, or LCK_SLEEP_UNLOCK)
 * and if the priority needs to be kept boosted until the lock is
 * re-acquired (LCK_SLEEP_PROMOTED_PRI).
 *
 * @param lck                   rw_lock to use to synch the assert_wait.
 * @param lck_sleep_action      flags.
 * @param event                 event to assert_wait on.
 * @param interruptible         wait type.
 */
__lck_rw_old_func
wait_result_t
lck_rw_sleep(
	lck_rw_t                *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	wait_result_t           res;
	lck_rw_type_t           lck_rw_type;
	thread_pri_floor_t      token;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * Although we are dropping the RW lock, the intent in most cases
		 * is that this thread remains as an observer, since it may hold
		 * some secondary resource, but must yield to avoid deadlock. In
		 * this situation, make sure that the thread is boosted to the
		 * ceiling while blocked, so that it can re-acquire the
		 * RW lock at that priority.
		 */
		token = thread_priority_floor_start();
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
				lck_rw_lock(lck, lck_rw_type);
			} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
				lck_rw_lock_exclusive(lck);
			} else {
				lck_rw_lock_shared(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		(void)lck_rw_done(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	return res;
}

/*!
 * @function lck_rw_sleep_deadline
 *
 * @abstract
 * Assert_wait_deadline on an event while holding the rw_lock.
 *
 * @discussion
 * the flags can decide how to re-acquire the lock upon wake up
 * (LCK_SLEEP_SHARED, or LCK_SLEEP_EXCLUSIVE, or LCK_SLEEP_UNLOCK)
 * and if the priority needs to be kept boosted until the lock is
 * re-acquired (LCK_SLEEP_PROMOTED_PRI).
 *
 * @param lck                   rw_lock to use to synch the assert_wait.
 * @param lck_sleep_action      flags.
 * @param event                 event to assert_wait on.
 * @param interruptible         wait type.
 * @param deadline              maximum time after which being woken up
 */
__lck_rw_old_func
wait_result_t
lck_rw_sleep_deadline(
	lck_rw_t                *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t           res;
	lck_rw_type_t           lck_rw_type;
	thread_pri_floor_t      token;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		token = thread_priority_floor_start();
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
				lck_rw_lock(lck, lck_rw_type);
			} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
				lck_rw_lock_exclusive(lck);
			} else {
				lck_rw_lock_shared(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		(void)lck_rw_done(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	return res;
}
