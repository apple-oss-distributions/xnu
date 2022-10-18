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

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>
#include <kern/locks_internal.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/thread.h>

#include <mach/machine/sdt.h>

#include <machine/cpu_data.h>
#include <machine/machine_cpu.h>

#if !LCK_MTX_USE_ARCH

/*
 * lck_mtx_t
 * ~~~~~~~~~
 *
 * Kernel mutexes in this implementation are made of four 32 bits words:
 *
 *   - word 0: turnstile compact ID (24 bits) and the 0x22 lock tag
 *   - word 1: padding (to be used for group compact IDs)
 *   - word 2: mutex state (lock owner + interlock, spin and waiters bits),
 *             refered to as "data" in the code.
 *   - word 3: adaptive spin and interlock MCS queue tails.
 *
 * The 64 bits word made of the last two words is refered to
 * as the "mutex state" in code.
 *
 *
 * Core serialization rules
 * ~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The mutex has a bit (lck_mtx_t::lck_mtx.ilocked or bit LCK_MTX_ILOCK
 * of the data word) that serves as a spinlock for the mutex state.
 *
 *
 * Updating the lock fields must follow the following rules:
 *
 *   - It is ok to "steal" the mutex (updating its data field) if no one
 *     holds the interlock.
 *
 *   - Holding the interlock allows its holder to update the first 3 words
 *     of the kernel mutex without using RMW atomics (plain stores are OK).
 *
 *   - Holding the interlock is required for a thread to remove itself
 *     from the adaptive spin queue.
 *
 *   - Threads can enqueue themselves onto the adaptive spin wait queue
 *     or the interlock wait queue at any time.
 *
 *
 * Waiters bit and turnstiles
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The turnstile on a kernel mutex is set by waiters, and cleared
 * once they have all been resumed and successfully acquired the lock.
 *
 * LCK_MTX_NEEDS_WAKEUP being set (always with an owner set too)
 * forces threads to the lck_mtx_unlock slowpath,
 * in order to evaluate whether lck_mtx_unlock_wakeup() must be called.
 *
 * As a result it means it really only needs to be set at select times:
 *
 *   - when a thread blocks and "snitches" on the current thread owner,
 *     so that when that thread unlocks it calls wake up,
 *
 *   - when a thread that was woken up resumes its work and became
 *     the inheritor.
 */

/*!
 * @typedef lck_mtx_mcs_t
 *
 * @brief
 * The type of per-cpu MCS-like nodes used for the mutex acquisition slowpath.
 *
 * @discussion
 * There is one such structure per CPU: such nodes are used with preemption
 * disabled, and using kernel mutexes in interrupt context isn't allowed.
 *
 * The nodes are used not as a lock as in traditional MCS, but to order
 * waiters. The head of the queue spins against the lock itself, which allows
 * to release the MCS node once the kernel mutex is acquired.
 *
 * Those nodes provide 2 queues:
 *
 * 1. an adaptive spin queue that is used to order threads who chose to
 *    adaptively spin to wait for the lock to become available,
 *
 *    This queue is doubly linked, threads can add themselves concurrently,
 *    the interlock of the mutex is required to dequeue.
 *
 * 2. an interlock queue which is more typical MCS.
 */
typedef struct lck_mtx_mcs {
	struct _lck_mtx_       *lmm_ilk_current;

	struct lck_mtx_mcs     *lmm_ilk_next;
	unsigned long           lmm_ilk_ready;

	struct lck_mtx_mcs     *lmm_as_next;
	unsigned long long      lmm_as_prev;

	unsigned long long      lmm_bzero_limit[] __attribute__((aligned(16)));
} __attribute__((aligned(128))) * lck_mtx_mcs_t;

static struct lck_mtx_mcs       PERCPU_DATA(lck_mtx_mcs);

#define ADAPTIVE_SPIN_ENABLE 0x1

#define NOINLINE                __attribute__((noinline))
#define LCK_MTX_EVENT(lck)      CAST_EVENT64_T(&(lck)->lck_mtx.data)
#define LCK_EVENT_TO_MUTEX(e)   __container_of((uint32_t *)(e), lck_mtx_t, lck_mtx.data)
#define LCK_MTX_HAS_WAITERS(l)  ((l)->lck_mtx.data & LCK_MTX_NEEDS_WAKEUP)

#if DEVELOPMENT || DEBUG
TUNABLE(bool, LckDisablePreemptCheck, "-disable_mtx_chk", false);
#endif /* DEVELOPMENT || DEBUG */

extern unsigned int not_in_kdp;

KALLOC_TYPE_DEFINE(KT_LCK_MTX, lck_mtx_t, KT_PRIV_ACCT);

#define LCK_MTX_NULL_CTID       0x00000000u

__enum_decl(lck_mtx_mode_t, uint32_t, {
	LCK_MTX_MODE_SLEEPABLE,
	LCK_MTX_MODE_SPIN,
	LCK_MTX_MODE_SPIN_ALWAYS,
});

__enum_decl(lck_ilk_mode_t, uint32_t, {
	LCK_ILK_MODE_UNLOCK,
	LCK_ILK_MODE_DIRECT,
	LCK_ILK_MODE_FROM_AS,
});

static inline void
lck_mtx_mcs_clear(lck_mtx_mcs_t mcs)
{
	/*
	 * Avoid clearing 128 bytes when only 40 are sufficient,
	 * make that 48 for better CG.
	 */
	bzero(mcs, offsetof(struct lck_mtx_mcs, lmm_bzero_limit));
}

static inline uint16_t
lck_mtx_get_mcs_id(void)
{
	return (uint16_t)cpu_number() + 1;
}

__pure2
static inline lck_mtx_mcs_t
lck_mtx_get_mcs(int idx)
{
	return PERCPU_GET_WITH_BASE(other_percpu_base(idx - 1), lck_mtx_mcs);
}


#pragma mark lck_mtx_t: validation

__abortlike
static void
__lck_mtx_invalid_panic(lck_mtx_t *lck)
{
	panic("Invalid/destroyed mutex %p: "
	    "<0x%06x 0x%02x 0x%08x 0x%08x/%p 0x%04x 0x%04x>",
	    lck, lck->lck_mtx_tsid, lck->lck_mtx_type, lck->lck_mtx_grp,
	    lck->lck_mtx.data, ctid_get_thread_unsafe(lck->lck_mtx.owner),
	    lck->lck_mtx.as_tail, lck->lck_mtx.ilk_tail);
}

__abortlike
static void
__lck_mtx_not_owned_panic(lck_mtx_t *lock, thread_t thread)
{
	panic("Mutex %p is unexpectedly not owned by thread %p", lock, thread);
}

__abortlike
static void
__lck_mtx_owned_panic(lck_mtx_t *lock, thread_t thread)
{
	panic("Mutex %p is unexpectedly owned by thread %p", lock, thread);
}

__abortlike
static void
__lck_mtx_lock_is_sleepable_panic(lck_mtx_t *lck)
{
	// "Always" variants can never block. If the lock is held as a normal mutex
	// then someone is mixing always and non-always calls on the same lock, which is
	// forbidden.
	panic("Mutex %p is held as a full-mutex (spin-always lock attempted)", lck);
}

#if DEVELOPMENT || DEBUG
__abortlike
static void
__lck_mtx_preemption_disabled_panic(lck_mtx_t *lck, int expected)
{
	panic("Attempt to take mutex %p with preemption disabled (%d)",
	    lck, get_preemption_level() - expected);
}

__abortlike
static void
__lck_mtx_at_irq_panic(lck_mtx_t *lck)
{
	panic("Attempt to take mutex %p in IRQ context", lck);
}

/*
 *	Routine:	lck_mtx_check_preemption
 *
 *	Verify preemption is enabled when attempting to acquire a mutex.
 */
static inline void
lck_mtx_check_preemption(lck_mtx_t *lock, thread_t thread, int expected)
{
#pragma unused(thread)
	if (lock_preemption_level_for_thread(thread) == expected) {
		return;
	}
	if (LckDisablePreemptCheck) {
		return;
	}
	if (current_cpu_datap()->cpu_hibernate) {
		return;
	}
	if (startup_phase < STARTUP_SUB_EARLY_BOOT) {
		return;
	}
	__lck_mtx_preemption_disabled_panic(lock, expected);
}

static inline void
lck_mtx_check_irq(lck_mtx_t *lock)
{
	if (ml_at_interrupt_context()) {
		__lck_mtx_at_irq_panic(lock);
	}
}

#define LCK_MTX_SNIFF_PREEMPTION(thread)   lock_preemption_level_for_thread(thread)
#define LCK_MTX_CHECK_INVARIANTS           1
#else
#define lck_mtx_check_irq(lck)             ((void)0)
#define LCK_MTX_SNIFF_PREEMPTION(thread)   0
#define LCK_MTX_CHECK_INVARIANTS           0
#endif /* !DEVELOPMENT && !DEBUG */

#if CONFIG_DTRACE
#define LCK_MTX_SNIFF_DTRACE()             lck_debug_state.lds_value
#else
#define LCK_MTX_SNIFF_DTRACE()             0
#endif


#pragma mark lck_mtx_t: alloc/init/destroy/free

lck_mtx_t *
lck_mtx_alloc_init(lck_grp_t *grp, lck_attr_t *attr)
{
	lck_mtx_t      *lck;

	lck = zalloc(KT_LCK_MTX);
	lck_mtx_init(lck, grp, attr);
	return lck;
}

void
lck_mtx_free(lck_mtx_t *lck, lck_grp_t *grp)
{
	lck_mtx_destroy(lck, grp);
	zfree(KT_LCK_MTX, lck);
}

void
lck_mtx_init(lck_mtx_t *lck, lck_grp_t *grp, lck_attr_t *attr)
{
	if (attr == LCK_ATTR_NULL) {
		attr = &lck_attr_default;
	}

	*lck = (lck_mtx_t){
		.lck_mtx_type = LCK_TYPE_MUTEX,
		.lck_mtx_grp  = grp->lck_grp_attr_id,
	};
	if (attr->lck_attr_val & LCK_ATTR_DEBUG) {
		lck->lck_mtx.data |= LCK_MTX_PROFILE;
	}

	lck_grp_reference(grp, &grp->lck_grp_mtxcnt);
}

void
lck_mtx_destroy(lck_mtx_t *lck, lck_grp_t *grp)
{
	if (lck->lck_mtx_tsid || lck->lck_mtx_type != LCK_TYPE_MUTEX ||
	    (lck->lck_mtx.data & ~LCK_MTX_PROFILE) ||
	    lck->lck_mtx.as_tail || lck->lck_mtx.ilk_tail) {
		__lck_mtx_invalid_panic(lck);
	}
	LCK_GRP_ASSERT_ID(grp, lck->lck_mtx_grp);
	lck->lck_mtx_type = LCK_TYPE_NONE;
	lck->lck_mtx.data = LCK_MTX_TAG_DESTROYED;
	lck->lck_mtx_grp      = 0;
	lck_grp_deallocate(grp, &grp->lck_grp_mtxcnt);
}


#pragma mark lck_mtx_t: lck_mtx_ilk*

static hw_spin_timeout_status_t
lck_mtx_ilk_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	lck_mtx_t *lck = _lock;

	panic("Mutex interlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "current owner: %p, "
	    "<0x%06x 0x%02x 0x%08x 0x%08x 0x%04x 0x%04x>, "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lck, HW_SPIN_TIMEOUT_ARG(to, st),
	    ctid_get_thread_unsafe(lck->lck_mtx.owner),
	    lck->lck_mtx_tsid, lck->lck_mtx_type,
	    lck->lck_mtx_grp, lck->lck_mtx.data,
	    lck->lck_mtx.as_tail, lck->lck_mtx.ilk_tail,
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy lck_mtx_ilk_timeout_policy = {
	.hwsp_name              = "lck_mtx_t (ilk)",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = lck_mtx_ilk_timeout_panic,
};

static void
lck_mtx_ilk_lock_cleanup_as_mcs(
	lck_mtx_t               *lock,
	uint16_t                 idx,
	lck_mtx_mcs_t            mcs,
	hw_spin_timeout_t        to,
	hw_spin_state_t         *ss)
{
	lck_mtx_mcs_t nnode = NULL;
	uint16_t      pidx  = (uint16_t)mcs->lmm_as_prev;
	bool          was_last;

	/*
	 *	This is called when the thread made use
	 *	of the adaptive spin queue and needs
	 *	to remove itself from it.
	 */

	/*
	 *	If the thread is last, set the tail to the node before us.
	 */
	was_last = lock_cmpxchg(&lock->lck_mtx.as_tail, idx, pidx, release);

	if (was_last) {
		/*
		 *	If @c mcs was last, we need to erase the previous
		 *	node link to it.
		 *
		 *	However, new nodes could have now taken our place
		 *	and set the previous node's @c lmm_as_next field
		 *	already, so we must CAS rather than blindly set.
		 *
		 *	We know the previous node is stable because
		 *	we hold the interlock (preventing concurrent
		 *	removals).
		 */
		if (pidx) {
			os_atomic_cmpxchg(&lck_mtx_get_mcs(pidx)->lmm_as_next,
			    mcs, nnode, relaxed);
		}
	} else {
		/*
		 *	If @c mcs wasn't last, then wait to make sure
		 *	we observe @c lmm_as_next. Once we do, we know
		 *	the field is stable since we hold the interlock
		 *	(preventing concurrent dequeues).
		 *
		 *	We can then update it to @c mcs next node index
		 *	(which is also stable for similar reasons).
		 *
		 *	Lastly update the previous node @c lmm_as_next
		 *	field as well to terminate the dequeue.
		 */
		while (!hw_spin_wait_until(&mcs->lmm_as_next, nnode, nnode)) {
			hw_spin_policy_t pol = &lck_mtx_ilk_timeout_policy;
			hw_spin_should_keep_spinning(lock, pol, to, ss);
		}

		os_atomic_store(&nnode->lmm_as_prev, pidx, relaxed);
		if (pidx) {
			os_atomic_store(&lck_mtx_get_mcs(pidx)->lmm_as_next,
			    nnode, relaxed);
		}
	}

	/*
	 *	@c mcs's fields are left dangling,
	 *	it is the responsibilty of the caller
	 *	to terminate the cleanup.
	 */
}

static NOINLINE void
lck_mtx_ilk_lock_contended(
	lck_mtx_t              *lock,
	lck_mtx_state_t         state,
	lck_ilk_mode_t          mode)
{
	hw_spin_policy_t  pol = &lck_mtx_ilk_timeout_policy;
	hw_spin_timeout_t to  = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss  = { };

	lck_mtx_mcs_t     mcs, nnode, pnode;
	uint16_t          idx, pidx;
	lck_mtx_state_t   nstate;
	unsigned long     ready;
	uint64_t          spin_start;

	/*
	 *	Take a spot in the interlock MCS queue,
	 *	and then spin until we're at the head of it.
	 */

	idx  = lck_mtx_get_mcs_id();
	mcs  = PERCPU_GET(lck_mtx_mcs);
	if (mode != LCK_MTX_MODE_SPIN) {
		spin_start = LCK_MTX_ADAPTIVE_SPIN_BEGIN();
	}

	mcs->lmm_ilk_current = lock;
	pidx = os_atomic_xchg(&lock->lck_mtx.ilk_tail, idx, release);
	if (pidx) {
		pnode = lck_mtx_get_mcs(pidx);
		os_atomic_store(&pnode->lmm_ilk_next, mcs, relaxed);

		while (!hw_spin_wait_until(&mcs->lmm_ilk_ready, ready, ready)) {
			hw_spin_should_keep_spinning(lock, pol, to, &ss);
		}
	}


	/*
	 *	We're now the first in line, wait for the interlock
	 *	to look ready and take it.
	 *
	 *	We can't just assume the lock is ours for the taking,
	 *	because the fastpath of lck_mtx_lock_spin{,_always}
	 *	only look at the mutex "data" and might steal it.
	 *
	 *	Also clear the interlock MCS tail if @c mcs is last.
	 */
	do {
		while (!hw_spin_wait_until(&lock->lck_mtx.val,
		    state.val, state.ilocked == 0)) {
			hw_spin_should_keep_spinning(lock, pol, to, &ss);
		}

		nstate = state;
		nstate.ilocked = 1;
		if (nstate.ilk_tail == idx) {
			nstate.ilk_tail = 0;
		}
	} while (!os_atomic_cmpxchg(&lock->lck_mtx, state, nstate, acquire));


	/*
	 *	We now have the interlock, let's cleanup the MCS state.
	 *
	 *	First, if there is a node after us, notify that it
	 *	is at the head of the interlock queue.
	 *
	 *	Second, perform the adaptive spin MCS cleanup if needed.
	 *
	 *	Lastly, clear the MCS node.
	 */
	if (state.ilk_tail != idx) {
		while (!hw_spin_wait_until(&mcs->lmm_ilk_next, nnode, nnode)) {
			hw_spin_should_keep_spinning(lock, pol, to, &ss);
		}

		os_atomic_store(&nnode->lmm_ilk_ready, 1, relaxed);
	}

	if (mode == LCK_ILK_MODE_FROM_AS) {
		lck_mtx_ilk_lock_cleanup_as_mcs(lock, idx, mcs, to, &ss);
	}
	lck_mtx_mcs_clear(mcs);

	if (mode != LCK_MTX_MODE_SPIN) {
		LCK_MTX_ADAPTIVE_SPIN_END(lock, lock->lck_mtx_grp, spin_start);
	}
}

static void
lck_mtx_ilk_lock_nopreempt(lck_mtx_t *lock, lck_ilk_mode_t mode)
{
	lck_mtx_state_t state, nstate;

	os_atomic_rmw_loop(&lock->lck_mtx.val, state.val, nstate.val, acquire, {
		if (__improbable(state.ilocked || state.ilk_tail)) {
		        os_atomic_rmw_loop_give_up({
				return lck_mtx_ilk_lock_contended(lock, state, mode);
			});
		}

		nstate = state;
		nstate.ilocked = true;
	});
}

static void
lck_mtx_ilk_unlock_v(lck_mtx_t *lock, uint32_t data)
{
	os_atomic_store(&lock->lck_mtx.data, data, release);
	lock_enable_preemption();
}

static void
lck_mtx_ilk_unlock(lck_mtx_t *lock)
{
	lck_mtx_ilk_unlock_v(lock, lock->lck_mtx.data & ~LCK_MTX_ILOCK);
}


#pragma mark lck_mtx_t: turnstile integration

/*
 * Routine: lck_mtx_lock_wait
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * returns it unlocked.
 *
 * Always aggressively sets the owning thread to promoted,
 * even if it's the same or higher priority
 * This prevents it from lowering its own priority while holding a lock
 *
 * TODO: Come up with a more efficient way to handle same-priority promotions
 *      <rdar://problem/30737670> ARM mutex contention logic could avoid taking the thread lock
 */
static struct turnstile *
lck_mtx_lock_wait(
	lck_mtx_t              *lck,
	thread_t                self,
	thread_t                holder,
	struct turnstile       *ts)
{
	uint64_t sleep_start = LCK_MTX_BLOCK_BEGIN();

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START,
	    unslide_for_kdebug(lck), (uintptr_t)thread_tid(self), 0, 0, 0);

	if (ts == TURNSTILE_NULL) {
		ts = turnstile_prepare_compact_id((uintptr_t)lck,
		    lck->lck_mtx_tsid, TURNSTILE_KERNEL_MUTEX);
		if (lck->lck_mtx_tsid == 0) {
			lck->lck_mtx_tsid = ts->ts_compact_id;
		}
	}
	assert3u(ts->ts_compact_id, ==, lck->lck_mtx_tsid);

	thread_set_pending_block_hint(self, kThreadWaitKernelMutex);
	turnstile_update_inheritor(ts, holder, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	waitq_assert_wait64(&ts->ts_waitq, LCK_MTX_EVENT(lck),
	    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);

	lck_mtx_ilk_unlock(lck);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	thread_block(THREAD_CONTINUE_NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);

	LCK_MTX_BLOCK_END(lck, lck->lck_mtx_grp, sleep_start);

	return ts;
}

static void
lck_mtx_lock_wait_done(lck_mtx_t *lck, struct turnstile  *ts)
{
	if (turnstile_complete_compact_id((uintptr_t)lck, ts,
	    TURNSTILE_KERNEL_MUTEX)) {
		lck->lck_mtx_tsid = 0;
	}
}

/*
 * Routine:     lck_mtx_lock_will_need_wakeup
 *
 * Returns whether the thread is the current turnstile inheritor,
 * which means it will have to call lck_mtx_unlock_wakeup()
 * on unlock.
 */
__attribute__((always_inline))
static bool
lck_mtx_lock_will_need_wakeup(lck_mtx_t *lck, thread_t  self)
{
	uint32_t tsid = lck->lck_mtx_tsid;

	return tsid && turnstile_get_by_id(tsid)->ts_inheritor == self;
}

/*
 * Routine:     lck_mtx_unlock_wakeup
 *
 * Invoked on unlock when there is contention.
 *
 * Called with the interlock locked.
 *
 * NOTE: callers should call turnstile_clenup after
 * dropping the interlock.
 */
static void
lck_mtx_unlock_wakeup(
	lck_mtx_t                       *lck,
	__kdebug_only thread_t          thread)
{
	struct turnstile *ts;
	kern_return_t did_wake;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_START,
	    unslide_for_kdebug(lck), (uintptr_t)thread_tid(thread), 0, 0, 0);

	ts = turnstile_get_by_id(lck->lck_mtx_tsid);

	/*
	 * We can skip turnstile_{prepare,cleanup} because
	 * we hold the interlock of the primitive,
	 * and enqueues/wakeups all happen under the interlock,
	 * which means the turnstile is stable.
	 */
	did_wake = waitq_wakeup64_one(&ts->ts_waitq, LCK_MTX_EVENT(lck),
	    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);
	assert(did_wake == KERN_SUCCESS);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}


#pragma mark lck_mtx_t: lck_mtx_lock

static inline bool
lck_mtx_ctid_on_core(uint32_t ctid)
{
	thread_t th = ctid_get_thread_unsafe(ctid);

	return th && machine_thread_on_core_allow_invalid(th);
}

#define LCK_MTX_OWNER_FOR_TRACE(lock) \
	VM_KERNEL_UNSLIDE_OR_PERM(ctid_get_thread_unsafe((lock)->lck_mtx.data))

static void
lck_mtx_lock_adaptive_spin(lck_mtx_t *lock, lck_mtx_state_t state)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	hw_spin_policy_t  pol = &lck_mtx_ilk_timeout_policy;
	hw_spin_timeout_t to  = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss  = { };
	uint64_t          deadline;

	lck_mtx_mcs_t     mcs, node;
	uint16_t          idx, pidx, clear_idx;
	unsigned long     prev;
	lck_mtx_state_t   nstate;
	ast_t      *const astp = ast_pending();

	idx  = lck_mtx_get_mcs_id();
	mcs  = PERCPU_GET(lck_mtx_mcs);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_START,
	    trace_lck, LCK_MTX_OWNER_FOR_TRACE(lock), lock->lck_mtx_tsid, 0, 0);

	/*
	 *	Take a spot in the adaptive spin queue,
	 *	and then spin until we're at the head of it.
	 *
	 *	Until we're at the head, we do not need to monitor
	 *	for whether the current owner is on core or not:
	 *
	 *	1. the head of the queue is doing it already,
	 *
	 *	2. when the entire adaptive spin queue will "give up"
	 *	   as a result of the owner going off core, we want
	 *	   to avoid a thundering herd and let the AS queue
	 *	   pour into the interlock one slowly.
	 *
	 *	Do give up if the scheduler made noises something
	 *	more important has shown up.
	 *
	 *	Note: this function is optimized so that we do not touch
	 *	      our local mcs node when we're the head of the queue.
	 *
	 *	      This allows us in the case when the contention is
	 *	      between 2 cores only to not have to touch this
	 *	      cacheline at all.
	 */
	pidx = os_atomic_xchg(&lock->lck_mtx.as_tail, idx, release);
	if (pidx) {
		node = lck_mtx_get_mcs(pidx);
		mcs->lmm_as_prev = pidx;
		os_atomic_store(&node->lmm_as_next, mcs, release);

		while (!hw_spin_wait_until(&mcs->lmm_as_prev, prev,
		    prev == 0 || (os_atomic_load(astp, relaxed) & AST_URGENT))) {
			hw_spin_should_keep_spinning(lock, pol, to, &ss);
		}

		if (__improbable(prev)) {
			goto adaptive_spin_fail;
		}

		clear_idx = 0;
	} else {
		clear_idx = idx;
	}

	/*
	 *	We're now first in line.
	 *
	 *	It's our responsbility to monitor the lock's state
	 *	for whether (1) the lock has become available,
	 *	(2) its owner has gone off core, (3) the scheduler
	 *	wants its CPU back, or (4) we've spun for too long.
	 */
	deadline = ml_get_timebase() + os_atomic_load(&MutexSpin, relaxed);

	for (;;) {
		state.val = lock_load_exclusive(&lock->lck_mtx.val, acquire);

		if (__probable(!state.ilocked && !state.ilk_tail && !state.owner)) {
			/*
			 * 2-core contention: if we can, try to dequeue
			 * ourselves from the adaptive spin queue
			 * as part of this CAS in order to avoid
			 * the cost of lck_mtx_ilk_lock_cleanup_as_mcs()
			 * and zeroing the mcs node at all.
			 *
			 * Because the queue is designed to limit contention,
			 * using store-exclusive over an armv8.1 LSE atomic
			 * is actually marginally better (presumably due to
			 * the better codegen).
			 */
			nstate = state;
			nstate.ilocked = true;
			if (state.as_tail == clear_idx) {
				nstate.as_tail = 0;
			}
			if (__probable(lock_store_exclusive(&lock->lck_mtx.val,
			    state.val, nstate.val, acquire))) {
				break;
			}
		} else {
			lock_wait_for_event();
		}

		if (__improbable(ml_get_timebase() > deadline ||
		    (os_atomic_load(astp, relaxed) & AST_URGENT) ||
		    (!state.ilocked && !state.ilk_tail && state.owner &&
		    !lck_mtx_ctid_on_core(state.owner)))) {
			goto adaptive_spin_fail;
		}
	}

	/*
	 *	If we're here, we got the lock, we just have to cleanup
	 *	the MCS nodes and return.
	 */
	if (state.as_tail != clear_idx) {
		lck_mtx_ilk_lock_cleanup_as_mcs(lock, idx, mcs, to, &ss);
		lck_mtx_mcs_clear(mcs);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_END,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(thread),
	    lock->lck_mtx_tsid, 0, 0);
	return;

adaptive_spin_fail:
	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_END,
	    trace_lck, LCK_MTX_OWNER_FOR_TRACE(lock), lock->lck_mtx_tsid, 0, 0);
	return lck_mtx_ilk_lock_contended(lock, state, LCK_ILK_MODE_FROM_AS);
}

static NOINLINE void
lck_mtx_lock_contended(lck_mtx_t *lock, thread_t thread, lck_mtx_mode_t mode)
{
	struct turnstile *ts = TURNSTILE_NULL;
	lck_mtx_state_t   state;
	uint32_t          ctid = thread->ctid;
	uint32_t          data;
#if CONFIG_DTRACE
	int               first_miss = 0;
#endif /* CONFIG_DTRACE */
	bool              direct_wait = false;
	uint64_t          spin_start;
	uint32_t          profile;

	lck_mtx_check_irq(lock);
	if (mode == LCK_MTX_MODE_SLEEPABLE) {
		lock_disable_preemption_for_thread(thread);
	}

	for (;;) {
		/*
		 *	Load the current state and perform sanity checks
		 *
		 *	Note that the various "corrupt" values are designed
		 *	so that the slowpath is taken when a mutex was used
		 *	after destruction, so that we do not have to do
		 *	sanity checks in the fast path.
		 */
		state = os_atomic_load(&lock->lck_mtx, relaxed);
		if (state.owner == ctid) {
			__lck_mtx_owned_panic(lock, thread);
		}
		if (lock->lck_mtx_type != LCK_TYPE_MUTEX ||
		    state.data == LCK_MTX_TAG_DESTROYED) {
			__lck_mtx_invalid_panic(lock);
		}
		profile = (state.data & LCK_MTX_PROFILE);

		/*
		 *	Attempt steal
		 *
		 *	When the lock state is 0, then no thread can be queued
		 *	for adaptive spinning or for the interlock yet.
		 *
		 *	As such we can attempt to try to take the interlock.
		 *	(we can't take the mutex directly because we need
		 *	the interlock to do turnstile operations on the way out).
		 */
		if ((state.val & ~LCK_MTX_PROFILE) == 0) {
			if (!os_atomic_cmpxchgv(&lock->lck_mtx.val,
			    state.val, state.val | LCK_MTX_ILOCK,
			    &state.val, acquire)) {
				continue;
			}
			break;
		}

#if CONFIG_DTRACE
		if (profile) {
			LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &first_miss);
		}
#endif /* CONFIG_DTRACE */

		if (mode == LCK_MTX_MODE_SLEEPABLE) {
			spin_start = LCK_MTX_ADAPTIVE_SPIN_BEGIN();
		} else {
			spin_start = LCK_MTX_SPIN_SPIN_BEGIN();
		}

		/*
		 *	Adaptive spin or interlock
		 *
		 *	Evaluate if adaptive spinning should be attempted,
		 *	and if yes go to adaptive spin.
		 *
		 *	Otherwise (and this includes always-spin mutexes),
		 *	go for the interlock.
		 */
		if (mode != LCK_MTX_MODE_SPIN_ALWAYS &&
		    (state.ilocked || state.as_tail || !state.owner ||
		    lck_mtx_ctid_on_core(state.owner))) {
			lck_mtx_lock_adaptive_spin(lock, state);
		} else {
			direct_wait = true;
			lck_mtx_ilk_lock_nopreempt(lock, LCK_ILK_MODE_DIRECT);
		}

		if (mode == LCK_MTX_MODE_SLEEPABLE) {
			LCK_MTX_ADAPTIVE_SPIN_END(lock, lock->lck_mtx_grp, spin_start);
		} else {
			LCK_MTX_SPIN_SPIN_END(lock, lock->lck_mtx_grp, spin_start);
		}

		/*
		 *	Take or sleep
		 *
		 *	We now have the interlock. Either the owner
		 *	isn't set, and the mutex is ours to claim,
		 *	or we must go to sleep.
		 *
		 *	If we go to sleep, we need to set LCK_MTX_NEEDS_WAKEUP
		 *	to force the current lock owner to call
		 *	lck_mtx_unlock_wakeup().
		 */
		state = os_atomic_load(&lock->lck_mtx, relaxed);
		if (state.owner == LCK_MTX_NULL_CTID) {
			break;
		}

		if (mode == LCK_MTX_MODE_SPIN_ALWAYS) {
			__lck_mtx_lock_is_sleepable_panic(lock);
		}

#if CONFIG_DTRACE
		if (profile) {
			LCK_MTX_PROF_WAIT(lock, lock->lck_mtx_grp,
			    direct_wait, &first_miss);
		}
#endif /* CONFIG_DTRACE */
		os_atomic_store(&lock->lck_mtx.data,
		    state.data | LCK_MTX_ILOCK | LCK_MTX_NEEDS_WAKEUP,
		    compiler_acq_rel);
		ts = lck_mtx_lock_wait(lock, thread,
		    ctid_get_thread(state.owner), ts);

		/* returns interlock unlocked and preemption re-enabled */
		lock_disable_preemption_for_thread(thread);
	}

	/*
	 *	We can take the lock!
	 *
	 *	We only have the interlock and the owner field is 0.
	 *
	 *	Perform various turnstile cleanups if needed,
	 *	claim the lock, and reenable preemption (if needed).
	 */
	if (ts) {
		lck_mtx_lock_wait_done(lock, ts);
	}
	data = ctid | profile;
	if (lck_mtx_lock_will_need_wakeup(lock, thread)) {
		data |= LCK_MTX_NEEDS_WAKEUP;
	}
	if (mode != LCK_MTX_MODE_SLEEPABLE) {
		data |= LCK_MTX_ILOCK | LCK_MTX_SPIN_MODE;
	}
	os_atomic_store(&lock->lck_mtx.data, data, release);

	if (mode == LCK_MTX_MODE_SLEEPABLE) {
		lock_enable_preemption();
	}

	assert(thread->turnstile != NULL);

	if (ts) {
		turnstile_cleanup();
	}
	LCK_MTX_ACQUIRED(lock, lock->lck_mtx_grp,
	    mode != LCK_MTX_MODE_SLEEPABLE, profile);
}

#if LCK_MTX_CHECK_INVARIANTS || CONFIG_DTRACE
__attribute__((noinline))
#else
__attribute__((always_inline))
#endif
static void
lck_mtx_lock_slow(
	lck_mtx_t              *lock,
	thread_t                thread,
	lck_mtx_state_t         state,
	lck_mtx_mode_t          mode)
{
#pragma unused(state)
#if CONFIG_DTRACE
	lck_mtx_state_t ostate = {
		.data = LCK_MTX_PROFILE,
	};
#endif /* CONFIG_DTRACE */

#if LCK_MTX_CHECK_INVARIANTS
	if (mode != LCK_MTX_MODE_SPIN_ALWAYS) {
		lck_mtx_check_preemption(lock, thread,
		    (mode == LCK_MTX_MODE_SPIN));
	}
#endif /* LCK_MTX_CHECK_INVARIANTS */
#if CONFIG_DTRACE
	if (state.val == ostate.val) {
		state.data = thread->ctid | LCK_MTX_PROFILE;
		if (mode != LCK_MTX_MODE_SLEEPABLE) {
			state.ilocked = true;
			state.spin_mode = true;
		}
		os_atomic_cmpxchgv(&lock->lck_mtx.val,
		    ostate.val, state.val, &state.val, acquire);
	}
	if ((state.val & ~ostate.val) == 0) {
		LCK_MTX_ACQUIRED(lock, lock->lck_mtx_grp,
		    mode != LCK_MTX_MODE_SLEEPABLE,
		    state.data & LCK_MTX_PROFILE);
		return;
	}
#endif /* CONFIG_DTRACE */
	lck_mtx_lock_contended(lock, thread, mode);
}

static __attribute__((always_inline)) void
lck_mtx_lock_fastpath(lck_mtx_t *lock, lck_mtx_mode_t mode)
{
	thread_t thread = current_thread();
	lck_mtx_state_t state = {
		.data = thread->ctid,
	};
	uint64_t take_slowpath = 0;

	if (mode != LCK_MTX_MODE_SPIN_ALWAYS) {
		take_slowpath |= LCK_MTX_SNIFF_PREEMPTION(thread);
	}
	take_slowpath |= LCK_MTX_SNIFF_DTRACE();

	if (mode != LCK_MTX_MODE_SLEEPABLE) {
		lock_disable_preemption_for_thread(thread);
		state.ilocked = true;
		state.spin_mode = true;
	}

	/*
	 * Do the CAS on the entire mutex state,
	 * which hence requires for the ILK/AS queues
	 * to be empty (which is fairer).
	 */
	lock_cmpxchgv(&lock->lck_mtx.val,
	    0, state.val, &state.val, acquire);

	take_slowpath |= state.val;
	if (__improbable(take_slowpath)) {
		return lck_mtx_lock_slow(lock, thread, state, mode);
	}
}

void
lck_mtx_lock(lck_mtx_t *lock)
{
	lck_mtx_lock_fastpath(lock, LCK_MTX_MODE_SLEEPABLE);
}

void
lck_mtx_lock_spin(lck_mtx_t *lock)
{
	lck_mtx_lock_fastpath(lock, LCK_MTX_MODE_SPIN);
}

void
lck_mtx_lock_spin_always(lck_mtx_t *lock)
{
	lck_mtx_lock_fastpath(lock, LCK_MTX_MODE_SPIN_ALWAYS);
}


#pragma mark lck_mtx_t: lck_mtx_try_lock

static __attribute__((always_inline)) bool
lck_mtx_try_lock_slow_inline(
	lck_mtx_t              *lock,
	thread_t                thread,
	uint32_t                odata,
	uint32_t                ndata,
	bool                    spin)
{
#pragma unused(lock, thread, odata, ndata)
#if CONFIG_DTRACE
	if (odata == LCK_MTX_PROFILE) {
		os_atomic_cmpxchgv(&lock->lck_mtx.data,
		    odata, ndata | LCK_MTX_PROFILE, &odata, acquire);
	}
	if ((odata & ~LCK_MTX_PROFILE) == 0) {
		LCK_MTX_TRY_ACQUIRED(lock, lock->lck_mtx_grp,
		    spin, odata & LCK_MTX_PROFILE);
		return true;
	}
	if (odata & LCK_MTX_PROFILE) {
		LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &(int){ 0 });
	}
#endif /* CONFIG_DTRACE */

	if (spin) {
		lock_enable_preemption();
	}
	return false;
}

#if CONFIG_DTRACE || LCK_MTX_CHECK_INVARIANTS
__attribute__((noinline))
#else
__attribute__((always_inline))
#endif
static bool
lck_mtx_try_lock_slow(
	lck_mtx_t              *lock,
	thread_t                thread,
	uint32_t                odata,
	uint32_t                ndata)
{
	return lck_mtx_try_lock_slow_inline(lock, thread, odata, ndata, false);
}

#if CONFIG_DTRACE || LCK_MTX_CHECK_INVARIANTS
__attribute__((noinline))
#else
__attribute__((always_inline))
#endif
static bool
lck_mtx_try_lock_slow_spin(
	lck_mtx_t              *lock,
	thread_t                thread,
	uint32_t                odata,
	uint32_t                ndata)
{
	return lck_mtx_try_lock_slow_inline(lock, thread, odata, ndata, true);
}

static __attribute__((always_inline)) bool
lck_mtx_try_lock_fastpath(lck_mtx_t *lock, lck_mtx_mode_t mode)
{
	thread_t thread = current_thread();
	uint32_t odata, ndata = thread->ctid;
	uint32_t take_slowpath = 0;

#if CONFIG_DTRACE
	take_slowpath |= lck_debug_state.lds_value;
#endif
	if (mode != LCK_MTX_MODE_SLEEPABLE) {
		lock_disable_preemption_for_thread(thread);
		ndata |= LCK_MTX_SPIN_MODE | LCK_MTX_ILOCK;
	}

	/*
	 * try_lock because it's likely to be used for cases
	 * like lock inversion resolutions tries a bit harder
	 * than lck_mtx_lock() to take the lock and ignores
	 * adaptive spin / interlock queues by doing the CAS
	 * on the 32bit mutex data only.
	 */
	lock_cmpxchgv(&lock->lck_mtx.data, 0, ndata, &odata, acquire);

	take_slowpath |= odata;
	if (__probable(!take_slowpath)) {
		return true;
	}

	if (mode == LCK_MTX_MODE_SPIN_ALWAYS &&
	    (odata & LCK_MTX_CTID_MASK) &&
	    !(odata & LCK_MTX_SPIN_MODE)) {
		__lck_mtx_lock_is_sleepable_panic(lock);
	}

	if (mode == LCK_MTX_MODE_SLEEPABLE) {
		return lck_mtx_try_lock_slow(lock, thread, odata, ndata);
	} else {
		return lck_mtx_try_lock_slow_spin(lock, thread, odata, ndata);
	}
}

boolean_t
lck_mtx_try_lock(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_fastpath(lock, LCK_MTX_MODE_SLEEPABLE);
}

boolean_t
lck_mtx_try_lock_spin(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_fastpath(lock, LCK_MTX_MODE_SPIN);
}

boolean_t
lck_mtx_try_lock_spin_always(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_fastpath(lock, LCK_MTX_MODE_SPIN_ALWAYS);
}


#pragma mark lck_mtx_t: lck_mtx_unlock

static NOINLINE void
lck_mtx_unlock_contended(lck_mtx_t *lock, thread_t thread, uint32_t data)
{
	bool cleanup = false;

#if !CONFIG_DTRACE
	/*
	 * This check is done by lck_mtx_unlock_slow() when it is enabled.
	 */
	if (thread->ctid != (data & LCK_MTX_CTID_MASK)) {
		__lck_mtx_not_owned_panic(lock, thread);
	}
#endif /* !CONFIG_DTRACE */

	if ((data & LCK_MTX_SPIN_MODE) == 0) {
		lock_disable_preemption_for_thread(thread);
		lck_mtx_ilk_lock_nopreempt(lock, LCK_ILK_MODE_UNLOCK);
	}

	/*
	 * We must re-load the data: we might have taken
	 * the slowpath because another thread had taken
	 * the interlock and set the NEEDS_WAKEUP bit
	 * while we were spinning to get it.
	 */
	data = os_atomic_load(&lock->lck_mtx.data, compiler_acq_rel);
	if (data & LCK_MTX_NEEDS_WAKEUP) {
		lck_mtx_unlock_wakeup(lock, thread);
		cleanup = true;
	}
	lck_mtx_ilk_unlock_v(lock, data & LCK_MTX_PROFILE);

	LCK_MTX_RELEASED(lock, lock->lck_mtx_grp, data & LCK_MTX_PROFILE);

	/*
	 * Do not do any turnstile operations outside of this block.
	 *
	 * lock/unlock is called at early stage of boot while single
	 * threaded, without turnstiles being available yet.
	 * Even without contention we can come throught the slow path
	 * if the mutex is acquired as a spin lock.
	 */
	if (cleanup) {
		turnstile_cleanup();
	}
}

#if CONFIG_DTRACE
__attribute__((noinline))
#else
__attribute__((always_inline))
#endif
static void
lck_mtx_unlock_slow(lck_mtx_t *lock, thread_t thread, uint32_t data)
{
#if CONFIG_DTRACE
	/*
	 *	If Dtrace is enabled, locks can be profiled,
	 *	which causes the fastpath of unlock to fail.
	 */
	if ((data & LCK_MTX_BITS_MASK) == LCK_MTX_PROFILE) {
		os_atomic_cmpxchgv(&lock->lck_mtx.data, data, LCK_MTX_PROFILE,
		    &data, release);
	}
	if (thread->ctid != (data & LCK_MTX_CTID_MASK)) {
		__lck_mtx_not_owned_panic(lock, thread);
	}
	if ((data & (LCK_MTX_BITS_MASK & ~LCK_MTX_PROFILE)) == 0) {
		LCK_MTX_RELEASED(lock, lock->lck_mtx_grp, false);
		return;
	}
#endif /* CONFIG_DTRACE */

	lck_mtx_unlock_contended(lock, thread, data);
}

void
lck_mtx_unlock(lck_mtx_t *lock)
{
	thread_t thread = current_thread();
	uint32_t take_slowpath = 0;
	uint32_t data;

	take_slowpath |= LCK_MTX_SNIFF_DTRACE();

	/*
	 * The fast path ignores the ILK/AS queues on purpose,
	 * those really are a "lock" concept, not unlock.
	 */
	if (__probable(lock_cmpxchgv(&lock->lck_mtx.data,
	    thread->ctid, 0, &data, release))) {
		if (__probable(!take_slowpath)) {
			return;
		}
	}

	lck_mtx_unlock_slow(lock, thread, data);
}


#pragma mark lck_mtx_t: misc

void
lck_mtx_assert(lck_mtx_t *lock, unsigned int type)
{
	lck_mtx_state_t state  = os_atomic_load(&lock->lck_mtx, relaxed);
	thread_t        thread = current_thread();

	if (type == LCK_MTX_ASSERT_OWNED) {
		if (state.owner != thread->ctid) {
			__lck_mtx_not_owned_panic(lock, thread);
		}
	} else if (type == LCK_MTX_ASSERT_NOTOWNED) {
		if (state.owner == thread->ctid) {
			__lck_mtx_owned_panic(lock, thread);
		}
	} else {
		panic("lck_mtx_assert(): invalid arg (%u)", type);
	}
}

/*
 *	Routine:	lck_mtx_convert_spin
 *
 *	Convert a mutex held for spin into a held full mutex
 */
void
lck_mtx_convert_spin(lck_mtx_t *lock)
{
	lck_mtx_state_t state  = os_atomic_load(&lock->lck_mtx, relaxed);
	thread_t        thread = current_thread();
	uint32_t        data   = thread->ctid;

	if (state.owner != data) {
		__lck_mtx_not_owned_panic(lock, thread);
	}

	if (state.spin_mode) {
		/*
		 * Note: we can acquire the lock in spin mode
		 *       _and_ be the inheritor if we waited.
		 *
		 *       We must only clear ilocked and spin_mode,
		 *       but preserve owner and needs_wakeup.
		 */
		state.ilocked = false;
		state.spin_mode = false;
		lck_mtx_ilk_unlock_v(lock, state.data);
		turnstile_cleanup();
	}
}

/*
 * Routine: kdp_lck_mtx_lock_spin_is_acquired
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_mtx_lock_spin_is_acquired(lck_mtx_t *lck)
{
	lck_mtx_state_t state = os_atomic_load(&lck->lck_mtx, relaxed);

	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	if (state.data == LCK_MTX_TAG_DESTROYED) {
		return false;
	}
	return state.owner || state.ilocked;
}

void
kdp_lck_mtx_find_owner(
	struct waitq           *waitq __unused,
	event64_t               event,
	thread_waitinfo_t      *waitinfo)
{
	lck_mtx_t      *mutex  = LCK_EVENT_TO_MUTEX(event);
	lck_mtx_state_t state  = os_atomic_load(&mutex->lck_mtx, relaxed);

	assert3u(state.data, !=, LCK_MTX_TAG_DESTROYED);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(mutex);
	waitinfo->owner   = thread_tid(ctid_get_thread(state.owner));
}

#endif /* !LCK_MTX_USE_ARCH */

/*
 * Routine:     mutex_pause
 *
 * Called by former callers of simple_lock_pause().
 */
#define MAX_COLLISION_COUNTS    32
#define MAX_COLLISION   8

unsigned int max_collision_count[MAX_COLLISION_COUNTS];

uint32_t collision_backoffs[MAX_COLLISION] = {
	10, 50, 100, 200, 400, 600, 800, 1000
};


void
mutex_pause(uint32_t collisions)
{
	wait_result_t wait_result;
	uint32_t        back_off;

	if (collisions >= MAX_COLLISION_COUNTS) {
		collisions = MAX_COLLISION_COUNTS - 1;
	}
	max_collision_count[collisions]++;

	if (collisions >= MAX_COLLISION) {
		collisions = MAX_COLLISION - 1;
	}
	back_off = collision_backoffs[collisions];

	wait_result = assert_wait_timeout((event_t)mutex_pause, THREAD_UNINT, back_off, NSEC_PER_USEC);
	assert(wait_result == THREAD_WAITING);

	wait_result = thread_block(THREAD_CONTINUE_NULL);
	assert(wait_result == THREAD_TIMED_OUT);
}


unsigned int mutex_yield_wait = 0;
unsigned int mutex_yield_no_wait = 0;

boolean_t
lck_mtx_yield(
	lck_mtx_t   *lck)
{
	bool has_waiters = LCK_MTX_HAS_WAITERS(lck);

#if DEBUG
	lck_mtx_assert(lck, LCK_MTX_ASSERT_OWNED);
#endif /* DEBUG */

	if (!has_waiters) {
		mutex_yield_no_wait++;
	} else {
		mutex_yield_wait++;
		lck_mtx_unlock(lck);
		mutex_pause(0);
		lck_mtx_lock(lck);
	}
	return has_waiters;
}
