/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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
#define ATOMIC_PRIVATE 1
#define LOCK_PRIVATE 1

#include <stdint.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <kern/locks.h>
#include <kern/lock_stat.h>
#include <machine/machine_cpu.h>
#include <os/atomic_private.h>
#include <vm/pmap.h>

#if defined(__x86_64__)
#include <i386/mp.h>
extern uint64_t LockTimeOutTSC;
#define TICKET_LOCK_PANIC_TIMEOUT LockTimeOutTSC
#define lock_enable_preemption enable_preemption
#endif /* defined(__x86_64__) */

#if defined(__arm__) || defined(__arm64__)
extern uint64_t TLockTimeOut;
#define TICKET_LOCK_PANIC_TIMEOUT TLockTimeOut
#endif /* defined(__arm__) || defined(__arm64__) */


/*
 * "Ticket": A FIFO spinlock with constant backoff
 * cf. Algorithms for Scalable Synchronization on Shared-Memory Multiprocessors
 * by Mellor-Crumney and Scott, 1991
 */

/*
 * TODO: proportional back-off based on desired-current ticket distance
 * This has the potential to considerably reduce snoop traffic
 * but must be tuned carefully
 * TODO: Evaluate a bias towards the performant clusters on
 * asymmetric efficient/performant multi-cluster systems, while
 * retaining the starvation-free property. A small intra-cluster bias may
 * be profitable for overall throughput
 */

static_assert(sizeof(hw_lck_ticket_t) == 4);
static_assert(offsetof(hw_lck_ticket_t, tcurnext) == 2);
static_assert(offsetof(hw_lck_ticket_t, cticket) == 2);
static_assert(offsetof(hw_lck_ticket_t, nticket) == 3);
static_assert(HW_LCK_TICKET_LOCK_VALID_BIT ==
    (8 * offsetof(hw_lck_ticket_t, lck_valid)));
static_assert(HW_LCK_TICKET_LOCK_INCREMENT ==
    (1u << (8 * offsetof(hw_lck_ticket_t, nticket))));

/*
 * Current ticket size limit--tickets can be trivially expanded
 * to 16-bits if needed
 */
static_assert(MAX_CPUS < 256);

#if DEVELOPMENT || DEBUG
__abortlike
static void
__hw_lck_invalid_panic(hw_lck_ticket_t *lck)
{
	if (lck->lck_type != LCK_TICKET_TYPE) {
		panic("Invalid ticket lock %p", lck);
	} else {
		panic("Ticket lock destroyed %p", lck);
	}
}
#endif /* DEVELOPMENT || DEBUG */

static inline void
hw_lck_ticket_verify(hw_lck_ticket_t *lck)
{
#if DEVELOPMENT || DEBUG
	if (lck->lck_type != LCK_TICKET_TYPE) {
		__hw_lck_invalid_panic(lck);
	}
#else
	(void)lck;
#endif /* DEVELOPMENT || DEBUG */
}

static inline void
lck_ticket_verify(lck_ticket_t *tlock)
{
	hw_lck_ticket_verify(&tlock->tu);
#if DEVELOPMENT || DEBUG
	if (tlock->lck_tag == LCK_TICKET_TAG_DESTROYED) {
		__hw_lck_invalid_panic(&tlock->tu);
	}
#endif /* DEVELOPMENT || DEBUG */
}

void
hw_lck_ticket_init(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	assert(((uintptr_t)lck & 3) == 0);
	os_atomic_store(lck, ((hw_lck_ticket_t){
		.lck_type = LCK_TICKET_TYPE,
		.lck_valid = 1,
	}), relaxed);

#if LOCK_STATS
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LOCK_STATS */
}

void
hw_lck_ticket_init_locked(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	assert(((uintptr_t)lck & 3) == 0);

	lock_disable_preemption_for_thread(current_thread());

	os_atomic_store(lck, ((hw_lck_ticket_t){
		.lck_type = LCK_TICKET_TYPE,
		.lck_valid = 1,
		.nticket = 1,
	}), relaxed);

#if LOCK_STATS
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LOCK_STATS */
}

void
lck_ticket_init(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	memset(tlock, 0, sizeof(*tlock));
	hw_lck_ticket_init(&tlock->tu, grp);
}

static inline void
hw_lck_ticket_destroy_internal(hw_lck_ticket_t *lck, bool sync
    LCK_GRP_ARG(lck_grp_t *grp))
{
	__assert_only hw_lck_ticket_t tmp;

	tmp.lck_value = os_atomic_load(&lck->lck_value, relaxed);

	if (__improbable(sync && !tmp.lck_valid && tmp.nticket != tmp.cticket)) {
		/*
		 * If the lock has been invalidated and there are pending
		 * reservations, it means hw_lck_ticket_lock_allow_invalid()
		 * or hw_lck_ticket_reserve() are being used.
		 *
		 * Such caller do not guarantee the liveness of the object
		 * they try to lock, we need to flush their reservations
		 * before proceeding.
		 *
		 * Because the lock is FIFO, we go through a cycle of
		 * locking/unlocking which will have this effect, because
		 * the lock is now invalid, new calls to
		 * hw_lck_ticket_lock_allow_invalid() will fail before taking
		 * a reservation, and we can safely destroy the lock.
		 */
		hw_lck_ticket_lock(lck, grp);
		hw_lck_ticket_unlock(lck);
	}

	os_atomic_store(&lck->lck_value, 0U, relaxed);

#if LOCK_STATS
	if (grp) {
		lck_grp_deallocate(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LOCK_STATS */
}

void
hw_lck_ticket_destroy(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	hw_lck_ticket_verify(lck);
	hw_lck_ticket_destroy_internal(lck, true LCK_GRP_ARG(grp));
}

void
lck_ticket_destroy(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	lck_ticket_verify(tlock);
	assert(tlock->lck_owner == 0);
	tlock->lck_tag = LCK_TICKET_TAG_DESTROYED;
	hw_lck_ticket_destroy_internal(&tlock->tu, false LCK_GRP_ARG(grp));
}

bool
hw_lck_ticket_held(hw_lck_ticket_t *lck)
{
	hw_lck_ticket_t tmp;
	tmp.tcurnext = os_atomic_load(&lck->tcurnext, relaxed);
	return tmp.cticket != tmp.nticket;
}

bool
kdp_lck_ticket_is_acquired(lck_ticket_t *lck)
{
	if (not_in_kdp) {
		panic("panic: ticket lock acquired check done outside of kernel debugger");
	}
	return hw_lck_ticket_held(&lck->tu);
}

static inline void
tlock_mark_owned(lck_ticket_t *tlock, thread_t cthread)
{
	/*
	 * There is a small pre-emption disabled window (also interrupts masked
	 * for the pset lock) between the acquisition of the lock and the
	 * population of the advisory 'owner' thread field
	 * On architectures with a DCAS (ARM v8.1 or x86), conceivably we could
	 * populate the next ticket and the thread atomically, with
	 * possible overhead, potential loss of micro-architectural fwd progress
	 * properties of an unconditional fetch-add, and a 16 byte alignment requirement.
	 */
	assert(tlock->lck_owner == 0);
	os_atomic_store(&tlock->lck_owner, (uintptr_t)cthread, relaxed);
}

__abortlike
static hw_lock_timeout_status_t
hw_lck_ticket_timeout_panic(void *_lock, uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(interrupt_time)

	lck_spinlock_to_info_t lsti;
	hw_lck_ticket_t *lck = _lock;
	hw_lck_ticket_t tmp;

	lsti = lck_spinlock_timeout_hit(lck, 0);
	tmp.tcurnext = os_atomic_load(&lck->tcurnext, relaxed);

	panic("Ticket spinlock[%p] timeout after %llu ticks; "
	    "cticket: 0x%x, nticket: 0x%x, waiting for 0x%x, "
#if INTERRUPT_MASKED_DEBUG
	    "interrupt time: %llu, "
#endif /* INTERRUPT_MASKED_DEBUG */
	    "start time: %llu, now: %llu, timeout: %llu",
	    lck, now - start, tmp.cticket, tmp.nticket, lsti->extra,
#if INTERRUPT_MASKED_DEBUG
	    interrupt_time,
#endif /* INTERRUPT_MASKED_DEBUG */
	    start, now, timeout);
}

__abortlike
static hw_lock_timeout_status_t
lck_ticket_timeout_panic(void *_lock, uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(interrupt_time)
	lck_spinlock_to_info_t lsti;
	hw_lck_ticket_t *lck = _lock;
	lck_ticket_t *tlock = __container_of(lck, lck_ticket_t, tu);
	hw_lck_ticket_t tmp;

	lsti = lck_spinlock_timeout_hit(lck, tlock->lck_owner);
	tmp.tcurnext = os_atomic_load(&lck->tcurnext, relaxed);

	panic("Ticket spinlock[%p] timeout after %llu ticks; "
	    "cticket: 0x%x, nticket: 0x%x, waiting for 0x%x, "
	    "current owner: %p (on CPU %d), "
#if DEBUG || DEVELOPMENT
	    "orig owner: %p, "
#endif /* DEBUG || DEVELOPMENT */
#if INTERRUPT_MASKED_DEBUG
	    "interrupt time: %llu, "
#endif /* INTERRUPT_MASKED_DEBUG */
	    "start time: %llu, now: %llu, timeout: %llu",
	    tlock, now - start, tmp.cticket, tmp.nticket, lsti->extra,
	    (void *)lsti->owner_thread_cur, lsti->owner_cpu,
#if DEBUG || DEVELOPMENT
	    (void *)lsti->owner_thread_orig,
#endif /* DEBUG || DEVELOPMENT */
#if INTERRUPT_MASKED_DEBUG
	    interrupt_time,
#endif /* INTERRUPT_MASKED_DEBUG */
	    start, now, timeout);
}

static inline void
hw_lck_ticket_unlock_internal_nopreempt(hw_lck_ticket_t *lck)
{
	_Atomic uint8_t *ctp = (_Atomic uint8_t *)&lck->cticket;
	uint8_t cticket;

	/*
	 * Do not use os_atomic* here, we want non volatile atomics
	 * so that the compiler can codegen an `incb` on Intel.
	 */
	cticket = atomic_load_explicit(ctp, memory_order_relaxed);
	atomic_store_explicit(ctp, cticket + 1, memory_order_release);
#if __arm__
	set_event();
#endif  // __arm__
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_TICKET_LOCK_RELEASE, lck);
#endif /* CONFIG_DTRACE */
}

__header_always_inline void
hw_lck_ticket_unlock_internal(hw_lck_ticket_t *lck)
{
	hw_lck_ticket_unlock_internal_nopreempt(lck);
	lock_enable_preemption();
}

struct hw_lck_ticket_reserve_arg {
	uint8_t mt;
	bool    validate;
};

/*
 * On contention, poll for ownership
 * Returns when the current ticket is observed equal to "mt"
 */
__result_use_check
static hw_lock_status_t __attribute__((noinline))
hw_lck_ticket_contended(hw_lck_ticket_t *lck, thread_t cthread, struct hw_lck_ticket_reserve_arg arg,
    uint64_t timeout, hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(cthread)

	uint64_t end = 0, start = 0, interrupts = 0;
	bool     has_timeout = true;

	uint8_t  cticket;
	uint8_t  mt = arg.mt;
#if INTERRUPT_MASKED_DEBUG
	bool in_ppl = pmap_in_ppl();
	bool interruptible = !in_ppl && ml_get_interrupts_enabled();
	uint64_t start_interrupts = 0;
#endif /* INTERRUPT_MASKED_DEBUG */

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_ticket_spin_enabled(lck LCK_GRP_ARG(grp));

	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* CONFIG_DTRACE || LOCK_STATS */

#if INTERRUPT_MASKED_DEBUG
	timeout = hw_lock_compute_timeout(timeout, TICKET_LOCK_PANIC_TIMEOUT, in_ppl, interruptible);
#else
	timeout = hw_lock_compute_timeout(timeout, TICKET_LOCK_PANIC_TIMEOUT);
#endif /* INTERRUPT_MASKED_DEBUG */
	if (timeout == 0) {
		has_timeout = false;
	}

	for (;;) {
		for (int i = 0; i < LOCK_SNOOP_SPINS; i++) {
#if OS_ATOMIC_HAS_LLSC
			cticket = os_atomic_load_exclusive(&lck->cticket, acquire);
			if (__improbable(cticket != mt)) {
				wait_for_event();
				continue;
			}
			os_atomic_clear_exclusive();
#elif defined(__x86_64__)
			__builtin_ia32_pause();
			cticket = os_atomic_load(&lck->cticket, acquire);
			if (__improbable(cticket != mt)) {
				continue;
			}
#else
#error unsupported architecture
#endif

			/*
			 * We now have successfully acquired the lock
			 */

#if CONFIG_DTRACE || LOCK_STATS
			if (__improbable(stat_enabled)) {
				lck_grp_ticket_update_spin(lck LCK_GRP_ARG(grp),
				    mach_absolute_time() - begin);
			}
			lck_grp_ticket_update_miss(lck LCK_GRP_ARG(grp));
			lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */
			if (__improbable(arg.validate && !lck->lck_valid)) {
				/*
				 * We got the lock, however the caller is
				 * hw_lck_ticket_lock_allow_invalid() and the
				 * lock has been invalidated while we were
				 * waiting for our turn.
				 *
				 * We need to unlock and pretend we failed.
				 */
				hw_lck_ticket_unlock_internal(lck);
				return HW_LOCK_INVALID;
			}

			return HW_LOCK_ACQUIRED;
		}

		if (has_timeout) {
			uint64_t now = ml_get_timebase();
			if (end == 0) {
#if INTERRUPT_MASKED_DEBUG
				if (interruptible) {
					start_interrupts = cthread->machine.int_time_mt;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				start = now;
				end = now + timeout;
				/* remember the droid we're looking for */
				PERCPU_GET(lck_spinlock_to_info)->extra = mt;
			} else if (now < end) {
				/* keep spinning */
			} else {
#if INTERRUPT_MASKED_DEBUG
				if (interruptible) {
					interrupts = cthread->machine.int_time_mt - start_interrupts;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				if (handler(lck, timeout, start, now, interrupts)) {
					/* push the deadline */
					end += timeout;
				} else {
					break;
				}
			}
		}
	}

#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(stat_enabled)) {
		lck_grp_ticket_update_spin(lck LCK_GRP_ARG(grp),
		    mach_absolute_time() - begin);
	}
	lck_grp_ticket_update_miss(lck LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */
	return HW_LOCK_CONTENDED;
}

static void __attribute__((noinline))
lck_ticket_contended(lck_ticket_t *tlock, uint8_t mt, thread_t cthread
    LCK_GRP_ARG(lck_grp_t *grp))
{
	assertf(tlock->lck_owner != (uintptr_t) cthread,
	    "Recursive ticket lock, owner: %p, current thread: %p",
	    (void *) tlock->lck_owner, (void *) cthread);

	struct hw_lck_ticket_reserve_arg arg = { .mt = mt };
	lck_spinlock_timeout_set_orig_owner(tlock->lck_owner);
	(void)hw_lck_ticket_contended(&tlock->tu, cthread, arg, 0,
	    lck_ticket_timeout_panic LCK_GRP_ARG(grp));
	tlock_mark_owned(tlock, cthread);
}

static inline hw_lck_ticket_t
hw_lck_ticket_reserve_orig(hw_lck_ticket_t *lck)
{
	hw_lck_ticket_t tmp;

	/*
	 * Atomically load both the entier lock state, and increment the
	 * "nticket". Wrap of the ticket field is OK as long as the total
	 * number of contending CPUs is < maximum ticket
	 */
	tmp.lck_value = os_atomic_add_orig(&lck->lck_value,
	    1U << (8 * offsetof(hw_lck_ticket_t, nticket)), acquire);

	return tmp;
}

void
hw_lck_ticket_lock(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	thread_t cthread = current_thread();
	hw_lck_ticket_t tmp;

	hw_lck_ticket_verify(lck);
	lock_disable_preemption_for_thread(cthread);
	tmp = hw_lck_ticket_reserve_orig(lck);

	if (__probable(tmp.cticket == tmp.nticket)) {
		return lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
	}

	/* Contention? branch to out of line contended block */
	struct hw_lck_ticket_reserve_arg arg = { .mt = tmp.nticket };
	lck_spinlock_timeout_set_orig_owner(0);
	(void)hw_lck_ticket_contended(lck, cthread, arg, 0,
	    hw_lck_ticket_timeout_panic LCK_GRP_ARG(grp));
}

hw_lock_status_t
hw_lck_ticket_lock_to(hw_lck_ticket_t *lck, uint64_t timeout,
    hw_lock_timeout_handler_t handler, lck_grp_t *grp)
{
	thread_t cthread = current_thread();
	hw_lck_ticket_t tmp;

	hw_lck_ticket_verify(lck);
	lock_disable_preemption_for_thread(cthread);
	tmp = hw_lck_ticket_reserve_orig(lck);

	if (__probable(tmp.cticket == tmp.nticket)) {
		lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	/* Contention? branch to out of line contended block */
	struct hw_lck_ticket_reserve_arg arg = { .mt = tmp.nticket };
	lck_spinlock_timeout_set_orig_owner(0);
	return hw_lck_ticket_contended(lck, cthread, arg, timeout,
	           handler LCK_GRP_ARG(grp));
}

__header_always_inline void
__lck_ticket_lock(lck_ticket_t *tlock, __unused lck_grp_t *grp, bool nopreempt)
{
	thread_t cthread = current_thread();
	hw_lck_ticket_t tmp;

	lck_ticket_verify(tlock);
	if (!nopreempt) {
		lock_disable_preemption_for_thread(cthread);
	}
	tmp = hw_lck_ticket_reserve_orig(&tlock->tu);

	if (__probable(tmp.cticket == tmp.nticket)) {
		tlock_mark_owned(tlock, cthread);
		return lck_grp_ticket_update_held(&tlock->tu LCK_GRP_ARG(grp));
	}

	/* Contention? branch to out of line contended block */
	lck_ticket_contended(tlock, tmp.nticket, cthread LCK_GRP_ARG(grp));
}

void
lck_ticket_lock(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	__lck_ticket_lock(tlock, grp, false);
}

void
lck_ticket_lock_nopreempt(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	__lck_ticket_lock(tlock, grp, true);
}

bool
hw_lck_ticket_lock_try(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	hw_lck_ticket_t olck, nlck;

	hw_lck_ticket_verify(lck);
	lock_disable_preemption_for_thread(current_thread());

	os_atomic_rmw_loop(&lck->tcurnext, olck.tcurnext, nlck.tcurnext, acquire, {
		if (__improbable(olck.cticket != olck.nticket)) {
		        os_atomic_rmw_loop_give_up({
				lock_enable_preemption();
				return false;
			});
		}
		nlck.cticket = olck.cticket;
		nlck.nticket = olck.nticket + 1;
	});

	lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
	return true;
}

__header_always_inline bool
__lck_ticket_lock_try(lck_ticket_t *tlock, __unused lck_grp_t *grp, bool nopreempt)
{
	thread_t cthread = current_thread();
	hw_lck_ticket_t olck, nlck;

	lck_ticket_verify(tlock);
	if (!nopreempt) {
		lock_disable_preemption_for_thread(cthread);
	}

	os_atomic_rmw_loop(&tlock->tu.tcurnext, olck.tcurnext, nlck.tcurnext, acquire, {
		if (__improbable(olck.cticket != olck.nticket)) {
		        os_atomic_rmw_loop_give_up({
				if (!nopreempt) {
				        lock_enable_preemption();
				}
				return false;
			});
		}
		nlck.cticket = olck.cticket;
		nlck.nticket = olck.nticket + 1;
	});

	tlock_mark_owned(tlock, cthread);
	lck_grp_ticket_update_held(&tlock->tu LCK_GRP_ARG(grp));
	return true;
}

bool
lck_ticket_lock_try(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	return __lck_ticket_lock_try(tlock, grp, false);
}

bool
lck_ticket_lock_try_nopreempt(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	return __lck_ticket_lock_try(tlock, grp, true);
}

/*
 * Returns a "reserved" lock or a lock where `lck_valid` is 0.
 *
 * More or less equivalent to this:
 *
 *	hw_lck_ticket_t
 *	hw_lck_ticket_lock_allow_invalid(hw_lck_ticket_t *lck)
 *	{
 *		hw_lck_ticket_t o, n;
 *
 *		os_atomic_rmw_loop(lck, o, n, acquire, {
 *			if (__improbable(!o.lck_valid)) {
 *				os_atomic_rmw_loop_give_up({
 *					return (hw_lck_ticket_t){ 0 };
 *				});
 *			}
 *			n = o;
 *			n.nticket++;
 *		});
 *		return o;
 *	}
 */
extern hw_lck_ticket_t
hw_lck_ticket_reserve_orig_allow_invalid(hw_lck_ticket_t *lck);

bool
hw_lck_ticket_reserve(hw_lck_ticket_t *lck, uint32_t *ticket, lck_grp_t *grp)
{
	hw_lck_ticket_t tmp;

	hw_lck_ticket_verify(lck);
	lock_disable_preemption_for_thread(current_thread());
	tmp = hw_lck_ticket_reserve_orig(lck);
	*ticket = tmp.lck_value;

	if (__probable(tmp.cticket == tmp.nticket)) {
		lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
		return true;
	}

	return false;
}

hw_lock_status_t
hw_lck_ticket_reserve_allow_invalid(hw_lck_ticket_t *lck, uint32_t *ticket, lck_grp_t *grp)
{
	hw_lck_ticket_t tmp;

	lock_disable_preemption_for_thread(current_thread());

	tmp = hw_lck_ticket_reserve_orig_allow_invalid(lck);
	*ticket = tmp.lck_value;

	if (__improbable(!tmp.lck_valid)) {
		lock_enable_preemption();
		return HW_LOCK_INVALID;
	}

	if (__probable(tmp.cticket == tmp.nticket)) {
		lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	return HW_LOCK_CONTENDED;
}

hw_lock_status_t
hw_lck_ticket_wait(hw_lck_ticket_t *lck, uint32_t ticket, uint64_t timeout,
    hw_lock_timeout_handler_t handler, lck_grp_t *grp)
{
	hw_lck_ticket_t tmp = { .lck_value = ticket };
	struct hw_lck_ticket_reserve_arg arg = { .mt = tmp.nticket };
	lck_spinlock_timeout_set_orig_owner(0);
	return hw_lck_ticket_contended(lck, current_thread(), arg, timeout,
	           handler LCK_GRP_ARG(grp));
}

hw_lock_status_t
hw_lck_ticket_lock_allow_invalid(hw_lck_ticket_t *lck, uint64_t timeout,
    hw_lock_timeout_handler_t handler, lck_grp_t *grp)
{
	hw_lock_status_t st;
	hw_lck_ticket_t tmp;

	st = hw_lck_ticket_reserve_allow_invalid(lck, &tmp.lck_value, grp);

	if (__improbable(st == HW_LOCK_CONTENDED)) {
		/* Contention? branch to out of line contended block */
		struct hw_lck_ticket_reserve_arg arg = {
			.mt = tmp.nticket,
			.validate = true,
		};
		lck_spinlock_timeout_set_orig_owner(0);
		return hw_lck_ticket_contended(lck, current_thread(), arg, timeout,
		           handler LCK_GRP_ARG(grp));
	}

	return st;
}

void
hw_lck_ticket_invalidate(hw_lck_ticket_t *lck)
{
	hw_lck_ticket_t tmp = { .lck_valid = 1 };

	os_atomic_andnot(&lck->lck_value, tmp.lck_value, relaxed);
}

void
hw_lck_ticket_unlock(hw_lck_ticket_t *lck)
{
	hw_lck_ticket_verify(lck);
#if MACH_ASSERT
	hw_lck_ticket_t tmp;
	tmp.lck_value = os_atomic_load(&lck->lck_value, relaxed);
	assertf(tmp.cticket != tmp.nticket,
	    "Ticket lock %p is not locked (0x%08x)", lck, tmp.lck_value);
#endif /* MACH_ASSERT */
	hw_lck_ticket_unlock_internal(lck);
}

void
lck_ticket_unlock_nopreempt(lck_ticket_t *tlock)
{
	lck_ticket_verify(tlock);

	assertf(tlock->lck_owner == (uintptr_t)current_thread(),
	    "Ticket unlock non-owned, owner: %p", (void *) tlock->lck_owner);
	os_atomic_store(&tlock->lck_owner, 0, relaxed);

	hw_lck_ticket_unlock_internal_nopreempt(&tlock->tu);
}

void
lck_ticket_unlock(lck_ticket_t *tlock)
{
	lck_ticket_unlock_nopreempt(tlock);
	lock_enable_preemption();
}

void
lck_ticket_assert_owned(__assert_only lck_ticket_t *tlock)
{
#if MACH_ASSERT
	thread_t self, owner;

	owner = (thread_t)os_atomic_load(&tlock->lck_owner, relaxed);
	self = current_thread();
	assertf(owner == self, "lck_ticket_assert_owned: owner %p, current: %p",
	    owner, self);
#endif /* MACH_ASSERT */
}
