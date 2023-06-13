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

#define LOCK_PRIVATE 1
#include <stdint.h>
#include <kern/thread.h>
#include <kern/locks_internal.h>
#include <kern/locks.h>
#include <kern/lock_stat.h>
#include <machine/machine_cpu.h>
#include <vm/pmap.h>
#include <san/kasan.h>

/*
 * "Ticket": A FIFO spinlock with constant backoff
 * cf. Algorithms for Scalable Synchronization on Shared-Memory Multiprocessors
 * by Mellor-Crumney and Scott, 1991
 *
 * Note: 'cticket' is 'now_serving', 'nticket' is 'next_ticket'
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

#if defined(__x86_64__)
#include <i386/mp.h>
extern uint64_t LockTimeOutTSC;
#define TICKET_LOCK_PANIC_TIMEOUT LockTimeOutTSC
#endif /* defined(__x86_64__) */

#if defined(__arm64__)
extern uint64_t TLockTimeOut;
#define TICKET_LOCK_PANIC_TIMEOUT TLockTimeOut
#endif /* defined(__arm64__) */

#if CONFIG_PV_TICKET

/*
 * Tunable that controls how many pause/wfe loops
 * to execute before checking for timeouts and
 * issuing a "wait" hypercall.
 */
#if __x86_64__
#define DEFAULT_TICKET_LOOPS (LOCK_SNOOP_SPINS)
#else
#define DEFAULT_TICKET_LOOPS (LOCK_SNOOP_SPINS / 8)
#endif
uint32_t ticket_lock_spins = DEFAULT_TICKET_LOOPS;
#define TICKET_LOCK_SNOOP_LOOPS ticket_lock_spins

#else /* CONFIG_PV_TICKET */

/*
 * How many pause/wfe loops to execute before
 * checking for timeouts.
 */
#define TICKET_LOCK_SNOOP_LOOPS LOCK_SNOOP_SPINS

#endif /* CONFIG_PV_TICKET */

/*
 * Current ticket size limit--tickets can be trivially expanded
 * to 16-bits if needed
 */
static_assert(MAX_CPUS < (256 / HW_LCK_TICKET_LOCK_INCREMENT));
static_assert(sizeof(hw_lck_ticket_t) == 4);
static_assert(offsetof(hw_lck_ticket_t, tcurnext) == 2);
static_assert(offsetof(hw_lck_ticket_t, cticket) == 2);
static_assert(offsetof(hw_lck_ticket_t, nticket) == 3);
static_assert(HW_LCK_TICKET_LOCK_INC_WORD ==
    (HW_LCK_TICKET_LOCK_INCREMENT << (8 * offsetof(hw_lck_ticket_t, nticket))));
#if 0 /* the expression below is sadly not constant, thank you for nothing C */
static_assert((1u << HW_LCK_TICKET_LOCK_VALID_BIT) ==
    ((hw_lck_ticket_t){ .lck_valid = 1 }).lck_value);
#endif

__header_always_inline int
equal_tickets(uint8_t t0, uint8_t t1)
{
	return !((t0 ^ t1) & ~HW_LCK_TICKET_LOCK_PVWAITFLAG);
}

__header_always_inline uint8_t
ticket_count(uint8_t t)
{
	return t & ~HW_LCK_TICKET_LOCK_PVWAITFLAG;
}

__abortlike
static void
__hw_lck_ticket_invalid_panic(hw_lck_ticket_t *lck)
{
	panic("Invalid HW ticket lock %p <0x%08x>", lck, lck->lck_value);
}

__abortlike
static void
__lck_ticket_invalid_panic(lck_ticket_t *lck)
{
	panic("Invalid ticket lock %p <0x%08x 0x%08x 0x%08x 0x%08x>",
	    lck, *(uint32_t *)lck, lck->lck_ticket_owner,
	    lck->tu.lck_value, lck->lck_ticket_padding);
}

__abortlike
static void
__lck_ticket_owned_panic(lck_ticket_t *lck)
{
	thread_t self = current_thread();

	panic("Ticket lock %p is unexpectedly owned by thread %p", lck, self);
}

__abortlike
static void
__lck_ticket_not_owned_panic(lck_ticket_t *lck)
{
	thread_t self = current_thread();

	panic("Ticket lock %p is unexpectedly not owned by thread %p", lck, self);
}

static inline void
hw_lck_ticket_verify(hw_lck_ticket_t *lck)
{
	if (lck->lck_type != LCK_TYPE_TICKET) {
		__hw_lck_ticket_invalid_panic(lck);
	}
}

static inline void
lck_ticket_verify(lck_ticket_t *tlock)
{
	if (tlock->lck_ticket_type != LCK_TYPE_TICKET) {
		__lck_ticket_invalid_panic(tlock);
	}
}

#if DEVELOPMENT || DEBUG
#define HW_LCK_TICKET_VERIFY(lck)      hw_lck_ticket_verify(lck)
#define LCK_TICKET_VERIFY(lck)         lck_ticket_verify(lck)
#define LCK_TICKET_UNLOCK_VERIFY(l)    ({ \
	if ((l)->lck_ticket_owner != current_thread()->ctid) {  \
	        __lck_ticket_not_owned_panic(l);                \
	}                                                       \
})
#else
#define HW_LCK_TICKET_VERIFY(lck)      ((void)0)
#define LCK_TICKET_VERIFY(lck)         ((void)0)
#define LCK_TICKET_UNLOCK_VERIFY(l)    ((void)0)
#endif /* DEVELOPMENT || DEBUG */

MARK_AS_HIBERNATE_TEXT void
hw_lck_ticket_init(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	assert(((uintptr_t)lck & 3) == 0);
	os_atomic_store(lck, ((hw_lck_ticket_t){
		.lck_type = LCK_TYPE_TICKET,
#if CONFIG_PV_TICKET
		.lck_is_pv = has_lock_pv,
#endif /* CONFIG_PV_TICKET */
		.lck_valid = 1,
	}), relaxed);

#if LCK_GRP_USE_ARG
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LCK_GRP_USE_ARG */
}

void
hw_lck_ticket_init_locked(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	assert(((uintptr_t)lck & 3) == 0);

	lock_disable_preemption_for_thread(current_thread());

	os_atomic_store(lck, ((hw_lck_ticket_t){
		.lck_type = LCK_TYPE_TICKET,
#if CONFIG_PV_TICKET
		.lck_is_pv = has_lock_pv,
#endif /* CONFIG_PV_TICKET */
		.lck_valid = 1,
		.nticket = HW_LCK_TICKET_LOCK_INCREMENT,
	}), relaxed);

#if LCK_GRP_USE_ARG
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LCK_GRP_USE_ARG */
}

MARK_AS_HIBERNATE_TEXT void
lck_ticket_init(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	*tlock = (lck_ticket_t){
		.lck_ticket_type = LCK_TYPE_TICKET,
		.tu = {
			.lck_type = LCK_TYPE_TICKET,
#if CONFIG_PV_TICKET
			.lck_is_pv = has_lock_pv,
#endif /* CONFIG_PV_TICKET */
			.lck_valid = 1,
		},
	};

#if LCK_GRP_USE_ARG
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LCK_GRP_USE_ARG */
}

static inline void
hw_lck_ticket_destroy_internal(hw_lck_ticket_t *lck, bool sync
    LCK_GRP_ARG(lck_grp_t *grp))
{
	__assert_only hw_lck_ticket_t tmp;

	tmp.lck_value = os_atomic_load(&lck->lck_value, relaxed);

	if (__improbable(sync && !tmp.lck_valid && !equal_tickets(tmp.nticket, tmp.cticket))) {
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

#if LCK_GRP_USE_ARG
	if (grp) {
		lck_grp_deallocate(grp, &grp->lck_grp_ticketcnt);
	}
#endif /* LCK_GRP_USE_ARG */
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
	assert(tlock->lck_ticket_owner == 0);
	tlock->lck_ticket_type = LCK_TYPE_NONE;
	hw_lck_ticket_destroy_internal(&tlock->tu, false LCK_GRP_ARG(grp));
}

bool
hw_lck_ticket_held(hw_lck_ticket_t *lck)
{
	hw_lck_ticket_t tmp;
	tmp.tcurnext = os_atomic_load(&lck->tcurnext, relaxed);
	return !equal_tickets(tmp.cticket, tmp.nticket);
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
	assert3u(tlock->lck_ticket_owner, ==, 0);
	os_atomic_store(&tlock->lck_ticket_owner, cthread->ctid, relaxed);
}

__abortlike
static hw_spin_timeout_status_t
hw_lck_ticket_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	lck_spinlock_to_info_t lsti;
	hw_lck_ticket_t *lck = _lock;
	hw_lck_ticket_t tmp;

	tmp.lck_value = os_atomic_load(&lck->lck_value, relaxed);

	if (pmap_in_ppl()) {
		panic("Ticket spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
		    "cticket: 0x%x, nticket: 0x%x, valid: %d, "
		    HW_SPIN_TIMEOUT_DETAILS_FMT,
		    lck, HW_SPIN_TIMEOUT_ARG(to, st),
		    tmp.cticket, tmp.nticket, tmp.lck_valid,
		    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
	}

	lsti = lck_spinlock_timeout_hit(lck, 0);
	panic("Ticket spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "cticket: 0x%x, nticket: 0x%x, waiting for 0x%x, valid: %d, "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lck, HW_SPIN_TIMEOUT_ARG(to, st),
	    tmp.cticket, tmp.nticket, lsti->extra, tmp.lck_valid,
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

__abortlike
static hw_spin_timeout_status_t
lck_ticket_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	lck_spinlock_to_info_t lsti;
	lck_ticket_t *lck = _lock;
	hw_lck_ticket_t tmp;

	lsti = lck_spinlock_timeout_hit(&lck->tu, lck->lck_ticket_owner);
	tmp.tcurnext = os_atomic_load(&lck->tu.tcurnext, relaxed);

	panic("Ticket spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "cticket: 0x%x, nticket: 0x%x, waiting for 0x%x, "
	    "current owner: %p (on CPU %d), "
#if DEBUG || DEVELOPMENT
	    "orig owner: %p, "
#endif /* DEBUG || DEVELOPMENT */
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lck, HW_SPIN_TIMEOUT_ARG(to, st),
	    tmp.cticket, tmp.nticket, lsti->extra,
	    (void *)lsti->owner_thread_cur, lsti->owner_cpu,
#if DEBUG || DEVELOPMENT
	    (void *)lsti->owner_thread_orig,
#endif /* DEBUG || DEVELOPMENT */
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy hw_lck_ticket_spin_policy = {
	.hwsp_name              = "hw_lck_ticket_lock",
	.hwsp_timeout           = &TICKET_LOCK_PANIC_TIMEOUT,
	.hwsp_op_timeout        = hw_lck_ticket_timeout_panic,
};

static const struct hw_spin_policy lck_ticket_spin_policy = {
	.hwsp_name              = "lck_ticket_lock",
	.hwsp_timeout           = &TICKET_LOCK_PANIC_TIMEOUT,
	.hwsp_lock_offset       = offsetof(lck_ticket_t, tu),
	.hwsp_op_timeout        = lck_ticket_timeout_panic,
};


#if CONFIG_PV_TICKET

#if DEBUG || DEVELOPMENT
SCALABLE_COUNTER_DEFINE(ticket_wflag_cleared);
SCALABLE_COUNTER_DEFINE(ticket_wflag_still);
SCALABLE_COUNTER_DEFINE(ticket_just_unlock);
SCALABLE_COUNTER_DEFINE(ticket_kick_count);
SCALABLE_COUNTER_DEFINE(ticket_wait_count);
SCALABLE_COUNTER_DEFINE(ticket_already_count);
SCALABLE_COUNTER_DEFINE(ticket_spin_count);
#endif

static inline void
hw_lck_ticket_unlock_inner_pv(hw_lck_ticket_t *lck)
{
	const uint8_t cticket = (uint8_t) os_atomic_add(&lck->cticket,
	    HW_LCK_TICKET_LOCK_INCREMENT, acq_rel);
	if (__improbable(cticket & HW_LCK_TICKET_LOCK_PVWAITFLAG)) {
		hw_lck_ticket_unlock_kick_pv(lck, ticket_count(cticket));
	} else {
		PVTICKET_STATS_INC(just_unlock);
	}
}
#endif /* CONFIG_PV_TICKET */

__header_always_inline void
hw_lck_ticket_unlock_inner(hw_lck_ticket_t *lck)
{
	_Atomic uint8_t *ctp = (_Atomic uint8_t *)&lck->cticket;
	uint8_t cticket;

	/*
	 * Do not use os_atomic* here, we want non volatile atomics
	 * so that the compiler can codegen an `incb` on Intel.
	 */
	cticket = atomic_load_explicit(ctp, memory_order_relaxed);
	atomic_store_explicit(ctp, cticket +
	    HW_LCK_TICKET_LOCK_INCREMENT, memory_order_release);
}

__header_always_inline void
hw_lck_ticket_unlock_internal_nopreempt(hw_lck_ticket_t *lck)
{
#if CONFIG_PV_TICKET
	if (lck->lck_is_pv) {
		hw_lck_ticket_unlock_inner_pv(lck);
	} else {
		hw_lck_ticket_unlock_inner(lck);
	}
#else
	hw_lck_ticket_unlock_inner(lck);
#endif
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
hw_lck_ticket_contended(
	hw_lck_ticket_t        *lck,
	struct hw_lck_ticket_reserve_arg arg,
	hw_spin_policy_t       pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_spin_timeout_t to = hw_spin_compute_timeout(pol);
	hw_spin_state_t   state = { };
	uint32_t          pv_spin_count = 0;
	hw_lck_ticket_t   value;

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_ticket_spin_enabled(lck LCK_GRP_ARG(grp));

	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* CONFIG_DTRACE || LOCK_STATS */

	while (__improbable(!hw_spin_wait_until_n(TICKET_LOCK_SNOOP_LOOPS,
	    &lck->lck_value, value.lck_value,
	    (pv_spin_count++, equal_tickets(value.cticket, arg.mt))))) {
		if (state.hwss_deadline == 0 && !hw_spin_in_ppl(to)) {
			/* remember the droid we're looking for */
			PERCPU_GET(lck_spinlock_to_info)->extra = arg.mt;
		}

		if (__improbable(!hw_spin_should_keep_spinning(lck, pol, to, &state))) {
#if CONFIG_PV_TICKET
			PVTICKET_STATS_ADD(spin_count, pv_spin_count);
#endif /* CONFIG_PV_TICKET */
#if CONFIG_DTRACE || LOCK_STATS
			if (__improbable(stat_enabled)) {
				lck_grp_ticket_update_spin(lck LCK_GRP_ARG(grp),
				    mach_absolute_time() - begin);
			}
			lck_grp_ticket_update_miss(lck LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */
			return HW_LOCK_CONTENDED;
		}

#if CONFIG_PV_TICKET
		if (lck->lck_is_pv) {
			os_atomic_or(&lck->cticket, HW_LCK_TICKET_LOCK_PVWAITFLAG, acq_rel);
			hw_lck_ticket_lock_wait_pv(lck, arg.mt);
		}
#endif /* CONFIG_PV_TICKET */
	}

	/*
	 * We now have successfully acquired the lock
	 */

#if CONFIG_PV_TICKET
	PVTICKET_STATS_ADD(spin_count, pv_spin_count);
	if (__improbable(value.cticket & HW_LCK_TICKET_LOCK_PVWAITFLAG)) {
		/*
		 * Try and clear the wait flag
		 */
		const hw_lck_ticket_t olck = {
			.cticket = value.cticket,
			.nticket = ticket_count(value.cticket)
		    + HW_LCK_TICKET_LOCK_INCREMENT,
		};
		const hw_lck_ticket_t nlck = {
			.cticket = ticket_count(value.cticket),
			.nticket = olck.nticket,
		};
		if (os_atomic_cmpxchg(&lck->tcurnext,
		    olck.tcurnext, nlck.tcurnext, acq_rel)) {
			PVTICKET_STATS_INC(wflag_cleared);
		} else {
			PVTICKET_STATS_INC(wflag_still);
		}
	}
#endif /* CONFIG_PV_TICKET */
#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(stat_enabled)) {
		lck_grp_ticket_update_spin(lck LCK_GRP_ARG(grp),
		    mach_absolute_time() - begin);
	}
	lck_grp_ticket_update_miss(lck LCK_GRP_ARG(grp));
	lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */

	if (__improbable(arg.validate && !value.lck_valid)) {
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

	os_atomic_thread_fence(acquire);
	return HW_LOCK_ACQUIRED;
}

static void __attribute__((noinline))
lck_ticket_contended(lck_ticket_t *tlock, uint8_t mt, thread_t cthread
    LCK_GRP_ARG(lck_grp_t *grp))
{
	if (cthread->ctid == tlock->lck_ticket_owner) {
		__lck_ticket_owned_panic(tlock);
	}

	struct hw_lck_ticket_reserve_arg arg = { .mt = mt };
	lck_spinlock_timeout_set_orig_ctid(tlock->lck_ticket_owner);
	(void)hw_lck_ticket_contended(&tlock->tu, arg, &lck_ticket_spin_policy
	    LCK_GRP_ARG(grp));
	lck_spinlock_timeout_set_orig_ctid(0);
	tlock_mark_owned(tlock, cthread);
}

static inline uint32_t
hw_lck_ticket_reserve_orig(hw_lck_ticket_t *lck)
{
	/*
	 * Atomically load both the entier lock state, and increment the
	 * "nticket". Wrap of the ticket field is OK as long as the total
	 * number of contending CPUs is < maximum ticket
	 */
	return os_atomic_add_orig(&lck->lck_value,
	           HW_LCK_TICKET_LOCK_INC_WORD, acquire);
}

__header_always_inline void
hw_lck_ticket_lock_internal(
	hw_lck_ticket_t        *lck
	LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_lck_ticket_t tmp;

	HW_LCK_TICKET_VERIFY(lck);
	tmp.lck_value = hw_lck_ticket_reserve_orig(lck);

	if (__probable(equal_tickets(tmp.cticket, tmp.nticket))) {
		return lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
	}

	/* Contention? branch to out of line contended block */
	struct hw_lck_ticket_reserve_arg arg = { .mt = tmp.nticket };
	(void)hw_lck_ticket_contended(lck, arg, &hw_lck_ticket_spin_policy
	    LCK_GRP_ARG(grp));
}

void
hw_lck_ticket_lock_nopreempt(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	hw_lck_ticket_lock_internal(lck LCK_GRP_ARG(grp));
}

void
hw_lck_ticket_lock(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	lock_disable_preemption_for_thread(current_thread());
	hw_lck_ticket_lock_internal(lck LCK_GRP_ARG(grp));
}

__header_always_inline hw_lock_status_t
hw_lck_ticket_lock_to_internal(
	hw_lck_ticket_t        *lck,
	hw_spin_policy_t        pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_lck_ticket_t tmp;

	HW_LCK_TICKET_VERIFY(lck);
	tmp.lck_value = hw_lck_ticket_reserve_orig(lck);

	if (__probable(equal_tickets(tmp.cticket, tmp.nticket))) {
		lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	/* Contention? branch to out of line contended block */
	struct hw_lck_ticket_reserve_arg arg = { .mt = tmp.nticket };
	return hw_lck_ticket_contended(lck, arg, pol LCK_GRP_ARG(grp));
}

hw_lock_status_t
hw_lck_ticket_lock_nopreempt_to(
	hw_lck_ticket_t        *lck,
	hw_spin_policy_t        pol,
	lck_grp_t              *grp)
{
	return hw_lck_ticket_lock_to_internal(lck, pol LCK_GRP_ARG(grp));
}

hw_lock_status_t
hw_lck_ticket_lock_to(
	hw_lck_ticket_t        *lck,
	hw_spin_policy_t        pol,
	lck_grp_t              *grp)
{
	lock_disable_preemption_for_thread(current_thread());
	return hw_lck_ticket_lock_to_internal(lck, pol LCK_GRP_ARG(grp));
}

__header_always_inline void
lck_ticket_lock_internal(lck_ticket_t *tlock, thread_t cthread, __unused lck_grp_t *grp)
{
	hw_lck_ticket_t tmp;

	LCK_TICKET_VERIFY(tlock);
	tmp.lck_value = hw_lck_ticket_reserve_orig(&tlock->tu);

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
	thread_t cthread = current_thread();

	lock_disable_preemption_for_thread(cthread);
	lck_ticket_lock_internal(tlock, cthread, grp);
}

void
lck_ticket_lock_nopreempt(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	thread_t cthread = current_thread();

	lck_ticket_lock_internal(tlock, cthread, grp);
}

__header_always_inline bool
hw_lck_ticket_lock_try_internal(
	hw_lck_ticket_t        *lck,
	bool                    nopreempt
	LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_lck_ticket_t olck, nlck;

	HW_LCK_TICKET_VERIFY(lck);
	if (!nopreempt) {
		lock_disable_preemption_for_thread(current_thread());
	}

	os_atomic_rmw_loop(&lck->tcurnext, olck.tcurnext, nlck.tcurnext, acquire, {
		if (__improbable(!equal_tickets(olck.cticket, olck.nticket))) {
		        os_atomic_rmw_loop_give_up({
				if (!nopreempt) {
				        lock_enable_preemption();
				}
				return false;
			});
		}
		nlck.cticket = olck.cticket;
		nlck.nticket = olck.nticket + HW_LCK_TICKET_LOCK_INCREMENT;
	});

	lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
	return true;
}

bool
hw_lck_ticket_lock_try(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	return hw_lck_ticket_lock_try_internal(lck, false LCK_GRP_ARG(grp));
}

bool
hw_lck_ticket_lock_try_nopreempt(hw_lck_ticket_t *lck, lck_grp_t *grp)
{
	return hw_lck_ticket_lock_try_internal(lck, true LCK_GRP_ARG(grp));
}

__header_always_inline bool
lck_ticket_lock_try_internal(lck_ticket_t *tlock, __unused lck_grp_t *grp, bool nopreempt)
{
	thread_t cthread = current_thread();
	hw_lck_ticket_t olck, nlck;

	LCK_TICKET_VERIFY(tlock);
	if (!nopreempt) {
		lock_disable_preemption_for_thread(cthread);
	}

	os_atomic_rmw_loop(&tlock->tu.tcurnext, olck.tcurnext, nlck.tcurnext, acquire, {
		if (__improbable(!equal_tickets(olck.cticket, olck.nticket))) {
		        os_atomic_rmw_loop_give_up({
				if (!nopreempt) {
				        lock_enable_preemption();
				}
				return false;
			});
		}
		nlck.cticket = olck.cticket;
		nlck.nticket = olck.nticket + HW_LCK_TICKET_LOCK_INCREMENT;
	});

	tlock_mark_owned(tlock, cthread);
	lck_grp_ticket_update_held(&tlock->tu LCK_GRP_ARG(grp));
	return true;
}

bool
lck_ticket_lock_try(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	return lck_ticket_lock_try_internal(tlock, grp, false);
}

bool
lck_ticket_lock_try_nopreempt(lck_ticket_t *tlock, __unused lck_grp_t *grp)
{
	return lck_ticket_lock_try_internal(tlock, grp, true);
}

/*
 * Assembly routine that
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

#if KASAN_TBI
extern hw_lck_ticket_t
hw_lck_ticket_reserve_orig_allow_invalid(hw_lck_ticket_t *lck, const uint8_t *tag_addr);
#else /* KASAN_TBI */
extern hw_lck_ticket_t
hw_lck_ticket_reserve_orig_allow_invalid(hw_lck_ticket_t *lck);
#endif /* KASAN_TBI */

bool
hw_lck_ticket_reserve_nopreempt(hw_lck_ticket_t *lck, uint32_t *ticket, lck_grp_t *grp)
{
	hw_lck_ticket_t tmp;

	HW_LCK_TICKET_VERIFY(lck);
	tmp.lck_value = *ticket = hw_lck_ticket_reserve_orig(lck);

	if (__probable(tmp.cticket == tmp.nticket)) {
		lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
		return true;
	}

	return false;
}

bool
hw_lck_ticket_reserve(hw_lck_ticket_t *lck, uint32_t *ticket, lck_grp_t *grp)
{
	lock_disable_preemption_for_thread(current_thread());

	return hw_lck_ticket_reserve_nopreempt(lck, ticket, grp);
}

hw_lock_status_t
hw_lck_ticket_reserve_allow_invalid(hw_lck_ticket_t *lck, uint32_t *ticket, lck_grp_t *grp)
{
	hw_lck_ticket_t tmp;

	lock_disable_preemption_for_thread(current_thread());

#if KASAN_TBI
	/* Expand the check to also include the tag value. See machine_routines_asm.s for the details */
	tmp = hw_lck_ticket_reserve_orig_allow_invalid(lck,
	    kasan_tbi_get_tag_address((vm_offset_t)lck));
#else /* KASAN_TBI */
	tmp = hw_lck_ticket_reserve_orig_allow_invalid(lck);
#endif /* KASAN_TBI */
	*ticket = tmp.lck_value;

	if (__improbable(!tmp.lck_valid)) {
		lock_enable_preemption();
		return HW_LOCK_INVALID;
	}

	if (__probable(equal_tickets(tmp.cticket, tmp.nticket))) {
		lck_grp_ticket_update_held(lck LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	return HW_LOCK_CONTENDED;
}

hw_lock_status_t
hw_lck_ticket_wait(
	hw_lck_ticket_t        *lck,
	uint32_t                ticket,
	hw_spin_policy_t        pol,
	lck_grp_t              *grp)
{
	hw_lck_ticket_t tmp = { .lck_value = ticket };
	struct hw_lck_ticket_reserve_arg arg = { .mt = tmp.nticket };

	if (pol == NULL) {
		pol = &hw_lck_ticket_spin_policy;
	}
	return hw_lck_ticket_contended(lck, arg, pol LCK_GRP_ARG(grp));
}

hw_lock_status_t
hw_lck_ticket_lock_allow_invalid(
	hw_lck_ticket_t        *lck,
	hw_spin_policy_t        pol,
	lck_grp_t              *grp)
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
		return hw_lck_ticket_contended(lck, arg, pol LCK_GRP_ARG(grp));
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
hw_lck_ticket_unlock_nopreempt(hw_lck_ticket_t *lck)
{
	HW_LCK_TICKET_VERIFY(lck);
	hw_lck_ticket_unlock_internal_nopreempt(lck);
}

void
hw_lck_ticket_unlock(hw_lck_ticket_t *lck)
{
	HW_LCK_TICKET_VERIFY(lck);
	hw_lck_ticket_unlock_internal(lck);
}

void
lck_ticket_unlock_nopreempt(lck_ticket_t *tlock)
{
	LCK_TICKET_VERIFY(tlock);
	LCK_TICKET_UNLOCK_VERIFY(tlock);
	os_atomic_store(&tlock->lck_ticket_owner, 0, relaxed);
	hw_lck_ticket_unlock_internal_nopreempt(&tlock->tu);
}

void
lck_ticket_unlock(lck_ticket_t *tlock)
{
	LCK_TICKET_VERIFY(tlock);
	LCK_TICKET_UNLOCK_VERIFY(tlock);
	os_atomic_store(&tlock->lck_ticket_owner, 0, relaxed);
	hw_lck_ticket_unlock_internal(&tlock->tu);
}

void
lck_ticket_assert_owned(lck_ticket_t *tlock)
{
	if (current_thread()->ctid != tlock->lck_ticket_owner) {
		__lck_ticket_not_owned_panic(tlock);
	}
}

void
lck_ticket_assert_not_owned(lck_ticket_t *tlock)
{
	if (current_thread()->ctid == tlock->lck_ticket_owner) {
		__lck_ticket_owned_panic(tlock);
	}
}
