/*
 * Copyright (c) 2021-2025 Apple Inc. All rights reserved.
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
#include <kern/locks_internal.h>
#include <kern/lock_rw.h>
#include <kern/lock_stat.h>
#include <kern/compact_id.h>
#include <kern/machine.h>
#include <kern/thread.h>

#include <sys/kdebug_kernel.h>

#include <machine/cpu_data.h>
#include <machine/machine_cpu.h>

#define lck_rw_t                lck_rw_new_t

__enum_closed_decl(lck_rw_mode_t, uint32_t, {
	LCK_RW_MODE_SLEEPABLE   = 0x00,
	LCK_RW_MODE_SPIN        = 0x01,
});

#if XNU_LCK_RW_DEFAULT_TO_NEW
KALLOC_TYPE_DEFINE(KT_LCK_RW, lck_rw_t, KT_PRIV_ACCT);
#endif /* !XNU_LCK_RW_DEFAULT_TO_NEW */

static_assert(offsetof(lck_rw_new_t, lck_rw_owner) == offsetof(lck_rw_new_t, lck_rw_owner));

#if MACH_ASSERT
#define LCK_RW_DBG_SLOT(arg)    , arg
#define LCK_RW_DBG_NO_SLOT      , NULL
#define LCK_RW_DBG_FMT          "caller:%#lx mode %c/%d"
#define LCK_RW_DBG_ARG(th, entry) \
	(vm_kernel_stext + (entry)->rwlde_caller_packed), \
	((entry)->rwlde_mode_count < 0 ? 'x' : 's'), \
	(entry)->rwlde_mode_count
#else
#define LCK_RW_DBG_SLOT(arg)
#define LCK_RW_DBG_NO_SLOT
#endif /* MACH_ASSERT */

/*
 * XNU reader writer locks
 * =======================
 *
 * Note: the algorithm comes with a formal specification
 *       in tools/tla/rwlock.tla
 *
 * Shared lock fastpath
 * --------------------
 *
 * The lock is designed so that the shared lock/unlock fastpaths use atomic
 * increment (ldadd on arm, xadd on Intel).
 *
 * In order to achieve this, taking the shared lock will pre-test
 * for the state of the lock to see whether this is ok to steal the lock,
 * and if the pre-test passes, the r_count field gets atomically incremented.
 * (See @c __lck_rw_try_lock_shared(), @c __lck_rw_lock_shared()).
 *
 * However, because this is not a proper compare-and-swap this is a racy
 * operation, which is why the value of r_count is ignored if the lock
 * is exclusively locked, so that readers to not have to rollback incorrect
 * attempts to lock.
 *
 * Exclusive unlockers will clear the field as part of their unlock.
 * (See @c __lck_rw_unlock_exclusive(), @c lck_rw_lock_exclusive_to_shared()).
 *
 *
 * Other fastpaths
 * ---------------
 *
 * The general design of this lock is that it will privilege threads on core
 * over ones that are on the wait queues. In order to achieve that, the lock
 * state is split so that the fastpath only looks at a single word containing:
 *
 * - u_wanted (an upgrader is waiting for readers to drain),
 * - x_locked (the lock is held exclusively),
 * - r_count  (the number of readers holding the lock if x_locked == false).
 *
 * While the reason for x_locked and r_count being part of the fast lock word
 * should be self explanatory, the reason for u_wanted is more subtle: there is
 * a general desire to have upgrade waiters disrupt the fastpath and be flushed
 * out as soon as possible, so that new upgraders have a chance at succeeding.
 *
 *
 * The other half of the lock contains information such as:
 * - x_tail (the exclusive adaptive spinners),
 * - shared/upgrade/exclusive waiter bits,
 * - lock configuration (x_bias).
 *
 *
 * Wait queue integration
 * ----------------------
 *
 * The reader writer lock uses 3 distinct events:
 * - WAITQ_TYPED_EVENT64(kThreadWaitKernelRWLockRead, lock) + 1 for readers,
 * - WAITQ_TYPED_EVENT64(kThreadWaitKernelRWLockWrite, lock) + 2 for writers,
 * - WAITQ_TYPED_EVENT64(kThreadWaitKernelRWLockUpgrade, lock) + 3 for the upgrader.
 *
 * Unlike the kernel mutex, this lock doesn't have an embedded interlock.
 * Instead, it abuses the lock of the wait queue for this event as an interlock.
 *
 * As a result, going to wait on a wait queue follows the following algorithm,
 * which can fail at the (2) step, in which case the thread behaves as if
 * it was woken up:
 *
 *   1. take the wait queue lock for the proper event,
 *   2. atomically try to set the proper shared/upgrade/exclusive waiter bit,
 *   3. if (2) succeeded, then assert_wait() and unlock the wait queue.
 *
 *
 * On the wakeup side, wait bits are being cleared under the wait queue lock,
 * which serializes with the (2) step of the going-to-block algorithm.
 *
 *
 * Wakeup strategies
 * -----------------
 *
 * While mutexes can afford a CAS on the unlock path, these are unacceptable
 * for rwlocks as it would cause large scalability issues for shared unlockers.
 * As a result, the unlock paths for both shared-unlock and exclusive-unlock
 * are atomic-add and atomic-and based respectively, and wakeups of waiters
 * are handled after the lock has been unconditionally unlocked.
 *
 * This causes a correctness challenge: as soon as the locks are dropped,
 * a thread can come in and destroy the lock, and it means that performing
 * wakeups and maintaining the "waiter bits" in the lock could possibly cause
 * use-after-frees.
 *
 * To solve this, XNU's rwlock implementation uses typed-events and
 * a combination of rules for which performing wakeups and updates are legal:
 *
 * 1. all lock acquiring, sleeping, upgrade, downgrade functions can rely
 *    on the caller being allowed to touch the lock, and as a result, it is
 *    always safe to perform lock status update in these functions.
 *
 * 2. while any form of lock (shared or exclusive) is held, it is also obviously
 *    allowed to update the lock.
 *
 * 3. In the unlock functions, if a thread was pulled from the wait queues
 *    using lck_rw_pull_thread_locked(), then it is legal to update the lock
 *    until lck_rw_resume_thread() has been called, because we borrow principle
 *    (1) for this thread.
 *
 * This is achieved using the waitq typed event (@see WAITQ_TYPED_EVENT64())
 * feature which lets us know that when we pull a thread out of the wait queue
 * for a given event, a reader-writer lock is present at this address, and
 * performing updates will not cause a type-confusion.
 *
 * *However* this could be a completely different new instance of a different
 * reader-writer lock. The reader-writer lock algorithm is resilient to spurious
 * wakeups and this strategy as a result doesn't cause correctness issues.
 */

#pragma mark lck_rw_t: helpers

static_assert(sizeof(lck_rw_word_t) == sizeof(uint64_t));

#define LCK_RW_FMT \
	"<%#08x %#02x[%c-bias,%s] o:%#x/%p %#06x bits:%c%c%c%c %c/%d>"

#define LCK_RW_FMT_ARG(lck, word) \
	(lck)->lck_rw_grp, \
	(lck)->lck_rw_type, \
	(lck)->lck_rw.x_bias ? 'x' : 's', \
	(lck)->lck_rw.no_sleep ? "no-sleep" : "sleepable", \
	(lck)->lck_rw_owner, \
	ctid_get_thread_unsafe((lck)->lck_rw_owner), \
        \
	(word).x_tail, \
	(word).s_waiters ? 's' : '-', \
	(word).u_wanted  ? 'u' : '-', \
	(word).x_waiters ? 'x' : '-', \
	(word).x_urgent  ? 'X' : '-', \
	(word).x_locked  ? 'x' : '-', \
	(word).r_count

#define LCK_RW_R_COUNT_INC      ((lck_rw_word_t){ .r_count   = 1 })
#define LCK_RW_S_WAITERS        ((lck_rw_word_t){ .s_waiters = true })
#define LCK_RW_U_WAITER         ((lck_rw_word_t){ .u_waiter  = true })
#define LCK_RW_X_WAITERS        ((lck_rw_word_t){ .x_waiters = true })
#define LCK_RW_X_URGENT         ((lck_rw_word_t){ .x_waiters = true, .x_urgent  = true })
#define LCK_RW_U_WANTED         ((lck_rw_word_t){ .u_wanted  = true })
#define LCK_RW_X_LOCKED         ((lck_rw_word_t){ .x_locked  = true })
#define LCK_RW_UNLOCKED         ((lck_rw_word_t){ })


static lck_rw_word_t
lck_rw_load_word(lck_rw_t *lck)
{
	return os_atomic_load(&lck->lck_rw, relaxed);
}

static void
lck_rw_set_owner(lck_rw_t *lck, compact_id_t ctid)
{
	os_atomic_store(&lck->lck_rw_owner, ctid, relaxed);
}

static void
lck_rw_clear_owner(lck_rw_t *lck, thread_t self)
{
	release_assert(lck->lck_rw_owner == self->ctid);
	lck_rw_set_owner(lck, 0);
}


__attribute__((always_inline))
static bool
lck_rw_lock_s_allowed(lck_rw_word_t word, bool pretest)
{
	lck_rw_word_t mask = {
		.x_tail   = -word.x_bias,
		.u_wanted = true,
		.x_locked = true,
	};

	/*
	 * allow to steal from x_waiters regardless of the configured bias:
	 * give priority to things on core, even if it biases toward reads.
	 */
	return (word.lock64 & mask.lock64) == 0 && (!pretest || word.valid);
}

__attribute__((always_inline))
static bool
lck_rw_lock_x_allowed(lck_rw_word_t word, bool pretest)
{
	lck_rw_word_t mask = {
		.x_tail   = -pretest,
		.u_wanted = true,
		.x_locked = true,
		.r_count  = ~0,
	};

	/*
	 * allow to steal from x_waiters regardless of the configured bias:
	 * give priority to things on core, even if it biases toward reads.
	 */
	return (word.lock64 & mask.lock64) == 0 && (!pretest || word.valid);
}

#define lck_rw_lock_u2x_allowed(word)   ((word).lock32 == LCK_RW_U_WANTED.lock32)

__attribute__((always_inline))
static bool
lck_rw_lock_cas32(lck_rw_t *lck, lck_rw_word_t from, lck_rw_word_t to, bool pretest)
{
	if (pretest) {
		return lock_cmpxchg(&lck->lck_rw.lock32, from.lock32, to.lock32, acquire);
	}
	return os_atomic_cmpxchg(&lck->lck_rw.lock32, from.lock32, to.lock32, acquire);
}

__attribute__((always_inline))
static bool
lck_rw_lock_s_try(lck_rw_t *lck, bool pretest)
{
	lck_rw_word_t word;
	bool success = false;

	if (!pretest || lck_rw_lock_s_allowed(lck_rw_load_word(lck), pretest)) {
#if __arm64__ && __ARM_ARCH_8_3__
		/*
		 * os_atomic_add(acquire) compiles down to ldadda which has
		 * LoadAcquire semantics, which in particular enforces that this
		 * is totally ordered with any StoreRelease that preceded.
		 *
		 * This is stronger than the minimum requirements mandated by
		 * the C/C++11 memory models. Fortunately, armv8.3+ has
		 * the LoadAcquirePC semantics (provided by the ldapr family
		 * of instructions) which gives us precisely what we need
		 * and allows for more reodering.
		 *
		 * Given the density of rwlocks in the VM code, this small
		 * optimization gives us an edge in performance.
		 *
		 * In theory we should be allowed to perform this optimization
		 * on any lock-acquire the kernel does. However, this would mean
		 * that mutations performed under two consecutive lock holds of
		 * different locks can now be observed out of order, and the
		 * likelyhood that someone relies on that is so high that it
		 * sounds like a recipe for disaster.
		 *
		 * Doing it for shared lock holds is much less dangerous since
		 * no non atomic mutation should happen under a read critical
		 * section.
		 */
		word.lock64 = os_atomic_add(&lck->lck_rw.lock64,
		    LCK_RW_R_COUNT_INC.lock64, relaxed);
		os_atomic_load(&lck->lck_rw.lock64, acquire);
#else
		word.lock64 = os_atomic_add(&lck->lck_rw.lock64,
		    LCK_RW_R_COUNT_INC.lock64, acquire);
#endif
		success = !word.x_locked;
	}

	return success;
}
#define lck_rw_lock_s_try(...)          __probable(lck_rw_lock_s_try(__VA_ARGS__))

__attribute__((always_inline))
static bool
lck_rw_lock_x_try(lck_rw_t *lck, bool pretest)
{
	uint32_t from = LCK_RW_UNLOCKED.lock32;
	uint32_t to   = LCK_RW_X_LOCKED.lock32;

	return (!pretest || lck_rw_lock_x_allowed(lck_rw_load_word(lck), pretest)) &&
	       os_atomic_cmpxchg(&lck->lck_rw.lock32, from, to, acquire);
}
#define lck_rw_lock_x_try(...)          __probable(lck_rw_lock_x_try(__VA_ARGS__))

#define lck_rw_lock_s2x_try(lck, pretest) \
	__probable(lck_rw_lock_cas32(lck, LCK_RW_R_COUNT_INC, LCK_RW_X_LOCKED, pretest))

#define lck_rw_lock_u2x_try(lck) \
	__probable(lck_rw_lock_cas32(lck, LCK_RW_U_WANTED, LCK_RW_X_LOCKED, false))

#define lck_rw_clear(lck, mask, mo) \
	os_atomic_andnot_orig(&(lck)->lck_rw.lock64, mask.lock64, mo)

__attribute__((always_inline))
static void
lck_rw_lock_will_acquire(lck_rw_t *lck, thread_t self, lck_rw_mode_t mode)
{
	if (mode == LCK_RW_MODE_SPIN) {
		lock_disable_preemption_for_thread(self);
	} else {
		lck_rw_lock_count_inc(self, lck);
	}
}

__attribute__((always_inline))
static void
lck_rw_lock_was_released(lck_rw_t *lck, thread_t self, lck_rw_mode_t mode)
{
	if (mode == LCK_RW_MODE_SPIN) {
		lock_enable_preemption();
	} else {
		lck_rw_lock_count_dec(self, lck);
	}
}


#pragma mark lck_rw_t: validation

__abortlike
static void
__lck_rw_invalid_panic(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	panic("Invalid/destroyed RWLock %p: " LCK_RW_FMT,
	    lck, LCK_RW_FMT_ARG(lck, word));
}

__abortlike
static void
__lck_rw_no_sleep_panic(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	panic("No-sleep RWLock %p passed to a sleepable call: " LCK_RW_FMT,
	    lck, LCK_RW_FMT_ARG(lck, word));
}

__abortlike
static void
__lck_rw_has_waiters_panics(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	panic("RWLock %p still has waiters: " LCK_RW_FMT,
	    lck, LCK_RW_FMT_ARG(lck, word));
}

__abortlike
static void
__lck_rw_not_owned_panic(
	lck_rw_t               *lck,
	lck_rw_word_t           word,
	lck_rw_type_t           type
	LCK_RW_DBG_SLOT(struct rw_lock_debug_entry *entry))
{
	thread_t self = current_thread();
	const char *how = type == LCK_RW_TYPE_EXCLUSIVE ? "exclusive" : "shared";

#if MACH_ASSERT
	if (entry) {
		panic("RWLock %p ("LCK_RW_FMT")"
		    " is not held %s by thread %p"
		    " ("LCK_RW_DBG_FMT")",
		    lck, LCK_RW_FMT_ARG(lck, word), how,
		    self, LCK_RW_DBG_ARG(self, entry));
	}
#endif /* MACH_ASSERT */

	panic("RWLock %p ("LCK_RW_FMT") is not held %s by thread %p",
	    lck, LCK_RW_FMT_ARG(lck, word), how, self);
}

__abortlike
static void
__lck_rw_owned_panic(
	lck_rw_t               *lck,
	thread_t                self
	LCK_RW_DBG_SLOT(struct rw_lock_debug_entry *entry))
{
	lck_rw_word_t word = lck_rw_load_word(lck);
	const char *how = word.x_locked ? "exclusive" : "shared";

#if MACH_ASSERT
	if (entry) {
		panic("RWLock %p ("LCK_RW_FMT")"
		    " is unexpectedly held %s by thread %p"
		    " ("LCK_RW_DBG_FMT")",
		    lck, LCK_RW_FMT_ARG(lck, word), how,
		    self, LCK_RW_DBG_ARG(self, entry));
	}
#endif /* MACH_ASSERT */

	panic("RWLock %p ("LCK_RW_FMT") is unexpectedly held %s by thread %p",
	    lck, LCK_RW_FMT_ARG(lck, word), how, self);
}


__abortlike
static void
__lck_rw_held_panic(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);
	const char *how = word.x_locked ? "exclusive" : "shared";

	panic("RWLock %p ("LCK_RW_FMT") is unexpectedly held %s",
	    lck, LCK_RW_FMT_ARG(lck, word), how);
}


#pragma mark lck_rw_t: debug
#if CONFIG_DTRACE

#define LCK_RW_SNIFF_DTRACE()           lck_debug_state.lds_value

static inline enum lockstat_probe_id
__lck_rw_block_probe_id(block_hint_t hint)
{
	if (hint == kThreadWaitKernelRWLockRead) {
		return LS_LCK_RW_LOCK_SHARED_BLOCK;
	}
	return LS_LCK_RW_LOCK_EXCL_BLOCK;
}

static inline enum lockstat_probe_id
__lck_rw_spin_probe_id(block_hint_t hint)
{
	if (hint == kThreadWaitKernelRWLockRead) {
		return LS_LCK_RW_LOCK_SHARED_SPIN;
	}
	return LS_LCK_RW_LOCK_EXCL_SPIN;
}

#define LCK_RW_BLOCK_BEGIN(lck, hint) \
	lck_time_stat_begin(__lck_rw_block_probe_id(hint))

#define LCK_RW_BLOCK_END(lck, hint, start) \
	lck_time_stat_record(__lck_rw_block_probe_id(hint), \
	    lck, lck->lck_rw_grp, start);

#define LCK_RW_SPIN_END(lck, hint, start) \
	lck_time_stat_record(__lck_rw_spin_probe_id(hint), \
	    lck, lck->lck_rw_grp, start);

#else

#define LCK_RW_SNIFF_DTRACE()           0
#define LCK_RW_BLOCK_BEGIN(lck, hint)   ({ (void)(hint); 0ull; })
#define LCK_RW_BLOCK_END(a, b, start)   ((void)(start))
#define LCK_RW_SPIN_END(a, b, start)    ((void)(hint))

#endif /* !CONFIG_DTRACE */
#if MACH_ASSERT

/*
 * Best effort mechanism to debug rw_locks.
 *
 * This mechanism is in addition to the owner checks. The owner is set
 * only when the lock is held in exclusive mode so the checks do not cover
 * the cases in which the lock is held in shared mode.
 *
 * This mechanism tentatively stores the rw_lock acquired and its debug
 * information on the thread struct.
 * Just up to LCK_RW_EXPECTED_MAX_NUMBER rw lock debug information can be stored.
 *
 * NOTE: LCK_RW_EXPECTED_MAX_NUMBER is the expected number of rw_locks held
 * at the same time. If a thread holds more than this number of rw_locks we
 * will start losing debug information.
 * Increasing LCK_RW_EXPECTED_MAX_NUMBER will increase the probability we will
 * store the debug information but it will require more memory per thread
 * and longer lock/unlock time.
 *
 * If an empty slot is found for the debug information, we record the lock
 * otherwise we set the overflow threshold flag.
 *
 * If we reached the overflow threshold we might stop asserting because we cannot be sure
 * anymore if the lock was acquired or not.
 *
 * Even if we reached the overflow threshold, we try to store the debug information
 * for the new locks acquired. This can be useful in core dumps to debug
 * possible return to userspace without unlocking and to find possible readers
 * holding the lock.
 */

static TUNABLE(bool, lck_rw_recursive_shared_assert_74048094,
    "lck_rw_recursive_shared_assert", false);

_Static_assert(LCK_RW_EXPECTED_MAX_NUMBER <= 127, "LCK_RW_EXPECTED_MAX_NUMBER bigger than rwld_locks_saved");

#define LCK_RW_OLD_FMT "<%#08x o:%p>"
#define LCK_RW_OLD_FMT_ARG(lck) \
	((lck_rw_old_t *)(lck))->lck_rw_data, \
	ctid_get_thread_unsafe(((lck_rw_old_t *)(lck))->lck_rw_owner)

__abortlike
static void
__lck_rw_old_owned_panic(
	lck_rw_t               *lck
	LCK_RW_DBG_SLOT(struct rw_lock_debug_entry *entry))
{
	thread_t self = current_thread();
#if MACH_ASSERT
	if (entry) {
		panic("RW lock %p ("LCK_RW_OLD_FMT")"
		    " is unexpectedly held by thread %p"
		    " ("LCK_RW_DBG_FMT")",
		    lck, LCK_RW_OLD_FMT_ARG(lck),
		    self, LCK_RW_DBG_ARG(self, entry));
	}
#endif /* MACH_ASSERT */

	panic("RW lock %p ("LCK_RW_OLD_FMT") is unexpectedly held by thread %p",
	    lck, LCK_RW_OLD_FMT_ARG(lck), self);
}

__abortlike
static void
__lck_rw_old_not_owned_panic(
	lck_rw_old_t           *lck,
	lck_rw_type_t           type,
	struct rw_lock_debug_entry *entry)
{
	thread_t self = current_thread();
	const char *how = type == LCK_RW_TYPE_EXCLUSIVE ? "exclusive" : "shared";

	if (entry) {
		panic("RWLock %p ("LCK_RW_OLD_FMT")"
		    " is not held %s by thread %p"
		    " ("LCK_RW_DBG_FMT")",
		    lck, LCK_RW_OLD_FMT_ARG(lck), how,
		    self, LCK_RW_DBG_ARG(self, entry));
	}

	panic("RWLock %p ("LCK_RW_OLD_FMT") is not held %s by thread %p",
	    lck, LCK_RW_OLD_FMT_ARG(lck), how, self);
}

static inline struct rw_lock_debug_entry *
find_lock_in_savedlocks(void *lock, rw_lock_debug_t rw_locks_held)
{
	int i;
	for (i = 0; i < LCK_RW_EXPECTED_MAX_NUMBER; i++) {
		struct rw_lock_debug_entry *existing = &rw_locks_held->rwld_locks[i];
		if (existing->rwlde_lock == lock) {
			return existing;
		}
	}

	return NULL;
}

static inline struct rw_lock_debug_entry *
find_empty_slot(rw_lock_debug_t rw_locks_held)
{
	int i;
	for (i = 0; i < LCK_RW_EXPECTED_MAX_NUMBER; i++) {
		struct rw_lock_debug_entry *entry = &rw_locks_held->rwld_locks[i];
		if (entry->rwlde_lock == NULL) {
			return entry;
		}
	}
	return NULL;
}

static void
set_rwlde_caller_packed(struct rw_lock_debug_entry *entry, uintptr_t caller)
{
	caller = (vm_offset_t)ptrauth_strip((void *)caller, ptrauth_key_function_pointer);
	entry->rwlde_caller_packed = (int32_t)(caller - vm_kernel_stext);
}

static inline bool
lck_rw_dbg_is_new(lck_rw_t *lck)
{
	return lck->lck_rw_type == LCK_TYPE_RW;
}

static inline bool
allow_recursive_shared_locking(void *lck)
{
	if (lck_rw_recursive_shared_assert_74048094) {
		if (lck_rw_dbg_is_new(lck)) {
			return !((lck_rw_t *)lck)->lck_rw.x_bias;
		}
		return !((lck_rw_old_t *)lck)->lck_rw.priv_excl;
	}
	/*
	 * currently rw_lock_shared is called recursively,
	 * until the code is fixed allow to lock
	 * recursively in shared mode
	 */
	return true;
}

__attribute__((noinline))
void
lck_rw_dbg_assert_canlock_slow(void *lock, lck_rw_type_t type)
{
	thread_t        self = current_thread();
	rw_lock_debug_t rw_locks_held = &self->rw_lock_held;

	if (__probable(rw_locks_held->rwld_locks_acquired == 0)) {
		//no locks saved, safe to lock
		return;
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__improbable(entry != NULL)) {
		if ((type == LCK_RW_TYPE_SHARED) && allow_recursive_shared_locking(lock) && entry->rwlde_mode_count >= 1) {
			return;
		}
		if (lck_rw_dbg_is_new(lock)) {
			__lck_rw_owned_panic(lock, self, entry);
		} else {
			__lck_rw_old_owned_panic(lock, entry);
		}
	}
}

__attribute__((noinline))
void
lck_rw_dbg_assert_held_slow(void *lock, lck_rw_type_t type)
{
	thread_t        self = current_thread();
	rw_lock_debug_t rw_locks_held = &self->rw_lock_held;

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__probable(entry != NULL)) {
		if ((type != LCK_RW_TYPE_SHARED && entry->rwlde_mode_count == -1) ||
		    (type != LCK_RW_TYPE_EXCLUSIVE && entry->rwlde_mode_count > 0)) {
			return;
		}
	} else if (rw_locks_held->rwld_overflow) {
		return;
	}

	if (lck_rw_dbg_is_new(lock)) {
		__lck_rw_not_owned_panic(lock, lck_rw_load_word(lock), type, entry);
	} else {
		__lck_rw_old_not_owned_panic(lock, type, entry);
	}
}

__attribute__((noinline))
void
lck_rw_dbg_add_slow(void *lock, lck_rw_type_t type, uintptr_t caller)
{
	thread_t        self = current_thread();
	rw_lock_debug_t rw_locks_held = &self->rw_lock_held;

	if (os_add_overflow(rw_locks_held->rwld_locks_acquired, 1,
	    &rw_locks_held->rwld_locks_acquired)) {
		panic("RWLock too many locks held, for thread %p", self);
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (entry == NULL) {
		entry = find_empty_slot(rw_locks_held);
		if (__improbable(entry == NULL)) {
			//array is full
			rw_locks_held->rwld_overflow = 1;
			return;
		}

		entry->rwlde_lock = lock;
		set_rwlde_caller_packed(entry, caller);
		if (type == LCK_RW_TYPE_EXCLUSIVE) {
			entry->rwlde_mode_count = -1;
		} else {
			entry->rwlde_mode_count = 1;
		}
		rw_locks_held->rwld_locks_saved++;
		return;
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE || entry->rwlde_mode_count < 0 ||
	    !allow_recursive_shared_locking(lock)) {
		if (lck_rw_dbg_is_new(lock)) {
			__lck_rw_owned_panic(lock, self, entry);
		} else {
			__lck_rw_old_owned_panic(lock, entry);
		}
	}

	if (os_add_overflow(entry->rwlde_mode_count, 1, &entry->rwlde_mode_count)) {
		panic("RWLock %p ("LCK_RW_OLD_FMT")"
		    " locked shared recursively by %p too many times"
		    " ("LCK_RW_DBG_FMT")",
		    lock, LCK_RW_OLD_FMT_ARG(lock), self,
		    LCK_RW_DBG_ARG(self, entry));
	}
}

__attribute__((noinline))
void
lck_rw_dbg_modify_slow(void *lock, lck_rw_type_t typeFrom, uintptr_t caller)
{
	thread_t        self = current_thread();
	rw_lock_debug_t rw_locks_held = &self->rw_lock_held;

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__probable(entry != NULL)) {
		if (typeFrom == LCK_RW_TYPE_SHARED) {
			//We are upgrading
			if (entry->rwlde_mode_count != 1) {
				if (lck_rw_dbg_is_new(lock)) {
					__lck_rw_not_owned_panic(lock,
					    lck_rw_load_word(lock), typeFrom, entry);
				} else {
					__lck_rw_old_not_owned_panic(lock, typeFrom, entry);
				}
			}
			entry->rwlde_mode_count = -1;
			set_rwlde_caller_packed(entry, caller);
		} else {
			//We are downgrading
			if (entry->rwlde_mode_count != -1) {
				if (lck_rw_dbg_is_new(lock)) {
					__lck_rw_not_owned_panic(lock,
					    lck_rw_load_word(lock), typeFrom, entry);
				} else {
					__lck_rw_old_not_owned_panic(lock, typeFrom, entry);
				}
			}
			entry->rwlde_mode_count = 1;
			set_rwlde_caller_packed(entry, caller);
		}
		return;
	}

	if (rw_locks_held->rwld_overflow == 0) {
		if (lck_rw_dbg_is_new(lock)) {
			__lck_rw_not_owned_panic(lock,
			    lck_rw_load_word(lock), typeFrom, entry);
		} else {
			__lck_rw_old_not_owned_panic(lock, typeFrom, entry);
		}
	}

	if (rw_locks_held->rwld_locks_saved == LCK_RW_EXPECTED_MAX_NUMBER) {
		//array is full
		return;
	}

	struct rw_lock_debug_entry *null_entry = find_empty_slot(rw_locks_held);
	null_entry->rwlde_lock = lock;
	set_rwlde_caller_packed(null_entry, caller);
	if (typeFrom == LCK_RW_TYPE_SHARED) {
		null_entry->rwlde_mode_count = -1;
	} else {
		null_entry->rwlde_mode_count = 1;
	}
	rw_locks_held->rwld_locks_saved++;
}

__attribute__((noinline))
void
lck_rw_dbg_remove_slow(void *lock, lck_rw_type_t type)
{
	thread_t        self = current_thread();
	rw_lock_debug_t rw_locks_held = &self->rw_lock_held;

	if (os_sub_overflow(rw_locks_held->rwld_locks_acquired, 1,
	    &rw_locks_held->rwld_locks_acquired)) {
		panic("RWLock too many unlocks, for thread %p", self);
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__probable(entry != NULL)) {
		if (type != LCK_RW_TYPE_EXCLUSIVE && entry->rwlde_mode_count > 1) {
			entry->rwlde_mode_count--;
			goto out;
		}

		if ((type != LCK_RW_TYPE_SHARED && entry->rwlde_mode_count == -1) ||
		    (type != LCK_RW_TYPE_EXCLUSIVE && entry->rwlde_mode_count == 1)) {
			entry->rwlde_mode_count = 0;
			entry->rwlde_caller_packed = 0;
			entry->rwlde_lock = NULL;
			rw_locks_held->rwld_locks_saved--;
			goto out;
		}
	} else if (rw_locks_held->rwld_overflow) {
		goto out;
	}

	if (lck_rw_dbg_is_new(lock)) {
		__lck_rw_not_owned_panic(lock, lck_rw_load_word(lock), type, entry);
	} else {
		__lck_rw_old_not_owned_panic(lock, type, entry);
	}

out:
	if (rw_locks_held->rwld_locks_acquired == 0) {
		rw_locks_held->rwld_overflow = 0;
	}
}

static inline void
lck_rw_check_preemption(lck_rw_t *lck, thread_t self, lck_rw_mode_t mode)
{
	uint32_t expected = (mode == LCK_RW_MODE_SPIN);

	if (lck->lck_rw.no_sleep) {
		if (preemption_enabled()) {
			panic("Attempt to take no-sleep RWLock %p with preemption enabled", lck);
		}
		return;
	}

	if (ml_at_interrupt_context()) {
		panic("Attempt to take RWLock %p in IRQ context", lck);
	}
	if (lock_preemption_level_for_thread(self) == expected) {
		(void)self;
		return;
	}
	if (current_cpu_datap()->cpu_hibernate) {
		return;
	}
	if (startup_phase < STARTUP_SUB_EARLY_BOOT) {
		return;
	}
#if CONFIG_SPTM
	/*
	 * If a panic has been initiated on SPTM devices, preemption was
	 * disabled by sleh, but platform callbacks could be acquiring rwlocks.
	 */
	extern const bool *sptm_xnu_triggered_panic_ptr;
	if (*sptm_xnu_triggered_panic_ptr) {
		return;
	}
#endif
	panic("Attempt to take RWLock %p with preemption disabled (%d)",
	    lck, get_preemption_level() - expected);
}

#define LCK_RW_DBG_CALLER \
	, ptrauth_nop_cast(uintptr_t, __builtin_return_address(0))
#define LCK_RW_DBG_CALLER_ARG \
	, uintptr_t caller
#else

#define lck_rw_check_preemption(lck, th, mode)     ((void)0)

#define LCK_RW_DBG_CALLER
#define LCK_RW_DBG_CALLER_ARG
#endif /* MACH_ASSERT */
#pragma mark lck_rw_t: alloc/init/destroy/free
#if XNU_LCK_RW_DEFAULT_TO_NEW

lck_rw_t *
lck_rw_alloc_init(lck_grp_t *grp, lck_attr_t *attr)
{
	lck_rw_t *lck;

	lck = zalloc_flags(KT_LCK_RW, Z_WAITOK | Z_ZERO);
	lck_rw_init(lck, grp, attr);
	return lck;
}

void
lck_rw_free(lck_rw_t *lck, lck_grp_t *grp)
{
	lck_rw_destroy(lck, grp);
	zfree(KT_LCK_RW, lck);
}

#endif /* XNU_LCK_RW_DEFAULT_TO_NEW */

__lck_rw_new_func
void
lck_rw_init(lck_rw_t *lck, lck_grp_t *grp, lck_attr_t *attrp)
{
	/* keep this so that the lck_type_t type is referenced for lldb */
	lck_type_t type = LCK_TYPE_RW;
	uint32_t   attr = (attrp ?: &lck_attr_default)->lck_attr_val;

	*lck = (lck_rw_t){
		.lck_rw_grp      = grp->lck_grp_attr_id,
		.lck_rw_type     = type,
		.lck_rw.valid    = true,
		.lck_rw.x_bias   = !(attr & LCK_ATTR_RW_SHARED_PRIORITY),
		.lck_rw.no_sleep = (bool)(attr & LCK_ATTR_RW_NO_SLEEP),
	};

	lck_grp_reference(grp, &grp->lck_grp_rwcnt);
}

__lck_rw_new_func
void
lck_rw_destroy(lck_rw_t *lck, lck_grp_t *grp)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	if (lck->lck_rw_type != LCK_TYPE_RW || !word.valid) {
		__lck_rw_invalid_panic(lck);
	}

	word.config8 = 0;
	if (word.lock64) {
		__lck_rw_has_waiters_panics(lck);
	}
	LCK_GRP_ASSERT_ID(grp, lck->lck_rw_grp);
	lck_grp_deallocate(grp, &grp->lck_grp_rwcnt);
	*lck = (lck_rw_t){ };
}


#pragma mark lck_rw_t: slowpaths (dtrace/debug)
#if CONFIG_DTRACE || MACH_ASSERT

__attribute__((noinline))
static void
lck_rw_lock_s_slow(lck_rw_t *lck, lck_rw_mode_t mode LCK_RW_DBG_CALLER_ARG)
{
#if MACH_ASSERT
	if (lck_rw_assert_enabled()) {
		lck_rw_check_preemption(lck, current_thread(), mode);
		lck_rw_dbg_add_slow(lck, LCK_RW_TYPE_SHARED, caller);
	}
#else
	(void)mode;
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lck, DTRACE_RW_SHARED);
#endif /* CONFIG_DTRACE */
}

__attribute__((noinline))
static void
lck_rw_try_lock_s_slow(lck_rw_t *lck LCK_RW_DBG_CALLER_ARG)
{
#if MACH_ASSERT
	if (lck_rw_assert_enabled()) {
		lck_rw_dbg_add_slow(lck, LCK_RW_TYPE_SHARED, caller);
	}
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lck, DTRACE_RW_SHARED);
#endif /* CONFIG_DTRACE */
}

__attribute__((noinline))
static void
lck_rw_unlock_s_slow(lck_rw_t *lck)
{
#if MACH_ASSERT
	if (lck_rw_assert_enabled()) {
		lck_rw_dbg_remove_slow(lck, LCK_RW_TYPE_SHARED);
	}
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, DTRACE_RW_SHARED);
#endif
}

__attribute__((noinline))
static void
lck_rw_lock_s2x_success_slow(lck_rw_t *lck, lck_rw_mode_t mode LCK_RW_DBG_CALLER_ARG)
{
#if MACH_ASSERT
	if (lck_rw_assert_enabled()) {
		lck_rw_check_preemption(lck, current_thread(), mode);
		lck_rw_dbg_modify_slow(lck, LCK_RW_TYPE_SHARED, caller);
	}
#else
	(void)mode;
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lck, true);
#endif
}

__attribute__((noinline))
static void
lck_rw_lock_x_slow(lck_rw_t *lck, lck_rw_mode_t mode LCK_RW_DBG_CALLER_ARG)
{
#if MACH_ASSERT
	if (lck_rw_assert_enabled()) {
		lck_rw_check_preemption(lck, current_thread(), mode);
		lck_rw_dbg_add_slow(lck, LCK_RW_TYPE_EXCLUSIVE, caller);
	}
#else
	(void)mode;
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lck, DTRACE_RW_EXCL);
#endif /* CONFIG_DTRACE */
}

__attribute__((noinline))
static void
lck_rw_try_lock_x_slow(lck_rw_t *lck LCK_RW_DBG_CALLER_ARG)
{
#if MACH_ASSERT
	lck_rw_dbg_add(lck, LCK_RW_TYPE_EXCLUSIVE, caller);
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lck, DTRACE_RW_EXCL);
#endif /* CONFIG_DTRACE */
}

__attribute__((noinline))
static void
lck_rw_unlock_x_slow(lck_rw_t *lck)
{
#if MACH_ASSERT
	if (lck_rw_assert_enabled()) {
		lck_rw_dbg_remove_slow(lck, LCK_RW_TYPE_EXCLUSIVE);
	}
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, DTRACE_RW_EXCL);
#endif /* CONFIG_DTRACE */
}

__attribute__((noinline))
static void
lck_rw_lock_x2s_slow(lck_rw_t *lck LCK_RW_DBG_CALLER_ARG)
{
#if MACH_ASSERT
	lck_rw_dbg_modify(lck, LCK_RW_TYPE_EXCLUSIVE, caller);
#endif /* MACH_ASSERT */
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck,
	    DTRACE_RW_NOFLAG);
#endif
}

#define LCK_RW_SLOWPATH(call, lck, ...)  ({ \
	if (__improbable(LCK_RW_SNIFF_DTRACE() || lck_rw_assert_enabled())) {   \
	        call(lck, ##__VA_ARGS__);                                       \
	}                                                                       \
})

#else

#define LCK_RW_SLOWPATH(...)            ((void)0)

#endif
#pragma mark lck_rw_t: waitq integration

__enum_decl(lck_rw_wait_t, int, {
	LCK_RW_WAIT_SUCCESS,
	LCK_RW_WAIT_BLOCK,
	LCK_RW_WAIT_BACKOFF,
});

static hw_spin_timeout_status_t
lck_rw_lock_timeout_panic(void *_lck, hw_spin_timeout_t to, hw_spin_state_t st)
{
	lck_rw_t     *lck   = _lck;
	lck_rw_word_t word = lck_rw_load_word(lck);

	panic("RWLock[%p] " HW_SPIN_TIMEOUT_FMT "; " LCK_RW_FMT ", "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lck, HW_SPIN_TIMEOUT_ARG(to, st), LCK_RW_FMT_ARG(lck, word),
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy lck_rw_timeout_policy = {
	.hwsp_name              = "lck_rw_t (adaptive spin)",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = lck_rw_lock_timeout_panic,
};

static event64_t
lck_rw_event64(lck_rw_t *lck, block_hint_t hint)
{
	static_assert(kThreadWaitKernelRWLockRead + 1 == kThreadWaitKernelRWLockWrite);
	static_assert(kThreadWaitKernelRWLockRead + 2 == kThreadWaitKernelRWLockUpgrade);
	uint64_t delta = hint + 1 - kThreadWaitKernelRWLockRead;

	return WAITQ_TYPED_EVENT64(hint, lck) + delta;
}

__header_always_inline lck_rw_t *
lck_rw_from_event64(event64_t event)
{
	return (lck_rw_t *)(waitq_untyped_event(event) & ~7ull);
}

__header_always_inline thread_t
lck_rw_pull_thread_locked(waitq_t waitq, event64_t event, bool *has_more)
{
	waitq_wakeup_flags_t flags = WAITQ_KEEP_LOCKED;

	if (has_more) {
		flags |= WAITQ_CHECK_HAS_MORE;
	}
	return waitq_wakeup64_identify_locked(waitq, event, flags, has_more);
}

__header_always_inline void
lck_rw_resume_thread(waitq_t waitq, thread_t thread)
{
	if (thread) {
		waitq_resume_identified_thread(waitq, thread,
		    THREAD_AWAKENED, WAITQ_WAKEUP_DEFAULT);
	}
}

static void
lck_rw_wakeup_x(lck_rw_t *lck, lck_rw_word_t word)
{
	event64_t     event   = lck_rw_event64(lck, kThreadWaitKernelRWLockWrite);
	struct waitq *waitq   = global_eventq(event);
	thread_t      thread1 = THREAD_NULL;
	thread_t      thread2 = THREAD_NULL;
	spl_t         spl;

	/*
	 * The point of waking up 2 waiters is a little subtle.
	 *
	 * Write lock holders tend to be short (or should be) and sending two
	 * to compete is probably not getting the loser back to sleep, as
	 * a result we do twice as few wait queue operations than the naive
	 * algorithm of one at a time.
	 *
	 * If we could wake up a second one, ask the wait queue if there's
	 * a third thread still on the queue (but do not dequeue it) so that we
	 * can clear the waiter bit eagerly.
	 */

	spl = splsched();
	waitq_lock(waitq);

	thread1 = lck_rw_pull_thread_locked(waitq, event, NULL);

	if (thread1) {
		bool more = false;

		if (!word.x_urgent) {
			thread2 = lck_rw_pull_thread_locked(waitq, event, &more);
		}
		if (!more) {
			lck_rw_clear(lck, LCK_RW_X_URGENT, relaxed);
		}
	}

	if (thread1 && word.x_urgent) {
		waitq_wakeup64_all_locked(waitq, event, THREAD_AWAKENED,
		    WAITQ_UNLOCK | waitq_flags_splx(spl));
	} else {
		waitq_unlock(waitq);
		splx(spl);
	}

	lck_rw_resume_thread(waitq, thread1);
	lck_rw_resume_thread(waitq, thread2);
}

static void
lck_rw_wakeup_s(lck_rw_t *lck)
{
	event64_t     event   = lck_rw_event64(lck, kThreadWaitKernelRWLockRead);
	struct waitq *waitq   = global_eventq(event);
	thread_t      thread  = THREAD_NULL;
	spl_t         spl;

	spl = splsched();
	waitq_lock(waitq);

	thread = lck_rw_pull_thread_locked(waitq, event, NULL);

	if (thread) {
		lck_rw_clear(lck, LCK_RW_S_WAITERS, relaxed);
	}

	waitq_wakeup64_all_locked(waitq, event, THREAD_AWAKENED,
	    WAITQ_UNLOCK | waitq_flags_splx(spl));

	lck_rw_resume_thread(waitq, thread);
}

static void
lck_rw_wakeup_u(lck_rw_t *lck)
{
	event64_t     event = lck_rw_event64(lck, kThreadWaitKernelRWLockUpgrade);
	struct waitq *waitq = global_eventq(event);
	thread_t      thread;
	spl_t         spl;

	spl = splsched();
	waitq_lock(waitq);

	thread = lck_rw_pull_thread_locked(waitq, event, NULL);

	if (thread) {
		lck_rw_clear(lck, LCK_RW_U_WAITER, relaxed);
	}

	waitq_unlock(waitq);
	splx(spl);

	lck_rw_resume_thread(waitq, thread);
}

/*!
 * @brief
 * perform wakeups after an unlock operation.
 *
 * @discussion
 * This function is called on a lock that might be destroyed already
 * (see headerdoc at the top of the file).
 *
 * All waiter bits are "precise" (when the bit is set, there is always at least
 * one thread to wake up for either of the u_waiter, s_waiters or x_waiters
 * bits.
 *
 * However, because several threads might observe these bits and decide to take
 * action on them, it is possible that by the time the upgrade/shared/exclusive
 * wakeup function is hit no thread is found on the wait queue. It means that
 * some other thread won the race to handle the bit, and that it is safe to
 * return and do nothing.
 *
 * As a result, the lck_rw_wakeup_[usx] functions have the same pattern
 * of trying to pull a thread out of the wait queue, and update the waiter
 * bits if and only if a thread was actually pulled.
 */
__attribute__((cold, noinline))
static void
lck_rw_wakeup(lck_rw_t *lck, lck_rw_word_t word)
{
	/*
	 * Upgraders always win, and prevent any other wakeups.
	 */
	if (word.u_wanted) {
		if (!word.u_waiter) {
			return;
		}
		return lck_rw_wakeup_u(lck);
	}

	/*
	 * If the lock is reader biased and has shared waiters,
	 * then let's wake them up.
	 */
	if (!word.x_bias && word.s_waiters) {
		return lck_rw_wakeup_s(lck);
	}

	if (word.x_waiters) {
		if (word.r_count > 0) {
			return;
		}
		return lck_rw_wakeup_x(lck, word);
	}

	if (word.s_waiters) {
		return lck_rw_wakeup_s(lck);
	}
}

__attribute__((noinline))
static bool
lck_rw_assert_wait(
	lck_rw_t                *lck,
	thread_t                 self,
	block_hint_t             hint,
	lck_rw_word_t            mask)
{
	event64_t     event = lck_rw_event64(lck, hint);
	struct waitq *waitq = global_eventq(event);
	bool          waiting;
	lck_rw_word_t word;
	spl_t         spl;

	spl = splsched();
	waitq_lock(waitq);

	word = lck_rw_load_word(lck);

	if (hint == kThreadWaitKernelRWLockRead &&
	    lck_rw_lock_s_allowed(word, false)) {
		waiting = false;
	} else if (hint == kThreadWaitKernelRWLockWrite &&
	    lck_rw_lock_x_allowed(word, false)) {
		waiting = false;
	} else if (hint == kThreadWaitKernelRWLockUpgrade &&
	    lck_rw_lock_u2x_allowed(word)) {
		waiting = false;
	} else if ((word.lock64 & mask.lock64) == mask.lock64) {
		waiting = true;
	} else {
		waiting = os_atomic_cmpxchg(&lck->lck_rw.lock64, word.lock64,
		    word.lock64 | mask.lock64, relaxed);
	}

	if (waiting) {
		thread_set_pending_block_hint(self, hint);
		waitq_assert_wait64_locked(waitq, event,
		    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER,
		    TIMEOUT_URGENCY_SYS_NORMAL, TIMEOUT_WAIT_FOREVER,
		    TIMEOUT_NO_LEEWAY, self);
	}

	waitq_unlock(waitq);
	splx(spl);

	return waiting;
}

__attribute__((cold, noinline))
static void
lck_rw_block(lck_adaptive_spin_ctx_t ctx, lck_rw_mode_t mode, lck_rw_wait_t wait)
{
	thread_pri_floor_t token;

	if (mode == LCK_RW_MODE_SPIN) {
		token = thread_priority_floor_start();
		lock_enable_preemption();
	}

	if (wait == LCK_RW_WAIT_BACKOFF) {
		mutex_pause(++ctx->backoff);
	} else {
		thread_block(THREAD_CONTINUE_NULL);
	}

	if (mode == LCK_RW_MODE_SPIN) {
		lock_disable_preemption_for_thread(current_thread());
		thread_priority_floor_end(&token);
	}
}


#pragma mark lck_rw_t: lck_rw{,_try)_lock_shared

__attribute__((always_inline))
static void
lck_rw_lock_s_checks(lck_rw_t *lck, thread_t self)
{
	lck_rw_dbg_assert_canlock(lck, LCK_RW_TYPE_SHARED);
	if (lck->lck_rw_type != LCK_TYPE_RW) {
		__lck_rw_invalid_panic(lck);
	}
	if (lck->lck_rw_owner == self->ctid) {
		__lck_rw_owned_panic(lck, self LCK_RW_DBG_NO_SLOT);
	}
}

__attribute__((always_inline))
static lck_rw_wait_t
lck_rw_lock_s_contended_step(
	lck_rw_t               *lck,
	thread_t                self,
	lck_rw_mode_t           mode,
	lck_adaptive_spin_ctx_t ctx)
{
	block_hint_t  hint = kThreadWaitKernelRWLockRead;
	lck_rw_word_t mask = LCK_RW_S_WAITERS;
	lck_rw_word_t word;
	lck_rw_wait_t wait;

	if (mode == LCK_RW_MODE_SLEEPABLE) {
		lock_disable_preemption_for_thread(self);
	}
	lck_adaptive_spin_start(ctx);

	for (;;) {
		word.lock64 = lock_load_exclusive(&lck->lck_rw.lock64, relaxed);

		if (!lck_rw_lock_s_allowed(word, false)) {
			lck_adaptive_spin_wait_for_event(ctx);
		} else if (lck_rw_lock_s_try(lck, false)) {
			wait = LCK_RW_WAIT_SUCCESS;
			break;
		}

		lck_adaptive_spin_step(ctx);

		if ((ctx->expired || word.u_waiter) &&
		    lck_rw_assert_wait(lck, self, hint, mask)) {
			wait = LCK_RW_WAIT_BLOCK;
			break;
		}

		if (ctx->expired && ctx->snoops > LOCK_SNOOP_SPINS) {
			/*
			 * It's possible for the loop above to never make
			 * progress due to extremely unlucky contention with
			 * an aggressor that does very fast lock/unlock pairs.
			 *
			 * LCK_RW_WAIT_BACKOFF will cause the caller to do
			 * exponential backoffs if we spend too much time
			 * acquiring the loop.
			 */
			wait = LCK_RW_WAIT_BACKOFF;
			break;
		}
	}

	LCK_RW_SPIN_END(lck, hint, ctx->start);
	if (mode == LCK_RW_MODE_SLEEPABLE) {
		lock_enable_preemption();
	}
	return wait;
}

__attribute__((noinline))
static void
lck_rw_lock_s_contended(lck_rw_t *lck, thread_t self, lck_rw_mode_t mode)
{
	block_hint_t hint = kThreadWaitKernelRWLockRead;
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);
	lck_rw_wait_t wait;

	lck_rw_check_preemption(lck, self, mode);
	lck_rw_lock_s_checks(lck, self);
	if (lck->lck_rw.no_sleep) {
		__lck_rw_no_sleep_panic(lck);
	}

	while ((wait = lck_rw_lock_s_contended_step(lck, self, mode, &ctx)) !=
	    LCK_RW_WAIT_SUCCESS) {
		uint64_t start = LCK_RW_BLOCK_BEGIN(lck, hint);

		lck_rw_block(&ctx, mode, wait);
		LCK_RW_BLOCK_END(lck, hint, start);
		lck_adaptive_spin_reset(&ctx);
	}
}

__attribute__((noinline))
static void
lck_rw_lock_s_contended_no_sleep(lck_rw_t *lck, thread_t self)
{
#if CONFIG_DTRACE
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);
#endif /* CONFIG_DTRACE */
	block_hint_t      hint = kThreadWaitKernelRWLockRead;
	hw_spin_policy_t  pol  = &lck_rw_timeout_policy;
	hw_spin_timeout_t to   = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss   = { };
	lck_rw_word_t     word;

	assert(!preemption_enabled());
	lck_rw_lock_s_checks(lck, self);
#if CONFIG_DTRACE
	lck_adaptive_spin_start(&ctx);
#endif /* CONFIG_DTRACE */

	do {
		while (!hw_spin_wait_until(&lck->lck_rw.lock64, word.lock64,
		    lck_rw_lock_s_allowed(word, false))) {
			hw_spin_should_keep_spinning(lck, pol, to, &ss);
		}
	} while (!lck_rw_lock_s_try(lck, false));

	LCK_RW_SPIN_END(lck, hint, ctx.start);
}

__attribute__((always_inline))
static void
__lck_rw_lock_shared(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t self = current_thread();

	lck_rw_lock_will_acquire(lck, self, mode);

	if (!lck_rw_lock_s_try(lck, true)) {
		if (mode == LCK_RW_MODE_SPIN && lck->lck_rw.no_sleep) {
			lck_rw_lock_s_contended_no_sleep(lck, self);
		} else {
			lck_rw_lock_s_contended(lck, self, mode);
		}
	}

	LCK_RW_SLOWPATH(lck_rw_lock_s_slow, lck, mode LCK_RW_DBG_CALLER);
}

__mockable
__lck_rw_new_func
void
lck_rw_lock_shared(lck_rw_t *lck)
{
	__lck_rw_lock_shared(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
void
lck_rw_lock_shared_spin(lck_rw_t *lck)
{
	__lck_rw_lock_shared(lck, LCK_RW_MODE_SPIN);
}

__attribute__((always_inline))
static bool
__lck_rw_try_lock_shared(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t self = current_thread();

	lck_rw_lock_will_acquire(lck, self, mode);

	if (lck->lck_rw_type != LCK_TYPE_RW) {
		__lck_rw_invalid_panic(lck);
	}

	if (!lck_rw_lock_s_try(lck, false)) {
		lck_rw_lock_was_released(lck, self, mode);
		return false;
	}

	LCK_RW_SLOWPATH(lck_rw_try_lock_s_slow, lck LCK_RW_DBG_CALLER);
	return true;
}

__mockable
__lck_rw_new_func
boolean_t
lck_rw_try_lock_shared(lck_rw_t *lck)
{
	return __lck_rw_try_lock_shared(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
bool
lck_rw_try_lock_shared_spin(lck_rw_t *lck)
{
	return __lck_rw_try_lock_shared(lck, LCK_RW_MODE_SPIN);
}


#pragma mark lck_rw_t: lck_rw_unlock_shared, lck_rw_lock_shared_to_exclusive

__attribute__((always_inline))
static void
lck_rw_lock_u2x_contended_prepare(lck_rw_t *lck, thread_t self)
{
	lck_rw_word_t word;

	lck_rw_dbg_assert_held(lck, LCK_RW_TYPE_SHARED);

	lck_rw_set_owner(lck, self->ctid);
	word.lock64 = os_atomic_sub_orig(&lck->lck_rw.lock64,
	    LCK_RW_R_COUNT_INC.lock64, relaxed);

	if (word.r_count == 0) {
		__lck_rw_not_owned_panic(lck, word, LCK_RW_TYPE_SHARED
		    LCK_RW_DBG_NO_SLOT);
	}
}

__attribute__((always_inline))
static lck_rw_wait_t
lck_rw_lock_u2x_contended_step(
	lck_rw_t               *lck,
	thread_t                self,
	lck_rw_mode_t           mode,
	lck_adaptive_spin_ctx_t ctx)
{
	block_hint_t  hint = kThreadWaitKernelRWLockUpgrade;
	lck_rw_word_t mask = LCK_RW_U_WAITER;
	lck_rw_word_t word;
	lck_rw_wait_t wait;

	if (mode == LCK_RW_MODE_SLEEPABLE) {
		lock_disable_preemption_for_thread(self);
	}
	lck_adaptive_spin_start(ctx);

	for (;;) {
		word.lock64 = lock_load_exclusive(&lck->lck_rw.lock64, relaxed);

		if (!lck_rw_lock_u2x_allowed(word)) {
			lck_adaptive_spin_wait_for_event(ctx);
		} else if (lck_rw_lock_u2x_try(lck)) {
			wait = LCK_RW_WAIT_SUCCESS;
			break;
		}

		lck_adaptive_spin_step(ctx);

		if (ctx->expired &&
		    lck_rw_assert_wait(lck, self, hint, mask)) {
			wait = LCK_RW_WAIT_BLOCK;
			break;
		}

		if (ctx->expired && ctx->snoops > LOCK_SNOOP_SPINS) {
			/*
			 * It's possible for the loop above to never make
			 * progress due to extremely unlucky contention with
			 * an aggressor that does very fast lock/unlock pairs.
			 *
			 * LCK_RW_WAIT_BACKOFF will cause the caller to do
			 * exponential backoffs if we spend too much time
			 * acquiring the loop.
			 */
			wait = LCK_RW_WAIT_BACKOFF;
			break;
		}
	}

	LCK_RW_SPIN_END(lck, hint, ctx->start);
	if (mode == LCK_RW_MODE_SLEEPABLE) {
		lock_enable_preemption();
	}

	return wait;
}

__attribute__((noinline))
static void
lck_rw_lock_u2x_contended(lck_rw_t *lck, thread_t self, lck_rw_mode_t mode)
{
	block_hint_t hint = kThreadWaitKernelRWLockUpgrade;
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);
	lck_rw_wait_t wait;

	lck_rw_check_preemption(lck, self, mode);
	lck_rw_lock_u2x_contended_prepare(lck, self);
	if (lck->lck_rw.no_sleep) {
		__lck_rw_no_sleep_panic(lck);
	}

	while ((wait = lck_rw_lock_u2x_contended_step(lck, self, mode, &ctx)) !=
	    LCK_RW_WAIT_SUCCESS) {
		uint64_t start = LCK_RW_BLOCK_BEGIN(lck, hint);

		lck_rw_block(&ctx, mode, wait);
		LCK_RW_BLOCK_END(lck, hint, start);
		lck_adaptive_spin_reset(&ctx);
	}
}


__attribute__((noinline))
static void
lck_rw_lock_u2x_contended_no_sleep(lck_rw_t *lck, thread_t self)
{
#if CONFIG_DTRACE
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);
#endif /* CONFIG_DTRACE */
	block_hint_t      hint = kThreadWaitKernelRWLockUpgrade;
	hw_spin_policy_t  pol  = &lck_rw_timeout_policy;
	hw_spin_timeout_t to   = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss   = { };
	lck_rw_word_t     word;

	assert(!preemption_enabled());
	lck_rw_lock_u2x_contended_prepare(lck, self);
#if CONFIG_DTRACE
	lck_adaptive_spin_start(&ctx);
#endif /* CONFIG_DTRACE */

	do {
		while (!hw_spin_wait_until(&lck->lck_rw.lock64, word.lock64,
		    lck_rw_lock_u2x_allowed(word))) {
			hw_spin_should_keep_spinning(lck, pol, to, &ss);
		}
	} while (!lck_rw_lock_u2x_try(lck));

	LCK_RW_SPIN_END(lck, hint, ctx.start);
	os_atomic_thread_fence(acquire);
}

__attribute__((always_inline))
static bool
lck_rw_wakeup_needed_after_s_unlock(lck_rw_word_t word)
{
	lck_rw_word_t mask = {
		.u_waiter  = true,
		.x_waiters = true,
	};

	return word.r_count == 0 && (word.lock64 & mask.lock64);
}

__attribute__((always_inline))
static void
__lck_rw_unlock_shared(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t      self = current_thread();
	lck_rw_word_t word;

	word.lock64 = os_atomic_sub(&lck->lck_rw.lock64,
	    LCK_RW_R_COUNT_INC.lock64, release);

	if (lck_rw_wakeup_needed_after_s_unlock(word)) {
		lck_rw_wakeup(lck, word);
	}

	lck_rw_lock_was_released(lck, self, mode);
	LCK_RW_SLOWPATH(lck_rw_unlock_s_slow, lck);
}

__mockable
__lck_rw_new_func
void
lck_rw_unlock_shared(lck_rw_t *lck)
{
	__lck_rw_unlock_shared(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
void
lck_rw_unlock_shared_spin(lck_rw_t *lck)
{
	__lck_rw_unlock_shared(lck, LCK_RW_MODE_SPIN);
}

__attribute__((always_inline))
static bool
__lck_rw_lock_shared_to_exclusive(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t      self = current_thread();
	lck_rw_word_t word;

	if (lck_rw_lock_s2x_try(lck, true)) {
		lck_rw_set_owner(lck, self->ctid);
	} else {
		word.lock32 = os_atomic_or_orig(&lck->lck_rw.lock32,
		    LCK_RW_U_WANTED.lock32, relaxed);

		if (__improbable(word.u_wanted)) {
			__lck_rw_unlock_shared(lck, mode);
			return false;
		}

		if (mode == LCK_RW_MODE_SPIN && lck->lck_rw.no_sleep) {
			lck_rw_lock_u2x_contended_no_sleep(lck, self);
		} else {
			lck_rw_lock_u2x_contended(lck, self, mode);
		}
	}

	LCK_RW_SLOWPATH(lck_rw_lock_s2x_success_slow, lck, mode LCK_RW_DBG_CALLER);
	return true;
}

__mockable
__lck_rw_new_func
boolean_t
lck_rw_lock_shared_to_exclusive(lck_rw_t *lck)
{
	return __lck_rw_lock_shared_to_exclusive(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
bool
lck_rw_lock_shared_to_exclusive_spin(lck_rw_t *lck)
{
	return __lck_rw_lock_shared_to_exclusive(lck, LCK_RW_MODE_SPIN);
}

#pragma mark lck_rw_t: lck_rw{,_try}_lock_exclusive

__attribute__((always_inline))
static void
lck_rw_lock_x_checks(lck_rw_t *lck, thread_t self)
{
	lck_rw_dbg_assert_canlock(lck, LCK_RW_TYPE_EXCLUSIVE);
	if (lck->lck_rw_type != LCK_TYPE_RW) {
		__lck_rw_invalid_panic(lck);
	}
	if (lck->lck_rw_owner == self->ctid) {
		__lck_rw_owned_panic(lck, self LCK_RW_DBG_NO_SLOT);
	}
}

__attribute__((always_inline))
static lck_rw_wait_t
lck_rw_lock_x_contended_step(
	lck_rw_t               *lck,
	thread_t                self,
	lck_rw_mode_t           rw_mode,
	lck_adaptive_spin_ctx_t ctx)
{
	hw_spin_policy_t  pol  = &lck_rw_timeout_policy;
	lck_mcs_id_t     *link = &lck->lck_rw.x_tail;
	lck_mcs_mode_t    mode = LCK_MCS_SLEEPABLE | LCK_MCS_ABORTABLE;

	block_hint_t      hint = kThreadWaitKernelRWLockWrite;
	lck_rw_word_t     mask = LCK_RW_X_WAITERS;
	lck_rw_word_t     word = lck_rw_load_word(lck);
	lck_mcs_node_t    node;
	lck_rw_wait_t     wait;

	if (rw_mode == LCK_RW_MODE_SLEEPABLE) {
		lock_disable_preemption_for_thread(self);
	}
	lck_adaptive_spin_start(ctx);

	if (self->sched_pri < BASEPRI_REALTIME &&
	    self->sched_pri > MINPRI_FLOOR &&
	    !(self->options & TH_OPT_VMPRIV)) {
		/*
		 * VM-privileged or realtime threads go to the head of the wait
		 * queue, and all threads are raised to MINPRI_FLOOR while
		 * holding or waiting for an rwlock.
		 *
		 * We do have a problem for threads that have a priority higher
		 * than MINPRI_FLOOR, because they are added at the end of the
		 * wait queues and under important contention can be blocked
		 * behind lower priority threads for a while.
		 *
		 * To minimize this risk, when we detect such a thread blocking,
		 * we will mark the rwlock as having urgent x-waiters, and on
		 * wakeup, instead of waking up 2 threads at a time, all
		 * exclusive waiters will be woken up at once, letting the
		 * scheduler sort it out.
		 *
		 * TODO: this is a rather unfortunate implementation, the wait
		 *       queue subsystem should really have some form of
		 *       priority aware ordering (not necessarily a full
		 *       priority ordered queue which would be problematic,
		 *       but at the very least a few tiers).
		 */
		mask = LCK_RW_X_URGENT;
	}

	node = lck_mcs_enqueue(link, mode, lck, pol);
	if (node == NULL) {
		ctx->expired = true;
	}

	for (;;) {
		word.lock64 = lock_load_exclusive(&lck->lck_rw.lock64, relaxed);

		if (!lck_rw_lock_x_allowed(word, false)) {
			lck_adaptive_spin_wait_for_event(ctx);
		} else if (lck_rw_lock_x_try(lck, false)) {
			wait = LCK_RW_WAIT_SUCCESS;
			break;
		}

		if (node) {
			lck_mcs_spin_step(node, link, mode, &ctx->abort_slot);
		}
		lck_adaptive_spin_step(ctx);

		if ((ctx->expired || word.u_waiter) &&
		    lck_rw_assert_wait(lck, self, hint, mask)) {
			wait = LCK_RW_WAIT_BLOCK;
			break;
		}

		if (ctx->expired && ctx->snoops > LOCK_SNOOP_SPINS) {
			/*
			 * It's possible for the loop above to never make
			 * progress due to extremely unlucky contention with
			 * an aggressor that does very fast lock/unlock pairs.
			 *
			 * LCK_RW_WAIT_BACKOFF will cause the caller to do
			 * exponential backoffs if we spend too much time
			 * acquiring the loop.
			 */
			wait = LCK_RW_WAIT_BACKOFF;
			break;
		}
	}

	if (node) {
		lck_mcs_dequeue(node, link, mode);
	}
	LCK_RW_SPIN_END(lck, hint, ctx->start);
	if (rw_mode == LCK_RW_MODE_SLEEPABLE) {
		lock_enable_preemption();
	}

	return wait;
}

__attribute__((noinline))
static void
lck_rw_lock_x_contended(lck_rw_t *lck, thread_t self, lck_rw_mode_t mode)
{
	block_hint_t hint = kThreadWaitKernelRWLockWrite;
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);
	lck_rw_wait_t wait;

	lck_rw_check_preemption(lck, self, mode);
	lck_rw_lock_x_checks(lck, self);
	if (lck->lck_rw.no_sleep) {
		__lck_rw_no_sleep_panic(lck);
	}

	while ((wait = lck_rw_lock_x_contended_step(lck, self, mode, &ctx)) !=
	    LCK_RW_WAIT_SUCCESS) {
		uint64_t start = LCK_RW_BLOCK_BEGIN(lck, hint);

		lck_rw_block(&ctx, mode, wait);
		LCK_RW_BLOCK_END(lck, hint, start);
		lck_adaptive_spin_reset(&ctx);
	}
}

__attribute__((noinline))
static void
lck_rw_lock_x_contended_no_sleep(lck_rw_t *lck, thread_t self)
{
	hw_spin_policy_t  pol  = &lck_rw_timeout_policy;
	hw_spin_timeout_t to   = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss   = { };
	lck_mcs_id_t     *link = &lck->lck_rw.x_tail;
	lck_mcs_mode_t    mode = LCK_MCS_SPINNING;

	lck_rw_word_t     word;
	lck_mcs_node_t    node;

	assert(!preemption_enabled());
	lck_rw_lock_x_checks(lck, self);

	node = lck_mcs_enqueue(link, mode, lck, pol);

	do {
		while (!hw_spin_wait_until_n(LOCK_SNOOP_SPINS_MCS,
		    &lck->lck_rw.lock64, word.lock64,
		    lck_rw_lock_x_allowed(word, false))) {
			lck_mcs_spin_step(node, link, mode, NULL);
			hw_spin_should_keep_spinning(lck, pol, to, &ss);
		}
	} while (!lck_rw_lock_x_try(lck, false));

	lck_mcs_dequeue(node, link, mode);
}

__attribute__((always_inline))
static void
__lck_rw_lock_exclusive(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t self = current_thread();

	lck_rw_lock_will_acquire(lck, self, mode);

	if (!lck_rw_lock_x_try(lck, true)) {
		if (mode == LCK_RW_MODE_SPIN && lck->lck_rw.no_sleep) {
			lck_rw_lock_x_contended_no_sleep(lck, self);
		} else {
			lck_rw_lock_x_contended(lck, self, mode);
		}
	}

	lck_rw_set_owner(lck, self->ctid);
	LCK_RW_SLOWPATH(lck_rw_lock_x_slow, lck, mode LCK_RW_DBG_CALLER);
}

__mockable
__lck_rw_new_func
void
lck_rw_lock_exclusive(lck_rw_t *lck)
{
	(void)__lck_rw_lock_exclusive(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
void
lck_rw_lock_exclusive_spin(lck_rw_t *lck)
{
	__lck_rw_lock_exclusive(lck, LCK_RW_MODE_SPIN);
}

__attribute__((always_inline))
static bool
__lck_rw_try_lock_exclusive(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t self = current_thread();

	lck_rw_lock_will_acquire(lck, self, mode);

	if (lck->lck_rw_type != LCK_TYPE_RW) {
		__lck_rw_invalid_panic(lck);
	}

	if (!lck_rw_lock_x_try(lck, false)) {
		lck_rw_lock_was_released(lck, self, mode);
		return false;
	}

	lck_rw_set_owner(lck, self->ctid);
	LCK_RW_SLOWPATH(lck_rw_try_lock_x_slow, lck LCK_RW_DBG_CALLER);
	return true;
}

__mockable
__lck_rw_new_func
boolean_t
lck_rw_try_lock_exclusive(lck_rw_t *lck)
{
	return __lck_rw_try_lock_exclusive(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
bool
lck_rw_try_lock_exclusive_spin(lck_rw_t *lck)
{
	return __lck_rw_try_lock_exclusive(lck, LCK_RW_MODE_SPIN);
}


#pragma mark lck_rw_t: lck_rw_unlock_exclusive  lck_rw_lock_exclusive_to_shared

__attribute__((always_inline))
static bool
lck_rw_wakeup_needed_after_x_unlock(lck_rw_word_t word)
{
	lck_rw_word_t mask = {
		.s_waiters = true,
		.u_waiter  = true, /* not needed but generates better code */
		.x_waiters = true,
	};
	return word.lock64 & mask.lock64;
}

__attribute__((always_inline))
static void
__lck_rw_unlock_exclusive(lck_rw_t *lck, lck_rw_mode_t mode)
{
	thread_t      self = current_thread();
	lck_rw_word_t word = { .lock32 = ~0u };

	lck_rw_clear_owner(lck, self);
	word.lock64 = os_atomic_andnot(&lck->lck_rw.lock64, word.lock64, release);

	if (lck_rw_wakeup_needed_after_x_unlock(word)) {
		lck_rw_wakeup(lck, word);
	}

	lck_rw_lock_was_released(lck, self, mode);
	LCK_RW_SLOWPATH(lck_rw_unlock_x_slow, lck);
}

__mockable
__lck_rw_new_func
void
lck_rw_unlock_exclusive(lck_rw_t *lck)
{
	__lck_rw_unlock_exclusive(lck, LCK_RW_MODE_SLEEPABLE);
}

__mockable
void
lck_rw_unlock_exclusive_spin(lck_rw_t *lck)
{
	__lck_rw_unlock_exclusive(lck, LCK_RW_MODE_SPIN);
}

__mockable
__lck_rw_new_func
void
lck_rw_lock_exclusive_to_shared(lck_rw_t *lck)
{
	thread_t      self = current_thread();
	lck_rw_word_t oword, nword;

	lck_rw_clear_owner(lck, self);

	os_atomic_rmw_loop(&lck->lck_rw.lock64, oword.lock64, nword.lock64, release, {
		nword = oword;
		nword.lock32 = LCK_RW_R_COUNT_INC.lock32;
	});

	if (nword.s_waiters && (!nword.x_bias || !nword.x_waiters)) {
		lck_rw_wakeup(lck, nword);
	}

	LCK_RW_SLOWPATH(lck_rw_lock_x2s_slow, lck LCK_RW_DBG_CALLER);
}


#pragma mark lck_rw_t: generic interfaces

__lck_rw_new_func
void
lck_rw_lock(lck_rw_t *lck, lck_rw_type_t type)
{
	if (type == LCK_RW_TYPE_SHARED) {
		return lck_rw_lock_shared(lck);
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_lock_exclusive(lck);
	}

	if (type == LCK_RW_TYPE_SHARED_SPIN) {
		return lck_rw_lock_shared_spin(lck);
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE_SPIN) {
		return lck_rw_lock_exclusive_spin(lck);
	}

	panic("Invalid RW lock type %d", type);
}

__lck_rw_new_func
boolean_t
lck_rw_try_lock(lck_rw_t *lck, lck_rw_type_t type)
{
	if (type == LCK_RW_TYPE_SHARED) {
		return lck_rw_try_lock_shared(lck);
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_try_lock_exclusive(lck);
	}

	if (type == LCK_RW_TYPE_SHARED_SPIN) {
		return lck_rw_try_lock_shared_spin(lck);
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE_SPIN) {
		return lck_rw_try_lock_exclusive_spin(lck);
	}

	panic("Invalid RW lock type %d", type);
}

__mockable
__lck_rw_new_func
void
lck_rw_unlock(lck_rw_t *lck, lck_rw_type_t type)
{
	if (type == LCK_RW_TYPE_SHARED) {
		return lck_rw_unlock_shared(lck);
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_unlock_exclusive(lck);
	}

	if (type == LCK_RW_TYPE_SHARED_SPIN) {
		return lck_rw_unlock_shared_spin(lck);
	}

	if (type == LCK_RW_TYPE_EXCLUSIVE_SPIN) {
		return lck_rw_unlock_exclusive(lck);
	}

	panic("Invalid RW lock type %d", type);
}

void
lck_rw_convert_nospin(lck_rw_t *lck)
{
	thread_t self = current_thread();

	lck_rw_lock_count_inc(self, lck);
	lock_enable_preemption();
}

void
lck_rw_convert_spin(lck_rw_t *lck)
{
	thread_t self = current_thread();

	lock_disable_preemption_for_thread(self);
	lck_rw_lock_count_dec(self, lck);
}

__mockable
__lck_rw_new_func
lck_rw_type_t
lck_rw_done(lck_rw_t *lck)
{
	if (lck->lck_rw.x_locked) {
		lck_rw_unlock_exclusive(lck);
		return LCK_RW_TYPE_EXCLUSIVE;
	} else {
		lck_rw_unlock_shared(lck);
		return LCK_RW_TYPE_SHARED;
	}
}

bool
lck_rw_is_contended_for_kdbg(lck_rw_new_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	if (word.lock32 != LCK_RW_UNLOCKED.lock32) {
		return true;
	}

	if (word.wait8 != LCK_RW_UNLOCKED.wait8) {
		return true;
	}

	return false;
}

#pragma mark lck_rw_t: assertions

static void
lck_rw_assert_shared(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);
	lck_rw_type_t type = LCK_RW_TYPE_SHARED;

	lck_rw_dbg_assert_held(lck, type);
	if (word.x_locked || word.r_count == 0) {
		__lck_rw_not_owned_panic(lck, word, type LCK_RW_DBG_NO_SLOT);
	}
}

static void
lck_rw_assert_exclusive(lck_rw_t *lck)
{
	thread_t      self = current_thread();
	lck_rw_word_t word = lck_rw_load_word(lck);
	lck_rw_type_t type = LCK_RW_TYPE_EXCLUSIVE;

	lck_rw_dbg_assert_held(lck, type);
	if (!word.x_locked || lck->lck_rw_owner != self->ctid) {
		__lck_rw_not_owned_panic(lck, word, type LCK_RW_DBG_NO_SLOT);
	}
}

static void
lck_rw_assert_held(lck_rw_t *lck)
{
	if (lck->lck_rw.x_locked) {
		lck_rw_assert_exclusive(lck);
	} else {
		lck_rw_assert_shared(lck);
	}
}

static void
lck_rw_assert_not_held(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	lck_rw_dbg_assert_canlock(lck, LCK_RW_TYPE_EXCLUSIVE);
	if (lck->lck_rw_type != LCK_TYPE_RW) {
		__lck_rw_invalid_panic(lck);
	}
	if (word.lock32) {
		__lck_rw_held_panic(lck);
	}
}

static void
lck_rw_assert_not_owned(lck_rw_t *lck)
{
	lck_rw_lock_x_checks(lck, current_thread());
}

__mockable
void
lck_rw_assert_held_type(lck_rw_t *lck, lck_rw_type_t type)
{
	switch (type) {
	case LCK_RW_TYPE_NONE:
		return lck_rw_assert_not_held(lck);
	case LCK_RW_TYPE_SHARED_SPIN:
		assert(get_preemption_level() > 0);
		OS_FALLTHROUGH;
	case LCK_RW_TYPE_SHARED:
		return lck_rw_assert_shared(lck);
	case LCK_RW_TYPE_EXCLUSIVE_SPIN:
		assert(get_preemption_level() > 0);
		OS_FALLTHROUGH;
	case LCK_RW_TYPE_EXCLUSIVE:
		return lck_rw_assert_exclusive(lck);
	case LCK_RW_TYPE_ANY:
		return lck_rw_assert_held(lck);
	}

	panic("Invalid RW lock type %d", type);
}

__mockable
__lck_rw_new_func
void
lck_rw_assert(lck_rw_t *lck, unsigned int type)
{
	switch (type) {
	case LCK_RW_ASSERT_SHARED:
		return lck_rw_assert_shared(lck);
	case LCK_RW_ASSERT_EXCLUSIVE:
		return lck_rw_assert_exclusive(lck);
	case LCK_RW_ASSERT_HELD:
		return lck_rw_assert_held(lck);
	case LCK_RW_ASSERT_NOTHELD:
		return lck_rw_assert_not_held(lck);
	case LCK_RW_ASSERT_NOT_OWNED:
		return lck_rw_assert_not_owned(lck);
	}
	panic("Invalid RW lock type %d", type);
}

__lck_rw_new_func
boolean_t
kdp_lck_rw_lock_is_acquired_exclusive(lck_rw_t *lck)
{
	if (not_in_kdp) {
		panic("panic: rw lock exclusive check done outside of kernel debugger");
	}

	return lck->lck_rw.x_locked;
}

void
kdp_rwlck_find_owner(
	__unused struct waitq  *waitq,
	event64_t               event,
	thread_waitinfo_t      *waitinfo)
{
	lck_rw_t *lck;

	switch (waitinfo->wait_type) {
	case kThreadWaitKernelRWLockRead:
	case kThreadWaitKernelRWLockWrite:
	case kThreadWaitKernelRWLockUpgrade:
		break;
	default:
		panic("Invalid blocking type: %d", waitinfo->wait_type);
		break;
	}

	lck = lck_rw_from_event64(event);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	waitinfo->owner   = thread_tid(ctid_get_thread_unsafe(lck->lck_rw_owner));
}


#pragma mark lck_rw_t: yielding

static bool
lck_rw_has_any_x_waiters(lck_rw_word_t word)
{
	return word.x_tail || word.u_waiter || word.x_waiters || word.u_wanted;
}

bool
lck_rw_has_exclusive_spinners(lck_rw_t *lck)
{
	return os_atomic_load(&lck->lck_rw.x_tail, relaxed);
}

__lck_rw_new_func
bool
lck_rw_lock_would_yield_shared(lck_rw_t *lck)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	return lck_rw_has_any_x_waiters(word);
}

__lck_rw_new_func
__attribute__((cold, noinline))
bool
lck_rw_lock_yield_shared(lck_rw_t *lck, boolean_t force_yield)
{
	bool yield = force_yield || lck_rw_lock_would_yield_shared(lck);

	if (yield) {
		lck_rw_unlock_shared(lck);
		mutex_pause(2);
		lck_rw_lock_shared(lck);
	}

	return yield;
}

__lck_rw_new_func
bool
lck_rw_lock_would_yield_exclusive(lck_rw_t *lck, lck_rw_yield_t mode)
{
	lck_rw_word_t word = lck_rw_load_word(lck);

	if (mode == LCK_RW_YIELD_ALWAYS) {
		return true;
	}

	if (lck_rw_has_any_x_waiters(word)) {
		return true;
	}

	if (mode == LCK_RW_YIELD_ANY_WAITER && word.s_waiters) {
		return true;
	}

	return false;
}

__lck_rw_new_func
__attribute__((cold, noinline))
bool
lck_rw_lock_yield_exclusive(lck_rw_t *lck, lck_rw_yield_t mode)
{
	bool yield = lck_rw_lock_would_yield_exclusive(lck, mode);

	if (yield) {
		lck_rw_unlock_exclusive(lck);
		mutex_pause(2);
		lck_rw_lock_exclusive(lck);
	}

	return yield;
}


#pragma mark lck_rw_t: sleeping

__lck_rw_new_func
wait_result_t
lck_rw_sleep(
	lck_rw_t               *lck,
	lck_sleep_action_t      action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	return lck_rw_sleep_deadline(lck, action, event, interruptible, TIMEOUT_WAIT_FOREVER);
}

__lck_rw_new_func
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


#pragma mark lck_rw_t: promotion

/*
 * Reader-writer lock promotion
 *
 * We support a limited form of reader-writer
 * lock promotion whose effects are:
 *
 *   * Qualifying threads have decay disabled
 *   * Scheduler priority is reset to a floor of
 *     of their statically assigned priority
 *     or MINPRI_RWLOCK
 *
 * The rationale is that lck_rw_ts do not have
 * a single owner, so we cannot apply a directed
 * priority boost from all waiting threads
 * to all holding threads without maintaining
 * lists of all shared owners and all waiting
 * threads for every lock.
 *
 * Instead (and to preserve the uncontended fast-
 * path), acquiring (or attempting to acquire)
 * a RW lock in shared or exclusive lock increments
 * a per-thread counter. Only if that thread stops
 * making forward progress (for instance blocking
 * on a mutex, or being preempted) do we consult
 * the counter and apply the priority floor.
 * When the thread becomes runnable again (or in
 * the case of preemption it never stopped being
 * runnable), it has the priority boost and should
 * be in a good position to run on the CPU and
 * release all RW locks (at which point the priority
 * boost is cleared).
 *
 * Care must be taken to ensure that priority
 * boosts are not retained indefinitely, since unlike
 * mutex priority boosts (where the boost is tied
 * to the mutex lifecycle), the boost is tied
 * to the thread and independent of any particular
 * lck_rw_t. Assertions are in place on return
 * to userspace so that the boost is not held
 * indefinitely.
 *
 * The routines that increment/decrement the
 * per-thread counter should err on the side of
 * incrementing any time a preemption is possible
 * and the lock would be visible to the rest of the
 * system as held (so it should be incremented before
 * interlocks are dropped/preemption is enabled, or
 * before a CAS is executed to acquire the lock).
 *
 */

/*!
 * @function lck_rw_clear_promotion
 *
 * @abstract
 * Undo priority promotions when the last rw_lock
 * is released by a thread (if a promotion was active).
 *
 * @param thread        thread to demote.
 * @param lock          object reason for the demotion.
 */
__attribute__((noinline))
static void
lck_rw_clear_promotion(thread_t thread, const void *lock)
{
	/*
	 * For codegen quality reasons, this function is called even for cases
	 * when rwlock_count isn't 0.
	 *
	 * We have to check again (see lck_rw_lock_count_dec()).
	 */
	if (thread->rwlock_count == 0) {
		spl_t s = splsched();
		thread_lock(thread);

		if (thread->sched_flags & TH_SFLAG_RW_PROMOTED) {
			sched_thread_unpromote_reason(thread, TH_SFLAG_RW_PROMOTED,
			    unslide_for_kdebug(lock));
		}

		thread_unlock(thread);
		splx(s);
	}
}

/*!
 * @function lck_rw_set_promotion_locked
 *
 * @abstract
 * Callout from context switch if the thread goes
 * off core with a positive rwlock_count.
 *
 * @discussion
 * Called at splsched with the thread locked.
 *
 * @param thread        thread to promote.
 */
__attribute__((always_inline))
void
lck_rw_set_promotion_locked(thread_t thread)
{
	if (LcksOpts & LCK_OPTION_DISABLE_RW_PRIO) {
		return;
	}

	assert(thread->rwlock_count > 0);

	if (!(thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		sched_thread_promote_reason(thread, TH_SFLAG_RW_PROMOTED, 0);
	}
}

__attribute__((always_inline))
void
lck_rw_lock_count_inc(thread_t thread, const void *lock __unused)
{
	if (thread->rwlock_count++ == 0) {
#if MACH_ASSERT
		/*
		 * Set the ast to check that the
		 * rwlock_count is going to be set to zero when
		 * going back to userspace.
		 * Set it only once when we increment it for the first time.
		 */
		if (improbable_static_if(mach_assert)) {
			act_set_debug_assert();
		}
#endif
	}
	os_compiler_barrier();
}

__attribute__((always_inline))
void
lck_rw_lock_count_dec(thread_t thread, const void *lock)
{
	os_compiler_barrier();
	release_assert(thread->rwlock_count-- > 0);
	os_compiler_barrier();

	/* sched_flags checked without lock, but will be rechecked while clearing */
	if (__improbable(thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		lck_rw_clear_promotion(thread, lock);
	}
}
