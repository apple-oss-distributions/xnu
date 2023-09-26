/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>

#include <kern/locks_internal.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#if defined(__x86_64__)
#include <i386/tsc.h>
#include <i386/machine_routines.h>
#endif
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <string.h>
#include <vm/pmap.h>

#include <sys/kdebug.h>

#define LCK_MTX_SLEEP_CODE              0
#define LCK_MTX_SLEEP_DEADLINE_CODE     1
#define LCK_MTX_LCK_WAIT_CODE           2
#define LCK_MTX_UNLCK_WAKEUP_CODE       3

// Panic in tests that check lock usage correctness
// These are undesirable when in a panic or a debugger is runnning.
#define LOCK_CORRECTNESS_PANIC() (kernel_debugger_entry_count == 0)

#if MACH_LDEBUG
#define ALIGN_TEST(p, t) do{if((uintptr_t)p&(sizeof(t)-1)) __builtin_trap();}while(0)
#else
#define ALIGN_TEST(p, t) do{}while(0)
#endif

#define NOINLINE                __attribute__((noinline))

#define ordered_load_hw(lock)          os_atomic_load(&(lock)->lock_data, compiler_acq_rel)
#define ordered_store_hw(lock, value)  os_atomic_store(&(lock)->lock_data, (value), compiler_acq_rel)

KALLOC_TYPE_DEFINE(KT_GATE, gate_t, KT_PRIV_ACCT);

struct lck_spinlock_to_info PERCPU_DATA(lck_spinlock_to_info);
volatile lck_spinlock_to_info_t lck_spinlock_timeout_in_progress;

SECURITY_READ_ONLY_LATE(boolean_t) spinlock_timeout_panic = TRUE;

struct lck_tktlock_pv_info PERCPU_DATA(lck_tktlock_pv_info);

#if CONFIG_PV_TICKET
SECURITY_READ_ONLY_LATE(bool) has_lock_pv = FALSE; /* used by waitq.py */
#endif

#if DEBUG
TUNABLE(uint32_t, LcksOpts, "lcks", LCK_OPTION_ENABLE_DEBUG);
#else
TUNABLE(uint32_t, LcksOpts, "lcks", 0);
#endif

#if CONFIG_DTRACE
#if defined (__x86_64__)
machine_timeout_t dtrace_spin_threshold = 500; // 500ns
#elif defined(__arm64__)
MACHINE_TIMEOUT(dtrace_spin_threshold, "dtrace-spin-threshold",
    0xC /* 12 ticks == 500ns with 24MHz OSC */, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
#endif
#endif

struct lck_mcs PERCPU_DATA(lck_mcs);

__kdebug_only
uintptr_t
unslide_for_kdebug(const void* object)
{
	if (__improbable(kdebug_enable)) {
		return VM_KERNEL_UNSLIDE_OR_PERM(object);
	} else {
		return 0;
	}
}

static __abortlike void
__lck_require_preemption_disabled_panic(void *lock)
{
	panic("Attempt to take no-preempt lock %p in preemptible context", lock);
}

static inline void
__lck_require_preemption_disabled(void *lock, thread_t self __unused)
{
	if (__improbable(!lock_preemption_disabled_for_thread(self))) {
		__lck_require_preemption_disabled_panic(lock);
	}
}

#pragma mark - HW Spin policies

/*
 * Input and output timeouts are expressed in absolute_time for arm and TSC for Intel
 */
__attribute__((always_inline))
hw_spin_timeout_t
hw_spin_compute_timeout(hw_spin_policy_t pol)
{
	hw_spin_timeout_t ret = {
		.hwst_timeout = os_atomic_load(pol->hwsp_timeout, relaxed),
	};

	ret.hwst_timeout <<= pol->hwsp_timeout_shift;
#if SCHED_HYGIENE_DEBUG
	ret.hwst_in_ppl = pmap_in_ppl();
	/* Note we can't check if we are interruptible if in ppl */
	ret.hwst_interruptible = !ret.hwst_in_ppl && ml_get_interrupts_enabled();
#endif /* SCHED_HYGIENE_DEBUG */

#if SCHED_HYGIENE_DEBUG
#ifndef KASAN
	if (ret.hwst_timeout > 0 &&
	    !ret.hwst_in_ppl &&
	    !ret.hwst_interruptible &&
	    interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
		uint64_t int_timeout = os_atomic_load(&interrupt_masked_timeout, relaxed);

#if defined(__x86_64__)
		int_timeout = tmrCvt(int_timeout, tscFCvtn2t);
#endif
		if (int_timeout < ret.hwst_timeout) {
			ret.hwst_timeout = int_timeout;
		}
	}
#endif /* !KASAN */
#endif /* SCHED_HYGIENE_DEBUG */

	return ret;
}

__attribute__((always_inline))
bool
hw_spin_in_ppl(hw_spin_timeout_t to)
{
#if SCHED_HYGIENE_DEBUG
	return to.hwst_in_ppl;
#else
	(void)to;
	return pmap_in_ppl();
#endif
}

bool
hw_spin_should_keep_spinning(
	void                   *lock,
	hw_spin_policy_t        pol,
	hw_spin_timeout_t       to,
	hw_spin_state_t        *state)
{
	hw_spin_timeout_status_t rc;
#if SCHED_HYGIENE_DEBUG
	uint64_t irq_time = 0;
#endif
	uint64_t now;

	if (__improbable(to.hwst_timeout == 0)) {
		return true;
	}

	now = ml_get_timebase();
	if (__probable(now < state->hwss_deadline)) {
		/* keep spinning */
		return true;
	}

#if SCHED_HYGIENE_DEBUG
	if (to.hwst_interruptible) {
		irq_time = current_thread()->machine.int_time_mt;
	}
#endif /* SCHED_HYGIENE_DEBUG */

	if (__probable(state->hwss_deadline == 0)) {
		state->hwss_start     = now;
		state->hwss_deadline  = now + to.hwst_timeout;
#if SCHED_HYGIENE_DEBUG
		state->hwss_irq_start = irq_time;
#endif
		return true;
	}

	/*
	 * Update fields that the callback needs
	 */
	state->hwss_now     = now;
#if SCHED_HYGIENE_DEBUG
	state->hwss_irq_end = irq_time;
#endif /* SCHED_HYGIENE_DEBUG */

	rc = pol->hwsp_op_timeout((char *)lock - pol->hwsp_lock_offset,
	    to, *state);
	if (rc == HW_LOCK_TIMEOUT_CONTINUE) {
		/* push the deadline */
		state->hwss_deadline += to.hwst_timeout;
	}
	return rc == HW_LOCK_TIMEOUT_CONTINUE;
}

__attribute__((always_inline))
void
lck_spinlock_timeout_set_orig_owner(uintptr_t owner)
{
#if DEBUG || DEVELOPMENT
	PERCPU_GET(lck_spinlock_to_info)->owner_thread_orig = owner & ~0x7ul;
#else
	(void)owner;
#endif
}

__attribute__((always_inline))
void
lck_spinlock_timeout_set_orig_ctid(uint32_t ctid)
{
#if DEBUG || DEVELOPMENT
	PERCPU_GET(lck_spinlock_to_info)->owner_thread_orig =
	    (uintptr_t)ctid_get_thread_unsafe(ctid);
#else
	(void)ctid;
#endif
}

lck_spinlock_to_info_t
lck_spinlock_timeout_hit(void *lck, uintptr_t owner)
{
	lck_spinlock_to_info_t lsti = PERCPU_GET(lck_spinlock_to_info);

	if (owner < (1u << CTID_SIZE_BIT)) {
		owner = (uintptr_t)ctid_get_thread_unsafe((uint32_t)owner);
	} else {
		/* strip possible bits used by the lock implementations */
		owner &= ~0x7ul;
	}

	lsti->lock = lck;
	lsti->owner_thread_cur = owner;
	lsti->owner_cpu = ~0u;
	os_atomic_store(&lck_spinlock_timeout_in_progress, lsti, release);

	if (owner == 0) {
		/* if the owner isn't known, just bail */
		goto out;
	}

	for (uint32_t i = 0; i <= ml_early_cpu_max_number(); i++) {
		cpu_data_t *data = cpu_datap(i);
		if (data && (uintptr_t)data->cpu_active_thread == owner) {
			lsti->owner_cpu = i;
			os_atomic_store(&lck_spinlock_timeout_in_progress, lsti, release);
#if __x86_64__
			if ((uint32_t)cpu_number() != i) {
				/* Cause NMI and panic on the owner's cpu */
				NMIPI_panic(cpu_to_cpumask(i), SPINLOCK_TIMEOUT);
			}
#endif
			break;
		}
	}

out:
	return lsti;
}

#pragma mark - HW locks

/*
 * Routine:	hw_lock_init
 *
 *	Initialize a hardware lock.
 */
MARK_AS_HIBERNATE_TEXT void
hw_lock_init(hw_lock_t lock)
{
	ordered_store_hw(lock, 0);
}

__result_use_check
static inline bool
hw_lock_trylock_contended(hw_lock_t lock, uintptr_t newval)
{
#if OS_ATOMIC_USE_LLSC
	uintptr_t oldval;
	os_atomic_rmw_loop(&lock->lock_data, oldval, newval, acquire, {
		if (oldval != 0) {
		        wait_for_event(); // clears the monitor so we don't need give_up()
		        return false;
		}
	});
	return true;
#else // !OS_ATOMIC_USE_LLSC
#if OS_ATOMIC_HAS_LLSC
	uintptr_t oldval = os_atomic_load_exclusive(&lock->lock_data, relaxed);
	if (oldval != 0) {
		wait_for_event(); // clears the monitor so we don't need give_up()
		return false;
	}
#endif
	return lock_cmpxchg(&lock->lock_data, 0, newval, acquire);
#endif // !OS_ATOMIC_USE_LLSC
}

__result_use_check
static inline bool
hw_lock_trylock_bit(uint32_t *target, unsigned int bit, bool wait)
{
	uint32_t mask = 1u << bit;

#if OS_ATOMIC_USE_LLSC || !OS_ATOMIC_HAS_LLSC
	uint32_t oldval, newval;
	os_atomic_rmw_loop(target, oldval, newval, acquire, {
		newval = oldval | mask;
		if (__improbable(oldval & mask)) {
#if OS_ATOMIC_HAS_LLSC
		        if (wait) {
		                wait_for_event(); // clears the monitor so we don't need give_up()
			} else {
		                os_atomic_clear_exclusive();
			}
#else
		        if (wait) {
		                cpu_pause();
			}
#endif
		        return false;
		}
	});
	return true;
#else
	uint32_t oldval = os_atomic_load_exclusive(target, relaxed);
	if (__improbable(oldval & mask)) {
		if (wait) {
			wait_for_event(); // clears the monitor so we don't need give_up()
		} else {
			os_atomic_clear_exclusive();
		}
		return false;
	}
	return (os_atomic_or_orig(target, mask, acquire) & mask) == 0;
#endif // !OS_ATOMIC_USE_LLSC && OS_ATOMIC_HAS_LLSC
}

static hw_spin_timeout_status_t
hw_spin_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	hw_lock_t lock  = _lock;
	uintptr_t owner = lock->lock_data & ~0x7ul;
	lck_spinlock_to_info_t lsti;

	if (!spinlock_timeout_panic) {
		/* keep spinning rather than panicing */
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	if (pmap_in_ppl()) {
		/*
		 * This code is used by the PPL and can't write to globals.
		 */
		panic("Spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
		    "current owner: %p, " HW_SPIN_TIMEOUT_DETAILS_FMT,
		    lock, HW_SPIN_TIMEOUT_ARG(to, st),
		    (void *)owner, HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
	}

	// Capture the actual time spent blocked, which may be higher than the timeout
	// if a misbehaving interrupt stole this thread's CPU time.
	lsti = lck_spinlock_timeout_hit(lock, owner);
	panic("Spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "current owner: %p (on cpu %d), "
#if DEBUG || DEVELOPMENT
	    "initial owner: %p, "
#endif /* DEBUG || DEVELOPMENT */
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lock, HW_SPIN_TIMEOUT_ARG(to, st),
	    (void *)lsti->owner_thread_cur, lsti->owner_cpu,
#if DEBUG || DEVELOPMENT
	    (void *)lsti->owner_thread_orig,
#endif /* DEBUG || DEVELOPMENT */
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

const struct hw_spin_policy hw_lock_spin_policy = {
	.hwsp_name              = "hw_lock_t",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = hw_spin_timeout_panic,
};

static hw_spin_timeout_status_t
hw_spin_always_return(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
#pragma unused(_lock, to, st)
	return HW_LOCK_TIMEOUT_RETURN;
}

const struct hw_spin_policy hw_lock_spin_panic_policy = {
	.hwsp_name              = "hw_lock_t[panic]",
#if defined(__x86_64__)
	.hwsp_timeout           = &LockTimeOutTSC,
#else
	.hwsp_timeout_atomic    = &LockTimeOut,
#endif
	.hwsp_timeout_shift     = 2,
	.hwsp_op_timeout        = hw_spin_always_return,
};

#if DEBUG || DEVELOPMENT
static machine_timeout_t hw_lock_test_to;
const struct hw_spin_policy hw_lock_test_give_up_policy = {
	.hwsp_name              = "testing policy",
#if defined(__x86_64__)
	.hwsp_timeout           = &LockTimeOutTSC,
#else
	.hwsp_timeout_atomic    = &LockTimeOut,
#endif
	.hwsp_timeout_shift     = 2,
	.hwsp_op_timeout        = hw_spin_always_return,
};

__startup_func
static void
hw_lock_test_to_init(void)
{
	uint64_t timeout;

	nanoseconds_to_absolutetime(100 * NSEC_PER_USEC, &timeout);
#if defined(__x86_64__)
	timeout = tmrCvt(timeout, tscFCvtn2t);
#endif
	os_atomic_init(&hw_lock_test_to, timeout);
}
STARTUP(TIMEOUTS, STARTUP_RANK_FIRST, hw_lock_test_to_init);
#endif

static hw_spin_timeout_status_t
hw_lock_bit_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	hw_lock_bit_t *lock = _lock;

	if (!spinlock_timeout_panic) {
		/* keep spinning rather than panicing */
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	panic("Spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "current value: 0x%08x, " HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lock, HW_SPIN_TIMEOUT_ARG(to, st),
	    *lock, HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy hw_lock_bit_policy = {
	.hwsp_name              = "hw_lock_bit_t",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = hw_lock_bit_timeout_panic,
};

#if __arm64__
const uint64_t hw_lock_bit_timeout_2s = 0x3000000;
const struct hw_spin_policy hw_lock_bit_policy_2s = {
	.hwsp_name              = "hw_lock_bit_t",
	.hwsp_timeout           = &hw_lock_bit_timeout_2s,
	.hwsp_op_timeout        = hw_lock_bit_timeout_panic,
};
#endif

/*
 *	Routine: hw_lock_lock_contended
 *
 *	Spin until lock is acquired or timeout expires.
 *	timeout is in mach_absolute_time ticks. Called with
 *	preemption disabled.
 */
static hw_lock_status_t NOINLINE
hw_lock_lock_contended(
	hw_lock_t               lock,
	uintptr_t               data,
	hw_spin_policy_t        pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_spin_timeout_t to = hw_spin_compute_timeout(pol);
	hw_spin_state_t   state = { };
	hw_lock_status_t  rc = HW_LOCK_CONTENDED;

	if (HW_LOCK_STATE_TO_THREAD(lock->lock_data) ==
	    HW_LOCK_STATE_TO_THREAD(data) && LOCK_CORRECTNESS_PANIC()) {
		panic("hwlock: thread %p is trying to lock %p recursively",
		    HW_LOCK_STATE_TO_THREAD(data), lock);
	}

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_spin_spin_enabled(lock LCK_GRP_ARG(grp));

	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* CONFIG_DTRACE || LOCK_STATS */

	if (!hw_spin_in_ppl(to)) {
		/*
		 * This code is used by the PPL and can't write to globals.
		 */
		lck_spinlock_timeout_set_orig_owner(lock->lock_data);
	}

	do {
		for (uint32_t i = 0; i < LOCK_SNOOP_SPINS; i++) {
			cpu_pause();
			if (hw_lock_trylock_contended(lock, data)) {
				lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
				rc = HW_LOCK_ACQUIRED;
				goto end;
			}
		}
	} while (hw_spin_should_keep_spinning(lock, pol, to, &state));

end:
#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(stat_enabled)) {
		lck_grp_spin_update_spin(lock LCK_GRP_ARG(grp),
		    mach_absolute_time() - begin);
	}
	lck_grp_spin_update_miss(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */
	return rc;
}

static hw_spin_timeout_status_t
hw_wait_while_equals32_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	uint32_t *address = _lock;

	if (!spinlock_timeout_panic) {
		/* keep spinning rather than panicing */
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	panic("wait_while_equals32[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "current value: 0x%08x, " HW_SPIN_TIMEOUT_DETAILS_FMT,
	    address, HW_SPIN_TIMEOUT_ARG(to, st),
	    *address, HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy hw_wait_while_equals32_policy = {
	.hwsp_name              = "hw_wait_while_equals32",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = hw_wait_while_equals32_panic,
};

static hw_spin_timeout_status_t
hw_wait_while_equals64_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	uint64_t *address = _lock;

	if (!spinlock_timeout_panic) {
		/* keep spinning rather than panicing */
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	panic("wait_while_equals64[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "current value: 0x%016llx, " HW_SPIN_TIMEOUT_DETAILS_FMT,
	    address, HW_SPIN_TIMEOUT_ARG(to, st),
	    *address, HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy hw_wait_while_equals64_policy = {
	.hwsp_name              = "hw_wait_while_equals64",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = hw_wait_while_equals64_panic,
};

uint32_t
hw_wait_while_equals32(uint32_t *address, uint32_t current)
{
	hw_spin_policy_t  pol   = &hw_wait_while_equals32_policy;
	hw_spin_timeout_t to    = hw_spin_compute_timeout(pol);
	hw_spin_state_t   state = { };
	uint32_t          v;

	while (__improbable(!hw_spin_wait_until(address, v, v != current))) {
		hw_spin_should_keep_spinning(address, pol, to, &state);
	}

	return v;
}

uint64_t
hw_wait_while_equals64(uint64_t *address, uint64_t current)
{
	hw_spin_policy_t  pol   = &hw_wait_while_equals64_policy;
	hw_spin_timeout_t to    = hw_spin_compute_timeout(pol);
	hw_spin_state_t   state = { };
	uint64_t          v;

	while (__improbable(!hw_spin_wait_until(address, v, v != current))) {
		hw_spin_should_keep_spinning(address, pol, to, &state);
	}

	return v;
}

__result_use_check
static inline hw_lock_status_t
hw_lock_to_internal(
	hw_lock_t               lock,
	thread_t                thread,
	hw_spin_policy_t        pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	uintptr_t state = HW_LOCK_THREAD_TO_STATE(thread);

	if (__probable(hw_lock_trylock_contended(lock, state))) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	return hw_lock_lock_contended(lock, state, pol LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_lock
 *
 *	Acquire lock, spinning until it becomes available,
 *	return with preemption disabled.
 */
void
(hw_lock_lock)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	lock_disable_preemption_for_thread(thread);
	(void)hw_lock_to_internal(lock, thread, &hw_lock_spin_policy
	    LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_lock_nopreempt
 *
 *	Acquire lock, spinning until it becomes available.
 */
void
(hw_lock_lock_nopreempt)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	__lck_require_preemption_disabled(lock, thread);
	(void)hw_lock_to_internal(lock, thread, &hw_lock_spin_policy
	    LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_to
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	Timeout is in mach_absolute_time ticks (TSC in Intel), return with
 *	preemption disabled.
 */
unsigned
int
(hw_lock_to)(hw_lock_t lock, hw_spin_policy_t pol LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	lock_disable_preemption_for_thread(thread);
	return (unsigned)hw_lock_to_internal(lock, thread, pol LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_to_nopreempt
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	Timeout is in mach_absolute_time ticks, called and return with
 *	preemption disabled.
 */
unsigned
int
(hw_lock_to_nopreempt)(hw_lock_t lock, hw_spin_policy_t pol LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	__lck_require_preemption_disabled(lock, thread);
	return (unsigned)hw_lock_to_internal(lock, thread, pol LCK_GRP_ARG(grp));
}

__result_use_check
static inline unsigned int
hw_lock_try_internal(hw_lock_t lock, thread_t thread LCK_GRP_ARG(lck_grp_t *grp))
{
	if (__probable(lock_cmpxchg(&lock->lock_data, 0,
	    HW_LOCK_THREAD_TO_STATE(thread), acquire))) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
		return true;
	}
	return false;
}

/*
 *	Routine: hw_lock_try
 *
 *	returns with preemption disabled on success.
 */
unsigned
int
(hw_lock_try)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	lock_disable_preemption_for_thread(thread);
	unsigned int success = hw_lock_try_internal(lock, thread LCK_GRP_ARG(grp));
	if (!success) {
		lock_enable_preemption();
	}
	return success;
}

unsigned
int
(hw_lock_try_nopreempt)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	__lck_require_preemption_disabled(lock, thread);
	return hw_lock_try_internal(lock, thread LCK_GRP_ARG(grp));
}

#if DEBUG || DEVELOPMENT
__abortlike
static void
__hw_lock_unlock_unowned_panic(hw_lock_t lock)
{
	panic("hwlock: thread %p is trying to lock %p recursively",
	    current_thread(), lock);
}
#endif /* DEBUG || DEVELOPMENT */

/*
 *	Routine: hw_lock_unlock
 *
 *	Unconditionally release lock, release preemption level.
 */
static inline void
hw_lock_unlock_internal(hw_lock_t lock)
{
#if DEBUG || DEVELOPMENT
	if (HW_LOCK_STATE_TO_THREAD(lock->lock_data) != current_thread() &&
	    LOCK_CORRECTNESS_PANIC()) {
		__hw_lock_unlock_unowned_panic(lock);
	}
#endif /* DEBUG || DEVELOPMENT */

	os_atomic_store(&lock->lock_data, 0, release);
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
}

void
(hw_lock_unlock)(hw_lock_t lock)
{
	hw_lock_unlock_internal(lock);
	lock_enable_preemption();
}

void
(hw_lock_unlock_nopreempt)(hw_lock_t lock)
{
	hw_lock_unlock_internal(lock);
}

void
hw_lock_assert(__assert_only hw_lock_t lock, __assert_only unsigned int type)
{
#if MACH_ASSERT
	thread_t thread, holder;

	holder = HW_LOCK_STATE_TO_THREAD(lock->lock_data);
	thread = current_thread();

	if (type == LCK_ASSERT_OWNED) {
		if (holder == 0) {
			panic("Lock not owned %p = %p", lock, holder);
		}
		if (holder != thread) {
			panic("Lock not owned by current thread %p = %p", lock, holder);
		}
	} else if (type == LCK_ASSERT_NOTOWNED) {
		if (holder != THREAD_NULL && holder == thread) {
			panic("Lock owned by current thread %p = %p", lock, holder);
		}
	} else {
		panic("hw_lock_assert(): invalid arg (%u)", type);
	}
#endif /* MACH_ASSERT */
}

/*
 *	Routine hw_lock_held, doesn't change preemption state.
 *	N.B.  Racy, of course.
 */
unsigned int
hw_lock_held(hw_lock_t lock)
{
	return ordered_load_hw(lock) != 0;
}

static hw_lock_status_t NOINLINE
hw_lock_bit_to_contended(
	hw_lock_bit_t          *lock,
	uint32_t                bit,
	hw_spin_policy_t        pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_spin_timeout_t to = hw_spin_compute_timeout(pol);
	hw_spin_state_t   state = { };
	hw_lock_status_t  rc = HW_LOCK_CONTENDED;

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_spin_spin_enabled(lock LCK_GRP_ARG(grp));

	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* LOCK_STATS || CONFIG_DTRACE */

	do {
		for (int i = 0; i < LOCK_SNOOP_SPINS; i++) {
			rc = hw_lock_trylock_bit(lock, bit, true);

			if (rc == HW_LOCK_ACQUIRED) {
				lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
				goto end;
			}
		}

		assert(rc == HW_LOCK_CONTENDED);
	} while (hw_spin_should_keep_spinning(lock, pol, to, &state));

end:
#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(stat_enabled)) {
		lck_grp_spin_update_spin(lock LCK_GRP_ARG(grp),
		    mach_absolute_time() - begin);
	}
	lck_grp_spin_update_miss(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LCK_GRP_STAT */
	return rc;
}

__result_use_check
static inline unsigned int
hw_lock_bit_to_internal(
	hw_lock_bit_t          *lock,
	unsigned int            bit,
	hw_spin_policy_t        pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	if (__probable(hw_lock_trylock_bit(lock, bit, true))) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	return (unsigned)hw_lock_bit_to_contended(lock, bit, pol LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_bit_to
 *
 *	Acquire bit lock, spinning until it becomes available or timeout.
 *	Timeout is in mach_absolute_time ticks (TSC in Intel), return with
 *	preemption disabled.
 */
unsigned
int
(hw_lock_bit_to)(
	hw_lock_bit_t          * lock,
	uint32_t                bit,
	hw_spin_policy_t        pol
	LCK_GRP_ARG(lck_grp_t *grp))
{
	_disable_preemption();
	return hw_lock_bit_to_internal(lock, bit, pol LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_bit
 *
 *	Acquire bit lock, spinning until it becomes available,
 *	return with preemption disabled.
 */
void
(hw_lock_bit)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	_disable_preemption();
	(void)hw_lock_bit_to_internal(lock, bit, &hw_lock_bit_policy LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_bit_nopreempt
 *
 *	Acquire bit lock, spinning until it becomes available.
 */
void
(hw_lock_bit_nopreempt)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	__lck_require_preemption_disabled(lock, current_thread());
	(void)hw_lock_bit_to_internal(lock, bit, &hw_lock_bit_policy LCK_GRP_ARG(grp));
}


unsigned
int
(hw_lock_bit_try)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	boolean_t success = false;

	_disable_preemption();
	success = hw_lock_trylock_bit(lock, bit, false);
	if (!success) {
		lock_enable_preemption();
	}

	if (success) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
	}

	return success;
}

static inline void
hw_unlock_bit_internal(hw_lock_bit_t *lock, unsigned int bit)
{
	os_atomic_andnot(lock, 1u << bit, release);
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lock, bit);
#endif
}

/*
 *	Routine:	hw_unlock_bit
 *
 *		Release spin-lock. The second parameter is the bit number to test and set.
 *		Decrement the preemption level.
 */
void
hw_unlock_bit(hw_lock_bit_t * lock, unsigned int bit)
{
	hw_unlock_bit_internal(lock, bit);
	lock_enable_preemption();
}

void
hw_unlock_bit_nopreempt(hw_lock_bit_t * lock, unsigned int bit)
{
	__lck_require_preemption_disabled(lock, current_thread());
	hw_unlock_bit_internal(lock, bit);
}


#pragma mark - lck_*_sleep

/*
 * Routine:	lck_spin_sleep
 */
wait_result_t
lck_spin_sleep_grp(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	lck_grp_t               *grp)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			lck_spin_lock_grp(lck, grp);
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_spin_unlock(lck);
	}

	return res;
}

wait_result_t
lck_spin_sleep(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	return lck_spin_sleep_grp(lck, lck_sleep_action, event, interruptible, LCK_GRP_NULL);
}

/*
 * Routine:	lck_spin_sleep_deadline
 */
wait_result_t
lck_spin_sleep_deadline(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			lck_spin_lock(lck);
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_spin_unlock(lck);
	}

	return res;
}

/*
 * Routine:	lck_mtx_sleep
 */
wait_result_t
lck_mtx_sleep(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	wait_result_t           res;
	thread_pri_floor_t      token;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * We get a priority floor
		 * during the time that this thread is asleep, so that when it
		 * is re-awakened (and not yet contending on the mutex), it is
		 * runnable at a reasonably high priority.
		 */
		token = thread_priority_floor_start();
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN)) {
				lck_mtx_lock_spin(lck);
			} else if ((lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS)) {
				lck_mtx_lock_spin_always(lck);
			} else {
				lck_mtx_lock(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_mtx_unlock(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}


/*
 * Routine:	lck_mtx_sleep_deadline
 */
wait_result_t
lck_mtx_sleep_deadline(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t           res;
	thread_pri_floor_t      token;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * See lck_mtx_sleep().
		 */
		token = thread_priority_floor_start();
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN)) {
				lck_mtx_lock_spin(lck);
			} else {
				lck_mtx_lock(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_mtx_unlock(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * sleep_with_inheritor and wakeup_with_inheritor KPI
 *
 * Functions that allow to sleep on an event and use turnstile to propagate the priority of the sleeping threads to
 * the latest thread specified as inheritor.
 *
 * The inheritor management is delegated to the caller, the caller needs to store a thread identifier to provide to this functions to specified upon whom
 * direct the push. The inheritor cannot return to user space or exit while holding a push from an event. Therefore is the caller responsibility to call a
 * wakeup_with_inheritor from inheritor before running in userspace or specify another inheritor before letting the old inheritor run in userspace.
 *
 * sleep_with_inheritor requires to hold a locking primitive while invoked, but wakeup_with_inheritor and change_sleep_inheritor don't require it.
 *
 * Turnstile requires a non blocking primitive as interlock to synchronize the turnstile data structure manipulation, threfore sleep_with_inheritor, change_sleep_inheritor and
 * wakeup_with_inheritor will require the same interlock to manipulate turnstiles.
 * If sleep_with_inheritor is associated with a locking primitive that can block (like lck_mtx_t or lck_rw_t), an handoff to a non blocking primitive is required before
 * invoking any turnstile operation.
 *
 * All functions will save the turnstile associated with the event on the turnstile kernel hash table and will use the the turnstile kernel hash table bucket
 * spinlock as the turnstile interlock. Because we do not want to hold interrupt disabled while holding the bucket interlock a new turnstile kernel hash table
 * is instantiated for this KPI to manage the hash without interrupt disabled.
 * Also:
 * - all events on the system that hash on the same bucket will contend on the same spinlock.
 * - every event will have a dedicated wait_queue.
 *
 * Different locking primitives can be associated with sleep_with_inheritor as long as the primitive_lock() and primitive_unlock() functions are provided to
 * sleep_with_inheritor_turnstile to perform the handoff with the bucket spinlock.
 */

static kern_return_t
wakeup_with_inheritor_and_turnstile(
	event_t                 event,
	wait_result_t           result,
	bool                    wake_one,
	lck_wake_action_t       action,
	thread_t               *thread_wokenup)
{
	turnstile_type_t type = TURNSTILE_SLEEP_INHERITOR;
	uint32_t index;
	struct turnstile *ts = NULL;
	kern_return_t ret = KERN_NOT_WAITING;

	/*
	 * the hash bucket spinlock is used as turnstile interlock
	 */
	turnstile_hash_bucket_lock((uintptr_t)event, &index, type);

	ts = turnstile_prepare_hash((uintptr_t)event, type);

	if (wake_one) {
		waitq_wakeup_flags_t flags = WAITQ_WAKEUP_DEFAULT;

		if (action == LCK_WAKE_DEFAULT) {
			flags = WAITQ_UPDATE_INHERITOR;
		} else {
			assert(action == LCK_WAKE_DO_NOT_TRANSFER_PUSH);
		}

		/*
		 * WAITQ_UPDATE_INHERITOR will call turnstile_update_inheritor
		 * if it finds a thread
		 */
		if (thread_wokenup) {
			thread_t wokeup;

			wokeup = waitq_wakeup64_identify(&ts->ts_waitq,
			    CAST_EVENT64_T(event), result, flags);
			*thread_wokenup = wokeup;
			ret = wokeup ? KERN_SUCCESS : KERN_NOT_WAITING;
		} else {
			ret = waitq_wakeup64_one(&ts->ts_waitq,
			    CAST_EVENT64_T(event), result, flags);
		}
		if (ret == KERN_SUCCESS && action == LCK_WAKE_DO_NOT_TRANSFER_PUSH) {
			goto complete;
		}
		if (ret == KERN_NOT_WAITING) {
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL,
			    TURNSTILE_IMMEDIATE_UPDATE);
		}
	} else {
		ret = waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(event),
		    result, WAITQ_UPDATE_INHERITOR);
	}

	/*
	 * turnstile_update_inheritor_complete could be called while holding the interlock.
	 * In this case the new inheritor or is null, or is a thread that is just been woken up
	 * and have not blocked because it is racing with the same interlock used here
	 * after the wait.
	 * So there is no chain to update for the new inheritor.
	 *
	 * However unless the current thread is the old inheritor,
	 * old inheritor can be blocked and requires a chain update.
	 *
	 * The chain should be short because kernel turnstiles cannot have user turnstiles
	 * chained after them.
	 *
	 * We can anyway optimize this by asking turnstile to tell us
	 * if old inheritor needs an update and drop the lock
	 * just in that case.
	 */
	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

complete:
	turnstile_complete_hash((uintptr_t)event, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();

	return ret;
}

static wait_result_t
sleep_with_inheritor_and_turnstile(
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline,
	void                  (^primitive_lock)(void),
	void                  (^primitive_unlock)(void))
{
	turnstile_type_t type = TURNSTILE_SLEEP_INHERITOR;
	wait_result_t ret;
	uint32_t index;
	struct turnstile *ts = NULL;

	/*
	 * the hash bucket spinlock is used as turnstile interlock,
	 * lock it before releasing the primitive lock
	 */
	turnstile_hash_bucket_lock((uintptr_t)event, &index, type);

	primitive_unlock();

	ts = turnstile_prepare_hash((uintptr_t)event, type);

	thread_set_pending_block_hint(current_thread(), kThreadWaitSleepWithInheritor);
	/*
	 * We need TURNSTILE_DELAYED_UPDATE because we will call
	 * waitq_assert_wait64 after.
	 */
	turnstile_update_inheritor(ts, inheritor, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	ret = waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(event), interruptible, deadline);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	/*
	 * Update new and old inheritor chains outside the interlock;
	 */
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	if (ret == THREAD_WAITING) {
		ret = thread_block(THREAD_CONTINUE_NULL);
	}

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

	turnstile_complete_hash((uintptr_t)event, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();

	primitive_lock();

	return ret;
}

/*
 * change_sleep_inheritor is independent from the locking primitive.
 */

/*
 * Name: change_sleep_inheritor
 *
 * Description: Redirect the push of the waiting threads of event to the new inheritor specified.
 *
 * Args:
 *   Arg1: event to redirect the push.
 *   Arg2: new inheritor for event.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: In case of success, the new inheritor cannot return to user space or exit until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *             NOTE: this cannot be called from interrupt context.
 */
kern_return_t
change_sleep_inheritor(event_t event, thread_t inheritor)
{
	uint32_t index;
	struct turnstile *ts = NULL;
	kern_return_t ret =  KERN_SUCCESS;
	turnstile_type_t type = TURNSTILE_SLEEP_INHERITOR;

	/*
	 * the hash bucket spinlock is used as turnstile interlock
	 */
	turnstile_hash_bucket_lock((uintptr_t)event, &index, type);

	ts = turnstile_prepare_hash((uintptr_t)event, type);

	if (!turnstile_has_waiters(ts)) {
		ret = KERN_NOT_WAITING;
	}

	/*
	 * We will not call an assert_wait later so use TURNSTILE_IMMEDIATE_UPDATE
	 */
	turnstile_update_inheritor(ts, inheritor, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	/*
	 * update the chains outside the interlock
	 */
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

	turnstile_complete_hash((uintptr_t)event, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();

	return ret;
}

wait_result_t
lck_spin_sleep_with_inheritor(
	lck_spin_t *lock,
	lck_sleep_action_t lck_sleep_action,
	event_t event,
	thread_t inheritor,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile(event, inheritor,
		           interruptible, deadline,
		           ^{}, ^{ lck_spin_unlock(lock); });
	} else {
		return sleep_with_inheritor_and_turnstile(event, inheritor,
		           interruptible, deadline,
		           ^{ lck_spin_lock(lock); }, ^{ lck_spin_unlock(lock); });
	}
}

wait_result_t
hw_lck_ticket_sleep_with_inheritor(
	hw_lck_ticket_t *lock,
	lck_grp_t *grp __unused,
	lck_sleep_action_t lck_sleep_action,
	event_t event,
	thread_t inheritor,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile(event, inheritor,
		           interruptible, deadline,
		           ^{}, ^{ hw_lck_ticket_unlock(lock); });
	} else {
		return sleep_with_inheritor_and_turnstile(event, inheritor,
		           interruptible, deadline,
		           ^{ hw_lck_ticket_lock(lock, grp); }, ^{ hw_lck_ticket_unlock(lock); });
	}
}

wait_result_t
lck_ticket_sleep_with_inheritor(
	lck_ticket_t *lock,
	lck_grp_t *grp,
	lck_sleep_action_t lck_sleep_action,
	event_t event,
	thread_t inheritor,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile(event, inheritor,
		           interruptible, deadline,
		           ^{}, ^{ lck_ticket_unlock(lock); });
	} else {
		return sleep_with_inheritor_and_turnstile(event, inheritor,
		           interruptible, deadline,
		           ^{ lck_ticket_lock(lock, grp); }, ^{ lck_ticket_unlock(lock); });
	}
}

wait_result_t
lck_mtx_sleep_with_inheritor(
	lck_mtx_t              *lock,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{;},
		           ^{lck_mtx_unlock(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN) {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{lck_mtx_lock_spin(lock);},
		           ^{lck_mtx_unlock(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS) {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{lck_mtx_lock_spin_always(lock);},
		           ^{lck_mtx_unlock(lock);});
	} else {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{lck_mtx_lock(lock);},
		           ^{lck_mtx_unlock(lock);});
	}
}

/*
 * sleep_with_inheritor functions with lck_rw_t as locking primitive.
 */

wait_result_t
lck_rw_sleep_with_inheritor(
	lck_rw_t               *lock,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	__block lck_rw_type_t lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;

	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{;},
		           ^{lck_rw_type = lck_rw_done(lock);});
	} else if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{lck_rw_lock(lock, lck_rw_type);},
		           ^{lck_rw_type = lck_rw_done(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{lck_rw_lock_exclusive(lock);},
		           ^{lck_rw_type = lck_rw_done(lock);});
	} else {
		return sleep_with_inheritor_and_turnstile(event,
		           inheritor,
		           interruptible,
		           deadline,
		           ^{lck_rw_lock_shared(lock);},
		           ^{lck_rw_type = lck_rw_done(lock);});
	}
}

/*
 * wakeup_with_inheritor functions are independent from the locking primitive.
 */

kern_return_t
wakeup_one_with_inheritor(event_t event, wait_result_t result, lck_wake_action_t action, thread_t *thread_wokenup)
{
	return wakeup_with_inheritor_and_turnstile(event,
	           result,
	           TRUE,
	           action,
	           thread_wokenup);
}

kern_return_t
wakeup_all_with_inheritor(event_t event, wait_result_t result)
{
	return wakeup_with_inheritor_and_turnstile(event,
	           result,
	           FALSE,
	           0,
	           NULL);
}

void
kdp_sleep_with_inheritor_find_owner(struct waitq * waitq, __unused event64_t event, thread_waitinfo_t * waitinfo)
{
	assert(waitinfo->wait_type == kThreadWaitSleepWithInheritor);
	assert(waitq_type(waitq) == WQT_TURNSTILE);
	waitinfo->owner = 0;
	waitinfo->context = 0;

	if (waitq_held(waitq)) {
		return;
	}

	struct turnstile *turnstile = waitq_to_turnstile(waitq);
	assert(turnstile->ts_inheritor_flags & TURNSTILE_INHERITOR_THREAD);
	waitinfo->owner = thread_tid(turnstile->ts_inheritor);
}

static_assert(SWI_COND_OWNER_BITS == CTID_SIZE_BIT);
static_assert(sizeof(cond_swi_var32_s) == sizeof(uint32_t));
static_assert(sizeof(cond_swi_var64_s) == sizeof(uint64_t));

static wait_result_t
cond_sleep_with_inheritor_and_turnstile_type(
	cond_swi_var_t cond,
	bool (^cond_sleep_check)(ctid_t*),
	wait_interrupt_t interruptible,
	uint64_t deadline,
	turnstile_type_t type)
{
	wait_result_t ret;
	uint32_t index;
	struct turnstile *ts = NULL;
	ctid_t ctid = 0;
	thread_t inheritor;

	/*
	 * the hash bucket spinlock is used as turnstile interlock,
	 * lock it before checking the sleep condition
	 */
	turnstile_hash_bucket_lock((uintptr_t)cond, &index, type);

	/*
	 * In case the sleep check succeeds, the block will
	 * provide us the ctid observed on the variable.
	 */
	if (!cond_sleep_check(&ctid)) {
		turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);
		return THREAD_NOT_WAITING;
	}

	/*
	 * We can translate the ctid to a thread_t only
	 * if cond_sleep_check succeded.
	 */
	inheritor = ctid_get_thread(ctid);
	assert(inheritor != NULL);

	ts = turnstile_prepare_hash((uintptr_t)cond, type);

	thread_set_pending_block_hint(current_thread(), kThreadWaitSleepWithInheritor);
	/*
	 * We need TURNSTILE_DELAYED_UPDATE because we will call
	 * waitq_assert_wait64 after.
	 */
	turnstile_update_inheritor(ts, inheritor, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	ret = waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(cond), interruptible, deadline);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	/*
	 * Update new and old inheritor chains outside the interlock;
	 */
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);
	if (ret == THREAD_WAITING) {
		ret = thread_block(THREAD_CONTINUE_NULL);
	}

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

	turnstile_complete_hash((uintptr_t)cond, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();
	return ret;
}

/*
 * Name: cond_sleep_with_inheritor32_mask
 *
 * Description: Conditionally sleeps with inheritor, with condition variable of 32bits.
 *              Allows a thread to conditionally sleep while indicating which thread should
 *              inherit the priority push associated with the condition.
 *              The condition should be expressed through a cond_swi_var32_s pointer.
 *              The condition needs to be populated by the caller with the ctid of the
 *              thread that should inherit the push. The remaining bits of the condition
 *              can be used by the caller to implement its own synchronization logic.
 *              A copy of the condition value observed by the caller when it decided to call
 *              this function should be provided to prevent races with matching wakeups.
 *              This function will atomically check the value stored in the condition against
 *              the expected/observed one provided only for the bits that are set in the mask.
 *              If the check doesn't pass the thread will not sleep and the function will return.
 *              The ctid provided in the condition will be used only after a successful
 *              check.
 *
 * Args:
 *   Arg1: cond_swi_var32_s pointer that stores the condition to check.
 *   Arg2: cond_swi_var32_s observed value to check for conditionally sleep.
 *   Arg3: mask to apply to the condition to check.
 *   Arg4: interruptible flag for wait.
 *   Arg5: deadline for wait.
 *
 * Conditions: The inheritor specified cannot return to user space or exit until another inheritor is specified for the cond or a
 *             wakeup for the cond is called.
 *
 * Returns: result of the wait.
 */
static wait_result_t
cond_sleep_with_inheritor32_mask(cond_swi_var_t cond, cond_swi_var32_s expected_cond, uint32_t check_mask, wait_interrupt_t interruptible, uint64_t deadline)
{
	bool (^cond_sleep_check)(uint32_t*) = ^(ctid_t *ctid) {
		cond_swi_var32_s cond_val = {.cond32_data = os_atomic_load((uint32_t*) cond, relaxed)};
		bool ret;
		if ((cond_val.cond32_data & check_mask) == (expected_cond.cond32_data & check_mask)) {
			ret = true;
			*ctid = cond_val.cond32_owner;
		} else {
			ret = false;
		}
		return ret;
	};

	return cond_sleep_with_inheritor_and_turnstile_type(cond, cond_sleep_check, interruptible, deadline, TURNSTILE_SLEEP_INHERITOR);
}

/*
 * Name: cond_sleep_with_inheritor64_mask
 *
 * Description: Conditionally sleeps with inheritor, with condition variable of 64bits.
 *              Allows a thread to conditionally sleep while indicating which thread should
 *              inherit the priority push associated with the condition.
 *              The condition should be expressed through a cond_swi_var64_s pointer.
 *              The condition needs to be populated by the caller with the ctid of the
 *              thread that should inherit the push. The remaining bits of the condition
 *              can be used by the caller to implement its own synchronization logic.
 *              A copy of the condition value observed by the caller when it decided to call
 *              this function should be provided to prevent races with matching wakeups.
 *              This function will atomically check the value stored in the condition against
 *              the expected/observed one provided only for the bits that are set in the mask.
 *              If the check doesn't pass the thread will not sleep and the function will return.
 *              The ctid provided in the condition will be used only after a successful
 *              check.
 *
 * Args:
 *   Arg1: cond_swi_var64_s pointer that stores the condition to check.
 *   Arg2: cond_swi_var64_s observed value to check for conditionally sleep.
 *   Arg3: mask to apply to the condition to check.
 *   Arg4: interruptible flag for wait.
 *   Arg5: deadline for wait.
 *
 * Conditions: The inheritor specified cannot return to user space or exit until another inheritor is specified for the cond or a
 *             wakeup for the cond is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
cond_sleep_with_inheritor64_mask(cond_swi_var_t cond, cond_swi_var64_s expected_cond, uint64_t check_mask, wait_interrupt_t interruptible, uint64_t deadline)
{
	bool (^cond_sleep_check)(uint32_t*) = ^(ctid_t *ctid) {
		cond_swi_var64_s cond_val = {.cond64_data = os_atomic_load((uint64_t*) cond, relaxed)};
		bool ret;
		if ((cond_val.cond64_data & check_mask) == (expected_cond.cond64_data & check_mask)) {
			ret = true;
			*ctid = cond_val.cond64_owner;
		} else {
			ret = false;
		}
		return ret;
	};

	return cond_sleep_with_inheritor_and_turnstile_type(cond, cond_sleep_check, interruptible, deadline, TURNSTILE_SLEEP_INHERITOR);
}

/*
 * Name: cond_sleep_with_inheritor32
 *
 * Description: Conditionally sleeps with inheritor, with condition variable of 32bits.
 *              Allows a thread to conditionally sleep while indicating which thread should
 *              inherit the priority push associated with the condition.
 *              The condition should be expressed through a cond_swi_var32_s pointer.
 *              The condition needs to be populated by the caller with the ctid of the
 *              thread that should inherit the push. The remaining bits of the condition
 *              can be used by the caller to implement its own synchronization logic.
 *              A copy of the condition value observed by the caller when it decided to call
 *              this function should be provided to prevent races with matching wakeups.
 *              This function will atomically check the value stored in the condition against
 *              the expected/observed one provided. If the check doesn't pass the thread will not
 *              sleep and the function will return.
 *              The ctid provided in the condition will be used only after a successful
 *              check.
 *
 * Args:
 *   Arg1: cond_swi_var32_s pointer that stores the condition to check.
 *   Arg2: cond_swi_var32_s observed value to check for conditionally sleep.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline for wait.
 *
 * Conditions: The inheritor specified cannot return to user space or exit until another inheritor is specified for the cond or a
 *             wakeup for the cond is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
cond_sleep_with_inheritor32(cond_swi_var_t cond, cond_swi_var32_s expected_cond, wait_interrupt_t interruptible, uint64_t deadline)
{
	return cond_sleep_with_inheritor32_mask(cond, expected_cond, ~0u, interruptible, deadline);
}

/*
 * Name: cond_sleep_with_inheritor64
 *
 * Description: Conditionally sleeps with inheritor, with condition variable of 64bits.
 *              Allows a thread to conditionally sleep while indicating which thread should
 *              inherit the priority push associated with the condition.
 *              The condition should be expressed through a cond_swi_var64_s pointer.
 *              The condition needs to be populated by the caller with the ctid of the
 *              thread that should inherit the push. The remaining bits of the condition
 *              can be used by the caller to implement its own synchronization logic.
 *              A copy of the condition value observed by the caller when it decided to call
 *              this function should be provided to prevent races with matching wakeups.
 *              This function will atomically check the value stored in the condition against
 *              the expected/observed one provided. If the check doesn't pass the thread will not
 *              sleep and the function will return.
 *              The ctid provided in the condition will be used only after a successful
 *              check.
 *
 * Args:
 *   Arg1: cond_swi_var64_s pointer that stores the condition to check.
 *   Arg2: cond_swi_var64_s observed value to check for conditionally sleep.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline for wait.
 *
 * Conditions: The inheritor specified cannot return to user space or exit until another inheritor is specified for the cond or a
 *             wakeup for the cond is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
cond_sleep_with_inheritor64(cond_swi_var_t cond, cond_swi_var64_s expected_cond, wait_interrupt_t interruptible, uint64_t deadline)
{
	return cond_sleep_with_inheritor64_mask(cond, expected_cond, ~0ull, interruptible, deadline);
}

/*
 * Name: cond_wakeup_one_with_inheritor
 *
 * Description: Wake up one waiter waiting on the condition (if any).
 *              The thread woken up will be the one with the higher sched priority waiting on the condition.
 *              The push for the condition will be transferred from the last inheritor to the woken up thread.
 *
 * Args:
 *   Arg1: condition to wake from.
 *   Arg2: wait result to pass to the woken up thread.
 *   Arg3: pointer for storing the thread wokenup.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: The new inheritor wokenup cannot return to user space or exit until another inheritor is specified for the
 *             condition or a wakeup for the event is called.
 *             A reference for the wokenup thread is acquired.
 *             NOTE: this cannot be called from interrupt context.
 */
kern_return_t
cond_wakeup_one_with_inheritor(cond_swi_var_t cond, wait_result_t result, lck_wake_action_t action, thread_t *thread_wokenup)
{
	return wakeup_with_inheritor_and_turnstile((event_t)cond,
	           result,
	           TRUE,
	           action,
	           thread_wokenup);
}

/*
 * Name: cond_wakeup_all_with_inheritor
 *
 * Description: Wake up all waiters waiting on the same condition. The old inheritor will lose the push.
 *
 * Args:
 *   Arg1: condition to wake from.
 *   Arg2: wait result to pass to the woken up threads.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: NOTE: this cannot be called from interrupt context.
 */
kern_return_t
cond_wakeup_all_with_inheritor(cond_swi_var_t cond, wait_result_t result)
{
	return wakeup_with_inheritor_and_turnstile((event_t)cond,
	           result,
	           FALSE,
	           0,
	           NULL);
}


#pragma mark - gates

#define GATE_TYPE        3
#define GATE_ILOCK_BIT   0
#define GATE_WAITERS_BIT 1

#define GATE_ILOCK (1 << GATE_ILOCK_BIT)
#define GATE_WAITERS (1 << GATE_WAITERS_BIT)

#define gate_ilock(gate) hw_lock_bit((hw_lock_bit_t*)(&(gate)->gt_data), GATE_ILOCK_BIT, LCK_GRP_NULL)
#define gate_iunlock(gate) hw_unlock_bit((hw_lock_bit_t*)(&(gate)->gt_data), GATE_ILOCK_BIT)
#define gate_has_waiter_bit(state) ((state & GATE_WAITERS) != 0)
#define ordered_load_gate(gate) os_atomic_load(&(gate)->gt_data, compiler_acq_rel)
#define ordered_store_gate(gate, value)  os_atomic_store(&(gate)->gt_data, value, compiler_acq_rel)

#define GATE_THREAD_MASK (~(uintptr_t)(GATE_ILOCK | GATE_WAITERS))
#define GATE_STATE_TO_THREAD(state) (thread_t)((state) & GATE_THREAD_MASK)
#define GATE_STATE_MASKED(state) (uintptr_t)((state) & GATE_THREAD_MASK)
#define GATE_THREAD_TO_STATE(thread) ((uintptr_t)(thread))

#define GATE_DESTROYED GATE_STATE_MASKED(0xdeadbeefdeadbeef)

#define GATE_EVENT(gate)     ((event_t) gate)
#define EVENT_TO_GATE(event) ((gate_t *) event)

typedef void (*void_func_void)(void);

__abortlike
static void
gate_verify_tag_panic(gate_t *gate)
{
	panic("Gate used is invalid. gate %p data %lx turnstile %p refs %d flags %x ", gate, gate->gt_data, gate->gt_turnstile, gate->gt_refs, gate->gt_flags);
}

__abortlike
static void
gate_verify_destroy_panic(gate_t *gate)
{
	panic("Gate used was destroyed. gate %p data %lx turnstile %p refs %d flags %x", gate, gate->gt_data, gate->gt_turnstile, gate->gt_refs, gate->gt_flags);
}

static void
gate_verify(gate_t *gate)
{
	if (gate->gt_type != GATE_TYPE) {
		gate_verify_tag_panic(gate);
	}
	if (GATE_STATE_MASKED(gate->gt_data) == GATE_DESTROYED) {
		gate_verify_destroy_panic(gate);
	}

	assert(gate->gt_refs > 0);
}

__abortlike
static void
gate_already_owned_panic(gate_t *gate, thread_t holder)
{
	panic("Trying to close a gate already closed gate %p holder %p current_thread %p", gate, holder, current_thread());
}

static kern_return_t
gate_try_close(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	kern_return_t ret;
	thread_t thread = current_thread();

	gate_verify(gate);

	if (os_atomic_cmpxchg(&gate->gt_data, 0, GATE_THREAD_TO_STATE(thread), acquire)) {
		return KERN_SUCCESS;
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	if (holder == NULL) {
		assert(gate_has_waiter_bit(state) == FALSE);

		state = GATE_THREAD_TO_STATE(current_thread());
		state |= GATE_ILOCK;
		ordered_store_gate(gate, state);
		ret = KERN_SUCCESS;
	} else {
		if (holder == current_thread()) {
			gate_already_owned_panic(gate, holder);
		}
		ret = KERN_FAILURE;
	}

	gate_iunlock(gate);
	return ret;
}

static void
gate_close(gate_t* gate)
{
	uintptr_t state;
	thread_t holder;
	thread_t thread = current_thread();

	gate_verify(gate);

	if (os_atomic_cmpxchg(&gate->gt_data, 0, GATE_THREAD_TO_STATE(thread), acquire)) {
		return;
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	if (holder != NULL) {
		gate_already_owned_panic(gate, holder);
	}

	assert(gate_has_waiter_bit(state) == FALSE);

	state = GATE_THREAD_TO_STATE(thread);
	state |= GATE_ILOCK;
	ordered_store_gate(gate, state);

	gate_iunlock(gate);
}

static void
gate_open_turnstile(gate_t *gate)
{
	struct turnstile *ts = NULL;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile,
	    TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
	waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(GATE_EVENT(gate)),
	    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);
	/*
	 * We can do the cleanup while holding the interlock.
	 * It is ok because:
	 * 1. current_thread is the previous inheritor and it is running
	 * 2. new inheritor is NULL.
	 * => No chain of turnstiles needs to be updated.
	 */
	turnstile_cleanup();
}

__abortlike
static void
gate_not_owned_panic(gate_t *gate, thread_t holder, bool open)
{
	if (open) {
		panic("Trying to open a gate %p owned by %p from current_thread %p", gate, holder, current_thread());
	} else {
		panic("Trying to handoff a gate %p owned by %p from current_thread %p", gate, holder, current_thread());
	}
}

static void
gate_open(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	bool waiters;
	thread_t thread = current_thread();

	gate_verify(gate);
	if (os_atomic_cmpxchg(&gate->gt_data, GATE_THREAD_TO_STATE(thread), 0, release)) {
		return;
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);
	waiters = gate_has_waiter_bit(state);

	if (holder != thread) {
		gate_not_owned_panic(gate, holder, true);
	}

	if (waiters) {
		gate_open_turnstile(gate);
	}

	state = GATE_ILOCK;
	ordered_store_gate(gate, state);

	gate_iunlock(gate);
}

static kern_return_t
gate_handoff_turnstile(gate_t *gate,
    int flags,
    thread_t *thread_woken_up,
    bool *waiters)
{
	struct turnstile *ts = NULL;
	kern_return_t ret = KERN_FAILURE;
	thread_t hp_thread;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
	/*
	 * Wake up the higest priority thread waiting on the gate
	 */
	hp_thread = waitq_wakeup64_identify(&ts->ts_waitq, CAST_EVENT64_T(GATE_EVENT(gate)),
	    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);

	if (hp_thread != NULL) {
		/*
		 * In this case waitq_wakeup64_identify has called turnstile_update_inheritor for us
		 */
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		*thread_woken_up = hp_thread;
		*waiters = turnstile_has_waiters(ts);
		/*
		 * Note: hp_thread is the new holder and the new inheritor.
		 * In case there are no more waiters, it doesn't need to be the inheritor
		 * and it shouldn't be it by the time it finishes the wait, so that its next open or
		 * handoff can go through the fast path.
		 * We could set the inheritor to NULL here, or the new holder itself can set it
		 * on its way back from the sleep. In the latter case there are more chanses that
		 * new waiters will come by, avoiding to do the opearation at all.
		 */
		ret = KERN_SUCCESS;
	} else {
		/*
		 * waiters can have been woken up by an interrupt and still not
		 * have updated gate->waiters, so we couldn't find them on the waitq.
		 * Update the inheritor to NULL here, so that the current thread can return to userspace
		 * indipendently from when the interrupted waiters will finish the wait.
		 */
		if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
			turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		}
		// there are no waiters.
		ret = KERN_NOT_WAITING;
	}

	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);

	/*
	 * We can do the cleanup while holding the interlock.
	 * It is ok because:
	 * 1. current_thread is the previous inheritor and it is running
	 * 2. new inheritor is NULL or it is a just wokenup thread that will race acquiring the lock
	 *    of the gate before trying to sleep.
	 * => No chain of turnstiles needs to be updated.
	 */
	turnstile_cleanup();

	return ret;
}

static kern_return_t
gate_handoff(gate_t *gate,
    int flags)
{
	kern_return_t ret;
	thread_t new_holder = NULL;
	uintptr_t state;
	thread_t holder;
	bool waiters;
	thread_t thread = current_thread();

	assert(flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS || flags == GATE_HANDOFF_DEFAULT);
	gate_verify(gate);

	if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
		if (os_atomic_cmpxchg(&gate->gt_data, GATE_THREAD_TO_STATE(thread), 0, release)) {
			//gate opened but there were no waiters, so return KERN_NOT_WAITING.
			return KERN_NOT_WAITING;
		}
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);
	waiters = gate_has_waiter_bit(state);

	if (holder != current_thread()) {
		gate_not_owned_panic(gate, holder, false);
	}

	if (waiters) {
		ret = gate_handoff_turnstile(gate, flags, &new_holder, &waiters);
		if (ret == KERN_SUCCESS) {
			state = GATE_THREAD_TO_STATE(new_holder);
			if (waiters) {
				state |= GATE_WAITERS;
			}
		} else {
			if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
				state = 0;
			}
		}
	} else {
		if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
			state = 0;
		}
		ret = KERN_NOT_WAITING;
	}
	state |= GATE_ILOCK;
	ordered_store_gate(gate, state);

	gate_iunlock(gate);

	if (new_holder) {
		thread_deallocate(new_holder);
	}
	return ret;
}

static void_func_void
gate_steal_turnstile(gate_t *gate,
    thread_t new_inheritor)
{
	struct turnstile *ts = NULL;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	turnstile_update_inheritor(ts, new_inheritor, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);

	/*
	 * turnstile_cleanup might need to update the chain of the old holder.
	 * This operation should happen without the turnstile interlock held.
	 */
	return turnstile_cleanup;
}

__abortlike
static void
gate_not_closed_panic(gate_t *gate, bool wait)
{
	if (wait) {
		panic("Trying to wait on a not closed gate %p from current_thread %p", gate, current_thread());
	} else {
		panic("Trying to steal a not closed gate %p from current_thread %p", gate, current_thread());
	}
}

static void
gate_steal(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	thread_t thread = current_thread();
	bool waiters;

	void_func_void func_after_interlock_unlock;

	gate_verify(gate);

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);
	waiters = gate_has_waiter_bit(state);

	if (holder == NULL) {
		gate_not_closed_panic(gate, false);
	}

	state = GATE_THREAD_TO_STATE(thread) | GATE_ILOCK;
	if (waiters) {
		state |= GATE_WAITERS;
		ordered_store_gate(gate, state);
		func_after_interlock_unlock = gate_steal_turnstile(gate, thread);
		gate_iunlock(gate);

		func_after_interlock_unlock();
	} else {
		ordered_store_gate(gate, state);
		gate_iunlock(gate);
	}
}

static void_func_void
gate_wait_turnstile(gate_t *gate,
    wait_interrupt_t interruptible,
    uint64_t deadline,
    thread_t holder,
    wait_result_t* wait,
    bool* waiters)
{
	struct turnstile *ts;
	uintptr_t state;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	turnstile_update_inheritor(ts, holder, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));
	waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(GATE_EVENT(gate)), interruptible, deadline);

	gate_iunlock(gate);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	*wait = thread_block(THREAD_CONTINUE_NULL);

	gate_ilock(gate);

	*waiters = turnstile_has_waiters(ts);

	if (!*waiters) {
		/*
		 * We want to enable the fast path as soon as we see that there are no more waiters.
		 * On the fast path the holder will not do any turnstile operations.
		 * Set the inheritor as NULL here.
		 *
		 * NOTE: if it was an open operation that woke this thread up, the inheritor has
		 * already been set to NULL.
		 */
		state = ordered_load_gate(gate);
		holder = GATE_STATE_TO_THREAD(state);
		if (holder &&
		    ((*wait != THREAD_AWAKENED) ||     // thread interrupted or timedout
		    holder == current_thread())) {     // thread was woken up and it is the new holder
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
			turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);
		}
	}

	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);

	/*
	 * turnstile_cleanup might need to update the chain of the old holder.
	 * This operation should happen without the turnstile primitive interlock held.
	 */
	return turnstile_cleanup;
}

static void
gate_free_internal(gate_t *gate)
{
	zfree(KT_GATE, gate);
}

__abortlike
static void
gate_too_many_refs_panic(gate_t *gate)
{
	panic("Too many refs taken on gate. gate %p data %lx turnstile %p refs %d flags %x", gate, gate->gt_data, gate->gt_turnstile, gate->gt_refs, gate->gt_flags);
}

static gate_wait_result_t
gate_wait(gate_t* gate,
    wait_interrupt_t interruptible,
    uint64_t deadline,
    void (^primitive_unlock)(void),
    void (^primitive_lock)(void))
{
	gate_wait_result_t ret;
	void_func_void func_after_interlock_unlock;
	wait_result_t wait_result;
	uintptr_t state;
	thread_t holder;
	bool waiters;

	gate_verify(gate);

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	if (holder == NULL) {
		gate_not_closed_panic(gate, true);
	}

	/*
	 * Get a ref on the gate so it will not
	 * be freed while we are coming back from the sleep.
	 */
	if (gate->gt_refs == UINT16_MAX) {
		gate_too_many_refs_panic(gate);
	}
	gate->gt_refs++;
	state |= GATE_WAITERS;
	ordered_store_gate(gate, state);

	/*
	 * Release the primitive lock before any
	 * turnstile operation. Turnstile
	 * does not support a blocking primitive as
	 * interlock.
	 *
	 * In this way, concurrent threads will be
	 * able to acquire the primitive lock
	 * but still will wait for me through the
	 * gate interlock.
	 */
	primitive_unlock();

	func_after_interlock_unlock = gate_wait_turnstile(    gate,
	    interruptible,
	    deadline,
	    holder,
	    &wait_result,
	    &waiters);

	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	switch (wait_result) {
	case THREAD_INTERRUPTED:
	case THREAD_TIMED_OUT:
		assert(holder != current_thread());

		if (waiters) {
			state |= GATE_WAITERS;
		} else {
			state &= ~GATE_WAITERS;
		}
		ordered_store_gate(gate, state);

		if (wait_result == THREAD_INTERRUPTED) {
			ret = GATE_INTERRUPTED;
		} else {
			ret = GATE_TIMED_OUT;
		}
		break;
	default:
		/*
		 * Note it is possible that even if the gate was handed off to
		 * me, someone called gate_steal() before I woke up.
		 *
		 * As well as it is possible that the gate was opened, but someone
		 * closed it while I was waking up.
		 *
		 * In both cases we return GATE_OPENED, as the gate was opened to me
		 * at one point, it is the caller responsibility to check again if
		 * the gate is open.
		 */
		if (holder == current_thread()) {
			ret = GATE_HANDOFF;
		} else {
			ret = GATE_OPENED;
		}
		break;
	}

	assert(gate->gt_refs > 0);
	uint32_t ref = --gate->gt_refs;
	bool to_free = gate->gt_alloc;
	gate_iunlock(gate);

	if (GATE_STATE_MASKED(state) == GATE_DESTROYED) {
		if (to_free == true) {
			assert(!waiters);
			if (ref == 0) {
				gate_free_internal(gate);
			}
			ret = GATE_OPENED;
		} else {
			gate_verify_destroy_panic(gate);
		}
	}

	/*
	 * turnstile func that needs to be executed without
	 * holding the primitive interlock
	 */
	func_after_interlock_unlock();

	primitive_lock();

	return ret;
}

static void
gate_assert(gate_t *gate, int flags)
{
	uintptr_t state;
	thread_t holder;

	gate_verify(gate);

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	switch (flags) {
	case GATE_ASSERT_CLOSED:
		assert(holder != NULL);
		break;
	case GATE_ASSERT_OPEN:
		assert(holder == NULL);
		break;
	case GATE_ASSERT_HELD:
		assert(holder == current_thread());
		break;
	default:
		panic("invalid %s flag %d", __func__, flags);
	}

	gate_iunlock(gate);
}

enum {
	GT_INIT_DEFAULT = 0,
	GT_INIT_ALLOC
};

static void
gate_init(gate_t *gate, uint type)
{
	bzero(gate, sizeof(gate_t));

	gate->gt_data = 0;
	gate->gt_turnstile = NULL;
	gate->gt_refs = 1;
	switch (type) {
	case GT_INIT_ALLOC:
		gate->gt_alloc = 1;
		break;
	default:
		gate->gt_alloc = 0;
		break;
	}
	gate->gt_type = GATE_TYPE;
	gate->gt_flags_pad = 0;
}

static gate_t*
gate_alloc_init(void)
{
	gate_t *gate;
	gate = zalloc_flags(KT_GATE, Z_WAITOK | Z_NOFAIL);
	gate_init(gate, GT_INIT_ALLOC);
	return gate;
}

__abortlike
static void
gate_destroy_owned_panic(gate_t *gate, thread_t holder)
{
	panic("Trying to destroy a gate owned by %p. Gate %p", holder, gate);
}

__abortlike
static void
gate_destroy_waiter_panic(gate_t *gate)
{
	panic("Trying to destroy a gate with waiters. Gate %p data %lx turnstile %p", gate, gate->gt_data, gate->gt_turnstile);
}

static uint16_t
gate_destroy_internal(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	uint16_t ref;

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	/*
	 * The gate must be open
	 * and all the threads must
	 * have been woken up by this time
	 */
	if (holder != NULL) {
		gate_destroy_owned_panic(gate, holder);
	}
	if (gate_has_waiter_bit(state)) {
		gate_destroy_waiter_panic(gate);
	}

	assert(gate->gt_refs > 0);

	ref = --gate->gt_refs;

	/*
	 * Mark the gate as destroyed.
	 * The interlock bit still need
	 * to be available to let the
	 * last wokenup threads to clear
	 * the wait.
	 */
	state = GATE_DESTROYED;
	state |= GATE_ILOCK;
	ordered_store_gate(gate, state);
	gate_iunlock(gate);
	return ref;
}

__abortlike
static void
gate_destroy_panic(gate_t *gate)
{
	panic("Trying to destroy a gate that was allocated by gate_alloc_init(). gate_free() should be used instead, gate %p thread %p", gate, current_thread());
}

static void
gate_destroy(gate_t *gate)
{
	gate_verify(gate);
	if (gate->gt_alloc == 1) {
		gate_destroy_panic(gate);
	}
	gate_destroy_internal(gate);
}

__abortlike
static void
gate_free_panic(gate_t *gate)
{
	panic("Trying to free a gate that was not allocated by gate_alloc_init(), gate %p thread %p", gate, current_thread());
}

static void
gate_free(gate_t *gate)
{
	uint16_t ref;

	gate_verify(gate);

	if (gate->gt_alloc == 0) {
		gate_free_panic(gate);
	}

	ref = gate_destroy_internal(gate);
	/*
	 * Some of the threads waiting on the gate
	 * might still need to run after being woken up.
	 * They will access the gate to cleanup the
	 * state, so we cannot free it.
	 * The last waiter will free the gate in this case.
	 */
	if (ref == 0) {
		gate_free_internal(gate);
	}
}

/*
 * Name: lck_rw_gate_init
 *
 * Description: initializes a variable declared with decl_lck_rw_gate_data.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 */
void
lck_rw_gate_init(lck_rw_t *lock, gate_t *gate)
{
	(void) lock;
	gate_init(gate, GT_INIT_DEFAULT);
}

/*
 * Name: lck_rw_gate_alloc_init
 *
 * Description: allocates and initializes a gate_t.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *
 * Returns:
 *         gate_t allocated.
 */
gate_t*
lck_rw_gate_alloc_init(lck_rw_t *lock)
{
	(void) lock;
	return gate_alloc_init();
}

/*
 * Name: lck_rw_gate_destroy
 *
 * Description: destroys a variable previously initialized
 *              with lck_rw_gate_init().
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 */
void
lck_rw_gate_destroy(lck_rw_t *lock, gate_t *gate)
{
	(void) lock;
	gate_destroy(gate);
}

/*
 * Name: lck_rw_gate_free
 *
 * Description: destroys and tries to free a gate previously allocated
 *              with lck_rw_gate_alloc_init().
 *              The gate free might be delegated to the last thread returning
 *              from the gate_wait().
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate obtained with lck_rw_gate_alloc_init().
 */
void
lck_rw_gate_free(lck_rw_t *lock, gate_t *gate)
{
	(void) lock;
	gate_free(gate);
}

/*
 * Name: lck_rw_gate_try_close
 *
 * Description: Tries to close the gate.
 *              In case of success the current thread will be set as
 *              the holder of the gate.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *
 * Returns:
 *          KERN_SUCCESS in case the gate was successfully closed. The current thread is the new holder
 *          of the gate.
 *          A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *          to wake up possible waiters on the gate before returning to userspace.
 *          If the intent is to conditionally probe the gate before waiting, the lock must not be dropped
 *          between the calls to lck_rw_gate_try_close() and lck_rw_gate_wait().
 *
 *          KERN_FAILURE in case the gate was already closed. Will panic if the current thread was already the holder of the gate.
 *          lck_rw_gate_wait() should be called instead if the intent is to unconditionally wait on this gate.
 *          The calls to lck_rw_gate_try_close() and lck_rw_gate_wait() should
 *          be done without dropping the lock that is protecting the gate in between.
 */
int
lck_rw_gate_try_close(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	return gate_try_close(gate);
}

/*
 * Name: lck_rw_gate_close
 *
 * Description: Closes the gate. The current thread will be set as
 *              the holder of the gate. Will panic if the gate is already closed.
 *              A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be open.
 *
 */
void
lck_rw_gate_close(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	return gate_close(gate);
}

/*
 * Name: lck_rw_gate_open
 *
 * Description: Opens the gate and wakes up possible waiters.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 */
void
lck_rw_gate_open(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	gate_open(gate);
}

/*
 * Name: lck_rw_gate_handoff
 *
 * Description: Tries to transfer the ownership of the gate. The waiter with highest sched
 *              priority will be selected as the new holder of the gate, and woken up,
 *              with the gate remaining in the closed state throughout.
 *              If no waiters are present, the gate will be kept closed and KERN_NOT_WAITING
 *              will be returned.
 *              GATE_HANDOFF_OPEN_IF_NO_WAITERS flag can be used to specify if the gate should be opened in
 *              case no waiters were found.
 *
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: flags - GATE_HANDOFF_DEFAULT or GATE_HANDOFF_OPEN_IF_NO_WAITERS
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 * Returns:
 *          KERN_SUCCESS in case one of the waiters became the new holder.
 *          KERN_NOT_WAITING in case there were no waiters.
 *
 */
kern_return_t
lck_rw_gate_handoff(__assert_only lck_rw_t *lock, gate_t *gate, gate_handoff_flags_t flags)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	return gate_handoff(gate, flags);
}

/*
 * Name: lck_rw_gate_steal
 *
 * Description: Set the current ownership of the gate. It sets the current thread as the
 *              new holder of the gate.
 *              A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *              NOTE: the previous holder should not call lck_rw_gate_open() or lck_rw_gate_handoff()
 *              anymore.
 *
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be closed and the current thread must not already be the holder.
 *
 */
void
lck_rw_gate_steal(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	gate_steal(gate);
}

/*
 * Name: lck_rw_gate_wait
 *
 * Description: Waits for the current thread to become the holder of the gate or for the
 *              gate to become open. An interruptible mode and deadline can be specified
 *              to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_SHARED, LCK_SLEEP_EXCLUSIVE, LCK_SLEEP_UNLOCK.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The gate must be closed.
 *
 * Returns: Reason why the thread was woken up.
 *          GATE_HANDOFF - the current thread was handed off the ownership of the gate.
 *                         A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on.
 *                         to wake up possible waiters on the gate before returning to userspace.
 *          GATE_OPENED - the gate was opened by the holder.
 *          GATE_TIMED_OUT - the thread was woken up by a timeout.
 *          GATE_INTERRUPTED - the thread was interrupted while sleeping.
 */
gate_wait_result_t
lck_rw_gate_wait(lck_rw_t *lock, gate_t *gate, lck_sleep_action_t lck_sleep_action, wait_interrupt_t interruptible, uint64_t deadline)
{
	__block lck_rw_type_t lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;

	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{;});
	} else if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{lck_rw_lock(lock, lck_rw_type);});
	} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{lck_rw_lock_exclusive(lock);});
	} else {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{lck_rw_lock_shared(lock);});
	}
}

/*
 * Name: lck_rw_gate_assert
 *
 * Description: asserts that the gate is in the specified state.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: flags to specified assert type.
 *         GATE_ASSERT_CLOSED - the gate is currently closed
 *         GATE_ASSERT_OPEN - the gate is currently opened
 *         GATE_ASSERT_HELD - the gate is currently closed and the current thread is the holder
 */
void
lck_rw_gate_assert(__assert_only lck_rw_t *lock, gate_t *gate, gate_assert_flags_t flags)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	gate_assert(gate, flags);
	return;
}

/*
 * Name: lck_mtx_gate_init
 *
 * Description: initializes a variable declared with decl_lck_mtx_gate_data.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 */
void
lck_mtx_gate_init(lck_mtx_t *lock, gate_t *gate)
{
	(void) lock;
	gate_init(gate, GT_INIT_DEFAULT);
}

/*
 * Name: lck_mtx_gate_alloc_init
 *
 * Description: allocates and initializes a gate_t.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *
 * Returns:
 *         gate_t allocated.
 */
gate_t*
lck_mtx_gate_alloc_init(lck_mtx_t *lock)
{
	(void) lock;
	return gate_alloc_init();
}

/*
 * Name: lck_mtx_gate_destroy
 *
 * Description: destroys a variable previously initialized
 *              with lck_mtx_gate_init().
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 */
void
lck_mtx_gate_destroy(lck_mtx_t *lock, gate_t *gate)
{
	(void) lock;
	gate_destroy(gate);
}

/*
 * Name: lck_mtx_gate_free
 *
 * Description: destroys and tries to free a gate previously allocated
 *	        with lck_mtx_gate_alloc_init().
 *              The gate free might be delegated to the last thread returning
 *              from the gate_wait().
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate obtained with lck_rw_gate_alloc_init().
 */
void
lck_mtx_gate_free(lck_mtx_t *lock, gate_t *gate)
{
	(void) lock;
	gate_free(gate);
}

/*
 * Name: lck_mtx_gate_try_close
 *
 * Description: Tries to close the gate.
 *              In case of success the current thread will be set as
 *              the holder of the gate.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *
 * Returns:
 *          KERN_SUCCESS in case the gate was successfully closed. The current thread is the new holder
 *          of the gate.
 *          A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *          to wake up possible waiters on the gate before returning to userspace.
 *          If the intent is to conditionally probe the gate before waiting, the lock must not be dropped
 *          between the calls to lck_mtx_gate_try_close() and lck_mtx_gate_wait().
 *
 *          KERN_FAILURE in case the gate was already closed. Will panic if the current thread was already the holder of the gate.
 *          lck_mtx_gate_wait() should be called instead if the intent is to unconditionally wait on this gate.
 *          The calls to lck_mtx_gate_try_close() and lck_mtx_gate_wait() should
 *          be done without dropping the lock that is protecting the gate in between.
 */
int
lck_mtx_gate_try_close(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	return gate_try_close(gate);
}

/*
 * Name: lck_mtx_gate_close
 *
 * Description: Closes the gate. The current thread will be set as
 *              the holder of the gate. Will panic if the gate is already closed.
 *              A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be open.
 *
 */
void
lck_mtx_gate_close(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	return gate_close(gate);
}

/*
 * Name: lck_mtx_gate_open
 *
 * Description: Opens of the gate and wakes up possible waiters.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 */
void
lck_mtx_gate_open(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	gate_open(gate);
}

/*
 * Name: lck_mtx_gate_handoff
 *
 * Description: Tries to transfer the ownership of the gate. The waiter with highest sched
 *              priority will be selected as the new holder of the gate, and woken up,
 *              with the gate remaining in the closed state throughout.
 *              If no waiters are present, the gate will be kept closed and KERN_NOT_WAITING
 *              will be returned.
 *              GATE_HANDOFF_OPEN_IF_NO_WAITERS flag can be used to specify if the gate should be opened in
 *              case no waiters were found.
 *
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: flags - GATE_HANDOFF_DEFAULT or GATE_HANDOFF_OPEN_IF_NO_WAITERS
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 * Returns:
 *          KERN_SUCCESS in case one of the waiters became the new holder.
 *          KERN_NOT_WAITING in case there were no waiters.
 *
 */
kern_return_t
lck_mtx_gate_handoff(__assert_only lck_mtx_t *lock, gate_t *gate, gate_handoff_flags_t flags)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	return gate_handoff(gate, flags);
}

/*
 * Name: lck_mtx_gate_steal
 *
 * Description: Steals the ownership of the gate. It sets the current thread as the
 *              new holder of the gate.
 *              A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *              NOTE: the previous holder should not call lck_mtx_gate_open() or lck_mtx_gate_handoff()
 *              anymore.
 *
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be closed and the current thread must not already be the holder.
 *
 */
void
lck_mtx_gate_steal(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	gate_steal(gate);
}

/*
 * Name: lck_mtx_gate_wait
 *
 * Description: Waits for the current thread to become the holder of the gate or for the
 *              gate to become open. An interruptible mode and deadline can be specified
 *              to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK, LCK_SLEEP_SPIN, LCK_SLEEP_SPIN_ALWAYS.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The gate must be closed.
 *
 * Returns: Reason why the thread was woken up.
 *          GATE_HANDOFF - the current thread was handed off the ownership of the gate.
 *                         A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *                         to wake up possible waiters on the gate before returning to userspace.
 *          GATE_OPENED - the gate was opened by the holder.
 *          GATE_TIMED_OUT - the thread was woken up by a timeout.
 *          GATE_INTERRUPTED - the thread was interrupted while sleeping.
 */
gate_wait_result_t
lck_mtx_gate_wait(lck_mtx_t *lock, gate_t *gate, lck_sleep_action_t lck_sleep_action, wait_interrupt_t interruptible, uint64_t deadline)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{;});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{lck_mtx_lock_spin(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{lck_mtx_lock_spin_always(lock);});
	} else {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{lck_mtx_lock(lock);});
	}
}

/*
 * Name: lck_mtx_gate_assert
 *
 * Description: asserts that the gate is in the specified state.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: flags to specified assert type.
 *         GATE_ASSERT_CLOSED - the gate is currently closed
 *         GATE_ASSERT_OPEN - the gate is currently opened
 *         GATE_ASSERT_HELD - the gate is currently closed and the current thread is the holder
 */
void
lck_mtx_gate_assert(__assert_only lck_mtx_t *lock, gate_t *gate, gate_assert_flags_t flags)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	gate_assert(gate, flags);
}

#pragma mark - LCK_*_DECLARE support

__startup_func
void
lck_spin_startup_init(struct lck_spin_startup_spec *sp)
{
	lck_spin_init(sp->lck, sp->lck_grp, sp->lck_attr);
}

__startup_func
void
lck_mtx_startup_init(struct lck_mtx_startup_spec *sp)
{
	lck_mtx_init(sp->lck, sp->lck_grp, sp->lck_attr);
}

__startup_func
void
lck_rw_startup_init(struct lck_rw_startup_spec *sp)
{
	lck_rw_init(sp->lck, sp->lck_grp, sp->lck_attr);
}

__startup_func
void
usimple_lock_startup_init(struct usimple_lock_startup_spec *sp)
{
	simple_lock_init(sp->lck, sp->lck_init_arg);
}

__startup_func
void
lck_ticket_startup_init(struct lck_ticket_startup_spec *sp)
{
	lck_ticket_init(sp->lck, sp->lck_grp);
}
