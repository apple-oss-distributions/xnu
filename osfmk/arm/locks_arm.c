/*
 * Copyright (c) 2007-2018 Apple Inc. All rights reserved.
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
 * Mach Operating System Copyright (c) 1991,1990,1989,1988,1987 Carnegie
 * Mellon University All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright notice
 * and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof, and that
 * both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION.
 * CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 * Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 * School of Computer Science Carnegie Mellon University Pittsburgh PA
 * 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon the
 * rights to redistribute these changes.
 */
/*
 *	File:	kern/lock.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Locking primitives implementation
 */

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>

#include <mach/machine/sdt.h>

#include <kern/zalloc.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_hygiene.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <kern/kcdata.h>
#include <kern/percpu.h>
#include <string.h>
#include <arm/cpu_internal.h>
#include <os/hash.h>
#include <arm/cpu_data.h>

#include <arm/cpu_data_internal.h>
#include <arm/proc_reg.h>
#include <arm/smp.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>

#include <pexpert/pexpert.h>

#include <sys/kdebug.h>

#define ANY_LOCK_DEBUG  (USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

// Panic in tests that check lock usage correctness
// These are undesirable when in a panic or a debugger is runnning.
#define LOCK_CORRECTNESS_PANIC() (kernel_debugger_entry_count == 0)

#define ADAPTIVE_SPIN_ENABLE 0x1

int lck_mtx_adaptive_spin_mode = ADAPTIVE_SPIN_ENABLE;

#define SPINWAIT_OWNER_CHECK_COUNT 4

typedef enum {
	SPINWAIT_ACQUIRED,     /* Got the lock. */
	SPINWAIT_INTERLOCK,    /* Got the interlock, no owner, but caller must finish acquiring the lock. */
	SPINWAIT_DID_SPIN_HIGH_THR, /* Got the interlock, spun, but failed to get the lock. */
	SPINWAIT_DID_SPIN_OWNER_NOT_CORE, /* Got the interlock, spun, but failed to get the lock. */
	SPINWAIT_DID_SPIN_NO_WINDOW_CONTENTION, /* Got the interlock, spun, but failed to get the lock. */
	SPINWAIT_DID_SPIN_SLIDING_THR,/* Got the interlock, spun, but failed to get the lock. */
	SPINWAIT_DID_NOT_SPIN, /* Got the interlock, did not spin. */
} spinwait_result_t;

#if CONFIG_DTRACE
extern machine_timeout32_t dtrace_spin_threshold;
#endif

/* Forwards */

extern unsigned int not_in_kdp;

/*
 *	We often want to know the addresses of the callers
 *	of the various lock routines.  However, this information
 *	is only used for debugging and statistics.
 */
typedef void   *pc_t;
#define INVALID_PC      ((void *) VM_MAX_KERNEL_ADDRESS)
#define INVALID_THREAD  ((void *) VM_MAX_KERNEL_ADDRESS)

#ifdef  lint
/*
 *	Eliminate lint complaints about unused local pc variables.
 */
#define OBTAIN_PC(pc, l) ++pc
#else                           /* lint */
#define OBTAIN_PC(pc, l)
#endif                          /* lint */


/*
 *	Portable lock package implementation of usimple_locks.
 */

/*
 * Owner thread pointer when lock held in spin mode
 */
#define LCK_MTX_SPIN_TAG  0xfffffff0


#define interlock_lock(lock)    hw_lock_bit    ((hw_lock_bit_t*)(&(lock)->lck_mtx_data), LCK_ILOCK_BIT, LCK_GRP_NULL)
#define interlock_try(lock)             hw_lock_bit_try((hw_lock_bit_t*)(&(lock)->lck_mtx_data), LCK_ILOCK_BIT, LCK_GRP_NULL)
#define interlock_unlock(lock)  hw_unlock_bit  ((hw_lock_bit_t*)(&(lock)->lck_mtx_data), LCK_ILOCK_BIT)
#define load_memory_barrier()   os_atomic_thread_fence(acquire)

// Enforce program order of loads and stores.
#define ordered_load(target) \
	        os_atomic_load(target, compiler_acq_rel)
#define ordered_store(target, value) \
	        os_atomic_store(target, value, compiler_acq_rel)

#define ordered_load_mtx(lock)                  ordered_load(&(lock)->lck_mtx_data)
#define ordered_store_mtx(lock, value)  ordered_store(&(lock)->lck_mtx_data, (value))
#define ordered_load_hw(lock)                   ordered_load(&(lock)->lock_data)
#define ordered_store_hw(lock, value)   ordered_store(&(lock)->lock_data, (value))
#define ordered_load_bit(lock)                  ordered_load((lock))
#define ordered_store_bit(lock, value)  ordered_store((lock), (value))


// Prevent the compiler from reordering memory operations around this
#define compiler_memory_fence() __asm__ volatile ("" ::: "memory")

MACHINE_TIMEOUT32(lock_panic_timeout, "lock-panic",
    0xc00000 /* 12.5 m ticks ~= 524ms with 24MHz OSC */, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

#define NOINLINE                __attribute__((noinline))


#if __arm__
#define interrupts_disabled(mask) (mask & PSR_INTMASK)
#else
#define interrupts_disabled(mask) (mask & DAIF_IRQF)
#endif


#if __arm__
#define enable_fiq()            __asm__ volatile ("cpsie  f" ::: "memory");
#define enable_interrupts()     __asm__ volatile ("cpsie if" ::: "memory");
#endif

KALLOC_TYPE_DEFINE(KT_LCK_SPIN, lck_spin_t, KT_PRIV_ACCT);

KALLOC_TYPE_DEFINE(KT_LCK_MTX, lck_mtx_t, KT_PRIV_ACCT);

KALLOC_TYPE_DEFINE(KT_LCK_MTX_EXT, lck_mtx_ext_t, KT_PRIV_ACCT);

#pragma GCC visibility push(hidden)
/*
 * atomic exchange API is a low level abstraction of the operations
 * to atomically read, modify, and write a pointer.  This abstraction works
 * for both Intel and ARMv8.1 compare and exchange atomic instructions as
 * well as the ARM exclusive instructions.
 *
 * atomic_exchange_begin() - begin exchange and retrieve current value
 * atomic_exchange_complete() - conclude an exchange
 * atomic_exchange_abort() - cancel an exchange started with atomic_exchange_begin()
 */
uint32_t
load_exclusive32(uint32_t *target, enum memory_order ord)
{
	uint32_t        value;

#if __arm__
	if (_os_atomic_mo_has_release(ord)) {
		// Pre-load release barrier
		atomic_thread_fence(memory_order_release);
	}
	value = __builtin_arm_ldrex(target);
#else
	if (_os_atomic_mo_has_acquire(ord)) {
		value = __builtin_arm_ldaex(target);    // ldaxr
	} else {
		value = __builtin_arm_ldrex(target);    // ldxr
	}
#endif  // __arm__
	return value;
}

boolean_t
store_exclusive32(uint32_t *target, uint32_t value, enum memory_order ord)
{
	boolean_t err;

#if __arm__
	err = __builtin_arm_strex(value, target);
	if (_os_atomic_mo_has_acquire(ord)) {
		// Post-store acquire barrier
		atomic_thread_fence(memory_order_acquire);
	}
#else
	if (_os_atomic_mo_has_release(ord)) {
		err = __builtin_arm_stlex(value, target);       // stlxr
	} else {
		err = __builtin_arm_strex(value, target);       // stxr
	}
#endif  // __arm__
	return !err;
}

uint32_t
atomic_exchange_begin32(uint32_t *target, uint32_t *previous, enum memory_order ord)
{
	uint32_t        val;

#if __ARM_ATOMICS_8_1
	ord = memory_order_relaxed;
#endif
	val = load_exclusive32(target, ord);
	*previous = val;
	return val;
}

boolean_t
atomic_exchange_complete32(uint32_t *target, uint32_t previous, uint32_t newval, enum memory_order ord)
{
#if __ARM_ATOMICS_8_1
	return __c11_atomic_compare_exchange_strong((_Atomic uint32_t *)target, &previous, newval, ord, memory_order_relaxed);
#else
	(void)previous;         // Previous not needed, monitor is held
	return store_exclusive32(target, newval, ord);
#endif
}

void
atomic_exchange_abort(void)
{
	os_atomic_clear_exclusive();
}

boolean_t
atomic_test_and_set32(uint32_t *target, uint32_t test_mask, uint32_t set_mask, enum memory_order ord, boolean_t wait)
{
	uint32_t                value, prev;

	for (;;) {
		value = atomic_exchange_begin32(target, &prev, ord);
		if (value & test_mask) {
			if (wait) {
				wait_for_event();       // Wait with monitor held
			} else {
				atomic_exchange_abort();        // Clear exclusive monitor
			}
			return FALSE;
		}
		value |= set_mask;
		if (atomic_exchange_complete32(target, prev, value, ord)) {
			return TRUE;
		}
	}
}

#pragma GCC visibility pop

#if SCHED_PREEMPTION_DISABLE_DEBUG

uint64_t PERCPU_DATA(preemption_disable_max_mt);

MACHINE_TIMEOUT_WRITEABLE(sched_preemption_disable_threshold_mt, "sched-preemption", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, kprintf_spam_mt_pred);

TUNABLE_DT_WRITEABLE(sched_hygiene_mode_t, sched_preemption_disable_debug_mode,
    "machine-timeouts",
    "sched-preemption-disable-mode", /* DT property names have to be 31 chars max */
    "sched_preemption_disable_debug_mode",
    SCHED_HYGIENE_MODE_OFF,
    TUNABLE_DT_CHECK_CHOSEN);

static uint32_t const sched_preemption_disable_debug_dbgid = MACHDBG_CODE(DBG_MACH_SCHED, MACH_PREEMPTION_EXPIRED) | DBG_FUNC_NONE;

NOINLINE void
_prepare_preemption_disable_measurement(thread_t thread)
{
	if (thread->machine.inthandler_timestamp == 0) {
		/*
		 * Only prepare a measurement if not currently in an interrupt
		 * handler.
		 *
		 * We are only interested in the net duration of disabled
		 * preemption, that is: The time in which preemption was
		 * disabled, minus the intervals in which any (likely
		 * unrelated) interrupts were handled.
		 * ml_adjust_preemption_disable_time() will remove those
		 * intervals, however we also do not even start measuring
		 * preemption disablement if we are already within handling of
		 * an interrupt when preemption was disabled (the resulting
		 * net time would be 0).
		 *
		 * Interrupt handling duration is handled separately, and any
		 * long intervals of preemption disablement are counted
		 * towards that.
		 */
		thread->machine.preemption_disable_adj_mt = ml_get_speculative_timebase();
	}
}

NOINLINE void
_collect_preemption_disable_measurement(thread_t thread)
{
	bool istate = ml_set_interrupts_enabled(false);
	/*
	 * Collect start time and current time with interrupts disabled.
	 * Otherwise an interrupt coming in after grabbing the timestamp
	 * could spuriously inflate the measurement, because it will
	 * adjust preemption_disable_adj_mt only after we already grabbed
	 * it.
	 *
	 * (Even worse if we collected the current time first: Then a
	 * subsequent interrupt could adjust preemption_disable_adj_mt to
	 * make the duration go negative after subtracting the already
	 * grabbed time. With interrupts disabled we don't care much about
	 * the order.)
	 */

	uint64_t const mt = thread->machine.preemption_disable_adj_mt;
	uint64_t const now = ml_get_speculative_timebase();

	os_compiler_barrier(acq_rel);

	ml_set_interrupts_enabled(istate);

	int64_t const duration = now - mt;


	uint64_t * const max_duration = PERCPU_GET(preemption_disable_max_mt);

	if (__improbable(duration > *max_duration)) {
		*max_duration = duration;
	}

	uint64_t const threshold = os_atomic_load(&sched_preemption_disable_threshold_mt, relaxed);
	if (__improbable(threshold > 0 && duration >= threshold)) {
		if (sched_preemption_disable_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
			panic("preemption disable timeout exceeded: %llu >= %llu timebase ticks", duration, threshold);
		}

		DTRACE_SCHED1(mach_preemption_expired, uint64_t, duration);
		if (__improbable(kdebug_debugid_enabled(sched_preemption_disable_debug_dbgid))) {
			KDBG(sched_preemption_disable_debug_dbgid, duration);
		}
	}

	thread->machine.preemption_disable_adj_mt = 0;
}

/*
 * Skip predicate for sched_preemption_disable, which would trigger
 * spuriously when kprintf spam is enabled.
 */
bool
kprintf_spam_mt_pred(struct machine_timeout_spec const __unused *spec)
{
	bool const kprintf_spam_enabled = !(disable_kprintf_output || disable_serial_output);
	return kprintf_spam_enabled;
}

#endif /* SCHED_PREEMPTION_DISABLE_DEBUG */

/*
 * To help _disable_preemption() inline everywhere with LTO,
 * we keep these nice non inlineable functions as the panic()
 * codegen setup is quite large and for weird reasons causes a frame.
 */
__abortlike
static void
_disable_preemption_overflow(void)
{
	panic("Preemption count overflow");
}

void
_disable_preemption(void)
{
	thread_t     thread = current_thread();
	unsigned int count  = thread->machine.preemption_count;

	if (__improbable(++count == 0)) {
		_disable_preemption_overflow();
	}

	os_atomic_store(&thread->machine.preemption_count, count, compiler_acq_rel);

#if SCHED_PREEMPTION_DISABLE_DEBUG

	/*
	 * Note that this is not the only place preemption gets disabled,
	 * it also gets modified on ISR and PPL entry/exit. Both of those
	 * events will be treated specially however, and
	 * increment/decrement being paired around their entry/exit means
	 * that collection here is not desynced otherwise.
	 */

	if (count == 1 && sched_preemption_disable_debug_mode) {
		_prepare_preemption_disable_measurement(thread);
	}
#endif /* SCHED_PREEMPTION_DISABLE_DEBUG */
}

/*
 * This variant of _disable_preemption() allows disabling preemption
 * without taking measurements (and later potentially triggering
 * actions on those).
 *
 * We do this through a separate variant because we do not want to
 * disturb inlinability of _disable_preemption(). However, in order to
 * also avoid code duplication, instead of repeating common code we
 * simply call _disable_preemption() and explicitly abandon any taken
 * measurement.
 */
void
_disable_preemption_without_measurements(void)
{
	_disable_preemption();

#if SCHED_PREEMPTION_DISABLE_DEBUG
	/*
	 * Abandon a potential preemption disable measurement. Useful for
	 * example for the idle thread, which would just spuriously
	 * trigger the threshold while actually idling, which we don't
	 * care about.
	 */
	thread_t t = current_thread();
	if (t->machine.preemption_disable_adj_mt != 0) {
		t->machine.preemption_disable_adj_mt = 0;
	}
#endif /* SCHED_PREEMPTION_DISABLE_DEBUG */
}

/*
 * This function checks whether an AST_URGENT has been pended.
 *
 * It is called once the preemption has been reenabled, which means the thread
 * may have been preempted right before this was called, and when this function
 * actually performs the check, we've changed CPU.
 *
 * This race is however benign: the point of AST_URGENT is to trigger a context
 * switch, so if one happened, there's nothing left to check for, and AST_URGENT
 * was cleared in the process.
 *
 * It follows that this check cannot have false negatives, which allows us
 * to avoid fiddling with interrupt state for the vast majority of cases
 * when the check will actually be negative.
 */
static NOINLINE void
kernel_preempt_check(thread_t thread)
{
	cpu_data_t *cpu_data_ptr;
	long        state;

#if __arm__
#define INTERRUPT_MASK PSR_IRQF
#else   // __arm__
#define INTERRUPT_MASK DAIF_IRQF
#endif  // __arm__

	/*
	 * This check is racy and could load from another CPU's pending_ast mask,
	 * but as described above, this can't have false negatives.
	 */
	cpu_data_ptr = os_atomic_load(&thread->machine.CpuDatap, compiler_acq_rel);
	if (__probable((cpu_data_ptr->cpu_pending_ast & AST_URGENT) == 0)) {
		return;
	}

	/* If interrupts are masked, we can't take an AST here */
	state = get_interrupts();
	if ((state & INTERRUPT_MASK) == 0) {
		disable_interrupts_noread();                    // Disable interrupts

		/*
		 * Reload cpu_data_ptr: a context switch would cause it to change.
		 * Now that interrupts are disabled, this will debounce false positives.
		 */
		cpu_data_ptr = os_atomic_load(&thread->machine.CpuDatap, compiler_acq_rel);
		if (thread->machine.CpuDatap->cpu_pending_ast & AST_URGENT) {
#if __arm__
#if __ARM_USER_PROTECT__
			uintptr_t up = arm_user_protect_begin(thread);
#endif  // __ARM_USER_PROTECT__
			enable_fiq();
#endif  // __arm__
			ast_taken_kernel();                 // Handle urgent AST
#if __arm__
#if __ARM_USER_PROTECT__
			arm_user_protect_end(thread, up, TRUE);
#endif  // __ARM_USER_PROTECT__
			enable_interrupts();
			return;                             // Return early on arm only due to FIQ enabling
#endif  // __arm__
		}
		restore_interrupts(state);              // Enable interrupts
	}
}

/*
 * To help _enable_preemption() inline everywhere with LTO,
 * we keep these nice non inlineable functions as the panic()
 * codegen setup is quite large and for weird reasons causes a frame.
 */
__abortlike
static void
_enable_preemption_underflow(void)
{
	panic("Preemption count underflow");
}

void
_enable_preemption(void)
{
	thread_t     thread = current_thread();
	unsigned int count  = thread->machine.preemption_count;

	if (__improbable(count == 0)) {
		_enable_preemption_underflow();
	}
	count -= 1;

#if SCHED_PREEMPTION_DISABLE_DEBUG
	if (count == 0 && thread->machine.preemption_disable_adj_mt != 0) {
		_collect_preemption_disable_measurement(thread);
	}
#endif /* SCHED_PREEMPTION_DISABLE_DEBUG */

	os_atomic_store(&thread->machine.preemption_count, count, compiler_acq_rel);
	if (count == 0) {
		kernel_preempt_check(thread);
	}

	os_compiler_barrier();
}

int
get_preemption_level(void)
{
	return current_thread()->machine.preemption_count;
}

/*
 *      Routine:        lck_spin_alloc_init
 */
lck_spin_t     *
lck_spin_alloc_init(
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	lck_spin_t *lck;

	lck = zalloc(KT_LCK_SPIN);
	lck_spin_init(lck, grp, attr);
	return lck;
}

/*
 *      Routine:        lck_spin_free
 */
void
lck_spin_free(
	lck_spin_t * lck,
	lck_grp_t * grp)
{
	lck_spin_destroy(lck, grp);
	zfree(KT_LCK_SPIN, lck);
}

/*
 *      Routine:        lck_spin_init
 */
void
lck_spin_init(
	lck_spin_t * lck,
	lck_grp_t * grp,
	__unused lck_attr_t * attr)
{
	lck->type = LCK_SPIN_TYPE;
	hw_lock_init(&lck->hwlock);
	if (grp) {
		lck_grp_reference(grp);
		lck_grp_lckcnt_incr(grp, LCK_TYPE_SPIN);
	}
}

/*
 * arm_usimple_lock is a lck_spin_t without a group or attributes
 */
MARK_AS_HIBERNATE_TEXT void inline
arm_usimple_lock_init(simple_lock_t lck, __unused unsigned short initial_value)
{
	lck->type = LCK_SPIN_TYPE;
	hw_lock_init(&lck->hwlock);
}


/*
 *      Routine:        lck_spin_lock
 */
void
lck_spin_lock(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_lock_nopreempt
 */
void
lck_spin_lock_nopreempt(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock_nopreempt(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_try_lock
 */
int
lck_spin_try_lock(lck_spin_t *lock)
{
	return hw_lock_try(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	return hw_lock_try(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_try_lock_nopreempt
 */
int
lck_spin_try_lock_nopreempt(lck_spin_t *lock)
{
	return hw_lock_try_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	return hw_lock_try_nopreempt(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_unlock
 */
void
lck_spin_unlock(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if ((LCK_MTX_STATE_TO_THREAD(lock->lck_spin_data) != current_thread()) && LOCK_CORRECTNESS_PANIC()) {
		panic("Spinlock not owned by thread %p = %lx", lock, lock->lck_spin_data);
	}
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock type %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_unlock(&lock->hwlock);
}

/*
 *      Routine:        lck_spin_unlock_nopreempt
 */
void
lck_spin_unlock_nopreempt(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if ((LCK_MTX_STATE_TO_THREAD(lock->lck_spin_data) != current_thread()) && LOCK_CORRECTNESS_PANIC()) {
		panic("Spinlock not owned by thread %p = %lx", lock, lock->lck_spin_data);
	}
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock type %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_unlock_nopreempt(&lock->hwlock);
}

/*
 *      Routine:        lck_spin_destroy
 */
void
lck_spin_destroy(
	lck_spin_t * lck,
	lck_grp_t * grp)
{
	if (lck->lck_spin_data == LCK_SPIN_TAG_DESTROYED) {
		return;
	}
	lck->lck_spin_data = LCK_SPIN_TAG_DESTROYED;
	if (grp) {
		lck_grp_lckcnt_decr(grp, LCK_TYPE_SPIN);
		lck_grp_deallocate(grp);
	}
}

/*
 * Routine: kdp_lck_spin_is_acquired
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_spin_is_acquired(lck_spin_t *lck)
{
	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	return ((lck->lck_spin_data & ~LCK_SPIN_TAG_DESTROYED) != 0) ? TRUE:FALSE;
}

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t l,
	unsigned short tag)
{
	simple_lock_init((simple_lock_t) l, tag);
}


/*
 *	Acquire a usimple_lock.
 *
 *	Returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_lock)(
	usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
	simple_lock((simple_lock_t) l, LCK_GRP_PROBEARG(grp));
}


extern void     sync(void);

/*
 *	Release a usimple_lock.
 *
 *	Returns with preemption enabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_unlock)(
	usimple_lock_t l)
{
	simple_unlock((simple_lock_t)l);
}


/*
 *	Conditionally acquire a usimple_lock.
 *
 *	On success, returns with preemption disabled.
 *	On failure, returns with preemption in the same state
 *	as when first invoked.  Note that the hw_lock routines
 *	are responsible for maintaining preemption state.
 *
 *	XXX No stats are gathered on a miss; I preserved this
 *	behavior from the original assembly-language code, but
 *	doesn't it make sense to log misses?  XXX
 */
unsigned
int
(usimple_lock_try)(
	usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
	return simple_lock_try((simple_lock_t) l, grp);
}

/*
 * The C portion of the mutex package.  These routines are only invoked
 * if the optimized assembler routines can't do the work.
 */

/*
 * Forward declaration
 */

void
lck_mtx_ext_init(
	lck_mtx_ext_t * lck,
	lck_grp_t * grp,
	lck_attr_t * attr);

/*
 *      Routine:        lck_mtx_alloc_init
 */
lck_mtx_t      *
lck_mtx_alloc_init(
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	lck_mtx_t      *lck;

	lck = zalloc(KT_LCK_MTX);
	lck_mtx_init(lck, grp, attr);
	return lck;
}

/*
 *      Routine:        lck_mtx_free
 */
void
lck_mtx_free(
	lck_mtx_t * lck,
	lck_grp_t * grp)
{
	lck_mtx_destroy(lck, grp);
	zfree(KT_LCK_MTX, lck);
}

/*
 *      Routine:        lck_mtx_init
 */
void
lck_mtx_init(
	lck_mtx_t * lck,
	lck_grp_t * grp,
	lck_attr_t * attr)
{
#ifdef  BER_XXX
	lck_mtx_ext_t  *lck_ext;
#endif
	lck_attr_t     *lck_attr;

	if (attr != LCK_ATTR_NULL) {
		lck_attr = attr;
	} else {
		lck_attr = &LockDefaultLckAttr;
	}

#ifdef  BER_XXX
	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck_ext = zalloc(KT_LCK_MTX_EXT);
		lck_mtx_ext_init(lck_ext, grp, lck_attr);
		lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
		lck->lck_mtx_ptr = lck_ext;
		lck->lck_mtx_type = LCK_MTX_TYPE;
	} else
#endif
	{
		*lck = (lck_mtx_t){
			.lck_mtx_type = LCK_MTX_TYPE,
		};
	}
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_init_ext
 */
void
lck_mtx_init_ext(
	lck_mtx_t * lck,
	lck_mtx_ext_t * lck_ext __unused,
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	lck_attr_t     *lck_attr;

	if (attr != LCK_ATTR_NULL) {
		lck_attr = attr;
	} else {
		lck_attr = &LockDefaultLckAttr;
	}

#if LOCKS_INDIRECT_ALLOW
	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck_mtx_ext_init(lck_ext, grp, lck_attr);
		lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
		lck->lck_mtx_ptr = lck_ext;
		lck->lck_mtx_type = LCK_MTX_TYPE;
	} else
#endif /* LOCKS_INDIRECT_ALLOW */
	{
		lck->lck_mtx_waiters = 0;
		lck->lck_mtx_type = LCK_MTX_TYPE;
		ordered_store_mtx(lck, 0);
	}
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_ext_init
 */
void
lck_mtx_ext_init(
	lck_mtx_ext_t * lck,
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	bzero((void *) lck, sizeof(lck_mtx_ext_t));

	lck->lck_mtx.lck_mtx_type = LCK_MTX_TYPE;

	if ((attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck->lck_mtx_deb.type = MUTEX_TAG;
		lck->lck_mtx_attr |= LCK_MTX_ATTR_DEBUG;
	}
	lck->lck_mtx_grp = grp;

	if (grp->lck_grp_attr & LCK_GRP_ATTR_STAT) {
		lck->lck_mtx_attr |= LCK_MTX_ATTR_STAT;
	}
}

/* The slow versions */
static void lck_mtx_lock_contended(lck_mtx_t *lock, thread_t thread, boolean_t interlocked);
static boolean_t lck_mtx_try_lock_contended(lck_mtx_t *lock, thread_t thread);
static void lck_mtx_unlock_contended(lck_mtx_t *lock, thread_t thread, boolean_t interlocked);

/* The adaptive spin function */
static spinwait_result_t lck_mtx_lock_contended_spinwait_arm(lck_mtx_t *lock, thread_t thread, boolean_t interlocked);

/*
 *	Routine:	lck_mtx_verify
 *
 *	Verify if a mutex is valid
 */
static inline void
lck_mtx_verify(lck_mtx_t *lock)
{
	if (lock->lck_mtx_type != LCK_MTX_TYPE) {
		panic("Invalid mutex %p", lock);
	}
#if     DEVELOPMENT || DEBUG
	if (lock->lck_mtx_tag == LCK_MTX_TAG_DESTROYED) {
		panic("Mutex destroyed %p", lock);
	}
#endif  /* DEVELOPMENT || DEBUG */
}

/*
 *	Routine:	lck_mtx_check_preemption
 *
 *	Verify preemption is enabled when attempting to acquire a mutex.
 */

static inline void
lck_mtx_check_preemption(lck_mtx_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if (current_cpu_datap()->cpu_hibernate) {
		return;
	}

	int pl = get_preemption_level();

	if (pl != 0) {
		panic("Attempt to take mutex with preemption disabled. Lock=%p, level=%d", lock, pl);
	}
#else
	(void)lock;
#endif
}

/*
 *	Routine:	lck_mtx_lock
 */
void
lck_mtx_lock(lck_mtx_t *lock)
{
	thread_t        thread;

	lck_mtx_verify(lock);
	lck_mtx_check_preemption(lock);
	thread = current_thread();
	if (os_atomic_cmpxchg(&lock->lck_mtx_data,
	    0, LCK_MTX_THREAD_TO_STATE(thread), acquire)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
		return;
	}
	lck_mtx_lock_contended(lock, thread, FALSE);
}

/*
 *       This is the slow version of mutex locking.
 */
static void NOINLINE
lck_mtx_lock_contended(lck_mtx_t *lock, thread_t thread, boolean_t interlocked)
{
	thread_t                holding_thread;
	uintptr_t               state;
	int                     waiters = 0;
	spinwait_result_t       sw_res;
	struct turnstile        *ts = NULL;

	/* Loop waiting until I see that the mutex is unowned */
	for (;;) {
		sw_res = lck_mtx_lock_contended_spinwait_arm(lock, thread, interlocked);
		interlocked = FALSE;

		switch (sw_res) {
		case SPINWAIT_ACQUIRED:
			if (ts != NULL) {
				interlock_lock(lock);
				turnstile_complete((uintptr_t)lock, NULL, NULL, TURNSTILE_KERNEL_MUTEX);
				interlock_unlock(lock);
			}
			goto done;
		case SPINWAIT_INTERLOCK:
			goto set_owner;
		default:
			break;
		}

		state = ordered_load_mtx(lock);
		holding_thread = LCK_MTX_STATE_TO_THREAD(state);
		if (holding_thread == NULL) {
			break;
		}
		ordered_store_mtx(lock, (state | LCK_ILOCK | ARM_LCK_WAITERS)); // Set waiters bit and wait
		lck_mtx_lock_wait(lock, holding_thread, &ts);
		/* returns interlock unlocked */
	}

set_owner:
	/* Hooray, I'm the new owner! */
	state = ordered_load_mtx(lock);

	if (state & ARM_LCK_WAITERS) {
		/* Skip lck_mtx_lock_acquire if there are no waiters. */
		waiters = lck_mtx_lock_acquire(lock, ts);
		/*
		 * lck_mtx_lock_acquire will call
		 * turnstile_complete
		 */
	} else {
		if (ts != NULL) {
			turnstile_complete((uintptr_t)lock, NULL, NULL, TURNSTILE_KERNEL_MUTEX);
		}
	}

	state = LCK_MTX_THREAD_TO_STATE(thread);
	if (waiters != 0) {
		state |= ARM_LCK_WAITERS;
	}
	state |= LCK_ILOCK;                             // Preserve interlock
	ordered_store_mtx(lock, state); // Set ownership
	interlock_unlock(lock);                 // Release interlock, enable preemption

done:
	load_memory_barrier();

	assert(thread->turnstile != NULL);

	if (ts != NULL) {
		turnstile_cleanup();
	}

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
}

/*
 * Routine: lck_mtx_lock_spinwait_arm
 *
 * Invoked trying to acquire a mutex when there is contention but
 * the holder is running on another processor. We spin for up to a maximum
 * time waiting for the lock to be released.
 */
static spinwait_result_t
lck_mtx_lock_contended_spinwait_arm(lck_mtx_t *lock, thread_t thread, boolean_t interlocked)
{
	int                     has_interlock = (int)interlocked;
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	thread_t        owner, prev_owner;
	uint64_t        window_deadline, sliding_deadline, high_deadline;
	uint64_t        start_time, cur_time, avg_hold_time, bias, delta;
	int             loopcount = 0;
	uint            i, prev_owner_cpu;
	int             total_hold_time_samples, window_hold_time_samples, unfairness;
	bool            owner_on_core, adjust;
	uintptr_t       state, new_state, waiters;
	spinwait_result_t       retval = SPINWAIT_DID_SPIN_HIGH_THR;

	if (__improbable(!(lck_mtx_adaptive_spin_mode & ADAPTIVE_SPIN_ENABLE))) {
		if (!has_interlock) {
			interlock_lock(lock);
		}

		return SPINWAIT_DID_NOT_SPIN;
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_START,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(LCK_MTX_STATE_TO_THREAD(state)), lock->lck_mtx_waiters, 0, 0);

	start_time = mach_absolute_time();
	/*
	 * window_deadline represents the "learning" phase.
	 * The thread collects statistics about the lock during
	 * window_deadline and then it makes a decision on whether to spin more
	 * or block according to the concurrency behavior
	 * observed.
	 *
	 * Every thread can spin at least low_MutexSpin.
	 */
	window_deadline = start_time + low_MutexSpin;
	/*
	 * Sliding_deadline is the adjusted spin deadline
	 * computed after the "learning" phase.
	 */
	sliding_deadline = window_deadline;
	/*
	 * High_deadline is a hard deadline. No thread
	 * can spin more than this deadline.
	 */
	if (high_MutexSpin >= 0) {
		high_deadline = start_time + high_MutexSpin;
	} else {
		high_deadline = start_time + low_MutexSpin * real_ncpus;
	}

	/*
	 * Do not know yet which is the owner cpu.
	 * Initialize prev_owner_cpu with next cpu.
	 */
	prev_owner_cpu = (cpu_number() + 1) % real_ncpus;
	total_hold_time_samples = 0;
	window_hold_time_samples = 0;
	avg_hold_time = 0;
	adjust = TRUE;
	bias = (os_hash_kernel_pointer(lock) + cpu_number()) % real_ncpus;

	/* Snoop the lock state */
	state = ordered_load_mtx(lock);
	owner = LCK_MTX_STATE_TO_THREAD(state);
	prev_owner = owner;

	if (has_interlock) {
		if (owner == NULL) {
			retval = SPINWAIT_INTERLOCK;
			goto done_spinning;
		} else {
			/*
			 * We are holding the interlock, so
			 * we can safely dereference owner.
			 */
			if (!machine_thread_on_core(owner) || (owner->state & TH_IDLE)) {
				retval = SPINWAIT_DID_NOT_SPIN;
				goto done_spinning;
			}
		}
		interlock_unlock(lock);
		has_interlock = 0;
	}

	/*
	 * Spin while:
	 *   - mutex is locked, and
	 *   - it's locked as a spin lock, and
	 *   - owner is running on another processor, and
	 *   - we haven't spun for long enough.
	 */
	do {
		/*
		 * Try to acquire the lock.
		 */
		owner = LCK_MTX_STATE_TO_THREAD(state);
		if (owner == NULL) {
			waiters = state & ARM_LCK_WAITERS;
			if (waiters) {
				/*
				 * preserve the waiter bit
				 * and try acquire the interlock.
				 * Note: we will successfully acquire
				 * the interlock only if we can also
				 * acquire the lock.
				 */
				new_state = ARM_LCK_WAITERS | LCK_ILOCK;
				has_interlock = 1;
				retval = SPINWAIT_INTERLOCK;
				disable_preemption();
			} else {
				new_state = LCK_MTX_THREAD_TO_STATE(thread);
				retval = SPINWAIT_ACQUIRED;
			}

			/*
			 * The cmpxchg will succed only if the lock
			 * is not owned (doesn't have an owner set)
			 * and it is not interlocked.
			 * It will not fail if there are waiters.
			 */
			if (os_atomic_cmpxchgv(&lock->lck_mtx_data,
			    waiters, new_state, &state, acquire)) {
				goto done_spinning;
			} else {
				if (waiters) {
					has_interlock = 0;
					enable_preemption();
				}
			}
		}

		cur_time = mach_absolute_time();

		/*
		 * Never spin past high_deadline.
		 */
		if (cur_time >= high_deadline) {
			retval = SPINWAIT_DID_SPIN_HIGH_THR;
			break;
		}

		/*
		 * Check if owner is on core. If not block.
		 */
		owner = LCK_MTX_STATE_TO_THREAD(state);
		if (owner) {
			i = prev_owner_cpu;
			owner_on_core = FALSE;

			disable_preemption();
			state = ordered_load_mtx(lock);
			owner = LCK_MTX_STATE_TO_THREAD(state);

			/*
			 * For scalability we want to check if the owner is on core
			 * without locking the mutex interlock.
			 * If we do not lock the mutex interlock, the owner that we see might be
			 * invalid, so we cannot dereference it. Therefore we cannot check
			 * any field of the thread to tell us if it is on core.
			 * Check if the thread that is running on the other cpus matches the owner.
			 */
			if (owner) {
				do {
					cpu_data_t *cpu_data_ptr = CpuDataEntries[i].cpu_data_vaddr;
					if ((cpu_data_ptr != NULL) && (cpu_data_ptr->cpu_active_thread == owner)) {
						owner_on_core = TRUE;
						break;
					}
					if (++i >= real_ncpus) {
						i = 0;
					}
				} while (i != prev_owner_cpu);
				enable_preemption();

				if (owner_on_core) {
					prev_owner_cpu = i;
				} else {
					prev_owner = owner;
					state = ordered_load_mtx(lock);
					owner = LCK_MTX_STATE_TO_THREAD(state);
					if (owner == prev_owner) {
						/*
						 * Owner is not on core.
						 * Stop spinning.
						 */
						if (loopcount == 0) {
							retval = SPINWAIT_DID_NOT_SPIN;
						} else {
							retval = SPINWAIT_DID_SPIN_OWNER_NOT_CORE;
						}
						break;
					}
					/*
					 * Fall through if the owner changed while we were scanning.
					 * The new owner could potentially be on core, so loop
					 * again.
					 */
				}
			} else {
				enable_preemption();
			}
		}

		/*
		 * Save how many times we see the owner changing.
		 * We can roughly estimate the the mutex hold
		 * time and the fairness with that.
		 */
		if (owner != prev_owner) {
			prev_owner = owner;
			total_hold_time_samples++;
			window_hold_time_samples++;
		}

		/*
		 * Learning window expired.
		 * Try to adjust the sliding_deadline.
		 */
		if (cur_time >= window_deadline) {
			/*
			 * If there was not contention during the window
			 * stop spinning.
			 */
			if (window_hold_time_samples < 1) {
				retval = SPINWAIT_DID_SPIN_NO_WINDOW_CONTENTION;
				break;
			}

			if (adjust) {
				/*
				 * For a fair lock, we'd wait for at most (NCPU-1) periods,
				 * but the lock is unfair, so let's try to estimate by how much.
				 */
				unfairness = total_hold_time_samples / real_ncpus;

				if (unfairness == 0) {
					/*
					 * We observed the owner changing `total_hold_time_samples` times which
					 * let us estimate the average hold time of this mutex for the duration
					 * of the spin time.
					 * avg_hold_time = (cur_time - start_time) / total_hold_time_samples;
					 *
					 * In this case spin at max avg_hold_time * (real_ncpus - 1)
					 */
					delta = cur_time - start_time;
					sliding_deadline = start_time + (delta * (real_ncpus - 1)) / total_hold_time_samples;
				} else {
					/*
					 * In this case at least one of the other cpus was able to get the lock twice
					 * while I was spinning.
					 * We could spin longer but it won't necessarily help if the system is unfair.
					 * Try to randomize the wait to reduce contention.
					 *
					 * We compute how much time we could potentially spin
					 * and distribute it over the cpus.
					 *
					 * bias is an integer between 0 and real_ncpus.
					 * distributed_increment = ((high_deadline - cur_time) / real_ncpus) * bias
					 */
					delta = high_deadline - cur_time;
					sliding_deadline = cur_time + ((delta * bias) / real_ncpus);
					adjust = FALSE;
				}
			}

			window_deadline += low_MutexSpin;
			window_hold_time_samples = 0;
		}

		/*
		 * Stop spinning if we past
		 * the adjusted deadline.
		 */
		if (cur_time >= sliding_deadline) {
			retval = SPINWAIT_DID_SPIN_SLIDING_THR;
			break;
		}

		/*
		 * We want to arm the monitor for wfe,
		 * so load exclusively the lock.
		 *
		 * NOTE:
		 * we rely on the fact that wfe will
		 * eventually return even if the cache line
		 * is not modified. This way we will keep
		 * looping and checking if the deadlines expired.
		 */
		state = os_atomic_load_exclusive(&lock->lck_mtx_data, relaxed);
		owner = LCK_MTX_STATE_TO_THREAD(state);
		if (owner != NULL) {
			wait_for_event();
			state = ordered_load_mtx(lock);
		} else {
			atomic_exchange_abort();
		}

		loopcount++;
	} while (TRUE);

done_spinning:
#if     CONFIG_DTRACE
	/*
	 * Note that we record a different probe id depending on whether
	 * this is a direct or indirect mutex.  This allows us to
	 * penalize only lock groups that have debug/stats enabled
	 * with dtrace processing if desired.
	 */
#if LOCKS_INDIRECT_ALLOW
	if (__probable(lock->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)) {
		LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN, lock,
		    mach_absolute_time() - start_time);
	} else
#endif /* LOCKS_INDIRECT_ALLOW */
	{
		LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_SPIN, lock,
		    mach_absolute_time() - start_time);
	}
	/* The lockstat acquire event is recorded by the caller. */
#endif

	state = ordered_load_mtx(lock);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_END,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(LCK_MTX_STATE_TO_THREAD(state)), lock->lck_mtx_waiters, retval, 0);
	if ((!has_interlock) && (retval != SPINWAIT_ACQUIRED)) {
		/* We must own either the lock or the interlock on return. */
		interlock_lock(lock);
	}

	return retval;
}


/*
 *	Common code for mutex locking as spinlock
 */
static inline void
lck_mtx_lock_spin_internal(lck_mtx_t *lock, boolean_t allow_held_as_mutex)
{
	uintptr_t       state;

	interlock_lock(lock);
	state = ordered_load_mtx(lock);
	if (LCK_MTX_STATE_TO_THREAD(state)) {
		if (allow_held_as_mutex) {
			lck_mtx_lock_contended(lock, current_thread(), TRUE);
		} else {
			// "Always" variants can never block. If the lock is held and blocking is not allowed
			// then someone is mixing always and non-always calls on the same lock, which is
			// forbidden.
			panic("Attempting to block on a lock taken as spin-always %p", lock);
		}
		return;
	}
	state &= ARM_LCK_WAITERS;                                               // Preserve waiters bit
	state |= (LCK_MTX_SPIN_TAG | LCK_ILOCK);        // Add spin tag and maintain interlock
	ordered_store_mtx(lock, state);
	load_memory_barrier();

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
}

/*
 *	Routine:	lck_mtx_lock_spin
 */
void
lck_mtx_lock_spin(lck_mtx_t *lock)
{
	lck_mtx_check_preemption(lock);
	lck_mtx_lock_spin_internal(lock, TRUE);
}

/*
 *	Routine:	lck_mtx_lock_spin_always
 */
void
lck_mtx_lock_spin_always(lck_mtx_t *lock)
{
	lck_mtx_lock_spin_internal(lock, FALSE);
}

/*
 *	Routine:	lck_mtx_try_lock
 */
boolean_t
lck_mtx_try_lock(lck_mtx_t *lock)
{
	thread_t        thread = current_thread();

	lck_mtx_verify(lock);
	if (os_atomic_cmpxchg(&lock->lck_mtx_data,
	    0, LCK_MTX_THREAD_TO_STATE(thread), acquire)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
		return TRUE;
	}
	return lck_mtx_try_lock_contended(lock, thread);
}

static boolean_t NOINLINE
lck_mtx_try_lock_contended(lck_mtx_t *lock, thread_t thread)
{
	thread_t        holding_thread;
	uintptr_t       state;
	int             waiters;

	interlock_lock(lock);
	state = ordered_load_mtx(lock);
	holding_thread = LCK_MTX_STATE_TO_THREAD(state);
	if (holding_thread) {
		interlock_unlock(lock);
		return FALSE;
	}
	waiters = lck_mtx_lock_acquire(lock, NULL);
	state = LCK_MTX_THREAD_TO_STATE(thread);
	if (waiters != 0) {
		state |= ARM_LCK_WAITERS;
	}
	state |= LCK_ILOCK;                             // Preserve interlock
	ordered_store_mtx(lock, state); // Set ownership
	interlock_unlock(lock);                 // Release interlock, enable preemption
	load_memory_barrier();

	turnstile_cleanup();

	return TRUE;
}

static inline boolean_t
lck_mtx_try_lock_spin_internal(lck_mtx_t *lock, boolean_t allow_held_as_mutex)
{
	uintptr_t       state;

	if (!interlock_try(lock)) {
		return FALSE;
	}
	state = ordered_load_mtx(lock);
	if (LCK_MTX_STATE_TO_THREAD(state)) {
		// Lock is held as mutex
		if (allow_held_as_mutex) {
			interlock_unlock(lock);
		} else {
			// "Always" variants can never block. If the lock is held as a normal mutex
			// then someone is mixing always and non-always calls on the same lock, which is
			// forbidden.
			panic("Spin-mutex held as full mutex %p", lock);
		}
		return FALSE;
	}
	state &= ARM_LCK_WAITERS;                                               // Preserve waiters bit
	state |= (LCK_MTX_SPIN_TAG | LCK_ILOCK);        // Add spin tag and maintain interlock
	ordered_store_mtx(lock, state);
	load_memory_barrier();

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
	return TRUE;
}

/*
 *	Routine: lck_mtx_try_lock_spin
 */
boolean_t
lck_mtx_try_lock_spin(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_spin_internal(lock, TRUE);
}

/*
 *	Routine: lck_mtx_try_lock_spin_always
 */
boolean_t
lck_mtx_try_lock_spin_always(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_spin_internal(lock, FALSE);
}



/*
 *	Routine:	lck_mtx_unlock
 */
void
lck_mtx_unlock(lck_mtx_t *lock)
{
	thread_t        thread = current_thread();
	uintptr_t       state;
	boolean_t       ilk_held = FALSE;

	lck_mtx_verify(lock);

	state = ordered_load_mtx(lock);
	if (state & LCK_ILOCK) {
		if (LCK_MTX_STATE_TO_THREAD(state) == (thread_t)LCK_MTX_SPIN_TAG) {
			ilk_held = TRUE;        // Interlock is held by (presumably) this thread
		}
		goto slow_case;
	}
	// Locked as a mutex
	if (os_atomic_cmpxchg(&lock->lck_mtx_data,
	    LCK_MTX_THREAD_TO_STATE(thread), 0, release)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
		return;
	}
slow_case:
	lck_mtx_unlock_contended(lock, thread, ilk_held);
}

static void NOINLINE
lck_mtx_unlock_contended(lck_mtx_t *lock, thread_t thread, boolean_t ilk_held)
{
	uintptr_t       state;
	boolean_t               cleanup = FALSE;

	if (ilk_held) {
		state = ordered_load_mtx(lock);
	} else {
		interlock_lock(lock);
		state = ordered_load_mtx(lock);
		if (thread != LCK_MTX_STATE_TO_THREAD(state)) {
			panic("lck_mtx_unlock(): Attempt to release lock not owned by thread (%p)", lock);
		}
		if (state & ARM_LCK_WAITERS) {
			if (lck_mtx_unlock_wakeup(lock, thread)) {
				state = ARM_LCK_WAITERS;
			} else {
				state = 0;
			}
			cleanup = TRUE;
			goto unlock;
		}
	}
	state &= ARM_LCK_WAITERS;   /* Clear state, retain waiters bit */
unlock:
	state |= LCK_ILOCK;
	ordered_store_mtx(lock, state);
	interlock_unlock(lock);
	if (cleanup) {
		/*
		 * Do not do any turnstile operations outside of this block.
		 * lock/unlock is called at early stage of boot with single thread,
		 * when turnstile is not yet initialized.
		 * Even without contention we can come throught the slow path
		 * if the mutex is acquired as a spin lock.
		 */
		turnstile_cleanup();
	}

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
}

/*
 *	Routine:	lck_mtx_assert
 */
void
lck_mtx_assert(lck_mtx_t *lock, unsigned int type)
{
	thread_t        thread, holder;
	uintptr_t       state;

	state = ordered_load_mtx(lock);
	holder = LCK_MTX_STATE_TO_THREAD(state);
	if (holder == (thread_t)LCK_MTX_SPIN_TAG) {
		// Lock is held in spin mode, owner is unknown.
		return; // Punt
	}
	thread = current_thread();
	if (type == LCK_MTX_ASSERT_OWNED) {
		if (thread != holder) {
			panic("lck_mtx_assert(): mutex (%p) owned", lock);
		}
	} else if (type == LCK_MTX_ASSERT_NOTOWNED) {
		if (thread == holder) {
			panic("lck_mtx_assert(): mutex (%p) not owned", lock);
		}
	} else {
		panic("lck_mtx_assert(): invalid arg (%u)", type);
	}
}

/*
 *	Routine:	lck_mtx_ilk_unlock
 */
boolean_t
lck_mtx_ilk_unlock(lck_mtx_t *lock)
{
	interlock_unlock(lock);
	return TRUE;
}

/*
 *	Routine:	lck_mtx_convert_spin
 *
 *	Convert a mutex held for spin into a held full mutex
 */
void
lck_mtx_convert_spin(lck_mtx_t *lock)
{
	thread_t        thread = current_thread();
	uintptr_t       state;
	int                     waiters;

	state = ordered_load_mtx(lock);
	if (LCK_MTX_STATE_TO_THREAD(state) == thread) {
		return;         // Already owned as mutex, return
	}
	if ((state & LCK_ILOCK) == 0 || (LCK_MTX_STATE_TO_THREAD(state) != (thread_t)LCK_MTX_SPIN_TAG)) {
		panic("lck_mtx_convert_spin: Not held as spinlock (%p)", lock);
	}
	state &= ~(LCK_MTX_THREAD_MASK);                // Clear the spin tag
	ordered_store_mtx(lock, state);
	waiters = lck_mtx_lock_acquire(lock, NULL);   // Acquire to manage priority boosts
	state = LCK_MTX_THREAD_TO_STATE(thread);
	if (waiters != 0) {
		state |= ARM_LCK_WAITERS;
	}
	state |= LCK_ILOCK;
	ordered_store_mtx(lock, state);                 // Set ownership
	interlock_unlock(lock);                                 // Release interlock, enable preemption
	turnstile_cleanup();
}


/*
 *      Routine:        lck_mtx_destroy
 */
void
lck_mtx_destroy(
	lck_mtx_t * lck,
	lck_grp_t * grp)
{
	if (lck->lck_mtx_type != LCK_MTX_TYPE) {
		panic("Destroying invalid mutex %p", lck);
	}
	if (lck->lck_mtx_tag == LCK_MTX_TAG_DESTROYED) {
		panic("Destroying previously destroyed lock %p", lck);
	}
	lck_mtx_assert(lck, LCK_MTX_ASSERT_NOTOWNED);
	lck->lck_mtx_tag = LCK_MTX_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_MTX);
	lck_grp_deallocate(grp);
	return;
}

/*
 *	Routine:	lck_spin_assert
 */
void
lck_spin_assert(lck_spin_t *lock, unsigned int type)
{
	thread_t        thread, holder;
	uintptr_t       state;

	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}

	state = lock->lck_spin_data;
	holder = (thread_t)(state & ~LCK_ILOCK);
	thread = current_thread();
	if (type == LCK_ASSERT_OWNED) {
		if (holder == 0) {
			panic("Lock not owned %p = %lx", lock, state);
		}
		if (holder != thread) {
			panic("Lock not owned by current thread %p = %lx", lock, state);
		}
		if ((state & LCK_ILOCK) == 0) {
			panic("Lock bit not set %p = %lx", lock, state);
		}
	} else if (type == LCK_ASSERT_NOTOWNED) {
		if (holder != 0) {
			if (holder == thread) {
				panic("Lock owned by current thread %p = %lx", lock, state);
			}
		}
	} else {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}
}

/*
 * Routine: kdp_lck_mtx_lock_spin_is_acquired
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_mtx_lock_spin_is_acquired(lck_mtx_t *lck)
{
	uintptr_t       state;

	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	state = ordered_load_mtx(lck);
	if (state == LCK_MTX_TAG_DESTROYED) {
		return FALSE;
	}
	if (LCK_MTX_STATE_TO_THREAD(state) || (state & LCK_ILOCK)) {
		return TRUE;
	}
	return FALSE;
}

void
kdp_lck_mtx_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	lck_mtx_t * mutex = LCK_EVENT_TO_MUTEX(event);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(mutex);
	uintptr_t state   = ordered_load_mtx(mutex);
	thread_t holder   = LCK_MTX_STATE_TO_THREAD(state);
	if ((uintptr_t)holder == (uintptr_t)LCK_MTX_SPIN_TAG) {
		waitinfo->owner = STACKSHOT_WAITOWNER_MTXSPIN;
	} else {
		assertf(state != (uintptr_t)LCK_MTX_TAG_DESTROYED, "state=0x%llx", (uint64_t)state);
#if LOCKS_INDIRECT_ALLOW
		assertf(state != (uintptr_t)LCK_MTX_TAG_INDIRECT, "state=0x%llx", (uint64_t)state);
#endif /* LOCKS_INDIRECT_ALLOW */
		waitinfo->owner = thread_tid(holder);
	}
}
