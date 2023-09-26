/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
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

#include <kern/locks_internal.h>
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
#include <kern/hvg_hypercall.h>
#include <string.h>
#include <arm/cpu_internal.h>
#include <os/hash.h>
#include <arm/cpu_data.h>

#include <arm/cpu_data_internal.h>
#include <arm64/proc_reg.h>
#include <arm/smp.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>

#include <pexpert/pexpert.h>

#include <sys/kdebug.h>

#define ANY_LOCK_DEBUG  (USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

// Panic in tests that check lock usage correctness
// These are undesirable when in a panic or a debugger is runnning.
#define LOCK_CORRECTNESS_PANIC() (kernel_debugger_entry_count == 0)

/* Forwards */

extern unsigned int not_in_kdp;

MACHINE_TIMEOUT(lock_panic_timeout, "lock-panic",
    0xc00000 /* 12.5 m ticks ~= 524ms with 24MHz OSC */, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

#define NOINLINE                __attribute__((noinline))

#define interrupts_disabled(mask) (mask & DAIF_IRQF)

KALLOC_TYPE_DEFINE(KT_LCK_SPIN, lck_spin_t, KT_PRIV_ACCT);

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

	if (_os_atomic_mo_has_acquire(ord)) {
		value = __builtin_arm_ldaex(target);    // ldaxr
	} else {
		value = __builtin_arm_ldrex(target);    // ldxr
	}

	return value;
}

boolean_t
store_exclusive32(uint32_t *target, uint32_t value, enum memory_order ord)
{
	boolean_t err;

	if (_os_atomic_mo_has_release(ord)) {
		err = __builtin_arm_stlex(value, target);       // stlxr
	} else {
		err = __builtin_arm_strex(value, target);       // stxr
	}

	return !err;
}

uint32_t
atomic_exchange_begin32(uint32_t *target, uint32_t *previous, enum memory_order ord)
{
	uint32_t        val;

#if !OS_ATOMIC_USE_LLSC
	ord = memory_order_relaxed;
#endif
	val = load_exclusive32(target, ord);
	*previous = val;
	return val;
}

boolean_t
atomic_exchange_complete32(uint32_t *target, uint32_t previous, uint32_t newval, enum memory_order ord)
{
#if !OS_ATOMIC_USE_LLSC
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
#pragma mark preemption

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
kernel_preempt_check(void)
{
	uint64_t state;

	/* If interrupts are masked, we can't take an AST here */
	state = __builtin_arm_rsr64("DAIF");
	if (state & DAIF_IRQF) {
		return;
	}

	/* disable interrupts (IRQ FIQ ASYNCF) */
	__builtin_arm_wsr64("DAIFSet", DAIFSC_STANDARD_DISABLE);

	/*
	 * Reload cpu_pending_ast: a context switch would cause it to change.
	 * Now that interrupts are disabled, this will debounce false positives.
	 */
	if (current_thread()->machine.CpuDatap->cpu_pending_ast & AST_URGENT) {
		ast_taken_kernel();
	}

	/* restore the original interrupt mask */
	__builtin_arm_wsr64("DAIF", state);
}

static inline void
_enable_preemption_write_count(thread_t thread, unsigned int count)
{
	os_atomic_store(&thread->machine.preemption_count, count, compiler_acq_rel);

	/*
	 * This check is racy and could load from another CPU's pending_ast mask,
	 * but as described above, this can't have false negatives.
	 */
	if (count == 0) {
		if (__improbable(thread->machine.CpuDatap->cpu_pending_ast & AST_URGENT)) {
			return kernel_preempt_check();
		}
	}
}

#if SCHED_HYGIENE_DEBUG

uint64_t _Atomic PERCPU_DATA_HACK_78750602(preemption_disable_max_mt);

#if XNU_PLATFORM_iPhoneOS
#define DEFAULT_PREEMPTION_TIMEOUT 120000 /* 5ms */
#define DEFAULT_PREEMPTION_MODE SCHED_HYGIENE_MODE_PANIC
#else
#define DEFAULT_PREEMPTION_TIMEOUT 0      /* Disabled */
#define DEFAULT_PREEMPTION_MODE SCHED_HYGIENE_MODE_OFF
#endif /* XNU_PLATFORM_iPhoneOS */

MACHINE_TIMEOUT_DEV_WRITEABLE(sched_preemption_disable_threshold_mt, "sched-preemption",
    DEFAULT_PREEMPTION_TIMEOUT, MACHINE_TIMEOUT_UNIT_TIMEBASE, kprintf_spam_mt_pred);
TUNABLE_DT_WRITEABLE(sched_hygiene_mode_t, sched_preemption_disable_debug_mode,
    "machine-timeouts",
    "sched-preemption-disable-mode", /* DT property names have to be 31 chars max */
    "sched_preemption_disable_debug_mode",
    DEFAULT_PREEMPTION_MODE,
    TUNABLE_DT_CHECK_CHOSEN);

static uint32_t const sched_preemption_disable_debug_dbgid = MACHDBG_CODE(DBG_MACH_SCHED, MACH_PREEMPTION_EXPIRED) | DBG_FUNC_NONE;

NOINLINE void
_prepare_preemption_disable_measurement(void)
{
	thread_t thread = current_thread();

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

		bool istate = ml_set_interrupts_enabled_with_debug(false, false); // don't take int masked timestamp
		thread->machine.preemption_disable_abandon = false;
		thread->machine.preemption_disable_mt = ml_get_sched_hygiene_timebase();
		thread->machine.preemption_disable_adjust = 0;
		thread->machine.preemption_count |= SCHED_HYGIENE_MARKER;
#if MONOTONIC
		if (sched_hygiene_debug_pmc) {
			mt_cur_cpu_cycles_instrs_speculative(&thread->machine.preemption_disable_cycles, &thread->machine.preemption_disable_instr);
		}
#endif
		ml_set_interrupts_enabled_with_debug(istate, false);
	}
}

NOINLINE void
_collect_preemption_disable_measurement(void)
{
	bool istate = ml_set_interrupts_enabled_with_debug(false, false); // don't take int masked timestamp
	/*
	 * Collect start time and current time with interrupts disabled.
	 * Otherwise an interrupt coming in after grabbing the timestamp
	 * could spuriously inflate the measurement, because it will
	 * adjust preemption_disable_mt only after we already grabbed
	 * it.
	 *
	 * (Even worse if we collected the current time first: Then a
	 * subsequent interrupt could adjust preemption_disable_mt to
	 * make the duration go negative after subtracting the already
	 * grabbed time. With interrupts disabled we don't care much about
	 * the order.)
	 */

	thread_t thread = current_thread();
	uint64_t const mt = thread->machine.preemption_disable_mt;
	uint64_t const adjust = thread->machine.preemption_disable_adjust;
	uint64_t const now = ml_get_sched_hygiene_timebase();
	thread->machine.preemption_disable_mt = 0;
	thread->machine.preemption_disable_adjust = 0;
	/* no need to clear SCHED_HYGIENE_MARKER, will be done on exit */

	/*
	 * Don't need to reset (or even save) preemption_disable_abandon
	 * here: abandon_preemption_disable_measurement is a no-op anyway
	 * if preemption_disable_mt == 0 (which we just set), and it
	 * will stay that way until the next call to
	 * _collect_preemption_disable_measurement.
	 */

	os_compiler_barrier(acq_rel);

	ml_set_interrupts_enabled_with_debug(istate, false);

	/*
	 * Fine to get with interrupts enabled:
	 * Above we set preemption_disable_mt to 0, which turns
	 * abandon_preemption_disable_measurement() into a no-op
	 * until the next collection starts.
	 */
	if (thread->machine.preemption_disable_abandon) {
		goto out;
	}

	int64_t const gross_duration = now - mt;
	int64_t const net_duration = gross_duration - adjust;

	uint64_t _Atomic * const max_duration = PERCPU_GET(preemption_disable_max_mt);

	if (__improbable(net_duration > *max_duration)) {
		os_atomic_store(max_duration, net_duration, relaxed);
	}

	uint64_t const threshold = os_atomic_load(&sched_preemption_disable_threshold_mt, relaxed);
	if (__improbable(threshold > 0 && net_duration >= threshold)) {
		uint64_t average_freq = 0;
		uint64_t average_cpi_whole = 0;
		uint64_t average_cpi_fractional = 0;

#if MONOTONIC
		if (sched_hygiene_debug_pmc) {
			uint64_t current_cycles = 0, current_instrs = 0;

			/*
			 * We're getting these values a bit late, but getting them
			 * is a bit expensive, so we take the slight hit in
			 * accuracy for the reported values (which aren't very
			 * stable anyway).
			 */
			istate = ml_set_interrupts_enabled_with_debug(false, false);
			mt_cur_cpu_cycles_instrs_speculative(&current_cycles, &current_instrs);
			ml_set_interrupts_enabled_with_debug(istate, false);

			uint64_t duration_ns;
			absolutetime_to_nanoseconds(gross_duration, &duration_ns);

			average_freq = (current_cycles - thread->machine.preemption_disable_cycles) / (duration_ns / 1000);
			average_cpi_whole = (current_cycles - thread->machine.preemption_disable_cycles) / (current_instrs - thread->machine.preemption_disable_instr);
			average_cpi_fractional =
			    (((current_cycles - thread->machine.preemption_disable_cycles) * 100) / (current_instrs - thread->machine.preemption_disable_instr)) % 100;
		}
#endif

		if (sched_preemption_disable_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
			panic("preemption disable timeout exceeded: %llu >= %llu mt ticks (start: %llu, now: %llu, gross: %llu, inttime: %llu), "
			    "freq = %llu MHz, CPI = %llu.%llu",
			    net_duration, threshold, mt, now, gross_duration, adjust,
			    average_freq, average_cpi_whole, average_cpi_fractional);
		}

		DTRACE_SCHED4(mach_preemption_expired, uint64_t, net_duration, uint64_t, gross_duration,
		    uint64_t, average_cpi_whole, uint64_t, average_cpi_fractional);
		if (__improbable(kdebug_debugid_enabled(sched_preemption_disable_debug_dbgid))) {
			KDBG(sched_preemption_disable_debug_dbgid, net_duration, gross_duration, average_cpi_whole, average_cpi_fractional);
		}
	}

out:
	/*
	 * the preemption count is SCHED_HYGIENE_MARKER, we need to clear it.
	 */
	_enable_preemption_write_count(thread, 0);
}

/*
 * Abandon a potential preemption disable measurement. Useful for
 * example for the idle thread, which would just spuriously
 * trigger the threshold while actually idling, which we don't
 * care about.
 */
void
abandon_preemption_disable_measurement(void)
{
	thread_t t = current_thread();
	bool istate = ml_set_interrupts_enabled_with_debug(false, false); // don't take int masked timestamp

	if (t->machine.preemption_disable_mt != 0) {
		t->machine.preemption_disable_abandon = true;
	}
	ml_set_interrupts_enabled_with_debug(istate, false);
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

/*
 * Abandon function exported for AppleCLPC, as a workaround to rdar://91668370.
 *
 * Only for AppleCLPC!
 */
void
sched_perfcontrol_abandon_preemption_disable_measurement(void)
{
	abandon_preemption_disable_measurement();
}

#else /* SCHED_HYGIENE_DEBUG */
void
sched_perfcontrol_abandon_preemption_disable_measurement(void)
{
	// No-op. Function is exported, so needs to be defined
}
#endif /* SCHED_HYGIENE_DEBUG */

/*
 * This function is written in a way that the codegen is extremely short.
 *
 * LTO isn't smart enough to inline it, yet it is profitable because
 * the vast majority of callers use current_thread() already.
 *
 * TODO: It is unfortunate that we have to load
 *       sched_preemption_disable_debug_mode
 *
 * /!\ Breaking inlining causes zalloc to be roughly 10% slower /!\
 */
__attribute__((always_inline))
void
_disable_preemption(void)
{
	thread_t thread = current_thread();
	unsigned int count = thread->machine.preemption_count;

	os_atomic_store(&thread->machine.preemption_count,
	    count + 1, compiler_acq_rel);

#if SCHED_HYGIENE_DEBUG
	/*
	 * Note that this is not the only place preemption gets disabled,
	 * it also gets modified on ISR and PPL entry/exit. Both of those
	 * events will be treated specially however, and
	 * increment/decrement being paired around their entry/exit means
	 * that collection here is not desynced otherwise.
	 */

	if (__improbable(count == 0 && sched_preemption_disable_debug_mode)) {
		__attribute__((musttail))
		return _prepare_preemption_disable_measurement();
	}
#endif /* SCHED_HYGIENE_DEBUG */
}


/*
 * This variant of disable_preemption() allows disabling preemption
 * without taking measurements (and later potentially triggering
 * actions on those).
 */
__attribute__((always_inline))
void
_disable_preemption_without_measurements(void)
{
	thread_t thread = current_thread();
	unsigned int count = thread->machine.preemption_count;

#if SCHED_HYGIENE_DEBUG
	/*
	 * Inform _collect_preemption_disable_measurement()
	 * that we didn't really care.
	 */
	thread->machine.preemption_disable_abandon = true;
#endif

	os_atomic_store(&thread->machine.preemption_count,
	    count + 1, compiler_acq_rel);
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

/*
 * This function is written in a way that the codegen is extremely short.
 *
 * LTO isn't smart enough to inline it, yet it is profitable because
 * the vast majority of callers use current_thread() already.
 *
 * The SCHED_HYGIENE_MARKER trick is used so that we do not have to load
 * unrelated fields of current_thread().
 *
 * /!\ Breaking inlining causes zalloc to be roughly 10% slower /!\
 */
__attribute__((always_inline))
void
_enable_preemption(void)
{
	thread_t thread = current_thread();
	unsigned int count  = thread->machine.preemption_count;

	if (__improbable(count == 0)) {
		_enable_preemption_underflow();
	}

#if SCHED_HYGIENE_DEBUG
	if (__improbable(count == SCHED_HYGIENE_MARKER + 1)) {
		return _collect_preemption_disable_measurement();
	}
#endif /* SCHED_HYGIENE_DEBUG */

	_enable_preemption_write_count(thread, count - 1);
}

__attribute__((always_inline))
unsigned int
get_preemption_level_for_thread(thread_t thread)
{
	unsigned int count = thread->machine.preemption_count;

#if SCHED_HYGIENE_DEBUG
	/*
	 * hide this "flag" from callers,
	 * and it would make the count look negative anyway
	 * which some people dislike
	 */
	count &= ~SCHED_HYGIENE_MARKER;
#endif
	return (int)count;
}

__attribute__((always_inline))
int
get_preemption_level(void)
{
	return get_preemption_level_for_thread(current_thread());
}

#if CONFIG_PV_TICKET
__startup_func
void
lck_init_pv(void)
{
	uint32_t pvtck = 1;
	PE_parse_boot_argn("pvticket", &pvtck, sizeof(pvtck));
	if (pvtck == 0) {
		return;
	}
	has_lock_pv = hvg_is_hcall_available(HVG_HCALL_VCPU_WFK) &&
	    hvg_is_hcall_available(HVG_HCALL_VCPU_KICK);
}
STARTUP(LOCKS, STARTUP_RANK_FIRST, lck_init_pv);
#endif


#pragma mark lck_spin_t
#if LCK_SPIN_IS_TICKET_LOCK

lck_spin_t *
lck_spin_alloc_init(lck_grp_t *grp, lck_attr_t *attr)
{
	lck_spin_t *lck;

	lck = zalloc(KT_LCK_SPIN);
	lck_spin_init(lck, grp, attr);
	return lck;
}

void
lck_spin_free(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_spin_destroy(lck, grp);
	zfree(KT_LCK_SPIN, lck);
}

void
lck_spin_init(lck_spin_t *lck, lck_grp_t *grp, __unused lck_attr_t *attr)
{
	lck_ticket_init(lck, grp);
}

/*
 * arm_usimple_lock is a lck_spin_t without a group or attributes
 */
MARK_AS_HIBERNATE_TEXT void inline
arm_usimple_lock_init(simple_lock_t lck, __unused unsigned short initial_value)
{
	lck_ticket_init((lck_ticket_t *)lck, LCK_GRP_NULL);
}

void
lck_spin_assert(const lck_spin_t *lock, unsigned int type)
{
	if (type == LCK_ASSERT_OWNED) {
		lck_ticket_assert_owned(lock);
	} else if (type == LCK_ASSERT_NOTOWNED) {
		lck_ticket_assert_not_owned(lock);
	} else {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}
}

void
lck_spin_lock(lck_spin_t *lock)
{
	lck_ticket_lock(lock, LCK_GRP_NULL);
}

void
lck_spin_lock_nopreempt(lck_spin_t *lock)
{
	lck_ticket_lock_nopreempt(lock, LCK_GRP_NULL);
}

int
lck_spin_try_lock(lck_spin_t *lock)
{
	return lck_ticket_lock_try(lock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_nopreempt(lck_spin_t *lock)
{
	return lck_ticket_lock_try_nopreempt(lock, LCK_GRP_NULL);
}

void
lck_spin_unlock(lck_spin_t *lock)
{
	lck_ticket_unlock(lock);
}

void
lck_spin_destroy(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_ticket_destroy(lck, grp);
}

/*
 * those really should be in an alias file instead,
 * but you can't make that conditional.
 *
 * it will be good enough for perf evals for now
 *
 * we also can't make aliases for symbols that
 * are in alias files like lck_spin_init and friends,
 * so this suffers double jump penalties for kexts
 * (LTO does the right thing for XNU).
 */
#define make_alias(a, b) asm(".globl _" #a "\n" ".set   _" #a ", _" #b "\n")
make_alias(lck_spin_lock_grp, lck_ticket_lock);
make_alias(lck_spin_lock_nopreempt_grp, lck_ticket_lock_nopreempt);
make_alias(lck_spin_try_lock_grp, lck_ticket_lock_try);
make_alias(lck_spin_try_lock_nopreempt_grp, lck_ticket_lock_try_nopreempt);
make_alias(lck_spin_unlock_nopreempt, lck_ticket_unlock_nopreempt);
make_alias(kdp_lck_spin_is_acquired, kdp_lck_ticket_is_acquired);
#undef make_alias

#else /* !LCK_SPIN_IS_TICKET_LOCK */

#if DEVELOPMENT || DEBUG
__abortlike
static void
__lck_spin_invalid_panic(lck_spin_t *lck)
{
	const char *how = "Invalid";

	if (lck->type == LCK_SPIN_TYPE_DESTROYED ||
	    lck->lck_spin_data == LCK_SPIN_TAG_DESTROYED) {
		how = "Destroyed";
	}

	panic("%s spinlock %p: <0x%016lx 0x%16lx>",
	    how, lck, lck->lck_spin_data, lck->type);
}

static inline void
lck_spin_verify(lck_spin_t *lck)
{
	if (lck->type != LCK_SPIN_TYPE ||
	    lck->lck_spin_data == LCK_SPIN_TAG_DESTROYED) {
		__lck_spin_invalid_panic(lck);
	}
}
#else /* DEVELOPMENT || DEBUG */
#define lck_spin_verify(lck)            ((void)0)
#endif /* DEVELOPMENT || DEBUG */

lck_spin_t *
lck_spin_alloc_init(lck_grp_t *grp, lck_attr_t *attr)
{
	lck_spin_t *lck;

	lck = zalloc(KT_LCK_SPIN);
	lck_spin_init(lck, grp, attr);
	return lck;
}

void
lck_spin_free(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_spin_destroy(lck, grp);
	zfree(KT_LCK_SPIN, lck);
}

void
lck_spin_init(lck_spin_t *lck, lck_grp_t *grp, __unused lck_attr_t *attr)
{
	lck->type = LCK_SPIN_TYPE;
	hw_lock_init(&lck->hwlock);
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_spincnt);
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

void
lck_spin_assert(const lck_spin_t *lock, unsigned int type)
{
	thread_t thread, holder;

	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}

	holder = HW_LOCK_STATE_TO_THREAD(lock->lck_spin_data);
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
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}
}

void
lck_spin_lock(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_lock(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	hw_lock_lock(&lock->hwlock, grp);
}

void
lck_spin_lock_nopreempt(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_lock_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	hw_lock_lock_nopreempt(&lock->hwlock, grp);
}

int
lck_spin_try_lock(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	return hw_lock_try(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	return hw_lock_try(&lock->hwlock, grp);
}

int
lck_spin_try_lock_nopreempt(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	return hw_lock_try_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	return hw_lock_try_nopreempt(&lock->hwlock, grp);
}

void
lck_spin_unlock(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_unlock(&lock->hwlock);
}

void
lck_spin_unlock_nopreempt(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_unlock_nopreempt(&lock->hwlock);
}

void
lck_spin_destroy(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_spin_verify(lck);
	*lck = (lck_spin_t){
		.lck_spin_data = LCK_SPIN_TAG_DESTROYED,
		.type = LCK_SPIN_TYPE_DESTROYED,
	};
	if (grp) {
		lck_grp_deallocate(grp, &grp->lck_grp_spincnt);
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

#endif /* !LCK_SPIN_IS_TICKET_LOCK */

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
