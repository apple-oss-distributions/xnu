/*
 * Copyright (c) 2007-2023 Apple Inc. All rights reserved.
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
 * Routines for preemption disablement,
 * which prevents the current thread from giving up its current CPU.
 */

#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/preemption_disable_internal.h>
#include <kern/cpu_data.h>
#include <kern/percpu.h>
#include <kern/thread.h>
#include <mach/machine/sdt.h>
#include <os/base.h>
#include <stdint.h>
#include <sys/kdebug.h>

#if SCHED_HYGIENE_DEBUG
static void
_do_disable_preemption_without_measurements(void);
#endif

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
static OS_NOINLINE
void
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

/*
 * This function is written in a way that the codegen is extremely short.
 *
 * LTO isn't smart enough to inline it, yet it is profitable because
 * the vast majority of callers use current_thread() already.
 *
 * /!\ Breaking inlining causes zalloc to be roughly 10% slower /!\
 */
OS_ALWAYS_INLINE __mockable
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
	if (improbable_static_if(sched_debug_preemption_disable)) {
		if (__improbable(count == 0)) {
			__attribute__((musttail))
			return _prepare_preemption_disable_measurement();
		}
	}
#endif /* SCHED_HYGIENE_DEBUG */
}

/*
 * This variant of disable_preemption() allows disabling preemption
 * without taking measurements (and later potentially triggering
 * actions on those).
 */
OS_ALWAYS_INLINE __mockable
void
_disable_preemption_without_measurements(void)
{
	thread_t thread = current_thread();
	unsigned int count = thread->machine.preemption_count;

#if SCHED_HYGIENE_DEBUG
	_do_disable_preemption_without_measurements();
#endif /* SCHED_HYGIENE_DEBUG */

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
OS_ALWAYS_INLINE __mockable
void
_enable_preemption(void)
{
	thread_t thread = current_thread();
	unsigned int count  = thread->machine.preemption_count;

	if (__improbable(count == 0)) {
		_enable_preemption_underflow();
	}

#if SCHED_HYGIENE_DEBUG
	if (improbable_static_if(sched_debug_preemption_disable)) {
		if (__improbable(count == SCHED_HYGIENE_MARKER + 1)) {
			return _collect_preemption_disable_measurement();
		}
	}
#endif /* SCHED_HYGIENE_DEBUG */

	_enable_preemption_write_count(thread, count - 1);
}

OS_ALWAYS_INLINE
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

OS_ALWAYS_INLINE
int
get_preemption_level(void)
{
	return get_preemption_level_for_thread(current_thread());
}

#if SCHED_HYGIENE_DEBUG

uint64_t _Atomic PERCPU_DATA_HACK_78750602(preemption_disable_max_mt);

#if XNU_PLATFORM_iPhoneOS
#define DEFAULT_PREEMPTION_TIMEOUT 120000 /* 5ms */
#define DEFAULT_PREEMPTION_MODE SCHED_HYGIENE_MODE_PANIC
#elif XNU_PLATFORM_XROS
#define DEFAULT_PREEMPTION_TIMEOUT 24000  /* 1ms */
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

struct _preemption_disable_pcpu PERCPU_DATA(_preemption_disable_pcpu_data);

/*
** Start a measurement window for the current CPU's preemption disable timeout.
*
* Interrupts must be disabled when calling this function,
* but the assertion has been elided as this is on the fast path.
*/
OS_ALWAYS_INLINE
static void
_preemption_disable_snap_start(void)
{
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);
	const timeout_flags_t flags = ML_TIMEOUT_TIMEBASE_FLAGS | ML_TIMEOUT_PMC_FLAGS | TF_SAMPLE_INTERRUPT_TIME | TF_BACKTRACE;

	kern_timeout_start(&pcpu->pdp_timeout, flags);
}

/*
**
* End a measurement window for the current CPU's preemption disable timeout,
* using the snapshot started by _preemption_disable_snap_start().
*
* @param top An out-parameter for the current times,
* captured at the same time as the start and with interrupts disabled.
*
* This is meant for computing a delta.
* Even with @link sched_hygiene_debug_pmc , the PMCs will not be read.
* This allows their (relatively expensive) reads to happen only if the time threshold has been violated.
*
* @return Whether to abandon the current measurement due to a call to abandon_preemption_disable_measurement().
*/
OS_ALWAYS_INLINE
static bool
_preemption_disable_snap_end(kern_timeout_t *top)
{
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);
	const timeout_flags_t flags = ML_TIMEOUT_TIMEBASE_FLAGS | TF_SAMPLE_INTERRUPT_TIME;
	const bool int_masked_debug = false;
	const bool istate = ml_set_interrupts_enabled_with_debug(false, int_masked_debug);
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
	kern_timeout_end(&pcpu->pdp_timeout, flags);

	const uint64_t max_duration = os_atomic_load(&pcpu->pdp_max_mach_duration, relaxed);
	const uint64_t gross_duration = kern_timeout_gross_duration(&pcpu->pdp_timeout);
	if (__improbable(gross_duration > max_duration)) {
		os_atomic_store(&pcpu->pdp_max_mach_duration, gross_duration, relaxed);
	}

	*top = pcpu->pdp_timeout;
	ml_set_interrupts_enabled_with_debug(istate, int_masked_debug);

	return gross_duration == 0;
}

OS_NOINLINE
void
_prepare_preemption_disable_measurement(void)
{
	thread_t thread = current_thread();

	if (thread->machine.int_handler_addr == 0 &&
	    sched_preemption_disable_debug_mode) {
		/*
		 * Only prepare a measurement if not currently in an interrupt
		 * handler.
		 *
		 * We are only interested in the net duration of disabled
		 * preemption, that is: The time in which preemption was
		 * disabled, minus the intervals in which any (likely
		 * unrelated) interrupts were handled.
		 * recount_current_thread_interrupt_time_mach() will remove those
		 * intervals, however we also do not even start measuring
		 * preemption disablement if we are already within handling of
		 * an interrupt when preemption was disabled (the resulting
		 * net time would be 0).
		 *
		 * Interrupt handling duration is handled separately, and any
		 * long intervals of preemption disablement are counted
		 * towards that.
		 */

		bool const int_masked_debug = false;
		bool istate = ml_set_interrupts_enabled_with_debug(false, int_masked_debug);
		thread->machine.preemption_count |= SCHED_HYGIENE_MARKER;
		_preemption_disable_snap_start();
		ml_set_interrupts_enabled_with_debug(istate, int_masked_debug);
	}
}

OS_NOINLINE
void
_collect_preemption_disable_measurement(void)
{
	kern_timeout_t to;
	const bool abandon = _preemption_disable_snap_end(&to);

	if (__improbable(abandon)) {
		goto out;
	}

	const uint64_t gross_duration = kern_timeout_gross_duration(&to);
	const uint64_t threshold = os_atomic_load(&sched_preemption_disable_threshold_mt, relaxed);
	if (__improbable(threshold > 0 && gross_duration >= threshold)) {
		/*
		 * Double check that the time spent not handling interrupts is over the threshold.
		 */
		const int64_t net_duration = kern_timeout_net_duration(&to);
		uint64_t average_cpi_whole, average_cpi_fractional;

		assert3u(net_duration, >=, 0);
		if (net_duration < threshold) {
			goto out;
		}

		if (__probable(sched_preemption_disable_debug_mode == SCHED_HYGIENE_MODE_PANIC)) {
			kern_timeout_try_panic(KERN_TIMEOUT_PREEMPTION, 0, &to,
			    "preemption disable timeout exceeded:", threshold);
		}

		kern_timeout_cpi(&to, &average_cpi_whole, &average_cpi_fractional);

		DTRACE_SCHED4(mach_preemption_expired, uint64_t, net_duration, uint64_t, gross_duration,
		    uint64_t, average_cpi_whole, uint64_t, average_cpi_fractional);
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PREEMPTION_EXPIRED), net_duration, gross_duration, average_cpi_whole, average_cpi_fractional);
	}

out:
	/*
	 * the preemption count is SCHED_HYGIENE_MARKER, we need to clear it.
	 */
	_enable_preemption_write_count(current_thread(), 0);
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
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);

	kern_timeout_override(&pcpu->pdp_timeout);
}

/* Inner part of disable_preemption_without_measuerments() */
OS_ALWAYS_INLINE
static void
_do_disable_preemption_without_measurements(void)
{
	/*
	 * Inform _collect_preemption_disable_measurement()
	 * that we didn't really care.
	 */
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);
	kern_timeout_override(&pcpu->pdp_timeout);
}

/**
 * Reset the max interrupt durations of all CPUs.
 */
void preemption_disable_reset_max_durations(void);
void
preemption_disable_reset_max_durations(void)
{
	percpu_foreach(pcpu, _preemption_disable_pcpu_data) {
		os_atomic_store(&pcpu->pdp_max_mach_duration, 0, relaxed);
	}
}

unsigned int preemption_disable_get_max_durations(uint64_t *durations, size_t count);
unsigned int
preemption_disable_get_max_durations(uint64_t *durations, size_t count)
{
	int cpu = 0;
	percpu_foreach(pcpu, _preemption_disable_pcpu_data) {
		if (cpu < count) {
			durations[cpu++] = os_atomic_load(&pcpu->pdp_max_mach_duration, relaxed);
		}
	}
	return cpu;
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
abandon_preemption_disable_measurement(void)
{
	// No-op. Function is exported, so needs to be defined
}

void
sched_perfcontrol_abandon_preemption_disable_measurement(void)
{
	// No-op. Function is exported, so needs to be defined
}

#endif /* SCHED_HYGIENE_DEBUG */
