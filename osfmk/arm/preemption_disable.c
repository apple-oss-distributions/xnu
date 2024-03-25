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
 * TODO: It is unfortunate that we have to load
 *       sched_preemption_disable_debug_mode
 *
 * /!\ Breaking inlining causes zalloc to be roughly 10% slower /!\
 */
OS_ALWAYS_INLINE
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
OS_ALWAYS_INLINE
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
OS_ALWAYS_INLINE
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
static void
_preemption_disable_snap_start(void)
{
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);
	pcpu->pdp_abandon = false;
	pcpu->pdp_start.pds_mach_time = ml_get_sched_hygiene_timebase();
	pcpu->pdp_start.pds_int_mach_time = recount_current_processor_interrupt_time_mach();
#if CONFIG_CPU_COUNTERS
	if (__probable(sched_hygiene_debug_pmc)) {
		mt_cur_cpu_cycles_instrs_speculative(&pcpu->pdp_start.pds_cycles,
		    &pcpu->pdp_start.pds_instrs);
	}
#endif /* CONFIG_CPU_COUNTERS */
}

/*
**
* End a measurement window for the current CPU's preemption disable timeout,
* using the snapshot started by _preemption_disable_snap_start().
*
* @param start An out-parameter for the starting snapshot,
* captured while interrupts are disabled.
*
* @param now An out-parameter for the current times,
* captured at the same time as the start and with interrupts disabled.
* This is meant for computing a delta.
* Even with @link sched_hygiene_debug_pmc , the PMCs will not be read.
* This allows their (relatively expensive) reads to happen only if the time threshold has been violated.
*
* @return Whether to abandon the current measurement due to a call to abandon_preemption_disable_measurement().
*/
static bool
_preemption_disable_snap_end(
	struct _preemption_disable_snap *start,
	struct _preemption_disable_snap *now)
{
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);

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

	*start = pcpu->pdp_start;
	uint64_t now_time = ml_get_sched_hygiene_timebase();
	now->pds_mach_time = now_time;
	now->pds_int_mach_time = recount_current_processor_interrupt_time_mach();
	const bool abandon = pcpu->pdp_abandon;
	const uint64_t max_duration = os_atomic_load(&pcpu->pdp_max_mach_duration, relaxed);

	pcpu->pdp_start.pds_mach_time = 0;

	/*
	 * Don't need to reset (or even save) pdp_abandon here:
	 * abandon_preemption_disable_measurement is a no-op anyway
	 * if pdp_start.pds_mach_time == 0 (which we just set), and it
	 * will stay that way until the next call to
	 * _collect_preemption_disable_measurement.
	 */
	ml_set_interrupts_enabled_with_debug(istate, int_masked_debug);
	if (__probable(!abandon)) {
		const int64_t gross_duration = now_time - start->pds_mach_time;
		if (__improbable(gross_duration > max_duration)) {
			os_atomic_store(&pcpu->pdp_max_mach_duration, gross_duration, relaxed);
		}
	}
	return abandon;
}

OS_NOINLINE
void
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
	struct _preemption_disable_snap start = { 0 };
	struct _preemption_disable_snap now = { 0 };
	const bool abandon = _preemption_disable_snap_end(&start, &now);

	if (__improbable(abandon)) {
		goto out;
	}

	int64_t const gross_duration = now.pds_mach_time - start.pds_mach_time;
	uint64_t const threshold = os_atomic_load(&sched_preemption_disable_threshold_mt, relaxed);
	if (__improbable(threshold > 0 && gross_duration >= threshold)) {
		/*
		 * Double check that the time spent not handling interrupts is over the threshold.
		 */
		int64_t const interrupt_duration = now.pds_int_mach_time - start.pds_int_mach_time;
		int64_t const net_duration = gross_duration - interrupt_duration;
		assert3u(net_duration, >=, 0);
		if (net_duration < threshold) {
			goto out;
		}

		uint64_t average_freq = 0;
		uint64_t average_cpi_whole = 0;
		uint64_t average_cpi_fractional = 0;

#if CONFIG_CPU_COUNTERS
		if (__probable(sched_hygiene_debug_pmc)) {
			/*
			 * We're getting these values a bit late, but getting them
			 * is a bit expensive, so we take the slight hit in
			 * accuracy for the reported values (which aren't very
			 * stable anyway).
			 */
			const bool int_masked_debug = false;
			const bool istate = ml_set_interrupts_enabled_with_debug(false, int_masked_debug);
			mt_cur_cpu_cycles_instrs_speculative(&now.pds_cycles, &now.pds_instrs);
			ml_set_interrupts_enabled_with_debug(istate, int_masked_debug);
			const uint64_t cycles_elapsed = now.pds_cycles - start.pds_cycles;
			const uint64_t instrs_retired = now.pds_instrs - start.pds_instrs;

			uint64_t duration_ns;
			absolutetime_to_nanoseconds(gross_duration, &duration_ns);

			average_freq = cycles_elapsed / (duration_ns / 1000);
			average_cpi_whole = cycles_elapsed / instrs_retired;
			average_cpi_fractional =
			    ((cycles_elapsed * 100) / instrs_retired) % 100;
		}
#endif /* CONFIG_CPU_COUNTERS */

		if (__probable(sched_preemption_disable_debug_mode == SCHED_HYGIENE_MODE_PANIC)) {
			panic("preemption disable timeout exceeded: %llu >= %llu mt ticks (start: %llu, now: %llu, gross: %llu, inttime: %llu), "
			    "freq = %llu MHz, CPI = %llu.%llu",
			    net_duration, threshold, start.pds_mach_time, now.pds_mach_time,
			    gross_duration, interrupt_duration,
			    average_freq, average_cpi_whole, average_cpi_fractional);
		}

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
	const bool int_masked_debug = false;
	bool istate = ml_set_interrupts_enabled_with_debug(false, int_masked_debug);
	struct _preemption_disable_pcpu *pcpu = PERCPU_GET(_preemption_disable_pcpu_data);
	if (pcpu->pdp_start.pds_mach_time != 0) {
		pcpu->pdp_abandon = true;
	}
	ml_set_interrupts_enabled_with_debug(istate, int_masked_debug);
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
	pcpu->pdp_abandon = true;
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
sched_perfcontrol_abandon_preemption_disable_measurement(void)
{
	// No-op. Function is exported, so needs to be defined
}

#endif /* SCHED_HYGIENE_DEBUG */
