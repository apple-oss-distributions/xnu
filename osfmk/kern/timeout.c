/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <kern/timeout.h>
#include <kern/clock.h>
#include <kern/monotonic.h>
#include <kern/recount.h>
#include <kern/debug.h>
#include <kern/backtrace.h>
#include <kern/trap_telemetry.h>
#include <machine/machine_routines.h>


kern_timeout_t panic_timeout; /* for debugging */
boolean_t kern_timeout_panic_initiated = false;

#if defined(__x86_64__)
#define ml_get_speculative_timebase ml_get_timebase
#endif

#if DEVELOPMENT || DEBUG
TUNABLE_DT_WRITEABLE(int, timeouts_are_fatal, "machine-timeouts", "timeouts-are-fatal",
    "timeouts_are_fatal", 1, TUNABLE_DT_CHECK_CHOSEN);
#endif

void
kern_timeout_restart(kern_timeout_t *to, timeout_flags_t flags)
{
#if CONFIG_CPU_COUNTERS
	if (__improbable(!(flags & TF_SAMPLE_PMC))) {
		to->start_cycles = 0;
		to->start_instrs = 0;
	} else {
		struct cpc_cycles_instrs counts = cpc_cycles_instrs_spec();
		to->start_cycles = counts.cycles;
		to->start_instrs = counts.instrs;
	}
#endif /* CONFIG_CPU_COUNTERS */

	if (flags & TF_SAMPLE_INTERRUPT_TIME) {
		to->int_mt = recount_current_processor_interrupt_duration_mach();
	} else {
		to->int_mt = 0;
	}

	to->start_mt = (flags & TF_NONSPEC_TIMEBASE)? ml_get_timebase() : ml_get_speculative_timebase();
}

void
kern_timeout_start(kern_timeout_t *to, timeout_flags_t flags)
{
	if (flags & TF_BACKTRACE) {
		(void) backtrace(&to->bt[0], TO_BT_FRAMES, NULL, NULL);
	}
	kern_timeout_restart(to, flags);
}

void
kern_timeout_end(kern_timeout_t *to, timeout_flags_t flags)
{
	to->end_mt = (flags & TF_NONSPEC_TIMEBASE)? ml_get_timebase() : ml_get_speculative_timebase();
	if (flags & TF_SAMPLE_INTERRUPT_TIME) {
		to->int_mt = recount_current_processor_interrupt_duration_mach() - to->int_mt;
	}
}

/*
 * Zero out the timeout state so that we won't have a timeout triggered later in the processing
 * of this timeout.
 */
void
kern_timeout_override(kern_timeout_t *to)
{
	to->start_mt = 0;
#if CONFIG_CPU_COUNTERS
	to->start_cycles = 0;
	to->start_instrs = 0;
#endif /* CONFIG_CPU_COUNTERS */
}

#if CONFIG_CPU_COUNTERS
void
kern_timeout_cycles_instrs(kern_timeout_t *to, uint64_t *cycles, uint64_t *instrs)
{
	if (__improbable(to->start_cycles == 0)) {
		*cycles = 0;
		*instrs = 0;
	} else {
		struct cpc_cycles_instrs counts = cpc_cycles_instrs_spec();
		*cycles = counts.cycles - to->start_cycles;
		*instrs = counts.instrs - to->start_instrs;
	}
}

void
kern_timeout_cpi(kern_timeout_t *to, uint64_t *cpi_whole, uint64_t *cpi_fractional)
{
	uint64_t cycles, instrs;

	kern_timeout_cycles_instrs(to, &cycles, &instrs);
	*cpi_whole = cycles / instrs;
	*cpi_fractional = ((cycles * 100) / instrs) % 100;
}
#else /* !CONFIG_CPU_COUNTERS */
void
kern_timeout_cycles_instrs(kern_timeout_t __unused *to, uint64_t *cycles, uint64_t *instrs)
{
	*cycles = 0;
	*instrs = 0;
}

void
kern_timeout_cpi(kern_timeout_t __unused *to, uint64_t *cpi_whole, uint64_t *cpi_fractional)
{
	*cpi_whole = 0;
	*cpi_fractional = 0;
}
#endif /* CONFIG_CPU_COUNTERS */

__enum_closed_decl(timeout_mode_t, uint32_t, {
	TIMEOUT_TELEMETRY,
	TIMEOUT_PANIC
});

/*
 * This interface is a "try panic" because we won't invoke a nested panic
 * if a timeout has already happened that initiated the original panic.
 */
void
kern_timeout_try_panic(kern_timeout_type_t __unused type, uint64_t __unused payload, kern_timeout_t *to, const char *prefix, uint64_t threshold)
{
	char cpi[80];
	char duration[80];
	const uint64_t gross_duration = kern_timeout_gross_duration(to);
	const uint64_t net_duration = kern_timeout_net_duration(to);
	uint64_t gross_ns, net_ns, threshold_ns;
	uint64_t gross_us, net_us, threshold_us;
	uint64_t gross_ms, net_ms, threshold_ms;
	uint64_t start_mt, end_mt;
	uint64_t __unused average_freq = 0;
	uint64_t __unused cpi_whole = 0;
#ifdef __arm64__
	const char __unused core_type = ml_get_current_core_type();
#else
	const char __unused core_type = '-';
#endif /* __arm64__ */

	/*
	 * We can recursively try to panic due to a timeout in the panic flow,
	 * so if that happens, just bail out here.
	 */
	if (kern_timeout_panic_initiated) {
		return;
	}

	absolutetime_to_nanoseconds(gross_duration, &gross_ns);
	absolutetime_to_nanoseconds(net_duration, &net_ns);
	absolutetime_to_nanoseconds(threshold, &threshold_ns);
	kern_timeout_mach_times(to, &start_mt, &end_mt);

	cpi[0] = 0;

#if CONFIG_CPU_COUNTERS
	uint64_t cycles;
	uint64_t instrs;

	/*
	 * We're getting these values a bit late, but getting them
	 * is a bit expensive, so we take the slight hit in
	 * accuracy for the reported values (which aren't very
	 * stable anyway).
	 */
	kern_timeout_cycles_instrs(to, &cycles, &instrs);
	if (cycles > 0 && instrs > 0) {
		cpi_whole = cycles / instrs;
		average_freq = cycles / (gross_ns / 1000);
	}
#endif /* CONFIG_CPU_COUNTERS */

#if DEVELOPMENT || DEBUG
	timeout_mode_t mode = timeouts_are_fatal ? TIMEOUT_PANIC : TIMEOUT_TELEMETRY;
	if (mode == TIMEOUT_PANIC) {

#if CONFIG_CPU_COUNTERS && !defined(HAS_FEAT_XS)
		/*
		 * POLICY: if CPI > 100 and we are on a SoC that does not support
		 * FEAT_XS, it's likely the stall was caused by a long TLBI. This
		 * isn't an actionable radar condition for preemption or interrupt
		 * disabled timeouts, so do nothing.
		 */
		if ((type == KERN_TIMEOUT_PREEMPTION || type == KERN_TIMEOUT_INTERRUPT) &&
		    cpi_whole > 100) {
			return;
		}
#endif /* CONFIG_CPU_COUNTERS && !HAS_FEAT_XS */

#if ML_IO_TIMEOUTS_ENABLED
		/*
		 * POLICY: check the MMIO override window to see if we are still
		 * within it. If we are, abandon the attempt to panic, since
		 * the timeout is almost certainly due to a known issue causing
		 * a stall that got entangled with this core. We don't emit
		 * telemetry in this case because the MMIO overrides have their
		 * own telemetry mechanism.
		 */
		if (ml_io_check_for_mmio_overrides(start_mt)) {
			return;
		}
#endif /* ML_IO_TIMEOUTS_ENABLED */
	}

	if (mode == TIMEOUT_TELEMETRY) {
		trap_telemetry_type_t trap_type;
		switch (type) {
		case KERN_TIMEOUT_PREEMPTION:
			trap_type = TRAP_TELEMETRY_TYPE_PREEMPTION_TIMEOUT;
			break;
		case KERN_TIMEOUT_INTERRUPT:
			trap_type = TRAP_TELEMETRY_TYPE_INTERRUPT_TIMEOUT;
			break;
		case KERN_TIMEOUT_MMIO:
			trap_type = TRAP_TELEMETRY_TYPE_MMIO_TIMEOUT;
			break;
		case KERN_TIMEOUT_LOCK:
			trap_type = TRAP_TELEMETRY_TYPE_LOCK_TIMEOUT;
			break;
		default:
			panic("unknown timeout type\n");
		}
		trap_telemetry_report_latency_violation(
			trap_type,
			(trap_telemetry_latency_s) {
			.violation_cpi = cpi_whole,
			.violation_freq = average_freq,
			.violation_cpu_type = core_type,
			.violation_duration = net_ns,
			.violation_threshold = threshold_ns,
			.violation_payload = payload
		});
		return;
	}
#endif /* DEVELOPMENT || DEBUG */

	kern_timeout_panic_initiated = true;
	panic_timeout = *to;

	gross_us = gross_ns / 1000;
	net_us = net_ns / 1000;
	threshold_us = threshold_ns / 1000;
	gross_ms = gross_us / 1000;
	net_ms = net_us / 1000;
	threshold_ms = threshold_us / 1000;

#if CONFIG_CPU_COUNTERS
	if (cycles > 0 && instrs > 0) {
		uint64_t cpi_fractional;

		cpi_fractional = ((cycles * 100) / instrs) % 100;

		snprintf(cpi, sizeof(cpi), ", freq %llu MHz, type = %c, CPI = %llu.%llu [%llu, %llu]",
		    average_freq, core_type, cpi_whole, cpi_fractional, cycles, instrs);
	}
#endif /* CONFIG_CPU_COUNTERS */

	if (gross_ns > net_ns) {
		if (threshold_ms > 0) {
			snprintf(duration, sizeof(duration), "gross %llu.%llu ms, net %llu.%llu ms >= %llu.%llu ms",
			    gross_ms, gross_us % 1000, net_ms, net_us % 1000, threshold_ms, threshold_us % 1000);
		} else {
			snprintf(duration, sizeof(duration), "gross %llu us, net %llu us >= %llu us",
			    gross_us, net_us, threshold_us);
		}
	} else {
		if (threshold_ms > 0) {
			snprintf(duration, sizeof(duration), "%llu.%llu ms >= %llu.%llu ms",
			    gross_ms, gross_us % 1000, threshold_ms, threshold_us % 1000);
		} else {
			snprintf(duration, sizeof(duration), "%llu us >= %llu us",
			    gross_us, threshold_us);
		}
	}

	panic_plain("%s %s (start: %llu, end: %llu)%s", prefix, duration, start_mt, end_mt, cpi);
}

