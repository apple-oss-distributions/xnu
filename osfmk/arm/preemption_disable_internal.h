/*
 * Copyright (c) 2020-2023 Apple Inc. All rights reserved.
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

#include <kern/percpu.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#pragma once


/**
 * Track time and other counters during a preemption disabled window,
 * when `SCHED_HYGIENE` is configured.
 */
struct _preemption_disable_pcpu {
	/**
	 * A snapshot of times and counters relevant to preemption disable measurement.
	 */
	struct _preemption_disable_snap {
		/* The time when preemption was disabled, in Mach time units. */
		uint64_t pds_mach_time;
		/* The amount of time spent in interrupts by the current CPU, in Mach time units. */
		uint64_t pds_int_mach_time;
#if MONOTONIC
		/* The number of cycles elapsed on this CPU. */
		uint64_t pds_cycles;
		/* The number of instructions seen by this CPU. */
		uint64_t pds_instrs;
#endif /* MONOTONIC */
	}
	/* At the start of the preemption disabled window. */
	pdp_start;

	/* The maximum duration seen by this CPU, in Mach time units. */
	_Atomic uint64_t pdp_max_mach_duration;
	/*
	 * Whether to abandon the measurement on this CPU,
	 * due to a call to abandon_preemption_disable_measurement().
	 */
	bool pdp_abandon;
};

PERCPU_DECL(struct _preemption_disable_pcpu, _preemption_disable_pcpu_data);
