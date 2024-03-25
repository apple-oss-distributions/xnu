/*
 * Copyright (c) 2017-2019 Apple Inc. All rights reserved.
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
#ifndef KERN_MONOTONIC_H
#define KERN_MONOTONIC_H

#if CONFIG_CPU_COUNTERS

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

extern bool mt_debug;
extern _Atomic uint64_t mt_pmis;
extern _Atomic uint64_t mt_retrograde;

void mt_fixed_counts(uint64_t *counts);
uint64_t mt_cur_cpu_instrs(void);
uint64_t mt_cur_cpu_cycles(void);
void mt_cur_cpu_cycles_instrs_speculative(uint64_t *cycles, uint64_t *instrs);

bool mt_acquire_counters(void);
bool mt_owns_counters(void);
void mt_ownership_change(bool available);
void mt_release_counters(void);

__END_DECLS

#if MACH_KERNEL_PRIVATE

#include <kern/thread.h>
#include <kern/task.h>
#include <stdbool.h>

__BEGIN_DECLS

#if defined(__arm__) || defined(__arm64__)
#include <arm/cpu_data_internal.h>
#elif defined(__x86_64__)
#include <i386/cpu_data.h>
#else /* !defined(__arm__) && !defined(__arm64__) && !defined(__x86_64__) */
#error unsupported architecture
#endif /* !defined(__arm__) && !defined(__arm64__) && !defined(__x86_64__) */

void mt_update_fixed_counts(void);

/*
 * Private API for the platform layers.
 */

/*
 * Called once early in boot, before CPU initialization occurs (where
 * `mt_cpu_up` is called).
 *
 * This allows monotonic to detect if the hardware supports performance counters
 * and install the global PMI handler.
 */
void mt_early_init(void);

/*
 * Called when a core is idling and exiting from idle.
 */
void mt_cpu_idle(cpu_data_t *cpu);
void mt_cpu_run(cpu_data_t *cpu);

/*
 * Called when a core is shutting down or powering up.
 */
void mt_cpu_down(cpu_data_t *cpu);
void mt_cpu_up(cpu_data_t *cpu);

/*
 * Called while single-threaded when the system is going to sleep.
 */
void mt_sleep(void);

/*
 * Called on each CPU as the system is waking from sleep.
 */
void mt_wake_per_core(void);

/*
 * "Up-call" to the Mach layer to update counters from a PMI.
 */
uint64_t mt_cpu_update_count(cpu_data_t *cpu, unsigned int ctr);

/*
 * Private API for the performance controller callout.
 */
void mt_perfcontrol(uint64_t *instrs, uint64_t *cycles);

/*
 * Private API for microstackshot.
 */
typedef void (*mt_pmi_fn)(bool user_mode, void *ctx);
int mt_microstackshot_start(unsigned int ctr, uint64_t period, mt_pmi_fn fn,
    void *ctx);
int mt_microstackshot_stop(void);

__END_DECLS

#endif /* MACH_KERNEL_PRIVATE */

#endif /* CONFIG_CPU_COUNTERS */

#endif /* !defined(KERN_MONOTONIC_H) */
