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
/*
 * @OSF_COPYRIGHT@
 *
 */

#include <stdbool.h>
#include <stdint.h>

#ifndef KERN_SCHED_HYGIENE_DEBUG
#define KERN_SCHED_HYGIENE_DEBUG

#if SCHED_HYGIENE_DEBUG

#include <mach/mach_types.h>

#include <kern/startup.h>

typedef enum sched_hygiene_mode {
	SCHED_HYGIENE_MODE_OFF = 0,
	SCHED_HYGIENE_MODE_TRACE = 1,
	SCHED_HYGIENE_MODE_PANIC = 2,
} sched_hygiene_mode_t;

extern boolean_t sched_hygiene_debug_pmc;

extern sched_hygiene_mode_t sched_preemption_disable_debug_mode;

MACHINE_TIMEOUT_SPEC_DECL(sched_preemption_disable_threshold_mt);
extern machine_timeout_t sched_preemption_disable_threshold_mt;

__attribute__((noinline)) void _prepare_preemption_disable_measurement(thread_t thread);
__attribute__((noinline)) void _collect_preemption_disable_measurement(thread_t thread);

extern sched_hygiene_mode_t interrupt_masked_debug_mode;

MACHINE_TIMEOUT_SPEC_DECL(interrupt_masked_timeout);
MACHINE_TIMEOUT_SPEC_DECL(stackshot_interrupt_masked_timeout);

extern machine_timeout_t interrupt_masked_timeout;
extern machine_timeout_t stackshot_interrupt_masked_timeout;

extern bool sched_hygiene_nonspec_tb;

#define ml_get_sched_hygiene_timebase() (sched_hygiene_nonspec_tb ? ml_get_timebase() : ml_get_speculative_timebase())

extern bool kprintf_spam_mt_pred(struct machine_timeout_spec const *spec);

#endif /* SCHED_HYGIENE_DEBUG */

#endif /* KERN_SCHED_HYGIENE_DEBUG */
