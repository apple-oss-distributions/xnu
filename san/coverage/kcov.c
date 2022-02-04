/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
#include <string.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <libkern/libkern.h>
#include <os/atomic_private.h>
#include <vm/pmap.h>
#include <machine/machine_routines.h>

#include <san/kcov.h>
#include <san/kcov_data.h>

#include <san/kcov_stksz.h>
#include <san/kcov_stksz_data.h>

#include <san/kcov_ksancov.h>
#include <san/kcov_ksancov_data.h>

/* Global flag that enables the sanitizer hook. */
static _Atomic unsigned int kcov_enabled = 0;


/*
 * Sysctl interface to coverage sanitizer.
 */
SYSCTL_DECL(_kern_kcov);
SYSCTL_NODE(_kern, OID_AUTO, kcov, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "kcov");


/*
 * Coverage sanitizer bootstrap.
 *
 * A compiler will add hooks almost in any basic block in the kernel. However it is
 * not safe to call hook from some of the contexts. To make this safe it would require
 * precise blacklist of all unsafe sources. Which results in high maintenance costs.
 *
 * To avoid this we bootsrap the coverage sanitizer in phases:
 *
 *   1. Kernel starts with globaly disabled coverage sanitizer. At this point the hook
 *      can access safely only global variables.
 *   2. The boot cpu has allocated/configured per-cpu data. At this point the hook can
 *      use per-cpu data by using current_* but only on the boot cpu.
 *
 *   ... From this point we can start recording on boot cpu
 *
 *   3. Additional CPUs are added by kext. We rely on the fact that default value of
 *      per-cpu variable is 0. The assumption here is that some other (already configured)
 *      cpu is running the bootsrap of secondary CPU which is safe. Once secondary gets
 *      configured the boostrap originator enables its converage sanitizer by writing
 *      secondary's per-cpu data.
 *
 *      To make this step safe, it is required to maintain blacklist that contains CPU
 *      bootstrap code to avoid firing hook from unsupported context.
 *
 *   ... From this point all CPUs can execute the hook correctly.
 *
 * This allows stack size monitoring during early boot. For all other cases we simply
 * boot with global set to 0 waiting for a client to actually enable sanitizer.
 */

/*
 * 1. & 2. enabling step. Must be called *after* per-cpu data are set up.
 */
__startup_func
static void
kcov_init(void)
{
	/* Master CPU is fully setup at this point so just enable coverage tracking. */
	printf("KCOV: Enabling coverage tracking on cpu %d\n", cpu_number());
	current_kcov_data()->kcd_enabled = 1;
}
STARTUP(EARLY_BOOT, STARTUP_RANK_LAST, kcov_init);

/*
 * 3. secondary CPU. Called on bootstrap originator after secondary is ready.
 */
void
kcov_start_cpu(int cpuid)
{
	printf("KCOV: Enabling coverage tracking on cpu %d\n", cpuid);
	/* No need to use atomics as we don't need to be so precise here. */
	cpu_kcov_data(cpuid)->kcd_enabled = 1;
}

void
kcov_enable(void)
{
	os_atomic_add(&kcov_enabled, 1, relaxed);
}

void
kcov_disable(void)
{
	os_atomic_sub(&kcov_enabled, 1, relaxed);
}


/*
 * Disable coverage sanitizer recording for given thread.
 */
static void
kcov_disable_thread(kcov_thread_data_t *data)
{
	data->ktd_disabled++;
}


/*
 * Enable coverage sanitizer recording for given thread.
 */
static void
kcov_enable_thread(kcov_thread_data_t *data)
{
	data->ktd_disabled--;
}


/*
 * Called when system enters panic code path with no return. There is no point in tracking
 * stack usage and delay (and possibly break) the coredump code.
 */
void
kcov_panic_disable(void)
{
	printf("KCOV: Disabling coverage tracking. System panicking.\n");
	/* Force disable the sanitizer hook. */
	os_atomic_store(&kcov_enabled, 0, relaxed);
}


/* Initialize per-thread sanitizer data for each new kernel thread. */
void
kcov_init_thread(kcov_thread_data_t *data)
{
	data->ktd_disabled = 0;

	kcov_ksancov_init_thread(&data->ktd_device);
	kcov_stksz_init_thread(&data->ktd_stksz);
}

/*
 * This is the core of the coverage recording.
 *
 * A compiler inlines this function into every place eligible for instrumentation.
 * Every modification is very risky as added code may be called from unexpected
 * contexts (for example per-cpu data access).
 *
 * Do not call anything unnecessary before ksancov_disable() as that will cause
 * recursion. Update blacklist after any such change.
 *
 * Every complex code here may have impact on the overall performance. This function
 * is called for every edge in the kernel and that means multiple times through a
 * single function execution.
 */
static void
trace_pc_guard(uint32_t __unused *guardp, void __unused *caller, uintptr_t __unused sp)
{
	kcov_ksancov_trace_guard(guardp, caller);

	/* Check the global flag for the case no recording is enabled. */
	if (__probable(os_atomic_load(&kcov_enabled, relaxed) == 0)) {
		return;
	}

	/* Per-cpu area access. Must happen with disabled interrupts/preemtion. */
	disable_preemption();

	if (!current_kcov_data()->kcd_enabled) {
		enable_preemption();
		return;
	}

	/* No support for PPL. */
	if (pmap_in_ppl()) {
		enable_preemption();
		return;
	}
	/* Interrupt context not supported. */
	if (ml_at_interrupt_context()) {
		enable_preemption();
		return;
	}

	thread_t th = current_thread();
	if (__improbable(th == THREAD_NULL)) {
		enable_preemption();
		return;
	}

	/* This thread does not want to record stack usage. */
	kcov_thread_data_t *data = kcov_get_thread_data(th);
	if (__improbable(data->ktd_disabled) != 0) {
		enable_preemption();
		return;
	}

	/* Enable preemption as we are no longer accessing per-cpu data. */
	enable_preemption();

	/* It is now safe to call back to kernel from this thread without recursing in the hook itself. */
	kcov_disable_thread(data);

	kcov_stksz_update_stack_size(th, data, caller, sp);
	kcov_ksancov_trace_pc(data, guardp, caller, sp);

	kcov_enable_thread(data);
}

/*
 * Coverage Sanitizer ABI implementation.
 */


void
__sanitizer_cov_trace_pc_indirect(void * __unused callee)
{
	/* No indirect call recording support at this moment. */
	return;
}


__attribute__((nodebug))
void
__sanitizer_cov_trace_pc(void)
{
	uintptr_t sp = (uintptr_t)&sp;
	trace_pc_guard(NULL, __builtin_return_address(0), sp);
}


__attribute__((nodebug))
void
__sanitizer_cov_trace_pc_guard(uint32_t __unused *guardp)
{
	uintptr_t sp = (uintptr_t)&sp;
	trace_pc_guard(guardp, __builtin_return_address(0), sp);
}


void
__sanitizer_cov_trace_pc_guard_init(uint32_t __unused *start, uint32_t __unused *stop)
{
	kcov_ksancov_trace_pc_guard_init(start, stop);
}


void
__sanitizer_cov_pcs_init(uintptr_t __unused *start, uintptr_t __unused *stop)
{
	kcov_ksancov_pcs_init(start, stop);
}
