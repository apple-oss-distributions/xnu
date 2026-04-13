/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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


#include <pexpert/pexpert.h>
#include <machine/smp.h>

#include <sys/sysctl.h>

#include <kern/sched_hygiene.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>

#if DEVELOPMENT || DEBUG

extern int32_t sysctl_get_bound_cpuid(void);
extern kern_return_t sysctl_thread_bind_cpuid(int32_t cpuid);
static int
sysctl_kern_sched_thread_bind_cpu SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	/*
	 * DO NOT remove this bootarg guard or make this non-development.
	 * This kind of binding should only be used for tests and
	 * experiments in a custom configuration, never shipping code.
	 */

	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	int32_t cpuid = sysctl_get_bound_cpuid();

	int32_t new_value;
	int changed;
	int error = sysctl_io_number(req, cpuid, sizeof(cpuid), &new_value, &changed);
	if (error) {
		return error;
	}

	if (changed) {
		kern_return_t kr = sysctl_thread_bind_cpuid(new_value);

		if (kr == KERN_NOT_SUPPORTED) {
			return ENOTSUP;
		}

		if (kr == KERN_INVALID_VALUE) {
			return ERANGE;
		}
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cpu, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cpu, "I", "");

#if __AMP__

errno_t mach_to_bsd_errno(kern_return_t mach_err);

extern char sysctl_get_bound_pset_type(void);
static int
sysctl_kern_sched_thread_bind_pset_type SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char pset_type = buff[0];

	if (!req->newptr) {
		goto out;
	}

	kern_return_t kr = thread_soft_bind_pset_type(current_thread(), pset_type);
	if (kr != KERN_SUCCESS) {
		return mach_to_bsd_errno(kr);
	}

out:
	buff[0] = sysctl_get_bound_pset_type();

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_pset_type,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_pset_type, "A", "");
SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cluster_type, /* alias for sched_thread_bind_pset_type */
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_pset_type, "A", "");

extern char sysctl_get_task_pset_type(void);
extern kern_return_t sysctl_task_set_pset_type(char pset_type_char);
static int
sysctl_kern_sched_task_set_pset_type SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	if (!PE_parse_boot_argn("enable_skstsct", NULL, 0)) {
		return ENOENT;
	}

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char pset_type = buff[0];

	if (!req->newptr) {
		goto out;
	}

	kern_return_t kr = sysctl_task_set_pset_type(pset_type);
	if (kr != KERN_SUCCESS) {
		return mach_to_bsd_errno(kr);
	}

out:
	pset_type = sysctl_get_task_pset_type();
	buff[0] = pset_type;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_pset_type,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_task_set_pset_type, "A", "");
SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_cluster_type, /* alias for sched_task_set_pset_type */
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_task_set_pset_type, "A", "");

extern pset_id_t thread_bound_pset_id(thread_t);
static int
sysctl_kern_sched_thread_bind_pset_id SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	thread_t self = current_thread();
	int32_t old_value = thread_bound_pset_id(self);
	int32_t new_value;
	int changed;
	int error = sysctl_io_number(req, old_value, sizeof(old_value), &new_value, &changed);
	if (error) {
		return error;
	}

	if (changed) {
		/*
		 * Note, this binds the thread to the pset without passing the
		 * THREAD_BIND_ELIGIBLE_ONLY option, which means we won't check
		 * whether the thread is otherwise eligible to run on that pset--
		 * we will send it there regardless.
		 */
		pset_id_t new_pset_id;
		if (new_value == (int32_t)-1) { /* bincompat for clients who pass -1 as "unbind" */
			new_pset_id = THREAD_BOUND_PSET_NONE;
		} else {
			new_pset_id = (pset_id_t)new_value;
		}

		kern_return_t kr = thread_soft_bind_pset_id(self, new_pset_id, 0);
		if (kr == KERN_INVALID_VALUE) {
			return ERANGE;
		}

		if (kr != KERN_SUCCESS) {
			return EINVAL;
		}
	}

	return error;
}
SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_pset_id,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_pset_id, "I", "");

extern unsigned int pset_cluster_id(processor_set_t);
extern processor_set_t pset_for_id_checked(pset_id_t);
extern kern_return_t thread_soft_bind_cluster_id(thread_t thread, uint32_t cluster_id, thread_bind_option_t options);

/*
 * Binding to a cluster by ID will find the first processor in the cluster and
 * bind to its pset.
 */
static int
sysctl_kern_sched_thread_bind_cluster_id SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	thread_t self = current_thread();
	pset_id_t pset_id = thread_bound_pset_id(self);
	int32_t old_value = (pset_id == PSET_ID_INVALID)
	    ? THREAD_BOUND_CLUSTER_NONE
	    : pset_cluster_id(pset_for_id_checked(pset_id));
	int32_t new_value;
	int changed;
	int error = sysctl_io_number(req, old_value, sizeof(old_value), &new_value, &changed);
	if (error) {
		return error;
	}

	if (changed) {
		/*
		 * Note, this binds the thread to the pset without passing the
		 * THREAD_BIND_ELIGIBLE_ONLY option, which means we won't check
		 * whether the thread is otherwise eligible to run on that pset--
		 * we will send it there regardless.
		 */
		kern_return_t kr = thread_soft_bind_cluster_id(self, new_value, 0);
		if (kr == KERN_INVALID_VALUE) {
			return ERANGE;
		}

		if (kr != KERN_SUCCESS) {
			return EINVAL;
		}
	}

	return 0;
}
SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cluster_id,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cluster_id, "I", "");

#if CONFIG_SCHED_EDGE

extern int sched_edge_migrate_ipi_immediate;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_migrate_ipi_immediate, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_migrate_ipi_immediate, 0, "Edge Scheduler uses immediate IPIs for migration event based on execution latency");

#endif /* CONFIG_SCHED_EDGE */

#endif /* __AMP__ */

extern int timeouts_are_fatal;
EXPERIMENT_FACTOR_INT(timeouts_are_fatal, &timeouts_are_fatal, 0, 1,
    "Do timeouts panic or emit telemetry (0: telemetry, 1: panic)");

#if SCHED_HYGIENE_DEBUG

SYSCTL_QUAD(_kern, OID_AUTO, interrupt_masked_threshold_mt, CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_LEGACY_EXPERIMENT,
    &interrupt_masked_timeout,
    "Interrupt masked duration after which a tracepoint is emitted or the device panics (in mach timebase units)");

SYSCTL_INT(_kern, OID_AUTO, interrupt_masked_debug_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &interrupt_masked_debug_mode, 0,
    "Enable interrupt masked tracing or panic (0: off, 1: trace, 2: panic)");

SYSCTL_QUAD(_kern, OID_AUTO, sched_preemption_disable_threshold_mt, CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_LEGACY_EXPERIMENT,
    &sched_preemption_disable_threshold_mt,
    "Preemption disablement duration after which a tracepoint is emitted or the device panics (in mach timebase units)");

SYSCTL_INT(_kern, OID_AUTO, sched_preemption_disable_debug_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sched_preemption_disable_debug_mode, 0,
    "Enable preemption disablement tracing or panic (0: off, 1: trace, 2: panic)");

static int
sysctl_sched_preemption_disable_stats(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	extern unsigned int preemption_disable_get_max_durations(uint64_t *durations, size_t count);
	extern void preemption_disable_reset_max_durations(void);

	uint64_t stats[MAX_CPUS]; // maximum per CPU

	unsigned int ncpus = preemption_disable_get_max_durations(stats, MAX_CPUS);
	if (req->newlen > 0) {
		/* Reset when attempting to write to the sysctl. */
		preemption_disable_reset_max_durations();
	}

	return sysctl_io_opaque(req, stats, ncpus * sizeof(uint64_t), NULL);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_preemption_disable_stats,
    CTLTYPE_OPAQUE | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_sched_preemption_disable_stats, "I", "Preemption disablement statistics");

#endif /* SCHED_HYGIENE_DEBUG */

extern void sysctl_task_set_no_smt(char no_smt);
extern char sysctl_task_get_no_smt(void);

static int
sysctl_kern_sched_task_set_no_smt SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char no_smt = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_task_set_no_smt(no_smt);
out:
	no_smt = sysctl_task_get_no_smt();
	buff[0] = no_smt;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_no_smt, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_sched_task_set_no_smt, "A", "");

#if CONFIG_SCHED_SMT
static int
sysctl_kern_sched_thread_set_no_smt(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int old_value = thread_get_no_smt() ? 1 : 0;
	int error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (changed) {
		thread_set_no_smt(!!new_value);
	}

	return error;
}
#else /* CONFIG_SCHED_SMT */
static int
sysctl_kern_sched_thread_set_no_smt(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, __unused struct sysctl_req *req)
{
	return 0;
}
#endif /* CONFIG_SCHED_SMT*/

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_set_no_smt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_sched_thread_set_no_smt, "I", "");

#if CONFIG_SCHED_RT_ALLOW

#if DEVELOPMENT || DEBUG
#define RT_ALLOW_CTLFLAGS CTLFLAG_RW
#else /* DEVELOPMENT || DEBUG */
#define RT_ALLOW_CTLFLAGS CTLFLAG_RD
#endif /* DEVELOPMENT || DEBUG */

static int
sysctl_kern_rt_allow_limit_percent(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	extern uint8_t rt_allow_limit_percent;

	int new_value = 0;
	int old_value = rt_allow_limit_percent;
	int changed = 0;

	int error = sysctl_io_number(req, old_value, sizeof(old_value),
	    &new_value, &changed);
	if (error != 0) {
		return error;
	}

	/* Only accept a percentage between 1 and 99 inclusive. */
	if (changed) {
		if (new_value >= 100 || new_value <= 0) {
			return EINVAL;
		}

		rt_allow_limit_percent = (uint8_t)new_value;
	}

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, rt_allow_limit_percent,
    RT_ALLOW_CTLFLAGS | CTLTYPE_INT | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_rt_allow_limit_percent, "I", "");

static int
sysctl_kern_rt_allow_limit_interval_ms(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	extern uint16_t rt_allow_limit_interval_ms;

	uint64_t new_value = 0;
	uint64_t old_value = rt_allow_limit_interval_ms;
	int changed = 0;

	int error = sysctl_io_number(req, old_value, sizeof(old_value),
	    &new_value, &changed);
	if (error != 0) {
		return error;
	}

	/* Value is in ns. Must be at least 1ms. */
	if (changed) {
		if (new_value < 1 || new_value > UINT16_MAX) {
			return EINVAL;
		}

		rt_allow_limit_interval_ms = (uint16_t)new_value;
	}

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, rt_allow_limit_interval_ms,
    RT_ALLOW_CTLFLAGS | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_rt_allow_limit_interval_ms, "Q", "");

#endif /* CONFIG_SCHED_RT_ALLOW */


#endif /* DEVELOPMENT || DEBUG */
