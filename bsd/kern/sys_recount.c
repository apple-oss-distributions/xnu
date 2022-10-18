// Copyright (c) 2021 Apple Inc.  All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#include <kern/recount.h>
#include <machine/machine_routines.h>
#include <machine/smp.h>
#include <sys/proc_info.h>
#include <sys/resource_private.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>

// Recount's BSD-specific implementation for syscalls.

#if CONFIG_PERVASIVE_CPI

static struct thsc_cpi
_usage_to_cpi(struct recount_usage *usage)
{
	return (struct thsc_cpi){
		       .tcpi_instructions = usage->ru_instructions,
		       .tcpi_cycles = usage->ru_cycles,
	};
}

static struct thsc_time_cpi
_usage_to_time_cpi(struct recount_usage *usage)
{
	return (struct thsc_time_cpi){
		       .ttci_instructions = usage->ru_instructions,
		       .ttci_cycles = usage->ru_cycles,
		       .ttci_system_time_mach = usage->ru_system_time_mach,
		       .ttci_user_time_mach = usage->ru_user_time_mach,
	};
}

static struct thsc_time_energy_cpi
_usage_to_time_energy_cpi(struct recount_usage *usage)
{
	return (struct thsc_time_energy_cpi){
		       .ttec_instructions = usage->ru_instructions,
		       .ttec_cycles = usage->ru_cycles,
		       .ttec_system_time_mach = usage->ru_system_time_mach,
		       .ttec_user_time_mach = usage->ru_user_time_mach,
#if CONFIG_PERVASIVE_ENERGY
		       .ttec_energy_nj = usage->ru_energy_nj,
#endif // CONFIG_PERVASIVE_ENERGY
	};
}

static int
_selfcounts(thread_selfcounts_kind_t kind, user_addr_t buf, size_t size)
{
	struct recount_usage usage = { 0 };
	boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
	recount_current_thread_usage(&usage);
	ml_set_interrupts_enabled(interrupt_state);

	switch (kind) {
	case THSC_CPI: {
		struct thsc_cpi counts = _usage_to_cpi(&usage);
		return copyout(&counts, buf, MIN(sizeof(counts), size));
	}
	case THSC_TIME_CPI: {
		struct thsc_time_cpi counts = _usage_to_time_cpi(&usage);
		return copyout(&counts, buf, MIN(sizeof(counts), size));
	}
	case THSC_TIME_ENERGY_CPI: {
		struct thsc_time_energy_cpi counts = _usage_to_time_energy_cpi(&usage);
		return copyout(&counts, buf, MIN(sizeof(counts), size));
	}
	default:
		panic("recount: unexpected thread_selfcounts kind: %d", kind);
	}
}

static int
_selfcounts_perf_level(thread_selfcounts_kind_t kind, user_addr_t buf,
    size_t size)
{
	struct recount_usage usages[RCT_CPU_KIND_COUNT] = { 0 };
	boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
	recount_current_thread_perf_level_usage(usages);
	ml_set_interrupts_enabled(interrupt_state);

	switch (kind) {
	case THSC_CPI_PER_PERF_LEVEL: {
		struct thsc_cpi counts[RCT_CPU_KIND_COUNT] = { 0 };
		for (size_t i = 0; i < RCT_CPU_KIND_COUNT; i++) {
			counts[i] = _usage_to_cpi(&usages[i]);
		}
		return copyout(&counts, buf, MIN(sizeof(counts), size));
	}
	case THSC_TIME_CPI_PER_PERF_LEVEL: {
		struct thsc_time_cpi counts[RCT_CPU_KIND_COUNT] = { 0 };
		for (size_t i = 0; i < RCT_CPU_KIND_COUNT; i++) {
			counts[i] = _usage_to_time_cpi(&usages[i]);
		}
		return copyout(&counts, buf, MIN(sizeof(counts), size));
	}
	case THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL: {
		struct thsc_time_energy_cpi counts[RCT_CPU_KIND_COUNT] = { 0 };
		for (size_t i = 0; i < RCT_CPU_KIND_COUNT; i++) {
			counts[i] = _usage_to_time_energy_cpi(&usages[i]);
		}
		return copyout(&counts, buf, MIN(sizeof(counts), size));
	}
	default:
		panic("recount: unexpected thread_selfcounts kind: %d", kind);
	}
}

int
thread_selfcounts(__unused struct proc *p,
    struct thread_selfcounts_args *uap, __unused int *ret_out)
{
	switch (uap->kind) {
	case THSC_CPI:
	case THSC_TIME_CPI:
	case THSC_TIME_ENERGY_CPI:
		return _selfcounts(uap->kind, uap->buf, uap->size);

	case THSC_CPI_PER_PERF_LEVEL:
	case THSC_TIME_CPI_PER_PERF_LEVEL:
	case THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL:
		return _selfcounts_perf_level(uap->kind, uap->buf, uap->size);

	default:
		return ENOTSUP;
	}
}

static struct proc_threadcounts_data
_usage_to_proc_threadcounts(struct recount_usage *usage)
{
	return (struct proc_threadcounts_data){
		       .ptcd_instructions = usage->ru_instructions,
		       .ptcd_cycles = usage->ru_cycles,
		       .ptcd_system_time_mach = usage->ru_system_time_mach,
		       .ptcd_user_time_mach = usage->ru_user_time_mach,
#if CONFIG_PERVASIVE_ENERGY
		       .ptcd_energy_nj = usage->ru_energy_nj,
#endif // CONFIG_PERVASIVE_ENERGY
	};
}

static recount_cpu_kind_t
_perflevel_index_to_cpu_kind(unsigned int perflevel)
{
#if __AMP__
	extern cluster_type_t cpu_type_for_perflevel(int perflevel);
	cluster_type_t cluster = cpu_type_for_perflevel(perflevel);
#else // __AMP__
	cluster_type_t cluster = CLUSTER_TYPE_SMP;
#endif // !__AMP__

	switch (cluster) {
	case CLUSTER_TYPE_SMP:
		// Default to first index for SMP.
		return (recount_cpu_kind_t)0;
#if __AMP__
	case CLUSTER_TYPE_E:
		return RCT_CPU_EFFICIENCY;
	case CLUSTER_TYPE_P:
		return RCT_CPU_PERFORMANCE;
#endif // __AMP__
	default:
		panic("recount: unexpected CPU type %d for perflevel %d", cluster,
		    perflevel);
	}
}

int
proc_pidthreadcounts(
	struct proc *p,
	uint64_t tid,
	user_addr_t uaddr,
	size_t usize,
	int *size_out)
{
	struct recount_usage usages[RCT_CPU_KIND_COUNT] = { 0 };
	// Keep this in sync with proc_threadcounts_data -- this one just has the
	// array length hard-coded to the maximum.
	struct {
		uint16_t counts_len;
		uint16_t reserved0;
		uint32_t reserved1;
		struct proc_threadcounts_data counts[RCT_CPU_KIND_COUNT];
	} counts = { 0 };

	task_t task = proc_task(p);
	if (task == TASK_NULL) {
		return ESRCH;
	}

	bool found = recount_task_thread_perf_level_usage(task, tid, usages);
	if (!found) {
		return ESRCH;
	}

	const size_t counts_len = MIN(recount_topo_count(RCT_TOPO_CPU_KIND),
	    RCT_CPU_KIND_COUNT);
	counts.counts_len = (uint16_t)counts_len;

	for (unsigned int i = 0; i < counts_len; i++) {
		const recount_cpu_kind_t cpu_kind = _perflevel_index_to_cpu_kind(i);
		counts.counts[i] = _usage_to_proc_threadcounts(&usages[cpu_kind]);
	}
	size_t copyout_size = MIN(sizeof(uint64_t) +
	    counts_len * sizeof(struct proc_threadcounts_data), usize);
	assert(copyout_size <= sizeof(counts));
	int error = copyout(&counts, uaddr, copyout_size);
	if (error == 0) {
		*size_out = (int)copyout_size;
	}
	return error;
}

#else // CONFIG_PERVASIVE_CPI

int
proc_pidthreadcounts(
	__unused struct proc *p,
	__unused uint64_t tid,
	__unused user_addr_t uaddr,
	__unused size_t usize,
	__unused int *ret_out)
{
	return ENOTSUP;
}

int
thread_selfcounts(__unused struct proc *p,
    __unused struct thread_selfcounts_args *uap, __unused int *ret_out)
{
	return ENOTSUP;
}

#endif // !CONFIG_PERVASIVE_CPI
