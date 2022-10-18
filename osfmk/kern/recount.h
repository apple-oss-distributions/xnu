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

#ifndef KERN_RECOUNT_H
#define KERN_RECOUNT_H

#include <os/base.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/_types/_size_t.h>

__BEGIN_DECLS;

// Recount maintains counters for resources used by software, like CPU time and cycles.
// These counters are tracked at different levels of granularity depending on what execution bucket they're tracked in.
// For instance, while threads only differentiate on the broad CPU kinds due to memory constraints,
// the fewer number of tasks are free to use more memory and accumulate counters per-CPU.
//
// At context-switch, the scheduler calls `recount_context_switch` to update the counters.
// The difference between the current counter values and per-CPU snapshots are added to each thread.
// On modern systems with fast timebase reads, the counters are also updated on entering and exiting the kernel.

#pragma mark - config

// A level of the system's CPU topology, used as the precision when tracking
// counter values.
__enum_decl(recount_topo_t, unsigned int, {
	RCT_TOPO_SYSTEM,
	RCT_TOPO_CPU,
	RCT_TOPO_CPU_KIND,
	RCT_TOPO_COUNT,
});

// Get the number of elements in an array for per-topography data.
size_t recount_topo_count(recount_topo_t topo);

// Recount's definitions of CPU kinds, in lieu of one from the platform layers.
__enum_decl(recount_cpu_kind_t, unsigned int, {
	RCT_CPU_EFFICIENCY,
	RCT_CPU_PERFORMANCE,
	RCT_CPU_KIND_COUNT,
});

// A `recount_plan` structure controls the granularity of counting for a set of
// tracks and must be consulted when updating their counters.
typedef const struct recount_plan {
	const char *rpl_name;
	recount_topo_t rpl_topo;
} *recount_plan_t;

#define RECOUNT_PLAN_DECLARE(_name) \
    extern const struct recount_plan _name;

#define RECOUNT_PLAN_DEFINE(_name, _topo) \
	const struct recount_plan _name = { \
	        .rpl_name = #_name, \
	        .rpl_topo = _topo, \
	}

// The current objects with resource accounting policies.
RECOUNT_PLAN_DECLARE(recount_thread_plan);
RECOUNT_PLAN_DECLARE(recount_task_plan);
RECOUNT_PLAN_DECLARE(recount_task_terminated_plan);
RECOUNT_PLAN_DECLARE(recount_coalition_plan);
RECOUNT_PLAN_DECLARE(recount_processor_plan);

#pragma mark - generic accounting

// A track is where counter values can be updated atomically for readers by a
// single writer.
struct recount_track {
	uint32_t rt_sync;
	uint32_t rt_pad;

	// The CPU usage metrics currently supported by Recount.
	struct recount_usage {
		uint64_t ru_user_time_mach;
		uint64_t ru_system_time_mach;
#if CONFIG_PERVASIVE_CPI
		uint64_t ru_cycles;
		uint64_t ru_instructions;
#endif // CONFIG_PERVASIVE_CPI
#if CONFIG_PERVASIVE_ENERGY
		uint64_t ru_energy_nj;
#endif // CONFIG_PERVASIVE_ENERGY
	} rt_usage;
};

// Memory management routines for tracks and usage structures.
struct recount_track *recount_tracks_create(recount_plan_t plan);
void recount_tracks_destroy(recount_plan_t plan, struct recount_track *tracks);
struct recount_usage *recount_usage_alloc(recount_topo_t topo);
void recount_usage_free(recount_topo_t topo, struct recount_usage *usage);

// Attribute tracks to usage structures, to read their values for typical high-level interfaces.

// Sum any tracks to a single sum.
void recount_sum(recount_plan_t plan, const struct recount_track *tracks,
    struct recount_usage *sum);

// Summarize tracks into a total sum and another for a particular CPU kind.
void recount_sum_and_isolate_cpu_kind(recount_plan_t plan,
    struct recount_track *tracks, recount_cpu_kind_t kind,
    struct recount_usage *sum, struct recount_usage *only_kind);
// The same as above, but for usage-only objects, like coalitions.
void recount_sum_usage_and_isolate_cpu_kind(recount_plan_t plan,
    struct recount_usage *usage_list, recount_cpu_kind_t kind,
    struct recount_usage *sum, struct recount_usage *only_kind);

// Sum the counters for each perf-level, in the order returned by the sysctls.
void recount_sum_perf_levels(recount_plan_t plan,
    struct recount_track *tracks, struct recount_usage *sums);

#pragma mark - xnu internals

#if XNU_KERNEL_PRIVATE

struct thread;
struct task;
struct proc;

struct recount_times_mach {
	uint64_t rtm_user;
	uint64_t rtm_system;
};

// Access another thread's usage data.
void recount_thread_usage(struct thread *thread, struct recount_usage *usage);
void recount_thread_perf_level_usage(struct thread *thread,
    struct recount_usage *usage_levels);
uint64_t recount_thread_time_mach(struct thread *thread);
struct recount_times_mach recount_thread_times(struct thread *thread);

// Read the current thread's usage data, accumulating counts until now.
void recount_current_thread_usage(struct recount_usage *usage);
struct recount_times_mach recount_current_thread_times(void);
void recount_current_thread_usage_perf_only(struct recount_usage *usage,
    struct recount_usage *usage_perf_only);
void recount_current_thread_perf_level_usage(struct recount_usage
    *usage_levels);
uint64_t recount_current_thread_time_mach(void);
uint64_t recount_current_thread_user_time_mach(void);
uint64_t recount_current_thread_energy_nj(void);
void recount_current_task_usage(struct recount_usage *usage);
void recount_current_task_usage_perf_only(struct recount_usage *usage,
    struct recount_usage *usage_perf_only);

// Access another task's usage data.
void recount_task_usage(struct task *task, struct recount_usage *usage);
struct recount_times_mach recount_task_times(struct task *task);
void recount_task_usage_perf_only(struct task *task, struct recount_usage *sum,
    struct recount_usage *sum_perf_only);
void recount_task_times_perf_only(struct task *task,
    struct recount_times_mach *sum, struct recount_times_mach *sum_perf_only);
uint64_t recount_task_energy_nj(struct task *task);
bool recount_task_thread_perf_level_usage(struct task *task, uint64_t tid,
    struct recount_usage *usage_levels);

// Get the sum of all terminated threads in the task (not including active threads).
void recount_task_terminated_usage(struct task *task,
    struct recount_usage *sum);
struct recount_times_mach recount_task_terminated_times(struct task *task);
void recount_task_terminated_usage_perf_only(struct task *task,
    struct recount_usage *sum, struct recount_usage *perf_only);

int proc_pidthreadcounts(struct proc *p, uint64_t thuniqueid, user_addr_t uaddr,
    size_t usize, int *ret);

#endif // XNU_KERNEL_PRIVATE

#if MACH_KERNEL_PRIVATE

#include <kern/smp.h>
#include <mach/machine/thread_status.h>
#include <machine/machine_routines.h>

#if __arm64__
static_assert((RCT_CPU_EFFICIENCY > RCT_CPU_PERFORMANCE) ==
    (CLUSTER_TYPE_E > CLUSTER_TYPE_P));
#endif // __arm64__

#pragma mark threads

// The per-thread resource accounting structure.
struct recount_thread {
	// Resources consumed across the lifetime of the thread, according to
	// `recount_thread_plan`.
	struct recount_track *rth_lifetime;
};
void recount_thread_init(struct recount_thread *th);
void recount_thread_copy(struct recount_thread *dst,
    struct recount_thread *src);
void recount_thread_deinit(struct recount_thread *th);

#pragma mark tasks

// The per-task resource accounting structure.
struct recount_task {
	// Resources consumed across the lifetime of the task, including active
	// threads, according to `recount_task_plan`.
	//
	// The `recount_task_plan` must be per-CPU to provide mutual exclusion for
	// writers.
	struct recount_track *rtk_lifetime;
	// Usage from threads that have terminated or child tasks that have exited,
	// according to `recount_task_terminated_plan`.
	//
	// Protected by the task lock when threads terminate.
	struct recount_usage *rtk_terminated;
};
void recount_task_init(struct recount_task *tk);
// Called on tasks that are moving their accounting information to a
// synthetic or re-exec-ed task.
void recount_task_copy(struct recount_task *dst,
    const struct recount_task *src);
void recount_task_deinit(struct recount_task *tk);

#pragma mark coalitions

// The per-coalition resource accounting structure.
struct recount_coalition {
	// Resources consumed by exited tasks only, according to
	// `recount_coalition_plan`.
	//
	// Protected by the coalition lock when tasks exit and roll-up their
	// statistics.
	struct recount_usage *rco_exited;
};
void recount_coalition_init(struct recount_coalition *co);
void recount_coalition_deinit(struct recount_coalition *co);

// Get the sum of all currently-exited tasks in the coalition, and a separate P-only structure.
void recount_coalition_usage_perf_only(struct recount_coalition *coal,
    struct recount_usage *sum, struct recount_usage *sum_perf_only);

#pragma mark processors

struct processor;

// The per-processor resource accounting structure.
struct recount_processor {
	struct recount_track rpr_active;
	uint64_t rpr_idle_time_mach;
	_Atomic uint64_t rpr_state_last_abs_time;
#if __AMP__
	// Cache the RCT_TOPO_CPU_KIND offset, which cannot change.
	uint8_t rpr_cpu_kind_index;
#endif // __AMP__
};
void recount_processor_init(struct processor *processor);

// Get a snapshot of the processor's usage, along with an up-to-date snapshot
// of its idle time (to now if the processor is currently idle).
void recount_processor_usage(struct recount_processor *pr,
    struct recount_usage *usage, uint64_t *idle_time_mach);

#pragma mark updates

// The following interfaces are meant for specific adopters, like the
// scheduler or platform code responsible for entering and exiting the kernel.

// A snap records counter values at a specific point in time.
struct recount_snap {
	uint64_t rsn_time_mach;
#if CONFIG_PERVASIVE_CPI
	uint64_t rsn_insns;
	uint64_t rsn_cycles;
#endif // CONFIG_PERVASIVE_CPI
};

// Fill in a snap with the current values from time- and count-keeping hardware.
void recount_snapshot(struct recount_snap *snap);

// During user/kernel transitions, other serializing events provide enough
// serialization around reading the counter values.
void recount_snapshot_speculative(struct recount_snap *snap);

// Called by the scheduler when a context switch occurs.
void recount_switch_thread(struct recount_snap *snap, struct thread *off_thread,
    struct task *off_task);
// Called by the machine-dependent code to accumulate energy.
void recount_add_energy(struct thread *off_thread, struct task *off_task,
    uint64_t energy_nj);
// Log a kdebug event on switching threads.
void recount_log_switch_thread(const struct recount_snap *snap);

// Called by the startup threads on each CPU to initialize Recount.
void recount_update_snap(struct recount_snap *cur);

// This function requires that no writers race with it -- this is only safe in
// debugger context or while running in the context of the track being
// inspected.
void recount_sum_unsafe(recount_plan_t plan, const struct recount_track *tracks,
    struct recount_usage *sum);

// For handling precise user/kernel time updates.
void recount_leave_user(void);
void recount_enter_user(void);
#if __x86_64__
// Handle interrupt time-keeping on Intel, which aren't unified with the trap
// handlers, so whether the user or system timers are updated depends on the
// save-state.
void recount_enter_intel_interrupt(x86_saved_state_t *state);
void recount_leave_intel_interrupt(void);
#endif // __x86_64__

// Hooks for each processor idling and running.
void recount_processor_idle(struct recount_processor *pr,
    struct recount_snap *snap);
void recount_processor_run(struct recount_processor *pr,
    struct recount_snap *snap);

#pragma mark rollups

// Called by the thread termination queue with the task lock held.
void recount_task_rollup_thread(struct recount_task *tk,
    const struct recount_thread *th);

// Called by the coalition roll-up statistics functions with coalition lock
// held.
void recount_coalition_rollup_task(struct recount_coalition *co,
    struct recount_task *tk);

#endif // MACH_KERNEL_PRIVATE

__END_DECLS

#endif // KERN_RECOUNT_H
