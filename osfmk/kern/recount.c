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

#include <kern/assert.h>
#include <kern/kalloc.h>
#include <pexpert/pexpert.h>
#include <sys/kdebug.h>
#include <sys/_types/_size_t.h>
#include <kern/monotonic.h>
#include <kern/percpu.h>
#include <kern/processor.h>
#include <kern/recount.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/work_interval.h>
#include <mach/mach_time.h>
#include <mach/mach_types.h>
#include <machine/config.h>
#include <machine/machine_routines.h>
#include <os/atomic_private.h>
#include <stdbool.h>
#include <stdint.h>

// Recount's machine-independent implementation and interfaces for the kernel
// at-large.

#define PRECISE_USER_KERNEL_PMCS PRECISE_USER_KERNEL_TIME

// On non-release kernels, allow precise PMC (instructions, cycles) updates to
// be disabled for performance characterization.
#if PRECISE_USER_KERNEL_PMCS && (DEVELOPMENT || DEBUG)
#define PRECISE_USER_KERNEL_PMC_TUNABLE 1

TUNABLE(bool, no_precise_pmcs, "-no-precise-pmcs", false);
#endif // PRECISE_USER_KERNEL_PMCS

#if !PRECISE_USER_KERNEL_TIME
#define PRECISE_TIME_FATAL_FUNC OS_NORETURN
#define PRECISE_TIME_ONLY_FUNC OS_UNUSED
#else // !PRECISE_USER_KERNEL_TIME
#define PRECISE_TIME_FATAL_FUNC
#define PRECISE_TIME_ONLY_FUNC
#endif // PRECISE_USER_KERNEL_TIME

#if !PRECISE_USER_KERNEL_PMCS
#define PRECISE_PMCS_ONLY_FUNC OS_UNUSED
#else // !PRECISE_PMCS_ONLY_FUNC
#define PRECISE_PMCS_ONLY_FUNC
#endif // PRECISE_USER_KERNEL_PMCS

#if HAS_CPU_DPE_COUNTER
// Only certain platforms have DPE counters.
#define RECOUNT_ENERGY CONFIG_PERVASIVE_ENERGY
#else // HAS_CPU_DPE_COUNTER
#define RECOUNT_ENERGY 0
#endif // !HAS_CPU_DPE_COUNTER

// Topography helpers.
size_t recount_topo_count(recount_topo_t topo);
static bool recount_topo_matches_cpu_kind(recount_topo_t topo,
    recount_cpu_kind_t kind, size_t idx);
static size_t recount_topo_index(recount_topo_t topo, processor_t processor);
static size_t recount_convert_topo_index(recount_topo_t from, recount_topo_t to,
    size_t i);

// Prevent counter updates before the system is ready.
__security_const_late bool _recount_started = false;

// Lookup table that matches CPU numbers (indices) to their track index.
__security_const_late uint8_t _topo_cpu_kinds[MAX_CPUS] = { 0 };

// Allocation metadata and zones.

// Keep static strings for `zone_create`.
static const char *_usage_zone_names[RCT_TOPO_COUNT] = {
	[RCT_TOPO_CPU] = "recount_usage_cpu",
	[RCT_TOPO_CPU_KIND] = "recount_usage_cpu_kind",
};

static const char *_track_zone_names[RCT_TOPO_COUNT] = {
	[RCT_TOPO_CPU] = "recount_track_cpu",
	[RCT_TOPO_CPU_KIND] = "recount_track_cpu_kind",
};

static const bool _topo_allocates[RCT_TOPO_COUNT] = {
	[RCT_TOPO_SYSTEM] = false,
	[RCT_TOPO_CPU] = true,
	[RCT_TOPO_CPU_KIND] = true,
};

// Fixed-size zones for allocations.
__security_const_late zone_t _recount_usage_zones[RCT_TOPO_COUNT] = { };
__security_const_late zone_t _recount_track_zones[RCT_TOPO_COUNT] = { };

__startup_func
static void
recount_startup(void)
{
#if __AMP__
	unsigned int cpu_count = ml_get_cpu_count();
	const ml_topology_info_t *topo_info = ml_get_topology_info();
	for (unsigned int i = 0; i < cpu_count; i++) {
		cluster_type_t type = topo_info->cpus[i].cluster_type;
		uint8_t cluster_i = (type == CLUSTER_TYPE_P) ? RCT_CPU_PERFORMANCE :
		    RCT_CPU_EFFICIENCY;
		_topo_cpu_kinds[i] = cluster_i;
	}
#endif // __AMP__

	for (unsigned int i = 0; i < RCT_TOPO_COUNT; i++) {
		if (_topo_allocates[i]) {
			const char *usage_name = _usage_zone_names[i];
			assert(usage_name != NULL);
			_recount_usage_zones[i] = zone_create(usage_name,
			    sizeof(struct recount_usage) * recount_topo_count(i),
			    0);

			const char *track_name = _track_zone_names[i];
			assert(track_name != NULL);
			_recount_track_zones[i] = zone_create(track_name,
			    sizeof(struct recount_track) * recount_topo_count(i),
			    0);
		}
	}

	_recount_started = true;
}

STARTUP(PERCPU, STARTUP_RANK_LAST, recount_startup);

#pragma mark - tracks

RECOUNT_PLAN_DEFINE(recount_thread_plan, RCT_TOPO_CPU_KIND);
RECOUNT_PLAN_DEFINE(recount_work_interval_plan, RCT_TOPO_CPU);
RECOUNT_PLAN_DEFINE(recount_task_plan, RCT_TOPO_CPU);
RECOUNT_PLAN_DEFINE(recount_task_terminated_plan, RCT_TOPO_CPU_KIND);
RECOUNT_PLAN_DEFINE(recount_coalition_plan, RCT_TOPO_CPU_KIND);
RECOUNT_PLAN_DEFINE(recount_processor_plan, RCT_TOPO_SYSTEM);

OS_ALWAYS_INLINE
static inline uint64_t
recount_timestamp_speculative(void)
{
#if __arm__ || __arm64__
	return ml_get_speculative_timebase();
#else // __arm__ || __arm64__
	return mach_absolute_time();
#endif // !__arm__ && !__arm64__
}

OS_ALWAYS_INLINE
void
recount_snapshot_speculative(struct recount_snap *snap)
{
	snap->rsn_time_mach = recount_timestamp_speculative();
#if CONFIG_PERVASIVE_CPI
	mt_cur_cpu_cycles_instrs_speculative(&snap->rsn_cycles, &snap->rsn_insns);
#endif // CONFIG_PERVASIVE_CPI
}

void
recount_snapshot(struct recount_snap *snap)
{
#if __arm__ || __arm64__
	__builtin_arm_isb(ISB_SY);
#endif // __arm__ || __arm64__
	recount_snapshot_speculative(snap);
}

static struct recount_snap *
recount_get_snap(processor_t processor)
{
	return &processor->pr_recount.rpr_snap;
}

static struct recount_snap *
recount_get_interrupt_snap(processor_t processor)
{
	return &processor->pr_recount.rpr_interrupt_snap;
}

// A simple sequence lock implementation.

static void
_seqlock_shared_lock_slowpath(const uint32_t *lck, uint32_t gen)
{
	disable_preemption();
	do {
		gen = hw_wait_while_equals32((uint32_t *)(uintptr_t)lck, gen);
	} while (__improbable((gen & 1) != 0));
	os_atomic_thread_fence(acquire);
	enable_preemption();
}

static uintptr_t
_seqlock_shared_lock(const uint32_t *lck)
{
	uint32_t gen = os_atomic_load(lck, acquire);
	if (__improbable((gen & 1) != 0)) {
		_seqlock_shared_lock_slowpath(lck, gen);
	}
	return gen;
}

static bool
_seqlock_shared_try_unlock(const uint32_t *lck, uintptr_t on_enter)
{
	return os_atomic_load(lck, acquire) == on_enter;
}

static void
_seqlock_excl_lock_relaxed(uint32_t *lck)
{
	__assert_only uintptr_t new = os_atomic_inc(lck, relaxed);
	assert3u((new & 1), ==, 1);
}

static void
_seqlock_excl_commit(void)
{
	os_atomic_thread_fence(release);
}

static void
_seqlock_excl_unlock_relaxed(uint32_t *lck)
{
	__assert_only uint32_t new = os_atomic_inc(lck, relaxed);
	assert3u((new & 1), ==, 0);
}

static struct recount_track *
recount_update_start(struct recount_track *tracks, recount_topo_t topo,
    processor_t processor)
{
	struct recount_track *track = &tracks[recount_topo_index(topo, processor)];
	_seqlock_excl_lock_relaxed(&track->rt_sync);
	return track;
}

#if RECOUNT_ENERGY

static struct recount_track *
recount_update_single_start(struct recount_track *tracks, recount_topo_t topo,
    processor_t processor)
{
	return &tracks[recount_topo_index(topo, processor)];
}

#endif // RECOUNT_ENERGY

static void
recount_update_commit(void)
{
	_seqlock_excl_commit();
}

static void
recount_update_end(struct recount_track *track)
{
	_seqlock_excl_unlock_relaxed(&track->rt_sync);
}

static const struct recount_usage *
recount_read_start(const struct recount_track *track, uintptr_t *on_enter)
{
	const struct recount_usage *stats = &track->rt_usage;
	*on_enter = _seqlock_shared_lock(&track->rt_sync);
	return stats;
}

static bool
recount_try_read_end(const struct recount_track *track, uintptr_t on_enter)
{
	return _seqlock_shared_try_unlock(&track->rt_sync, on_enter);
}

static void
recount_read_track(struct recount_usage *stats,
    const struct recount_track *track)
{
	uintptr_t on_enter = 0;
	do {
		const struct recount_usage *vol_stats =
		    recount_read_start(track, &on_enter);
		*stats = *vol_stats;
	} while (!recount_try_read_end(track, on_enter));
}

static void
recount_metrics_add(struct recount_metrics *sum, const struct recount_metrics *to_add)
{
	sum->rm_time_mach += to_add->rm_time_mach;
#if CONFIG_PERVASIVE_CPI
	sum->rm_instructions += to_add->rm_instructions;
	sum->rm_cycles += to_add->rm_cycles;
#endif // CONFIG_PERVASIVE_CPI
}

static void
recount_usage_add(struct recount_usage *sum, const struct recount_usage *to_add)
{
	for (unsigned int i = 0; i < RCT_LVL_COUNT; i++) {
		recount_metrics_add(&sum->ru_metrics[i], &to_add->ru_metrics[i]);
	}
#if CONFIG_PERVASIVE_ENERGY
	sum->ru_energy_nj += to_add->ru_energy_nj;
#endif // CONFIG_PERVASIVE_CPI
}

OS_ALWAYS_INLINE
static inline void
recount_usage_add_snap(struct recount_usage *usage, recount_level_t level,
    struct recount_snap *snap)
{
	struct recount_metrics *metrics = &usage->ru_metrics[level];

	metrics->rm_time_mach += snap->rsn_time_mach;
#if CONFIG_PERVASIVE_CPI
	metrics->rm_cycles += snap->rsn_cycles;
	metrics->rm_instructions += snap->rsn_insns;
#else // CONFIG_PERVASIVE_CPI
#pragma unused(usage)
#endif // !CONFIG_PERVASIVE_CPI
}

static void
recount_rollup(recount_plan_t plan, const struct recount_track *tracks,
    recount_topo_t to_topo, struct recount_usage *stats)
{
	recount_topo_t from_topo = plan->rpl_topo;
	size_t topo_count = recount_topo_count(from_topo);
	struct recount_usage tmp = { 0 };
	for (size_t i = 0; i < topo_count; i++) {
		recount_read_track(&tmp, &tracks[i]);
		size_t to_i = recount_convert_topo_index(from_topo, to_topo, i);
		recount_usage_add(&stats[to_i], &tmp);
	}
}

// This function must be run when counters cannot increment for the track, like from the current thread.
static void
recount_rollup_unsafe(recount_plan_t plan, struct recount_track *tracks,
    recount_topo_t to_topo, struct recount_usage *stats)
{
	recount_topo_t from_topo = plan->rpl_topo;
	size_t topo_count = recount_topo_count(from_topo);
	for (size_t i = 0; i < topo_count; i++) {
		size_t to_i = recount_convert_topo_index(from_topo, to_topo, i);
		recount_usage_add(&stats[to_i], &tracks[i].rt_usage);
	}
}

void
recount_sum(recount_plan_t plan, const struct recount_track *tracks,
    struct recount_usage *sum)
{
	recount_rollup(plan, tracks, RCT_TOPO_SYSTEM, sum);
}

void
recount_sum_unsafe(recount_plan_t plan, const struct recount_track *tracks,
    struct recount_usage *sum)
{
	recount_topo_t topo = plan->rpl_topo;
	size_t topo_count = recount_topo_count(topo);
	for (size_t i = 0; i < topo_count; i++) {
		recount_usage_add(sum, &tracks[i].rt_usage);
	}
}

void
recount_sum_and_isolate_cpu_kind(recount_plan_t plan,
    struct recount_track *tracks, recount_cpu_kind_t kind,
    struct recount_usage *sum, struct recount_usage *only_kind)
{
	size_t topo_count = recount_topo_count(plan->rpl_topo);
	struct recount_usage tmp = { 0 };
	for (size_t i = 0; i < topo_count; i++) {
		recount_read_track(&tmp, &tracks[i]);
		recount_usage_add(sum, &tmp);
		if (recount_topo_matches_cpu_kind(plan->rpl_topo, kind, i)) {
			recount_usage_add(only_kind, &tmp);
		}
	}
}

static void
recount_sum_usage(recount_plan_t plan, const struct recount_usage *usages,
    struct recount_usage *sum)
{
	const size_t topo_count = recount_topo_count(plan->rpl_topo);
	for (size_t i = 0; i < topo_count; i++) {
		recount_usage_add(sum, &usages[i]);
	}
}

void
recount_sum_usage_and_isolate_cpu_kind(recount_plan_t plan,
    struct recount_usage *usage, recount_cpu_kind_t kind,
    struct recount_usage *sum, struct recount_usage *only_kind)
{
	const size_t topo_count = recount_topo_count(plan->rpl_topo);
	for (size_t i = 0; i < topo_count; i++) {
		recount_usage_add(sum, &usage[i]);
		if (only_kind && recount_topo_matches_cpu_kind(plan->rpl_topo, kind, i)) {
			recount_usage_add(only_kind, &usage[i]);
		}
	}
}

void
recount_sum_perf_levels(recount_plan_t plan, struct recount_track *tracks,
    struct recount_usage *sums)
{
	recount_rollup(plan, tracks, RCT_TOPO_CPU_KIND, sums);
}

struct recount_times_mach
recount_usage_times_mach(struct recount_usage *usage)
{
	return (struct recount_times_mach){
		       .rtm_user = usage->ru_metrics[RCT_LVL_USER].rm_time_mach,
		       .rtm_system = recount_usage_system_time_mach(usage),
	};
}

uint64_t
recount_usage_system_time_mach(struct recount_usage *usage)
{
	uint64_t system_time = usage->ru_metrics[RCT_LVL_KERNEL].rm_time_mach;
#if RECOUNT_SECURE_METRICS
	system_time += usage->ru_metrics[RCT_LVL_SECURE].rm_time_mach;
#endif // RECOUNT_SECURE_METRICS
	return system_time;
}

uint64_t
recount_usage_time_mach(struct recount_usage *usage)
{
	uint64_t time = 0;
	for (unsigned int i = 0; i < RCT_LVL_COUNT; i++) {
		time += usage->ru_metrics[i].rm_time_mach;
	}
	return time;
}

uint64_t
recount_usage_cycles(struct recount_usage *usage)
{
	uint64_t cycles = 0;
#if CONFIG_CPU_COUNTERS
	for (unsigned int i = 0; i < RCT_LVL_COUNT; i++) {
		cycles += usage->ru_metrics[i].rm_cycles;
	}
#else // CONFIG_CPU_COUNTERS
#pragma unused(usage)
#endif // !CONFIG_CPU_COUNTERS
	return cycles;
}

uint64_t
recount_usage_instructions(struct recount_usage *usage)
{
	uint64_t instructions = 0;
#if CONFIG_CPU_COUNTERS
	for (unsigned int i = 0; i < RCT_LVL_COUNT; i++) {
		instructions += usage->ru_metrics[i].rm_instructions;
	}
#else // CONFIG_CPU_COUNTERS
#pragma unused(usage)
#endif // !CONFIG_CPU_COUNTERS
	return instructions;
}

// Plan-specific helpers.

void
recount_coalition_rollup_task(struct recount_coalition *co,
    struct recount_task *tk)
{
	recount_rollup(&recount_task_plan, tk->rtk_lifetime,
	    recount_coalition_plan.rpl_topo, co->rco_exited);
}

void
recount_task_rollup_thread(struct recount_task *tk,
    const struct recount_thread *th)
{
	recount_rollup(&recount_thread_plan, th->rth_lifetime,
	    recount_task_terminated_plan.rpl_topo, tk->rtk_terminated);
}

#pragma mark - scheduler

// `result = lhs - rhs` for snapshots.
OS_ALWAYS_INLINE
static void
recount_snap_diff(struct recount_snap *result,
    const struct recount_snap *lhs, const struct recount_snap *rhs)
{
	assert3u(lhs->rsn_time_mach, >=, rhs->rsn_time_mach);
	result->rsn_time_mach = lhs->rsn_time_mach - rhs->rsn_time_mach;
#if CONFIG_PERVASIVE_CPI
	assert3u(lhs->rsn_insns, >=, rhs->rsn_insns);
	assert3u(lhs->rsn_cycles, >=, rhs->rsn_cycles);
	result->rsn_cycles = lhs->rsn_cycles - rhs->rsn_cycles;
	result->rsn_insns = lhs->rsn_insns - rhs->rsn_insns;
#endif // CONFIG_PERVASIVE_CPI
}

static void
_fix_time_precision(struct recount_usage *usage)
{
#if PRECISE_USER_KERNEL_TIME
#pragma unused(usage)
#else // PRECISE_USER_KERNEL_TIME
	// Attribute all time to user, as the system is only acting "on behalf
	// of" user processes -- a bit sketchy.
	usage->ru_metrics[RCT_LVL_USER].rm_time_mach +=
	    recount_usage_system_time_mach(usage);
	usage->ru_metrics[RCT_LVL_KERNEL].rm_time_mach = 0;
#endif // !PRECISE_USER_KERNEL_TIME
}

void
recount_current_thread_usage(struct recount_usage *usage)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	thread_t thread = current_thread();
	struct recount_snap snap = { 0 };
	recount_snapshot(&snap);
	recount_sum_unsafe(&recount_thread_plan, thread->th_recount.rth_lifetime,
	    usage);
	struct recount_snap *last = recount_get_snap(current_processor());
	struct recount_snap diff = { 0 };
	recount_snap_diff(&diff, &snap, last);
	recount_usage_add_snap(usage, RCT_LVL_KERNEL, &diff);
	_fix_time_precision(usage);
}

void
recount_current_thread_usage_perf_only(struct recount_usage *usage,
    struct recount_usage *usage_perf_only)
{
	struct recount_usage usage_perf_levels[RCT_CPU_KIND_COUNT] = { 0 };
	recount_current_thread_perf_level_usage(usage_perf_levels);
	recount_sum_usage(&recount_thread_plan, usage_perf_levels, usage);
	*usage_perf_only = usage_perf_levels[RCT_CPU_PERFORMANCE];
	_fix_time_precision(usage);
	_fix_time_precision(usage_perf_only);
}

void
recount_thread_perf_level_usage(struct thread *thread,
    struct recount_usage *usage_levels)
{
	recount_rollup(&recount_thread_plan, thread->th_recount.rth_lifetime,
	    RCT_TOPO_CPU_KIND, usage_levels);
	size_t topo_count = recount_topo_count(RCT_TOPO_CPU_KIND);
	for (size_t i = 0; i < topo_count; i++) {
		_fix_time_precision(&usage_levels[i]);
	}
}

void
recount_current_thread_perf_level_usage(struct recount_usage *usage_levels)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	processor_t processor = current_processor();
	thread_t thread = current_thread();
	struct recount_snap snap = { 0 };
	recount_snapshot(&snap);
	recount_rollup_unsafe(&recount_thread_plan, thread->th_recount.rth_lifetime,
	    RCT_TOPO_CPU_KIND, usage_levels);
	struct recount_snap *last = recount_get_snap(processor);
	struct recount_snap diff = { 0 };
	recount_snap_diff(&diff, &snap, last);
	size_t cur_i = recount_topo_index(RCT_TOPO_CPU_KIND, processor);
	struct recount_usage *cur_usage = &usage_levels[cur_i];
	recount_usage_add_snap(cur_usage, RCT_LVL_KERNEL, &diff);
	size_t topo_count = recount_topo_count(RCT_TOPO_CPU_KIND);
	for (size_t i = 0; i < topo_count; i++) {
		_fix_time_precision(&usage_levels[i]);
	}
}

uint64_t
recount_current_thread_energy_nj(void)
{
#if RECOUNT_ENERGY
	assert(ml_get_interrupts_enabled() == FALSE);
	thread_t thread = current_thread();
	size_t topo_count = recount_topo_count(recount_thread_plan.rpl_topo);
	uint64_t energy_nj = 0;
	for (size_t i = 0; i < topo_count; i++) {
		energy_nj += thread->th_recount.rth_lifetime[i].rt_usage.ru_energy_nj;
	}
	return energy_nj;
#else // RECOUNT_ENERGY
	return 0;
#endif // !RECOUNT_ENERGY
}

static void
_times_add_usage(struct recount_times_mach *times, struct recount_usage *usage)
{
	times->rtm_user += usage->ru_metrics[RCT_LVL_USER].rm_time_mach;
#if PRECISE_USER_KERNEL_TIME
	times->rtm_system += recount_usage_system_time_mach(usage);
#else // PRECISE_USER_KERNEL_TIME
	times->rtm_user += recount_usage_system_time_mach(usage);
#endif // !PRECISE_USER_KERNEL_TIME
}

struct recount_times_mach
recount_thread_times(struct thread *thread)
{
	size_t topo_count = recount_topo_count(recount_thread_plan.rpl_topo);
	struct recount_times_mach times = { 0 };
	for (size_t i = 0; i < topo_count; i++) {
		_times_add_usage(&times, &thread->th_recount.rth_lifetime[i].rt_usage);
	}
	return times;
}

uint64_t
recount_thread_time_mach(struct thread *thread)
{
	struct recount_times_mach times = recount_thread_times(thread);
	return times.rtm_user + times.rtm_system;
}

static uint64_t
_time_since_last_snapshot(void)
{
	struct recount_snap *last = recount_get_snap(current_processor());
	uint64_t cur_time = mach_absolute_time();
	return cur_time - last->rsn_time_mach;
}

uint64_t
recount_current_thread_time_mach(void)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	uint64_t previous_time = recount_thread_time_mach(current_thread());
	return previous_time + _time_since_last_snapshot();
}

struct recount_times_mach
recount_current_thread_times(void)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	struct recount_times_mach times = recount_thread_times(
		current_thread());
#if PRECISE_USER_KERNEL_TIME
	// This code is executing in the kernel, so the time since the last snapshot
	// (with precise user/kernel time) is since entering the kernel.
	times.rtm_system += _time_since_last_snapshot();
#else // PRECISE_USER_KERNEL_TIME
	times.rtm_user += _time_since_last_snapshot();
#endif // !PRECISE_USER_KERNEL_TIME
	return times;
}

void
recount_thread_usage(thread_t thread, struct recount_usage *usage)
{
	recount_sum(&recount_thread_plan, thread->th_recount.rth_lifetime, usage);
	_fix_time_precision(usage);
}

uint64_t
recount_current_thread_interrupt_time_mach(void)
{
	thread_t thread = current_thread();
	return thread->th_recount.rth_interrupt_time_mach;
}

void
recount_work_interval_usage(struct work_interval *work_interval, struct recount_usage *usage)
{
	recount_sum(&recount_work_interval_plan, work_interval_get_recount_tracks(work_interval), usage);
	_fix_time_precision(usage);
}

struct recount_times_mach
recount_work_interval_times(struct work_interval *work_interval)
{
	size_t topo_count = recount_topo_count(recount_work_interval_plan.rpl_topo);
	struct recount_times_mach times = { 0 };
	for (size_t i = 0; i < topo_count; i++) {
		_times_add_usage(&times, &work_interval_get_recount_tracks(work_interval)[i].rt_usage);
	}
	return times;
}

uint64_t
recount_work_interval_energy_nj(struct work_interval *work_interval)
{
#if RECOUNT_ENERGY
	size_t topo_count = recount_topo_count(recount_work_interval_plan.rpl_topo);
	uint64_t energy = 0;
	for (size_t i = 0; i < topo_count; i++) {
		energy += work_interval_get_recount_tracks(work_interval)[i].rt_usage.ru_energy_nj;
	}
	return energy;
#else // RECOUNT_ENERGY
#pragma unused(work_interval)
	return 0;
#endif // !RECOUNT_ENERGY
}

void
recount_current_task_usage(struct recount_usage *usage)
{
	task_t task = current_task();
	struct recount_track *tracks = task->tk_recount.rtk_lifetime;
	recount_sum(&recount_task_plan, tracks, usage);
	_fix_time_precision(usage);
}

void
recount_current_task_usage_perf_only(struct recount_usage *usage,
    struct recount_usage *usage_perf_only)
{
	task_t task = current_task();
	struct recount_track *tracks = task->tk_recount.rtk_lifetime;
	recount_sum_and_isolate_cpu_kind(&recount_task_plan,
	    tracks, RCT_CPU_PERFORMANCE, usage, usage_perf_only);
	_fix_time_precision(usage);
	_fix_time_precision(usage_perf_only);
}

void
recount_task_times_perf_only(struct task *task,
    struct recount_times_mach *sum, struct recount_times_mach *sum_perf_only)
{
	const recount_topo_t topo = recount_task_plan.rpl_topo;
	const size_t topo_count = recount_topo_count(topo);
	struct recount_track *tracks = task->tk_recount.rtk_lifetime;
	for (size_t i = 0; i < topo_count; i++) {
		struct recount_usage *usage = &tracks[i].rt_usage;
		_times_add_usage(sum, usage);
		if (recount_topo_matches_cpu_kind(topo, RCT_CPU_PERFORMANCE, i)) {
			_times_add_usage(sum_perf_only, usage);
		}
	}
}

void
recount_task_terminated_usage(task_t task, struct recount_usage *usage)
{
	recount_sum_usage(&recount_task_terminated_plan,
	    task->tk_recount.rtk_terminated, usage);
	_fix_time_precision(usage);
}

struct recount_times_mach
recount_task_terminated_times(struct task *task)
{
	size_t topo_count = recount_topo_count(recount_task_terminated_plan.rpl_topo);
	struct recount_times_mach times = { 0 };
	for (size_t i = 0; i < topo_count; i++) {
		_times_add_usage(&times, &task->tk_recount.rtk_terminated[i]);
	}
	return times;
}

void
recount_task_terminated_usage_perf_only(task_t task,
    struct recount_usage *usage, struct recount_usage *perf_only)
{
	recount_sum_usage_and_isolate_cpu_kind(&recount_task_terminated_plan,
	    task->tk_recount.rtk_terminated, RCT_CPU_PERFORMANCE, usage, perf_only);
	_fix_time_precision(usage);
	_fix_time_precision(perf_only);
}

void
recount_task_usage_perf_only(task_t task, struct recount_usage *sum,
    struct recount_usage *sum_perf_only)
{
	recount_sum_and_isolate_cpu_kind(&recount_task_plan,
	    task->tk_recount.rtk_lifetime, RCT_CPU_PERFORMANCE, sum, sum_perf_only);
	_fix_time_precision(sum);
	_fix_time_precision(sum_perf_only);
}

void
recount_task_usage(task_t task, struct recount_usage *usage)
{
	recount_sum(&recount_task_plan, task->tk_recount.rtk_lifetime, usage);
	_fix_time_precision(usage);
}

struct recount_times_mach
recount_task_times(struct task *task)
{
	size_t topo_count = recount_topo_count(recount_task_plan.rpl_topo);
	struct recount_times_mach times = { 0 };
	for (size_t i = 0; i < topo_count; i++) {
		_times_add_usage(&times, &task->tk_recount.rtk_lifetime[i].rt_usage);
	}
	return times;
}

uint64_t
recount_task_energy_nj(struct task *task)
{
#if RECOUNT_ENERGY
	size_t topo_count = recount_topo_count(recount_task_plan.rpl_topo);
	uint64_t energy = 0;
	for (size_t i = 0; i < topo_count; i++) {
		energy += task->tk_recount.rtk_lifetime[i].rt_usage.ru_energy_nj;
	}
	return energy;
#else // RECOUNT_ENERGY
#pragma unused(task)
	return 0;
#endif // !RECOUNT_ENERGY
}

void
recount_coalition_usage_perf_only(struct recount_coalition *coal,
    struct recount_usage *sum, struct recount_usage *sum_perf_only)
{
	recount_sum_usage_and_isolate_cpu_kind(&recount_coalition_plan,
	    coal->rco_exited, RCT_CPU_PERFORMANCE, sum, sum_perf_only);
	_fix_time_precision(sum);
	_fix_time_precision(sum_perf_only);
}

OS_ALWAYS_INLINE
static void
recount_absorb_snap(struct recount_snap *to_add, thread_t thread, task_t task,
    processor_t processor, recount_level_t level)
{
	// Idle threads do not attribute their usage back to the task or processor,
	// as the time is not spent "running."
	//
	// The processor-level metrics include idle time, instead, as the idle time
	// needs to be read as up-to-date from `recount_processor_usage`.

	const bool was_idle = (thread->options & TH_OPT_IDLE_THREAD) != 0;

	struct recount_track *wi_tracks_array = NULL;
	if (!was_idle) {
		wi_tracks_array = work_interval_get_recount_tracks(
			thread->th_work_interval);
	}
	bool absorb_work_interval = wi_tracks_array != NULL;

	struct recount_track *th_track = recount_update_start(
		thread->th_recount.rth_lifetime, recount_thread_plan.rpl_topo,
		processor);
	struct recount_track *wi_track = NULL;
	if (absorb_work_interval) {
		wi_track = recount_update_start(wi_tracks_array,
		    recount_work_interval_plan.rpl_topo, processor);
	}
	struct recount_track *tk_track = was_idle ? NULL : recount_update_start(
		task->tk_recount.rtk_lifetime, recount_task_plan.rpl_topo, processor);
	struct recount_track *pr_track = was_idle ? NULL : recount_update_start(
		&processor->pr_recount.rpr_active, recount_processor_plan.rpl_topo,
		processor);
	recount_update_commit();

	recount_usage_add_snap(&th_track->rt_usage, level, to_add);
	if (!was_idle) {
		if (absorb_work_interval) {
			recount_usage_add_snap(&wi_track->rt_usage, level, to_add);
		}
		recount_usage_add_snap(&tk_track->rt_usage, level, to_add);
		recount_usage_add_snap(&pr_track->rt_usage, level, to_add);
	}

	recount_update_commit();
	recount_update_end(th_track);
	if (!was_idle) {
		if (absorb_work_interval) {
			recount_update_end(wi_track);
		}
		recount_update_end(tk_track);
		recount_update_end(pr_track);
	}
}

void
recount_switch_thread(struct recount_snap *cur, struct thread *off_thread,
    struct task *off_task)
{
	assert(ml_get_interrupts_enabled() == FALSE);

	if (__improbable(!_recount_started)) {
		return;
	}

	processor_t processor = current_processor();

	struct recount_snap *last = recount_get_snap(processor);
	struct recount_snap diff = { 0 };
	recount_snap_diff(&diff, cur, last);
	recount_absorb_snap(&diff, off_thread, off_task, processor,
#if RECOUNT_THREAD_BASED_LEVEL
	    off_thread->th_recount.rth_current_level
#else // RECOUNT_THREAD_BASED_LEVEL
	    RCT_LVL_KERNEL
#endif // !RECOUNT_THREAD_BASED_LEVEL
	    );
	memcpy(last, cur, sizeof(*last));
}

void
recount_add_energy(struct thread *off_thread, struct task *off_task,
    uint64_t energy_nj)
{
#if RECOUNT_ENERGY
	assert(ml_get_interrupts_enabled() == FALSE);
	if (__improbable(!_recount_started)) {
		return;
	}

	bool was_idle = (off_thread->options & TH_OPT_IDLE_THREAD) != 0;
	struct recount_track *wi_tracks_array = work_interval_get_recount_tracks(off_thread->th_work_interval);
	bool collect_work_interval_telemetry = wi_tracks_array != NULL;
	processor_t processor = current_processor();

	struct recount_track *th_track = recount_update_single_start(
		off_thread->th_recount.rth_lifetime, recount_thread_plan.rpl_topo,
		processor);
	struct recount_track *wi_track = (was_idle || !collect_work_interval_telemetry) ? NULL :
	    recount_update_single_start(wi_tracks_array,
	    recount_work_interval_plan.rpl_topo, processor);
	struct recount_track *tk_track = was_idle ? NULL :
	    recount_update_single_start(off_task->tk_recount.rtk_lifetime,
	    recount_task_plan.rpl_topo, processor);
	struct recount_track *pr_track = was_idle ? NULL :
	    recount_update_single_start(&processor->pr_recount.rpr_active,
	    recount_processor_plan.rpl_topo, processor);

	th_track->rt_usage.ru_energy_nj += energy_nj;
	if (!was_idle) {
		if (collect_work_interval_telemetry) {
			wi_track->rt_usage.ru_energy_nj += energy_nj;
		}
		tk_track->rt_usage.ru_energy_nj += energy_nj;
		pr_track->rt_usage.ru_energy_nj += energy_nj;
	}
#else // RECOUNT_ENERGY
#pragma unused(off_thread, off_task, energy_nj)
#endif // !RECOUNT_ENERGY
}

#define MT_KDBG_IC_CPU_CSWITCH \
	KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_INSTRS_CYCLES, 1)

#define MT_KDBG_IC_CPU_CSWITCH_ON \
    KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_INSTRS_CYCLES_ON_CPU, 1)

void
recount_log_switch_thread(const struct recount_snap *snap)
{
#if CONFIG_PERVASIVE_CPI
	if (kdebug_debugid_explicitly_enabled(MT_KDBG_IC_CPU_CSWITCH)) {
		// In Monotonic's event hierarchy for backwards-compatibility.
		KDBG_RELEASE(MT_KDBG_IC_CPU_CSWITCH, snap->rsn_insns, snap->rsn_cycles);
	}
#else // CONFIG_PERVASIVE_CPI
#pragma unused(snap)
#endif // CONFIG_PERVASIVE_CPI
}

void
recount_log_switch_thread_on(const struct recount_snap *snap)
{
#if CONFIG_PERVASIVE_CPI
	if (kdebug_debugid_explicitly_enabled(MT_KDBG_IC_CPU_CSWITCH_ON)) {
		if (!snap) {
			snap = recount_get_snap(current_processor());
		}
		// In Monotonic's event hierarchy for backwards-compatibility.
		KDBG_RELEASE(MT_KDBG_IC_CPU_CSWITCH_ON, snap->rsn_insns, snap->rsn_cycles);
	}
#else // CONFIG_PERVASIVE_CPI
#pragma unused(snap)
#endif // CONFIG_PERVASIVE_CPI
}

OS_ALWAYS_INLINE
PRECISE_TIME_ONLY_FUNC
static void
recount_precise_transition_diff(struct recount_snap *diff,
    struct recount_snap *last, struct recount_snap *cur)
{
#if PRECISE_USER_KERNEL_PMCS
#if PRECISE_USER_KERNEL_PMC_TUNABLE
	// The full `recount_snapshot_speculative` shouldn't get PMCs with a tunable
	// in this configuration.
	if (__improbable(no_precise_pmcs)) {
		cur->rsn_time_mach = recount_timestamp_speculative();
		diff->rsn_time_mach = cur->rsn_time_mach - last->rsn_time_mach;
	} else
#endif // PRECISE_USER_KERNEL_PMC_TUNABLE
	{
		recount_snapshot_speculative(cur);
		recount_snap_diff(diff, cur, last);
	}
#else // PRECISE_USER_KERNEL_PMCS
	cur->rsn_time_mach = recount_timestamp_speculative();
	diff->rsn_time_mach = cur->rsn_time_mach - last->rsn_time_mach;
#endif // !PRECISE_USER_KERNEL_PMCS
}

#if MACH_ASSERT && RECOUNT_THREAD_BASED_LEVEL

PRECISE_TIME_ONLY_FUNC
static void
recount_assert_level(thread_t thread, recount_level_t old)
{
	assert3u(thread->th_recount.rth_current_level, ==, old);
}

#else // MACH_ASSERT && RECOUNT_THREAD_BASED_LEVEL

PRECISE_TIME_ONLY_FUNC
static void
recount_assert_level(thread_t __unused thread,
    recount_level_t __unused old)
{
}

#endif // !(MACH_ASSERT && RECOUNT_THREAD_BASED_LEVEL)

/// Called when entering or exiting the kernel to maintain system vs. user counts, extremely performance sensitive.
///
/// Must be called with interrupts disabled.
///
/// - Parameter from: What level is being switched from.
/// - Parameter to: What level is being switched to.
///
/// - Returns: The value of Mach time that was sampled inside this function.
PRECISE_TIME_FATAL_FUNC
static uint64_t
recount_transition(recount_level_t from, recount_level_t to)
{
#if PRECISE_USER_KERNEL_TIME
	// Omit interrupts-disabled assertion for performance reasons.
	processor_t processor = current_processor();
	thread_t thread = processor->active_thread;
	if (thread) {
		task_t task = get_thread_ro_unchecked(thread)->tro_task;

		recount_assert_level(thread, from);
#if RECOUNT_THREAD_BASED_LEVEL
		thread->th_recount.rth_current_level = to;
#else // RECOUNT_THREAD_BASED_LEVEL
#pragma unused(to)
#endif // !RECOUNT_THREAD_BASED_LEVEL
		struct recount_snap *last = recount_get_snap(processor);
		struct recount_snap diff = { 0 };
		struct recount_snap cur = { 0 };
		recount_precise_transition_diff(&diff, last, &cur);
		recount_absorb_snap(&diff, thread, task, processor, from);
		memcpy(last, &cur, sizeof(*last));

		return cur.rsn_time_mach;
	} else {
		return 0;
	}
#else // PRECISE_USER_KERNEL_TIME
#pragma unused(from, to)
	panic("recount: kernel transition called with precise time off");
#endif // !PRECISE_USER_KERNEL_TIME
}

PRECISE_TIME_FATAL_FUNC
void
recount_leave_user(void)
{
	recount_transition(RCT_LVL_USER, RCT_LVL_KERNEL);
}

PRECISE_TIME_FATAL_FUNC
void
recount_enter_user(void)
{
	recount_transition(RCT_LVL_KERNEL, RCT_LVL_USER);
}

void
recount_enter_interrupt(void)
{
	processor_t processor = current_processor();
	struct recount_snap *last = recount_get_interrupt_snap(processor);
	recount_snapshot_speculative(last);
}

void
recount_leave_interrupt(void)
{
	processor_t processor = current_processor();
	thread_t thread = processor->active_thread;
	struct recount_snap *last = recount_get_snap(processor);
	uint64_t last_time = last->rsn_time_mach;
	recount_snapshot_speculative(last);
	processor->pr_recount.rpr_interrupt_time_mach +=
	    last->rsn_time_mach - last_time;
	thread->th_recount.rth_interrupt_time_mach +=
	    last->rsn_time_mach - last_time;
}

#if __x86_64__

void
recount_enter_intel_interrupt(x86_saved_state_t *state)
{
	// The low bits of `%cs` being set indicate interrupt was delivered while
	// executing in user space.
	bool from_user = (is_saved_state64(state) ? state->ss_64.isf.cs :
	    state->ss_32.cs) & 0x03;
	uint64_t timestamp = recount_transition(
		from_user ? RCT_LVL_USER : RCT_LVL_KERNEL, RCT_LVL_KERNEL);
	current_cpu_datap()->cpu_int_event_time = timestamp;
}

void
recount_leave_intel_interrupt(void)
{
	recount_transition(RCT_LVL_KERNEL, RCT_LVL_KERNEL);
	current_cpu_datap()->cpu_int_event_time = 0;
}

#endif // __x86_64__

#if RECOUNT_SECURE_METRICS

PRECISE_TIME_FATAL_FUNC
void
recount_leave_secure(void)
{
	boolean_t intrs_en = ml_set_interrupts_enabled(FALSE);
	recount_transition(RCT_LVL_SECURE, RCT_LVL_KERNEL);
	ml_set_interrupts_enabled(intrs_en);
}

PRECISE_TIME_FATAL_FUNC
void
recount_enter_secure(void)
{
	boolean_t intrs_en = ml_set_interrupts_enabled(FALSE);
	recount_transition(RCT_LVL_KERNEL, RCT_LVL_SECURE);
	ml_set_interrupts_enabled(intrs_en);
}

#endif // RECOUNT_SECURE_METRICS

// Set on rpr_state_last_abs_time when the processor is idle.
#define RCT_PR_IDLING (0x1ULL << 63)

void
recount_processor_idle(struct recount_processor *pr, struct recount_snap *snap)
{
	__assert_only uint64_t state_time = os_atomic_load_wide(
		&pr->rpr_state_last_abs_time, relaxed);
	assert((state_time & RCT_PR_IDLING) == 0);
	assert((snap->rsn_time_mach & RCT_PR_IDLING) == 0);
	uint64_t new_state_stamp = RCT_PR_IDLING | snap->rsn_time_mach;
	os_atomic_store_wide(&pr->rpr_state_last_abs_time, new_state_stamp,
	    relaxed);
}

OS_PURE OS_ALWAYS_INLINE
static inline uint64_t
_state_time(uint64_t state_stamp)
{
	return state_stamp & ~(RCT_PR_IDLING);
}

void
recount_processor_init(processor_t processor)
{
#if __AMP__
	processor->pr_recount.rpr_cpu_kind_index =
	    processor->processor_set->pset_cluster_type == PSET_AMP_P ?
	    RCT_CPU_PERFORMANCE : RCT_CPU_EFFICIENCY;
#else // __AMP__
#pragma unused(processor)
#endif // !__AMP__
}

void
recount_processor_run(struct recount_processor *pr, struct recount_snap *snap)
{
	uint64_t state = os_atomic_load_wide(&pr->rpr_state_last_abs_time, relaxed);
	assert(state == 0 || (state & RCT_PR_IDLING) == RCT_PR_IDLING);
	assert((snap->rsn_time_mach & RCT_PR_IDLING) == 0);
	uint64_t new_state_stamp = snap->rsn_time_mach;
	pr->rpr_idle_time_mach += snap->rsn_time_mach - _state_time(state);
	os_atomic_store_wide(&pr->rpr_state_last_abs_time, new_state_stamp,
	    relaxed);
}

void
recount_processor_online(processor_t processor, struct recount_snap *cur)
{
	recount_processor_run(&processor->pr_recount, cur);
	struct recount_snap *pr_snap = recount_get_snap(processor);
	memcpy(pr_snap, cur, sizeof(*pr_snap));
}

void
recount_processor_usage(struct recount_processor *pr,
    struct recount_usage *usage, uint64_t *idle_time_out)
{
	recount_sum(&recount_processor_plan, &pr->rpr_active, usage);
	_fix_time_precision(usage);

	uint64_t idle_time = pr->rpr_idle_time_mach;
	uint64_t idle_stamp = os_atomic_load_wide(&pr->rpr_state_last_abs_time,
	    relaxed);
	bool idle = (idle_stamp & RCT_PR_IDLING) == RCT_PR_IDLING;
	if (idle) {
		// Since processors can idle for some time without an update, make sure
		// the idle time is up-to-date with respect to the caller.
		idle_time += mach_absolute_time() - _state_time(idle_stamp);
	}
	*idle_time_out = idle_time;
}

uint64_t
recount_current_processor_interrupt_time_mach(void)
{
	assert(!preemption_enabled());
	return current_processor()->pr_recount.rpr_interrupt_time_mach;
}

bool
recount_task_thread_perf_level_usage(struct task *task, uint64_t tid,
    struct recount_usage *usage_levels)
{
	thread_t thread = task_findtid(task, tid);
	if (thread != THREAD_NULL) {
		if (thread == current_thread()) {
			boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
			recount_current_thread_perf_level_usage(usage_levels);
			ml_set_interrupts_enabled(interrupt_state);
		} else {
			recount_thread_perf_level_usage(thread, usage_levels);
		}
	}
	return thread != THREAD_NULL;
}

#pragma mark - utilities

// For rolling up counts, convert an index from one topography to another.
static size_t
recount_convert_topo_index(recount_topo_t from, recount_topo_t to, size_t i)
{
	if (from == to) {
		return i;
	} else if (to == RCT_TOPO_SYSTEM) {
		return 0;
	} else if (from == RCT_TOPO_CPU) {
		assertf(to == RCT_TOPO_CPU_KIND,
		    "recount: cannot convert from CPU topography to %d", to);
		return _topo_cpu_kinds[i];
	} else {
		panic("recount: unexpected rollup request from %d to %d", from, to);
	}
}

// Get the track index of the provided processor and topography.
OS_ALWAYS_INLINE
static size_t
recount_topo_index(recount_topo_t topo, processor_t processor)
{
	switch (topo) {
	case RCT_TOPO_SYSTEM:
		return 0;
	case RCT_TOPO_CPU:
		return processor->cpu_id;
	case RCT_TOPO_CPU_KIND:
#if __AMP__
		return processor->pr_recount.rpr_cpu_kind_index;
#else // __AMP__
		return 0;
#endif // !__AMP__
	default:
		panic("recount: invalid topology %u to index", topo);
	}
}

// Return the number of tracks needed for a given topography.
size_t
recount_topo_count(recount_topo_t topo)
{
	// Allow the compiler to reason about at least the system and CPU kind
	// counts.
	switch (topo) {
	case RCT_TOPO_SYSTEM:
		return 1;

	case RCT_TOPO_CPU_KIND:
#if __AMP__
		return 2;
#else // __AMP__
		return 1;
#endif // !__AMP__

	case RCT_TOPO_CPU:
#if __arm__ || __arm64__
		return ml_get_cpu_count();
#else // __arm__ || __arm64__
		return ml_early_cpu_max_number() + 1;
#endif // !__arm__ && !__arm64__

	default:
		panic("recount: invalid topography %d", topo);
	}
}

static bool
recount_topo_matches_cpu_kind(recount_topo_t topo, recount_cpu_kind_t kind,
    size_t idx)
{
#if !__AMP__
#pragma unused(kind, idx)
#endif // !__AMP__
	switch (topo) {
	case RCT_TOPO_SYSTEM:
		return true;

	case RCT_TOPO_CPU_KIND:
#if __AMP__
		return kind == idx;
#else // __AMP__
		return false;
#endif // !__AMP__

	case RCT_TOPO_CPU: {
#if __AMP__
		return _topo_cpu_kinds[idx] == kind;
#else // __AMP__
		return false;
#endif // !__AMP__
	}

	default:
		panic("recount: unexpected topography %d", topo);
	}
}

struct recount_track *
recount_tracks_create(recount_plan_t plan)
{
	assert(_topo_allocates[plan->rpl_topo]);
	return zalloc_flags(_recount_track_zones[plan->rpl_topo],
	           Z_VM_TAG(Z_WAITOK | Z_ZERO | Z_NOFAIL, VM_KERN_MEMORY_RECOUNT));
}

static void
recount_tracks_copy(recount_plan_t plan, struct recount_track *dst,
    struct recount_track *src)
{
	size_t topo_count = recount_topo_count(plan->rpl_topo);
	for (size_t i = 0; i < topo_count; i++) {
		recount_read_track(&dst[i].rt_usage, &src[i]);
	}
}

void
recount_tracks_destroy(recount_plan_t plan, struct recount_track *tracks)
{
	assert(_topo_allocates[plan->rpl_topo]);
	zfree(_recount_track_zones[plan->rpl_topo], tracks);
}

void
recount_thread_init(struct recount_thread *th)
{
	th->rth_lifetime = recount_tracks_create(&recount_thread_plan);
}

void
recount_thread_copy(struct recount_thread *dst, struct recount_thread *src)
{
	recount_tracks_copy(&recount_thread_plan, dst->rth_lifetime,
	    src->rth_lifetime);
}

void
recount_task_copy(struct recount_task *dst, const struct recount_task *src)
{
	recount_tracks_copy(&recount_task_plan, dst->rtk_lifetime,
	    src->rtk_lifetime);
}

void
recount_thread_deinit(struct recount_thread *th)
{
	recount_tracks_destroy(&recount_thread_plan, th->rth_lifetime);
}

void
recount_task_init(struct recount_task *tk)
{
	tk->rtk_lifetime = recount_tracks_create(&recount_task_plan);
	tk->rtk_terminated = recount_usage_alloc(
		recount_task_terminated_plan.rpl_topo);
}

void
recount_task_deinit(struct recount_task *tk)
{
	recount_tracks_destroy(&recount_task_plan, tk->rtk_lifetime);
	recount_usage_free(recount_task_terminated_plan.rpl_topo,
	    tk->rtk_terminated);
}

void
recount_coalition_init(struct recount_coalition *co)
{
	co->rco_exited = recount_usage_alloc(recount_coalition_plan.rpl_topo);
}

void
recount_coalition_deinit(struct recount_coalition *co)
{
	recount_usage_free(recount_coalition_plan.rpl_topo, co->rco_exited);
}

void
recount_work_interval_init(struct recount_work_interval *wi)
{
	wi->rwi_current_instance = recount_tracks_create(&recount_work_interval_plan);
}

void
recount_work_interval_deinit(struct recount_work_interval *wi)
{
	recount_tracks_destroy(&recount_work_interval_plan, wi->rwi_current_instance);
}

struct recount_usage *
recount_usage_alloc(recount_topo_t topo)
{
	assert(_topo_allocates[topo]);
	return zalloc_flags(_recount_usage_zones[topo],
	           Z_VM_TAG(Z_WAITOK | Z_ZERO | Z_NOFAIL, VM_KERN_MEMORY_RECOUNT));
}

void
recount_usage_free(recount_topo_t topo, struct recount_usage *usage)
{
	assert(_topo_allocates[topo]);
	zfree(_recount_usage_zones[topo], usage);
}
