/*
 * Copyright (c) 2006-2018 Apple Inc. All rights reserved.
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
 *
 */

#include <kern/sched_prim.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <kern/policy_internal.h>
#include <kern/thread_call.h>
#include <kern/thread_group.h>

#include <libkern/libkern.h>
#include <mach/coalition.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/host_priv.h>
#include <mach/mach_host.h>
#include <os/log.h>
#include <pexpert/pexpert.h>
#include <sys/coalition.h>
#include <sys/kern_event.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/reason.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/priv.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <mach/machine/sdt.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <libkern/section_keywords.h>
#include <stdatomic.h>

#include <IOKit/IOBSD.h>

#if CONFIG_FREEZE
#include <vm/vm_map.h>
#endif /* CONFIG_FREEZE */

#include <sys/kern_memorystatus.h>
#include <sys/kern_memorystatus_freeze.h>
#include <sys/kern_memorystatus_notify.h>

#if CONFIG_JETSAM

extern unsigned int memorystatus_available_pages;
extern unsigned int memorystatus_available_pages_pressure;
extern unsigned int memorystatus_available_pages_critical;
extern unsigned int memorystatus_available_pages_critical_base;
extern unsigned int memorystatus_available_pages_critical_idle_offset;

#else /* CONFIG_JETSAM */

extern uint64_t memorystatus_available_pages;
extern uint64_t memorystatus_available_pages_pressure;
extern uint64_t memorystatus_available_pages_critical;

#endif /* CONFIG_JETSAM */

unsigned int memorystatus_frozen_count = 0;
unsigned int memorystatus_frozen_count_webcontent = 0;
unsigned int memorystatus_frozen_count_xpc_service = 0;
unsigned int memorystatus_suspended_count = 0;
unsigned long freeze_threshold_percentage = 50;

#if CONFIG_FREEZE

static LCK_GRP_DECLARE(freezer_lck_grp, "freezer");
static LCK_MTX_DECLARE(freezer_mutex, &freezer_lck_grp);

/* Thresholds */
unsigned int memorystatus_freeze_threshold = 0;
unsigned int memorystatus_freeze_pages_min = 0;
unsigned int memorystatus_freeze_pages_max = 0;
unsigned int memorystatus_freeze_suspended_threshold = FREEZE_SUSPENDED_THRESHOLD_DEFAULT;
unsigned int memorystatus_freeze_daily_mb_max = FREEZE_DAILY_MB_MAX_DEFAULT;
uint64_t     memorystatus_freeze_budget_pages_remaining = 0; /* Remaining # of pages that can be frozen to disk */
uint64_t     memorystatus_freeze_budget_multiplier = 100; /* Multiplies the daily budget by 100/multiplier */
boolean_t memorystatus_freeze_degradation = FALSE; /* Protected by the freezer mutex. Signals we are in a degraded freeze mode. */
unsigned int memorystatus_freeze_max_candidate_band = FREEZE_MAX_CANDIDATE_BAND;

unsigned int memorystatus_max_frozen_demotions_daily = 0;
unsigned int memorystatus_thaw_count_demotion_threshold = 0;

boolean_t memorystatus_freeze_enabled = FALSE;
int memorystatus_freeze_wakeup = 0;
int memorystatus_freeze_jetsam_band = 0; /* the jetsam band which will contain P_MEMSTAT_FROZEN processes */

#define MAX_XPC_SERVICE_PIDS 10 /* Max. # of XPC services per coalition we'll consider freezing. */

#ifdef XNU_KERNEL_PRIVATE

unsigned int memorystatus_frozen_processes_max = 0;
unsigned int memorystatus_frozen_shared_mb = 0;
unsigned int memorystatus_frozen_shared_mb_max = 0;
unsigned int memorystatus_freeze_shared_mb_per_process_max = 0; /* Max. MB allowed per process to be freezer-eligible. */
unsigned int memorystatus_freeze_private_shared_pages_ratio = 2; /* Ratio of private:shared pages for a process to be freezer-eligible. */
unsigned int memorystatus_thaw_count = 0; /* # of thaws in the current freezer interval */
uint64_t memorystatus_thaw_count_since_boot = 0; /* The number of thaws since boot */
unsigned int memorystatus_refreeze_eligible_count = 0; /* # of processes currently thawed i.e. have state on disk & in-memory */

struct memorystatus_freezer_stats_t memorystatus_freezer_stats = {0};

#endif /* XNU_KERNEL_PRIVATE */

static inline boolean_t memorystatus_can_freeze_processes(void);
static boolean_t memorystatus_can_freeze(boolean_t *memorystatus_freeze_swap_low);
static boolean_t memorystatus_is_process_eligible_for_freeze(proc_t p);
static void memorystatus_freeze_thread(void *param __unused, wait_result_t wr __unused);
static uint32_t memorystatus_freeze_calculate_new_budget(
	unsigned int time_since_last_interval_expired_sec,
	unsigned int burst_multiple,
	unsigned int interval_duration_min,
	uint32_t rollover);
static void memorystatus_freeze_start_normal_throttle_interval(uint32_t new_budget, mach_timespec_t start_ts);

static void memorystatus_set_freeze_is_enabled(bool enabled);
static void memorystatus_disable_freeze(void);
static bool kill_all_frozen_processes(uint64_t max_band, bool suspended_only, os_reason_t jetsam_reason, uint64_t *memory_reclaimed_out);

/* Stats */
static uint64_t memorystatus_freeze_pageouts = 0;

/* Throttling */
#define DEGRADED_WINDOW_MINS    (30)
#define NORMAL_WINDOW_MINS      (24 * 60)

/* Protected by the freezer_mutex */
static throttle_interval_t throttle_intervals[] = {
	{ DEGRADED_WINDOW_MINS, 1, 0, 0, { 0, 0 }},
	{ NORMAL_WINDOW_MINS, 1, 0, 0, { 0, 0 }},
};
throttle_interval_t *degraded_throttle_window = &throttle_intervals[0];
throttle_interval_t *normal_throttle_window = &throttle_intervals[1];
uint32_t memorystatus_freeze_current_interval = 0;
static thread_call_t freeze_interval_reset_thread_call;
static uint32_t memorystatus_freeze_calculate_new_budget(
	unsigned int time_since_last_interval_expired_sec,
	unsigned int burst_multiple,
	unsigned int interval_duration_min,
	uint32_t rollover);

/* An ordered list of freeze or demotion candidates */
struct memorystatus_freezer_candidate_list {
	memorystatus_properties_freeze_entry_v1 *mfcl_list;
	size_t mfcl_length;
};
struct memorystatus_freezer_candidate_list memorystatus_global_freeze_list = {NULL, 0};
struct memorystatus_freezer_candidate_list memorystatus_global_demote_list = {NULL, 0};
/*
 * When enabled, freeze candidates are chosen from the memorystatus_global_freeze_list
 * in order (as opposed to using the older LRU approach).
 */
int memorystatus_freezer_use_ordered_list = 0;
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freezer_use_ordered_list, &memorystatus_freezer_use_ordered_list, 0, 1, "");
/*
 * When enabled, demotion candidates are chosen from memorystatus_global_demotion_list
 */
int memorystatus_freezer_use_demotion_list = 0;
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freezer_use_demotion_list, &memorystatus_freezer_use_demotion_list, 0, 1, "");

extern uint64_t vm_swap_get_free_space(void);
extern boolean_t vm_swap_max_budget(uint64_t *);
extern int i_coal_jetsam_get_taskrole(coalition_t coal, task_t task);

static void memorystatus_freeze_update_throttle(uint64_t *budget_pages_allowed);
static void memorystatus_demote_frozen_processes(bool urgent_mode);

static void memorystatus_freeze_handle_error(proc_t p, const int freezer_error_code, bool was_refreeze, pid_t pid, const coalition_t coalition, const char* log_prefix);
static void memorystatus_freeze_out_of_slots(void);
static uint64_t memorystatus_freezer_thread_next_run_ts = 0;

/* Sysctls needed for aggd stats */

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_frozen_count, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_count_webcontent, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_frozen_count_webcontent, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_count_xpc_service, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_frozen_count_xpc_service, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_thaw_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_thaw_count, 0, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_thaw_count_since_boot, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_thaw_count_since_boot, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_pageouts, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freeze_pageouts, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_interval, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freeze_current_interval, 0, "");

/*
 * Force a new interval with the given budget (no rollover).
 */
static void
memorystatus_freeze_force_new_interval(uint64_t new_budget)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	mach_timespec_t now_ts;
	clock_sec_t sec;
	clock_nsec_t nsec;

	clock_get_system_nanotime(&sec, &nsec);
	now_ts.tv_sec = (unsigned int)(MIN(sec, UINT32_MAX));
	now_ts.tv_nsec = nsec;
	memorystatus_freeze_start_normal_throttle_interval((uint32_t) MIN(new_budget, UINT32_MAX), now_ts);
	/* Don't carry over any excess pageouts since we're forcing a new budget */
	normal_throttle_window->pageouts = 0;
	memorystatus_freeze_budget_pages_remaining = normal_throttle_window->max_pageouts;
}
#if DEVELOPMENT || DEBUG
static int sysctl_memorystatus_freeze_budget_pages_remaining SYSCTL_HANDLER_ARGS
{
	#pragma unused(arg1, arg2, oidp)
	int error, changed;
	uint64_t new_budget = memorystatus_freeze_budget_pages_remaining;

	lck_mtx_lock(&freezer_mutex);

	error = sysctl_io_number(req, memorystatus_freeze_budget_pages_remaining, sizeof(uint64_t), &new_budget, &changed);
	if (changed) {
		if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			lck_mtx_unlock(&freezer_mutex);
			return ENOTSUP;
		}
		memorystatus_freeze_force_new_interval(new_budget);
	}

	lck_mtx_unlock(&freezer_mutex);
	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freeze_budget_pages_remaining, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0, &sysctl_memorystatus_freeze_budget_pages_remaining, "Q", "");
#else /* DEVELOPMENT || DEBUG */
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freeze_budget_pages_remaining, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freeze_budget_pages_remaining, "");
#endif /* DEVELOPMENT || DEBUG */
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_excess_shared_memory_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_excess_shared_memory_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_low_private_shared_ratio_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_low_private_shared_ratio_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_no_compressor_space_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_no_compressor_space_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_no_swap_space_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_no_swap_space_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_below_min_pages_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_below_min_pages_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_low_probability_of_use_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_low_probability_of_use_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_elevated_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_elevated_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_error_other_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_error_other_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_process_considered_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_process_considered_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_below_threshold_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_below_threshold_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_skipped_full_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_skipped_full_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_skipped_shared_mb_high_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_skipped_shared_mb_high_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_shared_pages_skipped, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_shared_pages_skipped, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_bytes_refrozen, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_bytes_refrozen, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_refreeze_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_refreeze_count, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_freeze_pid_mismatches, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_freeze_pid_mismatches, "");
SYSCTL_QUAD(_kern, OID_AUTO, memorystatus_freezer_demote_pid_mismatches, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freezer_stats.mfs_demote_pid_mismatches, "");

static_assert(_kMemorystatusFreezeSkipReasonMax <= UINT8_MAX);

static inline bool
proc_is_refreeze_eligible(proc_t p)
{
	return (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) != 0;
}

/*
 * Calculates the hit rate for the freezer.
 * The hit rate is defined as the percentage of procs that are currently in the
 * freezer which we have thawed.
 * A low hit rate means we're freezing bad candidates since they're not re-used.
 */
static int
calculate_thaw_percentage(uint64_t frozen_count, uint64_t thaw_count)
{
	int thaw_percentage = 100;

	if (frozen_count > 0) {
		if (thaw_count > frozen_count) {
			/*
			 * Both counts are using relaxed atomics & could be out of sync
			 * causing us to see thaw_percentage > 100.
			 */
			thaw_percentage = 100;
		} else {
			thaw_percentage = (int)(100 * thaw_count / frozen_count);
		}
	}
	return thaw_percentage;
}

static int
get_thaw_percentage()
{
	uint64_t processes_frozen, processes_thawed;
	processes_frozen = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
	processes_thawed = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed, relaxed);
	return calculate_thaw_percentage(processes_frozen, processes_thawed);
}

static int
sysctl_memorystatus_freezer_thaw_percentage SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int thaw_percentage = get_thaw_percentage();
	return sysctl_handle_int(oidp, &thaw_percentage, 0, req);
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freezer_thaw_percentage, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, &sysctl_memorystatus_freezer_thaw_percentage, "I", "");

static int
get_thaw_percentage_fg()
{
	uint64_t processes_frozen, processes_thawed_fg;
	processes_frozen = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
	processes_thawed_fg = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed_fg, relaxed);
	return calculate_thaw_percentage(processes_frozen, processes_thawed_fg);
}

static int sysctl_memorystatus_freezer_thaw_percentage_fg SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int thaw_percentage = get_thaw_percentage_fg();
	return sysctl_handle_int(oidp, &thaw_percentage, 0, req);
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freezer_thaw_percentage_fg, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, &sysctl_memorystatus_freezer_thaw_percentage_fg, "I", "");

static int
get_thaw_percentage_webcontent()
{
	uint64_t processes_frozen_webcontent, processes_thawed_webcontent;
	processes_frozen_webcontent = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen_webcontent, relaxed);
	processes_thawed_webcontent = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed_webcontent, relaxed);
	return calculate_thaw_percentage(processes_frozen_webcontent, processes_thawed_webcontent);
}

static int sysctl_memorystatus_freezer_thaw_percentage_webcontent SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int thaw_percentage = get_thaw_percentage_webcontent();
	return sysctl_handle_int(oidp, &thaw_percentage, 0, req);
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freezer_thaw_percentage_webcontent, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, &sysctl_memorystatus_freezer_thaw_percentage_webcontent, "I", "");


static int
get_thaw_percentage_bg()
{
	uint64_t processes_frozen, processes_thawed_fg, processes_thawed;
	processes_frozen = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
	processes_thawed = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed, relaxed);
	processes_thawed_fg = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed_fg, relaxed);
	return calculate_thaw_percentage(processes_frozen, processes_thawed - processes_thawed_fg);
}

static int sysctl_memorystatus_freezer_thaw_percentage_bg SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int thaw_percentage = get_thaw_percentage_bg();
	return sysctl_handle_int(oidp, &thaw_percentage, 0, req);
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freezer_thaw_percentage_bg, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, &sysctl_memorystatus_freezer_thaw_percentage_bg, "I", "");

static int
get_thaw_percentage_fg_non_xpc_service()
{
	uint64_t processes_frozen, processes_frozen_xpc_service, processes_thawed_fg, processes_thawed_fg_xpc_service;
	processes_frozen = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
	processes_frozen_xpc_service = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen_xpc_service, relaxed);
	processes_thawed_fg = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed_fg, relaxed);
	processes_thawed_fg_xpc_service = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed_fg_xpc_service, relaxed);
	/*
	 * Since these are all relaxed loads, it's possible (although unlikely) to read a value for
	 * frozen/thawed xpc services that's > the value for processes frozen / thawed.
	 * Clamp just in case.
	 */
	processes_frozen_xpc_service = MIN(processes_frozen_xpc_service, processes_frozen);
	processes_thawed_fg_xpc_service = MIN(processes_thawed_fg_xpc_service, processes_thawed_fg);
	return calculate_thaw_percentage(processes_frozen - processes_frozen_xpc_service, processes_thawed_fg - processes_thawed_fg_xpc_service);
}

static int sysctl_memorystatus_freezer_thaw_percentage_fg_non_xpc_service SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int thaw_percentage = get_thaw_percentage_fg_non_xpc_service();
	return sysctl_handle_int(oidp, &thaw_percentage, 0, req);
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freezer_thaw_percentage_fg_non_xpc_service, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, &sysctl_memorystatus_freezer_thaw_percentage_fg_non_xpc_service, "I", "");

#define FREEZER_ERROR_STRING_LENGTH 128

EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_pages_min, &memorystatus_freeze_pages_min, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_pages_max, &memorystatus_freeze_pages_max, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_processes_max, &memorystatus_frozen_processes_max, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_jetsam_band, &memorystatus_freeze_jetsam_band, JETSAM_PRIORITY_IDLE, JETSAM_PRIORITY_MAX - 1, "");
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_private_shared_pages_ratio, &memorystatus_freeze_private_shared_pages_ratio, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_min_processes, &memorystatus_freeze_suspended_threshold, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_freeze_max_candidate_band, &memorystatus_freeze_max_candidate_band, JETSAM_PRIORITY_IDLE, JETSAM_PRIORITY_MAX - 1, "");
static int
sysctl_memorystatus_freeze_budget_multiplier SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp, req)
	int error = 0, changed = 0;
	uint64_t val = memorystatus_freeze_budget_multiplier;
	unsigned int new_budget;
	clock_sec_t sec;
	clock_nsec_t nsec;
	mach_timespec_t now_ts;

	error = sysctl_io_number(req, memorystatus_freeze_budget_multiplier, sizeof(val), &val, &changed);
	if (error) {
		return error;
	}
	if (changed) {
		if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			return ENOTSUP;
		}
#if !(DEVELOPMENT || DEBUG)
		if (val > 100) {
			/* Can not increase budget on release. */
			return EINVAL;
		}
#endif
		lck_mtx_lock(&freezer_mutex);

		memorystatus_freeze_budget_multiplier = val;
		/* Start a new throttle interval with this budget multiplier */
		new_budget = memorystatus_freeze_calculate_new_budget(0, 1, NORMAL_WINDOW_MINS, 0);
		clock_get_system_nanotime(&sec, &nsec);
		now_ts.tv_sec = (unsigned int)(MIN(sec, UINT32_MAX));
		now_ts.tv_nsec = nsec;
		memorystatus_freeze_start_normal_throttle_interval(new_budget, now_ts);
		memorystatus_freeze_budget_pages_remaining = normal_throttle_window->max_pageouts;

		lck_mtx_unlock(&freezer_mutex);
	}
	return 0;
}
EXPERIMENT_FACTOR_PROC(_kern, memorystatus_freeze_budget_multiplier, CTLTYPE_QUAD | CTLFLAG_RW, 0, 0, &sysctl_memorystatus_freeze_budget_multiplier, "Q", "");
/*
 * max. # of frozen process demotions we will allow in our daily cycle.
 */
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_max_freeze_demotions_daily, &memorystatus_max_frozen_demotions_daily, 0, UINT32_MAX, "");

/*
 * min # of thaws needed by a process to protect it from getting demoted into the IDLE band.
 */
EXPERIMENT_FACTOR_UINT(_kern, memorystatus_thaw_count_demotion_threshold, &memorystatus_thaw_count_demotion_threshold, 0, UINT32_MAX, "");

#if DEVELOPMENT || DEBUG

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_daily_mb_max, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_freeze_daily_mb_max, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_degraded_mode, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_freeze_degradation, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_threshold, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_freeze_threshold, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_refreeze_eligible_count, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_refreeze_eligible_count, 0, "");

/*
 * Max. shared-anonymous memory in MB that can be held by frozen processes in the high jetsam band.
 * "0" means no limit.
 * Default is 10% of system-wide task limit.
 */

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_shared_mb_max, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_frozen_shared_mb_max, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_shared_mb, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_frozen_shared_mb, 0, "");

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_shared_mb_per_process_max, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_freeze_shared_mb_per_process_max, 0, "");

boolean_t memorystatus_freeze_throttle_enabled = TRUE;
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_throttle_enabled, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_freeze_throttle_enabled, 0, "");

/*
 * When set to true, this keeps frozen processes in the compressor pool in memory, instead of swapping them out to disk.
 * Exposed via the sysctl kern.memorystatus_freeze_to_memory.
 */
boolean_t memorystatus_freeze_to_memory = FALSE;
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_freeze_to_memory, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_freeze_to_memory, 0, "");

#define VM_PAGES_FOR_ALL_PROCS    (2)

/*
 * Manual trigger of freeze and thaw for dev / debug kernels only.
 */
static int
sysctl_memorystatus_freeze SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, pid = 0;
	proc_t p;
	int freezer_error_code = 0;
	pid_t pid_list[MAX_XPC_SERVICE_PIDS];
	int ntasks = 0;
	coalition_t coal = COALITION_NULL;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (pid == VM_PAGES_FOR_ALL_PROCS) {
		vm_pageout_anonymous_pages();

		return 0;
	}

	lck_mtx_lock(&freezer_mutex);
	if (memorystatus_freeze_enabled == FALSE) {
		lck_mtx_unlock(&freezer_mutex);
		printf("sysctl_freeze: Freeze is DISABLED\n");
		return ENOTSUP;
	}

again:
	p = proc_find(pid);
	if (p != NULL) {
		memorystatus_freezer_stats.mfs_process_considered_count++;
		uint32_t purgeable, wired, clean, dirty, shared;
		uint32_t max_pages = 0, state = 0;

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			/*
			 * Freezer backed by the compressor and swap file(s)
			 * will hold compressed data.
			 *
			 * Set the sysctl kern.memorystatus_freeze_to_memory to true to keep compressed data from
			 * being swapped out to disk. Note that this disables freezer swap support globally,
			 * not just for the process being frozen.
			 *
			 *
			 * We don't care about the global freezer budget or the process's (min/max) budget here.
			 * The freeze sysctl is meant to force-freeze a process.
			 *
			 * We also don't update any global or process stats on this path, so that the jetsam/ freeze
			 * logic remains unaffected. The tasks we're performing here are: freeze the process, set the
			 * P_MEMSTAT_FROZEN bit, and elevate the process to a higher band (if the freezer is active).
			 */
			max_pages = memorystatus_freeze_pages_max;
		} else {
			/*
			 * We only have the compressor without any swap.
			 */
			max_pages = UINT32_MAX - 1;
		}

		proc_list_lock();
		state = p->p_memstat_state;
		proc_list_unlock();

		/*
		 * The jetsam path also verifies that the process is a suspended App. We don't care about that here.
		 * We simply ensure that jetsam is not already working on the process and that the process has not
		 * explicitly disabled freezing.
		 */
		if (state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_FREEZE_DISABLED)) {
			printf("sysctl_freeze: p_memstat_state check failed, process is%s%s%s\n",
			    (state & P_MEMSTAT_TERMINATED) ? " terminated" : "",
			    (state & P_MEMSTAT_LOCKED) ? " locked" : "",
			    (state & P_MEMSTAT_FREEZE_DISABLED) ? " unfreezable" : "");

			proc_rele(p);
			lck_mtx_unlock(&freezer_mutex);
			return EPERM;
		}

		error = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, &freezer_error_code, FALSE /* eval only */);
		if (!error || freezer_error_code == FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO) {
			memorystatus_freezer_stats.mfs_shared_pages_skipped += shared;
		}

		if (error) {
			memorystatus_freeze_handle_error(p, freezer_error_code, state & P_MEMSTAT_FROZEN, pid, coal, "sysctl_freeze");
			if (error == KERN_NO_SPACE) {
				/* Make it easy to distinguish between failures due to low compressor/ swap space and other failures. */
				error = ENOSPC;
			} else {
				error = EIO;
			}
		} else {
			proc_list_lock();
			if ((p->p_memstat_state & P_MEMSTAT_FROZEN) == 0) {
				p->p_memstat_state |= P_MEMSTAT_FROZEN;
				p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
				memorystatus_frozen_count++;
				os_atomic_inc(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
				if (strcmp(p->p_name, "com.apple.WebKit.WebContent") == 0) {
					memorystatus_frozen_count_webcontent++;
					os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_frozen_webcontent), relaxed);
				}
				if (memorystatus_frozen_count == memorystatus_frozen_processes_max) {
					memorystatus_freeze_out_of_slots();
				}
			} else {
				// This was a re-freeze
				if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
					memorystatus_freezer_stats.mfs_bytes_refrozen += dirty * PAGE_SIZE;
					memorystatus_freezer_stats.mfs_refreeze_count++;
				}
			}
			p->p_memstat_frozen_count++;

			if (coal != NULL) {
				/* We just froze an xpc service. Mark it as such for telemetry */
				p->p_memstat_state |= P_MEMSTAT_FROZEN_XPC_SERVICE;
				memorystatus_frozen_count_xpc_service++;
				os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_frozen_xpc_service), relaxed);
			}


			proc_list_unlock();

			if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
				/*
				 * We elevate only if we are going to swap out the data.
				 */
				error = memorystatus_update_inactive_jetsam_priority_band(pid, MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE,
				    memorystatus_freeze_jetsam_band, TRUE);

				if (error) {
					printf("sysctl_freeze: Elevating frozen process to higher jetsam band failed with %d\n", error);
				}
			}
		}

		if ((error == 0) && (coal == NULL)) {
			/*
			 * We froze a process and so we check to see if it was
			 * a coalition leader and if it has XPC services that
			 * might need freezing.
			 * Only one leader can be frozen at a time and so we shouldn't
			 * enter this block more than once per call. Hence the
			 * check that 'coal' has to be NULL. We should make this an
			 * assert() or panic() once we have a much more concrete way
			 * to detect an app vs a daemon.
			 */

			task_t          curr_task = NULL;

			curr_task = proc_task(p);
			coal = task_get_coalition(curr_task, COALITION_TYPE_JETSAM);
			if (coalition_is_leader(curr_task, coal)) {
				ntasks = coalition_get_pid_list(coal, COALITION_ROLEMASK_XPC,
				    COALITION_SORT_DEFAULT, pid_list, MAX_XPC_SERVICE_PIDS);

				if (ntasks > MAX_XPC_SERVICE_PIDS) {
					ntasks = MAX_XPC_SERVICE_PIDS;
				}
			}
		}

		proc_rele(p);

		while (ntasks) {
			pid = pid_list[--ntasks];
			goto again;
		}

		lck_mtx_unlock(&freezer_mutex);
		return error;
	} else {
		printf("sysctl_freeze: Invalid process\n");
	}


	lck_mtx_unlock(&freezer_mutex);
	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_freeze, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_freeze, "I", "");

/*
 * Manual trigger of agressive frozen demotion for dev / debug kernels only.
 */
static int
sysctl_memorystatus_demote_frozen_process SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, val;
	/*
	 * Only demote on write to prevent demoting during `sysctl -a`.
	 * The actual value written doesn't matter.
	 */
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return error;
	}
	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return ENOTSUP;
	}
	lck_mtx_lock(&freezer_mutex);
	memorystatus_demote_frozen_processes(false);
	lck_mtx_unlock(&freezer_mutex);
	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_demote_frozen_processes, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, 0, &sysctl_memorystatus_demote_frozen_process, "I", "");

static int
sysctl_memorystatus_available_pages_thaw SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int error, pid = 0;
	proc_t p;

	if (memorystatus_freeze_enabled == FALSE) {
		return ENOTSUP;
	}

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (pid == VM_PAGES_FOR_ALL_PROCS) {
		do_fastwake_warmup_all();
		return 0;
	} else {
		p = proc_find(pid);
		if (p != NULL) {
			error = task_thaw(p->task);

			if (error) {
				error = EIO;
			} else {
				/*
				 * task_thaw() succeeded.
				 *
				 * We increment memorystatus_frozen_count on the sysctl freeze path.
				 * And so we need the P_MEMSTAT_FROZEN to decrement the frozen count
				 * when this process exits.
				 *
				 * proc_list_lock();
				 * p->p_memstat_state &= ~P_MEMSTAT_FROZEN;
				 * proc_list_unlock();
				 */
			}
			proc_rele(p);
			return error;
		}
	}

	return EINVAL;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_thaw, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_available_pages_thaw, "I", "");


typedef struct _global_freezable_status {
	boolean_t       freeze_pages_threshold_crossed;
	boolean_t       freeze_eligible_procs_available;
	boolean_t       freeze_scheduled_in_future;
}global_freezable_status_t;

typedef struct _proc_freezable_status {
	boolean_t    freeze_has_memstat_state;
	boolean_t    freeze_has_pages_min;
	int        freeze_has_probability;
	int        freeze_leader_eligible;
	boolean_t    freeze_attempted;
	uint32_t    p_memstat_state;
	uint32_t    p_pages;
	int        p_freeze_error_code;
	int        p_pid;
	int        p_leader_pid;
	char        p_name[MAXCOMLEN + 1];
}proc_freezable_status_t;

#define MAX_FREEZABLE_PROCESSES 200 /* Total # of processes in band 0 that we evaluate for freezability */

/*
 * For coalition based freezing evaluations, we proceed as follows:
 *  - detect that the process is a coalition member and a XPC service
 *  - mark its 'freeze_leader_eligible' field with FREEZE_PROC_LEADER_FREEZABLE_UNKNOWN
 *  - continue its freezability evaluation assuming its leader will be freezable too
 *
 * Once we are done evaluating all processes, we do a quick run thru all
 * processes and for a coalition member XPC service we look up the 'freezable'
 * status of its leader and iff:
 *  - the xpc service is freezable i.e. its individual freeze evaluation worked
 *  - and, its leader is also marked freezable
 * we update its 'freeze_leader_eligible' to FREEZE_PROC_LEADER_FREEZABLE_SUCCESS.
 */

#define FREEZE_PROC_LEADER_FREEZABLE_UNKNOWN   (-1)
#define FREEZE_PROC_LEADER_FREEZABLE_SUCCESS    (1)
#define FREEZE_PROC_LEADER_FREEZABLE_FAILURE    (2)

static int
memorystatus_freezer_get_status(user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	uint32_t            proc_count = 0, freeze_eligible_proc_considered = 0, band = 0, xpc_index = 0, leader_index = 0;
	global_freezable_status_t    *list_head;
	proc_freezable_status_t     *list_entry, *list_entry_start;
	size_t                list_size = 0, entry_count = 0;
	proc_t                p, leader_proc;
	memstat_bucket_t        *bucket;
	uint32_t            state = 0, pages = 0;
	boolean_t            try_freeze = TRUE, xpc_skip_size_probability_check = FALSE;
	int                error = 0, probability_of_use = 0;
	pid_t              leader_pid = 0;


	if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE == FALSE) {
		return ENOTSUP;
	}

	list_size = sizeof(global_freezable_status_t) + (sizeof(proc_freezable_status_t) * MAX_FREEZABLE_PROCESSES);

	if (buffer_size < list_size) {
		return EINVAL;
	}

	list_head = (global_freezable_status_t *)kalloc_data(list_size, Z_WAITOK | Z_ZERO);
	if (list_head == NULL) {
		return ENOMEM;
	}

	list_size = sizeof(global_freezable_status_t);

	proc_list_lock();

	uint64_t curr_time = mach_absolute_time();

	list_head->freeze_pages_threshold_crossed = (memorystatus_available_pages < memorystatus_freeze_threshold);
	list_head->freeze_eligible_procs_available = ((memorystatus_suspended_count - memorystatus_frozen_count) > memorystatus_freeze_suspended_threshold);
	list_head->freeze_scheduled_in_future = (curr_time < memorystatus_freezer_thread_next_run_ts);

	list_entry_start = (proc_freezable_status_t*) ((uintptr_t)list_head + sizeof(global_freezable_status_t));
	list_entry = list_entry_start;

	bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];

	entry_count = (memorystatus_global_probabilities_size / sizeof(memorystatus_internal_probabilities_t));

	p = memorystatus_get_first_proc_locked(&band, FALSE);
	proc_count++;

	while ((proc_count <= MAX_FREEZABLE_PROCESSES) &&
	    (p) &&
	    (list_size < buffer_size)) {
		if (isSysProc(p)) {
			/*
			 * Daemon:- We will consider freezing it iff:
			 * - it belongs to a coalition and the leader is freeze-eligible (delayed evaluation)
			 * - its role in the coalition is XPC service.
			 *
			 * We skip memory size requirements in this case.
			 */

			coalition_t     coal = COALITION_NULL;
			task_t          leader_task = NULL, curr_task = NULL;
			int             task_role_in_coalition = 0;

			curr_task = proc_task(p);
			coal = task_get_coalition(curr_task, COALITION_TYPE_JETSAM);

			if (coal == COALITION_NULL || coalition_is_leader(curr_task, coal)) {
				/*
				 * By default, XPC services without an app
				 * will be the leader of their own single-member
				 * coalition.
				 */
				goto skip_ineligible_xpc;
			}

			leader_task = coalition_get_leader(coal);
			if (leader_task == TASK_NULL) {
				/*
				 * This jetsam coalition is currently leader-less.
				 * This could happen if the app died, but XPC services
				 * have not yet exited.
				 */
				goto skip_ineligible_xpc;
			}

			leader_proc = (proc_t)get_bsdtask_info(leader_task);
			task_deallocate(leader_task);

			if (leader_proc == PROC_NULL) {
				/* leader task is exiting */
				goto skip_ineligible_xpc;
			}

			task_role_in_coalition = i_coal_jetsam_get_taskrole(coal, curr_task);

			if (task_role_in_coalition == COALITION_TASKROLE_XPC) {
				xpc_skip_size_probability_check = TRUE;
				leader_pid = proc_getpid(leader_proc);
				goto continue_eval;
			}

skip_ineligible_xpc:
			p = memorystatus_get_next_proc_locked(&band, p, FALSE);
			proc_count++;
			continue;
		}

continue_eval:
		strlcpy(list_entry->p_name, p->p_name, MAXCOMLEN + 1);

		list_entry->p_pid = proc_getpid(p);

		state = p->p_memstat_state;

		if ((state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_FREEZE_DISABLED | P_MEMSTAT_FREEZE_IGNORE)) ||
		    !(state & P_MEMSTAT_SUSPENDED)) {
			try_freeze = list_entry->freeze_has_memstat_state = FALSE;
		} else {
			try_freeze = list_entry->freeze_has_memstat_state = TRUE;
		}

		list_entry->p_memstat_state = state;

		if (xpc_skip_size_probability_check == TRUE) {
			/*
			 * Assuming the coalition leader is freezable
			 * we don't care re. minimum pages and probability
			 * as long as the process isn't marked P_MEMSTAT_FREEZE_DISABLED.
			 * XPC services have to be explicity opted-out of the disabled
			 * state. And we checked that state above.
			 */
			list_entry->freeze_has_pages_min = TRUE;
			list_entry->p_pages = -1;
			list_entry->freeze_has_probability = -1;

			list_entry->freeze_leader_eligible = FREEZE_PROC_LEADER_FREEZABLE_UNKNOWN;
			list_entry->p_leader_pid = leader_pid;

			xpc_skip_size_probability_check = FALSE;
		} else {
			list_entry->freeze_leader_eligible = FREEZE_PROC_LEADER_FREEZABLE_SUCCESS; /* Apps are freeze eligible and their own leaders. */
			list_entry->p_leader_pid = 0; /* Setting this to 0 signifies this isn't a coalition driven freeze. */

			memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL);
			if (pages < memorystatus_freeze_pages_min) {
				try_freeze = list_entry->freeze_has_pages_min = FALSE;
			} else {
				list_entry->freeze_has_pages_min = TRUE;
			}

			list_entry->p_pages = pages;

			if (entry_count) {
				uint32_t j = 0;
				for (j = 0; j < entry_count; j++) {
					if (strncmp(memorystatus_global_probabilities_table[j].proc_name,
					    p->p_name,
					    MAXCOMLEN) == 0) {
						probability_of_use = memorystatus_global_probabilities_table[j].use_probability;
						break;
					}
				}

				list_entry->freeze_has_probability = probability_of_use;

				try_freeze = ((probability_of_use > 0) && try_freeze);
			} else {
				list_entry->freeze_has_probability = -1;
			}
		}

		if (try_freeze) {
			uint32_t purgeable, wired, clean, dirty, shared;
			uint32_t max_pages = 0;
			int freezer_error_code = 0;

			error = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, max_pages, &shared, &freezer_error_code, TRUE /* eval only */);

			if (error) {
				list_entry->p_freeze_error_code = freezer_error_code;
			}

			list_entry->freeze_attempted = TRUE;
		}

		list_entry++;
		freeze_eligible_proc_considered++;

		list_size += sizeof(proc_freezable_status_t);

		p = memorystatus_get_next_proc_locked(&band, p, FALSE);
		proc_count++;
	}

	proc_list_unlock();

	list_entry = list_entry_start;

	for (xpc_index = 0; xpc_index < freeze_eligible_proc_considered; xpc_index++) {
		if (list_entry[xpc_index].freeze_leader_eligible == FREEZE_PROC_LEADER_FREEZABLE_UNKNOWN) {
			leader_pid = list_entry[xpc_index].p_leader_pid;

			leader_proc = proc_find(leader_pid);

			if (leader_proc) {
				if (leader_proc->p_memstat_state & P_MEMSTAT_FROZEN) {
					/*
					 * Leader has already been frozen.
					 */
					list_entry[xpc_index].freeze_leader_eligible = FREEZE_PROC_LEADER_FREEZABLE_SUCCESS;
					proc_rele(leader_proc);
					continue;
				}
				proc_rele(leader_proc);
			}

			for (leader_index = 0; leader_index < freeze_eligible_proc_considered; leader_index++) {
				if (list_entry[leader_index].p_pid == leader_pid) {
					if (list_entry[leader_index].freeze_attempted && list_entry[leader_index].p_freeze_error_code == 0) {
						list_entry[xpc_index].freeze_leader_eligible = FREEZE_PROC_LEADER_FREEZABLE_SUCCESS;
					} else {
						list_entry[xpc_index].freeze_leader_eligible = FREEZE_PROC_LEADER_FREEZABLE_FAILURE;
						list_entry[xpc_index].p_freeze_error_code = FREEZER_ERROR_GENERIC;
					}
					break;
				}
			}

			/*
			 * Didn't find the leader entry. This might be likely because
			 * the leader never made it down to band 0.
			 */
			if (leader_index == freeze_eligible_proc_considered) {
				list_entry[xpc_index].freeze_leader_eligible = FREEZE_PROC_LEADER_FREEZABLE_FAILURE;
				list_entry[xpc_index].p_freeze_error_code = FREEZER_ERROR_GENERIC;
			}
		}
	}

	buffer_size = MIN(list_size, INT32_MAX);

	error = copyout(list_head, buffer, buffer_size);
	if (error == 0) {
		*retval = (int32_t) buffer_size;
	} else {
		*retval = 0;
	}

	list_size = sizeof(global_freezable_status_t) + (sizeof(proc_freezable_status_t) * MAX_FREEZABLE_PROCESSES);
	kfree_data(list_head, list_size);

	MEMORYSTATUS_DEBUG(1, "memorystatus_freezer_get_status: returning %d (%lu - size)\n", error, (unsigned long)*list_size);

	return error;
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Get a list of all processes in the freezer band which are currently frozen.
 * Used by powerlog to collect analytics on frozen process.
 */
static int
memorystatus_freezer_get_procs(user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	global_frozen_procs_t *frozen_procs = NULL;
	uint32_t band = memorystatus_freeze_jetsam_band;
	proc_t p;
	uint32_t state;
	int error;
	if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE == FALSE) {
		return ENOTSUP;
	}
	if (buffer_size < sizeof(global_frozen_procs_t)) {
		return EINVAL;
	}
	frozen_procs = (global_frozen_procs_t *)kalloc_data(sizeof(global_frozen_procs_t), Z_WAITOK | Z_ZERO);
	if (frozen_procs == NULL) {
		return ENOMEM;
	}

	proc_list_lock();
	p = memorystatus_get_first_proc_locked(&band, FALSE);
	while (p && frozen_procs->gfp_num_frozen < FREEZER_CONTROL_GET_PROCS_MAX_COUNT) {
		state = p->p_memstat_state;
		if (state & P_MEMSTAT_FROZEN) {
			frozen_procs->gfp_procs[frozen_procs->gfp_num_frozen].fp_pid = proc_getpid(p);
			strlcpy(frozen_procs->gfp_procs[frozen_procs->gfp_num_frozen].fp_name,
			    p->p_name, sizeof(proc_name_t));
			frozen_procs->gfp_num_frozen++;
		}
		p = memorystatus_get_next_proc_locked(&band, p, FALSE);
	}
	proc_list_unlock();

	buffer_size = MIN(buffer_size, sizeof(global_frozen_procs_t));
	error = copyout(frozen_procs, buffer, buffer_size);
	if (error == 0) {
		*retval = (int32_t) buffer_size;
	} else {
		*retval = 0;
	}
	kfree_data(frozen_procs, sizeof(global_frozen_procs_t));

	return error;
}

/*
 * If dasd is running an experiment that impacts their freezer candidate selection,
 * we record that in our telemetry.
 */
static memorystatus_freezer_trial_identifiers_v1 dasd_trial_identifiers;

static int
memorystatus_freezer_set_dasd_trial_identifiers(user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	memorystatus_freezer_trial_identifiers_v1 identifiers;
	int error = 0;

	if (buffer_size != sizeof(identifiers)) {
		return EINVAL;
	}
	error = copyin(buffer, &identifiers, sizeof(identifiers));
	if (error != 0) {
		return error;
	}
	if (identifiers.version != 1) {
		return EINVAL;
	}
	dasd_trial_identifiers = identifiers;
	*retval = 0;
	return error;
}

/*
 * Reset the freezer state by wiping out all suspended frozen apps, clearing
 * per-process freezer state, and starting a fresh interval.
 */
static int
memorystatus_freezer_reset_state(int32_t *retval)
{
	uint32_t band = JETSAM_PRIORITY_IDLE;
	/* Don't kill above the frozen band */
	uint32_t kMaxBand = memorystatus_freeze_jetsam_band;
	proc_t next_p = PROC_NULL;
	uint64_t new_budget;

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return ENOTSUP;
	}

	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_GENERIC);
	if (jetsam_reason == OS_REASON_NULL) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus_freezer_reset_state -- sync: failed to allocate jetsam reason\n");
	}
	lck_mtx_lock(&freezer_mutex);
	kill_all_frozen_processes(kMaxBand, true, jetsam_reason, NULL);
	proc_list_lock();

	/*
	 * Clear the considered and skip reason flags on all processes
	 * so we're starting fresh with the new policy.
	 */
	next_p = memorystatus_get_first_proc_locked(&band, TRUE);
	while (next_p) {
		proc_t p = next_p;
		uint32_t state = p->p_memstat_state;
		next_p = memorystatus_get_next_proc_locked(&band, p, TRUE);

		if (p->p_memstat_effectivepriority > kMaxBand) {
			break;
		}
		if (state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED)) {
			continue;
		}

		p->p_memstat_state &= ~(P_MEMSTAT_FREEZE_CONSIDERED);
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
	}

	proc_list_unlock();

	new_budget = memorystatus_freeze_calculate_new_budget(0, normal_throttle_window->burst_multiple, normal_throttle_window->mins, 0);
	memorystatus_freeze_force_new_interval(new_budget);

	lck_mtx_unlock(&freezer_mutex);
	*retval = 0;
	return 0;
}

int
memorystatus_freezer_control(int32_t flags, user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	int err = ENOTSUP;

#if DEVELOPMENT || DEBUG
	if (flags == FREEZER_CONTROL_GET_STATUS) {
		err = memorystatus_freezer_get_status(buffer, buffer_size, retval);
	}
#endif /* DEVELOPMENT || DEBUG */
	if (flags == FREEZER_CONTROL_GET_PROCS) {
		err = memorystatus_freezer_get_procs(buffer, buffer_size, retval);
	} else if (flags == FREEZER_CONTROL_SET_DASD_TRIAL_IDENTIFIERS) {
		err = memorystatus_freezer_set_dasd_trial_identifiers(buffer, buffer_size, retval);
	} else if (flags == FREEZER_CONTROL_RESET_STATE) {
		err = memorystatus_freezer_reset_state(retval);
	}

	return err;
}

extern void        vm_swap_consider_defragmenting(int);
extern void vm_page_reactivate_all_throttled(void);

static bool
kill_all_frozen_processes(uint64_t max_band, bool suspended_only, os_reason_t jetsam_reason, uint64_t *memory_reclaimed_out)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);

	unsigned int band = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	pid_t pid = 0;
	bool retval = false, killed = false;
	uint32_t state;
	uint64_t memory_reclaimed = 0, footprint = 0, skips = 0;
	proc_list_lock();

	band = JETSAM_PRIORITY_IDLE;
	p = PROC_NULL;
	next_p = PROC_NULL;

	next_p = memorystatus_get_first_proc_locked(&band, TRUE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&band, p, TRUE);
		state = p->p_memstat_state;

		if (p->p_memstat_effectivepriority > max_band) {
			break;
		}

		if (!(state & P_MEMSTAT_FROZEN)) {
			continue;
		}

		if (suspended_only && !(state & P_MEMSTAT_SUSPENDED)) {
			continue;
		}

		if (state & P_MEMSTAT_ERROR) {
			p->p_memstat_state &= ~P_MEMSTAT_ERROR;
		}

		if (state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED)) {
			os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Skipping kill of frozen process %s (%d) because it's already exiting.\n", p->p_name, p->p_pid);
			skips++;
			continue;
		}

		footprint = get_task_phys_footprint(p->task);
		p->p_memstat_state |= P_MEMSTAT_TERMINATED;
		pid = proc_getpid(p);
		proc_list_unlock();

		/* memorystatus_kill_with_jetsam_reason_sync drops a reference. */
		os_reason_ref(jetsam_reason);
		retval = memorystatus_kill_with_jetsam_reason_sync(pid, jetsam_reason);
		if (retval) {
			killed = true;
			memory_reclaimed += footprint;
		}
		proc_list_lock();
		/*
		 * The bands might have changed when we dropped the proc list lock.
		 * So start from the beginning.
		 * Since we're preventing any further freezing by holding the freezer mutex,
		 * and we skip anything we've already tried to kill this is guaranteed to terminate.
		 */
		band = 0;
		skips = 0;
		next_p = memorystatus_get_first_proc_locked(&band, TRUE);
	}

	assert(skips <= memorystatus_frozen_count);
#if DEVELOPMENT || DEBUG
	if (!suspended_only && max_band >= JETSAM_PRIORITY_FOREGROUND) {
		/*
		 * Check that we've killed all frozen processes.
		 * Note that they may still be exiting (represented by skips).
		 */
		if (memorystatus_frozen_count - skips > 0) {
			assert(memorystatus_freeze_enabled == FALSE);

			panic("memorystatus_disable_freeze: Failed to kill all frozen processes, memorystatus_frozen_count = %d",
			    memorystatus_frozen_count);
		}
	}
#endif /* DEVELOPMENT || DEBUG */
	if (memory_reclaimed_out) {
		*memory_reclaimed_out = memory_reclaimed;
	}
	proc_list_unlock();
	return killed;
}

/*
 * Disables the freezer, jetsams all frozen processes,
 * and reclaims the swap space immediately.
 */

void
memorystatus_disable_freeze(void)
{
	uint64_t memory_reclaimed = 0;
	bool killed = false;
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);


	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE_DISABLE) | DBG_FUNC_START,
	    memorystatus_available_pages, 0, 0, 0, 0);
	os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Disabling freezer. Will kill all frozen processes\n");

	/*
	 * We hold the freezer_mutex (preventing anything from being frozen in parallel)
	 * and all frozen processes will be killed
	 * by the time we release it. Setting memorystatus_freeze_enabled to false,
	 * ensures that no new processes will be frozen once we release the mutex.
	 *
	 */
	memorystatus_freeze_enabled = FALSE;

	/*
	 * Move dirty pages out from the throttle to the active queue since we're not freezing anymore.
	 */
	vm_page_reactivate_all_throttled();
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_DISK_SPACE_SHORTAGE);
	if (jetsam_reason == OS_REASON_NULL) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus_disable_freeze -- sync: failed to allocate jetsam reason\n");
	}

	killed = kill_all_frozen_processes(JETSAM_PRIORITY_FOREGROUND, false, jetsam_reason, &memory_reclaimed);

	if (killed) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Killed all frozen processes.\n");
		vm_swap_consider_defragmenting(VM_SWAP_FLAGS_FORCE_DEFRAG | VM_SWAP_FLAGS_FORCE_RECLAIM);

		proc_list_lock();
		size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) +
		    sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_count);
		uint64_t timestamp_now = mach_absolute_time();
		memorystatus_jetsam_snapshot->notification_time = timestamp_now;
		memorystatus_jetsam_snapshot->js_gencount++;
		if (memorystatus_jetsam_snapshot_count > 0 && (memorystatus_jetsam_snapshot_last_timestamp == 0 ||
		    timestamp_now > memorystatus_jetsam_snapshot_last_timestamp + memorystatus_jetsam_snapshot_timeout)) {
			proc_list_unlock();
			int ret = memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
			if (!ret) {
				proc_list_lock();
				memorystatus_jetsam_snapshot_last_timestamp = timestamp_now;
			}
		}
		proc_list_unlock();
	} else {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: No frozen processes to kill.\n");
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE_DISABLE) | DBG_FUNC_END,
	    memorystatus_available_pages, memory_reclaimed, 0, 0, 0);

	return;
}

static void
memorystatus_set_freeze_is_enabled(bool enabled)
{
	lck_mtx_lock(&freezer_mutex);
	if (enabled != memorystatus_freeze_enabled) {
		if (enabled) {
			memorystatus_freeze_enabled = true;
		} else {
			memorystatus_disable_freeze();
		}
	}
	lck_mtx_unlock(&freezer_mutex);
}


static int
sysctl_freeze_enabled SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, val = memorystatus_freeze_enabled ? 1 : 0;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Failed attempt to set vm.freeze_enabled sysctl\n");
		return EINVAL;
	}

	memorystatus_set_freeze_is_enabled(val);

	return 0;
}

SYSCTL_PROC(_vm, OID_AUTO, freeze_enabled, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY, NULL, 0, sysctl_freeze_enabled, "I", "");

static void
schedule_interval_reset(thread_call_t reset_thread_call, throttle_interval_t *interval)
{
	uint64_t interval_expiration_ns = interval->ts.tv_sec * NSEC_PER_SEC + interval->ts.tv_nsec;
	uint64_t interval_expiration_absolutetime;
	nanoseconds_to_absolutetime(interval_expiration_ns, &interval_expiration_absolutetime);
	os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: scheduling new freezer interval at %llu absolute time\n", interval_expiration_absolutetime);

	thread_call_enter_delayed(reset_thread_call, interval_expiration_absolutetime);
}

extern uuid_string_t trial_treatment_id;
extern uuid_string_t trial_experiment_id;
extern int trial_deployment_id;

CA_EVENT(freezer_interval,
    CA_INT, budget_remaining,
    CA_INT, error_below_min_pages,
    CA_INT, error_excess_shared_memory,
    CA_INT, error_low_private_shared_ratio,
    CA_INT, error_no_compressor_space,
    CA_INT, error_no_swap_space,
    CA_INT, error_low_probability_of_use,
    CA_INT, error_elevated,
    CA_INT, error_other,
    CA_INT, frozen_count,
    CA_INT, pageouts,
    CA_INT, refreeze_average,
    CA_INT, skipped_full,
    CA_INT, skipped_shared_mb_high,
    CA_INT, swapusage,
    CA_INT, thaw_count,
    CA_INT, thaw_percentage,
    CA_INT, thaws_per_gb,
    CA_INT, trial_deployment_id,
    CA_INT, dasd_trial_deployment_id,
    CA_INT, budget_exhaustion_duration_remaining,
    CA_INT, thaw_percentage_webcontent,
    CA_INT, thaw_percentage_fg,
    CA_INT, thaw_percentage_bg,
    CA_INT, thaw_percentage_fg_non_xpc_service,
    CA_INT, fg_resume_count,
    CA_INT, unique_freeze_count,
    CA_INT, unique_thaw_count,
    CA_STATIC_STRING(CA_UUID_LEN), trial_treatment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_experiment_id,
    CA_STATIC_STRING(CA_UUID_LEN), dasd_trial_treatment_id,
    CA_STATIC_STRING(CA_UUID_LEN), dasd_trial_experiment_id);

extern uint64_t vm_swap_get_total_space(void);
extern uint64_t vm_swap_get_free_space(void);

/*
 * Record statistics from the expiring interval
 * via core analytics.
 */
static void
memorystatus_freeze_record_interval_analytics(void)
{
	ca_event_t event = CA_EVENT_ALLOCATE(freezer_interval);
	CA_EVENT_TYPE(freezer_interval) * e = event->data;
	e->budget_remaining = memorystatus_freeze_budget_pages_remaining * PAGE_SIZE / (1UL << 20);
	uint64_t process_considered_count, refrozen_count, below_threshold_count;
	memory_object_size_t swap_size;
	process_considered_count = memorystatus_freezer_stats.mfs_process_considered_count;
	if (process_considered_count != 0) {
		e->error_below_min_pages = memorystatus_freezer_stats.mfs_error_below_min_pages_count * 100 / process_considered_count;
		e->error_excess_shared_memory = memorystatus_freezer_stats.mfs_error_excess_shared_memory_count * 100 / process_considered_count;
		e->error_low_private_shared_ratio = memorystatus_freezer_stats.mfs_error_low_private_shared_ratio_count * 100 / process_considered_count;
		e->error_no_compressor_space = memorystatus_freezer_stats.mfs_error_no_compressor_space_count * 100 / process_considered_count;
		e->error_no_swap_space = memorystatus_freezer_stats.mfs_error_no_swap_space_count * 100 / process_considered_count;
		e->error_low_probability_of_use = memorystatus_freezer_stats.mfs_error_low_probability_of_use_count * 100 / process_considered_count;
		e->error_elevated = memorystatus_freezer_stats.mfs_error_elevated_count * 100 / process_considered_count;
		e->error_other = memorystatus_freezer_stats.mfs_error_other_count * 100 / process_considered_count;
	}
	e->frozen_count = memorystatus_frozen_count;
	e->pageouts = normal_throttle_window->pageouts * PAGE_SIZE / (1UL << 20);
	refrozen_count = memorystatus_freezer_stats.mfs_refreeze_count;
	if (refrozen_count != 0) {
		e->refreeze_average = (memorystatus_freezer_stats.mfs_bytes_refrozen / (1UL << 20)) / refrozen_count;
	}
	below_threshold_count = memorystatus_freezer_stats.mfs_below_threshold_count;
	if (below_threshold_count != 0) {
		e->skipped_full = memorystatus_freezer_stats.mfs_skipped_full_count * 100 / below_threshold_count;
		e->skipped_shared_mb_high = memorystatus_freezer_stats.mfs_skipped_shared_mb_high_count * 100 / below_threshold_count;
	}
	if (VM_CONFIG_SWAP_IS_PRESENT) {
		swap_size = vm_swap_get_total_space();
		if (swap_size) {
			e->swapusage = vm_swap_get_free_space() * 100 / swap_size;
		}
	}
	e->thaw_count = memorystatus_thaw_count;
	e->thaw_percentage = get_thaw_percentage();
	e->thaw_percentage_webcontent = get_thaw_percentage_webcontent();
	e->thaw_percentage_fg = get_thaw_percentage_fg();
	e->thaw_percentage_bg = get_thaw_percentage_bg();
	e->thaw_percentage_fg_non_xpc_service = get_thaw_percentage_fg_non_xpc_service();

	if (e->pageouts / (1UL << 10) != 0) {
		e->thaws_per_gb = memorystatus_thaw_count / (e->pageouts / (1UL << 10));
	}
	e->budget_exhaustion_duration_remaining = memorystatus_freezer_stats.mfs_budget_exhaustion_duration_remaining;
	e->fg_resume_count = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed_fg, relaxed);
	e->unique_freeze_count = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
	e->unique_thaw_count = os_atomic_load(&memorystatus_freezer_stats.mfs_processes_thawed, relaxed);

	/*
	 * Record any xnu or dasd experiment information
	 */
	strlcpy(e->trial_treatment_id, trial_treatment_id, CA_UUID_LEN);
	strlcpy(e->trial_experiment_id, trial_experiment_id, CA_UUID_LEN);
	e->trial_deployment_id = trial_deployment_id;
	strlcpy(e->dasd_trial_treatment_id, dasd_trial_identifiers.treatment_id, CA_UUID_LEN);
	strlcpy(e->dasd_trial_experiment_id, dasd_trial_identifiers.experiment_id, CA_UUID_LEN);
	e->dasd_trial_deployment_id = dasd_trial_identifiers.deployment_id;

	CA_EVENT_SEND(event);
}

static void
memorystatus_freeze_reset_interval(void *arg0, void *arg1)
{
#pragma unused(arg0, arg1)
	struct throttle_interval_t *interval = NULL;
	clock_sec_t sec;
	clock_nsec_t nsec;
	mach_timespec_t now_ts;
	uint32_t budget_rollover = 0;

	clock_get_system_nanotime(&sec, &nsec);
	now_ts.tv_sec = (unsigned int)(MIN(sec, UINT32_MAX));
	now_ts.tv_nsec = nsec;
	interval = normal_throttle_window;

	/* Record analytics from the old interval before resetting. */
	memorystatus_freeze_record_interval_analytics();

	lck_mtx_lock(&freezer_mutex);
	/* How long has it been since the previous interval expired? */
	mach_timespec_t expiration_period_ts = now_ts;
	SUB_MACH_TIMESPEC(&expiration_period_ts, &interval->ts);
	/* Get unused budget. Clamp to 0. We'll adjust for overused budget in the next interval. */
	budget_rollover = interval->pageouts > interval->max_pageouts ?
	    0 : interval->max_pageouts - interval->pageouts;

	memorystatus_freeze_start_normal_throttle_interval(memorystatus_freeze_calculate_new_budget(
		    expiration_period_ts.tv_sec, interval->burst_multiple,
		    interval->mins, budget_rollover),
	    now_ts);
	memorystatus_freeze_budget_pages_remaining = interval->max_pageouts;

	if (!memorystatus_freezer_use_demotion_list) {
		memorystatus_demote_frozen_processes(false); /* normal mode...don't force a demotion */
	}
	lck_mtx_unlock(&freezer_mutex);
}

__private_extern__ void
memorystatus_freeze_init(void)
{
	kern_return_t result;
	thread_t thread;

	if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		/*
		 * This is just the default value if the underlying
		 * storage device doesn't have any specific budget.
		 * We check with the storage layer in memorystatus_freeze_update_throttle()
		 * before we start our freezing the first time.
		 */
		memorystatus_freeze_budget_pages_remaining = (memorystatus_freeze_daily_mb_max * 1024 * 1024) / PAGE_SIZE;

		result = kernel_thread_start(memorystatus_freeze_thread, NULL, &thread);
		if (result == KERN_SUCCESS) {
			proc_set_thread_policy(thread, TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);
			proc_set_thread_policy(thread, TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			thread_set_thread_name(thread, "VM_freezer");

			thread_deallocate(thread);
		} else {
			panic("Could not create memorystatus_freeze_thread");
		}

		freeze_interval_reset_thread_call = thread_call_allocate_with_options(memorystatus_freeze_reset_interval, NULL, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
		/* Start a new interval */

		lck_mtx_lock(&freezer_mutex);
		uint32_t budget;
		budget = memorystatus_freeze_calculate_new_budget(0, normal_throttle_window->burst_multiple, normal_throttle_window->mins, 0);
		memorystatus_freeze_force_new_interval(budget);
		lck_mtx_unlock(&freezer_mutex);
	} else {
		memorystatus_freeze_budget_pages_remaining = 0;
	}
}

static boolean_t
memorystatus_is_process_eligible_for_freeze(proc_t p)
{
	/*
	 * Called with proc_list_lock held.
	 */

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	boolean_t should_freeze = FALSE;
	uint32_t state = 0, pages = 0;
	int probability_of_use = 0;
	size_t entry_count = 0, i = 0;
	bool first_consideration = true;

	state = p->p_memstat_state;

	if (state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_FREEZE_DISABLED | P_MEMSTAT_FREEZE_IGNORE)) {
		if (state & P_MEMSTAT_FREEZE_DISABLED) {
			p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonDisabled;
		}
		goto out;
	}

	if (isSysProc(p)) {
		/*
		 * Daemon:- We consider freezing it if:
		 * - it belongs to a coalition and the leader is frozen, and,
		 * - its role in the coalition is XPC service.
		 *
		 * We skip memory size requirements in this case.
		 */

		coalition_t     coal = COALITION_NULL;
		task_t          leader_task = NULL, curr_task = NULL;
		proc_t          leader_proc = NULL;
		int             task_role_in_coalition = 0;

		curr_task = proc_task(p);
		coal = task_get_coalition(curr_task, COALITION_TYPE_JETSAM);

		if (coal == NULL || coalition_is_leader(curr_task, coal)) {
			/*
			 * By default, XPC services without an app
			 * will be the leader of their own single-member
			 * coalition.
			 */
			goto out;
		}

		leader_task = coalition_get_leader(coal);
		if (leader_task == TASK_NULL) {
			/*
			 * This jetsam coalition is currently leader-less.
			 * This could happen if the app died, but XPC services
			 * have not yet exited.
			 */
			goto out;
		}

		leader_proc = (proc_t)get_bsdtask_info(leader_task);
		task_deallocate(leader_task);

		if (leader_proc == PROC_NULL) {
			/* leader task is exiting */
			goto out;
		}

		if (!(leader_proc->p_memstat_state & P_MEMSTAT_FROZEN)) {
			goto out;
		}

		task_role_in_coalition = i_coal_jetsam_get_taskrole(coal, curr_task);

		if (task_role_in_coalition == COALITION_TASKROLE_XPC) {
			should_freeze = TRUE;
		}

		goto out;
	} else {
		/*
		 * Application. In addition to the above states we need to make
		 * sure we only consider suspended applications for freezing.
		 */
		if (!(state & P_MEMSTAT_SUSPENDED)) {
			goto out;
		}
	}

	/*
	 * This proc is a suspended application.
	 * We're interested in tracking what percentage of these
	 * actually get frozen.
	 * To avoid skewing the metrics towards processes which
	 * are considered more frequently, we only track failures once
	 * per process.
	 */
	first_consideration = !(state & P_MEMSTAT_FREEZE_CONSIDERED);

	if (first_consideration) {
		memorystatus_freezer_stats.mfs_process_considered_count++;
		p->p_memstat_state |= P_MEMSTAT_FREEZE_CONSIDERED;
	}

	/* Only freeze applications meeting our minimum resident page criteria */
	memorystatus_get_task_page_counts(p->task, &pages, NULL, NULL);
	if (pages < memorystatus_freeze_pages_min) {
		if (first_consideration) {
			memorystatus_freezer_stats.mfs_error_below_min_pages_count++;
		}
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonBelowMinPages;
		goto out;
	}

	/* Don't freeze processes that are already exiting on core. It may have started exiting
	 * after we chose it for freeze, but before we obtained the proc_list_lock.
	 * NB: This is only possible if we're coming in from memorystatus_freeze_process_sync.
	 * memorystatus_freeze_top_process holds the proc_list_lock while it traverses the bands.
	 */
	if (proc_list_exited(p)) {
		if (first_consideration) {
			memorystatus_freezer_stats.mfs_error_other_count++;
		}
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonOther;
		goto out;
	}

	entry_count = (memorystatus_global_probabilities_size / sizeof(memorystatus_internal_probabilities_t));
	if (entry_count && !memorystatus_freezer_use_ordered_list) {
		for (i = 0; i < entry_count; i++) {
			/*
			 * NB: memorystatus_internal_probabilities.proc_name is MAXCOMLEN + 1 bytes
			 * proc_t.p_name is 2*MAXCOMLEN + 1 bytes. So we only compare the first
			 * MAXCOMLEN bytes here since the name in the probabilities table could
			 * be truncated from the proc_t's p_name.
			 */
			if (strncmp(memorystatus_global_probabilities_table[i].proc_name,
			    p->p_name,
			    MAXCOMLEN) == 0) {
				probability_of_use = memorystatus_global_probabilities_table[i].use_probability;
				break;
			}
		}

		if (probability_of_use == 0) {
			if (first_consideration) {
				memorystatus_freezer_stats.mfs_error_low_probability_of_use_count++;
			}
			p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonLowProbOfUse;
			goto out;
		}
	}

	if (!(state & P_MEMSTAT_FROZEN) && p->p_memstat_effectivepriority > memorystatus_freeze_max_candidate_band) {
		/*
		 * Proc has been elevated by something else.
		 * Don't freeze it.
		 */
		if (first_consideration) {
			memorystatus_freezer_stats.mfs_error_elevated_count++;
		}
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonElevated;
		goto out;
	}

	should_freeze = TRUE;
out:
	if (should_freeze && !(state & P_MEMSTAT_FROZEN)) {
		/*
		 * Reset the skip reason. If it's killed before we manage to actually freeze it
		 * we failed to consider it early enough.
		 */
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
		if (!first_consideration) {
			/*
			 * We're freezing this for the first time and we previously considered it ineligible.
			 * Bump the considered count so that we track this as 1 failure
			 * and 1 success.
			 */
			memorystatus_freezer_stats.mfs_process_considered_count++;
		}
	}
	return should_freeze;
}

/*
 * Called with both the freezer_mutex and proc_list_lock held & both will be held on return.
 */
static int
memorystatus_freeze_process(
	proc_t p,
	bool refreeze_processes,
	coalition_t *coal, /* IN / OUT */
	pid_t *coalition_list, /* OUT */
	unsigned int *coalition_list_length /* OUT */)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	kern_return_t kr;
	uint32_t purgeable, wired, clean, dirty, shared;
	uint64_t max_pages = 0;
	int    freezer_error_code = 0;
	bool was_refreeze = false;
	task_t curr_task = TASK_NULL;

	pid_t aPid = proc_getpid(p);

	/* Ensure the process is eligible for (re-)freezing */
	if ((p->p_memstat_state & P_MEMSTAT_FROZEN) && !proc_is_refreeze_eligible(p)) {
		/* Process is already frozen & hasn't been thawed. Nothing to do here. */
		return EINVAL;
	}
	if (refreeze_processes) {
		/*
		 * Has to have been frozen once before.
		 */
		if ((p->p_memstat_state & P_MEMSTAT_FROZEN) == FALSE) {
			return EINVAL;
		}

		/*
		 * Not currently being looked at for something.
		 */
		if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
			return EBUSY;
		}

		/*
		 * We are going to try and refreeze and so re-evaluate
		 * the process. We don't want to double count the shared
		 * memory. So deduct the old snapshot here.
		 */
		memorystatus_frozen_shared_mb -= p->p_memstat_freeze_sharedanon_pages;
		p->p_memstat_freeze_sharedanon_pages = 0;

		p->p_memstat_state &= ~P_MEMSTAT_REFREEZE_ELIGIBLE;
		memorystatus_refreeze_eligible_count--;
	} else {
		if (memorystatus_is_process_eligible_for_freeze(p) == FALSE) {
			return EINVAL;
		}
	}

	if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		/*
		 * Freezer backed by the compressor and swap file(s)
		 * will hold compressed data.
		 */

		max_pages = MIN(memorystatus_freeze_pages_max, memorystatus_freeze_budget_pages_remaining);
	} else {
		/*
		 * We only have the compressor pool.
		 */
		max_pages = UINT32_MAX - 1;
	}

	/* Mark as locked temporarily to avoid kill */
	p->p_memstat_state |= P_MEMSTAT_LOCKED;

	p = proc_ref(p, true);
	if (!p) {
		memorystatus_freezer_stats.mfs_error_other_count++;
		return EBUSY;
	}

	proc_list_unlock();

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE) | DBG_FUNC_START,
	    memorystatus_available_pages, 0, 0, 0, 0);

	max_pages = MIN(max_pages, UINT32_MAX);
	kr = task_freeze(p->task, &purgeable, &wired, &clean, &dirty, (uint32_t) max_pages, &shared, &freezer_error_code, FALSE /* eval only */);
	if (kr == KERN_SUCCESS || freezer_error_code == FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO) {
		memorystatus_freezer_stats.mfs_shared_pages_skipped += shared;
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE) | DBG_FUNC_END,
	    memorystatus_available_pages, aPid, 0, 0, 0);

	MEMORYSTATUS_DEBUG(1, "memorystatus_freeze_top_process: task_freeze %s for pid %d [%s] - "
	    "memorystatus_pages: %d, purgeable: %d, wired: %d, clean: %d, dirty: %d, max_pages %d, shared %d\n",
	    (kr == KERN_SUCCESS) ? "SUCCEEDED" : "FAILED", aPid, (*p->p_name ? p->p_name : "(unknown)"),
	    memorystatus_available_pages, purgeable, wired, clean, dirty, max_pages, shared);

	proc_list_lock();

	/* Success? */
	if (KERN_SUCCESS == kr) {
		memorystatus_freeze_entry_t data = { aPid, TRUE, dirty };

		p->p_memstat_freeze_sharedanon_pages += shared;

		memorystatus_frozen_shared_mb += shared;

		if ((p->p_memstat_state & P_MEMSTAT_FROZEN) == 0) {
			p->p_memstat_state |= P_MEMSTAT_FROZEN;
			p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
			memorystatus_frozen_count++;
			os_atomic_inc(&memorystatus_freezer_stats.mfs_processes_frozen, relaxed);
			if (strcmp(p->p_name, "com.apple.WebKit.WebContent") == 0) {
				memorystatus_frozen_count_webcontent++;
				os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_frozen_webcontent), relaxed);
			}
			if (memorystatus_frozen_count == memorystatus_frozen_processes_max) {
				memorystatus_freeze_out_of_slots();
			}
		} else {
			// This was a re-freeze
			if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
				memorystatus_freezer_stats.mfs_bytes_refrozen += dirty * PAGE_SIZE;
				memorystatus_freezer_stats.mfs_refreeze_count++;
			}
			was_refreeze = true;
		}

		p->p_memstat_frozen_count++;

		/*
		 * Still keeping the P_MEMSTAT_LOCKED bit till we are actually done elevating this frozen process
		 * to its higher jetsam band.
		 */
		proc_list_unlock();

		memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			int ret;
			unsigned int i;
			ret = memorystatus_update_inactive_jetsam_priority_band(proc_getpid(p), MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE, memorystatus_freeze_jetsam_band, TRUE);

			if (ret) {
				printf("Elevating the frozen process failed with %d\n", ret);
				/* not fatal */
			}

			/* Update stats */
			for (i = 0; i < sizeof(throttle_intervals) / sizeof(struct throttle_interval_t); i++) {
				throttle_intervals[i].pageouts += dirty;
			}
		}
		memorystatus_freeze_update_throttle(&memorystatus_freeze_budget_pages_remaining);
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: %sfreezing (%s) pid %d [%s] done, memorystatus_freeze_budget_pages_remaining %llu %sfroze %u pages\n",
		    was_refreeze ? "re" : "", ((!coal || !*coal) ? "general" : "coalition-driven"), aPid, ((p && *p->p_name) ? p->p_name : "unknown"), memorystatus_freeze_budget_pages_remaining, was_refreeze ? "Re" : "", dirty);

		proc_list_lock();

		memorystatus_freeze_pageouts += dirty;

		if (memorystatus_frozen_count == (memorystatus_frozen_processes_max - 1)) {
			/*
			 * Add some eviction logic here? At some point should we
			 * jetsam a process to get back its swap space so that we
			 * can freeze a more eligible process at this moment in time?
			 */
		}

		/* Check if we just froze a coalition leader. If so, return the list of XPC services to freeze next. */
		if (coal != NULL && *coal == NULL) {
			curr_task = proc_task(p);
			*coal = task_get_coalition(curr_task, COALITION_TYPE_JETSAM);
			if (coalition_is_leader(curr_task, *coal)) {
				*coalition_list_length = coalition_get_pid_list(*coal, COALITION_ROLEMASK_XPC,
				    COALITION_SORT_DEFAULT, coalition_list, MAX_XPC_SERVICE_PIDS);

				if (*coalition_list_length > MAX_XPC_SERVICE_PIDS) {
					*coalition_list_length = MAX_XPC_SERVICE_PIDS;
				}
			}
		} else {
			/* We just froze an xpc service. Mark it as such for telemetry */
			p->p_memstat_state |= P_MEMSTAT_FROZEN_XPC_SERVICE;
			memorystatus_frozen_count_xpc_service++;
			os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_frozen_xpc_service), relaxed);
		}

		p->p_memstat_state &= ~P_MEMSTAT_LOCKED;
		wakeup(&p->p_memstat_state);
		proc_rele(p);
		return 0;
	} else {
		if (refreeze_processes) {
			if ((freezer_error_code == FREEZER_ERROR_EXCESS_SHARED_MEMORY) ||
			    (freezer_error_code == FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO)) {
				/*
				 * Keeping this prior-frozen process in this high band when
				 * we failed to re-freeze it due to bad shared memory usage
				 * could cause excessive pressure on the lower bands.
				 * We need to demote it for now. It'll get re-evaluated next
				 * time because we don't set the P_MEMSTAT_FREEZE_IGNORE
				 * bit.
				 */

				p->p_memstat_state &= ~P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;
				memorystatus_invalidate_idle_demotion_locked(p, TRUE);
				memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, TRUE, TRUE);
			}
		} else {
			p->p_memstat_state |= P_MEMSTAT_FREEZE_IGNORE;
		}
		memorystatus_freeze_handle_error(p, freezer_error_code, p->p_memstat_state & P_MEMSTAT_FROZEN, aPid, *coal, "memorystatus_freeze_top_process");

		p->p_memstat_state &= ~P_MEMSTAT_LOCKED;
		wakeup(&p->p_memstat_state);
		proc_rele(p);

		return EINVAL;
	}
}

/*
 * Synchronously freeze the passed proc. Called with a reference to the proc held.
 *
 * Doesn't deal with:
 * - re-freezing because this is called on a specific process and
 *   not by the freezer thread. If that changes, we'll have to teach it about
 *   refreezing a frozen process.
 *
 * - grouped/coalition freezing because we are hoping to deprecate this
 *   interface as it was used by user-space to freeze particular processes. But
 *   we have moved away from that approach to having the kernel choose the optimal
 *   candidates to be frozen.
 *
 * Returns ENOTSUP if the freezer isn't supported on this device. Otherwise
 * returns EINVAL or the value returned by task_freeze().
 */
int
memorystatus_freeze_process_sync(proc_t p)
{
	int ret = EINVAL;
	boolean_t memorystatus_freeze_swap_low = FALSE;

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return ENOTSUP;
	}

	lck_mtx_lock(&freezer_mutex);

	if (p == NULL) {
		printf("memorystatus_freeze_process_sync: Invalid process\n");
		goto exit;
	}

	if (memorystatus_freeze_enabled == FALSE) {
		printf("memorystatus_freeze_process_sync: Freezing is DISABLED\n");
		goto exit;
	}

	if (!memorystatus_can_freeze(&memorystatus_freeze_swap_low)) {
		printf("memorystatus_freeze_process_sync: Low compressor and/or low swap space...skipping freeze\n");
		goto exit;
	}

	memorystatus_freeze_update_throttle(&memorystatus_freeze_budget_pages_remaining);
	if (!memorystatus_freeze_budget_pages_remaining) {
		printf("memorystatus_freeze_process_sync: exit with NO available budget\n");
		goto exit;
	}

	proc_list_lock();

	ret = memorystatus_freeze_process(p, false, NULL, NULL, NULL);

exit:
	lck_mtx_unlock(&freezer_mutex);

	return ret;
}

static proc_t
memorystatus_freezer_candidate_list_get_proc(
	struct memorystatus_freezer_candidate_list *list,
	size_t index,
	uint64_t *pid_mismatch_counter)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	if (list->mfcl_list == NULL || list->mfcl_length <= index) {
		return NULL;
	}
	memorystatus_properties_freeze_entry_v1 *entry = &list->mfcl_list[index];
	if (entry->pid == NO_PID) {
		/* Entry has been removed. */
		return NULL;
	}

	proc_t p = proc_find_locked(entry->pid);
	if (p && strncmp(entry->proc_name, p->p_name, sizeof(proc_name_t)) == 0) {
		/*
		 * We grab a reference when we are about to freeze the process. So drop
		 * the reference that proc_find_locked() grabbed for us.
		 * We also have the proc_list_lock so this process is stable.
		 */
		proc_rele(p);
		return p;
	} else {
		if (p) {
			/* pid rollover. */
			proc_rele(p);
		}
		/*
		 * The proc has exited since we received this list.
		 * It may have re-launched with a new pid, so we go looking for it.
		 */
		unsigned int band = JETSAM_PRIORITY_IDLE;
		p = memorystatus_get_first_proc_locked(&band, TRUE);
		while (p != NULL && band <= memorystatus_freeze_max_candidate_band) {
			if (strncmp(entry->proc_name, p->p_name, sizeof(proc_name_t)) == 0) {
				(*pid_mismatch_counter)++;
				/* Stash the pid for faster lookup next time. */
				entry->pid = proc_getpid(p);
				return p;
			}
			p = memorystatus_get_next_proc_locked(&band, p, TRUE);
		}
		/* No match. */
		return NULL;
	}
}

/*
 * Caller must hold the freezer_mutex and it will be locked on return.
 */
static int
memorystatus_freeze_top_process(void)
{
	pid_t coal_xpc_pid = 0;
	int ret = -1;
	int freeze_ret;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	unsigned int band = JETSAM_PRIORITY_IDLE;
	bool refreeze_processes = false;
	coalition_t coal = COALITION_NULL;
	pid_t pid_list[MAX_XPC_SERVICE_PIDS];
	unsigned int    ntasks = 0;
	size_t global_freeze_list_index = 0;
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE_SCAN) | DBG_FUNC_START, memorystatus_available_pages, 0, 0, 0, 0);

	proc_list_lock();

	if (memorystatus_frozen_count >= memorystatus_frozen_processes_max) {
		/*
		 * Freezer is already full but we are here and so let's
		 * try to refreeze any processes we might have thawed
		 * in the past and push their compressed state out.
		 */
		refreeze_processes = true;
		band = (unsigned int) memorystatus_freeze_jetsam_band;
	}

freeze_process:

	next_p = NULL;
	if (memorystatus_freezer_use_ordered_list && !refreeze_processes) {
		global_freeze_list_index = 0;
		next_p = memorystatus_freezer_candidate_list_get_proc(
			&memorystatus_global_freeze_list,
			global_freeze_list_index++,
			&memorystatus_freezer_stats.mfs_freeze_pid_mismatches);
		if (!next_p) {
			/*
			 * No candidate to freeze.
			 * But we're here. So try to re-freeze.
			 */
			refreeze_processes = true;
			band = (unsigned int) memorystatus_freeze_jetsam_band;
		}
	}
	if (next_p == NULL) {
		next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	}
	while (next_p) {
		p = next_p;
		if (!memorystatus_freezer_use_ordered_list && p->p_memstat_effectivepriority != (int32_t) band) {
			/*
			 * We shouldn't be freezing processes outside the
			 * prescribed band (unless we've been given an ordered list).
			 */
			break;
		}

		freeze_ret = memorystatus_freeze_process(p, refreeze_processes, &coal, pid_list, &ntasks);
		if (!freeze_ret) {
			ret = 0;
			/*
			 * We froze a process successfully. We can stop now
			 * and see if that helped if this process isn't part
			 * of a coalition.
			 */

			if (coal != NULL) {
				next_p = NULL;

				if (ntasks > 0) {
					coal_xpc_pid = pid_list[--ntasks];
					next_p = proc_find_locked(coal_xpc_pid);

					/*
					 * We grab a reference when we are about to freeze the process. So drop
					 * the reference that proc_find_locked() grabbed for us.
					 * We also have the proc_list_lock and so this process is stable.
					 */
					if (next_p) {
						proc_rele(next_p);
					}
				}
			}

			if (coal && next_p) {
				continue;
			}

			/*
			 * No coalition leader was frozen. So we don't
			 * need to evaluate any XPC services.
			 *
			 * OR
			 *
			 * We have frozen all eligible XPC services for
			 * the current coalition leader.
			 *
			 * Either way, we can break here and see if freezing
			 * helped.
			 */

			break;
		} else {
			if (vm_compressor_low_on_space() || vm_swap_low_on_space()) {
				break;
			}
			if (memorystatus_freezer_use_ordered_list && !refreeze_processes) {
				next_p = memorystatus_freezer_candidate_list_get_proc(
					&memorystatus_global_freeze_list,
					global_freeze_list_index++,
					&memorystatus_freezer_stats.mfs_freeze_pid_mismatches);
			} else {
				next_p = memorystatus_get_next_proc_locked(&band, p, FALSE);
			}
		}
	}

	if ((ret == -1) &&
	    (memorystatus_refreeze_eligible_count >= MIN_THAW_REFREEZE_THRESHOLD) &&
	    (!refreeze_processes)) {
		/*
		 * We failed to freeze a process from the IDLE
		 * band AND we have some thawed processes
		 * AND haven't tried refreezing as yet.
		 * Let's try and re-freeze processes in the
		 * frozen band that have been resumed in the past
		 * and so have brought in state from disk.
		 */

		band = (unsigned int) memorystatus_freeze_jetsam_band;

		refreeze_processes = true;

		goto freeze_process;
	}

	proc_list_unlock();

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_FREEZE_SCAN) | DBG_FUNC_END, memorystatus_available_pages, 0, 0, 0, 0);

	return ret;
}

#if DEVELOPMENT || DEBUG
/* For testing memorystatus_freeze_top_process */
static int
sysctl_memorystatus_freeze_top_process SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, val;
	/*
	 * Only freeze on write to prevent freezing during `sysctl -a`.
	 * The actual value written doesn't matter.
	 */
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return ENOTSUP;
	}

	lck_mtx_lock(&freezer_mutex);
	int ret = memorystatus_freeze_top_process();
	lck_mtx_unlock(&freezer_mutex);

	if (ret == -1) {
		ret = ESRCH;
	}
	return ret;
}
SYSCTL_PROC(_vm, OID_AUTO, memorystatus_freeze_top_process, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_freeze_top_process, "I", "");
#endif /* DEVELOPMENT || DEBUG */

static inline boolean_t
memorystatus_can_freeze_processes(void)
{
	boolean_t ret;

	proc_list_lock();

	if (memorystatus_suspended_count) {
		memorystatus_freeze_suspended_threshold = MIN(memorystatus_freeze_suspended_threshold, FREEZE_SUSPENDED_THRESHOLD_DEFAULT);

		if ((memorystatus_suspended_count - memorystatus_frozen_count) > memorystatus_freeze_suspended_threshold) {
			ret = TRUE;
		} else {
			ret = FALSE;
		}
	} else {
		ret = FALSE;
	}

	proc_list_unlock();

	return ret;
}

static boolean_t
memorystatus_can_freeze(boolean_t *memorystatus_freeze_swap_low)
{
	boolean_t can_freeze = TRUE;

	/* Only freeze if we're sufficiently low on memory; this holds off freeze right
	*  after boot,  and is generally is a no-op once we've reached steady state. */
	if (memorystatus_available_pages > memorystatus_freeze_threshold) {
		return FALSE;
	}

	/* Check minimum suspended process threshold. */
	if (!memorystatus_can_freeze_processes()) {
		return FALSE;
	}
	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		/*
		 * In-core compressor used for freezing WITHOUT on-disk swap support.
		 */
		if (vm_compressor_low_on_space()) {
			if (*memorystatus_freeze_swap_low) {
				*memorystatus_freeze_swap_low = TRUE;
			}

			can_freeze = FALSE;
		} else {
			if (*memorystatus_freeze_swap_low) {
				*memorystatus_freeze_swap_low = FALSE;
			}

			can_freeze = TRUE;
		}
	} else {
		/*
		 * Freezing WITH on-disk swap support.
		 *
		 * In-core compressor fronts the swap.
		 */
		if (vm_swap_low_on_space()) {
			if (*memorystatus_freeze_swap_low) {
				*memorystatus_freeze_swap_low = TRUE;
			}

			can_freeze = FALSE;
		}
	}

	return can_freeze;
}

/*
 * Demote the given frozen process.
 * Caller must hold the proc_list_lock & it will be held on return.
 */
static void
memorystatus_demote_frozen_process(proc_t p, bool urgent_mode __unused)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	/* We demote to IDLE unless someone has asserted a higher priority on this process. */
	int maxpriority = JETSAM_PRIORITY_IDLE;
	p->p_memstat_state &= ~P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;
	memorystatus_invalidate_idle_demotion_locked(p, TRUE);

	maxpriority = MAX(p->p_memstat_assertionpriority, maxpriority);
	memorystatus_update_priority_locked(p, maxpriority, FALSE, FALSE);
#if DEVELOPMENT || DEBUG
	os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus_demote_frozen_process(%s) pid %d [%s]\n",
	    (urgent_mode ? "urgent" : "normal"), (p ? proc_getpid(p) : -1), ((p && *p->p_name) ? p->p_name : "unknown"));
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * The freezer thread will consider this a normal app to be frozen
	 * because it is in the IDLE band. So we don't need the
	 * P_MEMSTAT_REFREEZE_ELIGIBLE state here. Also, if it gets resumed
	 * we'll correctly count it as eligible for re-freeze again.
	 *
	 * We don't drop the frozen count because this process still has
	 * state on disk. So there's a chance it gets resumed and then it
	 * should land in the higher jetsam band. For that it needs to
	 * remain marked frozen.
	 */
	if (proc_is_refreeze_eligible(p)) {
		p->p_memstat_state &= ~P_MEMSTAT_REFREEZE_ELIGIBLE;
		memorystatus_refreeze_eligible_count--;
	}
}

static unsigned int
memorystatus_demote_frozen_processes_using_thaw_count(bool urgent_mode)
{
	unsigned int band = (unsigned int) memorystatus_freeze_jetsam_band;
	unsigned int demoted_proc_count = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&band, p, FALSE);

		if ((p->p_memstat_state & P_MEMSTAT_FROZEN) == FALSE) {
			continue;
		}

		if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
			continue;
		}

		if (urgent_mode) {
			if (!proc_is_refreeze_eligible(p)) {
				/*
				 * This process hasn't been thawed recently and so most of
				 * its state sits on NAND and so we skip it -- jetsamming it
				 * won't help with memory pressure.
				 */
				continue;
			}
		} else {
			if (p->p_memstat_thaw_count >= memorystatus_thaw_count_demotion_threshold) {
				/*
				 * This process has met / exceeded our thaw count demotion threshold
				 * and so we let it live in the higher bands.
				 */
				continue;
			}
		}

		memorystatus_demote_frozen_process(p, urgent_mode);
		demoted_proc_count++;
		if ((urgent_mode) || (demoted_proc_count == memorystatus_max_frozen_demotions_daily)) {
			break;
		}
	}

	proc_list_unlock();
	return demoted_proc_count;
}

static unsigned int
memorystatus_demote_frozen_processes_using_demote_list(bool urgent_mode)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);
	assert(memorystatus_freezer_use_demotion_list);
	unsigned int demoted_proc_count = 0;

	proc_list_lock();
	for (size_t i = 0; i < memorystatus_global_demote_list.mfcl_length; i++) {
		proc_t p = memorystatus_freezer_candidate_list_get_proc(
			&memorystatus_global_demote_list,
			i,
			&memorystatus_freezer_stats.mfs_demote_pid_mismatches);
		if (p != NULL && proc_is_refreeze_eligible(p)) {
			memorystatus_demote_frozen_process(p, urgent_mode);
			/* Remove this entry now that it's been demoted. */
			memorystatus_global_demote_list.mfcl_list[i].pid = NO_PID;
			demoted_proc_count++;
			/*
			 * We only demote one proc at a time in this mode.
			 * This gives jetsam a chance to kill the recently demoted processes.
			 */
			break;
		}
	}

	proc_list_unlock();
	return demoted_proc_count;
}

/*
 * This function evaluates if the currently frozen processes deserve
 * to stay in the higher jetsam band. There are 2 modes:
 * - 'force one == TRUE': (urgent mode)
 *	We are out of budget and can't refreeze a process. The process's
 * state, if it was resumed, will stay in compressed memory. If we let it
 * remain up in the higher frozen jetsam band, it'll put a lot of pressure on
 * the lower bands. So we force-demote the least-recently-used-and-thawed
 * process.
 *
 * - 'force_one == FALSE': (normal mode)
 *      If the # of thaws of a process is below our threshold, then we
 * will demote that process into the IDLE band.
 * We don't immediately kill the process here because it  already has
 * state on disk and so it might be worth giving it another shot at
 * getting thawed/resumed and used.
 */
static void
memorystatus_demote_frozen_processes(bool urgent_mode)
{
	unsigned int demoted_proc_count = 0;

	if (memorystatus_freeze_enabled == FALSE) {
		/*
		 * Freeze has been disabled likely to
		 * reclaim swap space. So don't change
		 * any state on the frozen processes.
		 */
		return;
	}

	/*
	 * We have two demotion policies which can be toggled by userspace.
	 * In non-urgent mode, the ordered list policy will
	 * choose a demotion candidate using the list provided by dasd.
	 * The thaw count policy will demote the oldest process that hasn't been
	 * thawed more than memorystatus_thaw_count_demotion_threshold times.
	 *
	 * If urgent_mode is set, both policies will only consider demoting
	 * processes that are re-freeze eligible. But the ordering is different.
	 * The ordered list policy will scan in the order given by dasd.
	 * The thaw count policy will scan through the frozen band.
	 */
	if (memorystatus_freezer_use_demotion_list) {
		demoted_proc_count += memorystatus_demote_frozen_processes_using_demote_list(urgent_mode);

		if (demoted_proc_count == 0 && urgent_mode) {
			/*
			 * We're out of budget and the demotion list doesn't contain any valid
			 * candidates. We still need to demote something. Fall back to scanning
			 * the frozen band.
			 */
			memorystatus_demote_frozen_processes_using_thaw_count(true);
		}
	} else {
		demoted_proc_count += memorystatus_demote_frozen_processes_using_thaw_count(urgent_mode);
	}
}

/*
 * Calculate a new freezer budget.
 * @param time_since_last_interval_expired_sec How long has it been (in seconds) since the previous interval expired.
 * @param burst_multiple The burst_multiple for the new period
 * @param interval_duration_min How many minutes will the new interval be?
 * @param rollover The amount to rollover from the previous budget.
 *
 * @return A budget for the new interval.
 */
static uint32_t
memorystatus_freeze_calculate_new_budget(
	unsigned int time_since_last_interval_expired_sec,
	unsigned int burst_multiple,
	unsigned int interval_duration_min,
	uint32_t rollover)
{
	uint64_t freeze_daily_budget = 0, freeze_daily_budget_mb = 0, daily_budget_pageouts = 0, budget_missed = 0, freeze_daily_pageouts_max = 0, new_budget = 0;
	const static unsigned int kNumSecondsInDay = 60 * 60 * 24;
	/* Precision factor for days_missed. 2 decimal points. */
	const static unsigned int kFixedPointFactor = 100;
	unsigned int days_missed;

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return 0;
	}

	/* Get the daily budget from the storage layer */
	if (vm_swap_max_budget(&freeze_daily_budget)) {
		freeze_daily_budget_mb = freeze_daily_budget / (1024 * 1024);
		assert(freeze_daily_budget_mb <= UINT32_MAX);
		memorystatus_freeze_daily_mb_max = (unsigned int) freeze_daily_budget_mb;
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: memorystatus_freeze_daily_mb_max set to %dMB\n", memorystatus_freeze_daily_mb_max);
	}
	/* Calculate the daily pageout budget */
	freeze_daily_pageouts_max = memorystatus_freeze_daily_mb_max * (1024 * 1024 / PAGE_SIZE);
	/* Multiply by memorystatus_freeze_budget_multiplier */
	freeze_daily_pageouts_max = ((kFixedPointFactor * memorystatus_freeze_budget_multiplier / 100) * freeze_daily_pageouts_max) / kFixedPointFactor;

	daily_budget_pageouts = (burst_multiple * (((uint64_t) interval_duration_min * freeze_daily_pageouts_max) / (kNumSecondsInDay / 60)));

	/*
	 * Add additional budget for time since the interval expired.
	 * For example, if the interval expired n days ago, we should get an additional n days
	 * of budget since we didn't use any budget during those n days.
	 */
	days_missed = time_since_last_interval_expired_sec * kFixedPointFactor / kNumSecondsInDay;
	budget_missed = days_missed * freeze_daily_pageouts_max / kFixedPointFactor;
	new_budget = rollover + daily_budget_pageouts + budget_missed;
	return (uint32_t) MIN(new_budget, UINT32_MAX);
}

/*
 * Mark all non frozen, freezer-eligible processes as skipped for the given reason.
 * Used when we hit some system freeze limit and know that we won't be considering remaining processes.
 * If you're using this for a new reason, make sure to add it to memorystatus_freeze_init_proc so that
 * it gets set for new processes.
 * NB: These processes will retain this skip reason until they are reconsidered by memorystatus_is_process_eligible_for_freeze.
 */
static void
memorystatus_freeze_mark_eligible_processes_with_skip_reason(memorystatus_freeze_skip_reason_t reason, bool locked)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, locked ? LCK_MTX_ASSERT_OWNED : LCK_MTX_ASSERT_NOTOWNED);
	unsigned int band = JETSAM_PRIORITY_IDLE;
	proc_t p;

	if (!locked) {
		proc_list_lock();
	}
	p = memorystatus_get_first_proc_locked(&band, FALSE);
	while (p) {
		assert(p->p_memstat_effectivepriority == (int32_t) band);
		if (!(p->p_memstat_state & P_MEMSTAT_FROZEN) && memorystatus_is_process_eligible_for_freeze(p)) {
			assert(p->p_memstat_freeze_skip_reason == kMemorystatusFreezeSkipReasonNone);
			p->p_memstat_freeze_skip_reason = (uint8_t) reason;
		}
		p = memorystatus_get_next_proc_locked(&band, p, FALSE);
	}
	if (!locked) {
		proc_list_unlock();
	}
}

/*
 * Called after we fail to freeze a process.
 * Logs the failure, marks the process with the failure reason, and updates freezer stats.
 */
static void
memorystatus_freeze_handle_error(
	proc_t p,
	const int freezer_error_code,
	bool was_refreeze,
	pid_t pid,
	const coalition_t coalition,
	const char* log_prefix)
{
	const char *reason;
	memorystatus_freeze_skip_reason_t skip_reason;

	switch (freezer_error_code) {
	case FREEZER_ERROR_EXCESS_SHARED_MEMORY:
		memorystatus_freezer_stats.mfs_error_excess_shared_memory_count++;
		reason = "too much shared memory";
		skip_reason = kMemorystatusFreezeSkipReasonExcessSharedMemory;
		break;
	case FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO:
		memorystatus_freezer_stats.mfs_error_low_private_shared_ratio_count++;
		reason = "private-shared pages ratio";
		skip_reason = kMemorystatusFreezeSkipReasonLowPrivateSharedRatio;
		break;
	case FREEZER_ERROR_NO_COMPRESSOR_SPACE:
		memorystatus_freezer_stats.mfs_error_no_compressor_space_count++;
		reason = "no compressor space";
		skip_reason = kMemorystatusFreezeSkipReasonNoCompressorSpace;
		break;
	case FREEZER_ERROR_NO_SWAP_SPACE:
		memorystatus_freezer_stats.mfs_error_no_swap_space_count++;
		reason = "no swap space";
		skip_reason = kMemorystatusFreezeSkipReasonNoSwapSpace;
		break;
	default:
		reason = "unknown error";
		skip_reason = kMemorystatusFreezeSkipReasonOther;
	}

	p->p_memstat_freeze_skip_reason = (uint8_t) skip_reason;

	os_log_with_startup_serial(OS_LOG_DEFAULT, "%s: %sfreezing (%s) pid %d [%s]...skipped (%s)\n",
	    log_prefix, was_refreeze ? "re" : "",
	    (coalition == NULL ? "general" : "coalition-driven"), pid,
	    ((p && *p->p_name) ? p->p_name : "unknown"), reason);
}

/*
 * Start a new normal throttle interval with the given budget.
 * Caller must hold the freezer mutex
 */
static void
memorystatus_freeze_start_normal_throttle_interval(uint32_t new_budget, mach_timespec_t start_ts)
{
	unsigned int band;
	proc_t p, next_p;
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);

	normal_throttle_window->max_pageouts = new_budget;
	normal_throttle_window->ts.tv_sec = normal_throttle_window->mins * 60;
	normal_throttle_window->ts.tv_nsec = 0;
	ADD_MACH_TIMESPEC(&normal_throttle_window->ts, &start_ts);
	/* Since we update the throttle stats pre-freeze, adjust for overshoot here */
	if (normal_throttle_window->pageouts > normal_throttle_window->max_pageouts) {
		normal_throttle_window->pageouts -= normal_throttle_window->max_pageouts;
	} else {
		normal_throttle_window->pageouts = 0;
	}
	/* Ensure the normal window is now active. */
	memorystatus_freeze_degradation = FALSE;

	/*
	 * Reset interval statistics.
	 */
	memorystatus_freezer_stats.mfs_shared_pages_skipped = 0;
	memorystatus_freezer_stats.mfs_process_considered_count = 0;
	memorystatus_freezer_stats.mfs_error_below_min_pages_count = 0;
	memorystatus_freezer_stats.mfs_error_excess_shared_memory_count = 0;
	memorystatus_freezer_stats.mfs_error_low_private_shared_ratio_count = 0;
	memorystatus_freezer_stats.mfs_error_no_compressor_space_count = 0;
	memorystatus_freezer_stats.mfs_error_no_swap_space_count = 0;
	memorystatus_freezer_stats.mfs_error_low_probability_of_use_count = 0;
	memorystatus_freezer_stats.mfs_error_elevated_count = 0;
	memorystatus_freezer_stats.mfs_error_other_count = 0;
	memorystatus_freezer_stats.mfs_refreeze_count = 0;
	memorystatus_freezer_stats.mfs_bytes_refrozen = 0;
	memorystatus_freezer_stats.mfs_below_threshold_count = 0;
	memorystatus_freezer_stats.mfs_skipped_full_count = 0;
	memorystatus_freezer_stats.mfs_skipped_shared_mb_high_count = 0;
	memorystatus_freezer_stats.mfs_budget_exhaustion_duration_remaining = 0;
	memorystatus_thaw_count = 0;
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_thawed, 0, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_thawed_webcontent, 0, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_thawed_fg, 0, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_thawed_fg_xpc_service, 0, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_frozen, memorystatus_frozen_count, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_frozen_webcontent, memorystatus_frozen_count_webcontent, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_frozen_xpc_service, memorystatus_frozen_count_xpc_service, release);
	os_atomic_store(&memorystatus_freezer_stats.mfs_processes_fg_resumed, 0, release);
	os_atomic_inc(&memorystatus_freeze_current_interval, release);

	/* Clear the focal thaw bit */
	proc_list_lock();
	band = JETSAM_PRIORITY_IDLE;
	p = PROC_NULL;
	next_p = PROC_NULL;

	next_p = memorystatus_get_first_proc_locked(&band, TRUE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&band, p, TRUE);

		if (p->p_memstat_effectivepriority > JETSAM_PRIORITY_FOREGROUND) {
			break;
		}
		p->p_memstat_state &= ~P_MEMSTAT_FROZEN_FOCAL_THAW;
	}
	proc_list_unlock();

	schedule_interval_reset(freeze_interval_reset_thread_call, normal_throttle_window);
}

#if DEVELOPMENT || DEBUG

static int
sysctl_memorystatus_freeze_calculate_new_budget SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error = 0;
	unsigned int time_since_last_interval_expired_sec = 0;
	unsigned int new_budget;

	error = sysctl_handle_int(oidp, &time_since_last_interval_expired_sec, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return ENOTSUP;
	}
	new_budget = memorystatus_freeze_calculate_new_budget(time_since_last_interval_expired_sec, 1, NORMAL_WINDOW_MINS, 0);
	return copyout(&new_budget, req->oldptr, MIN(sizeof(req->oldlen), sizeof(new_budget)));
}

SYSCTL_PROC(_vm, OID_AUTO, memorystatus_freeze_calculate_new_budget, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_freeze_calculate_new_budget, "I", "");

#endif /* DEVELOPMENT || DEBUG */

/*
 * Called when we first run out of budget in an interval.
 * Marks idle processes as not frozen due to lack of budget.
 * NB: It might be worth having a CA event here.
 */
static void
memorystatus_freeze_out_of_budget(const struct throttle_interval_t *interval)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);

	mach_timespec_t time_left = {0, 0};
	mach_timespec_t now_ts;
	clock_sec_t sec;
	clock_nsec_t nsec;

	time_left.tv_sec = interval->ts.tv_sec;
	time_left.tv_nsec = 0;
	clock_get_system_nanotime(&sec, &nsec);
	now_ts.tv_sec = (unsigned int)(MIN(sec, UINT32_MAX));
	now_ts.tv_nsec = nsec;

	SUB_MACH_TIMESPEC(&time_left, &now_ts);
	memorystatus_freezer_stats.mfs_budget_exhaustion_duration_remaining = time_left.tv_sec;
	os_log(OS_LOG_DEFAULT,
	    "memorystatus_freeze: Out of NAND write budget with %u minutes left in the current freezer interval. %u procs are frozen.\n",
	    time_left.tv_sec / 60, memorystatus_frozen_count);

	memorystatus_freeze_mark_eligible_processes_with_skip_reason(kMemorystatusFreezeSkipReasonOutOfBudget, false);
}

/*
 * Called when we cross over the threshold of maximum frozen processes allowed.
 * Marks remaining idle processes as not frozen due to lack of slots.
 */
static void
memorystatus_freeze_out_of_slots(void)
{
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	assert(memorystatus_frozen_count == memorystatus_frozen_processes_max);

	os_log(OS_LOG_DEFAULT,
	    "memorystatus_freeze: Out of slots in the freezer. %u procs are frozen.\n",
	    memorystatus_frozen_count);

	memorystatus_freeze_mark_eligible_processes_with_skip_reason(kMemorystatusFreezeSkipReasonOutOfSlots, true);
}

/*
 * This function will do 4 things:
 *
 * 1) check to see if we are currently in a degraded freezer mode, and if so:
 *    - check to see if our window has expired and we should exit this mode, OR,
 *    - return a budget based on the degraded throttle window's max. pageouts vs current pageouts.
 *
 * 2) check to see if we are in a NEW normal window and update the normal throttle window's params.
 *
 * 3) check what the current normal window allows for a budget.
 *
 * 4) calculate the current rate of pageouts for DEGRADED_WINDOW_MINS duration. If that rate is below
 *    what we would normally expect, then we are running low on our daily budget and need to enter
 *    degraded perf. mode.
 *
 *    Caller must hold the freezer mutex
 *    Caller must not hold the proc_list lock
 */

static void
memorystatus_freeze_update_throttle(uint64_t *budget_pages_allowed)
{
	clock_sec_t sec;
	clock_nsec_t nsec;
	mach_timespec_t now_ts;
	LCK_MTX_ASSERT(&freezer_mutex, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);

	unsigned int freeze_daily_pageouts_max = 0;
	bool started_with_budget = (*budget_pages_allowed > 0);

#if DEVELOPMENT || DEBUG
	if (!memorystatus_freeze_throttle_enabled) {
		/*
		 * No throttling...we can use the full budget everytime.
		 */
		*budget_pages_allowed = UINT64_MAX;
		return;
	}
#endif

	clock_get_system_nanotime(&sec, &nsec);
	now_ts.tv_sec = (unsigned int)(MIN(sec, UINT32_MAX));
	now_ts.tv_nsec = nsec;

	struct throttle_interval_t *interval = NULL;

	if (memorystatus_freeze_degradation == TRUE) {
		interval = degraded_throttle_window;

		if (CMP_MACH_TIMESPEC(&now_ts, &interval->ts) >= 0) {
			interval->pageouts = 0;
			interval->max_pageouts = 0;
		} else {
			*budget_pages_allowed = interval->max_pageouts - interval->pageouts;
		}
	}

	interval = normal_throttle_window;

	/*
	 * Current throttle window.
	 * Deny freezing if we have no budget left.
	 * Try graceful degradation if we are within 25% of:
	 * - the daily budget, and
	 * - the current budget left is below our normal budget expectations.
	 */

	if (memorystatus_freeze_degradation == FALSE) {
		if (interval->pageouts >= interval->max_pageouts) {
			*budget_pages_allowed = 0;
			if (started_with_budget) {
				memorystatus_freeze_out_of_budget(interval);
			}
		} else {
			int budget_left = interval->max_pageouts - interval->pageouts;
			int budget_threshold = (freeze_daily_pageouts_max * FREEZE_DEGRADATION_BUDGET_THRESHOLD) / 100;

			mach_timespec_t time_left = {0, 0};

			time_left.tv_sec = interval->ts.tv_sec;
			time_left.tv_nsec = 0;

			SUB_MACH_TIMESPEC(&time_left, &now_ts);

			if (budget_left <= budget_threshold) {
				/*
				 * For the current normal window, calculate how much we would pageout in a DEGRADED_WINDOW_MINS duration.
				 * And also calculate what we would pageout for the same DEGRADED_WINDOW_MINS duration if we had the full
				 * daily pageout budget.
				 */

				unsigned int current_budget_rate_allowed = ((budget_left / time_left.tv_sec) / 60) * DEGRADED_WINDOW_MINS;
				unsigned int normal_budget_rate_allowed = (freeze_daily_pageouts_max / NORMAL_WINDOW_MINS) * DEGRADED_WINDOW_MINS;

				/*
				 * The current rate of pageouts is below what we would expect for
				 * the normal rate i.e. we have below normal budget left and so...
				 */

				if (current_budget_rate_allowed < normal_budget_rate_allowed) {
					memorystatus_freeze_degradation = TRUE;
					degraded_throttle_window->max_pageouts = current_budget_rate_allowed;
					degraded_throttle_window->pageouts = 0;

					/*
					 * Switch over to the degraded throttle window so the budget
					 * doled out is based on that window.
					 */
					interval = degraded_throttle_window;
				}
			}

			*budget_pages_allowed = interval->max_pageouts - interval->pageouts;
		}
	}

	MEMORYSTATUS_DEBUG(1, "memorystatus_freeze_update_throttle_interval: throttle updated - %d frozen (%d max) within %dm; %dm remaining; throttle %s\n",
	    interval->pageouts, interval->max_pageouts, interval->mins, (interval->ts.tv_sec - now_ts->tv_sec) / 60,
	    interval->throttle ? "on" : "off");
}

bool memorystatus_freeze_thread_init = false;
static void
memorystatus_freeze_thread(void *param __unused, wait_result_t wr __unused)
{
	static boolean_t memorystatus_freeze_swap_low = FALSE;

	if (!memorystatus_freeze_thread_init) {
#if CONFIG_THREAD_GROUPS
		thread_group_vm_add();
#endif
		memorystatus_freeze_thread_init = true;
	}

	lck_mtx_lock(&freezer_mutex);

	if (memorystatus_freeze_enabled) {
		if (memorystatus_freezer_use_demotion_list && memorystatus_refreeze_eligible_count > 0) {
			memorystatus_demote_frozen_processes(false); /* Normal mode. Consider demoting thawed processes. */
		}
		if ((memorystatus_frozen_count < memorystatus_frozen_processes_max) ||
		    (memorystatus_refreeze_eligible_count >= MIN_THAW_REFREEZE_THRESHOLD)) {
			if (memorystatus_can_freeze(&memorystatus_freeze_swap_low)) {
				/* Only freeze if we've not exceeded our pageout budgets.*/
				memorystatus_freeze_update_throttle(&memorystatus_freeze_budget_pages_remaining);

				if (memorystatus_freeze_budget_pages_remaining) {
					memorystatus_freeze_top_process();
				} else {
					memorystatus_demote_frozen_processes(true); /* urgent mode..force one demotion */
				}
			}
		}
	}

	/*
	 * Give applications currently in the aging band a chance to age out into the idle band before
	 * running the freezer again.
	 */
	memorystatus_freezer_thread_next_run_ts = mach_absolute_time() + memorystatus_apps_idle_delay_time;

	assert_wait((event_t) &memorystatus_freeze_wakeup, THREAD_UNINT);
	lck_mtx_unlock(&freezer_mutex);

	thread_block((thread_continue_t) memorystatus_freeze_thread);
}

boolean_t
memorystatus_freeze_thread_should_run(void)
{
	/*
	 * No freezer_mutex held here...see why near call-site
	 * within memorystatus_pages_update().
	 */

	boolean_t should_run = FALSE;

	if (memorystatus_freeze_enabled == FALSE) {
		goto out;
	}

	if (memorystatus_available_pages > memorystatus_freeze_threshold) {
		goto out;
	}

	memorystatus_freezer_stats.mfs_below_threshold_count++;

	if ((memorystatus_frozen_count >= memorystatus_frozen_processes_max)) {
		/*
		 * Consider this as a skip even if we wake up to refreeze because
		 * we won't freeze any new procs.
		 */
		memorystatus_freezer_stats.mfs_skipped_full_count++;
		if (memorystatus_refreeze_eligible_count < MIN_THAW_REFREEZE_THRESHOLD) {
			goto out;
		}
	}

	if (memorystatus_frozen_shared_mb_max && (memorystatus_frozen_shared_mb >= memorystatus_frozen_shared_mb_max)) {
		memorystatus_freezer_stats.mfs_skipped_shared_mb_high_count++;
		goto out;
	}

	uint64_t curr_time = mach_absolute_time();

	if (curr_time < memorystatus_freezer_thread_next_run_ts) {
		goto out;
	}

	should_run = TRUE;

out:
	return should_run;
}

int
memorystatus_get_process_is_freezable(pid_t pid, int *is_freezable)
{
	proc_t p = PROC_NULL;

	if (pid == 0) {
		return EINVAL;
	}

	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Only allow this on the current proc for now.
	 * We can check for privileges and allow targeting another process in the future.
	 */
	if (p != current_proc()) {
		proc_rele(p);
		return EPERM;
	}

	proc_list_lock();
	*is_freezable = ((p->p_memstat_state & P_MEMSTAT_FREEZE_DISABLED) ? 0 : 1);
	proc_rele(p);
	proc_list_unlock();

	return 0;
}

errno_t
memorystatus_get_process_is_frozen(pid_t pid, int *is_frozen)
{
	proc_t p = PROC_NULL;

	if (pid == 0) {
		return EINVAL;
	}

	/*
	 * Only allow this on the current proc for now.
	 * We can check for privileges and allow targeting another process in the future.
	 */
	p = current_proc();
	if (proc_getpid(p) != pid) {
		return EPERM;
	}

	proc_list_lock();
	*is_frozen = (p->p_memstat_state & P_MEMSTAT_FROZEN) != 0;
	proc_list_unlock();

	return 0;
}

int
memorystatus_set_process_is_freezable(pid_t pid, boolean_t is_freezable)
{
	proc_t p = PROC_NULL;

	if (pid == 0) {
		return EINVAL;
	}

	/*
	 * To enable freezable status, you need to be root or an entitlement.
	 */
	if (is_freezable &&
	    !kauth_cred_issuser(kauth_cred_get()) &&
	    !IOCurrentTaskHasEntitlement(MEMORYSTATUS_ENTITLEMENT)) {
		return EPERM;
	}

	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * A process can change its own status. A coalition leader can
	 * change the status of coalition members.
	 */
	if (p != current_proc()) {
		coalition_t coal = task_get_coalition(proc_task(p), COALITION_TYPE_JETSAM);
		if (!coalition_is_leader(proc_task(current_proc()), coal)) {
			proc_rele(p);
			return EPERM;
		}
	}

	proc_list_lock();
	if (is_freezable == FALSE) {
		/* Freeze preference set to FALSE. Set the P_MEMSTAT_FREEZE_DISABLED bit. */
		p->p_memstat_state |= P_MEMSTAT_FREEZE_DISABLED;
		printf("memorystatus_set_process_is_freezable: disabling freeze for pid %d [%s]\n",
		    proc_getpid(p), (*p->p_name ? p->p_name : "unknown"));
	} else {
		p->p_memstat_state &= ~P_MEMSTAT_FREEZE_DISABLED;
		printf("memorystatus_set_process_is_freezable: enabling freeze for pid %d [%s]\n",
		    proc_getpid(p), (*p->p_name ? p->p_name : "unknown"));
	}
	proc_rele(p);
	proc_list_unlock();

	return 0;
}

/*
 * Called when process is created before it is added to a memorystatus bucket.
 */
void
memorystatus_freeze_init_proc(proc_t p)
{
	/* NB: Process is not on the memorystatus lists yet so it's safe to modify the skip reason without the freezer mutex. */
	if (memorystatus_freeze_budget_pages_remaining == 0) {
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonOutOfBudget;
	} else if ((memorystatus_frozen_count >= memorystatus_frozen_processes_max)) {
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonOutOfSlots;
	} else {
		p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
	}
}


static int
sysctl_memorystatus_do_fastwake_warmup_all  SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	if (!req->newptr) {
		return EINVAL;
	}

	/* Need to be root or have entitlement */
	if (!kauth_cred_issuser(kauth_cred_get()) && !IOCurrentTaskHasEntitlement( MEMORYSTATUS_ENTITLEMENT)) {
		return EPERM;
	}

	if (memorystatus_freeze_enabled == FALSE) {
		return ENOTSUP;
	}

	if (!VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
		return ENOTSUP;
	}

	do_fastwake_warmup_all();

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_do_fastwake_warmup_all, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_do_fastwake_warmup_all, "I", "");

/*
 * Takes in a candidate list from the user_addr, validates it, and copies it into the list pointer.
 * Takes ownership over the original value of list.
 * Assumes that list is protected by the freezer_mutex.
 * The caller should not hold any locks.
 */
static errno_t
set_freezer_candidate_list(user_addr_t buffer, size_t buffer_size, struct memorystatus_freezer_candidate_list *list)
{
	errno_t error = 0;
	memorystatus_properties_freeze_entry_v1 *entries = NULL, *tmp_entries = NULL;
	size_t entry_count = 0, entries_size = 0, tmp_size = 0;

	/* Validate the user provided list. */
	if ((buffer == USER_ADDR_NULL) || (buffer_size == 0)) {
		os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus_cmd_grp_set_freeze_priority: NULL or empty list\n");
		return EINVAL;
	}

	if (buffer_size % sizeof(memorystatus_properties_freeze_entry_v1) != 0) {
		os_log_with_startup_serial(OS_LOG_DEFAULT,
		    "memorystatus_cmd_grp_set_freeze_priority: Invalid list length (caller might have comiled agsinst invalid headers.)\n");
		return EINVAL;
	}

	entry_count = buffer_size / sizeof(memorystatus_properties_freeze_entry_v1);
	entries_size = buffer_size;
	entries = kalloc_data(buffer_size, Z_WAITOK | Z_ZERO);
	if (entries == NULL) {
		return ENOMEM;
	}

	error = copyin(buffer, entries, buffer_size);
	if (error != 0) {
		goto out;
	}

#if MACH_ASSERT
	for (size_t i = 0; i < entry_count; i++) {
		memorystatus_properties_freeze_entry_v1 *entry = &entries[i];
		if (entry->version != 1) {
			os_log(OS_LOG_DEFAULT, "memorystatus_cmd_grp_set_freeze_priority: Invalid entry version number.");
			error = EINVAL;
			goto out;
		}
		if (i > 0 && entry->priority >= entries[i - 1].priority) {
			os_log(OS_LOG_DEFAULT, "memorystatus_cmd_grp_set_freeze_priority: Entry list is not in descending order.");
			error = EINVAL;
			goto out;
		}
	}
#endif /* MACH_ASSERT */

	lck_mtx_lock(&freezer_mutex);

	tmp_entries = list->mfcl_list;
	tmp_size = list->mfcl_length * sizeof(memorystatus_properties_freeze_entry_v1);
	list->mfcl_list = entries;
	list->mfcl_length = entry_count;

	lck_mtx_unlock(&freezer_mutex);

	entries = tmp_entries;
	entries_size = tmp_size;

out:
	kfree_data(entries, entries_size);
	return error;
}

errno_t
memorystatus_cmd_grp_set_freeze_list(user_addr_t buffer, size_t buffer_size)
{
	return set_freezer_candidate_list(buffer, buffer_size, &memorystatus_global_freeze_list);
}

errno_t
memorystatus_cmd_grp_set_demote_list(user_addr_t buffer, size_t buffer_size)
{
	return set_freezer_candidate_list(buffer, buffer_size, &memorystatus_global_demote_list);
}

void
memorystatus_freezer_mark_ui_transition(proc_t p)
{
	bool frozen = false, previous_focal_thaw = false, xpc_service = false, suspended = false;
	proc_list_lock();

	if (isSysProc(p)) {
		goto out;
	}

	frozen = (p->p_memstat_state & P_MEMSTAT_FROZEN) != 0;
	previous_focal_thaw = (p->p_memstat_state & P_MEMSTAT_FROZEN_FOCAL_THAW) != 0;
	xpc_service = (p->p_memstat_state & P_MEMSTAT_FROZEN_XPC_SERVICE) != 0;
	suspended = (p->p_memstat_state & P_MEMSTAT_SUSPENDED) != 0;
	if (!suspended) {
		if (frozen) {
			if (!previous_focal_thaw) {
				p->p_memstat_state |= P_MEMSTAT_FROZEN_FOCAL_THAW;
				os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_thawed_fg), relaxed);
				if (xpc_service) {
					os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_thawed_fg_xpc_service), relaxed);
				}
			}
		}
		os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_fg_resumed), relaxed);
	}

out:
	proc_list_unlock();
}

#endif /* CONFIG_FREEZE */
