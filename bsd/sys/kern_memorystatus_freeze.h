/*
 * Copyright (c) 2006-2018 Apple Computer, Inc. All rights reserved.
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

#ifndef SYS_MEMORYSTATUS_FREEZE_H
#define SYS_MEMORYSTATUS_FREEZE_H

#include <stdint.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/param.h>
#include <sys/kern_memorystatus.h>
#include <mach/resource_monitors.h>     // command/proc_name_t
#include <uuid/uuid.h>

typedef struct memorystatus_freeze_entry {
	int32_t pid;
	uint32_t flags;
	uint32_t pages;
} memorystatus_freeze_entry_t;

#ifdef PRIVATE
#define FREEZE_PROCESSES_MAX 20
#define FREEZE_PROCESSES_MAX_SWAP_ENABLED 36
#endif /* PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

extern unsigned long freeze_threshold_percentage;
extern unsigned int memorystatus_frozen_count; /* # of processes that are currently frozen. */
extern unsigned int memorystatus_frozen_count_webcontent; /* # of webcontent processes that are currently frozen. */
extern unsigned int memorystatus_frozen_count_xpc_service; /* # of xpc services that are currently frozen. */
extern unsigned int memorystatus_frozen_processes_max;
extern unsigned int memorystatus_frozen_shared_mb;
extern unsigned int memorystatus_frozen_shared_mb_max;
extern unsigned int memorystatus_freeze_shared_mb_per_process_max; /* Max. MB allowed per process to be freezer-eligible. */
extern unsigned int memorystatus_freeze_private_shared_pages_ratio; /* Ratio of private:shared pages for a process to be freezer-eligible. */
extern unsigned int memorystatus_suspended_count;
extern unsigned int memorystatus_thaw_count; /* # of processes that have been thawed in the current interval. */
extern unsigned int memorystatus_refreeze_eligible_count; /* # of processes currently thawed i.e. have state on disk & in-memory */
extern unsigned int memorystatus_freeze_max_candidate_band;
extern uint32_t memorystatus_freeze_current_interval; /* Monotonically increasing interval id. */

void memorystatus_freeze_init(void);
extern int  memorystatus_freeze_process_sync(proc_t p);

#ifdef CONFIG_FREEZE
extern int memorystatus_entitled_max_task_footprint_mb;

#define FREEZE_PAGES_MIN   ( 8 * 1024 * 1024 / PAGE_SIZE)
#define FREEZE_PAGES_MAX   (max_task_footprint_mb == 0 ? INT_MAX : (max_task_footprint_mb << (20 - PAGE_SHIFT)))
#define FREEZE_PAGES_MAX_SWAP_ENABLED \
    (memorystatus_entitled_max_task_footprint_mb == 0 ? INT_MAX : (memorystatus_entitled_max_task_footprint_mb << (20 - PAGE_SHIFT)))

#define FREEZE_SUSPENDED_THRESHOLD_DEFAULT 4

#define FREEZE_DAILY_MB_MAX_DEFAULT       1024
#define FREEZE_DEGRADATION_BUDGET_THRESHOLD     25 //degraded perf. when the daily budget left falls below this threshold percentage

#define MAX_FROZEN_SHARED_MB_PERCENT 10
#define MAX_FROZEN_PROCESS_DEMOTIONS 2
#define MAX_FROZEN_PROCESS_DEMOTIONS_SWAP_ENABLED 4
#define MIN_THAW_DEMOTION_THRESHOLD  5
#define MIN_THAW_REFREEZE_THRESHOLD  3
#define FREEZE_MAX_CANDIDATE_BAND JETSAM_PRIORITY_AGING_BAND2

typedef struct throttle_interval_t {
	uint32_t mins;
	uint32_t burst_multiple;
	uint32_t pageouts;
	uint32_t max_pageouts;
	mach_timespec_t ts;
} throttle_interval_t;

extern boolean_t memorystatus_freeze_enabled;
extern int memorystatus_freeze_wakeup;

/* Thresholds */
extern unsigned int memorystatus_freeze_threshold;
extern unsigned int memorystatus_freeze_pages_min;
extern unsigned int memorystatus_freeze_pages_max;
extern unsigned int memorystatus_freeze_suspended_threshold;
extern unsigned int memorystatus_freeze_daily_mb_max;
extern uint64_t     memorystatus_freeze_budget_pages_remaining; //remaining # of pages that can be frozen to disk
extern boolean_t memorystatus_freeze_degradation; //protected by the freezer mutex. Signals we are in a degraded freeze mode.

extern unsigned int memorystatus_max_frozen_demotions_daily;
extern unsigned int memorystatus_thaw_count_demotion_threshold;
extern unsigned int memorystatus_min_thaw_refreeze_threshold;

#if DEVELOPMENT || DEBUG
#define FREEZER_CONTROL_GET_STATUS      (1)
#endif /* DEVELOPMENT || DEBUG */

extern boolean_t memorystatus_freeze_enabled;
extern int memorystatus_freeze_wakeup;
extern int memorystatus_freeze_jetsam_band; /* the jetsam band which will contain P_MEMSTAT_FROZEN processes */

bool memorystatus_freeze_thread_should_run(void);
int memorystatus_set_process_is_freezable(pid_t pid, boolean_t is_freezable);
int memorystatus_get_process_is_freezable(pid_t pid, int *is_freezable);
int memorystatus_freezer_control(int32_t flags, user_addr_t buffer, size_t buffer_size, int32_t *retval);
void memorystatus_freeze_init_proc(proc_t p);
errno_t memorystatus_get_process_is_frozen(pid_t pid, int *is_freezable);
errno_t memorystatus_cmd_grp_set_freeze_list(user_addr_t buffer, size_t buffer_size);
errno_t memorystatus_cmd_grp_set_demote_list(user_addr_t buffer, size_t buffer_size);

/* Freezer counters collected for telemtry */
struct memorystatus_freezer_stats_t {
	/*
	 * # of processes that we've considered freezing.
	 * Used to normalize the error reasons below.
	 */
	uint64_t mfs_process_considered_count;

	/*
	 * The following counters track how many times we've failed to freeze
	 * a process because of a specific FREEZER_ERROR.
	 */
	/* EXCESS_SHARED_MEMORY */
	uint64_t mfs_error_excess_shared_memory_count;
	/* LOW_PRIVATE_SHARED_RATIO */
	uint64_t mfs_error_low_private_shared_ratio_count;
	/* NO_COMPRESSOR_SPACE */
	uint64_t mfs_error_no_compressor_space_count;
	/* NO_SWAP_SPACE */
	uint64_t mfs_error_no_swap_space_count;
	/* pages < memorystatus_freeze_pages_min */
	uint64_t mfs_error_below_min_pages_count;
	/* dasd determined it was unlikely to be relaunched. */
	uint64_t mfs_error_low_probability_of_use_count;
	/* not in idle bands */
	uint64_t mfs_error_elevated_count;
	/* transient reasons (like inability to acquire a lock). */
	uint64_t mfs_error_other_count;

	/*
	 * # of times that we saw memorystatus_available_pages <= memorystatus_freeze_threshold.
	 * Used to normalize skipped_full_count and shared_mb_high_count.
	 */
	uint64_t mfs_below_threshold_count;

	/* Skipped running the freezer because we were out of slots */
	uint64_t mfs_skipped_full_count;

	/* Skipped running the freezer because we were over the shared mb limit*/
	uint64_t mfs_skipped_shared_mb_high_count;

	/*
	 * How many pages have not been sent to swap because they were in a shared object?
	 * This is being used to gather telemtry so we can understand the impact we'd have
	 * on our NAND budget if we did swap out these pages.
	 */
	uint64_t mfs_shared_pages_skipped;

	/*
	 * A running sum of the total number of bytes sent to NAND during
	 * refreeze operations since boot.
	 */
	uint64_t mfs_bytes_refrozen;
	/* The number of refreeze operations since boot */
	uint64_t mfs_refreeze_count;

	/* The number of proceses which have been frozen at least once in the current interval. */
	uint64_t mfs_processes_frozen;
	/* The number of processes which have been thawed at least once in the current interval. */
	uint64_t mfs_processes_thawed;

	/*
	 * Telemetry shows that the majority of freezer usage is attributed to webcontent
	 * so we track some specific webcontent telemetry here to get more visibility.
	 */

	/* The number of webcontent processes which have been frozen at least once in the current interval. */
	uint64_t mfs_processes_frozen_webcontent;
	/* The number of webcontent processes which have been thawed at least once in the current interval. */
	uint64_t mfs_processes_thawed_webcontent;

	/* The number of xpc service processes which have been frozen at least once in the current interval. */
	uint64_t mfs_processes_frozen_xpc_service;

	/* The number of fg thaws in the current interval. */
	uint64_t mfs_processes_thawed_fg;
	/* The number of fg xpc service thaws in the current interval. */
	uint64_t mfs_processes_thawed_fg_xpc_service;

	/*
	 * Counts the number of incorrect pids provided via
	 * MEMORYSTATUS_FLAGS_GRP_SET_FREEZE_PRIORITY in the current interval.
	 * A high value means dasd should be updating the list more
	 * frequently.
	 */
	uint64_t mfs_freeze_pid_mismatches;
	/*
	 * Counts the number of incorrect pids provided via
	 * MEMORYSTATUS_FLAGS_GRP_SET_DEMOTE_PRIORITY in the current interval.
	 * A high value means dasd should be updating the list more
	 * frequently.
	 */
	uint64_t mfs_demote_pid_mismatches;

	/*
	 * When we run out of budget, this records how much time is left in the current
	 * interval. 0 means we have not run out of budget.
	 */
	uint64_t mfs_budget_exhaustion_duration_remaining;

	/* The number of visible resumes in this interval. Mostly used to filter out idle devices. */
	uint64_t mfs_processes_fg_resumed;
};
extern struct memorystatus_freezer_stats_t memorystatus_freezer_stats;

/*
 * Called by kern_resource when a process gets a UI priority
 */
void memorystatus_freezer_mark_ui_transition(proc_t p);

#endif /* CONFIG_FREEZE */

#endif /* XNU_KERNEL_PRIVATE */

#ifdef PRIVATE
/* Lists all the processes that are currently in the freezer. */
#define FREEZER_CONTROL_GET_PROCS        (2)

#define FREEZER_CONTROL_GET_PROCS_MAX_COUNT (FREEZE_PROCESSES_MAX * 2)

typedef struct _global_frozen_procs {
	size_t gfp_num_frozen;
	struct {
		pid_t fp_pid;
		proc_name_t fp_name;
	} gfp_procs[FREEZER_CONTROL_GET_PROCS_MAX_COUNT];
} global_frozen_procs_t;

/* Set the dasd trial identifiers */
#define FREEZER_CONTROL_SET_DASD_TRIAL_IDENTIFIERS (3)

typedef struct _memorystatus_freezer_trial_identifiers_v1 {
	int version; /* Must be set to 1 */
	uuid_string_t treatment_id;
	uuid_string_t experiment_id;
	int deployment_id;
} memorystatus_freezer_trial_identifiers_v1;

/*
 * Destructively reset the freezer state in order to perform a policy change.
 * Note that this could result in multiple suspended apps getting killed,
 * so it should only be used when the device is idle.
 */
#define FREEZER_CONTROL_RESET_STATE (4)

#endif /* PRIVATE */

#endif /* SYS_MEMORYSTATUS_FREEZE_H */
