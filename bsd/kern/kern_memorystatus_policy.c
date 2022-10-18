/*
 * Copyright (c) 2006-2021 Apple Inc. All rights reserved.
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

#include <kern/task.h>
#include <libkern/libkern.h>
#include <machine/atomic.h>
#include <mach/coalition.h>
#include <os/log.h>
#include <sys/coalition.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kdebug.h>
#include <sys/kern_memorystatus.h>
#include <vm/vm_protos.h>

#include "kern_memorystatus_internal.h"

/*
 * All memory pressure policy decisions should live here, and there should be
 * as little mechanism as possible. This file prioritizes readability.
 */

#pragma mark Policy Function Declarations

#if CONFIG_JETSAM
static bool memorystatus_check_aggressive_jetsam_needed(int *jld_idle_kills);
#endif /* CONFIG_JETSAM */

#pragma mark Memorystatus Health Check

/*
 * Each subsystem that relies on the memorystatus thread
 * for resource exhaustion should put a health check in this section.
 * The memorystatus thread runs all of the health checks
 * to determine if the system is healthy. If the system is unhealthy
 * it picks an action based on the system health status. See the
 * Memorystatus Thread Actions section below.
 */

extern bool vm_compressor_needs_to_swap(bool wake_memorystatus_thread);
extern boolean_t vm_compressor_low_on_space(void);
extern bool vm_compressor_compressed_pages_nearing_limit(void);
extern bool vm_compressor_is_thrashing(void);
extern bool vm_compressor_swapout_is_ripe(void);

static void
memorystatus_health_check(memorystatus_system_health_t *status)
{
	memset(status, 0, sizeof(memorystatus_system_health_t));
#if CONFIG_JETSAM
	status->msh_available_pages_below_pressure = memorystatus_avail_pages_below_pressure();
	status->msh_available_pages_below_critical = memorystatus_avail_pages_below_critical();
	status->msh_compressor_is_low_on_space = (vm_compressor_low_on_space() == TRUE);
	status->msh_compressed_pages_nearing_limit = vm_compressor_compressed_pages_nearing_limit();
	status->msh_swapout_is_ripe = vm_compressor_swapout_is_ripe();
	if (!status->msh_swapout_is_ripe) {
		status->msh_compressor_is_thrashing = !memorystatus_swap_all_apps && vm_compressor_is_thrashing();
#if CONFIG_PHANTOM_CACHE
		status->msh_phantom_cache_pressure = os_atomic_load(&memorystatus_phantom_cache_pressure, acquire);
#else
		status->msh_phantom_cache_pressure = false;
#endif /* CONFIG_PHANTOM_CACHE */
	} else {
		status->msh_compressor_is_thrashing = false;
		status->msh_phantom_cache_pressure = false;
	}
	if (!memorystatus_swap_all_apps &&
	    (status->msh_swapout_is_ripe || status->msh_phantom_cache_pressure) &&
	    !(status->msh_compressor_is_thrashing && status->msh_compressor_is_low_on_space)) {
		status->msh_filecache_is_thrashing = true;
	}
	if (os_atomic_load(&memorystatus_compressor_space_shortage, relaxed)) {
		status->msh_compressor_is_low_on_space = true;
	}
	status->msh_swappable_compressor_segments_over_limit = memorystatus_swap_over_trigger(100);
	status->msh_swapin_queue_over_limit = memorystatus_swapin_over_trigger();
	status->msh_swap_low_on_space = vm_swap_low_on_space();
	status->msh_swap_out_of_space = vm_swap_out_of_space();
#endif /* CONFIG_JETSAM */
	status->msh_zone_map_is_exhausted = os_atomic_load(&memorystatus_zone_map_is_exhausted, relaxed);
}

bool
memorystatus_is_system_healthy(const memorystatus_system_health_t *status)
{
#if CONFIG_JETSAM
	return !(status->msh_available_pages_below_critical
	       || status->msh_compressor_is_low_on_space
	       || status->msh_compressor_is_thrashing
	       || status->msh_filecache_is_thrashing
	       || status->msh_zone_map_is_exhausted);
#else /* CONFIG_JETSAM */
	return !status->msh_zone_map_is_exhausted;
#endif /* CONFIG_JETSAM */
}


#pragma mark Memorystatus Thread Actions

/*
 * This section picks the appropriate memorystatus_action & deploys it.
 */

/*
 * Inspects the state of various resources in the system to see if
 * the system is healthy. If the system is not healthy, picks a
 * memorystatus_action_t to recover the system.
 *
 * Every time the memorystatus thread wakes up it calls into here
 * to pick an action. It will continue performing memorystatus actions until this
 * function returns MEMORYSTATUS_KILL_NONE. At that point the thread will block.
 */
memorystatus_action_t
memorystatus_pick_action(struct jetsam_thread_state *jetsam_thread,
    uint32_t *kill_cause,
    bool highwater_remaining,
    bool suspended_swappable_apps_remaining,
    bool swappable_apps_remaining,
    int *jld_idle_kills)
{
	memorystatus_system_health_t status;
	memorystatus_health_check(&status);
	memorystatus_log_system_health(&status);
	bool is_system_healthy = memorystatus_is_system_healthy(&status);

#if CONFIG_JETSAM
	if (status.msh_available_pages_below_pressure || !is_system_healthy) {
		/*
		 * If swap is enabled, first check if we're running low or are out of swap space.
		 */
		if (memorystatus_swap_all_apps && jetsam_kill_on_low_swap) {
			if (swappable_apps_remaining && status.msh_swap_out_of_space) {
				*kill_cause = kMemorystatusKilledLowSwap;
				return MEMORYSTATUS_KILL_SWAPPABLE;
			} else if (suspended_swappable_apps_remaining && status.msh_swap_low_on_space) {
				*kill_cause = kMemorystatusKilledLowSwap;
				return MEMORYSTATUS_KILL_SUSPENDED_SWAPPABLE;
			}
		}

		/*
		 * We're below the pressure level or the system is unhealthy,
		 * regardless of the system health let's check if we should be swapping
		 * and if there are high watermark kills left to do.
		 */
		if (memorystatus_swap_all_apps) {
			if (status.msh_swappable_compressor_segments_over_limit && !vm_swapout_thread_running && !os_atomic_load(&vm_swapout_wake_pending, relaxed)) {
				/*
				 * TODO: The swapper will keep running until it has drained the entire early swapout queue.
				 * That might be overly aggressive & we should look into tuning it.
				 * See rdar://84102304.
				 */
				return MEMORYSTATUS_WAKE_SWAPPER;
			} else if (status.msh_swapin_queue_over_limit) {
				return MEMORYSTATUS_PROCESS_SWAPIN_QUEUE;
			} else if (status.msh_swappable_compressor_segments_over_limit) {
				os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Skipping swap wakeup because the swap thread is already running. vm_swapout_thread_running=%d, vm_swapout_wake_pending=%d\n", vm_swapout_thread_running, os_atomic_load(&vm_swapout_wake_pending, relaxed));
			}
		}

		if (highwater_remaining) {
			*kill_cause = kMemorystatusKilledHiwat;
			os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Looking for highwatermark kills.\n");
			return MEMORYSTATUS_KILL_HIWATER;
		}
	}

	if (is_system_healthy) {
		*kill_cause = 0;
		return MEMORYSTATUS_KILL_NONE;
	}

	/*
	 * At this point the system is unhealthy and there are no
	 * more highwatermark processes to kill.
	 */

	if (!jetsam_thread->limit_to_low_bands) {
		if (memorystatus_check_aggressive_jetsam_needed(jld_idle_kills)) {
			os_log_with_startup_serial(OS_LOG_DEFAULT, "memorystatus: Starting aggressive jetsam.\n");
			*kill_cause = kMemorystatusKilledProcThrashing;
			return MEMORYSTATUS_KILL_AGGRESSIVE;
		}
	}
	/*
	 * The system is unhealthy and we either don't need aggressive jetsam
	 * or are not allowed to deploy it.
	 * Kill in priority order. We'll use LRU within every band except the
	 * FG (which will be sorted by coalition role).
	 */
	*kill_cause = memorystatus_pick_kill_cause(&status);
	return MEMORYSTATUS_KILL_TOP_PROCESS;
#else /* CONFIG_JETSAM */
	(void) jetsam_thread;
	(void) jld_idle_kills;
	(void) suspended_swappable_apps_remaining;
	(void) swappable_apps_remaining;
	/*
	 * Without CONFIG_JETSAM, we only kill if the system is unhealthy.
	 * There is no aggressive jetsam and no
	 * early highwatermark killing.
	 */
	if (is_system_healthy) {
		*kill_cause = 0;
		return MEMORYSTATUS_KILL_NONE;
	}
	if (highwater_remaining) {
		*kill_cause = kMemorystatusKilledHiwat;
		return MEMORYSTATUS_KILL_HIWATER;
	} else {
		*kill_cause = memorystatus_pick_kill_cause(&status);
		return MEMORYSTATUS_KILL_TOP_PROCESS;
	}
#endif /* CONFIG_JETSAM */
}

#pragma mark Aggressive Jetsam
/*
 * This section defines when we deploy aggressive jetsam.
 * Aggressive jetsam kills everything up to the jld_priority_band_max band.
 */

#if CONFIG_JETSAM

static bool
memorystatus_aggressive_jetsam_needed_sysproc_aging(__unused int jld_eval_aggressive_count, __unused int *jld_idle_kills, __unused int jld_idle_kill_candidates, int *total_candidates);

/*
 * kJetsamHighRelaunchCandidatesThreshold defines the percentage of candidates
 * in the idle & deferred bands that need to be bad candidates in order to trigger
 * aggressive jetsam.
 */
#define kJetsamHighRelaunchCandidatesThreshold  (100)

/* kJetsamMinCandidatesThreshold defines the minimum number of candidates in the
 * idle/deferred bands to trigger aggressive jetsam. This value basically decides
 * how much memory the system is ready to hold in the lower bands without triggering
 * aggressive jetsam. This number should ideally be tuned based on the memory config
 * of the device.
 */
#define kJetsamMinCandidatesThreshold           (5)

static bool
memorystatus_check_aggressive_jetsam_needed(int *jld_idle_kills)
{
	bool aggressive_jetsam_needed = false;
	int total_candidates = 0;
	/*
	 * The aggressive jetsam logic looks at the number of times it has been in the
	 * aggressive loop to determine the max priority band it should kill upto. The
	 * static variables below are used to track that property.
	 *
	 * To reset those values, the implementation checks if it has been
	 * memorystatus_jld_eval_period_msecs since the parameters were reset.
	 */

	if (memorystatus_jld_enabled == FALSE) {
		/* If aggressive jetsam is disabled, nothing to do here */
		return FALSE;
	}

	/* Get current timestamp (msecs only) */
	struct timeval  jld_now_tstamp = {0, 0};
	uint64_t        jld_now_msecs = 0;
	microuptime(&jld_now_tstamp);
	jld_now_msecs = (jld_now_tstamp.tv_sec * 1000);

	/*
	 * Look at the number of candidates in the idle and deferred band and
	 * how many out of them are marked as high relaunch probability.
	 */
	aggressive_jetsam_needed = memorystatus_aggressive_jetsam_needed_sysproc_aging(jld_eval_aggressive_count,
	    jld_idle_kills, jld_idle_kill_candidates, &total_candidates);

	/*
	 * Check if its been really long since the aggressive jetsam evaluation
	 * parameters have been refreshed. This logic also resets the jld_eval_aggressive_count
	 * counter to make sure we reset the aggressive jetsam severity.
	 */
	boolean_t param_reval = false;

	if ((total_candidates == 0) ||
	    (jld_now_msecs > (jld_timestamp_msecs + memorystatus_jld_eval_period_msecs))) {
		jld_timestamp_msecs      = jld_now_msecs;
		jld_idle_kill_candidates = total_candidates;
		*jld_idle_kills          = 0;
		jld_eval_aggressive_count = 0;
		jld_priority_band_max   = JETSAM_PRIORITY_UI_SUPPORT;
		param_reval = true;
	}

	/*
	 * It is also possible that the system is down to a very small number of processes in the candidate
	 * bands. In that case, the decisions made by the memorystatus_aggressive_jetsam_needed_* routines
	 * would not be useful. In that case, do not trigger aggressive jetsam.
	 */
	if (total_candidates < kJetsamMinCandidatesThreshold) {
#if DEVELOPMENT || DEBUG
		printf("memorystatus: aggressive: [FAILED] Low Candidate Count (current: %d, threshold: %d)\n", total_candidates, kJetsamMinCandidatesThreshold);
#endif /* DEVELOPMENT || DEBUG */
		aggressive_jetsam_needed = false;
	}
	return aggressive_jetsam_needed;
}

static bool
memorystatus_aggressive_jetsam_needed_sysproc_aging(__unused int eval_aggressive_count, __unused int *idle_kills, __unused int idle_kill_candidates, int *total_candidates)
{
	bool aggressive_jetsam_needed = false;

	/*
	 * For the kJetsamAgingPolicySysProcsReclaimedFirst aging policy, we maintain the jetsam
	 * relaunch behavior for all daemons. Also, daemons and apps are aged in deferred bands on
	 * every dirty->clean transition. For this aging policy, the best way to determine if
	 * aggressive jetsam is needed, is to see if the kill candidates are mostly bad candidates.
	 * If yes, then we need to go to higher bands to reclaim memory.
	 */
	proc_list_lock();
	/* Get total candidate counts for idle and idle deferred bands */
	*total_candidates = memstat_bucket[JETSAM_PRIORITY_IDLE].count + memstat_bucket[system_procs_aging_band].count;
	/* Get counts of bad kill candidates in idle and idle deferred bands */
	int bad_candidates = memstat_bucket[JETSAM_PRIORITY_IDLE].relaunch_high_count + memstat_bucket[system_procs_aging_band].relaunch_high_count;

	proc_list_unlock();

	/* Check if the number of bad candidates is greater than kJetsamHighRelaunchCandidatesThreshold % */
	aggressive_jetsam_needed = (((bad_candidates * 100) / *total_candidates) >= kJetsamHighRelaunchCandidatesThreshold);

	/*
	 * Since the new aging policy bases the aggressive jetsam trigger on percentage of
	 * bad candidates, it is prone to being overly aggressive. In order to mitigate that,
	 * make sure the system is really under memory pressure before triggering aggressive
	 * jetsam.
	 */
	if (memorystatus_available_pages > memorystatus_sysproc_aging_aggr_pages) {
		aggressive_jetsam_needed = false;
	}

#if DEVELOPMENT || DEBUG
	printf("memorystatus: aggressive%d: [%s] Bad Candidate Threshold Check (total: %d, bad: %d, threshold: %d %%); Memory Pressure Check (available_pgs: %llu, threshold_pgs: %llu)\n",
	    eval_aggressive_count, aggressive_jetsam_needed ? "PASSED" : "FAILED", *total_candidates, bad_candidates,
	    kJetsamHighRelaunchCandidatesThreshold, (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, (uint64_t)memorystatus_sysproc_aging_aggr_pages);
#endif /* DEVELOPMENT || DEBUG */
	return aggressive_jetsam_needed;
}

#endif /* CONFIG_JETSAM */

#pragma mark Freezer
#if CONFIG_FREEZE
/*
 * Freezer policies
 */

/*
 * These functions determine what is eligible for the freezer
 * and the order that we consider freezing them
 */

/*
 * Checks if the given process is eligible for the freezer.
 * Processes can only be frozen if this returns true.
 */
bool
memorystatus_is_process_eligible_for_freeze(proc_t p)
{
	/*
	 * Called with proc_list_lock held.
	 */

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	bool should_freeze = false;
	uint32_t state = 0, pages = 0;
	bool first_consideration = true;
	task_t task;

	state = p->p_memstat_state;

	if (state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_LOCKED | P_MEMSTAT_FREEZE_DISABLED | P_MEMSTAT_FREEZE_IGNORE)) {
		if (state & P_MEMSTAT_FREEZE_DISABLED) {
			p->p_memstat_freeze_skip_reason = kMemorystatusFreezeSkipReasonDisabled;
		}
		goto out;
	}

	task = proc_task(p);

	if (isSysProc(p)) {
		/*
		 * Daemon:- We consider freezing it if:
		 * - it belongs to a coalition and the leader is frozen, and,
		 * - its role in the coalition is XPC service.
		 *
		 * We skip memory size requirements in this case.
		 */
		int task_role_in_coalition = 0;
		proc_t leader_proc = memorystatus_get_coalition_leader_and_role(p, &task_role_in_coalition);
		if (leader_proc == PROC_NULL || leader_proc == p) {
			/*
			 * Jetsam coalition is leaderless or the leader is not an app.
			 * Either way, don't freeze this proc.
			 */
			goto out;
		}

		/* Leader must be frozen */
		if (!(leader_proc->p_memstat_state & P_MEMSTAT_FROZEN)) {
			goto out;
		}
		/* Only freeze XPC services */
		if (task_role_in_coalition == COALITION_TASKROLE_XPC) {
			should_freeze = true;
		}

		goto out;
	} else {
		/*
		 * Application. Only freeze if it's suspended.
		 */
		if (!(state & P_MEMSTAT_SUSPENDED)) {
			goto out;
		}
	}

	/*
	 * We're interested in tracking what percentage of
	 * eligible apps actually get frozen.
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
	memorystatus_get_task_page_counts(proc_task(p), &pages, NULL, NULL);
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

	if (!memorystatus_freezer_use_ordered_list) {
		/*
		 * We're not using the ordered list so we need to check
		 * that dasd recommended the process. Note that the ordered list
		 * algorithm only considers processes on the list in the first place
		 * so there's no need to double check here.
		 */
		if (!memorystatus_freeze_process_is_recommended(p)) {
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

	should_freeze = true;
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

bool
memorystatus_freeze_proc_is_refreeze_eligible(proc_t p)
{
	return (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) != 0;
}


static proc_t
memorystatus_freeze_pick_refreeze_process(proc_t last_p)
{
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	unsigned int band = (unsigned int) memorystatus_freeze_jetsam_band;
	if (last_p == PROC_NULL) {
		next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	} else {
		next_p = memorystatus_get_next_proc_locked(&band, last_p, FALSE);
	}
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&band, p, FALSE);
		if ((p->p_memstat_state & P_MEMSTAT_FROZEN) && !memorystatus_freeze_proc_is_refreeze_eligible(p)) {
			/* Process is already frozen & hasn't been thawed. */
			continue;
		}
		/*
		 * Has to have been frozen once before.
		 */
		if (!(p->p_memstat_state & P_MEMSTAT_FROZEN)) {
			continue;
		}

		/*
		 * Not currently being looked at for something.
		 */
		if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
			continue;
		}
		/*
		 * Found it
		 */
		break;
	}
	return p;
}

proc_t
memorystatus_freeze_pick_process(struct memorystatus_freeze_list_iterator *iterator)
{
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	unsigned int band = JETSAM_PRIORITY_IDLE;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	/*
	 * If the freezer is full, only consider refreezes.
	 */
	if (iterator->refreeze_only || memorystatus_frozen_count >= memorystatus_frozen_processes_max) {
		if (!iterator->refreeze_only) {
			/*
			 * The first time the iterator starts to return refreeze
			 * candidates, we need to reset the last pointer b/c it's pointing into the wrong band.
			 */
			iterator->last_p = PROC_NULL;
			iterator->refreeze_only = true;
		}
		iterator->last_p = memorystatus_freeze_pick_refreeze_process(iterator->last_p);
		return iterator->last_p;
	}

	/*
	 * Search for the next freezer candidate.
	 */
	if (memorystatus_freezer_use_ordered_list) {
		next_p = memorystatus_freezer_candidate_list_get_proc(
			&memorystatus_global_freeze_list,
			(iterator->global_freeze_list_index)++,
			&memorystatus_freezer_stats.mfs_freeze_pid_mismatches);
	} else if (iterator->last_p == PROC_NULL) {
		next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	} else {
		next_p = memorystatus_get_next_proc_locked(&band, iterator->last_p, FALSE);
	}
	while (next_p) {
		p = next_p;
		if (memorystatus_is_process_eligible_for_freeze(p)) {
			iterator->last_p = p;
			return iterator->last_p;
		} else {
			if (memorystatus_freezer_use_ordered_list) {
				next_p = memorystatus_freezer_candidate_list_get_proc(
					&memorystatus_global_freeze_list,
					(iterator->global_freeze_list_index)++,
					&memorystatus_freezer_stats.mfs_freeze_pid_mismatches);
			} else {
				next_p = memorystatus_get_next_proc_locked(&band, p, FALSE);
			}
		}
	}

	/*
	 * Failed to find a new freezer candidate.
	 * Try to re-freeze.
	 */
	if (memorystatus_refreeze_eligible_count >= MIN_THAW_REFREEZE_THRESHOLD) {
		assert(!iterator->refreeze_only);
		iterator->refreeze_only = true;
		iterator->last_p = memorystatus_freeze_pick_refreeze_process(PROC_NULL);
		return iterator->last_p;
	}
	return PROC_NULL;
}

/*
 * memorystatus_pages_update calls this function whenever the number
 * of available pages changes. It wakes the freezer thread iff the function returns
 * true. The freezer thread will try to freeze (or refreeze) up to 1 process
 * before blocking again.
 *
 * Note the freezer thread is also woken up by memorystatus_on_inactivity.
 */

bool
memorystatus_freeze_thread_should_run()
{
	/*
	 * No freezer_mutex held here...see why near call-site
	 * within memorystatus_pages_update().
	 */

	if (memorystatus_freeze_enabled == FALSE) {
		return false;
	}

	if (memorystatus_available_pages > memorystatus_freeze_threshold) {
		return false;
	}

	memorystatus_freezer_stats.mfs_below_threshold_count++;

	if ((memorystatus_frozen_count >= memorystatus_frozen_processes_max)) {
		/*
		 * Consider this as a skip even if we wake up to refreeze because
		 * we won't freeze any new procs.
		 */
		memorystatus_freezer_stats.mfs_skipped_full_count++;
		if (memorystatus_refreeze_eligible_count < MIN_THAW_REFREEZE_THRESHOLD) {
			return false;
		}
	}

	if (memorystatus_frozen_shared_mb_max && (memorystatus_frozen_shared_mb >= memorystatus_frozen_shared_mb_max)) {
		memorystatus_freezer_stats.mfs_skipped_shared_mb_high_count++;
		return false;
	}

	uint64_t curr_time = mach_absolute_time();

	if (curr_time < memorystatus_freezer_thread_next_run_ts) {
		return false;
	}

	return true;
}

size_t
memorystatus_pick_freeze_count_for_wakeup()
{
	size_t num_to_freeze = 0;
	if (!memorystatus_swap_all_apps) {
		num_to_freeze = 1;
	} else {
		/*
		 * When app swap is enabled, we want the freezer thread to aggressively freeze
		 * all candidates so we clear out space for the fg working set.
		 * But we still cap it to the current size of the candidate bands to avoid
		 * consuming excessive CPU if there's a lot of churn in the candidate band.
		 */
		proc_list_lock();
		for (unsigned int band = JETSAM_PRIORITY_IDLE; band <= memorystatus_freeze_max_candidate_band; band++) {
			num_to_freeze += memstat_bucket[band].count;
		}
		proc_list_unlock();
	}

	return num_to_freeze;
}

#endif /* CONFIG_FREEZE */
