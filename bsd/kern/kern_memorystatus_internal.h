/*
 * Copyright (c) 2006-2019 Apple Inc. All rights reserved.
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

#ifndef _KERN_MEMORYSTATUS_INTERNAL_H_
#define _KERN_MEMORYSTATUS_INTERNAL_H_

/*
 * Contains memorystatus subsystem definitions that are not
 * exported outside of the memorystatus subsystem.
 *
 * For example, all of the mechanisms used by kern_memorystatus_policy.c
 * should be defined in this header.
 */

#if BSD_KERNEL_PRIVATE

#include <mach/boolean.h>
#include <stdbool.h>
#include <os/base.h>
#include <os/log.h>
#include <kern/sched_prim.h>

#if CONFIG_FREEZE
#include <sys/kern_memorystatus_freeze.h>
#endif /* CONFIG_FREEZE */

/*
 * memorystatus subsystem globals
 */
#if CONFIG_JETSAM
extern unsigned int memorystatus_available_pages;
extern unsigned int memorystatus_available_pages_pressure;
extern unsigned int memorystatus_available_pages_critical;
extern uint32_t jetsam_kill_on_low_swap;
#else /* CONFIG_JETSAM */
extern uint64_t memorystatus_available_pages;
extern uint64_t memorystatus_available_pages_pressure;
extern uint64_t memorystatus_available_pages_critical;
#endif /* CONFIG_JETSAM */
extern int block_corpses; /* counter to block new corpses if jetsam purges them */
extern int system_procs_aging_band;
extern int applications_aging_band;
/*
 * TODO(jason): This should really be calculated dynamically by the zalloc
 * subsystem before we do a zone map exhaustion kill. But the zone_gc
 * logic is non-trivial, so for now it just sets this global.
 */
extern _Atomic bool memorystatus_zone_map_is_exhausted;
/*
 * TODO(jason): We should get rid of this global
 * and have the memorystatus thread check for compressor space shortages
 * itself. However, there are 3 async call sites remaining that require more work to get us there:
 * 2 of them are in vm_swap_defragment. When it's about to swap in a segment, it checks if that
 * will cause a compressor space shortage & pre-emptively triggers jetsam. vm_compressor_backing_store
 * needs to keep track of in-flight swapins due to defrag so we can perform those checks
 * in the memorystatus thread.
 * The other is in no_paging_space_action. This is only on macOS right now, but will
 * be needed on iPad when we run out of swap space. This should be a new kill
 * reason and we need to add a new health check for it.
 * We need to maintain the macOS behavior though that we kill no more than 1 process
 * every 5 seconds.
 */
extern _Atomic bool memorystatus_compressor_space_shortage;
/*
 * TODO(jason): We should also get rid of this global
 * and check for phantom cache pressure from the memorystatus
 * thread. But first we need to fix the syncronization in
 * vm_phantom_cache_check_pressure
 */
extern _Atomic bool memorystatus_phantom_cache_pressure;

extern _Atomic bool memorystatus_pageout_starved;
/*
 * The actions that the memorystatus thread can perform
 * when we're low on memory.
 * See memorystatus_pick_action to see when each action is deployed.
 */
OS_CLOSED_ENUM(memorystatus_action, uint32_t,
    MEMORYSTATUS_KILL_HIWATER,     // Kill 1 highwatermark process
    MEMORYSTATUS_KILL_AGGRESSIVE,     // Do aggressive jetsam
    MEMORYSTATUS_KILL_TOP_PROCESS,     // Kill based on jetsam priority
    MEMORYSTATUS_WAKE_SWAPPER,  // Wake up the swap thread
    MEMORYSTATUS_PROCESS_SWAPIN_QUEUE, // Compact the swapin queue and move segments to the swapout queue
    MEMORYSTATUS_KILL_SUSPENDED_SWAPPABLE, // Kill a suspended swap-eligible processes based on jetsam priority
    MEMORYSTATUS_KILL_SWAPPABLE, // Kill a swap-eligible process (even if it's running)  based on jetsam priority
    MEMORYSTATUS_KILL_NONE,     // Do nothing
    );

/*
 * Structure to hold state for a jetsam thread.
 * Typically there should be a single jetsam thread
 * unless parallel jetsam is enabled.
 */
typedef struct jetsam_thread_state {
	uint8_t                         inited; /* boolean - if the thread is initialized */
	uint8_t                         limit_to_low_bands; /* boolean */
	int                             index; /* jetsam thread index */
	thread_t                        thread; /* jetsam thread pointer */
	int                             jld_idle_kills; /*  idle jetsam kill counter for this session */
	uint32_t                        errors; /* Error accumulator */
	bool                            sort_flag; /* Sort the fg band (idle on macOS) before killing? */
	bool                            corpse_list_purged; /* Has the corpse list been purged? */
	bool                            post_snapshot; /* Do we need to post a jetsam snapshot after this session? */
	uint64_t                        memory_reclaimed; /* Amount of memory that was just reclaimed */
	uint32_t                        hwm_kills; /* hwm kill counter for this session */
	sched_cond_atomic_t             jt_wakeup_cond; /* condition var used to synchronize wake/sleep operations for this jetsam thread */
} jetsam_thread_state_t;

/*
 * The memorystatus thread monitors these conditions
 * and will continue to act until the system is considered
 * healthy.
 */
typedef struct memorystatus_system_health {
#if CONFIG_JETSAM
	bool msh_available_pages_below_pressure;
	bool msh_available_pages_below_critical;
	bool msh_compressor_needs_to_swap;
	bool msh_compressor_is_low_on_space;
	bool msh_compressor_is_thrashing;
	bool msh_compressed_pages_nearing_limit;
	bool msh_filecache_is_thrashing;
	bool msh_phantom_cache_pressure;
	bool msh_swappable_compressor_segments_over_limit;
	bool msh_swapin_queue_over_limit;
	bool msh_swap_low_on_space;
	bool msh_swap_out_of_space;
	bool msh_pageout_starved;
#endif /* CONFIG_JETSAM */
	bool msh_zone_map_is_exhausted;
} memorystatus_system_health_t;

void memorystatus_log_system_health(const memorystatus_system_health_t *health);
bool memorystatus_is_system_healthy(const memorystatus_system_health_t *status);
/* Picks a kill cause given an unhealthy system status */
uint32_t memorystatus_pick_kill_cause(const memorystatus_system_health_t *status);

/*
 * Agressive jetsam tunables
 */
#define kJetsamAgingPolicyNone                          (0)
#define kJetsamAgingPolicyLegacy                        (1)
#define kJetsamAgingPolicySysProcsReclaimedFirst        (2)
#define kJetsamAgingPolicyAppsReclaimedFirst            (3)
#define kJetsamAgingPolicyMax                           kJetsamAgingPolicyAppsReclaimedFirst
extern boolean_t memorystatus_jld_enabled;              /* Enable jetsam loop detection */
extern uint32_t memorystatus_jld_eval_period_msecs;         /* Init pass sets this based on device memory size */
extern int      memorystatus_jld_eval_aggressive_count;     /* Raise the priority max after 'n' aggressive loops */
extern int      memorystatus_jld_eval_aggressive_priority_band_max;  /* Kill aggressively up through this band */
extern int      memorystatus_jld_max_kill_loops;            /* How many times should we try and kill up to the target band */
extern unsigned int memorystatus_sysproc_aging_aggr_pages; /* Aggressive jetsam pages threshold for sysproc aging policy */
extern int       jld_eval_aggressive_count;
extern int32_t   jld_priority_band_max;
extern uint64_t  jld_timestamp_msecs;
extern int       jld_idle_kill_candidates;


/*
 * VM globals read by the memorystatus subsystem
 */
extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_throttled_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;
extern unsigned int    vm_page_speculative_count;
extern uint32_t        c_late_swapout_count, c_late_swappedin_count;
extern uint32_t        c_seg_allocsize;
extern bool            vm_swapout_thread_running;
extern _Atomic bool    vm_swapout_wake_pending;
#define VM_PAGE_DONATE_DISABLED     0
#define VM_PAGE_DONATE_ENABLED      1
extern uint32_t vm_page_donate_mode;
void vm_swapout_thread(void);
void vm_compressor_process_special_swapped_in_segments(void);

#if CONFIG_JETSAM
#define MEMORYSTATUS_LOG_AVAILABLE_PAGES memorystatus_available_pages
#else /* CONFIG_JETSAM */
#define MEMORYSTATUS_LOG_AVAILABLE_PAGES (vm_page_active_count + vm_page_inactive_count + vm_page_free_count + vm_page_speculative_count)
#endif /* CONFIG_JETSAM */

bool memorystatus_avail_pages_below_pressure(void);
bool memorystatus_avail_pages_below_critical(void);
#if CONFIG_JETSAM
bool memorystatus_swap_over_trigger(uint64_t adjustment_factor);
bool memorystatus_swapin_over_trigger(void);
#endif /* CONFIG_JETSAM */

/* Does cause indicate vm or fc thrashing? */
bool is_reason_thrashing(unsigned cause);
/* Is the zone map almost full? */
bool is_reason_zone_map_exhaustion(unsigned cause);

memorystatus_action_t memorystatus_pick_action(struct jetsam_thread_state *jetsam_thread,
    uint32_t *kill_cause, bool highwater_remaining,
    bool suspended_swappable_apps_remaining,
    bool swappable_apps_remaining, int *jld_idle_kills);

#define MEMSTAT_PERCENT_TOTAL_PAGES(p) (p * atop_64(max_mem) / 100)

#pragma mark Logging Utilities

__enum_decl(memorystatus_log_level_t, unsigned int, {
	MEMORYSTATUS_LOG_LEVEL_DEFAULT = 0,
	MEMORYSTATUS_LOG_LEVEL_INFO = 1,
	MEMORYSTATUS_LOG_LEVEL_DEBUG = 2,
});

extern os_log_t memorystatus_log_handle;
extern memorystatus_log_level_t memorystatus_log_level;

/*
 * NB: Critical memorystatus logs (e.g. jetsam kills) are load-bearing for OS
 * performance testing infrastructure. Be careful when modifying the log-level for
 * important system events.
 *
 * Memorystatus logs are interpreted by a wide audience. To avoid logging information
 * that could lead to false diagnoses, INFO and DEBUG messages are only logged if the
 * system has been configured to do so via `kern.memorystatus_log_level` (sysctl) or
 * `memorystatus_log_level` (boot-arg).
 *
 * os_log supports a mechanism for configuring these properties dynamically; however,
 * this mechanism is currently unsupported in XNU.
 *
 * TODO (JC) Deprecate sysctl/boot-arg and move to subsystem preferences pending:
 *  - rdar://27006343 (Custom kernel log handles)
 *  - rdar://80958044 (Kernel Logging Configuration)
 */
#define _memorystatus_log_with_type(type, format, ...) os_log_with_type(memorystatus_log_handle, type, format, ##__VA_ARGS__)
#define memorystatus_log(format, ...) _memorystatus_log_with_type(OS_LOG_TYPE_DEFAULT, format, ##__VA_ARGS__)
#define memorystatus_log_info(format, ...) if (memorystatus_log_level >= MEMORYSTATUS_LOG_LEVEL_INFO) { _memorystatus_log_with_type(OS_LOG_TYPE_INFO, format, ##__VA_ARGS__); }
#define memorystatus_log_debug(format, ...) if (memorystatus_log_level >= MEMORYSTATUS_LOG_LEVEL_DEBUG) { _memorystatus_log_with_type(OS_LOG_TYPE_DEBUG, format, ##__VA_ARGS__); }
#define memorystatus_log_error(format, ...) _memorystatus_log_with_type(OS_LOG_TYPE_ERROR, format, ##__VA_ARGS__)
#define memorystatus_log_fault(format, ...) _memorystatus_log_with_type(OS_LOG_TYPE_FAULT, format, ##__VA_ARGS__)

#pragma mark Freezer
#if CONFIG_FREEZE
/*
 * Freezer data types
 */

/* An ordered list of freeze or demotion candidates */
struct memorystatus_freezer_candidate_list {
	memorystatus_properties_freeze_entry_v1 *mfcl_list;
	size_t mfcl_length;
};

struct memorystatus_freeze_list_iterator {
	bool refreeze_only;
	proc_t last_p;
	size_t global_freeze_list_index;
};

/*
 * Freezer globals
 */
extern struct memorystatus_freezer_stats_t memorystatus_freezer_stats;
extern int memorystatus_freezer_use_ordered_list;
extern struct memorystatus_freezer_candidate_list memorystatus_global_freeze_list;
extern struct memorystatus_freezer_candidate_list memorystatus_global_demote_list;
extern uint64_t memorystatus_freezer_thread_next_run_ts;
bool memorystatus_is_process_eligible_for_freeze(proc_t p);
bool memorystatus_freeze_proc_is_refreeze_eligible(proc_t p);

proc_t memorystatus_freezer_candidate_list_get_proc(
	struct memorystatus_freezer_candidate_list *list,
	size_t index,
	uint64_t *pid_mismatch_counter);
/*
 * Returns the leader of the p's jetsam coalition
 * and the role of p in that coalition.
 */
proc_t memorystatus_get_coalition_leader_and_role(proc_t p, int *role_in_coalition);
bool memorystatus_freeze_process_is_recommended(const proc_t p);

/*
 * Ordered iterator over all freeze candidates.
 * The iterator should initially be zeroed out by the caller and
 * can be zeroed out whenever the caller wishes to start from the beginning
 * of the list again.
 * Returns PROC_NULL when all candidates have been iterated over.
 */
proc_t memorystatus_freeze_pick_process(struct memorystatus_freeze_list_iterator *iterator);

/*
 * Returns the number of processes that the freezer thread should try to freeze
 * on this wakeup.
 */
size_t memorystatus_pick_freeze_count_for_wakeup(void);

/*
 * Configure the freezer for app-based swap mode.
 * Should be called at boot.
 */
void memorystatus_freeze_configure_for_swap(void);
/*
 * Undo memorystatus_freeze_configure_for_swap
 */
void memorystatus_freeze_disable_swap(void);
#endif /* CONFIG_FREEZE */

#endif /* BSD_KERNEL_PRIVATE */

#endif /* _KERN_MEMORYSTATUS_INTERNAL_H_ */
