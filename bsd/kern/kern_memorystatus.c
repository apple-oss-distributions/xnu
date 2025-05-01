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

#include <kern/sched_prim.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <kern/policy_internal.h>
#include <kern/thread_group.h>
#include <kern/zalloc.h>

#include <corpses/task_corpse.h>
#include <libkern/libkern.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/host_priv.h>
#include <mach/mach_host.h>
#include <pexpert/pexpert.h>
#include <sys/coalition.h>
#include <sys/code_signing.h>
#include <sys/kern_event.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/reason.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/spawn_internal.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/priv.h>
#include <vm/pmap.h>
#include <vm/vm_reclaim_xnu.h>
#include <vm/vm_pageout_xnu.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_xnu.h>
#include <vm/vm_page.h>
#include <vm/vm_compressor_xnu.h>
#include <mach/machine/sdt.h>
#include <libkern/section_keywords.h>
#include <os/atomic_private.h>
#include <os/overflow.h>
#include <mach/mach_time.h>

#include <IOKit/IOBSD.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#if CONFIG_FREEZE
#include <vm/vm_map.h>
#endif /* CONFIG_FREEZE */

#include <kern/kern_memorystatus_internal.h>
#include <sys/kern_memorystatus.h>
#include <sys/kern_memorystatus_xnu.h>
#include <sys/kern_memorystatus_freeze.h>
#include <sys/kern_memorystatus_notify.h>
#include <sys/kdebug_triage.h>
#include <sys/file_internal.h>
#include <net/necp.h>

errno_t mach_to_bsd_errno(kern_return_t mach_err);
extern uint32_t vm_compressor_pool_size(void);
extern uint32_t vm_compressor_fragmentation_level(void);

pid_t memorystatus_freeze_last_pid_thawed = 0;
uint64_t memorystatus_freeze_last_pid_thawed_ts = 0;

int block_corpses = 0; /* counter to block new corpses if jetsam purges them */

/* For logging clarity */
static const char *memorystatus_kill_cause_name[] = {
	"",                                             /* kMemorystatusInvalid							*/
	"jettisoned",                                   /* kMemorystatusKilled							*/
	"highwater",                                    /* kMemorystatusKilledHiwat						*/
	"vnode-limit",                                  /* kMemorystatusKilledVnodes					*/
	"vm-pageshortage",                              /* kMemorystatusKilledVMPageShortage			*/
	"proc-thrashing",                               /* kMemorystatusKilledProcThrashing				*/
	"fc-thrashing",                                 /* kMemorystatusKilledFCThrashing				*/
	"per-process-limit",                            /* kMemorystatusKilledPerProcessLimit			*/
	"disk-space-shortage",                          /* kMemorystatusKilledDiskSpaceShortage			*/
	"idle-exit",                                    /* kMemorystatusKilledIdleExit					*/
	"zone-map-exhaustion",                          /* kMemorystatusKilledZoneMapExhaustion			*/
	"vm-compressor-thrashing",                      /* kMemorystatusKilledVMCompressorThrashing		*/
	"vm-compressor-space-shortage",                 /* kMemorystatusKilledVMCompressorSpaceShortage	*/
	"low-swap",                                     /* kMemorystatusKilledLowSwap                   */
	"sustained-memory-pressure",                    /* kMemorystatusKilledSustainedPressure         */
	"vm-pageout-starvation",                        /* kMemorystatusKilledVMPageoutStarvation       */
	"",                                             /* Future kMemorystatusKilledConclaveLimit      */
	"long-idle-exit",                               /* kMemorystatusKilledLongIdleExit				*/
};

static const char *
memorystatus_priority_band_name(int32_t priority)
{
	switch (priority) {
	case JETSAM_PRIORITY_FOREGROUND:
		return "FOREGROUND";
	case JETSAM_PRIORITY_AUDIO_AND_ACCESSORY:
		return "AUDIO_AND_ACCESSORY";
	case JETSAM_PRIORITY_CONDUCTOR:
		return "CONDUCTOR";
	case JETSAM_PRIORITY_DRIVER_APPLE:
		return "DRIVER_APPLE";
	case JETSAM_PRIORITY_HOME:
		return "HOME";
	case JETSAM_PRIORITY_EXECUTIVE:
		return "EXECUTIVE";
	case JETSAM_PRIORITY_IMPORTANT:
		return "IMPORTANT";
	case JETSAM_PRIORITY_CRITICAL:
		return "CRITICAL";
	}

	return "?";
}

bool
is_reason_thrashing(unsigned cause)
{
	switch (cause) {
	case kMemorystatusKilledFCThrashing:
	case kMemorystatusKilledVMCompressorThrashing:
	case kMemorystatusKilledVMCompressorSpaceShortage:
		return true;
	default:
		return false;
	}
}

bool
is_reason_zone_map_exhaustion(unsigned cause)
{
	return cause == kMemorystatusKilledZoneMapExhaustion;
}

/*
 * Returns the current zone map size and capacity to include in the jetsam snapshot.
 * Defined in zalloc.c
 */
extern void get_zone_map_size(uint64_t *current_size, uint64_t *capacity);

/*
 * Returns the name of the largest zone and its size to include in the jetsam snapshot.
 * Defined in zalloc.c
 */
extern void get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size);

static int memstat_set_memlimits_locked(proc_t p, int32_t active_limit,
    int32_t inactive_limit, memlimit_options_t options);
static bool memstat_proc_is_active_locked(proc_t);

static int memorystatus_highwater_enabled = 1;  /* Update the cached memlimit data. */

/*
 * Cache this proc's active limit as its current limit before writing it to
 * the ledger. Returns whether the new limit should be written to the ledger.
 */
static inline bool
memstat_update_memlimit_locked(proc_t p, bool use_active)
{
	bool ledger_needed = false;
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	/* Cache limit value */
	if (use_active && p->p_memstat_memlimit != p->p_memstat_memlimit_active) {
		p->p_memstat_memlimit = p->p_memstat_memlimit_active;
		ledger_needed = true;
	} else if (!use_active &&
	    p->p_memstat_memlimit != p->p_memstat_memlimit_inactive) {
		p->p_memstat_memlimit = p->p_memstat_memlimit_inactive;
		ledger_needed = true;
	}

	/* Cache limit fatality */
	if (_memstat_proc_memlimit_is_fatal(p, use_active) &&
	    !_memstat_proc_cached_memlimit_is_fatal(p)) {
		p->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;
		ledger_needed = true;
	} else if (!_memstat_proc_memlimit_is_fatal(p, use_active) &&
	    _memstat_proc_cached_memlimit_is_fatal(p)) {
		p->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;
		ledger_needed = true;
	}

	return ledger_needed;
}

/*
 * Write the process' current memlimit to the ledger for enforcement.
 *
 * Holding the proc_list_lock while writing to the ledgers (where the task
 * lock is taken) can be problematic.  The proc list lock may optionally be
 * dropped and re-taken while writing limits to the ledger. (rdar://21394491)
 */
static int
_memstat_write_memlimit_to_ledger_locked(proc_t p, bool is_active, bool drop_lock)
{
	kern_return_t kr;
	bool is_fatal = _memstat_proc_cached_memlimit_is_fatal(p);

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

#if MACH_ASSERT
	if (memorystatus_highwater_enabled) {
		if (is_active) {
			assert3u(is_fatal, ==, _memstat_proc_active_memlimit_is_fatal(p));
			assert3u(p->p_memstat_memlimit, ==, p->p_memstat_memlimit_active);
		} else {
			assert3u(is_fatal, ==, _memstat_proc_inactive_memlimit_is_fatal(p));
			assert3u(p->p_memstat_memlimit, ==, p->p_memstat_memlimit_inactive);
		}
	}
#endif /* MACH_ASSERT */

	if (drop_lock) {
		if (proc_ref(p, true) != p) {
			memorystatus_log_error("Unable to take a reference on proc %s [%d]. "
			    "Cannot update memlimit", proc_best_name(p), proc_getpid(p));
			return ESRCH;
		}
		proc_list_unlock();
	}

	memorystatus_log_debug("memorystatus: new limit on pid %d (%dMB %s)\n",
	    proc_getpid(p), (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
	    (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"));

	kr = task_set_phys_footprint_limit_internal(proc_task(p),
	    (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1,
	    NULL, is_active, is_fatal);

	if (drop_lock) {
		proc_list_lock();
		proc_rele(p);
	}

	if (kr != KERN_SUCCESS) {
		memorystatus_log_fault("memorystatus: error (%d) setting memlimit in "
		    "ledger for %s [%d]\n", kr, proc_best_name(p), proc_pid(p));
		return mach_to_bsd_errno(kr);
	}
	return 0;
}

#pragma mark General Tunables

#define MEMORYSTATUS_SMALL_MEMORY_THRESHOLD (3UL * (1UL << 30))
#define MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD (6UL * (1UL << 30))

#define MEMORYSTATUS_CLEAR_THE_DECKS_OFFSET_PERCENTAGE 5UL
#define MEMORYSTATUS_BALLAST_OFFSET_PERCENTAGE 5UL
#define MEMORYSTATUS_AGGR_SYSPROC_AGING_PERCENTAGE 7UL
#define MEMORYSTATUS_DELTA_PERCENTAGE_LARGE 4UL
#define MEMORYSTATUS_DELTA_PERCENTAGE_SMALL 5UL

/*
 * Fall back to these percentages/ratios if a mb value is not provided via EDT
 *  DRAM (GB) | critical | idle | pressure | reaper | freeze
 *  (0,3]     | 5%       | 10%  | 15%      | 20%    | 50%
 *  (3,6]     | 4%       | 9%   | 15%      | 18%    | 50%
 *  (6,∞)     | 4%       | 8%   | 12%      | 16%    | 50%
 */

#define MEMORYSTATUS_CRITICAL_PERCENTAGE_SMALL 5UL
#define MEMORYSTATUS_CRITICAL_PERCENTAGE_LARGE 4UL

#define MEMORYSTATUS_IDLE_RATIO_NUM 2UL
#define MEMORYSTATUS_IDLE_RATIO_DENOM 1UL
#define MEMORYSTATUS_PRESSURE_RATIO_NUM 3UL
#define MEMORYSTATUS_PRESSURE_RATIO_DENOM 1UL
#define MEMORYSTATUS_REAPER_RATIO_NUM 4UL
#define MEMORYSTATUS_REAPER_RATIO_DENOM 1UL

#if (XNU_TARGET_OS_IOS && !XNU_TARGET_OS_XR)
#define MEMORYSTATUS_REAPER_ENABLED_DEFAULT TRUE
#else
#define MEMORYSTATUS_REAPER_ENABLED_DEFAULT FALSE
#endif /* (XNU_TARGET_OS_IOS && !XNU_TARGET_OS_XR) */
#define MEMORYSTATUS_REAPER_MIN_AGE_SECS_DEFAULT 300
#define MEMORYSTATUS_REAPER_MAX_PRIORITY_DEFAULT JETSAM_PRIORITY_IDLE
#define MEMORYSTATUS_REAPER_RESCAN_SECS_DEFAULT 300
#define MEMORYSTATUS_REAPER_SENTINAL_VALUE_MEANING_USE_DEFAULT -1

#define MEMORYSTATUS_REAPER_REAP_RELAUNCH_MASK_UNKNOWN (P_MEMSTAT_RELAUNCH_HIGH << 1)
#define MEMORYSTATUS_REAPER_REAP_RELAUNCH_MASK_DEFAULT (P_MEMSTAT_RELAUNCH_LOW | MEMORYSTATUS_REAPER_REAP_RELAUNCH_MASK_UNKNOWN)

/*
 * For historical reasons, devices with "medium"-sized memory configs have a critical:idle:pressure ratio of
 * 4:9:15. This ratio is preserved for these devices when a fixed-mb base value has not been provided by EDT/boot-arg;
 * all other devices use a 1:2:3 ratio.
 */
#define MEMORYSTATUS_IDLE_RATIO_NUM_MEDIUM 9UL
#define MEMORYSTATUS_IDLE_RATIO_DENOM_MEDIUM 4UL
#define MEMORYSTATUS_PRESSURE_RATIO_NUM_MEDIUM  15UL
#define MEMORYSTATUS_PRESSURE_RATIO_DENOM_MEDIUM  4UL
#define MEMORYSTATUS_REAPER_RATIO_NUM_MEDIUM 18UL
#define MEMORYSTATUS_REAPER_RATIO_DENOM_MEDIUM 4UL

static int32_t memorystatus_get_default_task_active_limit(proc_t p);
static int32_t memorystatus_get_default_task_inactive_limit(proc_t p);

/*
 * default jetsam snapshot support
 */
memorystatus_jetsam_snapshot_t *memorystatus_jetsam_snapshot;

#if CONFIG_FREEZE
memorystatus_jetsam_snapshot_t *memorystatus_jetsam_snapshot_freezer;
/*
 * The size of the freezer snapshot is given by memorystatus_jetsam_snapshot_max / JETSAM_SNAPSHOT_FREEZER_MAX_FACTOR
 * The freezer snapshot can be much smaller than the default snapshot
 * because it only includes apps that have been killed and dasd consumes it every 30 minutes.
 * Since the snapshots are always wired we don't want to overallocate too much.
 */
#define JETSAM_SNAPSHOT_FREEZER_MAX_FACTOR 20
unsigned int memorystatus_jetsam_snapshot_freezer_max;
unsigned int memorystatus_jetsam_snapshot_freezer_size;
TUNABLE(bool, memorystatus_jetsam_use_freezer_snapshot, "kern.jetsam_user_freezer_snapshot", true);

#define MEMORYSTATUS_FREEZE_THRESHOLD_PERCENTAGE 50UL
TUNABLE_DT(uint32_t, memorystatus_freeze_threshold_mb, "/defaults", "kern.memstat_freeze_mb",
    "memorystatus_freeze_threshold_mb", 0, TUNABLE_DT_NONE);
#endif /* CONFIG_FREEZE */

unsigned int memorystatus_jetsam_snapshot_count = 0;
unsigned int memorystatus_jetsam_snapshot_max = 0;
unsigned int memorystatus_jetsam_snapshot_size = 0;
uint64_t memorystatus_jetsam_snapshot_last_timestamp = 0;
uint64_t memorystatus_jetsam_snapshot_timeout = 0;

#if DEVELOPMENT || DEBUG
/*
 * On development and debug kernels, we allow one pid to take ownership
 * of some memorystatus data structures for testing purposes (via memorystatus_control).
 * If there's an owner, then only they may consume the jetsam snapshot & set freezer probabilities.
 * This is used when testing these interface to avoid racing with other
 * processes on the system that typically use them (namely OSAnalytics & dasd).
 */
static pid_t memorystatus_testing_pid = 0;
SYSCTL_INT(_kern, OID_AUTO, memorystatus_testing_pid, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_testing_pid, 0, "");
#endif /* DEVELOPMENT || DEBUG */

/*
 * jetsam zprint snapshot data
 */
#if JETSAM_ZPRINT_SNAPSHOT
static unsigned int        jzs_trigger_band = JETSAM_PRIORITY_FOREGROUND;
static mach_zone_name_t    *jzs_names = NULL;
static mach_zone_info_t    *jzs_info = NULL;
static int                *jzs_coalesce = NULL;
static unsigned int        jzs_zone_cnt = 0;
static mach_memory_info_t *jzs_meminfo = NULL;
static unsigned int        jzs_meminfo_cnt = 0;
static uint64_t            jzs_gencount = (uint64_t) -1ll;

#if DEVELOPMENT || DEBUG
SYSCTL_UINT(_kern, OID_AUTO, jzs_trigger_band, CTLFLAG_RW | CTLFLAG_LOCKED, &jzs_trigger_band, 0, "Priority band threshold for taking jetsam zprint snapshot");
#endif /* DEVELOPMENT || DEBUG */
#endif /* JETSAM_ZPRINT_SNAPSHOT */


static void memorystatus_init_jetsam_snapshot_header(memorystatus_jetsam_snapshot_t *snapshot);

/* General memorystatus stuff */

/*
 * Daemons: The actual idle deferred time for the daemon is based on
 * the relaunch behavior of the daemon. The relaunch behavior determines
 * the scaling factor applied to memorystatus_sysprocs_idle_delay_time. See
 * kJetsamSysProcsIdleDelayTime* ratios defined in kern_memorystatus.c
 *
 * Apps: The apps are aged for memorystatus_apps_idle_delay_time factored
 * by kJetsamAppsIdleDelayTimeRatio.
 */
TUNABLE(uint64_t, memstat_idle_deferral_time_s, "memorystatus_idle_deferral_time_s", 10);
TUNABLE(uint64_t, memstat_aging_stuck_time_s, "memorystatus_aging_stuck_time_s", 30);
uint64_t memorystatus_sysprocs_idle_delay_time = 0;
uint64_t memorystatus_apps_idle_delay_time = 0;
uint64_t memorystatus_aging_stuck_delay_time = 0;
/* 2GB devices support an entitlement for a higher app memory limit of "almost 2GB". */
static int32_t memorystatus_ios13extended_footprint_limit_mb = 1800;

#define CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT XNU_TARGET_OS_XR

/* Some devices give entitled apps a higher memory limit */
TUNABLE_DT_WRITEABLE(int32_t, memorystatus_entitled_max_task_footprint_mb,
    "/defaults", "kern.entitled_max_task_pmem",
    "entitled_max_task_pmem", 0, TUNABLE_DT_NONE);
TUNABLE_DT_WRITEABLE(int32_t, memorystatus_entitled_dev_max_task_footprint_mb,
    "/defaults", "kern.entitled_dev_max_task_pmem",
    "entitled_dev_max_task_pmem", 0, TUNABLE_DT_NONE);
#if CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
/* On visionOS, we want a separate high memory limit for bincompat (iOS) apps. */
TUNABLE_DT_WRITEABLE(int32_t, memorystatus_entitled_bincompat_max_task_footprint_mb,
    "/defaults", "kern.entitled_bc_max_task_pmem",
    "entitled_bincompat_max_task_pmem", 0, TUNABLE_DT_NONE);
#endif // CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT

#if __arm64__
#if DEVELOPMENT || DEBUG
SYSCTL_INT(_kern, OID_AUTO, ios13extended_footprint_limit_mb,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &memorystatus_ios13extended_footprint_limit_mb, 0, "");
SYSCTL_INT(_kern, OID_AUTO, entitled_max_task_pmem,
    CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_KERN,
    &memorystatus_entitled_max_task_footprint_mb, 0, "");
SYSCTL_INT(_kern, OID_AUTO, entitled_dev_max_task_pmem,
    CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_KERN,
    &memorystatus_entitled_dev_max_task_footprint_mb, 0, "");
#if CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
SYSCTL_INT(_kern, OID_AUTO, entitled_bincompat_max_task_pmem,
    CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_KERN,
    &memorystatus_entitled_bincompat_max_task_footprint_mb, 0, "");
#endif /* CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT */
#else /* !(DEVELOPMENT || DEBUG) */
SYSCTL_INT(_kern, OID_AUTO, entitled_max_task_pmem,
    CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_KERN,
    &memorystatus_entitled_max_task_footprint_mb, 0, "");
#if CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
SYSCTL_INT(_kern, OID_AUTO, entitled_bincompat_max_task_pmem,
    CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_KERN,
    &memorystatus_entitled_bincompat_max_task_footprint_mb, 0, "");
#endif /* CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT */
#endif /* DEVELOPMENT || DEBUG */
#endif /* __arm64__ */

#pragma mark Logging

os_log_t memorystatus_log_handle;

TUNABLE_WRITEABLE(memorystatus_log_level_t, memorystatus_log_level, "memorystatus_log_level", MEMORYSTATUS_LOG_LEVEL_DEFAULT);

#if DEBUG || DEVELOPMENT
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_log_level, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_log_level, MEMORYSTATUS_LOG_LEVEL_DEFAULT, "");
#endif

#pragma mark Locks

static LCK_GRP_DECLARE(memorystatus_lock_group, "memorystatus");

/* Synchronizes jetsam pressure broadcasts */
LCK_MTX_DECLARE(memorystatus_jetsam_broadcast_lock, &memorystatus_lock_group);

#if DEVELOPMENT || DEBUG
static LCK_MTX_DECLARE(disconnect_page_mappings_mutex, &memorystatus_lock_group);
#endif /* DEVELOPMENT || DEBUG */

/* Idle guard handling */

static void memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2);
static void _memstat_invalidate_idle_demotion_locked(proc_t p);
static void _memstat_schedule_idle_demotion_locked(proc_t p);
static void _memstat_reschedule_idle_demotion_locked(void);
int memorystatus_update_priority_for_appnap(proc_t p, boolean_t is_appnap);
vm_pressure_level_t convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);
boolean_t is_knote_registered_modify_task_pressure_bits(struct knote*, int, task_t, vm_pressure_level_t, vm_pressure_level_t);
void memorystatus_klist_reset_all_for_level(vm_pressure_level_t pressure_level_to_clear);
void memorystatus_send_low_swap_note(void);
boolean_t memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, unsigned int band, int aggr_count,
    uint32_t *errors, uint64_t *memory_reclaimed);
uint64_t memorystatus_available_memory_internal(proc_t p);
void memorystatus_thread_wake(void);
static bool _memstat_consider_waking_jetsam_thread(void);
#if CONFIG_JETSAM
static void memorystatus_thread_pool_default(void);
static void memorystatus_thread_pool_max(void);
#endif /* CONFIG_JETSAM */

unsigned int memorystatus_level = 0;
static int memorystatus_list_count = 0;
memstat_bucket_t memstat_bucket[MEMSTAT_BUCKET_COUNT];
static thread_call_t memorystatus_idle_demotion_call;
uint64_t memstat_idle_demotion_deadline = 0;
#if CONFIG_FREEZE
unsigned int memorystatus_suspended_count = 0;
#endif /* CONFIG_FREEZE */

#ifdef XNU_TARGET_OS_OSX
/*
 * Effectively disable the system process and application demotion
 * logic on macOS. This means system processes and apps won't get the
 * 10 second protection before landing in the IDLE band after moving
 * out of their active band. Reasons:-
 * - daemons + extensions + apps on macOS don't behave the way they
 *   do on iOS and so they are confusing the demotion logic. For example,
 *   not all apps go from FG to IDLE. Some sit in higher bands instead. This
 *   is causing multiple asserts to fire internally.
 * - we use the aging bands to protect processes from jetsam. But on macOS,
 *   we have a very limited jetsam that is only invoked under extreme conditions
 *   where we have no more swap / compressor space OR are under critical pressure.
 */
int system_procs_aging_band = 0;
int system_procs_aging_band_stuck = 0;
int applications_aging_band = 0;
#else /* XNU_TARGET_OS_OSX */
int system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
int system_procs_aging_band_stuck = JETSAM_PRIORITY_AGING_BAND1_STUCK;
int applications_aging_band = JETSAM_PRIORITY_AGING_BAND2;
#endif /* XNU_TARGET_OS_OSX */

/* the jetsam band which will contain P_MEMSTAT_FROZEN processes */
#if CONFIG_FREEZE
int memorystatus_freeze_jetsam_band = JETSAM_PRIORITY_FREEZER;
#else /* CONFIG_FREEZE */
int memorystatus_freeze_jetsam_band = 0;
#endif /* CONFIG_FREEZE */

_Atomic bool memorystatus_zone_map_is_exhausted = false;
_Atomic bool memorystatus_compressor_space_shortage = false;
_Atomic bool memorystatus_pageout_starved = false;
#if CONFIG_PHANTOM_CACHE
_Atomic bool memorystatus_phantom_cache_pressure = false;
#endif /* CONFIG_PHANTOM_CACHE */

bool memorystatus_should_issue_fg_band_notify = true;

extern void coalition_mark_swappable(coalition_t coal);
extern bool coalition_is_swappable(coalition_t coal);
boolean_t memorystatus_allowed_vm_map_fork(task_t, bool *);
#if DEVELOPMENT || DEBUG
void memorystatus_abort_vm_map_fork(task_t);
#endif

SYSCTL_NODE(_kern, OID_AUTO, memorystatus,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "memorystatus subsystem");

/*
 * Idle delay timeout factors for daemons based on relaunch behavior. Only used in
 * kJetsamAgingPolicySysProcsReclaimedFirst aging policy.
 */
#define kJetsamSysProcsIdleDelayTimeLowRatio    (5)
#define kJetsamSysProcsIdleDelayTimeMedRatio    (2)
#define kJetsamSysProcsIdleDelayTimeHighRatio   (1)

/*
 * For the kJetsamAgingPolicySysProcsReclaimedFirst aging policy, treat apps as well
 * behaved daemons for aging purposes.
 */
#define kJetsamAppsIdleDelayTimeRatio   (kJetsamSysProcsIdleDelayTimeLowRatio)

static uint64_t
memorystatus_sysprocs_idle_time(proc_t p)
{
	uint64_t idle_delay_time = 0;
	/*
	 * For system processes, base the idle delay time on the
	 * jetsam relaunch behavior specified by launchd. The idea
	 * is to provide extra protection to the daemons which would
	 * relaunch immediately after jetsam.
	 */
	switch (p->p_memstat_relaunch_flags) {
	case P_MEMSTAT_RELAUNCH_UNKNOWN:
	case P_MEMSTAT_RELAUNCH_LOW:
		idle_delay_time = memorystatus_sysprocs_idle_delay_time / kJetsamSysProcsIdleDelayTimeLowRatio;
		break;
	case P_MEMSTAT_RELAUNCH_MED:
		idle_delay_time = memorystatus_sysprocs_idle_delay_time / kJetsamSysProcsIdleDelayTimeMedRatio;
		break;
	case P_MEMSTAT_RELAUNCH_HIGH:
		idle_delay_time = memorystatus_sysprocs_idle_delay_time / kJetsamSysProcsIdleDelayTimeHighRatio;
		break;
	default:
		panic("Unknown relaunch flags on process!");
		break;
	}
	return idle_delay_time;
}

static uint64_t
memorystatus_apps_idle_time(__unused proc_t p)
{
	return memorystatus_apps_idle_delay_time / kJetsamAppsIdleDelayTimeRatio;
}

static uint64_t
_memstat_sysprocs_aging_stuck_delay_time(__unused proc_t p)
{
	return memorystatus_aging_stuck_delay_time;
}


static int
sysctl_jetsam_set_sysprocs_idle_delay_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	int error = 0, val = 0, old_time_in_secs = 0;
	uint64_t old_time_in_ns = 0;

	absolutetime_to_nanoseconds(memorystatus_sysprocs_idle_delay_time, &old_time_in_ns);
	old_time_in_secs = (int) (old_time_in_ns / NSEC_PER_SEC);

	error = sysctl_io_number(req, old_time_in_secs, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
		return error;
	}

	if ((val < 0) || (val > INT32_MAX)) {
		memorystatus_log_error("jetsam: new idle delay interval has invalid value.\n");
		return EINVAL;
	}

	nanoseconds_to_absolutetime((uint64_t)val * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);

	return 0;
}

SYSCTL_PROC(_kern_memorystatus, OID_AUTO, sysprocs_idle_delay_time_ns, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_jetsam_set_sysprocs_idle_delay_time, "I", "Aging window for system processes");


static int
sysctl_jetsam_set_apps_idle_delay_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	int error = 0, val = 0, old_time_in_secs = 0;
	uint64_t old_time_in_ns = 0;

	absolutetime_to_nanoseconds(memorystatus_apps_idle_delay_time, &old_time_in_ns);
	old_time_in_secs = (int) (old_time_in_ns / NSEC_PER_SEC);

	error = sysctl_io_number(req, old_time_in_secs, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
		return error;
	}

	if ((val < 0) || (val > INT32_MAX)) {
		memorystatus_log_error("jetsam: new idle delay interval has invalid value.\n");
		return EINVAL;
	}

	nanoseconds_to_absolutetime((uint64_t)val * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);

	return 0;
}

SYSCTL_PROC(_kern_memorystatus, OID_AUTO, apps_idle_delay_time_ns, CTLTYPE_INT | CTLFLAG_RW,
    0, 0, sysctl_jetsam_set_apps_idle_delay_time, "I", "Aging window for applications");

SYSCTL_INT(_kern, OID_AUTO, max_task_pmem, CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_KERN, &max_task_footprint_mb, 0, "");

#if __arm64__
int legacy_footprint_bonus_mb = 50; /* This value was chosen after looking at the top 30 apps
                                     * that needed the additional room in their footprint when
                                     * the 'correct' accounting methods were applied to them.
                                     */

#if DEVELOPMENT || DEBUG
SYSCTL_INT(_kern, OID_AUTO, legacy_footprint_bonus_mb, CTLFLAG_RW | CTLFLAG_LOCKED, &legacy_footprint_bonus_mb, 0, "");
#endif /* DEVELOPMENT || DEBUG */
/*
 * Raise the inactive and active memory limits to new values.
 * Will only raise the limits and will do nothing if either of the current
 * limits are 0.
 * Caller must hold the proc_list_lock
 */
static void
memorystatus_raise_memlimit_locked(proc_t p,
    int new_memlimit_active,
    int new_memlimit_inactive)
{
	int memlimit_mb_active = 0, memlimit_mb_inactive = 0;
	memlimit_options_t memlimit_options = MEMLIMIT_OPTIONS_NONE;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	if (p->p_memstat_memlimit_active > 0) {
		memlimit_mb_active = p->p_memstat_memlimit_active;
	} else if (p->p_memstat_memlimit_active == -1) {
		memlimit_mb_active = max_task_footprint_mb;
	} else {
		/*
		 * Nothing to do for '0' which is
		 * a special value only used internally
		 * to test 'no limits'.
		 */
		return;
	}

	if (p->p_memstat_memlimit_inactive > 0) {
		memlimit_mb_inactive = p->p_memstat_memlimit_inactive;
	} else if (p->p_memstat_memlimit_inactive == -1) {
		memlimit_mb_inactive = max_task_footprint_mb;
	} else {
		/*
		 * Nothing to do for '0' which is
		 * a special value only used internally
		 * to test 'no limits'.
		 */
		return;
	}

	memlimit_mb_active = MAX(new_memlimit_active, memlimit_mb_active);
	memlimit_mb_inactive = MAX(new_memlimit_inactive, memlimit_mb_inactive);

	/* Maintain pre-existing limit fatality */
	if (_memstat_proc_active_memlimit_is_fatal(p)) {
		memlimit_options |= MEMLIMIT_ACTIVE_FATAL;
	}
	if (_memstat_proc_inactive_memlimit_is_fatal(p)) {
		memlimit_options |= MEMLIMIT_INACTIVE_FATAL;
	}

	memstat_set_memlimits_locked(p, memlimit_mb_active,
	    memlimit_mb_inactive, memlimit_options);
}

void
memorystatus_act_on_legacy_footprint_entitlement(proc_t p, boolean_t footprint_increase)
{
	int memlimit_mb_active = 0, memlimit_mb_inactive = 0;

	if (p == NULL) {
		return;
	}

	proc_list_lock();

	if (p->p_memstat_memlimit_active > 0) {
		memlimit_mb_active = p->p_memstat_memlimit_active;
	} else if (p->p_memstat_memlimit_active == -1) {
		memlimit_mb_active = max_task_footprint_mb;
	} else {
		/*
		 * Nothing to do for '0' which is
		 * a special value only used internally
		 * to test 'no limits'.
		 */
		proc_list_unlock();
		return;
	}

	if (p->p_memstat_memlimit_inactive > 0) {
		memlimit_mb_inactive = p->p_memstat_memlimit_inactive;
	} else if (p->p_memstat_memlimit_inactive == -1) {
		memlimit_mb_inactive = max_task_footprint_mb;
	} else {
		/*
		 * Nothing to do for '0' which is
		 * a special value only used internally
		 * to test 'no limits'.
		 */
		proc_list_unlock();
		return;
	}

	if (footprint_increase) {
		memlimit_mb_active += legacy_footprint_bonus_mb;
		memlimit_mb_inactive += legacy_footprint_bonus_mb;
	} else {
		memlimit_mb_active -= legacy_footprint_bonus_mb;
		if (memlimit_mb_active == max_task_footprint_mb) {
			memlimit_mb_active = -1; /* reverting back to default system limit */
		}

		memlimit_mb_inactive -= legacy_footprint_bonus_mb;
		if (memlimit_mb_inactive == max_task_footprint_mb) {
			memlimit_mb_inactive = -1; /* reverting back to default system limit */
		}
	}
	memorystatus_raise_memlimit_locked(p, memlimit_mb_active, memlimit_mb_inactive);

	proc_list_unlock();
}

void
memorystatus_act_on_ios13extended_footprint_entitlement(proc_t p)
{
	proc_list_lock();
	memorystatus_raise_memlimit_locked(p,
	    memorystatus_ios13extended_footprint_limit_mb,
	    memorystatus_ios13extended_footprint_limit_mb);
	proc_list_unlock();
}

void
memorystatus_act_on_entitled_task_limit(proc_t p)
{
	int memlimit;
	if (memorystatus_entitled_max_task_footprint_mb == 0) {
		// Entitlement is not supported on this device.
		return;
	}
	proc_list_lock();
#if CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
	// We want a separate memory limit for bincompat (iPad) apps on visionOS.
	switch (proc_platform(p)) {
	case PLATFORM_XROS:
	case PLATFORM_XROSSIMULATOR:
		memlimit = memorystatus_entitled_max_task_footprint_mb;
		break;
	default:
		if (memorystatus_entitled_bincompat_max_task_footprint_mb != 0) {
			memlimit = memorystatus_entitled_bincompat_max_task_footprint_mb;
		} else {
			memlimit = memorystatus_entitled_max_task_footprint_mb;
		}
		break;
	}
#else // CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
	memlimit = memorystatus_entitled_max_task_footprint_mb;
#endif // !CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
	memorystatus_raise_memlimit_locked(p, memlimit, memlimit);
	proc_list_unlock();
}

void
memorystatus_act_on_entitled_developer_task_limit(proc_t p)
{
	if (memorystatus_entitled_dev_max_task_footprint_mb == 0) {
		// Entitlement not supported on this device
		return;
	}
	memorystatus_log("memorystatus: WARNING %s [%d] is receiving an entitled "
	    "debugging memory limit. This is intended only for debugging and "
	    "can result in unstable device behavior.",
	    proc_best_name(p), proc_getpid(p));
	proc_list_lock();
	memorystatus_raise_memlimit_locked(p,
	    memorystatus_entitled_dev_max_task_footprint_mb,
	    memorystatus_entitled_dev_max_task_footprint_mb);
	proc_list_unlock();
}

#endif /* __arm64__ */

SYSCTL_INT(_kern, OID_AUTO, memorystatus_level, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_level, 0, "");

int
memorystatus_get_level(__unused struct proc *p, struct memorystatus_get_level_args *args, __unused int *ret)
{
	user_addr_t     level = 0;

	level = args->level;

	if (copyout(&memorystatus_level, level, sizeof(memorystatus_level)) != 0) {
		return EFAULT;
	}

	return 0;
}

static void memorystatus_thread(void *param __unused, wait_result_t wr __unused);

/* Memory Limits */

static bool memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);
static bool memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);


static int memorystatus_cmd_set_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

#if DEBUG || DEVELOPMENT
static int memorystatus_cmd_set_diag_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);
static int memorystatus_cmd_get_diag_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);
static int memorystatus_set_diag_memlimit_properties_internal(proc_t p, memorystatus_diag_memlimit_properties_t *p_entry);
static int memorystatus_get_diag_memlimit_properties_internal(proc_t p, memorystatus_diag_memlimit_properties_t *p_entry);
#endif  // DEBUG || DEVELOPMENT
static int memorystatus_set_memlimit_properties(pid_t pid, memorystatus_memlimit_properties_t *entry);

static int memorystatus_cmd_get_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static int memorystatus_cmd_get_memlimit_excess_np(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval);

static void memorystatus_get_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t *p_entry);

int proc_get_memstat_priority(proc_t, boolean_t);

static boolean_t memorystatus_idle_snapshot = 0;

unsigned int memorystatus_delta = 0;

/* Jetsam Loop Detection */
boolean_t memorystatus_jld_enabled = FALSE;              /* Enable jetsam loop detection */
uint32_t memorystatus_jld_eval_period_msecs = 0;         /* Init pass sets this based on device memory size */
int      memorystatus_jld_max_kill_loops = 2;            /* How many times should we try and kill up to the target band */

/*
 * A FG app can request that the aggressive jetsam mechanism display some leniency in the FG band. This 'lenient' mode is described as:
 * --- if aggressive jetsam kills an app in the FG band and gets back >=AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD memory, it will stop the aggressive march further into and up the jetsam bands.
 *
 * RESTRICTIONS:
 * - Such a request is respected/acknowledged only once while that 'requesting' app is in the FG band i.e. if aggressive jetsam was
 * needed and the 'lenient' mode was deployed then that's it for this special mode while the app is in the FG band.
 *
 * - If the app is still in the FG band and aggressive jetsam is needed again, there will be no stop-and-check the next time around.
 *
 * - Also, the transition of the 'requesting' app away from the FG band will void this special behavior.
 */

#define AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD        25
boolean_t       memorystatus_aggressive_jetsam_lenient_allowed = FALSE;
boolean_t       memorystatus_aggressive_jetsam_lenient = FALSE;

#if DEVELOPMENT || DEBUG
/*
 * Jetsam Loop Detection tunables.
 */

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_period_msecs, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_eval_period_msecs, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_max_kill_loops, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_max_kill_loops, 0, "");
#endif /* DEVELOPMENT || DEBUG */

/*
 * snapshot support for memstats collected at boot.
 */
static memorystatus_jetsam_snapshot_t memorystatus_at_boot_snapshot;

static void memorystatus_init_jetsam_snapshot_locked(memorystatus_jetsam_snapshot_t *od_snapshot, uint32_t ods_list_count);
static boolean_t memorystatus_init_jetsam_snapshot_entry_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry, uint64_t gencount);
static void memorystatus_update_jetsam_snapshot_entry_locked(proc_t p, uint32_t kill_cause, uint64_t killtime);

static void memorystatus_clear_errors(void);

static void memorystatus_get_task_phys_footprint_page_counts(task_t task,
    uint64_t *internal_pages, uint64_t *internal_compressed_pages,
    uint64_t *purgeable_nonvolatile_pages, uint64_t *purgeable_nonvolatile_compressed_pages,
    uint64_t *alternate_accounting_pages, uint64_t *alternate_accounting_compressed_pages,
    uint64_t *iokit_mapped_pages, uint64_t *page_table_pages, uint64_t *frozen_to_swap_pages,
    uint64_t *neural_nofootprint_total_pages);

static void memorystatus_get_task_memory_region_count(task_t task, uint64_t *count);

static memorystatus_proc_state_t _memstat_build_state(proc_t p);
//static boolean_t memorystatus_issue_pressure_kevent(boolean_t pressured);

static bool memorystatus_kill_top_process(bool any, bool sort_flag, uint32_t cause, os_reason_t jetsam_reason,
    int32_t max_priority, bool only_swappable, bool only_long_idle,
    int32_t *priority, uint32_t *errors, uint64_t *memory_reclaimed);
static bool memorystatus_kill_processes_aggressive(uint32_t cause, int aggr_count, int32_t priority_max, int32_t max_kills, uint32_t *errors, uint64_t *memory_reclaimed);
static boolean_t memorystatus_kill_hiwat_proc(uint32_t *errors, boolean_t *purged, uint64_t *memory_reclaimed);
static bool _memstat_proc_is_reapable(proc_t p);
static void _memstat_refresh_oldest_reapable_proc_info(void);

#if CONFIG_JETSAM
static void _memstat_reaper_check_oldest_reapable_proc_info_timeout(void);
static void _memstat_reaper_start_sweep(void);
static void _memstat_reaper_end_sweep(void);
static void _memstat_reaper_record_kill(uint64_t bytes_freed);
#endif /* CONFIG_JETSAM */
static const char* _memstat_relaunch_flags_description(uint32_t flags);


/* Priority Band Sorting Routines */
static int  memorystatus_sort_bucket(unsigned int bucket_index, int sort_order);
static int  memorystatus_sort_by_largest_coalition_locked(unsigned int bucket_index, int coal_sort_order);
static void memorystatus_sort_by_largest_process_locked(unsigned int bucket_index);
static int  memorystatus_move_list_locked(unsigned int bucket_index, pid_t *pid_list, int list_sz);

/* qsort routines */
typedef int (*cmpfunc_t)(const void *a, const void *b);
extern void qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);
static int memstat_asc_cmp(const void *a, const void *b);

/* VM pressure */

#if CONFIG_SECLUDED_MEMORY
extern unsigned int     vm_page_secluded_count;
extern unsigned int     vm_page_secluded_count_over_target;
#endif /* CONFIG_SECLUDED_MEMORY */

/* Aggressive jetsam pages threshold for sysproc aging policy */
unsigned int memorystatus_sysproc_aging_aggr_pages = 0;

uint32_t memorystatus_available_pages = UINT32_MAX;

__options_closed_decl(memorystatus_policy_t, uint8_t, {
	kPolicyDefault        = 0x00,
	kPolicyClearTheDecks  = 0x01,
	kPolicyBallastDrain   = 0x02,
});

static memorystatus_policy_t memstat_policy_config = kPolicyDefault;

#define MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX ((uint32_t)(atop_64(max_mem) / 2))

/*
 * Jetsam Page Shortage Thresholds (PSTs):
 *  - critical: jetsam above the idle band
 *  - idle: jetsam in the idle band
 *  - pressure: jetsam soft memory limit violators
 *  - reaper: jetsam long-idle processes
 *  - ballast: offset applied to non-critical thresholds upon request
 *    from userspace
 *  - ctd (clear-the-decks): offset applied to non-critical thresholds upon request
 *    from userspace
 */
uint32_t memstat_critical_threshold = 0;
uint32_t memstat_idle_threshold = 0;
uint32_t memstat_soft_threshold = 0;
uint32_t memstat_reaper_threshold = 0;
uint32_t memstat_ballast_offset = 0;
uint32_t memstat_ctd_offset = 0;

int32_t  memstat_reaper_min_age_secs = MEMORYSTATUS_REAPER_MIN_AGE_SECS_DEFAULT;
boolean_t memstat_reaper_enabled = MEMORYSTATUS_REAPER_ENABLED_DEFAULT;
uint32_t memstat_reaper_max_priority = MEMORYSTATUS_REAPER_MAX_PRIORITY_DEFAULT;
int32_t  memstat_reaper_rescan_secs = MEMORYSTATUS_REAPER_RESCAN_SECS_DEFAULT;
bool     memstat_reaper_is_currently_sweeping = false;
uint64_t memstat_reaper_can_run_after_ts_matu = 0;
uint64_t memstat_reaper_start_ts_matu = 0;

uint32_t memstat_reaper_reap_relaunch_mask = MEMORYSTATUS_REAPER_REAP_RELAUNCH_MASK_DEFAULT;

#define MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_UNKNOWN UINT64_MAX
#define MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_NONE    (UINT64_MAX-1)
uint64_t memstat_oldest_reapable_proc_prio_start = MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_UNKNOWN;
uint64_t memstat_oldest_reapable_proc_info_expiration_ts_matu = 0;

uint64_t memstat_oldest_reapable_proc_will_be_reapable_at_ts_matu = 0;

typedef struct memstat_reaper_stats {
	uint32_t sweep_count;
	uint32_t kill_count;
	uint64_t memory_freed_bytes;
} memstat_reaper_stats_t;

memstat_reaper_stats_t memstat_reaper_current_sweep_stats;
memstat_reaper_stats_t memstat_reaper_cumulative_stats;
uint32_t memstat_reaper_cumulative_memory_freed_mb = 0;
/*
 * NB: These MiB thresholds are only read at boot and may become out of sync
 * with the PSTs above.
 */
TUNABLE_DT(uint32_t, memorystatus_critical_threshold_mb, "/defaults",
    "kern.memstat_critical_mb", "memorystatus_critical_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_idle_threshold_mb, "/defaults",
    "kern.memstat_idle_mb", "memorystatus_idle_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_pressure_threshold_mb, "/defaults",
    "kern.memstat_pressure_mb", "memorystatus_pressure_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_reaper_threshold_mb, "/defaults",
    "kern.memstat_reaper_mb", "memorystatus_reaper_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memstat_ballast_offset_mb, "/defaults",
    "kern.memstat_ballast_mb", "memstat_ballast_offset_mb", 0, TUNABLE_DT_NONE);
TUNABLE(uint32_t, memstat_ctd_offset_mb, "memstat_ballast_offset_mb", 0);

/*
 * Kill count tracking
 *
 * Since idle exit is only applicable to processes in the idle band, track it
 * separately to save space. We also don't care about kMemorysatusInvalid.
 */
uint32_t _Atomic memorystatus_kill_counts[JETSAM_PRIORITY_MAX + 1][JETSAM_REASON_MEMORYSTATUS_MAX - 1];
uint32_t _Atomic memorystatus_idle_exit_kill_count = 0;

TUNABLE_DT(int32_t, memorystatus_reaper_minimum_age_seconds, "/defaults",
    "kern.memstat_reaper_minage_secs", "memorystatus_reaper_minimum_age_seconds", MEMORYSTATUS_REAPER_MIN_AGE_SECS_DEFAULT, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_reaper_rescan_delay_seconds, "/defaults",
    "kern.memstat_reaper_rescan_secs", "memorystatus_reaper_rescan_delay_seconds", MEMORYSTATUS_REAPER_RESCAN_SECS_DEFAULT, TUNABLE_DT_NONE);
TUNABLE_DT(bool, memorystatus_reaper_enabled, "/defaults",
    "kern.memstat_reaper_enabled", "memorystatus_reaper_enabled", MEMORYSTATUS_REAPER_ENABLED_DEFAULT, TUNABLE_DT_NONE);


#if CONFIG_JETSAM
TUNABLE_DT_WRITEABLE(unsigned int, memorystatus_swap_all_apps, "/defaults", "kern.swap_all_apps", "kern.swap_all_apps", false, TUNABLE_DT_NONE);
/* Will compact the early swapin queue if there are >= this many csegs on it. */
static unsigned int memorystatus_swapin_trigger_segments = 10;
unsigned int memorystatus_swapin_trigger_pages = 0;

#if DEVELOPMENT || DEBUG
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_available_pages, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_swapin_trigger_pages, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_swapin_trigger_pages, 0, "");
#else
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages, CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, &memorystatus_available_pages, 0, "");
#endif /* DEVELOPMENT || DEBUG */
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_swap_all_apps, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_swap_all_apps, 0, "");

static int memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit);

proc_name_t memorystatus_jetsam_proc_name_panic; /* Panic when we are about to jetsam this process. */
uint32_t    memorystatus_jetsam_proc_cause_panic = 0; /* If specified, panic only when we are about to jetsam the process above for this cause. */
uint32_t    memorystatus_jetsam_proc_size_panic = 0; /* If specified, panic only when we are about to jetsam the process above and its footprint is more than this in MB. */

/* If set, kill swappable processes when we're low on swap space. Currently off until we can allocate more swap space (rdar://87800902) */
TUNABLE(bool, jetsam_kill_on_low_swap, "jetsam_kill_on_low_swap", false);

/*
 * Global switch for enabling fast jetsam. Fast jetsam is
 * hooked up via the system_override() system call. When
 * enabled, the following features can be toggled:
 * - clear-the-decks jetsam
 * - ballast-drain jetsam
 */
TUNABLE_WRITEABLE(bool, fast_jetsam_enabled, "fast_jetsam_enabled", true);

#else /* !CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG
TUNABLE(bool, kill_on_no_paging_space, "-kill_on_no_paging_space", false);
#else /* !(DEVELOPMENT || DEBUG) */
bool kill_on_no_paging_space = false;
#endif /* DEVELOPMENT || DEBUG */

/* The timestamp (MAS) of the last no paging space action */
_Atomic uint64_t last_no_space_action_ts = 0;
/* The minimum duration between no paging space actions */
TUNABLE(uint64_t, no_paging_space_action_throttle_delay_ns,
    "no_paging_space_throttle_delay_ns", 5 * NSEC_PER_SEC);

#endif /* CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG
static inline uint32_t
roundToNearestMB(uint32_t in)
{
	return (in + ((1 << 20) - 1)) >> 20;
}

static int memorystatus_cmd_increase_jetsam_task_limit(pid_t pid, uint32_t byte_increase);
#endif

#if __arm64__
extern int legacy_footprint_entitlement_mode;
#endif /* __arm64__ */

/* Debug */

extern struct knote *vm_find_knote_from_pid(pid_t, struct klist *);

#if DEVELOPMENT || DEBUG

static unsigned int memorystatus_debug_dump_this_bucket = 0;

static void
memorystatus_debug_dump_bucket_locked(unsigned int bucket_index)
{
	proc_t p = NULL;
	uint64_t bytes = 0;
	int ledger_limit = 0;
	unsigned int b = bucket_index;
	boolean_t traverse_all_buckets = FALSE;

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		traverse_all_buckets = TRUE;
		b = 0;
	} else {
		traverse_all_buckets = FALSE;
		b = bucket_index;
	}

	/*
	 * footprint reported in [pages / MB ]
	 * limits reported as:
	 *      L-limit  proc's Ledger limit
	 *      C-limit  proc's Cached limit, should match Ledger
	 *      A-limit  proc's Active limit
	 *     IA-limit  proc's Inactive limit
	 *	F==Fatal,  NF==NonFatal
	 */

	memorystatus_log_debug("memorystatus_debug_dump ***START*(PAGE_SIZE_64=%llu)**\n", PAGE_SIZE_64);
	memorystatus_log_debug("bucket [pid]       [pages / MB]     [state]      [EP / RP / AP]   dirty     deadline [L-limit / C-limit / A-limit / IA-limit] name\n");
	p = memorystatus_get_first_proc_locked(&b, traverse_all_buckets);
	while (p) {
		bytes = get_task_phys_footprint(proc_task(p));
		task_get_phys_footprint_limit(proc_task(p), &ledger_limit);
		memorystatus_log_debug("%2d     [%5d]     [%5lld /%3lldMB]   0x%-8x   [%2d / %2d / %2d]   0x%-3x   %10lld    [%3d / %3d%s / %3d%s / %3d%s]   %s\n",
		    b, proc_getpid(p),
		    (bytes / PAGE_SIZE_64),             /* task's footprint converted from bytes to pages     */
		    (bytes / (1024ULL * 1024ULL)),      /* task's footprint converted from bytes to MB */
		    p->p_memstat_state, p->p_memstat_effectivepriority, p->p_memstat_requestedpriority, p->p_memstat_assertionpriority,
		    p->p_memstat_dirty, p->p_memstat_idledeadline,
		    ledger_limit,
		    p->p_memstat_memlimit,
		    (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"),
		    p->p_memstat_memlimit_active,
		    (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL ? "F " : "NF"),
		    p->p_memstat_memlimit_inactive,
		    (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL ? "F " : "NF"),
		    (*p->p_name ? p->p_name : "unknown"));
		p = memorystatus_get_next_proc_locked(&b, p, traverse_all_buckets);
	}
	memorystatus_log_debug("memorystatus_debug_dump ***END***\n");
}

static int
sysctl_memorystatus_debug_dump_bucket SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int bucket_index = 0;
	int error;
	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}
	error = SYSCTL_IN(req, &bucket_index, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}
	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		/*
		 * All jetsam buckets will be dumped.
		 */
	} else {
		/*
		 * Only a single bucket will be dumped.
		 */
	}

	proc_list_lock();
	memorystatus_debug_dump_bucket_locked(bucket_index);
	proc_list_unlock();
	memorystatus_debug_dump_this_bucket = bucket_index;
	return error;
}

/*
 * Debug aid to look at jetsam buckets and proc jetsam fields.
 *	Use this sysctl to act on a particular jetsam bucket.
 *	Writing the sysctl triggers the dump.
 *      Usage: sysctl kern.memorystatus_debug_dump_this_bucket=<bucket_index>
 */

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_debug_dump_this_bucket, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_debug_dump_this_bucket, 0, sysctl_memorystatus_debug_dump_bucket, "I", "");


/* Debug aid to aid determination of limit */

static int
sysctl_memorystatus_highwater_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	proc_t p;
	unsigned int b = 0;
	int error, enable = 0;
	bool use_active;   /* use the active limit and active limit attributes */

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}

	error = SYSCTL_IN(req, &enable, sizeof(int));
	if (error || !req->newptr) {
		return error;
	}

	if (!(enable == 0 || enable == 1)) {
		return EINVAL;
	}

	proc_list_lock();

	memorystatus_highwater_enabled = enable;

	p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (p) {
		use_active = memstat_proc_is_active_locked(p);

		if (enable) {
			(void)memstat_update_memlimit_locked(p, use_active);
		} else {
			/*
			 * Disabling limits does not touch the stored variants.
			 * Set the cached limit fields to system_wide defaults.
			 */
			p->p_memstat_memlimit = -1;
			p->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		_memstat_write_memlimit_to_ledger_locked(p, use_active, false);

		p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	}


	proc_list_unlock();

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_highwater_enabled, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_highwater_enabled, 0, sysctl_memorystatus_highwater_enable, "I", "");

SYSCTL_INT(_kern, OID_AUTO, memorystatus_idle_snapshot, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_idle_snapshot, 0, "");

#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
static int
memstat_page_shortage_threshold_sysctl_handler SYSCTL_HANDLER_ARGS
{
	uint32_t threshold;
	if (arg1 == &memstat_idle_threshold) {
		threshold = memorystatus_get_idle_exit_page_shortage_threshold();
	} else if (arg1 == &memstat_soft_threshold) {
		threshold = memorystatus_get_soft_memlimit_page_shortage_threshold();
	} else if (arg1 == &memstat_critical_threshold) {
		threshold = memorystatus_get_critical_page_shortage_threshold();
	} else if (arg1 == &memstat_reaper_threshold) {
		threshold = memorystatus_get_reaper_page_shortage_threshold();
	} else {
		return EINVAL;
	}
	return sysctl_handle_int(oidp, NULL, threshold, req);
}

SYSCTL_PROC(_kern_memorystatus, OID_AUTO, available_pages_critical,
    CTLFLAG_RD | CTLFLAG_LOCKED, &memstat_critical_threshold, 0,
    memstat_page_shortage_threshold_sysctl_handler, "IU",
    "");
SYSCTL_PROC(_kern_memorystatus, OID_AUTO, available_pages_idle,
    CTLFLAG_RD | CTLFLAG_LOCKED, &memstat_idle_threshold, 0,
    memstat_page_shortage_threshold_sysctl_handler, "IU",
    "");
SYSCTL_PROC(_kern_memorystatus, OID_AUTO, available_pages_soft,
    CTLFLAG_RD | CTLFLAG_LOCKED, &memstat_soft_threshold, 0,
    memstat_page_shortage_threshold_sysctl_handler, "IU",
    "");
SYSCTL_PROC(_kern_memorystatus, OID_AUTO, available_pages_reaper,
    CTLFLAG_RD | CTLFLAG_LOCKED, &memstat_reaper_threshold, 0,
    memstat_page_shortage_threshold_sysctl_handler, "IU",
    "");

SYSCTL_INT(_kern_memorystatus, OID_AUTO, ballast_offset_pages,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &memstat_ballast_offset, 0, "");
SYSCTL_INT(_kern_memorystatus, OID_AUTO, ctd_offset_pages,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &memstat_ctd_offset, 0, "");
#endif /* DEVELOPMENT || DEBUG */

EXPERIMENT_FACTOR_UINT(_kern_memorystatus, reaper_enabled, &memstat_reaper_enabled, FALSE, TRUE, "");
EXPERIMENT_FACTOR_UINT(_kern_memorystatus, reaper_min_age_secs, &memstat_reaper_min_age_secs, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern_memorystatus, reaper_max_priority, &memstat_reaper_max_priority, 0, JETSAM_PRIORITY_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern_memorystatus, reaper_reap_relaunch_mask, &memstat_reaper_reap_relaunch_mask, 0, UINT32_MAX, "");
EXPERIMENT_FACTOR_UINT(_kern_memorystatus, reaper_rescan_secs, &memstat_reaper_rescan_secs, 0, UINT32_MAX, "");

SYSCTL_INT(_kern_memorystatus, OID_AUTO, reaper_stats_sweep_count,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &(memstat_reaper_cumulative_stats.sweep_count), 0, "");
SYSCTL_INT(_kern_memorystatus, OID_AUTO, reaper_stats_total_kills,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &(memstat_reaper_cumulative_stats.kill_count), 0, "");
SYSCTL_INT(_kern_memorystatus, OID_AUTO, reaper_stats_total_freed_mb,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &memstat_reaper_cumulative_memory_freed_mb, 0, "");

static int
memstat_page_shortage_threshold_experiment_handler SYSCTL_HANDLER_ARGS
{
	uint32_t threshold_mb;
	int error;

	assert3p(arg1, !=, NULL);
	threshold_mb = ptoa_32(os_atomic_load((uint32_t *)arg1, relaxed)) >> 20;

	error = sysctl_handle_int(oidp, &threshold_mb, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (threshold_mb > UINT32_MAX >> 20) {
		/* Converting to bytes would overflow */
		return EINVAL;
	}

	uint32_t new_threshold_pages = atop_32(threshold_mb << 20);
	/*
	 * Page shortage thresholds may not exceed 1/2 max_mem
	 */
	if (new_threshold_pages > MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX) {
		return EINVAL;
	}
	if ((arg1 == &memstat_soft_threshold ||
	    arg1 == &memstat_idle_threshold ||
	    arg1 == &memstat_critical_threshold ||
	    arg1 == &memstat_reaper_threshold) &&
	    new_threshold_pages == 0) {
		return EINVAL;
	}

	if (arg1 == &memstat_soft_threshold) {
		memorystatus_log("memorystatus: setting soft memory limit "
		    "page shortage threshold to %u MiB\n", threshold_mb);
	} else if (arg1 == &memstat_idle_threshold) {
		memorystatus_log("memorystatus: setting idle exit page "
		    "shortage threshold to %u MiB\n", threshold_mb);
	} else if (arg1 == &memstat_critical_threshold) {
		memorystatus_log("memorystatus: setting critical page shortage"
		    " threshold to %u MiB\n", threshold_mb);
	} else if (arg1 == &memstat_reaper_threshold) {
		memorystatus_log("memorystatus: setting reaper page shortage"
		    " threshold to %u MiB\n", threshold_mb);
	} else if (arg1 == &memstat_ctd_offset) {
		memorystatus_log("memorystatus: setting clear-the-decks page shortage"
		    " offset to %u MiB\n", threshold_mb);
	} else if (arg1 == &memstat_ballast_offset) {
		memorystatus_log("memorystatus: setting ballast page shortage"
		    " offset to %u MiB\n", threshold_mb);
	} else {
		return EINVAL;
	}
	os_atomic_store((uint32_t *)arg1, new_threshold_pages, relaxed);

	return 0;
}

#if DEVELOPMENT || DEBUG
#define MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS (CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED)
#else /* RELEASE */
#define MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS (CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED | CTLFLAG_MASKED)
#endif /* DEVELOPMENT || DEBUG */

EXPERIMENT_FACTOR_PROC(_kern_memorystatus, soft_threshold_mb,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    &memstat_soft_threshold, 0, memstat_page_shortage_threshold_experiment_handler,
    "IU",
    "The minimum amount of available memory to maintain before killing "
    "processes which have violated there soft memory limit");

EXPERIMENT_FACTOR_PROC(_kern_memorystatus, idle_threshold_mb,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    &memstat_idle_threshold, 0, memstat_page_shortage_threshold_experiment_handler,
    "IU",
    "The minimum amount of available memory to maintain before exiting idle "
    "processes");
EXPERIMENT_FACTOR_PROC(_kern_memorystatus, critical_threshold_mb,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    &memstat_critical_threshold, 0, memstat_page_shortage_threshold_experiment_handler,
    "IU",
    "The minimum amount of available memory to maintain before killing non-idle "
    "processes");
EXPERIMENT_FACTOR_PROC(_kern_memorystatus, reaper_threshold_mb,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    &memstat_reaper_threshold, 0, memstat_page_shortage_threshold_experiment_handler,
    "IU",
    "The minimum amount of available memory to maintain before killing long-idle "
    "processes");
EXPERIMENT_FACTOR_PROC(_kern_memorystatus, ballast_offset_mb,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    &memstat_ballast_offset, 0, memstat_page_shortage_threshold_experiment_handler,
    "IU",
    "An offset to apply to all non-critical page shortage thresholds when "
    "ballast is filling");
EXPERIMENT_FACTOR_PROC(_kern_memorystatus, clear_the_decks_offset_mb,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    &memstat_ctd_offset, 0, memstat_page_shortage_threshold_experiment_handler,
    "IU",
    "An offset to apply to all non-critical page shortage thresholds when "
    "clear-the-decks is engaged");

int
memorystatus_ballast_control(bool drain)
{
	if (!fast_jetsam_enabled) {
		memorystatus_log_error("memorystatus: fast-jetsam "
		    "has been disabled on this system. denying request to %s ballast\n",
		    drain ? "drain" : "flood");
		return ENOTSUP;
	}
	if (memstat_ballast_offset == 0) {
		/* nothing to do */
		return 0;
	}
	if (drain) {
		/*
		 * Drain the ballast tanks, providing additional buoyancy by requiring that
		 * they only be used to store "available" memory.
		 */
		memorystatus_policy_t orig_policy = os_atomic_or_orig(
			&memstat_policy_config,
			(memorystatus_policy_t)kPolicyBallastDrain, relaxed);
		if (orig_policy & kPolicyBallastDrain) {
			return 0;
		}
		memorystatus_log("memorystatus: draining ballast "
		    "-- will add %u MiB to non-critical page shortage "
		    "thresholds\n", ptoa_32(memstat_ballast_offset) >> 20);
		memorystatus_thread_pool_max();
		_memstat_consider_waking_jetsam_thread();
	} else {
		/*
		 * Flood the ballast tanks, removing the extra buoyancy by allowing them to be
		 * filled with "unavailable" memory.
		 */
		memorystatus_policy_t orig_policy = os_atomic_andnot_orig(
			&memstat_policy_config,
			(memorystatus_policy_t)kPolicyBallastDrain, relaxed);
		if (!(orig_policy & kPolicyBallastDrain)) {
			/* already disabled */
			return 0;
		}
		assertf(fast_jetsam_enabled, "ballast was drained while fast-jetsam was disabled");
		memorystatus_log("memorystatus: flooding ballast "
		    "-- will subtract %u MiB from non-critical page shortage "
		    "thresholds\n", ptoa_32(memstat_ballast_offset) >> 20);
		memorystatus_thread_pool_default();
		_memstat_consider_waking_jetsam_thread();
	}
	return 0;
}

static int
sysctl_kern_memorystatus_ballast_drain SYSCTL_HANDLER_ARGS
{
	int error = 0;

	boolean_t drained = os_atomic_load(&memstat_policy_config, relaxed) & kPolicyBallastDrain ? TRUE : FALSE;

	error = sysctl_handle_int(oidp, &drained, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	/*
	 * Writers must be root or have the com.apple.private.kernel.jetsam entitlement
	 */
	error = priv_check_cred(kauth_cred_get(), PRIV_VM_JETSAM, 0);
	if (error) {
		return error;
	}

	return memorystatus_ballast_control(drained);
}

SYSCTL_PROC(_kern_memorystatus, OID_AUTO, ballast_drained,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS, 0, 0,
    sysctl_kern_memorystatus_ballast_drain, "IU",
    "If true, apply an offset (kern.memorystatus.ballast_offset_mb) to "
    "all non-critical page shortage thresholds");

#if DEVELOPMENT || DEBUG
/*
 * In preparation for a storm, sailors may "clear the decks" of non-essential
 * cargo to increase the seaworthiness of a vessel. In our analogy, the
 * non-essential cargo is idle processes or processes which have exceeded
 * their memory limit. The storm may be any foreseeable user activity that will
 * require significant memory demand.
 *
 * Mechanically, clearing the decks involves adding a configurable offset to
 * the idle and soft available page shortage thresholds.
 *
 * Readers may note that the clear-the-decks policy is mechanically identical
 * the ballast-draining policy. Their difference lies in intended use.
 * Clear-the-decks is intended to address imminent memory demand and may be
 * configured with an offset that wouldn't be sustainable for long-term system
 * use. The interface is generally intended to allow clients to hint to the
 * system that they will need a significant amount of memory in the near future,
 * and the system should proactively try to free unneeded reserves to satisfy
 * to be able to better satisfy the demand.
 *
 * This policy is currently only exposed on development kernels for prototyping
 * until a productized use case emerges
 *
 * TODO: If adopted on production systems, this mechanism should use a
 * dedicated system-call / memorystatus-command
 */
static int
memstat_clear_the_decks(bool clear)
{
	if (!fast_jetsam_enabled) {
		memorystatus_log_error("memorystatus: fast-jetsam "
		    "has been disabled on this system\n");
		return ENOTSUP;
	}
	if (clear) {
		/*
		 * Clear the decks of non-essential cargo.
		 */
		memorystatus_policy_t orig_policy = os_atomic_or_orig(
			&memstat_policy_config,
			(memorystatus_policy_t)kPolicyClearTheDecks, relaxed);
		if (orig_policy & kPolicyClearTheDecks) {
			return EALREADY;
		}
		memorystatus_log("memorystatus: clear-the-decks engaged "
		    "-- will add %u MiB to non-critical page shortage "
		    "thresholds\n", ptoa_32(memstat_ctd_offset) >> 20);
		memorystatus_thread_pool_max();
		_memstat_consider_waking_jetsam_thread();
	} else {
		/*
		 * Allow the decks to be reloaded with non-essential cargo.
		 */
		memorystatus_policy_t orig_policy = os_atomic_andnot_orig(
			&memstat_policy_config,
			(memorystatus_policy_t)kPolicyClearTheDecks, relaxed);
		if (!(orig_policy & kPolicyClearTheDecks)) {
			return EALREADY;
		}
		assertf(fast_jetsam_enabled, "clear the decks was set while fast-jetsam was disabled");
		memorystatus_log("memorystatus: clear-the-decks disengaged "
		    "-- will subtract %u MiB from non-critical page shortage "
		    "thresholds\n", ptoa_32(memstat_ctd_offset) >> 20);
		memorystatus_thread_pool_default();
		_memstat_consider_waking_jetsam_thread();
	}
	return 0;
}

static int
sysctl_kern_memorystatus_decks_cleared SYSCTL_HANDLER_ARGS
{
	int error = 0;

	boolean_t cleared = os_atomic_load(&memstat_policy_config, relaxed) & kPolicyClearTheDecks ? TRUE : FALSE;

	error = sysctl_handle_int(oidp, &cleared, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	/*
	 * Writers must be root or have the com.apple.private.kernel.jetsam entitlement
	 */
	error = priv_check_cred(kauth_cred_get(), PRIV_VM_JETSAM, 0);
	if (error) {
		return error;
	}

	return memstat_clear_the_decks(cleared);
}

SYSCTL_PROC(_kern_memorystatus, OID_AUTO, decks_cleared,
    MEMSTAT_PAGE_SHORTAGE_EXPERIMENT_FLAGS,
    0, 0, sysctl_kern_memorystatus_decks_cleared, "I",
    "If true, apply an offset (kern.memorystatus_ctd_offset_mb) to "
    "all non-critical page shortage thresholds");
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

extern kern_return_t kernel_thread_start_priority(thread_continue_t continuation,
    void *parameter,
    integer_t priority,
    thread_t *new_thread);

#if DEVELOPMENT || DEBUG

static int
sysctl_memorystatus_disconnect_page_mappings SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int     error = 0, pid = 0;
	proc_t  p;

	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	lck_mtx_lock(&disconnect_page_mappings_mutex);

	if (pid == -1) {
		vm_pageout_disconnect_all_pages();
	} else {
		p = proc_find(pid);

		if (p != NULL) {
			error = task_disconnect_page_mappings(proc_task(p));

			proc_rele(p);

			if (error) {
				error = EIO;
			}
		} else {
			error = EINVAL;
		}
	}
	lck_mtx_unlock(&disconnect_page_mappings_mutex);

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_disconnect_page_mappings, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_memorystatus_disconnect_page_mappings, "I", "");

#endif /* DEVELOPMENT || DEBUG */

/*
 * Sorts the given bucket.
 *
 * Input:
 *	bucket_index - jetsam priority band to be sorted.
 *	sort_order - JETSAM_SORT_xxx from kern_memorystatus.h
 *		Currently sort_order is only meaningful when handling
 *		coalitions.
 *
 * proc_list_lock must be held by the caller.
 */
static void
memorystatus_sort_bucket_locked(unsigned int bucket_index, int sort_order)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	assert(bucket_index < MEMSTAT_BUCKET_COUNT);
	if (memstat_bucket[bucket_index].count == 0) {
		return;
	}

	switch (bucket_index) {
	case JETSAM_PRIORITY_FOREGROUND:
		if (memorystatus_sort_by_largest_coalition_locked(bucket_index, sort_order) == 0) {
			/*
			 * Fall back to per process sorting when zero coalitions are found.
			 */
			memorystatus_sort_by_largest_process_locked(bucket_index);
		}
		break;
	default:
		memorystatus_sort_by_largest_process_locked(bucket_index);
		break;
	}
}

/*
 * Picks the sorting routine for a given jetsam priority band.
 *
 * Input:
 *	bucket_index - jetsam priority band to be sorted.
 *	sort_order - JETSAM_SORT_xxx from kern_memorystatus.h
 *		Currently sort_order is only meaningful when handling
 *		coalitions.
 *
 * Return:
 *	0     on success
 *      non-0 on failure
 */
static int
memorystatus_sort_bucket(unsigned int bucket_index, int sort_order)
{
	int coal_sort_order;

	/*
	 * Verify the jetsam priority
	 */
	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return EINVAL;
	}

#if DEVELOPMENT || DEBUG
	if (sort_order == JETSAM_SORT_DEFAULT) {
		coal_sort_order = COALITION_SORT_DEFAULT;
	} else {
		coal_sort_order = sort_order;           /* only used for testing scenarios */
	}
#else
	/* Verify default */
	if (sort_order == JETSAM_SORT_DEFAULT) {
		coal_sort_order = COALITION_SORT_DEFAULT;
	} else {
		return EINVAL;
	}
#endif

	proc_list_lock();
	memorystatus_sort_bucket_locked(bucket_index, coal_sort_order);
	proc_list_unlock();

	return 0;
}

/*
 * Sort processes by size for a single jetsam bucket.
 */

static void
memorystatus_sort_by_largest_process_locked(unsigned int bucket_index)
{
	proc_t p = NULL, insert_after_proc = NULL, max_proc = NULL;
	proc_t next_p = NULL, prev_max_proc = NULL;
	uint32_t pages = 0, max_pages = 0;
	memstat_bucket_t *current_bucket;

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return;
	}

	current_bucket = &memstat_bucket[bucket_index];

	p = TAILQ_FIRST(&current_bucket->list);

	while (p) {
		memorystatus_get_task_page_counts(proc_task(p), &pages, NULL, NULL);
		max_pages = pages;
		max_proc = p;
		prev_max_proc = p;

		while ((next_p = TAILQ_NEXT(p, p_memstat_list)) != NULL) {
			/* traversing list until we find next largest process */
			p = next_p;
			memorystatus_get_task_page_counts(proc_task(p), &pages, NULL, NULL);
			if (pages > max_pages) {
				max_pages = pages;
				max_proc = p;
			}
		}

		if (prev_max_proc != max_proc) {
			/* found a larger process, place it in the list */
			TAILQ_REMOVE(&current_bucket->list, max_proc, p_memstat_list);
			if (insert_after_proc == NULL) {
				TAILQ_INSERT_HEAD(&current_bucket->list, max_proc, p_memstat_list);
			} else {
				TAILQ_INSERT_AFTER(&current_bucket->list, insert_after_proc, max_proc, p_memstat_list);
			}
			prev_max_proc = max_proc;
		}

		insert_after_proc = max_proc;

		p = TAILQ_NEXT(max_proc, p_memstat_list);
	}
}

proc_t
memorystatus_get_first_proc_locked(unsigned int *bucket_index, boolean_t search)
{
	memstat_bucket_t *current_bucket;
	proc_t next_p;

	if ((*bucket_index) >= MEMSTAT_BUCKET_COUNT) {
		return NULL;
	}

	current_bucket = &memstat_bucket[*bucket_index];
	next_p = TAILQ_FIRST(&current_bucket->list);
	if (!next_p && search) {
		while (!next_p && (++(*bucket_index) < MEMSTAT_BUCKET_COUNT)) {
			current_bucket = &memstat_bucket[*bucket_index];
			next_p = TAILQ_FIRST(&current_bucket->list);
		}
	}

	return next_p;
}

proc_t
memorystatus_get_next_proc_locked(unsigned int *bucket_index, proc_t p, boolean_t search)
{
	memstat_bucket_t *current_bucket;
	proc_t next_p;

	if (!p || ((*bucket_index) >= MEMSTAT_BUCKET_COUNT)) {
		return NULL;
	}

	next_p = TAILQ_NEXT(p, p_memstat_list);
	while (!next_p && search && (++(*bucket_index) < MEMSTAT_BUCKET_COUNT)) {
		current_bucket = &memstat_bucket[*bucket_index];
		next_p = TAILQ_FIRST(&current_bucket->list);
	}

	return next_p;
}

jetsam_state_t jetsam_threads;

/* Maximum number of jetsam threads allowed */
#define JETSAM_THREADS_LIMIT   3

/* Number of active jetsam threads */
_Atomic unsigned int active_jetsam_threads = 1;
/* Number of maximum jetsam threads configured */
unsigned int max_jetsam_threads = 1;

static jetsam_state_t
jetsam_current_thread()
{
	for (int thr_id = 0; thr_id < max_jetsam_threads; thr_id++) {
		if (jetsam_threads[thr_id].thread == current_thread()) {
			return &(jetsam_threads[thr_id]);
		}
	}
	return NULL;
}

#if CONFIG_JETSAM
static void
initialize_entitled_max_task_limit()
{
#if !XNU_TARGET_OS_XR
	/**
	 * We've already stored the potential boot-arg "entitled_max_task_pmem" in
	 * memorystatus_entitled_max_task_footprint_mb as a TUNABLE_DT.  We provide
	 * argptr=NULL and max_len=0 here to check only for existence of the boot-arg.
	 *
	 * The boot-arg takes precedence over memorystatus_swap_all_apps.
	 */
	if (!PE_parse_boot_argn("entitled_max_task_pmem", NULL, 0) && memorystatus_swap_all_apps) {
		/*
		 * When we have swap, we let entitled apps go up to the dram config
		 * regardless of what's set in EDT,
		 * This can still be overriden with the entitled_max_task_pmem boot-arg.
		 *
		 * We do not want to do this on visionOS, since we can have an effectively
		 * infinite number of apps open at a time, and cannot swap our way to safety.
		 */
		memorystatus_entitled_max_task_footprint_mb =
		    (int32_t)(max_mem_actual / (1ULL << 20));
		memorystatus_entitled_dev_max_task_footprint_mb =
		    memorystatus_entitled_max_task_footprint_mb;
	}
#endif

	if (memorystatus_entitled_max_task_footprint_mb < 0) {
		memorystatus_log_error("Invalid value (%d) for entitled_max_task_pmem. "
		    "Setting to 0\n", memorystatus_entitled_max_task_footprint_mb);
		memorystatus_entitled_max_task_footprint_mb = 0;
	}

#if CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
	if (memorystatus_entitled_bincompat_max_task_footprint_mb < 0) {
		memorystatus_log_error("Invalid value (%d) for entitled_bincompat_max_task_pmem. "
		    "Setting to 0\n", memorystatus_entitled_bincompat_max_task_footprint_mb);
		memorystatus_entitled_bincompat_max_task_footprint_mb = 0;
	}
#endif /* CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT */

	if (memorystatus_entitled_dev_max_task_footprint_mb < -1) {
		memorystatus_log_error("Invalid value (%d) for entitled_max_developer_task_pmem. "
		    "Setting to 0\n", memorystatus_entitled_dev_max_task_footprint_mb);
		memorystatus_entitled_dev_max_task_footprint_mb = 0;
	} else if (memorystatus_entitled_dev_max_task_footprint_mb == -1) {
		memorystatus_entitled_dev_max_task_footprint_mb = (int32_t)
		    (max_mem_actual >> 20);
	}

	if (memorystatus_entitled_dev_max_task_footprint_mb &&
	    memorystatus_entitled_dev_max_task_footprint_mb <
	    memorystatus_entitled_max_task_footprint_mb) {
		memorystatus_log_error("memorystatus: Entitled developer limit (%d MB) "
		    "must be ≥ entitled task limit (%d MB)\n",
		    memorystatus_entitled_dev_max_task_footprint_mb,
		    memorystatus_entitled_max_task_footprint_mb);
		memorystatus_entitled_dev_max_task_footprint_mb =
		    memorystatus_entitled_max_task_footprint_mb;
	}
}

#endif /* CONFIG_JETSAM */


__private_extern__ void
memorystatus_init(void)
{
	kern_return_t result;
	int i;

#if CONFIG_FREEZE
	memorystatus_frozen_processes_max = FREEZE_PROCESSES_MAX_DEFAULT;
	memorystatus_frozen_shared_mb_max = ((MAX_FROZEN_SHARED_MB_PERCENT * max_task_footprint_mb) / 100); /* 10% of the system wide task limit */
	memorystatus_freeze_shared_mb_per_process_max = (memorystatus_frozen_shared_mb_max / 4);
	memorystatus_freeze_pages_min = FREEZE_PAGES_MIN_DEFAULT;
	memorystatus_freeze_pages_max = FREEZE_PAGES_MAX_DEFAULT;
	memorystatus_max_frozen_demotions_daily = MAX_FROZEN_PROCESS_DEMOTIONS_DEFAULT;
	memorystatus_thaw_count_demotion_threshold = MIN_THAW_DEMOTION_THRESHOLD_DEFAULT;
	memorystatus_min_thaw_refreeze_threshold = MIN_THAW_REFREEZE_THRESHOLD_DEFAULT;
#endif /* CONFIG_FREEZE */

	// Note: no-op pending rdar://27006343 (Custom kernel log handles)
	memorystatus_log_handle = os_log_create("com.apple.xnu", "memorystatus");

	/* Init buckets */
	for (i = 0; i < MEMSTAT_BUCKET_COUNT; i++) {
		TAILQ_INIT(&memstat_bucket[i].list);
		memstat_bucket[i].count = 0;
		memstat_bucket[i].relaunch_high_count = 0;
	}
	memorystatus_idle_demotion_call = thread_call_allocate((thread_call_func_t)memorystatus_perform_idle_demotion, NULL);

	nanoseconds_to_absolutetime(memstat_idle_deferral_time_s * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);
	nanoseconds_to_absolutetime(memstat_idle_deferral_time_s * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);
	nanoseconds_to_absolutetime(memstat_aging_stuck_time_s * NSEC_PER_SEC, &memorystatus_aging_stuck_delay_time);
	assert3u(memstat_idle_deferral_time_s, >=, kJetsamSysProcsIdleDelayTimeLowRatio);

#if CONFIG_JETSAM
	bzero(memorystatus_jetsam_proc_name_panic, sizeof(memorystatus_jetsam_proc_name_panic));
	if (PE_parse_boot_argn("jetsam_proc_name_panic", &memorystatus_jetsam_proc_name_panic, sizeof(memorystatus_jetsam_proc_name_panic))) {
		/*
		 * No bounds check to see if this is a valid cause.
		 * This is a debugging aid. The callers should know precisely which cause they wish to track.
		 */
		PE_parse_boot_argn("jetsam_proc_cause_panic", &memorystatus_jetsam_proc_cause_panic, sizeof(memorystatus_jetsam_proc_cause_panic));
		PE_parse_boot_argn("jetsam_proc_size_panic", &memorystatus_jetsam_proc_size_panic, sizeof(memorystatus_jetsam_proc_size_panic));
	}

	if (memorystatus_swap_all_apps && vm_page_donate_mode == VM_PAGE_DONATE_DISABLED) {
		panic("kern.swap_all_apps is not supported on this platform");
	}

	/*
	 * The aging bands cannot overlap with the JETSAM_PRIORITY_ELEVATED_INACTIVE
	 * band and must be below it in priority. This is so that we don't have to make
	 * our 'aging' code worry about a mix of processes, some of which need to age
	 * and some others that need to stay elevated in the jetsam bands.
	 */
	assert(JETSAM_PRIORITY_ELEVATED_INACTIVE > system_procs_aging_band);
	assert(JETSAM_PRIORITY_ELEVATED_INACTIVE > system_procs_aging_band_stuck);
	assert(JETSAM_PRIORITY_ELEVATED_INACTIVE > applications_aging_band);

	/* Take snapshots for idle-exit kills by default? First check the boot-arg... */
	if (!PE_parse_boot_argn("jetsam_idle_snapshot", &memorystatus_idle_snapshot, sizeof(memorystatus_idle_snapshot))) {
		/* ...no boot-arg, so check the device tree */
		PE_get_default("kern.jetsam_idle_snapshot", &memorystatus_idle_snapshot, sizeof(memorystatus_idle_snapshot));
	}

	memorystatus_sysproc_aging_aggr_pages = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_AGGR_SYSPROC_AGING_PERCENTAGE);

	if (max_mem <= MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) {
		memorystatus_delta = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_DELTA_PERCENTAGE_SMALL);
	} else {
		memorystatus_delta = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_DELTA_PERCENTAGE_LARGE);
	}

	if (memorystatus_critical_threshold_mb != 0) {
		memstat_critical_threshold = atop_32(memorystatus_critical_threshold_mb << 20);
	} else {
		if (max_mem <= MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) {
			memstat_critical_threshold = MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_CRITICAL_PERCENTAGE_SMALL);
		} else {
			memstat_critical_threshold = MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_CRITICAL_PERCENTAGE_LARGE);
		}
	}
	assert3u(memstat_critical_threshold, <, MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX);

	if (memorystatus_idle_threshold_mb != 0) {
		memstat_idle_threshold = atop_32(memorystatus_idle_threshold_mb << 20);
	} else {
		/*
		 * For historical reasons, devices with "medium"-sized memory configs have a different critical:idle:pressure ratio
		 */
		if ((max_mem > MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) &&
		    (max_mem <= MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD)) {
			memstat_idle_threshold = (MEMORYSTATUS_IDLE_RATIO_NUM_MEDIUM * memstat_critical_threshold) /
			    MEMORYSTATUS_IDLE_RATIO_DENOM_MEDIUM;
		} else {
			memstat_idle_threshold = (MEMORYSTATUS_IDLE_RATIO_NUM * memstat_critical_threshold) /
			    MEMORYSTATUS_IDLE_RATIO_DENOM;
		}
	}
	assert3u(memstat_idle_threshold, <, MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX);

	if (memorystatus_pressure_threshold_mb != 0) {
		memstat_soft_threshold = atop_32(memorystatus_pressure_threshold_mb << 20);
	} else {
		if ((max_mem > MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) &&
		    (max_mem <= MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD)) {
			memstat_soft_threshold = (MEMORYSTATUS_PRESSURE_RATIO_NUM_MEDIUM * memstat_critical_threshold) /
			    MEMORYSTATUS_PRESSURE_RATIO_DENOM_MEDIUM;
		} else {
			memstat_soft_threshold = (MEMORYSTATUS_PRESSURE_RATIO_NUM * memstat_critical_threshold) /
			    MEMORYSTATUS_PRESSURE_RATIO_DENOM;
		}
	}
	assert3u(memstat_soft_threshold, <, MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX);

	memstat_reaper_max_priority = MEMORYSTATUS_REAPER_MAX_PRIORITY_DEFAULT;

	if (memorystatus_reaper_threshold_mb != 0) {
		memstat_reaper_threshold = atop_32(memorystatus_reaper_threshold_mb << 20);
	} else {
		if ((max_mem > MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) &&
		    (max_mem <= MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD)) {
			memstat_reaper_threshold = (MEMORYSTATUS_REAPER_RATIO_NUM_MEDIUM * memstat_critical_threshold) /
			    MEMORYSTATUS_REAPER_RATIO_DENOM_MEDIUM;
		} else {
			memstat_reaper_threshold = (MEMORYSTATUS_REAPER_RATIO_NUM * memstat_critical_threshold) /
			    MEMORYSTATUS_REAPER_RATIO_DENOM;
		}
	}
	assert3u(memstat_reaper_threshold, <, MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX);

	if (memorystatus_reaper_minimum_age_seconds != MEMORYSTATUS_REAPER_SENTINAL_VALUE_MEANING_USE_DEFAULT) {
		memstat_reaper_min_age_secs = memorystatus_reaper_minimum_age_seconds;
	} else {
		memstat_reaper_min_age_secs = MEMORYSTATUS_REAPER_MIN_AGE_SECS_DEFAULT;
	}

	if (memorystatus_reaper_rescan_delay_seconds != MEMORYSTATUS_REAPER_SENTINAL_VALUE_MEANING_USE_DEFAULT) {
		memstat_reaper_rescan_secs = memorystatus_reaper_rescan_delay_seconds;
	} else {
		memstat_reaper_rescan_secs = MEMORYSTATUS_REAPER_RESCAN_SECS_DEFAULT;
	}

	memstat_reaper_enabled = memorystatus_reaper_enabled;

	if (memstat_ballast_offset_mb != 0) {
		memstat_ballast_offset = atop_32(memstat_ballast_offset_mb << 20);
	}
	assert3u(memstat_ballast_offset, <, MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX);

	if (memstat_ctd_offset_mb != 0) {
		memstat_ctd_offset = atop_32(memstat_ctd_offset_mb << 20);
	}
	assert3u(memstat_ctd_offset, <, MEMSTAT_PAGE_SHORTAGE_THRESHOLD_MAX);

	/* Set the swapin trigger in pages based on the maximum size allocated for each c_seg */
	memorystatus_swapin_trigger_pages = (unsigned int) atop_64(memorystatus_swapin_trigger_segments * c_seg_allocsize);

	/* Jetsam Loop Detection */
	if (max_mem <= (512 * 1024 * 1024)) {
		/* 512 MB devices */
		memorystatus_jld_eval_period_msecs = 8000;      /* 8000 msecs == 8 second window */
	} else {
		/* 1GB and larger devices */
		memorystatus_jld_eval_period_msecs = 6000;      /* 6000 msecs == 6 second window */
	}

	memorystatus_jld_enabled = TRUE;

	initialize_entitled_max_task_limit();
#endif /* CONFIG_JETSAM */

	memorystatus_jetsam_snapshot_max = maxproc;

	memorystatus_jetsam_snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) +
	    (sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_max);

	memorystatus_jetsam_snapshot = kalloc_data(memorystatus_jetsam_snapshot_size, Z_WAITOK | Z_ZERO);
	if (!memorystatus_jetsam_snapshot) {
		panic("Could not allocate memorystatus_jetsam_snapshot");
	}

#if CONFIG_FREEZE
	memorystatus_jetsam_snapshot_freezer_max = memorystatus_jetsam_snapshot_max / JETSAM_SNAPSHOT_FREEZER_MAX_FACTOR;
	memorystatus_jetsam_snapshot_freezer_size = sizeof(memorystatus_jetsam_snapshot_t) +
	    (sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_freezer_max);

	memorystatus_jetsam_snapshot_freezer =
	    zalloc_permanent(memorystatus_jetsam_snapshot_freezer_size, ZALIGN_PTR);
#endif /* CONFIG_FREEZE */

	nanoseconds_to_absolutetime((uint64_t)JETSAM_SNAPSHOT_TIMEOUT_SECS * NSEC_PER_SEC, &memorystatus_jetsam_snapshot_timeout);

	memset(&memorystatus_at_boot_snapshot, 0, sizeof(memorystatus_jetsam_snapshot_t));

#if CONFIG_FREEZE
	if (memorystatus_freeze_threshold_mb != 0) {
		memorystatus_freeze_threshold = (unsigned int)atop_64((uint64_t)memorystatus_freeze_threshold_mb << 20);
	} else {
		memorystatus_freeze_threshold = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_FREEZE_THRESHOLD_PERCENTAGE);
	}
	assert(memorystatus_freeze_threshold < (unsigned int)atop_64(max_mem));

	if (memorystatus_swap_all_apps) {
		/*
		 * Swap is enabled, so we expect a larger working set & larger apps.
		 * Adjust thresholds accordingly.
		 */
		memorystatus_freeze_configure_for_swap();
	}
#endif

	/* Check the boot-arg to configure the maximum number of jetsam threads */
	if (!PE_parse_boot_argn("max_jetsam_threads", &max_jetsam_threads, sizeof(max_jetsam_threads))) {
		max_jetsam_threads = JETSAM_THREADS_LIMIT;
	}

	/* Restrict the maximum number of jetsam threads to JETSAM_THREADS_LIMIT */
	if (max_jetsam_threads > JETSAM_THREADS_LIMIT) {
		max_jetsam_threads = JETSAM_THREADS_LIMIT;
	}

#if CONFIG_JETSAM
	/* For low CPU systems disable fast jetsam mechanism */
	if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
		max_jetsam_threads = 1;
	}
#endif /* CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG
	if (PE_parse_boot_argn("-memorystatus-skip-fg-notify", &i, sizeof(i))) {
		memorystatus_should_issue_fg_band_notify = false;
	}
#endif /* DEVELOPMENT || DEBUG */

	/* Initialize the jetsam_threads state array */
	jetsam_threads = zalloc_permanent(sizeof(struct jetsam_state_s) *
	    max_jetsam_threads, ZALIGN(struct jetsam_state_s));

	/* Initialize all the jetsam threads */
	for (i = 0; i < max_jetsam_threads; i++) {
		jetsam_threads[i].inited = false;
		jetsam_threads[i].index = i;
		result = kernel_thread_start_priority(memorystatus_thread, NULL, 95 /* MAXPRI_KERNEL */, &jetsam_threads[i].thread);
		if (result != KERN_SUCCESS) {
			panic("Could not create memorystatus_thread %d", i);
		}
		thread_deallocate(jetsam_threads[i].thread);
	}

#if VM_PRESSURE_EVENTS
	memorystatus_notify_init();
#endif /* VM_PRESSURE_EVENTS */

#if JETSAM_ZPRINT_SNAPSHOT
	size_t jzs_names_size, jzs_info_size, jzs_meminfo_size;

	jzs_zone_cnt = zone_max_zones();
	jzs_names_size = jzs_zone_cnt * sizeof(mach_zone_name_t);
	jzs_names = zalloc_permanent(jzs_names_size, ZALIGN(mach_zone_name_t));

	jzs_info_size = jzs_zone_cnt * sizeof(mach_zone_info_t);
	jzs_info = zalloc_permanent(jzs_info_size, ZALIGN(mach_zone_info_t));

	jzs_coalesce = zalloc_permanent(jzs_zone_cnt * sizeof(int), ZALIGN(int));

	jzs_meminfo_cnt = vm_page_diagnose_estimate();
	jzs_meminfo_size = jzs_meminfo_cnt * sizeof(mach_memory_info_t);
	jzs_meminfo = kalloc_data_tag(jzs_meminfo_size, Z_WAITOK, VM_KERN_MEMORY_DIAG);
#endif /* JETSAM_ZPRINT_SNAPSHOT */

	bzero(memorystatus_kill_counts, sizeof(memorystatus_kill_counts));
}

#if CONFIG_JETSAM
bool
memorystatus_disable_swap(void)
{
#if DEVELOPMENT || DEBUG
	int boot_arg_val = 0;
	if (PE_parse_boot_argn("kern.swap_all_apps", &boot_arg_val, sizeof(boot_arg_val))) {
		if (boot_arg_val) {
			/* Can't disable app swap if it was set via a boot-arg */
			return false;
		}
	}
#endif /* DEVELOPMENT || DEBUG */
	memorystatus_swap_all_apps = false;
#if CONFIG_FREEZE
	/* Go back to the smaller freezer thresholds */
	memorystatus_freeze_disable_swap();
#endif /* CONFIG_FREEZE */
	initialize_entitled_max_task_limit();
	return true;
}
#endif /* CONFIG_JETSAM */

static void
_memstat_record_kill(int32_t priority, memorystatus_kill_cause_t cause)
{
	uint32_t _Atomic *count;
	uint32_t orig;

	/* Check validity of reason / cause */
	if ((priority < JETSAM_PRIORITY_IDLE) ||
	    (priority > JETSAM_PRIORITY_MAX) ||
	    (cause <= kMemorystatusInvalid) ||
	    (cause > JETSAM_REASON_MEMORYSTATUS_MAX)) {
		memorystatus_log_error("memorystatus: not tracking kill with invalid priority %d / cause %d\n",
		    priority, cause);
		return;
	}

	if ((priority == JETSAM_PRIORITY_IDLE) && (cause == kMemorystatusKilledIdleExit)) {
		/* rdar://141462516 */
		count = &memorystatus_idle_exit_kill_count;
	} else {
		if (cause == kMemorystatusKilledIdleExit) {
			memorystatus_log_error("memorystatus: not tracking idle exit kill for priority %d\n", priority);
			return;
		}

		/* kMemorystatusKilledIdleExit and kMemorystatusInvalid are not in the array */
		if (cause < kMemorystatusKilledIdleExit) {
			count = &memorystatus_kill_counts[priority][cause - 1];
		} else {
			count = &memorystatus_kill_counts[priority][cause - 2];
		}
	}

	orig = os_atomic_inc_orig(count, relaxed);
	if (orig == UINT32_MAX) {
		os_atomic_dec(count, relaxed);
		memorystatus_log_error("memorystatus: overflowed kill count for priority %d + cause %d\n", priority, cause);
	}
}

/*
 * The jetsam no frills kill call
 *      Return: 0 on success
 *		error code on failure (EINVAL...)
 */
static int
jetsam_do_kill(proc_t p, int jetsam_flags, os_reason_t jetsam_reason)
{
	int error = 0;
	error = exit_with_reason(p, W_EXITCODE(0, SIGKILL), (int *)NULL, FALSE, FALSE, jetsam_flags, jetsam_reason);
	return error;
}

/*
 * Wrapper for processes exiting with memorystatus details
 */
static bool
memorystatus_do_kill(proc_t p, uint32_t cause, os_reason_t jetsam_reason, uint64_t *footprint_out)
{
	int error = 0;
	__unused pid_t victim_pid = proc_getpid(p);
	uint64_t footprint = get_task_phys_footprint(proc_task(p));
#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD)
	int32_t memstat_effectivepriority = p->p_memstat_effectivepriority;
#endif /* (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD) */

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_DO_KILL) | DBG_FUNC_START,
	    victim_pid, cause, vm_page_free_count, footprint);
	DTRACE_MEMORYSTATUS4(memorystatus_do_kill, proc_t, p, os_reason_t, jetsam_reason, uint32_t, cause, uint64_t, footprint);

#if CONFIG_JETSAM
	if (*p->p_name && !strncmp(memorystatus_jetsam_proc_name_panic, p->p_name, sizeof(p->p_name))) { /* name */
		if ((!memorystatus_jetsam_proc_cause_panic || cause == memorystatus_jetsam_proc_cause_panic) && /* cause */
		    (!memorystatus_jetsam_proc_size_panic || (footprint >> 20) >= memorystatus_jetsam_proc_size_panic)) { /* footprint */
			panic("memorystatus_do_kill(): requested panic on jetsam of %s (cause: %d and footprint: %llu mb)",
			    memorystatus_jetsam_proc_name_panic, cause, footprint >> 20);
		}
	}
#else /* CONFIG_JETSAM */
#pragma unused(cause)
#endif /* CONFIG_JETSAM */

	if (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND) {
		memorystatus_log(
			"memorystatus: killing process %d [%s] in high band %s (%d) - memorystatus_available_pages: %llu\n",
			proc_getpid(p), (*p->p_name ? p->p_name : "unknown"),
			memorystatus_priority_band_name(p->p_memstat_effectivepriority), p->p_memstat_effectivepriority,
			(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);
	}

	_memstat_record_kill(p->p_memstat_effectivepriority, cause);

	/*
	 * The jetsam_reason (os_reason_t) has enough information about the kill cause.
	 * We don't really need jetsam_flags anymore, so it's okay that not all possible kill causes have been mapped.
	 */
	int jetsam_flags = P_LTERM_JETSAM;
	switch (cause) {
	case kMemorystatusKilledHiwat:                                          jetsam_flags |= P_JETSAM_HIWAT; break;
	case kMemorystatusKilledVnodes:                                         jetsam_flags |= P_JETSAM_VNODE; break;
	case kMemorystatusKilledVMPageShortage:                         jetsam_flags |= P_JETSAM_VMPAGESHORTAGE; break;
	case kMemorystatusKilledVMCompressorThrashing:
	case kMemorystatusKilledVMCompressorSpaceShortage:      jetsam_flags |= P_JETSAM_VMTHRASHING; break;
	case kMemorystatusKilledFCThrashing:                            jetsam_flags |= P_JETSAM_FCTHRASHING; break;
	case kMemorystatusKilledPerProcessLimit:                        jetsam_flags |= P_JETSAM_PID; break;
	case kMemorystatusKilledIdleExit:                                       jetsam_flags |= P_JETSAM_IDLEEXIT; break;
	}
	/* jetsam_do_kill drops a reference. */
	os_reason_ref(jetsam_reason);
	error = jetsam_do_kill(p, jetsam_flags, jetsam_reason);
	if (footprint_out) {
		*footprint_out = ((error == 0) ? footprint : 0);
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_DO_KILL) | DBG_FUNC_END,
	    victim_pid, memstat_effectivepriority, vm_page_free_count, error);

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_COMPACTOR_RUN) | DBG_FUNC_START,
	    victim_pid, cause, vm_page_free_count, footprint);

	if (jetsam_reason->osr_code == JETSAM_REASON_VNODE) {
		/*
		 * vnode jetsams are syncronous and not caused by memory pressure.
		 * Running the compactor on this thread adds significant latency to the filesystem operation
		 * that triggered this jetsam.
		 * Kick of compactor thread asyncronously instead.
		 */
		vm_wake_compactor_swapper();
	} else {
		/* compact now, except for idle reaper kills.
		 * idle reaper kills are done in batches, so we defer compaction until the end of the batch.
		 */
		if (jetsam_reason->osr_code != JETSAM_REASON_MEMORY_LONGIDLE_EXIT) {
			vm_run_compactor();
		}
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_COMPACTOR_RUN) | DBG_FUNC_END,
	    victim_pid, cause, vm_page_free_count);

	os_reason_free(jetsam_reason);
	return error == 0;
}

static int
memstat_update_inactive_priority(proc_t  p, boolean_t enable, int jetsam_prio, boolean_t effective_now)
{
	if (_memstat_proc_is_internal(p)) {
		return EINVAL;
	}

	if ((enable && _memstat_proc_is_elevated(p)) ||
	    (!enable && !_memstat_proc_is_elevated(p))) {
		/*
		 * No change in state.
		 */
	} else {
		proc_list_lock();

		if (enable) {
			p->p_memstat_state |= P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;

			if (effective_now) {
				if (p->p_memstat_effectivepriority < jetsam_prio) {
					memstat_update_priority_locked(p, jetsam_prio, MEMSTAT_PRIORITY_OPTIONS_NONE);
				}
			} else {
				if (_memstat_proc_is_aging(p)) {
					memstat_update_priority_locked(p, JETSAM_PRIORITY_IDLE, MEMSTAT_PRIORITY_NO_AGING);
				}
			}
		} else {
			p->p_memstat_state &= ~P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;

			if (effective_now) {
				if (p->p_memstat_effectivepriority == jetsam_prio) {
					memstat_update_priority_locked(p, JETSAM_PRIORITY_IDLE, MEMSTAT_PRIORITY_NO_AGING);
				}
			} else {
				if (_memstat_proc_is_aging(p)) {
					memstat_update_priority_locked(p, JETSAM_PRIORITY_IDLE, MEMSTAT_PRIORITY_NO_AGING);
				}
			}
		}
		proc_list_unlock();
	}
	return 0;
}

/*
 * Pin a process to a particular jetsam band when it is in the background i.e. not doing active work.
 * For an application: that means no longer in the FG band
 * For a daemon: that means no longer in its 'requested' jetsam priority band
 */

int
memorystatus_update_inactive_jetsam_priority_band(pid_t pid, uint32_t op_flags, int jetsam_prio, boolean_t effective_now)
{
	int error = 0;
	boolean_t enable = FALSE;
	proc_t  p = NULL;

	/* Validate inputs */
	if (pid == 0) {
		return EINVAL;
	}

	if (op_flags == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE) {
		enable = TRUE;
	} else if (op_flags == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE) {
		enable = FALSE;
	} else {
		return EINVAL;
	}

	p = proc_find(pid);
	if (p != NULL) {
		error = memstat_update_inactive_priority(p, enable, jetsam_prio, effective_now);
		proc_rele(p);
	} else {
		error = ESRCH;
	}
	return error;
}

static bool
_memstat_proc_has_importance_assertion(proc_t p)
{
	return (p->p_memstat_state & P_MEMSTAT_TEST_IMP_ASSERTION) || task_has_assertions(proc_task(p));
}

static void
_memstat_perform_idle_demotion_for_band(unsigned int demote_prio_band)
{
	proc_t p;
	uint64_t current_time = 0, idle_delay_time = 0;
	memstat_bucket_t *demotion_bucket;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	current_time = mach_absolute_time();

	demotion_bucket = &memstat_bucket[demote_prio_band];
	p = memorystatus_get_first_proc_locked(&demote_prio_band, FALSE);

	while (p) {
		memorystatus_log_debug("memorystatus_perform_idle_demotion() found %s [%d]\n", proc_best_name(p), proc_getpid(p));

		assert(p->p_memstat_idledeadline);

		assert(_memstat_proc_is_aging(p));

		if (current_time >= p->p_memstat_idledeadline) {
			proc_t next_proc = NULL;

			next_proc = memorystatus_get_next_proc_locked(&demote_prio_band, p, FALSE);

			if ((isSysProc(p) && _memstat_proc_is_dirty(p)) || /* system proc marked dirty*/
			    _memstat_proc_has_importance_assertion(p)) {    /* has outstanding assertions which might indicate outstanding work too */
				idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_time(p) : memorystatus_apps_idle_time(p);

				if (isSysProc(p) && _memstat_proc_has_importance_assertion(p)) {
					if (demote_prio_band != system_procs_aging_band_stuck) {
						memorystatus_log_debug("memorystatus_perform_idle_demotion() found stuck process %d [%s], moving to JETSAM_PRIORITY_AGING_BAND1_STUCK\n",
						    proc_getpid(p), (*p->p_name ? p->p_name : "(unknown)"));
						memstat_update_priority_locked(p, JETSAM_PRIORITY_AGING_BAND1_STUCK, MEMSTAT_PRIORITY_NO_AGING);
						idle_delay_time = _memstat_sysprocs_aging_stuck_delay_time(p);
						KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_NONE,
						    proc_pid(p), JETSAM_PRIORITY_AGING_BAND1_STUCK, p->p_memstat_idledeadline + idle_delay_time);
					} else {
						memorystatus_log("memorystatus_perform_idle_demotion() timed out stuck process %d [%s], moving to idle band\n",
						    proc_getpid(p), proc_best_name(p));
						memstat_update_priority_locked(p, JETSAM_PRIORITY_IDLE, MEMSTAT_PRIORITY_NO_AGING);
						KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_NONE,
						    proc_pid(p), JETSAM_PRIORITY_IDLE, p->p_memstat_idledeadline);
						idle_delay_time = 0;
					}
				}

				p->p_memstat_idledeadline += idle_delay_time;
			} else {
				memstat_update_priority_locked(p, JETSAM_PRIORITY_IDLE, MEMSTAT_PRIORITY_NO_AGING);
				KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_NONE,
				    proc_pid(p), JETSAM_PRIORITY_IDLE, p->p_memstat_idledeadline);
			}
			p = next_proc;
		} else {
			// No further candidates
			break;
		}
	}
}

static void
memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2)
{
	memorystatus_log_debug("memorystatus_perform_idle_demotion()\n");

	if (!system_procs_aging_band && !system_procs_aging_band_stuck && !applications_aging_band) {
		return;
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_START);

	proc_list_lock();

	_memstat_perform_idle_demotion_for_band(system_procs_aging_band);
	_memstat_perform_idle_demotion_for_band(system_procs_aging_band_stuck);
	_memstat_perform_idle_demotion_for_band(applications_aging_band);

	_memstat_reschedule_idle_demotion_locked();

	proc_list_unlock();

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_END);
}

/*
 * Schedule a process for idle demotion. Updates the process' idle deadline
 * and marks it as aging. The caller is responsible for rescheduling the idle
 * demotion thread
 */
static void
_memstat_schedule_idle_demotion_locked(proc_t p)
{
	uint64_t  idle_delay_time = 0;
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	assert(system_procs_aging_band || applications_aging_band);
	assert(!_memstat_proc_is_aging(p));

	memorystatus_log_debug(
		"%s: scheduling demotion to idle band for pid %d (dirty:0x%x).\n",
		__func__, proc_getpid(p), p->p_memstat_dirty);

	idle_delay_time = isSysProc(p) ? memorystatus_sysprocs_idle_time(p) :
	    memorystatus_apps_idle_time(p);
	p->p_memstat_dirty |= P_DIRTY_AGING_IN_PROGRESS;
	p->p_memstat_idledeadline = mach_absolute_time() + idle_delay_time;
}

/*
 * Cancel a process' idle demotion. The caller must also reschedule the idle
 * demotion thread.
 */
static void
_memstat_invalidate_idle_demotion_locked(proc_t p)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	assert(system_procs_aging_band || applications_aging_band);
	assert(_memstat_proc_is_aging(p));

	memorystatus_log_debug(
		"%s: invalidating demotion to idle band for %s [%d]\n",
		__func__, proc_best_name(p), proc_getpid(p));

	p->p_memstat_idledeadline = 0;
	p->p_memstat_dirty &= ~P_DIRTY_AGING_IN_PROGRESS;
}

/*
 * Return the earliest idle deadline of all aging procs. Returns 0 if there are
 * no aging procs.
 */
static uint64_t
_memstat_find_earliest_idle_deadline(void)
{
	memstat_bucket_t *demotion_bucket;
	proc_t oldest_proc = PROC_NULL;
	uint32_t aging_app_count = 0, aging_sysproc_count = 0, aging_sysproc_count_stuck = 0;
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	assert(system_procs_aging_band || system_procs_aging_band_stuck || applications_aging_band);

	if (system_procs_aging_band) {
		aging_sysproc_count = memstat_bucket[system_procs_aging_band].count;
	}
	if (system_procs_aging_band_stuck) {
		aging_sysproc_count_stuck = memstat_bucket[system_procs_aging_band_stuck].count;
	}
	if (applications_aging_band) {
		aging_app_count = memstat_bucket[applications_aging_band].count;
	}

	if ((aging_app_count + aging_sysproc_count + aging_sysproc_count_stuck) == 0) {
		return 0;
	}

	if (system_procs_aging_band && aging_sysproc_count > 0) {
		demotion_bucket = &memstat_bucket[system_procs_aging_band];
		oldest_proc = TAILQ_FIRST(&demotion_bucket->list);
	}

	if (system_procs_aging_band_stuck && aging_sysproc_count_stuck > 0) {
		proc_t oldest_sysproc_stuck;
		demotion_bucket = &memstat_bucket[system_procs_aging_band_stuck];
		oldest_sysproc_stuck = TAILQ_FIRST(&demotion_bucket->list);

		if (oldest_proc) {
			if (oldest_sysproc_stuck->p_memstat_idledeadline <
			    oldest_proc->p_memstat_idledeadline) {
				oldest_proc = oldest_sysproc_stuck;
			}
		} else {
			oldest_proc = oldest_sysproc_stuck;
		}
	}

	if (applications_aging_band && aging_app_count > 0) {
		proc_t oldest_app;
		demotion_bucket = &memstat_bucket[applications_aging_band];
		oldest_app = TAILQ_FIRST(&demotion_bucket->list);

		if (!oldest_proc ||
		    (oldest_app->p_memstat_idledeadline <
		    oldest_proc->p_memstat_idledeadline)) {
			oldest_proc = oldest_app;
		}
	}

	assert(oldest_proc);
	assert(oldest_proc->p_memstat_idledeadline);
	assert(_memstat_proc_is_aging(oldest_proc));

	return oldest_proc->p_memstat_idledeadline;
}

/*
 * Reschedule or cancel a pending wakeup of the idle_demotion thread. If called
 * in response to a process transitioning in/out of the aging band, then
 * rescheduling must occur *after* the new priority is updated.
 */
static void
_memstat_reschedule_idle_demotion_locked(void)
{
	uint64_t idle_deadline;
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	if (!system_procs_aging_band && !applications_aging_band) {
		return;
	}
	idle_deadline = _memstat_find_earliest_idle_deadline();
	if (idle_deadline == 0) {
		/* No aging processes, cancel call to demotion thread */
		thread_call_cancel(memorystatus_idle_demotion_call);
	} else if (memstat_idle_demotion_deadline != idle_deadline) {
		thread_call_enter_delayed(memorystatus_idle_demotion_call, idle_deadline);
	}
	memstat_idle_demotion_deadline = idle_deadline;
}

/*
 * List manipulation
 */

int
memorystatus_add(proc_t p, boolean_t locked)
{
	memstat_bucket_t *bucket;
	bool reschedule_demotion = false;

	memorystatus_log_debug("memorystatus_list_add(): adding pid %d with priority %d.\n",
	    proc_getpid(p), p->p_memstat_effectivepriority);

	if (!locked) {
		proc_list_lock();
	}

	DTRACE_MEMORYSTATUS2(memorystatus_add, proc_t, p, int32_t, p->p_memstat_effectivepriority);

	/* Processes marked internal do not have priority tracked */
	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		goto exit;
	}

	/*
	 * Opt out system processes from being frozen by default.
	 * For coalition-based freezing, we only want to freeze sysprocs that have specifically opted in.
	 */
	if (isSysProc(p)) {
		p->p_memstat_state |= P_MEMSTAT_FREEZE_DISABLED;
	}
#if CONFIG_FREEZE
	memorystatus_freeze_init_proc(p);
#endif

	bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if ((system_procs_aging_band &&
	    p->p_memstat_effectivepriority == system_procs_aging_band) ||
	    (applications_aging_band &&
	    p->p_memstat_effectivepriority == applications_aging_band)) {
		_memstat_schedule_idle_demotion_locked(p);
		reschedule_demotion = true;
	}

	p->p_memstat_prio_start = mach_absolute_time();

	TAILQ_INSERT_TAIL(&bucket->list, p, p_memstat_list);
	bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		bucket->relaunch_high_count++;
	}

	memorystatus_list_count++;

	if (reschedule_demotion) {
		_memstat_reschedule_idle_demotion_locked();
	}

	task_t t = proc_task(p);
	if (t && task_is_app_suspended(t)) {
		_memstat_proc_set_suspended(p);
	}

	_memstat_consider_waking_jetsam_thread();

exit:
	if (!locked) {
		proc_list_unlock();
	}

	return 0;
}

/*
 * Record timestamps if process p is transitioning in/out of the IDLE band.
 */
static void
_memstat_record_prio_transition(proc_t p, int new_priority)
{
	uint64_t now;

	if (p->p_memstat_effectivepriority == new_priority) {
		/* no change in priority */
		return;
	}

	now = mach_absolute_time();

	if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Transitioning out of the idle priority bucket.
		 * Record idle delta.
		 */
		assert(p->p_memstat_prio_start != 0);
		if (now < p->p_memstat_prio_start) {
			// rdar://139660508
			memorystatus_log_error("memorystatus: prio_start > mach_absolute_time "
			    "for %s(%d)? Using delta of 0.\n",
			    proc_best_name(p), proc_getpid(p));
			p->p_memstat_prio_start = now;
		}
		p->p_memstat_idle_delta = now - p->p_memstat_prio_start;

		/*
		 * About to become active and so memory footprint could change.
		 * So mark it eligible for freeze-considerations next time around.
		 */
		p->p_memstat_state &= ~P_MEMSTAT_FREEZE_IGNORE;

		_memstat_consider_waking_jetsam_thread();
	}
	p->p_memstat_prio_start = now;
}

/*
 * Description:
 *	Moves a process from one jetsam bucket to another.
 *	which changes the LRU position of the process.
 *
 *	Monitors transition between buckets and if necessary
 *	will update cached memory limits accordingly.
 *
 */
void
memstat_update_priority_locked(proc_t p,
    int priority,
    memstat_priority_options_t options)
{
	memstat_bucket_t *old_bucket, *new_bucket;
	bool reschedule_demotion = false;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	assert(priority < MEMSTAT_BUCKET_COUNT);
	/* Not allowed */
	assert(!_memstat_proc_is_internal(p));

	/* Ensure that exit isn't underway, leaving the proc retained but removed from its bucket */
	if (proc_list_exited(p)) {
		return;
	}

	memorystatus_log_debug("memorystatus: setting %s(%d) to priority %d, inserting at %s\n",
	    (*p->p_name ? p->p_name : "unknown"), proc_getpid(p), priority,
	    (options & MEMSTAT_PRIORITY_INSERT_HEAD) ? "head" : "tail");

	DTRACE_MEMORYSTATUS3(memorystatus_update_priority, proc_t, p, int32_t, p->p_memstat_effectivepriority, int, priority);

	old_bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if (!(options & MEMSTAT_PRIORITY_NO_AGING)) {
		if (_memstat_proc_is_elevated(p)) {
			/*
			 * 2 types of processes can use the non-standard elevated inactive band:
			 * - Frozen processes that always land in memorystatus_freeze_jetsam_band
			 * OR
			 * - processes that specifically opt-in to the elevated inactive support e.g. docked processes.
			 */
			if (_memstat_proc_is_frozen(p) &&
			    priority <= memorystatus_freeze_jetsam_band) {
				priority = memorystatus_freeze_jetsam_band;
			} else if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE) {
				priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
			}
		}
		if (_memstat_proc_is_tracked(p)) {
			if (system_procs_aging_band && priority <= system_procs_aging_band) {
				if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
					/* process has already aged */
					priority = JETSAM_PRIORITY_IDLE;
				} else {
					priority = system_procs_aging_band;
				}
			} else if (system_procs_aging_band_stuck && priority <= system_procs_aging_band_stuck) {
				if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
					/* process has already aged */
					priority = JETSAM_PRIORITY_IDLE;
				} else {
					/* don't let anyone move anything between sysproc and sysproc stuck inclusive */
					priority = system_procs_aging_band;
				}
			}
		} else if (_memstat_proc_is_managed(p)) {
			if (applications_aging_band && priority <= applications_aging_band) {
				if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
					/* process has already aged */
					priority = JETSAM_PRIORITY_IDLE;
				} else {
					priority = applications_aging_band;
				}
			}
		}
	}

	TAILQ_REMOVE(&old_bucket->list, p, p_memstat_list);
	old_bucket->count--;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		old_bucket->relaunch_high_count--;
	}

	new_bucket = &memstat_bucket[priority];
	if (options & MEMSTAT_PRIORITY_INSERT_HEAD) {
		TAILQ_INSERT_HEAD(&new_bucket->list, p, p_memstat_list);
	} else {
		TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	}
	new_bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		new_bucket->relaunch_high_count++;
	}

	if (p->p_memstat_effectivepriority != priority) {
		/*
		 * This process is transitioning between
		 * jetsam priority buckets.
		 */
		_memstat_record_prio_transition(p, priority);

		if ((system_procs_aging_band &&
		    p->p_memstat_effectivepriority == system_procs_aging_band) ||
		    (system_procs_aging_band_stuck &&
		    p->p_memstat_effectivepriority == system_procs_aging_band_stuck) ||
		    (applications_aging_band &&
		    p->p_memstat_effectivepriority == applications_aging_band)) {
			/* removing this process from an aging band */
			_memstat_invalidate_idle_demotion_locked(p);
			reschedule_demotion = true;
		}

		if ((system_procs_aging_band &&
		    priority == system_procs_aging_band) ||
		    (system_procs_aging_band_stuck &&
		    priority == system_procs_aging_band_stuck) ||
		    (applications_aging_band &&
		    priority == applications_aging_band)) {
			/* placing this process into an aging band */
			_memstat_schedule_idle_demotion_locked(p);
			reschedule_demotion = true;
		}

		if (reschedule_demotion) {
			_memstat_reschedule_idle_demotion_locked();
		}

		KDBG(MEMSTAT_CODE(BSD_MEMSTAT_CHANGE_PRIORITY) | DBG_FUNC_NONE,
		    proc_getpid(p), priority, p->p_memstat_effectivepriority);
		p->p_memstat_effectivepriority = priority;
	}

	if (memorystatus_highwater_enabled) {
		const bool use_active = memstat_proc_is_active_locked(p);
		if (memstat_update_memlimit_locked(p, use_active)) {
			_memstat_write_memlimit_to_ledger_locked(p, use_active, false);
		}
	}

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_apps &&
	    task_could_use_secluded_mem(proc_task(p))) {
		task_set_can_use_secluded_mem(
			proc_task(p),
			(priority >= JETSAM_PRIORITY_FOREGROUND));
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	_memstat_consider_waking_jetsam_thread();
}

int
memorystatus_relaunch_flags_update(proc_t p, int relaunch_flags)
{
	p->p_memstat_relaunch_flags = relaunch_flags;
	KDBG(BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_RELAUNCH_FLAGS), proc_getpid(p), relaunch_flags);
	return 0;
}

#if DEVELOPMENT || DEBUG
static int sysctl_memorystatus_relaunch_flags SYSCTL_HANDLER_ARGS {
#pragma unused(oidp, arg1, arg2)
	proc_t p;
	int relaunch_flags = 0;

	p = current_proc();
	relaunch_flags = p->p_memstat_relaunch_flags;
	switch (relaunch_flags) {
	case P_MEMSTAT_RELAUNCH_LOW:
		relaunch_flags = POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_LOW;
		break;
	case P_MEMSTAT_RELAUNCH_MED:
		relaunch_flags = POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_MED;
		break;
	case P_MEMSTAT_RELAUNCH_HIGH:
		relaunch_flags = POSIX_SPAWN_JETSAM_RELAUNCH_BEHAVIOR_HIGH;
		break;
	}

	return SYSCTL_OUT(req, &relaunch_flags, sizeof(relaunch_flags));
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_relaunch_flags, CTLTYPE_INT | CTLFLAG_RD |
    CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, 0, sysctl_memorystatus_relaunch_flags, "I", "get relaunch flags for current process");
#endif /* DEVELOPMENT || DEBUG */

/*
 * Everything between the idle band and the application agining band
 * are reserved for internal use. We allow some entitled user space programs
 * to use this range for experimentation.
 */
static bool
current_task_can_use_entitled_range()
{
	static const char kInternalJetsamRangeEntitlement[] = "com.apple.private.internal-jetsam-range";
	task_t task = current_task();
	if (task == kernel_task) {
		return true;
	}
	return IOTaskHasEntitlement(task, kInternalJetsamRangeEntitlement);
}

/*
 * Set a process' requested priority band. This is the entry point used during
 * spawn and by memorystatus_control.
 */
int
memorystatus_set_priority(proc_t p, int priority, uint64_t user_data,
    memstat_priority_options_t options)
{
	int ret;

	memorystatus_log_debug("memorystatus: changing (%s) pid %d: priority %d, user_data 0x%llx\n",
	    (*p->p_name ? p->p_name : "unknown"), proc_getpid(p), priority, user_data);

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_UPDATE) | DBG_FUNC_START, proc_getpid(p), priority, user_data, options);

	if (priority == -1) {
		/* Use as shorthand for default priority */
		priority = JETSAM_PRIORITY_DEFAULT;
	} else if (priority > JETSAM_PRIORITY_IDLE && priority <= JETSAM_PRIORITY_AGING_BAND2) {
		/*
		 * Everything between idle and the aging bands are reserved for internal use.
		 * if requested, adjust to JETSAM_PRIORITY_IDLE.
		 * Entitled processes (just munch) can use a subset of this range for testing.
		 */
		if (priority > JETSAM_PRIORITY_ENTITLED_MAX ||
		    !current_task_can_use_entitled_range()) {
			priority = JETSAM_PRIORITY_IDLE;
			options |= MEMSTAT_PRIORITY_NO_AGING;
		}
	} else if (priority == JETSAM_PRIORITY_IDLE_HEAD) {
		/* JETSAM_PRIORITY_IDLE_HEAD inserts at the head of the idle queue */
		priority = JETSAM_PRIORITY_IDLE;
		options |= MEMSTAT_PRIORITY_INSERT_HEAD;
	} else if ((priority < 0) || (priority >= MEMSTAT_BUCKET_COUNT)) {
		/* Sanity check */
		ret = EINVAL;
		goto out;
	}

	proc_list_lock();

	assert(!(p->p_memstat_state & P_MEMSTAT_INTERNAL));

	if ((options & MEMSTAT_PRIORITY_IS_EFFECTIVE) &&
	    (p->p_memstat_state & P_MEMSTAT_PRIORITYUPDATED)) {
		ret = EALREADY;
		proc_list_unlock();
		memorystatus_log_error("memorystatus_update: effective change specified for pid %d, but change already occurred.\n",
		    proc_getpid(p));
		goto out;
	}

	if ((p->p_memstat_state & (P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP)) || proc_list_exited(p)) {
		/*
		 * This could happen when a process calling posix_spawn() is exiting on the jetsam thread.
		 */
		ret = EBUSY;
		proc_list_unlock();
		goto out;
	}

	p->p_memstat_state |= P_MEMSTAT_PRIORITYUPDATED;
	p->p_memstat_userdata = user_data;

	if ((options & MEMSTAT_PRIORITY_IS_ASSERTION)) {
		if (priority != JETSAM_PRIORITY_IDLE) {
			/*
			 * Process is now being managed by assertions,
			 */
			p->p_memstat_state |= P_MEMSTAT_PRIORITY_ASSERTION;
			p->p_memstat_assertionpriority = priority;
		} else if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
			/*
			 * Assertions relinquish control when the process is heading to IDLE.
			 */
			p->p_memstat_state &= ~P_MEMSTAT_PRIORITY_ASSERTION;
		}

		if (_memstat_proc_is_tracked(p) &&
		    (_memstat_proc_is_dirty(p) || !_memstat_proc_can_idle_exit(p))) {
			priority = MAX(p->p_memstat_assertionpriority,
			    p->p_memstat_requestedpriority);
		}
	} else {
		p->p_memstat_requestedpriority = priority;
	}

	memstat_update_priority_locked(p, priority, options);

	proc_list_unlock();
	ret = 0;

out:
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_UPDATE) | DBG_FUNC_END, ret);

	return ret;
}

static int
memstat_set_memlimits_locked(proc_t p, int32_t active_limit,
    int32_t inactive_limit, memlimit_options_t options)
{
	/*
	 * Posix_spawn'd processes and managed processes come through this path to
	 * instantiate ledger limits. Forked processes do not come through this
	 * path and will always receive the default task limit.
	 */

	int err = 0;
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	int32_t default_active_limit = memorystatus_get_default_task_active_limit(p);
	/*
	 * The special value of -1 specifies that this proc wants the default
	 * memory limit
	 */
	if (active_limit <= 0) {
		active_limit = default_active_limit;
	}
	/*
	 * Work around a bug in JetsamProperties whereby processes may mistakenly receive
	 * ActiveSoftMemoryLimit := -1 by forcing the default task limit to be fatal.
	 */
	if (default_active_limit && active_limit == default_active_limit) {
		options |= MEMLIMIT_ACTIVE_FATAL;
	}

	int32_t default_inactive_limit = memorystatus_get_default_task_inactive_limit(p);
	if (inactive_limit <= 0) {
		inactive_limit = default_inactive_limit;
	}
	if (default_inactive_limit && inactive_limit == default_inactive_limit) {
		options |= MEMLIMIT_INACTIVE_FATAL;
	}
#if DEVELOPMENT || DEBUG
	if (p->p_memlimit_increase) {
		/* Apply memlimit increase (for testing with overlay roots) */
		int32_t memlimit_increase = roundToNearestMB(p->p_memlimit_increase);
		active_limit = active_limit + memlimit_increase;
		inactive_limit = inactive_limit + memlimit_increase;
	}
#endif /* DEVELOPMENT || DEBUG */

	memorystatus_log_debug(
		"memorystatus: setting memlimit for %s [%d], "
		"Active(%dMB %s), Inactive(%dMB, %s)\n",
		proc_best_name(p), proc_getpid(p),
		active_limit, ((options & MEMLIMIT_ACTIVE_FATAL) ? "F" : "NF"),
		inactive_limit, ((options & MEMLIMIT_INACTIVE_FATAL) ? "F" : "NF"));

	p->p_memstat_memlimit_active = active_limit;
	p->p_memstat_memlimit_inactive = inactive_limit;
	if (options & MEMLIMIT_INACTIVE_FATAL) {
		p->p_memstat_state |= P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;
	} else {
		p->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;
	}
	if (options & MEMLIMIT_ACTIVE_FATAL) {
		p->p_memstat_state |= P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;
	} else {
		p->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;
	}

	/*
	 * Initialize the cached limits for target process.
	 * When the target process is dirty tracked, it's typically
	 * in a clean state.  Non dirty tracked processes are
	 * typically active (Foreground or above).
	 * But just in case, we don't make assumptions...
	 */
	const bool use_active = memstat_proc_is_active_locked(p);
	if (memorystatus_highwater_enabled &&
	    memstat_update_memlimit_locked(p, use_active)) {
		err = _memstat_write_memlimit_to_ledger_locked(p, use_active, false);
	}

	return err;
}

int
memorystatus_set_memlimits(proc_t p, int32_t active_limit,
    int32_t inactive_limit, memlimit_options_t options)
{
	int err;
	proc_list_lock();
	err = memstat_set_memlimits_locked(p, active_limit, inactive_limit,
	    options);
	proc_list_unlock();
	return err;
}

int
memorystatus_remove(proc_t p)
{
	int ret;
	memstat_bucket_t *bucket;
	bool reschedule = false;

	memorystatus_log_debug("memorystatus_list_remove: removing pid %d\n", proc_getpid(p));

	/* Processes marked internal do not have priority tracked */
	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		return 0;
	}

	/*
	 * Check if this proc is locked (because we're performing a freeze).
	 * If so, we fail and instruct the caller to try again later.
	 */
	if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
		return EAGAIN;
	}

	assert(!(p->p_memstat_state & P_MEMSTAT_INTERNAL));

	bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if ((system_procs_aging_band &&
	    p->p_memstat_effectivepriority == system_procs_aging_band) ||
	    (system_procs_aging_band_stuck &&
	    p->p_memstat_effectivepriority == system_procs_aging_band_stuck) ||
	    (applications_aging_band &&
	    p->p_memstat_effectivepriority == applications_aging_band)) {
		_memstat_invalidate_idle_demotion_locked(p);
		reschedule = true;
	}

	/*
	 * Record idle delta
	 */

	if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		uint64_t now = mach_absolute_time();
		if (now > p->p_memstat_prio_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_prio_start;
		}
	}

	TAILQ_REMOVE(&bucket->list, p, p_memstat_list);
	bucket->count--;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		bucket->relaunch_high_count--;
	}

	memorystatus_list_count--;

	/* If awaiting demotion to the idle band, clean up */
	if (reschedule) {
		_memstat_reschedule_idle_demotion_locked();
	}

#if CONFIG_FREEZE
	if (_memstat_proc_is_frozen(p)) {
		if (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) {
			p->p_memstat_state &= ~P_MEMSTAT_REFREEZE_ELIGIBLE;
			assert(memorystatus_refreeze_eligible_count > 0);
			memorystatus_refreeze_eligible_count--;
		}

		assert(memorystatus_frozen_count > 0);
		memorystatus_frozen_count--;
		if (p->p_memstat_state & P_MEMSTAT_FROZEN_XPC_SERVICE) {
			assert(memorystatus_frozen_count_xpc_service > 0);
			memorystatus_frozen_count_xpc_service--;
		}
		if (strcmp(p->p_name, "com.apple.WebKit.WebContent") == 0) {
			assert(memorystatus_frozen_count_webcontent > 0);
			memorystatus_frozen_count_webcontent--;
		}
		memorystatus_frozen_shared_mb -= p->p_memstat_freeze_sharedanon_pages;
		p->p_memstat_freeze_sharedanon_pages = 0;
	}
#endif /* CONFIG_FREEZE */

	_memstat_proc_set_resumed(p);

#if DEVELOPMENT || DEBUG
	if (proc_getpid(p) == memorystatus_testing_pid) {
		memorystatus_testing_pid = 0;
	}
#endif /* DEVELOPMENT || DEBUG */

	if (p) {
		ret = 0;
	} else {
		ret = ESRCH;
	}

	return ret;
}

/*
 * Validate dirty tracking flags with process state.
 *
 * Return:
 *	0     on success
 *      non-0 on failure
 *
 * The proc_list_lock is held by the caller.
 */

static int
memorystatus_validate_track_flags(struct proc *target_p, uint32_t pcontrol)
{
	/* See that the process isn't marked for termination */
	if (target_p->p_memstat_dirty & P_DIRTY_TERMINATED) {
		return EBUSY;
	}

	/* Idle exit requires that process be tracked */
	if ((pcontrol & PROC_DIRTY_ALLOW_IDLE_EXIT) &&
	    !(pcontrol & PROC_DIRTY_TRACK)) {
		return EINVAL;
	}

	/* 'Launch in progress' tracking requires that process have enabled dirty tracking too. */
	if ((pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) &&
	    !(pcontrol & PROC_DIRTY_TRACK)) {
		return EINVAL;
	}

	/* Only one type of DEFER behavior is allowed.*/
	if ((pcontrol & PROC_DIRTY_DEFER) &&
	    (pcontrol & PROC_DIRTY_DEFER_ALWAYS)) {
		return EINVAL;
	}

	/* Deferral is only relevant if idle exit is specified */
	if (((pcontrol & PROC_DIRTY_DEFER) ||
	    (pcontrol & PROC_DIRTY_DEFER_ALWAYS)) &&
	    !(pcontrol & PROC_DIRTY_ALLOWS_IDLE_EXIT)) {
		return EINVAL;
	}

	return 0;
}

/*
 * Processes can opt to have their state tracked by the kernel, indicating  when they are busy (dirty) or idle
 * (clean). They may also indicate that they support termination when idle, with the result that they are promoted
 * to their desired, higher, jetsam priority when dirty (and are therefore killed later), and demoted to the low
 * priority idle band when clean (and killed earlier, protecting higher priority procesess).
 *
 * If the deferral flag is set, then newly tracked processes will be protected for an initial period (as determined by
 * memorystatus_sysprocs_idle_delay_time); if they go clean during this time, then they will be moved to a deferred-idle band
 * with a slightly higher priority, guarding against immediate termination under memory pressure and being unable to
 * make forward progress. Finally, when the guard expires, they will be moved to the standard, lowest-priority, idle
 * band. The deferral can be cleared early by clearing the appropriate flag.
 *
 * The deferral timer is active only for the duration that the process is marked as guarded and clean; if the process
 * is marked dirty, the timer will be cancelled. Upon being subsequently marked clean, the deferment will either be
 * re-enabled or the guard state cleared, depending on whether the guard deadline has passed.
 */

int
memorystatus_dirty_track(proc_t p, uint32_t pcontrol)
{
	unsigned int old_dirty;
	boolean_t defer_now = FALSE;
	int ret = 0;
	int priority;
	memstat_priority_options_t priority_options =
	    MEMSTAT_PRIORITY_OPTIONS_NONE;

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_DIRTY_TRACK),
	    proc_getpid(p), p->p_memstat_dirty, pcontrol);

	proc_list_lock();

	if (proc_list_exited(p)) {
		/*
		 * Process is on its way out.
		 */
		ret = EBUSY;
		goto exit;
	}

	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}

	if ((ret = memorystatus_validate_track_flags(p, pcontrol)) != 0) {
		/* error  */
		goto exit;
	}

	old_dirty = p->p_memstat_dirty;

	/* These bits are cumulative, as per <rdar://problem/11159924> */
	if (pcontrol & PROC_DIRTY_TRACK) {
		/* Request to turn ON Dirty tracking... */
		if (p->p_memstat_state & P_MEMSTAT_MANAGED) {
			/* on a process managed by RunningBoard or its equivalent...*/
			if (!_memstat_proc_cached_memlimit_is_fatal(p)) {
				/* but this might be an app because there's no fatal limits
				 * NB: This _big_ assumption is not universal. What we really
				 * need is a way to say this is an _APP_ and we can't have dirty
				 * tracking turned ON for it. Lacking that functionality we clump
				 * together some checks and try to do the best detection we can.
				 * Reason we can't allow addition of these flags is because, per the
				 * kernel checks, they change the role of a process from app to daemon. And the
				 * AGING_IN_PROGRESS bits might still be set i.e. it needs to be demoted
				 * correctly from the right aging band (app or sysproc). We can't simply try
				 * to invalidate the demotion here because, owing to assertion priorities, we
				 * might not be in the aging bands.
				 */
				memorystatus_log(
					"memorystatus: Denying dirty-tracking opt-in for managed %s [%d]\n",
					proc_best_name(p), proc_getpid(p));
				/* fail silently to avoid an XPC assertion... */
				ret = 0;
				goto exit;
			}
		}

		p->p_memstat_dirty |= P_DIRTY_TRACK;
	}

	if (pcontrol & PROC_DIRTY_ALLOW_IDLE_EXIT) {
		p->p_memstat_dirty |= P_DIRTY_ALLOW_IDLE_EXIT;
	}

	if (pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) {
		p->p_memstat_dirty |= P_DIRTY_LAUNCH_IN_PROGRESS;
	}

	/*
	 * NB: All processes are now automatically enrolled in idle aging
	 * regardless of whether they request to be deferred.
	 */
	if (pcontrol & (PROC_DIRTY_DEFER | PROC_DIRTY_DEFER_ALWAYS)) {
		if ((pcontrol & (PROC_DIRTY_DEFER)) &&
		    !(old_dirty & P_DIRTY_DEFER)) {
			p->p_memstat_dirty |= P_DIRTY_DEFER;
		}

		if ((pcontrol & (PROC_DIRTY_DEFER_ALWAYS)) &&
		    !(old_dirty & P_DIRTY_DEFER_ALWAYS)) {
			p->p_memstat_dirty |= P_DIRTY_DEFER_ALWAYS;
		}

		defer_now = TRUE;
	}

	memorystatus_log_info(
		"%s [%d] enrolled in ActivityTracking tracked %d / idle-exit %d / defer %d / dirty %d",
		proc_best_name(p), proc_getpid(p),
		_memstat_proc_is_tracked(p), _memstat_proc_can_idle_exit(p), defer_now,
		_memstat_proc_is_dirty(p));

	if (!_memstat_proc_is_dirty(p) && _memstat_proc_is_tracked(p) &&
	    _memstat_proc_can_idle_exit(p)) {
		priority = JETSAM_PRIORITY_IDLE;
		if (!defer_now && _memstat_proc_is_aging(p)) {
			/*
			 * Historically, some processes have tried to use this to opt out
			 * of the 'aging' facility.
			 */
			priority_options |= MEMSTAT_PRIORITY_NO_AGING;
		}
	} else {
		priority = p->p_memstat_requestedpriority;
	}

	if (_memstat_proc_has_priority_assertion(p)) {
		priority = MAX(priority, p->p_memstat_assertionpriority);
	}

	memstat_update_priority_locked(p, priority, priority_options);

exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_set(proc_t p, boolean_t self, uint32_t pcontrol)
{
	int ret = 0;
	bool kill = false;
	bool was_dirty;
	bool now_dirty = false;
	int priority;
	task_t t = proc_task(p);

	memorystatus_log_debug("memorystatus_dirty_set(): %d %d 0x%x 0x%x\n", self, proc_getpid(p), pcontrol, p->p_memstat_dirty);
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_DIRTY_SET), proc_getpid(p), self, pcontrol);

	proc_list_lock();

	if (proc_list_exited(p)) {
		/*
		 * Process is on its way out.
		 */
		ret = EBUSY;
		goto exit;
	}

	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}

	was_dirty = _memstat_proc_is_dirty(p);

	if (!_memstat_proc_is_tracked(p)) {
		/* Dirty tracking not enabled */
		ret = EINVAL;
		goto exit;
	} else if (pcontrol && (p->p_memstat_dirty & P_DIRTY_TERMINATED)) {
		/*
		 * Process is set to be terminated and we're attempting to mark it dirty.
		 * Set for termination and marking as clean is OK - see <rdar://problem/10594349>.
		 */
		ret = EBUSY;
		goto exit;
	}

	int flag = (self == TRUE) ? P_DIRTY : P_DIRTY_SHUTDOWN;
	if (pcontrol && !(p->p_memstat_dirty & flag)) {
		/* Mark the process as having been dirtied at some point */
		p->p_memstat_dirty |= (flag | P_DIRTY_MARKED);
	} else if ((pcontrol == 0) && (p->p_memstat_dirty & flag)) {
		if ((flag == P_DIRTY_SHUTDOWN) && (!(p->p_memstat_dirty & P_DIRTY))) {
			/* Clearing the dirty shutdown flag, and the process is otherwise clean - kill */
			p->p_memstat_dirty |= P_DIRTY_TERMINATED;
			kill = true;
		} else if ((flag == P_DIRTY) && (p->p_memstat_dirty & P_DIRTY_TERMINATED)) {
			/* Kill previously terminated processes if set clean */
			kill = true;
		}
		p->p_memstat_dirty &= ~flag;
	} else {
		/* Already set */
		ret = EALREADY;
		goto exit;
	}

	now_dirty = _memstat_proc_is_dirty(p);

	if (was_dirty && !now_dirty) {
		if (_memstat_proc_can_idle_exit(p)) {
			/*
			 * Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band OR it might be heading back
			 * there once it's clean again. For the legacy case, this only applies if it has some protection window left.
			 * P_DIRTY_DEFER: one-time protection window given at launch
			 * P_DIRTY_DEFER_ALWAYS: protection window given for every dirty->clean transition. Like non-legacy mode.
			 *
			 * Non-Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band. It will always stop over
			 * in that band on it's way to IDLE.
			 */
			assert(!_memstat_proc_is_aging(p));
			priority = JETSAM_PRIORITY_IDLE;
		} else {
			priority = p->p_memstat_requestedpriority;
		}
		task_ledger_settle_dirty_time(t);
		task_set_dirty_start(t, 0);
	} else if (!was_dirty && now_dirty) {
		priority = p->p_memstat_requestedpriority;
		task_set_dirty_start(t, mach_absolute_time());
	}

	if (_memstat_proc_has_priority_assertion(p)) {
		priority = MAX(priority, p->p_memstat_assertionpriority);
	}

	memstat_update_priority_locked(p, priority, MEMSTAT_PRIORITY_OPTIONS_NONE);

	if (kill) {
		if (proc_ref(p, true) == p) {
			proc_list_unlock();
			psignal(p, SIGKILL);
			proc_list_lock();
			proc_rele(p);
		}
	}

exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_clear(proc_t p, uint32_t pcontrol)
{
	int ret = 0;

	memorystatus_log_debug("memorystatus_dirty_clear(): %d 0x%x 0x%x\n", proc_getpid(p), pcontrol, p->p_memstat_dirty);
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_DIRTY_CLEAR), proc_getpid(p), pcontrol);

	proc_list_lock();

	if (proc_list_exited(p)) {
		/*
		 * Process is on its way out.
		 */
		ret = EBUSY;
		goto exit;
	}

	if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
		ret = EPERM;
		goto exit;
	}

	if (!_memstat_proc_is_tracked(p)) {
		/* Dirty tracking not enabled */
		ret = EINVAL;
		goto exit;
	}

	if (!pcontrol || (pcontrol & (PROC_DIRTY_LAUNCH_IN_PROGRESS | PROC_DIRTY_DEFER | PROC_DIRTY_DEFER_ALWAYS)) == 0) {
		ret = EINVAL;
		goto exit;
	}

	if (pcontrol & PROC_DIRTY_LAUNCH_IN_PROGRESS) {
		p->p_memstat_dirty &= ~P_DIRTY_LAUNCH_IN_PROGRESS;
	}

	/* This can be set and cleared exactly once. */
	if (pcontrol & (PROC_DIRTY_DEFER | PROC_DIRTY_DEFER_ALWAYS)) {
		if (p->p_memstat_dirty & P_DIRTY_DEFER) {
			p->p_memstat_dirty &= ~(P_DIRTY_DEFER);
		}

		if (p->p_memstat_dirty & P_DIRTY_DEFER_ALWAYS) {
			p->p_memstat_dirty &= ~(P_DIRTY_DEFER_ALWAYS);
		}

		if (_memstat_proc_is_aging(p)) {
			memstat_update_priority_locked(p, JETSAM_PRIORITY_IDLE,
			    MEMSTAT_PRIORITY_NO_AGING);
		}
	}

	ret = 0;
exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_get(proc_t p, boolean_t locked)
{
	int ret = 0;

	if (!locked) {
		proc_list_lock();
	}

	if (_memstat_proc_is_tracked(p)) {
		ret |= PROC_DIRTY_TRACKED;
		if (_memstat_proc_can_idle_exit(p)) {
			ret |= PROC_DIRTY_ALLOWS_IDLE_EXIT;
		}
		if (p->p_memstat_dirty & P_DIRTY) {
			ret |= PROC_DIRTY_IS_DIRTY;
		}
		if (p->p_memstat_dirty & P_DIRTY_LAUNCH_IN_PROGRESS) {
			ret |= PROC_DIRTY_LAUNCH_IS_IN_PROGRESS;
		}
	}

	if (!locked) {
		proc_list_unlock();
	}

	return ret;
}

int
memorystatus_on_terminate(proc_t p)
{
	int sig;

	proc_list_lock();

	p->p_memstat_dirty |= P_DIRTY_TERMINATED;

	if ((_memstat_proc_is_tracked(p) && !_memstat_proc_is_dirty(p)) ||
	    (_memstat_proc_is_suspended(p))) {
		/*
		 * Mark as terminated and issue SIGKILL if:-
		 * - process is clean, or,
		 * - if process is dirty but suspended. This case is likely
		 * an extension because apps don't opt into dirty-tracking
		 * and daemons aren't suspended.
		 */
#if DEVELOPMENT || DEBUG
		if (_memstat_proc_is_suspended(p)) {
			memorystatus_log(
				"memorystatus: sending suspended process %s (pid %d) SIGKILL\n",
				(*p->p_name ? p->p_name : "unknown"), proc_getpid(p));
		}
#endif /* DEVELOPMENT || DEBUG */
		sig = SIGKILL;
	} else {
		/* Dirty, terminated, or state tracking is unsupported; issue SIGTERM to allow cleanup */
		sig = SIGTERM;
	}

	proc_list_unlock();

	return sig;
}

void
memorystatus_on_suspend(proc_t p)
{
#if CONFIG_FREEZE
	uint32_t pages;
	memorystatus_get_task_page_counts(proc_task(p), &pages, NULL, NULL);
#endif
	proc_list_lock();

	_memstat_proc_set_suspended(p);

	/* Check if proc is marked for termination */
	bool kill_process = !!(p->p_memstat_dirty & P_DIRTY_TERMINATED);
	proc_list_unlock();

	if (kill_process) {
		psignal(p, SIGKILL);
	}
}

extern uint64_t memorystatus_thaw_count_since_boot;

void
memorystatus_on_resume(proc_t p)
{
#if CONFIG_FREEZE
	pid_t pid;
#endif

	proc_list_lock();

#if CONFIG_FREEZE
	const bool frozen = _memstat_proc_is_frozen(p);
	if (frozen) {
		/*
		 * Now that we don't _thaw_ a process completely,
		 * resuming it (and having some on-demand swapins)
		 * shouldn't preclude it from being counted as frozen.
		 *
		 * memorystatus_frozen_count--;
		 *
		 * We preserve the P_MEMSTAT_FROZEN state since the process
		 * could have state on disk AND so will deserve some protection
		 * in the jetsam bands.
		 */
		if ((p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) == 0) {
			p->p_memstat_state |= P_MEMSTAT_REFREEZE_ELIGIBLE;
			memorystatus_refreeze_eligible_count++;
		}
		if (p->p_memstat_thaw_count == 0 || p->p_memstat_last_thaw_interval < memorystatus_freeze_current_interval) {
			os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_thawed), relaxed);
			if (strcmp(p->p_name, "com.apple.WebKit.WebContent") == 0) {
				os_atomic_inc(&(memorystatus_freezer_stats.mfs_processes_thawed_webcontent), relaxed);
			}
		}
		p->p_memstat_last_thaw_interval = memorystatus_freeze_current_interval;
		p->p_memstat_thaw_count++;

		memorystatus_freeze_last_pid_thawed = p->p_pid;
		memorystatus_freeze_last_pid_thawed_ts = mach_absolute_time();

		memorystatus_thaw_count++;
		memorystatus_thaw_count_since_boot++;
	}

	pid = proc_getpid(p);
#endif

	/*
	 * P_MEMSTAT_FROZEN will remain unchanged. This used to be:
	 * p->p_memstat_state &= ~(P_MEMSTAT_SUSPENDED | P_MEMSTAT_FROZEN);
	 */
	_memstat_proc_set_resumed(p);

	proc_list_unlock();

#if CONFIG_FREEZE
	if (frozen) {
		memorystatus_freeze_entry_t data = { pid, FALSE, 0 };
		memorystatus_send_note(kMemorystatusFreezeNote, &data, sizeof(data));
	}
#endif
}

void
memorystatus_on_inactivity(proc_t p)
{
#pragma unused(p)
#if CONFIG_FREEZE
	/* Wake the freeze thread */
	thread_wakeup((event_t)&memorystatus_freeze_wakeup);
#endif
}

/*
 * The proc_list_lock is held by the caller.
 */
static memorystatus_proc_state_t
_memstat_build_state(proc_t p)
{
	uint32_t snapshot_state = 0;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	/* General */
	if (_memstat_proc_is_suspended(p)) {
		snapshot_state |= kMemorystatusSuspended;
	}
	if (_memstat_proc_is_frozen(p)) {
		snapshot_state |= kMemorystatusFrozen;
	}
	if (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) {
		snapshot_state |= kMemorystatusWasThawed;
	}
	if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
		snapshot_state |= kMemorystatusAssertion;
	}

	/* Tracking */
	if (_memstat_proc_is_tracked(p)) {
		snapshot_state |= kMemorystatusTracked;
	}
	if (_memstat_proc_can_idle_exit(p)) {
		snapshot_state |= kMemorystatusSupportsIdleExit;
	}
	if (_memstat_proc_is_dirty(p)) {
		snapshot_state |= kMemorystatusDirty;
	}
	if (memstat_proc_is_active_locked(p)) {
		snapshot_state |= kMemorystatusActive;
	}

	/* Probable relaunch behavior */
	if (p->p_memstat_relaunch_flags & P_MEMSTAT_RELAUNCH_LOW) {
		snapshot_state |= kMemorystatusRelaunchLow;
	}
	if (p->p_memstat_relaunch_flags & P_MEMSTAT_RELAUNCH_MED) {
		snapshot_state |= kMemorystatusRelaunchMed;
	}
	if (p->p_memstat_relaunch_flags & P_MEMSTAT_RELAUNCH_HIGH) {
		snapshot_state |= kMemorystatusRelaunchHigh;
	}

	return snapshot_state;
}

bool
memstat_kill_idle_process(memorystatus_kill_cause_t cause,
    uint64_t *footprint_out)
{
	proc_t p = PROC_NULL;
	uint64_t current_time;
	bool killed = FALSE;
	unsigned int i = 0;
	os_reason_t jetsam_reason = OS_REASON_NULL;

	/* Pick next idle exit victim. */
	current_time = mach_absolute_time();

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_IDLE_EXIT);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus: failed to allocate jetsam reason\n");
	}

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&i, FALSE);
	while (p) {
		/* No need to look beyond the idle band */
		if (p->p_memstat_effectivepriority != JETSAM_PRIORITY_IDLE) {
			break;
		}

		if ((_memstat_proc_can_idle_exit(p) && !_memstat_proc_is_dirty(p)) ||
		    (_memstat_proc_is_managed(p) && !_memstat_proc_has_priority_assertion(p))) {
			if (current_time >= p->p_memstat_idledeadline) {
				p->p_memstat_dirty |= P_DIRTY_TERMINATED;
				p = proc_ref(p, true);
				break;
			}
		}

		p = memorystatus_get_next_proc_locked(&i, p, FALSE);
	}

	proc_list_unlock();

	if (p) {
		memorystatus_log(
			"memorystatus: killing_idle_process pid %d [%s] jetsam_reason->osr_code: %llu\n",
			proc_getpid(p), proc_best_name(p), jetsam_reason->osr_code);
		killed = memorystatus_do_kill(p, cause, jetsam_reason, footprint_out);
		proc_rele(p);
	} else {
		os_reason_free(jetsam_reason);
	}

	return killed;
}

/*
 * Consider waking the jetsam thread. Returns true if the thread was awoken.
 */
static bool
_memstat_consider_waking_jetsam_thread(void)
{
#if CONFIG_JETSAM
	if (memstat_evaluate_page_shortage(NULL, NULL, NULL, NULL)) {
		memorystatus_thread_wake();
		return true;
	}
#endif /* CONFIG_JETSAM */
	return false;
}

void
memorystatus_thread_wake()
{
	int thr_id = 0;
	int active_thr = atomic_load(&active_jetsam_threads);

	/* Wakeup all the jetsam threads */
	for (thr_id = 0; thr_id < active_thr; thr_id++) {
		jetsam_state_t jetsam_thread = &jetsam_threads[thr_id];
		sched_cond_signal(&(jetsam_thread->jt_wakeup_cond), jetsam_thread->thread);
	}
}

void
memorystatus_respond_to_compressor_exhaustion(void)
{
#if CONFIG_JETSAM
	memorystatus_thread_wake();
#else /* !CONFIG_JETSAM */
	if (kill_on_no_paging_space) {
		memorystatus_thread_wake();
	} else {
		if (memstat_get_idle_proccnt() > 0) {
			/* There are idle processes to kill */
			memorystatus_thread_wake();
		}

		/*
		 * Throttle how often the jetsam thread is woken due to
		 * compressor/swap exhaustion
		 */
		uint64_t now = mach_absolute_time();
		uint64_t delta_since_last_no_space_ns;
		uint64_t last_action_ts = os_atomic_load(&last_no_space_action_ts, relaxed);
		if (now < last_action_ts) {
			/* Raced with a concurrent no-paging-space action */
			return;
		}
		absolutetime_to_nanoseconds(now - last_action_ts, &delta_since_last_no_space_ns);
		if (delta_since_last_no_space_ns > no_paging_space_action_throttle_delay_ns) {
			/* TODO: this should happen on the memorystatus thread (rdar://138409129) */
			if (os_atomic_cmpxchg(&last_no_space_action_ts, last_action_ts, now, relaxed)) {
				bool should_notify = no_paging_space_action();
				if (should_notify) {
					/* Put up the "Out of Application Memory" dialogue */
					memorystatus_send_low_swap_note();
				}
			}
		}
	}
#endif /* CONFIG_JETSAM */
}

void
memorystatus_respond_to_swap_exhaustion(void)
{
#if CONFIG_JETSAM
	/*
	 * On systems with both swap and jetsam,
	 * just wake up the jetsam thread and have it handle the low swap condition
	 * by killing apps.
	 */
	if (jetsam_kill_on_low_swap) {
		memorystatus_thread_wake();
	}
#else /* !CONFIG_JETSAM */
	memorystatus_respond_to_compressor_exhaustion();
#endif /* CONFIG_JETSAM */
}

#if CONFIG_JETSAM
static void
memorystatus_thread_pool_max()
{
	/* Increase the jetsam thread pool to max_jetsam_threads */
	int max_threads = max_jetsam_threads;
	memorystatus_log_info("Expanding memorystatus pool to %d\n", max_threads);
	os_atomic_store(&active_jetsam_threads, max_threads, relaxed);
}

static void
memorystatus_thread_pool_default()
{
	/* Restore the jetsam thread pool to a single thread */
	memorystatus_log_info("Reverting memorystatus pool back to 1\n");
	os_atomic_store(&active_jetsam_threads, 1, relaxed);
}
#endif /* CONFIG_JETSAM */

/*
 * An offset applied to non-critical page shortage thresholds.
 */
static uint32_t
_memstat_page_shortage_offset(void)
{
	uint32_t offset = 0;
	if (os_atomic_load(&memstat_policy_config, acquire) & kPolicyClearTheDecks) {
		offset += memstat_ctd_offset;
	}
	if (os_atomic_load(&memstat_policy_config, acquire) & kPolicyBallastDrain) {
		offset += memstat_ballast_offset;
	}
	return offset;
}

uint32_t
memorystatus_get_critical_page_shortage_threshold(void)
{
	return memstat_critical_threshold;
}

uint32_t
memorystatus_get_idle_exit_page_shortage_threshold(void)
{
	uint32_t offset = _memstat_page_shortage_offset();
	return memstat_idle_threshold + offset;
}

uint32_t
memorystatus_get_soft_memlimit_page_shortage_threshold(void)
{
	uint32_t offset = _memstat_page_shortage_offset();
	return memstat_soft_threshold + offset;
}

uint32_t
memorystatus_get_reaper_page_shortage_threshold(void)
{
	uint32_t offset = _memstat_page_shortage_offset();
	return memstat_reaper_threshold + offset;
}

#if CONFIG_JETSAM
void
_memstat_reaper_check_oldest_reapable_proc_info_timeout(void)
{
	if (memstat_oldest_reapable_proc_prio_start != MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_UNKNOWN) {
		uint64_t curr_ts_matu = mach_absolute_time();
		if (curr_ts_matu > memstat_oldest_reapable_proc_info_expiration_ts_matu) {
			memstat_oldest_reapable_proc_prio_start = MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_UNKNOWN;
			memstat_oldest_reapable_proc_will_be_reapable_at_ts_matu = 0;
		}
	}
}

void
_memstat_reaper_start_sweep(void)
{
	if (!memstat_reaper_is_currently_sweeping) {
		memorystatus_log("memorystatus: _memstat_reaper_start_sweep: reaper sweep starting\n");
		memstat_reaper_is_currently_sweeping = true;
		memstat_reaper_start_ts_matu = mach_absolute_time();
		memstat_reaper_current_sweep_stats.kill_count = 0;
		memstat_reaper_current_sweep_stats.memory_freed_bytes = 0;
	}
}

void
_memstat_reaper_end_sweep(void)
{
	uint64_t rescan_delta_matu;
	if (memstat_reaper_is_currently_sweeping) {
		uint64_t delta_time_nsec;

		/* For idle reaper kills, we skip the normal compaction after each kill,
		 * and do one compaction here at the end of the sweep.
		 */
		vm_run_compactor();

		absolutetime_to_nanoseconds(mach_absolute_time() - memstat_reaper_start_ts_matu, &delta_time_nsec);
		memstat_reaper_cumulative_stats.sweep_count++;
		memstat_reaper_cumulative_memory_freed_mb = (uint32_t)(memstat_reaper_cumulative_stats.memory_freed_bytes >> 20);
		memorystatus_log("memorystatus: _memstat_reaper_end_sweep: reaper sweep ended, %d processes killed, %lluMB freed, %llums elapsed, %lluus/process\n",
		    memstat_reaper_current_sweep_stats.kill_count,
		    memstat_reaper_current_sweep_stats.memory_freed_bytes >> 20,
		    (delta_time_nsec / NSEC_PER_MSEC),
		    memstat_reaper_current_sweep_stats.kill_count ? ((delta_time_nsec / NSEC_PER_USEC) / memstat_reaper_current_sweep_stats.kill_count) : 0);
		memorystatus_log("memorystatus: _memstat_reaper_end_sweep: reaper totals: %d sweeps, %d processes killed, %dMB freed\n",
		    memstat_reaper_cumulative_stats.sweep_count,
		    memstat_reaper_cumulative_stats.kill_count,
		    memstat_reaper_cumulative_memory_freed_mb);
		memstat_reaper_is_currently_sweeping = false;
		nanoseconds_to_absolutetime((memstat_reaper_rescan_secs * NSEC_PER_SEC), &rescan_delta_matu);
		memstat_reaper_can_run_after_ts_matu = mach_absolute_time() + rescan_delta_matu;
	}
}

void
_memstat_reaper_record_kill(uint64_t bytes_freed)
{
	memstat_reaper_current_sweep_stats.kill_count++;
	memstat_reaper_current_sweep_stats.memory_freed_bytes += bytes_freed;
	memstat_reaper_cumulative_stats.kill_count++;
	memstat_reaper_cumulative_stats.memory_freed_bytes += bytes_freed;
}
#endif /* CONFIG_JETSAM */

const char*
_memstat_relaunch_flags_description(uint32_t flags)
{
	switch (flags) {
	case P_MEMSTAT_RELAUNCH_UNKNOWN:
		return "-";
	case P_MEMSTAT_RELAUNCH_LOW:
		return "low";
	case P_MEMSTAT_RELAUNCH_MED:
		return "med";
	case P_MEMSTAT_RELAUNCH_HIGH:
		return "high";
	default:
		return "??";
	}
}

bool
memstat_evaluate_page_shortage(
	bool *should_enforce_memlimits,
	bool *should_idle_exit,
	bool *should_jetsam,
	bool *should_reap)
{
	bool requires_action = false;
	if (should_enforce_memlimits) {
		*should_enforce_memlimits = false;
	}
	if (should_idle_exit) {
		*should_idle_exit = false;
	}
	if (should_jetsam) {
		*should_jetsam = false;
	}
	if (should_reap) {
		*should_reap = false;
	}
#if CONFIG_JETSAM
	uint32_t available_page_count = os_atomic_load(&memorystatus_available_pages, relaxed);
#if VM_PRESSURE_EVENTS
	if (available_page_count <
	    memorystatus_get_soft_memlimit_page_shortage_threshold()) {
		/*
		 * Only wake the jetsam thread if there are hwm violators to
		 * kill
		 */
		bool hwm_candidates = os_atomic_load(&memorystatus_hwm_candidates, acquire);
		requires_action = requires_action || hwm_candidates;
		if (should_enforce_memlimits) {
			*should_enforce_memlimits = true;
		}
	}
#endif /* VM_PRESSURE_EVENTS */

	if (memstat_reaper_enabled) {
		/*
		 * Only wake the jetsam thread to do reaper kills if the reaper is currently alreay running a sweep
		 * OR if other conditions suggest that we should start a sweep
		 */

		// if we are already in the middle of a reaper sweep already, continue it
		if (memstat_reaper_is_currently_sweeping) {
			requires_action = true;
			if (should_reap) {
				*should_reap = true;
			}
		} else {
			uint64_t curr_ts_matu = mach_absolute_time();
			// if we are not already in the middle of a reaper sweep, do very quick tests to see if we should possibly start one:
			// - the minimum rescan time has passed since the end of the last sweep
			// - we are below the page threshold
			// - the oldest reapable process is old enough to be a reaper candidate now

			if ((curr_ts_matu > memstat_reaper_can_run_after_ts_matu)
			    && (available_page_count < memorystatus_get_reaper_page_shortage_threshold())) {
				_memstat_reaper_check_oldest_reapable_proc_info_timeout();

				if (memstat_oldest_reapable_proc_prio_start == MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_NONE) {
					memorystatus_log_debug("memorystatus: memstat_evaluate_page_shortage: no known-reapable processes\n");
				} else {
					if (curr_ts_matu >= memstat_oldest_reapable_proc_will_be_reapable_at_ts_matu) {
						requires_action = true;
						if (should_reap) {
							*should_reap = true;
							memorystatus_log_debug("memorystatus: memstat_evaluate_page_shortage: should start reaping long-idle processes\n");
						}
						_memstat_reaper_start_sweep();
					}
				}
			}
		}
	}
	if (available_page_count < memorystatus_get_idle_exit_page_shortage_threshold()) {
		/*
		 * Only wake the jetsam thread if there are idle processes that
		 * could exit.
		 */
		uint32_t idle_proc_count = os_atomic_load(
			&memstat_bucket[JETSAM_PRIORITY_IDLE].count, relaxed);
		requires_action = requires_action || (idle_proc_count > 0);
		if (should_idle_exit) {
			*should_idle_exit = true;
		}
	}
	if (available_page_count < memorystatus_get_critical_page_shortage_threshold()) {
		if (should_jetsam) {
			*should_jetsam = true;
		}
		requires_action = true;
	}
#endif /* CONFIG_JETSAM */
	return requires_action;
}

#if CONFIG_JETSAM
static uint64_t
memorystatus_swap_trigger_pages(void)
{
	/*
	 * The swapout trigger varies based on the current memorystatus_level.
	 * When available memory is somewhat high (at memorystatus_available_pages_pressure)
	 * we keep more swappable compressor segments in memory.
	 * However, as available memory drops to our idle and eventually critical kill
	 * thresholds we start swapping more aggressively.
	 */
	static uint32_t available_pages_factor[] = {0, 1, 1, 1, 2, 2, 3, 5, 7, 8, 10, 13, 15, 17, 20};
	size_t index = MIN(memorystatus_level, sizeof(available_pages_factor) / sizeof(uint32_t) - 1);
	return available_pages_factor[index] * memorystatus_available_pages / 10;
}

static int
sysctl_memorystatus_swap_trigger_pages SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t trigger_pages = memorystatus_swap_trigger_pages();
	return SYSCTL_OUT(req, &trigger_pages, sizeof(trigger_pages));
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_swap_trigger_pages, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, &sysctl_memorystatus_swap_trigger_pages, "I", "");

/*
 * Check if the number of full swappable csegments is over the trigger
 * threshold to start swapping.
 * The adjustment_factor is applied to the trigger to raise or lower
 * it. For example an adjustement factor of 110 will raise the threshold by 10%.
 */
bool
memorystatus_swap_over_trigger(uint64_t adjustment_factor)
{
	if (!memorystatus_swap_all_apps) {
		return false;
	}
	uint64_t trigger_pages = memorystatus_swap_trigger_pages();
	trigger_pages = trigger_pages * adjustment_factor / 100;
	return atop_64(c_late_swapout_count * c_seg_allocsize) > trigger_pages;
}

/*
 * Check if the number of segments on the early swapin queue
 * is over the trigger to start compacting it.
 */
bool
memorystatus_swapin_over_trigger(void)
{
	return atop_64(c_late_swappedin_count * c_seg_allocsize) > memorystatus_swapin_trigger_pages;
}
#endif /* CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG
SYSCTL_UINT(_vm, OID_AUTO, c_late_swapout_count, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, &c_late_swapout_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, c_seg_allocsize, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, &c_seg_allocsize, 0, "");
#if CONFIG_FREEZE
extern int32_t c_segment_pages_compressed_incore_late_swapout;
SYSCTL_INT(_vm, OID_AUTO, c_segment_pages_compressed_incore_late_swapout, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, &c_segment_pages_compressed_incore_late_swapout, 0, "");
#endif /* CONFIG_FREEZE */
#endif /* DEVELOPMENT || DEBUG */

static boolean_t
memorystatus_should_post_snapshot(int32_t priority, uint32_t cause)
{
	boolean_t is_idle_priority;

	is_idle_priority = (priority == JETSAM_PRIORITY_IDLE || priority == JETSAM_PRIORITY_IDLE_DEFERRED);
#if CONFIG_JETSAM
#pragma unused(cause)
	/*
	 * Don't generate logs for steady-state idle-exit kills,
	 * unless it is overridden for debug or by the device
	 * tree.
	 */

	return !is_idle_priority || memorystatus_idle_snapshot;

#else /* CONFIG_JETSAM */
	/*
	 * Don't generate logs for steady-state idle-exit kills,
	 * unless
	 * - it is overridden for debug or by the device
	 * tree.
	 * OR
	 * - the kill causes are important i.e. not kMemorystatusKilledIdleExit
	 */

	boolean_t snapshot_eligible_kill_cause = (is_reason_thrashing(cause) || is_reason_zone_map_exhaustion(cause));
	return !is_idle_priority || memorystatus_idle_snapshot || snapshot_eligible_kill_cause;
#endif /* CONFIG_JETSAM */
}


static boolean_t
memorystatus_act_on_hiwat_processes(uint32_t *errors, uint32_t *hwm_kill, bool *post_snapshot, uint64_t *memory_reclaimed)
{
	boolean_t purged = FALSE, killed = FALSE;

	*memory_reclaimed = 0;
	killed = memorystatus_kill_hiwat_proc(errors, &purged, memory_reclaimed);

	if (killed) {
		*hwm_kill = *hwm_kill + 1;
		*post_snapshot = TRUE;
		return TRUE;
	} else {
		if (purged == FALSE) {
			/* couldn't purge and couldn't kill */
			os_atomic_store(&memorystatus_hwm_candidates, false, relaxed);
		}
	}

	return killed;
}

/*
 * Purge kernel memory caches
 */
static void
memstat_purge_caches(jetsam_state_t state)
{
	memorystatus_log("memorystatus: purging kernel memory caches\n");

	uint64_t pmap_released = pmap_release_pages_fast();
	memorystatus_log("memorystatus: recovered %llu pages from pmap\n",
	    pmap_released);

	/*
	 * Only purge corpses once per jetsam event. No new corpses can be created
	 * after the initial purge (block_corpses)
	 */
	if (!state->corpse_list_purged) {
		memorystatus_log("memorystatus: purging all corpses\n");
		os_atomic_inc(&block_corpses, relaxed);
		assert(block_corpses > 0);
		if (total_corpses_count() > 0) {
			task_purge_all_corpses();
		} else {
			memorystatus_log("memorystatus: no corpses to purge\n");
		}
		state->corpse_list_purged = true;
	}

#if CONFIG_DEFERRED_RECLAIM
	/* TODO: estimate memory recovered from deferred reclaim */
	memorystatus_log("memorystatus: reclaiming all deferred user memory\n");
	vm_deferred_reclamation_gc(RECLAIM_GC_DRAIN, RECLAIM_NO_FAULT | RECLAIM_NO_WAIT);
#endif /* CONFIG_DEFERRED_RECLAIM */

	/* TODO: estimate wired memory recovered from zone_gc */
	memorystatus_log("memorystatus: trimming kernel zone allocator\n");
	zone_gc_trim();
}

/*
 * Called before jetsamming in the foreground band in the hope that we'll
 * avoid a jetsam.
 */
static void
memstat_approaching_fg_band(jetsam_state_t state)
{
	memorystatus_log("memorystatus: jetsam is approaching JETSAM_PRIORITY_FOREGROUND\n");
	if (memorystatus_should_issue_fg_band_notify) {
		memorystatus_broadcast_jetsam_pressure(kVMPressureForegroundJetsam);
	}
	memstat_purge_caches(state);
}

unsigned int jld_eval_aggressive_count = 0;
uint64_t  jld_timestamp_msecs = 0;
int       jld_idle_kill_candidates = 0;

/*
 * Progressively raise the maximum priority to aggressively kill to
 * when a jetsam loop is detected. Background work often happens at
 * @c JETSAM_PRIORITY_MAIL. Start there and elevate as needed if
 * the jetsam loop re-occurs in a short time window.
 */
int jld_max_priority_arr[] = {
	JETSAM_PRIORITY_MAIL,
	JETSAM_PRIORITY_MAIL,
	JETSAM_PRIORITY_UI_SUPPORT,
	JETSAM_PRIORITY_UI_SUPPORT,
	JETSAM_PRIORITY_DRIVER_APPLE,
};
#define JLD_MAX_PRIORITY_ARR_COUNT (sizeof(jld_max_priority_arr) / sizeof(jld_max_priority_arr[0]))

static bool
memorystatus_act_aggressive(jetsam_state_t state, uint32_t cause, os_reason_t jetsam_reason)
{
	boolean_t killed;
	uint32_t errors = 0;
	uint64_t footprint_of_killed_proc = 0;
	int elevated_bucket_count = 0, maximum_kills = 0, band = 0;
	state->memory_reclaimed = 0;

	unsigned int iteration_no = jld_eval_aggressive_count++;
	int max_kill_pri = jld_max_priority_arr[MIN(iteration_no, JLD_MAX_PRIORITY_ARR_COUNT - 1)];
	assert3u(max_kill_pri, <=, MEMSTAT_BUCKET_COUNT);

	if (max_kill_pri >= JETSAM_PRIORITY_FOREGROUND) {
		memstat_approaching_fg_band(state);
	}

	proc_list_lock();
	elevated_bucket_count = memstat_bucket[JETSAM_PRIORITY_ELEVATED_INACTIVE].count;
	proc_list_unlock();

	/* Visit elevated processes first */
	while (elevated_bucket_count) {
		elevated_bucket_count--;

		/*
		 * memorystatus_kill_elevated_process() drops a reference,
		 * so take another one so we can continue to use this exit reason
		 * even after it returns.
		 */

		os_reason_ref(jetsam_reason);
		killed = memorystatus_kill_elevated_process(
			cause,
			jetsam_reason,
			JETSAM_PRIORITY_ELEVATED_INACTIVE,
			jld_eval_aggressive_count,
			&errors, &footprint_of_killed_proc);
		if (killed) {
			state->post_snapshot = true;
			state->memory_reclaimed += footprint_of_killed_proc;
			if (!memstat_evaluate_page_shortage(NULL, NULL, NULL, NULL)) {
				/*
				 * System is no longer under pressure --
				 * bail early because the pressure was
				 * coming from an inactive process
				 */
				return true;
			}
		} else {
			/*
			 * No pinned processes left to kill.
			 * Abandon elevated band.
			 */
			break;
		}
	}

	proc_list_lock();
	for (band = JETSAM_PRIORITY_IDLE; band < max_kill_pri; band++) {
		maximum_kills += memstat_bucket[band].count;
	}
	proc_list_unlock();
	maximum_kills *= memorystatus_jld_max_kill_loops;
	/*
	 * memorystatus_kill_processes_aggressive() allocates its own
	 * jetsam_reason so the kMemorystatusKilledProcThrashing cause
	 * is consistent throughout the aggressive march.
	 */
	killed = memorystatus_kill_processes_aggressive(
		kMemorystatusKilledProcThrashing,
		jld_eval_aggressive_count,
		max_kill_pri,
		maximum_kills,
		&errors, &footprint_of_killed_proc);

	if (killed) {
		/* Always generate logs after aggressive kill */
		state->post_snapshot = true;
		state->memory_reclaimed += footprint_of_killed_proc;
		state->jld_idle_kills = 0;
	}

	return killed;
}

/*
 * Sets up a new jetsam thread.
 */
static void
memorystatus_thread_init(jetsam_state_t jetsam_thread)
{
	char name[32];
	thread_wire_internal(host_priv_self(), current_thread(), TRUE, NULL);
	snprintf(name, 32, "VM_memorystatus_%d", jetsam_thread->index + 1);

	/* Limit all but one thread to the lower jetsam bands, as that's where most of the victims are. */
	if (jetsam_thread->index == 0) {
		if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
			thread_vm_bind_group_add();
		}
		jetsam_thread->limit_to_low_bands = false;
	} else {
		jetsam_thread->limit_to_low_bands = true;
	}
#if CONFIG_THREAD_GROUPS
	thread_group_vm_add();
#endif
	thread_set_thread_name(current_thread(), name);
	sched_cond_init(&(jetsam_thread->jt_wakeup_cond));
	jetsam_thread->inited = true;
}

/*
 * Create a new jetsam reason from the given kill cause.
 */
static os_reason_t
create_jetsam_reason(memorystatus_kill_cause_t cause)
{
	os_reason_t jetsam_reason = OS_REASON_NULL;

	jetsam_reason_t reason_code = (jetsam_reason_t)cause;
	assert3u(reason_code, <=, JETSAM_REASON_MEMORYSTATUS_MAX);

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, reason_code);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus: failed to allocate jetsam reason for cause %u\n", cause);
	}
	return jetsam_reason;
}

/*
 * Do one kill as we're marching up the priority bands.
 * This is a wrapper around memorystatus_kill_top_process that also
 * sets post_snapshot, tracks jld_idle_kills, and notifies if we're appraoching the fg band.
 */
static bool
memorystatus_do_priority_kill(jetsam_state_t state,
    uint32_t kill_cause, int32_t max_priority, bool only_swappable, bool only_long_idle)
{
	os_reason_t jetsam_reason = OS_REASON_NULL;
	bool killed = false;
	int priority;

	jetsam_reason = create_jetsam_reason(kill_cause);
	/*
	 * memorystatus_kill_top_process() drops a reference,
	 * so take another one so we can continue to use this exit reason
	 * even after it returns
	 */
	os_reason_ref(jetsam_reason);

	/* LRU */
	killed = memorystatus_kill_top_process(true, state->sort_flag, kill_cause, jetsam_reason, max_priority,
	    only_swappable, only_long_idle, &priority, &state->errors, &state->memory_reclaimed);
	state->sort_flag = false;

	if (killed) {
		if (memorystatus_should_post_snapshot(priority, kill_cause) == TRUE) {
			state->post_snapshot = true;
		}

		/* Jetsam Loop Detection */
		if (memorystatus_jld_enabled == TRUE) {
			if (priority <= applications_aging_band) {
				state->jld_idle_kills++;
			} else {
				/*
				 * We've reached into bands beyond idle deferred.
				 * We make no attempt to monitor them
				 */
			}
		}

		if (priority >= JETSAM_PRIORITY_FREEZER) {
			memstat_approaching_fg_band(state);
		} else if (priority >= JETSAM_PRIORITY_BACKGROUND) {
			memorystatus_broadcast_jetsam_pressure(kVMPressureBackgroundJetsam);
		}
	}
	os_reason_free(jetsam_reason);

	return killed;
}

static bool
memorystatus_do_action(jetsam_state_t state, memorystatus_action_t action, uint32_t kill_cause)
{
	bool killed = false;
	os_reason_t jetsam_reason = OS_REASON_NULL;

	switch (action) {
	case MEMORYSTATUS_KILL_HIWATER:
		killed = memorystatus_act_on_hiwat_processes(&state->errors, &state->hwm_kills,
		    &state->post_snapshot, &state->memory_reclaimed);
		break;
	case MEMORYSTATUS_KILL_AGGRESSIVE:
		jetsam_reason = create_jetsam_reason(kill_cause);
		killed = memorystatus_act_aggressive(state, kill_cause, jetsam_reason);
		os_reason_free(jetsam_reason);
		break;
	case MEMORYSTATUS_KILL_TOP_PROCESS:
		killed = memorystatus_do_priority_kill(state, kill_cause, JETSAM_PRIORITY_MAX, false, false);
		break;
	case MEMORYSTATUS_WAKE_SWAPPER:
		memorystatus_log_info(
			"memorystatus_do_action: Waking up swap thread. memorystatus_available_pages: %llu\n",
			(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);
		os_atomic_store(&vm_swapout_wake_pending, true, relaxed);
		thread_wakeup((event_t)&vm_swapout_thread);
		break;
	case MEMORYSTATUS_PROCESS_SWAPIN_QUEUE:
		memorystatus_log_info(
			"memorystatus_do_action: Processing swapin queue of length: %u memorystatus_available_pages: %llu\n",
			c_late_swappedin_count, (uint64_t) MEMORYSTATUS_LOG_AVAILABLE_PAGES);
		vm_compressor_process_special_swapped_in_segments();
		break;
	case MEMORYSTATUS_KILL_SUSPENDED_SWAPPABLE:
		killed = memorystatus_do_priority_kill(state, kill_cause, JETSAM_PRIORITY_BACKGROUND - 1, true, false);
		break;
	case MEMORYSTATUS_KILL_SWAPPABLE:
		killed = memorystatus_do_priority_kill(state, kill_cause, JETSAM_PRIORITY_MAX, true, false);
		break;
	case MEMORYSTATUS_KILL_IDLE:
		killed = memorystatus_do_priority_kill(state, kill_cause, JETSAM_PRIORITY_IDLE, false, false);
		break;
	case MEMORYSTATUS_KILL_LONG_IDLE:
		killed = memorystatus_do_priority_kill(state, kill_cause, JETSAM_PRIORITY_IDLE, false, true);
		break;
	case MEMORYSTATUS_KILL_NONE:
		panic("memorystatus_do_action: Impossible! memorystatus_do_action called with action = NONE\n");
	}
	return killed;
}

void
memorystatus_post_snapshot()
{
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
			memorystatus_jetsam_snapshot_last_timestamp = timestamp_now; proc_list_unlock();
		}
	} else {
		proc_list_unlock();
	}
}

#if JETSAM_ZPRINT_SNAPSHOT

/*
 *  Called by memorystatus_update_jetsam_snapshot_entry_locked to take a zprint snapshot.
 */
static void
memorystatus_collect_jetsam_snapshot_zprint(void)
{
	unsigned int new_meminfo_cnt;

	jzs_zone_cnt = zone_max_zones();

	new_meminfo_cnt = vm_page_diagnose_estimate();
	if (new_meminfo_cnt > jzs_meminfo_cnt) {
		jzs_meminfo = krealloc_data_tag(jzs_meminfo,
		    jzs_meminfo_cnt * sizeof(mach_memory_info_t),
		    new_meminfo_cnt * sizeof(mach_memory_info_t),
		    Z_WAITOK,
		    VM_KERN_MEMORY_DIAG);

		jzs_meminfo_cnt = new_meminfo_cnt;
	}

	mach_memory_info_sample(jzs_names, jzs_info, jzs_coalesce, &jzs_zone_cnt, jzs_meminfo, jzs_meminfo_cnt, true);
}

#endif /* JETSAM_ZPRINT_SNAPSHOT */

/*
 * Main entrypoint for the memorystatus thread.
 * This thread is woken up when we're low on one of the following resources:
 * - available pages (free + filebacked)
 * - zone memory
 * - compressor space
 *
 * Or when thrashing is detected in the compressor or file cache.
 */
static void
memorystatus_thread_internal(jetsam_state_t state)
{
	uint64_t total_memory_reclaimed = 0;
	bool highwater_remaining = true;
	bool swappable_apps_remaining = false;
	bool suspended_swappable_apps_remaining = false;

#if CONFIG_JETSAM
	swappable_apps_remaining = memorystatus_swap_all_apps;
	suspended_swappable_apps_remaining = memorystatus_swap_all_apps;
#endif /* CONFIG_JETSAM */

	assert(state != NULL);
	state->jld_idle_kills = 0;
	state->errors = 0;
	state->hwm_kills = 0;
	state->sort_flag = true;
	state->corpse_list_purged = false;
	state->post_snapshot = false;
	state->memory_reclaimed = 0;

	if (state->inited == FALSE) {
		/*
		 * It's the first time the thread has run, so just mark the thread as privileged and block.
		 */
		memorystatus_thread_init(state);
		sched_cond_wait(&state->jt_wakeup_cond, THREAD_UNINT, memorystatus_thread);
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_SCAN) | DBG_FUNC_START,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, memorystatus_jld_enabled, memorystatus_jld_eval_period_msecs, jld_eval_aggressive_count);

	extern uint32_t c_segment_count;
	extern mach_timespec_t major_compact_ts;
	clock_sec_t now;
	clock_nsec_t nsec;
	clock_get_system_nanotime(&now, &nsec);
	mach_timespec_t major_compact_diff = {.tv_sec = (int)now, .tv_nsec = nsec};
	SUB_MACH_TIMESPEC(&major_compact_diff, &major_compact_ts);
	memorystatus_log_info(
		"memorystatus: c_segment_count=%u major compaction occurred %u seconds ago\n",
		c_segment_count, major_compact_diff.tv_sec);

	/*
	 * Jetsam aware version.
	 *
	 * The VM pressure notification thread is working its way through clients in parallel.
	 *
	 * So, while the pressure notification thread is targeting processes in order of
	 * increasing jetsam priority, we can hopefully reduce / stop its work by killing
	 * any processes that have exceeded their highwater mark.
	 *
	 * If we run out of HWM processes and our available pages drops below the critical threshold, then,
	 * we target the least recently used process in order of increasing jetsam priority (exception: the FG band).
	 */
	while (true) {
		bool killed;
		state->memory_reclaimed = 0;
		uint32_t cause = 0;

		memorystatus_action_t action = memorystatus_pick_action(state, &cause,
		    highwater_remaining, suspended_swappable_apps_remaining, swappable_apps_remaining,
		    &state->jld_idle_kills);
		if (action == MEMORYSTATUS_KILL_NONE) {
			break;
		}

		if (cause == kMemorystatusKilledVMCompressorThrashing || cause == kMemorystatusKilledVMCompressorSpaceShortage) {
			memorystatus_log("memorystatus: killing due to \"%s\" - compression_ratio=%u\n", memorystatus_kill_cause_name[cause], vm_compression_ratio());
		}

		killed = memorystatus_do_action(state, action, cause);
		total_memory_reclaimed += state->memory_reclaimed;

		if (!killed) {
			if (action == MEMORYSTATUS_KILL_HIWATER) {
				highwater_remaining = false;
			} else if (action == MEMORYSTATUS_KILL_SWAPPABLE) {
				swappable_apps_remaining = false;
				suspended_swappable_apps_remaining = false;
			} else if (action == MEMORYSTATUS_KILL_SUSPENDED_SWAPPABLE) {
				suspended_swappable_apps_remaining = false;
			}
		} else {
			if (cause == kMemorystatusKilledVMCompressorThrashing || cause == kMemorystatusKilledVMCompressorSpaceShortage) {
				memorystatus_log("memorystatus: post-jetsam compressor fragmentation_level=%u\n", vm_compressor_fragmentation_level());
			}
			/* Always re-check for highwater and swappable kills after doing a kill. */
			highwater_remaining = true;
			swappable_apps_remaining = true;
			suspended_swappable_apps_remaining = true;
		}

		if (!killed && total_memory_reclaimed == 0) {
			memorystatus_log("memorystatus: failed to kill a process and no memory was reclaimed\n");
			if ((action == MEMORYSTATUS_KILL_TOP_PROCESS || action == MEMORYSTATUS_KILL_AGGRESSIVE) &&
			    memorystatus_get_available_page_count() < memorystatus_get_critical_page_shortage_threshold()) {
				/*
				 * Still under pressure and unable to kill a process - purge corpse memory
				 * and get everything back from the pmap.
				 */
				memorystatus_log("memorystatus: ran out of %sprocesses to kill but "
				    "system is still in critical condition\n",
				    state->limit_to_low_bands ? "low-band " : "");
				memstat_purge_caches(state);

				if (!state->limit_to_low_bands &&
				    memorystatus_get_available_page_count() < memorystatus_get_critical_page_shortage_threshold()) {
					/*
					 * Still under pressure and unable to kill a process
					 */
					memorystatus_log_fault("memorystatus: attempting full drain of kernel zone allocator\n");
					zone_gc_drain();
					if (memorystatus_get_available_page_count() < memorystatus_get_critical_page_shortage_threshold()) {
						panic("memorystatus_jetsam_thread: no victim! available pages:%llu", (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);
					}
				}
			}
		}

		/*
		 * If we did a kill on behalf of another subsystem (compressor or zalloc)
		 * notify them.
		 */
		if (killed && is_reason_thrashing(cause)) {
			os_atomic_store(&memorystatus_compressor_space_shortage, false, release);
#if CONFIG_PHANTOM_CACHE
			os_atomic_store(&memorystatus_phantom_cache_pressure, false, release);
#endif /* CONFIG_PHANTOM_CACHE */
#if CONFIG_JETSAM
			vm_thrashing_jetsam_done();
#endif /* CONFIG_JETSAM */
		} else if (killed && is_reason_zone_map_exhaustion(cause)) {
			os_atomic_store(&memorystatus_zone_map_is_exhausted, false, release);
		} else if (killed && cause == kMemorystatusKilledVMPageoutStarvation) {
			os_atomic_store(&memorystatus_pageout_starved, false, release);
		}
	}

	if (state->errors) {
		memorystatus_clear_errors();
	}

	if (state->post_snapshot) {
		memorystatus_post_snapshot();
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_SCAN) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, total_memory_reclaimed);

	if (state->corpse_list_purged) {
		os_atomic_dec(&block_corpses, relaxed);
		assert(block_corpses >= 0);
	}
}

OS_NORETURN
static void
memorystatus_thread(void *param __unused, wait_result_t wr __unused)
{
	jetsam_state_t jetsam_thread = jetsam_current_thread();
	sched_cond_ack(&(jetsam_thread->jt_wakeup_cond));
	while (1) {
		memorystatus_thread_internal(jetsam_thread);
		sched_cond_wait(&(jetsam_thread->jt_wakeup_cond), THREAD_UNINT, memorystatus_thread);
	}
}

/*
 * Callback invoked when allowable physical memory footprint exceeded
 * (dirty pages + IOKit mappings)
 *
 * This is invoked for both advisory, non-fatal per-task high watermarks,
 * as well as the fatal task memory limits.
 */
void
memorystatus_on_ledger_footprint_exceeded(boolean_t warning, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal)
{
	os_reason_t jetsam_reason = OS_REASON_NULL;

	proc_t p = current_proc();

#if VM_PRESSURE_EVENTS
	if (warning == TRUE) {
		/*
		 * This is a warning path which implies that the current process is close, but has
		 * not yet exceeded its per-process memory limit.
		 */
		if (memorystatus_warn_process(p, memlimit_is_active, memlimit_is_fatal, FALSE /* not exceeded */) != TRUE) {
			/* Print warning, since it's possible that task has not registered for pressure notifications */
			memorystatus_log_debug(
				"memorystatus_on_ledger_footprint_exceeded: failed to warn %s [%d] (exiting, or no handler registered?).\n",
				proc_best_name(p), proc_getpid(p));
		}
		return;
	}
#endif /* VM_PRESSURE_EVENTS */

	if (memlimit_is_fatal) {
		/*
		 * If this process has no high watermark or has a fatal task limit, then we have been invoked because the task
		 * has violated either the system-wide per-task memory limit OR its own task limit.
		 */
		jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_PERPROCESSLIMIT);
		if (jetsam_reason == NULL) {
			memorystatus_log_error("task_exceeded footprint: failed to allocate jetsam reason\n");
		} else if (corpse_for_fatal_memkill && proc_send_synchronous_EXC_RESOURCE(p) == FALSE) {
			/* Set OS_REASON_FLAG_GENERATE_CRASH_REPORT to generate corpse */
			jetsam_reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
		}

		if (memorystatus_kill_process_sync(proc_getpid(p), kMemorystatusKilledPerProcessLimit, jetsam_reason) != TRUE) {
			memorystatus_log_error("task_exceeded_footprint: failed to kill the current task (exiting?).\n");
		}
	} else {
		/*
		 * HWM offender exists. Done without locks or synchronization.
		 * See comment near its declaration for more details.
		 */
		os_atomic_store(&memorystatus_hwm_candidates, true, release);
		_memstat_consider_waking_jetsam_thread();

#if VM_PRESSURE_EVENTS
		/*
		 * The current process is not in the warning path.
		 * This path implies the current process has exceeded a non-fatal (soft) memory limit.
		 * Failure to send note is ignored here.
		 */
		(void)memorystatus_warn_process(p, memlimit_is_active, memlimit_is_fatal, TRUE /* exceeded */);

#endif /* VM_PRESSURE_EVENTS */
	}
}

void
memorystatus_log_exception(const int max_footprint_mb, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal)
{
	proc_t p = current_proc();

	/*
	 * The limit violation is logged here, but only once per process per limit.
	 * Soft memory limit is a non-fatal high-water-mark
	 * Hard memory limit is a fatal custom-task-limit or system-wide per-task memory limit.
	 */

	memorystatus_log("memorystatus: %s [%d] exceeded mem limit: %s%s %d MB (%s)\n",
	    ((p && *p->p_name) ? p->p_name : "unknown"), (p ? proc_getpid(p) : -1), (memlimit_is_active ? "Active" : "Inactive"),
	    (memlimit_is_fatal  ? "Hard" : "Soft"), max_footprint_mb,
	    (memlimit_is_fatal  ? "fatal" : "non-fatal"));
}

void
memorystatus_log_diag_threshold_exception(const int diag_threshold_value)
{
	proc_t p = current_proc();

	/*
	 * The limit violation is logged here, but only once per process per limit.
	 * Soft memory limit is a non-fatal high-water-mark
	 * Hard memory limit is a fatal custom-task-limit or system-wide per-task memory limit.
	 */

	memorystatus_log("memorystatus: %s [%d] exceeded diag threshold limit: %d MB \n",
	    ((p && *p->p_name) ? p->p_name : "unknown"), (p ? proc_getpid(p) : -1), diag_threshold_value);
}

/*
 * Description:
 *	Evaluates process state to determine which limit
 *	should be applied (active vs. inactive limit).
 *
 *	Return: TRUE if active
 *		False if inactive
 */
static bool
memstat_proc_is_active_locked(proc_t p)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	if (_memstat_proc_is_elevated(p) &&
	    (p->p_memstat_effectivepriority == JETSAM_PRIORITY_ELEVATED_INACTIVE ||
	    p->p_memstat_effectivepriority == JETSAM_PRIORITY_FREEZER)) {
		/* This process is sitting in an elevated inactive band. */
		if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_ELEVATED_INACTIVE) {
			/*
			 * This process is in an elevated band and may be doing background
			 * work.
			 */
			return true;
		} else {
			/* This process is frozen. */
			return false;
		}
	} else if (_memstat_proc_is_tracked(p)) {
		/*
		 * Process has enrolled in ActivityTracking. Its limit will be
		 * determined based on whether it is clean or dirty.
		 */
		if (_memstat_proc_is_dirty(p)) {
			/* Dirty processes are always active */
			return true;
		} else if (_memstat_proc_can_idle_exit(p) &&
		    p->p_memstat_effectivepriority > JETSAM_PRIORITY_IDLE) {
			/*
			 * This process is clean and supports idle exit, but has not made
			 * its way to the idle band. It is either aging in the deferred
			 * idle band or has a RunningBoard assertion that is keeping it
			 * from going idle.
			 */
			return true;
		} else {
			/*
			 * This process is clean and either:
			 *   - does not support idle exit
			 *   or
			 *   - does support idle exit and is now idle
			 */
			return false;
		}
	} else if (_memstat_proc_is_managed(p)) {
		/*
		 * RunningBoard-managed processes are active if they have any
		 * outstanding assertions
		 */
		return _memstat_proc_has_priority_assertion(p);
	} else {
		/*
		 * Unmanaged and untracked processes receive an active limit unless
		 * they are completely idle.
		 */
		return p->p_memstat_effectivepriority > JETSAM_PRIORITY_IDLE;
	}
}

static bool
memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason)
{
	bool killed;

	uint32_t errors = 0;
	uint64_t memory_reclaimed = 0;

	/* Validate inputs */
	if (victim_pid == 0) {
		return false;
	}

	if (victim_pid == -1) {
		uint32_t max_priority;
#if CONFIG_JETSAM
		max_priority = JETSAM_PRIORITY_MAX;
#else /* !CONFIG_JETSAM */
		if (kill_on_no_paging_space ||
		    cause == kMemorystatusKilledZoneMapExhaustion) {
			max_priority = JETSAM_PRIORITY_MAX;
		} else {
			max_priority = JETSAM_PRIORITY_IDLE;
		}
#endif /* CONFIG_JETSAM */
		/* No pid, so kill first process */
		killed = memorystatus_kill_top_process(true, true, cause, jetsam_reason,
		    max_priority, false, false, NULL, &errors, &memory_reclaimed);
	} else {
		killed = memorystatus_kill_specific_process(victim_pid, cause, jetsam_reason);
	}

	if (errors) {
		memorystatus_clear_errors();
	}

	if (killed) {
		/* Fire off snapshot notification */
		proc_list_lock();
		size_t snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) +
		    sizeof(memorystatus_jetsam_snapshot_entry_t) * memorystatus_jetsam_snapshot_count;
		uint64_t timestamp_now = mach_absolute_time();
		memorystatus_jetsam_snapshot->notification_time = timestamp_now;
		if (memorystatus_jetsam_snapshot_count > 0 && (memorystatus_jetsam_snapshot_last_timestamp == 0 ||
		    timestamp_now > memorystatus_jetsam_snapshot_last_timestamp + memorystatus_jetsam_snapshot_timeout)) {
			proc_list_unlock();
			int ret = memorystatus_send_note(kMemorystatusSnapshotNote, &snapshot_size, sizeof(snapshot_size));
			if (!ret) {
				proc_list_lock();
				memorystatus_jetsam_snapshot_last_timestamp = timestamp_now;
				proc_list_unlock();
			}
		} else {
			proc_list_unlock();
		}
	}

	return killed;
}

/*
 * Jetsam a specific process.
 */
static bool
memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason)
{
	bool killed;
	proc_t p;
	uint64_t killtime = 0;
	uint64_t time_in_priority_band_secs = 0;
	uint64_t footprint_of_killed_proc;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;

	/* TODO - add a victim queue and push this into the main jetsam thread */

	p = proc_find(victim_pid);
	if (!p) {
		os_reason_free(jetsam_reason);
		return false;
	}

	proc_list_lock();

	if (p->p_memstat_state & P_MEMSTAT_TERMINATED) {
		/*
		 * Someone beat us to this kill.
		 * Nothing to do here.
		 */
		proc_list_unlock();
		os_reason_free(jetsam_reason);
		proc_rele(p);
		return false;
	}
	p->p_memstat_state |= P_MEMSTAT_TERMINATED;

	if (memorystatus_jetsam_snapshot_count == 0) {
		memorystatus_init_jetsam_snapshot_locked(NULL, 0);
	}

	killtime = mach_absolute_time();
	absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
	tv_msec = tv_usec / 1000;

	memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

	proc_list_unlock();

	absolutetime_to_nanoseconds(killtime - p->p_memstat_prio_start, &time_in_priority_band_secs);
	time_in_priority_band_secs /= NSEC_PER_SEC;

	killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

	memorystatus_log("%lu.%03d memorystatus: killing_specific_process pid %d [%s] (%s %d %llus rf:%s) %lluKB - memorystatus_available_pages: %llu\n",
	    (unsigned long)tv_sec, tv_msec, victim_pid, ((p && *p->p_name) ? p->p_name : "unknown"),
	    memorystatus_kill_cause_name[cause], (p ? p->p_memstat_effectivepriority: -1), time_in_priority_band_secs, (p ? _memstat_relaunch_flags_description(p->p_memstat_relaunch_flags) : 0),
	    footprint_of_killed_proc >> 10, (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);

	if (!killed) {
		proc_list_lock();
		p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
		proc_list_unlock();
	}

	proc_rele(p);

	return killed;
}


/*
 * Toggle the P_MEMSTAT_SKIP bit.
 * Takes the proc_list_lock.
 */
void
proc_memstat_skip(proc_t p, boolean_t set)
{
#if DEVELOPMENT || DEBUG
	if (p) {
		proc_list_lock();
		if (set == TRUE) {
			p->p_memstat_state |= P_MEMSTAT_SKIP;
		} else {
			p->p_memstat_state &= ~P_MEMSTAT_SKIP;
		}
		proc_list_unlock();
	}
#else
#pragma unused(p, set)
	/*
	 * do nothing
	 */
#endif /* DEVELOPMENT || DEBUG */
	return;
}


#if CONFIG_JETSAM
/*
 * This is invoked when cpulimits have been exceeded while in fatal mode.
 * The jetsam_flags do not apply as those are for memory related kills.
 * We call this routine so that the offending process is killed with
 * a non-zero exit status.
 */
void
jetsam_on_ledger_cpulimit_exceeded(void)
{
	int retval = 0;
	int jetsam_flags = 0;  /* make it obvious */
	proc_t p = current_proc();
	os_reason_t jetsam_reason = OS_REASON_NULL;

	memorystatus_log("memorystatus: killing %s [%d] due to cpulimit "
	    "violation\n", proc_best_name(p), proc_getpid(p));

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_CPULIMIT);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus: unable to allocate memory for jetsam reason\n");
	}

	retval = jetsam_do_kill(p, jetsam_flags, jetsam_reason);

	if (retval) {
		memorystatus_log_error("memorystatus: failed to kill current task (exiting?).\n");
	}
}

#endif /* CONFIG_JETSAM */

static void
memorystatus_get_task_memory_region_count(task_t task, uint64_t *count)
{
	assert(task);
	assert(count);

	*count = get_task_memory_region_count(task);
}


#define MEMORYSTATUS_VM_MAP_FORK_ALLOWED     0x100000000
#define MEMORYSTATUS_VM_MAP_FORK_NOT_ALLOWED 0x200000000

#if DEVELOPMENT || DEBUG

/*
 * Sysctl only used to test memorystatus_allowed_vm_map_fork() path.
 *   set a new pidwatch value
 *	or
 *   get the current pidwatch value
 *
 * The pidwatch_val starts out with a PID to watch for in the map_fork path.
 * Its value is:
 * - OR'd with MEMORYSTATUS_VM_MAP_FORK_ALLOWED if we allow the map_fork.
 * - OR'd with MEMORYSTATUS_VM_MAP_FORK_NOT_ALLOWED if we disallow the map_fork.
 * - set to -1ull if the map_fork() is aborted for other reasons.
 */

uint64_t memorystatus_vm_map_fork_pidwatch_val = 0;

static int sysctl_memorystatus_vm_map_fork_pidwatch SYSCTL_HANDLER_ARGS {
#pragma unused(oidp, arg1, arg2)

	uint64_t new_value = 0;
	uint64_t old_value = 0;
	int error = 0;

	/*
	 * The pid is held in the low 32 bits.
	 * The 'allowed' flags are in the upper 32 bits.
	 */
	old_value = memorystatus_vm_map_fork_pidwatch_val;

	error = sysctl_io_number(req, old_value, sizeof(old_value), &new_value, NULL);

	if (error || !req->newptr) {
		/*
		 * No new value passed in.
		 */
		return error;
	}

	/*
	 * A new pid was passed in via req->newptr.
	 * Ignore any attempt to set the higher order bits.
	 */
	memorystatus_vm_map_fork_pidwatch_val = new_value & 0xFFFFFFFF;
	memorystatus_log_debug("memorystatus: pidwatch old_value = 0x%llx, new_value = 0x%llx\n", old_value, new_value);

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_vm_map_fork_pidwatch, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, sysctl_memorystatus_vm_map_fork_pidwatch, "Q", "get/set pid watched for in vm_map_fork");


/*
 * Record if a watched process fails to qualify for a vm_map_fork().
 */
void
memorystatus_abort_vm_map_fork(task_t task)
{
	if (memorystatus_vm_map_fork_pidwatch_val != 0) {
		proc_t p = get_bsdtask_info(task);
		if (p != NULL && memorystatus_vm_map_fork_pidwatch_val == (uint64_t)proc_getpid(p)) {
			memorystatus_vm_map_fork_pidwatch_val = -1ull;
		}
	}
}

static void
set_vm_map_fork_pidwatch(task_t task, uint64_t x)
{
	if (memorystatus_vm_map_fork_pidwatch_val != 0) {
		proc_t p = get_bsdtask_info(task);
		if (p && (memorystatus_vm_map_fork_pidwatch_val == (uint64_t)proc_getpid(p))) {
			memorystatus_vm_map_fork_pidwatch_val |= x;
		}
	}
}

#else /* DEVELOPMENT || DEBUG */


static void
set_vm_map_fork_pidwatch(task_t task, uint64_t x)
{
#pragma unused(task)
#pragma unused(x)
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Called during EXC_RESOURCE handling when a process exceeds a soft
 * memory limit.  This is the corpse fork path and here we decide if
 * vm_map_fork will be allowed when creating the corpse.
 * The task being considered is suspended.
 *
 * By default, a vm_map_fork is allowed to proceed.
 *
 * A few simple policy assumptions:
 *	If the device has a zero system-wide task limit,
 *	then the vm_map_fork is allowed. macOS always has a zero
 *	system wide task limit (unless overriden by a boot-arg).
 *
 *	And if a process's memory footprint calculates less
 *	than or equal to quarter of the system-wide task limit,
 *	then the vm_map_fork is allowed.  This calculation
 *	is based on the assumption that a process can
 *	munch memory up to the system-wide task limit.
 *
 *      For watchOS, which has a low task limit, we use a
 *      different value. Current task limit has been reduced
 *      to 300MB and it's been decided the limit should be 200MB.
 */
int large_corpse_count = 0;
boolean_t
memorystatus_allowed_vm_map_fork(task_t task, bool *is_large)
{
	boolean_t is_allowed = TRUE;   /* default */
	uint64_t footprint_in_bytes;
	uint64_t max_allowed_bytes;
	thread_t self = current_thread();

	*is_large = false;

	/* Jetsam in high bands blocks any new corpse */
	if (os_atomic_load(&block_corpses, relaxed) != 0) {
		memorystatus_log("memorystatus_allowed_vm_map_fork: corpse for pid %d blocked by jetsam).\n", task_pid(task));
		ktriage_record(thread_tid(self), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_CORPSE, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_CORPSE_BLOCKED_JETSAM), 0 /* arg */);
		return FALSE;
	}

	if (max_task_footprint_mb == 0) {
		set_vm_map_fork_pidwatch(task, MEMORYSTATUS_VM_MAP_FORK_ALLOWED);
		return is_allowed;
	}

	footprint_in_bytes = get_task_phys_footprint(task);

	/*
	 * Maximum is 1/4 of the system-wide task limit by default.
	 */
	max_allowed_bytes = ((uint64_t)max_task_footprint_mb * 1024 * 1024) >> 2;

#if XNU_TARGET_OS_WATCH
	/*
	 * For watches with > 1G, use a limit of 200MB and allow
	 * one corpse at a time of up to 300MB.
	 */
#define LARGE_CORPSE_LIMIT 1
	if (sane_size > 1 * 1024 * 1024 * 1024) {
		int cnt = large_corpse_count;
		if (footprint_in_bytes > 200 * 1024 * 1024 &&
		    footprint_in_bytes <= 300 * 1024 * 1024 &&
		    cnt < LARGE_CORPSE_LIMIT &&
		    OSCompareAndSwap(cnt, cnt + 1, &large_corpse_count)) {
			*is_large = true;
			max_allowed_bytes = MAX(max_allowed_bytes, 300 * 1024 * 1024);
		} else {
			max_allowed_bytes = MAX(max_allowed_bytes, 200 * 1024 * 1024);
		}
	}
#endif /* XNU_TARGET_OS_WATCH */

#if DEBUG || DEVELOPMENT
	if (corpse_threshold_system_limit) {
		max_allowed_bytes = (uint64_t)max_task_footprint_mb * (1UL << 20);
	}
#endif /* DEBUG || DEVELOPMENT */

	if (footprint_in_bytes > max_allowed_bytes) {
		memorystatus_log("memorystatus disallowed vm_map_fork %lld  %lld\n", footprint_in_bytes, max_allowed_bytes);
		set_vm_map_fork_pidwatch(task, MEMORYSTATUS_VM_MAP_FORK_NOT_ALLOWED);
		ktriage_record(thread_tid(self), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_CORPSE, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_CORPSE_PROC_TOO_BIG), 0 /* arg */);
		return !is_allowed;
	}

	set_vm_map_fork_pidwatch(task, MEMORYSTATUS_VM_MAP_FORK_ALLOWED);
	return is_allowed;
}

void
memorystatus_get_task_page_counts(task_t task, uint32_t *footprint, uint32_t *max_footprint_lifetime, uint32_t *purgeable_pages)
{
	assert(task);
	assert(footprint);

	uint64_t pages;

	pages = (get_task_phys_footprint(task) / PAGE_SIZE_64);
	assert(((uint32_t)pages) == pages);
	*footprint = (uint32_t)pages;

	if (max_footprint_lifetime) {
		pages = (get_task_phys_footprint_lifetime_max(task) / PAGE_SIZE_64);
		assert(((uint32_t)pages) == pages);
		*max_footprint_lifetime = (uint32_t)pages;
	}
	if (purgeable_pages) {
		pages = (get_task_purgeable_size(task) / PAGE_SIZE_64);
		assert(((uint32_t)pages) == pages);
		*purgeable_pages = (uint32_t)pages;
	}
}

static void
memorystatus_get_task_phys_footprint_page_counts(task_t task,
    uint64_t *internal_pages, uint64_t *internal_compressed_pages,
    uint64_t *purgeable_nonvolatile_pages, uint64_t *purgeable_nonvolatile_compressed_pages,
    uint64_t *alternate_accounting_pages, uint64_t *alternate_accounting_compressed_pages,
    uint64_t *iokit_mapped_pages, uint64_t *page_table_pages, uint64_t *frozen_to_swap_pages,
    uint64_t *neural_nofootprint_total_pages)
{
	assert(task);

	if (internal_pages) {
		*internal_pages = (get_task_internal(task) / PAGE_SIZE_64);
	}

	if (internal_compressed_pages) {
		*internal_compressed_pages = (get_task_internal_compressed(task) / PAGE_SIZE_64);
	}

	if (purgeable_nonvolatile_pages) {
		*purgeable_nonvolatile_pages = (get_task_purgeable_nonvolatile(task) / PAGE_SIZE_64);
	}

	if (purgeable_nonvolatile_compressed_pages) {
		*purgeable_nonvolatile_compressed_pages = (get_task_purgeable_nonvolatile_compressed(task) / PAGE_SIZE_64);
	}

	if (alternate_accounting_pages) {
		*alternate_accounting_pages = (get_task_alternate_accounting(task) / PAGE_SIZE_64);
	}

	if (alternate_accounting_compressed_pages) {
		*alternate_accounting_compressed_pages = (get_task_alternate_accounting_compressed(task) / PAGE_SIZE_64);
	}

	if (iokit_mapped_pages) {
		*iokit_mapped_pages = (get_task_iokit_mapped(task) / PAGE_SIZE_64);
	}

	if (page_table_pages) {
		*page_table_pages = (get_task_page_table(task) / PAGE_SIZE_64);
	}

	if (neural_nofootprint_total_pages) {
		*neural_nofootprint_total_pages = (get_task_neural_nofootprint_total(task) / PAGE_SIZE_64);
	}

#if CONFIG_FREEZE
	if (frozen_to_swap_pages) {
		*frozen_to_swap_pages = (get_task_frozen_to_swap(task) / PAGE_SIZE_64);
	}
#else /* CONFIG_FREEZE */
#pragma unused(frozen_to_swap_pages)
#endif /* CONFIG_FREEZE */
}

#if CONFIG_FREEZE
/*
 * Copies the source entry into the destination snapshot.
 * Returns true on success. Fails if the destination snapshot is full.
 * Caller must hold the proc list lock.
 */
static bool
memorystatus_jetsam_snapshot_copy_entry_locked(memorystatus_jetsam_snapshot_t *dst_snapshot, unsigned int dst_snapshot_size, const memorystatus_jetsam_snapshot_entry_t *src_entry)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	assert(dst_snapshot);

	if (dst_snapshot->entry_count == dst_snapshot_size) {
		/* Destination snapshot is full. Can not be updated until it is consumed. */
		return false;
	}
	if (dst_snapshot->entry_count == 0) {
		memorystatus_init_jetsam_snapshot_header(dst_snapshot);
	}
	memorystatus_jetsam_snapshot_entry_t *dst_entry = &dst_snapshot->entries[dst_snapshot->entry_count++];
	memcpy(dst_entry, src_entry, sizeof(memorystatus_jetsam_snapshot_entry_t));
	return true;
}
#endif /* CONFIG_FREEZE */

static bool
memorystatus_init_jetsam_snapshot_entry_with_kill_locked(memorystatus_jetsam_snapshot_t *snapshot, proc_t p, uint32_t kill_cause, uint64_t killtime, memorystatus_jetsam_snapshot_entry_t **entry)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	memorystatus_jetsam_snapshot_entry_t *snapshot_list = snapshot->entries;
	size_t i = snapshot->entry_count;

	if (memorystatus_init_jetsam_snapshot_entry_locked(p, &snapshot_list[i], (snapshot->js_gencount)) == TRUE) {
		*entry = &snapshot_list[i];
		(*entry)->killed       = kill_cause;
		(*entry)->jse_killtime = killtime;

		snapshot->entry_count = i + 1;
		return true;
	}
	return false;
}

/*
 * This routine only acts on the global jetsam event snapshot.
 * Updating the process's entry can race when the memorystatus_thread
 * has chosen to kill a process that is racing to exit on another core.
 */
static void
memorystatus_update_jetsam_snapshot_entry_locked(proc_t p, uint32_t kill_cause, uint64_t killtime)
{
	memorystatus_jetsam_snapshot_entry_t *entry = NULL;
	memorystatus_jetsam_snapshot_t *snapshot    = NULL;
	memorystatus_jetsam_snapshot_entry_t *snapshot_list = NULL;

	unsigned int i;
#if CONFIG_FREEZE
	bool copied_to_freezer_snapshot = false;
#endif /* CONFIG_FREEZE */

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	if (memorystatus_jetsam_snapshot_count == 0) {
		/*
		 * No active snapshot.
		 * Nothing to do.
		 */
		goto exit;
	}

	/*
	 * Sanity check as this routine should only be called
	 * from a jetsam kill path.
	 */
	assert(kill_cause != 0 && killtime != 0);

	snapshot       = memorystatus_jetsam_snapshot;
	snapshot_list  = memorystatus_jetsam_snapshot->entries;

#if JETSAM_ZPRINT_SNAPSHOT
	/*
	 * Collect the snapshot zprint info if we've reached the right priority
	 */
	if (p->p_memstat_effectivepriority >= (int)jzs_trigger_band &&
	    jzs_gencount != snapshot->js_gencount) {
		memorystatus_collect_jetsam_snapshot_zprint();
		jzs_gencount = snapshot->js_gencount;
	}
#endif

	for (i = 0; i < memorystatus_jetsam_snapshot_count; i++) {
		if (snapshot_list[i].pid == proc_getpid(p)) {
			entry = &snapshot_list[i];

			if (entry->killed || entry->jse_killtime) {
				/*
				 * We apparently raced on the exit path
				 * for this process, as it's snapshot entry
				 * has already recorded a kill.
				 */
				assert(entry->killed && entry->jse_killtime);
				break;
			}

			/*
			 * Update the entry we just found in the snapshot.
			 */

			entry->killed       = kill_cause;
			entry->jse_killtime = killtime;
			entry->jse_gencount = snapshot->js_gencount;
			entry->jse_idle_delta = p->p_memstat_idle_delta;
#if CONFIG_FREEZE
			entry->jse_thaw_count = p->p_memstat_thaw_count;
			entry->jse_freeze_skip_reason = p->p_memstat_freeze_skip_reason;
#else /* CONFIG_FREEZE */
			entry->jse_thaw_count = 0;
			entry->jse_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
#endif /* CONFIG_FREEZE */

			/*
			 * If a process has moved between bands since snapshot was
			 * initialized, then likely these fields changed too.
			 */
			if (entry->priority != p->p_memstat_effectivepriority) {
				strlcpy(entry->name, p->p_name, sizeof(entry->name));
				entry->priority  = p->p_memstat_effectivepriority;
				entry->state     = _memstat_build_state(p);
				entry->user_data = p->p_memstat_userdata;
				entry->fds       = p->p_fd.fd_nfiles;
			}

			/*
			 * Always update the page counts on a kill.
			 */

			uint32_t pages              = 0;
			uint32_t max_pages_lifetime = 0;
			uint32_t purgeable_pages    = 0;

			memorystatus_get_task_page_counts(proc_task(p), &pages, &max_pages_lifetime, &purgeable_pages);
			entry->pages              = (uint64_t)pages;
			entry->max_pages_lifetime = (uint64_t)max_pages_lifetime;
			entry->purgeable_pages    = (uint64_t)purgeable_pages;

			uint64_t internal_pages                        = 0;
			uint64_t internal_compressed_pages             = 0;
			uint64_t purgeable_nonvolatile_pages           = 0;
			uint64_t purgeable_nonvolatile_compressed_pages = 0;
			uint64_t alternate_accounting_pages            = 0;
			uint64_t alternate_accounting_compressed_pages = 0;
			uint64_t iokit_mapped_pages                    = 0;
			uint64_t page_table_pages                      = 0;
			uint64_t frozen_to_swap_pages                  = 0;
			uint64_t neural_nofootprint_total_pages        = 0;

			memorystatus_get_task_phys_footprint_page_counts(proc_task(p), &internal_pages, &internal_compressed_pages,
			    &purgeable_nonvolatile_pages, &purgeable_nonvolatile_compressed_pages,
			    &alternate_accounting_pages, &alternate_accounting_compressed_pages,
			    &iokit_mapped_pages, &page_table_pages, &frozen_to_swap_pages, &neural_nofootprint_total_pages);

			entry->jse_internal_pages = internal_pages;
			entry->jse_internal_compressed_pages = internal_compressed_pages;
			entry->jse_purgeable_nonvolatile_pages = purgeable_nonvolatile_pages;
			entry->jse_purgeable_nonvolatile_compressed_pages = purgeable_nonvolatile_compressed_pages;
			entry->jse_alternate_accounting_pages = alternate_accounting_pages;
			entry->jse_alternate_accounting_compressed_pages = alternate_accounting_compressed_pages;
			entry->jse_iokit_mapped_pages = iokit_mapped_pages;
			entry->jse_page_table_pages = page_table_pages;
			entry->jse_frozen_to_swap_pages = frozen_to_swap_pages;
			entry->jse_neural_nofootprint_total_pages = neural_nofootprint_total_pages;

			uint64_t region_count = 0;
			memorystatus_get_task_memory_region_count(proc_task(p), &region_count);
			entry->jse_memory_region_count = region_count;
			entry->csflags = proc_getcsflags(p);
			goto exit;
		}
	}

	if (entry == NULL) {
		/*
		 * The entry was not found in the snapshot, so the process must have
		 * launched after the snapshot was initialized.
		 * Let's try to append the new entry.
		 */
		if (memorystatus_jetsam_snapshot_count < memorystatus_jetsam_snapshot_max) {
			/*
			 * A populated snapshot buffer exists
			 * and there is room to init a new entry.
			 */
			assert(memorystatus_jetsam_snapshot_count == snapshot->entry_count);

			if (memorystatus_init_jetsam_snapshot_entry_with_kill_locked(snapshot, p, kill_cause, killtime, &entry)) {
				memorystatus_jetsam_snapshot_count++;

				if (memorystatus_jetsam_snapshot_count >= memorystatus_jetsam_snapshot_max) {
					/*
					 * We just used the last slot in the snapshot buffer.
					 * We only want to log it once... so we do it here
					 * when we notice we've hit the max.
					 */
					memorystatus_log_error("memorystatus: WARNING snapshot buffer is full, count %d\n", memorystatus_jetsam_snapshot_count);
				}
			}
		}
	}

exit:
	if (entry) {
#if CONFIG_FREEZE
		if (memorystatus_jetsam_use_freezer_snapshot && isApp(p)) {
			/* This is an app kill. Record it in the freezer snapshot so dasd can incorporate this in its recommendations. */
			copied_to_freezer_snapshot = memorystatus_jetsam_snapshot_copy_entry_locked(memorystatus_jetsam_snapshot_freezer, memorystatus_jetsam_snapshot_freezer_max, entry);
			if (copied_to_freezer_snapshot && memorystatus_jetsam_snapshot_freezer->entry_count == memorystatus_jetsam_snapshot_freezer_max) {
				/*
				 * We just used the last slot in the freezer snapshot buffer.
				 * We only want to log it once... so we do it here
				 * when we notice we've hit the max.
				 */
				memorystatus_log_error("memorystatus: WARNING freezer snapshot buffer is full, count %zu\n",
				    memorystatus_jetsam_snapshot_freezer->entry_count);
			}
		}
#endif /* CONFIG_FREEZE */
	} else {
		/*
		 * If we reach here, the snapshot buffer could not be updated.
		 * Most likely, the buffer is full, in which case we would have
		 * logged a warning in the previous call.
		 *
		 * For now, we will stop appending snapshot entries.
		 * When the buffer is consumed, the snapshot state will reset.
		 */

		memorystatus_log_error(
			"memorystatus_update_jetsam_snapshot_entry_locked: failed to update pid %d, priority %d, count %d\n",
			proc_getpid(p), p->p_memstat_effectivepriority, memorystatus_jetsam_snapshot_count);

#if CONFIG_FREEZE
		/* We still attempt to record this in the freezer snapshot */
		if (memorystatus_jetsam_use_freezer_snapshot && isApp(p)) {
			snapshot = memorystatus_jetsam_snapshot_freezer;
			if (snapshot->entry_count < memorystatus_jetsam_snapshot_freezer_max) {
				copied_to_freezer_snapshot = memorystatus_init_jetsam_snapshot_entry_with_kill_locked(snapshot, p, kill_cause, killtime, &entry);
				if (copied_to_freezer_snapshot && memorystatus_jetsam_snapshot_freezer->entry_count == memorystatus_jetsam_snapshot_freezer_max) {
					/*
					 * We just used the last slot in the freezer snapshot buffer.
					 * We only want to log it once... so we do it here
					 * when we notice we've hit the max.
					 */
					memorystatus_log_error("memorystatus: WARNING freezer snapshot buffer is full, count %zu\n",
					    memorystatus_jetsam_snapshot_freezer->entry_count);
				}
			}
		}
#endif /* CONFIG_FREEZE */
	}

	return;
}

uint32_t
memorystatus_get_available_page_count(void)
{
	return os_atomic_load(&memorystatus_available_pages, relaxed);
}

void
memorystatus_update_available_page_count(uint32_t available_page_count)
{
	os_atomic_store(&memorystatus_available_pages, available_page_count,
	    relaxed);
#if VM_PRESSURE_EVENTS
	/*
	 * Since memorystatus_available_pages changes, we should
	 * re-evaluate the pressure levels on the system and
	 * check if we need to wake the pressure thread.
	 * We also update memorystatus_level in that routine.
	 */
	vm_pressure_response();
#endif /* VM_PRESSURE_EVENTS */
#if CONFIG_FREEZE
	/*
	 * We can't grab the freezer_mutex here even though that synchronization would be correct to inspect
	 * the # of frozen processes and wakeup the freezer thread. Reason being that we come here into this
	 * code with (possibly) the page-queue locks held and preemption disabled. So trying to grab a mutex here
	 * will result in the "mutex with preemption disabled" panic.
	 */

	if (memorystatus_freeze_thread_should_run()) {
		/*
		 * The freezer thread is usually woken up by some user-space call i.e. pid_hibernate(any process).
		 * That trigger isn't invoked often enough and so we are enabling this explicit wakeup here.
		 */
		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			thread_wakeup((event_t)&memorystatus_freeze_wakeup);
		}
	}
#endif /* CONFIG_FREEZE */
	_memstat_consider_waking_jetsam_thread();
}

static boolean_t
memorystatus_init_jetsam_snapshot_entry_locked(proc_t p, memorystatus_jetsam_snapshot_entry_t *entry, uint64_t gencount)
{
	clock_sec_t                     tv_sec;
	clock_usec_t                    tv_usec;
	uint32_t pages = 0;
	uint32_t max_pages_lifetime = 0;
	uint32_t purgeable_pages = 0;
	uint64_t internal_pages                         = 0;
	uint64_t internal_compressed_pages              = 0;
	uint64_t purgeable_nonvolatile_pages            = 0;
	uint64_t purgeable_nonvolatile_compressed_pages = 0;
	uint64_t alternate_accounting_pages             = 0;
	uint64_t alternate_accounting_compressed_pages  = 0;
	uint64_t iokit_mapped_pages                     = 0;
	uint64_t page_table_pages                       = 0;
	uint64_t frozen_to_swap_pages                   = 0;
	uint64_t neural_nofootprint_total_pages         = 0;
	uint64_t region_count                           = 0;
	uint64_t cids[COALITION_NUM_TYPES];
	uint32_t trust                                  = 0;
	kern_return_t ret                               = 0;
	memset(entry, 0, sizeof(memorystatus_jetsam_snapshot_entry_t));

	entry->pid = proc_getpid(p);
	strlcpy(&entry->name[0], p->p_name, sizeof(entry->name));
	entry->priority = p->p_memstat_effectivepriority;

	memorystatus_get_task_page_counts(proc_task(p), &pages, &max_pages_lifetime, &purgeable_pages);
	entry->pages              = (uint64_t)pages;
	entry->max_pages_lifetime = (uint64_t)max_pages_lifetime;
	entry->purgeable_pages    = (uint64_t)purgeable_pages;

	memorystatus_get_task_phys_footprint_page_counts(proc_task(p), &internal_pages, &internal_compressed_pages,
	    &purgeable_nonvolatile_pages, &purgeable_nonvolatile_compressed_pages,
	    &alternate_accounting_pages, &alternate_accounting_compressed_pages,
	    &iokit_mapped_pages, &page_table_pages, &frozen_to_swap_pages, &neural_nofootprint_total_pages);

	entry->jse_internal_pages = internal_pages;
	entry->jse_internal_compressed_pages = internal_compressed_pages;
	entry->jse_purgeable_nonvolatile_pages = purgeable_nonvolatile_pages;
	entry->jse_purgeable_nonvolatile_compressed_pages = purgeable_nonvolatile_compressed_pages;
	entry->jse_alternate_accounting_pages = alternate_accounting_pages;
	entry->jse_alternate_accounting_compressed_pages = alternate_accounting_compressed_pages;
	entry->jse_iokit_mapped_pages = iokit_mapped_pages;
	entry->jse_page_table_pages = page_table_pages;
	entry->jse_frozen_to_swap_pages = frozen_to_swap_pages;
	entry->jse_neural_nofootprint_total_pages = neural_nofootprint_total_pages;

	memorystatus_get_task_memory_region_count(proc_task(p), &region_count);
	entry->jse_memory_region_count = region_count;

	entry->state     = _memstat_build_state(p);
	entry->user_data = p->p_memstat_userdata;
	proc_getexecutableuuid(p, &entry->uuid[0], sizeof(entry->uuid));
	entry->fds       = p->p_fd.fd_nfiles;

	absolutetime_to_microtime(get_task_cpu_time(proc_task(p)), &tv_sec, &tv_usec);
	entry->cpu_time.tv_sec = (int64_t)tv_sec;
	entry->cpu_time.tv_usec = (int64_t)tv_usec;

	assert(p->p_stats != NULL);
	entry->jse_starttime =  p->p_stats->ps_start;   /* abstime process started */
	entry->jse_killtime = 0;                        /* abstime jetsam chose to kill process */
	entry->killed       = 0;                        /* the jetsam kill cause */
	entry->jse_gencount = gencount;                 /* indicates a pass through jetsam thread, when process was targeted to be killed */

	entry->jse_idle_delta = p->p_memstat_idle_delta; /* Most recent timespan spent in idle-band */

#if CONFIG_FREEZE
	entry->jse_freeze_skip_reason = p->p_memstat_freeze_skip_reason;
	entry->jse_thaw_count = p->p_memstat_thaw_count;
#else /* CONFIG_FREEZE */
	entry->jse_thaw_count = 0;
	entry->jse_freeze_skip_reason = kMemorystatusFreezeSkipReasonNone;
#endif /* CONFIG_FREEZE */

	proc_coalitionids(p, cids);
	entry->jse_coalition_jetsam_id = cids[COALITION_TYPE_JETSAM];
	entry->csflags = proc_getcsflags(p);
	ret = get_trust_level_kdp(get_task_pmap(proc_task(p)), &trust);
	if (ret != KERN_SUCCESS) {
		trust = KCDATA_INVALID_CS_TRUST_LEVEL;
	}
	entry->cs_trust_level = trust;
	return TRUE;
}

static void
memorystatus_init_snapshot_vmstats(memorystatus_jetsam_snapshot_t *snapshot)
{
	kern_return_t kr = KERN_SUCCESS;
	mach_msg_type_number_t  count = HOST_VM_INFO64_COUNT;
	vm_statistics64_data_t  vm_stat;

	if ((kr = host_statistics64(host_self(), HOST_VM_INFO64, (host_info64_t)&vm_stat, &count)) != KERN_SUCCESS) {
		memorystatus_log_error("memorystatus_init_jetsam_snapshot_stats: host_statistics64 failed with %d\n", kr);
		memset(&snapshot->stats, 0, sizeof(snapshot->stats));
	} else {
		snapshot->stats.free_pages      = vm_stat.free_count;
		snapshot->stats.active_pages    = vm_stat.active_count;
		snapshot->stats.inactive_pages  = vm_stat.inactive_count;
		snapshot->stats.throttled_pages = vm_stat.throttled_count;
		snapshot->stats.purgeable_pages = vm_stat.purgeable_count;
		snapshot->stats.wired_pages     = vm_stat.wire_count;

		snapshot->stats.speculative_pages = vm_stat.speculative_count;
		snapshot->stats.filebacked_pages  = vm_stat.external_page_count;
		snapshot->stats.anonymous_pages   = vm_stat.internal_page_count;
		snapshot->stats.compressions      = vm_stat.compressions;
		snapshot->stats.decompressions    = vm_stat.decompressions;
		snapshot->stats.compressor_pages  = vm_stat.compressor_page_count;
		snapshot->stats.total_uncompressed_pages_in_compressor = vm_stat.total_uncompressed_pages_in_compressor;
	}

	get_zone_map_size(&snapshot->stats.zone_map_size, &snapshot->stats.zone_map_capacity);

	bzero(snapshot->stats.largest_zone_name, sizeof(snapshot->stats.largest_zone_name));
	get_largest_zone_info(snapshot->stats.largest_zone_name, sizeof(snapshot->stats.largest_zone_name),
	    &snapshot->stats.largest_zone_size);
}

/*
 * Collect vm statistics at boot.
 * Called only once (see kern_exec.c)
 * Data can be consumed at any time.
 */
void
memorystatus_init_at_boot_snapshot()
{
	memorystatus_init_snapshot_vmstats(&memorystatus_at_boot_snapshot);
	memorystatus_at_boot_snapshot.entry_count = 0;
	memorystatus_at_boot_snapshot.notification_time = 0;   /* updated when consumed */
	memorystatus_at_boot_snapshot.snapshot_time = mach_absolute_time();
}

static void
memorystatus_init_jetsam_snapshot_header(memorystatus_jetsam_snapshot_t *snapshot)
{
	memorystatus_init_snapshot_vmstats(snapshot);
	snapshot->snapshot_time = mach_absolute_time();
	snapshot->notification_time = 0;
	snapshot->js_gencount = 0;
}

static void
memorystatus_init_jetsam_snapshot_locked(memorystatus_jetsam_snapshot_t *od_snapshot, uint32_t ods_list_count )
{
	proc_t p, next_p;
	unsigned int b = 0, i = 0;

	memorystatus_jetsam_snapshot_t *snapshot = NULL;
	memorystatus_jetsam_snapshot_entry_t *snapshot_list = NULL;
	unsigned int snapshot_max = 0;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	if (od_snapshot) {
		/*
		 * This is an on_demand snapshot
		 */
		snapshot      = od_snapshot;
		snapshot_list = od_snapshot->entries;
		snapshot_max  = ods_list_count;
	} else {
		/*
		 * This is a jetsam event snapshot
		 */
		snapshot      = memorystatus_jetsam_snapshot;
		snapshot_list = memorystatus_jetsam_snapshot->entries;
		snapshot_max  = memorystatus_jetsam_snapshot_max;
	}

	memorystatus_init_jetsam_snapshot_header(snapshot);

	next_p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&b, p, TRUE);

		if (FALSE == memorystatus_init_jetsam_snapshot_entry_locked(p, &snapshot_list[i], snapshot->js_gencount)) {
			continue;
		}

		if (++i == snapshot_max) {
			break;
		}
	}

	/* Log launchd and kernel_task as well to see more context, even though jetsam doesn't apply to them. */
	if (i < snapshot_max) {
		memorystatus_init_jetsam_snapshot_entry_locked(initproc, &snapshot_list[i], snapshot->js_gencount);
		i++;
	}

	if (i < snapshot_max) {
		memorystatus_init_jetsam_snapshot_entry_locked(kernproc, &snapshot_list[i], snapshot->js_gencount);
		i++;
	}

	snapshot->entry_count = i;

	if (!od_snapshot) {
		/* update the system buffer count */
		memorystatus_jetsam_snapshot_count = i;
	}
}

/* number of entries added to the end of the jetsam snapshot (for launchd and kernel) */
static const int memorystatus_artificial_snapshot_entry_count = 2;

#if DEVELOPMENT || DEBUG

/*
 * Verify that the given bucket has been sorted correctly.
 *
 * Walks through the bucket and verifies that all pids in the
 * expected_order buffer are in that bucket and in the same
 * relative order.
 *
 * The proc_list_lock must be held by the caller.
 */
static int
memorystatus_verify_sort_order(unsigned int bucket_index, pid_t *expected_order, size_t num_pids)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	int error = 0;
	proc_t p = NULL;
	size_t i = 0;

	/*
	 * NB: We allow other procs to be mixed in within the expected ones.
	 * We just need the expected procs to be in the right order relative to each other.
	 */
	p = memorystatus_get_first_proc_locked(&bucket_index, FALSE);
	while (p) {
		if (proc_getpid(p) == expected_order[i]) {
			i++;
		}
		if (i == num_pids) {
			break;
		}
		p = memorystatus_get_next_proc_locked(&bucket_index, p, FALSE);
	}
	if (i != num_pids) {
		char buffer[128];
		size_t len = sizeof(buffer);
		size_t buffer_idx = 0;
		memorystatus_log_error("memorystatus_verify_sort_order: Processes in bucket %d were not sorted properly\n", bucket_index);
		for (i = 0; i < num_pids; i++) {
			int num_written = snprintf(buffer + buffer_idx, len - buffer_idx, "%d,", expected_order[i]);
			if (num_written <= 0) {
				break;
			}
			if (buffer_idx + (unsigned int) num_written >= len) {
				break;
			}
			buffer_idx += num_written;
		}
		memorystatus_log_error("memorystatus_verify_sort_order: Expected order [%s]\n", buffer);
		memset(buffer, 0, len);
		buffer_idx = 0;
		p = memorystatus_get_first_proc_locked(&bucket_index, FALSE);
		i = 0;
		memorystatus_log_error("memorystatus_verify_sort_order: Actual order:\n");
		while (p) {
			int num_written;
			if (buffer_idx == 0) {
				num_written = snprintf(buffer + buffer_idx, len - buffer_idx, "%zu: %d,", i, proc_getpid(p));
			} else {
				num_written = snprintf(buffer + buffer_idx, len - buffer_idx, "%d,", proc_getpid(p));
			}
			if (num_written <= 0) {
				break;
			}
			buffer_idx += (unsigned int) num_written;
			assert(buffer_idx <= len);
			if (i % 10 == 0) {
				memorystatus_log_error("memorystatus_verify_sort_order: %s\n", buffer);
				buffer_idx = 0;
			}
			p = memorystatus_get_next_proc_locked(&bucket_index, p, FALSE);
			i++;
		}
		if (buffer_idx != 0) {
			memorystatus_log_error("memorystatus_verify_sort_order: %s\n", buffer);
		}
		error = EINVAL;
	}
	return error;
}

/*
 * Triggers a sort_order on a specified jetsam priority band.
 * This is for testing only, used to force a path through the sort
 * function.
 */
static int
memorystatus_cmd_test_jetsam_sort(int priority,
    int sort_order,
    user_addr_t expected_order_user,
    size_t expected_order_user_len)
{
	int error = 0;
	unsigned int bucket_index = 0;
	const size_t kMaxPids = 8;
	pid_t expected_order[kMaxPids];
	size_t copy_size = sizeof(expected_order);
	size_t num_pids;

	if (expected_order_user_len < copy_size) {
		copy_size = expected_order_user_len;
	}
	num_pids = copy_size / sizeof(pid_t);

	error = copyin(expected_order_user, expected_order, copy_size);
	if (error != 0) {
		return error;
	}

	if (priority == -1) {
		/* Use as shorthand for default priority */
		bucket_index = JETSAM_PRIORITY_DEFAULT;
	} else {
		bucket_index = (unsigned int)priority;
	}

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return EINVAL;
	}

	/*
	 * Acquire lock before sorting so we can check the sort order
	 * while still holding the lock.
	 */
	proc_list_lock();

	memorystatus_sort_bucket_locked(bucket_index, sort_order);

	if (expected_order_user != CAST_USER_ADDR_T(NULL) && expected_order_user_len > 0) {
		error = memorystatus_verify_sort_order(bucket_index, expected_order, num_pids);
	}

	proc_list_unlock();

	return error;
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * Prepare the process to be killed (set state, update snapshot) and kill it.
 */
static uint64_t memorystatus_purge_before_jetsam_success = 0;

#if SOCKETS
static int
networking_memstatus_callout(proc_t p, uint32_t status)
{
	struct fileproc *fp;

	/*
	 * proc list lock NOT held
	 * proc lock NOT held
	 * a reference on the proc has been held / shall be dropped by the caller.
	 */
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);
	LCK_MTX_ASSERT(&p->p_mlock, LCK_MTX_ASSERT_NOTOWNED);

	proc_fdlock(p);

	fdt_foreach(fp, p) {
		switch (FILEGLOB_DTYPE(fp->fp_glob)) {
#if NECP
		case DTYPE_NETPOLICY:
			necp_fd_memstatus(p, status,
			    (struct necp_fd_data *)fp_get_data(fp));
			break;
#endif /* NECP */
#if SKYWALK
		case DTYPE_CHANNEL:
			kern_channel_memstatus(p, status,
			    (struct kern_channel *)fp_get_data(fp));
			break;
#endif /* SKYWALK */
		default:
			break;
		}
	}
	proc_fdunlock(p);

	return 1;
}
#endif /* SOCKETS */

static bool
memorystatus_kill_proc(proc_t p, uint32_t cause, os_reason_t jetsam_reason, bool *killed, uint64_t *footprint_of_killed_proc)
{
	pid_t aPid = 0;
	uint32_t aPid_ep = 0;

	uint64_t        killtime = 0;
	uint64_t        time_in_priority_band_secs = 0;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;
	bool retval = false;

	aPid = proc_getpid(p);
	aPid_ep = p->p_memstat_effectivepriority;

	if (cause != kMemorystatusKilledVnodes && cause != kMemorystatusKilledZoneMapExhaustion) {
		/*
		 * Genuine memory pressure and not other (vnode/zone) resource exhaustion.
		 */
		boolean_t success = FALSE;
		uint64_t num_pages_purged;
		uint64_t num_pages_reclaimed = 0;
		uint64_t num_pages_unsecluded = 0;

		networking_memstatus_callout(p, cause);
		num_pages_purged = vm_purgeable_purge_task_owned(proc_task(p));
		num_pages_reclaimed += num_pages_purged;
#if CONFIG_SECLUDED_MEMORY
		if (cause == kMemorystatusKilledVMPageShortage &&
		    vm_page_secluded_count > 0 &&
		    task_can_use_secluded_mem(proc_task(p), FALSE)) {
			/*
			 * We're about to kill a process that has access
			 * to the secluded pool.  Drain that pool into the
			 * free or active queues to make these pages re-appear
			 * as "available", which might make us no longer need
			 * to kill that process.
			 * Since the secluded pool does not get refilled while
			 * a process has access to it, it should remain
			 * drained.
			 */
			num_pages_unsecluded = vm_page_secluded_drain();
			num_pages_reclaimed += num_pages_unsecluded;
		}
#endif /* CONFIG_SECLUDED_MEMORY */

		if (num_pages_reclaimed) {
			/*
			 * We actually reclaimed something and so let's
			 * check if we need to continue with the kill.
			 */
			if (cause == kMemorystatusKilledHiwat) {
				uint64_t footprint_in_bytes = get_task_phys_footprint(proc_task(p));
				uint64_t memlimit_in_bytes  = (((uint64_t)p->p_memstat_memlimit) * 1024ULL * 1024ULL);  /* convert MB to bytes */
				success = (footprint_in_bytes <= memlimit_in_bytes);
			} else {
				success = !(memorystatus_get_available_page_count() < memorystatus_get_soft_memlimit_page_shortage_threshold());
#if CONFIG_SECLUDED_MEMORY
				if (!success && num_pages_unsecluded) {
					/*
					 * We just drained the secluded pool
					 * because we're about to kill a
					 * process that has access to it.
					 * This is an important process and
					 * we'd rather not kill it unless
					 * absolutely necessary, so declare
					 * success even if draining the pool
					 * did not quite get us out of the
					 * "pressure" level but still got
					 * us out of the "critical" level.
					 */
					success = !(
						memorystatus_get_available_page_count() <
						memorystatus_get_critical_page_shortage_threshold());
				}
#endif /* CONFIG_SECLUDED_MEMORY */
			}

			if (success) {
				memorystatus_purge_before_jetsam_success++;

				memorystatus_log_info("memorystatus: reclaimed %llu pages (%llu purged, %llu unsecluded) from pid %d [%s] and avoided %s\n",
				    num_pages_reclaimed, num_pages_purged, num_pages_unsecluded, aPid, ((p && *p->p_name) ? p->p_name : "unknown"), memorystatus_kill_cause_name[cause]);

				*killed = false;
				*footprint_of_killed_proc = num_pages_reclaimed + num_pages_purged + num_pages_unsecluded;

				return true;
			}
		}
	}

	killtime = mach_absolute_time();
	absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
	tv_msec = tv_usec / 1000;

	proc_list_lock();
	memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);
	proc_list_unlock();

	char kill_reason_string[128];

	if (cause == kMemorystatusKilledHiwat) {
		strlcpy(kill_reason_string, "killing_highwater_process", 128);
	} else {
		if (aPid_ep == JETSAM_PRIORITY_IDLE) {
			strlcpy(kill_reason_string, "killing_idle_process", 128);
		} else {
			strlcpy(kill_reason_string, "killing_top_process", 128);
		}
	}

	/*
	 * memorystatus_do_kill drops a reference, so take another one so we can
	 * continue to use this exit reason even after memorystatus_do_kill()
	 * returns
	 */
	os_reason_ref(jetsam_reason);

	retval = memorystatus_do_kill(p, cause, jetsam_reason, footprint_of_killed_proc);
	*killed = retval;

	absolutetime_to_nanoseconds(killtime - p->p_memstat_prio_start, &time_in_priority_band_secs);
	time_in_priority_band_secs /= NSEC_PER_SEC;

	memorystatus_log("memorystatus: %s pid %d [%s] (%s %d %llus rf:%s) %lluKB - memorystatus_available_pages: %llu compressor_size:%u\n",
	    kill_reason_string,
	    aPid, proc_best_name(p),
	    memorystatus_kill_cause_name[cause], aPid_ep, time_in_priority_band_secs, _memstat_relaunch_flags_description(p->p_memstat_relaunch_flags),
	    (*footprint_of_killed_proc) >> 10, (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());

	return retval;
}

/*
 * Jetsam the first process in the queue.
 */
static bool
memorystatus_kill_top_process(bool any, bool sort_flag, uint32_t cause, os_reason_t jetsam_reason,
    int32_t max_priority, bool only_swappable, bool only_long_idle,
    int32_t *priority, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	bool new_snapshot = false, force_new_snapshot = false, killed = false, freed_mem = false;
	unsigned int i = 0;
	uint32_t aPid_ep;
	uint64_t footprint_of_killed_proc = 0;

#ifndef CONFIG_FREEZE
#pragma unused(any)
#endif

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES);


#if CONFIG_JETSAM
	if (sort_flag) {
		(void)memorystatus_sort_bucket(JETSAM_PRIORITY_FOREGROUND, JETSAM_SORT_DEFAULT);
	}

	*memory_reclaimed = 0;

#if VM_PRESSURE_EVENTS
	if (cause == kMemorystatusKilledSustainedPressure) {
		max_priority = memorystatus_sustained_pressure_maximum_band;
	}
#endif /* VM_PRESSURE_EVENTS */

	force_new_snapshot = false;

#else /* CONFIG_JETSAM */
	if (sort_flag) {
		(void)memorystatus_sort_bucket(JETSAM_PRIORITY_IDLE, JETSAM_SORT_DEFAULT);
	}

	/*
	 * And, because we are here under extreme circumstances, we force a snapshot even for
	 * IDLE kills.
	 */
	force_new_snapshot = true;

#endif /* CONFIG_JETSAM */

	if (cause != kMemorystatusKilledZoneMapExhaustion &&
	    jetsam_current_thread() != NULL &&
	    jetsam_current_thread()->limit_to_low_bands &&
	    max_priority > JETSAM_PRIORITY_MAIL) {
		max_priority = JETSAM_PRIORITY_MAIL;
	}

	_memstat_refresh_oldest_reapable_proc_info();

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p && (next_p->p_memstat_effectivepriority <= max_priority)) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);


		aPid = proc_getpid(p);
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP)) {
			continue;   /* with lock held */
		}

		if (cause == kMemorystatusKilledVnodes) {
			/*
			 * If the system runs out of vnodes, we systematically jetsam
			 * processes in hopes of stumbling onto a vnode gain that helps
			 * the system recover.  The process that happens to trigger
			 * this path has no known relationship to the vnode shortage.
			 * Deadlock avoidance: attempt to safeguard the caller.
			 */

			if (p == current_proc()) {
				/* do not jetsam the current process */
				continue;
			}
		}

		if (only_swappable && !task_donates_own_pages(proc_task(p))) {
			continue;
		}

		if (only_long_idle) {
			if (!_memstat_proc_is_reapable(p)) {
				memorystatus_log_debug("memorystatus: memorystatus_kill_top_process: skipping non-reapable process %s [%d]\n",
				    proc_best_name(p), p->p_pid);
				continue;
			}
			memorystatus_log_debug("memorystatus: memorystatus_kill_top_process: found reapable long-idle process %s [%d]\n",
			    proc_best_name(p), p->p_pid);
		}

#if !CONFIG_JETSAM
		if (max_priority == JETSAM_PRIORITY_IDLE &&
		    !((_memstat_proc_can_idle_exit(p) && !_memstat_proc_is_dirty(p)) ||
		    (_memstat_proc_is_managed(p) && !_memstat_proc_has_priority_assertion(p)))) {
			/*
			 * This process is in the idle band but is not clean+idle-exitable or
			 * managed+assertion-less. Skip it.
			 */
			memorystatus_log_error("memorystatus: skipping idle but not idle-exitable process "
			    "%s [%d] (0x%x)\n", proc_best_name(p), proc_getpid(p), p->p_memstat_state);
			continue;
		}
#endif /* !CONFIG_JETSAM */
#if CONFIG_FREEZE
		boolean_t skip;
		boolean_t reclaim_proc = !(p->p_memstat_state & P_MEMSTAT_LOCKED);
		if (any || reclaim_proc) {
			skip = FALSE;
		} else {
			skip = TRUE;
		}

		if (skip) {
			continue;
		} else
#endif
		{
			if (proc_ref(p, true) == p) {
				/*
				 * Mark as terminated so that if exit1() indicates success, but the process (for example)
				 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see
				 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the
				 * acquisition of the proc lock.
				 */
				p->p_memstat_state |= P_MEMSTAT_TERMINATED;
			} else {
				/*
				 * We need to restart the search again because
				 * proc_ref _can_ drop the proc_list lock
				 * and we could have lost our stored next_p via
				 * an exit() on another core.
				 */
				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
				continue;
			}

			/*
			 * Capture a snapshot if none exists and:
			 * - we are forcing a new snapshot creation, either because:
			 *      - on a particular platform we need these snapshots every time, OR
			 *	- a boot-arg/embedded device tree property has been set.
			 * - priority was not requested (this is something other than an ambient kill)
			 * - the priority was requested *and* the targeted process is not at idle priority
			 */
			if ((memorystatus_jetsam_snapshot_count == 0) &&
			    (force_new_snapshot || memorystatus_idle_snapshot || ((!priority) || (priority && (aPid_ep != JETSAM_PRIORITY_IDLE))))) {
				memorystatus_init_jetsam_snapshot_locked(NULL, 0);
				new_snapshot = true;
			}

			proc_list_unlock();

			freed_mem = memorystatus_kill_proc(p, cause, jetsam_reason, &killed, &footprint_of_killed_proc); /* purged and/or killed 'p' */
			/* Success? */
			if (freed_mem) {
				*memory_reclaimed = footprint_of_killed_proc;
				if (killed) {
					if (priority) {
						*priority = aPid_ep;
					}
				} else {
					/* purged */
					proc_list_lock();
					p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
					proc_list_unlock();
				}
				proc_rele(p);
				goto exit;
			}

			/*
			 * Failure - first unwind the state,
			 * then fall through to restart the search.
			 */
			proc_list_lock();
			proc_rele(p);
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
			p->p_memstat_state |= P_MEMSTAT_ERROR;
			*errors += 1;

			i = 0;
			next_p = memorystatus_get_first_proc_locked(&i, TRUE);
		}
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	if (!killed) {
		/* Clear snapshot if freshly captured and no target was found */
		if (new_snapshot) {
			proc_list_lock();
			memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
			proc_list_unlock();
		}
#if CONFIG_JETSAM
		if (only_long_idle) {
			_memstat_reaper_end_sweep();
		}
#endif
	}

#if CONFIG_JETSAM
	if (killed && only_long_idle) {
		_memstat_reaper_record_kill(footprint_of_killed_proc);
	}
#endif

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, killed ? aPid : 0, killed, *memory_reclaimed);

	return killed;
}

static
void
_memstat_refresh_oldest_reapable_proc_info()
{
	uint64_t oldest_prio_start = MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_NONE;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	unsigned int i = 0;
	uint64_t mat = mach_absolute_time();
	uint64_t rescan_timeout_duration_matu;


	/* If we're still within 'memstat_reaper_rescan_secs' of the last process-list walk,
	 * don't do another walk yet, and just use the existing information.
	 */
	if (mat < memstat_oldest_reapable_proc_info_expiration_ts_matu) {
		memorystatus_log_debug("memorystatus: _memstat_refresh_oldest_reapable_proc_info: re-using existing data\n");
		return;
	} else {
		memorystatus_log_debug("memorystatus: _memstat_refresh_oldest_reapable_proc_info: rescanning proc list\n");
	}

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);

		/* Since the process list is sorted in priority order, once we find the first
		 * process that is out of the reaper's acceptible range, we can skip the rest
		 */
		if (p->p_memstat_effectivepriority > memstat_reaper_max_priority) {
			break;
		}

		if (_memstat_proc_is_reapable(p)) {
			uint64_t proc_prio_start = p->p_memstat_prio_start;
			if (proc_prio_start < oldest_prio_start) {
				oldest_prio_start = proc_prio_start;
			}
		}
	}

	proc_list_unlock();

	memstat_oldest_reapable_proc_prio_start = oldest_prio_start;

	if (memstat_oldest_reapable_proc_prio_start != MEMSTAT_OLDEST_REAPABLE_PROC_PRIO_START_NONE) {
		uint64_t min_age_matu;
		nanoseconds_to_absolutetime((memstat_reaper_min_age_secs * NSEC_PER_SEC), &min_age_matu);
		memstat_oldest_reapable_proc_will_be_reapable_at_ts_matu = memstat_oldest_reapable_proc_prio_start + min_age_matu;
	}

	nanoseconds_to_absolutetime((memstat_reaper_rescan_secs * NSEC_PER_SEC), &rescan_timeout_duration_matu);
	memstat_oldest_reapable_proc_info_expiration_ts_matu = mat + rescan_timeout_duration_matu;
}

static bool
_memstat_proc_is_reapable(proc_t proc)
{
	uint32_t priority_band;
	uint64_t time_in_priority_band_secs;
	uint32_t relaunch_probability_acceptable_mask;

	/*
	 *  To be potentially reapable, the process
	 *  - must be in or below the max reapable priority and
	 *  - must have been in that priority band longer than the reaper minimum age threshold
	 *  - must not have a relaunch probability of High or Medium
	 */
	priority_band = proc->p_memstat_effectivepriority;
	if (priority_band > memstat_reaper_max_priority) {
		memorystatus_log_debug("_memstat_proc_is_reapable: %s [%d] not reapable because priority (%d) is above threshold (%d)\n",
		    proc_best_name(proc), proc->p_pid, priority_band, memstat_reaper_max_priority);
		return false;
	}

	absolutetime_to_nanoseconds(mach_absolute_time() - proc->p_memstat_prio_start, &time_in_priority_band_secs);
	time_in_priority_band_secs /= NSEC_PER_SEC;
	if (time_in_priority_band_secs < memstat_reaper_min_age_secs) {
		memorystatus_log_debug("_memstat_proc_is_reapable: %s [%d] not reapable because age (%llu) is below min age (%d)\n",
		    proc_best_name(proc), proc->p_pid, time_in_priority_band_secs, memstat_reaper_min_age_secs);
		return false;
	}

	uint32_t relaunch_flags = proc->p_memstat_relaunch_flags;
	// There's no explicit flag for "unknown" relaunch probability, and we need one for our control bitmask.
	// So if none of the Low Medium or High bits are set, we set the next higher bit as the "unknown relaunch probability" bit
	// and then test all the bits at once, below, with a bitwise-and.
	if ((relaunch_flags & (P_MEMSTAT_RELAUNCH_LOW | P_MEMSTAT_RELAUNCH_MED | P_MEMSTAT_RELAUNCH_HIGH)) == 0) {
		relaunch_flags |= MEMORYSTATUS_REAPER_REAP_RELAUNCH_MASK_UNKNOWN; // The bit for 'unknown' is the one just to the left (above) of High, e.g. 0x08
	}
	relaunch_probability_acceptable_mask = relaunch_flags & memstat_reaper_reap_relaunch_mask;

	if (relaunch_probability_acceptable_mask == 0) {
		memorystatus_log_debug("_memstat_proc_is_reapable: %s [%d] not reapable because relaunch probability bitmask (0x%02X) does not match with the memstat_reaper_reap_relaunch_mask (0x%02X).\n",
		    proc_best_name(proc), proc->p_pid, relaunch_flags, memstat_reaper_reap_relaunch_mask);
		return false;
	}

	memorystatus_log_debug("_memstat_proc_is_reapable: %s [%d] is reapable; priority=%d, age=%d, relaunch_probability_acceptable_mask=0x%02X\n",
	    proc_best_name(proc), proc->p_pid, priority_band, (uint32_t)(time_in_priority_band_secs), relaunch_probability_acceptable_mask );
	return true;
}

/*
 * Jetsam aggressively
 */
static bool
memorystatus_kill_processes_aggressive(uint32_t cause, int aggr_count,
    int32_t priority_max, int max_kills, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	unsigned int priority_band = JETSAM_PRIORITY_IDLE;
	int32_t aPid_ep = 0;
	unsigned int memorystatus_level_snapshot = 0;
	uint64_t killtime = 0;
	uint64_t time_in_priority_band_secs = 0;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;
	os_reason_t jetsam_reason = OS_REASON_NULL;
	uint64_t footprint_of_killed_proc = 0;

	*memory_reclaimed = 0;

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, priority_max);

	if (priority_max >= JETSAM_PRIORITY_FOREGROUND) {
		/*
		 * Check if aggressive jetsam has been asked to kill upto or beyond the
		 * JETSAM_PRIORITY_FOREGROUND bucket. If yes, sort the FG band based on
		 * coalition footprint.
		 */
		memorystatus_sort_bucket(JETSAM_PRIORITY_FOREGROUND, JETSAM_SORT_DEFAULT);
	}

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, cause);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus_kill_processes_aggressive: failed to allocate exit reason\n");
	}
	memorystatus_log("memorystatus: aggressively killing up to %d processes below band %d.\n", max_kills, priority_max + 1);
	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&priority_band, TRUE);
	while (next_p) {
		if (proc_list_exited(next_p) ||
		    ((unsigned int)(next_p->p_memstat_effectivepriority) != priority_band)) {
			/*
			 * We have raced with next_p running on another core.
			 * It may be exiting or it may have moved to a different
			 * jetsam priority band.  This means we have lost our
			 * place in line while traversing the jetsam list.  We
			 * attempt to recover by rewinding to the beginning of the band
			 * we were already traversing.  By doing this, we do not guarantee
			 * that no process escapes this aggressive march, but we can make
			 * skipping an entire range of processes less likely. (PR-21069019)
			 */

			memorystatus_log_debug(
				"memorystatus: aggressive%d: rewinding band %d, %s(%d) moved or exiting.\n",
				aggr_count, priority_band, (*next_p->p_name ? next_p->p_name : "unknown"), proc_getpid(next_p));

			next_p = memorystatus_get_first_proc_locked(&priority_band, TRUE);
			continue;
		}

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&priority_band, p, TRUE);

		if (p->p_memstat_effectivepriority > priority_max) {
			/*
			 * Bail out of this killing spree if we have
			 * reached beyond the priority_max jetsam band.
			 * That is, we kill up to and through the
			 * priority_max jetsam band.
			 */
			proc_list_unlock();
			goto exit;
		}

		aPid = proc_getpid(p);
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP)) {
			continue;
		}

		/*
		 * Capture a snapshot if none exists.
		 */
		if (memorystatus_jetsam_snapshot_count == 0) {
			memorystatus_init_jetsam_snapshot_locked(NULL, 0);
			new_snapshot = TRUE;
		}

		/*
		 * Mark as terminated so that if exit1() indicates success, but the process (for example)
		 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see
		 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the
		 * acquisition of the proc lock.
		 */
		p->p_memstat_state |= P_MEMSTAT_TERMINATED;

		killtime = mach_absolute_time();
		absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
		tv_msec = tv_usec / 1000;

		/* Shift queue, update stats */
		memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

		/*
		 * In order to kill the target process, we will drop the proc_list_lock.
		 * To guaranteee that p and next_p don't disappear out from under the lock,
		 * we must take a ref on both.
		 * If we cannot get a reference, then it's likely we've raced with
		 * that process exiting on another core.
		 */
		if (proc_ref(p, true) == p) {
			if (next_p) {
				while (next_p && (proc_ref(next_p, true) != next_p)) {
					proc_t temp_p;

					/*
					 * We must have raced with next_p exiting on another core.
					 * Recover by getting the next eligible process in the band.
					 */

					memorystatus_log_debug(
						"memorystatus: aggressive%d: skipping %d [%s] (exiting?)\n",
						aggr_count, proc_getpid(next_p), (*next_p->p_name ? next_p->p_name : "(unknown)"));

					temp_p = next_p;
					next_p = memorystatus_get_next_proc_locked(&priority_band, temp_p, TRUE);
				}
			}
			proc_list_unlock();

			if (aPid_ep <= system_procs_aging_band &&
			    (p->p_memstat_relaunch_flags & P_MEMSTAT_RELAUNCH_HIGH)) {
				memorystatus_log("memorystatus: killing %s [%d] in band %d "
				    "with high relaunch probability\n",
				    proc_best_name(p), aPid, aPid_ep);
			}
			absolutetime_to_nanoseconds(killtime - p->p_memstat_prio_start, &time_in_priority_band_secs);
			time_in_priority_band_secs /= NSEC_PER_SEC;
			memorystatus_log(
				"memorystatus: %s%d pid %d [%s] (%s %d %llus rf:%s - memorystatus_available_pages: %llu\n",
				((aPid_ep == JETSAM_PRIORITY_IDLE) ? "killing_idle_process_aggressive" : "killing_top_process_aggressive"),
				aggr_count, aPid, proc_best_name(p),
				memorystatus_kill_cause_name[cause], aPid_ep,
				time_in_priority_band_secs, _memstat_relaunch_flags_description(p->p_memstat_relaunch_flags),
				(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);

			memorystatus_level_snapshot = memorystatus_level;

			/*
			 * memorystatus_do_kill() drops a reference, so take another one so we can
			 * continue to use this exit reason even after memorystatus_do_kill()
			 * returns.
			 */
			os_reason_ref(jetsam_reason);
			killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

			/* Success? */
			if (killed) {
				*memory_reclaimed += footprint_of_killed_proc;
				proc_rele(p);
				kill_count++;
				p = NULL;
				killed = FALSE;

				/*
				 * Continue the killing spree.
				 */
				proc_list_lock();
				if (next_p) {
					proc_rele(next_p);
				}

				if (kill_count == max_kills) {
					memorystatus_log_info(
						"memorystatus: giving up aggressive kill after killing "
						"%d processes below band %d.\n",
						max_kills, priority_max + 1);
					break;
				}

				if (aPid_ep == JETSAM_PRIORITY_FOREGROUND && memorystatus_aggressive_jetsam_lenient == TRUE) {
					if (memorystatus_level > memorystatus_level_snapshot && ((memorystatus_level - memorystatus_level_snapshot) >= AGGRESSIVE_JETSAM_LENIENT_MODE_THRESHOLD)) {
#if DEVELOPMENT || DEBUG
						memorystatus_log_info("Disabling Lenient mode after one-time deployment.\n");
#endif /* DEVELOPMENT || DEBUG */
						memorystatus_aggressive_jetsam_lenient = FALSE;
						break;
					}
				}

				continue;
			}

			/*
			 * Failure - first unwind the state,
			 * then fall through to restart the search.
			 */
			proc_list_lock();
			proc_rele(p);
			if (next_p) {
				proc_rele(next_p);
			}
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
			p->p_memstat_state |= P_MEMSTAT_ERROR;
			*errors += 1;
			p = NULL;
		}

		/*
		 * Failure - restart the search at the beginning of
		 * the band we were already traversing.
		 *
		 * We might have raced with "p" exiting on another core, resulting in no
		 * ref on "p".  Or, we may have failed to kill "p".
		 *
		 * Either way, we fall thru to here, leaving the proc in the
		 * P_MEMSTAT_TERMINATED or P_MEMSTAT_ERROR state.
		 *
		 * And, we hold the the proc_list_lock at this point.
		 */

		next_p = memorystatus_get_first_proc_locked(&priority_band, TRUE);
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	/* Clear snapshot if freshly captured and no target was found */
	if (new_snapshot && (kill_count == 0)) {
		proc_list_lock();
		memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
		proc_list_unlock();
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, 0, kill_count, *memory_reclaimed);

	return kill_count > 0;
}

static boolean_t
memorystatus_kill_hiwat_proc(uint32_t *errors, boolean_t *purged, uint64_t *memory_reclaimed)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	bool new_snapshot = false, killed = false, freed_mem = false;
	unsigned int i = 0;
	uint32_t aPid_ep;
	os_reason_t jetsam_reason = OS_REASON_NULL;
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_START,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES);

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_HIGHWATER);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus_kill_hiwat_proc: failed to allocate exit reason\n");
	}

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		uint64_t footprint_in_bytes = 0;
		uint64_t memlimit_in_bytes  = 0;
		boolean_t skip = 0;

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);

		aPid = proc_getpid(p);
		aPid_ep = p->p_memstat_effectivepriority;

		if (p->p_memstat_state  & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP)) {
			continue;
		}

		/* skip if no limit set */
		if (p->p_memstat_memlimit <= 0) {
			continue;
		}

		footprint_in_bytes = get_task_phys_footprint(proc_task(p));
		memlimit_in_bytes  = (((uint64_t)p->p_memstat_memlimit) * 1024ULL * 1024ULL);   /* convert MB to bytes */
		skip = (footprint_in_bytes <= memlimit_in_bytes);

#if CONFIG_FREEZE
		if (!skip) {
			if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
				skip = TRUE;
			} else {
				skip = FALSE;
			}
		}
#endif

		if (skip) {
			continue;
		} else {
			if (memorystatus_jetsam_snapshot_count == 0) {
				memorystatus_init_jetsam_snapshot_locked(NULL, 0);
				new_snapshot = true;
			}

			if (proc_ref(p, true) == p) {
				/*
				 * Mark as terminated so that if exit1() indicates success, but the process (for example)
				 * is blocked in task_exception_notify(), it'll be skipped if encountered again - see
				 * <rdar://problem/13553476>. This is cheaper than examining P_LEXIT, which requires the
				 * acquisition of the proc lock.
				 */
				p->p_memstat_state |= P_MEMSTAT_TERMINATED;

				proc_list_unlock();
			} else {
				/*
				 * We need to restart the search again because
				 * proc_ref _can_ drop the proc_list lock
				 * and we could have lost our stored next_p via
				 * an exit() on another core.
				 */
				i = 0;
				next_p = memorystatus_get_first_proc_locked(&i, TRUE);
				continue;
			}

			footprint_in_bytes = 0;
			freed_mem = memorystatus_kill_proc(p, kMemorystatusKilledHiwat, jetsam_reason, &killed, &footprint_in_bytes); /* purged and/or killed 'p' */

			/* Success? */
			if (freed_mem) {
				if (!killed) {
					/* purged 'p'..don't reset HWM candidate count */
					*purged = TRUE;

					proc_list_lock();
					p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
					proc_list_unlock();
				} else {
					*memory_reclaimed = footprint_in_bytes;
				}
				proc_rele(p);
				goto exit;
			}
			/*
			 * Failure - first unwind the state,
			 * then fall through to restart the search.
			 */
			proc_list_lock();
			proc_rele(p);
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
			p->p_memstat_state |= P_MEMSTAT_ERROR;
			*errors += 1;

			i = 0;
			next_p = memorystatus_get_first_proc_locked(&i, TRUE);
		}
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	if (!killed) {
		*memory_reclaimed = 0;

		/* Clear snapshot if freshly captured and no target was found */
		if (new_snapshot) {
			proc_list_lock();
			memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
			proc_list_unlock();
		}
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM_HIWAT) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, killed ? aPid : 0, killed, *memory_reclaimed, 0);

	return killed;
}

/*
 * Jetsam a process pinned in the elevated band.
 *
 * Return:  true -- a pinned process was jetsammed
 *	    false -- no pinned process was jetsammed
 */
boolean_t
memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, unsigned int band, int aggr_count, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid = 0;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	uint32_t aPid_ep;
	uint64_t killtime = 0;
	uint64_t time_in_priority_band_secs = 0;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;
	uint64_t footprint_of_killed_proc = 0;


	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_START,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES);

#if CONFIG_FREEZE
	boolean_t consider_frozen_only = FALSE;

	if (band == (unsigned int) memorystatus_freeze_jetsam_band) {
		consider_frozen_only = TRUE;
	}
#endif /* CONFIG_FREEZE */

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	while (next_p) {
		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&band, p, FALSE);

		aPid = proc_getpid(p);
		aPid_ep = p->p_memstat_effectivepriority;

		/*
		 * Only pick a process pinned in this elevated band
		 */
		if (!_memstat_proc_is_elevated(p)) {
			continue;
		}

		if (p->p_memstat_state  & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP)) {
			continue;
		}

#if CONFIG_FREEZE
		if (consider_frozen_only && !_memstat_proc_is_frozen(p)) {
			continue;
		}

		if (p->p_memstat_state & P_MEMSTAT_LOCKED) {
			continue;
		}
#endif /* CONFIG_FREEZE */

#if DEVELOPMENT || DEBUG
		memorystatus_log_info(
			"jetsam: elevated%d process pid %d [%s] - memorystatus_available_pages: %d\n",
			aggr_count, aPid, (*p->p_name ? p->p_name : "unknown"), MEMORYSTATUS_LOG_AVAILABLE_PAGES);
#endif /* DEVELOPMENT || DEBUG */

		if (memorystatus_jetsam_snapshot_count == 0) {
			memorystatus_init_jetsam_snapshot_locked(NULL, 0);
			new_snapshot = TRUE;
		}

		p->p_memstat_state |= P_MEMSTAT_TERMINATED;

		killtime = mach_absolute_time();
		absolutetime_to_microtime(killtime, &tv_sec, &tv_usec);
		tv_msec = tv_usec / 1000;

		memorystatus_update_jetsam_snapshot_entry_locked(p, cause, killtime);

		if (proc_ref(p, true) == p) {
			proc_list_unlock();

			/*
			 * memorystatus_do_kill drops a reference, so take another one so we can
			 * continue to use this exit reason even after memorystatus_do_kill()
			 * returns
			 */
			os_reason_ref(jetsam_reason);
			killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

			absolutetime_to_nanoseconds(killtime - p->p_memstat_prio_start, &time_in_priority_band_secs);
			time_in_priority_band_secs /= NSEC_PER_SEC;
			memorystatus_log("%lu.%03d memorystatus: killing_top_process_elevated%d pid %d [%s] (%s %d %llus rf:%s) %lluKB - memorystatus_available_pages: %llu\n",
			    (unsigned long)tv_sec, tv_msec,
			    aggr_count,
			    aPid, ((p && *p->p_name) ? p->p_name : "unknown"),
			    memorystatus_kill_cause_name[cause], aPid_ep,
			    time_in_priority_band_secs, _memstat_relaunch_flags_description(p->p_memstat_relaunch_flags),
			    footprint_of_killed_proc >> 10, (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);

			/* Success? */
			if (killed) {
				*memory_reclaimed = footprint_of_killed_proc;
				proc_rele(p);
				kill_count++;
				goto exit;
			}

			/*
			 * Failure - first unwind the state,
			 * then fall through to restart the search.
			 */
			proc_list_lock();
			proc_rele(p);
			p->p_memstat_state &= ~P_MEMSTAT_TERMINATED;
			p->p_memstat_state |= P_MEMSTAT_ERROR;
			*errors += 1;
		}

		/*
		 * Failure - restart the search.
		 *
		 * We might have raced with "p" exiting on another core, resulting in no
		 * ref on "p".  Or, we may have failed to kill "p".
		 *
		 * Either way, we fall thru to here, leaving the proc in the
		 * P_MEMSTAT_TERMINATED state or P_MEMSTAT_ERROR state.
		 *
		 * And, we hold the the proc_list_lock at this point.
		 */

		next_p = memorystatus_get_first_proc_locked(&band, FALSE);
	}

	proc_list_unlock();

exit:
	os_reason_free(jetsam_reason);

	if (kill_count == 0) {
		*memory_reclaimed = 0;

		/* Clear snapshot if freshly captured and no target was found */
		if (new_snapshot) {
			proc_list_lock();
			memorystatus_jetsam_snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
			proc_list_unlock();
		}
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, killed ? aPid : 0, kill_count, *memory_reclaimed);

	return killed;
}

bool
memorystatus_kill_on_VM_compressor_space_shortage(bool async)
{
	if (async) {
		os_atomic_store(&memorystatus_compressor_space_shortage, true, release);
		memorystatus_thread_wake();
		return true;
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_VMCOMPRESSOR_SPACE_SHORTAGE);
		if (jetsam_reason == OS_REASON_NULL) {
			memorystatus_log_error("memorystatus_kill_on_VM_compressor_space_shortage -- sync: failed to allocate jetsam reason\n");
		}

		return memorystatus_kill_process_sync(-1, kMemorystatusKilledVMCompressorSpaceShortage, jetsam_reason);
	}
}

#if CONFIG_JETSAM

void
memorystatus_kill_on_vps_starvation(void)
{
	os_atomic_store(&memorystatus_pageout_starved, true, release);
	memorystatus_thread_wake();
}

bool
memorystatus_kill_on_vnode_exhaustion(void)
{
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_VNODE);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus_kill_on_vnode_limit: failed to allocate jetsam reason\n");
	}

	return memorystatus_kill_process_sync(-1, kMemorystatusKilledVnodes, jetsam_reason);
}

bool
memorystatus_kill_on_sustained_pressure()
{
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_SUSTAINED_PRESSURE);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus_kill_on_FC_thrashing -- sync: failed to allocate jetsam reason\n");
	}

	return memorystatus_kill_process_sync(-1, kMemorystatusKilledSustainedPressure, jetsam_reason);
}

bool
memstat_kill_with_jetsam_reason_sync(pid_t pid, os_reason_t jetsam_reason)
{
	uint32_t kill_cause = jetsam_reason->osr_code <= JETSAM_REASON_MEMORYSTATUS_MAX ?
	    (uint32_t) jetsam_reason->osr_code : JETSAM_REASON_INVALID;
	return memorystatus_kill_process_sync(pid, kill_cause, jetsam_reason);
}

#endif /* CONFIG_JETSAM */

bool
memorystatus_kill_on_zone_map_exhaustion(pid_t pid)
{
	if (pid == -1) {
		os_atomic_store(&memorystatus_zone_map_is_exhausted, true, release);
		memorystatus_thread_wake();
		return true;
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_ZONE_MAP_EXHAUSTION);
		if (jetsam_reason == OS_REASON_NULL) {
			memorystatus_log_error("memorystatus_kill_on_zone_map_exhaustion: failed to allocate jetsam reason\n");
		}
		return memorystatus_kill_process_sync(pid, kMemorystatusKilledZoneMapExhaustion, jetsam_reason);
	}
}

void
memorystatus_on_pageout_scan_end(void)
{
	/* No-op */
}

static size_t
memorystatus_priority_list_size(pid_t pid, size_t entry_size)
{
	assert(
		(entry_size == sizeof(memorystatus_priority_entry_t)) ||
		(entry_size == sizeof(memorystatus_priority_entry_v2_t)));
	uint32_t list_count = (pid == 0) ? memorystatus_list_count : 1;
	return entry_size * list_count;
}

/* Return both allocated and actual size, since there's a race between allocation and list compilation */
static int
memorystatus_get_priority_list(memorystatus_priority_entry_v2_t **list_ptr, size_t *buffer_size, size_t *list_size, size_t entry_size)
{
	memorystatus_priority_entry_v2_t *entry;
	proc_t p;
	uint32_t i = 0;

	*list_size = memorystatus_priority_list_size(0, entry_size);

	/* Otherwise, validate the size of the buffer */
	if (*buffer_size < *list_size) {
		return EINVAL;
	}

	*list_ptr = kalloc_data(*list_size, Z_WAITOK | Z_ZERO);
	if (!*list_ptr) {
		return ENOMEM;
	}

	*buffer_size = *list_size;
	*list_size = 0;

	entry = *list_ptr;

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (p && (*list_size < *buffer_size)) {
		entry->pid = proc_getpid(p);
		entry->priority = p->p_memstat_effectivepriority;
		entry->user_data = p->p_memstat_userdata;

		if (p->p_memstat_memlimit <= 0) {
			task_get_phys_footprint_limit(proc_task(p), &entry->limit);
		} else {
			entry->limit = p->p_memstat_memlimit;
		}

		entry->state = _memstat_build_state(p);

		if (entry_size == sizeof(memorystatus_priority_entry_t)) {
			entry = (memorystatus_priority_entry_v2_t *) (((memorystatus_priority_entry_t *)entry) + 1);
		} else {
			/* Only add v2 entries if we're not using the legacy version of this call */
			entry->priority_start_mtime = p->p_memstat_prio_start;

			entry++;
		}

		*list_size += entry_size;
		p = memorystatus_get_next_proc_locked(&i, p, TRUE);
	}

	proc_list_unlock();

	memorystatus_log_debug("memorystatus_get_priority_list: returning %lu for size\n", (unsigned long)*list_size);

	return 0;
}

static int
memorystatus_get_priority_pid(pid_t pid, user_addr_t buffer, size_t buffer_size)
{
	int error = 0;
	bool zombref = false;
	memorystatus_priority_entry_v2_t mp_entry;
	kern_return_t ret;
	boolean_t size_valid =
	    (buffer_size == sizeof(memorystatus_priority_entry_v2_t)) ||
	    (buffer_size == sizeof(memorystatus_priority_entry_t));

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || !size_valid) {
		return EINVAL;
	}

	proc_list_lock();
	proc_t p = proc_find_locked(pid);
	if (!p) {
		zombref = true;
		p = proc_find_zombref_locked(pid);
		if (!p) {
			proc_list_unlock();
			return ESRCH;
		}
	}

	memset(&mp_entry, 0, sizeof(memorystatus_priority_entry_v2_t));

	mp_entry.pid = proc_getpid(p);
	mp_entry.priority = p->p_memstat_effectivepriority;
	mp_entry.user_data = p->p_memstat_userdata;
	if (p->p_memstat_memlimit <= 0 && !zombref) {
		task_t task = proc_task(p);
		assert(task);
		ret = task_get_phys_footprint_limit(task, &mp_entry.limit);
		if (ret != KERN_SUCCESS) {
			error = mach_to_bsd_errno(ret);
			proc_list_unlock();
			goto done;
		}
	} else {
		mp_entry.limit = p->p_memstat_memlimit;
	}

	mp_entry.state = _memstat_build_state(p);
	mp_entry.priority_start_mtime = p->p_memstat_prio_start;
	proc_list_unlock();

	error = copyout(&mp_entry, buffer, buffer_size);

done:
	if (zombref) {
		proc_drop_zombref(p);
	} else {
		proc_rele(p);
	}

	return error;
}

static int
memorystatus_cmd_get_priority_list(pid_t pid, user_addr_t buffer, size_t buffer_size, int32_t *retval, size_t entry_size)
{
	int error = 0;
	boolean_t size_only;
	size_t list_size;

	static_assert(sizeof(memorystatus_priority_entry_v2_t) == 128);
	assert(
		(entry_size == sizeof(memorystatus_priority_entry_t)) ||
		(entry_size == sizeof(memorystatus_priority_entry_v2_t)));

	/*
	 * When a non-zero pid is provided, the 'list' has only one entry.
	 */

	size_only = ((buffer == USER_ADDR_NULL) ? TRUE: FALSE);

	if (pid != 0) {
		/* One PID */
		list_size = entry_size;
		if (!size_only) {
			error = memorystatus_get_priority_pid(pid, buffer, buffer_size);
		}
	} else if (size_only) {
		/* List size query */
		list_size = memorystatus_priority_list_size(0, entry_size);
	} else {
		/* List */
		memorystatus_priority_entry_v2_t *list = NULL;
		error = memorystatus_get_priority_list(&list, &buffer_size, &list_size, entry_size);
		if (error == 0) {
			error = copyout(list, buffer, list_size);
			kfree_data(list, buffer_size);
		}
	}

	if (error == 0) {
		assert(list_size <= INT32_MAX);
		*retval = (int32_t) list_size;
	}

	return error;
}

static void
memorystatus_clear_errors(void)
{
	proc_t p;
	unsigned int i = 0;

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_CLEAR_ERRORS) | DBG_FUNC_START);

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (p) {
		if (p->p_memstat_state & P_MEMSTAT_ERROR) {
			p->p_memstat_state &= ~P_MEMSTAT_ERROR;
		}
		p = memorystatus_get_next_proc_locked(&i, p, TRUE);
	}

	proc_list_unlock();

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_CLEAR_ERRORS) | DBG_FUNC_END);
}

void
memorystatus_fast_jetsam_override(bool enable_override)
{
#if CONFIG_JETSAM
	fast_jetsam_enabled = !enable_override;
	if (!fast_jetsam_enabled) {
		/* Disable any pre-configured policies */
		os_atomic_store(&memstat_policy_config, kPolicyDefault, relaxed);
		memorystatus_thread_pool_default();
		_memstat_consider_waking_jetsam_thread();
	}
#else /* CONFIG_JETSAM */
	(void)enable_override;
#endif /* CONFIG_JETSAM */
}

/*
 * Get the at_boot snapshot
 */
static int
memorystatus_get_at_boot_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
	size_t input_size = *snapshot_size;

	/*
	 * The at_boot snapshot has no entry list.
	 */
	*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t);

	if (size_only) {
		return 0;
	}

	/*
	 * Validate the size of the snapshot buffer
	 */
	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	/*
	 * Update the notification_time only
	 */
	memorystatus_at_boot_snapshot.notification_time = mach_absolute_time();
	*snapshot = &memorystatus_at_boot_snapshot;

	memorystatus_log_debug(
		"memorystatus_get_at_boot_snapshot: returned inputsize (%ld), snapshot_size(%ld), listcount(%d)\n",
		(long)input_size, (long)*snapshot_size, 0);
	return 0;
}

#if CONFIG_FREEZE
static int
memorystatus_get_jetsam_snapshot_freezer(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
	size_t input_size = *snapshot_size;

	if (memorystatus_jetsam_snapshot_freezer->entry_count > 0) {
		*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + (sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_freezer->entry_count));
	} else {
		*snapshot_size = 0;
	}
	assert(*snapshot_size <= memorystatus_jetsam_snapshot_freezer_size);

	if (size_only) {
		return 0;
	}

	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	*snapshot = memorystatus_jetsam_snapshot_freezer;

	memorystatus_log_debug(
		"memorystatus_get_jetsam_snapshot_freezer: returned inputsize (%ld), snapshot_size(%ld), listcount(%ld)\n",
		(long)input_size, (long)*snapshot_size, (long)memorystatus_jetsam_snapshot_freezer->entry_count);

	return 0;
}
#endif /* CONFIG_FREEZE */

static int
memorystatus_get_on_demand_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
	size_t input_size = *snapshot_size;
	uint32_t ods_list_count = memorystatus_list_count + memorystatus_artificial_snapshot_entry_count;
	memorystatus_jetsam_snapshot_t *ods = NULL;     /* The on_demand snapshot buffer */

	*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + (sizeof(memorystatus_jetsam_snapshot_entry_t) * (ods_list_count));

	if (size_only) {
		return 0;
	}

	/*
	 * Validate the size of the snapshot buffer.
	 * This is inherently racey. May want to revisit
	 * this error condition and trim the output when
	 * it doesn't fit.
	 */
	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	/*
	 * Allocate and initialize a snapshot buffer.
	 */
	ods = kalloc_data(*snapshot_size, Z_WAITOK | Z_ZERO);
	if (!ods) {
		return ENOMEM;
	}

	proc_list_lock();
	memorystatus_init_jetsam_snapshot_locked(ods, ods_list_count);
	proc_list_unlock();

	/*
	 * Return the kernel allocated, on_demand buffer.
	 * The caller of this routine will copy the data out
	 * to user space and then free the kernel allocated
	 * buffer.
	 */
	*snapshot = ods;

	memorystatus_log_debug(
		"memorystatus_get_on_demand_snapshot: returned inputsize (%ld), snapshot_size(%ld), listcount(%ld)\n",
		(long)input_size, (long)*snapshot_size, (long)ods_list_count);

	return 0;
}

static int
memorystatus_get_jetsam_snapshot(memorystatus_jetsam_snapshot_t **snapshot, size_t *snapshot_size, boolean_t size_only)
{
	size_t input_size = *snapshot_size;

	if (memorystatus_jetsam_snapshot_count > 0) {
		*snapshot_size = sizeof(memorystatus_jetsam_snapshot_t) + (sizeof(memorystatus_jetsam_snapshot_entry_t) * (memorystatus_jetsam_snapshot_count));
	} else {
		*snapshot_size = 0;
	}

	if (size_only) {
		return 0;
	}

	if (input_size < *snapshot_size) {
		return EINVAL;
	}

	*snapshot = memorystatus_jetsam_snapshot;

	memorystatus_log_debug(
		"memorystatus_get_jetsam_snapshot: returned inputsize (%ld), snapshot_size(%ld), listcount(%ld)\n",
		(long)input_size, (long)*snapshot_size, (long)memorystatus_jetsam_snapshot_count);

	return 0;
}

#if JETSAM_ZPRINT_SNAPSHOT
/*
 * Utility function to handle copyout of jetsam zprint snapshot data
 */
static int
memorystatus_cmd_get_data_buffer(
	user_addr_t  buffer,
	size_t       buffer_size,
	int32_t      *retval,
	size_t       data_size,
	void         *data)
{
	boolean_t size_only = (buffer == USER_ADDR_NULL);
	int error;

	/* Nothing to return if there's no data yet, instruct the caller to try again later. */
	if (data == NULL) {
		*retval = -1;
		return EAGAIN;
	}

	/* Handle just a size request */
	if (size_only) {
		*retval = (int32_t)data_size;
		return 0;
	}

	/* buffer needs to be large enough */
	if (buffer_size < data_size) {
		*retval = -1;
		return EINVAL;
	}

	error = copyout(data, buffer, data_size);
	if (error == 0) {
		*retval = (int32_t)data_size;
	} else {
		*retval = -1;
	}

	return error;
}
#endif

static int
memorystatus_cmd_get_jetsam_snapshot(int32_t flags, user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	int error = EINVAL;
	boolean_t size_only;
	boolean_t is_default_snapshot = FALSE;
	boolean_t is_on_demand_snapshot = FALSE;
	boolean_t is_at_boot_snapshot = FALSE;
#if CONFIG_FREEZE
	bool is_freezer_snapshot = false;
#endif /* CONFIG_FREEZE */
	memorystatus_jetsam_snapshot_t *snapshot;

	size_only = ((buffer == USER_ADDR_NULL) ? TRUE : FALSE);

	if (flags == 0) {
		/* Default */
		is_default_snapshot = TRUE;
		error = memorystatus_get_jetsam_snapshot(&snapshot, &buffer_size, size_only);
	} else {
		if (flags & ~(MEMORYSTATUS_SNAPSHOT_ON_DEMAND | MEMORYSTATUS_SNAPSHOT_AT_BOOT | MEMORYSTATUS_FLAGS_SNAPSHOT_FREEZER)) {
			/*
			 * Unsupported bit set in flag.
			 */
			return EINVAL;
		}

		if (flags & (flags - 0x1)) {
			/*
			 * Can't have multiple flags set at the same time.
			 */
			return EINVAL;
		}

		if (flags & MEMORYSTATUS_SNAPSHOT_ON_DEMAND) {
			is_on_demand_snapshot = TRUE;
			/*
			 * When not requesting the size only, the following call will allocate
			 * an on_demand snapshot buffer, which is freed below.
			 */
			error = memorystatus_get_on_demand_snapshot(&snapshot, &buffer_size, size_only);
		} else if (flags & MEMORYSTATUS_SNAPSHOT_AT_BOOT) {
			is_at_boot_snapshot = TRUE;
			error = memorystatus_get_at_boot_snapshot(&snapshot, &buffer_size, size_only);
#if CONFIG_FREEZE
		} else if (flags & MEMORYSTATUS_FLAGS_SNAPSHOT_FREEZER) {
			is_freezer_snapshot = true;
			error = memorystatus_get_jetsam_snapshot_freezer(&snapshot, &buffer_size, size_only);
#endif /* CONFIG_FREEZE */
		} else {
			/*
			 * Invalid flag setting.
			 */
			return EINVAL;
		}
	}

	if (error) {
		goto out;
	}

	/*
	 * Copy the data out to user space and clear the snapshot buffer.
	 * If working with the jetsam snapshot,
	 *	clearing the buffer means, reset the count.
	 * If working with an on_demand snapshot
	 *	clearing the buffer means, free it.
	 * If working with the at_boot snapshot
	 *	there is nothing to clear or update.
	 * If working with a copy of the snapshot
	 *	there is nothing to clear or update.
	 * If working with the freezer snapshot
	 *	clearing the buffer means, reset the count.
	 */
	if (!size_only) {
		if ((error = copyout(snapshot, buffer, buffer_size)) == 0) {
#if CONFIG_FREEZE
			if (is_default_snapshot || is_freezer_snapshot) {
#else
			if (is_default_snapshot) {
#endif /* CONFIG_FREEZE */
				/*
				 * The jetsam snapshot is never freed, its count is simply reset.
				 * However, we make a copy for any parties that might be interested
				 * in the previous fully populated snapshot.
				 */
				proc_list_lock();
#if DEVELOPMENT || DEBUG
				if (memorystatus_testing_pid != 0 && memorystatus_testing_pid != proc_getpid(current_proc())) {
					/* Snapshot is currently owned by someone else. Don't consume it. */
					proc_list_unlock();
					goto out;
				}
#endif /* (DEVELOPMENT || DEBUG)*/
				if (is_default_snapshot) {
					snapshot->entry_count = memorystatus_jetsam_snapshot_count = 0;
					memorystatus_jetsam_snapshot_last_timestamp = 0;
				}
#if CONFIG_FREEZE
				else if (is_freezer_snapshot) {
					memorystatus_jetsam_snapshot_freezer->entry_count = 0;
				}
#endif /* CONFIG_FREEZE */
				proc_list_unlock();
			}
		}

		if (is_on_demand_snapshot) {
			/*
			 * The on_demand snapshot is always freed,
			 * even if the copyout failed.
			 */
			kfree_data(snapshot, buffer_size);
		}
	}

out:
	if (error == 0) {
		assert(buffer_size <= INT32_MAX);
		*retval = (int32_t) buffer_size;
	}
	return error;
}

#if DEVELOPMENT || DEBUG
static int
memorystatus_cmd_set_testing_pid(int32_t flags)
{
	int error = EINVAL;
	proc_t caller = current_proc();
	assert(caller != kernproc);
	proc_list_lock();
	if (flags & MEMORYSTATUS_FLAGS_SET_TESTING_PID) {
		if (memorystatus_testing_pid == 0) {
			memorystatus_testing_pid = proc_getpid(caller);
			error = 0;
		} else if (memorystatus_testing_pid == proc_getpid(caller)) {
			error = 0;
		} else {
			/* We don't allow ownership to be taken from another proc. */
			error = EBUSY;
		}
	} else if (flags & MEMORYSTATUS_FLAGS_UNSET_TESTING_PID) {
		if (memorystatus_testing_pid == proc_getpid(caller)) {
			memorystatus_testing_pid = 0;
			error = 0;
		} else if (memorystatus_testing_pid != 0) {
			/* We don't allow ownership to be taken from another proc. */
			error = EPERM;
		}
	} else if (flags & MEMORYSTATUS_FLAGS_SET_IMP_TESTING_PID) {
		caller->p_memstat_state |= P_MEMSTAT_TEST_IMP_ASSERTION;
		error = 0;
	}
	proc_list_unlock();

	return error;
}
#endif /* DEVELOPMENT || DEBUG */

/*
 *      Routine:	memorystatus_cmd_grp_set_priorities
 *	Purpose:	Update priorities for a group of processes.
 *
 *	[priority]
 *		Move each process out of its effective priority
 *		band and into a new priority band.
 *		Maintains relative order from lowest to highest priority.
 *		In single band, maintains relative order from head to tail.
 *
 *		eg: before	[effectivepriority | pid]
 *				[18 | p101              ]
 *				[17 | p55, p67, p19     ]
 *				[12 | p103 p10          ]
 *				[ 7 | p25               ]
 *			        [ 0 | p71, p82,         ]
 *
 *		after	[ new band | pid]
 *			[ xxx | p71, p82, p25, p103, p10, p55, p67, p19, p101]
 *
 *	Returns:  0 on success, else non-zero.
 *
 *	Caveat:   We know there is a race window regarding recycled pids.
 *		  A process could be killed before the kernel can act on it here.
 *		  If a pid cannot be found in any of the jetsam priority bands,
 *		  then we simply ignore it.  No harm.
 *		  But, if the pid has been recycled then it could be an issue.
 *		  In that scenario, we might move an unsuspecting process to the new
 *		  priority band. It's not clear how the kernel can safeguard
 *		  against this, but it would be an extremely rare case anyway.
 *		  The caller of this api might avoid such race conditions by
 *		  ensuring that the processes passed in the pid list are suspended.
 */


static int
memorystatus_cmd_grp_set_priorities(user_addr_t buffer, size_t buffer_size)
{
	/*
	 * We only handle setting priority
	 * per process
	 */
	int error = 0;
	memorystatus_properties_entry_v1_t *entries = NULL;
	size_t entry_count = 0;

	/* This will be the ordered proc list */
	typedef struct memorystatus_internal_properties {
		proc_t proc;
		int32_t priority;
	} memorystatus_internal_properties_t;

	memorystatus_internal_properties_t *table = NULL;
	uint32_t table_count = 0;

	size_t i = 0;
	uint32_t bucket_index = 0;
	int32_t new_priority;

	proc_t p;

	/* Verify inputs */
	if ((buffer == USER_ADDR_NULL) || (buffer_size == 0)) {
		error = EINVAL;
		goto out;
	}

	entry_count = (buffer_size / sizeof(memorystatus_properties_entry_v1_t));
	if (entry_count == 0) {
		/* buffer size was not large enough for a single entry */
		error = EINVAL;
		goto out;
	}

	if ((entries = kalloc_data(buffer_size, Z_WAITOK)) == NULL) {
		error = ENOMEM;
		goto out;
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_START, MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY, entry_count);

	if ((error = copyin(buffer, entries, buffer_size)) != 0) {
		goto out;
	}

	/* Verify sanity of input priorities */
	if (entries[0].version == MEMORYSTATUS_MPE_VERSION_1) {
		if ((buffer_size % MEMORYSTATUS_MPE_VERSION_1_SIZE) != 0) {
			error = EINVAL;
			goto out;
		}
	} else {
		error = EINVAL;
		goto out;
	}

	for (i = 0; i < entry_count; i++) {
		if (entries[i].priority == -1) {
			/* Use as shorthand for default priority */
			entries[i].priority = JETSAM_PRIORITY_DEFAULT;
		} else if (entries[i].priority > JETSAM_PRIORITY_IDLE && entries[i].priority <= applications_aging_band) {
			/*
			 * Everything between idle and the aging bands are reserved for internal use.
			 * if requested, adjust to JETSAM_PRIORITY_IDLE.
			 * Entitled processes (just munch) can use a subset of this range for testing.
			 */
			if (entries[i].priority > JETSAM_PRIORITY_ENTITLED_MAX ||
			    !current_task_can_use_entitled_range()) {
				entries[i].priority = JETSAM_PRIORITY_IDLE;
			}
		} else if (entries[i].priority == JETSAM_PRIORITY_IDLE_HEAD) {
			/* JETSAM_PRIORITY_IDLE_HEAD inserts at the head of the idle
			 * queue */
			/* Deal with this later */
		} else if ((entries[i].priority < 0) || (entries[i].priority >= MEMSTAT_BUCKET_COUNT)) {
			/* Sanity check */
			error = EINVAL;
			goto out;
		}
	}

	table = kalloc_type(memorystatus_internal_properties_t, entry_count,
	    Z_WAITOK | Z_ZERO);
	if (table == NULL) {
		error = ENOMEM;
		goto out;
	}


	/*
	 * For each jetsam bucket entry, spin through the input property list.
	 * When a matching pid is found, populate an adjacent table with the
	 * appropriate proc pointer and new property values.
	 * This traversal automatically preserves order from lowest
	 * to highest priority.
	 */

	bucket_index = 0;

	proc_list_lock();

	/* Create the ordered table */
	p = memorystatus_get_first_proc_locked(&bucket_index, TRUE);
	while (p && (table_count < entry_count)) {
		for (i = 0; i < entry_count; i++) {
			if (proc_getpid(p) == entries[i].pid) {
				/* Build the table data  */
				table[table_count].proc = p;
				table[table_count].priority = entries[i].priority;
				table_count++;
				break;
			}
		}
		p = memorystatus_get_next_proc_locked(&bucket_index, p, TRUE);
	}

	/* We now have ordered list of procs ready to move */
	for (i = 0; i < table_count; i++) {
		p = table[i].proc;
		assert(p != NULL);
		memstat_priority_options_t priority_options = MEMSTAT_PRIORITY_OPTIONS_NONE;

		/* Allow head inserts -- but relative order is now  */
		if (table[i].priority == JETSAM_PRIORITY_IDLE_HEAD) {
			new_priority = JETSAM_PRIORITY_IDLE;
			priority_options |= MEMSTAT_PRIORITY_INSERT_HEAD;
		} else {
			new_priority = table[i].priority;
		}

		/* Not allowed */
		if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
			continue;
		}

		memstat_update_priority_locked(p, new_priority, priority_options);
	}

	proc_list_unlock();

	/*
	 * if (table_count != entry_count)
	 * then some pids were not found in a jetsam band.
	 * harmless but interesting...
	 */
out:
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_END, MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY, entry_count, table_count);

	kfree_data(entries, buffer_size);
	kfree_type(memorystatus_internal_properties_t, entry_count, table);

	return error;
}

memorystatus_internal_probabilities_t *memorystatus_global_probabilities_table = NULL;
size_t memorystatus_global_probabilities_size = 0;

static int
memorystatus_cmd_grp_set_probabilities(user_addr_t buffer, size_t buffer_size)
{
	int error = 0;
	memorystatus_properties_entry_v1_t *entries = NULL;
	size_t entry_count = 0, i = 0;
	memorystatus_internal_probabilities_t *tmp_table_new = NULL, *tmp_table_old = NULL;
	size_t tmp_table_new_size = 0, tmp_table_old_size = 0;
#if DEVELOPMENT || DEBUG
	if (memorystatus_testing_pid != 0 && memorystatus_testing_pid != proc_getpid(current_proc())) {
		/* probabilites are currently owned by someone else. Don't change them. */
		error = EPERM;
		goto out;
	}
#endif /* (DEVELOPMENT || DEBUG)*/

	/* Verify inputs */
	if ((buffer == USER_ADDR_NULL) || (buffer_size == 0)) {
		error = EINVAL;
		goto out;
	}

	entry_count = (buffer_size / sizeof(memorystatus_properties_entry_v1_t));
	if (entry_count == 0) {
		error = EINVAL;
		goto out;
	}

	if ((entries = kalloc_data(buffer_size, Z_WAITOK)) == NULL) {
		error = ENOMEM;
		goto out;
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_START, MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY, entry_count);

	if ((error = copyin(buffer, entries, buffer_size)) != 0) {
		goto out;
	}

	if (entries[0].version == MEMORYSTATUS_MPE_VERSION_1) {
		if ((buffer_size % MEMORYSTATUS_MPE_VERSION_1_SIZE) != 0) {
			error = EINVAL;
			goto out;
		}
	} else {
		error = EINVAL;
		goto out;
	}

	/* Verify sanity of input priorities */
	for (i = 0; i < entry_count; i++) {
		/*
		 * 0 - low probability of use.
		 * 1 - high probability of use.
		 *
		 * Keeping this field an int (& not a bool) to allow
		 * us to experiment with different values/approaches
		 * later on.
		 */
		if (entries[i].use_probability > 1) {
			error = EINVAL;
			goto out;
		}
	}

	tmp_table_new_size = sizeof(memorystatus_internal_probabilities_t) * entry_count;

	if ((tmp_table_new = kalloc_data(tmp_table_new_size, Z_WAITOK | Z_ZERO)) == NULL) {
		error = ENOMEM;
		goto out;
	}

	proc_list_lock();

	if (memorystatus_global_probabilities_table) {
		tmp_table_old = memorystatus_global_probabilities_table;
		tmp_table_old_size = memorystatus_global_probabilities_size;
	}

	memorystatus_global_probabilities_table = tmp_table_new;
	memorystatus_global_probabilities_size = tmp_table_new_size;
	tmp_table_new = NULL;

	for (i = 0; i < entry_count; i++) {
		/* Build the table data  */
		strlcpy(memorystatus_global_probabilities_table[i].proc_name, entries[i].proc_name, MAXCOMLEN + 1);
		memorystatus_global_probabilities_table[i].use_probability = entries[i].use_probability;
	}

	proc_list_unlock();

out:
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_GRP_SET_PROP) | DBG_FUNC_END, MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY, entry_count, tmp_table_new_size);

	kfree_data(entries, buffer_size);
	kfree_data(tmp_table_old, tmp_table_old_size);

	return error;
}

static int
memorystatus_cmd_grp_set_properties(int32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;

	if ((flags & MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY) == MEMORYSTATUS_FLAGS_GRP_SET_PRIORITY) {
		error = memorystatus_cmd_grp_set_priorities(buffer, buffer_size);
	} else if ((flags & MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY) == MEMORYSTATUS_FLAGS_GRP_SET_PROBABILITY) {
		error = memorystatus_cmd_grp_set_probabilities(buffer, buffer_size);
#if CONFIG_FREEZE
	} else if ((flags & MEMORYSTATUS_FLAGS_GRP_SET_FREEZE_PRIORITY) == MEMORYSTATUS_FLAGS_GRP_SET_FREEZE_PRIORITY) {
		error = memorystatus_cmd_grp_set_freeze_list(buffer, buffer_size);
	} else if ((flags & MEMORYSTATUS_FLAGS_GRP_SET_DEMOTE_PRIORITY) == MEMORYSTATUS_FLAGS_GRP_SET_DEMOTE_PRIORITY) {
		error = memorystatus_cmd_grp_set_demote_list(buffer, buffer_size);
#endif /* CONFIG_FREEZE */
	} else {
		error = EINVAL;
	}

	return error;
}

/*
 * This routine is used to update a process's jetsam priority position and stored user_data.
 * It is not used for the setting of memory limits.
 *
 * Flags passed into this call are used to distinguish the motivation behind a jetsam priority
 * transition.  By default, the kernel updates the process's original requested priority when
 * no flag is passed.  But when the MEMORYSTATUS_SET_PRIORITY_ASSERTION flag is used, the kernel
 * updates the process's assertion driven priority.
 *
 * The assertion flag was introduced for use by the device's assertion mediator (eg: runningboardd).
 * When an assertion is controlling a process's jetsam priority, it may conflict with that process's
 * dirty/clean (active/inactive) jetsam state.  The kernel attempts to resolve a priority transition
 * conflict by reviewing the process state and then choosing the maximum jetsam band at play,
 * eg: requested priority versus assertion priority.
 */

static int
memorystatus_cmd_set_priority_properties(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;
	memorystatus_priority_properties_t mpp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_priority_properties_t))) {
		return EINVAL;
	}

	/* Validate flags */
	if (flags & ~(MEMORYSTATUS_SET_PRIORITY_ASSERTION)) {
		/*
		 * Unsupported bit set in flag.
		 */
		return EINVAL;
	}

	error = copyin(buffer, &mpp_entry, buffer_size);

	if (error == 0) {
		proc_t p;

		p = proc_find(pid);
		if (!p) {
			return ESRCH;
		}

		if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
			proc_rele(p);
			return EPERM;
		}

		if ((flags & MEMORYSTATUS_SET_PRIORITY_ASSERTION) &&
		    !(p->p_memstat_state & P_MEMSTAT_MANAGED)) {
			/*
			 * Assertion-
			 * processes.
			 */
			proc_rele(p);
			return EPERM;
		}

		memstat_priority_options_t options = MEMSTAT_PRIORITY_OPTIONS_NONE;
		if (flags & MEMORYSTATUS_SET_PRIORITY_ASSERTION) {
			options |= MEMSTAT_PRIORITY_IS_ASSERTION;
		}
		error = memorystatus_set_priority(p, mpp_entry.priority, mpp_entry.user_data,
		    options);
		proc_rele(p);
	}

	return error;
}

static int
memorystatus_cmd_set_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;
	memorystatus_memlimit_properties_t mmp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_memlimit_properties_t))) {
		return EINVAL;
	}

	error = copyin(buffer, &mmp_entry, buffer_size);

	if (error == 0) {
		error = memorystatus_set_memlimit_properties(pid, &mmp_entry);
	}

	return error;
}

#if DEBUG || DEVELOPMENT
static int
memorystatus_cmd_set_diag_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;
	memorystatus_diag_memlimit_properties_t mmp_entry;
	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_diag_memlimit_properties_t))) {
		proc_rele(p);
		return EINVAL;
	}

	error = copyin(buffer, &mmp_entry, buffer_size);

	if (error == 0) {
		proc_list_lock();
		error = memorystatus_set_diag_memlimit_properties_internal(p, &mmp_entry);
		proc_list_unlock();
	}
	proc_rele(p);
	return error;
}

static int
memorystatus_cmd_get_diag_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;
	memorystatus_diag_memlimit_properties_t mmp_entry;
	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_diag_memlimit_properties_t))) {
		proc_rele(p);
		return EINVAL;
	}
	proc_list_lock();
	error = memorystatus_get_diag_memlimit_properties_internal(p, &mmp_entry);
	proc_list_unlock();
	proc_rele(p);
	if (error == 0) {
		error = copyout(&mmp_entry, buffer, buffer_size);
	}


	return error;
}
#endif //DEBUG || DEVELOPMENT

static void
memorystatus_get_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t* p_entry)
{
	memset(p_entry, 0, sizeof(memorystatus_memlimit_properties_t));

	if (p->p_memstat_memlimit_active > 0) {
		p_entry->memlimit_active = p->p_memstat_memlimit_active;
	} else {
		task_convert_phys_footprint_limit(-1, &p_entry->memlimit_active);
	}

	if (_memstat_proc_active_memlimit_is_fatal(p)) {
		p_entry->memlimit_active_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	/*
	 * Get the inactive limit and attributes
	 */
	if (p->p_memstat_memlimit_inactive <= 0) {
		task_convert_phys_footprint_limit(-1, &p_entry->memlimit_inactive);
	} else {
		p_entry->memlimit_inactive = p->p_memstat_memlimit_inactive;
	}
	if (_memstat_proc_inactive_memlimit_is_fatal(p)) {
		p_entry->memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
}

/*
 * When getting the memlimit settings, we can't simply call task_get_phys_footprint_limit().
 * That gets the proc's cached memlimit and there is no guarantee that the active/inactive
 * limits will be the same in the no-limit case.  Instead we convert limits <= 0 using
 * task_convert_phys_footprint_limit(). It computes the same limit value that would be written
 * to the task's ledgers via task_set_phys_footprint_limit().
 */
static int
memorystatus_cmd_get_memlimit_properties(pid_t pid, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	memorystatus_memlimit_properties2_t mmp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) ||
	    ((buffer_size != sizeof(memorystatus_memlimit_properties_t)) &&
	    (buffer_size != sizeof(memorystatus_memlimit_properties2_t)))) {
		return EINVAL;
	}

	memset(&mmp_entry, 0, sizeof(memorystatus_memlimit_properties2_t));

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Get the active limit and attributes.
	 * No locks taken since we hold a reference to the proc.
	 */

	memorystatus_get_memlimit_properties_internal(p, &mmp_entry.v1);

#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	/*
	 * Get the limit increased via SPI
	 */
	mmp_entry.memlimit_increase = roundToNearestMB(p->p_memlimit_increase);
	mmp_entry.memlimit_increase_bytes = p->p_memlimit_increase;
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

	proc_rele(p);

	int error = copyout(&mmp_entry, buffer, buffer_size);

	return error;
}


/*
 * SPI for kbd - pr24956468
 * This is a very simple snapshot that calculates how much a
 * process's phys_footprint exceeds a specific memory limit.
 * Only the inactive memory limit is supported for now.
 * The delta is returned as bytes in excess or zero.
 */
static int
memorystatus_cmd_get_memlimit_excess_np(pid_t pid, uint32_t flags, user_addr_t buffer, size_t buffer_size, __unused int32_t *retval)
{
	int error = 0;
	uint64_t footprint_in_bytes = 0;
	uint64_t delta_in_bytes = 0;
	int32_t  memlimit_mb = 0;
	uint64_t memlimit_bytes = 0;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(uint64_t)) || (flags != 0)) {
		return EINVAL;
	}

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Get the inactive limit.
	 * No locks taken since we hold a reference to the proc.
	 */

	if (p->p_memstat_memlimit_inactive <= 0) {
		task_convert_phys_footprint_limit(-1, &memlimit_mb);
	} else {
		memlimit_mb = p->p_memstat_memlimit_inactive;
	}

	footprint_in_bytes = get_task_phys_footprint(proc_task(p));

	proc_rele(p);

	memlimit_bytes = memlimit_mb * 1024 * 1024;     /* MB to bytes */

	/*
	 * Computed delta always returns >= 0 bytes
	 */
	if (footprint_in_bytes > memlimit_bytes) {
		delta_in_bytes = footprint_in_bytes - memlimit_bytes;
	}

	error = copyout(&delta_in_bytes, buffer, sizeof(delta_in_bytes));

	return error;
}


static int
memorystatus_cmd_get_pressure_status(int32_t *retval)
{
	int error;

	/* Need privilege for check */
	error = priv_check_cred(kauth_cred_get(), PRIV_VM_PRESSURE, 0);
	if (error) {
		return error;
	}

	/* Inherently racy, so it's not worth taking a lock here */
	*retval = (kVMPressureNormal != memorystatus_vm_pressure_level) ? 1 : 0;

	return error;
}

int
memorystatus_get_pressure_status_kdp()
{
	return (kVMPressureNormal != memorystatus_vm_pressure_level) ? 1 : 0;
}

/*
 * Every process, including a P_MEMSTAT_INTERNAL process (currently only pid 1), is allowed to set a HWM.
 *
 * This call is inflexible -- it does not distinguish between active/inactive, fatal/non-fatal
 * So, with 2-level HWM preserving previous behavior will map as follows.
 *      - treat the limit passed in as both an active and inactive limit.
 *      - treat the is_fatal_limit flag as though it applies to both active and inactive limits.
 *
 * When invoked via MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK
 *      - the is_fatal_limit is FALSE, meaning the active and inactive limits are non-fatal/soft
 *      - so mapping is (active/non-fatal, inactive/non-fatal)
 *
 * When invoked via MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT
 *      - the is_fatal_limit is TRUE, meaning the process's active and inactive limits are fatal/hard
 *      - so mapping is (active/fatal, inactive/fatal)
 */

#if CONFIG_JETSAM
static int
memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit)
{
	int error = 0;
	memorystatus_memlimit_properties_t entry;

	entry.memlimit_active = high_water_mark;
	entry.memlimit_active_attr = 0;
	entry.memlimit_inactive = high_water_mark;
	entry.memlimit_inactive_attr = 0;

	if (is_fatal_limit == TRUE) {
		entry.memlimit_active_attr   |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
		entry.memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	error = memorystatus_set_memlimit_properties(pid, &entry);
	return error;
}

static int
memorystatus_cmd_mark_process_coalition_swappable(pid_t pid, __unused int32_t *retval)
{
	int error = 0;
	proc_t p = PROC_NULL;
	coalition_t coal = COALITION_NULL;

	if (!memorystatus_swap_all_apps) {
		/* Swap is not supported on this device. */
		return ENOTSUP;
	}
	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}
	coal = task_get_coalition((task_t) proc_task(p), COALITION_TYPE_JETSAM);
	if (coal && coalition_is_leader((task_t) proc_task(p), coal)) {
		coalition_mark_swappable(coal);
	} else {
		/* This SPI is only supported on coalition leaders. */
		error = EINVAL;
	}

	proc_rele(p);
	return error;
}

static int
memorystatus_cmd_get_process_coalition_is_swappable(pid_t pid, int32_t *retval)
{
	int error = 0;
	proc_t p = PROC_NULL;
	coalition_t coal = COALITION_NULL;

	if (!memorystatus_swap_all_apps) {
		/* Swap is not supported on this device. */
		return ENOTSUP;
	}
	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}
	coal = task_get_coalition((task_t) proc_task(p), COALITION_TYPE_JETSAM);
	if (coal) {
		*retval = coalition_is_swappable(coal);
	} else {
		error = EINVAL;
	}

	proc_rele(p);
	return error;
}

static int
memorystatus_cmd_convert_memlimit_mb(pid_t pid, int32_t limit, int32_t *retval)
{
	int error = 0;
	proc_t p;
	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}
	if (limit <= 0) {
		/*
		 * A limit of <= 0 implies that the task gets its default limit.
		 */
		limit = memorystatus_get_default_task_active_limit(p);
		if (limit <= 0) {
			/* Task uses system wide default limit */
			limit = max_task_footprint_mb ? max_task_footprint_mb : INT32_MAX;
		}
		*retval = limit;
	} else {
#if DEVELOPMENT || DEBUG
		/* add the current increase to it, for roots */
		limit += roundToNearestMB(p->p_memlimit_increase);
#endif /* DEVELOPMENT || DEBUG */
		*retval = limit;
	}

	proc_rele(p);
	return error;
}
#endif /* CONFIG_JETSAM */

#if DEBUG || DEVELOPMENT
static int
memorystatus_set_diag_memlimit_properties_internal(proc_t p, memorystatus_diag_memlimit_properties_t *p_entry)
{
	int error = 0;
	uint64_t old_limit = 0;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	/* Enforce the limit by writing to the ledgers */
	error = (task_set_diag_footprint_limit_internal(proc_task(p), p_entry->memlimit, &old_limit) == KERN_SUCCESS) ? KERN_SUCCESS : EINVAL;

	memorystatus_log_debug( "memorystatus_set_diag_memlimit_properties: new limit on pid %d (%lluMB old %lluMB)\n",
	    proc_getpid(p), (p_entry->memlimit > 0 ? p_entry->memlimit : -1), (old_limit)
	    );
	DTRACE_MEMORYSTATUS2(memorystatus_diag_memlimit_properties_t, proc_t, p, int32_t, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1));
	return error;
}

static int
memorystatus_get_diag_memlimit_properties_internal(proc_t p, memorystatus_diag_memlimit_properties_t *p_entry)
{
	int error = 0;
	/* Enforce the limit by writing to the ledgers */
	error = (task_get_diag_footprint_limit_internal(proc_task(p), &p_entry->memlimit, &p_entry->threshold_enabled) == KERN_SUCCESS) ? KERN_SUCCESS : EINVAL;

	DTRACE_MEMORYSTATUS2(memorystatus_diag_memlimit_properties_t, proc_t, p, int32_t, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1));
	return error;
}
#endif // DEBUG || DEVELOPMENT

bool
memorystatus_task_has_increased_memory_limit_entitlement(task_t task)
{
	if (memorystatus_entitled_max_task_footprint_mb == 0) {
		// Entitlement is not supported on this device.
		return false;
	}
	return IOTaskHasEntitlement(task,
	           "com.apple.developer.kernel.increased-memory-limit");
}

bool
memorystatus_task_has_increased_debugging_memory_limit_entitlement(task_t task)
{
	if (memorystatus_entitled_dev_max_task_footprint_mb == 0) {
		// Entitlement is not supported on this device.
		return false;
	}
	return IOTaskHasEntitlement(task,
	           "com.apple.developer.kernel.increased-debugging-memory-limit");
}

bool
memorystatus_task_has_legacy_footprint_entitlement(task_t task)
{
	return IOTaskHasEntitlement(task,
	           "com.apple.private.memory.legacy_footprint");
}

bool
memorystatus_task_has_ios13extended_footprint_limit(task_t task)
{
	if (max_mem < 1500ULL * 1024 * 1024 ||
	    max_mem > 2ULL * 1024 * 1024 * 1024) {
		/* ios13extended_footprint is only for 2GB devices */
		return false;
	}
	return IOTaskHasEntitlement(task,
	           "com.apple.developer.memory.ios13extended_footprint");
}

static int32_t
memorystatus_get_default_task_active_limit(proc_t p)
{
	int32_t limit = (int32_t)max_task_footprint_mb;
	task_t task = proc_task(p);

	/*
	 * Check for the various entitlement footprint hacks
	 * and try to apply each one. Note that if multiple entitlements are present
	 * whichever results in the largest limit applies.
	 */
	if (memorystatus_task_has_increased_debugging_memory_limit_entitlement(task)) {
		limit = MAX(limit, memorystatus_entitled_dev_max_task_footprint_mb);
	}
	if (memorystatus_task_has_increased_memory_limit_entitlement(task)) {
#if CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT
		/* On visionOS, we want a separate memory limit for iOS (bincompat) apps. */
		if ((proc_platform(p) == PLATFORM_IOS) &&
		    (memorystatus_entitled_bincompat_max_task_footprint_mb != 0)) {
			limit = MAX(limit, memorystatus_entitled_bincompat_max_task_footprint_mb);
		} else {
			limit = MAX(limit, memorystatus_entitled_max_task_footprint_mb);
		}
#else /* CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT */
		limit = MAX(limit, memorystatus_entitled_max_task_footprint_mb);
#endif /* !CONFIG_SEPARATE_BINCOMPAT_ENTITLED_MEMLIMIT */
	}
#if __arm64__
	if (legacy_footprint_entitlement_mode == LEGACY_FOOTPRINT_ENTITLEMENT_LIMIT_INCREASE &&
	    memorystatus_task_has_legacy_footprint_entitlement(task)) {
		limit = MAX(limit, max_task_footprint_mb + legacy_footprint_bonus_mb);
	}
#endif /* __arm64__ */
	if (memorystatus_task_has_ios13extended_footprint_limit(task)) {
		limit = MAX(limit, memorystatus_ios13extended_footprint_limit_mb);
	}

	return limit;
}

static int32_t
memorystatus_get_default_task_inactive_limit(proc_t p)
{
	// Currently the default active and inactive limits are always the same.
	return memorystatus_get_default_task_active_limit(p);
}

static int
memorystatus_set_memlimit_properties(pid_t pid, memorystatus_memlimit_properties_t *entry)
{
	int32_t memlimit_active, memlimit_inactive;
	memlimit_options_t memlimit_options = MEMLIMIT_OPTIONS_NONE;

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	/*
	 * Check for valid attribute flags.
	 */
	const uint32_t valid_attrs = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	if ((entry->memlimit_active_attr & (~valid_attrs)) != 0) {
		proc_rele(p);
		return EINVAL;
	}
	if ((entry->memlimit_inactive_attr & (~valid_attrs)) != 0) {
		proc_rele(p);
		return EINVAL;
	}

	/*
	 * Setup the active memlimit properties
	 */
	memlimit_active = entry->memlimit_active;
	if (entry->memlimit_active_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL) {
		memlimit_options |= MEMLIMIT_ACTIVE_FATAL;
	}

	/*
	 * Setup the inactive memlimit properties
	 */
	memlimit_inactive = entry->memlimit_inactive;
	if (entry->memlimit_inactive_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL) {
		memlimit_options |= MEMLIMIT_INACTIVE_FATAL;
	}

	int error = memorystatus_set_memlimits(p, memlimit_active,
	    memlimit_inactive, memlimit_options);
	proc_rele(p);
	return error;
}

/*
 * Returns the jetsam priority (effective or requested) of the process
 * associated with this task.
 */
int
proc_get_memstat_priority(proc_t p, boolean_t effective_priority)
{
	if (p) {
		if (effective_priority) {
			return p->p_memstat_effectivepriority;
		} else {
			return p->p_memstat_requestedpriority;
		}
	}
	return 0;
}

static int
memorystatus_get_process_is_managed(pid_t pid, int *is_managed)
{
	proc_t p = NULL;

	/* Validate inputs */
	if (pid == 0) {
		return EINVAL;
	}

	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	proc_list_lock();
	*is_managed = ((p->p_memstat_state & P_MEMSTAT_MANAGED) ? 1 : 0);
	proc_rele(p);
	proc_list_unlock();

	return 0;
}

static int
memorystatus_set_process_is_managed(pid_t pid, boolean_t set_managed)
{
	proc_t p = NULL;

	/* Validate inputs */
	if (pid == 0) {
		return EINVAL;
	}

	p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	proc_list_lock();

	if (set_managed == TRUE) {
		p->p_memstat_state |= P_MEMSTAT_MANAGED;
		/*
		 * The P_MEMSTAT_MANAGED bit is set by Runningboard for Apps.
		 * Also opt them in to being frozen (they might have started
		 * off with the P_MEMSTAT_FREEZE_DISABLED bit set.)
		 */
		p->p_memstat_state &= ~P_MEMSTAT_FREEZE_DISABLED;
	} else {
		p->p_memstat_state &= ~P_MEMSTAT_MANAGED;
	}

	if (_memstat_proc_is_tracked(p)) {
		memorystatus_log_error("memorystatus: process %s [%d] opted in to both "
		    "Management and ActivityTracking\n", proc_best_name(p),
		    proc_pid(p));
	}

	proc_list_unlock();

	proc_rele(p);

	return 0;
}

static int
_memstat_get_kill_count(int priority, memorystatus_kill_cause_t cause, bool clear)
{
	uint32_t _Atomic *ptr;

	assert(priority >= JETSAM_PRIORITY_IDLE);
	assert(priority <= JETSAM_PRIORITY_MAX);

	/* rdar://141462516 */
	if (cause == kMemorystatusInvalid) {
		return 0;
	} else if (cause == kMemorystatusKilledIdleExit) {
		if (priority == JETSAM_PRIORITY_IDLE) {
			ptr = &memorystatus_idle_exit_kill_count;
		} else {
			return 0; /* This never happens */
		}
	} else {
		if (cause < kMemorystatusKilledIdleExit) {
			ptr = &memorystatus_kill_counts[priority][cause - 1];
		} else {
			ptr = &memorystatus_kill_counts[priority][cause - 2];
		}
	}

	if (clear) {
		return os_atomic_xchg(ptr, 0, relaxed);
	} else {
		return os_atomic_load(ptr, relaxed);
	}
}

static int
memorystatus_cmd_get_kill_counts(int priority, user_addr_t buffer, size_t buffer_size, int flags)
{
	memorystatus_kill_cause_t cause;
	uint32_t outbuf[JETSAM_REASON_MEMORYSTATUS_MAX + 1];
	bool clear = flags & MEMORYSTATUS_GET_KILL_COUNTS_CLEAR;

	if (((buffer_size % sizeof(uint32_t)) != 0) ||
	    (priority < JETSAM_PRIORITY_IDLE) ||
	    (priority > JETSAM_PRIORITY_MAX)) {
		return EINVAL;
	}

	for (cause = kMemorystatusInvalid; cause <= JETSAM_REASON_MEMORYSTATUS_MAX; cause++) {
		outbuf[cause] = _memstat_get_kill_count(priority, cause, clear);
	}

	return copyout(outbuf, buffer, MIN(buffer_size, sizeof(outbuf)));
}

int
memorystatus_control(struct proc *p, struct memorystatus_control_args *args, int *ret)
{
	int error = EINVAL;
	boolean_t skip_auth_check = FALSE;
	os_reason_t jetsam_reason = OS_REASON_NULL;

#if !CONFIG_JETSAM
    #pragma unused(ret)
    #pragma unused(jetsam_reason)
#endif

	/* We don't need entitlements if we're setting / querying the freeze preference or frozen status for a process. */
	if (args->command == MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE ||
	    args->command == MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE ||
	    args->command == MEMORYSTATUS_CMD_GET_PROCESS_IS_FROZEN) {
		skip_auth_check = TRUE;
	}

	/*
	 * On development kernel, we don't need entitlements if we're adjusting the limit.
	 * This required for limit adjustment by dyld when roots are detected, see rdar://99669958
	 */
#if DEVELOPMENT || DEBUG
	if (args->command == MEMORYSTATUS_CMD_INCREASE_JETSAM_TASK_LIMIT && proc_getpid(p) == args->pid) {
		skip_auth_check = TRUE;
	}
#endif /* DEVELOPMENT || DEBUG */

	/* Need to be root or have entitlement. */
	if (!kauth_cred_issuser(kauth_cred_get()) && !IOCurrentTaskHasEntitlement(MEMORYSTATUS_ENTITLEMENT) && !skip_auth_check) {
		error = EPERM;
		goto out;
	}

	/*
	 * Sanity check.
	 * Do not enforce it for snapshots or v2 priority list.
	 * (the latter always allocates an appropriately-sized buffer.)
	 */
	if (args->command != MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT &&
	    args->command != MEMORYSTATUS_CMD_GET_PRIORITY_LIST_V2 &&
	    args->command != MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_NAMES &&
	    args->command != MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_INFO &&
	    args->command != MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_MEMINFO) {
		if (args->buffersize > MEMORYSTATUS_BUFFERSIZE_MAX) {
			error = EINVAL;
			goto out;
		}
	}

#if CONFIG_MACF
	error = mac_proc_check_memorystatus_control(p, args->command, args->pid);
	if (error) {
		goto out;
	}
#endif /* MAC */

	switch (args->command) {
	case MEMORYSTATUS_CMD_GET_PRIORITY_LIST:
		error = memorystatus_cmd_get_priority_list(
			args->pid,
			args->buffer,
			args->buffersize,
			ret,
			sizeof(memorystatus_priority_entry_t));
		break;
	case MEMORYSTATUS_CMD_GET_PRIORITY_LIST_V2:
		error = memorystatus_cmd_get_priority_list(
			args->pid,
			args->buffer,
			args->buffersize,
			ret,
			sizeof(memorystatus_priority_entry_v2_t));
		break;
	case MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES:
		error = memorystatus_cmd_set_priority_properties(args->pid, args->flags, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES:
		error = memorystatus_cmd_set_memlimit_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES:
		error = memorystatus_cmd_get_memlimit_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_MEMLIMIT_EXCESS:
		error = memorystatus_cmd_get_memlimit_excess_np(args->pid, args->flags, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GRP_SET_PROPERTIES:
		error = memorystatus_cmd_grp_set_properties((int32_t)args->flags, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT:
		error = memorystatus_cmd_get_jetsam_snapshot((int32_t)args->flags, args->buffer, args->buffersize, ret);
		break;
#if JETSAM_ZPRINT_SNAPSHOT
	case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_NAMES:
		error = memorystatus_cmd_get_data_buffer(args->buffer, args->buffersize, ret,
		    jzs_zone_cnt * sizeof(mach_zone_name_t), jzs_names);
		break;
	case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_INFO:
		error = memorystatus_cmd_get_data_buffer(args->buffer, args->buffersize, ret,
		    jzs_zone_cnt * sizeof(mach_zone_info_t), jzs_info);
		break;
	case MEMORYSTATUS_CMD_GET_JETSAM_ZPRINT_MEMINFO:
		error = memorystatus_cmd_get_data_buffer(args->buffer, args->buffersize, ret,
		    jzs_meminfo_cnt * sizeof(mach_memory_info_t), jzs_meminfo);
		break;
#endif
#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_SET_TESTING_PID:
		error = memorystatus_cmd_set_testing_pid((int32_t) args->flags);
		break;
#endif
	case MEMORYSTATUS_CMD_GET_PRESSURE_STATUS:
		error = memorystatus_cmd_get_pressure_status(ret);
		break;
#if CONFIG_JETSAM
	case MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK:
		/*
		 * This call does not distinguish between active and inactive limits.
		 * Default behavior in 2-level HWM world is to set both.
		 * Non-fatal limit is also assumed for both.
		 */
		error = memorystatus_cmd_set_jetsam_memory_limit(args->pid, (int32_t)args->flags, ret, FALSE);
		break;
	case MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT:
		/*
		 * This call does not distinguish between active and inactive limits.
		 * Default behavior in 2-level HWM world is to set both.
		 * Fatal limit is also assumed for both.
		 */
		error = memorystatus_cmd_set_jetsam_memory_limit(args->pid, (int32_t)args->flags, ret, TRUE);
		break;
	case MEMORYSTATUS_CMD_MARK_PROCESS_COALITION_SWAPPABLE:
		error = memorystatus_cmd_mark_process_coalition_swappable(args->pid, ret);
		break;

	case MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE:
		error = memorystatus_cmd_get_process_coalition_is_swappable(args->pid, ret);
		break;

	case MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB:
		error = memorystatus_cmd_convert_memlimit_mb(args->pid, (int32_t) args->flags, ret);
		break;
#endif /* CONFIG_JETSAM */
		/* Test commands */
#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_TEST_JETSAM:
		jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_GENERIC);
		if (jetsam_reason == OS_REASON_NULL) {
			memorystatus_log_error("memorystatus_control: failed to allocate jetsam reason\n");
		}

		error = memorystatus_kill_process_sync(args->pid, kMemorystatusKilled, jetsam_reason) ? 0 : EINVAL;
		break;
	case MEMORYSTATUS_CMD_TEST_JETSAM_SORT:
		error = memorystatus_cmd_test_jetsam_sort(args->pid, (int32_t)args->flags, args->buffer, args->buffersize);
		break;
#else /* DEVELOPMENT || DEBUG */
	#pragma unused(jetsam_reason)
#endif /* DEVELOPMENT || DEBUG */
	case MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_ENABLE:
		if (memorystatus_aggressive_jetsam_lenient_allowed == FALSE) {
#if DEVELOPMENT || DEBUG
			memorystatus_log_info("Enabling Lenient Mode\n");
#endif /* DEVELOPMENT || DEBUG */

			memorystatus_aggressive_jetsam_lenient_allowed = TRUE;
			memorystatus_aggressive_jetsam_lenient = TRUE;
			error = 0;
		}
		break;
	case MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_DISABLE:
#if DEVELOPMENT || DEBUG
		memorystatus_log_info("Disabling Lenient mode\n");
#endif /* DEVELOPMENT || DEBUG */
		memorystatus_aggressive_jetsam_lenient_allowed = FALSE;
		memorystatus_aggressive_jetsam_lenient = FALSE;
		error = 0;
		break;
	case MEMORYSTATUS_CMD_GET_AGGRESSIVE_JETSAM_LENIENT_MODE:
		*ret = (memorystatus_aggressive_jetsam_lenient ? 1 : 0);
		error = 0;
		break;
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE:
	case MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE:
		error = memorystatus_low_mem_privileged_listener(args->command);
		break;

	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE:
	case MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE:
		error = memorystatus_update_inactive_jetsam_priority_band(args->pid, args->command, JETSAM_PRIORITY_ELEVATED_INACTIVE, args->flags ? TRUE : FALSE);
		break;
	case MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED:
		error = memorystatus_set_process_is_managed(args->pid, args->flags);
		break;

	case MEMORYSTATUS_CMD_GET_PROCESS_IS_MANAGED:
		error = memorystatus_get_process_is_managed(args->pid, ret);
		break;

#if CONFIG_FREEZE
	case MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE:
		error = memorystatus_set_process_is_freezable(args->pid, args->flags ? TRUE : FALSE);
		break;

	case MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE:
		error = memorystatus_get_process_is_freezable(args->pid, ret);
		break;
	case MEMORYSTATUS_CMD_GET_PROCESS_IS_FROZEN:
		error = memorystatus_get_process_is_frozen(args->pid, ret);
		break;

	case MEMORYSTATUS_CMD_FREEZER_CONTROL:
		error = memorystatus_freezer_control(args->flags, args->buffer, args->buffersize, ret);
		break;
#endif /* CONFIG_FREEZE */

#if DEVELOPMENT || DEBUG
	case MEMORYSTATUS_CMD_INCREASE_JETSAM_TASK_LIMIT:
		error = memorystatus_cmd_increase_jetsam_task_limit(args->pid, args->flags);
		break;
	case MEMORYSTATUS_CMD_SET_DIAG_LIMIT:
		error = memorystatus_cmd_set_diag_memlimit_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
	case MEMORYSTATUS_CMD_GET_DIAG_LIMIT:
		error = memorystatus_cmd_get_diag_memlimit_properties(args->pid, args->buffer, args->buffersize, ret);
		break;
#endif /* DEVELOPMENT || DEBUG */

	case MEMORYSTATUS_CMD_GET_KILL_COUNTS:
		error = memorystatus_cmd_get_kill_counts(args->pid, args->buffer, args->buffersize, args->flags);
		break;
	default:
		error = EINVAL;
		break;
	}

out:
	return error;
}

/* Coalition support */

/* sorting info for a particular priority bucket */
typedef struct memstat_sort_info {
	coalition_t     msi_coal;
	uint64_t        msi_page_count;
	pid_t           msi_pid;
	int             msi_ntasks;
} memstat_sort_info_t;

/*
 * qsort from smallest page count to largest page count
 *
 * return < 0 for a < b
 *          0 for a == b
 *        > 0 for a > b
 */
static int
memstat_asc_cmp(const void *a, const void *b)
{
	const memstat_sort_info_t *msA = (const memstat_sort_info_t *)a;
	const memstat_sort_info_t *msB = (const memstat_sort_info_t *)b;

	return (int)((uint64_t)msA->msi_page_count - (uint64_t)msB->msi_page_count);
}

/*
 * Return the number of pids rearranged during this sort.
 */
static int
memorystatus_sort_by_largest_coalition_locked(unsigned int bucket_index, int coal_sort_order)
{
#define MAX_SORT_PIDS           80
#define MAX_COAL_LEADERS        10

	unsigned int b = bucket_index;
	int nleaders = 0;
	int ntasks = 0;
	proc_t p = NULL;
	coalition_t coal = COALITION_NULL;
	int pids_moved = 0;
	int total_pids_moved = 0;
	int i;

	/*
	 * The system is typically under memory pressure when in this
	 * path, hence, we want to avoid dynamic memory allocation.
	 */
	memstat_sort_info_t leaders[MAX_COAL_LEADERS];
	pid_t pid_list[MAX_SORT_PIDS];

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return 0;
	}

	/*
	 * Clear the array that holds coalition leader information
	 */
	for (i = 0; i < MAX_COAL_LEADERS; i++) {
		leaders[i].msi_coal = COALITION_NULL;
		leaders[i].msi_page_count = 0;          /* will hold total coalition page count */
		leaders[i].msi_pid = 0;                 /* will hold coalition leader pid */
		leaders[i].msi_ntasks = 0;              /* will hold the number of tasks in a coalition */
	}

	p = memorystatus_get_first_proc_locked(&b, FALSE);
	while (p) {
		coal = task_get_coalition(proc_task(p), COALITION_TYPE_JETSAM);
		if (coalition_is_leader(proc_task(p), coal)) {
			if (nleaders < MAX_COAL_LEADERS) {
				int coal_ntasks = 0;
				uint64_t coal_page_count = coalition_get_page_count(coal, &coal_ntasks);
				leaders[nleaders].msi_coal = coal;
				leaders[nleaders].msi_page_count = coal_page_count;
				leaders[nleaders].msi_pid = proc_getpid(p);           /* the coalition leader */
				leaders[nleaders].msi_ntasks = coal_ntasks;
				nleaders++;
			} else {
				/*
				 * We've hit MAX_COAL_LEADERS meaning we can handle no more coalitions.
				 * Abandoned coalitions will linger at the tail of the priority band
				 * when this sort session ends.
				 * TODO:  should this be an assert?
				 */
				memorystatus_log_error(
					"%s: WARNING: more than %d leaders in priority band [%d]\n",
					__FUNCTION__, MAX_COAL_LEADERS, bucket_index);
				break;
			}
		}
		p = memorystatus_get_next_proc_locked(&b, p, FALSE);
	}

	if (nleaders == 0) {
		/* Nothing to sort */
		return 0;
	}

	/*
	 * Sort the coalition leader array, from smallest coalition page count
	 * to largest coalition page count.  When inserted in the priority bucket,
	 * smallest coalition is handled first, resulting in the last to be jetsammed.
	 */
	if (nleaders > 1) {
		qsort(leaders, nleaders, sizeof(memstat_sort_info_t), memstat_asc_cmp);
	}

	/*
	 * During coalition sorting, processes in a priority band are rearranged
	 * by being re-inserted at the head of the queue.  So, when handling a
	 * list, the first process that gets moved to the head of the queue,
	 * ultimately gets pushed toward the queue tail, and hence, jetsams last.
	 *
	 * So, for example, the coalition leader is expected to jetsam last,
	 * after its coalition members.  Therefore, the coalition leader is
	 * inserted at the head of the queue first.
	 *
	 * After processing a coalition, the jetsam order is as follows:
	 *   undefs(jetsam first), extensions, xpc services, leader(jetsam last)
	 */

	/*
	 * Coalition members are rearranged in the priority bucket here,
	 * based on their coalition role.
	 */
	total_pids_moved = 0;
	for (i = 0; i < nleaders; i++) {
		/* a bit of bookkeeping */
		pids_moved = 0;

		/* Coalition leaders are jetsammed last, so move into place first */
		pid_list[0] = leaders[i].msi_pid;
		pids_moved += memorystatus_move_list_locked(bucket_index, pid_list, 1);

		/* xpc services should jetsam after extensions */
		ntasks = coalition_get_pid_list(leaders[i].msi_coal, COALITION_ROLEMASK_XPC,
		    coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list,
			    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		/* extensions should jetsam after unmarked processes */
		ntasks = coalition_get_pid_list(leaders[i].msi_coal, COALITION_ROLEMASK_EXT,
		    coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list,
			    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		/* undefined coalition members should be the first to jetsam */
		ntasks = coalition_get_pid_list(leaders[i].msi_coal, COALITION_ROLEMASK_UNDEF,
		    coal_sort_order, pid_list, MAX_SORT_PIDS);

		if (ntasks > 0) {
			pids_moved += memorystatus_move_list_locked(bucket_index, pid_list,
			    (ntasks <= MAX_SORT_PIDS ? ntasks : MAX_SORT_PIDS));
		}

		total_pids_moved += pids_moved;
	} /* end for */

	return total_pids_moved;
}


/*
 * Traverse a list of pids, searching for each within the priority band provided.
 * If pid is found, move it to the front of the priority band.
 * Never searches outside the priority band provided.
 *
 * Input:
 *	bucket_index - jetsam priority band.
 *	pid_list - pointer to a list of pids.
 *	list_sz  - number of pids in the list.
 *
 * Pid list ordering is important in that,
 * pid_list[n] is expected to jetsam ahead of pid_list[n+1].
 * The sort_order is set by the coalition default.
 *
 * Return:
 *	the number of pids found and hence moved within the priority band.
 */
static int
memorystatus_move_list_locked(unsigned int bucket_index, pid_t *pid_list, int list_sz)
{
	memstat_bucket_t *current_bucket;
	int i;
	int found_pids = 0;

	if ((pid_list == NULL) || (list_sz <= 0)) {
		return 0;
	}

	if (bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return 0;
	}

	current_bucket = &memstat_bucket[bucket_index];
	for (i = 0; i < list_sz; i++) {
		unsigned int b = bucket_index;
		proc_t p = NULL;
		proc_t aProc = NULL;
		pid_t  aPid;
		int list_index;

		list_index = ((list_sz - 1) - i);
		aPid = pid_list[list_index];

		/* never search beyond bucket_index provided */
		p = memorystatus_get_first_proc_locked(&b, FALSE);
		while (p) {
			if (proc_getpid(p) == aPid) {
				aProc = p;
				break;
			}
			p = memorystatus_get_next_proc_locked(&b, p, FALSE);
		}

		if (aProc == NULL) {
			/* pid not found in this band, just skip it */
			continue;
		} else {
			TAILQ_REMOVE(&current_bucket->list, aProc, p_memstat_list);
			TAILQ_INSERT_HEAD(&current_bucket->list, aProc, p_memstat_list);
			found_pids++;
		}
	}
	return found_pids;
}

uint32_t
memstat_get_idle_proccnt(void)
{
#if CONFIG_JETSAM
	return os_atomic_load(&memstat_bucket[JETSAM_PRIORITY_IDLE].count, relaxed);
#else /* !CONFIG_JETSAM */
	uint32_t count = 0;
	uint32_t bucket = JETSAM_PRIORITY_IDLE;

	proc_list_lock();
	for (proc_t p = memorystatus_get_first_proc_locked(&bucket, FALSE);
	    p != PROC_NULL;
	    p = memorystatus_get_next_proc_locked(&bucket, p, FALSE)) {
		if ((_memstat_proc_can_idle_exit(p) && !_memstat_proc_is_dirty(p)) ||
		    (_memstat_proc_is_managed(p) && !_memstat_proc_has_priority_assertion(p))) {
			count++;
		}
	}
	proc_list_unlock();

	return count;
#endif /* CONFIG_JETSAM */
}

uint32_t
memstat_get_proccnt_upto_priority(uint32_t max_bucket_index)
{
	int32_t i = JETSAM_PRIORITY_IDLE;
	int count = 0;

	if (max_bucket_index >= MEMSTAT_BUCKET_COUNT) {
		return -1;
	}

	while (i <= max_bucket_index) {
		count += memstat_bucket[i++].count;
	}

	return count;
}

int
memorystatus_update_priority_for_appnap(proc_t p, boolean_t is_appnap)
{
#if !CONFIG_JETSAM
	if (!p || (!isApp(p)) || (p->p_memstat_state & (P_MEMSTAT_INTERNAL | P_MEMSTAT_MANAGED))) {
		/*
		 * Ineligible processes OR system processes e.g. launchd.
		 *
		 * We also skip processes that have the P_MEMSTAT_MANAGED bit set, i.e.
		 * they're managed by assertiond. These are iOS apps that have been ported
		 * to macOS. assertiond might be in the process of modifying the app's
		 * priority / memory limit - so it might have the proc_list lock, and then try
		 * to take the task lock. Meanwhile we've entered this function with the task lock
		 * held, and we need the proc_list lock below. So we'll deadlock with assertiond.
		 *
		 * It should be fine to read the P_MEMSTAT_MANAGED bit without the proc_list
		 * lock here, since assertiond only sets this bit on process launch.
		 */
		return -1;
	}

	/*
	 * For macOS only:
	 * We would like to use memorystatus_set_priority() here to move the processes
	 * within the bands. Unfortunately memorystatus_set_priority() calls
	 * memorystatus_update_priority_locked() which uses any band transitions
	 * as an indication to modify ledgers. For that it needs the task lock
	 * and since we came into this function with the task lock held, we'll deadlock.
	 *
	 * Unfortunately we can't completely disable ledger updates  because we still
	 * need the ledger updates for a subset of processes i.e. daemons.
	 * When all processes on all platforms support memory limits, we can simply call
	 * memorystatus_set_priority().
	 *
	 * It also has some logic to deal with 'aging' which, currently, is only applicable
	 * on CONFIG_JETSAM configs. So, till every platform has CONFIG_JETSAM we'll need
	 * to do this explicit band transition.
	 */

	memstat_bucket_t *current_bucket, *new_bucket;
	uint64_t now;
	int32_t priority = 0;

	proc_list_lock();

	if (proc_list_exited(p) ||
	    (p->p_memstat_state & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP))) {
		/*
		 * If the process is on its way out OR
		 * jetsam has alread tried and failed to kill this process,
		 * let's skip the whole jetsam band transition.
		 */
		proc_list_unlock();
		return 0;
	}

	if (is_appnap) {
		current_bucket = &memstat_bucket[p->p_memstat_effectivepriority];
		new_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
		priority = JETSAM_PRIORITY_IDLE;
	} else {
		if (p->p_memstat_effectivepriority != JETSAM_PRIORITY_IDLE) {
			/*
			 * It is possible that someone pulled this process
			 * out of the IDLE band without updating its app-nap
			 * parameters.
			 */
			proc_list_unlock();
			return 0;
		}

		current_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
		new_bucket = &memstat_bucket[p->p_memstat_requestedpriority];
		priority = p->p_memstat_requestedpriority;
	}

	now = mach_absolute_time();

	TAILQ_REMOVE(&current_bucket->list, p, p_memstat_list);
	current_bucket->count--;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		current_bucket->relaunch_high_count--;
	}
	TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	new_bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		new_bucket->relaunch_high_count++;
	}
	/*
	 * Record idle start or idle delta.
	 */
	if (p->p_memstat_effectivepriority == priority) {
		/*
		 * This process is not transitioning between
		 * jetsam priority buckets.  Do nothing.
		 */
	} else if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Transitioning out of the idle priority bucket.
		 * Record idle delta.
		 */
		assert(p->p_memstat_prio_start != 0);
		if (now > p->p_memstat_prio_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_prio_start;
		}
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_CHANGE_PRIORITY), proc_getpid(p), priority, p->p_memstat_effectivepriority);

	p->p_memstat_effectivepriority = priority;
	p->p_memstat_prio_start = now;

	proc_list_unlock();

	return 0;

#else /* !CONFIG_JETSAM */
	#pragma unused(p)
	#pragma unused(is_appnap)
	return -1;
#endif /* !CONFIG_JETSAM */
}

uint64_t
memorystatus_available_memory_internal(struct proc *p)
{
#ifdef XNU_TARGET_OS_OSX
	if (p->p_memstat_memlimit <= 0) {
		return 0;
	}
#endif /* XNU_TARGET_OS_OSX */
	const uint64_t footprint_in_bytes = get_task_phys_footprint(proc_task(p));
	int32_t memlimit_mb;
	int64_t memlimit_bytes;
	int64_t rc;

	if (isApp(p) == FALSE) {
		return 0;
	}

	if (p->p_memstat_memlimit > 0) {
		memlimit_mb = p->p_memstat_memlimit;
	} else if (task_convert_phys_footprint_limit(-1, &memlimit_mb) != KERN_SUCCESS) {
		return 0;
	}

	if (memlimit_mb <= 0) {
		memlimit_bytes = INT_MAX & ~((1 << 20) - 1);
	} else {
		memlimit_bytes = ((int64_t) memlimit_mb) << 20;
	}

	rc = memlimit_bytes - footprint_in_bytes;

	return (rc >= 0) ? rc : 0;
}

int
memorystatus_available_memory(struct proc *p, __unused struct memorystatus_available_memory_args *args, uint64_t *ret)
{
	*ret = memorystatus_available_memory_internal(p);

	return 0;
}

void
memorystatus_log_system_health(const memorystatus_system_health_t *status)
{
	static struct memorystatus_system_health prev_status = {0};

	bool healthy = memorystatus_is_system_healthy(status);

	/*
	 * Avoid spamming logs by only logging when the system status has changed.
	 */
	if (prev_status.msh_zone_map_is_exhausted == status->msh_zone_map_is_exhausted &&
	    prev_status.msh_compressor_exhausted == status->msh_compressor_exhausted &&
	    prev_status.msh_swap_low_on_space == status->msh_swap_low_on_space &&
	    prev_status.msh_swap_exhausted == status->msh_swap_exhausted
#if CONFIG_JETSAM
	    &&
	    prev_status.msh_available_pages_below_idle == status->msh_available_pages_below_idle &&
	    prev_status.msh_available_pages_below_soft == status->msh_available_pages_below_soft &&
	    prev_status.msh_available_pages_below_critical == status->msh_available_pages_below_critical &&
	    prev_status.msh_available_pages_below_reaper == status->msh_available_pages_below_reaper &&
	    prev_status.msh_compressor_needs_to_swap == status->msh_compressor_needs_to_swap &&
	    prev_status.msh_compressor_is_thrashing == status->msh_compressor_is_thrashing &&
	    prev_status.msh_filecache_is_thrashing == status->msh_filecache_is_thrashing &&
	    prev_status.msh_phantom_cache_pressure == status->msh_phantom_cache_pressure &&
	    prev_status.msh_swapin_queue_over_limit == status->msh_swapin_queue_over_limit &&
	    prev_status.msh_pageout_starved == status->msh_pageout_starved
#endif /* CONFIG_JETSAM */
	    ) {
		/* No change */
		return;
	}

#if CONFIG_JETSAM
	if (healthy) {
		if (status->msh_available_pages_below_soft) {
			memorystatus_log(
				"memorystatus: System will begin enforcing "
				"soft memory limits. "
				"memorystatus_available_pages: %llu compressor_size: %u\n",
				(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		} else if (status->msh_available_pages_below_idle) {
			memorystatus_log(
				"memorystatus: System will begin enacting "
				"idle-exits. "
				"memorystatus_available_pages: %llu compressor_size: %u\n",
				(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		} else if (status->msh_available_pages_below_reaper) {
			memorystatus_log(
				"memorystatus: System will begin reaping "
				"long-idle processes. "
				"memorystatus_available_pages: %llu compressor_size: %u\n",
				(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		} else {
			memorystatus_log(
				"memorystatus: System is healthy. "
				"memorystatus_available_pages: %llu compressor_size:%u\n",
				(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		}
	} else {
		/* Unhealthy */
		memorystatus_log("memorystatus: System is unhealthy! memorystatus_available_pages: %llu compressor_size:%u\n",
		    (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		memorystatus_log(
			"memorystatus: {"
			"\"available_pages_below_critical\": %d, "
			"\"available_pages_below_idle\": %d, "
			"\"available_pages_below_soft\": %d, "
			"\"available_pages_below_reaper\": %d, "
			"\"compressor_needs_to_swap\": %d, "
			"\"compressor_exhausted\": %d, "
			"\"compressor_is_thrashing\": %d, "
			"\"filecache_is_thrashing\": %d, "
			"\"zone_map_is_exhausted\": %d, "
			"\"phantom_cache_pressure\": %d, "
			"\"swappable_compressor_segments_over_limit\": %d, "
			"\"swapin_queue_over_limit\": %d, "
			"\"swap_low\": %d, "
			"\"swap_exhausted\": %d"
			"}\n",
			status->msh_available_pages_below_critical,
			status->msh_available_pages_below_idle,
			status->msh_available_pages_below_soft,
			status->msh_available_pages_below_reaper,
			status->msh_compressor_needs_to_swap,
			status->msh_compressor_exhausted,
			status->msh_compressor_is_thrashing,
			status->msh_filecache_is_thrashing,
			status->msh_zone_map_is_exhausted,
			status->msh_phantom_cache_pressure,
			status->msh_swappable_compressor_segments_over_limit,
			status->msh_swapin_queue_over_limit,
			status->msh_swap_low_on_space,
			status->msh_swap_exhausted);
	}
#else /* CONFIG_JETSAM */
	memorystatus_log("memorystatus: System is %s. memorystatus_available_pages: %llu compressor_size:%u\n",
	    healthy ? "healthy" : "unhealthy",
	    (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
	if (!healthy) {
		memorystatus_log(
			"memorystatus: {"
			"\"compressor_exhausted\": %d, "
			"\"zone_map_is_exhausted\": %d, "
			"\"swap_low\": %d, "
			"\"swap_exhausted\": %d"
			"}\n",
			status->msh_compressor_exhausted,
			status->msh_zone_map_is_exhausted,
			status->msh_swap_low_on_space,
			status->msh_swap_exhausted);
	}
#endif /* CONFIG_JETSAM */
	prev_status = *status;
}

uint32_t
memorystatus_pick_kill_cause(const memorystatus_system_health_t *status)
{
	assert(!memorystatus_is_system_healthy(status));
#if CONFIG_JETSAM
	if (status->msh_compressor_is_thrashing) {
		return kMemorystatusKilledVMCompressorThrashing;
	} else if (status->msh_compressor_exhausted) {
		return kMemorystatusKilledVMCompressorSpaceShortage;
	} else if (status->msh_swap_low_on_space) {
		return kMemorystatusKilledLowSwap;
	} else if (status->msh_filecache_is_thrashing) {
		return kMemorystatusKilledFCThrashing;
	} else if (status->msh_zone_map_is_exhausted) {
		return kMemorystatusKilledZoneMapExhaustion;
	} else if (status->msh_pageout_starved) {
		return kMemorystatusKilledVMPageoutStarvation;
	} else {
		assert(status->msh_available_pages_below_critical);
		return kMemorystatusKilledVMPageShortage;
	}
#else /* CONFIG_JETSAM */
	if (status->msh_zone_map_is_exhausted) {
		return kMemorystatusKilledZoneMapExhaustion;
	} else if (status->msh_compressor_exhausted) {
		return kMemorystatusKilledVMCompressorSpaceShortage;
	} else if (status->msh_swap_exhausted) {
		return kMemorystatusKilledLowSwap;
	} else {
		return kMemorystatusKilled;
	}
#endif /* CONFIG_JETSAM */
}

#if DEVELOPMENT || DEBUG
static int
memorystatus_cmd_increase_jetsam_task_limit(pid_t pid, uint32_t byte_increase)
{
	int32_t memlimit_active, memlimit_inactive;

	/* Validate inputs */
	if ((pid == 0) || (byte_increase == 0)) {
		return EINVAL;
	}

	proc_t p = proc_find(pid);

	if (!p) {
		return ESRCH;
	}

	const uint32_t current_memlimit_increase = roundToNearestMB(p->p_memlimit_increase);
	/* round to page */
	const int32_t page_aligned_increase = (int32_t) MIN(round_page(p->p_memlimit_increase + byte_increase), INT32_MAX);

	proc_list_lock();

	memlimit_active = p->p_memstat_memlimit_active;
	if (memlimit_active > 0) {
		memlimit_active -= current_memlimit_increase;
		memlimit_active += roundToNearestMB(page_aligned_increase);
	}

	memlimit_inactive = p->p_memstat_memlimit_inactive;
	if (memlimit_inactive > 0) {
		memlimit_inactive -= current_memlimit_increase;
		memlimit_inactive += roundToNearestMB(page_aligned_increase);
	}

	/*
	 * Store the updated delta limit in the proc.
	 */
	p->p_memlimit_increase = page_aligned_increase;

	memlimit_options_t memlimit_options = MEMLIMIT_OPTIONS_NONE;
	if (_memstat_proc_inactive_memlimit_is_fatal(p)) {
		memlimit_options |= MEMLIMIT_INACTIVE_FATAL;
	}
	if (_memstat_proc_active_memlimit_is_fatal(p)) {
		memlimit_options |= MEMLIMIT_ACTIVE_FATAL;
	}

	int error = memstat_set_memlimits_locked(p,
	    memlimit_active, memlimit_inactive,
	    memlimit_options);

	proc_list_unlock();
	proc_rele(p);

	return error;
}
#endif /* DEVELOPMENT */
