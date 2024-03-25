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
#include <vm/vm_reclaim_internal.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <mach/machine/sdt.h>
#include <libkern/section_keywords.h>
#include <stdatomic.h>
#include <os/atomic_private.h>

#include <IOKit/IOBSD.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#if CONFIG_FREEZE
#include <vm/vm_map.h>
#endif /* CONFIG_FREEZE */

#include <kern/kern_memorystatus_internal.h>
#include <sys/kern_memorystatus.h>
#include <sys/kern_memorystatus_freeze.h>
#include <sys/kern_memorystatus_notify.h>
#include <sys/kdebug_triage.h>


extern uint32_t vm_compressor_pool_size(void);
extern uint32_t vm_compressor_fragmentation_level(void);
extern uint32_t vm_compression_ratio(void);

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
	"zone-map-exhaustion",                         /* kMemorystatusKilledZoneMapExhaustion			*/
	"vm-compressor-thrashing",                     /* kMemorystatusKilledVMCompressorThrashing		*/
	"vm-compressor-space-shortage",                /* kMemorystatusKilledVMCompressorSpaceShortage	*/
	"low-swap",                                    /* kMemorystatusKilledLowSwap                   */
	"sustained-memory-pressure",                   /* kMemorystatusKilledSustainedPressure         */
	"vm-pageout-starvation",                       /* kMemorystatusKilledVMPageoutStarvation       */
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

/*
 * Active / Inactive limit support
 * proc list must be locked
 *
 * The SET_*** macros are used to initialize a limit
 * for the first time.
 *
 * The CACHE_*** macros are use to cache the limit that will
 * soon be in effect down in the ledgers.
 */

#define SET_ACTIVE_LIMITS_LOCKED(p, limit, is_fatal)                    \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit_active = (limit);                               \
   if (is_fatal) {                                                      \
	   (p)->p_memstat_state |= P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;     \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL;    \
   }                                                                    \
MACRO_END

#define SET_INACTIVE_LIMITS_LOCKED(p, limit, is_fatal)                  \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit_inactive = (limit);                             \
   if (is_fatal) {                                                      \
	   (p)->p_memstat_state |= P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;   \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL;  \
   }                                                                    \
MACRO_END

#define CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal)                         \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit = (p)->p_memstat_memlimit_active;               \
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL) {        \
	   (p)->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;            \
	   is_fatal = TRUE;                                             \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;           \
	   is_fatal = FALSE;                                            \
   }                                                                    \
MACRO_END

#define CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal)                       \
MACRO_BEGIN                                                             \
(p)->p_memstat_memlimit = (p)->p_memstat_memlimit_inactive;             \
   if ((p)->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) {      \
	   (p)->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;            \
	   is_fatal = TRUE;                                             \
   } else {                                                             \
	   (p)->p_memstat_state &= ~P_MEMSTAT_FATAL_MEMLIMIT;           \
	   is_fatal = FALSE;                                            \
   }                                                                    \
MACRO_END


#pragma mark General Tunables

#define MEMORYSTATUS_SMALL_MEMORY_THRESHOLD (3UL * (1UL << 30))
#define MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD (6UL * (1UL << 30))

#define MEMORYSTATUS_MORE_FREE_OFFSET_PERCENTAGE 5UL
#define MEMORYSTATUS_AGGR_SYSPROC_AGING_PERCENTAGE 7UL
#define MEMORYSTATUS_DELTA_PERCENTAGE_LARGE 4UL
#define MEMORYSTATUS_DELTA_PERCENTAGE_SMALL 5UL

/*
 * Fall back to these percentages/ratios if a mb value is not provided via EDT
 *  DRAM (GB) | critical | idle | pressure | freeze
 *  (0,3]     | 5%       | 10%  | 15%      | 50%
 *  (3,6]     | 4%       | 9%   | 15%      | 50%
 *  (6,∞)     | 4%       | 8%   | 12%      | 50%
 */

#define MEMORYSTATUS_CRITICAL_BASE_PERCENTAGE_SMALL 5UL
#define MEMORYSTATUS_CRITICAL_BASE_PERCENTAGE_LARGE 4UL

#define MEMORYSTATUS_CRITICAL_IDLE_RATIO_NUM 2UL
#define MEMORYSTATUS_CRITICAL_IDLE_RATIO_DENOM 1UL
#define MEMORYSTATUS_PRESSURE_RATIO_NUM 3UL
#define MEMORYSTATUS_PRESSURE_RATIO_DENOM 1UL

/*
 * For historical reasons, devices with "medium"-sized memory configs have a critical:idle:pressure ratio of
 * 4:9:15. This ratio is preserved for these devices when a fixed-mb base value has not been provided by EDT/boot-arg;
 * all other devices use a 1:2:3 ratio.
 */
#define MEMORYSTATUS_CRITICAL_IDLE_RATIO_NUM_MEDIUM 9UL
#define MEMORYSTATUS_CRITICAL_IDLE_RATIO_DENOM_MEDIUM 4UL
#define MEMORYSTATUS_PRESSURE_RATIO_NUM_MEDIUM  15UL
#define MEMORYSTATUS_PRESSURE_RATIO_DENOM_MEDIUM  4UL

#if CONFIG_JETSAM
static int32_t memorystatus_get_default_task_active_limit(proc_t p);
#endif /* CONFIG_JETSAM */

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
static void memorystatus_init_jetsam_snapshot_header(memorystatus_jetsam_snapshot_t *snapshot);

/* General memorystatus stuff */

uint64_t memorystatus_sysprocs_idle_delay_time = 0;
uint64_t memorystatus_apps_idle_delay_time = 0;
/* 2GB devices support an entitlement for a higher app memory limit of "almost 2GB". */
static int32_t memorystatus_ios13extended_footprint_limit_mb = 1800;

/* Some devices give entitled apps a higher memory limit */
TUNABLE_DT_WRITEABLE(int32_t, memorystatus_entitled_max_task_footprint_mb, "/defaults", "kern.entitled_max_task_pmem", "entitled_max_task_pmem", 0, TUNABLE_DT_NONE);

#if __arm64__
#if DEVELOPMENT || DEBUG
SYSCTL_INT(_kern, OID_AUTO, ios13extended_footprint_limit_mb, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_ios13extended_footprint_limit_mb, 0, "");
SYSCTL_INT(_kern, OID_AUTO, entitled_max_task_pmem, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_KERN, &memorystatus_entitled_max_task_footprint_mb, 0, "");
#else /* !(DEVELOPMENT || DEBUG) */
SYSCTL_INT(_kern, OID_AUTO, entitled_max_task_pmem, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_KERN, &memorystatus_entitled_max_task_footprint_mb, 0, "");
#endif /* DEVELOPMENT || DEBUG */
#endif /* __arm64__ */

#pragma mark Logging

os_log_t memorystatus_log_handle;

TUNABLE_WRITEABLE(memorystatus_log_level_t, memorystatus_log_level, "memorystatus_log_level", MEMORYSTATUS_LOG_LEVEL_DEFAULT);

#if DEBUG || DEVELOPMENT
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_log_level, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_log_level, MEMORYSTATUS_LOG_LEVEL_DEFAULT, "");
#endif

static LCK_GRP_DECLARE(memorystatus_jetsam_fg_band_lock_grp,
    "memorystatus_jetsam_fg_band");
LCK_MTX_DECLARE(memorystatus_jetsam_fg_band_lock,
    &memorystatus_jetsam_fg_band_lock_grp);

/* Idle guard handling */

static int32_t memorystatus_scheduled_idle_demotions_sysprocs = 0;
static int32_t memorystatus_scheduled_idle_demotions_apps = 0;

static void memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2);
static void memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state);
static void memorystatus_reschedule_idle_demotion_locked(void);
int memorystatus_update_priority_for_appnap(proc_t p, boolean_t is_appnap);
vm_pressure_level_t convert_internal_pressure_level_to_dispatch_level(vm_pressure_level_t);
boolean_t is_knote_registered_modify_task_pressure_bits(struct knote*, int, task_t, vm_pressure_level_t, vm_pressure_level_t);
void memorystatus_klist_reset_all_for_level(vm_pressure_level_t pressure_level_to_clear);
void memorystatus_send_low_swap_note(void);
boolean_t memorystatus_kill_elevated_process(uint32_t cause, os_reason_t jetsam_reason, unsigned int band, int aggr_count,
    uint32_t *errors, uint64_t *memory_reclaimed);
uint64_t memorystatus_available_memory_internal(proc_t p);
void memorystatus_thread_wake(void);

unsigned int memorystatus_level = 0;
static int memorystatus_list_count = 0;
memstat_bucket_t memstat_bucket[MEMSTAT_BUCKET_COUNT];
static thread_call_t memorystatus_idle_demotion_call;
uint64_t memstat_idle_demotion_deadline = 0;

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
int applications_aging_band = 0;
#else /* XNU_TARGET_OS_OSX */
int system_procs_aging_band = JETSAM_PRIORITY_AGING_BAND1;
int applications_aging_band = JETSAM_PRIORITY_AGING_BAND2;
#endif /* XNU_TARGET_OS_OSX */

_Atomic bool memorystatus_zone_map_is_exhausted = false;
_Atomic bool memorystatus_compressor_space_shortage = false;
_Atomic bool memorystatus_pageout_starved = false;
#if CONFIG_PHANTOM_CACHE
_Atomic bool memorystatus_phantom_cache_pressure = false;
#endif /* CONFIG_PHANTOM_CACHE */

#define isProcessInAgingBands(p)        ((isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) || (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)))

/*
 * For a while we had support for a couple of different aging policies in the kernel,
 * but the sysproc aging policy is now the default on all platforms.
 * This flag was exported as RO via sysctl & is only kept for backwards compatability.
 */
unsigned int jetsam_aging_policy = kJetsamAgingPolicySysProcsReclaimedFirst;
bool memorystatus_should_issue_fg_band_notify = true;

extern uint64_t vm_purgeable_purge_task_owned(task_t task);
extern void coalition_mark_swappable(coalition_t coal);
extern bool coalition_is_swappable(coalition_t coal);
boolean_t memorystatus_allowed_vm_map_fork(task_t, bool *);
#if DEVELOPMENT || DEBUG
void memorystatus_abort_vm_map_fork(task_t);
#endif

/*
 * Idle delay timeout factors for daemons based on relaunch behavior. Only used in
 * kJetsamAgingPolicySysProcsReclaimedFirst aging policy.
 */
#define kJetsamSysProcsIdleDelayTimeLowRatio    (5)
#define kJetsamSysProcsIdleDelayTimeMedRatio    (2)
#define kJetsamSysProcsIdleDelayTimeHighRatio   (1)
static_assert(kJetsamSysProcsIdleDelayTimeLowRatio <= DEFERRED_IDLE_EXIT_TIME_SECS, "sysproc idle delay time for low relaunch daemons would be 0");

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

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_sysprocs_idle_delay_time, CTLTYPE_INT | CTLFLAG_RW,
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

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_apps_idle_delay_time, CTLTYPE_INT | CTLFLAG_RW,
    0, 0, sysctl_jetsam_set_apps_idle_delay_time, "I", "Aging window for applications");

SYSCTL_INT(_kern, OID_AUTO, jetsam_aging_policy, CTLTYPE_INT | CTLFLAG_RD, &jetsam_aging_policy, 0, "");

static unsigned int memorystatus_dirty_count = 0;

SYSCTL_INT(_kern, OID_AUTO, max_task_pmem, CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_KERN, &max_task_footprint_mb, 0, "");

static int memorystatus_highwater_enabled = 1;  /* Update the cached memlimit data. */
static boolean_t proc_jetsam_state_is_active_locked(proc_t);

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
memorystatus_raise_memlimit(proc_t p, int new_memlimit_active, int new_memlimit_inactive)
{
	int memlimit_mb_active = 0, memlimit_mb_inactive = 0;
	boolean_t memlimit_active_is_fatal = FALSE, memlimit_inactive_is_fatal = FALSE, use_active_limit = FALSE;

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

	memlimit_active_is_fatal = (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL);
	memlimit_inactive_is_fatal = (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL);

	SET_ACTIVE_LIMITS_LOCKED(p, memlimit_mb_active, memlimit_active_is_fatal);
	SET_INACTIVE_LIMITS_LOCKED(p, memlimit_mb_inactive, memlimit_inactive_is_fatal);

	if (proc_jetsam_state_is_active_locked(p) == TRUE) {
		use_active_limit = TRUE;
		CACHE_ACTIVE_LIMITS_LOCKED(p, memlimit_active_is_fatal);
	} else {
		CACHE_INACTIVE_LIMITS_LOCKED(p, memlimit_inactive_is_fatal);
	}

	if (memorystatus_highwater_enabled) {
		task_set_phys_footprint_limit_internal(proc_task(p),
		    (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1,
		    NULL,                                    /*return old value */
		    use_active_limit,                                    /*active limit?*/
		    (use_active_limit ? memlimit_active_is_fatal : memlimit_inactive_is_fatal));
	}
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
	memorystatus_raise_memlimit(p, memlimit_mb_active, memlimit_mb_inactive);

	proc_list_unlock();
}

void
memorystatus_act_on_ios13extended_footprint_entitlement(proc_t p)
{
	proc_list_lock();
	memorystatus_raise_memlimit(p, memorystatus_ios13extended_footprint_limit_mb,
	    memorystatus_ios13extended_footprint_limit_mb);
	proc_list_unlock();
}

void
memorystatus_act_on_entitled_task_limit(proc_t p)
{
	if (memorystatus_entitled_max_task_footprint_mb == 0) {
		// Entitlement is not supported on this device.
		return;
	}
	proc_list_lock();
	memorystatus_raise_memlimit(p, memorystatus_entitled_max_task_footprint_mb, memorystatus_entitled_max_task_footprint_mb);
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

static boolean_t memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);
static boolean_t memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason);


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
static int memorystatus_set_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t *p_entry);

int proc_get_memstat_priority(proc_t, boolean_t);

static boolean_t memorystatus_idle_snapshot = 0;

unsigned int memorystatus_delta = 0;

/* Jetsam Loop Detection */
boolean_t memorystatus_jld_enabled = FALSE;              /* Enable jetsam loop detection */
uint32_t memorystatus_jld_eval_period_msecs = 0;         /* Init pass sets this based on device memory size */
int      memorystatus_jld_eval_aggressive_count = 3;     /* Raise the priority max after 'n' aggressive loops */
int      memorystatus_jld_eval_aggressive_priority_band_max = 15;  /* Kill aggressively up through this band */
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
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_aggressive_count, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_eval_aggressive_count, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_jld_eval_aggressive_priority_band_max, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_jld_eval_aggressive_priority_band_max, 0, "");
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
    uint64_t *iokit_mapped_pages, uint64_t *page_table_pages, uint64_t *frozen_to_swap_pages);

static void memorystatus_get_task_memory_region_count(task_t task, uint64_t *count);

static uint32_t memorystatus_build_state(proc_t p);
//static boolean_t memorystatus_issue_pressure_kevent(boolean_t pressured);

static bool memorystatus_kill_top_process(bool any, bool sort_flag, uint32_t cause, os_reason_t jetsam_reason,
    int32_t max_priority, bool only_swappable,
    int32_t *priority, uint32_t *errors, uint64_t *memory_reclaimed);
static boolean_t memorystatus_kill_processes_aggressive(uint32_t cause, int aggr_count, int32_t priority_max, int32_t max_kills, uint32_t *errors, uint64_t *memory_reclaimed);
static boolean_t memorystatus_kill_hiwat_proc(uint32_t *errors, boolean_t *purged, uint64_t *memory_reclaimed);

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

#if CONFIG_JETSAM

/* Jetsam Thresholds in MB */
TUNABLE_DT(uint32_t, memorystatus_critical_threshold_mb, "/defaults",
    "kern.memstat_critical_mb", "memorystatus_critical_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_idle_threshold_mb, "/defaults",
    "kern.memstat_idle_mb", "memorystatus_idle_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_pressure_threshold_mb, "/defaults",
    "kern.memstat_pressure_mb", "memorystatus_pressure_threshold_mb", 0, TUNABLE_DT_NONE);
TUNABLE_DT(uint32_t, memorystatus_more_free_offset_mb, "/defaults",
    "kern.memstat_more_free_mb", "memorystatus_more_free_offset_mb", 0, TUNABLE_DT_NONE);

/*
 * Available Pages Thresholds
 *     critical_base: jetsam above the idle band
 *     critical_idle: jetsam in the idle band
 *     more_free_offset: offset applied to critical/idle upon request from userspace
 *     sysproc_aging_aggr: allow aggressive jetsam due to sysproc aging
 *     pressure: jetsam hwm violators
 */
unsigned int memorystatus_available_pages = (unsigned int)-1;
unsigned int memorystatus_available_pages_pressure = 0;
unsigned int memorystatus_available_pages_critical = 0;
unsigned int memorystatus_available_pages_critical_base = 0;
unsigned int memorystatus_available_pages_critical_idle = 0;
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

static unsigned int memorystatus_jetsam_policy = kPolicyDefault;
unsigned int memorystatus_policy_more_free_offset_pages = 0;
static void memorystatus_update_levels_locked(void);

static int memorystatus_cmd_set_jetsam_memory_limit(pid_t pid, int32_t high_water_mark, __unused int32_t *retval, boolean_t is_fatal_limit);

int32_t max_kill_priority = JETSAM_PRIORITY_MAX;

proc_name_t memorystatus_jetsam_proc_name_panic; /* Panic when we are about to jetsam this process. */
uint32_t    memorystatus_jetsam_proc_cause_panic = 0; /* If specified, panic only when we are about to jetsam the process above for this cause. */
uint32_t    memorystatus_jetsam_proc_size_panic = 0; /* If specified, panic only when we are about to jetsam the process above and its footprint is more than this in MB. */

/* If set, kill swappable processes when we're low on swap space. Currently off until we can allocate more swap space (rdar://87800902) */
uint32_t jetsam_kill_on_low_swap = 0;
#else /* CONFIG_JETSAM */

uint64_t memorystatus_available_pages = (uint64_t)-1;
uint64_t memorystatus_available_pages_pressure = (uint64_t)-1;
uint64_t memorystatus_available_pages_critical = (uint64_t)-1;

int32_t max_kill_priority = JETSAM_PRIORITY_IDLE;
#endif /* CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG

static LCK_GRP_DECLARE(disconnect_page_mappings_lck_grp, "disconnect_page_mappings");
static LCK_MTX_DECLARE(disconnect_page_mappings_mutex, &disconnect_page_mappings_lck_grp);

extern bool kill_on_no_paging_space;
#endif /* DEVELOPMENT || DEBUG */

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
	boolean_t use_active;   /* use the active limit and active limit attributes */
	boolean_t is_fatal;

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

	p = memorystatus_get_first_proc_locked(&b, TRUE);
	while (p) {
		use_active = proc_jetsam_state_is_active_locked(p);

		if (enable) {
			if (use_active == TRUE) {
				CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			} else {
				CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			}
		} else {
			/*
			 * Disabling limits does not touch the stored variants.
			 * Set the cached limit fields to system_wide defaults.
			 */
			p->p_memstat_memlimit = -1;
			p->p_memstat_state |= P_MEMSTAT_FATAL_MEMLIMIT;
			is_fatal = TRUE;
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		task_set_phys_footprint_limit_internal(proc_task(p), (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit: -1, NULL, use_active, is_fatal);

		p = memorystatus_get_next_proc_locked(&b, p, TRUE);
	}

	memorystatus_highwater_enabled = enable;

	proc_list_unlock();

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, memorystatus_highwater_enabled, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_highwater_enabled, 0, sysctl_memorystatus_highwater_enable, "I", "");

SYSCTL_INT(_kern, OID_AUTO, memorystatus_idle_snapshot, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_idle_snapshot, 0, "");

#if CONFIG_JETSAM
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_available_pages_critical, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_base, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_available_pages_critical_base, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_critical_idle, CTLFLAG_RD | CTLFLAG_LOCKED, &memorystatus_available_pages_critical_idle, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_policy_more_free_offset_pages, CTLFLAG_RD, &memorystatus_policy_more_free_offset_pages, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_aggr_sysproc_aging, CTLFLAG_RD, &memorystatus_sysproc_aging_aggr_pages, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_kill_on_low_swap, CTLFLAG_RW, &jetsam_kill_on_low_swap, 0, "");
#if VM_PRESSURE_EVENTS

SYSCTL_UINT(_kern, OID_AUTO, memorystatus_available_pages_pressure, CTLFLAG_RW | CTLFLAG_LOCKED, &memorystatus_available_pages_pressure, 0, "");

#endif /* VM_PRESSURE_EVENTS */

#endif /* CONFIG_JETSAM */

#endif /* DEVELOPMENT || DEBUG */

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

jetsam_thread_state_t *jetsam_threads;

/* Maximum number of jetsam threads allowed */
#define JETSAM_THREADS_LIMIT   3

/* Number of active jetsam threads */
_Atomic int active_jetsam_threads = 1;

/* Number of maximum jetsam threads configured */
int max_jetsam_threads = JETSAM_THREADS_LIMIT;

/*
 * Global switch for enabling fast jetsam. Fast jetsam is
 * hooked up via the system_override() system call. It has the
 * following effects:
 * - Raise the jetsam threshold ("clear-the-deck")
 * - Enabled parallel jetsam on eligible devices
 */
#if __AMP__
int fast_jetsam_enabled = 1;
#else /* __AMP__ */
int fast_jetsam_enabled = 0;
#endif /* __AMP__ */

static jetsam_thread_state_t *
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
		 */
		memorystatus_entitled_max_task_footprint_mb = (int32_t) (max_mem_actual / (1ULL << 20));
	}

	if (memorystatus_entitled_max_task_footprint_mb < 0) {
		memorystatus_log_error("Invalid value (%d) for entitled_max_task_pmem. Setting to 0\n",
		    memorystatus_entitled_max_task_footprint_mb);
		memorystatus_entitled_max_task_footprint_mb = 0;
	}
}

#endif /* CONFIG_JETSAM */


__private_extern__ void
memorystatus_init(void)
{
	kern_return_t result;
	int i;

#if CONFIG_FREEZE
	memorystatus_freeze_jetsam_band = JETSAM_PRIORITY_FREEZER;
	memorystatus_frozen_processes_max = FREEZE_PROCESSES_MAX;
	memorystatus_frozen_shared_mb_max = ((MAX_FROZEN_SHARED_MB_PERCENT * max_task_footprint_mb) / 100); /* 10% of the system wide task limit */
	memorystatus_freeze_shared_mb_per_process_max = (memorystatus_frozen_shared_mb_max / 4);
	memorystatus_freeze_pages_min = FREEZE_PAGES_MIN;
	memorystatus_freeze_pages_max = FREEZE_PAGES_MAX;
	memorystatus_max_frozen_demotions_daily = MAX_FROZEN_PROCESS_DEMOTIONS;
	memorystatus_thaw_count_demotion_threshold = MIN_THAW_DEMOTION_THRESHOLD;
	memorystatus_min_thaw_refreeze_threshold = MIN_THAW_REFREEZE_THRESHOLD;
#endif /* CONFIG_FREEZE */

#if DEVELOPMENT || DEBUG
	if (kill_on_no_paging_space) {
		max_kill_priority = JETSAM_PRIORITY_MAX;
	}
#endif
	// Note: no-op pending rdar://27006343 (Custom kernel log handles)
	memorystatus_log_handle = os_log_create("com.apple.xnu", "memorystatus");

	/* Init buckets */
	for (i = 0; i < MEMSTAT_BUCKET_COUNT; i++) {
		TAILQ_INIT(&memstat_bucket[i].list);
		memstat_bucket[i].count = 0;
		memstat_bucket[i].relaunch_high_count = 0;
	}
	memorystatus_idle_demotion_call = thread_call_allocate((thread_call_func_t)memorystatus_perform_idle_demotion, NULL);

	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_sysprocs_idle_delay_time);
	nanoseconds_to_absolutetime((uint64_t)DEFERRED_IDLE_EXIT_TIME_SECS * NSEC_PER_SEC, &memorystatus_apps_idle_delay_time);

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
		memorystatus_available_pages_critical_base = (unsigned int)atop_64((uint64_t)memorystatus_critical_threshold_mb << 20);
	} else if (max_mem <= MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) {
		memorystatus_available_pages_critical_base = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_CRITICAL_BASE_PERCENTAGE_SMALL);
	} else {
		memorystatus_available_pages_critical_base = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_CRITICAL_BASE_PERCENTAGE_LARGE);
	}
	assert(memorystatus_available_pages_critical_base < (unsigned int)atop_64(max_mem));

	/*
	 * For historical reasons, devices with "medium"-sized memory configs have a different critical:idle:pressure ratio
	 */
	if ((memorystatus_idle_threshold_mb != 0)) {
		memorystatus_available_pages_critical_idle = (unsigned int)atop_64((uint64_t)memorystatus_idle_threshold_mb << 20);
	} else {
		if ((max_mem > MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) &&
		    (max_mem <= MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD)) {
			memorystatus_available_pages_critical_idle = (MEMORYSTATUS_CRITICAL_IDLE_RATIO_NUM_MEDIUM * memorystatus_available_pages_critical_base) /
			    MEMORYSTATUS_CRITICAL_IDLE_RATIO_DENOM_MEDIUM;
		} else {
			memorystatus_available_pages_critical_idle = (MEMORYSTATUS_CRITICAL_IDLE_RATIO_NUM * memorystatus_available_pages_critical_base) /
			    MEMORYSTATUS_CRITICAL_IDLE_RATIO_DENOM;
		}
	}
	assert(memorystatus_available_pages_critical_idle < (unsigned int)atop_64(max_mem));

	if (memorystatus_pressure_threshold_mb != 0) {
		memorystatus_available_pages_pressure = (unsigned int)atop_64((uint64_t)memorystatus_pressure_threshold_mb << 20);
	} else {
		if ((max_mem > MEMORYSTATUS_SMALL_MEMORY_THRESHOLD) &&
		    (max_mem <= MEMORYSTATUS_MEDIUM_MEMORY_THRESHOLD)) {
			memorystatus_available_pages_pressure = (MEMORYSTATUS_PRESSURE_RATIO_NUM_MEDIUM * memorystatus_available_pages_critical_base) /
			    MEMORYSTATUS_PRESSURE_RATIO_DENOM_MEDIUM;
		} else {
			memorystatus_available_pages_pressure = (MEMORYSTATUS_PRESSURE_RATIO_NUM * memorystatus_available_pages_critical_base) /
			    MEMORYSTATUS_PRESSURE_RATIO_DENOM;
		}
	}
	assert(memorystatus_available_pages_pressure < (unsigned int)atop_64(max_mem));

	if (memorystatus_more_free_offset_mb != 0) {
		memorystatus_policy_more_free_offset_pages = (unsigned int)atop_64((uint64_t)memorystatus_more_free_offset_mb);
	} else {
		memorystatus_policy_more_free_offset_pages = (unsigned int)MEMSTAT_PERCENT_TOTAL_PAGES(MEMORYSTATUS_MORE_FREE_OFFSET_PERCENTAGE);
	}
	assert(memorystatus_policy_more_free_offset_pages < (unsigned int)atop_64(max_mem));

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

	/* No contention at this point */
	memorystatus_update_levels_locked();

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

	/* Check the boot-arg to see if fast jetsam is allowed */
	if (!PE_parse_boot_argn("fast_jetsam_enabled", &fast_jetsam_enabled, sizeof(fast_jetsam_enabled))) {
		fast_jetsam_enabled = 0;
	}

	/* Check the boot-arg to configure the maximum number of jetsam threads */
	if (!PE_parse_boot_argn("max_jetsam_threads", &max_jetsam_threads, sizeof(max_jetsam_threads))) {
		max_jetsam_threads = JETSAM_THREADS_LIMIT;
	}

	/* Restrict the maximum number of jetsam threads to JETSAM_THREADS_LIMIT */
	if (max_jetsam_threads > JETSAM_THREADS_LIMIT) {
		max_jetsam_threads = JETSAM_THREADS_LIMIT;
	}

	/* For low CPU systems disable fast jetsam mechanism */
	if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
		max_jetsam_threads = 1;
		fast_jetsam_enabled = 0;
	}

#if DEVELOPMENT || DEBUG
	if (PE_parse_boot_argn("-memorystatus-skip-fg-notify", &i, sizeof(i))) {
		memorystatus_should_issue_fg_band_notify = false;
	}
#endif /* DEVELOPMENT || DEBUG */

	/* Initialize the jetsam_threads state array */
	jetsam_threads = zalloc_permanent(sizeof(jetsam_thread_state_t) *
	    max_jetsam_threads, ZALIGN(jetsam_thread_state_t));

	/* Initialize all the jetsam threads */
	for (i = 0; i < max_jetsam_threads; i++) {
		jetsam_threads[i].inited = FALSE;
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

/* Centralised for the purposes of allowing panic-on-jetsam */
extern void
vm_run_compactor(void);
extern void
vm_wake_compactor_swapper(void);

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
static boolean_t
memorystatus_do_kill(proc_t p, uint32_t cause, os_reason_t jetsam_reason, uint64_t *footprint_of_killed_proc)
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
	*footprint_of_killed_proc = ((error == 0) ? footprint : 0);

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_DO_KILL) | DBG_FUNC_END,
	    victim_pid, memstat_effectivepriority, vm_page_free_count, error);

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_COMPACTOR_RUN) | DBG_FUNC_START,
	    victim_pid, cause, vm_page_free_count, *footprint_of_killed_proc);

	if (jetsam_reason->osr_code == JETSAM_REASON_VNODE) {
		/*
		 * vnode jetsams are syncronous and not caused by memory pressure.
		 * Running the compactor on this thread adds significant latency to the filesystem operation
		 * that triggered this jetsam.
		 * Kick of compactor thread asyncronously instead.
		 */
		vm_wake_compactor_swapper();
	} else {
		vm_run_compactor();
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_COMPACTOR_RUN) | DBG_FUNC_END,
	    victim_pid, cause, vm_page_free_count);

	os_reason_free(jetsam_reason);
	return error == 0;
}

/*
 * Node manipulation
 */

static void
memorystatus_check_levels_locked(void)
{
#if CONFIG_JETSAM
	/* Update levels */
	memorystatus_update_levels_locked();
#else /* CONFIG_JETSAM */
	/*
	 * Nothing to do here currently since we update
	 * memorystatus_available_pages in vm_pressure_response.
	 */
#endif /* CONFIG_JETSAM */
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

	if (op_flags == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE) {
		enable = TRUE;
	} else if (op_flags == MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE) {
		enable = FALSE;
	} else {
		return EINVAL;
	}

	p = proc_find(pid);
	if (p != NULL) {
		if ((enable && ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) == P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND)) ||
		    (!enable && ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) == 0))) {
			/*
			 * No change in state.
			 */
		} else {
			proc_list_lock();

			if (enable) {
				p->p_memstat_state |= P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;
				memorystatus_invalidate_idle_demotion_locked(p, TRUE);

				if (effective_now) {
					if (p->p_memstat_effectivepriority < jetsam_prio) {
						if (memorystatus_highwater_enabled) {
							/*
							 * Process is about to transition from
							 * inactive --> active
							 * assign active state
							 */
							boolean_t is_fatal;
							boolean_t use_active = TRUE;
							CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
							task_set_phys_footprint_limit_internal(proc_task(p), (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1, NULL, use_active, is_fatal);
						}
						memorystatus_update_priority_locked(p, jetsam_prio, FALSE, FALSE);
					}
				} else {
					if (isProcessInAgingBands(p)) {
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
					}
				}
			} else {
				p->p_memstat_state &= ~P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND;
				memorystatus_invalidate_idle_demotion_locked(p, TRUE);

				if (effective_now) {
					if (p->p_memstat_effectivepriority == jetsam_prio) {
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
					}
				} else {
					if (isProcessInAgingBands(p)) {
						memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
					}
				}
			}

			proc_list_unlock();
		}
		proc_rele(p);
		error = 0;
	} else {
		error = ESRCH;
	}

	return error;
}

static void
memorystatus_perform_idle_demotion(__unused void *spare1, __unused void *spare2)
{
	proc_t p;
	uint64_t current_time = 0, idle_delay_time = 0;
	int demote_prio_band = 0;
	memstat_bucket_t *demotion_bucket;

	memorystatus_log_debug("memorystatus_perform_idle_demotion()\n");

	if (!system_procs_aging_band && !applications_aging_band) {
		return;
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_START);

	current_time = mach_absolute_time();

	proc_list_lock();

	demote_prio_band = JETSAM_PRIORITY_IDLE + 1;

	for (; demote_prio_band < JETSAM_PRIORITY_MAX; demote_prio_band++) {
		if (demote_prio_band != system_procs_aging_band && demote_prio_band != applications_aging_band) {
			continue;
		}

		demotion_bucket = &memstat_bucket[demote_prio_band];
		p = TAILQ_FIRST(&demotion_bucket->list);

		while (p) {
			memorystatus_log_debug("memorystatus_perform_idle_demotion() found %d\n", proc_getpid(p));

			assert(p->p_memstat_idledeadline);

			assert(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS);

			if (current_time >= p->p_memstat_idledeadline) {
				if ((isSysProc(p) &&
				    ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED | P_DIRTY_IS_DIRTY)) != P_DIRTY_IDLE_EXIT_ENABLED)) || /* system proc marked dirty*/
				    task_has_assertions((struct task *)(proc_task(p)))) {     /* has outstanding assertions which might indicate outstanding work too */
					idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_time(p) : memorystatus_apps_idle_time(p);

					p->p_memstat_idledeadline += idle_delay_time;
					p = TAILQ_NEXT(p, p_memstat_list);
				} else {
					proc_t next_proc = NULL;

					next_proc = TAILQ_NEXT(p, p_memstat_list);
					memorystatus_invalidate_idle_demotion_locked(p, TRUE);

					memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, false, true);

					p = next_proc;
					continue;
				}
			} else {
				// No further candidates
				break;
			}
		}
	}

	memorystatus_reschedule_idle_demotion_locked();

	proc_list_unlock();

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_IDLE_DEMOTE) | DBG_FUNC_END);
}

static void
memorystatus_schedule_idle_demotion_locked(proc_t p, boolean_t set_state)
{
	boolean_t present_in_sysprocs_aging_bucket = FALSE;
	boolean_t present_in_apps_aging_bucket = FALSE;
	uint64_t  idle_delay_time = 0;

	if (!system_procs_aging_band && !applications_aging_band) {
		return;
	}

	if ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) ||
	    (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION)) {
		/*
		 * This process isn't going to be making the trip to the lower bands.
		 */
		return;
	}

	if (isProcessInAgingBands(p)) {
		assert((p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) != P_DIRTY_AGING_IN_PROGRESS);

		if (isSysProc(p) && system_procs_aging_band) {
			present_in_sysprocs_aging_bucket = TRUE;
		} else if (isApp(p) && applications_aging_band) {
			present_in_apps_aging_bucket = TRUE;
		}
	}

	assert(!present_in_sysprocs_aging_bucket);
	assert(!present_in_apps_aging_bucket);

	memorystatus_log_info(
		"memorystatus_schedule_idle_demotion_locked: scheduling demotion to idle band for pid %d (dirty:0x%x, set_state %d, demotions %d).\n",
		proc_getpid(p), p->p_memstat_dirty, set_state, (memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps));

	if (isSysProc(p)) {
		assert((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED);
	}

	idle_delay_time = (isSysProc(p)) ? memorystatus_sysprocs_idle_time(p) : memorystatus_apps_idle_time(p);
	if (set_state) {
		p->p_memstat_dirty |= P_DIRTY_AGING_IN_PROGRESS;
		p->p_memstat_idledeadline = mach_absolute_time() + idle_delay_time;
	}

	assert(p->p_memstat_idledeadline);

	if (isSysProc(p) && present_in_sysprocs_aging_bucket == FALSE) {
		memorystatus_scheduled_idle_demotions_sysprocs++;
	} else if (isApp(p) && present_in_apps_aging_bucket == FALSE) {
		memorystatus_scheduled_idle_demotions_apps++;
	}
}

void
memorystatus_invalidate_idle_demotion_locked(proc_t p, boolean_t clear_state)
{
	boolean_t present_in_sysprocs_aging_bucket = FALSE;
	boolean_t present_in_apps_aging_bucket = FALSE;

	if (!system_procs_aging_band && !applications_aging_band) {
		return;
	}

	if ((p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) == 0) {
		return;
	}

	if (isProcessInAgingBands(p)) {
		assert((p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) == P_DIRTY_AGING_IN_PROGRESS);

		if (isSysProc(p) && system_procs_aging_band) {
			assert(p->p_memstat_effectivepriority == system_procs_aging_band);
			assert(p->p_memstat_idledeadline);
			present_in_sysprocs_aging_bucket = TRUE;
		} else if (isApp(p) && applications_aging_band) {
			assert(p->p_memstat_effectivepriority == applications_aging_band);
			assert(p->p_memstat_idledeadline);
			present_in_apps_aging_bucket = TRUE;
		}
	}

	memorystatus_log_info(
		"memorystatus_invalidate_idle_demotion(): invalidating demotion to idle band for pid %d (clear_state %d, demotions %d).\n",
		proc_getpid(p), clear_state, (memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps));


	if (clear_state) {
		p->p_memstat_idledeadline = 0;
		p->p_memstat_dirty &= ~P_DIRTY_AGING_IN_PROGRESS;
	}

	if (isSysProc(p) && present_in_sysprocs_aging_bucket == TRUE) {
		memorystatus_scheduled_idle_demotions_sysprocs--;
		assert(memorystatus_scheduled_idle_demotions_sysprocs >= 0);
	} else if (isApp(p) && present_in_apps_aging_bucket == TRUE) {
		memorystatus_scheduled_idle_demotions_apps--;
		assert(memorystatus_scheduled_idle_demotions_apps >= 0);
	}

	assert((memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps) >= 0);
}

static void
memorystatus_reschedule_idle_demotion_locked(void)
{
	if (!system_procs_aging_band && !applications_aging_band) {
		return;
	}

	if (0 == (memorystatus_scheduled_idle_demotions_sysprocs + memorystatus_scheduled_idle_demotions_apps)) {
		if (memstat_idle_demotion_deadline) {
			/* Transitioned 1->0, so cancel next call */
			thread_call_cancel(memorystatus_idle_demotion_call);
			memstat_idle_demotion_deadline = 0;
		}
	} else {
		memstat_bucket_t *demotion_bucket;
		proc_t p = NULL, p1 = NULL, p2 = NULL;

		if (system_procs_aging_band) {
			demotion_bucket = &memstat_bucket[system_procs_aging_band];
			p1 = TAILQ_FIRST(&demotion_bucket->list);

			p = p1;
		}

		if (applications_aging_band) {
			demotion_bucket = &memstat_bucket[applications_aging_band];
			p2 = TAILQ_FIRST(&demotion_bucket->list);

			if (p1 && p2) {
				p = (p1->p_memstat_idledeadline > p2->p_memstat_idledeadline) ? p2 : p1;
			} else {
				p = (p1 == NULL) ? p2 : p1;
			}
		}

		assert(p);

		if (p != NULL) {
			assert(p && p->p_memstat_idledeadline);
			if (memstat_idle_demotion_deadline != p->p_memstat_idledeadline) {
				thread_call_enter_delayed(memorystatus_idle_demotion_call, p->p_memstat_idledeadline);
				memstat_idle_demotion_deadline = p->p_memstat_idledeadline;
			}
		}
	}
}

/*
 * List manipulation
 */

int
memorystatus_add(proc_t p, boolean_t locked)
{
	memstat_bucket_t *bucket;

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

	if (isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) {
		assert(bucket->count == memorystatus_scheduled_idle_demotions_sysprocs - 1);
	} else if (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)) {
		assert(bucket->count == memorystatus_scheduled_idle_demotions_apps - 1);
	} else if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Entering the idle band.
		 * Record idle start time.
		 */
		p->p_memstat_idle_start = mach_absolute_time();
	}

	TAILQ_INSERT_TAIL(&bucket->list, p, p_memstat_list);
	bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		bucket->relaunch_high_count++;
	}

	memorystatus_list_count++;

	memorystatus_check_levels_locked();

exit:
	if (!locked) {
		proc_list_unlock();
	}

	return 0;
}

/*
 * Description:
 *	Moves a process from one jetsam bucket to another.
 *	which changes the LRU position of the process.
 *
 *	Monitors transition between buckets and if necessary
 *	will update cached memory limits accordingly.
 *
 *	skip_demotion_check:
 *	- if the 'jetsam aging policy' is NOT 'legacy':
 *		When this flag is TRUE, it means we are going
 *		to age the ripe processes out of the aging bands and into the
 *		IDLE band and apply their inactive memory limits.
 *
 *	- if the 'jetsam aging policy' is 'legacy':
 *		When this flag is TRUE, it might mean the above aging mechanism
 *		OR
 *		It might be that we have a process that has used up its 'idle deferral'
 *		stay that is given to it once per lifetime. And in this case, the process
 *		won't be going through any aging codepaths. But we still need to apply
 *		the right inactive limits and so we explicitly set this to TRUE if the
 *		new priority for the process is the IDLE band.
 */
void
memorystatus_update_priority_locked(proc_t p, int priority, boolean_t head_insert, boolean_t skip_demotion_check)
{
	memstat_bucket_t *old_bucket, *new_bucket;

	assert(priority < MEMSTAT_BUCKET_COUNT);

	/* Ensure that exit isn't underway, leaving the proc retained but removed from its bucket */
	if (proc_list_exited(p)) {
		return;
	}

	memorystatus_log_info("memorystatus_update_priority_locked(): setting %s(%d) to priority %d, inserting at %s\n",
	    (*p->p_name ? p->p_name : "unknown"), proc_getpid(p), priority, head_insert ? "head" : "tail");

	DTRACE_MEMORYSTATUS3(memorystatus_update_priority, proc_t, p, int32_t, p->p_memstat_effectivepriority, int, priority);

	old_bucket = &memstat_bucket[p->p_memstat_effectivepriority];

	if (skip_demotion_check == FALSE) {
		if (isSysProc(p)) {
			/*
			 * For system processes, the memorystatus_dirty_* routines take care of adding/removing
			 * the processes from the aging bands and balancing the demotion counts.
			 * We can, however, override that if the process has an 'elevated inactive jetsam band' attribute.
			 */

			if (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) {
				/*
				 * 2 types of processes can use the non-standard elevated inactive band:
				 * - Frozen processes that always land in memorystatus_freeze_jetsam_band
				 * OR
				 * - processes that specifically opt-in to the elevated inactive support e.g. docked processes.
				 */
#if CONFIG_FREEZE
				if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
					if (priority <= memorystatus_freeze_jetsam_band) {
						priority = memorystatus_freeze_jetsam_band;
					}
				} else
#endif /* CONFIG_FREEZE */
				{
					if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE) {
						priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
					}
				}
				assert(!(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS));
			}
		} else if (isApp(p)) {
			/*
			 * Check to see if the application is being lowered in jetsam priority. If so, and:
			 * - it has an 'elevated inactive jetsam band' attribute, then put it in the appropriate band.
			 * - it is a normal application, then let it age in the aging band if that policy is in effect.
			 */

			if (p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) {
#if CONFIG_FREEZE
				if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
					if (priority <= memorystatus_freeze_jetsam_band) {
						priority = memorystatus_freeze_jetsam_band;
					}
				} else
#endif /* CONFIG_FREEZE */
				{
					if (priority <= JETSAM_PRIORITY_ELEVATED_INACTIVE) {
						priority = JETSAM_PRIORITY_ELEVATED_INACTIVE;
					}
				}
			} else {
				if (applications_aging_band) {
					if (p->p_memstat_effectivepriority == applications_aging_band) {
						assert(old_bucket->count == (memorystatus_scheduled_idle_demotions_apps + 1));
					}

					if (priority <= applications_aging_band) {
						assert(!(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS));
						priority = applications_aging_band;
						memorystatus_schedule_idle_demotion_locked(p, TRUE);
					}
				}
			}
		}
	}

	if ((system_procs_aging_band && (priority == system_procs_aging_band)) || (applications_aging_band && (priority == applications_aging_band))) {
		assert(p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS);
	}

#if DEVELOPMENT || DEBUG
	if (priority == JETSAM_PRIORITY_IDLE &&                         /* if the process is on its way into the IDLE band */
	    (system_procs_aging_band && applications_aging_band) &&     /* we have support for _both_ aging bands */
	    (skip_demotion_check == FALSE) &&                           /* and it isn't via the path that will set the INACTIVE memlimits */
	    (p->p_memstat_dirty & P_DIRTY_TRACK) &&                     /* and it has 'DIRTY' tracking enabled */
	    ((p->p_memstat_memlimit != p->p_memstat_memlimit_inactive) || /* and we notice that the current limit isn't the right value (inactive) */
	    ((p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) ? (!(p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)) : (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)))) { /* OR type (fatal vs non-fatal) */
		memorystatus_log_error("memorystatus_update_priority_locked: on %s with 0x%x, prio: %d and %d\n",
		    p->p_name, p->p_memstat_state, priority, p->p_memstat_memlimit); /* then we must catch this */
	}
#endif /* DEVELOPMENT || DEBUG */

	TAILQ_REMOVE(&old_bucket->list, p, p_memstat_list);
	old_bucket->count--;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		old_bucket->relaunch_high_count--;
	}

	new_bucket = &memstat_bucket[priority];
	if (head_insert) {
		TAILQ_INSERT_HEAD(&new_bucket->list, p, p_memstat_list);
	} else {
		TAILQ_INSERT_TAIL(&new_bucket->list, p, p_memstat_list);
	}
	new_bucket->count++;
	if (p->p_memstat_relaunch_flags & (P_MEMSTAT_RELAUNCH_HIGH)) {
		new_bucket->relaunch_high_count++;
	}

	if (memorystatus_highwater_enabled) {
		boolean_t is_fatal;
		boolean_t use_active;

		/*
		 * If cached limit data is updated, then the limits
		 * will be enforced by writing to the ledgers.
		 */
		boolean_t ledger_update_needed = TRUE;

		/*
		 * Here, we must update the cached memory limit if the task
		 * is transitioning between:
		 *      active <--> inactive
		 *	FG     <-->       BG
		 * but:
		 *	dirty  <-->    clean   is ignored
		 *
		 * We bypass non-idle processes that have opted into dirty tracking because
		 * a move between buckets does not imply a transition between the
		 * dirty <--> clean state.
		 */

		if (p->p_memstat_dirty & P_DIRTY_TRACK) {
			if (skip_demotion_check == TRUE && priority == JETSAM_PRIORITY_IDLE) {
				CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
				use_active = FALSE;
			} else {
				ledger_update_needed = FALSE;
			}
		} else if ((priority >= JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority < JETSAM_PRIORITY_FOREGROUND)) {
			/*
			 *      inactive --> active
			 *	BG       -->     FG
			 *      assign active state
			 */
			CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = TRUE;
		} else if ((priority < JETSAM_PRIORITY_FOREGROUND) && (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND)) {
			/*
			 *      active --> inactive
			 *	FG     -->       BG
			 *      assign inactive state
			 */
			CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = FALSE;
		} else {
			/*
			 * The transition between jetsam priority buckets apparently did
			 * not affect active/inactive state.
			 * This is not unusual... especially during startup when
			 * processes are getting established in their respective bands.
			 */
			ledger_update_needed = FALSE;
		}

		/*
		 * Enforce the new limits by writing to the ledger
		 */
		if (ledger_update_needed) {
			task_set_phys_footprint_limit_internal(proc_task(p), (p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1, NULL, use_active, is_fatal);

			memorystatus_log_info("memorystatus_update_priority_locked: new limit on pid %d (%dMB %s) priority old --> new (%d --> %d) dirty?=0x%x %s\n",
			    proc_getpid(p), (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
			    (p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, priority, p->p_memstat_dirty,
			    (p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
		}
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
		uint64_t now;
		/*
		 * Transitioning out of the idle priority bucket.
		 * Record idle delta.
		 */
		assert(p->p_memstat_idle_start != 0);
		now = mach_absolute_time();
		if (now > p->p_memstat_idle_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_idle_start;
		}

		/*
		 * About to become active and so memory footprint could change.
		 * So mark it eligible for freeze-considerations next time around.
		 */
		if (p->p_memstat_state & P_MEMSTAT_FREEZE_IGNORE) {
			p->p_memstat_state &= ~P_MEMSTAT_FREEZE_IGNORE;
		}
	} else if (priority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Transitioning into the idle priority bucket.
		 * Record idle start.
		 */
		p->p_memstat_idle_start = mach_absolute_time();
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_CHANGE_PRIORITY), proc_getpid(p), priority, p->p_memstat_effectivepriority);

	p->p_memstat_effectivepriority = priority;

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_apps &&
	    task_could_use_secluded_mem(proc_task(p))) {
		task_set_can_use_secluded_mem(
			proc_task(p),
			(priority >= JETSAM_PRIORITY_FOREGROUND));
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	memorystatus_check_levels_locked();
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
 *
 * Description: Update the jetsam priority and memory limit attributes for a given process.
 *
 * Parameters:
 *	p	init this process's jetsam information.
 *	priority          The jetsam priority band
 *	user_data	  user specific data, unused by the kernel
 *	is_assertion	  When true, a priority update is driven by an assertion.
 *	effective	  guards against race if process's update already occurred
 *	update_memlimit   When true we know this is the init step via the posix_spawn path.
 *
 *	memlimit_active	  Value in megabytes; The monitored footprint level while the
 *			  process is active.  Exceeding it may result in termination
 *			  based on it's associated fatal flag.
 *
 *	memlimit_active_is_fatal  When a process is active and exceeds its memory footprint,
 *				  this describes whether or not it should be immediately fatal.
 *
 *	memlimit_inactive Value in megabytes; The monitored footprint level while the
 *			  process is inactive.  Exceeding it may result in termination
 *			  based on it's associated fatal flag.
 *
 *	memlimit_inactive_is_fatal  When a process is inactive and exceeds its memory footprint,
 *				    this describes whether or not it should be immediatly fatal.
 *
 * Returns:     0	Success
 *		non-0	Failure
 */

int
memorystatus_update(proc_t p, int priority, uint64_t user_data, boolean_t is_assertion, boolean_t effective, boolean_t update_memlimit,
    int32_t memlimit_active, boolean_t memlimit_active_is_fatal,
    int32_t memlimit_inactive, boolean_t memlimit_inactive_is_fatal)
{
	int ret;
	boolean_t head_insert = false;

	memorystatus_log_info("memorystatus_update: changing (%s) pid %d: priority %d, user_data 0x%llx\n",
	    (*p->p_name ? p->p_name : "unknown"), proc_getpid(p), priority, user_data);

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_UPDATE) | DBG_FUNC_START, proc_getpid(p), priority, user_data, effective);

	if (priority == -1) {
		/* Use as shorthand for default priority */
		priority = JETSAM_PRIORITY_DEFAULT;
	} else if (priority > JETSAM_PRIORITY_IDLE && priority <= applications_aging_band) {
		/*
		 * Everything between idle and the aging bands are reserved for internal use.
		 * if requested, adjust to JETSAM_PRIORITY_IDLE.
		 * Entitled processes (just munch) can use a subset of this range for testing.
		 */
		if (priority > JETSAM_PRIORITY_ENTITLED_MAX ||
		    !current_task_can_use_entitled_range()) {
			priority = JETSAM_PRIORITY_IDLE;
		}
	} else if (priority == JETSAM_PRIORITY_IDLE_HEAD) {
		/* JETSAM_PRIORITY_IDLE_HEAD inserts at the head of the idle queue */
		priority = JETSAM_PRIORITY_IDLE;
		head_insert = TRUE;
	} else if ((priority < 0) || (priority >= MEMSTAT_BUCKET_COUNT)) {
		/* Sanity check */
		ret = EINVAL;
		goto out;
	}

	proc_list_lock();

	assert(!(p->p_memstat_state & P_MEMSTAT_INTERNAL));

	if (effective && (p->p_memstat_state & P_MEMSTAT_PRIORITYUPDATED)) {
		ret = EALREADY;
		proc_list_unlock();
		memorystatus_log_debug("memorystatus_update: effective change specified for pid %d, but change already occurred.\n",
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

	if (is_assertion) {
		if (priority == JETSAM_PRIORITY_IDLE) {
			/*
			 * Assertions relinquish control when the process is heading to IDLE.
			 */
			if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
				/*
				 * Mark the process as no longer being managed by assertions.
				 */
				p->p_memstat_state &= ~P_MEMSTAT_PRIORITY_ASSERTION;
			} else {
				/*
				 * Ignore an idle priority transition if the process is not
				 * already managed by assertions.  We won't treat this as
				 * an error, but we will log the unexpected behavior and bail.
				 */
				memorystatus_log_error(
					"memorystatus: Ignore assertion driven idle priority. Process not previously controlled %s:%d\n",
					(*p->p_name ? p->p_name : "unknown"), proc_getpid(p));

				ret = 0;
				proc_list_unlock();
				goto out;
			}
		} else {
			/*
			 * Process is now being managed by assertions,
			 */
			p->p_memstat_state |= P_MEMSTAT_PRIORITY_ASSERTION;
		}

		/* Always update the assertion priority in this path */

		p->p_memstat_assertionpriority = priority;

		int memstat_dirty_flags = memorystatus_dirty_get(p, TRUE);  /* proc_list_lock is held */

		if (memstat_dirty_flags != 0) {
			/*
			 * Calculate maximum priority only when dirty tracking processes are involved.
			 */
			int maxpriority;
			if (memstat_dirty_flags & PROC_DIRTY_IS_DIRTY) {
				maxpriority = MAX(p->p_memstat_assertionpriority, p->p_memstat_requestedpriority);
			} else {
				/* clean */

				if (memstat_dirty_flags & PROC_DIRTY_ALLOWS_IDLE_EXIT) {
					/*
					 * The aging policy must be evaluated and applied here because runnningboardd
					 * has relinquished its hold on the jetsam priority by attempting to move a
					 * clean process to the idle band.
					 */

					int newpriority = JETSAM_PRIORITY_IDLE;
					if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED | P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED) {
						newpriority = (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) ? system_procs_aging_band : JETSAM_PRIORITY_IDLE;
					}

					maxpriority = MAX(p->p_memstat_assertionpriority, newpriority );

					if (newpriority == system_procs_aging_band) {
						memorystatus_schedule_idle_demotion_locked(p, FALSE);
					}
				} else {
					/*
					 * Preserves requestedpriority when the process does not support pressured exit.
					 */
					maxpriority = MAX(p->p_memstat_assertionpriority, p->p_memstat_requestedpriority);
				}
			}
			priority = maxpriority;
		}
	} else {
		p->p_memstat_requestedpriority = priority;
	}

	if (update_memlimit) {
		boolean_t is_fatal;
		boolean_t use_active;

		/*
		 * Posix_spawn'd processes come through this path to instantiate ledger limits.
		 * Forked processes do not come through this path, so no ledger limits exist.
		 * (That's why forked processes can consume unlimited memory.)
		 */

		memorystatus_log_info(
			"memorystatus_update: update memlimit (%s) pid %d, priority %d, dirty=0x%x, Active(%dMB %s), Inactive(%dMB, %s)\n",
			(*p->p_name ? p->p_name : "unknown"), proc_getpid(p), priority, p->p_memstat_dirty,
			memlimit_active, (memlimit_active_is_fatal ? "F " : "NF"),
			memlimit_inactive, (memlimit_inactive_is_fatal ? "F " : "NF"));

		if (memlimit_active <= 0) {
			/*
			 * This process will have a system_wide task limit when active.
			 * System_wide task limit is always fatal.
			 * It's quite common to see non-fatal flag passed in here.
			 * It's not an error, we just ignore it.
			 */

			/*
			 * For backward compatibility with some unexplained launchd behavior,
			 * we allow a zero sized limit.  But we still enforce system_wide limit
			 * when written to the ledgers.
			 */

			if (memlimit_active < 0) {
				memlimit_active = -1;  /* enforces system_wide task limit */
			}
			memlimit_active_is_fatal = TRUE;
		}

		if (memlimit_inactive <= 0) {
			/*
			 * This process will have a system_wide task limit when inactive.
			 * System_wide task limit is always fatal.
			 */

			memlimit_inactive = -1;
			memlimit_inactive_is_fatal = TRUE;
		}

		/*
		 * Initialize the active limit variants for this process.
		 */
		SET_ACTIVE_LIMITS_LOCKED(p, memlimit_active, memlimit_active_is_fatal);

		/*
		 * Initialize the inactive limit variants for this process.
		 */
		SET_INACTIVE_LIMITS_LOCKED(p, memlimit_inactive, memlimit_inactive_is_fatal);

		/*
		 * Initialize the cached limits for target process.
		 * When the target process is dirty tracked, it's typically
		 * in a clean state.  Non dirty tracked processes are
		 * typically active (Foreground or above).
		 * But just in case, we don't make assumptions...
		 */

		if (proc_jetsam_state_is_active_locked(p) == TRUE) {
			CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = TRUE;
		} else {
			CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = FALSE;
		}

		/*
		 * Enforce the cached limit by writing to the ledger.
		 */
		if (memorystatus_highwater_enabled) {
			/* apply now */
			task_set_phys_footprint_limit_internal(proc_task(p),
			    ((p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1), NULL, use_active, is_fatal);
		}
	}

	/*
	 * We can't add to the aging bands buckets here.
	 * But, we could be removing it from those buckets.
	 * Check and take appropriate steps if so.
	 */

	if (isProcessInAgingBands(p)) {
		if (isApp(p) && (priority > applications_aging_band)) {
			/*
			 * Runningboardd is pulling up an application that is in the aging band.
			 * We reset the app's state here so that it'll get a fresh stay in the
			 * aging band on the way back.
			 *
			 * We always handled the app 'aging' in the memorystatus_update_priority_locked()
			 * function. Daemons used to be handled via the dirty 'set/clear/track' path.
			 * But with extensions (daemon-app hybrid), runningboardd is now going through
			 * this routine for daemons too and things have gotten a bit tangled. This should
			 * be simplified/untangled at some point and might require some assistance from
			 * runningboardd.
			 */
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		} else {
			memorystatus_invalidate_idle_demotion_locked(p, FALSE);
		}
		memorystatus_update_priority_locked(p, JETSAM_PRIORITY_IDLE, FALSE, TRUE);
	}

	memorystatus_update_priority_locked(p, priority, head_insert, FALSE);

	proc_list_unlock();
	ret = 0;

out:
	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_UPDATE) | DBG_FUNC_END, ret);

	return ret;
}

int
memorystatus_remove(proc_t p)
{
	int ret;
	memstat_bucket_t *bucket;
	boolean_t       reschedule = FALSE;

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

	if (isSysProc(p) && system_procs_aging_band && (p->p_memstat_effectivepriority == system_procs_aging_band)) {
		assert(bucket->count == memorystatus_scheduled_idle_demotions_sysprocs);
		reschedule = TRUE;
	} else if (isApp(p) && applications_aging_band && (p->p_memstat_effectivepriority == applications_aging_band)) {
		assert(bucket->count == memorystatus_scheduled_idle_demotions_apps);
		reschedule = TRUE;
	}

	/*
	 * Record idle delta
	 */

	if (p->p_memstat_effectivepriority == JETSAM_PRIORITY_IDLE) {
		uint64_t now = mach_absolute_time();
		if (now > p->p_memstat_idle_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_idle_start;
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
		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		memorystatus_reschedule_idle_demotion_locked();
	}

	memorystatus_check_levels_locked();

#if CONFIG_FREEZE
	if (p->p_memstat_state & (P_MEMSTAT_FROZEN)) {
		if (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) {
			p->p_memstat_state &= ~P_MEMSTAT_REFREEZE_ELIGIBLE;
			memorystatus_refreeze_eligible_count--;
		}

		memorystatus_frozen_count--;
		if (p->p_memstat_state & P_MEMSTAT_FROZEN_XPC_SERVICE) {
			memorystatus_frozen_count_xpc_service--;
		}
		if (strcmp(p->p_name, "com.apple.WebKit.WebContent") == 0) {
			memorystatus_frozen_count_webcontent--;
		}
		memorystatus_frozen_shared_mb -= p->p_memstat_freeze_sharedanon_pages;
		p->p_memstat_freeze_sharedanon_pages = 0;
	}

	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		memorystatus_suspended_count--;
	}
#endif

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

static void
memorystatus_update_idle_priority_locked(proc_t p)
{
	int32_t priority;

	memorystatus_log_debug("memorystatus_update_idle_priority_locked(): pid %d dirty 0x%X\n",
	    proc_getpid(p), p->p_memstat_dirty);

	assert(isSysProc(p));

	if ((p->p_memstat_dirty & (P_DIRTY_IDLE_EXIT_ENABLED | P_DIRTY_IS_DIRTY)) == P_DIRTY_IDLE_EXIT_ENABLED) {
		priority = (p->p_memstat_dirty & P_DIRTY_AGING_IN_PROGRESS) ? system_procs_aging_band : JETSAM_PRIORITY_IDLE;
	} else {
		priority = p->p_memstat_requestedpriority;
	}

	if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
		/*
		 * This process has a jetsam priority managed by an assertion.
		 * Policy is to choose the max priority.
		 */
		if (p->p_memstat_assertionpriority > priority) {
			memorystatus_log_debug("memorystatus: assertion priority %d overrides priority %d for %s:%d\n",
			    p->p_memstat_assertionpriority, priority,
			    (*p->p_name ? p->p_name : "unknown"), proc_getpid(p));
			priority = p->p_memstat_assertionpriority;
		}
	}

	if (priority != p->p_memstat_effectivepriority) {
		memorystatus_update_priority_locked(p, priority, false, false);
	}
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
	boolean_t reschedule = FALSE;
	boolean_t already_deferred = FALSE;
	boolean_t defer_now = FALSE;
	int ret = 0;

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
		/*Request to turn ON Dirty tracking...*/
		if (p->p_memstat_state & P_MEMSTAT_MANAGED) {
			/* on a process managed by RunningBoard or its equivalent...*/
			if (!(p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT)) {
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
#if DEVELOPMENT || DEBUG
				memorystatus_log_info(
					"memorystatus: Denying dirty-tracking opt-in for app %s (pid %d)\n",
					(*p->p_name ? p->p_name : "unknown"), proc_getpid(p));
#endif /*DEVELOPMENT || DEBUG*/
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

	if (old_dirty & P_DIRTY_AGING_IN_PROGRESS) {
		already_deferred = TRUE;
	}


	/* This can be set and cleared exactly once. */
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
		"memorystatus_on_track_dirty(): set idle-exit %s / defer %s / dirty %s for pid %d\n",
		((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) ? "Y" : "N",
		defer_now ? "Y" : "N", p->p_memstat_dirty & P_DIRTY ? "Y" : "N", proc_getpid(p));

	/* Kick off or invalidate the idle exit deferment if there's a state transition. */
	if (!(p->p_memstat_dirty & P_DIRTY_IS_DIRTY)) {
		if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {
			if (defer_now && !already_deferred) {
				/*
				 * Request to defer a clean process that's idle-exit enabled
				 * and not already in the jetsam deferred band. Most likely a
				 * new launch.
				 */
				memorystatus_schedule_idle_demotion_locked(p, TRUE);
				reschedule = TRUE;
			} else if (!defer_now) {
				/*
				 * The process isn't asking for the 'aging' facility.
				 * Could be that it is:
				 */

				if (already_deferred) {
					/*
					 * already in the aging bands. Traditionally,
					 * some processes have tried to use this to
					 * opt out of the 'aging' facility.
					 */

					memorystatus_invalidate_idle_demotion_locked(p, TRUE);
				} else {
					/*
					 * agnostic to the 'aging' facility. In that case,
					 * we'll go ahead and opt it in because this is likely
					 * a new launch (clean process, dirty tracking enabled)
					 */

					memorystatus_schedule_idle_demotion_locked(p, TRUE);
				}

				reschedule = TRUE;
			}
		}
	} else {
		/*
		 * We are trying to operate on a dirty process. Dirty processes have to
		 * be removed from the deferred band & their state has to be reset.
		 *
		 * This could be a legal request like:
		 * - this process had opted into the 'aging' band
		 * - but it's now dirty and requests to opt out.
		 * In this case, we remove the process from the band and reset its
		 * state too. It'll opt back in properly when needed.
		 *
		 * OR, this request could be a user-space bug. E.g.:
		 * - this process had opted into the 'aging' band when clean
		 * - and, then issues another request to again put it into the band except
		 *   this time the process is dirty.
		 * The process going dirty, as a transition in memorystatus_dirty_set(), will pull the process out of
		 * the deferred band with its state intact. So our request below is no-op.
		 * But we do it here anyways for coverage.
		 *
		 * memorystatus_update_idle_priority_locked()
		 * single-mindedly treats a dirty process as "cannot be in the aging band".
		 */

		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		reschedule = TRUE;
	}

	memorystatus_update_idle_priority_locked(p);

	if (reschedule) {
		memorystatus_reschedule_idle_demotion_locked();
	}

	ret = 0;

exit:
	proc_list_unlock();

	return ret;
}

int
memorystatus_dirty_set(proc_t p, boolean_t self, uint32_t pcontrol)
{
	int ret;
	boolean_t kill = false;
	boolean_t reschedule = FALSE;
	boolean_t was_dirty = FALSE;
	boolean_t now_dirty = FALSE;

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

	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
		was_dirty = TRUE;
	}

	if (!(p->p_memstat_dirty & P_DIRTY_TRACK)) {
		/* Dirty tracking not enabled */
		ret = EINVAL;
	} else if (pcontrol && (p->p_memstat_dirty & P_DIRTY_TERMINATED)) {
		/*
		 * Process is set to be terminated and we're attempting to mark it dirty.
		 * Set for termination and marking as clean is OK - see <rdar://problem/10594349>.
		 */
		ret = EBUSY;
	} else {
		int flag = (self == TRUE) ? P_DIRTY : P_DIRTY_SHUTDOWN;
		if (pcontrol && !(p->p_memstat_dirty & flag)) {
			/* Mark the process as having been dirtied at some point */
			p->p_memstat_dirty |= (flag | P_DIRTY_MARKED);
			memorystatus_dirty_count++;
			ret = 0;
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
			memorystatus_dirty_count--;
			ret = 0;
		} else {
			/* Already set */
			ret = EALREADY;
		}
	}

	if (ret != 0) {
		goto exit;
	}

	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
		now_dirty = TRUE;
	}

	if ((was_dirty == TRUE && now_dirty == FALSE) ||
	    (was_dirty == FALSE && now_dirty == TRUE)) {
		/* Manage idle exit deferral, if applied */
		if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {
			/*
			 * Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band OR it might be heading back
			 * there once it's clean again. For the legacy case, this only applies if it has some protection window left.
			 * P_DIRTY_DEFER: one-time protection window given at launch
			 * P_DIRTY_DEFER_ALWAYS: protection window given for every dirty->clean transition. Like non-legacy mode.
			 *
			 * Non-Legacy mode: P_DIRTY_AGING_IN_PROGRESS means the process is in the aging band. It will always stop over
			 * in that band on it's way to IDLE.
			 */

			if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
				/*
				 * New dirty process i.e. "was_dirty == FALSE && now_dirty == TRUE"
				 *
				 * The process will move from its aging band to its higher requested
				 * jetsam band.
				 */
				memorystatus_invalidate_idle_demotion_locked(p, TRUE);
				reschedule = TRUE;
			} else {
				/*
				 * Process is back from "dirty" to "clean".
				 */

				memorystatus_schedule_idle_demotion_locked(p, TRUE);
				reschedule = TRUE;
			}
		}

		memorystatus_update_idle_priority_locked(p);

		if (memorystatus_highwater_enabled) {
			boolean_t ledger_update_needed = TRUE;
			boolean_t use_active;
			boolean_t is_fatal;
			/*
			 * We are in this path because this process transitioned between
			 * dirty <--> clean state.  Update the cached memory limits.
			 */

			if (proc_jetsam_state_is_active_locked(p) == TRUE) {
				/*
				 * process is pinned in elevated band
				 * or
				 * process is dirty
				 */
				CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
				use_active = TRUE;
				ledger_update_needed = TRUE;
			} else {
				/*
				 * process is clean...but if it has opted into pressured-exit
				 * we don't apply the INACTIVE limit till the process has aged
				 * out and is entering the IDLE band.
				 * See memorystatus_update_priority_locked() for that.
				 */

				if (p->p_memstat_dirty & P_DIRTY_ALLOW_IDLE_EXIT) {
					ledger_update_needed = FALSE;
				} else {
					CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
					use_active = FALSE;
					ledger_update_needed = TRUE;
				}
			}

			/*
			 * Enforce the new limits by writing to the ledger.
			 *
			 * This is a hot path and holding the proc_list_lock while writing to the ledgers,
			 * (where the task lock is taken) is bad.  So, we temporarily drop the proc_list_lock.
			 * We aren't traversing the jetsam bucket list here, so we should be safe.
			 * See rdar://21394491.
			 */

			if (ledger_update_needed && proc_ref(p, true) == p) {
				int ledger_limit;
				if (p->p_memstat_memlimit > 0) {
					ledger_limit = p->p_memstat_memlimit;
				} else {
					ledger_limit = -1;
				}
				proc_list_unlock();
				task_set_phys_footprint_limit_internal(proc_task(p), ledger_limit, NULL, use_active, is_fatal);
				proc_list_lock();
				proc_rele(p);

				memorystatus_log_debug(
					"memorystatus_dirty_set: new limit on pid %d (%dMB %s) priority(%d) dirty?=0x%x %s\n",
					proc_getpid(p), (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
					(p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, p->p_memstat_dirty,
					(p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
			}
		}

		/* If the deferral state changed, reschedule the demotion timer */
		if (reschedule) {
			memorystatus_reschedule_idle_demotion_locked();
		}

		/* Settle dirty time in ledger, and update transition timestamp */
		task_t t = proc_task(p);
		if (was_dirty) {
			task_ledger_settle_dirty_time(t);
			task_set_dirty_start(t, 0);
		} else {
			task_set_dirty_start(t, mach_absolute_time());
		}
	}

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

	if (!(p->p_memstat_dirty & P_DIRTY_TRACK)) {
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

		memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		memorystatus_update_idle_priority_locked(p);
		memorystatus_reschedule_idle_demotion_locked();
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

	if (p->p_memstat_dirty & P_DIRTY_TRACK) {
		ret |= PROC_DIRTY_TRACKED;
		if (p->p_memstat_dirty & P_DIRTY_ALLOW_IDLE_EXIT) {
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

	if (((p->p_memstat_dirty & (P_DIRTY_TRACK | P_DIRTY_IS_DIRTY)) == P_DIRTY_TRACK) ||
	    (p->p_memstat_state & P_MEMSTAT_SUSPENDED)) {
		/*
		 * Mark as terminated and issue SIGKILL if:-
		 * - process is clean, or,
		 * - if process is dirty but suspended. This case is likely
		 * an extension because apps don't opt into dirty-tracking
		 * and daemons aren't suspended.
		 */
#if DEVELOPMENT || DEBUG
		if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
			memorystatus_log_info(
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
#if CONFIG_FREEZE
	memorystatus_suspended_count++;
#endif
	p->p_memstat_state |= P_MEMSTAT_SUSPENDED;

	/* Check if proc is marked for termination */
	bool kill_process = !!(p->p_memstat_dirty & P_DIRTY_TERMINATED);
	proc_list_unlock();

	if (kill_process) {
		psignal(p, SIGKILL);
	}

#if CONFIG_DEFERRED_RECLAIM
	vm_deferred_reclamation_reclaim_from_task_async(proc_task(p));
#endif /* CONFIG_DEFERRED_RECLAIM */
}

extern uint64_t memorystatus_thaw_count_since_boot;

void
memorystatus_on_resume(proc_t p)
{
#if CONFIG_FREEZE
	boolean_t frozen;
	pid_t pid;
#endif

	proc_list_lock();

#if CONFIG_FREEZE
	frozen = (p->p_memstat_state & P_MEMSTAT_FROZEN);
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

	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		memorystatus_suspended_count--;
	}

	pid = proc_getpid(p);
#endif

	/*
	 * P_MEMSTAT_FROZEN will remain unchanged. This used to be:
	 * p->p_memstat_state &= ~(P_MEMSTAT_SUSPENDED | P_MEMSTAT_FROZEN);
	 */
	p->p_memstat_state &= ~P_MEMSTAT_SUSPENDED;

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
static uint32_t
memorystatus_build_state(proc_t p)
{
	uint32_t snapshot_state = 0;

	/* General */
	if (p->p_memstat_state & P_MEMSTAT_SUSPENDED) {
		snapshot_state |= kMemorystatusSuspended;
	}
	if (p->p_memstat_state & P_MEMSTAT_FROZEN) {
		snapshot_state |= kMemorystatusFrozen;
	}
	if (p->p_memstat_state & P_MEMSTAT_REFREEZE_ELIGIBLE) {
		snapshot_state |= kMemorystatusWasThawed;
	}
	if (p->p_memstat_state & P_MEMSTAT_PRIORITY_ASSERTION) {
		snapshot_state |= kMemorystatusAssertion;
	}

	/* Tracking */
	if (p->p_memstat_dirty & P_DIRTY_TRACK) {
		snapshot_state |= kMemorystatusTracked;
	}
	if ((p->p_memstat_dirty & P_DIRTY_IDLE_EXIT_ENABLED) == P_DIRTY_IDLE_EXIT_ENABLED) {
		snapshot_state |= kMemorystatusSupportsIdleExit;
	}
	if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
		snapshot_state |= kMemorystatusDirty;
	}

	return snapshot_state;
}

static boolean_t
kill_idle_exit_proc(void)
{
	proc_t p, victim_p = PROC_NULL;
	uint64_t current_time, footprint_of_killed_proc;
	boolean_t killed = FALSE;
	unsigned int i = 0;
	os_reason_t jetsam_reason = OS_REASON_NULL;

	/* Pick next idle exit victim. */
	current_time = mach_absolute_time();

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_IDLE_EXIT);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("kill_idle_exit_proc: failed to allocate jetsam reason\n");
	}

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&i, FALSE);
	while (p) {
		/* No need to look beyond the idle band */
		if (p->p_memstat_effectivepriority != JETSAM_PRIORITY_IDLE) {
			break;
		}

		if ((p->p_memstat_dirty & (P_DIRTY_ALLOW_IDLE_EXIT | P_DIRTY_IS_DIRTY | P_DIRTY_TERMINATED)) == (P_DIRTY_ALLOW_IDLE_EXIT)) {
			if (current_time >= p->p_memstat_idledeadline) {
				p->p_memstat_dirty |= P_DIRTY_TERMINATED;
				victim_p = proc_ref(p, true);
				break;
			}
		}

		p = memorystatus_get_next_proc_locked(&i, p, FALSE);
	}

	proc_list_unlock();

	if (victim_p) {
		memorystatus_log(
			"memorystatus: killing_idle_process pid %d [%s] jetsam_reason->osr_code: %llu\n",
			proc_getpid(victim_p), (*victim_p->p_name ? victim_p->p_name : "unknown"), jetsam_reason->osr_code);
		killed = memorystatus_do_kill(victim_p, kMemorystatusKilledIdleExit, jetsam_reason, &footprint_of_killed_proc);
		proc_rele(victim_p);
	} else {
		os_reason_free(jetsam_reason);
	}

	return killed;
}

void
memorystatus_thread_wake()
{
	int thr_id = 0;
	int active_thr = atomic_load(&active_jetsam_threads);

	/* Wakeup all the jetsam threads */
	for (thr_id = 0; thr_id < active_thr; thr_id++) {
		jetsam_thread_state_t *jetsam_thread = &jetsam_threads[thr_id];
		sched_cond_signal(&(jetsam_thread->jt_wakeup_cond), jetsam_thread->thread);
	}
}

#if CONFIG_JETSAM

static void
memorystatus_thread_pool_max()
{
	/* Increase the jetsam thread pool to max_jetsam_threads */
	int max_threads = max_jetsam_threads;
	memorystatus_log_info("Expanding memorystatus pool to %d!\n", max_threads);
	atomic_store(&active_jetsam_threads, max_threads);
}

static void
memorystatus_thread_pool_default()
{
	/* Restore the jetsam thread pool to a single thread */
	memorystatus_log_info("Reverting memorystatus pool back to 1\n");
	atomic_store(&active_jetsam_threads, 1);
}

#endif /* CONFIG_JETSAM */

extern void vm_pressure_response(void);

bool
memorystatus_avail_pages_below_pressure(void)
{
#if CONFIG_JETSAM
	return memorystatus_available_pages <= memorystatus_available_pages_pressure;
#else /* CONFIG_JETSAM */
	return false;
#endif /* CONFIG_JETSAM */
}

bool
memorystatus_avail_pages_below_critical(void)
{
#if CONFIG_JETSAM
	return memorystatus_available_pages <= memorystatus_available_pages_critical;
#else /* CONFIG_JETSAM */
	return false;
#endif /* CONFIG_JETSAM */
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
			memorystatus_hwm_candidates = FALSE;
		}
	}

	return killed;
}

static bool
memorystatus_dump_caches(bool purge_corpses)
{
	pmap_release_pages_fast();
	if (purge_corpses && total_corpses_count() > 0) {
		os_atomic_inc(&block_corpses, relaxed);
		assert(block_corpses > 0);
		task_purge_all_corpses();
		return true;
	}
	return false;
}

/*
 * Called before jetsamming in the foreground band in the hope that we'll
 * avoid a jetsam.
 */
static void
memorystatus_approaching_fg_band(bool *corpse_list_purged)
{
	bool corpses_purged = false;
	assert(corpse_list_purged != NULL);
	if (memorystatus_should_issue_fg_band_notify) {
		memorystatus_issue_fg_band_notify();
	}
	corpses_purged = memorystatus_dump_caches(!(*corpse_list_purged));
	*corpse_list_purged |= corpses_purged;
#if CONFIG_DEFERRED_RECLAIM
	vm_deferred_reclamation_reclaim_all_memory();
#endif /* CONFIG_DEFERRED_RECLAIM */
}

int       jld_eval_aggressive_count = 0;
int32_t   jld_priority_band_max = JETSAM_PRIORITY_UI_SUPPORT;
uint64_t  jld_timestamp_msecs = 0;
int       jld_idle_kill_candidates = 0;

static boolean_t
memorystatus_act_aggressive(uint32_t cause, os_reason_t jetsam_reason, int *jld_idle_kills, bool *corpse_list_purged, bool *post_snapshot, uint64_t *memory_reclaimed)
{
	boolean_t killed;
	uint32_t errors = 0;
	uint64_t footprint_of_killed_proc = 0;
	int elevated_bucket_count = 0, maximum_kills = 0, band = 0;
	*memory_reclaimed = 0;

	jld_eval_aggressive_count++;

	if (jld_eval_aggressive_count == memorystatus_jld_eval_aggressive_count) {
		memorystatus_approaching_fg_band(corpse_list_purged);
	} else if (jld_eval_aggressive_count > memorystatus_jld_eval_aggressive_count) {
		/*
		 * Bump up the jetsam priority limit (eg: the bucket index)
		 * Enforce bucket index sanity.
		 */
		if ((memorystatus_jld_eval_aggressive_priority_band_max < 0) ||
		    (memorystatus_jld_eval_aggressive_priority_band_max >= MEMSTAT_BUCKET_COUNT)) {
			/*
			 * Do nothing.  Stick with the default level.
			 */
		} else {
			jld_priority_band_max = memorystatus_jld_eval_aggressive_priority_band_max;
		}
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
			*post_snapshot = true;
			*memory_reclaimed += footprint_of_killed_proc;
			if (memorystatus_avail_pages_below_pressure()) {
				/*
				 * Still under pressure.
				 * Find another pinned processes.
				 */
				continue;
			} else {
				return TRUE;
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
	for (band = 0; band < jld_priority_band_max; band++) {
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
		jld_priority_band_max,
		maximum_kills,
		&errors, &footprint_of_killed_proc);

	if (killed) {
		/* Always generate logs after aggressive kill */
		*post_snapshot = true;
		*memory_reclaimed += footprint_of_killed_proc;
		*jld_idle_kills = 0;
		return TRUE;
	}

	return FALSE;
}

/*
 * Sets up a new jetsam thread.
 */
static void
memorystatus_thread_init(jetsam_thread_state_t *jetsam_thread)
{
	char name[32];
	thread_wire(host_priv_self(), current_thread(), TRUE);
	snprintf(name, 32, "VM_memorystatus_%d", jetsam_thread->index + 1);

	/* Limit all but one thread to the lower jetsam bands, as that's where most of the victims are. */
	if (jetsam_thread->index == 0) {
		if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
			thread_vm_bind_group_add();
		}
		jetsam_thread->limit_to_low_bands = FALSE;
	} else {
		jetsam_thread->limit_to_low_bands = TRUE;
	}
#if CONFIG_THREAD_GROUPS
	thread_group_vm_add();
#endif
	thread_set_thread_name(current_thread(), name);
	sched_cond_init(&(jetsam_thread->jt_wakeup_cond));
	jetsam_thread->inited = TRUE;
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
memorystatus_do_priority_kill(jetsam_thread_state_t *thread,
    uint32_t kill_cause, int32_t max_priority, bool only_swappable)
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
	killed = memorystatus_kill_top_process(true, thread->sort_flag, kill_cause, jetsam_reason, max_priority,
	    only_swappable, &priority, &thread->errors, &thread->memory_reclaimed);
	thread->sort_flag = false;

	if (killed) {
		if (memorystatus_should_post_snapshot(priority, kill_cause) == TRUE) {
			thread->post_snapshot = true;
		}

		/* Jetsam Loop Detection */
		if (memorystatus_jld_enabled == TRUE) {
			if (priority <= applications_aging_band) {
				thread->jld_idle_kills++;
			} else {
				/*
				 * We've reached into bands beyond idle deferred.
				 * We make no attempt to monitor them
				 */
			}
		}

		/*
		 * If we have jetsammed a process in or above JETSAM_PRIORITY_FREEZER
		 * then we attempt to relieve pressure by purging corpse memory and notifying
		 * anybody wanting to know this.
		 */
		if (priority >= JETSAM_PRIORITY_FREEZER) {
			memorystatus_approaching_fg_band(&thread->corpse_list_purged);
		}
	}
	os_reason_free(jetsam_reason);

	return killed;
}

static bool
memorystatus_do_action(jetsam_thread_state_t *thread, memorystatus_action_t action, uint32_t kill_cause)
{
	bool killed = false;
	os_reason_t jetsam_reason = OS_REASON_NULL;

	switch (action) {
	case MEMORYSTATUS_KILL_HIWATER:
		killed = memorystatus_act_on_hiwat_processes(&thread->errors, &thread->hwm_kills,
		    &thread->post_snapshot, &thread->memory_reclaimed);
		break;
	case MEMORYSTATUS_KILL_AGGRESSIVE:
		jetsam_reason = create_jetsam_reason(kill_cause);
		killed = memorystatus_act_aggressive(kill_cause, jetsam_reason,
		    &thread->jld_idle_kills, &thread->corpse_list_purged, &thread->post_snapshot,
		    &thread->memory_reclaimed);
		os_reason_free(jetsam_reason);
		break;
	case MEMORYSTATUS_KILL_TOP_PROCESS:
		killed = memorystatus_do_priority_kill(thread, kill_cause, max_kill_priority, false);
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
		killed = memorystatus_do_priority_kill(thread, kill_cause, JETSAM_PRIORITY_BACKGROUND - 1, true);
		break;
	case MEMORYSTATUS_KILL_SWAPPABLE:
		killed = memorystatus_do_priority_kill(thread, kill_cause, max_kill_priority, true);
		break;
	case MEMORYSTATUS_KILL_NONE:
		panic("memorystatus_do_action: Impossible! memorystatus_do_action called with action = NONE\n");
	}
	return killed;
}

static void
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


/* Callback into vm_compressor.c to signal that thrashing has been mitigated. */
extern void vm_thrashing_jetsam_done(void);

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
memorystatus_thread_internal(jetsam_thread_state_t *jetsam_thread)
{
	uint64_t total_memory_reclaimed = 0;
	bool highwater_remaining = true;
	bool swappable_apps_remaining = false;
	bool suspended_swappable_apps_remaining = false;

#if CONFIG_JETSAM
	swappable_apps_remaining = memorystatus_swap_all_apps;
	suspended_swappable_apps_remaining = memorystatus_swap_all_apps;
#endif /* CONFIG_JETSAM */

	assert(jetsam_thread != NULL);
	jetsam_thread->jld_idle_kills = 0;
	jetsam_thread->errors = 0;
	jetsam_thread->hwm_kills = 0;
	jetsam_thread->sort_flag = true;
	jetsam_thread->corpse_list_purged = false;
	jetsam_thread->post_snapshot = FALSE;
	jetsam_thread->memory_reclaimed = 0;

	if (jetsam_thread->inited == FALSE) {
		/*
		 * It's the first time the thread has run, so just mark the thread as privileged and block.
		 */
		memorystatus_thread_init(jetsam_thread);
		sched_cond_wait(&(jetsam_thread->jt_wakeup_cond), THREAD_UNINT, memorystatus_thread);
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_SCAN) | DBG_FUNC_START,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, memorystatus_jld_enabled, memorystatus_jld_eval_period_msecs, memorystatus_jld_eval_aggressive_count);

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
		jetsam_thread->memory_reclaimed = 0;
		uint32_t cause = 0;

		memorystatus_action_t action = memorystatus_pick_action(jetsam_thread, &cause,
		    highwater_remaining, suspended_swappable_apps_remaining, swappable_apps_remaining,
		    &jetsam_thread->jld_idle_kills);
		if (action == MEMORYSTATUS_KILL_NONE) {
			break;
		}

		if (cause == kMemorystatusKilledVMCompressorThrashing || cause == kMemorystatusKilledVMCompressorSpaceShortage) {
			memorystatus_log("memorystatus: killing due to \"%s\" - compression_ratio=%u\n", memorystatus_kill_cause_name[cause], vm_compression_ratio());
		}

		killed = memorystatus_do_action(jetsam_thread, action, cause);
		total_memory_reclaimed += jetsam_thread->memory_reclaimed;

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

		if ((action == MEMORYSTATUS_KILL_TOP_PROCESS || action == MEMORYSTATUS_KILL_AGGRESSIVE) && !killed && total_memory_reclaimed == 0 && memorystatus_avail_pages_below_critical()) {
			/*
			 * Still under pressure and unable to kill a process - purge corpse memory
			 * and get everything back from the pmap.
			 */
			memorystatus_dump_caches(true);

			if (!jetsam_thread->limit_to_low_bands && memorystatus_avail_pages_below_critical()) {
				/*
				 * Still under pressure and unable to kill a process - panic
				 */
				panic("memorystatus_jetsam_thread: no victim! available pages:%llu", (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);
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

	if (jetsam_thread->errors) {
		memorystatus_clear_errors();
	}

	if (jetsam_thread->post_snapshot) {
		memorystatus_post_snapshot();
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_SCAN) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, total_memory_reclaimed);

	if (jetsam_thread->corpse_list_purged) {
		os_atomic_dec(&block_corpses, relaxed);
		assert(block_corpses >= 0);
	}
}

OS_NORETURN
static void
memorystatus_thread(void *param __unused, wait_result_t wr __unused)
{
	jetsam_thread_state_t *jetsam_thread = jetsam_current_thread();
	sched_cond_ack(&(jetsam_thread->jt_wakeup_cond));
	while (1) {
		memorystatus_thread_internal(jetsam_thread);
		sched_cond_wait(&(jetsam_thread->jt_wakeup_cond), THREAD_UNINT, memorystatus_thread);
	}
}

/*
 * This section defines when we deploy aggressive jetsam.
 * Aggressive jetsam kills everything up to the jld_priority_band_max band.
 */

/*
 * Returns TRUE:
 *      when an idle-exitable proc was killed
 * Returns FALSE:
 *	when there are no more idle-exitable procs found
 *      when the attempt to kill an idle-exitable proc failed
 */
boolean_t
memorystatus_idle_exit_from_VM(void)
{
	/*
	 * This routine should no longer be needed since we are
	 * now using jetsam bands on all platforms and so will deal
	 * with IDLE processes within the memorystatus thread itself.
	 *
	 * But we still use it because we observed that macos systems
	 * started heavy compression/swapping with a bunch of
	 * idle-exitable processes alive and doing nothing. We decided
	 * to rather kill those processes than start swapping earlier.
	 */

	return kill_idle_exit_proc();
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
			memorystatus_log_error(
				"memorystatus_on_ledger_footprint_exceeded: failed to warn the current task (%d exiting, or no handler registered?).\n",
				proc_getpid(p));
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
		memorystatus_hwm_candidates = TRUE;

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

inline void
memorystatus_log_exception(const int max_footprint_mb, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal)
{
	proc_t p = current_proc();

	/*
	 * The limit violation is logged here, but only once per process per limit.
	 * Soft memory limit is a non-fatal high-water-mark
	 * Hard memory limit is a fatal custom-task-limit or system-wide per-task memory limit.
	 */

	memorystatus_log("EXC_RESOURCE -> %s[%d] exceeded mem limit: %s%s %d MB (%s)\n",
	    ((p && *p->p_name) ? p->p_name : "unknown"), (p ? proc_getpid(p) : -1), (memlimit_is_active ? "Active" : "Inactive"),
	    (memlimit_is_fatal  ? "Hard" : "Soft"), max_footprint_mb,
	    (memlimit_is_fatal  ? "fatal" : "non-fatal"));
}

inline void
memorystatus_log_diag_threshold_exception(const int diag_threshold_value)
{
	proc_t p = current_proc();

	/*
	 * The limit violation is logged here, but only once per process per limit.
	 * Soft memory limit is a non-fatal high-water-mark
	 * Hard memory limit is a fatal custom-task-limit or system-wide per-task memory limit.
	 */

	memorystatus_log("EXC_RESOURCE -> %s[%d] exceeded diag threshold limit: %d MB \n",
	    ((p && *p->p_name) ? p->p_name : "unknown"), (p ? proc_getpid(p) : -1), diag_threshold_value);
}

/*
 * Description:
 *	Evaluates process state to determine which limit
 *	should be applied (active vs. inactive limit).
 *
 *	Processes that have the 'elevated inactive jetsam band' attribute
 *	are first evaluated based on their current priority band.
 *	presently elevated ==> active
 *
 *	Processes that opt into dirty tracking are evaluated
 *	based on clean vs dirty state.
 *	dirty ==> active
 *	clean ==> inactive
 *
 *	Process that do not opt into dirty tracking are
 *	evalulated based on priority level.
 *	Foreground or above ==> active
 *	Below Foreground    ==> inactive
 *
 *	Return: TRUE if active
 *		False if inactive
 */

static boolean_t
proc_jetsam_state_is_active_locked(proc_t p)
{
	if ((p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND) &&
	    (p->p_memstat_effectivepriority == JETSAM_PRIORITY_ELEVATED_INACTIVE)) {
		/*
		 * process has the 'elevated inactive jetsam band' attribute
		 * and process is present in the elevated band
		 * implies active state
		 */
		return TRUE;
	} else if (p->p_memstat_dirty & P_DIRTY_TRACK) {
		/*
		 * process has opted into dirty tracking
		 * active state is based on dirty vs. clean
		 */
		if (p->p_memstat_dirty & P_DIRTY_IS_DIRTY) {
			/*
			 * process is dirty
			 * implies active state
			 */
			return TRUE;
		} else {
			/*
			 * process is clean
			 * implies inactive state
			 */
			return FALSE;
		}
	} else if (p->p_memstat_effectivepriority >= JETSAM_PRIORITY_FOREGROUND) {
		/*
		 * process is Foreground or higher
		 * implies active state
		 */
		return TRUE;
	} else {
		/*
		 * process found below Foreground
		 * implies inactive state
		 */
		return FALSE;
	}
}

static boolean_t
memorystatus_kill_process_sync(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason)
{
	boolean_t res;

	uint32_t errors = 0;
	uint64_t memory_reclaimed = 0;

	if (victim_pid == -1) {
		/* No pid, so kill first process */
		res = memorystatus_kill_top_process(true, true, cause, jetsam_reason,
		    max_kill_priority, false, NULL, &errors, &memory_reclaimed);
	} else {
		res = memorystatus_kill_specific_process(victim_pid, cause, jetsam_reason);
	}

	if (errors) {
		memorystatus_clear_errors();
	}

	if (res == TRUE) {
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

	return res;
}

/*
 * Jetsam a specific process.
 */
static boolean_t
memorystatus_kill_specific_process(pid_t victim_pid, uint32_t cause, os_reason_t jetsam_reason)
{
	boolean_t killed;
	proc_t p;
	uint64_t killtime = 0;
	uint64_t footprint_of_killed_proc;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;

	/* TODO - add a victim queue and push this into the main jetsam thread */

	p = proc_find(victim_pid);
	if (!p) {
		os_reason_free(jetsam_reason);
		return FALSE;
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
		return FALSE;
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

	killed = memorystatus_do_kill(p, cause, jetsam_reason, &footprint_of_killed_proc);

	memorystatus_log("%lu.%03d memorystatus: killing_specific_process pid %d [%s] (%s %d) %lluKB - memorystatus_available_pages: %llu\n",
	    (unsigned long)tv_sec, tv_msec, victim_pid, ((p && *p->p_name) ? p->p_name : "unknown"),
	    memorystatus_kill_cause_name[cause], (p ? p->p_memstat_effectivepriority: -1),
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

	memorystatus_log("task_exceeded_cpulimit: killing pid %d [%s]\n", proc_getpid(p), (*p->p_name ? p->p_name : "(unknown)"));

	jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_CPULIMIT);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("task_exceeded_cpulimit: unable to allocate memory for jetsam reason\n");
	}

	retval = jetsam_do_kill(p, jetsam_flags, jetsam_reason);

	if (retval) {
		memorystatus_log_error("task_exceeded_cpulimit: failed to kill current task (exiting?).\n");
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
    uint64_t *iokit_mapped_pages, uint64_t *page_table_pages, uint64_t *frozen_to_swap_pages)
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
				entry->state     = memorystatus_build_state(p);
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

			memorystatus_get_task_phys_footprint_page_counts(proc_task(p), &internal_pages, &internal_compressed_pages,
			    &purgeable_nonvolatile_pages, &purgeable_nonvolatile_compressed_pages,
			    &alternate_accounting_pages, &alternate_accounting_compressed_pages,
			    &iokit_mapped_pages, &page_table_pages, &frozen_to_swap_pages);

			entry->jse_internal_pages = internal_pages;
			entry->jse_internal_compressed_pages = internal_compressed_pages;
			entry->jse_purgeable_nonvolatile_pages = purgeable_nonvolatile_pages;
			entry->jse_purgeable_nonvolatile_compressed_pages = purgeable_nonvolatile_compressed_pages;
			entry->jse_alternate_accounting_pages = alternate_accounting_pages;
			entry->jse_alternate_accounting_compressed_pages = alternate_accounting_compressed_pages;
			entry->jse_iokit_mapped_pages = iokit_mapped_pages;
			entry->jse_page_table_pages = page_table_pages;
			entry->jse_frozen_to_swap_pages = frozen_to_swap_pages;

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

#if CONFIG_JETSAM

void
memorystatus_pages_update(unsigned int pages_avail)
{
	memorystatus_available_pages = pages_avail;

#if VM_PRESSURE_EVENTS
	/*
	 * Since memorystatus_available_pages changes, we should
	 * re-evaluate the pressure levels on the system and
	 * check if we need to wake the pressure thread.
	 * We also update memorystatus_level in that routine.
	 */
	vm_pressure_response();

	if (memorystatus_available_pages <= memorystatus_available_pages_pressure) {
		if (memorystatus_hwm_candidates || (memorystatus_available_pages <= memorystatus_available_pages_critical)) {
			memorystatus_thread_wake();
		}
	}
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

#else /* VM_PRESSURE_EVENTS */

	boolean_t critical, delta;

	if (!memorystatus_delta) {
		return;
	}

	critical = (pages_avail < memorystatus_available_pages_critical) ? TRUE : FALSE;
	delta = ((pages_avail >= (memorystatus_available_pages + memorystatus_delta))
	    || (memorystatus_available_pages >= (pages_avail + memorystatus_delta))) ? TRUE : FALSE;

	if (critical || delta) {
		unsigned int total_pages;

		total_pages = (unsigned int) atop_64(max_mem);
#if CONFIG_SECLUDED_MEMORY
		total_pages -= vm_page_secluded_count;
#endif /* CONFIG_SECLUDED_MEMORY */
		memorystatus_level = memorystatus_available_pages * 100 / total_pages;
		memorystatus_thread_wake();
	}
#endif /* VM_PRESSURE_EVENTS */
}
#endif /* CONFIG_JETSAM */

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
	    &iokit_mapped_pages, &page_table_pages, &frozen_to_swap_pages);

	entry->jse_internal_pages = internal_pages;
	entry->jse_internal_compressed_pages = internal_compressed_pages;
	entry->jse_purgeable_nonvolatile_pages = purgeable_nonvolatile_pages;
	entry->jse_purgeable_nonvolatile_compressed_pages = purgeable_nonvolatile_compressed_pages;
	entry->jse_alternate_accounting_pages = alternate_accounting_pages;
	entry->jse_alternate_accounting_compressed_pages = alternate_accounting_compressed_pages;
	entry->jse_iokit_mapped_pages = iokit_mapped_pages;
	entry->jse_page_table_pages = page_table_pages;
	entry->jse_frozen_to_swap_pages = frozen_to_swap_pages;

	memorystatus_get_task_memory_region_count(proc_task(p), &region_count);
	entry->jse_memory_region_count = region_count;

	entry->state     = memorystatus_build_state(p);
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
	static size_t kMaxPids = 8;
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

static boolean_t
memorystatus_kill_proc(proc_t p, uint32_t cause, os_reason_t jetsam_reason, bool *killed, uint64_t *footprint_of_killed_proc)
{
	pid_t aPid = 0;
	uint32_t aPid_ep = 0;

	uint64_t        killtime = 0;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;
	boolean_t       retval = FALSE;

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
				success = !memorystatus_avail_pages_below_pressure();
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
					success = !memorystatus_avail_pages_below_critical();
				}
#endif /* CONFIG_SECLUDED_MEMORY */
			}

			if (success) {
				memorystatus_purge_before_jetsam_success++;

				memorystatus_log_info("memorystatus: reclaimed %llu pages (%llu purged, %llu unsecluded) from pid %d [%s] and avoided %s\n",
				    num_pages_reclaimed, num_pages_purged, num_pages_unsecluded, aPid, ((p && *p->p_name) ? p->p_name : "unknown"), memorystatus_kill_cause_name[cause]);

				*killed = false;
				*footprint_of_killed_proc = num_pages_reclaimed + num_pages_purged + num_pages_unsecluded;

				return TRUE;
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

	memorystatus_log("%lu.%03d memorystatus: %s pid %d [%s] (%s %d) %lluKB - memorystatus_available_pages: %llu compressor_size:%u\n",
	    (unsigned long)tv_sec, tv_msec, kill_reason_string,
	    aPid, ((p && *p->p_name) ? p->p_name : "unknown"),
	    memorystatus_kill_cause_name[cause], aPid_ep,
	    (*footprint_of_killed_proc) >> 10, (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());

	return retval;
}

/*
 * Jetsam the first process in the queue.
 */
static bool
memorystatus_kill_top_process(bool any, bool sort_flag, uint32_t cause, os_reason_t jetsam_reason,
    int32_t max_priority, bool only_swappable,
    int32_t *priority, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	bool new_snapshot = false, force_new_snapshot = false, killed = false, freed_mem = false;
	unsigned int i = 0;
	uint32_t aPid_ep;
	int32_t local_max_kill_prio = JETSAM_PRIORITY_IDLE;
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
	local_max_kill_prio = MIN(max_kill_priority, max_priority);

#if VM_PRESSURE_EVENTS
	if (cause == kMemorystatusKilledSustainedPressure) {
		local_max_kill_prio = memorystatus_sustained_pressure_maximum_band;
	}
#endif /* VM_PRESSURE_EVENTS */

	force_new_snapshot = false;

#else /* CONFIG_JETSAM */
	(void) max_priority;

	if (sort_flag) {
		(void)memorystatus_sort_bucket(JETSAM_PRIORITY_IDLE, JETSAM_SORT_DEFAULT);
	}

	/*
	 * On macos, we currently only have 2 reasons to be here:
	 *
	 * kMemorystatusKilledZoneMapExhaustion
	 * AND
	 * kMemorystatusKilledVMCompressorSpaceShortage
	 *
	 * If we are here because of kMemorystatusKilledZoneMapExhaustion, we will consider
	 * any and all processes as eligible kill candidates since we need to avoid a panic.
	 *
	 * Since this function can be called async. it is harder to toggle the max_kill_priority
	 * value before and after a call. And so we use this local variable to set the upper band
	 * on the eligible kill bands.
	 */
	if (cause == kMemorystatusKilledZoneMapExhaustion) {
		local_max_kill_prio = JETSAM_PRIORITY_MAX;
	} else {
		local_max_kill_prio = max_kill_priority;
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
	    local_max_kill_prio > JETSAM_PRIORITY_MAIL) {
		local_max_kill_prio = JETSAM_PRIORITY_MAIL;
	}

	proc_list_lock();

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p && (next_p->p_memstat_effectivepriority <= local_max_kill_prio)) {
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
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_JETSAM) | DBG_FUNC_END,
	    MEMORYSTATUS_LOG_AVAILABLE_PAGES, killed ? aPid : 0, killed, *memory_reclaimed);

	return killed;
}

/*
 * Jetsam aggressively
 */
static boolean_t
memorystatus_kill_processes_aggressive(uint32_t cause, int aggr_count,
    int32_t priority_max, int max_kills, uint32_t *errors, uint64_t *memory_reclaimed)
{
	pid_t aPid;
	proc_t p = PROC_NULL, next_p = PROC_NULL;
	boolean_t new_snapshot = FALSE, killed = FALSE;
	int kill_count = 0;
	unsigned int i = 0;
	int32_t aPid_ep = 0;
	unsigned int memorystatus_level_snapshot = 0;
	uint64_t killtime = 0;
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

	next_p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (next_p) {
		if (proc_list_exited(next_p) ||
		    ((unsigned int)(next_p->p_memstat_effectivepriority) != i)) {
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
				aggr_count, i, (*next_p->p_name ? next_p->p_name : "unknown"), proc_getpid(next_p));

			next_p = memorystatus_get_first_proc_locked(&i, TRUE);
			continue;
		}

		p = next_p;
		next_p = memorystatus_get_next_proc_locked(&i, p, TRUE);

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
					next_p = memorystatus_get_next_proc_locked(&i, temp_p, TRUE);
				}
			}
			proc_list_unlock();

			memorystatus_log(
				"%lu.%03d memorystatus: %s%d pid %d [%s] (%s %d) - memorystatus_available_pages: %llu\n",
				(unsigned long)tv_sec, tv_msec,
				((aPid_ep == JETSAM_PRIORITY_IDLE) ? "killing_idle_process_aggressive" : "killing_top_process_aggressive"),
				aggr_count, aPid, (*p->p_name ? p->p_name : "unknown"),
				memorystatus_kill_cause_name[cause], aPid_ep, (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES);

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
						"memorystatus: giving up aggressive kill after killing %d processes below band %d.\n", max_kills, priority_max + 1);
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

		next_p = memorystatus_get_first_proc_locked(&i, TRUE);
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

	if (kill_count > 0) {
		return TRUE;
	} else {
		return FALSE;
	}
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
		if (!(p->p_memstat_state & P_MEMSTAT_USE_ELEVATED_INACTIVE_BAND)) {
			continue;
		}

		if (p->p_memstat_state  & (P_MEMSTAT_ERROR | P_MEMSTAT_TERMINATED | P_MEMSTAT_SKIP)) {
			continue;
		}

#if CONFIG_FREEZE
		if (consider_frozen_only && !(p->p_memstat_state & P_MEMSTAT_FROZEN)) {
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

			memorystatus_log("%lu.%03d memorystatus: killing_top_process_elevated%d pid %d [%s] (%s %d) %lluKB - memorystatus_available_pages: %llu\n",
			    (unsigned long)tv_sec, tv_msec,
			    aggr_count,
			    aPid, ((p && *p->p_name) ? p->p_name : "unknown"),
			    memorystatus_kill_cause_name[cause], aPid_ep,
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

boolean_t
memorystatus_kill_on_VM_compressor_space_shortage(boolean_t async)
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

boolean_t
memorystatus_kill_on_vnode_limit(void)
{
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_VNODE);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus_kill_on_vnode_limit: failed to allocate jetsam reason\n");
	}

	return memorystatus_kill_process_sync(-1, kMemorystatusKilledVnodes, jetsam_reason);
}

boolean_t
memorystatus_kill_on_sustained_pressure()
{
	os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_MEMORY_SUSTAINED_PRESSURE);
	if (jetsam_reason == OS_REASON_NULL) {
		memorystatus_log_error("memorystatus_kill_on_FC_thrashing -- sync: failed to allocate jetsam reason\n");
	}

	return memorystatus_kill_process_sync(-1, kMemorystatusKilledSustainedPressure, jetsam_reason);
}

boolean_t
memorystatus_kill_with_jetsam_reason_sync(pid_t pid, os_reason_t jetsam_reason)
{
	uint32_t kill_cause = jetsam_reason->osr_code <= JETSAM_REASON_MEMORYSTATUS_MAX ?
	    (uint32_t) jetsam_reason->osr_code : JETSAM_REASON_INVALID;
	return memorystatus_kill_process_sync(pid, kill_cause, jetsam_reason);
}

#endif /* CONFIG_JETSAM */

boolean_t
memorystatus_kill_on_zone_map_exhaustion(pid_t pid)
{
	boolean_t res = FALSE;
	if (pid == -1) {
		os_atomic_store(&memorystatus_zone_map_is_exhausted, true, release);
		memorystatus_thread_wake();
		return true;
	} else {
		os_reason_t jetsam_reason = os_reason_create(OS_REASON_JETSAM, JETSAM_REASON_ZONE_MAP_EXHAUSTION);
		if (jetsam_reason == OS_REASON_NULL) {
			memorystatus_log_error("memorystatus_kill_on_zone_map_exhaustion: failed to allocate jetsam reason\n");
		}

		res = memorystatus_kill_process_sync(pid, kMemorystatusKilledZoneMapExhaustion, jetsam_reason);
	}
	return res;
}

void
memorystatus_on_pageout_scan_end(void)
{
	/* No-op */
}

/* Return both allocated and actual size, since there's a race between allocation and list compilation */
static int
memorystatus_get_priority_list(memorystatus_priority_entry_t **list_ptr, size_t *buffer_size, size_t *list_size, boolean_t size_only)
{
	uint32_t list_count, i = 0;
	memorystatus_priority_entry_t *list_entry;
	proc_t p;

	list_count = memorystatus_list_count;
	*list_size = sizeof(memorystatus_priority_entry_t) * list_count;

	/* Just a size check? */
	if (size_only) {
		return 0;
	}

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

	list_entry = *list_ptr;

	proc_list_lock();

	p = memorystatus_get_first_proc_locked(&i, TRUE);
	while (p && (*list_size < *buffer_size)) {
		list_entry->pid = proc_getpid(p);
		list_entry->priority = p->p_memstat_effectivepriority;
		list_entry->user_data = p->p_memstat_userdata;

		if (p->p_memstat_memlimit <= 0) {
			task_get_phys_footprint_limit(proc_task(p), &list_entry->limit);
		} else {
			list_entry->limit = p->p_memstat_memlimit;
		}

		list_entry->state = memorystatus_build_state(p);
		list_entry++;

		*list_size += sizeof(memorystatus_priority_entry_t);

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
	memorystatus_priority_entry_t mp_entry;
	kern_return_t ret;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_priority_entry_t))) {
		return EINVAL;
	}

	proc_t p = proc_find(pid);
	if (!p) {
		return ESRCH;
	}

	memset(&mp_entry, 0, sizeof(memorystatus_priority_entry_t));

	mp_entry.pid = proc_getpid(p);
	mp_entry.priority = p->p_memstat_effectivepriority;
	mp_entry.user_data = p->p_memstat_userdata;
	if (p->p_memstat_memlimit <= 0) {
		ret = task_get_phys_footprint_limit(proc_task(p), &mp_entry.limit);
		if (ret != KERN_SUCCESS) {
			proc_rele(p);
			return EINVAL;
		}
	} else {
		mp_entry.limit = p->p_memstat_memlimit;
	}
	mp_entry.state = memorystatus_build_state(p);

	proc_rele(p);

	error = copyout(&mp_entry, buffer, buffer_size);

	return error;
}

static int
memorystatus_cmd_get_priority_list(pid_t pid, user_addr_t buffer, size_t buffer_size, int32_t *retval)
{
	int error = 0;
	boolean_t size_only;
	size_t list_size;

	/*
	 * When a non-zero pid is provided, the 'list' has only one entry.
	 */

	size_only = ((buffer == USER_ADDR_NULL) ? TRUE: FALSE);

	if (pid != 0) {
		list_size = sizeof(memorystatus_priority_entry_t) * 1;
		if (!size_only) {
			error = memorystatus_get_priority_pid(pid, buffer, buffer_size);
		}
	} else {
		memorystatus_priority_entry_t *list = NULL;
		error = memorystatus_get_priority_list(&list, &buffer_size, &list_size, size_only);

		if (error == 0) {
			if (!size_only) {
				error = copyout(list, buffer, list_size);
			}

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

#if CONFIG_JETSAM
static void
memorystatus_update_levels_locked(void)
{
	/*
	 * If there's an entry in the first bucket, we have idle processes.
	 */
	memstat_bucket_t *first_bucket = &memstat_bucket[JETSAM_PRIORITY_IDLE];
	if (first_bucket->count) {
		memorystatus_available_pages_critical = memorystatus_available_pages_critical_idle;
	} else {
		memorystatus_available_pages_critical = memorystatus_available_pages_critical_base;
	}

	if (memorystatus_available_pages_critical > memorystatus_available_pages_pressure) {
		/*
		 * The critical threshold must never exceed the pressure threshold
		 */
		memorystatus_available_pages_critical = memorystatus_available_pages_pressure;
	}

	if (memorystatus_jetsam_policy & kPolicyMoreFree) {
		memorystatus_available_pages_critical += memorystatus_policy_more_free_offset_pages;
	}
}

void
memorystatus_fast_jetsam_override(boolean_t enable_override)
{
	/* If fast jetsam is not enabled, simply return */
	if (!fast_jetsam_enabled) {
		return;
	}

	if (enable_override) {
		if ((memorystatus_jetsam_policy & kPolicyMoreFree) == kPolicyMoreFree) {
			return;
		}
		proc_list_lock();
		memorystatus_jetsam_policy |= kPolicyMoreFree;
		memorystatus_thread_pool_max();
		memorystatus_update_levels_locked();
		proc_list_unlock();
	} else {
		if ((memorystatus_jetsam_policy & kPolicyMoreFree) == 0) {
			return;
		}
		proc_list_lock();
		memorystatus_jetsam_policy &= ~kPolicyMoreFree;
		memorystatus_thread_pool_default();
		memorystatus_update_levels_locked();
		proc_list_unlock();
	}
}


static int
sysctl_kern_memorystatus_policy_more_free SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error = 0, more_free = 0;

	/*
	 * TODO: Enable this privilege check?
	 *
	 * error = priv_check_cred(kauth_cred_get(), PRIV_VM_JETSAM, 0);
	 * if (error)
	 *	return (error);
	 */

	error = sysctl_handle_int(oidp, &more_free, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (more_free) {
		memorystatus_fast_jetsam_override(true);
	} else {
		memorystatus_fast_jetsam_override(false);
	}

	return 0;
}
SYSCTL_PROC(_kern, OID_AUTO, memorystatus_policy_more_free, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_kern_memorystatus_policy_more_free, "I", "");

#endif /* CONFIG_JETSAM */

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
	uint32_t ods_list_count = memorystatus_list_count;
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
	boolean_t head_insert;
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

		/* Allow head inserts -- but relative order is now  */
		if (table[i].priority == JETSAM_PRIORITY_IDLE_HEAD) {
			new_priority = JETSAM_PRIORITY_IDLE;
			head_insert = true;
		} else {
			new_priority = table[i].priority;
			head_insert = false;
		}

		/* Not allowed */
		if (p->p_memstat_state & P_MEMSTAT_INTERNAL) {
			continue;
		}

		/*
		 * Take appropriate steps if moving proc out of
		 * either of the aging bands.
		 */
		if ((p->p_memstat_effectivepriority == system_procs_aging_band) || (p->p_memstat_effectivepriority == applications_aging_band)) {
			memorystatus_invalidate_idle_demotion_locked(p, TRUE);
		}

		memorystatus_update_priority_locked(p, new_priority, head_insert, false);
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
 * It is not used for the setting of memory limits, which is why the last 6 args to the
 * memorystatus_update() call are 0 or FALSE.
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
	boolean_t is_assertion = FALSE;         /* priority is driven by an assertion */
	memorystatus_priority_properties_t mpp_entry;

	/* Validate inputs */
	if ((pid == 0) || (buffer == USER_ADDR_NULL) || (buffer_size != sizeof(memorystatus_priority_properties_t))) {
		return EINVAL;
	}

	/* Validate flags */
	if (flags == 0) {
		/*
		 * Default. This path updates requestedpriority.
		 */
	} else {
		if (flags & ~(MEMORYSTATUS_SET_PRIORITY_ASSERTION)) {
			/*
			 * Unsupported bit set in flag.
			 */
			return EINVAL;
		} else if (flags & MEMORYSTATUS_SET_PRIORITY_ASSERTION) {
			is_assertion = TRUE;
		}
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

		if (is_assertion) {
			memorystatus_log_debug("memorystatus: set assertion priority(%d) target %s:%d\n",
			    mpp_entry.priority, (*p->p_name ? p->p_name : "unknown"), proc_getpid(p));
		}

		error = memorystatus_update(p, mpp_entry.priority, mpp_entry.user_data, is_assertion, FALSE, FALSE, 0, 0, FALSE, FALSE);
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

	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_ACTIVE_FATAL) {
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
	if (p->p_memstat_state & P_MEMSTAT_MEMLIMIT_INACTIVE_FATAL) {
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

static int
memorystatus_set_memlimit_properties_internal(proc_t p, memorystatus_memlimit_properties_t *p_entry)
{
	int error = 0;

	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Store the active limit variants in the proc.
	 */
	SET_ACTIVE_LIMITS_LOCKED(p, p_entry->memlimit_active, p_entry->memlimit_active_attr);

	/*
	 * Store the inactive limit variants in the proc.
	 */
	SET_INACTIVE_LIMITS_LOCKED(p, p_entry->memlimit_inactive, p_entry->memlimit_inactive_attr);

	/*
	 * Enforce appropriate limit variant by updating the cached values
	 * and writing the ledger.
	 * Limit choice is based on process active/inactive state.
	 */

	if (memorystatus_highwater_enabled) {
		boolean_t is_fatal;
		boolean_t use_active;

		if (proc_jetsam_state_is_active_locked(p) == TRUE) {
			CACHE_ACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = TRUE;
		} else {
			CACHE_INACTIVE_LIMITS_LOCKED(p, is_fatal);
			use_active = FALSE;
		}

		/* Enforce the limit by writing to the ledgers */
		error = (task_set_phys_footprint_limit_internal(proc_task(p), ((p->p_memstat_memlimit > 0) ? p->p_memstat_memlimit : -1), NULL, use_active, is_fatal) == 0) ? 0 : EINVAL;

		memorystatus_log_info(
			"memorystatus_set_memlimit_properties: new limit on pid %d (%dMB %s) current priority (%d) dirty_state?=0x%x %s\n",
			proc_getpid(p), (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1),
			(p->p_memstat_state & P_MEMSTAT_FATAL_MEMLIMIT ? "F " : "NF"), p->p_memstat_effectivepriority, p->p_memstat_dirty,
			(p->p_memstat_dirty ? ((p->p_memstat_dirty & P_DIRTY) ? "isdirty" : "isclean") : ""));
		DTRACE_MEMORYSTATUS2(memorystatus_set_memlimit, proc_t, p, int32_t, (p->p_memstat_memlimit > 0 ? p->p_memstat_memlimit : -1));
	}

	return error;
}

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
	static const char kIncreasedMemoryLimitEntitlement[] = "com.apple.developer.kernel.increased-memory-limit";
	if (memorystatus_entitled_max_task_footprint_mb == 0) {
		// Entitlement is not supported on this device.
		return false;
	}

	return IOTaskHasEntitlement(task, kIncreasedMemoryLimitEntitlement);
}

bool
memorystatus_task_has_legacy_footprint_entitlement(task_t task)
{
	return IOTaskHasEntitlement(task, "com.apple.private.memory.legacy_footprint");
}

bool
memorystatus_task_has_ios13extended_footprint_limit(task_t task)
{
	if (max_mem < 1500ULL * 1024 * 1024 ||
	    max_mem > 2ULL * 1024 * 1024 * 1024) {
		/* ios13extended_footprint is only for 2GB devices */
		return false;
	}
	return IOTaskHasEntitlement(task, "com.apple.developer.memory.ios13extended_footprint");
}

static int32_t
memorystatus_get_default_task_active_limit(proc_t p)
{
	bool entitled = memorystatus_task_has_increased_memory_limit_entitlement(proc_task(p));
	int32_t limit = -1;

	/*
	 * Check for the various entitlement footprint hacks
	 * and try to apply each one. Note that if multiple entitlements are present
	 * whichever results in the largest limit applies.
	 */
	if (entitled) {
		limit = MAX(limit, memorystatus_entitled_max_task_footprint_mb);
	}
#if __arm64__
	if (legacy_footprint_entitlement_mode == LEGACY_FOOTPRINT_ENTITLEMENT_LIMIT_INCREASE &&
	    memorystatus_task_has_legacy_footprint_entitlement(proc_task(p))) {
		limit = MAX(limit, max_task_footprint_mb + legacy_footprint_bonus_mb);
	}
#endif /* __arm64__ */
	if (memorystatus_task_has_ios13extended_footprint_limit(proc_task(p))) {
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
	memorystatus_memlimit_properties_t set_entry;

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
	set_entry.memlimit_active = entry->memlimit_active;
	set_entry.memlimit_active_attr = entry->memlimit_active_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;

	/*
	 * Setup the inactive memlimit properties
	 */
	set_entry.memlimit_inactive = entry->memlimit_inactive;
	set_entry.memlimit_inactive_attr = entry->memlimit_inactive_attr & MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;

	/*
	 * Setting a limit of <= 0 implies that the process has no
	 * high-water-mark and has no per-task-limit.  That means
	 * the system_wide task limit is in place, which by the way,
	 * is always fatal.
	 */

	if (set_entry.memlimit_active <= 0) {
		/*
		 * Enforce the fatal system_wide task limit while process is active.
		 */
		set_entry.memlimit_active = memorystatus_get_default_task_active_limit(p);
		set_entry.memlimit_active_attr = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	else {
		/* add the current increase to it, for roots */
		set_entry.memlimit_active += roundToNearestMB(p->p_memlimit_increase);
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

	if (set_entry.memlimit_inactive <= 0) {
		/*
		 * Enforce the fatal system_wide task limit while process is inactive.
		 */
		set_entry.memlimit_inactive = memorystatus_get_default_task_inactive_limit(p);
		set_entry.memlimit_inactive_attr = MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}
#if CONFIG_JETSAM
#if DEVELOPMENT || DEBUG
	else {
		/* add the current increase to it, for roots */
		set_entry.memlimit_inactive += roundToNearestMB(p->p_memlimit_increase);
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_JETSAM */

	proc_list_lock();

	int error = memorystatus_set_memlimit_properties_internal(p, &set_entry);

	proc_list_unlock();
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
	proc_list_unlock();

	proc_rele(p);

	return 0;
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
	 * Do not enforce it for snapshots.
	 */
	if (args->command != MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT) {
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
		error = memorystatus_cmd_get_priority_list(args->pid, args->buffer, args->buffersize, ret);
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

#if 0
	for (i = 0; i < nleaders; i++) {
		printf("%s: coal_leader[%d of %d] pid[%d] pages[%llu] ntasks[%d]\n",
		    __FUNCTION__, i, nleaders, leaders[i].msi_pid, leaders[i].msi_page_count,
		    leaders[i].msi_ntasks);
	}
#endif

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

#if 0
		if (pids_moved == leaders[i].msi_ntasks) {
			/*
			 * All the pids in the coalition were found in this band.
			 */
			printf("%s: pids_moved[%d]  equal  total coalition ntasks[%d] \n", __FUNCTION__,
			    pids_moved, leaders[i].msi_ntasks);
		} else if (pids_moved > leaders[i].msi_ntasks) {
			/*
			 * Apparently new coalition members showed up during the sort?
			 */
			printf("%s: pids_moved[%d] were greater than expected coalition ntasks[%d] \n", __FUNCTION__,
			    pids_moved, leaders[i].msi_ntasks);
		} else {
			/*
			 * Apparently not all the pids in the coalition were found in this band?
			 */
			printf("%s: pids_moved[%d] were less than  expected coalition ntasks[%d] \n", __FUNCTION__,
			    pids_moved, leaders[i].msi_ntasks);
		}
#endif

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

int
memorystatus_get_proccnt_upto_priority(int32_t max_bucket_index)
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
	 * We would like to use memorystatus_update() here to move the processes
	 * within the bands. Unfortunately memorystatus_update() calls
	 * memorystatus_update_priority_locked() which uses any band transitions
	 * as an indication to modify ledgers. For that it needs the task lock
	 * and since we came into this function with the task lock held, we'll deadlock.
	 *
	 * Unfortunately we can't completely disable ledger updates  because we still
	 * need the ledger updates for a subset of processes i.e. daemons.
	 * When all processes on all platforms support memory limits, we can simply call
	 * memorystatus_update().
	 *
	 * It also has some logic to deal with 'aging' which, currently, is only applicable
	 * on CONFIG_JETSAM configs. So, till every platform has CONFIG_JETSAM we'll need
	 * to do this explicit band transition.
	 */

	memstat_bucket_t *current_bucket, *new_bucket;
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
		uint64_t now;
		/*
		 * Transitioning out of the idle priority bucket.
		 * Record idle delta.
		 */
		assert(p->p_memstat_idle_start != 0);
		now = mach_absolute_time();
		if (now > p->p_memstat_idle_start) {
			p->p_memstat_idle_delta = now - p->p_memstat_idle_start;
		}
	} else if (priority == JETSAM_PRIORITY_IDLE) {
		/*
		 * Transitioning into the idle priority bucket.
		 * Record idle start.
		 */
		p->p_memstat_idle_start = mach_absolute_time();
	}

	KDBG(MEMSTAT_CODE(BSD_MEMSTAT_CHANGE_PRIORITY), proc_getpid(p), priority, p->p_memstat_effectivepriority);

	p->p_memstat_effectivepriority = priority;

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
	static bool healthy = true;
	bool prev_healthy = healthy;

	healthy = memorystatus_is_system_healthy(status);

	/*
	 * Avoid spamming logs by only logging when the health level has changed
	 */
	if (prev_healthy == healthy) {
		return;
	}

#if CONFIG_JETSAM
	if (healthy && !status->msh_available_pages_below_pressure) {
		memorystatus_log("memorystatus: System is healthy. memorystatus_available_pages: %llu compressor_size:%u\n",
		    (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		return;
	}
	if (healthy && status->msh_available_pages_below_pressure) {
		memorystatus_log(
			"memorystatus: System is below pressure level, but otherwise healthy. memorystatus_available_pages: %llu compressor_size:%u\n",
			(uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
		return;
	}
	memorystatus_log("memorystatus: System is unhealthy!  memorystatus_available_pages: %llu compressor_size:%u\n",
	    (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
	memorystatus_log(
		"memorystatus: available_pages_below_critical=%d, compressor_needs_to_swap=%d, compressor_is_low_on_space=%d compressor_is_thrashing=%d compressed_pages_nearing_limit=%d filecache_is_thrashing=%d zone_map_is_exhausted=%d phantom_cache_pressure=%d swappable_compressor_segments_over_limit=%d swapin_queue_over_limit=%d swap_low=%d swap_full=%d\n",
		status->msh_available_pages_below_critical, status->msh_compressor_needs_to_swap,
		status->msh_compressor_is_low_on_space, status->msh_compressor_is_thrashing,
		status->msh_compressed_pages_nearing_limit, status->msh_filecache_is_thrashing,
		status->msh_zone_map_is_exhausted, status->msh_phantom_cache_pressure,
		status->msh_swappable_compressor_segments_over_limit, status->msh_swapin_queue_over_limit,
		status->msh_swap_low_on_space, status->msh_swap_out_of_space);
#else /* CONFIG_JETSAM */
	memorystatus_log("memorystatus: System is %s. memorystatus_available_pages: %llu compressor_size:%u\n",
	    healthy ? "healthy" : "unhealthy",
	    (uint64_t)MEMORYSTATUS_LOG_AVAILABLE_PAGES, vm_compressor_pool_size());
	if (!healthy) {
		memorystatus_log("memorystatus: zone_map_is_exhausted=%d\n",
		    status->msh_zone_map_is_exhausted);
	}
#endif /* CONFIG_JETSAM */
}

uint32_t
memorystatus_pick_kill_cause(const memorystatus_system_health_t *status)
{
	assert(!memorystatus_is_system_healthy(status));
#if CONFIG_JETSAM
	if (status->msh_compressor_is_thrashing) {
		return kMemorystatusKilledVMCompressorThrashing;
	} else if (status->msh_compressor_is_low_on_space) {
		return kMemorystatusKilledVMCompressorSpaceShortage;
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
	assert(status->msh_zone_map_is_exhausted);
	(void) status;
	return kMemorystatusKilledZoneMapExhaustion;
#endif /* CONFIG_JETSAM */
}

#if DEVELOPMENT || DEBUG
static int
memorystatus_cmd_increase_jetsam_task_limit(pid_t pid, uint32_t byte_increase)
{
	memorystatus_memlimit_properties_t mmp_entry;

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

	memorystatus_get_memlimit_properties_internal(p, &mmp_entry);

	if (mmp_entry.memlimit_active > 0) {
		mmp_entry.memlimit_active -= current_memlimit_increase;
		mmp_entry.memlimit_active += roundToNearestMB(page_aligned_increase);
	}

	if (mmp_entry.memlimit_inactive > 0) {
		mmp_entry.memlimit_inactive -= current_memlimit_increase;
		mmp_entry.memlimit_inactive += roundToNearestMB(page_aligned_increase);
	}

	/*
	 * Store the updated delta limit in the proc.
	 */
	p->p_memlimit_increase = page_aligned_increase;

	int error = memorystatus_set_memlimit_properties_internal(p, &mmp_entry);

	proc_list_unlock();
	proc_rele(p);

	return error;
}
#endif /* DEVELOPMENT */
