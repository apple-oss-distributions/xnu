/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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

/*
 * Telemetry from the VM is usually colected at a daily cadence.
 * All of those events are in this file along with a single thread
 * call for reporting them.
 *
 * NB: The freezer subsystem has its own telemetry based on its budget interval
 * so it's not included here.
 */

#include <kern/thread_call.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <os/log.h>
#include <vm/vm_page.h>

#include "vm_compressor_backing_store.h"

void vm_analytics_tick(void *arg0, void *arg1);

#define ANALYTICS_PERIOD_HOURS (24ULL)

static thread_call_t vm_analytics_thread_call;

CA_EVENT(vm_swapusage,
    CA_INT, max_alloced,
    CA_INT, max_used,
    CA_INT, trial_deployment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_treatment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_experiment_id);

CA_EVENT(mlock_failures,
    CA_INT, over_global_limit,
    CA_INT, over_user_limit,
    CA_INT, trial_deployment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_treatment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_experiment_id);

/*
 * NB: It's a good practice to include these trial
 * identifiers in all of our events so that we can
 * measure the impact of any A/B tests on these metrics.
 */
extern uuid_string_t trial_treatment_id;
extern uuid_string_t trial_experiment_id;
extern int trial_deployment_id;

static void
add_trial_uuids(char *treatment_id, char *experiment_id)
{
	strlcpy(treatment_id, trial_treatment_id, CA_UUID_LEN);
	strlcpy(experiment_id, trial_experiment_id, CA_UUID_LEN);
}

static void
report_vm_swapusage()
{
	uint64_t max_alloced, max_used;
	ca_event_t event = CA_EVENT_ALLOCATE(vm_swapusage);
	CA_EVENT_TYPE(vm_swapusage) * e = event->data;

	vm_swap_reset_max_segs_tracking(&max_alloced, &max_used);
	e->max_alloced = max_alloced;
	e->max_used = max_used;
	add_trial_uuids(e->trial_treatment_id, e->trial_experiment_id);
	e->trial_deployment_id = trial_deployment_id;
	CA_EVENT_SEND(event);
}

static void
report_mlock_failures()
{
	ca_event_t event = CA_EVENT_ALLOCATE(mlock_failures);
	CA_EVENT_TYPE(mlock_failures) * e = event->data;

	e->over_global_limit = os_atomic_load_wide(&vm_add_wire_count_over_global_limit, relaxed);
	e->over_user_limit = os_atomic_load_wide(&vm_add_wire_count_over_user_limit, relaxed);

	os_atomic_store_wide(&vm_add_wire_count_over_global_limit, 0, relaxed);
	os_atomic_store_wide(&vm_add_wire_count_over_user_limit, 0, relaxed);

	add_trial_uuids(e->trial_treatment_id, e->trial_experiment_id);
	e->trial_deployment_id = trial_deployment_id;
	CA_EVENT_SEND(event);
}

#if XNU_TARGET_OS_WATCH
CA_EVENT(compressor_age,
    CA_INT, hour1,
    CA_INT, hour6,
    CA_INT, hour12,
    CA_INT, hour24,
    CA_INT, hour36,
    CA_INT, hour48,
    CA_INT, hourMax,
    CA_INT, trial_deployment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_treatment_id,
    CA_STATIC_STRING(CA_UUID_LEN), trial_experiment_id);

/**
 * Compressor age bucket descriptor.
 */
typedef struct {
	/* Number of segments in this bucket. */
	uint64_t count;
	/* The bucket's lower bound (inclusive) */
	uint64_t lower;
	/* The bucket's upper bound (exclusive) */
	uint64_t upper;
} c_reporting_bucket_t;
#define C_REPORTING_BUCKETS_MAX (UINT64_MAX)
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif
#define HR_TO_S(x) ((x) * 60 * 60)

/**
 * Report the age of segments in the compressor.
 */
static void
report_compressor_age()
{
	/* If the compressor is not configured, do nothing and return early. */
	if (vm_compressor_mode == VM_PAGER_NOT_CONFIGURED) {
		os_log(OS_LOG_DEFAULT, "%s: vm_compressor_mode == VM_PAGER_NOT_CONFIGURED, returning early", __func__);
		return;
	}

	const queue_head_t *c_queues[] = {&c_age_list_head, &c_major_list_head};
	c_reporting_bucket_t c_buckets[] = {
		{.count = 0, .lower = HR_TO_S(0), .upper = HR_TO_S(1)},  /* [0, 1) hours */
		{.count = 0, .lower = HR_TO_S(1), .upper = HR_TO_S(6)},  /* [1, 6) hours */
		{.count = 0, .lower = HR_TO_S(6), .upper = HR_TO_S(12)},  /* [6, 12) hours */
		{.count = 0, .lower = HR_TO_S(12), .upper = HR_TO_S(24)}, /* [12, 24) hours */
		{.count = 0, .lower = HR_TO_S(24), .upper = HR_TO_S(36)}, /* [24, 36) hours */
		{.count = 0, .lower = HR_TO_S(36), .upper = HR_TO_S(48)}, /* [36, 48) hours */
		{.count = 0, .lower = HR_TO_S(48), .upper = C_REPORTING_BUCKETS_MAX}, /* [48, MAX) hours */
	};
	clock_sec_t now;
	clock_nsec_t nsec;

	/* Collect the segments and update the bucket counts. */
	lck_mtx_lock_spin_always(c_list_lock);
	for (unsigned q = 0; q < ARRAY_SIZE(c_queues); q++) {
		c_segment_t c_seg = (c_segment_t) queue_first(c_queues[q]);
		while (!queue_end(c_queues[q], (queue_entry_t) c_seg)) {
			for (unsigned b = 0; b < ARRAY_SIZE(c_buckets); b++) {
				uint32_t creation_ts = c_seg->c_creation_ts;
				clock_get_system_nanotime(&now, &nsec);
				clock_sec_t age = now - creation_ts;
				if ((age >= c_buckets[b].lower) &&
				    (age < c_buckets[b].upper)) {
					c_buckets[b].count++;
					break;
				}
			}
			c_seg = (c_segment_t) queue_next(&c_seg->c_age_list);
		}
	}
	lck_mtx_unlock_always(c_list_lock);

	/* Send the ages to CoreAnalytics. */
	ca_event_t event = CA_EVENT_ALLOCATE(compressor_age);
	CA_EVENT_TYPE(compressor_age) * e = event->data;
	e->hour1 = c_buckets[0].count;
	e->hour6 = c_buckets[1].count;
	e->hour12 = c_buckets[2].count;
	e->hour24 = c_buckets[3].count;
	e->hour36 = c_buckets[4].count;
	e->hour48 = c_buckets[5].count;
	e->hourMax = c_buckets[6].count;
	add_trial_uuids(e->trial_treatment_id, e->trial_experiment_id);
	e->trial_deployment_id = trial_deployment_id;
	CA_EVENT_SEND(event);
}
#endif /* XNU_TARGET_OS_WATCH */


extern uint64_t max_mem;
CA_EVENT(accounting_health, CA_INT, percentage);
/**
 * Report health of resident vm page accounting.
 */
static void
report_accounting_health()
{
	/**
	 * @note If a new accounting bucket is added, it must also be added in
	 * MemoryMaintenance sysstatuscheck, which panics when accounting reaches
	 * unhealthy levels.
	 */
	int64_t pages = (vm_page_wire_count
	    + vm_page_free_count
	    + vm_page_inactive_count
	    + vm_page_active_count
	    + VM_PAGE_COMPRESSOR_COUNT
	    + vm_page_speculative_count
#if CONFIG_SECLUDED_MEMORY
	    + vm_page_secluded_count
#endif /* CONFIG_SECLUDED_MEMORY */
	    );
	int64_t percentage = (pages * 100) / (max_mem >> PAGE_SHIFT);

	/* Send the percentage health to CoreAnalytics. */
	ca_event_t event = CA_EVENT_ALLOCATE(accounting_health);
	CA_EVENT_TYPE(accounting_health) * e = event->data;
	e->percentage = percentage;
	CA_EVENT_SEND(event);
}

static void
schedule_analytics_thread_call()
{
	static const uint64_t analytics_period_ns = ANALYTICS_PERIOD_HOURS * 60 * 60 * NSEC_PER_SEC;
	uint64_t analytics_period_absolutetime;
	nanoseconds_to_absolutetime(analytics_period_ns, &analytics_period_absolutetime);

	thread_call_enter_delayed(vm_analytics_thread_call, analytics_period_absolutetime + mach_absolute_time());
}

/*
 * This is the main entry point for reporting periodic analytics.
 * It's called once every ANALYTICS_PERIOD_HOURS hours.
 */
void
vm_analytics_tick(void *arg0, void *arg1)
{
#pragma unused(arg0, arg1)
	report_vm_swapusage();
	report_mlock_failures();
#if XNU_TARGET_OS_WATCH
	report_compressor_age();
#endif /* XNU_TARGET_OS_WATCH */
	report_accounting_health();
	schedule_analytics_thread_call();
}

static void
vm_analytics_init()
{
	vm_analytics_thread_call = thread_call_allocate_with_options(vm_analytics_tick, NULL, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	schedule_analytics_thread_call();
}

STARTUP(THREAD_CALL, STARTUP_RANK_MIDDLE, vm_analytics_init);
