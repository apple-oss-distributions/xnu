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

#include <libkern/coreanalytics/coreanalytics.h>
#include "vm_compressor_backing_store.h"
#include <vm/vm_page.h>
#include <kern/thread_call.h>

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
	schedule_analytics_thread_call();
}

static void
vm_analytics_init()
{
	vm_analytics_thread_call = thread_call_allocate_with_options(vm_analytics_tick, NULL, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	schedule_analytics_thread_call();
}

STARTUP(THREAD_CALL, STARTUP_RANK_MIDDLE, vm_analytics_init);
