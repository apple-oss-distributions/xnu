/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
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

#include <arm/machine_cpu.h>
#include <arm/cpu_internal.h>
#include <arm/cpuid.h>
#include <arm/cpuid_internal.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <arm/machdep_call.h>
#include <arm/machine_routines.h>
#include <arm/rtclock.h>
#include <kern/machine.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/policy_internal.h>
#include <kern/sched_hygiene.h>
#include <kern/startup.h>
#include <machine/config.h>
#include <machine/atomic.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>

#if MONOTONIC
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* MONOTONIC */

#include <mach/machine.h>
#include <mach/machine/sdt.h>

#if !HAS_CONTINUOUS_HWCLOCK
extern uint64_t mach_absolutetime_asleep;
#else
extern uint64_t wake_abstime;
static uint64_t wake_conttime = UINT64_MAX;
#endif

extern volatile uint32_t debug_enabled;
extern _Atomic unsigned int cluster_type_num_active_cpus[MAX_CPU_TYPES];
const char *cluster_type_names[MAX_CPU_TYPES] = {
	[CLUSTER_TYPE_SMP] = "Standard",
	[CLUSTER_TYPE_P] = "Performance",
	[CLUSTER_TYPE_E] = "Efficiency",
};

static int max_cpus_initialized = 0;
#define MAX_CPUS_SET    0x1
#define MAX_CPUS_WAIT   0x2

LCK_GRP_DECLARE(max_cpus_grp, "max_cpus");
LCK_MTX_DECLARE(max_cpus_lock, &max_cpus_grp);
uint32_t lockdown_done = 0;
boolean_t is_clock_configured = FALSE;


static void
sched_perfcontrol_oncore_default(perfcontrol_state_t new_thread_state __unused, going_on_core_t on __unused)
{
}

static void
sched_perfcontrol_switch_default(perfcontrol_state_t old_thread_state __unused, perfcontrol_state_t new_thread_state __unused)
{
}

static void
sched_perfcontrol_offcore_default(perfcontrol_state_t old_thread_state __unused, going_off_core_t off __unused, boolean_t thread_terminating __unused)
{
}

static void
sched_perfcontrol_thread_group_default(thread_group_data_t data __unused)
{
}

static void
sched_perfcontrol_max_runnable_latency_default(perfcontrol_max_runnable_latency_t latencies __unused)
{
}

static void
sched_perfcontrol_work_interval_notify_default(perfcontrol_state_t thread_state __unused,
    perfcontrol_work_interval_t work_interval __unused)
{
}

static void
sched_perfcontrol_work_interval_ctl_default(perfcontrol_state_t thread_state __unused,
    perfcontrol_work_interval_instance_t instance __unused)
{
}

static void
sched_perfcontrol_deadline_passed_default(__unused uint64_t deadline)
{
}

static void
sched_perfcontrol_csw_default(
	__unused perfcontrol_event event, __unused uint32_t cpu_id, __unused uint64_t timestamp,
	__unused uint32_t flags, __unused struct perfcontrol_thread_data *offcore,
	__unused struct perfcontrol_thread_data *oncore,
	__unused struct perfcontrol_cpu_counters *cpu_counters, __unused void *unused)
{
}

static void
sched_perfcontrol_state_update_default(
	__unused perfcontrol_event event, __unused uint32_t cpu_id, __unused uint64_t timestamp,
	__unused uint32_t flags, __unused struct perfcontrol_thread_data *thr_data,
	__unused void *unused)
{
}

static void
sched_perfcontrol_thread_group_blocked_default(
	__unused thread_group_data_t blocked_tg, __unused thread_group_data_t blocking_tg,
	__unused uint32_t flags, __unused perfcontrol_state_t blocked_thr_state)
{
}

static void
sched_perfcontrol_thread_group_unblocked_default(
	__unused thread_group_data_t unblocked_tg, __unused thread_group_data_t unblocking_tg,
	__unused uint32_t flags, __unused perfcontrol_state_t unblocked_thr_state)
{
}

sched_perfcontrol_offcore_t                     sched_perfcontrol_offcore = sched_perfcontrol_offcore_default;
sched_perfcontrol_context_switch_t              sched_perfcontrol_switch = sched_perfcontrol_switch_default;
sched_perfcontrol_oncore_t                      sched_perfcontrol_oncore = sched_perfcontrol_oncore_default;
sched_perfcontrol_thread_group_init_t           sched_perfcontrol_thread_group_init = sched_perfcontrol_thread_group_default;
sched_perfcontrol_thread_group_deinit_t         sched_perfcontrol_thread_group_deinit = sched_perfcontrol_thread_group_default;
sched_perfcontrol_thread_group_flags_update_t   sched_perfcontrol_thread_group_flags_update = sched_perfcontrol_thread_group_default;
sched_perfcontrol_max_runnable_latency_t        sched_perfcontrol_max_runnable_latency = sched_perfcontrol_max_runnable_latency_default;
sched_perfcontrol_work_interval_notify_t        sched_perfcontrol_work_interval_notify = sched_perfcontrol_work_interval_notify_default;
sched_perfcontrol_work_interval_ctl_t           sched_perfcontrol_work_interval_ctl = sched_perfcontrol_work_interval_ctl_default;
sched_perfcontrol_deadline_passed_t             sched_perfcontrol_deadline_passed = sched_perfcontrol_deadline_passed_default;
sched_perfcontrol_csw_t                         sched_perfcontrol_csw = sched_perfcontrol_csw_default;
sched_perfcontrol_state_update_t                sched_perfcontrol_state_update = sched_perfcontrol_state_update_default;
sched_perfcontrol_thread_group_blocked_t        sched_perfcontrol_thread_group_blocked = sched_perfcontrol_thread_group_blocked_default;
sched_perfcontrol_thread_group_unblocked_t      sched_perfcontrol_thread_group_unblocked = sched_perfcontrol_thread_group_unblocked_default;
boolean_t sched_perfcontrol_thread_shared_rsrc_flags_enabled = false;

void
sched_perfcontrol_register_callbacks(sched_perfcontrol_callbacks_t callbacks, unsigned long size_of_state)
{
	assert(callbacks == NULL || callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_2);

	if (size_of_state > sizeof(struct perfcontrol_state)) {
		panic("%s: Invalid required state size %lu", __FUNCTION__, size_of_state);
	}

	if (callbacks) {
#if CONFIG_THREAD_GROUPS
		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_3) {
			if (callbacks->thread_group_init != NULL) {
				sched_perfcontrol_thread_group_init = callbacks->thread_group_init;
			} else {
				sched_perfcontrol_thread_group_init = sched_perfcontrol_thread_group_default;
			}
			if (callbacks->thread_group_deinit != NULL) {
				sched_perfcontrol_thread_group_deinit = callbacks->thread_group_deinit;
			} else {
				sched_perfcontrol_thread_group_deinit = sched_perfcontrol_thread_group_default;
			}
			// tell CLPC about existing thread groups
			thread_group_resync(TRUE);
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_6) {
			if (callbacks->thread_group_flags_update != NULL) {
				sched_perfcontrol_thread_group_flags_update = callbacks->thread_group_flags_update;
			} else {
				sched_perfcontrol_thread_group_flags_update = sched_perfcontrol_thread_group_default;
			}
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_8) {
			if (callbacks->thread_group_blocked != NULL) {
				sched_perfcontrol_thread_group_blocked = callbacks->thread_group_blocked;
			} else {
				sched_perfcontrol_thread_group_blocked = sched_perfcontrol_thread_group_blocked_default;
			}

			if (callbacks->thread_group_unblocked != NULL) {
				sched_perfcontrol_thread_group_unblocked = callbacks->thread_group_unblocked;
			} else {
				sched_perfcontrol_thread_group_unblocked = sched_perfcontrol_thread_group_unblocked_default;
			}
		}
#endif
		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_9) {
			sched_perfcontrol_thread_shared_rsrc_flags_enabled = true;
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_7) {
			if (callbacks->work_interval_ctl != NULL) {
				sched_perfcontrol_work_interval_ctl = callbacks->work_interval_ctl;
			} else {
				sched_perfcontrol_work_interval_ctl = sched_perfcontrol_work_interval_ctl_default;
			}
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_5) {
			if (callbacks->csw != NULL) {
				sched_perfcontrol_csw = callbacks->csw;
			} else {
				sched_perfcontrol_csw = sched_perfcontrol_csw_default;
			}

			if (callbacks->state_update != NULL) {
				sched_perfcontrol_state_update = callbacks->state_update;
			} else {
				sched_perfcontrol_state_update = sched_perfcontrol_state_update_default;
			}
		}

		if (callbacks->version >= SCHED_PERFCONTROL_CALLBACKS_VERSION_4) {
			if (callbacks->deadline_passed != NULL) {
				sched_perfcontrol_deadline_passed = callbacks->deadline_passed;
			} else {
				sched_perfcontrol_deadline_passed = sched_perfcontrol_deadline_passed_default;
			}
		}

		if (callbacks->offcore != NULL) {
			sched_perfcontrol_offcore = callbacks->offcore;
		} else {
			sched_perfcontrol_offcore = sched_perfcontrol_offcore_default;
		}

		if (callbacks->context_switch != NULL) {
			sched_perfcontrol_switch = callbacks->context_switch;
		} else {
			sched_perfcontrol_switch = sched_perfcontrol_switch_default;
		}

		if (callbacks->oncore != NULL) {
			sched_perfcontrol_oncore = callbacks->oncore;
		} else {
			sched_perfcontrol_oncore = sched_perfcontrol_oncore_default;
		}

		if (callbacks->max_runnable_latency != NULL) {
			sched_perfcontrol_max_runnable_latency = callbacks->max_runnable_latency;
		} else {
			sched_perfcontrol_max_runnable_latency = sched_perfcontrol_max_runnable_latency_default;
		}

		if (callbacks->work_interval_notify != NULL) {
			sched_perfcontrol_work_interval_notify = callbacks->work_interval_notify;
		} else {
			sched_perfcontrol_work_interval_notify = sched_perfcontrol_work_interval_notify_default;
		}
	} else {
		/* reset to defaults */
#if CONFIG_THREAD_GROUPS
		thread_group_resync(FALSE);
#endif
		sched_perfcontrol_offcore = sched_perfcontrol_offcore_default;
		sched_perfcontrol_switch = sched_perfcontrol_switch_default;
		sched_perfcontrol_oncore = sched_perfcontrol_oncore_default;
		sched_perfcontrol_thread_group_init = sched_perfcontrol_thread_group_default;
		sched_perfcontrol_thread_group_deinit = sched_perfcontrol_thread_group_default;
		sched_perfcontrol_thread_group_flags_update = sched_perfcontrol_thread_group_default;
		sched_perfcontrol_max_runnable_latency = sched_perfcontrol_max_runnable_latency_default;
		sched_perfcontrol_work_interval_notify = sched_perfcontrol_work_interval_notify_default;
		sched_perfcontrol_work_interval_ctl = sched_perfcontrol_work_interval_ctl_default;
		sched_perfcontrol_csw = sched_perfcontrol_csw_default;
		sched_perfcontrol_state_update = sched_perfcontrol_state_update_default;
		sched_perfcontrol_thread_group_blocked = sched_perfcontrol_thread_group_blocked_default;
		sched_perfcontrol_thread_group_unblocked = sched_perfcontrol_thread_group_unblocked_default;
	}
}


static void
machine_switch_populate_perfcontrol_thread_data(struct perfcontrol_thread_data *data,
    thread_t thread,
    uint64_t same_pri_latency)
{
	bzero(data, sizeof(struct perfcontrol_thread_data));
	data->perfctl_class = thread_get_perfcontrol_class(thread);
	data->energy_estimate_nj = 0;
	data->thread_id = thread->thread_id;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg = thread_group_get(thread);
	data->thread_group_id = thread_group_get_id(tg);
	data->thread_group_data = thread_group_get_machine_data(tg);
#endif
	data->scheduling_latency_at_same_basepri = same_pri_latency;
	data->perfctl_state = FIND_PERFCONTROL_STATE(thread);
}

static void
machine_switch_populate_perfcontrol_cpu_counters(struct perfcontrol_cpu_counters *cpu_counters)
{
#if MONOTONIC
	mt_perfcontrol(&cpu_counters->instructions, &cpu_counters->cycles);
#else /* MONOTONIC */
	cpu_counters->instructions = 0;
	cpu_counters->cycles = 0;
#endif /* !MONOTONIC */
}

int perfcontrol_callout_stats_enabled = 0;
static _Atomic uint64_t perfcontrol_callout_stats[PERFCONTROL_CALLOUT_MAX][PERFCONTROL_STAT_MAX];
static _Atomic uint64_t perfcontrol_callout_count[PERFCONTROL_CALLOUT_MAX];

#if MONOTONIC
static inline
bool
perfcontrol_callout_counters_begin(uint64_t *counters)
{
	if (!perfcontrol_callout_stats_enabled) {
		return false;
	}
	mt_fixed_counts(counters);
	return true;
}

static inline
void
perfcontrol_callout_counters_end(uint64_t *start_counters,
    perfcontrol_callout_type_t type)
{
	uint64_t end_counters[MT_CORE_NFIXED];
	mt_fixed_counts(end_counters);
	os_atomic_add(&perfcontrol_callout_stats[type][PERFCONTROL_STAT_CYCLES],
	    end_counters[MT_CORE_CYCLES] - start_counters[MT_CORE_CYCLES], relaxed);
	os_atomic_add(&perfcontrol_callout_stats[type][PERFCONTROL_STAT_INSTRS],
	    end_counters[MT_CORE_INSTRS] - start_counters[MT_CORE_INSTRS], relaxed);
	os_atomic_inc(&perfcontrol_callout_count[type], relaxed);
}
#endif /* MONOTONIC */

uint64_t
perfcontrol_callout_stat_avg(perfcontrol_callout_type_t type,
    perfcontrol_callout_stat_t stat)
{
	if (!perfcontrol_callout_stats_enabled) {
		return 0;
	}
	return os_atomic_load_wide(&perfcontrol_callout_stats[type][stat], relaxed) /
	       os_atomic_load_wide(&perfcontrol_callout_count[type], relaxed);
}


#if CONFIG_SCHED_EDGE

/*
 * The Edge scheduler allows the performance controller to update properties about the
 * threads as part of the callouts. These properties typically include shared cluster
 * resource usage. This allows the scheduler to manage specific threads within the
 * workload more optimally.
 */
static void
sched_perfcontrol_thread_flags_update(thread_t thread,
    struct perfcontrol_thread_data *thread_data,
    shared_rsrc_policy_agent_t agent)
{
	kern_return_t kr = KERN_SUCCESS;
	if (thread_data->thread_flags_mask & PERFCTL_THREAD_FLAGS_MASK_CLUSTER_SHARED_RSRC_RR) {
		if (thread_data->thread_flags & PERFCTL_THREAD_FLAGS_MASK_CLUSTER_SHARED_RSRC_RR) {
			kr = thread_shared_rsrc_policy_set(thread, 0, CLUSTER_SHARED_RSRC_TYPE_RR, agent);
		} else {
			kr = thread_shared_rsrc_policy_clear(thread, CLUSTER_SHARED_RSRC_TYPE_RR, agent);
		}
	}
	if (thread_data->thread_flags_mask & PERFCTL_THREAD_FLAGS_MASK_CLUSTER_SHARED_RSRC_NATIVE_FIRST) {
		if (thread_data->thread_flags & PERFCTL_THREAD_FLAGS_MASK_CLUSTER_SHARED_RSRC_NATIVE_FIRST) {
			kr = thread_shared_rsrc_policy_set(thread, 0, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST, agent);
		} else {
			kr = thread_shared_rsrc_policy_clear(thread, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST, agent);
		}
	}
	/*
	 * The thread_shared_rsrc_policy_* routines only fail if the performance controller is
	 * attempting to double set/clear a policy on the thread.
	 */
	assert(kr == KERN_SUCCESS);
}

#endif /* CONFIG_SCHED_EDGE */

void
machine_switch_perfcontrol_context(perfcontrol_event event,
    uint64_t timestamp,
    uint32_t flags,
    uint64_t new_thread_same_pri_latency,
    thread_t old,
    thread_t new)
{

	if (sched_perfcontrol_switch != sched_perfcontrol_switch_default) {
		perfcontrol_state_t old_perfcontrol_state = FIND_PERFCONTROL_STATE(old);
		perfcontrol_state_t new_perfcontrol_state = FIND_PERFCONTROL_STATE(new);
		sched_perfcontrol_switch(old_perfcontrol_state, new_perfcontrol_state);
	}

	if (sched_perfcontrol_csw != sched_perfcontrol_csw_default) {
		uint32_t cpu_id = (uint32_t)cpu_number();
		struct perfcontrol_cpu_counters cpu_counters;
		struct perfcontrol_thread_data offcore, oncore;
		machine_switch_populate_perfcontrol_thread_data(&offcore, old, 0);
		machine_switch_populate_perfcontrol_thread_data(&oncore, new,
		    new_thread_same_pri_latency);
		machine_switch_populate_perfcontrol_cpu_counters(&cpu_counters);

#if MONOTONIC
		uint64_t counters[MT_CORE_NFIXED];
		bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
		sched_perfcontrol_csw(event, cpu_id, timestamp, flags,
		    &offcore, &oncore, &cpu_counters, NULL);
#if MONOTONIC
		if (ctrs_enabled) {
			perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_CONTEXT);
		}
#endif /* MONOTONIC */

		recount_add_energy(old, get_threadtask(old),
		    offcore.energy_estimate_nj);

#if CONFIG_SCHED_EDGE
		if (sched_perfcontrol_thread_shared_rsrc_flags_enabled) {
			sched_perfcontrol_thread_flags_update(old, &offcore, SHARED_RSRC_POLICY_AGENT_PERFCTL_CSW);
		}
#endif /* CONFIG_SCHED_EDGE */
	}
}

void
machine_switch_perfcontrol_state_update(perfcontrol_event event,
    uint64_t timestamp,
    uint32_t flags,
    thread_t thread)
{

	if (sched_perfcontrol_state_update == sched_perfcontrol_state_update_default) {
		return;
	}
	uint32_t cpu_id = (uint32_t)cpu_number();
	struct perfcontrol_thread_data data;
	machine_switch_populate_perfcontrol_thread_data(&data, thread, 0);

#if MONOTONIC
	uint64_t counters[MT_CORE_NFIXED];
	bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
	sched_perfcontrol_state_update(event, cpu_id, timestamp, flags,
	    &data, NULL);
#if MONOTONIC
	if (ctrs_enabled) {
		perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_STATE_UPDATE);
	}
#endif /* MONOTONIC */

#if CONFIG_PERVASIVE_ENERGY
	recount_add_energy(thread, get_threadtask(thread), data.energy_estimate_nj);
#endif /* CONFIG_PERVASIVE_ENERGY */

#if CONFIG_SCHED_EDGE
	if (sched_perfcontrol_thread_shared_rsrc_flags_enabled && (event == QUANTUM_EXPIRY)) {
		sched_perfcontrol_thread_flags_update(thread, &data, SHARED_RSRC_POLICY_AGENT_PERFCTL_QUANTUM);
	} else {
		assert(data.thread_flags_mask == 0);
	}
#endif /* CONFIG_SCHED_EDGE */
}

void
machine_thread_going_on_core(thread_t   new_thread,
    thread_urgency_t        urgency,
    uint64_t   sched_latency,
    uint64_t   same_pri_latency,
    uint64_t   timestamp)
{
	if (sched_perfcontrol_oncore == sched_perfcontrol_oncore_default) {
		return;
	}
	struct going_on_core on_core;
	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(new_thread);

	on_core.thread_id = new_thread->thread_id;
	on_core.energy_estimate_nj = 0;
	on_core.qos_class = (uint16_t)proc_get_effective_thread_policy(new_thread, TASK_POLICY_QOS);
	on_core.urgency = (uint16_t)urgency;
	on_core.is_32_bit = thread_is_64bit_data(new_thread) ? FALSE : TRUE;
	on_core.is_kernel_thread = get_threadtask(new_thread) == kernel_task;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg = thread_group_get(new_thread);
	on_core.thread_group_id = thread_group_get_id(tg);
	on_core.thread_group_data = thread_group_get_machine_data(tg);
#endif
	on_core.scheduling_latency = sched_latency;
	on_core.start_time = timestamp;
	on_core.scheduling_latency_at_same_basepri = same_pri_latency;

#if MONOTONIC
	uint64_t counters[MT_CORE_NFIXED];
	bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
	sched_perfcontrol_oncore(state, &on_core);
#if MONOTONIC
	if (ctrs_enabled) {
		perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_ON_CORE);
	}
#endif /* MONOTONIC */
}

void
machine_thread_going_off_core(thread_t old_thread, boolean_t thread_terminating,
    uint64_t last_dispatch, __unused boolean_t thread_runnable)
{
	if (sched_perfcontrol_offcore == sched_perfcontrol_offcore_default) {
		return;
	}
	struct going_off_core off_core;
	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(old_thread);

	off_core.thread_id = old_thread->thread_id;
	off_core.energy_estimate_nj = 0;
	off_core.end_time = last_dispatch;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg = thread_group_get(old_thread);
	off_core.thread_group_id = thread_group_get_id(tg);
	off_core.thread_group_data = thread_group_get_machine_data(tg);
#endif

#if MONOTONIC
	uint64_t counters[MT_CORE_NFIXED];
	bool ctrs_enabled = perfcontrol_callout_counters_begin(counters);
#endif /* MONOTONIC */
	sched_perfcontrol_offcore(state, &off_core, thread_terminating);
#if MONOTONIC
	if (ctrs_enabled) {
		perfcontrol_callout_counters_end(counters, PERFCONTROL_CALLOUT_OFF_CORE);
	}
#endif /* MONOTONIC */
}

#if CONFIG_THREAD_GROUPS
void
machine_thread_group_init(struct thread_group *tg)
{
	if (sched_perfcontrol_thread_group_init == sched_perfcontrol_thread_group_default) {
		return;
	}
	struct thread_group_data data;
	data.thread_group_id = thread_group_get_id(tg);
	data.thread_group_data = thread_group_get_machine_data(tg);
	data.thread_group_size = thread_group_machine_data_size();
	data.thread_group_flags = thread_group_get_flags(tg);
	sched_perfcontrol_thread_group_init(&data);
}

void
machine_thread_group_deinit(struct thread_group *tg)
{
	if (sched_perfcontrol_thread_group_deinit == sched_perfcontrol_thread_group_default) {
		return;
	}
	struct thread_group_data data;
	data.thread_group_id = thread_group_get_id(tg);
	data.thread_group_data = thread_group_get_machine_data(tg);
	data.thread_group_size = thread_group_machine_data_size();
	data.thread_group_flags = thread_group_get_flags(tg);
	sched_perfcontrol_thread_group_deinit(&data);
}

void
machine_thread_group_flags_update(struct thread_group *tg, uint32_t flags)
{
	if (sched_perfcontrol_thread_group_flags_update == sched_perfcontrol_thread_group_default) {
		return;
	}
	struct thread_group_data data;
	data.thread_group_id = thread_group_get_id(tg);
	data.thread_group_data = thread_group_get_machine_data(tg);
	data.thread_group_size = thread_group_machine_data_size();
	data.thread_group_flags = flags;
	sched_perfcontrol_thread_group_flags_update(&data);
}

void
machine_thread_group_blocked(struct thread_group *blocked_tg,
    struct thread_group *blocking_tg,
    uint32_t flags,
    thread_t blocked_thread)
{
	if (sched_perfcontrol_thread_group_blocked == sched_perfcontrol_thread_group_blocked_default) {
		return;
	}

	spl_t s = splsched();

	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(blocked_thread);
	struct thread_group_data blocked_data;
	assert(blocked_tg != NULL);

	blocked_data.thread_group_id = thread_group_get_id(blocked_tg);
	blocked_data.thread_group_data = thread_group_get_machine_data(blocked_tg);
	blocked_data.thread_group_size = thread_group_machine_data_size();

	if (blocking_tg == NULL) {
		/*
		 * For special cases such as the render server, the blocking TG is a
		 * well known TG. Only in that case, the blocking_tg should be NULL.
		 */
		assert(flags & PERFCONTROL_CALLOUT_BLOCKING_TG_RENDER_SERVER);
		sched_perfcontrol_thread_group_blocked(&blocked_data, NULL, flags, state);
	} else {
		struct thread_group_data blocking_data;
		blocking_data.thread_group_id = thread_group_get_id(blocking_tg);
		blocking_data.thread_group_data = thread_group_get_machine_data(blocking_tg);
		blocking_data.thread_group_size = thread_group_machine_data_size();
		sched_perfcontrol_thread_group_blocked(&blocked_data, &blocking_data, flags, state);
	}
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_BLOCK) | DBG_FUNC_START,
	    thread_tid(blocked_thread), thread_group_get_id(blocked_tg),
	    blocking_tg ? thread_group_get_id(blocking_tg) : THREAD_GROUP_INVALID,
	    flags);

	splx(s);
}

void
machine_thread_group_unblocked(struct thread_group *unblocked_tg,
    struct thread_group *unblocking_tg,
    uint32_t flags,
    thread_t unblocked_thread)
{
	if (sched_perfcontrol_thread_group_unblocked == sched_perfcontrol_thread_group_unblocked_default) {
		return;
	}

	spl_t s = splsched();

	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(unblocked_thread);
	struct thread_group_data unblocked_data;
	assert(unblocked_tg != NULL);

	unblocked_data.thread_group_id = thread_group_get_id(unblocked_tg);
	unblocked_data.thread_group_data = thread_group_get_machine_data(unblocked_tg);
	unblocked_data.thread_group_size = thread_group_machine_data_size();

	if (unblocking_tg == NULL) {
		/*
		 * For special cases such as the render server, the unblocking TG is a
		 * well known TG. Only in that case, the unblocking_tg should be NULL.
		 */
		assert(flags & PERFCONTROL_CALLOUT_BLOCKING_TG_RENDER_SERVER);
		sched_perfcontrol_thread_group_unblocked(&unblocked_data, NULL, flags, state);
	} else {
		struct thread_group_data unblocking_data;
		unblocking_data.thread_group_id = thread_group_get_id(unblocking_tg);
		unblocking_data.thread_group_data = thread_group_get_machine_data(unblocking_tg);
		unblocking_data.thread_group_size = thread_group_machine_data_size();
		sched_perfcontrol_thread_group_unblocked(&unblocked_data, &unblocking_data, flags, state);
	}
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_BLOCK) | DBG_FUNC_END,
	    thread_tid(unblocked_thread), thread_group_get_id(unblocked_tg),
	    unblocking_tg ? thread_group_get_id(unblocking_tg) : THREAD_GROUP_INVALID,
	    flags);

	splx(s);
}

#endif /* CONFIG_THREAD_GROUPS */

void
machine_max_runnable_latency(uint64_t bg_max_latency,
    uint64_t default_max_latency,
    uint64_t realtime_max_latency)
{
	if (sched_perfcontrol_max_runnable_latency == sched_perfcontrol_max_runnable_latency_default) {
		return;
	}
	struct perfcontrol_max_runnable_latency latencies = {
		.max_scheduling_latencies = {
			[THREAD_URGENCY_NONE] = 0,
			[THREAD_URGENCY_BACKGROUND] = bg_max_latency,
			[THREAD_URGENCY_NORMAL] = default_max_latency,
			[THREAD_URGENCY_REAL_TIME] = realtime_max_latency
		}
	};

	sched_perfcontrol_max_runnable_latency(&latencies);
}

void
machine_work_interval_notify(thread_t thread,
    struct kern_work_interval_args* kwi_args)
{
	if (sched_perfcontrol_work_interval_notify == sched_perfcontrol_work_interval_notify_default) {
		return;
	}
	perfcontrol_state_t state = FIND_PERFCONTROL_STATE(thread);
	struct perfcontrol_work_interval work_interval = {
		.thread_id      = thread->thread_id,
		.qos_class      = (uint16_t)proc_get_effective_thread_policy(thread, TASK_POLICY_QOS),
		.urgency        = kwi_args->urgency,
		.flags          = kwi_args->notify_flags,
		.work_interval_id = kwi_args->work_interval_id,
		.start          = kwi_args->start,
		.finish         = kwi_args->finish,
		.deadline       = kwi_args->deadline,
		.next_start     = kwi_args->next_start,
		.create_flags   = kwi_args->create_flags,
	};
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg;
	tg = thread_group_get(thread);
	work_interval.thread_group_id = thread_group_get_id(tg);
	work_interval.thread_group_data = thread_group_get_machine_data(tg);
#endif
	sched_perfcontrol_work_interval_notify(state, &work_interval);
}


void
machine_perfcontrol_deadline_passed(uint64_t deadline)
{
	if (sched_perfcontrol_deadline_passed != sched_perfcontrol_deadline_passed_default) {
		sched_perfcontrol_deadline_passed(deadline);
	}
}

#if SCHED_HYGIENE_DEBUG

__options_decl(int_mask_hygiene_flags_t, uint8_t, {
	INT_MASK_BASE = 0x00,
	INT_MASK_FROM_HANDLER = 0x01,
	INT_MASK_IS_STACKSHOT = 0x02,
});

/*
 * ml_spin_debug_reset()
 * Reset the timestamp on a thread that has been unscheduled
 * to avoid false alarms. Alarm will go off if interrupts are held
 * disabled for too long, starting from now.
 *
 * Call ml_get_timebase() directly to prevent extra overhead on newer
 * platforms that's enabled in DEVELOPMENT kernel configurations.
 */
void
ml_spin_debug_reset(thread_t thread)
{
	if (thread->machine.intmask_timestamp) {
		thread->machine.intmask_timestamp = ml_get_sched_hygiene_timebase();
		INTERRUPT_MASKED_DEBUG_CAPTURE_PMC(thread);
	}
}

/*
 * ml_spin_debug_clear()
 * Clear the timestamp and cycle/instruction counts on a thread that
 * has been unscheduled to avoid false alarms
 */
void
ml_spin_debug_clear(thread_t thread)
{
	thread->machine.intmask_timestamp = 0;
	thread->machine.intmask_cycles = 0;
	thread->machine.intmask_instr = 0;
}

/*
 * ml_spin_debug_clear_self()
 * Clear the timestamp on the current thread to prevent
 * false alarms
 */
void
ml_spin_debug_clear_self(void)
{
	ml_spin_debug_clear(current_thread());
}

#ifndef KASAN

/*
 * Get a character representing the provided thread's kind of CPU.
 */
#if !MONOTONIC
__unused
#endif // !MONOTONIC
static char
__ml_interrupts_disabled_cpu_kind(thread_t thread)
{
#if __AMP__
	processor_t processor = thread->last_processor;
	if (!processor) {
		return '!';
	}

	switch (processor->processor_set->pset_cluster_type) {
	case PSET_AMP_P:
		return 'P';
	case PSET_AMP_E:
		return 'E';
	default:
		return '?';
	}
#else // __AMP__
#pragma unused(thread)
	return '-';
#endif // !__AMP__
}

#define EXTRA_INFO_STRING_SIZE 256
#define LOW_FREQ_THRESHOLD_MHZ 500
#define HIGH_CPI_THRESHOLD     3

static void
__ml_trigger_interrupts_disabled_handle(thread_t thread, uint64_t start, uint64_t now, uint64_t timeout, int_mask_hygiene_flags_t flags)
{
	mach_timebase_info_data_t timebase;
	clock_timebase_info(&timebase);
	bool is_int_handler = flags & INT_MASK_FROM_HANDLER;
	bool is_stackshot = flags & INT_MASK_IS_STACKSHOT;

	const uint64_t time_elapsed = now - start;
	const uint64_t time_elapsed_ns = (time_elapsed * timebase.numer) / timebase.denom;

	uint64_t current_cycles = 0, current_instrs = 0;

#if MONOTONIC
	if (sched_hygiene_debug_pmc) {
		mt_cur_cpu_cycles_instrs_speculative(&current_cycles, &current_instrs);
	}
#endif // MONOTONIC

	const uint64_t cycles_elapsed = current_cycles - thread->machine.intmask_cycles;
	const uint64_t instrs_elapsed = current_instrs - thread->machine.intmask_instr;

	if (interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
		const uint64_t timeout_ns = ((timeout * debug_cpu_performance_degradation_factor) * timebase.numer) / timebase.denom;
		char extra_info_string[EXTRA_INFO_STRING_SIZE] = { '\0' };
#if MONOTONIC
		if (sched_hygiene_debug_pmc) {
			const uint64_t time_elapsed_us = time_elapsed_ns / 1000;
			const uint64_t average_freq_mhz = cycles_elapsed / time_elapsed_us;
			const uint64_t average_cpi_whole = cycles_elapsed / instrs_elapsed;
			const uint64_t average_cpi_fractional = ((cycles_elapsed * 100) / instrs_elapsed) % 100;
			bool high_cpi = average_cpi_whole >= HIGH_CPI_THRESHOLD;
			char core_kind = __ml_interrupts_disabled_cpu_kind(thread);
			bool low_mhz = average_freq_mhz < LOW_FREQ_THRESHOLD_MHZ;

			snprintf(extra_info_string, EXTRA_INFO_STRING_SIZE,
			    ", %sfreq = %llu MHz, %sCPI = %llu.%llu, CPU kind = %c",
			    low_mhz ? "low " : "",
			    average_freq_mhz,
			    high_cpi ? "high " : "",
			    average_cpi_whole,
			    average_cpi_fractional,
			    core_kind);
		}
#endif // MONOTONIC

		if (is_int_handler) {
			panic("Processing of an interrupt (type = %u, handler address = %p, vector = %p) "
			    "took %llu nanoseconds (start = %llu, now = %llu, timeout = %llu ns%s)",
			    thread->machine.int_type, (void *)thread->machine.int_handler_addr, (void *)thread->machine.int_vector,
			    time_elapsed_ns, start, now, timeout_ns, extra_info_string);
		} else {
			panic("%s for %llu nanoseconds (start = %llu, now = %llu, timeout = %llu ns%s)",
			    is_stackshot ? "Stackshot disabled interrupts" : "Interrupts held disabled",
			    time_elapsed_ns, start, now, timeout_ns, extra_info_string);
		}
	} else if (interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_TRACE) {
		if (is_int_handler) {
			static const uint32_t interrupt_handled_dbgid =
			    MACHDBG_CODE(DBG_MACH_SCHED, MACH_INT_HANDLED_EXPIRED);
			DTRACE_SCHED3(interrupt_handled_dbgid, uint64_t, time_elapsed,
			    uint64_t, cycles_elapsed, uint64_t, instrs_elapsed);
			KDBG(interrupt_handled_dbgid, time_elapsed,
			    cycles_elapsed, instrs_elapsed);
		} else {
			static const uint32_t interrupt_masked_dbgid =
			    MACHDBG_CODE(DBG_MACH_SCHED, MACH_INT_MASKED_EXPIRED);
			DTRACE_SCHED3(interrupt_masked_dbgid, uint64_t, time_elapsed,
			    uint64_t, cycles_elapsed, uint64_t, instrs_elapsed);
			KDBG(interrupt_masked_dbgid, time_elapsed,
			    cycles_elapsed, instrs_elapsed);
		}
	}
}
#endif // !defined(KASAN)

static inline void
__ml_handle_interrupts_disabled_duration(thread_t thread, uint64_t timeout, bool is_int_handler)
{
	if (timeout == 0) {
		return; // 0 means timeout disabled.
	}
	uint64_t start = is_int_handler ? thread->machine.inthandler_timestamp : thread->machine.intmask_timestamp;
	if (start != 0) {
		uint64_t now = ml_get_sched_hygiene_timebase();

		if (interrupt_masked_debug_mode &&
		    ((now - start) > timeout * debug_cpu_performance_degradation_factor) &&
		    !thread->machine.inthandler_abandon) {
			/*
			 * Disable the actual panic for KASAN due to the overhead of KASAN itself, leave the rest of the
			 * mechanism enabled so that KASAN can catch any bugs in the mechanism itself.
			 */
#ifndef KASAN
			__ml_trigger_interrupts_disabled_handle(thread, start, now, timeout, is_int_handler);
#endif
		}

		if (is_int_handler) {
			uint64_t const duration = now - start;
#if SCHED_HYGIENE_DEBUG
			ml_adjust_preemption_disable_time(thread, duration);
#endif /* SCHED_HYGIENE_DEBUG */
			/*
			 * No need for an atomic add, the only thread modifying
			 * this is ourselves. Other threads querying will just see
			 * either the old or the new value. (This will also just
			 * resolve to regular loads and stores on relevant
			 * platforms.)
			 */
			uint64_t const old_duration = os_atomic_load_wide(&thread->machine.int_time_mt, relaxed);
			os_atomic_store_wide(&thread->machine.int_time_mt, old_duration + duration, relaxed);
		}
	}
}

void
ml_handle_interrupts_disabled_duration(thread_t thread)
{
	__ml_handle_interrupts_disabled_duration(thread, os_atomic_load(&interrupt_masked_timeout, relaxed), INT_MASK_BASE);
}

void
ml_handle_stackshot_interrupt_disabled_duration(thread_t thread)
{
	/* Use MAX() to let the user bump the timeout further if needed */
	uint64_t stackshot_timeout = os_atomic_load(&stackshot_interrupt_masked_timeout, relaxed);
	uint64_t normal_timeout = os_atomic_load(&interrupt_masked_timeout, relaxed);
	uint64_t timeout = MAX(stackshot_timeout, normal_timeout);
	__ml_handle_interrupts_disabled_duration(thread, timeout, INT_MASK_IS_STACKSHOT);
}

void
ml_handle_interrupt_handler_duration(thread_t thread)
{
	__ml_handle_interrupts_disabled_duration(thread, os_atomic_load(&interrupt_masked_timeout, relaxed), INT_MASK_FROM_HANDLER);
}

#if SCHED_HYGIENE_DEBUG
void
ml_adjust_preemption_disable_time(thread_t thread, int64_t duration)
{
	/* We don't want to count interrupt handler duration in preemption disable time. */
	if (thread->machine.preemption_disable_mt != 0) {
		/* We don't care *when* preemption was disabled, just for how
		 * long.  So to exclude interrupt handling intervals, we
		 * adjust the start time forward. */
		thread->machine.preemption_disable_adjust += duration;
	}
}
#endif /* SCHED_HYGIENE_DEBUG */

void
ml_irq_debug_start(uintptr_t handler, uintptr_t vector)
{
	INTERRUPT_MASKED_DEBUG_START(handler, DBG_INTR_TYPE_OTHER);
	current_thread()->machine.int_vector = (uintptr_t)VM_KERNEL_STRIP_PTR(vector);
}

void
ml_irq_debug_end()
{
	INTERRUPT_MASKED_DEBUG_END();
}

/*
 * Abandon a potential timeout when handling an interrupt. It is important to
 * continue to keep track of the interrupt time so the time-stamp can't be
 * reset. (Interrupt time is subtracted from preemption time to maintain
 * accurate preemption time measurement).
 * When `inthandler_abandon` is true, a timeout will be ignored when the
 * interrupt handler finishes.
 */
void
ml_irq_debug_abandon(void)
{
	assert(!ml_get_interrupts_enabled());

	thread_t t = current_thread();
	if (t->machine.inthandler_timestamp != 0) {
		t->machine.inthandler_abandon = true;
	}
}
#endif // SCHED_HYGIENE_DEBUG

#if SCHED_HYGIENE_DEBUG
__attribute__((noinline))
static void
ml_interrupt_masked_debug_timestamp(thread_t thread)
{
	thread->machine.intmask_timestamp = ml_get_sched_hygiene_timebase();
	INTERRUPT_MASKED_DEBUG_CAPTURE_PMC(thread);
}
#endif

boolean_t
ml_set_interrupts_enabled_with_debug(boolean_t enable, boolean_t __unused debug)
{
	thread_t        thread;
	uint64_t        state;

	thread = current_thread();

	state = __builtin_arm_rsr("DAIF");

	if (enable && (state & DAIF_IRQF)) {
		assert(getCpuDatap()->cpu_int_state == NULL); // Make sure we're not enabling interrupts from primary interrupt context
#if SCHED_HYGIENE_DEBUG
		if (__probable(debug && (interrupt_masked_debug_mode || sched_preemption_disable_debug_mode))) {
			// Interrupts are currently masked, we will enable them (after finishing this check)
			if (stackshot_active()) {
				ml_handle_stackshot_interrupt_disabled_duration(thread);
			} else {
				ml_handle_interrupts_disabled_duration(thread);
			}
			thread->machine.intmask_timestamp = 0;
			thread->machine.intmask_cycles = 0;
			thread->machine.intmask_instr = 0;
		}
#endif  // SCHED_HYGIENE_DEBUG
		if (get_preemption_level() == 0) {
			while (thread->machine.CpuDatap->cpu_pending_ast & AST_URGENT) {
#if __ARM_USER_PROTECT__
				uintptr_t up = arm_user_protect_begin(thread);
#endif
				ast_taken_kernel();
#if __ARM_USER_PROTECT__
				arm_user_protect_end(thread, up, FALSE);
#endif
			}
		}
		__builtin_arm_wsr("DAIFClr", DAIFSC_STANDARD_DISABLE);
	} else if (!enable && ((state & DAIF_IRQF) == 0)) {
		__builtin_arm_wsr("DAIFSet", DAIFSC_STANDARD_DISABLE);

#if SCHED_HYGIENE_DEBUG
		if (__probable(debug && (interrupt_masked_debug_mode || sched_preemption_disable_debug_mode))) {
			// Interrupts were enabled, we just masked them
			ml_interrupt_masked_debug_timestamp(thread);
		}
#endif
	}
	return (state & DAIF_IRQF) == 0;
}

boolean_t
ml_set_interrupts_enabled(boolean_t enable)
{
	return ml_set_interrupts_enabled_with_debug(enable, true);
}

boolean_t
ml_early_set_interrupts_enabled(boolean_t enable)
{
	return ml_set_interrupts_enabled(enable);
}

/*
 * Interrupt enable function exported for AppleCLPC without
 * measurements enabled.
 *
 * Only for AppleCLPC!
 */
boolean_t
sched_perfcontrol_ml_set_interrupts_without_measurement(boolean_t enable)
{
	return ml_set_interrupts_enabled_with_debug(enable, false);
}

/*
 *	Routine:        ml_at_interrupt_context
 *	Function:	Check if running at interrupt context
 */
boolean_t
ml_at_interrupt_context(void)
{
	/* Do not use a stack-based check here, as the top-level exception handler
	 * is free to use some other stack besides the per-CPU interrupt stack.
	 * Interrupts should always be disabled if we're at interrupt context.
	 * Check that first, as we may be in a preemptible non-interrupt context, in
	 * which case we could be migrated to a different CPU between obtaining
	 * the per-cpu data pointer and loading cpu_int_state.  We then might end
	 * up checking the interrupt state of a different CPU, resulting in a false
	 * positive.  But if interrupts are disabled, we also know we cannot be
	 * preempted. */
	return !ml_get_interrupts_enabled() && (getCpuDatap()->cpu_int_state != NULL);
}

vm_offset_t
ml_stack_remaining(void)
{
	uintptr_t local = (uintptr_t) &local;
	vm_offset_t     intstack_top_ptr;

	/* Since this is a stack-based check, we don't need to worry about
	 * preemption as we do in ml_at_interrupt_context().  If we are preemptible,
	 * then the sp should never be within any CPU's interrupt stack unless
	 * something has gone horribly wrong. */
	intstack_top_ptr = getCpuDatap()->intstack_top;
	if ((local < intstack_top_ptr) && (local > intstack_top_ptr - INTSTACK_SIZE)) {
		return local - (getCpuDatap()->intstack_top - INTSTACK_SIZE);
	} else {
		return local - current_thread()->kernel_stack;
	}
}

static boolean_t ml_quiescing = FALSE;

void
ml_set_is_quiescing(boolean_t quiescing)
{
	ml_quiescing = quiescing;
	os_atomic_thread_fence(release);
}

boolean_t
ml_is_quiescing(void)
{
	os_atomic_thread_fence(acquire);
	return ml_quiescing;
}

uint64_t
ml_get_booter_memory_size(void)
{
	uint64_t size;
	uint64_t roundsize = 512 * 1024 * 1024ULL;
	size = BootArgs->memSizeActual;
	if (!size) {
		size  = BootArgs->memSize;
		if (size < (2 * roundsize)) {
			roundsize >>= 1;
		}
		size  = (size + roundsize - 1) & ~(roundsize - 1);
	}

	size -= BootArgs->memSize;

	return size;
}

uint64_t
ml_get_abstime_offset(void)
{
	return rtclock_base_abstime;
}

uint64_t
ml_get_conttime_offset(void)
{
#if HIBERNATION && HAS_CONTINUOUS_HWCLOCK
	return hwclock_conttime_offset;
#elif HAS_CONTINUOUS_HWCLOCK
	return 0;
#else
	return rtclock_base_abstime + mach_absolutetime_asleep;
#endif
}

uint64_t
ml_get_time_since_reset(void)
{
#if HAS_CONTINUOUS_HWCLOCK
	if (wake_conttime == UINT64_MAX) {
		return UINT64_MAX;
	} else {
		return mach_continuous_time() - wake_conttime;
	}
#else
	/* The timebase resets across S2R, so just return the raw value. */
	return ml_get_hwclock();
#endif
}

void
ml_set_reset_time(__unused uint64_t wake_time)
{
#if HAS_CONTINUOUS_HWCLOCK
	wake_conttime = wake_time;
#endif
}

uint64_t
ml_get_conttime_wake_time(void)
{
#if HAS_CONTINUOUS_HWCLOCK
	/*
	 * For now, we will reconstitute the timebase value from
	 * cpu_timebase_init and use it as the wake time.
	 */
	return wake_abstime - ml_get_abstime_offset();
#else /* HAS_CONTINOUS_HWCLOCK */
	/* The wake time is simply our continuous time offset. */
	return ml_get_conttime_offset();
#endif /* HAS_CONTINOUS_HWCLOCK */
}

/*
 * ml_snoop_thread_is_on_core(thread_t thread)
 * Check if the given thread is currently on core.  This function does not take
 * locks, disable preemption, or otherwise guarantee synchronization.  The
 * result should be considered advisory.
 */
bool
ml_snoop_thread_is_on_core(thread_t thread)
{
	unsigned int cur_cpu_num = 0;
	const unsigned int max_cpu_id = ml_get_max_cpu_number();

	for (cur_cpu_num = 0; cur_cpu_num <= max_cpu_id; cur_cpu_num++) {
		if (CpuDataEntries[cur_cpu_num].cpu_data_vaddr) {
			if (CpuDataEntries[cur_cpu_num].cpu_data_vaddr->cpu_active_thread == thread) {
				return true;
			}
		}
	}

	return false;
}

int
ml_early_cpu_max_number(void)
{
	assert(startup_phase >= STARTUP_SUB_TUNABLES);
	return ml_get_max_cpu_number();
}

void
ml_set_max_cpus(unsigned int max_cpus __unused)
{
	lck_mtx_lock(&max_cpus_lock);
	if (max_cpus_initialized != MAX_CPUS_SET) {
		if (max_cpus_initialized == MAX_CPUS_WAIT) {
			thread_wakeup((event_t) &max_cpus_initialized);
		}
		max_cpus_initialized = MAX_CPUS_SET;
	}
	lck_mtx_unlock(&max_cpus_lock);
}

unsigned int
ml_wait_max_cpus(void)
{
	assert(lockdown_done);
	lck_mtx_lock(&max_cpus_lock);
	while (max_cpus_initialized != MAX_CPUS_SET) {
		max_cpus_initialized = MAX_CPUS_WAIT;
		lck_mtx_sleep(&max_cpus_lock, LCK_SLEEP_DEFAULT, &max_cpus_initialized, THREAD_UNINT);
	}
	lck_mtx_unlock(&max_cpus_lock);
	return machine_info.max_cpus;
}

void
ml_cpu_get_info_type(ml_cpu_info_t * ml_cpu_info, cluster_type_t cluster_type)
{
	cache_info_t   *cpuid_cache_info;

	cpuid_cache_info = cache_info_type(cluster_type);
	ml_cpu_info->vector_unit = 0;
	ml_cpu_info->cache_line_size = cpuid_cache_info->c_linesz;
	ml_cpu_info->l1_icache_size = cpuid_cache_info->c_isize;
	ml_cpu_info->l1_dcache_size = cpuid_cache_info->c_dsize;

#if (__ARM_ARCH__ >= 8)
	ml_cpu_info->l2_settings = 1;
	ml_cpu_info->l2_cache_size = cpuid_cache_info->c_l2size;
#else
#error Unsupported arch
#endif
	ml_cpu_info->l3_settings = 0;
	ml_cpu_info->l3_cache_size = 0xFFFFFFFF;
}

/*
 *	Routine:        ml_cpu_get_info
 *	Function: Fill out the ml_cpu_info_t structure with parameters associated
 *	with the boot cluster.
 */
void
ml_cpu_get_info(ml_cpu_info_t * ml_cpu_info)
{
	ml_cpu_get_info_type(ml_cpu_info, ml_get_topology_info()->boot_cpu->cluster_type);
}

unsigned int
ml_get_cpu_number_type(cluster_type_t cluster_type, bool logical, bool available)
{
	/*
	 * At present no supported ARM system features SMT, so the "logical"
	 * parameter doesn't have an impact on the result.
	 */
	if (logical && available) {
		return os_atomic_load(&cluster_type_num_active_cpus[cluster_type], relaxed);
	} else if (logical && !available) {
		return ml_get_topology_info()->cluster_type_num_cpus[cluster_type];
	} else if (!logical && available) {
		return os_atomic_load(&cluster_type_num_active_cpus[cluster_type], relaxed);
	} else {
		return ml_get_topology_info()->cluster_type_num_cpus[cluster_type];
	}
}

void
ml_get_cluster_type_name(cluster_type_t cluster_type, char *name, size_t name_size)
{
	strlcpy(name, cluster_type_names[cluster_type], name_size);
}

unsigned int
ml_get_cluster_number_type(cluster_type_t cluster_type)
{
	return ml_get_topology_info()->cluster_type_num_clusters[cluster_type];
}

unsigned int
ml_cpu_cache_sharing(unsigned int level, cluster_type_t cluster_type, bool include_all_cpu_types __unused)
{
	unsigned int cpu_number = 0, cluster_types = 0;

	/*
	 * Level 0 corresponds to main memory, which is shared across all cores.
	 */
	if (level == 0) {
		return ml_get_topology_info()->num_cpus;
	}

	/*
	 * At present no supported ARM system features more than 2 levels of caches.
	 */
	if (level > 2) {
		return 0;
	}

	/*
	 * L1 caches are always per core.
	 */
	if (level == 1) {
		return 1;
	}

	cluster_types = (1 << cluster_type);

	/*
	 * Traverse clusters until we find the one(s) of the desired type(s).
	 */
	for (int i = 0; i < ml_get_topology_info()->num_clusters; i++) {
		ml_topology_cluster_t *cluster = &ml_get_topology_info()->clusters[i];
		if ((1 << cluster->cluster_type) & cluster_types) {
			cpu_number += cluster->num_cpus;
			cluster_types &= ~(1 << cluster->cluster_type);
			if (!cluster_types) {
				break;
			}
		}
	}

	return cpu_number;
}

unsigned int
ml_get_cpu_types(void)
{
	return ml_get_topology_info()->cluster_types;
}

void
machine_conf(void)
{
	/*
	 * This is known to be inaccurate. mem_size should always be capped at 2 GB
	 */
	machine_info.memory_size = (uint32_t)mem_size;

	// rdar://problem/58285685: Userland expects _COMM_PAGE_LOGICAL_CPUS to report
	// (max_cpu_id+1) rather than a literal *count* of logical CPUs.
	unsigned int num_cpus = ml_get_topology_info()->max_cpu_id + 1;
	machine_info.max_cpus = num_cpus;
	machine_info.physical_cpu_max = num_cpus;
	machine_info.logical_cpu_max = num_cpus;
}

void
machine_init(void)
{
	debug_log_init();
	clock_config();
	is_clock_configured = TRUE;
	if (debug_enabled) {
		pmap_map_globals();
	}
	ml_lockdown_init();
}
