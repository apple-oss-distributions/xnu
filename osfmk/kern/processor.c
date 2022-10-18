/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

/*
 *	processor.c: processor and processor_set manipulation routines.
 */

#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/processor.h>
#include <mach/processor_info.h>
#include <mach/vm_param.h>
#include <kern/cpu_number.h>
#include <kern/host.h>
#include <kern/ipc_host.h>
#include <kern/ipc_tt.h>
#include <kern/kalloc.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/timer.h>
#if KPERF
#include <kperf/kperf.h>
#endif /* KPERF */
#include <ipc/ipc_port.h>

#include <security/mac_mach_internal.h>

#if defined(CONFIG_XNUPOST)

#include <tests/xnupost.h>

#endif /* CONFIG_XNUPOST */

/*
 * Exported interface
 */
#include <mach/mach_host_server.h>
#include <mach/processor_set_server.h>
#include <san/kcov.h>

/*
 * The first pset and the pset_node are created by default for all platforms.
 * Those typically represent the boot-cluster. For AMP platforms, all clusters
 * of the same type are part of the same pset_node. This allows for easier
 * CPU selection logic.
 */
struct processor_set    pset0;
struct pset_node        pset_node0;

#if __AMP__
struct pset_node        pset_node1;
pset_node_t             ecore_node;
pset_node_t             pcore_node;
#endif

LCK_SPIN_DECLARE(pset_node_lock, LCK_GRP_NULL);

LCK_GRP_DECLARE(pset_lck_grp, "pset");

queue_head_t            tasks;
queue_head_t            terminated_tasks;       /* To be used ONLY for stackshot. */
queue_head_t            corpse_tasks;
int                     tasks_count;
int                     terminated_tasks_count;
queue_head_t            threads;
queue_head_t            terminated_threads;
int                     threads_count;
int                     terminated_threads_count;
LCK_GRP_DECLARE(task_lck_grp, "task");
LCK_ATTR_DECLARE(task_lck_attr, 0, 0);
LCK_MTX_DECLARE_ATTR(tasks_threads_lock, &task_lck_grp, &task_lck_attr);
LCK_MTX_DECLARE_ATTR(tasks_corpse_lock, &task_lck_grp, &task_lck_attr);

processor_t             processor_list;
unsigned int            processor_count;
static processor_t      processor_list_tail;
SIMPLE_LOCK_DECLARE(processor_list_lock, 0);

uint32_t                processor_avail_count;
uint32_t                processor_avail_count_user;
uint32_t                primary_processor_avail_count;
uint32_t                primary_processor_avail_count_user;

SECURITY_READ_ONLY_LATE(int)    master_cpu = 0;

struct processor        PERCPU_DATA(processor);
processor_t             processor_array[MAX_SCHED_CPUS] = { 0 };
processor_set_t         pset_array[MAX_PSETS] = { 0 };

static timer_call_func_t running_timer_funcs[] = {
	[RUNNING_TIMER_QUANTUM] = thread_quantum_expire,
	[RUNNING_TIMER_KPERF] = kperf_timer_expire,
};
static_assert(sizeof(running_timer_funcs) / sizeof(running_timer_funcs[0])
    == RUNNING_TIMER_MAX, "missing running timer function");

#if defined(CONFIG_XNUPOST)
kern_return_t ipi_test(void);
extern void arm64_ipi_test(void);

kern_return_t
ipi_test()
{
#if __arm64__
	processor_t p;

	for (p = processor_list; p != NULL; p = p->processor_list) {
		thread_bind(p);
		thread_block(THREAD_CONTINUE_NULL);
		kprintf("Running IPI test on cpu %d\n", p->cpu_id);
		arm64_ipi_test();
	}

	/* unbind thread from specific cpu */
	thread_bind(PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);

	T_PASS("Done running IPI tests");
#else
	T_PASS("Unsupported platform. Not running IPI tests");

#endif /* __arm64__ */

	return KERN_SUCCESS;
}
#endif /* defined(CONFIG_XNUPOST) */

int sched_enable_smt = 1;

void
processor_bootstrap(void)
{
	/* Initialize PSET node and PSET associated with boot cluster */
	pset_node0.psets = &pset0;
	pset_node0.pset_cluster_type = PSET_SMP;

#if __AMP__
	const ml_topology_info_t *topology_info = ml_get_topology_info();

	/*
	 * Since this is an AMP system, fill up cluster type and ID information; this should do the
	 * same kind of initialization done via ml_processor_register()
	 */
	ml_topology_cluster_t *boot_cluster = topology_info->boot_cluster;
	pset0.pset_id = boot_cluster->cluster_id;
	pset0.pset_cluster_id = boot_cluster->cluster_id;
	if (boot_cluster->cluster_type == CLUSTER_TYPE_E) {
		pset0.pset_cluster_type      = PSET_AMP_E;
		pset_node0.pset_cluster_type = PSET_AMP_E;
		ecore_node = &pset_node0;

		pset_node1.pset_cluster_type = PSET_AMP_P;
		pcore_node = &pset_node1;
	} else {
		pset0.pset_cluster_type      = PSET_AMP_P;
		pset_node0.pset_cluster_type = PSET_AMP_P;
		pcore_node = &pset_node0;

		pset_node1.pset_cluster_type = PSET_AMP_E;
		ecore_node = &pset_node1;
	}

	/* Link pset_node1 to pset_node0 */
	pset_node0.node_list = &pset_node1;
#endif

	pset_init(&pset0, &pset_node0);
	queue_init(&tasks);
	queue_init(&terminated_tasks);
	queue_init(&threads);
	queue_init(&terminated_threads);
	queue_init(&corpse_tasks);

	processor_init(master_processor, master_cpu, &pset0);
}

/*
 *	Initialize the given processor for the cpu
 *	indicated by cpu_id, and assign to the
 *	specified processor set.
 */
void
processor_init(
	processor_t            processor,
	int                    cpu_id,
	processor_set_t        pset)
{
	spl_t           s;

	assert(cpu_id < MAX_SCHED_CPUS);
	processor->cpu_id = cpu_id;

	if (processor != master_processor) {
		/* Scheduler state for master_processor initialized in sched_init() */
		SCHED(processor_init)(processor);
	}

	processor->state = PROCESSOR_OFF_LINE;
	processor->active_thread = processor->startup_thread = processor->idle_thread = THREAD_NULL;
	processor->processor_set = pset;
	processor_state_update_idle(processor);
	processor->starting_pri = MINPRI;
	processor->quantum_end = UINT64_MAX;
	processor->deadline = UINT64_MAX;
	processor->first_timeslice = FALSE;
	processor->processor_offlined = false;
	processor->processor_primary = processor; /* no SMT relationship known at this point */
	processor->processor_secondary = NULL;
	processor->is_SMT = false;
	processor->is_recommended = true;
	processor->processor_self = IP_NULL;
	processor->processor_list = NULL;
	processor->must_idle = false;
	processor->last_startup_reason = REASON_SYSTEM;
	processor->last_shutdown_reason = REASON_NONE;
	processor->shutdown_temporary = false;
	processor->shutdown_locked = false;
	processor->last_recommend_reason = REASON_SYSTEM;
	processor->last_derecommend_reason = REASON_NONE;
	processor->running_timers_active = false;
	for (int i = 0; i < RUNNING_TIMER_MAX; i++) {
		timer_call_setup(&processor->running_timers[i],
		    running_timer_funcs[i], processor);
		running_timer_clear(processor, i);
	}
	recount_processor_init(processor);
	simple_lock_init(&processor->start_state_lock, 0);

	s = splsched();
	pset_lock(pset);
	bit_set(pset->cpu_bitmask, cpu_id);
	bit_set(pset->recommended_bitmask, cpu_id);
	bit_set(pset->primary_map, cpu_id);
	bit_set(pset->cpu_state_map[PROCESSOR_OFF_LINE], cpu_id);
	if (pset->cpu_set_count++ == 0) {
		pset->cpu_set_low = pset->cpu_set_hi = cpu_id;
	} else {
		pset->cpu_set_low = (cpu_id < pset->cpu_set_low)? cpu_id: pset->cpu_set_low;
		pset->cpu_set_hi = (cpu_id > pset->cpu_set_hi)? cpu_id: pset->cpu_set_hi;
	}
	pset_unlock(pset);
	splx(s);

	simple_lock(&processor_list_lock, LCK_GRP_NULL);
	if (processor_list == NULL) {
		processor_list = processor;
	} else {
		processor_list_tail->processor_list = processor;
	}
	processor_list_tail = processor;
	processor_count++;
	simple_unlock(&processor_list_lock);
	processor_array[cpu_id] = processor;
}

bool system_is_SMT = false;

void
processor_set_primary(
	processor_t             processor,
	processor_t             primary)
{
	assert(processor->processor_primary == primary || processor->processor_primary == processor);
	/* Re-adjust primary point for this (possibly) secondary processor */
	processor->processor_primary = primary;

	assert(primary->processor_secondary == NULL || primary->processor_secondary == processor);
	if (primary != processor) {
		/* Link primary to secondary, assumes a 2-way SMT model
		 * We'll need to move to a queue if any future architecture
		 * requires otherwise.
		 */
		assert(processor->processor_secondary == NULL);
		primary->processor_secondary = processor;
		/* Mark both processors as SMT siblings */
		primary->is_SMT = TRUE;
		processor->is_SMT = TRUE;

		if (!system_is_SMT) {
			system_is_SMT = true;
			sched_rt_n_backup_processors = SCHED_DEFAULT_BACKUP_PROCESSORS_SMT;
		}

		processor_set_t pset = processor->processor_set;
		spl_t s = splsched();
		pset_lock(pset);
		if (!pset->is_SMT) {
			pset->is_SMT = true;
		}
		bit_clear(pset->primary_map, processor->cpu_id);
		pset_unlock(pset);
		splx(s);
	}
}

processor_set_t
processor_pset(
	processor_t     processor)
{
	return processor->processor_set;
}

#if CONFIG_SCHED_EDGE

cluster_type_t
pset_type_for_id(uint32_t cluster_id)
{
	return pset_array[cluster_id]->pset_type;
}

/*
 * Processor foreign threads
 *
 * With the Edge scheduler, each pset maintains a bitmap of processors running threads
 * which are foreign to the pset/cluster. A thread is defined as foreign for a cluster
 * if its of a different type than its preferred cluster type (E/P). The bitmap should
 * be updated every time a new thread is assigned to run on a processor. Cluster shared
 * resource intensive threads are also not counted as foreign threads since these
 * threads should not be rebalanced when running on non-preferred clusters.
 *
 * This bitmap allows the Edge scheduler to quickly find CPUs running foreign threads
 * for rebalancing.
 */
static void
processor_state_update_running_foreign(processor_t processor, thread_t thread)
{
	cluster_type_t current_processor_type = pset_type_for_id(processor->processor_set->pset_cluster_id);
	cluster_type_t thread_type = pset_type_for_id(sched_edge_thread_preferred_cluster(thread));

	boolean_t non_rt_thr = (processor->current_pri < BASEPRI_RTQUEUES);
	boolean_t non_bound_thr = (thread->bound_processor == PROCESSOR_NULL);
	if (non_rt_thr && non_bound_thr && (current_processor_type != thread_type)) {
		bit_set(processor->processor_set->cpu_running_foreign, processor->cpu_id);
	} else {
		bit_clear(processor->processor_set->cpu_running_foreign, processor->cpu_id);
	}
}

/*
 * Cluster shared resource intensive threads
 *
 * With the Edge scheduler, each pset maintains a bitmap of processors running
 * threads that are shared resource intensive. This per-thread property is set
 * by the performance controller or explicitly via dispatch SPIs. The bitmap
 * allows the Edge scheduler to calculate the cluster shared resource load on
 * any given cluster and load balance intensive threads accordingly.
 */
static void
processor_state_update_running_cluster_shared_rsrc(processor_t processor, thread_t thread)
{
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_RR)) {
		bit_set(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_RR], processor->cpu_id);
	} else {
		bit_clear(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_RR], processor->cpu_id);
	}
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST)) {
		bit_set(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST], processor->cpu_id);
	} else {
		bit_clear(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST], processor->cpu_id);
	}
}

#endif /* CONFIG_SCHED_EDGE */

void
processor_state_update_idle(processor_t processor)
{
	processor->current_pri = IDLEPRI;
	processor->current_sfi_class = SFI_CLASS_KERNEL;
	processor->current_recommended_pset_type = PSET_SMP;
#if CONFIG_THREAD_GROUPS
	processor->current_thread_group = NULL;
#endif
	processor->current_perfctl_class = PERFCONTROL_CLASS_IDLE;
	processor->current_urgency = THREAD_URGENCY_NONE;
	processor->current_is_NO_SMT = false;
	processor->current_is_bound = false;
	processor->current_is_eagerpreempt = false;
#if CONFIG_SCHED_EDGE
	os_atomic_store(&processor->processor_set->cpu_running_buckets[processor->cpu_id], TH_BUCKET_SCHED_MAX, relaxed);
	bit_clear(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_RR], processor->cpu_id);
	bit_clear(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST], processor->cpu_id);
#endif /* CONFIG_SCHED_EDGE */
	sched_update_pset_load_average(processor->processor_set, 0);
}

void
processor_state_update_from_thread(processor_t processor, thread_t thread, boolean_t pset_lock_held)
{
	processor->current_pri = thread->sched_pri;
	processor->current_sfi_class = thread->sfi_class;
	processor->current_recommended_pset_type = recommended_pset_type(thread);
#if CONFIG_SCHED_EDGE
	processor_state_update_running_foreign(processor, thread);
	processor_state_update_running_cluster_shared_rsrc(processor, thread);
	/* Since idle and bound threads are not tracked by the edge scheduler, ignore when those threads go on-core */
	sched_bucket_t bucket = ((thread->state & TH_IDLE) || (thread->bound_processor != PROCESSOR_NULL)) ? TH_BUCKET_SCHED_MAX : thread->th_sched_bucket;
	os_atomic_store(&processor->processor_set->cpu_running_buckets[processor->cpu_id], bucket, relaxed);
#endif /* CONFIG_SCHED_EDGE */

#if CONFIG_THREAD_GROUPS
	processor->current_thread_group = thread_group_get(thread);
#endif
	processor->current_perfctl_class = thread_get_perfcontrol_class(thread);
	processor->current_urgency = thread_get_urgency(thread, NULL, NULL);
	processor->current_is_NO_SMT = thread_no_smt(thread);
	processor->current_is_bound = thread->bound_processor != PROCESSOR_NULL;
	processor->current_is_eagerpreempt = thread_is_eager_preempt(thread);
	if (pset_lock_held) {
		/* Only update the pset load average when the pset lock is held */
		sched_update_pset_load_average(processor->processor_set, 0);
	}
}

void
processor_state_update_explicit(processor_t processor, int pri, sfi_class_id_t sfi_class,
    pset_cluster_type_t pset_type, perfcontrol_class_t perfctl_class, thread_urgency_t urgency, __unused sched_bucket_t bucket)
{
	processor->current_pri = pri;
	processor->current_sfi_class = sfi_class;
	processor->current_recommended_pset_type = pset_type;
	processor->current_perfctl_class = perfctl_class;
	processor->current_urgency = urgency;
#if CONFIG_SCHED_EDGE
	os_atomic_store(&processor->processor_set->cpu_running_buckets[processor->cpu_id], bucket, relaxed);
	bit_clear(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_RR], processor->cpu_id);
	bit_clear(processor->processor_set->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST], processor->cpu_id);
#endif /* CONFIG_SCHED_EDGE */
}

pset_node_t
pset_node_root(void)
{
	return &pset_node0;
}

LCK_GRP_DECLARE(pset_create_grp, "pset_create");
LCK_MTX_DECLARE(pset_create_lock, &pset_create_grp);

processor_set_t
pset_create(
	pset_node_t node,
	pset_cluster_type_t pset_type,
	uint32_t pset_cluster_id,
	int      pset_id)
{
	/* some schedulers do not support multiple psets */
	if (SCHED(multiple_psets_enabled) == FALSE) {
		return processor_pset(master_processor);
	}

	processor_set_t *prev, pset = zalloc_permanent_type(struct processor_set);

	if (pset != PROCESSOR_SET_NULL) {
		pset->pset_cluster_type = pset_type;
		pset->pset_cluster_id = pset_cluster_id;
		pset->pset_id = pset_id;
		pset_init(pset, node);

		lck_spin_lock(&pset_node_lock);

		prev = &node->psets;
		while (*prev != PROCESSOR_SET_NULL) {
			prev = &(*prev)->pset_list;
		}

		*prev = pset;

		lck_spin_unlock(&pset_node_lock);
	}

	return pset;
}

/*
 *	Find processor set with specified cluster_id.
 *	Returns default_pset if not found.
 */
processor_set_t
pset_find(
	uint32_t cluster_id,
	processor_set_t default_pset)
{
	lck_spin_lock(&pset_node_lock);
	pset_node_t node = &pset_node0;
	processor_set_t pset = NULL;

	do {
		pset = node->psets;
		while (pset != NULL) {
			if (pset->pset_cluster_id == cluster_id) {
				break;
			}
			pset = pset->pset_list;
		}
	} while (pset == NULL && (node = node->node_list) != NULL);
	lck_spin_unlock(&pset_node_lock);
	if (pset == NULL) {
		return default_pset;
	}
	return pset;
}

/*
 *	Initialize the given processor_set structure.
 */
void
pset_init(
	processor_set_t         pset,
	pset_node_t                     node)
{
	pset->online_processor_count = 0;
	pset->load_average = 0;
	bzero(&pset->pset_load_average, sizeof(pset->pset_load_average));
	pset->cpu_set_low = pset->cpu_set_hi = 0;
	pset->cpu_set_count = 0;
	pset->last_chosen = -1;
	pset->cpu_bitmask = 0;
	pset->recommended_bitmask = 0;
	pset->primary_map = 0;
	pset->realtime_map = 0;
	pset->cpu_available_map = 0;

	for (uint i = 0; i < PROCESSOR_STATE_LEN; i++) {
		pset->cpu_state_map[i] = 0;
	}
	pset->pending_AST_URGENT_cpu_mask = 0;
	pset->pending_AST_PREEMPT_cpu_mask = 0;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	pset->pending_deferred_AST_cpu_mask = 0;
#endif
	pset->pending_spill_cpu_mask = 0;
	pset->rt_pending_spill_cpu_mask = 0;
	pset_lock_init(pset);
	pset->pset_self = IP_NULL;
	pset->pset_name_self = IP_NULL;
	pset->pset_list = PROCESSOR_SET_NULL;
	pset->is_SMT = false;
#if CONFIG_SCHED_EDGE
	bzero(&pset->pset_execution_time, sizeof(pset->pset_execution_time));
	pset->cpu_running_foreign = 0;
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		pset->cpu_running_cluster_shared_rsrc_thread[shared_rsrc_type] = 0;
		pset->pset_cluster_shared_rsrc_load[shared_rsrc_type] = 0;
	}
#endif /* CONFIG_SCHED_EDGE */
	pset->stealable_rt_threads_earliest_deadline = UINT64_MAX;

	if (pset != &pset0) {
		/*
		 * Scheduler runqueue initialization for non-boot psets.
		 * This initialization for pset0 happens in sched_init().
		 */
		SCHED(pset_init)(pset);
		SCHED(rt_init)(pset);
	}
	pset_array[pset->pset_id] = pset;
	lck_spin_lock(&pset_node_lock);
	bit_set(node->pset_map, pset->pset_id);
	pset->node = node;
	lck_spin_unlock(&pset_node_lock);
}

kern_return_t
processor_info_count(
	processor_flavor_t              flavor,
	mach_msg_type_number_t  *count)
{
	switch (flavor) {
	case PROCESSOR_BASIC_INFO:
		*count = PROCESSOR_BASIC_INFO_COUNT;
		break;

	case PROCESSOR_CPU_LOAD_INFO:
		*count = PROCESSOR_CPU_LOAD_INFO_COUNT;
		break;

	default:
		return cpu_info_count(flavor, count);
	}

	return KERN_SUCCESS;
}

void
processor_cpu_load_info(processor_t processor,
    natural_t ticks[static CPU_STATE_MAX])
{
	struct recount_usage usage = { 0 };
	uint64_t idle_time = 0;
	recount_processor_usage(&processor->pr_recount, &usage, &idle_time);

	ticks[CPU_STATE_USER] += (uint32_t)(usage.ru_user_time_mach /
	    hz_tick_interval);
	ticks[CPU_STATE_SYSTEM] += (uint32_t)(usage.ru_system_time_mach /
	    hz_tick_interval);
	ticks[CPU_STATE_IDLE] += (uint32_t)(idle_time / hz_tick_interval);
}

kern_return_t
processor_info(
	processor_t     processor,
	processor_flavor_t              flavor,
	host_t                                  *host,
	processor_info_t                info,
	mach_msg_type_number_t  *count)
{
	int     cpu_id, state;
	kern_return_t   result;

	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	cpu_id = processor->cpu_id;

	switch (flavor) {
	case PROCESSOR_BASIC_INFO:
	{
		processor_basic_info_t          basic_info;

		if (*count < PROCESSOR_BASIC_INFO_COUNT) {
			return KERN_FAILURE;
		}

		basic_info = (processor_basic_info_t) info;
		basic_info->cpu_type = slot_type(cpu_id);
		basic_info->cpu_subtype = slot_subtype(cpu_id);
		state = processor->state;
		if (((state == PROCESSOR_OFF_LINE || state == PROCESSOR_PENDING_OFFLINE) && !processor->shutdown_temporary)
#if defined(__x86_64__)
		    || !processor->is_recommended
#endif
		    ) {
			basic_info->running = FALSE;
		} else {
			basic_info->running = TRUE;
		}
		basic_info->slot_num = cpu_id;
		if (processor == master_processor) {
			basic_info->is_master = TRUE;
		} else {
			basic_info->is_master = FALSE;
		}

		*count = PROCESSOR_BASIC_INFO_COUNT;
		*host = &realhost;

		return KERN_SUCCESS;
	}

	case PROCESSOR_CPU_LOAD_INFO:
	{
		processor_cpu_load_info_t       cpu_load_info;

		if (*count < PROCESSOR_CPU_LOAD_INFO_COUNT) {
			return KERN_FAILURE;
		}

		cpu_load_info = (processor_cpu_load_info_t) info;

		cpu_load_info->cpu_ticks[CPU_STATE_SYSTEM] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_USER] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_IDLE] = 0;
		processor_cpu_load_info(processor, cpu_load_info->cpu_ticks);
		cpu_load_info->cpu_ticks[CPU_STATE_NICE] = 0;

		*count = PROCESSOR_CPU_LOAD_INFO_COUNT;
		*host = &realhost;

		return KERN_SUCCESS;
	}

	default:
		result = cpu_info(flavor, cpu_id, info, count);
		if (result == KERN_SUCCESS) {
			*host = &realhost;
		}

		return result;
	}
}

void
processor_wait_for_start(processor_t processor)
{
	spl_t s = splsched();
	simple_lock(&processor->start_state_lock, LCK_GRP_NULL);
	while (processor->state == PROCESSOR_START) {
		assert_wait_timeout((event_t)&processor->state, THREAD_UNINT, 1000, 1000 * NSEC_PER_USEC); /* 1 second */
		simple_unlock(&processor->start_state_lock);
		splx(s);

		wait_result_t wait_result = thread_block(THREAD_CONTINUE_NULL);
		if (wait_result == THREAD_TIMED_OUT) {
			panic("%s>cpu %d failed to start\n", __FUNCTION__, processor->cpu_id);
		}

		s = splsched();
		simple_lock(&processor->start_state_lock, LCK_GRP_NULL);
	}
	simple_unlock(&processor->start_state_lock);
	splx(s);
}

LCK_GRP_DECLARE(processor_updown_grp, "processor_updown");
LCK_MTX_DECLARE(processor_updown_lock, &processor_updown_grp);

static kern_return_t
processor_startup(
	processor_t                     processor,
	processor_reason_t              reason,
	uint32_t                        flags)
{
	processor_set_t         pset;
	thread_t                        thread;
	kern_return_t           result;
	spl_t                           s;

	if (processor == PROCESSOR_NULL || processor->processor_set == PROCESSOR_SET_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((flags & (LOCK_STATE | UNLOCK_STATE)) && (reason != REASON_SYSTEM)) {
		return KERN_INVALID_ARGUMENT;
	}

	lck_mtx_lock(&processor_updown_lock);

	if (processor == master_processor) {
		processor_t             prev;

		processor->last_startup_reason = reason;

		ml_cpu_power_enable(processor->cpu_id);

		prev = thread_bind(processor);
		thread_block(THREAD_CONTINUE_NULL);

		result = cpu_start(processor->cpu_id);

		thread_bind(prev);

		lck_mtx_unlock(&processor_updown_lock);
		return result;
	}

	bool scheduler_disable = false;

	if ((processor->processor_primary != processor) && (sched_enable_smt == 0)) {
		if (cpu_can_exit(processor->cpu_id)) {
			lck_mtx_unlock(&processor_updown_lock);
			return KERN_SUCCESS;
		}
		/*
		 * This secondary SMT processor must start in order to service interrupts,
		 * so instead it will be disabled at the scheduler level.
		 */
		scheduler_disable = true;
	}

	s = splsched();
	pset = processor->processor_set;
	pset_lock(pset);
	if (flags & LOCK_STATE) {
		processor->shutdown_locked = true;
	} else if (flags & UNLOCK_STATE) {
		processor->shutdown_locked = false;
	}

	if (processor->state == PROCESSOR_START) {
		pset_unlock(pset);
		splx(s);

		processor_wait_for_start(processor);

		lck_mtx_unlock(&processor_updown_lock);
		return KERN_SUCCESS;
	}

	if ((processor->state != PROCESSOR_OFF_LINE) || ((flags & SHUTDOWN_TEMPORARY) && !processor->shutdown_temporary)) {
		pset_unlock(pset);
		splx(s);

		lck_mtx_unlock(&processor_updown_lock);
		return KERN_FAILURE;
	}

	pset_update_processor_state(pset, processor, PROCESSOR_START);
	processor->last_startup_reason = reason;
	pset_unlock(pset);
	splx(s);

	/*
	 *	Create the idle processor thread.
	 */
	if (processor->idle_thread == THREAD_NULL) {
		result = idle_thread_create(processor);
		if (result != KERN_SUCCESS) {
			s = splsched();
			pset_lock(pset);
			pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
			pset_unlock(pset);
			splx(s);

			lck_mtx_unlock(&processor_updown_lock);
			return result;
		}
	}

	/*
	 *	If there is no active thread, the processor
	 *	has never been started.  Create a dedicated
	 *	start up thread.
	 */
	if (processor->active_thread == THREAD_NULL &&
	    processor->startup_thread == THREAD_NULL) {
		result = kernel_thread_create(processor_start_thread, NULL, MAXPRI_KERNEL, &thread);
		if (result != KERN_SUCCESS) {
			s = splsched();
			pset_lock(pset);
			pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
			pset_unlock(pset);
			splx(s);

			lck_mtx_unlock(&processor_updown_lock);
			return result;
		}

		s = splsched();
		thread_lock(thread);
		thread->bound_processor = processor;
		processor->startup_thread = thread;
		thread->state = TH_RUN;
		thread->last_made_runnable_time = thread->last_basepri_change_time = mach_absolute_time();
		thread_unlock(thread);
		splx(s);

		thread_deallocate(thread);
	}

	if (processor->processor_self == IP_NULL) {
		ipc_processor_init(processor);
	}

	ml_cpu_power_enable(processor->cpu_id);
	ml_cpu_begin_state_transition(processor->cpu_id);
	ml_broadcast_cpu_event(CPU_BOOT_REQUESTED, processor->cpu_id);
	result = cpu_start(processor->cpu_id);
#if defined (__arm__) || defined (__arm64__)
	assert(result == KERN_SUCCESS);
#else
	if (result != KERN_SUCCESS) {
		s = splsched();
		pset_lock(pset);
		pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
		pset_unlock(pset);
		splx(s);
		ml_cpu_end_state_transition(processor->cpu_id);

		lck_mtx_unlock(&processor_updown_lock);
		return result;
	}
#endif
	if (scheduler_disable) {
		assert(processor->processor_primary != processor);
		sched_processor_enable(processor, FALSE);
	}

	if (flags & WAIT_FOR_START) {
		processor_wait_for_start(processor);
	}

	ml_cpu_end_state_transition(processor->cpu_id);
	ml_broadcast_cpu_event(CPU_ACTIVE, processor->cpu_id);

#if CONFIG_KCOV
	kcov_start_cpu(processor->cpu_id);
#endif

	lck_mtx_unlock(&processor_updown_lock);
	return KERN_SUCCESS;
}

kern_return_t
processor_exit_reason(processor_t processor, processor_reason_t reason, uint32_t flags)
{
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (sched_is_in_sleep() && (reason != REASON_SYSTEM)) {
#ifdef RHODES_CLUSTER_POWERDOWN_WORKAROUND
		/*
		 * Must allow CLPC to finish powering down the whole cluster,
		 * or IOCPUSleepKernel() will fail to restart the offline cpus.
		 */
		if (reason != REASON_CLPC_SYSTEM) {
			return KERN_FAILURE;
		}
#else
		return KERN_FAILURE;
#endif
	}

	if ((reason == REASON_USER) && !cpu_can_exit(processor->cpu_id)) {
		return sched_processor_enable(processor, FALSE);
	} else if ((reason == REASON_SYSTEM) || cpu_can_exit(processor->cpu_id)) {
		return processor_shutdown(processor, reason, flags);
	}

	return KERN_INVALID_ARGUMENT;
}

kern_return_t
processor_exit(
	processor_t     processor)
{
	return processor_exit_reason(processor, REASON_SYSTEM, 0);
}

kern_return_t
processor_exit_from_user(
	processor_t     processor)
{
	return processor_exit_reason(processor, REASON_USER, 0);
}

kern_return_t
processor_start_reason(processor_t processor, processor_reason_t reason, uint32_t flags)
{
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (sched_is_in_sleep() && (reason != REASON_SYSTEM)) {
		return KERN_FAILURE;
	}

	if ((reason == REASON_USER) && !cpu_can_exit(processor->cpu_id)) {
		return sched_processor_enable(processor, TRUE);
	} else {
		return processor_startup(processor, reason, flags);
	}
}

kern_return_t
processor_start(
	processor_t                     processor)
{
	return processor_start_reason(processor, REASON_SYSTEM, 0);
}

kern_return_t
processor_start_from_user(
	processor_t                     processor)
{
	return processor_start_reason(processor, REASON_USER, 0);
}

kern_return_t
enable_smt_processors(bool enable)
{
	if (machine_info.logical_cpu_max == machine_info.physical_cpu_max) {
		/* Not an SMT system */
		return KERN_INVALID_ARGUMENT;
	}

	int ncpus = machine_info.logical_cpu_max;

	for (int i = 1; i < ncpus; i++) {
		processor_t processor = processor_array[i];

		if (processor->processor_primary != processor) {
			if (enable) {
				processor_start_from_user(processor);
			} else { /* Disable */
				processor_exit_from_user(processor);
			}
		}
	}

#define BSD_HOST 1
	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	kern_return_t kret = host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);
	if (kret != KERN_SUCCESS) {
		return kret;
	}

	if (enable && (hinfo.logical_cpu != hinfo.logical_cpu_max)) {
		return KERN_FAILURE;
	}

	if (!enable && (hinfo.logical_cpu != hinfo.physical_cpu)) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

bool
processor_should_kprintf(processor_t processor, bool starting)
{
	processor_reason_t reason = starting ? processor->last_startup_reason : processor->last_shutdown_reason;

	return reason != REASON_CLPC_SYSTEM;
}

kern_return_t
processor_control(
	processor_t             processor,
	processor_info_t        info,
	mach_msg_type_number_t  count)
{
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return cpu_control(processor->cpu_id, info, count);
}

kern_return_t
processor_get_assignment(
	processor_t     processor,
	processor_set_t *pset)
{
	int state;

	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	state = processor->state;
	if (state == PROCESSOR_SHUTDOWN || state == PROCESSOR_OFF_LINE || state == PROCESSOR_PENDING_OFFLINE) {
		return KERN_FAILURE;
	}

	*pset = &pset0;

	return KERN_SUCCESS;
}

kern_return_t
processor_set_info(
	processor_set_t         pset,
	int                     flavor,
	host_t                  *host,
	processor_set_info_t    info,
	mach_msg_type_number_t  *count)
{
	if (pset == PROCESSOR_SET_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (flavor == PROCESSOR_SET_BASIC_INFO) {
		processor_set_basic_info_t      basic_info;

		if (*count < PROCESSOR_SET_BASIC_INFO_COUNT) {
			return KERN_FAILURE;
		}

		basic_info = (processor_set_basic_info_t) info;
#if defined(__x86_64__)
		basic_info->processor_count = processor_avail_count_user;
#else
		basic_info->processor_count = processor_avail_count;
#endif
		basic_info->default_policy = POLICY_TIMESHARE;

		*count = PROCESSOR_SET_BASIC_INFO_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_TIMESHARE_DEFAULT) {
		policy_timeshare_base_t ts_base;

		if (*count < POLICY_TIMESHARE_BASE_COUNT) {
			return KERN_FAILURE;
		}

		ts_base = (policy_timeshare_base_t) info;
		ts_base->base_priority = BASEPRI_DEFAULT;

		*count = POLICY_TIMESHARE_BASE_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_FIFO_DEFAULT) {
		policy_fifo_base_t              fifo_base;

		if (*count < POLICY_FIFO_BASE_COUNT) {
			return KERN_FAILURE;
		}

		fifo_base = (policy_fifo_base_t) info;
		fifo_base->base_priority = BASEPRI_DEFAULT;

		*count = POLICY_FIFO_BASE_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_RR_DEFAULT) {
		policy_rr_base_t                rr_base;

		if (*count < POLICY_RR_BASE_COUNT) {
			return KERN_FAILURE;
		}

		rr_base = (policy_rr_base_t) info;
		rr_base->base_priority = BASEPRI_DEFAULT;
		rr_base->quantum = 1;

		*count = POLICY_RR_BASE_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_TIMESHARE_LIMITS) {
		policy_timeshare_limit_t        ts_limit;

		if (*count < POLICY_TIMESHARE_LIMIT_COUNT) {
			return KERN_FAILURE;
		}

		ts_limit = (policy_timeshare_limit_t) info;
		ts_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_TIMESHARE_LIMIT_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_FIFO_LIMITS) {
		policy_fifo_limit_t             fifo_limit;

		if (*count < POLICY_FIFO_LIMIT_COUNT) {
			return KERN_FAILURE;
		}

		fifo_limit = (policy_fifo_limit_t) info;
		fifo_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_FIFO_LIMIT_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_RR_LIMITS) {
		policy_rr_limit_t               rr_limit;

		if (*count < POLICY_RR_LIMIT_COUNT) {
			return KERN_FAILURE;
		}

		rr_limit = (policy_rr_limit_t) info;
		rr_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_RR_LIMIT_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_ENABLED_POLICIES) {
		int                             *enabled;

		if (*count < (sizeof(*enabled) / sizeof(int))) {
			return KERN_FAILURE;
		}

		enabled = (int *) info;
		*enabled = POLICY_TIMESHARE | POLICY_RR | POLICY_FIFO;

		*count = sizeof(*enabled) / sizeof(int);
		*host = &realhost;
		return KERN_SUCCESS;
	}


	*host = HOST_NULL;
	return KERN_INVALID_ARGUMENT;
}

/*
 *	processor_set_statistics
 *
 *	Returns scheduling statistics for a processor set.
 */
kern_return_t
processor_set_statistics(
	processor_set_t         pset,
	int                     flavor,
	processor_set_info_t    info,
	mach_msg_type_number_t  *count)
{
	if (pset == PROCESSOR_SET_NULL || pset != &pset0) {
		return KERN_INVALID_PROCESSOR_SET;
	}

	if (flavor == PROCESSOR_SET_LOAD_INFO) {
		processor_set_load_info_t     load_info;

		if (*count < PROCESSOR_SET_LOAD_INFO_COUNT) {
			return KERN_FAILURE;
		}

		load_info = (processor_set_load_info_t) info;

		load_info->mach_factor = sched_mach_factor;
		load_info->load_average = sched_load_average;

		load_info->task_count = tasks_count;
		load_info->thread_count = threads_count;

		*count = PROCESSOR_SET_LOAD_INFO_COUNT;
		return KERN_SUCCESS;
	}

	return KERN_INVALID_ARGUMENT;
}

/*
 *	processor_set_things:
 *
 *	Common internals for processor_set_{threads,tasks}
 */
static kern_return_t
processor_set_things(
	processor_set_t pset,
	void **thing_list,
	mach_msg_type_number_t *countp,
	int type,
	mach_task_flavor_t flavor)
{
	unsigned int i;
	task_t task;
	thread_t thread;

	task_t *task_list;
	vm_size_t actual_tasks, task_count_cur, task_count_needed;

	thread_t *thread_list;
	vm_size_t actual_threads, thread_count_cur, thread_count_needed;

	void *addr, *newaddr;
	vm_size_t count, count_needed;

	if (pset == PROCESSOR_SET_NULL || pset != &pset0) {
		return KERN_INVALID_ARGUMENT;
	}

	task_count_cur = 0;
	task_count_needed = 0;
	task_list = NULL;
	actual_tasks = 0;

	thread_count_cur = 0;
	thread_count_needed = 0;
	thread_list = NULL;
	actual_threads = 0;

	for (;;) {
		lck_mtx_lock(&tasks_threads_lock);

		/* do we have the memory we need? */
		if (type == PSET_THING_THREAD) {
			thread_count_needed = threads_count;
		}
#if !CONFIG_MACF
		else
#endif
		task_count_needed = tasks_count;

		if (task_count_needed <= task_count_cur &&
		    thread_count_needed <= thread_count_cur) {
			break;
		}

		/* unlock and allocate more memory */
		lck_mtx_unlock(&tasks_threads_lock);

		/* grow task array */
		if (task_count_needed > task_count_cur) {
			kfree_type(task_t, task_count_cur, task_list);
			assert(task_count_needed > 0);
			task_count_cur = task_count_needed;

			task_list = kalloc_type(task_t, task_count_cur, Z_WAITOK | Z_ZERO);
			if (task_list == NULL) {
				kfree_type(thread_t, thread_count_cur, thread_list);
				return KERN_RESOURCE_SHORTAGE;
			}
		}

		/* grow thread array */
		if (thread_count_needed > thread_count_cur) {
			kfree_type(thread_t, thread_count_cur, thread_list);

			assert(thread_count_needed > 0);
			thread_count_cur = thread_count_needed;

			thread_list = kalloc_type(thread_t, thread_count_cur, Z_WAITOK | Z_ZERO);
			if (thread_list == NULL) {
				kfree_type(task_t, task_count_cur, task_list);
				return KERN_RESOURCE_SHORTAGE;
			}
		}
	}

	/* OK, have memory and the list locked */

	/* If we need it, get the thread list */
	if (type == PSET_THING_THREAD) {
		queue_iterate(&threads, thread, thread_t, threads) {
			task = get_threadtask(thread);
#if defined(SECURE_KERNEL)
			if (task == kernel_task) {
				/* skip threads belonging to kernel_task */
				continue;
			}
#endif
			if (!task->ipc_active || task_is_exec_copy(task)) {
				/* skip threads in inactive tasks (in the middle of exec/fork/spawn) */
				continue;
			}

			thread_reference(thread);
			thread_list[actual_threads++] = thread;
		}
	}
#if !CONFIG_MACF
	else
#endif
	{
		/* get a list of the tasks */
		queue_iterate(&tasks, task, task_t, tasks) {
#if defined(SECURE_KERNEL)
			if (task == kernel_task) {
				/* skip kernel_task */
				continue;
			}
#endif
			if (!task->ipc_active || task_is_exec_copy(task)) {
				/* skip inactive tasks (in the middle of exec/fork/spawn) */
				continue;
			}

			task_reference(task);
			task_list[actual_tasks++] = task;
		}
	}

	lck_mtx_unlock(&tasks_threads_lock);

#if CONFIG_MACF
	unsigned int j, used;

	/* for each task, make sure we are allowed to examine it */
	for (i = used = 0; i < actual_tasks; i++) {
		if (mac_task_check_expose_task(task_list[i], flavor)) {
			task_deallocate(task_list[i]);
			continue;
		}
		task_list[used++] = task_list[i];
	}
	actual_tasks = used;
	task_count_needed = actual_tasks;

	if (type == PSET_THING_THREAD) {
		/* for each thread (if any), make sure it's task is in the allowed list */
		for (i = used = 0; i < actual_threads; i++) {
			boolean_t found_task = FALSE;

			task = get_threadtask(thread_list[i]);
			for (j = 0; j < actual_tasks; j++) {
				if (task_list[j] == task) {
					found_task = TRUE;
					break;
				}
			}
			if (found_task) {
				thread_list[used++] = thread_list[i];
			} else {
				thread_deallocate(thread_list[i]);
			}
		}
		actual_threads = used;
		thread_count_needed = actual_threads;

		/* done with the task list */
		for (i = 0; i < actual_tasks; i++) {
			task_deallocate(task_list[i]);
		}
		kfree_type(task_t, task_count_cur, task_list);
		task_count_cur = 0;
		actual_tasks = 0;
		task_list = NULL;
	}
#endif

	if (type == PSET_THING_THREAD) {
		if (actual_threads == 0) {
			/* no threads available to return */
			assert(task_count_cur == 0);
			kfree_type(thread_t, thread_count_cur, thread_list);
			*thing_list = NULL;
			*countp = 0;
			return KERN_SUCCESS;
		}
		count_needed = actual_threads;
		count = thread_count_cur;
		addr = thread_list;
	} else {
		if (actual_tasks == 0) {
			/* no tasks available to return */
			assert(thread_count_cur == 0);
			kfree_type(task_t, task_count_cur, task_list);
			*thing_list = NULL;
			*countp = 0;
			return KERN_SUCCESS;
		}
		count_needed = actual_tasks;
		count = task_count_cur;
		addr = task_list;
	}

	/* if we allocated too much, must copy */
	if (count_needed < count) {
		newaddr = kalloc_type(void *, count_needed, Z_WAITOK | Z_ZERO);
		if (newaddr == 0) {
			for (i = 0; i < actual_tasks; i++) {
				if (type == PSET_THING_THREAD) {
					thread_deallocate(thread_list[i]);
				} else {
					task_deallocate(task_list[i]);
				}
			}
			kfree_type(void *, count, addr);
			return KERN_RESOURCE_SHORTAGE;
		}

		bcopy(addr, newaddr, count_needed * sizeof(void *));
		kfree_type(void *, count, addr);

		addr = newaddr;
		count = count_needed;
	}

	*thing_list = (void **)addr;
	*countp = (mach_msg_type_number_t)count;

	return KERN_SUCCESS;
}

/*
 *	processor_set_tasks:
 *
 *	List all tasks in the processor set.
 */
static kern_return_t
processor_set_tasks_internal(
	processor_set_t         pset,
	task_array_t            *task_list,
	mach_msg_type_number_t  *count,
	mach_task_flavor_t      flavor)
{
	kern_return_t ret;
	mach_msg_type_number_t i;

	ret = processor_set_things(pset, (void **)task_list, count, PSET_THING_TASK, flavor);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/* do the conversion that Mig should handle */
	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
		for (i = 0; i < *count; i++) {
			if ((*task_list)[i] == current_task()) {
				/* if current_task(), return pinned port */
				(*task_list)[i] = (task_t)convert_task_to_port_pinned((*task_list)[i]);
			} else {
				(*task_list)[i] = (task_t)convert_task_to_port((*task_list)[i]);
			}
		}
		break;
	case TASK_FLAVOR_READ:
		for (i = 0; i < *count; i++) {
			(*task_list)[i] = (task_t)convert_task_read_to_port((*task_list)[i]);
		}
		break;
	case TASK_FLAVOR_INSPECT:
		for (i = 0; i < *count; i++) {
			(*task_list)[i] = (task_t)convert_task_inspect_to_port((*task_list)[i]);
		}
		break;
	case TASK_FLAVOR_NAME:
		for (i = 0; i < *count; i++) {
			(*task_list)[i] = (task_t)convert_task_name_to_port((*task_list)[i]);
		}
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

kern_return_t
processor_set_tasks(
	processor_set_t         pset,
	task_array_t            *task_list,
	mach_msg_type_number_t  *count)
{
	return processor_set_tasks_internal(pset, task_list, count, TASK_FLAVOR_CONTROL);
}

/*
 *	processor_set_tasks_with_flavor:
 *
 *	Based on flavor, return task/inspect/read port to all tasks in the processor set.
 */
kern_return_t
processor_set_tasks_with_flavor(
	processor_set_t         pset,
	mach_task_flavor_t      flavor,
	task_array_t            *task_list,
	mach_msg_type_number_t  *count)
{
	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
	case TASK_FLAVOR_READ:
	case TASK_FLAVOR_INSPECT:
	case TASK_FLAVOR_NAME:
		return processor_set_tasks_internal(pset, task_list, count, flavor);
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

/*
 *	processor_set_threads:
 *
 *	List all threads in the processor set.
 */
#if defined(SECURE_KERNEL)
kern_return_t
processor_set_threads(
	__unused processor_set_t                pset,
	__unused thread_array_t         *thread_list,
	__unused mach_msg_type_number_t *count)
{
	return KERN_FAILURE;
}
#elif !defined(XNU_TARGET_OS_OSX)
kern_return_t
processor_set_threads(
	__unused processor_set_t                pset,
	__unused thread_array_t         *thread_list,
	__unused mach_msg_type_number_t *count)
{
	return KERN_NOT_SUPPORTED;
}
#else
kern_return_t
processor_set_threads(
	processor_set_t         pset,
	thread_array_t          *thread_list,
	mach_msg_type_number_t  *count)
{
	kern_return_t ret;
	mach_msg_type_number_t i;

	ret = processor_set_things(pset, (void **)thread_list, count, PSET_THING_THREAD, TASK_FLAVOR_CONTROL);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/* do the conversion that Mig should handle */
	for (i = 0; i < *count; i++) {
		(*thread_list)[i] = (thread_t)convert_thread_to_port((*thread_list)[i]);
	}
	return KERN_SUCCESS;
}
#endif

pset_cluster_type_t
recommended_pset_type(thread_t thread)
{
#if CONFIG_THREAD_GROUPS && __AMP__
	if (thread == THREAD_NULL) {
		return PSET_AMP_E;
	}

#if DEVELOPMENT || DEBUG
	extern bool system_ecore_only;
	extern int enable_task_set_cluster_type;
	task_t task = get_threadtask(thread);
	if (enable_task_set_cluster_type && (task->t_flags & TF_USE_PSET_HINT_CLUSTER_TYPE)) {
		processor_set_t pset_hint = task->pset_hint;
		if (pset_hint) {
			return pset_hint->pset_cluster_type;
		}
	}

	if (system_ecore_only) {
		return PSET_AMP_E;
	}
#endif

	if (thread->th_bound_cluster_id != THREAD_BOUND_CLUSTER_NONE) {
		return pset_array[thread->th_bound_cluster_id]->pset_cluster_type;
	}

	if (thread->base_pri <= MAXPRI_THROTTLE) {
		if (os_atomic_load(&sched_perfctl_policy_bg, relaxed) != SCHED_PERFCTL_POLICY_FOLLOW_GROUP) {
			return PSET_AMP_E;
		}
	} else if (thread->base_pri <= BASEPRI_UTILITY) {
		if (os_atomic_load(&sched_perfctl_policy_util, relaxed) != SCHED_PERFCTL_POLICY_FOLLOW_GROUP) {
			return PSET_AMP_E;
		}
	}

	struct thread_group *tg = thread_group_get(thread);
	cluster_type_t recommendation = thread_group_recommendation(tg);
	switch (recommendation) {
	case CLUSTER_TYPE_SMP:
	default:
		if (get_threadtask(thread) == kernel_task) {
			return PSET_AMP_E;
		}
		return PSET_AMP_P;
	case CLUSTER_TYPE_E:
		return PSET_AMP_E;
	case CLUSTER_TYPE_P:
		return PSET_AMP_P;
	}
#else
	(void)thread;
	return PSET_SMP;
#endif
}

#if CONFIG_THREAD_GROUPS && __AMP__

void
sched_perfcontrol_inherit_recommendation_from_tg(perfcontrol_class_t perfctl_class, boolean_t inherit)
{
	sched_perfctl_class_policy_t sched_policy = inherit ? SCHED_PERFCTL_POLICY_FOLLOW_GROUP : SCHED_PERFCTL_POLICY_RESTRICT_E;

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_PERFCTL_POLICY_CHANGE) | DBG_FUNC_NONE, perfctl_class, sched_policy, 0, 0);

	switch (perfctl_class) {
	case PERFCONTROL_CLASS_UTILITY:
		os_atomic_store(&sched_perfctl_policy_util, sched_policy, relaxed);
		break;
	case PERFCONTROL_CLASS_BACKGROUND:
		os_atomic_store(&sched_perfctl_policy_bg, sched_policy, relaxed);
		break;
	default:
		panic("perfctl_class invalid");
		break;
	}
}

#elif defined(__arm64__)

/* Define a stub routine since this symbol is exported on all arm64 platforms */
void
sched_perfcontrol_inherit_recommendation_from_tg(__unused perfcontrol_class_t perfctl_class, __unused boolean_t inherit)
{
}

#endif /* defined(__arm64__) */
