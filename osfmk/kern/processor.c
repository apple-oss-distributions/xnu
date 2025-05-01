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
#include <machine/commpage.h>

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

/* The boot pset and pset node */
struct processor_set    pset0;
struct pset_node        pset_node0;

#if __AMP__
/* Additional AMP node */
static struct pset_node        pset_node1;
/*
 * For AMP platforms, all clusters of the same type are part of
 * the same pset_node. This allows for easier CPU selection logic.
 */
pset_node_t             ecore_node;
pset_node_t             pcore_node;
#endif /* __AMP__ */

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
SIMPLE_LOCK_DECLARE(processor_start_state_lock, 0);

uint32_t                processor_avail_count;
uint32_t                processor_avail_count_user;
#if CONFIG_SCHED_SMT
uint32_t                primary_processor_avail_count_user;
#endif /* CONFIG_SCHED_SMT */

#if XNU_SUPPORT_BOOTCPU_SHUTDOWN
TUNABLE(bool, support_bootcpu_shutdown, "support_bootcpu_shutdown", true);
#else
TUNABLE(bool, support_bootcpu_shutdown, "support_bootcpu_shutdown", false);
#endif

#if __x86_64__ || XNU_ENABLE_PROCESSOR_EXIT
TUNABLE(bool, enable_processor_exit, "processor_exit", true);
#else
TUNABLE(bool, enable_processor_exit, "processor_exit", false);
#endif

SECURITY_READ_ONLY_LATE(int)    master_cpu = 0;

struct processor        PERCPU_DATA(processor);
processor_t             processor_array[MAX_SCHED_CPUS] = { 0 };
processor_set_t         pset_array[MAX_PSETS] = { 0 };

static timer_call_func_t running_timer_funcs[] = {
	[RUNNING_TIMER_QUANTUM] = thread_quantum_expire,
	[RUNNING_TIMER_PREEMPT] = thread_preempt_expire,
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

cpumap_t processor_offline_state_map[PROCESSOR_OFFLINE_MAX];

void
processor_update_offline_state_locked(processor_t processor,
    processor_offline_state_t new_state)
{
	simple_lock_assert(&sched_available_cores_lock, LCK_ASSERT_OWNED);

	processor_offline_state_t old_state = processor->processor_offline_state;

	uint cpuid = (uint)processor->cpu_id;

	assert(old_state < PROCESSOR_OFFLINE_MAX);
	assert(new_state < PROCESSOR_OFFLINE_MAX);

	processor->processor_offline_state = new_state;

	bit_clear(processor_offline_state_map[old_state], cpuid);
	bit_set(processor_offline_state_map[new_state], cpuid);
}

void
processor_update_offline_state(processor_t processor,
    processor_offline_state_t new_state)
{
	spl_t s = splsched();
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);
	processor_update_offline_state_locked(processor, new_state);
	simple_unlock(&sched_available_cores_lock);
	splx(s);
}

void
processor_bootstrap(void)
{
	simple_lock_init(&sched_available_cores_lock, 0);
	simple_lock_init(&processor_start_state_lock, 0);

	/* Initialize boot pset node */
	pset_node0.psets = &pset0;
	pset_node0.pset_cluster_type = PSET_SMP;

#if __AMP__
	const ml_topology_info_t *topology_info = ml_get_topology_info();

	/*
	 * Continue initializing boot pset and node.
	 * Since this is an AMP system, fill up cluster type and ID information; this should do the
	 * same kind of initialization done via ml_processor_register()
	 */
	ml_topology_cluster_t *boot_cluster = topology_info->boot_cluster;
	pset0.pset_id = boot_cluster->cluster_id;
	pset0.pset_cluster_id = boot_cluster->cluster_id;
	pset_cluster_type_t boot_type = cluster_type_to_pset_cluster_type(boot_cluster->cluster_type);
	pset0.pset_cluster_type = boot_type;
	pset_node0.pset_cluster_type = boot_type;

	/* Initialize pset node pointers according to their type */
	switch (boot_type) {
	case PSET_AMP_P:
		pcore_node = &pset_node0;
		ecore_node = &pset_node1;
		break;
	case PSET_AMP_E:
		ecore_node = &pset_node0;
		pcore_node = &pset_node1;
		break;
	default:
		panic("Unexpected boot pset cluster type %d", boot_type);
	}
	ecore_node->pset_cluster_type = PSET_AMP_E;
	pcore_node->pset_cluster_type = PSET_AMP_P;

	/* Link pset_node1 to pset_node0 */
	pset_node0.node_list = &pset_node1;
#endif /* __AMP__ */

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
		smr_cpu_init(processor);
	}

	processor->state = PROCESSOR_OFF_LINE;
	processor->active_thread = processor->startup_thread = processor->idle_thread = THREAD_NULL;
	processor->processor_set = pset;
	processor_state_update_idle(processor);
	processor->starting_pri = MINPRI;
	processor->quantum_end = UINT64_MAX;
	processor->deadline = UINT64_MAX;
	processor->first_timeslice = FALSE;
	processor->processor_online = false;
#if CONFIG_SCHED_SMT
	processor->processor_primary = processor; /* no SMT relationship known at this point */
	processor->processor_secondary = NULL;
	processor->is_SMT = false;
#endif /* CONFIG_SCHED_SMT */
	processor->processor_self = IP_NULL;
	processor->processor_list = NULL;
	processor->must_idle = false;
	processor->next_idle_short = false;
	processor->last_startup_reason = REASON_SYSTEM;
	processor->last_shutdown_reason = REASON_NONE;
	processor->shutdown_temporary = false;
	processor->processor_inshutdown = false;
	processor->processor_instartup = false;
	processor->last_derecommend_reason = REASON_NONE;
	processor->running_timers_active = false;
	for (int i = 0; i < RUNNING_TIMER_MAX; i++) {
		timer_call_setup(&processor->running_timers[i],
		    running_timer_funcs[i], processor);
		running_timer_clear(processor, i);
	}
	recount_processor_init(processor);

	s = splsched();
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);

	pset_lock(pset);
	bit_set(pset->cpu_bitmask, cpu_id);
	bit_set(pset->recommended_bitmask, cpu_id);
	atomic_bit_set(&pset->node->pset_recommended_map, pset->pset_id, memory_order_relaxed);
#if CONFIG_SCHED_SMT
	bit_set(pset->primary_map, cpu_id);
#endif /* CONFIG_SCHED_SMT */
	bit_set(pset->cpu_state_map[PROCESSOR_OFF_LINE], cpu_id);
	if (pset->cpu_set_count++ == 0) {
		pset->cpu_set_low = pset->cpu_set_hi = cpu_id;
	} else {
		pset->cpu_set_low = (cpu_id < pset->cpu_set_low)? cpu_id: pset->cpu_set_low;
		pset->cpu_set_hi = (cpu_id > pset->cpu_set_hi)? cpu_id: pset->cpu_set_hi;
	}

	processor->last_recommend_reason = REASON_SYSTEM;
	sched_processor_change_mode_locked(processor, PCM_RECOMMENDED, true);
	pset_unlock(pset);

	processor->processor_offline_state = PROCESSOR_OFFLINE_NOT_BOOTED;
	bit_set(processor_offline_state_map[processor->processor_offline_state], cpu_id);

	if (processor == master_processor) {
		processor_update_offline_state_locked(processor, PROCESSOR_OFFLINE_STARTING);
	}

	simple_unlock(&sched_available_cores_lock);
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

#if CONFIG_SCHED_SMT
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
#endif /* CONFIG_SCHED_SMT */

processor_set_t
processor_pset(
	processor_t     processor)
{
	return processor->processor_set;
}

#if CONFIG_SCHED_EDGE

/* Returns the scheduling type for the pset */
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
#if CONFIG_SCHED_SMT
	processor->current_is_NO_SMT = false;
#endif /* CONFIG_SCHED_SMT */
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
#if CONFIG_SCHED_SMT
	processor->current_is_NO_SMT = thread_no_smt(thread);
#endif /* CONFIG_SCHED_SMT */
	processor->current_is_bound = thread->bound_processor != PROCESSOR_NULL;
	processor->current_is_eagerpreempt = thread_is_eager_preempt(thread);
	if (pset_lock_held) {
		/* Only update the pset load average when the pset lock is held */
		sched_update_pset_load_average(processor->processor_set, 0);
	}
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
#if CONFIG_SCHED_EDGE
	bzero(&pset->pset_load_average, sizeof(pset->pset_load_average));
	bzero(&pset->pset_runnable_depth, sizeof(pset->pset_runnable_depth));
#else /* !CONFIG_SCHED_EDGE */
	pset->load_average = 0;
#endif /* CONFIG_SCHED_EDGE */
	pset->cpu_set_low = pset->cpu_set_hi = 0;
	pset->cpu_set_count = 0;
	pset->last_chosen = -1;
	pset->cpu_bitmask = 0;
	pset->recommended_bitmask = 0;
#if CONFIG_SCHED_SMT
	pset->primary_map = 0;
#endif /* CONFIG_SCHED_SMT */
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
#if CONFIG_SCHED_SMT
	pset->is_SMT = false;
#endif /* CONFIG_SCHED_SMT */
#if CONFIG_SCHED_EDGE
	bzero(&pset->pset_execution_time, sizeof(pset->pset_execution_time));
	pset->cpu_running_foreign = 0;
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		pset->cpu_running_cluster_shared_rsrc_thread[shared_rsrc_type] = 0;
		pset->pset_cluster_shared_rsrc_load[shared_rsrc_type] = 0;
	}
#endif /* CONFIG_SCHED_EDGE */

	/*
	 * No initial preferences or forced migrations, so use the least numbered
	 * available idle core when picking amongst idle cores in a cluster.
	 */
	pset->perfcontrol_cpu_preferred_bitmask = 0;
	pset->perfcontrol_cpu_migration_bitmask = 0;
	pset->cpu_preferred_last_chosen = -1;

	pset->stealable_rt_threads_earliest_deadline = UINT64_MAX;

	if (pset != &pset0) {
		/*
		 * Scheduler runqueue initialization for non-boot psets.
		 * This initialization for pset0 happens in sched_init().
		 */
		SCHED(pset_init)(pset);
		SCHED(rt_init)(pset);
	}

	/*
	 * Because the pset_node_lock is not taken by every client of the pset_map,
	 * we need to make sure that the initialized pset contents are visible to any
	 * client that loads a non-NULL value from pset_array.
	 */
	os_atomic_store(&pset_array[pset->pset_id], pset, release);

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

	ticks[CPU_STATE_USER] += (uint32_t)(usage.ru_metrics[RCT_LVL_USER].rm_time_mach /
	    hz_tick_interval);
	ticks[CPU_STATE_SYSTEM] += (uint32_t)(
		recount_usage_system_time_mach(&usage) / hz_tick_interval);
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

/*
 * Now that we're enforcing all CPUs actually boot, we may need a way to
 * relax the timeout.
 */
TUNABLE(uint32_t, cpu_boot_timeout_secs, "cpu_boot_timeout_secs", 1); /* seconds, default to 1 second */

static const char *
    processor_start_panic_strings[] = {
	[PROCESSOR_FIRST_BOOT]                  = "boot for the first time",
	[PROCESSOR_BEFORE_ENTERING_SLEEP]       = "come online while entering system sleep",
	[PROCESSOR_WAKE_FROM_SLEEP]             = "come online after returning from system sleep",
	[PROCESSOR_CLUSTER_POWERDOWN_SUSPEND]   = "come online while disabling cluster powerdown",
	[PROCESSOR_CLUSTER_POWERDOWN_RESUME]    = "come online before enabling cluster powerdown",
	[PROCESSOR_POWERED_CORES_CHANGE]        = "come online during dynamic cluster power state change",
};

void
processor_wait_for_start(processor_t processor, processor_start_kind_t start_kind)
{
	if (!processor->processor_booted) {
		panic("processor_boot() missing for cpu %d", processor->cpu_id);
	}

	uint32_t boot_timeout_extended = cpu_boot_timeout_secs *
	    debug_cpu_performance_degradation_factor;

	spl_t s = splsched();
	simple_lock(&processor_start_state_lock, LCK_GRP_NULL);
	while (processor->processor_instartup) {
		assert_wait_timeout((event_t)&processor->processor_instartup,
		    THREAD_UNINT, boot_timeout_extended, NSEC_PER_SEC);
		simple_unlock(&processor_start_state_lock);
		splx(s);

		wait_result_t wait_result = thread_block(THREAD_CONTINUE_NULL);
		if (wait_result == THREAD_TIMED_OUT) {
			panic("cpu %d failed to %s, waited %d seconds\n",
			    processor->cpu_id,
			    processor_start_panic_strings[start_kind],
			    boot_timeout_extended);
		}

		s = splsched();
		simple_lock(&processor_start_state_lock, LCK_GRP_NULL);
	}

	if (processor->processor_inshutdown) {
		panic("%s>cpu %d still in shutdown",
		    __func__, processor->cpu_id);
	}

	simple_unlock(&processor_start_state_lock);

	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);

	if (!processor->processor_online) {
		panic("%s>cpu %d not online",
		    __func__, processor->cpu_id);
	}

	if (processor->processor_offline_state == PROCESSOR_OFFLINE_STARTED_NOT_WAITED) {
		processor_update_offline_state_locked(processor, PROCESSOR_OFFLINE_RUNNING);
	} else {
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_RUNNING);
	}

	simple_unlock(&sched_available_cores_lock);
	splx(s);
}

LCK_GRP_DECLARE(processor_updown_grp, "processor_updown");
LCK_MTX_DECLARE(processor_updown_lock, &processor_updown_grp);

static void
processor_dostartup(
	processor_t     processor,
	bool            first_boot)
{
	if (!processor->processor_booted && !first_boot) {
		panic("processor %d not booted", processor->cpu_id);
	}

	lck_mtx_assert(&cluster_powerdown_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&processor_updown_lock, LCK_MTX_ASSERT_OWNED);

	processor_set_t pset = processor->processor_set;

	assert(processor->processor_self);

	spl_t s = splsched();

	simple_lock(&processor_start_state_lock, LCK_GRP_NULL);
	assert(processor->processor_inshutdown || first_boot);
	processor->processor_inshutdown = false;
	assert(processor->processor_instartup == false);
	processor->processor_instartup = true;
	simple_unlock(&processor_start_state_lock);

	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);

	pset_lock(pset);

	if (first_boot) {
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_NOT_BOOTED);
	} else {
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_FULLY_OFFLINE);
	}

	processor_update_offline_state_locked(processor, PROCESSOR_OFFLINE_STARTING);

	assert(processor->state == PROCESSOR_OFF_LINE);

	pset_update_processor_state(pset, processor, PROCESSOR_START);
	pset_unlock(pset);

	simple_unlock(&sched_available_cores_lock);

	splx(s);

	ml_cpu_power_enable(processor->cpu_id);
	ml_cpu_begin_state_transition(processor->cpu_id);
	ml_broadcast_cpu_event(CPU_BOOT_REQUESTED, processor->cpu_id);

	cpu_start(processor->cpu_id);

	s = splsched();
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);

	if (processor->processor_offline_state == PROCESSOR_OFFLINE_STARTING) {
		processor_update_offline_state_locked(processor, PROCESSOR_OFFLINE_STARTED_NOT_RUNNING);
	} else {
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_STARTED_NOT_WAITED);
	}

	simple_unlock(&sched_available_cores_lock);
	splx(s);

	ml_cpu_end_state_transition(processor->cpu_id);
	/*
	 * Note: Because the actual wait-for-start happens sometime later,
	 * this races with processor_up calling CPU_BOOTED.
	 * To fix that, this should happen after the first wait for start
	 * confirms the CPU has booted.
	 */
	ml_broadcast_cpu_event(CPU_ACTIVE, processor->cpu_id);
}

void
processor_exit_reason(processor_t processor, processor_reason_t reason, bool is_system_sleep)
{
	assert(processor);
	assert(processor->processor_set);

	lck_mtx_lock(&processor_updown_lock);

	if (sched_is_in_sleep()) {
		assert(reason == REASON_SYSTEM);
	}

	assert((processor != master_processor) || (reason == REASON_SYSTEM) || support_bootcpu_shutdown);

	processor->last_shutdown_reason = reason;

	bool is_final_system_sleep = is_system_sleep && (processor == master_processor);

	processor_doshutdown(processor, is_final_system_sleep);

	lck_mtx_unlock(&processor_updown_lock);
}

/*
 * Called `processor_exit` in Unsupported KPI.
 * AppleARMCPU and AppleACPIPlatform call this in response to haltCPU().
 *
 * Behavior change: on both platforms, now xnu does the processor_sleep,
 * and ignores processor_exit calls from kexts.
 */
kern_return_t
processor_exit_from_kext(
	__unused processor_t processor)
{
	/* This is a no-op now. */
	return KERN_FAILURE;
}

void
processor_sleep(
	processor_t     processor)
{
	lck_mtx_assert(&cluster_powerdown_lock, LCK_MTX_ASSERT_OWNED);

	processor_exit_reason(processor, REASON_SYSTEM, true);
}

kern_return_t
processor_exit_from_user(
	processor_t     processor)
{
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t result;

	lck_mtx_lock(&cluster_powerdown_lock);

	result = sched_processor_exit_user(processor);

	lck_mtx_unlock(&cluster_powerdown_lock);

	return result;
}

void
processor_start_reason(processor_t processor, processor_reason_t reason)
{
	lck_mtx_lock(&processor_updown_lock);

	assert(processor);
	assert(processor->processor_set);
	assert(processor->processor_booted);

	if (sched_is_in_sleep()) {
		assert(reason == REASON_SYSTEM);
	}

	processor->last_startup_reason = reason;

	processor_dostartup(processor, false);

	lck_mtx_unlock(&processor_updown_lock);
}

/*
 * Called `processor_start` in Unsupported KPI.
 * AppleARMCPU calls this to boot processors.
 * AppleACPIPlatform expects ml_processor_register to call processor_boot.
 *
 * Behavior change: now ml_processor_register also boots CPUs on ARM, and xnu
 * ignores processor_start calls from kexts.
 */
kern_return_t
processor_start_from_kext(
	__unused processor_t processor)
{
	/* This is a no-op now. */
	return KERN_FAILURE;
}

kern_return_t
processor_start_from_user(
	processor_t                     processor)
{
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t result;

	lck_mtx_lock(&cluster_powerdown_lock);

	result = sched_processor_start_user(processor);

	lck_mtx_unlock(&cluster_powerdown_lock);

	return result;
}

/*
 * Boot up a processor for the first time.
 *
 * This will also be called against the main processor during system boot,
 * even though it's already running.
 */
void
processor_boot(
	processor_t                     processor)
{
	lck_mtx_lock(&cluster_powerdown_lock);
	lck_mtx_lock(&processor_updown_lock);

	assert(!sched_is_in_sleep());
	assert(!sched_is_cpu_init_completed());

	if (processor->processor_booted) {
		panic("processor %d already booted", processor->cpu_id);
	}

	if (processor == master_processor) {
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_STARTED_NOT_WAITED);
	} else {
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_NOT_BOOTED);
	}

	/*
	 *	Create the idle processor thread.
	 */
	if (processor->idle_thread == THREAD_NULL) {
		idle_thread_create(processor, processor_start_thread);
	}

	if (processor->processor_self == IP_NULL) {
		ipc_processor_init(processor);
	}

	if (processor == master_processor) {
		processor->last_startup_reason = REASON_SYSTEM;

		ml_cpu_power_enable(processor->cpu_id);

		processor_t prev = thread_bind(processor);
		thread_block(THREAD_CONTINUE_NULL);

		cpu_start(processor->cpu_id);

		assert(processor->state == PROCESSOR_RUNNING);
		processor_update_offline_state(processor, PROCESSOR_OFFLINE_RUNNING);

		thread_bind(prev);
	} else {
		processor->last_startup_reason = REASON_SYSTEM;

		/*
		 * We don't wait for startup to finish, so all CPUs can start
		 * in parallel.
		 */
		processor_dostartup(processor, true);
	}

	processor->processor_booted = true;

	lck_mtx_unlock(&processor_updown_lock);
	lck_mtx_unlock(&cluster_powerdown_lock);
}

/*
 * Wake a previously booted processor from a temporarily powered off state.
 */
void
processor_wake(
	processor_t                     processor)
{
	lck_mtx_assert(&cluster_powerdown_lock, LCK_MTX_ASSERT_OWNED);

	assert(processor->processor_booted);
	processor_start_reason(processor, REASON_SYSTEM);
}

#if CONFIG_SCHED_SMT
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
#endif /* CONFIG_SCHED_SMT */

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
	if (state == PROCESSOR_OFF_LINE || state == PROCESSOR_PENDING_OFFLINE) {
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
	processor_set_t         pset,
	mach_port_array_t      *thing_list,
	mach_msg_type_number_t *countp,
	int                     type,
	mach_task_flavor_t      flavor)
{
	unsigned int i;
	task_t task;
	thread_t thread;

	mach_port_array_t task_addr;
	task_t *task_list;
	vm_size_t actual_tasks, task_count_cur, task_count_needed;

	mach_port_array_t thread_addr;
	thread_t *thread_list;
	vm_size_t actual_threads, thread_count_cur, thread_count_needed;

	mach_port_array_t addr, newaddr;
	vm_size_t count, count_needed;

	if (pset == PROCESSOR_SET_NULL || pset != &pset0) {
		return KERN_INVALID_ARGUMENT;
	}

	task_count_cur = 0;
	task_count_needed = 0;
	task_list = NULL;
	task_addr = NULL;
	actual_tasks = 0;

	thread_count_cur = 0;
	thread_count_needed = 0;
	thread_list = NULL;
	thread_addr = NULL;
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
			mach_port_array_free(task_addr, task_count_cur);
			assert(task_count_needed > 0);
			task_count_cur = task_count_needed;

			task_addr = mach_port_array_alloc(task_count_cur,
			    Z_WAITOK | Z_ZERO);
			if (task_addr == NULL) {
				mach_port_array_free(thread_addr, thread_count_cur);
				return KERN_RESOURCE_SHORTAGE;
			}
			task_list = (task_t *)task_addr;
		}

		/* grow thread array */
		if (thread_count_needed > thread_count_cur) {
			mach_port_array_free(thread_addr, thread_count_cur);
			assert(thread_count_needed > 0);
			thread_count_cur = thread_count_needed;

			thread_addr = mach_port_array_alloc(thread_count_cur,
			    Z_WAITOK | Z_ZERO);
			if (thread_addr == NULL) {
				mach_port_array_free(task_addr, task_count_cur);
				return KERN_RESOURCE_SHORTAGE;
			}
			thread_list = (thread_t *)thread_addr;
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
		mach_port_array_free(task_addr, task_count_cur);
		task_list = NULL;
		task_count_cur = 0;
		actual_tasks = 0;
	}
#endif

	if (type == PSET_THING_THREAD) {
		if (actual_threads == 0) {
			/* no threads available to return */
			assert(task_count_cur == 0);
			mach_port_array_free(thread_addr, thread_count_cur);
			thread_list = NULL;
			*thing_list = NULL;
			*countp = 0;
			return KERN_SUCCESS;
		}
		count_needed = actual_threads;
		count = thread_count_cur;
		addr = thread_addr;
	} else {
		if (actual_tasks == 0) {
			/* no tasks available to return */
			assert(thread_count_cur == 0);
			mach_port_array_free(task_addr, task_count_cur);
			*thing_list = NULL;
			*countp = 0;
			return KERN_SUCCESS;
		}
		count_needed = actual_tasks;
		count = task_count_cur;
		addr = task_addr;
	}

	/* if we allocated too much, must copy */
	if (count_needed < count) {
		newaddr = mach_port_array_alloc(count_needed, Z_WAITOK | Z_ZERO);
		if (newaddr == NULL) {
			for (i = 0; i < actual_tasks; i++) {
				if (type == PSET_THING_THREAD) {
					thread_deallocate(thread_list[i]);
				} else {
					task_deallocate(task_list[i]);
				}
			}
			mach_port_array_free(addr, count);
			return KERN_RESOURCE_SHORTAGE;
		}

		bcopy(addr, newaddr, count_needed * sizeof(void *));
		mach_port_array_free(addr, count);

		addr = newaddr;
		count = count_needed;
	}

	*thing_list = addr;
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

	ret = processor_set_things(pset, task_list, count, PSET_THING_TASK, flavor);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/* do the conversion that Mig should handle */
	convert_task_array_to_ports(*task_list, *count, flavor);
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
	__unused processor_set_t         pset,
	__unused thread_act_array_t     *thread_list,
	__unused mach_msg_type_number_t *count)
{
	return KERN_FAILURE;
}
#elif !defined(XNU_TARGET_OS_OSX)
kern_return_t
processor_set_threads(
	__unused processor_set_t         pset,
	__unused thread_act_array_t     *thread_list,
	__unused mach_msg_type_number_t *count)
{
	return KERN_NOT_SUPPORTED;
}
#else
kern_return_t
processor_set_threads(
	processor_set_t         pset,
	thread_act_array_t      *thread_list,
	mach_msg_type_number_t  *count)
{
	kern_return_t ret;

	ret = processor_set_things(pset, thread_list, count,
	    PSET_THING_THREAD, TASK_FLAVOR_CONTROL);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/* do the conversion that Mig should handle */
	convert_thread_array_to_ports(*thread_list, *count, TASK_FLAVOR_CONTROL);
	return KERN_SUCCESS;
}
#endif

pset_cluster_type_t
recommended_pset_type(thread_t thread)
{
	/* Only used by the AMP scheduler policy */
#if CONFIG_THREAD_GROUPS && __AMP__ && !CONFIG_SCHED_EDGE
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
#else /* !CONFIG_THREAD_GROUPS || !__AMP__ || CONFIG_SCHED_EDGE */
	(void)thread;
	return PSET_SMP;
#endif /* !CONFIG_THREAD_GROUPS || !__AMP__ || CONFIG_SCHED_EDGE */
}

#if __arm64__

pset_cluster_type_t
cluster_type_to_pset_cluster_type(cluster_type_t cluster_type)
{
	switch (cluster_type) {
#if __AMP__
	case CLUSTER_TYPE_E:
		return PSET_AMP_E;
	case CLUSTER_TYPE_P:
		return PSET_AMP_P;
#endif /* __AMP__ */
	case CLUSTER_TYPE_SMP:
		return PSET_SMP;
	default:
		panic("Unexpected cluster type %d", cluster_type);
	}
}

pset_node_t
cluster_type_to_pset_node(cluster_type_t cluster_type)
{
	switch (cluster_type) {
#if __AMP__
	case CLUSTER_TYPE_E:
		return ecore_node;
	case CLUSTER_TYPE_P:
		return pcore_node;
#endif /* __AMP__ */
	case CLUSTER_TYPE_SMP:
		return &pset_node0;
	default:
		panic("Unexpected cluster type %d", cluster_type);
	}
}

#endif /* __arm64__ */

#if CONFIG_THREAD_GROUPS && __AMP__ && !CONFIG_SCHED_EDGE

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
