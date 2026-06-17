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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 *	processor.h:	Processor and processor-related definitions.
 */

#ifndef _KERN_PROCESSOR_H_
#define _KERN_PROCESSOR_H_

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>

#include <sys/cdefs.h>

#if defined(MACH_KERNEL_PRIVATE) || SCHED_TEST_HARNESS
#include <kern/bits.h>
#include <kern/sched_common.h>
#include <kern/sched_urgency.h>
#include <mach/sfi_class.h>
#include <kern/circle_queue.h>
#endif /* defined(MACH_KERNEL_PRIVATE) || SCHED_TEST_HARNESS */

#ifdef  MACH_KERNEL_PRIVATE
#include <mach/mach_types.h>
#include <kern/ast.h>
#include <kern/cpu_number.h>
#include <kern/smp.h>
#include <kern/simple_lock.h>
#include <kern/locks.h>
#include <kern/percpu.h>
#include <kern/queue.h>
#include <kern/recount.h>
#include <kern/sched.h>
#include <kern/timer.h>
#include <kern/sched_clutch.h>
#include <kern/timer_call.h>
#include <kern/assert.h>
#include <machine/limits.h>
#endif

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

#if defined(MACH_KERNEL_PRIVATE) || SCHED_TEST_HARNESS

/*
 *	Processor state is accessed by locking the scheduling lock
 *	for the assigned processor set.
 *
 *           --- PENDING_OFFLINE <
 *          /                     \
 *        _/                      \
 *  OFF_LINE ---> START ---> RUNNING ---> IDLE ---> DISPATCHING
 *         \_________________^   ^ ^______/           /
 *                                \__________________/
 *
 *  The transition from offline to start and idle to dispatching
 *  is externally driven as a a directive. However these
 *  are paired with a handshake by the processor itself
 *  to indicate that it has completed a transition of indeterminate
 *  length (for example, the DISPATCHING->RUNNING or START->RUNNING
 *  transitions must occur on the processor itself).
 *
 *  The boot processor has some special cases, and skips the START state,
 *  since it has already bootstrapped and is ready to context switch threads.
 *
 *  When a processor is in DISPATCHING or RUNNING state, the current_pri,
 *  current_thmode, and deadline fields should be set, so that other
 *  processors can evaluate if it is an appropriate candidate for preemption.
 */
#if defined(CONFIG_SCHED_DEFERRED_AST)
/*
 *           --- PENDING_OFFLINE <
 *          /                     \
 *        _/                      \
 *  OFF_LINE ---> START ---> RUNNING ---> IDLE ---> DISPATCHING
 *         \_________________^   ^ ^______/ ^_____ /  /
 *                                \__________________/
 *
 *  A DISPATCHING processor may be put back into IDLE, if another
 *  processor determines that the target processor will have nothing to do
 *  upon reaching the RUNNING state.  This is racy, but if the target
 *  responds and becomes RUNNING, it will not break the processor state
 *  machine.
 *
 *  This change allows us to cancel an outstanding signal/AST on a processor
 *  (if such an operation is supported through hardware or software), and
 *  push the processor back into the IDLE state as a power optimization.
 */
#endif /* defined(CONFIG_SCHED_DEFERRED_AST) */

typedef enum {
	PROCESSOR_OFF_LINE        = 0,    /* Not booted or off-line */
	/* PROCESSOR_SHUTDOWN     = 1,    Going off-line, but schedulable. No longer used. */
	PROCESSOR_START           = 2,    /* Being started */
	PROCESSOR_PENDING_OFFLINE = 3,    /* Going off-line, not schedulable */
	PROCESSOR_IDLE            = 4,    /* Idle (available) */
	PROCESSOR_DISPATCHING     = 5,    /* Dispatching (idle -> active) */
	PROCESSOR_RUNNING         = 6,    /* Normal execution */
	PROCESSOR_STATE_LEN       = (PROCESSOR_RUNNING + 1)
} processor_state_t;

typedef enum {
#if __AMP__
	PSET_AMP_E  = 0,
	PSET_AMP_P  = 1,
	PSET_AMP_M  = 2,
#else /* !__AMP__*/
	PSET_SMP    = 0,
#endif /* !__AMP__ */
	MAX_PSET_TYPES,
} pset_type_t;

#if __AMP__

typedef enum {
	SCHED_PERFCTL_POLICY_DEFAULT,           /*  static policy: set at boot */
	SCHED_PERFCTL_POLICY_FOLLOW_GROUP,      /* dynamic policy: perfctl_class follows thread group across amp clusters */
	SCHED_PERFCTL_POLICY_RESTRICT_E,        /* dynamic policy: limits perfctl_class to amp e cluster */
} sched_perfctl_class_policy_t;

extern _Atomic sched_perfctl_class_policy_t sched_perfctl_policy_util;
extern _Atomic sched_perfctl_class_policy_t sched_perfctl_policy_bg;

#endif /* __AMP__ */

typedef bitmap_t cpumap_t;

struct pulled_thread_queue {
	circle_queue_head_t ptq_threadq;
	cpumap_t ptq_needs_smr_cpu_down;
	bool ptq_queue_active;
};

extern __result_use_check struct pulled_thread_queue *
pulled_thread_queue_prepare(void);

/* Ensure the correct caller is blamed for preemption hygiene panics */
__not_tail_called
extern void
pulled_thread_queue_flush(struct pulled_thread_queue * threadq);

extern void
pulled_thread_queue_enqueue(
	struct pulled_thread_queue * threadq,
	thread_t thread);

extern void
pulled_thread_queue_needs_smr_cpu_down(
	struct pulled_thread_queue * threadq,
	int cpu_id);

#if __AMP__
extern pset_type_t cluster_type_to_pset_type(cluster_type_t cluster_type);
#endif /* __AMP__ */

#if __arm64__

/*
 * pset_execution_time_t
 *
 * The pset_execution_time_t type is used to maintain the average
 * execution time of threads on a pset, in us. Since the avg. execution
 * time is updated from contexts where the pset lock is not held, it uses
 * a double-wide RMW loop to update these values atomically.
 */
typedef union {
	struct {
		uint64_t        pset_avg_thread_execution_time;
		uint64_t        pset_execution_time_last_update;
	};
	unsigned __int128       pset_execution_time_packed;
} pset_execution_time_t;

#endif /* __arm64__ */

struct processor_set {
	pset_id_t               pset_id;    /* unique */
	uint32_t                cluster_id;
	int                     online_processor_count;
	/* Note: cpu_set_low, cpu_set_hi, and cpu_set_count are initialized late (in
	 * processor_init()) and should not be used during boot. On AMP platforms,
	 * cpu_bitmask is accurate at initialization. */
	int                     cpu_set_low, cpu_set_hi, cpu_set_count;
	int                     last_chosen;

#if CONFIG_SCHED_EDGE
	uint32_t                pset_load_average[TH_BUCKET_SCHED_MAX];
	/*
	 * Count of threads running or enqueued on the cluster (not including threads enqueued in a processor-bound runq).
	 * Updated atomically per scheduling bucket, around the same time as pset_load_average
	 */
	uint32_t                pset_runnable_depth[TH_BUCKET_SCHED_MAX];
#elif __AMP__
	int                     load_average;
#endif /* !CONFIG_SCHED_EDGE && __AMP__ */
	uint64_t                pset_load_last_update;
	cpumap_t                cpu_bitmask;
	cpumap_t                recommended_bitmask;
	cpumap_t                cpu_state_map[PROCESSOR_STATE_LEN];
#if CONFIG_SCHED_SMT
	cpumap_t                primary_map;
#endif /* CONFIG_SCHED_SMT */
	cpumap_t                realtime_map;
	cpumap_t                cpu_available_map;

#define SCHED_PSET_TLOCK (1)
#if     defined(SCHED_PSET_TLOCK)
/* TODO: reorder struct for temporal cache locality */
	__attribute__((aligned(128))) lck_ticket_t      sched_lock;
#else /* SCHED_PSET_TLOCK*/
	__attribute__((aligned(128))) lck_spin_t        sched_lock;     /* lock for above */
#endif /* SCHED_PSET_TLOCK*/

	struct run_queue        pset_runq;      /* runq for this processor set, used by the amp and dualq scheduler policies */
	struct rt_queue         rt_runq;        /* realtime runq for this processor set */
	/*
	 * stealable_rt_threads_earliest_deadline stores the earliest deadline of
	 * the rt_runq if this pset has stealable RT threads, and RT_DEADLINE_NONE
	 * otherwise.
	 *
	 * It can only be read outside of the pset lock in sched_rt_steal_thread as
	 * a hint for which pset to lock. It must be re-checked under the lock
	 * before relying on its value to dequeue a thread.
	 *
	 * Updates are made under the pset lock by pset_update_rt_stealable_state.
	 */
	_Atomic uint64_t        stealable_rt_threads_earliest_deadline;
#if CONFIG_SCHED_CLUTCH
	struct sched_clutch_root pset_clutch_root; /* clutch hierarchy root */
#endif /* CONFIG_SCHED_CLUTCH */

	/* CPUs that have been sent an unacknowledged remote AST for scheduling purposes */
	cpumap_t                pending_AST_URGENT_cpu_mask;
	_Atomic cpumap_t        pending_AST_PREEMPT_cpu_mask;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	/*
	 * A separate mask, for ASTs that we may be able to cancel.  This is dependent on
	 * some level of support for requesting an AST on a processor, and then quashing
	 * that request later.
	 *
	 * The purpose of this field (and the associated codepaths) is to infer when we
	 * no longer need a processor that is DISPATCHING to come up, and to prevent it
	 * from coming out of IDLE if possible.  This should serve to decrease the number
	 * of spurious ASTs in the system, and let processors spend longer periods in
	 * IDLE.
	 */
	cpumap_t                pending_deferred_AST_cpu_mask;
#endif /* defined(CONFIG_SCHED_DEFERRED_AST) */
	cpumap_t                pending_spill_cpu_mask;
	cpumap_t                rt_pending_spill_cpu_mask;

	struct ipc_port *       pset_self;              /* port for operations */
	struct ipc_port *       pset_name_self; /* port for information */

	processor_set_t         pset_list;              /* chain of associated psets */
	pset_node_t             node;

	/*
	 * The type that this pset will be treated like for scheduling purposes
	 */
	pset_type_t             pset_type;

#if CONFIG_SCHED_EDGE
	/*
	 * Fields used by Clutch/Edge scheduler are protected by a combination of
	 * atomics and the pset lock.
	 * See the legend of field annotations below:
	 *
	 * (P): Reads/writes protected by the pset lock.
	 * (A): Reads/writes done atomically.
	 * (I): Safe to read unprotected because values are not updated
	 *      after initialization.
	 * (W): Reads/writes done atomically, but writes are only
	 *      published with the pset lock held.
	 */
	/* (A) Map of CPUs running threads considered "foreign" relative to their current pset */
	_Atomic cpumap_t        cpu_running_foreign;
	/* (A) Map of CPUs running threads tagged as shared resource */
	_Atomic cpumap_t        cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	/* (A) sched_bucket running on each CPU, as last observed by that CPU */
	_Atomic sched_bucket_t          cpu_running_buckets[MAX_CPUS];
	/* (I) Map of psets considered "foreign" relative to this pset */
	bitmap_t                foreign_psets[BITMAP_LEN(MAX_PSETS)];
	/* (I) Map of psets considered "native" relative to this pset */
	bitmap_t                native_psets[BITMAP_LEN(MAX_PSETS)];
	/* (I) Map of psets local on the same die as this pset */
	bitmap_t                local_psets[BITMAP_LEN(MAX_PSETS)];
	/* (I) Map of psets positioned on a remote die relative to this pset */
	bitmap_t                remote_psets[BITMAP_LEN(MAX_PSETS)];
	/* (A) Moving avg. execution time in ns for threads of each sched bucket that recently ran on this pset  */
	pset_execution_time_t   pset_execution_time[TH_BUCKET_SCHED_MAX];
	uint64_t                pset_cluster_shared_rsrc_load[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	/* (A) Edge matrix graph, encoding inter-pset migration policy */
	_Atomic sched_clutch_edge       sched_edges[MAX_PSETS][TH_BUCKET_SCHED_MAX];
	/* (A) Order in which to search other psets and break ties for spill policy */
	sched_pset_search_order_t       spill_search_order[TH_BUCKET_SCHED_MAX];
	/* (I) Recommended width of threads (one per core) if this is the preferred pset */
	uint8_t                 max_parallel_cores[TH_BUCKET_SCHED_MAX];
	/* (I) Recommended width of shared resource threads (one per cluster) if this is the preferred pset */
	uint8_t                 max_parallel_clusters[TH_BUCKET_SCHED_MAX];
#endif /* CONFIG_SCHED_EDGE */

#if __AMP__
	/* Writes to sched_rt_* fields are guarded by sched_available_cores_lock to
	 * prevent concurrent updates. Reads are not guaranteed to be consistent
	 * except atomicity of specific fields, as noted below */

	/* sched_rt_edges controls realtime thread scheduling policies like migration and steal. */
	sched_clutch_edge       sched_rt_edges[MAX_PSETS];
	sched_pset_search_order_t       sched_rt_spill_search_order; /* should be stored/accessed atomically */
#if CONFIG_SCHED_EDGE
	sched_pset_search_order_t       sched_rt_steal_search_order; /* should be stored/accessed atomically */
#endif /* CONFIG_SCHED_EDGE */
#endif /* __AMP__ */
	cpumap_t                perfcontrol_cpu_preferred_bitmask;
	cpumap_t                perfcontrol_cpu_migration_bitmask;
	int                     cpu_preferred_last_chosen;
#if CONFIG_SCHED_SMT
	bool                    is_SMT;                 /* pset contains SMT processors */
#endif /* CONFIG_SCHED_SMT */
};

typedef bitmap_t pset_map_t;

struct pset_node {
	processor_set_t         psets;                  /* list of associated psets */

	pset_node_t             node_list;              /* chain of associated nodes */

	pset_type_t             pset_type;              /* Same as the type of all psets in this node */

	pset_map_t              pset_map;               /* map of associated psets */

	cpumap_t                cpu_map;                /* map of associated processors */

	_Atomic pset_map_t      pset_idle_map;          /* psets with at least one IDLE CPU */
	_Atomic pset_map_t      pset_non_rt_map;        /* psets with at least one available CPU not running a realtime thread */
#if CONFIG_SCHED_SMT
	_Atomic pset_map_t      pset_non_rt_primary_map;/* psets with at least one available primary CPU not running a realtime thread */
#endif /* CONFIG_SCHED_SMT */
	_Atomic pset_map_t      pset_recommended_map;   /* psets with at least one recommended processor */
};

/* Returns true if the node contains no psets. */
extern bool pset_node_is_empty(pset_node_t node);

/* Boot pset node */
extern pset_node_t sched_boot_pset_node;

extern pset_node_t pset_node_for_pset_type(pset_type_t pset_type);

extern queue_head_t tasks, threads, corpse_tasks;
extern int tasks_count, terminated_tasks_count, threads_count, terminated_threads_count;
decl_lck_mtx_data(extern, tasks_threads_lock);
decl_lck_mtx_data(extern, tasks_corpse_lock);

/*
 * The terminated tasks queue should only be inspected elsewhere by stackshot.
 */
extern queue_head_t terminated_tasks;

extern queue_head_t terminated_threads;

/*
 * Valid state transitions:
 * not booted -> starting
 * starting -> started not running
 * starting -> started not waited
 * started not running | not waited -> running
 * running -> begin shutdown
 * begin shutdown -> pending offline
 * pending offline -> system sleep
 * system sleep -> running
 * pending offline -> cpu offline -> fully offline
 * fully offline -> starting
 */
__enum_closed_decl(processor_offline_state_t, uint8_t, {
	/* Before it's ever booted */
	PROCESSOR_OFFLINE_NOT_BOOTED            = 0,

	/* cpu_start is going to be sent */
	PROCESSOR_OFFLINE_STARTING              = 1,

	/* cpu_start has been sent, but it hasn't started up yet */
	PROCESSOR_OFFLINE_STARTED_NOT_RUNNING   = 2,

	/* processor has started up and began running, but nobody has wait-for-start-ed it */
	PROCESSOR_OFFLINE_STARTED_NOT_WAITED    = 3,

	/* processor is running and someone confirmed this with wait for start, no state change operations are in flight */
	PROCESSOR_OFFLINE_RUNNING               = 4,  /* This is the 'normal' state */

	/* someone is working on asking to shut this processor down */
	PROCESSOR_OFFLINE_BEGIN_SHUTDOWN        = 5,

	/* this processor has started itself on its way to offline */
	PROCESSOR_OFFLINE_PENDING_OFFLINE       = 6,

	/* another processor has confirmed the processor has powered down */
	PROCESSOR_OFFLINE_CPU_OFFLINE           = 7,

	/* cluster power has been disabled for this processor if it's going to be */
	PROCESSOR_OFFLINE_FULLY_OFFLINE         = 8, /* This is the finished powering down state */

	/* This processor is the boot processor, and it's in the final system sleep */
	PROCESSOR_OFFLINE_FINAL_SYSTEM_SLEEP    = 9,

	PROCESSOR_OFFLINE_MAX                   = 10,
});

/* Locked under the sched_available_cores_lock */
extern cpumap_t processor_offline_state_map[PROCESSOR_OFFLINE_MAX];


struct processor {
	processor_state_t       state;                  /* See above */
#if CONFIG_SCHED_SMT
	bool                    is_SMT;
	bool                    current_is_NO_SMT;      /* cached TH_SFLAG_NO_SMT of current thread */
#endif /* CONFIG_SCHED_SMT */
	bool                    is_recommended;
	bool                    current_is_bound;       /* current thread is bound to this processor */
	bool                    current_is_eagerpreempt;/* current thread is TH_SFLAG_EAGERPREEMPT */
	bool                    pending_nonurgent_preemption; /* RUNNING_TIMER_PREEMPT is armed */
	struct thread          *active_thread;          /* thread running on processor */
	struct thread          *idle_thread;            /* this processor's idle thread. */
	struct thread          *startup_thread;

	processor_set_t         processor_set;  /* assigned set */

	/*
	 * XXX All current_* fields should be grouped together, as they're
	 * updated at the same time.
	 */
	int                     current_pri;            /* priority of current thread */
	sfi_class_id_t          current_sfi_class;      /* SFI class of current thread */
	perfcontrol_class_t     current_perfctl_class;  /* Perfcontrol class for current thread */
	/*
	 * The pset type recommended for the current thread, used by AMP scheduler
	 */
	pset_type_t             current_recommended_pset_type;
	thread_urgency_t        current_urgency;        /* cached urgency of current thread */

#if CONFIG_THREAD_GROUPS
	struct thread_group    *current_thread_group;   /* thread_group of current thread */
#endif /* CONFIG_THREAD_GROUPS */
	int                     starting_pri;           /* priority of current thread as it was when scheduled */
	int                     cpu_id;                 /* platform numeric id */

	uint64_t                quantum_end;            /* time when current quantum ends */
	uint64_t                last_dispatch;          /* time of last dispatch */

#if KPERF
	uint64_t                kperf_last_sample_time; /* time of last kperf sample */
#endif /* KPERF */

	uint64_t                deadline;               /* for next realtime thread */
	bool                    first_timeslice;        /* has the quantum expired since context switch */

	bool                    must_idle;              /* Needs to be forced idle as next selected thread is allowed on this processor */
	bool                    next_idle_short;        /* Expecting a response IPI soon, so the next idle period is likely very brief */
	uint64_t                next_idle_short_wfe_deadline;  /* Pending deadline to stop a WFE spin, when expecting a thread to rebalance here */

#if !SCHED_TEST_HARNESS
	bool                    running_timers_active;  /* whether the running timers should fire */
	struct timer_call       running_timers[RUNNING_TIMER_MAX];
#endif /* !SCHED_TEST_HARNESS */

	struct run_queue        runq;                   /* runq for this processor */

#if !SCHED_TEST_HARNESS
	struct recount_processor pr_recount;
#endif /* !SCHED_TEST_HARNESS */

#if CONFIG_SCHED_SMT
	/*
	 * Pointer to primary processor for secondary SMT processors, or a
	 * pointer to ourselves for primaries or non-SMT.
	 */
	processor_t             processor_primary;
	processor_t             processor_secondary;
#endif /* CONFIG_SCHED_SMT */
	struct ipc_port        *processor_self;         /* port for operations */

	processor_t             processor_list;         /* all existing processors */

	uint64_t                timer_call_ttd;         /* current timer call time-to-deadline */
	processor_reason_t      last_startup_reason;
	processor_reason_t      last_shutdown_reason;
	processor_reason_t      last_recommend_reason;
	processor_reason_t      last_derecommend_reason;

	struct pulled_thread_queue processor_threadq;   /* queue of threads pulled from runq */
	struct pulled_thread_queue processor_threadq_interrupt;   /* queue of threads pulled from runq when in an interrupt handler */

	/* locked by processor_start_state_lock */
	bool                    processor_instartup;     /* between dostartup and up */

	/* Locked by the processor_updown_lock */
	bool                    processor_booted;       /* Has gone through processor_boot */

	/* Locked by sched_available_cores_lock */
	bool                    shutdown_temporary;     /* Shutdown should be transparent to user - don't update CPU counts */
	bool                    processor_online;       /* between mark-online and mark-offline, tracked in sched_online_processors */

	bool                    processor_inshutdown;   /* is the processor between processor_shutdown and processor_startup */
	processor_offline_state_t processor_offline_state;

#if CONFIG_SCHED_EDGE
	_Atomic int             stir_the_pot_inbox_cpu; /* ID of P-core available to be preempted for stir-the-pot */
#endif /* CONFIG_SCHED_EDGE */
};

extern bool sched_all_cpus_offline(void);
extern void sched_assert_not_last_online_cpu(int cpu_id);

extern processor_t processor_list; /* finalized during startup by the boot processor */

decl_simple_lock_data(extern, processor_start_state_lock);

/*
 * Maximum number of CPUs supported by the scheduler.  bits.h bitmap macros
 * need to be used to support greater than 64.
 */
static_assert(MAX_CPUS <= 64, "The scheduler cannot support more than 64 CPUs.");

extern processor_t     __single processor_array[MAX_CPUS];    /* array indexed by cpuid */
extern processor_set_t __single pset_array[MAX_PSETS];              /* array indexed by pset_id */
#if CONFIG_SCHED_EDGE
extern pset_id_t                cluster_id_to_pset_id[MAX_CPU_CLUSTERS] /* array indexed by cluster_id */;
#endif /* CONFIG_SCHED_EDGE */

/* Returns the processor set for the given ID, asserting on its existence. */
processor_set_t
pset_for_id_checked(pset_id_t id);

/* Returns the processor set for the given ID. */
OS_INLINE
processor_set_t
pset_for_id(pset_id_t id)
{
	extern struct processor_set pset_array_actual[MAX_PSETS];
	return &pset_array_actual[id];
}

#if __AMP__
bool pset_is_primary(pset_id_t);
#endif /* __AMP__ */

/* Boot (and default) pset */
extern processor_set_t          sched_boot_pset;

extern uint32_t                 processor_avail_count;
extern uint32_t                 processor_avail_count_user;
#if CONFIG_SCHED_SMT
extern uint32_t                 primary_processor_avail_count_user;
#endif /* CONFIG_SCHED_SMT */

#define cpumap_foreach(cpu_id, cpumap) \
	for (int cpu_id = lsb_first(cpumap); \
	    (cpu_id) >= 0; \
	     cpu_id = lsb_next((cpumap), cpu_id))

#define foreach_node(node) \
	for (pset_node_t node = sched_boot_pset_node; node != NULL; node = node->node_list)

#define foreach_pset_id(pset_id, node) \
	for (int pset_id = lsb_first((node)->pset_map); \
	    pset_id >= 0; \
	    pset_id = lsb_next((node)->pset_map, pset_id))

cpumap_t pset_available_cpumap(processor_set_t pset);

unsigned int pset_cluster_id(processor_set_t);

/*
 * All of the operations on a processor that change the processor count
 * published to userspace and kernel.
 */
__enum_closed_decl(processor_mode_t, uint8_t, {
	PCM_RECOMMENDED = 0, /* processor->is_recommended */
	PCM_TEMPORARY   = 1, /* processor->shutdown_temporary */
	PCM_ONLINE      = 2, /* processor->processor_online */
});

extern void sched_processor_change_mode_locked(processor_t processor, processor_mode_t pcm_mode, bool value);

extern processor_t      current_processor(void);

#if !SCHED_TEST_HARNESS

#define master_processor PERCPU_GET_MASTER(processor)
PERCPU_DECL(struct processor, processor);

/* Lock macros, always acquired and released with interrupts disabled (splsched()) */

extern lck_grp_t pset_lck_grp;

#if defined(SCHED_PSET_TLOCK)
#define pset_lock_init(p)               lck_ticket_init(&(p)->sched_lock, &pset_lck_grp)
#define pset_lock(p)                    lck_ticket_lock(&(p)->sched_lock, &pset_lck_grp)
#define pset_unlock(p)                  lck_ticket_unlock(&(p)->sched_lock)
#define pset_assert_locked(p)           lck_ticket_assert_owned(&(p)->sched_lock)
#else /* SCHED_PSET_TLOCK*/
#define pset_lock_init(p)               lck_spin_init(&(p)->sched_lock, &pset_lck_grp, NULL)
#define pset_lock(p)                    lck_spin_lock_grp(&(p)->sched_lock, &pset_lck_grp)
#define pset_unlock(p)                  lck_spin_unlock(&(p)->sched_lock)
#define pset_assert_locked(p)           LCK_SPIN_ASSERT(&(p)->sched_lock, LCK_ASSERT_OWNED)
#endif /*!SCHED_PSET_TLOCK*/

inline static processor_set_t
change_locked_pset(processor_set_t current_pset, processor_set_t new_pset)
{
	if (current_pset != new_pset) {
		pset_unlock(current_pset);
		pset_lock(new_pset);
	}

	return new_pset;
}

#endif /* !SCHED_TEST_HARNESS */

extern void             pset_node_add_pset(
	pset_node_t             node,
	processor_set_t         pset);

extern void             processor_bootstrap(void);

extern void             processor_init(
	processor_t             processor,
	int                     cpu_id,
	processor_set_t         processor_set);

#if CONFIG_SCHED_SMT
extern void             processor_set_primary(
	processor_t             processor,
	processor_t             primary);
#endif /* CONFIG_SCHED_SMT */

extern void
processor_update_offline_state(processor_t processor, processor_offline_state_t new_state);
extern void
processor_update_offline_state_locked(processor_t processor, processor_offline_state_t new_state);

extern void processor_doshutdown(
	processor_t             processor,
	bool                    is_final_system_sleep);

__enum_closed_decl(processor_start_kind_t, uint8_t, {
	PROCESSOR_FIRST_BOOT = 0,
	PROCESSOR_BEFORE_ENTERING_SLEEP = 1,
	PROCESSOR_WAKE_FROM_SLEEP = 2,
	PROCESSOR_CLUSTER_POWERDOWN_SUSPEND = 3,
	PROCESSOR_CLUSTER_POWERDOWN_RESUME = 4,
	PROCESSOR_POWERED_CORES_CHANGE = 5,
});

extern void             processor_wait_for_start(
	processor_t             processor,
	processor_start_kind_t  start_kind);

extern kern_return_t    processor_start_from_user(
	processor_t             processor);
extern kern_return_t    processor_start_from_kext(
	processor_t             processor);
extern kern_return_t    processor_exit_from_kext(
	processor_t             processor);


extern void processor_start_reason(
	processor_t             processor,
	processor_reason_t      reason);
extern void processor_exit_reason(
	processor_t             processor,
	processor_reason_t      reason,
	bool is_system_sleep);

extern kern_return_t sched_processor_exit_user(processor_t processor);
extern kern_return_t sched_processor_start_user(processor_t processor);

extern bool sched_mark_processor_online(processor_t processor, processor_reason_t reason);
extern void sched_mark_processor_offline(processor_t processor, bool is_final_system_sleep);

extern processor_set_t  processor_pset(
	processor_t             processor);

#if __AMP__
/* Create one or more psets for the given cluster. Can only be called at startup. */
extern void
psets_create_for_cluster(
	uint32_t                  cluster_id,
	const ml_topology_info_t *topology);
#endif /* __AMP__ */
#if __x86_64__
extern processor_set_t  pset_create_smp(
	int                     pset_id);
#endif /* __x86_64__ */

extern void             pset_init(
	processor_set_t         pset);

#if __AMP__
extern processor_set_t  pset_find_for_cpu_id(
	uint32_t                cpu_id);
#endif /* __AMP__ */

#if !SCHED_TEST_HARNESS

extern lck_mtx_t cluster_powerdown_lock;
extern lck_mtx_t processor_updown_lock;

extern bool sched_is_in_sleep(void);
extern bool sched_is_cpu_init_completed(void);

extern void             processor_queue_shutdown(
	processor_t             processor);

extern kern_return_t    processor_info_count(
	processor_flavor_t      flavor,
	mach_msg_type_number_t  *count);

extern void processor_cpu_load_info(
	processor_t processor,
	natural_t ticks[static CPU_STATE_MAX]);

extern void             machine_run_count(
	uint32_t                count);

#if defined(__x86_64__)
extern processor_t      machine_choose_processor(
	processor_set_t         pset,
	processor_t             processor);
#endif /* __x86_64__ */

#endif /* !SCHED_TEST_HARNESS */

inline static processor_set_t
next_pset(processor_set_t pset)
{
	pset_map_t map = pset->node->pset_map;

	int pset_id = lsb_next(map, pset->pset_id);
	if (pset_id == -1) {
		pset_id = lsb_first(map);
	}

	return pset_for_id((pset_id_t)pset_id);
}

#define PSET_THING_TASK         0
#define PSET_THING_THREAD       1

extern pset_type_t      recommended_pset_type(
	thread_t                thread);

extern void             processor_state_update_idle(
	processor_t             processor);

extern void             processor_state_update_from_new_thread(
	processor_t             processor,
	thread_t                thread,
	bool                    pset_lock_held);

extern void             processor_state_update_from_running_thread(
	processor_t             processor,
	thread_t                thread,
	bool                    pset_lock_held);

#if CONFIG_SCHED_EDGE
extern pset_type_t pset_type_for_id(pset_id_t pset_id);
#endif /* CONFIG_SCHED_EDGE */

extern void
pset_update_processor_state(processor_set_t pset, processor_t processor, uint new_state);

decl_simple_lock_data(extern, sched_available_cores_lock);

#endif  /* defined(MACH_KERNEL_PRIVATE) || SCHED_TEST_HARNESS */

#ifdef KERNEL_PRIVATE

/* Private KPI */
extern processor_t      cpu_to_processor(int cpu);

/*!
 * @function              sched_enable_acc_rail
 * @abstract              Enable shared voltage rail for a single ACC block.
 * @param die_id          0-based die number indicating which die the ACC is on.
 * @param die_cluster_id  0 for the first cluster on the die, 1 for the second, ...
 * @discussion            Called from the PMGR driver.  On systems where ANE and PACC
 *                        share a voltage rail, the PMGR driver calls into XNU prior to
 *                        accessing the ANE hardware, to ensure that the ANE block
 *                        is powered.  This will block until the rail has been enabled,
 *                        and it must be called from a schedulable context.
 *
 *                        This should not be called on systems without a shared ANE/ACC rail.
 *                        The caller is responsible for knowing which die/cluster needs to
 *                        be forced on, in order to allow access to the ANE block.
 */
extern void sched_enable_acc_rail(unsigned int die_id, unsigned int die_cluster_id);

/*!
 * @function              sched_disable_acc_rail
 * @abstract              Disable voltage rail for a single ACC block.
 * @param die_id          0-based die number indicating which die the ACC is on.
 * @param die_cluster_id  0 for the first cluster on the die, 1 for the second, ...
 * @discussion            Tells XNU that the shared ACC voltage rail can be safely disabled.
 *                        This may or may not cut voltage immediately.  Must be called from a
 *                        schedulable context.
 */
extern void sched_disable_acc_rail(unsigned int die_id, unsigned int die_cluster_id);

/*
 * Private KPI with CLPC
 *
 * Update the scheduler with the set of cores that should be used to dispatch new threads.
 * Non-recommended cores can still be used to field interrupts or run bound threads.
 * This should be called with interrupts enabled and no scheduler locks held.
 */
#define ALL_CORES_RECOMMENDED   (~(uint64_t)0)
#define ALL_CORES_POWERED       (~(uint64_t)0)

extern void sched_perfcontrol_update_recommended_cores(uint32_t recommended_cores);
extern void sched_perfcontrol_update_recommended_cores_reason(uint64_t recommended_cores, processor_reason_t reason, uint32_t flags);

/* Request a change to the powered cores mask that CLPC wants.  Does not block waiting for completion. */
extern void sched_perfcontrol_update_powered_cores(uint64_t powered_cores, processor_reason_t reason, uint32_t flags);

/* Reevaluate the thread placement decision on cpu_id and force a preemption if necessary. */
extern bool sched_perfcontrol_check_oncore_thread_preemption(uint64_t flags, int cpu_id);

#endif /* KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

extern bool support_bootcpu_shutdown;
extern bool enable_processor_exit;
extern unsigned int processor_count;

#if CONFIG_SCHED_SMT
extern int sched_enable_smt;

extern kern_return_t    enable_smt_processors(bool enable);
#endif /* CONFIG_SCHED_SMT */

extern void sched_override_available_cores_for_sleep(void);
extern void sched_restore_available_cores_after_sleep(void);
extern bool processor_should_kprintf(processor_t processor, bool starting);
extern void suspend_cluster_powerdown(void);
extern void resume_cluster_powerdown(void);
extern kern_return_t suspend_cluster_powerdown_from_user(void);
extern kern_return_t resume_cluster_powerdown_from_user(void);
extern int get_cluster_powerdown_user_suspended(void);

extern void processor_wake(
	processor_t             processor);
extern void processor_sleep(
	processor_t             processor);
extern void processor_boot(
	processor_t             processor);
extern kern_return_t    processor_exit_from_user(
	processor_t             processor);

#endif /* XNU_KERNEL_PRIVATE */

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* _KERN_PROCESSOR_H_ */
