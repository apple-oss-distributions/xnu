/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#ifndef _KERN_SCHED_CLUTCH_H_
#define _KERN_SCHED_CLUTCH_H_

#include <kern/sched.h>
#include <kern/priority_queue.h>
#include <kern/bits.h>
#include <kern/kern_types.h>
#include <kern/sched_common.h>

#if !SCHED_TEST_HARNESS

#include <machine/atomic.h>
#include <kern/thread_group.h>

#endif /* !SCHED_TEST_HARNESS */

#if CONFIG_SCHED_CLUTCH

/*
 * Threads hard-bound to specific processors are not managed in
 * the Clutch hierarchy. This helper macro is used to indicate
 * whether a thread should be enqueued in the hierarchy.
 */
#define SCHED_CLUTCH_THREAD_ELIGIBLE(thread)    ((thread->bound_processor) == PROCESSOR_NULL)

#if CONFIG_SCHED_EDGE
#define SCHED_CLUTCH_THREAD_PSET_BOUND(thread)       (thread->th_bound_pset_id != THREAD_BOUND_PSET_NONE)

#else /* CONFIG_SCHED_EDGE */
#define SCHED_CLUTCH_THREAD_PSET_BOUND(thread)       (0)
#endif /* CONFIG_SCHED_EDGE */

/*
 * Clutch Bucket Runqueue Structure.
 */
struct sched_clutch_bucket_runq {
	int                     scbrq_highq;
	int                     scbrq_count;
	bitmap_t                scbrq_bitmap[BITMAP_LEN(NRQS_MAX)];
	circle_queue_head_t     scbrq_queues[NRQS_MAX];
};
typedef struct sched_clutch_bucket_runq *sched_clutch_bucket_runq_t;

/*
 *
 * Clutch hierarchy locking protocol
 *
 * The scheduler clutch hierarchy is protected by a combination of
 * atomics and pset lock.
 * See the legend of field annotations below:
 *
 * (P): Reads/writes protected by the pset lock.
 * (A): Reads/writes done atomically.
 * (I): Safe to read unprotected because values are not updated
 *      after initialization.
 * (W): Reads/writes done atomically, but writes are only
 *      published with the pset lock held.
 */

/*
 * struct sched_clutch_root_bucket
 *
 * A clutch_root_bucket represents all threads across all thread groups
 * that are in the same scheduler bucket (FG/IN/...). The clutch_root_bucket
 * is selected for execution by the root level bucket selection algorithm
 * which bases the decision on the clutch_root_bucket's deadline (EDF). The
 * deadline for a root bucket is calculated based on its runnable timestamp
 * and the worst-case-execution-latency values specied in sched_clutch_root_bucket_wcel[]
 */
struct sched_clutch_root_bucket {
	/* (I) sched bucket represented by this root bucket */
	uint8_t                         scrb_bucket;
	/* (I) Indicates the root bucket represents cluster bound threads */
	bool                            scrb_bound;
	/* (P) Indicates if the root bucket is in starvation avoidance mode */
	bool                            scrb_starvation_avoidance;

	union {
		/* (P) priority queue for all unbound clutch buckets in this sched bucket */
		struct sched_clutch_bucket_runq scrb_clutch_buckets;
		/* (P) Runqueue for all bound threads part of this root bucket */
		struct run_queue                scrb_bound_thread_runq;
	};
	/* (P) priority queue entry to use for enqueueing root bucket into root prioq */
	struct priority_queue_entry_deadline scrb_pqlink;
	/* (P) warped deadline for root bucket */
	uint64_t                        scrb_warped_deadline;
	/* (P) warp remaining for root bucket */
	uint64_t                        scrb_warp_remaining;
	/* (P) timestamp for the start of the starvation avoidance window */
	uint64_t                        scrb_starvation_ts;
};
typedef struct sched_clutch_root_bucket *sched_clutch_root_bucket_t;

#if CONFIG_SCHED_EDGE

struct sched_edge_steal_silo {
	/*
	 * (P) priority queue per QoS bucket, containing runnable
	 * clutch buckets enqueued in the owning clutch hierarchy
	 * and recommended to the same preferred pset (may be
	 * different from the clutch hierarchy where the clutch
	 * buckets are enqueued).
	 */
	struct priority_queue_sched_max sess_steal_queues[TH_BUCKET_SCHED_MAX];
	/* (W) bitmap of which steal queues contain threads */
	bitmap_t _Atomic                sess_populated_steal_queues[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
};
typedef struct sched_edge_steal_silo *sched_edge_steal_silo_t;

#endif /* CONFIG_SCHED_EDGE */

/*
 * struct sched_clutch_root
 *
 * A clutch_root represents the root of the hierarchy. It maintains a
 * priority queue of all runnable root buckets. The clutch_root also
 * maintains the information about the last clutch_root_bucket scheduled
 * in order to implement bucket level quantum. The bucket level quantums
 * allow low priority buckets to get a "fair" chance of using the CPU even
 * if they contain a bunch of short executing threads. The bucket quantums
 * are configured using sched_clutch_root_bucket_quantum[]
 */
struct sched_clutch_root {
	/* (P) root level priority; represents the highest runnable thread in the hierarchy */
	int16_t                         scr_priority;
	/* (P) total number of runnable threads in the hierarchy */
	uint16_t                        scr_thr_count;
	/* (P) root level urgency; represents the urgency of the whole hierarchy for pre-emption purposes */
	int16_t                         scr_urgency;
#if CONFIG_SCHED_EDGE
	/* (P) runnable shared resource load enqueued in this cluster/root hierarchy */
	uint16_t                        scr_shared_rsrc_load_runnable[CLUSTER_SHARED_RSRC_TYPE_COUNT];
#endif /* CONFIG_SCHED_EDGE */

	pset_id_t                       scr_pset_id;
	/* (I) processor set this hierarchy belongs to */
	processor_set_t                 scr_pset;
	/*
	 * (P) list of all runnable clutch buckets across the system;
	 * allows easy iteration in the sched tick based timesharing code
	 */
	queue_head_t                    scr_clutch_buckets;

#if CONFIG_SCHED_EDGE
	/*
	 * (P) silo per pset recommendation, consisting of steal (priority)
	 * queues per QoS bucket that track runnable clutch buckets enqueued
	 * in this hierarchy. This allows other psets to steal threads of
	 * specific recommendations/QoSes from this pset in a fine-grained
	 * manner, respecting the Edge matrix.
	 */
	struct sched_edge_steal_silo    scr_steal_silos[MAX_PSETS];
	/* (W) bitmap of which steal silos contain threads */
	bitmap_t _Atomic                scr_populated_steal_silos[BITMAP_LEN(MAX_PSETS)];
	/* (W) bitmap of which pset recommendations can migrate here */
	bitmap_t _Atomic                scr_incoming_migration_allowed[TH_BUCKET_SCHED_MAX][BITMAP_LEN(MAX_PSETS)];
#endif /* CONFIG_SCHED_EDGE */

	/* Root level bucket management */

	/* (P) bitmap of all runnable unbounded root buckets */
	bitmap_t                        scr_unbound_runnable_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
	/* (P) bitmap of all runnable unbounded root buckets which have warps remaining */
	bitmap_t                        scr_unbound_warp_available[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
	/* (P) bitmap of all runnable bounded root buckets */
	bitmap_t                        scr_bound_runnable_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];
	/* (P) bitmap of all runnable bounded root buckets which have warps remaining */
	bitmap_t                        scr_bound_warp_available[BITMAP_LEN(TH_BUCKET_SCHED_MAX)];

	/* (P) priority queue of all runnable unbounded root buckets in deadline order */
	struct priority_queue_deadline_min scr_unbound_root_buckets;
	/* (P) priority queue of all bounded root buckets in deadline order */
	struct priority_queue_deadline_min scr_bound_root_buckets;

	/* (P) cumulative run counts at each bucket for load average calculation */
	uint16_t _Atomic                scr_cumulative_run_count[TH_BUCKET_SCHED_MAX];

	/* (P) storage for all unbound clutch_root_buckets */
	struct sched_clutch_root_bucket scr_unbound_buckets[TH_BUCKET_SCHED_MAX];
	/* (P) storage for all bound clutch_root_buckets */
	struct sched_clutch_root_bucket scr_bound_buckets[TH_BUCKET_SCHED_MAX];
};
typedef struct sched_clutch_root *sched_clutch_root_t;

/* forward declaration for sched_clutch */
struct sched_clutch;

/*
 * sched_clutch_bucket_cpu_data_t
 *
 * Used for maintaining clutch bucket used and blocked time. The
 * values are used for calculating the interactivity score for the
 * clutch bucket.
 */
#define CLUTCH_CPU_DATA_MAX             (UINT64_MAX)
typedef uint64_t                        clutch_cpu_data_t;
typedef unsigned __int128               clutch_cpu_data_wide_t;

typedef union sched_clutch_bucket_cpu_data {
	struct {
		/* Clutch bucket CPU used across all threads */
		clutch_cpu_data_t       scbcd_cpu_used;
		/* Clutch bucket voluntary blocked time */
		clutch_cpu_data_t       scbcd_cpu_blocked;
	} cpu_data;
	clutch_cpu_data_wide_t          scbcd_cpu_data_packed;
} sched_clutch_bucket_cpu_data_t;

/*
 * struct sched_clutch_bucket
 *
 * A sched_clutch_bucket represents the set of threads for a thread
 * group at a particular scheduling bucket in a specific cluster.
 * It maintains information about the CPU usage & blocking behavior
 * of all threads part of the clutch_bucket. It inherits the timeshare
 * values from the clutch_bucket_group for decay and timesharing among
 * threads in the clutch.
 *
 * Since the clutch bucket is a per thread group per-QoS entity it is
 * important to keep its size small and the structure well aligned.
 */
struct sched_clutch_bucket {
#if CONFIG_SCHED_EDGE
	/* (P) preferred pset id when the clutch_bucket was enqueued */
	pset_id_t                       scb_preferred_pset_when_enqueued;
#endif /* CONFIG_SCHED_EDGE */
	/* (I) bucket for the clutch_bucket */
	uint8_t                         scb_bucket;
	/* (P) priority of the clutch bucket */
	uint8_t                         scb_priority;
	/* (P) number of threads in this clutch_bucket; should match runq.count */
	uint16_t                        scb_thr_count;

	/* Pointer to the clutch bucket group this clutch bucket belongs to */
	struct sched_clutch_bucket_group *scb_group;
	/* (P) pointer to the root of the hierarchy this bucket is in */
	struct sched_clutch_root        *scb_root;
	/* (P) priority queue of threads based on their promoted/base priority */
	struct priority_queue_sched_max scb_clutchpri_prioq;
	/* (P) runq of threads in clutch_bucket */
	struct priority_queue_sched_stable_max scb_thread_runq;

	/* (P) linkage for all clutch_buckets in a root bucket; used for tick operations */
	queue_chain_t                   scb_listlink;
	/* (P) linkage for clutch_bucket in root_bucket runqueue */
	queue_chain_t                   scb_runqlink;
	/* (P) queue of threads for timesharing purposes */
	queue_head_t                    scb_thread_timeshare_queue;
#if CONFIG_SCHED_EDGE
	/* (P) linkage for clutch_bucket in its steal_queue */
	struct priority_queue_entry_sched     scb_stealqlink;
#endif /* CONFIG_SCHED_EDGE */
};
typedef struct sched_clutch_bucket *sched_clutch_bucket_t;

/*
 * sched_clutch_counter_time_t
 *
 * Holds thread counts and a timestamp (typically for a clutch bucket group).
 * Used to allow atomic updates to these fields.
 */
typedef union sched_clutch_counter_time {
	struct {
		uint64_t                scct_count;
		uint64_t                scct_timestamp;
	};
	unsigned __int128               scct_packed;
} __attribute__((aligned(16))) sched_clutch_counter_time_t;

/*
 * struct sched_clutch_bucket_group
 *
 * It represents all the threads for a thread group at a particular
 * QoS/Scheduling bucket. This structure also maintains the timesharing
 * properties that are used for decay calculation for all threads in the
 * thread group at the specific scheduling bucket.
 */
struct sched_clutch_bucket_group {
	/* (I) bucket for the clutch_bucket_group */
	uint8_t                         scbg_bucket;
	/* (A) sched tick when the clutch bucket group load/shifts were updated */
	uint32_t _Atomic                scbg_timeshare_tick;
	/* (A) priority shifts for threads in the clutch_bucket_group */
	uint32_t _Atomic                scbg_pri_shift;
	/* (A) preferred pset ID for clutch bucket */
	pset_id_t _Atomic               scbg_preferred_pset;
	/* (I) clutch to which this clutch bucket_group belongs */
	struct sched_clutch             *scbg_clutch;
	/* (A) holds blocked timestamp and runnable/running count */
	sched_clutch_counter_time_t     scbg_blocked_data;
	/* (P/A depending on scheduler) holds pending timestamp and thread count */
	sched_clutch_counter_time_t     scbg_pending_data;
	/* (P/A depending on scheduler) holds interactivity timestamp and score */
	sched_clutch_counter_time_t     scbg_interactivity_data;
	/* (A) CPU usage information for the clutch bucket group */
	sched_clutch_bucket_cpu_data_t  scbg_cpu_data;
	/* Storage for all clutch buckets for a thread group at scbg_bucket */
	struct sched_clutch_bucket      *scbg_clutch_buckets;
};
typedef struct sched_clutch_bucket_group *sched_clutch_bucket_group_t;


/*
 * struct sched_clutch
 *
 * A sched_clutch is a 1:1 mapping to a thread group. It maintains the
 * storage for all clutch buckets for this thread group and some properties
 * of the thread group (such as flags etc.)
 */
struct sched_clutch {
	/*
	 * (A) number of runnable threads in sched_clutch; needs to be atomic
	 * to support cross cluster sched_clutch migrations.
	 */
	uint16_t _Atomic                sc_thr_count;
	/*
	 * Grouping specific parameters. Currently the implementation only
	 * supports thread_group based grouping.
	 */
	union {
		/* (I) Pointer to thread group */
		struct thread_group     *sc_tg;
	};
	/* (I) storage for all clutch_buckets for this clutch */
	struct sched_clutch_bucket_group sc_clutch_groups[TH_BUCKET_SCHED_MAX];
};
typedef struct sched_clutch *sched_clutch_t;


/* Clutch lifecycle management */
void sched_clutch_init_with_thread_group(sched_clutch_t, struct thread_group *);
void sched_clutch_destroy(sched_clutch_t);

/* Clutch thread membership management */
void sched_clutch_thread_clutch_update(thread_t, sched_clutch_t, sched_clutch_t);
pset_id_t sched_edge_thread_preferred_pset(thread_t);

/* Clutch timesharing stats management */
uint32_t sched_clutch_thread_run_bucket_incr(thread_t, sched_bucket_t);
uint32_t sched_clutch_thread_run_bucket_decr(thread_t, sched_bucket_t);
void sched_clutch_cpu_usage_update(thread_t, uint64_t);
uint32_t sched_clutch_thread_pri_shift(thread_t, sched_bucket_t);

/* Clutch properties accessors */
uint32_t sched_clutch_root_count(sched_clutch_root_t);

/* Grouping specific external routines */
extern sched_clutch_t sched_clutch_for_thread(thread_t);
extern sched_clutch_t sched_clutch_for_thread_group(struct thread_group *);

#if DEVELOPMENT || DEBUG

extern kern_return_t sched_clutch_thread_group_cpu_time_for_thread(thread_t thread, int sched_bucket, uint64_t *cpu_stats);

#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_SCHED_EDGE

/*
 * Getter and Setter for Edge configuration. Used by CLPC to affect thread migration behavior.
 */
void sched_edge_matrix_get(sched_clutch_edge *edge_matrix, bool *edge_request_bitmap, uint64_t flags, uint64_t num_psets);
void sched_edge_matrix_set(sched_clutch_edge *edge_matrix, bool *edge_changes_bitmap, uint64_t flags, uint64_t num_psets);
void sched_edge_tg_preferred_pset_change(struct thread_group *tg, pset_id_t tg_bucket_preferred_pset[TH_BUCKET_SCHED_MAX], sched_perfcontrol_preferred_cluster_options_t options);

/*
 * Iterate through the entire edge matrix by src pset, dst pset, and scheduling
 * bucket (dimension: num_psets X num_psets X TH_BUCKET_SCHED_MAX)
 */
#define sched_edge_matrix_iterate(src_id, dst_id, bucket, ...) \
	for (pset_id_t src_id = 0; src_id < sched_num_psets; src_id++) { \
	    for (pset_id_t dst_id = 0; dst_id < sched_num_psets; dst_id++) { \
	        for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) { \
	            __VA_ARGS__; \
	        } \
	    } \
	}

uint16_t sched_edge_pset_cumulative_count(sched_clutch_root_t root_clutch, sched_bucket_t bucket);
uint16_t sched_edge_shared_rsrc_runnable_load(sched_clutch_root_t root_clutch, cluster_shared_rsrc_type_t load_type);

/*
 * sched_edge_search_order_weight_then_locality_cmp()
 *
 * Search order that prioritizes outgoing edges with a lower
 * migration weight, then breaks ties with die-locality followed
 * by least pset id.
 */
extern int (*sched_edge_search_order_weight_then_locality_cmp)(const void *a, const void *b);

/*
 * Used to keep stir-the-pot state up-to-date for the current
 * processor, as new threads come on-core.
 */
extern void sched_edge_stir_the_pot_update_registry_state(thread_t thread, bool thread_is_new);
extern void sched_edge_stir_the_pot_clear_registry_entry(void);

extern void sched_edge_update_running_foreign_state(processor_t processor, thread_t thread);

#endif /* CONFIG_SCHED_EDGE */

#endif /* CONFIG_SCHED_CLUTCH */

#endif /* _KERN_SCHED_CLUTCH_H_ */
