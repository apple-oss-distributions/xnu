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

#if !SCHED_TEST_HARNESS

#include <kern/debug.h>
#include <kern/kern_types.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/queue.h>
#include <kern/sched_clutch.h>
#include <kern/sched_common.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <mach/mach_types.h>
#include <mach/machine.h>

#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <machine/machine_routines.h>
#include <machine/sched_param.h>

#include <sys/kdebug.h>

#endif /* !SCHED_TEST_HARNESS */

#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/sched_rt.h>

#if CONFIG_SCHED_EDGE
#include <kern/sched_amp_common.h>
#endif /* CONFIG_SCHED_EDGE */

#if CONFIG_SCHED_CLUTCH

#if CONFIG_SCHED_SMT
#error "The clutch scheduler does not support CONFIG_SCHED_SMT."
#endif /* CONFIG_SCHED_SMT */

#define SCHED_CLUTCH_DBG_THREAD_SELECT_PACKED_VERSION 1
typedef union {
	struct __attribute__((packed)) {
		unsigned int version                            : 4;
		unsigned int traverse_mode                      : 3;
		unsigned int pset_id                            : 6;
		unsigned int selection_was_edf                  : 1;
		unsigned int selection_was_pset_bound           : 1;
		unsigned int selection_opened_starvation_avoidance_window  : 1;
		unsigned int selection_opened_warp_window       : 1;
		unsigned int starvation_avoidance_window_close  : 12;
		unsigned int warp_window_close                  : 12;
		unsigned int reserved                           : 23;  /* For future usage */
	} trace_data;
	uint64_t scdts_trace_data_packed;
} sched_clutch_dbg_thread_select_packed_t;

static_assert(TH_BUCKET_SCHED_MAX == 6, "Ensure layout of sched_clutch_dbg_thread_select_packed can fit root bucket bitmasks");
static_assert(sizeof(sched_clutch_dbg_thread_select_packed_t) <= sizeof(uint64_t), "Ensure sched_clutch_dbg_thread_select_packed_t can fit in one tracepoint argument");

/* Forward declarations of static routines */

/* Root level hierarchy management */
static void sched_clutch_root_init(sched_clutch_root_t, processor_set_t);
static void sched_clutch_root_bucket_init(sched_clutch_root_bucket_t, sched_bucket_t, bool);
static void sched_clutch_root_pri_update(sched_clutch_root_t);
static void sched_clutch_root_urgency_inc(sched_clutch_root_t, thread_t);
static void sched_clutch_root_urgency_dec(sched_clutch_root_t, thread_t);

__enum_decl(sched_clutch_highest_root_bucket_type_t, uint32_t, {
	SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_NONE           = 0,
	SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY   = 1,
	SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL            = 2,
});
__enum_decl(sched_clutch_traverse_mode_t, uint32_t, {
	SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY   = 0,
	SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT = 1,
	SCHED_CLUTCH_TRAVERSE_CHECK_PREEMPT           = 2,
});
static_assert(SCHED_CLUTCH_TRAVERSE_CHECK_PREEMPT < (1 << 3), "Ensure traverse mode can be encoded within 3 bits of sched_clutch_dbg_thread_select_packed_t");
static sched_clutch_root_bucket_t sched_clutch_root_highest_root_bucket(sched_clutch_root_t, uint64_t, sched_clutch_highest_root_bucket_type_t, sched_clutch_root_bucket_t, thread_t, bool *, sched_clutch_traverse_mode_t, sched_clutch_dbg_thread_select_packed_t *);

/* Root bucket level hierarchy management */
static uint64_t sched_clutch_root_bucket_deadline_calculate(sched_clutch_root_bucket_t, uint64_t);
static void sched_clutch_root_bucket_deadline_update(sched_clutch_root_bucket_t, sched_clutch_root_t, uint64_t, bool);
static int sched_clutch_root_highest_runnable_qos(sched_clutch_root_t, sched_clutch_highest_root_bucket_type_t);

/* Options for clutch bucket ordering in the runq */
__options_decl(sched_clutch_bucket_options_t, uint32_t, {
	SCHED_CLUTCH_BUCKET_OPTIONS_NONE        = 0x0,
	/* Round robin clutch bucket on thread removal */
	SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR  = 0x1,
	/* Insert clutch bucket at head (for thread preemption) */
	SCHED_CLUTCH_BUCKET_OPTIONS_HEADQ       = 0x2,
	/* Insert clutch bucket at tail (default) */
	SCHED_CLUTCH_BUCKET_OPTIONS_TAILQ       = 0x4,
});

/* Clutch bucket level hierarchy management */
static void sched_clutch_bucket_hierarchy_insert(sched_clutch_root_t, sched_clutch_bucket_t, sched_bucket_t, uint64_t, sched_clutch_bucket_options_t);
static void sched_clutch_bucket_hierarchy_remove(sched_clutch_root_t, sched_clutch_bucket_t, sched_bucket_t, uint64_t, sched_clutch_bucket_options_t);
static boolean_t sched_clutch_bucket_runnable(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t, sched_clutch_bucket_options_t);
static boolean_t sched_clutch_bucket_update(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t, sched_clutch_bucket_options_t);
static void sched_clutch_bucket_empty(sched_clutch_bucket_t, sched_clutch_root_t, uint64_t, sched_clutch_bucket_options_t);
static uint8_t sched_clutch_bucket_pri_calculate(sched_clutch_bucket_t, uint64_t);

/* Clutch bucket group level properties management */
static void sched_clutch_bucket_group_cpu_usage_update(sched_clutch_bucket_group_t, uint64_t);
static void sched_clutch_bucket_group_cpu_adjust(sched_clutch_bucket_group_t, uint8_t);
static void sched_clutch_bucket_group_pri_shift_update(sched_clutch_bucket_group_t);
static uint8_t sched_clutch_bucket_group_pending_ageout(sched_clutch_bucket_group_t, uint64_t);
static uint32_t sched_clutch_bucket_group_run_count_inc(sched_clutch_bucket_group_t);
static uint32_t sched_clutch_bucket_group_run_count_dec(sched_clutch_bucket_group_t);
static uint8_t sched_clutch_bucket_group_interactivity_score_calculate(sched_clutch_bucket_group_t, uint64_t);

/* Clutch timeshare properties updates */
static uint32_t sched_clutch_run_bucket_incr(sched_clutch_t, sched_bucket_t);
static uint32_t sched_clutch_run_bucket_decr(sched_clutch_t, sched_bucket_t);

/* Clutch membership management */
static boolean_t sched_clutch_thread_insert(sched_clutch_root_t, thread_t, integer_t);
static void sched_clutch_thread_remove(sched_clutch_root_t, thread_t, uint64_t, sched_clutch_bucket_options_t);
static thread_t sched_clutch_hierarchy_thread_highest(sched_clutch_root_t, processor_t, thread_t, sched_clutch_traverse_mode_t);

/* Clutch properties updates */
static uint32_t sched_clutch_root_urgency(sched_clutch_root_t);
static uint32_t sched_clutch_root_count_sum(sched_clutch_root_t);
static int sched_clutch_root_priority(sched_clutch_root_t);
static sched_clutch_bucket_t sched_clutch_root_bucket_highest_clutch_bucket(sched_clutch_root_t, sched_clutch_root_bucket_t, processor_t _Nullable processor, thread_t _Nullable prev_thread, bool *_Nullable chose_prev_thread);

/* Clutch thread properties */
static boolean_t sched_thread_sched_pri_promoted(thread_t);
static inline sched_clutch_bucket_t sched_clutch_bucket_for_thread(sched_clutch_root_t, thread_t);
static inline sched_clutch_bucket_group_t sched_clutch_bucket_group_for_thread(thread_t);

/* General utilities */
static inline bool sched_clutch_pri_greater_than_tiebreak(int, int, bool);

#if CONFIG_SCHED_EDGE
/* System based routines */
static bool sched_edge_pset_peek_steal_possible(processor_set_t, processor_set_t, bitmap_t);
static pset_id_t sched_edge_thread_bound_pset_id(thread_t);
#endif /* CONFIG_SCHED_EDGE */

/* Helper debugging routines */
static inline void sched_clutch_hierarchy_locked_assert(sched_clutch_root_t);

/*
 * Special markers for buckets that have invalid WCELs/quantums etc.
 */
#define SCHED_CLUTCH_INVALID_TIME_32 ((uint32_t)~0)
#define SCHED_CLUTCH_INVALID_TIME_64 ((uint64_t)~0)

/*
 * Root level bucket WCELs
 *
 * The root level bucket selection algorithm is an Earliest Deadline
 * First (EDF) algorithm where the deadline for buckets are defined
 * by the worst-case-execution-latency and the make runnable timestamp
 * for the bucket.
 *
 */
static uint32_t sched_clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX] = {
	SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
	0,                                              /* FG */
	37500,                                          /* IN (37.5ms) */
	75000,                                          /* DF (75ms) */
	150000,                                         /* UT (150ms) */
	250000                                          /* BG (250ms) */
};
static uint64_t sched_clutch_root_bucket_wcel[TH_BUCKET_SCHED_MAX] = {0};

/*
 * Root level bucket warp
 *
 * Each root level bucket has a warp value associated with it as well.
 * The warp value allows the root bucket to effectively warp ahead of
 * lower priority buckets for a limited time even if it has a later
 * deadline. The warping behavior provides extra (but limited)
 * opportunity for high priority buckets to remain responsive.
 */

/* Special warp deadline value to indicate that the bucket has not used any warp yet */
#define SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED    (SCHED_CLUTCH_INVALID_TIME_64)

/* Warp window durations for various tiers */
static uint32_t sched_clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX] = {
	SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
	8000,                                           /* FG (8ms)*/
	4000,                                           /* IN (4ms) */
	2000,                                           /* DF (2ms) */
	1000,                                           /* UT (1ms) */
	0                                               /* BG (0ms) */
};
static uint64_t sched_clutch_root_bucket_warp[TH_BUCKET_SCHED_MAX] = {0};

/*
 * Thread level quantum
 *
 * The algorithm defines quantums for threads at various buckets. This
 * (combined with the root level bucket quantums) restricts how much
 * the lower priority levels can preempt the higher priority threads.
 */

#if XNU_TARGET_OS_OSX
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
	10000,                                          /* FIXPRI (10ms) */
	10000,                                          /* FG (10ms) */
	10000,                                          /* IN (10ms) */
	10000,                                          /* DF (10ms) */
	4000,                                           /* UT (4ms) */
	2000                                            /* BG (2ms) */
};
#else /* XNU_TARGET_OS_OSX */
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
	10000,                                          /* FIXPRI (10ms) */
	10000,                                          /* FG (10ms) */
	8000,                                           /* IN (8ms) */
	6000,                                           /* DF (6ms) */
	4000,                                           /* UT (4ms) */
	2000                                            /* BG (2ms) */
};
#endif /* XNU_TARGET_OS_OSX */

static uint64_t sched_clutch_thread_quantum[TH_BUCKET_SCHED_MAX] = {0};

/*
 * sched_clutch_us_to_abstime()
 *
 * Initializer for converting all durations in usec to abstime
 */
static void
sched_clutch_us_to_abstime(uint32_t *us_vals, uint64_t *abstime_vals)
{
	for (int i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		if (us_vals[i] == SCHED_CLUTCH_INVALID_TIME_32) {
			abstime_vals[i] = SCHED_CLUTCH_INVALID_TIME_64;
		} else {
			clock_interval_to_absolutetime_interval(us_vals[i],
			    NSEC_PER_USEC, &abstime_vals[i]);
		}
	}
}

/* Clutch/Edge Scheduler Debugging support */
#define SCHED_CLUTCH_DBG_THR_COUNT_PACK(a, b, c)        ((uint64_t)c | ((uint64_t)b << 16) | ((uint64_t)a << 32))

#if DEVELOPMENT || DEBUG

kern_return_t
sched_clutch_thread_group_cpu_time_for_thread(thread_t thread, int sched_bucket, uint64_t *cpu_stats)
{
	if (sched_bucket < 0 || sched_bucket >= TH_BUCKET_MAX) {
		return KERN_INVALID_ARGUMENT;
	}
	sched_clutch_bucket_group_t clutch_bucket_group = &sched_clutch_for_thread(thread)->sc_clutch_groups[sched_bucket];
	sched_clutch_bucket_cpu_data_t scb_cpu_data;
	scb_cpu_data.scbcd_cpu_data_packed = os_atomic_load_wide(&clutch_bucket_group->scbg_cpu_data.scbcd_cpu_data_packed, relaxed);
	cpu_stats[0] = scb_cpu_data.cpu_data.scbcd_cpu_used;
	cpu_stats[1] = scb_cpu_data.cpu_data.scbcd_cpu_blocked;
	return KERN_SUCCESS;
}

/*
 * sched_clutch_hierarchy_locked_assert()
 *
 * Debugging helper routine. Asserts that the hierarchy is locked. The locking
 * for the hierarchy depends on where the hierarchy is hooked. The current
 * implementation hooks the hierarchy at the pset, so the hierarchy is locked
 * using the pset lock.
 */
static inline void
sched_clutch_hierarchy_locked_assert(
	sched_clutch_root_t root_clutch)
{
	pset_assert_locked(root_clutch->scr_pset);
}

#else /* DEVELOPMENT || DEBUG */

static inline void
sched_clutch_hierarchy_locked_assert(
	__unused sched_clutch_root_t root_clutch)
{
}

#endif /* DEVELOPMENT || DEBUG */

/*
 * sched_clutch_thr_count_inc()
 *
 * Increment thread count at a hierarchy level with overflow checks.
 */
static void
sched_clutch_thr_count_inc(
	uint16_t *thr_count)
{
	if (__improbable(os_inc_overflow(thr_count))) {
		panic("sched_clutch thread count overflowed!");
	}
}

/*
 * sched_clutch_thr_count_dec()
 *
 * Decrement thread count at a hierarchy level with underflow checks.
 */
static void
sched_clutch_thr_count_dec(
	uint16_t *thr_count)
{
	if (__improbable(os_dec_overflow(thr_count))) {
		panic("sched_clutch thread count underflowed!");
	}
}

static sched_bucket_t
sched_convert_pri_to_bucket(uint8_t priority)
{
	sched_bucket_t bucket = TH_BUCKET_RUN;

	if (priority > BASEPRI_USER_INITIATED) {
		bucket = TH_BUCKET_SHARE_FG;
	} else if (priority > BASEPRI_DEFAULT) {
		bucket = TH_BUCKET_SHARE_IN;
	} else if (priority > BASEPRI_UTILITY) {
		bucket = TH_BUCKET_SHARE_DF;
	} else if (priority > MAXPRI_THROTTLE) {
		bucket = TH_BUCKET_SHARE_UT;
	} else {
		bucket = TH_BUCKET_SHARE_BG;
	}
	return bucket;
}

/*
 * sched_clutch_thread_bucket_map()
 *
 * Map a thread to a scheduling bucket for the clutch/edge scheduler
 * based on its scheduling mode and the priority attribute passed in.
 */
static sched_bucket_t
sched_clutch_thread_bucket_map(thread_t thread, int pri)
{
	switch (thread->sched_mode) {
	case TH_MODE_FIXED:
		if (pri >= BASEPRI_FOREGROUND) {
			return TH_BUCKET_FIXPRI;
		} else {
			return sched_convert_pri_to_bucket(pri);
		}

	case TH_MODE_REALTIME:
		return TH_BUCKET_FIXPRI;

	case TH_MODE_TIMESHARE:
		return sched_convert_pri_to_bucket(pri);

	default:
		panic("unexpected mode: %d", thread->sched_mode);
		break;
	}
}

/*
 * The clutch scheduler attempts to ageout the CPU usage of clutch bucket groups
 * based on the amount of time they have been pending and the load at that
 * scheduling bucket level. Since the clutch bucket groups are global (i.e. span
 * multiple clusters, its important to keep the load also as a global counter.
 */
static uint32_t _Atomic sched_clutch_global_bucket_load[TH_BUCKET_SCHED_MAX];

/*
 * sched_clutch_root_init()
 *
 * Routine to initialize the scheduler hierarchy root.
 */
static void
sched_clutch_root_init(
	sched_clutch_root_t root_clutch,
	processor_set_t pset)
{
	root_clutch->scr_thr_count = 0;
	root_clutch->scr_priority = NOPRI;
	root_clutch->scr_urgency = 0;
	root_clutch->scr_pset = pset;
#if CONFIG_SCHED_EDGE
	root_clutch->scr_pset_id = pset->pset_id;
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		root_clutch->scr_shared_rsrc_load_runnable[shared_rsrc_type] = 0;
	}
	/* Initialize the silos for tracking steal eligibility */
	bitmap_zero((bitmap_t *)root_clutch->scr_populated_steal_silos, MAX_PSETS);
	for (pset_id_t p = 0; p < MAX_PSETS; p++) {
		bitmap_zero((bitmap_t *)root_clutch->scr_steal_silos[p].sess_populated_steal_queues, TH_BUCKET_SCHED_MAX);
		for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
			priority_queue_init(&root_clutch->scr_steal_silos[p].sess_steal_queues[bucket]);
		}
	}
#else /* CONFIG_SCHED_EDGE */
	root_clutch->scr_pset_id = 0;
#endif /* CONFIG_SCHED_EDGE */

	/* Initialize the queue which maintains all runnable clutch_buckets for timesharing purposes */
	queue_init(&root_clutch->scr_clutch_buckets);

	bzero(&root_clutch->scr_cumulative_run_count, sizeof(root_clutch->scr_cumulative_run_count));
	bitmap_zero(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	bitmap_zero(root_clutch->scr_bound_warp_available, TH_BUCKET_SCHED_MAX);
	priority_queue_init(&root_clutch->scr_bound_root_buckets);

	/* Initialize the bitmap and priority queue of runnable root buckets */
	priority_queue_init(&root_clutch->scr_unbound_root_buckets);
	bitmap_zero(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	bitmap_zero(root_clutch->scr_unbound_warp_available, TH_BUCKET_SCHED_MAX);

	/* Initialize all the root buckets */
	for (uint32_t i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		sched_clutch_root_bucket_init(&root_clutch->scr_unbound_buckets[i], i, false);
		sched_clutch_root_bucket_init(&root_clutch->scr_bound_buckets[i], i, true);
	}
}

/*
 * Clutch Bucket Runqueues
 *
 * The clutch buckets are maintained in a runq at the root bucket level. The
 * runq organization allows clutch buckets to be ordered based on various
 * factors such as:
 *
 * - Clutch buckets are round robin'ed at the same priority level when a
 *   thread is selected from a clutch bucket. This prevents a clutch bucket
 *   from starving out other clutch buckets at the same priority.
 *
 * - Clutch buckets are inserted at the head when it becomes runnable due to
 *   thread preemption. This allows threads that were preempted to maintain
 *   their order in the queue.
 */

/*
 * sched_clutch_bucket_runq_init()
 *
 * Initialize a clutch bucket runq.
 */
static void
sched_clutch_bucket_runq_init(
	sched_clutch_bucket_runq_t clutch_buckets_rq)
{
	clutch_buckets_rq->scbrq_highq = NOPRI;
	for (uint8_t i = 0; i < BITMAP_LEN(NRQS); i++) {
		clutch_buckets_rq->scbrq_bitmap[i] = 0;
	}
	clutch_buckets_rq->scbrq_count = 0;
	for (int i = 0; i < NRQS; i++) {
		circle_queue_init(&clutch_buckets_rq->scbrq_queues[i]);
	}
}

/*
 * sched_clutch_bucket_runq_empty()
 *
 * Returns if a clutch bucket runq is empty.
 */
static boolean_t
sched_clutch_bucket_runq_empty(
	sched_clutch_bucket_runq_t clutch_buckets_rq)
{
	return clutch_buckets_rq->scbrq_count == 0;
}

/*
 * sched_clutch_bucket_runq_peek()
 *
 * Returns the highest priority clutch bucket in the runq.
 */
static sched_clutch_bucket_t
sched_clutch_bucket_runq_peek(
	sched_clutch_bucket_runq_t clutch_buckets_rq)
{
	if (clutch_buckets_rq->scbrq_count > 0) {
		circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_buckets_rq->scbrq_highq];
		return cqe_queue_first(queue, struct sched_clutch_bucket, scb_runqlink);
	} else {
		return NULL;
	}
}

/*
 * sched_clutch_bucket_runq_enqueue()
 *
 * Enqueue a clutch bucket into the runq based on the options passed in.
 */
static void
sched_clutch_bucket_runq_enqueue(
	sched_clutch_bucket_runq_t clutch_buckets_rq,
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_bucket_options_t options)
{
	circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_bucket->scb_priority];
	if (circle_queue_empty(queue)) {
		circle_enqueue_tail(queue, &clutch_bucket->scb_runqlink);
		bitmap_set(clutch_buckets_rq->scbrq_bitmap, clutch_bucket->scb_priority);
		if (clutch_bucket->scb_priority > clutch_buckets_rq->scbrq_highq) {
			clutch_buckets_rq->scbrq_highq = clutch_bucket->scb_priority;
		}
	} else {
		if (options & SCHED_CLUTCH_BUCKET_OPTIONS_HEADQ) {
			circle_enqueue_head(queue, &clutch_bucket->scb_runqlink);
		} else {
			/*
			 * Default behavior (handles SCHED_CLUTCH_BUCKET_OPTIONS_TAILQ &
			 * SCHED_CLUTCH_BUCKET_OPTIONS_NONE)
			 */
			circle_enqueue_tail(queue, &clutch_bucket->scb_runqlink);
		}
	}
	clutch_buckets_rq->scbrq_count++;
}

/*
 * sched_clutch_bucket_runq_remove()
 *
 * Remove a clutch bucket from the runq.
 */
static void
sched_clutch_bucket_runq_remove(
	sched_clutch_bucket_runq_t clutch_buckets_rq,
	sched_clutch_bucket_t clutch_bucket)
{
	circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_bucket->scb_priority];
	circle_dequeue(queue, &clutch_bucket->scb_runqlink);
	assert(clutch_buckets_rq->scbrq_count > 0);
	clutch_buckets_rq->scbrq_count--;
	if (circle_queue_empty(queue)) {
		bitmap_clear(clutch_buckets_rq->scbrq_bitmap, clutch_bucket->scb_priority);
		clutch_buckets_rq->scbrq_highq = bitmap_first(clutch_buckets_rq->scbrq_bitmap, NRQS);
	}
}

static void
sched_clutch_bucket_runq_rotate(
	sched_clutch_bucket_runq_t clutch_buckets_rq,
	sched_clutch_bucket_t clutch_bucket)
{
	circle_queue_t queue = &clutch_buckets_rq->scbrq_queues[clutch_bucket->scb_priority];
	assert(clutch_bucket == cqe_queue_first(queue, struct sched_clutch_bucket, scb_runqlink));
	circle_queue_rotate_head_forward(queue);
}

/*
 * sched_clutch_root_bucket_init()
 *
 * Routine to initialize root buckets.
 */
static void
sched_clutch_root_bucket_init(
	sched_clutch_root_bucket_t root_bucket,
	sched_bucket_t bucket,
	bool bound_root_bucket)
{
	root_bucket->scrb_bucket = bucket;
	if (bound_root_bucket) {
		/* For bound root buckets, initialize the bound thread runq. */
		root_bucket->scrb_bound = true;
		run_queue_init(&root_bucket->scrb_bound_thread_runq);
	} else {
		/*
		 * The unbounded root buckets contain a runq of runnable clutch buckets
		 * which then hold the runnable threads.
		 */
		root_bucket->scrb_bound = false;
		sched_clutch_bucket_runq_init(&root_bucket->scrb_clutch_buckets);
	}
	priority_queue_entry_init(&root_bucket->scrb_pqlink);
	root_bucket->scrb_pqlink.deadline = 0;
	root_bucket->scrb_warped_deadline = SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED;
	root_bucket->scrb_warp_remaining = sched_clutch_root_bucket_warp[root_bucket->scrb_bucket];
	root_bucket->scrb_starvation_avoidance = false;
	root_bucket->scrb_starvation_ts = 0;
}

/*
 * Special case scheduling for Above UI bucket.
 *
 * AboveUI threads are typically system critical threads that need low latency
 * which is why they are handled specially.
 *
 * Since the priority range for AboveUI and FG Timeshare buckets overlap, it is
 * important to maintain some native priority order between those buckets. For unbounded
 * root buckets, the policy is to compare the highest clutch buckets of both buckets; if the
 * Above UI bucket is higher, schedule it immediately. Otherwise fall through to the
 * deadline based scheduling which should pickup the timeshare buckets. For the bound
 * case, the policy simply compares the priority of the highest runnable threads in
 * the above UI and timeshare buckets.
 *
 * The implementation allows extremely low latency CPU access for Above UI threads
 * while supporting the use case of high priority timeshare threads contending with
 * lower priority fixed priority threads.
 */


/*
 * sched_clutch_root_unbound_select_aboveui()
 *
 * Routine to determine if the above UI unbounded bucket should be selected for execution.
 *
 * Writes the highest unbound (timeshare FG vs. above UI) bucket, its priority, and whether
 * it is an above UI bucket into the pointer parameters.
 */
static void
sched_clutch_root_unbound_select_aboveui(
	sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t *highest_bucket,
	int *highest_pri,
	bool *highest_is_aboveui,
	sched_clutch_root_bucket_t _Nullable prev_bucket,
	thread_t _Nullable prev_thread)
{
	/* First determine the highest Clutch bucket */
	sched_clutch_root_bucket_t higher_root_bucket = NULL;
	sched_clutch_bucket_t higher_clutch_bucket = NULL;
	int higher_bucket_sched_pri = -1;
	bool higher_is_aboveui = false;
	/* Consider unbound Above UI */
	if (bitmap_test(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_FIXPRI)) {
		higher_root_bucket = &root_clutch->scr_unbound_buckets[TH_BUCKET_FIXPRI];
		higher_clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_clutch, higher_root_bucket, NULL, NULL, NULL);
		higher_bucket_sched_pri = priority_queue_max_sched_pri(&higher_clutch_bucket->scb_clutchpri_prioq);
		higher_is_aboveui = true;
	}
	/* Consider unbound Timeshare FG */
	if (bitmap_test(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SHARE_FG)) {
		sched_clutch_root_bucket_t root_bucket_sharefg = &root_clutch->scr_unbound_buckets[TH_BUCKET_SHARE_FG];
		sched_clutch_bucket_t clutch_bucket_sharefg = sched_clutch_root_bucket_highest_clutch_bucket(root_clutch, root_bucket_sharefg, NULL, NULL, NULL);
		/* Strict greater-than because unbound timeshare FG root bucket loses all priority ties at this level */
		if (higher_root_bucket == NULL || clutch_bucket_sharefg->scb_priority > higher_clutch_bucket->scb_priority) {
			higher_root_bucket = root_bucket_sharefg;
			higher_clutch_bucket = clutch_bucket_sharefg;
			higher_bucket_sched_pri = priority_queue_max_sched_pri(&higher_clutch_bucket->scb_clutchpri_prioq);
			higher_is_aboveui = false;
		}
	}
	/* Consider the previous thread */
	if (prev_thread != NULL) {
		assert(prev_bucket->scrb_bound == false);
		sched_clutch_bucket_group_t prev_clutch_bucket_group = sched_clutch_bucket_group_for_thread(prev_thread);
		int prev_clutch_bucket_pri = prev_thread->sched_pri + (int)(os_atomic_load(&prev_clutch_bucket_group->scbg_interactivity_data.scct_count, relaxed));
		sched_clutch_bucket_t prev_clutch_bucket = sched_clutch_bucket_for_thread(root_clutch, prev_thread);
		bool prev_bucket_should_win_ties = prev_bucket->scrb_bucket == TH_BUCKET_FIXPRI && higher_is_aboveui == false;
		if (higher_clutch_bucket == NULL ||
		    sched_clutch_pri_greater_than_tiebreak(prev_clutch_bucket_pri, higher_clutch_bucket->scb_priority, prev_bucket_should_win_ties)) {
			higher_root_bucket = prev_bucket;
			higher_clutch_bucket = prev_clutch_bucket;
			higher_bucket_sched_pri = prev_thread->sched_pri;
			higher_is_aboveui = prev_bucket->scrb_bucket == TH_BUCKET_FIXPRI;
		}
	}
	/* Compare highest priority in the highest unbound Clutch bucket to highest priority seen from the bound buckets */
	if (higher_root_bucket != NULL) {
		bool unbound_should_win_ties = higher_is_aboveui == true && *highest_is_aboveui == false;
		if (sched_clutch_pri_greater_than_tiebreak(higher_bucket_sched_pri, *highest_pri, unbound_should_win_ties)) {
			*highest_pri = higher_bucket_sched_pri;
			*highest_bucket = higher_root_bucket;
			*highest_is_aboveui = higher_is_aboveui;
		}
	}
}

/*
 * sched_clutch_root_bound_select_aboveui()
 *
 * Routine to determine if the above UI bounded bucket should be selected for execution.
 *
 * Writes the highest bound (timeshare FG vs. above UI) bucket, its priority, and whether
 * it is an above UI bucket into the pointer parameters.
 */
static void
sched_clutch_root_bound_select_aboveui(
	sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t *highest_bucket,
	int *highest_pri,
	bool *highest_is_aboveui,
	sched_clutch_root_bucket_t _Nullable prev_bucket,
	thread_t _Nullable prev_thread)
{
	/* Consider bound Above UI */
	sched_clutch_root_bucket_t root_bucket_aboveui = &root_clutch->scr_bound_buckets[TH_BUCKET_FIXPRI];
	if (bitmap_test(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_FIXPRI) &&
	    sched_clutch_pri_greater_than_tiebreak(root_bucket_aboveui->scrb_bound_thread_runq.highq, *highest_pri, *highest_is_aboveui == false)) {
		*highest_pri = root_bucket_aboveui->scrb_bound_thread_runq.highq;
		*highest_bucket = root_bucket_aboveui;
		*highest_is_aboveui = true;
	}
	/* Consider bound Timeshare FG */
	sched_clutch_root_bucket_t root_bucket_sharefg = &root_clutch->scr_bound_buckets[TH_BUCKET_SHARE_FG];
	if (bitmap_test(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SHARE_FG) &&
	    sched_clutch_pri_greater_than_tiebreak(root_bucket_sharefg->scrb_bound_thread_runq.highq, *highest_pri, false)) {
		*highest_pri = root_bucket_sharefg->scrb_bound_thread_runq.highq;
		*highest_bucket = root_bucket_sharefg;
		*highest_is_aboveui = false;
	}
	/* Consider the previous thread */
	if (prev_thread != NULL) {
		assert(prev_bucket->scrb_bound == true);
		bool prev_bucket_should_win_ties = prev_bucket->scrb_bucket == TH_BUCKET_FIXPRI && *highest_is_aboveui == false;
		if (sched_clutch_pri_greater_than_tiebreak(prev_thread->sched_pri, *highest_pri, prev_bucket_should_win_ties)) {
			*highest_pri = prev_thread->sched_pri;
			*highest_bucket = prev_bucket;
			*highest_is_aboveui = prev_bucket->scrb_bucket == TH_BUCKET_FIXPRI;
		}
	}
}

/*
 * sched_clutch_root_highest_runnable_qos()
 *
 * Returns the index of the highest-QoS root bucket which is currently runnable.
 */
static int
sched_clutch_root_highest_runnable_qos(
	sched_clutch_root_t root_clutch,
	sched_clutch_highest_root_bucket_type_t type)
{
	int highest_unbound_bucket = bitmap_lsb_first(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY) {
		return highest_unbound_bucket;
	}
	assert(type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL);
	int highest_bound_bucket = bitmap_lsb_first(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX);
	if (highest_bound_bucket == -1) {
		return highest_unbound_bucket;
	}
	if (highest_unbound_bucket == -1) {
		return highest_bound_bucket;
	}
	/* Both bound and unbound buckets are runnable, return the higher QoS */
	return MIN(highest_bound_bucket, highest_unbound_bucket);
}

/*
 * sched_clutch_root_highest_aboveui_root_bucket()
 *
 * Routine to determine if an above UI root bucket should be selected for execution.
 *
 * Returns the root bucket if we should run an above UI bucket or NULL otherwise.
 */
static sched_clutch_root_bucket_t
sched_clutch_root_highest_aboveui_root_bucket(
	sched_clutch_root_t root_clutch,
	sched_clutch_highest_root_bucket_type_t type,
	sched_clutch_root_bucket_t _Nullable prev_bucket,
	thread_t _Nullable prev_thread,
	bool *chose_prev_thread)
{
	assert((prev_thread == NULL && prev_bucket == NULL) || (prev_thread != NULL && prev_bucket != NULL));
	assert((type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL) || (prev_bucket == NULL));

	sched_clutch_root_bucket_t highest_bucket = NULL;
	int highest_pri = -1;
	bool highest_is_aboveui = false;

	/* Forward previous thread to the correct comparison logic, based on boundness */
	sched_clutch_root_bucket_t bound_prev_bucket = NULL, unbound_prev_bucket = NULL;
	thread_t bound_prev_thread = NULL, unbound_prev_thread = NULL;
	if (prev_thread != NULL) {
		if (prev_bucket->scrb_bound) {
			bound_prev_bucket = prev_bucket;
			bound_prev_thread = prev_thread;
		} else {
			unbound_prev_bucket = prev_bucket;
			unbound_prev_thread = prev_thread;
		}
	}

	/* Consider bound Above UI vs. Timeshare FG first, so those buckets will win ties against the corresponding unbound buckets */
	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL) {
		sched_clutch_root_bound_select_aboveui(root_clutch, &highest_bucket, &highest_pri, &highest_is_aboveui, bound_prev_bucket, bound_prev_thread);
	}

	/* Consider unbound Above UI vs. Timeshare FG */
	sched_clutch_root_unbound_select_aboveui(root_clutch, &highest_bucket, &highest_pri, &highest_is_aboveui, unbound_prev_bucket, unbound_prev_thread);
	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY) {
		return highest_is_aboveui ? highest_bucket : NULL;
	}
	assert(type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL);

	/* Determine whether we already know to continue running the previous thread */
	if (prev_thread != NULL &&
	    bitmap_test(highest_bucket->scrb_bound ? root_clutch->scr_bound_runnable_bitmap : root_clutch->scr_unbound_runnable_bitmap, highest_bucket->scrb_bucket) == false) {
		/* Highest bucket we saw is empty, so the previous thread must have been the highest */
		assert(highest_bucket == prev_bucket);
		*chose_prev_thread = true;
	}

	return highest_is_aboveui ? highest_bucket : NULL;
}

/*
 * sched_clutch_root_highest_root_bucket()
 *
 * Main routine to find the highest runnable root level bucket.
 * This routine is called from performance sensitive contexts; so it is
 * crucial to keep this O(1). The options parameter determines if
 * the selection logic should look at unbounded threads only (for
 * cross-cluster stealing operations) or both bounded and unbounded
 * threads (for selecting next thread for execution on current cluster).
 */
static sched_clutch_root_bucket_t
sched_clutch_root_highest_root_bucket(
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	sched_clutch_highest_root_bucket_type_t type,
	sched_clutch_root_bucket_t _Nullable prev_bucket,
	thread_t _Nullable prev_thread,
	bool *chose_prev_thread,
	sched_clutch_traverse_mode_t mode,
	sched_clutch_dbg_thread_select_packed_t *debug_info)
{
	assert((prev_thread == NULL && prev_bucket == NULL) || (prev_thread != NULL && prev_bucket != NULL));
	assert(type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL || (prev_thread == NULL));
	assert(prev_thread == NULL || (mode != SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY));
	sched_clutch_hierarchy_locked_assert(root_clutch);

	int highest_runnable_bucket = sched_clutch_root_highest_runnable_qos(root_clutch, type);
	if (highest_runnable_bucket == -1) {
		/*
		 * The Clutch hierarchy has no runnable threads. We can continue running
		 * whatever was running previously.
		 */
		assert(sched_clutch_root_count(root_clutch) == 0 || type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY);
		*chose_prev_thread = true;
		if (prev_thread != NULL) {
			debug_info->trace_data.selection_was_edf = true;
		}
		return prev_bucket;
	}

	/* Consider Above UI threads, in comparison to Timeshare FG threads */
	sched_clutch_root_bucket_t highest_aboveui_bucket = sched_clutch_root_highest_aboveui_root_bucket(root_clutch, type, prev_bucket, prev_thread, chose_prev_thread);
	if (highest_aboveui_bucket != NULL) {
		debug_info->trace_data.selection_was_edf = true;
		return highest_aboveui_bucket;
	}

	/*
	 * Above UI bucket is not runnable or has a low priority runnable thread; use the
	 * earliest deadline model to schedule threads. The idea is that as the timeshare
	 * buckets use CPU, they will drop their interactivity score/sched priority and
	 * allow the low priority AboveUI buckets to be scheduled.
	 */

	/* Find the earliest deadline bucket */
	sched_clutch_root_bucket_t edf_bucket;
	bool edf_bucket_enqueued_normally;

evaluate_root_buckets:
	edf_bucket = NULL;
	edf_bucket_enqueued_normally = true;

	if (type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_UNBOUND_ONLY) {
		edf_bucket = priority_queue_min(&root_clutch->scr_unbound_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);
	} else {
		assert(type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL);
		sched_clutch_root_bucket_t unbound_bucket = priority_queue_min(&root_clutch->scr_unbound_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);
		sched_clutch_root_bucket_t bound_bucket = priority_queue_min(&root_clutch->scr_bound_root_buckets, struct sched_clutch_root_bucket, scrb_pqlink);
		if (bound_bucket && unbound_bucket) {
			/* If bound and unbound root buckets are runnable, select the one with the earlier deadline */
			edf_bucket = (bound_bucket->scrb_pqlink.deadline <= unbound_bucket->scrb_pqlink.deadline) ? bound_bucket : unbound_bucket;
		} else {
			edf_bucket = (bound_bucket) ? bound_bucket : unbound_bucket;
		}
	}
	if (edf_bucket == NULL) {
		/* The timeshare portion of the runqueue is empty */
		assert(type == SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL);
		assert(prev_thread != NULL);
		*chose_prev_thread = true;
		if (prev_thread != NULL) {
			debug_info->trace_data.selection_was_edf = true;
		}
		return prev_bucket;
	}
	if (prev_bucket != NULL && prev_bucket->scrb_pqlink.deadline < edf_bucket->scrb_pqlink.deadline) {
		/* The previous thread's root bucket has the earliest deadline and is not currently enqueued */
		edf_bucket = prev_bucket;
		edf_bucket_enqueued_normally = false;
	}

	if (edf_bucket->scrb_starvation_avoidance) {
		/* Check if the EDF bucket is in an expired starvation avoidance window */
		uint64_t starvation_window = sched_clutch_thread_quantum[edf_bucket->scrb_bucket];
		if (timestamp >= (edf_bucket->scrb_starvation_ts + starvation_window)) {
			/* Starvation avoidance window is over; update deadline and re-evaluate EDF */
			edf_bucket->scrb_starvation_avoidance = false;
			edf_bucket->scrb_starvation_ts = 0;
			sched_clutch_root_bucket_deadline_update(edf_bucket, root_clutch, timestamp, edf_bucket_enqueued_normally);
			bit_set(debug_info->trace_data.starvation_avoidance_window_close, edf_bucket->scrb_bound * TH_BUCKET_SCHED_MAX + edf_bucket->scrb_bucket);
			goto evaluate_root_buckets;
		}
	}

	/*
	 * Check if any of the buckets have warp available. The implementation only allows root buckets to warp ahead of
	 * buckets of the same type (i.e. bound/unbound). The reason for doing that is because warping is a concept that
	 * makes sense between root buckets of the same type since its effectively a scheduling advantage over a lower
	 * QoS root bucket.
	 */
	bitmap_t *warp_available_bitmap = (edf_bucket->scrb_bound) ? (root_clutch->scr_bound_warp_available) : (root_clutch->scr_unbound_warp_available);
	int warp_bucket_index = bitmap_lsb_first(warp_available_bitmap, TH_BUCKET_SCHED_MAX);

	/* Allow the prev_bucket to use its warp as well */
	bool prev_bucket_warping = (prev_bucket != NULL) && (prev_bucket->scrb_bound == edf_bucket->scrb_bound) &&
	    prev_bucket->scrb_bucket < edf_bucket->scrb_bucket && (prev_bucket->scrb_warp_remaining > 0) &&
	    (warp_bucket_index == -1 || prev_bucket->scrb_bucket < warp_bucket_index);

	bool non_edf_bucket_can_warp = (warp_bucket_index != -1 && warp_bucket_index < edf_bucket->scrb_bucket) || prev_bucket_warping;

	if (non_edf_bucket_can_warp == false) {
		/* No higher buckets have warp left; best choice is the EDF based bucket */
		debug_info->trace_data.selection_was_edf = true;

		bool should_update_edf_starvation_state = edf_bucket == prev_bucket || mode == SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY || mode == SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT;
		if (edf_bucket->scrb_starvation_avoidance == false && should_update_edf_starvation_state) {
			/* Looks like the EDF bucket is not in starvation avoidance mode; check if it should be */
			if (highest_runnable_bucket < edf_bucket->scrb_bucket || (prev_bucket != NULL && prev_bucket->scrb_bucket < edf_bucket->scrb_bucket)) {
				/*
				 * Since a higher bucket is runnable, it indicates that the EDF bucket should be in starvation avoidance.
				 *
				 * The starvation avoidance window is allocated as a single quantum for the starved bucket, enforced
				 * simultaneously across all CPUs in the cluster. The idea is to grant the starved bucket roughly one
				 * quantum per core, each time the bucket reaches the earliest deadline position. Note that this
				 * cadence is driven by the difference between the starved bucket's and highest-runnable bucket's WCELs.
				 */
				edf_bucket->scrb_starvation_avoidance = true;
				edf_bucket->scrb_starvation_ts = timestamp;
				debug_info->trace_data.selection_opened_starvation_avoidance_window = true;
			} else {
				/* EDF bucket is being selected in the natural order; update deadline and reset warp */
				sched_clutch_root_bucket_deadline_update(edf_bucket, root_clutch, timestamp, edf_bucket_enqueued_normally);
				edf_bucket->scrb_warp_remaining = sched_clutch_root_bucket_warp[edf_bucket->scrb_bucket];
				edf_bucket->scrb_warped_deadline = SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED;
				if (edf_bucket_enqueued_normally) {
					if (edf_bucket->scrb_bound) {
						bitmap_set(root_clutch->scr_bound_warp_available, edf_bucket->scrb_bucket);
					} else {
						bitmap_set(root_clutch->scr_unbound_warp_available, edf_bucket->scrb_bucket);
					}
				}
			}
		}
		*chose_prev_thread = !edf_bucket_enqueued_normally;
		return edf_bucket;
	}

	/*
	 * Looks like there is a root bucket which is higher in the natural priority
	 * order than edf_bucket and might have some warp remaining.
	 */
	assert(prev_bucket_warping || warp_bucket_index >= 0);
	sched_clutch_root_bucket_t warp_bucket = NULL;
	if (prev_bucket_warping) {
		assert(warp_bucket_index == -1 || prev_bucket->scrb_bucket < warp_bucket_index);
		warp_bucket = prev_bucket;
	} else {
		warp_bucket = (edf_bucket->scrb_bound) ? &root_clutch->scr_bound_buckets[warp_bucket_index] : &root_clutch->scr_unbound_buckets[warp_bucket_index];
	}

	bool warp_is_being_utilized = warp_bucket == prev_bucket || mode == SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY || mode == SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT;

	if (warp_bucket->scrb_warped_deadline == SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED) {
		if (warp_is_being_utilized) {
			/* Root bucket has not used any of its warp; set a deadline to expire its warp and return it */
			warp_bucket->scrb_warped_deadline = timestamp + warp_bucket->scrb_warp_remaining;
			sched_clutch_root_bucket_deadline_update(warp_bucket, root_clutch, timestamp, !prev_bucket_warping);
			debug_info->trace_data.selection_opened_warp_window = true;
		}
		*chose_prev_thread = prev_bucket_warping;
		debug_info->trace_data.selection_was_edf = false;
		assert(warp_bucket != edf_bucket);
		return warp_bucket;
	}
	if (warp_bucket->scrb_warped_deadline > timestamp) {
		/* Root bucket already has a warp window open with some warp remaining */
		if (warp_is_being_utilized) {
			sched_clutch_root_bucket_deadline_update(warp_bucket, root_clutch, timestamp, !prev_bucket_warping);
		}
		*chose_prev_thread = prev_bucket_warping;
		debug_info->trace_data.selection_was_edf = false;
		return warp_bucket;
	}

	/*
	 * For this bucket, warp window was opened sometime in the past but has now
	 * expired. Mark the bucket as not available for warp anymore and re-run the
	 * warp bucket selection logic.
	 */
	warp_bucket->scrb_warp_remaining = 0;
	if (!prev_bucket_warping) {
		if (warp_bucket->scrb_bound) {
			bitmap_clear(root_clutch->scr_bound_warp_available, warp_bucket->scrb_bucket);
		} else {
			bitmap_clear(root_clutch->scr_unbound_warp_available, warp_bucket->scrb_bucket);
		}
	}
	bit_set(debug_info->trace_data.warp_window_close, warp_bucket->scrb_bound * TH_BUCKET_SCHED_MAX + warp_bucket->scrb_bucket);
	goto evaluate_root_buckets;
}

static inline bool
sched_clutch_bucket_is_above_timeshare(sched_bucket_t bucket)
{
	return bucket == TH_BUCKET_FIXPRI;
}

/*
 * sched_clutch_root_bucket_deadline_calculate()
 *
 * Calculate the deadline for the bucket based on its WCEL
 */
static uint64_t
sched_clutch_root_bucket_deadline_calculate(
	sched_clutch_root_bucket_t root_bucket,
	uint64_t timestamp)
{
	/* For fixpri AboveUI bucket always return it as the earliest deadline */
	if (sched_clutch_bucket_is_above_timeshare(root_bucket->scrb_bucket)) {
		return 0;
	}

	/* For all timeshare buckets set the deadline as current time + worst-case-execution-latency */
	return timestamp + sched_clutch_root_bucket_wcel[root_bucket->scrb_bucket];
}

/*
 * sched_clutch_root_bucket_deadline_update()
 *
 * Routine to update the deadline of the root bucket when it is selected.
 * Updating the deadline also moves the root_bucket in the EDF priority
 * queue.
 */
static void
sched_clutch_root_bucket_deadline_update(
	sched_clutch_root_bucket_t root_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	bool bucket_is_enqueued)
{
	if (sched_clutch_bucket_is_above_timeshare(root_bucket->scrb_bucket)) {
		/* The algorithm never uses the deadlines for scheduling TH_BUCKET_FIXPRI bucket */
		return;
	}

	uint64_t old_deadline = root_bucket->scrb_pqlink.deadline;
	uint64_t new_deadline = sched_clutch_root_bucket_deadline_calculate(root_bucket, timestamp);
	if (__improbable(old_deadline > new_deadline)) {
		panic("old_deadline (%llu) > new_deadline (%llu); root_bucket (%d); timestamp (%llu)", old_deadline, new_deadline, root_bucket->scrb_bucket, timestamp);
	}
	if (old_deadline != new_deadline) {
		root_bucket->scrb_pqlink.deadline = new_deadline;
		if (bucket_is_enqueued) {
			struct priority_queue_deadline_min *prioq = (root_bucket->scrb_bound) ? &root_clutch->scr_bound_root_buckets : &root_clutch->scr_unbound_root_buckets;
			priority_queue_entry_increased(prioq, &root_bucket->scrb_pqlink);
		}
	}
}

/*
 * sched_clutch_root_bucket_runnable()
 *
 * Routine to insert a newly runnable root bucket into the hierarchy.
 * Also updates the deadline and warp parameters as necessary.
 */
static void
sched_clutch_root_bucket_runnable(
	sched_clutch_root_bucket_t root_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	/* Mark the root bucket as runnable */
	bitmap_t *runnable_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_runnable_bitmap : root_clutch->scr_unbound_runnable_bitmap;
	bitmap_set(runnable_bitmap, root_bucket->scrb_bucket);

	if (sched_clutch_bucket_is_above_timeshare(root_bucket->scrb_bucket)) {
		/* Since the TH_BUCKET_FIXPRI bucket is not scheduled based on deadline, nothing more needed here */
		return;
	}

	if (root_bucket->scrb_starvation_avoidance == false) {
		/*
		 * Only update the deadline if the bucket was not in starvation avoidance mode. If the bucket was in
		 * starvation avoidance and its window has expired, the highest root bucket selection logic will notice
		 * that and fix it up.
		 */
		root_bucket->scrb_pqlink.deadline = sched_clutch_root_bucket_deadline_calculate(root_bucket, timestamp);
	}
	struct priority_queue_deadline_min *prioq = (root_bucket->scrb_bound) ? &root_clutch->scr_bound_root_buckets : &root_clutch->scr_unbound_root_buckets;
	priority_queue_insert(prioq, &root_bucket->scrb_pqlink);
	if (root_bucket->scrb_warp_remaining) {
		/* Since the bucket has some warp remaining and its now runnable, mark it as available for warp */
		bitmap_t *warp_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_warp_available : root_clutch->scr_unbound_warp_available;
		bitmap_set(warp_bitmap, root_bucket->scrb_bucket);
	}
}

/*
 * sched_clutch_root_bucket_empty()
 *
 * Routine to remove an empty root bucket from the hierarchy.
 * Also updates the deadline and warp parameters as necessary.
 */
static void
sched_clutch_root_bucket_empty(
	sched_clutch_root_bucket_t root_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp)
{
	bitmap_t *runnable_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_runnable_bitmap : root_clutch->scr_unbound_runnable_bitmap;
	bitmap_clear(runnable_bitmap, root_bucket->scrb_bucket);

	if (sched_clutch_bucket_is_above_timeshare(root_bucket->scrb_bucket)) {
		/* Since the TH_BUCKET_FIXPRI bucket is not scheduled based on deadline, nothing more needed here */
		return;
	}

	struct priority_queue_deadline_min *prioq = (root_bucket->scrb_bound) ? &root_clutch->scr_bound_root_buckets : &root_clutch->scr_unbound_root_buckets;
	priority_queue_remove(prioq, &root_bucket->scrb_pqlink);

	bitmap_t *warp_bitmap = (root_bucket->scrb_bound) ? root_clutch->scr_bound_warp_available : root_clutch->scr_unbound_warp_available;
	bitmap_clear(warp_bitmap, root_bucket->scrb_bucket);

	if (root_bucket->scrb_warped_deadline != SCHED_CLUTCH_ROOT_BUCKET_WARP_UNUSED) {
		if (root_bucket->scrb_warped_deadline > timestamp) {
			/*
			 * For root buckets that were using the warp, check if the warp
			 * deadline is in the future. If yes, remove the wall time the
			 * warp was active and update the warp remaining. This allows
			 * the root bucket to use the remaining warp the next time it
			 * becomes runnable.
			 */
			root_bucket->scrb_warp_remaining = root_bucket->scrb_warped_deadline - timestamp;
		} else {
			/*
			 * If the root bucket's warped deadline is in the past, it has used up
			 * all the warp it was assigned. Empty out its warp remaining.
			 */
			root_bucket->scrb_warp_remaining = 0;
		}
	}
}

static int
sched_clutch_global_bucket_load_get(
	sched_bucket_t bucket)
{
	return (int)os_atomic_load(&sched_clutch_global_bucket_load[bucket], relaxed);
}

/*
 * sched_clutch_root_pri_update()
 *
 * The root level priority is used for thread selection and preemption
 * logic.
 *
 * The logic uses the same decision as thread selection for deciding between the
 * above UI and timeshare buckets. If one of the timesharing buckets have to be
 * used for priority calculation, the logic is slightly different from thread
 * selection, because thread selection considers deadlines, warps etc. to
 * decide the most optimal bucket at a given timestamp. Since the priority
 * value is used for preemption decisions only, it needs to be based on the
 * highest runnable thread available in the timeshare domain. This logic can
 * be made more sophisticated if there are cases of unnecessary preemption
 * being seen in workloads.
 */
static void
sched_clutch_root_pri_update(
	sched_clutch_root_t root_clutch)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	int16_t root_bound_pri = NOPRI;
	int16_t root_unbound_pri = NOPRI;

	/* Consider bound root buckets */
	if (bitmap_lsb_first(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		goto root_pri_update_unbound;
	}
	sched_clutch_root_bucket_t highest_bound_root_bucket = NULL;
	__unused int highest_bound_root_bucket_pri = -1;
	bool highest_bound_root_bucket_is_fixpri = false;
	sched_clutch_root_bound_select_aboveui(root_clutch, &highest_bound_root_bucket, &highest_bound_root_bucket_pri, &highest_bound_root_bucket_is_fixpri, NULL, NULL);
	if (highest_bound_root_bucket_is_fixpri == false) {
		int root_bucket_index = bitmap_lsb_next(root_clutch->scr_bound_runnable_bitmap, TH_BUCKET_SCHED_MAX, TH_BUCKET_FIXPRI);
		assert(root_bucket_index != -1);
		highest_bound_root_bucket = &root_clutch->scr_bound_buckets[root_bucket_index];
	}
	root_bound_pri = highest_bound_root_bucket->scrb_bound_thread_runq.highq;

root_pri_update_unbound:
	/* Consider unbound root buckets */
	if (bitmap_lsb_first(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		goto root_pri_update_complete;
	}
	sched_clutch_root_bucket_t highest_unbound_root_bucket = NULL;
	__unused int highest_unbound_root_bucket_pri = -1;
	bool highest_unbound_root_bucket_is_fixpri = false;
	sched_clutch_root_unbound_select_aboveui(root_clutch, &highest_unbound_root_bucket, &highest_unbound_root_bucket_pri, &highest_unbound_root_bucket_is_fixpri, NULL, NULL);
	if (highest_unbound_root_bucket_is_fixpri == false) {
		int root_bucket_index = bitmap_lsb_next(root_clutch->scr_unbound_runnable_bitmap, TH_BUCKET_SCHED_MAX, TH_BUCKET_FIXPRI);
		assert(root_bucket_index != -1);
		highest_unbound_root_bucket = &root_clutch->scr_unbound_buckets[root_bucket_index];
	}

	/* For the selected root bucket, find the highest priority clutch bucket */
	sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_clutch, highest_unbound_root_bucket, NULL, NULL, NULL);
	root_unbound_pri = priority_queue_max_sched_pri(&clutch_bucket->scb_clutchpri_prioq);

root_pri_update_complete:
	root_clutch->scr_priority = MAX(root_bound_pri, root_unbound_pri);
}

/*
 * sched_clutch_root_urgency_inc()
 *
 * Routine to increment the urgency at the root level based on the thread
 * priority that is being inserted into the hierarchy. The root urgency
 * counter is updated based on the urgency of threads in any of the
 * clutch buckets which are part of the hierarchy.
 *
 * Always called with the pset lock held.
 */
static void
sched_clutch_root_urgency_inc(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		root_clutch->scr_urgency++;
	}
}

/*
 * sched_clutch_root_urgency_dec()
 *
 * Routine to decrement the urgency at the root level based on the thread
 * priority that is being removed from the hierarchy. The root urgency
 * counter is updated based on the urgency of threads in any of the
 * clutch buckets which are part of the hierarchy.
 *
 * Always called with the pset lock held.
 */
static void
sched_clutch_root_urgency_dec(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		root_clutch->scr_urgency--;
	}
}

/*
 * Clutch bucket level scheduling
 *
 * The second level of scheduling is the clutch bucket level scheduling
 * which tries to schedule thread groups within root_buckets. Each
 * clutch represents a thread group and a clutch_bucket_group represents
 * threads at a particular sched_bucket within that thread group. The
 * clutch_bucket_group contains a clutch_bucket per cluster on the system
 * where it holds the runnable threads destined for execution on that
 * cluster.
 *
 * The goal of this level of scheduling is to allow interactive thread
 * groups low latency access to the CPU. It also provides slight
 * scheduling preference for App and unrestricted thread groups.
 *
 * The clutch bucket scheduling algorithm measures an interactivity
 * score for all clutch bucket groups. The interactivity score is based
 * on the ratio of the CPU used and the voluntary blocking of threads
 * within the clutch bucket group. The algorithm is very close to the ULE
 * scheduler on FreeBSD in terms of calculations. The interactivity
 * score provides an interactivity boost in the range of
 * [0:SCHED_CLUTCH_BUCKET_INTERACTIVE_PRI * 2] which allows interactive
 * thread groups to win over CPU spinners.
 *
 * The interactivity score of the clutch bucket group is combined with the
 * highest base/promoted priority of threads in the clutch bucket to form
 * the overall priority of the clutch bucket.
 */

/* Priority boost range for interactivity */
#define SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT     (8)
static uint8_t sched_clutch_bucket_group_interactive_pri = SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT;

/* window to scale the cpu usage and blocked values (currently 500ms). Its the threshold of used+blocked */
static uint64_t sched_clutch_bucket_group_adjust_threshold = 0;
#define SCHED_CLUTCH_BUCKET_GROUP_ADJUST_THRESHOLD_USECS      (500000)

/* The ratio to scale the cpu/blocked time per window */
#define SCHED_CLUTCH_BUCKET_GROUP_ADJUST_RATIO                (10)

/* Initial value for voluntary blocking time for the clutch_bucket */
#define SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID          (uint64_t)(~0)

/* Value indicating the clutch bucket is not pending execution */
#define SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID             ((uint64_t)(~0))

/*
 * Thread group CPU starvation avoidance
 *
 * In heavily CPU contended scenarios, it is possible that some thread groups
 * which have a low interactivity score do not get CPU time at all. In order to
 * resolve that, the scheduler tries to ageout the CPU usage of the clutch
 * bucket group when it has been pending execution for a certain time as defined
 * by the sched_clutch_bucket_group_pending_delta_us values below.
 *
 * The values chosen here are very close to the WCEL values for each sched bucket.
 * Theses values are added into the pending interval used to determine how
 * frequently we will ageout the CPU usage, ensuring a reasonable limit on the
 * frequency.
 */
static uint32_t sched_clutch_bucket_group_pending_delta_us[TH_BUCKET_SCHED_MAX] = {
	SCHED_CLUTCH_INVALID_TIME_32,           /* FIXPRI */
	10000,                                  /* FG */
	37500,                                  /* IN */
	75000,                                  /* DF */
	150000,                                 /* UT */
	250000,                                 /* BG */
};
static uint64_t sched_clutch_bucket_group_pending_delta[TH_BUCKET_SCHED_MAX] = {0};

/*
 * sched_clutch_bucket_init()
 *
 * Initializer for clutch buckets.
 */
static void
sched_clutch_bucket_init(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_bucket_group_t clutch_bucket_group,
	sched_bucket_t bucket)
{
	clutch_bucket->scb_bucket = bucket;
	/* scb_priority will be recalculated when a thread is inserted in the clutch bucket */
	clutch_bucket->scb_priority = 0;
#if CONFIG_SCHED_EDGE
	clutch_bucket->scb_preferred_pset_when_enqueued = PSET_ID_INVALID;
	priority_queue_entry_init(&clutch_bucket->scb_stealqlink);
#endif /* CONFIG_SCHED_EDGE */
	clutch_bucket->scb_group = clutch_bucket_group;
	clutch_bucket->scb_root = NULL;
	priority_queue_init(&clutch_bucket->scb_clutchpri_prioq);
	priority_queue_init(&clutch_bucket->scb_thread_runq);
	queue_init(&clutch_bucket->scb_thread_timeshare_queue);
}

/*
 * sched_clutch_bucket_group_init()
 *
 * Initializer for clutch bucket groups.
 */
static void
sched_clutch_bucket_group_init(
	sched_clutch_bucket_group_t clutch_bucket_group,
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	bzero(clutch_bucket_group, sizeof(struct sched_clutch_bucket_group));
	clutch_bucket_group->scbg_bucket = bucket;
	clutch_bucket_group->scbg_clutch = clutch;

	clutch_bucket_group->scbg_clutch_buckets = kalloc_type(struct sched_clutch_bucket, sched_num_psets, Z_WAITOK | Z_ZERO);
	for (int i = 0; i < sched_num_psets; i++) {
		sched_clutch_bucket_init(&clutch_bucket_group->scbg_clutch_buckets[i], clutch_bucket_group, bucket);
	}

	os_atomic_store(&clutch_bucket_group->scbg_timeshare_tick, 0, relaxed);
	os_atomic_store(&clutch_bucket_group->scbg_pri_shift, INT8_MAX, relaxed);
	os_atomic_store(&clutch_bucket_group->scbg_preferred_pset, sched_boot_pset->pset_id, relaxed);
	/*
	 * All thread groups should be initialized to be interactive; this allows the newly launched
	 * thread groups to fairly compete with already running thread groups.
	 */
	clutch_bucket_group->scbg_interactivity_data.scct_count = (sched_clutch_bucket_group_interactive_pri * 2);
	clutch_bucket_group->scbg_interactivity_data.scct_timestamp = 0;
	os_atomic_store(&clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_blocked, (clutch_cpu_data_t)sched_clutch_bucket_group_adjust_threshold, relaxed);
	clutch_bucket_group->scbg_blocked_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID;
	clutch_bucket_group->scbg_pending_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID;
}

static void
sched_clutch_bucket_group_destroy(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	kfree_type(struct sched_clutch_bucket, sched_num_psets, clutch_bucket_group->scbg_clutch_buckets);
}

/*
 * sched_clutch_init_with_thread_group()
 *
 * Initialize the sched_clutch when the thread group is being created
 */
void
sched_clutch_init_with_thread_group(
	sched_clutch_t clutch,
	struct thread_group *tg)
{
	os_atomic_store(&clutch->sc_thr_count, 0, relaxed);

	/* Initialize all the clutch buckets */
	for (uint32_t i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		sched_clutch_bucket_group_init(&(clutch->sc_clutch_groups[i]), clutch, i);
	}

	/* Grouping specific fields */
	clutch->sc_tg = tg;
}

/*
 * sched_clutch_destroy()
 *
 * Destructor for clutch; called from thread group release code.
 */
void
sched_clutch_destroy(
	sched_clutch_t clutch)
{
	assert(os_atomic_load(&clutch->sc_thr_count, relaxed) == 0);
	for (uint32_t i = 0; i < TH_BUCKET_SCHED_MAX; i++) {
		sched_clutch_bucket_group_destroy(&(clutch->sc_clutch_groups[i]));
	}
}

#if CONFIG_SCHED_EDGE

/*
 * Edge Scheduler Preferred Pset Mechanism
 *
 * In order to have better control over various QoS buckets within a thread
 * group, the Edge scheduler allows CLPC to specify a preferred cluster for each
 * QoS level in a TG. The cluster ID is translated by XNU to a pset ID, and
 * these preferences are stored at the sched_clutch_bucket_group level since
 * that represents all threads at a particular QoS level within a sched_clutch.
 * For any lookup of preferred pset, the logic always goes back to the
 * preference stored at the clutch_bucket_group.
 */

static pset_id_t
sched_edge_clutch_bucket_group_preferred_pset(sched_clutch_bucket_group_t clutch_bucket_group)
{
	return os_atomic_load(&clutch_bucket_group->scbg_preferred_pset, relaxed);
}

static pset_id_t
sched_clutch_bucket_preferred_pset(sched_clutch_bucket_t clutch_bucket)
{
	return sched_edge_clutch_bucket_group_preferred_pset(clutch_bucket->scb_group);
}

pset_id_t
sched_edge_thread_preferred_pset(thread_t thread)
{
	if (SCHED_CLUTCH_THREAD_PSET_BOUND(thread)) {
		/* For threads bound to a specific pset, return the bound pset id */
		return sched_edge_thread_bound_pset_id(thread);
	}

	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_bucket_t sched_bucket = thread->th_sched_bucket;
	if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
		sched_bucket = sched_clutch_thread_bucket_map(thread, thread->base_pri);
	}
	sched_clutch_bucket_group_t clutch_bucket_group = &clutch->sc_clutch_groups[sched_bucket];
	return sched_edge_clutch_bucket_group_preferred_pset(clutch_bucket_group);
}

/*
 * Edge Scheduler Steal Silo Support
 *
 * Steal mechanisms in the Edge scheduler, including foreign rebalance
 * and regular work-stealing, are implemented using steal "silos"
 * on every pset tracking the clutch buckets with steal-able threads,
 * where each steal silo on a pset corresponds to a possible preferred
 * pset recommendation. Silos are comprised of per-bucket steal
 * queues. This amount of subdivision allows for fine-grained steal
 * policies which stay precisely in-sync with the complex Edge matrix.
 */

/*
 * sched_edge_steal_silo_from_pset_id()
 *
 * Routine to return the steal silo corresponding to a particular
 * preferred pset on a root clutch.
 */
static sched_edge_steal_silo_t
sched_edge_steal_silo_from_pset_id(pset_id_t preferred_pset_id, sched_clutch_root_t root_clutch)
{
	return &root_clutch->scr_steal_silos[preferred_pset_id];
}

/*
 * sched_edge_steal_silo_clutch_bucket_unclassify()
 *
 * Routine to reset a clutch bucket's steal silo tracking on the
 * pset where it is enqueued, necessary when dequeueing a clutch
 * bucket or changing its priority.
 * Always called with the pset lock held.
 */
static void
sched_edge_steal_silo_clutch_bucket_unclassify(sched_clutch_bucket_t clutch_bucket, sched_clutch_root_t root_clutch)
{
	assert3u(clutch_bucket->scb_preferred_pset_when_enqueued, !=, PSET_ID_INVALID);
	sched_edge_steal_silo_t steal_silo =
	    sched_edge_steal_silo_from_pset_id(clutch_bucket->scb_preferred_pset_when_enqueued, root_clutch);
	struct priority_queue_sched_max *steal_queue = &steal_silo->sess_steal_queues[clutch_bucket->scb_bucket];
	priority_queue_remove(steal_queue, &clutch_bucket->scb_stealqlink);
	if (priority_queue_empty(steal_queue)) {
		/* Last bucket from this steal queue */
		atomic_bit_clear(steal_silo->sess_populated_steal_queues, clutch_bucket->scb_bucket, memory_order_relaxed);
	}
	if (os_atomic_load(steal_silo->sess_populated_steal_queues, relaxed) == 0) {
		/* Last populated steal queue from this silo */
		atomic_bit_clear(root_clutch->scr_populated_steal_silos,
		    clutch_bucket->scb_preferred_pset_when_enqueued, memory_order_relaxed);
	}
	clutch_bucket->scb_preferred_pset_when_enqueued = PSET_ID_INVALID;
}

/*
 * sched_edge_steal_silo_clutch_bucket_classify()
 *
 * Routine to establish a clutch bucket's steal silo tracking on
 * the pset where it is (being) enqueued. Can be used to update the
 * tracking of a previously enqueued clutch bucket.
 * Always called with the pset lock held.
 */
static void
sched_edge_steal_silo_clutch_bucket_classify(sched_clutch_bucket_t clutch_bucket,
    sched_clutch_root_t root_clutch, pset_id_t preferred_pset_id)
{
	if (clutch_bucket->scb_preferred_pset_when_enqueued != PSET_ID_INVALID) {
		if (clutch_bucket->scb_preferred_pset_when_enqueued == preferred_pset_id) {
			/* Already classified correctly */
			return;
		} else {
			/* Remove from previous queue */
			sched_edge_steal_silo_clutch_bucket_unclassify(clutch_bucket, root_clutch);
		}
	}
	assert3u(clutch_bucket->scb_preferred_pset_when_enqueued, ==, PSET_ID_INVALID);
	/*
	 * Insert clutch bucket into the steal silo matching its preferred pset
	 * and into the queue in the silo matching its scheduling bucket.
	 */
	clutch_bucket->scb_preferred_pset_when_enqueued = preferred_pset_id;
	sched_edge_steal_silo_t steal_silo =
	    sched_edge_steal_silo_from_pset_id(clutch_bucket->scb_preferred_pset_when_enqueued, root_clutch);
	struct priority_queue_sched_max *steal_queue = &steal_silo->sess_steal_queues[clutch_bucket->scb_bucket];
	priority_queue_entry_set_sched_pri(steal_queue, &clutch_bucket->scb_stealqlink, clutch_bucket->scb_priority, 0);
	priority_queue_insert(steal_queue, &clutch_bucket->scb_stealqlink);
	atomic_bit_set(steal_silo->sess_populated_steal_queues, clutch_bucket->scb_bucket, memory_order_relaxed);
	atomic_bit_set(root_clutch->scr_populated_steal_silos, clutch_bucket->scb_preferred_pset_when_enqueued, memory_order_relaxed);
}

/*
 * Edge Scheduler Cumulative Load Average
 *
 * The Edge scheduler maintains a per-QoS/scheduling bucket load average for
 * making thread migration decisions. The per-bucket load is maintained as a
 * cumulative count since higher scheduling buckets impact load on lower buckets
 * for thread migration decisions.
 */

static void
sched_edge_pset_cumulative_count_incr(sched_clutch_root_t root_clutch, sched_bucket_t bucket)
{
	switch (bucket) {
	case TH_BUCKET_FIXPRI:    os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_FIXPRI], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_FG:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_FG], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_IN:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_IN], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_DF:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_DF], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_UT:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_UT], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_BG:  os_atomic_inc(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_BG], relaxed); break;
	default:
		panic("Unexpected sched_bucket passed to sched_edge_pset_cumulative_count_incr()");
	}
}

static void
sched_edge_pset_cumulative_count_decr(sched_clutch_root_t root_clutch, sched_bucket_t bucket)
{
	switch (bucket) {
	case TH_BUCKET_FIXPRI:    os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_FIXPRI], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_FG:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_FG], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_IN:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_IN], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_DF:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_DF], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_UT:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_UT], relaxed); OS_FALLTHROUGH;
	case TH_BUCKET_SHARE_BG:  os_atomic_dec(&root_clutch->scr_cumulative_run_count[TH_BUCKET_SHARE_BG], relaxed); break;
	default:
		panic("Unexpected sched_bucket passed to sched_edge_pset_cumulative_count_decr()");
	}
}

uint16_t
sched_edge_pset_cumulative_count(sched_clutch_root_t root_clutch, sched_bucket_t bucket)
{
	return os_atomic_load(&root_clutch->scr_cumulative_run_count[bucket], relaxed);
}

#endif /* CONFIG_SCHED_EDGE */

/*
 * sched_clutch_bucket_hierarchy_insert()
 *
 * Routine to insert a newly runnable clutch_bucket into the root hierarchy.
 */
static void
sched_clutch_bucket_hierarchy_insert(
	sched_clutch_root_t root_clutch,
	sched_clutch_bucket_t clutch_bucket,
	sched_bucket_t bucket,
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (sched_clutch_bucket_is_above_timeshare(bucket) == false) {
		/* Enqueue the timeshare clutch buckets into the global runnable clutch_bucket list; used for sched tick operations */
		enqueue_tail(&root_clutch->scr_clutch_buckets, &clutch_bucket->scb_listlink);
	}
#if CONFIG_SCHED_EDGE
	/* Check if the bucket is a foreign clutch bucket and add it to the foreign buckets list */
	pset_id_t preferred_pset = sched_clutch_bucket_preferred_pset(clutch_bucket);
	sched_edge_steal_silo_clutch_bucket_classify(clutch_bucket, root_clutch, preferred_pset);
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_unbound_buckets[bucket];

	/* If this is the first clutch bucket in the root bucket, insert the root bucket into the root priority queue */
	if (sched_clutch_bucket_runq_empty(&root_bucket->scrb_clutch_buckets)) {
		sched_clutch_root_bucket_runnable(root_bucket, root_clutch, timestamp);
	}

	/* Insert the clutch bucket into the root bucket run queue with order based on options */
	sched_clutch_bucket_runq_enqueue(&root_bucket->scrb_clutch_buckets, clutch_bucket, options);
	clutch_bucket->scb_root = root_clutch;
	os_atomic_inc(&sched_clutch_global_bucket_load[bucket], relaxed);
}

/*
 * sched_clutch_bucket_hierarchy_remove()
 *
 * Rotuine to remove a empty clutch bucket from the root hierarchy.
 */
static void
sched_clutch_bucket_hierarchy_remove(
	sched_clutch_root_t root_clutch,
	sched_clutch_bucket_t clutch_bucket,
	sched_bucket_t bucket,
	uint64_t timestamp,
	__unused sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	if (sched_clutch_bucket_is_above_timeshare(bucket) == false) {
		/* Remove the timeshare clutch bucket from the globally runnable clutch_bucket list */
		remqueue(&clutch_bucket->scb_listlink);
	}
#if CONFIG_SCHED_EDGE
	sched_edge_steal_silo_clutch_bucket_unclassify(clutch_bucket, root_clutch);
#endif /* CONFIG_SCHED_EDGE */

	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_unbound_buckets[bucket];

	/* Remove the clutch bucket from the root bucket priority queue */
	sched_clutch_bucket_runq_remove(&root_bucket->scrb_clutch_buckets, clutch_bucket);
	clutch_bucket->scb_root = NULL;

	/* If the root bucket priority queue is now empty, remove it from the root priority queue */
	if (sched_clutch_bucket_runq_empty(&root_bucket->scrb_clutch_buckets)) {
		sched_clutch_root_bucket_empty(root_bucket, root_clutch, timestamp);
	}
	os_atomic_dec(&sched_clutch_global_bucket_load[bucket], relaxed);
}

/*
 * sched_clutch_bucket_base_pri()
 *
 * Calculates the "base" priority of the clutch bucket, which is equal to the max of the
 * highest base_pri and the highest sched_pri in the clutch bucket.
 */
static uint8_t
sched_clutch_bucket_base_pri(
	sched_clutch_bucket_t clutch_bucket)
{
	assert(priority_queue_empty(&clutch_bucket->scb_thread_runq) == false);
	/*
	 * Since the clutch bucket can contain threads that are members of the group due
	 * to the sched_pri being promoted or due to their base pri, the base priority of
	 * the entire clutch bucket should be based on the highest thread (promoted or base)
	 * in the clutch bucket.
	 */
	uint8_t max_pri = 0;
	if (!priority_queue_empty(&clutch_bucket->scb_clutchpri_prioq)) {
		max_pri = priority_queue_max_sched_pri(&clutch_bucket->scb_clutchpri_prioq);
	}
	return max_pri;
}

/*
 * sched_clutch_interactivity_from_cpu_data()
 *
 * Routine to calculate the interactivity score of a clutch bucket group from its CPU usage
 */
static uint8_t
sched_clutch_interactivity_from_cpu_data(sched_clutch_bucket_group_t clutch_bucket_group)
{
	sched_clutch_bucket_cpu_data_t scb_cpu_data;
	scb_cpu_data.scbcd_cpu_data_packed = os_atomic_load_wide(&clutch_bucket_group->scbg_cpu_data.scbcd_cpu_data_packed, relaxed);
	clutch_cpu_data_t cpu_used = scb_cpu_data.cpu_data.scbcd_cpu_used;
	clutch_cpu_data_t cpu_blocked = scb_cpu_data.cpu_data.scbcd_cpu_blocked;
	uint8_t interactive_score = 0;

	if ((cpu_blocked == 0) && (cpu_used == 0)) {
		return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
	}
	/*
	 * For all timeshare buckets, calculate the interactivity score of the bucket
	 * and add it to the base priority
	 */
	if (cpu_blocked > cpu_used) {
		/* Interactive clutch_bucket case */
		interactive_score = sched_clutch_bucket_group_interactive_pri +
		    ((sched_clutch_bucket_group_interactive_pri * (cpu_blocked - cpu_used)) / cpu_blocked);
	} else {
		/* Non-interactive clutch_bucket case */
		interactive_score = ((sched_clutch_bucket_group_interactive_pri * cpu_blocked) / cpu_used);
	}
	return interactive_score;
}

/*
 * sched_clutch_bucket_pri_calculate()
 *
 * The priority calculation algorithm for the clutch_bucket is a slight
 * modification on the ULE interactivity score. It uses the base priority
 * of the clutch bucket and applies an interactivity score boost to the
 * highly responsive clutch buckets.
 */
static uint8_t
sched_clutch_bucket_pri_calculate(
	sched_clutch_bucket_t clutch_bucket,
	uint64_t timestamp)
{
	/* For empty clutch buckets, return priority 0 */
	if (clutch_bucket->scb_thr_count == 0) {
		return 0;
	}

	uint8_t base_pri = sched_clutch_bucket_base_pri(clutch_bucket);
	uint8_t interactive_score = sched_clutch_bucket_group_interactivity_score_calculate(clutch_bucket->scb_group, timestamp);

	assert(((uint64_t)base_pri + interactive_score) <= UINT8_MAX);
	uint8_t pri = base_pri + interactive_score;
	if (pri != clutch_bucket->scb_priority) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_TG_BUCKET_PRI) | DBG_FUNC_NONE,
		    thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket, pri, interactive_score, 0);
	}
	return pri;
}

/*
 * sched_clutch_root_bucket_highest_clutch_bucket()
 *
 * Routine to find the highest priority clutch bucket
 * within the root bucket.
 */
static sched_clutch_bucket_t
sched_clutch_root_bucket_highest_clutch_bucket(
	sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t root_bucket,
	processor_t _Nullable processor,
	thread_t _Nullable prev_thread,
	bool *_Nullable chose_prev_thread)
{
	if (sched_clutch_bucket_runq_empty(&root_bucket->scrb_clutch_buckets)) {
		if (prev_thread != NULL) {
			*chose_prev_thread = true;
			return sched_clutch_bucket_for_thread(root_clutch, prev_thread);
		}
		return NULL;
	}
	sched_clutch_bucket_t clutch_bucket = sched_clutch_bucket_runq_peek(&root_bucket->scrb_clutch_buckets);
	/* Consider the Clutch bucket of the previous thread */
	if (prev_thread != NULL) {
		assert(chose_prev_thread != NULL);
		sched_clutch_bucket_group_t prev_clutch_bucket_group = sched_clutch_bucket_group_for_thread(prev_thread);
		int prev_clutch_bucket_pri = prev_thread->sched_pri + (int)(os_atomic_load(&prev_clutch_bucket_group->scbg_interactivity_data.scct_count, relaxed));
		sched_clutch_bucket_t prev_clutch_bucket = sched_clutch_bucket_for_thread(root_clutch, prev_thread);
		if (prev_clutch_bucket != clutch_bucket &&
		    sched_clutch_pri_greater_than_tiebreak(prev_clutch_bucket_pri, clutch_bucket->scb_priority, processor->first_timeslice)) {
			*chose_prev_thread = true;
			return prev_clutch_bucket;
		}
	}
	return clutch_bucket;
}

/*
 * sched_clutch_bucket_runnable()
 *
 * Perform all operations needed when a new clutch bucket becomes runnable.
 * It involves inserting the clutch_bucket into the hierarchy and updating the
 * root priority appropriately.
 */
static boolean_t
sched_clutch_bucket_runnable(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	/* Since the clutch bucket became newly runnable, update its pending timestamp */
	clutch_bucket->scb_priority = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	sched_clutch_bucket_hierarchy_insert(root_clutch, clutch_bucket, clutch_bucket->scb_bucket, timestamp, options);

	/* Update the timesharing properties of this clutch_bucket_group; also done every sched_tick */
	sched_clutch_bucket_group_pri_shift_update(clutch_bucket->scb_group);

	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

/*
 * sched_clutch_bucket_update()
 *
 * Update the clutch_bucket's position in the hierarchy. This routine is
 * called when a new thread is inserted or removed from a runnable clutch
 * bucket. The options specify some properties about the clutch bucket
 * insertion order into the clutch bucket runq.
 */
static boolean_t
sched_clutch_bucket_update(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	uint64_t new_pri = sched_clutch_bucket_pri_calculate(clutch_bucket, timestamp);
	sched_clutch_bucket_runq_t bucket_runq = &root_clutch->scr_unbound_buckets[clutch_bucket->scb_bucket].scrb_clutch_buckets;
	if (new_pri == clutch_bucket->scb_priority) {
		/*
		 * If SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR is specified, move the clutch bucket
		 * to the end of the runq. Typically used when a thread is selected for execution
		 * from a clutch bucket.
		 */
		if (options & SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR) {
			sched_clutch_bucket_runq_rotate(bucket_runq, clutch_bucket);
		}
		return false;
	}
	sched_clutch_bucket_runq_remove(bucket_runq, clutch_bucket);
#if CONFIG_SCHED_EDGE
	/* Need to update clutch bucket's priority ranking in its foreign queue */
	pset_id_t pset_preference = clutch_bucket->scb_preferred_pset_when_enqueued;
	sched_edge_steal_silo_clutch_bucket_unclassify(clutch_bucket, root_clutch);
#endif /* CONFIG_SCHED_EDGE */
	clutch_bucket->scb_priority = new_pri;
#if CONFIG_SCHED_EDGE
	sched_edge_steal_silo_clutch_bucket_classify(clutch_bucket, root_clutch, pset_preference);
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_bucket_runq_enqueue(bucket_runq, clutch_bucket, options);

	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

/*
 * sched_clutch_bucket_empty()
 *
 * Perform all the operations needed when a clutch_bucket is no longer runnable.
 * It involves removing the clutch bucket from the hierarchy and updaing the root
 * priority appropriately.
 */
static void
sched_clutch_bucket_empty(
	sched_clutch_bucket_t clutch_bucket,
	sched_clutch_root_t root_clutch,
	uint64_t timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
	assert3u(clutch_bucket->scb_thr_count, ==, 0);
	sched_clutch_bucket_hierarchy_remove(root_clutch, clutch_bucket, clutch_bucket->scb_bucket, timestamp, options);

	/* Update the timesharing properties of this clutch_bucket_group; also done every sched_tick */
	sched_clutch_bucket_group_pri_shift_update(clutch_bucket->scb_group);

	clutch_bucket->scb_priority = 0;
	sched_clutch_root_pri_update(root_clutch);
}

/*
 * sched_clutch_cpu_usage_update()
 *
 * Routine to update CPU usage of the thread in the hierarchy.
 */
void
sched_clutch_cpu_usage_update(
	thread_t thread,
	uint64_t delta)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread) || SCHED_CLUTCH_THREAD_PSET_BOUND(thread)) {
		return;
	}

	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[thread->th_sched_bucket]);
	sched_clutch_bucket_group_cpu_usage_update(clutch_bucket_group, delta);
}

/*
 * sched_clutch_bucket_group_cpu_usage_update()
 *
 * Routine to update the CPU usage of the clutch_bucket.
 */
static void
sched_clutch_bucket_group_cpu_usage_update(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t delta)
{
	if (sched_clutch_bucket_is_above_timeshare(clutch_bucket_group->scbg_bucket)) {
		/* Since Above UI bucket has maximum interactivity score always, nothing to do here */
		return;
	}
	delta = MIN(delta, sched_clutch_bucket_group_adjust_threshold);
	os_atomic_add(&(clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_used), (clutch_cpu_data_t)delta, relaxed);
}

/*
 * sched_clutch_bucket_group_cpu_pending_adjust()
 *
 * Routine to calculate the adjusted CPU usage value based on the pending intervals. The calculation is done
 * such that one "pending interval" provides one point improvement in interactivity score.
 */
static inline uint64_t
sched_clutch_bucket_group_cpu_pending_adjust(
	uint64_t cpu_used,
	uint64_t cpu_blocked,
	uint8_t pending_intervals)
{
	uint64_t cpu_used_adjusted = 0;
	if (cpu_blocked < cpu_used) {
		cpu_used_adjusted = (sched_clutch_bucket_group_interactive_pri * cpu_blocked * cpu_used);
		cpu_used_adjusted = cpu_used_adjusted / ((sched_clutch_bucket_group_interactive_pri * cpu_blocked) + (cpu_used * pending_intervals));
	} else {
		uint64_t adjust_factor = (cpu_blocked * pending_intervals) / sched_clutch_bucket_group_interactive_pri;
		cpu_used_adjusted = (adjust_factor > cpu_used) ? 0 : (cpu_used - adjust_factor);
	}
	return cpu_used_adjusted;
}

/*
 * sched_clutch_bucket_group_cpu_adjust()
 *
 * Routine to scale the cpu usage and blocked time once the sum gets bigger
 * than sched_clutch_bucket_group_adjust_threshold. Allows the values to remain
 * manageable and maintain the same ratio while allowing clutch buckets to
 * adjust behavior and reflect in the interactivity score in a reasonable
 * amount of time. Also adjusts the CPU usage based on pending_intervals
 * which allows ageout of CPU to avoid starvation in highly contended scenarios.
 */
static void
sched_clutch_bucket_group_cpu_adjust(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint8_t pending_intervals)
{
	sched_clutch_bucket_cpu_data_t old_cpu_data = {};
	sched_clutch_bucket_cpu_data_t new_cpu_data = {};
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_cpu_data.scbcd_cpu_data_packed, old_cpu_data.scbcd_cpu_data_packed, new_cpu_data.scbcd_cpu_data_packed, relaxed, {
		clutch_cpu_data_t cpu_used = old_cpu_data.cpu_data.scbcd_cpu_used;
		clutch_cpu_data_t cpu_blocked = old_cpu_data.cpu_data.scbcd_cpu_blocked;

		if ((pending_intervals == 0) && (cpu_used + cpu_blocked) < sched_clutch_bucket_group_adjust_threshold) {
		        /* No changes to the CPU used and blocked values */
		        os_atomic_rmw_loop_give_up();
		}
		if ((cpu_used + cpu_blocked) >= sched_clutch_bucket_group_adjust_threshold) {
		        /* Only keep the recent CPU history to better indicate how this TG has been behaving */
		        cpu_used = cpu_used / SCHED_CLUTCH_BUCKET_GROUP_ADJUST_RATIO;
		        cpu_blocked = cpu_blocked / SCHED_CLUTCH_BUCKET_GROUP_ADJUST_RATIO;
		}
		/* Use the shift passed in to ageout the CPU usage */
		cpu_used = (clutch_cpu_data_t)sched_clutch_bucket_group_cpu_pending_adjust(cpu_used, cpu_blocked, pending_intervals);
		new_cpu_data.cpu_data.scbcd_cpu_used = cpu_used;
		new_cpu_data.cpu_data.scbcd_cpu_blocked = cpu_blocked;
	});
}

/*
 * Thread level scheduling algorithm
 *
 * The thread level scheduling algorithm uses the mach timeshare
 * decay based algorithm to achieve sharing between threads within the
 * same clutch bucket. The load/priority shifts etc. are all maintained
 * at the clutch bucket level and used for decay calculation of the
 * threads. The load sampling is still driven off the scheduler tick
 * for runnable clutch buckets (it does not use the new higher frequency
 * EWMA based load calculation). The idea is that the contention and load
 * within clutch_buckets should be limited enough to not see heavy decay
 * and timeshare effectively.
 */

/*
 * sched_clutch_thread_run_bucket_incr() / sched_clutch_run_bucket_incr()
 *
 * Increment the run count for the clutch bucket associated with the
 * thread.
 */
uint32_t
sched_clutch_thread_run_bucket_incr(
	thread_t thread,
	sched_bucket_t bucket)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return 0;
	}
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	return sched_clutch_run_bucket_incr(clutch, bucket);
}

static uint32_t
sched_clutch_run_bucket_incr(
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[bucket]);
	return sched_clutch_bucket_group_run_count_inc(clutch_bucket_group);
}

/*
 * sched_clutch_thread_run_bucket_decr() / sched_clutch_run_bucket_decr()
 *
 * Decrement the run count for the clutch bucket associated with the
 * thread.
 */
uint32_t
sched_clutch_thread_run_bucket_decr(
	thread_t thread,
	sched_bucket_t bucket)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return 0;
	}
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	return sched_clutch_run_bucket_decr(clutch, bucket);
}

static uint32_t
sched_clutch_run_bucket_decr(
	sched_clutch_t clutch,
	sched_bucket_t bucket)
{
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[bucket]);
	return sched_clutch_bucket_group_run_count_dec(clutch_bucket_group);
}

/*
 * sched_clutch_bucket_group_pri_shift_update()
 *
 * Routine to update the priority shift for a clutch bucket group,
 * necessary for timesharing correctly with priority decay within a
 * thread group + QoS.
 */
static void
sched_clutch_bucket_group_pri_shift_update(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	if (sched_clutch_bucket_is_above_timeshare(clutch_bucket_group->scbg_bucket)) {
		/* No timesharing needed for fixed priority Above UI threads */
		return;
	}

	/*
	 * Update the timeshare parameters for the clutch bucket group
	 * if they haven't been updated in this tick.
	 */
	uint32_t sched_ts = os_atomic_load(&clutch_bucket_group->scbg_timeshare_tick, relaxed);
	uint32_t current_sched_ts = os_atomic_load(&sched_tick, relaxed);
	if (sched_ts < current_sched_ts) {
		os_atomic_store(&clutch_bucket_group->scbg_timeshare_tick, current_sched_ts, relaxed);
		/* NCPU wide workloads should not experience decay */
		uint64_t bucket_group_run_count = os_atomic_load_wide(&clutch_bucket_group->scbg_blocked_data.scct_count, relaxed) - 1;
		uint32_t bucket_group_load = (uint32_t)(bucket_group_run_count / processor_avail_count);
		bucket_group_load = MIN(bucket_group_load, NRQS - 1);
		uint32_t pri_shift = sched_fixed_shift - sched_load_shifts[bucket_group_load];
		/* Ensure that the pri_shift value is reasonable */
		pri_shift = (pri_shift > SCHED_PRI_SHIFT_MAX) ? INT8_MAX : pri_shift;
		os_atomic_store(&clutch_bucket_group->scbg_pri_shift, pri_shift, relaxed);
	}
}

/*
 * sched_clutch_bucket_group_timeshare_update()
 *
 * Routine to update the priority shift and priority for the clutch_bucket_group
 * every sched_tick. For multi-cluster platforms, each QoS level will have multiple
 * clutch buckets with runnable threads in them. So it is important to maintain
 * the timesharing information at the clutch_bucket_group level instead of
 * individual clutch buckets (because the algorithm is trying to timeshare all
 * threads at the same QoS irrespective of which hierarchy they are enqueued in).
 *
 * The routine is called from the sched tick handling code to make sure this value
 * is updated at least once every sched tick. For clutch bucket groups which have
 * not been runnable for very long, the clutch_bucket_group maintains a "last
 * updated schedtick" parameter. As threads become runnable in the clutch bucket group,
 * if this value is outdated, we update the priority shift.
 *
 * Possible optimization:
 * - The current algorithm samples the load at most once every sched tick (125ms).
 *   This is prone to spikes in runnable counts; if that turns out to be
 *   a problem, a simple solution would be to do the EWMA trick to sample
 *   load at every load_tick (30ms) and use the averaged value for the pri
 *   shift calculation.
 */
static void
sched_clutch_bucket_group_timeshare_update(
	sched_clutch_bucket_group_t clutch_bucket_group,
	sched_clutch_bucket_t clutch_bucket,
	uint64_t ctime)
{
	if (sched_clutch_bucket_is_above_timeshare(clutch_bucket_group->scbg_bucket)) {
		/* No timesharing needed for fixed priority Above UI threads */
		return;
	}
	sched_clutch_bucket_group_pri_shift_update(clutch_bucket_group);
	/*
	 * Update the clutch bucket priority; this allows clutch buckets that have been pending
	 * for a long time to get an updated interactivity score.
	 */
	sched_clutch_bucket_update(clutch_bucket, clutch_bucket->scb_root, ctime, SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
}

/*
 * Calculate the CPU used by this thread and attribute it to the
 * thread's current scheduling bucket and clutch bucket group, or
 * a previous clutch bucket group if specified.
 * Also update the general scheduler CPU usage, matching
 * what we do for lightweight_update_priority().
 */
static inline void
sched_clutch_thread_tick_delta(thread_t thread, sched_clutch_bucket_group_t _Nullable clutch_bucket_group)
{
	uint32_t cpu_delta;
	sched_tick_delta(thread, cpu_delta);
	if (thread->pri_shift < INT8_MAX) {
		thread->sched_usage += cpu_delta;
	}
	thread->cpu_delta += cpu_delta;
	if (clutch_bucket_group != NULL) {
		sched_clutch_bucket_group_cpu_usage_update(clutch_bucket_group, cpu_delta);
	} else {
		sched_clutch_cpu_usage_update(thread, cpu_delta);
	}
}

/*
 * sched_clutch_thread_clutch_update()
 *
 * Routine called when the thread changes its thread group. The current
 * implementation relies on the fact that the thread group is changed only from
 * the context of the thread itself or when the thread is runnable but not in a
 * runqueue. Due to this fact, the thread group change causes only counter
 * updates in the old & new clutch buckets and no hierarchy changes. The routine
 * also attributes the CPU used so far to the old clutch.
 */
void
sched_clutch_thread_clutch_update(
	thread_t thread,
	sched_clutch_t old_clutch,
	sched_clutch_t new_clutch)
{
	if (old_clutch) {
		assert((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN);

		sched_clutch_run_bucket_decr(old_clutch, thread->th_sched_bucket);

		/* Attribute CPU usage with the old clutch */
		sched_clutch_bucket_group_t old_clutch_bucket_group = NULL;
		if (!SCHED_CLUTCH_THREAD_PSET_BOUND(thread)) {
			old_clutch_bucket_group = &(old_clutch->sc_clutch_groups[thread->th_sched_bucket]);
		}
		sched_clutch_thread_tick_delta(thread, old_clutch_bucket_group);
	}

	if (new_clutch) {
		sched_clutch_run_bucket_incr(new_clutch, thread->th_sched_bucket);
	}
}

/* Thread Insertion/Removal/Selection routines */

#if CONFIG_SCHED_EDGE

/*
 * Edge Scheduler Bound Thread Support
 *
 * The edge scheduler allows threads to be bound to specific psets. The
 * scheduler maintains a separate runq on the clutch root to hold these bound
 * threads. These bound threads count towards the root priority and thread
 * count, but are ignored for thread migration/steal decisions. Bound threads
 * that are enqueued in the separate runq have the th_bound_pset_enqueued flag
 * set to allow easy removal.
 *
 * Bound Threads Timesharing
 * The bound threads share the timesharing properties of the clutch bucket group
 * they are part of. They contribute to the load and use priority shifts/decay
 * values from the clutch bucket group.
 */

static boolean_t
sched_edge_bound_thread_insert(
	sched_clutch_root_t root_clutch,
	thread_t thread,
	integer_t options)
{
	/* Update the clutch runnable count and priority */
	sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_bound_buckets[thread->th_sched_bucket];
	if (root_bucket->scrb_bound_thread_runq.count == 0) {
		sched_clutch_root_bucket_runnable(root_bucket, root_clutch, mach_absolute_time());
	}

	assert((thread->th_bound_pset_enqueued) == false);
	run_queue_enqueue(&root_bucket->scrb_bound_thread_runq, thread, options);
	thread->th_bound_pset_enqueued = true;

	/*
	 * Trigger an update to the thread's clutch bucket group's priority shift parameters,
	 * needed for global timeshare within a clutch bucket group.
	 */
	sched_clutch_bucket_group_pri_shift_update(sched_clutch_bucket_group_for_thread(thread));

	/* Increment the urgency counter for the root if necessary */
	sched_clutch_root_urgency_inc(root_clutch, thread);

	int16_t root_old_pri = root_clutch->scr_priority;
	sched_clutch_root_pri_update(root_clutch);
	return root_clutch->scr_priority > root_old_pri;
}

static void
sched_edge_bound_thread_remove(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	sched_clutch_root_bucket_t root_bucket = &root_clutch->scr_bound_buckets[thread->th_sched_bucket];
	assert((thread->th_bound_pset_enqueued) == true);
	run_queue_remove(&root_bucket->scrb_bound_thread_runq, thread);
	thread->th_bound_pset_enqueued = false;

	/* Decrement the urgency counter for the root if necessary */
	sched_clutch_root_urgency_dec(root_clutch, thread);

	/* Update the clutch runnable count and priority */
	sched_clutch_thr_count_dec(&root_clutch->scr_thr_count);
	if (root_bucket->scrb_bound_thread_runq.count == 0) {
		sched_clutch_root_bucket_empty(root_bucket, root_clutch, mach_absolute_time());
	}
	sched_clutch_root_pri_update(root_clutch);

	/*
	 * Trigger an update to the thread's clutch bucket group's priority shift parameters,
	 * needed for global timeshare within a clutch bucket group.
	 */
	sched_clutch_bucket_group_pri_shift_update(sched_clutch_bucket_group_for_thread(thread));
}

/*
 * Edge Scheduler cluster shared resource threads load balancing
 *
 * The Edge scheduler attempts to load balance cluster shared resource intensive threads
 * across clusters in order to reduce contention on the shared resources. It achieves
 * that by maintaining the runnable and running shared resource load on each cluster
 * and balancing the load across multiple clusters.
 *
 * The current implementation for cluster shared resource load balancing looks at
 * the per-cluster load at thread runnable time to enqueue the thread in the appropriate
 * cluster. The thread is enqueued in the cluster bound runqueue to ensure idle CPUs
 * do not steal/rebalance shared resource threads. Some more details for the implementation:
 *
 * - When threads are tagged as shared resource, they go through the cluster selection logic
 *   which looks at cluster shared resource loads and picks a cluster accordingly. The thread is
 *   enqueued in the cluster bound runqueue.
 *
 * - When the threads start running and call avoid_processor, the load balancing logic will be
 *   invoked and cause the thread to be sent to a more preferred cluster if one exists and has
 *   no shared resource load.
 *
 * - If a CPU in a preferred cluster is going idle and that cluster has no more shared load,
 *   it will look at running shared resource threads on foreign clusters and actively rebalance them.
 *
 * - Runnable shared resource threads are not stolen by the preferred cluster CPUs as they
 *   go idle intentionally.
 *
 * - One caveat of this design is that if a preferred CPU has already run and finished its shared
 *   resource thread execution, it will not go out and steal the runnable thread in the non-preferred cluster.
 *   The rebalancing will happen when the thread actually runs on a non-preferred cluster and one of the
 *   events listed above happen.
 *
 * - Also it currently does not consider other properties such as thread priorities and
 *   qos level thread load in the thread placement decision.
 *
 * Edge Scheduler cluster shared resource thread scheduling policy
 *
 * The threads for shared resources can be scheduled using one of the two policies:
 *
 * EDGE_SHARED_RSRC_SCHED_POLICY_RR
 * This policy distributes the threads so that they spread across all available clusters
 * irrespective of type. The idea is that this scheduling policy will put a shared resource
 * thread on each cluster on the platform before it starts doubling up on clusters.
 *
 * EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST
 * This policy distributes threads so that the threads first fill up all the capacity on
 * the preferred cluster and its homogeneous peers before spilling to different core type.
 * The current implementation defines capacity based on the number of CPUs in the cluster;
 * so a cluster's shared resource is considered full if there are "n" runnable + running
 * shared resource threads on the cluster with n cpus. This policy is different from the
 * default scheduling policy of the edge scheduler since this always tries to fill up the
 * native clusters to capacity even when non-native clusters might be idle.
 */
__options_decl(edge_shared_rsrc_sched_policy_t, uint32_t, {
	EDGE_SHARED_RSRC_SCHED_POLICY_RR                = 0,
	EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST      = 1,
});

static const edge_shared_rsrc_sched_policy_t edge_shared_rsrc_policy[CLUSTER_SHARED_RSRC_TYPE_COUNT] = {
	[CLUSTER_SHARED_RSRC_TYPE_RR] = EDGE_SHARED_RSRC_SCHED_POLICY_RR,
	[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST] = EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST,
};

static void
sched_edge_shared_rsrc_runnable_load_incr(sched_clutch_root_t root_clutch, thread_t thread)
{
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_RR)) {
		root_clutch->scr_shared_rsrc_load_runnable[CLUSTER_SHARED_RSRC_TYPE_RR]++;
		thread->th_shared_rsrc_enqueued[CLUSTER_SHARED_RSRC_TYPE_RR] = true;
	}
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST)) {
		root_clutch->scr_shared_rsrc_load_runnable[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST]++;
		thread->th_shared_rsrc_enqueued[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST] = true;
	}
}

static void
sched_edge_shared_rsrc_runnable_load_decr(sched_clutch_root_t root_clutch, thread_t thread)
{
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		if (thread->th_shared_rsrc_enqueued[shared_rsrc_type]) {
			thread->th_shared_rsrc_enqueued[shared_rsrc_type] = false;
			root_clutch->scr_shared_rsrc_load_runnable[shared_rsrc_type]--;
		}
	}
}

uint16_t
sched_edge_shared_rsrc_runnable_load(sched_clutch_root_t root_clutch, cluster_shared_rsrc_type_t shared_rsrc_type)
{
	return root_clutch->scr_shared_rsrc_load_runnable[shared_rsrc_type];
}

static uint64_t
sched_edge_pset_cluster_shared_rsrc_load(processor_set_t pset, cluster_shared_rsrc_type_t shared_rsrc_type)
{
	/* Prevent migrations to derecommended clusters */
	if (!pset_is_recommended(pset)) {
		return UINT64_MAX;
	}
	return os_atomic_load(&pset->pset_cluster_shared_rsrc_load[shared_rsrc_type], relaxed);
}

/*
 * sched_edge_shared_rsrc_idle()
 *
 * Routine used to determine if the constrained resource for the pset is idle. This is
 * used by a CPU going idle to decide if it should rebalance a running shared resource
 * thread from a non-preferred cluster.
 */
static boolean_t
sched_edge_shared_rsrc_idle(processor_set_t pset, cluster_shared_rsrc_type_t shared_rsrc_type)
{
	return sched_edge_pset_cluster_shared_rsrc_load(pset, shared_rsrc_type) == 0;
}

/*
 * sched_edge_thread_shared_rsrc_type
 *
 * This routine decides if a given thread needs special handling for being a
 * heavy shared resource user. It is valid for the same thread to be using
 * several shared resources at the same time and have multiple policy flags set.
 * This routine determines which of those properties will be used for load
 * balancing and migration decisions.
 */
static cluster_shared_rsrc_type_t
sched_edge_thread_shared_rsrc_type(thread_t thread)
{
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_RR)) {
		return CLUSTER_SHARED_RSRC_TYPE_RR;
	}
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST)) {
		return CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST;
	}
	return CLUSTER_SHARED_RSRC_TYPE_NONE;
}

#endif /* CONFIG_SCHED_EDGE */

/*
 * sched_clutch_thread_bound_lookup()
 *
 * Routine to lookup the highest priority runnable thread in a bounded root bucket.
 */
static thread_t
sched_clutch_thread_bound_lookup(
	__unused sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t root_bucket,
	processor_t processor,
	thread_t _Nullable prev_thread)
{
	assert(root_bucket->scrb_bound == true);
	thread_t bound_thread = run_queue_peek(&root_bucket->scrb_bound_thread_runq);
	if ((prev_thread != NULL) &&
	    (bound_thread == NULL || sched_clutch_pri_greater_than_tiebreak(prev_thread->sched_pri, bound_thread->sched_pri, processor->first_timeslice))) {
		return prev_thread;
	}
	assert(bound_thread != THREAD_NULL);
	return bound_thread;
}

/*
 * Clutch Bucket Group Thread Counts and Pending time calculation
 *
 * The pending time on the clutch_bucket_group allows the scheduler to track if it
 * needs to ageout the CPU usage because the clutch_bucket_group has been pending for
 * a very long time. The pending time is set to the timestamp as soon as a thread becomes
 * runnable. When a thread is picked up for execution from this clutch_bucket_group, the
 * pending time is advanced to the time of thread selection.
 *
 * Since threads for a clutch bucket group can be added or removed from multiple CPUs
 * simulataneously, it is important that the updates to thread counts and pending timestamps
 * happen atomically. The implementation relies on the following aspects to make that work
 * as expected:
 * - The clutch scheduler would be deployed on single cluster platforms where the pset lock
 *   is held when threads are added/removed and pending timestamps are updated
 * - The thread count and pending timestamp can be updated atomically using double wide
 *   128 bit atomics
 *
 * Clutch bucket group interactivity timestamp and score updates also rely on the properties
 * above to atomically update the interactivity score for a clutch bucket group.
 */

#if CONFIG_SCHED_EDGE

static void
sched_clutch_bucket_group_thr_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_counter_time_t old_pending_data;
	sched_clutch_counter_time_t new_pending_data;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_pending_data.scct_packed, old_pending_data.scct_packed, new_pending_data.scct_packed, relaxed, {
		new_pending_data.scct_count = old_pending_data.scct_count + 1;
		new_pending_data.scct_timestamp = old_pending_data.scct_timestamp;
		if (old_pending_data.scct_count == 0) {
		        new_pending_data.scct_timestamp = timestamp;
		}
	});
}

static void
sched_clutch_bucket_group_thr_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_counter_time_t old_pending_data;
	sched_clutch_counter_time_t new_pending_data;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_pending_data.scct_packed, old_pending_data.scct_packed, new_pending_data.scct_packed, relaxed, {
		new_pending_data.scct_count = old_pending_data.scct_count - 1;
		if (new_pending_data.scct_count == 0) {
		        new_pending_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID;
		} else {
		        new_pending_data.scct_timestamp = timestamp;
		}
	});
}

static uint8_t
sched_clutch_bucket_group_pending_ageout(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	int bucket_load = sched_clutch_global_bucket_load_get(clutch_bucket_group->scbg_bucket);
	sched_clutch_counter_time_t old_pending_data;
	sched_clutch_counter_time_t new_pending_data;
	uint8_t cpu_usage_shift = 0;

	os_atomic_rmw_loop(&clutch_bucket_group->scbg_pending_data.scct_packed, old_pending_data.scct_packed, new_pending_data.scct_packed, relaxed, {
		cpu_usage_shift = 0;
		uint64_t old_pending_ts = old_pending_data.scct_timestamp;
		bool old_update = (old_pending_ts >= timestamp);
		bool no_pending_time = (old_pending_ts == SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID);
		bool no_bucket_load = (bucket_load == 0);
		if (old_update || no_pending_time || no_bucket_load) {
		        os_atomic_rmw_loop_give_up();
		}

		/* Calculate the time the clutch bucket group has been pending */
		uint64_t pending_delta = timestamp - old_pending_ts;
		/*
		 * Other buckets should get a chance to run first before artificially boosting
		 * this clutch bucket group's interactivity score, at least when the entire root
		 * bucket is getting a large enough share of CPU.
		 */
		uint64_t interactivity_delta = sched_clutch_bucket_group_pending_delta[clutch_bucket_group->scbg_bucket] + (bucket_load * sched_clutch_thread_quantum[clutch_bucket_group->scbg_bucket]);
		if (pending_delta < interactivity_delta) {
		        os_atomic_rmw_loop_give_up();
		}
		cpu_usage_shift = (pending_delta / interactivity_delta);
		new_pending_data.scct_timestamp = old_pending_ts + (cpu_usage_shift * interactivity_delta);
		new_pending_data.scct_count = old_pending_data.scct_count;
	});
	return cpu_usage_shift;
}

static boolean_t
sched_edge_thread_should_be_inserted_as_bound(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	/*
	 * Check if the thread is bound and is being enqueued in its desired bound cluster.
	 * If the thread is cluster-bound but to a different cluster, we should enqueue as unbound.
	 */
	if (SCHED_CLUTCH_THREAD_PSET_BOUND(thread) && (sched_edge_thread_bound_pset_id(thread) == root_clutch->scr_pset_id)) {
		return TRUE;
	}
	/*
	 * Use bound runqueue for shared resource threads. See "cluster shared resource
	 * threads load balancing" section for details.
	 */
	if (sched_edge_thread_shared_rsrc_type(thread) != CLUSTER_SHARED_RSRC_TYPE_NONE) {
		return TRUE;
	}
	return FALSE;
}

#else /* CONFIG_SCHED_EDGE */

/*
 * For the clutch scheduler, atomicity is ensured by making sure all operations
 * are happening under the pset lock of the only cluster present on the platform.
 */
static void
sched_clutch_bucket_group_thr_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&sched_boot_pset->pset_clutch_root);
	if (clutch_bucket_group->scbg_pending_data.scct_count == 0) {
		clutch_bucket_group->scbg_pending_data.scct_timestamp = timestamp;
	}
	clutch_bucket_group->scbg_pending_data.scct_count++;
}

static void
sched_clutch_bucket_group_thr_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&sched_boot_pset->pset_clutch_root);
	clutch_bucket_group->scbg_pending_data.scct_count--;
	if (clutch_bucket_group->scbg_pending_data.scct_count == 0) {
		clutch_bucket_group->scbg_pending_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID;
	} else {
		clutch_bucket_group->scbg_pending_data.scct_timestamp = timestamp;
	}
}

static uint8_t
sched_clutch_bucket_group_pending_ageout(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	sched_clutch_hierarchy_locked_assert(&sched_boot_pset->pset_clutch_root);
	int bucket_load = sched_clutch_global_bucket_load_get(clutch_bucket_group->scbg_bucket);
	uint64_t old_pending_ts = clutch_bucket_group->scbg_pending_data.scct_timestamp;
	bool old_update = (old_pending_ts >= timestamp);
	bool no_pending_time = (old_pending_ts == SCHED_CLUTCH_BUCKET_GROUP_PENDING_INVALID);
	bool no_bucket_load = (bucket_load == 0);
	if (old_update || no_pending_time || no_bucket_load) {
		return 0;
	}
	uint64_t pending_delta = timestamp - old_pending_ts;
	/*
	 * Other buckets should get a chance to run first before artificially boosting
	 * this clutch bucket group's interactivity score, at least when the entire root
	 * bucket is getting a large enough share of CPU.
	 */
	uint64_t interactivity_delta = sched_clutch_bucket_group_pending_delta[clutch_bucket_group->scbg_bucket] + (bucket_load * sched_clutch_thread_quantum[clutch_bucket_group->scbg_bucket]);
	if (pending_delta < interactivity_delta) {
		return 0;
	}
	uint8_t cpu_usage_shift = (pending_delta / interactivity_delta);
	clutch_bucket_group->scbg_pending_data.scct_timestamp = old_pending_ts + (cpu_usage_shift * interactivity_delta);
	return cpu_usage_shift;
}

#endif /* CONFIG_SCHED_EDGE */

static uint8_t
sched_clutch_bucket_group_interactivity_score_calculate(
	sched_clutch_bucket_group_t clutch_bucket_group,
	uint64_t timestamp)
{
	if (sched_clutch_bucket_is_above_timeshare(clutch_bucket_group->scbg_bucket)) {
		/*
		 * Since the root bucket selection algorithm for Above UI looks at clutch bucket
		 * priorities, make sure all AboveUI buckets are marked interactive.
		 */
		assert(clutch_bucket_group->scbg_interactivity_data.scct_count == (2 * sched_clutch_bucket_group_interactive_pri));
		return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
	}
	/* Check if the clutch bucket group CPU usage needs to be aged out due to pending time */
	uint8_t pending_intervals = sched_clutch_bucket_group_pending_ageout(clutch_bucket_group, timestamp);
	/* Adjust CPU stats based on the calculated shift and to make sure only recent behavior is used */
	sched_clutch_bucket_group_cpu_adjust(clutch_bucket_group, pending_intervals);
	uint8_t interactivity_score = sched_clutch_interactivity_from_cpu_data(clutch_bucket_group);
	/* Write back any interactivity score update */
#if CONFIG_SCHED_EDGE
	sched_clutch_counter_time_t old_interactivity_data;
	sched_clutch_counter_time_t new_interactivity_data;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_interactivity_data.scct_packed, old_interactivity_data.scct_packed, new_interactivity_data.scct_packed, relaxed, {
		new_interactivity_data.scct_count = old_interactivity_data.scct_count;
		if (old_interactivity_data.scct_timestamp >= timestamp) {
		        os_atomic_rmw_loop_give_up();
		}
		new_interactivity_data.scct_timestamp = timestamp;
		if (old_interactivity_data.scct_timestamp != 0) {
		        new_interactivity_data.scct_count = interactivity_score;
		}
	});
	return (uint8_t)new_interactivity_data.scct_count;
#else /* !CONFIG_SCHED_EDGE */
	sched_clutch_hierarchy_locked_assert(&sched_boot_pset->pset_clutch_root);
	if (timestamp > clutch_bucket_group->scbg_interactivity_data.scct_timestamp) {
		clutch_bucket_group->scbg_interactivity_data.scct_count = interactivity_score;
		clutch_bucket_group->scbg_interactivity_data.scct_timestamp = timestamp;
	}
	return (uint8_t)clutch_bucket_group->scbg_interactivity_data.scct_count;
#endif /* !CONFIG_SCHED_EDGE */
}

/*
 * Clutch Bucket Group Run Count and Blocked Time Accounting
 *
 * The clutch bucket group maintains the number of runnable/running threads in the group.
 * Since the blocked time of the clutch bucket group is based on this count, it is
 * important to make sure the blocking timestamp and the run count are updated atomically.
 *
 * Since the run count increments happen without any pset locks held, the scheduler updates
 * the count & timestamp using double wide 128 bit atomics.
 */

static uint32_t
sched_clutch_bucket_group_run_count_inc(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	sched_clutch_counter_time_t old_blocked_data;
	sched_clutch_counter_time_t new_blocked_data;

	bool update_blocked_time = false;
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_blocked_data.scct_packed, old_blocked_data.scct_packed, new_blocked_data.scct_packed, relaxed, {
		new_blocked_data.scct_count = old_blocked_data.scct_count + 1;
		new_blocked_data.scct_timestamp = old_blocked_data.scct_timestamp;
		update_blocked_time = false;
		if (old_blocked_data.scct_count == 0) {
		        new_blocked_data.scct_timestamp = SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID;
		        update_blocked_time = true;
		}
	});
	if (update_blocked_time && (old_blocked_data.scct_timestamp != SCHED_CLUTCH_BUCKET_GROUP_BLOCKED_TS_INVALID)) {
		uint64_t ctime = mach_absolute_time();
		if (ctime > old_blocked_data.scct_timestamp) {
			uint64_t blocked_time = ctime - old_blocked_data.scct_timestamp;
			blocked_time = MIN(blocked_time, sched_clutch_bucket_group_adjust_threshold);
			os_atomic_add(&(clutch_bucket_group->scbg_cpu_data.cpu_data.scbcd_cpu_blocked), (clutch_cpu_data_t)blocked_time, relaxed);
		}
	}
	return (uint32_t)new_blocked_data.scct_count;
}

static uint32_t
sched_clutch_bucket_group_run_count_dec(
	sched_clutch_bucket_group_t clutch_bucket_group)
{
	sched_clutch_counter_time_t old_blocked_data;
	sched_clutch_counter_time_t new_blocked_data;

	uint64_t ctime = mach_absolute_time();
	os_atomic_rmw_loop(&clutch_bucket_group->scbg_blocked_data.scct_packed, old_blocked_data.scct_packed, new_blocked_data.scct_packed, relaxed, {
		new_blocked_data.scct_count = old_blocked_data.scct_count - 1;
		new_blocked_data.scct_timestamp = old_blocked_data.scct_timestamp;
		if (new_blocked_data.scct_count == 0) {
		        new_blocked_data.scct_timestamp = ctime;
		}
	});
	return (uint32_t)new_blocked_data.scct_count;
}

static inline sched_clutch_bucket_t
sched_clutch_bucket_for_thread(
	sched_clutch_root_t root_clutch,
	thread_t thread)
{
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);

	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[thread->th_sched_bucket]);
	sched_clutch_bucket_t clutch_bucket = &(clutch_bucket_group->scbg_clutch_buckets[root_clutch->scr_pset_id]);
	assert((clutch_bucket->scb_root == NULL) || (clutch_bucket->scb_root == root_clutch));

	return clutch_bucket;
}

static inline sched_clutch_bucket_group_t
sched_clutch_bucket_group_for_thread(thread_t prev_thread)
{
	sched_clutch_t clutch = sched_clutch_for_thread_group(prev_thread->thread_group);
	return &clutch->sc_clutch_groups[prev_thread->th_sched_bucket];
}

/*
 * sched_clutch_thread_insert()
 *
 * Routine to insert a thread into the sched clutch hierarchy.
 * Update the counts at all levels of the hierarchy and insert the nodes
 * as they become runnable. Always called with the pset lock held.
 */
static boolean_t
sched_clutch_thread_insert(
	sched_clutch_root_t root_clutch,
	thread_t thread,
	integer_t options)
{
	boolean_t result = FALSE;

	sched_clutch_hierarchy_locked_assert(root_clutch);
#if CONFIG_SCHED_EDGE
	sched_edge_pset_cumulative_count_incr(root_clutch, thread->th_sched_bucket);
	sched_edge_shared_rsrc_runnable_load_incr(root_clutch, thread);

	if (sched_edge_thread_should_be_inserted_as_bound(root_clutch, thread)) {
		/*
		 * Includes threads bound to this specific cluster as well as all
		 * shared resource threads.
		 */
		return sched_edge_bound_thread_insert(root_clutch, thread, options);
	}
#endif /* CONFIG_SCHED_EDGE */

	uint64_t current_timestamp = mach_absolute_time();
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);
	sched_clutch_bucket_t clutch_bucket = sched_clutch_bucket_for_thread(root_clutch, thread);
	assert((clutch_bucket->scb_root == NULL) || (clutch_bucket->scb_root == root_clutch));

	/*
	 * Thread linkage in clutch_bucket
	 *
	 * A thread has a few linkages within the clutch bucket:
	 * - A stable priority queue linkage which is the main runqueue (based on sched_pri) for the clutch bucket
	 * - A regular priority queue linkage which is based on thread's base/promoted pri (used for clutch bucket priority calculation)
	 * - A queue linkage used for timesharing operations of threads at the scheduler tick
	 */

	/* Insert thread into the clutch_bucket stable priority runqueue using sched_pri */
	thread->th_clutch_runq_link.stamp = current_timestamp;
	priority_queue_entry_set_sched_pri(&clutch_bucket->scb_thread_runq, &thread->th_clutch_runq_link, thread->sched_pri,
	    (options & SCHED_TAILQ) ? PRIORITY_QUEUE_ENTRY_NONE : PRIORITY_QUEUE_ENTRY_PREEMPTED);
	priority_queue_insert(&clutch_bucket->scb_thread_runq, &thread->th_clutch_runq_link);

	/* Insert thread into clutch_bucket priority queue based on the promoted or base priority */
	priority_queue_entry_set_sched_pri(&clutch_bucket->scb_clutchpri_prioq, &thread->th_clutch_pri_link,
	    sched_thread_sched_pri_promoted(thread) ? thread->sched_pri : thread->base_pri, false);
	priority_queue_insert(&clutch_bucket->scb_clutchpri_prioq, &thread->th_clutch_pri_link);

	/* Insert thread into timesharing queue of the clutch bucket */
	enqueue_tail(&clutch_bucket->scb_thread_timeshare_queue, &thread->th_clutch_timeshare_link);

	/* Increment the urgency counter for the root if necessary */
	sched_clutch_root_urgency_inc(root_clutch, thread);

	os_atomic_inc(&clutch->sc_thr_count, relaxed);
	sched_clutch_bucket_group_thr_count_inc(clutch_bucket->scb_group, current_timestamp);

	/* Enqueue the clutch into the hierarchy (if needed) and update properties; pick the insertion order based on thread options */
	sched_clutch_bucket_options_t scb_options = (options & SCHED_HEADQ) ? SCHED_CLUTCH_BUCKET_OPTIONS_HEADQ : SCHED_CLUTCH_BUCKET_OPTIONS_TAILQ;
	if (clutch_bucket->scb_thr_count == 0) {
		sched_clutch_thr_count_inc(&clutch_bucket->scb_thr_count);
		sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
		result = sched_clutch_bucket_runnable(clutch_bucket, root_clutch, current_timestamp, scb_options);
	} else {
		sched_clutch_thr_count_inc(&clutch_bucket->scb_thr_count);
		sched_clutch_thr_count_inc(&root_clutch->scr_thr_count);
		result = sched_clutch_bucket_update(clutch_bucket, root_clutch, current_timestamp, scb_options);
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THR_COUNT) | DBG_FUNC_NONE,
	    root_clutch->scr_pset_id, thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket,
	    SCHED_CLUTCH_DBG_THR_COUNT_PACK(root_clutch->scr_thr_count, os_atomic_load(&clutch->sc_thr_count, relaxed), clutch_bucket->scb_thr_count));
	return result;
}

/*
 * sched_clutch_thread_remove()
 *
 * Routine to remove a thread from the sched clutch hierarchy.
 * Update the counts at all levels of the hierarchy and remove the nodes
 * as they become empty. Always called with the pset lock held.
 */
static void
sched_clutch_thread_remove(
	sched_clutch_root_t root_clutch,
	thread_t thread,
	uint64_t current_timestamp,
	sched_clutch_bucket_options_t options)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);
#if CONFIG_SCHED_EDGE
	sched_edge_pset_cumulative_count_decr(root_clutch, thread->th_sched_bucket);
	sched_edge_shared_rsrc_runnable_load_decr(root_clutch, thread);

	if (thread->th_bound_pset_enqueued) {
		sched_edge_bound_thread_remove(root_clutch, thread);
		return;
	}
#endif /* CONFIG_SCHED_EDGE */
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	assert(thread->thread_group == clutch->sc_tg);
	thread_assert_runq_nonnull(thread);

	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[thread->th_sched_bucket]);
	sched_clutch_bucket_t clutch_bucket = &(clutch_bucket_group->scbg_clutch_buckets[root_clutch->scr_pset_id]);
	assert(clutch_bucket->scb_root == root_clutch);

	/* Decrement the urgency counter for the root if necessary */
	sched_clutch_root_urgency_dec(root_clutch, thread);
	/* Remove thread from the clutch_bucket */
	priority_queue_remove(&clutch_bucket->scb_thread_runq, &thread->th_clutch_runq_link);
	remqueue(&thread->th_clutch_timeshare_link);

	priority_queue_remove(&clutch_bucket->scb_clutchpri_prioq, &thread->th_clutch_pri_link);

	/*
	 * Warning: After this point, the thread's scheduling fields may be
	 * modified by other cores that acquire the thread lock.
	 */
	thread_clear_runq(thread);

	/* Update counts at various levels of the hierarchy */
	os_atomic_dec(&clutch->sc_thr_count, relaxed);
	sched_clutch_bucket_group_thr_count_dec(clutch_bucket->scb_group, current_timestamp);
	sched_clutch_thr_count_dec(&root_clutch->scr_thr_count);
	sched_clutch_thr_count_dec(&clutch_bucket->scb_thr_count);

	/* Remove the clutch from hierarchy (if needed) and update properties */
	if (clutch_bucket->scb_thr_count == 0) {
		sched_clutch_bucket_empty(clutch_bucket, root_clutch, current_timestamp, options);
	} else {
		sched_clutch_bucket_update(clutch_bucket, root_clutch, current_timestamp, options);
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THR_COUNT) | DBG_FUNC_NONE,
	    root_clutch->scr_pset_id, thread_group_get_id(clutch_bucket->scb_group->scbg_clutch->sc_tg), clutch_bucket->scb_bucket,
	    SCHED_CLUTCH_DBG_THR_COUNT_PACK(root_clutch->scr_thr_count, os_atomic_load(&clutch->sc_thr_count, relaxed), clutch_bucket->scb_thr_count));
}

/*
 * sched_clutch_thread_unbound_lookup()
 *
 * Routine to find the highest unbound thread in the root clutch.
 * Helps find threads easily for steal/migrate scenarios in the
 * Edge scheduler.
 */
static thread_t
sched_clutch_thread_unbound_lookup(
	sched_clutch_root_t root_clutch,
	sched_clutch_root_bucket_t root_bucket,
	processor_t _Nullable processor,
	thread_t _Nullable prev_thread)
{
	assert(processor != NULL || prev_thread == NULL);
	assert(root_bucket->scrb_bound == false);
	sched_clutch_hierarchy_locked_assert(root_clutch);

	/* Find the highest priority clutch bucket in this root bucket */
	bool chose_prev_thread = false;
	sched_clutch_bucket_t clutch_bucket = sched_clutch_root_bucket_highest_clutch_bucket(root_clutch, root_bucket, processor, prev_thread, &chose_prev_thread);
	assert(clutch_bucket != NULL);

	if (chose_prev_thread) {
		/* We have determined that prev_thread is the highest thread, based on the Clutch bucket level policy */
		assert(processor != NULL && prev_thread != NULL);
		return prev_thread;
	}

	/* Find the highest priority runnable thread in this clutch bucket */
	thread_t thread = priority_queue_max(&clutch_bucket->scb_thread_runq, struct thread, th_clutch_runq_link);
	assert(thread != NULL);

	/* Consider the previous thread */
	if (prev_thread != NULL &&
	    sched_clutch_bucket_for_thread(root_clutch, prev_thread) == clutch_bucket &&
	    sched_clutch_pri_greater_than_tiebreak(prev_thread->sched_pri, thread->sched_pri, processor->first_timeslice)) {
		thread = prev_thread;
	}

	return thread;
}

static sched_clutch_root_bucket_t
sched_clutch_root_bucket_for_thread(
	sched_clutch_root_t root_clutch,
	thread_t prev_thread)
{
#if CONFIG_SCHED_EDGE
	if (sched_edge_thread_should_be_inserted_as_bound(root_clutch, prev_thread)) {
		return &root_clutch->scr_bound_buckets[prev_thread->th_sched_bucket];
	}
#endif /* CONFIG_SCHED_EDGE */
	return &root_clutch->scr_unbound_buckets[prev_thread->th_sched_bucket];
}

/*
 * sched_clutch_hierarchy_thread_highest()
 *
 * Routine to traverse the Clutch hierarchy and return the highest thread which
 * should be selected to run next, optionally comparing against the previously
 * running thread. Removes the highest thread with sched_clutch_thread_remove()
 * depending on the traverse mode and whether it is the previously running thread.
 * Always called with the pset lock held.
 */
static thread_t
sched_clutch_hierarchy_thread_highest(
	sched_clutch_root_t root_clutch,
	processor_t processor,
	thread_t _Nullable prev_thread,
	sched_clutch_traverse_mode_t mode)
{
	assert(mode != SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY || prev_thread == NULL);
	sched_clutch_hierarchy_locked_assert(root_clutch);

	thread_t highest_thread = NULL;
	uint64_t current_timestamp = mach_absolute_time();
	bool chose_prev_thread = false;
	sched_clutch_dbg_thread_select_packed_t debug_info = {0};
	sched_clutch_root_bucket_t prev_root_bucket = prev_thread != NULL ? sched_clutch_root_bucket_for_thread(root_clutch, prev_thread) : NULL;
	sched_clutch_root_bucket_t root_bucket = sched_clutch_root_highest_root_bucket(root_clutch, current_timestamp, SCHED_CLUTCH_HIGHEST_ROOT_BUCKET_ALL, prev_root_bucket, prev_thread, &chose_prev_thread, mode, &debug_info);
	if (chose_prev_thread) {
		/* We disambiguated that we want to keep running the previous thread */
		highest_thread = processor->active_thread;
		goto done_selecting_thread;
	}
	if (root_bucket == NULL) {
		/* The Clutch hierarchy has no runnable threads, including the previous thread */
		assert(sched_clutch_root_count(root_clutch) == 0);
		assert(prev_thread == NULL);
		return NULL;
	}
	if (root_bucket != prev_root_bucket) {
		/* We have ruled out continuing to run the previous thread, based on the root bucket level policy */
		prev_thread = NULL;
		assert((mode == SCHED_CLUTCH_TRAVERSE_CHECK_PREEMPT) || (prev_root_bucket == NULL) ||
		    (prev_root_bucket->scrb_bucket >= root_bucket->scrb_bucket) || (root_bucket->scrb_starvation_avoidance) ||
		    (prev_root_bucket->scrb_bound != root_bucket->scrb_bound) ||
		    (root_bucket->scrb_warp_remaining > 0 && root_bucket->scrb_warped_deadline > current_timestamp && prev_root_bucket->scrb_warp_remaining == 0));
	}

	if (root_bucket->scrb_bound) {
		highest_thread = sched_clutch_thread_bound_lookup(root_clutch, root_bucket, processor, prev_thread);
	} else {
		highest_thread = sched_clutch_thread_unbound_lookup(root_clutch, root_bucket, processor, prev_thread);
	}

	if (mode == SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY ||
	    (mode == SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT && highest_thread != processor->active_thread)) {
		assert(mode != SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY || highest_thread != processor->active_thread);
		sched_clutch_thread_remove(root_clutch, highest_thread, current_timestamp, SCHED_CLUTCH_BUCKET_OPTIONS_SAMEPRI_RR);
	}

done_selecting_thread:
	debug_info.trace_data.version = SCHED_CLUTCH_DBG_THREAD_SELECT_PACKED_VERSION;
	debug_info.trace_data.traverse_mode = mode;
	debug_info.trace_data.pset_id = root_clutch->scr_pset_id;
	debug_info.trace_data.selection_was_pset_bound = root_bucket->scrb_bound;
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_CLUTCH_THREAD_SELECT) | DBG_FUNC_NONE,
	    thread_tid(highest_thread), thread_group_get_id(highest_thread->thread_group), root_bucket->scrb_bucket, debug_info.scdts_trace_data_packed, 0);
	return highest_thread;
}

/* High level global accessor routines */

/*
 * sched_clutch_root_urgency()
 *
 * Routine to get the urgency of the highest runnable
 * thread in the hierarchy.
 */
static uint32_t
sched_clutch_root_urgency(
	sched_clutch_root_t root_clutch)
{
	return root_clutch->scr_urgency;
}

/*
 * sched_clutch_root_count_sum()
 *
 * The count_sum mechanism is used for scheduler runq
 * statistics calculation. Its only useful for debugging
 * purposes; since it takes a mach_absolute_time() on
 * other scheduler implementations, its better to avoid
 * populating this until absolutely necessary.
 */
static uint32_t
sched_clutch_root_count_sum(
	__unused sched_clutch_root_t root_clutch)
{
	return 0;
}

/*
 * sched_clutch_root_priority()
 *
 * Routine to get the priority of the highest runnable
 * thread in the hierarchy.
 */
static int
sched_clutch_root_priority(
	sched_clutch_root_t root_clutch)
{
	return root_clutch->scr_priority;
}

/*
 * sched_clutch_root_count()
 *
 * Returns total number of runnable threads in the hierarchy.
 */
uint32_t
sched_clutch_root_count(
	sched_clutch_root_t root_clutch)
{
	return root_clutch->scr_thr_count;
}

/*
 * sched_clutch_thread_pri_shift()
 *
 * Routine to get the priority shift value for a thread.
 * Since the timesharing is done at the clutch_bucket level,
 * this routine gets the clutch_bucket and retrieves the
 * values from there.
 */
uint32_t
sched_clutch_thread_pri_shift(
	thread_t thread,
	sched_bucket_t bucket)
{
	if (!SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		return INT8_MAX;
	}
	assert(bucket != TH_BUCKET_RUN);
	sched_clutch_t clutch = sched_clutch_for_thread(thread);
	sched_clutch_bucket_group_t clutch_bucket_group = &(clutch->sc_clutch_groups[bucket]);
	return os_atomic_load(&clutch_bucket_group->scbg_pri_shift, relaxed);
}

#pragma mark -- Clutch Scheduler Algorithm

static void
sched_clutch_init(void);

static thread_t
sched_clutch_steal_thread(processor_set_t pset);

#if !SCHED_TEST_HARNESS

static void
sched_clutch_thread_update_scan(sched_update_scan_context_t scan_context);

#endif /* !SCHED_TEST_HARNESS */

static boolean_t
sched_clutch_processor_enqueue(processor_t processor, thread_t thread,
    sched_options_t options);

static boolean_t
sched_clutch_processor_queue_remove(processor_t processor, thread_t thread);

static ast_t
sched_clutch_processor_csw_check(processor_t processor);

static boolean_t
sched_clutch_processor_queue_has_priority(processor_t processor, int priority, boolean_t gte);

static int
sched_clutch_runq_count(processor_t processor);

static boolean_t
sched_clutch_processor_queue_empty(processor_t processor);

#if !SCHED_TEST_HARNESS

static uint64_t
sched_clutch_runq_stats_count_sum(processor_t processor);

#endif /* !SCHED_TEST_HARNESS */

static int
sched_clutch_processor_bound_count(processor_t processor);

static void
sched_clutch_pset_init(processor_set_t pset);

static void
sched_clutch_processor_init(processor_t processor);

static thread_t
sched_clutch_processor_highest_thread(processor_t processor, sched_clutch_traverse_mode_t mode);

static thread_t
sched_clutch_choose_thread(processor_t processor, int priority, thread_t prev_thread, ast_t reason);

#if !SCHED_TEST_HARNESS

static void
sched_clutch_processor_queue_shutdown(processor_t processor, struct pulled_thread_queue * threadq);

#endif /* !SCHED_TEST_HARNESS */

static sched_mode_t
sched_clutch_initial_thread_sched_mode(task_t parent_task);

static uint32_t
sched_clutch_initial_quantum_size(thread_t thread);

static uint32_t
sched_clutch_run_incr(thread_t thread);

static uint32_t
sched_clutch_run_decr(thread_t thread);

static void
sched_clutch_update_thread_bucket(thread_t thread);

#if !SCHED_TEST_HARNESS

static void
sched_clutch_thread_group_recommendation_change(struct thread_group *tg, cluster_type_t new_recommendation);

#endif /* !SCHED_TEST_HARNESS */

const struct sched_dispatch_table sched_clutch_dispatch = {
	.sched_name                                     = "clutch",
	.init                                           = sched_clutch_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_clutch_processor_init,
	.pset_init                                      = sched_clutch_pset_init,
	.choose_thread                                  = sched_clutch_choose_thread,
	.steal_thread_enabled                           = sched_steal_thread_enabled,
	.steal_thread                                   = sched_clutch_steal_thread,
	.processor_enqueue                              = sched_clutch_processor_enqueue,
	.processor_queue_remove                         = sched_clutch_processor_queue_remove,
	.processor_queue_empty                          = sched_clutch_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_clutch_processor_csw_check,
	.processor_queue_has_priority                   = sched_clutch_processor_queue_has_priority,
	.initial_quantum_size                           = sched_clutch_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_clutch_initial_thread_sched_mode,
	.processor_runq_count                           = sched_clutch_runq_count,
	.processor_bound_count                          = sched_clutch_processor_bound_count,
	.multiple_psets_enabled                         = TRUE,
	.avoid_processor_enabled                        = FALSE,
	.thread_avoid_processor                         = NULL,
	.update_thread_bucket                           = sched_clutch_update_thread_bucket,
	.cpu_init_completed                             = NULL,
	.thread_eligible_for_pset                       = NULL,
	.update_pset_load_average                       = sched_update_pset_load_average,
	.update_pset_avg_execution_time                 = sched_update_pset_avg_execution_time,

	.rt_choose_processor                            = sched_rt_choose_processor,
	.rt_steal_thread                                = NULL,
	.rt_init_pset                                   = sched_rt_init_pset,
	.rt_init_completed                              = sched_rt_init_completed,
	.rt_runq_count_sum                              = sched_rt_runq_count_sum,

#if !SCHED_TEST_HARNESS
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_node                                    = sched_choose_node,
	.choose_processor                               = choose_processor,
	.processor_queue_shutdown                       = sched_clutch_processor_queue_shutdown,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_default_quantum_expire,
	.processor_runq_stats_count_sum                 = sched_clutch_runq_stats_count_sum,
	.thread_update_scan                             = sched_clutch_thread_update_scan,
	.processor_balance                              = sched_SMT_balance,
	.qos_max_parallelism                            = sched_qos_max_parallelism,
	.check_spill                                    = sched_check_spill,
	.ipi_policy                                     = sched_ipi_policy,
	.thread_should_yield                            = sched_thread_should_yield,
	.run_count_incr                                 = sched_clutch_run_incr,
	.run_count_decr                                 = sched_clutch_run_decr,
	.pset_made_schedulable                          = sched_pset_made_schedulable,
	.thread_group_recommendation_change             = sched_clutch_thread_group_recommendation_change,

	.rt_queue_shutdown                              = sched_rt_queue_shutdown,
	.rt_runq_scan                                   = sched_rt_runq_scan,
#endif /* !SCHED_TEST_HARNESS */
};

__attribute__((always_inline))
static inline run_queue_t
sched_clutch_bound_runq(processor_t processor)
{
	return &processor->runq;
}

__attribute__((always_inline))
static inline sched_clutch_root_t
sched_clutch_processor_root_clutch(processor_t processor)
{
	return &processor->processor_set->pset_clutch_root;
}

__attribute__((always_inline))
static inline run_queue_t
sched_clutch_thread_bound_runq(processor_t processor, __assert_only thread_t thread)
{
	assert(thread->bound_processor == processor);
	return sched_clutch_bound_runq(processor);
}

static uint32_t
sched_clutch_initial_quantum_size(thread_t thread)
{
	if (thread == THREAD_NULL) {
		return std_quantum;
	}
	assert(sched_clutch_thread_quantum[thread->th_sched_bucket] <= UINT32_MAX);
	return (uint32_t)sched_clutch_thread_quantum[thread->th_sched_bucket];
}

static sched_mode_t
sched_clutch_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task) {
		return TH_MODE_FIXED;
	} else {
		return TH_MODE_TIMESHARE;
	}
}

static void
sched_clutch_processor_init(processor_t processor)
{
	run_queue_init(&processor->runq);
}

static void
sched_clutch_pset_init(processor_set_t pset)
{
	sched_clutch_root_init(&pset->pset_clutch_root, pset);
}

static void
sched_clutch_tunables_init(void)
{
	sched_clutch_us_to_abstime(sched_clutch_root_bucket_wcel_us, sched_clutch_root_bucket_wcel);
	sched_clutch_us_to_abstime(sched_clutch_root_bucket_warp_us, sched_clutch_root_bucket_warp);
	sched_clutch_us_to_abstime(sched_clutch_thread_quantum_us, sched_clutch_thread_quantum);
	clock_interval_to_absolutetime_interval(SCHED_CLUTCH_BUCKET_GROUP_ADJUST_THRESHOLD_USECS,
	    NSEC_PER_USEC, &sched_clutch_bucket_group_adjust_threshold);
	assert(sched_clutch_bucket_group_adjust_threshold <= CLUTCH_CPU_DATA_MAX);
	sched_clutch_us_to_abstime(sched_clutch_bucket_group_pending_delta_us, sched_clutch_bucket_group_pending_delta);
}

static void
sched_clutch_init(void)
{
	if (!PE_parse_boot_argn("sched_clutch_bucket_group_interactive_pri", &sched_clutch_bucket_group_interactive_pri, sizeof(sched_clutch_bucket_group_interactive_pri))) {
		sched_clutch_bucket_group_interactive_pri = SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT;
	}
	sched_timeshare_init();
	sched_clutch_tunables_init();
}

static inline bool
sched_clutch_pri_greater_than_tiebreak(int pri_one, int pri_two, bool one_wins_ties)
{
	if (one_wins_ties) {
		return pri_one >= pri_two;
	} else {
		return pri_one > pri_two;
	}
}

/*
 * sched_clutch_processor_highest_thread()
 *
 * Routine to determine the highest thread on the entire cluster runqueue which
 * should be selected to run next, optionally comparing against the previously
 * running thread. Removes the highest thread from the runqueue, depending on the
 * traverse mode and whether the highest thread is the previously running thread.
 *
 * Always called with the pset lock held. Assumes that processor->active_thread
 * may be locked and modified by another processor.
 */
static thread_t
sched_clutch_processor_highest_thread(
	processor_t      processor,
	sched_clutch_traverse_mode_t mode)
{
	sched_clutch_root_t root_clutch = sched_clutch_processor_root_clutch(processor);
	int clutch_pri = sched_clutch_root_priority(root_clutch);
	run_queue_t bound_runq = sched_clutch_bound_runq(processor);
	int bound_pri = bound_runq->highq;

	bool has_prev_thread = mode == SCHED_CLUTCH_TRAVERSE_CHECK_PREEMPT || mode == SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT;
	thread_t prev_thread = has_prev_thread ? processor->active_thread : NULL;

	if (bound_runq->count == 0 && root_clutch->scr_thr_count == 0) {
		/* The runqueue is totally empty */
		assert(bound_pri < MINPRI && clutch_pri < MINPRI);
		return prev_thread;
	}

	if (has_prev_thread) {
		if (prev_thread->sched_pri >= BASEPRI_RTQUEUES) {
			/* The previous thread is real-time and thus guaranteed higher than the non-RT runqueue */
			return prev_thread;
		}
		/* Allow the previous thread to influence the priority comparison of Clutch hierarchy vs. processor-bound runqueue */
		if (prev_thread->bound_processor != NULL) {
			bound_pri = MAX(bound_pri, prev_thread->sched_pri);
		} else {
			clutch_pri = MAX(clutch_pri, prev_thread->sched_pri);
		}
	}

	bool prev_thread_is_not_processor_bound = has_prev_thread && (prev_thread->bound_processor == NULL);
	bool prev_thread_is_processor_bound = has_prev_thread && (prev_thread->bound_processor != NULL);
	thread_t next_thread = prev_thread;
	if (clutch_pri > bound_pri) {
		if (root_clutch->scr_thr_count == 0) {
			goto found_thread;
		}
		next_thread = sched_clutch_hierarchy_thread_highest(root_clutch, processor, prev_thread_is_not_processor_bound ? prev_thread : NULL, mode);
	} else {
		if (bound_runq->count == 0 ||
		    (prev_thread_is_processor_bound && sched_clutch_pri_greater_than_tiebreak(prev_thread->sched_pri, bound_runq->highq, processor->first_timeslice))) {
			goto found_thread;
		}
		next_thread = (mode == SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT || mode == SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY) ?
		    run_queue_dequeue(bound_runq, SCHED_HEADQ) : run_queue_peek(bound_runq);
		assert(mode == SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY || next_thread != prev_thread);
	}
found_thread:
	assert(next_thread != NULL);
	return next_thread;
}

static thread_t
sched_clutch_choose_thread(
	processor_t      processor,
	__unused int              priority,
	thread_t _Nullable        prev_thread,
	__unused ast_t            reason)
{
	assert(prev_thread == NULL || prev_thread == processor->active_thread);
	return sched_clutch_processor_highest_thread(processor, prev_thread != NULL ? SCHED_CLUTCH_TRAVERSE_REMOVE_CONSIDER_CURRENT : SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY);
}

static boolean_t
sched_clutch_processor_enqueue(
	processor_t       processor,
	thread_t          thread,
	sched_options_t   options)
{
	boolean_t       result;

	thread_set_runq_locked(thread, processor);
	if (SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
		sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
		result = sched_clutch_thread_insert(pset_clutch_root, thread, options);
	} else {
		run_queue_t rq = sched_clutch_thread_bound_runq(processor, thread);
		result = run_queue_enqueue(rq, thread, options);
	}
	return result;
}

static boolean_t
sched_clutch_processor_queue_empty(processor_t processor)
{
	return sched_clutch_root_count(sched_clutch_processor_root_clutch(processor)) == 0 &&
	       sched_clutch_bound_runq(processor)->count == 0;
}

static ast_t
sched_clutch_processor_csw_check(processor_t processor)
{
	assert(processor->active_thread != NULL);
	thread_t runqueue_thread = sched_clutch_processor_highest_thread(processor, SCHED_CLUTCH_TRAVERSE_CHECK_PREEMPT);
	if (runqueue_thread != processor->active_thread) {
		/* Found a better thread to run */
		if (sched_clutch_root_urgency(sched_clutch_processor_root_clutch(processor)) > 0 ||
		    sched_clutch_bound_runq(processor)->urgency > 0) {
			return AST_PREEMPT | AST_URGENT;
		}
		return AST_PREEMPT;
	}
	return AST_NONE;
}

static boolean_t
sched_clutch_processor_queue_has_priority(
	__unused processor_t    processor,
	__unused int            priority,
	__unused boolean_t      gte)
{
	/*
	 * Never short-circuit the Clutch runqueue by returning FALSE here. Instead,
	 * thread_select() should always go through sched_clutch_choose_thread().
	 */
	return TRUE;
}

static int
sched_clutch_runq_count(processor_t processor)
{
	return (int)sched_clutch_root_count(sched_clutch_processor_root_clutch(processor)) + sched_clutch_bound_runq(processor)->count;
}

#if !SCHED_TEST_HARNESS

static uint64_t
sched_clutch_runq_stats_count_sum(processor_t processor)
{
	uint64_t bound_sum = sched_clutch_bound_runq(processor)->runq_stats.count_sum;

	if (processor->cpu_id == processor->processor_set->cpu_set_low) {
		return bound_sum + sched_clutch_root_count_sum(sched_clutch_processor_root_clutch(processor));
	} else {
		return bound_sum;
	}
}

#endif /* !SCHED_TEST_HARNESS */

static int
sched_clutch_processor_bound_count(processor_t processor)
{
	return sched_clutch_bound_runq(processor)->count;
}

#if !SCHED_TEST_HARNESS

static void
sched_clutch_processor_queue_shutdown(processor_t processor, struct pulled_thread_queue * threadq)
{
	processor_set_t pset = processor->processor_set;
	sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);

	/* We only need to migrate threads if this is the last active processor in the pset */
	if (pset->online_processor_count == 0) {
		while (sched_clutch_root_count(pset_clutch_root) > 0) {
			thread_t thread = sched_clutch_hierarchy_thread_highest(
				pset_clutch_root, processor, NULL, SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY);
			pulled_thread_queue_enqueue(threadq, thread);
		}
	}

	pset_unlock(pset);
}

#endif /* !SCHED_TEST_HARNESS */

static boolean_t
sched_clutch_processor_queue_remove(
	processor_t processor,
	thread_t    thread)
{
	processor_set_t         pset = processor->processor_set;

	pset_lock(pset);

	if (processor == thread_get_runq_locked(thread)) {
		/*
		 * Thread is on a run queue and we have a lock on
		 * that run queue.
		 */
		if (SCHED_CLUTCH_THREAD_ELIGIBLE(thread)) {
			sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);
			sched_clutch_thread_remove(pset_clutch_root, thread, mach_absolute_time(), SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
		} else {
			run_queue_t rq = sched_clutch_thread_bound_runq(processor, thread);
			run_queue_remove(rq, thread);
		}
	} else {
		/*
		 * The thread left the run queue before we could
		 * lock the run queue.
		 */
		thread_assert_runq_null(thread);
		processor = PROCESSOR_NULL;
	}

	pset_unlock(pset);

	return processor != PROCESSOR_NULL;
}

static thread_t
sched_clutch_steal_thread(__unused processor_set_t pset)
{
	/* Thread stealing is not enabled for single cluster clutch scheduler platforms */
	return THREAD_NULL;
}

#if !SCHED_TEST_HARNESS

static void
sched_clutch_thread_update_scan(sched_update_scan_context_t scan_context)
{
	boolean_t               restart_needed = FALSE;
	processor_t             processor = processor_list;
	processor_set_t         pset;
	thread_t                thread;
	spl_t                   s;

	/*
	 *  We update the threads associated with each processor (bound and idle threads)
	 *  and then update the threads in each pset runqueue.
	 */

	do {
		do {
			pset = processor->processor_set;

			s = splsched();
			pset_lock(pset);

			restart_needed = runq_scan(sched_clutch_bound_runq(processor), scan_context);

			pset_unlock(pset);
			splx(s);

			if (restart_needed) {
				break;
			}

			thread = processor->idle_thread;
			if (thread != THREAD_NULL && thread->sched_stamp != os_atomic_load(&sched_tick, relaxed)) {
				if (thread_update_add_thread(thread) == FALSE) {
					restart_needed = TRUE;
					break;
				}
			}
		} while ((processor = processor->processor_list) != NULL);

		/* Ok, we now have a collection of candidates -- fix them. */
		thread_update_process_threads();
	} while (restart_needed);

	pset_node_t node = sched_boot_pset_node;
	pset = node->psets;

	do {
		do {
			restart_needed = FALSE;
			while (pset != NULL) {
				s = splsched();
				pset_lock(pset);

				if (sched_clutch_root_count(&pset->pset_clutch_root) > 0) {
					for (sched_bucket_t bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
						restart_needed = runq_scan(&pset->pset_clutch_root.scr_bound_buckets[bucket].scrb_bound_thread_runq, scan_context);
						if (restart_needed) {
							break;
						}
					}
					queue_t clutch_bucket_list = &pset->pset_clutch_root.scr_clutch_buckets;
					sched_clutch_bucket_t clutch_bucket;
					qe_foreach_element(clutch_bucket, clutch_bucket_list, scb_listlink) {
						sched_clutch_bucket_group_timeshare_update(clutch_bucket->scb_group, clutch_bucket, scan_context->sched_tick_last_abstime);
						restart_needed = sched_clutch_timeshare_scan(&clutch_bucket->scb_thread_timeshare_queue, clutch_bucket->scb_thr_count, scan_context);
						if (restart_needed) {
							break;
						}
					}
				}

				pset_unlock(pset);
				splx(s);

				if (restart_needed) {
					break;
				}
				pset = pset->pset_list;
			}

			if (restart_needed) {
				break;
			}
		} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));

		/* Ok, we now have a collection of candidates -- fix them. */
		thread_update_process_threads();
	} while (restart_needed);
}

/*
 * For threads that have changed sched_pri without changing the
 * base_pri for any reason other than decay, use the sched_pri
 * as the bucketizing priority instead of base_pri. All such
 * changes are typically due to kernel locking primitives boosts
 * or demotions.
 */
static boolean_t
sched_thread_sched_pri_promoted(thread_t thread)
{
	return (thread->sched_flags & TH_SFLAG_PROMOTE_REASON_MASK) ||
	       (thread->sched_flags & TH_SFLAG_DEMOTED_MASK) ||
	       (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) ||
	       (thread->kern_promotion_schedpri != 0);
}

#endif /* !SCHED_TEST_HARNESS */

/*
 * For the clutch scheduler, the run counts are maintained in the clutch
 * buckets (i.e thread group scheduling structure).
 */
static uint32_t
sched_clutch_run_incr(thread_t thread)
{
	assert((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN);
	uint32_t new_count = os_atomic_inc(&sched_run_buckets[TH_BUCKET_RUN], relaxed);
	sched_clutch_thread_run_bucket_incr(thread, thread->th_sched_bucket);
	return new_count;
}

static uint32_t
sched_clutch_run_decr(thread_t thread)
{
	assert((thread->state & (TH_RUN | TH_IDLE)) != TH_RUN);
	uint32_t new_count = os_atomic_dec(&sched_run_buckets[TH_BUCKET_RUN], relaxed);
	sched_clutch_thread_run_bucket_decr(thread, thread->th_sched_bucket);
	return new_count;
}

/*
 * Routine to update the scheduling bucket for the thread.
 *
 * In the clutch scheduler implementation, the thread's bucket
 * is based on sched_pri if it was promoted due to a kernel
 * primitive; otherwise its based on the thread base_pri. This
 * enhancement allows promoted threads to reach a higher priority
 * bucket and potentially get selected sooner for scheduling.
 *
 * Also, the clutch scheduler does not honor fixed priority below
 * FG priority. It simply puts those threads in the corresponding
 * timeshare bucket. The reason for to do that is because it is
 * extremely hard to define the scheduling properties of such threads
 * and they typically lead to performance issues.
 *
 * Called with the thread lock held and the thread held off the runqueue.
 */

void
sched_clutch_update_thread_bucket(thread_t thread)
{
	sched_bucket_t old_bucket = thread->th_sched_bucket;
	thread_assert_runq_null(thread);
	int pri = (sched_thread_sched_pri_promoted(thread)) ? thread->sched_pri : thread->base_pri;
	sched_bucket_t new_bucket = sched_clutch_thread_bucket_map(thread, pri);

	if (old_bucket == new_bucket) {
		return;
	}

	/* Bypass accounting CPU usage for a newly created thread */
	if (old_bucket != TH_BUCKET_RUN) {
		/* Attribute CPU usage with the old scheduling bucket */
		sched_clutch_thread_tick_delta(thread, NULL);
	}

	/* Transition to the new sched_bucket */
	thread->th_sched_bucket = new_bucket;
	thread->pri_shift = sched_clutch_thread_pri_shift(thread, new_bucket);

	/*
	 * Since this is called after the thread has been removed from the runq,
	 * only the run counts need to be updated. The re-insert into the runq
	 * would put the thread into the correct new bucket's runq.
	 */
	if ((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN) {
		sched_clutch_thread_run_bucket_decr(thread, old_bucket);
		sched_clutch_thread_run_bucket_incr(thread, new_bucket);
	}
}

#if !SCHED_TEST_HARNESS

static void
sched_clutch_thread_group_recommendation_change(__unused struct thread_group *tg, __unused cluster_type_t new_recommendation)
{
	/* Clutch ignores the recommendation because Clutch does not migrate
	 * threads between cluster types independently from the Edge scheduler.
	 */
}

#endif /* !SCHED_TEST_HARNESS */

#if CONFIG_SCHED_EDGE

/* Implementation of the AMP version of the clutch scheduler */

static void
sched_edge_init(void);

static void
sched_edge_pset_init(processor_set_t pset);

static thread_t
sched_edge_processor_idle(processor_set_t pset);

static boolean_t
sched_edge_processor_queue_empty(processor_t processor);

static void
sched_edge_processor_queue_shutdown(processor_t processor, struct pulled_thread_queue * threadq);

static processor_t
sched_edge_choose_processor(processor_set_t pset, processor_t processor, thread_t thread, sched_options_t *options_inout);

static void
sched_edge_quantum_expire(thread_t thread);

static bool
sched_edge_thread_avoid_processor(processor_t processor, thread_t thread, ast_t reason);

static bool
sched_edge_balance(processor_t idle_processor, processor_set_t idle_pset);

static void
sched_edge_check_spill(processor_set_t pset, thread_t thread);

static bool
sched_edge_thread_should_yield(processor_t processor, thread_t thread);

static void
sched_edge_pset_made_schedulable(processor_set_t pset);

static void
sched_edge_cpu_init_completed(void);

static bool
sched_edge_thread_eligible_for_pset(thread_t thread, processor_set_t pset);

static bool
sched_edge_steal_thread_enabled(processor_set_t pset);

static sched_ipi_type_t
sched_edge_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event);

static uint32_t
sched_edge_qos_max_parallelism(int qos, uint64_t options);

static void
sched_edge_update_pset_load_average(processor_set_t pset, uint64_t curtime);

static void
sched_edge_update_pset_avg_execution_time(processor_set_t pset, uint64_t execution_time, uint64_t curtime, sched_bucket_t sched_bucket);

static uint32_t
sched_edge_pset_load_metric(processor_set_t pset, sched_bucket_t sched_bucket);

static uint32_t
sched_edge_run_count_incr(thread_t thread);

static bool
sched_edge_stir_the_pot_core_type_is_desired(processor_set_t pset);

const struct sched_dispatch_table sched_edge_dispatch = {
	.sched_name                                     = "edge",
	.init                                           = sched_edge_init,
	.timebase_init                                  = sched_timeshare_timebase_init,
	.processor_init                                 = sched_clutch_processor_init,
	.pset_init                                      = sched_edge_pset_init,
	.choose_thread                                  = sched_clutch_choose_thread,
	.steal_thread_enabled                           = sched_edge_steal_thread_enabled,
	.steal_thread                                   = sched_edge_processor_idle,
	.choose_processor                               = sched_edge_choose_processor,
	.processor_enqueue                              = sched_clutch_processor_enqueue,
	.processor_queue_remove                         = sched_clutch_processor_queue_remove,
	.processor_queue_empty                          = sched_edge_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = sched_clutch_processor_csw_check,
	.processor_queue_has_priority                   = sched_clutch_processor_queue_has_priority,
	.initial_quantum_size                           = sched_clutch_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_clutch_initial_thread_sched_mode,
	.processor_runq_count                           = sched_clutch_runq_count,
	.processor_bound_count                          = sched_clutch_processor_bound_count,
	.multiple_psets_enabled                         = TRUE,
	.avoid_processor_enabled                        = TRUE,
	.thread_avoid_processor                         = sched_edge_thread_avoid_processor,
	.processor_balance                              = sched_edge_balance,
	.qos_max_parallelism                            = sched_edge_qos_max_parallelism,
	.check_spill                                    = sched_edge_check_spill,
	.ipi_policy                                     = sched_edge_ipi_policy,
	.thread_should_yield                            = sched_edge_thread_should_yield,
	.update_thread_bucket                           = sched_clutch_update_thread_bucket,
	.cpu_init_completed                             = sched_edge_cpu_init_completed,
	.thread_eligible_for_pset                       = sched_edge_thread_eligible_for_pset,
	.update_pset_load_average                       = sched_edge_update_pset_load_average,
	.update_pset_avg_execution_time                 = sched_edge_update_pset_avg_execution_time,

	.rt_choose_processor                            = sched_rt_choose_processor,
	.rt_steal_thread                                = sched_rt_steal_thread,
	.rt_init_pset                                   = sched_rt_init_pset,
	.rt_init_completed                              = sched_rt_init_completed,
	.rt_runq_count_sum                              = sched_rt_runq_count_sum,

#if !SCHED_TEST_HARNESS
	.maintenance_continuation                       = sched_timeshare_maintenance_continue,
	.compute_timeshare_priority                     = sched_compute_timeshare_priority,
	.choose_node                                    = sched_choose_node,
	.processor_queue_shutdown                       = sched_edge_processor_queue_shutdown,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_edge_quantum_expire,
	.processor_runq_stats_count_sum                 = sched_clutch_runq_stats_count_sum,
	.thread_update_scan                             = sched_clutch_thread_update_scan,
	.run_count_incr                                 = sched_edge_run_count_incr,
	.run_count_decr                                 = sched_clutch_run_decr,
	.pset_made_schedulable                          = sched_edge_pset_made_schedulable,
	.thread_group_recommendation_change             = NULL,

	.rt_queue_shutdown                              = sched_rt_queue_shutdown,
	.rt_runq_scan                                   = sched_rt_runq_scan,
#endif /* !SCHED_TEST_HARNESS */
};

static _Atomic bitmap_t sched_edge_available_pset_bitmask[BITMAP_LEN(MAX_PSETS)];

/*
 * sched_edge_thread_bound_pset_id()
 *
 * Routine to determine which cluster a particular thread is bound to. Uses
 * the sched_flags on the thread to map back to a specific cluster id.
 *
 * <Edge Multi-cluster Support Needed>
 */
static pset_id_t
sched_edge_thread_bound_pset_id(thread_t thread)
{
	assert(SCHED_CLUTCH_THREAD_PSET_BOUND(thread));
	return thread->th_bound_pset_id;
}

/* Forward declaration for some thread migration routines */
static bool sched_edge_foreign_running_thread_available(processor_set_t idle_pset);
static int sched_edge_running_rebal_candidate_best_eligible_cpu(processor_set_t idle_pset, processor_set_t candidate_pset, sched_bucket_t *highest_eligible_qos_observed, bool pset_lock_held);
static processor_set_t sched_edge_migrate_candidate(processor_set_t preferred_pset, thread_t thread, processor_set_t locked_pset, bool switch_pset_locks, processor_t *processor_hint_out, sched_options_t *options_inout);

static_assert(sizeof(sched_clutch_edge) == sizeof(uint64_t), "sched_clutch_edge fits in 64 bits");

#define PERMISSIVE_MIGRATION_BUCKET (TH_BUCKET_FIXPRI)

/*
 * sched_edge_config_set()
 *
 * Support to update an edge configuration. Typically used by CLPC to affect thread migration
 * policies in the scheduler.
 */
static void
sched_edge_config_set(pset_id_t src_pset, pset_id_t dst_pset, sched_bucket_t bucket, sched_clutch_edge edge_config)
{
	os_atomic_store(&pset_for_id(src_pset)->sched_edges[dst_pset][bucket], edge_config, relaxed);
}

/*
 * sched_edge_config_get()
 *
 * Support to get an edge configuration. Typically used by CLPC to query edge configs to decide
 * if it needs to update edges.
 */
static sched_clutch_edge
sched_edge_config_get(pset_id_t src_pset, pset_id_t dst_pset, sched_bucket_t bucket)
{
	return os_atomic_load(&pset_array[src_pset]->sched_edges[dst_pset][bucket], relaxed);
}

/*
 * sched_edge_config_pset_push()
 *
 * After using sched_edge_config_set() to update edge tunables outgoing from a particular source
 * pset, this function should be called in order to propagate the updates to derived metadata for
 * the pset, such as search orders for outgoing spill and steal.
 */
static void
sched_edge_config_pset_push(pset_id_t src_pset_id)
{
	processor_set_t src_pset = pset_for_id(src_pset_id);
	uint8_t search_order_len = sched_num_psets - 1;
	sched_pset_search_order_sort_data_t search_order_datas[MAX_PSETS - 1];
	for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		uint8_t dst_pset_id = 0;
		for (int i = 0; i < search_order_len; i++, dst_pset_id++) {
			if (dst_pset_id == src_pset_id) {
				dst_pset_id++;
			}
			search_order_datas[i].spsosd_src_pset = src_pset;
			search_order_datas[i].spsosd_dst_pset_id = dst_pset_id;
			sched_clutch_edge edge = sched_edge_config_get(src_pset_id, dst_pset_id, bucket);
			search_order_datas[i].spsosd_migration_weight = edge.sce_migration_allowed ?
			    edge.sce_migration_weight : UINT32_MAX;
		}
		sched_pset_search_order_compute(&src_pset->spill_search_order[bucket],
		    search_order_datas, search_order_len, sched_edge_search_order_weight_then_locality_cmp);
	}
}

static int
sched_edge_search_order_weight_then_locality(const void *a, const void *b)
{
	const sched_pset_search_order_sort_data_t *data_a = (const sched_pset_search_order_sort_data_t *)a;
	const sched_pset_search_order_sort_data_t *data_b = (const sched_pset_search_order_sort_data_t *)b;
	assert3p(data_a->spsosd_src_pset, ==, data_b->spsosd_src_pset);
	assert3u(data_a->spsosd_dst_pset_id, !=, data_b->spsosd_dst_pset_id);
	/*
	 * Sort based on lowest edge migration weight, followed by die-local psets
	 * first, followed by lowest pset id.
	 */
	if (data_a->spsosd_migration_weight != data_b->spsosd_migration_weight) {
		return (data_a->spsosd_migration_weight < data_b->spsosd_migration_weight) ? -1 : 1;
	}

	bool is_local_a = bitmap_test(data_a->spsosd_src_pset->local_psets, data_a->spsosd_dst_pset_id);
	bool is_local_b = bitmap_test(data_b->spsosd_src_pset->local_psets, data_b->spsosd_dst_pset_id);
	if (is_local_a != is_local_b) {
		return is_local_a ? -1 : 1;
	}

	if (data_a->spsosd_dst_pset_id != data_b->spsosd_dst_pset_id) {
		return (data_a->spsosd_dst_pset_id < data_b->spsosd_dst_pset_id) ? -1 : 1;
	}
	return 0;
}

cmpfunc_t sched_edge_search_order_weight_then_locality_cmp = &sched_edge_search_order_weight_then_locality;

#if DEVELOPMENT || DEBUG || SCHED_TEST_HARNESS

/*
 * sched_edge_config_verify_non_decreasing_qos_strictness()
 *
 * Routine to validate the assumption that higher QoSes
 * will be configured with the less restrictive migration
 * allowance for each edge in the matrix. This allows
 * early-exiting searches when migration is disallowed for
 * a higher QoS edge.
 * Returns true if no violations were discovered.
 */
static inline bool
sched_edge_config_verify_non_decreasing_qos_strictness(
	pset_id_t src_id, pset_id_t dst_id, sched_bucket_t bucket)
{
	if (bucket == PERMISSIVE_MIGRATION_BUCKET) {
		return true;
	}
	sched_clutch_edge edge = sched_edge_config_get(src_id, dst_id, bucket);
	sched_clutch_edge higher_bucket_edge = sched_edge_config_get(src_id, dst_id, bucket - 1);
	if ((edge.sce_migration_allowed && !higher_bucket_edge.sce_migration_allowed) ||
	    (edge.sce_steal_allowed && !higher_bucket_edge.sce_steal_allowed)) {
		kprintf("warn: Edge matrix config violates non-decreasing strictness "
		    "across buckets %u and %u for edge %u->%u\n",
		    bucket - 1, bucket, src_id, dst_id);
		return false;
	}
	return true;
}

static bool
sched_edge_config_verify_transitive_traverse(pset_id_t dst_id, pset_id_t curr_id,
    sched_bucket_t qos, bitmap_t *visited_map)
{
	if (bitmap_test(visited_map, curr_id)) {
		/* Been there, done that */
		return true;
	}
	bitmap_set(visited_map, curr_id);
	bool pass = true;
	for (pset_id_t next_id = 0; next_id < sched_num_psets; next_id++) {
		if (next_id == curr_id) {
			continue;
		}
		sched_clutch_edge path_edge = sched_edge_config_get(next_id, curr_id, qos);
		if (path_edge.sce_migration_allowed) {
			/*
			 * We have found a migration path from next_id to dst_id.
			 * Verify that the direct edge agrees.
			 */
			if (next_id != dst_id) {
				sched_clutch_edge direct_edge = sched_edge_config_get(next_id, dst_id, qos);
				if (!direct_edge.sce_migration_allowed || !direct_edge.sce_steal_allowed) {
					pass = false;
					kprintf("warn: Edge matrix config violates transitive property across "
					    "psets %u->%u for scheduling bucket %u\n", next_id, dst_id, qos);
				}
			}
			/* DFS onward */
			pass = sched_edge_config_verify_transitive_traverse(dst_id, next_id, qos, visited_map) && pass;
		}
	}
	return pass;
}

/*
 * sched_edge_config_verify_transitive()
 *
 * Routine to validate transitivity of the Edge matrix which
 * helps ensure that the configured migration policy minimizes
 * scheduling latency by allowing threads to directly spill to
 * idle cores where they are allowed to run, rather than
 * arrive on those cores only via steal operations.
 * Returns true if no violations were discovered.
 */
static bool
sched_edge_config_verify_transitive(pset_id_t dst_id)
{
	bool pass = true;
	for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		/*
		 * Depth-first-search paths to get to the destination pset,
		 * and verify that each path also has a matching direct edge
		 * from start to finish.
		 */
		bitmap_t visited_map[BITMAP_LEN(MAX_PSETS)] = {0};
		pass = sched_edge_config_verify_transitive_traverse(dst_id, dst_id, bucket, visited_map) && pass;
	}
	return pass;
}

/*
 * sched_edge_config_verify()
 *
 * Performs checks to validate assumed properties of the Edge matrix,
 * such as transitivity.
 * Returns true if no violations were discovered.
 */
static bool
sched_edge_config_verify(void)
{
	bool pass = true;
	sched_edge_matrix_iterate(src_id, dst_id, bucket, { \
		pass = sched_edge_config_verify_non_decreasing_qos_strictness(src_id, dst_id, bucket) && pass;
	});
	for (pset_id_t dst_id = 0; dst_id < sched_num_psets; dst_id++) {
		pass = sched_edge_config_verify_transitive(dst_id) && pass;
	}
	return pass;
}

#endif /* DEVELOPMENT || DEBUG || SCHED_TEST_HARNESS */

/*
 * sched_edge_config_final_push()
 *
 * After using sched_edge_config_set() to update edge tunables outgoing from every pset,
 * this function is called in order to propagate the updates to derived global metadata,
 * such as short-cut bitmasks.
 */
static void
sched_edge_config_final_push(void)
{
	for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		for (pset_id_t dst_id = 0; dst_id < sched_num_psets; dst_id++) {
			bitmap_t updated_steal_map[BITMAP_LEN(MAX_PSETS)] = {0};
			for (pset_id_t src_id = 0; src_id < sched_num_psets; src_id++) {
				sched_clutch_edge edge = sched_edge_config_get(src_id, dst_id, bucket);
				if ((dst_id == src_id) || edge.sce_migration_allowed) {
					bitmap_set(updated_steal_map, src_id);
				}
			}
			sched_clutch_root_t dst_root = &pset_array[dst_id]->pset_clutch_root;
			os_atomic_store(dst_root->scr_incoming_migration_allowed[bucket], updated_steal_map[0], relaxed);
		}
	}
}

/*
 * sched_edge_matrix_set()
 *
 * Routine to update various edges in the edge migration graph. The edge_changed array
 * indicates which edges need to be updated. Both the edge_matrix and edge_changed arrays
 * are matrices with dimension num_psets * num_psets * TH_BUCKET_SCHED_MAX, flattened into a
 * single-dimensional array.
 */
void
sched_edge_matrix_set(sched_clutch_edge *edge_matrix, bool *edge_changed, __unused uint64_t flags,
    __assert_only uint64_t num_psets)
{
	assert3u(num_psets, ==, sched_num_psets);
	uint32_t edge_index = 0;
	for (pset_id_t src_pset = 0; src_pset < sched_num_psets; src_pset++) {
		for (pset_id_t dst_pset = 0; dst_pset < sched_num_psets; dst_pset++) {
			for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
				if (edge_changed[edge_index]) {
					sched_edge_config_set(src_pset, dst_pset, bucket, edge_matrix[edge_index]);
				}
				edge_index++;
			}
		}
		sched_edge_config_pset_push(src_pset);
	}
	sched_edge_config_final_push();
}

/*
 * sched_edge_matrix_get()
 *
 * Routine to retrieve various edges in the edge migration graph. The edge_requested array
 * indicates which edges need to be retrieved. Both the edge_matrix and edge_requested arrays
 * are matrices with dimension num_psets * num_psets * TH_BUCKET_SCHED_MAX, flattened into a
 * single-dimensional array.
 */
void
sched_edge_matrix_get(sched_clutch_edge *edge_matrix, bool *edge_requested, __unused uint64_t flags,
    __assert_only uint64_t num_psets)
{
	assert3u(num_psets, ==, sched_num_psets);
	uint32_t edge_index = 0;
	for (uint32_t src_pset = 0; src_pset < sched_num_psets; src_pset++) {
		for (uint32_t dst_pset = 0; dst_pset < sched_num_psets; dst_pset++) {
			for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
				if (edge_requested[edge_index]) {
					edge_matrix[edge_index] = sched_edge_config_get(src_pset, dst_pset, bucket);
				}
				edge_index++;
			}
		}
	}
}

#if CONFIG_SCHED_PERF_ISLANDS
/*
 * Friction edge weights
 *
 * Default migration weight settings in the edge matrix between performance islands
 * of matching type.
 *
 * These are enforced strictly (i.e. even in the presence of idle cores), and higher
 * values introduce greater "friction" between the performance islands, making spills
 * across the edge less likely at a cost of scheduling latency. The values represent
 * reasonable preemption latencies we are willing to sacrifice in exchange for power
 * savings.
 */
static uint64_t sched_edge_qos_friction_weight_us[TH_BUCKET_SCHED_MAX] = {
	0,                                              /* FIXPRI */
	0,                                              /* FG */
	250,                                            /* IN */
	500,                                            /* DF */
	1000,                                           /* UT (1ms) */
	2000                                            /* BG (2ms) */
};
#endif /* CONFIG_SCHED_PERF_ISLANDS */

/*
 * sched_edge_init()
 *
 * Routine to initialize the data structures for the Edge scheduler.
 */
static void
sched_edge_init(void)
{
	if (!PE_parse_boot_argn("sched_clutch_bucket_group_interactive_pri", &sched_clutch_bucket_group_interactive_pri, sizeof(sched_clutch_bucket_group_interactive_pri))) {
		sched_clutch_bucket_group_interactive_pri = SCHED_CLUTCH_BUCKET_GROUP_INTERACTIVE_PRI_DEFAULT;
	}
	sched_timeshare_init();
	sched_clutch_tunables_init();
	assert3s(sched_num_psets, >, 0);
	assert3s(sched_num_psets, <=, (int)MAX_PSETS);
}

static void
sched_edge_pset_init(processor_set_t pset)
{
	uint32_t pset_id = pset->pset_id;

	/* Set the edge weight and properties for the pset itself */
	bitmap_clear(pset->foreign_psets, pset_id);
	bitmap_clear(pset->native_psets, pset_id);
	bitmap_clear(pset->local_psets, pset_id);
	bitmap_clear(pset->remote_psets, pset_id);
	bzero(&pset->sched_edges, sizeof(pset->sched_edges));
	bzero(&pset->max_parallel_cores, sizeof(pset->max_parallel_cores));
	bzero(&pset->max_parallel_clusters, sizeof(pset->max_parallel_clusters));

	/* Before sched_num_psets is stable, initialize the search order to be invalid. */
	for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		os_atomic_store_wide(&pset->spill_search_order[bucket], SCHED_PSET_SEARCH_ORDER_INIT, relaxed);
	}

	sched_clutch_root_init(&pset->pset_clutch_root, pset);
	atomic_bitmap_set(sched_edge_available_pset_bitmask, pset_id, memory_order_relaxed);
}

static boolean_t
sched_edge_processor_queue_empty(processor_t processor)
{
	return (sched_clutch_root_count(sched_clutch_processor_root_clutch(processor)) == 0) &&
	       (sched_clutch_bound_runq(processor)->count == 0);
}

static void
sched_edge_check_spill(__unused processor_set_t pset, __unused thread_t thread)
{
	assert(thread->bound_processor == PROCESSOR_NULL);
}

__options_decl(sched_edge_thread_yield_reason_t, uint32_t, {
	SCHED_EDGE_YIELD_RUNQ_NONEMPTY       = 0x0,
	/* SCHED_EDGE_YIELD_FOREIGN_RUNNABLE    = 0x1, unused */
	SCHED_EDGE_YIELD_FOREIGN_RUNNING     = 0x2,
	SCHED_EDGE_YIELD_STEAL_POSSIBLE      = 0x3,
	SCHED_EDGE_YIELD_DISALLOW            = 0x4,
});

/*
 * sched_edge_thread_should_yield()
 *
 * Routine for a fast-path decision of whether or not to proceed
 * depressing the priority of and considering preempting a
 * yielding thread.
 * Called with preemption disabled but WITHOUT the pset lock held.
 */
static bool
sched_edge_thread_should_yield(processor_t processor, __unused thread_t thread)
{
	/* Self runqueue case exactly matches sched_thread_should_yield() */
	if (!sched_edge_processor_queue_empty(processor) || (rt_runq_count(processor->processor_set) > 0)) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
		    thread_tid(thread), processor->processor_set->pset_id, 0, SCHED_EDGE_YIELD_RUNQ_NONEMPTY);
		return true;
	}

	/* Scan for running rebalance opportunity */
	if (sched_edge_foreign_running_thread_available(processor->processor_set)) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
		    thread_tid(thread), processor->processor_set->pset_id, 0, SCHED_EDGE_YIELD_FOREIGN_RUNNING);
		return true;
	}

	/* Scan for steal opportunity */
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	uint64_t try_all_mask = ~0ULL;
	while (sched_iterate_psets_ordered(processor->processor_set,
	    &processor->processor_set->spill_search_order[TH_BUCKET_FIXPRI], try_all_mask, &istate)) {
		processor_set_t target_pset = pset_for_id(istate.spis_pset_id);
		if (sched_edge_pset_peek_steal_possible(target_pset, processor->processor_set, try_all_mask)) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
			    thread_tid(thread), processor->processor_set->pset_id, 0, SCHED_EDGE_YIELD_STEAL_POSSIBLE);
			return true;
		}
	}

	/*
	 * Note, the current yield policy in thread_select() does NOT attempt
	 * to steal or rebalance before falling back to continue running the
	 * yielding thread.
	 */
	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHOULD_YIELD) | DBG_FUNC_NONE,
	    thread_tid(thread), processor->processor_set->pset_id, 0, SCHED_EDGE_YIELD_DISALLOW);
	return false;
}

#if !SCHED_TEST_HARNESS

static void
sched_edge_processor_queue_shutdown(processor_t processor, struct pulled_thread_queue * threadq)
{
	processor_set_t pset = processor->processor_set;
	sched_clutch_root_t pset_clutch_root = sched_clutch_processor_root_clutch(processor);

	/* We only need to migrate threads if this is the last active or last recommended processor in the pset */
	if (pset->online_processor_count == 0 || !pset_is_recommended(pset)) {
		atomic_bitmap_clear(sched_edge_available_pset_bitmask, pset->pset_id, memory_order_relaxed);

		while (sched_clutch_root_count(pset_clutch_root) > 0) {
			thread_t thread = sched_clutch_hierarchy_thread_highest(pset_clutch_root,
			    processor, NULL, SCHED_CLUTCH_TRAVERSE_REMOVE_HIERARCHY_ONLY);
			pulled_thread_queue_enqueue(threadq, thread);
		}
	}

	pset_unlock(pset);
}

#endif /* !SCHED_TEST_HARNESS */

/*
 * The Edge scheduler uses average scheduling latency as the metric for making
 * thread migration decisions. One component of avg scheduling latency is the
 * load average on the pset.
 *
 * Load Average Fixed Point Arithmetic
 *
 * The load average is maintained as a 24.8 fixed point arithmetic value for
 * precision.  When multiplied by the average execution time, it needs to be
 * rounded up (based on the most significant bit of the fractional part) for
 * better accuracy. After rounding up, the whole number part of the value is
 * used as the actual load value for migrate/steal decisions.
 */
#define SCHED_PSET_LOAD_EWMA_FRACTION_BITS 8
#define SCHED_PSET_LOAD_EWMA_ROUND_BIT     (1 << (SCHED_PSET_LOAD_EWMA_FRACTION_BITS - 1))
#define SCHED_PSET_LOAD_EWMA_FRACTION_MASK ((1 << SCHED_PSET_LOAD_EWMA_FRACTION_BITS) - 1)
#define SCHED_PSET_LOAD_EWMA_TC_NSECS 10000000u

inline static uint32_t
sched_edge_get_pset_load_average(processor_set_t pset, sched_bucket_t sched_bucket)
{
	uint64_t load_average = os_atomic_load(&pset->pset_load_average[sched_bucket], relaxed);
	uint64_t avg_execution_time = os_atomic_load(&pset->pset_execution_time[sched_bucket].pset_avg_thread_execution_time, relaxed);
	/*
	 * Since a load average of 0 indicates an idle pset, don't allow an average
	 * execution time less than 1us to cause a pset to appear idle.
	 */
	avg_execution_time = MAX(avg_execution_time, 1ULL);
	uint64_t product = ((load_average + SCHED_PSET_LOAD_EWMA_ROUND_BIT) >> SCHED_PSET_LOAD_EWMA_FRACTION_BITS) * avg_execution_time;
	/* Perform a saturating cast to uint32_t. */
	return (uint32_t)MIN(product, UINT32_MAX);
}

/*
 * sched_edge_pset_running_higher_bucket()
 *
 * Routine to calculate cumulative running counts for each scheduling bucket.
 * This effectively lets the load calculation calculate if a pset is running any
 * threads at a QoS lower than the thread being migrated etc.
 */
static void
sched_edge_pset_running_higher_bucket(processor_set_t pset, uint32_t *running_higher)
{
	bitmap_t *active_map = &pset->cpu_state_map[PROCESSOR_RUNNING];
	bzero(running_higher, sizeof(uint32_t) * TH_BUCKET_SCHED_MAX);

	/* Count the running threads per bucket */
	for (int cpu = bitmap_first(active_map, MAX_CPUS); cpu >= 0; cpu = bitmap_next(active_map, cpu)) {
		sched_bucket_t cpu_bucket = os_atomic_load(&pset->cpu_running_buckets[cpu], relaxed);
		/* Don't count idle threads */
		if (cpu_bucket < TH_BUCKET_SCHED_MAX) {
			running_higher[cpu_bucket]++;
		}
	}

	/* Calculate the cumulative running counts as a prefix sum */
	for (sched_bucket_t bucket = TH_BUCKET_FIXPRI; bucket < TH_BUCKET_SCHED_MAX - 1; bucket++) {
		running_higher[bucket + 1] += running_higher[bucket];
	}
}

/*
 * sched_edge_update_pset_load_average()
 *
 * Updates the load average for each sched bucket for a pset.
 * This routine must be called with the pset lock held.
 */
static void
sched_edge_update_pset_load_average(processor_set_t pset, uint64_t curtime)
{
	int avail_cpu_count = pset_available_cpu_count(pset);
	if (avail_cpu_count == 0) {
		/* Looks like the pset is not runnable any more; nothing to do here */
		return;
	}

	/*
	 * Edge Scheduler Optimization
	 *
	 * See if more callers of this routine can pass in timestamps to avoid the
	 * mach_absolute_time() call here.
	 */

	if (!curtime) {
		curtime = mach_absolute_time();
	}
	uint64_t last_update = os_atomic_load(&pset->pset_load_last_update, relaxed);
	int64_t delta_ticks = curtime - last_update;
	if (delta_ticks < 0) {
		return;
	}

	uint64_t delta_nsecs = 0;
	absolutetime_to_nanoseconds(delta_ticks, &delta_nsecs);

	if (__improbable(delta_nsecs > UINT32_MAX)) {
		delta_nsecs = UINT32_MAX;
	}

	/* Update the shared resource load on the pset */
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		uint64_t shared_rsrc_runnable_load = sched_edge_shared_rsrc_runnable_load(&pset->pset_clutch_root, shared_rsrc_type);
		uint64_t shared_rsrc_running_load = atomic_bit_count(&pset->cpu_running_cluster_shared_rsrc_thread[shared_rsrc_type], memory_order_relaxed);
		uint64_t new_shared_load = shared_rsrc_runnable_load + shared_rsrc_running_load;
		uint64_t old_shared_load = os_atomic_xchg(&pset->pset_cluster_shared_rsrc_load[shared_rsrc_type], new_shared_load, relaxed);
		if (old_shared_load != new_shared_load) {
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_CLUSTER_SHARED_LOAD) | DBG_FUNC_NONE, pset->pset_id, shared_rsrc_type, new_shared_load, shared_rsrc_running_load);
		}
	}

	uint32_t running_higher[TH_BUCKET_SCHED_MAX];
	sched_edge_pset_running_higher_bucket(pset, running_higher);

	for (sched_bucket_t sched_bucket = TH_BUCKET_FIXPRI; sched_bucket < TH_BUCKET_SCHED_MAX; sched_bucket++) {
		uint64_t old_load_average = os_atomic_load(&pset->pset_load_average[sched_bucket], relaxed);
		uint64_t old_load_average_factor = ((uint64_t)old_load_average) * SCHED_PSET_LOAD_EWMA_TC_NSECS;
		uint32_t current_runq_depth = sched_edge_pset_cumulative_count(&pset->pset_clutch_root, sched_bucket) +  rt_runq_count(pset) + running_higher[sched_bucket];
		os_atomic_store(&pset->pset_runnable_depth[sched_bucket], current_runq_depth, relaxed);

		uint32_t current_load = current_runq_depth / avail_cpu_count;
		/*
		 * For the new load average multiply current_load by delta_nsecs (which results in a 32.0 value).
		 * Since we want to maintain the load average as a 24.8 fixed arithmetic value for precision, the
		 * new load average needs to be shifted before it can be added to the old load average.
		 */
		uint64_t new_load_average_factor = (current_load * delta_nsecs) << SCHED_PSET_LOAD_EWMA_FRACTION_BITS;

		/*
		 * For extremely parallel workloads, it is important that the load average on a pset moves zero to non-zero
		 * instantly to allow threads to be migrated to other (potentially idle) pset quickly. Hence use the EWMA
		 * when the system is already loaded; otherwise for an idle system use the latest load average immediately.
		 */
		uint32_t old_load_shifted = (old_load_average + SCHED_PSET_LOAD_EWMA_ROUND_BIT) >> SCHED_PSET_LOAD_EWMA_FRACTION_BITS;
		boolean_t load_uptick = (old_load_shifted == 0) && (current_load != 0);
		boolean_t load_downtick = (old_load_shifted != 0) && (current_load == 0);
		uint64_t load_average;
		if (load_uptick || load_downtick) {
			load_average = (current_load << SCHED_PSET_LOAD_EWMA_FRACTION_BITS);
		} else {
			/* Indicates a loaded system; use EWMA for load average calculation */
			load_average = (old_load_average_factor + new_load_average_factor) / (delta_nsecs + SCHED_PSET_LOAD_EWMA_TC_NSECS);
		}
		/* Perform a saturating cast to uint32_t. */
		load_average = MIN(load_average, UINT32_MAX);
		os_atomic_store(&pset->pset_load_average[sched_bucket], (uint32_t)load_average, relaxed);
		if (load_average != old_load_average) {
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_LOAD_AVG) | DBG_FUNC_NONE, pset->pset_id, (load_average >> SCHED_PSET_LOAD_EWMA_FRACTION_BITS), load_average & SCHED_PSET_LOAD_EWMA_FRACTION_MASK, sched_bucket);
			os_atomic_store(&pset->pset_load_last_update, curtime, relaxed);
		}
	}
	os_atomic_store(&pset->pset_load_last_update, curtime, relaxed);
}

static void
sched_edge_update_pset_avg_execution_time(processor_set_t pset, uint64_t execution_time, uint64_t curtime, sched_bucket_t sched_bucket)
{
	pset_execution_time_t old_execution_time_packed, new_execution_time_packed;
	uint64_t avg_thread_execution_time = 0;

	os_atomic_rmw_loop(&pset->pset_execution_time[sched_bucket].pset_execution_time_packed,
	    old_execution_time_packed.pset_execution_time_packed,
	    new_execution_time_packed.pset_execution_time_packed, relaxed, {
		uint64_t last_update = old_execution_time_packed.pset_execution_time_last_update;
		int64_t delta_ticks = curtime - last_update;
		if (delta_ticks <= 0) {
		        /*
		         * Its possible that another CPU came in and updated the pset_execution_time
		         * before this CPU could do it. Since the average execution time is meant to
		         * be an approximate measure per pset, ignore the older update.
		         */
		        os_atomic_rmw_loop_give_up(return );
		}
		uint64_t delta_nsecs = 0;
		absolutetime_to_nanoseconds(delta_ticks, &delta_nsecs);

		uint64_t nanotime = 0;
		absolutetime_to_nanoseconds(execution_time, &nanotime);
		uint64_t execution_time_us = nanotime / NSEC_PER_USEC;

		/*
		 * Since the average execution time is stored in microseconds, avoid rounding errors in
		 * the EWMA calculation by only using a non-zero previous value.
		 */
		uint64_t old_avg_thread_execution_time = MAX(old_execution_time_packed.pset_avg_thread_execution_time, 1ULL);

		uint64_t old_execution_time = (old_avg_thread_execution_time * SCHED_PSET_LOAD_EWMA_TC_NSECS);
		uint64_t new_execution_time = (execution_time_us * delta_nsecs);

		avg_thread_execution_time = (old_execution_time + new_execution_time) / (delta_nsecs + SCHED_PSET_LOAD_EWMA_TC_NSECS);
		new_execution_time_packed.pset_avg_thread_execution_time = avg_thread_execution_time;
		new_execution_time_packed.pset_execution_time_last_update = curtime;
	});
	if (new_execution_time_packed.pset_avg_thread_execution_time != old_execution_time_packed.pset_execution_time_packed) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PSET_AVG_EXEC_TIME) | DBG_FUNC_NONE, pset->pset_id, avg_thread_execution_time, sched_bucket);
	}
}

/*
 * sched_edge_pset_load_metric()
 *
 * The load metric for a pset is a measure of the average scheduling latency
 * experienced by threads on that pset. It is a product of the average number
 * of threads in the runqueue and the average execution time for threads. The metric
 * has special values in the following cases:
 * - UINT32_MAX: If the pset is not available for scheduling, its load is set to
 *   the maximum value to disallow any threads to migrate to this pset.
 * - 0: If there are idle CPUs in the pset or an empty runqueue; this allows threads
 *   to be spread across the platform quickly for ncpu wide workloads.
 */
static uint32_t
sched_edge_pset_load_metric(processor_set_t pset, sched_bucket_t sched_bucket)
{
	if (pset_is_recommended(pset) == false) {
		return UINT32_MAX;
	}
	return sched_edge_get_pset_load_average(pset, sched_bucket);
}

/*
 *
 * Edge Scheduler Steal/Rebalance logic
 *
 * = Generic scheduler logic =
 *
 * The SCHED(steal_thread) scheduler callout is invoked when the processor does not
 * find any thread for execution in its runqueue. The aim of the steal operation
 * is to find other threads running/runnable in other psets which should be
 * executed here.
 *
 * If the steal callout does not return a thread, the thread_select() logic calls
 * SCHED(processor_balance) callout which is supposed to IPI other CPUs to rebalance
 * threads and idle out the current CPU.
 *
 * = SCHED(steal_thread) for Edge Scheduler =
 *
 * The edge scheduler hooks into sched_edge_processor_idle() for steal_thread. This
 * routine tries to do the following operations in order:
 * (1) Find foreign runnnable threads in non-native pset
 *     runqueues (sched_edge_foreign_runnable_thread_remove())
 * (2) Check if foreign threads are running on the non-native
 *     psets (sched_edge_foreign_running_thread_available())
 *         - If yes, return THREAD_NULL for the steal callout and
 *         perform rebalancing as part of SCHED(processor_balance) i.e. sched_edge_balance()
 * (3) Steal a thread from another pset based on edge
 *     weights (sched_edge_steal_thread())
 *
 * = SCHED(processor_balance) for Edge Scheduler =
 *
 * If steal_thread did not return a thread for the processor, use
 * sched_edge_balance() to rebalance foreign running threads and idle out this CPU.
 *
 * = Clutch Bucket Preferred Pset Overrides =
 *
 * Since these operations (just like thread migrations on enqueue)
 * move threads across psets, they need support for handling clutch
 * bucket group level preferred pset recommendations.
 * For (1), a clutch bucket will be enqueued in the corresponding steal
 * silo and queue based on its preferred pset and scheduling bucket
 * respectively.
 * For (2), the running thread will set the bit on the processor based
 * on its preferred pset type.
 * For (3), the edge configuration would prevent threads from being stolen
 * in the wrong direction.
 *
 * = SCHED(thread_should_yield) =
 * The thread_should_yield() logic should remain close to matching what
 * thread_select() would do for a yielding thread. Note, cases where
 * thread_should_yield() answers "yes" but thread_select() does not
 * context-switch out the yielding thread still result in a transient
 * priority drop for the yielding thread (not to mention timing effects
 * from choosing to consult thread_select()), which could racily affect
 * migration decisions happening from other cores.
 */

static bool
sched_edge_steal_thread_enabled(__unused processor_set_t pset)
{
	return true;
}

/*
 * sched_edge_pset_peek_steal_possible()
 *
 * Routine to fast-path evaluate whether the steal_from_pset may
 * contain threads eligible to be stolen to the idle_pset.
 * Can be called WITHOUT either pset locked.
 */
static inline bool
sched_edge_pset_peek_steal_possible(
	processor_set_t steal_from_pset,
	processor_set_t idle_pset,
	bitmap_t silos_filter)
{
	bitmap_t populated_silos =
	    os_atomic_load(steal_from_pset->pset_clutch_root.scr_populated_steal_silos, relaxed);
	bitmap_t permissive_migration_allowed_map =
	    os_atomic_load(idle_pset->pset_clutch_root.scr_incoming_migration_allowed[PERMISSIVE_MIGRATION_BUCKET], relaxed);
	bitmap_t eligible_silos = silos_filter & populated_silos & permissive_migration_allowed_map;
	if (eligible_silos == 0) {
		/* No eligible silos that contain threads */
		return false;
	}
	for (int silo_id = lsb_first(eligible_silos); silo_id >= 0; silo_id = lsb_next(eligible_silos, silo_id)) {
		sched_edge_steal_silo_t steal_silo =
		    sched_edge_steal_silo_from_pset_id((pset_id_t)silo_id, &steal_from_pset->pset_clutch_root);
		bitmap_t populated_queues = os_atomic_load(steal_silo->sess_populated_steal_queues, relaxed);
		int highest_populated_bucket = lsb_first(populated_queues);
		if (highest_populated_bucket != -1) {
			sched_clutch_edge silo_edge =
			    sched_edge_config_get(silo_id, idle_pset->pset_id, highest_populated_bucket);
			if (silo_edge.sce_steal_allowed || (silo_id == idle_pset->pset_id)) {
				/* Found eligible candidate */
				return true;
			}
		}
	}
	/* Silos only contain threads of QoSes not allowed to be stolen across the edge */
	return false;
}

#if CONFIG_SCHED_PERF_ISLANDS

/*
 * sched_edge_crosses_perf_islands()
 *
 * Logic to infer whether two psets are considered to be
 * isolated in separate performance islands, for the purpose
 * of enforcing a more restrictive migration policy.
 */
static inline bool
sched_edge_crosses_perf_islands(processor_set_t src, processor_set_t dst, sched_clutch_edge edge)
{
	return (src->pset_id != dst->pset_id) && (edge.sce_migration_weight > 0) && (src->pset_type == dst->pset_type);
}

#endif /* CONFIG_SCHED_PERF_ISLANDS */

/*
 * Configurable behaviors when looking for threads to steal
 * out of a particular pset.
 */
__options_decl(sched_edge_steal_options_t, uint8_t, {
	SCHED_EDGE_STEAL_OPTIONS_NONE                 = 0x0,
	/* Only steal when there are more threads at the QoS than CPUs in the pset */
	SCHED_EDGE_STEAL_OPTIONS_ONLY_EXCESS_LOAD     = 0x1,
#if CONFIG_SCHED_PERF_ISLANDS
	/* Only steal when the load metric exceeds the edge weight from the silo */
	SCHED_EDGE_STEAL_OPTIONS_EDGE_THRESHOLD       = 0x2,
#endif /* CONFIG_SCHED_PERF_ISLANDS */
});

/*
 * sched_edge_pset_steal_thread()
 *
 * Routine to return the highest QoS thread enqueued in
 * steal_from_pset which is eligible to be stolen to
 * idle_pset, based on the policy configured in steal_options
 * combined with the Edge matrix.
 * Always called with the steal_from_pset locked.
 */
static thread_t
sched_edge_pset_steal_thread(
	processor_set_t steal_from_pset,
	processor_set_t idle_pset,
	bitmap_t silos_filter,
	sched_edge_steal_options_t steal_options)
{
	bitmap_t populated_silos =
	    os_atomic_load(steal_from_pset->pset_clutch_root.scr_populated_steal_silos, relaxed);
	bitmap_t silos_to_search = populated_silos & silos_filter;
	thread_t highest_pri_thread = THREAD_NULL;
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(idle_pset, &idle_pset->spill_search_order[TH_BUCKET_FIXPRI],
	    silos_to_search, &istate)) {
		int silo_id = istate.spis_pset_id;
		sched_edge_steal_silo_t steal_silo =
		    sched_edge_steal_silo_from_pset_id(silo_id, &steal_from_pset->pset_clutch_root);
		bitmap_t populated_queues = os_atomic_load(steal_silo->sess_populated_steal_queues, relaxed);
		for (int bucket = lsb_first(populated_queues); bucket >= 0; bucket = lsb_next(populated_queues, bucket)) {
			sched_clutch_edge silo_edge = sched_edge_config_get(silo_id, idle_pset->pset_id, bucket);
			if ((silo_edge.sce_steal_allowed == false) && (silo_id != idle_pset->pset_id)) {
				/*
				 * Stealing not allowed to the idle_pset for threads of this QoS and
				 * recommended to this silo.
				 * Assume that a higher QoS disallowing steal implies the same for
				 * all lower QoSes.
				 */
				break;
			}
			if (steal_options & SCHED_EDGE_STEAL_OPTIONS_ONLY_EXCESS_LOAD) {
				if (silo_edge.sce_migration_weight != 0) {
					uint32_t candidate_runq_depth = os_atomic_load(&steal_from_pset->pset_runnable_depth[bucket], relaxed);
					if (candidate_runq_depth <= pset_available_cpu_count(steal_from_pset)) {
						/* No excess threads at or above this bucket */
						continue;
					}
				}
			}
#if CONFIG_SCHED_PERF_ISLANDS
			if (steal_options & SCHED_EDGE_STEAL_OPTIONS_EDGE_THRESHOLD) {
				processor_set_t silo_pset = pset_for_id(silo_id);
				if (sched_edge_crosses_perf_islands(silo_pset, idle_pset, silo_edge)) {
					uint32_t candidate_load = sched_edge_pset_load_metric(silo_pset, bucket);
					uint32_t idle_load = sched_edge_pset_load_metric(idle_pset, bucket);
					if ((idle_load > candidate_load) || ((candidate_load - idle_load) < silo_edge.sce_migration_weight)) {
						/* Delta not high enough for us to steal */
						continue;
					}
				}
			}
#endif /* CONFIG_SCHED_PERF_ISLANDS */
			/* Thread candidate found */
			struct priority_queue_sched_max *steal_queue = &steal_silo->sess_steal_queues[bucket];
			sched_clutch_bucket_t clutch_bucket = priority_queue_max(steal_queue, struct sched_clutch_bucket, scb_stealqlink);
			thread_t thread = priority_queue_max(&clutch_bucket->scb_thread_runq, struct thread, th_clutch_runq_link);
			/* Bias ties in favor of psets earlier in the search order */
			if ((highest_pri_thread == THREAD_NULL) || (thread->sched_pri > highest_pri_thread->sched_pri)) {
				highest_pri_thread = thread;
			}
			/* Since this thread is from the highest eligible QoS we found in this silo, move on to search other silos */
			break;
		}
	}
	return highest_pri_thread;
}

static thread_t
sched_edge_foreign_runnable_thread_remove(processor_set_t idle_pset, uint64_t ctime)
{
	thread_t thread = THREAD_NULL;

	/*
	 * Search all the psets that are foreign for the idle_pset,
	 * iterating in reverse spill order to prioritize rescuing
	 * threads from their least desired, most "distant" spill
	 * location.
	 */
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	istate.spis_options = SCHED_PSET_ITERATE_STATE_OPTIONS_REVERSE;
	while (sched_iterate_psets_ordered(idle_pset, &idle_pset->spill_search_order[PERMISSIVE_MIGRATION_BUCKET],
	    idle_pset->foreign_psets[0], &istate)) {
		processor_set_t target_pset = pset_for_id(istate.spis_pset_id);
		/*
		 * For each pset, see if there are any runnable foreign threads.
		 * This check is currently being done without the pset lock to make it cheap for
		 * the common case.
		 */
		pset_node_t dst_node = pset_node_for_pset_type(idle_pset->pset_type);
		if (!sched_edge_pset_peek_steal_possible(target_pset, idle_pset, dst_node->pset_map)) {
			continue;
		}
		/*
		 * Looks like there are runnable foreign threads in the hierarchy; lock the pset
		 * and get the highest priority thread.
		 */
		pset_lock(target_pset);
		thread = sched_edge_pset_steal_thread(target_pset, idle_pset, dst_node->pset_map,
		    SCHED_EDGE_STEAL_OPTIONS_NONE);
		if (thread != THREAD_NULL) {
			sched_clutch_thread_remove(&target_pset->pset_clutch_root, thread, ctime, SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
			SCHED(update_pset_load_average)(target_pset, ctime);
		}
		pset_unlock(target_pset);

		/*
		 * Edge Scheduler Optimization
		 *
		 * The current implementation immediately returns as soon as it finds a foreign
		 * runnable thread. This could be enhanced to look at highest priority threads
		 * from all foreign psets and pick the highest amongst them. That would need
		 * some form of global state across psets to make that kind of a check cheap.
		 */
		if (thread != THREAD_NULL) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_REBAL_RUNNABLE) | DBG_FUNC_NONE, thread_tid(thread), idle_pset->pset_id, target_pset->pset_id, 0);
			break;
		}
		/* Looks like the thread escaped after the check but before the pset lock was taken; continue the search */
	}

	return thread;
}

/*
 * sched_edge_cpu_running_foreign_shared_rsrc_available()
 *
 * Routine to determine if the thread running on a CPU is a shared resource thread
 * and can be rebalanced to the pset with an idle CPU. It is used to determine if
 * a CPU going idle on a pset should rebalance a running shared resource heavy thread
 * from another non-ideal pset based on the former's shared resource load.
 * May be called WITHOUT the pset lock held.
 */
static bool
sched_edge_cpu_running_foreign_shared_rsrc_available(processor_set_t foreign_pset, int foreign_cpu, processor_set_t idle_pset)
{
	bool foreign_running_round_robin = atomic_bit_test(&foreign_pset->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_RR], foreign_cpu, memory_order_relaxed);
	bool foreign_running_native_first = atomic_bit_test(&foreign_pset->cpu_running_cluster_shared_rsrc_thread[CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST], foreign_cpu, memory_order_relaxed);
	bool idle_round_robin = sched_edge_shared_rsrc_idle(idle_pset, CLUSTER_SHARED_RSRC_TYPE_RR);
	bool idle_native_first = sched_edge_shared_rsrc_idle(idle_pset, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST);
	/* Enforce that for both shared resource policies, tagged threads do not "swim upstream" just because of an idle CPU */
	return (!foreign_running_round_robin || idle_round_robin) && (!foreign_running_native_first || idle_native_first);
}

/*
 * sched_edge_foreign_running_thread_available()
 *
 * Returns true if a foreign pset is found to be running a thread eligible
 * to be preempted and rebalanced to the idle_pset.
 * Called WITHOUT the pset lock held.
 */
static bool
sched_edge_foreign_running_thread_available(processor_set_t idle_pset)
{
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(idle_pset, &idle_pset->spill_search_order[PERMISSIVE_MIGRATION_BUCKET],
	    idle_pset->foreign_psets[0], &istate)) {
		processor_set_t candidate_pset = pset_for_id(istate.spis_pset_id);
		int candidate_cpuid = sched_edge_running_rebal_candidate_best_eligible_cpu(idle_pset, candidate_pset, NULL, false);
		if (candidate_cpuid != -1) {
			return true;
		}
	}
	return false;
}

static thread_t
sched_edge_steal_thread(processor_set_t idle_pset, uint64_t candidate_pset_bitmap)
{
	thread_t stolen_thread = THREAD_NULL;

	/*
	 * Edge Scheduler Optimization
	 *
	 * The logic today bails as soon as it finds a pset where the pset load is
	 * greater than the edge weight. Maybe it should have a more advanced version
	 * which looks for the maximum delta etc.
	 */
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(idle_pset, &idle_pset->spill_search_order[PERMISSIVE_MIGRATION_BUCKET], candidate_pset_bitmap, &istate)) {
		processor_set_t steal_from_pset = pset_for_id(istate.spis_pset_id);
		bitmap_t migration_allowed_map =
		    os_atomic_load(idle_pset->pset_clutch_root.scr_incoming_migration_allowed[PERMISSIVE_MIGRATION_BUCKET], relaxed);
		if (!sched_edge_pset_peek_steal_possible(steal_from_pset, idle_pset, migration_allowed_map)) {
			continue;
		}
		pset_lock(steal_from_pset);

		sched_edge_steal_options_t steal_options = SCHED_EDGE_STEAL_OPTIONS_ONLY_EXCESS_LOAD;
#if CONFIG_SCHED_PERF_ISLANDS
		steal_options |= SCHED_EDGE_STEAL_OPTIONS_EDGE_THRESHOLD;
#endif /* CONFIG_SCHED_PERF_ISLANDS */
		stolen_thread = sched_edge_pset_steal_thread(steal_from_pset, idle_pset, migration_allowed_map, steal_options);

		if (stolen_thread != THREAD_NULL) {
			uint64_t current_timestamp = mach_absolute_time();
			sched_clutch_thread_remove(&steal_from_pset->pset_clutch_root, stolen_thread, current_timestamp, SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
			SCHED(update_pset_load_average)(steal_from_pset, current_timestamp);
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STEAL) | DBG_FUNC_NONE, thread_tid(stolen_thread), idle_pset->pset_id, steal_from_pset->pset_id, 0);
		}

		pset_unlock(steal_from_pset);
		if (stolen_thread != THREAD_NULL) {
			break;
		}
	}
	return stolen_thread;
}

/*
 * sched_edge_processor_idle()
 *
 * The routine is the implementation for steal_thread() for the Edge scheduler.
 */
static thread_t
sched_edge_processor_idle(processor_set_t pset)
{
	thread_t thread = THREAD_NULL;

	uint64_t ctime = mach_absolute_time();

	processor_t processor = current_processor();
	bit_clear(pset->pending_spill_cpu_mask, processor->cpu_id);

	/* Each of the operations acquire the lock for the pset they target */
	pset_unlock(pset);

	/* Find highest priority runnable thread on all non-native psets */
	thread = sched_edge_foreign_runnable_thread_remove(pset, ctime);
	if (thread != THREAD_NULL) {
		return thread;
	}

	/* Find highest priority runnable thread on all native psets */
	thread = sched_edge_steal_thread(pset, pset->native_psets[0]);
	if (thread != THREAD_NULL) {
		return thread;
	}

	/* Find foreign running threads to rebalance; the actual rebalance is done in sched_edge_balance() */
	boolean_t rebalance_needed = sched_edge_foreign_running_thread_available(pset);
	if (rebalance_needed) {
		return THREAD_NULL;
	}

	/* No foreign-enqueued threads found; find a thread to steal from all psets based on weights/loads etc. */
	thread = sched_edge_steal_thread(pset, pset->native_psets[0] | pset->foreign_psets[0]);
	return thread;
}

/* Return true if this shared resource thread has a better pset to run on */
static bool
sched_edge_shared_rsrc_migrate_possible(thread_t thread, processor_set_t preferred_pset, processor_set_t current_pset)
{
	cluster_shared_rsrc_type_t shared_rsrc_type = sched_edge_thread_shared_rsrc_type(thread);
	uint64_t current_cluster_load = sched_edge_pset_cluster_shared_rsrc_load(current_pset, shared_rsrc_type);
	/*
	 * Adjust the current pset load to discount the current thread only if the current pset is a preferred pset type. This allows the
	 * scheduler to rebalance threads from non-preferred cluster to an idle cluster of the preferred type.
	 *
	 * Edge Scheduler Optimization
	 * For multi-cluster machines, it might be useful to enhance this mechanism to migrate between clusters of the preferred type.
	 */
	uint64_t current_pset_adjusted_load = (current_pset->pset_type != preferred_pset->pset_type) ? current_cluster_load : (current_cluster_load - 1);

	uint64_t eligible_pset_bitmask = 0;
	if (edge_shared_rsrc_policy[shared_rsrc_type] == EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST) {
		/*
		 * For the EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST policy, the load balancing occurs
		 * only among clusters native with the preferred cluster.
		 */
		eligible_pset_bitmask = preferred_pset->native_psets[0];
		bit_set(eligible_pset_bitmask, preferred_pset->pset_id);
	} else {
		/* For EDGE_SHARED_RSRC_SCHED_POLICY_RR, the load balancing happens among all clusters */
		eligible_pset_bitmask = os_atomic_load(&sched_edge_available_pset_bitmask[0], relaxed);
	}

	/* For each eligible cluster check if there is an under-utilized cluster; return true if there is */
	for (int pset_id = bit_first(eligible_pset_bitmask); pset_id >= 0; pset_id = bit_next(eligible_pset_bitmask, pset_id)) {
		if (pset_id == current_pset->pset_id) {
			continue;
		}
		uint64_t cluster_load = sched_edge_pset_cluster_shared_rsrc_load(pset_array[pset_id], shared_rsrc_type);
		if (current_pset_adjusted_load > cluster_load) {
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_SHARED_RSRC_MIGRATE) | DBG_FUNC_NONE, current_cluster_load, current_pset->pset_id, cluster_load, pset_id);
			return true;
		}
	}
	return false;
}

/*
 * Stir-the-pot Registry:
 *
 * Global state tracking which cores currently have threads that
 * are ready to be stirred onto cores of the opposite type.
 *
 * The registry state updates are implemented with atomic transaction
 * operations rather than a global lock, in order to avoid the cost
 * of serializing some of the most frequent registry state update
 * callsites that depend on consistent speed--namely the
 * preemption check and context-switch paths. The most expensive
 * state update, in sched_edge_stir_the_pot_try_trigger_swap(), only
 * happens at quantum expiration, which should allow cheaper
 * operations at other callsites to win the race.
 */
typedef unsigned __int128 sched_edge_stp_registry_t;
_Atomic sched_edge_stp_registry_t sched_edge_stir_the_pot_global_registry = 0LL;
#define SESTP_BITS_PER_CORE (2)
#define SESTP_BIT_POS(cpu_id) ((sched_edge_stp_registry_t)(cpu_id * SESTP_BITS_PER_CORE))
#define SESTP_MASK(cpu_id) ((sched_edge_stp_registry_t)bits_mask(SESTP_BITS_PER_CORE) << SESTP_BIT_POS(cpu_id))
static_assert((SESTP_BITS_PER_CORE * MAX_CPUS) <= (sizeof(sched_edge_stp_registry_t) * 8),
    "Global registry must fit per-core bits for each core");

#define SESTP_EXTRACT_STATE(registry, cpu_id) ((registry >> SESTP_BIT_POS(cpu_id)) & bits_mask(SESTP_BITS_PER_CORE))
#define SESTP_SET_STATE(registry, cpu_id, state) ((registry & ~SESTP_MASK(cpu_id)) | ((sched_edge_stp_registry_t)state << SESTP_BIT_POS(cpu_id)))
__enum_decl(sched_edge_stp_state_t, uint8_t, {
	SCHED_EDGE_STP_NOT_WANT          = 0,
	SCHED_EDGE_STP_REQUESTED         = 1,
	SCHED_EDGE_STP_PENDING_SELF      = 2,
	SCHED_EDGE_STP_PENDING_EXTERNAL  = 3,
	SCHED_EDGE_STP_MAX               = SCHED_EDGE_STP_PENDING_EXTERNAL
});
static_assert(SCHED_EDGE_STP_MAX <= bits_mask(SESTP_BITS_PER_CORE),
    "Per-core stir-the-pot request state must fit in per-core bits");

#if OS_ATOMIC_USE_LLSC
#error "Expecting CAS implementation of os_atomic_rmw_loop()"
#endif /* OS_ATOMIC_USE_LLSC */

static cpumap_t sched_edge_p_core_map = 0ULL;
static cpumap_t sched_edge_non_p_core_map = 0ULL;

/*
 * In order to reduce the chance of picking the same CPUs over
 * and over unfairly for stir-the-pot swaps, use an offset value
 * for the lsb selection, which rotates by one index each time
 * the choice is evaluated.
 */
static _Atomic uint64_t sched_edge_stp_selection_p_core_offset = 0;
static _Atomic uint64_t sched_edge_stp_selection_non_p_core_offset = 0;

/*
 * sched_edge_stir_the_pot_try_trigger_swap()
 *
 * Search for an eligible swap candidate on the opposite core
 * type, and if one is found, initiate a swap for stir-the-pot.
 * From a P-core, initiating means sending an inbox message and IPI
 * to the swapping lower performance core. For initiating swap from
 * a lower performance core, only an inbox message needs to be sent
 * to itself, naming the P-core for swap.
 * If no eligible candidate is found, mark the current processor
 * as requesting stir-the-pot swap--that is unless a swap has already
 * been initiated for this core, in which case we should sit tight.
 * Thread lock must be held.
 */
static inline int
sched_edge_stir_the_pot_try_trigger_swap(thread_t thread)
{
	processor_t self_processor = current_processor();
	int self_cpu = self_processor->cpu_id;
	/*
	 * Prepare the core mask of candidate cores (of the opposite type),
	 * and compute an offset where the candidate search should begin,
	 * to avoid unfairly swapping with the same cores repeatedly.
	 */
	cpumap_t swap_candidates_map;
	uint64_t offset;
	if (sched_edge_stir_the_pot_core_type_is_desired(self_processor->processor_set)) {
		swap_candidates_map = sched_edge_non_p_core_map;
		offset = os_atomic_inc_orig(&sched_edge_stp_selection_non_p_core_offset, relaxed);
	} else {
		swap_candidates_map = sched_edge_p_core_map;
		offset = os_atomic_inc_orig(&sched_edge_stp_selection_p_core_offset, relaxed);
	}
	int num_candidates = bit_count(swap_candidates_map);
	if (num_candidates == 0) {
		/* Too early in boot, no cores of opposite type */
		return -1;
	}
	int cpu_of_type_offset_ind = offset % num_candidates;
	int search_start_ind = lsb_first(swap_candidates_map);
	for (int i = 0; i < cpu_of_type_offset_ind; i++) {
		search_start_ind = lsb_next(swap_candidates_map, search_start_ind);
		assert3s(search_start_ind, !=, -1);
	}
	assert3s(search_start_ind, !=, -1);
	swap_candidates_map = bit_ror64(swap_candidates_map, search_start_ind);
	/*
	 * Search the registry for candidate cores of the opposite type which
	 * have requested swap.
	 */
	int swap_cpu;
	sched_edge_stp_registry_t old_registry, new_registry, intermediate_registry;
	sched_edge_stp_state_t self_state;
	/* BEGIN IGNORE CODESTYLE */
	os_atomic_rmw_loop(&sched_edge_stir_the_pot_global_registry,
	    old_registry, new_registry, relaxed, {
		swap_cpu = -1;
		self_state = SESTP_EXTRACT_STATE(old_registry, self_cpu);
		if (self_state == SCHED_EDGE_STP_PENDING_EXTERNAL) {
			/*
			 * Another core already initiated a swap with us, so we should
			 * wait for that one to finish rather than initiate or request
			 * a new one.
			 * Do convert this CPU's registry state to PENDING_SELF, so
			 * that if we still haven't swapped by the next quantum, we can
			 * re-try to trigger swap then.
			 */
			intermediate_registry = SESTP_SET_STATE(old_registry, self_cpu, SCHED_EDGE_STP_PENDING_SELF);
		} else {
			/* Scan candidates */
			sched_bucket_t self_qos = thread->th_sched_bucket;
			for (int rotid = lsb_first(swap_candidates_map); rotid != -1; rotid = lsb_next(swap_candidates_map, rotid)) {
				int candidate_cpu = (rotid + search_start_ind) % 64; // un-rotate the bit
				sched_edge_stp_state_t candidate_state = SESTP_EXTRACT_STATE(old_registry, candidate_cpu);
				if (candidate_state == SCHED_EDGE_STP_REQUESTED) {
					sched_bucket_t candidate_qos = os_atomic_load(
						&processor_array[candidate_cpu]->processor_set->cpu_running_buckets[candidate_cpu], relaxed);
					if (candidate_qos == self_qos) {
						/* Found a requesting candidate of matching QoS */
						swap_cpu = candidate_cpu;
						break;
					}
				}
			}
			if (swap_cpu == -1) {
				/* No candidates requesting swap, so mark this core as requesting */
				intermediate_registry = SESTP_SET_STATE(old_registry, self_cpu, SCHED_EDGE_STP_REQUESTED);
			} else {
				/*
				* Mark candidate core as selected/pending for swap, and mark
				* current CPU as not needing a swap anymore, since we will now
				* start one.
				*/
				intermediate_registry = SESTP_SET_STATE(old_registry, self_cpu, SCHED_EDGE_STP_PENDING_SELF);
				intermediate_registry = SESTP_SET_STATE(intermediate_registry, swap_cpu, SCHED_EDGE_STP_PENDING_EXTERNAL);
			}
		}
		/* Publish updates to registry state */
		new_registry = intermediate_registry;
	});
	/* END IGNORE CODESTYLE */
	/* Leave debug tracepoints for tracking any updates to registry state */
	sched_edge_stp_state_t new_self_state = SESTP_EXTRACT_STATE(new_registry, self_cpu);
	if (new_self_state == SCHED_EDGE_STP_REQUESTED && self_state != SCHED_EDGE_STP_REQUESTED) {
		/* Self now requesting */
		assert((self_state == SCHED_EDGE_STP_NOT_WANT) || (self_state == SCHED_EDGE_STP_PENDING_SELF));
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) |
		    DBG_FUNC_START, 0, self_cpu, cpu_of_type_offset_ind, 0);
	}
	if (new_self_state != SCHED_EDGE_STP_REQUESTED && self_state == SCHED_EDGE_STP_REQUESTED) {
		/* Self now pending */
		assert3u(new_self_state, ==, SCHED_EDGE_STP_PENDING_SELF);
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) |
		    DBG_FUNC_END, 1, self_cpu, cpu_of_type_offset_ind, 0);
	}
	if (swap_cpu != -1) {
		/* Swap core now pending */
		assert3u(SESTP_EXTRACT_STATE(old_registry, swap_cpu), ==, SCHED_EDGE_STP_REQUESTED);
		assert3u(SESTP_EXTRACT_STATE(new_registry, swap_cpu), ==, SCHED_EDGE_STP_PENDING_EXTERNAL);
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) |
		    DBG_FUNC_END, 1, swap_cpu, cpu_of_type_offset_ind, 0);

		/* Initiate a stir-the-pot swap */
		assert3s(swap_cpu, <, ml_get_topology_info()->num_cpus);
		assert3s(swap_cpu, !=, self_processor->cpu_id);
		processor_t swap_processor = processor_array[swap_cpu];
		if (swap_processor == PROCESSOR_NULL) {
			/* Unlikely early boot initialization race */
			return -1;
		}
		assert3u(sched_edge_stir_the_pot_core_type_is_desired(swap_processor->processor_set), !=,
		    sched_edge_stir_the_pot_core_type_is_desired(self_processor->processor_set));
		if (sched_edge_stir_the_pot_core_type_is_desired(self_processor->processor_set)) {
			/*
			 * Send a message and IPI notification to the lower-performance
			 * core we found which wants to swap, so it will know to send its
			 * thread back here.
			 */
			os_atomic_store(&swap_processor->stir_the_pot_inbox_cpu, self_cpu, relaxed);
			processor_set_t swap_pset = swap_processor->processor_set;
			pset_lock(swap_pset);
			sched_ipi_type_t ipi_type = sched_ipi_action(swap_processor, NULL,
			    SCHED_IPI_EVENT_REBALANCE);
			pset_unlock(swap_pset);
			sched_ipi_perform(swap_processor, ipi_type);
		} else {
			/*
			 * Send message to self to send this thread to the swap P-core. P-core
			 * will clear its own pending state upon commiting to the incoming swap
			 * thread after that happens.
			 */
			os_atomic_store(&self_processor->stir_the_pot_inbox_cpu, swap_cpu, relaxed);
		}
	}
	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) | DBG_FUNC_NONE,
	    (swap_cpu != -1) ? 1 : 0, swap_cpu, old_registry, cpu_of_type_offset_ind);
	return swap_cpu;
}

/*
 * sched_edge_stir_the_pot_clear_registry_entry()
 *
 * Mark the current CPU as NOT containing a thread which is eligible
 * to be swapped for stir-the-pot.
 * Preemption must be disabled.
 */
void
sched_edge_stir_the_pot_clear_registry_entry(void)
{
	int self_cpu = current_processor()->cpu_id;
	sched_edge_stp_state_t self_state;
	sched_edge_stp_registry_t old_registry, new_registry;
	os_atomic_rmw_loop(&sched_edge_stir_the_pot_global_registry,
	    old_registry, new_registry, relaxed, {
		self_state = SESTP_EXTRACT_STATE(old_registry, self_cpu);
		if (self_state == SCHED_EDGE_STP_NOT_WANT) {
		        /* State already cleared, nothing to be done */
		        os_atomic_rmw_loop_give_up(break);
		}
		new_registry = SESTP_SET_STATE(old_registry, self_cpu, SCHED_EDGE_STP_NOT_WANT);
	});
	if (self_state == SCHED_EDGE_STP_REQUESTED) {
		/* Request was cleared */
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) | DBG_FUNC_END,
		    2, self_cpu, 0, 0);
	}
}

/*
 * sched_edge_stir_the_pot_set_registry_entry()
 *
 * Mark the current CPU as containing a thread which is eligible
 * to be swapped to a core of the opposite type for stir-the-pot.
 * Preemption must be disabled.
 */
static inline void
sched_edge_stir_the_pot_set_registry_entry(bool override_pending_state)
{
	int self_cpu = current_processor()->cpu_id;
	sched_edge_stp_state_t self_state;
	sched_edge_stp_registry_t old_registry, new_registry;
	bool newly_requested = os_atomic_rmw_loop(&sched_edge_stir_the_pot_global_registry,
	    old_registry, new_registry, relaxed, {
		self_state = SESTP_EXTRACT_STATE(old_registry, self_cpu);
		if (self_state == SCHED_EDGE_STP_REQUESTED) {
		        /* Core already registered, nothing to be done */
		        os_atomic_rmw_loop_give_up(break);
		} else if (!override_pending_state &&
		(self_state == SCHED_EDGE_STP_PENDING_SELF || self_state == SCHED_EDGE_STP_PENDING_EXTERNAL)) {
		        /* Core is already pending a swap for the running thread */
		        os_atomic_rmw_loop_give_up(break);
		}
		new_registry = SESTP_SET_STATE(old_registry, self_cpu, SCHED_EDGE_STP_REQUESTED);
	});
	if (newly_requested) {
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) | DBG_FUNC_START,
		    3, self_cpu, self_state, 0);
	}
}

/* Stir-the-pot is designed for sharing time on the P-cores */
static inline bool
sched_edge_stir_the_pot_core_type_is_desired(processor_set_t pset)
{
	return pset->pset_type == PSET_AMP_P;
}

static inline bool
sched_edge_thread_eligible_for_rebalance(thread_t thread)
{
	assert(((thread->state & TH_IDLE) == 0) || (SCHED_CLUTCH_THREAD_ELIGIBLE(thread) == false));
	return (thread->sched_pri < BASEPRI_RTQUEUES) &&
	       SCHED_CLUTCH_THREAD_ELIGIBLE(thread) &&
	       (SCHED_CLUTCH_THREAD_PSET_BOUND(thread) == false);
}

/*
 * sched_edge_stir_the_pot_thread_eligible()
 *
 * Determine whether a thread is eligible to engage in a
 * stir-the-pot swap. It must be P-recommended, unbound, and not
 * round-robin shared resource. Additionally, it must have already
 * expired quantum on its current core type.
 */
static inline bool
sched_edge_stir_the_pot_thread_eligible(thread_t thread)
{
	processor_set_t preferred_pset;
	if ((thread == THREAD_NULL) ||
	    ((preferred_pset = pset_array[sched_edge_thread_preferred_pset(thread)]) == PROCESSOR_SET_NULL)) {
		/* Still initializing at boot */
		return false;
	}
	cluster_shared_rsrc_type_t shared_rsrc_type = sched_edge_thread_shared_rsrc_type(thread);
	bool right_kind_of_thread =
	    sched_edge_stir_the_pot_core_type_is_desired(preferred_pset) &&
	    sched_edge_thread_eligible_for_rebalance(thread) &&
	    (shared_rsrc_type == CLUSTER_SHARED_RSRC_TYPE_NONE ||
	    shared_rsrc_type == CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST);
	bool ready_for_swap = sched_edge_stir_the_pot_core_type_is_desired(current_processor()->processor_set) ?
	    thread->th_expired_quantum_on_higher_core :
	    thread->th_expired_quantum_on_lower_core;
	return right_kind_of_thread && ready_for_swap;
}

/*
 * sched_edge_stir_the_pot_check_inbox_for_thread()
 *
 * Called from the processor (as current_processor()) where this thread is
 * or was just running, in order to check whether this thread has been
 * chosen by a P-core to swap places for stir-the-pot.
 * May optionally consume the inbox message on behalf of this thread, in
 * which case, the thread should already be context-switched off-core.
 * Additionally has the side effect of updating registry state for the
 * current_processor().
 * Preemption must be disabled.
 */
static inline int
sched_edge_stir_the_pot_check_inbox_for_thread(thread_t thread, bool consume_message)
{
	processor_t self_processor = current_processor();
	int dst_cpu = -1;
	if (sched_edge_stir_the_pot_thread_eligible(thread)) {
		/* Thread can accept the inbox message */
		dst_cpu = os_atomic_load(&self_processor->stir_the_pot_inbox_cpu, relaxed);
	}
	if (consume_message) {
		assert3p(thread, !=, self_processor->active_thread);
		/*
		 * Unconditionally clear inbox, since either we are using the
		 * message for a swap now or ultimately discarding it if
		 * conditions have changed (thread not eligible).
		 */
		os_atomic_store(&self_processor->stir_the_pot_inbox_cpu, -1, relaxed);
	} else {
		/*
		 * Note, we don't clear a possible inbox message, in case an eligible
		 * thread is still on-core or comes back on-core quickly to receive it.
		 */
	}
	/*
	 * Need to update stir-the-pot registry status if we delayed requesting
	 * stir-the-pot due to a pending inbox message for the previous thread.
	 *
	 * If there is no previous thread and we are just evaluating preemption,
	 * we should still keep the registry status as up-to-date as possible,
	 * as eligibility conditions could have changed for the running thread.
	 */
	sched_edge_stir_the_pot_update_registry_state(self_processor->active_thread, consume_message);
	return dst_cpu;
}

/*
 * sched_edge_stir_the_pot_update_registry_state()
 *
 * Update stir-the-pot state for the current processor based on its
 * (possibly new) current thread. This sets or clears the registry state
 * which indicates whether the processor is running a thread that wants
 * and is eligible to be swapped with a thread on the opposite core type.
 * Preemption must be disabled.
 */
void
sched_edge_stir_the_pot_update_registry_state(thread_t thread, bool thread_is_new)
{
	processor_t self_processor = current_processor();
	/*
	 * Clear corresponding th_expired_quantum_on_ field now that thread
	 * is getting a chance to run on the opposite type.
	 */
	if (sched_edge_stir_the_pot_core_type_is_desired(self_processor->processor_set)) {
		thread->th_expired_quantum_on_lower_core = false;
	} else {
		thread->th_expired_quantum_on_higher_core = false;
	}
	if (sched_edge_stir_the_pot_thread_eligible(thread)) {
		int inbox_message = os_atomic_load(&self_processor->stir_the_pot_inbox_cpu, relaxed);
		if (inbox_message == -1) {
			/* Set the registry bit */
			sched_edge_stir_the_pot_set_registry_entry(thread_is_new);
		} else {
			assert(sched_edge_stir_the_pot_core_type_is_desired(self_processor->processor_set) == false);
			/*
			 * There's an inbox message which still needs to be used at the next
			 * migration decision, so avoid starting a new request or clearing the
			 * interim pending status until then.
			 */
		}
	} else {
		/* Thread is ineligible for swap, so clear the registry bit */
		sched_edge_stir_the_pot_clear_registry_entry();
	}
}

/*
 * sched_edge_update_running_foreign_state()
 *
 * Update the bitmap which allows the Edge scheduler to quickly find CPUs running
 * foreign threads (threads preferring a different core type) for rebalancing. The
 * bitmap should be updated every time a new thread is assigned to run on a processor.
 * May be called WITHOUT the pset lock held.
 */
void
sched_edge_update_running_foreign_state(processor_t processor, thread_t thread)
{
	pset_type_t current_processor_type = processor->processor_set->pset_type;
	pset_type_t thread_preferred_type = pset_type_for_id(sched_edge_thread_preferred_pset(thread));
	if (sched_edge_thread_eligible_for_rebalance(thread) && (current_processor_type != thread_preferred_type)) {
		atomic_bit_set(&processor->processor_set->cpu_running_foreign, processor->cpu_id, memory_order_relaxed);
	} else {
		atomic_bit_clear(&processor->processor_set->cpu_running_foreign, processor->cpu_id, memory_order_relaxed);
	}
}

/*
 * sched_edge_quantum_expire()
 *
 * Update stir-the-pot eligibility and drive stir-the-pot swaps.
 * Thread lock must be held.
 */
static void
sched_edge_quantum_expire(thread_t thread)
{
	if (sched_edge_stir_the_pot_core_type_is_desired(current_processor()->processor_set)) {
		thread->th_expired_quantum_on_higher_core = true;
	} else {
		thread->th_expired_quantum_on_lower_core = true;
	}
	if (sched_edge_stir_the_pot_thread_eligible(thread)) {
		sched_edge_stir_the_pot_try_trigger_swap(thread);
	}
}

/*
 * sched_edge_run_count_incr()
 *
 * Update runnable thread counts in the same way as
 * sched_clutch_run_incr(), and reset per-thread, quantum-
 * expired tracking used by stir-the-pot, as the thread
 * is unblocking.
 */
static uint32_t
sched_edge_run_count_incr(thread_t thread)
{
	uint32_t new_count = sched_clutch_run_incr(thread);
	/* Thread is unblocking and so resets its quantum tracking */
	thread->th_expired_quantum_on_lower_core = false;
	thread->th_expired_quantum_on_higher_core = false;
	return new_count;
}

/*
 * sched_edge_thread_avoid_processor()
 *
 * Return true if this thread should not continue running on this processor,
 * either because it is no longer allowed to run here or because there is a
 * better place where it would prefer to run.
 * Called on current_processor(), for the current thread, with the pset lock held.
 */
static bool
sched_edge_thread_avoid_processor(processor_t processor, thread_t thread, ast_t reason)
{
	assert3p(processor, ==, current_processor());
	assert3p(thread, ==, processor->active_thread);

	if (thread->bound_processor == processor) {
		/* Thread is bound here */
		return false;
	}

	/*
	 * On quantum expiry, check the migration bitmask if this thread should be migrated off this core.
	 * A migration is only recommended if there's also an idle core available that needn't be avoided.
	 */
	if (reason & AST_QUANTUM) {
		if (bit_test(processor->processor_set->perfcontrol_cpu_migration_bitmask, processor->cpu_id)) {
			uint64_t non_avoided_idle_primary_map = processor->processor_set->cpu_state_map[PROCESSOR_IDLE] & processor->processor_set->recommended_bitmask & ~processor->processor_set->perfcontrol_cpu_migration_bitmask;
			if (non_avoided_idle_primary_map != 0) {
				return true;
			}
		}
	}

	processor_set_t preferred_pset = pset_array[sched_edge_thread_preferred_pset(thread)];

	if (SCHED_CLUTCH_THREAD_PSET_BOUND(thread) &&
	    preferred_pset->pset_id != processor->processor_set->pset_id &&
	    pset_type_is_recommended(preferred_pset)) {
		/* We should send this thread to the bound pset */
		return true;
	}

	sched_clutch_edge edge = (thread->sched_pri >= BASEPRI_RTQUEUES)
	    ? sched_rt_config_get(preferred_pset->pset_id, processor->processor_set->pset_id)
	    : sched_edge_config_get(preferred_pset->pset_id, processor->processor_set->pset_id, thread->th_sched_bucket);
	if (SCHED_CLUTCH_THREAD_PSET_BOUND(thread) == false &&
	    preferred_pset->pset_id != processor->processor_set->pset_id &&
	    edge.sce_migration_allowed == false &&
	    edge.sce_steal_allowed == false) {
		/*
		 * Thread isn't allowed to be here, according to the edge migration graph.
		 * Perhaps the thread's priority or boundness or its thread group's preferred
		 * pset or the edge migration graph changed.
		 *
		 * We should only preempt after confirming the thread actually has a
		 * recommended, allowed alternative pset to run on.
		 */
		for (uint32_t pset_id = 0; pset_id < sched_num_psets; pset_id++) {
			if (pset_id == processor->processor_set->pset_id) {
				continue;
			}
			edge = (thread->sched_pri >= BASEPRI_RTQUEUES)
			    ? sched_rt_config_get(preferred_pset->pset_id, pset_id)
			    : sched_edge_config_get(preferred_pset->pset_id, pset_id, thread->th_sched_bucket);
			if (pset_is_recommended(pset_array[pset_id]) && ((pset_id == preferred_pset->pset_id) || edge.sce_migration_allowed)) {
				/* Thread can be run elsewhere. */
				return true;
			}
		}
	}

	/* Evaluate shared resource policies */
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_RR)) {
		return sched_edge_shared_rsrc_migrate_possible(thread, preferred_pset, processor->processor_set);
	}
	if (thread_shared_rsrc_policy_get(thread, CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST)) {
		if (processor->processor_set->pset_type != preferred_pset->pset_type &&
		    pset_type_is_recommended(preferred_pset)) {
			return true;
		}
		return sched_edge_shared_rsrc_migrate_possible(thread, preferred_pset, processor->processor_set);
	}

	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		return false;
	}
	/* ~~ No realtime or shared resource threads beyond this point ~~ */

	/*
	 * Stir-the-Pot:
	 * A non-P-core should preempt if a P-core has been found to swap the current,
	 * quantum-expired thread to for stir-the-pot. This is in order for threads in a
	 * multi-threaded workload to share time on the P-cores so they make roughly equal
	 * forward progress.
	 */
	if (sched_edge_stir_the_pot_check_inbox_for_thread(thread, false) != -1) {
		return true;
	}

	/*
	 * Compaction:
	 * If the preferred pset for the thread is now idle, try and migrate the thread to that pset.
	 */
	if ((processor->processor_set != preferred_pset) &&
	    (sched_edge_pset_load_metric(preferred_pset, thread->th_sched_bucket) == 0)) {
		return true;
	}

	/*
	 * Running Rebalance:
	 * We are willing to preempt the thread in order to migrate it onto an idle core
	 * of the preferred type.
	 */
	if ((processor->processor_set->pset_type != preferred_pset->pset_type) &&
	    pset_type_is_recommended(preferred_pset)) {
		/* Scan for idle pset */
		for (uint32_t pset_id = 0; pset_id < sched_num_psets; pset_id++) {
			processor_set_t candidate_pset = pset_array[pset_id];
			edge = sched_edge_config_get(preferred_pset->pset_id, pset_id, thread->th_sched_bucket);
			if ((candidate_pset->pset_type == preferred_pset->pset_type) &&
			    edge.sce_migration_allowed &&
			    (sched_edge_pset_load_metric(candidate_pset, thread->th_sched_bucket) == 0)) {
				return true;
			}
		}
	}

	return false;
}

/*
 * sched_edge_running_rebal_candidate_best_eligible_cpu()
 *
 * Routine to scan CPUs in the foreign candidate_pset and return the one
 * which is running the highest QoS thread that is also eligible to be
 * preempted and rebalanced onto idle_pset. Returns -1 if no eligible CPU
 * is found. And if highest_eligible_qos_observed is non-null, there is an
 * added requirement for the best eligible CPU in candidate_pset to be of a
 * strictly higher QoS than *highest_eligible_qos_observed in order to be
 * returned and written into highest_eligible_qos_observed as the new highest.
 */
static int
sched_edge_running_rebal_candidate_best_eligible_cpu(processor_set_t idle_pset, processor_set_t candidate_pset,
    sched_bucket_t *highest_eligible_qos_observed, bool pset_lock_held)
{
	assert3u(idle_pset->foreign_psets[0], &, BIT(candidate_pset->pset_id));
	uint64_t foreign_map = os_atomic_load(&candidate_pset->cpu_running_foreign, relaxed);
	uint64_t running_map = UINT64_MAX;
	if (pset_lock_held) {
		/*
		 * Typically, a pset->cpu_running_foreign bit set implies that the
		 * corresponding CPU is currently in or will immently enter PROCESSOR_RUNNING
		 * state. But since pset->cpu_running_foreign can be edited out from under
		 * the pset lock, it could be found out-of-sync with pset->cpu_state_map. This
		 * is why we permit skipping the cpu_state_map check for the racy evaluation
		 * and require checking it when the pset lock is held.
		 */
		running_map = os_atomic_load(&candidate_pset->cpu_state_map[PROCESSOR_RUNNING], relaxed);
	}
	uint64_t pending_AST_preempt_map = os_atomic_load(&candidate_pset->pending_AST_PREEMPT_cpu_mask, relaxed);
	uint64_t rebalance_eligible_candidates_map = foreign_map & running_map & ~pending_AST_preempt_map;
	sched_bucket_t local_highest_qos = TH_BUCKET_SCHED_MAX;
	int best_candidate_cpuid = -1;
	for (int cpuid = lsb_first(rebalance_eligible_candidates_map); cpuid >= 0;
	    cpuid = lsb_next(rebalance_eligible_candidates_map, cpuid)) {
		if (!sched_edge_cpu_running_foreign_shared_rsrc_available(candidate_pset, cpuid, idle_pset)) {
			continue;
		}
		sched_bucket_t running_qos = os_atomic_load(&candidate_pset->cpu_running_buckets[cpuid], relaxed);
		if (running_qos < local_highest_qos) {
			local_highest_qos = running_qos;
			best_candidate_cpuid = cpuid;
		}
	}
	if (highest_eligible_qos_observed != NULL) {
		if (local_highest_qos < *highest_eligible_qos_observed) {
			*highest_eligible_qos_observed = local_highest_qos;
			return best_candidate_cpuid;
		}
		/* Locally highest QoS is lower than previously seen */
		return -1;
	}
	return best_candidate_cpuid;
}

/*
 * sched_edge_balance()
 *
 * Routine to optionally IPI a CPU from a non-native pset and that
 * is currently running a foreign thread eligible to be preempted
 * and rebalanced onto the idle_processor. Attempts to find the CPU
 * running the highest QoS such thread, and returns true if any
 * eligible CPU was found and IPIed, which indicates that a thread
 * is imminently anticipated to make its way back to idle_processor.
 * Called with idle_pset's lock held but drops it before returning.
 */
static bool
sched_edge_balance(__unused processor_t idle_processor, processor_set_t idle_pset)
{
	assert(idle_processor == current_processor());
	pset_unlock(idle_pset);

	/*
	 * Iterate over all psets without acquiring pset locks, and racily
	 * evaluate which CPU is running the highest QoS, rebalance-eligible
	 * thread. That will inform us which pset to lock first to find a
	 * candidate with increased odds of actually being the best.
	 * Iterate in reverse spill order to prefer rescuing threads from
	 * their least desired, most "distant" spill location.
	 */
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	istate.spis_options = SCHED_PSET_ITERATE_STATE_OPTIONS_REVERSE;
	sched_bucket_t global_racy_highest_qos = TH_BUCKET_SCHED_MAX;
	int best_racy_candidate_cpuid = -1;
	while (sched_iterate_psets_ordered(idle_pset, &idle_pset->spill_search_order[PERMISSIVE_MIGRATION_BUCKET],
	    idle_pset->foreign_psets[0], &istate)) {
		processor_set_t candidate_pset = pset_for_id(istate.spis_pset_id);
		int local_candidate_cpuid = sched_edge_running_rebal_candidate_best_eligible_cpu(idle_pset, candidate_pset,
		    &global_racy_highest_qos, false);
		if (local_candidate_cpuid != -1) {
			assert3u(global_racy_highest_qos, <, TH_BUCKET_SCHED_MAX);
			best_racy_candidate_cpuid = local_candidate_cpuid;
		}
	}
	/*
	 * Now scan psets with the pset lock acquired. Hopefully we
	 * succeed to find an eligible candidate at the first one.
	 */
	processor_set_t start_candidate_pset = PROCESSOR_SET_NULL;
	if (best_racy_candidate_cpuid == -1) {
		/*
		 * In the racy search, no eligible CPUs were found.
		 * Rather than give up, continue to the locking search
		 * and follow the idle pset's default spill search order.
		 */
		start_candidate_pset = idle_pset;
	} else {
		start_candidate_pset = processor_array[best_racy_candidate_cpuid]->processor_set;
	}
	istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(start_candidate_pset, &start_candidate_pset->spill_search_order[PERMISSIVE_MIGRATION_BUCKET],
	    idle_pset->foreign_psets[0], &istate)) {
		processor_set_t candidate_pset = pset_for_id(istate.spis_pset_id);
		pset_lock(candidate_pset);
		/* Skip the pset if it's not schedulable */
		if (pset_is_recommended(candidate_pset) == false) {
			pset_unlock(candidate_pset);
			continue;
		}
		__kdebug_only sched_bucket_t target_qos = TH_BUCKET_SCHED_MAX;
		int best_candidate_cpuid = sched_edge_running_rebal_candidate_best_eligible_cpu(idle_pset, candidate_pset, &target_qos, true);
		if (best_candidate_cpuid != -1) {
			/* We found an eligible CPU! Prepare the IPI to send to it */
			processor_t target_cpu = processor_array[best_candidate_cpuid];
			sched_ipi_type_t ipi_type = sched_ipi_action(target_cpu, NULL, SCHED_IPI_EVENT_REBALANCE);
			assert3u(ipi_type, ==, SCHED_IPI_IMMEDIATE);
			pset_unlock(candidate_pset);
			/* Finally send the IPI */
			processor_t ast_processor = processor_array[best_candidate_cpuid];
			sched_ipi_perform(ast_processor, ipi_type);
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_REBAL_RUNNING) | DBG_FUNC_NONE,
			    start_candidate_pset->pset_id, idle_processor->cpu_id, best_candidate_cpuid, target_qos);
			/* Core should light-weight idle using WFE since it sent out a rebalance IPI */
			return true;
		}
		/*
		 * No eligible CPUs in this pset.
		 * Note, continuing beyond the start_candidate_pset for a valid best_racy_candidate_cpuid
		 * is a fall-back case where we failed to find an eligible CPU after taking the pset_lock,
		 * despite expecting one based on our lock-free check. So we only iterate additional pset
		 * locks in that case, or if no eligible CPUs anywhere were identified in the lock-free check.
		 */
		pset_unlock(candidate_pset);
	}
	return false;
}

/*
 * sched_edge_migration_check()
 *
 * Routine to evaluate an edge between two psets to decide if migration is
 * possible across that edge. Also updates the selected_pset and max_edge_delta
 * out parameters accordingly. The return value indicates if the invoking
 * routine should short circuit the search, since an ideal candidate has been
 * found. The routine looks at the regular edges and pset load metrics or the
 * shared resource load metrics based on the type of thread.
 */
static bool
sched_edge_migration_check(pset_id_t pset_id, processor_set_t preferred_pset,
    uint32_t preferred_pset_load, thread_t thread, processor_set_t *selected_pset, uint32_t *max_edge_delta)
{
	pset_id_t preferred_pset_id = preferred_pset->pset_id;
	pset_type_t preferred_pset_type = pset_type_for_id(preferred_pset_id);
	processor_set_t dst_pset = pset_array[pset_id];
	cluster_shared_rsrc_type_t shared_rsrc_type = sched_edge_thread_shared_rsrc_type(thread);
	bool shared_rsrc_thread = (shared_rsrc_type != CLUSTER_SHARED_RSRC_TYPE_NONE);

	if (pset_id == preferred_pset_id) {
		return false;
	}

	if (dst_pset == NULL) {
		return false;
	}

	sched_clutch_edge edge = sched_edge_config_get(preferred_pset_id, pset_id, thread->th_sched_bucket);
	if (edge.sce_migration_allowed == false) {
		return false;
	}
	uint32_t dst_load = shared_rsrc_thread ? (uint32_t)sched_edge_pset_cluster_shared_rsrc_load(dst_pset, shared_rsrc_type) : sched_edge_pset_load_metric(dst_pset, thread->th_sched_bucket);
	if (dst_load == 0
#if CONFIG_SCHED_PERF_ISLANDS
	    /* Still enforce edge weights across performance islands */
	    && (sched_edge_crosses_perf_islands(preferred_pset, dst_pset, edge) == false)
#endif /* CONFIG_SCHED_PERF_ISLANDS */
	    ) {
		/* The candidate pset is idle; select it immediately for execution */
		*selected_pset = dst_pset;
		*max_edge_delta = preferred_pset_load;
		return true;
	}

	uint32_t edge_delta = 0;
	if (dst_load > preferred_pset_load) {
		return false;
	}
	edge_delta = preferred_pset_load - dst_load;
	if (!shared_rsrc_thread && (edge_delta < edge.sce_migration_weight)) {
		/*
		 * For non shared resource threads, use the edge migration weight to decide if
		 * this pset is over-committed at the QoS level of this thread.
		 */
		return false;
	}

	if (edge_delta < *max_edge_delta) {
		return false;
	}
	if (edge_delta == *max_edge_delta) {
		/* If the edge delta is the same as the max delta, make sure a homogeneous pset is picked */
		boolean_t selected_homogeneous = ((*selected_pset)->pset_type == preferred_pset_type);
		boolean_t candidate_homogeneous = (dst_pset->pset_type == preferred_pset_type);
		if (selected_homogeneous || !candidate_homogeneous) {
			return false;
		}
	}
	/* dst_pset seems to be the best candidate for migration; however other candidates should still be evaluated */
	*max_edge_delta = edge_delta;
	*selected_pset = dst_pset;
	return false;
}

/*
 * sched_edge_migrate_edges_evaluate()
 *
 * Routine to find the candidate for thread migration based on edge weights.
 *
 * Returns the most ideal pset for execution of this thread based on outgoing edges of the preferred pset. Can
 * return preferred_pset if its the most ideal destination for this thread.
 */
static processor_set_t
sched_edge_migrate_edges_evaluate(processor_set_t preferred_pset, uint32_t preferred_pset_load, thread_t thread)
{
	processor_set_t selected_pset = preferred_pset;
	uint32_t max_edge_delta = 0;
	bool search_complete = false;
	cluster_shared_rsrc_type_t shared_rsrc_type = sched_edge_thread_shared_rsrc_type(thread);
	bool shared_rsrc_thread = (shared_rsrc_type != CLUSTER_SHARED_RSRC_TYPE_NONE);

	bitmap_t *foreign_pset_bitmap = preferred_pset->foreign_psets;
	bitmap_t *native_pset_bitmap = preferred_pset->native_psets;
	/* Always start the search with the native psets */
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(preferred_pset, &preferred_pset->spill_search_order[thread->th_sched_bucket], native_pset_bitmap[0], &istate)) {
		search_complete = sched_edge_migration_check(istate.spis_pset_id, preferred_pset, preferred_pset_load, thread, &selected_pset, &max_edge_delta);
		if (search_complete) {
			break;
		}
	}

	if (search_complete) {
		return selected_pset;
	}

	if (shared_rsrc_thread && (edge_shared_rsrc_policy[shared_rsrc_type] == EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST)) {
		/*
		 * If the shared resource scheduling policy is EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST, the scheduler tries
		 * to fill up the preferred pset and its homogeneous peers first.
		 */

		if (max_edge_delta > 0) {
			/*
			 * This represents that there is a peer pset of the same type as the preferred pset (since the code
			 * above only looks at the native_psets) which has lesser threads as compared to the preferred pset of
			 * the shared resource type. This indicates that there is capacity on a native pset where this thread
			 * should be placed.
			 */
			return selected_pset;
		}
		/*
		 * Indicates that all peer native psets are at the same shared resource usage; check if the preferred pset has
		 * any more capacity left.
		 */
		if (sched_edge_pset_cluster_shared_rsrc_load(preferred_pset, shared_rsrc_type) < pset_available_cpu_count(preferred_pset)) {
			return preferred_pset;
		}
		/*
		 * Looks like the preferred pset and all its native peers are full with shared resource threads; need to start looking
		 * at non-native psets for capacity.
		 */
	}

	/* Now look at the non-native clusters */
	istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(preferred_pset, &preferred_pset->spill_search_order[thread->th_sched_bucket], foreign_pset_bitmap[0], &istate)) {
		search_complete = sched_edge_migration_check(istate.spis_pset_id, preferred_pset, preferred_pset_load, thread, &selected_pset, &max_edge_delta);
		if (search_complete) {
			break;
		}
	}
	return selected_pset;
}

/*
 * sched_edge_candidate_alternative()
 *
 * Routine to find an alternative pset from candidate_pset_bitmap since the
 * selected_pset is not available for execution. The logic tries to prefer homogeneous
 * psets over heterogeneous psets since this is typically used in thread
 * placement decisions.
 */
_Static_assert(MAX_PSETS <= 64, "Unable to fit maximum number of psets in uint64_t bitmask");
static processor_set_t
sched_edge_candidate_alternative(processor_set_t selected_pset, uint64_t candidate_pset_bitmap)
{
	/*
	 * It looks like the most ideal pset is not available for scheduling currently.
	 * Try to find a homogeneous pset that is still available.
	 */
	uint64_t available_native_psets = selected_pset->native_psets[0] & candidate_pset_bitmap;
	int available_pset_id = lsb_first(available_native_psets);
	if (available_pset_id == -1) {
		/* Looks like none of the homogeneous psets are available; pick the first available pset */
		available_pset_id = bit_first(candidate_pset_bitmap);
	}
	assert(available_pset_id != -1);
	return pset_array[available_pset_id];
}

/*
 * sched_edge_switch_pset_lock()
 *
 * Helper routine for sched_edge_migrate_candidate() which switches pset locks (if needed) based on
 * switch_pset_locks.
 * Returns the newly locked pset after the switch.
 */
static processor_set_t
sched_edge_switch_pset_lock(processor_set_t selected_pset, processor_set_t locked_pset, bool switch_pset_locks)
{
	if (!switch_pset_locks) {
		return locked_pset;
	}
	if (selected_pset != locked_pset) {
		pset_unlock(locked_pset);
		pset_lock(selected_pset);
		return selected_pset;
	} else {
		return locked_pset;
	}
}

/*
 * sched_edge_migrate_candidate()
 *
 * Routine to find an appropriate pset for scheduling a thread. The routine looks at the properties of
 * the thread and the preferred pset to determine the best available pset for scheduling.
 *
 * The switch_pset_locks parameter defines whether the routine should switch pset locks to provide an
 * accurate scheduling decision. This mode is typically used when choosing a pset for scheduling a thread since the
 * decision has to be synchronized with another CPU changing the recommendation of psets available
 * on the system. If this parameter is set to false, this routine returns the best effort indication of
 * the pset the thread should be scheduled on. It is typically used in fast path contexts (such as
 * SCHED(thread_avoid_processor) to determine if there is a possibility of scheduling this thread on a
 * more appropriate pset.
 *
 * Routine returns the most ideal pset for scheduling. If switch_pset_locks is set, it ensures that the
 * resultant pset lock is held.
 */
static processor_set_t
sched_edge_migrate_candidate(processor_set_t _Nullable preferred_pset, thread_t thread,
    processor_set_t locked_pset, bool switch_pset_locks, processor_t *processor_hint_out,
    sched_options_t *options_inout)
{
	processor_set_t selected_pset = preferred_pset;
	cluster_shared_rsrc_type_t shared_rsrc_type = sched_edge_thread_shared_rsrc_type(thread);
	bool shared_rsrc_thread = (shared_rsrc_type != CLUSTER_SHARED_RSRC_TYPE_NONE);
	bool stirring_the_pot = false;

	if (SCHED_CLUTCH_THREAD_PSET_BOUND(thread)) {
		/*
		 * For pset-bound threads, choose the pset to which the thread is bound,
		 * unless that pset is unavailable. If it's not available, fall through
		 * to the regular pset selection logic which handles derecommended psets
		 * appropriately.
		 */
		selected_pset = pset_array[sched_edge_thread_bound_pset_id(thread)];
		if (selected_pset != NULL) {
			locked_pset = sched_edge_switch_pset_lock(selected_pset, locked_pset, switch_pset_locks);
			if (pset_is_recommended(selected_pset)) {
				return selected_pset;
			}
		}
	}

	uint64_t candidate_pset_bitmap = bits_mask(sched_num_psets);
#if DEVELOPMENT || DEBUG
	extern int enable_task_set_cluster_type;
	task_t task = get_threadtask(thread);
	if (enable_task_set_cluster_type && (task->t_flags & TF_USE_PSET_HINT_CLUSTER_TYPE)) {
		processor_set_t pset_hint = task->pset_hint;
		if (pset_hint && (selected_pset == NULL || selected_pset->pset_type != pset_hint->pset_type)) {
			selected_pset = pset_hint;
			goto migrate_candidate_available_check;
		}
	}
#endif

	if (preferred_pset == NULL) {
		/* The preferred_pset has not finished initializing at boot */
		goto migrate_candidate_available_check;
	}

	if (thread->sched_pri >= BASEPRI_RTQUEUES) {
		/* For realtime threads, try and schedule them on the preferred pset always */
		goto migrate_candidate_available_check;
	}

	uint32_t preferred_pset_load = shared_rsrc_thread ? (uint32_t)sched_edge_pset_cluster_shared_rsrc_load(preferred_pset, shared_rsrc_type) : sched_edge_pset_load_metric(preferred_pset, thread->th_sched_bucket);
	if (preferred_pset_load == 0) {
		goto migrate_candidate_available_check;
	}

	if (*options_inout & SCHED_CSW) {
		/*
		 * If this thread has expired quantum on a non-preferred core and is waiting on
		 * "stir-the-pot" to get a turn running on a P-core, check our processor inbox for
		 * stir-the-pot to see if an eligible P-core has already been found for swap.
		 * If so, try to migrate to the corresponding pset and also carry over the
		 * processor hint to preempt that specific P-core.
		 *
		 * The AMP rebalancing mechanism is available for regular threads or shared resource
		 * threads with the EDGE_SHARED_RSRC_SCHED_POLICY_NATIVE_FIRST policy.
		 */
		int stir_the_pot_swap_cpu = sched_edge_stir_the_pot_check_inbox_for_thread(thread, true);
		if (stir_the_pot_swap_cpu != -1) {
			*processor_hint_out = processor_array[stir_the_pot_swap_cpu];
			selected_pset = processor_array[stir_the_pot_swap_cpu]->processor_set;
			stirring_the_pot = true;
			KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_STIR_THE_POT) | DBG_FUNC_NONE,
			    2, stir_the_pot_swap_cpu, 0, 0);
			goto migrate_candidate_available_check;
		}
	}

	/* Look at edge weights to decide the most ideal migration candidate for this thread */
	selected_pset = sched_edge_migrate_edges_evaluate(preferred_pset, preferred_pset_load, thread);

migrate_candidate_available_check:
	if (selected_pset == NULL) {
		/* The selected_pset has not finished initializing at boot */
		pset_unlock(locked_pset);
		return NULL;
	}

	locked_pset = sched_edge_switch_pset_lock(selected_pset, locked_pset, switch_pset_locks);
	if (pset_is_recommended(selected_pset) == true) {
		/* Committing to the pset */
		if (stirring_the_pot) {
			*options_inout |= SCHED_STIR_POT;
		}
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_CLUSTER_OVERLOAD) | DBG_FUNC_NONE, thread_tid(thread), preferred_pset->pset_id, selected_pset->pset_id, preferred_pset_load);
		return selected_pset;
	}
	stirring_the_pot = false;
	/* Looks like selected_pset is not available for scheduling; remove it from candidate_pset_bitmap */
	bitmap_clear(&candidate_pset_bitmap, selected_pset->pset_id);
	if (__improbable(bitmap_first(&candidate_pset_bitmap, sched_num_psets) == -1)) {
		pset_unlock(locked_pset);
		return NULL;
	}
	/* Try and find an alternative for the selected pset */
	selected_pset = sched_edge_candidate_alternative(selected_pset, candidate_pset_bitmap);
	goto migrate_candidate_available_check;
}

static processor_t
sched_edge_choose_processor(processor_set_t pset, processor_t processor, thread_t thread, sched_options_t *options_inout)
{
	/* Bound threads don't call this function */
	assert(thread->bound_processor == PROCESSOR_NULL);
	processor_t chosen_processor = PROCESSOR_NULL;

	/*
	 * sched_edge_preferred_pset() returns the preferred pset for a given thread.
	 * It should take the passed in "pset" as a hint which represents the recency metric for
	 * pset selection logic.
	 */
	processor_set_t preferred_pset = pset_array[sched_edge_thread_preferred_pset(thread)];
	processor_set_t chosen_pset = preferred_pset;
	/*
	 * If the preferred pset is overloaded, find a pset which is the best candidate to migrate
	 * threads to. sched_edge_migrate_candidate() returns the preferred pset
	 * if it has capacity; otherwise finds the best candidate pset to migrate this thread to.
	 *
	 * Edge Scheduler Optimization
	 * It might be useful to build a recency metric for the thread for multiple psets and
	 * factor that into the migration decisions.
	 */
	chosen_pset = sched_edge_migrate_candidate(preferred_pset, thread, pset, true, &processor, options_inout);
	if (chosen_pset) {
		chosen_processor = choose_processor(chosen_pset, processor, thread, options_inout);
	}
	return chosen_processor;
}

/*
 * sched_edge_clutch_bucket_threads_drain()
 *
 * Drains all the runnable threads which are not restricted to the root_clutch (due to clutch
 * bucket overrides etc.) into a local thread queue.
 */
static void
sched_edge_clutch_bucket_threads_drain(sched_clutch_bucket_t clutch_bucket, sched_clutch_root_t root_clutch, struct pulled_thread_queue * threadq)
{
	thread_t thread = THREAD_NULL;
	uint64_t current_timestamp = mach_approximate_time();
	qe_foreach_element_safe(thread, &clutch_bucket->scb_thread_timeshare_queue, th_clutch_timeshare_link) {
		sched_clutch_thread_remove(root_clutch, thread, current_timestamp, SCHED_CLUTCH_BUCKET_OPTIONS_NONE);
		pulled_thread_queue_enqueue(threadq, thread);
	}
}

/*
 * sched_edge_update_preferred_pset()
 *
 * Routine to update the preferred pset for QoS buckets within a thread group.
 * The buckets to be updated are specifed as a bitmap (clutch_bucket_modify_bitmap).
 */
static void
sched_edge_update_preferred_pset(
	sched_clutch_t sched_clutch,
	bitmap_t  *clutch_bucket_modify_bitmap,
	pset_id_t *tg_bucket_preferred_pset)
{
	for (int bucket = bitmap_first(clutch_bucket_modify_bitmap, TH_BUCKET_SCHED_MAX); bucket >= 0; bucket = bitmap_next(clutch_bucket_modify_bitmap, bucket)) {
		os_atomic_store(&sched_clutch->sc_clutch_groups[bucket].scbg_preferred_pset, tg_bucket_preferred_pset[bucket], relaxed);
	}
}

#if !SCHED_TEST_HARNESS

/*
 * sched_edge_migrate_thread_group_runnable_threads()
 *
 * Routine to implement the migration of threads on a pset when the thread group
 * recommendation is updated. The migration works using a 2-phase
 * algorithm.
 *
 * Phase 1: With the pset lock held, check the recommendation of the clutch buckets.
 * For each clutch bucket, if it needs to be migrated immediately, drain the threads
 * into a local thread queue. Otherwise mark the clutch bucket as native/foreign as
 * appropriate.
 *
 * Phase 2: After unlocking the pset, drain all the threads from the local thread
 * queue and mark them runnable which should land them in the right hierarchy.
 *
 * The routine assumes that the preferences for the clutch buckets/clutch bucket
 * groups have already been updated by the caller.
 *
 * - Called with the pset locked and interrupts disabled.
 * - Returns with the pset unlocked.
 */
static void
sched_edge_migrate_thread_group_runnable_threads(
	sched_clutch_t sched_clutch,
	sched_clutch_root_t root_clutch,
	bitmap_t *clutch_bucket_modify_bitmap,
	__unused pset_id_t *tg_bucket_preferred_pset,
	bool migrate_immediately, struct pulled_thread_queue * threadq)
{
	sched_clutch_hierarchy_locked_assert(root_clutch);

	for (int bucket = bitmap_first(clutch_bucket_modify_bitmap, TH_BUCKET_SCHED_MAX); bucket >= 0; bucket = bitmap_next(clutch_bucket_modify_bitmap, bucket)) {
		/* Get the clutch bucket for this pset and sched bucket */
		sched_clutch_bucket_group_t clutch_bucket_group = &(sched_clutch->sc_clutch_groups[bucket]);
		sched_clutch_bucket_t clutch_bucket = &(clutch_bucket_group->scbg_clutch_buckets[root_clutch->scr_pset_id]);
		if (clutch_bucket->scb_root == NULL) {
			/* Clutch bucket not runnable or already in the right hierarchy; nothing to do here */
			assert3u(clutch_bucket->scb_thr_count, ==, 0);
			continue;
		}
		assert3p(clutch_bucket->scb_root, ==, root_clutch);
		pset_id_t clutch_bucket_preferred_pset = sched_clutch_bucket_preferred_pset(clutch_bucket);

		sched_edge_steal_silo_clutch_bucket_classify(clutch_bucket, root_clutch, clutch_bucket_preferred_pset);

		if (migrate_immediately && (root_clutch->scr_pset_id != clutch_bucket_preferred_pset)) {
			/*
			 * For transitions where threads need to be migrated immediately, drain the threads into a
			 * local queue unless we are looking at the clutch buckets for the newly recommended
			 * pset.
			 */
			sched_edge_clutch_bucket_threads_drain(clutch_bucket, clutch_bucket->scb_root, threadq);
		}
	}

	pset_unlock(root_clutch->scr_pset);
}

/*
 * sched_edge_migrate_thread_group_running_threads()
 *
 * Routine to find all running threads of a thread group on a specific pset
 * and IPI them if they need to be moved immediately.
 */
static void
sched_edge_migrate_thread_group_running_threads(
	sched_clutch_t sched_clutch,
	sched_clutch_root_t root_clutch,
	__unused bitmap_t *clutch_bucket_modify_bitmap,
	pset_id_t *tg_bucket_preferred_pset,
	bool migrate_immediately)
{
	if (migrate_immediately == false) {
		/* If CLPC has recommended not to move threads immediately, nothing to do here */
		return;
	}

	/*
	 * Edge Scheduler Optimization
	 *
	 * When the system has a large number of psets and cores, it might be useful to
	 * narrow down the iteration by using a thread running bitmap per clutch.
	 */
	uint64_t ast_processor_map = 0;
	sched_ipi_type_t ipi_type[MAX_CPUS] = {SCHED_IPI_NONE};

	uint64_t running_map = root_clutch->scr_pset->cpu_state_map[PROCESSOR_RUNNING];
	/*
	 * Iterate all CPUs and look for the ones running threads from this thread group and are
	 * not restricted to the specific pset (due to overrides etc.)
	 */
	for (int cpuid = lsb_first(running_map); cpuid >= 0; cpuid = lsb_next(running_map, cpuid)) {
		processor_t src_processor = processor_array[cpuid];
		boolean_t expected_tg = (src_processor->current_thread_group == sched_clutch->sc_tg);
		sched_bucket_t processor_sched_bucket = os_atomic_load(&src_processor->processor_set->cpu_running_buckets[cpuid], relaxed);
		if (processor_sched_bucket == TH_BUCKET_SCHED_MAX) {
			continue;
		}
		boolean_t non_preferred_pset = tg_bucket_preferred_pset[processor_sched_bucket] != root_clutch->scr_pset_id;

		if (expected_tg && non_preferred_pset) {
			ipi_type[cpuid] = sched_ipi_action(src_processor, NULL, SCHED_IPI_EVENT_REBALANCE);
			if (ipi_type[cpuid] != SCHED_IPI_NONE) {
				bit_set(ast_processor_map, cpuid);
			} else if (src_processor == current_processor()) {
				atomic_bit_set(&root_clutch->scr_pset->pending_AST_PREEMPT_cpu_mask, cpuid, memory_order_relaxed);
				ast_t new_preempt = update_pending_nonurgent_preemption(src_processor, AST_PREEMPT);
				ast_on(new_preempt);
			}
		}
	}

	/* Perform all the IPIs */
	if (bit_first(ast_processor_map) != -1) {
		for (int cpuid = lsb_first(ast_processor_map); cpuid >= 0; cpuid = lsb_next(ast_processor_map, cpuid)) {
			processor_t ast_processor = processor_array[cpuid];
			sched_ipi_perform(ast_processor, ipi_type[cpuid]);
		}
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_AMP_RECOMMENDATION_CHANGE) | DBG_FUNC_NONE, thread_group_get_id(sched_clutch->sc_tg), ast_processor_map, 0, 0);
	}
}

/*
 * sched_edge_tg_preferred_pset_change()
 *
 * Routine to handle changes to a thread group's recommendation. In the Edge
 * Scheduler, the preferred pset is specified on a per-QoS basis within a
 * thread group. The routine updates the preferences and performs thread
 * migrations based on the policy specified by CLPC.
 *
 * tg_bucket_preferred_pset is an array of size TH_BUCKET_SCHED_MAX which
 * specifies the new preferred pset for each QoS within the thread group.
 */
void
sched_edge_tg_preferred_pset_change(struct thread_group *tg, pset_id_t tg_bucket_preferred_pset[TH_BUCKET_SCHED_MAX], sched_perfcontrol_preferred_pset_options_t options)
{
	sched_clutch_t clutch = sched_clutch_for_thread_group(tg);
	/*
	 * In order to optimize the processing, create a bitmap which represents all QoS buckets
	 * for which the preferred pset has changed.
	 */
	bitmap_t clutch_bucket_modify_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)] = {0};
	for (sched_bucket_t bucket = TH_BUCKET_FIXPRI; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		pset_id_t old_preferred_pset = sched_edge_clutch_bucket_group_preferred_pset(&clutch->sc_clutch_groups[bucket]);
		pset_id_t new_preferred_pset = tg_bucket_preferred_pset[bucket];
		if (old_preferred_pset != new_preferred_pset) {
			bitmap_set(clutch_bucket_modify_bitmap, bucket);
		}
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_PREFERRED_PSET) | DBG_FUNC_NONE,
		    thread_group_get_id(tg), bucket, new_preferred_pset, options);
	}
	if (bitmap_lsb_first(clutch_bucket_modify_bitmap, TH_BUCKET_SCHED_MAX) == -1) {
		/* No changes in any clutch buckets; nothing to do here */
		return;
	}

	/*
	 * The first operation is to update the preferred pset for all QoS buckets within the
	 * thread group so that any future threads becoming runnable would see the new preferred
	 * pset value.
	 */
	sched_edge_update_preferred_pset(clutch, clutch_bucket_modify_bitmap, tg_bucket_preferred_pset);

	for (pset_id_t pset_id = 0; pset_id < sched_num_psets; pset_id++) {
		processor_set_t pset = pset_for_id(pset_id);
		struct pulled_thread_queue *threadq = pulled_thread_queue_prepare();

		spl_t s = splsched();
		pset_lock(pset);
		/*
		 * Currently iterates all psets looking for running threads for a TG to be migrated. Can be optimized
		 * by keeping a per-clutch bitmap of psets running threads for a particular TG.
		 *
		 * Edge Scheduler Optimization
		 */
		/* Migrate all running threads of the TG on this pset based on options specified by CLPC */
		sched_edge_migrate_thread_group_running_threads(clutch, &pset->pset_clutch_root, clutch_bucket_modify_bitmap,
		    tg_bucket_preferred_pset, (options & SCHED_PERFCONTROL_PREFERRED_PSET_MIGRATE_RUNNING));
		/* Migrate all runnable threads of the TG in this pset's hierarchy based on options specified by CLPC */
		sched_edge_migrate_thread_group_runnable_threads(clutch, &pset->pset_clutch_root, clutch_bucket_modify_bitmap,
		    tg_bucket_preferred_pset, (options & SCHED_PERFCONTROL_PREFERRED_PSET_MIGRATE_RUNNABLE), threadq);
		/* sched_edge_migrate_thread_group_runnable_threads() returns with pset unlocked */
		splx(s);

		pulled_thread_queue_flush(threadq);
	}
}

/*
 * sched_edge_pset_made_schedulable()
 *
 * Pset may already be marked schedulable. Called at least once when new
 * processor(s) are made available.
 *
 * Invoked with the pset lock held and interrupts disabled.
 */
static void
sched_edge_pset_made_schedulable(
	processor_set_t pset)
{
	/* Mark the pset as schedulable. The bit may already be set if the pset was already schedulable. */
	atomic_bit_set(sched_edge_available_pset_bitmask, pset->pset_id, memory_order_relaxed);
}
#endif /* !SCHED_TEST_HARNESS */


/*
 * sched_edge_cpu_init_completed()
 *
 * Callback routine from the platform layer once all CPUs/psets have been initialized. This
 * provides an opportunity for the edge scheduler to initialize all the edge parameters.
 */
static void
sched_edge_cpu_init_completed(void)
{
	/* Now that all cores have registered, compute bitmaps for different core types */
	for (int pset_id = 0; pset_id < sched_num_psets; pset_id++) {
		processor_set_t pset = pset_for_id(pset_id);
		if (sched_edge_stir_the_pot_core_type_is_desired(pset)) {
			os_atomic_or(&sched_edge_p_core_map, pset->cpu_bitmask, relaxed);
		} else {
			os_atomic_or(&sched_edge_non_p_core_map, pset->cpu_bitmask, relaxed);
		}
	}
	/* Build policy table for setting edge weight tunables based on pset types */
	sched_clutch_edge edge_config_defaults[MAX_PSET_TYPES][MAX_PSET_TYPES];
	sched_clutch_edge free_spill = (sched_clutch_edge){.sce_migration_weight = 0, .sce_migration_allowed = 1, .sce_steal_allowed = 1};
	sched_clutch_edge no_spill = (sched_clutch_edge){.sce_migration_weight = 0, .sce_migration_allowed = 0, .sce_steal_allowed = 0};
	sched_clutch_edge weighted_spill = (sched_clutch_edge){.sce_migration_weight = 64, .sce_migration_allowed = 1, .sce_steal_allowed = 1};
	/* P -> P */
	edge_config_defaults[PSET_AMP_P][PSET_AMP_P] = free_spill;
	/* E -> E */
	edge_config_defaults[PSET_AMP_E][PSET_AMP_E] = free_spill;
	/* P -> E */
	edge_config_defaults[PSET_AMP_P][PSET_AMP_E] = weighted_spill;
	/* E -> P */
	edge_config_defaults[PSET_AMP_E][PSET_AMP_P] = no_spill;
#if HAS_MCORE
	/* M -> M */
	edge_config_defaults[PSET_AMP_M][PSET_AMP_M] = free_spill;
	/* P -> M */
	edge_config_defaults[PSET_AMP_P][PSET_AMP_M] = weighted_spill;
	/* M -> E */
	edge_config_defaults[PSET_AMP_M][PSET_AMP_E] = weighted_spill;
	/* E -> M */
	edge_config_defaults[PSET_AMP_E][PSET_AMP_M] = no_spill;
	/* M -> P */
	edge_config_defaults[PSET_AMP_M][PSET_AMP_P] = no_spill;
#endif /* HAS_MCORE */

	spl_t s = splsched();
	for (pset_id_t src_pset_id = 0; src_pset_id < sched_num_psets; src_pset_id++) {
		processor_set_t src_pset = pset_for_id(src_pset_id);
		pset_lock(src_pset);

		/* Each pset recommendation is at least allowed to access its own cluster */
		for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
			src_pset->max_parallel_cores[bucket] = src_pset->cpu_set_count;
			src_pset->max_parallel_clusters[bucket] = 1;
		}

		/* For each pset, set all its outgoing edge parameters */
		for (pset_id_t dst_pset_id = 0; dst_pset_id < sched_num_psets; dst_pset_id++) {
			if (dst_pset_id == src_pset_id) {
				continue;
			}
			processor_set_t dst_pset = pset_for_id(dst_pset_id);
			bool psets_homogeneous = (src_pset->pset_type == dst_pset->pset_type);
			if (psets_homogeneous) {
				bitmap_clear(src_pset->foreign_psets, dst_pset_id);
				bitmap_set(src_pset->native_psets, dst_pset_id);
				/* Default realtime policy: spill allowed among homogeneous psets. */
				sched_rt_config_set(src_pset_id, dst_pset_id, (sched_clutch_edge) {
					.sce_migration_allowed = true,
					.sce_steal_allowed = true,
					.sce_migration_weight = 0,
				});
			} else {
				bitmap_set(src_pset->foreign_psets, dst_pset_id);
				bitmap_clear(src_pset->native_psets, dst_pset_id);
				/* Default realtime policy: disallow spill among heterogeneous psets. */
				sched_rt_config_set(src_pset_id, dst_pset_id, (sched_clutch_edge) {
					.sce_migration_allowed = false,
					.sce_steal_allowed = false,
					.sce_migration_weight = 0,
				});
			}

			bool psets_local = (ml_get_die_id(src_pset->cluster_id) == ml_get_die_id(dst_pset->cluster_id));
			if (psets_local) {
				bitmap_set(src_pset->local_psets, dst_pset_id);
				bitmap_clear(src_pset->remote_psets, dst_pset_id);
			} else {
				bitmap_set(src_pset->remote_psets, dst_pset_id);
				bitmap_clear(src_pset->local_psets, dst_pset_id);
			}

			for (sched_bucket_t bucket = 0; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
				/* Set tunables for an edge based on the pset types at either ends of it */
				sched_clutch_edge edge_config = edge_config_defaults[src_pset->pset_type][dst_pset->pset_type];
#if HAS_MCORE && CONFIG_SCHED_PERF_ISLANDS
				if ((src_pset->pset_type == PSET_AMP_M) && (dst_pset->pset_type == PSET_AMP_M)) {
					if (bucket == TH_BUCKET_SHARE_BG) {
						/* BG threads isolated to their preferred island by default */
						edge_config = no_spill;
					} else {
						/* Introduce non-zero edge weight between M-islands for some QoSes */
						edge_config.sce_migration_weight = sched_edge_qos_friction_weight_us[bucket];
					}
				} else if ((src_pset->pset_type == PSET_AMP_P) && (dst_pset->pset_type == PSET_AMP_M)) {
					/* Default ordering of M-islands prefers spilling down to higher id psets first */
					assert3u(edge_config.sce_migration_weight, >=, dst_pset->pset_id);
					edge_config.sce_migration_weight -= dst_pset->pset_id;
				}
#elif CONFIG_SCHED_PERF_ISLANDS
				/*
				 * Use the same edge setting across all QoS-levels. CLPC can override specific
				 * values when deciding to enforce performance islands for certain buckets.
				 */
#endif /* CONFIG_SCHED_PERF_ISLANDS */
				sched_edge_config_set(src_pset_id, dst_pset_id, bucket, edge_config);
				if (edge_config.sce_migration_allowed) {
					src_pset->max_parallel_cores[bucket] += dst_pset->cpu_set_count;
					if (pset_is_primary(dst_pset_id)) {
						src_pset->max_parallel_clusters[bucket] += 1;
					}
				}
			}
		}
		sched_edge_config_pset_push(src_pset_id);

		pset_unlock(src_pset);
	}
	sched_edge_config_final_push();
#if DEVELOPMENT || DEBUG
	assert(sched_edge_config_verify());
#endif /* DEVELOPMENT || DEBUG */
	splx(s);
}

static bool
sched_edge_thread_eligible_for_pset(thread_t thread, processor_set_t pset)
{
	pset_id_t preferred_pset_id = sched_edge_thread_preferred_pset(thread);
	if (preferred_pset_id == pset->pset_id) {
		return true;
	} else {
		sched_clutch_edge edge;
		if (thread->sched_pri >= BASEPRI_RTQUEUES) {
			edge = sched_rt_config_get(preferred_pset_id, pset->pset_id);
		} else {
			edge = sched_edge_config_get(preferred_pset_id, pset->pset_id, thread->th_sched_bucket);
		}
		return edge.sce_migration_allowed;
	}
}

extern int sched_amp_spill_deferred_ipi;
extern int sched_amp_pcores_preempt_immediate_ipi;

int sched_edge_migrate_ipi_immediate = 1;

sched_ipi_type_t
sched_edge_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event)
{
	processor_set_t pset = dst->processor_set;
	assert(dst != current_processor());

	boolean_t deferred_ipi_supported = false;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	deferred_ipi_supported = true;
#endif /* CONFIG_SCHED_DEFERRED_AST */

	switch (event) {
	case SCHED_IPI_EVENT_SPILL:
		/* For Spill event, use deferred IPIs if sched_amp_spill_deferred_ipi set */
		if (deferred_ipi_supported && sched_amp_spill_deferred_ipi) {
			return sched_ipi_deferred_policy(pset, dst, thread, event);
		}
		break;
	case SCHED_IPI_EVENT_PREEMPT:
		/* For preemption, the default policy is to use deferred IPIs
		 * for Non-RT P-core preemption. Override that behavior if
		 * sched_amp_pcores_preempt_immediate_ipi is set
		 */
		if (thread && thread->sched_pri < BASEPRI_RTQUEUES) {
			if (sched_amp_pcores_preempt_immediate_ipi && (pset->pset_type == PSET_AMP_P)) {
				return dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
			}
			if (sched_edge_migrate_ipi_immediate) {
				processor_set_t preferred_pset = pset_array[sched_edge_thread_preferred_pset(thread)];
				/*
				 * For IPI'ing CPUs that are homogeneous with the preferred pset, use immediate IPIs
				 * <rdar://153574674> reconsider this policy
				 */
				if (preferred_pset->pset_type == pset->pset_type) {
					return dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
				}
				/*
				 * For workloads that are going wide, it might be useful to use Immediate IPI to
				 * wakeup the idle CPU if the scheduler estimates that the preferred pset will
				 * be busy for the deferred IPI timeout. The Edge Scheduler uses the avg execution
				 * latency on the preferred pset as an estimate of busyness.
				 */
				uint64_t avg_execution_time_us =
				    os_atomic_load(&preferred_pset->pset_execution_time[thread->th_sched_bucket].pset_avg_thread_execution_time, relaxed);
				if ((avg_execution_time_us * NSEC_PER_USEC) >= ml_cpu_signal_deferred_get_timer()) {
					return dst_idle ? SCHED_IPI_IDLE : SCHED_IPI_IMMEDIATE;
				}
			}
		}
		break;
	default:
		break;
	}
	/* Default back to the global policy for all other scenarios */
	return sched_ipi_policy(dst, thread, dst_idle, event);
}

#if __AMP__

static uint32_t
pset_realtime_max_parallelism(processor_set_t pset, uint64_t options)
{
	bool shared_rsrc = options & QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE;
	uint32_t count = 0;
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(pset, &pset->sched_rt_spill_search_order, ~0, &istate)) {
		uint32_t cpu_count = bit_count(pset_array[istate.spis_pset_id]->cpu_bitmask);
		uint32_t cluster_count = pset_is_primary(pset->pset_id) ? 1 : 0;
		count += shared_rsrc ? cluster_count : cpu_count;
	}
	return count;
}

#endif /* __AMP__ */

/*
 * sched_edge_qos_max_parallelism()
 */
uint32_t
sched_edge_qos_max_parallelism(int qos, uint64_t options)
{
	pset_node_t low_node = pset_node_for_pset_type(PSET_AMP_E);
	pset_node_t high_node = pset_node_for_pset_type(PSET_AMP_P);
#if HAS_MCORE
	if (pset_node_is_empty(low_node)) {
		low_node = pset_node_for_pset_type(PSET_AMP_M);
	}
	if (pset_node_is_empty(high_node)) {
		high_node = pset_node_for_pset_type(PSET_AMP_M);
	}
#endif /* HAS_MCORE */
	if (pset_node_is_empty(low_node) || pset_node_is_empty(high_node)) {
		low_node = high_node = sched_boot_pset_node;
	}
	assert3p(low_node, !=, PSET_NODE_NULL);
	assert3p(high_node, !=, PSET_NODE_NULL);
	if (sched_is_standard_topology()) {
		assert3p(low_node, !=, high_node);
	}
	assert(!pset_node_is_empty(low_node));
	assert(!pset_node_is_empty(high_node));

#if __AMP__
	if (options & QOS_PARALLELISM_REALTIME) {
		/*
		 * Realtime threads on AMP are width-limited.
		 *
		 * Assume all psets of the same type have the same spill policy, and
		 * return the policy for an arbitrary high pset.
		 */
		int pset_id = bitmap_first(&high_node->pset_map, MAX_PSETS);
		assert3u(pset_id, >=, 0);
		return pset_realtime_max_parallelism(pset_for_id(pset_id), options);
	}
#endif /* __AMP__ */

	/*
	 * The Edge scheduler supports per-QoS recommendations for thread groups.
	 * This enables lower QoS buckets (such as UT) to be scheduled on all
	 * CPUs on the system.
	 *
	 * The only restriction is for BG/Maintenance QoS classes for which the
	 * performance controller would never recommend execution on the P-cores.
	 * If that policy changes in the future, this value should be changed.
	 */
	switch (qos) {
	case THREAD_QOS_BACKGROUND:
	case THREAD_QOS_MAINTENANCE:;
#if CONFIG_SCHED_PERF_ISLANDS
		/*
		 * With performance islands, BG threads are isolated to fewer psets
		 * than the full M- or E-width of the system (whichever core type is
		 * the lowest present).
		 *
		 * Iterate over all psets of the lowest core type and return the
		 * largest width found, were CLPC to assign that pset as the preferred
		 * island for some BG threads.
		 */
		uint32_t bg_cpu_count = 0;
		uint32_t bg_pset_count = 0;
		foreach_pset_id(src_pset_id, low_node) {
			processor_set_t src_pset = pset_for_id(src_pset_id);
			bg_cpu_count = MAX(bg_cpu_count, src_pset->max_parallel_cores[TH_BUCKET_SHARE_BG]);
			bg_pset_count = MAX(bg_pset_count, src_pset->max_parallel_clusters[TH_BUCKET_SHARE_BG]);
		}
		return (options & QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE) ? bg_pset_count : bg_cpu_count;
#else /* !CONFIG_SCHED_PERF_ISLANDS */
		uint32_t low_pset_count = bitmap_count(&low_node->pset_map, MAX_PSETS);
		uint32_t low_cpu_count = bitmap_count(&low_node->cpu_map, MAX_CPUS);
		return (options & QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE) ? low_pset_count : low_cpu_count;
#endif /* !CONFIG_SCHED_PERF_ISLANDS */
	default:;
		uint32_t total_cpus = ml_get_cpu_count();
		uint32_t total_clusters = ml_get_cluster_count();
		return (options & QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE) ? total_clusters : total_cpus;
	}
}


#endif /* CONFIG_SCHED_EDGE */

#endif /* CONFIG_SCHED_CLUTCH */
