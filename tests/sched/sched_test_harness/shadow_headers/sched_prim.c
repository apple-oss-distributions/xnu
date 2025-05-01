/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 *	File:	sched_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Scheduling primitives
 *
 */

/*
 * This version of osfmk/kern/sched_prim.c contains the limited subset of dependencies strictly
 * required by the Clutch runqueue test harness in tests/sched/sched_test_harness/sched_clutch_harness.c.
 * The dependencies have been copied here in order to isolate maintenance of the Clutch test
 * harness from the rest of xnu.
 */
#if !SCHED_TEST_HARNESS
#error File only for use with the Clutch runqueue test harness
#endif

#include <kern/sched_prim.h>
#include <kern/processor.h>

boolean_t
priority_is_urgent(int priority)
{
	if (priority <= BASEPRI_FOREGROUND) {
		return FALSE;
	}
	if (priority < MINPRI_KERNEL) {
		return TRUE;
	}
	if (priority >= BASEPRI_PREEMPT) {
		return TRUE;
	}
	return FALSE;
}

/*
 *	run_queue_init:
 *
 *	Initialize a run queue before first use.
 */
void
run_queue_init(
	run_queue_t             rq)
{
	rq->highq = NOPRI;
	for (u_int i = 0; i < BITMAP_LEN(NRQS); i++) {
		rq->bitmap[i] = 0;
	}
	rq->urgency = rq->count = 0;
	for (int i = 0; i < NRQS; i++) {
		circle_queue_init(&rq->queues[i]);
	}
}
/*
 *	run_queue_dequeue:
 *
 *	Perform a dequeue operation on a run queue,
 *	and return the resulting thread.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info), and not empty.
 */
thread_t
run_queue_dequeue(
	run_queue_t     rq,
	sched_options_t options)
{
	thread_t        thread;
	circle_queue_t  queue = &rq->queues[rq->highq];

	if (options & SCHED_HEADQ) {
		thread = cqe_dequeue_head(queue, struct thread, runq_links);
	} else {
		thread = cqe_dequeue_tail(queue, struct thread, runq_links);
	}

	assert(thread != THREAD_NULL);

	thread_clear_runq(thread);
	rq->count--;
	if (SCHED(priority_is_urgent)(rq->highq)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}
	if (circle_queue_empty(queue)) {
		bitmap_clear(rq->bitmap, rq->highq);
		rq->highq = bitmap_first(rq->bitmap, NRQS);
	}

	return thread;
}

/*
 *	run_queue_enqueue:
 *
 *	Perform a enqueue operation on a run queue.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info).
 */
boolean_t
run_queue_enqueue(
	run_queue_t      rq,
	thread_t         thread,
	sched_options_t  options)
{
	circle_queue_t  queue = &rq->queues[thread->sched_pri];
	boolean_t       result = FALSE;

	if (circle_queue_empty(queue)) {
		circle_enqueue_tail(queue, &thread->runq_links);

		rq_bitmap_set(rq->bitmap, thread->sched_pri);
		if (thread->sched_pri > rq->highq) {
			rq->highq = thread->sched_pri;
			result = TRUE;
		}
	} else {
		if (options & SCHED_TAILQ) {
			circle_enqueue_tail(queue, &thread->runq_links);
		} else {
			circle_enqueue_head(queue, &thread->runq_links);
		}
	}
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		rq->urgency++;
	}
	rq->count++;

	return result;
}

/*
 *	run_queue_remove:
 *
 *	Remove a specific thread from a runqueue.
 *
 *	The run queue must be locked.
 */
void
run_queue_remove(
	run_queue_t    rq,
	thread_t       thread)
{
	circle_queue_t  queue = &rq->queues[thread->sched_pri];

	thread_assert_runq_nonnull(thread);

	circle_dequeue(queue, &thread->runq_links);
	rq->count--;
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}

	if (circle_queue_empty(queue)) {
		/* update run queue status */
		bitmap_clear(rq->bitmap, thread->sched_pri);
		rq->highq = bitmap_first(rq->bitmap, NRQS);
	}

	thread_clear_runq(thread);
}

/*
 *      run_queue_peek
 *
 *      Peek at the runq and return the highest
 *      priority thread from the runq.
 *
 *	The run queue must be locked.
 */
thread_t
run_queue_peek(
	run_queue_t    rq)
{
	if (rq->count > 0) {
		circle_queue_t queue = &rq->queues[rq->highq];
		thread_t thread = cqe_queue_first(queue, struct thread, runq_links);
		return thread;
	} else {
		return THREAD_NULL;
	}
}

uint32_t       sched_run_buckets[TH_BUCKET_MAX];
unsigned                sched_tick = 0;
int8_t          sched_load_shifts[NRQS];

#define         DEFAULT_PREEMPTION_RATE         100             /* (1/s) */
int default_preemption_rate = DEFAULT_PREEMPTION_RATE;
#define         DEFAULT_BG_PREEMPTION_RATE      400             /* (1/s) */
static int default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;

uint32_t        std_quantum;
uint32_t        min_std_quantum;
static uint32_t        bg_quantum;

uint32_t        std_quantum_us;
static uint32_t        bg_quantum_us;

uint32_t default_timeshare_constraint;
uint32_t sched_fixed_shift;

void
sched_timeshare_init(void)
{
	/*
	 * Calculate the timeslicing quantum
	 * in us.
	 */
	if (default_preemption_rate < 1) {
		default_preemption_rate = DEFAULT_PREEMPTION_RATE;
	}
	std_quantum_us = (1000 * 1000) / default_preemption_rate;

	if (default_bg_preemption_rate < 1) {
		default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;
	}
	bg_quantum_us = (1000 * 1000) / default_bg_preemption_rate;
}

void
sched_timeshare_timebase_init(void)
{
	uint64_t        abstime;
	uint32_t        shift;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
		std_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	std_quantum = (uint32_t)abstime;

	/* smallest remaining quantum (250 us) */
	clock_interval_to_absolutetime_interval(250, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_std_quantum = (uint32_t)abstime;

	/* quantum for background tasks */
	clock_interval_to_absolutetime_interval(
		bg_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	bg_quantum = (uint32_t)abstime;

	/* scheduler tick interval */
	clock_interval_to_absolutetime_interval(USEC_PER_SEC >> SCHED_TICK_SHIFT,
	    NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);

	/*
	 * Compute conversion factor from usage to
	 * timesharing priorities with 5/8 ** n aging.
	 */
	abstime = (abstime * 5) / 3;
	for (shift = 0; abstime > BASEPRI_DEFAULT; ++shift) {
		abstime >>= 1;
	}
	sched_fixed_shift = shift;

	default_timeshare_constraint = std_quantum;
}

/* Returns the scheduling type for the pset */
cluster_type_t
pset_type_for_id(uint32_t cluster_id)
{
	return pset_array[cluster_id]->pset_type;
}

#if CONFIG_SCHED_EDGE

uint64_t
sched_pset_cluster_shared_rsrc_load(processor_set_t pset, cluster_shared_rsrc_type_t shared_rsrc_type)
{
	/* Prevent migrations to derecommended clusters */
	if (!pset_is_recommended(pset)) {
		return UINT64_MAX;
	}
	return os_atomic_load(&pset->pset_cluster_shared_rsrc_load[shared_rsrc_type], relaxed);
}

#endif /* CONFIG_SCHED_EDGE */

/* Mocked version */
processor_t
choose_processor(
	processor_set_t         starting_pset,
	processor_t             processor,
	thread_t                thread)
{
	(void)processor;
	if (thread->bound_processor != NULL) {
		return thread->bound_processor;
	}
	/* Choose the first-indexed processor in the pset */
	return processor_array[starting_pset->cpu_set_low];
}

static cpumap_t
pset_available_cpumap(processor_set_t pset)
{
	return pset->cpu_available_map & pset->recommended_bitmask;
}

int
pset_available_cpu_count(processor_set_t pset)
{
	return bit_count(pset_available_cpumap(pset));
}

bool
pset_is_recommended(processor_set_t pset)
{
	if (!pset) {
		return false;
	}
	return pset_available_cpu_count(pset) > 0;
}

bool
pset_type_is_recommended(processor_set_t pset)
{
	if (!pset) {
		return false;
	}
	pset_map_t recommended_psets = os_atomic_load(&pset->node->pset_recommended_map, relaxed);
	return bit_count(recommended_psets) > 0;
}

void
sched_update_pset_load_average(processor_set_t pset, uint64_t curtime)
{
	(void)pset;
	(void)curtime;
}

int
rt_runq_count(processor_set_t pset)
{
	(void)pset;
	return 0;
}
