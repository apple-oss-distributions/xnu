/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 *	File:	sched_prim.h
 *	Author:	David Golub
 *
 *	Scheduling primitive definitions file
 *
 */

/*
 * This version of osfmk/kern/sched_prim.h contains the limited subset of dependencies strictly
 * required by the Clutch runqueue test harness in tests/sched/sched_test_harness/sched_clutch_harness.c.
 * The dependencies have been copied here in order to isolate maintenance of the Clutch test
 * harness from the rest of xnu.
 */
#if !SCHED_TEST_HARNESS
#error File only for use with the Clutch runqueue test harness
#endif

#ifndef _KERN_SCHED_PRIM_H_
#define _KERN_SCHED_PRIM_H_

#include <mach/boolean.h>
#include <kern/circle_queue.h>
#include <kern/sched.h>

__options_decl(sched_options_t, uint32_t, {
	SCHED_NONE      = 0x0,
	SCHED_TAILQ     = 0x1,
	SCHED_HEADQ     = 0x2,
	SCHED_PREEMPT   = 0x4,
	SCHED_REBALANCE = 0x8,
});

#if CONFIG_SCHED_CLUTCH
extern const struct sched_dispatch_table sched_clutch_dispatch;
#define SCHED(f) (sched_clutch_dispatch.f)
#else
#error "Scheduler Test Harness only supports Clutch policy"
#endif

struct sched_dispatch_table {
	const char *sched_name;
	void    (*init)(void);                          /* Init global state */
	void    (*timebase_init)(void);         /* Timebase-dependent initialization */
	void    (*processor_init)(processor_t processor);       /* Per-processor scheduler init */
	void    (*pset_init)(processor_set_t pset);     /* Per-processor set scheduler init */

	/*
	 * Choose a thread of greater or equal priority from the per-processor
	 * runqueue for timeshare/fixed threads
	 */
	thread_t        (*choose_thread)(
		processor_t           processor,
		int                           priority,
		thread_t prev_thread,
		ast_t reason);

	/*
	 * Enqueue a timeshare or fixed priority thread onto the per-processor
	 * runqueue
	 */
	boolean_t (*processor_enqueue)(
		processor_t                    processor,
		thread_t                       thread,
		sched_options_t                options);

	/* Remove the specific thread from the per-processor runqueue */
	boolean_t       (*processor_queue_remove)(
		processor_t             processor,
		thread_t                thread);

	/*
	 * Does the per-processor runqueue have any timeshare or fixed priority
	 * threads on it? Called without pset lock held, so should
	 * not assume immutability while executing.
	 */
	boolean_t       (*processor_queue_empty)(processor_t            processor);

	/*
	 * Would this priority trigger an urgent preemption if it's sitting
	 * on the per-processor runqueue?
	 */
	boolean_t       (*priority_is_urgent)(int priority);

	/*
	 * Does the per-processor runqueue contain runnable threads that
	 * should cause the currently-running thread to be preempted?
	 */
	ast_t           (*processor_csw_check)(processor_t processor);

	/*
	 * Does the per-processor runqueue contain a runnable thread
	 * of > or >= priority, as a preflight for choose_thread() or other
	 * thread selection
	 */
	boolean_t       (*processor_queue_has_priority)(processor_t             processor,
	    int                             priority,
	    boolean_t               gte);

	/* Quantum size for the specified non-realtime thread. */
	uint32_t        (*initial_quantum_size)(thread_t thread);

	/* Scheduler mode for a new thread */
	sched_mode_t    (*initial_thread_sched_mode)(task_t parent_task);

	/*
	 * Runnable threads on per-processor runqueue. Should only
	 * be used for relative comparisons of load between processors.
	 */
	int                     (*processor_runq_count)(processor_t     processor);

	boolean_t       (*processor_bound_count)(processor_t processor);

	/* Supports more than one pset */
	boolean_t   multiple_psets_enabled;

	/* Supports avoid-processor */
	boolean_t   avoid_processor_enabled;

	/* Returns true if this processor should avoid running this thread. */
	bool    (*thread_avoid_processor)(processor_t processor, thread_t thread, ast_t reason);

	/* Routine to update scheduling bucket for a thread */
	void (*update_thread_bucket)(thread_t thread);

	/* Routine to inform the scheduler when all CPUs have finished initializing */
	void (*cpu_init_completed)(void);
	/* Routine to check if a thread is eligible to execute on a specific pset */
	bool (*thread_eligible_for_pset)(thread_t thread, processor_set_t pset);
};

#endif  /* _KERN_SCHED_PRIM_H_ */
