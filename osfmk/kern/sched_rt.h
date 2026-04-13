/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef _KERN_SCHED_RT_H_
#define _KERN_SCHED_RT_H_

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>

__BEGIN_DECLS

#pragma mark - Constants and Tunables

extern uint32_t rt_deadline_epsilon;
extern uint32_t rt_constraint_threshold;
extern int sched_rt_runq_strict_priority;
extern int sched_allow_rt_smt;

#pragma mark - Initialization

void sched_realtime_timebase_init(void);

/* Initialize realtime runqueues for the given pset. */
void sched_rt_init_pset(processor_set_t pset);

/* Called once all psets are initialized. */
void sched_rt_init_completed(void);

#if CONFIG_SCHED_EDGE
#pragma mark - Realtime Scheduler-CLPC Interface

/*
 * The realtime scheduler uses edges between psets to define policies
 * regarding migration and steal operations, similar to the edge scheduler.
 * The weights define an explicit search order for the scheduler to identify
 * alternative psets when a realtime thread's preferred pset is overloaded.
 *
 * The matrix can be directly manipulated with
 * sched_rt_config_set()/sched_rt_config_get(), but the preferred interface for
 * updates is to call sched_rt_matrix_set(), which will update cached values
 * computed from the matrix.
 */

void              sched_rt_config_set(pset_id_t src_pset, pset_id_t dst_pset, sched_clutch_edge edge_config);
sched_clutch_edge sched_rt_config_get(pset_id_t src_pset, pset_id_t dst_pset);

/*
 * sched_rt_matrix_get()/sched_rt_matrix_set()
 *
 * Selectively retrieve (or update, respectively) multiple edges in the realtime
 * matrix. The realtime spill order is recomputed for every pset with a changed
 * outgoing edge.
 *
 * The matrix provided should be `num_psets * num_psets`, where `num_psets`
 * is equal to `sched_num_psets`. Like the Edge matrix, it is indexed
 * first by source pset (major), then by destination pset (minor).
 */

void sched_rt_matrix_get(sched_clutch_edge *rt_matrix, bool *edge_requests, uint64_t num_psets);
void sched_rt_matrix_set(sched_clutch_edge *rt_matrix, bool *edge_changes, uint64_t num_psets);

#endif /* CONFIG_SCHED_EDGE */

#pragma mark - Scheduler Callouts

#if CONFIG_SCHED_SMT
/* SMT-aware callout for rt_choose_processor. */
processor_t sched_rtlocal_choose_processor_smt(processor_set_t starting_pset, processor_t processor, thread_t thread);
#else /* !CONFIG_SCHED_SMT */
processor_t sched_rt_choose_processor(processor_set_t starting_pset, processor_t processor, thread_t thread);
#endif /* !CONFIG_SCHED_SMT */

#if CONFIG_SCHED_EDGE
thread_t sched_rt_steal_thread(processor_set_t stealing_pset);
#endif /* CONFIG_SCHED_EDGE */
thread_t sched_rt_choose_thread(processor_t processor);

void sched_rt_queue_shutdown(processor_t processor, struct pulled_thread_queue * threadq);

void sched_rt_runq_scan(sched_update_scan_context_t scan_context);

int64_t sched_rt_runq_count_sum(void);

#pragma mark - Utilities

/*
 * We are in the process of migrating realtime scheduler code into sched_rt.c
 * to make it unit-testable in isolation.
 *
 * For the time being, these methods are made accessible to code that include
 * sched_rt.h. They will be made static members of sched_rt.c as soon as
 * practicable.
 */
uint64_t rt_deadline_add(uint64_t d, uint64_t e);

cpumap_t pset_available_but_not_running_rt_threads_cpumap(processor_set_t pset);

processor_t
pset_choose_furthest_deadline_processor_for_realtime_thread(
	processor_set_t pset,
	int             max_pri,
	uint64_t        minimum_deadline,
	processor_t     skip_processor,
	bool            skip_spills,
	bool            include_ast_urgent_pending_cpus);

#if CONFIG_SCHED_SMT
processor_t pset_choose_processor_for_realtime_thread_smt(
	processor_set_t pset,
	processor_t     skip_processor,
	bool            consider_secondaries,
	bool            skip_spills);
#else /* !CONFIG_SCHED_SMT */
processor_t
pset_choose_processor_for_realtime_thread(
	processor_set_t pset,
	processor_t     skip_processor,
	bool            skip_spills);
#endif /* !CONFIG_SCHED_SMT */

#if CONFIG_SCHED_EDGE
bool     rt_pset_has_stealable_threads(processor_set_t pset);
void     pset_update_rt_stealable_state(processor_set_t pset);
/* Realtime spill is only supported on platforms with the edge scheduler. */
bool rt_choose_next_processor_for_spill_IPI(processor_set_t starting_pset, processor_t chosen_processor, processor_t *result_processor, sched_ipi_type_t *result_ipi_type);
#else /* !CONFIG_SCHED_EDGE */
#define pset_update_rt_stealable_state(x) do {(void) x;} while (0)
#endif /* !CONFIG_SCHED_EDGE */

bool rt_pset_needs_a_followup_IPI(processor_set_t pset);
void rt_choose_next_processor_for_followup_IPI(processor_set_t pset, processor_t chosen_processor, processor_t *result_processor, sched_ipi_type_t *result_ipi_type);

bool rt_clear_pending_spill(processor_t processor, int reason);

#pragma mark - Realtime Runqueues

#if DEBUG || SCHED_TEST_HARNESS
void check_rt_runq_consistency(rt_queue_t rt_run_queue, thread_t thread);
#define CHECK_RT_RUNQ_CONSISTENCY(q, th)    check_rt_runq_consistency(q, th)
#else /* !(DEBUG || SCHED_TEST_HARNESS) */
#define CHECK_RT_RUNQ_CONSISTENCY(q, th)    do {} while (0)
#endif /* !(DEBUG || SCHED_TEST_HARNESS) */

int      rt_runq_count(processor_set_t);
thread_t rt_runq_dequeue(rt_queue_t rt_run_queue);
uint64_t rt_runq_earliest_deadline(processor_set_t);
thread_t rt_runq_first(rt_queue_t rt_run_queue);
bool     rt_runq_insert(processor_t processor, processor_set_t pset, thread_t thread);
bool     rt_runq_is_low_latency(processor_set_t pset);
int      rt_runq_priority(processor_set_t pset);
void     rt_runq_remove(rt_queue_t rt_run_queue, thread_t thread);

__END_DECLS

#endif /* _KERN_SCHED_RT_H_ */
