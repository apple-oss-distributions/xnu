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

#include <stdint.h>

#include <kern/bits.h>
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/sched_clutch.h>
#include <kern/sched_common.h>
#include <kern/sched_prim.h>
#include <kern/sched_rt.h>
#include <kern/thread.h>
#include <kern/queue.h>

#include <sys/kdebug_kernel.h>

#include <os/atomic_private.h>

#include <machine/machine_routines.h>

#define KTRC KDBG_RELEASE

#pragma mark - Constants and Tunables

uint32_t rt_deadline_epsilon;
uint32_t rt_constraint_threshold;
/* epsilon for comparing RT deadlines */
int rt_deadline_epsilon_us = 100;
uint32_t max_rt_quantum;
uint32_t min_rt_quantum;
int sched_allow_rt_smt = 1;
int sched_rt_runq_strict_priority = false;

int
sched_get_rt_deadline_epsilon(void)
{
	return rt_deadline_epsilon_us;
}

void
sched_set_rt_deadline_epsilon(int new_epsilon_us)
{
	rt_deadline_epsilon_us = new_epsilon_us;

	uint64_t abstime;
	clock_interval_to_absolutetime_interval(rt_deadline_epsilon_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && ((rt_deadline_epsilon_us == 0) || (uint32_t)abstime != 0));
	rt_deadline_epsilon = (uint32_t)abstime;
}

#pragma mark - Initialization

void
sched_realtime_timebase_init(void)
{
	uint64_t abstime;

	/* smallest rt computation (50 us) */
	clock_interval_to_absolutetime_interval(50, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_rt_quantum = (uint32_t)abstime;

	/* maximum rt computation (50 ms) */
	clock_interval_to_absolutetime_interval(
		50, 1000 * NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	max_rt_quantum = (uint32_t)abstime;

	/* constraint threshold for sending backup IPIs (4 ms) */
	clock_interval_to_absolutetime_interval(4, NSEC_PER_MSEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	rt_constraint_threshold = (uint32_t)abstime;

	/* epsilon for comparing deadlines */
	sched_set_rt_deadline_epsilon(rt_deadline_epsilon_us);
}

#if CONFIG_SCHED_EDGE
/* forward-declare config utility */
static void
sched_rt_config_pset_push(processor_set_t pset);
#endif /* CONFIG_SCHED_EDGE */

static void
rt_init_completed(void)
{
	/* Realtime spill/steal are only supported on platforms with the edge scheduler. */
#if CONFIG_SCHED_EDGE
	/* Hold sched_available_cores_lock to prevent multiple concurrent matrix updates. */
	spl_t s = splsched();
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);
	for (pset_id_t src_pset_id = 0; src_pset_id < sched_num_psets; src_pset_id++) {
		processor_set_t src_pset = pset_array[src_pset_id];
		assert3p(src_pset, !=, PROCESSOR_SET_NULL); /* all psets should be initialized */

		/* For each cluster, set all its outgoing edge parameters */
		for (pset_id_t dst_pset_id = 0; dst_pset_id < sched_num_psets; dst_pset_id++) {
			if (dst_pset_id == src_pset_id) {
				continue;
			}
			processor_set_t dst_pset = pset_array[dst_pset_id];
			assert3p(dst_pset, !=, PROCESSOR_SET_NULL); /* all psets should be initialized */

			bool clusters_homogenous = (src_pset->pset_type == dst_pset->pset_type);
			if (clusters_homogenous) {
				/* Default realtime policy: spill allowed among homogeneous psets. */
				sched_rt_config_set((pset_id_t) src_pset_id, (pset_id_t) dst_pset_id, (sched_clutch_edge) {
					.sce_migration_allowed = true,
					.sce_steal_allowed = true,
					.sce_migration_weight = 0,
				});
			} else {
				/* Default realtime policy: disallow spill among heterogeneous psets. */
				sched_rt_config_set((pset_id_t) src_pset_id, (pset_id_t) dst_pset_id, (sched_clutch_edge) {
					.sce_migration_allowed = false,
					.sce_steal_allowed = false,
					.sce_migration_weight = 0,
				});
			}
		}
	}

#if HAS_MCORE
	pset_node_t p_node = pset_node_for_pset_type(PSET_AMP_P);
	pset_node_t m_node = pset_node_for_pset_type(PSET_AMP_M);

	/* Disallow spill/steal between M psets. */
	foreach_pset_id(src_pset_id, m_node) {
		foreach_pset_id(dst_pset_id, m_node) {
			if (src_pset_id == dst_pset_id) {
				continue;
			}
			sched_rt_config_set((pset_id_t)src_pset_id, (pset_id_t)dst_pset_id, (sched_clutch_edge) {
				.sce_migration_allowed = false,
				.sce_steal_allowed = false,
				.sce_migration_weight = 0,
			});
		}
	}

	/* Identify a "reserve" pset for the system to run on when P-recommended
	 * realtime threads spill. */
	pset_id_t reserve_pset_id = PSET_ID_INVALID;

	if (!pset_node_is_empty(m_node)) {
		/* Choose an M pset to be the reserve pset. We should choose the same
		 * pset as sched_edge_cpu_init_completed() uses for a low-M performance
		 * island. */
		reserve_pset_id = (pset_id_t)lsb_first(m_node->pset_map);
	}


	foreach_pset_id(src_pset_id, p_node) {
		foreach_pset_id(dst_pset_id, m_node) {
			if (dst_pset_id == reserve_pset_id) {
				/* Spill is already disallowed because the psets are heterogeneous. */
				continue;
			}
			/* Allow bi-directional steal. */
			sched_rt_config_set((pset_id_t)src_pset_id, (pset_id_t)dst_pset_id, (sched_clutch_edge) {
				.sce_migration_allowed = true,
				.sce_steal_allowed = true,
				.sce_migration_weight = 1,
			});
			sched_rt_config_set((pset_id_t)dst_pset_id, (pset_id_t)src_pset_id, (sched_clutch_edge) {
				.sce_migration_allowed = true, /* allow migration so followup-spill IPIs work */
				.sce_steal_allowed = true,
				.sce_migration_weight = 0,
			});
		}
	}
#endif /* HAS_MCORE */

	for (pset_id_t pset_id = 0; pset_id < sched_num_psets; pset_id++) {
		sched_rt_config_pset_push(pset_array[pset_id]);
	}

	simple_unlock(&sched_available_cores_lock);
	splx(s);
#endif /* CONFIG_SCHED_EDGE */
}

static void
pset_rt_init(processor_set_t pset)
{
	for (int pri = BASEPRI_RTQUEUES; pri <= MAXPRI; pri++) {
		int i = pri - BASEPRI_RTQUEUES;
		rt_queue_pri_t *rqi = &pset->rt_runq.rt_queue_pri[i];
		queue_init(&rqi->pri_queue);
		rqi->pri_count = 0;
		rqi->pri_earliest_deadline = RT_DEADLINE_NONE;
		rqi->pri_constraint = RT_CONSTRAINT_NONE;
	}
	os_atomic_init(&pset->stealable_rt_threads_earliest_deadline, RT_DEADLINE_NONE);

	rt_queue_t rt_runq = &pset->rt_runq;
	os_atomic_init(&rt_runq->count, 0);
	os_atomic_init(&rt_runq->earliest_deadline, RT_DEADLINE_NONE);
	os_atomic_init(&rt_runq->constraint, RT_CONSTRAINT_NONE);
	os_atomic_init(&rt_runq->ed_index, NOPRI);
	bzero(&rt_runq->bitmap, sizeof(rt_runq->bitmap));
	bzero(&rt_runq->runq_stats, sizeof(rt_runq->runq_stats));

#if __AMP__
	/*
	 * Initialize spill/steal search orders as invalid to prevent spill/steal
	 * before the matrix is configured.
	 */
	bzero(pset->sched_rt_edges, sizeof(pset->sched_rt_edges));
	for (pset_id_t i = 0; i < MAX_PSETS - 1; i++) {
		pset->sched_rt_spill_search_order.spso_search_order[i] = PSET_ID_INVALID;
#if CONFIG_SCHED_EDGE
		pset->sched_rt_steal_search_order.spso_search_order[i] = PSET_ID_INVALID;
#endif /* CONFIG_SCHED_EDGE */
	}
#endif /* __AMP__ */
}

#pragma mark - Realtime Scheduler/CLPC interface

#if CONFIG_SCHED_EDGE
void
sched_rt_config_set(
	uint8_t src_pset,
	uint8_t dst_pset,
	sched_clutch_edge edge_config)
{
	assert(src_pset != dst_pset || !edge_config.sce_migration_allowed); /* No self-edges. */
	os_atomic_store(&pset_array[src_pset]->sched_rt_edges[dst_pset], edge_config, relaxed);
}

sched_clutch_edge
sched_rt_config_get(
	uint8_t src_pset,
	uint8_t dst_pset)
{
	return os_atomic_load(&pset_array[src_pset]->sched_rt_edges[dst_pset], relaxed);
}

void
sched_rt_matrix_get(
	sched_clutch_edge *edge_matrix,
	bool *edge_requests,
	uint64_t num_psets)
{
	uint64_t edge_index = 0;
	for (uint8_t src_pset = 0; src_pset < num_psets; src_pset++) {
		for (uint8_t dst_pset = 0; dst_pset < num_psets; dst_pset++) {
			if (edge_requests[edge_index]) {
				edge_matrix[edge_index] = sched_rt_config_get(src_pset, dst_pset);
			}
			edge_index++;
		}
	}
}

/*
 * sched_rt_config_pset_push()
 *
 * After using sched_rt_config_set() to update edge tunables outgoing from a particular source
 * pset, this function should be called in order to propagate the updates to derived metadata for
 * the pset, such as search orders for outgoing spill and steal.
 */
static void
sched_rt_config_pset_push(processor_set_t pset)
{
	assert3u(pset->pset_id, <, UINT8_MAX);

	sched_pset_search_order_sort_data_t spill_datas[MAX_PSETS - 1], steal_datas[MAX_PSETS - 1];
	uint num_spill_datas = 0, num_steal_datas = 0;
	for (pset_id_t other_pset_id = 0; other_pset_id < sched_num_psets; other_pset_id++) {
		if (pset->pset_id == other_pset_id) {
			continue; /* No self-edges. */
		}
		/* Spill */
		sched_clutch_edge out_edge = sched_rt_config_get((pset_id_t)pset->pset_id, other_pset_id);
		if (out_edge.sce_migration_allowed) {
			spill_datas[num_spill_datas++] = (sched_pset_search_order_sort_data_t) {
				.spsosd_src_pset = pset,
				.spsosd_migration_weight = out_edge.sce_migration_weight,
				.spsosd_dst_pset_id = other_pset_id
			};
		}
		/* Steal */
		sched_clutch_edge in_edge = sched_rt_config_get(other_pset_id, (pset_id_t)pset->pset_id);
		if (in_edge.sce_steal_allowed) {
			steal_datas[num_steal_datas++] = (sched_pset_search_order_sort_data_t) {
				.spsosd_src_pset = pset,
				.spsosd_migration_weight = in_edge.sce_migration_weight,
				.spsosd_dst_pset_id = other_pset_id,
			};
		}
	}
	sched_pset_search_order_compute(&pset->sched_rt_spill_search_order, spill_datas, num_spill_datas, sched_edge_search_order_weight_then_locality_cmp);
	sched_pset_search_order_compute(&pset->sched_rt_steal_search_order, steal_datas, num_steal_datas, sched_edge_search_order_weight_then_locality_cmp);
}

void
sched_rt_matrix_set(
	sched_clutch_edge *rt_matrix,
	bool *edge_changes,
	uint64_t num_psets)
{
	/* Hold sched_available_cores_lock to prevent multiple concurrent matrix updates. */
	spl_t s = splsched();
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);

	for (uint8_t src_pset_id = 0; src_pset_id < num_psets; src_pset_id++) {
		for (uint8_t dst_pset_id = 0; dst_pset_id < num_psets; dst_pset_id++) {
			const uint64_t rt_matrix_index = src_pset_id * num_psets + dst_pset_id;
			if (edge_changes[rt_matrix_index]) {
				sched_rt_config_set(src_pset_id, dst_pset_id, rt_matrix[rt_matrix_index]);
			}
		}
	}

	for (pset_id_t pset_id = 0; pset_id < num_psets; pset_id++) {
		sched_rt_config_pset_push(pset_array[pset_id]);
	}

	simple_unlock(&sched_available_cores_lock);
	splx(s);
}
#endif /* CONFIG_SCHED_EDGE */

#pragma mark - Scheduler Callouts

#if CONFIG_SCHED_SMT
/*
 * SMT-aware callout for rt_choose_processor.
 */
processor_t
sched_rtlocal_choose_processor_smt(
	processor_set_t         starting_pset,
	processor_t             processor,
	thread_t                thread)
{
	processor_set_t nset = PROCESSOR_SET_NULL;
	processor_set_t pset = starting_pset;
	pset_node_t node = pset->node;

	processor_t lc_processor = processor;
	integer_t lowest_count = INT_MAX;
	if (lc_processor != PROCESSOR_NULL) {
		lowest_count = SCHED(processor_runq_count)(processor);
	}

	bool include_ast_urgent_pending_cpus = false;
	cpumap_t ast_urgent_pending;
try_again:
	ast_urgent_pending = 0;
	int consider_secondaries = (!pset->is_SMT) || (bit_count(node->pset_map) == 1) || (node->pset_non_rt_primary_map == 0) || include_ast_urgent_pending_cpus;
	for (; consider_secondaries < 2; consider_secondaries++) {
		pset = change_locked_pset(pset, starting_pset);
		do {
			cpumap_t available_map = pset_available_cpumap(pset);
			if (available_map == 0) {
				goto no_available_cpus;
			}

			processor = pset_choose_processor_for_realtime_thread_smt(pset, PROCESSOR_NULL, consider_secondaries, false);
			if (processor) {
				return processor;
			}

			if (consider_secondaries) {
				processor = pset_choose_furthest_deadline_processor_for_realtime_thread(pset, thread->sched_pri, thread->realtime.deadline, PROCESSOR_NULL, false, include_ast_urgent_pending_cpus);
				if (processor) {
					/*
					 * Instead of looping through all the psets to find the global
					 * furthest deadline processor, preempt the first candidate found.
					 * The preempted thread will then find any other available far deadline
					 * processors to preempt.
					 */
					return processor;
				}

				ast_urgent_pending |= pset->pending_AST_URGENT_cpu_mask;

				if (rt_runq_count(pset) < lowest_count) {
					int cpuid = bit_first(available_map);
					assert(cpuid >= 0);
					lc_processor = processor_array[cpuid];
					lowest_count = rt_runq_count(pset);
				}
			}

no_available_cpus:
			nset = next_pset(pset);

			if (nset != starting_pset) {
				pset = change_locked_pset(pset, nset);
			}
		} while (nset != starting_pset);
	}

	/* Short cut for single pset nodes */
	if (bit_count(node->pset_map) == 1) {
		if (lc_processor) {
			pset_assert_locked(lc_processor->processor_set);
			return lc_processor;
		}
	} else {
		if (ast_urgent_pending && !include_ast_urgent_pending_cpus) {
			/* See the comment in pset_choose_furthest_deadline_processor_for_realtime_thread() */
			include_ast_urgent_pending_cpus = true;
			goto try_again;
		}
	}

	processor = lc_processor;

	if (processor) {
		pset = change_locked_pset(pset, processor->processor_set);
		/* Check that chosen processor is still usable */
		cpumap_t available_map = pset_available_cpumap(pset);
		if (bit_test(available_map, processor->cpu_id)) {
			return processor;
		}

		/* processor is no longer usable */
		processor = PROCESSOR_NULL;
	}

	pset_assert_locked(pset);
	pset_unlock(pset);
	return PROCESSOR_NULL;
}
#else /* !CONFIG_SCHED_SMT */
/*
 * Called with thread and starting_pset locked. The returned processor's pset is
 * locked on return.
 */
processor_t
sched_rt_choose_processor(
	const processor_set_t starting_pset,
	processor_t processor,
	thread_t thread)
{
	assert3u(thread->sched_pri, >=, BASEPRI_RTQUEUES);
	assert3u(thread->sched_pri, <=, MAXPRI);

	/*
	 * In choose_starting_pset, we found a good candidate pset for this thread.
	 * Now, we pick the best processor to preempt, if there is one.  It is also
	 * possible that conditions have changed and the thread should spill to
	 * another pset.
	 */

	processor_set_t pset = starting_pset; /* Lock is held on this pset. */
	pset_assert_locked(pset);

#if __AMP__
	/*
	 * If there are processors with outstanding urgent preemptions, we consider
	 * them in a second pass. While we are changing pset locks here, it is
	 * possible a processor may resolve its outstanding urgent preemption and
	 * become eligible to run this thread. See comment in
	 * pset_choose_furthest_deadline_processor_for_realtime_thread().
	 */
	bool found_ast_urgent_pending = false; /* Tracks whether any (eligible) processors have pending urgent ASTs. */
	for (int include_ast_urgent_pending_cpus = 0; include_ast_urgent_pending_cpus < 2; include_ast_urgent_pending_cpus++) {
		if (include_ast_urgent_pending_cpus && !found_ast_urgent_pending) {
			break; /* Skip the second pass. */
		}

		sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
		while (sched_iterate_psets_ordered(starting_pset, &starting_pset->sched_rt_spill_search_order, ~0, &istate)) {
			/* Switch to the next pset. We need to check for null psets because
			 * we do not use acquire/release semantics for the spill order. */
			processor_set_t nset = pset_array[istate.spis_pset_id];
			if (__improbable(nset == PROCESSOR_SET_NULL)) {
				continue;
			}
			pset = change_locked_pset(pset, nset);

			processor = pset_choose_processor_for_realtime_thread(pset, PROCESSOR_NULL, false);
			if (processor != PROCESSOR_NULL) {
				/* We found a candidate processor on this pset to wake or preempt. */
				pset_assert_locked(processor->processor_set);
				return processor;
			}

			/* TODO <rdar://140219824>: Policy question of EDF vs targeting idle cores on another pset. */
			processor = pset_choose_furthest_deadline_processor_for_realtime_thread(pset, thread->sched_pri, thread->realtime.deadline, PROCESSOR_NULL, false, include_ast_urgent_pending_cpus);
			if (processor) {
				/*
				 * Instead of looping through all the psets to find the global
				 * furthest deadline processor, preempt the first candidate found.
				 * The preempted thread will then find any other available far deadline
				 * processors to preempt.
				 */
				pset_assert_locked(processor->processor_set);
				return processor;
			}

			found_ast_urgent_pending = found_ast_urgent_pending || (pset->pending_AST_URGENT_cpu_mask != 0);
		}
	}

	/*
	 * There was no obvious (idle or non-realtime) processor to run the thread.
	 * Instead, do EDF scheduling again on starting_pset, putting the thread on
	 * the run queue if there is no processor to preempt.
	 */

	pset = change_locked_pset(pset, starting_pset);
#endif /* __AMP__ */

	/* Check (again, for AMP systems) that there is no lower-priority or idle processor. */
	processor = pset_choose_processor_for_realtime_thread(pset, PROCESSOR_NULL, false);
	if (processor != PROCESSOR_NULL) {
		/* We found a candidate processor on this pset to wake or preempt. */
		pset_assert_locked(processor->processor_set);
		return processor;
	}

	processor = pset_choose_furthest_deadline_processor_for_realtime_thread(pset, thread->sched_pri, thread->realtime.deadline, PROCESSOR_NULL, false, true);
	if (processor == PROCESSOR_NULL) {
		/* Choose an arbitrary available and recommended processor from the pset.
		 * It won't get preempted anyways, since this thread has a later
		 * deadline. */
		int processor_id = lsb_first(pset_available_cpumap(pset));

		/* starting_pset had available, recommended processors coming into
		 * rt_choose_processor(), but that might have changed after dropping the
		 * pset lock. If there are no such processors, bail out here and let
		 * sched_edge_migrate_candidate() find a better starting pset. */
		if (processor_id < 0) {
			pset_unlock(pset);
			return PROCESSOR_NULL;
		}

		processor = processor_array[processor_id];
	}

	pset_assert_locked(processor->processor_set);
	return processor;
}
#endif /* !CONFIG_SCHED_SMT */

#if CONFIG_SCHED_EDGE
/*
 * Called with stealing_pset locked and returns with stealing_pset locked but
 * the lock will have been dropped if a thread is returned. The lock may have
 * been temporarily dropped, even if no thread is returned.
 */
thread_t
sched_rt_steal_thread(processor_set_t stealing_pset)
{
	uint64_t earliest_deadline = rt_runq_earliest_deadline(stealing_pset);
	processor_set_t pset = stealing_pset;

	/* Continue searching until there are no steal candidates found in a single iteration. */
	while (true) {
		processor_set_t target_pset = NULL;
		uint64_t target_deadline;
		if (__improbable(os_sub_overflow(earliest_deadline, rt_deadline_epsilon, &target_deadline))) {
			target_deadline = 0;
		}

		sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
		while (sched_iterate_psets_ordered(stealing_pset, &stealing_pset->sched_rt_steal_search_order, ~BIT(stealing_pset->pset_id), &istate)) {
			assert3s(istate.spis_pset_id, !=, stealing_pset->pset_id); /* stealing_pset's runqueue is drained by sched_rt_choose_processor */
			const processor_set_t nset = pset_array[istate.spis_pset_id];
			/* Check for null because we do not use acquire/release semantics for steal order. */
			if (__improbable(nset == PROCESSOR_SET_NULL)) {
				continue;
			}
			uint64_t nset_deadline = os_atomic_load(&nset->stealable_rt_threads_earliest_deadline, relaxed);
			if (nset_deadline < target_deadline) {
				target_pset = nset;
				target_deadline = nset_deadline;
			}
		}

		if (target_pset != PROCESSOR_SET_NULL) {
			assert3u(target_deadline, !=, RT_DEADLINE_NONE);

			/* target_pset is a candidate for steal. Check again under its pset lock. */

			pset = change_locked_pset(pset, target_pset);
			if (os_atomic_load(&pset->stealable_rt_threads_earliest_deadline, relaxed) <= target_deadline) {
				/* Steal the next thread from target_pset's runqueue. */
				thread_t new_thread = rt_runq_dequeue(&pset->rt_runq);
				pset_update_rt_stealable_state(pset);
				KTRC(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RT_STEAL) | DBG_FUNC_NONE, (uintptr_t)thread_tid(new_thread), pset->pset_id, pset->cpu_set_low, 0);

				pset = change_locked_pset(pset, stealing_pset);
				return new_thread;
			} else {
				/* Failed to steal (another pset stole first). Try again. */
				KTRC(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RT_STEAL) | DBG_FUNC_NONE, (uintptr_t)thread_tid(THREAD_NULL), pset->pset_id, pset->cpu_set_low, 1);
				pset = change_locked_pset(pset, stealing_pset);
				/* Update earliest_deadline in case it changed while the stealing_pset lock was not held. */
				earliest_deadline = rt_runq_earliest_deadline(pset);
				continue;
			}
		} else {
			/* No steal candidates, stop searching. */
			break;
		}
	}
	/* No stealable threads, return with stealing_pset locked. */
	pset = change_locked_pset(pset, stealing_pset);
	return THREAD_NULL;
}
#endif /* CONFIG_SCHED_EDGE */

/*
 * processor's pset is locked, may drop and retake the lock
 */
thread_t
sched_rt_choose_thread(processor_t processor)
{
	processor_set_t pset = processor->processor_set;
	pset_assert_locked(pset);

	if (SCHED(rt_steal_thread) != NULL) {
		do {
			rt_clear_pending_spill(processor, 2);
			thread_t new_thread = SCHED(rt_steal_thread)(pset);
			/* pset lock may have been dropped and retaken, is currently locked */
			pset_assert_locked(pset);
			if (new_thread != THREAD_NULL) {
				/* Spill might have been set if the pset lock was dropped in steal. */
				rt_clear_pending_spill(processor, 3);
				return new_thread;
			}
		} while (bit_test(pset->rt_pending_spill_cpu_mask, processor->cpu_id));
	}
	rt_clear_pending_spill(processor, 5);

	if (rt_runq_count(pset) > 0) {
		thread_t new_thread = rt_runq_dequeue(&pset->rt_runq);
		assert(new_thread != THREAD_NULL);
		pset_update_rt_stealable_state(pset);
		return new_thread;
	}

	return THREAD_NULL;
}

void
sched_rt_init_pset(processor_set_t pset)
{
	pset_rt_init(pset);
}

void
sched_rt_init_completed(void)
{
	rt_init_completed();
}

void
sched_rt_queue_shutdown(processor_t processor, struct pulled_thread_queue * threadq)
{
	processor_set_t pset = processor->processor_set;

	pset_lock(pset);

	/* We only need to migrate threads if this is the last active or last recommended processor in the pset */
	if (bit_count(pset_available_cpumap(pset)) > 0) {
		pset_unlock(pset);
		return;
	}

	while (rt_runq_count(pset) > 0) {
		thread_t thread = rt_runq_dequeue(&pset->rt_runq);
		pulled_thread_queue_enqueue(threadq, thread);
	}
	SCHED(update_pset_load_average)(pset, 0);
	pset_update_rt_stealable_state(pset);
	pset_unlock(pset);
}

/*
 * Assumes RT lock is not held, and acquires splsched/rt_lock itself.
 * Also records tracepoints for pset bitmasks under the pset lock.
 */
void
sched_rt_runq_scan(sched_update_scan_context_t scan_context)
{
	thread_t        thread;

	pset_node_t node = sched_boot_pset_node;
	processor_set_t pset = node->psets;

	spl_t s = splsched();
	do {
		while (pset != NULL) {
			pset_lock(pset);

			bitmap_t *map = pset->rt_runq.bitmap;
			for (int i = bitmap_first(map, NRTQS); i >= 0; i = bitmap_next(map, i)) {
				rt_queue_pri_t *rt_runq = &pset->rt_runq.rt_queue_pri[i];

				qe_foreach_element_safe(thread, &rt_runq->pri_queue, runq_links) {
					if (thread->last_made_runnable_time < scan_context->earliest_rt_make_runnable_time) {
						scan_context->earliest_rt_make_runnable_time = thread->last_made_runnable_time;
					}
				}
			}

			KTRC(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_PSET_BITMASKS),
			    pset->pset_id,
			    pset->recommended_bitmask,
			    pset->perfcontrol_cpu_migration_bitmask,
			    pset->perfcontrol_cpu_preferred_bitmask);

			pset_unlock(pset);

			pset = pset->pset_list;
		}
	} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));
	splx(s);
}

int64_t
sched_rt_runq_count_sum(void)
{
	pset_node_t node = sched_boot_pset_node;
	processor_set_t pset = node->psets;
	int64_t count = 0;

	do {
		while (pset != NULL) {
			count += pset->rt_runq.runq_stats.count_sum;

			pset = pset->pset_list;
		}
	} while (((node = node->node_list) != NULL) && ((pset = node->psets) != NULL));

	return count;
}

#pragma mark - Utilities

uint64_t
rt_deadline_add(uint64_t d, uint64_t e)
{
	uint64_t sum;
	return os_add_overflow(d, e, &sum) ? RT_DEADLINE_NONE : sum;
}

cpumap_t
pset_available_but_not_running_rt_threads_cpumap(processor_set_t pset)
{
	cpumap_t avail_map = pset_available_cpumap(pset);
#if CONFIG_SCHED_SMT
	if (!sched_allow_rt_smt) {
		/*
		 * Secondary CPUs are not allowed to run RT threads, so
		 * only primary CPUs should be included
		 */
		avail_map &= pset->primary_map;
	}
#endif /* CONFIG_SCHED_SMT */

	return avail_map & ~pset->realtime_map;
}

/* pset is locked */
static processor_t
pset_choose_next_processor_for_realtime_thread(processor_set_t pset, int max_pri, uint64_t minimum_deadline, processor_t skip_processor, bool consider_secondaries)
{
	(void) consider_secondaries;
	bool skip_spills = true;
	bool include_ast_urgent_pending_cpus = false;

#if CONFIG_SCHED_SMT
	processor_t next_processor = pset_choose_processor_for_realtime_thread_smt(pset, skip_processor, consider_secondaries, skip_spills);
#else /* CONFIG_SCHED_SMT */
	processor_t next_processor = pset_choose_processor_for_realtime_thread(pset, skip_processor, skip_spills);
#endif /* CONFIG_SCHED_SMT */
	if (next_processor != PROCESSOR_NULL) {
		return next_processor;
	}

	next_processor = pset_choose_furthest_deadline_processor_for_realtime_thread(pset, max_pri, minimum_deadline, skip_processor, skip_spills, include_ast_urgent_pending_cpus);
	return next_processor;
}

#if CONFIG_SCHED_EDGE
/*
 * Realtime Steal Utilities
 *
 * Realtime steal is only supported on platforms with the edge scheduler.
 */

/* Update realtime stealable state. */
void
pset_update_rt_stealable_state(processor_set_t pset)
{
	pset_assert_locked(pset);
	if (rt_pset_has_stealable_threads(pset)) {
		os_atomic_store(&pset->stealable_rt_threads_earliest_deadline, rt_runq_earliest_deadline(pset), relaxed);
	} else {
		os_atomic_store(&pset->stealable_rt_threads_earliest_deadline, RT_DEADLINE_NONE, relaxed);
	}
}

bool
rt_pset_has_stealable_threads(processor_set_t pset)
{
	cpumap_t avail_map = pset_available_but_not_running_rt_threads_cpumap(pset);

	return rt_runq_count(pset) > bit_count(avail_map);
}

/*
 * Returns the next processor to IPI for a migrating realtime thread. Realtime
 * spill is only supported with the edge scheduler.
 *
 * Expects starting_pset to be locked. Returns false if starting_pset was never
 * unlocked; otherwise, returns true with no lock held.
 */
bool
rt_choose_next_processor_for_spill_IPI(
	processor_set_t  starting_pset,
	processor_t      chosen_processor,
	processor_t      *result_processor,
	sched_ipi_type_t *result_ipi_type
	)
{
	assert3p(starting_pset, !=, PROCESSOR_SET_NULL);
	assert3p(chosen_processor, !=, PROCESSOR_NULL);

	uint64_t earliest_deadline = rt_runq_earliest_deadline(starting_pset);
	int max_pri = rt_runq_priority(starting_pset);
	__kdebug_only uint64_t spill_tid = thread_tid(rt_runq_first(&starting_pset->rt_runq));
	processor_set_t pset = starting_pset; /* lock is held on this pset */
	processor_t next_rt_processor = PROCESSOR_NULL;
	/* Optimization so caller can avoid unnecessary lock-takes if there are no psets eligible for spill: */
	bool starting_pset_was_unlocked = false;

	cpumap_t candidate_map = ~BIT(starting_pset->pset_id); /* exclude stealing_pset */
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	while (sched_iterate_psets_ordered(starting_pset, &starting_pset->sched_rt_spill_search_order, candidate_map, &istate)) {
		assert3u(starting_pset->pset_id, !=, istate.spis_pset_id);
		/* Check for null pset because we do not use acquire/release semantics for spill order. */
		processor_set_t nset = pset_array[istate.spis_pset_id];
		if (__improbable(nset == PROCESSOR_SET_NULL)) {
			continue;
		}

		/* Make sure the pset is allowed to steal threads from stealing_pset's runqueue. */
		sched_clutch_edge edge = sched_rt_config_get((pset_id_t) starting_pset->pset_id, (pset_id_t) istate.spis_pset_id);
		if (istate.spis_pset_id != starting_pset->pset_id && edge.sce_steal_allowed == false) {
			continue;
		}
		pset = change_locked_pset(pset, nset);
		starting_pset_was_unlocked = true;

		next_rt_processor = pset_choose_next_processor_for_realtime_thread(pset, max_pri, earliest_deadline, chosen_processor, true);
		if (next_rt_processor != PROCESSOR_NULL) {
			break;
		}
	}

	if (next_rt_processor != PROCESSOR_NULL) {
		if (pset != starting_pset) {
			if (bit_set_if_clear(pset->rt_pending_spill_cpu_mask, next_rt_processor->cpu_id)) {
				KTRC(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RT_SIGNAL_SPILL) | DBG_FUNC_START,
				    next_rt_processor->cpu_id, pset->rt_pending_spill_cpu_mask, starting_pset->cpu_set_low, spill_tid);
			}
		}
		*result_ipi_type = sched_ipi_action(next_rt_processor, NULL, SCHED_IPI_EVENT_RT_PREEMPT);
		*result_processor = next_rt_processor;
	}
	if (starting_pset_was_unlocked) {
		pset_unlock(pset);
		return true;
	} else {
		return false;
	}
}
#endif /* CONFIG_SCHED_EDGE */

bool
rt_pset_needs_a_followup_IPI(processor_set_t pset)
{
	int nbackup_cpus = 0;

	if (rt_runq_is_low_latency(pset)) {
		nbackup_cpus = sched_rt_n_backup_processors;
	}

	int rt_rq_count = rt_runq_count(pset);

	return (rt_rq_count > 0) && ((rt_rq_count + nbackup_cpus - bit_count(pset->pending_AST_URGENT_cpu_mask)) > 0);
}

/*
 * Returns the next processor to IPI as a followup for low-latency realtime
 * threads on the runqueue.
 *
 * pset should be locked, and stays locked the whole time.
 */
void
rt_choose_next_processor_for_followup_IPI(
	processor_set_t pset,
	processor_t chosen_processor,
	processor_t *result_processor,
	sched_ipi_type_t *result_ipi_type)
{
	uint64_t earliest_deadline = rt_runq_earliest_deadline(pset);
	int max_pri = rt_runq_priority(pset);
	processor_t next_rt_processor = pset_choose_next_processor_for_realtime_thread(pset, max_pri, earliest_deadline, chosen_processor, true);
	if (next_rt_processor != PROCESSOR_NULL) {
		*result_ipi_type = sched_ipi_action(next_rt_processor, NULL, SCHED_IPI_EVENT_RT_PREEMPT);
		*result_processor = next_rt_processor;
	}
}

#if CONFIG_SCHED_SMT
extern int sched_avoid_cpu0;
extern int sched_allow_rt_smt;

/* pset is locked */
processor_t
pset_choose_processor_for_realtime_thread_smt(processor_set_t pset, processor_t skip_processor, bool consider_secondaries, bool skip_spills)
{
#if defined(__x86_64__)
	bool avoid_cpu0 = sched_avoid_cpu0 && bit_test(pset->cpu_bitmask, 0);
#else
	const bool avoid_cpu0 = false;
#endif
	cpumap_t cpu_map;

try_again:
	cpu_map = pset_available_cpumap(pset) & ~pset->pending_AST_URGENT_cpu_mask & ~pset->realtime_map;
	if (skip_processor) {
		bit_clear(cpu_map, skip_processor->cpu_id);
	}
	if (skip_spills) {
		cpu_map &= ~pset->rt_pending_spill_cpu_mask;
	}

	if (avoid_cpu0 && (sched_avoid_cpu0 == 2)) {
		bit_clear(cpu_map, 0);
	}

	cpumap_t primary_map = cpu_map & pset->primary_map;
	if (avoid_cpu0) {
		primary_map = bit_ror64(primary_map, 1);
	}

	int rotid = lsb_first(primary_map);
	if (rotid >= 0) {
		int cpuid = avoid_cpu0 ? ((rotid + 1) & 63) : rotid;

		processor_t processor = processor_array[cpuid];

		return processor;
	}

	if (!pset->is_SMT || !sched_allow_rt_smt || !consider_secondaries) {
		goto out;
	}

	if (avoid_cpu0 && (sched_avoid_cpu0 == 2)) {
		/* Also avoid cpu1 */
		bit_clear(cpu_map, 1);
	}

	/* Consider secondary processors whose primary is actually running a realtime thread */
	cpumap_t secondary_map = cpu_map & ~pset->primary_map & (pset->realtime_map << 1);
	if (avoid_cpu0) {
		/* Also avoid cpu1 */
		secondary_map = bit_ror64(secondary_map, 2);
	}
	rotid = lsb_first(secondary_map);
	if (rotid >= 0) {
		int cpuid = avoid_cpu0 ?  ((rotid + 2) & 63) : rotid;

		processor_t processor = processor_array[cpuid];

		return processor;
	}

	/* Consider secondary processors */
	secondary_map = cpu_map & ~pset->primary_map;
	if (avoid_cpu0) {
		/* Also avoid cpu1 */
		secondary_map = bit_ror64(secondary_map, 2);
	}
	rotid = lsb_first(secondary_map);
	if (rotid >= 0) {
		int cpuid = avoid_cpu0 ?  ((rotid + 2) & 63) : rotid;

		processor_t processor = processor_array[cpuid];

		return processor;
	}

	/*
	 * I was hoping the compiler would optimize
	 * this away when avoid_cpu0 is const bool false
	 * but it still complains about the assignmnent
	 * in that case.
	 */
	if (avoid_cpu0 && (sched_avoid_cpu0 == 2)) {
#if defined(__x86_64__)
		avoid_cpu0 = false;
#else
		assert(0);
#endif
		goto try_again;
	}

out:
	if (skip_processor) {
		return PROCESSOR_NULL;
	}

	/*
	 * If we didn't find an obvious processor to choose, but there are still more CPUs
	 * not already running realtime threads than realtime threads in the realtime run queue,
	 * this thread belongs in this pset, so choose some other processor in this pset
	 * to ensure the thread is enqueued here.
	 */
	cpumap_t non_realtime_map = pset_available_cpumap(pset) & pset->primary_map & ~pset->realtime_map;
	if (bit_count(non_realtime_map) > rt_runq_count(pset)) {
		cpu_map = non_realtime_map;
		assert(cpu_map != 0);
		int cpuid = bit_first(cpu_map);
		assert(cpuid >= 0);
		return processor_array[cpuid];
	}

	if (!pset->is_SMT || !sched_allow_rt_smt || !consider_secondaries) {
		goto skip_secondaries;
	}

	non_realtime_map = pset_available_cpumap(pset) & ~pset->realtime_map;
	if (bit_count(non_realtime_map) > rt_runq_count(pset)) {
		cpu_map = non_realtime_map;
		assert(cpu_map != 0);
		int cpuid = bit_first(cpu_map);
		assert(cpuid >= 0);
		return processor_array[cpuid];
	}

skip_secondaries:
	return PROCESSOR_NULL;
}
#else /* !CONFIG_SCHED_SMT*/
/* pset is locked */
processor_t
pset_choose_processor_for_realtime_thread(processor_set_t pset, processor_t skip_processor, bool skip_spills)
{
	cpumap_t cpu_map = pset_available_cpumap(pset) & ~pset->pending_AST_URGENT_cpu_mask & ~pset->realtime_map;
	if (skip_processor) {
		bit_clear(cpu_map, skip_processor->cpu_id);
	}
	if (skip_spills) {
		cpu_map &= ~pset->rt_pending_spill_cpu_mask;
	}

	int rotid = lsb_first(cpu_map);
	if (rotid >= 0) {
		return processor_array[rotid];
	}

	/*
	 * If we didn't find an obvious processor to choose, but there are still more CPUs
	 * not already running realtime threads than realtime threads in the realtime run queue,
	 * this thread belongs in this pset, so choose some other processor in this pset
	 * to ensure the thread is enqueued here.
	 */
	cpumap_t non_realtime_map = pset_available_cpumap(pset) & ~pset->realtime_map;
	if (bit_count(non_realtime_map) > rt_runq_count(pset)) {
		cpu_map = non_realtime_map;
		assert(cpu_map != 0);
		int cpuid = bit_first(cpu_map);
		assert(cpuid >= 0);
		return processor_array[cpuid];
	}

	return PROCESSOR_NULL;
}
#endif /* !CONFIG_SCHED_SMT */

/*
 * Choose the processor with (1) the lowest priority less than max_pri and (2) the furthest deadline for that priority.
 * If all available processors are at max_pri, choose the furthest deadline that is greater than minimum_deadline.
 *
 * pset is locked.
 */
processor_t
pset_choose_furthest_deadline_processor_for_realtime_thread(processor_set_t pset, int max_pri, uint64_t minimum_deadline, processor_t skip_processor, bool skip_spills, bool include_ast_urgent_pending_cpus)
{
	uint64_t  furthest_deadline = rt_deadline_add(minimum_deadline, rt_deadline_epsilon);
	processor_t fd_processor = PROCESSOR_NULL;
	int lowest_priority = max_pri;

	cpumap_t cpu_map = pset_available_cpumap(pset) & ~pset->pending_AST_URGENT_cpu_mask;
	if (skip_processor) {
		bit_clear(cpu_map, skip_processor->cpu_id);
	}
	if (skip_spills) {
		cpu_map &= ~pset->rt_pending_spill_cpu_mask;
	}

	for (int cpuid = bit_first(cpu_map); cpuid >= 0; cpuid = bit_next(cpu_map, cpuid)) {
		processor_t processor = processor_array[cpuid];

		if (processor->current_pri > lowest_priority) {
			continue;
		}

		if (processor->current_pri < lowest_priority) {
			lowest_priority = processor->current_pri;
			furthest_deadline = processor->deadline;
			fd_processor = processor;
			continue;
		}

		if (processor->deadline > furthest_deadline) {
			furthest_deadline = processor->deadline;
			fd_processor = processor;
		}
	}

	if (fd_processor) {
		return fd_processor;
	}

	/*
	 * There is a race condition possible when there are multiple processor sets.
	 * choose_processor() takes pset lock A, sees the pending_AST_URGENT_cpu_mask set for a processor in that set and finds no suitable candiate CPU,
	 * so it drops pset lock A and tries to take pset lock B.  Meanwhile the pending_AST_URGENT_cpu_mask CPU is looking for a thread to run and holds
	 * pset lock B. It doesn't find any threads (because the candidate thread isn't yet on any run queue), so drops lock B, takes lock A again to clear
	 * the pending_AST_URGENT_cpu_mask bit, and keeps running the current (far deadline) thread. choose_processor() now has lock B and can only find
	 * the lowest count processor in set B so enqueues it on set B's run queue but doesn't IPI anyone. (The lowest count includes all threads,
	 * near and far deadlines, so will prefer a low count of earlier deadlines to a high count of far deadlines, which is suboptimal for EDF scheduling.
	 * To make a better choice we would need to know how many threads with earlier deadlines than the candidate thread exist on each pset's run queue.
	 * But even if we chose the better run queue, we still wouldn't send an IPI in this case.)
	 *
	 * The migitation is to also look for suitable CPUs that have their pending_AST_URGENT_cpu_mask bit set where there are no earlier deadline threads
	 * on the run queue of that pset.
	 */
	if (include_ast_urgent_pending_cpus && (rt_runq_earliest_deadline(pset) > furthest_deadline)) {
		cpu_map = pset_available_cpumap(pset) & pset->pending_AST_URGENT_cpu_mask;
		assert(skip_processor == PROCESSOR_NULL);
		assert(skip_spills == false);

		for (int cpuid = bit_first(cpu_map); cpuid >= 0; cpuid = bit_next(cpu_map, cpuid)) {
			processor_t processor = processor_array[cpuid];

			if (processor->current_pri > lowest_priority) {
				continue;
			}

			if (processor->current_pri < lowest_priority) {
				lowest_priority = processor->current_pri;
				furthest_deadline = processor->deadline;
				fd_processor = processor;
				continue;
			}

			if (processor->deadline > furthest_deadline) {
				furthest_deadline = processor->deadline;
				fd_processor = processor;
			}
		}
	}

	return fd_processor;
}

bool
rt_clear_pending_spill(processor_t processor, int reason)
{
	processor_set_t pset = processor->processor_set;
	if (bit_clear_if_set(pset->rt_pending_spill_cpu_mask, processor->cpu_id)) {
		KTRC(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RT_SIGNAL_SPILL) | DBG_FUNC_END, processor->cpu_id, pset->rt_pending_spill_cpu_mask, 0, reason);
		return true;
	} else {
		return false;
	}
}

#pragma mark - Realtime Runqueues

#if DEBUG || SCHED_TEST_HARNESS
void
check_rt_runq_consistency(rt_queue_t rt_run_queue, thread_t thread)
{
	__assert_only bitmap_t *map = rt_run_queue->bitmap;

	uint64_t earliest_deadline = RT_DEADLINE_NONE;
	uint32_t constraint = RT_CONSTRAINT_NONE;
	int ed_index = NOPRI;
	int count = 0;
	bool found_thread = false;

	for (int pri = BASEPRI_RTQUEUES; pri <= MAXPRI; pri++) {
		int i = pri - BASEPRI_RTQUEUES;
		rt_queue_pri_t *rt_runq = &rt_run_queue->rt_queue_pri[i];
		queue_t queue = &rt_runq->pri_queue;
		queue_entry_t iter;
		int n = 0;
		uint64_t previous_deadline = 0;
		qe_foreach(iter, queue) {
			thread_t iter_thread = qe_element(iter, struct thread, runq_links);
			assert_thread_magic(iter_thread);
			if (iter_thread == thread) {
				found_thread = true;
			}
			assert(iter_thread->sched_pri == (i + BASEPRI_RTQUEUES));
			assert(iter_thread->realtime.deadline < RT_DEADLINE_NONE);
			assert(iter_thread->realtime.constraint < RT_CONSTRAINT_NONE);
			assert(previous_deadline <= iter_thread->realtime.deadline);
			n++;
			if (iter == queue_first(queue)) {
				assert(rt_runq->pri_earliest_deadline == iter_thread->realtime.deadline);
				assert(rt_runq->pri_constraint == iter_thread->realtime.constraint);
			}
			previous_deadline = iter_thread->realtime.deadline;
		}
		assert(n == rt_runq->pri_count);
		if (n == 0) {
			assert(bitmap_test(map, i) == false);
			assert(rt_runq->pri_earliest_deadline == RT_DEADLINE_NONE);
			assert(rt_runq->pri_constraint == RT_CONSTRAINT_NONE);
		} else {
			assert(bitmap_test(map, i) == true);
		}
		if (rt_runq->pri_earliest_deadline < earliest_deadline) {
			earliest_deadline = rt_runq->pri_earliest_deadline;
			constraint = rt_runq->pri_constraint;
			ed_index = i;
		}
		count += n;
	}
	assert(os_atomic_load_wide(&rt_run_queue->earliest_deadline, relaxed) == earliest_deadline);
	assert(os_atomic_load(&rt_run_queue->count, relaxed) == count);
	assert(os_atomic_load(&rt_run_queue->constraint, relaxed) == constraint);
	assert(os_atomic_load(&rt_run_queue->ed_index, relaxed) == ed_index);
	if (thread) {
		assert(found_thread);
	}
}
#endif /* DEBUG || SCHED_TEST_HARNESS */

static bool
rt_runq_enqueue(rt_queue_t rt_run_queue, thread_t thread, processor_t processor)
{
	int pri = thread->sched_pri;
	assert((pri >= BASEPRI_RTQUEUES) && (pri <= MAXPRI));
	int i = pri - BASEPRI_RTQUEUES;
	rt_queue_pri_t *rt_runq = &rt_run_queue->rt_queue_pri[i];
	bitmap_t *map = rt_run_queue->bitmap;

	bitmap_set(map, i);

	queue_t     queue       = &rt_runq->pri_queue;
	uint64_t    deadline    = thread->realtime.deadline;
	bool        preempt     = false;
	bool        earliest    = false;

	if (queue_empty(queue)) {
		enqueue_tail(queue, &thread->runq_links);
		preempt = true;
		earliest = true;
		rt_runq->pri_earliest_deadline = deadline;
		rt_runq->pri_constraint = thread->realtime.constraint;
	} else {
		/* Insert into rt_runq in thread deadline order */
		queue_entry_t iter;
		qe_foreach(iter, queue) {
			thread_t iter_thread = qe_element(iter, struct thread, runq_links);
			assert_thread_magic(iter_thread);

			if (deadline < iter_thread->realtime.deadline) {
				if (iter == queue_first(queue)) {
					preempt = true;
					earliest = true;
					rt_runq->pri_earliest_deadline = deadline;
					rt_runq->pri_constraint = thread->realtime.constraint;
				}
				insque(&thread->runq_links, queue_prev(iter));
				break;
			} else if (iter == queue_last(queue)) {
				enqueue_tail(queue, &thread->runq_links);
				break;
			}
		}
	}
	if (earliest && (deadline < os_atomic_load_wide(&rt_run_queue->earliest_deadline, relaxed))) {
		os_atomic_store_wide(&rt_run_queue->earliest_deadline, deadline, relaxed);
		os_atomic_store(&rt_run_queue->constraint, thread->realtime.constraint, relaxed);
		os_atomic_store(&rt_run_queue->ed_index, pri - BASEPRI_RTQUEUES, relaxed);
	}

	SCHED_STATS_RUNQ_CHANGE(&rt_run_queue->runq_stats, os_atomic_load(&rt_run_queue->count, relaxed));
	rt_runq->pri_count++;
	os_atomic_inc(&rt_run_queue->count, relaxed);

	thread_set_runq_locked(thread, processor);

	CHECK_RT_RUNQ_CONSISTENCY(rt_run_queue, thread);

	return preempt;
}

uint64_t
rt_runq_earliest_deadline(processor_set_t pset)
{
	return os_atomic_load_wide(&pset->rt_runq.earliest_deadline, relaxed);
}

/*
 *	rt_runq_insert:
 *
 *	Enqueue a thread for realtime execution.
 */
bool
rt_runq_insert(processor_t processor, processor_set_t pset, thread_t thread)
{
	pset_assert_locked(pset);

	bool preempt = rt_runq_enqueue(&pset->rt_runq, thread, processor);
	pset_update_rt_stealable_state(pset);

	return preempt;
}

int
rt_runq_count(processor_set_t pset)
{
	return os_atomic_load(&pset->rt_runq.count, relaxed);
}

int
rt_runq_priority(processor_set_t pset)
{
	pset_assert_locked(pset);
	rt_queue_t rt_run_queue = &pset->rt_runq;

	bitmap_t *map = rt_run_queue->bitmap;
	int i = bitmap_first(map, NRTQS);
	assert(i < NRTQS);

	if (i >= 0) {
		return i + BASEPRI_RTQUEUES;
	}

	return i;
}

bool
rt_runq_is_low_latency(processor_set_t pset)
{
	return os_atomic_load(&pset->rt_runq.constraint, relaxed) <= rt_constraint_threshold;
}

thread_t
rt_runq_dequeue(rt_queue_t rt_run_queue)
{
	bitmap_t *map = rt_run_queue->bitmap;
	int i = bitmap_first(map, NRTQS);
	assert((i >= 0) && (i < NRTQS));

	rt_queue_pri_t *rt_runq = &rt_run_queue->rt_queue_pri[i];

	if (!sched_rt_runq_strict_priority) {
		int ed_index = os_atomic_load(&rt_run_queue->ed_index, relaxed);
		if (ed_index != i) {
			assert((ed_index >= 0) && (ed_index < NRTQS));
			rt_queue_pri_t *ed_runq = &rt_run_queue->rt_queue_pri[ed_index];

			thread_t ed_thread = qe_queue_first(&ed_runq->pri_queue, struct thread, runq_links);
			thread_t hi_thread = qe_queue_first(&rt_runq->pri_queue, struct thread, runq_links);

			if (ed_thread->realtime.computation + hi_thread->realtime.computation + rt_deadline_epsilon < hi_thread->realtime.constraint) {
				/* choose the earliest deadline thread */
				rt_runq = ed_runq;
				i = ed_index;
			}
		}
	}

	assert(rt_runq->pri_count > 0);
	uint64_t earliest_deadline = RT_DEADLINE_NONE;
	uint32_t constraint = RT_CONSTRAINT_NONE;
	int ed_index = NOPRI;
	thread_t new_thread = qe_dequeue_head(&rt_runq->pri_queue, struct thread, runq_links);
	SCHED_STATS_RUNQ_CHANGE(&rt_run_queue->runq_stats, os_atomic_load(&rt_run_queue->count, relaxed));
	if (--rt_runq->pri_count > 0) {
		thread_t next_rt = qe_queue_first(&rt_runq->pri_queue, struct thread, runq_links);
		assert(next_rt != THREAD_NULL);
		earliest_deadline = next_rt->realtime.deadline;
		constraint = next_rt->realtime.constraint;
		ed_index = i;
	} else {
		bitmap_clear(map, i);
	}
	rt_runq->pri_earliest_deadline = earliest_deadline;
	rt_runq->pri_constraint = constraint;

	for (i = bitmap_first(map, NRTQS); i >= 0; i = bitmap_next(map, i)) {
		rt_runq = &rt_run_queue->rt_queue_pri[i];
		if (rt_runq->pri_earliest_deadline < earliest_deadline) {
			earliest_deadline = rt_runq->pri_earliest_deadline;
			constraint = rt_runq->pri_constraint;
			ed_index = i;
		}
	}
	os_atomic_store_wide(&rt_run_queue->earliest_deadline, earliest_deadline, relaxed);
	os_atomic_store(&rt_run_queue->constraint, constraint, relaxed);
	os_atomic_store(&rt_run_queue->ed_index, ed_index, relaxed);
	os_atomic_dec(&rt_run_queue->count, relaxed);

	thread_clear_runq(new_thread);

	CHECK_RT_RUNQ_CONSISTENCY(rt_run_queue, THREAD_NULL);

	return new_thread;
}

thread_t
rt_runq_first(rt_queue_t rt_run_queue)
{
	bitmap_t *map = rt_run_queue->bitmap;
	int i = bitmap_first(map, NRTQS);
	if (i < 0) {
		return THREAD_NULL;
	}
	rt_queue_pri_t *rt_runq = &rt_run_queue->rt_queue_pri[i];
	thread_t next_rt = qe_queue_first(&rt_runq->pri_queue, struct thread, runq_links);

	return next_rt;
}

void
rt_runq_remove(rt_queue_t rt_run_queue, thread_t thread)
{
	CHECK_RT_RUNQ_CONSISTENCY(rt_run_queue, thread);

	int pri = thread->sched_pri;
	assert((pri >= BASEPRI_RTQUEUES) && (pri <= MAXPRI));
	int i = pri - BASEPRI_RTQUEUES;
	rt_queue_pri_t *rt_runq = &rt_run_queue->rt_queue_pri[i];
	bitmap_t *map = rt_run_queue->bitmap;

	assert(rt_runq->pri_count > 0);
	uint64_t earliest_deadline = RT_DEADLINE_NONE;
	uint32_t constraint = RT_CONSTRAINT_NONE;
	int ed_index = NOPRI;
	remqueue(&thread->runq_links);
	SCHED_STATS_RUNQ_CHANGE(&rt_run_queue->runq_stats, os_atomic_load(&rt_run_queue->count, relaxed));
	if (--rt_runq->pri_count > 0) {
		thread_t next_rt = qe_queue_first(&rt_runq->pri_queue, struct thread, runq_links);
		earliest_deadline = next_rt->realtime.deadline;
		constraint = next_rt->realtime.constraint;
		ed_index = i;
	} else {
		bitmap_clear(map, i);
	}
	rt_runq->pri_earliest_deadline = earliest_deadline;
	rt_runq->pri_constraint = constraint;

	for (i = bitmap_first(map, NRTQS); i >= 0; i = bitmap_next(map, i)) {
		rt_runq = &rt_run_queue->rt_queue_pri[i];
		if (rt_runq->pri_earliest_deadline < earliest_deadline) {
			earliest_deadline = rt_runq->pri_earliest_deadline;
			constraint = rt_runq->pri_constraint;
			ed_index = i;
		}
	}
	os_atomic_store_wide(&rt_run_queue->earliest_deadline, earliest_deadline, relaxed);
	os_atomic_store(&rt_run_queue->constraint, constraint, relaxed);
	os_atomic_store(&rt_run_queue->ed_index, ed_index, relaxed);
	os_atomic_dec(&rt_run_queue->count, relaxed);

	thread_clear_runq_locked(thread);

	CHECK_RT_RUNQ_CONSISTENCY(rt_run_queue, THREAD_NULL);
}
