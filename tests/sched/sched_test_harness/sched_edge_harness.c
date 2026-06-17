// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <stdint.h>
#include <stdbool.h>

/* Edge shares some of its implementation with the Clutch scheduler */
#include "sched_clutch_harness_impl.c"

/* Machine-layer mocking */

unsigned int
ml_get_die_id(unsigned int cluster_id)
{
	return topology_info.clusters[cluster_id].die_id;
}

uint64_t
ml_cpu_signal_deferred_get_timer(void)
{
	/* Matching deferred_ipi_timer_ns */
	return 64 * NSEC_PER_USEC;
}

static unsigned int cpu_count_for_type[MAX_PSET_TYPES] = { 0 };
static unsigned int recommended_cpu_count_for_type[MAX_PSET_TYPES] = { 0 };

unsigned int
ml_get_cpu_number_type(cluster_type_t cluster_type, bool logical, bool available)
{
	(void)logical;
	if (available) {
		return recommended_cpu_count_for_type[cluster_type_to_pset_type(cluster_type)];
	} else {
		return cpu_count_for_type[cluster_type_to_pset_type(cluster_type)];
	}
}

int sched_amp_spill_deferred_ipi = 1;
int sched_amp_pcores_preempt_immediate_ipi = 1;

/* Implementation of sched_runqueue_harness.h interface */

struct test_hw_topology basic_amp = {
	.num_cpus = 6,
	.boot_cpu = 0,
	.cpu_ranges = {
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 0,
			.die_id = 0,
			.first_cpu_id = 0,
			.num_cpus = 2,
		},
		{
			.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
			.cluster_id = 1,
			.die_id = 0,
			.first_cpu_id = 2,
			.num_cpus = 4,
		}
	}
};

struct test_hw_topology dual_die = {
	.num_cpus = 20,
	.boot_cpu = 2,
	.cpu_ranges = {
		{
			.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
			.cluster_id = 0,
			.die_id = 0,
			.first_cpu_id = 0,
			.num_cpus = 2,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 1,
			.die_id = 0,
			.first_cpu_id = 2,
			.num_cpus = 4,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 2,
			.die_id = 0,
			.first_cpu_id = 6,
			.num_cpus = 4,
		},
		{
			.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
			.cluster_id = 3,
			.die_id = 1,
			.first_cpu_id = 10,
			.num_cpus = 2,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 4,
			.die_id = 1,
			.first_cpu_id = 12,
			.num_cpus = 4,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 5,
			.die_id = 1,
			.first_cpu_id = 16,
			.num_cpus = 4,
		},
	}
};

struct test_hw_topology two_of_each = {
	.num_cpus = 8,
	.boot_cpu = 0,
	.cpu_ranges = {
		{
			.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
			.cluster_id = 0,
			.die_id = 0,
			.first_cpu_id = 0,
			.num_cpus = 2,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 1,
			.die_id = 0,
			.first_cpu_id = 2,
			.num_cpus = 2,
		},
		{
			.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
			.cluster_id = 2,
			.die_id = 1,
			.first_cpu_id = 4,
			.num_cpus = 2,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 3,
			.die_id = 1,
			.first_cpu_id = 6,
			.num_cpus = 2,
		},
	}
};

#if HAS_MCORE
struct test_hw_topology sotra_chop = {
	.num_cpus = 18,
	.boot_cpu = 6,
	.cpu_ranges = {
		{
			.cpu_type = TEST_CPU_TYPE_MP_OPTIMIZED,
			.cluster_id = 0,
			.die_id = 0,
			.first_cpu_id = 0,
			.num_cpus = 6,
		},
		{
			.cpu_type = TEST_CPU_TYPE_MP_OPTIMIZED,
			.cluster_id = 1,
			.die_id = 0,
			.first_cpu_id = 6,
			.num_cpus = 6,
		},
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 2,
			.die_id = 0,
			.first_cpu_id = 12,
			.num_cpus = 6,
		},
	}
};


#endif /* HAS_MCORE */

#if HAS_MCORE
#define MAX_NODES 3
#else /* !HAS_MCORE */
#define MAX_NODES 2
#endif /* !HAS_MCORE */

const unsigned int EDGE_REBAL_RUNNABLE = MACH_SCHED_EDGE_REBAL_RUNNABLE;
const unsigned int EDGE_REBAL_RUNNING = MACH_SCHED_EDGE_REBAL_RUNNING;
const unsigned int EDGE_STEAL = MACH_SCHED_EDGE_STEAL;
const unsigned int EDGE_SHOULD_YIELD = MACH_SCHED_EDGE_SHOULD_YIELD;

void
edge_impl_init_tracepoints(void)
{
	clutch_impl_add_logged_trace_code(EDGE_REBAL_RUNNABLE);
	clutch_impl_add_logged_trace_code(EDGE_REBAL_RUNNING);
	clutch_impl_add_logged_trace_code(EDGE_STEAL);
	clutch_impl_add_logged_trace_code(EDGE_SHOULD_YIELD);
}

static test_sched_topology_t
edge_impl_init_runqueues(test_hw_topology_t hw_topology)
{
	test_sched_topology_t sched_topo = clutch_impl_init_topology(hw_topology);
	for (int i = 0; i < sched_num_psets; i++) {
		pset_type_t pset_type = pset_array[i]->pset_type;
		uint num_cpus = bit_count(pset_array[i]->cpu_bitmask);
		cpu_count_for_type[pset_type] += num_cpus;
		recommended_cpu_count_for_type[pset_type] += num_cpus;
	}
	increment_mock_time(100);
	clutch_impl_init_params();
	clutch_impl_init_tracepoints();
	edge_impl_init_tracepoints();
	return sched_topo;
}

void
impl_init_runqueue(void)
{
	edge_impl_init_runqueues(&single_core);
}

test_sched_topology_t
impl_init_migration_harness(test_hw_topology_t hw_topology)
{
	return edge_impl_init_runqueues(hw_topology);
}

struct thread_group *
impl_create_tg(int interactivity_score)
{
	return clutch_impl_create_tg(interactivity_score);
}

test_thread_t
impl_create_thread(int root_bucket, struct thread_group *tg, int pri)
{
	return clutch_impl_create_thread(root_bucket, tg, pri);
}

void
impl_set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	_curr_cpu = cpu_id;
	clutch_impl_set_thread_processor_bound(thread, cpu_id);
}

void
impl_set_thread_pset_bound(test_thread_t thread, pset_id_t pset_id)
{
	/* Should not be already enqueued */
	assert(thread_get_runq_locked((thread_t)thread) == NULL);
	((thread_t)thread)->th_bound_pset_id = pset_id;
}

void
impl_cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	_curr_cpu = cpu_id;
	processor_set_t pset = processor_array[cpu_id]->processor_set;
	clutch_impl_cpu_set_thread_current(cpu_id, thread);

	/* Send followup IPIs for realtime, as needed */
	bit_clear(pset->rt_pending_spill_cpu_mask, cpu_id);
	processor_t next_rt_processor = PROCESSOR_NULL;
	sched_ipi_type_t next_rt_ipi_type = SCHED_IPI_NONE;
	if (rt_pset_has_stealable_threads(pset)) {
		rt_choose_next_processor_for_spill_IPI(pset, processor_array[cpu_id], &next_rt_processor, &next_rt_ipi_type);
	} else if (rt_pset_needs_a_followup_IPI(pset)) {
		rt_choose_next_processor_for_followup_IPI(pset, processor_array[cpu_id], &next_rt_processor, &next_rt_ipi_type);
	}
	if (next_rt_processor != PROCESSOR_NULL) {
		sched_ipi_perform(next_rt_processor, next_rt_ipi_type);
	}
}

test_thread_t
impl_cpu_clear_thread_current(int cpu_id)
{
	_curr_cpu = cpu_id;
	test_thread_t thread = clutch_impl_cpu_clear_thread_current(cpu_id);
	pset_update_processor_state(processor_array[cpu_id]->processor_set, processor_array[cpu_id], PROCESSOR_IDLE);
	os_atomic_store(&processor_array[cpu_id]->processor_set->cpu_running_buckets[cpu_id], TH_BUCKET_SCHED_MAX, relaxed);
	sched_edge_stir_the_pot_clear_registry_entry();
	return thread;
}

void
impl_cpu_enqueue_thread(int cpu_id, test_thread_t thread)
{
	_curr_cpu = cpu_id;
	if (((thread_t) thread)->sched_pri >= BASEPRI_RTQUEUES) {
		rt_runq_insert(processor_array[cpu_id], processor_array[cpu_id]->processor_set, (thread_t) thread);
	} else {
		sched_clutch_processor_enqueue(processor_array[cpu_id], (thread_t) thread, SCHED_TAILQ);
	}
	SCHED(update_pset_load_average)(processor_array[cpu_id]->processor_set, 0);
}

test_thread_t
impl_cpu_dequeue_thread(int cpu_id)
{
	_curr_cpu = cpu_id;
	test_thread_t chosen_thread = sched_rt_choose_thread(processor_array[cpu_id]);
	if (chosen_thread != THREAD_NULL) {
		return chosen_thread;
	}
	/* No realtime threads. */
	return sched_clutch_choose_thread(processor_array[cpu_id], MINPRI, NULL, 0);
}

test_thread_t
impl_cpu_dequeue_thread_compare_current(int cpu_id)
{
	_curr_cpu = cpu_id;
	assert(processor_array[cpu_id]->active_thread != NULL);
	processor_set_t pset = processor_array[cpu_id]->processor_set;
	if (rt_runq_count(pset) > 0) {
		return impl_dequeue_realtime_thread(pset);
	} else {
		return sched_clutch_choose_thread(processor_array[cpu_id], MINPRI, processor_array[cpu_id]->active_thread, 0);
	}
}

bool
impl_processor_csw_check(int cpu_id)
{
	_curr_cpu = cpu_id;
	assert(processor_array[cpu_id]->active_thread != NULL);
	ast_t preempt_ast = sched_clutch_processor_csw_check(processor_array[cpu_id]);
	return preempt_ast & AST_PREEMPT;
}

void
impl_pop_tracepoint(uint64_t clutch_trace_code, uint64_t *arg1, uint64_t *arg2,
    uint64_t *arg3, uint64_t *arg4)
{
	clutch_impl_pop_tracepoint(clutch_trace_code, arg1, arg2, arg3, arg4);
}

int
impl_choose_pset_for_thread(test_thread_t thread, test_sched_options_t options)
{
	sched_options_t stable_options = (sched_options_t)options;
	/* Begins search starting from current pset */
	processor_t chosen_processor = sched_edge_choose_processor(
		current_processor()->processor_set, current_processor(), (thread_t)thread, &stable_options);
	return chosen_processor->processor_set->pset_id;
}

bool
impl_thread_avoid_processor(test_thread_t thread, int cpu_id, bool quantum_expired)
{
	_curr_cpu = cpu_id;
	return sched_edge_thread_avoid_processor(processor_array[cpu_id], (thread_t)thread, quantum_expired ? AST_QUANTUM : AST_NONE);
}

void
impl_cpu_expire_quantum(int cpu_id)
{
	_curr_cpu = cpu_id;
	sched_edge_quantum_expire(processor_array[cpu_id]->active_thread);
	/* Simulate other side effects of thread_quantum_expire() */
	processor_array[cpu_id]->first_timeslice = FALSE;
	processor_state_update_from_running_thread(processor_array[cpu_id],
	    processor_array[cpu_id]->active_thread, true);
}

test_thread_t
impl_steal_thread(int cpu_id)
{
	_curr_cpu = cpu_id;
	return sched_edge_processor_idle(pset_array[cpu_id_to_pset_id(cpu_id)]);
}

bool
impl_processor_balance(int cpu_id)
{
	_curr_cpu = cpu_id;
	return sched_edge_balance(processor_array[cpu_id], pset_array[cpu_id_to_pset_id(cpu_id)]);
}

void
impl_cpu_clear_pending_ast_bits(int cpu_id)
{
	clear_pending_AST_bits(pset_array[cpu_id_to_pset_id(cpu_id)], processor_array[cpu_id], 0);
}

void
impl_set_current_processor(int cpu_id)
{
	_curr_cpu = cpu_id;
}

void
impl_set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, pset_id_t pset_id)
{
	assert(sched_bucket < TH_BUCKET_SCHED_MAX);
	sched_clutch_t clutch = sched_clutch_for_thread_group(tg);
	bitmap_t modify_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)] = {0};
	bitmap_set(modify_bitmap, sched_bucket);
	pset_id_t tg_bucket_preferred_pset[TH_BUCKET_SCHED_MAX] = {0};
	tg_bucket_preferred_pset[sched_bucket] = pset_id;
	sched_edge_update_preferred_pset(clutch, modify_bitmap, tg_bucket_preferred_pset);
}

void
impl_set_pset_load_avg(int pset_id, int QoS, uint32_t load_avg)
{
	assert(QoS >= 0 && QoS < TH_BUCKET_SCHED_MAX);
	pset_array[pset_id]->pset_load_average[QoS] = load_avg;
}

void
edge_set_thread_shared_rsrc(test_thread_t thread, bool native_first)
{
	int shared_rsrc_type = native_first ? CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST :
	    CLUSTER_SHARED_RSRC_TYPE_RR;
	((thread_t)thread)->th_shared_rsrc_heavy_user[shared_rsrc_type] = true;
}

void
impl_set_pset_derecommended(int pset_id)
{
	processor_set_t pset = pset_array[pset_id];
	pset->recommended_bitmask = 0;
	atomic_bit_clear(&pset->node->pset_recommended_map, pset_id, memory_order_relaxed);
	recommended_cpu_count_for_type[pset->pset_type] -=
	    bit_count(pset->cpu_bitmask);
}

void
impl_set_pset_recommended(int pset_id)
{
	processor_set_t pset = pset_array[pset_id];
	pset->recommended_bitmask = pset->cpu_bitmask;
	atomic_bit_set(&pset->node->pset_recommended_map, pset_id, memory_order_relaxed);
	recommended_cpu_count_for_type[pset->pset_type] +=
	    bit_count(pset->cpu_bitmask);
}

void
impl_pop_ipi(int *cpu_id, test_ipi_type_t *ipi_type)
{
	assert(expect_ipi_ind < curr_ipi_ind);
	*cpu_id = logged_ipis[expect_ipi_ind].cpu_id;
	*ipi_type = (test_ipi_type_t)logged_ipis[expect_ipi_ind].ipi_type;
	expect_ipi_ind++;
}

bool
impl_thread_should_yield(int cpu_id)
{
	_curr_cpu = cpu_id;
	assert(processor_array[cpu_id]->active_thread != NULL);
	return sched_edge_thread_should_yield(processor_array[cpu_id], processor_array[cpu_id]->active_thread);
}

void
impl_send_ipi(int cpu_id, test_thread_t thread, test_ipi_event_t event)
{
	sched_ipi_type_t triggered_ipi = sched_ipi_action(processor_array[cpu_id],
	    (thread_t)thread, (sched_ipi_event_t)event);
	sched_ipi_perform(processor_array[cpu_id], triggered_ipi);
}

int
rt_pset_spill_search_order_at_offset(int src_pset_id, int offset)
{
	return pset_array[src_pset_id]->sched_rt_spill_search_order.spso_search_order[offset];
}

void
rt_pset_recompute_spill_order(int src_pset_id)
{
	sched_rt_config_pset_push(pset_array[src_pset_id]);
}

uint32_t
impl_qos_max_parallelism(int qos, uint64_t options)
{
	return sched_edge_qos_max_parallelism(qos, options);
}

int *
impl_iterate_pset_search_order(int src_pset_id, uint64_t candidate_map, int sched_bucket)
{
	int *psets = (int *)calloc(sched_num_psets, sizeof(int));
	for (int i = 0; i < sched_num_psets; i++) {
		psets[i] = -1;
	}
	sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
	int ind = 0;
	processor_set_t starting_pset = pset_array[src_pset_id];
	while (sched_iterate_psets_ordered(starting_pset,
	    &starting_pset->spill_search_order[sched_bucket], candidate_map, &istate)) {
		psets[ind++] = istate.spis_pset_id;
	}
	return psets;
}

test_thread_t
impl_rt_choose_thread(int cpu_id)
{
	return sched_rt_choose_thread(processor_array[cpu_id]);
}

int
pset_cpu_count_for_id(int pset_id)
{
	return pset_array[pset_id]->cpu_set_count;
}

test_cpu_type_t
pset_cpu_type_for_id(pset_id_t pset_id)
{
	return get_sched_topology()->psets[pset_id].cpu_type;
}

int
pset_id_for_cluster_id(int cluster_id)
{
	return cluster_id_to_pset_id[cluster_id];
}
