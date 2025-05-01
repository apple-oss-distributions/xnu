// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <stdint.h>
#include <stdbool.h>

/* Edge shares some of its implementation with the Clutch scheduler */
#include "sched_clutch_harness_impl.c"

/* Machine-layer mocking */

processor_t
current_processor(void)
{
	return cpus[_curr_cpu];
}

unsigned int
ml_get_die_id(unsigned int cluster_id)
{
	return curr_hw_topo.psets[cluster_id].die_id;
}

uint64_t
ml_cpu_signal_deferred_get_timer(void)
{
	/* Matching deferred_ipi_timer_ns */
	return 64 * NSEC_PER_USEC;
}

static test_cpu_type_t
cluster_type_to_test_cpu_type(cluster_type_t cluster_type)
{
	return (test_cpu_type_t)(cluster_type - 1);
}

static unsigned int cpu_count_for_type[TEST_CPU_TYPE_MAX] = { 0 };
static unsigned int recommended_cpu_count_for_type[TEST_CPU_TYPE_MAX] = { 0 };

unsigned int
ml_get_cpu_number_type(cluster_type_t cluster_type, bool logical, bool available)
{
	(void)logical;
	if (available) {
		return recommended_cpu_count_for_type[cluster_type_to_test_cpu_type(cluster_type)];
	} else {
		return cpu_count_for_type[cluster_type_to_test_cpu_type(cluster_type)];
	}
}

static unsigned int cluster_count_for_type[TEST_CPU_TYPE_MAX] = { 0 };

unsigned int
ml_get_cluster_number_type(cluster_type_t cluster_type)
{
	return cluster_count_for_type[cluster_type_to_test_cpu_type(cluster_type)];
}

int sched_amp_spill_deferred_ipi = 1;
int sched_amp_pcores_preempt_immediate_ipi = 1;

sched_ipi_type_t
sched_ipi_action(processor_t dst, thread_t thread, sched_ipi_event_t event)
{
	/* Forward to the policy-specific implementation */
	return SCHED(ipi_policy)(dst, thread, (dst->active_thread == NULL), event);
}

#define MAX_LOGGED_IPIS 10000
typedef struct {
	int cpu_id;
	sched_ipi_type_t ipi_type;
} logged_ipi_t;
static logged_ipi_t logged_ipis[MAX_LOGGED_IPIS];
static uint32_t curr_ipi_ind = 0;
static uint32_t expect_ipi_ind = 0;

void
sched_ipi_perform(processor_t dst, sched_ipi_type_t ipi)
{
	/* Record the IPI type and where we sent it */
	logged_ipis[curr_ipi_ind].cpu_id = dst->cpu_id;
	logged_ipis[curr_ipi_ind].ipi_type = ipi;
	curr_ipi_ind++;
}

sched_ipi_type_t
sched_ipi_policy(processor_t dst, thread_t thread,
    boolean_t dst_idle, sched_ipi_event_t event)
{
	(void)dst;
	(void)thread;
	(void)dst_idle;
	(void)event;
	/* For now, only send IPIs based on a policy-specific decision */
	return SCHED_IPI_NONE;
}

sched_ipi_type_t
sched_ipi_deferred_policy(processor_set_t pset,
    processor_t dst, thread_t thread, sched_ipi_event_t event)
{
	(void)pset;
	(void)dst;
	(void)thread;
	(void)event;
	return SCHED_IPI_NONE;
}

/* Implementation of sched_runqueue_harness.h interface */

static test_pset_t basic_amp_psets[2] = {
	{
		.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
		.num_cpus = 2,
		.die_id = 0,
	},
	{
		.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
		.num_cpus = 4,
		.die_id = 0,
	},
};
test_hw_topology_t basic_amp = {
	.psets = &basic_amp_psets[0],
	.num_psets = 2,
};

static test_pset_t dual_die_psets[6] = {
	{
		.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
		.num_cpus = 2,
		.die_id = 0,
	},
	{
		.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
		.num_cpus = 4,
		.die_id = 0,
	},
	{
		.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
		.num_cpus = 4,
		.die_id = 0,
	},
	{
		.cpu_type = TEST_CPU_TYPE_EFFICIENCY,
		.num_cpus = 2,
		.die_id = 1,
	},
	{
		.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
		.num_cpus = 4,
		.die_id = 1,
	},
	{
		.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
		.num_cpus = 4,
		.die_id = 1,
	},
};
test_hw_topology_t dual_die = {
	.psets = &dual_die_psets[0],
	.num_psets = 6,
};

#define MAX_NODES 2
static struct pset_node node_array[MAX_NODES];

static void
edge_impl_set_cluster_type(processor_set_t pset, test_cpu_type_t type)
{
	switch (type) {
	case TEST_CPU_TYPE_EFFICIENCY:
		pset->pset_cluster_type = PSET_AMP_E;
		pset->node = &node_array[0];
		break;
	case TEST_CPU_TYPE_PERFORMANCE:
		pset->pset_cluster_type = PSET_AMP_P;
		pset->node = &node_array[1];
		break;
	default:
		assert(false);
		break;
	}
}

static void
edge_impl_init_runqueues(void)
{
	assert(curr_hw_topo.num_psets != 0);
	clutch_impl_init_topology(curr_hw_topo);
	sched_edge_init();
	node_array[0].pset_cluster_type = PSET_AMP_E;
	os_atomic_store(&node_array[0].pset_recommended_map, 0, relaxed);
	atomic_bit_set(&node_array[0].pset_recommended_map, 0, memory_order_relaxed);
	node_array[1].pset_cluster_type = PSET_AMP_P;
	os_atomic_store(&node_array[1].pset_recommended_map, 0, relaxed);
	atomic_bit_set(&node_array[1].pset_recommended_map, 1, memory_order_relaxed);
	for (int i = 0; i < curr_hw_topo.num_psets; i++) {
		pset_array[i] = psets[i];
		edge_impl_set_cluster_type(psets[i], curr_hw_topo.psets[i].cpu_type);
		sched_edge_pset_init(psets[i]);
		bzero(&psets[i]->pset_load_average, sizeof(psets[i]->pset_load_average));
		bzero(&psets[i]->pset_execution_time, sizeof(psets[i]->pset_execution_time));
		assert(psets[i]->cpu_bitmask != 0);
		psets[i]->foreign_psets[0] = 0;
		psets[i]->native_psets[0] = 0;
		psets[i]->local_psets[0] = 0;
		psets[i]->remote_psets[0] = 0;
		cluster_count_for_type[curr_hw_topo.psets[i].cpu_type]++;
		cpu_count_for_type[curr_hw_topo.psets[i].cpu_type] += curr_hw_topo.psets[i].num_cpus;
		recommended_cpu_count_for_type[curr_hw_topo.psets[i].cpu_type] +=
		    curr_hw_topo.psets[i].num_cpus;
	}
	for (unsigned int j = 0; j < processor_avail_count; j++) {
		processor_array[j] = cpus[j];
		sched_clutch_processor_init(cpus[j]);
	}
	sched_edge_cpu_init_completed();
	increment_mock_time(100);
	clutch_impl_init_params();
	clutch_impl_init_tracepoints();
}

void
impl_init_runqueue(void)
{
	assert(curr_hw_topo.num_psets == 0);
	curr_hw_topo = single_core;
	edge_impl_init_runqueues();
}

void
impl_init_migration_harness(test_hw_topology_t hw_topology)
{
	assert(curr_hw_topo.num_psets == 0);
	curr_hw_topo = hw_topology;
	edge_impl_init_runqueues();
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
impl_set_thread_sched_mode(test_thread_t thread, int mode)
{
	clutch_impl_set_thread_sched_mode(thread, mode);
}

void
impl_set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	_curr_cpu = cpu_id;
	clutch_impl_set_thread_processor_bound(thread, cpu_id);
}

void
impl_set_thread_cluster_bound(test_thread_t thread, int cluster_id)
{
	/* Should not be already enqueued */
	assert(thread_get_runq_locked((thread_t)thread) == NULL);
	((thread_t)thread)->th_bound_cluster_id = cluster_id;
}

void
impl_cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	_curr_cpu = cpu_id;
	clutch_impl_cpu_set_thread_current(cpu_id, thread);
}

void
impl_cpu_clear_thread_current(int cpu_id)
{
	_curr_cpu = cpu_id;
	clutch_impl_cpu_clear_thread_current(cpu_id);
}

void
impl_cpu_enqueue_thread(int cpu_id, test_thread_t thread)
{
	_curr_cpu = cpu_id;
	sched_clutch_processor_enqueue(cpus[cpu_id], thread, SCHED_TAILQ);
}

test_thread_t
impl_cpu_dequeue_thread(int cpu_id)
{
	_curr_cpu = cpu_id;
	return sched_clutch_choose_thread(cpus[cpu_id], MINPRI, NULL, 0);
}

test_thread_t
impl_cpu_dequeue_thread_compare_current(int cpu_id)
{
	_curr_cpu = cpu_id;
	assert(cpus[cpu_id]->active_thread != NULL);
	return sched_clutch_choose_thread(cpus[cpu_id], MINPRI, cpus[cpu_id]->active_thread, 0);
}

bool
impl_processor_csw_check(int cpu_id)
{
	_curr_cpu = cpu_id;
	assert(cpus[cpu_id]->active_thread != NULL);
	ast_t preempt_ast = sched_clutch_processor_csw_check(cpus[cpu_id]);
	return preempt_ast & AST_PREEMPT;
}

void
impl_pop_tracepoint(uint64_t *clutch_trace_code, uint64_t *arg1, uint64_t *arg2,
    uint64_t *arg3, uint64_t *arg4)
{
	clutch_impl_pop_tracepoint(clutch_trace_code, arg1, arg2, arg3, arg4);
}

int
impl_choose_pset_for_thread(test_thread_t thread)
{
	/* Begins search starting from current pset */
	processor_t chosen_processor = sched_edge_choose_processor(
		current_processor()->processor_set, current_processor(), (thread_t)thread);
	return chosen_processor->processor_set->pset_id;
}

void
impl_set_current_processor(int cpu_id)
{
	_curr_cpu = cpu_id;
}

void
impl_set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, int cluster_id)
{
	assert(sched_bucket > 0 && sched_bucket < TH_BUCKET_SCHED_MAX);
	sched_clutch_t clutch = sched_clutch_for_thread_group(tg);
	bitmap_t modify_bitmap[BITMAP_LEN(TH_BUCKET_SCHED_MAX)] = {0};
	bitmap_set(modify_bitmap, sched_bucket);
	uint32_t tg_bucket_preferred_cluster[TH_BUCKET_SCHED_MAX] = {0};
	tg_bucket_preferred_cluster[sched_bucket] = cluster_id;
	sched_edge_update_preferred_cluster(clutch, modify_bitmap, tg_bucket_preferred_cluster);
}

void
impl_set_pset_load_avg(int cluster_id, int QoS, uint64_t load_avg)
{
	assert(QoS > 0 && QoS < TH_BUCKET_SCHED_MAX);
	pset_array[cluster_id]->pset_load_average[QoS] = load_avg;
}

void
edge_set_thread_shared_rsrc(test_thread_t thread, bool native_first)
{
	int shared_rsrc_type = native_first ? CLUSTER_SHARED_RSRC_TYPE_NATIVE_FIRST :
	    CLUSTER_SHARED_RSRC_TYPE_RR;
	((thread_t)thread)->th_shared_rsrc_heavy_user[shared_rsrc_type] = true;
}

void
impl_set_pset_derecommended(int cluster_id)
{
	processor_set_t pset = pset_array[cluster_id];
	pset->recommended_bitmask = 0;
	atomic_bit_clear(&pset->node->pset_recommended_map, cluster_id, memory_order_relaxed);
	recommended_cpu_count_for_type[cluster_type_to_test_cpu_type(pset->pset_type)] -=
	    bit_count(pset->cpu_bitmask);
}

void
impl_set_pset_recommended(int cluster_id)
{
	processor_set_t pset = pset_array[cluster_id];
	pset->recommended_bitmask = pset->cpu_bitmask;
	atomic_bit_set(&pset->node->pset_recommended_map, cluster_id, memory_order_relaxed);
	recommended_cpu_count_for_type[cluster_type_to_test_cpu_type(pset->pset_type)] +=
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
	assert(cpus[cpu_id]->active_thread != NULL);
	return sched_edge_thread_should_yield(cpus[cpu_id], cpus[cpu_id]->active_thread);
}

void
impl_send_ipi(int cpu_id, test_thread_t thread, test_ipi_event_t event)
{
	sched_ipi_type_t triggered_ipi = sched_ipi_action(cpus[cpu_id],
	    (thread_t)thread, (sched_ipi_event_t)event);
	sched_ipi_perform(cpus[cpu_id], triggered_ipi);
}

uint32_t
impl_qos_max_parallelism(int qos, uint64_t options)
{
	return sched_edge_qos_max_parallelism(qos, options);
}
