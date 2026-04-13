// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <stdlib.h>
#include <stdio.h>

#include <kern/kern_types.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "sched_migration_harness.h"
#include "sched_harness_impl.h"

test_sched_topology_t
init_migration_harness(test_hw_topology_t hw_topology)
{
	/* Sets up _log and ATEND to close it */
	init_harness_logging(T_NAME);
	assert(_log != NULL);
	assert(hw_topology->num_cpus > 0);

	fprintf(_log, "\tinitializing migration harness\n");
	return impl_init_migration_harness(hw_topology);
}

void
set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, pset_id_t pset_id)
{
	fprintf(_log, "\tset TG %p bucket %d recommended for pset %u\n", (void *)tg, sched_bucket, pset_id);
	impl_set_tg_sched_bucket_preferred_pset(tg, sched_bucket, pset_id);
}

void
set_thread_pset_bound(test_thread_t thread, pset_id_t pset_id)
{
	fprintf(_log, "\tset thread %p bound to pset %u\n", (void *)thread, pset_id);
	impl_set_thread_pset_bound(thread, pset_id);
}

int
choose_pset_for_thread(test_thread_t thread)
{
	return choose_pset_for_thread_options(thread, TEST_SCHED_NONE);
}

int
choose_pset_for_thread_options(test_thread_t thread, test_sched_options_t options)
{
	int chosen_pset_id = impl_choose_pset_for_thread(thread, options);
	fprintf(_log, "for thread %p, with options (%x), we chose pset_id %d\n",
	    (void *)thread, (uint32_t)options, chosen_pset_id);
	return chosen_pset_id;
}

bool
choose_pset_for_thread_expect(test_thread_t thread, int expected_cluster_id)
{
	int chosen_pset_id = choose_pset_for_thread(thread);
	fprintf(_log, "%s: for thread %p we chose pset_id %d, expecting %d\n", chosen_pset_id == expected_cluster_id ?
	    "PASS" : "FAIL", (void *)thread, chosen_pset_id, expected_cluster_id);
	return chosen_pset_id == expected_cluster_id;
}

bool
thread_avoid_processor_expect(test_thread_t thread, int cpu_id, bool quantum_expiry, bool avoid_expected)
{
	bool avoiding = impl_thread_avoid_processor(thread, cpu_id, quantum_expiry);
	fprintf(_log, "%s: thread %p would avoid cpu %d? %d, expecting to avoid? %d\n", avoiding == avoid_expected ?
	    "PASS" : "FAIL", (void *)thread, cpu_id, avoiding, avoid_expected);
	return avoiding == avoid_expected;
}

void
cpu_expire_quantum(int cpu_id)
{
	impl_cpu_expire_quantum(cpu_id);
	fprintf(_log, "cpu %d expired quantum\n", cpu_id);
}

test_thread_t
cpu_steal_thread(int cpu_id)
{
	test_thread_t stolen_thread = impl_steal_thread(cpu_id);
	fprintf(_log, "on cpu %d, stole thread %p\n", cpu_id, (void *)stolen_thread);
	return stolen_thread;
}

bool
cpu_processor_balance(int cpu_id)
{
	bool doing_rebalance = impl_processor_balance(cpu_id);
	fprintf(_log, "on cpu %d, doing rebalance? %d\n", cpu_id, doing_rebalance);
	return doing_rebalance;
}

void
cpu_clear_pending_ast_bits(int cpu_id)
{
	fprintf(_log, "on cpu %d cleared pending AST bits\n", cpu_id);
	impl_cpu_clear_pending_ast_bits(cpu_id);
}

void
set_current_processor(int cpu_id)
{
	fprintf(_log, "\tset current_processor() to cpu id %d\n", cpu_id);
	impl_set_current_processor(cpu_id);
}

void
set_pset_load_avg(int cluster_id, int QoS, uint32_t load_avg)
{
	fprintf(_log, "\tset pset_load_avg for cluster %d QoS %d to %llu\n", cluster_id, QoS, load_avg);
	impl_set_pset_load_avg(cluster_id, QoS, load_avg);
}

void
set_pset_recommended(int cluster_id)
{
	fprintf(_log, "\tset cluster %d as recommended\n", cluster_id);
	impl_set_pset_recommended(cluster_id);
}

void
set_pset_derecommended(int cluster_id)
{
	fprintf(_log, "\tset cluster %d as derecommended\n", cluster_id);
	impl_set_pset_derecommended(cluster_id);
}

bool
ipi_expect(int cpu_id, test_ipi_type_t ipi_type)
{
	int found_cpu_id = -1;
	test_ipi_type_t found_ipi_type = TEST_IPI_NONE;
	impl_pop_ipi(&found_cpu_id, &found_ipi_type);
	bool pass = (cpu_id == found_cpu_id) && (ipi_type == found_ipi_type);
	fprintf(_log, "%s: expected ipi to cpu %d type %u, found ipi to cpu %d type %u\n",
	    pass ? "PASS": "FAIL", cpu_id, ipi_type, found_cpu_id, found_ipi_type);
	return pass;
}

bool
cpu_check_should_yield(int cpu_id, bool yield_expected)
{
	bool yielding = impl_thread_should_yield(cpu_id);
	fprintf(_log, "%s: would yield on cpu %d? %d, expecting to yield? %d\n",
	    yielding == yield_expected ? "PASS" : "FAIL", cpu_id, yielding, yield_expected);
	return yielding == yield_expected;
}

void
cpu_send_ipi_for_thread(int cpu_id, test_thread_t thread, test_ipi_event_t event)
{
	fprintf(_log, "requesting IPI to cpu %d thread %p event %u\n", cpu_id,
	    (void *)thread, event);
	impl_send_ipi(cpu_id, thread, event);
}

bool
max_parallelism_expect(int qos, uint64_t options, uint32_t expected_parallelism)
{
	uint32_t found_parallelism = impl_qos_max_parallelism(qos, options);
	fprintf(_log, "expected parallelism %u for QoS %d options %llx, found parallelism %u\n",
	    expected_parallelism, qos, options, found_parallelism);
	return found_parallelism == expected_parallelism;
}

int
iterate_pset_search_order_expect(int src_pset_id, uint64_t candidate_map, int sched_bucket,
    int *expected_pset_ids, int num_psets)
{
	int *search_order = impl_iterate_pset_search_order(src_pset_id, candidate_map, sched_bucket);
	fprintf(_log, "for src pset %d candidate map %llx bucket %d, we found search order:\t",
	    src_pset_id, candidate_map, sched_bucket);
	int first_failure_ind = -1;
	for (int i = 0; (i < num_psets) && (search_order[i] != -1); i++) {
		fprintf(_log, "%2d ", search_order[i]);
		if ((expected_pset_ids[i] != search_order[i]) && (first_failure_ind == -1)) {
			first_failure_ind = i;
		}
	}
	fprintf(_log, "\n\t%s: expected search order:\t", (first_failure_ind == -1) ? "PASS" : "FAIL");
	for (int i = 0; i < num_psets; i++) {
		fprintf(_log, "%2d ", expected_pset_ids[i]);
	}
	fprintf(_log, "\n");
	return first_failure_ind;
}
