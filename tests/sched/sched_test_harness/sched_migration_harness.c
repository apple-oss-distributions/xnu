// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <stdlib.h>
#include <stdio.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "sched_migration_harness.h"
#include "sched_harness_impl.h"

void
init_migration_harness(test_hw_topology_t hw_topology)
{
	/* Sets up _log and ATEND to close it */
	init_harness_logging(T_NAME);
	assert(_log != NULL);

	fprintf(_log, "\tinitializing migration harness\n");
	set_hw_topology(hw_topology);
	impl_init_migration_harness(hw_topology);
}

void
set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, int cluster_id)
{
	fprintf(_log, "\tset TG %p bucket %d recommended for pset %d\n", (void *)tg, sched_bucket, cluster_id);
	impl_set_tg_sched_bucket_preferred_pset(tg, sched_bucket, cluster_id);
}

void
set_thread_cluster_bound(test_thread_t thread, int cluster_id)
{
	fprintf(_log, "\tset thread %p bound to cluster %d\n", (void *)thread, cluster_id);
	impl_set_thread_cluster_bound(thread, cluster_id);
}

bool
choose_pset_for_thread_expect(test_thread_t thread, int expected_cluster_id)
{
	int chosen_pset_id = impl_choose_pset_for_thread(thread);
	fprintf(_log, "%s: for thread %p we chose pset_id %d, expecting %d\n", chosen_pset_id == expected_cluster_id ?
	    "PASS" : "FAIL", (void *)thread, chosen_pset_id, expected_cluster_id);
	return chosen_pset_id == expected_cluster_id;
}

void
set_current_processor(int cpu_id)
{
	fprintf(_log, "\tset current_processor() to cpu id %d\n", cpu_id);
	impl_set_current_processor(cpu_id);
}

void
set_pset_load_avg(int cluster_id, int QoS, uint64_t load_avg)
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
