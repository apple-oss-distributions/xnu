// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include "sched_test_harness/sched_policy_darwintest.h"
#include "sched_test_harness/sched_edge_harness.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_RUN_CONCURRENTLY(true),
    T_META_OWNER("emily_peterson"));

SCHED_POLICY_T_DECL(migration_cluster_bound,
    "Verify that cluster-bound threads always choose the bound "
    "cluster except when its derecommended")
{
	int ret;
	init_migration_harness(dual_die);
	struct thread_group *tg = create_tg(0);
	test_thread_t threads[dual_die.num_psets];
	int idle_load = 0;
	int low_load = 100000;
	int high_load = 10000000;
	for (int i = 0; i < dual_die.num_psets; i++) {
		threads[i] = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
		set_thread_cluster_bound(threads[i], i);
		set_pset_load_avg(i, TH_BUCKET_SHARE_DF, low_load);
	}
	for (int i = 0; i < dual_die.num_psets; i++) {
		set_current_processor(cluster_id_to_cpu_id(i));
		for (int j = 0; j < dual_die.num_psets; j++) {
			/* Add extra load to the bound cluster, so we're definitely not just idle short-circuiting */
			set_pset_load_avg(j, TH_BUCKET_SHARE_DF, high_load);
			ret = choose_pset_for_thread_expect(threads[j], j);
			T_QUIET; T_EXPECT_TRUE(ret, "Expecting the bound cluster");
			set_pset_load_avg(j, TH_BUCKET_SHARE_DF, low_load);
		}
	}
	SCHED_POLICY_PASS("Cluster bound chooses bound cluster");
	/* Derecommend the bound cluster */
	for (int i = 0; i < dual_die.num_psets; i++) {
		set_pset_derecommended(i);
		int replacement_pset = -1;
		for (int j = 0; j < dual_die.num_psets; j++) {
			/* Find the first homogenous cluster and mark it as idle so we choose it */
			if ((i != j) && (dual_die.psets[i].cpu_type == dual_die.psets[j].cpu_type)) {
				replacement_pset = j;
				set_pset_load_avg(replacement_pset, TH_BUCKET_SHARE_DF, idle_load);
				break;
			}
		}
		ret = choose_pset_for_thread_expect(threads[i], replacement_pset);
		T_QUIET; T_EXPECT_TRUE(ret, "Expecting the idle pset when the bound cluster is derecommended");
		/* Restore pset conditions */
		set_pset_recommended(i);
		set_pset_load_avg(replacement_pset, TH_BUCKET_SHARE_DF, low_load);
	}
	SCHED_POLICY_PASS("Cluster binding is soft");
}

SCHED_POLICY_T_DECL(migration_should_yield,
    "Verify that we only yield if there's a \"good enough\" thread elsewhere "
    "to switch to")
{
	int ret;
	init_migration_harness(basic_amp);
	struct thread_group *tg = create_tg(0);
	test_thread_t background = create_thread(TH_BUCKET_SHARE_BG, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_BG]);
	test_thread_t yielder = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	cpu_set_thread_current(0, yielder);
	ret = cpu_check_should_yield(0, false);
	T_QUIET; T_EXPECT_TRUE(ret, "No thread present to yield to");
	enqueue_thread(cluster_target(0), background);
	ret = cpu_check_should_yield(0, true);
	T_QUIET; T_EXPECT_TRUE(ret, "Should yield to a low priority thread on the current runqueue");
	SCHED_POLICY_PASS("Basic yield behavior on single pset");

	ret = dequeue_thread_expect(cluster_target(0), background);
	T_QUIET; T_EXPECT_TRUE(ret, "Only background thread in runqueue");
	cpu_set_thread_current(0, yielder); /* Reset current thread */
	enqueue_thread(cluster_target(1), background);
	ret = cpu_check_should_yield(0, true);
	T_QUIET; T_EXPECT_TRUE(ret, "Should yield in order to steal thread");
	ret = dequeue_thread_expect(cluster_target(1), background);
	T_QUIET; T_EXPECT_TRUE(ret, "Only background thread in runqueue");
	cpu_set_thread_current(cluster_id_to_cpu_id(1), background);
	ret = cpu_check_should_yield(cluster_id_to_cpu_id(1), false);
	T_QUIET; T_EXPECT_TRUE(ret, "Should not yield in order to rebalance (presumed) native thread");
	SCHED_POLICY_PASS("Thread yields in order to steal from other psets");
}

SCHED_POLICY_T_DECL(migration_ipi_policy,
    "Verify we send the right type of IPI in different cross-core preemption scenarios")
{
	int ret;
	init_migration_harness(dual_die);
	struct thread_group *tg = create_tg(0);
	thread_t thread = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	int dst_pcore = 3;
	int src_pcore = 0;

	set_current_processor(src_pcore);
	cpu_send_ipi_for_thread(dst_pcore, thread, TEST_IPI_EVENT_PREEMPT);
	ret = ipi_expect(dst_pcore, TEST_IPI_IDLE);
	T_QUIET; T_EXPECT_TRUE(ret, "Idle CPU");

	thread_t core_busy = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	cpu_set_thread_current(dst_pcore, core_busy);
	set_current_processor(src_pcore);
	cpu_send_ipi_for_thread(dst_pcore, thread, TEST_IPI_EVENT_PREEMPT);
	ret = ipi_expect(dst_pcore, TEST_IPI_IMMEDIATE);
	T_QUIET; T_EXPECT_TRUE(ret, "Should immediate IPI to preempt on P-core");
	SCHED_POLICY_PASS("Immediate IPIs to preempt P-cores");

	int dst_ecore = 13;
	int ecluster_id = 5;
	set_tg_sched_bucket_preferred_pset(tg, TH_BUCKET_SHARE_DF, ecluster_id);
	set_current_processor(src_pcore);
	cpu_send_ipi_for_thread(dst_ecore, thread, TEST_IPI_EVENT_PREEMPT);
	ret = ipi_expect(dst_ecore, TEST_IPI_IDLE);
	T_QUIET; T_EXPECT_TRUE(ret, "Idle CPU");

	cpu_set_thread_current(dst_ecore, core_busy);
	set_current_processor(src_pcore);
	cpu_send_ipi_for_thread(dst_ecore, thread, TEST_IPI_EVENT_PREEMPT);
	ret = ipi_expect(dst_ecore, TEST_IPI_IMMEDIATE);
	T_QUIET; T_EXPECT_TRUE(ret, "Should immediate IPI to preempt for E->E");
	SCHED_POLICY_PASS("Immediate IPIs to cluster homogeneous with preferred");
}

SCHED_POLICY_T_DECL(migration_max_parallelism,
    "Verify we report expected values for recommended width of parallel workloads")
{
	int ret;
	init_migration_harness(dual_die);
	uint32_t num_pclusters = 4;
	uint32_t num_pcores = 4 * num_pclusters;
	uint32_t num_eclusters = 2;
	uint32_t num_ecores = 2 * num_eclusters;
	for (thread_qos_t qos = THREAD_QOS_UNSPECIFIED; qos < THREAD_QOS_LAST; qos++) {
		for (int shared_rsrc = 0; shared_rsrc < 2; shared_rsrc++) {
			for (int rt = 0; rt < 2; rt++) {
				uint64_t options = 0;
				uint32_t expected_width = 0;
				if (shared_rsrc) {
					options |= QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE;
				}
				if (rt) {
					options |= QOS_PARALLELISM_REALTIME;
					/* Recommend P-width */
					expected_width = shared_rsrc ? num_pclusters : num_pcores;
				} else if (qos == THREAD_QOS_BACKGROUND || qos == THREAD_QOS_MAINTENANCE) {
					/* Recommend E-width */
					expected_width = shared_rsrc ? num_eclusters : num_ecores;
				} else {
					/* Recommend full width */
					expected_width = shared_rsrc ? (num_eclusters + num_pclusters) : (num_pcores + num_ecores);
				}
				ret = max_parallelism_expect(qos, options, expected_width);
				T_QUIET; T_EXPECT_TRUE(ret, "Unexpected width for QoS %d shared_rsrc %d RT %d",
				    qos, shared_rsrc, rt);
			}
		}
	}
	SCHED_POLICY_PASS("Correct recommended parallel width for all configurations");
}
