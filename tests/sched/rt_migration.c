// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include "sched_test_harness/sched_policy_darwintest.h"
#include "sched_test_harness/sched_edge_harness.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_RUN_CONCURRENTLY(true),
    T_META_OWNER("m_zinn"));

static mach_timebase_info_data_t timebase_info;

uint64_t
nanos_to_abs(uint64_t nanos)
{
	static mach_timebase_info_data_t timebase = {};

	if (timebase.numer == 0 || timebase.denom == 0) {
		kern_return_t kr;

		kr = mach_timebase_info(&timebase_info);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");

		timebase = timebase_info;
	}
	return nanos * timebase.denom / timebase.numer;
}

SCHED_POLICY_T_DECL(rt_migration_pset_bound,
    "Verify that pset-bound realtime threads always choose the bound "
    "pset except when its derecommended")
{
	int ret;
	test_sched_topology_t sched_topo = init_migration_harness(&dual_die);
	struct thread_group *tg = create_tg(0);
	test_thread_t threads[MAX_PSETS];
	for (int i = 0; i < sched_topo->num_psets; i++) {
		threads[i] = create_thread(TH_BUCKET_FIXPRI, tg, BASEPRI_RTQUEUES);
		set_thread_pset_bound(threads[i], i);
	}
	for (int i = 0; i < sched_topo->num_psets; i++) {
		set_current_processor(pset_id_to_cpu_id(i));
		for (int j = 0; j < sched_topo->num_psets; j++) {
			ret = choose_pset_for_thread_expect(threads[j], j);
			T_QUIET; T_EXPECT_TRUE(ret, "Expecting the bound cluster");
		}
	}
	SCHED_POLICY_PASS("Pset bound chooses bound pset");
	/* Derecommend the bound cluster */
	for (int i = 0; i < sched_topo->num_psets; i++) {
		set_pset_derecommended(i);
		int replacement_pset = -1;
		for (int j = 0; j < sched_topo->num_psets; j++) {
			/* Find the first homogenous cluster and mark it as idle so we choose it */
			if ((i != j) && (pset_cpu_type_for_id(i) == pset_cpu_type_for_id(j))) {
				replacement_pset = j;
				break;
			}
		}
		ret = choose_pset_for_thread_expect(threads[i], replacement_pset);
		T_QUIET; T_EXPECT_TRUE(ret, "Expecting the idle pset when the bound cluster is derecommended");
		/* Restore pset conditions */
		set_pset_recommended(i);
	}
	SCHED_POLICY_PASS("Cluster binding is soft");
}

SCHED_POLICY_T_DECL(rt_choose_processor,
    "Verify the realtime spill policy")
{
	test_sched_topology_t sched_topo = init_migration_harness(&dual_die);

	uint64_t start = mach_absolute_time();

	const uint64_t period = 0;
	const uint64_t computation = nanos_to_abs(5000000ULL); /* 5ms */
	const uint64_t constraint = nanos_to_abs(10000000ULL); /* 10ms */
	const bool preemptible = false;
	const uint8_t priority_offset = 0;

	struct thread_group *tg = create_tg(0);
	thread_t thread = create_thread(TH_BUCKET_FIXPRI, tg, BASEPRI_RTQUEUES);
	set_thread_sched_mode(thread, TH_MODE_REALTIME);
	const uint64_t deadline = rt_deadline_add(start, nanos_to_abs(10000000ULL /* 10ms */));
	set_thread_realtime(thread, period, computation, constraint, preemptible, priority_offset, deadline);

	test_thread_t earlier_threads[topology_info.num_cpus] = {};
	for (int i = 0; i < topology_info.num_cpus; i++) {
		earlier_threads[i] = create_thread(TH_BUCKET_FIXPRI, tg, BASEPRI_RTQUEUES);
		set_thread_sched_mode(earlier_threads[i], TH_MODE_REALTIME);
		const uint64_t early_deadline = rt_deadline_add(start, nanos_to_abs(5000000) /* 5ms */);
		set_thread_realtime(earlier_threads[i], period, computation, constraint, preemptible, priority_offset, early_deadline);
	}

	test_thread_t later_thread = create_thread(TH_BUCKET_FIXPRI, tg, BASEPRI_RTQUEUES);
	set_thread_sched_mode(later_thread, TH_MODE_REALTIME);
	const uint64_t late_deadline = rt_deadline_add(start, nanos_to_abs(20000000ULL) /* 20ms */);
	set_thread_realtime(later_thread, period, computation, constraint, preemptible, priority_offset, late_deadline);

	for (int preferred_pset_id = 0; preferred_pset_id < sched_topo->num_psets; preferred_pset_id++) {
		set_tg_sched_bucket_preferred_pset(tg, TH_BUCKET_FIXPRI, preferred_pset_id);
		sched_policy_push_metadata("preferred_pset_id", preferred_pset_id);

		/* Unloaded system. Expect to choose the preferred pset. */
		choose_pset_for_thread_expect(thread, preferred_pset_id);

		/*
		 * Load the preferred pset with earlier-deadline threads. Should cause
		 * the thread to spill (since the die has multiple clusters of each
		 * performance type).
		 */
		for (int i = 0; i < pset_cpu_count_for_id(preferred_pset_id); i++) {
			int cpu_id = pset_id_to_cpu_id(preferred_pset_id) + i;
			cpu_set_thread_current(cpu_id, earlier_threads[i]);
		}
		int chosen = choose_pset_for_thread(thread);
		T_QUIET; T_EXPECT_GE(chosen, 0, "chose a valid cluster");
		T_QUIET; T_EXPECT_NE(chosen, preferred_pset_id, "chose an unloaded cluster");
		T_QUIET; T_EXPECT_EQ(pset_cpu_type_for_id(chosen), pset_cpu_type_for_id(preferred_pset_id), "chose a pset of the same performance type");

		/* Replace the first earlier-deadline thread with a later-deadline thread. Should cause the thread to preempt. */
		cpu_set_thread_current(pset_id_to_cpu_id(preferred_pset_id), later_thread);
		chosen = choose_pset_for_thread(thread);
		T_QUIET; T_EXPECT_EQ(chosen, preferred_pset_id, "preempting later-deadline thread");

		/* Load all psets of the same performance type with early-deadline threads. Expected preferred pset to be chosen. */
		for (int i = 0; i < sched_topo->num_psets; i++) {
			if (pset_cpu_type_for_id(i) != pset_cpu_type_for_id(preferred_pset_id)) {
				continue;
			}
			for (int j = 0; j < pset_cpu_count_for_id(i); j++) {
				int cpu_id = pset_id_to_cpu_id(i) + j;
				cpu_set_thread_current(cpu_id, earlier_threads[cpu_id]);
			}
		}
		choose_pset_for_thread_expect(thread, preferred_pset_id);

		/* Clean up */
		for (int i = 0; i < topology_info.num_cpus; i++) {
			cpu_clear_thread_current(i);
		}

		sched_policy_pop_metadata(/* preferred_pset_id */);
	}

	SCHED_POLICY_PASS("sched_rt_choose_processor selects the right pset");
}

SCHED_POLICY_T_DECL(rt_spill_order, "Verify computed realtime spill orders.")
{
	test_sched_topology_t sched_topo = init_migration_harness(&dual_die);

	/* Test setup: reset all edges. */
	for (uint src_id = 0; src_id < sched_topo->num_psets; src_id++) {
		for (uint dst_id = 0; dst_id < sched_topo->num_psets; dst_id++) {
			sched_rt_config_set(src_id, dst_id, (sched_clutch_edge) {});
		}
	}

	/* First test: create edges from pset 5 to psets 0-3. */
	for (unsigned i = 0; i < 4; i++) {
		sched_rt_config_set(5, i, (sched_clutch_edge) {
			.sce_migration_allowed = 1,
			.sce_steal_allowed = 0,
			.sce_migration_weight = i % 3 /* create ties to test die-locality */
		});
	}
	/* Disallow spill from 5 to 4, despite being the same perf level. */
	sched_rt_config_set(5, 4, (sched_clutch_edge) {
		.sce_migration_allowed = 0,
		.sce_steal_allowed = 0,
		.sce_migration_weight = 0
	});

	rt_pset_recompute_spill_order(5);

	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(5, 0), 3, "spso_search_order[0] == 3");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(5, 1), 0, "spso_search_order[1] == 0");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(5, 2), 1, "spso_search_order[2] == 1");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(5, 3), 2, "spso_search_order[3] == 2");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(5, 4), PSET_ID_INVALID, "spso_search_order[4] == PSET_ID_INVALID");

	/* Second test: create edges from 0 to psets 1, 2, 4, and 5. */
	sched_rt_config_set(0, 1, (sched_clutch_edge) {
		.sce_migration_allowed = 1,
		.sce_steal_allowed = 0,
		.sce_migration_weight = 2
	});
	sched_rt_config_set(0, 2, (sched_clutch_edge) {
		.sce_migration_allowed = 1,
		.sce_steal_allowed = 0,
		.sce_migration_weight = 1
	});
	sched_rt_config_set(0, 4, (sched_clutch_edge) {
		.sce_migration_allowed = 1,
		.sce_steal_allowed = 0,
		.sce_migration_weight = 0
	});
	sched_rt_config_set(0, 5, (sched_clutch_edge) {
		.sce_migration_allowed = 1,
		.sce_steal_allowed = 0,
		.sce_migration_weight = 1
	});

	rt_pset_recompute_spill_order(0);

	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(0, 0), 4, "spso_search_order[0] == 4");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(0, 1), 2, "spso_search_order[1] == 2");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(0, 2), 5, "spso_search_order[2] == 5");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(0, 3), 1, "spso_search_order[3] == 1");
	T_QUIET; T_EXPECT_EQ(rt_pset_spill_search_order_at_offset(0, 4), PSET_ID_INVALID, "spso_search_order[4] == PSET_ID_INVALID");

	SCHED_POLICY_PASS("Realtime spill orders are computed correctly.");
}

SCHED_POLICY_T_DECL(rt_thread_avoid_processor,
    "Verify that thread_avoid_processor is correct for realtime threads")
{
	int ret;
	test_sched_topology_t sched_topo = init_migration_harness(&dual_die);
	struct thread_group *tg = create_tg(0);
	thread_t thread = create_thread(TH_BUCKET_FIXPRI, tg, BASEPRI_RTQUEUES);

	/* Iterate conditions with different preferred psets and pset loads */
	for (int preferred_pset_id = 0; preferred_pset_id < sched_topo->num_psets; preferred_pset_id++) {
		set_tg_sched_bucket_preferred_pset(tg, TH_BUCKET_FIXPRI, preferred_pset_id);
		sched_policy_push_metadata("preferred_pset_id", preferred_pset_id);

		/* Where the thread proactively wants to go */
		int chosen_pset = choose_pset_for_thread(thread);
		T_QUIET; T_EXPECT_EQ(preferred_pset_id, chosen_pset, "Thread should choose un-loaded preferred pset %s",
		    sched_policy_dump_metadata());

		/* Thread generally should not avoid a processor in its chosen pset */
		for (int c = 0; c < pset_cpu_count_for_id(chosen_pset); c++) {
			int avoid_cpu_id = pset_id_to_cpu_id(chosen_pset) + c;
			sched_policy_push_metadata("avoid_cpu_id", avoid_cpu_id);
			cpu_set_thread_current(avoid_cpu_id, thread);
			ret = thread_avoid_processor_expect(thread, avoid_cpu_id, false, false);
			T_QUIET; T_EXPECT_TRUE(ret, "Thread should not want to leave processor in just chosen pset %s",
			    sched_policy_dump_metadata());
			cpu_clear_thread_current(avoid_cpu_id);
			sched_policy_pop_metadata();
		}

		/* Thread should avoid processor if not allowed to run on the pset */
		for (int c = 0; c < topology_info.num_cpus; c++) {
			sched_clutch_edge edge = sched_rt_config_get(preferred_pset_id, cpu_id_to_pset_id(c));
			if (cpu_id_to_pset_id(c) != preferred_pset_id && !(edge.sce_migration_allowed || edge.sce_steal_allowed)) {
				sched_policy_push_metadata("avoid_non_preferred_cpu_id", c);
				cpu_set_thread_current(c, thread);
				ret = thread_avoid_processor_expect(thread, c, false, true);
				T_QUIET; T_EXPECT_TRUE(ret, "Thread should avoid processor in non-preferred pset to get to idle "
				    "preferred pset %s", sched_policy_dump_metadata());
				cpu_clear_thread_current(c);
				sched_policy_pop_metadata();
			}
		}

		sched_policy_pop_metadata();
	}
	SCHED_POLICY_PASS("thread_avoid_processor works for realtime threads");
}

static thread_t
create_realtime_thread_with_deadline(uint64_t deadline_nanos)
{
	test_thread_t thread = create_thread(
		TH_BUCKET_FIXPRI,
		create_tg(0) /* realtime policies don't consider thread groups */,
		BASEPRI_RTQUEUES);
	set_thread_sched_mode(thread, TH_MODE_REALTIME);
	set_thread_realtime(
		thread,
		0,
		(uint32_t) nanos_to_abs(5000000ULL /* 5ms */),
		(uint32_t) nanos_to_abs(10000000ULL /* 10ms */),
		false,
		0,
		nanos_to_abs(deadline_nanos));
	return thread;
}

static void
fill_all_cpus_with_realtime_threads(uint64_t deadline_nanos)
{
	for (int i = 0; i < topology_info.num_cpus; i++) {
		cpu_set_thread_current(i, create_realtime_thread_with_deadline(deadline_nanos));
	}
}

SCHED_POLICY_T_DECL(rt_choose_thread, "Verify realtime thread selection policy and mechanism")
{
	int ret;
	test_sched_topology_t sched_topo = init_migration_harness(&dual_die);

	const uint64_t start = mach_absolute_time();
	const uint64_t deadline = rt_deadline_add(start, nanos_to_abs(5000000)); /* start + 5ms */
	const uint64_t later_deadline = rt_deadline_add(start, nanos_to_abs(6000000)); /* start + 6ms */

	fill_all_cpus_with_realtime_threads(later_deadline);

	/* One of these threads will be on the stealing pset runqueue: */
	test_thread_t later_deadline_thread = create_realtime_thread_with_deadline(later_deadline);
	test_thread_t earlier_deadline_thread = create_realtime_thread_with_deadline(deadline);

	/* And this thread will be on another runqueue: */
	test_thread_t stealable_thread = create_realtime_thread_with_deadline(deadline);

	/* Check that sched_rt_choose_thread obeys the steal policies configured by
	 * the realtime matrix. A pset should only steal if the thread's deadline
	 * is earlier than that of any thread on the pset's runqueue. */

	for (uint stealing_pset_id = 0; stealing_pset_id < sched_topo->num_psets; stealing_pset_id++) {
		sched_policy_push_metadata("stealing_pset", stealing_pset_id);
		for (uint off = 1; off < sched_topo->num_psets; off++) {
			uint other_pset_id = (stealing_pset_id + off) % sched_topo->num_psets;
			sched_policy_push_metadata("other_pset", other_pset_id);

			enqueue_thread(pset_target(other_pset_id), stealable_thread);

			enqueue_thread(pset_target(stealing_pset_id), earlier_deadline_thread);
			ret = dequeue_thread_expect(pset_target(stealing_pset_id), earlier_deadline_thread);
			T_QUIET; T_ASSERT_TRUE(ret, "when deadlines are equal, prefer thread from local runqueue %s", sched_policy_dump_metadata());

			enqueue_thread(pset_target(stealing_pset_id), later_deadline_thread);
			if (pset_cpu_type_for_id(other_pset_id) == pset_cpu_type_for_id(stealing_pset_id)) {
				T_QUIET; T_ASSERT_TRUE(sched_rt_config_get(other_pset_id, stealing_pset_id).sce_steal_allowed, "steal allowed between psets of the same type %s", sched_policy_dump_metadata());

				ret = dequeue_thread_expect(pset_target(stealing_pset_id), stealable_thread);
				T_QUIET; T_ASSERT_TRUE(ret, "steal because the other pset has an earlier-deadline thread %s", sched_policy_dump_metadata());

				ret = dequeue_thread_expect(pset_target(stealing_pset_id), later_deadline_thread);
				T_QUIET; T_ASSERT_TRUE(ret, "take thread from local runqueue because no earlier-deadline threads on other psets %s", sched_policy_dump_metadata());
			} else {
				T_QUIET; T_ASSERT_FALSE(sched_rt_config_get(other_pset_id, stealing_pset_id).sce_steal_allowed, "steal disallowed between psets of different types %s", sched_policy_dump_metadata());

				ret = dequeue_thread_expect(pset_target(stealing_pset_id), later_deadline_thread);
				T_QUIET; T_ASSERT_TRUE(ret, "take later-deadline thread because policy disallows steal %s", sched_policy_dump_metadata());

				ret = dequeue_thread_expect(pset_target(other_pset_id), stealable_thread);
				T_QUIET; T_ASSERT_TRUE(ret, "removed stealable thread %s", sched_policy_dump_metadata());
			}
			sched_policy_pop_metadata(/* other_pset */);
		}
		sched_policy_pop_metadata(/* stealing_pset */);
	}

	SCHED_POLICY_PASS("Verified realtime thread selection");
}

SCHED_POLICY_T_DECL(rt_followup_ipi, "Verify that followup IPIs are sent when there are stealable realtime threads and idle processors")
{
	int ret;
	init_migration_harness(&dual_die);

	const uint64_t start = mach_absolute_time();
	const uint64_t deadline = rt_deadline_add(start, nanos_to_abs(5000000)); /* start + 5ms */

	fill_all_cpus_with_realtime_threads(deadline);

	/* This thread is used to load a runqueue. */
	test_thread_t thread = create_realtime_thread_with_deadline(deadline);

	for (int target_cpu = 0; target_cpu < topology_info.num_cpus; target_cpu++) {
		sched_policy_push_metadata("target_cpu", target_cpu);
		for (int idle_cpu = 0; idle_cpu < topology_info.num_cpus; idle_cpu++) {
			if (target_cpu == idle_cpu) {
				continue;
			}

			sched_policy_push_metadata("idle_cpu", idle_cpu);
			enqueue_thread(cpu_target(target_cpu), thread);
			test_thread_t saved_idle_thread = cpu_clear_thread_current(idle_cpu);

			/* idle_cpu is now "idle," now simulate thread_select() on target_cpu: */
			cpu_set_thread_current(target_cpu, cpu_clear_thread_current(target_cpu));

			/* That should result in an immediate followup IPI, if spill is allowed between target_cpu and idle_cpu. */
			int target_pset = cpu_id_to_pset_id(target_cpu);
			int idle_pset = cpu_id_to_pset_id(idle_cpu);

			if ((pset_cpu_type_for_id(target_pset) == pset_cpu_type_for_id(idle_pset)) && (target_pset != idle_pset || true)) {
				ret = ipi_expect(idle_cpu, TEST_IPI_IDLE);
				T_QUIET; T_EXPECT_TRUE(ret, "should send a followup IPI %s", sched_policy_dump_metadata());
			}

			/* Clean up for the next iteration. */
			ret = dequeue_thread_expect(cpu_target(target_cpu), thread);
			T_QUIET; T_ASSERT_TRUE(ret, "cleaning up %s", sched_policy_dump_metadata());
			cpu_set_thread_current(idle_cpu, saved_idle_thread);
			sched_policy_pop_metadata(/* idle_cpu */);
			cpu_clear_pending_ast_bits(idle_cpu);
		}
		sched_policy_pop_metadata(/* target_cpu */);
	}

	SCHED_POLICY_PASS("Realtime followup IPIs work");
}
