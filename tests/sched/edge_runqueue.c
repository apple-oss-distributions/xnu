// Copyright (c) 2024 Apple Inc.  All rights reserved.

/*
 * Since the Edge scheduler depends on the Clutch scheduler as most of its
 * timesharing policy, the Edge scheduler should also pass all of the Clutch
 * unit tests.
 */
#include "clutch_runqueue.c"

#include "sched_test_harness/sched_edge_harness.h"

SCHED_POLICY_T_DECL(runq_shared_rsrc_bound,
    "Shared resource threads should be enqueued into bound root buckets")
{
	int ret;
	init_migration_harness(single_core);
	struct thread_group *tg = create_tg(0);
	/* Test both shared resource types */
	for (int i = 0; i < 2; i++) {
		thread_t thread = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
		edge_set_thread_shared_rsrc(thread, i);
		enqueue_thread(default_target, thread);
		ret = dequeue_thread_expect(default_target, thread);
		T_QUIET; T_EXPECT_TRUE(ret, "Single shared rsrc thread");
		uint64_t bound_arg = SELECTION_WAS_CLUSTER_BOUND | SELECTION_WAS_EDF | CTS_VERSION;
		ret = tracepoint_expect(CLUTCH_THREAD_SELECT, i, 0, TH_BUCKET_SHARE_DF, bound_arg);
		T_EXPECT_TRUE(ret, "CLUTCH_THREAD_SELECT tracepoint confirms shared resource "
		    "(%s) thread was enqueued as bound", i == 0 ? "native first" : "round robin");
	}
	SCHED_POLICY_PASS("Shared resource threads enqueued as bound");
}

SCHED_POLICY_T_DECL(runq_aboveui_bound_tiebreaks,
    "Tiebreaking Above UI vs. timeshare FG and bound vs. unbound root buckets")
{
	int ret;
	init_migration_harness(single_core);

	/* Create a thread for each permutation (4 total), all at matching priority 63 */
	struct thread_group *same_tg = create_tg(clutch_interactivity_score_max);
	test_thread_t unbound_aboveui = create_thread(TH_BUCKET_FIXPRI, same_tg, root_bucket_to_highest_pri[TH_BUCKET_FIXPRI]);
	set_thread_sched_mode(unbound_aboveui, TH_MODE_FIXED);
	test_thread_t bound_aboveui = create_thread(TH_BUCKET_FIXPRI, same_tg, root_bucket_to_highest_pri[TH_BUCKET_FIXPRI]);
	set_thread_sched_mode(bound_aboveui, TH_MODE_FIXED);
	set_thread_cluster_bound(bound_aboveui, 0);
	test_thread_t unbound_timeshare_fg = create_thread(TH_BUCKET_SHARE_FG, same_tg, root_bucket_to_highest_pri[TH_BUCKET_FIXPRI]);
	test_thread_t bound_timeshare_fg = create_thread(TH_BUCKET_SHARE_FG, same_tg, root_bucket_to_highest_pri[TH_BUCKET_FIXPRI]);
	set_thread_cluster_bound(bound_timeshare_fg, 0);

	for (int i = 0; i < NUM_RAND_SEEDS; i++) {
		enqueue_threads_rand_order(default_target, rand_seeds[i], 4, unbound_aboveui, bound_aboveui, unbound_timeshare_fg, bound_timeshare_fg);
		ret = dequeue_threads_expect_ordered(default_target, 2, bound_aboveui, unbound_aboveui);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Aboveui buckets didn't come out first and correctly ordered in iteration %d", i);
		/* Needed because bound/unbound root buckets alternate picks, as demonstrated below */
		disable_auto_current_thread();
		ret = dequeue_threads_expect_ordered(default_target, 2, bound_timeshare_fg, unbound_timeshare_fg);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Timeshare buckets didn't come out second and correctly ordered in iteration %d", i);
		T_QUIET; T_ASSERT_EQ(runqueue_empty(default_target), true, "runqueue_empty");
		reenable_auto_current_thread();
	}
	SCHED_POLICY_PASS("Correct tiebreaking for aboveui vs. foreground and unbound vs. bound root buckets");
}

SCHED_POLICY_T_DECL(runq_cluster_bound,
    "Cluster-bound threads vs. regular threads")
{
	int ret;
	init_migration_harness(basic_amp);
	struct thread_group *tg = create_tg(0);
	int num_threads = 4;
	test_thread_t threads[num_threads];
	for (int i = 0; i < NUM_RAND_SEEDS; i++) {
		/* High root bucket unbound */
		threads[0] = create_thread(TH_BUCKET_SHARE_IN, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_IN]);
		/* Middle root bucket bound */
		threads[1] = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
		set_thread_cluster_bound(threads[1], 0);
		/* Low root bucket unbound */
		threads[2] = create_thread(TH_BUCKET_SHARE_UT, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_UT]);
		/* Lowest root bucket bound */
		threads[3] = create_thread(TH_BUCKET_SHARE_BG, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_BG]);
		set_thread_cluster_bound(threads[3], 0);
		enqueue_threads_arr_rand_order(default_target, rand_seeds[i], num_threads, threads);
		/* Bound comes out first due to bound/unbound root bucket tie break in favor of bound */
		ret = dequeue_threads_expect_ordered_arr(default_target, num_threads, threads);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Threads dequeued without respect to QoS");
		T_QUIET; T_EXPECT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Cluster bound respects QoS level");

	int num_tie_break_threads = 10;
	test_thread_t tie_break_threads[num_tie_break_threads];
	for (int k = 0; k < num_tie_break_threads / 2; k++) {
		tie_break_threads[k * 2] = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
		set_thread_cluster_bound(tie_break_threads[k * 2], 0);
		increment_mock_time_us(5);
		enqueue_thread(default_target, tie_break_threads[k * 2]);
	}
	for (int k = 0; k < num_tie_break_threads / 2; k++) {
		tie_break_threads[k * 2 + 1] = create_thread(TH_BUCKET_SHARE_DF, tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
		increment_mock_time_us(5);
		enqueue_thread(default_target, tie_break_threads[k * 2 + 1]);
	}
	/* Disable current thread check because bound and unbound alternate without time passing */
	disable_auto_current_thread();
	for (int k = 0; k < num_tie_break_threads; k++) {
		/* Simulates repeatedly dequeing threads over time */
		increment_mock_time_us(5);
		ret = dequeue_thread_expect(default_target, tie_break_threads[k]);
		T_QUIET; T_EXPECT_TRUE(ret, "Out-of-order thread\n");
	}
	T_QUIET; T_EXPECT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	SCHED_POLICY_PASS("Unbound vs. bound tie-break");

	struct thread_group *low_iscore_tg = create_tg(0);
	test_thread_t low_iscore_bound = create_thread(TH_BUCKET_SHARE_DF, low_iscore_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	struct thread_group *high_iscore_tg = create_tg(clutch_interactivity_score_max);
	test_thread_t high_iscore_bound = create_thread(TH_BUCKET_SHARE_DF, high_iscore_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	set_thread_cluster_bound(low_iscore_bound, 0);
	set_thread_cluster_bound(high_iscore_bound, 0);
	enqueue_threads(default_target, 2, low_iscore_bound, high_iscore_bound);
	ret = dequeue_threads_expect_ordered(default_target, 2, low_iscore_bound, high_iscore_bound);
	T_QUIET; T_EXPECT_EQ(ret, -1, "Threads dequeued in non-FIFO order");
	T_QUIET; T_EXPECT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	SCHED_POLICY_PASS("Cluster bound threads don't use interactivity score");
}
