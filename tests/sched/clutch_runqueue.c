// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <string.h>

#include "sched_test_harness/sched_policy_darwintest.h"
#include "sched_test_harness/sched_clutch_harness.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_RUN_CONCURRENTLY(true),
    T_META_OWNER("emily_peterson"));

#define NUM_RAND_SEEDS 5
static unsigned int rand_seeds[NUM_RAND_SEEDS] = {377111, 2738572, 1717171, 4990221, 777777};

SCHED_POLICY_T_DECL(runq_processor_bound,
    "Processor-bound threads vs. Regular threads")
{
	int ret;
	init_runqueue_harness();

	struct thread_group *high_tg = create_tg(clutch_interactivity_score_max);
	struct thread_group *low_tg = create_tg(0);

	test_thread_t lowest_bound = create_thread(TH_BUCKET_SHARE_BG, low_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_BG]);
	set_thread_processor_bound(lowest_bound, get_default_cpu());
	test_thread_t highest_bound = create_thread(TH_BUCKET_SHARE_IN, high_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_IN]);
	set_thread_processor_bound(highest_bound, get_default_cpu());
	test_thread_t lowest_unbound = create_thread(TH_BUCKET_SHARE_BG, low_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_BG]);
	test_thread_t highest_unbound = create_thread(TH_BUCKET_SHARE_IN, high_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_IN]);

	for (int i = 0; i < NUM_RAND_SEEDS; i++) {
		enqueue_threads_rand_order(default_target, rand_seeds[i], 4, lowest_bound, highest_bound, lowest_unbound, highest_unbound);
		ret = dequeue_threads_expect_ordered(default_target, 4, highest_bound, highest_unbound, lowest_bound, lowest_unbound);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Processor-bound failed to win tie-break");
		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Processor-bound threads win priority tie-breaker");

	test_thread_t bound = create_thread(TH_BUCKET_SHARE_DF, low_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF] - 1);
	set_thread_processor_bound(bound, get_default_cpu());
	test_thread_t higherpri_unbound = create_thread(TH_BUCKET_SHARE_DF, low_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	test_thread_t interactive_higherpri_unbound = create_thread(TH_BUCKET_SHARE_DF, high_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	test_thread_t interactive_lowerpri_unbound = create_thread(TH_BUCKET_SHARE_DF, high_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF] - 2);
	for (int i = 0; i < NUM_RAND_SEEDS; i++) {
		enqueue_threads_rand_order(default_target, rand_seeds[i], 4, bound, higherpri_unbound, interactive_higherpri_unbound, interactive_lowerpri_unbound);
		ret = dequeue_threads_expect_ordered(default_target, 4, interactive_higherpri_unbound, bound, interactive_lowerpri_unbound, higherpri_unbound);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Priority and Clutch interactivity score not factored correctly against processor-bound thread");
		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Clutch root represented against processor-bound threads by highest pri thread in the highest pri Clutch bucket");
}

SCHED_POLICY_T_DECL(runq_aboveui,
    "Above UI vs. timeshare FG root buckets")
{
	int ret;
	init_runqueue_harness();

	struct thread_group *same_tg = create_tg(clutch_interactivity_score_max);
	test_thread_t aboveui = create_thread(TH_BUCKET_FIXPRI, same_tg, root_bucket_to_highest_pri[TH_BUCKET_FIXPRI]);
	set_thread_sched_mode(aboveui, TH_MODE_FIXED);
	test_thread_t low_fg = create_thread(TH_BUCKET_SHARE_FG, same_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_FG]);
	test_thread_t high_fg = create_thread(TH_BUCKET_SHARE_FG, same_tg, root_bucket_to_highest_pri[TH_BUCKET_FIXPRI] + 1);

	for (int i = 0; i < NUM_RAND_SEEDS; i++) {
		enqueue_threads_rand_order(default_target, rand_seeds[i], 3, aboveui, low_fg, high_fg);
		ret = dequeue_threads_expect_ordered(default_target, 3, high_fg, aboveui, low_fg);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Aboveui vs. foreground threads dequeued out of order");
		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Aboveui vs. foreground ordered according to priority");
}

SCHED_POLICY_T_DECL(runq_diff_root_bucket,
    "Different root buckets (EDF, Starvation Avoidance Mode, and Warp)")
{
	int ret;
	init_runqueue_harness();

	struct thread_group *same_tg = create_tg(0);
	int num_threads = TH_BUCKET_SCHED_MAX - 1;
	test_thread_t threads[num_threads];
	test_thread_t rev_threads[num_threads];
	test_thread_t warper_threads[num_threads];
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		threads[bucket - 1] = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket]);
		rev_threads[num_threads - bucket] = threads[bucket - 1];
		warper_threads[bucket - 1] = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket]);
	}

	/* Validate natural EDF between root buckets */
	for (int i = 0; i < NUM_RAND_SEEDS; i++) {
		enqueue_threads_arr_rand_order(default_target, rand_seeds[i], num_threads, threads);
		ret = dequeue_threads_expect_ordered_arr(default_target, num_threads, threads);
		T_QUIET; T_EXPECT_EQ(ret, -1, "Root buckets dequeued out of EDF order, after the first %d threads dequeued were correct", ret);
		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Basic EDF root bucket order respected");

	/* Warp lets high root buckets win despite reverse ordering of root bucket deadlines */
	for (int bucket = TH_BUCKET_SHARE_BG; bucket >= TH_BUCKET_SHARE_FG; bucket--) {
		if (bucket < TH_BUCKET_SHARE_BG) {
			increment_mock_time_us(clutch_root_bucket_wcel_us[bucket + 1] - clutch_root_bucket_wcel_us[bucket] + 1);
		}
		enqueue_thread(default_target, warper_threads[bucket - 1]);
		enqueue_thread(default_target, threads[bucket - 1]);
	}
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		ret = dequeue_thread_expect(default_target, warper_threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "Root bucket %d failed to warp ahead", bucket);
		increment_mock_time_us(clutch_root_bucket_warp_us[bucket] / 2);
		ret = dequeue_thread_expect(default_target, threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "Root bucket %d's warp window failed to stay open", bucket);
		increment_mock_time_us(clutch_root_bucket_warp_us[bucket] / 2 + 1);
	}
	T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	SCHED_POLICY_PASS("Warping and Warp Windows respected");

	/* After Warp is exhausted, Starvation Avoidance Mode kicks in to choose the buckets in EDF order */
	for (int bucket = TH_BUCKET_SHARE_BG; bucket >= TH_BUCKET_SHARE_FG; bucket--) {
		if (bucket < TH_BUCKET_SHARE_BG) {
			increment_mock_time_us(clutch_root_bucket_wcel_us[bucket + 1] - clutch_root_bucket_wcel_us[bucket] + 1);
		}
		enqueue_thread(default_target, threads[bucket - 1]);
	}
	ret = dequeue_threads_expect_ordered_arr(default_target, num_threads, rev_threads);
	T_QUIET; T_EXPECT_EQ(ret, -1, "Starvation avoidance failed to kick in, after the first %d threads dequeued were correct", ret);
	T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	SCHED_POLICY_PASS("Starvation Avoidance Mode respected");
}

SCHED_POLICY_T_DECL(runq_diff_clutch_bucket,
    "Same root bucket, different TGs")
{
	int ret;
	init_runqueue_harness();

	int num_tgs = clutch_interactivity_score_max + 1;
	struct thread_group *tgs[num_tgs];
	for (int i = 0; i < num_tgs; i++) {
		tgs[i] = create_tg(i);
	}

	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		test_thread_t threads[num_tgs];
		for (int i = 0; i < num_tgs; i++) {
			threads[i] = create_thread(bucket, tgs[clutch_interactivity_score_max - i], root_bucket_to_highest_pri[bucket]);
		}

		for (int i = 0; i < NUM_RAND_SEEDS; i++) {
			enqueue_threads_arr_rand_order(default_target, rand_seeds[i], num_tgs, threads);
			ret = dequeue_threads_expect_ordered_arr(default_target, num_tgs, threads);
			T_QUIET; T_EXPECT_EQ(ret, -1, "Unique interactivity scores dequeued out-of-order, after the first %d threads dequeued were correct", ret);
			T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
		}
	}
	SCHED_POLICY_PASS("Interactivity scores between Clutch buckets respected");

	struct thread_group *low_tg = create_tg(clutch_interactivity_score_max / 2);
	struct thread_group *high_tg = create_tg((clutch_interactivity_score_max / 2) + 2);
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		test_thread_t lowpri_but_interactive = create_thread(bucket, high_tg, root_bucket_to_highest_pri[bucket] - 1);
		test_thread_t highpri = create_thread(bucket, low_tg, root_bucket_to_highest_pri[bucket]);

		for (int order = 0; order < 2; order++) {
			enqueue_threads(default_target, 2, (order == 0 ? lowpri_but_interactive : highpri), (order == 0 ? highpri : lowpri_but_interactive));
			ret = dequeue_threads_expect_ordered(default_target, 2, lowpri_but_interactive, highpri);
			T_QUIET; T_EXPECT_EQ(ret, -1, "Pri %d and i-score %d dequeued before pri %d and i-score %d, enqueue-order %d", root_bucket_to_highest_pri[bucket] - 1, (clutch_interactivity_score_max / 2) + 2, root_bucket_to_highest_pri[bucket], clutch_interactivity_score_max / 2, order);
		}

		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Priority correctly combined with interactivity scores to order Clutch buckets");

	struct thread_group *first_tg = create_tg(clutch_interactivity_score_max / 2);
	struct thread_group *second_tg = create_tg(clutch_interactivity_score_max / 2);
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		test_thread_t first = create_thread(bucket, first_tg, root_bucket_to_highest_pri[bucket]);
		test_thread_t second = create_thread(bucket, second_tg, root_bucket_to_highest_pri[bucket]);
		enqueue_threads(default_target, 2, first, second);

		ret = dequeue_threads_expect_ordered(default_target, 2, first, second);
		T_QUIET; T_EXPECT_EQ(ret, -1, "FIFO order disrespected for threads in two Clutch buckets of equal priority");

		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Clutch bucket FIFO order respected, for Clutch buckets with the same priority");
}

SCHED_POLICY_T_DECL(runq_diff_priority,
    "Same root bucket, same TG, different priorities")
{
	int ret;
	init_runqueue_harness();

	struct thread_group *same_tg = create_tg(0);

	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		test_thread_t lowpri = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket] - 1);
		test_thread_t highpri = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket]);

		for (int order = 0; order < 2; order++) {
			enqueue_threads(default_target, 2, (order == 0 ? lowpri : highpri), (order == 0 ? highpri : lowpri));
			ret = dequeue_threads_expect_ordered(default_target, 2, highpri, lowpri);
			T_QUIET; T_EXPECT_EQ(ret, -1, "Pri %d dequeued before pri %d, enqueue-order %d", root_bucket_to_highest_pri[bucket] - 1, root_bucket_to_highest_pri[bucket], order);
		}

		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("sched_pri order respected, for threads in the same Clutch bucket");

	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		int num_threads = 10;
		test_thread_t threads[num_threads];
		for (int i = 0; i < num_threads; i++) {
			threads[i] = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket]);
			increment_mock_time_us(5);
			enqueue_thread(default_target, threads[i]);
		}
		ret = dequeue_threads_expect_ordered_arr(default_target, num_threads, threads);
		T_QUIET; T_EXPECT_EQ(ret, -1, "FIFO order disrespected for %d threads at pri %d", num_threads, root_bucket_to_highest_pri[bucket]);
		T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	}
	SCHED_POLICY_PASS("Thread FIFO order respected, for threads in the same Clutch bucket with the same sched_pri");
}

/*
 * 64 bits of fourth argument to CLUTCH_THREAD_SELECT expected to
 * match the following layout, ordered from most to least significant bit:
 *
 * (reserved 23)                 (selection_opened_starvation_avoidance_window 1)
 *        |      (starvation_avoidance_window_close 12)   | (selection_was_edf 1)
 *        |                                  |            | |   (traverse mode 3)
 *        v                                  v            v v      v
 *        r----------------------wc----------sc----------wsbec-----t--v---
 *                               ^                       ^ ^ ^        ^
 *                               |                       | | |       (version 4)
 *                  (warp_window_close 12)               | | (cluster_id 6)
 *                                                       | (selection_was_cluster_bound 1)
 *                                   (selection_opened_warp_window 1)
 */
#define CTS_VERSION 1ULL
#define TRAVERSE_MODE_REMOVE_CONSIDER_CURRENT (1ULL << 4)
#define TRAVERSE_MODE_CHECK_PREEMPT (2ULL << 4)
#define CLUSTER_ID(id) (id << 7)
#define SELECTION_WAS_EDF (1ULL << 13)
#define SELECTION_WAS_CLUSTER_BOUND (1ULL << 14)
#define SELECTION_OPENED_STARVATION_AVOIDANCE_WINDOW (1ULL << 15) | SELECTION_WAS_EDF
#define SELECTION_OPENED_WARP_WINDOW (1ULL << 16)
#define WINDOW_MASK(bucket, cluster_bound) ( 1ULL << (bucket + cluster_bound * TH_BUCKET_SCHED_MAX) )
#define STARVATION_AVOIDANCE_WINDOW_CLOSE(bucket, cluster_bound) (WINDOW_MASK(bucket, cluster_bound) << 17)
#define WARP_WINDOW_CLOSE(bucket, cluster_bound) (WINDOW_MASK(bucket, cluster_bound) << 29)

/*
 * We test the selection_was_cluster_bound bit and cluster_id field gated
 * on the Edge version of this test case.
 */

SCHED_POLICY_T_DECL(runq_tracepoint_thread_select,
    "Validate emitted MACH_SCHED_CLUTCH_THREAD_SELECT tracepoints")
{
	int ret;
	uint64_t root_bucket_arg;
	uint64_t bucket_is_bound = false;
#if CONFIG_SCHED_EDGE
	init_migration_harness(basic_amp);
	bucket_is_bound = true;
#else /* !CONFIG_SCHED_EDGE */
	init_runqueue_harness();
#endif /* CONFIG_SCHED_EDGE */
	disable_auto_current_thread();

	struct thread_group *same_tg = create_tg(0);
	int num_threads = TH_BUCKET_SCHED_MAX - 1;
	test_thread_t threads[num_threads];
	test_thread_t rev_threads[num_threads];
	test_thread_t warper_threads[num_threads];
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		threads[bucket - 1] = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket]);
		rev_threads[num_threads - bucket] = threads[bucket - 1];
		warper_threads[bucket - 1] = create_thread(bucket, same_tg, root_bucket_to_highest_pri[bucket]);
#if CONFIG_SCHED_EDGE
		set_thread_cluster_bound(threads[bucket - 1], 0);
		set_thread_cluster_bound(warper_threads[bucket - 1], 0);
#endif /* CONFIG_SCHED_EDGE */
	}

	/* Natural EDF */
	enqueue_threads_arr(default_target, num_threads, threads);
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		ret = dequeue_thread_expect(default_target, threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "Root bucket %d failed to warp ahead", bucket);
		root_bucket_arg = SELECTION_WAS_EDF | CTS_VERSION;
#if CONFIG_SCHED_EDGE
		root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
		ret = tracepoint_expect(CLUTCH_THREAD_SELECT, (bucket - 1) * 2, 0, bucket, root_bucket_arg);
		T_QUIET; T_EXPECT_TRUE(ret, "EDF CLUTCH_THREAD_SELECT tracepoint");
	}
	T_QUIET; T_ASSERT_EQ(runqueue_empty(default_target), true, "runqueue_empty");
	SCHED_POLICY_PASS("Correct CLUTCH_THREAD_SELECT tracepoint info for EDF selections");

	/* Warp windows */
	for (int bucket = TH_BUCKET_SHARE_BG; bucket >= TH_BUCKET_SHARE_FG; bucket--) {
		if (bucket < TH_BUCKET_SHARE_BG) {
			increment_mock_time_us(clutch_root_bucket_wcel_us[bucket + 1] - clutch_root_bucket_wcel_us[bucket] + 1);
		}
		enqueue_thread(default_target, warper_threads[bucket - 1]);
		enqueue_thread(default_target, threads[bucket - 1]);
	}
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		/* Opens a new warp window */
		ret = dequeue_thread_expect(default_target, warper_threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "Root bucket %d failed to warp ahead", bucket);
		root_bucket_arg = (bucket < TH_BUCKET_SHARE_BG ? SELECTION_OPENED_WARP_WINDOW : SELECTION_WAS_EDF) | CTS_VERSION;
#if CONFIG_SCHED_EDGE
		root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
		ret = tracepoint_expect(CLUTCH_THREAD_SELECT, bucket * 2 - 1, 0, bucket, root_bucket_arg);
		T_QUIET; T_EXPECT_TRUE(ret, "Open warp window CLUTCH_THREAD_SELECT tracepoint");

		/* Makes use of the opened warp window */
		increment_mock_time_us(clutch_root_bucket_warp_us[bucket] / 2);
		ret = dequeue_thread_expect(default_target, threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "Root bucket %d's warp window failed to stay open", bucket);
		root_bucket_arg = (bucket < TH_BUCKET_SHARE_BG ? 0 : SELECTION_WAS_EDF) | CTS_VERSION;
#if CONFIG_SCHED_EDGE
		root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
		ret = tracepoint_expect(CLUTCH_THREAD_SELECT, bucket * 2 - 2, 0, bucket, root_bucket_arg);
		T_QUIET; T_EXPECT_TRUE(ret, "Active warp window CLUTCH_THREAD_SELECT tracepoint");

		increment_mock_time_us(clutch_root_bucket_warp_us[bucket] / 2 + 1);
	}
	T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	SCHED_POLICY_PASS("Correct CLUTCH_THREAD_SELECT tracepoint info for warp windows");

	/* Starvation avoidance windows */
	for (int bucket = TH_BUCKET_SHARE_BG; bucket >= TH_BUCKET_SHARE_FG; bucket--) {
		if (bucket < TH_BUCKET_SHARE_BG) {
			increment_mock_time_us(clutch_root_bucket_wcel_us[bucket + 1] - clutch_root_bucket_wcel_us[bucket] + 1);
		}
		enqueue_thread(default_target, threads[bucket - 1]);
	}
	for (int bucket = TH_BUCKET_SHARE_BG; bucket >= TH_BUCKET_SHARE_FG; bucket--) {
		ret = dequeue_thread_expect(default_target, threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "Starvation avoidance failed to kick in for bucket %d", bucket);
		root_bucket_arg = SELECTION_WAS_EDF | CTS_VERSION;
#if CONFIG_SCHED_EDGE
		root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
		if (bucket == TH_BUCKET_SHARE_BG) {
			/* Enough time has passed for the warp windows opened in the last phase to be closed in one go */
			for (int warping_bucket = TH_BUCKET_SHARE_FG; warping_bucket < TH_BUCKET_SHARE_BG; warping_bucket++) {
				root_bucket_arg |= WARP_WINDOW_CLOSE(warping_bucket, bucket_is_bound);
			}
		}
		if (bucket > TH_BUCKET_SHARE_FG) {
			root_bucket_arg |= SELECTION_OPENED_STARVATION_AVOIDANCE_WINDOW;
		}
		ret = tracepoint_expect(CLUTCH_THREAD_SELECT, (bucket - 1) * 2, 0, bucket, root_bucket_arg);
		T_QUIET; T_EXPECT_TRUE(ret, "Open starvation avoidance window CLUTCH_THREAD_SELECT tracepoint");
	}
	increment_mock_time_us(clutch_root_bucket_wcel_us[TH_BUCKET_SHARE_BG]);
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		enqueue_thread(default_target, threads[bucket - 1]);
	}
	for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
		ret = dequeue_thread_expect(default_target, threads[bucket - 1]);
		T_QUIET; T_EXPECT_TRUE(ret, "EDF dequeue for bucket %d", bucket);
		root_bucket_arg = SELECTION_WAS_EDF | CTS_VERSION;
#if CONFIG_SCHED_EDGE
		root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
		if (bucket == TH_BUCKET_SHARE_FG) {
			/* Enough time has passed for the starvation avoidance windows opened in the last phase to be closed in one go */
			for (int starved_bucket = TH_BUCKET_SHARE_BG; starved_bucket > TH_BUCKET_SHARE_FG; starved_bucket--) {
				root_bucket_arg |= STARVATION_AVOIDANCE_WINDOW_CLOSE(starved_bucket, bucket_is_bound);
			}
		}
		ret = tracepoint_expect(CLUTCH_THREAD_SELECT, (bucket - 1) * 2, 0, bucket, root_bucket_arg);
		T_QUIET; T_EXPECT_TRUE(ret, "Closing starvation avoidance window or EDF CLUTCH_THREAD_SELECT tracepoint");
	}
	T_QUIET; T_ASSERT_TRUE(runqueue_empty(default_target), "runqueue_empty");
	SCHED_POLICY_PASS("Correct CLUTCH_THREAD_SELECT tracepoint info for starvation avoidance windows");

	/* Different runq traverse modes */
	cpu_set_thread_current(get_default_cpu(), threads[0]);
	enqueue_thread(default_target, threads[1]);
	ret = cpu_dequeue_thread_expect_compare_current(get_default_cpu(), threads[0]);
	T_QUIET; T_EXPECT_TRUE(ret, "EDF dequeue current thread for bucket");
	root_bucket_arg = TRAVERSE_MODE_REMOVE_CONSIDER_CURRENT | SELECTION_WAS_EDF | CTS_VERSION;
#if CONFIG_SCHED_EDGE
	root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 0, 0, TH_BUCKET_SHARE_FG, root_bucket_arg);
	T_QUIET; T_EXPECT_TRUE(ret, "Current thread EDF CLUTCH_THREAD_SELECT tracepoint");
	ret = cpu_check_preempt_current(get_default_cpu(), false);
	T_QUIET; T_EXPECT_TRUE(ret, "Current thread check preempt");
	root_bucket_arg = TRAVERSE_MODE_CHECK_PREEMPT | SELECTION_WAS_EDF | CTS_VERSION;
#if CONFIG_SCHED_EDGE
	root_bucket_arg |= SELECTION_WAS_CLUSTER_BOUND;
#endif /* CONFIG_SCHED_EDGE */
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 0, 0, TH_BUCKET_SHARE_FG, root_bucket_arg);
	T_QUIET; T_EXPECT_TRUE(ret, "Current thread check preempt CLUTCH_THREAD_SELECT tracepoint");
	SCHED_POLICY_PASS("Correct CLUTCH_THREAD_SELECT tracepoint info for current thread (traverse modes)");
#if CONFIG_SCHED_EDGE
	/* Test the cluster_id field */
	test_thread_t bound_thread = create_thread(TH_BUCKET_SHARE_DF, same_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	set_thread_cluster_bound(bound_thread, 1);
	enqueue_thread(cluster_target(1), bound_thread);
	ret = dequeue_thread_expect(cluster_target(1), bound_thread);
	T_QUIET; T_ASSERT_TRUE(ret, "Dequeue single thread on cluster 1");
	root_bucket_arg = SELECTION_WAS_EDF | CTS_VERSION | SELECTION_WAS_CLUSTER_BOUND | CLUSTER_ID(1);
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 10, 0, TH_BUCKET_SHARE_DF, root_bucket_arg);
	T_QUIET; T_EXPECT_TRUE(ret, "Cluster-bound CLUTCH_THREAD_SELECT tracepoint");
	SCHED_POLICY_PASS("CLUTCH_THREAD_SELECT tracepoint handles non-zero cluster id");
#endif /* CONFIG_SCHED_EDGE */
}

SCHED_POLICY_T_DECL(runq_root_bucket_expired_windows,
    "Root bucket warp and starvation avoidance windows should expire at the right time")
{
	int ret;
	uint64_t root_bucket_arg;
	init_runqueue_harness();
	disable_auto_current_thread();

	struct thread_group *same_tg = create_tg(0);
	test_thread_t def_thread = create_thread(TH_BUCKET_SHARE_DF, same_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	test_thread_t in_thread = create_thread(TH_BUCKET_SHARE_IN, same_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_IN]);

	/* Expect user_initiated bucket to warp ahread of starved default bucket */
	enqueue_thread(default_target, def_thread);
	increment_mock_time_us(clutch_root_bucket_wcel_us[TH_BUCKET_SHARE_DF] + 1);
	enqueue_thread(default_target, in_thread);
	ret = dequeue_thread_expect(default_target, in_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = SELECTION_OPENED_WARP_WINDOW | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 1, 0, TH_BUCKET_SHARE_IN, root_bucket_arg);
	T_EXPECT_TRUE(ret, "IN warped ahead, tracepoint");

	/* Expect warp window to close and default starvation avoidance window to begin */
	enqueue_thread(default_target, in_thread);
	increment_mock_time_us(clutch_root_bucket_warp_us[TH_BUCKET_SHARE_IN] + 1);
	ret = dequeue_thread_expect(default_target, def_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = WARP_WINDOW_CLOSE(TH_BUCKET_SHARE_IN, false) | SELECTION_OPENED_STARVATION_AVOIDANCE_WINDOW | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 0, 0, TH_BUCKET_SHARE_DF, root_bucket_arg);
	T_EXPECT_TRUE(ret, "IN closed warp and DEF opened starvation avoidance, tracepoint");

	/* Expect default starvation avoidance window to close and refresh warp for user_initiated with natural EDF */
	enqueue_thread(default_target, def_thread);
	increment_mock_time_us(clutch_root_bucket_wcel_us[TH_BUCKET_SHARE_DF] + 1);
	ret = dequeue_thread_expect(default_target, in_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = STARVATION_AVOIDANCE_WINDOW_CLOSE(TH_BUCKET_SHARE_DF, false) | SELECTION_WAS_EDF | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 1, 0, TH_BUCKET_SHARE_IN, root_bucket_arg);
	T_EXPECT_TRUE(ret, "DEF closed starvation avoidance window and IN refreshed warp, tracepoint");

	/* Expect foreground to warp ahead of starved default bucket */
	increment_mock_time_us(clutch_root_bucket_wcel_us[TH_BUCKET_SHARE_DF] + 1);
	test_thread_t fg_thread = create_thread(TH_BUCKET_SHARE_FG, same_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_FG]);
	enqueue_thread(default_target, fg_thread);
	ret = dequeue_thread_expect(default_target, fg_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = SELECTION_OPENED_WARP_WINDOW | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 2, 0, TH_BUCKET_SHARE_FG, root_bucket_arg);
	T_EXPECT_TRUE(ret, "FG opened warp window, tracepoint");

	/* Expect foreground to close warp window and default to open starvation avoidance window */
	increment_mock_time_us(clutch_root_bucket_warp_us[TH_BUCKET_SHARE_FG] + 1);
	enqueue_thread(default_target, fg_thread);
	ret = dequeue_thread_expect(default_target, def_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = WARP_WINDOW_CLOSE(TH_BUCKET_SHARE_FG, false) | SELECTION_OPENED_STARVATION_AVOIDANCE_WINDOW | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 0, 0, TH_BUCKET_SHARE_DF, root_bucket_arg);
	T_EXPECT_TRUE(ret, "FG closed warp window and DEF opened starvation avoidance window, tracepoint");

	/* Expect default to close starvation avoidance window */
	increment_mock_time_us(clutch_root_bucket_wcel_us[TH_BUCKET_SHARE_DF] + 1);
	enqueue_thread(default_target, def_thread);
	ret = dequeue_thread_expect(default_target, fg_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = STARVATION_AVOIDANCE_WINDOW_CLOSE(TH_BUCKET_SHARE_DF, false) | SELECTION_WAS_EDF | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 2, 0, TH_BUCKET_SHARE_FG, root_bucket_arg);
	T_EXPECT_TRUE(ret, "DEF closed starvation avoidance window and FG refreshed warp, tracepoint");

	/*
	 * Expect user_initiated to experience a full-length warp window
	 * (none spent on expired default starvation avoidance window rdar://120562509)
	 */
	increment_mock_time_us(clutch_root_bucket_wcel_us[TH_BUCKET_SHARE_DF] + 1);
	enqueue_thread(default_target, in_thread);
	ret = dequeue_thread_expect(default_target, in_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = SELECTION_OPENED_WARP_WINDOW | CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 1, 0, TH_BUCKET_SHARE_IN, root_bucket_arg);
	T_EXPECT_TRUE(ret, "IN opened warp window, tracepoint");
	enqueue_thread(default_target, in_thread);
	increment_mock_time_us(clutch_root_bucket_warp_us[TH_BUCKET_SHARE_IN] - 1);
	ret = dequeue_thread_expect(default_target, in_thread);
	T_QUIET; T_EXPECT_TRUE(ret, "unexpected bucket");
	root_bucket_arg = CTS_VERSION;
	ret = tracepoint_expect(CLUTCH_THREAD_SELECT, 1, 0, TH_BUCKET_SHARE_IN, root_bucket_arg);
	T_EXPECT_TRUE(ret, "IN had full-length warp window, tracepoint");

	SCHED_POLICY_PASS("Correct warp/starvation avoidance window expiration");
}

SCHED_POLICY_T_DECL(runq_interactivity_starts_maxed,
    "A new Clutch bucket group should start with max interactivity score")
{
	int ret;
	init_runqueue_harness();

	struct thread_group *non_interactive_tg = create_tg(clutch_interactivity_score_max - 1);
	test_thread_t non_interactive_tg_thread = create_thread(TH_BUCKET_SHARE_DF, non_interactive_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	enqueue_thread(default_target, non_interactive_tg_thread);

	struct thread_group *new_tg = create_tg(INITIAL_INTERACTIVITY_SCORE);
	test_thread_t new_tg_thread = create_thread(TH_BUCKET_SHARE_DF, new_tg, root_bucket_to_highest_pri[TH_BUCKET_SHARE_DF]);
	enqueue_thread(default_target, new_tg_thread);

	ret = dequeue_thread_expect(default_target, new_tg_thread);
	T_EXPECT_TRUE(ret, "New TG Clutch bucket is interactive");

	ret = dequeue_thread_expect(default_target, non_interactive_tg_thread);
	T_EXPECT_TRUE(ret, "Non-interactive thread comes second");

	SCHED_POLICY_PASS("Interactivity score initialized correctly");
}
