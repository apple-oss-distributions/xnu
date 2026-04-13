#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <spawn.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <TargetConditionals.h>
#include <sys/work_interval.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <os/atomic_private.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <perfdata/perfdata.h>
#include "test_utils.h"
#include "sched_test_utils.h"

static const unsigned char sched_thread_group_fairness_workload_config_plist[] = {
#embed "thread_group_fairness_workload_config.plist" suffix(,)
	0,
};

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_TAG_PERF,
    T_META_TAG_VM_NOT_ELIGIBLE);

static const size_t MAX_PDJ_PATH_LEN = 256;
static unsigned int num_cores;

static void
workload_config_load(void)
{
	int ret;
	size_t len = 0;
	ret = sysctlbyname("kern.workload_config", NULL, &len,
	    sched_thread_group_fairness_workload_config_plist,
	    strlen(sched_thread_group_fairness_workload_config_plist));
	if (ret == -1 && errno == ENOENT) {
		T_SKIP("kern.workload_config failed");
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.workload_config");
}

static void
workload_config_cleanup(void)
{
	size_t len = 0;
	sysctlbyname("kern.workload_config", NULL, &len, "", 1);
}

static void
environment_init(void)
{
	num_cores = (unsigned int) dt_ncpu();

	if (platform_is_amp()) {
		/*
		 * Derecommend all clusters except the E cores, to ensure that thread groups
		 * compete over the same cores irrespective of CLPC's cluster recommendations
		 */
		char *clpcctrl_args[] = {"-C", "e", NULL};
		execute_clpcctrl(clpcctrl_args, false);
	}

	/*
	 * Load a test workload plist containing a Workload ID with
	 * WorkloadClass == DISCRETIONARY, in order to mark the thread group
	 * for that workload as THREAD_GROUP_FLAGS_EFFICIENT
	 */
	T_ATEND(workload_config_cleanup);
	workload_config_load();
}

static void
set_work_interval_id(work_interval_t *handle, uint32_t work_interval_flags)
{
	int ret;
	mach_port_t port = MACH_PORT_NULL;

	ret = work_interval_copy_port(*handle, &port);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_copy_port");

	struct work_interval_workload_id_params wlid_params = {
		.wlidp_flags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.wlidp_wicreate_flags = work_interval_flags,
		.wlidp_name = (uintptr_t)"com.test.myapp.discretionary",
	};

	ret = __work_interval_ctl(WORK_INTERVAL_OPERATION_SET_WORKLOAD_ID, port, &wlid_params, sizeof(wlid_params));
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "WORK_INTERVAL_OPERATION_SET_WORKLOAD_ID");
}

static uint32_t
make_work_interval(work_interval_t *handle, uint32_t work_type_flags)
{
	int ret;
	uint32_t work_interval_flags = WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_FLAG_GROUP | work_type_flags;
	ret = work_interval_create(handle, work_interval_flags);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create");

	if (work_type_flags & WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID) {
		set_work_interval_id(handle, work_interval_flags);
	}
	return work_interval_flags;
}

struct thread_data {
	work_interval_t *handle;
	uint32_t work_interval_flags;
};

static void *
spin_thread_fn(void *arg)
{
	struct thread_data *info = (struct thread_data *)arg;
	int ret;

	/* Join the thread group associated with the work interval handle */
	ret = work_interval_join(*(info->handle));
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_join");

	/* Spin indefinitely */
	volatile uint64_t spin_count = 0;
	while (mach_absolute_time() < UINT64_MAX) {
		spin_count++;
	}
	return NULL;
}

static void
start_threads(pthread_t *threads, struct thread_data *thread_datas, work_interval_t *handle, uint32_t work_interval_flags)
{
	int ret;
	for (unsigned int i = 0; i < num_cores; i++) {
		thread_datas[i].handle = handle;
		thread_datas[i].work_interval_flags = work_interval_flags;
		ret = pthread_create(&threads[i], NULL, spin_thread_fn, &thread_datas[i]);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create");
	}
}

static uint64_t
snapshot_user_time_usec(pthread_t *threads)
{
	kern_return_t kr;
	uint64_t cumulative_user_time_usec = 0;
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	for (unsigned int i = 0; i < num_cores; i++) {
		mach_port_t thread_port = pthread_mach_thread_np(threads[i]);
		thread_basic_info_data_t info;
		kr = thread_info(thread_port, THREAD_BASIC_INFO, (thread_info_t)&info, &count);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");
		uint64_t thread_usr_usec = (uint64_t) (info.user_time.seconds) * USEC_PER_SEC + (uint64_t) info.user_time.microseconds;
		cumulative_user_time_usec += thread_usr_usec;
	}
	return cumulative_user_time_usec;
}

T_DECL(thread_group_fairness,
    "Ensure that thread groups tagged as higher priority do not starve out "
    "thread groups tagged as lower priority when both behave as CPU spinners",
    T_META_ASROOT(YES),
    XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL)
{
	T_SETUPBEGIN;

	wait_for_quiescence_default(argc, argv);
	environment_init();

	/*
	 * Create two work intervals with corresponding thread groups that would
	 * be associated with differing priorities.
	 */
	work_interval_t lower_pri_handle, higher_pri_handle;
	uint32_t lower_pri_flags = make_work_interval(&lower_pri_handle, WORK_INTERVAL_TYPE_DEFAULT | WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID);
	uint32_t higher_pri_flags = make_work_interval(&higher_pri_handle, WORK_INTERVAL_TYPE_DEFAULT);

	/* Start threads to join the lower priority thread group */
	pthread_t lower_threads[num_cores];
	struct thread_data lower_thread_datas[num_cores];
	start_threads(lower_threads, lower_thread_datas, &lower_pri_handle, lower_pri_flags);

	/* Start threads to join the higher priority thread group  */
	pthread_t higher_threads[num_cores];
	struct thread_data higher_thread_datas[num_cores];
	start_threads(higher_threads, higher_thread_datas, &higher_pri_handle, higher_pri_flags);

	T_SETUPEND;

	/* Snapshot thread runtimes */
	uint64_t start_lower_priority_runtime_usec = snapshot_user_time_usec(lower_threads);
	uint64_t start_higher_priority_runtime_usec = snapshot_user_time_usec(higher_threads);

	/* Allow thread groups time to compete */
	sleep(3);

	/*
	 * Snapshot runtimes again and compare the usage ratio between the lower and
	 * higher priority thread groups, to determine whether the lower priority group
	 * has been starved
	 */
	uint64_t finish_lower_priority_runtime_usec = snapshot_user_time_usec(lower_threads);
	uint64_t finish_higher_priority_runtime_usec = snapshot_user_time_usec(higher_threads);

	uint64_t lower_priority_runtime = finish_lower_priority_runtime_usec - start_lower_priority_runtime_usec;
	uint64_t higher_priority_runtime = finish_higher_priority_runtime_usec - start_higher_priority_runtime_usec;

	T_QUIET; T_ASSERT_GT(lower_priority_runtime, 10000LL, "lower priority thread group got at least 10ms of CPU time");
	T_QUIET; T_ASSERT_GT(higher_priority_runtime, 10000LL, "higher priority thread group got at least 10ms of CPU time");

	/* Record the observed runtime ratio */
	char pdj_path[MAX_PDJ_PATH_LEN];
	pdwriter_t writer = pdwriter_open_tmp("xnu", "scheduler.thread_group_fairness", 0, 0, pdj_path, MAX_PDJ_PATH_LEN);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(writer, "pdwriter_open_tmp");

	double runtime_ratio_value;
	double total_runtime = (double)(lower_priority_runtime + higher_priority_runtime);
	if (lower_priority_runtime <= higher_priority_runtime) {
		runtime_ratio_value = (double)(lower_priority_runtime) / total_runtime;
	} else {
		runtime_ratio_value = (double)(higher_priority_runtime) / total_runtime;
	}
	T_LOG("Observed timeshare ratio: %f", runtime_ratio_value);

	pdwriter_new_value(writer, "Thread Group Runtime Ratio", PDUNIT_CUSTOM(runtime_ratio), runtime_ratio_value);
	pdwriter_record_larger_better(writer);
	pdwriter_close(writer);
	/* Ensure that the perfdata file can be copied by BATS */
	T_QUIET; T_ASSERT_POSIX_ZERO(chmod(pdj_path, 0644), "chmod");

	T_END;
}

static uint64_t
get_thread_group_cpu_time(int sched_bucket)
{
	int ret;
	uint64_t cpu_stats[2];
	size_t cpu_stats_len = sizeof(uint64_t) * 2;
	ret = sysctlbyname("kern.clutch_bucket_group_cpu_stats", cpu_stats, &cpu_stats_len,
	    &sched_bucket, sizeof(sched_bucket));
	if (ret != 0 && errno == ENOTSUP) {
		T_LOG("Test only supported on Clutch/Edge scheduler (current policy is \"%s\") "
		    "platforms on development/debug build variants", platform_sched_policy());
		T_SKIP("kern.clutch_bucket_group_cpu_stats development-only sysctl not present");
	}
	T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "kern.clutch_bucket_group_cpu_stats");
	return cpu_stats[0];
}

static volatile uint64_t mach_deadline = 0;
static const int seconds = 2;
static _Atomic volatile uint64_t count = 0;
static const int iters_per_lock_hold = 100000;
static const int low_qos = QOS_CLASS_USER_INITIATED;
static const int low_sched_bucket = 2; // TH_BUCKET_SHARE_IN
static const int high_qos = QOS_CLASS_USER_INTERACTIVE;
static const int high_sched_bucket = 1; // TH_BUCKET_SHARE_FG
static _Atomic volatile bool recorder_picked = false;

static void *
boost_while_working(void *arg)
{
	int ret;
	work_interval_t wi = (work_interval_t)arg;
	ret = work_interval_join(wi);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_join");

	bool is_recorder = os_atomic_cmpxchg(&recorder_picked, false, true, relaxed);
	uint64_t cpu_time_begin_low = 0;
	uint64_t cpu_time_begin_high = 0;
	if (is_recorder) {
		cpu_time_begin_low = get_thread_group_cpu_time(low_sched_bucket);
		cpu_time_begin_high = get_thread_group_cpu_time(high_sched_bucket);
	}

	while (mach_absolute_time() < mach_deadline) {
		/* Assume high priority */
		ret = pthread_set_qos_class_self_np(high_qos, 0);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_set_qos_class_self_np UI");
		T_QUIET; T_ASSERT_EQ(qos_class_self(), high_qos, "qos_class_self");
		/* Complete a "work item" */
		for (volatile int i = 0; i < iters_per_lock_hold; i++) {
			os_atomic_inc(&count, relaxed);
		}
		/* Drop priority down before parking to sleep */
		ret = pthread_set_qos_class_self_np(low_qos, 0);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_set_qos_class_self_np IN");
		T_QUIET; T_ASSERT_EQ(qos_class_self(), low_qos, "qos_class_self");
		usleep(2 * 1000); // 2ms
	}

	if (is_recorder) {
		uint64_t cpu_time_end_low = get_thread_group_cpu_time(low_sched_bucket);
		uint64_t cpu_time_end_high = get_thread_group_cpu_time(high_sched_bucket);

		T_QUIET; T_ASSERT_GE(cpu_time_end_high, cpu_time_begin_high,
		    "non-monotonic thread group CPU time");
		uint64_t high_cpu_time = cpu_time_end_high - cpu_time_begin_high;
		T_QUIET; T_ASSERT_GE(cpu_time_end_low, cpu_time_begin_low,
		    "non-monotonic thread group CPU time");
		uint64_t low_cpu_time = cpu_time_end_low - cpu_time_begin_low;

		T_QUIET; T_ASSERT_GT(high_cpu_time + low_cpu_time, 0ULL,
		    "CPU not attributed to either expected bucket");
		T_LOG("High ticks: %llu, Low ticks: %llu, High-to-low ratio: %.3f",
		    high_cpu_time, low_cpu_time, high_cpu_time * 1.0 / (high_cpu_time + low_cpu_time));
		T_EXPECT_GE(high_cpu_time, low_cpu_time, "More work accounted to the high QoS");
		T_EXPECT_LE(low_cpu_time * 1.0, high_cpu_time * 0.2,
		    "Vast majority of work accounted to the high QoS");
	}
	return NULL;
}

/*
 * Note, preemption due to non-test threads poses a special problem for
 * this test because time the test threads spend preempted at their low
 * QoS, in between processing work items, translates to "blocked" time
 * for the thread group at its high QoS. This leads to CPU usage aging
 * out more quickly for the high QoS, causing the test to fail.
 *
 * Additionally, the test must be run like an application in the QoS
 * engine, without a QoS ceiling which would prevent the test threads
 * from performing adequately high QoS boosts. For example:
 * sudo taskpolicy -a ./thread_group_fairness -n interactivity_cpu_accounting
 */
T_DECL(interactivity_cpu_accounting,
    "Ensure that CPU runtime tracked for calculating interactivity score "
    "gets attributed to the right QoS that performed the work, even if we "
    "switch QoS while on-core (rdar://125045167)",
    T_META_ENABLED(TARGET_CPU_ARM64 && !TARGET_OS_BRIDGE),
#if TARGET_OS_WATCH
    T_META_MAYFAIL("Watches too noisy with high priority spinners (rdar://150323037)"),
#elif TARGET_OS_TV
    T_META_MAYFAIL("TVs too noisy with high priority audio (rdar://149974201)"),
#endif
    T_META_ASROOT(YES))
{
	/* Skips the test if needed sysctl isn't present */
	get_thread_group_cpu_time(0);

	/* Ensure we don't have a QoS ceiling that would prevent high enough boosts */
	struct task_policy_state policy_state;
	mach_msg_type_number_t count = TASK_POLICY_STATE_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t kr = task_policy_get(mach_task_self(), TASK_POLICY_STATE,
	    (task_policy_t)&policy_state, &count, &get_default);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_policy_get(self, TASK_POLICY_STATE)");
	int requested_app_type = (policy_state.requested & POLICY_REQ_APPTYPE_MASK) >> POLICY_REQ_APPTYPE_SHIFT;
	T_QUIET; T_ASSERT_EQ(requested_app_type, TASK_APPTYPE_APP_DEFAULT,
	    "Test needs to be run like an application for QoS boosting above pri 37 to succeed");

	wait_for_quiescence(argc, argv, 0.9, 10);

	trace_handle_t trace = begin_collect_trace(argc, argv, T_NAME);
	T_SETUPEND;

	if (platform_is_amp()) {
		/*
		 * Isolate-out the effects of cluster recommendation, since that
		 * causes threads to be preempted sometimes for rebalancing purposes.
		 */
		char *clpcctrl_args[] = {"-C", "p", NULL};
		execute_clpcctrl(clpcctrl_args, false);
	}

	mach_deadline = mach_absolute_time() + nanos_to_abs(seconds * NSEC_PER_SEC);

	/*
	 * Create threads in their own TG that will run work at "boosted"
	 * priority and after a work item is complete, lower their
	 * priority back down to a low QoS before "parking" via usleep().
	 *
	 * We expect that the interactivity score for the high QoS for this
	 * TG will be the one to lower, rather than the low QoS which the
	 * threads are switching down to before context-switching off-core.
	 */
	int num_boosters = MIN(4, dt_ncpu());
	work_interval_t wi_handle;
	make_work_interval(&wi_handle, WORK_INTERVAL_TYPE_DEFAULT);
	pthread_t threads[num_boosters];
	for (int i = 0; i < num_boosters; i++) {
		create_thread(&threads[i], NULL, boost_while_working, wi_handle);
	}

	/*
	 * Wait for test deadline to pass, to avoid priority boosting
	 * with pthread_join(), which would affect the results.
	 */
	uint64_t curr_time = mach_absolute_time();
	if (curr_time < mach_deadline) {
		usleep(abs_to_nanos(mach_deadline - curr_time) / NSEC_PER_USEC);
	}
	for (int i = 0; i < num_boosters; i++) {
		pthread_join(threads[i], NULL);
	}

	if (platform_is_amp()) {
		/* Reenable all cores to speed up trace post-processing */
		char *recommend_all_cores_args[] = {"-C", "all", NULL};
		execute_clpcctrl(recommend_all_cores_args, false);
	}
	end_collect_trace(trace);
}
