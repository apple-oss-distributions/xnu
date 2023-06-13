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

#include <darwintest.h>
#include <perfdata/perfdata.h>

extern unsigned char sched_thread_group_fairness_workload_config_plist[];
extern unsigned int sched_thread_group_fairness_workload_config_plist_len;

#include "sched_thread_group_fairness_workload_config.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_TAG_PERF);

static const size_t MAX_PDJ_PATH_LEN = 256;
static unsigned int num_cores;
static unsigned int num_perf_levels;

static bool
platform_is_amp(void)
{
	if (num_perf_levels != 0) {
		return num_perf_levels > 1;
	}
	int ret;
	num_perf_levels = 0;
	ret = sysctlbyname("hw.nperflevels", &num_perf_levels, &(size_t){ sizeof(num_perf_levels) }, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "hw.nperflevels");
	return num_perf_levels > 1;
}

static unsigned int
get_ncpu(void)
{
	int ret;
	int ncpu;
	char cpu_sysctl_name[32];
	if (platform_is_amp()) {
		sprintf(cpu_sysctl_name, "hw.perflevel%u.logicalcpu", num_perf_levels - 1);
	} else {
		sprintf(cpu_sysctl_name, "hw.ncpu");
	}
	ret = sysctlbyname(cpu_sysctl_name, &ncpu, &(size_t){ sizeof(ncpu) }, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "%s", cpu_sysctl_name);
	return (unsigned int) ncpu;
}

extern char **environ;

static void
execute_clpcctrl(char *const clpcctrl_args[])
{
	int ret, pid;
	ret = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, environ);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn");
	waitpid(pid, &ret, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "waitpid");
}

static void
clpcctrl_cleanup(void)
{
	char *const recommend_all_cores_args[] = {"/usr/local/bin/clpcctrl", "-C", "all", NULL};
	execute_clpcctrl(recommend_all_cores_args);
	char *const restore_dynamic_control_args[] = {"/usr/local/bin/clpcctrl", "-d", NULL};
	execute_clpcctrl(restore_dynamic_control_args);
}

static void
workload_config_load(void)
{
	int ret;
	size_t len = 0;
	ret = sysctlbyname("kern.workload_config", NULL, &len,
	    sched_thread_group_fairness_workload_config_plist,
	    sched_thread_group_fairness_workload_config_plist_len);
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
	num_cores = get_ncpu();

	if (platform_is_amp()) {
		/*
		 * Derecommend all clusters except the E cores, to ensure that thread groups
		 * compete over the same cores irrespective of CLPC's cluster recommendations
		 */
		T_ATEND(clpcctrl_cleanup);
		char *const clpcctrl_args[] = {"/usr/local/bin/clpcctrl", "-C", "e", NULL};
		execute_clpcctrl(clpcctrl_args);
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
    T_META_ASROOT(YES))
{
	T_SETUPBEGIN;

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

	pdwriter_new_value(writer, "Thread Group Runtime Ratio", PDUNIT_CUSTOM(runtime_ratio), runtime_ratio_value);
	pdwriter_record_larger_better(writer);
	pdwriter_close(writer);
	/* Ensure that the perfdata file can be copied by BATS */
	T_QUIET; T_ASSERT_POSIX_ZERO(chmod(pdj_path, 0644), "chmod");

	T_END;
}
