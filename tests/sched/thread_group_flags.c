// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/resource_private.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <stdatomic.h>
#include <sys/work_interval.h>
#include <ktrace.h>
#include <sys/kdebug.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define CONFIG_THREAD_GROUPS 1
typedef void *cluster_type_t;
#include "../../osfmk/kern/thread_group.h"

#include "thread_group_flags_workload_config.h"


T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_REQUIRES_SYSCTL_EQ("kern.thread_groups_supported", 1));


static void
workload_config_load(void)
{
	int ret;
	size_t len = 0;
	ret = sysctlbyname("kern.workload_config", NULL, &len,
	    sched_thread_group_flags_workload_config_plist,
	    sched_thread_group_flags_workload_config_plist_len);
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
set_work_interval_id(work_interval_t *handle, uint32_t work_interval_flags, char *workload_id)
{
	int ret;
	mach_port_t port = MACH_PORT_NULL;

	ret = work_interval_copy_port(*handle, &port);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_copy_port");

	struct work_interval_workload_id_params wlid_params = {
		.wlidp_flags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.wlidp_wicreate_flags = work_interval_flags,
		.wlidp_name = (uintptr_t)workload_id,
	};

	ret = __work_interval_ctl(WORK_INTERVAL_OPERATION_SET_WORKLOAD_ID, port, &wlid_params, sizeof(wlid_params));
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "WORK_INTERVAL_OPERATION_SET_WORKLOAD_ID");
}

static void
make_work_interval(work_interval_t *handle, uint32_t work_type_flags, char *workload_id)
{
	int ret;
	uint32_t work_interval_flags = WORK_INTERVAL_FLAG_JOINABLE | WORK_INTERVAL_FLAG_GROUP | work_type_flags;
	ret = work_interval_create(handle, work_interval_flags);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "work_interval_create");

	if (work_type_flags & WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID) {
		set_work_interval_id(handle, work_interval_flags, workload_id);
	}
}

static uint64_t
get_thread_group_id(void)
{
	int ret;
	uint64_t tg_id;
	size_t tg_id_len = sizeof(tg_id);
	ret = sysctlbyname("kern.thread_group_id", &tg_id, &tg_id_len, NULL, 0);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "kern.thread_group_id");
	return tg_id;
}

struct thread_data {
	work_interval_t wi_handle;
	uint64_t tg_id;
};

static void *
join_workload_fn(void *arg)
{
	int ret;
	struct thread_data *data = (struct thread_data *)arg;

	uint64_t old_tg_id = get_thread_group_id();

	/* Join the thread group associated with the work interval handle */
	ret = work_interval_join(data->wi_handle);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "work_interval_join");

	data->tg_id = get_thread_group_id();
	T_LOG("Joined TG %llx", data->tg_id);
	T_QUIET; T_EXPECT_NE(data->tg_id, old_tg_id, "Thread failed to join new TG");
	return NULL;
}

static pthread_t *
start_threads(void *(*func)(void *), struct thread_data *datas, int num_threads)
{
	int ret;
	pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
	pthread_attr_t attr;
	ret = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_attr_init");
	for (int i = 0; i < num_threads; i++) {
		struct sched_param param = { .sched_priority = 31 };
		ret = pthread_attr_setschedparam(&attr, &param);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_attr_setschedparam");
		ret = pthread_create(&threads[i], &attr, func, (void *)&datas[i]);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create");
	}
	return threads;
}

static void
start_test(ktrace_session_t session, pthread_t *threads, int num_threads)
{
	dispatch_async(dispatch_get_main_queue(), ^{
		/* Wait for threads to finish, as last test action */
		for (int i = 0; i < num_threads; i++) {
		        int ret = pthread_join(threads[i], NULL);
		        T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_join");
		}
		ktrace_end(session, 0);
	});
	dispatch_main();
}

static char *trace_location = NULL;

static void
delete_trace_file(void)
{
	if (T_FAILCOUNT == 0) {
		T_LOG("Test passed, so deleting \"%s\" to save memory", trace_location);
		int ret;
		/* Delete trace file in order to reclaim disk space on the test device */
		ret = remove(trace_location);
		T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "remove trace file");
	}
}

static char *
make_ktrace_filepath(char *short_name)
{
	int ret;
	char *filepath = (char *)malloc(sizeof(char) * MAXPATHLEN);
	snprintf(filepath, MAXPATHLEN, "%s/%s.ktrace", dt_tmpdir(), short_name);
	ret = remove(filepath);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_TRUE((ret == 0) || (errno == ENOENT), "remove");
	return filepath;
}

static const int num_workload_ids = 5;
static char *workload_ids[num_workload_ids] = {
	"com.test.myapp.efficient",
	"com.test.myapp.best_effort",
	"com.test.myapp.application",
	"com.test.myapp.critical",
	"com.test.myapp.shared_flags",
};

static uint64_t expected_tg_flags[num_workload_ids] = {
	THREAD_GROUP_FLAGS_EFFICIENT,
	THREAD_GROUP_FLAGS_BEST_EFFORT,
	THREAD_GROUP_FLAGS_APPLICATION,
	THREAD_GROUP_FLAGS_CRITICAL,
#if TARGET_OS_XR
	THREAD_GROUP_FLAGS_MANAGED | THREAD_GROUP_FLAGS_STRICT_TIMERS | THREAD_GROUP_FLAGS_APPLICATION,
#else /* !TARGET_OS_XR */
	THREAD_GROUP_FLAGS_APPLICATION,
#endif /* !TARGET_OS_XR */
};

static int
tg_id_to_index(struct thread_data *datas, int num_datas, uint64_t tg_id)
{
	int index = -1;
	for (int i = 0; i < num_datas; i++) {
		if (tg_id == datas[i].tg_id) {
			index = i;
			break;
		}
	}
	return index;
}

static void
search_for_workload_id_tg_flags_tracepoints(char *trace_path, int num_workload_ids, struct thread_data *datas)
{
	__block int ret;
	trace_location = trace_path;
	T_ATEND(delete_trace_file);
	ktrace_session_t read_session = ktrace_session_create();
	ret = ktrace_set_file(read_session, trace_path);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_set_file");
	__block int num_validated_new_tgs = 0;
	ktrace_events_single(read_session, MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NEW), ^(ktrace_event_t e) {
		ret = ktrace_print_trace_point(stdout, read_session, e, KTP_KIND_CSV,
		KTP_FLAG_WALLTIME | KTP_FLAG_THREADNAME | KTP_FLAG_PID | KTP_FLAG_EVENTNAME | KTP_FLAG_EXECNAME);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ktrace_print_trace_point output");
		printf("\n"); // Flush output from ktrace_print_trace_point
		uint64_t tg_id = e->arg1;
		uint64_t tg_flags = e->arg2;
		int workload_ind = tg_id_to_index(datas, num_workload_ids, tg_id);
		if (workload_ind != -1) {
		        T_LOG("MACH_THREAD_GROUP_NEW tracepoint from TG %llx with flags %llx, expecting %llx", tg_id, tg_flags, expected_tg_flags[workload_ind]);
		        T_EXPECT_EQ(tg_flags, expected_tg_flags[workload_ind], "Correct new TG flags for \"%s\"", workload_ids[workload_ind]);
		        num_validated_new_tgs++;
		}
	});
	__block int num_validated_flags = 0;
	ktrace_events_single(read_session, MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS), ^(ktrace_event_t e) {
		ret = ktrace_print_trace_point(stdout, read_session, e, KTP_KIND_CSV,
		KTP_FLAG_WALLTIME | KTP_FLAG_THREADNAME | KTP_FLAG_PID | KTP_FLAG_EVENTNAME | KTP_FLAG_EXECNAME);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ktrace_print_trace_point output");
		printf("\n"); // Flush output from ktrace_print_trace_point
		uint64_t tg_id = e->arg1;
		uint64_t tg_flags = e->arg2;
		int workload_ind = tg_id_to_index(datas, num_workload_ids, tg_id);
		if (workload_ind != -1) {
		        T_LOG("MACH_THREAD_GROUP_FLAGS tracepoint from TG %llx with flags %llx, expecting %llx", tg_id, tg_flags, expected_tg_flags[workload_ind]);
		        T_EXPECT_EQ(tg_flags, expected_tg_flags[workload_ind], "Correct TG flags for \"%s\"", workload_ids[workload_ind]);
		        T_QUIET; T_EXPECT_EQ(e->arg3, 0ULL, "tracepoint not dropped at TG creation time");
		        num_validated_flags++;
		}
	});
	__block int num_validated_joins = 0;
	ktrace_events_single(read_session, MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET), ^(ktrace_event_t e) {
		uint64_t new_tg_id = e->arg2;
		int workload_ind = tg_id_to_index(datas, num_workload_ids, new_tg_id);
		if (workload_ind != -1) {
		        ret = ktrace_print_trace_point(stdout, read_session, e, KTP_KIND_CSV,
		        KTP_FLAG_WALLTIME | KTP_FLAG_THREADNAME | KTP_FLAG_PID | KTP_FLAG_EVENTNAME | KTP_FLAG_EXECNAME);
		        T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ktrace_print_trace_point output");
		        printf("\n"); // Flush output from ktrace_print_trace_point
		        T_LOG("MACH_THREAD_GROUP_SET tracepoint for joining TG %llx", new_tg_id);
		        num_validated_joins++;
		}
	});
	ktrace_set_completion_handler(read_session, ^{
		T_EXPECT_EQ(num_validated_new_tgs, num_workload_ids, "Found all expected MACH_THREAD_GROUP_NEW tracepoints");
		T_EXPECT_EQ(num_validated_flags, num_workload_ids, "Found all expected MACH_THREAD_GROUP_FLAGS tracepoints");
		T_EXPECT_EQ(num_validated_joins, num_workload_ids, "Found all expected MACH_THREAD_GROUP_SET tracepoints");
		T_END;
	});
	ret = ktrace_start(read_session, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start");
}

static const char *THREAD_GROUP_FILTER = "S0x01A6";

T_DECL(thread_group_flags_from_workload_properties,
    "Verify that workload properties correctly propagate thread group flags",
    T_META_ASROOT(true))
{
	int ret;
	T_ATEND(workload_config_cleanup);
	workload_config_load();

	ktrace_session_t session = ktrace_session_create();
	char *filepath = make_ktrace_filepath("thread_group_flags_from_workload_properties");

	ret = ktrace_events_filter(session, THREAD_GROUP_FILTER, ^(__unused ktrace_event_t event){});
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_events_filter");
	__block struct thread_data *datas = (struct thread_data *)calloc(num_workload_ids, sizeof(struct thread_data));
	ktrace_set_completion_handler(session, ^{
		search_for_workload_id_tg_flags_tracepoints(filepath, num_workload_ids, datas);
	});
	ret = ktrace_start_writing_path(session, filepath, 0);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start_writing_path");
	T_LOG("Ktrace file being written to %s", filepath);

	/* Create a work interval for each test workload id */
	work_interval_t wi_handles[num_workload_ids];
	for (int w = 0; w < num_workload_ids; w++) {
		make_work_interval(&wi_handles[w], WORK_INTERVAL_TYPE_DEFAULT | WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID, workload_ids[w]);
	}
	for (int i = 0; i < num_workload_ids; i++) {
		datas[i].wi_handle = wi_handles[i];
	}
	__block pthread_t *threads = start_threads(join_workload_fn, datas, num_workload_ids);
	start_test(session, threads, num_workload_ids);
}

static void *
join_leave_pid_based(void *arg)
{
	int ret;
	struct thread_data *data = (struct thread_data *)arg;
	data->tg_id = get_thread_group_id();

	ret = setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "set_priority(PRIO_DARWIN_CARPLAY_MODE_ON)");

	ret = setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "set_priority(PRIO_DARWIN_CARPLAY_MODE_OFF)");

	ret = setpriority(PRIO_DARWIN_GAME_MODE, 0, PRIO_DARWIN_GAME_MODE_ON);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "set_priority(PRIO_DARWIN_GAME_MODE_ON)");

	ret = setpriority(PRIO_DARWIN_GAME_MODE, 0, PRIO_DARWIN_GAME_MODE_OFF);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "set_priority(PRIO_DARWIN_GAME_MODE_OFF)");

	T_EXPECT_EQ(data->tg_id, get_thread_group_id(), "Unchanged TG");
	return NULL;
}

static void
search_for_pid_based_tg_flags_tracepoints(char *trace_path, int num_threads, struct thread_data *datas)
{
	__block int ret;
	trace_location = trace_path;
	T_ATEND(delete_trace_file);
	ktrace_session_t read_session = ktrace_session_create();
	ret = ktrace_set_file(read_session, trace_path);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_set_file");
	__block int tracepoint_idx = 0;
	ktrace_events_single(read_session, MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS), ^(ktrace_event_t e) {
		ret = ktrace_print_trace_point(stdout, read_session, e, KTP_KIND_CSV,
		KTP_FLAG_WALLTIME | KTP_FLAG_THREADNAME | KTP_FLAG_PID | KTP_FLAG_EVENTNAME | KTP_FLAG_EXECNAME);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ktrace_print_trace_point output");
		printf("\n"); // Flush output from ktrace_print_trace_point
		uint64_t tg_id = e->arg1;
		uint64_t new_tg_flags = e->arg2;
		uint64_t old_tg_flags = e->arg3;
		int data = tg_id_to_index(datas, num_workload_ids, tg_id);
		if (data != -1) {
		        T_LOG("MACH_THREAD_GROUP_FLAGS tracepoint from TG %llx with new flags %llx from old flags %llx", tg_id, new_tg_flags, old_tg_flags);
		        bool had_carplay = old_tg_flags & THREAD_GROUP_FLAGS_CARPLAY_MODE;
		        bool has_carplay = new_tg_flags & THREAD_GROUP_FLAGS_CARPLAY_MODE;
		        bool had_gamemode = old_tg_flags & THREAD_GROUP_FLAGS_GAME_MODE;
		        bool has_gamemode = new_tg_flags & THREAD_GROUP_FLAGS_GAME_MODE;
		        switch (tracepoint_idx) {
			case 0:
				T_QUIET; T_EXPECT_TRUE(!had_gamemode && !has_gamemode, "Game Mode on");
				T_EXPECT_TRUE(!had_carplay && has_carplay, "Correct flags for Car Play");
				break;
			case 1:
				T_QUIET; T_EXPECT_TRUE(!had_gamemode && !has_gamemode, "Game Mode on");
				T_EXPECT_TRUE(had_carplay && !has_carplay, "Correct flags for disabled Car Play");
				break;
			case 2:
				T_QUIET; T_EXPECT_TRUE(!had_carplay && !has_carplay, "Car Play on");
				T_EXPECT_TRUE(!had_gamemode && has_gamemode, "Correct flags for Game Mode");
				break;
			case 3:
				T_QUIET; T_EXPECT_TRUE(!had_carplay && !has_carplay, "Car Play on");
				T_EXPECT_TRUE(had_gamemode && !has_gamemode, "Correct flags for disabled Game Mode");
				break;
			}
		        T_QUIET; T_EXPECT_FALSE(new_tg_flags & THREAD_GROUP_FLAGS_EFFICIENT, "Test runner TG should not be efficient");
		        tracepoint_idx++;
		}
	});
	ktrace_set_completion_handler(read_session, ^{
		T_EXPECT_EQ(tracepoint_idx, 4, "Found all expected MACH_THREAD_GROUP_FLAGS tracepoints");
		T_END;
	});
	ret = ktrace_start(read_session, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start");
}

T_DECL(thread_group_flags_from_pid_interfaces,
    "Verify that Car Play and Game Mode correctly propagate thread group flags",
    T_META_ASROOT(true))
{
	int ret;
	int num_threads = 1;

	ktrace_session_t session = ktrace_session_create();
	char *filepath = make_ktrace_filepath("thread_group_flags_from_pid_interfaces");

	ret = ktrace_events_filter(session, THREAD_GROUP_FILTER, ^(__unused ktrace_event_t event){});
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_events_filter");
	__block struct thread_data *datas = (struct thread_data *)calloc(num_threads, sizeof(struct thread_data));
	ktrace_set_completion_handler(session, ^{
		search_for_pid_based_tg_flags_tracepoints(filepath, num_threads, datas);
	});
	ret = ktrace_start_writing_path(session, filepath, 0);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start_writing_path");
	T_LOG("Ktrace file being written to %s", filepath);

	__block pthread_t *threads = start_threads(join_leave_pid_based, datas, num_threads);
	start_test(session, threads, num_threads);
}
