// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <stdatomic.h>
#include <sys/work_interval.h>
#include <ktrace.h>
#include <sys/kdebug.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"));

static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	mach_timebase_info(&timebase_info);
	return nanos * timebase_info.denom / timebase_info.numer;
}

static uint64_t
abs_to_nanos(uint64_t abs)
{
	mach_timebase_info(&timebase_info);
	return abs * timebase_info.numer / timebase_info.denom;
}

static int BACKGROUND_PRI;
static int NUM_THREADS;
static uint64_t SLEEP_SECONDS;
static uint64_t INTERRUPT_DISABLE_TIMEOUT_NS;

static uint64_t start_timestamp = 0ULL;
static volatile int sum = 0; // Keeps the spin-loop below from compiling-out

static void *
make_tg_and_spin(__unused void *arg)
{
	int ret;
	assert(SLEEP_SECONDS > 2);

	/* Create and join a new thread group (TG) */
	work_interval_t wi_handle;
	ret = work_interval_create(&wi_handle, WORK_INTERVAL_FLAG_GROUP);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, 0, "work_interval_create");

	/* Allow other threads a chance to get on-core and create/join their own TGs */
	uint64_t yield_deadline = start_timestamp + nanos_to_abs(1 * NSEC_PER_SEC);
	while (mach_absolute_time() < yield_deadline) {
		sched_yield();
	}

	/*
	 * Remain runnable long enough for the sched_maintenance_thread to scan the
	 * many created TGs all at the same time in one scheduler tick.
	 */
	uint64_t spin_deadline = start_timestamp + nanos_to_abs((SLEEP_SECONDS - 2) * NSEC_PER_SEC);
	while (mach_absolute_time() < spin_deadline) {
		sum++;
	}

	/*
	 * Terminate with about a second to spare of SLEEP_SECONDS, so that we have
	 * time to bring down the number of runnable thread groups before the test
	 * case reenables the previous kern.interrupt_masked_debug_mode value.
	 * Otherwise, a system failing this test could panic.
	 */
	return NULL;
}

static void
start_threads(pthread_t *threads, void *(*start_routine)(void *), int priority, int num_threads)
{
	int rv;
	pthread_attr_t attr;

	rv = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_init");

	for (int i = 0; i < num_threads; i++) {
		struct sched_param param = { .sched_priority = priority };

		rv = pthread_attr_setschedparam(&attr, &param);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_setschedparam");

		rv = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_setdetachstate");

		/* Make the thread stacks smaller, so pthread will let us make more */
		rv = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_setstacksize");

		rv = pthread_create(&threads[i], &attr, start_routine, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_create");
	}

	rv = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(rv, "pthread_attr_destroy");
}

static uint64_t old_preemption_debug_mode = 0;
static size_t old_preemption_debug_mode_size = sizeof(old_preemption_debug_mode);

static void
restore_preemption_disable_debug_mode(void)
{
	int ret = sysctlbyname("kern.sched_preemption_disable_debug_mode", NULL, NULL,
	    &old_preemption_debug_mode, old_preemption_debug_mode_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "kern.sched_preemption_disable_debug_mode");
	T_LOG("kern.sched_preemption_disable_debug_mode restored to previous value: %llu", old_preemption_debug_mode);
}

static uint64_t old_interrupt_debug_mode = 0;
static size_t old_interrupt_debug_mode_size = sizeof(old_interrupt_debug_mode);

static void
restore_interrupt_disable_debug_mode(void)
{
	int ret = sysctlbyname("kern.interrupt_masked_debug_mode", NULL, NULL,
	    &old_interrupt_debug_mode, old_interrupt_debug_mode_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "kern.interrupt_masked_debug_mode");
	T_LOG("kern.interrupt_masked_debug_mode restored to previous value: %llu", old_interrupt_debug_mode);
}

static uint64_t old_interrupt_disable_timeout = 0;
static size_t old_interrupt_disable_timeout_size = sizeof(old_interrupt_disable_timeout);

static void
restore_interrupt_disable_timeout(void)
{
	int ret = sysctlbyname("kern.interrupt_masked_threshold_mt", NULL, NULL,
	    &old_interrupt_disable_timeout, old_interrupt_disable_timeout_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "kern.interrupt_masked_threshold_mt");
	T_LOG("kern.interrupt_masked_threshold_mt restored to previous value: %llu", old_interrupt_disable_timeout);
}

static const char *ktrace_file_short_name = "overload_runqueue_with_thread_groups.ktrace";

static void
save_collected_ktrace(char *trace_path)
{
	int ret;

	T_LOG("ktrace file saved at \"%s\"", trace_path);
	ret = chmod(trace_path, 0777);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "chmod");

	char compressed_path[MAXPATHLEN];
	snprintf(compressed_path, MAXPATHLEN, "%s.tar.gz", ktrace_file_short_name);
	ret = dt_resultfile(compressed_path, sizeof(compressed_path));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "dt_resultfile marking \"%s\" for collection", compressed_path);
	T_LOG("\"%s\" marked for upload", compressed_path);

	char *tar_args[] = {"/usr/bin/tar", "-czvf", compressed_path, trace_path, NULL};
	pid_t tar_pid = dt_launch_tool_pipe(tar_args, false, NULL,
	    ^bool (__unused char *data, __unused size_t data_size, __unused dt_pipe_data_handler_context_t *context) {
		return true;
	},
	    ^bool (char *data, __unused size_t data_size, __unused dt_pipe_data_handler_context_t *context) {
		T_LOG("[tar] Error msg: %s", data);
		return true;
	},
	    BUFFER_PATTERN_LINE, NULL);

	T_QUIET; T_ASSERT_TRUE(tar_pid, "[tar] pid %d", tar_pid);
	ret = dt_waitpid(tar_pid, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "dt_waitpid");

	ret = chmod(compressed_path, 0777);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "chmod");
}

/*
 * Parse the recorded ktrace file to see if we crossed the set interrupt-disabled
 * timeout and thus failed the test.
 */
static void
search_for_interrupt_disable_timeout_tracepoint(char *trace_path)
{
	__block int ret;
	ktrace_session_t read_session = ktrace_session_create();
	ret = ktrace_set_file(read_session, trace_path);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_set_file");
	__block const char *offending_thread = NULL;

	ktrace_events_single(read_session, MACHDBG_CODE(DBG_MACH_SCHED, MACH_INT_MASKED_EXPIRED), ^(ktrace_event_t e) {
		if (offending_thread == NULL) {
		        T_LOG("Interrupts were held disabled for %llu ns, crossing the %llu ns threshold:", abs_to_nanos(e->arg1), INTERRUPT_DISABLE_TIMEOUT_NS);
		        ret = ktrace_print_trace_point(stdout, read_session, e, KTP_KIND_CSV,
		        KTP_FLAG_WALLTIME | KTP_FLAG_THREADNAME | KTP_FLAG_PID | KTP_FLAG_EVENTNAME | KTP_FLAG_EXECNAME);
		        T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ktrace_print_trace_point output");
		        printf("\n"); // Flush output from ktrace_print_trace_point
		        offending_thread = ktrace_get_name_for_thread(read_session, e->threadid);
		        ktrace_end(read_session, 0);
		}
	});

	ktrace_set_completion_handler(read_session, ^{
		if (offending_thread == NULL) {
		        T_PASS("Scheduler survived %d simulatenously runnable thread groups without disabling interrupts for more than %llu ns!", NUM_THREADS, INTERRUPT_DISABLE_TIMEOUT_NS);
		} else {
		        save_collected_ktrace(trace_path);
		        T_FAIL("Interrupts held disabled for more than %llu ns by thread \"%s\"", INTERRUPT_DISABLE_TIMEOUT_NS, offending_thread);
		}
		T_END;
	});

	ret = ktrace_start(read_session, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start");
}

T_DECL(overload_runqueue_with_thread_groups,
    "Overload the runqueue with distinct thread groups to verify that the scheduler"
    "does not trip an interrupts-disabled timeout whenever it scans the runqueue",
    T_META_ASROOT(true), XNU_T_META_SOC_SPECIFIC, T_META_ENABLED(TARGET_OS_IOS))
{
	BACKGROUND_PRI = 4;
	NUM_THREADS = 1000;
	SLEEP_SECONDS = 20;
	/* Matches DEFAULT_INTERRUPT_MASKED_TIMEOUT value in XNU */
	INTERRUPT_DISABLE_TIMEOUT_NS = 500 * NSEC_PER_USEC; // 500 microseconds

	__block int ret;

	/* Configure interrupts-disabled timeout to drop a ktracepoint */
	uint64_t emit_tracepoint_mode = 1;
	ret = sysctlbyname("kern.interrupt_masked_debug_mode",
	    &old_interrupt_debug_mode, &old_interrupt_debug_mode_size,
	    &emit_tracepoint_mode, sizeof(emit_tracepoint_mode));
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "kern.interrupt_masked_debug_mode");
	T_ATEND(restore_interrupt_disable_debug_mode);
	/* Configure the preemption-disabled debug mode as well, to avoid panicking if the test fails */
	ret = sysctlbyname("kern.sched_preemption_disable_debug_mode",
	    &old_preemption_debug_mode, &old_preemption_debug_mode_size,
	    &emit_tracepoint_mode, sizeof(emit_tracepoint_mode));
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "kern.sched_preemption_disable_debug_mode");
	T_ATEND(restore_preemption_disable_debug_mode);

	/* Set interrupts-disabled timeout threshold */
	uint64_t disable_timeout = nanos_to_abs(INTERRUPT_DISABLE_TIMEOUT_NS);
	ret = sysctlbyname("kern.interrupt_masked_threshold_mt",
	    &old_interrupt_disable_timeout, &old_interrupt_disable_timeout_size,
	    &disable_timeout, sizeof(disable_timeout));
	T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_ZERO(ret, "kern.interrupt_masked_threshold_mt");
	T_ATEND(restore_interrupt_disable_timeout);

	/* Use ktrace to observe if the interrupt-disable timeout drops a tracepoint */
	ktrace_session_t session = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(session, "ktrace_session_create");
	char filepath_arr[MAXPATHLEN] = "";
	const char *tmp_dir = dt_tmpdir();
	strlcpy(filepath_arr, tmp_dir, sizeof(filepath_arr));
	strlcat(filepath_arr, "/", sizeof(filepath_arr));
	strlcat(filepath_arr, ktrace_file_short_name, sizeof(filepath_arr));
	ret = remove(filepath_arr);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_TRUE((ret == 0) || (errno == ENOENT), "remove");
	char *filepath = filepath_arr;
	ret = ktrace_events_filter(session, "C0x01", ^(__unused ktrace_event_t event){}); // records scheduler tracepoints
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_events_filter");
	ktrace_set_completion_handler(session, ^{
		search_for_interrupt_disable_timeout_tracepoint(filepath);
	});
	ret = ktrace_start_writing_path(session, filepath, 0);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start_writing_path");

	/* Spin up lots of threads, each creating and joining its own thread group */
	T_LOG("Creating %d threads at pri %d, each with a unique thread group", NUM_THREADS, BACKGROUND_PRI);
	start_timestamp = mach_absolute_time();
	pthread_t *bg_threads = malloc(sizeof(pthread_t) * (size_t)NUM_THREADS);
	start_threads(bg_threads, make_tg_and_spin, BACKGROUND_PRI, NUM_THREADS);

	T_LOG("Waiting %llu seconds to see if the scheduler can handle it...", SLEEP_SECONDS);
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(SLEEP_SECONDS * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
		ktrace_end(session, 0);
	});
	dispatch_main();
}
