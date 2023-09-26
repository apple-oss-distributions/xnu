/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <notify.h>
#include <signal.h>
#include <stdint.h>
#include <strings.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <TargetConditionals.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("kern.task"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("performance"),
	T_META_OWNER("jarrad"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true),
	// rdar://112041307
	T_META_REQUIRES_SYSCTL_EQ("kern.hv_vmm_present", 0));

// sleep for 1 sec between suspend/resume
static unsigned int sleep_duration = 1;

static uint64_t
get_thread_id(void)
{
	kern_return_t kr;
	mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
	thread_identifier_info_data_t data;
	kr = thread_info(mach_thread_self(), THREAD_IDENTIFIER_INFO, (thread_info_t)&data, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");
	return data.thread_id;
}

static void
get_procname(char *dest, size_t size)
{
	int ret;
	ret = proc_name(getpid(), dest, (uint32_t)size);
	T_QUIET; T_ASSERT_GE(ret, 0, "proc_name");
}

static void
get_stats(task_t task, task_suspend_stats_t _Nonnull out)
{
	kern_return_t kr;
	mach_msg_type_number_t count = TASK_SUSPEND_STATS_INFO_COUNT;

	kr = task_info(task, TASK_SUSPEND_STATS_INFO, (task_info_t)out, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SUSPEND_STATS_INFO)");
}

static void
get_sources(task_t task, task_suspend_source_t _Nonnull out)
{
	kern_return_t kr;
	mach_msg_type_number_t count = TASK_SUSPEND_SOURCES_INFO_COUNT;

	kr = task_info(task, TASK_SUSPEND_SOURCES_INFO, (task_info_t)out, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SUSPEND_SOURCES_INFO)");
}

static void
log_stats(mach_timebase_info_data_t timebase, uint64_t now, const char *name, task_suspend_stats_t _Nonnull stats)
{
	uint64_t last_start_ago = (now - stats->tss_last_start) * timebase.numer / timebase.denom;
	uint64_t last_end_ago = (now - stats->tss_last_end) * timebase.numer / timebase.denom;
	uint64_t last_duration = (stats->tss_last_end - stats->tss_last_start) * timebase.numer / timebase.denom;
	uint64_t total_duration = (stats->tss_duration) * timebase.numer / timebase.denom;

	uint64_t nanosec = 1000000000llu;
	T_LOG("%s: %8lld suspensions, %10lld.%09lld total secs, last start %lld.%09lld secs ago, last end %lld.%09lld secs ago, %lld.%09lld secs long",
	    name, stats->tss_count,
	    total_duration / nanosec, total_duration % nanosec,
	    last_start_ago / nanosec, last_start_ago % nanosec,
	    last_end_ago / nanosec, last_end_ago % nanosec,
	    last_duration / nanosec, last_duration % nanosec);
}

static void
log_sources(mach_timebase_info_data_t timebase, uint64_t now, const char *name, task_suspend_source_array_t _Nonnull sources)
{
	uint64_t nanosec = 1000000000llu;
	for (int i = 0; i < TASK_SUSPEND_SOURCES_MAX; i++) {
		task_suspend_source_t source = &sources[i];
		uint64_t source_ago = (now - source->tss_time) * timebase.numer / timebase.denom;
		T_LOG("%s suspender #%d: start %lld.%09lld secs ago, pid %d, tid %llu, procname \"%s\"",
		    name, i, source_ago / nanosec, source_ago % nanosec, source->tss_pid, source->tss_tid, source->tss_procname);
	}
}

static void
log_time(mach_timebase_info_data_t timebase, uint64_t now, uint64_t time, const char *name)
{
	uint64_t nanosec = 1000000000llu;
	uint64_t time_ago = (now - time) * timebase.numer / timebase.denom;
	T_LOG("%s: %lld.%09lld secs ago",
	    name, time_ago / nanosec, time_ago % nanosec);
}

static void
verify_source(task_suspend_source_t source)
{
	char procname[65];
	get_procname(procname, sizeof(procname));

	T_EXPECT_EQ(source->tss_pid, getpid(), "suspend source should mark suspender as current task");
	T_EXPECT_EQ(source->tss_tid, get_thread_id(), "suspend source should mark suspender as current thread");
	T_EXPECT_GT(source->tss_time, 0ull, "suspend source should have non-zero time");
	T_EXPECT_EQ_STR(source->tss_procname, procname, "suspend source should have procname matching current proc");
}

static void
verify_stats(mach_timebase_info_data_t timebase, task_suspend_stats_t _Nonnull pre, task_suspend_stats_t _Nonnull post)
{
	uint64_t now = mach_absolute_time();

	log_stats(timebase, now, "  pre", pre);
	log_stats(timebase, now, " post", post);

	int64_t delta_suspensions = (int64_t)(post->tss_count - pre->tss_count);
	int64_t delta_duration = (int64_t)(post->tss_duration - pre->tss_duration) * (int64_t)timebase.numer / (int64_t)timebase.denom;
	int64_t delta_nsec = delta_duration % 1000000000ll;
	if (delta_nsec < 0) {
		delta_nsec += 1000000000ll;
	}
	T_LOG("delta: %+8lld suspensions, %+10lld.%09lld total nsecs", delta_suspensions, delta_duration / 1000000000ll, delta_nsec);

	T_EXPECT_LT(pre->tss_count, post->tss_count, "suspension count should increase when task is suspended");
	T_EXPECT_LT(pre->tss_duration, post->tss_duration, "suspension duration should increase when task is suspended");
	T_EXPECT_LT(post->tss_last_start, post->tss_last_end, "post: suspension should take time");
}

static int
spawn_helper(char *helper)
{
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	int ret;
	pid_t child_pid;

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		helper,
		NULL
	};

	// Spawn the child process
	ret = dt_launch_tool(&child_pid, launch_tool_args, false, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "dt_launch_tool");

	return child_pid;
}

static void
wakeup_helper(pid_t pid)
{
	int ret = kill(pid, SIGKILL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "kill()");
}

T_HELPER_DECL(wait_for_finished,
    "spin waiting for signal",
    T_META_CHECK_LEAKS(false))
{
	pause();
	exit(0);
}

T_DECL(get_suspend_stats,
    "test that task suspension statistics can be read out")
{
	mach_timebase_info_data_t timebase = {0, 0};
	mach_timebase_info(&timebase);

	struct task_suspend_stats_s stats;

	get_stats(current_task(), &stats);
	log_stats(timebase, mach_absolute_time(), "stats", &stats);
}

T_DECL(get_suspend_sources,
    "test that task suspension debug info can be read out")
{
	mach_timebase_info_data_t timebase = {0, 0};
	mach_timebase_info(&timebase);

	task_suspend_source_array_t sources;

	get_sources(current_task(), sources);
	log_sources(timebase, mach_absolute_time(), "sources", sources);
}

T_DECL(suspend_stats_update_on_pidsuspend,
    "test that task suspension info are updated on pidsuspend")
{
	kern_return_t kr;
	pid_t child_pid;
	task_t child_task;
	int rc;
	struct task_suspend_stats_s pre, post;
	task_suspend_source_array_t sources;
	mach_timebase_info_data_t timebase = {0, 0};

	mach_timebase_info(&timebase);

	child_pid = spawn_helper("wait_for_finished");
	kr = task_for_pid(mach_task_self(), child_pid, &child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid(%d)", child_pid);

	get_stats(child_task, &pre);

	T_LOG("Suspending helper...");
	rc = pid_suspend(child_pid);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "pid_suspend");

	T_LOG("Sleeping %d sec...", sleep_duration);
	sleep(sleep_duration);

	T_LOG("Resuming helper...");
	rc = pid_resume(child_pid);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "pid_resume");

	get_stats(child_task, &post);
	verify_stats(timebase, &pre, &post);
	get_sources(child_task, sources);
	log_sources(timebase, mach_absolute_time(), "sources", sources);
	verify_source(&sources[0]);

	wakeup_helper(child_pid);
	mach_port_deallocate(mach_task_self(), child_task);
}

T_DECL(suspend_stats_update_on_task_suspend,
    "test that task suspension info are updated on task_suspend")
{
	kern_return_t kr;
	pid_t child_pid;
	task_t child_task;
	struct task_suspend_stats_s pre, post;
	task_suspend_source_array_t sources;
	mach_timebase_info_data_t timebase = {0, 0};

	mach_timebase_info(&timebase);

	child_pid = spawn_helper("wait_for_finished");
	kr = task_for_pid(mach_task_self(), child_pid, &child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid(%d)", child_pid);

	get_stats(child_task, &pre);

	T_LOG("Suspending helper...");
	kr = task_suspend(child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_suspend");

	T_LOG("Sleeping %d sec...", sleep_duration);
	sleep(sleep_duration);

	T_LOG("Resuming helper...");
	kr = task_resume(child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_resume");

	get_stats(child_task, &post);
	verify_stats(timebase, &pre, &post);
	get_sources(child_task, sources);
	log_sources(timebase, mach_absolute_time(), "sources", sources);
	verify_source(&sources[0]);

	wakeup_helper(child_pid);
	mach_port_deallocate(mach_task_self(), child_task);
}

T_DECL(suspend_stats_update_on_forkcorpse,
    "test that task suspension info are updated on fork corpse")
{
	kern_return_t kr;
	pid_t child_pid;
	task_t child_task;
	mach_port_t cp;
	struct task_suspend_stats_s pre, post;
	task_suspend_source_array_t sources;
	mach_timebase_info_data_t timebase = {0, 0};

	mach_timebase_info(&timebase);

	child_pid = spawn_helper("wait_for_finished");
	kr = task_for_pid(mach_task_self(), child_pid, &child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid(%d)", child_pid);

	get_stats(child_task, &pre);

	T_LOG("Generating corpse of helper...");
	kr = task_generate_corpse(child_task, &cp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_generate_corpse");

	get_stats(child_task, &post);
	verify_stats(timebase, &pre, &post);
	get_sources(child_task, sources);
	log_sources(timebase, mach_absolute_time(), "sources", sources);
	verify_source(&sources[0]);

	kr = mach_port_deallocate(mach_task_self(), cp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");

	wakeup_helper(child_pid);
	kr = mach_port_deallocate(mach_task_self(), child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");
}

#define NUM_SUSPEND_RESUME (TASK_SUSPEND_SOURCES_MAX * 2)
T_DECL(suspend_source_created_for_every_suspend,
    "test that suspend sources are created for every suspend call")
{
	kern_return_t kr;
	pid_t child_pid;
	task_t child_task;
	struct task_suspend_stats_s pre, post;
	task_suspend_source_array_t sources;
	mach_timebase_info_data_t timebase = {0, 0};
	uint64_t first_suspend_time = 0;

	mach_timebase_info(&timebase);

	child_pid = spawn_helper("wait_for_finished");
	kr = task_for_pid(mach_task_self(), child_pid, &child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid(%d)", child_pid);

	get_stats(child_task, &pre);

	T_LOG("Suspending helper...");

	for (int i = 0; i < NUM_SUSPEND_RESUME; i++) {
		kr = task_suspend(child_task);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_suspend");
		if (i == 0) {
			first_suspend_time = mach_absolute_time();
		}
	}

	T_LOG("Sleeping %d sec...", sleep_duration);
	sleep(sleep_duration);

	T_LOG("Resuming helper...");
	for (int i = 0; i < NUM_SUSPEND_RESUME; i++) {
		kr = task_resume(child_task);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_resume");
	}

	uint64_t now = mach_absolute_time();

	get_stats(child_task, &post);
	verify_stats(timebase, &pre, &post);
	get_sources(child_task, sources);
	log_sources(timebase, now, "sources", sources);
	log_time(timebase, now, first_suspend_time, "first_suspend");

	for (int i = 0; i < TASK_SUSPEND_SOURCES_MAX; i++) {
		T_LOG("Verifying suspender no. %d", i);
		task_suspend_source_t source = &sources[i];
		verify_source(source);
		T_EXPECT_LT(source->tss_time, post.tss_last_end, "suspend source timestamp should be < last suspension end");
		T_EXPECT_GT(source->tss_time, first_suspend_time, "suspend source timestamp should be > first suspend");
	}

	wakeup_helper(child_pid);
	mach_port_deallocate(mach_task_self(), child_task);
}
