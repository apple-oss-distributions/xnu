// Copyright 2021-2023 (c) Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <darwintest_utils.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <stdint.h>
#include <sys/resource.h>
#include <unistd.h>

#include "test_utils.h"
#include "recount_test_utils.h"

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("cpu counters"),
    T_META_OWNER("mwidmann"),
    T_META_CHECK_LEAKS(false));

static void
proc_pidtaskinfo_increasing(pid_t pid, struct proc_taskinfo *last,
    const char *desc)
{
	struct proc_taskinfo info = { 0 };
	T_SETUPBEGIN;
	int ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, sizeof(info));
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(..., PROC_PIDTASKINFO, ...)");
	T_SETUPEND;

	const char *name = "PROC_PIDTASKINFO";
	T_LOG("%s: usr = %llu, sys = %llu, th_usr = %llu, th_sys = %llu, "
			"term_usr = %llu, term_sys = %llu", name, info.pti_total_user,
			info.pti_total_system, info.pti_threads_user,
			info.pti_threads_system,
			info.pti_total_user - info.pti_threads_user,
			info.pti_total_system - info.pti_threads_system);
	T_EXPECT_GE(info.pti_total_user, last->pti_total_user,
			"%s user time should increase %s", name, desc);
	T_EXPECT_GE(info.pti_total_system, last->pti_total_system,
			"%s system time should increase %s", name, desc);
	*last = info;
}

static void *
spin_thread(void *arg)
{
	volatile int *spin = arg;
	while (*spin);
	return NULL;
}

static void *
sleep_thread(void *arg)
{
	volatile int *keep_going = arg;
	while (*keep_going) {
		usleep(100000);
	}
	return NULL;
}

enum usage_style {
	USAGE_SPIN,
	USAGE_SLEEP,
};

struct usage_thread {
	enum usage_style ut_style;
	const char *ut_name;
	uintptr_t ut_arg;
	pthread_t ut_thread;
};

static void
thread_start(struct usage_thread *th, const char *name, enum usage_style style)
{
	th->ut_style = style;
	th->ut_name = name;
	th->ut_arg = 1;
	T_SETUPBEGIN;
	int error = pthread_create(&th->ut_thread, NULL,
			style == USAGE_SPIN ? spin_thread : sleep_thread, &th->ut_arg);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_create");
	T_LOG("created %s thread to %s", name,
			style == USAGE_SPIN ? "spin" : "sleep");
	T_SETUPEND;
}

static void
thread_end(struct usage_thread *th)
{
	th->ut_arg = 0;
	T_SETUPBEGIN;
	int error = pthread_join(th->ut_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_join");
	T_LOG("terminated %s thread", th->ut_name);
	T_SETUPEND;
}

T_DECL(proc_pidtaskinfo_sanity, "ensure proc_pidtaskinfo CPU times are sane")
{
	struct proc_taskinfo prev = { 0 };
	struct usage_thread first = { 0 };
	struct usage_thread second = { 0 };

	proc_pidtaskinfo_increasing(getpid(), &prev, "initially");
	thread_start(&first, "first", USAGE_SPIN);
	proc_pidtaskinfo_increasing(getpid(), &prev,
			"after first thread has been created");
	thread_start(&second, "second", USAGE_SPIN);
	proc_pidtaskinfo_increasing(getpid(), &prev,
			"after second thread has been created");
	// Sleep for ~10 quanta.
	usleep(100 * 1000);
	thread_end(&first);
	proc_pidtaskinfo_increasing(getpid(), &prev,
			"after first thread has terminated");
	thread_end(&second);
	proc_pidtaskinfo_increasing(getpid(), &prev,
			"after all threads have terminated");
}

struct usr_sys_times {
	uint64_t usr_time;
	uint64_t sys_time;
};

static void
_assert_increasing(struct usr_sys_times *before, struct usr_sys_times *after,
    const char *name, const char *desc)
{
	T_EXPECT_GE(after->usr_time, before->usr_time,
			"%s user time should increase %s", name, desc);
	T_EXPECT_GE(after->sys_time, before->sys_time,
			"%s system time should increase %s", name, desc);
}

static void
test_usr_sys_time_sanity(struct usr_sys_times (*fn)(pid_t), const char *name)
{
	struct usr_sys_times init = fn(getpid());
	struct usage_thread first = { 0 };
	thread_start(&first, "first", USAGE_SLEEP);

	struct usr_sys_times thread_active = fn(getpid());
	_assert_increasing(&init, &thread_active, name,
			"after first thread has been created");

	struct usage_thread second = { 0 };
	thread_start(&second, "second", USAGE_SLEEP);

	struct usr_sys_times thread_top_active = fn(getpid());
	_assert_increasing(&thread_active, &thread_top_active, name,
			"after second thread has been created");

	thread_end(&first);

	struct usr_sys_times thread_top_gone = fn(getpid());
	_assert_increasing(&thread_top_active, &thread_top_gone, name,
			"after first thread has terminated");

	thread_end(&second);

	struct usr_sys_times thread_gone = fn(getpid());
	_assert_increasing(&thread_top_gone, &thread_gone, name,
			"after all threads have terminated");
}

static void
_get_proc_pid_rusage(pid_t pid, struct rusage_info_v6 *info)
{
	T_SETUPBEGIN;
	int ret = proc_pid_rusage(pid, RUSAGE_INFO_V6, (rusage_info_t *)info);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage");
	T_SETUPEND;
}

static struct usr_sys_times
proc_pid_rusage_times(pid_t pid)
{
	struct rusage_info_v6 info = { 0 };
	_get_proc_pid_rusage(pid, &info);
	return (struct usr_sys_times){
		.usr_time = info.ri_user_time,
		.sys_time = info.ri_system_time,
	};
}

T_DECL(proc_pid_rusage_sanity, "ensure proc_pidtaskinfo CPU times are sane")
{
	test_usr_sys_time_sanity(proc_pid_rusage_times, "proc_pid_rusage");
}

static struct usr_sys_times
task_basic_info_times(pid_t __unused pid)
{
	struct task_basic_info_64 info = { 0 };
	mach_msg_type_number_t info_count = TASK_BASIC_INFO_64_COUNT;

	T_SETUPBEGIN;
	kern_return_t kr = task_info(mach_task_self(), TASK_BASIC_INFO_64,
			(task_info_t)&info, &info_count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "task_info(... TASK_BASIC_INFO_64 ...)");
	T_SETUPEND;

	return (struct usr_sys_times){
		.usr_time = ns_from_time_value(info.user_time),
		.sys_time = ns_from_time_value(info.system_time),
	};
}

T_DECL(task_basic_info_sanity, "ensure TASK_BASIC_INFO CPU times are sane")
{
	test_usr_sys_time_sanity(task_basic_info_times, "TASK_BASIC_INFO");
}

static struct usr_sys_times
task_power_info_times(pid_t __unused pid)
{
	struct task_power_info info = { 0 };
	mach_msg_type_number_t info_count = TASK_POWER_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_POWER_INFO,
			(task_info_t)&info, &info_count);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "task_info(... TASK_POWER_INFO ...)");
	T_SETUPEND;

	return (struct usr_sys_times){
		.usr_time = ns_from_mach(info.total_user),
		.sys_time = ns_from_mach(info.total_system),
	};
}

T_DECL(task_power_info_sanity, "ensure TASK_POWER_INFO CPU times are sane")
{
	test_usr_sys_time_sanity(task_power_info_times, "TASK_POWER_INFO");
}

static struct usr_sys_times
task_absolutetime_info_times(pid_t __unused pid)
{
	task_absolutetime_info_data_t info = { 0 };
	mach_msg_type_number_t info_count = TASK_ABSOLUTETIME_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_ABSOLUTETIME_INFO,
			(task_info_t)&info, &info_count);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "task_info(... TASK_ABSOLUTETIME_INFO ...)");
	T_SETUPEND;

	return (struct usr_sys_times){
		.usr_time = ns_from_mach(info.total_user),
		.sys_time = ns_from_mach(info.total_system),
	};
}

T_DECL(task_absolutetime_info_sanity,
		"ensure TASK_ABSOLUTETIME_INFO CPU times are sane")
{
	test_usr_sys_time_sanity(task_absolutetime_info_times,
			"TASK_ABSOLUTETIME_INFO");
}

static struct usr_sys_times
getrusage_times(pid_t __unused pid)
{
	struct rusage usage = { 0 };
	int ret = getrusage(RUSAGE_SELF, &usage);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "getrusage(RUSAGE_SELF ...)");
	T_SETUPEND;

	return (struct usr_sys_times){
		.usr_time = ns_from_timeval(usage.ru_utime),
		.sys_time = ns_from_timeval(usage.ru_stime),
	};
}

T_DECL(getrusage_sanity, "ensure getrusage CPU times are sane")
{
	test_usr_sys_time_sanity(getrusage_times, "getrusage");
}

T_DECL(thread_selfusage_sanity, "ensure thread_selfusage times are sane")
{
	uint64_t before = __thread_selfusage();
	uint64_t after = __thread_selfusage();
	T_ASSERT_GT(after, before, "thread_selfusage is increasing");
	before = __thread_selfusage();
	for (int i = 0; i < 5; i++) {
		usleep(1000);
	}
	after = __thread_selfusage();
	T_ASSERT_GT(after, before, "thread_selfusage increases after sleeping");
}

T_DECL(proc_pid_rusage_perf_levels,
		"ensure proc_pid_rusage fills in per-perf level information",
		REQUIRE_RECOUNT_PMCS,
    	// REQUIRE_MULTIPLE_PERF_LEVELS, disabled due to rdar://111297938
		SET_THREAD_BIND_BOOTARG)
{
	struct rusage_info_v6 before = { 0 };
	struct rusage_info_v6 after = { 0 };

	// Until rdar://111297938, manually skip the test if there aren't multiple perf levels.
	if (perf_level_count() < 2) {
		T_SKIP("device is not eligible for checking perf levels because it is SMP");
	}

	_get_proc_pid_rusage(getpid(), &before);
	run_on_all_perf_levels();
	_get_proc_pid_rusage(getpid(), &after);

	T_EXPECT_GE(after.ri_cycles, before.ri_cycles, "cycles increasing");
	T_EXPECT_GE(after.ri_instructions, before.ri_instructions,
			"instructions increasing");
	T_EXPECT_GE(after.ri_user_time, before.ri_user_time,
			"user_time increasing");
	T_EXPECT_GE(after.ri_system_time, before.ri_system_time,
			"system_time increasing");

	T_EXPECT_GE(after.ri_pcycles, before.ri_pcycles, "cycles_p increasing");
	T_EXPECT_GE(after.ri_pinstructions, before.ri_pinstructions,
			"instructions_p increasing");
	T_EXPECT_GE(after.ri_user_ptime, before.ri_user_ptime,
			"user_time_p increasing");
	T_EXPECT_GE(after.ri_system_ptime, before.ri_system_ptime,
			"system_time_p increasing");

	if (has_energy()) {
		T_EXPECT_GE(after.ri_energy_nj, before.ri_energy_nj,
				"energy_nj increasing");
		T_EXPECT_GE(after.ri_penergy_nj, before.ri_penergy_nj,
				"penergy_nj increasing");
	}
}

T_DECL(proc_pid_rusage_secure_perf_levels,
		"ensure proc_pid_rusage fills in per-perf level information",
		REQUIRE_RECOUNT_PMCS,
		REQUIRE_MULTIPLE_PERF_LEVELS,
		REQUIRE_EXCLAVES,
		SET_THREAD_BIND_BOOTARG)
{
	int status = 0;
	size_t status_size = sizeof(status);
	(void)sysctlbyname("kern.exclaves_status", &status, &status_size, NULL, 0);
	if (status != 1) {
		T_SKIP("exclaves must be supported");
	}

	struct rusage_info_v6 before = { 0 };
	struct rusage_info_v6 after = { 0 };

	_get_proc_pid_rusage(getpid(), &before);
	run_in_exclaves_on_all_perf_levels();
	_get_proc_pid_rusage(getpid(), &after);

	T_EXPECT_GT(after.ri_secure_time_in_system, 0ULL,
			"secure time after running in exclaves is non-zero");
	T_EXPECT_GT(after.ri_secure_time_in_system, 0ULL,
			"secure time on P-cores after running in exclaves is non-zero");

	T_EXPECT_GT(after.ri_secure_time_in_system, before.ri_secure_time_in_system,
			"secure time in system increasing");
	T_EXPECT_GT(after.ri_secure_ptime_in_system,
			before.ri_secure_ptime_in_system,
			"secure time in system on P-cores increasing");

	uint64_t system_time_delta = after.ri_system_time - before.ri_system_time;
	uint64_t secure_time_delta = after.ri_secure_time_in_system -
			before.ri_secure_time_in_system;
	T_EXPECT_LE(secure_time_delta, system_time_delta,
			"secure time is less than system time");
	uint64_t system_ptime_delta = after.ri_system_ptime -
			before.ri_system_ptime;
	uint64_t secure_ptime_delta = after.ri_secure_ptime_in_system -
			before.ri_secure_ptime_in_system;
	T_EXPECT_LE(secure_ptime_delta, system_ptime_delta,
			"secure time is less than system time on P-cores");
}

static void
_proc_pidthreadcounts_increasing(struct proc_threadcounts_data *before,
		struct proc_threadcounts_data *after, const char *perf_level)
{
	const char *name = "PROC_PIDTHREADCOUNTS";
	T_LOG("%s %s before: usr = %llu, sys = %llu, instrs = %llu, cycles = %llu, "
			"energy = %llu", name, perf_level,  before->ptcd_user_time_mach,
			before->ptcd_system_time_mach, before->ptcd_instructions,
			before->ptcd_cycles, before->ptcd_energy_nj);
	T_LOG("%s %s after: usr = %llu, sys = %llu, instrs = %llu, cycles = %llu, "
			"energy = %llu", name, perf_level, after->ptcd_user_time_mach,
			after->ptcd_system_time_mach, after->ptcd_instructions,
			after->ptcd_cycles, after->ptcd_energy_nj);

	T_EXPECT_NE(before->ptcd_user_time_mach, 0ULL,
			"%s user time should be non-zero", perf_level);
	T_EXPECT_NE(before->ptcd_system_time_mach, 0ULL,
			"%s system time should be non-zero", perf_level);
	T_EXPECT_NE(before->ptcd_instructions, 0ULL,
			"%s instructions should be non-zero", perf_level);
	T_EXPECT_NE(before->ptcd_cycles, 0ULL,
			"%s cycles should be non-zero", perf_level);

	T_EXPECT_GT(after->ptcd_user_time_mach, before->ptcd_user_time_mach,
			"%s user time should increase", perf_level);
	T_EXPECT_GT(after->ptcd_system_time_mach, before->ptcd_system_time_mach,
			"%s system time should increase", perf_level);
	T_EXPECT_GT(after->ptcd_instructions, before->ptcd_instructions,
			"%s instructions should increase", perf_level);
	T_EXPECT_GT(after->ptcd_cycles, before->ptcd_cycles,
			"%s cycles should increase", perf_level);

	if (has_energy()) {
		T_EXPECT_GT(after->ptcd_energy_nj, before->ptcd_energy_nj,
				"%s energy should increase", perf_level);
	}
}

static void
_threadcounts_to_rusage_info(struct proc_threadcounts_data *counts,
		struct rusage_info_v6 *info)
{
	unsigned int level_count = perf_level_count();
	for (unsigned int i = 0; i < level_count; i++) {
		struct proc_threadcounts_data *count = &counts[i];
		if (perf_level_name(i)[0] == 'P') {
			info->ri_system_ptime += count->ptcd_system_time_mach;
			info->ri_user_ptime += count->ptcd_user_time_mach;
			info->ri_pinstructions += count->ptcd_instructions;
			info->ri_pcycles += count->ptcd_cycles;
		}
		info->ri_system_time += count->ptcd_system_time_mach;
		info->ri_user_time += count->ptcd_user_time_mach;
		info->ri_instructions += count->ptcd_instructions;
		info->ri_cycles += count->ptcd_cycles;
	}
}

static void
_rusage_info_le(struct rusage_info_v6 *lhs, const char *lhs_name,
		struct rusage_info_v6 *rhs, const char *rhs_name)
{
	T_EXPECT_LE(lhs->ri_user_time, rhs->ri_user_time,
			"%s user time <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_system_time, rhs->ri_system_time,
			"%s system time <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_instructions, rhs->ri_instructions,
			"%s instructions <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_cycles, rhs->ri_cycles,
			"%s cycles <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_energy_nj, rhs->ri_energy_nj,
			"%s energy <= %s", lhs_name, rhs_name);

	T_EXPECT_LE(lhs->ri_user_ptime, rhs->ri_user_ptime,
			"%s P-core user time <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_system_ptime, rhs->ri_system_ptime,
			"%s P-core system time <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_pinstructions, rhs->ri_pinstructions,
			"%s P-core instructions <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_pcycles, rhs->ri_pcycles,
			"%s P-core cycles <= %s", lhs_name, rhs_name);
	T_EXPECT_LE(lhs->ri_penergy_nj, rhs->ri_penergy_nj,
			"%s energy <= %s", lhs_name, rhs_name);
}

struct thread_sequence {
	dispatch_semaphore_t child_sema;
	dispatch_semaphore_t parent_sema;
};

static void *
_thread_runs_on_perf_levels(void *vsequence)
{
	struct thread_sequence *seq = vsequence;

	run_on_all_perf_levels();
	dispatch_semaphore_signal(seq->parent_sema);
	dispatch_semaphore_wait(seq->child_sema, DISPATCH_TIME_FOREVER);

	run_on_all_perf_levels();
	dispatch_semaphore_signal(seq->parent_sema);
	dispatch_semaphore_wait(seq->child_sema, DISPATCH_TIME_FOREVER);
	return NULL;
}

T_DECL(proc_pidthreadcounts_sanity,
		"check per-perf level time and CPI from proc_pidthreadcounts",
		REQUIRE_RECOUNT_PMCS,
		SET_THREAD_BIND_BOOTARG,
		// Select the most comprehensive test to run on each SoC.
		XNU_T_META_SOC_SPECIFIC,
		T_META_ASROOT(true))
{
	T_SETUPBEGIN;

	unsigned int level_count = perf_level_count();
	T_LOG("found %u perf levels", level_count);
	int counts_size = (int)sizeof(struct proc_threadcounts) +
			(int)level_count * (int)sizeof(struct proc_threadcounts_data);
	struct proc_threadcounts *before = malloc((unsigned int)counts_size);
	T_QUIET; T_ASSERT_NOTNULL(before, "allocate before counts");
	memset(before, 0, counts_size);
	struct proc_threadcounts *after = malloc((unsigned int)counts_size);
	T_QUIET; T_ASSERT_NOTNULL(before, "allocate after counts");
	memset(after, 0, counts_size);
	pthread_t target_thread = NULL;
	uint64_t target_tid = 0;

	struct thread_sequence seq = {
		.parent_sema = dispatch_semaphore_create(0),
		.child_sema = dispatch_semaphore_create(0),
	};
	int error = pthread_create(&target_thread, NULL,
			_thread_runs_on_perf_levels, &seq);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_create");
	error = pthread_threadid_np(target_thread, &target_tid);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_threadid_np");
	T_LOG("created thread to run on all perf levels with ID %" PRIx64,
			target_tid);

	dispatch_semaphore_wait(seq.parent_sema, DISPATCH_TIME_FOREVER);

	T_SETUPEND;

	int size = proc_pidinfo(getpid(), PROC_PIDTHREADCOUNTS, target_tid, before,
			counts_size);
	T_WITH_ERRNO;
	T_ASSERT_EQ(size, counts_size,
			"proc_pidinfo(..., PROC_PIDTHREADCOUNTS, ...)");

	dispatch_semaphore_signal(seq.child_sema);
	dispatch_semaphore_wait(seq.parent_sema, DISPATCH_TIME_FOREVER);

	size = proc_pidinfo(getpid(), PROC_PIDTHREADCOUNTS, target_tid, after,
			counts_size);
	T_WITH_ERRNO;
	T_ASSERT_EQ(size, counts_size,
			"proc_pidinfo(..., PROC_PIDTHREADCOUNTS, ...)");

	struct rusage_info_v6 proc_usage = { 0 };
	_get_proc_pid_rusage(getpid(), &proc_usage);


	dispatch_semaphore_signal(seq.child_sema);

	for (unsigned int i = 0; i < level_count; i++) {
		_proc_pidthreadcounts_increasing(&before->ptc_counts[i],
				&after->ptc_counts[i], perf_level_name(i));
	}
	struct rusage_info_v6 thread_usage = { 0 };
	_threadcounts_to_rusage_info(after->ptc_counts, &thread_usage);
	_rusage_info_le(&thread_usage, "thread", &proc_usage, "process");

	(void)pthread_join(target_thread, NULL);
	free(before);
	free(after);
}

T_DECL(proc_pidthreadcounts_invalid_tid,
		"check that proc_pidthreadcounts returns ESRCH on invalid thread",
		T_META_ASROOT(true))
{
	T_SETUPBEGIN;
	unsigned int level_count = perf_level_count();
	int counts_size = (int)sizeof(struct proc_threadcounts) +
			(int)level_count * (int)sizeof(struct proc_threadcounts_data);
	struct proc_threadcounts *counts = malloc((unsigned int)counts_size);
	T_QUIET; T_ASSERT_NOTNULL(counts, "allocate counts");
	T_SETUPEND;

	// proc_pidinfo has a unique return value protocol: it returns the size
	// that was copied out and 0 if an error occurs, with errno set.
	int size = proc_pidinfo(getpid(), PROC_PIDTHREADCOUNTS, UINT64_MAX, counts,
			counts_size);
	T_ASSERT_EQ(size, 0,
			"proc_pidinfo(..., PROC_PIDTHREADCOUNTS, UINT64_MAX, ...) should "
			"fail");
	T_ASSERT_EQ(errno, ESRCH, "should fail with ESRCH");
}
