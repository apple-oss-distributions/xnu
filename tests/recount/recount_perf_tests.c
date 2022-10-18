// Copyright 2021 (c) Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <darwintest_utils.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <os/base.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/resource_private.h>
#include <unistd.h>

#include "test_utils.h"
#include "recount_test_utils.h"

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("RM"),
	T_META_OWNER("mwidmann"),
	T_META_CHECK_LEAKS(false),
	T_META_TAG_PERF);

__options_decl(metrics_t, uint32_t, {
	METRIC_INSNS = 0x01,
	METRIC_CYCLES = 0x02,
	METRIC_SYS_TIME = 0x04,
	METRIC_CPU_TIME = 0x08,
});
#define METRIC_COUNT (4)

static const char *metric_units[METRIC_COUNT] = {
	"instructions",
	"cycles",
	"CPUns",
	"CPUns",
};

static const char *metric_names[METRIC_COUNT] = {
	"insns",
	"cycles",
	"sys_time",
	"cpu_time",
};

static int
next_bit(uint32_t *bits)
{
	if (*bits == 0) {
		return -1;
	}
	int bit = __builtin_ctzll(*bits);
	*bits &= ~(1U << bit);
	return bit;
}

struct measure {
	dt_stat_t m_stat;
	metrics_t m_metric;
};

static bool
measures_stable(struct measure *measures)
{
	for (int i = 0; i < METRIC_COUNT; i++) {
		if (measures[i].m_stat && !dt_stat_stable(measures[i].m_stat)) {
			return false;
		}
	}
	return true;
}

struct usage_scenario {
	const char *us_stat_name;
	void (^us_modify_stat)(dt_stat_t);
	void (*us_call)(void *);
	double (*us_measure)(metrics_t, void *);
	void *us_context;
	metrics_t us_metrics;
};

static void
interface_perf_test(struct usage_scenario *s)
{
	metrics_t metrics = s->us_metrics;

	T_SETUPBEGIN;
	if (!has_cpi()) {
		metrics &= ~(METRIC_INSNS | METRIC_CYCLES);
	}

	struct measure measures[4] = { 0 };
	for (int metric = next_bit(&metrics); metric >= 0;
	    metric = next_bit(&metrics)) {
		switch (1U << metric) {
		case METRIC_CPU_TIME:
		case METRIC_SYS_TIME:
			measures[metric].m_stat = (dt_stat_t)dt_stat_time_create("%s_%s",
			    s->us_stat_name, metric_names[metric]);
			break;
		case METRIC_INSNS:
		case METRIC_CYCLES:
			measures[metric].m_stat = dt_stat_create(metric_units[metric],
			    "%s_%s", s->us_stat_name, metric_names[metric]);
			break;
		default:
			T_ASSERT_FAIL("unexpected metric %d", metric);
			break;
		}
		if (s->us_modify_stat) {
			s->us_modify_stat(measures[metric].m_stat);
		}
		measures[metric].m_metric = 1U << metric;
	}

	while (!measures_stable(measures)) {
		s->us_call(s->us_context);
		for (int i = 0; i < METRIC_COUNT; i++) {
			if (measures[i].m_stat) {
				double m = s->us_measure(measures[i].m_metric, s->us_context);
				dt_stat_add(measures[i].m_stat, m);
			}
		}
	}

	for (int i = 0; i < METRIC_COUNT; i++) {
		if (measures[i].m_stat) {
			dt_stat_finalize(measures[i].m_stat);
		}
	}
}

static void
interface_scaling_test(struct usage_scenario *s)
{
	unsigned int thread_counts[] = { 1, 4, 8, 16, 32, 64, 128, 256, };

	for (unsigned int i = 0; i < ARRAY_COUNT(thread_counts); i++) {
		unsigned int n = thread_counts[i];
		struct scene *scene = scene_start(n - 1,
		    (role_t []){ ROLE_WAIT, ROLE_NONE, });
		T_LOG("%u threads", n);
		s->us_modify_stat = ^(dt_stat_t stat) {
			dt_stat_set_variable(stat, "threads", n);
		};
		interface_perf_test(s);
		scene_end(scene);
	}
}

static void
proc_pidtaskinfo_usage(void *ctx)
{
	struct proc_taskinfo before = { 0 };
	struct proc_taskinfo after = { 0 };
	pid_t pid = getpid();
	int before_ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &before,
		sizeof(before));
	int after_ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &after,
		sizeof(after));

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_ret,
		"proc_pidinfo(..., PROC_PIDTASKINFO, ...)");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_ret,
		"proc_pidinfo(..., PROC_PIDTASKINFO, ...)");
	T_SETUPEND;

	struct proc_taskinfo *delta = ctx;
	delta->pti_total_user = ns_from_mach(after.pti_total_user -
		before.pti_total_user);
	delta->pti_total_system = ns_from_mach(after.pti_total_system -
		before.pti_total_system);
}

static double
proc_pidtaskinfo_measurement(metrics_t metric, void *ctx)
{
	struct proc_taskinfo *info = ctx;
	switch (metric) {
	case METRIC_CPU_TIME:
		return (double)(info->pti_total_user + info->pti_total_system) / 1e9;
	case METRIC_SYS_TIME:
		return (double)info->pti_total_system / 1e9;
	default:
		T_ASSERT_FAIL("unsupported metric %d for proc_pidtaskinfo", metric);
	}
}

static void
proc_pid_rusage_usage(void *ctx)
{
	struct rusage_info_v5 before = { 0 };
	struct rusage_info_v5 after = { 0 };
	pid_t pid = getpid();
	int before_ret = proc_pid_rusage(pid, RUSAGE_INFO_V5,
			(rusage_info_t *)&before);
	int after_ret = proc_pid_rusage(pid, RUSAGE_INFO_V5,
			(rusage_info_t *)&after);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_ret, "proc_pid_rusage()");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_ret, "proc_pid_rusage()");
	T_SETUPEND;

	struct rusage_info_v5 *delta = ctx;
	delta->ri_user_time = ns_from_mach(after.ri_user_time -
		before.ri_user_time);
	delta->ri_system_time = ns_from_mach(after.ri_system_time -
		before.ri_system_time);
	delta->ri_cycles = after.ri_cycles - before.ri_cycles;
	delta->ri_instructions = after.ri_instructions - before.ri_instructions;
}

static double
proc_pid_rusage_measurement(metrics_t metric, void *ctx)
{
	struct rusage_info_v5 *info = ctx;
	switch (metric) {
	case METRIC_CPU_TIME:
		return (double)(info->ri_user_time + info->ri_system_time) / 1e9;
	case METRIC_SYS_TIME:
		return (double)info->ri_system_time / 1e9;
	case METRIC_INSNS:
		return (double)info->ri_instructions;
	case METRIC_CYCLES:
		return (double)info->ri_cycles;
	}
}

static const int RUSAGE_ITERS = 10;

static double
getrusage_measurement(metrics_t metric, void *ctx)
{
	struct rusage *usage = ctx;
	switch (metric) {
	case METRIC_CPU_TIME:
		return (double)(ns_from_timeval(usage->ru_utime) +
				ns_from_timeval(usage->ru_stime)) / 1e9 / RUSAGE_ITERS;
	case METRIC_SYS_TIME:
		return (double)ns_from_timeval(usage->ru_stime) / 1e9 / RUSAGE_ITERS;
	default:
		T_ASSERT_FAIL("unexpected metric %d", metric);
	}
}

static void
getrusage_usage(void *ctx)
{
	struct rusage before = { 0 };
	struct rusage after = { 0 };
	int before_ret = getrusage(RUSAGE_SELF, &before);
	for (int i = 0; i < RUSAGE_ITERS; i++) {
		// getrusage(2) is limited to microsecond precision, so loop around it
		// to increase its duration.
		getrusage(RUSAGE_SELF, &after);
	}
	int after_ret = getrusage(RUSAGE_SELF, &after);
	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_ret, "getrusage()");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_ret, "getrusage()");
	T_SETUPEND;

	struct rusage *delta = ctx;
	delta->ru_utime = timeval_from_ns(ns_from_timeval(after.ru_utime) -
			ns_from_timeval(before.ru_utime));
	delta->ru_stime = timeval_from_ns(ns_from_timeval(after.ru_stime) -
			ns_from_timeval(before.ru_stime));
}

static void
thread_selfcounts_usage(void *ctx)
{
	struct thsc_time_cpi before = { 0 };
	struct thsc_time_cpi after = { 0 };
	int before_ret = thread_selfcounts(THSC_TIME_CPI, &before, sizeof(before));
	int after_ret = thread_selfcounts(THSC_TIME_CPI, &after, sizeof(after));

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_ret, "thread_selfcounts(THSC_TIME_CPI, ...)");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_ret, "thread_selfcounts(THSC_TIME_CPI, ...)");
	T_SETUPEND;

	struct thsc_time_cpi *counts = ctx;
	counts->ttci_user_time_mach = after.ttci_user_time_mach -
			before.ttci_user_time_mach;
	counts->ttci_system_time_mach = after.ttci_system_time_mach -
			before.ttci_system_time_mach;
	counts->ttci_instructions = after.ttci_instructions -
			before.ttci_instructions;
	counts->ttci_cycles = after.ttci_cycles - before.ttci_cycles;
}

static double
thread_selfcounts_measurement(metrics_t metric, void *ctx)
{
	struct thsc_time_cpi *counts = ctx;
	switch (metric) {
	case METRIC_CPU_TIME:
		return (double)ns_from_mach(counts->ttci_user_time_mach +
				counts->ttci_system_time_mach) / 1e9;
	case METRIC_SYS_TIME:
		return (double)ns_from_mach(counts->ttci_system_time_mach) / 1e9;
	case METRIC_INSNS:
		return (double)counts->ttci_instructions;
	case METRIC_CYCLES:
		return (double)counts->ttci_cycles;
	}
}

static void
thread_selfusage_usage(void *ctx)
{
	uint64_t before = __thread_selfusage();
	uint64_t after = __thread_selfusage();
	uint64_t *delta = ctx;
	*delta = after - before;
}

static double
thread_selfusage_measurement(metrics_t metric, void *ctx)
{
	uint64_t *delta = ctx;
	if (metric != METRIC_CPU_TIME) {
		T_ASSERT_FAIL("unsupported metric %d for thread_selfusage", metric);
	}
	return (double)ns_from_mach(*delta);
}

static void
task_power_info_usage(void *ctx)
{
	struct task_power_info before = { 0 };
	struct task_power_info after = { 0 };
	mach_msg_type_number_t info_count = TASK_POWER_INFO_COUNT;
	kern_return_t before_kr = task_info(mach_task_self(), TASK_POWER_INFO,
			(task_info_t)&before, &info_count);
	info_count = TASK_POWER_INFO_COUNT;
	kern_return_t after_kr = task_info(mach_task_self(), TASK_POWER_INFO,
			(task_info_t)&after, &info_count);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(before_kr, "task_info(... TASK_POWER_INFO ...)");
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(after_kr, "task_info(... TASK_POWER_INFO ...)");
	T_SETUPEND;

	struct task_power_info *info = ctx;
	info->total_user = after.total_user - before.total_user;
	info->total_system = after.total_system - before.total_system;
}

static double
task_power_info_measurement(metrics_t metric, void *ctx)
{
	struct task_power_info *info = ctx;
	uint64_t ns = 0;
	switch (metric) {
	case METRIC_CPU_TIME:
		ns = ns_from_mach(info->total_user) + ns_from_mach(info->total_system);
		break;
	case METRIC_SYS_TIME:
		ns = ns_from_mach(info->total_system);
		break;
	case METRIC_INSNS:
	case METRIC_CYCLES:
	default:
		T_ASSERT_FAIL("unsupported metric %d for task_power_info", metric);
	}
	return (double)ns / 1e9;
}

static const int THREAD_BASIC_INFO_ITERS = 1000;

static void
thread_basic_info_usage(void *ctx)
{
	struct thread_basic_info before = { 0 };
	struct thread_basic_info after = { 0 };
	mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
	kern_return_t before_kr = thread_info(mach_thread_self(), THREAD_BASIC_INFO,
			(thread_info_t)&before, &info_count);
	for (int i = 0; i < THREAD_BASIC_INFO_ITERS; i++) {
		info_count = THREAD_BASIC_INFO_COUNT;
		thread_info(mach_thread_self(), THREAD_BASIC_INFO,
				(thread_info_t)&after, &info_count);
	}
	info_count = THREAD_BASIC_INFO_COUNT;
	kern_return_t after_kr = thread_info(mach_thread_self(), THREAD_BASIC_INFO,
			(thread_info_t)&after, &info_count);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_kr, "thread_info(... THREAD_BASIC_INFO ...)");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_kr, "thread_info(... THREAD_BASIC_INFO ...)");
	T_SETUPEND;

	struct thread_basic_info *info = ctx;

	info->user_time = time_value_from_ns(ns_from_time_value(after.user_time) -
			ns_from_time_value(before.user_time));
	info->system_time = time_value_from_ns(
			ns_from_time_value(after.system_time) -
			ns_from_time_value(before.system_time));
}

static double
thread_basic_info_measurement(metrics_t metric, void *ctx)
{
	struct thread_basic_info *info = ctx;
	uint64_t ns = 0;
	switch (metric) {
	case METRIC_CPU_TIME:
		ns = ns_from_time_value(info->user_time) +
				ns_from_time_value(info->system_time);
		break;
	case METRIC_SYS_TIME:
		ns = ns_from_time_value(info->system_time);
		break;
	case METRIC_INSNS:
	case METRIC_CYCLES:
	default:
		T_ASSERT_FAIL("unsupported metric %d for thread_basic_info", metric);
	}
	return (double)ns / 1e9 / THREAD_BASIC_INFO_ITERS;
}

static void
task_inspect_basic_counts_usage(void *ctx)
{
	struct task_inspect_basic_counts before = { 0 };
	struct task_inspect_basic_counts after = { 0 };
	mach_msg_type_number_t info_count = TASK_INSPECT_BASIC_COUNTS_COUNT;
	kern_return_t before_kr = task_inspect(mach_task_self(),
			TASK_INSPECT_BASIC_COUNTS, (task_inspect_info_t)&before,
			&info_count);
	info_count = TASK_INSPECT_BASIC_COUNTS_COUNT;
	kern_return_t after_kr = task_inspect(mach_task_self(),
			TASK_INSPECT_BASIC_COUNTS, (task_inspect_info_t)&after,
			&info_count);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_kr,
			"task_inspect(... TASK_INSPECT_BASIC_COUNTS ...)");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_kr,
			"task_inspect(... TASK_INSPECT_BASIC_COUNTS ...)");
	T_SETUPEND;

	struct task_inspect_basic_counts *counts = ctx;
	counts->instructions = after.instructions - before.instructions;
	counts->cycles = after.cycles - before.cycles;
}

static double
task_inspect_basic_counts_measurement(metrics_t metric, void *ctx)
{
	struct task_inspect_basic_counts *counts = ctx;
	switch (metric) {
	case METRIC_INSNS:
		return (double)counts->instructions;
	case METRIC_CYCLES:
		return (double)counts->cycles;
	case METRIC_SYS_TIME:
	case METRIC_CPU_TIME:
	default:
		T_ASSERT_FAIL("unsupported metric %d for task_inspect_basic_counts",
				metric);
	}
}

static void
task_absolutetime_info_usage(void *ctx)
{
	task_absolutetime_info_data_t before = { 0 };
	task_absolutetime_info_data_t after = { 0 };
	mach_msg_type_number_t info_count = TASK_ABSOLUTETIME_INFO_COUNT;
	kern_return_t before_kr = task_info(mach_task_self(),
			TASK_ABSOLUTETIME_INFO, (task_info_t)&before,
			&info_count);
	info_count = TASK_ABSOLUTETIME_INFO_COUNT;
	kern_return_t after_kr = task_info(mach_task_self(),
			TASK_ABSOLUTETIME_INFO, (task_info_t)&after,
			&info_count);

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(before_kr,
			"task_info(... TASK_ABSOLUTETIME_INFO ...)");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(after_kr,
			"task_info(... TASK_ABSOLUTETIME_INFO ...)");
	T_SETUPEND;

	task_absolutetime_info_data_t *counts = ctx;
	counts->total_user = after.total_user - before.total_user;
	counts->total_system = after.total_system - before.total_system;
}

static double
task_absolutetime_info_measurement(metrics_t metric, void *ctx)
{
	task_absolutetime_info_data_t *counts = ctx;
	switch (metric) {
	case METRIC_CPU_TIME:
		return (double)counts->total_user + counts->total_system;
	case METRIC_SYS_TIME:
		return (double)counts->total_system;
	case METRIC_INSNS:
	case METRIC_CYCLES:
	default:
		T_ASSERT_FAIL("unsupported metric %d for task_absolutetime_info",
				metric);
	}
}

T_DECL(task_usage_perf, "measure the performance of task usage interfaces")
{
	struct proc_taskinfo pti = { 0 };
	struct usage_scenario pti_scenario = {
		.us_stat_name = "proc_pidtaskinfo",
		.us_call = proc_pidtaskinfo_usage,
		.us_measure = proc_pidtaskinfo_measurement,
		.us_context = &pti,
		.us_metrics = METRIC_CPU_TIME | METRIC_SYS_TIME,
	};
	interface_scaling_test(&pti_scenario);

	struct rusage_info_v5 rui = { 0 };
	struct usage_scenario ppr_scenario = {
		.us_stat_name = "proc_pid_rusage",
		.us_call = proc_pid_rusage_usage,
		.us_measure = proc_pid_rusage_measurement,
		.us_context = &rui,
		.us_metrics = METRIC_INSNS | METRIC_CYCLES | METRIC_CPU_TIME |
				METRIC_SYS_TIME,
	};
	interface_scaling_test(&ppr_scenario);

	struct rusage usage = { 0 };
	struct usage_scenario gru_scenario = {
		.us_stat_name = "getrusage",
		.us_call = getrusage_usage,
		.us_measure = getrusage_measurement,
		.us_context = &usage,
		.us_metrics = METRIC_CPU_TIME | METRIC_SYS_TIME,
	};
	interface_scaling_test(&gru_scenario);

	struct task_power_info tpi = { 0 };
	struct usage_scenario tpi_scenario = {
		.us_stat_name = "task_power_info",
		.us_call = task_power_info_usage,
		.us_measure = task_power_info_measurement,
		.us_context = &tpi,
		.us_metrics = METRIC_CPU_TIME | METRIC_SYS_TIME,
	};
	interface_scaling_test(&tpi_scenario);

	task_absolutetime_info_data_t tati = { 0 };
	struct usage_scenario tati_scenario = {
		.us_stat_name = "task_absolutetime_info",
		.us_call = task_absolutetime_info_usage,
		.us_measure = task_absolutetime_info_measurement,
		.us_context = &tati,
		.us_metrics = METRIC_CPU_TIME | METRIC_SYS_TIME,
	};
	interface_scaling_test(&tati_scenario);

	struct task_inspect_basic_counts counts = { 0 };
	struct usage_scenario tibc_scenario = {
		.us_stat_name = "task_inspect_basic_counts",
		.us_call = task_inspect_basic_counts_usage,
		.us_measure = task_inspect_basic_counts_measurement,
		.us_context = &counts,
		.us_metrics = METRIC_INSNS | METRIC_CYCLES,
	};
	interface_scaling_test(&tibc_scenario);
}

T_DECL(thread_usage_perf, "measure the performance of thread usage interfaces")
{
	struct thsc_time_cpi counts = { 0 };
	struct usage_scenario tsc_scenario = {
		.us_stat_name = "thread_selfcounts",
		.us_call = thread_selfcounts_usage,
		.us_measure = thread_selfcounts_measurement,
		.us_context = &counts,
		.us_metrics = METRIC_INSNS | METRIC_CYCLES | METRIC_CPU_TIME |
				METRIC_SYS_TIME,
	};
	interface_perf_test(&tsc_scenario);

	uint64_t usage = 0;
	struct usage_scenario tsu_scenario = {
		.us_stat_name = "thread_selfusage",
		.us_call = thread_selfusage_usage,
		.us_measure = thread_selfusage_measurement,
		.us_context = &usage,
		.us_metrics = METRIC_CPU_TIME,
	};
	interface_perf_test(&tsu_scenario);

	struct thread_basic_info info = { 0 };
	struct usage_scenario tbi_scenario = {
		.us_stat_name = "thread_basic_info",
		.us_call = thread_basic_info_usage,
		.us_measure = thread_basic_info_measurement,
		.us_context = &info,
		.us_metrics = METRIC_CPU_TIME | METRIC_SYS_TIME,
	};
	interface_perf_test(&tbi_scenario);
}
