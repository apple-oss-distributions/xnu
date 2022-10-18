// Copyright (c) 2021-2022 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include "test_utils.h"
#include <fcntl.h>
#include <inttypes.h>
#ifndef PRIVATE
/*
 * Need new CPU families.
 */
#define PRIVATE
#include <mach/machine.h>
#undef PRIVATE
#else /* !defined(PRIVATE) */
#include <mach/machine.h>
#endif /* defined(PRIVATE) */
#include <ktrace.h>
#include <mach/mach.h>
#include <stdint.h>
#include <System/sys/guarded.h>
#include <System/sys/monotonic.h>
#include <sys/ioctl.h>
#include <sys/kdebug.h>
#include <sys/resource.h>
#include <sys/resource_private.h>
#include <sys/sysctl.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.monotonic"),
	T_META_CHECK_LEAKS(false)
	);

static void
skip_if_unsupported(void)
{
	int r;
	int supported = 0;
	size_t supported_size = sizeof(supported);

	r = sysctlbyname("kern.monotonic.supported", &supported, &supported_size,
	    NULL, 0);
	if (r < 0) {
		T_WITH_ERRNO;
		T_SKIP("could not find \"kern.monotonic.supported\" sysctl");
	}

	if (!supported) {
		T_SKIP("monotonic is not supported on this platform");
	}
}

static void
check_fixed_counts(struct thsc_cpi counts[2])
{
	T_QUIET;
	T_EXPECT_GT(counts[0].tcpi_instructions, UINT64_C(0), "non-zero instructions");
	T_QUIET;
	T_EXPECT_GT(counts[0].tcpi_cycles, UINT64_C(0), "non-zero cycles");

	T_EXPECT_GT(counts[1].tcpi_instructions, counts[0].tcpi_instructions,
	    "monotonically-increasing instructions");
	T_EXPECT_GT(counts[1].tcpi_cycles, counts[0].tcpi_cycles,
	    "monotonically-increasing cycles");
}

T_DECL(core_fixed_task, "check that task counting is working",
    XNU_T_META_SOC_SPECIFIC, T_META_ASROOT(true))
{
	task_t task = mach_task_self();
	kern_return_t kr;
	mach_msg_type_number_t size = TASK_INSPECT_BASIC_COUNTS_COUNT;
	struct thsc_cpi counts[2];

	skip_if_unsupported();

	kr = task_inspect(task, TASK_INSPECT_BASIC_COUNTS,
	    (task_inspect_info_t)&counts[0], &size);
	T_ASSERT_MACH_SUCCESS(kr,
	    "task_inspect(... TASK_INSPECT_BASIC_COUNTS ...)");

	size = TASK_INSPECT_BASIC_COUNTS_COUNT;
	kr = task_inspect(task, TASK_INSPECT_BASIC_COUNTS,
	    (task_inspect_info_t)&counts[1], &size);
	T_ASSERT_MACH_SUCCESS(kr,
	    "task_inspect(... TASK_INSPECT_BASIC_COUNTS ...)");

	check_fixed_counts(counts);
}

T_DECL(core_fixed_kdebug, "check that the kdebug macros for monotonic work",
    T_META_ASROOT(true))
{
	__block bool saw_events = false;
	ktrace_session_t s;
	int r;
	int set = 1;

	T_SETUPBEGIN;
	skip_if_unsupported();

	s = ktrace_session_create();
	T_QUIET; T_ASSERT_NOTNULL(s, "ktrace_session_create");

	ktrace_events_single_paired(s,
	    KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_TMPCPU, 0x3fff),
	    ^(struct trace_point *start, struct trace_point *end)
	{
		struct thsc_cpi counts[2];

		saw_events = true;

		counts[0].tcpi_instructions = start->arg1;
		counts[0].tcpi_cycles = start->arg2;
		counts[1].tcpi_instructions = end->arg1;
		counts[1].tcpi_cycles = end->arg2;

		check_fixed_counts(counts);
	});

	ktrace_set_completion_handler(s, ^{
		T_ASSERT_TRUE(saw_events, "should see monotonic kdebug events");
		T_END;
	});
	T_SETUPEND;

	T_ASSERT_POSIX_ZERO(ktrace_start(s,
	    dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)), NULL);

	r = sysctlbyname("kern.monotonic.kdebug_test", NULL, NULL, &set,
	    sizeof(set));
	T_ASSERT_POSIX_SUCCESS(r,
	    "sysctlbyname(\"kern.monotonic.kdebug_test\", ...)");

	ktrace_end(s, 0);
	dispatch_main();
}

static void *
spin_thread_self_counts(__unused void *arg)
{
	struct thsc_cpi counts = { 0 };
	while (true) {
		(void)thread_selfcounts(THSC_CPI, &counts, sizeof(counts));
	}
}

static void *
spin_task_inspect(__unused void *arg)
{
	task_t task = mach_task_self();
	uint64_t counts[2] = { 0 };
	unsigned int size = 0;
	while (true) {
		size = (unsigned int)sizeof(counts);
		(void)task_inspect(task, TASK_INSPECT_BASIC_COUNTS,
		    (task_inspect_info_t)&counts[0], &size);
		/*
		 * Not realistic for a process to see count values with the high bit
		 * set, but kernel pointers will be that high.
		 */
		T_QUIET; T_ASSERT_LT(counts[0], 1ULL << 63,
		        "check for valid count entry 1");
		T_QUIET; T_ASSERT_LT(counts[1], 1ULL << 63,
		        "check for valid count entry 2");
	}
}

T_DECL(core_fixed_stack_leak_race,
    "ensure no stack data is leaked by TASK_INSPECT_BASIC_COUNTS")
{
	T_SETUPBEGIN;

	int ncpus = 0;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("hw.logicalcpu_max", &ncpus,
	    &(size_t){ sizeof(ncpus) }, NULL, 0), "get number of CPUs");
	T_QUIET; T_ASSERT_GT(ncpus, 0, "got non-zero number of CPUs");
	pthread_t *threads = calloc((unsigned long)ncpus, sizeof(*threads));

	T_QUIET; T_ASSERT_NOTNULL(threads, "allocated space for threads");

	T_LOG("creating %d threads to attempt to race around task counts", ncpus);
	/*
	 * Have half the threads hammering thread_self_counts and the other half
	 * trying to get an error to occur inside TASK_INSPECT_BASIC_COUNTS and see
	 * uninitialized kernel memory.
	 */
	for (int i = 0; i < ncpus; i++) {
		T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&threads[i], NULL,
		    i & 1 ? spin_task_inspect : spin_thread_self_counts, NULL),
		    NULL);
	}

	T_SETUPEND;

	sleep(10);
	T_PASS("ending test after 10 seconds");
}

static void
perf_sysctl_deltas(const char *sysctl_name, const char *stat_name)
{
	uint64_t deltas[2];
	size_t deltas_size;
	int r;

	T_SETUPBEGIN;
	skip_if_unsupported();

	dt_stat_t instrs = dt_stat_create("instructions", "%s_instrs",
	    stat_name);
	dt_stat_t cycles = dt_stat_create("cycles", "%s_cycles", stat_name);
	T_SETUPEND;

	while (!dt_stat_stable(instrs) || !dt_stat_stable(cycles)) {
		deltas_size = sizeof(deltas);
		r = sysctlbyname(sysctl_name, deltas, &deltas_size, NULL, 0);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(r, "sysctlbyname(\"%s\", ...)", sysctl_name);
		dt_stat_add(instrs, (double)deltas[0]);
		dt_stat_add(cycles, (double)deltas[1]);
	}

	dt_stat_finalize(instrs);
	dt_stat_finalize(cycles);
}

T_DECL(perf_core_fixed_cpu, "test the performance of fixed CPU counter access",
    T_META_ASROOT(true), XNU_T_META_SOC_SPECIFIC, T_META_TAG_PERF)
{
	perf_sysctl_deltas("kern.monotonic.fixed_cpu_perf", "fixed_cpu_counters");
}

T_DECL(perf_core_fixed_thread, "test the performance of fixed thread counter access",
    T_META_ASROOT(true), XNU_T_META_SOC_SPECIFIC, T_META_TAG_PERF)
{
	perf_sysctl_deltas("kern.monotonic.fixed_thread_perf",
	    "fixed_thread_counters");
}

T_DECL(perf_core_fixed_task, "test the performance of fixed task counter access",
    T_META_ASROOT(true), XNU_T_META_SOC_SPECIFIC, T_META_TAG_PERF)
{
	perf_sysctl_deltas("kern.monotonic.fixed_task_perf", "fixed_task_counters");
}
