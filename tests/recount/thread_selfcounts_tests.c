// Copyright (c) 2021-2023 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <stdlib.h>
#include <sys/resource_private.h>
#include <sys/sysctl.h>

#include "test_utils.h"
#include "recount_test_utils.h"

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("cpu counters"),
    T_META_OWNER("mwidmann"),
    T_META_CHECK_LEAKS(false));

static char *amp_fail_reason = "P-binding on AMP scheduler";

static void
_check_cpi(struct thsc_cpi *before, struct thsc_cpi *after, const char *name)
{
	T_QUIET; T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_GT(before->tcpi_instructions, UINT64_C(0),
	    "%s: instructions non-zero", name);
	T_QUIET; T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_GT(before->tcpi_cycles, UINT64_C(0), "%s: cycles non-zero",
	    name);

	T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_GT(after->tcpi_instructions, before->tcpi_instructions,
	    "%s: instructions monotonically-increasing", name);
	T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_GT(after->tcpi_cycles, before->tcpi_cycles,
	    "%s: cycles monotonically-increasing", name);
}

static void
_check_no_cpi(struct thsc_cpi *before, struct thsc_cpi *after, const char *name)
{
	T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_EQ(after->tcpi_instructions, before->tcpi_instructions,
	    "%s: instructions should not increase", name);
	T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_EQ(after->tcpi_cycles, before->tcpi_cycles,
	    "%s: cycles should not increase", name);
}

static struct thsc_cpi
_remove_time_from_cpi(struct thsc_time_cpi *time_cpi)
{
	return (struct thsc_cpi){
		.tcpi_instructions = time_cpi->ttci_instructions,
		.tcpi_cycles = time_cpi->ttci_cycles,
	};
}

static void
_check_time_cpi(struct thsc_time_cpi *before, struct thsc_time_cpi *after,
    const char *name)
{
	struct thsc_cpi before_cpi = _remove_time_from_cpi(before);
	struct thsc_cpi after_cpi = _remove_time_from_cpi(after);
	_check_cpi(&before_cpi, &after_cpi, name);

	T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_GT(after->ttci_user_time_mach, before->ttci_user_time_mach,
			"%s: user time monotonically-increasing", name);

	if (has_user_system_times()) {
		T_MAYFAIL_IF_ENABLED(amp_fail_reason);
		T_EXPECT_GT(after->ttci_system_time_mach, before->ttci_system_time_mach,
				"%s: system time monotonically-increasing", name);
	}
}

static void
_check_no_time_cpi(struct thsc_time_cpi *before, struct thsc_time_cpi *after,
    const char *name)
{
	struct thsc_cpi before_cpi = _remove_time_from_cpi(before);
	struct thsc_cpi after_cpi = _remove_time_from_cpi(after);
	_check_no_cpi(&before_cpi, &after_cpi, name);

	T_MAYFAIL_IF_ENABLED(amp_fail_reason);
	T_EXPECT_EQ(after->ttci_user_time_mach, before->ttci_user_time_mach,
			"%s: user time should not change", name);

	if (has_user_system_times()) {
		T_MAYFAIL_IF_ENABLED(amp_fail_reason);
		T_EXPECT_EQ(after->ttci_system_time_mach, before->ttci_system_time_mach,
				"%s: system time should not change", name);
	}
}

static struct thsc_time_cpi
_remove_energy_from_cpi(struct thsc_time_energy_cpi *energy_cpi)
{
	return (struct thsc_time_cpi){
		.ttci_instructions = energy_cpi->ttec_instructions,
		.ttci_cycles = energy_cpi->ttec_cycles,
		.ttci_system_time_mach = energy_cpi->ttec_system_time_mach,
		.ttci_user_time_mach = energy_cpi->ttec_user_time_mach,
	};
}

static void
_check_usage(struct thsc_time_energy_cpi *before,
    struct thsc_time_energy_cpi *after, const char *name)
{
	struct thsc_time_cpi before_time = _remove_energy_from_cpi(before);
	struct thsc_time_cpi after_time = _remove_energy_from_cpi(after);
	_check_time_cpi(&before_time, &after_time, name);

	if (has_energy()) {
		T_MAYFAIL_IF_ENABLED(amp_fail_reason);
		T_EXPECT_GT(after->ttec_energy_nj, UINT64_C(0),
				"%s: energy monotonically-increasing", name);
	}
}

static void
_check_no_usage(struct thsc_time_energy_cpi *before,
    struct thsc_time_energy_cpi *after, const char *name)
{
	struct thsc_time_cpi before_time = _remove_energy_from_cpi(before);
	struct thsc_time_cpi after_time = _remove_energy_from_cpi(after);
	_check_no_time_cpi(&before_time, &after_time, name);
}

T_DECL(thread_selfcounts_cpi_sanity, "check the current thread's CPI",
    REQUIRE_RECOUNT_PMCS, T_META_TAG_VM_NOT_ELIGIBLE)
{
	int err;
	struct thsc_cpi counts[2] = { 0 };

	err = thread_selfcounts(THSC_CPI, &counts[0], sizeof(counts[0]));
	T_ASSERT_POSIX_ZERO(err, "thread_selfcounts(THSC_CPI, ...)");
	err = thread_selfcounts(THSC_CPI, &counts[1], sizeof(counts[1]));
	T_ASSERT_POSIX_ZERO(err, "thread_selfcounts(THSC_CPI, ...)");

	_check_cpi(&counts[0], &counts[1], "anywhere");
}

T_DECL(thread_selfcounts_perf_level_sanity,
    "check per-perf level time, energy, and CPI",
    REQUIRE_RECOUNT_PMCS,
    // REQUIRE_MULTIPLE_PERF_LEVELS, disabled due to rdar://111297938
    SET_THREAD_BIND_BOOTARG,
    T_META_ASROOT(true), T_META_TAG_VM_NOT_ELIGIBLE)
{
	unsigned int level_count = perf_level_count();

	// Until rdar://111297938, manually skip the test if there aren't multiple perf levels.
	if (level_count < 2) {
		T_SKIP("device is not eligible for checking perf levels because it is SMP");
	}
	struct thsc_time_energy_cpi *before = calloc(level_count, sizeof(*before));
	struct thsc_time_energy_cpi *after = calloc(level_count, sizeof(*after));

	run_on_all_perf_levels();

	int err = thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, before,
			level_count * sizeof(*before));
	T_ASSERT_POSIX_ZERO(err,
			"thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, ...)");

	run_on_all_perf_levels();

	err = thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, after,
			level_count * sizeof(*after));
	T_ASSERT_POSIX_ZERO(err,
			"thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, ...)");

	for (unsigned int i = 0; i < level_count; i++) {
		_check_usage(&before[i], &after[i], perf_level_name(i));
	}

	free(before);
	free(after);
}

static void
_expect_counts_on_perf_level(unsigned int perf_level_index,
		struct thsc_time_energy_cpi *before,
		struct thsc_time_energy_cpi *after)
{
	unsigned int level_count = perf_level_count();
	int err = thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, before,
			level_count * sizeof(*before));
	T_ASSERT_POSIX_ZERO(err,
			"thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, ...)");
	(void)getppid();
	// Allow time for CLPC to read energy counters
	usleep(10000);
	err = thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, after,
			level_count * sizeof(*after));
	T_ASSERT_POSIX_ZERO(err,
			"thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, ...)");

	char *name = perf_level_name(perf_level_index);
	_check_usage(&before[perf_level_index], &after[perf_level_index], name);
}

static void
_expect_no_counts_on_perf_level(unsigned int perf_level_index,
		struct thsc_time_energy_cpi *before,
		struct thsc_time_energy_cpi *after)
{
	unsigned int level_count = perf_level_count();
	int err = thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, before,
			level_count * sizeof(*before));
	T_ASSERT_POSIX_ZERO(err,
			"thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, ...)");
	(void)getppid();
	// Allow time for CLPC to read energy counters
	usleep(10000);
	err = thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, after,
			level_count * sizeof(*after));
	T_ASSERT_POSIX_ZERO(err,
			"thread_selfcounts(THSC_TIME_ENERGY_CPI_PER_PERF_LEVEL, ...)");

	char *name = perf_level_name(perf_level_index);
	_check_no_usage(&before[perf_level_index], &after[perf_level_index], name);
}

T_DECL(thread_selfcounts_perf_level_correct,
    "check that runtimes on each perf level match binding request",
    REQUIRE_RECOUNT_PMCS,
    // REQUIRE_MULTIPLE_PERF_LEVELS, disabled due to rdar://111297938
    SET_THREAD_BIND_BOOTARG,
    T_META_ASROOT(true), T_META_TAG_VM_NOT_ELIGIBLE)
{
	unsigned int level_count = perf_level_count();

	// Until rdar://111297938, manually skip the test if there aren't multiple perf levels.
	if (level_count < 2) {
		T_SKIP("device is not eligible for checking perf levels because it is SMP");
	}
	T_LOG("Currently running the \"%s\" scheduler policy", sched_policy_name());
	bool is_edge_scheduler = strcmp(sched_policy_name(), "edge") == 0;
	for (unsigned int i = 0; i < level_count; i++) {
		T_LOG("Level %d: %s", i, perf_level_name(i));
	}

	struct thsc_time_energy_cpi *before = calloc(level_count, sizeof(*before));
	struct thsc_time_energy_cpi *after = calloc(level_count, sizeof(*after));

	T_LOG("Binding to Efficiency cluster, should only see counts from E-cores");
	T_SETUPBEGIN;
	bind_to_cluster('E');
	T_SETUPEND;
	_expect_counts_on_perf_level(1, before, after);
	_expect_no_counts_on_perf_level(0, before, after);

	T_LOG("Binding to Performance cluster, should only see counts from P-cores");
	T_SETUPBEGIN;
	bind_to_cluster('P');
	T_SETUPEND;
	if (!is_edge_scheduler) {
		T_QUIET; T_EXPECT_EQ_STR(sched_policy_name(), "amp", "Unexpected multicluster scheduling policy");
		T_LOG("The AMP scheduler doesn't guarantee that a P-bound thread will "
		    "only run on P-cores, so the following expects may fail.");
		set_expects_may_fail(true);
	}
	_expect_counts_on_perf_level(0, before, after);
	_expect_no_counts_on_perf_level(1, before, after);

	free(before);
	free(after);
}

T_DECL(thread_selfcounts_cpi_perf,
    "test the overhead of thread_selfcounts(2) THSC_CPI", T_META_TAG_PERF,
    REQUIRE_RECOUNT_PMCS, T_META_TAG_VM_NOT_ELIGIBLE)
{
	struct thsc_cpi counts[2];

	T_SETUPBEGIN;
	dt_stat_t instrs = dt_stat_create("thread_selfcounts_cpi_instrs",
			"instructions");
	dt_stat_t cycles = dt_stat_create("thread_selfcounts_cpi_cycles", "cycles");
	T_SETUPEND;

	while (!dt_stat_stable(instrs) || !dt_stat_stable(cycles)) {
		int r1 = thread_selfcounts(THSC_CPI, &counts[0], sizeof(counts[0]));
		int r2 = thread_selfcounts(THSC_CPI, &counts[1], sizeof(counts[1]));
		T_QUIET; T_ASSERT_POSIX_ZERO(r1, "thread_selfcounts(THSC_CPI, ...)");
		T_QUIET; T_ASSERT_POSIX_ZERO(r2, "thread_selfcounts(THSC_CPI, ...)");

		dt_stat_add(instrs, counts[1].tcpi_instructions -
				counts[0].tcpi_instructions);
		dt_stat_add(cycles, counts[1].tcpi_cycles - counts[0].tcpi_cycles);
	}

	dt_stat_finalize(instrs);
	dt_stat_finalize(cycles);
}
