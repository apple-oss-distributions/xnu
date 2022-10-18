// Copyright (c) 2021 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <stdlib.h>
#include <sys/resource_private.h>
#include <sys/sysctl.h>

#include "test_utils.h"
#include "recount_test_utils.h"

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("RM"),
    T_META_OWNER("mwidmann"),
    T_META_CHECK_LEAKS(false));

static void
_check_cpi(struct thsc_cpi *before, struct thsc_cpi *after, const char *name)
{
	T_QUIET;
	T_EXPECT_GT(before->tcpi_instructions, UINT64_C(0),
	    "%s: instructions non-zero", name);
	T_QUIET;
	T_EXPECT_GT(before->tcpi_cycles, UINT64_C(0), "%s: cycles non-zero",
	    name);

	T_EXPECT_GT(after->tcpi_instructions, before->tcpi_instructions,
	    "%s: instructions monotonically-increasing", name);
	T_EXPECT_GT(after->tcpi_cycles, before->tcpi_cycles,
	    "%s: cycles monotonically-increasing", name);
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

	T_EXPECT_GT(after->ttci_user_time_mach, before->ttci_user_time_mach,
			"%s: user time monotonically-increasing", name);

	if (has_user_system_times()) {
		T_EXPECT_GT(after->ttci_system_time_mach, before->ttci_system_time_mach,
				"%s: system time monotonically-increasing", name);
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
		T_EXPECT_GT(after->ttec_energy_nj, UINT64_C(0),
				"%s: energy monotonically-increasing", name);
	}
}

T_DECL(thread_selfcounts_cpi_sanity, "check the current thread's CPI",
    REQUIRE_RECOUNT_PMCS)
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
    REQUIRE_MULTIPLE_PERF_LEVELS,
    SET_THREAD_BIND_BOOTARG,
    T_META_ASROOT(true))
{
	unsigned int level_count = perf_level_count();
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

T_DECL(thread_selfcounts_cpi_perf,
    "test the overhead of thread_selfcounts(2) THSC_CPI", T_META_TAG_PERF,
    REQUIRE_RECOUNT_PMCS)
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
