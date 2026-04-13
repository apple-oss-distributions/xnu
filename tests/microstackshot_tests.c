/* Copyright (c) 2018-2021,2024-2025 Apple Inc.  All rights reserved. */

#include <kern/telemetry.h>

#include <CoreFoundation/CoreFoundation.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <ktrace/ktrace.h>
#include <kperf/kperf.h>
#include <kern/debug.h>
#include <mach/mach_time.h>
#include <notify.h>
#include <stdio.h>
#include <sys/kdebug.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>

#include "test_utils.h"
#include "ktrace/ktrace_helpers.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.stackshot.microstackshot"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("stackshot"),
    T_META_OWNER("mwidmann"),
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true));

/*
 * Data Analytics (da) also has a microstackshot configuration -- set a PMI
 * cycle interval of 0 to force it to disable microstackshot on PMI.
 */

static void
set_da_microstackshot_period(CFNumberRef num)
{
	CFPreferencesSetValue(CFSTR("microstackshotPMICycleInterval"), num,
	    CFSTR("com.apple.da"),
#if TARGET_OS_IPHONE
	    CFSTR("mobile"),
#else // TARGET_OS_IPHONE
	    CFSTR("root"),
#endif // !TARGET_OS_IPHONE
	    kCFPreferencesCurrentHost);

	notify_post("com.apple.da.tasking_changed");
}

static void
disable_da_microstackshots(void)
{
	int64_t zero = 0;
	CFNumberRef num = CFNumberCreate(NULL, kCFNumberSInt64Type, &zero);
	set_da_microstackshot_period(num);
	T_LOG("notified da of tasking change, sleeping");
#if TARGET_OS_WATCH
	sleep(8);
#else /* TARGET_OS_WATCH */
	sleep(3);
#endif /* !TARGET_OS_WATCH */
}

/*
 * Unset the preference to allow da to reset its configuration.
 */
static void
reenable_da_microstackshots(void)
{
	set_da_microstackshot_period(NULL);
}

/*
 * Clean up the test's configuration and allow da to activate again.
 */
static void
telemetry_cleanup(void)
{
	(void)__telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_NONE, 0, 0, 0, 0);
	reenable_da_microstackshots();
}

/*
 * Make sure da hasn't configured the microstackshots -- otherwise the PMI
 * setup command will return EBUSY.
 */
static void
telemetry_init(void)
{
	disable_da_microstackshots();
	T_LOG("installing cleanup handler");
	T_ATEND(telemetry_cleanup);
}

volatile static bool spinning = true;

static void *
thread_spin(__unused void *arg)
{
	while (spinning) {
	}
	return NULL;
}

volatile static bool grabbing = true;

static void *
thread_use_memory(__unused void *arg)
{
	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "%s/microstackshot_tests-upl-induce", dt_tmpdir());
	int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, 0777);
	T_ASSERT_POSIX_SUCCESS(fd, "open file for writing for reading");

	while (grabbing) {
		mach_vm_address_t addr = 0;
		mach_vm_size_t size = 1 << 20;

		kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocated %llu bytes", size);
		T_QUIET; T_ASSERT_NE_ULLONG(0ULL, addr, "allocated address is not NULL");
		memset((char *)addr, 0, size);
		ssize_t bytes = write(fd, (char *)addr, size / 4);
		T_QUIET; T_ASSERT_GT(bytes, 0L, "wrote to file");
		kr = mach_vm_deallocate(mach_task_self(), addr, size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocated %llu bytes", size);
	}

	close(fd);
	unlink(path);

	return NULL;
}

static bool
query_pmi_params(unsigned int *pmi_counter, uint64_t *pmi_period)
{
	bool pmi_support = true;
	size_t sysctl_size = sizeof(pmi_counter);
	int ret = sysctlbyname(
			"kern.microstackshot.pmi_sample_counter",
			pmi_counter, &sysctl_size, NULL, 0);
	if (ret == -1 && errno == ENOENT) {
		pmi_support = false;
		T_LOG("no PMI support");
	} else {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "query PMI counter");
	}
	if (pmi_support) {
		sysctl_size = sizeof(*pmi_period);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname(
				"kern.microstackshot.pmi_sample_period",
				pmi_period, &sysctl_size, NULL, 0),
				"query PMI period");
	}
	return pmi_support;
}

__enum_closed_decl(record_type_t, uint16_t, {
	REC_PMI = 0,
	REC_IO,
	REC_VM_FAULT,
	REC_PAGE_GRAB,
	REC_INTERRUPT,
	REC_INVALID,
	REC_COUNT,
});

struct record_info {
	uint32_t ri_bits;
	const char *ri_name;
};

static struct record_info record_info[REC_COUNT] = {
	[REC_PMI] = { .ri_bits = kPMIRecord, .ri_name = "PMI", },
	[REC_IO] = { .ri_bits = kIORecord, .ri_name = "I/O", },
	[REC_VM_FAULT] = { .ri_bits = kVMFaultRecord, .ri_name = "VM fault", },
	[REC_PAGE_GRAB] = { .ri_bits = kPageGrabRecord, .ri_name = "page grab", },
	[REC_INTERRUPT] = { .ri_bits = kInterruptRecord, .ri_name = "interrupt", },
	[REC_INVALID] = {
		.ri_bits = ~(kPMIRecord | kIORecord | kVMFaultRecord | kPageGrabRecord),
		.ri_name = "invalid",
	},
};

struct record_stats {
	unsigned int rs_total_count;
	unsigned int rs_counts[REC_COUNT];
	uint64_t rs_time_range_mach[2];
	double rs_duration_secs;
};

static void
_record_stats_handle(struct record_stats *stats, uint64_t type, uint64_t time_mach)
{
	if (stats->rs_time_range_mach[0] == 0) {
		stats->rs_time_range_mach[0] = time_mach;
	}

	for (uint16_t i = 0; i < REC_COUNT; i++) {
		if (record_info[i].ri_bits & type) {
			stats->rs_counts[i] += 1;
		}
	}
	stats->rs_total_count += 1;

	stats->rs_time_range_mach[1] = time_mach;
}

static void
_record_stats_log(struct record_stats *stats)
{
	uint64_t duration_mach = stats->rs_time_range_mach[1] - stats->rs_time_range_mach[0];
	mach_timebase_info_data_t tb = { 0 };
	(void)mach_timebase_info(&tb);
	uint64_t duration_ns = duration_mach * tb.numer / tb.denom;
	T_LOG("saw record events over %.3f seconds (%.1f%% of expected)",
	    (double)duration_ns / 1e9,
	    (double)duration_ns / 1e9 / stats->rs_duration_secs * 100.0);

	for (uint16_t i = 0; i < REC_COUNT; i++) {
		struct record_info *info = &record_info[i];
		uint32_t count = stats->rs_counts[i];
		if (count == 0) {
			T_LOG("saw no %s record events", info->ri_name);			
		} else {
			double rate = (double)count / (double)stats->rs_duration_secs;
			T_LOG("saw %.2f %s record events per second, %.1f%% of total",
			    rate, info->ri_name,
			    (double)count / (double)stats->rs_total_count * 100.0);
		}
	}
}

#define MT_MICROSTACKSHOT KDBG_EVENTID(DBG_MONOTONIC, 2, 1)
#define MS_RECORD MACHDBG_CODE(DBG_MACH_STACKSHOT, \
	        MICROSTACKSHOT_RECORD)
#if defined(__arm64__)
#define INSTRS_PERIOD (100ULL * 1000 * 1000)
#else /* defined(__arm64__) */
#define INSTRS_PERIOD (1ULL * 1000 * 1000 * 1000)
#endif /* defined(__arm64__) */
#define SLEEP_SECS 10

T_DECL(pmi_sampling, "attempt to configure microstackshots on PMI",
		T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1), T_META_TAG_VM_NOT_ELIGIBLE)
{
	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "session create");

	__block struct record_stats stats = { .rs_duration_secs = SLEEP_SECS, };
	__block int empty_records = 0;

	ktrace_events_single_paired(s, MS_RECORD,
	    ^(struct trace_point *start, __unused struct trace_point *end) {
	    _record_stats_handle(&stats, start->arg1, start->timestamp);

		if (start->arg2 == end->arg2) {
			/*
			 * The buffer didn't grow for this record -- there was
			 * an error.
			 */
			empty_records++;
		}
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		_record_stats_log(&stats);
		T_LOG("saw %d empty records", empty_records);
		T_EXPECT_GT(stats.rs_counts[REC_PMI], 0, "saw non-zero PMI record events");
		T_EXPECT_GT(stats.rs_total_count, 0, "saw non-zero microstackshot record events");
		T_EXPECT_NE(empty_records, stats.rs_total_count, "saw non-empty records");

		T_END;
	});

	T_SETUPEND;

	telemetry_init();

	/*
	 * Start sampling via telemetry on the instructions PMI.
	 */
	int ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
			INSTRS_PERIOD, 0, 0, 0);
	T_ASSERT_POSIX_SUCCESS(ret,
			"telemetry syscall succeeded, started microstackshots");

	unsigned int pmi_counter = 0;
	uint64_t pmi_period = 0;
	bool pmi_support = query_pmi_params(&pmi_counter, &pmi_period);
	T_QUIET; T_ASSERT_TRUE(pmi_support, "PMI should be supported");

	T_LOG("PMI counter: %u", pmi_counter);
	T_LOG("PMI period: %llu", pmi_period);
#if defined(__arm64__)
	const unsigned int instrs_counter = 1;
#else
	const unsigned int instrs_counter = 0;
#endif // defined(__arm64__)
	T_QUIET; T_ASSERT_EQ(pmi_counter, instrs_counter,
			"PMI on instructions retired");
	T_QUIET; T_ASSERT_EQ(pmi_period, INSTRS_PERIOD, "PMI period is set");

	pthread_t thread;
	int error = pthread_create(&thread, NULL, thread_spin, NULL);
	T_ASSERT_POSIX_ZERO(error, "started thread to spin");

	error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, SLEEP_SECS * NSEC_PER_SEC),
			dispatch_get_main_queue(), ^{
		spinning = false;
		ktrace_end(s, 0);
		(void)pthread_join(thread, NULL);
		T_LOG("ending trace session after %d seconds", SLEEP_SECS);
	});

	dispatch_main();
}

static void
_reset_telemetry_memory_usage(void)
{
	(void)__telemetry(TELEMETRY_CMD_MEMORY_USAGE_SETUP, 0, 0, 0, 0, 0);
}

#if TARGET_OS_BRIDGE || defined(__x86_64__)
#define SUPPORTS_MEMORY_MICROSTACKSHOTS false
#else /* TARGET_OS_BRIDGE || defined(__x86_64__) */
#define SUPPORTS_MEMORY_MICROSTACKSHOTS true
#endif /* !(TARGET_OS_BRIDGE || defined(__x86_64__)) */ 

T_DECL(memory_sampling, "attempt to configure microstackshots on memory usage",
		XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL,
		T_META_ENABLED(SUPPORTS_MEMORY_MICROSTACKSHOTS))
{
	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "session create");

	__block struct record_stats stats = { .rs_duration_secs = SLEEP_SECS, };
	__block int empty_records = 0;

	ktrace_events_single_paired(s, MS_RECORD,
	    ^(struct trace_point *start, __unused struct trace_point *end) {
	    _record_stats_handle(&stats, start->arg1, start->timestamp);
		if (start->arg2 == end->arg2) {
			/*
			 * The buffer didn't grow for this record -- there was
			 * an error.
			 */
			empty_records++;
		}
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		_record_stats_log(&stats);
		T_EXPECT_GT(stats.rs_counts[REC_VM_FAULT], 0, "saw non-zero VM fault record events");
		T_EXPECT_GT(stats.rs_counts[REC_PAGE_GRAB], 0, "saw non-zero page grab record events");
		T_EXPECT_GT(stats.rs_total_count, 0, "saw non-zero microstackshot record events");
		T_EXPECT_NE(empty_records, stats.rs_total_count, "saw non-empty records");
		T_END;
	});

	T_SETUPEND;

	telemetry_init();

	/*
	 * Start sampling via telemetry on faults and page grabs.
	 */
	int ret = __telemetry(TELEMETRY_CMD_MEMORY_USAGE_SETUP, 5,
			(1 << 20) / (16 << 10), 0, 0, 0);
	T_ASSERT_POSIX_SUCCESS(ret,
			"telemetry syscall succeeded, started memory microstackshots");
	T_ATEND(_reset_telemetry_memory_usage);

	pthread_t thread;
	int error = pthread_create(&thread, NULL, thread_use_memory, NULL);
	T_ASSERT_POSIX_ZERO(error, "started thread to use memory");

	error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, SLEEP_SECS * NSEC_PER_SEC),
			dispatch_get_main_queue(), ^{
		grabbing = false;
		ktrace_end(s, 0);
		(void)pthread_join(thread, NULL);
		T_LOG("ending trace session after %d seconds", SLEEP_SECS);
	});

	dispatch_main();
}

T_DECL(error_handling,
		"ensure that error conditions for the telemetry syscall are observed",
		T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1), T_META_TAG_VM_NOT_ELIGIBLE)
{
	telemetry_init();

	int ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
	    1, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI every instruction");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
	    1000 * 1000, 0, 0, 0);
	T_EXPECT_EQ(ret, -1,
	    "telemetry shouldn't allow PMI every million instructions");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    1, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI every cycle");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    1000 * 1000, 0, 0, 0);
	T_EXPECT_EQ(ret, -1,
	    "telemetry shouldn't allow PMI every million cycles");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    UINT64_MAX, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI every UINT64_MAX cycles");
}

#define START_EVENT (0xfeedfad0)
#define STOP_EVENT (0xfeedfac0)

T_DECL(excessive_sampling,
		"ensure that microstackshots are not being sampled too frequently",
		T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1), T_META_TAG_VM_NOT_ELIGIBLE)
{
	unsigned int pmi_counter = 0;
	uint64_t pmi_period = 0;
	(void)query_pmi_params(&pmi_counter, &pmi_period);

	T_LOG("PMI counter: %u", pmi_counter);
	T_LOG("PMI period: %llu", pmi_period);

	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "session create");

	__block struct record_stats stats = { .rs_duration_secs = SLEEP_SECS, };
	__block uint64_t first_timestamp_ns = 0;
	__block uint64_t last_timestamp_ns = 0;
	__block int empty_records = 0;

	ktrace_events_single_paired(s, MS_RECORD,
			^(struct trace_point *start, __unused struct trace_point *end) {
		_record_stats_handle(&stats, start->arg1, start->timestamp);
		if (start->arg2 == end->arg2) {
			/*
			 * The buffer didn't grow for this record -- there was
			 * an error.
			 */
			empty_records++;
		}
	});

	ktrace_events_single(s, START_EVENT, ^(struct trace_point *tp) {
		int error = ktrace_convert_timestamp_to_nanoseconds(s,
				tp->timestamp, &first_timestamp_ns);
		T_QUIET;
		T_ASSERT_POSIX_ZERO(error, "converted timestamp to nanoseconds");
	});

	ktrace_events_single(s, STOP_EVENT, ^(struct trace_point *tp) {
		int error = ktrace_convert_timestamp_to_nanoseconds(s,
				tp->timestamp, &last_timestamp_ns);
		T_QUIET;
		T_ASSERT_POSIX_ZERO(error, "converted timestamp to nanoseconds");
		ktrace_end(s, 1);
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		_record_stats_log(&stats);

		T_MAYFAIL;
		T_EXPECT_EQ(stats.rs_counts[REC_INVALID], 0, "saw zero invalid record events");
		T_MAYFAIL;
		T_EXPECT_GT(stats.rs_total_count, 0,
				"saw non-zero microstackshot record events");

		double record_rate_hz = (double)stats.rs_total_count / stats.rs_duration_secs;

		T_EXPECT_LE(record_rate_hz, (double)(dt_ncpu() * 50),
				"found appropriate rate of microstackshots");

		T_END;
	});

	pthread_t thread;
	int error = pthread_create(&thread, NULL, thread_spin, NULL);
	T_ASSERT_POSIX_ZERO(error, "started thread to spin");

	T_SETUPEND;

	error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");
	kdebug_trace(START_EVENT, 0, 0, 0, 0);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, SLEEP_SECS * NSEC_PER_SEC),
			dispatch_get_main_queue(), ^{
		spinning = false;
		kdebug_trace(STOP_EVENT, 0, 0, 0, 0);
		(void)pthread_join(thread, NULL);
		T_LOG("ending trace session after %d seconds", SLEEP_SECS);
	});

	dispatch_main();
}

T_HELPER_DECL(read_kernel_microstackshots,
    "read kernel thread microstackshots to a file")
{
	extern int __microstackshot(char *tracebuf, uint32_t tracebuf_size, uint32_t flags);

	if (argc < 1) {
		T_ASSERT_FAIL("usage: microstackshot_tests -n read_kernel_microstackshots <file>");
	}

	const char *path = argv[0];

	char tracebuf[16 * 1024] = {};
	uint32_t size = (uint32_t)sizeof(tracebuf);

	int ret = __microstackshot(tracebuf, size, 0x08);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "microstackshot(2)");

	T_LOG("read %d bytes from microstackshot syscall ", ret);

	if (ret > 0) {
		FILE *tmp = fopen(path, "w");
		fwrite(tracebuf, ret, 1, tmp);
		fclose(tmp);
	}
	T_LOG("wrote microstackshot data to %s", path);
}
