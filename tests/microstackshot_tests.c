/* Copyright (c) 2018-2021 Apple Inc.  All rights reserved. */

#include <CoreFoundation/CoreFoundation.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <ktrace/ktrace.h>
#include <kperf/kperf.h>
#include <kern/debug.h>
#include <notify.h>
#include <sys/kdebug.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>

#include "ktrace/ktrace_helpers.h"

enum telemetry_pmi {
	TELEMETRY_PMI_NONE,
	TELEMETRY_PMI_INSTRS,
	TELEMETRY_PMI_CYCLES,
};
#define TELEMETRY_CMD_PMI_SETUP 3

T_GLOBAL_META(T_META_NAMESPACE("xnu.stackshot.microstackshot"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("stackshot"),
    T_META_OWNER("mwidmann"),
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true));

extern int __telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval,
    uint64_t leeway, uint64_t arg4, uint64_t arg5);

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

#define MT_MICROSTACKSHOT KDBG_EVENTID(DBG_MONOTONIC, 2, 1)
#define MS_RECORD MACHDBG_CODE(DBG_MACH_STACKSHOT, \
	        MICROSTACKSHOT_RECORD)
#if defined(__arm64__) || defined(__arm__)
#define INSTRS_PERIOD (100ULL * 1000 * 1000)
#else /* defined(__arm64__) || defined(__arm__) */
#define INSTRS_PERIOD (1ULL * 1000 * 1000 * 1000)
#endif /* !defined(__arm64__) && !defined(__arm__) */
#define SLEEP_SECS 10

T_DECL(pmi_sampling, "attempt to configure microstackshots on PMI",
		T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1))
{
	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "session create");

	__block int pmi_events = 0;
	__block int microstackshot_record_events = 0;
	__block int pmi_records = 0;
	__block int io_records = 0;
	__block int interrupt_records = 0;
	__block int timer_arm_records = 0;
	__block int unknown_records = 0;
	__block int empty_records = 0;

	ktrace_events_single(s, MT_MICROSTACKSHOT, ^(__unused struct trace_point *tp) {
		pmi_events++;
	});
	ktrace_events_single_paired(s, MS_RECORD,
	    ^(struct trace_point *start, __unused struct trace_point *end) {
		if (start->arg1 & kPMIRecord) {
		        pmi_records++;
		}
		if (start->arg1 & kIORecord) {
		        io_records++;
		}
		if (start->arg1 & kInterruptRecord) {
		        interrupt_records++;
		}
		if (start->arg1 & kTimerArmingRecord) {
		        timer_arm_records++;
		}

		if (start->arg2 == end->arg2) {
			/*
			 * The buffer didn't grow for this record -- there was
			 * an error.
			 */
			empty_records++;
		}

		const uint8_t any_record = kPMIRecord | kIORecord | kInterruptRecord |
		kTimerArmingRecord;
		if ((start->arg1 & any_record) == 0) {
		        unknown_records++;
		}

		microstackshot_record_events++;
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		T_EXPECT_GT(pmi_events, 0, "saw non-zero PMIs (%g/sec)",
				pmi_events / (double)SLEEP_SECS);
		T_EXPECT_GT(pmi_records, 0, "saw non-zero PMI record events (%g/sec)",
				pmi_records / (double)SLEEP_SECS);
		T_LOG("saw %d unknown record events", unknown_records);
		T_EXPECT_GT(microstackshot_record_events, 0,
				"saw non-zero microstackshot record events (%d -- %g/sec)",
				microstackshot_record_events,
				microstackshot_record_events / (double)SLEEP_SECS);
		T_EXPECT_NE(empty_records, microstackshot_record_events,
				"saw non-empty records (%d empty)", empty_records);

		if (interrupt_records > 0) {
			T_LOG("saw %g interrupt records per second",
					interrupt_records / (double)SLEEP_SECS);
		} else {
			T_LOG("saw no interrupt records");
		}
		if (io_records > 0) {
			T_LOG("saw %g I/O records per second",
					io_records / (double)SLEEP_SECS);
		} else {
			T_LOG("saw no I/O records");
		}
		if (timer_arm_records > 0) {
			T_LOG("saw %g timer arming records per second",
					timer_arm_records / (double)SLEEP_SECS);
		} else {
			T_LOG("saw no timer arming records");
		}

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

T_DECL(error_handling,
		"ensure that error conditions for the telemetry syscall are observed",
		T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1))
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
		T_META_REQUIRES_SYSCTL_EQ("kern.monotonic.supported", 1))
{
	unsigned int interrupt_sample_rate = 0;
	size_t sysctl_size = sizeof(interrupt_sample_rate);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(
			"kern.microstackshot.interrupt_sample_rate",
			&interrupt_sample_rate, &sysctl_size, NULL, 0),
			"query interrupt sample rate");
	unsigned int pmi_counter = 0;
	uint64_t pmi_period = 0;
	(void)query_pmi_params(&pmi_counter, &pmi_period);

	T_LOG("interrupt sample rate: %uHz", interrupt_sample_rate);
	T_LOG("PMI counter: %u", pmi_counter);
	T_LOG("PMI period: %llu", pmi_period);

	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "session create");

	__block int microstackshot_record_events = 0;
	__block int pmi_records = 0;
	__block int io_records = 0;
	__block int interrupt_records = 0;
	__block int timer_arm_records = 0;
	__block int unknown_records = 0;
	__block int empty_records = 0;
	__block uint64_t first_timestamp_ns = 0;
	__block uint64_t last_timestamp_ns = 0;

	ktrace_events_single_paired(s, MS_RECORD,
			^(struct trace_point *start, __unused struct trace_point *end) {
		if (start->arg1 & kPMIRecord) {
			pmi_records++;
		}
		if (start->arg1 & kIORecord) {
			io_records++;
		}
		if (start->arg1 & kInterruptRecord) {
			interrupt_records++;
		}
		if (start->arg1 & kTimerArmingRecord) {
			timer_arm_records++;
		}

		if (start->arg2 == end->arg2) {
			/*
			 * The buffer didn't grow for this record -- there was
			 * an error.
			 */
			empty_records++;
		}

		const uint8_t any_record = kPMIRecord | kIORecord | kInterruptRecord |
				kTimerArmingRecord;
		if ((start->arg1 & any_record) == 0) {
			unknown_records++;
		}

		microstackshot_record_events++;
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

		uint64_t duration_ns = last_timestamp_ns - first_timestamp_ns;
		double duration_secs = (double)duration_ns / 1e9;

		T_LOG("test lasted %g seconds", duration_secs);

		T_MAYFAIL;
		T_EXPECT_EQ(unknown_records, 0, "saw zero unknown record events");
		T_MAYFAIL;
		T_EXPECT_GT(microstackshot_record_events, 0,
				"saw non-zero microstackshot record events (%d, %gHz)",
				microstackshot_record_events,
				microstackshot_record_events / duration_secs);
		T_EXPECT_NE(empty_records, microstackshot_record_events,
				"saw non-empty records (%d empty)", empty_records);

		double record_rate_hz = microstackshot_record_events / duration_secs;
		T_LOG("record rate: %gHz", record_rate_hz);
		T_LOG("PMI record rate: %gHz", pmi_records / duration_secs);
		T_LOG("interrupt record rate: %gHz",
				interrupt_records / duration_secs);
		T_LOG("I/O record rate: %gHz", io_records / duration_secs);
		T_LOG("timer arm record rate: %gHz",
				timer_arm_records / duration_secs);

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
