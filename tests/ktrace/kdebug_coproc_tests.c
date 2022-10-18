// Copyright (c) 2020 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <ktrace/session.h>
#include <ktrace/private.h>
#include <kperf/kperf.h>
#include <stdlib.h>
#include <sys/kdebug.h>
#include <sys/kdebug_private.h>
#include <sys/sysctl.h>
#include <stdint.h>

#include "ktrace_helpers.h"
#include "test_utils.h"
#include "ktrace_meta.h"

static const uint32_t frame_eventid = KDBG_EVENTID(DBG_BSD,
    DBG_BSD_KDEBUG_TEST, 1);

static ktrace_session_t
future_events_session(void)
{
	ktrace_session_t ktsess = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(ktsess, "failed to create session");

	ktrace_events_single(ktsess, KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0),
	    ^(struct trace_point *tp __unused) {
		T_FAIL("saw future test event from IOP");
	});
	ktrace_events_single(ktsess, frame_eventid, ^(struct trace_point *tp) {
		if (tp->debugid & DBG_FUNC_START) {
			T_LOG("saw start event");
		} else {
			T_LOG("saw event traced after trying to trace future event, ending");
			ktrace_end(ktsess, 1);
		}
	});

	ktrace_set_collection_interval(ktsess, 100);
	return ktsess;
}

T_DECL(future_iop_events,
    "make sure IOPs cannot trace events in the future while live tracing")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing");
	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);
	assert_kdebug_test(KDTEST_FUTURE_TIMESTAMP, "induce future times");
	kdebug_trace(frame_eventid | DBG_FUNC_END, 0, 0, 0, 0);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		T_FAIL("ending tracing after timeout");
		ktrace_end(ktsess, 0);
	});

	dispatch_main();
}

T_DECL(future_iop_events_disabled,
    "make sure IOPs cannot trace events in the future after disabling tracing")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();
	T_ASSERT_POSIX_ZERO(ktrace_configure(ktsess), "configure tracing");

	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);
	assert_kdebug_test(KDTEST_FUTURE_TIMESTAMP, "induce future times");
	kdebug_trace(frame_eventid | DBG_FUNC_END, 0, 0, 0, 0);

	T_ASSERT_POSIX_ZERO(ktrace_disable_configured(ktsess),
	    "disable tracing");
	ktrace_session_destroy(ktsess);

	ktsess = future_events_session();
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(ktsess), "use existing trace");
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing existing session");

	dispatch_main();
}

T_DECL(iop_events_disable,
    "make sure IOP events are flushed before disabling trace")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();

	assert_kdebug_test(KDTEST_SETUP_IOP, "setup sync flush IOP");
	T_ASSERT_POSIX_ZERO(ktrace_configure(ktsess), "configure tracing");

	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);

	T_ASSERT_POSIX_ZERO(ktrace_disable_configured(ktsess),
	    "disable tracing");
	ktrace_session_destroy(ktsess);

	ktsess = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NOTNULL(ktsess, "create session");

	ktrace_events_single(ktsess,
	    KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0xff),
	    ^(struct trace_point *tp __unused) {
		T_PASS("saw IOP event from sync flush");
	});

	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(ktsess), "use existing trace");
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing existing session");

	dispatch_main();
}

T_DECL(past_coproc_events,
    "make sure past events from coprocessors log a TRACE_PAST_EVENTS event")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();
	T_ASSERT_POSIX_ZERO(ktrace_configure(ktsess), "configure tracing");

	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);
	assert_kdebug_test(KDTEST_PAST_EVENT, "induce past events");
	kdebug_trace(frame_eventid | DBG_FUNC_END, 0, 0, 0, 0);

	T_ASSERT_POSIX_ZERO(ktrace_disable_configured(ktsess), "disable tracing");
	ktrace_session_destroy(ktsess);

	ktsess = future_events_session();
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(ktsess), "use existing trace");
	__block bool saw_past_event = false;
	ktrace_events_single(ktsess, TRACE_PAST_EVENTS,
			^(__unused ktrace_event_t event) {
		saw_past_event = true;
	});
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_EXPECT_TRUE(saw_past_event, "saw past event");
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing existing session");

	dispatch_main();
}

static void
expect_convert_between_abs_cont(bool abs_to_cont)
{
	uint64_t cur_abs_time, cur_cont_time;
	kern_return_t kr = mach_get_times(&cur_abs_time, &cur_cont_time, NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_get_times");
	bool hasnt_slept = cur_abs_time == cur_cont_time;
	if (hasnt_slept) {
		T_LOG("system hasn't slept, so continuous and absolute times are equal");
		T_LOG("this test cannot ensure time conversions are done properly");
	} else {
		T_LOG("system has slept, times differ by %llu",
		    cur_cont_time - cur_abs_time);
	}

	start_controlling_ktrace();
	ktrace_session_t ktsess = ktrace_session_create();
	ktrace_set_collection_interval(ktsess, 100);
	if (abs_to_cont) {
		ktrace_set_continuous_timestamps(ktsess, true);
	}

	__block bool found_abs_event = false;
	__block bool found_cont_event = false;
	const uint32_t abs_eventid = KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0);
	ktrace_events_single(ktsess, abs_eventid, ^(struct trace_point *tp) {
		found_abs_event = true;
		uint64_t arg_timestamp = (tp->arg1 & UINT32_MAX) | (tp->arg2 << 32);
		if (abs_to_cont) {
			if (hasnt_slept) {
				T_MAYFAIL;
			}
			T_EXPECT_NE(tp->timestamp, arg_timestamp,
			    "timestamp from absolute time IOP should be converted");
		} else {
			T_EXPECT_EQ(tp->timestamp, arg_timestamp,
			    "timestamp from absolute time IOP should not be converted");
		}
		if (found_cont_event && found_abs_event) {
			ktrace_end(ktsess, 1);
		}
	});

	const uint32_t cont_eventid = KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 1);
	ktrace_events_single(ktsess, cont_eventid, ^(struct trace_point *tp) {
		found_cont_event = true;
		uint64_t arg_timestamp = (tp->arg1 & UINT32_MAX) | (tp->arg2 << 32);
		if (abs_to_cont) {
			T_EXPECT_EQ(tp->timestamp, arg_timestamp,
			    "timestamp from continuous time coprocessor should not be "
			    "converted");
		} else {
			if (hasnt_slept) {
				T_MAYFAIL;
			}
			T_EXPECT_NE(tp->timestamp, arg_timestamp,
			    "timestamp from continuous time coprocessor should be "
			    "converted");
		}
		if (found_cont_event && found_abs_event) {
			ktrace_end(ktsess, 1);
		}
	});

	ktrace_set_completion_handler(ktsess, ^{
		T_EXPECT_TRUE(found_abs_event, "absolute time event present");
		T_EXPECT_TRUE(found_cont_event, "continuous time event present");
		ktrace_session_destroy(ktsess);
		T_END;
	});

	assert_kdebug_test(KDTEST_SETUP_IOP, "setup sync flush IOP");
	assert_kdebug_test(KDTEST_SETUP_COPROCESSOR, "setup coprocessor");

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing");
	assert_kdebug_test(KDTEST_ABSOLUTE_TIMESTAMP, "induce absolute times");
	assert_kdebug_test(KDTEST_CONTINUOUS_TIMESTAMP, "induce continuous times");
	T_QUIET;
	T_EXPECT_EQ(kdebug_using_continuous_time(), abs_to_cont,
	    "should be using continuous time");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		T_LOG("ending tracing after timeout");
		ktrace_end(ktsess, 0);
	});
}

T_DECL(absolute_to_continuous_iop,
    "expect IOPs issuing absolute times show up as continuous in the stream")
{
	expect_convert_between_abs_cont(true);
	dispatch_main();
}

T_DECL(continuous_to_absolute_coproc,
    "expect IOPs issuing absolute times show up as continuous in the stream")
{
	expect_convert_between_abs_cont(false);
	dispatch_main();
}
