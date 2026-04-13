// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <stdlib.h>
#include <stdio.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "sched_runqueue_harness.h"
#include "sched_harness_impl.h"

FILE *_log = NULL;

static const int default_cpu = 0;

/* Mocking mach_absolute_time() */

static mach_timebase_info_data_t _timebase_info;
static uint64_t _curr_time = 0;

uint64_t
mock_absolute_time(void)
{
	return _curr_time;
}

void
set_mock_time(uint64_t timestamp)
{
	fprintf(_log, "\tnew mock time: %llu (%lluus)\n", timestamp,
	    timestamp * _timebase_info.numer / _timebase_info.denom / NSEC_PER_USEC);
	_curr_time = timestamp;
}

void
increment_mock_time(uint64_t added_time)
{
	set_mock_time(_curr_time + added_time);
}

void
increment_mock_time_us(uint64_t us)
{
	fprintf(_log, "\tadding mock microseconds: %lluus\n", us);
	increment_mock_time((us * NSEC_PER_USEC) * _timebase_info.denom / _timebase_info.numer);
}

/* Test harness utilities */

static void
cleanup_runqueue_harness(void)
{
	fclose(_log);
}

int
pset_id_to_cpu_id(int pset_id)
{
	return impl_pset_id_to_cpu_id((pset_id_t)pset_id);
}

int
cpu_id_to_pset_id(int cpu_id)
{
	return (int)impl_cpu_id_to_pset_id(cpu_id);
}

static char _log_filepath[MAXPATHLEN];
static bool auto_current_thread_disabled = false;

void
init_harness_logging(char *test_name)
{
	kern_return_t kr;
	kr = mach_timebase_info(&_timebase_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");
	auto_current_thread_disabled = false;

	/* Set up debugging log of harness events */
	strcpy(_log_filepath, test_name);
	strcat(_log_filepath, "_test_log.txt");
	dt_resultfile(_log_filepath, sizeof(_log_filepath));
	_log = fopen(_log_filepath, "w+");
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NE(_log, NULL, "fopen");
	T_LOG("For debugging, see log of harness events in \"%s\"", _log_filepath);

	T_ATEND(cleanup_runqueue_harness);
}

void
init_runqueue_harness(void)
{
	init_harness_logging(T_NAME);
	impl_init_runqueue();
}

struct thread_group *
create_tg(int interactivity_score)
{
	struct thread_group *tg = impl_create_tg(interactivity_score);
	fprintf(_log, "\tcreated TG %p w/ interactivity_score %d\n", (void *)tg, interactivity_score);
	return tg;
}

test_thread_t
create_thread(int th_sched_bucket, struct thread_group *tg, int pri)
{
	test_thread_t thread = impl_create_thread(th_sched_bucket, tg, pri);
	fprintf(_log, "\tcreated thread %p w/ bucket %d, tg %p, pri %d\n",
	    (void *)thread, th_sched_bucket, (void *)tg, pri);
	return thread;
}

void
set_thread_sched_mode(test_thread_t thread, int mode)
{
	fprintf(_log, "\tset thread %p sched_mode to %d\n", (void *)thread, mode);
	impl_set_thread_sched_mode(thread, mode);
}

void
set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	fprintf(_log, "\tset thread %p processor-bound to cpu %d\n", (void *)thread, cpu_id);
	impl_set_thread_processor_bound(thread, cpu_id);
}

void
cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	impl_cpu_set_thread_current(cpu_id, thread);
	fprintf(_log, "\tset %p as current thread on cpu %d\n", thread, cpu_id);
}

test_thread_t
cpu_clear_thread_current(int cpu_id)
{
	fprintf(_log, "\tclearing the current thread from cpu %d\n", cpu_id);
	return impl_cpu_clear_thread_current(cpu_id);
}

bool
runqueue_empty(test_runq_target_t runq_target)
{
	return dequeue_thread_expect(runq_target, NULL);
}

static int
runq_target_to_cpu_id(test_runq_target_t runq_target)
{
	switch (runq_target.target_type) {
	case TEST_RUNQ_TARGET_TYPE_CPU:
		return runq_target.target_id;
	case TEST_RUNQ_TARGET_TYPE_PSET:
		return pset_id_to_cpu_id(runq_target.target_id);
	default:
		T_ASSERT_FAIL("unexpected type %d", runq_target.target_type);
	}
}

int
get_default_cpu(void)
{
	return default_cpu;
}

test_runq_target_t default_target = {
	.target_type = TEST_RUNQ_TARGET_TYPE_CPU,
	.target_id = default_cpu,
};

static void
cpu_enqueue_thread(int cpu_id, test_thread_t thread)
{
	fprintf(_log, "\tenqueued %p to cpu %d\n", (void *)thread, cpu_id);
	impl_cpu_enqueue_thread(cpu_id, thread);
}

test_runq_target_t
pset_target(int pset_id)
{
	test_runq_target_t target = {
		.target_type = TEST_RUNQ_TARGET_TYPE_PSET,
		.target_id = pset_id,
	};
	return target;
}

test_runq_target_t
cpu_target(int cpu_id)
{
	test_runq_target_t target = {
		.target_type = TEST_RUNQ_TARGET_TYPE_CPU,
		.target_id = cpu_id,
	};
	return target;
}

void
enqueue_thread(test_runq_target_t runq_target, test_thread_t thread)
{
	int cpu_id = runq_target_to_cpu_id(runq_target);
	cpu_enqueue_thread(cpu_id, thread);
}

void
enqueue_threads(test_runq_target_t runq_target, int num_threads, ...)
{
	va_list args;
	va_start(args, num_threads);
	for (int i = 0; i < num_threads; i++) {
		test_thread_t thread = va_arg(args, test_thread_t);
		enqueue_thread(runq_target, thread);
	}
	va_end(args);
}

void
enqueue_threads_arr(test_runq_target_t runq_target, int num_threads, test_thread_t *threads)
{
	for (int i = 0; i < num_threads; i++) {
		enqueue_thread(runq_target, threads[i]);
	}
}

void
enqueue_threads_rand_order(test_runq_target_t runq_target, unsigned int random_seed, int num_threads, ...)
{
	va_list args;
	va_start(args, num_threads);
	test_thread_t *tmp = (test_thread_t *)calloc(num_threads, sizeof(test_thread_t));
	for (int i = 0; i < num_threads; i++) {
		test_thread_t thread = va_arg(args, test_thread_t);
		tmp[i] = thread;
	}
	enqueue_threads_arr_rand_order(runq_target, random_seed, num_threads, tmp);
	free(tmp);
	va_end(args);
}

void
enqueue_threads_arr_rand_order(test_runq_target_t runq_target, unsigned int random_seed, int num_threads, test_thread_t *threads)
{
	test_thread_t scratch_space[num_threads];
	for (int i = 0; i < num_threads; i++) {
		scratch_space[i] = threads[i];
	}
	srand(random_seed);
	for (int i = 0; i < num_threads; i++) {
		int rand_ind = (rand() % (num_threads - i)) + i;
		test_thread_t tmp = scratch_space[i];
		scratch_space[i] = scratch_space[rand_ind];
		scratch_space[rand_ind] = tmp;
	}
	enqueue_threads_arr(runq_target, num_threads, scratch_space);
}

bool
dequeue_thread_expect(test_runq_target_t runq_target, test_thread_t expected_thread)
{
	int cpu_id = runq_target_to_cpu_id(runq_target);
	test_thread_t chosen_thread = impl_cpu_dequeue_thread(cpu_id);
	fprintf(_log, "%s: dequeued %p from cpu %d, expecting %p\n", chosen_thread == expected_thread ?
	    "PASS" : "FAIL", (void *)chosen_thread, cpu_id, (void *)expected_thread);
	if (chosen_thread != expected_thread) {
		return false;
	}
	if (expected_thread != NULL && auto_current_thread_disabled == false && impl_get_thread_is_realtime(chosen_thread) == false) {
		/*
		 * Additionally verify that chosen_thread still gets returned as the highest
		 * thread, even when compared against the remaining runqueue as the currently
		 * running thread.
		 */
		cpu_set_thread_current(cpu_id, expected_thread);
		bool pass = cpu_dequeue_thread_expect_compare_current(cpu_id, expected_thread);
		if (pass) {
			pass = cpu_check_preempt_current(cpu_id, false);
		}
		impl_cpu_clear_thread_current(cpu_id);
		fprintf(_log, "\tcleared current thread\n");
		return pass;
	}
	return true;
}

int
dequeue_threads_expect_ordered(test_runq_target_t runq_target, int num_threads, ...)
{
	va_list args;
	va_start(args, num_threads);
	int first_bad_index = -1;
	for (int i = 0; i < num_threads; i++) {
		test_thread_t thread = va_arg(args, test_thread_t);
		bool result = dequeue_thread_expect(runq_target, thread);
		if ((result == false) && (first_bad_index == -1)) {
			first_bad_index = i;
			/* Instead of early-returning, keep dequeueing threads so we can log the information */
		}
	}
	va_end(args);
	return first_bad_index;
}

int
dequeue_threads_expect_ordered_arr(test_runq_target_t runq_target, int num_threads, test_thread_t *threads)
{
	int first_bad_index = -1;
	for (int i = 0; i < num_threads; i++) {
		bool result = dequeue_thread_expect(runq_target, threads[i]);
		if ((result == false) && (first_bad_index == -1)) {
			first_bad_index = i;
			/* Instead of early-returning, keep dequeueing threads so we can log the information */
		}
	}
	return first_bad_index;
}

bool
cpu_dequeue_thread_expect_compare_current(int cpu_id, test_thread_t expected_thread)
{
	test_thread_t chosen_thread = impl_cpu_dequeue_thread_compare_current(cpu_id);
	fprintf(_log, "%s: dequeued %p from cpu %d, expecting current %p\n", chosen_thread == expected_thread ?
	    "PASS" : "FAIL", (void *)chosen_thread, cpu_id, (void *)expected_thread);
	return chosen_thread == expected_thread;
}

bool
cpu_check_preempt_current(int cpu_id, bool preemption_expected)
{
	bool preempting = impl_processor_csw_check(cpu_id);
	fprintf(_log, "%s: would preempt on cpu %d? %d, expecting to preempt? %d\n", preempting == preemption_expected ?
	    "PASS" : "FAIL", cpu_id, preempting, preemption_expected);
	return preempting == preemption_expected;
}

static bool
tracepoint_arg_expect(uint64_t expected_arg, uint64_t found_arg)
{
	return (found_arg == expected_arg) || (expected_arg == TRACEPOINT_EXPECT_IGNORE_ARG);
}

bool
tracepoint_expect(uint64_t trace_code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
	uint64_t popped_arg1, popped_arg2, popped_arg3, popped_arg4;
	impl_pop_tracepoint(trace_code, &popped_arg1, &popped_arg2, &popped_arg3, &popped_arg4);
	bool pass = tracepoint_arg_expect(arg1, popped_arg1) && tracepoint_arg_expect(arg2, popped_arg2) &&
	    tracepoint_arg_expect(arg3, popped_arg3) && tracepoint_arg_expect(arg4, popped_arg4);
	fprintf(_log, "%s: expected code %llx arg1 %llx arg2 %llx arg3 %llx arg4 %llx\n", pass ? "PASS" : "FAIL",
	    trace_code, arg1, arg2, arg3, arg4);
	if (pass == false) {
		fprintf(_log, "\tfound code %llx arg1 %llx arg2 %llx arg3 %llx arg4 %llx\n",
		    trace_code, popped_arg1, popped_arg2, popped_arg3, popped_arg4);
	}
	return pass;
}

void
disable_auto_current_thread(void)
{
	auto_current_thread_disabled = true;
}

void
reenable_auto_current_thread(void)
{
	auto_current_thread_disabled = false;
}

uint64_t
get_thread_tid(test_thread_t thread)
{
	return impl_get_thread_tid(thread);
}

#pragma mark - Realtime

void
set_thread_realtime(test_thread_t thread, uint32_t period, uint32_t computation, uint32_t constraint, bool preemptible, uint8_t priority_offset, uint64_t deadline)
{
	fprintf(_log, "\tsetting realtime deadline on thread %p: period=0x%x, computation=0x%x, constraint=0x%x,"
	    " preemptible=%s, priority_offset=%x, deadline=%llx\n", (void *) thread, period, computation, constraint,
	    preemptible ? "true" : "false", priority_offset, deadline);
	impl_set_thread_realtime(thread, period, computation, constraint, preemptible, priority_offset, deadline);
}
