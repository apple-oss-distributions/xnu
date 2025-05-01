// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* Opaque thread pointer */
typedef void *test_thread_t;

/* Publish access to debug log */
extern FILE *_log;

/* Mocking mach_absolute_time() */
#define mach_absolute_time mock_absolute_time
extern uint64_t  mock_absolute_time(void);
extern void      set_mock_time(uint64_t timestamp);
extern void      increment_mock_time(uint64_t added_time);
extern void      increment_mock_time_us(uint64_t added_us);

/* Specifying a runqueue */
typedef enum {
	TEST_RUNQ_TARGET_TYPE_CPU,
	TEST_RUNQ_TARGET_TYPE_CLUSTER,
} test_runq_target_type_t;

typedef struct {
	test_runq_target_type_t target_type;
	int target_id;
} test_runq_target_t;

extern test_runq_target_t default_target;

extern int get_default_cpu(void);
extern test_runq_target_t cluster_target(int cluster_id);
extern test_runq_target_t cpu_target(int cpu_id);

/* Test harness utilities */
extern void                  init_harness_logging(char *test_name);
extern void                  init_runqueue_harness(void);
#define INITIAL_INTERACTIVITY_SCORE -1
extern struct thread_group  *create_tg(int interactivity_score);
extern test_thread_t         create_thread(int th_sched_bucket, struct thread_group *tg, int pri);
extern void                  set_thread_sched_mode(test_thread_t thread, int mode);
extern void                  set_thread_processor_bound(test_thread_t thread, int cpu_id);
extern void                  cpu_set_thread_current(int cpu_id, test_thread_t thread);
extern bool                  runqueue_empty(test_runq_target_t runq_target);
extern void                  enqueue_thread(test_runq_target_t runq_target, test_thread_t thread);
extern void                  enqueue_threads(test_runq_target_t runq_target, int num_threads, ...);
extern void                  enqueue_threads_arr(test_runq_target_t runq_target, int num_threads, test_thread_t *threads);
extern void                  enqueue_threads_rand_order(test_runq_target_t runq_target, unsigned int random_seed, int num_threads, ...);
extern void                  enqueue_threads_arr_rand_order(test_runq_target_t runq_target, unsigned int random_seed, int num_threads, test_thread_t *threads);
extern bool                  dequeue_thread_expect(test_runq_target_t runq_target, test_thread_t expected_thread);
extern int                   dequeue_threads_expect_ordered(test_runq_target_t runq_target, int num_threads, ...);
extern int                   dequeue_threads_expect_ordered_arr(test_runq_target_t runq_target, int num_threads, test_thread_t *threads);
extern bool                  cpu_dequeue_thread_expect_compare_current(int cpu_id, test_thread_t expected_thread);
extern bool                  cpu_check_preempt_current(int cpu_id, bool preemption_expected);
extern bool                  tracepoint_expect(uint64_t trace_code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
extern void                  disable_auto_current_thread(void);
extern void                  reenable_auto_current_thread(void);
extern bool                  cpu_check_should_yield(int cpu_id, bool yield_expected);
