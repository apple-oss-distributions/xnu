// Copyright (c) 2023 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* Opaque thread pointer */
typedef void *test_thread_t;

/* Mocking mach_absolute_time() */
#define mach_absolute_time mock_absolute_time
extern uint64_t  mock_absolute_time(void);
extern void      set_mock_time(uint64_t timestamp);
extern void      increment_mock_time(uint64_t added_time);
extern void      increment_mock_time_us(uint64_t added_us);

/* Test harness utilities */
extern void                  init_harness(char *test_name);
extern struct thread_group  *create_tg(int interactivity_score);
extern test_thread_t         create_thread(int th_sched_bucket, struct thread_group *tg, int pri);
extern void                  set_thread_sched_mode(test_thread_t thread, int mode);
extern void                  set_thread_processor_bound(test_thread_t thread);
extern void                  set_thread_current(test_thread_t thread);
extern bool                  runqueue_empty(void);
extern void                  enqueue_thread(test_thread_t thread);
extern void                  enqueue_threads(int num_threads, ...);
extern void                  enqueue_threads_arr(int num_threads, test_thread_t *threads);
extern void                  enqueue_threads_rand_order(unsigned int random_seed, int num_threads, ...);
extern void                  enqueue_threads_arr_rand_order(unsigned int random_seed, int num_threads, test_thread_t *threads);
extern bool                  dequeue_thread_expect(test_thread_t expected_thread);
extern int                   dequeue_threads_expect_ordered(int num_threads, ...);
extern int                   dequeue_threads_expect_ordered_arr(int num_threads, test_thread_t *threads);
extern bool                  dequeue_thread_expect_compare_current(test_thread_t expected_thread);
extern bool                  check_preempt_current(bool preemption_expected);
extern bool                  tracepoint_expect(uint64_t trace_code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
extern void                  disable_auto_current_thread(void);

/* Functions implemented by specific scheduler policy (i.e. Clutch) */
extern void                  impl_init_runqueue(void);
extern struct thread_group  *impl_create_tg(int interactivity_score);
extern test_thread_t         impl_create_thread(int th_sched_bucket, struct thread_group *tg, int pri);
extern void                  impl_set_thread_sched_mode(test_thread_t thread, int mode);
extern void                  impl_set_thread_processor_bound(test_thread_t thread);
extern void                  impl_set_thread_current(test_thread_t thread);
extern void                  impl_clear_thread_current(void);
extern void                  impl_enqueue_thread(test_thread_t thread);
extern test_thread_t         impl_dequeue_thread(void);
extern test_thread_t         impl_dequeue_thread_compare_current(void);
extern bool                  impl_processor_csw_check(void);
extern void                  impl_pop_tracepoint(uint64_t *trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4);
extern void                  impl_cleanup_harness(void);
