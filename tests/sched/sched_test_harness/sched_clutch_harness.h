// Copyright (c) 2023 Apple Inc.  All rights reserved.

#pragma once

/* Base harness interface */
#include "sched_harness_impl.h"
#include "sched_migration_harness.h"

#include <sys/types.h>
#include <kern/sched.h>

extern int root_bucket_to_highest_pri[TH_BUCKET_SCHED_MAX];

/* Publish Clutch implementation-specific paramemeters for use in unit tests */
extern uint64_t clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX];
extern uint64_t clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX];
extern int clutch_interactivity_score_max;

/* Clutch trace codes */
extern unsigned int CLUTCH_THREAD_SELECT;

/* Used by the Edge harness */
extern void clutch_impl_init_topology(test_hw_topology_t hw_topology);
extern void clutch_impl_init_params(void);
extern void clutch_impl_init_tracepoints(void);
extern struct thread_group *clutch_impl_create_tg(int interactivity_score);
extern test_thread_t clutch_impl_create_thread(int root_bucket, struct thread_group *tg, int pri);
extern void clutch_impl_set_thread_sched_mode(test_thread_t thread, int mode);
extern void clutch_impl_set_thread_processor_bound(test_thread_t thread, int cpu_id);
extern void clutch_impl_cpu_set_thread_current(int cpu_id, test_thread_t thread);
extern void clutch_impl_cpu_clear_thread_current(int cpu_id);
extern void clutch_impl_log_tracepoint(uint64_t trace_code, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
extern void clutch_impl_pop_tracepoint(uint64_t *clutch_trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4);
