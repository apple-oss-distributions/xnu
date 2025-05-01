// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "sched_runqueue_harness.h"
#include "sched_migration_harness.h"

extern void                  impl_init_runqueue(void);
extern struct thread_group  *impl_create_tg(int interactivity_score);
extern test_thread_t         impl_create_thread(int th_sched_bucket, struct thread_group *tg, int pri);
extern void                  impl_set_thread_sched_mode(test_thread_t thread, int mode);
extern void                  impl_set_thread_processor_bound(test_thread_t thread, int cpu_id);
extern void                  impl_cpu_set_thread_current(int cpu_id, test_thread_t thread);
extern void                  impl_cpu_clear_thread_current(int cpu_id);
extern void                  impl_cpu_enqueue_thread(int cpu_id, test_thread_t thread);
extern test_thread_t         impl_cpu_dequeue_thread(int cpu_id);
extern test_thread_t         impl_cpu_dequeue_thread_compare_current(int cpu_id);
extern bool                  impl_processor_csw_check(int cpu_id);
extern void                  impl_pop_tracepoint(uint64_t *trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4);
extern bool                  impl_thread_should_yield(int cpu_id);
extern void                  impl_pop_ipi(int *cpu_id, test_ipi_type_t *ipi_type);
extern void                  impl_send_ipi(int cpu_id, test_thread_t thread, test_ipi_event_t event);

/* Migration-specific functions */
extern void                  impl_init_migration_harness(test_hw_topology_t hw_topology);
extern void                  impl_set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, int cluster_id);
extern void                  impl_set_thread_cluster_bound(test_thread_t thread, int cluster_id);
extern int                   impl_choose_pset_for_thread(test_thread_t thread);
extern void                  impl_set_current_processor(int cpu_id);
extern void                  impl_set_pset_load_avg(int cluster_id, int QoS, uint64_t load_avg);
extern void                  impl_set_pset_derecommended(int cluster_id);
extern void                  impl_set_pset_recommended(int cluster_id);
extern uint32_t              impl_qos_max_parallelism(int qos, uint64_t options);
