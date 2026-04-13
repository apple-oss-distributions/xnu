// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <kern/kern_types.h>

#include "sched_runqueue_harness.h"
#include "sched_migration_harness.h"

extern void                  impl_init_runqueue(void);
extern struct thread_group  *impl_create_tg(int interactivity_score);
extern test_thread_t         impl_create_thread(int th_sched_bucket, struct thread_group *tg, int pri);
extern void                  impl_set_thread_sched_mode(test_thread_t thread, int mode);
extern bool                  impl_get_thread_is_realtime(test_thread_t thread);
extern void                  impl_set_thread_processor_bound(test_thread_t thread, int cpu_id);
extern void                  impl_cpu_set_thread_current(int cpu_id, test_thread_t thread);
extern test_thread_t         impl_cpu_clear_thread_current(int cpu_id);
extern void                  impl_cpu_enqueue_thread(int cpu_id, test_thread_t thread);
extern test_thread_t         impl_cpu_dequeue_thread(int cpu_id);
extern test_thread_t         impl_cpu_dequeue_thread_compare_current(int cpu_id);
extern bool                  impl_processor_csw_check(int cpu_id);
extern void                  impl_pop_tracepoint(uint64_t trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4);
extern bool                  impl_thread_should_yield(int cpu_id);
extern void                  impl_pop_ipi(int *cpu_id, test_ipi_type_t *ipi_type);
extern void                  impl_send_ipi(int cpu_id, test_thread_t thread, test_ipi_event_t event);
extern uint64_t              impl_get_thread_tid(test_thread_t thread);
extern int                   impl_pset_id_to_cpu_id(pset_id_t pset_id);
extern pset_id_t             impl_cpu_id_to_pset_id(int cpu_id);

/* Migration-specific functions */
extern test_sched_topology_t impl_init_migration_harness(test_hw_topology_t hw_topology);
extern void                  impl_set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, pset_id_t pset_id);
extern void                  impl_set_thread_pset_bound(test_thread_t thread, pset_id_t pset_id);
extern int                   impl_choose_pset_for_thread(test_thread_t thread, test_sched_options_t options);
extern bool                  impl_thread_avoid_processor(test_thread_t thread, int cpu_id, bool quantum_expiry);
extern void                  impl_cpu_expire_quantum(int cpu_id);
extern test_thread_t         impl_steal_thread(int cpu_id);
extern bool                  impl_processor_balance(int cpu_id);
extern void                  impl_cpu_clear_pending_ast_bits(int cpu_id);
extern void                  impl_set_current_processor(int cpu_id);
extern void                  impl_set_pset_load_avg(int pset_id, int QoS, uint32_t load_avg);
extern void                  impl_set_pset_derecommended(int pset_id);
extern int                   impl_iterate_pset_search_order_rt(int src_pset_id, int offset);
extern void                  impl_set_pset_recommended(int pset_id);
extern uint32_t              impl_qos_max_parallelism(int qos, uint64_t options);
extern int                  *impl_iterate_pset_search_order(int src_pset_id, uint64_t candidate_map, int sched_bucket);

/* Realtime */
extern void                  impl_set_thread_realtime(test_thread_t thread, uint32_t period, uint32_t computation, uint32_t constraint, bool preemptible, uint8_t priority_offset, uint64_t deadline);
extern test_thread_t         impl_rt_choose_thread(int cpu_id);
