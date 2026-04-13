// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include "sched_harness_impl.h"
#include "sched_clutch_harness.h"
/* To get sched_clutch_edge and cluster_shared_rsrc_type_t */
#include <kern/kern_types.h>

/* Edge trace codes */
extern const unsigned int EDGE_REBAL_RUNNABLE;
extern const unsigned int EDGE_REBAL_RUNNING;
extern const unsigned int EDGE_STEAL;
extern const unsigned int EDGE_SHOULD_YIELD;

extern void edge_set_thread_shared_rsrc(test_thread_t thread, bool native_first);

extern int pset_cpu_count_for_id(int pset_id);
extern test_cpu_type_t pset_cpu_type_for_id(int pset_id);
extern pset_id_t impl_get_pset_id_for_cluster_id(int cluster_id);

#pragma mark - Realtime

extern void              sched_rt_config_set(uint8_t src, uint8_t dst, sched_clutch_edge edge);
extern sched_clutch_edge sched_rt_config_get(uint8_t src, uint8_t dst);
extern uint64_t          rt_deadline_add(uint64_t d, uint64_t e);
extern void              rt_pset_recompute_spill_order(int src_pset_id);
extern int               rt_pset_spill_search_order_at_offset(int src_pset_id, int offset);
