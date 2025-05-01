// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include "sched_runqueue_harness.h"

/* Mocking the HW topology */
typedef enum {
	TEST_CPU_TYPE_EFFICIENCY,
	TEST_CPU_TYPE_PERFORMANCE,
	TEST_CPU_TYPE_MAX,
} test_cpu_type_t;

typedef struct {
	test_cpu_type_t cpu_type;
	int num_cpus;
	int die_id;
} test_pset_t;

typedef struct {
	test_pset_t *psets;
	int num_psets;
} test_hw_topology_t;

extern int                   cpu_id_to_cluster_id(int cpu_id);
extern int                   cluster_id_to_cpu_id(int cluster_id);
extern test_hw_topology_t    get_hw_topology(void);
extern void                  set_hw_topology(test_hw_topology_t hw_topology);

/* Given topologies */
extern test_hw_topology_t single_core; // 1P
extern test_hw_topology_t basic_amp; // 2P + 4E
extern test_hw_topology_t dual_die; // 2E + 4P + 4P + 2E + 4P + 4P

/* Test harness utilities */
extern void      init_migration_harness(test_hw_topology_t hw_topology);
extern void      set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, int cluster_id);
extern void      set_thread_cluster_bound(test_thread_t thread, int cluster_id);
extern bool      choose_pset_for_thread_expect(test_thread_t thread, int expected_cluster_id);
extern void      set_current_processor(int cpu_id);
extern void      set_pset_load_avg(int cluster_id, int QoS, uint64_t load_avg);
extern void      set_pset_recommended(int cluster_id);
extern void      set_pset_derecommended(int cluster_id);
typedef enum {
	TEST_IPI_NONE              = 0x0,
	TEST_IPI_IMMEDIATE         = 0x1,
	TEST_IPI_IDLE              = 0x2,
	TEST_IPI_DEFERRED          = 0x3,
} test_ipi_type_t; // Mirrors sched_ipi_type_t
extern bool      ipi_expect(int cpu_id, test_ipi_type_t ipi_type);
typedef enum {
	TEST_IPI_EVENT_BOUND_THR   = 0x1,
	TEST_IPI_EVENT_PREEMPT     = 0x2,
	TEST_IPI_EVENT_SMT_REBAL   = 0x3,
	TEST_IPI_EVENT_SPILL       = 0x4,
	TEST_IPI_EVENT_REBALANCE   = 0x5,
	TEST_IPI_EVENT_RT_PREEMPT  = 0x6,
} test_ipi_event_t; // Mirrors sched_ipi_event_t
extern void      cpu_send_ipi_for_thread(int cpu_id, test_thread_t thread, test_ipi_event_t event);
#define QOS_PARALLELISM_REALTIME        0x2
#define QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE              0x4
extern bool      max_parallelism_expect(int qos, uint64_t options, uint32_t expected_parallelism);
