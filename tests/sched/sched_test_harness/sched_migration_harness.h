// Copyright (c) 2024 Apple Inc.  All rights reserved.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include <kern/kern_types.h>

#include "sched_runqueue_harness.h"


/* Mocking the HW topology */
typedef enum {
	TEST_CPU_TYPE_EFFICIENCY,
#if HAS_MCORE
	TEST_CPU_TYPE_MP_OPTIMIZED,
#endif /* HAS_MCORE */
	TEST_CPU_TYPE_PERFORMANCE,
	TEST_CPU_TYPE_MAX,
} test_cpu_type_t;

extern const char * test_cpu_type_to_str(test_cpu_type_t cpu_type);

typedef const struct test_hw_cpu_range {
	test_cpu_type_t cpu_type;
	int             cluster_id;
	int             die_id;
	int             first_cpu_id;
	int             num_cpus;
} test_hw_cpu_range;

typedef const struct test_hw_topology {
	int num_cpus;
	int boot_cpu;
	test_hw_cpu_range cpu_ranges[];
} *test_hw_topology_t;

/* The mocked hardware topology is translated into a mocked scheduler topology. */
typedef struct test_pset {
	test_cpu_type_t cpu_type;
	unsigned int    num_cpus;
	unsigned int    cluster_id;
	unsigned int    die_id;
} test_pset;

typedef const struct test_scheduler_topology {
	unsigned int num_psets;
	test_pset   *psets;
} *test_sched_topology_t;

extern int                       pset_id_to_cpu_id(int pset_id);
extern int                       cpu_id_to_pset_id(int cpu_id);
extern test_sched_topology_t     get_sched_topology(void);

/* Given topologies */
extern struct test_hw_topology single_core; // 1P
extern struct test_hw_topology basic_amp; // 2P + 4E
extern struct test_hw_topology dual_die; // 2E + 4P + 4P + 2E + 4P + 4P
extern struct test_hw_topology two_of_each; // 2E + 2P + 2E + 2P
#if HAS_MCORE
extern struct test_hw_topology sotra_chop; /* 6M + 6M + 6P */
#endif /* HAS_MCORE */

/* Test harness utilities */
extern test_sched_topology_t init_migration_harness(test_hw_topology_t hw_topology);
extern void      set_tg_sched_bucket_preferred_pset(struct thread_group *tg, int sched_bucket, pset_id_t pset_id);
extern void      set_thread_pset_bound(test_thread_t thread, pset_id_t pset_id);
extern int       choose_pset_for_thread(test_thread_t thread);
typedef enum {
	TEST_SCHED_NONE = 0x0,
	TEST_SCHED_CSW  = 0x20,
} test_sched_options_t; // Mirrors sched_options_t
extern int       choose_pset_for_thread_options(test_thread_t thread, test_sched_options_t options);
extern bool      choose_pset_for_thread_expect(test_thread_t thread, int expected_cluster_id);
extern test_thread_t  cpu_steal_thread(int cpu_id);
extern bool      cpu_processor_balance(int cpu_id);
extern void      cpu_clear_pending_ast_bits(int cpu_id);
extern bool      thread_avoid_processor_expect(test_thread_t thread, int cpu_id, bool quantum_expiry, bool avoid_expected);
extern void      cpu_expire_quantum(int cpu_id);
extern void      set_current_processor(int cpu_id);
/* Note that load avg will be overriden by cpu_set_thread_current() or enqueue_thread() operations */
extern void      set_pset_load_avg(int cluster_id, int QoS, uint32_t load_avg);
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
extern int       iterate_pset_search_order_expect(int src_pset_id, uint64_t candidate_map, int sched_bucket, int *expected_pset_ids, int num_psets);
extern int       pset_id_for_cluster_id(int cluster_id);
