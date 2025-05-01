// Copyright (c) 2024 Apple Inc.  All rights reserved.
#ifndef XNU_SCHED_TEST_UTILS_H
#define XNU_SCHED_TEST_UTILS_H

#include <stdbool.h>

/* -- Meta-controls -- */

/* Verbose printing mode is enabled by default */
void disable_verbose_sched_utils(void);
void reenable_verbose_sched_utils(void);

/* -- Time conversions -- */
uint64_t nanos_to_abs(uint64_t nanos);
uint64_t abs_to_nanos(uint64_t abs);

/* -- 🎻 Thread orchestration -- */
void spin_for_duration(uint32_t seconds);
void stop_spinning_threads(void);

/*
 * Cluster-binding interfaces perform a soft bind on the current
 * thread and require "enable_skstb=1" boot-arg to be set.
 */

/* Returns the old bound type ('0' for unbound) */
char bind_to_cluster_of_type(char type);
/* Returns the old bound id (-1 for unbound) */
int bind_to_cluster_id(int cluster_id);

/*
 * Functions to create pthreads, optionally configured with
 * a number of pthread attributes:
 */
void create_thread_pri(pthread_t *thread_handle, int priority, void *(*func)(void *), void *arg);
typedef enum {
	eDetached,
	eJoinable, // default
} detach_state_t;
typedef enum {
	eSchedFIFO = 4,
	eSchedRR = 2,
	eSchedOther = 1,
	eSchedDefault = 0, // default
} sched_policy_t;
#define DEFAULT_STACK_SIZE 0
// Default qos_class is QOS_CLASS_UNSPECIFIED
pthread_attr_t *
create_pthread_attr(int priority,
    detach_state_t detach_state, qos_class_t qos_class,
    sched_policy_t sched_policy, size_t stack_size);
void create_thread(pthread_t *thread_handle, pthread_attr_t *attr, void *(*func)(void *), void *arg);
pthread_t *create_threads(int num_threads, int priority,
    detach_state_t detach_state, qos_class_t qos_class,
    sched_policy_t sched_policy, size_t stack_size,
    void *(*func)(void *), void *arg_array[]);

/* -- 🛰️ Platform checks -- */
bool platform_is_amp(void);
bool platform_is_virtual_machine(void);
char *platform_sched_policy(void);
unsigned int platform_num_clusters(void);
const char *platform_perflevel_name(unsigned int perflevel);
unsigned int platform_nperflevels(void);

/* -- 📈🕒 Monitor system performance state -- */

/*
 * Returns true if the system successfully quiesced below the specified threshold
 * within the specified timeout, and false otherwise.
 * idle_threshold is given as a ratio between [0.0, 1.0], defaulting to 0.9.
 * Passing argument --no-quiesce disables waiting for quiescence.
 */
bool wait_for_quiescence(int argc, char *const argv[], double idle_threshold, int timeout_seconds);
bool wait_for_quiescence_default(int argc, char *const argv[]);

/* Returns true if all cores on the device are recommended */
bool check_recommended_core_mask(uint64_t *core_mask);

/* -- 🏎️ Query/control CPU topology -- */

/*
 * Spawns and waits for clpcctrl with the given arguments.
 * If read_value is true, returns the value assumed to be elicited from clpcctrl.
 */
uint64_t execute_clpcctrl(char *clpcctrl_args[], bool read_value);

/* -- 🖊️ Record traces -- */

/*
 * Tracing requires root privilege.
 *
 * Standard usage of this interface would be to call begin_collect_trace()
 * followed by end_collect_trace() and allow the library to automatically
 * handle saving/discarding the collected trace upon test end. Traces will
 * automatically be saved if a failure occurred during the test run and
 * discarded otherwise.
 */

typedef void *trace_handle_t;

/*
 * Begins trace collection, using the specified name as a prefix for all
 * generated filenames. Arguments are parsed to check for --no-trace or
 * --save-trace options, which disable tracing and enable unconditional
 * saving of the trace file respectively.
 *
 * NOTE: Since scheduler tracing can generate large trace files when left to
 * run for long durations, take care to begin tracing close to the start of
 * the period of interest.
 */
trace_handle_t begin_collect_trace(int argc, char *const argv[], char *filename);
trace_handle_t begin_collect_trace_fmt(int argc, char *const argv[], char *filename_fmt, ...);

/*
 * NOTE: It's possible that tests may induce CPU starvation that can
 * prevent the trace from ending or cause post-processing to take an extra
 * long time. This can be avoided by terminating or blocking spawned test
 * threads before calling end_collect_trace().
 */
void end_collect_trace(trace_handle_t handle);

/*
 * Saves the recorded trace file to a tarball and marks the tarball for
 * upload in BATS as a debugging artifact.
 */
void save_collected_trace(trace_handle_t handle);

/* Deletes the recorded trace */
void discard_collected_trace(trace_handle_t handle);

#endif /* XNU_SCHED_TEST_UTILS_H */
