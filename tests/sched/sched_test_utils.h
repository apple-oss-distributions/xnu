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

/* -- Thread orchestration -- */
void spin_for_duration(uint32_t seconds);

/* -- 🛰️ Platform checks -- */
bool platform_is_amp(void);
bool platform_is_virtual_machine(void);
char *platform_sched_policy(void);

/* -- 📈🕒 Monitor system performance state -- */

/*
 * Returns true if the system successfully quiesced below the specified threshold
 * within the specified timeout, and false otherwise.
 * idle_threshold is given as a ratio between [0.0, 1.0], defaulting to 0.9.
 */
bool wait_for_quiescence(double idle_threshold, int timeout_seconds);
bool wait_for_quiescence_default(void);

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
 * generated filenames.
 *
 * NOTE: Since scheduler tracing can generate large trace files when left to
 * run for long durations, take care to begin tracing close to the start of
 * the period of interest.
 */
trace_handle_t begin_collect_trace(char *filename);
trace_handle_t begin_collect_trace_fmt(char *filename_fmt, ...);

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
