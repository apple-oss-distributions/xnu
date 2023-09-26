//
// diag_mem_threshold_test.h
// DiagThresholdTest
//
// Copyright (c) 2022 Apple Inc. All rights reserved.
//

#pragma once

#include "System/sys/kern_memorystatus.h"
#include "mach/mach_init.h"
#include "mach/exception_types.h"
#include "mach/port.h"
#include "mach/mach.h"
#include "mach/vm_page_size.h"
#include "mach/mach_vm.h"
#include "mach/mach_port.h"
#include "mach/sync_policy.h"
#include "mach/task.h"
#include "mach/semaphore.h"
#include "mach/thread_act.h"
#include "sys/dtrace_glue.h"
#include "dispatch/dispatch.h"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <darwintest.h>


#define MAX_MESSAGE 256
#define LOW_JETSAM_LIMIT (10*1024*1024)
#define WORKING_LIMIT (25*1024*1024)
#define COMMAND_LINE_MAX (128)
#define ABOVE_JETSAM_LIMIT (12*1024*1024)
#define HIGH_JETSAM_LIMIT  (WORKING_LIMIT+(1*(1024*1024)))
#define TEST_LIMIT (WORKING_LIMIT+(2*(1024*1024)))
#define NUM_MASKS 256

/**
 * Data types
 */
struct test_case;
typedef void (*test_code_fn)(struct test_case *, void *);                             /** Callback for the test execution code */
typedef void (*eval_code_fn)(struct test_case *, void *);                             /** Callback for the test evaluation code */
typedef struct test_case {
	char                   short_name[MAX_MESSAGE];                              /** Test name */
	char                   test_name[MAX_MESSAGE];                               /** Test completion message */
	char                   completion_message[MAX_MESSAGE];                      /** Test completion message */
	bool                   did_pass;                                             /** When true, the test did pass */
	bool                   result_already_present;                               /** When true, the test itself had a veredict, do not update */
	bool                   exception_not_expected;                               /** When true, the test should not have an exception  */
	test_code_fn           test_code;                                            /** Code to perform the test */
	bool                   exceptions_handled_in_test;                           /** Should the controller wait for exceptions */
	uint64_t               required_minimum_hw_ram_size;                             /** When present (not zero) indicates how much memory must have the HW device to run this test*/
} test_case_t;

typedef struct information_for_thread {
	test_case_t *test;
	semaphore_t exception_semaphore;
	dispatch_semaphore_t       exception_thread_start_sema;                          /** Semaphore used to sync the main thread to the exception thread*/
	dispatch_semaphore_t       executor_thread_start_sema;                           /** Semaphore used to sync the main thread to the executor thread*/
	dispatch_semaphore_t       executor_thread_end_sema;                             /** Semaphore used to signal the end of the executor thread*/
	dispatch_semaphore_t       executor_ready_for_exceptions;                        /** A holding point from the test execution before waiting for the exception */
	pthread_t                  exception_handler_thread_id;                          /** Posix thread used to receive exception information */
	pthread_t                  executor_handler_thread_id;                           /** Posix thread used to execute the test */
	exception_mask_t           old_mask[NUM_MASKS];                                  /** Save restore information about the task exeption handler */
	mach_msg_type_number_t     size_mask;                                            /** Same */
	exception_handler_t        old_handlers[NUM_MASKS];                              /** Same */
	exception_behavior_t       old_behaviors[NUM_MASKS];                             /** Same */
	thread_state_flavor_t      old_flavors[NUM_MASKS];                               /** Same */
	exception_mask_t           masks_original[NUM_MASKS];                            /** Same */
	bool                       exception_seen;                                       /** Did the exception appear? */
} test_context_t;

/**
 * Function prototypes (see documentation at implementation)
 */
void diag_mem_threshold_set_setup(test_case_t *test);
void diag_mem_threshold_set_shutdown(void);

void * exception_thread(void *);
bool set_memory_diagnostics_threshold_limits(uint64_t limit, bool assert_on_error);
void diag_mem_threshold_waste_memory(uint64_t ammount);
void diag_mem_threshold_log_test(const char *fmt, ...);
mach_port_t diag_mem_threshold_get_exception_port(void);
exception_mask_t diag_mem_threshold_get_exceptions_mask(void);
bool diag_mem_threshold_wait_for_exception(test_context_t *param);
kern_return_t mach_exception_raise(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, mach_exception_data_t code, mach_msg_type_number_t codeCnt);
kern_return_t catch_mach_exception_raise(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, exception_data_t code, mach_msg_type_number_t code_count);
kern_return_t catch_mach_exception_raise_state(mach_port_t port, exception_type_t exception, const exception_data_t code, mach_msg_type_number_t codeCnt, int *flavor, const thread_state_t old_state, mach_msg_type_number_t old_stateCnt, thread_state_t new_state, mach_msg_type_number_t *new_stateCnt);

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, mach_exception_data_t code, mach_msg_type_number_t codeCnt, int *flavor, thread_state_t old_state, mach_msg_type_number_t old_stateCnt, thread_state_t new_state, mach_msg_type_number_t *new_stateCnt);

kern_return_t catch_mach_exception_raise_state_identity(
	__unused mach_port_t                   exception_port,
	__unused mach_port_t                   thread,
	__unused mach_port_t                   task,
	__unused exception_type_t              exception,
	__unused mach_exception_data_t         code,
	__unused mach_msg_type_number_t        codeCnt,
	__unused int                          *flavor,
	__unused thread_state_t                old_state,
	__unused mach_msg_type_number_t        old_stateCnt,
	__unused thread_state_t                new_state,
	__unused mach_msg_type_number_t       *new_stateCnt);

void diag_mem_set_jetsam_watermark(uint ammount);
void diag_mem_set_jetsam_limit(uint ammount);



boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

/** Test definitions */
