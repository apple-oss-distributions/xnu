/**
 *  diag_threshold_test_no_retrigger_test.c
 *  DiagThresholdTest
 *
 * Test the check if reloading a memory diagnostics limit retriggers exceptions
 * Copyright (c) 2022 Apple Inc. All rights reserved.
 */
#include <stdio.h>
#include "vm/diag_threshold_test.h"
#include <sys/kern_memorystatus.h>

static void diag_threshold_test_no_retrigger_execution(struct test_case *test_case, void *param);
T_GLOBAL_META(
	T_META_ENABLED(TARGET_OS_IPHONE),
	T_META_NAMESPACE("xnu.vm.100432442"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("jsolsona"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);

static test_case_t diag_threshold_test_no_retrigger_test = {
	.short_name = "diag_threshold_test_no_retrigger_test",
	.test_name = "Set a limit, consume memory, free, and expect no other exception",
	.test_code = diag_threshold_test_no_retrigger_execution,
	.result_already_present = FALSE,
	.exception_not_expected = TRUE,
};


static void
diag_threshold_test_no_retrigger_execution(struct test_case *test_case, void *param)
{
	test_context_t *info = (test_context_t *)param;
	(void)set_memory_diagnostics_threshold_limits(WORKING_LIMIT, true);
	diag_mem_threshold_waste_memory(TEST_LIMIT);
	if (FALSE == diag_mem_threshold_wait_for_exception(info)) {
		test_case->did_pass = FALSE;
		test_case->result_already_present = TRUE;
		diag_mem_threshold_log_test("Giving up in wait, terminating\n");
		pthread_exit(NULL);
	}

	dispatch_semaphore_signal(info->executor_ready_for_exceptions);
	sleep(1);
	diag_mem_threshold_log_test("First exception seen, consuming again and not expecting exception\n");
	diag_mem_threshold_waste_memory(TEST_LIMIT);
	diag_mem_threshold_log_test("Finished wasting memory, existing\n");
}

T_DECL(diag_threshold_test_no_retrigger_test,
    "Set a limit, consume memory, free, and expect no other exception")
{
	diag_mem_threshold_set_setup(&diag_threshold_test_no_retrigger_test);
}
