/**
 *  double_limit_test.c
 *  DiagThresholdTest
 *
 * Test the check if reloading a memory diagnostics limit retriggers exceptions
 * Copyright (c) 2022 Apple Inc. All rights reserved.
 */
#include <stdio.h>
#include "vm/diag_threshold_test.h"
#include <sys/kern_memorystatus.h>
static void diag_threshold_test_with_low_watermark(struct test_case *test_case, void *param);
static test_case_t diag_threshold_test_with_low_watermark_test = {
	.short_name = "diag_threshold_test_with_low_watermark",
	.test_name = "Test on which a diag threshold is set and a watermark, the watermark is smaller than the diag threshold",
	.test_code = diag_threshold_test_with_low_watermark,
	.result_already_present = FALSE,
	.exception_not_expected = FALSE,
	.exceptions_handled_in_test = TRUE,
};

T_GLOBAL_META(
	T_META_ENABLED(TARGET_OS_IPHONE),
	T_META_NAMESPACE("xnu.vm.100432442"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("jsolsona"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);

static void
diag_threshold_test_with_low_watermark(struct test_case *test_case, void *param)
{
	test_context_t *info = (test_context_t *)param;
	(void)set_memory_diagnostics_threshold_limits(WORKING_LIMIT, true);
	diag_mem_set_jetsam_watermark(LOW_JETSAM_LIMIT);
	dispatch_semaphore_signal(info->executor_ready_for_exceptions);
	diag_mem_threshold_log_test("Going to waste memory 1\n");
	diag_mem_threshold_waste_memory(ABOVE_JETSAM_LIMIT);
	diag_mem_threshold_log_test("memory wasted #1\n");
	sleep(1);
	diag_mem_threshold_log_test("step #2\n");
	if (FALSE == diag_mem_threshold_wait_for_exception(info)) {
		test_case->did_pass = FALSE;
		test_case->result_already_present = TRUE;
		diag_mem_threshold_log_test("Giving up in wait, terminating\n");
		pthread_exit(NULL);
	}
	diag_mem_threshold_log_test("Got first exception ensuring no false positives (timeout expected)\n");
	diag_mem_threshold_wait_for_exception(info);
	diag_mem_threshold_log_test("Got first exception wasting memory\n");
	diag_mem_threshold_waste_memory(2 * WORKING_LIMIT);
	if (FALSE == diag_mem_threshold_wait_for_exception(info)) {
		test_case->did_pass = FALSE;
		test_case->result_already_present = TRUE;
		diag_mem_threshold_log_test("Giving up in wait, terminating\n");
		pthread_exit(NULL);
	}
	test_case->did_pass = TRUE;
	diag_mem_threshold_log_test("Got second exception\n");
}

T_DECL(diag_threshold_test_with_low_watermark,
    "Test on which a diag threshold is set and a watermark, the watermark is smaller than the diag threshold"
    )
{
	diag_mem_threshold_set_setup(&diag_threshold_test_with_low_watermark_test);
}
