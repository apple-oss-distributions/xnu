/**
 *  no_limit_cross_test_execution.c
 *  DiagThresholdTest
 *
 * Simple test that checks if a process gets diagnostic memory
 * threshold notifications when it does NOT cross the limit.
 *
 * Copyright (c) 2023 Apple Inc. All rights reserved.
 */

#include <stdio.h>
#include "vm/diag_threshold_test.h"
#include <sys/kern_memorystatus.h>

static void no_limit_cross_test_execution(struct test_case *test_case, void *param);
T_GLOBAL_META(
	T_META_ENABLED(TARGET_OS_IPHONE),
	T_META_NAMESPACE("xnu.vm.100432442"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("jsolsona"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);

static test_case_t diag_mem_threshold_no_limit_cross_test = {
	.short_name = "no_limit_cross_test",
	.test_name = "In this test is not expected to pass the threshold limit",
	.test_code = no_limit_cross_test_execution,
	.result_already_present = FALSE,
	.exception_not_expected = TRUE,
};


static void
no_limit_cross_test_execution(__unused struct test_case *test_case, void *param)
{
	test_context_t *info = (test_context_t *)param;
	dispatch_semaphore_signal(info->executor_ready_for_exceptions);
	(void)set_memory_diagnostics_threshold_limits(WORKING_LIMIT, true);
	diag_mem_threshold_waste_memory(WORKING_LIMIT - (1024 * 1024));
}


T_DECL(diag_mem_threshold_no_limit_cross,
    "In this test is not expected to pass the threshold limit")
{
	diag_mem_threshold_set_setup(&diag_mem_threshold_no_limit_cross_test);
}
