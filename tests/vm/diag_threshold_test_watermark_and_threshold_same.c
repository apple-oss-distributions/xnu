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
#include <darwintest.h>

static void diag_threshold_test_watermark_and_threshold_same(struct test_case *test_case, void *param);
static test_case_t diag_threshold_test_watermark_and_threshold_same_test = {
	.short_name = "diag_threshold_test_watermark_and_threshold_same",
	.test_name = "Test on which a limit watermark and a memory threshold is set with same value",
	.test_code = diag_threshold_test_watermark_and_threshold_same,
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

/**
 * This function sets a threshold, but is expected to fail, so we cannot use
 * the standard test threshold function
 */
static bool
get_diagthreshold_limits(int *limit_param, boolean_t *status)
{
	memorystatus_diag_memlimit_properties_t limit;
	diag_mem_threshold_log_test("Get threshold limit");
	int pid = getpid();
	int retValue = memorystatus_control(
		MEMORYSTATUS_CMD_GET_DIAG_LIMIT,
		pid,
		0,
		&limit, sizeof(limit)
		);
	T_ASSERT_MACH_ERROR( retValue, KERN_SUCCESS, "Verification diagnostics threshold limit adjustment");
	*limit_param = (int)(limit.memlimit);
	*status = limit.threshold_enabled;

	return (retValue == KERN_SUCCESS) ? false : true;
}
static void
diag_threshold_test_watermark_and_threshold_same(struct test_case *test_case, __unused void *param)
{
	test_context_t *info = (test_context_t *)param;
	int limit_param;
	boolean_t status;

	dispatch_semaphore_signal(info->executor_ready_for_exceptions);
	diag_mem_set_jetsam_watermark(WORKING_LIMIT);
	bool retValue = set_memory_diagnostics_threshold_limits(WORKING_LIMIT, true);
	retValue = get_diagthreshold_limits(&limit_param, &status);
	T_ASSERT_EQ(false, status, "Threshold is disabled automatically");
	T_ASSERT_EQ(WORKING_LIMIT, limit_param, "Adjusted threshold is correct");

	retValue = set_memory_diagnostics_threshold_limits(WORKING_LIMIT << 1, true);
	diag_mem_threshold_log_test("Modifying threshold limit,expecting threshold is automatically enabled");
	retValue = get_diagthreshold_limits(&limit_param, &status);
	T_ASSERT_EQ(true, status, "Threshold is enabled automatically");
	T_ASSERT_EQ(WORKING_LIMIT << 1, limit_param, "Adjusted threshold is correct");

	retValue = set_memory_diagnostics_threshold_limits(WORKING_LIMIT, true);
	diag_mem_set_jetsam_watermark(WORKING_LIMIT);
	retValue = get_diagthreshold_limits(&limit_param, &status);
	T_ASSERT_EQ(false, status, "Threshold is disabled automatically");
	T_ASSERT_EQ(WORKING_LIMIT, limit_param, "Adjusted threshold is correct");

	retValue = set_memory_diagnostics_threshold_limits(WORKING_LIMIT << 1, true);
	diag_mem_threshold_log_test("Modifying threshold limit,expecting threshold is automatically enabled");
	retValue = get_diagthreshold_limits(&limit_param, &status);
	T_ASSERT_EQ(true, status, "Threshold is enabled automatically");
	T_ASSERT_EQ(WORKING_LIMIT << 1, limit_param, "Adjusted threshold is correct");


	diag_mem_set_jetsam_watermark(WORKING_LIMIT << 1);
	diag_mem_threshold_log_test("Modifying jetsam limit,expecting threshold is automatically enabled");
	retValue = get_diagthreshold_limits(&limit_param, &status);
	T_ASSERT_EQ(false, status, "Threshold is disabled automatically");
	T_ASSERT_EQ(WORKING_LIMIT << 1, limit_param, "Adjusted threshold is correct");
	test_case->did_pass = TRUE;
	test_case->result_already_present = TRUE;
}

T_DECL(diag_threshold_test_watermark_and_threshold_same,
    "Test on which a limit watermark and a memory threshold is set with same value"
    )
{
	diag_mem_threshold_set_setup(&diag_threshold_test_watermark_and_threshold_same_test);
}
