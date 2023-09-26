//
//  simple_test.c
//  DiagThresholdTest
//
//

#include <stdio.h>
#include "vm/diag_threshold_test.h"
#include <sys/kern_memorystatus.h>

static void simple_test_execution(struct test_case *test_case, void *param);
T_GLOBAL_META(
	T_META_ENABLED(TARGET_OS_IPHONE),
	T_META_NAMESPACE("xnu.vm.100432442"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("jsolsona"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);


static test_case_t diag_mem_threshold_simple_test = {
	.short_name = "simple_test1",
	.test_name = "Simple test, set a limit and wait for exception",
	.test_code = simple_test_execution,
	.result_already_present = FALSE,
	.exception_not_expected = FALSE,
};

static void
simple_test_execution(__unused struct test_case *test_case, void *param)
{
	test_context_t *info = (test_context_t *)param;
	dispatch_semaphore_signal(info->executor_ready_for_exceptions);
	(void)set_memory_diagnostics_threshold_limits(WORKING_LIMIT, true);
	diag_mem_threshold_waste_memory(TEST_LIMIT);
}


T_DECL(diag_mem_threshold_simple_test,
    "Simple test, set a limit and wait for exception")
{
	diag_mem_threshold_set_setup(&diag_mem_threshold_simple_test);
}
