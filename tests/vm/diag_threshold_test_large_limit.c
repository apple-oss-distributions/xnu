//
//  simple_test.c
//  DiagThresholdTest
//
//

#include <stdio.h>
#include "vm/diag_threshold_test.h"
#include <sys/kern_memorystatus.h>
#define TEST_LIMIT_THIS_TEST (0x80100000ULL)   /* Limit of 2.1 Gb */
#define TEST_CONSUMPTION_THIS_TEST (TEST_LIMIT_THIS_TEST+(0x100000ULL))
#define MINIMUM_HW_SIZE_FOR_TEST (4ULL * 0x40000000ULL) /* This test required 6 GB RAM to work..*/
static void simple_test_large_limit_testexecution(struct test_case *test_case, void *param);
T_GLOBAL_META(
	T_META_ENABLED(TARGET_OS_IPHONE),
	T_META_NAMESPACE("xnu.vm.106714129"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("jsolsona"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);


static test_case_t diag_mem_threshold_large_limit_test = {
	.short_name = "large_threshold_test",
	.test_name = "Large limit test, set a limit over 2Gb and wait for exception",
	.test_code = simple_test_large_limit_testexecution,
	.result_already_present = FALSE,
	.exception_not_expected = FALSE,
	.required_minimum_hw_ram_size = MINIMUM_HW_SIZE_FOR_TEST,
};

static void
simple_test_large_limit_testexecution(__unused struct test_case *test_case, void *param)
{
	test_context_t *info = (test_context_t *)param;
	dispatch_semaphore_signal(info->executor_ready_for_exceptions);
	(void)set_memory_diagnostics_threshold_limits(TEST_LIMIT_THIS_TEST, true);
	diag_mem_threshold_waste_memory(TEST_CONSUMPTION_THIS_TEST);
}


T_DECL(diag_mem_threshold_large_limit_test,
    "Large limit test, set a limit over 2Gb and wait for exception")
{
	diag_mem_threshold_set_setup(&diag_mem_threshold_large_limit_test);
}
