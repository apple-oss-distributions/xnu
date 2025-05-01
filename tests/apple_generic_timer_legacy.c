#include <darwintest.h>
#include <sys/sysctl.h>
#include "apple_generic_timer.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_ENABLED(TARGET_CPU_ARM64),
	T_META_OWNER("xi_han"),
	T_META_RUN_CONCURRENTLY(true),
	XNU_T_META_SOC_SPECIFIC
	);

T_DECL(apple_generic_timer_legacy,
    "Test that CNTFRQ_EL0 reads the correct frequency when built with old SDKs")
{
	/* Always expect 24 MHz. Check Makefile for SDK version overrides. */
	agt_test_helper(false);
}
