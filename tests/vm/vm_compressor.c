/*
 * Created by Jarrad Cisco on 09/28/2022.
 * Copyright © 2022 Apple. All rights reserved.
 *
 * Functional tests for VM compressor/swap.
 */
#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ASROOT(YES),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(swap_enabled,
    "Check that Swap is successfully enabled",
    T_META_ENABLED(TARGET_OS_OSX))
{
	int swap_enabled;
	size_t len = sizeof(swap_enabled);
	int rc = sysctlbyname("vm.swap_enabled", &swap_enabled, &len, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "Failed to query sysctl `vm.swap_enabled`");
	T_EXPECT_EQ(swap_enabled, 1, "Check that vm.swap_enabled is set");
}
