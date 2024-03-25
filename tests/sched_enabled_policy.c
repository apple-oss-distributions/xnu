#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/sysctl.h>

#include <darwintest.h>
#include "test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"));

static void
get_sched_policy_name(char *policy_name, size_t policy_name_len)
{
	int ret;
	ret = sysctlbyname("kern.sched", policy_name, &policy_name_len, NULL, 0);
	T_QUIET; T_ASSERT_EQ(ret, 0, "sysctlbyname kern.sched");
}

static void
get_device_name(char *device_name, size_t device_name_len)
{
	int ret;
	ret = sysctlbyname("hw.target", device_name, &device_name_len, NULL, 0);
	T_QUIET; T_ASSERT_EQ(ret, 0, "sysctlbyname hw.target");
}

static void
get_kern_version(char *kern_version, size_t kern_version_len)
{
	int ret;
	ret = sysctlbyname("kern.version", kern_version, &kern_version_len, NULL, 0);
	T_QUIET; T_ASSERT_EQ(ret, 0, "sysctlbyname kern.version");
}

static bool
platform_is_arm64(void)
{
	int ret;
	int is_arm64 = 0;
	size_t is_arm64_size = sizeof(is_arm64);
	ret = sysctlbyname("hw.optional.arm64", &is_arm64, &is_arm64_size, NULL, 0);
	return ret == 0 && is_arm64;
}

static bool
platform_is_amp(void)
{
	int ret;
	int num_perf_levels = 0;
	ret = sysctlbyname("hw.nperflevels", &num_perf_levels, &(size_t){ sizeof(num_perf_levels) }, NULL, 0);
	T_QUIET; T_ASSERT_EQ(ret, 0, "sysctlbyname hw.nperflevels");
	bool is_amp = num_perf_levels > 1;
	T_LOG("Platform is %s", is_amp ? "asymmetric (AMP)" : "symmetric (SMP)");
	return is_amp;
}


T_DECL(enabled_policy, "Verify that the expected scheduler policy is running", XNU_T_META_SOC_SPECIFIC)
{
	size_t policy_name_len = 256;
	char policy_name[policy_name_len];
	get_sched_policy_name(policy_name, policy_name_len);
	T_LOG("Current scheduler policy: %s", policy_name);

	size_t device_name_len = 256;
	char device_name[device_name_len];
	get_device_name(device_name, device_name_len);
	T_LOG("Current device: %s", device_name);

	size_t kern_version_len = 256;
	char kern_version[kern_version_len];
	get_kern_version(kern_version, kern_version_len);
	T_LOG("Kernel version: %s", kern_version);

	if (!platform_is_arm64()) {
		T_SKIP("Skipping test on non-arm64 platform");
	}
	if (strstr(device_name, "DEV") != NULL) {
		T_SKIP("Skipping test on DEV hardware");
	}
	if (strstr(device_name, "SIM") != NULL) {
		T_SKIP("Skipping test on simulator");
	}

	if (!platform_is_amp()) {
		T_ASSERT_EQ_STR(policy_name, "clutch", "SMP platform should be running the Clutch scheduler");
		T_END;
	}


	T_ASSERT_EQ_STR(policy_name, "edge", "Non-exempt AMP platform should be running the Edge scheduler");
}
