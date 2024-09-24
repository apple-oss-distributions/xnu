#include <sys/kern_memorystatus.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <darwintest.h>

#define MAX_TASK_MEM "kern.max_task_pmem"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ENABLED(!TARGET_OS_OSX));

T_DECL(memorystatus_convert_limit_bytes, "memorystatus_convert_limit_bytes default limit", T_META_TAG_VM_PREFERRED)
{
	int ret;
	int32_t max_task_pmem = 0;
	size_t size_max_task_pmem = sizeof(max_task_pmem);

	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	if (max_task_pmem == 0) {
		T_SKIP("Device does not have a default task memory limit.");
	}

	ret = memorystatus_control(MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB, getpid(), (int32_t) -1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	T_QUIET; T_ASSERT_EQ(ret, max_task_pmem, "default limit is converted correctly");
}

T_DECL(memorystatus_set_task_limit_always_fatal,
    "Verify that a converted task limit is always fatal")
{
	int ret;
	int32_t max_task_pmem = 0;
	size_t size_max_task_pmem = sizeof(max_task_pmem);
	pid_t pid = getpid();

	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	if (max_task_pmem == 0) {
		T_SKIP("Device does not have a default task memory limit.");
	}

	/* Request non-fatal memlimits */
	memorystatus_memlimit_properties2_t mmprops = {
		.v1 = {
			.memlimit_active = max_task_pmem,
			.memlimit_inactive = max_task_pmem,
			.memlimit_active_attr = 0,
			.memlimit_inactive_attr = 0,
		},
	};
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops.v1, sizeof(mmprops.v1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_EXPECT_BITS_SET(mmprops.v1.memlimit_active_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Active limit (task limit) should be fatal");
	T_EXPECT_BITS_SET(mmprops.v1.memlimit_inactive_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Inactive limit (task limit) should be fatal");

	/* Request non-fatal memlimits */
	mmprops.v1.memlimit_active = -1;
	mmprops.v1.memlimit_inactive = -1;
	mmprops.v1.memlimit_active_attr = 0;
	mmprops.v1.memlimit_inactive_attr = 0;

	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops.v1, sizeof(mmprops.v1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_EXPECT_BITS_SET(mmprops.v1.memlimit_active_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Active limit (-1) should be fatal");
	T_EXPECT_BITS_SET(mmprops.v1.memlimit_inactive_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Inactive (-1) limit should be fatal");

	/* Request non-fatal memlimits */
	mmprops.v1.memlimit_active = 0;
	mmprops.v1.memlimit_inactive = 0;
	mmprops.v1.memlimit_active_attr = 0;
	mmprops.v1.memlimit_inactive_attr = 0;

	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops.v1, sizeof(mmprops.v1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_EXPECT_BITS_SET(mmprops.v1.memlimit_active_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Active limit (0) should be fatal");
	T_EXPECT_BITS_SET(mmprops.v1.memlimit_inactive_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Inactive (0) limit should be fatal");
}

T_DECL(memorystatus_memlimit_gt_task_limit,
    "Verify that memory limits can exceed the task limit")
{
	int ret;
	int32_t max_task_pmem = 0;
	size_t size_max_task_pmem = sizeof(max_task_pmem);
	pid_t pid = getpid();

	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	if (max_task_pmem == 0) {
		T_SKIP("Device does not have a default task memory limit.");
	}

	/* Request non-fatal memlimits */
	int32_t expected_memlimit = max_task_pmem + 100;
	memorystatus_memlimit_properties2_t mmprops = {
		.v1 = {
			.memlimit_active = expected_memlimit,
			.memlimit_inactive = expected_memlimit,
			.memlimit_active_attr = 0,
			.memlimit_inactive_attr = 0,
		},
	};
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops.v1, sizeof(mmprops.v1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_EXPECT_EQ(mmprops.v1.memlimit_active, expected_memlimit, "Active limit can exceed task limit");
	T_EXPECT_EQ(mmprops.v1.memlimit_inactive, expected_memlimit, "Inactive limit can exceed task limit");
	T_EXPECT_BITS_NOTSET(mmprops.v1.memlimit_active_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Active limit should be non-fatal");
	T_EXPECT_BITS_NOTSET(mmprops.v1.memlimit_inactive_attr, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
	    "Inactive limit should be non-fatal");
}
