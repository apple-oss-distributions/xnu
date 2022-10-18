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

T_DECL(memorystatus_convert_limit_bytes, "memorystatus_convert_limit_bytes default limit")
{
	int ret;
	int32_t max_task_pmem = 0;
	size_t size_max_task_pmem = sizeof(max_task_pmem);

	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	ret = memorystatus_control(MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB, getpid(), (int32_t) -1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	T_QUIET; T_ASSERT_EQ(ret, max_task_pmem, "default limit is converted correctly");
}
