#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <sys/kern_sysctl.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "test_utils.h"

bool
is_development_kernel(void)
{
	static dispatch_once_t is_development_once;
	static bool is_development;

	dispatch_once(&is_development_once, ^{
		int dev;
		size_t dev_size = sizeof(dev);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.development", &dev,
		&dev_size, NULL, 0), NULL);
		is_development = (dev != 0);
	});

	return is_development;
}

pid_t
launch_background_helper(
	const char* variant,
	bool start_suspended,
	bool memorystatus_managed)
{
	pid_t pid;
	char **launch_tool_args;
	char testpath[PATH_MAX];
	char *variant_cpy = strdup(variant);
	uint32_t testpath_buf_size;
	int ret;

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		variant_cpy,
		NULL
	};
	ret = dt_launch_tool(&pid, launch_tool_args, start_suspended, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "dt_launch_tool");
	if (memorystatus_managed) {
		set_process_memorystatus_managed(pid);
	}
	free(variant_cpy);
	return pid;
}

void
set_process_memorystatus_managed(pid_t pid)
{
	kern_return_t ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED, pid, 1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
}
