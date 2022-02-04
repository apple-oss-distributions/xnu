#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <pthread.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_NAMESPACE("xnu.ipc"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("IPC"));


T_DECL(task_fatal_port, "Create a child and kill it using the task fatal port")
{
	mach_port_name_t old_port_name = 0, new_port_name = 1;
	int port_name_size, status, ret;
	pid_t child, pid;

#if defined(__arm__) || TARGET_OS_BRIDGE
	T_SKIP("Skip this test on 32 bit kernels and bridgeos");
#endif

	child = fork();
	if (child == 0) {
		port_name_size = sizeof(old_port_name);
		ret = sysctlbyname("machdep.task_get_fatal_port", &old_port_name, &port_name_size, &new_port_name, sizeof(new_port_name));
		if (ret < 0) {
			printf("sysctlbyname failed");
			exit(2);
		}
		printf("old_port_name = %d \n", old_port_name);
		mach_port_deallocate(mach_task_self(), old_port_name);

		while (1) {
			sleep(1);
		}
	}

	pid = waitpid(child, &status, 0);
	T_ASSERT_EQ(pid, child, "waitpid returns correct pid");
	T_EXPECT_EQ(WIFSIGNALED(status), true, "child was signaled");
	T_EXPECT_EQ(WTERMSIG(status), SIGKILL, "child was sent SIGKILL");
}
