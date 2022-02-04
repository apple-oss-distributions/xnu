#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(false),
	T_META_BOOTARGS_SET("enable_skstsct=1"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true),
	T_META_REQUIRES_SYSCTL_EQ("kern.hv_vmm_present", 0),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("scheduler"),
	T_META_OWNER("ngamble")
	);

static void
print_cmd(char **cmd)
{
	char *s;

	while ((s = *cmd) != NULL) {
		printf("%s ", s);
		cmd++;
	}
	printf("\n");
}

T_DECL(zn_rt, "Schedule 1 RT thread per performance core, and test max latency", T_META_ENABLED(!TARGET_OS_TV))
{
	char *cmd[] = {"/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--test-rt",
		       NULL};
	print_cmd(cmd);

	pid_t test_pid;
	int ret = dt_launch_tool(&test_pid, cmd, false, NULL, NULL);
	if (ret) {
		T_ASSERT_FAIL("dt_launch_tool() failed unexpectedly with errno %d", errno);
	}

	int exitstatus;
	dt_waitpid(test_pid, &exitstatus, NULL, 0);
	if (exitstatus == 0) {
		T_PASS("zn_rt");
	} else if (exitstatus == 2) {
		T_SKIP("zn_rt");
	} else {
		T_FAIL("zn_rt");
	}
	T_END;
}

T_DECL(zn_rt_smt, "Schedule 1 RT thread per primary core, verify that the secondaries are idle iff the RT threads are running", T_META_ASROOT(true), T_META_ENABLED(TARGET_CPU_X86_64))
{
	char *cmd[] = {"/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--churn-pri", "4",
		       "--test-rt-smt",
		       "--intel-only",
		       NULL};
	print_cmd(cmd);

	pid_t test_pid;
	int ret = dt_launch_tool(&test_pid, cmd, false, NULL, NULL);
	if (ret) {
		T_ASSERT_FAIL("dt_launch_tool() failed unexpectedly with errno %d", errno);
	}

	int exitstatus;
	dt_waitpid(test_pid, &exitstatus, NULL, 0);
	if (exitstatus == 0) {
		T_PASS("zn_rt_smt");
	} else if (exitstatus == 2) {
		T_SKIP("zn_rt_smt");
	} else {
		T_FAIL("zn_rt_smt");
	}
	T_END;
}

T_DECL(zn_rt_avoid0, "Schedule 1 RT thread per primary core except for CPU 0", T_META_ASROOT(true), T_META_ENABLED(TARGET_CPU_X86_64))
{
	char *cmd[] = {"/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--test-rt-avoid0",
		       "--intel-only",
		       NULL};
	print_cmd(cmd);

	pid_t test_pid;
	int ret = dt_launch_tool(&test_pid, cmd, false, NULL, NULL);
	if (ret) {
		T_ASSERT_FAIL("dt_launch_tool() failed unexpectedly with errno %d", errno);
	}

	int exitstatus;
	dt_waitpid(test_pid, &exitstatus, NULL, 0);
	if (exitstatus == 0) {
		T_PASS("zn_rt_avoid0");
	} else if (exitstatus == 2) {
		T_SKIP("zn_rt_avoid0");
	} else {
		T_FAIL("zn_rt_avoid0");
	}
	T_END;
}

T_DECL(zn_rt_apt, "Emulate AVID Pro Tools with default latency deadlines", T_META_ENABLED(!TARGET_OS_TV))
{
	char *cmd[] = {"/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "chain", "realtime", "10000",
		       "--extra-thread-count", "-3",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--churn-pri", "31", "--churn-random",
		       "--test-rt",
		       NULL};
	print_cmd(cmd);

	pid_t test_pid;
	int ret = dt_launch_tool(&test_pid, cmd, false, NULL, NULL);
	if (ret) {
		T_ASSERT_FAIL("dt_launch_tool() failed unexpectedly with errno %d", errno);
	}

	int exitstatus;
	dt_waitpid(test_pid, &exitstatus, NULL, 0);
	if (exitstatus == 0) {
		T_PASS("zn_rt_apt");
	} else if (exitstatus == 2) {
		T_SKIP("zn_rt_apt");
	} else {
		T_FAIL("zn_rt_apt");
	}
	T_END;
}

T_DECL(zn_rt_apt_ll, "Emulate AVID Pro Tools with low latency deadlines")
{
	char *cmd[] = {"/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "chain", "realtime", "10000",
		       "--extra-thread-count", "-3",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--churn-pri", "31", "--churn-random",
		       "--trace", "500000",
		       "--test-rt",
		       "--rt-ll",
		       NULL};
	print_cmd(cmd);

	pid_t test_pid;
	int ret = dt_launch_tool(&test_pid, cmd, false, NULL, NULL);
	if (ret) {
		T_ASSERT_FAIL("dt_launch_tool() failed unexpectedly with errno %d", errno);
	}

	int exitstatus;
	dt_waitpid(test_pid, &exitstatus, NULL, 0);
	if (exitstatus == 0) {
		T_PASS("zn_rt_apt_ll");
	} else if (exitstatus == 2) {
		T_SKIP("zn_rt_apt_ll");
	} else {
		T_FAIL("zn_rt_apt_ll");
	}
	T_END;
}
