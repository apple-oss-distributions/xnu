#include <darwintest.h>
#include <darwintest_utils.h>
#include <perfdata/perfdata.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include "test_utils.h"

#if defined(__arm64__)
T_GLOBAL_META(
	T_META_TAG_PERF,
	T_META_RUN_CONCURRENTLY(false),
	T_META_BOOTARGS_SET("enable_skstsct=1"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true),
	T_META_REQUIRES_SYSCTL_EQ("kern.hv_vmm_present", 0),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("scheduler"),
	T_META_OWNER("ngamble")
	);
#else
T_GLOBAL_META(
	T_META_TAG_PERF,
	T_META_RUN_CONCURRENTLY(false),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true),
	T_META_REQUIRES_SYSCTL_EQ("kern.hv_vmm_present", 0),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("scheduler"),
	T_META_OWNER("ngamble")
	);
#endif

static void
log_cmd(char **cmd)
{
#define MAX_CMD_STR 1024
	char cmd_str[MAX_CMD_STR] = "";
	char *s;

	while ((s = *cmd) != NULL) {
		strlcat(cmd_str, s, MAX_CMD_STR);
		strlcat(cmd_str, " ", MAX_CMD_STR);
		cmd++;
	}
	T_LOG("%s\n", cmd_str);
}

static void
run_zn(char *name, char **cmd)
{
	char tracefile_path[MAXPATHLEN] = "zn.artrace";
	snprintf(tracefile_path, MAXPATHLEN, "%s.artrace", name);

	int ret = dt_resultfile(tracefile_path, sizeof(tracefile_path));
	if (ret) {
		T_ASSERT_FAIL("get file path for trace file failed with errno %d", errno);
	}

	cmd[3] = tracefile_path;
	log_cmd(cmd);

	__block bool test_failed = true;
	__block bool test_skipped = false;

	pid_t test_pid;
	test_pid = dt_launch_tool_pipe(cmd, false, NULL, ^bool (__unused char *data, __unused size_t data_size, __unused dt_pipe_data_handler_context_t *context) {
		T_LOG("%s", data);
		if (strstr(data, "TEST PASSED")) {
		        test_failed = false;
		}
		if (strstr(data, "TEST FAILED")) {
		        test_failed = true;
		}
		if (strstr(data, "TEST SKIPPED")) {
		        test_skipped = true;
		}
		return false;
	}, ^bool (__unused char *data, __unused size_t data_size, __unused dt_pipe_data_handler_context_t *context) {
		T_LOG("%s", data);
		return false;
	}, BUFFER_PATTERN_LINE, NULL);

	if (test_pid == 0) {
		T_ASSERT_FAIL("dt_launch_tool_pipe() failed unexpectedly with errno %d", errno);
	}

	int exitstatus;
	dt_waitpid(test_pid, &exitstatus, NULL, 0);
	if (exitstatus != 0) {
		T_LOG("ktrace artrace exitstatus=%d\n", exitstatus);
	}
	if (test_skipped) {
		unlink(tracefile_path);
		T_SKIP("%s", name);
	} else if (test_failed) {
		T_FAIL("%s", name);
	} else {
		unlink(tracefile_path);
		T_PASS("%s", name);
	}

	pdwriter_t writer = pdwriter_open_tmp("xnu", name, 0, 0, NULL, 0);
	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(writer, "pdwriter_open_tmp");
	pdwriter_new_value(writer, "scheduler_ok", PDUNIT_CUSTOM(passing), !test_failed);
	pdwriter_close(writer);
	T_END;
}

T_DECL(zn_rt, "Schedule 1 RT thread per performance core, and test max latency", T_META_ENABLED(!TARGET_OS_TV), XNU_T_META_SOC_SPECIFIC)
{
	char *cmd[] = {"/usr/bin/ktrace", "artrace", "-o", "zn.artrace", "-c",
		       "/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--test-rt",
#if defined(__x86_64__)
		       "--trace", "2000000",
#else
		       "--trace", "500000",
#endif
		       NULL};

	run_zn("zn_rt", cmd);
}

T_DECL(zn_rt_smt, "Schedule 1 RT thread per primary core, verify that the secondaries are idle iff the RT threads are running", T_META_ENABLED(TARGET_CPU_X86_64))
{
	char *cmd[] = {"/usr/bin/ktrace", "artrace", "-o", "zn.artrace", "-c",
		       "/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--churn-pri", "4",
		       "--test-rt-smt",
		       "--trace", "2000000",
		       NULL};

	run_zn("zn_rt_smt", cmd);
}

T_DECL(zn_rt_avoid0, "Schedule 1 RT thread per primary core except for CPU 0", T_META_ASROOT(true), T_META_ENABLED(TARGET_CPU_X86_64))
{
	char *cmd[] = {"/usr/bin/ktrace", "artrace", "-o", "zn.artrace", "-c",
		       "/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--test-rt-avoid0",
		       "--trace", "2000000",
		       NULL};

	run_zn("zn_rt_avoid0", cmd);
}

T_DECL(zn_rt_apt, "Emulate AVID Pro Tools with default latency deadlines", T_META_ENABLED(!TARGET_OS_TV))
{
	char *cmd[] = {"/usr/bin/ktrace", "artrace", "-o", "zn.artrace", "-c",
		       "/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "chain", "realtime", "1000",
		       "--extra-thread-count", "-3",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--churn-pri", "31", "--churn-random",
		       "--test-rt",
#if defined(__x86_64__)
		       "--trace", "2000000",
#else
		       "--trace", "500000",
#endif
		       NULL};

	run_zn("zn_rt_apt", cmd);
}

T_DECL(zn_rt_apt_ll, "Emulate AVID Pro Tools with low latency deadlines", XNU_T_META_SOC_SPECIFIC)
{
	char *cmd[] = {"/usr/bin/ktrace", "artrace", "-o", "zn.artrace", "-c",
		       "/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "chain", "realtime", "1000",
		       "--extra-thread-count", "-3",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--churn-pri", "31", "--churn-random",
		       "--test-rt",
		       "--rt-ll",
		       "--trace", "500000",
		       NULL};

	run_zn("zn_rt_apt_ll", cmd);
}

T_DECL(zn_rt_edf, "Test max latency of earliest deadline RT threads in the presence of later deadline threads", T_META_ENABLED(!TARGET_OS_TV), XNU_T_META_SOC_SPECIFIC)
{
	char *cmd[] = {"/usr/bin/ktrace", "artrace", "-o", "zn.artrace", "-c",
		       "/AppleInternal/CoreOS/tests/xnu/zero-to-n/zn",
		       "0", "broadcast-single-sem", "realtime", "1000",
		       "--extra-thread-count", "-1",
		       "--spin-time", "200000",
		       "--spin-all",
		       "--rt-churn",
		       "--test-rt",
#if defined(__x86_64__)
		       "--trace", "2000000",
#else
		       "--trace", "500000",
#endif
		       NULL};

	run_zn("zn_rt_edf", cmd);
}
