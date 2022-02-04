#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <sys/codesign.h>
#include <signal.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(static_binary,
    "Verify that static binaries have CS_NO_UNTRUSTED_HELPERS set") {
	int ret;
	pid_t pid;
	char *launch_argv[] = {"./static_binary", NULL};
	ret = dt_launch_tool(&pid, launch_argv, /*start_suspended*/ true, NULL, NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "dt_launch_tool on static binary");

	uint32_t status = 0;
	ret = csops(pid, CS_OPS_STATUS, &status, sizeof(status));
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "request CS_OPS_STATUS on static binary");

	if (!ret) {
		T_EXPECT_BITS_SET(status, CS_NO_UNTRUSTED_HELPERS, "CS_NO_UNTRUSTED_HELPERS should be set on static binary");
	}

	ret = kill(pid, SIGCONT);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "SIGCONT on static binary");

	int exitstatus, signal;
	dt_waitpid(pid, &exitstatus, &signal, 30);
	T_QUIET;
	T_ASSERT_EQ(signal, 0, "static binary exited");
	T_QUIET;
	T_ASSERT_EQ(exitstatus, 42, "static binary exited with code 42");
}
