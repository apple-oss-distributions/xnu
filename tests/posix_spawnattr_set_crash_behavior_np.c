#include <stdio.h>
#include <sys/sysctl.h>
#include <spawn_private.h>
#include <signal.h>
#include <sys/reason.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_NAMESPACE("xnu.spawn"));

extern char **environ;

#define SYSCTL_CRASH_BEHAVIOR_TEST_MODE "kern.crash_behavior_test_mode=1"
#define SYSCTL_CRASH_BEHAVIOR_WOULD_PANIC "kern.crash_behavior_test_would_panic"

#define TEST_REASON_CODE 5

static void
_do_set_crash_behavior_test(char *child_mode, int signal, uint32_t flags, bool expect_panic)
{
	bool should_wait = (strcmp(child_mode, "wait") == 0);
	bool reason = (strcmp(child_mode, "reason") == 0);
	bool dirty = (strcmp(child_mode, "dirty") == 0);
	bool shutdown = (strcmp(child_mode, "clean") == 0) || dirty;
	uint64_t deadline = mach_continuous_time();

	// 0. clear SYSCTL_CRASH_BEHAVIOR_WOULD_PANIC
	int would_panic = 0;
	size_t length = sizeof(would_panic);
	int ret = sysctlbyname(SYSCTL_CRASH_BEHAVIOR_WOULD_PANIC, NULL, 0, &would_panic, length);
	T_ASSERT_POSIX_SUCCESS(ret, "Clearing SYSCTL_CRASH_BEHAVIOR_WOULD_PANIC");

	// 1. posix_spawn a child process
	char *test_program = "./posix_spawnattr_set_crash_behavior_np_child";
	char *child_args[3];

	posix_spawnattr_t attrs;
	posix_spawnattr_init(&attrs);

	ret = posix_spawnattr_set_crash_behavior_np(&attrs, flags);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_crash_behavior_np");


	if (should_wait) {
		// For the purpose of the test we set the deadline to be now to avoid
		// making the test wait
		ret = posix_spawnattr_set_crash_behavior_deadline_np(&attrs, deadline, flags);
		T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_crash_behavior_deadline_np: %lld", deadline);
	}

	child_args[0] = test_program;
	child_args[1] = child_mode;
	child_args[2] = NULL;

	pid_t child_pid = 0;
	ret = posix_spawn(&child_pid, child_args[0], NULL, &attrs, &child_args[0], environ);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	posix_spawnattr_destroy(&attrs);

	if (should_wait) {
		while (mach_continuous_time() <= deadline) {
			usleep(1);
		}
	}

	if (signal != 0) {
		ret = kill(child_pid, signal);
		T_ASSERT_POSIX_SUCCESS(ret, "kill(%d, %d)", child_pid, signal);
	}

	if (reason) {
		ret = terminate_with_reason(child_pid, OS_REASON_TEST, TEST_REASON_CODE,
		    "Test forcing crash", OS_REASON_FLAG_CONSISTENT_FAILURE | OS_REASON_FLAG_NO_CRASH_REPORT);
		T_ASSERT_POSIX_SUCCESS(ret, "terminate_with_reason(%d)", child_pid);
	}

	if (dirty) {
		ret = proc_set_dirty(child_pid, true);
		T_ASSERT_POSIX_SUCCESS(ret, "proc_set_dirty(%d)", child_pid);
	}

	if (shutdown) {
		ret = proc_terminate(child_pid, &signal);
		T_ASSERT_POSIX_SUCCESS(ret, "proc_terminate(%d, %d)", child_pid, signal);
	}

	// 2. Wait for the child to exit
	int child_status;
	ret = wait4(-1, &child_status, 0, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "wait4");

	// 3. Check if we would have panic'ed
	would_panic = 0;
	length = sizeof(would_panic);
	ret = sysctlbyname(SYSCTL_CRASH_BEHAVIOR_WOULD_PANIC, &would_panic, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "SYSCTL_CRASH_BEHAVIOR_WOULD_PANIC");

	T_EXPECT_EQ(would_panic, expect_panic, NULL);
}

T_DECL(set_crash_behavior_panic_on_crash_with_crash,
    "set_crash_behavior_panic_on_crash_with_crash",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("crash", 0, POSIX_SPAWN_PANIC_ON_CRASH, true);
}

T_DECL(set_crash_behavior_panic_on_crash_with_exit,
    "set_crash_behavior_panic_on_crash_with_exit",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("exit", 0, POSIX_SPAWN_PANIC_ON_CRASH, false);
}

T_DECL(set_crash_behavior_panic_on_crash_with_success,
    "set_crash_behavior_panic_on_crash_with_success",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("success", 0, POSIX_SPAWN_PANIC_ON_CRASH, false);
}

T_DECL(set_crash_behavior_panic_on_nonzero_with_crash,
    "set_crash_behavior_panic_on_nonzero_with_crash",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("crash", 0, POSIX_SPAWN_PANIC_ON_NON_ZERO_EXIT, false);
}

T_DECL(set_crash_behavior_panic_on_nonzero_with_exit,
    "set_crash_behavior_panic_on_nonzero_with_exit",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("exit", 0, POSIX_SPAWN_PANIC_ON_NON_ZERO_EXIT, true);
}

T_DECL(set_crash_behavior_panic_on_nonzero_with_success,
    "set_crash_behavior_panic_on_nonzero_with_success",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("success", 0, POSIX_SPAWN_PANIC_ON_NON_ZERO_EXIT, false);
}

T_DECL(set_crash_behavior_panic_on_crash_cancelled,
    "set_crash_behavior_panic_on_crash_cancelled",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("wait", SIGUSR1, POSIX_SPAWN_PANIC_ON_CRASH, false);
}

T_DECL(set_crash_behavior_panic_on_crash_sigterm,
    "set_crash_behavior_panic_on_crash_sigterm",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("spin", SIGTERM, POSIX_SPAWN_PANIC_ON_CRASH, false);
}

T_DECL(set_crash_behavior_panic_on_crash_sigkill,
    "set_crash_behavior_panic_on_crash_sigkill",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("spin", SIGKILL, POSIX_SPAWN_PANIC_ON_CRASH, false);
}

T_DECL(set_crash_behavior_panic_on_crash_terminate_with_reason,
    "set_crash_behavior_panic_on_crash_terminate_with_reason",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("reason", 0, POSIX_SPAWN_PANIC_ON_CRASH, true);
}

T_DECL(set_crash_behavior_panic_on_crash_proc_terminate_clean,
    "set_crash_behavior_panic_on_crash_proc_terminate_clean",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("clean", 0, POSIX_SPAWN_PANIC_ON_CRASH, false);
}

T_DECL(set_crash_behavior_panic_on_crash_proc_terminate_dirty,
    "set_crash_behavior_panic_on_crash_proc_terminate_dirty",
    T_META_SYSCTL_INT(SYSCTL_CRASH_BEHAVIOR_TEST_MODE),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1)) {
	_do_set_crash_behavior_test("dirty", 0, POSIX_SPAWN_PANIC_ON_CRASH, false);
}
