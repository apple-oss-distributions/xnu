#include <darwintest.h>
#include <signal.h>
#include <spawn.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <libproc.h>
#include <sys/reason.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_ENABLED(TARGET_OS_OSX));

static void
__run_cmd(const char *cmd_prefix, const char *filename, const char *error)
{
	char cmd[PATH_MAX];

	strlcpy(cmd, cmd_prefix, sizeof(cmd));
	strlcat(cmd, filename, sizeof(cmd));

	FILE *file = popen(cmd, "r");
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(file, "%s (cmd = %s)", error, cmd);
	pclose(file);
}

static void
__spawn_exec(const char *args[], short flags)
{
	posix_spawnattr_t attr;
	int error;

	error = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(error, "spawn attributes initialized");

	error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC | flags);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(error, "spawn attributes flags set");

	posix_spawnp(NULL, args[0], NULL, &attr, args, NULL);
}

static void
invalid_code_signature_helper()
{
	char filename[PATH_MAX];
	sprintf(filename, "/tmp/echo-test-%ld", random());
	T_LOG("temporary file created: %s", filename);

	__run_cmd("cp /bin/echo ", filename, "create a temporary copy");
	__run_cmd("codesign --force --sign - --team-identifier 0 ", filename, "codesign the temporary copy with an invalid team ID");

	/* Exec into the modified binary */
	const char* args[] = { filename, NULL };
	__spawn_exec(args, 0);
}

static void
bad_spawnattr_helper()
{
	const char* args[] = { "/bin/echo", NULL};
	int error;

	error = setsid();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(error, "set SID before exec");

	__spawn_exec(args, POSIX_SPAWN_SETSID);
}

static bool
is_cs_enforcement_enabled()
{
	static const size_t max_size = 4096;
	bool result;
	size_t args_size = max_size;

	char *bootargs = calloc(max_size, 1);
	int err = sysctlbyname("kern.bootargs", bootargs, &args_size, NULL, 0);
	if (err) {
		T_LOG("sysctlbyname failed. err=%d", errno);
		result = false;
	} else if (strnstr(bootargs, "cs_enforcement_disable=1", max_size)) {
		result = false;
	} else {
		result = true;
	}

	free(bootargs);
	return result;
}

static void
setup_child_and_wait_for_exit(
	void (*do_exec)(void),
	uint64_t expected_reason_namespace,
	uint64_t expected_reason_code)
{
	pid_t child = fork();
	if (child > 0) {
		int status, ret;
		struct proc_exitreasonbasicinfo exit_reason;

		sleep(1);

		ret = proc_pidinfo(child, PROC_PIDEXITREASONBASICINFO, 1, &exit_reason, PROC_PIDEXITREASONBASICINFOSIZE);
		T_QUIET; T_ASSERT_EQ(ret, PROC_PIDEXITREASONBASICINFOSIZE, "retrive basic exit reason info");

		waitpid(child, &status, 0);
		T_QUIET; T_EXPECT_FALSE(WIFEXITED(status), "process did not exit normally");
		T_QUIET; T_EXPECT_TRUE(WIFSIGNALED(status), "process was terminated because of a signal");
		T_EXPECT_EQ(WTERMSIG(status), SIGKILL, "process was SIGKILLed");

		T_EXPECT_EQ(exit_reason.beri_namespace, expected_reason_namespace, "killed with reason EXEC");
		T_EXPECT_EQ(exit_reason.beri_code, expected_reason_code, "reason code is %d", expected_reason_code);
	} else {
		do_exec();
		T_FAIL("Shouldn't reach here!");
	}
}

T_DECL(spawn_exec_double_set_sid, "exec fails upon trying to set SID twice")
{
	setup_child_and_wait_for_exit(bad_spawnattr_helper, OS_REASON_EXEC, EXEC_EXIT_REASON_BAD_PSATTR);
}

T_DECL(spawn_exec_invalid_cs, "exec fails due to invalid code signature")
{
	if (!is_cs_enforcement_enabled()) {
		T_SKIP("cs enforcement is disabled.");
	}
#if defined(__arm64__)
	setup_child_and_wait_for_exit(invalid_code_signature_helper, OS_REASON_EXEC, EXEC_EXIT_REASON_SECURITY_POLICY);
#else /* __arm64__ */
	setup_child_and_wait_for_exit(invalid_code_signature_helper, OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_TASKGATED_INVALID_SIG);
#endif /* __arm64__ */
}
