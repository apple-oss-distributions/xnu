#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <spawn.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true), T_META_IGNORECRASHES("sigchld.*"));

static int exitcode = 0x6789BEEF;

static void
handler(int sig, siginfo_t *sip, __unused void *uconp)
{
	/* Should handle the SIGCHLD signal */
	T_ASSERT_EQ_INT(sig, SIGCHLD, "Captured signal returns 0x%x, expected SIGCHLD (0x%x).", sig, SIGCHLD);
	T_QUIET; T_ASSERT_NOTNULL(sip, "siginfo_t returned NULL but should have returned data.");
	T_ASSERT_EQ_INT(sip->si_code, CLD_EXITED, "si_code returns 0x%x, expected CLD_EXITED (0x%x).", sip->si_code, CLD_EXITED);
	T_ASSERT_EQ_INT(sip->si_status, exitcode, "si_status returns 0x%08X, expected the child's exit code (0x%08X).", sip->si_status, exitcode);

	T_END;
}


T_DECL(sigchldreturn, "checks that a child process exited with an exitcode returns correctly to parent", T_META_CHECK_LEAKS(false))
{
	struct sigaction act;
	int pid;

	act.sa_sigaction = handler;
	act.sa_flags = SA_SIGINFO;

	/* Set action for signal */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sigaction(SIGCHLD, &act, NULL), "Calling sigaction() failed for SIGCHLD");

	/* Now fork a child that just exits */
	pid = fork();
	T_QUIET; T_ASSERT_NE_INT(pid, -1, "fork() failed!");

	if (pid == 0) {
		/* Child process! */
		exit(exitcode);
	}

	/* Main program that did the fork */
	/* We should process the signal, then exit */
	while (1) {
		sleep(1);
	}
}

T_DECL(sigabrt_test, "check that child process' exitcode contains signum = SIGABRT", T_META_CHECK_LEAKS(false))
{
	int ret;
	siginfo_t siginfo;
	pid_t pid = fork();
	int expected_signal = SIGABRT;
	if (pid == 0) {
		/* child exits with SIGABRT */
		T_LOG("In child process. Now signalling SIGABRT");
		(void)signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		T_LOG("Child should not print");
	} else {
		ret = waitid(P_PID, (id_t) pid, &siginfo, WEXITED);
		T_ASSERT_POSIX_SUCCESS(0, "waitid");
		if (siginfo.si_signo != SIGCHLD) {
			T_FAIL("Signal was not SIGCHLD.");
		}
		T_LOG("si_status = 0x%x , expected = 0x%x \n", siginfo.si_status, expected_signal);
		if (siginfo.si_status != expected_signal) {
			T_FAIL("Unexpected exitcode");
		}
	}
}

T_DECL(sigkill_test, "check that child process' exitcode contains signum = SIGKILL", T_META_CHECK_LEAKS(false))
{
	int ret;
	siginfo_t siginfo;
	pid_t pid = fork();
	int expected_signal = SIGKILL;
	if (pid == 0) {
		/* child exits with SIGKILL */
		T_LOG("In child process. Now signalling SIGKILL");
		raise(SIGKILL);
		T_LOG("Child should not print");
	} else {
		ret = waitid(P_PID, (id_t) pid, &siginfo, WEXITED);
		T_ASSERT_POSIX_SUCCESS(0, "waitid");
		if (siginfo.si_signo != SIGCHLD) {
			T_FAIL("Signal was not SIGCHLD.");
		}
		T_LOG("si_status = 0x%x , expected = 0x%x \n", siginfo.si_status, expected_signal);
		if (siginfo.si_status != expected_signal) {
			T_FAIL("Unexpected exitcode");
		}
	}
}

T_DECL(sigchild_posix_spawn_fail, "check SIGCHLD is correctly delivered when posix_spawn fails", T_META_CHECK_LEAKS(false))
{
	struct sigaction act;
	int pid;
	char *args[4];

	act.sa_sigaction = handler;
	act.sa_flags = SA_SIGINFO;

	exitcode = 0;

	/* Set action for signal */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sigaction(SIGCHLD, &act, NULL), "Calling sigaction() failed for SIGCHLD");

	args[0] = "sh";
	args[1] = "-c";
	args[2] = "exit 0";
	args[3] = NULL;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(posix_spawn(&pid, "/bin/sh", NULL, NULL, args, NULL), "posix_spawn failed");

	for (int i = 0; i < 500; i++) {
		int ret = posix_spawn(&pid, "does not exist", NULL, NULL, args, NULL);
		T_QUIET; T_ASSERT_EQ(ret, ENOENT, "posix_spawn should fail with ENOENT");
	}

	/* Exit successfully in signal handler when SIGCHLD is delivered */
	sleep(10);

	T_FAIL("SIGCHLD is not delivered");
}
