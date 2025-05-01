#include <signal.h>
#include <libproc.h>
#include <sys/sysctl.h>

#include <darwintest.h>

// rdar://128791723
// Ensure pidversion always changes across exec

static int32_t
get_pidversion_for_pid(pid_t pid)
{
	struct proc_bsdinfowithuniqid bsd_info;
	int ret = proc_pidinfo(pid, PROC_PIDT_BSDINFOWITHUNIQID, 0, &bsd_info, sizeof(bsd_info));
	T_ASSERT_EQ((unsigned long)ret, sizeof(bsd_info), "PROC_PIDT_BSDINFOWITHUNIQID");
	return bsd_info.p_uniqidentifier.p_idversion;
}

T_DECL(ensure_pidversion_changes_on_exec,
    "Ensure pidversion always changes across exec, even when groomed not to",
    T_META_NAMESPACE("xnu.exec"),
    T_META_TAG_VM_PREFERRED
    ) {
	T_SETUPBEGIN;

	// Given we exec a helper program (in a forked child, so this runner can stick around)
	// (And we set up some resources to communicate with the forked process)
	int pipefd[2];
	T_ASSERT_POSIX_SUCCESS(pipe(pipefd), "pipe");

	pid_t forked_pid = fork();
	T_ASSERT_POSIX_SUCCESS(forked_pid, "fork");

	if (forked_pid == 0) {
		close(pipefd[0]);

		// And we keep track of our current pidversion
		int32_t forked_proc_pidv = get_pidversion_for_pid(getpid());

		// And we ask the kernel to groom things such that `nextpidversion == current_proc->p_idversion + 1`
		int64_t val = 0;
		size_t val_len = sizeof(val);
		sysctlbyname("debug.test.setup_ensure_pidversion_changes_on_exec", &val, &val_len, &val, sizeof(val));

		// (And we send the parent's pidversion back to the test runner, for comparison with the exec'd process)
		T_ASSERT_POSIX_SUCCESS(write(pipefd[1], (void*)&forked_proc_pidv, sizeof(forked_proc_pidv)), "write");
		T_ASSERT_POSIX_SUCCESS(close(pipefd[1]), "close");

		// When I exec a child
		// (Which spins forever, so we can poke it)
		char *args[4];
		char *tail_path = "/usr/bin/tail";
		args[0] = tail_path;
		args[1] = "-f";
		args[2] = "/dev/null";
		args[3] = NULL;
		execv(tail_path, args);
		T_FAIL("execve() failed");
	}

	T_ASSERT_POSIX_SUCCESS(close(pipefd[1]), "close");

	// (And we read the parent's pidversion from our forked counterpart, for comparison with the exec'd process)
	int32_t forked_proc_pidversion;
	T_ASSERT_POSIX_SUCCESS(read(pipefd[0], &forked_proc_pidversion, sizeof(forked_proc_pidversion)), "read");
	T_ASSERT_POSIX_SUCCESS(close(pipefd[0]), "close");

	// (Give the forked process a moment to exec().)
	// (To get rid of this, we could exec something controlled that signals a semaphore.)
	sleep(1);

	T_SETUPEND;

	// And I interrogate the pidversion of the exec'd process
	int32_t exec_proc_pidversion = get_pidversion_for_pid(forked_pid);

	// Then the pidversion should NOT be reused, despite our grooming
	T_ASSERT_NE(exec_proc_pidversion, forked_proc_pidversion, "Prevent pidversion reuse");

	// Cleanup: kill our errant child
	T_SETUPBEGIN;
	T_ASSERT_POSIX_SUCCESS(kill(forked_pid, SIGKILL), "kill");
	T_SETUPEND;
}
