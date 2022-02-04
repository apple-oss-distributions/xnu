#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/ptrace.h>
#include <sys/proc.h>
#include <stdlib.h>
#include <System/sys/codesign.h>
#include <darwintest.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.note_exec"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("spawn"));

static int kq;
static int pid;

static void
do_exec(void)
{
	char echo_arg[50] = "";

	snprintf(echo_arg, sizeof(echo_arg), "Child[%d] says hello after exec", getpid());

	char * new_argv[] = {
		"/bin/echo",
		echo_arg,
		NULL
	};

	int ret = execv(new_argv[0], new_argv);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "execv()");
}

static void *
thread_wait_exec(void *arg __unused)
{
	int ret;
	struct kevent64_s kev;
	int csret;
	uint32_t status = 0;

	while (1) {
		ret = kevent64(kq, NULL, 0, &kev, 1, 0, NULL);
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			}
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kevent64()");
		break;
	}

	/* Try to get the csops of child before we print anything */
	csret = csops(pid, CS_OPS_STATUS, &status, sizeof(status));
	if (csret != 0) {
		T_QUIET; T_LOG("Child exited before parent could call csops. The race didn't happen");
		return NULL;
	}

	T_QUIET; T_ASSERT_EQ(ret, 1, "kevent64 returned 1 event as expected");
	T_QUIET; T_ASSERT_EQ((int)kev.filter, EVFILT_PROC, "EVFILT_PROC event received");
	T_QUIET; T_ASSERT_EQ((int)kev.udata, pid, "EVFILT_PROC event received for child pid");
	T_QUIET; T_ASSERT_EQ((kev.fflags & NOTE_EXEC), NOTE_EXEC, "NOTE_EXEC event received");

	/* Check that the platform binary bit is set */
	T_EXPECT_BITS_SET(status, CS_PLATFORM_BINARY, "CS_PLATFORM_BINARY should be set on child");

	return NULL;
}

static void
run_test(void)
{
	struct kevent64_s kev;
	int ret;
	int fd[2];

	ret = pipe(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pipe()");
	close(fd[0]);

	T_QUIET; T_LOG("Forking child");

	pid = fork();

	if (pid == 0) {
		char buf[10];

		close(fd[1]);
		ret = (int)read(fd[0], buf, sizeof(buf));
		close(fd[0]);

		do_exec();
		exit(1);
	}

	T_QUIET; T_LOG("Setting up NOTE_EXEC Handler for child pid %d", pid);
	kq = kqueue();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kq, "kqueue()");

	EV_SET64(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE,
	    NOTE_EXEC, 0, pid, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kevent64()");

	pthread_t thread;
	ret = pthread_create(&thread, NULL, thread_wait_exec, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create()");

	T_QUIET; T_LOG("Signalling child to call exec");
	close(fd[1]);

	T_QUIET; T_LOG("Waiting for child to exit");
	pid = waitpid(pid, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "waitpid()");

	T_QUIET; T_LOG("Waiting for note exec thread to exit");
	ret = pthread_join(thread, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join()");

	close(kq);
}

T_DECL(test_note_exec, "test NOTE_EXEC race with setting csops") {
	T_QUIET; T_LOG("Testing race for NOTE_EXEC with csops");

	for (int i = 0; i < 100; i++) {
		T_QUIET; T_LOG("Running iteration %d", i);
		run_test();
	}
	T_END;
}
