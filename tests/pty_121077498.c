#include <util.h>
#include <stdlib.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <darwintest.h>
#include <darwintest_multiprocess.h>

#define TEST_TIMEOUT    10

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(TRUE));

static void
sigio_handler(__unused int sig)
{
	/* Do nothing; this should never actually be called. */
}

T_HELPER_DECL(pty_121077498_impl, "fork helper")
{
	int primary, replica, flags;
	char rname[128], c;
	sigset_t sigio_set, received_set;

	T_EXPECT_POSIX_SUCCESS(sigemptyset(&sigio_set), "sigemptyset");
	T_EXPECT_POSIX_SUCCESS(sigaddset(&sigio_set, SIGIO), "sigaddset");

	/*
	 * New session, lose any existing controlling terminal and become
	 * session leader.
	 */
	T_EXPECT_POSIX_SUCCESS(setsid(), NULL);

	/* Open the primary side, following `openpty`'s implementation. */
	T_ASSERT_POSIX_SUCCESS(primary = posix_openpt(O_RDWR | O_NOCTTY), NULL);
	T_ASSERT_POSIX_SUCCESS(grantpt(primary), NULL);
	T_ASSERT_POSIX_SUCCESS(unlockpt(primary), NULL);
	T_ASSERT_POSIX_SUCCESS(ptsname_r(primary, rname, sizeof(rname)), NULL);

	/* Enable both O_NONBLOCK and O_ASYNC before opening the replica. */
	T_ASSERT_POSIX_SUCCESS(flags = fcntl(primary, F_GETFL, 0), NULL);
	flags |= O_NONBLOCK | O_ASYNC;
	T_ASSERT_POSIX_SUCCESS(flags = fcntl(primary, F_SETFL, flags), NULL);

	/* Open the replica, making it our controlling terminal. */
	T_ASSERT_POSIX_SUCCESS(replica = open(rname, O_RDWR, 0), "open %s", rname);

	/* Verify that we are non-blocking. */
	T_EXPECT_POSIX_FAILURE(read(primary, &c, 1), EAGAIN, "read with no data returns EAGAIN");

	/* Set us up to detect when we get a SIGIO. */
	T_EXPECT_TRUE(SIG_ERR != signal(SIGIO, sigio_handler), "set SIGIO handler");
	T_EXPECT_POSIX_SUCCESS(sigprocmask(SIG_BLOCK, &sigio_set, NULL), "block SIGIO");

	/* Flush the replica, which should trigger a SIGIO. */
	T_EXPECT_POSIX_SUCCESS(tcflush(replica, TCIOFLUSH), NULL);

	/* Verify that we got SIGIO. */
	T_ASSERT_POSIX_SUCCESS(sigpending(&received_set), NULL);
	T_ASSERT_TRUE(sigismember(&received_set, SIGIO), "received SIGIO when we flushed");

	/* Reset state. */
	T_EXPECT_TRUE(SIG_ERR != signal(SIGIO, SIG_IGN), "reset SIGIO handler");
	T_EXPECT_POSIX_SUCCESS(sigprocmask(SIG_UNBLOCK, &sigio_set, NULL), "unblock SIGIO");

	/* Close fds. */
	T_EXPECT_POSIX_SUCCESS(close(replica), NULL);
	T_EXPECT_POSIX_SUCCESS(close(primary), NULL);
}

T_DECL(pty_121077498, "Ability to use O_NONBLOCK and O_ASYNC on pty primary without replica open.")
{
	/*
	 * We need to do the test in a child process because we might have
	 * getpgrp() == getpid().
	 */
	dt_helper_t helper = dt_child_helper("pty_121077498_impl");
	dt_run_helpers(&helper, 1, TEST_TIMEOUT);
}
