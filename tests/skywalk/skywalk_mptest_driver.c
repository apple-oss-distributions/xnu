/*
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * Testing Framework for skywalk wrappers and syscalls
 *
 * This version forks many subchildren and sequences them via
 * control messages on fd 3 (MPTEST_SEQ_FILENO)
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static uint64_t skywalk_features;
extern char **environ;
bool skywalk_in_driver;
static struct timeval inittime;
static struct skywalk_mptest *curr_test;

#define test_exit(ecode)                                                                           \
	{                                                                                          \
	        T_LOG("%s:%d := Test exiting with error code %d\n", __func__, __LINE__, (ecode)); \
	        T_END;                                                                            \
	}

/*
 * Print extra stats (e.g. AQM, ARP) that doesn't have to be done by the child.
 */
static void
print_extra_stats(struct skywalk_mptest *test)
{
	struct protox *tp;

	skt_aqstatpr("feth0");  /* netstat -qq -I feth0 */
	skt_aqstatpr("feth1");  /* netstat -qq -I feth1 */
	if ((!strncmp(test->skt_testname, "xferrdudpping",
	    strlen("xferrdudpping")))) {
		skt_aqstatpr("rd0");  /* netstat -qq -I rd0 */
	}

	/* netstat -sp arp */
	tp = &protox[0];
	skt_printproto(tp, tp->pr_name);
}

void
skywalk_mptest_driver_SIGINT_handler(int sig)
{
	signal(sig, SIG_IGN);

	if (curr_test != NULL) {
		if (curr_test->skt_fini != NULL) {
			curr_test->skt_fini();
		}
	}

	exit(0);
}

void
skywalk_mptest_driver_init(void)
{
	size_t len;

	assert(!skywalk_in_driver); // only call init once

	skywalk_in_driver = true;

	/* Query the kernel for available skywalk features */
	len = sizeof(skywalk_features);
	sysctlbyname("kern.skywalk.features", &skywalk_features, &len, NULL, 0);

	gettimeofday(&inittime, NULL);

	curr_test = NULL;

	signal(SIGINT, skywalk_mptest_driver_SIGINT_handler);
}


static struct skywalk_mptest_check *sk_checks[] = {
	&skt_filternative_check,
	&skt_filtercompat_check,
};

bool
skywalk_mptest_supported(const char *name)
{
	int i;

	for (i = 0; i < sizeof(sk_checks) / sizeof(sk_checks[0]); i++) {
		if (strcmp(name, sk_checks[i]->skt_testname) == 0) {
			return sk_checks[i]->skt_supported();
		}
	}
	return TRUE;
}

int
skywalk_mptest_driver_run(struct skywalk_mptest *skt, bool ignoreskip)
{
	posix_spawnattr_t attrs;
	int error;
	int childfail;
	bool childarg;

	skywalk_mptest_driver_init();

	/* Initialize posix_spawn attributes */
	posix_spawnattr_init(&attrs);

	if ((error = posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETEXEC)) != 0) {
		T_LOG("posix_spawnattr_setflags: %s", strerror(error));
		test_exit(1);
	}

	/* Run Tests */
	T_LOG("Test \"%s\":\t%s", skt->skt_testname, skt->skt_testdesc);

	if ((skt->skt_required_features & skywalk_features) !=
	    skt->skt_required_features) {
		T_LOG("Required features: 0x%llx, actual features 0x%llx",
		    skt->skt_required_features, skywalk_features);
		if (!ignoreskip) {
			T_LOG("Test Result: SKIPPED\n-------------------");
			return 0;
		} else {
			T_LOG("Proceeding with skipped test");
		}
	}
	if (!skywalk_mptest_supported(skt->skt_testname)) {
		T_LOG("Test is not supported on this device");
		if (!ignoreskip) {
			T_LOG("Test Result: SKIPPED\n-------------------");
			return 0;
		} else {
			T_LOG("Proceeding with skipped test");
		}
	}
	if (skt->skt_init) {
		skt->skt_init();
	}
	curr_test = skt;

	pid_t pids[skt->skt_nchildren];
	int fds[skt->skt_nchildren];

	/* If the child arg isn't set, then set it */
	childarg = !skt->skt_argv[3];

	T_LOG("Spawning %d children", skt->skt_nchildren);

	for (int j = 0; j < skt->skt_nchildren; j++) {
		int pfd[2];
		char argbuf[11];

		if (childarg) {
			snprintf(argbuf, sizeof(argbuf), "%d", j);
			skt->skt_argv[3] = "--child";
			skt->skt_argv[4] = argbuf;
		}

		//T_LOG("Spawning:");
		//for (int k = 0; skt->skt_argv[k]; k++) {
		//	T_LOG(" %s", skt->skt_argv[k]);
		//}
		//T_LOG("\n");

		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pfd) == -1) {
			SKT_LOG("socketpair: %s", strerror(errno));
			test_exit(1);
		}

		/* Fork and exec child */
		if ((pids[j] = fork()) == -1) {
			SKT_LOG("fork: %s", strerror(errno));
			test_exit(1);
		}

		if (pids[j] == 0) {
			/* XXX If a parent process test init expects to share an fd with a
			 * child process, care must be taken to make sure this doesn't
			 * accidentally close it.  So far, no test does this.  Another
			 * option would be to pass an fd number to the child's argv instead
			 * of assuming the hard coded fd number.
			 */
			error = close(pfd[1]);
			assert(!error);
			dup2(pfd[0], MPTEST_SEQ_FILENO);
			if (pfd[0] != MPTEST_SEQ_FILENO) {
				error = close(pfd[0]);
				assert(!error);
			}

			int argc = 0;  /* XXX */
			int ret = skt->skt_main(argc, skt->skt_argv);
			exit(ret);
			/* Not reached */
			abort();
		}

		error = close(pfd[0]);
		assert(!error);
		int fdflags = fcntl(pfd[1], F_GETFD);
		if (fdflags == -1) {
			SKT_LOG("fcntl(F_GETFD): %s", strerror(errno));
			test_exit(1);
		}
		error = fcntl(pfd[1], F_SETFD, fdflags | FD_CLOEXEC);
		assert(!error);
		fds[j] = pfd[1];
	}

	/* Wait for input from children */
	for (int j = 0; j < skt->skt_nchildren; j++) {
		ssize_t ret;
		char buf[1];
		if ((ret = read(fds[j], buf, sizeof(buf))) == -1) {
			SKT_LOG("read: %s", strerror(errno));
			test_exit(1);
		}
		assert(ret == 1);
	}

	// sleep for debug introspection
	//T_LOG("sleep 100\n");
	//sleep(100);

	/* Send output to children */
	for (int j = 0; j < skt->skt_nchildren; j++) {
		ssize_t ret;
		char buf[1] = { 0 };
		if ((ret = write(fds[j], buf, sizeof(buf))) == -1) {
			SKT_LOG("write: %s", strerror(errno));
			test_exit(1);
		}
		assert(ret == 1);

		error = close(fds[j]);
		assert(!error);
	}

	childfail = 0;
	for (int j = 0; j < skt->skt_nchildren; j++) {
		int child;
		pid_t childpid;
		int child_status;

		/* Wait for children and check results */
		if ((childpid = wait(&child_status)) == -1) {
			SKT_LOG("wait: %s", strerror(errno));
			test_exit(1);
		}

		/* Which child was this? */
		for (child = 0; child < skt->skt_nchildren; child++) {
			if (childpid == pids[child]) {
				pids[child] = 0;
				break;
			}
		}
		if (child == skt->skt_nchildren) {
			T_LOG("Received unexpected child status from pid %d\n", childpid);
			test_exit(1);
		}

		if (WIFEXITED(child_status)) {
			if (WEXITSTATUS(child_status)) {
				T_LOG("Child %d (pid %d) exited with status %d",
				    child, childpid, WEXITSTATUS(child_status));
			}
		}
		if (WIFSIGNALED(child_status)) {
			T_LOG("Child %d (pid %d) signaled with signal %d coredump %d",
			    child, childpid, WTERMSIG(child_status), WCOREDUMP(child_status));
		}

		if (!WIFEXITED(child_status) || WEXITSTATUS(child_status)) {
			childfail++;
			/* Wait for a second and then send sigterm to remaining children
			 * in case they may be stuck
			 */
			if (childfail == 1) {
				print_extra_stats(skt);
				sleep(1);
				for (int k = 0; k < skt->skt_nchildren; k++) {
					if (pids[k]) {
						error = kill(pids[k], SIGTERM);
						if (error == 0) {
							T_LOG("Delivered SIGTERM to child %d pid %d",
							    k, pids[k]);
						} else if (errno != ESRCH) {
							SKT_LOG("kill(%d, SIGTERM): %s", pids[k], strerror(errno));
							test_exit(1);
						}
					}
				}
			}
		}
	}

	if (skt->skt_fini) {
		skt->skt_fini();
	}
	curr_test = NULL;

	if (childfail) {
		T_FAIL("Test %s: %s", skt->skt_testname, skt->skt_testdesc);
		if ((skt->skt_required_features &
		    SK_FEATURE_NEXUS_KERNEL_PIPE) != 0 &&
		    geteuid() != 0) {
			T_LOG("%sPlease try running test as root%s",
			    BOLD, NORMAL);
		}
	} else {
		T_PASS("Test %s: %s", skt->skt_testname, skt->skt_testdesc);
	}

	posix_spawnattr_destroy(&attrs);

	return 0;
}
