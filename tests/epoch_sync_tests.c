/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>
#include <sys/wait.h>

#include <darwintest.h>
#include <signal.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.epoch_sync_tests"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("scheduler"),
	T_META_OWNER("mphalan"));

#define TEST_SYSCTL "debug.test.esync_test"
T_DECL(epoch_sync_test, "Test Epoch Sync",
    T_META_REQUIRES_SYSCTL_EQ(TEST_SYSCTL, 0))
{
	int64_t old = 0;
	size_t old_len = sizeof(old);
	int64_t new = 10;
	size_t new_len = sizeof(new);

	int rc = sysctlbyname(TEST_SYSCTL, &old, &old_len, &new, new_len);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(" TEST_SYSCTL ")");
}

#define TIMEOUT 10

static void
timeout(__unused int ignored)
{
	T_ASSERT_FAIL("child didn't exit in time");
}

#define TEST_WAIT_SYSCTL "debug.test.esync_test_wait"
T_DECL(epoch_sync_test_wait, "Test Epoch Sync Wait",
    T_META_REQUIRES_SYSCTL_EQ(TEST_WAIT_SYSCTL, 0))
{
	int64_t old = 0;
	size_t old_len = sizeof(old);
	int64_t new = 10;
	size_t new_len = sizeof(new);

	pid_t pid = fork();
	T_ASSERT_POSIX_SUCCESS(pid, "fork");

	/* Have the child block in an abortable esync_wait call. */
	if (pid == 0) {
		int rc = sysctlbyname(TEST_WAIT_SYSCTL, &old, &old_len, &new, new_len);
		/*
		 * The only way out of this syscall is if the process is killed.
		 * So nothing after this point should run.
		 */
		T_ASSERT_FAIL("Unexpectedly returned from sysctl (%d)", rc);
	}

	/* Give enough time for the child to block in esync_wait. */
	sleep(1);

	/* Kill the child. */
	int ret = kill(pid, SIGKILL);
	T_ASSERT_POSIX_SUCCESS(ret, "killing child");

	/* Wait a maximum of TIMEOUT seconds for the child to exit. */
	T_ASSERT_NE(signal(SIGALRM, timeout), SIG_ERR, NULL);
	T_ASSERT_POSIX_SUCCESS(alarm(TIMEOUT), NULL);

	int status = 0;
	T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waiting for child");

	/* Check that the child was killed. */
	T_ASSERT_TRUE(WIFSIGNALED(status), "exited due to signal");
	T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "killed with SIGKILL");
}
