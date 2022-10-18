/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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

#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_OWNER("jainam_shah"),
	T_META_RUN_CONCURRENTLY(true)
	);

T_DECL(test_ptraceme, "Test that ptraced process is stopped when it execs", T_META_ASROOT(true), T_META_ENABLED(TARGET_OS_OSX))
{
	int ret;

	T_LOG("Parent %d: Calling fork()", getpid());
	pid_t child_pid = fork();
	if (child_pid == -1) {
		T_FAIL("Fork failed with error: %d: %s", errno, strerror(errno));
	} else if (child_pid == 0) {
		/* Child */
		T_LOG("Child %d: Calling ptrace(PT_TRACE_ME, 0, NULL, 0)", getpid());
		ret = ptrace(PT_TRACE_ME, 0, NULL, 0);
		T_EXPECT_POSIX_SUCCESS(ret, "ptrace PT_TRACE_ME");

		T_LOG("Child %d: Calling execl(\"/bin/echo\", ...)", getpid());
		execl("/bin/echo", "echo", "/bin/echo executed - this should not happen before parent has detached!", NULL);
		T_FAIL("execl failed with error: %d: %s", errno, strerror(errno));
	} else {
		/* Parent */
		T_LOG("Parent %d: Calling waitpid(%d, NULL, WUNTRACED)", getpid(), child_pid);
		int child_status = 0;

		ret = waitpid(child_pid, &child_status, WUNTRACED);
		T_EXPECT_EQ(ret, child_pid, "Waitpid returned status for child pid");

		T_EXPECT_TRUE(WIFSTOPPED(child_status),
		    "Parent %d: waitpid() indicates that child %d is now stopped for tracing", getpid(), child_pid);

		T_LOG("Parent %d: Calling ptrace(PT_DETACH, %d, NULL, 0)", getpid(), child_pid);
		ret = ptrace(PT_DETACH, child_pid, NULL, 0);
		T_EXPECT_POSIX_SUCCESS(ret, "ptrace PT_DETACH");

		T_LOG("Parent %d: Calling kill(%d, SIGTERM)", getpid(), child_pid);
		kill(child_pid, SIGTERM);

		T_LOG("Parent %d: Calling wait(NULL)\n", getpid());
		wait(NULL);

		T_END;
	}
}
