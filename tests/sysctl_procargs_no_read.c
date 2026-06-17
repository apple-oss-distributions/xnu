/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <string.h>
#include <stdbool.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.sysctl"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("sysctl"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true),
	T_META_REQUIRES_PLATFORM_BINARY(true));

static int
read_procargs(pid_t pid, char *buf, size_t buf_size, size_t *out_size)
{
	int mib[3];
	size_t size = buf_size;
	int ret;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROCARGS2;
	mib[2] = pid;

	ret = sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &size, NULL, 0);
	if (out_size) {
		*out_size = size;
	}
	return ret;
}

static int
read_procargs1(pid_t pid, char *buf, size_t buf_size, size_t *out_size)
{
	int mib[3] = { CTL_KERN, KERN_PROCARGS, pid };
	size_t size = buf_size;
	int ret = sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &size, NULL, 0);
	if (out_size) {
		*out_size = size;
	}
	return ret;
}

T_HELPER_DECL(sleeper, "Helper that sleeps")
{
	raise(SIGSTOP);
}

T_HELPER_DECL(execer, "Helper that execs non-entitled binary")
{
	execv("/bin/sleep", (char *[]){"/bin/sleep", "1000", NULL});
}

static void
verify_hidden_procargs(pid_t child_pid, char *exec_path_out)
{
	char buf[sizeof(int) + MAXPATHLEN + 1 + MAXPATHLEN + 1];
	size_t out_size;
	int ret = read_procargs(child_pid, buf, sizeof(buf), &out_size);
	T_ASSERT_POSIX_SUCCESS(ret, "read_procargs()");

	T_ASSERT_GT_ULONG(out_size, sizeof(int) + 1, "read_procargs should return enough data");

	int child_argc;
	memcpy(&child_argc, buf, sizeof(int));
	char *exec_name = buf + sizeof(int);
	char *argv_0 = exec_name + strlen(exec_name) + 2; /* + 1 for null terminator, + 1 for padding */

	T_LOG("read procargs: argc = %d, exec name = %s, argv[0] = %s\n", child_argc, exec_name, argv_0);

	T_ASSERT_EQ(child_argc, 1, "argc should be 1 (synthesized)");
	T_ASSERT_EQ_STR(exec_name, argv_0, "exec_name should equal argv[0] in synthesized procargs");

	if (exec_path_out) {
		strlcpy(exec_path_out, exec_name, MAXPATHLEN);
	}
}

static void
verify_visible_procargs(pid_t child_pid)
{
	char buf[1024];
	size_t out_size;
	int ret = read_procargs(child_pid, buf, sizeof(buf), &out_size);
	T_ASSERT_POSIX_SUCCESS(ret, "read_procargs()");

	T_ASSERT_GT_ULONG(out_size, sizeof(int) + 1, "read_procargs should return enough data");

	int child_argc;
	memcpy(&child_argc, buf, sizeof(int));

	/* With real args, argc should be > 1 */
	T_ASSERT_GT(child_argc, 1, "argc should be > 1 (real args visible)");
}

static pid_t
spawn_helper(const char *helper_name)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");

	char *args[] = { path, "-n", (char *)helper_name, NULL };
	pid_t pid;
	int ret = posix_spawn(&pid, path, NULL, NULL, args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn %s", helper_name);
	return pid;
}


/*
 * Make sure that we handle strange buffer sizes the same way
 * as the unentitled logic, for compatibility purposes.
 */
static void
assert_procargs_buf_sizes(pid_t pid, const char *label)
{
	size_t argslen = 0;
	T_ASSERT_POSIX_SUCCESS(read_procargs(pid, NULL, 0, &argslen),
	    "%s: size query succeeds", label);
	T_ASSERT_GT_ULONG(argslen, (size_t)0, "%s: argslen is non-zero", label);

	char *buf = malloc(argslen * 2);
	T_ASSERT_NOTNULL(buf, "malloc");

	size_t small = argslen / 2;
	size_t big = argslen * 2;

	/* buflen < argslen: should succeed and report buflen bytes written */
	size_t out_size = small;
	T_ASSERT_POSIX_SUCCESS(read_procargs(pid, buf, small, &out_size),
	    "%s: small buf succeeds", label);
	T_ASSERT_EQ_ULONG(out_size, small, "%s: small buf returns buflen bytes", label);

	/* buflen == argslen: should succeed and report argslen bytes written */
	out_size = argslen;
	T_ASSERT_POSIX_SUCCESS(read_procargs(pid, buf, argslen, &out_size),
	    "%s: exact buf succeeds", label);
	T_ASSERT_EQ_ULONG(out_size, argslen, "%s: exact buf returns argslen bytes", label);

	/* buflen > argslen: should succeed and report argslen bytes written */
	out_size = big;
	T_ASSERT_POSIX_SUCCESS(read_procargs(pid, buf, argslen * 2, &out_size),
	    "%s: big buf succeeds", label);
	T_ASSERT_EQ_ULONG(out_size, argslen, "%s: big buf returns argslen bytes", label);

	free(buf);
}

T_DECL(procargs_no_read_spawn, "Spawning binary entitled with no-read-procargs hides the procargs")
{
	pid_t child_pid = spawn_helper("sleeper");

	char exec_path[MAXPATHLEN];
	verify_hidden_procargs(child_pid, exec_path);

	/* Make sure the new and old logic agree on the edge cases */
	assert_procargs_buf_sizes(child_pid, "child (synthetic path)");
	assert_procargs_buf_sizes(getpid(), "ourselves (data from stack)");

	/* Check KERN_PROCARGS (argc_yes=0) also succeeds and starts with the exec path */
#if TARGET_OS_OSX
	char buf[sizeof(int) + MAXPATHLEN + 1 + MAXPATHLEN + 1];
	size_t out_size;
	T_ASSERT_POSIX_SUCCESS(read_procargs1(child_pid, buf, sizeof(buf), &out_size), "KERN_PROCARGS succeeds");
	T_ASSERT_EQ_STR(buf, exec_path, "KERN_PROCARGS starts with exec path");
#endif

	kill(child_pid, SIGKILL);
}

T_DECL(procargs_no_read_fork, "Forking from binary entitled with no-read-procargs hides the procargs")
{
	pid_t child_pid = fork();
	if (child_pid == 0) {
		raise(SIGSTOP);
		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork");
		verify_hidden_procargs(child_pid, NULL);
		kill(child_pid, SIGKILL);
	}
}

T_DECL(procargs_no_read_spawn_unentitled, "Spawning from entitled to unentitled binary shows the procargs")
{
	char *args[] = {"/bin/sleep", "1000", NULL};
	pid_t child_pid;
	int ret = posix_spawn(&child_pid, "/bin/sleep", NULL, NULL, args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn /bin/sleep");
	verify_visible_procargs(child_pid);
	kill(child_pid, SIGKILL);
}

T_DECL(procargs_no_read_exec_unentitled, "Execing from entitled to unentitled binary shows the procargs")
{
	pid_t child_pid = spawn_helper("execer");

	char buf[1024];
	while (1) {
		usleep(10000);
		if (read_procargs(child_pid, buf, sizeof(buf), NULL) != 0) {
			break;
		}
		char *exec_name = buf + sizeof(int);
		if (strcmp(exec_name, "/bin/sleep") == 0) {
			break;
		}
	}

	verify_visible_procargs(child_pid);
	kill(child_pid, SIGKILL);
}
