/*
 * Copyright (c) 2026 Apple Computer, Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <spawn.h>
#include <mach-o/dyld.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.sysctl"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("sysctl"),
	T_META_RUN_CONCURRENTLY(true));

/*
 * We need the target process' argument data to span multiple pages,
 * so that vm_map_copy_overwrite goes through vm_fault_copy.
 */
#define PAD_TOTAL       (128 * 1024)
#define PAD_ARGLEN      4096
#define PAD_NARGS       (PAD_TOTAL / PAD_ARGLEN)

T_HELPER_DECL(large_args_sleeper,
    "Helper with large argv, sleeps until killed")
{
	raise(SIGSTOP);
}

static pid_t
spawn_large_args_helper(void)
{
	char path[PATH_MAX];
	char *pad = NULL;
	char **args = NULL;
	int nargs = PAD_NARGS + 3;
	uint32_t path_size = sizeof(path);

	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size),
	    "_NSGetExecutablePath");

	args = (char**)calloc(nargs + 1, sizeof(char *));

	T_QUIET; T_ASSERT_NOTNULL(args, "calloc argv");

	args[0] = path;
	args[1] = "-n";
	args[2] = "large_args_sleeper";

	pad = (char*)malloc(PAD_ARGLEN);
	T_QUIET; T_ASSERT_NOTNULL(pad, "malloc pad arg");

	memset(pad, 'A', PAD_ARGLEN - 1);
	pad[PAD_ARGLEN - 1] = '\0';

	for (int i = 0; i < PAD_NARGS; i++) {
		args[i + 3] = pad;
	}
	args[nargs] = NULL;

	pid_t pid;
	int ret = posix_spawn(&pid, path, NULL, NULL, args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn large_args_sleeper");

	free(args);
	free(pad);
	return pid;
}

T_DECL(procargsx_cow,
    "sysctl_procargsx must not panic on CoW of kernel buffer")
{
	size_t len = 0;
	char *buf = NULL;
	int ret;
	pid_t child_pid = spawn_large_args_helper();
	int mib[3] = { CTL_KERN, KERN_PROCARGS2, child_pid };

	ret = sysctl(mib, 3, NULL, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_PROCARGS2 size query");
	T_LOG("KERN_PROCARGS2 reports 0x%zx bytes", len);

	T_ASSERT_GT_ULONG(len, (size_t)(64 * 1024),
	    "procargs size should be large enough to span multiple pages");

	buf = (char*)malloc(len);
	T_ASSERT_NOTNULL(buf, "malloc 0x%zx bytes", len);

	/* Trigger CoW, should not panic */
	ret = sysctl(mib, 3, buf, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_PROCARGS2 fetch (0x%zx bytes)", len);

	free(buf);
	kill(child_pid, SIGKILL);

	T_PASS("sysctl_doprocargs2 CoW path exercised without panic");
}
