/*
 * Copyright (c) 2025 Apple Computer, Inc. All rights reserved.
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

#include <TargetConditionals.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <kern/debug.h>
#include <kern/telemetry.h>
#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <notify.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/syslimits.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fsgetpath_private.h>
#include <sys/coalition.h>
#include <sysexits.h>
#include <fcntl.h>
#include <spawn.h>
#include <spawn_private.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.misc.pagein_telemetry"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("misc"),
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true));

static uint64_t
create_coalition(int type)
{
	uint64_t id = 0;
	uint32_t flags = 0;
	uint64_t param[2];
	int ret;

	COALITION_CREATE_FLAGS_SET_TYPE(flags, type);
	ret = coalition_create(&id, flags);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_create(..., %d)", type);
	T_QUIET; T_ASSERT_GE(id, 0ULL, "coalition_create returned a valid id");

	/*
	 * Prevent notifications for this coalition so launchd doesn't get confused.
	 */
	param[0] = id;
	param[1] = 0;
	ret = sysctlbyname("kern.coalition_notify", NULL, NULL, param, sizeof(param));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.coalition_notify");

	return id;
}

static int
_spawn_command_under_coalition(char * const argv[])
{
	uint64_t jetsam_id = create_coalition(COALITION_TYPE_JETSAM);
	uint64_t resource_id = create_coalition(COALITION_TYPE_RESOURCE);

	posix_spawnattr_t spawn_attr;
	int error = posix_spawnattr_init(&spawn_attr);
	T_ASSERT_POSIX_ZERO(error, "posix_spawnattr_init");
	error = posix_spawnattr_set_telemetry_np(&spawn_attr, PSA_TELEMETRY_PAGEIN, 0);
	T_ASSERT_POSIX_ZERO(error, "posix_spawnattr_set_telemetry");
	error = posix_spawnattr_setcoalition_np(&spawn_attr, jetsam_id,
	    COALITION_TYPE_JETSAM, COALITION_TASKROLE_LEADER);
	T_ASSERT_POSIX_ZERO(error, "posix_spawnattr_setcoalition_np");
	error = posix_spawnattr_setcoalition_np(&spawn_attr, resource_id,
	    COALITION_TYPE_RESOURCE, COALITION_TASKROLE_LEADER);
	T_ASSERT_POSIX_ZERO(error, "posix_spawnattr_setcoalition_np");

	pid_t pid = 0;
	extern char **environ;
	error = posix_spawn(&pid, argv[0], NULL, &spawn_attr, argv, environ);
	T_ASSERT_POSIX_ZERO(error, "posix_spawn(%s, ...)", argv[0]);
	return pid;
}

static struct telemetry_pagein_buffer *
_read_pageins(size_t *pagein_count_inout)
{
	int size = __telemetry(TELEMETRY_CMD_PAGEIN_READ, 0, 0, 0, 0, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(size, "telemetry(PAGEIN_READ, 0, 0 ...)");
	size_t buf_size = (size_t)size;
	struct telemetry_pagein_buffer *buf = calloc(buf_size, 1);
	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(buf, "allocated %zu bytes for pagein data", buf_size);

	size = __telemetry(TELEMETRY_CMD_PAGEIN_READ, (uint64_t)buf, buf_size, 0, 0, 0);
	T_ASSERT_POSIX_SUCCESS(size, "telemetry(PAGEIN_READ, ...)");
	unsigned int copied = (size - sizeof(buf->tpb_header)) / sizeof(buf->tpb_pageins[0]);
	struct mach_timebase_info tb = { 0 };
	mach_timebase_info(&tb);
	uint64_t duration_ns = buf->tpb_header.tph_duration_mct * tb.numer / tb.denom;
	double duration_secs = (double)duration_ns / 1e9;
	T_LOG("copied %d/%d page-ins over %.6gs", copied, buf->tpb_header.tph_pagein_count, duration_secs);
	*pagein_count_inout = copied;
	return buf;
}

static bool
_log_pageins(struct telemetry_pagein_buffer *buf, size_t pageins_count, const char *check_path)
{
	bool found_path = false;
	for (int i = 0; i < pageins_count; i++) {
		char path[PATH_MAX] = { 0 };
		struct telemetry_pagein *pagein = &buf->tpb_pageins[i];
		int fd = openbyid_np((fsid_t *)&pagein->tp_fsid, (fsobj_id_t *)&pagein->tp_fsobj_id, O_RDONLY);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd, "openbyid_np(2)");
		if (fd >= 0) {
			int success = fcntl(fd, F_GETPATH, path);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(success, "fcntl(..., F_GETPATH, ...)");
			if (check_path) {
				if (strstr(path, check_path)) {
					found_path = true;
				}
			}
			T_LOG("+0x%016lld: %s", pagein->tp_file_offset, path);
			close(fd);
		} else {
			T_LOG("warning: failed to open file, fsid = %lld, fsobj_id = %lld, offset = %lld",
			    pagein->tp_fsid, pagein->tp_fsobj_id, pagein->tp_file_offset);
		}
	}
	return found_path;
}

T_HELPER_DECL(spawn_and_read_pageins,
    "spawn a process and read the page-in telemetry")
{
	if (argc < 1) {
		fprintf(stderr, "usage: telemetry_pagein_tests -n spawn_and_read_pageins <command> [<args> [...]]");
		exit(EX_USAGE);
	}
	int error = __telemetry(TELEMETRY_CMD_PAGEIN_SETUP, 1 << 20, 0, 0, 0, 0);
	T_ASSERT_POSIX_SUCCESS(error, "telemetry(PAGEIN_SETUP, ...)");

	int pid = _spawn_command_under_coalition(argv);
	int exit_status = 0;
	pid_t waited = waitpid(pid, &exit_status, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ(waited, pid, "waited on correct pid");

	size_t requested_in_copied_out = 100;
	struct telemetry_pagein_buffer *buf = _read_pageins(&requested_in_copied_out);
	(void)_log_pageins(buf, requested_in_copied_out, NULL);
	free(buf);
}

T_HELPER_DECL(sign_of_life, "show a sign of life and exit")
{
	T_LOG("Hello, World!");
}

/*
 * Page-in telemetry is only available on ARM64.
 */
#if defined(__arm64__)
#define PAGEIN_TELEMETRY_SUPPORTED 1
#else /* defined(__arm64__) */
#define PAGEIN_TELEMETRY_SUPPORTED 0
#endif /* !defined(__arm64__) */

T_DECL(pageins_self,
    "ensure page-ins are reported for launching the test program again",
    T_META_ENABLED(PAGEIN_TELEMETRY_SUPPORTED),
    T_META_SYSCTL_INT("kern.unrestrict_coalitions=1"),
    T_META_ASROOT(true))
{
	char exec_path[PATH_MAX];
	uint32_t path_size = sizeof(exec_path);

	T_SETUPBEGIN;

	T_QUIET;
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(exec_path, &path_size),
	    "_NSGetExecutablePath");

	int error = __telemetry(TELEMETRY_CMD_PAGEIN_SETUP, 1 << 20, 0, 0, 0, 0);
	T_ASSERT_POSIX_SUCCESS(error, "telemetry(PAGEIN_SETUP, ...)");

	extern int vfs_purge(void);
	T_LOG("purging filesystem cache");
	vfs_purge();

	char * helper_argv[] = {
		exec_path, "-n", "sign_of_life", NULL,
	};
	int pid = _spawn_command_under_coalition(helper_argv);
	int exit_status = 0;
	pid_t waited = waitpid(pid, &exit_status, 0);
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_EQ(waited, pid, "waited on correct pid");

	T_SETUPEND;

	T_LOG("spawned sign-of-life helper");

	size_t requested_in_copied_out = 100;
	struct telemetry_pagein_buffer *buf = _read_pageins(&requested_in_copied_out);
	bool found_executable = _log_pageins(buf, requested_in_copied_out, exec_path);
	free(buf);
	T_EXPECT_TRUE(found_executable, "found executable path in page-ins");
}
