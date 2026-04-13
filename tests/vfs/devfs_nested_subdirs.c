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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o devfs_nested_dir devfs_nested_dirs.c -g -Weverything */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <darwintest.h>
#include <darwintest/utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),
	T_META_ENABLED(TARGET_OS_OSX),
	T_META_CHECK_LEAKS(false));


#define MAX_NESTED_SUBDIRS      16

static char template[MAXPATHLEN];
static char *mount_path;

static void
cleanup(void)
{
	if (mount_path) {
		unmount(mount_path, MNT_FORCE);
		rmdir(mount_path);
	}
}

/* Create n-level nested subdirs and Return the last parent dir's fd. */
static int
create_nested_subdirs(char *dir, int levels)
{
	int parentdirfd = -1;

	T_QUIET; T_ASSERT_POSIX_SUCCESS((parentdirfd = open(mount_path, O_SEARCH, 0777)),
	    "Opening mount root diretory");

	for (int i = 0; i <= levels; i++) {
		int dirfd;

		T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdirat(parentdirfd, dir, 0777),
		    "Verifying that creating subdir at level %d should pass", i);
		T_QUIET; T_ASSERT_POSIX_SUCCESS((dirfd = openat(parentdirfd, dir, O_SEARCH)),
		    "Verifying that opening subdir at level %d should pass", i);

		close(parentdirfd);
		parentdirfd = dirfd;
	}

	return parentdirfd;
}

T_DECL(nested_subdirs_limit,
    "Test creating and renaming nested subdirs in devfs mount",
    T_META_ENABLED(true))
{
	char todirpath[PATH_MAX];
	int lastdirfd, rootdirfd, todirfd;

#if (!TARGET_OS_OSX)
	T_SKIP("Not macOS");
#endif

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/devfs", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((mount_path = mkdtemp(template)),
	    "Creating mount path %s", template);

	T_ASSERT_POSIX_SUCCESS(mount("devfs", mount_path, MNT_IGNORE_OWNERSHIP, NULL),
	    "Mounting devfs mount using path %s", mount_path);

	T_ASSERT_POSIX_SUCCESS(chmod(mount_path, 0777),
	    "Changing permission on root diretory");

	T_SETUPEND;

	lastdirfd = create_nested_subdirs("aaa", MAX_NESTED_SUBDIRS);
	T_ASSERT_NE_INT(lastdirfd, -1, "create_nested_subdirs(aaa, 16)");

	T_ASSERT_POSIX_FAILURE(mkdirat(lastdirfd, "aaa", 0777), EMLINK,
	    "Verifying that creating subdir at max level (>16) should fail");
	close(lastdirfd);

	/* Create a nested subdirs of 8 levels deep.*/
	lastdirfd = create_nested_subdirs("bbb", 8);
	T_ASSERT_NE_INT(lastdirfd, -1, "create_nested_subdirs(bbb, 8)");
	close(lastdirfd);

	/* Create a nested subdirs of 10 levels deep.*/
	lastdirfd = create_nested_subdirs("ccc", 10);
	T_ASSERT_NE_INT(lastdirfd, -1, "create_nested_subdirs(ccc, 10)");
	close(lastdirfd);

	T_QUIET; T_ASSERT_POSIX_SUCCESS((rootdirfd = open(mount_path, O_SEARCH, 0777)),
	    "Opening mount root diretory");

	snprintf(todirpath, sizeof(todirpath),
	    "%s/bbb/bbb/bbb/bbb/bbb/bbb/bbb/bbb/bbb", mount_path);
	T_QUIET; T_ASSERT_POSIX_SUCCESS((todirfd = open(todirpath, O_SEARCH, 0777)),
	    "Opening target diretory");

	/*
	 * Verify that rename should fail if the deepest subdir (after rename)
	 * would exceed the max nested subdirs limit.
	 */
	T_ASSERT_POSIX_FAILURE(renameat(rootdirfd, "ccc", todirfd, "ccc"), EMLINK,
	    "Verifying that rename a dir with deep nested subdirs that exceed limit should fail");

	/* Create a nested subdirs of 4 levels deep.*/
	lastdirfd = create_nested_subdirs("ddd", 4);
	T_ASSERT_NE_INT(lastdirfd, -1, "create_nested_subdirs(ddd, 4)");
	close(lastdirfd);

	/*
	 * Verify that rename should succeed if the deepest subdir (after rename)
	 * doesn't exceed the max nested subdirs limit.
	 */
	T_ASSERT_POSIX_SUCCESS(renameat(rootdirfd, "ddd", todirfd, "ddd"),
	    "Verifying that rename a dir with nested subdirs that doesn't exceed limit should succeed");

	close(todirfd);
	close(rootdirfd);
}
