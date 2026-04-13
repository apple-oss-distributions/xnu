/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o direntries_permissions direntries_permissions.c -g -Weverything */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/kauth.h>

#include <darwintest.h>
#include <darwintest/utils.h>

static char template[MAXPATHLEN];
static char *testdir = NULL;
static char dir1[PATH_MAX], dir2[PATH_MAX];

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

static int
switch_user(uid_t uid, gid_t gid)
{
	int ret;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	ret = pthread_setugid_np(uid, gid);
#pragma clang diagnostic pop
	return ret;
}

static void
cleanup(void)
{
	switch_user(KAUTH_UID_NONE, KAUTH_GID_NONE);

	if (dir2[0] != '\0') {
		rmdir(dir2);
	}
	if (dir1[0] != '\0') {
		rmdir(dir1);
	}

	if (rmdir(testdir)) {
		T_FAIL("Unable to remove the test directory (%s)", testdir);
	}
}

T_DECL(direntries_permissions_no_owner,
    "Directory write permission should give full control of directory contents")
{
	dir1[0] = dir2[0] = '\0';

	if (geteuid() != 0) {
		T_SKIP("Test should run as root");
	}

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Switch user to 20/501 */
	T_ASSERT_POSIX_SUCCESS(switch_user(501, 20), "Switching user to 501/20");

	/* Create test root dir */
	snprintf(template, sizeof(template), "%s/direntries_permissions_no_owner-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	/* Setup directory names */
	snprintf(dir1, sizeof(dir1), "%s/%s", testdir, "dir1");
	snprintf(dir2, sizeof(dir2), "%s/%s", testdir, "dir2");

	/* Switch user to root */
	T_ASSERT_POSIX_SUCCESS(switch_user(KAUTH_UID_NONE, KAUTH_GID_NONE), "Switching user to root");

	/* Create the second directory */
	T_ASSERT_POSIX_SUCCESS(mkdir(dir1, 0755), "Creating directory %s", dir1);

	/* Switch user to 20/501 */
	T_ASSERT_POSIX_SUCCESS(switch_user(501, 20), "Switching user to 501/20");

	T_SETUPEND;

	/* Rename dir1 -> dir2 */
	T_ASSERT_POSIX_SUCCESS(rename(dir1, dir2), "Renaming %s -> %s", dir1, dir2);
}

T_DECL(direntries_permissions_no_write,
    "Directory without write permissions should not be renamed")
{
	dir1[0] = dir2[0] = '\0';

	if (geteuid() != 0) {
		T_SKIP("Test should run as root");
	}

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Switch user to 20/501 */
	T_ASSERT_POSIX_SUCCESS(switch_user(501, 20), "Switching user to 501/20");

	/* Create test root dir */
	snprintf(template, sizeof(template), "%s/direntries_permissions_no_write-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	/* Changing directory */
	T_ASSERT_POSIX_SUCCESS(chdir(testdir), "Changing directory %s", testdir);

	/* Setup directory names */
	snprintf(dir1, sizeof(dir1), "%s/%s", testdir, "dir1");
	snprintf(dir2, sizeof(dir2), "%s/%s", testdir, "dir2");

	/* Create the first directory */
	T_ASSERT_POSIX_SUCCESS(mkdir(dir1, 0777), "Creating directory %s", dir1);

	/* Setup mode */
	T_ASSERT_POSIX_SUCCESS(chmod(dir1, 0777), "Changing mode to directory 0777");

	/* Create the second directory */
	T_ASSERT_POSIX_SUCCESS(mkdir(dir2, 0555), "Creating directory %s", dir2);

	/* Setup mode */
	T_ASSERT_POSIX_SUCCESS(chmod(dir2, 0555), "Changing mode to directory 0555");

	T_SETUPEND;

	T_EXPECT_POSIX_FAILURE(rename(dir1, dir2), EACCES, "Renaming dir1 -> dir2. should fail with EACCES");
	T_EXPECT_POSIX_FAILURE(rename(dir2, dir1), EACCES, "Renaming dir2 -> dir1. should fail with EACCES");
}
