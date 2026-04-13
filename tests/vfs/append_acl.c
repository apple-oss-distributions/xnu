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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o append_acl append_acl.c */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define RUN_TEST     (TARGET_OS_OSX || TARGET_OS_SIMULATOR)  /* Platforms that support system() and ACL management */

#define TESTFILE "testfile"

static char template[MAXPATHLEN];
static char *testdir = NULL;
static int testdir_fd = -1;
static char testfile_path[MAXPATHLEN];

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ENABLED(RUN_TEST),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (testdir_fd != -1) {
		unlinkat(testdir_fd, TESTFILE, 0);
		close(testdir_fd);
		rmdir(testdir);
	}
}

static int
setup_test_file_with_deny_append_acl(void)
{
	char cmd[512];
	int fd;

	/* Create test file */
	fd = openat(testdir_fd, TESTFILE, O_CREAT | O_WRONLY, 0644);
	if (fd == -1) {
		T_LOG("Failed to create test file: %s", strerror(errno));
		return -1;
	}
	close(fd);

	/* Add deny append ACL */
	snprintf(cmd, sizeof(cmd), "chmod +a \"group:everyone deny append\" %s", testfile_path);
	if (system(cmd) != 0) {
		T_LOG("Failed to set deny append ACL");
		return -1;
	}

	return 0;
}

T_DECL(append_acl_direct_open_denied,
    "Direct open with O_APPEND should be denied with deny append ACL")
{
	int fd;
	uid_t original_uid;

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	/* Check if running as root and switch to user 501 to test ACL enforcement */
	original_uid = geteuid();
	if (original_uid == 0) {
		T_LOG("Warning: Running as root, switching to user 501 to test ACL enforcement");
		T_ASSERT_POSIX_SUCCESS(seteuid(501), "Switching to user 501");
	}

	snprintf(template, sizeof(template), "%s/append_acl_test-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	snprintf(testfile_path, sizeof(testfile_path), "%s/%s", testdir, TESTFILE);

	T_ASSERT_POSIX_SUCCESS(setup_test_file_with_deny_append_acl(), "Setting up test file with deny append ACL");

	T_SETUPEND;

	/* Test: Direct open with O_APPEND should fail */
	fd = openat(testdir_fd, TESTFILE, O_WRONLY | O_APPEND);
	T_EXPECT_POSIX_FAILURE(fd, EACCES, "Direct open with O_APPEND should be denied");
	if (fd >= 0) {
		close(fd);
	}

	/* Restore original uid if we switched */
	if (original_uid == 0) {
		T_ASSERT_POSIX_SUCCESS(seteuid(original_uid), "Restoring original uid");
	}
}

T_DECL(append_acl_fcntl_setfl_denied,
    "Setting O_APPEND via F_SETFL should be denied with deny append ACL")
{
	int fd;
	uid_t original_uid;

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	/* Check if running as root and switch to user 501 to test ACL enforcement */
	original_uid = geteuid();
	if (original_uid == 0) {
		T_LOG("Warning: Running as root, switching to user 501 to test ACL enforcement");
		T_ASSERT_POSIX_SUCCESS(seteuid(501), "Switching to user 501");
	}

	snprintf(template, sizeof(template), "%s/append_acl_test-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	snprintf(testfile_path, sizeof(testfile_path), "%s/%s", testdir, TESTFILE);

	T_ASSERT_POSIX_SUCCESS(setup_test_file_with_deny_append_acl(), "Setting up test file with deny append ACL");

	T_SETUPEND;

	/* Open file without O_APPEND (should succeed) */
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, TESTFILE, O_WRONLY)), "Opening test file without O_APPEND");

	/* Test: Setting O_APPEND via fcntl should fail */
	T_EXPECT_POSIX_FAILURE(fcntl(fd, F_SETFL, O_APPEND), EACCES, "Setting O_APPEND via F_SETFL should be denied");

	/* Verify O_APPEND was not set */
	int flags = fcntl(fd, F_GETFL);
	T_EXPECT_POSIX_SUCCESS(flags, "Getting file flags");
	if (flags >= 0) {
		T_EXPECT_EQ((flags & O_APPEND), 0, "O_APPEND should not be set after failed F_SETFL");
	}

	close(fd);

	/* Restore original uid if we switched */
	if (original_uid == 0) {
		T_ASSERT_POSIX_SUCCESS(seteuid(original_uid), "Restoring original uid");
	}
}

T_DECL(append_acl_fcntl_setfl_allowed_without_acl,
    "Setting O_APPEND via F_SETFL should succeed without deny append ACL")
{
	int fd;

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/append_acl_test-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	snprintf(testfile_path, sizeof(testfile_path), "%s/%s", testdir, TESTFILE);

	/* Create test file without ACL restrictions */
	T_ASSERT_POSIX_SUCCESS(openat(testdir_fd, TESTFILE, O_CREAT | O_WRONLY, 0644), "Creating test file without ACL");

	T_SETUPEND;

	/* Open file without O_APPEND */
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, TESTFILE, O_WRONLY)), "Opening test file without O_APPEND");

	/* Test: Setting O_APPEND via fcntl should succeed */
	T_EXPECT_POSIX_SUCCESS(fcntl(fd, F_SETFL, O_APPEND), "Setting O_APPEND via F_SETFL should succeed without ACL restrictions");

	/* Verify O_APPEND was set */
	int flags = fcntl(fd, F_GETFL);
	T_EXPECT_POSIX_SUCCESS(flags, "Getting file flags");
	if (flags >= 0) {
		T_EXPECT_NE((flags & O_APPEND), 0, "O_APPEND should be set after successful F_SETFL");
	}

	close(fd);
}

T_DECL(append_acl_fcntl_setfl_other_flags_allowed,
    "Setting other flags via F_SETFL should succeed even with deny append ACL")
{
	int fd;

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/append_acl_test-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	snprintf(testfile_path, sizeof(testfile_path), "%s/%s", testdir, TESTFILE);

	T_ASSERT_POSIX_SUCCESS(setup_test_file_with_deny_append_acl(), "Setting up test file with deny append ACL");

	T_SETUPEND;

	/* Open file without O_APPEND */
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, TESTFILE, O_WRONLY)), "Opening test file without O_APPEND");

	/* Test: Setting other flags (like O_NONBLOCK) without O_APPEND should succeed */
	T_EXPECT_POSIX_SUCCESS(fcntl(fd, F_SETFL, O_NONBLOCK), "Setting flags without O_APPEND should succeed");

	close(fd);
}
