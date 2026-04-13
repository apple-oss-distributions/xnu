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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o setuid_race setuid_race.c */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/attr.h>
#include <time.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define TEST_DURATION 10 /* seconds */
#define UNPRIVILEGED_UID 501
#define UNPRIVILEGED_GID 20

static char template[MAXPATHLEN];
static char *testdir = NULL;
static char test_file[MAXPATHLEN];
static volatile int test_failed = 0;
static volatile int test_running = 1;

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (test_file[0] != '\0') {
		unlink(test_file);
	}

	if (testdir) {
		rmdir(testdir);
	}
}

static void
unprivileged_thread_chmod(void)
{
	while (test_running) {
		if (chmod(test_file, 0777 | S_ISUID) != 0) {
			if (errno != EPERM && errno != EACCES) {
				T_LOG("chmod failed with unexpected error: %d", errno);
			}
		}
	}
	exit(0);
}

static void
unprivileged_thread_setattrlist(void)
{
	struct attrlist attrlist = {};
	struct {
		uint32_t mode;
	} attrbuf;

	attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrlist.commonattr = ATTR_CMN_ACCESSMASK;
	attrbuf.mode = 0777 | S_ISUID;

	while (test_running) {
		if (setattrlist(test_file, &attrlist, &attrbuf, sizeof(attrbuf), 0) != 0) {
			if (errno != EPERM && errno != EACCES) {
				T_LOG("setattrlist failed with unexpected error: %d", errno);
			}
		}
	}
	exit(0);
}

static void
privileged_thread(pid_t child_pid)
{
	time_t start_time = time(NULL);
	time_t current_time;

	while (test_running && (current_time = time(NULL)) - start_time < TEST_DURATION) {
		/* Check if child is still running */
		if (waitpid(child_pid, NULL, WNOHANG) != 0) {
			T_LOG("Child process exited unexpectedly");
			break;
		}

		/* Change ownership to root */
		if (chown(test_file, 0, 0) != 0) {
			T_FAIL("chown to root failed: %d", errno);
			test_failed = 1;
			break;
		}

		/* Check if we have a root-owned setuid file (the race condition) */
		struct stat sb;
		if (stat(test_file, &sb) != 0) {
			T_FAIL("stat failed: %d", errno);
			test_failed = 1;
			break;
		}

		if (sb.st_uid == 0 && (sb.st_mode & S_ISUID)) {
			T_FAIL("Race condition detected! Root-owned setuid file created!");
			test_failed = 1;
			break;
		}

		/* Change ownership back to unprivileged user to allow next chmod */
		if (chown(test_file, UNPRIVILEGED_UID, UNPRIVILEGED_GID) != 0) {
			T_FAIL("chown to unprivileged user failed: %d", errno);
			test_failed = 1;
			break;
		}
	}

	test_running = 0;
}

T_DECL(setuid_race_chmod_chown,
    "Test that chmod/chown race condition is fixed",
    T_META_TIMEOUT(TEST_DURATION + 5))
{
	int fd;
	pid_t child_pid;

	test_file[0] = '\0';

	T_ATEND(cleanup);

	T_LOG("Starting setuid race test for %d seconds", TEST_DURATION);

	/* Create temporary directory for test file */
	snprintf(template, sizeof(template), "%s/setuid_race_chmod_chown-XXXXXX", dt_tmpdir());
	T_ASSERT_NOTNULL((testdir = mkdtemp(template)), "Creating test directory");

	/* Ensure directory has proper permissions */
	T_ASSERT_POSIX_SUCCESS(chmod(testdir, 0777), "chmod test directory");

	/* Build test file path */
	snprintf(test_file, sizeof(test_file), "%s/test_file", testdir);

	/* Create test file */
	fd = open(test_file, O_CREAT | O_EXCL | O_RDWR, 0666);
	T_ASSERT_POSIX_SUCCESS(fd, "create test file");
	close(fd);

	/* Set initial ownership to unprivileged user */
	T_ASSERT_POSIX_SUCCESS(chown(test_file, UNPRIVILEGED_UID, UNPRIVILEGED_GID),
	    "chown to unprivileged user");

	/* Ensure file has proper permissions for unprivileged user */
	T_ASSERT_POSIX_SUCCESS(chmod(test_file, 0666), "chmod test file");

	/* Verify dry run: unprivileged user can set setuid bit on their own file */
	T_ASSERT_POSIX_SUCCESS(seteuid(UNPRIVILEGED_UID), "seteuid to unprivileged");
	T_ASSERT_POSIX_SUCCESS(chmod(test_file, 0777 | S_ISUID), "chmod with setuid");
	T_ASSERT_POSIX_SUCCESS(seteuid(0), "seteuid back to root");

	struct stat sb;
	T_ASSERT_POSIX_SUCCESS(stat(test_file, &sb), "stat after chmod");
	T_ASSERT_TRUE(sb.st_mode & S_ISUID, "setuid bit should be set");

	/* Verify that chown to root clears setuid bit */
	T_ASSERT_POSIX_SUCCESS(chown(test_file, 0, 0), "chown to root");
	T_ASSERT_POSIX_SUCCESS(stat(test_file, &sb), "stat after chown");
	T_ASSERT_FALSE(sb.st_mode & S_ISUID, "setuid bit should be cleared after chown");

	/* Reset for race test */
	T_ASSERT_POSIX_SUCCESS(chown(test_file, UNPRIVILEGED_UID, UNPRIVILEGED_GID),
	    "reset ownership");

	/* Fork child process to run unprivileged chmod loop */
	child_pid = fork();
	T_ASSERT_POSIX_SUCCESS(child_pid, "fork");

	if (child_pid == 0) {
		/* Child process */
		T_ASSERT_POSIX_SUCCESS(seteuid(UNPRIVILEGED_UID), "child seteuid");
		unprivileged_thread_chmod();
		/* Not reached */
	}

	/* Parent process runs privileged chown loop */
	privileged_thread(child_pid);

	/* Kill child process */
	kill(child_pid, SIGKILL);
	waitpid(child_pid, NULL, 0);

	if (test_failed) {
		T_FAIL("Test detected race condition vulnerability");
	} else {
		T_PASS("No race condition detected after %d seconds", TEST_DURATION);
	}
}

T_DECL(setuid_race_setattrlist,
    "Test that setattrlist/chown race condition is fixed",
    T_META_TIMEOUT(TEST_DURATION + 5))
{
	int fd;
	pid_t child_pid;

	test_file[0] = '\0';
	test_failed = 0;
	test_running = 1;

	T_ATEND(cleanup);

	T_LOG("Starting setattrlist setuid race test for %d seconds", TEST_DURATION);

	/* Create temporary directory for test file */
	snprintf(template, sizeof(template), "%s/setuid_race_setattrlist-XXXXXX", dt_tmpdir());
	T_ASSERT_NOTNULL((testdir = mkdtemp(template)), "Creating test directory");

	/* Ensure directory has proper permissions */
	T_ASSERT_POSIX_SUCCESS(chmod(testdir, 0777), "chmod test directory");

	/* Build test file path */
	snprintf(test_file, sizeof(test_file), "%s/test_file", testdir);

	/* Create test file */
	fd = open(test_file, O_CREAT | O_EXCL | O_RDWR, 0666);
	T_ASSERT_POSIX_SUCCESS(fd, "create test file");
	close(fd);

	/* Set initial ownership to unprivileged user */
	T_ASSERT_POSIX_SUCCESS(chown(test_file, UNPRIVILEGED_UID, UNPRIVILEGED_GID),
	    "chown to unprivileged user");

	/* Ensure file has proper permissions for unprivileged user */
	T_ASSERT_POSIX_SUCCESS(chmod(test_file, 0666), "chmod test file");

	/* Verify dry run: unprivileged user can set setuid bit on their own file */
	T_ASSERT_POSIX_SUCCESS(seteuid(UNPRIVILEGED_UID), "seteuid to unprivileged");

	struct attrlist attrlist = {};
	struct {
		uint32_t mode;
	} attrbuf;

	attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrlist.commonattr = ATTR_CMN_ACCESSMASK;
	attrbuf.mode = 0777 | S_ISUID;

	T_ASSERT_POSIX_SUCCESS(setattrlist(test_file, &attrlist, &attrbuf, sizeof(attrbuf), 0),
	    "setattrlist with setuid");
	T_ASSERT_POSIX_SUCCESS(seteuid(0), "seteuid back to root");

	struct stat sb;
	T_ASSERT_POSIX_SUCCESS(stat(test_file, &sb), "stat after setattrlist");
	T_ASSERT_TRUE(sb.st_mode & S_ISUID, "setuid bit should be set");

	/* Verify that chown to root clears setuid bit */
	T_ASSERT_POSIX_SUCCESS(chown(test_file, 0, 0), "chown to root");
	T_ASSERT_POSIX_SUCCESS(stat(test_file, &sb), "stat after chown");
	T_ASSERT_FALSE(sb.st_mode & S_ISUID, "setuid bit should be cleared after chown");

	/* Reset for race test */
	T_ASSERT_POSIX_SUCCESS(chown(test_file, UNPRIVILEGED_UID, UNPRIVILEGED_GID),
	    "reset ownership");

	/* Fork child process to run unprivileged setattrlist loop */
	child_pid = fork();
	T_ASSERT_POSIX_SUCCESS(child_pid, "fork");

	if (child_pid == 0) {
		/* Child process */
		T_ASSERT_POSIX_SUCCESS(seteuid(UNPRIVILEGED_UID), "child seteuid");
		unprivileged_thread_setattrlist();
		/* Not reached */
	}

	/* Parent process runs privileged chown loop */
	privileged_thread(child_pid);

	/* Kill child process */
	kill(child_pid, SIGKILL);
	waitpid(child_pid, NULL, 0);

	if (test_failed) {
		T_FAIL("Test detected race condition vulnerability with setattrlist");
	} else {
		T_PASS("No race condition detected with setattrlist after %d seconds", TEST_DURATION);
	}
}
