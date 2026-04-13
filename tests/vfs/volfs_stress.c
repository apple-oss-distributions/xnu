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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o volfs_stress volfs_stress.c -g -Weverything */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fsgetpath_private.h>
#include <dispatch/dispatch.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define RUN_TEST      TARGET_OS_OSX
#define TEST_DURATION 10 /* seconds */

static char template[MAXPATHLEN];
static char *testdir = NULL;
static char file1[PATH_MAX], file2[PATH_MAX];

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_ENABLED(RUN_TEST),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	sleep(1);

	if (file1[0] != '\0') {
		unlink(file1);
	}
	if (file2[0] != '\0') {
		unlink(file2);
	}
	if (testdir && rmdir(testdir)) {
		T_FAIL("Unable to remove the test directory (%s)", testdir);
	}
}

T_DECL(volfs_stress,
    "Test that opening file via volfs path does not open the wrong file")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	int fd;
	struct stat st;
	char volfs_path[PATH_MAX];
	__block int timeout = 0;
	__block int error = 0;
	int64_t interval = TEST_DURATION * NSEC_PER_SEC;
	dispatch_queue_t queue;
	dispatch_source_t timeout_source;

	file1[0] = file2[0] = '\0';

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	T_ASSERT_NOTNULL((queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)), "Getting global queue");
	T_ASSERT_NOTNULL((timeout_source =  dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue)), "Creating dispatch source");

	dispatch_source_set_timer(timeout_source, dispatch_time(DISPATCH_TIME_NOW, interval), DISPATCH_TIME_FOREVER, 0);
	dispatch_source_set_event_handler(timeout_source, ^{
		timeout = 1;
		T_LOG("%d seconds timeout expired", TEST_DURATION);
	});

	snprintf(template, sizeof(template), "%s/volfs_stress-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	snprintf(file1, sizeof(file1), "%s/%s", testdir, "file1");
	snprintf(file2, sizeof(file2), "%s/%s", testdir, "file2");

	T_ASSERT_POSIX_SUCCESS((fd = open(file1, O_CREAT | O_RDWR, 0777)), "Creating file %s", file1);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", file1);

	T_ASSERT_POSIX_SUCCESS((fd = open(file2, O_CREAT | O_RDWR, 0777)), "Creating file %s", file2);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", file2);

	T_ASSERT_POSIX_SUCCESS(stat(file1, &st), "Calling stat() on %s", file1);

	snprintf(volfs_path, sizeof(volfs_path), "/.vol/%d/%llu", st.st_dev, st.st_ino);
	T_LOG("Testing using volfs path %s", volfs_path);

	T_SETUPEND;

	T_LOG("Running for %d seconds", TEST_DURATION);
	dispatch_resume(timeout_source);

	/* Replace between dir1 and dir2 */
	dispatch_async(queue, ^(void) {
		while (!timeout && !error) {
		        renamex_np(file1, file2, RENAME_SWAP);
		}
	});

	/* Query openbyid_np */
	while (!timeout && !error) {
		struct stat st_volfs;

		if ((error = stat(volfs_path, &st_volfs)) < 0) {
			T_FAIL("stat() failed");
			error = errno;
			break;
		}

		if (st_volfs.st_ino != st.st_ino) {
			T_FAIL("Wrong file opened! inode %llu", st_volfs.st_ino);
			error = EINVAL;
			break;
		}
	}

	T_ASSERT_POSIX_ZERO(error, "Test completed without error(s)");
}

T_DECL(volfs_path,
    "Test the volfs path lookup mechanism")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	int fd;
	struct stat st, st_file, st_testdir;
	char path[PATH_MAX];

	file1[0] = file2[0] = '\0';

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/volfs_path-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	snprintf(file1, sizeof(file1), "%s/%s", testdir, "file1");

	T_ASSERT_POSIX_SUCCESS((fd = open(file1, O_CREAT | O_RDWR, 0777)), "Creating file %s", file1);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", file1);

	T_ASSERT_POSIX_SUCCESS(stat(testdir, &st_testdir), "Calling stat() on %s", testdir);
	T_ASSERT_POSIX_SUCCESS(stat(file1, &st_file), "Calling stat() on %s", file1);

	T_LOG("%s stats: dev %d, ino %llu\n", testdir, st_testdir.st_dev, st_testdir.st_ino);
	T_LOG("%s stats: dev %d, ino %llu\n", file1, st_file.st_dev, st_file.st_ino);

	T_SETUPEND;

	/* Testing testdir */
	snprintf(path, sizeof(path), "/.vol/%d/%llu", st_testdir.st_dev, st_testdir.st_ino);
	T_EXPECT_POSIX_SUCCESS(stat(path, &st), "Calling stat() on %s", path);
	T_EXPECT_EQ(st.st_ino, st_testdir.st_ino, "Verifying identical inode numbers");

	/* Testing file1 */
	snprintf(path, sizeof(path), "/.vol/%d/%llu", st_file.st_dev, st_file.st_ino);
	T_EXPECT_POSIX_SUCCESS(stat(path, &st), "Calling stat() on %s", path);
	T_EXPECT_EQ(st.st_ino, st_file.st_ino, "Verifying identical inode numbers");

	/* Testing file1 using testdir volumeid and inode */
	snprintf(path, sizeof(path), "/.vol/%d/%llu/file1", st_testdir.st_dev, st_testdir.st_ino);
	T_EXPECT_POSIX_SUCCESS(stat(path, &st), "Calling stat() on %s", path);
	T_EXPECT_EQ(st.st_ino, st_file.st_ino, "Verifying identical inode numbers");
}
