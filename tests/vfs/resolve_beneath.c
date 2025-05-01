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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o resolve_beneath resolve_beneath.c -g -Weverything */

#include <darwintest.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/param.h>

#define TEMPLATE    "/private/var/tmp/resolve_beneath.XXXXXXXX"
static char template[] = TEMPLATE;
static char *testdir = NULL;
static int testdir_fd = -1, test_fd = -1;

#ifndef O_RESOLVE_BENEATH
#define O_RESOLVE_BENEATH       0x1000
#endif

#define TEST_DIR "test_dir"
#define NESTED_DIR "test_dir/nested"
#define OUTSIDE_FILE "outside_file.txt"
#define INSIDE_FILE "test_dir/inside_file.txt"
#define NESTED_FILE "test_dir/nested/nested_file.txt"
#define SYMLINK "test_dir/symlink"
#define SYMLINK_TO_NESTED "test_dir/symlink_to_nested"
#define PARENT_SYMLINK "test_dir/parent_symlink"
#define CIRCULAR_SYMLINK "test_dir/circular_symlink"
#define SYMLINK_ABSOLUTE "test_dir/symlink_absolute"

#define SYMLINK_FROM "../outside_file.txt"
#define SYMLINK_TO_NESTED_FROM "nested/nested_file.txt"
#define PARENT_SYMLINK_FROM ".."
#define CIRCULAR_SYMLINK_FROM "circular_symlink"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

static void
setup(void)
{
	int fd;

	testdir_fd = test_fd = -1;

	/* Create test root directory */
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root directory");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	/* Create test directories */
	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, TEST_DIR, 0777), "Creating %s/%s", testdir, TEST_DIR);
	T_ASSERT_POSIX_SUCCESS((test_fd = openat(testdir_fd, TEST_DIR, O_SEARCH, 0777)), "Opening test directory %s/%s", testdir, TEST_DIR);
	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, NESTED_DIR, 0777), "Creating %s/%s", testdir, NESTED_DIR);

	/* Create test files */
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, OUTSIDE_FILE, O_CREAT | O_RDWR, 0777)), "Creating file %s/%s", testdir, OUTSIDE_FILE);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", OUTSIDE_FILE);

	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, INSIDE_FILE, O_CREAT | O_RDWR, 0777)), "Creating file %s/%s", testdir, INSIDE_FILE);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", INSIDE_FILE);

	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, NESTED_FILE, O_CREAT | O_RDWR, 0777)), "Creating file %s/%s", testdir, NESTED_FILE);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", NESTED_FILE);

	/* Create test symlinks */
	T_ASSERT_POSIX_SUCCESS(symlinkat(SYMLINK_FROM, testdir_fd, SYMLINK), "Creating symlink %s/%s -> %s", testdir, SYMLINK, SYMLINK_FROM);
	T_ASSERT_POSIX_SUCCESS(symlinkat(SYMLINK_TO_NESTED_FROM, testdir_fd, SYMLINK_TO_NESTED), "Creating symlink %s/%s -> %s", testdir, SYMLINK_TO_NESTED, SYMLINK_TO_NESTED_FROM);
	T_ASSERT_POSIX_SUCCESS(symlinkat(PARENT_SYMLINK_FROM, testdir_fd, PARENT_SYMLINK), "Creating symlink %s/%s -> %s", testdir, PARENT_SYMLINK, PARENT_SYMLINK_FROM);
	T_ASSERT_POSIX_SUCCESS(symlinkat(CIRCULAR_SYMLINK_FROM, testdir_fd, CIRCULAR_SYMLINK), "Creating symlink %s/%s -> %s", testdir, CIRCULAR_SYMLINK, CIRCULAR_SYMLINK_FROM);
	T_ASSERT_POSIX_SUCCESS(symlinkat(testdir, testdir_fd, SYMLINK_ABSOLUTE), "Creating symlink %s/%s -> %s", testdir, SYMLINK_ABSOLUTE, testdir);
}

static void
cleanup(void)
{
	if (test_fd != -1) {
		close(test_fd);
	}
	if (testdir_fd != -1) {
		unlinkat(testdir_fd, SYMLINK_ABSOLUTE, 0);
		unlinkat(testdir_fd, CIRCULAR_SYMLINK, 0);
		unlinkat(testdir_fd, PARENT_SYMLINK, 0);
		unlinkat(testdir_fd, SYMLINK_TO_NESTED, 0);
		unlinkat(testdir_fd, SYMLINK, 0);
		unlinkat(testdir_fd, NESTED_FILE, 0);
		unlinkat(testdir_fd, NESTED_DIR, AT_REMOVEDIR);
		unlinkat(testdir_fd, INSIDE_FILE, 0);
		unlinkat(testdir_fd, TEST_DIR, AT_REMOVEDIR);
		unlinkat(testdir_fd, OUTSIDE_FILE, 0);

		close(testdir_fd);
		if (rmdir(testdir)) {
			T_FAIL("Unable to remove the test directory (%s)", testdir);
		}
	}
}

T_DECL(resolve_beneath_open,
    "test open()/openat() using the O_RESOLVE_BENEATH flag")
{
	int fd, root_fd;
	char path[MAXPATHLEN];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup();

	T_ASSERT_POSIX_SUCCESS((root_fd = open("/", O_SEARCH, 0777)), "Opening the root directory");

	T_SETUPEND;

	T_LOG("Testing the openat() syscall using O_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS((fd = openat(test_fd, "inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 1: File within the directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "symlink", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "../outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS((fd = openat(test_fd, "nested/nested_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 4: File within a nested directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS((fd = openat(test_fd, "symlink_to_nested", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 5: Symlink to a file within the same directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "parent_symlink/outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "circular_symlink", O_RDONLY | O_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "../test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "symlink_absolute/test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 10: File using a symlink pointing to absolute path");

	/* Test Case 11: Absolute path relative to the root directory */
	T_EXPECT_POSIX_FAILURE(openat(root_fd, "/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 11: Absolute path relative to the root directory");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	T_LOG("Testing the open() syscall using O_RESOLVE_BENEATH");

	/* Test Case 12: Open a file within the directory */
	T_EXPECT_POSIX_SUCCESS((fd = open("inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 12: Open a file within the directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 13: Attempt to open a file using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(open("symlink", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 13: Attempt to open a file using a symlink pointing outside");

	/* Test Case 14: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(open("../outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 14: Attempt to open a file using \"..\" to navigate outside");

	/* Test Case 15: Open a file within a nested directory */
	T_EXPECT_POSIX_SUCCESS((fd = open("nested/nested_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 15: Open a file within a nested directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 16: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS((fd = open("symlink_to_nested", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 16: Symlink to a file within the same directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 17: Attempt to open a file using an absolute path */
	T_EXPECT_POSIX_FAILURE(open("/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 17: Attempt to open a file using an absolute path");

	/* Test Case 18: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(open("parent_symlink/outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 18: Valid symlink to parent directory");

	/* Test Case 19: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(open("circular_symlink", O_RDONLY | O_RESOLVE_BENEATH), ELOOP, "Test Case 19: Circular symlink within directory");

	/* Test Case 20: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(open("../test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 20: Path can not escape outside at any point of the resolution");

	/* Test Case 21: Attempt to open a file using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(open("symlink_absolute/test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 21: Attempt to open a file using a symlink pointing to absolute path");

	/* Test Case 22: Path can not escape outside at any point of the resolution using absolute path */
	snprintf(path, sizeof(path), "%s/%s", testdir, INSIDE_FILE);
	T_EXPECT_POSIX_FAILURE(open(path, O_RDONLY | O_RESOLVE_BENEATH), EACCES, "Test Case 22: Path can not escape outside at any point of the resolution using absolute path");

	T_EXPECT_POSIX_SUCCESS(close(root_fd), "Closing the root directory");
}
