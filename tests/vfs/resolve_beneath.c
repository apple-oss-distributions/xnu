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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/xattr.h>
#include <sys/clonefile.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include <darwintest.h>
#include <darwintest/utils.h>

static char template[MAXPATHLEN];
static char *testdir = NULL;
static int testdir_fd = -1, test_fd = -1;

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
setup(const char *dirname)
{
	int fd;

	testdir_fd = test_fd = -1;

	/* Create test root directory */
	snprintf(template, sizeof(template), "%s/%s-XXXXXX", dt_tmpdir(), dirname);
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
		rmdir(testdir);
	}
}

T_DECL(resolve_beneath_open,
    "test open()/openat() using the O_RESOLVE_BENEATH flag")
{
	int fd, root_fd;
	char path[MAXPATHLEN];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_open");

	T_ASSERT_POSIX_SUCCESS((root_fd = open("/", O_SEARCH, 0777)), "Opening the root directory");

	T_SETUPEND;

	T_LOG("Testing the openat() syscall using O_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS((fd = openat(test_fd, "inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 1: File within the directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "symlink", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "../outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

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
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "parent_symlink/outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "circular_symlink", O_RDONLY | O_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "../test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(openat(test_fd, "symlink_absolute/test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	/* Test Case 11: Absolute path relative to the root directory */
	T_EXPECT_POSIX_FAILURE(openat(root_fd, "/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 11: Absolute path relative to the root directory");

	/* Test Case 12: Path can not escape outside of the root directory using dotdot */
	T_EXPECT_POSIX_FAILURE((fd = openat(root_fd, "../private", O_RESOLVE_BENEATH)), ENOTCAPABLE, "Test Case 12: Path can not escape outside of the root directory using dotdot");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	T_LOG("Testing the open() syscall using O_RESOLVE_BENEATH");

	/* Test Case 13: Open a file within the directory */
	T_EXPECT_POSIX_SUCCESS((fd = open("inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 13: Open a file within the directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 14: Attempt to open a file using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(open("symlink", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 14: Attempt to open a file using a symlink pointing outside");

	/* Test Case 15: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(open("../outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 15: Attempt to open a file using \"..\" to navigate outside");

	/* Test Case 16: Open a file within a nested directory */
	T_EXPECT_POSIX_SUCCESS((fd = open("nested/nested_file.txt", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 16: Open a file within a nested directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 17: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS((fd = open("symlink_to_nested", O_RDONLY | O_RESOLVE_BENEATH, 0777)), "Test Case 17: Symlink to a file within the same directory");
	if (fd >= 0) {
		close(fd);
	}

	/* Test Case 18: Attempt to open a file using an absolute path */
	T_EXPECT_POSIX_FAILURE(open("/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 18: Attempt to open a file using an absolute path");

	/* Test Case 19: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(open("parent_symlink/outside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 19: Valid symlink to parent directory");

	/* Test Case 20: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(open("circular_symlink", O_RDONLY | O_RESOLVE_BENEATH), ELOOP, "Test Case 20: Circular symlink within directory");

	/* Test Case 21: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(open("../test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 21: Path can not escape outside at any point of the resolution");

	/* Test Case 22: Attempt to open a file using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(open("symlink_absolute/test_dir/inside_file.txt", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 22: Attempt to open a file using a symlink pointing to absolute path");

	/* Test Case 23: Path can not escape outside at any point of the resolution using absolute path */
	snprintf(path, sizeof(path), "%s/%s", testdir, INSIDE_FILE);
	T_EXPECT_POSIX_FAILURE(open(path, O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 23: Path can not escape outside at any point of the resolution using absolute path");

	T_EXPECT_POSIX_SUCCESS(close(root_fd), "Closing the root directory");
}

T_DECL(resolve_beneath_faccessat,
    "test faccessat() using the AT_RESOLVE_BENEATH flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_faccessat");

	T_SETUPEND;

	T_LOG("Testing the faccessat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(faccessat(test_fd, "inside_file.txt", R_OK, AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "symlink", R_OK, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "../outside_file.txt", R_OK, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(faccessat(test_fd, "nested/nested_file.txt", R_OK, AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(faccessat(test_fd, "symlink_to_nested", R_OK, AT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "/etc/passwd", R_OK, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "parent_symlink/outside_file.txt", R_OK, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "circular_symlink", R_OK, AT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "../test_dir/inside_file.txt", R_OK, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(faccessat(test_fd, "symlink_absolute/test_dir/inside_file.txt", R_OK, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");
}

T_DECL(resolve_beneath_fstatat,
    "test fstatat() using the AT_RESOLVE_BENEATH flag")
{
	struct stat buf;

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_fstatat");

	T_SETUPEND;

	T_LOG("Testing the fstatat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(fstatat(test_fd, "inside_file.txt", &buf, AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "symlink", &buf, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "../outside_file.txt", &buf, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(fstatat(test_fd, "nested/nested_file.txt", &buf, AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(fstatat(test_fd, "symlink_to_nested", &buf, AT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "/etc/passwd", &buf, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "parent_symlink/outside_file.txt", &buf, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "circular_symlink", &buf, AT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "../test_dir/inside_file.txt", &buf, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(fstatat(test_fd, "symlink_absolute/test_dir/inside_file.txt", &buf, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");
}

T_DECL(resolve_beneath_fchmodat,
    "test fchmodat() using the AT_RESOLVE_BENEATH flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_fchmodat");

	T_SETUPEND;

	T_LOG("Testing the fchmodat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(fchmodat(test_fd, "inside_file.txt", S_IRWXU, AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "symlink", S_IRWXU, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "../outside_file.txt", S_IRWXU, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(fchmodat(test_fd, "nested/nested_file.txt", S_IRWXU, AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(fchmodat(test_fd, "symlink_to_nested", S_IRWXU, AT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "/etc/passwd", S_IRWXU, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "parent_symlink/outside_file.txt", S_IRWXU, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "circular_symlink", S_IRWXU, AT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "../test_dir/inside_file.txt", S_IRWXU, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(fchmodat(test_fd, "symlink_absolute/test_dir/inside_file.txt", S_IRWXU, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");
}

T_DECL(resolve_beneath_fchownat,
    "test fchownat() using the AT_RESOLVE_BENEATH flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_fchownat");

	T_SETUPEND;

	T_LOG("Testing the fchownat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(fchownat(test_fd, "inside_file.txt", geteuid(), getgid(), AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "symlink", geteuid(), getgid(), AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "../outside_file.txt", geteuid(), getgid(), AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(fchownat(test_fd, "nested/nested_file.txt", geteuid(), getgid(), AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(fchownat(test_fd, "symlink_to_nested", geteuid(), getgid(), AT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "/etc/passwd", geteuid(), getgid(), AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "parent_symlink/outside_file.txt", geteuid(), getgid(), AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "circular_symlink", geteuid(), getgid(), AT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "../test_dir/inside_file.txt", geteuid(), getgid(), AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(fchownat(test_fd, "symlink_absolute/test_dir/inside_file.txt", geteuid(), getgid(), AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");
}

T_DECL(resolve_beneath_linkat,
    "test linkat() using the AT_RESOLVE_BENEATH flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_linkat");

	T_SETUPEND;

	T_LOG("Testing the linkat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(linkat(test_fd, "inside_file.txt", test_fd, "inside_file_2.txt", AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");
	unlinkat(test_fd, "inside_file_2.txt", 0);

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(linkat(test_fd, "symlink/.", test_fd, "inside_file_2.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(linkat(test_fd, "inside_file.txt", test_fd, "../outside_file.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(linkat(test_fd, "nested/nested_file.txt", test_fd, "nested/nested_file_2.txt", AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(linkat(test_fd, "symlink_to_nested", test_fd, "nested/nested_file_2.txt", AT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(linkat(test_fd, "/etc/passwd", test_fd, "inside_file_2.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");
}

T_DECL(resolve_beneath_unlinkat,
    "test unlinkat() using the AT_RESOLVE_BENEATH flag")
{
	int fd;

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_unlinkat");

	T_SETUPEND;

	T_LOG("Testing the unlinkat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(unlinkat(test_fd, "inside_file.txt", AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");
	if ((fd = openat(testdir_fd, INSIDE_FILE, O_CREAT | O_RDWR, 0777)) < 0) {
		T_FAIL("Unable to recreate %s", INSIDE_FILE);
	}
	close(fd);

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_SUCCESS(unlinkat(test_fd, "symlink", AT_RESOLVE_BENEATH), "Test Case 2: File using a symlink pointing outside");
	if (symlinkat(SYMLINK_FROM, testdir_fd, SYMLINK) < 0) {
		T_FAIL("Unable to recreate %s", INSIDE_FILE);
	}

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(unlinkat(test_fd, "../outside_file.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(unlinkat(test_fd, "nested/nested_file.txt", AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");
	if ((fd = openat(testdir_fd, NESTED_FILE, O_CREAT | O_RDWR, 0777)) < 0) {
		T_FAIL("Unable to recreate %s", NESTED_FILE);
	}
	close(fd);

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(unlinkat(test_fd, "symlink_to_nested", AT_RESOLVE_BENEATH), "Test Case 5: Symlink //to a file within the same directory");
	if (symlinkat(SYMLINK_TO_NESTED_FROM, testdir_fd, SYMLINK_TO_NESTED) < 0) {
		T_FAIL("Unable to recreate %s", SYMLINK_TO_NESTED);
	}

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(unlinkat(test_fd, "/etc/passwd", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(unlinkat(test_fd, "parent_symlink/outside_file.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_SUCCESS(unlinkat(test_fd, "circular_symlink", AT_RESOLVE_BENEATH), "Test Case 8: Circular symlink within directory");
	if (symlinkat(CIRCULAR_SYMLINK_FROM, testdir_fd, CIRCULAR_SYMLINK) < 0) {
		T_FAIL("Unable to recreate %s", CIRCULAR_SYMLINK);
	}

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(unlinkat(test_fd, "../test_dir/inside_file.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(unlinkat(test_fd, "symlink_absolute/test_dir/inside_file.txt", AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");
}

T_DECL(resolve_beneath_utimensat,
    "test utimensat() using the AT_RESOLVE_BENEATH flag")
{
	static const struct timespec tptr[] = {
		{ 0x12345678, 987654321 },
		{ 0x15263748, 123456789 },
	};

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_utimensat");

	T_SETUPEND;

	T_LOG("Testing the utimensat() syscall using AT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(utimensat(test_fd, "inside_file.txt", tptr, AT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "symlink", tptr, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "../outside_file.txt", tptr, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(utimensat(test_fd, "nested/nested_file.txt", tptr, AT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(utimensat(test_fd, "symlink_to_nested", tptr, AT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "/etc/passwd", tptr, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "parent_symlink/outside_file.txt", tptr, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "circular_symlink", tptr, AT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "../test_dir/inside_file.txt", tptr, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(utimensat(test_fd, "symlink_absolute/test_dir/inside_file.txt", tptr, AT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");
}

T_DECL(resolve_beneath_getxattr,
    "test getxattr()/fgetxattr() using the XATTR_RESOLVE_BENEATH flag")
{
	char xattr_buff[100];
	const char *xattr = "test1234";
	size_t xattr_len = strlen(xattr);

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_getxattr");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	/* Setting extended attributes */
	T_ASSERT_POSIX_SUCCESS(setxattr("inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting extended attributes to inside_file.txt");
	T_ASSERT_POSIX_SUCCESS(setxattr("../outside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting extended attributes to outside_file.txt");
	T_ASSERT_POSIX_SUCCESS(setxattr("nested/nested_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting extended attributes to nested_file.txt");

	T_SETUPEND;

	T_LOG("Testing the getxattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(getxattr("inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(getxattr("symlink", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(getxattr("../outside_file.txt", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(getxattr("nested/nested_file.txt", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(getxattr("symlink_to_nested", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(getxattr("/etc/passwd", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(getxattr("parent_symlink/outside_file.txt", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(getxattr("circular_symlink", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(getxattr("../test_dir/inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(getxattr("symlink_absolute/test_dir/inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	T_LOG("Testing the fgetxattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 11: Verifying that fgetxattr() fails with EINVAL */
	T_EXPECT_POSIX_FAILURE(fgetxattr(test_fd, XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, XATTR_RESOLVE_BENEATH), EINVAL, "Test Case 11: Verifying that fgetxattr() fails with EINVAL");
}

T_DECL(resolve_beneath_setxattr,
    "test setxattr()/fsetxattr() using the XATTR_RESOLVE_BENEATH flag")
{
	const char *xattr = "test1234";
	size_t xattr_len = strlen(xattr);

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_setxattr");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	T_SETUPEND;

	T_LOG("Testing the setxattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(setxattr("inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(setxattr("symlink", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(setxattr("../outside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(setxattr("nested/nested_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(setxattr("symlink_to_nested", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(setxattr("/etc/passwd", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(setxattr("parent_symlink/outside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(setxattr("circular_symlink", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(setxattr("../test_dir/inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(setxattr("symlink_absolute/test_dir/inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	T_LOG("Testing the fsetxattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 11: Verifying that fsetxattr() fails with EINVAL */
	T_EXPECT_POSIX_FAILURE(fsetxattr(test_fd, XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, XATTR_RESOLVE_BENEATH), EINVAL, "Test Case 11: Verifying that fsetxattr() fails with EINVAL");
}

T_DECL(resolve_beneath_listxattr,
    "test listxattr()/flistxattr() using the XATTR_RESOLVE_BENEATH flag")
{
	char xattr_buff[100];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_listxattr");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	T_SETUPEND;

	T_LOG("Testing the listxattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(listxattr("inside_file.txt", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(listxattr("symlink", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(listxattr("../outside_file.txt", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(listxattr("nested/nested_file.txt", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(listxattr("symlink_to_nested", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(listxattr("/etc/passwd", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(listxattr("parent_symlink/outside_file.txt", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(listxattr("circular_symlink", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(listxattr("../test_dir/inside_file.txt", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(listxattr("symlink_absolute/test_dir/inside_file.txt", xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	T_LOG("Testing the flistxattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 11: Verifying that flistxattr() fails with EINVAL */
	T_EXPECT_POSIX_FAILURE(flistxattr(test_fd, xattr_buff, sizeof(xattr_buff), XATTR_RESOLVE_BENEATH), EINVAL, "Test Case 11: Verifying that flistxattr() fails with EINVAL");
}

T_DECL(resolve_beneath_removexattr,
    "test removexattr()/fremovexattr() using the XATTR_RESOLVE_BENEATH flag")
{
	const char *xattr = "test1234";
	size_t xattr_len = strlen(xattr);

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_removexattr");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	/* Setting extended attributes */
	T_ASSERT_POSIX_SUCCESS(setxattr("inside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting extended attributes to inside_file.txt");
	T_ASSERT_POSIX_SUCCESS(setxattr("../outside_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting extended attributes to outside_file.txt");
	T_ASSERT_POSIX_SUCCESS(setxattr("nested/nested_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting extended attributes to nested_file.txt");

	T_SETUPEND;

	T_LOG("Testing the removexattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(removexattr("inside_file.txt", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(removexattr("symlink", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(removexattr("../outside_file.txt", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(removexattr("nested/nested_file.txt", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	if (setxattr("nested/nested_file.txt", XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0) < 0) {
		T_FAIL("Unable to setxattr to nested_file.txt");
	}

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(removexattr("symlink_to_nested", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(removexattr("/etc/passwd", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(removexattr("parent_symlink/outside_file.txt", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(removexattr("circular_symlink", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(removexattr("../test_dir/inside_file.txt", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(removexattr("symlink_absolute/test_dir/inside_file.txt", XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	T_LOG("Testing the fremovexattr() syscall using XATTR_RESOLVE_BENEATH");

	/* Test Case 11: Verifying that fremovexattr() fails with EINVAL */
	T_EXPECT_POSIX_FAILURE(fremovexattr(test_fd, XATTR_RESOURCEFORK_NAME, XATTR_RESOLVE_BENEATH), EINVAL, "Test Case 11: Verifying that fremovexattr() fails with EINVAL");
}

T_DECL(resolve_beneath_clonefile,
    "test clonefile()/clonefileat()/fclonefileat() using the CLONE_RESOLVE_BENEATH flag")
{
	int fd;
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_clonefile");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	/* Open test file */
	T_ASSERT_POSIX_SUCCESS((fd = open("inside_file.txt", O_RDWR, 0777)), "Opening %s", INSIDE_FILE);

	T_SETUPEND;

	T_LOG("Testing the clonefile() syscall using CLONE_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(clonefile("inside_file.txt", "inside_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 1: File within the directory");
	unlink("inside_file_2.txt");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(clonefile("symlink", "inside_file_2.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(clonefile("inside_file.txt", "../outside_file.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(clonefile("nested/nested_file.txt", "nested/nested_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(clonefile("symlink_to_nested", "nested/nested_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(clonefile("/etc/passwd", "inside_file_2.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	T_LOG("Testing the clonefileat() syscall using CLONE_RESOLVE_BENEATH");

	/* Test Case 7: File within the directory */
	T_EXPECT_POSIX_SUCCESS(clonefileat(test_fd, "inside_file.txt", test_fd, "inside_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 7: File within the directory");
	unlinkat(test_fd, "inside_file_2.txt", 0);

	/* Test Case 8: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(clonefileat(test_fd, "symlink", test_fd, "inside_file_2.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 8: File using a symlink pointing outside");

	/* Test Case 9: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(clonefileat(test_fd, "inside_file.txt", test_fd, "../outside_file.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: File using \"..\" to navigate outside");

	/* Test Case 10: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(clonefileat(test_fd, "nested/nested_file.txt", test_fd, "nested/nested_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 10: File within a nested directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 11: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(clonefileat(test_fd, "symlink_to_nested", test_fd, "nested/nested_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 11: Symlink to a file within the same directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 12: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(clonefileat(test_fd, "/etc/passwd", test_fd, "inside_file_2.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 12: File using an absolute path");

	T_LOG("Testing the fclonefileat() syscall using CLONE_RESOLVE_BENEATH");

	/* Test Case 13: File within the directory */
	T_EXPECT_POSIX_SUCCESS(fclonefileat(fd, test_fd, "inside_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 13: File within the directory");
	unlinkat(test_fd, "inside_file_2.txt", 0);

	/* Test Case 14: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(fclonefileat(fd, test_fd, "symlink_absolute/test_dir/inside_file.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 14: File using a symlink pointing outside");

	/* Test Case 15: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(fclonefileat(fd, test_fd, "../outside_file.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 15: File using \"..\" to navigate outside");

	/* Test Case 16: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(fclonefileat(fd, test_fd, "nested/nested_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 16: File within a nested directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 17: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(fclonefileat(fd, test_fd, "nested/nested_file_2.txt", CLONE_RESOLVE_BENEATH), "Test Case 17: Symlink to a file within the same directory");
	unlinkat(test_fd, "nested/nested_file_2.txt", 0);

	/* Test Case 18: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(fclonefileat(fd, test_fd, "/etc/inside_file_2.txt", CLONE_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 18: File using an absolute path");

	T_EXPECT_POSIX_SUCCESS(close(fd), "Closing %s", INSIDE_FILE);
}

T_DECL(resolve_beneath_renamex_np,
    "test renamex_np()/renameatx_np() using the RENAME_RESOLVE_BENEATH flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_renamex_np");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	T_SETUPEND;

	T_LOG("Testing the renamex_np() syscall using RENAME_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(renamex_np("inside_file.txt", "inside_file_2.txt", RENAME_RESOLVE_BENEATH), "Test Case 1: File within the directory");
	if (renamex_np("inside_file_2.txt", "inside_file.txt", 0)) {
		T_FAIL("Unable to rename inside_file_2.txt to inside_file.txt");
	}

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(renamex_np("symlink/.", "inside_file_2.txt", RENAME_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(renamex_np("inside_file.txt", "../outside_file.txt", RENAME_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(renamex_np("nested/nested_file.txt", "nested/nested_file_2.txt", RENAME_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");
	if (renamex_np("nested/nested_file_2.txt", "nested/nested_file.txt", 0)) {
		T_FAIL("Unable to rename nested/nested_file_2.txt to nested/nested_file.txt");
	}

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(renamex_np("symlink_to_nested", "nested/nested_file_2.txt", RENAME_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");
	if (renamex_np("nested/nested_file_2.txt", "symlink_to_nested", 0)) {
		T_FAIL("Unable to rename nested/nested_file_2.txt to symlink_to_nested");
	}

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(renamex_np("/etc/passwd", "inside_file_2.txt", RENAME_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	T_LOG("Testing the renameatx_np() syscall using RENAME_RESOLVE_BENEATH");

	/* Test Case 7: File within the directory */
	T_EXPECT_POSIX_SUCCESS(renameatx_np(test_fd, "inside_file.txt", test_fd, "inside_file_2.txt", RENAME_RESOLVE_BENEATH), "Test Case 7: File within the directory");
	if (renamex_np("inside_file_2.txt", "inside_file.txt", 0)) {
		T_FAIL("Unable to rename inside_file_2.txt to inside_file.txt");
	}

	/* Test Case 8: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(renameatx_np(test_fd, "symlink/.", test_fd, "inside_file_2.txt", RENAME_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 8: File using a symlink pointing outside");

	/* Test Case 9: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(renameatx_np(test_fd, "inside_file.txt", test_fd, "../outside_file.txt", RENAME_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: File using \"..\" to navigate outside");

	/* Test Case 10: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(renameatx_np(test_fd, "nested/nested_file.txt", test_fd, "nested/nested_file_2.txt", RENAME_RESOLVE_BENEATH), "Test Case 10: File within a nested directory");
	if (renamex_np("nested/nested_file_2.txt", "nested/nested_file.txt", 0)) {
		T_FAIL("Unable to rename nested/nested_file_2.txt to nested/nested_file.txt");
	}

	/* Test Case 11: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(renameatx_np(test_fd, "symlink_to_nested", test_fd, "nested/nested_file_2.txt", RENAME_RESOLVE_BENEATH), "Test Case 11: Symlink to a file within the same directory");
	if (renamex_np("nested/nested_file_2.txt", "symlink_to_nested", 0)) {
		T_FAIL("Unable to rename nested/nested_file_2.txt to symlink_to_nested");
	}

	/* Test Case 12: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(renameatx_np(test_fd, "/etc/passwd", test_fd, "inside_file_2.txt", RENAME_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 12: File using an absolute path");
}

T_DECL(resolve_beneath_getattrlist,
    "test getattrlist()/fgetattrlist()/getattrlistat() using the FSOPT_RESOLVE_BENEATH flag")
{
	int fd;

	struct myattrbuf {
		uint32_t length;
		attribute_set_t returned_attrs;
		vol_attributes_attr_t vol_attributes;
		attrreference_t fstypename_ref;
		uint32_t fssubtype;
		char fstypename[MFSTYPENAMELEN];
	} attrbuf;

	struct attrlist attrs = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_RETURNED_ATTRS,
		/*
		 * Request ATTR_VOL_ATTRIBUTES to ensure that
		 * ATTR_VOL_FSTYPENAME and ATTR_VOL_FSSUBTYPE
		 * are packed into the buffer *after*.
		 */
		.volattr = ATTR_VOL_INFO | ATTR_VOL_ATTRIBUTES |
	    ATTR_VOL_FSTYPENAME | ATTR_VOL_FSSUBTYPE,
	};

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_beneath_getattrlist");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	/* Open test file */
	T_ASSERT_POSIX_SUCCESS((fd = open("inside_file.txt", O_RDWR, 0777)), "Opening %s", INSIDE_FILE);

	T_SETUPEND;

	T_LOG("Testing the getattrlist() syscall using FSOPT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(getattrlist("inside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(getattrlist("symlink", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(getattrlist("../outside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(getattrlist("nested/nested_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(getattrlist("symlink_to_nested", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(getattrlist("/etc/passwd", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(getattrlist("parent_symlink/outside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(getattrlist("circular_symlink", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(getattrlist("../test_dir/inside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(getattrlist("symlink_absolute/test_dir/inside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	T_LOG("Testing the fgetattrlist() syscall using FSOPT_RESOLVE_BENEATH");

	/* Test Case 11: fgetattrlist() syscall using FSOPT_RESOLVE_BENEATH */
	T_EXPECT_POSIX_SUCCESS(fgetattrlist(fd, &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 11: fgetattrlist() syscall using FSOPT_RESOLVE_BENEATH");

	T_LOG("Testing the getattrlistat() syscall using FSOPT_RESOLVE_BENEATH");

	/* Test Case 12: File within the directory */
	T_EXPECT_POSIX_SUCCESS(getattrlistat(test_fd, "inside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 12: File within the directory");

	/* Test Case 13: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "symlink", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 13: File using a symlink pointing outside");

	/* Test Case 14: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "../outside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 14: File using \"..\" to navigate outside");

	/* Test Case 15: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(getattrlistat(test_fd, "nested/nested_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 15: File within a nested directory");

	/* Test Case 16: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(getattrlistat(test_fd, "symlink_to_nested", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), "Test Case 16: Symlink to a file within the same directory");

	/* Test Case 17: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "/etc/passwd", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 17: File using an absolute path");

	/* Test Case 18: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "parent_symlink/outside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 18: Valid symlink to parent directory");

	/* Test Case 19: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "circular_symlink", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ELOOP, "Test Case 19: Circular symlink within directory");

	/* Test Case 20: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "../test_dir/inside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 20: Path can not escape outside at any point of the resolution");

	/* Test Case 21: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(getattrlistat(test_fd, "symlink_absolute/test_dir/inside_file.txt", &attrs, &attrbuf, sizeof(attrbuf), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 21: File using a symlink pointing to absolute path");

	T_EXPECT_POSIX_SUCCESS(close(fd), "Closing %s", INSIDE_FILE);
}

T_DECL(resolve_beneath_setattrlist,
    "test setattrlist()/fsetattrlist()/setattrlistat() using the FSOPT_RESOLVE_BENEATH flag")
{
	int fd;
	int flags;
	struct attrlist attrlist;

	T_SETUPBEGIN;

	flags = 0;
	memset(&attrlist, 0, sizeof(attrlist));
	attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrlist.commonattr = ATTR_CMN_FLAGS;

	T_ATEND(cleanup);
	setup("resolve_beneath_setattrlist");

	/* Changing current directory to the test directory */
	T_ASSERT_POSIX_SUCCESS(fchdir(test_fd), "Changing directory to %s/%s", testdir, TEST_DIR);

	/* Open test file */
	T_ASSERT_POSIX_SUCCESS((fd = open("inside_file.txt", O_RDWR, 0777)), "Opening %s", INSIDE_FILE);

	T_SETUPEND;

	T_LOG("Testing the setattrlist() syscall using FSOPT_RESOLVE_BENEATH");

	/* Test Case 1: File within the directory */
	T_EXPECT_POSIX_SUCCESS(setattrlist("inside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 1: File within the directory");

	/* Test Case 2: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(setattrlist("symlink", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 2: File using a symlink pointing outside");

	/* Test Case 3: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(setattrlist("../outside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 3: File using \"..\" to navigate outside");

	/* Test Case 4: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(setattrlist("nested/nested_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 4: File within a nested directory");

	/* Test Case 5: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(setattrlist("symlink_to_nested", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 5: Symlink to a file within the same directory");

	/* Test Case 6: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(setattrlist("/etc/passwd", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 6: File using an absolute path");

	/* Test Case 7: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(setattrlist("parent_symlink/outside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 7: Valid symlink to parent directory");

	/* Test Case 8: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(setattrlist("circular_symlink", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ELOOP, "Test Case 8: Circular symlink within directory");

	/* Test Case 9: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(setattrlist("../test_dir/inside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 9: Path can not escape outside at any point of the resolution");

	/* Test Case 10: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(setattrlist("symlink_absolute/test_dir/inside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 10: File using a symlink pointing to absolute path");

	T_LOG("Testing the fsetattrlist() syscall using FSOPT_RESOLVE_BENEATH");

	/* Test Case 11: fsetattrlist() syscall using FSOPT_RESOLVE_BENEATH */
	T_EXPECT_POSIX_SUCCESS(fsetattrlist(fd, &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 11: fsetattrlist() syscall using FSOPT_RESOLVE_BENEATH");

	T_LOG("Testing the setattrlistat() syscall using FSOPT_RESOLVE_BENEATH");

	/* Test Case 12: File within the directory */
	T_EXPECT_POSIX_SUCCESS(setattrlistat(test_fd, "inside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 12: File within the directory");

	/* Test Case 13: File using a symlink pointing outside */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "symlink", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 13: File using a symlink pointing outside");

	/* Test Case 14: Attempt to open a file using ".." to navigate outside */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "../outside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 14: File using \"..\" to navigate outside");

	/* Test Case 15: File within a nested directory */
	T_EXPECT_POSIX_SUCCESS(setattrlistat(test_fd, "nested/nested_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 15: File within a nested directory");

	/* Test Case 16: Symlink to a file in a nested directory */
	T_EXPECT_POSIX_SUCCESS(setattrlistat(test_fd, "symlink_to_nested", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), "Test Case 16: Symlink to a file within the same directory");

	/* Test Case 17: File using an absolute path */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "/etc/passwd", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 17: File using an absolute path");

	/* Test Case 18: Valid symlink to parent directory */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "parent_symlink/outside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 18: Valid symlink to parent directory");

	/* Test Case 19: Circular symlink within directory */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "circular_symlink", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ELOOP, "Test Case 19: Circular symlink within directory");

	/* Test Case 20: Path can not escape outside at any point of the resolution */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "../test_dir/inside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 20: Path can not escape outside at any point of the resolution");

	/* Test Case 21: File using a symlink pointing to absolute path */
	T_EXPECT_POSIX_FAILURE(setattrlistat(test_fd, "symlink_absolute/test_dir/inside_file.txt", &attrlist, &flags, sizeof(flags), FSOPT_RESOLVE_BENEATH), ENOTCAPABLE, "Test Case 21: File using a symlink pointing to absolute path");

	T_EXPECT_POSIX_SUCCESS(close(fd), "Closing %s", INSIDE_FILE);
}

