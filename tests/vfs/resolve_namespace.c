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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o resolve_namespace resolve_namespace.c */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/paths.h>
#include <sys/syslimits.h>
#include <sys/mount.h>
#include <sys/param.h>

#include <darwintest.h>
#include <darwintest/utils.h>

static char template[MAXPATHLEN];
static char testdir_path[MAXPATHLEN + 1];
static char *testdir = NULL;
static int testdir_fd = -1, test_fd = -1;

#define TEST_DIR       "test_dir"
#define FILE           "test_dir/file.txt"
#define FILE2          "test_dir/file2.txt"
#define FILE3          "test_dir/file3.txt"
#define DIR_SYMLINK    "test_dir/dir_symlink"
#define FILE_SYMLINK   "test_dir/dir_symlink/file_symlink.txt"
#define FILE_SYMLINK_2 "test_dir/dir_symlink/file_symlink_2.txt"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (test_fd != -1) {
		close(test_fd);
	}
	if (testdir_fd != -1) {
		unlinkat(testdir_fd, FILE_SYMLINK, 0);
		unlinkat(testdir_fd, FILE_SYMLINK_2, 0);
		unlinkat(testdir_fd, FILE, 0);
		unlinkat(testdir_fd, DIR_SYMLINK, 0);
		unlinkat(testdir_fd, TEST_DIR, AT_REMOVEDIR);

		close(testdir_fd);
		if (rmdir(testdir)) {
			T_FAIL("Unable to remove the test directory (%s)", testdir);
		}
	}
}

static void
setup(const char *dirname)
{
	int fd;
	char symlink_path[PATH_MAX];

	testdir_fd = test_fd = -1;

	/* Create test root directory */
	snprintf(template, sizeof(template), "%s/%s-XXXXXX", dt_tmpdir(), dirname);
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root directory");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);
	T_ASSERT_POSIX_SUCCESS(fcntl(testdir_fd, F_GETPATH, testdir_path), "Calling fcntl() to get the path");

	/* Create test directories */
	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, TEST_DIR, 0777), "Creating %s/%s", testdir_path, TEST_DIR);
	T_ASSERT_POSIX_SUCCESS((test_fd = openat(testdir_fd, TEST_DIR, O_SEARCH, 0777)), "Opening test directory %s/%s", testdir_path, TEST_DIR);

	/* Create the test files */
	snprintf(symlink_path, sizeof(symlink_path), "%s/%s/../", testdir_path, TEST_DIR);
	T_ASSERT_POSIX_SUCCESS(symlinkat(symlink_path, testdir_fd, DIR_SYMLINK), "Creating symbolic link %s ---> %s", DIR_SYMLINK, symlink_path);
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_CREAT | O_RDWR, 0777)), "Creating %s", FILE);
	close(fd);
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE_SYMLINK, O_CREAT | O_RDWR, 0777)), "Creating %s", FILE_SYMLINK);
	close(fd);
}

T_DECL(resolve_namespace_nofollow,
    "Test the RESOLVE_NOFOLLOW_ANY prefix-path")
{
	int fd;

	char file_nofollow[PATH_MAX];
	char symlink_nofollow[PATH_MAX];
	char symlink_resolve[PATH_MAX];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_namespace_nofollow");

	/* Setup file names */
	snprintf(file_nofollow, sizeof(file_nofollow), "/.nofollow/%s/%s", testdir_path, FILE);
	snprintf(symlink_nofollow, sizeof(symlink_nofollow), "/.nofollow/%s/%s", testdir_path, FILE_SYMLINK);
	snprintf(symlink_resolve, sizeof(symlink_resolve), "/.resolve/%d/%s/%s", RESOLVE_NOFOLLOW_ANY, testdir_path, FILE_SYMLINK_2);

	T_SETUPEND;

	T_EXPECT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_NOFOLLOW_ANY)), "Testing openat(O_NOFOLLOW_ANY) using path with no symlinks");
	close(fd);

	T_EXPECT_POSIX_SUCCESS((fd = open(file_nofollow, O_NOFOLLOW_ANY)), "Testing open() using path with no symlinks and '.nofollow' prefix");
	close(fd);

	T_EXPECT_POSIX_FAILURE((fd = openat(testdir_fd, FILE_SYMLINK, O_NOFOLLOW_ANY)), ELOOP, "Testing openat(O_NOFOLLOW_ANY) using path with a symlink");
	T_EXPECT_POSIX_FAILURE((fd = open(symlink_nofollow, 0)), ELOOP, "Testing open() using path with a symlink and '.nofollow' prefix");

	T_EXPECT_POSIX_FAILURE((fd = openat(testdir_fd, FILE_SYMLINK_2, O_CREAT | O_NOFOLLOW_ANY)), ELOOP, "Testing openat(O_CREAT | O_NOFOLLOW_ANY) using path with a symlink");
	T_EXPECT_POSIX_FAILURE((fd = open(symlink_resolve, O_CREAT)), ELOOP, "Testing open(O_CREAT) using path with a symlink and '.resolve' prefix");
}

T_DECL(resolve_namespace_nodotdot,
    "Test the RESOLVE_NODOTDOT prefix-path")
{
	int fd;

	char file_dotdot[PATH_MAX];
	char file_nodotdot[PATH_MAX];
	char symlink_dotdot[PATH_MAX];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_namespace_nodotdot");

	/* Setup file names */
	snprintf(file_dotdot, sizeof(file_dotdot), "/.resolve/%d/%s/%s/../%s", RESOLVE_NODOTDOT, testdir_path, TEST_DIR, FILE);
	snprintf(file_nodotdot, sizeof(file_nodotdot), "/.resolve/%d/%s/%s", RESOLVE_NODOTDOT, testdir_path, FILE);
	snprintf(symlink_dotdot, sizeof(symlink_dotdot), "/.resolve/%d/%s/%s", RESOLVE_NODOTDOT, testdir_path, FILE_SYMLINK);

	T_SETUPEND;

	T_EXPECT_POSIX_SUCCESS((fd = open(file_nodotdot, O_RDONLY)), "Testing open(O_RDONLY) without '..'");
	close(fd);

	T_EXPECT_POSIX_FAILURE((fd = open(file_dotdot, O_RDONLY)), ENOTCAPABLE, "Testing open(O_RDONLY) using path including '..'");
	T_EXPECT_POSIX_FAILURE((fd = open(file_dotdot, O_RDONLY | O_CREAT)), ENOTCAPABLE, "Testing open(O_RDONLY | O_CREAT) using path including '..'");
	T_EXPECT_POSIX_FAILURE((fd = open(symlink_dotdot, O_RDONLY)), ENOTCAPABLE, "Testing open(O_RDONLY) using path with a symlink including '..'");
	T_EXPECT_POSIX_FAILURE((fd = open(symlink_dotdot, O_RDONLY | O_CREAT)), ENOTCAPABLE, "Testing open(O_RDONLY | O_CREAT) using path with a symlink including '..'");
}

T_DECL(resolve_namespace_nodevfs,
    "Test the RESOLVE_NODEVFS prefix-path")
{
	int fd, dirfd;
	struct stat statbuf;
	char path[PATH_MAX];
	const char *dir = "/private/var/tmp/";

	T_SETUPBEGIN;

	T_ASSERT_POSIX_SUCCESS((dirfd = open(dir, O_RDONLY | O_DIRECTORY)), "Opening %s", dir);

	T_SETUPEND;

	snprintf(path, sizeof(path), "/dev/null");
	T_EXPECT_POSIX_SUCCESS((fd = open(path, O_RDONLY)), "Opening %s -> should PASS", path);
	close(fd);

	snprintf(path, sizeof(path), "/.resolve/%d/dev/null", RESOLVE_NODEVFS);
	T_EXPECT_POSIX_FAILURE((fd = open(path, O_RDONLY)), ENOTCAPABLE, "Opening %s -> Should fail with ENOTCAPABLE", path);

	snprintf(path, sizeof(path), "/dev/nosuchdir/nosuchfile.txt");
	T_EXPECT_POSIX_FAILURE((fd = open(path, O_RDONLY)), ENOENT, "Opening a non-existent file %s -> Should fail with ENOENT", path);

	snprintf(path, sizeof(path), "/.resolve/%d/dev/nosuchdir/nosuchfile.txt", RESOLVE_NODEVFS);
	T_EXPECT_POSIX_FAILURE((fd = open(path, O_RDONLY)), ENOTCAPABLE, "Opening a non-existent file %s -> Should fail with ENOTCAPABLE", path);

	snprintf(path, sizeof(path), "/dev/nosuchfile.txt");
	T_EXPECT_EQ((fd = open(path, O_RDWR | O_CREAT)), -1, "Creating a file %s -> Should fail with an error", path);

	snprintf(path, sizeof(path), "/.resolve/%d/dev/nosuchfile.txt", RESOLVE_NODEVFS);
	T_EXPECT_POSIX_FAILURE((fd = open(path, O_RDWR | O_CREAT)), ENOTCAPABLE, "Creating a file %s -> Should fail with ENOTCAPABLE", path);

	snprintf(path, sizeof(path), "/dev/../");
	T_EXPECT_POSIX_SUCCESS((stat(path, &statbuf)), "Calling stat() for %s -> Should PASS", path);
	T_EXPECT_POSIX_SUCCESS((fd = open(path, O_RDONLY)), "Opening %s -> Should PASS", path);
	close(fd);

	snprintf(path, sizeof(path), "/.resolve/%d/dev/../", RESOLVE_NODEVFS);
	T_EXPECT_POSIX_FAILURE((stat(path, &statbuf)), ENOTCAPABLE, "Calling stat() for %s -> Should fail with ENOTCAPABLE", path);
	T_EXPECT_POSIX_FAILURE((fd = open(path, O_RDONLY)), ENOTCAPABLE, "Opening %s -> Should fail with ENOTCAPABLE", path);

	snprintf(path, sizeof(path), "/dev/fd/%d", dirfd);
	T_EXPECT_POSIX_SUCCESS((stat(path, &statbuf)), "Calling stat() for %s -> Should PASS", path);
	T_EXPECT_POSIX_SUCCESS((fd = open(path, O_RDONLY)), "Opening %s paths -> Should PASS", path);
	close(fd);

	snprintf(path, sizeof(path), "/.resolve/%d/dev/fd/%d", RESOLVE_NODEVFS, dirfd);
	T_EXPECT_POSIX_FAILURE((stat(path, &statbuf)), ENOTCAPABLE, "Calling stat() for %s -> Should fail with ENOTCAPABLE", path);
	T_EXPECT_POSIX_FAILURE((fd = open(path, O_RDONLY)), ENOTCAPABLE, "Opening %s -> Should fail with ENOTCAPABLE", path);

	close(dirfd);
}

T_DECL(resolve_namespace_unique,
    "Test the RESOLVE_UNIQUE prefix-path")
{
	int fd;
	struct stat statbuf;
	char file_unique[PATH_MAX], file_unique_symlink[PATH_MAX], file3[PATH_MAX];
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_namespace_unique");
	snprintf(file3, sizeof(file3), "%s/%s", testdir_path, FILE3);
	snprintf(file_unique, sizeof(file_unique), "/.resolve/%d/%s/%s", RESOLVE_UNIQUE, testdir_path, FILE);
	snprintf(file_unique_symlink, sizeof(file_unique_symlink), "/.resolve/%d/%s/%s/%s", RESOLVE_UNIQUE, testdir_path, DIR_SYMLINK, FILE);

	T_SETUPEND;

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((stat(file_unique, &statbuf)), "Calling stat() for %s -> Should PASS", file_unique);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");
	T_EXPECT_POSIX_SUCCESS((fd = open(file_unique, O_RDONLY)), "Opening %s -> Should PASS", file_unique);
	close(fd);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate nlink count equals 2 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling fstatat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 2, "Validate nlink equals 2");

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE((stat(file_unique, &statbuf)), ENOTCAPABLE, "Calling stat() for %s -> Should fail with ENOTCAPABLE", file_unique);
	T_EXPECT_POSIX_FAILURE((fd = open(file_unique, O_RDONLY)), ENOTCAPABLE, "Opening %s -> Should fail with ENOTCAPABLE", file_unique);
	T_EXPECT_POSIX_FAILURE(link(file_unique, file3), ENOTCAPABLE, "Calling link() for %s, %s -> Should fail with ENOTCAPABLE", file_unique, file3);
	T_EXPECT_POSIX_FAILURE(rename(file_unique_symlink, file3), ENOTCAPABLE, "Calling rename() for %s, %s -> Should fail with ENOTCAPABLE", file_unique_symlink, file3);

	/* Reduce nlink count */
	T_EXPECT_POSIX_SUCCESS(unlinkat(testdir_fd, FILE2, 0), "Calling unlinkat() for %s -> Should PASS", FILE2);

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((stat(file_unique, &statbuf)), "Calling stat() for %s -> Should PASS", file_unique);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");
	T_EXPECT_POSIX_SUCCESS((fd = open(file_unique, O_RDONLY)), "Opening %s -> Should PASS", file_unique);
	close(fd);
}

T_DECL(resolve_namespace_noxattrs,
    "Test the RESOLVE_NOXATTRS prefix-path")
{
	int fd;
	struct stat statbuf;
	const char *xattr = "test1234";
	size_t xattr_len = strlen(xattr);
	char file_path[PATH_MAX];
	char file_rfork[PATH_MAX], file_noxattrs_rfork[PATH_MAX];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_namespace_noxattrs");
	snprintf(file_path, sizeof(file_path), "%s/%s", testdir_path, FILE);

	snprintf(file_rfork, sizeof(file_rfork), "%s/%s/%s", testdir_path, FILE, _PATH_RSRCFORKSPEC);
	snprintf(file_noxattrs_rfork, sizeof(file_noxattrs_rfork), "/.resolve/%d/%s/%s/%s", RESOLVE_NOXATTRS, testdir_path, FILE, _PATH_RSRCFORKSPEC);

	/* Set ResourceFork extended attribute */
	T_ASSERT_POSIX_SUCCESS(setxattr(file_path, XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting ResourceFork of %s to '%s'", file_path, xattr);

	T_SETUPEND;

	/* Call stat() for the resource fork file */
	T_EXPECT_POSIX_SUCCESS((stat(file_rfork, &statbuf)), "Calling stat() for %s -> Should PASS", file_rfork);
	T_EXPECT_POSIX_FAILURE((stat(file_noxattrs_rfork, &statbuf)), ENOTCAPABLE, "Calling stat() for %s -> Should fail with ENOTCAPABLE", file_noxattrs_rfork);

	/* Open the resource fork file */
	T_EXPECT_POSIX_SUCCESS((fd = open(file_rfork, O_RDONLY)), "Opening %s -> Should PASS", file_rfork);
	close(fd);
	T_EXPECT_POSIX_FAILURE((fd = open(file_noxattrs_rfork, O_RDONLY)), ENOTCAPABLE, "Opening %s -> Should fail with ENOTCAPABLE", file_noxattrs_rfork);
}

T_DECL(resolve_namespace_nounion,
    "Test the RESOLVE_NOUNION prefix-path prevents traversal to covered filesystem",
    T_META_ENABLED(TARGET_OS_OSX))
{
	int fd;
	struct stat statbuf;
	char union_mount_path[PATH_MAX];
	char base_file_path[PATH_MAX];
	char union_file_path[PATH_MAX];
	char union_file_nounion[PATH_MAX];
	char nonexistent_file[PATH_MAX];
	char nonexistent_nounion[PATH_MAX];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("resolve_namespace_nounion");

	/* Create union mount directory structure */
	snprintf(union_mount_path, sizeof(union_mount_path), "%s/union_mount", testdir_path);
	snprintf(base_file_path, sizeof(base_file_path), "%s/base_file.txt", union_mount_path);
	snprintf(union_file_path, sizeof(union_file_path), "%s/union_file.txt", union_mount_path);
	snprintf(union_file_nounion, sizeof(union_file_nounion), "/.resolve/%d/%s/union_file.txt", RESOLVE_NOUNION, union_mount_path);
	snprintf(nonexistent_file, sizeof(nonexistent_file), "%s/nonexistent.txt", union_mount_path);
	snprintf(nonexistent_nounion, sizeof(nonexistent_nounion), "/.resolve/%d/%s/nonexistent.txt", RESOLVE_NOUNION, union_mount_path);

	T_ASSERT_POSIX_SUCCESS(mkdir(union_mount_path, 0777), "Creating union mount directory %s", union_mount_path);

	/* Create files in the base directory before mounting */
	T_ASSERT_POSIX_SUCCESS((fd = open(base_file_path, O_CREAT | O_RDWR, 0777)), "Creating base file %s", base_file_path);
	write(fd, "base content", 12);
	close(fd);

	/* Create the union file in the base directory before mounting */
	T_ASSERT_POSIX_SUCCESS((fd = open(union_file_path, O_CREAT | O_RDWR, 0777)), "Creating union file in base directory %s", union_file_path);
	write(fd, "base union content", 18);
	close(fd);

	/* Create union mount: Mount devfs with union flag */
	T_ASSERT_POSIX_SUCCESS(mount("devfs", union_mount_path, MNT_UNION, NULL), "Mounting devfs with union flag at %s", union_mount_path);

	/* The union_file.txt now exists in the base layer and should be accessible through the union mount */

	T_SETUPEND;

	/* Test 1: Normal stat() access to union file should work */
	T_EXPECT_POSIX_SUCCESS((stat(union_file_path, &statbuf)), "Calling stat() for union file %s -> Should PASS", union_file_path);

	/* Test 2: stat() with RESOLVE_NOUNION should prevent traversal to covered filesystem */
	T_EXPECT_POSIX_FAILURE((stat(union_file_nounion, &statbuf)), ENOENT, "Calling stat() for union file with RESOLVE_NOUNION %s -> Should fail with ENOENT", union_file_nounion);

	/* Test 3: Test union traversal behavior - stat() nonexistent file */
	/* Without RESOLVE_NOUNION, this might traverse to covered filesystem looking for the file */
	T_EXPECT_POSIX_FAILURE((stat(nonexistent_file, &statbuf)), ENOENT, "Calling stat() for nonexistent file %s -> Should fail with ENOENT", nonexistent_file);

	/* Test 4: With RESOLVE_NOUNION, traversal to covered filesystem should be prevented */
	T_EXPECT_POSIX_FAILURE((stat(nonexistent_nounion, &statbuf)), ENOENT, "Calling stat() for nonexistent file with RESOLVE_NOUNION %s -> Should fail with ENOENT (traversal to covered filesystem prevented)", nonexistent_nounion);

	/* Test 5: Verify that open() also prevents traversal to covered filesystem with RESOLVE_NOUNION */
	T_EXPECT_POSIX_FAILURE((fd = open(union_file_nounion, O_RDONLY)), ENOENT, "Opening union file with RESOLVE_NOUNION %s -> Should fail with ENOENT", union_file_nounion);

	/* Clean up union mount */
	unmount(union_mount_path, MNT_FORCE);  /* Remove devfs union mount */

	/* Remove the files and directory */
	unlink(union_file_path);  /* Remove union file from base directory */
	unlink(base_file_path);   /* Remove base file */
	rmdir(union_mount_path);  /* Remove directory */

	T_LOG("RESOLVE_NOUNION flag test completed - prevents traversal from union filesystem to covered filesystem");
}
