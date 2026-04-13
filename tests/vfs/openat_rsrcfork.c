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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o openat_rsrcfork openat_rsrcfork.c */

#include <sys/xattr.h>
#include <TargetConditionals.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define RUN_TEST     TARGET_OS_OSX
#define RSRCFORK     "..namedfork/rsrc"

static char template[MAXPATHLEN];
static char *testdir = NULL;
static char rsrcfork[PATH_MAX];
static char file[PATH_MAX];

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
	if (file[0] != '\0') {
		unlink(file);
	}
	if (rsrcfork[0] != '\0') {
		unlink(rsrcfork);
	}
	if (testdir) {
		rmdir(testdir);
	}
}

T_DECL(openat_rsrcfork,
    "Validate openat()/fstatat() with '../namedfork/rsrc'")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	int error;
	int fd, fd_rsrcfork;
	char xattr_buff[100];
	const char *xattr = "test1234";
	size_t xattr_len = strlen(xattr);
	char testdir_path[MAXPATHLEN];
	struct stat buf;

	file[0] = rsrcfork[0] = '\0';

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Create test root dir */
	snprintf(template, sizeof(template), "%s/openat_rsrcfork-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);
	T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_GETPATH, testdir_path), "Calling fcntl() to get the path");
	close(fd);

	/* Setup file names */
	snprintf(file, sizeof(file), "%s/%s", testdir_path, "file");
	snprintf(rsrcfork, sizeof(rsrcfork), "%s/%s", file, RSRCFORK);

	/* Create the test file */
	T_ASSERT_POSIX_SUCCESS((fd = open(file, O_CREAT | O_RDWR, 0644)), "Creating %s", file);

	/* Set ResourceFork extended attribute */
	T_ASSERT_POSIX_SUCCESS(fsetxattr(fd, XATTR_RESOURCEFORK_NAME, xattr, xattr_len, 0, 0), "Setting ResourceFork of %s to '%s'", file, xattr);

	T_SETUPEND;

	T_LOG("Write ResourceFork with '%s' suffix while file is open using openat()", RSRCFORK);
	T_EXPECT_POSIX_SUCCESS((fd_rsrcfork = openat(fd, RSRCFORK, O_CREAT | O_RDWR, 0777)), "Creating %s", rsrcfork);
	if (fd_rsrcfork >= 0) {
		T_EXPECT_EQ((ssize_t)xattr_len, write(fd_rsrcfork, xattr, xattr_len), "Trying to write ResourceFork");
		close(fd_rsrcfork);
	}

	T_LOG("Read ResourceFork using getxattr()");
	T_EXPECT_EQ((ssize_t)xattr_len, fgetxattr(fd, XATTR_RESOURCEFORK_NAME, xattr_buff, sizeof(xattr_buff), 0, 0), "Trying to get ResourceFork");
	T_EXPECT_EQ(0, strncmp(xattr, xattr_buff, xattr_len), "Verifying ResourceFork content");

	T_LOG("Read ResourceFork with '%s' full path", RSRCFORK);
	T_EXPECT_POSIX_SUCCESS((fd_rsrcfork = open(rsrcfork, O_RDONLY, 0777)), "Opening %s", rsrcfork);
	if (fd_rsrcfork >= 0) {
		T_EXPECT_EQ((ssize_t)xattr_len, read(fd_rsrcfork, xattr_buff, sizeof(xattr_buff)), "Trying to read ResourceFork");
		T_EXPECT_EQ(0, strncmp(xattr, xattr_buff, xattr_len), "Verifying ResourceFork content");
		close(fd_rsrcfork);
	}

	T_LOG("Read ResourceFork with '%s' suffix while file is open using openat()", RSRCFORK);
	T_EXPECT_POSIX_SUCCESS((fd_rsrcfork = openat(fd, RSRCFORK, O_RDONLY, 0777)), "Opening(at) %s with '%s'", file, RSRCFORK);
	if (fd_rsrcfork >= 0) {
		T_EXPECT_EQ((ssize_t)xattr_len, read(fd_rsrcfork, xattr_buff, sizeof(xattr_buff)), "Trying to read ResourceFork");
		T_EXPECT_EQ(0, strncmp(xattr, xattr_buff, xattr_len), "Verifying ResourceFork content");
		close(fd_rsrcfork);
	}

	T_LOG("Read ResourceFork's size with '%s' suffix using fstatat()", RSRCFORK);
	T_EXPECT_POSIX_SUCCESS((error = fstatat(fd, RSRCFORK, &buf, 0)), "fstat(at) %s with '%s'", file, RSRCFORK);
	if (!error) {
		T_EXPECT_EQ((off_t)xattr_len, buf.st_size, "Verifying ResourceFork size");
	}

	/* Close the open files */
	close(fd);
}

T_DECL(openat_rsrcfork_create_permission,
    "Validate that O_CREAT on resource fork checks permissions")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	/* Skip test if running as root since root can bypass permission checks */
	if (getuid() == 0) {
		T_SKIP("Test requires non-root user to validate permission checks");
	}

	int fd, rsrc_fd;
	char test_file[PATH_MAX];
	char rsrc_path[PATH_MAX];
	char v = 0;
	char buffer[4] = "test";
	ssize_t bytes_read;

	/* Setup test file path */
	snprintf(test_file, sizeof(test_file), "%s/rsrc_perm_test_file", dt_tmpdir());
	snprintf(rsrc_path, sizeof(rsrc_path), "%s/%s", test_file, RSRCFORK);

	T_LOG("Testing resource fork permission bypass vulnerability fix");

	/* Create a file with write-only permissions (0222) */
	T_ASSERT_POSIX_SUCCESS((fd = open(test_file, O_CREAT | O_EXCL, 0222)),
	    "Creating test file with write-only permissions");
	close(fd);

	T_LOG("Created test file with write-only permissions (0222)");

	/* Verify that getxattr fails with permission denied (expected behavior) */
	T_EXPECT_POSIX_FAILURE(getxattr(test_file, XATTR_RESOURCEFORK_NAME, &v, 1, 0, 0), EACCES,
	    "getxattr should deny access to resource fork");

	/*
	 * Try to open the resource fork with O_CREAT | O_RDONLY
	 * This should fail with the fix in place
	 */
	T_LOG("Attempting to create resource fork with insufficient permissions - should fail");
	rsrc_fd = open(rsrc_path, O_CREAT | O_RDONLY, 0);
	if (rsrc_fd != -1) {
		/* If this succeeds, the vulnerability still exists */
		T_FAIL("Resource fork creation should have been denied");

		/* Try to demonstrate the vulnerability by reading */
		if (setxattr(test_file, XATTR_RESOURCEFORK_NAME, "bla", 3, 0, 0) == 0) {
			T_LOG("Successfully set resource fork content");

			bytes_read = read(rsrc_fd, buffer, sizeof(buffer));
			if (bytes_read > 0) {
				T_FAIL("VULNERABILITY: Successfully read resource fork despite insufficient permissions");
			}
		}

		close(rsrc_fd);
		T_FAIL("Resource fork creation should have failed due to insufficient permissions");
	} else {
		/* Check that the error is permission-related */
		T_EXPECT_TRUE((errno == EACCES || errno == EPERM),
		    "Resource fork creation should fail with permission error, got errno=%d", errno);
		T_LOG("✓ Resource fork creation correctly denied due to insufficient permissions");
	}

	/* Now test with a file that has proper read/write permissions */
	unlink(test_file);
	T_ASSERT_POSIX_SUCCESS((fd = open(test_file, O_CREAT | O_EXCL, 0644)),
	    "Creating test file with proper permissions");
	close(fd);

	T_LOG("Created test file with read/write permissions (0644)");

	/* This should succeed */
	T_EXPECT_POSIX_SUCCESS((rsrc_fd = open(rsrc_path, O_CREAT | O_RDONLY, 0)),
	    "Resource fork creation should succeed with proper permissions");
	if (rsrc_fd >= 0) {
		T_LOG("✓ Resource fork creation succeeded with proper permissions");
		close(rsrc_fd);
	}

	/* Clean up */
	unlink(test_file);
}

T_DECL(openat_rsrcfork_symlink_eperm,
    "Test that O_SYMLINK | O_CREAT | O_NOFOLLOW on symlink/..namedfork/rsrc returns EPERM")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	int fd;
	char symlink_file[PATH_MAX], symlink_rsrc_path[PATH_MAX];
	char testdir_path[MAXPATHLEN];
	const char *xattr_data = "fn";

	file[0] = rsrcfork[0] = '\0';

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Create test root dir */
	snprintf(template, sizeof(template), "%s/openat_rsrcfork_enotdir-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);
	T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_GETPATH, testdir_path), "Calling fcntl() to get the path");
	close(fd);

	/* Setup file paths */
	snprintf(file, sizeof(file), "%s/%s", testdir_path, "file");
	snprintf(rsrcfork, sizeof(rsrcfork), "%s/%s", file, RSRCFORK);
	snprintf(symlink_file, sizeof(symlink_file), "%s/%s", testdir_path, "symlink");
	snprintf(symlink_rsrc_path, sizeof(symlink_rsrc_path), "%s/%s", symlink_file, RSRCFORK);

	/* Create the target file and write to its resource fork */
	T_ASSERT_POSIX_SUCCESS((fd = open(file, O_CREAT | O_RDWR, 0777)), "Creating file %s", file);
	T_ASSERT_POSIX_SUCCESS(fsetxattr(fd, XATTR_RESOURCEFORK_NAME, xattr_data, strlen(xattr_data), 0, 0),
	    "Setting ResourceFork of %s", file);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing file");

	/* Create a symlink pointing to the file */
	T_ASSERT_POSIX_SUCCESS(symlink("file", symlink_file), "Creating symlink %s -> file", symlink_file);

	T_SETUPEND;

	T_LOG("Verify we can open the symlink itself with O_SYMLINK");
	T_ASSERT_POSIX_SUCCESS((fd = open(symlink_file, O_SYMLINK)), "Opening symlink %s with O_SYMLINK", symlink_file);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing symlink fd");

	T_LOG("Verify we can access resource fork through symlink normally");
	T_ASSERT_POSIX_SUCCESS((fd = open(symlink_rsrc_path, O_RDONLY)), "Opening %s", symlink_rsrc_path);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing resource fork fd");

	T_LOG("O_SYMLINK | O_CREAT | O_NOFOLLOW on symlink/..namedfork/rsrc should return EPERM");
	/* Should return EPERM since symlinks cannot have namedfork paths. */
	T_EXPECT_POSIX_FAILURE((fd = open(symlink_rsrc_path, O_RDWR | O_SYMLINK | O_CREAT | O_NOFOLLOW, 0777)), EPERM,
	    "Opening %s with O_SYMLINK | O_CREAT | O_NOFOLLOW should fail with EPERM", symlink_rsrc_path);
	if (fd >= 0) {
		close(fd);
	}

	/* Clean up the symlink */
	unlink(symlink_file);
}
