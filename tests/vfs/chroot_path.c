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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o chroot_path chroot_path.c */

#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fsgetpath.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ENABLED(TARGET_OS_OSX),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

T_DECL(chroot_path_volfs,
    "Check for and fail if the volfs path is not under the chroot")
{
#if TARGET_OS_OSX
	int fd;
	char root_volfs[MAXPATHLEN];
	const char *root_path = "/", *private_path = "/private";
	struct stat root_stat, root_stat2, private_stat, fd_stat;

	T_SETUPBEGIN;

	T_ASSERT_POSIX_SUCCESS(stat(root_path, &root_stat),
	    "Setup: Calling stat() on %s",
	    root_path);

	T_ASSERT_POSIX_SUCCESS(snprintf(root_volfs, sizeof(root_volfs), "/.vol/%d/2", root_stat.st_dev),
	    "Setup: Creating root_volfs path");

	T_ASSERT_POSIX_SUCCESS(stat(root_volfs, &root_stat2),
	    "Setup: Calling stat() on %s",
	    root_volfs);

	T_ASSERT_POSIX_SUCCESS(stat(private_path, &private_stat),
	    "Setup: Calling stat() on %s",
	    private_path);

	T_ASSERT_POSIX_SUCCESS(chroot(private_path),
	    "Setup: Calling chroot() on %s",
	    private_path);

	T_SETUPEND;

	T_ASSERT_EQ(root_stat.st_ino, root_stat2.st_ino, "Verifing %s and %s are the same file", root_path, root_volfs);
	T_ASSERT_POSIX_SUCCESS((fd = open(root_path, 0)), "Opening the updated root path");
	T_ASSERT_POSIX_SUCCESS((fstat(fd, &fd_stat)), "Calling stat on the updated root path");
	T_ASSERT_EQ(fd_stat.st_ino, private_stat.st_ino, "Verifing %s was opened", private_path);
	T_ASSERT_POSIX_FAILURE(open(root_volfs, 0), ENOENT, "Verifing %s can not be opened because path is not under the chroot", root_volfs);
#else
	T_SKIP("Not macOS");
#endif
}

T_DECL(chroot_path_fsgetpath,
    "Check that fsgetpath fails if the path is outside chroot")
{
#if TARGET_OS_OSX
	char fspath[MAXPATHLEN];
	const char *root_path = "/", *private_path = "/private";
	struct stat root_stat, private_stat;
	fsid_t fsid;

	T_SETUPBEGIN;

	T_ASSERT_POSIX_SUCCESS(stat(root_path, &root_stat),
	    "Setup: Calling stat() on %s",
	    root_path);

	T_ASSERT_POSIX_SUCCESS(stat(private_path, &private_stat),
	    "Setup: Calling stat() on %s",
	    private_path);

	T_SETUPEND;

	/* Test fsgetpath before chroot - should succeed */
	fsid.val[0] = root_stat.st_dev;
	fsid.val[1] = 0;
	T_ASSERT_POSIX_SUCCESS(fsgetpath(fspath, sizeof(fspath), &fsid, root_stat.st_ino),
	    "fsgetpath should succeed before chroot");
	T_LOG("fsgetpath returned: %s", fspath);

	/* Enter chroot */
	T_ASSERT_POSIX_SUCCESS(chroot(private_path),
	    "Calling chroot() on %s",
	    private_path);

	/* Test fsgetpath after chroot for file outside chroot - should fail */
	T_ASSERT_POSIX_FAILURE(fsgetpath(fspath, sizeof(fspath), &fsid, root_stat.st_ino), ENOENT,
	    "fsgetpath should fail with ENOENT for path outside chroot");

	/* Test fsgetpath for file inside chroot - should succeed */
	fsid.val[0] = private_stat.st_dev;
	T_ASSERT_POSIX_SUCCESS(fsgetpath(fspath, sizeof(fspath), &fsid, private_stat.st_ino),
	    "fsgetpath should succeed for path inside chroot");
	T_LOG("fsgetpath for chroot dir returned: %s", fspath);
#else
	T_SKIP("Not macOS");
#endif
}

T_DECL(chroot_path_fgetpath,
    "Check that F_GETPATH fails if the path is outside chroot")
{
#if TARGET_OS_OSX
	char fspath[MAXPATHLEN];
	const char *root_path = "/", *private_path = "/private";
	struct stat private_stat;
	int root_fd, private_fd;

	T_SETUPBEGIN;

	T_ASSERT_POSIX_SUCCESS(stat(private_path, &private_stat),
	    "Setup: Calling stat() on %s",
	    private_path);

	/* Open root directory before chroot */
	T_ASSERT_POSIX_SUCCESS((root_fd = open(root_path, O_RDONLY)),
	    "Setup: Opening %s",
	    root_path);

	/* Open private directory before chroot */
	T_ASSERT_POSIX_SUCCESS((private_fd = open(private_path, O_RDONLY)),
	    "Setup: Opening %s",
	    private_path);

	T_SETUPEND;

	/* Test F_GETPATH before chroot - should succeed */
	T_ASSERT_POSIX_SUCCESS(fcntl(root_fd, F_GETPATH, fspath),
	    "F_GETPATH should succeed before chroot");
	T_LOG("F_GETPATH returned: %s", fspath);

	/* Enter chroot */
	T_ASSERT_POSIX_SUCCESS(chroot(private_path),
	    "Calling chroot() on %s",
	    private_path);

	/* Test F_GETPATH after chroot for fd outside chroot - should fail */
	T_ASSERT_POSIX_FAILURE(fcntl(root_fd, F_GETPATH, fspath), ENOENT,
	    "F_GETPATH should fail with ENOENT for fd outside chroot");

	/* Test F_GETPATH for fd inside chroot - should succeed */
	T_ASSERT_POSIX_SUCCESS(fcntl(private_fd, F_GETPATH, fspath),
	    "F_GETPATH should succeed for fd inside chroot");
	T_LOG("F_GETPATH for chroot dir returned: %s", fspath);

	/* Clean up */
	close(root_fd);
	close(private_fd);
#else
	T_SKIP("Not macOS");
#endif
}

T_DECL(chroot_path_openat_fgetpath,
    "Check that F_GETPATH works with openat() within chroot")
{
#if TARGET_OS_OSX
	char fspath[MAXPATHLEN];
	const char *chroot_path = "/";
	const char *at_path = ".";
	const char *relative_path = "private";
	int at_fd, target_fd;

	T_SETUPBEGIN;

	/* Verify the target directory exists before chroot */
	char full_target_path[MAXPATHLEN];
	T_ASSERT_POSIX_SUCCESS(snprintf(full_target_path, sizeof(full_target_path), "%s%s", chroot_path, relative_path),
	    "Setup: Creating full target path");

	struct stat target_stat;
	T_ASSERT_POSIX_SUCCESS(stat(full_target_path, &target_stat),
	    "Setup: Verifying %s exists",
	    full_target_path);

	T_SETUPEND;

	/* Enter chroot */
	T_ASSERT_POSIX_SUCCESS(chroot(chroot_path),
	    "Calling chroot() on %s",
	    chroot_path);

	/* Open the base directory within chroot */
	T_ASSERT_POSIX_SUCCESS((at_fd = open(chroot_path, O_RDONLY | O_DIRECTORY)),
	    "Opening base directory %s within chroot",
	    at_path);

	/* Open target directory using openat() */
	T_ASSERT_POSIX_SUCCESS((target_fd = openat(at_fd, relative_path, O_RDONLY | O_DIRECTORY)),
	    "Opening %s relative to %s using openat()",
	    relative_path, at_path);

	/* Test F_GETPATH on the openat() file descriptor - should succeed */
	T_ASSERT_POSIX_SUCCESS(fcntl(target_fd, F_GETPATH, fspath),
	    "F_GETPATH should succeed for openat() fd within chroot");

	T_LOG("F_GETPATH for openat(%s, %s) returned: %s", at_path, relative_path, fspath);

	/* Verify the returned path is within the chroot */
	T_ASSERT_TRUE(fspath[0] == '/', "Returned path should be absolute");
	T_ASSERT_TRUE(strstr(fspath, relative_path) != NULL,
	    "Returned path should contain the relative path component");

	/* Clean up */
	close(target_fd);
	close(at_fd);
#else
	T_SKIP("Not macOS");
#endif
}
