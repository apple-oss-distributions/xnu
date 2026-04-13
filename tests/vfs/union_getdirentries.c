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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -lsandbox -o union_getdirentries union_getdirentries.c */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/dirent.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sandbox/libsandbox.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define RUN_TEST     TARGET_OS_OSX

#define FSTYPE_DEVFS "devfs"
#define FSTYPE_TMPFS "tmpfs"

#define TESTDIR   "testdir"
#define DIRECTORY "dir"
#define FILE      "dir/file"

static char template[MAXPATHLEN];
static char *testdir = NULL;
static int testdir_fd = -1;
static sandbox_params_t params = NULL;
static sandbox_profile_t profile = NULL;

extern ssize_t __getdirentries64(int, void *, size_t, off_t *);

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),
	T_META_ENABLED(RUN_TEST),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (params) {
		sandbox_free_params(params);
	}
	if (profile) {
		sandbox_free_profile(profile);
	}

	unmount(DIRECTORY, MNT_FORCE);

	if (testdir_fd != -1) {
		unlinkat(testdir_fd, FILE, 0);
		unlinkat(testdir_fd, DIRECTORY, AT_REMOVEDIR);
		unlinkat(testdir_fd, TESTDIR, AT_REMOVEDIR);
		close(testdir_fd);
		rmdir(testdir);
	}
}

T_DECL(union_getdirentries_open_lifecycle,
    "Ensure getdirentries64 maintains proper open/close lifecycle management with multiple union mounts")
{
	int fd;
	struct dirent *buf;
	off_t offset = 0;
	ssize_t result;
	char zero_path[MAXPATHLEN];
	char dir_path[MAXPATHLEN];
	char mount_tmpfs_cmd[1000];

#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	if (geteuid() != 0) {
		T_SKIP("Test should run as root");
	}

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	T_ASSERT_POSIX_NOTNULL((buf = malloc(4096)), "Allocating data buffer");

	snprintf(template, sizeof(template), "%s/union_getdirentries_open_lifecycle-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	/* Create base directory structure */
	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, DIRECTORY, 0777), "Creating %s/%s", testdir, DIRECTORY);

	/* Create directories path */
	snprintf(dir_path, sizeof(dir_path), "%s/%s", testdir, DIRECTORY);
	snprintf(zero_path, sizeof(zero_path), "%s/%s/zero", testdir, DIRECTORY);

	/* Create multi-layer union mount structure */
	/* Layer 1: Mount devfs with union flag on the base directory */
	T_ASSERT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, dir_path, MNT_UNION, NULL), "Mounting devfs layer 1 at %s", dir_path);

	/* Layer 2: Mount tmpfs on devfs directory using mount_tmpfs command with union flag */
	snprintf(mount_tmpfs_cmd, sizeof(mount_tmpfs_cmd), "/sbin/mount_tmpfs -o union -s 10m %s", dir_path);
	T_ASSERT_POSIX_SUCCESS(system(mount_tmpfs_cmd), "Mounting tmpfs with union flag at %s", dir_path);

	/* Create the zero directory in the tmpfs mount */
	T_ASSERT_POSIX_SUCCESS(mkdir(zero_path, 0777), "Creating %s", zero_path);

	T_SETUPEND;

	/* Open the multi-layer union mount entry - test proper lifecycle management */
	T_EXPECT_POSIX_SUCCESS((fd = open(zero_path, O_RDONLY)), "Opening multi-layer union mount entry");
	if (fd >= 0) {
		/*
		 * This tests that proper VNOP_OPEN/VNOP_CLOSE lifecycle
		 * is maintained when switching vnodes through multiple union mount layers
		 * (devfs + tmpfs), preventing filesystem state corruption.
		 */
		while (1) {
			result = __getdirentries64(fd, buf, 4096, &offset);
			if (result <= 0) {
				break;
			}
		}

		close(fd);
		T_PASS("getdirentries64 completed with proper open/close lifecycle management through multiple filesystem layers");
	}

	/* Clean up mounts in reverse order */
	unmount(dir_path, MNT_FORCE);  /* Remove union mount */
	unmount(dir_path, MNT_FORCE); /* Remove union mount */

	/* Clean up directories */
	rmdir(zero_path);
	rmdir(dir_path);
	rmdir(testdir);

	free(buf);
}

static void
create_profile_string(char *buff, size_t size)
{
	snprintf(buff, size, "(version 1) \n\
                          (allow default) \n\
                          (deny file-read* (filesystem-name \"apfs\")) \n");
}

static void
run_fopendir(int eperm)
{
	int fd;
	DIR *dirp = NULL;

	T_EXPECT_POSIX_SUCCESS((fd = open(DIRECTORY, O_RDONLY)), "Opening mount point");
	if (fd >= 0) {
		dirp = fdopendir(fd);
		if (eperm) {
			T_EXPECT_POSIX_FAILURE(dirp ? 0 : -1, EPERM, "Calling fdopendir -> should fail with EPERM");
		} else {
			T_EXPECT_POSIX_NOTNULL(dirp, "Calling fdopendir -> should PASS");
		}
		if (dirp) {
			closedir(dirp);
		}
		close(fd);
	}
}

T_DECL(union_getdirentries_sandbox,
    "Ensure getdirentries() enforces MAC policies on union mounts")
{
	int fd;
	char *sberror = NULL;
	char profile_string[1000];

#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	if (geteuid() != 0) {
		T_SKIP("Test should run as root");
	}

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/union_getdirentries-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, DIRECTORY, 0777), "Creating %s/%s", testdir, DIRECTORY);
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_CREAT | O_RDWR, 0777)), "Creating %s", FILE);
	close(fd);

	T_ASSERT_POSIX_ZERO(chdir(testdir), "Changing current directory to: %s", testdir);

	T_ASSERT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, DIRECTORY, MNT_UNION, NULL), "Mounting temporary %s mount at %s", FSTYPE_DEVFS, DIRECTORY);

	/* Create sandbox variables */
	T_ASSERT_POSIX_NOTNULL(params = sandbox_create_params(), "Creating Sandbox params object");
	create_profile_string(profile_string, sizeof(profile_string));
	T_ASSERT_POSIX_NOTNULL(profile = sandbox_compile_string(profile_string, params, &sberror), "Creating Sandbox profile object");

	T_SETUPEND;

	/* Run without sandbox profile */
	run_fopendir(0);

	/* Apply sandbox profile */
	T_ASSERT_POSIX_SUCCESS(sandbox_apply(profile), "Applying Sandbox profile");

	/* Run with sandbox profile */
	run_fopendir(1);
}

T_DECL(union_getdirentries_type,
    "Ensure getdirentries64 does not turn directory descriptors into non-directory descriptors")
{
	int fd;
	struct stat sb;
	struct dirent *buf;
	off_t offset = 0;

#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	if (geteuid() != 0) {
		T_SKIP("Test should run as root");
	}

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	T_ASSERT_POSIX_NOTNULL((buf = malloc(4096)), "Allocating data buffer");

	snprintf(template, sizeof(template), "%s/union_getdirentries_type-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);

	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, DIRECTORY, 0777), "Creating %s/%s", testdir, DIRECTORY);
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_CREAT | O_RDWR, 0777)), "Creating %s", FILE);
	close(fd);

	T_ASSERT_POSIX_ZERO(chdir(testdir), "Changing current directory to: %s", testdir);

	T_ASSERT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, DIRECTORY, MNT_UNION, NULL), "Mounting temporary %s mount at %s", FSTYPE_DEVFS, FILE);

	T_ASSERT_POSIX_SUCCESS(mkdirat(testdir_fd, FILE, 0777), "Creating directory %s/%s", testdir, FILE);

	T_SETUPEND;

	T_EXPECT_POSIX_SUCCESS((fd = open(FILE, O_RDONLY)), "Opening mount point");
	if (fd >= 0) {
		while (1) {
			ssize_t r = __getdirentries64(fd, buf, 4096, &offset);
			if (r <= 0) {
				break;
			}
		}

		if (fstat(fd, &sb) != 0) {
			T_FAIL("fstat failed");
			return;
		}

		T_EXPECT_TRUE(S_ISDIR(sb.st_mode), "Validating ISDIR file type");
	}

	unlinkat(testdir_fd, FILE, AT_REMOVEDIR);
	free(buf);
}
