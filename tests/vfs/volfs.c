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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o volfs volfs.c */

#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ENABLED(TARGET_OS_OSX),
	T_META_CHECK_LEAKS(false));

T_DECL(volfs_at_shortcut,
    "Test the @ shortcut for device root directory with relative paths",
    T_META_ASROOT(false))
{
#if TARGET_OS_OSX
	int fd1, fd2;
	char root_volfs_numeric[MAXPATHLEN];
	char root_volfs_at[MAXPATHLEN];
	char relative_path_numeric[MAXPATHLEN];
	char relative_path_at[MAXPATHLEN];
	const char *root_path = "/";
	const char *test_file = "etc/hosts";  // A file that should exist on most systems
	struct stat root_stat, stat1, stat2;

	T_SETUPBEGIN;

	T_ASSERT_POSIX_SUCCESS(stat(root_path, &root_stat),
	    "Setup: Calling stat() on %s", root_path);

	// Create volfs paths using numeric and @ shortcuts
	T_ASSERT_POSIX_SUCCESS(snprintf(root_volfs_numeric, sizeof(root_volfs_numeric),
	    "/.vol/%d/2", root_stat.st_dev),
	    "Setup: Creating numeric root volfs path");

	T_ASSERT_POSIX_SUCCESS(snprintf(root_volfs_at, sizeof(root_volfs_at),
	    "/.vol/%d/@", root_stat.st_dev),
	    "Setup: Creating @ root volfs path");

	// Create relative paths using both methods
	T_ASSERT_POSIX_SUCCESS(snprintf(relative_path_numeric, sizeof(relative_path_numeric),
	    "/.vol/%d/2/%s", root_stat.st_dev, test_file),
	    "Setup: Creating numeric relative path");

	T_ASSERT_POSIX_SUCCESS(snprintf(relative_path_at, sizeof(relative_path_at),
	    "/.vol/%d/@/%s", root_stat.st_dev, test_file),
	    "Setup: Creating @ relative path");

	T_SETUPEND;

	// Test 1: Verify both @ and numeric shortcuts point to the same root
	T_ASSERT_POSIX_SUCCESS(stat(root_volfs_numeric, &stat1),
	    "Calling stat() on numeric root path %s", root_volfs_numeric);

	T_ASSERT_POSIX_SUCCESS(stat(root_volfs_at, &stat2),
	    "Calling stat() on @ root path %s", root_volfs_at);

	T_ASSERT_EQ(stat1.st_ino, stat2.st_ino,
	    "Verifying %s and %s point to the same inode",
	    root_volfs_numeric, root_volfs_at);

	T_ASSERT_EQ(stat1.st_dev, stat2.st_dev,
	    "Verifying %s and %s are on the same device",
	    root_volfs_numeric, root_volfs_at);

	// Test 2: Verify relative paths work with @ shortcut
	T_ASSERT_POSIX_SUCCESS(stat(relative_path_numeric, &stat1),
	    "Calling stat() on numeric relative path %s", relative_path_numeric);

	T_ASSERT_POSIX_SUCCESS(stat(relative_path_at, &stat2),
	    "Calling stat() on @ relative path %s", relative_path_at);

	T_ASSERT_EQ(stat1.st_ino, stat2.st_ino,
	    "Verifying %s and %s point to the same file",
	    relative_path_numeric, relative_path_at);

	// Test 3: Verify file access works with @ shortcut
	T_ASSERT_POSIX_SUCCESS((fd1 = open(relative_path_numeric, O_RDONLY)),
	    "Opening file via numeric path %s", relative_path_numeric);

	T_ASSERT_POSIX_SUCCESS((fd2 = open(relative_path_at, O_RDONLY)),
	    "Opening file via @ path %s", relative_path_at);

	T_ASSERT_POSIX_SUCCESS(fstat(fd1, &stat1), "fstat on numeric path fd");
	T_ASSERT_POSIX_SUCCESS(fstat(fd2, &stat2), "fstat on @ path fd");

	T_ASSERT_EQ(stat1.st_ino, stat2.st_ino,
	    "Verifying both file descriptors point to the same file");

	close(fd1);
	close(fd2);

	T_LOG("@ shortcut test completed successfully");
	T_LOG("Both /.vol/%d/2/%s and /.vol/%d/@/%s work correctly",
	    root_stat.st_dev, test_file, root_stat.st_dev, test_file);

#else
	T_SKIP("Not macOS");
#endif
}
