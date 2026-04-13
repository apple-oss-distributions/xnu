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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o ftruncate_symlink ftruncate_symlink.c */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>

#include <darwintest.h>
#include <darwintest/utils.h>

static char template[MAXPATHLEN];
static char *testdir = NULL;
static char file[PATH_MAX], sym[PATH_MAX];

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (sym[0] != '\0') {
		unlink(sym);
	}
	if (file[0] != '\0') {
		unlink(file);
	}
	if (testdir) {
		rmdir(testdir);
	}
}

T_DECL(ftruncate_symlink,
    "Test ftruncate() is failing with EINVAL while the file descriptor points to symbolinc link")
{
	int fd;

	file[0] = sym[0] = '\0';

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Create test root dir */
	snprintf(template, sizeof(template), "%s/ftruncate_symlink-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	/* Setup file names */
	snprintf(file, sizeof(file), "%s/%s", testdir, "file");
	snprintf(sym, sizeof(sym), "%s/%s", testdir, "symlink");

	/* Create the test file */
	T_ASSERT_POSIX_SUCCESS((fd = open(file, O_CREAT | O_RDWR, 0777)), "Creating file %s", file);

	/* Create the symlink */
	T_ASSERT_POSIX_SUCCESS(symlink(file, sym), "Creating symlink %s -> %s", sym, file);

	/* Close the test file */
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", file);

	T_SETUPEND;

	/* Open using the O_SYMLINK flag */
	T_ASSERT_POSIX_SUCCESS((fd = open(sym, O_WRONLY | O_SYMLINK, 0777)), "Opening %s using the O_SYMLINK flag", sym);

	/* Validate EINVAL for symlinks */
	T_ASSERT_POSIX_FAILURE(ftruncate(fd, 0), EINVAL, "Validating EINVAL for symlinks");

	/* Close the file descriptor */
	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing %s", sym);
}
