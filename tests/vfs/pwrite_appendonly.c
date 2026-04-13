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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o pwrite_appendonly pwrite_appendonly.c -g -Weverything */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslimits.h>

#include <darwintest.h>
#include <darwintest/utils.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false),
	T_META_TAG_VM_PREFERRED);

#define TEST_DIR  "testdir"
#define TEST_FILE "testfile"

static char g_testfile[MAXPATHLEN];
static char g_testdir[MAXPATHLEN];


static void
exit_cleanup(void)
{
	(void)remove(g_testfile);
	(void)rmdir(g_testdir);
}

static void
create_test_file(void)
{
	const char *tmpdir = dt_tmpdir();
	int fd;

	T_SETUPBEGIN;

	atexit(exit_cleanup);

	snprintf(g_testdir, MAXPATHLEN, "%s/%s", tmpdir, TEST_DIR);

	T_ASSERT_POSIX_SUCCESS(mkdir(g_testdir, 0777),
	    "Setup: creating test dir: %s", g_testdir);

	snprintf(g_testfile, MAXPATHLEN, "%s/%s", g_testdir, TEST_FILE);

	T_WITH_ERRNO;
	fd = open(g_testfile, O_CREAT | O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Create test fi1e: %s", g_testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", TEST_FILE);

	T_SETUPEND;
}

T_DECL(pwrite_append, "Validate pwrite to arbitrary offsets should fail on append-only file")
{
	char buf[32];
	ssize_t ret;
	int err, fd;

	create_test_file();

	T_WITH_ERRNO;
	err = chflags(g_testfile, UF_APPEND);
	T_ASSERT_NE(err, -1, "Enable append-only on file: %s", g_testfile);

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDWR | O_APPEND);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDWR|O_APPEND: %s", g_testfile);

	T_WITH_ERRNO;
	ret = pwrite(fd, &buf, 16, 8);
	T_ASSERT_TRUE((ret == -1) && (errno == EPERM), "Write on append-only file: %s", g_testfile);

	T_WITH_ERRNO;
	err = ftruncate(fd, 100);
	T_ASSERT_TRUE((err == -1) && (errno == EPERM), "Truncate on append-only file: %s", g_testfile);

	T_WITH_ERRNO;
	err = chflags(g_testfile, 0);
	T_ASSERT_NE(err, -1, "Disable append-only on file: %s", g_testfile);

	T_WITH_ERRNO;
	ret = pwrite(fd, &buf, 16, 8);
	T_ASSERT_EQ(ret, (ssize_t)16, "Write on file: %s", g_testfile);

	T_WITH_ERRNO;
	err = ftruncate(fd, 100);
	T_ASSERT_NE(err, -1, "Truncate on file: %s", g_testfile);
}
