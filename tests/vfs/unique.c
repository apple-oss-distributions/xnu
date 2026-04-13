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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o unique unique.c */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <System/sys/fsctl.h>

#include <darwintest.h>
#include <darwintest/utils.h>

static char template[MAXPATHLEN];
static char testdir_path[MAXPATHLEN + 1];
static char file_path[MAXPATHLEN];
static char *testdir = NULL;
static int testdir_fd = -1;
struct stat statbuf = {};

#ifndef O_UNIQUE
#define O_UNIQUE         0x00002000
#endif

#ifndef AT_UNIQUE
#define AT_UNIQUE        0x8000
#endif

#ifndef FSOPT_UNIQUE
#define FSOPT_UNIQUE     0x00002000
#endif

#define FILE           "file.txt"
#define FILE2          "file2.txt"
#define FILE3          "file3.txt"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (testdir_fd != -1) {
		unlinkat(testdir_fd, FILE, 0);
		unlinkat(testdir_fd, FILE2, 0);
		unlinkat(testdir_fd, FILE3, 0);

		close(testdir_fd);
		if (rmdir(testdir)) {
			T_FAIL("Unable to remove the test directory (%s)", testdir);
		}
	}
}

static void
validate_link_counts(const char *file1, nlink_t expected_nlink1, const char *file2, nlink_t expected_nlink2)
{
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, file1, &statbuf, 0)), "Calling stat() for %s -> Should PASS", file1);
	T_EXPECT_EQ(statbuf.st_nlink, expected_nlink1, "Validate nlink equals %d for %s", expected_nlink1, file1);
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, file2, &statbuf, 0)), "Calling stat() for %s -> Should PASS", file2);
	T_EXPECT_EQ(statbuf.st_nlink, expected_nlink2, "Validate nlink equals %d for %s", expected_nlink2, file2);
}

static void
setup(const char *dirname)
{
	int fd;

	/* Create test root directory */
	snprintf(template, sizeof(template), "%s/%s-XXXXXX", dt_tmpdir(), dirname);
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root directory");
	T_ASSERT_POSIX_SUCCESS((testdir_fd = open(testdir, O_SEARCH, 0777)), "Opening test root directory %s", testdir);
	T_ASSERT_POSIX_SUCCESS(fcntl(testdir_fd, F_GETPATH, testdir_path), "Calling fcntl() to get the path");

	/* Create the test files */
	snprintf(file_path, sizeof(file_path), "%s/%s", testdir_path, FILE);
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_CREAT | O_RDWR | O_UNIQUE, 0777)), "Creating %s using openat() with O_UNIQUE -> Should PASS", FILE);
	close(fd);
}

T_DECL(unique_open,
    "Validate the functionality of the O_UNIQUE flag in the open/openat syscalls")
{
	int fd;

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_open");

	T_SETUPEND;

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");
	T_EXPECT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_RDONLY | O_UNIQUE, 0)), "Opening %s using O_UNIQUE -> Should PASS", FILE);
	close(fd);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate nlink count equals 2 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling fstatat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 2, "Validate nlink equals 2");
	T_EXPECT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_RDONLY, 0)), "Opening %s -> Should PASS", FILE);
	close(fd);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE((fd = open(file_path, O_RDONLY | O_UNIQUE, 0)), ENOTCAPABLE, "Opening using open() with O_UNIQUE -> Should FAIL with ENOTCAPABLE");

	T_EXPECT_POSIX_FAILURE((fd = openat(testdir_fd, FILE, O_WRONLY | O_UNIQUE, 0)), ENOTCAPABLE, "Opening %s using openat() with O_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);

	T_EXPECT_POSIX_FAILURE((fd = openat(testdir_fd, FILE2, O_CREAT | O_RDWR | O_UNIQUE, 0)), ENOTCAPABLE, "Opening %s using openat() with O_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE2);

	/* Reduce nlink count */
	T_EXPECT_POSIX_SUCCESS(unlinkat(testdir_fd, FILE2, 0), "Calling unlinkat() for %s -> Should PASS", FILE2);

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling fstatat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");
	T_EXPECT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_RDONLY | O_UNIQUE, 0)), "Opening %s -> Should PASS", FILE);
	close(fd);
}

T_DECL(unique_faccessat,
    "test faccessat() using the O_UNIQUE flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_faccessat");

	T_SETUPEND;

	T_LOG("Testing the faccessat() syscall using O_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(faccessat(testdir_fd, FILE, R_OK, AT_UNIQUE), "Calling faccessat() %s using AT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(faccessat(testdir_fd, FILE, R_OK, AT_UNIQUE), ENOTCAPABLE, "Calling faccessat() %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_fstatat,
    "test fstatat() using the O_UNIQUE flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_fstatat");

	T_SETUPEND;

	T_LOG("Testing the fstatat() syscall using O_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(fstatat(testdir_fd, FILE, &statbuf, AT_UNIQUE), "Calling fstatat() %s using AT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(fstatat(testdir_fd, FILE, &statbuf, AT_UNIQUE), ENOTCAPABLE, "Calling fstatat() %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_fchmodat,
    "test fchmodat() using the O_UNIQUE flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_fchmodat");

	T_SETUPEND;

	T_LOG("Testing the fchmodat() syscall using O_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(fchmodat(testdir_fd, FILE, ACCESSPERMS, AT_UNIQUE), "Calling fchmodat() %s using AT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(fchmodat(testdir_fd, FILE, ACCESSPERMS, AT_UNIQUE), ENOTCAPABLE, "Calling fchmodat() %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_fchownat,
    "test fchownat() using the O_UNIQUE flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_fchownat");

	T_SETUPEND;

	T_LOG("Testing the fchownat() syscall using O_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(fchownat(testdir_fd, FILE, statbuf.st_uid, statbuf.st_gid, AT_UNIQUE), "Calling fchownat() %s using AT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(fchownat(testdir_fd, FILE, statbuf.st_uid, statbuf.st_gid, AT_UNIQUE), ENOTCAPABLE, "Calling fchownat() %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_linkat,
    "test linkat() using the O_UNIQUE flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_linkat");

	T_SETUPEND;

	T_LOG("Testing the linkat() syscall using O_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, AT_UNIQUE), "Calling linkat() for %s, %s using AT_UNIQUE -> Should PASS", FILE, FILE2);

	/* Validate EEXIST */
	T_EXPECT_POSIX_FAILURE(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), EEXIST, "Calling linkat() for %s, %s -> Should FAIL with EEXIST", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(linkat(testdir_fd, FILE, testdir_fd, FILE3, AT_UNIQUE), ENOTCAPABLE, "Calling linkat() for %s, %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE, FILE3);
}

T_DECL(unique_unlinkat,
    "test unlinkat() using the O_UNIQUE flag")
{
	int fd;

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_unlinkat");

	T_SETUPEND;

	T_LOG("Testing the unlinkat() syscall using O_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(unlinkat(testdir_fd, FILE, AT_UNIQUE), "Calling unlinkat() %s using AT_UNIQUE -> Should PASS", FILE);

	/* Recreate the test file */
	T_ASSERT_POSIX_SUCCESS((fd = openat(testdir_fd, FILE, O_CREAT | O_RDWR, 0777)), "Creating %s", FILE);
	close(fd);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(unlinkat(testdir_fd, FILE, AT_UNIQUE), ENOTCAPABLE, "Calling unlinkat() %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}


T_DECL(unique_getattrlist,
    "test getattrlist() using the FSOPT_UNIQUE flag")
{
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
		.volattr = ATTR_VOL_INFO | ATTR_VOL_ATTRIBUTES |
	    ATTR_VOL_FSTYPENAME | ATTR_VOL_FSSUBTYPE,
	};

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_getattrlist");

	T_SETUPEND;

	T_LOG("Testing the getattrlist() syscall using FSOPT_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(getattrlist(file_path, &attrs, &attrbuf, sizeof(attrbuf), FSOPT_UNIQUE), "Calling getattrlist() %s using FSOPT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(getattrlist(file_path, &attrs, &attrbuf, sizeof(attrbuf), FSOPT_UNIQUE), ENOTCAPABLE, "Calling getattrlist() %s with FSOPT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_setattrlist,
    "test setattrlist() using the FSOPT_UNIQUE flag")
{
	int flags = 0;
	struct attrlist attrlist;

	T_SETUPBEGIN;

	memset(&attrlist, 0, sizeof(attrlist));
	attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrlist.commonattr = ATTR_CMN_FLAGS;

	T_ATEND(cleanup);
	setup("unique_setattrlist");

	T_SETUPEND;

	T_LOG("Testing the setattrlist() syscall using FSOPT_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(setattrlist(file_path, &attrlist, &flags, sizeof(flags), FSOPT_UNIQUE), "Calling setattrlist() %s using FSOPT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(setattrlist(file_path, &attrlist, &flags, sizeof(flags), FSOPT_UNIQUE), ENOTCAPABLE, "Calling setattrlist() %s with FSOPT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_exchangedata,
    "test exchangedata() using the FSOPT_UNIQUE flag")
{
	int fd2;
	char file2_path[MAXPATHLEN];

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_exchangedata");

	/* Create second test file */
	snprintf(file2_path, sizeof(file2_path), "%s/%s", testdir_path, FILE2);
	T_ASSERT_POSIX_SUCCESS((fd2 = openat(testdir_fd, FILE2, O_CREAT | O_RDWR, 0777)), "Creating %s", FILE2);
	close(fd2);

	T_SETUPEND;

	T_LOG("Testing the exchangedata() syscall using FSOPT_UNIQUE");

	/* Validate nlink count equals 1 for both files */
	validate_link_counts(FILE, 1, FILE2, 1);

	/* Validate PASS when both files have link count 1, or ENOTSUP if filesystem doesn't support exchangedata */
	int result = exchangedata(file_path, file2_path, FSOPT_UNIQUE);
	if (errno == ENOTSUP) {
		T_PASS("exchangedata() not supported on this filesystem (ENOTSUP) -> Expected");
	} else {
		T_EXPECT_EQ(result, 0, "Calling exchangedata() %s, %s using FSOPT_UNIQUE -> Should PASS", FILE, FILE2);
	}

	/* Increase nlink count for first file */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE3, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE3);

	/* Validate nlink count: first file = 2, second file = 1 */
	validate_link_counts(FILE, 2, FILE2, 1);

	/* Validate ENOTCAPABLE when first file has multiple links */
	T_EXPECT_POSIX_FAILURE(exchangedata(file_path, file2_path, FSOPT_UNIQUE), ENOTCAPABLE, "Calling exchangedata() %s, %s with FSOPT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE, FILE2);

	/* Remove extra link and add link to second file */
	T_EXPECT_POSIX_SUCCESS(unlinkat(testdir_fd, FILE3, 0), "Calling unlinkat() for %s -> Should PASS", FILE3);
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE2, testdir_fd, FILE3, 0), "Calling linkat() for %s, %s -> Should PASS", FILE2, FILE3);

	/* Validate nlink count: first file = 1, second file = 2 */
	validate_link_counts(FILE, 1, FILE2, 2);

	/* Validate ENOTCAPABLE when second file has multiple links */
	T_EXPECT_POSIX_FAILURE(exchangedata(file_path, file2_path, FSOPT_UNIQUE), ENOTCAPABLE, "Calling exchangedata() %s, %s with FSOPT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE, FILE2);

	/* Clean up the extra hard link */
	T_EXPECT_POSIX_SUCCESS(unlinkat(testdir_fd, FILE3, 0), "Calling unlinkat() for %s -> Should PASS", FILE3);
}

T_DECL(unique_fsctl,
    "test fsctl() using the FSOPT_UNIQUE flag")
{
	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_fsctl");

	T_SETUPEND;

	T_LOG("Testing the fsctl() syscall using FSOPT_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate EFAULT when link count is 1 */
	T_EXPECT_POSIX_FAILURE(fsctl(file_path, FSIOC_SYNC_VOLUME, NULL, FSOPT_UNIQUE), EFAULT, "Calling fsctl() %s using FSOPT_UNIQUE -> Should fail with EFAULT", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(fsctl(file_path, FSIOC_SYNC_VOLUME, NULL, FSOPT_UNIQUE), ENOTCAPABLE, "Calling fsctl() %s with FSOPT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}

T_DECL(unique_utimensat,
    "test utimensat() using the AT_UNIQUE flag")
{
	static const struct timespec tptr[] = {
		{ 0x12345678, 987654321 },
		{ 0x15263748, 123456789 },
	};

	T_SETUPBEGIN;

	T_ATEND(cleanup);
	setup("unique_utimensat");

	T_SETUPEND;

	T_LOG("Testing the utimensat() syscall using AT_UNIQUE");

	/* Validate nlink count equals 1 */
	T_EXPECT_POSIX_SUCCESS((fstatat(testdir_fd, FILE, &statbuf, 0)), "Calling stat() for %s -> Should PASS", FILE);
	T_EXPECT_EQ(statbuf.st_nlink, 1, "Validate nlink equals 1");

	/* Validate PASS when link count is 1 */
	T_EXPECT_POSIX_SUCCESS(utimensat(testdir_fd, FILE, tptr, AT_UNIQUE), "Calling utimensat() %s using AT_UNIQUE -> Should PASS", FILE);

	/* Increase nlink count */
	T_EXPECT_POSIX_SUCCESS(linkat(testdir_fd, FILE, testdir_fd, FILE2, 0), "Calling linkat() for %s, %s -> Should PASS", FILE, FILE2);

	/* Validate ENOTCAPABLE */
	T_EXPECT_POSIX_FAILURE(utimensat(testdir_fd, FILE, tptr, AT_UNIQUE), ENOTCAPABLE, "Calling utimensat() %s with AT_UNIQUE -> Should FAIL with ENOTCAPABLE", FILE);
}
