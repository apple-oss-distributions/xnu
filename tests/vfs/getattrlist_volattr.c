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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o getattrlist_volattr getattrlist_volattr.c */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/attr.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <darwintest.h>
#include <darwintest_utils.h>

static char template[MAXPATHLEN];
#define RUN_TEST     ((TARGET_OS_OSX || TARGET_OS_IOS) && !TARGET_OS_XR)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false),
	T_META_ENABLED(RUN_TEST));

static int
getMode(const char *path, bool targetMountpointInstead)
{
	struct AttributeBuffer {
		uint32_t length;
		uint32_t mode;
	} __attribute__((aligned(4), packed)) attrBuf = {};

	struct attrlist attrs = {};
	attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrs.commonattr = ATTR_CMN_ACCESSMASK;
	if (targetMountpointInstead) {
		attrs.volattr = ATTR_VOL_INFO;
	}

	if (getattrlist(path, &attrs, &attrBuf, sizeof(attrBuf), FSOPT_RETURN_REALDEV) != 0) {
		return -1;
	}

	return attrBuf.mode;
}

T_DECL(getattrlist_volattr_acl_bypass,
    "test that volume attributes respect ACL permissions")
{
	char *mount_path;
	char test_file[PATH_MAX];
	struct stat sb;
	int mode_result;
	int fd;

	/* Skip test if not running as root */
	if (getuid() != 0) {
		T_SKIP("Test requires root privileges for mounting and ACL operations");
	}

	T_SETUPBEGIN;

	/* Create unique mount path using dt_tmpdir */
	snprintf(template, sizeof(template), "%s/getattrlist_volattr_acl_bypass-XXXXXX", dt_tmpdir());

	/* Create mount directory */
	T_ASSERT_POSIX_NOTNULL((mount_path = mkdtemp(template)), "Creating test root directory");
	T_ASSERT_POSIX_SUCCESS(chmod(mount_path, 0000), "Setup: setting restrictive permissions on mount directory");

	/* Create test file name */
	snprintf(test_file, sizeof(test_file), "%s/x", mount_path);

	/* Mount tmpfs */
	char mount_tmpfs_cmd[256];
	snprintf(mount_tmpfs_cmd, sizeof(mount_tmpfs_cmd), "/sbin/mount_tmpfs -s 50m %s", mount_path);
	T_ASSERT_POSIX_SUCCESS(system(mount_tmpfs_cmd), "Mounting tmpfs mount -> Should PASS");

	/* Set permissions */
	T_ASSERT_POSIX_SUCCESS(chmod(mount_path, 0777), "Setup: setting open permissions on mounted filesystem");

	/* Create and set ACL to deny readattr for everyone using system command */
	char acl_cmd[512];
	snprintf(acl_cmd, sizeof(acl_cmd), "chmod +a 'group:everyone deny readattr' %s", mount_path);
	T_ASSERT_POSIX_SUCCESS(system(acl_cmd), "Setup: setting deny readattr ACL should succeed");

	/* Switch to non-root user for testing */
	T_ASSERT_POSIX_SUCCESS(seteuid(501), "Setup: switching to non-root user");

	T_SETUPEND;

	/* Verify that stat fails due to ACL */
	T_EXPECT_POSIX_FAILURE(stat(mount_path, &sb), EACCES, "stat should fail on mountpoint with deny readattr ACL");

	/* Create a test file in the mounted filesystem */
	fd = open(test_file, O_CREAT | O_WRONLY, 0644);
	T_ASSERT_POSIX_SUCCESS(fd, "Creating test file in mounted filesystem");
	close(fd);

	/* Test: getattrlist with volume attributes should respect ACL and fail */
	mode_result = getMode(test_file, true);
	T_EXPECT_EQ(mode_result, -1, "getattrlist with volume attributes should fail due to ACL restriction");
	T_EXPECT_EQ(errno, EACCES, "getattrlist should fail with EACCES due to ACL restriction");

	/* Test: getattrlist without volume attributes should work on the file itself */
	mode_result = getMode(test_file, false);
	T_EXPECT_NE(mode_result, -1, "getattrlist without volume attributes should succeed on file");

	/* Cleanup */
	T_ASSERT_POSIX_SUCCESS(seteuid(0), "Cleanup: switching back to root");
	unlink(test_file);
	unmount(mount_path, MNT_FORCE);
	rmdir(mount_path);
}
