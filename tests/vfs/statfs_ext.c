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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -lsandbox -ldarwintest -o statfs_ext statfs_ext.c */

#include <stdlib.h>
#include <fcntl.h>
#include <System/sys/mount.h>
#include <sandbox/libsandbox.h>
#include <sys/stat.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define RUN_TEST     TARGET_OS_OSX

#define FSTYPE_DEVFS "devfs"
static char template[MAXPATHLEN];
static char *testdir = NULL;
static sandbox_params_t params = NULL;
static sandbox_profile_t profile = NULL;

#define TEST_MODE_STATFS  0
#define TEST_MODE_FSTATFS 1

static const char *flag_name[] =
{ "0", "STATFS_EXT_NOBLOCK" };

static const char *mode_name[] =
{ "TEST_MODE_STATFS", "TEST_MODE_FSTATFS" };

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (profile) {
		sandbox_free_profile(profile);
	}
	if (params) {
		sandbox_free_params(params);
	}
	if (testdir) {
		unmount(testdir, MNT_FORCE);
		rmdir(testdir);
	}
}

static void
statfs_compare(const char *path, struct statfs *sfs_ext, int mode, int flag, int expected_err)
{
	int fd;
	struct statfs sfs = {};

	T_LOG("Testing: path %s, sfs_ext %p, mode %s, flag 0x%x, expected_err %d", path, (void *) sfs_ext, mode_name[mode], (unsigned int)flag, expected_err);

	if (sfs_ext) {
		bzero(sfs_ext, sizeof(struct statfs));
	}

	switch (mode) {
	case TEST_MODE_STATFS:
		if (expected_err) {
			T_ASSERT_POSIX_FAILURE(statfs_ext(path, sfs_ext, flag), expected_err, "Verifying that statfs_ext() fails with %d (%s)", expected_err, strerror(expected_err));
		} else {
			T_ASSERT_POSIX_SUCCESS(statfs_ext(path, sfs_ext, flag), "Calling statfs_ext() using the %s flag", flag_name[flag]);
			T_ASSERT_POSIX_SUCCESS(statfs(path, &sfs), "Calling stafs()");
		}
		break;
	case TEST_MODE_FSTATFS:
		T_ASSERT_POSIX_SUCCESS(fd = open(path, O_DIRECTORY | O_RDONLY), "Opening %s", path);
		if (expected_err) {
			T_ASSERT_POSIX_FAILURE(fstatfs_ext(fd, sfs_ext, flag), expected_err, "Verifying that fstatfs_ext() fails with %d (%s)", expected_err, strerror(expected_err));
		} else {
			T_ASSERT_POSIX_SUCCESS(fstatfs(fd, &sfs), "Calling fstafs()");
			T_ASSERT_POSIX_SUCCESS(fstatfs_ext(fd, sfs_ext, flag), "Calling fstatfs_ext() using the %s flag", flag_name[flag]);
		}
		T_ASSERT_POSIX_SUCCESS(close(fd), "Closing fd");
		break;
	default:
		T_FAIL("Unknown test mode");
	}

	if (expected_err) {
		return;
	}

	T_ASSERT_EQ(sfs.f_fsid.val[0], sfs_ext->f_fsid.val[0], "Validating f_fsid.val[0]");
	T_ASSERT_EQ(sfs.f_fsid.val[1], sfs_ext->f_fsid.val[1], "Validating f_fsid.val[1]");
	T_ASSERT_EQ(sfs.f_owner, sfs_ext->f_owner, "Validating f_owner");
	T_ASSERT_EQ(sfs.f_type, sfs_ext->f_type, "Validating f_type");
	T_ASSERT_EQ(sfs.f_flags, sfs_ext->f_flags, "Validating f_flags");
	T_ASSERT_EQ(sfs.f_fssubtype, sfs_ext->f_fssubtype, "Validating f_fssubtype");
	T_ASSERT_EQ_STR(sfs.f_fstypename, sfs_ext->f_fstypename, "Validating f_fstypename");
	T_ASSERT_EQ_STR(sfs.f_mntonname, sfs_ext->f_mntonname, "Validating f_mntonname");
	T_ASSERT_EQ_STR(sfs.f_mntfromname, sfs_ext->f_mntfromname, "Validating f_mntfromname");
	T_ASSERT_EQ(sfs.f_flags_ext, sfs_ext->f_flags_ext, "Validating f_flags_ext");
}

T_DECL(statfs_ext,
    "test statfs_ext and fstatfs_ext",
    T_META_ENABLED(RUN_TEST), T_META_ASROOT(false))
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	struct statfs sfs_ext;

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/statfs_ext-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, testdir, MNT_RDONLY, NULL), "Mounting temporary %s mount using path %s", FSTYPE_DEVFS, testdir);

	T_SETUPEND;

	/* Test fstatfs_ext() with invalid flags */
	statfs_compare("/dev", &sfs_ext, TEST_MODE_STATFS, 0x10, EINVAL);
	statfs_compare(testdir, &sfs_ext, TEST_MODE_FSTATFS, STATFS_EXT_NOBLOCK | 0x8, EINVAL);

	/* Test invalid inputs */
	statfs_compare(NULL, &sfs_ext, TEST_MODE_STATFS, STATFS_EXT_NOBLOCK, EFAULT);
	statfs_compare("/", NULL, TEST_MODE_STATFS, STATFS_EXT_NOBLOCK, EFAULT);
	statfs_compare("/dev", NULL, TEST_MODE_FSTATFS, STATFS_EXT_NOBLOCK, EFAULT);

	/* Test fstatfs_ext() with zero flags */
	statfs_compare("/", &sfs_ext, TEST_MODE_STATFS, 0, 0);
	statfs_compare("/private/var/tmp", &sfs_ext, TEST_MODE_FSTATFS, 0, 0);

	/* Test fstatfs_ext() with the STATFS_EXT_NOBLOCK flag */
	statfs_compare("/", &sfs_ext, TEST_MODE_STATFS, STATFS_EXT_NOBLOCK, 0);
	statfs_compare("/dev", &sfs_ext, TEST_MODE_STATFS, STATFS_EXT_NOBLOCK, 0);
	statfs_compare("/private/var/tmp", &sfs_ext, TEST_MODE_FSTATFS, STATFS_EXT_NOBLOCK, 0);
	statfs_compare(testdir, &sfs_ext, TEST_MODE_FSTATFS, STATFS_EXT_NOBLOCK, 0);
}

static void
create_profile_string_SYS_fgetattrlist(char *buff, size_t size)
{
	snprintf(buff, size, "(version 1) \n\
                          (allow default) \n\
                          (import \"system.sb\") \n\
                          (deny syscall-unix (syscall-number SYS_getattrlist) (syscall-number SYS_fgetattrlist)) \n");
}

T_DECL(statfs_ext_sandbox_SYS_getattrlist,
    "test statfs_ext and fstatfs_ext when the sandbox profile denies getattrlist/fgetattrlist",
    T_META_ENABLED(false), T_META_ASROOT(true))
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	struct statfs sfs_ext;
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

	/* Create sandbox variables */
	T_ASSERT_POSIX_NOTNULL(params = sandbox_create_params(), "Creating Sandbox params object");
	create_profile_string_SYS_fgetattrlist(profile_string, sizeof(profile_string));
	T_ASSERT_POSIX_NOTNULL(profile = sandbox_compile_string(profile_string, params, &sberror), "Creating Sandbox profile object");

	T_SETUPEND;

	/* Apply sandbox profile */
	T_ASSERT_POSIX_SUCCESS(sandbox_apply(profile), "Applying Sandbox profile");

	/* Test fstatfs_ext() with zero flags */
	statfs_compare("/", &sfs_ext, TEST_MODE_STATFS, STATFS_EXT_NOBLOCK, 0);

	/* Test fstatfs_ext() with the STATFS_EXT_NOBLOCK flag */
	statfs_compare("/private/var/tmp", &sfs_ext, TEST_MODE_FSTATFS, STATFS_EXT_NOBLOCK, 0);
}


static void
create_profile_string_root_metadata(char *buff, size_t size)
{
	snprintf(buff, size, "(version 1) \n\
                          (allow default) \n\
                          (import \"system.sb\") \n\
                          (deny file-read-metadata (path \"/\")) \n");
}

T_DECL(statfs_ext_sandbox_root_metadata,
    "test statfs_ext and fstatfs_ext when the sandbox profile denies file-read-metadata for root",
    T_META_ASROOT(true))
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	struct statfs sfs_ext;
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

	/* Create sandbox variables */
	T_ASSERT_POSIX_NOTNULL(params = sandbox_create_params(), "Creating Sandbox params object");
	create_profile_string_root_metadata(profile_string, sizeof(profile_string));
	T_ASSERT_POSIX_NOTNULL(profile = sandbox_compile_string(profile_string, params, &sberror), "Creating Sandbox profile object");

	T_SETUPEND;

	/* Apply sandbox profile */
	T_ASSERT_POSIX_SUCCESS(sandbox_apply(profile), "Applying Sandbox profile");

	/* Test fstatfs_ext() with zero flags */
	statfs_compare("/", &sfs_ext, TEST_MODE_STATFS, STATFS_EXT_NOBLOCK, 0);

	/* Test fstatfs_ext() with the STATFS_EXT_NOBLOCK flag */
	statfs_compare("/private/var/tmp", &sfs_ext, TEST_MODE_FSTATFS, STATFS_EXT_NOBLOCK, 0);
}
