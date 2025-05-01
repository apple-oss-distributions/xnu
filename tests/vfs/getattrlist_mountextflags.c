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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o getattrlist_mountextflags getattrlist_mountextflags.c -g -Weverything */

#include <darwintest.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <TargetConditionals.h>

#if !TARGET_OS_OSX
#define FSTYPE_LIFS  "lifs"
#endif /* !TARGET_OS_OSX */

#define FSTYPE_MSDOS "msdos"
#define FSTYPE_APFS  "apfs"
#define TEMPLATE     "/private/var/tmp/getattrlist_mountextflags_test.XXXXXXXX"

/* rdar://137970358: Disable the test for now until the root cause was determined */
#if 0
#define RUN_TEST     ((TARGET_OS_OSX || TARGET_OS_IOS) && !TARGET_OS_XR)
#else
#define RUN_TEST     0
#endif

static char template[] = TEMPLATE;
static char *testdir = NULL;
static char *output_buffer = NULL;
static char image_path[PATH_MAX];
static char mount_path[PATH_MAX];
static char disk[PATH_MAX];

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ENABLED(RUN_TEST),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

static void
get_mount_path(const char *diskid, char *path)
{
	int i, mntsize;
	struct statfs *mntbuf;
	char diskurl[NAME_MAX];

	if ((mntsize = getmntinfo(&mntbuf, MNT_NOWAIT)) == 0) {
		T_FAIL("getmntinfo failure");
		return;
	}

	snprintf(diskurl, sizeof(diskurl), "/%s", diskid);

	for (i = 0; i < mntsize; i++) {
#if TARGET_OS_OSX
		/* check if this mount is one we want */
		if (strcmp(mntbuf[i].f_fstypename, FSTYPE_MSDOS)) {
			continue;
		}
#else
		/* check if this mount is one we want */
		if (strcmp(mntbuf[i].f_fstypename, FSTYPE_LIFS)) {
			continue;
		}

		/* validate fstype */
		if (strncmp(mntbuf[i].f_mntfromname, FSTYPE_MSDOS, strlen(FSTYPE_MSDOS))) {
			continue;
		}
#endif /* TARGET_OS_OSX */

		/* validate disk */
		if (strstr(mntbuf[i].f_mntfromname, diskurl) == NULL) {
			continue;
		}

		strlcpy(path, mntbuf[i].f_mntonname, PATH_MAX);
		return;
	}

	T_FAIL("Cannot find mount path");
}

/*
 * run an external program
 */
static int
do_exec(const char *cmd)
{
	FILE *fp;
	char *pos;
	char *buffer = output_buffer;
	int output_len = PATH_MAX;

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	if (fp == NULL) {
		T_FAIL("Failed to run command");
		return -1;
	}

	/* Read the output a line at a time - output it. */
	while (fgets(buffer, output_len, fp) != NULL) {
		size_t bytes = strlen(buffer);

		buffer += bytes;
		output_len -= bytes;
	}

	/* replace last '\n' with '\0' */
	pos = strrchr(output_buffer, '\n');
	*pos = '\0';

	/* close */
	pclose(fp);
	return 0;
}

static void
cleanup(void)
{
	char args[PATH_MAX];

	if (mount_path[0] != '\0') {
		unmount(mount_path, MNT_FORCE);
	}
	if (disk[0] != '\0') {
		snprintf(args, sizeof(args), "diskutil eject %s", disk);
		do_exec(args);
	}
	if (image_path[0] != '\0') {
		unlink(image_path);
	}
	if (testdir) {
		rmdir(testdir);
	}
	if (output_buffer) {
		free(output_buffer);
	}
}

static void
test_getattrlist(const char *path, const char *fstypename, uint32_t mount_extflags)
{
	struct myattrbuf {
		uint32_t length;
		attribute_set_t returned_attrs;
		uint32_t mount_extflags;
		attrreference_t fstypename_ref;
		char fstypename[MFSTYPENAMELEN];
	} attrbuf;

	struct attrlist attrs = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_RETURNED_ATTRS,
		.volattr = ATTR_VOL_MOUNTEXTFLAGS | ATTR_VOL_FSTYPENAME,
	};

	T_LOG("Testing %s", path);

	T_ASSERT_POSIX_SUCCESS(getattrlist(path, &attrs, &attrbuf,
	    sizeof(attrbuf), FSOPT_REPORT_FULLSIZE | FSOPT_PACK_INVAL_ATTRS),
	    "Calling getattrlist");

	T_ASSERT_TRUE(attrbuf.length <= sizeof(attrbuf),
	    "Asserting attrbuf.length <= sizeof(attrbuf)");

	/* Verifing ATTR_VOL_FSTYPENAME and ATTR_VOL_MOUNTEXTFLAGS enabled */
	T_ASSERT_BITS_SET(attrbuf.returned_attrs.volattr, ATTR_VOL_FSTYPENAME | ATTR_VOL_MOUNTEXTFLAGS,
	    "Asserting ATTR_VOL_FSTYPENAME and ATTR_VOL_MOUNTEXTFLAGS was returned");

	/* Verifing ATTR_VOL_FSTYPENAME content */
	T_ASSERT_EQ(strncmp(attrbuf.fstypename, fstypename, strlen(fstypename)), 0,
	    "Asserting that fstypename matches");

	/* Verifing ATTR_VOL_MOUNTEXTFLAGS content */
	T_ASSERT_EQ(attrbuf.mount_extflags, mount_extflags,
	    "Asserting that mount_extflags matches");
}

T_DECL(getattrlist_mountextflags,
    "test ATTR_VOL_MOUNTEXTFLAGS")
{
#if (!RUN_TEST)
	T_SKIP("Test disabled for this platform");
#endif

	char *diskp = NULL;
	char args[PATH_MAX];

	image_path[0] = mount_path[0] = disk[0] = '\0';

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Allocate output buffer */
	output_buffer = malloc(PATH_MAX);

	/* Create test directory */
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	/* Create image path */
	snprintf(image_path, sizeof(image_path), "%s/msdos.dmg", testdir);

	/* Create disk image */
	snprintf(args, sizeof(args), "diskimagetool create -fs none -s 1m %s", image_path);
	T_ASSERT_POSIX_SUCCESS(do_exec(args), "Creating disk image %s", image_path);

	/* Attach disk image */
	snprintf(args, sizeof(args), "diskimagetool attach --external %s", image_path);
	T_ASSERT_POSIX_SUCCESS(do_exec(args), "Attaching disk image %s", image_path);

	/* Extract device identifier */
	T_ASSERT_POSIX_NOTNULL((diskp = strstr(output_buffer, "disk")), "Extracting device identifier: %s", diskp);
	strlcpy(disk, diskp, PATH_MAX);

	/* Execute newfs_msdos disk image */
	snprintf(args, sizeof(args), "newfs_msdos -v MSDOS %s", disk);
	T_ASSERT_POSIX_SUCCESS(do_exec(args), "Executing newfs_msdos on disk %s", disk);

	/* Mount disk image */
	snprintf(args, sizeof(args), "datest --mount --device %s", disk);
	T_ASSERT_POSIX_SUCCESS(do_exec(args), "Mounting disk image");

	/* Get the mount path */
	get_mount_path(disk, mount_path);
	T_ASSERT_NE_STR(mount_path, "", "Got msdos filesystem mount path %s", mount_path);

	T_SETUPEND;

	/* Testing existing directory */
	test_getattrlist("/", FSTYPE_APFS, 0);

#if TARGET_OS_OSX
	/* Testing Data volume directory */
	test_getattrlist("/private/var/tmp/", FSTYPE_APFS, MNT_EXT_ROOT_DATA_VOL);
#endif /* TARGET_OS_OSX */

	/* Testing msdos volume directory */
#if TARGET_OS_OSX
	test_getattrlist(mount_path, FSTYPE_MSDOS, MNT_EXT_FSKIT);
#else
	test_getattrlist(mount_path, FSTYPE_LIFS, MNT_EXT_FSKIT);
#endif /* TARGET_OS_OSX */
}
