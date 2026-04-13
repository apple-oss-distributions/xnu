/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#define UT_MODULE bsd

#include <darwintest.h>

#include <sys/mount.h>
#include <sys/errno.h>
#include <sys/param.h>

#include "mocks/osfmk/mock_vfs.h"

/* Forward declaration of the function we want to test */
extern int vfs_getrealpath_with_vp(const char *path, char *realpath, size_t bufsize, vfs_context_t ctx, vnode_t *volfs_vpp);

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_RUN_CONCURRENTLY(false)
	);

T_DECL(vfs_getrealpath_nonexistent_mount,
    "Test vfs_getrealpath with nonexistent mount - should return EINVAL when filesystem ID doesn't exist")
{
	char realpath[MAXPATHLEN];
	int error;

	/* Test with a filesystem ID that doesn't exist */
	error = vfs_getrealpath_with_vp("999999/path", realpath, sizeof(realpath), NULL, NULL);
	T_EXPECT_EQ(error, EINVAL, "Nonexistent filesystem ID should return EINVAL");
}

T_DECL(vfs_getrealpath_root_alias,
    "Test vfs_getrealpath with root alias - should resolve '@' to mount root path using VFS mocking")
{
	char realpath[MAXPATHLEN];
	int error;
	vnode_t mock_vnode = (vnode_t)0x87654321; /* Mock vnode pointer */
	mount_t mock_mount = (mount_t)0x12345678; /* Mock mount pointer */

	/* Mock mount_lookupby_volfsid to return a valid mount */
	T_MOCK_SET_RETVAL(mount_lookupby_volfsid, mount_t, mock_mount);

	/* Mock vfs_getattr to succeed and set dummy values */
	T_MOCK_SET_CALLBACK(vfs_getattr, int, (mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx), {
		/* Set dummy values for VFS attributes */
		if (vfa) {
		        /* Set some common VFS attributes with dummy values */
		        vfa->f_owner = 99;
		        vfa->f_files = 99;
		}
		return 0;
	});

	/* Mock VFS_ROOT to succeed and set vnode pointer */
	T_MOCK_SET_CALLBACK(VFS_ROOT, int, (mount_t mp, vnode_t * vpp, vfs_context_t ctx), {
		*vpp = mock_vnode; /* Mock vnode pointer */
		return 0;
	});

	/* Mock build_path to return a specific path */
	T_MOCK_SET_CALLBACK(build_path, int, (vnode_t vp, char *buff, int buflen, int *outlen, int flags, vfs_context_t ctx), {
		int len;
		const char* mock_path = "/mock/root/path";

		/* Validate that vp equals the mock vnode from VFS_ROOT */
		if (vp != mock_vnode) {
		        return EINVAL;
		}

		len = (int)strlen(mock_path);
		if (len < buflen) {
		        for (int i = 0; i <= len; i++) {
		                buff[i] = mock_path[i];
			}
		        *outlen = len;
		        return 0;
		}

		return ENOENT;
	});

	/* Test with root alias (@) - should succeed with mocked mount */
	error = vfs_getrealpath_with_vp("1/@", realpath, sizeof(realpath), NULL, NULL);
	/* This should return success with the mocked mount and validate the exact path content */
	T_EXPECT_EQ(error, 0, "Root alias with valid mount should return success");
	T_EXPECT_EQ(strcmp(realpath, "/mock/root/path"), 0, "Realpath should match the mocked path exactly");
}
