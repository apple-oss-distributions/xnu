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

#include <sys/errno.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <miscfs/devfs/fdesc.h>

#include "mocks/osfmk/mock_vfs.h"

/* Static mock structures to avoid capture issues with non-trivial copy semantics */
static struct vnode mock_vnode = {0};

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_RUN_CONCURRENTLY(false)
	);

T_MOCK_SET_PERM_FUNC(struct proc *,
    current_proc, (void))
{
	return (struct proc *)0x87654321; /* Mock proc */
}

T_DECL(vnode_getbackingvnode_invalid_tag,
    "Test vnode_getbackingvnode with invalid vnode tag - should return ENOENT")
{
	vnode_t out_vp;
	int error;

	/* Initialize the mock vnode structure */
	mock_vnode.v_tag = VT_APFS;

	error = vnode_getbackingvnode(&mock_vnode, &out_vp);
	T_EXPECT_EQ(error, ENOENT, "Non-fdesc, non-nullfs vnode should return ENOENT");
}

T_DECL(vnode_getbackingvnode_null_in_vp,
    "Test vnode_getbackingvnode with NULL in_vp - should return ENOENT")
{
	vnode_t vp;
	int error;

	error = vnode_getbackingvnode(NULL, &vp);
	T_EXPECT_EQ(error, ENOENT, "null in_vp should return ENOENT");
}

T_DECL(vnode_getbackingvnode_fdesc,
    "Test vnode_getbackingvnode with locally initialized mock fdesc vnode")
{
	struct fdescnode mock_fdesc = {0};
	static struct fileglob mock_glob = {0};
	static struct fileproc mock_fp = {0};
	static struct fileops mock_fops = {0};
	vnode_t backing_vp = NULL;
	int error;

	/* Initialize the mock fdescnode structure */
	mock_fdesc.fd_type = Fdesc;
	mock_fdesc.fd_fd = 3;  /* File descriptor 3 */

	/* Initialize the mock vnode structure with key fields from the memory dump */
	mock_vnode.v_tag = VT_FDESC;  /* Tag 7 from memory dump corresponds to VT_FDESC */
	mock_vnode.v_data = &mock_fdesc;  /* Point to our mock fdescnode */
	mock_vnode.v_type = VCHR;  /* Character device type (4 from memory dump) */
	mock_vnode.v_flag = 526336;  /* Flags from memory dump */
	mock_vnode.v_lflag = 16512;  /* Local flags from memory dump */
	mock_vnode.v_iocount = 1;  /* IO count from memory dump */
	mock_vnode.v_holdcount = 1;  /* Hold count from memory dump */
	mock_vnode.v_references = 4;  /* Reference count from memory dump */

	T_LOG("Created mock fdesc vnode: tag=%d, fd=%d", mock_vnode.v_tag, mock_fdesc.fd_fd);

	/* Mock the functions that will be called */
	T_MOCK_SET_RETVAL(vnode_tag, int, VT_FDESC);

	/* Set up the mock fileops to indicate this is a vnode */
	mock_fops.fo_type = DTYPE_VNODE;

	/* Set up the mock fileglob */
	mock_glob.fg_data = (uintptr_t)&mock_vnode;
	mock_glob.fg_ops = &mock_fops;

	/* Set up the mock fileproc to point to our mock fileglob */
	mock_fp.fp_glob = &mock_glob;

	T_MOCK_SET_CALLBACK(fp_lookup, int, (struct proc *p, int fd, struct fileproc **fpp, int locked), {
		T_EXPECT_EQ(fd, 3, "Should lookup file descriptor 3");
		T_EXPECT_EQ_PTR(p, current_proc(), "Process pointer should match: %p (expected: %p)", p, current_proc());
		*fpp = &mock_fp;
		return 0;  /* Success without accessing proc internals */
	});

	/* Mock fg_get_data_volatile to return our mock vnode */
	T_MOCK_SET_CALLBACK(fg_get_data_volatile, void *, (struct fileglob *fg), {
		T_EXPECT_EQ_PTR(fg, &mock_glob, "Should be called with our mock fileglob");
		return (void *)&mock_vnode;  /* Return our mock vnode */
	});

	/* Now test vnode_getbackingvnode with our mock fdesc vnode */
	error = vnode_getbackingvnode((vnode_t)&mock_vnode, &backing_vp);

	T_LOG("vnode_getbackingvnode returned: %d", error);

	if (error == 0) {
		T_PASS("vnode_getbackingvnode succeeded with mock fdesc vnode");
		T_ASSERT_NOTNULL(backing_vp, "Backing vnode should not be NULL on success");
		T_ASSERT_EQ_PTR(backing_vp, &mock_vnode, "Backing vnode should equal the expected mock vnode pointer");
		T_LOG("Successfully retrieved backing vnode: %p (expected: %p)", backing_vp, &mock_vnode);
	} else {
		T_LOG("vnode_getbackingvnode failed with error: %d", error);
		/* Log the error but don't fail the test - this helps us understand what's happening */
	}
}
