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

#include <sys/errno.h>
#include <sys/types.h>

#include "unit_test_utils.h"
#include "mock_vfs.h"

/* VFS mocks */
T_MOCK_F(mount_t,
mount_lookupby_volfsid,
(int volfs_id, int withref),
(volfs_id, withref))
{
	return NULL;
}

T_MOCK_F(void,
vfs_unbusy,
(mount_t mp), (mp))
{
	/* no-op by default */
}

T_MOCK_F(int,
VFS_ROOT,
(mount_t mp, vnode_t *vpp, vfs_context_t ctx),
(mp, vpp, ctx))
{
	return ENOTSUP;
}

T_MOCK_F(int,
VFS_VGET,
(mount_t mp, unsigned long long ino, vnode_t *vpp, vfs_context_t ctx),
(mp, ino, vpp, ctx))
{
	return ENOTSUP;
}

T_MOCK_F(int,
build_path,
(vnode_t vp, char *buff, int buflen, int *outlen, int flags, vfs_context_t ctx),
(vp, buff, buflen, outlen, flags, ctx))
{
	return ENOTSUP;
}

T_MOCK_F(int,
vnode_issubdir,
(vnode_t vp, vnode_t dvp, int *is_subdir, vfs_context_t ctx),
(vp, dvp, is_subdir, ctx))
{
	return ENOTSUP;
}

T_MOCK_F(int,
VFS_GETATTR,
(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx),
(mp, vfa, ctx))
{
	return ENOTSUP;
}

T_MOCK_F(int,
vfs_getattr,
(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx),
(mp, vfa, ctx))
{
	return ENOTSUP;
}

T_MOCK_F(int,
vnode_put,
(vnode_t vp),
(vp))
{
	return 0;
}

T_MOCK_F(int,
vnode_tag,
(vnode_t vp),
(vp))
{
	return 0;
}

T_MOCK_F(int,
vnode_getwithref,
(vnode_t vp),
(vp))
{
	return 0;
}

T_MOCK_F(vfs_context_t,
vfs_context_current,
(void),
())
{
	return (vfs_context_t)0x12345678; /* Mock context */
}

T_MOCK_F(int,
fp_lookup,
(struct proc *p, int fd, struct fileproc **fpp, int locked),
(p, fd, fpp, locked))
{
	return EBADF; /* Default: bad file descriptor */
}

T_MOCK_F(void *,
fg_get_data_volatile,
(struct fileglob *fg),
(fg))
{
	return NULL; /* Default: no data */
}

T_MOCK_F(int,
fp_drop,
(struct proc *p, int fd, struct fileproc *fp, int locked),
(p, fd, fp, locked))
{
	return 0; /* Default: success */
}

T_MOCK_F(int,
nullfs_getbackingvnode,
(vnode_t vp, vnode_t *out_vp),
(vp, out_vp))
{
	return ENOENT; /* Default: not found */
}
