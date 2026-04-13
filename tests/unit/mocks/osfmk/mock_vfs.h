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

#pragma once

#include "mocks/mock_dynamic.h"

/* Forward Declarations */

struct vfs_attr;
struct proc;
struct fileproc;
struct fileglob;
typedef struct mount * mount_t;
typedef struct vnode * vnode_t;
typedef struct vfs_context * vfs_context_t;

/* VFS mocks - using generic types to avoid conflicts */

T_MOCK_DECLARE(
	mount_t,
	mount_lookupby_volfsid,
	(int volfs_id, int withref));

T_MOCK_DECLARE(
	void,
	vfs_unbusy,
	(mount_t mp));

T_MOCK_DECLARE(
	int,
	VFS_ROOT,
	(mount_t mp, vnode_t *vpp, vfs_context_t ctx));

T_MOCK_DECLARE(
	int,
	VFS_VGET,
	(mount_t mp, unsigned long long ino, vnode_t *vpp, vfs_context_t ctx));

T_MOCK_DECLARE(
	int,
	build_path,
	(vnode_t vp, char *buff, int buflen, int *outlen, int flags, vfs_context_t ctx));

T_MOCK_DECLARE(
	int,
	vnode_issubdir,
	(vnode_t vp, vnode_t dvp, int *is_subdir, vfs_context_t ctx));

T_MOCK_DECLARE(
	int,
	VFS_GETATTR,
	(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx));

T_MOCK_DECLARE(
	int,
	vfs_getattr,
	(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx));

T_MOCK_DECLARE(
	int,
	vnode_put,
	(vnode_t vp));

T_MOCK_DECLARE(
	int,
	vnode_tag,
	(vnode_t vp));

T_MOCK_DECLARE(
	int,
	vnode_getwithref,
	(vnode_t vp));

T_MOCK_DECLARE(
	struct proc *,
	current_proc,
	(void));

T_MOCK_DECLARE(
	vfs_context_t,
	vfs_context_current,
	(void));

T_MOCK_DECLARE(
	int,
	fp_lookup,
	(struct proc *p, int fd, struct fileproc **fpp, int locked));

T_MOCK_DECLARE(
	void *,
	fg_get_data_volatile,
	(struct fileglob *fg));

T_MOCK_DECLARE(
	int,
	fp_drop,
	(struct proc *p, int fd, struct fileproc *fp, int locked));

T_MOCK_DECLARE(
	int,
	nullfs_getbackingvnode,
	(vnode_t vp, vnode_t *out_vp));
