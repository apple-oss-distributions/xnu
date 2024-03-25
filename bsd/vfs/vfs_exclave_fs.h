/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _VFS_EXCLAVE_FS_H_
#define _VFS_EXCLAVE_FS_H_

#include <kern/kern_types.h>

/* directory entry */
typedef struct {
	uint32_t length;
	uint32_t returned_attrs[5];
	int32_t name_offset;
	uint32_t name_length;
	uint32_t obj_type;
	uint64_t file_id;
	off_t data_length;
} __attribute__((packed)) exclave_fs_dirent_t;

/* root_id for non-EFT_EXCLAVE fs, maps to base dir */
#define EXCLAVE_FS_BASEDIR_ROOT_ID 0

/* sync operations for vfs_exclave_fs_sync() */
#define EXCLAVE_FS_SYNC_OP_BARRIER 0
#define EXCLAVE_FS_SYNC_OP_FULL 1

#define EXCLAVE_FS_REGISTER_ENTITLEMENT  "com.apple.private.vfs.exclave-fs-register"

int vfs_exclave_fs_start(void);
void vfs_exclave_fs_stop(void);

int vfs_exclave_fs_register(uint32_t fs_tag, vnode_t vp);
int vfs_exclave_fs_unregister(vnode_t vp);
int vfs_exclave_fs_get_base_dirs(void *buf, uint32_t *count);

int vfs_exclave_fs_register_path(uint32_t fs_tag, const char *base_path);
int vfs_exclave_fs_unregister_tag(uint32_t fs_tag);

int vfs_exclave_fs_root(const char *exclave_id, uint64_t *root_id);
int vfs_exclave_fs_open(uint32_t fs_tag, uint64_t root_id, const char *name, uint64_t *file_id);
int vfs_exclave_fs_close(uint32_t fs_tag, uint64_t file_id);
int vfs_exclave_fs_create(uint32_t fs_tag, uint64_t root_id, const char *name, uint64_t *file_id);
int vfs_exclave_fs_read(uint32_t fs_tag, uint64_t file_id, uint64_t file_offset, uint64_t length, void *data);
int vfs_exclave_fs_write(uint32_t fs_tag, uint64_t file_id, uint64_t file_offset, uint64_t length, void *data);
int vfs_exclave_fs_remove(uint32_t fs_tag, uint64_t root_id, const char *name);
int vfs_exclave_fs_sync(uint32_t fs_tag, uint64_t file_id, uint64_t sync_op);
int vfs_exclave_fs_readdir(uint32_t fs_tag, uint64_t file_id, void *dirent_buf,
    uint32_t buf_size, int32_t *count);
int vfs_exclave_fs_getsize(uint32_t fs_tag, uint64_t file_id, uint64_t *size);

#endif
