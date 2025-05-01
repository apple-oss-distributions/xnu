/*
 * Copyright (c) 2022-2024 Apple Inc. All rights reserved.
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

#include <string.h>
#include <sys/fcntl.h>
#include <sys/fsctl.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/uio_internal.h>
#include <sys/fsevents.h>
#include <kern/kalloc.h>
#include <vfs/vfs_exclave_fs.h>
#include <miscfs/devfs/devfs.h>
#include <pexpert/pexpert.h>

__private_extern__ int unlink1(vfs_context_t, vnode_t, user_addr_t,
    enum uio_seg, int);

// Flags for open vnodes, currently used only in DEVELOPMENT or DEBUG builds
#define OV_EXCLAVE_BASE 1
#define OV_FORCE_ENOSPC 2 // When this flag is set, writes fail with ENOSPC

struct open_vnode {
	LIST_ENTRY(open_vnode) chain;
	vnode_t vp;
	dev_t dev;
	uint64_t file_id;
	uint32_t open_count;
#if (DEVELOPMENT || DEBUG)
	uint32_t flags;
#endif
};

#define ROOT_DIR_INO_NUM 2

#define VFS_EXCLAVE_FS_BASE_DIR_GRAFT 1
#define VFS_EXCLAVE_FS_BASE_DIR_SEALED 2

typedef struct registered_fs_tag {
	LIST_ENTRY(registered_fs_tag) link;
	uint32_t fstag;
	uint32_t flags;
	vnode_t vp;
	dev_t dev;
	fsioc_graft_info_t graft_info;
} registered_fs_tag_t;

/* hash table that maps from file_id to a vnode and its open count */
typedef LIST_HEAD(open_vnode_head, open_vnode) open_vnodes_list_head_t;
static open_vnodes_list_head_t *open_vnodes_hashtbl = NULL;
static u_long open_vnodes_hashmask = 0;
static int open_vnodes_hashsize = 0;
static uint32_t num_open_vnodes = 0;

/* registered base directories */
typedef LIST_HEAD(registered_tags_head, registered_fs_tag) registered_tags_head_t;
static registered_tags_head_t *registered_tags_hash = NULL;
static uint32_t num_tags_registered = 0;
static u_long rft_hashmask;

#define REGFSTAG_HASH_WIDTH 32

static LCK_GRP_DECLARE(vfs_exclave_lck_grp, "vfs_exclave");

/* protects registered_tags list and num_tags_registered counter */
static lck_mtx_t regtag_mtx;

/* protects open vnodes hash table */
static lck_mtx_t open_vnodes_mtx;

#define HASHFUNC(dev, file_id) (((dev) + (file_id)) & open_vnodes_hashmask)
#define OPEN_VNODES_HASH(dev, file_id) (&open_vnodes_hashtbl[HASHFUNC(dev, file_id)])

#if (DEVELOPMENT || DEBUG)
static bool integrity_checks_disabled = false;
#define EXCLAVE_INTEGRITY_CHECKS_DISABLED_BOOTARG "disable_integrity_checks"
static bool vfs_exclave_is_enospc_exclave(const char *exclave_id);
#endif

static int exclave_fs_open_internal(uint32_t fs_tag, uint64_t root_id,
    const char *path, int flags, uint32_t ov_flags, uint64_t *file_id);
static int vfs_exclave_fs_unregister_internal(vnode_t vp, bool take_basedir_lock);

static uint32_t
hash_fstag(uint32_t tag)
{
	return tag % (rft_hashmask + 1);
}

static registered_tags_head_t *
get_registered_tags_chain(uint32_t tag)
{
	return registered_tags_hash + hash_fstag(tag);
}

/*
 * Get the fsid and fileid attributes of the given vnode.
 */
static int
get_vnode_info(vnode_t vp, dev_t *dev, fsid_t *fsid, uint64_t *file_id)
{
	struct vnode_attr va;
	int error;

	memset(&va, 0, sizeof(va));
	VATTR_INIT(&va);
	if (dev) {
		VATTR_WANTED(&va, va_fsid);
	}
	if (fsid) {
		VATTR_WANTED(&va, va_fsid64);
	}
	if (file_id) {
		VATTR_WANTED(&va, va_fileid);
	}

	error = vnode_getattr(vp, &va, vfs_context_kernel());
	if (error) {
		return error;
	}

	if (dev) {
		if (!VATTR_IS_SUPPORTED(&va, va_fsid)) {
			return ENOTSUP;
		}
		*dev = va.va_fsid;
	}

	if (fsid) {
		if (!VATTR_IS_SUPPORTED(&va, va_fsid64)) {
			return ENOTSUP;
		}
		*fsid = va.va_fsid64;
	}

	if (file_id) {
		if (!VATTR_IS_SUPPORTED(&va, va_fileid)) {
			return ENOTSUP;
		}
		*file_id = va.va_fileid;
	}

	return 0;
}

static inline bool
is_graft(registered_fs_tag_t *rft)
{
	return rft->flags & VFS_EXCLAVE_FS_BASE_DIR_GRAFT;
}

static inline bool
is_sealed(registered_fs_tag_t *rft)
{
	return rft->flags & VFS_EXCLAVE_FS_BASE_DIR_SEALED;
}

static int
graft_to_host_inum(fsioc_graft_info_t *gi, uint64_t graft_inum, uint64_t *host_inum)
{
	if (graft_inum == ROOT_DIR_INO_NUM) {
		*host_inum = gi->gi_graft_dir;
	} else if (graft_inum < gi->gi_inum_len) {
		*host_inum = gi->gi_inum_base + graft_inum;
	} else {
		return ERANGE;
	}

	return 0;
}

static int
host_to_graft_inum(fsioc_graft_info_t *gi, uint64_t host_inum, uint64_t *graft_inum)
{
	if (host_inum == gi->gi_graft_dir) {
		*graft_inum = ROOT_DIR_INO_NUM;
	} else if ((host_inum >= gi->gi_inum_base) && (host_inum < gi->gi_inum_base + gi->gi_inum_len)) {
		*graft_inum = host_inum - gi->gi_inum_base;
	} else {
		return ERANGE;
	}

	return 0;
}

/*
 * Check if a vnode is in an APFS graft and if so obtain information about the graft.
 */
static int
get_graft_info(vnode_t vp, bool *is_graft, fsioc_graft_info_t *graft_info)
{
	fsioc_get_graft_info_t ggi = {0};
	uint16_t alloc_count;
	fsioc_graft_info_t *graft_infos = NULL;
	int error = 0;

	*is_graft = false;

	error = VNOP_IOCTL(vp, FSIOC_GET_GRAFT_INFO, (caddr_t)&ggi, 0, vfs_context_kernel());
	if (error) {
		return error;
	}

	if (!ggi.ggi_is_in_graft) {
		return 0;
	}

	if (ggi.ggi_count == 0) {
		return EINVAL;
	}

	alloc_count = ggi.ggi_count;

	graft_infos = kalloc_type(fsioc_graft_info_t, alloc_count, Z_WAITOK | Z_ZERO);
	if (!graft_infos) {
		return ENOMEM;
	}

	memset(&ggi, 0, sizeof(ggi));
	ggi.ggi_count = alloc_count;
	ggi.ggi_buffer = (user64_addr_t)graft_infos;

	error = VNOP_IOCTL(vp, FSIOC_GET_GRAFT_INFO, (caddr_t)&ggi, 0, vfs_context_kernel());
	if (error) {
		goto out;
	}

	if (!ggi.ggi_is_in_graft) {
		error = EAGAIN;
		goto out;
	}

	if (ggi.ggi_graft_index >= alloc_count) {
		error = ERANGE;
		goto out;
	}

	*graft_info = graft_infos[ggi.ggi_graft_index];
	*is_graft = true;

out:
	if (graft_infos) {
		kfree_type(fsioc_graft_info_t, alloc_count, graft_infos);
	}

	return error;
}

static bool
is_fs_writeable(uint32_t fs_tag)
{
	return (fs_tag == EFT_EXCLAVE) || (fs_tag == EFT_EXCLAVE_MAIN);
}

/*
 * Set a base directory for the given fs tag.
 */
static int
set_base_dir(uint32_t fs_tag, vnode_t vp, fsioc_graft_info_t *graft_info, bool is_sealed)
{
	dev_t dev;
	int error = 0;
	registered_fs_tag_t *rft;

	lck_mtx_lock(&regtag_mtx);

	registered_tags_head_t *rfthead = get_registered_tags_chain(fs_tag);

	LIST_FOREACH(rft, rfthead, link) {
		if (rft->fstag == fs_tag) {
			// Check if the registered vp is DEAD, it can be the case in edu mode where the original location was unmounted
			// if the vnode is dead unregister it, and continue with setting new base_dir
			if (vnode_vtype(rft->vp) == VBAD) {
				vfs_exclave_fs_unregister_internal(rft->vp, false);
				break;
			}

			error = (rft->vp == vp) ? EALREADY : EBUSY;
			goto out;
		}
	}

	error = get_vnode_info(vp, &dev, NULL, NULL);
	if (error) {
		goto out;
	}

	/*
	 * make sure that a writable fs does not share a dev_t with another non writable fs (and vice versa)
	 * since writable vnodes are opened RW whereas non writable fs vnodes
	 * are opened RO
	 */
	int i;
	bool is_writable_fs_tag = is_fs_writeable(fs_tag);
	for (i = 0; i <= rft_hashmask; i++) {
		registered_tags_head_t *head = registered_tags_hash + i;
		LIST_FOREACH(rft, head, link) {
			if ((is_fs_writeable(rft->fstag) != is_writable_fs_tag) && rft->dev == dev) {
				printf("tag %u has same device 0x%x as tag %u\n", fs_tag, rft->fstag, dev);
				error = EBUSY;
				goto out;
			}
		}
	}

	rft = kalloc_type(registered_fs_tag_t, Z_WAITOK | Z_ZERO);
	if (rft == NULL) {
		error = ENOMEM;
		goto out;
	}

	if (graft_info) {
		rft->flags |= VFS_EXCLAVE_FS_BASE_DIR_GRAFT;
		if (is_sealed) {
			rft->flags |= VFS_EXCLAVE_FS_BASE_DIR_SEALED;
		}
		rft->graft_info = *graft_info;
	}

	rft->fstag = fs_tag;
	rft->vp = vp;
	rft->dev = dev;
	LIST_INSERT_HEAD(rfthead, rft, link);

	num_tags_registered++;

out:
	lck_mtx_unlock(&regtag_mtx);
	return error;
}

/*
 * Get the base directory entry for the given fs tag. If vpp is passed, return
 * with an iocount taken on the vnode.
 */
static int
get_base_dir(uint32_t fs_tag, registered_fs_tag_t *base_dir, vnode_t *vpp)
{
	int error = ENOENT;
	registered_fs_tag_t *rft;

	if (!base_dir && !vpp) {
		return EINVAL;
	}

	lck_mtx_lock(&regtag_mtx);

	registered_tags_head_t *rfthead = get_registered_tags_chain(fs_tag);

	LIST_FOREACH(rft, rfthead, link) {
		if (rft->fstag == fs_tag) {
			if (vpp) {
				vnode_t base_vp = rft->vp;
				error = vnode_getwithref(base_vp);
				if (error) {
					break;
				}
				*vpp = base_vp;
			}

			if (base_dir) {
				*base_dir = *rft;
			}
			error = 0;
			break;
		}
	}

	lck_mtx_unlock(&regtag_mtx);
	return error;
}

int
vfs_exclave_fs_start(void)
{
	lck_mtx_init(&regtag_mtx, &vfs_exclave_lck_grp, LCK_ATTR_NULL);
	lck_mtx_init(&open_vnodes_mtx, &vfs_exclave_lck_grp, LCK_ATTR_NULL);

	assert(open_vnodes_hashtbl == NULL);

	open_vnodes_hashsize = desiredvnodes / 16;
	open_vnodes_hashtbl = hashinit(open_vnodes_hashsize, M_VNODE, &open_vnodes_hashmask);
	if (open_vnodes_hashtbl == NULL) {
		open_vnodes_hashsize = open_vnodes_hashmask = 0;
		return ENOMEM;
	}

	registered_tags_hash = hashinit(REGFSTAG_HASH_WIDTH, M_VNODE /*unused*/, &rft_hashmask);
	if (registered_tags_hash == NULL) {
		hashdestroy(open_vnodes_hashtbl, M_VNODE, open_vnodes_hashmask);
		open_vnodes_hashtbl = NULL;
		open_vnodes_hashmask = open_vnodes_hashsize = 0;
		return ENOMEM;
	}

#if (DEVELOPMENT || DEBUG)
	uint32_t bootarg_val;
	if (PE_parse_boot_argn(EXCLAVE_INTEGRITY_CHECKS_DISABLED_BOOTARG, &bootarg_val, sizeof(bootarg_val))) {
		if (bootarg_val) {
			integrity_checks_disabled = true;
		}
	}
#endif

	return 0;
}

static bool
exclave_fs_started(void)
{
	return open_vnodes_hashtbl != NULL;
}

static void release_open_vnodes(registered_fs_tag_t *);

static void
drop_registered_tag(registered_fs_tag_t *rft)
{
	release_open_vnodes(rft);

	vnode_rele(rft->vp);
	LIST_REMOVE(rft, link);
	kfree_type(registered_fs_tag_t, rft);
	num_tags_registered--;
}

void
vfs_exclave_fs_stop(void)
{
	registered_fs_tag_t *rft, *nxt;
	int i;

	if (!exclave_fs_started()) {
		return;
	}

	/* No need to lock regtag_mtx - this function assumes
	 * single-threaded context */
	for (i = 0; i <= rft_hashmask; i++) {
		registered_tags_head_t *rfthead = registered_tags_hash + i;

		LIST_FOREACH_SAFE(rft, rfthead, link, nxt) {
			drop_registered_tag(rft);
		}
	}

	hashdestroy(registered_tags_hash, M_VNODE, rft_hashmask);

	assert(num_open_vnodes == 0);
	assert(open_vnodes_hashtbl);

	hashdestroy(open_vnodes_hashtbl, M_VNODE, open_vnodes_hashmask);
	open_vnodes_hashtbl = NULL;
	open_vnodes_hashmask = open_vnodes_hashsize = 0;

	lck_mtx_destroy(&regtag_mtx, &vfs_exclave_lck_grp);
	lck_mtx_destroy(&open_vnodes_mtx, &vfs_exclave_lck_grp);

#if (DEVELOPMENT || DEBUG)
	integrity_checks_disabled = false;
#endif
}

int
vfs_exclave_fs_register(uint32_t fs_tag, vnode_t vp)
{
	char vfs_name[MFSNAMELEN];
	bool is_graft;
	fsioc_graft_info_t graft_info;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

#if !defined(XNU_TARGET_OS_OSX)
	if (fs_tag == EFT_EXCLAVE_MAIN) {
		return ENOTSUP;
	}
#endif

	vnode_vfsname(vp, vfs_name);
	if (strcmp(vfs_name, "apfs")) {
		return ENOTSUP;
	}

	if (!vnode_isdir(vp)) {
		return ENOTDIR;
	}

	error = get_graft_info(vp, &is_graft, &graft_info);
	if (error) {
		return error;
	}

	if (is_graft && is_fs_writeable(fs_tag)) {
		return EROFS;
	}

	error = vnode_ref(vp);
	if (error) {
		return error;
	}

	// Check if tag is sealed, RW tags are always not sealed
	bool is_sealed = false;
	if (!is_fs_writeable(fs_tag)) {
		error = VNOP_IOCTL(vp, FSIOC_EVAL_ROOTAUTH, NULL, 0, vfs_context_kernel());
		if (!error) {
			is_sealed = true;
		}
	}

	error = set_base_dir(fs_tag, vp, is_graft ? &graft_info : NULL, is_sealed);
	if (error) {
		vnode_rele(vp);
		// if this directory is already registered in this tag do not consider it as an error
		if (error == EALREADY) {
			error = 0;
		}
		return error;
	}

	return 0;
}

int
vfs_exclave_fs_register_path(uint32_t fs_tag, const char *base_path)
{
	struct nameidata nd;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(base_path), vfs_context_kernel());

	error = namei(&nd);
	if (error) {
		return error;
	}

	error = vfs_exclave_fs_register(fs_tag, nd.ni_vp);

	vnode_put(nd.ni_vp);
	nameidone(&nd);

	return error;
}

/*
 * Release open vnodes for the given fs_tag.
 * regtag_mtx must be locked by caller.
 */
static void
release_open_vnodes(registered_fs_tag_t *base_dir)
{
	dev_t dev;
	int i;

	lck_mtx_lock(&open_vnodes_mtx);

	if (num_open_vnodes == 0) {
		goto done;
	}

	dev = base_dir->dev;

	if (num_tags_registered > 1) {
		/* skip release if another base dir has the same device */
		for (i = 0; i <= rft_hashmask; i++) {
			registered_tags_head_t *rfthead = registered_tags_hash + i;
			registered_fs_tag_t *rft;

			LIST_FOREACH(rft, rfthead, link) {
				if ((rft != base_dir) && (rft->dev == dev)) {
					goto done;
				}
			}
		}
	}

	for (i = 0; i < open_vnodes_hashmask + 1; i++) {
		struct open_vnode *entry, *temp_entry;

		LIST_FOREACH_SAFE(entry, &open_vnodes_hashtbl[i], chain, temp_entry) {
			if (entry->dev != dev) {
				continue;
			}
			while (entry->open_count) {
				vnode_rele(entry->vp);
				entry->open_count--;
			}
			LIST_REMOVE(entry, chain);
			kfree_type(struct open_vnode, entry);
			num_open_vnodes--;
		}
	}

done:
	lck_mtx_unlock(&open_vnodes_mtx);
}

static int
vfs_exclave_fs_unregister_internal(vnode_t vp, bool take_basedir_lock)
{
	int error = ENOENT;
	int i;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	if (take_basedir_lock) {
		lck_mtx_lock(&regtag_mtx);
	}

	for (i = 0; i <= rft_hashmask; i++) {
		registered_tags_head_t *rfthead = registered_tags_hash + i;
		registered_fs_tag_t *rft, *nxt;

		LIST_FOREACH_SAFE(rft, rfthead, link, nxt) {
			if (rft->vp == vp) {
				drop_registered_tag(rft);
				error = 0;
				goto done;
			}
		}
	}

done:

	if (take_basedir_lock) {
		lck_mtx_unlock(&regtag_mtx);
	}

	return error;
}

int
vfs_exclave_fs_unregister(vnode_t vp)
{
	return vfs_exclave_fs_unregister_internal(vp, true);
}

int
vfs_exclave_fs_get_base_dirs(void *buf, uint32_t *count)
{
	int error = 0;
	uint32_t num_copied = 0;
	exclave_fs_base_dir_t *dirs = (exclave_fs_base_dir_t *)buf;
	int i;

	if (!count || (dirs && !*count)) {
		return EINVAL;
	}

	lck_mtx_lock(&regtag_mtx);

	if (!dirs) {
		*count = num_tags_registered;
		goto out;
	} else if (*count < num_tags_registered) {
		error = ENOSPC;
		goto out;
	}

	for (i = 0; i <= rft_hashmask; i++) {
		registered_tags_head_t *rfthead = registered_tags_hash + i;
		registered_fs_tag_t *base_dir;

		LIST_FOREACH(base_dir, rfthead, link) {
			exclave_fs_base_dir_t *out_dir = &dirs[num_copied];

			memset(out_dir, 0, sizeof(exclave_fs_base_dir_t));

			error = get_vnode_info(base_dir->vp, NULL, &out_dir->fsid, &out_dir->base_dir);
			if (error) {
				goto out;
			}

			out_dir->fs_tag = base_dir->fstag;
			out_dir->graft_file = is_graft(base_dir) ? base_dir->graft_info.gi_graft_file : 0;
			num_copied++;
		}
	}

	*count = num_copied;

out:
	lck_mtx_unlock(&regtag_mtx);
	return error;
}

static int
create_exclave_dir(vnode_t base_vp, const char *exclave_id)
{
	vnode_t vp = NULLVP, dvp = NULLVP;
	vfs_context_t ctx;
	struct vnode_attr va, *vap = &va;
	struct nameidata nd;
	int update_flags = 0;
	int error;

	ctx = vfs_context_kernel();

	NDINIT(&nd, CREATE, OP_MKDIR, LOCKPARENT | AUDITVNPATH1, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(exclave_id), ctx);
	nd.ni_cnd.cn_flags |= WILLBEDIR;

continue_lookup:
	nd.ni_dvp = base_vp;
	nd.ni_cnd.cn_flags |= USEDVP;

	error = namei(&nd);
	if (error) {
		return error;
	}

	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp != NULLVP) {
		error = EEXIST;
		goto out;
	}

	nd.ni_cnd.cn_flags &= ~USEDVP;

	VATTR_INIT(vap);
	VATTR_SET(vap, va_mode, S_IRWXU | S_IRWXG);
	VATTR_SET(vap, va_type, VDIR);

	error = vn_authorize_mkdir(dvp, &nd.ni_cnd, vap, ctx, NULL);
	if (error) {
		goto out;
	}

	error = vn_create(dvp, &vp, &nd, vap, 0, 0, NULL, ctx);
	if (error == EKEEPLOOKING) {
		nd.ni_vp = vp;
		goto continue_lookup;
	}

	if (error) {
		goto out;
	}

	if (vp->v_name == NULL) {
		update_flags |= VNODE_UPDATE_NAME;
	}
	if (vp->v_parent == NULLVP) {
		update_flags |= VNODE_UPDATE_PARENT;
	}

	if (update_flags) {
		vnode_update_identity(vp, dvp, nd.ni_cnd.cn_nameptr,
		    nd.ni_cnd.cn_namelen, nd.ni_cnd.cn_hash, update_flags);
	}

out:
	nameidone(&nd);
	if (vp) {
		vnode_put(vp);
	}
	if (dvp) {
		vnode_put(dvp);
	}

	return error;
}

int
vfs_exclave_fs_root(const char *exclave_id, uint64_t *root_id)
{
	return vfs_exclave_fs_root_ex(EFT_EXCLAVE, exclave_id, root_id);
}

int
vfs_exclave_fs_root_ex(uint32_t fs_tag, const char *exclave_id, uint64_t *root_id)
{
	int error;
	uint32_t ov_flags = 0;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	if (!is_fs_writeable(fs_tag)) {
		/* root is valid only on RW tags */
		return EINVAL;
	}

	if (strchr(exclave_id, '/') || !strcmp(exclave_id, ".") || !strcmp(exclave_id, "..")) {
		/* don't allow an exclave_id that looks like a path */
		return EINVAL;
	}

#if (DEVELOPMENT || DEBUG)
	if (vfs_exclave_is_enospc_exclave(exclave_id)) {
		ov_flags = OV_EXCLAVE_BASE | OV_FORCE_ENOSPC;
	}
#endif

	error = exclave_fs_open_internal(fs_tag, EXCLAVE_FS_BASEDIR_ROOT_ID,
	    exclave_id, O_DIRECTORY, ov_flags, root_id);

	if (error == ENOENT) {
		vnode_t base_vp;

		error = get_base_dir(fs_tag, NULL, &base_vp);
		if (error) {
			return error;
		}

		error = create_exclave_dir(base_vp, exclave_id);
		if (!error) {
			error = exclave_fs_open_internal(fs_tag, EXCLAVE_FS_BASEDIR_ROOT_ID,
			    exclave_id, O_DIRECTORY, ov_flags, root_id);
		}

		vnode_put(base_vp);
	}

	return error;
}

/*
 * Find a vnode in the open vnodes hash table with the given file_id
 * under a base dir, take an iocount on it and return it.
 * If base dir is a graft, file_id should be the graft inode number.
 */
static int
get_open_vnode(registered_fs_tag_t *base_dir, uint64_t file_id, vnode_t *vpp, uint32_t *ov_flags)
{
	uint64_t vp_file_id;
	struct open_vnode *entry;
	int error;

	if (is_graft(base_dir)) {
		error = graft_to_host_inum(&base_dir->graft_info, file_id, &vp_file_id);
		if (error) {
			return error;
		}
	} else {
		vp_file_id = file_id;
	}

	error = ENOENT;

	lck_mtx_lock(&open_vnodes_mtx);

	LIST_FOREACH(entry, OPEN_VNODES_HASH(base_dir->dev, vp_file_id), chain) {
		if ((entry->dev == base_dir->dev) && (entry->file_id == vp_file_id)) {
			error = vnode_getwithref(entry->vp);
			if (!error) {
				*vpp = entry->vp;
				if (ov_flags) {
#if (DEVELOPMENT || DEBUG)
					*ov_flags = entry->flags;
#else
					*ov_flags = 0;
#endif
				}
			}
			break;
		}
	}

	lck_mtx_unlock(&open_vnodes_mtx);
	return error;
}

/*
 * Increment a vnode open count in the open vnodes hash table.
 * If base dir is a graft, file_id should be the host inode number.
 * Also update entry's flags
 */
static int
increment_vnode_open_count(vnode_t vp, registered_fs_tag_t *base_dir, uint64_t file_id, uint32_t flags)
{
	struct open_vnode *entry;
	open_vnodes_list_head_t *list;
	int error = 0;

	lck_mtx_lock(&open_vnodes_mtx);

	list = OPEN_VNODES_HASH(base_dir->dev, file_id);

	LIST_FOREACH(entry, list, chain) {
		if ((entry->dev == base_dir->dev) && (entry->file_id == file_id)) {
			break;
		}
	}

	if (!entry) {
		entry = kalloc_type(struct open_vnode, Z_WAITOK | Z_ZERO);
		if (!entry) {
			error = ENOMEM;
			goto out;
		}
		entry->vp = vp;
		entry->dev = base_dir->dev;
		entry->file_id = file_id;
		LIST_INSERT_HEAD(list, entry, chain);
		num_open_vnodes++;
	}

	entry->open_count++;
#if (DEVELOPMENT || DEBUG)
	entry->flags |= flags;
#else
#pragma unused(flags)
#endif

out:
	lck_mtx_unlock(&open_vnodes_mtx);
	return error;
}

/*
 * Decrement a vnode open count in the open vnodes hash table and
 * return it with an iocount taken on it.
 * If base dir is a graft, file_id should be the graft inode number.
 */
static int
decrement_vnode_open_count(registered_fs_tag_t *base_dir, uint64_t file_id, vnode_t *vpp)
{
	struct open_vnode *entry;
	vnode_t vp;
	uint64_t vp_file_id;
	int error = 0;

	if (is_graft(base_dir)) {
		error = graft_to_host_inum(&base_dir->graft_info, file_id, &vp_file_id);
		if (error) {
			return error;
		}
	} else {
		vp_file_id = file_id;
	}

	lck_mtx_lock(&open_vnodes_mtx);

	LIST_FOREACH(entry, OPEN_VNODES_HASH(base_dir->dev, vp_file_id), chain) {
		if ((entry->dev == base_dir->dev) && (entry->file_id == vp_file_id)) {
			break;
		}
	}

	if (!entry) {
		error = ENOENT;
		goto out;
	}

	vp = entry->vp;
	entry->open_count--;

	if (entry->open_count == 0) {
		LIST_REMOVE(entry, chain);
		kfree_type(struct open_vnode, entry);
		num_open_vnodes--;
	}

	error = vnode_getwithref(vp);
	if (!error) {
		*vpp = vp;
	}

out:
	lck_mtx_unlock(&open_vnodes_mtx);
	return error;
}

static int
exclave_fs_open_internal(uint32_t fs_tag, uint64_t root_id, const char *path,
    int flags, uint32_t ov_flags, uint64_t *file_id)
{
	vnode_t dvp = NULLVP, vp = NULLVP;
	registered_fs_tag_t base_dir;
	vfs_context_t ctx;
	struct nameidata *ndp = NULL;
	struct vnode_attr *vap = NULL;
	uint64_t vp_file_id;
	int error;
	uint32_t ndflags = NOCROSSMOUNT;
	uint32_t root_ov_flags = 0;

	if (flags & ~(O_CREAT | O_DIRECTORY)) {
		return EINVAL;
	}

	if (is_fs_writeable(fs_tag)) {
		ndflags |= NOFOLLOW;
	} else {
		ndflags |= FOLLOW;
	}

	if ((flags & O_CREAT) && !is_fs_writeable(fs_tag)) {
		return EROFS;
	}

	if (root_id == EXCLAVE_FS_BASEDIR_ROOT_ID) {
		error = get_base_dir(fs_tag, &base_dir, &dvp);
	} else {
		error = get_base_dir(fs_tag, &base_dir, NULL);
		if (!error) {
			error = get_open_vnode(&base_dir, root_id, &dvp, &root_ov_flags);
		}
	}

#if (DEVELOPMENT || DEBUG)
	// inherit the ENOSPC flag from the root
	ov_flags |= (root_ov_flags & OV_FORCE_ENOSPC);
#endif

	if (error) {
		return error;
	}

	// if we need to create the file, then delete it first (so that we won't reuse the same inode number)
	if ((flags & O_CREAT) && !(flags & O_DIRECTORY)) {
		error = unlink1(vfs_context_kernel(), dvp, CAST_USER_ADDR_T(path), UIO_SYSSPACE, 0);
		if (error) {
			if (error == ENOENT) {
				error = 0;
			} else {
				goto out;
			}
		}

		// Add an O_EXCL flag so that create will fail if the file is already there after delete (a possible attack)
		flags |= O_EXCL;
	}

	ndp = kalloc_type(struct nameidata, Z_WAITOK);
	if (!ndp) {
		error = ENOMEM;
		goto out;
	}

	ctx = vfs_context_kernel();

	NDINIT(ndp, LOOKUP, OP_OPEN, ndflags, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(path), ctx);

	ndp->ni_rootdir = dvp;
	ndp->ni_flag = NAMEI_ROOTDIR;
	ndp->ni_dvp = dvp;
	ndp->ni_cnd.cn_flags |= USEDVP;

	vap = kalloc_type(struct vnode_attr, Z_WAITOK);
	if (!vap) {
		error = ENOMEM;
		goto out;
	}

	VATTR_INIT(vap);
	VATTR_SET(vap, va_mode, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

	flags |= FREAD;

	if (is_fs_writeable(fs_tag) && (root_id != EXCLAVE_FS_BASEDIR_ROOT_ID)) {
		flags |= FWRITE;
	}

	error = vn_open_auth(ndp, &flags, vap, NULLVP);
	if (error) {
		goto out;
	}

	vp = ndp->ni_vp;

	error = get_vnode_info(vp, NULL, NULL, &vp_file_id);
	if (error) {
		goto out;
	}

	if (is_graft(&base_dir)) {
		error = host_to_graft_inum(&base_dir.graft_info, vp_file_id, file_id);
		if (error) {
			goto out;
		}
	} else {
		*file_id = vp_file_id;
	}

	error = increment_vnode_open_count(vp, &base_dir, vp_file_id, ov_flags);

out:
	if (dvp) {
		vnode_put(dvp);
	}
	if (vp) {
		vnode_put(vp);
	}
	if (ndp) {
		kfree_type(struct nameidata, ndp);
	}
	if (vap) {
		kfree_type(struct vnode_attr, vap);
	}

	return error;
}

int
vfs_exclave_fs_open(uint32_t fs_tag, uint64_t root_id, const char *name, uint64_t *file_id)
{
	if (!exclave_fs_started()) {
		return ENXIO;
	}

	if (is_fs_writeable(fs_tag) && (root_id == EXCLAVE_FS_BASEDIR_ROOT_ID)) {
		return EINVAL;
	}

	return exclave_fs_open_internal(fs_tag, root_id, name, 0, 0, file_id);
}

int
vfs_exclave_fs_create(uint32_t fs_tag, uint64_t root_id, const char *name, uint64_t *file_id)
{
	if (!exclave_fs_started()) {
		return ENXIO;
	}

	if (is_fs_writeable(fs_tag) && (root_id == EXCLAVE_FS_BASEDIR_ROOT_ID)) {
		return EINVAL;
	}

	return exclave_fs_open_internal(fs_tag, root_id, name, O_CREAT, 0, file_id);
}

int
vfs_exclave_fs_close(uint32_t fs_tag, uint64_t file_id)
{
	vnode_t vp = NULLVP;
	registered_fs_tag_t base_dir;
	int flags = FREAD;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	error = decrement_vnode_open_count(&base_dir, file_id, &vp);
	if (error) {
		goto out;
	}

	if (is_fs_writeable(fs_tag) && !vnode_isdir(vp)) {
		flags |= FWRITE;
	}

	error = vn_close(vp, flags, vfs_context_kernel());

out:
	if (vp) {
		vnode_put(vp);
	}

	return error;
}

static int
exclave_fs_io(uint32_t fs_tag, uint64_t file_id, uint64_t offset, uint64_t length, uint8_t *data, bool read)
{
	vnode_t vp = NULLVP;
	registered_fs_tag_t base_dir;
	UIO_STACKBUF(uio_buf, 1);
	uio_t auio = NULL;
	int error = 0;
	uint32_t ov_flags = 0;

	if (!read && !is_fs_writeable(fs_tag)) {
		return EROFS;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	error = get_open_vnode(&base_dir, file_id, &vp, &ov_flags);
	if (error) {
		goto out;
	}

	if (!read && (ov_flags & OV_FORCE_ENOSPC)) {
		error = ENOSPC;
		goto out;
	}

	auio = uio_createwithbuffer(1, offset, UIO_SYSSPACE, read ? UIO_READ : UIO_WRITE,
	    &uio_buf[0], sizeof(uio_buf));
	if (!auio) {
		error = ENOMEM;
		goto out;
	}

	error = uio_addiov(auio, (uintptr_t)data, length);
	if (error) {
		goto out;
	}

	if (read) {
		error = VNOP_READ(vp, auio, 0, vfs_context_kernel());
	} else {
		error = VNOP_WRITE(vp, auio, 0, vfs_context_kernel());
	}

	if (!error && uio_resid(auio)) {
		error = EIO;
	}

out:
	if (vp) {
		vnode_put(vp);
	}

	return error;
}

int
vfs_exclave_fs_read(uint32_t fs_tag, uint64_t file_id, uint64_t file_offset, uint64_t length, void *data)
{
	if (!exclave_fs_started()) {
		return ENXIO;
	}

	return exclave_fs_io(fs_tag, file_id, file_offset, length, data, true);
}

int
vfs_exclave_fs_write(uint32_t fs_tag, uint64_t file_id, uint64_t file_offset, uint64_t length, void *data)
{
	if (!exclave_fs_started()) {
		return ENXIO;
	}

	return exclave_fs_io(fs_tag, file_id, file_offset, length, (void *)data, false);
}

int
vfs_exclave_fs_remove(uint32_t fs_tag, uint64_t root_id, const char *name)
{
	vnode_t rvp = NULLVP;
	registered_fs_tag_t base_dir;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	if (!is_fs_writeable(fs_tag)) {
		return EROFS;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	error = get_open_vnode(&base_dir, root_id, &rvp, NULL);
	if (error) {
		return error;
	}

	error = unlink1(vfs_context_kernel(), rvp, CAST_USER_ADDR_T(name), UIO_SYSSPACE, 0);

	if (rvp) {
		vnode_put(rvp);
	}

	return error;
}

int
vfs_exclave_fs_sync(uint32_t fs_tag, uint64_t file_id, uint64_t sync_op)
{
	vnode_t vp = NULLVP;
	registered_fs_tag_t base_dir;
	u_long command;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	if (!is_fs_writeable(fs_tag)) {
		return EROFS;
	}

	if (sync_op == EXCLAVE_FS_SYNC_OP_BARRIER) {
		command = F_BARRIERFSYNC;
	} else if (sync_op == EXCLAVE_FS_SYNC_OP_FULL) {
		command = F_FULLFSYNC;
	} else if (sync_op != EXCLAVE_FS_SYNC_OP_UBC) {
		return EINVAL;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	error = get_open_vnode(&base_dir, file_id, &vp, NULL);
	if (error) {
		goto out;
	}

	if (sync_op == EXCLAVE_FS_SYNC_OP_UBC) {
		error = VNOP_FSYNC(vp, MNT_WAIT, vfs_context_kernel());
	} else {
		error = VNOP_IOCTL(vp, command, (caddr_t)NULL, 0, vfs_context_kernel());
	}

out:
	if (vp) {
		vnode_put(vp);
	}

	return error;
}

static int
map_graft_dirents(fsioc_graft_info_t *graft_info, void *dirent_buf, int32_t count)
{
	int i, error = 0;

	for (i = 0; i < count; i++) {
		exclave_fs_dirent_t *dirent = (exclave_fs_dirent_t *)dirent_buf;
		uint64_t mapped_file_id;

		error = host_to_graft_inum(graft_info, dirent->file_id, &mapped_file_id);
		if (error) {
			return error;
		}
		dirent->file_id = mapped_file_id;
		dirent_buf = (char *)dirent_buf + dirent->length;
	}

	return 0;
}

int
vfs_exclave_fs_readdir(uint32_t fs_tag, uint64_t file_id, void *dirent_buf,
    uint32_t buf_size, int32_t *count)
{
	vnode_t dvp = NULLVP;
	registered_fs_tag_t base_dir;
	UIO_STACKBUF(uio_buf, 1);
	uio_t auio = NULL;
	vfs_context_t ctx;
	uthread_t ut;
	struct attrlist al;
	struct vnode_attr *vap = NULL;
	char *va_name = NULL;
	int32_t eofflag;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	/*
	 * For ExclaveOS readdir through VFS is not permitted in RELEASE xnu
	 * variants. Directory enumeration should be based on the data in the
	 * integrity catalogue. Error out here if a request is routed here
	 * in this circumstance.
	 */
	if (fs_tag == EFT_SYSTEM) {
#if (DEVELOPMENT || DEBUG)
		/*
		 * For non-RELEASE xnu variants, we allow readdir to
		 * be routed through VFS if the relevant integrity checks
		 * are disabled, or if the underlying volume is not sealed.
		 */
		if (!integrity_checks_disabled && is_sealed(&base_dir)) {
			return ENOTSUP;
		}
#else
		// This is the RELEASE xnu case above
		return ENOTSUP;
#endif
	}

	error = get_open_vnode(&base_dir, file_id, &dvp, NULL);
	if (error) {
		goto out;
	}

	if (!vnode_isdir(dvp)) {
		error = ENOTDIR;
		goto out;
	}

	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ,
	    &uio_buf[0], sizeof(uio_buf));
	if (!auio) {
		error = ENOMEM;
		goto out;
	}

	error = uio_addiov(auio, (uintptr_t)dirent_buf, buf_size);
	if (error) {
		goto out;
	}

	al.bitmapcount = ATTR_BIT_MAP_COUNT;
	al.commonattr  = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_FILEID;
	al.fileattr = ATTR_FILE_DATALENGTH;

	vap = kalloc_type(struct vnode_attr, Z_WAITOK);
	if (!vap) {
		error = ENOMEM;
		goto out;
	}

	VATTR_INIT(vap);
	va_name = zalloc_flags(ZV_NAMEI, Z_WAITOK | Z_ZERO);
	if (!va_name) {
		error = ENOMEM;
		goto out;
	}
	vap->va_name = va_name;

	VATTR_SET_ACTIVE(vap, va_name);
	VATTR_SET_ACTIVE(vap, va_objtype);
	VATTR_SET_ACTIVE(vap, va_fileid);
	VATTR_SET_ACTIVE(vap, va_total_size);
	VATTR_SET_ACTIVE(vap, va_data_size);

	ctx = vfs_context_kernel();
	ut = current_uthread();

	ut->uu_flag |= UT_KERN_RAGE_VNODES;
	error = VNOP_GETATTRLISTBULK(dvp, &al, vap, auio, NULL,
	    0, &eofflag, count, ctx);
	ut->uu_flag &= ~UT_KERN_RAGE_VNODES;

	if (!error && !eofflag) {
		return ENOBUFS;
	}

	if (is_graft(&base_dir)) {
		error = map_graft_dirents(&base_dir.graft_info, dirent_buf, *count);
		if (error) {
			goto out;
		}
	}

out:
	if (va_name) {
		zfree(ZV_NAMEI, va_name);
	}
	if (vap) {
		kfree_type(struct vnode_attr, vap);
	}
	if (dvp) {
		vnode_put(dvp);
	}

	return error;
}

int
vfs_exclave_fs_getsize(uint32_t fs_tag, uint64_t file_id, uint64_t *size)
{
	vnode_t vp = NULLVP;
	registered_fs_tag_t base_dir;
	vfs_context_t ctx;
	struct vnode_attr *vap = NULL;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	error = get_open_vnode(&base_dir, file_id, &vp, NULL);
	if (error) {
		goto out;
	}

	if (vnode_isdir(vp)) {
		error = EISDIR;
		goto out;
	}

	vap = kalloc_type(struct vnode_attr, Z_WAITOK);
	if (!vap) {
		error = ENOMEM;
		goto out;
	}

	VATTR_INIT(vap);
	VATTR_WANTED(vap, va_data_size);

	ctx = vfs_context_kernel();

	error = VNOP_GETATTR(vp, vap, ctx);
	if (error) {
		goto out;
	}

	if (!VATTR_IS_SUPPORTED(vap, va_data_size)) {
		error = ENOTSUP;
		goto out;
	}

	*size = vap->va_data_size;

out:
	if (vap) {
		kfree_type(struct vnode_attr, vap);
	}
	if (vp) {
		vnode_put(vp);
	}

	return error;
}

int
vfs_exclave_fs_sealstate(uint32_t fs_tag, bool *sealed)
{
	registered_fs_tag_t base_dir;
	int error;

	if (!exclave_fs_started()) {
		return ENXIO;
	}

	error = get_base_dir(fs_tag, &base_dir, NULL);
	if (error) {
		return error;
	}

	*sealed = is_sealed(&base_dir);

	return 0;
}

#if DEVELOPMENT || DEBUG

#define ENOSPC_EXCLAVES_LEN 256
static char enospc_exclaves[ENOSPC_EXCLAVES_LEN];

static bool
vfs_exclave_is_enospc_exclave(const char *exclave_id)
{
	char *element;
	char *scratch_base;
	char *scratch;
	size_t buf_len = strlen(enospc_exclaves) + 1;
	bool is_enospc_exclave = false;

	/* allocate a scratch buffer the size of the string */
	scratch_base = kalloc_data(buf_len, Z_WAITOK);
	if (scratch_base == NULL) {
		goto out;
	}

	/* copy the elementlist to the scratch buffer */
	strlcpy(scratch_base, enospc_exclaves, buf_len);

	/*
	 * set up a temporary pointer that can be used to iterate the
	 * scratch buffer without losing the allocation address
	 */
	scratch = scratch_base;

	/* iterate the scratch buffer; NOTE: buffer contents modified! */
	while ((element = strsep(&scratch, ",")) != NULL) {
		if (strcmp(element, exclave_id) == 0) {
			printf("%s is enospc exclave\n", exclave_id);
			is_enospc_exclave = true;
			goto out;
		}
	}

out:
	if (scratch_base != NULL) {
		kfree_data(scratch_base, buf_len);
	}

	return is_enospc_exclave;
}

SYSCTL_STRING(_kern, OID_AUTO, enospc_exclaves, CTLFLAG_RW | CTLFLAG_LOCKED, enospc_exclaves, sizeof(enospc_exclaves), "List of comma-separated exclave_ids for writing immediately returns ENOSPC");

#endif /* DEVELOPMENT || DEBUG */
