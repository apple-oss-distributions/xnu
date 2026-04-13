/*
 * Copyright (c) 2004-2012 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>

#include <sys/fcntl.h>
#include <sys/file_internal.h>
#include <sys/fsevents.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utfconv.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/xattr.h>

#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/ipc_misc.h>

#include <mach/doubleagent_mig_server.h>
#include <mach/doubleagent_types.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>

#include <libkern/OSByteOrder.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>       /* XXX for ipc_port_release_send() */

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif


#if NAMEDSTREAMS

static int shadow_sequence;

/*
 * We use %p to prevent loss of precision for pointers on varying architectures.
 */

#define SHADOW_NAME_FMT         ".vfs_rsrc_stream_%p%08x%p"
#define SHADOW_DIR_FMT          ".vfs_rsrc_streams_%p%x"
#define SHADOW_DIR_CONTAINER    "/private/var/run"

#define MAKE_SHADOW_NAME(VP, NAME)  \
	snprintf((NAME), sizeof((NAME)), (SHADOW_NAME_FMT), \
	                ((void*)(VM_KERNEL_ADDRPERM(VP))), \
	                (VP)->v_id, \
	                ((void*)(VM_KERNEL_ADDRPERM((VP)->v_data))))

/* The full path to the shadow directory */
#define MAKE_SHADOW_DIRNAME(VP, NAME)   \
	snprintf((NAME), sizeof((NAME)), (SHADOW_DIR_CONTAINER "/" SHADOW_DIR_FMT), \
	                ((void*)(VM_KERNEL_ADDRPERM(VP))), shadow_sequence)

/* The shadow directory as a 'leaf' entry */
#define MAKE_SHADOW_DIR_LEAF(VP, NAME)  \
	snprintf((NAME), sizeof((NAME)), (SHADOW_DIR_FMT), \
	                ((void*)(VM_KERNEL_ADDRPERM(VP))), shadow_sequence)

static int  default_getnamedstream(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation op, vfs_context_t context);

static int  default_makenamedstream(vnode_t vp, vnode_t *svpp, const char *name, vfs_context_t context);

static int  default_removenamedstream(vnode_t vp, const char *name, vfs_context_t context);

static int  getshadowfile(vnode_t vp, vnode_t *svpp, int makestream, size_t *rsrcsize, int *creator, vfs_context_t context);

static int  get_shadow_dir(vnode_t *sdvpp);

#endif /* NAMEDSTREAMS */

/*
 * Default xattr support routines.
 */

static int default_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size, int options,
    vfs_context_t context);
static int default_setxattr(vnode_t vp, const char *name, uio_t uio, int options,
    vfs_context_t context);
static int default_listxattr(vnode_t vp, uio_t uio, size_t *size, int options,
    vfs_context_t context);
static int default_removexattr(vnode_t vp, const char *name, int options,
    vfs_context_t context);

/*
 *  Retrieve the data of an extended attribute.
 */
int
vn_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
    int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* getxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	/*
	 * Non-kernel request need extra checks performed.
	 *
	 * The XATTR_NOSECURITY flag implies a kernel request.
	 */
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_getextattr(context, vp, name, uio);
		if (error) {
			goto out;
		}
#endif /* MAC */
		if ((error = xattr_validatename(name))) {
			goto out;
		}
		if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context))) {
			goto out;
		}
	}

	/* The offset can only be non-zero for resource forks. */
	if (uio_offset(uio) != 0 &&
	    strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_GETXATTR(vp, name, uio, size, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_getxattr(vp, name, uio, size, options, context);
	}
out:
	return error;
}

/*
 * Set the data of an extended attribute.
 */
int
vn_setxattr(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* setxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	if ((options & (XATTR_REPLACE | XATTR_CREATE)) == (XATTR_REPLACE | XATTR_CREATE)) {
		return EINVAL;
	}
	if ((error = xattr_validatename(name))) {
		return error;
	}
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_setextattr(context, vp, name, uio);
		if (error) {
			goto out;
		}
#endif /* MAC */
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context);
		if (error) {
			goto out;
		}
	}
	/* The offset can only be non-zero for resource forks. */
	if (uio_offset(uio) != 0 &&
	    strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_SETXATTR(vp, name, uio, options, context);
#ifdef DUAL_EAS
	/*
	 * An EJUSTRETURN is from a filesystem which keeps this xattr
	 * natively as well as in a dot-underscore file.  In this case the
	 * EJUSTRETURN means the filesytem has done nothing, but identifies the
	 * EA as one which may be represented natively and/or in a DU, and
	 * since XATTR_CREATE or XATTR_REPLACE was specified, only up here in
	 * in vn_setxattr can we do the getxattrs needed to ascertain whether
	 * the XATTR_{CREATE,REPLACE} should yield an error.
	 */
	if (error == EJUSTRETURN) {
		int native = 0, dufile = 0;
		size_t sz;      /* not used */

		native = VNOP_GETXATTR(vp, name, NULL, &sz, 0, context) ? 0 : 1;
		dufile = default_getxattr(vp, name, NULL, &sz, 0, context) ? 0 : 1;
		if (options & XATTR_CREATE && (native || dufile)) {
			error = EEXIST;
			goto out;
		}
		if (options & XATTR_REPLACE && !(native || dufile)) {
			error = ENOATTR;
			goto out;
		}
		/*
		 * Having determined no CREATE/REPLACE error should result, we
		 * zero those bits, so both backing stores get written to.
		 */
		options &= ~(XATTR_CREATE | XATTR_REPLACE);
		error = VNOP_SETXATTR(vp, name, uio, options, context);
		/* the mainline path here is to have error==ENOTSUP ... */
	}
#endif /* DUAL_EAS */
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_setxattr(vp, name, uio, options, context);
	}
#if CONFIG_MACF
	if ((error == 0) && !(options & XATTR_NOSECURITY)) {
		mac_vnode_notify_setextattr(context, vp, name, uio);
		if (vfs_flags(vnode_mount(vp)) & MNT_MULTILABEL) {
			mac_vnode_label_update_extattr(vnode_mount(vp), vp, name);
		}
	}
#endif
out:
	return error;
}

/*
 * Remove an extended attribute.
 */
int
vn_removexattr(vnode_t vp, const char * name, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* removexattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	if ((error = xattr_validatename(name))) {
		return error;
	}
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_deleteextattr(context, vp, name);
		if (error) {
			goto out;
		}
#endif /* MAC */
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context);
		if (error) {
			goto out;
		}
	}
	error = VNOP_REMOVEXATTR(vp, name, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_removexattr(vp, name, options, context);
#ifdef DUAL_EAS
	} else if (error == EJUSTRETURN) {
		/*
		 * EJUSTRETURN is from a filesystem which keeps this xattr natively as well
		 * as in a dot-underscore file.  EJUSTRETURN means the filesytem did remove
		 * a native xattr, so failure to find it in a DU file during
		 * default_removexattr should not be considered an error.
		 */
		error = default_removexattr(vp, name, options, context);
		if (error == ENOATTR) {
			error = 0;
		}
#endif /* DUAL_EAS */
	}
#if CONFIG_MACF
	if ((error == 0) && !(options & XATTR_NOSECURITY)) {
		mac_vnode_notify_deleteextattr(context, vp, name);
		if (vfs_flags(vnode_mount(vp)) & MNT_MULTILABEL) {
			mac_vnode_label_update_extattr(vnode_mount(vp), vp, name);
		}
	}
#endif
out:
	return error;
}

/*
 * Retrieve the list of extended attribute names.
 */
int
vn_listxattr(vnode_t vp, uio_t uio, size_t *size, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return EPERM;
	}
#if NAMEDSTREAMS
	/* listxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		return EPERM;
	}
#endif

	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_listextattr(context, vp);
		if (error) {
			goto out;
		}
#endif /* MAC */

		error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context);
		if (error) {
			goto out;
		}
	}

	error = VNOP_LISTXATTR(vp, uio, size, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some but not all EAs natively, in which case
		 * the native EA names will have been uiomove-d out (or *size updated)
		 * and the default_listxattr here will finish the job.
		 */
		error = default_listxattr(vp, uio, size, options, context);
	}
out:
	return error;
}

int
xattr_validatename(const char *name)
{
	size_t namelen;

	if (name == NULL || name[0] == '\0') {
		return EINVAL;
	}
	namelen = strlen(name);

	if (utf8_validatestr((const unsigned char *)name, namelen) != 0) {
		return EINVAL;
	}

	return 0;
}


/*
 * Determine whether an EA is a protected system attribute.
 */
int
xattr_protected(const char *attrname)
{
	return !strncmp(attrname, "com.apple.system.", 17);
}


static void
vnode_setasnamedstream_internal(vnode_t vp, vnode_t svp)
{
	uint32_t streamflags = VISNAMEDSTREAM;

	if ((vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0) {
		streamflags |= VISSHADOW;
	}

	/* Tag the vnode. */
	vnode_lock_spin(svp);
	svp->v_flag |= streamflags;
	vnode_unlock(svp);

	/* Tag the parent so we know to flush credentials for streams on setattr */
	vnode_lock_spin(vp);
	vp->v_lflag |= VL_HASSTREAMS;
	vnode_unlock(vp);

	/* Make the file it's parent.
	 * Note:  This parent link helps us distinguish vnodes for
	 * shadow stream files from vnodes for resource fork on file
	 * systems that support namedstream natively (both have
	 * VISNAMEDSTREAM set) by allowing access to mount structure
	 * for checking MNTK_NAMED_STREAMS bit at many places in the
	 * code.
	 */
	vnode_update_identity(svp, vp, NULL, 0, 0, (VNODE_UPDATE_NAMEDSTREAM_PARENT | VNODE_UPDATE_FORCE_PARENT_REF));

	if (vnode_isdyldsharedcache(vp)) {
		vnode_lock_spin(svp);
		svp->v_flag |= VSHARED_DYLD;
		vnode_unlock(svp);
	}

	return;
}

errno_t
vnode_setasnamedstream(vnode_t vp, vnode_t svp)
{
	if ((vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0) {
		return EINVAL;
	}

	vnode_setasnamedstream_internal(vp, svp);
	return 0;
}

#if NAMEDSTREAMS

/*
 * Obtain a named stream from vnode vp.
 */
errno_t
vnode_getnamedstream(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation op, int flags, vfs_context_t context)
{
	int error;

	if (vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) {
		error = VNOP_GETNAMEDSTREAM(vp, svpp, name, op, flags, context);
	} else {
		if (flags) {
			error = ENOTSUP;
		} else {
			error = default_getnamedstream(vp, svpp, name, op, context);
		}
	}

	if (error == 0) {
		vnode_setasnamedstream_internal(vp, *svpp);
	}

	return error;
}

/*
 * Make a named stream for vnode vp.
 */
errno_t
vnode_makenamedstream(vnode_t vp, vnode_t *svpp, const char *name, int flags, vfs_context_t context)
{
	int error;

	if (vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) {
		error = VNOP_MAKENAMEDSTREAM(vp, svpp, name, flags, context);
	} else {
		error = default_makenamedstream(vp, svpp, name, context);
	}

	if (error == 0) {
		vnode_setasnamedstream_internal(vp, *svpp);
	}

	return error;
}

/*
 * Remove a named stream from vnode vp.
 */
errno_t
vnode_removenamedstream(vnode_t vp, vnode_t svp, const char *name, int flags, vfs_context_t context)
{
	int error;

	if (vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) {
		error = VNOP_REMOVENAMEDSTREAM(vp, svp, name, flags, context);
	} else {
		error = default_removenamedstream(vp, name, context);
	}

	return error;
}

#define NS_IOBUFSIZE  (128 * 1024)

/*
 * Release a named stream shadow file.
 *
 * Note: This function is called from two places where we do not need
 * to check if the vnode has any references held before deleting the
 * shadow file.  Once from vclean() when the vnode is being reclaimed
 * and we do not hold any references on the vnode.  Second time from
 * default_getnamedstream() when we get an error during shadow stream
 * file initialization so that other processes who are waiting for the
 * shadow stream file initialization by the creator will get opportunity
 * to create and initialize the file again.
 */
errno_t
vnode_relenamedstream(vnode_t vp, vnode_t svp)
{
	vnode_t dvp;
	struct componentname cn;
	char tmpname[80];
	errno_t err;

	/*
	 * We need to use the kernel context here.  If we used the supplied
	 * VFS context we have no clue whether or not it originated from userland
	 * where it could be subject to a chroot jail.  We need to ensure that all
	 * filesystem access to shadow files is done on the same FS regardless of
	 * userland process restrictions.
	 */
	vfs_context_t kernelctx = vfs_context_kernel();

	cache_purge(svp);

	vnode_lock(svp);
	MAKE_SHADOW_NAME(vp, tmpname);
	vnode_unlock(svp);

	cn.cn_nameiop = DELETE;
	cn.cn_flags = ISLASTCN;
	cn.cn_context = kernelctx;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = (int)strlen(tmpname);

	/*
	 * Obtain the vnode for the shadow files directory.  Make sure to
	 * use the kernel ctx as described above.
	 */
	err = get_shadow_dir(&dvp);
	if (err != 0) {
		return err;
	}

	(void) VNOP_REMOVE(dvp, svp, &cn, 0, kernelctx);
	vnode_put(dvp);

	return 0;
}

/*
 * Flush a named stream shadow file.
 *
 * 'vp' represents the AppleDouble file.
 * 'svp' represents the shadow file.
 */
errno_t
vnode_flushnamedstream(vnode_t vp, vnode_t svp, vfs_context_t context)
{
	struct vnode_attr va;
	uio_t auio = NULL;
	caddr_t  bufptr = NULL;
	size_t  bufsize = 0;
	size_t  offset;
	size_t  iosize;
	size_t datasize;
	int error;
	/*
	 * The kernel context must be used for all I/O to the shadow file
	 * and its namespace operations
	 */
	vfs_context_t kernelctx = vfs_context_kernel();

	/* The supplied context is used for access to the AD file itself */

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_data_size);
	if (VNOP_GETATTR(svp, &va, context) != 0 ||
	    !VATTR_IS_SUPPORTED(&va, va_data_size)) {
		return 0;
	}
	if (va.va_data_size > UINT32_MAX) {
		return EINVAL;
	}
	datasize = (size_t)va.va_data_size;
	if (datasize == 0) {
		(void) default_removexattr(vp, XATTR_RESOURCEFORK_NAME, 0, context);
		return 0;
	}

	iosize = bufsize = MIN(datasize, NS_IOBUFSIZE);
	bufptr = kalloc_data(bufsize, Z_WAITOK);
	if (bufptr == NULL) {
		return ENOMEM;
	}
	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	offset = 0;

	/*
	 * Copy the shadow stream file data into the resource fork.
	 */
	error = VNOP_OPEN(svp, 0, kernelctx);
	if (error) {
		printf("vnode_flushnamedstream: err %d opening file\n", error);
		goto out;
	}
	while (offset < datasize) {
		iosize = MIN(datasize - offset, iosize);

		uio_reset(auio, offset, UIO_SYSSPACE, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufptr, iosize);
		error = VNOP_READ(svp, auio, 0, kernelctx);
		if (error) {
			break;
		}
		/* Since there's no truncate xattr we must remove the resource fork. */
		if (offset == 0) {
			error = default_removexattr(vp, XATTR_RESOURCEFORK_NAME, 0, context);
			if ((error != 0) && (error != ENOATTR)) {
				break;
			}
		}
		uio_reset(auio, offset, UIO_SYSSPACE, UIO_WRITE);
		uio_addiov(auio, (uintptr_t)bufptr, iosize);
		error = vn_setxattr(vp, XATTR_RESOURCEFORK_NAME, auio, XATTR_NOSECURITY, context);
		if (error) {
			break;
		}
		offset += iosize;
	}

	/* close shadowfile */
	(void) VNOP_CLOSE(svp, 0, kernelctx);
out:
	kfree_data(bufptr, bufsize);
	if (auio) {
		uio_free(auio);
	}
	return error;
}


/*
 * Verify that the vnode 'vp' is a vnode that lives in the shadow
 * directory.  We can't just query the parent pointer directly since
 * the shadowfile is hooked up to the actual file it's a stream for.
 */
errno_t
vnode_verifynamedstream(vnode_t vp)
{
	int error;
	struct vnode *shadow_dvp = NULL;
	struct vnode *shadowfile = NULL;
	struct componentname cn;

	/*
	 * We need to use the kernel context here.  If we used the supplied
	 * VFS context we have no clue whether or not it originated from userland
	 * where it could be subject to a chroot jail.  We need to ensure that all
	 * filesystem access to shadow files is done on the same FS regardless of
	 * userland process restrictions.
	 */
	vfs_context_t kernelctx = vfs_context_kernel();
	char tmpname[80];


	/* Get the shadow directory vnode */
	error = get_shadow_dir(&shadow_dvp);
	if (error) {
		return error;
	}

	/* Re-generate the shadow name in the buffer */
	MAKE_SHADOW_NAME(vp, tmpname);

	/* Look up item in shadow dir */
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN | CN_ALLOWRSRCFORK;
	cn.cn_context = kernelctx;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = (int)strlen(tmpname);

	if (VNOP_LOOKUP(shadow_dvp, &shadowfile, &cn, kernelctx) == 0) {
		/* is the pointer the same? */
		if (shadowfile == vp) {
			error = 0;
		} else {
			error = EPERM;
		}
		/* drop the iocount acquired */
		vnode_put(shadowfile);
	}

	/* Drop iocount on shadow dir */
	vnode_put(shadow_dvp);
	return error;
}

/*
 * Access or create the shadow file as needed.
 *
 * 'makestream' with non-zero value means that we need to guarantee we were the
 * creator of the shadow file.
 *
 * 'context' is the user supplied context for the original VFS operation that
 * caused us to need a shadow file.
 *
 * int pointed to by 'creator' is nonzero if we created the shadowfile.
 */
static int
getshadowfile(vnode_t vp, vnode_t *svpp, int makestream, size_t *rsrcsize,
    int *creator, vfs_context_t context)
{
	vnode_t  dvp = NULLVP;
	vnode_t  svp = NULLVP;
	struct componentname cn;
	struct vnode_attr va;
	char tmpname[80];
	size_t datasize = 0;
	int  error = 0;
	int retries = 0;
	vfs_context_t kernelctx = vfs_context_kernel();

retry_create:
	*creator = 0;
	/* Establish a unique file name. */
	MAKE_SHADOW_NAME(vp, tmpname);
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN | MARKISSHADOW;
	cn.cn_context = context;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = (int)strlen(tmpname);

	/* Pick up uid, gid, mode and date from original file. */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_create_time);
	VATTR_WANTED(&va, va_modify_time);
	if (VNOP_GETATTR(vp, &va, context) != 0 ||
	    !VATTR_IS_SUPPORTED(&va, va_uid) ||
	    !VATTR_IS_SUPPORTED(&va, va_gid) ||
	    !VATTR_IS_SUPPORTED(&va, va_mode)) {
		va.va_uid = KAUTH_UID_NONE;
		va.va_gid = KAUTH_GID_NONE;
		va.va_mode = S_IRUSR | S_IWUSR;
	}
	va.va_vaflags = VA_EXCLUSIVE;
	VATTR_SET(&va, va_type, VREG);
	/* We no longer change the access, but we still hide it. */
	VATTR_SET(&va, va_flags, UF_HIDDEN);

	/* Obtain the vnode for the shadow files directory. */
	if (get_shadow_dir(&dvp) != 0) {
		error = ENOTDIR;
		goto out;
	}
	if (!makestream) {
		/* See if someone else already has it open. */
		if (VNOP_LOOKUP(dvp, &svp, &cn, kernelctx) == 0) {
			/* Double check existence by asking for size. */
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_data_size);
			if (VNOP_GETATTR(svp, &va, context) == 0 &&
			    VATTR_IS_SUPPORTED(&va, va_data_size)) {
				goto out;  /* OK to use. */
			}
		}

		/*
		 * Otherwise make sure the resource fork data exists.
		 * Use the supplied context for accessing the AD file.
		 */
		error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, NULL, &datasize,
		    XATTR_NOSECURITY, context);
		/*
		 * To maintain binary compatibility with legacy Carbon
		 * emulated resource fork support, if the resource fork
		 * doesn't exist but the Finder Info does,  then act as
		 * if an empty resource fork is present (see 4724359).
		 */
		if ((error == ENOATTR) &&
		    (vn_getxattr(vp, XATTR_FINDERINFO_NAME, NULL, &datasize,
		    XATTR_NOSECURITY, context) == 0)) {
			datasize = 0;
			error = 0;
		} else {
			if (error) {
				goto out;
			}

			/* If the resource fork exists, its size is expected to be non-zero. */
			if (datasize == 0) {
				error = ENOATTR;
				goto out;
			}
		}
	}
	/* Create the shadow stream file. */
	error = VNOP_CREATE(dvp, &svp, &cn, &va, kernelctx);
	if (error == 0) {
		vnode_recycle(svp);
		*creator = 1;
	} else if ((error == EEXIST) && !makestream) {
		error = VNOP_LOOKUP(dvp, &svp, &cn, kernelctx);
	} else if ((error == ENOENT) && !makestream) {
		/*
		 * We could have raced with a rmdir on the shadow directory
		 * post-lookup.  Retry from the beginning, 1x only, to
		 * try and see if we need to re-create the shadow directory
		 * in get_shadow_dir.
		 */
		if (retries == 0) {
			retries++;
			if (dvp) {
				vnode_put(dvp);
				dvp = NULLVP;
			}
			if (svp) {
				vnode_put(svp);
				svp = NULLVP;
			}
			goto retry_create;
		}
		/* Otherwise, just error out normally below */
	}

out:
	if (dvp) {
		vnode_put(dvp);
	}
	if (error) {
		/* On errors, clean up shadow stream file. */
		if (svp) {
			vnode_put(svp);
			svp = NULLVP;
		}
	}
	*svpp = svp;
	if (rsrcsize) {
		*rsrcsize = datasize;
	}
	return error;
}


static int
default_getnamedstream(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation op, vfs_context_t context)
{
	vnode_t  svp = NULLVP;
	uio_t auio = NULL;
	caddr_t  bufptr = NULL;
	size_t  bufsize = 0;
	size_t  datasize = 0;
	int  creator;
	int  error;

	/* need the kernel context for accessing the shadowfile */
	vfs_context_t kernelctx = vfs_context_kernel();

	/*
	 * Only the "com.apple.ResourceFork" stream is supported here.
	 */
	if (strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		*svpp = NULLVP;
		return ENOATTR;
	}
retry:
	/*
	 * Obtain a shadow file for the resource fork I/O.
	 *
	 * Need to pass along the supplied context so that getshadowfile
	 * can access the AD file as needed, using it.
	 */
	error = getshadowfile(vp, &svp, 0, &datasize, &creator, context);
	if (error) {
		*svpp = NULLVP;
		return error;
	}

	/*
	 * The creator of the shadow file provides its file data,
	 * all other threads should wait until its ready.  In order to
	 * prevent a deadlock during error codepaths, we need to check if the
	 * vnode is being created, or if it has failed out. Regardless of success or
	 * failure, we set the VISSHADOW bit on the vnode, so we check that
	 * if the vnode's flags don't have VISNAMEDSTREAM set.  If it doesn't,
	 * then we can infer the creator isn't done yet.  If it's there, but
	 * VISNAMEDSTREAM is not set, then we can infer it errored out and we should
	 * try again.
	 */
	if (!creator) {
		vnode_lock(svp);
		if (svp->v_flag & VISNAMEDSTREAM) {
			/* data is ready, go use it */
			vnode_unlock(svp);
			goto out;
		} else {
			/* It's not ready, wait for it (sleep using v_parent as channel) */
			if ((svp->v_flag & VISSHADOW)) {
				/*
				 * No VISNAMEDSTREAM, but we did see VISSHADOW, indicating that the other
				 * thread is done with this vnode. Just unlock the vnode and try again
				 */
				vnode_unlock(svp);
			} else {
				/* Otherwise, sleep if the shadow file is not created yet */
				msleep((caddr_t)&svp->v_parent, &svp->v_lock, PINOD | PDROP,
				    "getnamedstream", NULL);
			}
			vnode_put(svp);
			svp = NULLVP;
			goto retry;
		}
	}

	/*
	 * Copy the real resource fork data into shadow stream file.
	 */
	if (op == NS_OPEN && datasize != 0) {
		size_t  offset;
		size_t  iosize;

		iosize = bufsize = MIN(datasize, NS_IOBUFSIZE);
		bufptr = kalloc_data(bufsize, Z_WAITOK);
		if (bufptr == NULL) {
			error = ENOMEM;
			goto out;
		}

		auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
		offset = 0;

		/* open the shadow file */
		error = VNOP_OPEN(svp, 0, kernelctx);
		if (error) {
			goto out;
		}
		while (offset < datasize) {
			size_t  tmpsize;

			iosize = MIN(datasize - offset, iosize);

			uio_reset(auio, offset, UIO_SYSSPACE, UIO_READ);
			uio_addiov(auio, (uintptr_t)bufptr, iosize);
			/* use supplied ctx for AD file */
			error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, auio, &tmpsize,
			    XATTR_NOSECURITY, context);
			if (error) {
				break;
			}

			uio_reset(auio, offset, UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, (uintptr_t)bufptr, iosize);
			/* kernel context for writing shadowfile */
			error = VNOP_WRITE(svp, auio, 0, kernelctx);
			if (error) {
				break;
			}
			offset += iosize;
		}

		/* close shadow file */
		(void) VNOP_CLOSE(svp, 0, kernelctx);
	}
out:
	/* Wake up anyone waiting for svp file content */
	if (creator) {
		if (error == 0) {
			vnode_lock(svp);
			/* VISSHADOW would be set later on anyway, so we set it now */
			svp->v_flag |= (VISNAMEDSTREAM | VISSHADOW);
			wakeup((caddr_t)&svp->v_parent);
			vnode_unlock(svp);
		} else {
			/* On post create errors, get rid of the shadow file.  This
			 * way if there is another process waiting for initialization
			 * of the shadowfile by the current process will wake up and
			 * retry by creating and initializing the shadow file again.
			 * Also add the VISSHADOW bit here to indicate we're done operating
			 * on this vnode.
			 */
			(void)vnode_relenamedstream(vp, svp);
			vnode_lock(svp);
			svp->v_flag |= VISSHADOW;
			wakeup((caddr_t)&svp->v_parent);
			vnode_unlock(svp);
		}
	}

	kfree_data(bufptr, bufsize);
	if (auio) {
		uio_free(auio);
	}
	if (error) {
		/* On errors, clean up shadow stream file. */
		if (svp) {
			vnode_put(svp);
			svp = NULLVP;
		}
	}
	*svpp = svp;
	return error;
}

static int
default_makenamedstream(vnode_t vp, vnode_t *svpp, const char *name, vfs_context_t context)
{
	int creator;
	int error;

	/*
	 * Only the "com.apple.ResourceFork" stream is supported here.
	 */
	if (strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		*svpp = NULLVP;
		return ENOATTR;
	}

	/* Supply the context to getshadowfile so it can manipulate the AD file */
	error = getshadowfile(vp, svpp, 1, NULL, &creator, context);

	/*
	 * Wake up any waiters over in default_getnamedstream().
	 */
	if ((error == 0) && (*svpp != NULL) && creator) {
		vnode_t svp = *svpp;

		vnode_lock(svp);
		/* If we're the creator, mark it as a named stream */
		svp->v_flag |= (VISNAMEDSTREAM | VISSHADOW);
		/* Wakeup any waiters on the v_parent channel */
		wakeup((caddr_t)&svp->v_parent);
		vnode_unlock(svp);
	}

	return error;
}

static int
default_removenamedstream(vnode_t vp, const char *name, vfs_context_t context)
{
	/*
	 * Only the "com.apple.ResourceFork" stream is supported here.
	 */
	if (strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		return ENOATTR;
	}
	/*
	 * XXX - what about other opened instances?
	 */
	return default_removexattr(vp, XATTR_RESOURCEFORK_NAME, 0, context);
}

static bool
is_shadow_dir_valid(vnode_t parent_sdvp, vnode_t sdvp, vfs_context_t kernelctx)
{
	struct vnode_attr va;
	uint32_t tmp_fsid;
	bool is_valid = false;

	/* Make sure it's in fact a directory */
	if (sdvp->v_type != VDIR) {
		goto out;
	}

	/* Obtain the fsid for what should be the /private/var/run directory. */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_fsid);
	if (VNOP_GETATTR(parent_sdvp, &va, kernelctx) != 0 ||
	    !VATTR_IS_SUPPORTED(&va, va_fsid)) {
		goto out;
	}

	tmp_fsid = va.va_fsid;

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_dirlinkcount);
	VATTR_WANTED(&va, va_acl);
	/* Provide defaults for attrs that may not be supported */
	va.va_dirlinkcount = 1;
	va.va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;

	if (VNOP_GETATTR(sdvp, &va, kernelctx) != 0 ||
	    !VATTR_IS_SUPPORTED(&va, va_uid) ||
	    !VATTR_IS_SUPPORTED(&va, va_gid) ||
	    !VATTR_IS_SUPPORTED(&va, va_mode) ||
	    !VATTR_IS_SUPPORTED(&va, va_fsid)) {
		goto out;
	}

	/*
	 * Make sure its what we want:
	 *      - owned by root
	 *	- not writable by anyone
	 *	- on same file system as /private/var/run
	 *	- not a hard-linked directory
	 *	- no ACLs (they might grant write access)
	 */
	if ((va.va_uid != 0) || (va.va_gid != 0) ||
	    (va.va_mode & (S_IWUSR | S_IRWXG | S_IRWXO)) ||
	    (va.va_fsid != tmp_fsid) ||
	    (va.va_dirlinkcount != 1) ||
	    (va.va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE)) {
		goto out;
	}

	/* If we get here, then the shadow dir is valid. */
	is_valid = true;

out:
	return is_valid;
}

static int
get_shadow_dir(vnode_t *sdvpp)
{
	vnode_t  dvp = NULLVP;
	vnode_t  sdvp = NULLVP;
	struct componentname  cn;
	struct vnode_attr  va;
	char tmpname[80];
	int  error;
	vfs_context_t kernelctx = vfs_context_kernel();

	/*
	 * Make sure to use the kernel context.  We want a singular view of
	 * the shadow dir regardless of chrooted processes.
	 */

	/*
	 * Obtain the vnode for "/private/var/run" directory using the kernel
	 * context.
	 *
	 * This is defined in the SHADOW_DIR_CONTAINER macro
	 */
	error = vnode_lookup(SHADOW_DIR_CONTAINER, VNODE_LOOKUP_NOFOLLOW_ANY, &dvp,
	    kernelctx);
	if (error) {
		error = ENOTSUP;
		goto out;
	}

	/*
	 * Create the shadow stream directory.
	 * 'dvp' below suggests the parent directory so
	 * we only need to provide the leaf entry name
	 */
	bzero(tmpname, sizeof(tmpname));
	MAKE_SHADOW_DIR_LEAF(rootvnode, tmpname);

	/*
	 * Look up the shadow directory to ensure that it still exists.
	 * By looking it up, we get an iocounted sdvp to use, and avoid some
	 * coherency issues in caching it when multiple threads may be trying to
	 * manipulate the pointers.
	 */
	error = vnode_lookupat(tmpname, VNODE_LOOKUP_NOFOLLOW, &sdvp, kernelctx, dvp);
	if (error == 0) {
		if (is_shadow_dir_valid(dvp, sdvp, kernelctx)) {
			/*
			 * If we get here, then we have successfully looked up the shadow
			 * dir, and it has an iocount from the lookup. Return the vp in the
			 * output argument.
			 */
			goto out;
		}

		/*
		 * Lookup returned us something that is not a valid shadow dir.
		 * Remove it and proceed with recreating the shadow dir.
		 */
		bzero(&cn, sizeof(cn));
		cn.cn_nameiop = DELETE;
		cn.cn_flags = ISLASTCN;
		cn.cn_context = kernelctx;
		cn.cn_pnbuf = tmpname;
		cn.cn_pnlen = sizeof(tmpname);
		cn.cn_nameptr = cn.cn_pnbuf;
		cn.cn_namelen = (int)strlen(tmpname);

		error = VNOP_REMOVE(dvp, sdvp, &cn, 0, kernelctx);
		if (error) {
			error = ENOTSUP;
			goto out;
		}

		vnode_put(sdvp);
	}

	/* In the failure case, no iocount is acquired */
	sdvp = NULLVP;
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_context = kernelctx;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = (int)strlen(tmpname);

	/*
	 * owned by root, only readable by root, hidden
	 */
	VATTR_INIT(&va);
	VATTR_SET(&va, va_uid, 0);
	VATTR_SET(&va, va_gid, 0);
	VATTR_SET(&va, va_mode, S_IRUSR | S_IXUSR);
	VATTR_SET(&va, va_type, VDIR);
	VATTR_SET(&va, va_flags, UF_HIDDEN);
	va.va_vaflags = VA_EXCLUSIVE;

	error = VNOP_MKDIR(dvp, &sdvp, &cn, &va, kernelctx);

	/*
	 * There can be only one winner for an exclusive create.
	 */
	if (error == EEXIST) {
		/* loser has to look up directory */
		error = VNOP_LOOKUP(dvp, &sdvp, &cn, kernelctx);
		if (error == 0 && is_shadow_dir_valid(dvp, sdvp, kernelctx) == false) {
			goto baddir;
		}
	}
out:
	if (dvp) {
		vnode_put(dvp);
	}
	if (error) {
		/* On errors, clean up shadow stream directory. */
		if (sdvp) {
			vnode_put(sdvp);
			sdvp = NULLVP;
		}
	}
	*sdvpp = sdvp;
	return error;

baddir:
	/* This is not the dir we're looking for, move along */
	++shadow_sequence;  /* try something else next time */
	error = ENOTDIR;
	goto out;
}
#endif /* NAMEDSTREAMS */


#if CONFIG_APPLEDOUBLE
/*
 * Default Implementation (Non-native EA)
 */


/*
 *  Typical "._" AppleDouble Header File layout:
 * ------------------------------------------------------------
 *        MAGIC          0x00051607
 *        VERSION        0x00020000
 *        FILLER         0
 *        COUNT          2
 *    .-- AD ENTRY[0]    Finder Info Entry (must be first)
 * .--+-- AD ENTRY[1]    Resource Fork Entry (must be last)
 * |  '-> FINDER INFO
 * |      /////////////  Fixed Size Data (32 bytes)
 * |      EXT ATTR HDR
 * |      /////////////
 * |      ATTR ENTRY[0] --.
 * |      ATTR ENTRY[1] --+--.
 * |      ATTR ENTRY[2] --+--+--.
 * |         ...          |  |  |
 * |      ATTR ENTRY[N] --+--+--+--.
 * |      ATTR DATA 0   <-'  |  |  |
 * |      ////////////       |  |  |
 * |      ATTR DATA 1   <----'  |  |
 * |      /////////////         |  |
 * |      ATTR DATA 2   <-------'  |
 * |      /////////////            |
 * |         ...                   |
 * |      ATTR DATA N   <----------'
 * |      /////////////
 * |                      Attribute Free Space
 * |
 * '----> RESOURCE FORK
 *        /////////////   Variable Sized Data
 *        /////////////
 *        /////////////
 *        /////////////
 *        /////////////
 *        /////////////
 *           ...
 *        /////////////
 *
 * ------------------------------------------------------------
 *
 *  NOTE: The EXT ATTR HDR, ATTR ENTRY's and ATTR DATA's are
 *  stored as part of the Finder Info.  The length in the Finder
 *  Info AppleDouble entry includes the length of the extended
 *  attribute header, attribute entries, and attribute data.
 */

/*
 * On Disk Data Structures
 *
 * Note: Motorola 68K alignment and big-endian.
 *
 * See RFC 1740 for additional information about the AppleDouble file format.
 *
 */

#define ADH_MAGIC     0x00051607
#define ADH_VERSION   0x00020000
#define ADH_MACOSX    "Mac OS X        "

/*
 * AppleDouble Entry ID's
 */
#define AD_DATA          1   /* Data fork */
#define AD_RESOURCE      2   /* Resource fork */
#define AD_REALNAME      3   /* File's name on home file system */
#define AD_COMMENT       4   /* Standard Mac comment */
#define AD_ICONBW        5   /* Mac black & white icon */
#define AD_ICONCOLOR     6   /* Mac color icon */
#define AD_UNUSED        7   /* Not used */
#define AD_FILEDATES     8   /* File dates; create, modify, etc */
#define AD_FINDERINFO    9   /* Mac Finder info & extended info */
#define AD_MACINFO      10   /* Mac file info, attributes, etc */
#define AD_PRODOSINFO   11   /* Pro-DOS file info, attrib., etc */
#define AD_MSDOSINFO    12   /* MS-DOS file info, attributes, etc */
#define AD_AFPNAME      13   /* Short name on AFP server */
#define AD_AFPINFO      14   /* AFP file info, attrib., etc */
#define AD_AFPDIRID     15   /* AFP directory ID */
#define AD_ATTRIBUTES   AD_FINDERINFO


#define ATTR_FILE_PREFIX   "._"
#define ATTR_HDR_MAGIC     0x41545452   /* 'ATTR' */

#define ATTR_BUF_SIZE      4096        /* default size of the attr file and how much we'll grow by */

/* Implementation Limits */
#define ATTR_MAX_SIZE      AD_XATTR_MAXSIZE
#define ATTR_MAX_HDR_SIZE  65536
/*
 * Note: ATTR_MAX_HDR_SIZE is the largest attribute header
 * size supported (including the attribute entries). All of
 * the attribute entries must reside within this limit.  If
 * any of the attribute data crosses the ATTR_MAX_HDR_SIZE
 * boundry, then all of the attribute data I/O is performed
 * separately from the attribute header I/O.
 *
 * In particular, all of the attr_entry structures must lie
 * completely within the first ATTR_MAX_HDR_SIZE bytes of the
 * AppleDouble file.  However, the attribute data (i.e. the
 * contents of the extended attributes) may extend beyond the
 * first ATTR_MAX_HDR_SIZE bytes of the file.  Note that this
 * limit is to allow the implementation to optimize by reading
 * the first ATTR_MAX_HDR_SIZE bytes of the file.
 */


#define FINDERINFOSIZE  32

typedef struct apple_double_entry {
	u_int32_t   type;     /* entry type: see list, 0 invalid */
	u_int32_t   offset;   /* entry data offset from the beginning of the file. */
	u_int32_t   length;   /* entry data length in bytes. */
} __attribute__((aligned(2), packed)) apple_double_entry_t;


typedef struct apple_double_header {
	u_int32_t   magic;         /* == ADH_MAGIC */
	u_int32_t   version;       /* format version: 2 = 0x00020000 */
	u_int32_t   filler[4];
	u_int16_t   numEntries;    /* number of entries which follow */
	apple_double_entry_t   entries[2];  /* 'finfo' & 'rsrc' always exist */
	u_int8_t    finfo[FINDERINFOSIZE];  /* Must start with Finder Info (32 bytes) */
	u_int8_t    pad[2];        /* get better alignment inside attr_header */
} __attribute__((aligned(2), packed)) apple_double_header_t;

#define ADHDRSIZE  (4+4+16+2)

/* Entries are aligned on 4 byte boundaries */
typedef struct attr_entry {
	u_int32_t   offset;     /* file offset to data */
	u_int32_t   length;     /* size of attribute data */
	u_int16_t   flags;
	u_int8_t    namelen;
	u_int8_t    name[1];    /* NULL-terminated UTF-8 name (up to 128 bytes max) */
} __attribute__((aligned(2), packed)) attr_entry_t;


/* Header + entries must fit into 64K.  Data may extend beyond 64K. */
typedef struct attr_header {
	apple_double_header_t  appledouble;
	u_int32_t   magic;        /* == ATTR_HDR_MAGIC */
	u_int32_t   debug_tag;    /* for debugging == file id of owning file */
	u_int32_t   total_size;   /* file offset of end of attribute header + entries + data */
	u_int32_t   data_start;   /* file offset to attribute data area */
	u_int32_t   data_length;  /* length of attribute data area */
	u_int32_t   reserved[3];
	u_int16_t   flags;
	u_int16_t   num_attrs;
} __attribute__((aligned(2), packed)) attr_header_t;


/* Empty Resource Fork Header */
typedef struct rsrcfork_header {
	u_int32_t    fh_DataOffset;
	u_int32_t    fh_MapOffset;
	u_int32_t    fh_DataLength;
	u_int32_t    fh_MapLength;
	u_int8_t     systemData[112];
	u_int8_t     appData[128];
	u_int32_t    mh_DataOffset;
	u_int32_t    mh_MapOffset;
	u_int32_t    mh_DataLength;
	u_int32_t    mh_MapLength;
	u_int32_t    mh_Next;
	u_int16_t    mh_RefNum;
	u_int8_t     mh_Attr;
	u_int8_t     mh_InMemoryAttr;
	u_int16_t    mh_Types;
	u_int16_t    mh_Names;
	u_int16_t    typeCount;
} __attribute__((aligned(2), packed)) rsrcfork_header_t;

#define RF_FIRST_RESOURCE    256
#define RF_NULL_MAP_LENGTH    30
#define RF_EMPTY_TAG  "This resource fork intentionally left blank   "

/* Runtime information about the attribute file. */
typedef struct attr_info {
	vfs_context_t          context;
	vnode_t                filevp;
	size_t                 filesize;
	size_t                 iosize;
	u_int8_t               *rawdata;
	size_t                 rawsize;  /* minimum of filesize or ATTR_MAX_HDR_SIZE */
	apple_double_header_t  *filehdr;
	apple_double_entry_t   *finderinfo;
	apple_double_entry_t   *rsrcfork;
	attr_header_t          *attrhdr;
	attr_entry_t           *attr_entry;
	u_int8_t               readonly;
	u_int8_t               emptyfinderinfo;
} attr_info_t;


#define ATTR_SETTING  1

#define ATTR_ALIGN 3L  /* Use four-byte alignment */

#define ATTR_ENTRY_LENGTH(namelen)  \
	((sizeof(attr_entry_t) - 1 + (namelen) + ATTR_ALIGN) & (~ATTR_ALIGN))

#define ATTR_NEXT(ae)  \
	 (attr_entry_t *)((u_int8_t *)(ae) + ATTR_ENTRY_LENGTH((ae)->namelen))

#define ATTR_VALID(ae, ai)  \
	((&(ae)->namelen < ((ai).rawdata + (ai).rawsize)) && \
	 (u_int8_t *)ATTR_NEXT(ae) <= ((ai).rawdata + (ai).rawsize))

#define SWAP16(x)  OSSwapBigToHostInt16((x))
#define SWAP32(x)  OSSwapBigToHostInt32((x))
#define SWAP64(x)  OSSwapBigToHostInt64((x))


static int get_doubleagentd_port(mach_port_t *doubleagentd_port);

/*
 * DoubleAgent default xattr functions
 */
static int default_getxattr_doubleagent(vnode_t vp, const char *name,
    uio_t uio, size_t *size, int options, vfs_context_t context,
    mach_port_t);
static int default_setxattr_doubleagent(vnode_t vp, const char *name,
    uio_t uio, int options, vfs_context_t context, mach_port_t);
static int default_listxattr_doubleagent(vnode_t vp, uio_t uio, size_t *size,
    int options, vfs_context_t context, mach_port_t);
static int default_removexattr_doubleagent(vnode_t vp, const char *name,
    int options, vfs_context_t context, mach_port_t);


static u_int32_t emptyfinfo[8] = {0};


/*
 * Local support routines
 */
static void close_xattrfile(struct fileglob *xfg, bool have_iocount, bool drop_iocount, vfs_context_t context);

static int  open_xattrfile(vnode_t vp, int fileflags, struct fileglob **xfgp,
    int64_t *file_sizep, bool *created_xattr_filep, vfs_context_t context);

static void remove_xattrfile(struct fileglob *xfg, vnode_t xvp, vfs_context_t context);

static int  make_xattrfile_port(struct fileglob *xfg, ipc_port_t *portp);


/*
 * Retrieve the data of an extended attribute.
 */
static int
default_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
    __unused int options, vfs_context_t context)
{
	mach_port_t port;
	int error;

	if (get_doubleagentd_port(&port) == 0) {
		error = default_getxattr_doubleagent(vp, name, uio, size,
		    options, context, port);
		ipc_port_release_send(port);
	} else {
		error = ENOATTR;
	}
	return error;
}

/*
 * Set the data of an extended attribute.
 */
static int __attribute__((noinline))
default_setxattr(vnode_t vp, const char *name, uio_t uio, int options,
    vfs_context_t context)
{
	mach_port_t port;
	int error;

	if (get_doubleagentd_port(&port) == 0) {
		error = default_setxattr_doubleagent(vp, name, uio, options,
		    context, port);
		ipc_port_release_send(port);
	} else {
		error = ENOATTR;
	}
	return error;
}

/*
 * Remove an extended attribute.
 */
static int
default_removexattr(vnode_t vp, const char *name, __unused int options,
    vfs_context_t context)
{
	mach_port_t port;
	int error;

	if (get_doubleagentd_port(&port) == 0) {
		error = default_removexattr_doubleagent(vp, name, options,
		    context, port);
		ipc_port_release_send(port);
	} else {
		error = ENOATTR;
	}
	return error;
}

/*
 * Retrieve the list of extended attribute names.
 */
static int
default_listxattr(vnode_t vp, uio_t uio, size_t *size, __unused int options,
    vfs_context_t context)
{
	mach_port_t port;
	int error;

	if (get_doubleagentd_port(&port) == 0) {
		error = default_listxattr_doubleagent(vp, uio, size, options,
		    context, port);
		ipc_port_release_send(port);
	} else {
		error = 0;
	}
	return error;
}

static int
get_doubleagentd_port(mach_port_t *doubleagentd_port)
{
	kern_return_t ret;

	*doubleagentd_port = MACH_PORT_NULL;
	ret = host_get_doubleagentd_port(host_priv_self(), doubleagentd_port);
	if (ret != KERN_SUCCESS) {
		printf("vfs_xattr: can't get doubleagentd port, status 0x%08x\n", ret);
		return EIO;
	}
	if (!IPC_PORT_VALID(*doubleagentd_port)) {
		printf("vfs_xattr: doubleagentd port not valid\n");
		return EIO;
	}
	return 0;
}

/*
 * Retrieve the data of an extended attribute.
 * (Using DoubleAgent to parse the AD file).
 */
static int
default_getxattr_doubleagent(vnode_t vp, const char *name, uio_t uio,
    size_t *size, __unused int options, vfs_context_t context,
    mach_port_t doubleagentd_port)
{
	vnode_t xvp = NULL;
	struct fileglob *xfg = NULL;
	mach_port_t fileport = MACH_PORT_NULL;
	uint64_t value_offset = 0;
	uint64_t value_length = 0;
	int64_t fsize;
	int isrsrcfork;
	int fileflags;
	int error;
	kern_return_t kr;
	char cName[XATTR_MAXNAMELEN + 1] = {0};
	bool have_iocount = true;

	fileflags = FREAD | O_SHLOCK;
	isrsrcfork = strncmp(name, XATTR_RESOURCEFORK_NAME,
	    sizeof(XATTR_RESOURCEFORK_NAME)) == 0;

	if ((error = open_xattrfile(vp, fileflags, &xfg, &fsize, NULL, context))) {
		goto out;
	}
	xvp = fg_get_data(xfg);
	if ((error = make_xattrfile_port(xfg, &fileport))) {
		goto out;
	}

	/* Drop the iocount before upcalling to doubleagentd. */
	vnode_put(xvp);
	have_iocount = false;

	(void)strlcpy(cName, name, XATTR_MAXNAMELEN + 1);

	/*
	 * Call doubleagentd to look up the xattr.  The fileport argument
	 * is declared move-send, so the Mig stub consumes it.
	 */
	kr = doubleagent_lookup_xattr(doubleagentd_port, fileport, fsize, cName,
	    &error, &value_offset, &value_length);
	if (kr != KERN_SUCCESS) {
		error = EIO;
	}
	if (error == 0) {
		error = vnode_getwithref(xvp);
	}
	if (error) {
		goto out;
	}
	have_iocount = true;
	if (uio != NULL) {
		if (isrsrcfork) {
			// Resource Fork case is a bit different,
			// as we can have a non-zero uio offset.
			uio_setoffset(uio, uio_offset(uio) + value_offset);
			error = VNOP_READ(xvp, uio, 0, context);
			if (error == 0) {
				uio_setoffset(uio, uio_offset(uio) - value_offset);
			}
		} else {
			if (uio_resid(uio) < value_length) {
				error = ERANGE;
				goto out;
			}

			// Read from the relevant offset in the AD file into the uio.
			user_ssize_t orig_resid = uio_resid(uio);
			uio_setoffset(uio, value_offset);
			uio_setresid(uio, value_length);

			error = VNOP_READ(xvp, uio, 0, context);

			uio_setoffset(uio, 0);
			uio_setresid(uio, orig_resid - value_length + uio_resid(uio));
		}
	}

	*size = value_length;

out:
	if (xfg != NULL) {
		close_xattrfile(xfg, have_iocount, true, context);
	}
	return error;
}

/*
 * Retrieve the list of extended attribute names.
 * (Using DoubleAgent to parse the AD file).
 */
static int
default_listxattr_doubleagent(vnode_t vp, uio_t uio, size_t *size,
    __unused int options, vfs_context_t context, mach_port_t doubleagentd_port)
{
	vnode_t xvp = NULL;
	struct fileglob *xfg = NULL;
	int64_t fsize;
	int error;

	mach_port_t fileport = MACH_PORT_NULL;
	kern_return_t kr;
	void *buf = NULL;
	listxattrs_result_t *result;
	bool have_iocount = true;

	/*
	 * We do not zero "*size" here as we don't want to stomp a size set
	 * when VNOP_LISTXATTR() processed any native EAs.  That size is
	 * initially zeroed by the system call layer, up in listxattr() or
	 * flistxattr().
	 */

	if ((error = open_xattrfile(vp, FREAD | O_SHLOCK, &xfg, &fsize, NULL,
	    context))) {
		if (error == ENOATTR) {
			error = 0;
		}
		goto out;
	}
	xvp = fg_get_data(xfg);
	if ((error = make_xattrfile_port(xfg, &fileport))) {
		goto out;
	}

	/* Drop the iocount before upcalling to doubleagentd. */
	vnode_put(xvp);
	have_iocount = false;

	buf = kalloc_data(sizeof(listxattrs_result_t), Z_WAITOK);
	result = (listxattrs_result_t *)buf;

	/*
	 * Call doubleagentd to list the xattrs.  The fileport argument
	 * is declared move-send, so the Mig stub consumes it.
	 */
	kr = doubleagent_list_xattrs(doubleagentd_port, fileport, fsize, &error,
	    result);
	if (kr != KERN_SUCCESS) {
		error = EIO;
	}
	if (error == 0) {
		error = vnode_getwithref(xvp);
	}
	if (error) {
		goto out;
	}
	have_iocount = true;

	if (uio != NULL) {
		if (uio_resid(uio) < result->namesLength) {
			error = ERANGE;
			goto out;
		}
		// copy the relevant part of the result into the uio.
		error = uiomove((const char *)result->data, (int)result->namesLength, uio);
		if (error) {
			if (error != EFAULT) {
				error = ERANGE;
			}
			goto out;
		}
	}

	/*
	 * Set *size, while preserving any previous value from
	 * VNOP_LISTXATTR().
	 */
	*size += result->namesLength;

out:
	if (xfg != NULL) {
		close_xattrfile(xfg, have_iocount, true, context);
	}
	if (buf != NULL) {
		kfree_data(buf, sizeof(listxattrs_result_t));
	}
	return error;
}

/*
 * Set the data of an extended attribute.
 * (Using DoubleAgent to parse the AD file).
 */
static int __attribute__((noinline))
default_setxattr_doubleagent(vnode_t vp, const char *name, uio_t uio,
    int options, vfs_context_t context, mach_port_t doubleagentd_port)
{
	vnode_t xvp = NULL;
	struct fileglob *xfg = NULL;
	size_t datalen;
	int namelen;
	int fileflags;
	int error;
	char cName[XATTR_MAXNAMELEN + 1] = {0};
	char finfo[FINDERINFOSIZE];
	uio_t finfo_uio = NULL;
	mach_port_t fileport = MACH_PORT_NULL;
	uint64_t value_offset = 0;
	int64_t fsize;
	kern_return_t kr;
	bool have_iocount = true;
	bool created_xattr_file = false;
	bool removed_xattr_file = false;

	datalen = uio_resid(uio);
	if (datalen > XATTR_MAXSIZE) {
		return E2BIG;
	}
	namelen = (int)strlen(name) + 1;
	if (namelen > UINT8_MAX) {
		return EINVAL;
	}

	/*
	 * By convention, Finder Info that is all zeroes is equivalent to not
	 * having a Finder Info EA.  So if we're trying to set the Finder Info
	 * to all zeroes, then delete it instead.  If a file didn't have an
	 * AppleDouble file before, this prevents creating an AppleDouble file
	 * with no useful content.
	 *
	 * If neither XATTR_CREATE nor XATTR_REPLACE were specified, we check
	 * for all zeroes Finder Info before opening the AppleDouble file.
	 * But if either of those options were specified, we need to open the
	 * AppleDouble file to see whether there was already Finder Info (so we
	 * can return an error if needed); this case is handled in DoubleAgent.
	 */
	if (strncmp(name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if (uio_offset(uio) != 0) {
			return EINVAL;
		}

		if (datalen != FINDERINFOSIZE) {
			return ERANGE;
		}

		// Duplicate the uio to keep it as-is for later.
		finfo_uio = uio_duplicate(uio);
		// Get the finfo data from the duplicated uio.
		error = uiomove(finfo, (int)datalen, finfo_uio);
		uio_free(finfo_uio);
		if (error) {
			return error;
		}
		if ((options & (XATTR_CREATE | XATTR_REPLACE)) == 0 &&
		    bcmp(finfo, emptyfinfo, FINDERINFOSIZE) == 0) {
			error = default_removexattr(vp, name, 0, context);
			if (error == ENOATTR) {
				error = 0;
			}
			return error;
		}
	}

	if (strncmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
		/*
		 * For ResourceFork we allow offset to be != 0, so adjust datalen accordingly
		 * so doubleagent will adjust the file length accordingly
		 *
		 */
		if (__improbable(os_add_overflow(datalen, uio_offset(uio), &datalen))) {
			return EINVAL;
		}

		if (datalen > UINT32_MAX) {
			return EINVAL;
		}

		/*
		 * Don't allow overriding a part of the resource fork header (the first
		 * sizeof(rsrcfork_header_t) bytes of the resource fork).  We only allow
		 * overriding it completely, or writing beyond it.
		 * Note that datalen = uio_offset(uio) + uio_resid(uio).
		 */
		if ((uio_offset(uio) > 0 &&
		    uio_offset(uio) < sizeof(rsrcfork_header_t)) ||
		    (datalen < sizeof(rsrcfork_header_t))) {
			return EINVAL;
		}
	}

	/*
	 * Open the file locked since setting an attribute
	 * can change the layout of the Apple Double file.
	 */
	fileflags = FREAD | FWRITE | O_EXLOCK;
	if ((error = open_xattrfile(vp, O_CREAT | fileflags, &xfg, &fsize,
	    &created_xattr_file, context))) {
		goto out;
	}
	xvp = fg_get_data(xfg);
	if ((error = make_xattrfile_port(xfg, &fileport))) {
		goto out;
	}

	/* Drop the iocount before upcalling to doubleagentd. */
	vnode_put(xvp);
	have_iocount = false;

	(void)strlcpy(cName, name, XATTR_MAXNAMELEN + 1);

	/*
	 * Call doubleagentd to allocate space for the xattr.  The
	 * fileport argument is declared move-send, so the Mig stub
	 * consumes it.
	 */
	kr = doubleagent_allocate_xattr(doubleagentd_port, fileport, fsize,
	    cName, datalen, options, &error, &value_offset);
	if (kr != KERN_SUCCESS) {
		error = EIO;
	}
	if (error == 0) {
		error = vnode_getwithref(xvp);
	}
	if (error) {
		goto out;
	}
	have_iocount = true;

	/*
	 * write the uio data into the offset we got from doubleagent,
	 * while adding the given uio offset (could be non-zero only for
	 * resource fork; it is being checked earlier).
	 */
	uio_setoffset(uio, uio_offset(uio) + value_offset);
	error = VNOP_WRITE(xvp, uio, 0, context);
	uio_setoffset(uio, 0);

out:
	if (xfg != NULL) {
		/*
		 * In case we have just created the AppleDouble file, and DoubleAgent
		 * couldn't allocate space for the xattr, remove it so we won't leave
		 * an uninitialized AppleDouble file.
		 */
		if (error && created_xattr_file) {
			/* remove_xattrfile() assumes we have an iocount on the vnode */
			if (vnode_getwithref(xvp) == 0) {
				remove_xattrfile(xfg, xvp, context);
				removed_xattr_file = true;
			}
		}
		/* remove_xattrfile() would call close_xattrfile already */
		if (!removed_xattr_file) {
			close_xattrfile(xfg, have_iocount, true, context);
		}
	}

	/* Touch the change time if we changed an attribute. */
	if (error == 0) {
		struct vnode_attr va;

		/* Re-write the mtime to cause a ctime change. */
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_modify_time);
		if (vnode_getattr(vp, &va, context) == 0) {
			VATTR_INIT(&va);
			VATTR_SET(&va, va_modify_time, va.va_modify_time);
			(void) vnode_setattr(vp, &va, context);
		}
	}

	post_event_if_success(vp, error, NOTE_ATTRIB);

	return error;
}

/*
 * Remove an extended attribute.
 * (Using DoubleAgent to parse the AD file).
 */
static int
default_removexattr_doubleagent(vnode_t vp, const char *name,
    __unused int options, vfs_context_t context,
    mach_port_t doubleagentd_port)
{
	vnode_t xvp = NULL;
	struct fileglob *xfg = NULL;
	int isrsrcfork;
	int fileflags;
	int error;
	int64_t fsize;
	boolean_t is_empty = false;
	char cName[XATTR_MAXNAMELEN + 1] = {0};
	mach_port_t fileport = MACH_PORT_NULL;
	kern_return_t kr;
	bool have_iocount = true;

	fileflags = FREAD | FWRITE | O_EXLOCK;
	isrsrcfork = strncmp(name, XATTR_RESOURCEFORK_NAME,
	    sizeof(XATTR_RESOURCEFORK_NAME)) == 0;

	if ((error = open_xattrfile(vp, fileflags, &xfg, &fsize, NULL, context))) {
		goto out;
	}
	xvp = fg_get_data(xfg);
	if ((error = make_xattrfile_port(xfg, &fileport))) {
		goto out;
	}

	/* Drop the iocount before upcalling to doubleagentd. */
	vnode_put(xvp);
	have_iocount = false;

	(void)strlcpy(cName, name, XATTR_MAXNAMELEN + 1);

	/*
	 * Call doubleagentd to remove the xattr.  The fileport argument
	 * is declared move-send, so the Mig stub consumes it.
	 */
	kr = doubleagent_remove_xattr(doubleagentd_port, fileport, fsize, cName,
	    &error, &is_empty);
	if (kr != KERN_SUCCESS) {
		error = EIO;
	}
	if (error == 0) {
		error = vnode_getwithref(xvp);
	}
	if (error) {
		goto out;
	}
	have_iocount = true;

out:
	if (error == 0) {
		/* When there are no more attributes remove the ._ file. */
		if (is_empty) {
			remove_xattrfile(xfg, xvp, context);
		} else {
			close_xattrfile(xfg, have_iocount, true, context);
		}
		xfg = NULL;

		/* Touch the change time if we changed an attribute. */
		struct vnode_attr va;
		/* Re-write the mtime to cause a ctime change. */
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_modify_time);
		if (vnode_getattr(vp, &va, context) == 0) {
			VATTR_INIT(&va);
			VATTR_SET(&va, va_modify_time, va.va_modify_time);
			(void) vnode_setattr(vp, &va, context);
		}
	}

	post_event_if_success(vp, error, NOTE_ATTRIB);

	if (xfg != NULL) {
		close_xattrfile(xfg, have_iocount, true, context);
	}
	return error;
}

static int
open_xattrfile(vnode_t vp, int fileflags, struct fileglob **xfgp,
    int64_t *file_sizep, bool *created_xattr_filep, vfs_context_t context)
{
	extern const struct fileops vnops;      /* XXX */
	vnode_t xvp = NULLVP;
	vnode_t dvp = NULLVP;
	struct fileglob *fg = NULL;
	struct vnode_attr *va = NULL;
	struct nameidata *nd = NULL;
	char smallname[64];
	char *filename = NULL;
	const char *basename = NULL;
	size_t alloc_len = 0;
	size_t copy_len;
	errno_t error;
	int opened = 0;
	int referenced = 0;
	bool created_xattr_file = false;

	if (vnode_isvroot(vp) && vnode_isdir(vp)) {
		/*
		 * For the root directory use "._." to hold the attributes.
		 */
		filename = &smallname[0];
		snprintf(filename, sizeof(smallname), "%s%s", ATTR_FILE_PREFIX, ".");
		dvp = vp;  /* the "._." file resides in the root dir */
		goto lookup;
	}
	if ((dvp = vnode_getparent(vp)) == NULLVP) {
		error = ENOATTR;
		goto out;
	}
	if ((basename = vnode_getname(vp)) == NULL) {
		error = ENOATTR;
		goto out;
	}

	/* "._" Attribute files cannot have attributes */
	if (vp->v_type == VREG && strlen(basename) > 2 &&
	    basename[0] == '.' && basename[1] == '_') {
		error = EPERM;
		goto out;
	}
	filename = &smallname[0];
	alloc_len = snprintf(filename, sizeof(smallname), "%s%s", ATTR_FILE_PREFIX, basename);
	if (alloc_len >= sizeof(smallname)) {
		alloc_len++;  /* snprintf result doesn't include '\0' */
		filename = kalloc_data(alloc_len, Z_WAITOK);
		copy_len = snprintf(filename, alloc_len, "%s%s", ATTR_FILE_PREFIX, basename);
	}
	/*
	 * Note that the lookup here does not authorize.  Since we are looking
	 * up in the same directory that we already have the file vnode in,
	 * we must have been given the file vnode legitimately.  Read/write
	 * access has already been authorized in layers above for calls from
	 * userspace, and the authorization code using this path to read
	 * file security from the EA must always get access
	 */
lookup:
	nd = kalloc_type(struct nameidata, Z_WAITOK);
	NDINIT(nd, LOOKUP, OP_OPEN, LOCKLEAF | NOFOLLOW | USEDVP | DONOTAUTH,
	    UIO_SYSSPACE, CAST_USER_ADDR_T(filename), context);
	nd->ni_dvp = dvp;

	va = kalloc_type(struct vnode_attr, Z_WAITOK);

	if (fileflags & O_CREAT) {
		nd->ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
		nd->ni_op = OP_LINK;
#endif
		if (dvp != vp) {
			nd->ni_cnd.cn_flags |= LOCKPARENT;
		}
		if ((error = namei(nd))) {
			nd->ni_dvp = NULLVP;
			error = ENOATTR;
			goto out;
		}
		if ((xvp = nd->ni_vp) == NULLVP) {
			uid_t uid;
			gid_t gid;
			mode_t umode;

			/*
			 * Pick up uid/gid/mode from target file.
			 */
			VATTR_INIT(va);
			VATTR_WANTED(va, va_uid);
			VATTR_WANTED(va, va_gid);
			VATTR_WANTED(va, va_mode);
			if (VNOP_GETATTR(vp, va, context) == 0 &&
			    VATTR_IS_SUPPORTED(va, va_uid) &&
			    VATTR_IS_SUPPORTED(va, va_gid) &&
			    VATTR_IS_SUPPORTED(va, va_mode)) {
				uid = va->va_uid;
				gid = va->va_gid;
				umode = va->va_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
			} else { /* fallback values */
				uid = KAUTH_UID_NONE;
				gid = KAUTH_GID_NONE;
				umode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			}

			VATTR_INIT(va);
			VATTR_SET(va, va_type, VREG);
			VATTR_SET(va, va_mode, umode);
			if (uid != KAUTH_UID_NONE) {
				VATTR_SET(va, va_uid, uid);
			}
			if (gid != KAUTH_GID_NONE) {
				VATTR_SET(va, va_gid, gid);
			}

			error = vn_create(dvp, &nd->ni_vp, nd, va,
			    VN_CREATE_NOAUTH | VN_CREATE_NOINHERIT | VN_CREATE_NOLABEL,
			    0, NULL,
			    context);
			if (error) {
				error = ENOATTR;
			} else {
				xvp = nd->ni_vp;
				created_xattr_file = true;
				if (created_xattr_filep) {
					*created_xattr_filep = true;
				}
			}
		}
		nameidone(nd);
		if (dvp != vp) {
			vnode_put(dvp);  /* drop iocount from LOCKPARENT request above */
		}
		if (error) {
			goto out;
		}
	} else {
		if ((error = namei(nd))) {
			nd->ni_dvp = NULLVP;
			error = ENOATTR;
			goto out;
		}
		xvp = nd->ni_vp;
		nameidone(nd);
	}
	nd->ni_dvp = NULLVP;

	if (xvp->v_type != VREG) {
		error = ENOATTR;
		goto out;
	}
	/*
	 * Owners must match.
	 */
	VATTR_INIT(va);
	VATTR_WANTED(va, va_uid);
	if (VNOP_GETATTR(vp, va, context) == 0 && VATTR_IS_SUPPORTED(va, va_uid)) {
		uid_t owner = va->va_uid;

		VATTR_INIT(va);
		VATTR_WANTED(va, va_uid);
		if (VNOP_GETATTR(xvp, va, context) == 0 && (owner != va->va_uid)) {
			error = ENOATTR;  /* don't use this "._" file */
			goto out;
		}
	}

	if ((error = VNOP_OPEN(xvp, fileflags & ~(O_EXLOCK | O_SHLOCK), context))) {
		error = ENOATTR;
		goto out;
	}
	opened = 1;

	if ((error = vnode_ref_ext(xvp, fileflags, 0)) != 0) {
		goto out;
	}
	referenced = 1;

	/*
	 * Allocate a file object for the referenced vnode.
	 * This file object now owns the vnode reference,
	 * and the caller owns the iocount, which will be
	 * dropped in close_xattrfile().
	 */
	fg = fg_alloc_init(context);
	fg->fg_flag = fileflags & FMASK;
	fg->fg_ops = &vnops;
	fg_set_data(fg, xvp);

	/* Apply file locking if requested. */
	if (fileflags & (O_EXLOCK | O_SHLOCK)) {
		struct flock lf = {
			.l_whence = SEEK_SET,
		};

		if (fileflags & O_EXLOCK) {
			lf.l_type = F_WRLCK;
		} else {
			lf.l_type = F_RDLCK;
		}
		error = VNOP_ADVLOCK(xvp, (caddr_t)fg, F_SETLK, &lf, F_FLOCK | F_WAIT, context, NULL);
		if (error == ENOTSUP) {
			error = 0;
		} else if (error) {
			error = ENOATTR;
			goto out;
		} else { // error == 0
			fg->fg_flag |= FWASLOCKED;
		}
	}

	if (file_sizep != NULL) {
		/*
		 * Now that the file is locked, get the file's size.
		 */
		VATTR_INIT(va);
		VATTR_WANTED(va, va_data_size);
		if ((error = vnode_getattr(xvp, va, context)) != 0) {
			error = ENOATTR;
			goto out;
		}
		*file_sizep = va->va_data_size;
	}
out:
	if (error) {
		if (fg != NULL) {
			/* Let the normal close path handle this. */
			if (created_xattr_file) {
				remove_xattrfile(fg, xvp, context);
			} else {
				close_xattrfile(fg, true, true, context);
			}
			fg = NULL;
			xvp = NULLVP;
		} else if (xvp != NULLVP) {
			if (opened) {
				(void) VNOP_CLOSE(xvp, fileflags, context);
			}
			if (created_xattr_file) {
				remove_xattrfile(NULL, xvp, context);
			}
			if (referenced) {
				(void) vnode_rele(xvp);
			}
			/* remove_xattrfile() would have dropped the iocount already */
			if (!created_xattr_file) {
				(void) vnode_put(xvp);
			}
			xvp = NULLVP;
		}
		if ((error == ENOATTR) && (fileflags & O_CREAT)) {
			error = EPERM;
		}
	}

	/* Release resources after error-handling */
	kfree_type(struct nameidata, nd);
	kfree_type(struct vnode_attr, va);
	if (dvp && (dvp != vp)) {
		vnode_put(dvp);
	}
	if (basename) {
		vnode_putname(basename);
	}
	if (filename && filename != &smallname[0]) {
		kfree_data(filename, alloc_len);
	}

	*xfgp = fg;
	return error;
}

static void
close_xattrfile(struct fileglob *xfg, bool have_iocount, bool drop_iocount,
    vfs_context_t context)
{
	vnode_t xvp = fg_get_data(xfg);

	/*
	 * N.B. The only time have_iocount would be false would be when
	 * a vnode_getwithref() calls fails after coming back from a
	 * doubleagentd upcall.  If that happens, then it would mean
	 * that the old vnode identity is gone, and our advisory lock
	 * would have been garbage-collected when the vnode was reclaimed.
	 */
	if (have_iocount) {
		/*
		 * fg_drop() won't drop our advisory lock because we are not
		 * following POSIX semantics.  Drop it here.
		 */
		struct flock lf = {
			.l_whence = SEEK_SET,
			.l_type = F_UNLCK,
		};
		(void)VNOP_ADVLOCK(xvp, (caddr_t)xfg, F_UNLCK, &lf, F_FLOCK,
		    context, NULL);

		/* (Maybe) drop the iocount we took in open_xattrfile(). */
		if (drop_iocount) {
			vnode_put(xvp);
		}
	}

	(void) fg_drop(current_proc(), xfg);
}

static void
remove_xattrfile(struct fileglob *xfg, vnode_t xvp, vfs_context_t context)
{
	vnode_t dvp = NULL, rvp = NULL;
	struct nameidata nd;
	char *path = NULL;
	int pathlen;
	int error;

	if (xfg != NULL) {
		/*
		 * Close the xattr file but don't dispose of the
		 * iocount acquired in open_xattrfile() while doing
		 * so.  We'll do that below once we have performed
		 * the unlink operation.
		 */
		close_xattrfile(xfg, true, false, context);
	}

	path = zalloc(ZV_NAMEI);
	pathlen = MAXPATHLEN;
	error = vn_getpath(xvp, path, &pathlen);
	if (error) {
		zfree(ZV_NAMEI, path);
		goto out;
	}

	NDINIT(&nd, DELETE, OP_UNLINK, LOCKPARENT | NOFOLLOW | DONOTAUTH,
	    UIO_SYSSPACE, CAST_USER_ADDR_T(path), context);
	error = namei(&nd);
	zfree(ZV_NAMEI, path);
	if (error) {
		goto out;
	}
	dvp = nd.ni_dvp;
	rvp = nd.ni_vp;

	/*
	 * Only remove if the namei() returned to us the same vnode that
	 * we think we are supposed to be removing.  If they're not the
	 * same, we could have raced against something else trying to
	 * unlink it, and we don't want to remove someone else's (possibly
	 * very important) file.
	 */
	if (rvp == xvp) {
		(void) VNOP_REMOVE(dvp, rvp, &nd.ni_cnd, 0, context);
	}
	nameidone(&nd);

out:
	vnode_put(xvp);
	if (dvp != NULLVP) {
		vnode_put(dvp);
	}
	if (rvp != NULLVP) {
		vnode_put(rvp);
	}
}

static int
make_xattrfile_port(struct fileglob *fg, ipc_port_t *portp)
{
	/*
	 * This is essentially a stripped-down copy of
	 * sys_fileport_makeport().
	 */
	ipc_port_t fileport;
	int error = 0;

	/* Dropped when port is deallocated. */
	fg_ref(FG_NOPROC, fg);

	fileport = fileport_alloc(fg);
	if (fileport == IPC_PORT_NULL) {
		fg_drop_live(fg);
		error = EIO;
	} else {
		/* Tag the fileglob for debugging purposes */
		lck_mtx_lock_spin(&fg->fg_lock);
		fg->fg_lflags |= FG_PORTMADE;
		lck_mtx_unlock(&fg->fg_lock);
	}

	/*
	 * The Mig defs for doubleagentd declare the fileport argument
	 * as move-send.  If we ever decide we want to cache the fileport
	 * here in the kernel, we will either need to change the Mig
	 * defs back to the default mach_port_t (which is a copy-send)
	 * or explicitly ipc_port_copy_send_any() the right before
	 * sending it in the Mig stub.
	 */

	*portp = fileport;
	return error;
}

#else /* CONFIG_APPLEDOUBLE */


static int
default_getxattr(__unused vnode_t vp, __unused const char *name,
    __unused uio_t uio, __unused size_t *size, __unused int options,
    __unused vfs_context_t context)
{
	return ENOTSUP;
}

static int
default_setxattr(__unused vnode_t vp, __unused const char *name,
    __unused uio_t uio, __unused int options, __unused vfs_context_t context)
{
	return ENOTSUP;
}

static int
default_listxattr(__unused vnode_t vp,
    __unused uio_t uio, __unused size_t *size, __unused int options,
    __unused vfs_context_t context)
{
	return ENOTSUP;
}

static int
default_removexattr(__unused vnode_t vp, __unused const char *name,
    __unused int options, __unused vfs_context_t context)
{
	return ENOTSUP;
}

#endif /* CONFIG_APPLEDOUBLE */
