/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)dead_vnops.c	8.3 (Berkeley) 5/14/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode_internal.h>
#include <sys/buf_internal.h>
#include <sys/errno.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <vfs/vfs_support.h>

int     chkvnlock(vnode_t vp);

/*
 * Prototypes for dead operations on vnodes.
 */
int     dead_badop(void *);
int     dead_ebadf(void *);
int     dead_lookup(struct vnop_lookup_args *);
int     dead_open(struct vnop_open_args *);
#define dead_access (int (*)(struct  vnop_access_args *))dead_ebadf
#define dead_getattr (int (*)(struct  vnop_getattr_args *))dead_ebadf
#define dead_setattr (int (*)(struct  vnop_setattr_args *))dead_ebadf
int     dead_read(struct vnop_read_args *);
int     dead_write(struct vnop_write_args *);
int     dead_ioctl(struct vnop_ioctl_args *);
int     dead_select(struct vnop_select_args *);
#define dead_readdir (int (*)(struct  vnop_readdir_args *))dead_ebadf
#define dead_readlink (int (*)(struct  vnop_readlink_args *))dead_ebadf
int     dead_strategy(struct vnop_strategy_args *);
int     dead_bwrite(struct vnop_bwrite_args *);
#define dead_pathconf (int (*)(struct  vnop_pathconf_args *))dead_ebadf
#define dead_advlock (int (*)(struct  vnop_advlock_args *))dead_ebadf
int     dead_pagein(struct vnop_pagein_args *);
int     dead_pageout(struct vnop_pageout_args *);
int dead_blktooff(struct vnop_blktooff_args *);
int dead_offtoblk(struct vnop_offtoblk_args *);
int dead_blockmap(struct vnop_blockmap_args *);

#define dead_nullop (void (*)(void))nullop

#define VOPFUNC int (*)(void *)
int(**dead_vnodeop_p)(void *);
const struct vnodeopv_entry_desc dead_vnodeop_entries[] = {
	{ .opve_op = &vnop_default_desc, .opve_impl = (VOPFUNC)(void (*)(void ))vn_default_error },
	{ .opve_op = &vnop_lookup_desc, .opve_impl = (VOPFUNC)dead_lookup },    /* lookup */
	{ .opve_op = &vnop_create_desc, .opve_impl = (VOPFUNC)dead_badop },    /* create */
	{ .opve_op = &vnop_open_desc, .opve_impl = (VOPFUNC)dead_open },                /* open */
	{ .opve_op = &vnop_mknod_desc, .opve_impl = (VOPFUNC)dead_badop },              /* mknod */
	{ .opve_op = &vnop_close_desc, .opve_impl = (VOPFUNC)dead_nullop },      /* close */
	{ .opve_op = &vnop_access_desc, .opve_impl = (VOPFUNC)dead_access },    /* access */
	{ .opve_op = &vnop_getattr_desc, .opve_impl = (VOPFUNC)dead_getattr },  /* getattr */
	{ .opve_op = &vnop_setattr_desc, .opve_impl = (VOPFUNC)dead_setattr },  /* setattr */
	{ .opve_op = &vnop_read_desc, .opve_impl = (VOPFUNC)dead_read },                /* read */
	{ .opve_op = &vnop_write_desc, .opve_impl = (VOPFUNC)dead_write },      /* write */
	{ .opve_op = &vnop_ioctl_desc, .opve_impl = (VOPFUNC)dead_ioctl },      /* ioctl */
	{ .opve_op = &vnop_select_desc, .opve_impl = (VOPFUNC)dead_select },    /* select */
	{ .opve_op = &vnop_mmap_desc, .opve_impl = (VOPFUNC)dead_badop },                /* mmap */
	{ .opve_op = &vnop_fsync_desc, .opve_impl = (VOPFUNC)dead_nullop},      /* fsync */
	{ .opve_op = &vnop_remove_desc, .opve_impl = (VOPFUNC)dead_badop },    /* remove */
	{ .opve_op = &vnop_link_desc, .opve_impl = (VOPFUNC)dead_badop },                /* link */
	{ .opve_op = &vnop_rename_desc, .opve_impl = (VOPFUNC)dead_badop },    /* rename */
	{ .opve_op = &vnop_mkdir_desc, .opve_impl = (VOPFUNC)dead_badop },      /* mkdir */
	{ .opve_op = &vnop_rmdir_desc, .opve_impl = (VOPFUNC)dead_badop },      /* rmdir */
	{ .opve_op = &vnop_symlink_desc, .opve_impl = (VOPFUNC)dead_badop },  /* symlink */
	{ .opve_op = &vnop_readdir_desc, .opve_impl = (VOPFUNC)dead_readdir },  /* readdir */
	{ .opve_op = &vnop_readlink_desc, .opve_impl = (VOPFUNC)dead_readlink },        /* readlink */
	{ .opve_op = &vnop_inactive_desc, .opve_impl = (VOPFUNC)dead_nullop },        /* inactive */
	{ .opve_op = &vnop_reclaim_desc, .opve_impl = (VOPFUNC)dead_nullop },  /* reclaim */
	{ .opve_op = &vnop_strategy_desc, .opve_impl = (VOPFUNC)dead_strategy },        /* strategy */
	{ .opve_op = &vnop_pathconf_desc, .opve_impl = (VOPFUNC)dead_pathconf },        /* pathconf */
	{ .opve_op = &vnop_advlock_desc, .opve_impl = (VOPFUNC)dead_advlock },  /* advlock */
	{ .opve_op = &vnop_bwrite_desc, .opve_impl = (VOPFUNC)dead_bwrite },    /* bwrite */
	{ .opve_op = &vnop_pagein_desc, .opve_impl = (VOPFUNC)err_pagein },     /* Pagein */
	{ .opve_op = &vnop_pageout_desc, .opve_impl = (VOPFUNC)err_pageout },   /* Pageout */
	{ .opve_op = &vnop_copyfile_desc, .opve_impl = (VOPFUNC)err_copyfile }, /* Copyfile */
	{ .opve_op = &vnop_blktooff_desc, .opve_impl = (VOPFUNC)dead_blktooff },        /* blktooff */
	{ .opve_op = &vnop_offtoblk_desc, .opve_impl = (VOPFUNC)dead_offtoblk },        /* offtoblk */
	{ .opve_op = &vnop_blockmap_desc, .opve_impl = (VOPFUNC)dead_blockmap },                /* blockmap */
	{ .opve_op = (struct vnodeop_desc*)NULL, .opve_impl = (VOPFUNC)NULL }
};
const struct vnodeopv_desc dead_vnodeop_opv_desc =
{ .opv_desc_vector_p = &dead_vnodeop_p, .opv_desc_ops = dead_vnodeop_entries };

/*
 * Trivial lookup routine that always fails.
 */
/* ARGSUSED */
int
dead_lookup(struct vnop_lookup_args *ap)
{
	*ap->a_vpp = NULL;
	return ENOTDIR;
}

/*
 * Open always fails as if device did not exist.
 */
/* ARGSUSED */
int
dead_open(__unused struct vnop_open_args *ap)
{
	return ENXIO;
}

/*
 * Vnode op for read
 */
/* ARGSUSED */
int
dead_read(struct vnop_read_args *ap)
{
	if (chkvnlock(ap->a_vp)) {
		panic("dead_read: lock");
	}
	/*
	 * Return EOF for character devices, EIO for others
	 */
	if (ap->a_vp->v_type != VCHR) {
		return EIO;
	}
	return 0;
}

/*
 * Vnode op for write
 */
/* ARGSUSED */
int
dead_write(struct vnop_write_args *ap)
{
	if (chkvnlock(ap->a_vp)) {
		panic("dead_write: lock");
	}
	return EIO;
}

/*
 * Device ioctl operation.
 */
/* ARGSUSED */
int
dead_ioctl(struct vnop_ioctl_args *ap)
{
	if (!chkvnlock(ap->a_vp)) {
		return EBADF;
	}
	return VCALL(ap->a_vp, VOFFSET(vnop_ioctl), ap);
}

/* ARGSUSED */
int
dead_select(__unused struct vnop_select_args *ap)
{
	/*
	 * Let the user find out that the descriptor is gone.
	 */
	return 1;
}

/*
 * Just call the device strategy routine
 */
int
dead_strategy(struct vnop_strategy_args *ap)
{
	vnode_t vp = buf_vnop_vnode(ap->a_bp);

	if (!vp || !chkvnlock(vp)) {
		if (vp) {
			vnode_lock(vp);
			if (!(vp->v_lflag & VL_DEAD) || vp->v_op != dead_vnodeop_p) {
#if DEVELOPMENT || DEBUG
				panic("%s: vnode %p (v_lflag 0x%x) is NOT in dead state",
				    __func__, vp, vp->v_lflag);
#else
				printf("%s: vnode %p (v_lflag 0x%x) is NOT in dead state",
				    __func__, vp, vp->v_lflag);
#endif
			}
			vnode_unlock(vp);
			printf("%s: returning EIO for vnode v_flags = 0x%x v_numoutput = %d\n",
			    __func__, vp->v_flag, vp->v_numoutput);
		}
		buf_seterror(ap->a_bp, EIO);
		buf_biodone(ap->a_bp);
		return EIO;
	}

	printf("%s: vnode is going to call the original bwrite routine v_lflag 0x%x v_flags = 0x%x v_numoutput = %d\n",
	    __func__, vp->v_lflag, vp->v_flag, vp->v_numoutput);

	return VOCALL(vp->v_op, VOFFSET(vnop_strategy), ap);
}

/*
 * Return an error and complete the IO if the vnode is not changing state.
 */
int
dead_bwrite(struct vnop_bwrite_args *ap)
{
	buf_t bp = ap->a_bp;
	vnode_t vp = buf_vnop_vnode(bp);

	if (!vp || !chkvnlock(vp)) {
		vnode_t buf_vp = buf_vnode(bp);

		if (vp) {
			vnode_lock(vp);
			if (!(vp->v_lflag & VL_DEAD) || vp->v_op != dead_vnodeop_p) {
#if DEVELOPMENT || DEBUG
				panic("%s: vnode %p (v_lflag 0x%x) is NOT in dead state",
				    __func__, vp, vp->v_lflag);
#else
				printf("%s: vnode %p (v_lflag 0x%x) is NOT in dead state",
				    __func__, vp, vp->v_lflag);
#endif
			}
			vnode_unlock(vp);
		}

		buf_seterror(bp, EIO);

		if (buf_vp) {
			/*
			 * buf_biodone is expecting this to be incremented (see buf_bwrite)
			 */
			OSAddAtomic(1, &buf_vp->v_numoutput);
			printf("%s: returning EIO for vnode v_flags = 0x%x v_numoutput = %d\n",
			    __func__, buf_vp->v_flag, buf_vp->v_numoutput);
		}
		buf_biodone(bp);
		return EIO;
	}

	printf("%s: vnode is going to call the original bwrite routine v_lflag 0x%x v_flags = 0x%x v_numoutput = %d\n",
	    __func__, vp->v_lflag, vp->v_flag, vp->v_numoutput);

	return VOCALL(vp->v_op, VOFFSET(vnop_bwrite), ap);
}

/*
 * Wait until the vnode has finished changing state.
 */
int
dead_blockmap(struct vnop_blockmap_args *ap)
{
	if (!chkvnlock(ap->a_vp)) {
		return EIO;
	}
	return VNOP_BLOCKMAP(ap->a_vp, ap->a_foffset, ap->a_size, ap->a_bpn,
	           ap->a_run, ap->a_poff, ap->a_flags, ap->a_context);
}

/*
 * Empty vnode failed operation
 */
/* ARGSUSED */
int
dead_ebadf(__unused void *dummy)
{
	return EBADF;
}

/*
 * Empty vnode bad operation
 */
/* ARGSUSED */
int
dead_badop(__unused void *dummy)
{
	panic("dead_badop called");
	/* NOTREACHED */
	return -1;
}

/*
 * We have to wait during times when the vnode is
 * in a state of change.
 */
int
chkvnlock(vnode_t vp)
{
	vnode_lock(vp);
	if (!(vp->v_lflag & VL_OPSCHANGE)) {
		vnode_unlock(vp);
		return 0;
	}
	while (vp->v_lflag & VL_DEAD) {
		msleep(&vp->v_lflag, &vp->v_lock, PVFS, "chkvnlock", NULL);
	}
	vnode_unlock(vp);
	return 1;
}


/* Blktooff */
int
dead_blktooff(struct vnop_blktooff_args *ap)
{
	if (!chkvnlock(ap->a_vp)) {
		return EIO;
	}

	*ap->a_offset = (off_t)-1;      /* failure */
	return 0;
}
/* Blktooff */
int
dead_offtoblk(struct vnop_offtoblk_args *ap)
{
	if (!chkvnlock(ap->a_vp)) {
		return EIO;
	}

	*ap->a_lblkno = (daddr64_t)-1;  /* failure */
	return 0;
}
