/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)sys_generic.c	8.9 (Berkeley) 2/14/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/ioctl.h>
#include <sys/file_internal.h>
#include <sys/proc_internal.h>
#include <sys/socketvar.h>
#include <sys/uio_internal.h>
#include <sys/kernel.h>
#include <sys/guarded.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>

#include <sys/mount_internal.h>
#include <sys/protosw.h>
#include <sys/ev.h>
#include <sys/user.h>
#include <sys/kdebug.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <machine/smp.h>
#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/ledger.h>
#include <kern/monotonic.h>
#include <kern/task.h>
#include <kern/telemetry.h>
#include <kern/waitq.h>
#include <kern/sched_hygiene.h>
#include <kern/sched_prim.h>
#include <kern/mpsc_queue.h>
#include <kern/debug.h>

#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <sys/pipe.h>

#include <security/audit/audit.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>
/* for wait queue based select */
#include <kern/waitq.h>
#include <sys/vnode_internal.h>
/* for remote time api*/
#include <kern/remote_time.h>
#include <os/log.h>
#include <sys/log_data.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#ifdef CONFIG_KDP_INTERACTIVE_DEBUGGING
#include <mach_debug/mach_debug_types.h>
#endif

#if MONOTONIC
#include <machine/monotonic.h>
#endif /* MONOTONIC */

/* for entitlement check */
#include <IOKit/IOBSD.h>

/* XXX should be in a header file somewhere */
extern kern_return_t IOBSDGetPlatformUUID(__darwin_uuid_t uuid, mach_timespec_t timeoutp);

int do_uiowrite(struct proc *p, struct fileproc *fp, uio_t uio, int flags, user_ssize_t *retval);
__private_extern__ int  dofileread(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte,
    off_t offset, int flags, user_ssize_t *retval);
__private_extern__ int  dofilewrite(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte,
    off_t offset, int flags, user_ssize_t *retval);
static int preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_vnode);

/* needed by guarded_writev, etc. */
int write_internal(struct proc *p, int fd, user_addr_t buf, user_size_t nbyte,
    off_t offset, int flags, guardid_t *puguard, user_ssize_t *retval);
int writev_uio(struct proc *p, int fd, user_addr_t user_iovp, int iovcnt, off_t offset, int flags,
    guardid_t *puguard, user_ssize_t *retval);

#define f_flag fp_glob->fg_flag
#define f_type fp_glob->fg_ops->fo_type
#define f_cred fp_glob->fg_cred
#define f_ops fp_glob->fg_ops

/*
 * Validate if the file can be used for random access (pread, pwrite, etc).
 *
 * Conditions:
 *		proc_fdlock is held
 *
 * Returns:    0                       Success
 *             ESPIPE
 *             ENXIO
 */
static int
valid_for_random_access(struct fileproc *fp)
{
	if (__improbable(fp->f_type != DTYPE_VNODE)) {
		return ESPIPE;
	}

	vnode_t vp = (struct vnode *)fp_get_data(fp);
	if (__improbable(vnode_isfifo(vp))) {
		return ESPIPE;
	}

	if (__improbable(vp->v_flag & VISTTY)) {
		return ENXIO;
	}

	return 0;
}

/*
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *	fp_lookup:EBADF
 *  valid_for_random_access:ESPIPE
 *  valid_for_random_access:ENXIO
 */
static int
preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_pread)
{
	int     error;
	struct fileproc *fp;

	AUDIT_ARG(fd, fd);

	proc_fdlock_spin(p);

	error = fp_lookup(p, fd, &fp, 1);

	if (error) {
		proc_fdunlock(p);
		return error;
	}
	if ((fp->f_flag & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (check_for_pread) {
		if ((error = valid_for_random_access(fp))) {
			goto out;
		}
	}

	*fp_ret = fp;

	proc_fdunlock(p);
	return 0;

out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return error;
}

static int
fp_readv(vfs_context_t ctx, struct fileproc *fp, uio_t uio, int flags,
    user_ssize_t *retval)
{
	int error;
	user_ssize_t count;

	if ((error = uio_calculateresid(uio))) {
		*retval = 0;
		return error;
	}

	count = uio_resid(uio);
	error = fo_read(fp, uio, flags, ctx);

	switch (error) {
	case ERESTART:
	case EINTR:
	case EWOULDBLOCK:
		if (uio_resid(uio) != count) {
			error = 0;
		}
		break;

	default:
		break;
	}

	*retval = count - uio_resid(uio);
	return error;
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	fo_read:???
 */
__private_extern__ int
dofileread(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte, off_t offset, int flags,
    user_ssize_t *retval)
{
	UIO_STACKBUF(uio_buf, 1);
	uio_t uio;
	int spacetype;

	if (nbyte > INT_MAX) {
		*retval = 0;
		return EINVAL;
	}

	spacetype = vfs_context_is64bit(ctx) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	uio = uio_createwithbuffer(1, offset, spacetype, UIO_READ, &uio_buf[0],
	    sizeof(uio_buf));

	if (uio_addiov(uio, bufp, nbyte) != 0) {
		*retval = 0;
		return EINVAL;
	}

	return fp_readv(ctx, fp, uio, flags, retval);
}

static int
readv_internal(struct proc *p, int fd, uio_t uio, int flags,
    user_ssize_t *retval)
{
	struct fileproc *fp = NULL;
	struct vfs_context context;
	int error;

	if ((error = preparefileread(p, &fp, fd, flags & FOF_OFFSET))) {
		*retval = 0;
		return error;
	}

	context = *(vfs_context_current());
	context.vc_ucred = fp->fp_glob->fg_cred;

	error = fp_readv(&context, fp, uio, flags, retval);

	fp_drop(p, fd, fp, 0);
	return error;
}

static int
read_internal(struct proc *p, int fd, user_addr_t buf, user_size_t nbyte,
    off_t offset, int flags, user_ssize_t *retval)
{
	UIO_STACKBUF(uio_buf, 1);
	uio_t uio;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;

	if (nbyte > INT_MAX) {
		*retval = 0;
		return EINVAL;
	}

	uio = uio_createwithbuffer(1, offset, spacetype, UIO_READ,
	    &uio_buf[0], sizeof(uio_buf));

	if (uio_addiov(uio, buf, nbyte) != 0) {
		*retval = 0;
		return EINVAL;
	}

	return readv_internal(p, fd, uio, flags, retval);
}

int
read_nocancel(struct proc *p, struct read_nocancel_args *uap, user_ssize_t *retval)
{
	return read_internal(p, uap->fd, uap->cbuf, uap->nbyte, (off_t)-1, 0,
	           retval);
}

/*
 * Read system call.
 *
 * Returns:	0			Success
 *	preparefileread:EBADF
 *	preparefileread:ESPIPE
 *	preparefileread:ENXIO
 *	preparefileread:EBADF
 *	dofileread:???
 */
int
read(struct proc *p, struct read_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return read_nocancel(p, (struct read_nocancel_args *)uap, retval);
}

int
pread_nocancel(struct proc *p, struct pread_nocancel_args *uap, user_ssize_t *retval)
{
	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pread) | DBG_FUNC_NONE),
	    uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);

	return read_internal(p, uap->fd, uap->buf, uap->nbyte, uap->offset,
	           FOF_OFFSET, retval);
}

/*
 * Pread system call
 *
 * Returns:	0			Success
 *	preparefileread:EBADF
 *	preparefileread:ESPIPE
 *	preparefileread:ENXIO
 *	preparefileread:EBADF
 *	dofileread:???
 */
int
pread(struct proc *p, struct pread_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return pread_nocancel(p, (struct pread_nocancel_args *)uap, retval);
}

/*
 * Vector read.
 *
 * Returns:    0                       Success
 *             EINVAL
 *             ENOMEM
 *     preparefileread:EBADF
 *     preparefileread:ESPIPE
 *     preparefileread:ENXIO
 *     preparefileread:EBADF
 *     copyin:EFAULT
 *     rd_uio:???
 */
static int
readv_uio(struct proc *p, int fd,
    user_addr_t user_iovp, int iovcnt, off_t offset, int flags,
    user_ssize_t *retval)
{
	uio_t uio = NULL;
	int error;
	struct user_iovec *iovp;

	if (iovcnt <= 0 || iovcnt > UIO_MAXIOV) {
		error = EINVAL;
		goto out;
	}

	uio = uio_create(iovcnt, offset,
	    (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	    UIO_READ);

	iovp = uio_iovsaddr(uio);
	if (iovp == NULL) {
		error = ENOMEM;
		goto out;
	}

	error = copyin_user_iovec_array(user_iovp,
	    IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
	    iovcnt, iovp);

	if (error) {
		goto out;
	}

	error = readv_internal(p, fd, uio, flags, retval);

out:
	if (uio != NULL) {
		uio_free(uio);
	}

	return error;
}

int
readv_nocancel(struct proc *p, struct readv_nocancel_args *uap, user_ssize_t *retval)
{
	return readv_uio(p, uap->fd, uap->iovp, uap->iovcnt, 0, 0, retval);
}

/*
 * Scatter read system call.
 */
int
readv(struct proc *p, struct readv_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return readv_nocancel(p, (struct readv_nocancel_args *)uap, retval);
}

int
sys_preadv_nocancel(struct proc *p, struct preadv_nocancel_args *uap, user_ssize_t *retval)
{
	return readv_uio(p, uap->fd, uap->iovp, uap->iovcnt, uap->offset,
	           FOF_OFFSET, retval);
}

/*
 * Preadv system call
 */
int
sys_preadv(struct proc *p, struct preadv_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return sys_preadv_nocancel(p, (struct preadv_nocancel_args *)uap, retval);
}

/*
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *	fp_lookup:EBADF
 *	fp_guard_exception:???
 *  valid_for_random_access:ESPIPE
 *  valid_for_random_access:ENXIO
 */
static int
preparefilewrite(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_pwrite,
    guardid_t *puguard)
{
	int error;
	struct fileproc *fp;

	AUDIT_ARG(fd, fd);

	proc_fdlock_spin(p);

	if (puguard) {
		error = fp_lookup_guarded(p, fd, *puguard, &fp, 1);
		if (error) {
			proc_fdunlock(p);
			return error;
		}

		if ((fp->f_flag & FWRITE) == 0) {
			error = EBADF;
			goto out;
		}
	} else {
		error = fp_lookup(p, fd, &fp, 1);
		if (error) {
			proc_fdunlock(p);
			return error;
		}

		/* Allow EBADF first. */
		if ((fp->f_flag & FWRITE) == 0) {
			error = EBADF;
			goto out;
		}

		if (fp_isguarded(fp, GUARD_WRITE)) {
			error = fp_guard_exception(p, fd, fp, kGUARD_EXC_WRITE);
			goto out;
		}
	}

	if (check_for_pwrite) {
		if ((error = valid_for_random_access(fp))) {
			goto out;
		}
	}

	*fp_ret = fp;

	proc_fdunlock(p);
	return 0;

out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return error;
}

static int
fp_writev(vfs_context_t ctx, struct fileproc *fp, uio_t uio, int flags,
    user_ssize_t *retval)
{
	int error;
	user_ssize_t count;

	if ((error = uio_calculateresid(uio))) {
		*retval = 0;
		return error;
	}

	count = uio_resid(uio);
	error = fo_write(fp, uio, flags, ctx);

	switch (error) {
	case ERESTART:
	case EINTR:
	case EWOULDBLOCK:
		if (uio_resid(uio) != count) {
			error = 0;
		}
		break;

	case EPIPE:
		if (fp->f_type != DTYPE_SOCKET &&
		    (fp->fp_glob->fg_lflags & FG_NOSIGPIPE) == 0) {
			/* XXX Raise the signal on the thread? */
			psignal(vfs_context_proc(ctx), SIGPIPE);
		}
		break;

	default:
		break;
	}

	if ((*retval = count - uio_resid(uio))) {
		os_atomic_or(&fp->fp_glob->fg_flag, FWASWRITTEN, relaxed);
	}

	return error;
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	<fo_write>:EPIPE
 *	<fo_write>:???			[indirect through struct fileops]
 */
__private_extern__ int
dofilewrite(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte, off_t offset, int flags,
    user_ssize_t *retval)
{
	UIO_STACKBUF(uio_buf, 1);
	uio_t uio;
	int spacetype;

	if (nbyte > INT_MAX) {
		*retval = 0;
		return EINVAL;
	}

	spacetype = vfs_context_is64bit(ctx) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	uio = uio_createwithbuffer(1, offset, spacetype, UIO_WRITE, &uio_buf[0],
	    sizeof(uio_buf));

	if (uio_addiov(uio, bufp, nbyte) != 0) {
		*retval = 0;
		return EINVAL;
	}

	return fp_writev(ctx, fp, uio, flags, retval);
}

static int
writev_internal(struct proc *p, int fd, uio_t uio, int flags,
    guardid_t *puguard, user_ssize_t *retval)
{
	struct fileproc *fp = NULL;
	struct vfs_context context;
	int error;

	if ((error = preparefilewrite(p, &fp, fd, flags & FOF_OFFSET, puguard))) {
		*retval = 0;
		return error;
	}

	context = *(vfs_context_current());
	context.vc_ucred = fp->fp_glob->fg_cred;

	error = fp_writev(&context, fp, uio, flags, retval);

	fp_drop(p, fd, fp, 0);
	return error;
}

int
write_internal(struct proc *p, int fd, user_addr_t buf, user_size_t nbyte,
    off_t offset, int flags, guardid_t *puguard, user_ssize_t *retval)
{
	UIO_STACKBUF(uio_buf, 1);
	uio_t uio;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;

	if (nbyte > INT_MAX) {
		*retval = 0;
		return EINVAL;
	}

	uio = uio_createwithbuffer(1, offset, spacetype, UIO_WRITE,
	    &uio_buf[0], sizeof(uio_buf));

	if (uio_addiov(uio, buf, nbyte) != 0) {
		*retval = 0;
		return EINVAL;
	}

	return writev_internal(p, fd, uio, flags, puguard, retval);
}

int
write_nocancel(struct proc *p, struct write_nocancel_args *uap, user_ssize_t *retval)
{
	return write_internal(p, uap->fd, uap->cbuf, uap->nbyte, (off_t)-1, 0,
	           NULL, retval);
}

/*
 * Write system call
 *
 * Returns:	0			Success
 *		EBADF
 *	fp_lookup:EBADF
 *	dofilewrite:???
 */
int
write(struct proc *p, struct write_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return write_nocancel(p, (struct write_nocancel_args *)uap, retval);
}

int
pwrite_nocancel(struct proc *p, struct pwrite_nocancel_args *uap, user_ssize_t *retval)
{
	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pwrite) | DBG_FUNC_NONE),
	    uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);

	/* XXX: Should be < 0 instead? (See man page + pwritev) */
	if (uap->offset == (off_t)-1) {
		return EINVAL;
	}

	return write_internal(p, uap->fd, uap->buf, uap->nbyte, uap->offset,
	           FOF_OFFSET, NULL, retval);
}

/*
 * pwrite system call
 *
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *		EINVAL
 *	fp_lookup:EBADF
 *	dofilewrite:???
 */
int
pwrite(struct proc *p, struct pwrite_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return pwrite_nocancel(p, (struct pwrite_nocancel_args *)uap, retval);
}

int
writev_uio(struct proc *p, int fd,
    user_addr_t user_iovp, int iovcnt, off_t offset, int flags,
    guardid_t *puguard, user_ssize_t *retval)
{
	uio_t uio = NULL;
	int error;
	struct user_iovec *iovp;

	if (iovcnt <= 0 || iovcnt > UIO_MAXIOV || offset < 0) {
		error = EINVAL;
		goto out;
	}

	uio = uio_create(iovcnt, offset,
	    (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	    UIO_WRITE);

	iovp = uio_iovsaddr(uio);
	if (iovp == NULL) {
		error = ENOMEM;
		goto out;
	}

	error = copyin_user_iovec_array(user_iovp,
	    IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
	    iovcnt, iovp);

	if (error) {
		goto out;
	}

	error = writev_internal(p, fd, uio, flags, puguard, retval);

out:
	if (uio != NULL) {
		uio_free(uio);
	}

	return error;
}

int
writev_nocancel(struct proc *p, struct writev_nocancel_args *uap, user_ssize_t *retval)
{
	return writev_uio(p, uap->fd, uap->iovp, uap->iovcnt, 0, 0, NULL, retval);
}

/*
 * Gather write system call
 */
int
writev(struct proc *p, struct writev_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return writev_nocancel(p, (struct writev_nocancel_args *)uap, retval);
}

int
sys_pwritev_nocancel(struct proc *p, struct pwritev_nocancel_args *uap, user_ssize_t *retval)
{
	return writev_uio(p, uap->fd, uap->iovp, uap->iovcnt, uap->offset,
	           FOF_OFFSET, NULL, retval);
}

/*
 * Pwritev system call
 */
int
sys_pwritev(struct proc *p, struct pwritev_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return sys_pwritev_nocancel(p, (struct pwritev_nocancel_args *)uap, retval);
}

/*
 * Ioctl system call
 *
 * Returns:	0			Success
 *		EBADF
 *		ENOTTY
 *		ENOMEM
 *		ESRCH
 *	copyin:EFAULT
 *	copyoutEFAULT
 *	fp_lookup:EBADF			Bad file descriptor
 *	fo_ioctl:???
 */
int
ioctl(struct proc *p, struct ioctl_args *uap, __unused int32_t *retval)
{
	struct fileproc *fp = NULL;
	int error = 0;
	u_int size = 0;
	caddr_t datap = NULL, memp = NULL;
	boolean_t is64bit = FALSE;
	int tmp = 0;
#define STK_PARAMS      128
	char stkbuf[STK_PARAMS] = {};
	int fd = uap->fd;
	u_long com = uap->com;
	struct vfs_context context = *vfs_context_current();

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(addr, uap->data);

	is64bit = proc_is64bit(p);
#if CONFIG_AUDIT
	if (is64bit) {
		AUDIT_ARG(value64, com);
	} else {
		AUDIT_ARG(cmd, CAST_DOWN_EXPLICIT(int, com));
	}
#endif /* CONFIG_AUDIT */

	/*
	 * Interpret high order word to find amount of data to be
	 * copied to/from the user's address space.
	 */
	size = IOCPARM_LEN(com);
	if (size > IOCPARM_MAX) {
		return ENOTTY;
	}
	if (size > sizeof(stkbuf)) {
		memp = (caddr_t)kalloc_data(size, Z_WAITOK);
		if (memp == 0) {
			return ENOMEM;
		}
		datap = memp;
	} else {
		datap = &stkbuf[0];
	}
	if (com & IOC_IN) {
		if (size) {
			error = copyin(uap->data, datap, size);
			if (error) {
				goto out_nofp;
			}
		} else {
			/* XXX - IOC_IN and no size?  we should proably return an error here!! */
			if (is64bit) {
				*(user_addr_t *)datap = uap->data;
			} else {
				*(uint32_t *)datap = (uint32_t)uap->data;
			}
		}
	} else if ((com & IOC_OUT) && size) {
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(datap, size);
	} else if (com & IOC_VOID) {
		/* XXX - this is odd since IOC_VOID means no parameters */
		if (is64bit) {
			*(user_addr_t *)datap = uap->data;
		} else {
			*(uint32_t *)datap = (uint32_t)uap->data;
		}
	}

	proc_fdlock(p);
	error = fp_lookup(p, fd, &fp, 1);
	if (error) {
		proc_fdunlock(p);
		goto out_nofp;
	}

	AUDIT_ARG(file, p, fp);

	if ((fp->f_flag & (FREAD | FWRITE)) == 0) {
		error = EBADF;
		goto out;
	}

	context.vc_ucred = fp->fp_glob->fg_cred;

#if CONFIG_MACF
	error = mac_file_check_ioctl(context.vc_ucred, fp->fp_glob, com);
	if (error) {
		goto out;
	}
#endif

	switch (com) {
	case FIONCLEX:
		fp->fp_flags &= ~FP_CLOEXEC;
		break;

	case FIOCLEX:
		fp->fp_flags |= FP_CLOEXEC;
		break;

	case FIONBIO:
		// FIXME (rdar://54898652)
		//
		// this code is broken if fnctl(F_SETFL), ioctl() are
		// called concurrently for the same fileglob.
		if ((tmp = *(int *)datap)) {
			os_atomic_or(&fp->f_flag, FNONBLOCK, relaxed);
		} else {
			os_atomic_andnot(&fp->f_flag, FNONBLOCK, relaxed);
		}
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, &context);
		break;

	case FIOASYNC:
		// FIXME (rdar://54898652)
		//
		// this code is broken if fnctl(F_SETFL), ioctl() are
		// called concurrently for the same fileglob.
		if ((tmp = *(int *)datap)) {
			os_atomic_or(&fp->f_flag, FASYNC, relaxed);
		} else {
			os_atomic_andnot(&fp->f_flag, FASYNC, relaxed);
		}
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, &context);
		break;

	case FIOSETOWN:
		tmp = *(int *)datap;
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp_get_data(fp))->so_pgid = tmp;
			break;
		}
		if (fp->f_type == DTYPE_PIPE) {
			error = fo_ioctl(fp, TIOCSPGRP, (caddr_t)&tmp, &context);
			break;
		}
		if (tmp <= 0) {
			tmp = -tmp;
		} else {
			struct proc *p1 = proc_find(tmp);
			if (p1 == 0) {
				error = ESRCH;
				break;
			}
			tmp = p1->p_pgrpid;
			proc_rele(p1);
		}
		error = fo_ioctl(fp, TIOCSPGRP, (caddr_t)&tmp, &context);
		break;

	case FIOGETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			*(int *)datap = ((struct socket *)fp_get_data(fp))->so_pgid;
			break;
		}
		error = fo_ioctl(fp, TIOCGPGRP, datap, &context);
		*(int *)datap = -*(int *)datap;
		break;

	default:
		error = fo_ioctl(fp, com, datap, &context);
		/*
		 * Copy any data to user, size was
		 * already set and checked above.
		 */
		if (error == 0 && (com & IOC_OUT) && size) {
			error = copyout(datap, uap->data, (u_int)size);
		}
		break;
	}
out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

out_nofp:
	if (memp) {
		kfree_data(memp, size);
	}
	return error;
}

int     selwait;
#define SEL_FIRSTPASS 1
#define SEL_SECONDPASS 2
static int selprocess(struct proc *p, int error, int sel_pass);
static int selscan(struct proc *p, struct _select * sel, struct _select_data * seldata,
    int nfd, int32_t *retval, int sel_pass, struct select_set *selset);
static int selcount(struct proc *p, u_int32_t *ibits, int nfd, int *count);
static int seldrop_locked(struct proc *p, u_int32_t *ibits, int nfd, int lim, int *need_wakeup);
static int seldrop(struct proc *p, u_int32_t *ibits, int nfd, int lim);
static int select_internal(struct proc *p, struct select_nocancel_args *uap, uint64_t timeout, int32_t *retval);

/*
 * This is used for the special device nodes that do not implement
 * a proper kevent filter (see filt_specattach).
 *
 * In order to enable kevents on those, the spec_filtops will pretend
 * to call select, and try to sniff the selrecord(), if it observes one,
 * the knote is attached, which pairs with selwakeup() or selthreadclear().
 *
 * The last issue remaining, is that we need to serialize filt_specdetach()
 * with this, but it really can't know the "selinfo" or any locking domain.
 * To make up for this, We protect knote list operations with a global lock,
 * which give us a safe shared locking domain.
 *
 * Note: It is a little distasteful, but we really have very few of those.
 *       The big problem here is that sharing a lock domain without
 *       any kind of shared knowledge is a little complicated.
 *
 *       1. filters can really implement their own kqueue integration
 *          to side step this,
 *
 *       2. There's an opportunity to pick a private lock in selspec_attach()
 *          because both the selinfo and the knote are locked at that time.
 *          The cleanup story is however a little complicated.
 */
static LCK_GRP_DECLARE(selspec_grp, "spec_filtops");
static LCK_SPIN_DECLARE(selspec_lock, &selspec_grp);

/*
 * The "primitive" lock is held.
 * The knote lock is held.
 */
void
selspec_attach(struct knote *kn, struct selinfo *si)
{
	struct selinfo *cur = knote_kn_hook_get_raw(kn);

	if (cur == NULL) {
		si->si_flags |= SI_SELSPEC;
		lck_spin_lock(&selspec_lock);
		knote_kn_hook_set_raw(kn, (void *) si);
		KNOTE_ATTACH(&si->si_note, kn);
		lck_spin_unlock(&selspec_lock);
	} else {
		/*
		 * selspec_attach() can be called from e.g. filt_spectouch()
		 * which might be called before any event was dequeued.
		 *
		 * It is hence not impossible for the knote already be hooked.
		 *
		 * Note that selwakeup_internal() could possibly
		 * already have cleared this pointer. This is a race
		 * that filt_specprocess will debounce.
		 */
		assert(si->si_flags & SI_SELSPEC);
		assert(cur == si);
	}
}

/*
 * The "primitive" lock is _not_ held.
 *
 * knote "lock" is held
 */
void
selspec_detach(struct knote *kn)
{
	lck_spin_lock(&selspec_lock);

	if (!KNOTE_IS_AUTODETACHED(kn)) {
		struct selinfo *sip = knote_kn_hook_get_raw(kn);
		if (sip) {
			KNOTE_DETACH(&sip->si_note, kn);
		}
	}

	knote_kn_hook_set_raw(kn, NULL);

	lck_spin_unlock(&selspec_lock);
}

/*
 * Select system call.
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EAGAIN			Nonconformant error if allocation fails
 */
int
select(struct proc *p, struct select_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return select_nocancel(p, (struct select_nocancel_args *)uap, retval);
}

int
select_nocancel(struct proc *p, struct select_nocancel_args *uap, int32_t *retval)
{
	uint64_t timeout = 0;

	if (uap->tv) {
		int err;
		struct timeval atv;
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval atv64;
			err = copyin(uap->tv, (caddr_t)&atv64, sizeof(atv64));
			/* Loses resolution - assume timeout < 68 years */
			atv.tv_sec = (__darwin_time_t)atv64.tv_sec;
			atv.tv_usec = atv64.tv_usec;
		} else {
			struct user32_timeval atv32;
			err = copyin(uap->tv, (caddr_t)&atv32, sizeof(atv32));
			atv.tv_sec = atv32.tv_sec;
			atv.tv_usec = atv32.tv_usec;
		}
		if (err) {
			return err;
		}

		if (itimerfix(&atv)) {
			err = EINVAL;
			return err;
		}

		clock_absolutetime_interval_to_deadline(tvtoabstime(&atv), &timeout);
	}

	return select_internal(p, uap, timeout, retval);
}

int
pselect(struct proc *p, struct pselect_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return pselect_nocancel(p, (struct pselect_nocancel_args *)uap, retval);
}

int
pselect_nocancel(struct proc *p, struct pselect_nocancel_args *uap, int32_t *retval)
{
	int err;
	struct uthread *ut;
	uint64_t timeout = 0;

	if (uap->ts) {
		struct timespec ts;

		if (IS_64BIT_PROCESS(p)) {
			struct user64_timespec ts64;
			err = copyin(uap->ts, (caddr_t)&ts64, sizeof(ts64));
			ts.tv_sec = (__darwin_time_t)ts64.tv_sec;
			ts.tv_nsec = (long)ts64.tv_nsec;
		} else {
			struct user32_timespec ts32;
			err = copyin(uap->ts, (caddr_t)&ts32, sizeof(ts32));
			ts.tv_sec = ts32.tv_sec;
			ts.tv_nsec = ts32.tv_nsec;
		}
		if (err) {
			return err;
		}

		if (!timespec_is_valid(&ts)) {
			return EINVAL;
		}
		clock_absolutetime_interval_to_deadline(tstoabstime(&ts), &timeout);
	}

	ut = current_uthread();

	if (uap->mask != USER_ADDR_NULL) {
		/* save current mask, then copyin and set new mask */
		sigset_t newset;
		err = copyin(uap->mask, &newset, sizeof(sigset_t));
		if (err) {
			return err;
		}
		ut->uu_oldmask = ut->uu_sigmask;
		ut->uu_flag |= UT_SAS_OLDMASK;
		ut->uu_sigmask = (newset & ~sigcantmask);
	}

	err = select_internal(p, (struct select_nocancel_args *)uap, timeout, retval);

	if (err != EINTR && ut->uu_flag & UT_SAS_OLDMASK) {
		/*
		 * Restore old mask (direct return case). NOTE: EINTR can also be returned
		 * if the thread is cancelled. In that case, we don't reset the signal
		 * mask to its original value (which usually happens in the signal
		 * delivery path). This behavior is permitted by POSIX.
		 */
		ut->uu_sigmask = ut->uu_oldmask;
		ut->uu_oldmask = 0;
		ut->uu_flag &= ~UT_SAS_OLDMASK;
	}

	return err;
}

void
select_cleanup_uthread(struct _select *sel)
{
	kfree_data(sel->ibits, 2 * sel->nbytes);
	sel->ibits = sel->obits = NULL;
	sel->nbytes = 0;
}

static int
select_grow_uthread_cache(struct _select *sel, uint32_t nbytes)
{
	uint32_t *buf;

	buf = kalloc_data(2 * nbytes, Z_WAITOK | Z_ZERO);
	if (buf) {
		select_cleanup_uthread(sel);
		sel->ibits = buf;
		sel->obits = buf + nbytes / sizeof(uint32_t);
		sel->nbytes = nbytes;
		return true;
	}
	return false;
}

static void
select_bzero_uthread_cache(struct _select *sel)
{
	bzero(sel->ibits, sel->nbytes * 2);
}

/*
 * Generic implementation of {,p}select. Care: we type-pun uap across the two
 * syscalls, which differ slightly. The first 4 arguments (nfds and the fd sets)
 * are identical. The 5th (timeout) argument points to different types, so we
 * unpack in the syscall-specific code, but the generic code still does a null
 * check on this argument to determine if a timeout was specified.
 */
static int
select_internal(struct proc *p, struct select_nocancel_args *uap, uint64_t timeout, int32_t *retval)
{
	struct uthread *uth = current_uthread();
	struct _select *sel = &uth->uu_select;
	struct _select_data *seldata = &uth->uu_save.uus_select_data;
	int error = 0;
	u_int ni, nw;

	*retval = 0;

	seldata->abstime = timeout;
	seldata->args = uap;
	seldata->retval = retval;
	seldata->count = 0;

	if (uap->nd < 0) {
		return EINVAL;
	}

	if (uap->nd > p->p_fd.fd_nfiles) {
		uap->nd = p->p_fd.fd_nfiles; /* forgiving; slightly wrong */
	}
	nw = howmany(uap->nd, NFDBITS);
	ni = nw * sizeof(fd_mask);

	/*
	 * if the previously allocated space for the bits is smaller than
	 * what is requested or no space has yet been allocated for this
	 * thread, allocate enough space now.
	 *
	 * Note: If this process fails, select() will return EAGAIN; this
	 * is the same thing pool() returns in a no-memory situation, but
	 * it is not a POSIX compliant error code for select().
	 */
	if (sel->nbytes >= (3 * ni)) {
		select_bzero_uthread_cache(sel);
	} else if (!select_grow_uthread_cache(sel, 3 * ni)) {
		return EAGAIN;
	}

	/*
	 * get the bits from the user address space
	 */
#define getbits(name, x) \
	(uap->name ? copyin(uap->name, &sel->ibits[(x) * nw], ni) : 0)

	if ((error = getbits(in, 0))) {
		return error;
	}
	if ((error = getbits(ou, 1))) {
		return error;
	}
	if ((error = getbits(ex, 2))) {
		return error;
	}
#undef  getbits

	if ((error = selcount(p, sel->ibits, uap->nd, &seldata->count))) {
		return error;
	}

	if (uth->uu_selset == NULL) {
		uth->uu_selset = select_set_alloc();
	}
	return selprocess(p, 0, SEL_FIRSTPASS);
}

static int
selcontinue(int error)
{
	return selprocess(current_proc(), error, SEL_SECONDPASS);
}


/*
 * selprocess
 *
 * Parameters:	error			The error code from our caller
 *		sel_pass		The pass we are on
 */
int
selprocess(struct proc *p, int error, int sel_pass)
{
	struct uthread *uth = current_uthread();
	struct _select *sel = &uth->uu_select;
	struct _select_data *seldata = &uth->uu_save.uus_select_data;
	struct select_nocancel_args *uap = seldata->args;
	int *retval = seldata->retval;

	int unwind = 1;
	int prepost = 0;
	int somewakeup = 0;
	int doretry = 0;
	wait_result_t wait_result;

	if ((error != 0) && (sel_pass == SEL_FIRSTPASS)) {
		unwind = 0;
	}
	if (seldata->count == 0) {
		unwind = 0;
	}
retry:
	if (error != 0) {
		goto done;
	}

	OSBitOrAtomic(P_SELECT, &p->p_flag);

	/* skip scans if the select is just for timeouts */
	if (seldata->count) {
		error = selscan(p, sel, seldata, uap->nd, retval, sel_pass,
		    uth->uu_selset);
		if (error || *retval) {
			goto done;
		}
		if (prepost || somewakeup) {
			/*
			 * if the select of log, then we can wakeup and
			 * discover some one else already read the data;
			 * go to select again if time permits
			 */
			prepost = 0;
			somewakeup = 0;
			doretry = 1;
		}
	}

	if (uap->tv) {
		uint64_t        now;

		clock_get_uptime(&now);
		if (now >= seldata->abstime) {
			goto done;
		}
	}

	if (doretry) {
		/* cleanup obits and try again */
		doretry = 0;
		sel_pass = SEL_FIRSTPASS;
		goto retry;
	}

	/*
	 * To effect a poll, the timeout argument should be
	 * non-nil, pointing to a zero-valued timeval structure.
	 */
	if (uap->tv && seldata->abstime == 0) {
		goto done;
	}

	/* No spurious wakeups due to colls,no need to check for them */
	if ((sel_pass == SEL_SECONDPASS) || ((p->p_flag & P_SELECT) == 0)) {
		sel_pass = SEL_FIRSTPASS;
		goto retry;
	}

	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);

	/* if the select is just for timeout skip check */
	if (seldata->count && (sel_pass == SEL_SECONDPASS)) {
		panic("selprocess: 2nd pass assertwaiting");
	}

	wait_result = waitq_assert_wait64_leeway(uth->uu_selset,
	    NO_EVENT64, THREAD_ABORTSAFE,
	    TIMEOUT_URGENCY_USER_NORMAL,
	    seldata->abstime,
	    TIMEOUT_NO_LEEWAY);
	if (wait_result != THREAD_AWAKENED) {
		/* there are no preposted events */
		error = tsleep1(NULL, PSOCK | PCATCH,
		    "select", 0, selcontinue);
	} else {
		prepost = 1;
		error = 0;
	}

	if (error == 0) {
		sel_pass = SEL_SECONDPASS;
		if (!prepost) {
			somewakeup = 1;
		}
		goto retry;
	}
done:
	if (unwind) {
		seldrop(p, sel->ibits, uap->nd, seldata->count);
		select_set_reset(uth->uu_selset);
	}
	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);
	/* select is not restarted after signals... */
	if (error == ERESTART) {
		error = EINTR;
	}
	if (error == EWOULDBLOCK) {
		error = 0;
	}

	if (error == 0) {
		uint32_t nw = howmany(uap->nd, NFDBITS);
		uint32_t ni = nw * sizeof(fd_mask);

#define putbits(name, x) \
	(uap->name ? copyout(&sel->obits[(x) * nw], uap->name, ni) : 0)
		int e0 = putbits(in, 0);
		int e1 = putbits(ou, 1);
		int e2 = putbits(ex, 2);

		error = e0 ?: e1 ?: e2;
#undef putbits
	}

	if (error != EINTR && sel_pass == SEL_SECONDPASS && uth->uu_flag & UT_SAS_OLDMASK) {
		/* restore signal mask - continuation case */
		uth->uu_sigmask = uth->uu_oldmask;
		uth->uu_oldmask = 0;
		uth->uu_flag &= ~UT_SAS_OLDMASK;
	}

	return error;
}


/**
 * remove the fileproc's underlying waitq from the supplied waitq set;
 * clear FP_INSELECT when appropriate
 *
 * Parameters:
 *		fp	File proc that is potentially currently in select
 *		selset	Waitq set to which the fileproc may belong
 *			(usually this is the thread's private waitq set)
 * Conditions:
 *		proc_fdlock is held
 */
static void
selunlinkfp(struct fileproc *fp, struct select_set *selset)
{
	if (fp->fp_flags & FP_INSELECT) {
		if (fp->fp_guard_attrs) {
			if (fp->fp_guard->fpg_wset == selset) {
				fp->fp_guard->fpg_wset = NULL;
				fp->fp_flags &= ~FP_INSELECT;
			}
		} else {
			if (fp->fp_wset == selset) {
				fp->fp_wset = NULL;
				fp->fp_flags &= ~FP_INSELECT;
			}
		}
	}
}

/**
 * connect a fileproc to the given selset, potentially bridging to a waitq
 * pointed to indirectly by wq_data
 *
 * Parameters:
 *		fp	File proc potentially currently in select
 *		selset	Waitq set to which the fileproc should now belong
 *			(usually this is the thread's private waitq set)
 *
 * Conditions:
 *		proc_fdlock is held
 */
static void
sellinkfp(struct fileproc *fp, struct select_set *selset, waitq_link_t *linkp)
{
	if ((fp->fp_flags & FP_INSELECT) == 0) {
		if (fp->fp_guard_attrs) {
			fp->fp_guard->fpg_wset = selset;
		} else {
			fp->fp_wset = selset;
		}
		fp->fp_flags |= FP_INSELECT;
	} else {
		fp->fp_flags |= FP_SELCONFLICT;
		if (linkp->wqlh == NULL) {
			*linkp = waitq_link_alloc(WQT_SELECT_SET);
		}
		select_set_link(&select_conflict_queue, selset, linkp);
	}
}


/*
 * selscan
 *
 * Parameters:	p			Process performing the select
 *		sel			The per-thread select context structure
 *		nfd			The number of file descriptors to scan
 *		retval			The per thread system call return area
 *		sel_pass		Which pass this is; allowed values are
 *						SEL_FIRSTPASS and SEL_SECONDPASS
 *		selset			The per thread wait queue set
 *
 * Returns:	0			Success
 *		EIO			Invalid p->p_fd field XXX Obsolete?
 *		EBADF			One of the files in the bit vector is
 *						invalid.
 */
static int
selscan(struct proc *p, struct _select *sel, struct _select_data * seldata,
    int nfd, int32_t *retval, int sel_pass, struct select_set *selset)
{
	int msk, i, j, fd;
	u_int32_t bits;
	struct fileproc *fp;
	int n = 0;              /* count of bits */
	int nc = 0;             /* bit vector offset (nc'th bit) */
	static int flag[3] = { FREAD, FWRITE, 0 };
	u_int32_t *iptr, *optr;
	u_int nw;
	u_int32_t *ibits, *obits;
	int count;
	struct vfs_context context = {
		.vc_thread = current_thread(),
	};
	waitq_link_t link = WQL_NULL;
	void *s_data;

	ibits = sel->ibits;
	obits = sel->obits;

	nw = howmany(nfd, NFDBITS);

	count = seldata->count;

	nc = 0;
	if (!count) {
		*retval = 0;
		return 0;
	}

	if (sel_pass == SEL_FIRSTPASS) {
		/*
		 * Make sure the waitq-set is all clean:
		 *
		 * select loops until it finds at least one event, however it
		 * doesn't mean that the event that woke up select is still
		 * fired by the time the second pass runs, and then
		 * select_internal will loop back to a first pass.
		 */
		select_set_reset(selset);
		s_data = &link;
	} else {
		s_data = NULL;
	}

	proc_fdlock(p);
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		optr = (u_int32_t *)&obits[msk * nw];

		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i / NFDBITS];

			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1U << j);

				fp = fp_get_noref_locked(p, fd);
				if (fp == NULL) {
					/*
					 * If we abort because of a bad
					 * fd, let the caller unwind...
					 */
					proc_fdunlock(p);
					return EBADF;
				}
				if (sel_pass == SEL_SECONDPASS) {
					selunlinkfp(fp, selset);
				} else if (link.wqlh == NULL) {
					link = waitq_link_alloc(WQT_SELECT_SET);
				}

				context.vc_ucred = fp->f_cred;

				/* The select; set the bit, if true */
				if (fo_select(fp, flag[msk], s_data, &context)) {
					optr[fd / NFDBITS] |= (1U << (fd % NFDBITS));
					n++;
				}
				if (sel_pass == SEL_FIRSTPASS) {
					/*
					 * Hook up the thread's waitq set either to
					 * the fileproc structure, or to the global
					 * conflict queue: but only on the first
					 * select pass.
					 */
					sellinkfp(fp, selset, &link);
				}
				nc++;
			}
		}
	}
	proc_fdunlock(p);

	if (link.wqlh) {
		waitq_link_free(WQT_SELECT_SET, link);
	}

	*retval = n;
	return 0;
}

static int poll_callback(struct kevent_qos_s *, kevent_ctx_t);

int
poll(struct proc *p, struct poll_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return poll_nocancel(p, (struct poll_nocancel_args *)uap, retval);
}


int
poll_nocancel(struct proc *p, struct poll_nocancel_args *uap, int32_t *retval)
{
	struct pollfd *fds = NULL;
	struct kqueue *kq = NULL;
	int error = 0;
	u_int nfds = uap->nfds;
	u_int rfds = 0;
	rlim_t nofile = proc_limitgetcur(p, RLIMIT_NOFILE);
	size_t ni = nfds * sizeof(struct pollfd);

	/*
	 * This is kinda bogus.  We have fd limits, but that is not
	 * really related to the size of the pollfd array.  Make sure
	 * we let the process use at least FD_SETSIZE entries and at
	 * least enough for the current limits.  We want to be reasonably
	 * safe, but not overly restrictive.
	 */
	if (nfds > OPEN_MAX ||
	    (nfds > nofile && (proc_suser(p) || nfds > FD_SETSIZE))) {
		return EINVAL;
	}

	kq = kqueue_alloc(p);
	if (kq == NULL) {
		return EAGAIN;
	}

	if (nfds) {
		fds = (struct pollfd *)kalloc_data(ni, Z_WAITOK);
		if (NULL == fds) {
			error = EAGAIN;
			goto out;
		}

		error = copyin(uap->fds, fds, nfds * sizeof(struct pollfd));
		if (error) {
			goto out;
		}
	}

	/* JMM - all this P_SELECT stuff is bogus */
	OSBitOrAtomic(P_SELECT, &p->p_flag);
	for (u_int i = 0; i < nfds; i++) {
		short events = fds[i].events;
		__assert_only int rc;

		/* per spec, ignore fd values below zero */
		if (fds[i].fd < 0) {
			fds[i].revents = 0;
			continue;
		}

		/* convert the poll event into a kqueue kevent */
		struct kevent_qos_s kev = {
			.ident = fds[i].fd,
			.flags = EV_ADD | EV_ONESHOT | EV_POLL,
			.udata = i, /* Index into pollfd array */
		};

		/* Handle input events */
		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND | POLLHUP)) {
			kev.filter = EVFILT_READ;
			if (events & (POLLPRI | POLLRDBAND)) {
				kev.flags |= EV_OOBAND;
			}
			rc = kevent_register(kq, &kev, NULL);
			assert((rc & FILTER_REGISTER_WAIT) == 0);
		}

		/* Handle output events */
		if ((kev.flags & EV_ERROR) == 0 &&
		    (events & (POLLOUT | POLLWRNORM | POLLWRBAND))) {
			kev.filter = EVFILT_WRITE;
			rc = kevent_register(kq, &kev, NULL);
			assert((rc & FILTER_REGISTER_WAIT) == 0);
		}

		/* Handle BSD extension vnode events */
		if ((kev.flags & EV_ERROR) == 0 &&
		    (events & (POLLEXTEND | POLLATTRIB | POLLNLINK | POLLWRITE))) {
			kev.filter = EVFILT_VNODE;
			kev.fflags = 0;
			if (events & POLLEXTEND) {
				kev.fflags |= NOTE_EXTEND;
			}
			if (events & POLLATTRIB) {
				kev.fflags |= NOTE_ATTRIB;
			}
			if (events & POLLNLINK) {
				kev.fflags |= NOTE_LINK;
			}
			if (events & POLLWRITE) {
				kev.fflags |= NOTE_WRITE;
			}
			rc = kevent_register(kq, &kev, NULL);
			assert((rc & FILTER_REGISTER_WAIT) == 0);
		}

		if (kev.flags & EV_ERROR) {
			fds[i].revents = POLLNVAL;
			rfds++;
		} else {
			fds[i].revents = 0;
		}
	}

	/*
	 * Did we have any trouble registering?
	 * If user space passed 0 FDs, then respect any timeout value passed.
	 * This is an extremely inefficient sleep. If user space passed one or
	 * more FDs, and we had trouble registering _all_ of them, then bail
	 * out. If a subset of the provided FDs failed to register, then we
	 * will still call the kqueue_scan function.
	 */
	if (nfds && (rfds == nfds)) {
		goto done;
	}

	/* scan for, and possibly wait for, the kevents to trigger */
	kevent_ctx_t kectx = kevent_get_context(current_thread());
	*kectx = (struct kevent_ctx_s){
		.kec_process_noutputs = rfds,
		.kec_process_flags    = KEVENT_FLAG_POLL,
		.kec_deadline         = 0, /* wait forever */
		.kec_poll_fds         = fds,
	};

	/*
	 * If any events have trouble registering, an event has fired and we
	 * shouldn't wait for events in kqueue_scan.
	 */
	if (rfds) {
		kectx->kec_process_flags |= KEVENT_FLAG_IMMEDIATE;
	} else if (uap->timeout != -1) {
		clock_interval_to_deadline(uap->timeout, NSEC_PER_MSEC,
		    &kectx->kec_deadline);
	}

	error = kqueue_scan(kq, kectx->kec_process_flags, kectx, poll_callback);
	rfds = kectx->kec_process_noutputs;

done:
	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);
	/* poll is not restarted after signals... */
	if (error == ERESTART) {
		error = EINTR;
	}
	if (error == 0) {
		error = copyout(fds, uap->fds, nfds * sizeof(struct pollfd));
		*retval = rfds;
	}

out:
	kfree_data(fds, ni);

	kqueue_dealloc(kq);
	return error;
}

static int
poll_callback(struct kevent_qos_s *kevp, kevent_ctx_t kectx)
{
	assert(kectx->kec_process_flags & KEVENT_FLAG_POLL);
	struct pollfd *fds = &kectx->kec_poll_fds[kevp->udata];

	short prev_revents = fds->revents;
	short mask = 0;

	/* convert the results back into revents */
	if (kevp->flags & EV_EOF) {
		fds->revents |= POLLHUP;
	}
	if (kevp->flags & EV_ERROR) {
		fds->revents |= POLLERR;
	}

	switch (kevp->filter) {
	case EVFILT_READ:
		if (fds->revents & POLLHUP) {
			mask = (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND);
		} else {
			mask = (POLLIN | POLLRDNORM);
			if (kevp->flags & EV_OOBAND) {
				mask |= (POLLPRI | POLLRDBAND);
			}
		}
		fds->revents |= (fds->events & mask);
		break;

	case EVFILT_WRITE:
		if (!(fds->revents & POLLHUP)) {
			fds->revents |= (fds->events & (POLLOUT | POLLWRNORM | POLLWRBAND));
		}
		break;

	case EVFILT_VNODE:
		if (kevp->fflags & NOTE_EXTEND) {
			fds->revents |= (fds->events & POLLEXTEND);
		}
		if (kevp->fflags & NOTE_ATTRIB) {
			fds->revents |= (fds->events & POLLATTRIB);
		}
		if (kevp->fflags & NOTE_LINK) {
			fds->revents |= (fds->events & POLLNLINK);
		}
		if (kevp->fflags & NOTE_WRITE) {
			fds->revents |= (fds->events & POLLWRITE);
		}
		break;
	}

	if (fds->revents != 0 && prev_revents == 0) {
		kectx->kec_process_noutputs++;
	}

	return 0;
}

int
seltrue(__unused dev_t dev, __unused int flag, __unused struct proc *p)
{
	return 1;
}

/*
 * selcount
 *
 * Count the number of bits set in the input bit vector, and establish an
 * outstanding fp->fp_iocount for each of the descriptors which will be in
 * use in the select operation.
 *
 * Parameters:	p			The process doing the select
 *		ibits			The input bit vector
 *		nfd			The number of fd's in the vector
 *		countp			Pointer to where to store the bit count
 *
 * Returns:	0			Success
 *		EIO			Bad per process open file table
 *		EBADF			One of the bits in the input bit vector
 *						references an invalid fd
 *
 * Implicit:	*countp (modified)	Count of fd's
 *
 * Notes:	This function is the first pass under the proc_fdlock() that
 *		permits us to recognize invalid descriptors in the bit vector;
 *		the may, however, not remain valid through the drop and
 *		later reacquisition of the proc_fdlock().
 */
static int
selcount(struct proc *p, u_int32_t *ibits, int nfd, int *countp)
{
	int msk, i, j, fd;
	u_int32_t bits;
	struct fileproc *fp;
	int n = 0;
	u_int32_t *iptr;
	u_int nw;
	int error = 0;
	int need_wakeup = 0;

	nw = howmany(nfd, NFDBITS);

	proc_fdlock(p);
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i / NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1U << j);

				fp = fp_get_noref_locked(p, fd);
				if (fp == NULL) {
					*countp = 0;
					error = EBADF;
					goto bad;
				}
				os_ref_retain_locked(&fp->fp_iocount);
				n++;
			}
		}
	}
	proc_fdunlock(p);

	*countp = n;
	return 0;

bad:
	if (n == 0) {
		goto out;
	}
	/* Ignore error return; it's already EBADF */
	(void)seldrop_locked(p, ibits, nfd, n, &need_wakeup);

out:
	proc_fdunlock(p);
	if (need_wakeup) {
		wakeup(&p->p_fd.fd_fpdrainwait);
	}
	return error;
}


/*
 * seldrop_locked
 *
 * Drop outstanding wait queue references set up during selscan(); drop the
 * outstanding per fileproc fp_iocount picked up during the selcount().
 *
 * Parameters:	p			Process performing the select
 *		ibits			Input bit bector of fd's
 *		nfd			Number of fd's
 *		lim			Limit to number of vector entries to
 *						consider, or -1 for "all"
 *		inselect		True if
 *		need_wakeup		Pointer to flag to set to do a wakeup
 *					if f_iocont on any descriptor goes to 0
 *
 * Returns:	0			Success
 *		EBADF			One or more fds in the bit vector
 *						were invalid, but the rest
 *						were successfully dropped
 *
 * Notes:	An fd make become bad while the proc_fdlock() is not held,
 *		if a multithreaded application closes the fd out from under
 *		the in progress select.  In this case, we still have to
 *		clean up after the set up on the remaining fds.
 */
static int
seldrop_locked(struct proc *p, u_int32_t *ibits, int nfd, int lim, int *need_wakeup)
{
	int msk, i, j, nc, fd;
	u_int32_t bits;
	struct fileproc *fp;
	u_int32_t *iptr;
	u_int nw;
	int error = 0;
	uthread_t uth = current_uthread();
	struct _select_data *seldata;

	*need_wakeup = 0;

	nw = howmany(nfd, NFDBITS);
	seldata = &uth->uu_save.uus_select_data;

	nc = 0;
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i / NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1U << j);
				/*
				 * If we've already dropped as many as were
				 * counted/scanned, then we are done.
				 */
				if (nc >= lim) {
					goto done;
				}

				/*
				 * We took an I/O reference in selcount,
				 * so the fp can't possibly be NULL.
				 */
				fp = fp_get_noref_locked_with_iocount(p, fd);
				selunlinkfp(fp, uth->uu_selset);

				nc++;

				const os_ref_count_t refc = os_ref_release_locked(&fp->fp_iocount);
				if (0 == refc) {
					panic("fp_iocount overdecrement!");
				}

				if (1 == refc) {
					/*
					 * The last iocount is responsible for clearing
					 * selconfict flag - even if we didn't set it -
					 * and is also responsible for waking up anyone
					 * waiting on iocounts to drain.
					 */
					if (fp->fp_flags & FP_SELCONFLICT) {
						fp->fp_flags &= ~FP_SELCONFLICT;
					}
					if (p->p_fd.fd_fpdrainwait) {
						p->p_fd.fd_fpdrainwait = 0;
						*need_wakeup = 1;
					}
				}
			}
		}
	}
done:
	return error;
}


static int
seldrop(struct proc *p, u_int32_t *ibits, int nfd, int lim)
{
	int error;
	int need_wakeup = 0;

	proc_fdlock(p);
	error = seldrop_locked(p, ibits, nfd, lim, &need_wakeup);
	proc_fdunlock(p);
	if (need_wakeup) {
		wakeup(&p->p_fd.fd_fpdrainwait);
	}
	return error;
}

/*
 * Record a select request.
 */
void
selrecord(__unused struct proc *selector, struct selinfo *sip, void *s_data)
{
	struct select_set *selset = current_uthread()->uu_selset;

	/* do not record if this is second pass of select */
	if (!s_data) {
		return;
	}

	if (selset == SELSPEC_RECORD_MARKER) {
		/*
		 * The kevent subsystem is trying to sniff
		 * the selinfo::si_note to attach to.
		 */
		((selspec_record_hook_t)s_data)(sip);
	} else {
		waitq_link_t *linkp = s_data;

		if (!waitq_is_valid(&sip->si_waitq)) {
			waitq_init(&sip->si_waitq, WQT_SELECT, SYNC_POLICY_FIFO);
		}

		/* note: this checks for pre-existing linkage */
		select_set_link(&sip->si_waitq, selset, linkp);
	}
}

static void
selwakeup_internal(struct selinfo *sip, long hint, wait_result_t wr)
{
	if (sip->si_flags & SI_SELSPEC) {
		/*
		 * The "primitive" lock is held.
		 * The knote lock is not held.
		 *
		 * All knotes will transition their kn_hook to NULL and we will
		 * reeinitialize the primitive's klist
		 */
		lck_spin_lock(&selspec_lock);
		knote(&sip->si_note, hint, /*autodetach=*/ true);
		lck_spin_unlock(&selspec_lock);
		sip->si_flags &= ~SI_SELSPEC;
	}

	/*
	 * After selrecord() has been called, selinfo owners must call
	 * at least one of selwakeup() or selthreadclear().
	 *
	 * Use this opportunity to deinit the waitq
	 * so that all linkages are garbage collected
	 * in a combined wakeup-all + unlink + deinit call.
	 */
	select_waitq_wakeup_and_deinit(&sip->si_waitq, NO_EVENT64, wr);
}


void
selwakeup(struct selinfo *sip)
{
	selwakeup_internal(sip, 0, THREAD_AWAKENED);
}

void
selthreadclear(struct selinfo *sip)
{
	selwakeup_internal(sip, NOTE_REVOKE, THREAD_RESTART);
}


/*
 * gethostuuid
 *
 * Description:	Get the host UUID from IOKit and return it to user space.
 *
 * Parameters:	uuid_buf		Pointer to buffer to receive UUID
 *		timeout			Timespec for timout
 *
 * Returns:	0			Success
 *		EWOULDBLOCK		Timeout is too short
 *		copyout:EFAULT		Bad user buffer
 *		mac_system_check_info:EPERM		Client not allowed to perform this operation
 *
 * Notes:	A timeout seems redundant, since if it's tolerable to not
 *		have a system UUID in hand, then why ask for one?
 */
int
gethostuuid(struct proc *p, struct gethostuuid_args *uap, __unused int32_t *retval)
{
	kern_return_t kret;
	int error;
	mach_timespec_t mach_ts;        /* for IOKit call */
	__darwin_uuid_t uuid_kern = {}; /* for IOKit call */

	/* Check entitlement */
	if (!IOCurrentTaskHasEntitlement("com.apple.private.getprivatesysid")) {
#if !defined(XNU_TARGET_OS_OSX)
#if CONFIG_MACF
		if ((error = mac_system_check_info(kauth_cred_get(), "hw.uuid")) != 0) {
			/* EPERM invokes userspace upcall if present */
			return error;
		}
#endif
#endif
	}

	/* Convert the 32/64 bit timespec into a mach_timespec_t */
	if (proc_is64bit(p)) {
		struct user64_timespec ts;
		error = copyin(uap->timeoutp, &ts, sizeof(ts));
		if (error) {
			return error;
		}
		mach_ts.tv_sec = (unsigned int)ts.tv_sec;
		mach_ts.tv_nsec = (clock_res_t)ts.tv_nsec;
	} else {
		struct user32_timespec ts;
		error = copyin(uap->timeoutp, &ts, sizeof(ts));
		if (error) {
			return error;
		}
		mach_ts.tv_sec = ts.tv_sec;
		mach_ts.tv_nsec = ts.tv_nsec;
	}

	/* Call IOKit with the stack buffer to get the UUID */
	kret = IOBSDGetPlatformUUID(uuid_kern, mach_ts);

	/*
	 * If we get it, copy out the data to the user buffer; note that a
	 * uuid_t is an array of characters, so this is size invariant for
	 * 32 vs. 64 bit.
	 */
	if (kret == KERN_SUCCESS) {
		error = copyout(uuid_kern, uap->uuid_buf, sizeof(uuid_kern));
	} else {
		error = EWOULDBLOCK;
	}

	return error;
}

/*
 * ledger
 *
 * Description:	Omnibus system call for ledger operations
 */
int
ledger(struct proc *p, struct ledger_args *args, __unused int32_t *retval)
{
#if !CONFIG_MACF
#pragma unused(p)
#endif
	int rval, pid, len, error;
#ifdef LEDGER_DEBUG
	struct ledger_limit_args lla;
#endif
	task_t task;
	proc_t proc;

	/* Finish copying in the necessary args before taking the proc lock */
	error = 0;
	len = 0;
	if (args->cmd == LEDGER_ENTRY_INFO) {
		error = copyin(args->arg3, (char *)&len, sizeof(len));
	} else if (args->cmd == LEDGER_TEMPLATE_INFO) {
		error = copyin(args->arg2, (char *)&len, sizeof(len));
	} else if (args->cmd == LEDGER_LIMIT)
#ifdef LEDGER_DEBUG
	{ error = copyin(args->arg2, (char *)&lla, sizeof(lla));}
#else
	{ return EINVAL; }
#endif
	else if ((args->cmd < 0) || (args->cmd > LEDGER_MAX_CMD)) {
		return EINVAL;
	}

	if (error) {
		return error;
	}
	if (len < 0) {
		return EINVAL;
	}

	rval = 0;
	if (args->cmd != LEDGER_TEMPLATE_INFO) {
		pid = (int)args->arg1;
		proc = proc_find(pid);
		if (proc == NULL) {
			return ESRCH;
		}

#if CONFIG_MACF
		error = mac_proc_check_ledger(p, proc, args->cmd);
		if (error) {
			proc_rele(proc);
			return error;
		}
#endif

		task = proc_task(proc);
	}

	switch (args->cmd) {
#ifdef LEDGER_DEBUG
	case LEDGER_LIMIT: {
		if (!kauth_cred_issuser(kauth_cred_get())) {
			rval = EPERM;
		}
		rval = ledger_limit(task, &lla);
		proc_rele(proc);
		break;
	}
#endif
	case LEDGER_INFO: {
		struct ledger_info info = {};

		rval = ledger_info(task, &info);
		proc_rele(proc);
		if (rval == 0) {
			rval = copyout(&info, args->arg2,
			    sizeof(info));
		}
		break;
	}

	case LEDGER_ENTRY_INFO: {
		void *buf;
		int sz;

#if CONFIG_MEMORYSTATUS
		task_ledger_settle_dirty_time(task);
#endif /* CONFIG_MEMORYSTATUS */

		rval = ledger_get_task_entry_info_multiple(task, &buf, &len);
		proc_rele(proc);
		if ((rval == 0) && (len >= 0)) {
			sz = len * sizeof(struct ledger_entry_info);
			rval = copyout(buf, args->arg2, sz);
			kfree_data(buf, sz);
		}
		if (rval == 0) {
			rval = copyout(&len, args->arg3, sizeof(len));
		}
		break;
	}

	case LEDGER_TEMPLATE_INFO: {
		void *buf;
		int sz;

		rval = ledger_template_info(&buf, &len);
		if ((rval == 0) && (len >= 0)) {
			sz = len * sizeof(struct ledger_template_info);
			rval = copyout(buf, args->arg1, sz);
			kfree_data(buf, sz);
		}
		if (rval == 0) {
			rval = copyout(&len, args->arg2, sizeof(len));
		}
		break;
	}

	default:
		panic("ledger syscall logic error -- command type %d", args->cmd);
		proc_rele(proc);
		rval = EINVAL;
	}

	return rval;
}

int
telemetry(__unused struct proc *p, struct telemetry_args *args, __unused int32_t *retval)
{
	int error = 0;

	switch (args->cmd) {
#if CONFIG_TELEMETRY
	case TELEMETRY_CMD_TIMER_EVENT:
		error = telemetry_timer_event(args->deadline, args->interval, args->leeway);
		break;
	case TELEMETRY_CMD_PMI_SETUP:
		error = telemetry_pmi_setup((enum telemetry_pmi)args->deadline, args->interval);
		break;
#endif /* CONFIG_TELEMETRY */
	case TELEMETRY_CMD_VOUCHER_NAME:
		if (thread_set_voucher_name((mach_port_name_t)args->deadline)) {
			error = EINVAL;
		}
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

/*
 * Logging
 *
 * Description: syscall to access kernel logging from userspace
 *
 * Args:
 *	tag - used for syncing with userspace on the version.
 *	flags - flags used by the syscall.
 *	buffer - userspace address of string to copy.
 *	size - size of buffer.
 */
int
log_data(__unused struct proc *p, struct log_data_args *args, int *retval)
{
	unsigned int tag = args->tag;
	unsigned int flags = args->flags;
	user_addr_t buffer = args->buffer;
	unsigned int size = args->size;
	int ret = 0;
	*retval = 0;

	/* Only DEXTs are suppose to use this syscall. */
	if (!task_is_driver(current_task())) {
		return EPERM;
	}

	/*
	 * Tag synchronize the syscall version with userspace.
	 * Tag == 0 => flags == OS_LOG_TYPE
	 */
	if (tag != 0) {
		return EINVAL;
	}

	/*
	 * OS_LOG_TYPE are defined in libkern/os/log.h
	 * In userspace they are defined in libtrace/os/log.h
	 */
	if (flags != OS_LOG_TYPE_DEFAULT &&
	    flags != OS_LOG_TYPE_INFO &&
	    flags != OS_LOG_TYPE_DEBUG &&
	    flags != OS_LOG_TYPE_ERROR &&
	    flags != OS_LOG_TYPE_FAULT) {
		return EINVAL;
	}

	if (size == 0) {
		return EINVAL;
	}

	/* truncate to OS_LOG_DATA_MAX_SIZE */
	if (size > OS_LOG_DATA_MAX_SIZE) {
		printf("%s: WARNING msg is going to be truncated from %u to %u\n",
		    __func__, size, OS_LOG_DATA_MAX_SIZE);
		size = OS_LOG_DATA_MAX_SIZE;
	}

	char *log_msg = (char *)kalloc_data(size, Z_WAITOK);
	if (!log_msg) {
		return ENOMEM;
	}

	if (copyin(buffer, log_msg, size) != 0) {
		ret = EFAULT;
		goto out;
	}
	log_msg[size - 1] = '\0';

	/*
	 * This will log to dmesg and logd.
	 * The call will fail if the current
	 * process is not a driverKit process.
	 */
	os_log_driverKit(&ret, OS_LOG_DEFAULT, (os_log_type_t)flags, "%s", log_msg);

out:
	if (log_msg != NULL) {
		kfree_data(log_msg, size);
	}

	return ret;
}

#if DEVELOPMENT || DEBUG

static int
sysctl_mpsc_test_pingpong SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t value = 0;
	int error;

	error = SYSCTL_IN(req, &value, sizeof(value));
	if (error) {
		return error;
	}

	if (error == 0 && req->newptr) {
		error = mpsc_test_pingpong(value, &value);
		if (error == 0) {
			error = SYSCTL_OUT(req, &value, sizeof(value));
		}
	}

	return error;
}
SYSCTL_PROC(_kern, OID_AUTO, mpsc_test_pingpong, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mpsc_test_pingpong, "Q", "MPSC tests: pingpong");

#endif /* DEVELOPMENT || DEBUG */

/* Telemetry, microstackshots */

SYSCTL_NODE(_kern, OID_AUTO, microstackshot, CTLFLAG_RD | CTLFLAG_LOCKED, 0,
    "microstackshot info");

extern uint32_t telemetry_sample_rate;
SYSCTL_UINT(_kern_microstackshot, OID_AUTO, interrupt_sample_rate,
    CTLFLAG_RD | CTLFLAG_LOCKED, &telemetry_sample_rate, 0,
    "interrupt-based sampling rate in Hz");

#if defined(MT_CORE_INSTRS) && defined(MT_CORE_CYCLES)

extern uint64_t mt_microstackshot_period;
SYSCTL_QUAD(_kern_microstackshot, OID_AUTO, pmi_sample_period,
    CTLFLAG_RD | CTLFLAG_LOCKED, &mt_microstackshot_period,
    "PMI sampling rate");
extern unsigned int mt_microstackshot_ctr;
SYSCTL_UINT(_kern_microstackshot, OID_AUTO, pmi_sample_counter,
    CTLFLAG_RD | CTLFLAG_LOCKED, &mt_microstackshot_ctr, 0,
    "PMI counter");

#endif /* defined(MT_CORE_INSTRS) && defined(MT_CORE_CYCLES) */

/*Remote Time api*/
SYSCTL_NODE(_machdep, OID_AUTO, remotetime, CTLFLAG_RD | CTLFLAG_LOCKED, 0, "Remote time api");

#if DEVELOPMENT || DEBUG
#if CONFIG_MACH_BRIDGE_SEND_TIME
extern _Atomic uint32_t bt_init_flag;
extern uint32_t mach_bridge_timer_enable(uint32_t, int);

SYSCTL_INT(_machdep_remotetime, OID_AUTO, bridge_timer_init_flag,
    CTLFLAG_RD | CTLFLAG_LOCKED, &bt_init_flag, 0, "");

static int sysctl_mach_bridge_timer_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t value = 0;
	int error = 0;
	/* User is querying buffer size */
	if (req->oldptr == USER_ADDR_NULL && req->newptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(value);
		return 0;
	}
	if (os_atomic_load(&bt_init_flag, acquire)) {
		if (req->newptr) {
			int new_value = 0;
			error = SYSCTL_IN(req, &new_value, sizeof(new_value));
			if (error) {
				return error;
			}
			if (new_value == 0 || new_value == 1) {
				value = mach_bridge_timer_enable(new_value, 1);
			} else {
				return EPERM;
			}
		} else {
			value = mach_bridge_timer_enable(0, 0);
		}
	}
	error = SYSCTL_OUT(req, &value, sizeof(value));
	return error;
}

SYSCTL_PROC(_machdep_remotetime, OID_AUTO, bridge_timer_enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mach_bridge_timer_enable, "I", "");

#endif /* CONFIG_MACH_BRIDGE_SEND_TIME */

static int sysctl_mach_bridge_remote_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t ltime = 0, rtime = 0;
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(rtime);
		return 0;
	}
	if (req->newptr) {
		int error = SYSCTL_IN(req, &ltime, sizeof(ltime));
		if (error) {
			return error;
		}
	}
	rtime = mach_bridge_remote_time(ltime);
	return SYSCTL_OUT(req, &rtime, sizeof(rtime));
}
SYSCTL_PROC(_machdep_remotetime, OID_AUTO, mach_bridge_remote_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mach_bridge_remote_time, "Q", "");

#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_MACH_BRIDGE_RECV_TIME
extern struct bt_params bt_params_get_latest(void);

static int sysctl_mach_bridge_conversion_params SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct bt_params params = {};
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(struct bt_params);
		return 0;
	}
	if (req->newptr) {
		return EPERM;
	}
	params = bt_params_get_latest();
	return SYSCTL_OUT(req, &params, MIN(sizeof(params), req->oldlen));
}

SYSCTL_PROC(_machdep_remotetime, OID_AUTO, conversion_params,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0,
    0, sysctl_mach_bridge_conversion_params, "S,bt_params", "");

#endif /* CONFIG_MACH_BRIDGE_RECV_TIME */

#if DEVELOPMENT || DEBUG

#include <pexpert/pexpert.h>
extern int32_t sysctl_get_bound_cpuid(void);
extern kern_return_t sysctl_thread_bind_cpuid(int32_t cpuid);
static int
sysctl_kern_sched_thread_bind_cpu SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	/*
	 * DO NOT remove this bootarg guard or make this non-development.
	 * This kind of binding should only be used for tests and
	 * experiments in a custom configuration, never shipping code.
	 */

	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	int32_t cpuid = sysctl_get_bound_cpuid();

	int32_t new_value;
	int changed;
	int error = sysctl_io_number(req, cpuid, sizeof cpuid, &new_value, &changed);
	if (error) {
		return error;
	}

	if (changed) {
		kern_return_t kr = sysctl_thread_bind_cpuid(new_value);

		if (kr == KERN_NOT_SUPPORTED) {
			return ENOTSUP;
		}

		if (kr == KERN_INVALID_VALUE) {
			return ERANGE;
		}
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cpu, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cpu, "I", "");

#if __AMP__
extern char sysctl_get_bound_cluster_type(void);
extern void sysctl_thread_bind_cluster_type(char cluster_type);
static int
sysctl_kern_sched_thread_bind_cluster_type SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char cluster_type = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_thread_bind_cluster_type(cluster_type);
out:
	cluster_type = sysctl_get_bound_cluster_type();
	buff[0] = cluster_type;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cluster_type, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cluster_type, "A", "");

extern char sysctl_get_task_cluster_type(void);
extern void sysctl_task_set_cluster_type(char cluster_type);
static int
sysctl_kern_sched_task_set_cluster_type SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	if (!PE_parse_boot_argn("enable_skstsct", NULL, 0)) {
		return ENOENT;
	}

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char cluster_type = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_task_set_cluster_type(cluster_type);
out:
	cluster_type = sysctl_get_task_cluster_type();
	buff[0] = cluster_type;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_cluster_type, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_task_set_cluster_type, "A", "");

extern kern_return_t thread_bind_cluster_id(thread_t thread, uint32_t cluster_id, thread_bind_option_t options);
extern uint32_t thread_bound_cluster_id(thread_t);
static int
sysctl_kern_sched_thread_bind_cluster_id SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	thread_t self = current_thread();
	uint32_t old_value = thread_bound_cluster_id(self);
	uint32_t new_value;

	int error = SYSCTL_IN(req, &new_value, sizeof(new_value));
	if (error) {
		return error;
	}
	if (new_value != old_value) {
		/*
		 * This sysctl binds the thread to the cluster without any flags,
		 * which means it will be hard bound and not check eligibility.
		 */
		thread_bind_cluster_id(self, new_value, 0);
	}
	return SYSCTL_OUT(req, &old_value, sizeof(old_value));
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cluster_id, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cluster_id, "I", "");

#if CONFIG_SCHED_EDGE

extern int sched_edge_restrict_ut;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_restrict_ut, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_restrict_ut, 0, "Edge Scheduler Restrict UT Threads");
extern int sched_edge_restrict_bg;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_restrict_bg, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_restrict_ut, 0, "Edge Scheduler Restrict BG Threads");
extern int sched_edge_migrate_ipi_immediate;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_migrate_ipi_immediate, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_migrate_ipi_immediate, 0, "Edge Scheduler uses immediate IPIs for migration event based on execution latency");

#endif /* CONFIG_SCHED_EDGE */

#endif /* __AMP__ */

#if SCHED_HYGIENE_DEBUG

SYSCTL_QUAD(_kern, OID_AUTO, interrupt_masked_threshold_mt, CTLFLAG_RW | CTLFLAG_LOCKED,
    &interrupt_masked_timeout,
    "Interrupt masked duration after which a tracepoint is emitted or the device panics (in mach timebase units)");

SYSCTL_INT(_kern, OID_AUTO, interrupt_masked_debug_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &interrupt_masked_debug_mode, 0,
    "Enable interrupt masked tracing or panic (0: off, 1: trace, 2: panic)");

SYSCTL_QUAD(_kern, OID_AUTO, sched_preemption_disable_threshold_mt, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sched_preemption_disable_threshold_mt,
    "Preemption disablement duration after which a tracepoint is emitted or the device panics (in mach timebase units)");

SYSCTL_INT(_kern, OID_AUTO, sched_preemption_disable_debug_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sched_preemption_disable_debug_mode, 0,
    "Enable preemption disablement tracing or panic (0: off, 1: trace, 2: panic)");

PERCPU_DECL(uint64_t _Atomic, preemption_disable_max_mt);

static int
sysctl_sched_preemption_disable_stats(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	uint64_t stats[MAX_CPUS]; // maximum per CPU

	/*
	 * No synchronization here. The individual values are pretty much
	 * independent, and reading/writing them is atomic.
	 */

	int cpu = 0;
	percpu_foreach(max_stat, preemption_disable_max_mt) {
		stats[cpu++] = os_atomic_load(max_stat, relaxed);
	}

	if (req->newlen > 0) {
		// writing just resets all stats.
		percpu_foreach(max_stat, preemption_disable_max_mt) {
			os_atomic_store(max_stat, 0, relaxed);
		}
	}

	return sysctl_io_opaque(req, stats, cpu * sizeof(uint64_t), NULL);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_preemption_disable_stats,
    CTLTYPE_OPAQUE | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_sched_preemption_disable_stats, "I", "Preemption disablement statistics");

#endif /* SCHED_HYGIENE_DEBUG */

/* used for testing by exception_tests */
extern uint32_t ipc_control_port_options;
SYSCTL_INT(_kern, OID_AUTO, ipc_control_port_options,
    CTLFLAG_RD | CTLFLAG_LOCKED, &ipc_control_port_options, 0, "");

#endif /* DEVELOPMENT || DEBUG */

extern uint32_t task_exc_guard_default;

SYSCTL_INT(_kern, OID_AUTO, task_exc_guard_default,
    CTLFLAG_RD | CTLFLAG_LOCKED, &task_exc_guard_default, 0, "");


static int
sysctl_kern_tcsm_available SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t value = machine_csv(CPUVN_CI) ? 1 : 0;

	if (req->newptr) {
		return EINVAL;
	}

	return SYSCTL_OUT(req, &value, sizeof(value));
}
SYSCTL_PROC(_kern, OID_AUTO, tcsm_available,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_tcsm_available, "I", "");


static int
sysctl_kern_tcsm_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t soflags = 0;
	uint32_t old_value = thread_get_no_smt() ? 1 : 0;

	int error = SYSCTL_IN(req, &soflags, sizeof(soflags));
	if (error) {
		return error;
	}

	if (soflags && machine_csv(CPUVN_CI)) {
		thread_set_no_smt(true);
		machine_tecs(current_thread());
	}

	return SYSCTL_OUT(req, &old_value, sizeof(old_value));
}
SYSCTL_PROC(_kern, OID_AUTO, tcsm_enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_tcsm_enable, "I", "");

static int
sysctl_kern_debug_get_preoslog SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	static bool oneshot_executed = false;
	size_t preoslog_size = 0;
	const char *preoslog = NULL;
	int ret = 0;

	// DumpPanic passes a non-zero write value when it needs oneshot behaviour
	if (req->newptr != USER_ADDR_NULL) {
		uint8_t oneshot = 0;
		int error = SYSCTL_IN(req, &oneshot, sizeof(oneshot));
		if (error) {
			return error;
		}

		if (oneshot) {
			if (!os_atomic_cmpxchg(&oneshot_executed, false, true, acq_rel)) {
				return EPERM;
			}
		}
	}

	preoslog = sysctl_debug_get_preoslog(&preoslog_size);
	if (preoslog != NULL && preoslog_size == 0) {
		sysctl_debug_free_preoslog();
		return 0;
	}

	if (preoslog == NULL || preoslog_size == 0) {
		return 0;
	}

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = preoslog_size;
		return 0;
	}

	ret = SYSCTL_OUT(req, preoslog, preoslog_size);
	sysctl_debug_free_preoslog();
	return ret;
}

SYSCTL_PROC(_kern, OID_AUTO, preoslog, CTLTYPE_OPAQUE | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_debug_get_preoslog, "-", "");

#if DEVELOPMENT || DEBUG
extern void sysctl_task_set_no_smt(char no_smt);
extern char sysctl_task_get_no_smt(void);

static int
sysctl_kern_sched_task_set_no_smt SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char no_smt = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_task_set_no_smt(no_smt);
out:
	no_smt = sysctl_task_get_no_smt();
	buff[0] = no_smt;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_no_smt, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_sched_task_set_no_smt, "A", "");

static int
sysctl_kern_sched_thread_set_no_smt(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int old_value = thread_get_no_smt() ? 1 : 0;
	int error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (changed) {
		thread_set_no_smt(!!new_value);
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_set_no_smt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_sched_thread_set_no_smt, "I", "");

#if CONFIG_SCHED_RT_ALLOW

#if DEVELOPMENT || DEBUG
#define RT_ALLOW_CTLFLAGS CTLFLAG_RW
#else
#define RT_ALLOW_CTLFLAGS CTLFLAG_RD
#endif /* DEVELOPMENT || DEBUG */

static int
sysctl_kern_rt_allow_limit_percent(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	extern uint8_t rt_allow_limit_percent;

	int new_value = 0;
	int old_value = rt_allow_limit_percent;
	int changed = 0;

	int error = sysctl_io_number(req, old_value, sizeof(old_value),
	    &new_value, &changed);
	if (error != 0) {
		return error;
	}

	/* Only accept a percentage between 1 and 99 inclusive. */
	if (changed) {
		if (new_value >= 100 || new_value <= 0) {
			return EINVAL;
		}

		rt_allow_limit_percent = (uint8_t)new_value;
	}

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, rt_allow_limit_percent,
    RT_ALLOW_CTLFLAGS | CTLTYPE_INT | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_rt_allow_limit_percent, "I", "");

static int
sysctl_kern_rt_allow_limit_interval_ms(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	extern uint16_t rt_allow_limit_interval_ms;

	uint64_t new_value = 0;
	uint64_t old_value = rt_allow_limit_interval_ms;
	int changed = 0;

	int error = sysctl_io_number(req, old_value, sizeof(old_value),
	    &new_value, &changed);
	if (error != 0) {
		return error;
	}

	/* Value is in ns. Must be at least 1ms. */
	if (changed) {
		if (new_value < 1 || new_value > UINT16_MAX) {
			return EINVAL;
		}

		rt_allow_limit_interval_ms = (uint16_t)new_value;
	}

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, rt_allow_limit_interval_ms,
    RT_ALLOW_CTLFLAGS | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_rt_allow_limit_interval_ms, "Q", "");

#endif /* CONFIG_SCHED_RT_ALLOW */


static int
sysctl_kern_task_set_filter_msg_flag SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int new_value, changed;
	int old_value = task_get_filter_msg_flag(current_task()) ? 1 : 0;
	int error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (changed) {
		task_set_filter_msg_flag(current_task(), !!new_value);
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, task_set_filter_msg_flag, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_task_set_filter_msg_flag, "I", "");

#if CONFIG_PROC_RESOURCE_LIMITS

extern mach_port_name_t current_task_get_fatal_port_name(void);

static int
sysctl_kern_task_get_fatal_port SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int port = 0;
	int flag = 0;

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(mach_port_t);
		return 0;
	}

	int error = SYSCTL_IN(req, &flag, sizeof(flag));
	if (error) {
		return error;
	}

	if (flag == 1) {
		port = (int)current_task_get_fatal_port_name();
	}
	return SYSCTL_OUT(req, &port, sizeof(port));
}

SYSCTL_PROC(_machdep, OID_AUTO, task_get_fatal_port, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_task_get_fatal_port, "I", "");

#endif /* CONFIG_PROC_RESOURCE_LIMITS */

extern unsigned int ipc_entry_table_count_max(void);

static int
sysctl_mach_max_port_table_size SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int old_value = ipc_entry_table_count_max();
	int error = sysctl_io_number(req, old_value, sizeof(int), NULL, NULL);

	return error;
}

SYSCTL_PROC(_machdep, OID_AUTO, max_port_table_size, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mach_max_port_table_size, "I", "");

#endif /* DEVELOPMENT || DEBUG */

#if defined(CONFIG_KDP_INTERACTIVE_DEBUGGING) && defined(CONFIG_KDP_COREDUMP_ENCRYPTION)

#define COREDUMP_ENCRYPTION_KEY_ENTITLEMENT "com.apple.private.coredump-encryption-key"

static int
sysctl_coredump_encryption_key_update SYSCTL_HANDLER_ARGS
{
	kern_return_t ret = KERN_SUCCESS;
	int error = 0;
	struct kdp_core_encryption_key_descriptor key_descriptor = {
		.kcekd_format = MACH_CORE_FILEHEADER_V2_FLAG_NEXT_COREFILE_KEY_FORMAT_NIST_P256,
	};

	/* Need to be root and have entitlement */
	if (!kauth_cred_issuser(kauth_cred_get()) && !IOCurrentTaskHasEntitlement(COREDUMP_ENCRYPTION_KEY_ENTITLEMENT)) {
		return EPERM;
	}

	// Sanity-check the given key length
	if (req->newlen > UINT16_MAX) {
		return EINVAL;
	}

	// It is allowed for the caller to pass in a NULL buffer.
	// This indicates that they want us to forget about any public key we might have.
	if (req->newptr) {
		key_descriptor.kcekd_size = (uint16_t) req->newlen;
		key_descriptor.kcekd_key = kalloc_data(key_descriptor.kcekd_size, Z_WAITOK);

		if (key_descriptor.kcekd_key == NULL) {
			return ENOMEM;
		}

		error = SYSCTL_IN(req, key_descriptor.kcekd_key, key_descriptor.kcekd_size);
		if (error) {
			goto out;
		}
	}

	ret = IOProvideCoreFileAccess(kdp_core_handle_new_encryption_key, (void *)&key_descriptor);
	if (KERN_SUCCESS != ret) {
		printf("Failed to handle the new encryption key. Error 0x%x", ret);
		error = EFAULT;
	}

out:
	kfree_data(key_descriptor.kcekd_key, key_descriptor.kcekd_size);
	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, coredump_encryption_key, CTLTYPE_OPAQUE | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_coredump_encryption_key_update, "-", "Set a new encryption key for coredumps");

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING && CONFIG_KDP_COREDUMP_ENCRYPTION*/
