/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/guarded.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/uio_internal.h>
#include <sys/ubc_internal.h>
#include <vfs/vfs_support.h>
#include <security/audit/audit.h>
#include <sys/syscall.h>
#include <sys/kauth.h>
#include <sys/kdebug.h>
#include <stdbool.h>
#include <vm/vm_protos.h>
#include <libkern/section_keywords.h>

#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/exc_guard.h>

#if CONFIG_MACF && CONFIG_VNGUARD
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
#include <pexpert/pexpert.h>
#include <sys/sysctl.h>
#include <sys/reason.h>
#endif

#define f_flag fp_glob->fg_flag
extern int writev_uio(struct proc *p, int fd, user_addr_t user_iovp,
    int iovcnt, off_t offset, int flags, guardid_t *puguard,
    user_ssize_t *retval);
extern int write_internal(struct proc *p, int fd, user_addr_t buf,
    user_size_t nbyte, off_t offset, int flags, guardid_t *puguard,
    user_ssize_t *retval);
extern int exit_with_guard_exception(void *p, mach_exception_data_type_t code,
    mach_exception_data_type_t subcode);
/*
 * Experimental guarded file descriptor support.
 */

kern_return_t task_exception_notify(exception_type_t exception,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode);

#define GUARD_REQUIRED (GUARD_DUP)
#define GUARD_ALL      (GUARD_REQUIRED |        \
	                (GUARD_CLOSE | GUARD_SOCKET_IPC | GUARD_FILEPORT | GUARD_WRITE))

static KALLOC_TYPE_DEFINE(fp_guard_zone, struct fileproc_guard, KT_DEFAULT);

struct gfp_crarg {
	guardid_t gca_guard;
	uint16_t  gca_attrs;
};

static struct fileproc_guard *
guarded_fileproc_alloc(guardid_t guard)
{
	struct fileproc_guard *fpg;

	fpg = zalloc_flags(fp_guard_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	fpg->fpg_guard = guard;
	return fpg;
}

static void
guarded_fileproc_init(struct fileproc *fp, void *initarg)
{
	struct gfp_crarg *arg = initarg;

	assert(arg->gca_attrs);
	fp->fp_guard = guarded_fileproc_alloc(arg->gca_guard);
	fp->fp_guard_attrs = arg->gca_attrs;
}

/*
 * This is called from fdt_fork(),
 * where it needs to copy a guarded
 * fd to the new shadow proc.
 */
void
guarded_fileproc_copy_guard(struct fileproc *ofp, struct fileproc *nfp)
{
	struct gfp_crarg arg = {
		.gca_guard = ofp->fp_guard->fpg_guard,
		.gca_attrs = ofp->fp_guard_attrs
	};
	guarded_fileproc_init(nfp, &arg);
}

/*
 * This is called from fileproc_free(),
 * which is why it is safe to call
 * without holding the proc_fdlock.
 */
void
guarded_fileproc_unguard(struct fileproc *fp)
{
	struct fileproc_guard *fpg = fp->fp_guard;

	fp->fp_guard_attrs = 0;
	fp->fp_wset = fpg->fpg_wset;

	zfree(fp_guard_zone, fpg);
}

static int
fp_lookup_guarded_locked(proc_t p, int fd, guardid_t guard,
    struct fileproc **fpp)
{
	int error;
	struct fileproc *fp;

	if ((error = fp_lookup(p, fd, &fp, 1)) != 0) {
		return error;
	}

	if (fp->fp_guard_attrs == 0) {
		(void) fp_drop(p, fd, fp, 1);
		return EINVAL;
	}

	if (guard != fp->fp_guard->fpg_guard) {
		(void) fp_drop(p, fd, fp, 1);
		return EPERM; /* *not* a mismatch exception */
	}

	*fpp = fp;
	return 0;
}

int
fp_lookup_guarded(proc_t p, int fd, guardid_t guard,
    struct fileproc **fpp, int locked)
{
	int error;

	if (!locked) {
		proc_fdlock_spin(p);
	}

	error = fp_lookup_guarded_locked(p, fd, guard, fpp);

	if (!locked) {
		proc_fdunlock(p);
	}

	return error;
}

/*
 * Expected use pattern:
 *
 * if (fp_isguarded(fp, GUARD_CLOSE)) {
 *      error = fp_guard_exception(p, fd, fp, kGUARD_EXC_CLOSE);
 *      proc_fdunlock(p);
 *      return error;
 * }
 */
int
fp_isguarded(struct fileproc *fp, u_int attrs)
{
	return fp->fp_guard_attrs && (fp->fp_guard_attrs & attrs) == attrs;
}

extern char *proc_name_address(void *p);

int
fp_guard_exception(proc_t p, int fd, struct fileproc *fp, u_int flavor)
{
	/* all fp guard fields protected via proc_fdlock() */
	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);

	mach_exception_code_t code = 0;
	EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_FD);
	EXC_GUARD_ENCODE_FLAVOR(code, flavor);
	EXC_GUARD_ENCODE_TARGET(code, fd);
	mach_exception_subcode_t subcode = fp->fp_guard->fpg_guard;

	assert(fp->fp_guard_attrs);

	thread_t t = current_thread();
	thread_guard_violation(t, code, subcode, TRUE);
	return EPERM;
}

/*
 * (Invoked before returning to userland from the syscall handler.)
 */
void
fd_guard_ast(
	thread_t __unused t,
	mach_exception_code_t code,
	mach_exception_subcode_t subcode)
{
	/*
	 * Check if anyone has registered for Synchronous EXC_GUARD, if yes then,
	 * deliver it synchronously and then kill the process, else kill the process
	 * and deliver the exception via EXC_CORPSE_NOTIFY.
	 */
	if (task_exception_notify(EXC_GUARD, code, subcode) == KERN_SUCCESS) {
		psignal(current_proc(), SIGKILL);
	} else {
		exit_with_guard_exception(current_proc(), code, subcode);
	}
}

/*
 * Experimental guarded file descriptor SPIs
 */

/*
 * int guarded_open_np(const char *pathname, int flags,
 *     const guardid_t *guard, u_int guardflags, ...);
 *
 * In this initial implementation, GUARD_DUP must be specified.
 * GUARD_CLOSE, GUARD_SOCKET_IPC and GUARD_FILEPORT are optional.
 *
 * If GUARD_DUP wasn't specified, then we'd have to do the (extra) work
 * to allow dup-ing a descriptor to inherit the guard onto the new
 * descriptor.  (Perhaps GUARD_DUP behaviours should just always be true
 * for a guarded fd?  Or, more sanely, all the dup operations should
 * just always propagate the guard?)
 *
 * Guarded descriptors are always close-on-exec, and GUARD_CLOSE
 * requires close-on-fork; O_CLOEXEC must be set in flags.
 * This setting is immutable; attempts to clear the flag will
 * cause a guard exception.
 *
 * XXX	It's somewhat broken that change_fdguard_np() can completely
 *	remove the guard and thus revoke down the immutability
 *	promises above.  Ick.
 */
int
guarded_open_np(proc_t p, struct guarded_open_np_args *uap, int32_t *retval)
{
	if ((uap->flags & O_CLOEXEC) == 0) {
		return EINVAL;
	}

	if (((uap->guardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
	    ((uap->guardflags & ~GUARD_ALL) != 0)) {
		return EINVAL;
	}

	int error;
	struct gfp_crarg crarg = {
		.gca_attrs = (uint16_t)uap->guardflags
	};

	if ((error = copyin(uap->guard,
	    &(crarg.gca_guard), sizeof(crarg.gca_guard))) != 0) {
		return error;
	}

	/*
	 * Disallow certain guard values -- is zero enough?
	 */
	if (crarg.gca_guard == 0) {
		return EINVAL;
	}

	struct vnode_attr va;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	int cmode;

	VATTR_INIT(&va);
	cmode = ((uap->mode & ~p->p_fd.fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	    uap->path, ctx);

	return open1(ctx, &nd, uap->flags | O_CLOFORK, &va,
	           guarded_fileproc_init, &crarg, retval, AUTH_OPEN_NOAUTHFD);
}

/*
 * int guarded_open_dprotected_np(const char *pathname, int flags,
 *     const guardid_t *guard, u_int guardflags, int dpclass, int dpflags, ...);
 *
 * This SPI is extension of guarded_open_np() to include dataprotection class on creation
 * in "dpclass" and dataprotection flags 'dpflags'. Otherwise behaviors are same as in
 * guarded_open_np()
 */
int
guarded_open_dprotected_np(proc_t p, struct guarded_open_dprotected_np_args *uap, int32_t *retval)
{
	if ((uap->flags & O_CLOEXEC) == 0) {
		return EINVAL;
	}

	if (((uap->guardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
	    ((uap->guardflags & ~GUARD_ALL) != 0)) {
		return EINVAL;
	}

	int error;
	struct gfp_crarg crarg = {
		.gca_attrs = (uint16_t)uap->guardflags
	};

	if ((error = copyin(uap->guard,
	    &(crarg.gca_guard), sizeof(crarg.gca_guard))) != 0) {
		return error;
	}

	/*
	 * Disallow certain guard values -- is zero enough?
	 */
	if (crarg.gca_guard == 0) {
		return EINVAL;
	}

	struct vnode_attr va;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	int cmode;

	VATTR_INIT(&va);
	cmode = ((uap->mode & ~p->p_fd.fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	    uap->path, ctx);

	/*
	 * Initialize the extra fields in vnode_attr to pass down dataprotection
	 * extra fields.
	 * 1. target cprotect class.
	 * 2. set a flag to mark it as requiring open-raw-encrypted semantics.
	 */
	if (uap->flags & O_CREAT) {
		VATTR_SET(&va, va_dataprotect_class, uap->dpclass);
	}

	if (uap->dpflags & (O_DP_GETRAWENCRYPTED | O_DP_GETRAWUNENCRYPTED)) {
		if (uap->flags & (O_RDWR | O_WRONLY)) {
			/* Not allowed to write raw encrypted bytes */
			return EINVAL;
		}
		if (uap->dpflags & O_DP_GETRAWENCRYPTED) {
			VATTR_SET(&va, va_dataprotect_flags, VA_DP_RAWENCRYPTED);
		}
		if (uap->dpflags & O_DP_GETRAWUNENCRYPTED) {
			VATTR_SET(&va, va_dataprotect_flags, VA_DP_RAWUNENCRYPTED);
		}
	}

	return open1(ctx, &nd, uap->flags | O_CLOFORK, &va,
	           guarded_fileproc_init, &crarg, retval, AUTH_OPEN_NOAUTHFD);
}

/*
 * int guarded_kqueue_np(const guardid_t *guard, u_int guardflags);
 *
 * Create a guarded kqueue descriptor with guardid and guardflags.
 *
 * Same restrictions on guardflags as for guarded_open_np().
 * All kqueues are -always- close-on-exec and close-on-fork by themselves
 * and are not sendable.
 */
int
guarded_kqueue_np(proc_t p, struct guarded_kqueue_np_args *uap, int32_t *retval)
{
	if (((uap->guardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
	    ((uap->guardflags & ~GUARD_ALL) != 0)) {
		return EINVAL;
	}

	int error;
	struct gfp_crarg crarg = {
		.gca_attrs = (uint16_t)uap->guardflags
	};

	if ((error = copyin(uap->guard,
	    &(crarg.gca_guard), sizeof(crarg.gca_guard))) != 0) {
		return error;
	}

	if (crarg.gca_guard == 0) {
		return EINVAL;
	}

	return kqueue_internal(p, guarded_fileproc_init, &crarg, retval);
}

/*
 * int guarded_close_np(int fd, const guardid_t *guard);
 */
int
guarded_close_np(proc_t p, struct guarded_close_np_args *uap,
    __unused int32_t *retval)
{
	struct fileproc *fp;
	int fd = uap->fd;
	int error;
	guardid_t uguard;

	AUDIT_SYSCLOSE(p, fd);

	if ((error = copyin(uap->guard, &uguard, sizeof(uguard))) != 0) {
		return error;
	}

	proc_fdlock(p);
	if ((error = fp_lookup_guarded(p, fd, uguard, &fp, 1)) != 0) {
		proc_fdunlock(p);
		return error;
	}
	fp_drop(p, fd, fp, 1);
	return fp_close_and_unlock(p, fd, fp, 0);
}

/*
 * int
 * change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags,
 *    const guardid_t *nguard, u_int nguardflags, int *fdflagsp);
 *
 * Given a file descriptor, atomically exchange <guard, guardflags> for
 * a new guard <nguard, nguardflags>, returning the previous fd
 * flags (see fcntl:F_SETFD) in *fdflagsp.
 *
 * This syscall can be used to either (a) add a new guard to an existing
 * unguarded file descriptor (b) remove the old guard from an existing
 * guarded file descriptor or (c) change the guard (guardid and/or
 * guardflags) on a guarded file descriptor.
 *
 * If 'guard' is NULL, fd must be unguarded at entry. If the call completes
 * successfully the fd will be guarded with <nguard, nguardflags>.
 *
 * Guarding a file descriptor has some side-effects on the "fp_flags"
 * associated with the descriptor - in particular FD_CLOEXEC is
 * forced ON unconditionally, and FD_CLOFORK is forced ON by GUARD_CLOSE.
 * Callers who wish to subsequently restore the state of the fd should save
 * the value of *fdflagsp after a successful invocation.
 *
 * If 'nguard' is NULL, fd must be guarded at entry, <guard, guardflags>
 * must match with what's already guarding the descriptor, and the
 * result will be to completely remove the guard.
 *
 * If the descriptor is guarded, and neither 'guard' nor 'nguard' is NULL
 * and <guard, guardflags> matches what's already guarding the descriptor,
 * then <nguard, nguardflags> becomes the new guard.  In this case, even if
 * the GUARD_CLOSE flag is being cleared, it is still possible to continue
 * to keep FD_CLOFORK on the descriptor by passing FD_CLOFORK via fdflagsp.
 *
 * (File descriptors whose underlying fileglobs are marked FG_CONFINED are
 * still close-on-fork, regardless of the setting of FD_CLOFORK.)
 *
 * Example 1: Guard an unguarded descriptor during a set of operations,
 * then restore the original state of the descriptor.
 *
 * int sav_flags = 0;
 * change_fdguard_np(fd, NULL, 0, &myguard, GUARD_CLOSE, &sav_flags);
 * // do things with now guarded 'fd'
 * change_fdguard_np(fd, &myguard, GUARD_CLOSE, NULL, 0, &sav_flags);
 * // fd now unguarded.
 *
 * Example 2: Change the guard of a guarded descriptor during a set of
 * operations, then restore the original state of the descriptor.
 *
 * int sav_flags = (gdflags & GUARD_CLOSE) ? FD_CLOFORK : 0;
 * change_fdguard_np(fd, &gd, gdflags, &myguard, GUARD_CLOSE, &sav_flags);
 * // do things with 'fd' with a different guard
 * change_fdguard_np(fd, &myg, GUARD_CLOSE, &gd, gdflags, &sav_flags);
 * // back to original guarded state
 *
 * XXX	This SPI is too much of a chainsaw and should be revised.
 */

int
change_fdguard_np(proc_t p, struct change_fdguard_np_args *uap,
    __unused int32_t *retval)
{
	struct fileproc_guard *fpg = NULL;
	struct fileproc *fp;
	int fd = uap->fd;
	int error;
	guardid_t oldg = 0, newg = 0;
	int nfdflags = 0;

	if (0 != uap->guard &&
	    0 != (error = copyin(uap->guard, &oldg, sizeof(oldg)))) {
		return error; /* can't copyin current guard */
	}
	if (0 != uap->nguard &&
	    0 != (error = copyin(uap->nguard, &newg, sizeof(newg)))) {
		return error; /* can't copyin new guard */
	}
	if (0 != uap->fdflagsp &&
	    0 != (error = copyin(uap->fdflagsp, &nfdflags, sizeof(nfdflags)))) {
		return error; /* can't copyin new fdflags */
	}

	if (oldg == 0 && newg) {
		fpg = guarded_fileproc_alloc(newg);
	}

	proc_fdlock(p);

	if ((error = fp_lookup(p, fd, &fp, 1)) != 0) {
		proc_fdunlock(p);
		return error;
	}

	if (0 != uap->fdflagsp) {
		int ofl = 0;
		if (fp->fp_flags & FP_CLOEXEC) {
			ofl |= FD_CLOEXEC;
		}
		if (fp->fp_flags & FP_CLOFORK) {
			ofl |= FD_CLOFORK;
		}
		proc_fdunlock(p);
		if (0 != (error = copyout(&ofl, uap->fdflagsp, sizeof(ofl)))) {
			proc_fdlock(p);
			goto dropout; /* can't copyout old fdflags */
		}
		proc_fdlock(p);
	}

	if (fp->fp_guard_attrs) {
		if (0 == uap->guard || 0 == uap->guardflags) {
			error = EINVAL; /* missing guard! */
		} else if (0 == oldg) {
			error = EPERM; /* guardids cannot be zero */
		}
	} else {
		if (0 != uap->guard || 0 != uap->guardflags) {
			error = EINVAL; /* guard provided, but none needed! */
		}
	}

	if (0 != error) {
		goto dropout;
	}

	if (0 != uap->nguard) {
		/*
		 * There's a new guard in town.
		 */
		if (0 == newg) {
			error = EINVAL; /* guards cannot contain zero */
		} else if (((uap->nguardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
		    ((uap->nguardflags & ~GUARD_ALL) != 0)) {
			error = EINVAL; /* must have valid attributes too */
		}
		if (0 != error) {
			goto dropout;
		}

		if (fp->fp_guard_attrs) {
			/*
			 * Replace old guard with new guard
			 */
			if (oldg == fp->fp_guard->fpg_guard &&
			    uap->guardflags == fp->fp_guard_attrs) {
				/*
				 * Must match existing guard + attributes
				 * before we'll swap them to new ones, managing
				 * fdflags "side-effects" as we go.   Note that
				 * userland can request FD_CLOFORK semantics.
				 */
				if (fp->fp_guard_attrs & GUARD_CLOSE) {
					fp->fp_flags &= ~FP_CLOFORK;
				}
				fp->fp_guard->fpg_guard = newg;
				fp->fp_guard_attrs = (uint16_t)uap->nguardflags;
				if ((fp->fp_guard_attrs & GUARD_CLOSE) ||
				    (nfdflags & FD_CLOFORK)) {
					fp->fp_flags |= FP_CLOFORK;
				}
				/* FG_CONFINED enforced regardless */
			} else {
				error = EPERM;
			}
		} else {
			/*
			 * Add a guard to a previously unguarded descriptor
			 */
			switch (FILEGLOB_DTYPE(fp->fp_glob)) {
			case DTYPE_VNODE:
			case DTYPE_PIPE:
			case DTYPE_SOCKET:
			case DTYPE_KQUEUE:
			case DTYPE_NETPOLICY:
				break;
			default:
				error = ENOTSUP;
				goto dropout;
			}

			fp->fp_guard_attrs = (uint16_t)uap->nguardflags;
			fpg->fpg_wset = fp->fp_wset;
			fp->fp_guard = fpg;
			fpg = NULL;
			if (fp->fp_guard_attrs & GUARD_CLOSE) {
				fp->fp_flags |= FP_CLOFORK;
			}
			fp->fp_flags |= FP_CLOEXEC;
		}
	} else {
		if (fp->fp_guard_attrs) {
			/*
			 * Remove the guard altogether.
			 */
			if (0 != uap->nguardflags) {
				error = EINVAL;
				goto dropout;
			}

			if (oldg != fp->fp_guard->fpg_guard ||
			    uap->guardflags != fp->fp_guard_attrs) {
				error = EPERM;
				goto dropout;
			}

			assert(fpg == NULL);
			fp->fp_guard_attrs = 0;
			fpg = fp->fp_guard;
			fp->fp_wset = fpg->fpg_wset;

			fp->fp_flags &= ~(FP_CLOEXEC | FP_CLOFORK);
			if (nfdflags & FD_CLOFORK) {
				fp->fp_flags |= FP_CLOFORK;
			}
			if (nfdflags & FD_CLOEXEC) {
				fp->fp_flags |= FP_CLOEXEC;
			}
		} else {
			/*
			 * Not already guarded, and no new guard?
			 */
			error = EINVAL;
		}
	}

dropout:
	(void) fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

	if (fpg) {
		zfree(fp_guard_zone, fpg);
	}
	return error;
}

/*
 * user_ssize_t guarded_write_np(int fd, const guardid_t *guard,
 *                          user_addr_t cbuf, user_ssize_t nbyte);
 *
 * Initial implementation of guarded writes.
 */
int
guarded_write_np(struct proc *p, struct guarded_write_np_args *uap, user_ssize_t *retval)
{
	int error;
	guardid_t uguard;

	AUDIT_ARG(fd, uap->fd);

	if ((error = copyin(uap->guard, &uguard, sizeof(uguard))) != 0) {
		return error;
	}

	return write_internal(p, uap->fd, uap->cbuf, uap->nbyte, 0, 0, &uguard, retval);
}

/*
 * user_ssize_t guarded_pwrite_np(int fd, const guardid_t *guard,
 *                        user_addr_t buf, user_size_t nbyte, off_t offset);
 *
 * Initial implementation of guarded pwrites.
 */
int
guarded_pwrite_np(struct proc *p, struct guarded_pwrite_np_args *uap, user_ssize_t *retval)
{
	int error;
	guardid_t uguard;

	AUDIT_ARG(fd, uap->fd);

	if ((error = copyin(uap->guard, &uguard, sizeof(uguard))) != 0) {
		return error;
	}

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_guarded_pwrite_np) | DBG_FUNC_NONE),
	    uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);

	return write_internal(p, uap->fd, uap->buf, uap->nbyte, uap->offset, FOF_OFFSET,
	           &uguard, retval);
}

/*
 * user_ssize_t guarded_writev_np(int fd, const guardid_t *guard,
 *                                   struct iovec *iovp, u_int iovcnt);
 *
 * Initial implementation of guarded writev.
 *
 */
int
guarded_writev_np(struct proc *p, struct guarded_writev_np_args *uap, user_ssize_t *retval)
{
	int error;
	guardid_t uguard;

	AUDIT_ARG(fd, uap->fd);

	if ((error = copyin(uap->guard, &uguard, sizeof(uguard))) != 0) {
		return error;
	}

	return writev_uio(p, uap->fd, uap->iovp, uap->iovcnt, 0, 0, &uguard, retval);
}

/*
 * int falloc_guarded(struct proc *p, struct fileproc **fp, int *fd,
 *     vfs_context_t ctx, const guardid_t *guard, u_int attrs);
 *
 * This SPI is the guarded variant of falloc().  It borrows the same
 * restrictions as those used by the rest of the guarded_* routines.
 */
int
falloc_guarded(struct proc *p, struct fileproc **fp, int *fd,
    vfs_context_t ctx, const guardid_t *guard, u_int attrs)
{
	struct gfp_crarg crarg;

	if (((attrs & GUARD_REQUIRED) != GUARD_REQUIRED) ||
	    ((attrs & ~GUARD_ALL) != 0) || (*guard == 0)) {
		return EINVAL;
	}

	bzero(&crarg, sizeof(crarg));
	crarg.gca_guard = *guard;
	crarg.gca_attrs = (uint16_t)attrs;

	return falloc_withinit(p, fp, fd, ctx, guarded_fileproc_init, &crarg);
}

#if CONFIG_MACF && CONFIG_VNGUARD

/*
 * Guarded vnodes
 *
 * Uses MAC hooks to guard operations on vnodes in the system. Given an fd,
 * add data to the label on the fileglob and the vnode it points at.
 * The data contains a pointer to the fileglob, the set of attributes to
 * guard, a guard value for uniquification, and the pid of the process
 * who set the guard up in the first place.
 *
 * The fd must have been opened read/write, and the underlying
 * fileglob is FG_CONFINED so that there's no ambiguity about the
 * owning process.
 *
 * When there's a callback for a vnode operation of interest (rename, unlink,
 * etc.) check to see if the guard permits that operation, and if not
 * take an action e.g. log a message or generate a crash report.
 *
 * The label is removed from the vnode and the fileglob when the fileglob
 * is closed.
 *
 * The initial action to be taken can be specified by a boot arg (vnguard=0x42)
 * and change via the "kern.vnguard.flags" sysctl.
 */

struct vng_owner;

struct vng_info { /* lives on the vnode label */
	guardid_t vgi_guard;
	unsigned vgi_attrs;
	TAILQ_HEAD(, vng_owner) vgi_owners;
};

struct vng_owner { /* lives on the fileglob label */
	proc_t vgo_p;
	struct vng_info *vgo_vgi;
	TAILQ_ENTRY(vng_owner) vgo_link;
};

static struct vng_info *
new_vgi(unsigned attrs, guardid_t guard)
{
	struct vng_info *vgi = kalloc_type(struct vng_info, Z_WAITOK);
	vgi->vgi_guard = guard;
	vgi->vgi_attrs = attrs;
	TAILQ_INIT(&vgi->vgi_owners);
	return vgi;
}

static struct vng_owner *
new_vgo(proc_t p)
{
	struct vng_owner *vgo = kalloc_type(struct vng_owner, Z_WAITOK | Z_ZERO);
	vgo->vgo_p = p;
	return vgo;
}

static void
vgi_add_vgo(struct vng_info *vgi, struct vng_owner *vgo)
{
	vgo->vgo_vgi = vgi;
	TAILQ_INSERT_HEAD(&vgi->vgi_owners, vgo, vgo_link);
}

static boolean_t
vgi_remove_vgo(struct vng_info *vgi, struct vng_owner *vgo)
{
	TAILQ_REMOVE(&vgi->vgi_owners, vgo, vgo_link);
	vgo->vgo_vgi = NULL;
	return TAILQ_EMPTY(&vgi->vgi_owners);
}

static void
free_vgi(struct vng_info *vgi)
{
	assert(TAILQ_EMPTY(&vgi->vgi_owners));
#if DEVELOP || DEBUG
	memset(vgi, 0xbeadfade, sizeof(*vgi));
#endif
	kfree_type(struct vng_info, vgi);
}

static void
free_vgo(struct vng_owner *vgo)
{
#if DEVELOP || DEBUG
	memset(vgo, 0x2bedf1d0, sizeof(*vgo));
#endif
	kfree_type(struct vng_owner, vgo);
}

static int label_slot;
static LCK_GRP_DECLARE(llock_grp, VNG_POLICY_NAME);
static LCK_RW_DECLARE(llock, &llock_grp);

static __inline void *
vng_lbl_get(struct label *label)
{
	lck_rw_assert(&llock, LCK_RW_ASSERT_HELD);
	void *data;
	if (NULL == label) {
		data = NULL;
	} else {
		data = (void *)mac_label_get(label, label_slot);
	}
	return data;
}

static __inline struct vng_info *
vng_lbl_get_withattr(struct label *label, unsigned attrmask)
{
	struct vng_info *vgi = vng_lbl_get(label);
	assert(NULL == vgi || (vgi->vgi_attrs & ~VNG_ALL) == 0);
	if (NULL != vgi && 0 == (vgi->vgi_attrs & attrmask)) {
		vgi = NULL;
	}
	return vgi;
}

static __inline void
vng_lbl_set(struct label *label, void *data)
{
	assert(NULL != label);
	lck_rw_assert(&llock, LCK_RW_ASSERT_EXCLUSIVE);
	mac_label_set(label, label_slot, (intptr_t)data);
}

static int
vnguard_sysc_getguardattr(proc_t p, struct vnguard_getattr *vga)
{
	const int fd = vga->vga_fd;

	if (0 == vga->vga_guard) {
		return EINVAL;
	}

	int error;
	struct fileproc *fp;
	if (0 != (error = fp_lookup(p, fd, &fp, 0))) {
		return error;
	}
	do {
		struct fileglob *fg = fp->fp_glob;
		if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
			error = EBADF;
			break;
		}
		struct vnode *vp = fg_get_data(fg);
		if (!vnode_isreg(vp) || NULL == vp->v_mount) {
			error = EBADF;
			break;
		}
		error = vnode_getwithref(vp);
		if (0 != error) {
			break;
		}

		vga->vga_attrs = 0;

		lck_rw_lock_shared(&llock);

		if (NULL != mac_vnode_label(vp)) {
			const struct vng_info *vgi = vng_lbl_get(mac_vnode_label(vp));
			if (NULL != vgi) {
				if (vgi->vgi_guard != vga->vga_guard) {
					error = EPERM;
				} else {
					vga->vga_attrs = vgi->vgi_attrs;
				}
			}
		}

		lck_rw_unlock_shared(&llock);
		vnode_put(vp);
	} while (0);

	fp_drop(p, fd, fp, 0);
	return error;
}

static int
vnguard_sysc_setguard(proc_t p, const struct vnguard_set *vns)
{
	const int fd = vns->vns_fd;

	if ((vns->vns_attrs & ~VNG_ALL) != 0 ||
	    0 == vns->vns_attrs || 0 == vns->vns_guard) {
		return EINVAL;
	}

	int error;
	struct fileproc *fp;
	if (0 != (error = fp_lookup(p, fd, &fp, 0))) {
		return error;
	}
	do {
		/*
		 * To avoid trivial DoS, insist that the caller
		 * has read/write access to the file.
		 */
		if ((FREAD | FWRITE) != (fp->f_flag & (FREAD | FWRITE))) {
			error = EBADF;
			break;
		}
		struct fileglob *fg = fp->fp_glob;
		if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
			error = EBADF;
			break;
		}
		/*
		 * Confinement means there's only one fd pointing at
		 * this fileglob, and will always be associated with
		 * this pid.
		 */
		if (0 == (FG_CONFINED & fg->fg_lflags)) {
			error = EBADF;
			break;
		}
		struct vnode *vp = fg_get_data(fg);
		if (!vnode_isreg(vp) || NULL == vp->v_mount) {
			error = EBADF;
			break;
		}
		error = vnode_getwithref(vp);
		if (0 != error) {
			break;
		}

		/* Ensure the target vnode -has- a label */
		struct vfs_context *ctx = vfs_context_current();
		mac_vnode_label_update(ctx, vp, NULL);

		struct vng_info *nvgi = new_vgi(vns->vns_attrs, vns->vns_guard);
		struct vng_owner *nvgo = new_vgo(p);

		lck_rw_lock_exclusive(&llock);

		do {
			/*
			 * A vnode guard is associated with one or more
			 * fileglobs in one or more processes.
			 */
			struct vng_info *vgi = vng_lbl_get(mac_vnode_label(vp));
			struct vng_owner *vgo = fg->fg_vgo;

			if (NULL == vgi) {
				/* vnode unguarded, add the first guard */
				if (NULL != vgo) {
					panic("vnguard label on fileglob "
					    "but not vnode");
				}
				/* add a kusecount so we can unlabel later */
				error = vnode_ref_ext(vp, O_EVTONLY, 0);
				if (0 == error) {
					/* add the guard */
					vgi_add_vgo(nvgi, nvgo);
					vng_lbl_set(mac_vnode_label(vp), nvgi);
					fg->fg_vgo = nvgo;
				} else {
					free_vgo(nvgo);
					free_vgi(nvgi);
				}
			} else {
				/* vnode already guarded */
				free_vgi(nvgi);
				if (vgi->vgi_guard != vns->vns_guard) {
					error = EPERM; /* guard mismatch */
				} else if (vgi->vgi_attrs != vns->vns_attrs) {
					/*
					 * Temporary workaround for older versions of SQLite:
					 * allow newer guard attributes to be silently cleared.
					 */
					const unsigned mask = ~(VNG_WRITE_OTHER | VNG_TRUNC_OTHER);
					if ((vgi->vgi_attrs & mask) == (vns->vns_attrs & mask)) {
						vgi->vgi_attrs &= vns->vns_attrs;
					} else {
						error = EACCES; /* attr mismatch */
					}
				}
				if (0 != error || NULL != vgo) {
					free_vgo(nvgo);
					break;
				}
				/* record shared ownership */
				vgi_add_vgo(vgi, nvgo);
				fg->fg_vgo = nvgo;
			}
		} while (0);

		lck_rw_unlock_exclusive(&llock);
		vnode_put(vp);
	} while (0);

	fp_drop(p, fd, fp, 0);
	return error;
}

static int
vng_policy_syscall(proc_t p, int cmd, user_addr_t arg)
{
	int error = EINVAL;

	switch (cmd) {
	case VNG_SYSC_PING:
		if (0 == arg) {
			error = 0;
		}
		break;
	case VNG_SYSC_SET_GUARD: {
		struct vnguard_set vns;
		error = copyin(arg, (void *)&vns, sizeof(vns));
		if (error) {
			break;
		}
		error = vnguard_sysc_setguard(p, &vns);
		break;
	}
	case VNG_SYSC_GET_ATTR: {
		struct vnguard_getattr vga;
		error = copyin(arg, (void *)&vga, sizeof(vga));
		if (error) {
			break;
		}
		error = vnguard_sysc_getguardattr(p, &vga);
		if (error) {
			break;
		}
		error = copyout((void *)&vga, arg, sizeof(vga));
		break;
	}
	default:
		break;
	}
	return error;
}

/*
 * This is called just before the fileglob disappears in fg_free().
 * Take the exclusive lock: no other thread can add or remove
 * a vng_info to any vnode in the system.
 */
void
vng_file_label_destroy(struct fileglob *fg)
{
	struct vng_owner *lvgo = fg->fg_vgo;
	struct vng_info *vgi = NULL;

	if (lvgo) {
		lck_rw_lock_exclusive(&llock);
		fg->fg_vgo = NULL;
		vgi = lvgo->vgo_vgi;
		assert(vgi);
		if (vgi_remove_vgo(vgi, lvgo)) {
			/* that was the last reference */
			vgi->vgi_attrs = 0;
			if (DTYPE_VNODE == FILEGLOB_DTYPE(fg)) {
				struct vnode *vp = fg_get_data(fg);
				int error = vnode_getwithref(vp);
				if (0 == error) {
					vng_lbl_set(mac_vnode_label(vp), 0);
					lck_rw_unlock_exclusive(&llock);
					/* may trigger VNOP_INACTIVE */
					vnode_rele_ext(vp, O_EVTONLY, 0);
					vnode_put(vp);
					free_vgi(vgi);
					free_vgo(lvgo);
					return;
				}
			}
		}
		lck_rw_unlock_exclusive(&llock);
		free_vgo(lvgo);
	}
}

static os_reason_t
vng_reason_from_pathname(const char *path, uint32_t pathlen)
{
	os_reason_t r = os_reason_create(OS_REASON_GUARD, GUARD_REASON_VNODE);
	if (NULL == r) {
		return r;
	}
	/*
	 * If the pathname is very long, just keep the trailing part
	 */
	const uint32_t pathmax = 3 * EXIT_REASON_USER_DESC_MAX_LEN / 4;
	if (pathlen > pathmax) {
		path += (pathlen - pathmax);
		pathlen = pathmax;
	}
	uint32_t rsize = kcdata_estimate_required_buffer_size(1, pathlen);
	if (0 == os_reason_alloc_buffer(r, rsize)) {
		struct kcdata_descriptor *kcd = &r->osr_kcd_descriptor;
		mach_vm_address_t addr;
		if (kcdata_get_memory_addr(kcd,
		    EXIT_REASON_USER_DESC, pathlen, &addr) == KERN_SUCCESS) {
			kcdata_memcpy(kcd, addr, path, pathlen);
			return r;
		}
	}
	os_reason_free(r);
	return OS_REASON_NULL;
}

static int vng_policy_flags;

/*
 * Note: if an EXC_GUARD is generated, llock will be dropped and
 * subsequently reacquired by this routine. Data derived from
 * any label in the caller should be regenerated.
 */
static int
vng_guard_violation(const struct vng_info *vgi,
    unsigned opval, vnode_t vp)
{
	int retval = 0;

	if (vng_policy_flags & kVNG_POLICY_EPERM) {
		/* deny the operation */
		retval = EPERM;
	}

	if (vng_policy_flags & (kVNG_POLICY_LOGMSG | kVNG_POLICY_UPRINTMSG)) {
		/* log a message */
		const char *op;
		switch (opval) {
		case VNG_RENAME_FROM:
			op = "rename-from";
			break;
		case VNG_RENAME_TO:
			op = "rename-to";
			break;
		case VNG_UNLINK:
			op = "unlink";
			break;
		case VNG_LINK:
			op = "link";
			break;
		case VNG_EXCHDATA:
			op = "exchdata";
			break;
		case VNG_WRITE_OTHER:
			op = "write";
			break;
		case VNG_TRUNC_OTHER:
			op = "truncate";
			break;
		default:
			op = "(unknown)";
			break;
		}

		const char *nm = vnode_getname(vp);
		proc_t p = current_proc();
		const struct vng_owner *vgo;
		TAILQ_FOREACH(vgo, &vgi->vgi_owners, vgo_link) {
			const char fmt[] =
			    "%s[%d]: %s%s: '%s' guarded by %s[%d] (0x%llx)\n";

			if (vng_policy_flags & kVNG_POLICY_LOGMSG) {
				printf(fmt,
				    proc_name_address(p), proc_pid(p), op,
				    0 != retval ? " denied" : "",
				    NULL != nm ? nm : "(unknown)",
				    proc_name_address(vgo->vgo_p),
				    proc_pid(vgo->vgo_p), vgi->vgi_guard);
			}
			if (vng_policy_flags & kVNG_POLICY_UPRINTMSG) {
				uprintf(fmt,
				    proc_name_address(p), proc_pid(p), op,
				    0 != retval ? " denied" : "",
				    NULL != nm ? nm : "(unknown)",
				    proc_name_address(vgo->vgo_p),
				    proc_pid(vgo->vgo_p), vgi->vgi_guard);
			}
		}
		if (NULL != nm) {
			vnode_putname(nm);
		}
	}

	if (vng_policy_flags & (kVNG_POLICY_EXC | kVNG_POLICY_EXC_CORPSE)) {
		/* EXC_GUARD exception */
		const struct vng_owner *vgo = TAILQ_FIRST(&vgi->vgi_owners);
		pid_t pid = vgo ? proc_pid(vgo->vgo_p) : 0;
		mach_exception_code_t code;
		mach_exception_subcode_t subcode;

		code = 0;
		EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_VN);
		EXC_GUARD_ENCODE_FLAVOR(code, opval);
		EXC_GUARD_ENCODE_TARGET(code, pid);
		subcode = vgi->vgi_guard;

		lck_rw_unlock_shared(&llock);

		if (vng_policy_flags & kVNG_POLICY_EXC_CORPSE) {
			char *path;
			int len = MAXPATHLEN;

			path = zalloc_flags(ZV_NAMEI, Z_WAITOK | Z_NOFAIL);

			os_reason_t r = NULL;
			vn_getpath(vp, path, &len);
			if (*path && len) {
				r = vng_reason_from_pathname(path, len);
			}
			task_violated_guard(code, subcode, r, TRUE); /* not fatal */
			if (NULL != r) {
				os_reason_free(r);
			}

			zfree(ZV_NAMEI, path);
		} else {
			thread_t t = current_thread();
			thread_guard_violation(t, code, subcode, TRUE);
		}

		lck_rw_lock_shared(&llock);
	} else if (vng_policy_flags & kVNG_POLICY_SIGKILL) {
		proc_t p = current_proc();
		psignal(p, SIGKILL);
	}

	return retval;
}

/*
 * A fatal vnode guard was tripped on this thread.
 *
 * (Invoked before returning to userland from the syscall handler.)
 */
void
vn_guard_ast(thread_t __unused t,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode)
{
	/*
	 * Check if anyone has registered for Synchronous EXC_GUARD, if yes then,
	 * deliver it synchronously and then kill the process, else kill the process
	 * and deliver the exception via EXC_CORPSE_NOTIFY.
	 */
	if (task_exception_notify(EXC_GUARD, code, subcode) == KERN_SUCCESS) {
		psignal(current_proc(), SIGKILL);
	} else {
		exit_with_guard_exception(current_proc(), code, subcode);
	}
}

/*
 * vnode callbacks
 */

static int
vng_vnode_check_rename(kauth_cred_t __unused cred,
    struct vnode *__unused dvp, struct label *__unused dlabel,
    struct vnode *vp, struct label *label,
    struct componentname *__unused cnp,
    struct vnode *__unused tdvp, struct label *__unused tdlabel,
    struct vnode *tvp, struct label *tlabel,
    struct componentname *__unused tcnp)
{
	int error = 0;
	if (NULL != label || NULL != tlabel) {
		lck_rw_lock_shared(&llock);
		const struct vng_info *vgi =
		    vng_lbl_get_withattr(label, VNG_RENAME_FROM);
		if (NULL != vgi) {
			error = vng_guard_violation(vgi, VNG_RENAME_FROM, vp);
		}
		if (0 == error) {
			vgi = vng_lbl_get_withattr(tlabel, VNG_RENAME_TO);
			if (NULL != vgi) {
				error = vng_guard_violation(vgi,
				    VNG_RENAME_TO, tvp);
			}
		}
		lck_rw_unlock_shared(&llock);
	}
	return error;
}

static int
vng_vnode_check_link(kauth_cred_t __unused cred,
    struct vnode *__unused dvp, struct label *__unused dlabel,
    struct vnode *vp, struct label *label, struct componentname *__unused cnp)
{
	int error = 0;
	if (NULL != label) {
		lck_rw_lock_shared(&llock);
		const struct vng_info *vgi =
		    vng_lbl_get_withattr(label, VNG_LINK);
		if (vgi) {
			error = vng_guard_violation(vgi, VNG_LINK, vp);
		}
		lck_rw_unlock_shared(&llock);
	}
	return error;
}

static int
vng_vnode_check_unlink(kauth_cred_t __unused cred,
    struct vnode *__unused dvp, struct label *__unused dlabel,
    struct vnode *vp, struct label *label, struct componentname *__unused cnp)
{
	int error = 0;
	if (NULL != label) {
		lck_rw_lock_shared(&llock);
		const struct vng_info *vgi =
		    vng_lbl_get_withattr(label, VNG_UNLINK);
		if (vgi) {
			error = vng_guard_violation(vgi, VNG_UNLINK, vp);
		}
		lck_rw_unlock_shared(&llock);
	}
	return error;
}

/*
 * Only check violations for writes performed by "other processes"
 */
static int
vng_vnode_check_write(kauth_cred_t __unused actv_cred,
    kauth_cred_t __unused file_cred, struct vnode *vp, struct label *label)
{
	int error = 0;
	if (NULL != label) {
		lck_rw_lock_shared(&llock);
		const struct vng_info *vgi =
		    vng_lbl_get_withattr(label, VNG_WRITE_OTHER);
		if (vgi) {
			proc_t p = current_proc();
			const struct vng_owner *vgo;
			TAILQ_FOREACH(vgo, &vgi->vgi_owners, vgo_link) {
				if (vgo->vgo_p == p) {
					goto done;
				}
			}
			error = vng_guard_violation(vgi, VNG_WRITE_OTHER, vp);
		}
done:
		lck_rw_unlock_shared(&llock);
	}
	return error;
}

/*
 * Only check violations for truncates performed by "other processes"
 */
static int
vng_vnode_check_truncate(kauth_cred_t __unused actv_cred,
    kauth_cred_t __unused file_cred, struct vnode *vp,
    struct label *label)
{
	int error = 0;
	if (NULL != label) {
		lck_rw_lock_shared(&llock);
		const struct vng_info *vgi =
		    vng_lbl_get_withattr(label, VNG_TRUNC_OTHER);
		if (vgi) {
			proc_t p = current_proc();
			const struct vng_owner *vgo;
			TAILQ_FOREACH(vgo, &vgi->vgi_owners, vgo_link) {
				if (vgo->vgo_p == p) {
					goto done;
				}
			}
			error = vng_guard_violation(vgi, VNG_TRUNC_OTHER, vp);
		}
done:
		lck_rw_unlock_shared(&llock);
	}
	return error;
}

static int
vng_vnode_check_exchangedata(kauth_cred_t __unused cred,
    struct vnode *fvp, struct label *flabel,
    struct vnode *svp, struct label *slabel)
{
	int error = 0;
	if (NULL != flabel || NULL != slabel) {
		lck_rw_lock_shared(&llock);
		const struct vng_info *vgi =
		    vng_lbl_get_withattr(flabel, VNG_EXCHDATA);
		if (NULL != vgi) {
			error = vng_guard_violation(vgi, VNG_EXCHDATA, fvp);
		}
		if (0 == error) {
			vgi = vng_lbl_get_withattr(slabel, VNG_EXCHDATA);
			if (NULL != vgi) {
				error = vng_guard_violation(vgi,
				    VNG_EXCHDATA, svp);
			}
		}
		lck_rw_unlock_shared(&llock);
	}
	return error;
}

/* Intercept open-time truncations (by "other") of a guarded vnode */

static int
vng_vnode_check_open(kauth_cred_t cred,
    struct vnode *vp, struct label *label, int acc_mode)
{
	if (0 == (acc_mode & O_TRUNC)) {
		return 0;
	}
	return vng_vnode_check_truncate(cred, NULL, vp, label);
}

/*
 * Configuration gorp
 */

SECURITY_READ_ONLY_EARLY(static struct mac_policy_ops) vng_policy_ops = {
	.mpo_vnode_check_link = vng_vnode_check_link,
	.mpo_vnode_check_unlink = vng_vnode_check_unlink,
	.mpo_vnode_check_rename = vng_vnode_check_rename,
	.mpo_vnode_check_write = vng_vnode_check_write,
	.mpo_vnode_check_truncate = vng_vnode_check_truncate,
	.mpo_vnode_check_exchangedata = vng_vnode_check_exchangedata,
	.mpo_vnode_check_open = vng_vnode_check_open,

	.mpo_policy_syscall = vng_policy_syscall,
};

static const char *vng_labelnames[] = {
	"vnguard",
};

#define ACOUNT(arr) ((unsigned)(sizeof (arr) / sizeof (arr[0])))

SECURITY_READ_ONLY_LATE(static struct mac_policy_conf) vng_policy_conf = {
	.mpc_name = VNG_POLICY_NAME,
	.mpc_fullname = "Guarded vnode policy",
	.mpc_field_off = &label_slot,
	.mpc_labelnames = vng_labelnames,
	.mpc_labelname_count = ACOUNT(vng_labelnames),
	.mpc_ops = &vng_policy_ops,
	.mpc_loadtime_flags = 0,
	.mpc_runtime_flags = 0
};

SECURITY_READ_ONLY_LATE(static mac_policy_handle_t) vng_policy_handle;

void
vnguard_policy_init(void)
{
	if (0 == PE_i_can_has_debugger(NULL)) {
		return;
	}
	vng_policy_flags = kVNG_POLICY_LOGMSG |
	    kVNG_POLICY_EXC_CORPSE | kVNG_POLICY_UPRINTMSG;
	PE_parse_boot_argn("vnguard", &vng_policy_flags, sizeof(vng_policy_flags));
	if (vng_policy_flags) {
		mac_policy_register(&vng_policy_conf, &vng_policy_handle, NULL);
	}
}

#if DEBUG || DEVELOPMENT
#include <sys/sysctl.h>

SYSCTL_DECL(_kern_vnguard);
SYSCTL_NODE(_kern, OID_AUTO, vnguard, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "vnguard");
SYSCTL_INT(_kern_vnguard, OID_AUTO, flags, CTLFLAG_RW | CTLFLAG_LOCKED,
    &vng_policy_flags, 0, "vnguard policy flags");
#endif

#endif /* CONFIG_MACF && CONFIG_VNGUARD */
