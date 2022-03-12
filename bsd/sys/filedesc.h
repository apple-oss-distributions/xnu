/*
 * Copyright (c) 2000-2012 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1990, 1993
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
 *	@(#)filedesc.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _SYS_FILEDESC_H_
#define _SYS_FILEDESC_H_

#include <sys/appleapiopts.h>

/*
 * This structure is used for the management of descriptors.  It may be
 * shared by multiple processes.
 *
 * A process is initially started out with NDFILE descriptors [XXXstored within
 * this structureXXX], selected to be enough for typical applications based on
 * the historical limit of 20 open files (and the usage of descriptors by
 * shells).  If these descriptors are exhausted, a larger descriptor table
 * may be allocated, up to a process' resource limit; [XXXthe internal arrays
 * are then unusedXXX].  The initial expansion is set to NDEXTENT; each time
 * it runs out, it is doubled until the resource limit is reached. NDEXTENT
 * should be selected to be the biggest multiple of OFILESIZE (see below)
 * that will fit in a power-of-two sized piece of memory.
 */
#define NDFILE          25              /* 125 bytes */
#define NDEXTENT        50              /* 250 bytes in 256-byte alloc. */

#ifdef XNU_KERNEL_PRIVATE

#include <sys/kernel_types.h>
#include <kern/locks.h>

struct klist;
struct kqwllist;

__options_decl(filedesc_flags_t, uint8_t, {
	/*
	 * process was chrooted... keep track even
	 * if we're force unmounted and unable to
	 * take a vnode_ref on fd_rdir during a fork
	 */
	FD_CHROOT                     = 0x01,

	/*
	 * process has created a kqworkloop that
	 * requires manual cleanup on exit
	 */
	FD_WORKLOOP                   = 0x02,

#if CONFIG_PROC_RESOURCE_LIMITS
	/* process has exceeded fd_nfiles soft limit */
	FD_ABOVE_SOFT_LIMIT           = 0x04,
	/* process has exceeded fd_nfiles hard limit */
	FD_ABOVE_HARD_LIMIT           = 0x08,

	/* fd_nfiles soft limit notification has already been sent */
	FD_SOFT_LIMIT_NOTIFIED        = 0x10,
	/* fd_nfiles hard limit notification has already been sent */
	FD_HARD_LIMIT_NOTIFIED        = 0x20,
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
});

#define FILEDESC_FORK_INHERITED_MASK (FD_CHROOT)

struct filedesc {
	lck_mtx_t           fd_lock;        /* (L) lock to protect fdesc */
	uint8_t             fd_fpdrainwait; /* (L) has drain waiters */
	filedesc_flags_t    fd_flags;       /* (L) filedesc flags */
	u_short             fd_cmask;       /* (L) mask for file creation */
	int                 fd_nfiles;      /* (L) number of open fdesc slots allocated */
	int                 fd_afterlast;   /* (L) high-water mark of fd_ofiles */
	int                 fd_freefile;    /* (L) approx. next free file */
#if CONFIG_PROC_RESOURCE_LIMITS
	int                 fd_nfiles_open;
	int                 fd_nfiles_soft_limit;   /* (L) fd_nfiles soft limit to trigger guard */
	int                 fd_nfiles_hard_limit;   /* (L) fd_nfiles hard limit to terminate */
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

	struct fileproc   **XNU_PTRAUTH_SIGNED_PTR("filedesc.fd_ofiles") fd_ofiles; /* (L) file structures for open files */
	char               *fd_ofileflags;  /* (L) per-process open file flags */

	int                 fd_knlistsize;  /* (L) size of knlist */
	struct  klist      *fd_knlist;      /* (L) list of attached knotes */

	struct  kqworkq    *fd_wqkqueue;    /* (L) the workq kqueue */
	struct  vnode      *fd_cdir;        /* (L) current directory */
	struct  vnode      *fd_rdir;        /* (L) root directory */
	lck_rw_t            fd_dirs_lock;   /* keeps fd_cdir and fd_rdir stable across a lookup */

	lck_mtx_t           fd_kqhashlock;  /* (Q) lock for dynamic kqueue hash */
	u_long              fd_kqhashmask;  /* (Q) size of dynamic kqueue hash */
	struct  kqwllist   *fd_kqhash;      /* (Q) hash table for dynamic kqueues */

	lck_mtx_t           fd_knhashlock;  /* (N) lock for hash table for attached knotes */
	u_long              fd_knhashmask;  /* (N) size of knhash */
	struct  klist      *fd_knhash;      /* (N) hash table for attached knotes */
};

#define fdt_flag_test(fdt, flag)        (((fdt)->fd_flags & (flag)) != 0)
#define fdt_flag_set(fdt, flag)         ((void)((fdt)->fd_flags |= (flag)))
#define fdt_flag_clear(fdt, flag)       ((void)((fdt)->fd_flags &= ~(flag)))

#if CONFIG_PROC_RESOURCE_LIMITS
#define fd_above_soft_limit_notify(fdp)                 fdt_flag_test(fdp, FD_ABOVE_SOFT_LIMIT)
#define fd_above_hard_limit_notify(fdp)                 fdt_flag_test(fdp, FD_ABOVE_HARD_LIMIT)
#define fd_above_soft_limit_send_notification(fdp)      fdt_flag_set(fdp, FD_ABOVE_SOFT_LIMIT)
#define fd_above_hard_limit_send_notification(fdp)      fdt_flag_set(fdp, FD_ABOVE_HARD_LIMIT)
#define fd_soft_limit_already_notified(fdp)             fdt_flag_test(fdp, FD_SOFT_LIMIT_NOTIFIED)
#define fd_soft_limit_notified(fdp)                     fdt_flag_set(fdp, FD_SOFT_LIMIT_NOTIFIED)
#define fd_hard_limit_already_notified(fdp)             fdt_flag_test(fdp, FD_HARD_LIMIT_NOTIFIED)
#define fd_hard_limit_notified(fdp)                     fdt_flag_set(fdp, FD_HARD_LIMIT_NOTIFIED)
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

/*
 * Per-process open flags.
 */
#define UF_RESERVED     0x04            /* open pending / in progress */
#define UF_CLOSING      0x08            /* close in progress */
#define UF_RESVWAIT     0x10            /* close in progress */
#define UF_INHERIT      0x20            /* "inherit-on-exec" */

/*
 * Storage required per open file descriptor.
 */
#define OFILESIZE (sizeof(struct file *) + sizeof(char))

/*!
 * @function fdt_available
 *
 * @brief
 * Returns whether the file descritor table can accomodate
 * for @c n new entries.
 *
 * @discussion
 * The answer is only valid so long as the @c proc_fdlock() is held by the
 * caller.
 */
extern bool
fdt_available_locked(proc_t p, int n);

/*!
 * @struct fdt_iterator
 *
 * @brief
 * Type used to iterate a file descriptor table.
 */
struct fdt_iterator {
	int              fdti_fd;
	struct fileproc *fdti_fp;
};

/*!
 * @function fdt_next
 *
 * @brief
 * Seek the iterator forward.
 *
 * @discussion
 * The @c proc_fdlock() should be held by the caller.
 *
 * @param p
 * The process for which the file descriptor table is being iterated.
 *
 * @param fd
 * The current file file descriptor to scan from (exclusive).
 *
 * @param only_settled
 * When true, only fileprocs with @c UF_RESERVED set are returned.
 * If false, fileprocs that are in flux (@c UF_RESERVED is set) are returned.
 *
 * @returns
 * The next iterator position.
 * If @c fdti_fp is NULL, the iteration is done.
 */
extern struct fdt_iterator
fdt_next(proc_t p, int fd, bool only_settled);

/*!
 * @function fdt_next
 *
 * @brief
 * Seek the iterator backwards.
 *
 * @discussion
 * The @c proc_fdlock() should be held by the caller.
 *
 * @param p
 * The process for which the file descriptor table is being iterated.
 *
 * @param fd
 * The current file file descriptor to scan from (exclusive).
 *
 * @param only_settled
 * When true, only fileprocs with @c UF_RESERVED set are returned.
 * If false, fileprocs that are in flux (@c UF_RESERVED is set) are returned.
 *
 * @returns
 * The next iterator position.
 * If @c fdti_fp is NULL, the iteration is done.
 */
extern struct fdt_iterator
fdt_prev(proc_t p, int fd, bool only_settled);

/*!
 * @def fdt_foreach
 *
 * @brief
 * Convenience macro around @c fdt_next() to enumerates fileprocs in a process
 * file descriptor table.
 *
 * @discussion
 * The @c proc_fdlock() should be held by the caller.
 *
 * @param fp
 * The iteration variable.
 *
 * @param p
 * The process for which the file descriptor table is being iterated.
 */
#define fdt_foreach(fp, p) \
	for (struct fdt_iterator __fdt_it = fdt_next(p, -1, true); \
	    ((fp) = __fdt_it.fdti_fp); \
	    __fdt_it = fdt_next(p, __fdt_it.fdti_fd, true))

/*!
 * @def fdt_foreach_fd
 *
 * @brief
 * When in an @c fdt_foreach() loop, return the current file descriptor
 * being inspected.
 */
#define fdt_foreach_fd()  __fdt_it.fdti_fd

/*!
 * @function fdt_init
 *
 * @brief
 * Initializers a proc file descriptor table.
 *
 * @warning
 * The proc that is passed is supposed to have been zeroed out,
 * as this function is used to setup @c kernelproc's file descriptor table
 * and some fields are already initialized when fdt_init() is called.
 */
extern void
fdt_init(proc_t p);

/*!
 * @function fdt_destroy
 *
 * @brief
 * Destroys locks from the file descriptor table.
 *
 * @description
 * This function destroys the file descriptor table locks.
 *
 * This cannot be done while the process this table belongs
 * to can be looked up.
 */
extern void
fdt_destroy(proc_t p);

/*!
 * @function fdt_fork
 *
 * @brief
 * Clones a file descriptor table for the @c fork() system call.
 *
 * @discussion
 * This function internally takes and drops @c proc_fdlock().
 *
 * Files are copied directly, ignoring the new resource limits for the process
 * that's being copied into.  Since the descriptor references are just
 * additional references, this does not count against the number of open files
 * on the system.
 *
 * The struct filedesc includes the current working directory, and the current
 * root directory, if the process is chroot'ed.
 *
 * If the exec was called by a thread using a per thread current working
 * directory, we inherit the working directory from the thread making the call,
 * rather than from the process.
 *
 * In the case of a failure to obtain a reference, for most cases, the file
 * entry will be silently dropped.  There's an exception for the case of
 * a chroot dir, since a failure to to obtain a reference there would constitute
 * an "escape" from the chroot environment, which must not be allowed.
 *
 * @param child_fdt
 * The child process file descriptor table.
 *
 * @param parent_p
 * The parent process to clone the file descriptor table from.
 *
 * @param uth_cdir
 * The vnode for the current thread's current working directory if it is
 * different from the parent process one.
 *
 * @returns
 * 0            Success
 * EPERM        Unable to acquire a reference to the current chroot directory
 * ENOMEM       Not enough memory to perform the clone operation
 */
extern int
fdt_fork(struct filedesc *child_fdt, proc_t parent_p, struct vnode *uth_cdir);

/*!
 * @function fdt_exec
 *
 * @brief
 * Perform close-on-exec processing for all files in a process
 * that are either marked as close-on-exec.
 *
 * @description
 * Also handles the case (via posix_spawn()) where -all- files except those
 * marked with "inherit" as treated as close-on-exec.
 *
 * This function internally takes and drops proc_fdlock()
 * But assumes tables don't grow/change while unlocked.
 *
 * @param p
 * The process whose file descriptor table is being filrered.
 *
 * @param posix_spawn_flags
 * A set of @c POSIX_SPAWN_* flags.
 */
extern void
fdt_exec(proc_t p, short posix_spawn_flags);

/*!
 * @function fdt_invalidate
 *
 * @brief
 * Invalidates a proc file descriptor table.
 *
 * @discussion
 * Closes all open files in the file descriptor table,
 * empties hash tables, etc...
 *
 * However, the fileproc arrays stay allocated to still allow external lookups.
 * These get cleaned up by @c fdt_destroy().
 *
 * This function internally takes and drops proc_fdlock().
 */
extern void
fdt_invalidate(proc_t p);

/*
 * Kernel global variables and routines.
 */
extern int      dupfdopen(proc_t p, int indx, int dfd, int mode, int error);
extern int      fdalloc(proc_t p, int want, int *result);
extern void     fdrelse(struct proc * p, int fd);
#define         fdfile(p, fd)                                   \
	                (&(p)->p_fd.fd_ofiles[(fd)])
#define         fdflags(p, fd)                                  \
	                (&(p)->p_fd.fd_ofileflags[(fd)])

extern int      falloc(proc_t p, struct fileproc **resultfp,
    int *resultfd, struct vfs_context *ctx);

typedef void (*fp_initfn_t)(struct fileproc *, void *ctx);
extern int      falloc_withinit(proc_t p, struct fileproc **resultfp,
    int *resultfd, struct vfs_context *ctx,
    fp_initfn_t fp_init, void *initarg);

#if CONFIG_PROC_RESOURCE_LIMITS
void fd_check_limit_exceeded(struct filedesc *fdp);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

#endif /* XNU_KERNEL_PRIVATE */

#endif /* !_SYS_FILEDESC_H_ */
