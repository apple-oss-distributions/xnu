/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1986, 1989, 1991, 1993
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
 *	@(#)proc.h	8.15 (Berkeley) 5/19/95
 */

#ifndef _SYS_PROC_PRIVATE_H_
#define _SYS_PROC_PRIVATE_H_

#include <sys/cdefs.h>
#ifdef KERNEL
#include <sys/kernel_types.h>
#endif

#ifdef XNU_KERNEL_PRIVATE
#include <mach/coalition.h>             /* COALITION_NUM_TYPES */
#include <sys/codesign.h>
#endif

#ifndef KERNEL
#include <Availability.h>
#endif

#ifdef KERNEL
__BEGIN_DECLS

#if XNU_KERNEL_PRIVATE

extern bool proc_is_driver(proc_t p);
extern bool proc_is_third_party_debuggable_driver(proc_t p);

#endif /* XNU_KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE
extern const char *proc_best_name(proc_t p);
#endif
#ifdef KERNEL_PRIVATE
/*
 * Function: proc_find_ident_validated
 *
 * Description: Obtain a proc ref from the provided proc_ident.
 *
 * Returns:
 *   - 0 on Success
 *   - EINVAL: When the provided arguments are invalid (NULL)
 *   - ESTALE: The process exists but is currently a zombie and has not been reaped
 *     via wait(). Callers may choose to handle this edge case as a non-error.
 *   - ESRCH: When the lookup or validation fails otherwise. The process
 *     described by the identifier no longer exists.
 */
extern errno_t proc_find_ident_validated(const proc_ident_t i, proc_t *out);
/* compare a proc_ident to a proc ref */
extern bool proc_ident_equal_ref(proc_ident_t ident, proc_t proc);
/* compare a proc_ident to another proc_ident */
extern bool proc_ident_equal(proc_ident_t ident, proc_ident_t other);
/* compare a proc_ident to an audit_token_t */
extern bool proc_ident_equal_token(proc_ident_t ident, audit_token_t token);
// mark a process as being allowed to call vfs_markdependency()
void bsd_set_dependency_capable(task_t task);
#ifdef  __arm__
static inline int
IS_64BIT_PROCESS(__unused proc_t p)
{
	return 0;
}
#else
extern int IS_64BIT_PROCESS(proc_t);
#endif /* __arm__ */

extern int      tsleep(void *chan, int pri, const char *wmesg, int timo);
extern int      msleep1(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg, u_int64_t timo);

task_t proc_task(proc_t);
extern int proc_pidversion(proc_t);
extern proc_t proc_parent(proc_t);
extern void proc_parent_audit_token(proc_t, audit_token_t *);
extern uint32_t proc_persona_id(proc_t);
extern uint32_t proc_getuid(proc_t);
extern uint32_t proc_getgid(proc_t);
extern int proc_getcdhash(proc_t, unsigned char *);

/*!
 *  @function    proc_pidbackgrounded
 *  @abstract    KPI to determine if a process is currently backgrounded.
 *  @discussion  The process may move into or out of background state at any time,
 *             so be prepared for this value to be outdated immediately.
 *  @param pid   PID of the process to be queried.
 *  @param state Pointer to a value which will be set to 1 if the process
 *             is currently backgrounded, 0 otherwise.
 *  @return      ESRCH if pid cannot be found or has started exiting.
 *
 *             EINVAL if state is NULL.
 */
extern int proc_pidbackgrounded(pid_t pid, uint32_t* state);

/*
 * This returns an unique 64bit id of a given process.
 * Caller needs to hold proper reference on the
 * passed in process strucutre.
 */
extern uint64_t proc_uniqueid(proc_t);

/* unique 64bit id for process's original parent */
extern uint64_t proc_puniqueid(proc_t);

extern void proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid);

/* return 1 if process is forcing case-sensitive HFS+ access, 0 for default */
extern int proc_is_forcing_hfs_case_sensitivity(proc_t);

/* returns 1 if the process is parent of a vfork */
extern int proc_lvfork(proc_t);

/* increments process block output operations counter. returns original value if valid long pointer was passed */
extern int proc_increment_ru_oublock(proc_t, long *);

/* Check if process is aborted, but not killed by a signal or is not the exiting thread or is not attempting to dump core */
extern int proc_isabortedsignal(proc_t);

/* return true if the process is translated, false for default */
extern boolean_t proc_is_translated(proc_t);

/* return true if this is an x86_64 process running under translation */
extern bool proc_is_x86_64_compat(proc_t);

/* true if the process ignores errors from content protection APIs */
extern bool proc_ignores_content_protection(proc_t proc);

/* true if the file system shouldn't update mtime for operations by the process */
extern bool proc_skip_mtime_update(proc_t proc);

/* true if syscalls support long paths */
extern bool proc_support_long_paths(proc_t proc);

/* return true if the process is flagged as allow-low-space */
extern bool proc_allow_low_space_writes(proc_t p);

/* return true if process needs to use alternative extended attribute for symlinks */
bool proc_use_alternative_symlink_ea(proc_t p);

/* return true if rsr is set for process */
bool proc_is_rsr(proc_t p);

/*
 * Return true if the process disallows read or write access for files that
 * it opens with O_EVTONLY.
 */
extern bool proc_disallow_rw_for_o_evtonly(proc_t p);

/*!
 *  @function    proc_exitstatus
 *  @abstract    KPI to determine a process's exit status.
 *  @discussion  This function is not safe to call if the process could be
 *               concurrently stopped or started, but it can be called from a
 *               mpo_proc_notify_exit callback.
 *  @param p     The process to be queried.
 *  @return      Value in the same format as wait()'s output parameter.
 */
extern int proc_exitstatus(proc_t p);

/*!
 *  @function    proc_is_zombie
 *  @abstract    KPI to determine if the provided process is a zombie
 *  @discussion  This lookup is atomic and safe to call with either a proc ref or
 *               or a zombie ref.
 *  @param p     The process to be queried.
 *  @return      Boolean indicating whether the process has been removed from the primary proclist
 *               and moved to the zombproc list.
 */
extern bool   proc_is_zombie(proc_t p);

#endif /* KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

extern void proc_getexecutableuuid(proc_t, unsigned char *, unsigned long);
extern int proc_get_originatorbgstate(uint32_t *is_backgrounded);

/* Kernel interface to get the uuid of the originator of the work.*/
extern int proc_pidoriginatoruuid(uuid_t uuid_buf, uint32_t buffersize);

extern uint64_t proc_was_throttled(proc_t);
extern uint64_t proc_did_throttle(proc_t);

extern void proc_coalitionids(proc_t, uint64_t[COALITION_NUM_TYPES]);

extern uint64_t get_current_unique_pid(void);
#endif /* XNU_KERNEL_PRIVATE*/

#ifdef KERNEL_PRIVATE
/* If buf argument is NULL, the necessary length to allocate will be set in buflen */
extern int proc_selfexecutableargs(uint8_t *buf, size_t *buflen);
extern off_t proc_getexecutableoffset(proc_t p);
extern vnode_t proc_getexecutablevnode(proc_t); /* Returned with iocount, use vnode_put() to drop */
extern vnode_t proc_getexecutablevnode_noblock(proc_t); /* Returned with iocount, use vnode_put() to drop */

/* System call filtering for BSD syscalls, mach traps and kobject routines. */
#define SYSCALL_MASK_UNIX 0
#define SYSCALL_MASK_MACH 1
#define SYSCALL_MASK_KOBJ 2

#define SYSCALL_FILTER_CALLBACK_VERSION 1
typedef int (*syscall_filter_cbfunc_t)(proc_t p, int num);
typedef int (*kobject_filter_cbfunc_t)(proc_t p, int msgid, int idx);
struct syscall_filter_callbacks {
	int version;
	const syscall_filter_cbfunc_t unix_filter_cbfunc;
	const syscall_filter_cbfunc_t mach_filter_cbfunc;
	const kobject_filter_cbfunc_t kobj_filter_cbfunc;
};
typedef struct syscall_filter_callbacks * syscall_filter_cbs_t;

extern int proc_set_syscall_filter_callbacks(syscall_filter_cbs_t callback);
extern int proc_set_syscall_filter_index(int which, int num, int index);
extern size_t proc_get_syscall_filter_mask_size(int which);
extern unsigned char *proc_get_syscall_filter_mask(proc_t p, int which);
extern int proc_set_syscall_filter_mask(proc_t p, int which, unsigned char *maskptr, size_t masklen);

extern int proc_set_filter_message_flag(proc_t p, boolean_t flag);
extern int proc_get_filter_message_flag(proc_t p, boolean_t *flag);

#define SANDBOX_INFO_CALLBACK_VERSION 1
typedef int (*sandbox_profile_cbfunc_t)(proc_t p, char *profile, size_t profile_len);

struct sandbox_info_callbacks {
	int version;
	const sandbox_profile_cbfunc_t sandbox_profile_cbfunc;
};
typedef struct sandbox_info_callbacks * sandbox_info_cbs_t;
extern int proc_set_sandbox_info_callbacks(sandbox_info_cbs_t callback);

#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif  /* KERNEL */

/* Values for pid_shutdown_sockets */
#define SHUTDOWN_SOCKET_LEVEL_DISCONNECT_SVC            0x00000001
#define SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL            0x00000002

#ifdef KERNEL
#define SHUTDOWN_SOCKET_LEVEL_DISCONNECT_INTERNAL       0x10000000
#define SHUTDOWN_SOCKET_LEVEL_NECP                      0x20000000
#define SHUTDOWN_SOCKET_LEVEL_CONTENT_FILTER            0x40000000
#endif

#ifndef KERNEL

__BEGIN_DECLS

int pid_suspend(int pid);
int pid_resume(int pid);
__API_AVAILABLE(macos(11.3), ios(14.5), tvos(14.5), watchos(7.3))
int task_inspect_for_pid(unsigned int target_tport, int pid, unsigned int *t);  /* Returns task inspect port */
__API_AVAILABLE(macos(11.3), ios(14.5), tvos(14.5), watchos(7.3))
int task_read_for_pid(unsigned int target_tport, int pid, unsigned int *t);     /* Returns task read port */

#if defined(__arm__) || defined(__arm64__)
int pid_hibernate(int pid);
#endif /* defined(__arm__) || defined(__arm64__)  */
int pid_shutdown_sockets(int pid, int level);
int pid_shutdown_networking(int pid, int level);
__END_DECLS

#endif /* !KERNEL */

/* Entitlement to allow non-root processes to suspend/resume any task */
#define PROCESS_RESUME_SUSPEND_ENTITLEMENT "com.apple.private.process.suspend-resume.any"

#endif  /* !_SYS_PROC_PRIVATE_H_ */
