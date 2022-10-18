/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 *
 *
 * Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved
 *
 *
 * Copyright (c) 1982, 1986, 1989, 1990, 1991, 1993
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
 *	@(#)kern_prot.c	8.9 (Berkeley) 2/14/95
 *
 *
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 *
 *
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 *
 */

/*
 * System calls related to processes and protection
 */

#include <sys/param.h>
#include <sys/acct.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/kauth.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/malloc.h>
#include <sys/persona.h>

#include <security/audit/audit.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <sys/mount_internal.h>
#include <sys/sysproto.h>
#include <mach/message.h>

#include <kern/host.h>
#include <kern/task.h>          /* for current_task() */
#include <kern/assert.h>

#if DEVELOPMENT || DEBUG
extern void task_importance_update_owner_info(task_t);
#endif

/* Used by pmap.c to copy kauth_cred_t structs */
void kauth_cred_copy(const uintptr_t kv, const uintptr_t new_data);

/*
 * setprivexec
 *
 * Description:	(dis)allow this process to hold task, thread, or execption
 *		ports of processes about to exec.
 *
 * Parameters:	uap->flag			New value for flag
 *
 * Returns:	int				Previous value of flag
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setprivexec(proc_t p, struct setprivexec_args *uap, int32_t *retval)
{
	AUDIT_ARG(value32, uap->flag);
	*retval = p->p_debugger;
	p->p_debugger = (uap->flag != 0);
	return 0;
}


/*
 * getpid
 *
 * Description:	get the process ID
 *
 * Parameters:	(void)
 *
 * Returns:	pid_t				Current process ID
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getpid(proc_t p, __unused struct getpid_args *uap, int32_t *retval)
{
	*retval = proc_getpid(p);
	return 0;
}


/*
 * getppid
 *
 * Description: get the parent process ID
 *
 * Parameters:	(void)
 *
 * Returns:	pid_t				Parent process ID
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getppid(proc_t p, __unused struct getppid_args *uap, int32_t *retval)
{
	*retval = p->p_ppid;
	return 0;
}


/*
 * getpgrp
 *
 * Description:	get the process group ID of the calling process
 *
 * Parameters:	(void)
 *
 * Returns:	pid_t				Process group ID
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getpgrp(proc_t p, __unused struct getpgrp_args *uap, int32_t *retval)
{
	*retval = p->p_pgrpid;
	return 0;
}


/*
 * getpgid
 *
 * Description: Get an arbitary pid's process group id
 *
 * Parameters:	uap->pid			The target pid
 *
 * Returns:	0				Success
 *		ESRCH				No such process
 *
 * Notes:	We are permitted to return EPERM in the case that the target
 *		process is not in the same session as the calling process,
 *		which could be a security consideration
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getpgid(proc_t p, struct getpgid_args *uap, int32_t *retval)
{
	proc_t pt;
	int refheld = 0;

	pt = p;
	if (uap->pid == 0) {
		goto found;
	}

	if ((pt = proc_find(uap->pid)) == 0) {
		return ESRCH;
	}
	refheld = 1;
found:
	*retval = pt->p_pgrpid;
	if (refheld != 0) {
		proc_rele(pt);
	}
	return 0;
}


/*
 * getsid
 *
 * Description:	Get an arbitary pid's session leaders process group ID
 *
 * Parameters:	uap->pid			The target pid
 *
 * Returns:	0				Success
 *		ESRCH				No such process
 *
 * Notes:	We are permitted to return EPERM in the case that the target
 *		process is not in the same session as the calling process,
 *		which could be a security consideration
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getsid(proc_t p, struct getsid_args *uap, int32_t *retval)
{
	proc_t pt;

	if (uap->pid == 0) {
		*retval = proc_sessionid(p);
		return 0;
	}

	if ((pt = proc_find(uap->pid)) != PROC_NULL) {
		*retval = proc_sessionid(pt);
		proc_rele(pt);
		return 0;
	}

	return ESRCH;
}


/*
 * getuid
 *
 * Description:	get real user ID for caller
 *
 * Parameters:	(void)
 *
 * Returns:	uid_t				The real uid of the caller
 */
int
getuid(__unused proc_t p, __unused struct getuid_args *uap, int32_t *retval)
{
	*retval = kauth_getruid();
	return 0;
}


/*
 * geteuid
 *
 * Description:	get effective user ID for caller
 *
 * Parameters:	(void)
 *
 * Returns:	uid_t				The effective uid of the caller
 */
int
geteuid(__unused proc_t p, __unused struct geteuid_args *uap, int32_t *retval)
{
	*retval = kauth_getuid();
	return 0;
}


/*
 * gettid
 *
 * Description:	Return the per-thread override identity.
 *
 * Parameters:	uap->uidp			Address of uid_t to get uid
 *		uap->gidp			Address of gid_t to get gid
 *
 * Returns:	0				Success
 *		ESRCH				No per thread identity active
 */
int
gettid(__unused proc_t p, struct gettid_args *uap, int32_t *retval)
{
	thread_ro_t tro = current_thread_ro();
	kauth_cred_t tro_cred = tro->tro_cred;
	int     error;

	/*
	 * If this thread is not running with an override identity, we can't
	 * return one to the caller, so return an error instead.
	 */
	if (!(tro->tro_flags & TRO_SETUID)) {
		return ESRCH;
	}

	if ((error = suword(uap->uidp, kauth_cred_getruid(tro_cred)))) {
		return error;
	}
	if ((error = suword(uap->gidp, kauth_cred_getrgid(tro_cred)))) {
		return error;
	}

	*retval = 0;
	return 0;
}


/*
 * getgid
 *
 * Description:	get the real group ID for the calling process
 *
 * Parameters:	(void)
 *
 * Returns:	gid_t				The real gid of the caller
 */
int
getgid(__unused proc_t p, __unused struct getgid_args *uap, int32_t *retval)
{
	*retval = kauth_getrgid();
	return 0;
}


/*
 * getegid
 *
 * Description:	get the effective group ID for the calling process
 *
 * Parameters:	(void)
 *
 * Returns:	gid_t				The effective gid of the caller
 *
 * Notes:	As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list.
 *
 *		This could be implemented in Libc instead because of the above
 *		detail.
 */
int
getegid(__unused proc_t p, __unused struct getegid_args *uap, int32_t *retval)
{
	*retval = kauth_getgid();
	return 0;
}


/*
 * getgroups
 *
 * Description:	get the list of supplementary groups for the calling process
 *
 * Parameters:	uap->gidsetsize			# of gid_t's in user buffer
 *		uap->gidset			Pointer to user buffer
 *
 * Returns:	0				Success
 *		EINVAL				User buffer too small
 *	copyout:EFAULT				User buffer invalid
 *
 * Retval:	-1				Error
 *		!0				# of groups
 *
 * Notes:	The caller may specify a 0 value for gidsetsize, and we will
 *		then return how large a buffer is required (in gid_t's) to
 *		contain the answer at the time of the call.  Otherwise, we
 *		return the number of gid_t's catually copied to user space.
 *
 *		When called with a 0 gidsetsize from a multithreaded program,
 *		there is no guarantee that another thread may not change the
 *		number of supplementary groups, and therefore a subsequent
 *		call could still fail, unless the maximum possible buffer
 *		size is supplied by the user.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and will
 *		be returned by this call.
 */
int
getgroups(__unused proc_t p, struct getgroups_args *uap, int32_t *retval)
{
	int ngrp;
	int error;
	kauth_cred_t cred;
	posix_cred_t pcred;

	/* grab reference while we muck around with the credential */
	cred = kauth_cred_get_with_ref();
	pcred = posix_cred_get(cred);

	if ((ngrp = uap->gidsetsize) == 0) {
		*retval = pcred->cr_ngroups;
		kauth_cred_unref(&cred);
		return 0;
	}
	if (ngrp < pcred->cr_ngroups) {
		kauth_cred_unref(&cred);
		return EINVAL;
	}
	ngrp = pcred->cr_ngroups;
	if ((error = copyout((caddr_t)pcred->cr_groups,
	    uap->gidset,
	    ngrp * sizeof(gid_t)))) {
		kauth_cred_unref(&cred);
		return error;
	}
	kauth_cred_unref(&cred);
	*retval = ngrp;
	return 0;
}


/*
 * Return the per-thread/per-process supplementary groups list.
 *
 * XXX implement getsgroups
 *
 */

int
getsgroups(__unused proc_t p, __unused struct getsgroups_args *uap, __unused int32_t *retval)
{
	return ENOTSUP;
}

/*
 * Return the per-thread/per-process whiteout groups list.
 *
 * XXX implement getwgroups
 *
 */

int
getwgroups(__unused proc_t p, __unused struct getwgroups_args *uap, __unused int32_t *retval)
{
	return ENOTSUP;
}

/*
 * setsid_internal
 *
 * Description:	Core implementation of setsid().
 */
int
setsid_internal(proc_t p)
{
	struct pgrp * pg = PGRP_NULL;

	if (p->p_pgrpid == proc_getpid(p) ||
	    (pg = pgrp_find(proc_getpid(p)))) {
		pgrp_rele(pg);
		return EPERM;
	}

	/* enter pgrp works with its own pgrp refcount */
	(void)enterpgrp(p, proc_getpid(p), 1);
	return 0;
}

/*
 * setsid
 *
 * Description:	Create a new session and set the process group ID to the
 *		session ID
 *
 * Parameters:	(void)
 *
 * Returns:	0				Success
 *		EPERM				Permission denied
 *
 * Notes:	If the calling process is not the process group leader; there
 *		is no existing process group with its ID, then this function will
 *		create a new session, a new process group, and put the caller in the
 *		process group (as the sole member) and make it the session
 *		leader (as the sole process in the session).
 *
 *		The existing controlling tty (if any) will be dissociated
 *		from the process, and the next non-O_NOCTTY open of a tty
 *		will establish a new controlling tty.
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setsid(proc_t p, __unused struct setsid_args *uap, int32_t *retval)
{
	int rc = setsid_internal(p);
	if (rc == 0) {
		*retval = proc_getpid(p);
	}
	return rc;
}


/*
 * setpgid
 *
 * Description: set process group ID for job control
 *
 * Parameters:	uap->pid			Process to change
 *		uap->pgid			Process group to join or create
 *
 * Returns:	0			Success
 *		ESRCH			pid is not the caller or a child of
 *					the caller
 *	enterpgrp:ESRCH			No such process
 *		EACCES			Permission denied due to exec
 *		EINVAL			Invalid argument
 *		EPERM			The target process is not in the same
 *					session as the calling process
 *		EPERM			The target process is a session leader
 *		EPERM			pid and pgid are not the same, and
 *					there is no process in the calling
 *					process whose process group ID matches
 *					pgid
 *
 * Notes:	This function will cause the target process to either join
 *		an existing process process group, or create a new process
 *		group in the session of the calling process.  It cannot be
 *		used to change the process group ID of a process which is
 *		already a session leader.
 *
 *		If the target pid is 0, the pid of the calling process is
 *		substituted as the new target; if pgid is 0, the target pid
 *		is used as the target process group ID.
 *
 * Legacy:	This system call entry point is also used to implement the
 *		legacy library routine setpgrp(), which under POSIX
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setpgid(proc_t curp, struct setpgid_args *uap, __unused int32_t *retval)
{
	proc_t targp = PROC_NULL;       /* target process */
	struct pgrp *curp_pg = PGRP_NULL;
	struct pgrp *targp_pg = PGRP_NULL;
	int error = 0;
	int refheld = 0;
	int samesess = 0;

	curp_pg = proc_pgrp(curp, NULL);

	if (uap->pid != 0 && uap->pid != proc_getpid(curp)) {
		if ((targp = proc_find(uap->pid)) == 0 || !inferior(targp)) {
			if (targp != PROC_NULL) {
				refheld = 1;
			}
			error = ESRCH;
			goto out;
		}
		refheld = 1;
		targp_pg = proc_pgrp(targp, NULL);
		if (targp_pg->pg_session != curp_pg->pg_session) {
			error = EPERM;
			goto out;
		}
		if (targp->p_flag & P_EXEC) {
			error = EACCES;
			goto out;
		}
	} else {
		targp = curp;
		targp_pg = proc_pgrp(targp, NULL);
	}

	if (SESS_LEADER(targp, targp_pg->pg_session)) {
		error = EPERM;
		goto out;
	}

	if (uap->pgid < 0) {
		error = EINVAL;
		goto out;
	}
	if (uap->pgid == 0) {
		uap->pgid = proc_getpid(targp);
	} else if (uap->pgid != proc_getpid(targp)) {
		struct pgrp *pg = PGRP_NULL;

		if ((pg = pgrp_find(uap->pgid)) == PGRP_NULL) {
			error = EPERM;
			goto out;
		}
		samesess = (pg->pg_session != curp_pg->pg_session);
		pgrp_rele(pg);
		if (samesess != 0) {
			error = EPERM;
			goto out;
		}
	}
	error = enterpgrp(targp, uap->pgid, 0);
out:
	pgrp_rele(curp_pg);
	pgrp_rele(targp_pg);
	if (refheld != 0) {
		proc_rele(targp);
	}
	return error;
}


/*
 * issetugid
 *
 * Description:	Is current process tainted by uid or gid changes system call
 *
 * Parameters:	(void)
 *
 * Returns:	0				Not tainted
 *		1				Tainted
 *
 * Notes:	A process is considered tainted if it was created as a retult
 *		of an execve call from an imnage that had either the SUID or
 *		SGID bit set on the executable, or if it has changed any of its
 *		real, effective, or saved user or group IDs since beginning
 *		execution.
 */
int
proc_issetugid(proc_t p)
{
	return (p->p_flag & P_SUGID) ? 1 : 0;
}

int
issetugid(proc_t p, __unused struct issetugid_args *uap, int32_t *retval)
{
	/*
	 * Note: OpenBSD sets a P_SUGIDEXEC flag set at execve() time,
	 * we use P_SUGID because we consider changing the owners as
	 * "tainting" as well.
	 * This is significant for procs that start as root and "become"
	 * a user without an exec - programs cannot know *everything*
	 * that libc *might* have put in their data segment.
	 */

	*retval = proc_issetugid(p);
	return 0;
}

/*
 * setuid
 *
 * Description:	Set user ID system call
 *
 * Parameters:	uap->uid			uid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	If called by a privileged process, this function will set the
 *		real, effective, and saved uid to the requested value.
 *
 *		If called from an unprivileged process, but uid is equal to the
 *		real or saved uid, then the effective uid will be set to the
 *		requested value, but the real and saved uid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
int
setuid(proc_t p, struct setuid_args *uap, __unused int32_t *retval)
{
	__block int error = 0;
	__block uid_t old_ruid;
	__block uid_t ruid;
	uid_t want_uid;
	bool changed;

	want_uid = uap->uid;
	AUDIT_ARG(uid, want_uid);

	changed = proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
		posix_cred_t cur_pcred = posix_cred_get(cur_cred);
		uid_t svuid = KAUTH_UID_NONE;
		uid_t gmuid = KAUTH_UID_NONE;

		ruid = KAUTH_UID_NONE;
		old_ruid = cur_pcred->cr_ruid;

#if CONFIG_MACF
		if ((error = mac_proc_check_setuid(p, cur_cred, want_uid)) != 0) {
		        return cur_cred;
		}
#endif

		if (want_uid != cur_pcred->cr_ruid &&         /* allow setuid(getuid()) */
		want_uid != cur_pcred->cr_svuid &&            /* allow setuid(saved uid) */
		(error = suser(cur_cred, &p->p_acflag))) {
		        return cur_cred;
		}

		/*
		 * If we are privileged, then set the saved and real UID too;
		 * otherwise, just set the effective UID
		 */
		if (suser(cur_cred, &p->p_acflag) == 0) {
		        svuid = want_uid;
		        ruid = want_uid;
		}

		/*
		 * Only set the gmuid if the current cred has not opt'ed out;
		 * this normally only happens when calling setgroups() instead
		 * of initgroups() to set an explicit group list, or one of the
		 * other group manipulation functions is invoked and results in
		 * a dislocation (i.e. the credential group membership changes
		 * to something other than the default list for the user, as
		 * in entering a group or leaving an exclusion group).
		 */
		if (!(cur_pcred->cr_flags & CRF_NOMEMBERD)) {
		        gmuid = want_uid;
		}

		return kauth_cred_setresuid(cur_cred, ruid, want_uid, svuid, gmuid);
	});

	if (changed && ruid != KAUTH_UID_NONE && old_ruid != ruid &&
	    !proc_has_persona(p)) {
		(void)chgproccnt(ruid, 1);
		(void)chgproccnt(old_ruid, -1);
	}

	return error;
}


/*
 * seteuid
 *
 * Description:	Set effective user ID system call
 *
 * Parameters:	uap->euid			effective uid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	If called by a privileged process, or called from an
 *		unprivileged process but euid is equal to the real or saved
 *		uid, then the effective uid will be set to the requested
 *		value, but the real and saved uid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
int
seteuid(proc_t p, struct seteuid_args *uap, __unused int32_t *retval)
{
	__block int error = 0;
	uid_t want_euid;
	bool changed;

	want_euid = uap->euid;
	AUDIT_ARG(euid, want_euid);

	changed = proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
		posix_cred_t cur_pcred = posix_cred_get(cur_cred);

#if CONFIG_MACF
		if ((error = mac_proc_check_seteuid(p, cur_cred, want_euid)) != 0) {
		        return cur_cred;
		}
#endif

		if (want_euid != cur_pcred->cr_ruid && want_euid != cur_pcred->cr_svuid &&
		(error = suser(cur_cred, &p->p_acflag))) {
		        return cur_cred;
		}

		return kauth_cred_setresuid(cur_cred, KAUTH_UID_NONE, want_euid,
		KAUTH_UID_NONE, cur_pcred->cr_gmuid);
	});

	return error;
}


/*
 * setreuid
 *
 * Description:	Set real and effective user ID system call
 *
 * Parameters:	uap->ruid			real uid to set
 *		uap->euid			effective uid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	A value of -1 is a special case indicating that the uid for
 *		which that value is specified not be changed.  If both values
 *		are specified as -1, no action is taken.
 *
 *		If called by a privileged process, the real and effective uid
 *		will be set to the new value(s) specified.
 *
 *		If called from an unprivileged process, the real uid may be
 *		set to the current value of the real uid, or to the current
 *		value of the saved uid.  The effective uid may be set to the
 *		current value of any of the effective, real, or saved uid.
 *
 *		If the newly requested real uid or effective uid does not
 *		match the saved uid, then set the saved uid to the new
 *		effective uid (potentially unrecoverably dropping saved
 *		privilege).
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
int
setreuid(proc_t p, struct setreuid_args *uap, __unused int32_t *retval)
{
	__block int error = 0;
	__block uid_t old_ruid;
	uid_t want_ruid, want_euid;
	bool changed;

	want_ruid = uap->ruid;
	want_euid = uap->euid;

	if (want_ruid == (uid_t)-1) {
		want_ruid = KAUTH_UID_NONE;
	}

	if (want_euid == (uid_t)-1) {
		want_euid = KAUTH_UID_NONE;
	}

	AUDIT_ARG(euid, want_euid);
	AUDIT_ARG(ruid, want_ruid);

	changed = proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
		posix_cred_t cur_pcred = posix_cred_get(cur_cred);
		uid_t svuid = KAUTH_UID_NONE;

#if CONFIG_MACF
		if ((error = mac_proc_check_setreuid(p, cur_cred, want_ruid, want_euid)) != 0) {
		        return cur_cred;
		}
#endif

		if (((want_ruid != KAUTH_UID_NONE &&         /* allow no change of ruid */
		want_ruid != cur_pcred->cr_ruid &&            /* allow ruid = ruid */
		want_ruid != cur_pcred->cr_uid &&             /* allow ruid = euid */
		want_ruid != cur_pcred->cr_svuid) ||          /* allow ruid = svuid */
		(want_euid != KAUTH_UID_NONE &&              /* allow no change of euid */
		want_euid != cur_pcred->cr_uid &&             /* allow euid = euid */
		want_euid != cur_pcred->cr_ruid &&            /* allow euid = ruid */
		want_euid != cur_pcred->cr_svuid)) &&         /* allow euid = svuid */
		(error = suser(cur_cred, &p->p_acflag))) {     /* allow root user any */
		        return cur_cred;
		}

		uid_t new_euid = cur_pcred->cr_uid;

		if (want_euid != KAUTH_UID_NONE && cur_pcred->cr_uid != want_euid) {
		        new_euid = want_euid;
		}

		old_ruid = cur_pcred->cr_ruid;

		/*
		 * If the newly requested real uid or effective uid does
		 * not match the saved uid, then set the saved uid to the
		 * new effective uid.  We are protected from escalation
		 * by the prechecking.
		 */
		if (cur_pcred->cr_svuid != uap->ruid &&
		cur_pcred->cr_svuid != uap->euid) {
		        svuid = new_euid;
		}

		return kauth_cred_setresuid(cur_cred, want_ruid, want_euid,
		svuid, cur_pcred->cr_gmuid);
	});

	if (changed && want_ruid != KAUTH_UID_NONE && want_ruid != old_ruid &&
	    !proc_has_persona(p)) {
		(void)chgproccnt(want_ruid, 1);
		(void)chgproccnt(old_ruid, -1);
	}

	return error;
}


/*
 * setgid
 *
 * Description:	Set group ID system call
 *
 * Parameters:	uap->gid			gid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	If called by a privileged process, this function will set the
 *		real, effective, and saved gid to the requested value.
 *
 *		If called from an unprivileged process, but gid is equal to the
 *		real or saved gid, then the effective gid will be set to the
 *		requested value, but the real and saved gid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and
 *		therefore the effective group list may be reordered to keep
 *		the supplementary group list unchanged.
 */
int
setgid(proc_t p, struct setgid_args *uap, __unused int32_t *retval)
{
	__block int error = 0;
	gid_t want_gid;
	bool changed;

	want_gid = uap->gid;
	AUDIT_ARG(gid, want_gid);

	changed = proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
		posix_cred_t cur_pcred = posix_cred_get(cur_cred);
		gid_t rgid = KAUTH_GID_NONE;
		gid_t svgid = KAUTH_GID_NONE;

#if CONFIG_MACF
		if ((error = mac_proc_check_setgid(p, cur_cred, want_gid)) != 0) {
		        return cur_cred;
		}
#endif

		if (want_gid != cur_pcred->cr_rgid &&         /* allow setgid(getgid()) */
		want_gid != cur_pcred->cr_svgid &&            /* allow setgid(saved gid) */
		(error = suser(cur_cred, &p->p_acflag))) {
		        return cur_cred;
		}

		/*
		 * If we are privileged, then set the saved and real GID too;
		 * otherwise, just set the effective GID
		 */
		if (suser(cur_cred, &p->p_acflag) == 0) {
		        svgid = want_gid;
		        rgid = want_gid;
		}

		return kauth_cred_setresgid(cur_cred, rgid, want_gid, svgid);
	});

	return error;
}


/*
 * setegid
 *
 * Description:	Set effective group ID system call
 *
 * Parameters:	uap->egid			effective gid to set
 *
 * Returns:	0				Success
 *	suser:EPERM
 *
 * Notes:	If called by a privileged process, or called from an
 *		unprivileged process but egid is equal to the real or saved
 *		gid, then the effective gid will be set to the requested
 *		value, but the real and saved gid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and
 *		therefore the effective group list may be reordered to keep
 *		the supplementary group list unchanged.
 */
int
setegid(proc_t p, struct setegid_args *uap, __unused int32_t *retval)
{
	__block int error = 0;
	gid_t want_egid;
	bool changed;

	want_egid = uap->egid;
	AUDIT_ARG(egid, want_egid);

	changed = proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
		posix_cred_t cur_pcred = posix_cred_get(cur_cred);

#if CONFIG_MACF
		if ((error = mac_proc_check_setegid(p, cur_cred, want_egid)) != 0) {
		        return cur_cred;
		}
#endif

		if (want_egid != cur_pcred->cr_rgid &&
		want_egid != cur_pcred->cr_svgid &&
		(error = suser(cur_cred, &p->p_acflag))) {
		        return cur_cred;
		}

		return kauth_cred_setresgid(cur_cred, KAUTH_GID_NONE,
		want_egid, KAUTH_GID_NONE);
	});

	return error;
}

/*
 * setregid
 *
 * Description:	Set real and effective group ID system call
 *
 * Parameters:	uap->rgid			real gid to set
 *		uap->egid			effective gid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	A value of -1 is a special case indicating that the gid for
 *		which that value is specified not be changed.  If both values
 *		are specified as -1, no action is taken.
 *
 *		If called by a privileged process, the real and effective gid
 *		will be set to the new value(s) specified.
 *
 *		If called from an unprivileged process, the real gid may be
 *		set to the current value of the real gid, or to the current
 *		value of the saved gid.  The effective gid may be set to the
 *		current value of any of the effective, real, or saved gid.
 *
 *		If the new real and effective gid will not be equal, or the
 *		new real or effective gid is not the same as the saved gid,
 *		then the saved gid will be updated to reflect the new
 *		effective gid (potentially unrecoverably dropping saved
 *		privilege).
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and
 *		therefore the effective group list may be reordered to keep
 *		the supplementary group list unchanged.
 */
int
setregid(proc_t p, struct setregid_args *uap, __unused int32_t *retval)
{
	__block int error = 0;
	gid_t want_rgid;
	gid_t want_egid;
	bool changed;

	want_rgid = uap->rgid;
	want_egid = uap->egid;

	if (want_rgid == (gid_t)-1) {
		want_rgid = KAUTH_GID_NONE;
	}

	if (want_egid == (gid_t)-1) {
		want_egid = KAUTH_GID_NONE;
	}

	AUDIT_ARG(egid, want_egid);
	AUDIT_ARG(rgid, want_rgid);

	changed = proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
		posix_cred_t cur_pcred = posix_cred_get(cur_cred);
		uid_t svgid = KAUTH_UID_NONE;

#if CONFIG_MACF
		if ((error = mac_proc_check_setregid(p, cur_cred, want_rgid,
		want_egid)) != 0) {
		        return cur_cred;
		}
#endif

		if (((want_rgid != KAUTH_UID_NONE &&         /* allow no change of rgid */
		want_rgid != cur_pcred->cr_rgid &&            /* allow rgid = rgid */
		want_rgid != cur_pcred->cr_gid &&             /* allow rgid = egid */
		want_rgid != cur_pcred->cr_svgid) ||          /* allow rgid = svgid */
		(want_egid != KAUTH_UID_NONE &&              /* allow no change of egid */
		want_egid != cur_pcred->cr_groups[0] &&       /* allow no change of egid */
		want_egid != cur_pcred->cr_gid &&             /* allow egid = egid */
		want_egid != cur_pcred->cr_rgid &&            /* allow egid = rgid */
		want_egid != cur_pcred->cr_svgid)) &&         /* allow egid = svgid */
		(error = suser(cur_cred, &p->p_acflag))) {     /* allow root user any */
		        return cur_cred;
		}

		uid_t new_egid = cur_pcred->cr_gid;
		if (want_egid != KAUTH_UID_NONE && cur_pcred->cr_gid != want_egid) {
		        /* changing the effective GID */
		        new_egid = want_egid;
		}

		/*
		 * If the newly requested real gid or effective gid does
		 * not match the saved gid, then set the saved gid to the
		 * new effective gid.  We are protected from escalation
		 * by the prechecking.
		 */
		if (cur_pcred->cr_svgid != want_rgid &&
		cur_pcred->cr_svgid != want_egid) {
		        svgid = new_egid;
		}

		return kauth_cred_setresgid(cur_cred, want_rgid, want_egid, svgid);
	});

	return error;
}


/*
 * Set the per-thread override identity.  The first parameter can be the
 * current real UID, KAUTH_UID_NONE, or, if the caller is privileged, it
 * can be any UID.  If it is KAUTH_UID_NONE, then as a special case, this
 * means "revert to the per process credential"; otherwise, if permitted,
 * it changes the effective, real, and saved UIDs and GIDs for the current
 * thread to the requested UID and single GID, and clears all other GIDs.
 */
int
settid(proc_t p, struct settid_args *uap, __unused int32_t *retval)
{
	kauth_cred_t cred;
	struct thread_ro *tro = current_thread_ro();
	uid_t uid;
	gid_t gid;
#if CONFIG_MACF
	int error;
#endif

	uid = uap->uid;
	gid = uap->gid;
	AUDIT_ARG(uid, uid);
	AUDIT_ARG(gid, gid);

#if CONFIG_MACF
	if ((error = mac_proc_check_settid(p, uid, gid)) != 0) {
		return error;
	}
#endif

	if (proc_suser(p) != 0) {
		return EPERM;
	}

	if (uid == KAUTH_UID_NONE) {
		/* must already be assuming another identity in order to revert back */
		if ((tro->tro_flags & TRO_SETUID) == 0) {
			return EPERM;
		}

		/* revert to delayed binding of process credential */
		cred = kauth_cred_proc_ref(p);
		thread_ro_update_cred(tro, cred);
		thread_ro_update_flags(tro, TRO_NONE, TRO_SETUID);
		kauth_cred_unref(&cred);
	} else {
		/* cannot already be assuming another identity */
		if ((tro->tro_flags & TRO_SETUID) != 0) {
			return EPERM;
		}

		/*
		 * Get a new credential instance from the old if this one
		 * changes; otherwise kauth_cred_setuidgid() returns the
		 * same credential.  We take an extra reference on the
		 * current credential while we muck with it, so we can do
		 * the post-compare for changes by pointer.
		 */
		cred = tro->tro_cred;
		kauth_cred_ref(cred);
		cred = kauth_cred_setuidgid(cred, uid, gid);
		thread_ro_update_cred(tro, cred);
		thread_ro_update_flags(tro, TRO_SETUID, TRO_NONE);
		kauth_cred_unref(&cred);
	}

	/*
	 * XXX should potentially set per thread security token (there is
	 * XXX none).
	 * XXX it is unclear whether P_SUGID should be st at this point;
	 * XXX in theory, it is being deprecated.
	 */
	return 0;
}


/*
 * Set the per-thread override identity.  Use this system call for a thread to
 * assume the identity of another process or to revert back to normal identity
 * of the current process.
 *
 * When the "assume" argument is non zero the current thread will assume the
 * identity of the process represented by the pid argument.
 *
 * When the assume argument is zero we revert back to our normal identity.
 */
int
settid_with_pid(proc_t p, struct settid_with_pid_args *uap, __unused int32_t *retval)
{
	proc_t target_proc;
	thread_ro_t tro = current_thread_ro();
	kauth_cred_t cred, my_target_cred;
	posix_cred_t my_target_pcred;
	uid_t uid;
	gid_t gid;
	int error;

	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(value32, uap->assume);

	/*
	 * XXX should potentially set per thread security token (there is
	 * XXX none).
	 * XXX it is unclear whether P_SUGID should be st at this point;
	 * XXX in theory, it is being deprecated.
	 */

	/*
	 * assume argument tells us to assume the identity of the process with the
	 * id passed in the pid argument.
	 */
	if (uap->assume != 0) {
		target_proc = proc_find(uap->pid);
		if (target_proc == NULL || target_proc == kernproc) {
			if (target_proc != NULL) {
				proc_rele(target_proc);
			}
			return ESRCH;
		}
		my_target_cred = kauth_cred_proc_ref(target_proc);
		my_target_pcred = posix_cred_get(my_target_cred);
		uid = my_target_pcred->cr_uid;
		gid = my_target_pcred->cr_gid;
		kauth_cred_unref(&my_target_cred);
		proc_rele(target_proc);

#if CONFIG_MACF
		if ((error = mac_proc_check_settid(p, uid, gid)) != 0) {
			return error;
		}
#endif

		/* can't do this if we have already assumed an identity */
		if (proc_suser(p) != 0 || (tro->tro_flags & TRO_SETUID) != 0) {
			return EPERM;
		}

		/*
		 * Take a reference on the credential used in our target
		 * process then use it as the identity for our current
		 * thread.  We take an extra reference on the current
		 * credential while we muck with it, so we can do the
		 * post-compare for changes by pointer.
		 *
		 * The post-compare is needed for the case that our process
		 * credential has been changed to be identical to our thread
		 * credential following our assumption of a per-thread one,
		 * since the credential cache will maintain a unique instance.
		 */
		cred = tro->tro_cred;
		kauth_cred_ref(cred);
		cred = kauth_cred_setuidgid(cred, uid, gid);
		thread_ro_update_cred(tro, cred);
		thread_ro_update_flags(tro, TRO_SETUID, TRO_NONE);
		kauth_cred_unref(&cred);

		return 0;
	}

	/*
	 * Otherwise, we are reverting back to normal mode of operation where
	 * delayed binding of the process credential sets the credential in
	 * the thread_ro (tro_cred)
	 */

	if ((error = mac_proc_check_settid(p, KAUTH_UID_NONE, KAUTH_GID_NONE)) != 0) {
		return error;
	}

	if (proc_suser(p) != 0 || (tro->tro_flags & TRO_SETUID) == 0) {
		return EPERM;
	}

	/* revert to delayed binding of process credential */
	cred = kauth_cred_proc_ref(p);
	thread_ro_update_cred(tro, cred);
	thread_ro_update_flags(tro, TRO_NONE, TRO_SETUID);
	kauth_cred_unref(&cred);

	return 0;
}


/*
 * setgroups1
 *
 * Description: Internal implementation for both the setgroups and initgroups
 *		system calls
 *
 * Parameters:	gidsetsize			Number of groups in set
 *		gidset				Pointer to group list
 *		gmuid				Base gid (initgroups only!)
 *
 * Returns:	0				Success
 *	suser:EPERM				Permision denied
 *		EINVAL				Invalid gidsetsize value
 *	copyin:EFAULT				Bad gidset or gidsetsize is
 *						too large
 *
 * Notes:	When called from a thread running under an assumed per-thread
 *		identity, this function will operate against the per-thread
 *		credential, rather than against the process credential.  In
 *		this specific case, the process credential is verified to
 *		still be privileged at the time of the call, rather than the
 *		per-thread credential for this operation to be permitted.
 *
 *		This effectively means that setgroups/initigroups calls in
 *		a thread running a per-thread credential should occur *after*
 *		the settid call that created it, not before (unlike setuid,
 *		which must be called after, since it will result in privilege
 *		being dropped).
 *
 *		When called normally (i.e. no per-thread assumed identity),
 *		the per process credential is updated per POSIX.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
static int
setgroups1(proc_t p, u_int ngrp, user_addr_t gidset, uid_t gmuid, __unused int32_t *retval)
{
	gid_t   newgroups[NGROUPS] = { 0 };
	int     error;

	if (ngrp > NGROUPS) {
		return EINVAL;
	}

	if (ngrp >= 1) {
		error = copyin(gidset,
		    (caddr_t)newgroups, ngrp * sizeof(gid_t));
		if (error) {
			return error;
		}
	}
	return setgroups_internal(p, ngrp, newgroups, gmuid);
}

int
setgroups_internal(proc_t p, u_int ngrp, gid_t *newgroups, uid_t gmuid)
{
	thread_ro_t tro = current_thread_ro();
	kauth_cred_t cred;
	int     error;

	cred = kauth_cred_proc_ref(p);
	error = suser(cred, &p->p_acflag);
	kauth_cred_unref(&cred);

	if (error) {
		return error;
	}

	if (ngrp < 1) {
		ngrp = 1;
		newgroups[0] = 0;
	}

	if ((tro->tro_flags & TRO_SETUID) != 0) {
		/*
		 * If this thread is under an assumed identity, set the
		 * supplementary grouplist on the thread credential instead
		 * of the process one.  If we were the only reference holder,
		 * the credential is updated in place, otherwise, our reference
		 * is dropped and we get back a different cred with a reference
		 * already held on it.  Because this is per-thread, we don't
		 * need the referencing/locking/retry required for per-process.
		 */
		cred = tro->tro_cred;
		kauth_cred_ref(cred);
		cred = kauth_cred_setgroups(cred, &newgroups[0], ngrp, gmuid);
		thread_ro_update_cred(tro, cred);
		kauth_cred_unref(&cred);
	} else {
		proc_update_label(p, true, ^(kauth_cred_t cur_cred) {
			return kauth_cred_setgroups(cur_cred, &newgroups[0], ngrp, gmuid);
		});

		AUDIT_ARG(groupset, &newgroups[0], ngrp);
	}

	return 0;
}


/*
 * initgroups
 *
 * Description: Initialize the default supplementary groups list and set the
 *		gmuid for use by the external group resolver (if any)
 *
 * Parameters:	uap->gidsetsize			Number of groups in set
 *		uap->gidset			Pointer to group list
 *		uap->gmuid			Base gid
 *
 * Returns:	0				Success
 *	setgroups1:EPERM			Permision denied
 *	setgroups1:EINVAL			Invalid gidsetsize value
 *	setgroups1:EFAULT			Bad gidset or gidsetsize is
 *
 * Notes:	This function opts *IN* to memberd participation
 *
 *		The normal purpose of this function is for a privileged
 *		process to indicate supplementary groups and identity for
 *		participation in extended group membership resolution prior
 *		to dropping privilege by assuming a specific user identity.
 *
 *		It is the first half of the primary mechanism whereby user
 *		identity is established to the system by programs such as
 *		/usr/bin/login.  The second half is the drop of uid privilege
 *		for a specific uid corresponding to the user.
 *
 * See also:	setgroups1()
 */
int
initgroups(proc_t p, struct initgroups_args *uap, __unused int32_t *retval)
{
	return setgroups1(p, uap->gidsetsize, uap->gidset, uap->gmuid, retval);
}


/*
 * setgroups
 *
 * Description: Initialize the default supplementary groups list
 *
 * Parameters:	gidsetsize			Number of groups in set
 *		gidset				Pointer to group list
 *
 * Returns:	0				Success
 *	setgroups1:EPERM			Permision denied
 *	setgroups1:EINVAL			Invalid gidsetsize value
 *	setgroups1:EFAULT			Bad gidset or gidsetsize is
 *
 * Notes:	This functions opts *OUT* of memberd participation.
 *
 *		This function exists for compatibility with POSIX.  Most user
 *		programs should use initgroups() instead to ensure correct
 *		participation in group membership resolution when utilizing
 *		a directory service for authentication.
 *
 *		It is identical to an initgroups() call with a gmuid argument
 *		of KAUTH_UID_NONE.
 *
 * See also:	setgroups1()
 */
int
setgroups(proc_t p, struct setgroups_args *uap, __unused int32_t *retval)
{
	return setgroups1(p, uap->gidsetsize, uap->gidset, KAUTH_UID_NONE, retval);
}


/*
 * Set the per-thread/per-process supplementary groups list.
 *
 * XXX implement setsgroups
 *
 */

int
setsgroups(__unused proc_t p, __unused struct setsgroups_args *uap, __unused int32_t *retval)
{
	return ENOTSUP;
}

/*
 * Set the per-thread/per-process whiteout groups list.
 *
 * XXX implement setwgroups
 *
 */

int
setwgroups(__unused proc_t p, __unused struct setwgroups_args *uap, __unused int32_t *retval)
{
	return ENOTSUP;
}


/*
 * Check if gid is a member of the group set.
 *
 * XXX This interface is going away; use kauth_cred_ismember_gid() directly
 * XXX instead.
 */
int
groupmember(gid_t gid, kauth_cred_t cred)
{
	int is_member;

	if (kauth_cred_ismember_gid(cred, gid, &is_member) == 0 && is_member) {
		return 1;
	}
	return 0;
}


/*
 * Test whether the specified credentials imply "super-user"
 * privilege; if so, and we have accounting info, set the flag
 * indicating use of super-powers.
 * Returns 0 or error.
 *
 * XXX This interface is going away; use kauth_cred_issuser() directly
 * XXX instead.
 *
 * Note:	This interface exists to implement the "has used privilege"
 *		bit (ASU) in the p_acflags field of the process, which is
 *		only externalized via private sysctl and in process accounting
 *		records.  The flag is technically not required in either case.
 */
int
suser(kauth_cred_t cred, u_short *acflag)
{
	if (kauth_cred_getuid(cred) == 0) {
		if (acflag) {
			*acflag |= ASU;
		}
		return 0;
	}
	return EPERM;
}


/*
 * getlogin
 *
 * Description:	Get login name, if available.
 *
 * Parameters:	uap->namebuf			User buffer for return
 *		uap->namelen			User buffer length
 *
 * Returns:	0				Success
 *	copyout:EFAULT
 *
 * Notes:	Intended to obtain a string containing the user name of the
 *		user associated with the controlling terminal for the calling
 *		process.
 *
 *		Not very useful on modern systems, due to inherent length
 *		limitations for the static array in the session structure
 *		which is used to store the login name.
 *
 *		Permitted to return NULL
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getlogin(proc_t p, struct getlogin_args *uap, __unused int32_t *retval)
{
	char buffer[MAXLOGNAME];
	struct session *sessp;
	struct pgrp *pg;

	if (uap->namelen > MAXLOGNAME) {
		uap->namelen = MAXLOGNAME;
	}

	if ((pg = proc_pgrp(p, &sessp)) != PGRP_NULL) {
		session_lock(sessp);
		bcopy(sessp->s_login, buffer, uap->namelen);
		session_unlock(sessp);
		pgrp_rele(pg);
	} else {
		bzero(buffer, uap->namelen);
	}

	return copyout((caddr_t)buffer, uap->namebuf, uap->namelen);
}

void
setlogin_internal(proc_t p, const char login[static MAXLOGNAME])
{
	struct session *sessp;
	struct pgrp *pg;

	if ((pg = proc_pgrp(p, &sessp)) != PGRP_NULL) {
		session_lock(sessp);
		bcopy(login, sessp->s_login, MAXLOGNAME);
		session_unlock(sessp);
		pgrp_rele(pg);
	}
}

/*
 * setlogin
 *
 * Description:	Set login name.
 *
 * Parameters:	uap->namebuf			User buffer containing name
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *	copyinstr:EFAULT			User buffer invalid
 *	copyinstr:EINVAL			Supplied name was too long
 *
 * Notes:	This is a utility system call to support getlogin().
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setlogin(proc_t p, struct setlogin_args *uap, __unused int32_t *retval)
{
	int error;
	size_t dummy = 0;
	char buffer[MAXLOGNAME + 1];

	if ((error = proc_suser(p))) {
		return error;
	}

	bzero(&buffer[0], MAXLOGNAME + 1);


	error = copyinstr(uap->namebuf,
	    (caddr_t) &buffer[0],
	    MAXLOGNAME - 1, (size_t *)&dummy);

	setlogin_internal(p, buffer);

	if (!error) {
		AUDIT_ARG(text, buffer);
	} else if (error == ENAMETOOLONG) {
		error = EINVAL;
	}
	return error;
}


/* Set the secrity token of the task with current euid and eguid */
/*
 * XXX This needs to change to give the task a reference and/or an opaque
 * XXX identifier.
 */
int
set_security_token(proc_t p)
{
	return set_security_token_task_internal(p, proc_task(p));
}

static void
proc_calc_audit_token(proc_t p, kauth_cred_t my_cred, audit_token_t *audit_token)
{
	posix_cred_t my_pcred = posix_cred_get(my_cred);

	/*
	 * The current layout of the Mach audit token explicitly
	 * adds these fields.  But nobody should rely on such
	 * a literal representation.  Instead, the BSM library
	 * provides a function to convert an audit token into
	 * a BSM subject.  Use of that mechanism will isolate
	 * the user of the trailer from future representation
	 * changes.
	 */
	audit_token->val[0] = my_cred->cr_audit.as_aia_p->ai_auid;
	audit_token->val[1] = my_pcred->cr_uid;
	audit_token->val[2] = my_pcred->cr_gid;
	audit_token->val[3] = my_pcred->cr_ruid;
	audit_token->val[4] = my_pcred->cr_rgid;
	audit_token->val[5] = proc_getpid(p);
	audit_token->val[6] = my_cred->cr_audit.as_aia_p->ai_asid;
	audit_token->val[7] = proc_pidversion(p);
}

/*
 * Set the secrity token of the task with current euid and eguid
 * The function takes a proc and a task, where proc->task might point to a
 * different task if called from exec.
 */

int
set_security_token_task_internal(proc_t p, void *t)
{
	kauth_cred_t my_cred;
	security_token_t sec_token;
	audit_token_t    audit_token;
	host_priv_t host_priv;
	task_t task = t;


	my_cred = kauth_cred_proc_ref(p);

	proc_calc_audit_token(p, my_cred, &audit_token);

	sec_token.val[0] = kauth_cred_getuid(my_cred);
	sec_token.val[1] = kauth_cred_getgid(my_cred);

	host_priv = (sec_token.val[0]) ? HOST_PRIV_NULL : host_priv_self();
#if CONFIG_MACF
	if (host_priv != HOST_PRIV_NULL && mac_system_check_host_priv(my_cred)) {
		host_priv = HOST_PRIV_NULL;
	}
#endif
	kauth_cred_unref(&my_cred);

#if DEVELOPMENT || DEBUG
	/*
	 * Update the pid an proc name for importance base if any
	 */
	task_importance_update_owner_info(task);
#endif

	return task_set_security_tokens(task, sec_token, audit_token,
	           host_priv) != KERN_SUCCESS;
}

void
proc_parent_audit_token(proc_t p, audit_token_t *token_out)
{
	proc_t parent;
	kauth_cred_t my_cred;

	proc_list_lock();

	parent = p->p_pptr;
	my_cred = kauth_cred_proc_ref(parent);
	proc_calc_audit_token(parent, my_cred, token_out);
	kauth_cred_unref(&my_cred);

	proc_list_unlock();
}


int get_audit_token_pid(audit_token_t *audit_token);

int
get_audit_token_pid(audit_token_t *audit_token)
{
	/* keep in-sync with set_security_token (above) */
	if (audit_token) {
		return (int)audit_token->val[5];
	}
	return -1;
}


/*
 * Fill in a struct xucred based on a kauth_cred_t.
 */
void
cru2x(kauth_cred_t cr, struct xucred *xcr)
{
	posix_cred_t pcr = posix_cred_get(cr);

	bzero(xcr, sizeof(*xcr));
	xcr->cr_version = XUCRED_VERSION;
	xcr->cr_uid = kauth_cred_getuid(cr);
	xcr->cr_ngroups = pcr->cr_ngroups;
	bcopy(pcr->cr_groups, xcr->cr_groups, sizeof(xcr->cr_groups));
}

/*
 * Copy kauth_cred into a virtual address by assignment.
 * Needed because elements of kauth_cred are PACed
 * so memcpy doesn't work.
 */
void
kauth_cred_copy(const uintptr_t kv, const uintptr_t new_data)
{
	*(kauth_cred_t)kv = *(kauth_cred_t)new_data;
}
