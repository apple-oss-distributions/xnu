/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)kern_fork.c	8.8 (Berkeley) 2/14/95
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <kern/assert.h>
#include <kern/bits.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/user.h>
#include <sys/reason.h>
#include <sys/resourcevar.h>
#include <sys/vnode_internal.h>
#include <sys/file_internal.h>
#include <sys/acct.h>
#include <sys/codesign.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/ulock.h>
#if CONFIG_PERSONAS
#include <sys/persona.h>
#endif
#include <sys/doc_tombstone.h>
#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
extern void (*dtrace_proc_waitfor_exec_ptr)(proc_t);
extern void dtrace_proc_fork(proc_t, proc_t, int);

/*
 * Since dtrace_proc_waitfor_exec_ptr can be added/removed in dtrace_subr.c,
 * we will store its value before actually calling it.
 */
static void (*dtrace_proc_waitfor_hook)(proc_t) = NULL;

#include <sys/dtrace_ptss.h>
#endif

#include <security/audit/audit.h>

#include <mach/mach_types.h>
#include <kern/coalition.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <kern/zalloc.h>

#include <os/log.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#include <security/mac_mach_internal.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_shared_region.h>

#include <sys/shm_internal.h>   /* for shmfork() */
#include <mach/task.h>          /* for thread_create() */
#include <mach/thread_act.h>    /* for thread_resume() */

#include <sys/sdt.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

/* XXX routines which should have Mach prototypes, but don't */
void thread_set_parent(thread_t parent, int pid);
extern void act_thread_catt(void *ctx);
void thread_set_child(thread_t child, int pid);
boolean_t thread_is_active(thread_t thread);
void *act_thread_csave(void);
extern boolean_t task_is_exec_copy(task_t);
int nextpidversion = 0;

void ipc_task_enable(task_t task);

proc_t forkproc(proc_t, cloneproc_flags_t);
void forkproc_free(proc_t);
thread_t fork_create_child(task_t parent_task,
    coalition_t *parent_coalitions,
    proc_t child,
    int is_64bit_addr,
    int is_64bit_data,
    cloneproc_flags_t clone_flags);

__private_extern__ const size_t uthread_size = sizeof(struct uthread);
static LCK_GRP_DECLARE(rethrottle_lock_grp, "rethrottle");

os_refgrp_decl(, p_refgrp, "proc", NULL);

extern const size_t task_alignment;
const size_t proc_alignment = _Alignof(struct proc);

extern size_t task_struct_size;
size_t proc_struct_size = sizeof(struct proc);
size_t proc_and_task_size;

ZONE_DECLARE_ID(ZONE_ID_PROC_TASK, struct proc);
SECURITY_READ_ONLY_LATE(zone_t) proc_task_zone;

KALLOC_TYPE_DEFINE(proc_stats_zone, struct pstats, KT_DEFAULT);

/*
 * fork1
 *
 * Description:	common code used by all new process creation other than the
 *		bootstrap of the initial process on the system
 *
 * Parameters: parent_proc		parent process of the process being
 *		child_threadp		pointer to location to receive the
 *					Mach thread_t of the child process
 *					created
 *		kind			kind of creation being requested
 *		coalitions		if spawn, the set of coalitions the
 *					child process should join, or NULL to
 *					inherit the parent's. On non-spawns,
 *					this param is ignored and the child
 *					always inherits the parent's
 *					coalitions.
 *
 * Notes:	Permissable values for 'kind':
 *
 *		PROC_CREATE_FORK	Create a complete process which will
 *					return actively running in both the
 *					parent and the child; the child copies
 *					the parent address space.
 *		PROC_CREATE_SPAWN	Create a complete process which will
 *					return actively running in the parent
 *					only after returning actively running
 *					in the child; the child address space
 *					is newly created by an image activator,
 *					after which the child is run.
 *
 *		At first it may seem strange that we return the child thread
 *		address rather than process structure, since the process is
 *		the only part guaranteed to be "new"; however, since we do
 *		not actualy adjust other references between Mach and BSD, this
 *		is the only method which guarantees us the ability to get
 *		back to the other information.
 */
int
fork1(proc_t parent_proc, thread_t *child_threadp, int kind, coalition_t *coalitions)
{
	proc_t child_proc = NULL;       /* set in switch, but compiler... */
	thread_t child_thread = NULL;
	uid_t uid;
	size_t count;
	int err = 0;
	int spawn = 0;
	rlim_t rlimit_nproc_cur;

	/*
	 * Although process entries are dynamically created, we still keep
	 * a global limit on the maximum number we will create.  Don't allow
	 * a nonprivileged user to use the last process; don't let root
	 * exceed the limit. The variable nprocs is the current number of
	 * processes, maxproc is the limit.
	 */
	uid = kauth_getruid();
	proc_list_lock();
	if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
#if (DEVELOPMENT || DEBUG) && !defined(XNU_TARGET_OS_OSX)
		/*
		 * On the development kernel, panic so that the fact that we hit
		 * the process limit is obvious, as this may very well wedge the
		 * system.
		 */
		panic("The process table is full; parent pid=%d", proc_getpid(parent_proc));
#endif
		proc_list_unlock();
		tablefull("proc");
		return EAGAIN;
	}
	proc_list_unlock();

	/*
	 * Increment the count of procs running with this uid. Don't allow
	 * a nonprivileged user to exceed their current limit, which is
	 * always less than what an rlim_t can hold.
	 * (locking protection is provided by list lock held in chgproccnt)
	 */
	count = chgproccnt(uid, 1);
	rlimit_nproc_cur = proc_limitgetcur(parent_proc, RLIMIT_NPROC);
	if (uid != 0 &&
	    (rlim_t)count > rlimit_nproc_cur) {
#if (DEVELOPMENT || DEBUG) && !defined(XNU_TARGET_OS_OSX)
		/*
		 * On the development kernel, panic so that the fact that we hit
		 * the per user process limit is obvious.  This may be less dire
		 * than hitting the global process limit, but we cannot rely on
		 * that.
		 */
		panic("The per-user process limit has been hit; parent pid=%d, uid=%d", proc_getpid(parent_proc), uid);
#endif
		err = EAGAIN;
		goto bad;
	}

#if CONFIG_MACF
	/*
	 * Determine if MAC policies applied to the process will allow
	 * it to fork.  This is an advisory-only check.
	 */
	err = mac_proc_check_fork(parent_proc);
	if (err != 0) {
		goto bad;
	}
#endif

	switch (kind) {
	case PROC_CREATE_SPAWN:
		/*
		 * A spawned process differs from a forked process in that
		 * the spawned process does not carry around the parents
		 * baggage with regard to address space copying, dtrace,
		 * and so on.
		 */
		spawn = 1;

		OS_FALLTHROUGH;

	case PROC_CREATE_FORK:
		/*
		 * When we clone the parent process, we are going to inherit
		 * its task attributes and memory, since when we fork, we
		 * will, in effect, create a duplicate of it, with only minor
		 * differences.  Contrarily, spawned processes do not inherit.
		 */
		if ((child_thread = cloneproc(proc_task(parent_proc),
		    spawn ? coalitions : NULL,
		    parent_proc,
		    spawn ? CLONEPROC_FLAGS_NONE : CLONEPROC_FLAGS_INHERIT_MEMORY)) == NULL) {
			/* Failed to create thread */
			err = EAGAIN;
			goto bad;
		}

		/* child_proc = child_thread->task->proc; */
		child_proc = (proc_t)(get_bsdtask_info(get_threadtask(child_thread)));

		if (!spawn) {
			/* Copy current thread state into the child thread (only for fork) */
			thread_dup(child_thread);
			/*
			 * Also enable task ports for the new task for fork. In the spawn
			 * case, task ports enablement is delayed until after image activation
			 * since task map will be swapped during mach executable loading.
			 */
			ipc_task_enable(get_threadtask(child_thread));
		}

// XXX BEGIN: wants to move to be common code (and safe)
#if CONFIG_MACF
		/*
		 * allow policies to associate the credential/label that
		 * we referenced from the parent ... with the child
		 * JMM - this really isn't safe, as we can drop that
		 *       association without informing the policy in other
		 *       situations (keep long enough to get policies changed)
		 */
		mac_cred_label_associate_fork(proc_ucred(child_proc), child_proc);
#endif

		/*
		 * Propogate change of PID - may get new cred if auditing.
		 */
		set_security_token(child_proc);

		AUDIT_ARG(pid, proc_getpid(child_proc));

// XXX END: wants to move to be common code (and safe)

		/*
		 * Blow thread state information; this is what gives the child
		 * process its "return" value from a fork() call.
		 *
		 * Note: this should probably move to fork() proper, since it
		 * is not relevent to spawn, and the value won't matter
		 * until we resume the child there.  If you are in here
		 * refactoring code, consider doing this at the same time.
		 */
		thread_set_child(child_thread, proc_getpid(child_proc));

		child_proc->p_acflag = AFORK;   /* forked but not exec'ed */

#if CONFIG_DTRACE
		dtrace_proc_fork(parent_proc, child_proc, spawn);
#endif  /* CONFIG_DTRACE */
		if (!spawn) {
			/*
			 * Of note, we need to initialize the bank context behind
			 * the protection of the proc_trans lock to prevent a race with exit.
			 */
			task_bank_init(get_threadtask(child_thread));
		}

		break;

	default:
		panic("fork1 called with unknown kind %d", kind);
		break;
	}


	/* return the thread pointer to the caller */
	*child_threadp = child_thread;

bad:
	/*
	 * In the error case, we return a 0 value for the returned pid (but
	 * it is ignored in the trampoline due to the error return); this
	 * is probably not necessary.
	 */
	if (err) {
		(void)chgproccnt(uid, -1);
	}

	return err;
}




/*
 * fork_create_child
 *
 * Description:	Common operations associated with the creation of a child
 *		process. Return with new task and first thread's control port movable
 *      and not pinned.
 *
 * Parameters:	parent_task		parent task
 *		parent_coalitions	parent's set of coalitions
 *		child_proc			child process
 *		inherit_memory		TRUE, if the parents address space is
 *							to be inherited by the child
 *		is_64bit_addr		TRUE, if the child being created will
 *							be associated with a 64 bit address space
 *		is_64bit_data		TRUE if the child being created will use a
 *                                                       64-bit register state
 *		in_exec				TRUE, if called from execve or posix spawn set exec
 *							FALSE, if called from fork or vfexec
 *
 * Note:	This code is called in the fork() case, from the execve() call
 *		graph, from the posix_spawn() call graph (which implicitly
 *		includes a vfork() equivalent call, and in the system
 *		bootstrap case.
 *
 *		It creates a new task and thread (and as a side effect of the
 *		thread creation, a uthread) in the parent coalition set, which is
 *		then associated with the process 'child'.  If the parent
 *		process address space is to be inherited, then a flag
 *		indicates that the newly created task should inherit this from
 *		the child task.
 *
 *		As a special concession to bootstrapping the initial process
 *		in the system, it's possible for 'parent_task' to be TASK_NULL;
 *		in this case, 'inherit_memory' MUST be FALSE.
 */
thread_t
fork_create_child(task_t parent_task,
    coalition_t *parent_coalitions,
    proc_t child_proc,
    int is_64bit_addr,
    int is_64bit_data,
    cloneproc_flags_t clone_flags)
{
	thread_t        child_thread = NULL;
	task_t          child_task;
	kern_return_t   result;
	proc_ro_t       proc_ro;
	bool inherit_memory = !!(clone_flags & CLONEPROC_FLAGS_INHERIT_MEMORY);
	bool in_exec = !!(clone_flags & CLONEPROC_FLAGS_FOR_EXEC);

	proc_ro = proc_get_ro(child_proc);
	if (proc_ro_task(proc_ro) != NULL) {
		panic("Proc_ro_task for newly created proc %p is not NULL", child_proc);
	}

	child_task = proc_get_task_raw(child_proc);

	/*
	 * Create a new task for the child process, IPC access to the new task will
	 * be set up after task has been fully initialized.
	 */
	result = task_create_internal(parent_task,
	    proc_ro,
	    parent_coalitions,
	    inherit_memory,
	    is_64bit_addr,
	    is_64bit_data,
	    TF_NONE,
	    TF_NONE,
	    in_exec ? TPF_EXEC_COPY : TPF_NONE,                        /* Mark the task exec copy if in execve */
	    (TRW_LRETURNWAIT | TRW_LRETURNWAITER),                     /* All created threads will wait in task_wait_to_return */
	    child_task);
	if (result != KERN_SUCCESS) {
		printf("%s: task_create_internal failed.  Code: %d\n",
		    __func__, result);
		goto bad;
	}

	/* Set the child proc process to child task */
	proc_set_task(child_proc, child_task);

	/* Set child task process to child proc */
	set_bsdtask_info(child_task, child_proc);

	/* Propagate CPU limit timer from parent */
	if (timerisset(&child_proc->p_rlim_cpu)) {
		task_vtimer_set(child_task, TASK_VTIMER_RLIM);
	}

	/*
	 * Set child process BSD visible scheduler priority if nice value
	 * inherited from parent
	 */
	if (child_proc->p_nice != 0) {
		resetpriority(child_proc);
	}

	/*
	 * Create main thread for the child process. Its control port is not immovable/pinned
	 * until main_thread_set_immovable_pinned().
	 *
	 * The new thread is waiting on the event triggered by 'task_clear_return_wait'
	 */
	result = main_thread_create_waiting(child_task,
	    (thread_continue_t)task_wait_to_return,
	    task_get_return_wait_event(child_task),
	    &child_thread);

	if (result != KERN_SUCCESS) {
		printf("%s: thread_create failed. Code: %d\n",
		    __func__, result);
		task_deallocate(child_task);
		child_task = NULL;
	}

	/*
	 * Tag thread as being the first thread in its task.
	 */
	thread_set_tag(child_thread, THREAD_TAG_MAINTHREAD);

bad:
	thread_yield_internal(1);

	return child_thread;
}


/*
 * fork
 *
 * Description:	fork system call.
 *
 * Parameters:	parent			Parent process to fork
 *		uap (void)		[unused]
 *		retval			Return value
 *
 * Returns:	0			Success
 *		EAGAIN			Resource unavailable, try again
 *
 * Notes:	Attempts to create a new child process which inherits state
 *		from the parent process.  If successful, the call returns
 *		having created an initially suspended child process with an
 *		extra Mach task and thread reference, for which the thread
 *		is initially suspended.  Until we resume the child process,
 *		it is not yet running.
 *
 *		The return information to the child is contained in the
 *		thread state structure of the new child, and does not
 *		become visible to the child through a normal return process,
 *		since it never made the call into the kernel itself in the
 *		first place.
 *
 *		After resuming the thread, this function returns directly to
 *		the parent process which invoked the fork() system call.
 *
 * Important:	The child thread_resume occurs before the parent returns;
 *		depending on scheduling latency, this means that it is not
 *		deterministic as to whether the parent or child is scheduled
 *		to run first.  It is entirely possible that the child could
 *		run to completion prior to the parent running.
 */
int
fork(proc_t parent_proc, __unused struct fork_args *uap, int32_t *retval)
{
	thread_t child_thread;
	int err;

	retval[1] = 0;          /* flag parent return for user space */

	if ((err = fork1(parent_proc, &child_thread, PROC_CREATE_FORK, NULL)) == 0) {
		task_t child_task;
		proc_t child_proc;

		/* Return to the parent */
		child_proc = (proc_t)get_bsdthreadtask_info(child_thread);
		retval[0] = proc_getpid(child_proc);

		child_task = (task_t)get_threadtask(child_thread);
		assert(child_task != TASK_NULL);

		/* task_control_port_options has been inherited from parent, apply it */
		task_set_immovable_pinned(child_task);
		main_thread_set_immovable_pinned(child_thread);

		/*
		 * Drop the signal lock on the child which was taken on our
		 * behalf by forkproc()/cloneproc() to prevent signals being
		 * received by the child in a partially constructed state.
		 */
		proc_signalend(child_proc, 0);
		proc_transend(child_proc, 0);

		/* flag the fork has occurred */
		proc_knote(parent_proc, NOTE_FORK | proc_getpid(child_proc));
		DTRACE_PROC1(create, proc_t, child_proc);

#if CONFIG_DTRACE
		if ((dtrace_proc_waitfor_hook = dtrace_proc_waitfor_exec_ptr) != NULL) {
			(*dtrace_proc_waitfor_hook)(child_proc);
		}
#endif

		/*
		 * If current process died during the fork, the child would contain
		 * non consistent vmmap, kill the child and reap it internally.
		 */
		if (parent_proc->p_lflag & P_LEXIT || !thread_is_active(current_thread())) {
			task_terminate_internal(child_task);
			proc_list_lock();
			child_proc->p_listflag |= P_LIST_DEADPARENT;
			proc_list_unlock();
		}

		/* "Return" to the child */
		task_clear_return_wait(get_threadtask(child_thread), TCRW_CLEAR_ALL_WAIT);

		/* drop the extra references we got during the creation */
		task_deallocate(child_task);
		thread_deallocate(child_thread);
	}

	return err;
}


/*
 * cloneproc
 *
 * Description: Create a new process from a specified process.
 *
 * Parameters:	parent_task		The parent task to be cloned, or
 *					TASK_NULL is task characteristics
 *					are not to be inherited
 *					be cloned, or TASK_NULL if the new
 *					task is not to inherit the VM
 *					characteristics of the parent
 *		parent_proc		The parent process to be cloned
 *		clone_flags		Clone flags to specify if the cloned
 *					process should inherit memory,
 *					marked as memory stat internal,
 *					or if the cloneproc is called for exec.
 *
 * Returns:	!NULL			pointer to new child thread
 *		NULL			Failure (unspecified)
 *
 * Note:	On return newly created child process has signal lock held
 *		to block delivery of signal to it if called with lock set.
 *		fork() code needs to explicity remove this lock before
 *		signals can be delivered
 *
 *		In the case of bootstrap, this function can be called from
 *		bsd_utaskbootstrap() in order to bootstrap the first process;
 *		the net effect is to provide a uthread structure for the
 *		kernel process associated with the kernel task.
 *
 * XXX:		Tristating using the value parent_task as the major key
 *		and inherit_memory as the minor key is something we should
 *		refactor later; we owe the current semantics, ultimately,
 *		to the semantics of task_create_internal.  For now, we will
 *		live with this being somewhat awkward.
 */
thread_t
cloneproc(task_t parent_task, coalition_t *parent_coalitions, proc_t parent_proc, cloneproc_flags_t clone_flags)
{
#if !CONFIG_MEMORYSTATUS
#pragma unused(memstat_internal)
#endif
	task_t child_task;
	proc_t child_proc;
	thread_t child_thread = NULL;
	bool memstat_internal = !!(clone_flags & CLONEPROC_FLAGS_MEMSTAT_INTERNAL);
	bool in_exec = !!(clone_flags & CLONEPROC_FLAGS_FOR_EXEC);

	if ((child_proc = forkproc(parent_proc, clone_flags)) == NULL) {
		/* Failed to allocate new process */
		goto bad;
	}

	/*
	 * In the case where the parent_task is TASK_NULL (during the init path)
	 * we make the assumption that the register size will be the same as the
	 * address space size since there's no way to determine the possible
	 * register size until an image is exec'd.
	 *
	 * The only architecture that has different address space and register sizes
	 * (arm64_32) isn't being used within kernel-space, so the above assumption
	 * always holds true for the init path.
	 */
	const int parent_64bit_addr = parent_proc->p_flag & P_LP64;
	const int parent_64bit_data = (parent_task == TASK_NULL) ? parent_64bit_addr : task_get_64bit_data(parent_task);

	child_thread = fork_create_child(parent_task,
	    parent_coalitions,
	    child_proc,
	    parent_64bit_addr,
	    parent_64bit_data,
	    clone_flags);

	if (child_thread == NULL) {
		/*
		 * Failed to create thread; now we must deconstruct the new
		 * process previously obtained from forkproc().
		 */
		forkproc_free(child_proc);
		goto bad;
	}

	child_task = get_threadtask(child_thread);
	if (parent_64bit_addr) {
		OSBitOrAtomic(P_LP64, (UInt32 *)&child_proc->p_flag);
		get_bsdthread_info(child_thread)->uu_flag |= UT_LP64;
	} else {
		OSBitAndAtomic(~((uint32_t)P_LP64), (UInt32 *)&child_proc->p_flag);
		get_bsdthread_info(child_thread)->uu_flag &= ~UT_LP64;
	}

#if CONFIG_MEMORYSTATUS
	if (memstat_internal ||
	    (in_exec && (parent_proc->p_memstat_state & P_MEMSTAT_INTERNAL))) {
		proc_list_lock();
		child_proc->p_memstat_state |= P_MEMSTAT_INTERNAL;
		proc_list_unlock();
	}
	if (in_exec && parent_proc->p_memstat_relaunch_flags != P_MEMSTAT_RELAUNCH_UNKNOWN) {
		memorystatus_relaunch_flags_update(child_proc, parent_proc->p_memstat_relaunch_flags);
	}
#endif

	/* make child visible */
	pinsertchild(parent_proc, child_proc, in_exec);

	/*
	 * Make child runnable, set start time.
	 */
	child_proc->p_stat = SRUN;
bad:
	return child_thread;
}

void
proc_set_sigact(proc_t p, int sig, user_addr_t sigact)
{
	assert((sig > 0) && (sig < NSIG));

	p->p_sigacts.ps_sigact[sig] = sigact;
}

void
proc_set_trampact(proc_t p, int sig, user_addr_t trampact)
{
	assert((sig > 0) && (sig < NSIG));

	p->p_sigacts.ps_trampact[sig] = trampact;
}

void
proc_set_sigact_trampact(proc_t p, int sig, user_addr_t sigact, user_addr_t trampact)
{
	assert((sig > 0) && (sig < NSIG));

	p->p_sigacts.ps_sigact[sig] = sigact;
	p->p_sigacts.ps_trampact[sig] = trampact;
}

void
proc_reset_sigact(proc_t p, sigset_t sigs)
{
	user_addr_t *sigacts = p->p_sigacts.ps_sigact;
	int nc;

	while (sigs) {
		nc = ffs((unsigned int)sigs);
		if (sigacts[nc] != SIG_DFL) {
			sigacts[nc] = SIG_DFL;
		}
		sigs &= ~sigmask(nc);
	}
}

/*
 * Destroy a process structure that resulted from a call to forkproc(), but
 * which must be returned to the system because of a subsequent failure
 * preventing it from becoming active.
 *
 * Parameters:	p			The incomplete process from forkproc()
 *
 * Returns:	(void)
 *
 * Note:	This function should only be used in an error handler following
 *		a call to forkproc().
 *
 *		Operations occur in reverse order of those in forkproc().
 */
void
forkproc_free(proc_t p)
{
	struct pgrp *pg;

#if CONFIG_PERSONAS
	persona_proc_drop(p);
#endif /* CONFIG_PERSONAS */

#if PSYNCH
	pth_proc_hashdelete(p);
#endif /* PSYNCH */

	/* We held signal and a transition locks; drop them */
	proc_signalend(p, 0);
	proc_transend(p, 0);

	/*
	 * If we have our own copy of the resource limits structure, we
	 * need to free it.  If it's a shared copy, we need to drop our
	 * reference on it.
	 */
	proc_limitdrop(p);

#if SYSV_SHM
	/* Need to drop references to the shared memory segment(s), if any */
	if (p->vm_shm) {
		/*
		 * Use shmexec(): we have no address space, so no mappings
		 *
		 * XXX Yes, the routine is badly named.
		 */
		shmexec(p);
	}
#endif

	/* Need to undo the effects of the fdt_fork(), if any */
	fdt_invalidate(p);
	fdt_destroy(p);

	/*
	 * Drop the reference on a text vnode pointer, if any
	 * XXX This code is broken in forkproc(); see <rdar://4256419>;
	 * XXX if anyone ever uses this field, we will be extremely unhappy.
	 */
	if (p->p_textvp) {
		vnode_rele(p->p_textvp);
		p->p_textvp = NULL;
	}

	/* Update the audit session proc count */
	AUDIT_SESSION_PROCEXIT(p);

	lck_mtx_destroy(&p->p_mlock, &proc_mlock_grp);
	lck_mtx_destroy(&p->p_ucred_mlock, &proc_ucred_mlock_grp);
#if CONFIG_DTRACE
	lck_mtx_destroy(&p->p_dtrace_sprlock, &proc_lck_grp);
#endif
	lck_spin_destroy(&p->p_slock, &proc_slock_grp);

	/* Release the credential reference */
	proc_set_ucred(p, NOCRED);

	proc_list_lock();
	/* Decrement the count of processes in the system */
	nprocs--;

	/* quit the group */
	pg = pgrp_leave_locked(p);

	/* Take it out of process hash */
	assert((os_ref_get_raw_mask(&p->p_refcount) >> P_REF_BITS) == 1);
	assert((os_ref_get_raw_mask(&p->p_refcount) & P_REF_NEW) == P_REF_NEW);
	os_atomic_xor(&p->p_refcount, P_REF_NEW | P_REF_DEAD, relaxed);

	/* Remove from hash if not a shadow proc */
	if (!proc_is_shadow(p)) {
		phash_remove_locked(p);
	}

	proc_list_unlock();

	pgrp_rele(pg);

	thread_call_free(p->p_rcall);

	/* Free allocated memory */
	zfree(proc_stats_zone, p->p_stats);
	p->p_stats = NULL;
	if (p->p_subsystem_root_path) {
		zfree(ZV_NAMEI, p->p_subsystem_root_path);
		p->p_subsystem_root_path = NULL;
	}

	p->p_proc_ro = proc_ro_release_proc(p->p_proc_ro);
	if (p->p_proc_ro != NULL) {
		proc_ro_free(p->p_proc_ro);
		p->p_proc_ro = NULL;
	}

	proc_checkdeadrefs(p);
	proc_wait_release(p);
}


/*
 * forkproc
 *
 * Description:	Create a new process structure, given a parent process
 *		structure.
 *
 * Parameters:	parent_proc		The parent process
 *
 * Returns:	!NULL			The new process structure
 *		NULL			Error (insufficient free memory)
 *
 * Note:	When successful, the newly created process structure is
 *		partially initialized; if a caller needs to deconstruct the
 *		returned structure, they must call forkproc_free() to do so.
 */
proc_t
forkproc(proc_t parent_proc, cloneproc_flags_t clone_flags)
{
	static uint64_t nextuniqueid = 0;
	static pid_t lastpid = 0;

	proc_t child_proc;      /* Our new process */
	int error = 0;
	struct pgrp *pg;
	uthread_t parent_uthread = current_uthread();
	rlim_t rlimit_cpu_cur;
	pid_t pid;
	struct proc_ro_data proc_ro_data = {};
	bool in_exec = !!(clone_flags & CLONEPROC_FLAGS_FOR_EXEC);

	child_proc = zalloc_flags(proc_task_zone, Z_WAITOK | Z_ZERO);

	child_proc->p_stats = zalloc_flags(proc_stats_zone, Z_WAITOK | Z_ZERO);
	child_proc->p_sigacts = parent_proc->p_sigacts;
	os_ref_init_mask(&child_proc->p_refcount, P_REF_BITS, &p_refgrp, P_REF_NEW);
	os_ref_init_raw(&child_proc->p_waitref, &p_refgrp);
	proc_ref_hold_proc_task_struct(child_proc);

	/* allocate a callout for use by interval timers */
	child_proc->p_rcall = thread_call_allocate((thread_call_func_t)realitexpire, child_proc);


	/*
	 * Find an unused PID.
	 */

	fdt_init(child_proc);

	proc_list_lock();

	if (!in_exec) {
		pid = lastpid;
		do {
			/*
			 * If the process ID prototype has wrapped around,
			 * restart somewhat above 0, as the low-numbered procs
			 * tend to include daemons that don't exit.
			 */
			if (++pid >= PID_MAX) {
				pid = 100;
			}
			if (pid == lastpid) {
				panic("Unable to allocate a new pid");
			}

			/* if the pid stays in hash both for zombie and runniing state */
		} while (phash_find_locked(pid) != PROC_NULL ||
		    pghash_exists_locked(pid) ||
		    session_find_locked(pid) != SESSION_NULL);

		lastpid = pid;
		nprocs++;

		child_proc->p_pid = pid;
		proc_ro_data.p_idversion = OSIncrementAtomic(&nextpidversion);
		/* kernel process is handcrafted and not from fork, so start from 1 */
		proc_ro_data.p_uniqueid = ++nextuniqueid;

		/* Insert in the hash, and inherit our group (and session) */
		phash_insert_locked(child_proc);

		/* Check if the proc is from App Cryptex */
		if (parent_proc->p_ladvflag & P_RSR) {
			os_atomic_or(&child_proc->p_ladvflag, P_RSR, relaxed);
		}
	} else {
		/* For exec copy of the proc, copy the pid, pidversion and uniqueid of original proc */
		pid = parent_proc->p_pid;
		child_proc->p_pid = pid;
		proc_ro_data.p_idversion = parent_proc->p_proc_ro->p_idversion;
		proc_ro_data.p_uniqueid = parent_proc->p_proc_ro->p_uniqueid;

		nprocs++;
		os_atomic_or(&child_proc->p_refcount, P_REF_SHADOW, relaxed);
	}
	pg = pgrp_enter_locked(parent_proc, child_proc);
	proc_list_unlock();

	if (proc_ro_data.p_uniqueid == startup_serial_num_procs) {
		/*
		 * Turn off startup serial logging now that we have reached
		 * the defined number of startup processes.
		 */
		startup_serial_logging_active = false;
	}

	/*
	 * We've identified the PID we are going to use;
	 * initialize the new process structure.
	 */
	child_proc->p_stat = SIDL;

	/*
	 * The zero'ing of the proc was at the allocation time due to need
	 * for insertion to hash.  Copy the section that is to be copied
	 * directly from the parent.
	 */
	child_proc->p_forkcopy = parent_proc->p_forkcopy;

	proc_ro_data.syscall_filter_mask = proc_syscall_filter_mask(parent_proc);
	proc_ro_data.p_platform_data = proc_get_ro(parent_proc)->p_platform_data;

	/*
	 * Some flags are inherited from the parent.
	 * Duplicate sub-structures as needed.
	 * Increase reference counts on shared objects.
	 * The p_stats substruct is set in vm_fork.
	 */
#if CONFIG_DELAY_IDLE_SLEEP
	child_proc->p_flag = (parent_proc->p_flag & (P_LP64 | P_TRANSLATED | P_DISABLE_ASLR | P_DELAYIDLESLEEP | P_SUGID | P_AFFINITY));
#else /* CONFIG_DELAY_IDLE_SLEEP */
	child_proc->p_flag = (parent_proc->p_flag & (P_LP64 | P_TRANSLATED | P_DISABLE_ASLR | P_SUGID | P_AFFINITY));
#endif /* CONFIG_DELAY_IDLE_SLEEP */

	child_proc->p_vfs_iopolicy = (parent_proc->p_vfs_iopolicy & (P_VFS_IOPOLICY_VALID_MASK));

	child_proc->p_responsible_pid = parent_proc->p_responsible_pid;

	/*
	 * Note that if the current thread has an assumed identity, this
	 * credential will be granted to the new process.
	 */
	kauth_cred_set(&proc_ro_data.p_ucred, kauth_cred_get());

	lck_mtx_init(&child_proc->p_mlock, &proc_mlock_grp, &proc_lck_attr);
	lck_mtx_init(&child_proc->p_ucred_mlock, &proc_ucred_mlock_grp, &proc_lck_attr);
#if CONFIG_DTRACE
	lck_mtx_init(&child_proc->p_dtrace_sprlock, &proc_lck_grp, &proc_lck_attr);
#endif
	lck_spin_init(&child_proc->p_slock, &proc_slock_grp, &proc_lck_attr);

	klist_init(&child_proc->p_klist);

	if (child_proc->p_textvp != NULLVP) {
		/* bump references to the text vnode */
		/* Need to hold iocount across the ref call */
		if ((error = vnode_getwithref(child_proc->p_textvp)) == 0) {
			error = vnode_ref(child_proc->p_textvp);
			vnode_put(child_proc->p_textvp);
		}

		if (error != 0) {
			child_proc->p_textvp = NULLVP;
		}
	}

	/* Inherit the parent flags for code sign */
	proc_ro_data.p_csflags = ((uint32_t)proc_getcsflags(parent_proc) & ~CS_KILLED);

	child_proc->p_proc_ro = proc_ro_alloc(child_proc, &proc_ro_data, NULL, NULL);

	/* update cred on proc */
	proc_update_creds_onproc(child_proc);

	/* update audit session proc count */
	AUDIT_SESSION_PROCNEW(child_proc);

	/*
	 * Copy the parents per process open file table to the child; if
	 * there is a per-thread current working directory, set the childs
	 * per-process current working directory to that instead of the
	 * parents.
	 */
	if (fdt_fork(&child_proc->p_fd, parent_proc, parent_uthread->uu_cdir, in_exec) != 0) {
		forkproc_free(child_proc);
		child_proc = NULL;
		goto bad;
	}

#if SYSV_SHM
	if (parent_proc->vm_shm && !in_exec) {
		/* XXX may fail to attach shm to child */
		(void)shmfork(parent_proc, child_proc);
	}
#endif

	/*
	 * Child inherits the parent's plimit
	 */
	proc_limitfork(parent_proc, child_proc);

	rlimit_cpu_cur = proc_limitgetcur(child_proc, RLIMIT_CPU);
	if (rlimit_cpu_cur != RLIM_INFINITY) {
		child_proc->p_rlim_cpu.tv_sec = (rlimit_cpu_cur > __INT_MAX__) ? __INT_MAX__ : rlimit_cpu_cur;
	}

	if (in_exec) {
		/* Keep the original start time for exec'ed proc */
		child_proc->p_stats->ps_start = parent_proc->p_stats->ps_start;
		child_proc->p_start.tv_sec = parent_proc->p_start.tv_sec;
		child_proc->p_start.tv_usec = parent_proc->p_start.tv_usec;
	} else {
		/* Intialize new process stats, including start time */
		/* <rdar://6640543> non-zeroed portion contains garbage AFAICT */
		microtime_with_abstime(&child_proc->p_start, &child_proc->p_stats->ps_start);
	}

	if (pg->pg_session->s_ttyvp != NULL && parent_proc->p_flag & P_CONTROLT) {
		os_atomic_or(&child_proc->p_flag, P_CONTROLT, relaxed);
	}

	/*
	 * block all signals to reach the process.
	 * no transition race should be occuring with the child yet,
	 * but indicate that the process is in (the creation) transition.
	 */
	proc_signalstart(child_proc, 0);
	proc_transstart(child_proc, 0, 0);

	child_proc->p_pcaction = 0;

	TAILQ_INIT(&child_proc->p_uthlist);
	TAILQ_INIT(&child_proc->p_aio_activeq);
	TAILQ_INIT(&child_proc->p_aio_doneq);

	/*
	 * Copy work queue information
	 *
	 * Note: This should probably only happen in the case where we are
	 *	creating a child that is a copy of the parent; since this
	 *	routine is called in the non-duplication case of vfork()
	 *	or posix_spawn(), then this information should likely not
	 *	be duplicated.
	 *
	 * <rdar://6640553> Work queue pointers that no longer point to code
	 */
	child_proc->p_wqthread = parent_proc->p_wqthread;
	child_proc->p_threadstart = parent_proc->p_threadstart;
	child_proc->p_pthsize = parent_proc->p_pthsize;
	if ((parent_proc->p_lflag & P_LREGISTER) != 0) {
		child_proc->p_lflag |= P_LREGISTER;
	}
	child_proc->p_dispatchqueue_offset = parent_proc->p_dispatchqueue_offset;
	child_proc->p_dispatchqueue_serialno_offset = parent_proc->p_dispatchqueue_serialno_offset;
	child_proc->p_dispatchqueue_label_offset = parent_proc->p_dispatchqueue_label_offset;
	child_proc->p_return_to_kernel_offset = parent_proc->p_return_to_kernel_offset;
	child_proc->p_mach_thread_self_offset = parent_proc->p_mach_thread_self_offset;
	child_proc->p_pth_tsd_offset = parent_proc->p_pth_tsd_offset;
	child_proc->p_pthread_wq_quantum_offset = parent_proc->p_pthread_wq_quantum_offset;
#if PSYNCH
	pth_proc_hashinit(child_proc);
#endif /* PSYNCH */

#if CONFIG_PERSONAS
	child_proc->p_persona = NULL;
	error = persona_proc_inherit(child_proc, parent_proc);
	if (error != 0) {
		printf("forkproc: persona_proc_inherit failed (persona %d being destroyed?)\n", persona_id_from_proc(parent_proc));
		forkproc_free(child_proc);
		child_proc = NULL;
		goto bad;
	}
#endif

#if CONFIG_MEMORYSTATUS
	/* Memorystatus init */
	child_proc->p_memstat_state = 0;
	child_proc->p_memstat_effectivepriority = JETSAM_PRIORITY_DEFAULT;
	child_proc->p_memstat_requestedpriority = JETSAM_PRIORITY_DEFAULT;
	child_proc->p_memstat_assertionpriority = 0;
	child_proc->p_memstat_userdata          = 0;
	child_proc->p_memstat_idle_start        = 0;
	child_proc->p_memstat_idle_delta        = 0;
	child_proc->p_memstat_memlimit          = 0;
	child_proc->p_memstat_memlimit_active   = 0;
	child_proc->p_memstat_memlimit_inactive = 0;
	child_proc->p_memstat_relaunch_flags    = P_MEMSTAT_RELAUNCH_UNKNOWN;
#if CONFIG_FREEZE
	child_proc->p_memstat_freeze_sharedanon_pages = 0;
#endif
	child_proc->p_memstat_dirty = 0;
	child_proc->p_memstat_idledeadline = 0;
#endif /* CONFIG_MEMORYSTATUS */

	if (parent_proc->p_subsystem_root_path) {
		size_t parent_length = strlen(parent_proc->p_subsystem_root_path) + 1;
		assert(parent_length <= MAXPATHLEN);
		child_proc->p_subsystem_root_path = zalloc_flags(ZV_NAMEI,
		    Z_WAITOK | Z_ZERO);
		memcpy(child_proc->p_subsystem_root_path, parent_proc->p_subsystem_root_path, parent_length);
	}

bad:
	return child_proc;
}

void
proc_lock(proc_t p)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(&p->p_mlock);
}

void
proc_unlock(proc_t p)
{
	lck_mtx_unlock(&p->p_mlock);
}

void
proc_spinlock(proc_t p)
{
	lck_spin_lock_grp(&p->p_slock, &proc_slock_grp);
}

void
proc_spinunlock(proc_t p)
{
	lck_spin_unlock(&p->p_slock);
}

void
proc_list_lock(void)
{
	lck_mtx_lock(&proc_list_mlock);
}

void
proc_list_unlock(void)
{
	lck_mtx_unlock(&proc_list_mlock);
}

void
proc_ucred_lock(proc_t p)
{
	lck_mtx_lock(&p->p_ucred_mlock);
}

void
proc_ucred_unlock(proc_t p)
{
	lck_mtx_unlock(&p->p_ucred_mlock);
}

void
proc_update_creds_onproc(proc_t p)
{
	kauth_cred_t cred = proc_ucred(p);

	p->p_uid = kauth_cred_getuid(cred);
	p->p_gid = kauth_cred_getgid(cred);
	p->p_ruid = kauth_cred_getruid(cred);
	p->p_rgid = kauth_cred_getrgid(cred);
	p->p_svuid = kauth_cred_getsvuid(cred);
	p->p_svgid = kauth_cred_getsvgid(cred);
}


bool
uthread_is64bit(struct uthread *uth)
{
	return uth->uu_flag & UT_LP64;
}

void
uthread_init(task_t task, uthread_t uth, thread_ro_t tro_tpl, int workq_thread)
{
	uthread_t uth_parent = current_uthread();

	lck_spin_init(&uth->uu_rethrottle_lock, &rethrottle_lock_grp,
	    LCK_ATTR_NULL);

	/*
	 * Lazily set the thread on the kernel VFS context
	 * to the first thread made which will be vm_pageout_scan_thread.
	 */
	if (__improbable(vfs_context0.vc_thread == NULL)) {
		extern thread_t vm_pageout_scan_thread;

		assert(task == kernel_task);
		assert(get_machthread(uth) == vm_pageout_scan_thread);
		vfs_context0.vc_thread = get_machthread(uth);
	}

	if (task_get_64bit_addr(task)) {
		uth->uu_flag |= UT_LP64;
	}

	/*
	 * Thread inherits credential from the creating thread, if both
	 * are in the same task.
	 *
	 * If the creating thread has no credential or is from another
	 * task we can leave the new thread credential NULL.  If it needs
	 * one later, it will be lazily assigned from the task's process.
	 */
	if (task == kernel_task) {
		kauth_cred_set(&tro_tpl->tro_cred, vfs_context0.vc_ucred);
		tro_tpl->tro_proc = kernproc;
		tro_tpl->tro_proc_ro = kernproc->p_proc_ro;
	} else if (!task_is_a_corpse(task)) {
		thread_ro_t curtro = current_thread_ro();
		proc_t p = get_bsdtask_info(task);

		if (task == curtro->tro_task &&
		    ((curtro->tro_flags & TRO_SETUID) == 0 || !workq_thread)) {
			kauth_cred_set(&tro_tpl->tro_cred, curtro->tro_cred);
			tro_tpl->tro_flags = (curtro->tro_flags & TRO_SETUID);
			tro_tpl->tro_proc_ro = curtro->tro_proc_ro;
		} else {
			kauth_cred_t cred = kauth_cred_proc_ref(p);
			kauth_cred_set_and_unref(&tro_tpl->tro_cred, &cred);
			tro_tpl->tro_proc_ro = task_get_ro(task);
		}
		tro_tpl->tro_proc = p;

		proc_lock(p);
		if (workq_thread) {
			/* workq_thread threads will not inherit masks */
			uth->uu_sigmask = ~workq_threadmask;
		} else if (uth_parent->uu_flag & UT_SAS_OLDMASK) {
			uth->uu_sigmask = uth_parent->uu_oldmask;
		} else {
			uth->uu_sigmask = uth_parent->uu_sigmask;
		}

		TAILQ_INSERT_TAIL(&p->p_uthlist, uth, uu_list);
		proc_unlock(p);

#if CONFIG_DTRACE
		if (p->p_dtrace_ptss_pages != NULL) {
			uth->t_dtrace_scratch = dtrace_ptss_claim_entry(p);
		}
#endif
	} else {
		tro_tpl->tro_proc_ro = task_get_ro(task);
	}

	uth->uu_pending_sigreturn = 0;
	uthread_init_proc_refcount(uth);
}

mach_port_name_t
uthread_joiner_port(struct uthread *uth)
{
	return uth->uu_save.uus_bsdthread_terminate.kport;
}

user_addr_t
uthread_joiner_address(uthread_t uth)
{
	return uth->uu_save.uus_bsdthread_terminate.ulock_addr;
}

void
uthread_joiner_wake(task_t task, uthread_t uth)
{
	struct _bsdthread_terminate bts = uth->uu_save.uus_bsdthread_terminate;

	assert(bts.ulock_addr);
	bzero(&uth->uu_save.uus_bsdthread_terminate, sizeof(bts));

	int flags = UL_UNFAIR_LOCK | ULF_WAKE_ALL | ULF_WAKE_ALLOW_NON_OWNER;
	(void)ulock_wake(task, flags, bts.ulock_addr, 0);
	mach_port_deallocate(get_task_ipcspace(task), bts.kport);
}

/*
 * This routine frees the thread name field of the uthread_t structure. Split out of
 * uthread_cleanup() so thread name does not get deallocated while generating a corpse fork.
 */
void
uthread_cleanup_name(uthread_t uth)
{
	/*
	 * <rdar://17834538>
	 * Set pth_name to NULL before calling free().
	 * Previously there was a race condition in the
	 * case this code was executing during a stackshot
	 * where the stackshot could try and copy pth_name
	 * after it had been freed and before if was marked
	 * as null.
	 */
	if (uth->pth_name != NULL) {
		void *pth_name = uth->pth_name;
		uth->pth_name = NULL;
		kfree_data(pth_name, MAXTHREADNAMESIZE);
	}
	return;
}

/*
 * This routine frees all the BSD context in uthread except the credential.
 * It does not free the uthread structure as well
 */
void
uthread_cleanup(uthread_t uth, thread_ro_t tro)
{
	task_t task = tro->tro_task;
	proc_t p    = tro->tro_proc;

	uthread_assert_zero_proc_refcount(uth);

	if (uth->uu_lowpri_window || uth->uu_throttle_info) {
		/*
		 * task is marked as a low priority I/O type
		 * and we've somehow managed to not dismiss the throttle
		 * through the normal exit paths back to user space...
		 * no need to throttle this thread since its going away
		 * but we do need to update our bookeeping w/r to throttled threads
		 *
		 * Calling this routine will clean up any throttle info reference
		 * still inuse by the thread.
		 */
		throttle_lowpri_io(0);
	}

#if CONFIG_AUDIT
	/*
	 * Per-thread audit state should never last beyond system
	 * call return.  Since we don't audit the thread creation/
	 * removal, the thread state pointer should never be
	 * non-NULL when we get here.
	 */
	assert(uth->uu_ar == NULL);
#endif

	if (uth->uu_select.nbytes) {
		select_cleanup_uthread(&uth->uu_select);
	}

	if (uth->uu_cdir) {
		vnode_rele(uth->uu_cdir);
		uth->uu_cdir = NULLVP;
	}

	if (uth->uu_selset) {
		select_set_free(uth->uu_selset);
		uth->uu_selset = NULL;
	}

	os_reason_free(uth->uu_exit_reason);

	if ((task != kernel_task) && p) {
		/*
		 * Remove the thread from the process list and
		 * transfer [appropriate] pending signals to the process.
		 * Do not remove the uthread from proc uthlist for exec
		 * copy task, since they does not have a ref on proc and
		 * would not have been added to the list.
		 */
		if (uth->uu_kqr_bound) {
			kqueue_threadreq_unbind(p, uth->uu_kqr_bound);
		}

		if (get_bsdtask_info(task) == p) {
			proc_lock(p);
			TAILQ_REMOVE(&p->p_uthlist, uth, uu_list);
			p->p_siglist |= (uth->uu_siglist & execmask & (~p->p_sigignore | sigcantmask));
			proc_unlock(p);
		}

#if CONFIG_DTRACE
		struct dtrace_ptss_page_entry *tmpptr = uth->t_dtrace_scratch;
		uth->t_dtrace_scratch = NULL;
		if (tmpptr != NULL) {
			dtrace_ptss_release_entry(p, tmpptr);
		}
#endif
	} else {
		assert(!uth->uu_kqr_bound);
	}
}

/* This routine releases the credential stored in uthread */
void
uthread_cred_ref(struct ucred *ucred)
{
	kauth_cred_ref(ucred);
}

void
uthread_cred_free(struct ucred *ucred)
{
	kauth_cred_set(&ucred, NOCRED);
}

/* This routine frees the uthread structure held in thread structure */
void
uthread_destroy(uthread_t uth)
{
	uthread_destroy_proc_refcount(uth);

	if (uth->t_tombstone) {
		kfree_type(struct doc_tombstone, uth->t_tombstone);
		uth->t_tombstone = NULL;
	}

#if CONFIG_DEBUG_SYSCALL_REJECTION
	size_t const bitstr_len = BITMAP_SIZE(mach_trap_count + nsysent);

	if (uth->syscall_rejection_mask) {
		kfree_data(uth->syscall_rejection_mask, bitstr_len);
		uth->syscall_rejection_mask = NULL;
	}

	if (uth->syscall_rejection_once_mask) {
		kfree_data(uth->syscall_rejection_once_mask, bitstr_len);
		uth->syscall_rejection_once_mask = NULL;
	}
#endif /* CONFIG_DEBUG_SYSCALL_REJECTION */

	lck_spin_destroy(&uth->uu_rethrottle_lock, &rethrottle_lock_grp);

	uthread_cleanup_name(uth);
}

user_addr_t
thread_get_sigreturn_token(thread_t thread)
{
	uthread_t ut = (struct uthread *) get_bsdthread_info(thread);
	return ut->uu_sigreturn_token;
}

uint32_t
thread_get_sigreturn_diversifier(thread_t thread)
{
	uthread_t ut = (struct uthread *) get_bsdthread_info(thread);
	return ut->uu_sigreturn_diversifier;
}
