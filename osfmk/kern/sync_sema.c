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
/*
 * @OSF_COPYRIGHT@
 *
 */
/*
 *	File:	kern/sync_sema.c
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed semaphore synchronization services.
 */

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/kern_return.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>

#include <kern/misc_protos.h>
#include <kern/sync_sema.h>
#include <kern/spl.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <kern/host.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/mach_param.h>

static const uint8_t semaphore_event;
#define SEMAPHORE_EVENT CAST_EVENT64_T(&semaphore_event)

ZONE_DEFINE_ID(ZONE_ID_SEMAPHORE, "semaphores", struct semaphore,
    ZC_ZFREE_CLEARMEM);

os_refgrp_decl(static, sema_refgrp, "semaphore", NULL);

/* Forward declarations */

static inline bool
semaphore_active(semaphore_t semaphore)
{
	return semaphore->owner != TASK_NULL;
}

static __inline__ uint64_t
semaphore_deadline(
	unsigned int            sec,
	clock_res_t             nsec)
{
	uint64_t abstime;

	nanotime_to_absolutetime(sec, nsec, &abstime);
	clock_absolutetime_interval_to_deadline(abstime, &abstime);

	return abstime;
}

/*
 *	Routine:	semaphore_create
 *
 *	Creates a semaphore.
 *	The port representing the semaphore is returned as a parameter.
 */
kern_return_t
semaphore_create(
	task_t                  task,
	semaphore_t             *new_semaphore,
	int                     policy,
	int                     value)
{
	semaphore_t s = SEMAPHORE_NULL;

	*new_semaphore = SEMAPHORE_NULL;
	if (task == TASK_NULL || value < 0 || (policy & ~SYNC_POLICY_USER_MASK)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = zalloc_id(ZONE_ID_SEMAPHORE, Z_ZERO | Z_WAITOK | Z_NOFAIL);

	/*
	 *  Associate the new semaphore with the task by adding
	 *  the new semaphore to the task's semaphore list.
	 */
	task_lock(task);
	/* Check for race with task_terminate */
	if (!task->active) {
		task_unlock(task);
		zfree_id(ZONE_ID_SEMAPHORE, s);
		return KERN_INVALID_TASK;
	}

	waitq_init(&s->waitq, WQT_QUEUE, policy | SYNC_POLICY_INIT_LOCKED);

	/* init everything under both the task and semaphore locks */
	os_ref_init_raw(&s->ref_count, &sema_refgrp);
	s->count = value;
	s->owner = task;
	enqueue_head(&task->semaphore_list, &s->task_link);
	task->semaphores_owned++;

	semaphore_unlock(s);

	task_unlock(task);

	*new_semaphore = s;

	return KERN_SUCCESS;
}

/*
 *	Routine:	semaphore_destroy_internal
 *
 *	Disassociate a semaphore from its owning task, mark it inactive,
 *	and set any waiting threads running with THREAD_RESTART.
 *
 *	Conditions:
 *			task is locked
 *			semaphore is owned by the specified task
 *			disabling interrupts (splsched) is the responsibility of the caller.
 *	Returns:
 *			with semaphore unlocked
 */
static void
semaphore_destroy_internal(
	task_t                  task,
	semaphore_t             semaphore,
	bool                    semaphore_locked)
{
	int old_count;

	/* unlink semaphore from owning task */
	assert(semaphore->owner == task);
	remqueue(&semaphore->task_link);
	task->semaphores_owned--;

	/*
	 * deactivate semaphore under both locks
	 * and then wake up all waiters.
	 */
	if (!semaphore_locked) {
		semaphore_lock(semaphore);
	}

	semaphore->owner = TASK_NULL;
	old_count = semaphore->count;
	semaphore->count = 0;

	if (old_count < 0) {
		waitq_wakeup64_all_locked(&semaphore->waitq,
		    SEMAPHORE_EVENT, THREAD_RESTART,
		    WAITQ_ALL_PRIORITIES, WAITQ_UNLOCK);
		/* waitq/semaphore is unlocked */
	} else {
		assert(circle_queue_empty(&semaphore->waitq.waitq_queue));
		semaphore_unlock(semaphore);
	}
}

/*
 *	Routine:	semaphore_free
 *
 *	Free a semaphore that hit a 0 refcount.
 *
 *	Conditions:
 *			Nothing is locked.
 */
__attribute__((noinline))
static void
semaphore_free(
	semaphore_t             semaphore)
{
	ipc_port_t port;
	task_t task;

	/*
	 * Last ref, clean up the port [if any]
	 * associated with the semaphore, destroy
	 * it (if still active) and then free
	 * the semaphore.
	 */
	port = semaphore->port;
	if (IP_VALID(port)) {
		assert(!port->ip_srights);
		ipc_kobject_dealloc_port(port, 0, IKOT_SEMAPHORE);
	}

	/*
	 * If the semaphore owned by the current task,
	 * we know the current task can't go away,
	 * so we can take locks in the right order.
	 *
	 * Else we try to take locks in the "wrong" order
	 * but if we fail to, we take a task ref and do it "right".
	 */
	task = current_task();
	if (semaphore->owner == task) {
		task_lock(task);
		if (semaphore->owner == task) {
			spl_t s = splsched();
			semaphore_destroy_internal(task, semaphore, false);
			splx(s);
		} else {
			assert(semaphore->owner == TASK_NULL);
		}
		task_unlock(task);
	} else {
		spl_t s = splsched();

		semaphore_lock(semaphore);

		task = semaphore->owner;
		if (task == TASK_NULL) {
			semaphore_unlock(semaphore);
			splx(s);
		} else if (task_lock_try(task)) {
			semaphore_destroy_internal(task, semaphore, true);
			splx(s);
			/* semaphore unlocked */
			task_unlock(task);
		} else {
			task_reference(task);
			semaphore_unlock(semaphore);
			splx(s);

			task_lock(task);
			if (semaphore->owner == task) {
				s = splsched();
				semaphore_destroy_internal(task, semaphore, false);
				splx(s);
			}
			task_unlock(task);

			task_deallocate(task);
		}
	}

	waitq_deinit(&semaphore->waitq);
	zfree_id(ZONE_ID_SEMAPHORE, semaphore);
}

/*
 *	Routine:	semaphore_destroy
 *
 *	Destroys a semaphore and consume the caller's reference on the
 *	semaphore.
 */
kern_return_t
semaphore_destroy(
	task_t                  task,
	semaphore_t             semaphore)
{
	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (task == TASK_NULL) {
		semaphore_dereference(semaphore);
		return KERN_INVALID_ARGUMENT;
	}

	if (semaphore->owner == task) {
		task_lock(task);
		if (semaphore->owner == task) {
			spl_t spl_level = splsched();
			semaphore_destroy_internal(task, semaphore, false);
			splx(spl_level);
		}
		task_unlock(task);
	}

	semaphore_dereference(semaphore);
	return KERN_SUCCESS;
}

/*
 *	Routine:	semaphore_destroy_all
 *
 *	Destroy all the semaphores associated with a given task.
 */
#define SEMASPERSPL 20  /* max number of semaphores to destroy per spl hold */

void
semaphore_destroy_all(
	task_t                  task)
{
	semaphore_t semaphore;
	uint32_t count;
	spl_t spl_level;

	count = 0;
	task_lock(task);

	qe_foreach_element_safe(semaphore, &task->semaphore_list, task_link) {
		if (count == 0) {
			spl_level = splsched();
		}

		semaphore_destroy_internal(task, semaphore, false);

		/* throttle number of semaphores per interrupt disablement */
		if (++count == SEMASPERSPL) {
			count = 0;
			splx(spl_level);
		}
	}
	if (count != 0) {
		splx(spl_level);
	}

	task_unlock(task);
}

/*
 *	Routine:	semaphore_signal_internal
 *
 *		Signals the semaphore as direct.
 *	Assumptions:
 *		Semaphore is locked.
 */
static kern_return_t
semaphore_signal_internal(
	semaphore_t             semaphore,
	thread_t                thread,
	int                     options)
{
	kern_return_t kr;
	spl_t  spl_level;

	spl_level = splsched();
	semaphore_lock(semaphore);

	if (!semaphore_active(semaphore)) {
		semaphore_unlock(semaphore);
		splx(spl_level);
		return KERN_TERMINATED;
	}

	if (thread != THREAD_NULL) {
		if (semaphore->count < 0) {
			kr = waitq_wakeup64_thread_and_unlock(
				&semaphore->waitq, SEMAPHORE_EVENT,
				thread, THREAD_AWAKENED);
			/* waitq/semaphore is unlocked */
		} else {
			kr = KERN_NOT_WAITING;
			semaphore_unlock(semaphore);
		}
		splx(spl_level);
		return kr;
	}

	if (options & SEMAPHORE_SIGNAL_ALL) {
		int old_count = semaphore->count;

		kr = KERN_NOT_WAITING;
		if (old_count < 0) {
			semaphore->count = 0;  /* always reset */
			kr = waitq_wakeup64_all_locked(&semaphore->waitq,
			    SEMAPHORE_EVENT, THREAD_AWAKENED,
			    WAITQ_ALL_PRIORITIES, WAITQ_UNLOCK);
			/* waitq / semaphore is unlocked */
		} else {
			if (options & SEMAPHORE_SIGNAL_PREPOST) {
				semaphore->count++;
			}
			kr = KERN_SUCCESS;
			semaphore_unlock(semaphore);
		}
		splx(spl_level);
		return kr;
	}

	if (semaphore->count < 0) {
		waitq_options_t wq_option = (options & SEMAPHORE_THREAD_HANDOFF) ?
		    WQ_OPTION_HANDOFF : WQ_OPTION_NONE;
		kr = waitq_wakeup64_one_locked(&semaphore->waitq,
		    SEMAPHORE_EVENT, THREAD_AWAKENED,
		    WAITQ_ALL_PRIORITIES, WAITQ_KEEP_LOCKED, wq_option);
		if (kr == KERN_SUCCESS) {
			semaphore_unlock(semaphore);
			splx(spl_level);
			return KERN_SUCCESS;
		} else {
			semaphore->count = 0;  /* all waiters gone */
		}
	}

	if (options & SEMAPHORE_SIGNAL_PREPOST) {
		semaphore->count++;
	}

	semaphore_unlock(semaphore);
	splx(spl_level);
	return KERN_NOT_WAITING;
}

/*
 *	Routine:	semaphore_signal_thread
 *
 *	If the specified thread is blocked on the semaphore, it is
 *	woken up.  If a NULL thread was supplied, then any one
 *	thread is woken up.  Otherwise the caller gets KERN_NOT_WAITING
 *	and the	semaphore is unchanged.
 */
kern_return_t
semaphore_signal_thread(
	semaphore_t     semaphore,
	thread_t        thread)
{
	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return semaphore_signal_internal(semaphore, thread,
	           SEMAPHORE_OPTION_NONE);
}

/*
 *	Routine:	semaphore_signal_thread_trap
 *
 *	Trap interface to the semaphore_signal_thread function.
 */
kern_return_t
semaphore_signal_thread_trap(
	struct semaphore_signal_thread_trap_args *args)
{
	mach_port_name_t sema_name = args->signal_name;
	mach_port_name_t thread_name = args->thread_name;
	semaphore_t      semaphore;
	thread_t         thread;
	kern_return_t    kr;

	/*
	 * MACH_PORT_NULL is not an error. It means that we want to
	 * select any one thread that is already waiting, but not to
	 * pre-post the semaphore.
	 */
	if (thread_name != MACH_PORT_NULL) {
		thread = port_name_to_thread(thread_name, PORT_INTRANS_OPTIONS_NONE);
		if (thread == THREAD_NULL) {
			return KERN_INVALID_ARGUMENT;
		}
	} else {
		thread = THREAD_NULL;
	}

	kr = port_name_to_semaphore(sema_name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_signal_internal(semaphore,
		    thread,
		    SEMAPHORE_OPTION_NONE);
		semaphore_dereference(semaphore);
	}
	if (thread != THREAD_NULL) {
		thread_deallocate(thread);
	}
	return kr;
}



/*
 *	Routine:	semaphore_signal
 *
 *		Traditional (in-kernel client and MIG interface) semaphore
 *		signal routine.  Most users will access the trap version.
 *
 *		This interface in not defined to return info about whether
 *		this call found a thread waiting or not.  The internal
 *		routines (and future external routines) do.  We have to
 *		convert those into plain KERN_SUCCESS returns.
 */
kern_return_t
semaphore_signal(
	semaphore_t             semaphore)
{
	kern_return_t           kr;

	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = semaphore_signal_internal(semaphore,
	    THREAD_NULL,
	    SEMAPHORE_SIGNAL_PREPOST);
	if (kr == KERN_NOT_WAITING) {
		return KERN_SUCCESS;
	}
	return kr;
}

/*
 *	Routine:	semaphore_signal_trap
 *
 *	Trap interface to the semaphore_signal function.
 */
kern_return_t
semaphore_signal_trap(
	struct semaphore_signal_trap_args *args)
{
	mach_port_name_t sema_name = args->signal_name;

	return semaphore_signal_internal_trap(sema_name);
}

kern_return_t
semaphore_signal_internal_trap(mach_port_name_t sema_name)
{
	semaphore_t   semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(sema_name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_signal_internal(semaphore,
		    THREAD_NULL,
		    SEMAPHORE_SIGNAL_PREPOST);
		semaphore_dereference(semaphore);
		if (kr == KERN_NOT_WAITING) {
			kr = KERN_SUCCESS;
		}
	}
	return kr;
}

/*
 *	Routine:	semaphore_signal_all
 *
 *	Awakens ALL threads currently blocked on the semaphore.
 *	The semaphore count returns to zero.
 */
kern_return_t
semaphore_signal_all(
	semaphore_t             semaphore)
{
	kern_return_t kr;

	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = semaphore_signal_internal(semaphore,
	    THREAD_NULL,
	    SEMAPHORE_SIGNAL_ALL);
	if (kr == KERN_NOT_WAITING) {
		return KERN_SUCCESS;
	}
	return kr;
}

/*
 *	Routine:	semaphore_signal_all_trap
 *
 *	Trap interface to the semaphore_signal_all function.
 */
kern_return_t
semaphore_signal_all_trap(
	struct semaphore_signal_all_trap_args *args)
{
	mach_port_name_t sema_name = args->signal_name;
	semaphore_t     semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(sema_name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_signal_internal(semaphore,
		    THREAD_NULL,
		    SEMAPHORE_SIGNAL_ALL);
		semaphore_dereference(semaphore);
		if (kr == KERN_NOT_WAITING) {
			kr = KERN_SUCCESS;
		}
	}
	return kr;
}

/*
 *	Routine:	semaphore_convert_wait_result
 *
 *	Generate the return code after a semaphore wait/block.  It
 *	takes the wait result as an input and coverts that to an
 *	appropriate result.
 */
static kern_return_t
semaphore_convert_wait_result(int wait_result)
{
	switch (wait_result) {
	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	case THREAD_TIMED_OUT:
		return KERN_OPERATION_TIMED_OUT;

	case THREAD_INTERRUPTED:
		return KERN_ABORTED;

	case THREAD_RESTART:
		return KERN_TERMINATED;

	default:
		panic("semaphore_block");
		return KERN_FAILURE;
	}
}

/*
 *	Routine:	semaphore_wait_continue
 *
 *	Common continuation routine after waiting on a semphore.
 *	It returns directly to user space.
 */
static void
semaphore_wait_continue(void *arg __unused, wait_result_t wr)
{
	thread_t self = current_thread();
	semaphore_cont_t caller_cont = self->sth_continuation;

	assert(self->sth_waitsemaphore != SEMAPHORE_NULL);
	semaphore_dereference(self->sth_waitsemaphore);
	if (self->sth_signalsemaphore != SEMAPHORE_NULL) {
		semaphore_dereference(self->sth_signalsemaphore);
	}

	assert(self->handoff_thread == THREAD_NULL);
	assert(caller_cont != NULL);
	(*caller_cont)(semaphore_convert_wait_result(wr));
}

/*
 *	Routine:	semaphore_wait_internal
 *
 *		Decrements the semaphore count by one.  If the count is
 *		negative after the decrement, the calling thread blocks
 *		(possibly at a continuation and/or with a timeout).
 *
 *	Assumptions:
 *		The reference
 *		A reference is held on the signal semaphore.
 */
static kern_return_t
semaphore_wait_internal(
	semaphore_t             wait_semaphore,
	semaphore_t             signal_semaphore,
	uint64_t                deadline,
	int                     option,
	semaphore_cont_t        caller_cont)
{
	int           wait_result;
	spl_t         spl_level;
	kern_return_t kr = KERN_ALREADY_WAITING;
	thread_t      self = current_thread();
	thread_t      handoff_thread = THREAD_NULL;
	int           semaphore_signal_options = SEMAPHORE_SIGNAL_PREPOST;
	thread_handoff_option_t handoff_option = THREAD_HANDOFF_NONE;

	spl_level = splsched();
	semaphore_lock(wait_semaphore);

	if (!semaphore_active(wait_semaphore)) {
		kr = KERN_TERMINATED;
	} else if (wait_semaphore->count > 0) {
		wait_semaphore->count--;
		kr = KERN_SUCCESS;
	} else if (option & SEMAPHORE_TIMEOUT_NOBLOCK) {
		kr = KERN_OPERATION_TIMED_OUT;
	} else {
		wait_semaphore->count = -1;  /* we don't keep an actual count */

		thread_set_pending_block_hint(self, kThreadWaitSemaphore);
		(void)waitq_assert_wait64_locked(
			&wait_semaphore->waitq,
			SEMAPHORE_EVENT,
			THREAD_ABORTSAFE,
			TIMEOUT_URGENCY_USER_NORMAL,
			deadline, TIMEOUT_NO_LEEWAY,
			self);

		semaphore_signal_options |= SEMAPHORE_THREAD_HANDOFF;
	}
	semaphore_unlock(wait_semaphore);
	splx(spl_level);

	/*
	 * wait_semaphore is unlocked so we are free to go ahead and
	 * signal the signal_semaphore (if one was provided).
	 */
	if (signal_semaphore != SEMAPHORE_NULL) {
		kern_return_t signal_kr;

		/*
		 * lock the signal semaphore reference we got and signal it.
		 * This will NOT block (we cannot block after having asserted
		 * our intention to wait above).
		 */
		signal_kr = semaphore_signal_internal(signal_semaphore,
		    THREAD_NULL, semaphore_signal_options);

		if (signal_kr == KERN_NOT_WAITING) {
			assert(self->handoff_thread == THREAD_NULL);
			signal_kr = KERN_SUCCESS;
		} else if (signal_kr == KERN_TERMINATED) {
			/*
			 * Uh!Oh!  The semaphore we were to signal died.
			 * We have to get ourselves out of the wait in
			 * case we get stuck here forever (it is assumed
			 * that the semaphore we were posting is gating
			 * the decision by someone else to post the
			 * semaphore we are waiting on).  People will
			 * discover the other dead semaphore soon enough.
			 * If we got out of the wait cleanly (someone
			 * already posted a wakeup to us) then return that
			 * (most important) result.  Otherwise,
			 * return the KERN_TERMINATED status.
			 */
			assert(self->handoff_thread == THREAD_NULL);
			clear_wait(self, THREAD_INTERRUPTED);
			kr = semaphore_convert_wait_result(self->wait_result);
			if (kr == KERN_ABORTED) {
				kr = KERN_TERMINATED;
			}
		}
	}

	/*
	 * If we had an error, or we didn't really need to wait we can
	 * return now that we have signalled the signal semaphore.
	 */
	if (kr != KERN_ALREADY_WAITING) {
		assert(self->handoff_thread == THREAD_NULL);
		return kr;
	}

	if (self->handoff_thread) {
		handoff_thread = self->handoff_thread;
		self->handoff_thread = THREAD_NULL;
		handoff_option = THREAD_HANDOFF_SETRUN_NEEDED;
	}

	/*
	 * Now, we can block.  If the caller supplied a continuation
	 * pointer of his own for after the block, block with the
	 * appropriate semaphore continuation.  This will gather the
	 * semaphore results, release references on the semaphore(s),
	 * and then call the caller's continuation.
	 */
	if (caller_cont) {
		self->sth_continuation = caller_cont;
		self->sth_waitsemaphore = wait_semaphore;
		self->sth_signalsemaphore = signal_semaphore;

		thread_handoff_parameter(handoff_thread, semaphore_wait_continue,
		    NULL, handoff_option);
	} else {
		wait_result = thread_handoff_deallocate(handoff_thread, handoff_option);
	}

	assert(self->handoff_thread == THREAD_NULL);
	return semaphore_convert_wait_result(wait_result);
}


/*
 *	Routine:	semaphore_wait
 *
 *	Traditional (non-continuation) interface presented to
 *      in-kernel clients to wait on a semaphore.
 */
kern_return_t
semaphore_wait(
	semaphore_t             semaphore)
{
	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return semaphore_wait_internal(semaphore, SEMAPHORE_NULL,
	           0ULL, SEMAPHORE_OPTION_NONE, SEMAPHORE_CONT_NULL);
}

kern_return_t
semaphore_wait_noblock(
	semaphore_t             semaphore)
{
	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return semaphore_wait_internal(semaphore, SEMAPHORE_NULL,
	           0ULL, SEMAPHORE_TIMEOUT_NOBLOCK, SEMAPHORE_CONT_NULL);
}

kern_return_t
semaphore_wait_deadline(
	semaphore_t             semaphore,
	uint64_t                deadline)
{
	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return semaphore_wait_internal(semaphore, SEMAPHORE_NULL,
	           deadline, SEMAPHORE_OPTION_NONE, SEMAPHORE_CONT_NULL);
}

/*
 *	Trap:	semaphore_wait_trap
 *
 *	Trap version of semaphore wait.  Called on behalf of user-level
 *	clients.
 */

kern_return_t
semaphore_wait_trap(
	struct semaphore_wait_trap_args *args)
{
	return semaphore_wait_trap_internal(args->wait_name, thread_syscall_return);
}

kern_return_t
semaphore_wait_trap_internal(
	mach_port_name_t name,
	semaphore_cont_t caller_cont)
{
	semaphore_t   semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_wait_internal(semaphore,
		    SEMAPHORE_NULL,
		    0ULL, SEMAPHORE_OPTION_NONE,
		    caller_cont);
		semaphore_dereference(semaphore);
	}
	return kr;
}

/*
 *	Routine:	semaphore_timedwait
 *
 *	Traditional (non-continuation) interface presented to
 *      in-kernel clients to wait on a semaphore with a timeout.
 *
 *	A timeout of {0,0} is considered non-blocking.
 */
kern_return_t
semaphore_timedwait(
	semaphore_t             semaphore,
	mach_timespec_t         wait_time)
{
	int      option = SEMAPHORE_OPTION_NONE;
	uint64_t deadline = 0;

	if (semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (BAD_MACH_TIMESPEC(&wait_time)) {
		return KERN_INVALID_VALUE;
	}

	if (wait_time.tv_sec == 0 && wait_time.tv_nsec == 0) {
		option = SEMAPHORE_TIMEOUT_NOBLOCK;
	} else {
		deadline = semaphore_deadline(wait_time.tv_sec, wait_time.tv_nsec);
	}

	return semaphore_wait_internal(semaphore, SEMAPHORE_NULL,
	           deadline, option, SEMAPHORE_CONT_NULL);
}

/*
 *	Trap:	semaphore_timedwait_trap
 *
 *	Trap version of a semaphore_timedwait.  The timeout parameter
 *	is passed in two distinct parts and re-assembled on this side
 *	of the trap interface (to accomodate calling conventions that
 *	pass structures as pointers instead of inline in registers without
 *	having to add a copyin).
 *
 *	A timeout of {0,0} is considered non-blocking.
 */
kern_return_t
semaphore_timedwait_trap(
	struct semaphore_timedwait_trap_args *args)
{
	return semaphore_timedwait_trap_internal(args->wait_name,
	           args->sec, args->nsec, thread_syscall_return);
}


kern_return_t
semaphore_timedwait_trap_internal(
	mach_port_name_t name,
	unsigned int     sec,
	clock_res_t      nsec,
	semaphore_cont_t caller_cont)
{
	semaphore_t semaphore;
	mach_timespec_t wait_time;
	kern_return_t kr;

	wait_time.tv_sec = sec;
	wait_time.tv_nsec = nsec;
	if (BAD_MACH_TIMESPEC(&wait_time)) {
		return KERN_INVALID_VALUE;
	}

	kr = port_name_to_semaphore(name, &semaphore);
	if (kr == KERN_SUCCESS) {
		int      option = SEMAPHORE_OPTION_NONE;
		uint64_t deadline = 0;

		if (sec == 0 && nsec == 0) {
			option = SEMAPHORE_TIMEOUT_NOBLOCK;
		} else {
			deadline = semaphore_deadline(sec, nsec);
		}

		kr = semaphore_wait_internal(semaphore,
		    SEMAPHORE_NULL,
		    deadline, option,
		    caller_cont);
		semaphore_dereference(semaphore);
	}
	return kr;
}

/*
 *	Routine:	semaphore_wait_signal
 *
 *	Atomically register a wait on a semaphore and THEN signal
 *	another.  This is the in-kernel entry point that does not
 *	block at a continuation and does not free a signal_semaphore
 *      reference.
 */
kern_return_t
semaphore_wait_signal(
	semaphore_t             wait_semaphore,
	semaphore_t             signal_semaphore)
{
	if (wait_semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return semaphore_wait_internal(wait_semaphore, signal_semaphore,
	           0ULL, SEMAPHORE_OPTION_NONE, SEMAPHORE_CONT_NULL);
}

/*
 *	Trap:	semaphore_wait_signal_trap
 *
 *	Atomically register a wait on a semaphore and THEN signal
 *	another.  This is the trap version from user space.
 */
kern_return_t
semaphore_wait_signal_trap(
	struct semaphore_wait_signal_trap_args *args)
{
	return semaphore_wait_signal_trap_internal(args->wait_name,
	           args->signal_name, thread_syscall_return);
}

kern_return_t
semaphore_wait_signal_trap_internal(
	mach_port_name_t wait_name,
	mach_port_name_t signal_name,
	semaphore_cont_t caller_cont)
{
	semaphore_t wait_semaphore;
	semaphore_t signal_semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(signal_name, &signal_semaphore);
	if (kr == KERN_SUCCESS) {
		kr = port_name_to_semaphore(wait_name, &wait_semaphore);
		if (kr == KERN_SUCCESS) {
			kr = semaphore_wait_internal(wait_semaphore,
			    signal_semaphore,
			    0ULL, SEMAPHORE_OPTION_NONE,
			    caller_cont);
			semaphore_dereference(wait_semaphore);
		}
		semaphore_dereference(signal_semaphore);
	}
	return kr;
}


/*
 *	Routine:	semaphore_timedwait_signal
 *
 *	Atomically register a wait on a semaphore and THEN signal
 *	another.  This is the in-kernel entry point that does not
 *	block at a continuation.
 *
 *	A timeout of {0,0} is considered non-blocking.
 */
kern_return_t
semaphore_timedwait_signal(
	semaphore_t             wait_semaphore,
	semaphore_t             signal_semaphore,
	mach_timespec_t         wait_time)
{
	int      option = SEMAPHORE_OPTION_NONE;
	uint64_t deadline = 0;

	if (wait_semaphore == SEMAPHORE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (BAD_MACH_TIMESPEC(&wait_time)) {
		return KERN_INVALID_VALUE;
	}

	if (wait_time.tv_sec == 0 && wait_time.tv_nsec == 0) {
		option = SEMAPHORE_TIMEOUT_NOBLOCK;
	} else {
		deadline = semaphore_deadline(wait_time.tv_sec, wait_time.tv_nsec);
	}

	return semaphore_wait_internal(wait_semaphore, signal_semaphore,
	           deadline, option, SEMAPHORE_CONT_NULL);
}

/*
 *	Trap:	semaphore_timedwait_signal_trap
 *
 *	Atomically register a timed wait on a semaphore and THEN signal
 *	another.  This is the trap version from user space.
 */
kern_return_t
semaphore_timedwait_signal_trap(
	struct semaphore_timedwait_signal_trap_args *args)
{
	return semaphore_timedwait_signal_trap_internal(args->wait_name,
	           args->signal_name, args->sec, args->nsec, thread_syscall_return);
}

kern_return_t
semaphore_timedwait_signal_trap_internal(
	mach_port_name_t wait_name,
	mach_port_name_t signal_name,
	unsigned int sec,
	clock_res_t nsec,
	semaphore_cont_t caller_cont)
{
	semaphore_t wait_semaphore;
	semaphore_t signal_semaphore;
	mach_timespec_t wait_time;
	kern_return_t kr;

	wait_time.tv_sec = sec;
	wait_time.tv_nsec = nsec;
	if (BAD_MACH_TIMESPEC(&wait_time)) {
		return KERN_INVALID_VALUE;
	}

	kr = port_name_to_semaphore(signal_name, &signal_semaphore);
	if (kr == KERN_SUCCESS) {
		kr = port_name_to_semaphore(wait_name, &wait_semaphore);
		if (kr == KERN_SUCCESS) {
			int      option = SEMAPHORE_OPTION_NONE;
			uint64_t deadline = 0;

			if (sec == 0 && nsec == 0) {
				option = SEMAPHORE_TIMEOUT_NOBLOCK;
			} else {
				deadline = semaphore_deadline(sec, nsec);
			}

			kr = semaphore_wait_internal(wait_semaphore,
			    signal_semaphore,
			    deadline, option,
			    caller_cont);
			semaphore_dereference(wait_semaphore);
		}
		semaphore_dereference(signal_semaphore);
	}
	return kr;
}


/*
 *	Routine:	semaphore_reference
 *
 *	Take out a reference on a semaphore.  This keeps the data structure
 *	in existence (but the semaphore may be deactivated).
 */
void
semaphore_reference(
	semaphore_t             semaphore)
{
	zone_id_require(ZONE_ID_SEMAPHORE, sizeof(*semaphore), semaphore);
	os_ref_retain_raw(&semaphore->ref_count, &sema_refgrp);
}

/*
 *	Routine:	semaphore_dereference
 *
 *	Release a reference on a semaphore.  If this is the last reference,
 *	the semaphore data structure is deallocated.
 */
void
semaphore_dereference(
	semaphore_t             semaphore)
{
	if (semaphore == NULL) {
		return;
	}

	if (os_ref_release_raw(&semaphore->ref_count, &sema_refgrp) == 0) {
		return semaphore_free(semaphore);
	}
}

void
kdp_sema_find_owner(struct waitq *waitq, __assert_only event64_t event, thread_waitinfo_t * waitinfo)
{
	semaphore_t sem = __container_of(waitq, struct semaphore, waitq);
	assert(event == SEMAPHORE_EVENT);

	zone_id_require(ZONE_ID_SEMAPHORE, sizeof(*sem), sem);

	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(sem->port);
	if (sem->owner) {
		waitinfo->owner = pid_from_task(sem->owner);
	}
}

/*
 *	Routine:	port_name_to_semaphore
 *	Purpose:
 *		Convert from a port name in the current space to a semaphore.
 *		Produces a semaphore ref, which may be null.
 *	Conditions:
 *		Nothing locked.
 */
kern_return_t
port_name_to_semaphore(
	mach_port_name_t        name,
	semaphore_t             *semaphorep)
{
	ipc_port_t port;
	kern_return_t kr;

	if (!MACH_PORT_VALID(name)) {
		*semaphorep = SEMAPHORE_NULL;
		return KERN_INVALID_NAME;
	}

	kr = ipc_port_translate_send(current_space(), name, &port);
	if (kr != KERN_SUCCESS) {
		*semaphorep = SEMAPHORE_NULL;
		return kr;
	}
	/* have the port locked */

	*semaphorep = convert_port_to_semaphore(port);
	if (*semaphorep == SEMAPHORE_NULL) {
		/* the port is valid, but doesn't denote a semaphore */
		kr = KERN_INVALID_CAPABILITY;
	} else {
		kr = KERN_SUCCESS;
	}
	ip_mq_unlock(port);

	return kr;
}

/*
 *	Routine:	convert_port_to_semaphore
 *	Purpose:
 *		Convert from a port to a semaphore.
 *		Doesn't consume the port [send-right] ref;
 *		produces a semaphore ref, which may be null.
 *	Conditions:
 *		Caller has a send-right reference to port.
 *		Port may or may not be locked.
 */
semaphore_t
convert_port_to_semaphore(ipc_port_t port)
{
	semaphore_t semaphore = SEMAPHORE_NULL;

	if (IP_VALID(port)) {
		semaphore = ipc_kobject_get_stable(port, IKOT_SEMAPHORE);
		if (semaphore != SEMAPHORE_NULL) {
			semaphore_reference(semaphore);
		}
	}

	return semaphore;
}


/*
 *	Routine:	convert_semaphore_to_port
 *	Purpose:
 *		Convert a semaphore reference to a send right to a
 *		semaphore port.
 *
 *		Consumes the semaphore reference.  If the semaphore
 *		port currently has no send rights (or doesn't exist
 *		yet), the reference is donated to the port to represent
 *		all extant send rights collectively.
 */
ipc_port_t
convert_semaphore_to_port(semaphore_t semaphore)
{
	if (semaphore == SEMAPHORE_NULL) {
		return IP_NULL;
	}

	/*
	 * make a send right and donate our reference for
	 * semaphore_no_senders if this is the first send right
	 */
	if (!ipc_kobject_make_send_lazy_alloc_port(&semaphore->port,
	    semaphore, IKOT_SEMAPHORE, IPC_KOBJECT_ALLOC_NONE, 0)) {
		semaphore_dereference(semaphore);
	}
	return semaphore->port;
}

/*
 * Routine:	semaphore_no_senders
 * Purpose:
 *	Called whenever the Mach port system detects no-senders
 *	on the semaphore port.
 *
 *	When a send-right is first created, a no-senders
 *	notification is armed (and a semaphore reference is donated).
 *
 *	A no-senders notification will be posted when no one else holds a
 *	send-right (reference) to the semaphore's port. This notification function
 *	will consume the semaphore reference donated to the extant collection of
 *	send-rights.
 */
static void
semaphore_no_senders(ipc_port_t port, __unused mach_port_mscount_t mscount)
{
	semaphore_t semaphore = ipc_kobject_get_stable(port, IKOT_SEMAPHORE);

	assert(semaphore != SEMAPHORE_NULL);
	assert(semaphore->port == port);

	semaphore_dereference(semaphore);
}

IPC_KOBJECT_DEFINE(IKOT_SEMAPHORE,
    .iko_op_stable     = true,
    .iko_op_no_senders = semaphore_no_senders);
