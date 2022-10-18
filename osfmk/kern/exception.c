/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
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
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/mig_errors.h>
#include <mach/task.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <mach/exc.h>
#include <mach/mach_exc.h>

#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_machdep.h>

#include <kern/ipc_tt.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <kern/ux_handler.h>
#include <kern/task_ident.h>

#include <vm/vm_map.h>

#include <security/mac_mach_internal.h>
#include <string.h>

#include <pexpert/pexpert.h>

#include <os/log.h>
#include <os/system_event_log.h>

#include <libkern/coreanalytics/coreanalytics.h>

#include <sys/code_signing.h> /* for developer mode state */

bool panic_on_exception_triage = false;

/* Not used in coded, only for inspection during debugging */
unsigned long c_thr_exc_raise = 0;
unsigned long c_thr_exc_raise_identity_token = 0;
unsigned long c_thr_exc_raise_state = 0;
unsigned long c_thr_exc_raise_state_id = 0;
unsigned long c_thr_exc_raise_backtrace = 0;

/* forward declarations */
kern_return_t exception_deliver(
	thread_t                thread,
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt,
	struct exception_action *excp,
	lck_mtx_t                       *mutex);

#ifdef MACH_BSD
kern_return_t bsd_exception(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt);
#endif /* MACH_BSD */

#if __has_feature(ptrauth_calls)
extern int exit_with_pac_exception(
	void *proc,
	exception_type_t         exception,
	mach_exception_code_t    code,
	mach_exception_subcode_t subcode);
#endif /* __has_feature(ptrauth_calls) */

#ifdef MACH_BSD
extern bool proc_is_traced(void *p);
extern int      proc_selfpid(void);
extern char     *proc_name_address(struct proc *p);
#endif /* MACH_BSD */

#if (DEVELOPMENT || DEBUG)
TUNABLE_WRITEABLE(unsigned int, exception_log_max_pid, "exception_log_max_pid", 0);
#endif /* (DEVELOPMENT || DEBUG) */

/*
 * Routine: exception_init
 * Purpose:
 *   Global initialization of state for exceptions.
 * Conditions:
 *   None.
 */
void
exception_init(void)
{
	int tmp = 0;

	if (PE_parse_boot_argn("-panic_on_exception_triage", &tmp, sizeof(tmp))) {
		panic_on_exception_triage = true;
	}

#if (DEVELOPMENT || DEBUG)
	if (exception_log_max_pid) {
		printf("Logging all exceptions where pid < exception_log_max_pid (%d)\n", exception_log_max_pid);
	}
#endif /* (DEVELOPMENT || DEBUG) */
}

static TUNABLE(bool, pac_replace_ptrs_user, "pac_replace_ptrs_user", true);

ipc_port_t
exception_port_copy_send(ipc_port_t port)
{
	if (IP_VALID(port)) {
		if (is_ux_handler_port(port)) {
			/* is_ux_handler_port() compares against __DATA_CONST */
			port = ipc_port_copy_send_any(port);
		} else {
			port = ipc_port_copy_send_mqueue(port);
		}
	}
	return port;
}

/*
 *	Routine:	exception_deliver
 *	Purpose:
 *		Make an upcall to the exception server provided.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		KERN_SUCCESS if the exception was handled
 */
kern_return_t
exception_deliver(
	thread_t                thread,
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt,
	struct exception_action *excp,
	lck_mtx_t               *mutex)
{
	ipc_port_t              exc_port = IPC_PORT_NULL;
	exception_data_type_t   small_code[EXCEPTION_CODE_MAX];
	thread_state_t          new_state = NULL;
	int                     code64;
	int                     behavior;
	int                     flavor;
	kern_return_t           kr;
	task_t task;
	task_id_token_t task_token;
	ipc_port_t thread_port = IPC_PORT_NULL,
	    task_port = IPC_PORT_NULL,
	    task_token_port = IPC_PORT_NULL;

	/*
	 *  Save work if we are terminating.
	 *  Just go back to our AST handler.
	 */
	if (!thread->active && !thread->inspection) {
		return KERN_SUCCESS;
	}

	/*
	 * If there are no exception actions defined for this entity,
	 * we can't deliver here.
	 */
	if (excp == NULL) {
		return KERN_FAILURE;
	}

	assert(exception < EXC_TYPES_COUNT);
	if (exception >= EXC_TYPES_COUNT) {
		return KERN_FAILURE;
	}

	excp = &excp[exception];

	/*
	 * Snapshot the exception action data under lock for consistency.
	 * Hold a reference to the port over the exception_raise_* calls
	 * so it can't be destroyed.  This seems like overkill, but keeps
	 * the port from disappearing between now and when
	 * ipc_object_copyin_from_kernel is finally called.
	 */
	lck_mtx_lock(mutex);
	exc_port = exception_port_copy_send(excp->port);
	if (!IP_VALID(exc_port)) {
		lck_mtx_unlock(mutex);
		return KERN_FAILURE;
	}

	flavor = excp->flavor;
	behavior = excp->behavior;
	lck_mtx_unlock(mutex);

	code64 = (behavior & MACH_EXCEPTION_CODES);
	behavior &= ~MACH_EXCEPTION_MASK;

	if (!code64) {
		small_code[0] = CAST_DOWN_EXPLICIT(exception_data_type_t, code[0]);
		small_code[1] = CAST_DOWN_EXPLICIT(exception_data_type_t, code[1]);
	}

	task = get_threadtask(thread);

#if CONFIG_MACF
	/* Now is a reasonably good time to check if the exception action is
	 * permitted for this process, because after this point we will send
	 * the message out almost certainly.
	 * As with other failures, exception_triage_thread will go on
	 * to the next level.
	 */

	/* The global exception-to-signal translation port is safe to be an exception handler. */
	if (is_ux_handler_port(exc_port) == FALSE &&
	    mac_exc_action_check_exception_send(task, excp) != 0) {
		kr = KERN_FAILURE;
		goto out_release_right;
	}
#endif

	switch (behavior) {
	case EXCEPTION_STATE: {
		mach_msg_type_number_t old_state_cnt, new_state_cnt;
		thread_state_data_t old_state;
		thread_set_status_flags_t get_flags = TSSF_TRANSLATE_TO_USER;
		thread_set_status_flags_t set_flags = TSSF_CHECK_USER_FLAGS;
		bool task_allow_user_state = task_needs_user_signed_thread_state(task);

		if (pac_replace_ptrs_user || task_allow_user_state) {
			get_flags |= TSSF_RANDOM_USER_DIV;
			set_flags |= (TSSF_ALLOW_ONLY_USER_PTRS | TSSF_RANDOM_USER_DIV);
		}

		c_thr_exc_raise_state++;
		old_state_cnt = _MachineStateCount[flavor];
		kr = thread_getstatus_to_user(thread, flavor,
		    (thread_state_t)old_state,
		    &old_state_cnt, get_flags);
		new_state_cnt = old_state_cnt;
		if (kr == KERN_SUCCESS) {
			new_state = (thread_state_t)kalloc_data(sizeof(thread_state_data_t), Z_WAITOK | Z_ZERO);
			if (new_state == NULL) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out_release_right;
			}
			if (code64) {
				kr = mach_exception_raise_state(exc_port,
				    exception,
				    code,
				    codeCnt,
				    &flavor,
				    old_state, old_state_cnt,
				    new_state, &new_state_cnt);
			} else {
				kr = exception_raise_state(exc_port, exception,
				    small_code,
				    codeCnt,
				    &flavor,
				    old_state, old_state_cnt,
				    new_state, &new_state_cnt);
			}
			if (kr == KERN_SUCCESS) {
				if (exception != EXC_CORPSE_NOTIFY) {
					kr = thread_setstatus_from_user(thread, flavor,
					    (thread_state_t)new_state, new_state_cnt,
					    (thread_state_t)old_state, old_state_cnt,
					    set_flags);
				}
				goto out_release_right;
			}
		}

		goto out_release_right;
	}

	case EXCEPTION_DEFAULT: {
		c_thr_exc_raise++;

		task_reference(task);
		thread_reference(thread);
		/*
		 * Only deliver control port if Developer Mode enabled,
		 * or task is a corpse. Otherwise we only deliver the
		 * (immovable) read port in exception handler (both in
		 * or out of process). (94669540)
		 */
		if (developer_mode_state() || task_is_a_corpse(task)) {
			task_port = convert_task_to_port(task);
			thread_port = convert_thread_to_port(thread);
		} else {
			task_port = convert_task_read_to_port(task);
			thread_port = convert_thread_read_to_port(thread);
		}
		/* task and thread ref consumed */

		if (code64) {
			kr = mach_exception_raise(exc_port,
			    thread_port,
			    task_port,
			    exception,
			    code,
			    codeCnt);
		} else {
			kr = exception_raise(exc_port,
			    thread_port,
			    task_port,
			    exception,
			    small_code,
			    codeCnt);
		}

		goto out_release_right;
	}

	case EXCEPTION_IDENTITY_PROTECTED: {
		c_thr_exc_raise_identity_token++;

		kr = task_create_identity_token(task, &task_token);
		/* task_token now represents a task, or corpse */
		assert(kr == KERN_SUCCESS);
		task_token_port = convert_task_id_token_to_port(task_token);
		/* task token ref consumed */

		if (code64) {
			kr = mach_exception_raise_identity_protected(exc_port,
			    thread->thread_id,
			    task_token_port,
			    exception,
			    code,
			    codeCnt);
		} else {
			panic("mach_exception_raise_identity_protected() must be code64");
		}

		goto out_release_right;
	}

	case EXCEPTION_STATE_IDENTITY: {
		mach_msg_type_number_t old_state_cnt, new_state_cnt;
		thread_state_data_t old_state;
		thread_set_status_flags_t get_flags = TSSF_TRANSLATE_TO_USER;
		thread_set_status_flags_t set_flags = TSSF_CHECK_USER_FLAGS;
		bool task_allow_user_state = task_needs_user_signed_thread_state(task);

		if (pac_replace_ptrs_user || task_allow_user_state) {
			get_flags |= TSSF_RANDOM_USER_DIV;
			set_flags |= (TSSF_ALLOW_ONLY_USER_PTRS | TSSF_RANDOM_USER_DIV);
		}

		c_thr_exc_raise_state_id++;

		task_reference(task);
		thread_reference(thread);
		/*
		 * Only deliver control port if Developer Mode enabled,
		 * or task is a corpse. Otherwise we only deliver the
		 * (immovable) read port in exception handler (both in
		 * or out of process). (94669540)
		 */
		if (developer_mode_state() || task_is_a_corpse(task)) {
			task_port = convert_task_to_port(task);
			thread_port = convert_thread_to_port(thread);
		} else {
			task_port = convert_task_read_to_port(task);
			thread_port = convert_thread_read_to_port(thread);
		}
		/* task and thread ref consumed */

		old_state_cnt = _MachineStateCount[flavor];
		kr = thread_getstatus_to_user(thread, flavor,
		    (thread_state_t)old_state,
		    &old_state_cnt, get_flags);
		new_state_cnt = old_state_cnt;
		if (kr == KERN_SUCCESS) {
			new_state = (thread_state_t)kalloc_data(sizeof(thread_state_data_t), Z_WAITOK | Z_ZERO);
			if (new_state == NULL) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out_release_right;
			}
			if (code64) {
				kr = mach_exception_raise_state_identity(
					exc_port,
					thread_port,
					task_port,
					exception,
					code,
					codeCnt,
					&flavor,
					old_state, old_state_cnt,
					new_state, &new_state_cnt);
			} else {
				kr = exception_raise_state_identity(exc_port,
				    thread_port,
				    task_port,
				    exception,
				    small_code,
				    codeCnt,
				    &flavor,
				    old_state, old_state_cnt,
				    new_state, &new_state_cnt);
			}

			if (kr == KERN_SUCCESS) {
				if (exception != EXC_CORPSE_NOTIFY) {
					kr = thread_setstatus_from_user(thread, flavor,
					    (thread_state_t)new_state, new_state_cnt,
					    (thread_state_t)old_state, old_state_cnt, set_flags);
				}
				goto out_release_right;
			}
		}

		goto out_release_right;
	}

	default:
		panic("bad exception behavior!");
		return KERN_FAILURE;
	}/* switch */

out_release_right:

	if (task_port) {
		ipc_port_release_send(task_port);
	}

	if (thread_port) {
		ipc_port_release_send(thread_port);
	}

	if (exc_port) {
		ipc_port_release_send(exc_port);
	}

	if (task_token_port) {
		ipc_port_release_send(task_token_port);
	}

	if (new_state) {
		kfree_data(new_state, sizeof(thread_state_data_t));
	}

	return kr;
}

/*
 * Attempt exception delivery with backtrace info to exception ports
 * in exc_ports in order.
 */
/*
 *	Routine:	exception_deliver_backtrace
 *	Purpose:
 *      Attempt exception delivery with backtrace info to exception ports
 *      in exc_ports in order.
 *	Conditions:
 *		Caller has a reference on bt_object, and send rights on exc_ports.
 *		Does not consume any passed references or rights
 */
void
exception_deliver_backtrace(
	kcdata_object_t  bt_object,
	ipc_port_t       exc_ports[static BT_EXC_PORTS_COUNT],
	exception_type_t exception)
{
	kern_return_t kr;
	mach_exception_data_type_t code[EXCEPTION_CODE_MAX];
	ipc_port_t target_port, bt_obj_port;

	assert(exception == EXC_GUARD);

	code[0] = exception;
	code[1] = 0;

	kcdata_object_reference(bt_object);
	bt_obj_port = convert_kcdata_object_to_port(bt_object);
	/* backtrace object ref consumed, no-senders is armed */

	if (!IP_VALID(bt_obj_port)) {
		return;
	}

	/*
	 * We are guaranteed at task_enqueue_exception_with_corpse() time
	 * that the exception port prefers backtrace delivery.
	 */
	for (unsigned int i = 0; i < BT_EXC_PORTS_COUNT; i++) {
		target_port = exc_ports[i];

		if (!IP_VALID(target_port)) {
			continue;
		}

		ip_mq_lock(target_port);
		if (!ip_active(target_port)) {
			ip_mq_unlock(target_port);
			continue;
		}
		ip_mq_unlock(target_port);

		kr = mach_exception_raise_backtrace(target_port,
		    bt_obj_port,
		    EXC_CORPSE_NOTIFY,
		    code,
		    EXCEPTION_CODE_MAX);

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			/* Exception is handled at this level */
			break;
		}
	}

	/* May trigger no-senders notification for backtrace object */
	ipc_port_release_send(bt_obj_port);

	return;
}

/*
 * Routine: check_exc_receiver_dependency
 * Purpose:
 *      Verify that the port destined for receiving this exception is not
 *      on the current task. This would cause hang in kernel for
 *      EXC_CRASH primarily. Note: If port is transferred
 *      between check and delivery then deadlock may happen.
 *
 * Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context.
 * Returns:
 *      KERN_SUCCESS if its ok to send exception message.
 */
static kern_return_t
check_exc_receiver_dependency(
	exception_type_t exception,
	struct exception_action *excp,
	lck_mtx_t *mutex)
{
	kern_return_t retval = KERN_SUCCESS;

	if (excp == NULL || exception != EXC_CRASH) {
		return retval;
	}

	task_t task = current_task();
	lck_mtx_lock(mutex);
	ipc_port_t xport = excp[exception].port;
	if (IP_VALID(xport) && ip_in_space_noauth(xport, task->itk_space)) {
		retval = KERN_FAILURE;
	}
	lck_mtx_unlock(mutex);
	return retval;
}


/*
 *	Routine:	exception_triage_thread
 *	Purpose:
 *		The thread caught an exception.
 *		We make an up-call to the thread's exception server.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		KERN_SUCCESS if exception is handled by any of the handlers.
 */
kern_return_t
exception_triage_thread(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt,
	thread_t                thread)
{
	task_t                  task;
	thread_ro_t             tro;
	host_priv_t             host_priv;
	lck_mtx_t               *mutex;
	struct exception_action *actions;
	kern_return_t   kr = KERN_FAILURE;

	assert(exception != EXC_RPC_ALERT);

	/*
	 * If this behavior has been requested by the the kernel
	 * (due to the boot environment), we should panic if we
	 * enter this function.  This is intended as a debugging
	 * aid; it should allow us to debug why we caught an
	 * exception in environments where debugging is especially
	 * difficult.
	 */
	if (panic_on_exception_triage) {
		panic("called exception_triage when it was forbidden by the boot environment");
	}

	/*
	 * Try to raise the exception at the activation level.
	 */
	mutex   = &thread->mutex;
	tro     = get_thread_ro(thread);
	actions = tro->tro_exc_actions;
	if (KERN_SUCCESS == check_exc_receiver_dependency(exception, actions, mutex)) {
		kr = exception_deliver(thread, exception, code, codeCnt, actions, mutex);
		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			goto out;
		}
	}

	/*
	 * Maybe the task level will handle it.
	 */
	task    = tro->tro_task;
	mutex   = &task->itk_lock_data;
	actions = task->exc_actions;
	if (KERN_SUCCESS == check_exc_receiver_dependency(exception, actions, mutex)) {
		kr = exception_deliver(thread, exception, code, codeCnt, actions, mutex);
		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			goto out;
		}
	}

	/*
	 * How about at the host level?
	 */
	host_priv = host_priv_self();
	mutex     = &host_priv->lock;
	actions   = host_priv->exc_actions;
	if (KERN_SUCCESS == check_exc_receiver_dependency(exception, actions, mutex)) {
		kr = exception_deliver(thread, exception, code, codeCnt, actions, mutex);
		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			goto out;
		}
	}

out:
	if ((exception != EXC_CRASH) && (exception != EXC_RESOURCE) &&
	    (exception != EXC_GUARD) && (exception != EXC_CORPSE_NOTIFY)) {
		thread_exception_return();
	}
	return kr;
}

#if __has_feature(ptrauth_calls)
static TUNABLE(bool, pac_exception_telemetry, "-pac_exception_telemetry", false);

CA_EVENT(pac_exception_event,
    CA_INT, exception,
    CA_INT, exception_code_0,
    CA_INT, exception_code_1,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name);

static void
pac_exception_triage(
	exception_type_t        exception,
	mach_exception_data_t   code)
{
	boolean_t traced_flag = FALSE;
	task_t task = current_task();
	void *proc = get_bsdtask_info(task);
	char *proc_name = (char *) "unknown";
	int pid = 0;

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (proc) {
		traced_flag = proc_is_traced(proc);
		/* Should only be called on current proc */
		proc_name = proc_name_address(proc);

		/*
		 * For a ptrauth violation, check if process isn't being ptraced and
		 * the task has the TFRO_PAC_EXC_FATAL flag set. If both conditions are true,
		 * terminate the task via exit_with_reason
		 */
		if (!traced_flag) {
			if (pac_exception_telemetry) {
				ca_event_t ca_event = CA_EVENT_ALLOCATE(pac_exception_event);
				CA_EVENT_TYPE(pac_exception_event) * pexc_event = ca_event->data;
				pexc_event->exception = exception;
				pexc_event->exception_code_0 = code[0];
				pexc_event->exception_code_1 = code[1];
				strlcpy(pexc_event->proc_name, proc_name, CA_PROCNAME_LEN);
				CA_EVENT_SEND(ca_event);
			}
			if (task_is_pac_exception_fatal(task)) {
				os_log_error(OS_LOG_DEFAULT, "%s: process %s[%d] hit a pac violation\n", __func__, proc_name, pid);
				exit_with_pac_exception(proc, exception, code[0], code[1]);
				thread_exception_return();
				/* NOT_REACHABLE */
			}
		}
	}
#endif /* MACH_BSD */
}
#endif /* __has_feature(ptrauth_calls) */

/*
 *	Routine:	exception_triage
 *	Purpose:
 *		The current thread caught an exception.
 *		We make an up-call to the thread's exception server.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		KERN_SUCCESS if exception is handled by any of the handlers.
 */
int debug4k_panic_on_exception = 0;
kern_return_t
exception_triage(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt)
{
	thread_t thread = current_thread();
	task_t   task   = current_task();

	assert(codeCnt > 0);

	if (VM_MAP_PAGE_SIZE(task->map) < PAGE_SIZE) {
		DEBUG4K_EXC("thread %p task %p map %p exception %d codes 0x%llx 0x%llx\n",
		    thread, task, task->map, exception, code[0], codeCnt > 1 ? code[1] : 0);
		if (debug4k_panic_on_exception) {
			panic("DEBUG4K thread %p task %p map %p exception %d codes 0x%llx 0x%llx",
			    thread, task, task->map, exception, code[0], codeCnt > 1 ? code[1] : 0);
		}
	}

#if (DEVELOPMENT || DEBUG)
#ifdef MACH_BSD
	if (proc_pid(get_bsdtask_info(task)) <= exception_log_max_pid) {
		record_system_event(SYSTEM_EVENT_TYPE_INFO, SYSTEM_EVENT_SUBSYSTEM_PROCESS, "process exit",
		    "exception_log_max_pid: pid %d (%s): sending exception %d (0x%llx 0x%llx)",
		    proc_pid(get_bsdtask_info(task)), proc_name_address(get_bsdtask_info(task)),
		    exception, code[0], codeCnt > 1 ? code[1] : 0);
	}
#endif /* MACH_BSD */
#endif /* DEVELOPMENT || DEBUG */

#if __has_feature(ptrauth_calls)
	if (exception & EXC_PTRAUTH_BIT) {
		exception &= ~EXC_PTRAUTH_BIT;
		assert(codeCnt == 2);
		pac_exception_triage(exception, code);
	}
#endif /* __has_feature(ptrauth_calls) */
	return exception_triage_thread(exception, code, codeCnt, thread);
}

kern_return_t
bsd_exception(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt)
{
	task_t                  task;
	lck_mtx_t               *mutex;
	thread_t                self = current_thread();
	kern_return_t           kr;

	/*
	 * Maybe the task level will handle it.
	 */
	task = current_task();
	mutex = &task->itk_lock_data;

	kr = exception_deliver(self, exception, code, codeCnt, task->exc_actions, mutex);

	if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}


/*
 * Raise an exception on a task.
 * This should tell launchd to launch Crash Reporter for this task.
 */
kern_return_t
task_exception_notify(exception_type_t exception,
    mach_exception_data_type_t exccode, mach_exception_data_type_t excsubcode)
{
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
	wait_interrupt_t                wsave;
	kern_return_t kr = KERN_SUCCESS;

	code[0] = exccode;
	code[1] = excsubcode;

	wsave = thread_interrupt_level(THREAD_UNINT);
	kr = exception_triage(exception, code, EXCEPTION_CODE_MAX);
	(void) thread_interrupt_level(wsave);
	return kr;
}


/*
 *	Handle interface for special performance monitoring
 *	This is a special case of the host exception handler
 */
kern_return_t
sys_perf_notify(thread_t thread, int pid)
{
	host_priv_t             hostp;
	ipc_port_t              xport;
	wait_interrupt_t        wsave;
	kern_return_t           ret;

	hostp = host_priv_self();       /* Get the host privileged ports */
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
	code[0] = 0xFF000001;           /* Set terminate code */
	code[1] = pid;          /* Pass out the pid */

	lck_mtx_lock(&hostp->lock);
	xport = hostp->exc_actions[EXC_RPC_ALERT].port;

	/* Make sure we're not catching our own exception */
	if (!IP_VALID(xport) ||
	    !ip_active(xport) ||
	    ip_in_space_noauth(xport, get_threadtask(thread)->itk_space)) {
		lck_mtx_unlock(&hostp->lock);
		return KERN_FAILURE;
	}

	lck_mtx_unlock(&hostp->lock);

	wsave = thread_interrupt_level(THREAD_UNINT);
	ret = exception_deliver(
		thread,
		EXC_RPC_ALERT,
		code,
		2,
		hostp->exc_actions,
		&hostp->lock);
	(void)thread_interrupt_level(wsave);

	return ret;
}
