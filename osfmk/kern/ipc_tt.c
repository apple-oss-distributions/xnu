/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 */

/*
 * File:	ipc_tt.c
 * Purpose:
 *	Task and thread related IPC functions.
 */

#include <IOKit/IOBSD.h> // IOTaskHasEntitlement

#include <ipc/ipc_policy.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_param.h>
#include <mach/task_special_ports.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <mach/memory_object_types.h>
#include <mach/mach_traps.h>
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map_server.h>

#include <kern/exc_guard.h>
#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <corpses/task_corpse.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/ux_handler.h>
#include <kern/misc_protos.h>
#include <kern/exception_policy.h>
#include <kdp/kdp_dyld.h>

#include <sys/proc_ro.h>

#include <vm/vm_map_xnu.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <mach/vm_types.h>
#include <libkern/coreanalytics/coreanalytics.h>

#include <security/mac_mach_internal.h>

#if CONFIG_CSR
#include <sys/csr.h>
#endif

#include <sys/code_signing.h> /* for developer mode state */

#if !defined(XNU_TARGET_OS_OSX) && !SECURE_KERNEL
extern int cs_relax_platform_task_ports;
#endif

extern boolean_t IOCurrentTaskHasEntitlement(const char *);
extern boolean_t proc_is_simulated(const proc_t);
extern struct proc* current_proc(void);

/* bootarg to create lightweight corpse for thread identity lockdown */
TUNABLE(bool, thid_should_crash, "thid_should_crash", true);

/*
 * Entitlement to disallow setting the exception port of task/thread unless you
 * are being debugged or are setting up the hardened task exception handler
 */
#define IPC_ONLY_ONE_EXCEPTION_PORT "com.apple.security.only-one-exception-port"

__options_decl(ipc_reply_port_type_t, uint32_t, {
	IRPT_NONE        = 0x00,
	IRPT_USER        = 0x01,
	IRPT_KERNEL      = 0x02,
});

/* forward declarations */
static kern_return_t special_port_allowed_with_task_flavor(int which, mach_task_flavor_t flavor);
static kern_return_t special_port_allowed_with_thread_flavor(int which, mach_thread_flavor_t flavor);
static void ipc_port_bind_special_reply_port_locked(ipc_port_t port, ipc_reply_port_type_t reply_type);
static void ipc_port_unbind_special_reply_port(thread_t thread, ipc_reply_port_type_t reply_type);
extern kern_return_t task_conversion_eval(task_t caller, task_t victim, int flavor);
static thread_inspect_t convert_port_to_thread_inspect_no_eval(ipc_port_t port);
static ipc_port_t convert_thread_to_port_with_flavor(thread_t, thread_ro_t, mach_thread_flavor_t flavor);
ipc_port_t convert_task_to_port_with_flavor(task_t task, mach_task_flavor_t flavor, task_grp_t grp);
kern_return_t task_set_special_port(task_t task, int which, ipc_port_t port);
kern_return_t task_get_special_port(task_t task, int which, ipc_port_t *portp);

/*
 *	Routine:	ipc_task_init
 *	Purpose:
 *		Initialize a task's IPC state.
 *
 *		If non-null, some state will be inherited from the parent.
 *		The parent must be appropriately initialized.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_init(
	task_t          task,
	task_t          parent)
{
	ipc_space_t space;
	ipc_port_t kport;
	ipc_port_t nport;
	kern_return_t kr;
	struct label *temp_label;
	int i;


	kr = ipc_space_create(IPC_LABEL_NONE, &space);
	if (kr != KERN_SUCCESS) {
		panic("ipc_task_init");
	}

	space->is_task = task;

	kport = ipc_kobject_alloc_port(IKO_NULL, IKOT_TASK_CONTROL,
	    IPC_KOBJECT_ALLOC_NONE);

	nport = ipc_kobject_alloc_port(IKO_NULL, IKOT_TASK_NAME,
	    IPC_KOBJECT_ALLOC_NONE);

	itk_lock_init(task);
	task->itk_task_ports[TASK_FLAVOR_CONTROL] = kport;
	task->itk_task_ports[TASK_FLAVOR_NAME] = nport;

	/* Lazily allocated on-demand */
	task->itk_task_ports[TASK_FLAVOR_INSPECT] = IP_NULL;
	task->itk_task_ports[TASK_FLAVOR_READ] = IP_NULL;
	task->itk_dyld_notify = NULL;
#if CONFIG_PROC_RESOURCE_LIMITS
	task->itk_resource_notify = NULL;
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

	task->itk_resume = IP_NULL; /* Lazily allocated on-demand */
#if CONFIG_CSR
	if (task_is_a_corpse_fork(task)) {
		/*
		 * No sender's notification for corpse would not
		 * work with a naked send right in kernel.
		 */
		task->itk_settable_self = IP_NULL;
	} else {
		/* we just made the port, no need to triple check */
		task->itk_settable_self = ipc_port_make_send_any(kport);
	}
#endif /* CONFIG_CSR */
	task->itk_debug_control = IP_NULL;
	task->itk_space = space;

#if CONFIG_MACF
	task->exc_actions[0].label = NULL;
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		mac_exc_associate_action_label(&task->exc_actions[i],
		    mac_exc_create_label(&task->exc_actions[i]));
	}
#endif

	/* always zero-out the first (unused) array element */
	bzero(&task->exc_actions[0], sizeof(task->exc_actions[0]));
	/* We don't need to inherit this */
	bzero(&task->hardened_exception_action, sizeof(task->hardened_exception_action));

	if (parent == TASK_NULL) {
		ipc_port_t port = IP_NULL;
		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			task->exc_actions[i].port = IP_NULL;
			task->exc_actions[i].flavor = 0;
			task->exc_actions[i].behavior = 0;
			task->exc_actions[i].privileged = FALSE;
		}/* for */

		kr = host_get_host_port(host_priv_self(), &port);
		assert(kr == KERN_SUCCESS);
		task->itk_host = port;

		task->itk_bootstrap = IP_NULL;
		task->itk_task_access = IP_NULL;

		for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
			task->itk_registered[i] = IP_NULL;
		}
	} else {
		itk_lock(parent);
		assert(parent->itk_task_ports[TASK_FLAVOR_CONTROL] != IP_NULL);

		/* inherit registered ports */

		for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
			task->itk_registered[i] =
			    ipc_port_copy_send_any(parent->itk_registered[i]);
		}

		/* inherit exception and bootstrap ports */

		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			temp_label = task->exc_actions[i].label;
			task->exc_actions[i] = parent->exc_actions[i];
			task->exc_actions[i].port =
			    exception_port_copy_send(parent->exc_actions[i].port);
			task->exc_actions[i].label = temp_label;
#if CONFIG_MACF
			mac_exc_inherit_action_label(parent->exc_actions + i,
			    task->exc_actions + i);
#endif
		}

		task->itk_host = host_port_copy_send(parent->itk_host);

		task->itk_bootstrap =
		    ipc_port_copy_send_mqueue(parent->itk_bootstrap);

		task->itk_task_access =
		    ipc_port_copy_send_mqueue(parent->itk_task_access);

		itk_unlock(parent);
	}
}

/*
 *	Routine:	ipc_task_copyout_control_port
 *	Purpose:
 *		Copyout the task control port as pinned
 *      and stash the send right name in the port
 *  Condition:
 *      Nothing locked.
 */
void
ipc_task_copyout_control_port(
	task_t            task)
{
	ipc_port_t kport = task->itk_task_ports[TASK_FLAVOR_CONTROL];
	mach_port_name_t name;
	ipc_port_t pport;

#if CONFIG_CSR
	assert(kport == task->itk_settable_self);
#endif /* CONFIG_CSR */
	assert(!task_is_a_corpse(task));

	pport = ipc_port_make_send_any(kport);
	/*
	 * mach_task_self() is pinned, memorize the name we gave it
	 * in ip_receiver_name (it's an abuse as this port really
	 * isn't a message queue, but the field is up for grabs
	 * and otherwise `MACH_PORT_SPECIAL_DEFAULT` for special ports).
	 *
	 * port_name_to_task* use this to fastpath IPCs.
	 *
	 * ipc_task_disable() will revert this when the task dies.
	 */
	name = ipc_port_copyout_send_pinned(pport, task->itk_space);
	if (MACH_PORT_VALID(name)) {
		pport->ip_receiver_name = name;
	}
}

/*
 *	Routine:	ipc_thread_set_immovable_pinned
 *	Purpose:
 *		Copyout the task control port as pinned and immovable
 *      and stash the send right name in the port
 *  Notes:
 *		Consumes a thread ref; produces a naked send right
 *		which may be invalid.
 */
void
ipc_thread_set_immovable_pinned(
	thread_t            thread)
{
	ipc_port_t kport = convert_thread_to_port_immovable(thread);

	task_t task = get_threadtask(thread);
	mach_port_name_t name;

#if CONFIG_CSR
	assert(kport == thread->thread_settable_self_port);
#endif /* CONFIG_CSR */
	assert(!task_is_a_corpse(task));

	name = ipc_port_copyout_send_pinned(kport, task->itk_space);
}

/*
 *	Routine:	ipc_task_enable
 *	Purpose:
 *		Enable a task for IPC access.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_task_enable(
	task_t          task)
{
	ipc_port_t kport;
	ipc_port_t nport;
	ipc_port_t iport;
	ipc_port_t rdport;

	ipc_space_set_policy(task->itk_space, ipc_policy_for_task(task));

	itk_lock(task);
	if (!task->active) {
		/*
		 * task has been terminated before we can enable IPC access.
		 * The check is to make sure we don't accidentally re-enable
		 * the task ports _after_ they've been disabled during
		 * task_terminate_internal(), in which case we will hit the
		 * !task->ipc_active assertion in ipc_task_terminate().
		 *
		 * Technically we should grab task lock when checking task
		 * active bit, but since task termination unsets task->active
		 * _before_ calling ipc_task_disable(), we can always see the
		 * truth with just itk_lock() and bail if disable has been called.
		 */
		itk_unlock(task);
		return;
	}

	/* verify vm_map_setup called */
	assert(task_is_a_corpse(task) || task->map->owning_task == task);

	/* verify task_set_control_port_options called */
	assert(task_is_a_corpse_fork(task) || task == kernel_task ||
	    task_get_control_port_options(task) != TASK_CONTROL_PORT_OPTIONS_INVALID);

	assert(!task->ipc_active || task_is_a_corpse(task));
	task->ipc_active = true;

	kport = task->itk_task_ports[TASK_FLAVOR_CONTROL];
	if (kport != IP_NULL) {
		ipc_kobject_enable(kport, task, IKOT_TASK_CONTROL);
	}
	nport = task->itk_task_ports[TASK_FLAVOR_NAME];
	if (nport != IP_NULL) {
		ipc_kobject_enable(nport, task, IKOT_TASK_NAME);
	}
	iport = task->itk_task_ports[TASK_FLAVOR_INSPECT];
	if (iport != IP_NULL) {
		ipc_kobject_enable(iport, task, IKOT_TASK_INSPECT);
	}
	rdport = task->itk_task_ports[TASK_FLAVOR_READ];
	if (rdport != IP_NULL) {
		ipc_kobject_enable(rdport, task, IKOT_TASK_READ);
	}

	itk_unlock(task);
}

/*
 *	Routine:	ipc_task_disable
 *	Purpose:
 *		Disable IPC access to a task.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_disable(
	task_t          task)
{
	ipc_port_t kport;
	ipc_port_t nport;
	ipc_port_t iport;
	ipc_port_t rdport;
	ipc_port_t rport;

	itk_lock(task);

	/*
	 * This innocuous looking line is load bearing.
	 *
	 * It is used to disable the creation of lazy made ports.
	 * We must do so before we drop the last reference on the task,
	 * as task ports do not own a reference on the task, and
	 * convert_port_to_task* will crash trying to resurect a task.
	 */
	task->ipc_active = false;

	kport = task->itk_task_ports[TASK_FLAVOR_CONTROL];
	if (kport != IP_NULL) {
		ipc_kobject_disable(kport, IKOT_TASK_CONTROL);
	}
	nport = task->itk_task_ports[TASK_FLAVOR_NAME];
	if (nport != IP_NULL) {
		ipc_kobject_disable(nport, IKOT_TASK_NAME);
	}
	iport = task->itk_task_ports[TASK_FLAVOR_INSPECT];
	if (iport != IP_NULL) {
		ipc_kobject_disable(iport, IKOT_TASK_INSPECT);
	}
	rdport = task->itk_task_ports[TASK_FLAVOR_READ];
	if (rdport != IP_NULL) {
		/* clears ikol_alt_port */
		ipc_kobject_disable(rdport, IKOT_TASK_READ);
	}

	rport = task->itk_resume;
	if (rport != IP_NULL) {
		/*
		 * From this point onwards this task is no longer accepting
		 * resumptions.
		 *
		 * There are still outstanding suspensions on this task,
		 * even as it is being torn down. Disconnect the task
		 * from the rport, thereby "orphaning" the rport. The rport
		 * itself will go away only when the last suspension holder
		 * destroys his SO right to it -- when he either
		 * exits, or tries to actually use that last SO right to
		 * resume this (now non-existent) task.
		 */
		ipc_kobject_disable(rport, IKOT_TASK_RESUME);
	}
	itk_unlock(task);
}

/*
 *	Routine:	ipc_task_terminate
 *	Purpose:
 *		Clean up and destroy a task's IPC state.
 *	Conditions:
 *		Nothing locked.  The task must be suspended.
 *		(Or the current thread must be in the task.)
 */

void
ipc_task_terminate(
	task_t          task)
{
	ipc_port_t kport;
	ipc_port_t nport;
	ipc_port_t iport;
	ipc_port_t rdport;
	ipc_port_t rport;
#if CONFIG_CSR
	ipc_port_t sself;
#endif /* CONFIG_CSR */
	ipc_port_t *notifiers_ptr = NULL;

	itk_lock(task);

	/*
	 * If we ever failed to clear ipc_active before the last reference
	 * was dropped, lazy ports might be made and used after the last
	 * reference is dropped and cause use after free (see comment in
	 * ipc_task_disable()).
	 */
	assert(!task->ipc_active);

	kport = task->itk_task_ports[TASK_FLAVOR_CONTROL];
#if CONFIG_CSR
	sself = task->itk_settable_self;
#endif /* CONFIG_CSR */

	if (kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		return;
	}
	task->itk_task_ports[TASK_FLAVOR_CONTROL] = IP_NULL;

	rdport = task->itk_task_ports[TASK_FLAVOR_READ];
	task->itk_task_ports[TASK_FLAVOR_READ] = IP_NULL;

	iport = task->itk_task_ports[TASK_FLAVOR_INSPECT];
	task->itk_task_ports[TASK_FLAVOR_INSPECT] = IP_NULL;

	nport = task->itk_task_ports[TASK_FLAVOR_NAME];
	assert(nport != IP_NULL);
	task->itk_task_ports[TASK_FLAVOR_NAME] = IP_NULL;

	if (task->itk_dyld_notify) {
		notifiers_ptr = task->itk_dyld_notify;
		task->itk_dyld_notify = NULL;
	}

	rport = task->itk_resume;
	task->itk_resume = IP_NULL;

	itk_unlock(task);

	/* release the naked send rights */
#if CONFIG_CSR
	if (IP_VALID(sself)) {
		ipc_port_release_send(sself);
	}
#endif /* CONFIG_CSR */

	if (notifiers_ptr) {
		for (int i = 0; i < DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT; i++) {
			if (IP_VALID(notifiers_ptr[i])) {
				ipc_port_release_send(notifiers_ptr[i]);
			}
		}
		kfree_type(ipc_port_t, DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT, notifiers_ptr);
	}

	if (IP_VALID(task->hardened_exception_action.ea.port)) {
		ipc_port_release_send(task->hardened_exception_action.ea.port);
	}

	for (int i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(task->exc_actions[i].port)) {
			ipc_port_release_send(task->exc_actions[i].port);
		}
#if CONFIG_MACF
		mac_exc_free_action_label(task->exc_actions + i);
#endif
	}

	if (IP_VALID(task->itk_host)) {
		ipc_port_release_send(task->itk_host);
	}

	if (IP_VALID(task->itk_bootstrap)) {
		ipc_port_release_send(task->itk_bootstrap);
	}

	if (IP_VALID(task->itk_task_access)) {
		ipc_port_release_send(task->itk_task_access);
	}

	if (IP_VALID(task->itk_debug_control)) {
		ipc_port_release_send(task->itk_debug_control);
	}

#if CONFIG_PROC_RESOURCE_LIMITS
	if (IP_VALID(task->itk_resource_notify)) {
		ipc_port_release_send(task->itk_resource_notify);
	}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

	for (int i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		if (IP_VALID(task->itk_registered[i])) {
			ipc_port_release_send(task->itk_registered[i]);
		}
	}

	/* clears read port ikol_alt_port, must be done first */
	if (rdport != IP_NULL) {
		ipc_kobject_dealloc_port(rdport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_TASK_READ);
	}
	ipc_kobject_dealloc_port(kport, IPC_KOBJECT_NO_MSCOUNT,
	    IKOT_TASK_CONTROL);

	/* destroy other kernel ports */
	ipc_kobject_dealloc_port(nport, IPC_KOBJECT_NO_MSCOUNT,
	    IKOT_TASK_NAME);
	if (iport != IP_NULL) {
		ipc_kobject_dealloc_port(iport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_TASK_INSPECT);
	}
	if (rport != IP_NULL) {
		ipc_kobject_dealloc_port(rport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_TASK_RESUME);
	}

	itk_lock_destroy(task);
}

/*
 *	Routine:	ipc_task_reset
 *	Purpose:
 *		Reset a task's IPC state to protect it when
 *		it enters an elevated security context. The
 *		task name port can remain the same - since it
 *              represents no specific privilege.
 *	Conditions:
 *		Nothing locked.  The task must be suspended.
 *		(Or the current thread must be in the task.)
 */

void
ipc_task_reset(
	task_t          task)
{
	ipc_port_t old_kport, new_kport;
#if CONFIG_CSR
	ipc_port_t old_sself;
#endif /* CONFIG_CSR */
	ipc_port_t old_rdport;
	ipc_port_t old_iport;
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	ipc_port_t old_hardened_exception;
	ipc_port_t *notifiers_ptr = NULL;

#if CONFIG_MACF
	/* Fresh label to unset credentials in existing labels. */
	struct label *unset_label = mac_exc_create_label(NULL);
#endif

	new_kport = ipc_kobject_alloc_port((ipc_kobject_t)task,
	    IKOT_TASK_CONTROL, IPC_KOBJECT_ALLOC_NONE);
	/*
	 * ipc_task_reset() only happens during sugid or corpsify.
	 *
	 * (1) sugid happens early in exec_mach_imgact(),
	 *     at which point the old task port has not been enabled,
	 *     and is left movable.
	 * (2) corpse cannot execute more code so the notion of the immovable
	 *     task port is bogus, and should appear as if it doesn't have one.
	 *
	 */
	itk_lock(task);

	old_kport = task->itk_task_ports[TASK_FLAVOR_CONTROL];
	old_rdport = task->itk_task_ports[TASK_FLAVOR_READ];
	old_iport = task->itk_task_ports[TASK_FLAVOR_INSPECT];

	if (old_kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		ipc_kobject_dealloc_port(new_kport, IPC_KOBJECT_NO_MSCOUNT, IKOT_TASK_CONTROL);
#if CONFIG_MACF
		mac_exc_free_label(unset_label);
#endif
		return;
	}

	task->itk_task_ports[TASK_FLAVOR_CONTROL] = new_kport;

#if CONFIG_CSR
	old_sself = task->itk_settable_self;
	if (task_is_a_corpse(task)) {
		/* No extra send right for coprse, needed to arm no-sender notification */
		task->itk_settable_self = IP_NULL;
	} else {
		/* we just made the port, no need to triple check */
		task->itk_settable_self = ipc_port_make_send_any(new_kport);
	}
#endif /* CONFIG_CSR */

	ipc_kobject_disable(old_kport, IKOT_TASK_CONTROL);

	/* Reset the read and inspect flavors of task port */
	task->itk_task_ports[TASK_FLAVOR_READ] = IP_NULL;
	task->itk_task_ports[TASK_FLAVOR_INSPECT] = IP_NULL;

	if (IP_VALID(task->hardened_exception_action.ea.port)
	    && !task->hardened_exception_action.ea.privileged) {
		old_hardened_exception = task->hardened_exception_action.ea.port;
		task->hardened_exception_action.ea.port = IP_NULL;
	}

	for (int i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		old_exc_actions[i] = IP_NULL;

		if (i == EXC_CORPSE_NOTIFY && task_corpse_pending_report(task)) {
			continue;
		}

		if (!task->exc_actions[i].privileged) {
#if CONFIG_MACF
			mac_exc_update_action_label(task->exc_actions + i, unset_label);
#endif
			old_exc_actions[i] = task->exc_actions[i].port;
			task->exc_actions[i].port = IP_NULL;
		}
	}/* for */

	if (IP_VALID(task->itk_debug_control)) {
		ipc_port_release_send(task->itk_debug_control);
	}
	task->itk_debug_control = IP_NULL;

	if (task->itk_dyld_notify) {
		notifiers_ptr = task->itk_dyld_notify;
		task->itk_dyld_notify = NULL;
	}

	itk_unlock(task);

#if CONFIG_MACF
	mac_exc_free_label(unset_label);
#endif

	/* release the naked send rights */
#if CONFIG_CSR
	if (IP_VALID(old_sself)) {
		ipc_port_release_send(old_sself);
	}
#endif /* CONFIG_CSR */

	if (notifiers_ptr) {
		for (int i = 0; i < DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT; i++) {
			if (IP_VALID(notifiers_ptr[i])) {
				ipc_port_release_send(notifiers_ptr[i]);
			}
		}
		kfree_type(ipc_port_t, DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT, notifiers_ptr);
	}

	ipc_port_release_send(old_hardened_exception);

	for (int i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(old_exc_actions[i])) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}

	/* destroy all task port flavors */
	if (old_rdport != IP_NULL) {
		/* read port ikol_alt_port may point to kport, dealloc first */
		ipc_kobject_dealloc_port(old_rdport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_TASK_READ);
	}
	ipc_kobject_dealloc_port(old_kport, IPC_KOBJECT_NO_MSCOUNT,
	    IKOT_TASK_CONTROL);

	if (old_iport != IP_NULL) {
		ipc_kobject_dealloc_port(old_iport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_TASK_INSPECT);
	}
}

/*
 *	Routine:	ipc_thread_init
 *	Purpose:
 *		Initialize a thread's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_init(
	__unused task_t task,
	thread_t        thread)
{
	ipc_port_t         kport;

	/*
	 * pthreads are subsequently pinned via
	 * ipc_port_copyout_send_pinned() whereas raw threads are left
	 * unpinned.
	 */
	kport = ipc_kobject_alloc_port(thread, IKOT_THREAD_CONTROL,
	    IPC_KOBJECT_ALLOC_NONE);

	/* we just made the port, no need to triple check */
#if CONFIG_CSR
	thread->thread_settable_self_port = ipc_port_make_send_any(kport);
#endif /* CONFIG_CSR */
	thread->thread_ports[THREAD_FLAVOR_CONTROL] = kport;

	thread->thread_resume_port = IP_NULL;

	thread->ith_special_reply_port = IP_NULL;

#if IMPORTANCE_INHERITANCE
	thread->ith_assertions = 0;
#endif

	thread->ipc_active = true;
	ipc_kmsg_queue_init(&thread->ith_messages);

	thread->ith_kernel_reply_port = IP_NULL;
}

struct thread_init_exc_actions {
	struct exception_action array[EXC_TYPES_COUNT];
};

static void
ipc_thread_init_exc_actions(thread_ro_t tro)
{
	struct exception_action *actions;

	actions = kalloc_type(struct thread_init_exc_actions,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL)->array;

#if CONFIG_MACF
	for (size_t i = 0; i < EXC_TYPES_COUNT; ++i) {
		mac_exc_associate_action_label(&actions[i],
		    mac_exc_create_label(&actions[i]));
	}
#endif

	zalloc_ro_update_field(ZONE_ID_THREAD_RO, tro, tro_exc_actions, &actions);
}

static void
ipc_thread_destroy_exc_actions(thread_ro_t tro)
{
	struct exception_action *actions = tro->tro_exc_actions;

	if (actions) {
#if CONFIG_MACF
		for (size_t i = 0; i < EXC_TYPES_COUNT; ++i) {
			mac_exc_free_action_label(actions + i);
		}
#endif

		zalloc_ro_clear_field(ZONE_ID_THREAD_RO, tro, tro_exc_actions);
		struct thread_init_exc_actions *tr_actions =
		    (struct thread_init_exc_actions *)actions;
		kfree_type(struct thread_init_exc_actions, tr_actions);
	}
}

/*
 *	Routine:	ipc_thread_disable
 *	Purpose:
 *		Clean up and destroy a thread's IPC state.
 *	Conditions:
 *		Thread locked.
 */
void
ipc_thread_disable(
	thread_t        thread)
{
	ipc_port_t      kport = thread->thread_ports[THREAD_FLAVOR_CONTROL];
	ipc_port_t      iport = thread->thread_ports[THREAD_FLAVOR_INSPECT];
	ipc_port_t      rdport = thread->thread_ports[THREAD_FLAVOR_READ];
	ipc_port_t      rport = thread->thread_resume_port;

	/*
	 * This innocuous looking line is load bearing.
	 *
	 * It is used to disable the creation of lazy made ports.
	 * We must do so before we drop the last reference on the thread,
	 * as thread ports do not own a reference on the thread, and
	 * convert_port_to_thread* will crash trying to resurect a thread.
	 */
	thread->ipc_active = false;

	if (kport != IP_NULL) {
		ipc_kobject_disable(kport, IKOT_THREAD_CONTROL);
	}

	if (iport != IP_NULL) {
		ipc_kobject_disable(iport, IKOT_THREAD_INSPECT);
	}

	if (rdport != IP_NULL) {
		/* clears ikol_alt_port */
		ipc_kobject_disable(rdport, IKOT_THREAD_READ);
	}

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_special_reply_port)) {
		ipc_port_unbind_special_reply_port(thread, IRPT_USER);
	}

	if (rport != IP_NULL) {
		/*
		 * There may be outstanding suspensions on this thread.
		 * The port will go away when the last suspension holder
		 * destroys the send right.
		 */
		ipc_kobject_disable(rport, IKOT_THREAD_RESUME);
	}
}

/*
 *	Routine:	ipc_thread_terminate
 *	Purpose:
 *		Clean up and destroy a thread's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_terminate(
	thread_t        thread)
{
	thread_ro_t tro = get_thread_ro(thread);
	ipc_port_t kport = IP_NULL;
	ipc_port_t iport = IP_NULL;
	ipc_port_t rdport = IP_NULL;
#if CONFIG_CSR
	ipc_port_t sport = IP_NULL;
#endif /* CONFIG_CSR */
	ipc_port_t rport = IP_NULL;

	thread_mtx_lock(thread);

	/*
	 * If we ever failed to clear ipc_active before the last reference
	 * was dropped, lazy ports might be made and used after the last
	 * reference is dropped and cause use after free (see comment in
	 * ipc_thread_disable()).
	 */
	assert(!thread->ipc_active);

	kport = thread->thread_ports[THREAD_FLAVOR_CONTROL];
	iport = thread->thread_ports[THREAD_FLAVOR_INSPECT];
	rdport = thread->thread_ports[THREAD_FLAVOR_READ];
#if CONFIG_CSR
	sport = thread->thread_settable_self_port;
#endif /* CONFIG_CSR */
	rport = thread->thread_resume_port;

	if (kport != IP_NULL) {
#if CONFIG_CSR
		if (IP_VALID(sport)) {
			ipc_port_release_send(sport);
		}
#endif /* CONFIG_CSR */

		for (int i = 0; i < THREAD_SELF_PORT_COUNT; i++) {
			thread->thread_ports[i] = IP_NULL;
		}
#if CONFIG_CSR
		thread->thread_settable_self_port = IP_NULL;
#endif /* CONFIG_CSR */

		thread->thread_resume_port = IP_NULL;

		if (tro->tro_exc_actions != NULL) {
			for (int i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
				if (IP_VALID(tro->tro_exc_actions[i].port)) {
					ipc_port_release_send(tro->tro_exc_actions[i].port);
				}
			}
			ipc_thread_destroy_exc_actions(tro);
		}
	}

#if IMPORTANCE_INHERITANCE
	assert(thread->ith_assertions == 0);
#endif

	assert(ipc_kmsg_queue_empty(&thread->ith_messages));
	thread_mtx_unlock(thread);

	/* clears read port ikol_alt_port, must be done first */
	if (rdport != IP_NULL) {
		ipc_kobject_dealloc_port(rdport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_READ);
	}

	if (kport != IP_NULL) {
		ipc_kobject_dealloc_port(kport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_CONTROL);
	}
	if (iport != IP_NULL) {
		ipc_kobject_dealloc_port(iport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_INSPECT);
	}
	if (thread->ith_kernel_reply_port != IP_NULL) {
		thread_dealloc_kernel_special_reply_port(thread);
	}

	if (rport != IP_NULL) {
		ipc_kobject_dealloc_port(rport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_RESUME);
	}
}

/*
 *	Routine:	ipc_thread_reset
 *	Purpose:
 *		Reset the IPC state for a given Mach thread when
 *		its task enters an elevated security context.
 *		All flavors of thread port and its exception ports have
 *		to be reset.  Its RPC reply port cannot have any
 *		rights outstanding, so it should be fine. The thread
 *		inspect and read port are set to NULL.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_reset(
	thread_t        thread)
{
	thread_ro_t tro = get_thread_ro(thread);
	ipc_port_t old_kport, new_kport;
#if CONFIG_CSR
	ipc_port_t old_sself;
#endif /* CONFIG_CSR */
	ipc_port_t old_rdport;
	ipc_port_t old_iport;
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	boolean_t  has_old_exc_actions = FALSE;
	int i;

#if CONFIG_MACF
	struct label *new_label = mac_exc_create_label(NULL);
#endif

	new_kport = ipc_kobject_alloc_port((ipc_kobject_t)thread,
	    IKOT_THREAD_CONTROL, IPC_KOBJECT_ALLOC_NONE);
	/*
	 * ipc_thread_reset() only happens during sugid or corpsify.
	 *
	 * (1) sugid happens early in exec_mach_imgact(), at which point
	 *     the old thread port is still movable.
	 * (2) corpse cannot execute more code so the notion of the immovable
	 *     thread port is bogus, and should appear as if it doesn't have one.
	 */

	thread_mtx_lock(thread);

	old_kport = thread->thread_ports[THREAD_FLAVOR_CONTROL];
	old_rdport = thread->thread_ports[THREAD_FLAVOR_READ];
	old_iport = thread->thread_ports[THREAD_FLAVOR_INSPECT];

#if CONFIG_CSR
	old_sself = thread->thread_settable_self_port;
#endif /* CONFIG_CSR */

	if (old_kport == IP_NULL && thread->inspection == FALSE) {
		/* thread is already terminated (can this happen?) */
		thread_mtx_unlock(thread);
		ipc_kobject_dealloc_port(new_kport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_CONTROL);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return;
	}

	thread->ipc_active = true;

	for (i = 0; i < THREAD_SELF_PORT_COUNT; i++) {
		thread->thread_ports[i] = IP_NULL;
	}
	thread->thread_ports[THREAD_FLAVOR_CONTROL] = new_kport;
#if CONFIG_CSR
	/* we just made the port, no need to triple check */
	thread->thread_settable_self_port = ipc_port_make_send_any(new_kport);
#endif /* CONFIG_CSR */

	if (old_kport != IP_NULL) {
		(void)ipc_kobject_disable(old_kport, IKOT_THREAD_CONTROL);
	}
	if (old_rdport != IP_NULL) {
		/* clears ikol_alt_port */
		(void)ipc_kobject_disable(old_rdport, IKOT_THREAD_READ);
	}
	if (old_iport != IP_NULL) {
		(void)ipc_kobject_disable(old_iport, IKOT_THREAD_INSPECT);
	}

	/*
	 * Only ports that were set by root-owned processes
	 * (privileged ports) should survive
	 */
	if (tro->tro_exc_actions != NULL) {
		has_old_exc_actions = TRUE;
		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			if (tro->tro_exc_actions[i].privileged) {
				old_exc_actions[i] = IP_NULL;
			} else {
#if CONFIG_MACF
				mac_exc_update_action_label(tro->tro_exc_actions + i, new_label);
#endif
				old_exc_actions[i] = tro->tro_exc_actions[i].port;
				tro->tro_exc_actions[i].port = IP_NULL;
			}
		}
	}

	thread_mtx_unlock(thread);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	/* release the naked send rights */
#if CONFIG_CSR
	if (IP_VALID(old_sself)) {
		ipc_port_release_send(old_sself);
	}
#endif /* CONFIG_CSR */

	if (has_old_exc_actions) {
		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}

	/* destroy the kernel ports */
	if (old_rdport != IP_NULL) {
		ipc_kobject_dealloc_port(old_rdport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_READ);
		/* ikol_alt_port cleared */
	}
	if (old_kport != IP_NULL) {
		ipc_kobject_dealloc_port(old_kport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_CONTROL);
	}

	if (old_iport != IP_NULL) {
		ipc_kobject_dealloc_port(old_iport, IPC_KOBJECT_NO_MSCOUNT,
		    IKOT_THREAD_INSPECT);
	}

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_special_reply_port)) {
		ipc_port_unbind_special_reply_port(thread, IRPT_USER);
	}
}

/*
 *	Routine:	retrieve_task_self_fast
 *	Purpose:
 *		Optimized version of retrieve_task_self,
 *		that only works for the current task.
 *
 *		Return a send right (possibly null/dead)
 *		for the task's user-visible self port.
 *	Conditions:
 *		Nothing locked.
 */

static ipc_port_t
retrieve_task_self_fast(
	task_t          task)
{
	ipc_port_t port = IP_NULL;
	ipc_port_t kport = task->itk_task_ports[TASK_FLAVOR_CONTROL];

	assert(task == current_task());

	itk_lock(task);
	assert(kport != IP_NULL);

#if CONFIG_CSR
	if (task->itk_settable_self != kport) {
		port = ipc_port_copy_send_mqueue(task->itk_settable_self);
	} else
#endif
	{
		port = ipc_kobject_make_send(kport, task, IKOT_TASK_CONTROL);
	}

	itk_unlock(task);

	return port;
}

/*
 *	Routine:	mach_task_is_self
 *	Purpose:
 *      [MIG call] Checks if the task (control/read/inspect/name/movable)
 *      port is pointing to current_task.
 */
kern_return_t
mach_task_is_self(
	task_t         task,
	boolean_t     *is_self)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	*is_self = (task == current_task());

	return KERN_SUCCESS;
}

/*
 *	Routine:	retrieve_thread_self_fast
 *	Purpose:
 *		Return a send right (possibly null/dead)
 *		for the thread's user-visible self port.
 *
 *		Only works for the current thread.
 *
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
retrieve_thread_self_fast(
	thread_t                thread)
{
	ipc_port_t port = IP_NULL;

	assert(thread == current_thread());

	thread_mtx_lock(thread);

#if CONFIG_CSR
	if (thread->thread_settable_self_port != thread->thread_ports[THREAD_FLAVOR_CONTROL]) {
		port = ipc_port_copy_send_mqueue(thread->thread_settable_self_port);
	} else
#endif
	{
		port = ipc_kobject_make_send(thread->thread_ports[THREAD_FLAVOR_CONTROL],
		    thread, IKOT_THREAD_CONTROL);
	}

	thread_mtx_unlock(thread);

	return port;
}

/*
 *	Routine:	task_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for their own task port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
task_self_trap(
	__unused struct task_self_trap_args *args)
{
	task_t task = current_task();
	ipc_port_t sright;

	sright = retrieve_task_self_fast(task);
	return ipc_port_copyout_send_allow_immovable(sright, task->itk_space);
}

/*
 *	Routine:	thread_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own thread port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
thread_self_trap(
	__unused struct thread_self_trap_args *args)
{
	thread_t thread = current_thread();
	ipc_space_t space = current_space();
	ipc_port_t sright;
	mach_port_name_t name;

	sright = retrieve_thread_self_fast(thread);
	name = ipc_port_copyout_send_allow_immovable(sright, space);
	return name;
}

/*
 *	Routine:	mach_reply_port [mach trap]
 *	Purpose:
 *		Allocate a port for the caller.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
mach_reply_port(
	__unused struct mach_reply_port_args *args)
{
	ipc_port_t port;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_port_alloc(current_space(), IPC_OBJECT_LABEL(IOT_PORT),
	    IP_INIT_NONE, &name, &port);
	if (kr == KERN_SUCCESS) {
		ip_mq_unlock(port);
	} else {
		name = MACH_PORT_NULL;
	}
	return name;
}

/*
 *	Routine:	thread_get_special_reply_port [mach trap]
 *	Purpose:
 *		Allocate a special reply port for the calling thread.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		mach_port_name_t: send right & receive right for special reply port.
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
thread_get_special_reply_port(
	__unused struct thread_get_special_reply_port_args *args)
{
	ipc_port_t port;
	mach_port_name_t name;
	kern_return_t kr;
	thread_t thread = current_thread();

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_special_reply_port)) {
		ipc_port_unbind_special_reply_port(thread, IRPT_USER);
	}

	kr = ipc_port_alloc(current_space(), IPC_OBJECT_LABEL(IOT_SPECIAL_REPLY_PORT),
	    IP_INIT_MAKE_SEND_RIGHT, &name, &port);
	if (kr == KERN_SUCCESS) {
		ipc_port_bind_special_reply_port_locked(port, IRPT_USER);
		ip_mq_unlock(port);
	} else {
		name = MACH_PORT_NULL;
	}
	return name;
}

/*
 *	Routine:	thread_get_kernel_special_reply_port
 *	Purpose:
 *		Allocate a kernel special reply port for the calling thread.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		Creates and sets kernel special reply port.
 *		KERN_SUCCESS on Success.
 *		KERN_FAILURE on Failure.
 */

kern_return_t
thread_get_kernel_special_reply_port(void)
{
	ipc_port_t port = IP_NULL;
	thread_t thread = current_thread();

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_kernel_reply_port)) {
		ipc_port_unbind_special_reply_port(thread, IRPT_KERNEL);
	}

	port = ipc_port_alloc_special(ipc_space_reply,
	    IPC_OBJECT_LABEL(IOT_SPECIAL_REPLY_PORT), IP_INIT_NONE);
	ipc_port_bind_special_reply_port_locked(port, IRPT_KERNEL);
	ip_mq_unlock(port);

	/* release the reference returned by ipc_port_alloc_special */
	ip_release(port);

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_port_bind_special_reply_port_locked
 *	Purpose:
 *		Bind the given port to current thread as a special reply port.
 *	Conditions:
 *		Port locked.
 *	Returns:
 *		None.
 */

static void
ipc_port_bind_special_reply_port_locked(
	ipc_port_t            port,
	ipc_reply_port_type_t reply_type)
{
	thread_t thread = current_thread();

	assert(ip_is_special_reply_port(port));
	assert(port->ip_sync_link_state == PORT_SYNC_LINK_ANY);

	ip_reference(port);

	if (reply_type == IRPT_USER) {
		assert(thread->ith_special_reply_port == IP_NULL);
		thread->ith_special_reply_port = port;
	} else {
		assert(thread->ith_kernel_reply_port == IP_NULL);
		thread->ith_kernel_reply_port = port;
	}

	port->ip_messages.imq_srp_owner_thread = thread;

	ipc_special_reply_port_bits_reset(port);
}

/*
 *	Routine:	ipc_port_unbind_special_reply_port
 *	Purpose:
 *		Unbind the thread's special reply port.
 *		If the special port has threads waiting on turnstile,
 *		update it's inheritor.
 *	Condition:
 *		Nothing locked.
 *	Returns:
 *		None.
 */
static void
ipc_port_unbind_special_reply_port(
	thread_t              thread,
	ipc_reply_port_type_t reply_type)
{
	bool should_refer_to_user_reply_port = reply_type == (IRPT_USER);

	ipc_port_t special_reply_port = should_refer_to_user_reply_port ? thread->ith_special_reply_port : thread->ith_kernel_reply_port;

	ip_mq_lock(special_reply_port);

	if (should_refer_to_user_reply_port) {
		thread->ith_special_reply_port = IP_NULL;
	} else {
		thread->ith_kernel_reply_port = IP_NULL;
	}

	ipc_port_adjust_special_reply_port_locked(special_reply_port, NULL,
	    IPC_PORT_ADJUST_UNLINK_THREAD, FALSE);
	/* port unlocked */

	/* Destroy the port if its kernel special reply, else just release a ref */
	if (reply_type == IRPT_USER) {
		ip_release(special_reply_port);
	} else {
		ip_mq_lock(special_reply_port);
		ipc_port_destroy(special_reply_port);
	}
}

/*
 *	Routine:	thread_dealloc_kernel_special_reply_port
 *	Purpose:
 *		Unbind the thread's kernel special reply port.
 *		If the special port has threads waiting on turnstile,
 *		update it's inheritor.
 *	Condition:
 *		Called on current thread or a terminated thread.
 *	Returns:
 *		None.
 */

void
thread_dealloc_kernel_special_reply_port(thread_t thread)
{
	ipc_port_unbind_special_reply_port(thread, IRPT_KERNEL);
}

/*
 *	Routine:	thread_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the thread's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null.
 *		KERN_FAILURE		The thread is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
thread_get_special_port(
	thread_inspect_t         thread,
	int                      which,
	ipc_port_t              *portp);

static kern_return_t
thread_get_special_port_internal(
	thread_inspect_t         thread,
	thread_ro_t              tro,
	int                      which,
	ipc_port_t              *portp,
	mach_thread_flavor_t     flavor)
{
	kern_return_t      kr;
	ipc_port_t port;

	if ((kr = special_port_allowed_with_thread_flavor(which, flavor)) != KERN_SUCCESS) {
		return kr;
	}

	thread_mtx_lock(thread);
	if (!thread->active) {
		thread_mtx_unlock(thread);
		return KERN_FAILURE;
	}

	switch (which) {
	case THREAD_KERNEL_PORT:
		port = thread->thread_ports[THREAD_FLAVOR_CONTROL];
#if CONFIG_CSR
		if (thread->thread_settable_self_port != port) {
			port = ipc_port_copy_send_mqueue(thread->thread_settable_self_port);
		} else
#endif /* CONFIG_CSR */
		{
			port = ipc_kobject_copy_send(port, thread, IKOT_THREAD_CONTROL);
		}
		thread_mtx_unlock(thread);
		break;

	case THREAD_READ_PORT:
	case THREAD_INSPECT_PORT:
		thread_mtx_unlock(thread);
		mach_thread_flavor_t current_flavor = (which == THREAD_READ_PORT) ?
		    THREAD_FLAVOR_READ : THREAD_FLAVOR_INSPECT;
		/* convert_thread_to_port_with_flavor consumes a thread reference */
		thread_reference(thread);
		port = convert_thread_to_port_with_flavor(thread, tro, current_flavor);
		break;

	default:
		thread_mtx_unlock(thread);
		return KERN_INVALID_ARGUMENT;
	}

	*portp = port;
	return KERN_SUCCESS;
}

kern_return_t
thread_get_special_port(
	thread_inspect_t         thread,
	int                      which,
	ipc_port_t              *portp)
{
	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return thread_get_special_port_internal(thread, get_thread_ro(thread),
	           which, portp, THREAD_FLAVOR_CONTROL);
}

kern_return_t
thread_get_special_port_from_user(
	mach_port_t     port,
	int             which,
	ipc_port_t      *portp)
{
	thread_ro_t tro;
	ipc_kobject_type_t kotype;
	mach_thread_flavor_t flavor;
	kern_return_t kr = KERN_SUCCESS;

	task_t curr_task = current_task();
	thread_t thread = convert_port_to_thread_inspect_no_eval(port);

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	tro = get_thread_ro(thread);
	kotype = ip_type(port);

	if (which == THREAD_KERNEL_PORT && tro->tro_task == curr_task) {
#if CONFIG_MACF
		/*
		 * only check for threads belong to current_task,
		 * because foreign thread ports are always movable
		 */
		if (mac_task_check_get_movable_control_port()) {
			kr = KERN_DENIED;
			goto out;
		}
#endif
		/*
		 * if `mac_task_check_get_movable_control_port` returned 0,
		 * then we must also have a movable task.
		 * see `task_set_exc_guard_default`
		 */
		assert(!task_is_immovable(curr_task));
	}

	switch (kotype) {
	case IKOT_THREAD_CONTROL:
		flavor = THREAD_FLAVOR_CONTROL;
		break;
	case IKOT_THREAD_READ:
		flavor = THREAD_FLAVOR_READ;
		break;
	case IKOT_THREAD_INSPECT:
		flavor = THREAD_FLAVOR_INSPECT;
		break;
	default:
		panic("strange kobject type");
	}

	kr = thread_get_special_port_internal(thread, tro, which, portp, flavor);
out:
	thread_deallocate(thread);
	return kr;
}

static kern_return_t
special_port_allowed_with_thread_flavor(
	int                  which,
	mach_thread_flavor_t flavor)
{
	switch (flavor) {
	case THREAD_FLAVOR_CONTROL:
		return KERN_SUCCESS;

	case THREAD_FLAVOR_READ:

		switch (which) {
		case THREAD_READ_PORT:
		case THREAD_INSPECT_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	case THREAD_FLAVOR_INSPECT:

		switch (which) {
		case THREAD_INSPECT_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	default:
		return KERN_INVALID_CAPABILITY;
	}
}

/*
 *	Routine:	thread_set_special_port [kernel call]
 *	Purpose:
 *		Changes one of the thread's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS            Changed the special port.
 *		KERN_INVALID_ARGUMENT   The thread is null.
 *      KERN_INVALID_RIGHT      Port is marked as immovable.
 *		KERN_FAILURE            The thread is dead.
 *		KERN_INVALID_ARGUMENT   Invalid special port.
 *		KERN_NO_ACCESS          Restricted access to set port.
 */

kern_return_t
thread_set_special_port(
	thread_t                thread,
	int                     which,
	ipc_port_t              port)
{
	kern_return_t   result = KERN_SUCCESS;
	ipc_port_t      old = IP_NULL;

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * rdar://70585367
	 * disallow immovable send so other process can't retrieve it through thread_get_special_port()
	 */
	if (!ipc_can_stash_naked_send(port)) {
		return KERN_INVALID_RIGHT;
	}

	switch (which) {
	case THREAD_KERNEL_PORT:
#if CONFIG_CSR
		if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) == 0) {
			/*
			 * Only allow setting of thread-self
			 * special port from user-space when SIP is
			 * disabled (for Mach-on-Mach emulation).
			 */
			thread_mtx_lock(thread);
			if (thread->active) {
				thread->thread_settable_self_port = port;
			} else {
				result = KERN_FAILURE;
			}
			thread_mtx_unlock(thread);

			if (IP_VALID(old)) {
				ipc_port_release_send(old);
			}

			return result;
		}
#else
		(void)old;
		(void)result;
#endif /* CONFIG_CSR */
		return KERN_NO_ACCESS;

	default:
		return KERN_INVALID_ARGUMENT;
	}
}

static inline mach_task_flavor_t
task_special_type_to_flavor(task_special_port_t which)
{
	switch (which) {
	case TASK_KERNEL_PORT:
		return TASK_FLAVOR_CONTROL;
	case TASK_NAME_PORT:
		return TASK_FLAVOR_NAME;
	case TASK_INSPECT_PORT:
		return TASK_FLAVOR_INSPECT;
	case TASK_READ_PORT:
		return TASK_FLAVOR_READ;
	default:
		break;
	}
	panic("invalid special port: %d", which);
}

/*
 *	Routine:	task_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the task's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		    Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		    The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

static kern_return_t
task_get_special_port_internal(
	task_t          task,
	int             which,
	ipc_port_t      *portp,
	mach_task_flavor_t        flavor)
{
	kern_return_t kr;
	ipc_port_t port;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((kr = special_port_allowed_with_task_flavor(which, flavor)) != KERN_SUCCESS) {
		return kr;
	}

	itk_lock(task);
	if (!task->ipc_active) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	switch (which) {
	case TASK_KERNEL_PORT:
		port = task->itk_task_ports[TASK_FLAVOR_CONTROL];
#if CONFIG_CSR
		if (task->itk_settable_self != port) {
			port = ipc_port_copy_send_mqueue(task->itk_settable_self);
		} else
#endif /* CONFIG_CSR */
		{
			port = ipc_kobject_copy_send(port, task, IKOT_TASK_CONTROL);
		}
		itk_unlock(task);
		break;

	case TASK_READ_PORT:
	case TASK_INSPECT_PORT:
		itk_unlock(task);
		mach_task_flavor_t current_flavor = task_special_type_to_flavor(which);
		/* convert_task_to_port_with_flavor consumes a task reference */
		task_reference(task);
		port = convert_task_to_port_with_flavor(task, current_flavor, TASK_GRP_KERNEL);
		break;

	case TASK_NAME_PORT:
		port = ipc_kobject_make_send(task->itk_task_ports[TASK_FLAVOR_NAME],
		    task, IKOT_TASK_NAME);
		itk_unlock(task);
		break;

	case TASK_HOST_PORT:
		port = host_port_copy_send(task->itk_host);
		itk_unlock(task);
		break;

	case TASK_BOOTSTRAP_PORT:
		port = ipc_port_copy_send_mqueue(task->itk_bootstrap);
		itk_unlock(task);
		break;

	case TASK_ACCESS_PORT:
		port = ipc_port_copy_send_mqueue(task->itk_task_access);
		itk_unlock(task);
		break;

	case TASK_DEBUG_CONTROL_PORT:
		port = ipc_port_copy_send_mqueue(task->itk_debug_control);
		itk_unlock(task);
		break;

#if CONFIG_PROC_RESOURCE_LIMITS
	case TASK_RESOURCE_NOTIFY_PORT:
		port = ipc_port_copy_send_mqueue(task->itk_resource_notify);
		itk_unlock(task);
		break;
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

	default:
		itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	*portp = port;
	return KERN_SUCCESS;
}

/* Kernel/Kext call only and skips MACF checks. MIG uses task_get_special_port_from_user(). */
kern_return_t
task_get_special_port(
	task_t          task,
	int             which,
	ipc_port_t      *portp)
{
	return task_get_special_port_internal(task, which, portp, TASK_FLAVOR_CONTROL);
}

/* MIG call only. Kernel/Kext uses task_get_special_port() */
kern_return_t
task_get_special_port_from_user(
	mach_port_t     port,
	int             which,
	ipc_port_t      *portp)
{
	ipc_kobject_type_t kotype;
	mach_task_flavor_t flavor;
	kern_return_t kr = KERN_SUCCESS;

	task_t curr_task = current_task();
	task_t task = convert_port_to_task_inspect_no_eval(port);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kotype = ip_type(port);

#if CONFIG_MACF
	if (mac_task_check_get_task_special_port(current_task(), task, which)) {
		kr = KERN_DENIED;
		goto out;
	}
#endif

	if (which == TASK_KERNEL_PORT && task == curr_task) {
#if CONFIG_MACF
		/*
		 * only check for current_task,
		 * because foreign task ports are always movable
		 */
		if (mac_task_check_get_movable_control_port()) {
			kr = KERN_DENIED;
			goto out;
		}
#endif
		/*
		 * if `mac_task_check_get_movable_control_port` returned 0,
		 * then we must also have a movable task.
		 * see `task_set_exc_guard_default`
		 */
		assert(!task_is_immovable(curr_task));
	}

	switch (kotype) {
	case IKOT_TASK_CONTROL:
		flavor = TASK_FLAVOR_CONTROL;
		break;
	case IKOT_TASK_READ:
		flavor = TASK_FLAVOR_READ;
		break;
	case IKOT_TASK_INSPECT:
		flavor = TASK_FLAVOR_INSPECT;
		break;
	default:
		panic("strange kobject type");
	}

	kr = task_get_special_port_internal(task, which, portp, flavor);
out:
	task_deallocate(task);
	return kr;
}

static kern_return_t
special_port_allowed_with_task_flavor(
	int                which,
	mach_task_flavor_t flavor)
{
	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
		return KERN_SUCCESS;

	case TASK_FLAVOR_READ:

		switch (which) {
		case TASK_READ_PORT:
		case TASK_INSPECT_PORT:
		case TASK_NAME_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	case TASK_FLAVOR_INSPECT:

		switch (which) {
		case TASK_INSPECT_PORT:
		case TASK_NAME_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	default:
		return KERN_INVALID_CAPABILITY;
	}
}

/*
 *	Routine:	task_set_special_port [MIG call]
 *	Purpose:
 *		Changes one of the task's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		    Changed the special port.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *      KERN_INVALID_RIGHT      Port is marked as immovable.
 *		KERN_FAILURE		    The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 *      KERN_NO_ACCESS		    Restricted access to set port.
 */

kern_return_t
task_set_special_port_from_user(
	task_t          task,
	int             which,
	ipc_port_t      port)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	if (mac_task_check_set_task_special_port(current_task(), task, which, port)) {
		return KERN_DENIED;
	}
#endif

	return task_set_special_port(task, which, port);
}

/* Kernel call only. MIG uses task_set_special_port_from_user() */
kern_return_t
task_set_special_port(
	task_t          task,
	int             which,
	ipc_port_t      port)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (task_is_driver(current_task())) {
		return KERN_NO_ACCESS;
	}

	/*
	 * rdar://70585367
	 * disallow immovable send so other process can't retrieve it through task_get_special_port()
	 */
	if (!ipc_can_stash_naked_send(port)) {
		return KERN_INVALID_RIGHT;
	}


	switch (which) {
	case TASK_KERNEL_PORT:
	case TASK_HOST_PORT:
#if CONFIG_CSR
		if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) == 0) {
			/*
			 * Only allow setting of task-self / task-host
			 * special ports from user-space when SIP is
			 * disabled (for Mach-on-Mach emulation).
			 */
			break;
		}
#endif
		return KERN_NO_ACCESS;
	default:
		break;
	}

	return task_set_special_port_internal(task, which, port);
}

/*
 *	Routine:	task_set_special_port_internal
 *	Purpose:
 *		Changes one of the task's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 *      KERN_NO_ACCESS		Restricted access to overwrite port.
 */

kern_return_t
task_set_special_port_internal(
	task_t          task,
	int             which,
	ipc_port_t      port)
{
	ipc_port_t old = IP_NULL;
	kern_return_t rc = KERN_INVALID_ARGUMENT;

	if (task == TASK_NULL) {
		goto out;
	}

	itk_lock(task);
	/*
	 * Allow setting special port during the span of ipc_task_init() to
	 * ipc_task_terminate(). posix_spawn() port actions can set special
	 * ports on target task _before_ task IPC access is enabled.
	 */
	if (task->itk_task_ports[TASK_FLAVOR_CONTROL] == IP_NULL) {
		rc = KERN_FAILURE;
		goto out_unlock;
	}

	switch (which) {
#if CONFIG_CSR
	case TASK_KERNEL_PORT:
		old = task->itk_settable_self;
		task->itk_settable_self = port;
		break;
#endif /* CONFIG_CSR */

	case TASK_HOST_PORT:
		old = task->itk_host;
		task->itk_host = port;
		break;

	case TASK_BOOTSTRAP_PORT:
		old = task->itk_bootstrap;
		task->itk_bootstrap = port;
		break;

	/* Never allow overwrite of the task access port */
	case TASK_ACCESS_PORT:
		if (IP_VALID(task->itk_task_access)) {
			rc = KERN_NO_ACCESS;
			goto out_unlock;
		}
		task->itk_task_access = port;
		break;

	case TASK_DEBUG_CONTROL_PORT:
		old = task->itk_debug_control;
		task->itk_debug_control = port;
		break;

#if CONFIG_PROC_RESOURCE_LIMITS
	case TASK_RESOURCE_NOTIFY_PORT:
		old = task->itk_resource_notify;
		task->itk_resource_notify = port;
		break;
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

	default:
		rc = KERN_INVALID_ARGUMENT;
		goto out_unlock;
	}/* switch */

	rc = KERN_SUCCESS;

out_unlock:
	itk_unlock(task);

	if (IP_VALID(old)) {
		ipc_port_release_send(old);
	}
out:
	return rc;
}
/*
 *	Routine:	mach_ports_register [kernel call]
 *	Purpose:
 *		Stash a handful of port send rights in the task.
 *		Child tasks will inherit these rights, but they
 *		must use mach_ports_lookup to acquire them.
 *
 *		The rights are supplied in a (wired) kalloc'd segment.
 *		Rights which aren't supplied are assumed to be null.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied rights and memory.
 *	Returns:
 *		KERN_SUCCESS		    Stashed the port rights.
 *      KERN_INVALID_RIGHT      Port in array is marked immovable.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_INVALID_ARGUMENT	The task is dead.
 *		KERN_INVALID_ARGUMENT	The memory param is null.
 *		KERN_INVALID_ARGUMENT	Too many port rights supplied.
 */

kern_return_t
_kernelrpc_mach_ports_register3(
	task_t                  task,
	mach_port_t             port1,
	mach_port_t             port2,
	mach_port_t             port3)
{
	ipc_port_t ports[TASK_PORT_REGISTER_MAX] = {
		port1, port2, port3,
	};

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	for (int i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		/*
		 * rdar://70585367
		 * disallow immovable send so other process can't retrieve it through mach_ports_lookup()
		 */
		if (!ipc_can_stash_naked_send(ports[i])) {
			return KERN_INVALID_RIGHT;
		}
	}

	itk_lock(task);
	if (!task->ipc_active) {
		itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Replace the old send rights with the new.
	 *	Release the old rights after unlocking.
	 */

	for (int i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		ipc_port_t old;

		old = task->itk_registered[i];
		task->itk_registered[i] = ports[i];
		ports[i] = old;
	}

	itk_unlock(task);

	for (int i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		ipc_port_release_send(ports[i]);
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_ports_lookup [kernel call]
 *	Purpose:
 *		Retrieves (clones) the stashed port send rights.
 *	Conditions:
 *		Nothing locked.  If successful, the caller gets
 *		rights and memory.
 *	Returns:
 *		KERN_SUCCESS		Retrieved the send rights.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_INVALID_ARGUMENT	The task is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
_kernelrpc_mach_ports_lookup3(
	task_t                  task,
	ipc_port_t             *port1,
	ipc_port_t             *port2,
	ipc_port_t             *port3)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	itk_lock(task);
	if (!task->ipc_active) {
		itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	*port1 = ipc_port_copy_send_any(task->itk_registered[0]);
	*port2 = ipc_port_copy_send_any(task->itk_registered[1]);
	*port3 = ipc_port_copy_send_any(task->itk_registered[2]);

	itk_unlock(task);

	return KERN_SUCCESS;
}

static kern_return_t
task_conversion_eval_internal(
	task_t             caller,
	task_t             victim,
	boolean_t          out_trans,
	int                flavor) /* control or read */
{
	boolean_t allow_kern_task_out_trans;
	boolean_t allow_kern_task;

	assert(flavor == TASK_FLAVOR_CONTROL || flavor == TASK_FLAVOR_READ);
	assert(flavor == THREAD_FLAVOR_CONTROL || flavor == THREAD_FLAVOR_READ);

#if defined(SECURE_KERNEL)
	/*
	 * On secure kernel platforms, reject converting kernel task/threads to port
	 * and sending it to user space.
	 */
	allow_kern_task_out_trans = FALSE;
#else
	allow_kern_task_out_trans = TRUE;
#endif

	allow_kern_task = out_trans && allow_kern_task_out_trans;

	if (victim == TASK_NULL) {
		return KERN_INVALID_SECURITY;
	}

	task_require(victim);

	/*
	 * If Developer Mode is not enabled, deny attempts to translate foreign task's
	 * control port completely. Read port or corpse is okay.
	 */
	if (!developer_mode_state()) {
		if ((caller != victim) &&
		    (flavor == TASK_FLAVOR_CONTROL) && !task_is_a_corpse(victim)) {
#if XNU_TARGET_OS_OSX
			return KERN_INVALID_SECURITY;
#else
			/*
			 * All control ports are immovable.
			 * Return an error for outtrans, but panic on intrans.
			 */
			if (out_trans) {
				return KERN_INVALID_SECURITY;
			} else {
				panic("Just like pineapple on pizza, this task/thread port doesn't belong here.");
			}
#endif /* XNU_TARGET_OS_OSX */
		}
	}

	/*
	 * Tasks are allowed to resolve their own task ports, and the kernel is
	 * allowed to resolve anyone's task port (subject to Developer Mode check).
	 */
	if (caller == kernel_task) {
		return KERN_SUCCESS;
	}

	if (caller == victim) {
		return KERN_SUCCESS;
	}

	/*
	 * Only the kernel can resolve the kernel's task port. We've established
	 * by this point that the caller is not kernel_task.
	 */
	if (victim == kernel_task && !allow_kern_task) {
		return KERN_INVALID_SECURITY;
	}

#if !defined(XNU_TARGET_OS_OSX)
	/*
	 * On platforms other than macOS, only a platform binary can resolve the task port
	 * of another platform binary.
	 */
	if (task_get_platform_binary(victim) && !task_get_platform_binary(caller)) {
#if SECURE_KERNEL
		return KERN_INVALID_SECURITY;
#else
		if (cs_relax_platform_task_ports) {
			return KERN_SUCCESS;
		} else {
			return KERN_INVALID_SECURITY;
		}
#endif /* SECURE_KERNEL */
	}
#endif /* !defined(XNU_TARGET_OS_OSX) */

	return KERN_SUCCESS;
}

kern_return_t
task_conversion_eval(task_t caller, task_t victim, int flavor)
{
	/* flavor is mach_task_flavor_t or mach_thread_flavor_t */
	static_assert(TASK_FLAVOR_CONTROL == THREAD_FLAVOR_CONTROL);
	static_assert(TASK_FLAVOR_READ == THREAD_FLAVOR_READ);
	return task_conversion_eval_internal(caller, victim, FALSE, flavor);
}

static kern_return_t
task_conversion_eval_out_trans(task_t caller, task_t victim, int flavor)
{
	assert(flavor == TASK_FLAVOR_CONTROL || flavor == THREAD_FLAVOR_CONTROL);
	return task_conversion_eval_internal(caller, victim, TRUE, flavor);
}

/*
 *	Routine:	task_port_kotype_valid_for_flavor
 *	Purpose:
 *		Check whether the kobject type of a mach port
 *      is valid for conversion to a task of given flavor.
 */
static boolean_t
task_port_kotype_valid_for_flavor(
	natural_t          kotype,
	mach_task_flavor_t flavor)
{
	switch (flavor) {
	/* Ascending capability */
	case TASK_FLAVOR_NAME:
		if (kotype == IKOT_TASK_NAME) {
			return TRUE;
		}
		OS_FALLTHROUGH;
	case TASK_FLAVOR_INSPECT:
		if (kotype == IKOT_TASK_INSPECT) {
			return TRUE;
		}
		OS_FALLTHROUGH;
	case TASK_FLAVOR_READ:
		if (kotype == IKOT_TASK_READ) {
			return TRUE;
		}
		OS_FALLTHROUGH;
	case TASK_FLAVOR_CONTROL:
		if (kotype == IKOT_TASK_CONTROL) {
			return TRUE;
		}
		break;
	default:
		panic("strange task flavor");
	}

	return FALSE;
}

/*
 *	Routine: convert_port_to_task_with_flavor_locked_noref
 *	Purpose:
 *		Internal helper routine to convert from a locked port to a task.
 *	Args:
 *		port   - target port
 *		flavor - requested task port flavor
 *		options - port translation options
 *	Conditions:
 *		Port is locked and active.
 */
static task_t
convert_port_to_task_with_flavor_locked_noref(
	ipc_port_t              port,
	mach_task_flavor_t      flavor,
	port_intrans_options_t  options)
{
	ipc_kobject_type_t type = ip_type(port);
	task_t task;

	ip_mq_lock_held(port);
	require_ip_active(port);

	if (!task_port_kotype_valid_for_flavor(type, flavor)) {
		return TASK_NULL;
	}

	task = ipc_kobject_get_locked(port, type);
	if (task == TASK_NULL) {
		return TASK_NULL;
	}

	if (!(options & PORT_INTRANS_ALLOW_CORPSE_TASK) && task_is_a_corpse(task)) {
		assert(flavor == TASK_FLAVOR_CONTROL);
		return TASK_NULL;
	}

	/* TODO: rdar://42389187 */
	if (flavor == TASK_FLAVOR_NAME || flavor == TASK_FLAVOR_INSPECT) {
		assert(options & PORT_INTRANS_SKIP_TASK_EVAL);
	}

	if (!(options & PORT_INTRANS_SKIP_TASK_EVAL) &&
	    task_conversion_eval(current_task(), task, flavor)) {
		return TASK_NULL;
	}

	return task;
}

/*
 *	Routine: convert_port_to_task_with_flavor_locked
 *	Purpose:
 *		Internal helper routine to convert from a locked port to a task.
 *	Args:
 *		port   - target port
 *		flavor - requested task port flavor
 *		options - port translation options
 *		grp    - task reference group
 *	Conditions:
 *		Port is locked and active.
 *		Produces task ref or TASK_NULL.
 */
static task_t
convert_port_to_task_with_flavor_locked(
	ipc_port_t              port,
	mach_task_flavor_t      flavor,
	port_intrans_options_t  options,
	task_grp_t              grp)
{
	task_t task;

	task = convert_port_to_task_with_flavor_locked_noref(port, flavor,
	    options);

	if (task != TASK_NULL) {
		task_reference_grp(task, grp);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task_with_flavor
 *	Purpose:
 *		Internal helper for converting from a port to a task.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Args:
 *		port   - target port
 *		flavor - requested task port flavor
 *		options - port translation options
 *		grp    - task reference group
 *	Conditions:
 *		Nothing locked.
 */
static task_t
convert_port_to_task_with_flavor(
	ipc_port_t         port,
	mach_task_flavor_t flavor,
	port_intrans_options_t options,
	task_grp_t         grp)
{
	task_t task = TASK_NULL;
	task_t self = current_task();

	if (IP_VALID(port)) {
		if (port == self->itk_task_ports[TASK_FLAVOR_CONTROL]) {
			task_reference_grp(self, grp);
			return self;
		}

		ip_mq_lock(port);
		if (ip_active(port)) {
			task = convert_port_to_task_with_flavor_locked(port,
			    flavor, options, grp);
		}
		ip_mq_unlock(port);
	}

	return task;
}

task_t
convert_port_to_task(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_CONTROL,
	           PORT_INTRANS_OPTIONS_NONE, TASK_GRP_KERNEL);
}

task_t
convert_port_to_task_mig(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_CONTROL,
	           PORT_INTRANS_OPTIONS_NONE, TASK_GRP_MIG);
}

task_read_t
convert_port_to_task_read(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_READ,
	           PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL);
}

task_read_t
convert_port_to_task_read_no_eval(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_READ,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL);
}

task_read_t
convert_port_to_task_read_mig(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_READ,
	           PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_MIG);
}

task_inspect_t
convert_port_to_task_inspect(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_INSPECT,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL);
}

task_inspect_t
convert_port_to_task_inspect_no_eval(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_INSPECT,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL);
}

task_inspect_t
convert_port_to_task_inspect_mig(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_INSPECT,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_MIG);
}

task_name_t
convert_port_to_task_name(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_NAME,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL);
}

task_name_t
convert_port_to_task_name_mig(
	ipc_port_t              port)
{
	return convert_port_to_task_with_flavor(port, TASK_FLAVOR_NAME,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_MIG);
}

/*
 *	Routine:	convert_port_to_task_policy
 *	Purpose:
 *		Convert from a port to a task.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *		If the port is being used with task_port_set(), any task port
 *		type other than TASK_CONTROL requires an entitlement. If the
 *		port is being used with task_port_get(), TASK_NAME requires an
 *		entitlement.
 *	Conditions:
 *		Nothing locked.
 */
static task_t
convert_port_to_task_policy_mig(ipc_port_t port, boolean_t set)
{
	task_t task = TASK_NULL;

	if (!IP_VALID(port)) {
		return TASK_NULL;
	}

	task = set ?
	    convert_port_to_task_mig(port) :
	    convert_port_to_task_inspect_mig(port);

	if (task == TASK_NULL &&
	    IOCurrentTaskHasEntitlement("com.apple.private.task_policy")) {
		task = convert_port_to_task_name_mig(port);
	}

	return task;
}

task_policy_set_t
convert_port_to_task_policy_set_mig(ipc_port_t port)
{
	return convert_port_to_task_policy_mig(port, true);
}

task_policy_get_t
convert_port_to_task_policy_get_mig(ipc_port_t port)
{
	return convert_port_to_task_policy_mig(port, false);
}

/*
 *	Routine:	convert_port_to_task_suspension_token
 *	Purpose:
 *		Convert from a port to a task suspension token.
 *		Doesn't consume the port ref; produces a suspension token ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
static task_suspension_token_t
convert_port_to_task_suspension_token_grp(
	ipc_port_t              port,
	task_grp_t              grp)
{
	task_suspension_token_t task = TASK_NULL;

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		task = ipc_kobject_get_locked(port, IKOT_TASK_RESUME);
		if (task != TASK_NULL) {
			task_reference_grp(task, grp);
		}
		ip_mq_unlock(port);
	}

	return task;
}

task_suspension_token_t
convert_port_to_task_suspension_token_external(
	ipc_port_t              port)
{
	return convert_port_to_task_suspension_token_grp(port, TASK_GRP_EXTERNAL);
}

task_suspension_token_t
convert_port_to_task_suspension_token_mig(
	ipc_port_t              port)
{
	return convert_port_to_task_suspension_token_grp(port, TASK_GRP_MIG);
}

task_suspension_token_t
convert_port_to_task_suspension_token_kernel(
	ipc_port_t              port)
{
	return convert_port_to_task_suspension_token_grp(port, TASK_GRP_KERNEL);
}

/*
 *	Routine:	convert_port_to_space_with_flavor
 *	Purpose:
 *		Internal helper for converting from a port to a space.
 *		Doesn't consume the port ref; produces a space ref,
 *		which may be null.
 *	Args:
 *		port   - target port
 *		flavor - requested ipc space flavor
 *		options - port translation options
 *	Conditions:
 *		Nothing locked.
 */
static ipc_space_t
convert_port_to_space_with_flavor(
	ipc_port_t         port,
	mach_task_flavor_t flavor,
	port_intrans_options_t options)
{
	ipc_space_t space = IPC_SPACE_NULL;
	task_t task = TASK_NULL;

	assert(flavor != TASK_FLAVOR_NAME);

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		if (ip_active(port)) {
			task = convert_port_to_task_with_flavor_locked_noref(port,
			    flavor, options);
		}

		/*
		 * Because we hold the port lock and we could resolve a task,
		 * even if we're racing with task termination, we know that
		 * ipc_task_disable() hasn't been called yet.
		 *
		 * We try to sniff if `task->active` flipped to accelerate
		 * resolving the race, but this isn't load bearing.
		 *
		 * The space will be torn down _after_ ipc_task_disable() returns,
		 * so it is valid to take a reference on it now.
		 */
		if (task && task->active) {
			space = task->itk_space;
			is_reference(space);
		}
		ip_mq_unlock(port);
	}

	return space;
}

ipc_space_t
convert_port_to_space(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_CONTROL,
	           PORT_INTRANS_OPTIONS_NONE);
}

ipc_space_read_t
convert_port_to_space_read(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_READ,
	           PORT_INTRANS_ALLOW_CORPSE_TASK);
}

ipc_space_read_t
convert_port_to_space_read_no_eval(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_READ,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK);
}

ipc_space_inspect_t
convert_port_to_space_inspect(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_INSPECT,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK);
}

/*
 *	Routine:	convert_port_to_map_with_flavor
 *	Purpose:
 *		Internal helper for converting from a port to a map.
 *		Doesn't consume the port ref; produces a map ref,
 *		which may be null.
 *	Args:
 *		port   - target port
 *		flavor - requested vm map flavor
 *		options - port translation options
 *	Conditions:
 *		Nothing locked.
 */
static vm_map_t
convert_port_to_map_with_flavor(
	ipc_port_t         port,
	mach_task_flavor_t flavor,
	port_intrans_options_t options)
{
	task_t task = TASK_NULL;
	vm_map_t map = VM_MAP_NULL;

	/* there is no vm_map_inspect_t routines at the moment. */
	assert(flavor != TASK_FLAVOR_NAME && flavor != TASK_FLAVOR_INSPECT);
	assert((options & PORT_INTRANS_SKIP_TASK_EVAL) == 0);

	if (IP_VALID(port)) {
		ip_mq_lock(port);

		if (ip_active(port)) {
			task = convert_port_to_task_with_flavor_locked_noref(port,
			    flavor, options);
		}

		/*
		 * Because we hold the port lock and we could resolve a task,
		 * even if we're racing with task termination, we know that
		 * ipc_task_disable() hasn't been called yet.
		 *
		 * We try to sniff if `task->active` flipped to accelerate
		 * resolving the race, but this isn't load bearing.
		 *
		 * The vm map will be torn down _after_ ipc_task_disable() returns,
		 * so it is valid to take a reference on it now.
		 */
		if (task && task->active) {
			map = task->map;

			if (map->pmap == kernel_pmap) {
				panic("userspace has control access to a "
				    "kernel map %p through task %p", map, task);
			}

			pmap_require(map->pmap);
			vm_map_reference(map);
		}

		ip_mq_unlock(port);
	}

	return map;
}

vm_map_t
convert_port_to_map(
	ipc_port_t              port)
{
	return convert_port_to_map_with_flavor(port, TASK_FLAVOR_CONTROL,
	           PORT_INTRANS_OPTIONS_NONE);
}

vm_map_read_t
convert_port_to_map_read(
	ipc_port_t              port)
{
	return convert_port_to_map_with_flavor(port, TASK_FLAVOR_READ,
	           PORT_INTRANS_ALLOW_CORPSE_TASK);
}

vm_map_inspect_t
convert_port_to_map_inspect(
	__unused ipc_port_t     port)
{
	/* there is no vm_map_inspect_t routines at the moment. */
	return VM_MAP_INSPECT_NULL;
}

/*
 *	Routine:	thread_port_kotype_valid_for_flavor
 *	Purpose:
 *		Check whether the kobject type of a mach port
 *      is valid for conversion to a thread of given flavor.
 */
static boolean_t
thread_port_kotype_valid_for_flavor(
	natural_t            kotype,
	mach_thread_flavor_t flavor)
{
	switch (flavor) {
	/* Ascending capability */
	case THREAD_FLAVOR_INSPECT:
		if (kotype == IKOT_THREAD_INSPECT) {
			return TRUE;
		}
		OS_FALLTHROUGH;
	case THREAD_FLAVOR_READ:
		if (kotype == IKOT_THREAD_READ) {
			return TRUE;
		}
		OS_FALLTHROUGH;
	case THREAD_FLAVOR_CONTROL:
		if (kotype == IKOT_THREAD_CONTROL) {
			return TRUE;
		}
		break;
	default:
		panic("strange thread flavor");
	}

	return FALSE;
}

/*
 *	Routine: convert_port_to_thread_with_flavor_locked
 *	Purpose:
 *		Internal helper routine to convert from a locked port to a thread.
 *	Args:
 *		port   - target port
 *		flavor - requested thread port flavor
 *		options - port translation options
 *	Conditions:
 *		Port is locked and active.
 *		Produces a thread ref or THREAD_NULL.
 */
static thread_t
convert_port_to_thread_with_flavor_locked(
	ipc_port_t               port,
	mach_thread_flavor_t     flavor,
	port_intrans_options_t   options)
{
	thread_t thread = THREAD_NULL;
	task_t task;
	ipc_kobject_type_t type = ip_type(port);

	ip_mq_lock_held(port);
	require_ip_active(port);

	if (!thread_port_kotype_valid_for_flavor(type, flavor)) {
		return THREAD_NULL;
	}

	thread = ipc_kobject_get_locked(port, type);

	if (thread == THREAD_NULL) {
		return THREAD_NULL;
	}

	if (options & PORT_INTRANS_THREAD_NOT_CURRENT_THREAD) {
		if (thread == current_thread()) {
			return THREAD_NULL;
		}
	}

	task = get_threadtask(thread);

	if (options & PORT_INTRANS_THREAD_IN_CURRENT_TASK) {
		if (task != current_task()) {
			return THREAD_NULL;
		}
	} else {
		if (!(options & PORT_INTRANS_ALLOW_CORPSE_TASK) && task_is_a_corpse(task)) {
			assert(flavor == THREAD_FLAVOR_CONTROL);
			return THREAD_NULL;
		}
		/* TODO: rdar://42389187 */
		if (flavor == THREAD_FLAVOR_INSPECT) {
			assert(options & PORT_INTRANS_SKIP_TASK_EVAL);
		}

		if (!(options & PORT_INTRANS_SKIP_TASK_EVAL) &&
		    task_conversion_eval(current_task(), task, flavor) != KERN_SUCCESS) {
			return THREAD_NULL;
		}
	}

	thread_reference(thread);
	return thread;
}

/*
 *	Routine:	convert_port_to_thread_with_flavor
 *	Purpose:
 *		Internal helper for converting from a port to a thread.
 *		Doesn't consume the port ref; produces a thread ref,
 *		which may be null.
 *	Args:
 *		port   - target port
 *		flavor - requested thread port flavor
 *		options - port translation options
 *	Conditions:
 *		Nothing locked.
 */
static thread_t
convert_port_to_thread_with_flavor(
	ipc_port_t           port,
	mach_thread_flavor_t flavor,
	port_intrans_options_t options)
{
	thread_t thread = THREAD_NULL;

	if (IP_VALID(port)) {
		ip_mq_lock(port);
		if (ip_active(port)) {
			thread = convert_port_to_thread_with_flavor_locked(port,
			    flavor, options);
		}
		ip_mq_unlock(port);
	}

	return thread;
}

thread_t
convert_port_to_thread(
	ipc_port_t              port)
{
	return convert_port_to_thread_with_flavor(port, THREAD_FLAVOR_CONTROL,
	           PORT_INTRANS_OPTIONS_NONE);
}

thread_read_t
convert_port_to_thread_read(
	ipc_port_t              port)
{
	return convert_port_to_thread_with_flavor(port, THREAD_FLAVOR_READ,
	           PORT_INTRANS_ALLOW_CORPSE_TASK);
}

static thread_read_t
convert_port_to_thread_read_no_eval(
	ipc_port_t              port)
{
	return convert_port_to_thread_with_flavor(port, THREAD_FLAVOR_READ,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK);
}

thread_inspect_t
convert_port_to_thread_inspect(
	ipc_port_t              port)
{
	return convert_port_to_thread_with_flavor(port, THREAD_FLAVOR_INSPECT,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK);
}

static thread_inspect_t
convert_port_to_thread_inspect_no_eval(
	ipc_port_t              port)
{
	return convert_port_to_thread_with_flavor(port, THREAD_FLAVOR_INSPECT,
	           PORT_INTRANS_SKIP_TASK_EVAL | PORT_INTRANS_ALLOW_CORPSE_TASK);
}

static inline ipc_kobject_type_t
thread_flavor_to_kotype(mach_thread_flavor_t flavor)
{
	switch (flavor) {
	case THREAD_FLAVOR_CONTROL:
		return IKOT_THREAD_CONTROL;
	case THREAD_FLAVOR_READ:
		return IKOT_THREAD_READ;
	default:
		return IKOT_THREAD_INSPECT;
	}
}


ipc_port_t
convert_thread_to_port_immovable(
	thread_t                thread)
{
	ipc_port_t  port = IP_NULL;

	thread_mtx_lock(thread);

	if (thread->ipc_active) {
		port = ipc_kobject_make_send(thread->thread_ports[THREAD_FLAVOR_CONTROL],
		    thread, IKOT_THREAD_CONTROL);
	}

	thread_mtx_unlock(thread);
	thread_deallocate(thread);
	return port;
}

/*
 *	Routine:	convert_thread_to_port_with_flavor
 *	Purpose:
 *		Convert from a thread to a port of given flavor.
 *		Consumes a thread ref; produces a naked send right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
static ipc_port_t
convert_thread_to_port_with_flavor(
	thread_t              thread,
	thread_ro_t           tro,
	mach_thread_flavor_t  flavor)
{
	ipc_kobject_type_t kotype = thread_flavor_to_kotype(flavor);
	ipc_port_t port = IP_NULL;

	thread_mtx_lock(thread);

	/*
	 * out-trans of weaker flavors are still permitted, but in-trans
	 * is separately enforced.
	 */
	if (flavor == THREAD_FLAVOR_CONTROL &&
	    task_conversion_eval_out_trans(current_task(), tro->tro_task, flavor)) {
		/* denied by security policy, make the port appear dead */
		port = IP_DEAD;
		goto exit;
	}

	if (!thread->ipc_active) {
		goto exit;
	}

	port = thread->thread_ports[flavor];
	if (flavor == THREAD_FLAVOR_CONTROL) {
		port = ipc_kobject_make_send(port, thread, IKOT_THREAD_CONTROL);
	} else if (IP_VALID(port)) {
		(void)ipc_kobject_make_send(port, thread, kotype);
	} else {
		ipc_object_label_t label = IPC_OBJECT_LABEL(kotype);

		/*
		 * If Developer Mode is off, substitute read port for control
		 * port if copying out to owning task's space, for the sake of
		 * in-process exception handler.
		 *
		 * Also see: exception_deliver().
		 */
		if (!developer_mode_state() && flavor == THREAD_FLAVOR_READ) {
			label = ipc_kobject_label_alloc(kotype,
			    IPC_LABEL_SUBST_THREAD_READ, thread->thread_ports[THREAD_FLAVOR_CONTROL]);
		}

		/*
		 * Claim a send right on the thread read/inspect port, and request a no-senders
		 * notification on that port (if none outstanding). A thread reference is not
		 * donated here even though the ports are created lazily because it doesn't own the
		 * kobject that it points to. Threads manage their lifetime explicitly and
		 * have to synchronize with each other, between the task/thread terminating and the
		 * send-once notification firing, and this is done under the thread mutex
		 * rather than with atomics.
		 */
		port = ipc_kobject_alloc_port(thread, label,
		    IPC_KOBJECT_ALLOC_MAKE_SEND);

		thread->thread_ports[flavor] = port;
	}

exit:
	thread_mtx_unlock(thread);
	thread_deallocate(thread);
	return port;
}

ipc_port_t
convert_thread_to_port(
	thread_t                thread)
{
	thread_ro_t tro = get_thread_ro(thread);
	return convert_thread_to_port_with_flavor(thread, tro, THREAD_FLAVOR_CONTROL);
}

ipc_port_t
convert_thread_read_to_port(thread_read_t thread)
{
	thread_ro_t tro = get_thread_ro(thread);
	return convert_thread_to_port_with_flavor(thread, tro, THREAD_FLAVOR_READ);
}

ipc_port_t
convert_thread_inspect_to_port(thread_inspect_t thread)
{
	thread_ro_t tro = get_thread_ro(thread);
	return convert_thread_to_port_with_flavor(thread, tro, THREAD_FLAVOR_INSPECT);
}

void
convert_thread_array_to_ports(
	thread_act_array_t      array,
	size_t                  count,
	mach_thread_flavor_t    flavor)
{
	thread_t *thread_list = (thread_t *)array;

	for (size_t i = 0; i < count; i++) {
		thread_t   thread = thread_list[i];
		ipc_port_t port;

		switch (flavor) {
		case THREAD_FLAVOR_CONTROL:
			port = convert_thread_to_port(thread);
			break;
		case THREAD_FLAVOR_READ:
			port = convert_thread_read_to_port(thread);
			break;
		case THREAD_FLAVOR_INSPECT:
			port = convert_thread_inspect_to_port(thread);
			break;
		}

		array[i].port = port;
	}
}


/*
 *	Routine:	port_name_to_thread
 *	Purpose:
 *		Convert from a port name to a thread reference
 *		A name of MACH_PORT_NULL is valid for the null thread.
 *	Conditions:
 *		Nothing locked.
 */
thread_t
port_name_to_thread(
	mach_port_name_t         name,
	port_intrans_options_t options)
{
	thread_t        thread = THREAD_NULL;
	ipc_port_t      kport;
	kern_return_t kr;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			/* port is locked and active */
			assert(!(options & PORT_INTRANS_ALLOW_CORPSE_TASK) &&
			    !(options & PORT_INTRANS_SKIP_TASK_EVAL));
			thread = convert_port_to_thread_with_flavor_locked(kport,
			    THREAD_FLAVOR_CONTROL, options);
			ip_mq_unlock(kport);
		}
	}

	return thread;
}

/*
 *	Routine:	port_name_is_pinned_self
 *	Purpose:
 *		Returns whether this port name is for the pinned
 *		mach_task_self (if it exists).
 *
 *		task_self_trap() will memorize the name the port has
 *		in the space in ip_receiver_name when it gets pinned,
 *		which we can use to fast-track this answer without
 *		taking any lock.
 *
 *		ipc_task_disable() will set `ip_receiver_name` back to
 *		MACH_PORT_SPECIAL_DEFAULT.
 *
 *	Conditions:
 *		self must be current_task()
 *		Nothing locked.
 */
static bool
port_name_is_pinned_self(
	task_t             self,
	mach_port_name_t   name)
{
	ipc_port_t kport = self->itk_task_ports[TASK_FLAVOR_CONTROL];
	return MACH_PORT_VALID(name) && name != MACH_PORT_SPECIAL_DEFAULT &&
	       ip_get_receiver_name(kport) == name;
}

/*
 *	Routine:	port_name_to_current_task*_noref
 *	Purpose:
 *		Convert from a port name to current_task()
 *		A name of MACH_PORT_NULL is valid for the null task.
 *
 *		If current_task() is in the process of being terminated,
 *		this might return a non NULL task even when port_name_to_task()
 *		would.
 *
 *		However, this is an acceptable race that can't be controlled by
 *		userspace, and that downstream code using the returned task
 *		has to handle anyway.
 *
 *		ipc_space_disable() does try to narrow this race,
 *		by causing port_name_is_pinned_self() to fail.
 *
 *	Returns:
 *		current_task() if the port name was for current_task()
 *		at the appropriate flavor.
 *
 *		TASK_NULL otherwise.
 *
 *	Conditions:
 *		Nothing locked.
 */
static task_t
port_name_to_current_task_internal_noref(
	mach_port_name_t   name,
	mach_task_flavor_t flavor)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_t task = TASK_NULL;
	task_t self = current_task();

	if (port_name_is_pinned_self(self, name)) {
		return self;
	}

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(self->itk_space, name, &kport);
		if (kr == KERN_SUCCESS) {
			ipc_kobject_type_t type = ip_type(kport);
			if (task_port_kotype_valid_for_flavor(type, flavor)) {
				task = ipc_kobject_get_locked(kport, type);
			}
			ip_mq_unlock(kport);
			if (task != self) {
				task = TASK_NULL;
			}
		}
	}

	return task;
}

task_t
port_name_to_current_task_noref(
	mach_port_name_t name)
{
	return port_name_to_current_task_internal_noref(name, TASK_FLAVOR_CONTROL);
}

task_read_t
port_name_to_current_task_read_noref(
	mach_port_name_t name)
{
	return port_name_to_current_task_internal_noref(name, TASK_FLAVOR_READ);
}

/*
 *	Routine:	port_name_to_task_grp
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *		Acquire a send right if [inout] @kportp is non-null.
 *	Conditions:
 *		Nothing locked.
 */
static task_t
port_name_to_task_grp(
	mach_port_name_t name,
	mach_task_flavor_t flavor,
	port_intrans_options_t options,
	task_grp_t       grp,
	ipc_port_t       *kportp)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_t task = TASK_NULL;
	task_t self = current_task();

	if (!kportp && port_name_is_pinned_self(self, name)) {
		task_reference_grp(self, grp);
		return self;
	}

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(self->itk_space, name, &kport);
		if (kr == KERN_SUCCESS) {
			/* port is locked and active */
			task = convert_port_to_task_with_flavor_locked(kport,
			    flavor, options, grp);
			if (kportp) {
				/* send right requested */
				ipc_port_copy_send_any_locked(kport);
				*kportp = kport;
			}
			ip_mq_unlock(kport);
		}
	}
	return task;
}

task_t
port_name_to_task_external(
	mach_port_name_t name)
{
	return port_name_to_task_grp(name, TASK_FLAVOR_CONTROL, PORT_INTRANS_OPTIONS_NONE, TASK_GRP_EXTERNAL, NULL);
}

task_t
port_name_to_task_kernel(
	mach_port_name_t name)
{
	return port_name_to_task_grp(name, TASK_FLAVOR_CONTROL, PORT_INTRANS_OPTIONS_NONE, TASK_GRP_KERNEL, NULL);
}

/*
 *	Routine:	port_name_to_task_read
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		Nothing locked.
 */
task_read_t
port_name_to_task_read(
	mach_port_name_t name)
{
	return port_name_to_task_grp(name, TASK_FLAVOR_READ, PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL, NULL);
}

/*
 *	Routine:	port_name_to_task_read_and_send_right
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		On success, ipc port returned with a +1 send right.
 */
task_read_t
port_name_to_task_read_and_send_right(
	mach_port_name_t name,
	ipc_port_t *kportp)
{
	return port_name_to_task_grp(name, TASK_FLAVOR_READ, PORT_INTRANS_ALLOW_CORPSE_TASK, TASK_GRP_KERNEL, kportp);
}

/*
 *	Routine:	port_name_to_task_read_no_eval
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *		Skips task_conversion_eval() during conversion.
 *	Conditions:
 *		Nothing locked.
 */
task_read_t
port_name_to_task_read_no_eval(
	mach_port_name_t name)
{
	port_intrans_options_t options = PORT_INTRANS_SKIP_TASK_EVAL |
	    PORT_INTRANS_ALLOW_CORPSE_TASK;
	return port_name_to_task_grp(name, TASK_FLAVOR_READ, options, TASK_GRP_KERNEL, NULL);
}

/*
 *	Routine:	port_name_to_task_name
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		Nothing locked.
 */
task_name_t
port_name_to_task_name(
	mach_port_name_t name)
{
	port_intrans_options_t options = PORT_INTRANS_SKIP_TASK_EVAL |
	    PORT_INTRANS_ALLOW_CORPSE_TASK;
	return port_name_to_task_grp(name, TASK_FLAVOR_NAME, options, TASK_GRP_KERNEL, NULL);
}

/*
 *	Routine:	port_name_to_task_id_token
 *	Purpose:
 *		Convert from a port name to a task identity token reference
 *	Conditions:
 *		Nothing locked.
 */
task_id_token_t
port_name_to_task_id_token(
	mach_port_name_t name)
{
	ipc_port_t port;
	kern_return_t kr;
	task_id_token_t token = TASK_ID_TOKEN_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &port);
		if (kr == KERN_SUCCESS) {
			token = convert_port_to_task_id_token(port);
			ip_mq_unlock(port);
		}
	}
	return token;
}

/*
 *	Routine:	port_name_to_host
 *	Purpose:
 *		Convert from a port name to a host pointer.
 *		NOTE: This does _not_ return a +1 reference to the host_t
 *	Conditions:
 *		Nothing locked.
 */
host_t
port_name_to_host(
	mach_port_name_t name)
{
	host_t host = HOST_NULL;
	kern_return_t kr;
	ipc_port_t port;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &port);
		if (kr == KERN_SUCCESS) {
			host = convert_port_to_host(port);
			ip_mq_unlock(port);
		}
	}
	return host;
}

static inline ipc_kobject_type_t
task_flavor_to_kotype(mach_task_flavor_t flavor)
{
	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
		return IKOT_TASK_CONTROL;
	case TASK_FLAVOR_READ:
		return IKOT_TASK_READ;
	case TASK_FLAVOR_INSPECT:
		return IKOT_TASK_INSPECT;
	default:
		return IKOT_TASK_NAME;
	}
}

/*
 *	Routine:	convert_task_to_port_with_flavor
 *	Purpose:
 *		Convert from a task to a port of given flavor.
 *		Consumes a task ref; produces a naked send right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
ipc_port_t
convert_task_to_port_with_flavor(
	task_t              task,
	mach_task_flavor_t  flavor,
	task_grp_t          grp)
{
	ipc_kobject_type_t kotype = task_flavor_to_kotype(flavor);
	ipc_port_t port = IP_NULL;

	itk_lock(task);

	if (!task->ipc_active) {
		goto exit;
	}

	/*
	 * out-trans of weaker flavors are still permitted, but in-trans
	 * is separately enforced.
	 */
	if (flavor == TASK_FLAVOR_CONTROL &&
	    task_conversion_eval_out_trans(current_task(), task, flavor)) {
		/* denied by security policy, make the port appear dead */
		port = IP_DEAD;
		goto exit;
	}

	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
	case TASK_FLAVOR_NAME:
		/*
		 * This check is relevant for corpse tasks.
		 * kobject of the port may be disabled. This can be done
		 * in task_port_no_senders. No need to take port lock here,
		 * instead we are doing this check under itk lock.
		 */
		if (ipc_kobject_get_locked(task->itk_task_ports[flavor], kotype) == IKO_NULL) {
			/* kobject of the port was disabled */
			break;
		}
		port = ipc_kobject_make_send(task->itk_task_ports[flavor],
		    task, kotype);
		break;
	/*
	 * Claim a send right on the task read/inspect port,
	 * and request a no-senders notification on that port
	 * (if none outstanding).
	 *
	 * The task's itk_lock is used to synchronize the handling
	 * of the no-senders notification with the task termination.
	 */
	case TASK_FLAVOR_READ:
	case TASK_FLAVOR_INSPECT:
		port = task->itk_task_ports[flavor];
		if (IP_VALID(port)) {
			(void)ipc_kobject_make_send(port, task, kotype);
		} else {
			ipc_object_label_t label = IPC_OBJECT_LABEL(kotype);

			/*
			 * If Developer Mode is off, substitute read port for control port if
			 * copying out to owning task's space, for the sake of in-process
			 * exception handler.
			 *
			 * Also see: exception_deliver().
			 */
			if (!developer_mode_state() && flavor == TASK_FLAVOR_READ) {
				label = ipc_kobject_label_alloc(kotype,
				    IPC_LABEL_SUBST_TASK_READ, task->itk_task_ports[TASK_FLAVOR_CONTROL]);
			}

			port = ipc_kobject_alloc_port(task, label,
			    IPC_KOBJECT_ALLOC_MAKE_SEND);
			task->itk_task_ports[flavor] = port;
		}
		break;
	}

exit:
	itk_unlock(task);
	task_deallocate_grp(task, grp);
	return port;
}

ipc_port_t
convert_corpse_to_port_and_nsrequest(
	task_t          corpse)
{
	ipc_port_t port = IP_NULL;

	assert(task_is_a_corpse(corpse));
	itk_lock(corpse);
	port = corpse->itk_task_ports[TASK_FLAVOR_CONTROL];
	port = ipc_kobject_make_send(port, corpse, IKOT_TASK_CONTROL);
	itk_unlock(corpse);

	task_deallocate(corpse);
	return port;
}

ipc_port_t
convert_task_to_port(
	task_t          task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_CONTROL, TASK_GRP_KERNEL);
}

ipc_port_t
convert_task_read_to_port(
	task_read_t          task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_READ, TASK_GRP_KERNEL);
}

ipc_port_t
convert_task_inspect_to_port(
	task_inspect_t          task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_INSPECT, TASK_GRP_KERNEL);
}

ipc_port_t
convert_task_name_to_port(
	task_name_t             task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_NAME, TASK_GRP_KERNEL);
}

ipc_port_t
convert_task_to_port_external(task_t task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_CONTROL, TASK_GRP_EXTERNAL);
}

ipc_port_t
convert_task_read_to_port_external(task_t task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_READ, TASK_GRP_EXTERNAL);
}

void
convert_task_array_to_ports(
	task_array_t            array,
	size_t                  count,
	mach_task_flavor_t      flavor)
{
	task_t *task_list = (task_t *)array;

	for (size_t i = 0; i < count; i++) {
		task_t     task = task_list[i];
		ipc_port_t port;

		switch (flavor) {
		case TASK_FLAVOR_CONTROL:
			/* copyout determines immovability, see `ipc_should_mark_immovable_send` */
			port = convert_task_to_port(task);
			break;
		case TASK_FLAVOR_READ:
			port = convert_task_read_to_port(task);
			break;
		case TASK_FLAVOR_INSPECT:
			port = convert_task_inspect_to_port(task);
			break;
		case TASK_FLAVOR_NAME:
			port = convert_task_name_to_port(task);
			break;
		}

		array[i].port = port;
	}
}

/*
 *	Routine:	convert_task_suspension_token_to_port_grp
 *	Purpose:
 *		Convert from a task suspension token to a port.
 *		Consumes a task suspension token ref; produces a naked send-once right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
static ipc_port_t
convert_task_suspension_token_to_port_grp(
	task_suspension_token_t         task,
	task_grp_t                      grp)
{
	ipc_port_t port;

	task_lock(task);
	if (task->active) {
		itk_lock(task);
		if (task->itk_resume == IP_NULL) {
			task->itk_resume = ipc_kobject_alloc_port((ipc_kobject_t) task,
			    IKOT_TASK_RESUME, IPC_KOBJECT_ALLOC_NONE);
		}

		/*
		 * Create a send-once right for each instance of a direct user-called
		 * task_suspend2 call. Each time one of these send-once rights is abandoned,
		 * the notification handler will resume the target task.
		 */
		port = task->itk_resume;
		ipc_kobject_require(port, task, IKOT_TASK_RESUME);
		port = ipc_port_make_sonce(port);
		itk_unlock(task);
		assert(IP_VALID(port));
	} else {
		port = IP_NULL;
	}

	task_unlock(task);
	task_suspension_token_deallocate_grp(task, grp);

	return port;
}

ipc_port_t
convert_task_suspension_token_to_port_external(
	task_suspension_token_t         task)
{
	return convert_task_suspension_token_to_port_grp(task, TASK_GRP_EXTERNAL);
}

ipc_port_t
convert_task_suspension_token_to_port_mig(
	task_suspension_token_t         task)
{
	return convert_task_suspension_token_to_port_grp(task, TASK_GRP_MIG);
}

/*
 *	Routine:	space_deallocate
 *	Purpose:
 *		Deallocate a space ref produced by convert_port_to_space.
 *	Conditions:
 *		Nothing locked.
 */

void
space_deallocate(
	ipc_space_t     space)
{
	if (space != IS_NULL) {
		is_release(space);
	}
}

/*
 *	Routine:	space_read_deallocate
 *	Purpose:
 *		Deallocate a space read ref produced by convert_port_to_space_read.
 *	Conditions:
 *		Nothing locked.
 */

void
space_read_deallocate(
	ipc_space_read_t     space)
{
	if (space != IS_INSPECT_NULL) {
		is_release((ipc_space_t)space);
	}
}

/*
 *	Routine:	space_inspect_deallocate
 *	Purpose:
 *		Deallocate a space inspect ref produced by convert_port_to_space_inspect.
 *	Conditions:
 *		Nothing locked.
 */

void
space_inspect_deallocate(
	ipc_space_inspect_t     space)
{
	if (space != IS_INSPECT_NULL) {
		is_release((ipc_space_t)space);
	}
}


static boolean_t
behavior_is_identity_protected(int new_behavior)
{
	return ((new_behavior & ~MACH_EXCEPTION_MASK) == EXCEPTION_IDENTITY_PROTECTED) ||
	       ((new_behavior & ~MACH_EXCEPTION_MASK) == EXCEPTION_STATE) ||
	       ((new_behavior & ~MACH_EXCEPTION_MASK) == EXCEPTION_STATE_IDENTITY_PROTECTED);
}

/* Returns whether the violation should be ignored */
static boolean_t
set_exception_behavior_violation(__unused const task_t excepting_task, const exception_mask_t mask, int new_behavior)
{
	if (thid_should_crash) {
		/* create lightweight corpse */
		mach_port_guard_exception(new_behavior, mask, kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE);
	}

	/* if the bootarg has been manually set to false, ignore the violation */
	return !thid_should_crash;
}

static bool
exception_exposes_protected_ports(const ipc_port_t new_port)
{
	/*
	 * sending exceptions to invalid port does not pose risk
	 * ux_handler port is an immovable, read-only kobject port; doesn't need protection.
	 */
	return IP_VALID(new_port) && !is_ux_handler_port(new_port);
}

static bool
exception_ports_frozen(task_t excepting_task)
{
	return excepting_task &&
	       (task_ro_flags_get(excepting_task) & TFRO_FREEZE_EXCEPTION_PORTS);
}

static bool
exception_is_identity_protected(const ipc_port_t new_port, int new_behavior,
    const task_t excepting_task, const exception_mask_t mask)
{
	ipc_space_policy_t policy = {};

	/* excepting_task is NULL if we are setting a host exception port. */
	if (excepting_task) {
		policy = ipc_policy_for_task(excepting_task);
	}

	if (exception_exposes_protected_ports(new_port)
	    && (!excepting_task || ipc_should_apply_policy(policy, IPC_POLICY_ENHANCED_V1))
	    && !behavior_is_identity_protected(new_behavior)
#if XNU_TARGET_OS_OSX && CONFIG_CSR
	    && SIP_is_enabled()     /* cannot enforce if SIP is disabled */
#endif /* XNU_TARGET_OS_OSX && CONFIG_CSR */
#if CONFIG_ROSETTA
	    && !task_is_translated(current_task())
#endif /* CONFIG_ROSETTA */
	    && !proc_is_simulated(current_proc())
	    ) {
		return set_exception_behavior_violation(excepting_task, mask, new_behavior);
	}

	return true;
}

static boolean_t
set_exception_behavior_allowed(const ipc_port_t new_port, int new_behavior,
    const task_t excepting_task, const exception_mask_t mask, const bool hardened_exception)
{
	const char *excepting_task_name = "";
	const char *cur_task_name = "";

	if (excepting_task) {
		excepting_task_name = task_best_name(excepting_task);
	}
	if (current_task()) {
		cur_task_name = task_best_name(current_task());
	}

	/* Allow debuggers, tests, and tooling to set exception ports however they wish */
	if (IOCurrentTaskHasEntitlement(SET_EXCEPTION_ENTITLEMENT)) {
		kprintf("Allowing set_exception_ports from [%s] on [%s] for "
		    "entitled process/debugger\n", cur_task_name, excepting_task_name);
		return true;
	}

	/* excepting_task can be NULL if setting the host port */
	if (excepting_task) {
		/*
		 * Only allow hardened set_exception_port calls on hardened tasks
		 * that opt in via entitlement
		 */
		ipc_space_policy_t pol = ipc_policy_for_task(excepting_task);
		bool only_one_exception_port =
		    IOTaskHasEntitlement(excepting_task, IPC_ONLY_ONE_EXCEPTION_PORT)
		    && ipc_should_apply_policy(pol, IPC_POLICY_ENHANCED_V1);

		if (!hardened_exception && only_one_exception_port) {
			kprintf("Disallowing set_exception_ports from [%s] on [%s] due "
			    "to only_one_exception_port policy\n", cur_task_name, excepting_task_name);
			return set_exception_behavior_violation(excepting_task, mask, new_behavior);
		}
	}

	/* Everyone else follows the standard policy and must use identity protected exceptions */
	return exception_is_identity_protected(new_port, new_behavior, excepting_task, mask);
}

/*
 *	Routine: set_exception_ports_validation
 *	Purpose:
 *		Common argument validation shared between all exception port
 *		setting/swapping routines
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS            Setting the exception port is allowed
 *		                        with these arguments
 *		KERN_INVALID_ARGUMENT   Invalid arguments
 *		KERN_INVALID_RIGHT      Incorrect port configuration
 *		KERN_DENIED             Denied by security policy
 */
kern_return_t
set_exception_ports_validation(
	task_t                  task,
	exception_mask_t        exception_mask,
	ipc_port_t              new_exception_receiver,
	exception_behavior_t    new_behavior,
	thread_state_flavor_t   new_flavor,
	bool                    hardened_exception)
{
	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_exception_receiver)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
		case EXCEPTION_IDENTITY_PROTECTED:
		case EXCEPTION_STATE_IDENTITY_PROTECTED:
			break;

		default:
			return KERN_INVALID_ARGUMENT;
		}
	}

	if (IP_VALID(new_exception_receiver) && !ipc_is_valid_exception_port(task, new_exception_receiver)) {
		return KERN_INVALID_RIGHT;
	}


	/*
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (((new_behavior & ~MACH_EXCEPTION_MASK) == EXCEPTION_IDENTITY_PROTECTED ||
	    (new_behavior & MACH_EXCEPTION_BACKTRACE_PREFERRED))
	    && !(new_behavior & MACH_EXCEPTION_CODES)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!set_exception_behavior_allowed(new_exception_receiver, new_behavior, task, exception_mask, hardened_exception)) {
		return KERN_DENIED;
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread_set_exception_ports_internal
 *	Purpose:
 *		Set a new exception action on the thread
 *	Conditions:
 *		Arguments have been validated via `set_exception_ports_validation`
 *		Nothing locked.
 *  Returns:
 *      KERN_SUCCESS	Setting the exception port is allowed with these arguments
 *		KERN_FAILURE	Thread is inactive
 */
kern_return_t
thread_set_exception_ports_internal(
	thread_t                thread,
	exception_mask_t        exception_mask,
	ipc_port_t              new_port,
	exception_behavior_t    new_behavior,
	thread_state_flavor_t   new_flavor,
	boolean_t               hardened)
{
	ipc_port_t  old_port[EXC_TYPES_COUNT];
	thread_ro_t tro;
	boolean_t   privileged = task_is_privileged(current_task());

#if CONFIG_MACF
	if (mac_task_check_set_thread_exception_ports(current_task(), get_threadtask(thread), exception_mask, new_behavior) != 0) {
		return KERN_NO_ACCESS;
	}

	struct label *new_label = mac_exc_create_label_for_current_proc();
#endif

	tro = get_thread_ro(thread);
	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return KERN_FAILURE;
	}

	if (tro->tro_exc_actions == NULL) {
		ipc_thread_init_exc_actions(tro);
	}
	for (size_t i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		struct exception_action *action = &tro->tro_exc_actions[i];

		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(action, new_label) == 0
#endif
		    ) {
			old_port[i] = action->port;
			action->port = exception_port_copy_send(new_port);
			action->behavior = new_behavior;
			action->flavor = new_flavor;
			action->privileged = privileged;
			action->hardened = hardened;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	thread_mtx_unlock(thread);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	for (size_t i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {         /* consume send right */
		ipc_port_release_send(new_port);
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread/task_set_exception_ports [kernel call]
 *	Purpose:
 *			Sets the thread/task exception port, flavor and
 *			behavior for the exception types specified by the mask.
 *			There will be one send right per exception per valid
 *			port.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 *		KERN_FAILURE		The thread is dead.
 *		KERN_NO_ACCESS		Restricted access to set port
 */

kern_return_t
thread_set_exception_ports(
	thread_t                thread,
	exception_mask_t        exception_mask,
	ipc_port_t              new_port,
	exception_behavior_t    new_behavior,
	thread_state_flavor_t   new_flavor)
{
	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	bool hardened_exception_flow = false;
	kern_return_t kr = set_exception_ports_validation(get_threadtask(thread),
	    exception_mask, new_port, new_behavior, new_flavor, hardened_exception_flow);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return thread_set_exception_ports_internal(thread, exception_mask, new_port, new_behavior, new_flavor, false);
}

kern_return_t
task_set_exception_ports(
	task_t                                  task,
	exception_mask_t                exception_mask,
	ipc_port_t                              new_port,
	exception_behavior_t    new_behavior,
	thread_state_flavor_t   new_flavor)
{
	ipc_port_t              old_port[EXC_TYPES_COUNT];
	boolean_t privileged = task_is_privileged(current_task());
	register int    i;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	bool hardened_exception_flow = false;
	kern_return_t kr = set_exception_ports_validation(task, exception_mask,
	    new_port, new_behavior, new_flavor, hardened_exception_flow);
	if (kr != KERN_SUCCESS) {
		return kr;
	}


#if CONFIG_MACF
	if (mac_task_check_set_task_exception_ports(current_task(), task, exception_mask, new_behavior) != 0) {
		return KERN_NO_ACCESS;
	}

	struct label *new_label = mac_exc_create_label_for_current_proc();
#endif

	itk_lock(task);

	/*
	 * Allow setting exception port during the span of ipc_task_init() to
	 * ipc_task_terminate(). posix_spawn() port actions can set exception
	 * ports on target task _before_ task IPC access is enabled.
	 */
	if (task->itk_task_ports[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return KERN_FAILURE;
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&task->exc_actions[i], new_label) == 0
#endif
		    ) {
			old_port[i] = task->exc_actions[i].port;
			task->exc_actions[i].port =
			    exception_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			task->exc_actions[i].privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	itk_unlock(task);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {         /* consume send right */
		ipc_port_release_send(new_port);
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread/task_swap_exception_ports [kernel call]
 *	Purpose:
 *			Sets the thread/task exception port, flavor and
 *			behavior for the exception types specified by the
 *			mask.
 *
 *			The old ports, behavior and flavors are returned
 *			Count specifies the array sizes on input and
 *			the number of returned ports etc. on output.  The
 *			arrays must be large enough to hold all the returned
 *			data, MIG returnes an error otherwise.  The masks
 *			array specifies the corresponding exception type(s).
 *
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *
 *		Returns upto [in} CountCnt elements.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 *		KERN_FAILURE		The thread is dead.
 *		KERN_NO_ACCESS		Restricted access to set port
 */

kern_return_t
thread_swap_exception_ports(
	thread_t                        thread,
	exception_mask_t                exception_mask,
	ipc_port_t                      new_port,
	exception_behavior_t            new_behavior,
	thread_state_flavor_t           new_flavor,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	ipc_port_t  old_port[EXC_TYPES_COUNT];
	thread_ro_t tro;
	boolean_t   privileged = task_is_privileged(current_task());
	unsigned int    i, j, count;

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	bool hardened_exception_flow = false;
	kern_return_t kr = set_exception_ports_validation(get_threadtask(thread),
	    exception_mask, new_port, new_behavior, new_flavor, hardened_exception_flow);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

#if CONFIG_MACF
	if (mac_task_check_set_thread_exception_ports(current_task(), get_threadtask(thread), exception_mask, new_behavior) != 0) {
		return KERN_NO_ACCESS;
	}

	struct label *new_label = mac_exc_create_label_for_current_proc();
#endif

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return KERN_FAILURE;
	}

	tro = get_thread_ro(thread);
	if (tro->tro_exc_actions == NULL) {
		ipc_thread_init_exc_actions(tro);
	}

	assert(EXC_TYPES_COUNT > FIRST_EXCEPTION);
	for (count = 0, i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT && count < *CountCnt; ++i) {
		struct exception_action *action = &tro->tro_exc_actions[i];

		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(action, new_label) == 0
#endif
		    ) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (action->port == ports[j] &&
				    action->behavior == behaviors[j] &&
				    action->flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = exception_port_copy_send(action->port);

				behaviors[j] = action->behavior;
				flavors[j] = action->flavor;
				++count;
			}

			old_port[i] = action->port;
			action->port = exception_port_copy_send(new_port);
			action->behavior = new_behavior;
			action->flavor = new_flavor;
			action->privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	thread_mtx_unlock(thread);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	while (--i >= FIRST_EXCEPTION) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {         /* consume send right */
		ipc_port_release_send(new_port);
	}

	*CountCnt = count;

	return KERN_SUCCESS;
}

kern_return_t
task_swap_exception_ports(
	task_t                                          task,
	exception_mask_t                        exception_mask,
	ipc_port_t                                      new_port,
	exception_behavior_t            new_behavior,
	thread_state_flavor_t           new_flavor,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	ipc_port_t              old_port[EXC_TYPES_COUNT];
	boolean_t privileged = task_is_privileged(current_task());
	unsigned int    i, j, count;

#if CONFIG_MACF
	struct label *new_label;
#endif

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	bool hardened_exception_flow = false;
	kern_return_t kr = set_exception_ports_validation(task, exception_mask,
	    new_port, new_behavior, new_flavor, hardened_exception_flow);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

#if CONFIG_MACF
	if (mac_task_check_set_task_exception_ports(current_task(), task, exception_mask, new_behavior) != 0) {
		return KERN_NO_ACCESS;
	}

	new_label = mac_exc_create_label_for_current_proc();
#endif

	itk_lock(task);

	if (!task->ipc_active) {
		itk_unlock(task);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return KERN_FAILURE;
	}

	assert(EXC_TYPES_COUNT > FIRST_EXCEPTION);
	for (count = 0, i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT && count < *CountCnt; ++i) {
		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&task->exc_actions[i], new_label) == 0
#endif
		    ) {
			for (j = 0; j < count; j++) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (task->exc_actions[i].port == ports[j] &&
				    task->exc_actions[i].behavior == behaviors[j] &&
				    task->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = exception_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				++count;
			}

			old_port[i] = task->exc_actions[i].port;

			task->exc_actions[i].port = exception_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			task->exc_actions[i].privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	itk_unlock(task);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	while (--i >= FIRST_EXCEPTION) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {         /* consume send right */
		ipc_port_release_send(new_port);
	}

	*CountCnt = count;

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread/task_get_exception_ports [kernel call]
 *	Purpose:
 *		Clones a send right for each of the thread/task's exception
 *		ports specified in the mask and returns the behaviour
 *		and flavor of said port.
 *
 *		Returns upto [in} CountCnt elements.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Invalid special port,
 *					Illegal mask bit set.
 *		KERN_FAILURE		The thread is dead.
 */
static kern_return_t
thread_get_exception_ports_internal(
	thread_t                        thread,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_info_array_t     ports_info,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	unsigned int count;
	boolean_t info_only = (ports_info != NULL);
	thread_ro_t tro;
	ipc_port_t port_ptrs[EXC_TYPES_COUNT]; /* pointers only, does not hold right */

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!info_only && !ports) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Allocate a save area for FP state before taking thread lock,
	 * if necessary, to ensure that VM_KERNEL_ADDRHASH() doesn't cause
	 * an FP state allocation while holding thread locks.
	 */
	ml_fp_save_area_prealloc();

	tro = get_thread_ro(thread);
	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);

		return KERN_FAILURE;
	}

	count = 0;

	if (tro->tro_exc_actions == NULL) {
		goto done;
	}

	for (int i = FIRST_EXCEPTION, j = 0; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			ipc_port_t exc_port = tro->tro_exc_actions[i].port;
			exception_behavior_t exc_behavior = tro->tro_exc_actions[i].behavior;
			thread_state_flavor_t exc_flavor = tro->tro_exc_actions[i].flavor;

			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (exc_port == port_ptrs[j] &&
				    exc_behavior == behaviors[j] &&
				    exc_flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count && count < *CountCnt) {
				masks[j] = (1 << i);
				port_ptrs[j] = exc_port;

				if (info_only) {
					if (!IP_VALID(exc_port)) {
						ports_info[j] = (ipc_info_port_t){ .iip_port_object = 0, .iip_receiver_object = 0 };
					} else {
						task_t receiver = TASK_NULL;
						(void)ipc_port_get_receiver_task(exc_port, &receiver);
						ports_info[j].iip_port_object = (natural_t)VM_KERNEL_ADDRHASH(exc_port);
						ports_info[j].iip_receiver_object = receiver ? (natural_t)VM_KERNEL_ADDRHASH(receiver) : 0;
					}
				} else {
					ports[j] = exception_port_copy_send(exc_port);
				}
				behaviors[j] = exc_behavior;
				flavors[j] = exc_flavor;
				++count;
			}
		}
	}

done:
	thread_mtx_unlock(thread);

	*CountCnt = count;

	return KERN_SUCCESS;
}

kern_return_t
thread_get_exception_ports(
	thread_t                        thread,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	return thread_get_exception_ports_internal(thread, exception_mask, masks, CountCnt,
	           NULL, ports, behaviors, flavors);
}

kern_return_t
thread_get_exception_ports_info(
	mach_port_t                     port,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_info_array_t     ports_info,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	kern_return_t kr;

	thread_t thread = convert_port_to_thread_read_no_eval(port);

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = thread_get_exception_ports_internal(thread, exception_mask, masks, CountCnt,
	    ports_info, NULL, behaviors, flavors);

	thread_deallocate(thread);
	return kr;
}

kern_return_t
thread_get_exception_ports_from_user(
	mach_port_t                     port,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t         *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	kern_return_t kr;

	thread_t thread = convert_port_to_thread(port);

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = thread_get_exception_ports(thread, exception_mask, masks, CountCnt, ports, behaviors, flavors);

	thread_deallocate(thread);
	return kr;
}

static kern_return_t
task_get_exception_ports_internal(
	task_t                          task,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_info_array_t     ports_info,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	unsigned int count;
	boolean_t info_only = (ports_info != NULL);
	ipc_port_t port_ptrs[EXC_TYPES_COUNT]; /* pointers only, does not hold right */

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!info_only && !ports) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Allocate a save area for FP state before taking task lock,
	 * if necessary, to ensure that VM_KERNEL_ADDRHASH() doesn't cause
	 * an FP state allocation while holding task locks.
	 */
	ml_fp_save_area_prealloc();

	itk_lock(task);

	if (!task->ipc_active) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	count = 0;

	for (int i = FIRST_EXCEPTION, j = 0; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			ipc_port_t exc_port = task->exc_actions[i].port;
			exception_behavior_t exc_behavior = task->exc_actions[i].behavior;
			thread_state_flavor_t exc_flavor = task->exc_actions[i].flavor;

			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (exc_port == port_ptrs[j] &&
				    exc_behavior == behaviors[j] &&
				    exc_flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count && count < *CountCnt) {
				masks[j] = (1 << i);
				port_ptrs[j] = exc_port;

				if (info_only) {
					if (!IP_VALID(exc_port)) {
						ports_info[j] = (ipc_info_port_t){ .iip_port_object = 0, .iip_receiver_object = 0 };
					} else {
						task_t receiver = TASK_NULL;
						(void)ipc_port_get_receiver_task(exc_port, &receiver);
						ports_info[j].iip_port_object = (natural_t)VM_KERNEL_ADDRHASH(exc_port);
						ports_info[j].iip_receiver_object = receiver ? (natural_t)VM_KERNEL_ADDRHASH(receiver) : 0;
					}
				} else {
					ports[j] = exception_port_copy_send(exc_port);
				}
				behaviors[j] = exc_behavior;
				flavors[j] = exc_flavor;
				++count;
			}
		}
	}

	itk_unlock(task);

	*CountCnt = count;

	return KERN_SUCCESS;
}

kern_return_t
task_get_exception_ports(
	task_t                          task,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	return task_get_exception_ports_internal(task, exception_mask, masks, CountCnt,
	           NULL, ports, behaviors, flavors);
}

kern_return_t
task_get_exception_ports_info(
	mach_port_t                     port,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_info_array_t     ports_info,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	kern_return_t kr;

	task_t task = convert_port_to_task_read_no_eval(port);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = task_get_exception_ports_internal(task, exception_mask, masks, CountCnt,
	    ports_info, NULL, behaviors, flavors);

	task_deallocate(task);
	return kr;
}

kern_return_t
task_get_exception_ports_from_user(
	mach_port_t                     port,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t         *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	kern_return_t kr;

	task_t task = convert_port_to_task(port);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = task_get_exception_ports(task, exception_mask, masks, CountCnt, ports, behaviors, flavors);

	task_deallocate(task);
	return kr;
}

/*
 *	Routine:	ipc_thread_port_unpin
 *	Purpose:
 *
 *		Called on the thread when it's terminating so that the last ref
 *		can be deallocated without a guard exception.
 *	Conditions:
 *		Thread mutex lock is held.
 */
void
ipc_thread_port_unpin(
	ipc_port_t port)
{
	ipc_object_unpin(current_space(), port);
}

/*
 *	Routine:	task_register_hardened_exception_handler
 *	Purpose:
 *		Register a port as a hardened exception handler.
 *		See task.defs for additional info
 *	Conditions:
 *		Nothing locked.
 *		Limit of one hardened exception handler per task
 *	Returns:
 *		KERN_INVALID_ARGUMENT	invalid thread
 *		KERN_DENIED             violating the security policy
 *		KERN_NAME_EXISTS        Already set a hardened exception handler
 *		                        on this task
 *		KERN_SUCCESS
 */
kern_return_t
task_register_hardened_exception_handler(
	task_t                  task,
	uint32_t                signed_pc_key,
	exception_mask_t        exceptions_allowed,
	exception_behavior_t    behaviors_allowed,
	thread_state_flavor_t   flavors_allowed,
	mach_port_t             new_port)
{
	ipc_port_t old_port;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (IP_VALID(new_port) && !ip_is_exception_port(new_port)) {
		return KERN_INVALID_ARGUMENT;
	}


	bool hardened_exception_flow = true;
	kern_return_t kr = set_exception_ports_validation(task, exceptions_allowed,
	    new_port, behaviors_allowed, flavors_allowed, hardened_exception_flow);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* You can only register one hardened exception handler */
	if (exception_ports_frozen(task)) {
		return KERN_INVALID_ARGUMENT;
	}
	task_ro_flags_set(task, TFRO_FREEZE_EXCEPTION_PORTS);
	itk_lock(task);

	/* No reason to allow setting this multiple times per task */
	old_port = task->hardened_exception_action.ea.port;
	if (IP_VALID(old_port)) {
		itk_unlock(task);
		return KERN_NAME_EXISTS;
	}

	/* Stash the semantics for this port on the task */
	struct hardened_exception_action hea;
	hea.ea.port = new_port; /* Donate our send right to the task */
	hea.ea.flavor = flavors_allowed;
	hea.ea.behavior = behaviors_allowed;
	hea.ea.privileged = false;
	hea.ea.label = NULL;
	hea.signed_pc_key = signed_pc_key;
	hea.exception = exceptions_allowed;

	task->hardened_exception_action = hea;
	itk_unlock(task);

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread_adopt_exception_handler
 *	Purpose:
 *		Adopt the hardened exception handler from the current task,
 *		for this thread.
 *
 *		Allows to set exception ports on a thread after exception ports
 *		have been frozen for the task.
 *	Conditions:
 *		Nothing locked
 *	Returns:
 *		KERN_INVALID_ARGUMENT   invalid thread
 *		KERN_DENIED             violating the security policy
 *		KERN_SUCCESS
 */
kern_return_t
thread_adopt_exception_handler(
	thread_t                thread,
	mach_port_t             exc_port,
	exception_mask_t        exc_mask,
	exception_behavior_t    behavior_mask,
	thread_state_flavor_t   flavor_mask)
{
	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_t task = get_threadtask(thread);

	if (task != current_task()) {
		return KERN_DENIED;
	}

	/* We must have exactly one hardened exception port per task */
	if (!exception_ports_frozen(task)) {
		return KERN_DENIED;
	}

	/* Ensure we see a consistent state of the hardened exception action */
	itk_lock(task);
	struct hardened_exception_action hea = task->hardened_exception_action;
	itk_unlock(task);

	if (exc_port != IP_NULL && exc_port != hea.ea.port) {
		return KERN_DENIED;
	}
	/* Ensure that the new masks for this thread are a subset of the
	 * allowable masks for this exception handler
	 */
	if (exc_mask & ~hea.exception ||
	    behavior_mask & ~hea.ea.behavior ||
	    flavor_mask & ~hea.ea.flavor) {
		return KERN_DENIED;
	}

	assert(!IP_VALID(exc_port) || ip_is_exception_port(exc_port));

	/*
	 * We can safely assume this will be valid because we called
	 * set_exception_ports_validation on it when it was originally
	 * set on the task
	 */
	return thread_set_exception_ports_internal(thread, exc_mask, exc_port,
	           behavior_mask, flavor_mask, true);
}
