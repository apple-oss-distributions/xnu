/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#include <mach/exception_types.h>
#include <mach/mach_types.h>
#include <osfmk/kern/exception.h>
#include <osfmk/kern/task.h>
#include <sys/codesign.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>

#include <kern/task.h>
#include <kern/telemetry.h>

#include <security/mac_framework.h>
#include <security/mac_internal.h>
#include <security/mac_mach_internal.h>

#if CONFIG_CSR
#include <sys/csr.h>
// Panic on internal builds, just log otherwise.
#define MAC_MACH_UNEXPECTED(fmt...) \
	if (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0) { panic(fmt); } else { printf(fmt); }
#else
#define MAC_MACH_UNEXPECTED(fmt...) printf(fmt)
#endif

static struct proc *
mac_task_get_proc(struct task *task)
{
	if (task == current_task()) {
		return proc_self();
	}

	/*
	 * Tasks don't really hold a reference on a proc unless the
	 * calling thread belongs to the task in question.
	 */
	int pid = task_pid(task);
	struct proc *p = proc_find(pid);

	if (p != NULL) {
		if (proc_task(p) == task) {
			return p;
		}
		proc_rele(p);
	}
	return NULL;
}

int
mac_task_check_expose_task(struct task *task, mach_task_flavor_t flavor)
{
	int error;

	assert(flavor <= TASK_FLAVOR_NAME);

	struct proc *p = mac_task_get_proc(task);
	if (p == NULL) {
		return ESRCH;
	}
	struct proc_ident pident = proc_ident(p);

	struct ucred *cred = kauth_cred_get();
	proc_rele(p);

	MAC_CHECK(proc_check_expose_task_with_flavor, cred, &pident, flavor);

	return error;
}

int
mac_task_check_task_id_token_get_task(struct task *task, mach_task_flavor_t flavor)
{
	int error;
	struct proc *target_proc = NULL;
	struct proc_ident *pidentp = NULL;
	struct proc_ident pident;

	assert(flavor <= TASK_FLAVOR_NAME);

	if (!task_is_a_corpse(task)) {
		/* only live task has proc */
		target_proc = mac_task_get_proc(task);
		if (target_proc == NULL) {
			return ESRCH;
		}
		pident = proc_ident(target_proc);
		pidentp = &pident;
		proc_rele(target_proc);
	}

	/* pidentp is NULL for corpse task */
	MAC_CHECK(proc_check_task_id_token_get_task,
	    current_cached_proc_cred(PROC_NULL), pidentp, flavor);

	return error;
}

int
mac_task_check_get_movable_control_port(void)
{
	int error;

	MAC_CHECK(proc_check_get_movable_control_port,
	    current_cached_proc_cred(PROC_NULL));

	return error;
}

int
mac_task_check_set_host_special_port(struct task *task, int id, struct ipc_port *port)
{
#pragma unused(task)
	int error;

	assert(task == current_task());
	MAC_CHECK(proc_check_set_host_special_port,
	    current_cached_proc_cred(PROC_NULL), id, port);

	return error;
}

int
mac_task_check_set_host_exception_port(struct task *task, unsigned int exception)
{
#pragma unused(task)
	int error;

	assert(task == current_task());
	MAC_CHECK(proc_check_set_host_exception_port,
	    current_cached_proc_cred(PROC_NULL), exception);

	return error;
}

int
mac_task_check_get_task_special_port(struct task *task, struct task *target, int which)
{
#pragma unused(task)
	int error;
	struct proc *target_proc = NULL;
	struct proc_ident *pidentp = NULL;
	struct proc_ident pident;

	assert(task == current_task());

	if (!task_is_a_corpse(target)) {
		/* only live task has proc */
		target_proc = mac_task_get_proc(target);
		if (target_proc == NULL) {
			return ESRCH;
		}
		pident = proc_ident(target_proc);
		pidentp = &pident;
		proc_rele(target_proc);
	}

	/* pidentp is NULL for corpse task */
	MAC_CHECK(proc_check_get_task_special_port,
	    current_cached_proc_cred(PROC_NULL), pidentp, which);

	return error;
}

int
mac_task_check_set_task_special_port(struct task *task, struct task *target, int which, struct ipc_port *port)
{
#pragma unused(task)
	int error;

	assert(task == current_task());

	/*
	 * task_set_special_port() is a CONTROL level interface, so we are guaranteed
	 * by MIG intrans that target is not a corpse.
	 */
	assert(!task_is_a_corpse(target));

	struct proc *targetp = mac_task_get_proc(target);
	if (targetp == NULL) {
		return ESRCH;
	}

	struct proc_ident pident = proc_ident(targetp);
	proc_rele(targetp);

	MAC_CHECK(proc_check_set_task_special_port,
	    current_cached_proc_cred(PROC_NULL), &pident, which, port);

	return error;
}

int
mac_task_check_dyld_process_info_notify_register(void)
{
	int error;

	MAC_CHECK(proc_check_dyld_process_info_notify_register,
	    current_cached_proc_cred(PROC_NULL));

	return error;
}

int
mac_task_check_set_host_exception_ports(struct task *task, unsigned int exception_mask)
{
#pragma unused(task)
	int error = 0;
	int exception;
	kauth_cred_t cred = current_cached_proc_cred(PROC_NULL);

	assert(task == current_task());

	for (exception = FIRST_EXCEPTION; exception < EXC_TYPES_COUNT; exception++) {
		if (exception_mask & (1 << exception)) {
			MAC_CHECK(proc_check_set_host_exception_port,
			    cred, exception);
			if (error) {
				break;
			}
		}
	}

	return error;
}

void
mac_thread_userret(struct thread *td)
{
	MAC_PERFORM(thread_userret, td);
}

void
mac_thread_telemetry(struct thread *t, int err, void *data, size_t length)
{
	MAC_PERFORM(thread_telemetry, t, err, data, length);
}

void
mac_proc_notify_exec_complete(struct proc *proc)
{
	thread_t thread = current_thread();

	/*
	 * Since this MAC hook was designed to support upcalls, make sure the hook
	 * is called with kernel importance propagation enabled so any daemons
	 * can get any appropriate importance donations.
	 */
	thread_enable_send_importance(thread, TRUE);
	MAC_PERFORM(proc_notify_exec_complete, proc);
	thread_enable_send_importance(thread, FALSE);
}

/**** Exception Policy
 *
 * Note that the functions below do not fully follow the usual convention for mac policy functions
 * in the kernel. Besides avoiding confusion in how the mac function names are mixed with the actual
 * policy function names, we diverge because the exception policy is somewhat special:
 * It is used in places where allocation and association must be separate, and its labels do not
 * only belong to one type of object as usual, but to two (on exception actions and on tasks as
 * crash labels).
 */

struct label *
mac_exc_label(struct exception_action *action)
{
	return mac_label_verify(&action->label);
}

void
mac_exc_set_label(struct exception_action *action, struct label *label)
{
	action->label = label;
}

// Label allocation and deallocation, may sleep.

struct label *
mac_exc_create_label(struct exception_action *action)
{
	return mac_labelzone_alloc_for_owner(action ? &action->label : NULL, MAC_WAITOK, ^(struct label *label) {
		// Policy initialization of the label, typically performs allocations as well.
		// (Unless the policy's full data really fits into a pointer size.)
		MAC_PERFORM(exc_action_label_init, label);
	});
}

void
mac_exc_free_label(struct label *label)
{
	MAC_PERFORM(exc_action_label_destroy, label);
	mac_labelzone_free(label);
}

// Action label initialization and teardown, may sleep.

void
mac_exc_associate_action_label(struct exception_action *action, struct label *label)
{
	mac_exc_set_label(action, label);
	MAC_PERFORM(exc_action_label_associate, action, mac_exc_label(action));
}

void
mac_exc_free_action_label(struct exception_action *action)
{
	mac_exc_free_label(mac_exc_label(action));
	mac_exc_set_label(action, NULL);
}

// Action label update and inheritance, may NOT sleep and must be quick.

int
mac_exc_update_action_label(struct exception_action *action,
    struct label *newlabel)
{
	int error;

	MAC_CHECK(exc_action_label_update, action, mac_exc_label(action), newlabel);

	return error;
}

int
mac_exc_inherit_action_label(struct exception_action *parent,
    struct exception_action *child)
{
	return mac_exc_update_action_label(child, mac_exc_label(parent));
}

int
mac_exc_update_task_crash_label(struct task *task, struct label *label)
{
	int error;

	assert(task != kernel_task);

	struct label *crash_label = get_task_crash_label(task);

	MAC_CHECK(exc_action_label_update, NULL, crash_label, label);

	return error;
}

// Process label creation, may sleep.

struct label *
mac_exc_create_label_for_proc(struct proc *proc)
{
	struct label *label = mac_exc_create_label(NULL);
	MAC_PERFORM(exc_action_label_populate, label, proc);
	return label;
}

struct label *
mac_exc_create_label_for_current_proc(void)
{
	return mac_exc_create_label_for_proc(current_proc());
}

// Exception handler policy checking, may sleep.

int
mac_exc_action_check_exception_send(struct task *victim_task, struct exception_action *action)
{
	int error = 0;

	struct proc *p = get_bsdtask_info(victim_task);
	struct label *bsd_label = NULL;
	struct label *label = NULL;

	if (p != NULL) {
		// Create a label from the still existing bsd process...
		label = bsd_label = mac_exc_create_label_for_proc(p);
	} else {
		// ... otherwise use the crash label on the task.
		label = get_task_crash_label(victim_task);
	}

	if (label == NULL) {
		MAC_MACH_UNEXPECTED("mac_exc_action_check_exception_send: no exc_action label for process");
		return EPERM;
	}

	MAC_CHECK(exc_action_check_exception_send, label, action, mac_exc_label(action));

	if (bsd_label != NULL) {
		mac_exc_free_label(bsd_label);
	}

	return error;
}

int
mac_schedule_telemetry(void)
{
	return telemetry_macf_mark_curthread();
}
