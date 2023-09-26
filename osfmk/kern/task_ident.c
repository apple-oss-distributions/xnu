/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <os/refcnt.h>

#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/task_ident.h>

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/notify.h>
#include <mach/kern_return.h>

#include <security/mac_mach_internal.h>
#include <kern/task_ident.h>
#include <corpses/task_corpse.h>

struct proc_ident {
	uint64_t        p_uniqueid;
	pid_t           p_pid;
	int             p_idversion;
};

extern void* proc_find_ident(struct proc_ident const *i);
extern int proc_rele(void* p);
extern task_t proc_task(void* p);
extern struct proc_ident proc_ident(void* p);
extern kern_return_t task_conversion_eval(task_t caller, task_t victim, int flavor);

/* Exported to kexts */
extern typeof(task_id_token_port_name_to_task) task_id_token_port_name_to_task_external;

struct task_id_token {
	struct proc_ident ident;
	ipc_port_t        port;
	uint64_t          task_uniqueid; /* for corpse task */
	os_refcnt_t       tidt_refs;
};

static ZONE_DEFINE_TYPE(task_id_token_zone, "task_id_token",
    struct task_id_token, ZC_ZFREE_CLEARMEM);

void task_id_token_set_port(task_id_token_t token, ipc_port_t port);

static void
tidt_reference(task_id_token_t token)
{
	if (token == TASK_ID_TOKEN_NULL) {
		return;
	}
	os_ref_retain(&token->tidt_refs);
}

static void
tidt_release(task_id_token_t token)
{
	ipc_port_t port;

	if (token == TASK_ID_TOKEN_NULL) {
		return;
	}

	if (os_ref_release(&token->tidt_refs) > 0) {
		return;
	}

	/* last ref */
	port = token->port;

	if (IP_VALID(port)) {
#if CONFIG_PROC_RESOURCE_LIMITS
		/*
		 * Ports of type IKOT_TASK_FATAL use task_ident objects to avoid holding a task reference
		 * and are created to send resource limit notifications
		 */
		int kotype = ip_kotype(port);
		if (kotype == IKOT_TASK_ID_TOKEN || kotype == IKOT_TASK_FATAL) {
			ipc_kobject_dealloc_port(port, 0, kotype);
		} else {
			panic("%s: unexpected kotype of port %p: got %d",
			    __func__, port, kotype);
		}
#else /* CONFIG_PROC_RESOURCE_LIMITS */
		ipc_kobject_dealloc_port(port, 0, IKOT_TASK_ID_TOKEN);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
	}

	zfree(task_id_token_zone, token);
}

void
task_id_token_release(task_id_token_t token)
{
	tidt_release(token);
}

static void
task_id_token_no_senders(ipc_port_t port, __unused mach_port_mscount_t mscount)
{
	task_id_token_t token;

	token = ipc_kobject_get_stable(port, IKOT_TASK_ID_TOKEN);
	assert(token != NULL);
	assert(port->ip_srights == 0);

	tidt_release(token); /* consumes ref given by notification */
}

IPC_KOBJECT_DEFINE(IKOT_TASK_ID_TOKEN,
    .iko_op_stable     = true,
    .iko_op_no_senders = task_id_token_no_senders);

kern_return_t
task_create_identity_token(
	task_t task,
	task_id_token_t *tokenp)
{
	task_id_token_t token;
	void *bsd_info = NULL;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	token = zalloc_flags(task_id_token_zone, Z_ZERO | Z_WAITOK | Z_NOFAIL);

	task_lock(task);

	bsd_info = get_bsdtask_info(task);
	if (task_is_a_corpse(task)) {
		token->task_uniqueid = task->task_uniqueid;
	} else if (task->active && bsd_info != NULL) {
		/* must check if the task is active to avoid a UAF - rdar://91431693 */
		token->ident = proc_ident(bsd_info);
	} else {
		task_unlock(task);
		zfree(task_id_token_zone, token);
		return KERN_INVALID_ARGUMENT;
	}

	task_unlock(task);

	token->port = IP_NULL;
	/* this reference will be donated to no-senders notification */
	os_ref_init_count(&token->tidt_refs, NULL, 1);

	*tokenp = token;

	return KERN_SUCCESS;
}

/* Produces (corpse) task reference, does not consume token reference */
kern_return_t
task_identity_token_get_task_grp(
	task_id_token_t token,
	task_t          *taskp,
	task_grp_t      grp)
{
	kern_return_t kr;
	task_t task;

	if (token == TASK_ID_TOKEN_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (token->task_uniqueid) {
		kr = find_corpse_task_by_uniqueid_grp(token->task_uniqueid, &task, grp); /* produces ref */
		if (kr) {
			return KERN_NOT_FOUND;
		}
		assert(task_is_a_corpse(task));
	} else {
		void* p = proc_find_ident(&token->ident);
		if (p == NULL) {
			return KERN_NOT_FOUND;
		}
		task = proc_task(p);
		task_reference_grp(task, grp); /* produces ref */
		proc_rele(p);
	}

	*taskp = task;

	return KERN_SUCCESS;
}

/* Produces task port send right, does not consume token reference */
kern_return_t
task_identity_token_get_task_port(
	task_id_token_t token,
	task_flavor_t   flavor,
	mach_port_t     *portp)
{
	task_t task;
	kern_return_t kr;

	if (token == TASK_ID_TOKEN_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (flavor > TASK_FLAVOR_MAX) {
		return KERN_INVALID_ARGUMENT;
	}

	if (token->task_uniqueid) {
		/*
		 * For corpses, the control port reference would hold the corpse,
		 * only allow conversion to control port for now.
		 */
		if (flavor != TASK_FLAVOR_CONTROL) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	if ((kr = task_identity_token_get_task_grp(token, &task, TASK_GRP_KERNEL)) != KERN_SUCCESS) {
		return kr;
	}

	assert(task != TASK_NULL);
	assert(token != TASK_ID_TOKEN_NULL);

	/* holding a ref on (corpse) task */

	if (flavor == TASK_FLAVOR_CONTROL && task == current_task()) {
		*portp = convert_task_to_port_pinned(task); /* consumes task ref */
		return KERN_SUCCESS;
	}

	if (flavor <= TASK_FLAVOR_READ &&
	    task_conversion_eval(current_task(), task, flavor)) {
		task_deallocate(task);
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF

	if (task != current_task()) {
		if (mac_task_check_task_id_token_get_task(task, flavor)) {
			task_deallocate(task);
			return KERN_DENIED;
		}
	}
#endif

	*portp = convert_task_to_port_with_flavor(task, flavor, TASK_GRP_KERNEL);
	/* task ref consumed */

	return KERN_SUCCESS;
}

/* Produces task reference */
static kern_return_t
task_id_token_port_name_to_task_grp(
	mach_port_name_t name,
	task_t           *task,
	task_grp_t       grp)
{
	kern_return_t kr;
	task_id_token_t token;

	token = port_name_to_task_id_token(name); /* produces ref */
	kr = task_identity_token_get_task_grp(token, task, grp);

	tidt_release(token); /* consumes ref */

	return kr;
}
/* Used by kexts only */
kern_return_t
task_id_token_port_name_to_task_external(
	mach_port_name_t name,
	task_t           *task)
{
	return task_id_token_port_name_to_task_grp(name, task, TASK_GRP_EXTERNAL);
}
/* Used by kernel proper */
kern_return_t
task_id_token_port_name_to_task(
	mach_port_name_t name,
	task_t           *task)
{
	return task_id_token_port_name_to_task_grp(name, task, TASK_GRP_KERNEL);
}

/* Produces token reference */
task_id_token_t
convert_port_to_task_id_token(
	ipc_port_t              port)
{
	task_id_token_t token = TASK_ID_TOKEN_NULL;

	if (IP_VALID(port)) {
		token = ipc_kobject_get_stable(port, IKOT_TASK_ID_TOKEN);
		if (token != TASK_ID_TOKEN_NULL) {
			zone_require(task_id_token_zone, token);
			tidt_reference(token);
		}
	}
	return token;
}

/* Consumes token reference */
ipc_port_t
convert_task_id_token_to_port(
	task_id_token_t token)
{
	__assert_only bool kr;

	if (token == TASK_ID_TOKEN_NULL) {
		return IP_NULL;
	}

	zone_require(task_id_token_zone, token);

	kr = ipc_kobject_make_send_lazy_alloc_port(&token->port,
	    token, IKOT_TASK_ID_TOKEN, IPC_KOBJECT_ALLOC_NONE);
	assert(kr == TRUE); /* no-senders notification is armed, consumes token ref */

	return token->port;
}

#if CONFIG_PROC_RESOURCE_LIMITS

/* Should be used only by ports of type IKOT_TASK_FATAL at allocation time */
void
task_id_token_set_port(
	task_id_token_t token,
	ipc_port_t port)
{
	assert(token && port && (ip_kotype(port) == IKOT_TASK_FATAL));
	token->port = port;
}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
