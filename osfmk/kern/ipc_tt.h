/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_IPC_TT_H_
#define _KERN_IPC_TT_H_

#include <mach/boolean.h>
#include <mach/port.h>
#include <vm/vm_kern.h>
#include <kern/kern_types.h>
#include <kern/ipc_kobject.h>
#include <kern/task_ref.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>


/* Initialize a task's IPC state */
extern void ipc_task_init(
	task_t          task,
	task_t          parent);

/* Enable a task for IPC access */
extern void ipc_task_enable(
	task_t          task);

/* Disable IPC access to a task */
extern void ipc_task_disable(
	task_t          task);

/* Clear out a task's IPC state */
extern void ipc_task_reset(
	task_t          task);

/* Clean up and destroy a task's IPC state */
extern void ipc_task_terminate(
	task_t          task);

/* Setup task control port according to it's control port options */
extern void ipc_task_set_immovable_pinned(
	task_t          task);

/* Setup thread control port according to it's owning task's port options */
extern void ipc_main_thread_set_immovable_pinned(
	thread_t          thread);

__options_decl(ipc_thread_init_options_t, uint32_t, {
	IPC_THREAD_INIT_NONE       = 0x00,
	IPC_THREAD_INIT_MAINTHREAD = 0x01,
});

__options_decl(port_intrans_options_t, uint32_t, {
	PORT_INTRANS_OPTIONS_NONE              = 0x0000,
	PORT_INTRANS_THREAD_IN_CURRENT_TASK    = 0x0001,
	PORT_INTRANS_THREAD_NOT_CURRENT_THREAD = 0x0002,

	PORT_INTRANS_SKIP_TASK_EVAL            = 0x0004,
	PORT_INTRANS_ALLOW_CORPSE_TASK         = 0x0008,
});

/* Initialize a thread's IPC state */
extern void ipc_thread_init(
	task_t          task,
	thread_t        thread,
	thread_ro_t     tro,
	ipc_thread_init_options_t options);

/* Disable IPC access to a thread */
extern void ipc_thread_disable(
	thread_t        thread);

/* Clean up and destroy a thread's IPC state */
extern void ipc_thread_terminate(
	thread_t        thread);

/* Clear out a thread's IPC state */
extern void ipc_thread_reset(
	thread_t        thread);

/* Return a send right for the thread's user-visible self port */
extern ipc_port_t retrieve_thread_self_fast(
	thread_t        thread);

/* Convert from a port to a task name */
extern task_name_t convert_port_to_task_name(
	ipc_port_t      port);

/* Convert from a port to a task name */
extern task_name_t convert_port_to_task_name_mig(
	ipc_port_t      port);

/* Convert from a port to a task for task_policy_set(). */
extern task_policy_set_t convert_port_to_task_policy_set_mig(
	ipc_port_t      port);


/* Convert from a port to a task for task_policy_get(). */
extern task_policy_get_t convert_port_to_task_policy_get_mig(
	ipc_port_t      port);

/* Convert from a port to a task inspect */
extern task_inspect_t convert_port_to_task_inspect(
	ipc_port_t      port);

/* Variant for skipping task_conversion_eval() */
extern task_inspect_t convert_port_to_task_inspect_no_eval(
	ipc_port_t      port);

/* Convert from a port to a task inspect - mig version */
extern task_inspect_t convert_port_to_task_inspect_mig(
	ipc_port_t      port);

/* Convert from a port to a task read */
extern task_read_t convert_port_to_task_read(
	ipc_port_t      port);

/* Convert from a port to a task read */
extern task_read_t convert_port_to_task_read_mig(
	ipc_port_t      port);

/* Convert from a port to a task */
extern task_t convert_port_to_task(
	ipc_port_t      port);

/* Convert from a port to a pinned task */
extern task_t convert_port_to_task_pinned(
	ipc_port_t      port);

/* Convert from a port to a task */
extern task_t convert_port_to_task_mig(
	ipc_port_t      port);

/* Doesn't give a +1 on task, returns current_task() or TASK_NULL */
extern task_t port_name_to_current_task_noref(
	mach_port_name_t name);

/* Doesn't give a +1 on task, returns current_task() or TASK_NULL */
extern task_read_t port_name_to_current_task_read_noref(
	mach_port_name_t name);

extern task_t port_name_to_task(
	mach_port_name_t name);

extern task_t port_name_to_task_kernel(
	mach_port_name_t name);

extern task_t port_name_to_task_external(
	mach_port_name_t name);

extern task_read_t port_name_to_task_read(
	mach_port_name_t name);

extern task_read_t port_name_to_task_read_no_eval(
	mach_port_name_t name);

extern task_t port_name_to_task_name(
	mach_port_name_t name);

extern task_id_token_t port_name_to_task_id_token(
	mach_port_name_t name);

extern host_t port_name_to_host(
	mach_port_name_t name);

extern boolean_t ref_task_port_locked(
	ipc_port_t port, task_t *ptask);

/* Convert from a port to a space */
extern ipc_space_t convert_port_to_space(
	ipc_port_t      port);

/* Convert from a port to a space inspection right */
extern ipc_space_read_t convert_port_to_space_read(
	ipc_port_t      port);
/* Variant for skipping task_conversion_eval() */
extern ipc_space_read_t convert_port_to_space_read_no_eval(
	ipc_port_t      port);

/* Convert from a port to a space inspection right */
extern ipc_space_inspect_t convert_port_to_space_inspect(
	ipc_port_t      port);

extern boolean_t ref_space_port_locked(
	ipc_port_t port, ipc_space_t *pspace);

/* Convert from a port to a map */
extern vm_map_t convert_port_to_map(
	ipc_port_t      port);

/* Convert from a port to a map read */
extern vm_map_read_t convert_port_to_map_read(
	ipc_port_t      port);

/* Convert from a port to a map inspect */
extern vm_map_inspect_t convert_port_to_map_inspect(
	ipc_port_t      port);

/* Convert from a port to a thread */
extern thread_t convert_port_to_thread(
	ipc_port_t              port);

/* Convert from a port to a thread inspect */
extern thread_inspect_t convert_port_to_thread_inspect(
	ipc_port_t              port);

/* Convert from a port to a thread read */
extern thread_read_t convert_port_to_thread_read(
	ipc_port_t              port);

extern thread_t port_name_to_thread(
	mach_port_name_t            port_name,
	port_intrans_options_t    options);

/* Deallocate a space ref produced by convert_port_to_space */
extern void space_deallocate(
	ipc_space_t             space);

extern void space_read_deallocate(
	ipc_space_read_t             space);

extern void space_inspect_deallocate(
	ipc_space_inspect_t     space);

extern kern_return_t thread_get_kernel_special_reply_port(void);

extern void thread_dealloc_kernel_special_reply_port(thread_t thread);

#if MACH_KERNEL_PRIVATE
extern void ipc_thread_port_unpin(
	ipc_port_t port);

extern ipc_port_t
convert_task_suspension_token_to_port_external(
	task_suspension_token_t         task);

extern ipc_port_t
convert_task_suspension_token_to_port_mig(
	task_suspension_token_t         task);

extern task_suspension_token_t
convert_port_to_task_suspension_token_external(
	ipc_port_t                      port);

extern task_suspension_token_t
convert_port_to_task_suspension_token_mig(
	ipc_port_t                      port);

extern task_suspension_token_t
convert_port_to_task_suspension_token_kernel(
	ipc_port_t                      port);


#endif

#endif  /* _KERN_IPC_TT_H_ */
