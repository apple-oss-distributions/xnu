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

/*
 *
 * A task identity token represents the identity of a mach task without carrying task
 * access capabilities. In applicable scenarios, task identity token can be moved between
 * tasks and be upgraded to desired level of task port flavor (namely, task name port,
 * inspect port, read port or control port) upon use.
 *
 */

#ifndef _KERN_TASK_IDENT_H
#define _KERN_TASK_IDENT_H

#if KERNEL_PRIVATE

#include <kern/kern_types.h>
#include <mach/mach_types.h>

__BEGIN_DECLS

#define TASK_IDENTITY_TOKEN_KPI_VERSION 1

/*!
 * @function task_id_token_port_name_to_task()
 *
 * @abstract
 * Produces a task reference from task identity token port name.
 *
 * For export to kexts only. _DO NOT_ use in kenel proper for correct task
 * reference counting.
 *
 * @param name     port name for the task identity token to operate on
 * @param taskp    task_t pointer
 *
 * @returns        KERN_SUCCESS           A valid task reference is produced.
 *                 KERN_NOT_FOUND         Cannot find task represented by token.
 *                 KERN_INVALID_ARGUMENT  Passed identity token is invalid.
 */
#if XNU_KERNEL_PRIVATE
kern_return_t task_id_token_port_name_to_task(mach_port_name_t name, task_t *taskp)
__XNU_INTERNAL(task_id_token_port_name_to_task);

void task_id_token_release(task_id_token_t token);

ipc_port_t convert_task_id_token_to_port(task_id_token_t token);

task_id_token_t convert_port_to_task_id_token(ipc_port_t port);

#if MACH_KERNEL_PRIVATE
kern_return_t task_identity_token_get_task_grp(task_id_token_t token, task_t *taskp, task_grp_t grp);
#endif /* MACH_KERNEL_PRIVATE */

#else  /* !XNU_KERNEL_PRIVATE */
kern_return_t task_id_token_port_name_to_task(mach_port_name_t name, task_t *taskp);
#endif /* !XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* KERNEL_PRIVATE */

#endif /* _KERN_TASK_IDENT_H */
