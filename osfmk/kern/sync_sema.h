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
 *	File:	kern/sync_sema.h
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed semaphore synchronization service definitions.
 */

#ifndef _KERN_SYNC_SEMA_H_
#define _KERN_SYNC_SEMA_H_

#include <kern/kern_types.h>
#include <mach/sync_policy.h>
#include <mach/clock_types.h>

#ifdef MACH_KERNEL_PRIVATE

#include <kern/queue.h>
#include <kern/waitq.h>
#include <os/refcnt.h>

typedef struct semaphore {
	queue_chain_t     task_link;  /* chain of semaphores owned by a task */
	struct waitq      waitq;      /* queue of blocked threads & lock     */
	task_t            owner;      /* task that owns semaphore            */
	ipc_port_t        port;       /* semaphore port                      */
	os_ref_atomic_t   ref_count;  /* reference count                     */
	int               count;      /* current count value                 */
} Semaphore;

#define semaphore_lock(semaphore)   waitq_lock(&(semaphore)->waitq)
#define semaphore_unlock(semaphore) waitq_unlock(&(semaphore)->waitq)

extern void semaphore_reference(
	semaphore_t semaphore);

extern void semaphore_dereference(
	semaphore_t semaphore);

#pragma GCC visibility push(hidden)

extern void semaphore_destroy_all(
	task_t      task);

extern semaphore_t convert_port_to_semaphore(
	ipc_port_t  port);

extern ipc_port_t convert_semaphore_to_port(
	semaphore_t semaphore);

extern kern_return_t port_name_to_semaphore(
	mach_port_name_t  name,
	semaphore_t       *semaphore);

#pragma GCC visibility pop
#endif /* MACH_KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

#define SEMAPHORE_CONT_NULL ((semaphore_cont_t)NULL)
typedef void (*semaphore_cont_t)(kern_return_t);

extern kern_return_t semaphore_signal_internal_trap(
	mach_port_name_t sema_name);

extern kern_return_t semaphore_timedwait_signal_trap_internal(
	mach_port_name_t wait_name,
	mach_port_name_t signal_name,
	unsigned int     sec,
	clock_res_t      nsec,
	semaphore_cont_t);

extern kern_return_t semaphore_timedwait_trap_internal(
	mach_port_name_t name,
	unsigned int     sec,
	clock_res_t      nsec,
	semaphore_cont_t);

extern kern_return_t semaphore_wait_signal_trap_internal(
	mach_port_name_t wait_name,
	mach_port_name_t signal_name,
	semaphore_cont_t);

extern kern_return_t semaphore_wait_trap_internal(
	mach_port_name_t name,
	semaphore_cont_t);

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */
#endif /* _KERN_SYNC_SEMA_H_ */
