/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef __VM_RECLAIM_XNU__
#define __VM_RECLAIM_XNU__

#ifdef XNU_KERNEL_PRIVATE
#if CONFIG_DEFERRED_RECLAIM
#include <mach/mach_types.h>
#if BSD_KERNEL_PRIVATE
#include <mach/mach_vm.h>
#else /* BSD_KERNEL_PRIVATE */
#include <mach/mach_vm_server.h>
#endif /* BSD_KERNEL_PRIVATE */

extern uint64_t vm_reclaim_max_threshold;
typedef struct vm_deferred_reclamation_metadata_s *vm_deferred_reclamation_metadata_t;

__options_closed_decl(vm_deferred_reclamation_options_t, uint8_t, {
	RECLAIM_OPTIONS_NONE = 0x00,
	/* Do not fault on the reclaim buffer if it is not resident */
	RECLAIM_NO_FAULT     = 0x01,
	/* Do not wait to acquire the buffer if it is owned by another thread */
	RECLAIM_NO_WAIT      = 0x02,
});

/*
 * Deallocate the kernel metadata associated with this reclamation buffer
 * Note that this does NOT free the memory in the buffer.
 * This is called from the task_destroy path, so we're about to reclaim all of the task's memory
 * anyways.
 */
void vm_deferred_reclamation_buffer_deallocate(vm_deferred_reclamation_metadata_t metadata);


/*
 * Uninstall the the kernel metadata associated with this reclamation buffer from all global queues. This
 * is called during task termination to ensure no kernel thread may start trying to reclaim from a task
 * that is about to exit
 */
void vm_deferred_reclamation_buffer_uninstall(vm_deferred_reclamation_metadata_t metadata);

/*
 * Equivalent to vm_deferred_reclamation_reclaim_memory(RECLAIM_FULL);
 */
void vm_deferred_reclamation_reclaim_all_memory(
	vm_deferred_reclamation_options_t options);

bool vm_deferred_reclamation_reclaim_from_task_async(task_t task);

kern_return_t vm_deferred_reclamation_reclaim_from_task_sync(
	task_t task,
	size_t max_entries_to_reclaim);

/*
 * Create a fork of the given reclamation buffer for a new task.
 * Parent buffer must be locked and will be unlocked on return.
 *
 * This must be called when forking a task that has a reclamation buffer
 * to ensure that the kernel knows about the child's reclamation buffer.
 * The caller must lock the parent's reclamation buffer BEFORE forking
 * the parent's vm_map. Otherwise the parent's buffer could get reclaimed
 * in between the map fork and the buffer fork causing the child's
 * data strucutres to be out of sync.
 */
vm_deferred_reclamation_metadata_t vm_deferred_reclamation_buffer_fork(
	task_t task,
	vm_deferred_reclamation_metadata_t parent);

/*
 * Set the current thread as the owner of a reclaim buffer. May block. Will
 * propagate priority.
 */
void vm_deferred_reclamation_buffer_own(vm_deferred_reclamation_metadata_t metadata);

/*
 * Release ownership of a reclaim buffer and wakeup any threads waiting for
 * ownership. Must be called from the thread that acquired ownership.
 */
void vm_deferred_reclamation_buffer_disown(vm_deferred_reclamation_metadata_t metadata);


#endif /* CONFIG_DEFERRED_RECLAIM */
#endif /* XNU_KERNEL_PRIVATE */
#endif  /* __VM_RECLAIM_XNU__ */
