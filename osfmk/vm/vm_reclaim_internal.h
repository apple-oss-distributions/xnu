/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef __VM_RECLAIM_INTERNAL__
#define __VM_RECLAIM_INTERNAL__

#if CONFIG_DEFERRED_RECLAIM

#ifdef XNU_KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <mach/mach_vm.h>

typedef struct vm_deferred_reclamation_metadata_s *vm_deferred_reclamation_metadata_t;

kern_return_t vm_deferred_reclamation_buffer_init_internal(task_t task, user_addr_t address, mach_vm_size_t size, user_addr_t indices);

/*
 * Deallocate the kernel metadata associated with this reclamation buffer
 * Note that this does NOT free the memory in the buffer.
 * This is called from the task_destroy path, so we're about to reclaim all of the task's memory
 * anyways.
 */
void vm_deferred_reclamation_buffer_deallocate(vm_deferred_reclamation_metadata_t metadata);

kern_return_t vm_deferred_reclamation_buffer_synchronize_internal(task_t task, size_t max_entries_to_reclaim);

__enum_decl(vm_deferred_reclamation_action_t, uint32_t, {
	RECLAIM_TRIM, // Reclaim a bit of memory from everyone
	RECLAIM_FULL, // Fully drain every reclaim buffer
	RECLAIM_ASYNC, // Drain the async reclaim queue
});

/*
 * Ask the deferred reclamation subsystem to reclaim memory.
 * See the documentation for vm_deferred_reclamation_action above.
 */
void vm_deferred_reclamation_reclaim_memory(vm_deferred_reclamation_action_t action);
/*
 * Equivalent to vm_deferred_reclamation_reclaim_memory(RECLAIM_FULL);
 */
void vm_deferred_reclamation_reclaim_all_memory(void);

bool vm_deferred_reclamation_reclaim_from_task_async(task_t task);
bool vm_deferred_reclamation_reclaim_from_task_sync(task_t task, size_t max_entries_to_reclaim);

kern_return_t vm_deferred_reclamation_buffer_update_reclaimable_bytes_internal(
	task_t task, size_t reclaimable_bytes);

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

void vm_deferred_reclamation_buffer_lock(vm_deferred_reclamation_metadata_t metadata);
void vm_deferred_reclamation_buffer_unlock(vm_deferred_reclamation_metadata_t metadata);

#if DEVELOPMENT || DEBUG
/*
 * Testing helpers
 */
bool vm_deferred_reclamation_block_until_pid_has_been_reclaimed(int pid);
#endif /* DEVELOPMENT || DEBUG */

#endif /* XNU_KERNEL_PRIVATE */
#endif /* CONFIG_DEFERRED_RECLAIM */
#endif /*__VM_RECLAIM_INTERNAL__ */
