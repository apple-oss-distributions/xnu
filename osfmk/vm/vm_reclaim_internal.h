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

#include <mach/mach_types.h>
#include <mach/vm_reclaim.h>
#include <sys/cdefs.h>
#include <vm/vm_reclaim_xnu.h>

#if MACH_KERNEL_PRIVATE

mach_error_t vm_deferred_reclamation_buffer_allocate_internal(
	task_t            task,
	mach_vm_address_ut *address,
	mach_vm_reclaim_count_t len,
	mach_vm_reclaim_count_t max_len);

kern_return_t vm_deferred_reclamation_buffer_flush_internal(
	task_t                  task,
	mach_vm_reclaim_count_t max_entries_to_reclaim);

kern_return_t vm_deferred_reclamation_buffer_update_reclaimable_bytes_internal(
	task_t task, uint64_t reclaimable_bytes);

/*
 * Resize the reclaim buffer for a given task
 */
kern_return_t vm_deferred_reclamation_buffer_resize_internal(
	task_t            task,
	mach_vm_reclaim_count_t len);


void vm_deferred_reclamation_buffer_lock(vm_deferred_reclamation_metadata_t metadata);
void vm_deferred_reclamation_buffer_unlock(vm_deferred_reclamation_metadata_t metadata);

#if DEVELOPMENT || DEBUG
/*
 * Testing helpers
 */
bool vm_deferred_reclamation_block_until_task_has_been_reclaimed(task_t task);
#endif /* DEVELOPMENT || DEBUG */

#endif /* MACH_KERNEL_PRIVATE */
#endif /* CONFIG_DEFERRED_RECLAIM */
#endif /*__VM_RECLAIM_INTERNAL__ */
