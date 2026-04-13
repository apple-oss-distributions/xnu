/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#ifndef _VM_STACKSHOT_UTILITIES_XNU_H_
#define _VM_STACKSHOT_UTILITIES_XNU_H_

#include <stdbool.h>
#include <vm/vm_map_xnu.h>

/*!
 * @file vm_stackshot_utilities.c
 *
 * @discussion
 * This module implements VM-related routines called from stackshot.
 *
 * It's meant to act as a bridge between VM and stackshot.
 */

#ifdef XNU_KERNEL_PRIVATE

struct vm_map_lock_ctx;
typedef struct vm_map_lock_ctx *vm_map_lock_ctx_t;

 __BEGIN_DECLS


#define STACKSHOT_VMRL_MAX_OWNERS                 512
#define STACKSHOT_VMRL_MAX_WAITERS                256
#define STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS 256

/* Meant for use in stackshot to record vmrl owners, eventually helping us to get vmrl_rels */
typedef struct stackshot_thread_vmrl_owner_info {
	uint64_t owner_tid;
	vm_map_t map;
	vm_offset_t start;
	vm_offset_t end;
	uint32_t flags;
} thread_vmrl_owner_info_t;

typedef struct stackshot_thread_vmrl_waiter_info {
	uint64_t waiter_tid;
	vm_map_t map;
	uint64_t entry_hash;
	vm_offset_t start;
	vm_offset_t end;
	uint32_t flags;
	uint32_t num_blockers;
} thread_vmrl_waiter_info_t;

struct stackshot_vmrl_state {
	thread_vmrl_owner_info_t     *owners;         /* Info about threads that are owners of some vm range */
	uint32_t _Atomic              num_owners;
	thread_vmrl_waiter_info_t    *waiters;         /* Info about threads that are waiting for some vm range */
	uint32_t _Atomic              num_waiters;
	vmrl_blocking_relationship_t  relationships[STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS];         /* Each of these denotes a dependency, i.e. one thread waiting for another thread to unlock a vm range. This is what ends up in the stackshot buffer. */
	uint32_t _Atomic              exp_num_relationships;         /* When going over all found waiters, we count how many other threads are owners og the entry they requested. This is the sum of all of these. */
};

void
vmrl_stackshot_collect_intermediary_info(
	thread_t                     thread,
	struct stackshot_vmrl_state *state);

/*!
 * This gets called outside the debugger trap.
 * Blockers' and waiters' data was collected under the stackshot debugger trap,
 * and now we can match waiters to their blockers based on that.
 */
uint32_t
vmrl_stackshot_collect_final_blocking_rels(
	struct stackshot_vmrl_state  *state);

__END_DECLS

#endif /* XNU_KERNEL_PRIVATE */
#endif /* _VM_STACKSHOT_UTILITIES_H_ */
