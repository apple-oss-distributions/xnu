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

#pragma once

#include <vm/vm_map_xnu.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_lock_perf.h>

#if DEBUG || DEVELOPMENT
SCALABLE_COUNTER_DECLARE(vm_fault_busy_trylock_count);
SCALABLE_COUNTER_DECLARE(vm_fault_excl_count);
SCALABLE_COUNTER_DECLARE(vm_fault_page_excl_count);
SCALABLE_COUNTER_DECLARE(vm_fault_copy_busy_trylock_count);
#endif /* DEVELOPMENT || DEBUG */
SCALABLE_COUNTER_DECLARE(vm_fault_busy_retry_count);
SCALABLE_COUNTER_DECLARE(vm_fault_excl_busy_count);
SCALABLE_COUNTER_DECLARE(vm_fault_page_excl_busy_count);
SCALABLE_COUNTER_DECLARE(vm_fault_page_excl_clean_count);
SCALABLE_COUNTER_DECLARE(vm_fault_page_excl_busy_copy_count);
SCALABLE_COUNTER_DECLARE(vm_fault_page_excl_blocked_obj_count);
SCALABLE_COUNTER_DECLARE(vm_fault_page_excl_pager_not_ready_count);
SCALABLE_COUNTER_DECLARE(vm_fault_copy_busy_retry_count);

typedef enum __enum_closed {
	VMLP_EVENT_LC_NONE = 0,
	VMLP_EVENT_LC_VM_FAULT_BUSY_RETRY,
	VMLP_EVENT_LC_VM_FAULT_EXCL_BUSY,
	VMLP_EVENT_LC_VM_FAULT_PAGE_EXCL_BUSY,
	VMLP_EVENT_LC_VM_FAULT_PAGE_EXCL_CLEAN,
	VMLP_EVENT_LC_VM_FAULT_PAGE_EXCL_BUSY_COPY,
	VMLP_EVENT_LC_VM_FAULT_PAGE_EXCL_BLOCKED_OBJ,
	VMLP_EVENT_LC_VM_FAULT_PAGE_EXCL_PAGER_NOT_READY,
	VMLP_EVENT_LC_VM_FAULT_COPY_BUSY_RETRY,
} vmlp_lock_contention_event_t;

static inline void
vm_lock_contention_event(
	vm_map_t map,
	scalable_counter_t *counter,
	vmlp_lock_contention_event_t eventid,
	vm_map_address_t start,
	vm_map_address_t end)
{
	/*
	 * We don't hold the interlock here, and we also don't use atomics to
	 * write to this bitfield, so it's theoretically possible for us to
	 * transiently read the wrong value of lock_contention_debug if one of
	 * the other bitfield members is being concurrently updated.
	 *
	 * However, this is unlikely to happen on platforms where stores are
	 * atomic, and this is only a debugging feature, so we avoid taking the
	 * lock here which can be potentially expensive in the fault path.
	 */
	if (map->lock_contention_debug) {
		counter_inc(counter);
		if (eventid != VMLP_EVENT_LC_NONE) {
			KDBG_RELEASE(VMLP_EVENTID(VM_LOCK_PERF_CONTENTION_EVENT, eventid, DBG_FUNC_NONE), map, start, end);
		}
	}
}

static inline void
vm_lock_contention_event_with_excl_ctx(
	vm_map_lock_ctx_t ctx,
	scalable_counter_t *counter,
	vmlp_lock_contention_event_t eventid)
{
	if (__improbable((ctx != NULL) && (ctx->__vmlc_flags & VMRL_EXCLUSIVE))) {
		vm_lock_contention_event(ctx->vmlc_map, counter, eventid, ctx->vmlc_req_start, ctx->vmlc_req_end);
	}
}

#if DEBUG || DEVELOPMENT

static inline void
vm_lock_contention_event_dev(
	vm_map_t map,
	scalable_counter_t *counter,
	vmlp_lock_contention_event_t eventid,
	vm_map_address_t start,
	vm_map_address_t end)
{
	vm_lock_contention_event(map, counter, eventid, start, end);
}

static inline void
vm_lock_contention_event_with_excl_ctx_dev(
	vm_map_lock_ctx_t ctx,
	scalable_counter_t *counter,
	vmlp_lock_contention_event_t eventid)
{
	vm_lock_contention_event_with_excl_ctx(ctx, counter, eventid);
}

#else

#define vm_lock_contention_event_dev(map, counter, eventid, start, end)
#define vm_lock_contention_event_with_excl_ctx_dev(ctx, counter, eventid)

#endif /* DEBUG || DEVELOPMENT */
