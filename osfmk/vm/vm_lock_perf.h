/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <sys/kdebug.h>

/* This should only be enabled at desk */
#define ENABLE_VM_LOCK_PERF 0

/*
 * The VM Lock Perf (VMLP) module uses ktrace to gather insights into the
 * performance profile of the VM subsystem, particularly as it pertains to
 * locking behavior.
 * We use the ktrace events, further subdividing the code field as below.
 * The "type" field indicates which type of VMLP event is being reported.
 * Currently supported types are API, Lock, and Range (see below).
 * The subcode is type-dependent.
 * DBG_MACH  VMLP  type subcode function
 * ╭──────┬───────┬────┬────────┬─╮
 * │  8   │   8   │  5 |   9    │2│
 * ╰──────┴───────┴────┴────────┴─╯
 */

#pragma mark VM Lock Performance Event IDs

typedef enum __enum_closed {
	VM_LOCK_PERF_API_EVENT = 1, /* Operations on map lock */
	VM_LOCK_PERF_LOCK_EVENT,   /* Function start/end */
	VM_LOCK_PERF_RANGE_EVENT,  /* Reporting a range */
	VM_LOCK_PERF_CONTENTION_EVENT, /* Abnormal lock contention */
} vmlp_event_type_t;

#define VMLP_CODE_TYPE_OFFSET (9)
#define VMLP_CODE_TYPE_MASK (0x1f)
#define VMLP_CODE_SUBCODE_OFFSET (0)
#define VMLP_CODE_SUBCODE_MASK (0x1ff)
#define VMLP_CODE(type, subcode) ((((type) & VMLP_CODE_TYPE_MASK) << VMLP_CODE_TYPE_OFFSET) | (((subcode) & VMLP_CODE_SUBCODE_MASK) << VMLP_CODE_SUBCODE_OFFSET))
#define VMLP_EVENTID(type, subcode, function) (MACHDBG_CODE(DBG_MACH_VM_LOCK_PERF, VMLP_CODE((type), (subcode))) | (function))

#pragma mark Subcodes for API events

#define VMLPAN(name) VMLP_EVENT_API_ ## name /* VM Perf API Name */

typedef enum __enum_closed {
	VMLPAN(FILL_PROCREGIONINFO) = 1,
	VMLPAN(FILL_PROCREGIONINFO_ONLYMAPPEDVNODES),
	VMLPAN(FIND_MAPPING_TO_SLIDE),
	VMLPAN(GET_VMMAP_ENTRIES),
	VMLPAN(GET_VMSUBMAP_ENTRIES), /* now unused; can be removed on next breaking change */
	VMLPAN(KDP_LIGHTWEIGHT_FAULT),
	VMLPAN(KMEM_ALLOC_GUARD_INTERNAL),
	VMLPAN(KMEM_FREE_GUARD),
	VMLPAN(KMEM_GET_GOBJ_STATS), /* now unused; can be removed on next breaking change */
	VMLPAN(KMEM_POPULATE_META_LOCKED),
	VMLPAN(KMEM_REALLOC_GUARD),
	VMLPAN(KMEM_SIZE_GUARD),
	VMLPAN(MACH_MAKE_MEMORY_ENTRY_SHARE),
	VMLPAN(MACH_VM_RANGE_CREATE_V1),
	VMLPAN(MOVE_PAGES_TO_QUEUE),
	VMLPAN(TASK_FIND_REGION_DETAILS),
	VMLPAN(TASK_INFO),
	VMLPAN(VM32_REGION_INFO),
	VMLPAN(VM32_REGION_INFO_64),
	VMLPAN(VM32__MAP_EXEC_LOCKDOWN),
	VMLPAN(VMTC_REVALIDATE_LOOKUP),
	VMLPAN(VM_FAULT_COPY),
	VMLPAN(VM_FAULT_INTERNAL),
	VMLPAN(VM_KERN_ALLOCATION_INFO),
	VMLPAN(VM_MAP_APPLE_PROTECTED),
	VMLPAN(VM_MAP_BEHAVIOR_SET),
	VMLPAN(VM_MAP_CAN_REUSE),
	VMLPAN(VM_MAP_CHECK_PROTECTION),
	VMLPAN(VM_MAP_COPYIN_INTERNAL),
	VMLPAN(VM_MAP_COPYOUT_INTERNAL),
	VMLPAN(VM_MAP_COPY_OVERWRITE),
	VMLPAN(VM_MAP_COPY_OVERWRITE_ALIGNED),
	VMLPAN(VM_MAP_COPY_OVERWRITE_IMPL),
	VMLPAN(VM_MAP_CREATE_UPL),
	VMLPAN(VM_MAP_CS_DEBUGGED_SET),
	VMLPAN(VM_MAP_CS_ENFORCEMENT_SET),
	VMLPAN(VM_MAP_DELETE_AND_IUNLOCK),
	VMLPAN(VM_MAP_DESTROY),
	VMLPAN(VM_MAP_DISCONNECT_PAGE_MAPPINGS),
	VMLPAN(VM_MAP_ENTER),
	VMLPAN(VM_MAP_ENTER_MEM_OBJECT),
	VMLPAN(VM_MAP_ENTRY_HAS_DEVICE_PAGER),
	VMLPAN(VM_MAP_EXEC_LOCKDOWN),
	VMLPAN(VM_MAP_FIND_SPACE),
	VMLPAN(VM_MAP_FORK),
	VMLPAN(VM_MAP_FORK_COPY),
	VMLPAN(VM_MAP_FREEZE),
	VMLPAN(VM_MAP_GET_PHYS_PAGE),
	VMLPAN(VM_MAP_INHERIT),
	VMLPAN(VM_MAP_INJECT_ERROR),
	VMLPAN(VM_MAP_IS_CORPSE_SOURCE),
	VMLPAN(VM_MAP_LOOKUP_AND_LOCK_OBJECT),
	VMLPAN(VM_MAP_MACHINE_ATTRIBUTE),
	VMLPAN(VM_MAP_MARK_ALIEN),
	VMLPAN(VM_MAP_MSYNC),
	VMLPAN(VM_MAP_PAGEOUT),
	VMLPAN(VM_MAP_PAGE_RANGE_INFO_INTERNAL),
	VMLPAN(VM_MAP_PARTIAL_REAP),
	VMLPAN(VM_MAP_PROTECT),
	VMLPAN(VM_MAP_PURGABLE_CONTROL),
	VMLPAN(VM_MAP_RAISE_MAX_OFFSET),
	VMLPAN(VM_MAP_RAISE_MIN_OFFSET),
	VMLPAN(VM_MAP_RANGE_CONFIGURE),
	VMLPAN(VM_MAP_REGION),
	VMLPAN(VM_MAP_REGION_RECURSE_64),
	VMLPAN(VM_MAP_REMAP),
	VMLPAN(VM_MAP_REMAP_EXTRACT),
	VMLPAN(VM_MAP_REMOVE_AND_IUNLOCK),
	VMLPAN(VM_MAP_REMOVE_GUARD),
	VMLPAN(VM_MAP_REUSABLE_PAGES),
	VMLPAN(VM_MAP_REUSE_PAGES),
	VMLPAN(VM_MAP_SET_CACHE_ATTR),
	VMLPAN(VM_MAP_SET_CORPSE_SOURCE),
	VMLPAN(VM_MAP_SET_DATA_LIMIT),
	VMLPAN(VM_MAP_SET_MAX_ADDR),
	VMLPAN(VM_MAP_SET_SIZE_LIMIT),
	VMLPAN(VM_MAP_SET_TPRO_ENFORCEMENT),
	VMLPAN(VM_MAP_SET_TPRO_RANGE),
	VMLPAN(VM_MAP_SET_USER_WIRE_LIMIT),
	VMLPAN(VM_MAP_SHADOW_MAX),
	VMLPAN(VM_MAP_SIGN),
	VMLPAN(VM_MAP_SIMPLIFY_RANGE),
	VMLPAN(VM_MAP_SINGLE_JIT),
	VMLPAN(VM_MAP_SIZES),
	VMLPAN(VM_MAP_SUBMAP_PMAP_CLEAN),
	VMLPAN(VM_MAP_SWITCH_PROTECT),
	VMLPAN(VM_MAP_TERMINATE),
	VMLPAN(VM_MAP_UNSET_CORPSE_SOURCE),
	VMLPAN(VM_MAP_UNWIRE_IMPL),
	VMLPAN(VM_MAP_WILLNEED),
	VMLPAN(VM_MAP_WIRE_IMPL),
	VMLPAN(VM_MAP_ZERO),
	VMLPAN(VM_SHARED_REGION_MAP_FILE),
	VMLPAN(VM_TOGGLE_ENTRY_REUSE),
	VMLPAN(ZONE_METADATA_INIT),
	VMLPAN(ZONE_SUBMAP_ALLOC_SEQUESTERED_VA),
	VMLPAN(VM_MAP_GUARD_OBJECT_CHUNK_UPDATE),
} vmlp_api_event_t;

#pragma mark Subcodes for Lock events

typedef enum __enum_closed {
	VMLP_EVENT_LOCK_TRY_EXCL = 1,
	VMLP_EVENT_LOCK_FAIL_EXCL,
	VMLP_EVENT_LOCK_REQ_EXCL,
	VMLP_EVENT_LOCK_GOT_EXCL,
	VMLP_EVENT_LOCK_UNLOCK_EXCL,
	VMLP_EVENT_LOCK_DOWNGRADE,
	VMLP_EVENT_LOCK_TRY_SH,
	VMLP_EVENT_LOCK_FAIL_SH,
	VMLP_EVENT_LOCK_REQ_SH,
	VMLP_EVENT_LOCK_GOT_SH,
	VMLP_EVENT_LOCK_UNLOCK_SH,
	VMLP_EVENT_LOCK_TRY_UPGRADE,
	VMLP_EVENT_LOCK_GOT_UPGRADE,
	VMLP_EVENT_LOCK_FAIL_UPGRADE,
	VMLP_EVENT_LOCK_SLEEP_BEGIN,
	VMLP_EVENT_LOCK_SLEEP_END,
	VMLP_EVENT_LOCK_YIELD_BEGIN,
	VMLP_EVENT_LOCK_YIELD_END,
} vmlp_lock_event_t;

#pragma mark Subcodes for Range events

typedef enum __enum_closed {
	VMLP_EVENT_RANGE = 1,
} vmlp_range_event_t;

/*
 * vmlp_* function calls do nothing under normal circumstances...
 * If we ever change this behavior we need to reconsider whether DBG_MACH is
 * the right class to be a subclass of given that it is enabled entirely in
 * default traces.
 */
#if !ENABLE_VM_LOCK_PERF

#define vmlp_lock_event_unlocked(event, map)
#define vmlp_lock_event_locked(event, map)
#define vmlp_api_start(func)
#define vmlp_api_end(func, kr)
#define vmlp_range_event(map, addr, size)
#define vmlp_range_event_entry(map, entry)
#define vmlp_range_event_none(map)
#define vmlp_range_event_all(map)

#else /* ...but when the module is enabled they emit tracepoints */

#pragma mark Debug infra

/*
 * Use stack counters to debug extra or missing end annotations.
 * Should only be turned on while debugging annotations.
 */
#define VMLP_DEBUG_COUNTERS 0

#if VMLP_DEBUG_COUNTERS
static inline void
__vmlp_debug_counter_check(int *__vmlp_debug_counter)
{
	if (1 != *__vmlp_debug_counter) {
		panic("vmlp_api_end was run %d times in this function (expected 1).", *__vmlp_debug_counter);
	}
}
#define VMLP_DEBUG_COUNTER_DECLARE int __vmlp_debug_counter __attribute__((cleanup(__vmlp_debug_counter_check))) = 0
#define VMLP_DEBUG_COUNTER_UPDATE __vmlp_debug_counter++
#else
#define VMLP_DEBUG_COUNTER_DECLARE
#define VMLP_DEBUG_COUNTER_UPDATE
#endif

#pragma mark API events

static inline void
__vmlp_api_start(vmlp_api_event_t api)
{
	(void)api;
	KDBG(VMLP_EVENTID(VM_LOCK_PERF_API_EVENT, api, DBG_FUNC_START));
}
#define vmlp_api_start(func) VMLP_DEBUG_COUNTER_DECLARE;                       \
	__vmlp_api_start(VMLPAN(func));

static inline void
__vmlp_api_end(vmlp_api_event_t api, uint64_t kr)
{
	(void)api, (void)kr;
	KDBG(VMLP_EVENTID(VM_LOCK_PERF_API_EVENT, api, DBG_FUNC_END), kr);
}
/*
 * Note that post-processing will treat any non-zero kr as failure, so annotate
 * accordingly when APIs do not return a kern_return_t.
 */
#define vmlp_api_end(func, kr) do {                                            \
	VMLP_DEBUG_COUNTER_UPDATE;                                             \
	__vmlp_api_end(VMLPAN(func), kr);                                      \
} while (0)

#pragma mark Lock events

static inline void
__vmlp_lock_event(vmlp_lock_event_t event, vm_map_t map, uint64_t timestamp)
{
	(void)event, (void)map, (void)timestamp;
	KDBG(VMLP_EVENTID(VM_LOCK_PERF_LOCK_EVENT, event, DBG_FUNC_NONE), map, timestamp);
}
static inline void
vmlp_lock_event_unlocked(vmlp_lock_event_t event, vm_map_t map)
{
	/*
	 * If we don't hold a lock on the map it's not safe to access the
	 * timestamp. Pass 0 as placeholder.
	 */
	__vmlp_lock_event(event, map, 0);
}
/*
 * Map timestamps get incremented at unlock time. Care should be taken to
 * position this annotation before the timestamp increase.
 */
static inline void
vmlp_lock_event_locked(vmlp_lock_event_t event, vm_map_t map)
{
	/*
	 * Postprocessing can use the map timestamp to reorder events that are
	 * causally related but end up having the same ktrace-timestamp and
	 * showing up in reverse order because they occured on different CPUs.
	 */
	__vmlp_lock_event(event, map, map->unlink_timestamp);
}

#pragma mark Range events

static inline void
vmlp_range_event(vm_map_t map, mach_vm_address_t addr, mach_vm_size_t size)
{
	(void)map, (void)addr, (void)size;
	KDBG(VMLP_EVENTID(VM_LOCK_PERF_RANGE_EVENT, VMLP_EVENT_RANGE, DBG_FUNC_NONE), map, map->unlink_timestamp, addr, size);
}

static inline void
vmlp_range_event_entry(vm_map_t map, vm_map_entry_t entry)
{
	vmlp_range_event(map, entry->vme_start, entry->vme_end - entry->vme_start);
}

static inline void
vmlp_range_event_none(vm_map_t map)
{
	vmlp_range_event(map, 0, 0);
}

static inline void
vmlp_range_event_all(vm_map_t map)
{
	vmlp_range_event(map, 0, 0xffffffffffffffff);
}

#endif /* !ENABLE_VM_LOCK_PERF */
