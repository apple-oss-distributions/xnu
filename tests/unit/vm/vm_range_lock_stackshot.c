/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#define UT_MODULE osfmk

#include <darwintest.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/mock_mem.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_thread.h"
#include <vm/vm_stackshot_utils_xnu.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_test_utils_internal.h>
#include <kern/thread.h>
#include <kern/debug.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm_range_lock_stackshot_146077971"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("tgal2"),
	T_META_RUN_CONCURRENTLY(true)
	);

extern int
__vmrl_stackshot_collect_waiter_info(thread_t waiter_thread, struct stackshot_vmrl_state *state);

extern void
__vmrl_stackshot_collect_owner_info(thread_t owner_thread, struct stackshot_vmrl_state *state);

extern uint32_t
vmrl_stackshot_collect_final_blocking_rels(
	struct stackshot_vmrl_state *state);

static void
setup_vm_prerequisites_for_waiter(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t entry,
	unsigned long map_size,
	unsigned long entry_start,
	unsigned long entry_end,
	int read_count
	)
{
	not_in_kdp = 0;
	entry->vme_start = entry_start;
	entry->vme_end = entry_end;
	entry->vme_lock.vmel_read_count = read_count;
	entry->vme_lock.vmel_valid = true;

	if (!read_count) { /* If there are no readers and we are blocked -> excl owner */
		entry->vme_lock.vmel_excl_locked = 1;
	}

	vm_map_t map = vm_test_alloc_map();
	map->size = map_size;

	ctx->vmlc_map = map;
	ctx->vmlc_vme = entry;
}

static void
setup_vm_and_ctx_for_blocker(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t entry,
	unsigned long map_size,
	unsigned long start, unsigned long end,
	vmrl_flags_t ctx_flags
	)
{
	vm_map_t map = vm_test_alloc_map();
	map->size = map_size;

	ctx->__vmlc_flags = ctx_flags;
	if (vmrl_is_streaming(ctx)) {
		entry->vme_start = start;
		entry->vme_end = end;
		ctx->vmlc_vme = entry;
	} else {
		ctx->__vmlc_atomic.locked_range_start = start;
		ctx->__vmlc_atomic.locked_range_end = end;
	}

	ctx->vmlc_map = map;
}

static void
setup_thread_wait_state(
	thread_t thread,
	vm_map_lock_ctx_t ctx_held_by_thread,
	vm_map_entry_t entry,
	uint64_t thread_id,
	uint32_t block_hint)
{
	uint32_t delta = block_hint + 1 - kThreadWaitVMEntryExclEvent;
	thread->thread_id = thread_id;
	thread->vm_map_lock_ctx_held = ctx_held_by_thread;
	thread->block_hint = block_hint;
	thread->wait_event = (event64_t)(CAST_EVENT64_T(&entry->vme_lock) + delta);
}

static void
setup_blocker_thread_state(
	thread_t thread,
	vm_map_lock_ctx_t ctx_held_by_thread,
	uint64_t thread_id)
{
	thread->thread_id = thread_id;
	thread->vm_map_lock_ctx_held = ctx_held_by_thread;
}

T_DECL(test_waitinfo_collection_shared, "test collecting info for a shared lock waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[STACKSHOT_VMRL_MAX_WAITERS];
	state.waiters = waiters;
	struct vm_map_entry entry;
	struct thread waiter_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	unsigned long   map_size              = 0xABCD;
	unsigned long   entry_start           = 0x4000;
	unsigned long   entry_end             = 0x8000;
	int             read_count            = 0;
	uint64_t        thread_id             = 0x5678;
	uint32_t        block_hint            = kThreadWaitVMEntrySharedEvent;
	uint32_t        expected_flags        = 0x1;
	int             expected_num_blockers = 1;

	setup_vm_prerequisites_for_waiter(ctx, &entry, map_size, entry_start, entry_end, read_count);
	setup_thread_wait_state(&waiter_thread, ctx, &entry, thread_id, block_hint);

	__vmrl_stackshot_collect_waiter_info(&waiter_thread, &state);

	T_ASSERT_EQ(os_atomic_load(&state.num_waiters, relaxed), 1U, "num_vmrl_waiters should be 1");
	T_ASSERT_EQ((int)state.waiters[0].waiter_tid, (int)thread_id, "waiter_tid");
	T_ASSERT_EQ(state.waiters[0].map->size, (unsigned long long)map_size, "waiter_map_size");
	T_ASSERT_EQ(state.waiters[0].start, (unsigned long)entry_start, "waiter_start");
	T_ASSERT_EQ(state.waiters[0].end, (unsigned long)entry_end, "waiter_end");
	T_ASSERT_EQ(state.waiters[0].flags, expected_flags, "waiter_flags");
	T_ASSERT_EQ((int)state.waiters[0].num_blockers, expected_num_blockers, "waiter_num_blockers");
	T_LOG("waiter->entry_hash: %llx", state.waiters[0].entry_hash);
}

T_DECL(test_waitinfo_collection_exclusive_lock, "test collecting info for an exclusive lock waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[STACKSHOT_VMRL_MAX_WAITERS];
	state.waiters = waiters;
	struct vm_map_entry entry;
	struct thread waiter_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	unsigned long   map_size              = 0xABCD;
	unsigned long   entry_start           = 0x4000;
	unsigned long   entry_end             = 0x8000;
	int             read_count            = 0;
	uint64_t        thread_id             = 0x5678;
	uint32_t        block_hint            = kThreadWaitVMEntryExclEvent;
	uint32_t        expected_flags        = 0x4;
	int             expected_num_blockers = 1;

	setup_vm_prerequisites_for_waiter(ctx, &entry, map_size, entry_start, entry_end, read_count);
	setup_thread_wait_state(&waiter_thread, ctx, &entry, thread_id, block_hint);

	__vmrl_stackshot_collect_waiter_info(&waiter_thread, &state);

	T_ASSERT_EQ(os_atomic_load(&state.num_waiters, relaxed), 1U, "num_vmrl_waiters should be 1");
	T_ASSERT_EQ((int)state.waiters[0].waiter_tid, (int)thread_id, "waiter_tid");
	T_ASSERT_EQ(state.waiters[0].map->size, (unsigned long long)map_size, "waiter_map_size");
	T_ASSERT_EQ(state.waiters[0].start, (unsigned long)entry_start, "waiter_start");
	T_ASSERT_EQ(state.waiters[0].end, (unsigned long)entry_end, "waiter_end");
	T_ASSERT_EQ(state.waiters[0].flags, expected_flags, "waiter_flags");
	T_ASSERT_EQ((int)state.waiters[0].num_blockers, expected_num_blockers, "waiter_num_blockers");
}

T_DECL(test_waitinfo_collection_exclusive_lock_w_reader_owners, "test collecting info for an exclusive lock waiter, waiting for shared owners")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[STACKSHOT_VMRL_MAX_WAITERS];
	state.waiters = waiters;
	struct vm_map_entry entry;
	struct thread waiter_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	unsigned long   map_size              = 0xABCD;
	unsigned long   entry_start           = 0x4000;
	unsigned long   entry_end             = 0x8000;
	int             read_count            = 0x123;
	uint64_t        thread_id             = 0x5678;
	uint32_t        block_hint            = kThreadWaitVMEntryExclEvent;
	uint32_t        expected_flags        = 0x4;
	int             expected_num_blockers = read_count;

	setup_vm_prerequisites_for_waiter(ctx, &entry, map_size, entry_start, entry_end, read_count);
	setup_thread_wait_state(&waiter_thread, ctx, &entry, thread_id, block_hint);

	__vmrl_stackshot_collect_waiter_info(&waiter_thread, &state);

	T_ASSERT_EQ(os_atomic_load(&state.num_waiters, relaxed), 1U, "num_vmrl_waiters should be 1");
	T_ASSERT_EQ((int)state.waiters[0].waiter_tid, (int)thread_id, "waiter_tid");
	T_ASSERT_EQ(state.waiters[0].map->size, (unsigned long long)map_size, "waiter_map_size");
	T_ASSERT_EQ(state.waiters[0].start, (unsigned long)entry_start, "waiter_start");
	T_ASSERT_EQ(state.waiters[0].end, (unsigned long)entry_end, "waiter_end");
	T_ASSERT_EQ(state.waiters[0].flags, expected_flags, "waiter_flags");
	T_ASSERT_EQ((int)state.waiters[0].num_blockers, expected_num_blockers, "waiter_num_blockers");
}

T_DECL(test_waitinfo_no_vm_lock_ctx_held, "test thread not holding any vm_map_lock_ctx")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[STACKSHOT_VMRL_MAX_WAITERS];
	state.waiters = waiters;
	struct thread waiter_thread = {0};

	waiter_thread.thread_id = 0x9ABC;
	waiter_thread.vm_map_lock_ctx_held = NULL;
	waiter_thread.block_hint = kThreadWaitVMEntrySharedEvent;
	waiter_thread.wait_event = 0;

	T_ASSERT_EQ(__vmrl_stackshot_collect_waiter_info(&waiter_thread, &state), -1, "should return with -1 because thread->ctx is NULL");
}

T_DECL(test_blockinfo_exclusive_atomic_blocker, "blocker is exclusive, atomic mode")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_OWNERS];
	state.owners = owners;
	struct vm_map_entry entry; // A vm_map_entry struct for the ctx
	struct thread owner_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	unsigned long   map_size            = 0xCAFE;
	unsigned long   range_start         = 0xA000; // This will be the atomic range
	unsigned long   range_end           = 0xD000;
	uint64_t        thread_id           = 0xBAD0;
	vmrl_flags_t    setup_ctx_flags     = VMRL_EXCLUSIVE | _VMRL_ATOMIC_INTERNAL;

	uint32_t        expected_flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE | STACKSHOT_BLOCKER_VMRL_ATOMIC;

	setup_vm_and_ctx_for_blocker(ctx, &entry, map_size, range_start, range_end, setup_ctx_flags);
	setup_blocker_thread_state(&owner_thread, ctx, thread_id);

	ctx->__vmlc_locked = 1;
	__vmrl_stackshot_collect_owner_info(&owner_thread, &state);
	ctx->__vmlc_locked = 0;

	T_ASSERT_EQ(os_atomic_load(&state.num_owners, relaxed), 1U, "num_vmrl_owners (=1)");
	T_ASSERT_EQ((int)state.owners[0].owner_tid, (int)thread_id, "blocker_tid");
	T_ASSERT_EQ(state.owners[0].map->size, (unsigned long long)map_size, "map_size");
	T_ASSERT_EQ(state.owners[0].start, (vm_offset_t)range_start, "blocker_start");
	T_ASSERT_EQ(state.owners[0].end, (vm_offset_t)range_end, "blocker_end");
	T_ASSERT_EQ(state.owners[0].flags, expected_flags, "blocker_flags");
}

T_DECL(test_blockinfo_shared_streaming_blocker, "blocker is shared, streaming mode")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_OWNERS];
	state.owners = owners;
	struct vm_map_entry entry; /* This will be the streaming entry */
	struct thread owner_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	unsigned long   map_size              = 0xF00D;
	unsigned long   range_start           = 0x5000; // This will be the streaming entry's range
	unsigned long   range_end             = 0x6000;
	uint64_t        thread_id             = 0xFEED;
	vmrl_flags_t    setup_ctx_flags       = VMRL_SHARED | _VMRL_STREAM_INTERNAL;

	uint32_t        expected_flags = STACKSHOT_BLOCKER_VMRL_SHARED | STACKSHOT_BLOCKER_VMRL_STREAMING;

	setup_vm_and_ctx_for_blocker(ctx, &entry, map_size, range_start, range_end, setup_ctx_flags);
	setup_blocker_thread_state(&owner_thread, ctx, thread_id);

	ctx->__vmlc_locked = 1;
	__vmrl_stackshot_collect_owner_info(&owner_thread, &state);
	ctx->__vmlc_locked = 0;

	T_ASSERT_EQ(os_atomic_load(&state.num_owners, relaxed), 1U, "num_vmrl_owners (=1)");
	T_ASSERT_EQ((int)state.owners[0].owner_tid, (int)thread_id, "blocker_tid");
	T_ASSERT_EQ(state.owners[0].map->size, (unsigned long long)map_size, "map_size");
	T_ASSERT_EQ(state.owners[0].start, (vm_offset_t)range_start, "blocker_start");
	T_ASSERT_EQ(state.owners[0].end, (vm_offset_t)range_end, "blocker_end");
	T_ASSERT_EQ(state.owners[0].flags, expected_flags, "blocker_flags");
}

T_DECL(test_blockinfo_exclusive_and_atomic_flags_blocker, "blocker exclusive, atomic flags")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_OWNERS];
	state.owners = owners;
	struct vm_map_entry entry; // This will be the streaming entry
	struct thread owner_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	unsigned long   map_size         = 0xBEEF;
	unsigned long   start            = 0x5000;
	unsigned long   end              = 0x6000;
	uint64_t        thread_id        = 0xFACE;
	vmrl_flags_t    ctx_flags  = VMRL_EXCLUSIVE | _VMRL_ATOMIC_INTERNAL;

	uint32_t        expected_flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE | STACKSHOT_BLOCKER_VMRL_ATOMIC;
	vm_offset_t     expected_start_range = start;
	vm_offset_t     expected_end_range   = end;

	setup_vm_and_ctx_for_blocker(ctx, &entry, map_size, start, end, ctx_flags);
	setup_blocker_thread_state(&owner_thread, ctx, thread_id);

	ctx->__vmlc_locked = 1;
	__vmrl_stackshot_collect_owner_info(&owner_thread, &state);
	ctx->__vmlc_locked = 0;

	T_ASSERT_EQ(os_atomic_load(&state.num_owners, relaxed), 1U, "num_vmrl_owners (=1)");
	T_ASSERT_EQ((int)state.owners[0].owner_tid, (int)thread_id, "blocker_tid");
	T_ASSERT_EQ(state.owners[0].map->size, (unsigned long long)map_size, "map_size");
	T_ASSERT_EQ(state.owners[0].start, (vm_offset_t)start, "blocker_start");
	T_ASSERT_EQ(state.owners[0].end, (vm_offset_t)end, "blocker_end");
	T_ASSERT_EQ(state.owners[0].flags, expected_flags, "blocker_flags");
}

T_DECL(test_blockinfo_collection_max_blockers_reached, "blockinfo collection stops if max count reached")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_OWNERS];
	state.owners = owners;
	os_atomic_store(&state.num_owners, STACKSHOT_VMRL_MAX_OWNERS, relaxed);
	struct vm_map_entry entry;
	struct thread owner_thread = {0};
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	setup_vm_and_ctx_for_blocker(ctx, &entry, 0x1, 0x1, 0x2, VMRL_SHARED | _VMRL_ATOMIC_INTERNAL);
	setup_blocker_thread_state(&owner_thread, ctx, 0x1);

	__vmrl_stackshot_collect_owner_info(&owner_thread, &state);

	T_ASSERT_EQ(os_atomic_load(&state.num_owners, relaxed), (uint32_t)STACKSHOT_VMRL_MAX_OWNERS, NULL);
}

T_DECL(test_blockinfo_no_vm_lock_ctx_held, "blockinfo collection panics if thread has no ctx")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_OWNERS];
	state.owners = owners;
	struct thread owner_thread = {0};
	owner_thread.thread_id = 0xBEEF;
	owner_thread.vm_map_lock_ctx_held = NULL;

	T_ASSERT_PANIC({
		__vmrl_stackshot_collect_owner_info(&owner_thread, &state);
	}, NULL);
}

T_DECL(test_collect_final_vmrl_blocking_rels, "test collecting final blocking relationships")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[1];
	thread_vmrl_owner_info_t owners[1];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 1, relaxed);
	os_atomic_store(&state.num_owners, 1, relaxed);

	// Initialize rels array to ensure no stale data
	memset(state.relationships, 0, sizeof(state.relationships));

	// Scenario parameters
	uint64_t waiter_tid = 0x1000;
	uint64_t blocker_tid = 0x2000;
	unsigned long map_size = 0x10000;
	unsigned long waiter_start = 0x20000;
	unsigned long waiter_end = 0x30000;
	unsigned long blocker_start = 0x10000; // Blocker range contains waiter range
	unsigned long blocker_end = 0x40000;
	uint32_t waiter_flags = STACKSHOT_WAITER_VMRL_SHARED; // (we don't care about atomic vs streaming at this point)
	uint32_t blocker_flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE; // (we don't care about atomic vs streaming at this point)
	uint64_t entry_hash = 0xABCDEF;
	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	// Setup waiter info
	waiters[0].waiter_tid = waiter_tid;
	waiters[0].map = test_map;
	waiters[0].start = waiter_start;
	waiters[0].end = waiter_end;
	waiters[0].flags = waiter_flags;
	waiters[0].num_blockers = 1;
	waiters[0].entry_hash = entry_hash;

	// Setup blocker info
	owners[0].owner_tid = blocker_tid;
	owners[0].map = test_map;
	owners[0].start = blocker_start;
	owners[0].end = blocker_end;
	owners[0].flags = blocker_flags;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, 1U, "Should find 1 relationship");
	T_ASSERT_EQ(state.relationships[0].waiter_tid, waiter_tid, "rels[0].waiter_tid should match waiter_tid");
	T_ASSERT_EQ(state.relationships[0].blocker_tid, blocker_tid, "rels[0].blocker_tid should match blocker_tid");
	T_ASSERT_EQ(state.relationships[0].entry_hash, entry_hash, "rels[0].entry_hash should match entry_hash");
	T_ASSERT_EQ(state.relationships[0].flags, waiter_flags | blocker_flags, "rels[0].flags should match waiter_flags | blocker_flags");

	// Verify that no other relationships were found (i.e., only one was added)
	T_ASSERT_EQ(state.relationships[1].waiter_tid, 0ULL, "rels[1].waiter_tid should be 0 (no second relationship)");
	T_ASSERT_EQ(state.relationships[1].blocker_tid, 0ULL, "rels[1].blocker_tid should be 0 (no second relationship)");
}

T_DECL(test_collect_final_vmrl_blocking_rels_no_overlap, "test no blocking relationship if no range overlap")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[1];
	thread_vmrl_owner_info_t owners[1];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 1, relaxed);
	os_atomic_store(&state.num_owners, 1, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t waiter_tid = 0x1000;
	uint64_t blocker_tid = 0x2000;
	unsigned long map_size = 0x10000;
	unsigned long waiter_start = 0x5000;
	unsigned long waiter_end = 0x6000;
	unsigned long blocker_start = 0x1000; // No overlap with waiter_start/end
	unsigned long blocker_end = 0x2000;
	uint32_t waiter_flags = STACKSHOT_WAITER_VMRL_SHARED;
	uint32_t blocker_flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE;
	uint64_t entry_hash = 0xABCDEF;

	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	waiters[0].waiter_tid = waiter_tid;
	waiters[0].map = test_map;
	waiters[0].start = waiter_start;
	waiters[0].end = waiter_end;
	waiters[0].flags = waiter_flags;
	waiters[0].num_blockers = 1; // Still expect 1 potential blocker, but is_range_owner will filter it
	waiters[0].entry_hash = entry_hash;

	owners[0].owner_tid = blocker_tid;
	owners[0].map = test_map;
	owners[0].start = blocker_start;
	owners[0].end = blocker_end;
	owners[0].flags = blocker_flags;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, 0U, "Should find 0 relationships");
	// Assert that no relationships were found
	T_ASSERT_EQ(state.relationships[0].waiter_tid, 0ULL, "rels[0].waiter_tid should be 0 (no relationship found)");
	T_ASSERT_EQ(state.relationships[0].blocker_tid, 0ULL, "rels[0].blocker_tid should be 0 (no relationship found)");
}

T_DECL(test_collect_final_vmrl_blocking_rels_shared_blocker_shared_waiter, "test shared blocker does not block shared waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[1];
	thread_vmrl_owner_info_t owners[1];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 1, relaxed);
	os_atomic_store(&state.num_owners, 1, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t waiter_tid = 0x1000;
	uint64_t blocker_tid = 0x2000;
	unsigned long map_size = 0x10000;
	unsigned long waiter_start = 0x2000;
	unsigned long waiter_end = 0x3000;
	unsigned long blocker_start = 0x1000; // Overlap exists
	unsigned long blocker_end = 0x4000;
	uint32_t waiter_flags = STACKSHOT_WAITER_VMRL_SHARED; // Shared waiter
	uint32_t blocker_flags = STACKSHOT_BLOCKER_VMRL_SHARED; // Shared blocker
	uint64_t entry_hash = 0xABCDEF;

	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	waiters[0].waiter_tid = waiter_tid;
	waiters[0].map = test_map;
	waiters[0].start = waiter_start;
	waiters[0].end = waiter_end;
	waiters[0].flags = waiter_flags;
	waiters[0].num_blockers = 1;
	waiters[0].entry_hash = entry_hash;

	owners[0].owner_tid = blocker_tid;
	owners[0].map = test_map;
	owners[0].start = blocker_start;
	owners[0].end = blocker_end;
	owners[0].flags = blocker_flags;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, 0U, "Should find 0 relationships");
	// Assert that no relationships were found due to shared-on-shared rule
	T_ASSERT_EQ(state.relationships[0].waiter_tid, 0ULL, "rels[0].waiter_tid should be 0 (no relationship found)");
	T_ASSERT_EQ(state.relationships[0].blocker_tid, 0ULL, "rels[0].blocker_tid should be 0 (no relationship found)");
}

T_DECL(test_collect_final_vmrl_blocking_rels_shared_blocker_exclusive_waiter, "test shared blocker blocks exclusive waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[1];
	thread_vmrl_owner_info_t owners[1];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 1, relaxed);
	os_atomic_store(&state.num_owners, 1, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t waiter_tid = 0x1000;
	uint64_t blocker_tid = 0x2000;
	unsigned long map_size = 0x10000;
	unsigned long waiter_start = 0x2000;
	unsigned long waiter_end = 0x3000;
	unsigned long blocker_start = 0x1000; // Overlap exists
	unsigned long blocker_end = 0x4000;
	uint32_t waiter_flags = STACKSHOT_WAITER_VMRL_EXCLUSIVE;
	uint32_t blocker_flags = STACKSHOT_BLOCKER_VMRL_SHARED;
	uint64_t entry_hash = 0xABCDEF;

	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	waiters[0].waiter_tid = waiter_tid;
	waiters[0].map = test_map;
	waiters[0].start = waiter_start;
	waiters[0].end = waiter_end;
	waiters[0].flags = waiter_flags;
	waiters[0].num_blockers = 1;
	waiters[0].entry_hash = entry_hash;

	owners[0].owner_tid = blocker_tid;
	owners[0].map = test_map;
	owners[0].start = blocker_start;
	owners[0].end = blocker_end;
	owners[0].flags = blocker_flags;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, 1U, "Should find 1 relationship");
	T_ASSERT_EQ(state.relationships[0].waiter_tid, waiter_tid, "rels[0].waiter_tid should match waiter_tid");
	T_ASSERT_EQ(state.relationships[0].blocker_tid, blocker_tid, "rels[0].blocker_tid should match blocker_tid");
	T_ASSERT_EQ(state.relationships[0].entry_hash, entry_hash, "rels[0].entry_hash should match entry_hash");
	T_ASSERT_EQ(state.relationships[0].flags, waiter_flags | blocker_flags, "rels[0].flags should match waiter_flags | blocker_flags");

	T_ASSERT_EQ(state.relationships[1].waiter_tid, 0ULL, "rels[1].waiter_tid should be 0 (no second relationship)");
}

T_DECL(test_collect_final_vmrl_blocking_rels_multiple_blockers, "test multiple blockers for a single waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[1];
	thread_vmrl_owner_info_t owners[2];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 1, relaxed);
	os_atomic_store(&state.num_owners, 2, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t waiter_tid = 0x1000;
	uint64_t blocker1_tid = 0x2000;
	uint64_t blocker2_tid = 0x3000;
	unsigned long map_size = 0x10000;
	unsigned long waiter_start = 0x2000;
	unsigned long waiter_end = 0x3000;
	uint64_t entry_hash = 0xABCDEF;

	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	// Setup waiter info
	waiters[0].waiter_tid = waiter_tid;
	waiters[0].map = test_map;
	waiters[0].start = waiter_start;
	waiters[0].end = waiter_end;
	waiters[0].flags = STACKSHOT_WAITER_VMRL_SHARED;
	waiters[0].num_blockers = 2;
	waiters[0].entry_hash = entry_hash;

	// Setup blocker 1 (exclusive, overlaps)
	owners[0].owner_tid = blocker1_tid;
	owners[0].map = test_map;
	owners[0].start = 0x1000;
	owners[0].end = 0x2500; // Partial overlap
	owners[0].flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE;

	// Setup blocker 2 (exclusive, overlaps)
	owners[1].owner_tid = blocker2_tid;
	owners[1].map = test_map;
	owners[1].start = 0x2800;
	owners[1].end = 0x4000; // Partial overlap
	owners[1].flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, 2U, "Should find 2 relationships");
	T_ASSERT_EQ(state.relationships[0].waiter_tid, waiter_tid, "rels[0].waiter_tid should match waiter_tid");
	T_ASSERT_EQ(state.relationships[0].blocker_tid, blocker1_tid, "rels[0].blocker_tid should match blocker1_tid");
	T_ASSERT_EQ(state.relationships[0].entry_hash, entry_hash, "rels[0].entry_hash should match entry_hash");
	T_ASSERT_EQ(state.relationships[0].flags, STACKSHOT_WAITER_VMRL_SHARED | STACKSHOT_BLOCKER_VMRL_EXCLUSIVE, "rels[0].flags should match waiter_flags | blocker_flags");

	T_ASSERT_EQ(state.relationships[1].waiter_tid, waiter_tid, "rels[1].waiter_tid should match waiter_tid");
	T_ASSERT_EQ(state.relationships[1].blocker_tid, blocker2_tid, "rels[1].blocker_tid should match blocker2_tid");
	T_ASSERT_EQ(state.relationships[1].entry_hash, entry_hash, "rels[1].entry_hash should match entry_hash");
	T_ASSERT_EQ(state.relationships[1].flags, STACKSHOT_WAITER_VMRL_SHARED | STACKSHOT_BLOCKER_VMRL_EXCLUSIVE, "rels[1].flags should match waiter_flags | blocker_flags");

	T_ASSERT_EQ(state.relationships[2].waiter_tid, 0ULL, "rels[2].waiter_tid should be 0 (no third relationship)");
}

T_DECL(test_collect_final_vmrl_blocking_rels_two_waiters_two_blockers, "test two waiters each blocked by one owner on different maps")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[2];
	thread_vmrl_owner_info_t owners[2];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 2, relaxed);
	os_atomic_store(&state.num_owners, 2, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t waiter1_tid = 4292;
	uint64_t waiter2_tid = 4374;
	uint64_t blocker1_tid = 4313;
	uint64_t blocker2_tid = 4373;
	unsigned long waiter1_start = 0x00000001026c4000;
	unsigned long waiter1_end = 0x00000001026d4000;
	unsigned long waiter2_start = 0x0000000102f54000;
	unsigned long waiter2_end = 0x0000000102f58000;
	unsigned long blocker1_start = 0x00000001026c4000;
	unsigned long blocker1_end = 0x0000000102704000;
	unsigned long blocker2_start = 0x0000000102f54000;
	unsigned long blocker2_end = 0x0000000102f58000;

	vm_map_t test_map1 = vm_test_alloc_map();
	vm_map_t test_map2 = vm_test_alloc_map();

	waiters[0].waiter_tid = waiter1_tid;
	waiters[0].map = test_map1;
	waiters[0].start = waiter1_start;
	waiters[0].end = waiter1_end;
	waiters[0].flags = 68;
	waiters[0].num_blockers = 1;

	waiters[1].waiter_tid = waiter2_tid;
	waiters[1].map = test_map2;
	waiters[1].start = waiter2_start;
	waiters[1].end = waiter2_end;
	waiters[1].flags = 65;
	waiters[1].num_blockers = 1;

	owners[0].owner_tid = blocker1_tid;
	owners[0].map = test_map1;
	owners[0].start = blocker1_start;
	owners[0].end = blocker1_end;
	owners[0].flags = 130;

	owners[1].owner_tid = blocker2_tid;
	owners[1].map = test_map2;
	owners[1].start = blocker2_start;
	owners[1].end = blocker2_end;
	owners[1].flags = 136;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, 2U, "Should find 2 relationships");
	T_ASSERT_EQ(state.relationships[0].waiter_tid, waiter1_tid, "rels[0].waiter_tid should match waiter1_tid");
	T_ASSERT_EQ(state.relationships[0].blocker_tid, blocker1_tid, "rels[0].blocker_tid should match blocker1_tid");

	T_ASSERT_EQ(state.relationships[1].waiter_tid, waiter2_tid, "rels[1].waiter_tid should match waiter2_tid");
	T_ASSERT_EQ(state.relationships[1].blocker_tid, blocker2_tid, "rels[1].blocker_tid should match blocker2_tid");

	T_ASSERT_EQ(state.relationships[2].waiter_tid, 0ULL, "rels[2].waiter_tid should be 0 (no third relationship)");
}

T_DECL(test_collect_final_vmrl_blocking_rels_max_rels_limit, "test max relationships limit")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[1];
	// Create more potential blockers than STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS for a single waiter
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS + 1];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 1, relaxed);
	os_atomic_store(&state.num_owners, STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS + 1, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t waiter_tid = 0x1000;
	unsigned long map_size = 0x10000;
	unsigned long waiter_start = 0x2000;
	unsigned long waiter_end = 0x3000;
	uint64_t entry_hash = 0xABCDEF;

	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	// Setup waiter info
	waiters[0].waiter_tid = waiter_tid;
	waiters[0].map = test_map;
	waiters[0].start = waiter_start;
	waiters[0].end = waiter_end;
	waiters[0].flags = STACKSHOT_WAITER_VMRL_SHARED;
	waiters[0].num_blockers = STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS + 1; // Expecting more blockers than we can store
	waiters[0].entry_hash = entry_hash;

	// Setup blockers (all exclusive, all overlap)
	for (size_t i = 0; i < STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS + 1; ++i) {
		owners[i].owner_tid = 0x2000 + i;
		owners[i].map = test_map;
		owners[i].start = 0x1000;
		owners[i].end = 0x4000;
		owners[i].flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE;
	}

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	T_ASSERT_EQ(num_rels, (uint32_t)STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS, "Should find max relationships");
	for (size_t i = 0; i < STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS; ++i) {
		T_QUIET; T_ASSERT_EQ(state.relationships[i].waiter_tid, waiter_tid, "rels[%zu].waiter_tid should match waiter_tid", i);
		T_QUIET; T_ASSERT_EQ(state.relationships[i].blocker_tid, (unsigned long long)(0x2000 + i), "rels[%zu].blocker_tid should match blocker_tid", i);
		T_QUIET; T_ASSERT_EQ(state.relationships[i].entry_hash, entry_hash, "rels[%zu].entry_hash should match entry_hash", i);
		T_QUIET; T_ASSERT_EQ(state.relationships[i].flags, STACKSHOT_WAITER_VMRL_SHARED | STACKSHOT_BLOCKER_VMRL_EXCLUSIVE, "rels[%zu].flags should match waiter_flags", i);
	}
}

T_DECL(test_complex_blocking_scenario_partial_acquire_and_wait, "test a complex blocking scenario where a thread os both a blocker and a waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_waiter_info_t waiters[2];
	thread_vmrl_owner_info_t owners[2];
	state.waiters = waiters;
	state.owners = owners;
	os_atomic_store(&state.num_waiters, 2, relaxed);
	os_atomic_store(&state.num_owners, 2, relaxed);

	memset(state.relationships, 0, sizeof(state.relationships));

	uint64_t tid1_blocker = 0x1001;
	uint64_t tid2_partial_acquirer_waiter = 0x1002;
	uint64_t tid3_waiter = 0x1003;

	unsigned long map_size = 0x10000;
	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;

	// Thread 1 owns this, Thread 2 waits for it
	unsigned long range_t1_owned_start = 0x2000;
	unsigned long range_t1_owned_end = 0x3000;

	// Thread 2 acquires this, Thread 3 waits for it
	unsigned long range_t2_acquired_start = 0x1000;
	unsigned long range_t2_acquired_end = 0x2000;

	// Thread 2 is waiting for this (same as T1 owned)
	unsigned long range_t2_waiting_start = 0x2000;
	unsigned long range_t2_waiting_end = 0x3000;

	// Thread 3 is waiting for this (same as T2 acquired)
	unsigned long range_t3_waiting_start = 0x1000;
	unsigned long range_t3_waiting_end = 0x2000;

	// Blocker 1: tid1_blocker owns range_t1_owned_start to range_t1_owned_end exclusively
	owners[0].owner_tid = tid1_blocker;
	owners[0].map = test_map;
	owners[0].start = range_t1_owned_start;
	owners[0].end = range_t1_owned_end;
	owners[0].flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE | STACKSHOT_BLOCKER_VMRL_ATOMIC;

	// Blocker 2: tid2_partial_acquirer_waiter owns range_t2_acquired_start to range_t2_acquired_end exclusively
	// This is the part of the range that Thread 2 successfully acquired.
	owners[1].owner_tid = tid2_partial_acquirer_waiter;
	owners[1].map = test_map;
	owners[1].start = range_t2_acquired_start;
	owners[1].end = range_t2_acquired_end;
	owners[1].flags = STACKSHOT_BLOCKER_VMRL_EXCLUSIVE | STACKSHOT_BLOCKER_VMRL_ATOMIC; // Thread 2 acquired atomically

	// Waiter 1: tid2_partial_acquirer_waiter is waiting for range_t2_waiting_start to range_t2_waiting_end exclusively
	// This is the part of the range that Thread 2 *could not* acquire and is waiting for.
	waiters[0].waiter_tid = tid2_partial_acquirer_waiter;
	waiters[0].map = test_map;
	waiters[0].start = range_t2_waiting_start;
	waiters[0].end = range_t2_waiting_end;
	waiters[0].flags = STACKSHOT_WAITER_VMRL_EXCLUSIVE | STACKSHOT_WAITER_VMRL_ATOMIC;
	waiters[0].num_blockers = 1; // Expect thread 1
	waiters[0].entry_hash = 0xABCDEF01;

	// Waiter 2: tid3_waiter is waiting for range_t3_waiting_start to range_t3_waiting_end exclusively
	// This is the range that Thread 3 wants, which is owned by Thread 2.
	waiters[1].waiter_tid = tid3_waiter;
	waiters[1].map = test_map;
	waiters[1].start = range_t3_waiting_start;
	waiters[1].end = range_t3_waiting_end;
	waiters[1].flags = STACKSHOT_WAITER_VMRL_EXCLUSIVE | STACKSHOT_WAITER_VMRL_ATOMIC;
	waiters[1].num_blockers = 1; // Expect 1 blocker (thread 2)
	waiters[1].entry_hash = 0xABCDEF02;

	uint32_t num_rels = vmrl_stackshot_collect_final_blocking_rels(&state);

	// --- Assertions ---
	// We expect two relationships:
	// 1. Thread 3 (waiter) blocked by Thread 2 (blocker)
	// 2. Thread 2 (waiter) blocked by Thread 1 (blocker)
	// The order in the `rels` array might not be guaranteed, so we'll check for presence.

	bool found_t3_waits_t2 = false;
	bool found_t2_waits_t1 = false;
	int found_rels_count = 0;

	for (size_t i = 0; i < STACKSHOT_VMRL_MAX_BLOCKING_RELATIONSHIPS; ++i) {
		if (state.relationships[i].waiter_tid == 0ULL && state.relationships[i].blocker_tid == 0ULL) {
			continue;
		}
		found_rels_count++;

		if (state.relationships[i].waiter_tid == tid3_waiter && state.relationships[i].blocker_tid == tid2_partial_acquirer_waiter) {
			T_ASSERT_EQ(state.relationships[i].entry_hash, waiters[1].entry_hash, "T3->T2: entry_hash");
			T_ASSERT_EQ(state.relationships[i].flags, waiters[1].flags | owners[1].flags, "T3->T2: flags");
			found_t3_waits_t2 = true;
		} else if (state.relationships[i].waiter_tid == tid2_partial_acquirer_waiter && state.relationships[i].blocker_tid == tid1_blocker) {
			T_ASSERT_EQ(state.relationships[i].entry_hash, waiters[0].entry_hash, "T2->T1: entry_hash");
			T_ASSERT_EQ(state.relationships[i].flags, waiters[0].flags | owners[0].flags, "T2->T1: flags");
			found_t2_waits_t1 = true;
		} else {
			T_FAIL("Unexpected relationship found: waiter %llx blocked by %llx",
			    state.relationships[i].waiter_tid, state.relationships[i].blocker_tid);
		}
	}

	T_ASSERT_EQ(num_rels, 2U, "Should find 2 relationships");
	T_ASSERT_TRUE(found_t3_waits_t2, "T3 waits for T2");
	T_ASSERT_TRUE(found_t2_waits_t1, "T2 waits for T1");
	T_ASSERT_EQ(found_rels_count, 2, "Found 2 rels");
}

T_DECL(test_collect_intermediary_info_thread_is_both_blocker_and_waiter, "test collecting info for a thread that is both a blocker and a waiter")
{
	struct stackshot_vmrl_state state = {};
	thread_vmrl_owner_info_t owners[STACKSHOT_VMRL_MAX_OWNERS];
	thread_vmrl_waiter_info_t waiters[STACKSHOT_VMRL_MAX_WAITERS];
	state.owners = owners;
	state.waiters = waiters;
	uint64_t tid_target_thread = 0x1002;
	unsigned long map_size = 0x10000;
	vm_map_t test_map = vm_test_alloc_map();
	test_map->size = map_size;
	struct thread thread = {0};
	struct vm_map_entry entry;
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/* What we already own: */
	ctx->__vmlc_atomic.locked_range_start = 0x1000;
	ctx->__vmlc_atomic.locked_range_end = 0x2000;
	ctx->__vmlc_flags |= (_VMRL_ATOMIC_INTERNAL | VMRL_EXCLUSIVE);

	setup_vm_prerequisites_for_waiter(ctx, &entry, map_size, /* What we are waiting for: */ 0x2000, 0x3000, 0);
	setup_thread_wait_state(&thread, ctx, &entry, tid_target_thread, kThreadWaitVMEntryExclEvent);

	vmrl_stackshot_collect_intermediary_info(&thread, &state);

	// --- ASSERTIONS ---

	// 1. Assert thread is collected as a WAITER
	T_ASSERT_EQ(os_atomic_load(&state.num_waiters, relaxed), 1U, "num_waiters should be 1");
	T_ASSERT_EQ(state.waiters[0].waiter_tid, tid_target_thread, "Waiter TID should match target thread");
	T_ASSERT_EQ(state.waiters[0].start, 0x2000UL, "Waiter start range should be 0x2000");
	T_ASSERT_EQ(state.waiters[0].end, 0x3000UL, "Waiter end range should be 0x3000");
	T_ASSERT_EQ(state.waiters[0].flags, (STACKSHOT_WAITER_VMRL_EXCLUSIVE | STACKSHOT_WAITER_VMRL_ATOMIC), "Waiter flags should be exclusive & atomic");
	T_ASSERT_EQ((int)state.waiters[0].num_blockers, 1, "Waiter's num_blockers should be 1");


	// 2. Assert Thread 2 is collected as a BLOCKER
	T_ASSERT_EQ(os_atomic_load(&state.num_owners, relaxed), 1U, "num_blockers should be 1");
	T_ASSERT_EQ(state.owners[0].owner_tid, tid_target_thread, "Blocker TID should match target thread");
	T_ASSERT_EQ(state.owners[0].start, 0x1000UL, "Blocker start range should be 0x1000");
	T_ASSERT_EQ(state.owners[0].end, 0x2000UL, "Blocker end range should be 0x2000");
	T_ASSERT_EQ(state.owners[0].flags, (STACKSHOT_BLOCKER_VMRL_EXCLUSIVE | STACKSHOT_BLOCKER_VMRL_ATOMIC), "Blocker flags should be exclusive & atomic");
	T_ASSERT_EQ(os_atomic_load(&state.exp_num_relationships, relaxed), 1U, "exp_num_relationships should be 1 (from the waiter info)");
}
