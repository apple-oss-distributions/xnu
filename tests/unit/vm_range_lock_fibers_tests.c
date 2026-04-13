/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include <darwintest.h>

#include <stdint.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_thread.h"
#include "mocks/osfmk/fibers/fibers.h"
#include "mocks/osfmk/fibers/mutex.h"

#include <vm/vm_object_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_test_utils_internal.h>


#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm_range_lock_fibers"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("s_shalom"),
	T_META_RUN_CONCURRENTLY(false)
	);

UT_USE_FIBERS(1);

enum safeabort_how_to_abort {
	SAFEABORT_TEST_LOCK_EXCLUSIVE,
	SAFEABORT_TEST_LOCK_SHARED,
	SAFEABORT_TEST_FIND_EXCLUSIVE,
	SAFEABORT_TEST_FIND_SHARED,
};

/*
 * Arguments to be passed to threads created by safeabort tests.
 */
struct safeabort_rangelock_thread_args {
	vm_map_t                                map;
	vm_map_offset_t                         range_start;
	vm_map_offset_t                         last_entry_start;
	vm_map_offset_t                         range_end;
	boolean_t                               atomic; /* Whether to use atomic vs. streaming. */
	enum safeabort_how_to_abort             how_to_abort;

	/* Blocker/aborter interleaving synchronization. */
	fibers_mutex_t *last_entry_locked;
	fibers_mutex_t *aborted;
	int            *sanity_check;
};

static void *
rangelock_blocker_thread(void *__args)
{
	struct safeabort_rangelock_thread_args args =
	    *(struct safeabort_rangelock_thread_args *)__args;
	args.last_entry_locked->holder = fibers_current; /* Steal this mutex from parent. */
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/* Lock the last entry in the range so that the aborter will contend on it. */
	kern_return_t kr = vm_map_range_ex_lock(
		ctx,
		&args.map,
		args.last_entry_start,
		args.range_end,
		VMRL_EX_ATOMIC);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "blocker locks last entry");

	/* Allow the aborter thread to run, and wait until it finishes. */
	T_QUIET; T_ASSERT_EQ((*args.sanity_check)++, 0, "blocker locks last entry before aborter runs");
	fibers_mutex_unlock(args.last_entry_locked);
	fibers_mutex_lock(args.aborted, TRUE);
	T_QUIET; T_ASSERT_EQ((*args.sanity_check)++, 3, "blocker unlocks last entry after aborter runs");

	/* Cleanup. */
	vm_map_range_ex_unlock(ctx, &args.map);

	return NULL;
}

static void *
rangelock_aborter_thread(void *__args)
{
	struct safeabort_rangelock_thread_args args =
	    *(struct safeabort_rangelock_thread_args *)__args;
	vm_map_t map_orig = args.map;
	args.aborted->holder = fibers_current; /* Steal this mutex from parent. */
	VM_MAP_LOCK_CTX_DECLARE(ctx);

	/* Wait for the last entry to be locked by the blocker. */
	fibers_mutex_lock(args.last_entry_locked, TRUE);
	T_QUIET; T_ASSERT_EQ((*args.sanity_check)++, 1, "aborter runs after blocker");

	/*
	 * Abort this thread and attempt to lock the range, which should fail when
	 * we attempt to contend on the final entry's lock.
	 */
	thread_t thread = current_thread();
	thread_mtx_lock(thread);
	thread->sched_flags |= TH_SFLAG_ABORT;
	thread_mtx_unlock(thread);

	/* Run the operation that should be aborted. */
	kern_return_t kr;
	switch (args.how_to_abort) {
	case SAFEABORT_TEST_LOCK_EXCLUSIVE:
		kr = vm_map_range_ex_lock(
			ctx,
			&args.map,
			args.range_start,
			args.range_end,
			VMRL_EX_INTERRUPTIBLE | (args.atomic ? VMRL_EX_ATOMIC : VMRL_EX_STREAM));
		break;
	case SAFEABORT_TEST_LOCK_SHARED:
		kr = vm_map_range_sh_lock(
			ctx,
			&args.map,
			args.range_start,
			args.range_end,
			VMRL_SH_INTERRUPTIBLE | (args.atomic ? VMRL_SH_ATOMIC : VMRL_SH_STREAM));
		break;
	case SAFEABORT_TEST_FIND_EXCLUSIVE:
		kr = vm_map_find_entry_ex_locked(
			ctx,
			&args.map,
			args.last_entry_start,
			VMRL_FIND_EX_INTERRUPTIBLE);
		break;
	case SAFEABORT_TEST_FIND_SHARED:
		kr = vm_map_find_entry_sh_locked(
			ctx,
			&args.map,
			args.last_entry_start,
			VMRL_FIND_SH_INTERRUPTIBLE);
		break;
	default:
		T_FAIL("Invalid 'how to abort' argument (%d)", args.how_to_abort);
	}

	/* Verify that the operation was aborted. */
	if (args.atomic ||
	    args.how_to_abort == SAFEABORT_TEST_FIND_EXCLUSIVE ||
	    args.how_to_abort == SAFEABORT_TEST_FIND_SHARED) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_ABORTED, "non-streaming operation aborted");
	} else { /* args.atomic == false */
		/*
		 * We'll need to iterate through the range until we contend and abort
		 * on the final entry. If there was an error (e.g., KERN_ABORTED) in
		 * the locking call, that would have also been surpressed and will
		 * surface on the first next() call.
		 */
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "lock(stream) initially succeeds");
		vm_map_entry_t entry;
		while ((entry = vm_map_range_next_with_error(ctx, &kr)) && kr == KERN_SUCCESS) {
		}
		T_QUIET; T_ASSERT_EQ(kr, KERN_ABORTED, "streaming range should cause abort");

		if (args.how_to_abort == SAFEABORT_TEST_LOCK_EXCLUSIVE) {
			vm_map_range_ex_unlock(ctx, &args.map);
		} else if (args.how_to_abort == SAFEABORT_TEST_LOCK_SHARED) {
			vm_map_range_sh_unlock(ctx, &args.map);
		}
	}
	T_QUIET; T_ASSERT_TRUE(args.map == map_orig, "map variable should be restored after abort");

	/*
	 * Allow the blocker to unlock the last entry and terminate.
	 */
	T_QUIET; T_ASSERT_EQ((*args.sanity_check)++, 2, "sanity check blocker hasn't run");
	fibers_mutex_unlock(args.aborted);

	return NULL;
}

static void
run_safeabort_test(
	int                         n_entries,
	boolean_t                   atomic, /* ignored if not locking a range. */
	enum safeabort_how_to_abort how_to_abort)
{
	T_SETUPBEGIN;

	/* Create a map with the requested number of entries. */
	vm_map_t map = vm_test_alloc_map();
	vm_map_entry_t prev_entry = VM_MAP_ENTRY_NULL;
	vm_map_offset_t range_start = 0x10000;
	for (int i = 0; i < n_entries; i++) {
		vm_map_entry_t entry;
		if (prev_entry == VM_MAP_ENTRY_NULL) {
			entry = vm_test_add_map_entry(map, range_start, range_start + PAGE_SIZE);
		} else {
			entry = vm_test_add_map_entry(map, prev_entry->vme_end, prev_entry->vme_end + PAGE_SIZE);
		}
		prev_entry = entry;
	}

	/* Initially owned by blocker, who unlocks once last entry locked.  */
	fibers_mutex_t last_entry_locked;
	fibers_mutex_init(&last_entry_locked);
	fibers_mutex_lock(&last_entry_locked, FALSE);

	/* Initially held by aborter, who unlocks once they've attempted lock the range. */
	fibers_mutex_t aborted;
	fibers_mutex_init(&aborted);
	fibers_mutex_lock(&aborted, FALSE);

	int thread_ordering_sanity_check = 0;
	struct safeabort_rangelock_thread_args args = {
		.map                = map,
		.range_start        = range_start,
		.last_entry_start   = prev_entry->vme_start,
		.range_end          = prev_entry->vme_end,
		.last_entry_locked  = &last_entry_locked,
		.atomic             = atomic,
		.how_to_abort       = how_to_abort,
		.aborted            = &aborted,
		.sanity_check       = &thread_ordering_sanity_check,
	};

	T_SETUPEND;

	fiber_t blocker = fibers_create(
		FIBERS_DEFAULT_STACK_SIZE,
		rangelock_blocker_thread,
		(void *)&args);
	fiber_t aborter = fibers_create(
		FIBERS_DEFAULT_STACK_SIZE,
		rangelock_aborter_thread,
		(void *)&args);

	fibers_join(blocker);
	fibers_join(aborter);

	/*
	 * Ensure that everything was properly cleaned up after the safe abort path
	 * was taken by verifying that we can successfully lock the entire range.
	 */
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr = vm_map_range_ex_lock(
		ctx,
		&map,
		args.range_start,
		args.range_end,
		VMRL_EX_ATOMIC);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "verify range can be locked after cleanup");

	vm_map_range_ex_unlock(ctx, &map);
	vm_map_destroy(map);
}

/*
 * Tests ALL range lock functions (not interlock) that can accept a
 * VMRL_*_INTERRUPTIBLE flag, interrupting them and causing them to take their
 * respective abort paths.
 *
 * This is achieved with two threads () which execute in the following order:
 *  0. Parent spawns aborter and blocker with pre-locked mutexes for synchronization
 *  1. Blocker locks the last entry in the range
 *  2. Aborter marks self as aborted
 *  3. Aborter attempts to lock range/already-locked entry (takes abort path)
 *  4. Aborter exits
 *  5. Blocker unlocks what was locked in step 1
 *  6. Blocker exits
 *  7. Parent locks & unlocks range to verify aborter cleaned up properly
 *
 * Each function is tested on ranges constructed from varying quantities of
 * entries, ranging from from min_entries_to_test to max_entries_to_test.
 */
T_DECL(range_lock_abort_paths, "verify thread aborts work properly with VMRL_INTERRUPTIBLE")
{
	int min_entries_to_test = 1;
	int max_entries_to_test = 3;

	for (int i = min_entries_to_test; i <= max_entries_to_test; i++) {
		run_safeabort_test(i, true, SAFEABORT_TEST_LOCK_EXCLUSIVE);
	}
	T_PASS("Abort vm_map_range_ex_lock (atomic)");

	for (int i = min_entries_to_test; i <= max_entries_to_test; i++) {
		run_safeabort_test(i, false, SAFEABORT_TEST_LOCK_EXCLUSIVE);
	}
	T_PASS("Abort vm_map_range_ex_lock (streaming)");

	for (int i = min_entries_to_test; i <= max_entries_to_test; i++) {
		run_safeabort_test(i, true, SAFEABORT_TEST_LOCK_SHARED);
	}
	T_PASS("Abort vm_map_range_sh_lock (atomic)");

	for (int i = min_entries_to_test; i <= max_entries_to_test; i++) {
		run_safeabort_test(i, false, SAFEABORT_TEST_LOCK_SHARED);
	}
	T_PASS("Abort vm_map_range_sh_lock (streaming)");

	run_safeabort_test(1, false, SAFEABORT_TEST_FIND_EXCLUSIVE);
	T_PASS("Abort vm_map_find_entry_ex_locked");
	run_safeabort_test(1, false, SAFEABORT_TEST_FIND_SHARED);
	T_PASS("Abort vm_map_find_entry_sh_locked");
}

static void *
interlock_aborter_thread(void *args)
{
	vm_map_t map = (vm_map_t)args;

	/* Abort this thread. */
	thread_t thread = current_thread();
	thread_mtx_lock(thread);
	thread->sched_flags |= TH_SFLAG_ABORT;
	thread_mtx_unlock(thread);

	vm_map_ilk_lock(map);

	/* Sleep on the interlock, which should abort and never drop the interlock. */
	wait_result_t wr = vm_map_ilk_sleep(map, (event_t)map, THREAD_ABORTSAFE);
	T_QUIET; T_ASSERT_EQ(wr, THREAD_INTERRUPTED, "Re-acquiring interlock should abort");

	vm_map_ilk_unlock(map);

	return NULL;
}

/*
 * interlock_aborter_thread will attempt to sleep on interlock while the thread
 * has been marked as aborted, causing vm_map_ilk_sleep to take the abort path,
 * and never actually release the interlock during the sleep call.
 */
T_DECL(interlock_abort_path, "verify thread abort works properly with vm_map_ilk_sleep")
{
	T_SETUPBEGIN;

	vm_map_t map = vm_test_alloc_map();

	T_SETUPEND;

	fiber_t aborter = fibers_create(
		FIBERS_DEFAULT_STACK_SIZE,
		interlock_aborter_thread,
		(void *)map);

	fibers_join(aborter);

	/* Verify interlock can be acquired and released. */
	vm_map_ilk_lock(map);
	vm_map_ilk_unlock(map);

	vm_map_destroy(map);

	T_PASS("Abort vm_map_ilk_sleep");
}
