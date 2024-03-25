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

#include <mach/exclaves.h>

#if CONFIG_EXCLAVES

#if CONFIG_SPTM
#include <arm64/sptm/sptm.h>
#else
#error Invalid configuration
#endif /* CONFIG_SPTM */

#include <libkern/section_keywords.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <stddef.h>

#include "exclaves_boot.h"
#include "exclaves_debug.h"
#include "exclaves_frame_mint.h"

extern lck_grp_t exclaves_lck_grp;

/* Lock around single-threaded exclaves boot */
LCK_MTX_DECLARE(exclaves_boot_lock, &exclaves_lck_grp);

/* Boot status. */
__enum_closed_decl(exclaves_boot_status_t, uint32_t, {
	EXCLAVES_BS_NOT_SUPPORTED = 0,
	EXCLAVES_BS_NOT_STARTED = 1,
	EXCLAVES_BS_BOOTED_STAGE_2 = 2,
	EXCLAVES_BS_BOOTED_EXCLAVEKIT = 3,
	EXCLAVES_BS_BOOTED_FAILURE = 4,
});

/* Atomic so that it can be safely checked outside the boot lock. */
static os_atomic(exclaves_boot_status_t) exclaves_boot_status = EXCLAVES_BS_NOT_SUPPORTED;

static thread_t exclaves_boot_thread = THREAD_NULL;

extern exclaves_boot_task_entry_t exclaves_boot_task_entries[]
__SECTION_START_SYM(EXCLAVES_BOOT_TASK_SEGMENT, EXCLAVES_BOOT_TASK_SECTION);

extern exclaves_boot_task_entry_t exclaves_boot_task_entries_end[]
__SECTION_END_SYM(EXCLAVES_BOOT_TASK_SEGMENT, EXCLAVES_BOOT_TASK_SECTION);

static int
ebt_cmp(const void *e1, const void *e2)
{
	const struct exclaves_boot_task_entry *a = e1;
	const struct exclaves_boot_task_entry *b = e2;

	if (a->ebt_rank > b->ebt_rank) {
		return 1;
	}

	if (a->ebt_rank < b->ebt_rank) {
		return -1;
	}

	return 0;
}

static void
exclaves_boot_tasks(void)
{
	const size_t count =
	    exclaves_boot_task_entries_end - exclaves_boot_task_entries;
	assert3u(count, >, 0);

	__assert_only const size_t size =
	    ((uintptr_t)exclaves_boot_task_entries_end -
	    (uintptr_t)exclaves_boot_task_entries);
	assert3u(size % sizeof(exclaves_boot_task_entry_t), ==, 0);

	/*
	 * exclaves_boot_task_entries is in _DATA_CONST, make a stack copy so it
	 * can be sorted.
	 */
	exclaves_boot_task_entry_t boot_tasks[count];
	memcpy(boot_tasks, exclaves_boot_task_entries, count * sizeof(boot_tasks[0]));

	extern void qsort(void *, size_t, size_t,
	    int (*)(const void *, const void *));
	qsort(boot_tasks, count, sizeof(boot_tasks[0]), ebt_cmp);

	for (size_t i = 0; i < count; i++) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES,
		    MACH_EXCLAVES_BOOT_TASK) | DBG_FUNC_START, i);
		kern_return_t ret = boot_tasks[i].ebt_func();
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES,
		    MACH_EXCLAVES_BOOT_TASK) | DBG_FUNC_END);
		if (ret != KERN_SUCCESS) {
			panic("exclaves: boot task failed: %s (%p)",
			    boot_tasks[i].ebt_name, &boot_tasks[i]);
		}
	}
}

/*
 * Check early in boot if the secure world has bootstrapped, and update the
 * boot status if not.
 */
__startup_func
static void
exclaves_check_sk(void)
{
	const bool sk_bootstrapped = SPTMArgs->sk_bootstrapped;

	if (sk_bootstrapped) {
		os_atomic_store(&exclaves_boot_status,
		    EXCLAVES_BS_NOT_STARTED, relaxed);
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, exclaves_check_sk);

static void
exclaves_boot_status_wait(const exclaves_boot_status_t status)
{
	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	while (os_atomic_load(&exclaves_boot_status, relaxed) < status) {
		lck_mtx_sleep(&exclaves_boot_lock, LCK_SLEEP_DEFAULT,
		    (event_t)(uintptr_t)&exclaves_boot_status, THREAD_UNINT);
	}
}

static void
exclaves_boot_status_wake(void)
{
	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);
	thread_wakeup((event_t)(uintptr_t)&exclaves_boot_status);
}

static void
exclaves_boot_status_set(const exclaves_boot_status_t status)
{
	assert3u(status, >, os_atomic_load(&exclaves_boot_status, relaxed));

	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * 'release' here to ensure that the status update is only seen after
	 * any boot update. exclaves_boot_status is loaded with 'acquire' in
	 * exclaves_boot_wait() without holding the lock so the mutex alone
	 * isn't sufficient for ordering.
	 */
	os_atomic_store(&exclaves_boot_status, status, release);
	exclaves_boot_status_wake();
}

static kern_return_t
exclaves_boot_stage_2(void)
{
	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	kern_return_t kr = KERN_FAILURE;
	const exclaves_boot_status_t status =
	    os_atomic_load(&exclaves_boot_status, relaxed);

	if (status == EXCLAVES_BS_NOT_SUPPORTED) {
		return KERN_NOT_SUPPORTED;
	}

	/* Should only be called from launchd. */
	if (task_pid(current_task()) != 1) {
		return KERN_DENIED;
	}

	/*
	 * This should only ever happen if there's a userspace bug which causes
	 * boot to be called twice and cause a race.
	 */
	if (status != EXCLAVES_BS_NOT_STARTED) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Early boot. */
	extern kern_return_t exclaves_boot_early(void);
	kr = exclaves_boot_early();
	if (kr != KERN_SUCCESS) {
		/*
		 * If exclaves failed to boot, there's not much that can be done other
		 * than panic.
		 */
		panic("Exclaves stage2 boot failed");
	}

	/*
	 * At this point it should be possible to make tightbeam calls/configure
	 * endpoints etc.
	 */
	exclaves_boot_thread = current_thread();
	exclaves_boot_tasks();
	exclaves_boot_thread = THREAD_NULL;

	exclaves_boot_status_set(EXCLAVES_BS_BOOTED_STAGE_2);

	return kr;
}

static kern_return_t
exclaves_boot_exclavekit(void)
{
	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	/* This should require an entitlement at some point. */

	const exclaves_boot_status_t status =
	    os_atomic_load(&exclaves_boot_status, relaxed);

	if (status == EXCLAVES_BS_NOT_SUPPORTED) {
		return KERN_NOT_SUPPORTED;
	}

	/* Should only be called after stage2 boot. */
	if (status != EXCLAVES_BS_BOOTED_STAGE_2) {
		return KERN_INVALID_ARGUMENT;
	}


	/*
	 * Treat a failure to boot exclavekit as a transition to the
	 * EXCLAVES_BS_BOOTED_FAILURE state and return a failure.
	 */
	kern_return_t kr = exclaves_frame_mint_populate();
	if (kr != KERN_SUCCESS) {
		exclaves_boot_status_set(EXCLAVES_BS_BOOTED_FAILURE);
		return KERN_FAILURE;
	}

	exclaves_boot_status_set(EXCLAVES_BS_BOOTED_EXCLAVEKIT);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_boot(exclaves_boot_stage_t boot_stage)
{
	lck_mtx_lock(&exclaves_boot_lock);

	kern_return_t kr = KERN_FAILURE;

	switch (boot_stage) {
	case EXCLAVES_BOOT_STAGE_2:
		kr = exclaves_boot_stage_2();
		break;

	case EXCLAVES_BOOT_STAGE_EXCLAVEKIT:
		kr = exclaves_boot_exclavekit();
		break;

	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	lck_mtx_unlock(&exclaves_boot_lock);

	return kr;
}

/*
 * This returns once the specified boot stage has been reached. If exclaves are
 * unavailable, it returns immediately with KERN_NOT_SUPPORTED.
 * Make it NOINLINE so it shows up in backtraces.
 */
kern_return_t OS_NOINLINE
exclaves_boot_wait(const exclaves_boot_stage_t desired_boot_stage)
{
	assert(desired_boot_stage == EXCLAVES_BOOT_STAGE_2 ||
	    desired_boot_stage == EXCLAVES_BOOT_STAGE_EXCLAVEKIT);

	/* Look up the equivalent status for the specified boot stage. */
	const exclaves_boot_status_t desired_boot_status =
	    desired_boot_stage == EXCLAVES_BOOT_STAGE_2 ?
	    EXCLAVES_BS_BOOTED_STAGE_2 : EXCLAVES_BS_BOOTED_EXCLAVEKIT;

	/*
	 * See comment in exclaves_boot_status_set() for why this is an acquire.
	 */
	const exclaves_boot_status_t current_boot_status =
	    os_atomic_load(&exclaves_boot_status, acquire);

	if (current_boot_status >= desired_boot_status) {
		/*
		 * Special-case the situation where the request is to wait for
		 * EXCLAVES_BOOT_STAGE_EXCLAVEKIT. EXCLAVEKIT boot can fail
		 * (unlike STAGE_2 boot which will panic on failure). If
		 * EXCLAVEKIT has failed, just return KERN_NOT_SUPPORTED.
		 */
		if (desired_boot_status == EXCLAVES_BS_BOOTED_EXCLAVEKIT &&
		    current_boot_status == EXCLAVES_BS_BOOTED_FAILURE) {
			return KERN_NOT_SUPPORTED;
		}

		return KERN_SUCCESS;
	}

	if (current_boot_status == EXCLAVES_BS_NOT_SUPPORTED) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * Allow the exclaves boot thread to pass this check during stage2
	 * boot. This allows exclaves boot tasks to make TB calls etc during
	 * stage2 boot.
	 */
	if (desired_boot_status == EXCLAVES_BS_BOOTED_STAGE_2 &&
	    current_thread() == exclaves_boot_thread) {
		return KERN_SUCCESS;
	}

	/*
	 * Otherwise, wait until exclaves has booted to the requested stage or
	 * failed to boot.
	 */
	lck_mtx_lock(&exclaves_boot_lock);
	exclaves_boot_status_wait(desired_boot_status);
	lck_mtx_unlock(&exclaves_boot_lock);

	/*
	 * At this point there are two possibilities. Success or EXCLAVEKIT has
	 * failed (STAGE_2 can never fail as it panics on failure).
	 */
	if (desired_boot_status == EXCLAVES_BS_BOOTED_EXCLAVEKIT &&
	    current_boot_status == EXCLAVES_BS_BOOTED_FAILURE) {
		return KERN_NOT_SUPPORTED;
	}

	return KERN_SUCCESS;
}

/*
 * This returns AVAILABLE once EXCLAVES_BOOT_STAGE_2 has completed. This is to
 * maintain backwards compatibility with existing code.
 */
exclaves_status_t
exclaves_get_status(void)
{
	kern_return_t kr = exclaves_boot_wait(EXCLAVES_BOOT_STAGE_2);
	assert(kr == KERN_SUCCESS || kr == KERN_NOT_SUPPORTED);

	if (kr == KERN_SUCCESS) {
		return EXCLAVES_STATUS_AVAILABLE;
	}

	return EXCLAVES_STATUS_NOT_SUPPORTED;
}

exclaves_boot_stage_t
exclaves_get_boot_stage(void)
{
	exclaves_boot_status_t status =
	    os_atomic_load(&exclaves_boot_status, relaxed);

	switch (status) {
	case EXCLAVES_BS_NOT_STARTED:
	case EXCLAVES_BS_NOT_SUPPORTED:
		return EXCLAVES_BOOT_STAGE_NONE;

	case EXCLAVES_BS_BOOTED_STAGE_2:
		return EXCLAVES_BOOT_STAGE_2;

	case EXCLAVES_BS_BOOTED_EXCLAVEKIT:
		return EXCLAVES_BOOT_STAGE_EXCLAVEKIT;

	case EXCLAVES_BS_BOOTED_FAILURE:
		return EXCLAVES_BOOT_STAGE_FAILED;

	default:
		panic("unknown boot status: %u", status);
	}
}

#else /* CONFIG_EXCLAVES */

exclaves_status_t
exclaves_get_status(void)
{
	return EXCLAVES_STATUS_NOT_SUPPORTED;
}


exclaves_boot_stage_t
exclaves_get_boot_stage(void)
{
	return EXCLAVES_BOOT_STAGE_NONE;
}

#endif /* CONFIG_EXCLAVES */
