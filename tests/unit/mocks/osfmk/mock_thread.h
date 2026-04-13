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

#include "mocks/mock_dynamic.h"
#include <arm/pmap_public.h>
#include <vm/pmap.h>
#include <kern/lock_mtx.h>
#include <kern/task.h>

#include "mocks/osfmk/fibers/fibers.h"

// Unit tests that wants to use fibers must call with macro in the global scope with val=1
#define UT_USE_FIBERS(val) int ut_mocks_use_fibers = (val)
// Unit tests using fibers that wants to enable the data race checker must call with macro in the global scope with val=1
#define UT_FIBERS_USE_CHECKER(val) int ut_fibers_use_data_race_checker = (val)

extern int ut_mocks_use_fibers __attribute__((weak));
extern int ut_fibers_use_data_race_checker __attribute__((weak));
extern bool ut_mocks_lock_upgrade_fail;

// You can set the fibers configuration variables either assigning a value to them in the test function (see fibers_test.c)
// or using these macros in the global scope
#define UT_FIBERS_LOG_LEVEL(val)    \
    __attribute__((constructor))    \
    static void                     \
    _ut_fibers_set_log_level(void)  \
    {                               \
	fibers_log_level = (val);       \
    }
#define UT_FIBERS_DEBUG(val)        \
    __attribute__((constructor))    \
    static void                     \
    _ut_fibers_set_log_debug(void)  \
    {                               \
	fibers_debug = (val);           \
    }
#define UT_FIBERS_ABORT_ON_ERROR(val)    \
    __attribute__((constructor))         \
    static void                          \
    _ut_fibers_set_abort_on_error(void)  \
    {                                    \
	fibers_abort_on_error = (val);       \
    }
#define UT_FIBERS_MAY_YIELD_PROB(val)      \
    __attribute__((constructor))           \
    static void                            \
    _ut_fibers_set_may_yield_prob(void)    \
    {                                      \
	fibers_may_yield_probability = (val);  \
    }

/*
 * Writing tests using fibers:
 *
 * If UT_USE_FIBERS(1) is used, every test defined in the same test executable will use the threading mocks implemented using the fibers API.
 * However, this is not sufficient to write a test with multiple "threads", the test itself is reposinsible of creating the fibers.
 * For some working examples, see the fibers_test.c file.
 *
 * The tests file must include the needed headers from mocks/osfmk/fibers/ depending on what needs to be used.
 * Fibers API are very similar to pthread, and if FIBERS_PREEMPTION=1 is used at compile time it behaves in a similar way to real threads.
 * The main different is that developers must be aware that blocking operations are blocking every fiber,
 * for instance you should not call sleep() in your test and if some kernel function is calling a similar function you should mock it with
 * a call to one or more fibers_yield() to trigger a context switch.
 * The scheduler is deterministic, the interleaving can be changed either setting a different seed in the PRNG with random_set_seed()
 * or with any change to the code itself, as possible context switch points are located inside the fibers API or, even more drastically,
 * at every memory load/store when FIBERS_PREEMPTION=1.
 *
 * Target code in XNU (like sysctl tests) can trigger a fibers context switch using the following API (see mock_attached.c):
 * void ut_fibers_ctxswitch(void); // Switch to a random fiber
 * void ut_fibers_ctxswitch_to(int fiber_id); // Switch to a specific fiber by id
 * int ut_fibers_current_id(void); // Get the current fiber id
 */

/*
 * Allocate and initialize a proc and task.
 * fake_alloc_init_proc_and_task() is in mock_proc.h
 */
extern task_t fake_alloc_init_task_and_proc(void);

/*
 * Dealloc a task and proc allocated by one of the fake alloc functions above.
 * fake_dealloc_proc_and_task(proc_t proc) is in mock_proc.h
 */
extern void fake_dealloc_task_and_proc(task_t task);

extern void fake_init_lock(lck_mtx_t *mtx);
extern void fake_init_task(task_t new_task);

T_MOCK_DECLARE(
	kern_return_t,
	thread_wakeup_prim, (
		event_t           event,
		boolean_t         one_thread,
		wait_result_t     result));

T_MOCK_DECLARE(
	wait_result_t,
	thread_block_reason, (
		thread_continue_t continuation,
		void              *parameter,
		ast_t             reason));

T_MOCK_DECLARE(
	int,
	task_pid,
	(task_t task));

T_MOCK_DECLARE(struct proc *,
current_proc, (void));
