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

#include <darwintest.h>
#include "mocks/osfmk/mock_thread.h"
#include "mocks/osfmk/mock_cpu.h"

// Single-CPU fiber tests
// Use FIBERS_PREEMPTION=1 to have simulated preemption at memory operations.
// make -C tests/unit SDKROOT=macosx.internal fibers_test FIBERS_PREEMPTION=1

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.fibers"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("misc"),
	T_META_OWNER("a_fioraldi"),
	T_META_RUN_CONCURRENTLY(true)
	);

// Use fibers for scheduling
UT_USE_FIBERS(1);
// Single-CPU simulation (default)
UT_CPU_COUNT(1);

// Enable the data race checker
// UT_FIBERS_USE_CHECKER(1);

// Include common tests
#include "fibers_test_common.inc"

// ============================================================================
// Cooperative Fiber Tests
// ============================================================================

static int third_fiber_id = -1;
static void*
coop_fibers_func(void* x)
{
	int *cooperative_counter = (int*)x;

	if (*cooperative_counter == 0) {
		// main thread can jump here just after fibers_create
		fibers_yield_to(0); // switch back to main thread and finish the fibers creation
	}

	T_QUIET; T_ASSERT_EQ(*cooperative_counter, fibers_current->id, "invalid cooperative_counter");
	*cooperative_counter = fibers_current->id + 1;

	// switch to next fiber or to main fiber (id=0) if the current is the last
	if (fibers_current->id == third_fiber_id) {
		fibers_yield_to(0);
	} else {
		fibers_yield_to(fibers_current->id + 1);
	}

	return NULL;
}

T_DECL(coop_fibers, "cooperative scheduling using fibers")
{
	// disable preemption in case FIBERS_PREEMPTION=1 was using to compile
	// context switches will still happen before and after locks / interrupt enable/disable / fibers creation
	fibers_may_yield_probability = 0;

	random_set_seed(1234);

	int cooperative_counter = 0;

	fiber_t first = fibers_create(FIBERS_DEFAULT_STACK_SIZE, coop_fibers_func, (void*)&cooperative_counter);
	fiber_t second = fibers_create(FIBERS_DEFAULT_STACK_SIZE, coop_fibers_func, (void*)&cooperative_counter);
	fiber_t third = fibers_create(FIBERS_DEFAULT_STACK_SIZE, coop_fibers_func, (void*)&cooperative_counter);

	third_fiber_id = third->id;

	// Start the chain of ctxswitches from the main thread and switch to first
	cooperative_counter = first->id;
	fibers_yield_to(first->id);

	T_LOG("Done cooperative_counter=%d", cooperative_counter);
	T_ASSERT_EQ(cooperative_counter, third->id + 1, "invalid cooperative schedule");

	// always join the fibers
	fibers_join(first);
	fibers_join(second);
	fibers_join(third);

	T_PASS("coop_fibers");
}
