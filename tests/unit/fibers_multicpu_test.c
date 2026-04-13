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

#include <arm64/sptm/pmap/pmap_data.h>

// Multi-CPU fiber tests
// Use FIBERS_PREEMPTION=1 to have simulated preemption at memory operations.
// make -C tests/unit SDKROOT=macosx.internal fibers_multicpu_test FIBERS_PREEMPTION=1

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.fibers_multicpu"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("misc"),
	T_META_OWNER("a_fioraldi"),
	T_META_RUN_CONCURRENTLY(true)
	);

// Use fibers for scheduling
UT_USE_FIBERS(1);
// Multi-CPU simulation with 4 CPUs
UT_CPU_COUNT(4);

// Include common tests
#include "fibers_test_common.inc"

// ============================================================================
// Multi-CPU Specific Tests
// ============================================================================

static lck_mtx_t multicpu_test_lock;
static lck_grp_t multicpu_test_grp;
static volatile int multicpu_counter = 0;
static volatile int cpu_assignments[NUM_THREADS];

static void*
simple_increment_with_cpu_tracking(void* arg)
{
	int thread_num = (int)(uintptr_t)arg;

	// Record which CPU this fiber is on
	cpu_assignments[thread_num] = fibers_current->assigned_cpu;

	lck_mtx_lock(&multicpu_test_lock);
	multicpu_counter++;
	lck_mtx_unlock(&multicpu_test_lock);

	return NULL;
}

T_DECL(basic_cpu_assignment, "Test basic CPU assignment in multi-CPU mode")
{
	fibers_may_yield_probability = 0;
	random_set_seed(1234);

	lck_grp_init(&multicpu_test_grp, "multicpu_test", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&multicpu_test_lock, &multicpu_test_grp, LCK_ATTR_NULL);

	multicpu_counter = 0;
	memset((void*)cpu_assignments, 0, sizeof(cpu_assignments));

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, simple_increment_with_cpu_tracking, (void*)(uintptr_t)i);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	lck_mtx_destroy(&multicpu_test_lock, &multicpu_test_grp);

	T_LOG("Counter: %d", multicpu_counter);
	T_ASSERT_EQ(multicpu_counter, NUM_THREADS, "All threads incremented counter");

	// Check that threads were assigned to different CPUs
	int cpu_count = fibers_multicpu.cpu_count;
	T_LOG("CPU count: %d", cpu_count);

	for (int i = 0; i < NUM_THREADS; i++) {
		T_LOG("Thread %d assigned to CPU %d", i, cpu_assignments[i]);
		T_ASSERT_LT(cpu_assignments[i], (int)cpu_count, "CPU assignment valid");
	}

	T_PASS("basic_cpu_assignment");
}

static void*
increment_counter_nopreempt(void* arg)
{
	fibers_current->disable_race_checker = 1;

	disable_preemption();
	volatile int64_t *counter = (volatile int64_t *)arg;
	for (int i = 0; i < NUM_INCREMENTS; i++) {
		volatile uint64_t val = *counter;
		fibers_may_yield();
		*counter = val + 1;
	}
	enable_preemption();
	return NULL;
}

T_DECL(increment_test_nopreempt, "increment a counter with fibers with disabled preemption")
{
	random_set_seed(1234);

	fiber_t mythreads[NUM_THREADS] = {};
	volatile int64_t counter = 0;

	for (int i = 0; i < NUM_THREADS; i++) {
		mythreads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, increment_counter_nopreempt, (void*)&counter);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(mythreads[i]);
	}

	T_LOG("Done counter=%lld", os_atomic_load(&counter, relaxed));
	T_ASSERT_NE(counter, (int64_t)(NUM_INCREMENTS * NUM_THREADS), "race detected on counter, thread interleaving on multi-cpu works");

	T_PASS("increment_test_nopreempt");
}

// ============================================================================
// CPU Migration Tests
// ============================================================================

static void*
cpu_migration_worker(void* arg)
{
	int thread_id = (int)(uintptr_t)arg;
	unsigned int initial_cpu = fibers_get_assigned_cpu(fibers_current);

	// Do some work
	for (int i = 0; i < 10; i++) {
		fibers_yield();
	}

	unsigned int final_cpu = fibers_get_assigned_cpu(fibers_current);

	T_LOG("Thread %d: initial CPU=%u, final CPU=%u", thread_id, initial_cpu, final_cpu);

	return NULL;
}

T_DECL(cpu_migration, "Test fiber migration across CPUs")
{
	fibers_may_yield_probability = 4;
	random_set_seed(1234);

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, cpu_migration_worker, (void*)(uintptr_t)i);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	T_PASS("cpu_migration");
}

T_DECL(preemption_pins_cpu, "Test that disable_preemption() pins fiber to CPU")
{
	fibers_may_yield_probability = 4;
	random_set_seed(1234);

	// Test the exact scenario: CPU ID must remain constant with preemption disabled
	disable_preemption();
	unsigned int cur_cpu = fibers_get_assigned_cpu(fibers_current);

	T_LOG("Initial CPU with preemption disabled: %u", cur_cpu);

	// Do work with many context switches - CPU must stay the same
	for (int i = 0; i < 100; i++) {
		fibers_yield();
		unsigned int check_cpu = fibers_get_assigned_cpu(fibers_current);
		T_QUIET; T_ASSERT_EQ(cur_cpu, check_cpu, "Iteration %d: CPU ID unchanged (expected %u, got %u)", i, cur_cpu, check_cpu);
	}

	T_LOG("CPU remained %u throughout all context switches", cur_cpu);

	enable_preemption();

	T_PASS("preemption_pins_cpu");
}

T_DECL(interrupts_allow_migration, "Test that interrupts disabled allows migration")
{
	fibers_may_yield_probability = 4;
	random_set_seed(1234);

	boolean_t prev = ml_set_interrupts_enabled(FALSE);
	unsigned int initial_cpu = fibers_get_assigned_cpu(fibers_current);

	T_LOG("Initial CPU with interrupts disabled: %u", initial_cpu);

	// With interrupts disabled, migration is still possible
	int migration_occurred = 0;
	unsigned int final_cpu = initial_cpu;
	for (int i = 0; i < 100; i++) {
		fibers_yield();
		unsigned int current_cpu = fibers_get_assigned_cpu(fibers_current);
		if (current_cpu != initial_cpu) {
			migration_occurred = 1;
			final_cpu = current_cpu;
			T_LOG("Migration at iteration %d: CPU %u -> %u", i, initial_cpu, current_cpu);
			break;
		}
	}

	ml_set_interrupts_enabled(prev);

	T_LOG("Migration %s with interrupts disabled (CPU %u -> %u)", migration_occurred ? "occurred" : "did not occur", initial_cpu, final_cpu);

	T_PASS("interrupts_allow_migration");
}

// ============================================================================
// PER CPU Access
// ============================================================================

#define NUM_TEST_FIBERS 3

static void*
verify_percpu_worker(void* arg)
{
	int fiber_id = (int)(uintptr_t)arg;

	extern cpu_data_entry_t CpuDataEntries[MAX_CPUS];

	vm_offset_t cpu0_base = (vm_offset_t)CpuDataEntries[0].cpu_data_vaddr;

	// Calculate the offset of pmap_sptm_percpu from CPU 0's base
	pmap_sptm_percpu_data_t *cpu0_pmap = PERCPU_GET_MASTER(pmap_sptm_percpu);
	vm_offset_t pmap_offset = (vm_offset_t)cpu0_pmap - cpu0_base;

	for (int i = 0; i < 10; i++) {
		disable_preemption();

		unsigned int cpu_id = fibers_get_assigned_cpu(fibers_current);

		pmap_sptm_percpu_data_t *current_pmap = PERCPU_GET(pmap_sptm_percpu);
		vm_offset_t current_cpu_base = (vm_offset_t)CpuDataEntries[cpu_id].cpu_data_vaddr;
		vm_offset_t expected_current = current_cpu_base + pmap_offset;

		T_ASSERT_EQ((vm_offset_t)current_pmap, expected_current,
		    "PERCPU_GET returns correct address for CPU %u (fiber %d, iteration %d)", cpu_id, fiber_id, i);
		T_ASSERT_EQ((uintptr_t)current_pmap % 8, 0UL,
		    "PERCPU_GET address is 8-byte aligned for CPU %u (fiber %d, iteration %d)", cpu_id, fiber_id, i);

		enable_preemption();

		fibers_yield();
	}

	return NULL;
}

T_DECL(verify_percpu_addresses, "Verify PERCPU_GET returns correct addresses on all CPUs")
{
	fibers_may_yield_probability = 4;
	random_set_seed(1234);

	T_LOG("Testing PERCPU_GET across %u CPUs", fibers_multicpu.cpu_count);

	fiber_t fibers[NUM_TEST_FIBERS];
	for (int i = 0; i < NUM_TEST_FIBERS; i++) {
		fibers[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE,
		    verify_percpu_worker,
		    (void*)(uintptr_t)i);
	}

	for (int i = 0; i < NUM_TEST_FIBERS; i++) {
		fibers_join(fibers[i]);
	}
}

static void*
pmap_epoch_worker(void* arg)
{
	int fiber_id = (int)(uintptr_t)arg;

	// Test pmap_epoch_enter/exit which uses PERCPU_GET internally
	pmap_epoch_t *epoch = pmap_epoch_enter();

	T_ASSERT_NE(epoch->local_seq, 0ULL, "Fiber %d: epoch entered", fiber_id);
	T_ASSERT_EQ(epoch->local_seq, epoch->next_seq, "Fiber %d: sequences match", fiber_id);

	// Do some work while in epoch
	for (int i = 0; i < 10; i++) {
		fibers_yield();
	}

	pmap_epoch_exit(epoch);

	return NULL;
}

T_DECL(pmap_epoch_basic, "Test pmap_epoch_enter/exit from multiple CPUs")
{
	fibers_may_yield_probability = 4;
	random_set_seed(1234);

	T_LOG("Creating %d fibers to test pmap epoch across %u CPUs",
	    NUM_TEST_FIBERS, fibers_multicpu.cpu_count);

	fiber_t fibers[NUM_TEST_FIBERS];
	for (int i = 0; i < NUM_TEST_FIBERS; i++) {
		fibers[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE,
		    pmap_epoch_worker,
		    (void*)(uintptr_t)i);
	}

	for (int i = 0; i < NUM_TEST_FIBERS; i++) {
		fibers_join(fibers[i]);
	}
}
