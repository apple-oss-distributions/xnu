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

// Common fiber tests that work in both single-CPU and multi-CPU modes.
// Fibers avoid context switching when preemption is disabled in single-CPU mode and a fast path is used.
// It is important to run tests that assert the correctness of the fibers implementation on both modes

#pragma once

#include <darwintest.h>

#include "mocks/std_safe.h"
#include "mocks/osfmk/mock_thread.h"
#include "mocks/osfmk/mock_vm.h"
#include "mocks/osfmk/mock_cpu.h"

#include "mocks/osfmk/fibers/fibers.h"
#include "mocks/osfmk/fibers/mutex.h"
#include "mocks/osfmk/fibers/condition.h"
#include "mocks/osfmk/fibers/random.h"

#include <vm/vm_fault_internal.h>
#include <vm/vm_page_internal.h>
#include <kern/ticket_lock.h>

T_MOCK_SET_PERM_FUNC(
	kern_return_t,
	vm_fault_enter_prepare, (
		vm_page_t m,
		pmap_t pmap,
		vm_map_offset_t vaddr,
		vm_prot_t * prot,
		vm_prot_t caller_prot,
		vm_map_size_t fault_page_size,
		vm_map_offset_t fault_phys_offset,
		vm_prot_t fault_type,
		vm_object_fault_info_t fault_info,
		int *type_of_fault,
		bool *page_needs_data_sync))
{
	return KERN_SUCCESS;
}

T_MOCK_SET_PERM_FUNC(
	kern_return_t,
	vm_fault_attempt_pmap_enter, (
		pmap_t pmap,
		vm_map_offset_t vaddr,
		vm_map_size_t fault_page_size,
		vm_map_offset_t fault_phys_offset,
		vm_page_t m,
		vm_prot_t * prot,
		vm_prot_t caller_prot,
		vm_prot_t fault_type,
		bool wired,
		int pmap_options))
{
	return KERN_SUCCESS;
}

// ============================================================================
// Basic Fiber Tests
// ============================================================================

static int global_var;
static void*
tiny_race_func(void* x)
{
	global_var = 42;
	return x;
}

// Standard ThreadSanitizer example in the llvm doc to showcase a race
// TSan will not fail the test by default, you beed to set halt_on_error=1 in TSAN_OPTIONS
// the test will just run fine without TSan, the data race between fibers can be detected with the fibers data race checker too
T_DECL(tsan_tiny_race, "tsan_tiny_race")
{
	// This sometimes triggers a ThreadSanitizer data race depending on the OS scheduler
	pthread_t thread;
	pthread_create(&thread, NULL, tiny_race_func, NULL);
	global_var = 43;
	pthread_join(thread, NULL);

	T_LOG("Done pthread global_var=%d", global_var);

	// This always triggers a ThreadSanitizer data race thanks to the fixed seed
	fibers_log_level = FIBERS_LOG_INFO;
	fibers_may_yield_probability = 1;
	random_set_seed(1234);

	fiber_t fiber = fibers_create(FIBERS_DEFAULT_STACK_SIZE, tiny_race_func, NULL);
	global_var = 43;
	fibers_join(fiber);

	T_LOG("Done fibers global_var=%d", global_var);
	T_PASS("tsan_tiny_race");
}

#define NUM_INCREMENTS 100000
#define NUM_THREADS 10

static void*
increment_counter_nolock(void* arg)
{
	fibers_current->disable_race_checker = 1;

	volatile int64_t *counter = (volatile int64_t *)arg;
	for (int i = 0; i < NUM_INCREMENTS; i++) {
		volatile uint64_t val = *counter;
		fibers_may_yield();
		*counter = val + 1;
	}
	return NULL;
}

T_DECL(increment_test, "increment a counter with fibers")
{
	random_set_seed(1234);

	fiber_t mythreads[NUM_THREADS] = {};
	volatile int64_t counter = 0;

	for (int i = 0; i < NUM_THREADS; i++) {
		mythreads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, increment_counter_nolock, (void*)&counter);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(mythreads[i]);
	}

	T_LOG("Done counter=%lld", os_atomic_load(&counter, relaxed));
	T_ASSERT_NE(counter, (int64_t)(NUM_INCREMENTS * NUM_THREADS), "race detected on counter, thread interleaving works");

	T_PASS("increment_test");
}

// ============================================================================
// Lock Tests
// ============================================================================

struct inc_state {
	volatile int64_t counter;
	lck_mtx_t mtx;
	lck_grp_t grp;
};

static void*
increment_counter(void* arg)
{
	struct inc_state *s = (struct inc_state *)arg;
	for (int i = 0; i < NUM_INCREMENTS; i++) {
		// Remove locks to fail the test and trigger a ThreadSanitizer data race
		lck_mtx_lock(&s->mtx);
		//lck_mtx_lock_spin(&s->mtx);
		s->counter++;
		fibers_may_yield();
		//os_atomic_inc(&s->counter, relaxed);
		lck_mtx_unlock(&s->mtx);
	}
	return NULL;
}

T_DECL(mutex_increment_test, "mutex lock test with fibers")
{
	random_set_seed(1234);

	fiber_t mythreads[NUM_THREADS] = {};
	struct inc_state s = {.counter = 0};
	lck_grp_init(&s.grp, "test_mutex", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&s.mtx, &s.grp, LCK_ATTR_NULL);

	for (int i = 0; i < NUM_THREADS; i++) {
		mythreads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, increment_counter, (void*)&s);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(mythreads[i]);
	}
	lck_mtx_destroy(&s.mtx, &s.grp);

	T_LOG("Done counter=%lld", os_atomic_load(&s.counter, relaxed));
	T_ASSERT_EQ(s.counter, (int64_t)(NUM_INCREMENTS * NUM_THREADS), "race detected on counter");

	T_PASS("mutex_increment_test");
}

extern lck_grp_t vm_page_lck_grp_bucket; // Reuse a VM lock group
static hw_lck_ticket_t test_ticket_lock;
static int64_t test_ticket_counter = 0;

static void*
increment_counter_ticket(void* arg)
{
	for (int i = 0; i < NUM_INCREMENTS; i++) {
		hw_lck_ticket_lock(&test_ticket_lock, &vm_page_lck_grp_bucket);
		test_ticket_counter++;
		hw_lck_ticket_unlock(&test_ticket_lock);
	}
	return NULL;
}

T_DECL(ticket_lock_increment_test, "ticket locks with fibers test")
{
	random_set_seed(1234);

	fiber_t mythreads[NUM_THREADS] = {};
	hw_lck_ticket_init(&test_ticket_lock, &vm_page_lck_grp_bucket);

	for (int i = 0; i < NUM_THREADS; i++) {
		mythreads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, increment_counter_ticket, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(mythreads[i]);
	}

	hw_lck_ticket_destroy(&test_ticket_lock, &vm_page_lck_grp_bucket);

	T_LOG("Done counter=%lld", os_atomic_load(&test_ticket_counter, relaxed));
	T_ASSERT_EQ(test_ticket_counter, (int64_t)(NUM_INCREMENTS * NUM_THREADS), "race detected on counter");

	T_PASS("ticket_lock_increment_test");
}

static lck_grp_t test_grp;
static hw_lck_ticket_t preempt_test_lock;
static volatile int preempt_counter = 0;

static void*
preemption_disabled_lock_worker(void* arg)
{
	for (int i = 0; i < 100; i++) {
		hw_lck_ticket_lock(&preempt_test_lock, &test_grp);
		preempt_counter++;
		hw_lck_ticket_unlock(&preempt_test_lock);
	}
	return NULL;
}

T_DECL(preemption_disabled_locks, "Test locks with preemption disabled")
{
	fibers_may_yield_probability = 16;
	random_set_seed(1234);

	lck_grp_init(&test_grp, "preempt_test", LCK_GRP_ATTR_NULL);
	hw_lck_ticket_init(&preempt_test_lock, &test_grp);

	preempt_counter = 0;

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, preemption_disabled_lock_worker, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	hw_lck_ticket_destroy(&preempt_test_lock, &test_grp);

	T_LOG("Counter: %d", preempt_counter);
	T_ASSERT_EQ(preempt_counter, NUM_THREADS * 100, "All increments completed");

	T_PASS("preemption_disabled_locks");
}

static volatile int interrupt_test_counter = 0;
static lck_mtx_t interrupt_test_lock;

static void*
interrupts_disabled_worker(void* arg)
{
	for (int i = 0; i < 100; i++) {
		boolean_t prev = ml_set_interrupts_enabled(FALSE);

		lck_mtx_lock(&interrupt_test_lock);
		interrupt_test_counter++;
		lck_mtx_unlock(&interrupt_test_lock);

		ml_set_interrupts_enabled(prev);
	}
	return NULL;
}

T_DECL(interrupts_disabled, "Test behavior with interrupts disabled")
{
	fibers_may_yield_probability = 16;
	random_set_seed(1234);

	lck_grp_init(&test_grp, "interrupt_test", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&interrupt_test_lock, &test_grp, LCK_ATTR_NULL);

	interrupt_test_counter = 0;

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, interrupts_disabled_worker, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	lck_mtx_destroy(&interrupt_test_lock, &test_grp);

	T_LOG("Counter: %d", interrupt_test_counter);
	T_ASSERT_EQ(interrupt_test_counter, NUM_THREADS * 100, "All increments completed");

	T_PASS("interrupts_disabled");
}

static lck_rw_t rw_lock;
static volatile int rw_shared_counter = 0;
static volatile int rw_exclusive_counter = 0;

static void*
rw_lock_shared_worker(void* arg)
{
	for (int i = 0; i < 50; i++) {
		lck_rw_lock_shared(&rw_lock);
		int val = rw_shared_counter;
		fibers_yield();
		rw_shared_counter = val;
		lck_rw_unlock_shared(&rw_lock);
	}
	return NULL;
}

static void*
rw_lock_exclusive_worker(void* arg)
{
	for (int i = 0; i < 50; i++) {
		lck_rw_lock_exclusive(&rw_lock);
		rw_exclusive_counter++;
		lck_rw_unlock_exclusive(&rw_lock);
	}
	return NULL;
}

T_DECL(rw_locks, "Test RW locks with fibers")
{
	fibers_may_yield_probability = 8;
	random_set_seed(1234);

	lck_grp_init(&test_grp, "rw_test", LCK_GRP_ATTR_NULL);
	lck_rw_init(&rw_lock, &test_grp, LCK_ATTR_NULL);

	rw_shared_counter = 0;
	rw_exclusive_counter = 0;

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS / 2; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, rw_lock_shared_worker, NULL);
	}
	for (int i = NUM_THREADS / 2; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, rw_lock_exclusive_worker, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	lck_rw_destroy(&rw_lock, &test_grp);

	T_LOG("Exclusive counter: %d", rw_exclusive_counter);
	T_ASSERT_EQ(rw_exclusive_counter, (NUM_THREADS / 2) * 50, "All exclusive increments completed");

	T_PASS("rw_locks");
}

static lck_rw_new_t rw_spin_lock;
static volatile int spin_counter = 0;

static void*
rw_spin_lock_worker(void* arg)
{
	for (int i = 0; i < 100; i++) {
		lck_rw_lock_exclusive_spin(&rw_spin_lock);
		spin_counter++;
		lck_rw_unlock_exclusive_spin(&rw_spin_lock);
	}
	return NULL;
}

T_DECL(rw_spin_locks, "Test RW spin locks with fibers")
{
	fibers_may_yield_probability = 16;
	random_set_seed(1234);

	lck_grp_init(&test_grp, "spin_test", LCK_GRP_ATTR_NULL);
	lck_rw_init(&rw_spin_lock, &test_grp, LCK_ATTR_NULL);

	spin_counter = 0;

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, rw_spin_lock_worker, NULL);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	lck_rw_destroy(&rw_spin_lock, &test_grp);

	T_LOG("Spin counter: %d", spin_counter);
	T_ASSERT_EQ(spin_counter, NUM_THREADS * 100, "All spin increments completed");

	T_PASS("rw_spin_locks");
}

// ============================================================================
// Stress Test
// ============================================================================

static void*
stress_test_worker(void* arg)
{
	for (int i = 0; i < 1000; i++) {
		if (i % 3 == 0) {
			disable_preemption();
			fibers_yield();
			enable_preemption();
		} else if (i % 3 == 1) {
			boolean_t prev = ml_set_interrupts_enabled(FALSE);
			fibers_yield();
			ml_set_interrupts_enabled(prev);
		} else {
			fibers_yield();
		}
	}

	return NULL;
}

T_DECL(stress_test, "Stress test fiber simulation")
{
	fibers_may_yield_probability = 8;
	random_set_seed(1234);

	fiber_t threads[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS; i++) {
		threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, stress_test_worker, (void*)(uintptr_t)i);
	}

	for (int i = 0; i < NUM_THREADS; i++) {
		fibers_join(threads[i]);
	}

	T_PASS("stress_test");
}

// ============================================================================
// VM Tests
// ============================================================================

uint64_t
pack_threads_and_iterations(uint32_t threads, uint32_t iterations)
{
	return (((uint64_t)threads) << 32) | ((uint64_t) iterations);
}

static void *
race_thread_impl(void * args)
{
	int64_t num_threads = (int64_t) args;
	int64_t result = run_sysctl_test("vm_range_lock_race_test", num_threads, 0, NULL);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_range_lock_race_test");
	return NULL;
}

static void
test_n_threads_for_n_iterations(uint32_t thread_count, uint32_t iterations, void *  (*func)(void *))
{
	fiber_t * race_threads = malloc(sizeof(fiber_t) * thread_count);
	for (size_t i = 0; i < thread_count; i++) {
		race_threads[i] = fibers_create(FIBERS_DEFAULT_STACK_SIZE, func, (void *) pack_threads_and_iterations(thread_count, iterations));
	}

	for (size_t i = 0; i < thread_count; i++) {
		fibers_join(race_threads[i]);
	}
	free(race_threads);
	T_PASS("test_threads(%u)", thread_count);
}

T_DECL(vm_range_lock_race_test, "vm_range_lock_race_test with fibers")
{
	random_set_seed(4);
	test_n_threads_for_n_iterations(32, 10000, race_thread_impl);
}

static vm_object_t dst_object;
static vm_page_t dst_page;
static vm_object_t src_object;
static vm_page_t src_page;

void
radar_148801298_setup(void)
{
	dst_object = vm_object_allocate(PAGE_SIZE * 12, VM_MAP_SERIAL_NONE);

	dst_page = vm_page_grab_options(0);
	vm_object_lock(dst_object);
	vm_page_insert(dst_page, dst_object, 0);
	vm_page_lockspin_queues();

	vm_page_wire(dst_page, VM_KERN_MEMORY_OSFMK, true);
	vm_page_unlock_queues();

	// avoid assertion in vm_page_wakeup_done
	dst_page->vmp_busy = true;

	vm_page_wakeup_done(dst_object, dst_page);
	vm_object_unlock(dst_object);

	src_object = vm_object_allocate(PAGE_SIZE * 12, VM_MAP_SERIAL_NONE);
	src_page = vm_page_grab_options(0);
	vm_object_lock(src_object);
	vm_page_insert(src_page, src_object, 0);

	// avoid assertion in vm_page_wakeup_done
	src_page->vmp_busy = true;

	vm_page_wakeup_done(src_object, src_page);
	vm_object_unlock(src_object);
}

static void*
radar_148801298_thread_one(void * param __unused)
{
	volatile vm_page_t page = dst_page;
	vm_object_lock(dst_object);
	page->vmp_busy = true;
	vm_object_unlock(dst_object);

	T_QUIET; T_ASSERT_TRUE(page->vmp_busy, "vmp_busy still true");

	vm_object_lock(dst_object);
	page->vmp_busy = false;
	vm_object_unlock(dst_object);

	T_QUIET; T_ASSERT_FALSE(page->vmp_busy, "vmp_busy still false");
	return NULL;
}

static void*
radar_148801298_thread_two(void * param __unused)
{
	vm_object_lock(src_object);
	vm_page_copy(src_page, dst_page);
	vm_object_unlock(src_object);
	return NULL;
}

/*
 * Try to reproduce rdar://148801298 with just two threads without any while loop in the
 * thread functions (unlike the sysctl test attached to the radar).
 * This will simulate a fuzzer scenario that generates few calls and mutate for a while
 * only the threads interlevings, the random seed in this case.
 */
T_DECL(vm_radar_148801298, "vm_radar_148801298 reproduction with fibers")
{
	const uint64_t iterations = 10000;

	fibers_debug = 1;
	fibers_may_yield_probability = 16;

	radar_148801298_setup();

	for (uint64_t cnt = 0; cnt < iterations; cnt++) {
		random_set_seed(cnt);
		if (cnt % 500 == 0) {
			printf("iteration %llu\n", cnt);
		}

		fiber_t first = fibers_create(FIBERS_DEFAULT_STACK_SIZE, radar_148801298_thread_one, NULL);
		fiber_t second = fibers_create(FIBERS_DEFAULT_STACK_SIZE, radar_148801298_thread_two, NULL);

		fibers_join(first);
		fibers_join(second);
	}
	T_PASS("vm_radar_148801298");
}

static void *
vm_map_wire_race_test_thread_one_caller(void * args)
{
	current_thread()->map = (vm_map_t)args;

	int64_t result = run_sysctl_test("vm_map_wire_race_test_thread_one", 0, 0, NULL);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_map_wire_race_test_thread_one failed");
	return NULL;
}

static void *
vm_map_wire_race_test_thread_two_caller(void * args)
{
	current_thread()->map = (vm_map_t)args;

	int64_t result = run_sysctl_test("vm_map_wire_race_test_thread_two", 0, 0, NULL);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_map_wire_race_test_thread_two failed");
	return NULL;
}

T_DECL(wire_concurrent_deletion_test, "Test concurrent deletions against a kernel wiring")
{
	vm_map_t map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
	current_thread()->map = map;
	current_task()->map = map;

	int64_t result = run_sysctl_test("vm_map_wire_race_test_setup", 0, 0, NULL);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "setup");

	fiber_t first = fibers_create(FIBERS_DEFAULT_STACK_SIZE, vm_map_wire_race_test_thread_one_caller, (void*)map);
	fiber_t second = fibers_create(FIBERS_DEFAULT_STACK_SIZE, vm_map_wire_race_test_thread_two_caller, (void*)map);

	// Simulate sleep with several ctxswitch
	for (int i = 0; i < 200000; ++i) {
		fibers_yield();
	}

	int race_hits = run_sysctl_test("vm_map_wire_race_test_signal_end", 0, 0, NULL);
	T_LOG("Hit the race we intend to hit: %i times\n", race_hits);

	fibers_join(first);
	fibers_join(second);

	run_sysctl_test("vm_map_wire_race_test_cleanup", 0, 0, NULL);

	T_PASS("wire_concurrent_deletion_test: Test didn't panic");
}
