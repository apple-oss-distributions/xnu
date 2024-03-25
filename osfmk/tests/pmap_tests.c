/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <kern/ledger.h>
#include <kern/thread.h>
#if defined(__arm64__)
#include <pexpert/arm64/board_config.h>
#if CONFIG_SPTM
#include <arm64/sptm/pmap/pmap_pt_geometry.h>
#else /* CONFIG_SPTM */
#include <arm/pmap/pmap_pt_geometry.h>
#endif /* CONFIG_SPTM */
#endif /* defined(__arm64__) */
#include <vm/vm_map.h>

extern void read_random(void* buffer, u_int numBytes);

extern ledger_template_t task_ledger_template;

extern boolean_t arm_force_fast_fault(ppnum_t, vm_prot_t, int, void*);
extern kern_return_t arm_fast_fault(pmap_t, vm_map_address_t, vm_prot_t, bool, bool);

kern_return_t test_pmap_enter_disconnect(unsigned int num_loops);
kern_return_t test_pmap_compress_remove(unsigned int num_loops);
kern_return_t test_pmap_exec_remove(unsigned int num_loops);
kern_return_t test_pmap_nesting(unsigned int num_loops);
kern_return_t test_pmap_iommu_disconnect(void);
kern_return_t test_pmap_extended(void);
void test_pmap_call_overhead(unsigned int num_loops);
uint64_t test_pmap_page_protect_overhead(unsigned int num_loops, unsigned int num_aliases);
#if CONFIG_SPTM
kern_return_t test_pmap_huge_pv_list(unsigned int num_loops, unsigned int num_mappings);
#endif

#define PMAP_TEST_VA (0xDEADULL << PAGE_SHIFT)

typedef struct {
	pmap_t pmap;
	vm_map_address_t va;
	processor_t proc;
	ppnum_t pn;
	volatile boolean_t stop;
} pmap_test_thread_args;


/**
 * Helper for creating a new pmap to be used for testing.
 *
 * @param flags Flags to pass to pmap_create_options()
 *
 * @return The newly-allocated pmap, or NULL if allocation fails.
 */
static pmap_t
pmap_create_wrapper(unsigned int flags)
{
	pmap_t new_pmap = NULL;
	ledger_t ledger;
	assert(task_ledger_template != NULL);
	if ((ledger = ledger_instantiate(task_ledger_template, LEDGER_CREATE_ACTIVE_ENTRIES)) == NULL) {
		return NULL;
	}
	new_pmap = pmap_create_options(ledger, 0, flags);
	ledger_dereference(ledger);
	return new_pmap;
}

/**
 * Helper for allocating a wired VM page to be used for testing.
 *
 * @note The allocated page will be wired with the VM_KERN_MEMORY_PTE tag,
 *       which will attribute the page to the pmap module.
 *
 * @return the newly-allocated vm_page_t, or NULL if allocation fails.
 */
static vm_page_t
pmap_test_alloc_vm_page(void)
{
	vm_page_t m = vm_page_grab();
	if (m != VM_PAGE_NULL) {
		vm_page_lock_queues();
		vm_page_wire(m, VM_KERN_MEMORY_PTE, TRUE);
		vm_page_unlock_queues();
	}
	return m;
}

/**
 * Helper for freeing a VM page previously allocated by pmap_test_alloc_vm_page().
 *
 * @param m The page to free.  This may be NULL, in which case this function will
 *          do nothing.
 */
static void
pmap_test_free_vm_page(vm_page_t m)
{
	if (m != VM_PAGE_NULL) {
		vm_page_lock_queues();
		vm_page_free(m);
		vm_page_unlock_queues();
	}
}

static void
pmap_disconnect_thread(void *arg, wait_result_t __unused wres)
{
	pmap_test_thread_args *args = arg;
	do {
		pmap_disconnect(args->pn);
	} while (!args->stop);
	thread_wakeup((event_t)args);
}

kern_return_t
test_pmap_enter_disconnect(unsigned int num_loops)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t disconnect_thread;
	pmap_t new_pmap = pmap_create_wrapper(0);
	if (new_pmap == NULL) {
		return KERN_FAILURE;
	}
	vm_page_t m = pmap_test_alloc_vm_page();
	if (m == VM_PAGE_NULL) {
		pmap_destroy(new_pmap);
		return KERN_FAILURE;
	}
	ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);
	pmap_test_thread_args args = {.pmap = new_pmap, .stop = FALSE, .pn = phys_page};
	kern_return_t res = kernel_thread_start_priority(pmap_disconnect_thread,
	    &args, thread_kern_get_pri(current_thread()), &disconnect_thread);
	if (res) {
		pmap_destroy(new_pmap);
		pmap_test_free_vm_page(m);
		return res;
	}
	thread_deallocate(disconnect_thread);

	while (num_loops-- != 0) {
		kr = pmap_enter(new_pmap, PMAP_TEST_VA, phys_page,
		    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_MAPPING_TYPE_INFER);
		assert(kr == KERN_SUCCESS);
	}

	assert_wait((event_t)&args, THREAD_UNINT);
	args.stop = TRUE;
	thread_block(THREAD_CONTINUE_NULL);

	pmap_remove(new_pmap, PMAP_TEST_VA, PMAP_TEST_VA + PAGE_SIZE);
	pmap_test_free_vm_page(m);
	pmap_destroy(new_pmap);
	return KERN_SUCCESS;
}

static void
pmap_remove_thread(void *arg, wait_result_t __unused wres)
{
	pmap_test_thread_args *args = arg;
	do {
		kern_return_t kr = pmap_enter_options(args->pmap, args->va, args->pn,
		    VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_OPTIONS_INTERNAL, NULL, PMAP_MAPPING_TYPE_INFER);
		assert(kr == KERN_SUCCESS);
		pmap_remove(args->pmap, args->va, args->va + PAGE_SIZE);
	} while (!args->stop);
	thread_wakeup((event_t)args);
}

/**
 * Test that a mapping to a physical page can be concurrently removed while
 * the page is being compressed, without triggering accounting panics.
 *
 * @param num_loops The number of test loops to run
 *
 * @return KERN_SUCCESS if the test runs to completion, otherwise an
 *         appropriate error code.
 */
kern_return_t
test_pmap_compress_remove(unsigned int num_loops)
{
	thread_t remove_thread;
	pmap_t new_pmap = pmap_create_wrapper(0);
	if (new_pmap == NULL) {
		return KERN_FAILURE;
	}
	vm_page_t m = pmap_test_alloc_vm_page();
	if (m == VM_PAGE_NULL) {
		pmap_destroy(new_pmap);
		return KERN_FAILURE;
	}
	ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);
	pmap_test_thread_args args = {.pmap = new_pmap, .stop = FALSE, .va = PMAP_TEST_VA, .pn = phys_page};
	kern_return_t res = kernel_thread_start_priority(pmap_remove_thread,
	    &args, thread_kern_get_pri(current_thread()), &remove_thread);
	if (res) {
		pmap_destroy(new_pmap);
		pmap_test_free_vm_page(m);
		return res;
	}
	thread_deallocate(remove_thread);

	while (num_loops-- != 0) {
		pmap_disconnect_options(phys_page, PMAP_OPTIONS_COMPRESSOR, NULL);
	}

	assert_wait((event_t)&args, THREAD_UNINT);
	args.stop = TRUE;
	thread_block(THREAD_CONTINUE_NULL);

	pmap_remove(new_pmap, PMAP_TEST_VA, PMAP_TEST_VA + PAGE_SIZE);
	pmap_destroy(new_pmap);
	pmap_test_free_vm_page(m);
	return KERN_SUCCESS;
}


kern_return_t
test_pmap_exec_remove(unsigned int num_loops __unused)
{
	return KERN_NOT_SUPPORTED;
}


#if defined(__arm64__)

static const vm_map_address_t nesting_start = SHARED_REGION_BASE;
static const vm_map_address_t nesting_size = 16 * ARM_16K_TT_L2_SIZE;

static void
pmap_nest_thread(void *arg, wait_result_t __unused wres)
{
	const pmap_test_thread_args *args = arg;
	pmap_t main_pmap = pmap_create_wrapper(0);
	kern_return_t kr;

	thread_bind(args->proc);
	thread_block(THREAD_CONTINUE_NULL);

	/**
	 * Exercise nesting and unnesting while bound to the specified CPU (if non-NULL).
	 * The unnesting size here should match the unnesting size used in the first
	 * unnesting step of the main thread, in order to avoid concurrently unnesting
	 * beyond that region and violating the checks against over-unnesting performed
	 * in the main thread.
	 */
	if (main_pmap != NULL) {
		kr = pmap_nest(main_pmap, args->pmap, nesting_start, nesting_size);
		assert(kr == KERN_SUCCESS);

		kr = pmap_unnest(main_pmap, nesting_start, nesting_size - ARM_16K_TT_L2_SIZE);
		assert(kr == KERN_SUCCESS);
	}

	thread_bind(PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);

	assert_wait((event_t)(uintptr_t)&(args->stop), THREAD_UNINT);
	if (!args->stop) {
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		clear_wait(current_thread(), THREAD_AWAKENED);
	}

	/* Unnest all remaining mappings so that we can safely destroy our pmap. */
	if (main_pmap != NULL) {
		kr = pmap_unnest(main_pmap, nesting_start + nesting_size - ARM_16K_TT_L2_SIZE, ARM_16K_TT_L2_SIZE);
		assert(kr == KERN_SUCCESS);
		pmap_destroy(main_pmap);
	}

	thread_wakeup((event_t)arg);
}

/**
 * Test that pmap_nest() and pmap_unnest() work correctly when executed concurrently from
 * multiple threads.  Spawn some worker threads at elevated priority and bound to the
 * same CPU in order to provoke preemption of the nest/unnest operation.
 *
 * @param num_loops The number of nest/unnest loops to perform.  This should be kept to
 *        a small number because each cycle is expensive and may consume a global shared
 *        region ID.
 *
 * @return KERN_SUCCESS if all tests succeed, an appropriate error code otherwise.
 */
kern_return_t
test_pmap_nesting(unsigned int num_loops)
{
	kern_return_t kr = KERN_SUCCESS;

	vm_page_t m1 = VM_PAGE_NULL, m2 = VM_PAGE_NULL;

	m1 = pmap_test_alloc_vm_page();
	m2 = pmap_test_alloc_vm_page();
	if ((m1 == VM_PAGE_NULL) || (m2 == VM_PAGE_NULL)) {
		kr = KERN_FAILURE;
		goto test_nesting_cleanup;
	}
	const ppnum_t pp1 = VM_PAGE_GET_PHYS_PAGE(m1);
	const ppnum_t pp2 = VM_PAGE_GET_PHYS_PAGE(m2);
	for (unsigned int i = 0; (i < num_loops) && (kr == KERN_SUCCESS); i++) {
		pmap_t nested_pmap = pmap_create_wrapper(0);
		pmap_t main_pmap = pmap_create_wrapper(0);
		if ((nested_pmap == NULL) || (main_pmap == NULL)) {
			pmap_destroy(main_pmap);
			pmap_destroy(nested_pmap);
			kr = KERN_FAILURE;
			break;
		}
		pmap_set_nested(nested_pmap);
		for (vm_map_address_t va = nesting_start; va < (nesting_start + nesting_size); va += PAGE_SIZE) {
			uint8_t rand;
			read_random(&rand, sizeof(rand));
			uint8_t rand_mod = rand % 3;
			if (rand_mod == 0) {
				continue;
			}
			kr = pmap_enter(nested_pmap, va, (rand_mod == 1) ? pp1 : pp2, VM_PROT_READ,
			    VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_MAPPING_TYPE_INFER);
			assert(kr == KERN_SUCCESS);
		}
		kr = pmap_nest(main_pmap, nested_pmap, nesting_start, nesting_size);
		assert(kr == KERN_SUCCESS);

		/* Validate the initial nest operation produced global mappings within the nested pmap. */
		for (vm_map_address_t va = nesting_start; va < (nesting_start + nesting_size); va += PAGE_SIZE) {
			pt_entry_t *nested_pte = pmap_pte(nested_pmap, va);
			pt_entry_t *main_pte = pmap_pte(main_pmap, va);
			if (nested_pte != main_pte) {
				panic("%s: nested_pte (%p) is not identical to main_pte (%p) for va 0x%llx",
				    __func__, nested_pte, main_pte, (unsigned long long)va);
			}
			if ((nested_pte != NULL) && (*nested_pte != ARM_PTE_EMPTY) && (*nested_pte & ARM_PTE_NG)) {
				panic("%s: nested_pte (%p) is not global for va 0x%llx",
				    __func__, nested_pte, (unsigned long long)va);
			}
		}

		/* Now kick off various worker threads to concurrently nest and unnest. */
		const processor_t nest_proc = current_processor();
		thread_bind(nest_proc);
		thread_block(THREAD_CONTINUE_NULL);

		/**
		 * Avoid clogging the CPUs with high-priority kernel threads on older devices.
		 * Testing has shown this may provoke a userspace watchdog timeout.
		 */
		#define TEST_NEST_THREADS 4
		#if TEST_NEST_THREADS >= MAX_CPUS
		#undef TEST_NEST_THREADS
		#define TEST_NEST_THREADS MAX_CPUS - 1
		#endif
		thread_t nest_threads[TEST_NEST_THREADS];
		kern_return_t thread_krs[TEST_NEST_THREADS];
		pmap_test_thread_args args[TEST_NEST_THREADS];
		for (unsigned int j = 0; j < (sizeof(nest_threads) / sizeof(nest_threads[0])); j++) {
			args[j].pmap = nested_pmap;
			args[j].stop = FALSE;
			/**
			 * Spawn the worker threads at various priorities at the high end of the kernel range,
			 * and bind every other thread to the same CPU as this thread to provoke preemption,
			 * while also allowing some threads to run concurrently on other CPUs.
			 */
			args[j].proc = ((j % 2) ? PROCESSOR_NULL : nest_proc);
			thread_krs[j] = kernel_thread_start_priority(pmap_nest_thread, &args[j], MAXPRI_KERNEL - (j % 4), &nest_threads[j]);
			if (thread_krs[j] == KERN_SUCCESS) {
				thread_set_thread_name(nest_threads[j], "pmap_nest_thread");
			}
		}

		/* Unnest the bulk of the nested region and validate that it produced the expected PTE contents. */
		kr = pmap_unnest(main_pmap, nesting_start, nesting_size - ARM_16K_TT_L2_SIZE);
		assert(kr == KERN_SUCCESS);

		for (vm_map_address_t va = nesting_start; va < (nesting_start + nesting_size - ARM_16K_TT_L2_SIZE); va += PAGE_SIZE) {
			pt_entry_t *nested_pte = pmap_pte(nested_pmap, va);
			pt_entry_t *main_pte = pmap_pte(main_pmap, va);

			if (main_pte != NULL) {
				panic("%s: main_pte (%p) is not NULL for unnested VA 0x%llx",
				    __func__, main_pte, (unsigned long long)va);
			}
			if ((nested_pte != NULL) && (*nested_pte != ARM_PTE_EMPTY) && !(*nested_pte & ARM_PTE_NG)) {
				panic("%s: nested_pte (%p) is global for va 0x%llx following unnest",
				    __func__, nested_pte, (unsigned long long)va);
			}
		}

		/* Validate that the prior unnest did not unnest too much. */
		for (vm_map_address_t va = nesting_start + nesting_size - ARM_16K_TT_L2_SIZE; va < (nesting_start + nesting_size); va += PAGE_SIZE) {
			pt_entry_t *nested_pte = pmap_pte(nested_pmap, va);
			pt_entry_t *main_pte = pmap_pte(main_pmap, va);
			if (nested_pte != main_pte) {
				panic("%s: nested_pte (%p) is not identical to main_pte (%p) for va 0x%llx following adjacent unnest",
				    __func__, nested_pte, main_pte, (unsigned long long)va);
			}
			if ((nested_pte != NULL) && (*nested_pte != ARM_PTE_EMPTY) && (*nested_pte & ARM_PTE_NG)) {
				panic("%s: nested_pte (%p) is not global for va 0x%llx following adjacent unnest",
				    __func__, nested_pte, (unsigned long long)va);
			}
		}

		/* Now unnest the remainder. */
		kr = pmap_unnest(main_pmap, nesting_start + nesting_size - ARM_16K_TT_L2_SIZE, ARM_16K_TT_L2_SIZE);
		assert(kr == KERN_SUCCESS);

		thread_bind(PROCESSOR_NULL);
		thread_block(THREAD_CONTINUE_NULL);

		for (vm_map_address_t va = nesting_start + nesting_size - ARM_16K_TT_L2_SIZE; va < (nesting_start + nesting_size); va += PAGE_SIZE) {
			pt_entry_t *nested_pte = pmap_pte(nested_pmap, va);
			pt_entry_t *main_pte = pmap_pte(main_pmap, va);

			if (main_pte != NULL) {
				panic("%s: main_pte (%p) is not NULL for unnested VA 0x%llx",
				    __func__, main_pte, (unsigned long long)va);
			}
			if ((nested_pte != NULL) && (*nested_pte != ARM_PTE_EMPTY) && !(*nested_pte & ARM_PTE_NG)) {
				panic("%s: nested_pte (%p) is global for va 0x%llx following unnest",
				    __func__, nested_pte, (unsigned long long)va);
			}
		}

		for (unsigned int j = 0; j < (sizeof(nest_threads) / sizeof(nest_threads[0])); j++) {
			if (thread_krs[j] == KERN_SUCCESS) {
				assert_wait((event_t)&args[j], THREAD_UNINT);
				args[j].stop = TRUE;
				thread_wakeup((event_t)(uintptr_t)&(args[j].stop));
				thread_block(THREAD_CONTINUE_NULL);
			} else {
				kr = thread_krs[j];
			}
		}
		pmap_remove(nested_pmap, nesting_start, nesting_start + nesting_size);
		pmap_destroy(main_pmap);
		pmap_destroy(nested_pmap);
	}

test_nesting_cleanup:
	pmap_test_free_vm_page(m1);
	pmap_test_free_vm_page(m2);

	return kr;
}

#else /* defined(__arm64__) */

kern_return_t
test_pmap_nesting(unsigned int num_loops __unused)
{
	return KERN_NOT_SUPPORTED;
}

#endif /* defined(__arm64__) */

kern_return_t
test_pmap_iommu_disconnect(void)
{
	return KERN_SUCCESS;
}


kern_return_t
test_pmap_extended(void)
{
#if !CONFIG_SPTM /* SPTM TODO: remove this condition once the SPTM supports 4K and stage-2 mappings */
#endif /* !CONFIG_SPTM */
	return KERN_SUCCESS;
}

void
test_pmap_call_overhead(unsigned int num_loops __unused)
{
#if defined(__arm64__)
	pmap_t pmap = current_thread()->map->pmap;
	for (unsigned int i = 0; i < num_loops; ++i) {
		pmap_nop(pmap);
	}
#endif
}

uint64_t
test_pmap_page_protect_overhead(unsigned int num_loops __unused, unsigned int num_aliases __unused)
{
	uint64_t duration = 0;
#if defined(__arm64__)
	pmap_t new_pmap = pmap_create_wrapper(0);
	vm_page_t m = pmap_test_alloc_vm_page();
	kern_return_t kr = KERN_SUCCESS;

	if ((new_pmap == NULL) || (m == VM_PAGE_NULL)) {
		goto ppo_cleanup;
	}

	ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);

	for (unsigned int loop = 0; loop < num_loops; ++loop) {
		for (unsigned int alias = 0; alias < num_aliases; ++alias) {
			kr = pmap_enter(new_pmap, PMAP_TEST_VA + (PAGE_SIZE * alias), phys_page,
			    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_MAPPING_TYPE_INFER);
			assert(kr == KERN_SUCCESS);
		}

		uint64_t start_time = mach_absolute_time();

		pmap_page_protect_options(phys_page, VM_PROT_READ, 0, NULL);

		duration += (mach_absolute_time() - start_time);

		pmap_remove(new_pmap, PMAP_TEST_VA, PMAP_TEST_VA + (num_aliases * PAGE_SIZE));
	}

ppo_cleanup:
	pmap_test_free_vm_page(m);
	if (new_pmap != NULL) {
		pmap_destroy(new_pmap);
	}
#endif
	return duration;
}

#if CONFIG_SPTM

typedef struct {
	pmap_test_thread_args args;
	unsigned int num_mappings;
	volatile unsigned int nthreads;
	thread_call_t panic_callout;
} pmap_hugepv_test_thread_args;

/**
 * Worker thread that exercises pmap_remove() and pmap_enter() with a huge PV list.
 * This thread relies on the fact that PV lists are structured with newer PTEs at
 * the beginning of the list, so it maximizes PV list traversal time by removing
 * mappings sequentially starting with the beginning VA of the mapping region
 * (thus the oldest mapping), and then re-entering that removed mapping at the
 * beginning of the list.
 *
 * @param arg Thread argument parameter, actually of type pmap_hugepv_test_thread_args*
 * @param wres Wait result, currently unused.
 */
static void
hugepv_remove_enter_thread(void *arg, wait_result_t __unused wres)
{
	unsigned int mapping = 0;
	pmap_hugepv_test_thread_args *args = arg;
	do {
		vm_map_address_t va = args->args.va + ((vm_offset_t)mapping << PAGE_SHIFT);
		pmap_remove(args->args.pmap, va, va + PAGE_SIZE);
		kern_return_t kr = pmap_enter_options(args->args.pmap, va, args->args.pn,
		    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_OPTIONS_INTERNAL,
		    NULL, PMAP_MAPPING_TYPE_INFER);
		assert(kr == KERN_SUCCESS);
		if (++mapping == args->num_mappings) {
			mapping = 0;
		}
	} while (!args->args.stop);
	/* Ensure the update of nthreads is not speculated ahead of checking the stop flag. */
	os_atomic_thread_fence(acquire);
	if (os_atomic_dec(&args->nthreads, relaxed) == 0) {
		thread_wakeup((event_t)args);
	}
}

/**
 * Worker thread to exercise fast-fault behavior with a huge PV list.
 * This thread first removes permissions from all mappings for the page, which
 * does not actually remove the mappings but rather clears their AF bit.
 * It then simulates a fast fault on one random mapping in the list, which
 * also clears the fast-fault state for the first 64  mappings in the list.
 *
 * @param arg Thread argument parameter, actually of type pmap_hugepv_test_thread_args*
 * @param wres Wait result, currently unused.
 */
static void
hugepv_fast_fault_thread(void *arg, wait_result_t __unused wres)
{
	pmap_hugepv_test_thread_args *args = arg;
	do {
		boolean_t success = arm_force_fast_fault(args->args.pn, VM_PROT_NONE, 0, NULL);
		assert(success);
		unsigned int rand;
		read_random(&rand, sizeof(rand));
		unsigned int mapping = rand % args->num_mappings;
		arm_fast_fault(args->args.pmap, args->args.va + ((vm_offset_t)mapping << PAGE_SHIFT), VM_PROT_READ, false, FALSE);
	} while (!args->args.stop);
	/* Ensure the update of nthreads is not speculated ahead of checking the stop flag. */
	os_atomic_thread_fence(acquire);
	if (os_atomic_dec(&args->nthreads, relaxed) == 0) {
		thread_wakeup((event_t)args);
	}
}

/**
 * Worker thread for updating cacheability of a physical page with a huge PV list.
 * This thread simply twiddles all mappings between write-combined and normal (write-back)
 * cacheability.
 *
 * @param arg Thread argument parameter, actually of type pmap_hugepv_test_thread_args*
 * @param wres Wait result, currently unused.
 */
static void
hugepv_cache_attr_thread(void *arg, wait_result_t __unused wres)
{
	pmap_hugepv_test_thread_args *args = arg;
	do {
		pmap_set_cache_attributes(args->args.pn, VM_WIMG_WCOMB);
		pmap_set_cache_attributes(args->args.pn, VM_WIMG_DEFAULT);
	} while (!args->args.stop);
	/* Ensure the update of nthreads is not speculated ahead of checking the stop flag. */
	os_atomic_thread_fence(acquire);
	if (os_atomic_dec(&args->nthreads, relaxed) == 0) {
		thread_wakeup((event_t)args);
	}
}

/**
 * Helper function for starting the 2.5-minute panic timer to ensure that we
 * don't get stuck during test teardown.
 *
 * @param panic_callout The timer call to use for the panic callout.
 */
static inline void
huge_pv_start_panic_timer(thread_call_t panic_callout)
{
	uint64_t deadline;
	clock_interval_to_deadline(150, NSEC_PER_SEC, &deadline);
	thread_call_enter_delayed(panic_callout, deadline);
}

/**
 * Timer callout that executes in case the huge PV test incurs excessive (>= 5min)
 * runtime, which can happen due to unlucky scheduling of the main thread.  In this
 * case we simply set the "stop" flag and expect the worker threads to exit gracefully.
 *
 * @param param0 The pmap_hugepv_test_thread_args used to control the test, cast
 *               as thread_call_param_t.
 * @param param1 Unused argument.
 */
static void
huge_pv_test_timeout(thread_call_param_t param0, __unused thread_call_param_t param1)
{
	pmap_hugepv_test_thread_args *args = (pmap_hugepv_test_thread_args*)param0;
	args->args.stop = TRUE;
	huge_pv_start_panic_timer(args->panic_callout);
}

/**
 * Timer callout that executes in case the huge PV test was canceled by
 * huge_pv_test_timeout above, but failed to terminate within 2.5 minutes.
 * This callout simply panics to allow inspection of the resultant coredump,
 * as it should never be reached under correct operation.
 *
 * @param param0 Unused argument.
 * @param param1 Unused argument.
 */
static void __attribute__((noreturn))
huge_pv_test_panic(__unused thread_call_param_t param0, __unused thread_call_param_t param1)
{
	panic("%s: test timed out", __func__);
}

/**
 * Main test thread for exercising contention on a massive physical-to-virtual
 * mapping list in the pmap.  This thread creates a large number of mappings
 * (as requested by the caller) to the same physical page, spawns the above
 * worker threads to do different operations on that physical page, then while
 * that is going on it repeatedly calls pmap_page_protect_options() on the page,
 * for the number of loops specified by the caller.
 *
 * @param num_loops Number of iterations to execute in the main thread before
 *                  stopping the workers.
 * @param num_mappings The number of alias mappings to create for the same
 *                     physical page.
 *
 * @return KERN_SUCCESS if the test succeeds, KERN_FAILURE if it encounters
 *         an unexpected setup failure.  Any failed integrity check during
 *         the actual execution of the worker threads will panic.
 */
kern_return_t
test_pmap_huge_pv_list(unsigned int num_loops, unsigned int num_mappings)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t remove_enter_thread, fast_fault_thread, cache_attr_thread;
	if ((num_loops == 0) || (num_mappings == 0)) {
		/**
		 * If num_mappings is 0, we'll get into a case in which the
		 * remove_enter_thread leaves a single dangling mapping, triggering
		 * a panic when we free the page.  This isn't a valid test
		 * configuration anyway.
		 */
		return KERN_SUCCESS;
	}
	pmap_t new_pmap = pmap_create_wrapper(0);
	if (new_pmap == NULL) {
		return KERN_FAILURE;
	}
	vm_page_t m = pmap_test_alloc_vm_page();
	if (m == VM_PAGE_NULL) {
		pmap_destroy(new_pmap);
		return KERN_FAILURE;
	}

	ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);

	for (unsigned int mapping = 0; mapping < num_mappings; ++mapping) {
		kr = pmap_enter(new_pmap, PMAP_TEST_VA + ((vm_offset_t)mapping << PAGE_SHIFT), phys_page,
		    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE, PMAP_MAPPING_TYPE_INFER);
		assert(kr == KERN_SUCCESS);
	}

	thread_call_t huge_pv_panic_call = thread_call_allocate(huge_pv_test_panic, NULL);

	pmap_hugepv_test_thread_args args = {
		.args = {.pmap = new_pmap, .stop = FALSE, .va = PMAP_TEST_VA, .pn = phys_page},
		.nthreads = 0, .num_mappings = num_mappings, .panic_callout = huge_pv_panic_call
	};

	thread_call_t huge_pv_timer_call = thread_call_allocate(huge_pv_test_timeout, &args);

	kr = kernel_thread_start_priority(hugepv_remove_enter_thread,
	    &args, thread_kern_get_pri(current_thread()), &remove_enter_thread);
	if (kr != KERN_SUCCESS) {
		goto hugepv_cleanup;
	}
	++args.nthreads;
	thread_deallocate(remove_enter_thread);

	kr = kernel_thread_start_priority(hugepv_fast_fault_thread, &args,
	    thread_kern_get_pri(current_thread()), &fast_fault_thread);
	if (kr != KERN_SUCCESS) {
		goto hugepv_cleanup;
	}
	++args.nthreads;
	thread_deallocate(fast_fault_thread);

	kr = kernel_thread_start_priority(hugepv_cache_attr_thread, &args,
	    thread_kern_get_pri(current_thread()), &cache_attr_thread);
	if (kr != KERN_SUCCESS) {
		goto hugepv_cleanup;
	}
	++args.nthreads;
	thread_deallocate(cache_attr_thread);

	/**
	 * Set up a 5 minute timer to gracefully halt the test upon expiry.
	 * Ordinarily the test should complete in well less than 5 minutes,
	 * but it can run longer and hit the 10 minute BATS timeout if this
	 * thread is really unlucky w.r.t. scheduling (which can happen if
	 * it is repeatedly preempted and starved by the other threads
	 * contending on the PVH lock).
	 */
	uint64_t deadline;
	clock_interval_to_deadline(300, NSEC_PER_SEC, &deadline);
	thread_call_enter_delayed(huge_pv_timer_call, deadline);

	for (unsigned int i = 0; (i < num_loops) && !args.args.stop; i++) {
		pmap_page_protect_options(phys_page, VM_PROT_READ, 0, NULL);
		/**
		 * Yield briefly to give the other workers a chance to get through
		 * more iterations.
		 */
		__builtin_arm_wfe();
	}

	pmap_disconnect_options(phys_page, PMAP_OPTIONS_COMPRESSOR, NULL);

hugepv_cleanup:
	thread_call_cancel_wait(huge_pv_timer_call);
	thread_call_free(huge_pv_timer_call);

	if (__improbable(args.args.stop)) {
		/**
		 * If stop is already set, we hit the timeout, so we can't safely block waiting for
		 * the workers to terminate as they may already be doing so.  Spin in a WFE loop
		 * instead.
		 */
		while (os_atomic_load_exclusive(&args.nthreads, relaxed) != 0) {
			__builtin_arm_wfe();
		}
		os_atomic_clear_exclusive();
	} else if (args.nthreads > 0) {
		/* Ensure prior stores to nthreads are visible before the update to args.args.stop. */
		os_atomic_thread_fence(release);
		huge_pv_start_panic_timer(huge_pv_panic_call);
		assert_wait((event_t)&args, THREAD_UNINT);
		args.args.stop = TRUE;
		thread_block(THREAD_CONTINUE_NULL);
		assert(args.nthreads == 0);
	}

	thread_call_cancel_wait(huge_pv_panic_call);
	thread_call_free(huge_pv_panic_call);

	if (new_pmap != NULL) {
		pmap_remove(new_pmap, PMAP_TEST_VA, PMAP_TEST_VA + ((vm_offset_t)num_mappings << PAGE_SHIFT));
	}

	pmap_test_free_vm_page(m);
	if (new_pmap != NULL) {
		pmap_destroy(new_pmap);
	}

	return kr;
}

#endif /* CONFIG_SPTM */
