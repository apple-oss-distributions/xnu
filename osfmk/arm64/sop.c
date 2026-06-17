/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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

#if CONFIG_SPTM

#include <kern/startup.h>
#include <kern/simple_lock.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <kern/cpu_data.h>
#include <arm64/sop.h>
#include <kern/spl.h>
#include <vm/pmap.h>
#include <vm/vm_page_internal.h>
#include <mach/vm_param.h>
#include <arm64/sptm/pmap/pmap_internal.h>
#include <arm64/sptm/sptm.h>
#include <arm/machine_routines.h>

#define SOP_PAGE_POOL_MAX_SIZE 200
#define SOP_PAGE_POOL_SIZE 4

static LCK_GRP_DECLARE(sop_lock_grp, "sop");
static SIMPLE_LOCK_DECLARE(sop_page_pool_lock, 0);

static pmap_paddr_t sop_page_pool[SOP_PAGE_POOL_MAX_SIZE];
static uint32_t sop_page_pool_count = 0;

#if DEVELOPMENT || DEBUG
/*
 * Debug counter tracking how many times a redzone stack page was allocated.
 * Exported via sysctl kern.sop_redzone_alloc_count (declared in bsd/kern/kern_sysctl.c)
 */
uint32_t sop_redzone_alloc_count = 0;
uint32_t sop_redzone_free_count = 0;

/*
 * Boot-arg to artificially reduce kernel stack size for testing stack overflow protection.
 * The value (in bytes) will be subtracted from kstackptr during thread stack setup.
 */
TUNABLE(uint32_t, sop_kstack_reduce, "sop_kstack_reduce", 0);
#endif

/*
 * SOP_DEBUG: Enable exception ring buffer for debugging stack overflow protection.
 * Define to 1 to enable.
 */

#if SOP_DEBUG
/*
 * Ring buffer to capture exception state at the very start of exception vectors.
 * This allows us to see what the original exception was, even if nested exceptions
 * occur and clobber ESR_EL1/FAR_EL1/ELR_EL1.
 */

/*
 * Flags for sop_exception_snapshot_t:
 * Captures the exception source (vector path taken):
 *   0 = SP0 synchronous exception
 *   1 = SP1 synchronous exception
 *   2 = SP0 IRQ
 *   3 = SP0 FIQ
 *   4 = SP0 SError
 *   5 = SPTM SP0 IRQ
 *   6 = SPTM SP0 FIQ
 *   7 = SP1 IRQ
 *   8 = SP1 FIQ
 *   9 = SP1 SError
 */
sop_exception_snapshot_t sop_exception_ring[SOP_EXCEPTION_RING_SIZE];
volatile uint32_t sop_exception_ring_index = 0;
#endif /* SOP_DEBUG */

/*
 * Initialize the SOP page pool by allocating pages from the VM system.
 * This pool is used to provide temporary stack pages for redzone mapping.
 */
static void
sop_page_pool_init(void)
{
	vm_page_t page;
	pmap_paddr_t pa;

	uint32_t pool_size = SOP_PAGE_POOL_SIZE;
#if DEVELOPMENT || DEBUG
	if (sop_kstack_reduce > 0) {
		pool_size = SOP_PAGE_POOL_MAX_SIZE;
	}
#endif

	/* Allocate pages from the VM free list and store in the pool */
	for (uint32_t i = 0; i < pool_size; i++) {
		/*
		 * Allocate a zeroed page from the VM system.
		 */
		page = vm_page_grab_options(VM_PAGE_GRAB_ZERO_FILL);
		assert(page != VM_PAGE_NULL);

		/* Wire the page so it's not reclaimed */
		vm_page_lock_queues();
		vm_page_wire(page, VM_KERN_MEMORY_STACK, TRUE);
		vm_page_unlock_queues();

		/* Get the physical address */
		pa = (pmap_paddr_t)ptoa(VM_PAGE_GET_PHYS_PAGE(page));
		assert(pa != 0);

		/* Verify the PA is in the valid kernel-managed range */
		assert(pa >= vm_first_phys && pa < vm_last_phys);

		sop_page_pool[i] = pa;
	}

	sop_page_pool_count = pool_size;
}
STARTUP(ZALLOC, STARTUP_RANK_LAST, sop_page_pool_init);

/*
 * Allocate a physical page from the SOP page pool.
 * Called from exception context, protected by spin lock.
 *
 * Returns: Physical address of allocated page, or (pmap_paddr_t)-1 if the pool is empty.
 */
static uint64_t
sop_page_alloc(void)
{
	pmap_paddr_t pa = (pmap_paddr_t)-1;

	simple_lock(&sop_page_pool_lock, &sop_lock_grp);

	if (sop_page_pool_count > 0) {
		/* Take a page from the pool */
		sop_page_pool_count--;
		pa = sop_page_pool[sop_page_pool_count];
#if DEVELOPMENT || DEBUG
		sop_redzone_alloc_count++;
#endif
	}

	simple_unlock(&sop_page_pool_lock);

	return pa;
}

/*
 * Free a physical page back to the SOP page pool.
 * Called from exception context, protected by spin lock.
 *
 * Parameters:
 *   pa: Physical address of the page to return to the pool.
 */
static void
sop_pool_free(uint64_t pa)
{
	simple_lock(&sop_page_pool_lock, &sop_lock_grp);

	/* Ensure we don't overflow the pool */
	assert(sop_page_pool_count < SOP_PAGE_POOL_MAX_SIZE);

	/* Return the page to the pool */
	sop_page_pool[sop_page_pool_count] = pa;
	sop_page_pool_count++;
#if DEVELOPMENT || DEBUG
	sop_redzone_free_count++;
#endif

	simple_unlock(&sop_page_pool_lock);
}

/*
 * Map the redzone page for the current thread's kernel stack.
 * Called from exception context with interrupts disabled.
 *
 * Parameters:
 *   va: Virtual address of the redzone page to map.
 *
 * Returns: true if mapping succeeded, false otherwise.
 */
bool __attribute__((noinline))
sop_try_map_redzone_page(uintptr_t va)
{
	pmap_t pmap = kernel_pmap;
	pmap_paddr_t pa;
	kern_return_t kr;

	/* Interrupts must be disabled when calling this function */
	assert(!ml_get_interrupts_enabled());

	if (current_thread()->machine.kredzonestack) {
		/* We have already been down this path so give up */
		return false;
	}

	pa = sop_page_alloc();
	if (pa == (pmap_paddr_t)-1) {
		return false;
	}

	/* Verify the PA is still in the valid kernel-managed range */
	assert(pa >= vm_first_phys && pa < vm_last_phys);

	current_thread()->machine.kredzonestack = pa;

	/*
	 * Use the special direct pmap function that bypasses epochs and PVH locks.
	 * This is safe for kernel stack pages because they are single-threaded
	 * and don't need synchronization between threads.
	 *
	 * This prevents re-entrance issues when we take a stack overflow exception
	 * while already executing pmap code.
	 *
	 * Preemption is implicitly disabled since interrupts are disabled.
	 */
	kr = pmap_map_stack_page_direct(pmap, va, pa);

	if (kr == KERN_SUCCESS) {
		return true;
	}

	current_thread()->machine.kredzonestack = 0;
	sop_pool_free(pa);
	return false;
}


/*
 * Unmap the thread stack redzone page and free the temporary stack page.
 * Called from normal kernel context (not exception context).
 *
 * Parameters:
 *   thread: Thread whose redzone page should be unmapped.
 */
void __attribute__((noinline))
sop_unmap_redzone_page(thread_t thread)
{
	pmap_t pmap = kernel_pmap;
	pmap_paddr_t pa;
	vm_offset_t kernel_stack_bottom, va;
	spl_t s;

	/*
	 * Disable interrupts for the entire operation to prevent:
	 * 1. Race conditions with kredzonestack field
	 * 2. Deadlock if interrupt handler tries to take sop_page_pool_lock
	 */
	s = splsched();

	assert3u(thread->machine.kredzonestack, >, 0);

	/* Get the physical address of the mapped redzone page */
	pa = thread->machine.kredzonestack;

	/* Verify the PA is in the valid kernel-managed range */
	assert(pa >= vm_first_phys && pa < vm_last_phys);

	/*
	 * Calculate the virtual address of the redzone page.
	 * Use thread->kernel_stack directly - it's the actual stack base.
	 * Don't calculate from kstackptr which may be reduced by sop_kstack_reduce.
	 */
	kernel_stack_bottom = thread->kernel_stack;
	va = kernel_stack_bottom - PAGE_SIZE;

	/* Clear the thread's redzone marker */
	thread->machine.kredzonestack = 0;

	/*
	 * Zero the redzone page before unmapping it.
	 * This prevents information leakage if the page is reused for another thread's
	 * redzone, and ensures the next use sees zeroed memory rather than stack data.
	 */
	bzero((void *)va, PAGE_SIZE);

	/*
	 * Use the special direct pmap function that bypasses epochs and PVH locks.
	 * This is safe for kernel stack pages because they are single-threaded
	 * and don't need synchronization between threads.
	 *
	 * This prevents re-entrance issues when unmapping during cleanup or
	 * stack handoff while pmap code may already be executing.
	 *
	 * Preemption is implicitly disabled since interrupts are disabled (splsched above).
	 */
	pmap_unmap_stack_page_direct(pmap, va);

	/* Return the page to the pool */
	sop_pool_free(pa);

	splx(s);
}

#endif /* CONFIG_SPTM */
