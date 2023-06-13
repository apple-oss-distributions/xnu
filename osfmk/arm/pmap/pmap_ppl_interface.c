/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
/**
 * This file is meant to contain all of the PPL entry points and PPL-specific
 * functionality.
 *
 * Every single function in the pmap that chooses between running a "*_ppl()" or
 * "*_internal()" function variant will be placed into this file. This file also
 * contains the ppl_handler_table, as well as a few PPL-only entry/exit helper
 * functions.
 *
 * See doc/ppl.md for more information about how these PPL entry points work.
 */
#include <kern/ledger.h>

#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>

#include <arm/pmap/pmap_internal.h>

/**
 * Keeps track of the total number of pages taken from the PPL page free lists
 * and returned back to the kernel. This value isn't used in logic anywhere,
 * it's available for debugging purposes strictly.
 */
#if XNU_MONITOR
static uint64_t pmap_ppl_pages_returned_to_kernel_count_total = 0;
#endif /* XNU_MONITOR */

/**
 * PMAP_SUPPORT_PROTOTYPES() will automatically create prototypes for the
 * _internal() and _ppl() variants of a PPL entry point. It also automatically
 * generates the code for the _ppl() variant which is what is used to jump into
 * the PPL.
 *
 * See doc/ppl.md for more information about how these PPL entry points work.
 */

#if XNU_MONITOR

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_mark_page_as_ppl_page, (pmap_paddr_t pa, bool initially_free), PMAP_MARK_PAGE_AS_PMAP_PAGE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_cpu_data_init, (unsigned int cpu_number), PMAP_CPU_DATA_INIT_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	uint64_t,
	pmap_release_ppl_pages_to_kernel, (void), PMAP_RELEASE_PAGES_TO_KERNEL_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_ledger_verify_size, (size_t),
	PMAP_LEDGER_VERIFY_SIZE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	ledger_t,
	pmap_ledger_alloc, (void),
	PMAP_LEDGER_ALLOC_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_ledger_free, (ledger_t),
	PMAP_LEDGER_FREE_INDEX);

#endif /* XNU_MONITOR */

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	mapping_free_prime, (void), MAPPING_FREE_PRIME_INDEX);

/* TODO: Move the ppl_handler_table into this file. */

#if XNU_MONITOR

/**
 * Claim a page on behalf of the PPL by marking it as PPL-owned and only
 * allowing the PPL to write to it. Also adds that page to the PPL page free
 * list for allocation later.
 *
 * @param pa The physical address of the page to mark as PPL-owned.
 */
void
pmap_mark_page_as_ppl_page(pmap_paddr_t pa)
{
	pmap_mark_page_as_ppl_page_ppl(pa, true);
}

/**
 * Quickly release pages living on the PPL page free list back to the VM. The
 * VM will call this when the system is under memory pressure.
 *
 * @note A minimum amount of pages (set by PMAP_MIN_FREE_PPL_PAGES) will always
 *       be kept on the PPL page free list to ensure that core operations can
 *       occur without having to refill the free list.
 */
uint64_t
pmap_release_ppl_pages_to_kernel(void)
{
	pmap_paddr_t pa = 0;
	vm_page_t mem = VM_PAGE_NULL;
	vm_page_t local_freeq = VM_PAGE_NULL;
	uint64_t pmap_ppl_pages_returned_to_kernel_count = 0;

	while (pmap_ppl_free_page_count > PMAP_MIN_FREE_PPL_PAGES) {
		/* Convert a single PPL page back into a kernel-usable page. */
		pa = pmap_release_ppl_pages_to_kernel_ppl();

		if (!pa) {
			break;
		}

		/**
		 * If we retrieved a page, add it to the queue of pages that will be
		 * given back to the VM.
		 */
		vm_object_lock(pmap_object);

		mem = vm_page_lookup(pmap_object, (pa - gPhysBase));
		assert(mem != VM_PAGE_NULL);
		assert(VM_PAGE_WIRED(mem));

		mem->vmp_busy = TRUE;
		mem->vmp_snext = local_freeq;
		local_freeq = mem;
		pmap_ppl_pages_returned_to_kernel_count++;
		pmap_ppl_pages_returned_to_kernel_count_total++;

		/* Pages are considered "in use" until given back to the VM. */
		OSAddAtomic(-1, &inuse_pmap_pages_count);

		vm_object_unlock(pmap_object);
	}

	/**
	 * Return back the pages to the VM that we've converted into kernel-usable
	 * pages.
	 */
	if (local_freeq) {
		/* We need to hold the object lock for freeing pages. */
		vm_object_lock(pmap_object);
		vm_page_free_list(local_freeq, TRUE);
		vm_object_unlock(pmap_object);
	}

	/**
	 * If we have any pages to return to the VM, take the page queues lock and
	 * decrement the wire count.
	 */
	if (pmap_ppl_pages_returned_to_kernel_count) {
		vm_page_lockspin_queues();
		vm_page_wire_count -= pmap_ppl_pages_returned_to_kernel_count;
		vm_page_unlock_queues();
	}

	return pmap_ppl_pages_returned_to_kernel_count;
}

#endif /* XNU_MONITOR */

/**
 * See pmap_cpu_data_init_internal()'s function header for more info.
 */
void
pmap_cpu_data_init(void)
{
#if XNU_MONITOR
	pmap_cpu_data_init_ppl(cpu_number());
#else
	pmap_cpu_data_init_internal(cpu_number());
#endif
}

/**
 * Prime the pv_entry_t free lists with a healthy amount of objects first thing
 * during boot. These objects will be used to keep track of physical-to-virtual
 * mappings.
 */
void
mapping_free_prime(void)
{
	kern_return_t kr = KERN_FAILURE;

#if XNU_MONITOR
	unsigned int i = 0;

	/**
	 * Allocate the needed PPL pages up front, to minimize the chance that we
	 * will need to call into the PPL multiple times.
	 */
	for (i = 0; i < pv_alloc_initial_target; i += (PAGE_SIZE / sizeof(pv_entry_t))) {
		pmap_alloc_page_for_ppl(0);
	}

	for (i = 0; i < pv_kern_alloc_initial_target; i += (PAGE_SIZE / sizeof(pv_entry_t))) {
		pmap_alloc_page_for_ppl(0);
	}

	while ((kr = mapping_free_prime_ppl()) == KERN_RESOURCE_SHORTAGE) {
		pmap_alloc_page_for_ppl(0);
	}
#else /* XNU_MONITOR */
	kr = mapping_free_prime_internal();
#endif /* XNU_MONITOR */

	if (kr != KERN_SUCCESS) {
		panic("%s: failed, no pages available? kr=%d", __func__, kr);
	}
}

/**
 * See pmap_ledger_verify_size_internal()'s function header for more information.
 */
#if !XNU_MONITOR
__attribute__((noreturn))
#endif /* !XNU_MONITOR */
void
pmap_ledger_verify_size(size_t size)
{
#if XNU_MONITOR
	pmap_ledger_verify_size_ppl(size);
#else /* XNU_MONITOR */
	/**
	 * Ledger objects are only managed by the pmap on PPL-enabled systems. Other
	 * systems will allocate them using a zone allocator.
	 */
	panic("%s: unsupported on non-PPL systems, size=%lu", __func__, size);
	__builtin_unreachable();
#endif /* XNU_MONITOR */
}

/**
 * See pmap_ledger_alloc_internal()'s function header for more information.
 */
ledger_t
pmap_ledger_alloc(void)
{
#if XNU_MONITOR
	ledger_t ledger = NULL;

	while ((ledger = pmap_ledger_alloc_ppl()) == NULL) {
		pmap_alloc_page_for_ppl(0);
	}

	return ledger;
#else /* XNU_MONITOR */
	/**
	 * Ledger objects are only managed by the pmap on PPL-enabled systems. Other
	 * systems will allocate them using a zone allocator.
	 */
	panic("%s: unsupported on non-PPL systems", __func__);
	__builtin_unreachable();
#endif /* XNU_MONITOR */
}

/**
 * See pmap_ledger_free_internal()'s function header for more information.
 */
#if !XNU_MONITOR
__attribute__((noreturn))
#endif /* !XNU_MONITOR */
void
pmap_ledger_free(ledger_t ledger)
{
#if XNU_MONITOR
	pmap_ledger_free_ppl(ledger);
#else /* XNU_MONITOR */
	/**
	 * Ledger objects are only managed by the pmap on PPL-enabled systems. Other
	 * systems will allocate them using a zone allocator.
	 */
	panic("%s: unsupported on non-PPL systems, ledger=%p", __func__, ledger);
	__builtin_unreachable();
#endif /* XNU_MONITOR */
}
