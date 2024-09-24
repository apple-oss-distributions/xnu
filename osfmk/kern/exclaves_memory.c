/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#include <vm/vm_page_internal.h>
#include <vm/vm_pageout_internal.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <kern/ledger.h>

#include "exclaves_memory.h"

/* -------------------------------------------------------------------------- */
#pragma mark Accounting

typedef struct {
	_Atomic uint64_t  pages_alloced;
	_Atomic uint64_t  pages_freed;
	_Atomic uint64_t  time_allocating;
	_Atomic uint64_t  max_alloc_latency;
	_Atomic uint64_t  alloc_latency_byhighbit[16];// highbit(MCT end - MCT start)/4
} exclaves_allocation_statistics_t;

exclaves_allocation_statistics_t exclaves_allocation_statistics;

CA_EVENT(ca_exclaves_allocation_statistics,
    CA_INT, pages_alloced,
    CA_INT, pages_freed,
    CA_INT, time_allocating,
    CA_INT, max_alloc_latency,
    CA_INT, alloc_latency_highbit0,
    CA_INT, alloc_latency_highbit1,
    CA_INT, alloc_latency_highbit2,
    CA_INT, alloc_latency_highbit3,
    CA_INT, alloc_latency_highbit4,
    CA_INT, alloc_latency_highbit5,
    CA_INT, alloc_latency_highbit6,
    CA_INT, alloc_latency_highbit7,
    CA_INT, alloc_latency_highbit8,
    CA_INT, alloc_latency_highbit9,
    CA_INT, alloc_latency_highbit10,
    CA_INT, alloc_latency_highbit11,
    CA_INT, alloc_latency_highbit12,
    CA_INT, alloc_latency_highbit13,
    CA_INT, alloc_latency_highbit14,
    CA_INT, alloc_latency_highbit15);

void
exclaves_memory_report_accounting(void)
{
	ca_event_t event = CA_EVENT_ALLOCATE(ca_exclaves_allocation_statistics);
	CA_EVENT_TYPE(ca_exclaves_allocation_statistics) * e = event->data;

	e->pages_alloced = os_atomic_load(&exclaves_allocation_statistics.pages_alloced, relaxed);
	e->pages_freed = os_atomic_load(&exclaves_allocation_statistics.pages_freed, relaxed);
	e->time_allocating = os_atomic_load(&exclaves_allocation_statistics.time_allocating, relaxed);
	e->max_alloc_latency = os_atomic_load(&exclaves_allocation_statistics.max_alloc_latency, relaxed);
	e->alloc_latency_highbit0 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[0], relaxed);
	e->alloc_latency_highbit1 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[1], relaxed);
	e->alloc_latency_highbit2 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[2], relaxed);
	e->alloc_latency_highbit3 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[3], relaxed);
	e->alloc_latency_highbit4 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[4], relaxed);
	e->alloc_latency_highbit5 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[5], relaxed);
	e->alloc_latency_highbit6 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[6], relaxed);
	e->alloc_latency_highbit7 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[7], relaxed);
	e->alloc_latency_highbit8 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[8], relaxed);
	e->alloc_latency_highbit9 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[9], relaxed);
	e->alloc_latency_highbit10 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[10], relaxed);
	e->alloc_latency_highbit11 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[11], relaxed);
	e->alloc_latency_highbit12 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[12], relaxed);
	e->alloc_latency_highbit13 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[13], relaxed);
	e->alloc_latency_highbit14 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[14], relaxed);
	e->alloc_latency_highbit15 = os_atomic_load(&exclaves_allocation_statistics.alloc_latency_byhighbit[15], relaxed);

	CA_EVENT_SEND(event);
}

static ledger_t
get_conclave_mem_ledger(xnuupcalls_pagekind_s kind)
{
	ledger_t ledger;
	switch (kind) {
	case XNUUPCALLS_PAGEKIND_ROOTDOMAIN:
		ledger = kernel_task->ledger;
		break;
	case XNUUPCALLS_PAGEKIND_CONCLAVE:
		if (current_thread()->conclave_stop_task != NULL) {
			ledger = current_thread()->conclave_stop_task->ledger;
		} else {
			ledger = current_task()->ledger;
		}
		break;
	default:
		panic("Conclave Memory ledger doesn't recognize pagekind");
		break;
	}
	return ledger;
}


/* -------------------------------------------------------------------------- */
#pragma mark Allocation/Free

void
exclaves_memory_alloc(const uint32_t npages, uint32_t *pages, const xnuupcalls_pagekind_s kind)
{
	uint32_t pages_left = npages;
	vm_page_t page_list = NULL;
	vm_page_t sequestered = NULL;
	unsigned p = 0;

	uint64_t start_time = mach_continuous_approximate_time();

	while (pages_left) {
		vm_page_t next;
		vm_page_alloc_list(npages, KMA_ZERO | KMA_NOFAIL, &page_list);

		vm_object_lock(exclaves_object);
		for (vm_page_t mem = page_list; mem != VM_PAGE_NULL; mem = next) {
			next = mem->vmp_snext;
			if (vm_page_created(mem)) {
				// avoid ml_static_mfree() pages due to 117505258
				mem->vmp_snext = sequestered;
				sequestered = mem;
				continue;
			}
			mem->vmp_snext = NULL;

			vm_page_lock_queues();
			vm_page_wire(mem, VM_KERN_MEMORY_EXCLAVES, FALSE);
			vm_page_unlock_queues();
			/* Insert the page into the exclaves object */
			vm_page_insert_wired(mem, exclaves_object,
			    ptoa(VM_PAGE_GET_PHYS_PAGE(mem)),
			    VM_KERN_MEMORY_EXCLAVES);

			/* Retype via SPTM to SK owned */
			sptm_retype_params_t retype_params = {
				.raw = SPTM_RETYPE_PARAMS_NULL
			};
			sptm_retype(ptoa(VM_PAGE_GET_PHYS_PAGE(mem)),
			    XNU_DEFAULT, SK_DEFAULT, retype_params);

			pages[p++] = VM_PAGE_GET_PHYS_PAGE(mem);
			pages_left--;
		}
		vm_object_unlock(exclaves_object);
	}

	vm_page_free_list(sequestered, FALSE);

	uint64_t elapsed_time = mach_continuous_approximate_time() - start_time;

	os_atomic_add(&exclaves_allocation_statistics.pages_alloced, npages, relaxed);
	os_atomic_add(&exclaves_allocation_statistics.time_allocating, elapsed_time, relaxed);
	os_atomic_max(&exclaves_allocation_statistics.max_alloc_latency, elapsed_time, relaxed);
	os_atomic_add(&exclaves_allocation_statistics.alloc_latency_byhighbit[ffsll(elapsed_time) / 4], elapsed_time, relaxed);

	ledger_t ledger = get_conclave_mem_ledger(kind);
	kern_return_t ledger_ret = ledger_credit(ledger,
	    task_ledgers.conclave_mem,
	    (ledger_amount_t) npages);
	if (ledger_ret != KERN_SUCCESS) {
		panic("Ledger credit failed. count %u error code %d",
		    npages,
		    ledger_ret);
	}
}

void
exclaves_memory_free(const uint32_t npages, const uint32_t *pages, const xnuupcalls_pagekind_s kind)
{
	vm_object_lock(exclaves_object);
	for (size_t p = 0; p < npages; p++) {
		/* Find the page in the exclaves object. */
		vm_page_t m;
		m = vm_page_lookup(exclaves_object, ptoa(pages[p]));

		/* Assert we found the page */
		assert(m != VM_PAGE_NULL);

		/* Via SPTM, verify the page type is something ownable by xnu. */
		assert3u(sptm_get_frame_type(ptoa(VM_PAGE_GET_PHYS_PAGE(m))),
		    ==, XNU_DEFAULT);

		/* Free the page */
		vm_page_lock_queues();
		vm_page_free(m);
		vm_page_unlock_queues();
	}
	vm_object_unlock(exclaves_object);

	os_atomic_add(&exclaves_allocation_statistics.pages_freed, npages, relaxed);

	ledger_t ledger = get_conclave_mem_ledger(kind);
	kern_return_t ledger_ret = ledger_debit(ledger,
	    task_ledgers.conclave_mem,
	    (ledger_amount_t) npages);
	if (ledger_ret != KERN_SUCCESS) {
		panic("Ledger debit failed. count %u error code %d",
		    npages,
		    ledger_ret);
	}
}


/* -------------------------------------------------------------------------- */
#pragma mark Upcalls

tb_error_t
exclaves_memory_upcall_alloc(uint32_t npages, xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(xnuupcalls_pagelist_s))
{
	xnuupcalls_pagelist_s pagelist = {};

	assert3u(npages, <=, ARRAY_COUNT(pagelist.pages));
	if (npages > ARRAY_COUNT(pagelist.pages)) {
		panic("npages");
	}

	exclaves_memory_alloc(npages, pagelist.pages, kind);
	return completion(pagelist);
}


tb_error_t
exclaves_memory_upcall_free(const uint32_t pages[EXCLAVES_MEMORY_MAX_REQUEST],
    uint32_t npages, const xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(void))
{
	/* Get pointer for page list paddr */
	assert(npages <= EXCLAVES_MEMORY_MAX_REQUEST);
	if (npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		panic("npages");
	}

	exclaves_memory_free(npages, pages, kind);

	return completion();
}

#endif /* CONFIG_EXCLAVES */
