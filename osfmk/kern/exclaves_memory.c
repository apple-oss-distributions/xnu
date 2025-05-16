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

#include <vm/pmap.h>

#include <vm/vm_page_internal.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_pageout_xnu.h>
#include <vm/vm_kern_xnu.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_memory_entry_xnu.h>
#include <vm/vm_protos.h>

#include <mach/mach_vm.h>
#include <mach/mach_host.h>

#include <device/device_port.h>

#include <kern/ipc_kobject.h>

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

static_assert(
	(EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN == XNUUPCALLS_PAGEKIND_ROOTDOMAIN) &&
	(EXCLAVES_MEMORY_PAGEKIND_CONCLAVE == XNUUPCALLS_PAGEKIND_CONCLAVE),
	"xnuupcalls_pagekind_s mismatch");
static_assert(
	(EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN == XNUUPCALLSV2_PAGEKIND_ROOTDOMAIN) &&
	(EXCLAVES_MEMORY_PAGEKIND_CONCLAVE == XNUUPCALLSV2_PAGEKIND_CONCLAVE),
	"xnuupcallsv2_pagekind_s mismatch");

static ledger_t
get_conclave_mem_ledger(exclaves_memory_pagekind_t kind)
{
	ledger_t ledger;
	switch (kind) {
	case EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN:
		ledger = kernel_task->ledger;
		break;
	case EXCLAVES_MEMORY_PAGEKIND_CONCLAVE:
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
exclaves_memory_alloc(const uint32_t npages, uint32_t *pages, const exclaves_memory_pagekind_t kind, const exclaves_memory_page_flags_t flags)
{
	uint32_t pages_left = npages;
	vm_page_t page_list = NULL;
	vm_page_t sequestered = NULL;
	unsigned p = 0;

	uint64_t start_time = mach_continuous_approximate_time();
	kma_flags_t kma_flags = KMA_ZERO | KMA_NOFAIL;
	vm_object_t vm_obj = exclaves_object;

	(void)flags;

	while (pages_left) {
		vm_page_t next;
		vm_page_alloc_list(pages_left, kma_flags, &page_list);

		vm_object_lock(vm_obj);
		for (vm_page_t mem = page_list; mem != VM_PAGE_NULL; mem = next) {
			next = mem->vmp_snext;
			if (!vm_page_in_array(mem)) {
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
			vm_page_insert_wired(mem, vm_obj,
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
		vm_object_unlock(vm_obj);
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
	    (ledger_amount_t) (npages * PAGE_SIZE));
	if (ledger_ret != KERN_SUCCESS) {
		panic("Ledger credit failed. count %u error code %d",
		    npages,
		    ledger_ret);
	}
}

void
exclaves_memory_free(const uint32_t npages, const uint32_t *pages, const exclaves_memory_pagekind_t kind, const exclaves_memory_page_flags_t flags)
{
	vm_object_t vm_obj = exclaves_object;
	(void)flags;

	vm_object_lock(vm_obj);
	for (size_t p = 0; p < npages; p++) {
		/* Find the page in the exclaves object. */
		vm_page_t m;
		m = vm_page_lookup(vm_obj, ptoa(pages[p]));

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
	vm_object_unlock(vm_obj);

	os_atomic_add(&exclaves_allocation_statistics.pages_freed, npages, relaxed);

	ledger_t ledger = get_conclave_mem_ledger(kind);
	kern_return_t ledger_ret = ledger_debit(ledger,
	    task_ledgers.conclave_mem,
	    (ledger_amount_t) (npages * PAGE_SIZE));
	if (ledger_ret != KERN_SUCCESS) {
		panic("Ledger debit failed. count %u error code %d",
		    npages,
		    ledger_ret);
	}
}

static void
validate_for_mapping(uint32_t page, vm_prot_t prot)
{
	const sptm_frame_type_t type = sptm_get_frame_type(ptoa(page));

	// Mapping RW and type is SK_SHARED_RW.
	if (type == SK_SHARED_RW && (prot & VM_PROT_WRITE) != 0) {
		return;
	}

	// Mapping RO and type is SK_SHARED_RW or SH_SHARED_RO
	if ((type == SK_SHARED_RW || type == SK_SHARED_RO) &&
	    (prot & VM_PROT_WRITE) == 0) {
		return;
	}

	// Mismatch of type and prot
	panic("trying to map exclaves memory (prot: %u) "
	    "but memory is of the wrong type (%u)", prot, type);
}

kern_return_t
exclaves_memory_map(uint32_t npages, const uint32_t *pages, vm_prot_t prot,
    char **address)
{
	assert3u(npages, >, 0);

	kern_return_t kr = KERN_FAILURE;
	const vm_map_kernel_flags_t vmk_flags = {
		.vmf_fixed = false,
		.vm_tag    = VM_KERN_MEMORY_EXCLAVES_SHARED,
	};
	const vm_size_t size = npages * PAGE_SIZE;

	memory_object_t pager = device_pager_setup((memory_object_t)NULL,
	    (uintptr_t)NULL, size, DEVICE_PAGER_COHERENT);
	assert3p(pager, !=, NULL);

	for (uint32_t i = 0; i < npages; i++) {
		validate_for_mapping(pages[i], prot);

		kr = device_pager_populate_object(pager, ptoa(i), pages[i],
		    PAGE_SIZE);
		if (kr != KERN_SUCCESS) {
			device_pager_deallocate(pager);
			return kr;
		}
	}

	ipc_port_t entry = IPC_PORT_NULL;
	kr = mach_memory_object_memory_entry_64((host_t)1, false, size,
	    prot, pager, &entry);
	if (kr != KERN_SUCCESS) {
		device_pager_deallocate(pager);
		return kr;
	}

	kr = mach_vm_map_kernel(kernel_map, (mach_vm_offset_ut *)address, size, 0, vmk_flags, entry,
	    0, FALSE, prot, prot, VM_INHERIT_DEFAULT);

	mach_memory_entry_port_release(entry);

	if (kr != KERN_SUCCESS) {
		device_pager_deallocate(pager);
		return kr;
	}

	device_pager_deallocate(pager);

	/*
	 * Wire the memory so that it's paged-in up-front. This memory is
	 * already wired via exclaves_memory_alloc.
	 */
	const vm_map_offset_ut start = *(vm_map_offset_ut *)address;
	kr = vm_map_wire_kernel(kernel_map, start, start + size, prot,
	    VM_KERN_MEMORY_EXCLAVES_SHARED, false);
	if (kr != KERN_SUCCESS) {
		mach_vm_deallocate(kernel_map, start, size);
		return kr;
	}

	return KERN_SUCCESS;
}

kern_return_t
exclaves_memory_unmap(char *address, size_t size)
{
	kern_return_t kr = KERN_FAILURE;

	const vm_map_offset_ut start = (vm_map_offset_ut)address;
	kr = vm_map_unwire(kernel_map, start, start + size, false);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	kr = mach_vm_deallocate(kernel_map, (mach_vm_address_t)address, size);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	return KERN_SUCCESS;
}

/* -------------------------------------------------------------------------- */
#pragma mark Upcalls

/* Legacy upcall handlers */

tb_error_t
exclaves_memory_upcall_legacy_alloc(uint32_t npages, xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(xnuupcalls_pagelist_s))
{
	xnuupcalls_pagelist_s pagelist = {};

	assert3u(npages, <=, ARRAY_COUNT(pagelist.pages));
	if (npages > ARRAY_COUNT(pagelist.pages)) {
		panic("npages");
	}

	exclaves_memory_alloc(npages, pagelist.pages,
	    (exclaves_memory_pagekind_t) kind,
	    EXCLAVES_MEMORY_PAGE_FLAGS_NONE);
	return completion(pagelist);
}

tb_error_t
exclaves_memory_upcall_legacy_alloc_ext(uint32_t npages, xnuupcalls_pageallocflags_s flags,
    tb_error_t (^completion)(xnuupcalls_pagelist_s))
{
	xnuupcalls_pagelist_s pagelist = {};
	exclaves_memory_pagekind_t kind = EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN;
	exclaves_memory_page_flags_t alloc_flags = EXCLAVES_MEMORY_PAGE_FLAGS_NONE;

	assert3u(npages, <=, ARRAY_COUNT(pagelist.pages));
	if (npages > ARRAY_COUNT(pagelist.pages)) {
		panic("npages");
	}

	if (flags & XNUUPCALLS_PAGEALLOCFLAGS_CONCLAVE) {
		kind = EXCLAVES_MEMORY_PAGEKIND_CONCLAVE;
	}
	exclaves_memory_alloc(npages, pagelist.pages, kind, alloc_flags);
	return completion(pagelist);
}


tb_error_t
exclaves_memory_upcall_legacy_free(const uint32_t pages[EXCLAVES_MEMORY_MAX_REQUEST],
    uint32_t npages, const xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(void))
{
	/* Get pointer for page list paddr */
	assert(npages <= EXCLAVES_MEMORY_MAX_REQUEST);
	if (npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		panic("npages");
	}

	exclaves_memory_free(npages, pages, (exclaves_memory_pagekind_t) kind, EXCLAVES_MEMORY_PAGE_FLAGS_NONE);

	return completion();
}

tb_error_t
exclaves_memory_upcall_legacy_free_ext(const uint32_t pages[EXCLAVES_MEMORY_MAX_REQUEST],
    uint32_t npages, const xnuupcalls_pagefreeflags_s flags,
    tb_error_t (^completion)(void))
{
	exclaves_memory_pagekind_t kind = EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN;
	exclaves_memory_page_flags_t free_flags = EXCLAVES_MEMORY_PAGE_FLAGS_NONE;
	/* Get pointer for page list paddr */
	assert(npages <= EXCLAVES_MEMORY_MAX_REQUEST);
	if (npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		panic("npages");
	}
	if (flags & XNUUPCALLS_PAGEALLOCFLAGS_CONCLAVE) {
		kind = EXCLAVES_MEMORY_PAGEKIND_CONCLAVE;
	}

	exclaves_memory_free(npages, pages, kind, free_flags);

	return completion();
}

/* Upcall handlers */

tb_error_t
exclaves_memory_upcall_alloc(uint32_t npages, xnuupcallsv2_pagekind_s kind,
    tb_error_t (^completion)(xnuupcallsv2_pagelist_s))
{
	uint32_t pages[EXCLAVES_MEMORY_MAX_REQUEST];
	xnuupcallsv2_pagelist_s pagelist = {};

	assert3u(npages, <=, EXCLAVES_MEMORY_MAX_REQUEST);
	if (npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		panic("npages");
	}

	exclaves_memory_alloc(npages, pages,
	    (exclaves_memory_pagekind_t) kind,
	    EXCLAVES_MEMORY_PAGE_FLAGS_NONE);

	u32__v_assign_unowned(&pagelist, pages, npages);

	return completion(pagelist);
}

tb_error_t
exclaves_memory_upcall_alloc_ext(uint32_t npages, xnuupcallsv2_pageallocflagsv2_s flags,
    tb_error_t (^completion)(xnuupcallsv2_pagelist_s))
{
	uint32_t pages[EXCLAVES_MEMORY_MAX_REQUEST];
	xnuupcallsv2_pagelist_s pagelist = {};
	exclaves_memory_pagekind_t kind = EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN;
	exclaves_memory_page_flags_t alloc_flags = EXCLAVES_MEMORY_PAGE_FLAGS_NONE;

	assert3u(npages, <=, EXCLAVES_MEMORY_MAX_REQUEST);
	if (npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		panic("npages");
	}

	if (flags & XNUUPCALLSV2_PAGEALLOCFLAGSV2_CONCLAVE) {
		kind = EXCLAVES_MEMORY_PAGEKIND_CONCLAVE;
	}

	exclaves_memory_alloc(npages, pages, kind, alloc_flags);

	u32__v_assign_unowned(&pagelist, pages, npages);

	return completion(pagelist);
}


tb_error_t
exclaves_memory_upcall_free(const xnuupcallsv2_pagelist_s pages,
    const xnuupcallsv2_pagekind_s kind, tb_error_t (^completion)(void))
{
	uint32_t _pages[EXCLAVES_MEMORY_MAX_REQUEST];
	uint32_t *pages_ptr = _pages;
	uint32_t __block npages = 0;

	u32__v_visit(&pages, ^(size_t i, const uint32_t page) {
		if (++npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		        panic("npages");
		}
		pages_ptr[i] = page;
	});

	exclaves_memory_free(npages, _pages, (exclaves_memory_pagekind_t) kind, EXCLAVES_MEMORY_PAGE_FLAGS_NONE);

	return completion();
}

tb_error_t
exclaves_memory_upcall_free_ext(const xnuupcallsv2_pagelist_s pages,
    const xnuupcallsv2_pagefreeflagsv2_s flags, tb_error_t (^completion)(void))
{
	uint32_t _pages[EXCLAVES_MEMORY_MAX_REQUEST];
	uint32_t *pages_ptr = _pages;
	uint32_t __block npages = 0;
	exclaves_memory_pagekind_t kind = EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN;
	exclaves_memory_page_flags_t free_flags = EXCLAVES_MEMORY_PAGE_FLAGS_NONE;

	u32__v_visit(&pages, ^(size_t i, const uint32_t page) {
		if (++npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		        panic("npages");
		}
		pages_ptr[i] = page;
	});

	if (flags & XNUUPCALLSV2_PAGEFREEFLAGSV2_CONCLAVE) {
		kind = EXCLAVES_MEMORY_PAGEKIND_CONCLAVE;
	}

	exclaves_memory_free(npages, _pages, kind, free_flags);

	return completion();
}

#endif /* CONFIG_EXCLAVES */
