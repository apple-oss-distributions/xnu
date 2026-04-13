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

#include <arm64/sptm/sptm.h>

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

#include <pexpert/device_tree.h>

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
			ledger = current_thread()->t_ledger;
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
	kma_flags_t kma_flags = KMA_NOFAIL;
	vm_object_t vm_obj = exclaves_object;

#if HAS_MTE
	/**
	 * Avoid specifying KMA_TAG if MTE has been disabled by boot arg.
	 * Otherwise, sptm_retype() will panic if asked to produce a tagged SK page
	 * without tag storage space to back it.
	 */
	if ((flags & EXCLAVES_MEMORY_PAGE_FLAGS_MTE_TAGGED) && mte_enabled()) {
		kma_flags |= KMA_TAG;
		vm_obj = exclaves_object_tagged;
	}
#else /* !HAS_MTE */
	(void)flags;
#endif /* HAS_MTE */
#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_START, ptoa(npages), 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */

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
#if HAS_MTE
			if (kma_flags & KMA_TAG) {
				retype_params.sk_flags |= SPTM_SK_PAGE_FLAGS_TAGGABLE;
				pmap_unmake_tagged_page(VM_PAGE_GET_PHYS_PAGE(mem));
			}
#endif /* HAS_MTE */
			sptm_retype(ptoa(VM_PAGE_GET_PHYS_PAGE(mem)),
			    XNU_DEFAULT, SK_DEFAULT, retype_params);

			pages[p++] = VM_PAGE_GET_PHYS_PAGE(mem);
			pages_left--;
		}
		vm_object_unlock(vm_obj);
	}

	vm_page_free_list(sequestered, FALSE);

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, DBG_VM_KERN_REQUEST, DBG_FUNC_END, npages, 0, 0, 0);
#endif /* DEBUG || DEVELOPMENT */
	uint64_t elapsed_time = mach_continuous_approximate_time() - start_time;

	os_atomic_add(&exclaves_allocation_statistics.pages_alloced, npages, relaxed);
	os_atomic_add(&exclaves_allocation_statistics.time_allocating, elapsed_time, relaxed);
	os_atomic_max(&exclaves_allocation_statistics.max_alloc_latency, elapsed_time, relaxed);
	os_atomic_add(&exclaves_allocation_statistics.alloc_latency_byhighbit[ffsll(elapsed_time) / 4], elapsed_time, relaxed);

	ledger_t ledger = get_conclave_mem_ledger(kind);
	ledger_credit(ledger, task_ledgers.conclave_mem,
	    (ledger_amount_t) (npages * PAGE_SIZE));
}

void
exclaves_memory_free(const uint32_t npages, const uint32_t *pages, const exclaves_memory_pagekind_t kind, const exclaves_memory_page_flags_t flags)
{
	vm_object_t vm_obj = exclaves_object;
#if HAS_MTE
	if (flags & EXCLAVES_MEMORY_PAGE_FLAGS_MTE_TAGGED) {
		vm_obj = exclaves_object_tagged;
	}
#else /* !HAS_MTE */
	(void)flags;
#endif /* HAS_MTE */

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

#if HAS_MTE
		if (vm_obj == exclaves_object_tagged) {
			/* pmap_make_tagged_page works lazily, hence we need to mark page m as `using_mte == false` */
			m->vmp_using_mte = false;
			pmap_make_tagged_page(VM_PAGE_GET_PHYS_PAGE(m));
			m->vmp_using_mte = true;
		}
#endif /* HAS_MTE */

		/* Free the page */
		vm_page_lock_queues();
		vm_page_free(m);
		vm_page_unlock_queues();
	}
	vm_object_unlock(vm_obj);

	os_atomic_add(&exclaves_allocation_statistics.pages_freed, npages, relaxed);

	ledger_t ledger = get_conclave_mem_ledger(kind);
	ledger_debit(ledger, task_ledgers.conclave_mem,
	    (ledger_amount_t) (npages * PAGE_SIZE));
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
		mach_vm_deallocate_kernel(kernel_map, start, size);
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

	kr = mach_vm_deallocate_kernel(kernel_map, (mach_vm_address_t)address, size);
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
#if HAS_MTE
	if (flags & XNUUPCALLS_PAGEALLOCFLAGS_SEC_TRANSITION) {
		alloc_flags |= EXCLAVES_MEMORY_PAGE_FLAGS_MTE_TAGGED;
	}
#endif /* HAS_MTE */
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
#if HAS_MTE
	if (flags & XNUUPCALLS_PAGEFREEFLAGS_SEC_TRANSITION) {
		free_flags |= EXCLAVES_MEMORY_PAGE_FLAGS_MTE_TAGGED;
	}
#endif /* HAS_MTE */

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
#if HAS_MTE
	if (flags & XNUUPCALLSV2_PAGEALLOCFLAGSV2_SEC_TRANSITION) {
		alloc_flags |= EXCLAVES_MEMORY_PAGE_FLAGS_MTE_TAGGED;
	}
#endif /* HAS_MTE */

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
#if HAS_MTE
	if (flags & XNUUPCALLSV2_PAGEFREEFLAGSV2_SEC_TRANSITION) {
		free_flags |= EXCLAVES_MEMORY_PAGE_FLAGS_MTE_TAGGED;
	}
#endif /* HAS_MTE */

	exclaves_memory_free(npages, _pages, kind, free_flags);

	return completion();
}

#pragma mark Carveout memory accounting

// Size of the iBoot-loaded ExclaveCoreBundle in bytes
// This is also part of VM_KERN_COUNT_BOOT_STOLEN / ml_get_booter_memory_size
uint64_t exclaves_bundle_size = 0;
// Size of the SPTM-managed Exclaves carveout in bytes
uint64_t exclaves_carveout_size = 0;

__startup_func
static void
initialize_exclaves_bundle_bytes(void)
{
	int err;
	DTEntry memory_map;

	err = SecureDTLookupEntry(NULL, "chosen/memory-map", &memory_map);

	const char *CL4_Properties[] = {
		"CL4-ro", "CL4-rx", "CL4-bx", "CL4-rw", "CL4-le"
	};

	for (int i = 0; i < sizeof(CL4_Properties) / sizeof(*CL4_Properties); i++) {
		unsigned int range_size;
		DTMemoryMapRange const *range;

		err = SecureDTGetProperty(memory_map, CL4_Properties[i], (void const **)&range, &range_size);
		if (err == kSuccess && range_size == sizeof(DTMemoryMapRange)) {
			if (range->length != SIZE_MAX) {
				exclaves_bundle_size += range->length;
			}
		}
	}

	exclaves_carveout_size = SPTMArgs->sk_carveout_size;

	/*
	 * Credit the carveout size to kernel_task's conclave_mem ledger so that
	 * exclaves memory accounting includes the initial carveout allocation.
	 */
	ledger_credit(kernel_task->ledger,
	    task_ledgers.conclave_mem,
	    (ledger_amount_t)exclaves_carveout_size);
}

STARTUP(EXCLAVES, STARTUP_RANK_MIDDLE, initialize_exclaves_bundle_bytes);

#endif /* CONFIG_EXCLAVES */
