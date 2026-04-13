/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include "mocks/std_safe.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mock_pmap.h"

#ifndef CONFIG_SPTM
#error pmap mocks are currently only implemented for SPTM
#else
#include <arm64/sptm/pmap/pmap_internal.h>
#endif

#include <vm/pmap.h>
#include <arm64/sptm/pmap/pmap_internal.h>

T_MOCK_F(void *,
pmap_steal_memory, (vm_size_t size, vm_size_t alignment), (size, alignment))
{
	return checked_alloc_align(size, alignment);
}

T_MOCK_F(void *,
pmap_steal_freeable_memory, (vm_size_t size), (size))
{
	return checked_alloc_align(size, 0);
}

T_MOCK_F(void,
pmap_startup, (vm_offset_t * startp, vm_offset_t * endp), (startp, endp))
{
	// RANGELOCKINGTODO rdar://136915968
}

T_MOCK_F(boolean_t,
pmap_virtual_region, (unsigned int region_select, vm_map_offset_t * startp, vm_map_size_t * size),
(region_select, startp, size))
{
	return false; // RANGELOCKINGTODO rdar://136915968
}

extern const struct page_table_attr * const native_pt_attr;
extern const struct page_table_attr pmap_pt_attr_4k;

T_MOCK_F(pmap_t,
pmap_create_options, (
	ledger_t ledger,
	vm_map_size_t size,
	unsigned int flags), (ledger, size, flags))
{
	pmap_t p = (pmap_t)calloc(1, sizeof(struct pmap));
	// this is needed for pmap_shared_region_size_min()
	if (flags & PMAP_CREATE_FORCE_4K_PAGES) {
		p->pmap_pt_attr = &pmap_pt_attr_4k;
	} else {
		p->pmap_pt_attr = native_pt_attr;
	}

	p->ledger = ledger;

	return p;
}

T_MOCK_F(void,
pmap_reference, (pmap_t pmap), (pmap))
{
}

T_MOCK_F(void,
pmap_set_nested, (pmap_t pmap), (pmap))
{
}

T_MOCK_F(void,
pmap_recycle_page, (ppnum_t pn), (pn))
{
}

T_MOCK_F(kern_return_t,
pmap_nest, (
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size), (grand, subord, vstart, size))
{
	return KERN_SUCCESS;
}

T_MOCK_F(kern_return_t,
pmap_unnest_options, (
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size,
	unsigned int option), (grand, vaddr, size, option))
{
	return KERN_SUCCESS;
}


T_MOCK_F(vm_map_address_t,
pmap_protect_options_internal, (
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	vm_prot_t prot,
	unsigned int options,
	void *args), (pmap, start, end, prot, options, args))
{
	return end;
}

// called from pmap_protect_options()
T_MOCK_F(void,
pmap_flush_sptm_traces, (void), ())
{
}

T_MOCK_F(kern_return_t,
pmap_enter_options_internal,
(pmap_t pmap,
vm_map_address_t v,
pmap_paddr_t pa,
vm_prot_t prot,
vm_prot_t fault_type,
unsigned int flags,
boolean_t wired,
unsigned int options,
pmap_mapping_type_t mapping_type),
(pmap, v, pa, prot, fault_type, flags, wired, options, mapping_type))
{
	return KERN_SUCCESS;
}

typedef struct pmap_remove_options_call {
	pmap_t pmap;
	vm_map_address_t start;
	vm_map_address_t end;
	int options;
} *pmap_remove_options_call_t;

static bool intercept_pmap_remove_options;
static pmap_remove_options_call_t *pmap_remove_options_calls;
static uint64_t pmap_remove_options_calls_count;
static uint64_t pmap_remove_options_calls_index = -1;

pmap_remove_options_call_t
make_pmap_remove_options_intercept(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options)
{
	pmap_remove_options_call_t call = (pmap_remove_options_call_t) calloc(1, sizeof(struct pmap_remove_options_call));
	call->pmap = pmap;
	call->start = start;
	call->end = end;
	call->options = options;

	return call;
}

void
_prepare_for_pmap_remove_options_call(pmap_remove_options_call_t *calls, uint64_t calls_count)
{
	pmap_remove_options_calls = calls;
	pmap_remove_options_calls_count = calls_count;
	assert3u(pmap_remove_options_calls_index, ==, -1);
	pmap_remove_options_calls_index = 0;
	intercept_pmap_remove_options = true;
}

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define prepare_for_pmap_remove_options_call(calls) _prepare_for_pmap_remove_options_call(calls, countof(calls))

bool
verify_pmap_remove_options_intercept_calls()
{
	bool worked = pmap_remove_options_calls_index == pmap_remove_options_calls_count;
	pmap_remove_options_calls_index = -1;
	return worked;
}

T_MOCK_F(void,
pmap_remove_options, (
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options),
(pmap, start, end, options))
{
	if (intercept_pmap_remove_options) {
		pmap_remove_options_call_t call = pmap_remove_options_calls[pmap_remove_options_calls_index];
		pmap_remove_options_calls_index++;

		assert3p(pmap, ==, call->pmap);
		assert3u(start, ==, call->start);
		assert3u(end, ==, call->end);
		assert3s(options, ==, call->options);
	}
}

T_MOCK_F(bool,
pmap_is_page_restricted, (__unused ppnum_t pn), (pn))
{
	// RANGELOCKINGTODO rdar://136915968
	return false;
}

T_MOCK_F(void,
pmap_copy_page, (
	ppnum_t psrc,
	ppnum_t pdst,
	int options), (psrc, pdst, options))
{
	// RANGELOCKINGTODO rdar://136915968
}

T_MOCK_F(void,
vm_page_part_copy, (
	vm_page_t       src_m,
	vm_offset_t     src_pa,
	vm_page_t       dst_m,
	vm_offset_t     dst_pa,
	vm_size_t       len),
(src_m, src_pa, dst_m, dst_pa, len))
{
	// RANGELOCKINGTODO rdar://136915968
}

T_MOCK_F(void,
pmap_zero_part_page, (
	ppnum_t pn,
	vm_offset_t offset,
	vm_size_t len),
(pn, offset, len))
{
	// RANGELOCKINGTODO rdar://136915968
}

T_MOCK_F(void,
pmap_map_cpu_windows_copy_internal, (
	ppnum_t pn,
	vm_prot_t prot,
	unsigned int wimg_bits), (pn, prot, wimg_bits))
{
	// RANGELOCKINGTODO rdar://136915968
}

T_MOCK_F(void,
pmap_destroy, (pmap_t pmap), (pmap))
{
}

T_MOCK_F(uint64_t,
pmap_shared_region_size_min, (pmap_t pmap), (pmap))
{
	// the default behaviour for arm64
	return 0x0000000002000000ULL;
}

T_MOCK_F(ppnum_t,
pmap_find_phys, (pmap_t pmap, addr64_t va), (pmap, va))
{
	return 0;
}

T_MOCK_F(unsigned int,
pmap_cache_attributes,
(ppnum_t phys), (phys))
{
	return 0;
}

T_MOCK_F(pmap_paddr_t,
kvtophys, (vm_offset_t offs), (offs))
{
	return 0;
}

T_MOCK_F(pmap_paddr_t,
kvtophys_nofail, (vm_offset_t offs), (offs))
{
	return 0;
}

T_MOCK(unsigned int,
pmap_disconnect_options, (ppnum_t phys, unsigned int options, void *arg), (phys, options, arg));

T_MOCK_F(void,
pmap_set_tpro, (pmap_t pmap), (pmap))
{
	pmap->xprr_tpro_enabled = true;
}

T_MOCK_F(void,
pmap_zero_page, (ppnum_t pn), (pn))
{
	// RANGELOCKINGTODO rdar://136915968
}

T_MOCK_F(void,
pmap_zero_page_with_options,
(ppnum_t pn, int options), (pn, options))
{
	// RANGELOCKINGTODO rdar://136915968
}

// added for setup_nested_submap
T_MOCK_F(void,
pmap_set_shared_region, (
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size), (grand, subord, vstart, size))
{
}

T_MOCK_F(void,
pmap_insert_commpage, (pmap_t pmap), (pmap))
{
}

T_MOCK(bool,
pmap_get_tpro,
(pmap_t pmap),
(pmap));

T_MOCK(bool,
pmap_is_page_free,
(pmap_paddr_t paddr),
(paddr));

T_MOCK_F(void,
pmap_switch_user, (thread_t thread, vm_map_t new_map), (thread, new_map))
{
	thread->map = new_map;
}
