/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <arm64/sptm/pmap/pmap.h>
#include <darwintest.h>

#include "ecc_utils.h"
#include "mocks/osfmk/mock_ecc.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/fake_libsptm.h"

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ecc_test_pmap"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("mnitenko")
	);

T_DECL(test_pmap_type_is_ecc_retireable_returns_true,
    "Test pmap_type_is_ecc_retireable returns true for retirable pages")
{
	bool result = pmap_type_is_ecc_retireable(XNU_DEFAULT);
	T_ASSERT_TRUE(result,
	    "pmap_type_is_ecc_retireable should return true for frame type %u",
	    XNU_DEFAULT);
}

T_DECL(test_pmap_type_is_ecc_retireable_returns_false,
    "Test pmap_type_is_ecc_retireable returns false for non-retirable pages")
{
	/* Array of frame types that should NOT be retirable. */
	const sptm_frame_type_t non_retirable_types[] = {
		SPTM_DEFAULT,
		SPTM_CODE,
	};
	const size_t size =
	    sizeof(non_retirable_types) / sizeof(non_retirable_types[0]);

	for (size_t i = 0; i < size; i++) {
		bool result =
		    pmap_type_is_ecc_retireable(non_retirable_types[i]);
		T_ASSERT_FALSE(result,
		    "pmap_type_is_ecc_retireable should return false for a non-retirable frame type %u",
		    non_retirable_types[i]);
	}
}

T_DECL(test_pmap_type_is_ecc_retireable_panics_on_sptm_error,
    "Test pmap_type_is_ecc_retireable panics if (mocked) sptm_type_is_ecc_retireable returns an error")
{
	sptm_type_is_ecc_retireable_set_ret(LIBSPTM_NOT_INITTED);

	T_ASSERT_PANIC_CONTAINS(pmap_type_is_ecc_retireable(XNU_DEFAULT),
	    "pmap_type_is_ecc_retireable: failed for type",
	    "Panic if sptm_type_is_ecc_retireable returns an error");
}

/* To retire a page the system has to be ECC capable. */
T_MOCK_SET_PERM_RETVAL(vm_ecc_capable, bool, true);

static unsigned ml_page_clear_poison_calls = 0;
T_MOCK_SET_PERM_FUNC(void, ml_page_clear_poison, (vm_address_t va))
{
	ml_page_clear_poison_calls++;
	return;
}

extern boolean_t pmap_initialized;
__attribute__((constructor)) void
pmap_test_init(void)
{
	setup_mem();

	/*
	 * Should be able to hold the number of VM pages that span all of
	 * kernel-managed memory.
	 */
	pv_head_table = malloc(atop(mem_size) * sizeof(uintptr_t));
	pmap_initialized = true;
}

__attribute__((destructor)) void
pmap_test_deinit(void)
{
	pmap_initialized = false;
	free(pv_head_table);
}

/**
 * Set up page as retired.
 *
 * @param addr Physical address to mark as retired.
 */
static void
pmap_pre_retire(const pmap_paddr_t addr)
{
	const unsigned int pai = pa_index(addr);
	locked_pvh_t locked_pvh = pvh_lock(pai);
	pvh_set_flags(&locked_pvh,
	    pvh_get_flags(locked_pvh.pvh) | PVH_FLAG_RETIRED);
	pvh_unlock(&locked_pvh);
}

T_DECL(retire_ecc_not_capable, "Retiring a page when ECC is not capable")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr = gPhysBase + 900 * PAGE_SIZE;
	sptm_get_paddr_type_set_type(XNU_DEFAULT);
	pmap_pre_retire(addr);
	T_SETUPEND;

	/* Mock vm_ecc_capable to return false. */
	T_MOCK_SET_RETVAL(vm_ecc_capable, bool, false);

	T_ASSERT_PANIC_CONTAINS(pmap_retire_page(atop(addr)),
	    "Assertion failed",
	    "Should panic when ECC is not capable.");
	T_ASSERT_EQ(ml_page_clear_poison_calls, 0,
	    "Did not try to clear poison.");
	T_ASSERT_NE(sptm_retype_get_type(), SPTM_UNUSED,
	    "Did not retype the page.");
}

T_DECL(retire_non_managed, "Retiring non-kernel managed pages")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr_out_of_dram = 10;
	const pmap_paddr_t addr_dram_start = gDramBase;
	T_SETUPEND;

	T_ASSERT_PANIC_CONTAINS(pmap_retire_page(atop(addr_out_of_dram)),
	    "attempt to retire non-kernel managed PA",
	    "Can't retire unmanaged PAs (out of DRAM).");
	T_ASSERT_NE(sptm_retype_get_type(), SPTM_UNUSED,
	    "Did not retype the page.");

	T_ASSERT_PANIC_CONTAINS(pmap_retire_page(atop(addr_dram_start)),
	    "attempt to retire non-kernel managed PA",
	    "Can't retire unmanaged PAs (start of DRAM).");
	T_ASSERT_NE(sptm_retype_get_type(), SPTM_UNUSED,
	    "Did not retype the page.");

	T_ASSERT_EQ(ml_page_clear_poison_calls, 0,
	    "Did not try to clear poison for non-managed pages.");
}

T_DECL(retire_without_retired_flag,
    "Retiring a page that lacks PVH_FLAG_RETIRED flag")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr = gPhysBase + 200 * PAGE_SIZE;
	sptm_get_paddr_type_set_type(XNU_DEFAULT);
	T_SETUPEND;

	T_ASSERT_PANIC_CONTAINS(pmap_retire_page(atop(addr)),
	    "that is not FLAG_RETIRED",
	    "Should panic when trying to retire page without PVH_FLAG_RETIRED flag.");
	T_ASSERT_EQ(ml_page_clear_poison_calls, 0,
	    "Did not try to clear poison.");
	T_ASSERT_NE(sptm_retype_get_type(), SPTM_UNUSED,
	    "Did not retype the page.");
}

T_DECL(retire_with_mappings, "Retiring a page with active mappings")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr = gPhysBase + 300 * PAGE_SIZE;
	sptm_get_paddr_type_set_type(XNU_DEFAULT);
	pmap_pre_retire(addr);
	const unsigned int pai = pa_index(addr);
	locked_pvh_t locked_pvh = pvh_lock(pai);

	/* Set PVH_TYPE_PTEP to simulate a mapping. */
	pvh_update_head(&locked_pvh, &locked_pvh, PVH_TYPE_PTEP);

	pvh_unlock(&locked_pvh);
	T_SETUPEND;

	T_ASSERT_PANIC_CONTAINS(pmap_retire_page(atop(addr)),
	    "with mappings",
	    "Should panic when trying to retire page that has mappings.");
}

T_DECL(retire_non_retirable, "Retiring a non-retirable page type")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr = gPhysBase + 400 * PAGE_SIZE;
	/* Set the page type to be something non-retirable -- SPTM_CODE. */
	sptm_get_paddr_type_set_type(SPTM_CODE);
	pmap_pre_retire(addr);
	T_SETUPEND;

	T_ASSERT_PANIC_CONTAINS(pmap_retire_page(atop(addr)),
	    "attempt to retire a non-retirable",
	    "Should panic when trying to retire a non-retirable page.");
	T_ASSERT_EQ(ml_page_clear_poison_calls, 0,
	    "Did not try to clear poison.");
	T_ASSERT_NE(sptm_retype_get_type(), SPTM_UNUSED,
	    "Did not retype the page.");
}

T_DECL(retire_limits, "Retire first and last managed pages")
{
	T_SETUPBEGIN;
	const unsigned expected_calls = 2;

	sptm_get_paddr_type_set_type(XNU_DEFAULT);

	/* Test with a page at the very beginning of managed memory. */
	const pmap_paddr_t first_page = gPhysBase;
	pmap_pre_retire(first_page);

	/* Test with the last page of managed memory. */
	const pmap_paddr_t last_page = gPhysBase + (gPhysSize - PAGE_SIZE);
	pmap_pre_retire(last_page);
	T_SETUPEND;

	pmap_retire_page(atop(first_page));
	T_ASSERT_TRUE(pmap_is_page_retired(atop(first_page)),
	    "First page of managed memory should be retired.");
	T_ASSERT_EQ(sptm_retype_get_type(), SPTM_UNUSED,
	    "Retyped the poisoned page.");

	pmap_retire_page(atop(last_page));
	T_ASSERT_TRUE(pmap_is_page_retired(atop(last_page)),
	    "Page at the end of managed memory should be retired.");
	T_ASSERT_EQ(sptm_retype_get_type(), SPTM_UNUSED,
	    "Retyped the poisoned page.");

	T_ASSERT_EQ(ml_page_clear_poison_calls, expected_calls,
	    "Cleared poison for retired pages.");
}

T_DECL(is_page_retired_non_managed,
    "Test if non-kernel managed pages are retired")
{
	const pmap_paddr_t addr_dram_start = gDramBase;
	const pmap_paddr_t addr_out_of_dram = 10;

	T_ASSERT_FALSE(pmap_is_page_retired(atop(addr_dram_start)),
	    "Non-kernel managed pages should not be considered retired.");

	T_ASSERT_FALSE(pmap_is_page_retired(atop(addr_out_of_dram)),
	    "Out of DRAM pages should not be considered retired.");
}

T_DECL(is_page_retired_before_init,
    "Test if pages are retired before pmap initialization")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr = gPhysBase + 600 * PAGE_SIZE;
	pmap_pre_retire(addr);

	/* Mock pmap not initialized. */
	pmap_initialized = false;
	T_SETUPEND;

	T_ASSERT_FALSE(pmap_is_page_retired(atop(addr)),
	    "Pages should not be considered retired before pmap initialization (even if the page is somehow retired).");
}

T_DECL(is_page_retired_flag_set,
    "Test if pages are retired with PVH_FLAG_RETIRED set")
{
	T_SETUPBEGIN;
	const pmap_paddr_t addr = gPhysBase + 700 * PAGE_SIZE;
	T_SETUPEND;

	T_ASSERT_FALSE(pmap_is_page_retired(atop(addr)),
	    "Page should not be retired initially.");

	pmap_pre_retire(addr);

	T_ASSERT_TRUE(pmap_is_page_retired(atop(addr)),
	    "Page with PVH_FLAG_RETIRED should be reported as retired.");
}
