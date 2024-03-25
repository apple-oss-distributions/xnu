/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
#pragma once

/**
 * This file is meant to be the main header that XNU uses to get access to all
 * of the exported SPTM types, declarations, and function prototypes. Wrappers
 * around some of the SPTM library functions are also located in here.
 */
#include <sptm/debug_header.h>
#include <sptm/sptm_xnu.h>
#include <kern/debug.h>

#include <stdbool.h>

/* Bootstrapping arguments passed from the SPTM to XNU. */
extern const sptm_bootstrap_args_xnu_t *SPTMArgs;

typedef struct arm_physrange {
	uint64_t        start_phys;     /* Starting physical address */
	uint64_t        end_phys;       /* Ending physical address (EXCLUSIVE) */
} arm_physrange_t;

/**
 * Convenience function for checking whether an SPTM operation on the given page
 * is in-flight.
 *
 * @note This is just a wrapper around the SPTM library.
 *
 * @param paddr The physical address of the managed page against which to check
 *              for in-flight operations.
 *
 * @return True if an operation is in-flight, false otherwise.
 */
static inline bool
sptm_paddr_is_inflight(sptm_paddr_t paddr)
{
	bool is_inflight = false;
	if (sptm_check_inflight(paddr, &is_inflight) != LIBSPTM_SUCCESS) {
		panic("%s: sptm_check_inflight returned failure for paddr 0x%llx",
		    __func__, (uint64_t)paddr);
	}

	return is_inflight;
}

/**
 * Convenience function for determining the SPTM frame type for a given
 * SPTM-managed page.
 *
 * @note This is just a wrapper around the SPTM library.
 *
 * @param paddr The physical address of the managed page to get the type of.
 *
 * @return The SPTM type for the given frame. If the page passed in is not an
 *         SPTM-managed page, then a panic will get triggered.
 */
static inline sptm_frame_type_t
sptm_get_frame_type(sptm_paddr_t paddr)
{
	sptm_frame_type_t frame_type;
	if (sptm_get_paddr_type(paddr, &frame_type) != LIBSPTM_SUCCESS) {
		panic("%s: sptm_get_paddr_type returned failure for paddr 0x%llx",
		    __func__, (uint64_t)paddr);
	}

	return frame_type;
}

/**
 * Convenience function for checking if a given SPTM-managed
 * page has any mappings.
 *
 * @note This is just a wrapper around the SPTM library.
 *
 * @param paddr The physical address of the managed page to query.
 *
 */
static inline bool
sptm_frame_is_last_mapping(sptm_paddr_t paddr, libsptm_refcnt_type_t refcnt_type)
{
	bool is_last;
	if (sptm_paddr_is_last_mapping(paddr, refcnt_type, &is_last) != LIBSPTM_SUCCESS) {
		panic("%s: sptm_paddr_is_last_mapping returned failure for paddr 0x%llx",
		    __func__, (uint64_t)paddr);
	}

	return is_last;
}

/**
 * Convenience function for retrieving the SPTM page table mapping reference
 * count.
 *
 * @note This is just a wrapper around the SPTM library.
 *
 * @param table_paddr The physical address of the page table page for which to
 *                    obtain the mapping reference count.
 *
 * @return The SPTM mapping reference count for the page table page.  If the page
 *         passed in is not an SPTM-managed page table page, then a panic will be
 *         triggered.
 */
static inline uint16_t
sptm_get_page_table_refcnt(sptm_paddr_t table_paddr)
{
	uint16_t refcnt;
	if (sptm_get_table_mapping_count(table_paddr, &refcnt) != LIBSPTM_SUCCESS) {
		panic("%s: sptm_get_table_mapping_count returned failure for paddr 0x%llx",
		    __func__, (uint64_t)table_paddr);
	}

	return refcnt;
}
