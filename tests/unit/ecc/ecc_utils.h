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

#pragma once

#include <arm64/sptm/pmap/pmap_internal.h>
#include <kern/ecc_init.h>
#include <memmap_types.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>

#include "mocks/std_safe.h"

#define GIB (1ULL * 1024 * 1024 * 1024)

extern vm_offset_t first_avail;

/**
 * Set up a realistically looking memory configuration.
 * The specific values here were taken from a 16 GB Mac.
 */
static void
setup_mem(void)
{
	vm_pages_first_pnum = 0x40044d4;
	gDramBase = 0x10000000000;
	gDramSize = 0x400000000;
	gPhysBase = 0x10001df8000;
	gPhysSize = 0x3d9014000;
	pmap_first_pnum = (ppnum_t)atop(gDramBase);
	vm_pages_count = 992943;

	mem_actual = gDramSize;
	/**
	 * This is not technically true, first_avail is not exactly gPhysBase,
	 * but it's fine to assume that for the tests.
	 */
	first_avail = gPhysBase;
	avail_end = gPhysBase + gPhysSize;

	vm_first_phys = gPhysBase;
	vm_last_phys = trunc_page(avail_end);

	mem_size = gPhysSize;
}

/**
 * Create a mock ECC database carveout with a specified panic page and dramecc.db text.
 *
 * @param carveout[out] The pointer that will point to the carveout. Caller should free this memory.
 * @param panic_page A panic page physical address that the carveout reports (0 to ignore).
 * @param bad_pages A string that represents dramecc.db, will be copied as-is.
 *
 * @return The allocated size of the carveout.
 */
static size_t
create_ecc_carveout(ecc_carveout_t **const carveout, const uint64_t panic_page,
    const char *const bad_pages)
{
	/**
	 * iBoot has a statically sized carveout, XNU on the other hand already supports a
	 * dynamically sized carveout -- so we can allocate just enough memory to fit everything.
	 */
	const size_t carveout_size = sizeof(ecc_carveout_t) + strlen(bad_pages) + 1;
	*carveout = malloc(carveout_size);
	(*carveout)->panic_page = panic_page;

	char *const db_pointer = (*carveout)->db;
	const size_t db_size = carveout_size - sizeof(ecc_carveout_t);
	strlcpy(db_pointer, bad_pages, db_size);

	return carveout_size;
}

/**
 * Create a formatted DB string from an array of addresses.
 *
 * @param db_string[out] The pointer that will point to the "textual" DB. Caller should free this
 *                       memory.
 * @param db_addrs The array of addresses that should be formatted into the DB.
 * @param count Count of addresses.
 *
 * @return The allocated size of the string.
 */
static size_t
create_db_string(char **const db_string, const uint64_t *const db_addrs, const size_t count)
{
	/* Calculate required size: each address is at most 16 hex charactes + \n. */
	const size_t max_size = count * 17 + 1;
	*db_string = malloc(max_size);

	char *ptr = *db_string;
	size_t remaining = max_size;
	for (size_t i = 0; i < count; i++) {
		int written = snprintf(ptr, remaining, "%llx\n", db_addrs[i]);
		if (written < 0 || (size_t)written >= remaining) {
			/* Should not happen. */
			T_FAIL("%s ran out of space", __func__);
		}
		ptr += written;
		remaining -= written;
	}

	if (count == 0) {
		(*db_string)[0] = '\0';
	}

	return strlen(*db_string) + 1;
}

/**
 * Create mock zeroization carveout.
 *
 * @param zero_errors[out] The pointer that will point to the zeroization data. Caller should free
 *                         this memory.
 * @param error_addrs An array of error addresses to use as data.
 * @param count A string that represents dramecc.db, will be copied as-is.
 *
 * @return The allocated size of the carveout.
 */
static size_t
create_zero_errors(bad_memory_entry_t **const zero_errors, const uint64_t *const error_addrs,
    const size_t count)
{
	*zero_errors = malloc(count * sizeof(bad_memory_entry_t));
	for (size_t i = 0; i < count; i++) {
		(*zero_errors)[i].addr = error_addrs[i];
		(*zero_errors)[i].flags = 0;
	}
	return count * sizeof(bad_memory_entry_t);
}

/**
 * Setup device tree mocks with both carveout and zeroization errors
 *
 * @note Pass NULL as the pointer and 0UL as size if a carveout is not needed.
 *
 * @param carveout Pointer to the DRAMECC carveout.
 * @param carveout_size Size of the DRAMECC carveout.
 * @param zero_errors Pointer to the zeroization carveout.
 * @param zero_size Size of the zeroization carveout.
 */
#define setup_ecc_dt_mocks(carveout, carveout_size, zero_errors, zero_size)                                       \
memory_region_v1_t db_entry = { .base = (uint64_t)carveout, .size = carveout_size };                              \
T_MOCK_SET_CALLBACK(SecureDTLookupEntry, int,                                                                     \
	                                (const DTEntry searchPoint, const char *pathName, DTEntry *foundEntry), { \
	        if (strcmp(pathName, "/chosen/carveout-memory-map") == 0UL) {                                     \
	                        return kSuccess;                                                                  \
	        }                                                                                                 \
	        if (strcmp(pathName, "/chosen/memory-report/zeroization-report") == 0UL) {                        \
	                        return ((zero_errors) != NULL) ? kSuccess : kError;                               \
	        }                                                                                                 \
	        return kError;                                                                                    \
});                                                                                                               \
T_MOCK_SET_CALLBACK(SecureDTGetProperty, int,                                                                     \
	                                (const DTEntry entry, const char *propertyName,                           \
	                                void const **propertyValue, unsigned int *propertySize), {                \
	        if (strcmp(propertyName, "region-id-162") == 0UL) {                                               \
	                        *propertyValue = &db_entry;                                                       \
	                        *propertySize = sizeof(memory_region_v1_t);                                       \
	                        return kSuccess;                                                                  \
	        }                                                                                                 \
	        if (strcmp(propertyName, "bad-memory-entry") == 0UL && (zero_errors) != NULL) {                   \
	                        *propertyValue = zero_errors;                                                     \
	                        *propertySize = zero_size;                                                        \
	                        return kSuccess;                                                                  \
	        }                                                                                                 \
	        return kError;                                                                                    \
});
