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

#include <pexpert/arm64/board_config.h>

#if HAS_GUARDED_IO_FILTER

#include <vm/pmap.h>
#include <arm/pmap/pmap_data.h>

extern uint64_t io_filter_vtop(uint64_t addr);

int io_filter_main(uint64_t addr, uint64_t value, uint64_t width, unsigned int io_attr_index, unsigned int io_filter_entry_index);

MARK_AS_PMAP_TEXT
static int
io_filter_write(uint64_t addr, uint64_t value, uint64_t width, unsigned int io_attr_index, unsigned int io_filter_entry_index)
{
	/* Convert the addr to a physical address. */
	const pmap_paddr_t pa = (pmap_paddr_t) io_filter_vtop(addr);

	/* Fail out if PA is zero, indicating translation went wrong. */
	if (__improbable(pa == 0)) {
		return 0;
	}

	extern pmap_io_range_t *io_attr_table;
	extern unsigned int num_io_rgns;

	/* Fail if io_attr_table arguments are bad. */
	if (__improbable(io_attr_table == NULL || io_attr_index >= (uint64_t) num_io_rgns)) {
		return 0;
	}

	extern pmap_io_filter_entry_t *io_filter_table;
	extern unsigned int num_io_filter_entries;

	/* Fail if io_fitler_table arguments are bad. */
	if (__improbable(io_filter_table == NULL || io_filter_entry_index >= (uint64_t) num_io_filter_entries)) {
		return 0;
	}

	const pmap_io_range_t *io_range = &io_attr_table[io_attr_index];
	const pmap_io_filter_entry_t *io_filter_entry = &io_filter_table[io_filter_entry_index];

	/* Fail if pa is not described by the io_attr_table entry. */
	if (__improbable(pa < io_range->addr || (pa + width) > (io_range->addr + io_range->len))) {
		return 0;
	}

	const uint32_t signature = io_range->signature;

	/* Fail if the signature doesn't match. */
	if (__improbable(signature != io_filter_entry->signature)) {
		return 0;
	}

	const uint16_t pa_offset = (uint16_t) (pa & PAGE_MASK);
	const uint16_t pa_length = (uint16_t) width;

	/* Fail if pa is not described by the io_filter_entry. */
	if (__improbable(pa_offset < io_filter_entry->offset || (pa_offset + pa_length) > (io_filter_entry->offset + io_filter_entry->length))) {
		return 0;
	}

	switch (width) {
	case 1:
		*(volatile uint8_t *)addr = (uint8_t) value;
		break;
	case 2:
		*(volatile uint16_t *)addr = (uint16_t) value;
		break;
	case 4:
		*(volatile uint32_t *)addr = (uint32_t) value;
		break;
	case 8:
		*(volatile uint64_t *)addr = (uint64_t) value;
		break;
	default:
		return 0;
	}

	return 1;
}

MARK_AS_PMAP_TEXT
int
io_filter_main(uint64_t addr, uint64_t value, uint64_t width, unsigned int io_attr_index, unsigned int io_filter_entry_index)
{
	// Check if width is supported.
	if ((width != 1) && (width != 2) && (width != 4) && (width != 8)) {
		return 0;
	}

	// Check if addr is width aligned.
	if ((width != 1) && ((addr & (width - 1)) != 0)) {
		return 0;
	}

	return io_filter_write(addr, value, width, io_attr_index, io_filter_entry_index);
}
#endif /* HAS_GUARDED_IO_FILTER */
