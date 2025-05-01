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

#pragma once

#if PRIVATE

#include <sys/cdefs.h>
#include <mach/machine/kern_return.h>


/*
 * c_segment_info and c_slot_info are used in the serialization protocol of sysctl vm.compressor_segments
 * one c_segment_info is dumped for every c_segment in memory, followed by a number of c_slot_info
 * Every change to this format should increment the version number in VM_C_SEGMENT_INFO_MAGIC
 */
struct c_slot_info {
	uint16_t       csi_size;
	uint16_t       csi_unused;
} __attribute__((packed));

struct c_segment_info {
	uint32_t       csi_mysegno;
	uint32_t       csi_creation_ts;
	uint32_t       csi_swappedin_ts;
	int32_t        csi_bytes_unused;
	int32_t        csi_bytes_used;
	uint32_t       csi_populated_offset;

	uint32_t       csi_state: 4,
	    csi_swappedin: 1,
	    csi_on_minor_compact_q: 1,
	    csi_has_donated_pages: 1,
	    csi_reserved: 25;
	int            csi_slot_var_array_len;/* max is 1024 so this can be short in needed */
	uint32_t       csi_decompressions_since_swapin;
	uint16_t       csi_slots_used;
	uint16_t       csi_slots_len;  /* count of csi_slots */
	struct c_slot_info  csi_slots[0];
} __attribute__((packed));

#define VM_C_SEGMENT_INFO_MAGIC 'C002'

/*
 * vm_map_info_hdr and vm_map_entry_info are used for output of ###
 * a starting header gives the number of entries that follow, the every entry in the vm_map
 * is represented by a vm_map_entry_info
 */
struct vm_map_info_hdr {
	int vmi_nentries;
} __attribute__((packed));

struct vm_map_entry_info {
	vm_map_offset_t         vmei_start;          /* start address */
	vm_map_offset_t         vmei_end;            /* end address */
	unsigned long long
	/* vm_tag_t          */ vmei_alias:12,   /* entry VM tag */
	/* vm_object_offset_t*/ vmei_offset:(64 - 12); /* offset into object */
	uint32_t vmei_is_sub_map: 1,
	    vmei_is_compressor_pager: 1,
	    vmei_protection: 3;
	uint32_t vmei_slot_mapping_count;
	int slot_mappings[0];
} __attribute__((packed));

#define VM_MAP_ENTRY_INFO_MAGIC 'S001'

#endif /* PRIVATE */
