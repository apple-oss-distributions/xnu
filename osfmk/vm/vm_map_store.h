/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_MAP_STORE_H
#define _VM_VM_MAP_STORE_H

#ifndef VM_MAP_STORE_USE_RB
#define VM_MAP_STORE_USE_RB
#endif

#include <libkern/tree.h>
#include <mach/shared_region.h>

struct _vm_map;
struct vm_map_entry;
struct vm_map_copy;
struct vm_map_header;

struct vm_map_store {
#ifdef VM_MAP_STORE_USE_RB
	RB_ENTRY(vm_map_store) entry;
#endif
};

#ifdef VM_MAP_STORE_USE_RB
RB_HEAD(rb_head, vm_map_store);
#endif

/*
 *	Type:		vm_map_entry_t [internal use only]
 *
 *	Description:
 *		A single mapping within an address map.
 *
 *	Implementation:
 *		Address map entries consist of start and end addresses,
 *		a VM object (or sub map) and offset into that object,
 *		and user-exported inheritance and protection information.
 *		Control information for virtual copy operations is also
 *		stored in the address map entry.
 *
 *	Note:
 *		vm_map_relocate_early_elem() knows about this layout,
 *		and needs to be kept in sync.
 */
struct vm_map_links {
	struct vm_map_entry     *prev;          /* previous entry */
	struct vm_map_entry     *next;          /* next entry */
	vm_map_offset_t         start;          /* start address */
	vm_map_offset_t         end;            /* end address */
};


/*
 *	Type:		struct vm_map_header
 *
 *	Description:
 *		Header for a vm_map and a vm_map_copy.
 *
 *	Note:
 *		vm_map_relocate_early_elem() knows about this layout,
 *		and needs to be kept in sync.
 */
struct vm_map_header {
	struct vm_map_links     links;          /* first, last, min, max */
	int                     nentries;       /* Number of entries */
	uint16_t                page_shift;     /* page shift */
	uint16_t                entries_pageable : 1;   /* are map entries pageable? */
	uint16_t                __padding : 15;
#ifdef VM_MAP_STORE_USE_RB
	struct rb_head          rb_head_store;
#endif /* VM_MAP_STORE_USE_RB */
};

#define VM_MAP_HDR_PAGE_SHIFT(hdr)      ((hdr)->page_shift)
#define VM_MAP_HDR_PAGE_SIZE(hdr)       (1 << VM_MAP_HDR_PAGE_SHIFT((hdr)))
#define VM_MAP_HDR_PAGE_MASK(hdr)       (VM_MAP_HDR_PAGE_SIZE((hdr)) - 1)


#include <vm/vm_map_store_ll.h>
#include <vm/vm_map_store_rb.h>

/*
 *	SAVE_HINT_MAP_WRITE:
 *
 *	Saves the specified entry as the hint for
 *	future lookups.  write lock held on map,
 *      so no one else can be writing or looking
 *      until the lock is dropped.
 */
#define SAVE_HINT_MAP_WRITE(map, value) \
	MACRO_BEGIN                    \
	(map)->hint = (value);         \
	MACRO_END

#define SAVE_HINT_HOLE_WRITE(map, value) \
	MACRO_BEGIN                    \
	(map)->hole_hint = (value);     \
	MACRO_END

#define SKIP_RB_TREE            0xBAADC0D1

extern void vm_map_store_init(
	struct vm_map_header   *header);

extern bool vm_map_store_lookup_entry(
	struct _vm_map         *map,
	vm_map_offset_t         address,
	struct vm_map_entry   **entryp);

extern void _vm_map_store_entry_link(
	struct vm_map_header   *header,
	struct vm_map_entry    *after_where,
	struct vm_map_entry    *entry);

extern void vm_map_store_entry_link(
	struct _vm_map         *map,
	struct vm_map_entry    *after_where,
	struct vm_map_entry    *entry,
	vm_map_kernel_flags_t   vmk_flags);

extern void _vm_map_store_entry_unlink(
	struct vm_map_header   *header,
	struct vm_map_entry    *entry,
	bool                    check_permanent);

extern void vm_map_store_entry_unlink(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	bool                    check_permanent);

extern void vm_map_store_update_first_free(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	bool                    new_entry_creation);

extern void vm_map_store_copy_reset(
	struct vm_map_copy     *copy_map,
	struct vm_map_entry    *entry);

#if MACH_ASSERT
extern bool first_free_is_valid_store(
	struct _vm_map         *map);
#endif

extern bool vm_map_store_has_RB_support(
	struct vm_map_header   *header);

extern struct vm_map_entry *vm_map_store_find_space(
	vm_map_t                map,
	vm_map_offset_t         hint,
	vm_map_offset_t         limit,
	bool                    backwards,
	vm_map_offset_t         guard_offset,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_offset_t        *addr_out);

#endif /* _VM_VM_MAP_STORE_H */
