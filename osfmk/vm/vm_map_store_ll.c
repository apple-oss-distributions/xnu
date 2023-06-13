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

#include <vm/vm_map.h>

bool
first_free_is_valid_ll(vm_map_t map)
{
	vm_map_offset_t map_page_mask = VM_MAP_PAGE_MASK(map);
	vm_map_entry_t  entry, next;

	entry = vm_map_to_entry(map);
	next = entry->vme_next;
	while (vm_map_trunc_page(next->vme_start, map_page_mask) ==
	    vm_map_trunc_page(entry->vme_end, map_page_mask) ||
	    (vm_map_trunc_page(next->vme_start, map_page_mask) ==
	    vm_map_trunc_page(entry->vme_start, map_page_mask) &&
	    next != vm_map_to_entry(map))) {
		entry = next;
		next = entry->vme_next;
		if (entry == vm_map_to_entry(map)) {
			break;
		}
	}
	if (map->first_free != entry) {
		printf("Bad first_free for map %p: %p should be %p\n",
		    map, map->first_free, entry);
		return FALSE;
	}
	return TRUE;
}

void
vm_map_store_init_ll(struct vm_map_header *hdr)
{
	hdr->links.next = hdr->links.prev = CAST_TO_VM_MAP_ENTRY(hdr);
}

void
vm_map_store_entry_link_ll(
	struct vm_map_header   *hdr,
	vm_map_entry_t          after_where,
	vm_map_entry_t          entry)
{
	if (entry->map_aligned) {
		assert(VM_MAP_PAGE_ALIGNED(entry->vme_start,
		    VM_MAP_HDR_PAGE_MASK(hdr)));
		assert(VM_MAP_PAGE_ALIGNED(entry->vme_end,
		    VM_MAP_HDR_PAGE_MASK(hdr)));
	}
	hdr->nentries++;
	entry->vme_prev = after_where;
	entry->vme_next = after_where->vme_next;
	entry->vme_prev->vme_next = entry->vme_next->vme_prev = entry;
}

void
vm_map_store_entry_unlink_ll(struct vm_map_header *hdr, vm_map_entry_t entry)
{
	hdr->nentries--;
	entry->vme_next->vme_prev = entry->vme_prev;
	entry->vme_prev->vme_next = entry->vme_next;
}

void
vm_map_store_copy_reset_ll(
	vm_map_copy_t           copy,
	__unused vm_map_entry_t entry,
	__unused int            nentries)
{
	copy->cpy_hdr.nentries = 0;
	vm_map_copy_first_entry(copy) =
	    vm_map_copy_last_entry(copy) =
	    vm_map_copy_to_entry(copy);
}

/*
 *	UPDATE_FIRST_FREE:
 *
 *	Updates the map->first_free pointer to the
 *	entry immediately before the first hole in the map.
 *      The map should be locked.
 */
void
update_first_free_ll(vm_map_t map, vm_map_entry_t new_first_free)
{
	vm_map_offset_t map_page_mask = VM_MAP_PAGE_MASK(map);
	vm_map_entry_t  next;

	if (map->holelistenabled || map->disable_vmentry_reuse) {
		return;
	}

	next = new_first_free->vme_next;
	while (vm_map_trunc_page(next->vme_start, map_page_mask) ==
	    vm_map_trunc_page(new_first_free->vme_end, map_page_mask) ||
	    (vm_map_trunc_page(next->vme_start, map_page_mask) ==
	    vm_map_trunc_page(new_first_free->vme_start, map_page_mask) &&
	    next != vm_map_to_entry(map))) {
		new_first_free = next;
		next = new_first_free->vme_next;
		if (new_first_free == vm_map_to_entry(map)) {
			break;
		}
	}

	map->first_free = new_first_free;
	assert(first_free_is_valid(map));
}
