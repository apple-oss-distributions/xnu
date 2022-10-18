/*
 * Copyright (c) 2009-2020 Apple Inc. All rights reserved.
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

#include <kern/backtrace.h>
#include <mach/sdt.h>
#include <vm/vm_map_store.h>
#include <vm/vm_pageout.h> /* for vm_debug_events */

#if MACH_ASSERT
boolean_t
first_free_is_valid_store( vm_map_t map )
{
	return first_free_is_valid_ll( map );
}
#endif

boolean_t
vm_map_store_has_RB_support( struct vm_map_header *hdr )
{
	if ((void*)hdr->rb_head_store.rbh_root == (void*)(int)SKIP_RB_TREE) {
		return FALSE;
	}
	return TRUE;
}

void
vm_map_store_init( struct vm_map_header *hdr )
{
	vm_map_store_init_ll( hdr );
#ifdef VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( hdr )) {
		vm_map_store_init_rb( hdr );
	}
#endif
}

static inline boolean_t
_vm_map_store_lookup_entry(
	vm_map_t                map,
	vm_map_offset_t         address,
	vm_map_entry_t          *entry)         /* OUT */
{
#ifdef VM_MAP_STORE_USE_LL
	return vm_map_store_lookup_entry_ll( map, address, entry );
#elif defined VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( &map->hdr )) {
		return vm_map_store_lookup_entry_rb( map, address, entry );
	} else {
		panic("VM map lookups need RB tree support.");
		return FALSE; /* For compiler warning.*/
	}
#endif
}

__attribute__((noinline))
boolean_t
vm_map_store_lookup_entry(
	vm_map_t                map,
	vm_map_offset_t         address,
	vm_map_entry_t          *entry)         /* OUT */
{
	return _vm_map_store_lookup_entry(map, address, entry);
}

void
vm_map_store_update( vm_map_t map, vm_map_entry_t entry, int update_type )
{
	switch (update_type) {
	case VM_MAP_ENTRY_CREATE:
		break;
	case VM_MAP_ENTRY_DELETE:
		if ((map->holelistenabled == FALSE) && ((entry) == (map)->first_free)) {
			(map)->first_free = vm_map_to_entry(map);
		}
		if ((entry) == (map)->hint) {
			(map)->hint = vm_map_to_entry(map);
		}
		break;
	default:
		break;
	}
}

/*
 *	vm_map_entry_{un,}link:
 *
 *	Insert/remove entries from maps (or map copies).
 *	The _vm_map_store_entry_{un,}link variants are used at
 *	some places where updating first_free is not needed &
 *	copy maps are being modified. Also note the first argument
 *	is the map header.
 *	Modifying the vm_map_store_entry_{un,}link functions to
 *	deal with these call sites made the interface confusing
 *	and clunky.
 */

void
_vm_map_store_entry_link( struct vm_map_header * mapHdr, vm_map_entry_t after_where, vm_map_entry_t entry)
{
	assert(entry->vme_start < entry->vme_end);
	if (__improbable(vm_debug_events)) {
		DTRACE_VM4(map_entry_link, vm_map_t, (char *)mapHdr - sizeof(lck_rw_t), vm_map_entry_t, entry, vm_address_t, entry->links.start, vm_address_t, entry->links.end);
	}

	vm_map_store_entry_link_ll(mapHdr, after_where, entry);
#ifdef VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( mapHdr )) {
		vm_map_store_entry_link_rb(mapHdr, after_where, entry);
	}
#endif
#if MAP_ENTRY_INSERTION_DEBUG
	if (entry->vme_start_original == 0 && entry->vme_end_original == 0) {
		entry->vme_start_original = entry->vme_start;
		entry->vme_end_original = entry->vme_end;
	}
	btref_put(entry->vme_insertion_bt);
	entry->vme_insertion_bt = btref_get(__builtin_frame_address(0),
	    BTREF_GET_NOWAIT);
#endif
}

void
vm_map_store_entry_link(
	vm_map_t                map,
	vm_map_entry_t          after_where,
	vm_map_entry_t          entry,
	vm_map_kernel_flags_t   vmk_flags)
{
	vm_map_t VMEL_map;
	vm_map_entry_t VMEL_entry;
	VMEL_map = (map);
	VMEL_entry = (entry);

	if (entry->is_sub_map) {
		assertf(VM_MAP_PAGE_SHIFT(VME_SUBMAP(entry)) >= VM_MAP_PAGE_SHIFT(map),
		    "map %p (%d) entry %p submap %p (%d)\n",
		    map, VM_MAP_PAGE_SHIFT(map), entry,
		    VME_SUBMAP(entry), VM_MAP_PAGE_SHIFT(VME_SUBMAP(entry)));
	}

	_vm_map_store_entry_link(&VMEL_map->hdr, after_where, VMEL_entry);
	if (VMEL_map->disable_vmentry_reuse == TRUE) {
		UPDATE_HIGHEST_ENTRY_END( VMEL_map, VMEL_entry);
	} else {
		update_first_free_ll(VMEL_map, VMEL_map->first_free);
#ifdef VM_MAP_STORE_USE_RB
		if (vm_map_store_has_RB_support( &VMEL_map->hdr )) {
			update_first_free_rb(VMEL_map, entry, TRUE);
		}
#endif
	}
	(void) vmk_flags;
}

void
_vm_map_store_entry_unlink(
	struct vm_map_header * mapHdr,
	vm_map_entry_t entry,
	bool check_permanent)
{
	if (__improbable(vm_debug_events)) {
		DTRACE_VM4(map_entry_unlink, vm_map_t, (char *)mapHdr - sizeof(lck_rw_t), vm_map_entry_t, entry, vm_address_t, entry->links.start, vm_address_t, entry->links.end);
	}

	/*
	 * We should never unlink a "permanent" entry.  The caller should
	 * clear "permanent" first if it wants it to be bypassed.
	 */
	if (check_permanent) {
		assertf(!entry->vme_permanent, "mapHdr %p entry %p [ 0x%llx end 0x%llx ] prot 0x%x/0x%x submap %d\n", mapHdr, entry, (uint64_t)entry->vme_start, (uint64_t)entry->vme_end, entry->protection, entry->max_protection, entry->is_sub_map);
	}

	vm_map_store_entry_unlink_ll(mapHdr, entry);
#ifdef VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( mapHdr )) {
		vm_map_store_entry_unlink_rb(mapHdr, entry);
	}
#endif
}

void
vm_map_store_entry_unlink(
	vm_map_t map,
	vm_map_entry_t entry,
	bool check_permanent)
{
	vm_map_t VMEU_map;
	vm_map_entry_t VMEU_entry = NULL;
	vm_map_entry_t VMEU_first_free = NULL;
	VMEU_map = (map);
	VMEU_entry = (entry);

	if (map->holelistenabled == FALSE) {
		if (VMEU_entry->vme_start <= VMEU_map->first_free->vme_start) {
			VMEU_first_free = VMEU_entry->vme_prev;
		} else {
			VMEU_first_free = VMEU_map->first_free;
		}
	}
	_vm_map_store_entry_unlink(&VMEU_map->hdr, VMEU_entry, check_permanent);
	vm_map_store_update( map, entry, VM_MAP_ENTRY_DELETE);
	update_first_free_ll(VMEU_map, VMEU_first_free);
#ifdef VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( &VMEU_map->hdr )) {
		update_first_free_rb(VMEU_map, entry, FALSE);
	}
#endif
}

void
vm_map_store_copy_reset( vm_map_copy_t copy, vm_map_entry_t entry)
{
	int nentries = copy->cpy_hdr.nentries;
	vm_map_store_copy_reset_ll(copy, entry, nentries);
#ifdef VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( &copy->c_u.hdr )) {
		vm_map_store_copy_reset_rb(copy, entry, nentries);
	}
#endif
}

void
vm_map_store_update_first_free( vm_map_t map, vm_map_entry_t first_free_entry, boolean_t new_entry_creation)
{
	update_first_free_ll(map, first_free_entry);
#ifdef VM_MAP_STORE_USE_RB
	if (vm_map_store_has_RB_support( &map->hdr )) {
		update_first_free_rb(map, first_free_entry, new_entry_creation);
	}
#endif
}

__abortlike
static void
__vm_map_store_find_space_holelist_corruption(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_entry_t          entry)
{
	panic("Found an existing entry %p [0x%llx, 0x%llx) in map %p "
	    "instead of potential hole at address: 0x%llx.",
	    entry, entry->vme_start, entry->vme_end, map, start);
}

static void
vm_map_store_convert_hole_to_entry(
	vm_map_t                map,
	vm_map_offset_t         addr,
	vm_map_entry_t         *entry_p)
{
	vm_map_entry_t entry = *entry_p;

	if (_vm_map_store_lookup_entry(map, entry->vme_start, entry_p)) {
		__vm_map_store_find_space_holelist_corruption(map, addr, entry);
	}
}

static struct vm_map_entry *
vm_map_store_find_space_backwards(
	vm_map_t                map,
	vm_map_offset_t         end,
	vm_map_offset_t         lowest_addr,
	vm_map_offset_t         guard_offset,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_offset_t        *addr_out)
{
	const vm_map_offset_t map_mask  = VM_MAP_PAGE_MASK(map);
	const bool            use_holes = map->holelistenabled;
	vm_map_offset_t       start;
	vm_map_entry_t        entry;

	/*
	 *	Find the entry we will scan from that is the closest
	 *	to our required scan hint "end".
	 */

	if (use_holes) {
		entry = CAST_TO_VM_MAP_ENTRY(map->holes_list);
		if (entry == VM_MAP_ENTRY_NULL) {
			return VM_MAP_ENTRY_NULL;
		}

		entry = entry->vme_prev;

		while (end <= entry->vme_start) {
			if (entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
				return VM_MAP_ENTRY_NULL;
			}

			entry = entry->vme_prev;
		}

		if (entry->vme_end < end) {
			end = entry->vme_end;
		}
	} else {
		if (map->max_offset <= end) {
			entry = vm_map_to_entry(map);
			end = map->max_offset;
		} else if (_vm_map_store_lookup_entry(map, end - 1, &entry)) {
			end = entry->vme_start;
		} else {
			entry = entry->vme_next;
		}
	}

	for (;;) {
		/*
		 * The "entry" follows the proposed new region.
		 */

		end    = vm_map_trunc_page(end, map_mask);
		start  = (end - size) & ~mask;
		start  = vm_map_trunc_page(start, map_mask);
		end    = start + size;
		start -= guard_offset;

		if (end < start || start < lowest_addr) {
			/*
			 * Fail: reached our scan lowest address limit,
			 * without finding a large enough hole.
			 */
			return VM_MAP_ENTRY_NULL;
		}

		if (use_holes) {
			if (entry->vme_start <= start) {
				/*
				 * Done: this hole is wide enough.
				 */
				vm_map_store_convert_hole_to_entry(map, start, &entry);
				break;
			}

			if (entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
				/*
				 * Fail: wrapped around, no more holes
				 */
				return VM_MAP_ENTRY_NULL;
			}

			entry = entry->vme_prev;
			end = entry->vme_end;
		} else {
			entry = entry->vme_prev;

			if (entry == vm_map_to_entry(map)) {
				/*
				 * Done: no more entries toward the start
				 * of the map, only a big enough void.
				 */
				break;
			}

			if (entry->vme_end <= start) {
				/*
				 * Done: the gap between the two consecutive
				 * entries is large enough.
				 */
				break;
			}

			end = entry->vme_start;
		}
	}

	*addr_out = start;
	return entry;
}

static struct vm_map_entry *
vm_map_store_find_space_forward(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         highest_addr,
	vm_map_offset_t         guard_offset,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_offset_t        *addr_out)
{
	const vm_map_offset_t map_mask  = VM_MAP_PAGE_MASK(map);
	const bool            use_holes = map->holelistenabled;
	vm_map_entry_t        entry;

	/*
	 *	Find the entry we will scan from that is the closest
	 *	to our required scan hint "start".
	 */

	if (__improbable(map->disable_vmentry_reuse)) {
		VM_MAP_HIGHEST_ENTRY(map, entry, start);
	} else if (use_holes) {
		entry = CAST_TO_VM_MAP_ENTRY(map->holes_list);
		if (entry == VM_MAP_ENTRY_NULL) {
			return VM_MAP_ENTRY_NULL;
		}

		while (entry->vme_end <= start) {
			entry = entry->vme_next;

			if (entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
				return VM_MAP_ENTRY_NULL;
			}
		}

		if (start < entry->vme_start) {
			start = entry->vme_start;
		}
	} else {
		vm_map_offset_t first_free_start;

		assert(first_free_is_valid(map));

		entry = map->first_free;
		if (entry == vm_map_to_entry(map)) {
			first_free_start = map->min_offset;
		} else {
			first_free_start = entry->vme_end;
		}

		if (start <= first_free_start) {
			start = first_free_start;
		} else if (_vm_map_store_lookup_entry(map, start, &entry)) {
			start = entry->vme_end;
		}
	}

	for (;;) {
		vm_map_offset_t orig_start = start;
		vm_map_offset_t end, desired_empty_end;

		/*
		 * The "entry" precedes the proposed new region.
		 */

		start  = (start + guard_offset + mask) & ~mask;
		start  = vm_map_round_page(start, map_mask);
		end    = start + size;
		start -= guard_offset;
		/*
		 * We want an entire page of empty space,
		 * but don't increase the allocation size.
		 */
		desired_empty_end = vm_map_round_page(end, map_mask);

		if (start < orig_start || desired_empty_end < start ||
		    highest_addr < desired_empty_end) {
			/*
			 * Fail: reached our scan highest address limit,
			 * without finding a large enough hole.
			 */
			return VM_MAP_ENTRY_NULL;
		}

		if (use_holes) {
			if (desired_empty_end <= entry->vme_end) {
				/*
				 * Done: this hole is wide enough.
				 */
				vm_map_store_convert_hole_to_entry(map, start, &entry);
				break;
			}

			entry = entry->vme_next;

			if (entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
				/*
				 * Fail: wrapped around, no more holes
				 */
				return VM_MAP_ENTRY_NULL;
			}

			start = entry->vme_start;
		} else {
			vm_map_entry_t next = entry->vme_next;

			if (next == vm_map_to_entry(map)) {
				/*
				 * Done: no more entries toward the end
				 * of the map, only a big enough void.
				 */
				break;
			}

			if (desired_empty_end <= next->vme_start) {
				/*
				 * Done: the gap between the two consecutive
				 * entries is large enough.
				 */
				break;
			}

			entry = next;
			start = entry->vme_end;
		}
	}

	*addr_out = start;
	return entry;
}

struct vm_map_entry *
vm_map_store_find_space(
	vm_map_t                map,
	vm_map_offset_t         hint,
	vm_map_offset_t         limit,
	boolean_t               backwards,
	vm_map_offset_t         guard_offset,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_offset_t        *addr_out)
{
	vm_map_entry_t entry;

#if defined VM_MAP_STORE_USE_RB
	__builtin_assume((void*)map->hdr.rb_head_store.rbh_root !=
	    (void*)(int)SKIP_RB_TREE);
#endif

	if (backwards) {
		entry = vm_map_store_find_space_backwards(map, hint, limit,
		    guard_offset, size, mask, addr_out);
	} else {
		entry = vm_map_store_find_space_forward(map, hint, limit,
		    guard_offset, size, mask, addr_out);
	}

	return entry;
}
