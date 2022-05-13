/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	vm/vm_kern.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Kernel memory management.
 */

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <vm/vm_kern.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_compressor.h>
#include <vm/vm_pageout.h>
#include <vm/vm_init.h>
#include <kern/misc_protos.h>
#include <vm/cpm.h>
#include <kern/ledger.h>
#include <kern/bits.h>
#include <kern/startup.h>

#include <string.h>

#include <libkern/OSDebug.h>
#include <libkern/crypto/sha2.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>

#include <san/kasan.h>
#include <kern/kext_alloc.h>

/*
 *	Variables exported by this module.
 */

SECURITY_READ_ONLY_LATE(vm_map_t) kernel_map;
SECURITY_READ_ONLY_LATE(struct kmem_range) kmem_ranges[KMEM_RANGE_COUNT] = {};
#if ZSECURITY_CONFIG(KERNEL_DATA_SPLIT)
SECURITY_READ_ONLY_LATE(struct kmem_range)
kmem_large_ranges[KMEM_RANGE_COUNT] = {};
#endif

/*
 * Forward declarations for internal functions.
 */
extern kern_return_t kmem_alloc_pages(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size);

#pragma mark kmem range methods

__attribute__((overloadable))
__header_always_inline bool
kmem_range_contains(const struct kmem_range *r, vm_offset_t addr)
{
	vm_offset_t rmin, rmax;

#if CONFIG_KERNEL_TBI
	addr = VM_KERNEL_TBI_FILL(addr);
#endif /* CONFIG_KERNEL_TBI */

	/*
	 * The `&` is not a typo: we really expect the check to pass,
	 * so encourage the compiler to eagerly load and test without branches
	 */
	kmem_range_load(r, rmin, rmax);
	return (addr >= rmin) & (addr < rmax);
}

__attribute__((overloadable))
__header_always_inline bool
kmem_range_contains(const struct kmem_range *r, vm_offset_t addr, vm_offset_t size)
{
	vm_offset_t rmin, rmax;

#if CONFIG_KERNEL_TBI
	addr = VM_KERNEL_TBI_FILL(addr);
#endif /* CONFIG_KERNEL_TBI */

	/*
	 * The `&` is not a typo: we really expect the check to pass,
	 * so encourage the compiler to eagerly load and test without branches
	 */
	kmem_range_load(r, rmin, rmax);
	return (addr >= rmin) & (addr + size >= rmin) & (addr + size <= rmax);
}

__header_always_inline vm_size_t
kmem_range_size(const struct kmem_range *r)
{
	vm_offset_t rmin, rmax;

	kmem_range_load(r, rmin, rmax);
	return rmax - rmin;
}

bool
kmem_range_id_contains(kmem_range_id_t range_id, vm_map_offset_t addr,
    vm_map_size_t size)
{
	return kmem_range_contains(&kmem_ranges[range_id], addr, size);
}

kmem_range_id_t
kmem_addr_get_range(vm_map_offset_t addr, vm_map_size_t size)
{
	kmem_range_id_t range_id = 0;
	for (; range_id < KMEM_RANGE_COUNT; range_id++) {
		if (kmem_range_id_contains(range_id, addr, size)) {
			break;
		}
	}
	return range_id;
}



kern_return_t
kmem_alloc_contig(
	vm_map_t                map,
	vm_offset_t             *addrp,
	vm_size_t               size,
	vm_offset_t             mask,
	ppnum_t                 max_pnum,
	ppnum_t                 pnum_mask,
	kma_flags_t             flags,
	vm_tag_t                tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_map_offset_t         map_addr;
	vm_map_offset_t         map_mask;
	vm_map_size_t           map_size, i;
	vm_map_entry_t          entry;
	vm_page_t               m, pages;
	kern_return_t           kr;
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	assert(VM_KERN_MEMORY_NONE != tag);
	assert(map);
	assert3u(flags & ~KMEM_ALLOC_CONTIG_FLAGS, ==, 0);

	map_size = vm_map_round_page(size, VM_MAP_PAGE_MASK(map));
	map_mask = (vm_map_offset_t)mask;

	/* Check for zero allocation size (either directly or via overflow) */
	if (map_size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Allocate a new object (if necessary) and the reference we
	 *	will be donating to the map entry.  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if ((flags & KMA_KOBJECT) != 0) {
		object = kernel_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
	}
	if (flags & KMA_PERMANENT) {
		vmk_flags.vmkf_permanent = true;
	}
	if (flags & KMA_DATA) {
		vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA;
		if (flags & KMA_PERMANENT) {
			vmk_flags.vmkf_last_free = true;
		}
	}

	kr = vm_map_find_space(map, 0, map_size, map_mask,
	    vmk_flags, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		return kr;
	}

	map_addr = entry->vme_start;
	if (object == kernel_object) {
		offset = map_addr;
	} else {
		offset = 0;
	}
	VME_OBJECT_SET(entry, object);
	VME_OFFSET_SET(entry, offset);
	VME_ALIAS_SET(entry, tag);

	/* Take an extra object ref in case the map entry gets deleted */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = cpm_allocate(CAST_DOWN(vm_size_t, map_size), &pages, max_pnum, pnum_mask, FALSE, flags);

	if (kr != KERN_SUCCESS) {
		vm_map_remove(map,
		    vm_map_trunc_page(map_addr,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(map_addr + map_size,
		    VM_MAP_PAGE_MASK(map)));
		vm_object_deallocate(object);
		*addrp = 0;
		return kr;
	}

	if (flags & KMA_ZERO) {
		for (m = pages; m; m = NEXT_PAGE(m)) {
			vm_page_zero_fill(m);
		}
	}


	vm_object_lock(object);
	for (i = 0; i < map_size; i += PAGE_SIZE) {
		m = pages;
		pages = NEXT_PAGE(m);
		*(NEXT_PAGE_PTR(m)) = VM_PAGE_NULL;
		m->vmp_busy = FALSE;
		vm_page_insert(m, object, offset + i);
	}
	vm_object_unlock(object);

	kr = vm_map_wire_kernel(map,
	    vm_map_trunc_page(map_addr,
	    VM_MAP_PAGE_MASK(map)),
	    vm_map_round_page(map_addr + map_size,
	    VM_MAP_PAGE_MASK(map)),
	    VM_PROT_DEFAULT, tag,
	    FALSE);

	if (kr != KERN_SUCCESS) {
		if (object == kernel_object) {
			vm_object_lock(object);
			vm_object_page_remove(object, offset, offset + map_size);
			vm_object_unlock(object);
		}
		vm_map_remove(map,
		    vm_map_trunc_page(map_addr,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(map_addr + map_size,
		    VM_MAP_PAGE_MASK(map)));
		vm_object_deallocate(object);
		return kr;
	}
	vm_object_deallocate(object);

	if (object == kernel_object) {
		vm_map_simplify(map, map_addr);
		vm_tag_update_size(tag, map_size);
	}
	*addrp = (vm_offset_t) map_addr;
	assert((vm_map_offset_t) *addrp == map_addr);

	return KERN_SUCCESS;
}

/*
 * Master entry point for allocating kernel memory.
 * NOTE: this routine is _never_ interrupt safe.
 *
 * map		: map to allocate into
 * addrp	: pointer to start address of new memory
 * size		: size of memory requested
 * flags	: see kma_flags_t.
 */

__abortlike
static void
__kma_failed_panic(
	vm_map_t        map,
	kern_return_t   kr,
	vm_size_t       size,
	vm_offset_t     mask,
	kma_flags_t     flags,
	vm_tag_t        tag)
{
	panic("kernel_memory_allocate(%p, _, %zd, 0x%zx, 0x%x, %d) "
	    "failed unexpectedly with %d",
	    map, (size_t)size, (size_t)mask, flags, tag, kr);
}

kern_return_t
kernel_memory_allocate(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_offset_t     mask,
	kma_flags_t     flags,
	vm_tag_t        tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_map_entry_t          entry = NULL;
	vm_map_offset_t         map_addr, fill_start;
	vm_map_size_t           map_size, fill_size;
	kern_return_t           kr;
	vm_page_t               guard_left = VM_PAGE_NULL;
	vm_page_t               guard_right = VM_PAGE_NULL;
	vm_page_t               wired_page_list = VM_PAGE_NULL;
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	bool                    need_guards;

	assert(kernel_map && map->pmap == kernel_pmap);

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#endif

	/* Check for zero allocation size (either directly or via overflow) */
	map_size = vm_map_round_page(size, VM_MAP_PAGE_MASK(map));
	if (__improbable(map_size == 0)) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	/*
	 * limit the size of a single extent of wired memory
	 * to try and limit the damage to the system if
	 * too many pages get wired down
	 * limit raised to 2GB with 128GB max physical limit,
	 * but scaled by installed memory above this
	 */
	if (__improbable(!(flags & (KMA_VAONLY | KMA_PAGEABLE)) &&
	    map_size > MAX(1ULL << 31, sane_size / 64))) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	/*
	 * Guard pages:
	 *
	 * Guard pages are implemented as fictitious pages.
	 *
	 * However, some maps, and some objects are known
	 * to manage their memory explicitly, and do not need
	 * those to be materialized, which saves memory.
	 *
	 * By placing guard pages on either end of a stack,
	 * they can help detect cases where a thread walks
	 * off either end of its stack.
	 *
	 * They are allocated and set up here and attempts
	 * to access those pages are trapped in vm_fault_page().
	 *
	 * The map_size we were passed may include extra space for
	 * guard pages. fill_size represents the actual size to populate.
	 * Similarly, fill_start indicates where the actual pages
	 * will begin in the range.
	 */

	fill_start = 0;
	fill_size = map_size;

	need_guards = flags & (KMA_KOBJECT | KMA_COMPRESSOR) ||
	    !map->never_faults;

	if (flags & KMA_GUARD_FIRST) {
		vmk_flags.vmkf_guard_before = true;
		fill_start += PAGE_SIZE;
		if (__improbable(os_sub_overflow(fill_size, PAGE_SIZE, &fill_size))) {
			/* no space for a guard page */
			kr = KERN_INVALID_ARGUMENT;
			goto out;
		}
		if (need_guards) {
			guard_left = vm_page_grab_guard((flags & KMA_NOPAGEWAIT) == 0);
			if (__improbable(guard_left == VM_PAGE_NULL)) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
		}
	}
	if (flags & KMA_GUARD_LAST) {
		if (__improbable(os_sub_overflow(fill_size, PAGE_SIZE, &fill_size))) {
			/* no space for a guard page */
			kr = KERN_INVALID_ARGUMENT;
			goto out;
		}
		if (need_guards) {
			guard_right = vm_page_grab_guard((flags & KMA_NOPAGEWAIT) == 0);
			if (__improbable(guard_right == VM_PAGE_NULL)) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
		}
	}

	if (!(flags & (KMA_VAONLY | KMA_PAGEABLE))) {
		kr = vm_page_alloc_list(atop(fill_size), flags,
		    &wired_page_list);
		if (__improbable(kr != KERN_SUCCESS)) {
			goto out;
		}
	}

	/*
	 *	Allocate a new object (if necessary).  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if (flags & KMA_KOBJECT) {
		object = kernel_object;
		vm_object_reference(object);
	} else if (flags & KMA_COMPRESSOR) {
		object = compressor_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
	}

	if (flags & KMA_ATOMIC) {
		vmk_flags.vmkf_atomic_entry = TRUE;
	}
	if (flags & KMA_LAST_FREE) {
		vmk_flags.vmkf_last_free = true;
	}
	if (flags & KMA_PERMANENT) {
		vmk_flags.vmkf_permanent = true;
	}
	if (flags & KMA_DATA) {
		vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA;
		if (flags & KMA_PERMANENT) {
			vmk_flags.vmkf_last_free = true;
		}
	}

	kr = vm_map_find_space(map, 0, map_size, mask, vmk_flags, &entry);
	if (__improbable(KERN_SUCCESS != kr)) {
		vm_object_deallocate(object);
		goto out;
	}

	map_addr = entry->vme_start;
	if (flags & (KMA_COMPRESSOR | KMA_KOBJECT)) {
		offset = map_addr;
	} else {
		offset = 0;
		vm_object_reference(object);
	}
	VME_OBJECT_SET(entry, object);
	VME_OFFSET_SET(entry, offset);
	VME_ALIAS_SET(entry, tag);

	if (!(flags & (KMA_COMPRESSOR | KMA_PAGEABLE))) {
		entry->wired_count = 1;
	}

	if (guard_left || guard_right || wired_page_list) {
		vm_object_lock(object);
		vm_map_unlock(map);

		if (guard_left) {
			vm_page_insert(guard_left, object, offset);
			guard_left->vmp_busy = FALSE;
			guard_left = VM_PAGE_NULL;
		}

		if (guard_right) {
			vm_page_insert(guard_right, object,
			    offset + fill_start + fill_size);
			guard_right->vmp_busy = FALSE;
			guard_right = VM_PAGE_NULL;
		}

		if (wired_page_list) {
			kernel_memory_populate_object_and_unlock(object,
			    map_addr + fill_start, offset + fill_start, fill_size,
			    wired_page_list, flags, tag, VM_PROT_DEFAULT);
		} else {
			vm_object_unlock(object);
		}
	} else {
		vm_map_unlock(map);
	}

#if KASAN
	if (flags & KMA_PAGEABLE) {
		/*
		 * We need to allow the range for pageable memory,
		 * or faulting will not be allowed.
		 */
		kasan_notify_address(map_addr, size);
	}
#endif
	/*
	 * now that the pages are wired, we no longer have to fear coalesce
	 */
	if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
		vm_map_simplify(map, map_addr);
	} else {
		vm_object_deallocate(object);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
	    atop(fill_size), 0, 0, 0);
#endif

	*addrp = CAST_DOWN(vm_offset_t, map_addr);
	return KERN_SUCCESS;

out:
	if (kr != KERN_SUCCESS && (flags & KMA_NOFAIL)) {
		__kma_failed_panic(map, kr, size, mask, flags, tag);
	}
	if (guard_left) {
		guard_left->vmp_snext = wired_page_list;
		wired_page_list = guard_left;
	}
	if (guard_right) {
		guard_right->vmp_snext = wired_page_list;
		wired_page_list = guard_right;
	}
	if (wired_page_list) {
		vm_page_free_list(wired_page_list, FALSE);
	}
	*addrp = 0;

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
	    0, 0, 0, 0);
#endif
	return kr;
}

void
kernel_memory_populate_object_and_unlock(
	vm_object_t     object, /* must be locked */
	vm_address_t    addr,
	vm_offset_t     offset,
	vm_size_t       size,
	vm_page_t       page_list,
	kma_flags_t     flags,
	vm_tag_t        tag,
	vm_prot_t       prot)
{
	kern_return_t   pe_result;
	vm_page_t       mem;
	int             pe_options;
	int             pe_flags;

	assert3u((bool)(flags & KMA_KOBJECT), ==, object == kernel_object);
	assert3u((bool)(flags & KMA_COMPRESSOR), ==, object == compressor_object);
	if (flags & (KMA_KOBJECT | KMA_COMPRESSOR)) {
		assert3u(offset, ==, addr);
	}

	if (flags & KMA_KSTACK) {
		pe_flags = VM_MEM_STACK;
	} else {
		pe_flags = 0;
	}

	for (vm_object_offset_t pg_offset = 0;
	    pg_offset < size;
	    pg_offset += PAGE_SIZE_64) {
		if (page_list == NULL) {
			panic("%s: page_list too short", __func__);
		}

		mem = page_list;
		page_list = mem->vmp_snext;
		mem->vmp_snext = NULL;

		assert(mem->vmp_wire_count == 0);
		assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);

		if (flags & KMA_COMPRESSOR) {
			mem->vmp_q_state = VM_PAGE_USED_BY_COMPRESSOR;

			vm_page_insert(mem, object, offset + pg_offset);
		} else {
			mem->vmp_q_state = VM_PAGE_IS_WIRED;
			mem->vmp_wire_count = 1;

			vm_page_insert_wired(mem, object, offset + pg_offset, tag);
		}

		mem->vmp_busy = false;
		mem->vmp_pmapped = true;
		mem->vmp_wpmapped = true;

		/*
		 * Manual PMAP_ENTER_OPTIONS() with shortcuts
		 * for the kernel and compressor objects.
		 */

		PMAP_ENTER_CHECK(kernel_pmap, mem);

		pe_options = PMAP_OPTIONS_NOWAIT;
		if (flags & (KMA_COMPRESSOR | KMA_KOBJECT)) {
			pe_options |= PMAP_OPTIONS_INTERNAL;
		} else {
			if (object->internal) {
				pe_options |= PMAP_OPTIONS_INTERNAL;
			}
			if (mem->vmp_reusable || object->all_reusable) {
				pe_options |= PMAP_OPTIONS_REUSABLE;
			}
		}

		pe_result = pmap_enter_options(kernel_pmap,
		    addr + pg_offset, VM_PAGE_GET_PHYS_PAGE(mem),
		    prot, VM_PROT_NONE, pe_flags,
		    /* wired */ TRUE, pe_options, NULL);

		if (pe_result == KERN_RESOURCE_SHORTAGE) {
			vm_object_unlock(object);

			pe_options &= ~PMAP_OPTIONS_NOWAIT;

			pe_result = pmap_enter_options(kernel_pmap,
			    addr + pg_offset, VM_PAGE_GET_PHYS_PAGE(mem),
			    prot, VM_PROT_NONE, pe_flags,
			    /* wired */ TRUE, pe_options, NULL);

			vm_object_lock(object);
		}

		assert(pe_result == KERN_SUCCESS);

		if (flags & KMA_NOENCRYPT) {
			pmap_set_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
		}
	}

	if (page_list) {
		panic("%s: page_list too long", __func__);
	}

	vm_object_unlock(object);

	if (!(flags & KMA_COMPRESSOR)) {
		vm_page_lockspin_queues();
		vm_page_wire_count += atop(size);
		vm_page_unlock_queues();
	}

	if (flags & KMA_KOBJECT) {
		/* vm_page_insert_wired() handles regular objects already */
		vm_tag_update_size(tag, size);
	}

#if KASAN
	if (flags & KMA_COMPRESSOR) {
		kasan_notify_address_nopoison(addr, size);
	} else {
		kasan_notify_address(addr, size);
	}
#endif
}

__abortlike
static void
__kernel_or_compressor_object_panic(kma_flags_t flags)
{
	if (flags == 0) {
		panic("KMA_KOBJECT or KMA_COMPRESSOR is required");
	}
	panic("more than one of KMA_KOBJECT or KMA_COMPRESSOR specified");
}

static inline vm_object_t
kernel_or_compressor_object(kma_flags_t flags)
{
	flags &= (KMA_KOBJECT | KMA_COMPRESSOR);
	if (flags == 0 || (flags & (flags - 1))) {
		__kernel_or_compressor_object_panic(flags);
	}

	return (flags & KMA_KOBJECT) ? kernel_object : compressor_object;
}

kern_return_t
kernel_memory_populate(
	vm_offset_t     addr,
	vm_size_t       size,
	kma_flags_t     flags,
	vm_tag_t        tag)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_page_t       page_list = NULL;
	vm_size_t       page_count = atop_64(size);
	vm_object_t     object = kernel_or_compressor_object(flags);

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#endif

	kr = vm_page_alloc_list(page_count, flags, &page_list);
	if (kr == KERN_SUCCESS) {
		vm_object_lock(object);
		kernel_memory_populate_object_and_unlock(object, addr,
		    addr, size, page_list, flags, tag, VM_PROT_DEFAULT);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
	    page_count, 0, 0, 0);
#endif
	return kr;
}

void
kernel_memory_depopulate(
	vm_offset_t        addr,
	vm_size_t          size,
	kma_flags_t        flags,
	vm_tag_t           tag)
{
	vm_object_t        object = kernel_or_compressor_object(flags);
	vm_object_offset_t offset = addr;
	vm_page_t          mem;
	vm_page_t          local_freeq = NULL;
	unsigned int       pages_unwired = 0;

	vm_object_lock(object);

	pmap_protect(kernel_pmap, offset, offset + size, VM_PROT_NONE);

	for (vm_object_offset_t pg_offset = 0;
	    pg_offset < size;
	    pg_offset += PAGE_SIZE_64) {
		mem = vm_page_lookup(object, offset + pg_offset);

		assert(mem);

		if (flags & KMA_COMPRESSOR) {
			assert(mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR);
		} else {
			assert(mem->vmp_q_state == VM_PAGE_IS_WIRED);
			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));
			pages_unwired++;
		}

		mem->vmp_busy = TRUE;

		assert(mem->vmp_tabled);
		vm_page_remove(mem, TRUE);
		assert(mem->vmp_busy);

		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);

		mem->vmp_q_state = VM_PAGE_NOT_ON_Q;
		mem->vmp_snext = local_freeq;
		local_freeq = mem;
	}

	vm_object_unlock(object);

	vm_page_free_list(local_freeq, TRUE);

	if (!(flags & KMA_COMPRESSOR)) {
		vm_page_lockspin_queues();
		vm_page_wire_count -= pages_unwired;
		vm_page_unlock_queues();
	}

	if (flags & KMA_KOBJECT) {
		/* vm_page_remove() handles regular objects already */
		vm_tag_update_size(tag, -ptoa_64(pages_unwired));
	}
}

/*
 *	kmem_realloc:
 *
 *	Reallocate wired-down memory in the kernel's address map
 *	or a submap.  Newly allocated pages are not zeroed.
 *	This can only be used on regions allocated with kmem_alloc.
 *
 *	If successful, the pages in the old region are mapped twice.
 *	The old region is unchanged.  Use kmem_free to get rid of it.
 */
kern_return_t
kmem_realloc(
	vm_map_t                map,
	vm_offset_t             oldaddr,
	vm_size_t               oldsize,
	vm_offset_t             *newaddrp,
	vm_size_t               newsize,
	vm_tag_t                tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_map_offset_t         oldmapmin;
	vm_map_offset_t         oldmapmax;
	vm_map_offset_t         newmapaddr;
	vm_map_size_t           oldmapsize;
	vm_map_size_t           newmapsize;
	vm_map_entry_t          oldentry;
	vm_map_entry_t          newentry;
	vm_page_t               mem;
	kern_return_t           kr;
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	oldmapmin = vm_map_trunc_page(oldaddr,
	    VM_MAP_PAGE_MASK(map));
	oldmapmax = vm_map_round_page(oldaddr + oldsize,
	    VM_MAP_PAGE_MASK(map));
	oldmapsize = oldmapmax - oldmapmin;
	newmapsize = vm_map_round_page(newsize,
	    VM_MAP_PAGE_MASK(map));
	if (newmapsize < newsize) {
		/* overflow */
		*newaddrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Find the VM object backing the old region.
	 */

	vm_map_lock(map);

	if (!vm_map_lookup_entry(map, oldmapmin, &oldentry)) {
		panic("kmem_realloc");
	}
	if (oldentry->vme_atomic) {
		vmk_flags.vmkf_atomic_entry = true;
	}
	vmk_flags.vmkf_range_id = kmem_addr_get_range(oldmapmin, oldmapsize);

	object = VME_OBJECT(oldentry);

	/*
	 *	Increase the size of the object and
	 *	fill in the new region.
	 */

	vm_object_reference(object);
	/* by grabbing the object lock before unlocking the map */
	/* we guarantee that we will panic if more than one     */
	/* attempt is made to realloc a kmem_alloc'd area       */
	vm_object_lock(object);
	vm_map_unlock(map);
	if (object->vo_size != oldmapsize) {
		panic("kmem_realloc");
	}
	object->vo_size = newmapsize;
	vm_object_unlock(object);

	/* allocate the new pages while expanded portion of the */
	/* object is still not mapped */
	kmem_alloc_pages(object, vm_object_round_page(oldmapsize),
	    vm_object_round_page(newmapsize - oldmapsize));

	/*
	 *	Find space for the new region.
	 */

	kr = vm_map_find_space(map, 0, newmapsize, 0, vmk_flags, &newentry);
	if (kr != KERN_SUCCESS) {
		vm_object_lock(object);
		for (offset = oldmapsize;
		    offset < newmapsize; offset += PAGE_SIZE) {
			if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				VM_PAGE_FREE(mem);
			}
		}
		object->vo_size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return kr;
	}

	newmapaddr = newentry->vme_start;
	VME_OBJECT_SET(newentry, object);
	VME_ALIAS_SET(newentry, tag);
	assert(newentry->wired_count == 0);


	/* add an extra reference in case we have someone doing an */
	/* unexpected deallocate */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = vm_map_wire_kernel(map, newmapaddr, newmapaddr + newmapsize,
	    VM_PROT_DEFAULT, tag, FALSE);
	if (KERN_SUCCESS != kr) {
		kmem_free(map, newmapaddr, newmapsize);
		vm_object_lock(object);
		for (offset = oldsize; offset < newmapsize; offset += PAGE_SIZE) {
			if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				VM_PAGE_FREE(mem);
			}
		}
		object->vo_size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return kr;
	}
	vm_object_deallocate(object);

	if (kernel_object == object) {
		vm_tag_update_size(tag, newmapsize);
	}

	*newaddrp = CAST_DOWN(vm_offset_t, newmapaddr);
	return KERN_SUCCESS;
}

void
kmem_realloc_down(
	vm_map_t                map,
	vm_offset_t             addr,
	vm_size_t               oldsize,
	vm_size_t               newsize)
{
	vm_object_t             object;
	vm_map_entry_t          entry;
	bool                    was_atomic;

	oldsize = round_page(oldsize);
	newsize = round_page(newsize);

	if (oldsize <= newsize) {
		panic("kmem_realloc_down() called with invalid sizes %zd <= %zd",
		    (size_t)oldsize, (size_t)newsize);
	}

	/*
	 *	Find the VM object backing the old region.
	 */

	vm_map_lock(map);

	if (!vm_map_lookup_entry(map, addr, &entry)) {
		panic("kmem_realloc");
	}
	object = VME_OBJECT(entry);
	vm_object_reference(object);

	/*
	 * This function has limited support for what it can do
	 * and assumes the object is fully mapped in the range.
	 *
	 * Its only caller is OSData::clipForCopyout()
	 * and only supports this use-case.
	 */
	assert(entry->vme_start == addr &&
	    entry->vme_end == addr + oldsize &&
	    entry->vme_offset == 0);

	was_atomic = entry->vme_atomic;
	entry->vme_atomic = false;
	vm_map_clip_end(map, entry, entry->vme_start + newsize);
	entry->vme_atomic = was_atomic;

	(void)vm_map_remove_and_unlock(map, addr + newsize, addr + oldsize,
	    VM_MAP_REMOVE_KUNWIRE);

	vm_object_lock(object);
	/* see kmem_realloc(): guarantees concurrent reallocs will panic */
	if (object->vo_size != oldsize) {
		panic("kmem_realloc");
	}
	vm_object_page_remove(object, newsize, oldsize);
	object->vo_size = newsize;
	vm_object_unlock(object);
	vm_object_deallocate(object);
}

/*
 *	kmem_alloc:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 */

__exported kern_return_t
kmem_alloc_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size);
kern_return_t
kmem_alloc_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	return kmem_alloc(map, addrp, size, KMA_NONE, vm_tag_bt());
}


/*
 *	kmem_alloc_kobject:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 *
 *	The memory is allocated in the kernel_object.
 *	It may not be copied with vm_map_copy, and
 *	it may not be reallocated with kmem_realloc.
 */

__exported kern_return_t
kmem_alloc_kobject_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size);
kern_return_t
kmem_alloc_kobject_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	return kmem_alloc(map, addrp, size, KMA_KOBJECT, vm_tag_bt());
}

/*
 *	kmem_alloc_pageable:
 *
 *	Allocate pageable memory in the kernel's address map.
 */

__exported kern_return_t
kmem_alloc_pageable_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size);
kern_return_t
kmem_alloc_pageable_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	return kmem_alloc(map, addrp, size, KMA_PAGEABLE, vm_tag_bt());
}

/*
 *	kmem_free:
 *
 *	Release a region of kernel virtual memory allocated
 *	with kmem_alloc, kmem_alloc_kobject, or kmem_alloc_pageable,
 *	and return the physical pages associated with that region.
 */

void
kmem_free(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       size)
{
	assert(addr >= VM_MIN_KERNEL_AND_KEXT_ADDRESS);
	assert(map->pmap == kernel_pmap);

	if (size == 0) {
#if MACH_ASSERT
		printf("kmem_free called with size==0 for map: %p with addr: 0x%llx\n", map, (uint64_t)addr);
#endif
		return;
	}

	(void)vm_map_remove_flags(map,
	    vm_map_trunc_page(addr, VM_MAP_PAGE_MASK(map)),
	    vm_map_round_page(addr + size, VM_MAP_PAGE_MASK(map)),
	    VM_MAP_REMOVE_KUNWIRE);
}

/*
 *	Allocate new pages in an object.
 */

kern_return_t
kmem_alloc_pages(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size)
{
	vm_object_size_t                alloc_size;

	alloc_size = vm_object_round_page(size);
	vm_object_lock(object);
	while (alloc_size) {
		vm_page_t   mem;


		/*
		 *	Allocate a page
		 */
		while (VM_PAGE_NULL ==
		    (mem = vm_page_alloc(object, offset))) {
			vm_object_unlock(object);
			VM_PAGE_WAIT();
			vm_object_lock(object);
		}
		mem->vmp_busy = FALSE;

		alloc_size -= PAGE_SIZE;
		offset += PAGE_SIZE;
	}
	vm_object_unlock(object);
	return KERN_SUCCESS;
}

kmem_return_t
kmem_suballoc(
	vm_map_t                parent,
	vm_offset_t             *addr,
	vm_size_t               size,
	vm_map_create_options_t vmc_options,
	int                     vm_flags,
	kms_flags_t             flags,
	vm_tag_t                tag)
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vm_map_offset_t map_addr = 0;
	kmem_return_t kmr = { };
	vm_map_t map;

	assert(page_aligned(size));
	assert(parent->pmap == kernel_pmap);

	if ((vm_flags & VM_FLAGS_ANYWHERE) == 0) {
		map_addr = trunc_page(*addr);
	}

	pmap_reference(vm_map_pmap(parent));
	map = vm_map_create_options(vm_map_pmap(parent), 0, size, vmc_options);

	/*
	 * 1. vm_map_enter() will consume one ref on success.
	 *
	 * 2. make the entry atomic as kernel submaps should never be split.
	 *
	 * 3. instruct vm_map_enter() that it is a fresh submap
	 *    that needs to be taught its bounds as it inserted.
	 */
	vm_map_reference(map);
	vmk_flags.vmkf_atomic_entry = true;
	vmk_flags.vmkf_submap = true;
	vmk_flags.vmkf_submap_adjust = true;
	if (flags & KMS_LAST_FREE) {
		vmk_flags.vmkf_last_free = true;
	}
	if (flags & KMS_PERMANENT) {
		vmk_flags.vmkf_permanent = true;
	}
	if (flags & KMS_DATA) {
		vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA;
	}

	kmr.kmr_return = vm_map_enter(parent, &map_addr, size, 0,
	    vm_flags, vmk_flags, tag, (vm_object_t)map, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kmr.kmr_return != KERN_SUCCESS) {
		if (flags & KMS_NOFAIL) {
			panic("kmem_suballoc(map=%p, size=%zd) failed with %d",
			    parent, (size_t)size, kmr.kmr_return);
		}
		assert(os_ref_get_count_raw(&map->map_refcnt) == 2);
		vm_map_deallocate(map);
		vm_map_deallocate(map); /* also removes ref to pmap */
		return kmr;
	}

	/*
	 * For kmem_suballocs that register a claim and are assigned a range, ensure
	 * that the exact same range is returned.
	 */
	if (*addr != 0 && parent == kernel_map &&
	    startup_phase > STARTUP_SUB_KMEM) {
		assert(CAST_DOWN(vm_offset_t, map_addr) == *addr);
	} else {
		*addr = CAST_DOWN(vm_offset_t, map_addr);
	}

	kmr.kmr_submap = map;
	return kmr;
}

/*
 * The default percentage of memory that can be mlocked is scaled based on the total
 * amount of memory in the system. These percentages are caclulated
 * offline and stored in this table. We index this table by
 * log2(max_mem) - VM_USER_WIREABLE_MIN_CONFIG. We clamp this index in the range
 * [0, sizeof(wire_limit_percents) / sizeof(vm_map_size_t))
 *
 * Note that these values were picked for mac.
 * If we ever have very large memory config arm devices, we may want to revisit
 * since the kernel overhead is smaller there due to the larger page size.
 */

/* Start scaling iff we're managing > 2^32 = 4GB of RAM. */
#define VM_USER_WIREABLE_MIN_CONFIG 32
#if CONFIG_JETSAM
/* Systems with jetsam can wire a bit more b/c the system can relieve wired
 * pressure.
 */
static vm_map_size_t wire_limit_percents[] =
{ 80, 80, 80, 80, 82, 85, 88, 91, 94, 97};
#else
static vm_map_size_t wire_limit_percents[] =
{ 70, 73, 76, 79, 82, 85, 88, 91, 94, 97};
#endif /* CONFIG_JETSAM */

/*
 * Sets the default global user wire limit which limits the amount of
 * memory that can be locked via mlock() based on the above algorithm..
 * This can be overridden via a sysctl.
 */
static void
kmem_set_user_wire_limits(void)
{
	uint64_t available_mem_log;
	uint64_t max_wire_percent;
	size_t wire_limit_percents_length = sizeof(wire_limit_percents) /
	    sizeof(vm_map_size_t);
	vm_map_size_t limit;
	uint64_t config_memsize = max_mem;
#if defined(XNU_TARGET_OS_OSX)
	config_memsize = max_mem_actual;
#endif /* defined(XNU_TARGET_OS_OSX) */

	available_mem_log = bit_floor(config_memsize);

	if (available_mem_log < VM_USER_WIREABLE_MIN_CONFIG) {
		available_mem_log = 0;
	} else {
		available_mem_log -= VM_USER_WIREABLE_MIN_CONFIG;
	}
	if (available_mem_log >= wire_limit_percents_length) {
		available_mem_log = wire_limit_percents_length - 1;
	}
	max_wire_percent = wire_limit_percents[available_mem_log];

	limit = config_memsize * max_wire_percent / 100;
	/* Cap the number of non lockable bytes at VM_NOT_USER_WIREABLE_MAX */
	if (config_memsize - limit > VM_NOT_USER_WIREABLE_MAX) {
		limit = config_memsize - VM_NOT_USER_WIREABLE_MAX;
	}

	vm_global_user_wire_limit = limit;
	/* the default per task limit is the same as the global limit */
	vm_per_task_user_wire_limit = limit;
	vm_add_wire_count_over_global_limit = 0;
	vm_add_wire_count_over_user_limit = 0;
}

#define KMEM_MAX_CLAIMS 50
__startup_data
struct kmem_range_startup_spec kmem_claims[KMEM_MAX_CLAIMS] = {};
__startup_data
uint32_t kmem_claim_count = 0;

__startup_func
void
kmem_range_startup_init(
	struct kmem_range_startup_spec *sp)
{
	assert(kmem_claim_count < KMEM_MAX_CLAIMS - KMEM_RANGE_COUNT);
	if (sp->kc_calculate_sz) {
		sp->kc_size = (sp->kc_calculate_sz)();
	}
	if (sp->kc_size) {
		kmem_claims[kmem_claim_count] = *sp;
		kmem_claim_count++;
	}
}

static vm_offset_t
kmem_fuzz_start(void)
{
	vm_offset_t kmapoff_kaddr = 0;
	uint32_t kmapoff_pgcnt = (early_random() & 0x1ff) + 1; /* 9 bits */
	vm_map_size_t kmapoff_size = ptoa(kmapoff_pgcnt);

	kmem_alloc(kernel_map, &kmapoff_kaddr, kmapoff_size,
	    KMA_NOFAIL | KMA_KOBJECT | KMA_PERMANENT | KMA_VAONLY,
	    VM_KERN_MEMORY_OSFMK);
	return kmapoff_kaddr + kmapoff_size;
}

/*
 * Returns a 16bit random number between 0 and
 * upper_limit (inclusive)
 */
__startup_func
uint16_t
kmem_get_random16(uint16_t upper_limit)
{
	static uint64_t random_entropy;
	assert(upper_limit < UINT16_MAX);
	if (random_entropy == 0) {
		random_entropy = early_random();
	}
	uint32_t result = random_entropy & UINT32_MAX;
	random_entropy >>= 32;
	return (uint16_t)(result % (upper_limit + 1));
}

/*
 * Generate a randomly shuffled array of indices from 0 to count - 1
 */
__startup_func
void
kmem_shuffle(uint16_t *shuffle_buf, uint16_t count)
{
	for (uint16_t i = 0; i < count; i++) {
		uint16_t j = kmem_get_random16(i);
		if (j != i) {
			shuffle_buf[i] = shuffle_buf[j];
		}
		shuffle_buf[j] = i;
	}
}

#if ZSECURITY_CONFIG(KERNEL_DATA_SPLIT)
__startup_func
static void
kmem_shuffle_claims(void)
{
	uint16_t shuffle_buf[KMEM_MAX_CLAIMS] = {};
	kmem_shuffle(&shuffle_buf[0], (uint16_t)kmem_claim_count);
	for (uint16_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec tmp = kmem_claims[i];
		kmem_claims[i] = kmem_claims[shuffle_buf[i]];
		kmem_claims[shuffle_buf[i]] = tmp;
	}
}

__startup_func
static void
kmem_readjust_ranges(uint32_t cur_idx)
{
	assert(cur_idx != 0);
	uint32_t j = cur_idx - 1, random;
	struct kmem_range_startup_spec sp = kmem_claims[cur_idx];
	struct kmem_range *sp_range = sp.kc_range;

	/*
	 * Find max index where restriction is met
	 */
	for (; j > 0; j--) {
		struct kmem_range_startup_spec spj = kmem_claims[j];
		vm_map_offset_t max_start = spj.kc_range->min_address;
		if (spj.kc_flags & KC_NO_MOVE) {
			panic("kmem_range_init: Can't scramble with multiple constraints");
		}
		if (max_start <= sp_range->min_address) {
			break;
		}
	}

	/*
	 * Pick a random index from 0 to max index and shift claims to the right
	 * to make room for restricted claim
	 */
	random = kmem_get_random16((uint16_t)j);
	assert(random <= j);

	sp_range->min_address = kmem_claims[random].kc_range->min_address;
	sp_range->max_address = sp_range->min_address + sp.kc_size;

	for (j = cur_idx - 1; j >= random && j != UINT32_MAX; j--) {
		struct kmem_range_startup_spec spj = kmem_claims[j];
		struct kmem_range *range = spj.kc_range;
		range->min_address += sp.kc_size;
		range->max_address += sp.kc_size;
		kmem_claims[j + 1] = spj;
	}

	sp.kc_flags = KC_NO_MOVE;
	kmem_claims[random] = sp;
}

#define KMEM_ROUND_GRANULE (32ul << 20)
#define KMEM_ROUND(x) \
	((x + KMEM_ROUND_GRANULE - 1) & -KMEM_ROUND_GRANULE)

__startup_func
static void
kmem_scramble_ranges(void)
{
	vm_map_size_t largest_free_size = 0, total_size, total_free;
	vm_map_size_t total_claims = 0, data_range_size = 0;
	vm_map_offset_t start = 0;
	struct kmem_range kmem_range_ptr = {};

	/*
	 * Initiatize KMEM_RANGE_ID_UNSORTED range to use the entire map so that
	 * the vm can find the requested ranges.
	 */
	kmem_ranges[KMEM_RANGE_ID_PTR].min_address = MAX(kernel_map->min_offset,
	    VM_MAP_PAGE_SIZE(kernel_map));
	kmem_ranges[KMEM_RANGE_ID_PTR].max_address = kernel_map->max_offset;

	/*
	 * Allocating the g_kext_map prior to randomizing the remaining submaps as
	 * this map is 2G in size and starts at the end of kernel_text on x86. It
	 * could overflow into the heap.
	 */
	kext_alloc_init();

	/*
	 * Eat a random amount of kernel_map to fuzz subsequent heap, zone and
	 * stack addresses. (With a 4K page and 9 bits of randomness, this
	 * eats about 2M of VA from the map)
	 *
	 * Note that we always need to slide by at least one page because the VM
	 * pointer packing schemes using KERNEL_PMAP_HEAP_RANGE_START as a base
	 * do not admit this address to be part of any zone submap.
	 */
	start = kmem_fuzz_start();

	vm_map_sizes(kernel_map, &total_size, &total_free, &largest_free_size);
	largest_free_size = trunc_page(largest_free_size);

	/*
	 * Determine size of data and pointer kmem_ranges
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		total_claims += kmem_claims[i].kc_size;
	}
	largest_free_size -= total_claims;
	data_range_size = round_page((2 * largest_free_size) / 3);
	largest_free_size -= data_range_size;

	/*
	 * Add claims for data and pointer
	 */
	struct kmem_range_startup_spec kmem_spec_data = {
		.kc_name = "kmem_data_range",
		.kc_range = &kmem_ranges[KMEM_RANGE_ID_DATA],
		.kc_size = data_range_size,
		.kc_flags = KC_NO_ENTRY,
	};
	/*
	 * Don't use &kmem_ranges[KMEM_RANGE_ID_PTR] as changing that range affects
	 * vm_map_locate_space for the initialization below.
	 */
	kmem_claims[kmem_claim_count++] = kmem_spec_data;
	struct kmem_range_startup_spec kmem_spec_ptr = {
		.kc_name = "kmem_ptr_range",
		.kc_range = &kmem_range_ptr,
		.kc_size = largest_free_size,
		.kc_flags = KC_NO_ENTRY,
	};
	kmem_claims[kmem_claim_count++] = kmem_spec_ptr;

	/*
	 * Shuffle registered claims
	 */
	assert(kmem_claim_count < UINT16_MAX);
	kmem_shuffle_claims();

	/*
	 * Apply restrictions and determine range for each claim
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		vm_map_offset_t end = 0;
		struct kmem_range_startup_spec sp = kmem_claims[i];
		struct kmem_range *sp_range = sp.kc_range;
		if (vm_map_locate_space(kernel_map, sp.kc_size, 0,
		    VM_MAP_KERNEL_FLAGS_NONE, &start, NULL) != KERN_SUCCESS) {
			panic("kmem_range_init: vm_map_locate_space failing for claim %s",
			    sp.kc_name);
		}

		end = start + sp.kc_size;
		/*
		 * Re-adjust ranges if restriction not met
		 */
		if (sp_range->min_address && start > sp_range->min_address) {
			kmem_readjust_ranges(i);
		} else {
			sp_range->min_address = start;
			sp_range->max_address = end;
		}
		start = end;
	}

	/*
	 * We have settled on the ranges, now create temporary entries for the
	 * claims
	 */
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp = kmem_claims[i];
		vm_map_entry_t entry = NULL;
		if (sp.kc_flags & KC_NO_ENTRY) {
			continue;
		}
		if (vm_map_find_space(kernel_map, sp.kc_range->min_address, sp.kc_size, 0,
		    VM_MAP_KERNEL_FLAGS_NONE, &entry) != KERN_SUCCESS) {
			panic("kmem_range_init: vm_map_find_space failing for claim %s",
			    sp.kc_name);
		}
		vm_object_reference(kernel_object);
		VME_OBJECT_SET(entry, kernel_object);
		VME_OFFSET_SET(entry, entry->vme_start);
		vm_map_unlock(kernel_map);
	}
	/*
	 * Now that we are done assigning all the ranges, fixup
	 * kmem_ranges[KMEM_RANGE_ID_PTR]
	 */
	kmem_ranges[KMEM_RANGE_ID_PTR] = kmem_range_ptr;

#if DEBUG || DEVELOPMENT
	for (uint32_t i = 0; i < kmem_claim_count; i++) {
		struct kmem_range_startup_spec sp = kmem_claims[i];
		const char *size_str = "K";
		uint32_t shift = 10;
		if (sp.kc_size >> 30) {
			size_str = "G";
			shift = 30;
		} else if (sp.kc_size >> 20) {
			size_str = "M";
			shift = 20;
		}
		printf("%-24s: %p - %p (%llu%s)\n", sp.kc_name,
		    (void *)sp.kc_range->min_address, (void *)sp.kc_range->max_address,
		    sp.kc_size >> shift, size_str);
	}
#endif /* DEBUG || DEVELOPMENT */
}

__startup_func
static void
kmem_range_init(void)
{
	kmem_scramble_ranges();

	/* Initialize kmem_large_ranges. Skip 1/8th from the left as we currently
	 * have one front
	 */
	for (kmem_range_id_t i = 0; i < KMEM_RANGE_COUNT; i++) {
		vm_size_t range_adjustment = kmem_range_size(&kmem_ranges[i]) >> 3;
		kmem_large_ranges[i].min_address = kmem_ranges[i].min_address +
		    range_adjustment;
		kmem_large_ranges[i].max_address = kmem_ranges[i].max_address;
	}

#if DEBUG || DEVELOPMENT
	for (kmem_range_id_t i = 0; i < KMEM_RANGE_COUNT; i++) {
		printf("kmem_large_ranges[%d]    : %p - %p\n", i,
		    (void *)kmem_large_ranges[i].min_address,
		    (void *)kmem_large_ranges[i].max_address);
	}
#endif
}
#else /* ZSECURITY_CONFIG(KERNEL_DATA_SPLIT) */
__startup_func
static void
kmem_range_init(void)
{
	for (kmem_range_id_t i = 0; i < KMEM_RANGE_COUNT; i++) {
		kmem_ranges[i].min_address = kernel_map->min_offset;
		kmem_ranges[i].max_address = kernel_map->max_offset;
	}
	kext_alloc_init();
	kmem_fuzz_start();
}
#endif
STARTUP(KMEM, STARTUP_RANK_THIRD, kmem_range_init);

/*
 *	kmem_init:
 *
 *	Initialize the kernel's virtual memory map, taking
 *	into account all memory allocated up to this time.
 */
__startup_func
void
kmem_init(
	vm_offset_t     start,
	vm_offset_t     end)
{
	vm_map_offset_t map_start;
	vm_map_offset_t map_end;
	vm_map_kernel_flags_t vmk_flags;

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	vmk_flags.vmkf_no_pmap_check = TRUE;

	map_start = vm_map_trunc_page(start,
	    VM_MAP_PAGE_MASK(kernel_map));
	map_end = vm_map_round_page(end,
	    VM_MAP_PAGE_MASK(kernel_map));

	vm_map_will_allocate_early_map(&kernel_map);
#if     defined(__arm__) || defined(__arm64__)
	kernel_map = vm_map_create_options(pmap_kernel(),
	    VM_MIN_KERNEL_AND_KEXT_ADDRESS,
	    VM_MAX_KERNEL_ADDRESS,
	    VM_MAP_CREATE_DEFAULT);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	{
		unsigned int    region_select = 0;
		vm_map_offset_t region_start;
		vm_map_size_t   region_size;
		vm_map_offset_t map_addr;
		kern_return_t kr;

		while (pmap_virtual_region(region_select, &region_start, &region_size)) {
			map_addr = region_start;
			kr = vm_map_enter(kernel_map, &map_addr,
			    vm_map_round_page(region_size,
			    VM_MAP_PAGE_MASK(kernel_map)),
			    (vm_map_offset_t) 0,
			    VM_FLAGS_FIXED,
			    vmk_flags,
			    VM_KERN_MEMORY_NONE,
			    VM_OBJECT_NULL,
			    (vm_object_offset_t) 0, FALSE, VM_PROT_NONE, VM_PROT_NONE,
			    VM_INHERIT_DEFAULT);

			if (kr != KERN_SUCCESS) {
				panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x",
				    (uint64_t) start, (uint64_t) end, (uint64_t) region_start,
				    (uint64_t) region_size, kr);
			}

			region_select++;
		}
	}
#else
	kernel_map = vm_map_create_options(pmap_kernel(),
	    VM_MIN_KERNEL_AND_KEXT_ADDRESS, map_end,
	    VM_MAP_CREATE_DEFAULT);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	if (start != VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		vm_map_offset_t map_addr;
		kern_return_t kr;

		vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		vmk_flags.vmkf_no_pmap_check = TRUE;

		map_addr = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
		kr = vm_map_enter(kernel_map,
		    &map_addr,
		    (vm_map_size_t)(map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
		    (vm_map_offset_t) 0,
		    VM_FLAGS_FIXED,
		    vmk_flags,
		    VM_KERN_MEMORY_NONE,
		    VM_OBJECT_NULL,
		    (vm_object_offset_t) 0, FALSE,
		    VM_PROT_NONE, VM_PROT_NONE,
		    VM_INHERIT_DEFAULT);

		if (kr != KERN_SUCCESS) {
			panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x",
			    (uint64_t) start, (uint64_t) end,
			    (uint64_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			    (uint64_t) (map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
			    kr);
		}
	}
#endif

	kmem_set_user_wire_limits();
}


#pragma mark map copyio

/*
 *	Routine:	copyinmap
 *	Purpose:
 *		Like copyin, except that fromaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
kern_return_t
copyinmap(
	vm_map_t                map,
	vm_map_offset_t         fromaddr,
	void                    *todata,
	vm_size_t               length)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(todata, CAST_DOWN(void *, fromaddr), length);
	} else if (current_map() == map) {
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	copyoutmap
 *	Purpose:
 *		Like copyout, except that toaddr is an address
 *		in the specified VM map.
 */
kern_return_t
copyoutmap(
	vm_map_t                map,
	void                    *fromdata,
	vm_map_address_t        toaddr,
	vm_size_t               length)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t        oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(CAST_DOWN(void *, toaddr), fromdata, length);
	} else if (current_map() == map) {
		if (copyout(fromdata, toaddr, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout(fromdata, toaddr, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	copyoutmap_atomic{32, 64}
 *	Purpose:
 *		Like copyoutmap, except that the operation is atomic.
 *      Takes in value rather than *fromdata pointer.
 */
kern_return_t
copyoutmap_atomic32(
	vm_map_t                map,
	uint32_t                value,
	vm_map_address_t        toaddr)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t        oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct toaddr */
		*(uint32_t *)toaddr = value;
	} else if (current_map() == map) {
		if (copyout_atomic32(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout_atomic32(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

kern_return_t
copyoutmap_atomic64(
	vm_map_t                map,
	uint64_t                value,
	vm_map_address_t        toaddr)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t        oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct toaddr */
		*(uint64_t *)toaddr = value;
	} else if (current_map() == map) {
		if (copyout_atomic64(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout_atomic64(value, toaddr) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}


#pragma mark pointer obfuscation / packing

/*
 *
 *	The following two functions are to be used when exposing kernel
 *	addresses to userspace via any of the various debug or info
 *	facilities that exist. These are basically the same as VM_KERNEL_ADDRPERM()
 *	and VM_KERNEL_UNSLIDE_OR_PERM() except they use a different random seed and
 *	are exported to KEXTs.
 *
 *	NOTE: USE THE MACRO VERSIONS OF THESE FUNCTIONS (in vm_param.h) FROM WITHIN THE KERNEL
 */

vm_offset_t
vm_kernel_addrhash_internal(vm_offset_t addr, uint64_t salt)
{
	assert(salt != 0);

	if (addr == 0) {
		return 0ul;
	}

	if (VM_KERNEL_IS_SLID(addr)) {
		return VM_KERNEL_UNSLIDE(addr);
	}

	vm_offset_t sha_digest[SHA256_DIGEST_LENGTH / sizeof(vm_offset_t)];
	SHA256_CTX sha_ctx;

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, &salt, sizeof(salt));
	SHA256_Update(&sha_ctx, &addr, sizeof(addr));
	SHA256_Final(sha_digest, &sha_ctx);

	return sha_digest[0];
}

__exported vm_offset_t
vm_kernel_addrhash_external(vm_offset_t addr);
vm_offset_t
vm_kernel_addrhash_external(vm_offset_t addr)
{
	return vm_kernel_addrhash_internal(addr, vm_kernel_addrhash_salt_ext);
}

void
vm_kernel_addrhide(
	vm_offset_t addr,
	vm_offset_t *hide_addr)
{
	*hide_addr = VM_KERNEL_ADDRHIDE(addr);
}

/*
 *	vm_kernel_addrperm_external:
 *	vm_kernel_unslide_or_perm_external:
 *
 *	Use these macros when exposing an address to userspace that could come from
 *	either kernel text/data *or* the heap.
 */
void
vm_kernel_addrperm_external(
	vm_offset_t addr,
	vm_offset_t *perm_addr)
{
	if (VM_KERNEL_IS_SLID(addr)) {
		*perm_addr = VM_KERNEL_UNSLIDE(addr);
	} else if (VM_KERNEL_ADDRESS(addr)) {
		*perm_addr = addr + vm_kernel_addrperm_ext;
	} else {
		*perm_addr = addr;
	}
}

void
vm_kernel_unslide_or_perm_external(
	vm_offset_t addr,
	vm_offset_t *up_addr)
{
	vm_kernel_addrperm_external(addr, up_addr);
}

void
vm_packing_pointer_invalid(vm_offset_t ptr, vm_packing_params_t params)
{
	if (ptr & ((1ul << params.vmpp_shift) - 1)) {
		panic("pointer %p can't be packed: low %d bits aren't 0",
		    (void *)ptr, params.vmpp_shift);
	} else if (ptr <= params.vmpp_base) {
		panic("pointer %p can't be packed: below base %p",
		    (void *)ptr, (void *)params.vmpp_base);
	} else {
		panic("pointer %p can't be packed: maximum encodable pointer is %p",
		    (void *)ptr, (void *)vm_packing_max_packable(params));
	}
}

void
vm_packing_verify_range(
	const char *subsystem,
	vm_offset_t min_address,
	vm_offset_t max_address,
	vm_packing_params_t params)
{
	if (min_address > max_address) {
		panic("%s: %s range invalid min:%p > max:%p",
		    __func__, subsystem, (void *)min_address, (void *)max_address);
	}

	if (!params.vmpp_base_relative) {
		return;
	}

	if (min_address <= params.vmpp_base) {
		panic("%s: %s range invalid min:%p <= base:%p",
		    __func__, subsystem, (void *)min_address, (void *)params.vmpp_base);
	}

	if (max_address > vm_packing_max_packable(params)) {
		panic("%s: %s range invalid max:%p >= max packable:%p",
		    __func__, subsystem, (void *)max_address,
		    (void *)vm_packing_max_packable(params));
	}
}
