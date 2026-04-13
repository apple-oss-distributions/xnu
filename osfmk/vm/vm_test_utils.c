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

#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_map_store_internal.h>
#include <vm/vm_test_utils_internal.h>
#include <sys/code_signing.h>

vm_map_t
vm_test_alloc_map(void)
{
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	return vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);
}

vm_map_t
vm_test_alloc_4k_map(void)
{
	pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
	return vm_map_create_with_page_shift(pmap, 0, 0xfffffffffffff, FOURK_PAGE_SHIFT, 0);
}

vm_map_entry_t
vm_test_add_map_entry(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	vm_map_entry_t entry = vm_map_entry_create_locked(map, start, end);
	vm_map_entry_t after_where;
	bool found;

	vm_map_ilk_lock(map);
	found = vm_map_lookup_or_next(map, start, &after_where);
	if (!found) {
		after_where = VME_PREV(after_where);
	}

	assert(end > start);

	if (!entry_is_map_end(map, after_where)) {
		assert(start >= after_where->vme_end);
	}
	if (!entry_is_map_end(map, after_where->vme_next)) {
		assert(end <= after_where->vme_next->vme_start);
	}

	entry->use_pmap = true;
	entry->protection = VM_PROT_DEFAULT;
	entry->max_protection = VM_PROT_ALL;

	vm_map_store_insert(map, entry);

	vm_map_ilk_unlock(map);

	vm_entry_unlock_exclusive(map, entry);

	return entry;
}

void
setup_constant_submap(vm_map_address_t constant_submap_entry_start, vm_map_address_t start, vm_map_address_t end, int nentries, vm_map_t * parent_map, vm_map_t * submap)
{
	vm_map_address_t submap_entry_length = PAGE_SIZE;
	kern_return_t kr;
	*parent_map = vm_map_create_options(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);


	pmap_t pmap_nested = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT | PMAP_CREATE_NESTED);
#if defined(__arm64__)
	pmap_set_nested(pmap_nested);
#endif
#if CODE_SIGNING_MONITOR
	csm_setup_nested_address_space(pmap_nested, start, end - start);
#endif
	pmap_set_shared_region((*parent_map)->pmap, pmap_nested, start, end - start);
	*submap = vm_map_create_options(pmap_nested, 0, 0xfffffffffffff, 0);
	(*submap)->is_nested_map = true;
	(*submap)->vmmap_sealed = VM_MAP_WILL_BE_SEALED;

	for (int i = 0; i < nentries; i++) {
		vm_map_address_t entry_start = constant_submap_entry_start + submap_entry_length * i;
		vm_object_t obj;
		obj = vm_object_allocate(submap_entry_length, (*submap)->serial_id);
		kr = vm_map_enter(*submap, &entry_start,
		    submap_entry_length, 0, VM_MAP_KERNEL_FLAGS_FIXED(),
		    obj,        /* non NULL to avoid coalesce */
		    0, true, VM_PROT_DEFAULT,
		    VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		assert3u(kr, ==, KERN_SUCCESS);
		assert(obj->shadowed); /* for entry's needs_copy */
		vm_map_reference(*submap);
	}

	kr = vm_map_enter(*parent_map, &start, end - start, 0,
	    VM_MAP_KERNEL_FLAGS_FIXED(.vmkf_submap = TRUE, .vmkf_nested_pmap =  TRUE), (vm_object_t)(uintptr_t) *submap, constant_submap_entry_start,
	    true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);

	assert3u(kr, ==, KERN_SUCCESS);
	assert3s((*submap)->hdr.nentries, ==, nentries);
	assert3s((*parent_map)->hdr.nentries, ==, 1);
	vm_map_seal(*submap, true);
}
