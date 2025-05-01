/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <mach/memory_entry.h>
#include <mach/memory_entry_server.h>
#include <mach/vm_map_server.h>
#include <mach/mach_vm_server.h>
#include <vm/vm_purgeable_internal.h>
#include <mach/mach_host_server.h>
#include <IOKit/IOBSD.h>
#include <vm/vm_memory_entry_xnu.h>
#include <vm/vm_map_internal.h>
#include <vm/memory_object_internal.h>
#include <vm/vm_protos_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_iokit.h>

static void mach_memory_entry_no_senders(ipc_port_t, mach_port_mscount_t);

IPC_KOBJECT_DEFINE(IKOT_NAMED_ENTRY,
    .iko_op_stable     = true,
    .iko_op_no_senders = mach_memory_entry_no_senders);

/*
 * mach_make_memory_entry_64
 *
 * Think of it as a two-stage vm_remap() operation.  First
 * you get a handle.  Second, you get map that handle in
 * somewhere else. Rather than doing it all at once (and
 * without needing access to the other whole map).
 */
kern_return_t
mach_make_memory_entry_64(
	vm_map_t                target_map,
	memory_object_size_ut  *size_u,
	memory_object_offset_ut offset_u,
	vm_prot_ut              permission_u,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_handle)
{
	return mach_make_memory_entry_internal(target_map,
	           size_u,
	           offset_u,
	           permission_u,
	           VM_NAMED_ENTRY_KERNEL_FLAGS_NONE,
	           object_handle,
	           parent_handle);
}

static inline void
vm_memory_entry_decode_perm(
	vm_prot_t                       permission,
	unsigned int                   *access,
	vm_prot_t                      *protections,
	bool                           *mask_protections,
	bool                           *use_data_addr,
	bool                           *use_4K_compat)
{
	*protections = permission & VM_PROT_ALL;
	*mask_protections = permission & VM_PROT_IS_MASK;
	*access = GET_MAP_MEM(permission);
	*use_data_addr = ((permission & MAP_MEM_USE_DATA_ADDR) != 0);
	*use_4K_compat = ((permission & MAP_MEM_4K_DATA_ADDR) != 0);
}

static inline vm_map_offset_t
vm_memory_entry_get_offset_in_page(
	vm_map_offset_t                 offset,
	vm_map_offset_t                 map_start,
	bool                            use_data_addr,
	bool                            use_4K_compat)
{
	vm_map_offset_t         offset_in_page;

	if (use_data_addr || use_4K_compat) {
		offset_in_page = offset - map_start;
		if (use_4K_compat) {
			offset_in_page &= ~((signed)(0xFFF));
		}
	} else {
		offset_in_page = 0;
	}

	return offset_in_page;
}

static inline kern_return_t
mach_make_memory_entry_cleanup(
	kern_return_t           kr,
	vm_map_t                target_map __unused,
	memory_object_size_ut  *size_u,
	vm_map_offset_ut        offset_u __unused,
	vm_prot_t               permission __unused,
	vm_named_entry_t        user_entry __unused,
	ipc_port_t             *object_handle)
{
	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> entry "
	    "%p kr 0x%x\n", target_map, VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
	    VM_SANITIZE_UNSAFE_UNWRAP(*size_u), permission, user_entry,
	    vm_sanitize_get_kr(kr));
	/*
	 * Set safe size and object_handle value on failed return
	 */
	*size_u = vm_sanitize_wrap_size(0);
	*object_handle = IPC_PORT_NULL;
	return vm_sanitize_get_kr(kr);
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_make_memory_entry_mem_only_sanitize(
	vm_map_t                target_map,
	memory_object_size_ut   size_u,
	vm_map_offset_ut        offset_u,
	vm_map_offset_t        *map_start,
	vm_map_offset_t        *map_end,
	vm_map_size_t          *map_size)
{
	/*
	 * This code path doesn't use offset and size. They don't need to be
	 * validated. However inorder to maintain backward compatibility some
	 * checks on offset and size have been left.
	 */
	return vm_sanitize_addr_size(offset_u, size_u,
	           VM_SANITIZE_CALLER_MACH_MAKE_MEMORY_ENTRY,
	           target_map, VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH,
	           map_start, map_end, map_size);
}

static kern_return_t
mach_make_memory_entry_mem_only(
	vm_map_t                        target_map,
	memory_object_size_ut          *size_u,
	memory_object_offset_ut         offset_u,
	vm_prot_t                       permission,
	ipc_port_t                     *object_handle,
	vm_named_entry_t                parent_entry)
{
	boolean_t               parent_is_object;
	vm_object_t             object;
	unsigned int            access;
	vm_prot_t               protections;
	bool                    mask_protections;
	unsigned int            wimg_mode;
	bool                    use_data_addr;
	bool                    use_4K_compat;
	vm_named_entry_t        user_entry __unused = NULL;
	kern_return_t           kr;
	vm_map_size_t           map_size;
	vm_map_offset_t         map_start, map_end;

	/*
	 * Sanitize addr and size. Permimssions have been sanitized prior to
	 * dispatch
	 */
	kr = mach_make_memory_entry_mem_only_sanitize(target_map,
	    *size_u,
	    offset_u,
	    &map_start,
	    &map_end,
	    &map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	vm_memory_entry_decode_perm(permission, &access, &protections,
	    &mask_protections, &use_data_addr, &use_4K_compat);

	if (use_data_addr || use_4K_compat || parent_entry == NULL) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	parent_is_object = parent_entry->is_object;
	if (!parent_is_object) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	if ((access != parent_entry->access) &&
	    !(parent_entry->protection & VM_PROT_WRITE)) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_RIGHT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	object = vm_named_entry_to_vm_object(parent_entry);
	if (parent_is_object && object != VM_OBJECT_NULL) {
		wimg_mode = object->wimg_bits;
	} else {
		wimg_mode = VM_WIMG_USE_DEFAULT;
	}
	vm_prot_to_wimg(access, &wimg_mode);
	if (parent_is_object && object &&
	    (access != MAP_MEM_NOOP) &&
	    (!(object->nophyscache))) {
		if (object->wimg_bits != wimg_mode) {
			vm_object_lock(object);
			vm_object_change_wimg_mode(object, wimg_mode);
			vm_object_unlock(object);
		}
	}
	if (access != MAP_MEM_NOOP) {
		parent_entry->access = access;
	}
	if (object_handle) {
		*object_handle = IP_NULL;
	}
	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> entry "
	    "%p kr 0x%x\n", target_map, VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
	    VM_SANITIZE_UNSAFE_UNWRAP(*size_u), permission, user_entry, KERN_SUCCESS);
	/*
	 * TODO: Size isn't being set in this path
	 */
	return KERN_SUCCESS;
}

#if CONFIG_PROB_GZALLOC
static inline vm_map_offset_ut
vm_memory_entry_pgz_decode_offset(
	vm_map_t                        target_map,
	vm_map_offset_ut                offset_u,
	memory_object_size_ut          *size_u __unused)
{
	if (target_map == NULL || target_map->pmap == kernel_pmap) {
		vm_map_offset_t pgz_offset;

		/*
		 * It's ok to unsafe unwrap because PGZ does not ship to
		 * customers.
		 */
		pgz_offset = pgz_decode(VM_SANITIZE_UNSAFE_UNWRAP(offset_u),
		    VM_SANITIZE_UNSAFE_UNWRAP(*size_u));
		return vm_sanitize_wrap_addr(pgz_offset);
	}
	return offset_u;
}
#endif /* CONFIG_PROB_GZALLOC */

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_make_memory_entry_generic_sanitize(
	vm_map_t                target_map,
	memory_object_size_ut   size_u,
	vm_map_offset_ut        offset_u,
	vm_map_offset_t        *map_start,
	vm_map_offset_t        *map_end,
	vm_map_size_t          *map_size,
	vm_map_offset_t        *offset)
{
	kern_return_t           kr;

	/*
	 * Validate start and end
	 */
	kr = vm_sanitize_addr_size(offset_u, size_u,
	    VM_SANITIZE_CALLER_MACH_MAKE_MEMORY_ENTRY,
	    target_map, VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH,
	    map_start, map_end, map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
	/*
	 * Validate offset
	 */
	kr = vm_sanitize_offset(offset_u, VM_SANITIZE_CALLER_MACH_MAKE_MEMORY_ENTRY,
	    *map_start, *map_end, offset);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	return KERN_SUCCESS;
}

static kern_return_t
mach_make_memory_entry_named_create(
	vm_map_t                        target_map,
	memory_object_size_ut          *size_u,
	vm_map_offset_ut                offset_u,
	vm_prot_t                       permission,
	vm_named_entry_kernel_flags_t   vmne_kflags,
	ipc_port_t                     *object_handle)
{
	vm_object_t             object;
	unsigned int            access;
	vm_prot_t               protections;
	bool                    mask_protections;
	unsigned int            wimg_mode;
	bool                    use_data_addr;
	bool                    use_4K_compat;
	int                     ledger_flags = 0;
	task_t                  owner;
	bool                    fully_owned = false;
	vm_named_entry_t        user_entry = NULL;
	kern_return_t           kr;
	vm_map_size_t           map_size;
	vm_map_offset_t         map_start, map_end, offset;

	if (VM_SANITIZE_UNSAFE_IS_ZERO(*size_u)) {
		return mach_make_memory_entry_cleanup(KERN_SUCCESS, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

#if CONFIG_PROB_GZALLOC
	/*
	 * If offset is PGZ protected we need PGZ to fix it up to the right
	 * value prior to validation and use.
	 */
	offset_u = vm_memory_entry_pgz_decode_offset(target_map, offset_u, size_u);
#endif /* CONFIG_PROB_GZALLOC */

	/*
	 * Sanitize addr and size. Permimssions have been sanitized prior to
	 * dispatch
	 */
	kr = mach_make_memory_entry_generic_sanitize(target_map,
	    *size_u,
	    offset_u,
	    &map_start,
	    &map_end,
	    &map_size,
	    &offset);
	if (__improbable(kr != KERN_SUCCESS)) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	assert(map_size != 0);

	vm_memory_entry_decode_perm(permission, &access, &protections,
	    &mask_protections, &use_data_addr, &use_4K_compat);

	if (use_data_addr || use_4K_compat) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	/*
	 * Force the creation of the VM object now.
	 */
#if __LP64__
	if (map_size > ANON_MAX_SIZE) {
		return mach_make_memory_entry_cleanup(KERN_FAILURE, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}
#endif /* __LP64__ */

	object = vm_object_allocate(map_size);
	assert(object != VM_OBJECT_NULL);
	vm_object_lock(object);

	/*
	 * XXX
	 * We use this path when we want to make sure that
	 * nobody messes with the object (coalesce, for
	 * example) before we map it.
	 * We might want to use these objects for transposition via
	 * vm_object_transpose() too, so we don't want any copy or
	 * shadow objects either...
	 */
	object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
	VM_OBJECT_SET_TRUE_SHARE(object, TRUE);

	owner = current_task();
	if ((permission & MAP_MEM_PURGABLE) ||
	    vmne_kflags.vmnekf_ledger_tag) {
		assert(object->vo_owner == NULL);
		assert(object->resident_page_count == 0);
		assert(object->wired_page_count == 0);
		assert(owner != TASK_NULL);
		if (vmne_kflags.vmnekf_ledger_no_footprint) {
			ledger_flags |= VM_LEDGER_FLAG_NO_FOOTPRINT;
			object->vo_no_footprint = TRUE;
		}
		if (permission & MAP_MEM_PURGABLE) {
			if (!(permission & VM_PROT_WRITE)) {
				/* if we can't write, we can't purge */
				vm_object_unlock(object);
				vm_object_deallocate(object);
				return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT,
				           target_map, size_u, offset_u, permission, user_entry,
				           object_handle);
			}
			VM_OBJECT_SET_PURGABLE(object, VM_PURGABLE_NONVOLATILE);
			if (permission & MAP_MEM_PURGABLE_KERNEL_ONLY) {
				VM_OBJECT_SET_PURGEABLE_ONLY_BY_KERNEL(object, TRUE);
			}
#if __arm64__
			if (owner->task_legacy_footprint) {
				/*
				 * For ios11, we failed to account for
				 * this memory.  Keep doing that for
				 * legacy apps (built before ios12),
				 * for backwards compatibility's sake...
				 */
				owner = kernel_task;
			}
#endif /* __arm64__ */
			vm_purgeable_nonvolatile_enqueue(object, owner);
			/* all memory in this named entry is "owned" */
			fully_owned = true;
		}
	}

	if (vmne_kflags.vmnekf_ledger_tag) {
		/*
		 * Bill this object to the current task's
		 * ledgers for the given tag.
		 */
		if (vmne_kflags.vmnekf_ledger_no_footprint) {
			ledger_flags |= VM_LEDGER_FLAG_NO_FOOTPRINT;
		}
		kr = vm_object_ownership_change(
			object,
			vmne_kflags.vmnekf_ledger_tag,
			owner,         /* new owner */
			ledger_flags,
			FALSE);         /* task_objq locked? */
		if (kr != KERN_SUCCESS) {
			vm_object_unlock(object);
			vm_object_deallocate(object);
			return mach_make_memory_entry_cleanup(kr, target_map,
			           size_u, offset_u, permission, user_entry, object_handle);
		}
		/* all memory in this named entry is "owned" */
		fully_owned = true;
	}

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_iokit && /* global boot-arg */
	    ((permission & MAP_MEM_GRAB_SECLUDED))) {
		object->can_grab_secluded = TRUE;
		assert(!object->eligible_for_secluded);
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	/*
	 * The VM object is brand new and nobody else knows about it,
	 * so we don't need to lock it.
	 */

	wimg_mode = object->wimg_bits;
	vm_prot_to_wimg(access, &wimg_mode);
	if (access != MAP_MEM_NOOP) {
		object->wimg_bits = wimg_mode;
	}

	vm_object_unlock(object);

	/* the object has no pages, so no WIMG bits to update here */

	user_entry = mach_memory_entry_allocate(object_handle);
	vm_named_entry_associate_vm_object(
		user_entry,
		object,
		0,
		map_size,
		(protections & VM_PROT_ALL));
	user_entry->internal = TRUE;
	user_entry->is_sub_map = FALSE;
	user_entry->offset = 0;
	user_entry->data_offset = 0;
	user_entry->protection = protections;
	user_entry->access = access;
	user_entry->size = map_size;
	user_entry->is_fully_owned = fully_owned;

	/* user_object pager and internal fields are not used */
	/* when the object field is filled in.		      */

	*size_u = vm_sanitize_wrap_size(user_entry->size - user_entry->data_offset);
	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> entry "
	    "%p kr 0x%x\n", target_map, offset, VM_SANITIZE_UNSAFE_UNWRAP(*size_u),
	    permission, user_entry, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static kern_return_t
mach_make_memory_entry_copy(
	vm_map_t                      target_map,
	memory_object_size_ut         *size_u,
	vm_map_offset_ut              offset_u,
	vm_prot_t                     permission,
	__unused vm_named_entry_kernel_flags_t vmne_kflags,
	ipc_port_t                    *object_handle)
{
	unsigned int            access;
	vm_prot_t               protections;
	bool                    mask_protections;
	bool                    use_data_addr;
	bool                    use_4K_compat;
	vm_named_entry_t        user_entry = NULL;
	vm_map_copy_t           copy;
	/*
	 * Stash the offset in the page for use by vm_map_enter_mem_object()
	 * in the VM_FLAGS_RETURN_DATA_ADDR/MAP_MEM_USE_DATA_ADDR case.
	 */
	vm_object_offset_t      offset_in_page;
	kern_return_t           kr;
	vm_map_size_t           map_size;
	vm_map_offset_t         map_start, map_end, offset;

	if (VM_SANITIZE_UNSAFE_IS_ZERO(*size_u)) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

#if CONFIG_PROB_GZALLOC
	/*
	 * If offset is PGZ protected we need PGZ to fix it up to the right
	 * value prior to validation and use.
	 */
	offset_u = vm_memory_entry_pgz_decode_offset(target_map, offset_u, size_u);
#endif /* CONFIG_PROB_GZALLOC */

	/*
	 * Sanitize addr and size. Permimssions have been sanitized prior to
	 * dispatch
	 */
	kr = mach_make_memory_entry_generic_sanitize(target_map,
	    *size_u,
	    offset_u,
	    &map_start,
	    &map_end,
	    &map_size,
	    &offset);
	if (__improbable(kr != KERN_SUCCESS)) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	assert(map_size != 0);

	vm_memory_entry_decode_perm(permission, &access, &protections,
	    &mask_protections, &use_data_addr, &use_4K_compat);

	if (target_map == VM_MAP_NULL) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_TASK, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	offset_in_page = vm_memory_entry_get_offset_in_page(offset, map_start,
	    use_data_addr, use_4K_compat);

	int copyin_flags = VM_MAP_COPYIN_ENTRY_LIST;
	kr = vm_map_copyin_internal(target_map,
	    map_start,
	    map_size,
	    copyin_flags,
	    &copy);
	if (kr != KERN_SUCCESS) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}
	assert(copy != VM_MAP_COPY_NULL);

	user_entry = mach_memory_entry_allocate(object_handle);
	user_entry->backing.copy = copy;
	user_entry->internal = FALSE;
	user_entry->is_sub_map = FALSE;
	user_entry->is_copy = TRUE;
	user_entry->offset = 0;
	user_entry->protection = protections;
	user_entry->size = map_size;
	user_entry->data_offset = offset_in_page;

	/* is all memory in this named entry "owned"? */
	vm_map_entry_t entry;
	user_entry->is_fully_owned = TRUE;
	for (entry = vm_map_copy_first_entry(copy);
	    entry != vm_map_copy_to_entry(copy);
	    entry = entry->vme_next) {
		if (entry->is_sub_map ||
		    VME_OBJECT(entry) == VM_OBJECT_NULL ||
		    VM_OBJECT_OWNER(VME_OBJECT(entry)) == TASK_NULL) {
			/* this memory is not "owned" */
			user_entry->is_fully_owned = FALSE;
			break;
		}
	}

	*size_u = vm_sanitize_wrap_size(user_entry->size - user_entry->data_offset);
	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> "
	    "entry %p kr 0x%x\n", target_map, offset, VM_SANITIZE_UNSAFE_UNWRAP(*size_u),
	    permission, user_entry, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static kern_return_t
mach_make_memory_entry_share(
	vm_map_t                      target_map,
	memory_object_size_ut        *size_u,
	vm_map_offset_ut              offset_u,
	vm_prot_t                     permission,
	__unused vm_named_entry_kernel_flags_t vmne_kflags,
	ipc_port_t                    *object_handle,
	ipc_port_t                    parent_handle,
	vm_named_entry_t              parent_entry)
{
	vm_object_t             object;
	unsigned int            access;
	vm_prot_t               protections;
	bool                    mask_protections;
	bool                    use_data_addr;
	bool                    use_4K_compat;
	vm_named_entry_t        user_entry = NULL;
	vm_map_copy_t           copy;
	vm_prot_t               cur_prot, max_prot;
	vm_map_kernel_flags_t   vmk_flags;
	vm_map_entry_t          parent_copy_entry;
	/*
	 * Stash the offset in the page for use by vm_map_enter_mem_object()
	 * in the VM_FLAGS_RETURN_DATA_ADDR/MAP_MEM_USE_DATA_ADDR case.
	 */
	vm_object_offset_t      offset_in_page;
	unsigned int            wimg_mode;
	kern_return_t           kr;
	vm_map_size_t           map_size;
	vm_map_offset_t         map_start, map_end, offset;

	if (VM_SANITIZE_UNSAFE_IS_ZERO(*size_u)) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

#if CONFIG_PROB_GZALLOC
	/*
	 * If offset is PGZ protected we need PGZ to fix it up to the right
	 * value prior to validation and use.
	 */
	offset_u = vm_memory_entry_pgz_decode_offset(target_map, offset_u, size_u);
#endif /* CONFIG_PROB_GZALLOC */

	/*
	 * Sanitize addr and size. Permimssions have been sanitized prior to
	 * dispatch
	 */
	kr = mach_make_memory_entry_generic_sanitize(target_map,
	    *size_u,
	    offset_u,
	    &map_start,
	    &map_end,
	    &map_size,
	    &offset);
	if (__improbable(kr != KERN_SUCCESS)) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	assert(map_size != 0);

	vm_memory_entry_decode_perm(permission, &access, &protections,
	    &mask_protections, &use_data_addr, &use_4K_compat);

	if (target_map == VM_MAP_NULL) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_TASK, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_range_id = KMEM_RANGE_ID_DATA;
	parent_copy_entry = VM_MAP_ENTRY_NULL;
	if (!(permission & MAP_MEM_VM_SHARE)) {
		vm_map_t tmp_map, real_map;
		vm_map_version_t version;
		vm_object_t tmp_object;
		vm_object_offset_t obj_off;
		vm_prot_t prot;
		boolean_t wired;
		bool contended;

		/* resolve any pending submap copy-on-write... */
		if (protections & VM_PROT_WRITE) {
			tmp_map = target_map;
			vm_map_lock_read(tmp_map);
			kr = vm_map_lookup_and_lock_object(&tmp_map,
			    map_start,
			    protections | (mask_protections ? VM_PROT_IS_MASK : 0),
			    OBJECT_LOCK_EXCLUSIVE,
			    &version,
			    &tmp_object,
			    &obj_off,
			    &prot,
			    &wired,
			    NULL,                               /* fault_info */
			    &real_map,
			    &contended);
			if (kr != KERN_SUCCESS) {
				vm_map_unlock_read(tmp_map);
			} else {
				vm_object_unlock(tmp_object);
				vm_map_unlock_read(tmp_map);
				if (real_map != tmp_map) {
					vm_map_unlock_read(real_map);
				}
			}
		}
		/* ... and carry on */

		/* stop extracting if VM object changes */
		vmk_flags.vmkf_copy_single_object = TRUE;
		if ((permission & MAP_MEM_NAMED_REUSE) &&
		    parent_entry != NULL &&
		    parent_entry->is_object) {
			vm_map_copy_t parent_copy;
			parent_copy = parent_entry->backing.copy;
			/*
			 * Assert that the vm_map_copy is coming from the right
			 * zone and hasn't been forged
			 */
			vm_map_copy_require(parent_copy);
			assert(parent_copy->cpy_hdr.nentries == 1);
			parent_copy_entry = vm_map_copy_first_entry(parent_copy);
			assert(!parent_copy_entry->is_sub_map);
		}
	}

	offset_in_page = vm_memory_entry_get_offset_in_page(offset, map_start,
	    use_data_addr, use_4K_compat);

	if (mask_protections) {
		/*
		 * caller is asking for whichever proctections are
		 * available: no required protections.
		 */
		cur_prot = VM_PROT_NONE;
		max_prot = VM_PROT_NONE;
		vmk_flags.vmkf_remap_legacy_mode = true;
	} else {
		/*
		 * Caller wants a memory entry with "protections".
		 * Make sure we extract only memory that matches that.
		 */
		cur_prot = protections;
		max_prot = protections;
	}
	if (target_map->pmap == kernel_pmap) {
		/*
		 * Get "reserved" map entries to avoid deadlocking
		 * on the kernel map or a kernel submap if we
		 * run out of VM map entries and need to refill that
		 * zone.
		 */
		vmk_flags.vmkf_copy_pageable = FALSE;
	} else {
		vmk_flags.vmkf_copy_pageable = TRUE;
	}
	vmk_flags.vmkf_copy_same_map = FALSE;
	assert(map_size != 0);
	kr = vm_map_copy_extract(target_map,
	    map_start,
	    map_size,
	    FALSE,                              /* copy */
	    &copy,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_SHARE,
	    vmk_flags);
	if (kr != KERN_SUCCESS) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}
	assert(copy != VM_MAP_COPY_NULL);

	if (mask_protections) {
		/*
		 * We just want as much of "original_protections"
		 * as we can get out of the actual "cur_prot".
		 */
		protections &= cur_prot;
		if (protections == VM_PROT_NONE) {
			/* no access at all: fail */
			vm_map_copy_discard(copy);
			return mach_make_memory_entry_cleanup(KERN_PROTECTION_FAILURE,
			           target_map, size_u, offset_u, permission, user_entry,
			           object_handle);
		}
	} else {
		/*
		 * We want exactly "original_protections"
		 * out of "cur_prot".
		 */
		assert((cur_prot & protections) == protections);
		assert((max_prot & protections) == protections);
		/* XXX FBDP TODO: no longer needed? */
		if ((cur_prot & protections) != protections) {
			vm_map_copy_discard(copy);
			return mach_make_memory_entry_cleanup(KERN_PROTECTION_FAILURE,
			           target_map, size_u, offset_u, permission, user_entry,
			           object_handle);
		}
	}

	if (!(permission & MAP_MEM_VM_SHARE)) {
		vm_map_entry_t copy_entry;

		/* limit size to what's actually covered by "copy" */
		assert(copy->cpy_hdr.nentries == 1);
		copy_entry = vm_map_copy_first_entry(copy);
		map_size = copy_entry->vme_end - copy_entry->vme_start;

		if ((permission & MAP_MEM_NAMED_REUSE) &&
		    parent_copy_entry != VM_MAP_ENTRY_NULL &&
		    VME_OBJECT(copy_entry) == VME_OBJECT(parent_copy_entry) &&
		    VME_OFFSET(copy_entry) == VME_OFFSET(parent_copy_entry) &&
		    parent_entry->offset == 0 &&
		    parent_entry->size == map_size &&
		    (parent_entry->data_offset == offset_in_page)) {
			/* we have a match: re-use "parent_entry" */

			/* release our new "copy" */
			vm_map_copy_discard(copy);
			/* get extra send right on handle */
			parent_handle = ipc_port_copy_send_any(parent_handle);

			*size_u = vm_sanitize_wrap_size(parent_entry->size -
			    parent_entry->data_offset);
			*object_handle = parent_handle;
			DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> "
			    "entry %p kr 0x%x\n", target_map, offset, VM_SANITIZE_UNSAFE_UNWRAP(*size_u),
			    permission, user_entry, KERN_SUCCESS);
			return KERN_SUCCESS;
		}

		/* no match: we need to create a new entry */
		object = VME_OBJECT(copy_entry);
		vm_object_lock(object);
		wimg_mode = object->wimg_bits;
		if (!(object->nophyscache)) {
			vm_prot_to_wimg(access, &wimg_mode);
		}
		if (object->wimg_bits != wimg_mode) {
			vm_object_change_wimg_mode(object, wimg_mode);
		}
		vm_object_unlock(object);
	}

	user_entry = mach_memory_entry_allocate(object_handle);
	user_entry->backing.copy = copy;
	user_entry->is_sub_map = FALSE;
	user_entry->is_object = FALSE;
	user_entry->internal = FALSE;
	user_entry->protection = protections;
	user_entry->size = map_size;
	user_entry->data_offset = offset_in_page;

	if (permission & MAP_MEM_VM_SHARE) {
		vm_map_entry_t copy_entry;

		user_entry->is_copy = TRUE;
		user_entry->offset = 0;

		/* is all memory in this named entry "owned"? */
		user_entry->is_fully_owned = TRUE;
		for (copy_entry = vm_map_copy_first_entry(copy);
		    copy_entry != vm_map_copy_to_entry(copy);
		    copy_entry = copy_entry->vme_next) {
			if (copy_entry->is_sub_map) {
				/* submaps can't be owned */
				user_entry->is_fully_owned = FALSE;
				break;
			}
			if (VM_OBJECT_OWNER(VME_OBJECT(copy_entry)) == TASK_NULL) {
				object = VME_OBJECT(copy_entry);
				if (object && !object->internal) {
					/* external objects can be "owned" */
					continue;
				}
				/* this memory is not "owned" */
				user_entry->is_fully_owned = FALSE;
				break;
			}
		}
	} else {
		user_entry->is_object = TRUE;
		user_entry->internal = object->internal;
		user_entry->offset = VME_OFFSET(vm_map_copy_first_entry(copy));
		user_entry->access = GET_MAP_MEM(permission);
		/* is all memory in this named entry "owned"? */
		user_entry->is_fully_owned = FALSE;
		object = vm_named_entry_to_vm_object(user_entry);
		if (VM_OBJECT_OWNER(object) != TASK_NULL) {
			/* object is owned */
			user_entry->is_fully_owned = TRUE;
		} else if (object && !object->internal) {
			/* external objects can become "owned" */
			user_entry->is_fully_owned = TRUE;
		}
	}

	*size_u = vm_sanitize_wrap_size(user_entry->size -
	    user_entry->data_offset);
	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> entry "
	    "%p kr 0x%x\n", target_map, offset, VM_SANITIZE_UNSAFE_UNWRAP(*size_u),
	    permission, user_entry, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_make_memory_entry_from_parent_entry_sanitize(
	vm_map_t                target_map,
	memory_object_size_ut   size_u,
	vm_map_offset_ut        offset_u,
	vm_prot_t               permission,
	vm_named_entry_t        parent_entry,
	vm_map_offset_t        *map_start,
	vm_map_offset_t        *map_end,
	vm_map_size_t          *map_size,
	vm_map_offset_t        *offset,
	vm_map_offset_t        *user_entry_offset)
{
	bool                    mask_protections;
	unsigned int            access;
	vm_prot_t               protections;
	bool                    use_data_addr;
	bool                    use_4K_compat;
	vm_map_offset_t         start_mask = vm_map_page_mask(target_map);
	kern_return_t           kr;

	vm_memory_entry_decode_perm(permission, &access, &protections,
	    &mask_protections, &use_data_addr, &use_4K_compat);

	if (use_data_addr || use_4K_compat) {
		/*
		 * Validate offset doesn't overflow when added to parent entry's offset
		 */
		if (vm_sanitize_add_overflow(offset_u, parent_entry->data_offset,
		    &offset_u)) {
			return KERN_INVALID_ARGUMENT;
		}
		start_mask = PAGE_MASK;
	}

	/*
	 * Currently the map_start is truncated using page mask from target_map
	 * when use_data_addr || use_4K_compat is false, while map_end uses
	 * PAGE_MASK. In order to maintain that behavior, we
	 * request for unaligned values and perform the truncing/rounding
	 * explicitly.
	 */
	kr = vm_sanitize_addr_size(offset_u, size_u,
	    VM_SANITIZE_CALLER_MACH_MAKE_MEMORY_ENTRY, PAGE_MASK,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH | VM_SANITIZE_FLAGS_GET_UNALIGNED_VALUES,
	    map_start, map_end, map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	*map_start =  vm_map_trunc_page_mask(*map_start, start_mask);
	*map_end = vm_map_round_page_mask(*map_end, PAGE_MASK);
	*map_size = *map_end - *map_start;

	/*
	 * Additional checks to make sure explicitly computed aligned start and end
	 * still make sense.
	 */
	if (__improbable(*map_end < *map_start) || (*map_end > parent_entry->size)) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Validate offset
	 */
	kr = vm_sanitize_offset(offset_u, VM_SANITIZE_CALLER_MACH_MAKE_MEMORY_ENTRY,
	    *map_start, *map_end, offset);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	if (__improbable(os_add_overflow(parent_entry->offset, *map_start,
	    user_entry_offset))) {
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

static kern_return_t
mach_make_memory_entry_from_parent_entry(
	vm_map_t                target_map,
	memory_object_size_ut  *size_u,
	vm_map_offset_ut        offset_u,
	vm_prot_t               permission,
	ipc_port_t             *object_handle,
	vm_named_entry_t        parent_entry)
{
	vm_object_t             object;
	unsigned int            access;
	vm_prot_t               protections;
	bool                    mask_protections;
	bool                    use_data_addr;
	bool                    use_4K_compat;
	vm_named_entry_t        user_entry = NULL;
	kern_return_t           kr;
	/*
	 * Stash the offset in the page for use by vm_map_enter_mem_object()
	 * in the VM_FLAGS_RETURN_DATA_ADDR/MAP_MEM_USE_DATA_ADDR case.
	 */
	vm_object_offset_t      offset_in_page;
	vm_map_offset_t         map_start, map_end;
	vm_map_size_t           map_size;
	vm_map_offset_t         user_entry_offset, offset;

	vm_memory_entry_decode_perm(permission, &access, &protections,
	    &mask_protections, &use_data_addr, &use_4K_compat);

	/*
	 * Sanitize addr and size. Permimssions have been sanitized prior to
	 * dispatch
	 */
	kr = mach_make_memory_entry_from_parent_entry_sanitize(target_map,
	    *size_u,
	    offset_u,
	    permission,
	    parent_entry,
	    &map_start,
	    &map_end,
	    &map_size,
	    &offset,
	    &user_entry_offset);
	if (__improbable(kr != KERN_SUCCESS)) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	if (use_data_addr || use_4K_compat) {
		/*
		 * submaps and pagers should only be accessible from within
		 * the kernel, which shouldn't use the data address flag, so can fail here.
		 */
		if (parent_entry->is_sub_map) {
			panic("Shouldn't be using data address with a parent entry that is a submap.");
		}
	}

	if (mask_protections) {
		/*
		 * The caller asked us to use the "protections" as
		 * a mask, so restrict "protections" to what this
		 * mapping actually allows.
		 */
		protections &= parent_entry->protection;
	}
	if ((protections & parent_entry->protection) != protections) {
		return mach_make_memory_entry_cleanup(KERN_PROTECTION_FAILURE, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	offset_in_page = vm_memory_entry_get_offset_in_page(offset, map_start,
	    use_data_addr, use_4K_compat);

	user_entry = mach_memory_entry_allocate(object_handle);
	user_entry->size = map_size;
	user_entry->offset = user_entry_offset;
	user_entry->data_offset = offset_in_page;
	user_entry->is_sub_map = parent_entry->is_sub_map;
	user_entry->is_copy = parent_entry->is_copy;
	user_entry->protection = protections;

	if (access != MAP_MEM_NOOP) {
		user_entry->access = access;
	}

	if (parent_entry->is_sub_map) {
		vm_map_t map = parent_entry->backing.map;
		vm_map_reference(map);
		user_entry->backing.map = map;
	} else {
		object = vm_named_entry_to_vm_object(parent_entry);
		assert(object != VM_OBJECT_NULL);
		assert(object->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC);
		vm_named_entry_associate_vm_object(
			user_entry,
			object,
			user_entry->offset,
			user_entry->size,
			(user_entry->protection & VM_PROT_ALL));
		assert(user_entry->is_object);
		/* we now point to this object, hold on */
		vm_object_lock(object);
		vm_object_reference_locked(object);
#if VM_OBJECT_TRACKING_OP_TRUESHARE
		if (!object->true_share &&
		    vm_object_tracking_btlog) {
			btlog_record(vm_object_tracking_btlog, object,
			    VM_OBJECT_TRACKING_OP_TRUESHARE,
			    btref_get(__builtin_frame_address(0), 0));
		}
#endif /* VM_OBJECT_TRACKING_OP_TRUESHARE */

		VM_OBJECT_SET_TRUE_SHARE(object, TRUE);
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
		vm_object_unlock(object);
	}
	*size_u = vm_sanitize_wrap_size(user_entry->size -
	    user_entry->data_offset);
	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x -> entry "
	    "%p kr 0x%x\n", target_map, offset, VM_SANITIZE_UNSAFE_UNWRAP(*size_u),
	    permission, user_entry, KERN_SUCCESS);
	return KERN_SUCCESS;
}

static inline kern_return_t
mach_make_memory_entry_sanitize_perm(
	vm_prot_ut              permission_u,
	vm_prot_t              *permission)
{
	return vm_sanitize_memory_entry_perm(permission_u,
	           VM_SANITIZE_CALLER_MACH_MAKE_MEMORY_ENTRY,
	           VM_SANITIZE_FLAGS_CHECK_USER_MEM_MAP_FLAGS,
	           VM_PROT_IS_MASK, permission);
}

kern_return_t
mach_make_memory_entry_internal(
	vm_map_t                        target_map,
	memory_object_size_ut          *size_u,
	memory_object_offset_ut         offset_u,
	vm_prot_ut                      permission_u,
	vm_named_entry_kernel_flags_t   vmne_kflags,
	ipc_port_t                     *object_handle,
	ipc_port_t                      parent_handle)
{
	vm_named_entry_t        user_entry __unused = NULL;
	vm_named_entry_t        parent_entry;
	kern_return_t           kr;
	vm_prot_t               permission;

	DEBUG4K_MEMENTRY("map %p offset 0x%llx size 0x%llx prot 0x%x\n",
	    target_map, VM_SANITIZE_UNSAFE_UNWRAP(offset_u), VM_SANITIZE_UNSAFE_UNWRAP(*size_u),
	    VM_SANITIZE_UNSAFE_UNWRAP(permission_u));

	/*
	 * Validate permissions as we need to dispatch the corresponding flavor
	 */
	kr = mach_make_memory_entry_sanitize_perm(permission_u, &permission);
	if (__improbable(kr != KERN_SUCCESS)) {
		return mach_make_memory_entry_cleanup(kr, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	if (permission & MAP_MEM_LEDGER_TAGGED) {
		vmne_kflags.vmnekf_ledger_tag = VM_LEDGER_TAG_DEFAULT;
	}

	parent_entry = mach_memory_entry_from_port(parent_handle);
	if (parent_entry && parent_entry->is_copy) {
		return mach_make_memory_entry_cleanup(KERN_INVALID_ARGUMENT, target_map,
		           size_u, offset_u, permission, user_entry, object_handle);
	}

	if (permission & MAP_MEM_ONLY) {
		return mach_make_memory_entry_mem_only(target_map, size_u, offset_u,
		           permission, object_handle, parent_entry);
	}

	if (permission & MAP_MEM_NAMED_CREATE) {
		return mach_make_memory_entry_named_create(target_map, size_u, offset_u,
		           permission, vmne_kflags, object_handle);
	}

	if (permission & MAP_MEM_VM_COPY) {
		return mach_make_memory_entry_copy(target_map, size_u, offset_u,
		           permission, vmne_kflags, object_handle);
	}

	if ((permission & MAP_MEM_VM_SHARE)
	    || parent_entry == NULL
	    || (permission & MAP_MEM_NAMED_REUSE)) {
		return mach_make_memory_entry_share(target_map, size_u, offset_u,
		           permission, vmne_kflags, object_handle, parent_handle,
		           parent_entry);
	}

	/*
	 * This function will compute map start, end and size by including the
	 * parent entry's offset. Therefore redo validation.
	 */
	return mach_make_memory_entry_from_parent_entry(target_map, size_u,
	           offset_u, permission, object_handle, parent_entry);
}

kern_return_t
_mach_make_memory_entry(
	vm_map_t                target_map,
	memory_object_size_ut  *size_u,
	memory_object_offset_ut offset_u,
	vm_prot_ut              permission_u,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_entry)
{
	return mach_make_memory_entry_64(target_map, size_u,
	           offset_u, permission_u, object_handle, parent_entry);
}

kern_return_t
mach_make_memory_entry(
	vm_map_t                target_map,
	vm_size_ut             *size_u,
	vm_offset_ut            offset_u,
	vm_prot_ut              permission_u,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_entry)
{
	kern_return_t           kr;

	kr = mach_make_memory_entry_64(target_map, size_u,
	    offset_u, permission_u, object_handle, parent_entry);
	return kr;
}

__private_extern__ vm_named_entry_t
mach_memory_entry_allocate(ipc_port_t *user_handle_p)
{
	vm_named_entry_t user_entry;

	user_entry = kalloc_type(struct vm_named_entry,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	named_entry_lock_init(user_entry);

	*user_handle_p = ipc_kobject_alloc_port((ipc_kobject_t)user_entry,
	    IKOT_NAMED_ENTRY,
	    IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);

#if VM_NAMED_ENTRY_DEBUG
	/* backtrace at allocation time, for debugging only */
	user_entry->named_entry_bt = btref_get(__builtin_frame_address(0), 0);
#endif /* VM_NAMED_ENTRY_DEBUG */
	return user_entry;
}

static __attribute__((always_inline, warn_unused_result))
kern_return_t
mach_memory_object_memory_entry_64_sanitize(
	vm_object_size_ut       size_u,
	vm_prot_ut              permission_u,
	vm_object_size_t       *size,
	vm_prot_t              *permission)
{
	kern_return_t           kr;

	kr = vm_sanitize_object_size(size_u,
	    VM_SANITIZE_CALLER_MACH_MEMORY_OBJECT_MEMORY_ENTRY,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS, size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}
	kr = vm_sanitize_memory_entry_perm(permission_u,
	    VM_SANITIZE_CALLER_MACH_MEMORY_OBJECT_MEMORY_ENTRY,
	    VM_SANITIZE_FLAGS_NONE, VM_PROT_NONE,
	    permission);
	if (__improbable(kr != KERN_SUCCESS)) {
		return kr;
	}

	return KERN_SUCCESS;
}

/*
 *	mach_memory_object_memory_entry_64
 *
 *	Create a named entry backed by the provided pager.
 *
 */
kern_return_t
mach_memory_object_memory_entry_64(
	host_t                  host,
	boolean_t               internal,
	vm_object_size_ut       size_u,
	vm_prot_ut              permission_u,
	memory_object_t         pager,
	ipc_port_t              *entry_handle)
{
	vm_named_entry_t        user_entry;
	ipc_port_t              user_handle;
	vm_object_t             object;
	vm_object_size_t        size;
	vm_prot_t               permission;
	kern_return_t           kr;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	/*
	 * Validate size and permission
	 */
	kr = mach_memory_object_memory_entry_64_sanitize(size_u,
	    permission_u,
	    &size,
	    &permission);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	if (pager == MEMORY_OBJECT_NULL && internal) {
		object = vm_object_allocate(size);
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
	} else {
		object = memory_object_to_vm_object(pager);
		if (object != VM_OBJECT_NULL) {
			vm_object_reference(object);
		}
	}
	if (object == VM_OBJECT_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	user_entry = mach_memory_entry_allocate(&user_handle);
	user_entry->size = size;
	user_entry->offset = 0;
	user_entry->protection = permission & VM_PROT_ALL;
	user_entry->access = GET_MAP_MEM(permission);
	user_entry->is_sub_map = FALSE;

	vm_named_entry_associate_vm_object(user_entry, object, 0, size,
	    (user_entry->protection & VM_PROT_ALL));
	user_entry->internal = object->internal;
	assert(object->internal == internal);
	if (VM_OBJECT_OWNER(object) != TASK_NULL) {
		/* all memory in this entry is "owned" */
		user_entry->is_fully_owned = TRUE;
	} else if (object && !object->internal) {
		/* external objects can become "owned" */
		user_entry->is_fully_owned = TRUE;
	}

	*entry_handle = user_handle;
	return KERN_SUCCESS;
}

kern_return_t
mach_memory_object_memory_entry(
	host_t          host,
	boolean_t       internal,
	vm_size_ut      size_u,
	vm_prot_ut      permission_u,
	memory_object_t pager,
	ipc_port_t      *entry_handle)
{
	return mach_memory_object_memory_entry_64( host, internal,
	           size_u, permission_u, pager, entry_handle);
}

kern_return_t
mach_memory_entry_purgable_control(
	ipc_port_t      entry_port,
	vm_purgable_t   control,
	int             *state)
{
	if (control == VM_PURGABLE_SET_STATE_FROM_KERNEL) {
		/* not allowed from user-space */
		return KERN_INVALID_ARGUMENT;
	}

	return memory_entry_purgeable_control_internal(entry_port, control, state);
}

kern_return_t
memory_entry_purgeable_control_internal(
	ipc_port_t      entry_port,
	vm_purgable_t   control,
	int             *state)
{
	kern_return_t           kr;
	vm_named_entry_t        mem_entry;
	vm_object_t             object;

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (control != VM_PURGABLE_SET_STATE &&
	    control != VM_PURGABLE_GET_STATE &&
	    control != VM_PURGABLE_SET_STATE_FROM_KERNEL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((control == VM_PURGABLE_SET_STATE ||
	    control == VM_PURGABLE_SET_STATE_FROM_KERNEL) &&
	    (((*state & ~(VM_PURGABLE_ALL_MASKS)) != 0) ||
	    ((*state & VM_PURGABLE_STATE_MASK) > VM_PURGABLE_STATE_MASK))) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map ||
	    mem_entry->is_copy) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	assert(mem_entry->is_object);
	object = vm_named_entry_to_vm_object(mem_entry);
	if (object == VM_OBJECT_NULL) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_lock(object);

	/* check that named entry covers entire object ? */
	if (mem_entry->offset != 0 || object->vo_size != mem_entry->size) {
		vm_object_unlock(object);
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_unlock(mem_entry);

	kr = vm_object_purgable_control(object, control, state);

	vm_object_unlock(object);

	return kr;
}

static kern_return_t
memory_entry_access_tracking_internal(
	ipc_port_t      entry_port,
	int             *access_tracking,
	uint32_t        *access_tracking_reads,
	uint32_t        *access_tracking_writes)
{
	vm_named_entry_t        mem_entry;
	vm_object_t             object;
	kern_return_t           kr;

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map ||
	    mem_entry->is_copy) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	assert(mem_entry->is_object);
	object = vm_named_entry_to_vm_object(mem_entry);
	if (object == VM_OBJECT_NULL) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

#if VM_OBJECT_ACCESS_TRACKING
	vm_object_access_tracking(object,
	    access_tracking,
	    access_tracking_reads,
	    access_tracking_writes);
	kr = KERN_SUCCESS;
#else /* VM_OBJECT_ACCESS_TRACKING */
	(void) access_tracking;
	(void) access_tracking_reads;
	(void) access_tracking_writes;
	kr = KERN_NOT_SUPPORTED;
#endif /* VM_OBJECT_ACCESS_TRACKING */

	named_entry_unlock(mem_entry);

	return kr;
}

kern_return_t
mach_memory_entry_access_tracking(
	ipc_port_t      entry_port,
	int             *access_tracking,
	uint32_t        *access_tracking_reads,
	uint32_t        *access_tracking_writes)
{
	return memory_entry_access_tracking_internal(entry_port,
	           access_tracking,
	           access_tracking_reads,
	           access_tracking_writes);
}

#if DEVELOPMENT || DEBUG
/* For dtrace probe in mach_memory_entry_ownership */
extern int proc_selfpid(void);
extern char *proc_name_address(void *p);
#endif /* DEVELOPMENT || DEBUG */

/* Kernel call only, MIG uses *_from_user() below */
kern_return_t
mach_memory_entry_ownership(
	ipc_port_t      entry_port,
	task_t          owner,
	int             ledger_tag,
	int             ledger_flags)
{
	task_t                  cur_task;
	kern_return_t           kr;
	vm_named_entry_t        mem_entry;
	vm_object_t             object;

	if (ledger_flags & ~VM_LEDGER_FLAGS_ALL) {
		/* reject unexpected flags */
		return KERN_INVALID_ARGUMENT;
	}

	cur_task = current_task();
	if (cur_task == kernel_task) {
		/* kernel thread: no entitlement needed */
	} else if (ledger_flags & VM_LEDGER_FLAG_FROM_KERNEL) {
		/* call is from trusted kernel code: no entitlement needed */
	} else if ((owner != cur_task && owner != TASK_NULL) ||
	    (ledger_flags & VM_LEDGER_FLAG_NO_FOOTPRINT) ||
	    (ledger_flags & VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG) ||
	    ledger_tag == VM_LEDGER_TAG_NETWORK) {
		bool transfer_ok = false;

		/*
		 * An entitlement is required to:
		 * + tranfer memory ownership to someone else,
		 * + request that the memory not count against the footprint,
		 * + tag as "network" (since that implies "no footprint")
		 *
		 * Exception: task with task_no_footprint_for_debug == 1 on internal build
		 */
		if (!cur_task->task_can_transfer_memory_ownership &&
		    IOCurrentTaskHasEntitlement("com.apple.private.memory.ownership_transfer")) {
			cur_task->task_can_transfer_memory_ownership = TRUE;
		}
		if (cur_task->task_can_transfer_memory_ownership) {
			/* we're allowed to transfer ownership to any task */
			transfer_ok = true;
		}
#if DEVELOPMENT || DEBUG
		if (!transfer_ok &&
		    ledger_tag == VM_LEDGER_TAG_DEFAULT &&
		    (ledger_flags & VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG) &&
		    cur_task->task_no_footprint_for_debug) {
			int         to_panic = 0;
			static bool init_bootarg = false;

			/*
			 * Allow performance tools running on internal builds to hide memory usage from phys_footprint even
			 * WITHOUT an entitlement. This can be enabled by per task sysctl vm.task_no_footprint_for_debug=1
			 * with the ledger tag VM_LEDGER_TAG_DEFAULT and flag VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG.
			 *
			 * If the boot-arg "panic_on_no_footprint_for_debug" is set, the kernel will
			 * panic here in order to detect any abuse of this feature, which is intended solely for
			 * memory debugging purpose.
			 */
			if (!init_bootarg) {
				PE_parse_boot_argn("panic_on_no_footprint_for_debug", &to_panic, sizeof(to_panic));
				init_bootarg = true;
			}
			if (to_panic) {
				panic("%s: panic_on_no_footprint_for_debug is triggered by pid %d procname %s", __func__, proc_selfpid(), get_bsdtask_info(cur_task)? proc_name_address(get_bsdtask_info(cur_task)) : "?");
			}

			/*
			 * Flushing out user space processes using this interface:
			 * $ dtrace -n 'task_no_footprint_for_debug {printf("%d[%s]\n", pid, execname); stack(); ustack();}'
			 */
			DTRACE_VM(task_no_footprint_for_debug);
			transfer_ok = true;
		}
#endif /* DEVELOPMENT || DEBUG */
		if (!transfer_ok) {
#define TRANSFER_ENTITLEMENT_MAX_LENGTH 1024 /* XXX ? */
			const char *our_id, *their_id;
			our_id = IOTaskGetEntitlement(current_task(), "com.apple.developer.memory.transfer-send");
			their_id = IOTaskGetEntitlement(owner, "com.apple.developer.memory.transfer-accept");
			if (our_id && their_id &&
			    !strncmp(our_id, their_id, TRANSFER_ENTITLEMENT_MAX_LENGTH)) {
				/* allow transfer between tasks that have matching entitlements */
				if (strnlen(our_id, TRANSFER_ENTITLEMENT_MAX_LENGTH) < TRANSFER_ENTITLEMENT_MAX_LENGTH &&
				    strnlen(their_id, TRANSFER_ENTITLEMENT_MAX_LENGTH) < TRANSFER_ENTITLEMENT_MAX_LENGTH) {
					transfer_ok = true;
				} else {
					/* complain about entitlement(s) being too long... */
					assertf((strlen(our_id) <= TRANSFER_ENTITLEMENT_MAX_LENGTH &&
					    strlen(their_id) <= TRANSFER_ENTITLEMENT_MAX_LENGTH),
					    "our_id:%lu their_id:%lu",
					    strlen(our_id), strlen(their_id));
				}
			}
		}
		if (!transfer_ok) {
			/* transfer denied */
			return KERN_NO_ACCESS;
		}

		if (ledger_flags & VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG) {
			/*
			 * We've made it past the checks above, so we either
			 * have the entitlement or the sysctl.
			 * Convert to VM_LEDGER_FLAG_NO_FOOTPRINT.
			 */
			ledger_flags &= ~VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG;
			ledger_flags |= VM_LEDGER_FLAG_NO_FOOTPRINT;
		}
	}

	if (ledger_tag == VM_LEDGER_TAG_UNCHANGED) {
		/* leave "ledger_tag" unchanged */
	} else if (ledger_tag < 0 ||
	    ledger_tag > VM_LEDGER_TAG_MAX) {
		return KERN_INVALID_ARGUMENT;
	}
	if (owner == TASK_NULL) {
		/* leave "owner" unchanged */
		owner = VM_OBJECT_OWNER_UNCHANGED;
	}

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map ||
	    !mem_entry->is_fully_owned) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	if (mem_entry->is_object) {
		object = vm_named_entry_to_vm_object(mem_entry);
		if (object == VM_OBJECT_NULL) {
			named_entry_unlock(mem_entry);
			return KERN_INVALID_ARGUMENT;
		}
		vm_object_lock(object);
		if (object->internal) {
			/* check that named entry covers entire object ? */
			if (mem_entry->offset != 0 ||
			    object->vo_size != mem_entry->size) {
				vm_object_unlock(object);
				named_entry_unlock(mem_entry);
				return KERN_INVALID_ARGUMENT;
			}
		}
		named_entry_unlock(mem_entry);
		kr = vm_object_ownership_change(object,
		    ledger_tag,
		    owner,
		    ledger_flags,
		    FALSE);                             /* task_objq_locked */
		vm_object_unlock(object);
	} else if (mem_entry->is_copy) {
		vm_map_copy_t copy;
		vm_map_entry_t entry;

		copy = mem_entry->backing.copy;
		named_entry_unlock(mem_entry);
		for (entry = vm_map_copy_first_entry(copy);
		    entry != vm_map_copy_to_entry(copy);
		    entry = entry->vme_next) {
			object = VME_OBJECT(entry);
			if (entry->is_sub_map ||
			    object == VM_OBJECT_NULL) {
				kr = KERN_INVALID_ARGUMENT;
				break;
			}
			vm_object_lock(object);
			if (object->internal) {
				if (VME_OFFSET(entry) != 0 ||
				    entry->vme_end - entry->vme_start != object->vo_size) {
					vm_object_unlock(object);
					kr = KERN_INVALID_ARGUMENT;
					break;
				}
			}
			kr = vm_object_ownership_change(object,
			    ledger_tag,
			    owner,
			    ledger_flags,
			    FALSE);                             /* task_objq_locked */
			vm_object_unlock(object);
			if (kr != KERN_SUCCESS) {
				kr = KERN_INVALID_ARGUMENT;
				break;
			}
		}
	} else {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	return kr;
}

/* MIG call from userspace */
kern_return_t
mach_memory_entry_ownership_from_user(
	ipc_port_t      entry_port,
	mach_port_t     owner_port,
	int             ledger_tag,
	int             ledger_flags)
{
	task_t owner = TASK_NULL;
	kern_return_t kr;

	if (ledger_flags & ~VM_LEDGER_FLAGS_USER) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(owner_port)) {
		if (ip_kotype(owner_port) == IKOT_TASK_ID_TOKEN) {
			task_id_token_t token = convert_port_to_task_id_token(owner_port);
			(void)task_identity_token_get_task_grp(token, &owner, TASK_GRP_MIG);
			task_id_token_release(token);
			/* token ref released */
		} else {
			owner = convert_port_to_task_mig(owner_port);
		}
	}
	/* hold task ref on owner (Nullable) */

	if (owner && task_is_a_corpse(owner)) {
		/* identity token can represent a corpse, disallow it */
		task_deallocate_mig(owner);
		owner = TASK_NULL;
	}

	/* mach_memory_entry_ownership() will handle TASK_NULL owner */
	kr = mach_memory_entry_ownership(entry_port, owner, /* Nullable */
	    ledger_tag, ledger_flags);

	if (owner) {
		task_deallocate_mig(owner);
	}

	if (kr == KERN_SUCCESS) {
		/* MIG rule, consume port right on success */
		ipc_port_release_send(owner_port);
	}
	return kr;
}

kern_return_t
mach_memory_entry_get_page_counts(
	ipc_port_t      entry_port,
	unsigned int    *resident_page_count,
	unsigned int    *dirty_page_count)
{
	kern_return_t           kr;
	vm_named_entry_t        mem_entry;
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_object_size_t        size;

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map ||
	    mem_entry->is_copy) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	assert(mem_entry->is_object);
	object = vm_named_entry_to_vm_object(mem_entry);
	if (object == VM_OBJECT_NULL) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_lock(object);

	offset = mem_entry->offset;
	size = mem_entry->size;
	size = vm_object_round_page(offset + size) - vm_object_trunc_page(offset);
	offset = vm_object_trunc_page(offset);

	named_entry_unlock(mem_entry);

	kr = vm_object_get_page_counts(object, offset, size, resident_page_count, dirty_page_count);

	vm_object_unlock(object);

	return kr;
}

kern_return_t
mach_memory_entry_phys_page_offset(
	ipc_port_t              entry_port,
	vm_object_offset_t      *offset_p)
{
	vm_named_entry_t        mem_entry;
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_object_offset_t      data_offset;

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map ||
	    mem_entry->is_copy) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	assert(mem_entry->is_object);
	object = vm_named_entry_to_vm_object(mem_entry);
	if (object == VM_OBJECT_NULL) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	offset = mem_entry->offset;
	data_offset = mem_entry->data_offset;

	named_entry_unlock(mem_entry);

	*offset_p = offset - vm_object_trunc_page(offset) + data_offset;
	return KERN_SUCCESS;
}

static inline kern_return_t
mach_memory_entry_map_size_sanitize_locked(
	vm_map_t                   map,
	memory_object_offset_ut   *offset_u,
	memory_object_size_ut      size_u,
	vm_named_entry_t           mem_entry,
	memory_object_offset_t    *offset,
	memory_object_offset_t    *end,
	mach_vm_size_t            *map_size)
{
	kern_return_t           kr;

	if (mem_entry->is_object ||
	    (mem_entry->is_copy &&
	    (VM_MAP_COPY_PAGE_MASK(mem_entry->backing.copy) ==
	    VM_MAP_PAGE_MASK(map)))) {
		if (__improbable(vm_sanitize_add_overflow(*offset_u, mem_entry->offset,
		    offset_u))) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	if (__improbable(vm_sanitize_add_overflow(*offset_u, mem_entry->data_offset,
	    offset_u))) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_sanitize_addr_size(*offset_u, size_u,
	    VM_SANITIZE_CALLER_MACH_MEMORY_ENTRY_MAP_SIZE, map,
	    VM_SANITIZE_FLAGS_SIZE_ZERO_FALLTHROUGH, offset, end, map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	return KERN_SUCCESS;
}

kern_return_t
mach_memory_entry_map_size(
	ipc_port_t                 entry_port,
	vm_map_t                   map,
	memory_object_offset_ut    offset_u,
	memory_object_size_ut      size_u,
	mach_vm_size_t            *map_size_out)
{
	vm_named_entry_t        mem_entry;
	vm_object_t             object;
	vm_map_copy_t           copy_map, target_copy_map;
	vm_map_offset_t         overmap_start, overmap_end, trimmed_start;
	kern_return_t           kr;
	memory_object_offset_t  offset;
	memory_object_offset_t  end;
	mach_vm_size_t          map_size;

	*map_size_out = 0;

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Sanitize offset and size before use
	 */
	kr = mach_memory_entry_map_size_sanitize_locked(map,
	    &offset_u,
	    size_u,
	    mem_entry,
	    &offset,
	    &end,
	    &map_size);
	if (__improbable(kr != KERN_SUCCESS)) {
		named_entry_unlock(mem_entry);
		return kr;
	}

	if (mem_entry->is_object) {
		object = vm_named_entry_to_vm_object(mem_entry);
		if (object == VM_OBJECT_NULL) {
			named_entry_unlock(mem_entry);
			return KERN_INVALID_ARGUMENT;
		}

		named_entry_unlock(mem_entry);
		*map_size_out = map_size;
		return KERN_SUCCESS;
	}

	if (!mem_entry->is_copy) {
		panic("unsupported type of mem_entry %p", mem_entry);
	}

	assert(mem_entry->is_copy);
	if (VM_MAP_COPY_PAGE_MASK(mem_entry->backing.copy) == VM_MAP_PAGE_MASK(map)) {
		DEBUG4K_SHARE("map %p (%d) mem_entry %p offset 0x%llx + 0x%llx + 0x%llx size 0x%llx -> map_size 0x%llx\n", map, VM_MAP_PAGE_MASK(map), mem_entry, mem_entry->offset, mem_entry->data_offset, offset, VM_SANITIZE_UNSAFE_UNWRAP(size_u), map_size);
		named_entry_unlock(mem_entry);
		*map_size_out = map_size;
		return KERN_SUCCESS;
	}

	DEBUG4K_SHARE("mem_entry %p copy %p (%d) map %p (%d) offset 0x%llx size 0x%llx\n", mem_entry, mem_entry->backing.copy, VM_MAP_COPY_PAGE_SHIFT(mem_entry->backing.copy), map, VM_MAP_PAGE_SHIFT(map), offset, VM_SANITIZE_UNSAFE_UNWRAP(size_u));
	copy_map = mem_entry->backing.copy;
	target_copy_map = VM_MAP_COPY_NULL;
	DEBUG4K_ADJUST("adjusting...\n");
	kr = vm_map_copy_adjust_to_target(copy_map,
	    offset_u,
	    size_u,
	    map,
	    FALSE,
	    &target_copy_map,
	    &overmap_start,
	    &overmap_end,
	    &trimmed_start);
	if (kr == KERN_SUCCESS) {
		if (target_copy_map->size != copy_map->size) {
			DEBUG4K_ADJUST("copy %p (%d) map %p (%d) offset 0x%llx size 0x%llx overmap_start 0x%llx overmap_end 0x%llx trimmed_start 0x%llx map_size 0x%llx -> 0x%llx\n", copy_map, VM_MAP_COPY_PAGE_SHIFT(copy_map), map, VM_MAP_PAGE_SHIFT(map), (uint64_t)offset, (uint64_t)VM_SANITIZE_UNSAFE_UNWRAP(size_u), (uint64_t)overmap_start, (uint64_t)overmap_end, (uint64_t)trimmed_start, (uint64_t)copy_map->size, (uint64_t)target_copy_map->size);
		}
		*map_size_out = target_copy_map->size;
		if (target_copy_map != copy_map) {
			vm_map_copy_discard(target_copy_map);
		}
		target_copy_map = VM_MAP_COPY_NULL;
	}
	named_entry_unlock(mem_entry);
	return kr;
}

/*
 * mach_memory_entry_port_release:
 *
 * Release a send right on a named entry port.  This is the correct
 * way to destroy a named entry.  When the last right on the port is
 * released, mach_memory_entry_no_senders() willl be called.
 */
void
mach_memory_entry_port_release(
	ipc_port_t      port)
{
	assert(ip_kotype(port) == IKOT_NAMED_ENTRY);
	ipc_port_release_send(port);
}

vm_named_entry_t
mach_memory_entry_from_port(ipc_port_t port)
{
	if (IP_VALID(port)) {
		return ipc_kobject_get_stable(port, IKOT_NAMED_ENTRY);
	}
	return NULL;
}

/*
 * mach_memory_entry_no_senders:
 *
 * Destroys the memory entry associated with a mach port.
 * Memory entries have the exact same lifetime as their owning port.
 *
 * Releasing a memory entry is done by calling
 * mach_memory_entry_port_release() on its owning port.
 */
static void
mach_memory_entry_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	vm_named_entry_t named_entry;

	named_entry = ipc_kobject_dealloc_port(port, mscount, IKOT_NAMED_ENTRY);

	if (named_entry->is_sub_map) {
		vm_map_deallocate(named_entry->backing.map);
	} else if (named_entry->is_copy) {
		vm_map_copy_discard(named_entry->backing.copy);
	} else if (named_entry->is_object) {
		assert(named_entry->backing.copy->cpy_hdr.nentries == 1);
		vm_map_copy_discard(named_entry->backing.copy);
	} else {
		assert(named_entry->backing.copy == VM_MAP_COPY_NULL);
	}

#if VM_NAMED_ENTRY_DEBUG
	btref_put(named_entry->named_entry_bt);
#endif /* VM_NAMED_ENTRY_DEBUG */

	named_entry_lock_destroy(named_entry);
	kfree_type(struct vm_named_entry, named_entry);
}

#if XNU_PLATFORM_MacOSX
/* Allow manipulation of individual page state.  This is actually part of */
/* the UPL regimen but takes place on the memory entry rather than on a UPL */

kern_return_t
mach_memory_entry_page_op(
	ipc_port_t              entry_port,
	vm_object_offset_ut     offset_u,
	int                     ops,
	ppnum_t                 *phys_entry,
	int                     *flags)
{
	vm_named_entry_t        mem_entry;
	vm_object_t             object;
	kern_return_t           kr;
	/*
	 * Unwrap offset as no mathematical operations are
	 * performed on it.
	 */
	vm_object_offset_t      offset = VM_SANITIZE_UNSAFE_UNWRAP(offset_u);

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (mem_entry->is_sub_map ||
	    mem_entry->is_copy) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	assert(mem_entry->is_object);
	object = vm_named_entry_to_vm_object(mem_entry);
	if (object == VM_OBJECT_NULL) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_reference(object);
	named_entry_unlock(mem_entry);

	kr = vm_object_page_op(object, offset, ops, phys_entry, flags);

	vm_object_deallocate(object);

	return kr;
}

/*
 * mach_memory_entry_range_op offers performance enhancement over
 * mach_memory_entry_page_op for page_op functions which do not require page
 * level state to be returned from the call.  Page_op was created to provide
 * a low-cost alternative to page manipulation via UPLs when only a single
 * page was involved.  The range_op call establishes the ability in the _op
 * family of functions to work on multiple pages where the lack of page level
 * state handling allows the caller to avoid the overhead of the upl structures.
 */

kern_return_t
mach_memory_entry_range_op(
	ipc_port_t              entry_port,
	vm_object_offset_ut     offset_beg_u,
	vm_object_offset_ut     offset_end_u,
	int                     ops,
	int                     *range)
{
	vm_named_entry_t        mem_entry;
	vm_object_t             object;
	kern_return_t           kr;
	vm_object_offset_t      offset_range;
	/*
	 * Unwrap offset beginning and end as no mathematical operations are
	 * performed on these quantities.
	 */
	vm_object_offset_t      offset_beg = VM_SANITIZE_UNSAFE_UNWRAP(offset_beg_u);
	vm_object_offset_t      offset_end = VM_SANITIZE_UNSAFE_UNWRAP(offset_end_u);

	mem_entry = mach_memory_entry_from_port(entry_port);
	if (mem_entry == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	named_entry_lock(mem_entry);

	if (__improbable(os_sub_overflow(offset_end, offset_beg, &offset_range) ||
	    (offset_range > (uint32_t) -1))) {
		/* range is too big and would overflow "*range" */
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	if (mem_entry->is_sub_map ||
	    mem_entry->is_copy) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	assert(mem_entry->is_object);
	object = vm_named_entry_to_vm_object(mem_entry);
	if (object == VM_OBJECT_NULL) {
		named_entry_unlock(mem_entry);
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_reference(object);
	named_entry_unlock(mem_entry);

	kr = vm_object_range_op(object,
	    offset_beg,
	    offset_end,
	    ops,
	    (uint32_t *) range);

	vm_object_deallocate(object);

	return kr;
}
#endif /* XNU_PLATFORM_MacOSX */

kern_return_t
memory_entry_check_for_adjustment(
	vm_map_t                        src_map,
	ipc_port_t                      port,
	vm_map_offset_t         *overmap_start,
	vm_map_offset_t         *overmap_end)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_copy_t copy_map = VM_MAP_COPY_NULL, target_copy_map = VM_MAP_COPY_NULL;

	assert(port);
	assertf(ip_kotype(port) == IKOT_NAMED_ENTRY, "Port Type expected: %d...received:%d\n", IKOT_NAMED_ENTRY, ip_kotype(port));

	vm_named_entry_t        named_entry;

	named_entry = mach_memory_entry_from_port(port);
	named_entry_lock(named_entry);
	copy_map = named_entry->backing.copy;
	target_copy_map = copy_map;

	if (src_map && VM_MAP_PAGE_SHIFT(src_map) < PAGE_SHIFT) {
		vm_map_offset_t trimmed_start;

		trimmed_start = 0;
		DEBUG4K_ADJUST("adjusting...\n");
		kr = vm_map_copy_adjust_to_target(
			copy_map,
			vm_sanitize_wrap_addr(0), /* offset */
			vm_sanitize_wrap_size(copy_map->size), /* size */
			src_map,
			FALSE, /* copy */
			&target_copy_map,
			overmap_start,
			overmap_end,
			&trimmed_start);
		assert(trimmed_start == 0);
	}
	named_entry_unlock(named_entry);

	return kr;
}

vm_object_t
vm_convert_port_to_copy_object(
	ipc_port_t      port)
{
	/* Invalid / wrong port type? */
	if (!IP_VALID(port) || ip_kotype(port) != IKOT_NAMED_ENTRY) {
		return NULL;
	}

	/* We expect the named entry to point to an object. */
	vm_named_entry_t named_entry = mach_memory_entry_from_port(port);
	if (!named_entry || !named_entry->is_object) {
		return NULL;
	}

	/* Pull out the copy map object... */
	return vm_named_entry_to_vm_object(named_entry);
}
