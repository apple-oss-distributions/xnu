/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_MAP_INTERNAL_H_
#define _VM_VM_MAP_INTERNAL_H_

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

/*
 * This file contains interfaces that are private to the VM
 */

#define KiB(x) (1024 * (x))
#define MeB(x) (1024 * 1024 * (x))

#if __LP64__
#define KMEM_SMALLMAP_THRESHOLD     (MeB(1))
#else
#define KMEM_SMALLMAP_THRESHOLD     (KiB(256))
#endif

struct kmem_page_meta;


/* We can't extern this from vm_kern.h because we can't include pmap.h */
extern void kernel_memory_populate_object_and_unlock(
	vm_object_t             object, /* must be locked */
	vm_address_t            addr,
	vm_offset_t             offset,
	vm_size_t               size,
	struct vm_page         *page_list,
	kma_flags_t             flags,
	vm_tag_t                tag,
	vm_prot_t               prot,
	pmap_mapping_type_t     mapping_type);

/* Initialize the module */
extern void vm_map_init(void);

extern kern_return_t vm_map_locate_space(
	vm_map_t                map,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_offset_t        *start_inout,
	vm_map_entry_t         *entry_out);

/* Allocate a range in the specified virtual address map and
 * return the entry allocated for that range. */
extern kern_return_t vm_map_find_space(
	vm_map_t                map,
	vm_map_address_t        hint_addr,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_entry_t          *o_entry);                              /* OUT */

extern void vm_map_clip_start(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_offset_t         endaddr);

extern void vm_map_clip_end(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_offset_t         endaddr);

extern boolean_t vm_map_entry_should_cow_for_true_share(
	vm_map_entry_t          entry);

/*!
 * @typedef vmr_flags_t
 *
 * @brief
 * Flags for vm_map_remove() and vm_map_delete()
 *
 * @const VM_MAP_REMOVE_NO_FLAGS
 * When no special flags is to be passed.
 *
 * @const VM_MAP_REMOVE_KUNWIRE
 * Unwire memory as a side effect.
 *
 * @const VM_MAP_REMOVE_INTERRUPTIBLE
 * Whether the call is interruptible if it needs to wait for a vm map
 * entry to quiesce (interruption leads to KERN_ABORTED).
 *
 * @const VM_MAP_REMOVE_NOKUNWIRE_LAST
 * Do not unwire the last page of this entry during remove.
 * (Used by kmem_realloc()).
 *
 * @const VM_MAP_REMOVE_IMMUTABLE
 * Allow permanent entries to be removed.
 *
 * @const VM_MAP_REMOVE_GAPS_FAIL
 * Return KERN_INVALID_VALUE when a gap is being removed instead of panicking.
 *
 * @const VM_MAP_REMOVE_NO_YIELD.
 * Try to avoid yielding during this call.
 *
 * @const VM_MAP_REMOVE_GUESS_SIZE
 * The caller doesn't know the precise size of the entry,
 * but the address must match an atomic entry.
 *
 * @const VM_MAP_REMOVE_IMMUTABLE_CODE
 * Allow executables entries to be removed (for VM_PROT_COPY),
 * which is used by debuggers.
 */
__options_decl(vmr_flags_t, uint32_t, {
	VM_MAP_REMOVE_NO_FLAGS          = 0x000,
	VM_MAP_REMOVE_KUNWIRE           = 0x001,
	VM_MAP_REMOVE_INTERRUPTIBLE     = 0x002,
	VM_MAP_REMOVE_NOKUNWIRE_LAST    = 0x004,
	VM_MAP_REMOVE_NO_MAP_ALIGN      = 0x008,
	VM_MAP_REMOVE_IMMUTABLE         = 0x010,
	VM_MAP_REMOVE_GAPS_FAIL         = 0x020,
	VM_MAP_REMOVE_NO_YIELD          = 0x040,
	VM_MAP_REMOVE_GUESS_SIZE        = 0x080,
	VM_MAP_REMOVE_IMMUTABLE_CODE    = 0x100,
	VM_MAP_REMOVE_TO_OVERWRITE      = 0x200,
});

/* Deallocate a region */
extern kmem_return_t vm_map_remove_guard(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard) __result_use_check;

extern kmem_return_t vm_map_remove_and_unlock(
	vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end,
	vmr_flags_t     flags,
	kmem_guard_t    guard) __result_use_check;

/* Deallocate a region */
static inline void
vm_map_remove(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end)
{
	vmr_flags_t  flags = VM_MAP_REMOVE_NO_FLAGS;
	kmem_guard_t guard = KMEM_GUARD_NONE;

	(void)vm_map_remove_guard(map, start, end, flags, guard);
}

extern bool kmem_is_ptr_range(vm_map_range_id_t range_id);

extern mach_vm_range_t kmem_validate_range_for_overwrite(
	vm_map_offset_t         addr,
	vm_map_size_t           size);

extern uint32_t kmem_addr_get_slot_idx(
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_map_range_id_t       range_id,
	struct kmem_page_meta **meta,
	uint32_t               *size_idx,
	mach_vm_range_t         slot);

extern void kmem_validate_slot(
	vm_map_offset_t         addr,
	struct kmem_page_meta  *meta,
	uint32_t                size_idx,
	uint32_t                slot_idx);

/*
 * Function used to allocate VA from kmem pointer ranges
 */
extern kern_return_t kmem_locate_space(
	vm_map_size_t           size,
	vm_map_range_id_t       range_id,
	bool                    direction,
	vm_map_offset_t        *start_inout,
	vm_map_entry_t         *entry_out);

/*
 * Function used to free VA to kmem pointer ranges
 */
extern void kmem_free_space(
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_map_range_id_t       range_id,
	mach_vm_range_t         slot);

#pragma GCC visibility pop
__END_DECLS

#endif  /* _VM_VM_MAP_INTERNAL_H_ */
