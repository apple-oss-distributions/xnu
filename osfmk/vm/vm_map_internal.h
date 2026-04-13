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

#include <vm/vm_map_xnu.h>
#include <vm/vm_kern_xnu.h>
#include <mach/vm_types_unsafe.h>
#include <vm/vm_sanitize_internal.h>
#include <kern/counter.h>
#include <kern/thread_test_context.h>
#ifdef MACH_KERNEL_PRIVATE
#include <vm/vm_object_internal.h>
#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE

/* Check protection */
extern boolean_t vm_map_check_protection(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              protection_u,
	vm_sanitize_caller_t    vm_sanitize_caller);

extern kern_return_t vm_map_wire_impl(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	vm_prot_ut              prot_u,
	vm_tag_t                tag,
	boolean_t               user_wire,
	ppnum_t                *physpage_p,
	vm_sanitize_caller_t    vm_sanitize_caller);

extern kern_return_t vm_map_unwire_impl(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	boolean_t               user_wire,
	vm_sanitize_caller_t    vm_sanitize_caller);

#endif /* XNU_KERNEL_PRIVATE */
#ifdef MACH_KERNEL_PRIVATE
__exported_push_hidden
#include <vm/vm_entry_lock_internal.h>

/* definitions related to overriding the NX behavior */
#define VM_ABI_32       0x1
#define VM_ABI_64       0x2

/*
 * This file contains interfaces that are private to the VM
 */

#define KiB(kb) ((kb) << 10ull)
#define BtoKiB(b) ((b) >> 10)
#define MiB(mb) ((mb) << 20ull)
#define BtoMiB(b) ((b) >> 20)

typedef struct vm_map_lock_ctx *vm_map_lock_ctx_t;

/*
 * Debugging options available via boot-arg.
 * See vm_debug_parse_boot_args() for usage.
 */
#if MACH_ASSERT
extern bool vm_debug_any_options_enabled;
#endif  /* MACH_ASSERT */

/*!
 * @function vm_map_entry_create_locked()
 *
 * @brief
 * Creates a new vm map entry.
 *
 * @discussion.
 * The entry is returned exclusively locked.
 *
 * @param map           the map this entry belongs to.
 * @param start         the entry start address.
 * @param end           the entry end address.
 */
extern vm_map_entry_t vm_map_entry_create_locked(
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end);

/*!
 * @function vm_map_entry_create_sentinel_locked()
 *
 * @brief
 * Creates a new sentinel vm map entry outside of any range lock context. See
 * documentation of VMRL_ATOMIC_ALLOW_HOLES for discussion of sentinel entries.
 *
 * @discussion.
 * The entry is returned exclusively locked, and should never be unlocked.
 * This is intended to be used by vm_map_delete to fill holes in the space
 * deleted.
 *
 * @param map           the map this entry belongs to.
 * @param start         the start address of the range where the sentinel will be mapped
 * @param end           the end address of the range where the sentinel will be mapped
 */
extern vm_map_entry_t vm_map_entry_create_sentinel_locked(
	vm_map_t                map,
	mach_vm_address_t       start,
	mach_vm_address_t       end);

/*!
 * @function vm_map_entry_copy_locked()
 *
 * @brief
 * Creates a copy of an exclusively locked entry.
 *
 * @discussion.
 * The entry is returned locked.
 * The entry owns a reference on the object/submap it points to if any.
 * The entry should only be inserted in real maps, not copy maps. For the
 * latter, look at @c vm_map_copy_entry_copy.
 *
 * @param map           the map this entry belongs to.
 * @param entry         the entry to copy.
 */
extern vm_map_entry_t vm_map_entry_copy_locked(
	vm_map_t                map,
	vm_map_entry_t          entry);

/*!
 * @function vm_map_entry_free_locked()
 *
 * @brief
 * Wakes up any waiters and then frees an entry that is currently locked, or
 * simply frees an entry whose lock is already invalid.
 *
 * @discussion.
 * This should not be the lock_context's vmlc_vme, but instead on a
 * zap list (vm_map_zap_t) or a newly created entry.
 *
 * This function releases references to the object/submap the entry points
 * to as well.
 *
 * @param map           the map this entry belongs to.
 * @param entry         the entry to be freed.
 */
extern void vm_map_entry_free_locked(
	vm_map_t                map,
	vm_map_entry_t          entry);

/*!
 * @function vm_map_copy_entry_copy
 *
 * @brief
 * Creates a copy of a vm map entry in a vm_map_copy_t.
 *
 * @discussion
 * The entry owns a reference on the object/submap it points to if any.
 * The entry should only be inserted in copy maps, not real maps. For the
 * latter, look at @c vm_map_entry_copy_locked.
 *
 * @param copy           the copy this entry belongs to.
 * @param entry          the entry to copy
 */
extern vm_map_entry_t vm_map_copy_entry_copy(
	vm_map_copy_t           copy,
	vm_map_entry_t          entry);

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

/*!
 * @function vm_map_locate_space_anywhere()
 *
 * @brief
 * Locate (no reservation) a range in the specified VM map.
 *
 * @param map           the map to scan for memory. interlock must be held.
 * @param hint          an optional address to start scanning from, or 0
 * @param size          the size of the allocation to make.
 * @param mask          an alignment mask the allocation must respect.
 *                      (takes vmk_flags.vmkf_guard_before into account).
 * @param vmk_flags     the vm map kernel flags to influence this call.
 *                      vmk_flags.vmf_anywhere must be set.
 * @param reservation   the reservation if KERN_SUCCESS is returned.
 *
 * @returns
 * - KERN_SUCCESS in case of success, in which case:
 *   o the address pointed at by @c start_inout is updated to the start
 *     of the range located
 *   o entry_out is set to the entry right before the hole in the map.
 *
 * - KERN_INVALID_ARGUMENT if some of the parameters aren't right
 *   (typically invalid vmk_flags).
 *
 * - KERN_NO_SPACE if no space was found with the specified constraints.
 *
 * @note
 * This function may sleep and temporarily release the interlock, but it always
 * returns with it held.
 */
extern kern_return_t vm_map_locate_space_anywhere(
	vm_map_t                map,
	vm_map_address_t        hint,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_store_rsv_t     *reservation);

extern void vm_map_seal(
	vm_map_t                 map,
	bool                     nested_pmap);

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
 * Not valid for the kernel_map.
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
 * @const VM_MAP_REMOVE_TO_OVERWRITE
 * The caller will overwrite the region with new memory.
 *
 * @const VM_MAP_REMOVE_IMMUTABLE_CODE
 * Allow executables entries to be removed (for VM_PROT_COPY),
 * which is used by debuggers.
 *
 * @const VM_MAP_REMOVE_RANGE_LOCKED
 * Allow the removal of a range which is already exclusively locked by the
 * caller. Callers should only use the vm_map_delete_and_iunlock_range_locked
 * interface when passing this flag, as it re-runs the deletion preflight.
 *
 * @constant VM_MAP_REMOVE_ZERO_FILL
 * Replaces each removed entry with a new entry with a NULL object, resulting
 * in faults in the entry being zero-filled. The replacement entries are created
 * with the same protections and inheritance as the entries they replace.
 *
 */
__options_decl(vmr_flags_t, uint32_t, {
	VM_MAP_REMOVE_NO_FLAGS          = 0x000,
	VM_MAP_REMOVE_KUNWIRE           = 0x001,
	VM_MAP_REMOVE_INTERRUPTIBLE     = 0x002,
	VM_MAP_REMOVE_NOKUNWIRE_LAST    = 0x004,
	VM_MAP_REMOVE_IMMUTABLE         = 0x008,
	VM_MAP_REMOVE_GAPS_FAIL         = 0x010,
	VM_MAP_REMOVE_TO_OVERWRITE      = 0x020,
	VM_MAP_REMOVE_IMMUTABLE_CODE    = 0x040,
	VM_MAP_REMOVE_RANGE_LOCKED      = 0x080,
	VM_MAP_REMOVE_ZERO_FILL         = 0x100,
});

extern void vm_map_remove_entry(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vmr_flags_t             flags);

/* Deallocate a region */
extern kern_return_t vm_map_remove_guard(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard) __result_use_check;

extern kern_return_t vm_map_remove_and_iunlock(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vmr_flags_t             flags,
	kmem_guard_t            guard) __result_use_check;

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

ppnum_t vm_map_get_phys_page(
	vm_map_t        map,
	vm_offset_t     offset);

/* Change inheritance */
extern kern_return_t    vm_map_inherit(
	vm_map_t                map,
	vm_map_offset_ut        start,
	vm_map_offset_ut        end,
	vm_inherit_ut           new_inheritance);

/* Change protection */
extern kern_return_t    vm_map_protect(
	vm_map_t                map,
	vm_map_offset_ut        start_u,
	vm_map_offset_ut        end_u,
	boolean_t               set_max,
	vm_prot_ut              new_prot_u);

__exported_pop

static inline void
VME_OBJECT_SET(
	vm_map_entry_t entry,
	vm_object_t    object,
	bool           atomic,
	uint32_t       context)
{
	__builtin_assume(((vm_offset_t)object & 3) == 0);

	VM_ENTRY_ASSERT_FIELDS_WRITABLE(entry);

	entry->vme_atomic = atomic;
	entry->is_sub_map = false;
	if (atomic) {
		entry->vme_context = context;
	} else {
		entry->vme_context = 0;
	}

	if (!object) {
		entry->vme_object_or_delta = 0;
	} else if (is_kernel_object(object)) {
#if VM_BTLOG_TAGS
		if (!(entry->vme_kernel_object && entry->vme_tag_btref))
#endif /* VM_BTLOG_TAGS */
		{
			entry->vme_object_or_delta = 0;
		}
	} else {
#if VM_BTLOG_TAGS
		if (entry->vme_kernel_object && entry->vme_tag_btref) {
			btref_put(entry->vme_tag_btref);
		}
#endif /* VM_BTLOG_TAGS */
		entry->vme_object_or_delta = VM_OBJECT_PACK(object);
	}

	entry->vme_kernel_object = is_kernel_object(object);
	entry->vme_resilient_codesign = false;
	entry->used_for_jit = false;
#if HAS_MTE
	if (object == kernel_object_tagged) {
		entry->vme_is_tagged = TRUE;
	} else if (object == kernel_object_default) {
		entry->vme_is_tagged = FALSE;
	}
#endif /* HAS_MTE */
}

static inline void
VM_OBJECT_SET_KEEP_JIT(
	vm_map_entry_t entry,
	vm_object_t    object,
	bool           atomic,
	uint32_t       context)
{
	/* VME_OBJECT_SET will reset used_for_jit, so preserve it. */
	boolean_t saved_used_for_jit = entry->used_for_jit;
	VME_OBJECT_SET(entry, object, atomic, context);
	entry->used_for_jit = saved_used_for_jit;
}


static inline void
VME_OFFSET_SET(
	vm_map_entry_t entry,
	vm_object_offset_t offset)
{
	entry->vme_offset = offset >> VME_OFFSET_SHIFT;
	assert3u(VME_OFFSET(entry), ==, offset);
}

/*
 * IMPORTANT:
 * The "alias" field can be updated while holding the VM map lock
 * "shared".  It's OK as along as it's the only field that can be
 * updated without the VM map "exclusive" lock.
 */
static inline void
VME_ALIAS_SET(
	vm_map_entry_t entry,
	unsigned int alias)
{
	assert3u(alias & VME_ALIAS_MASK, ==, alias);
	entry->vme_alias = alias;
}

static inline void
VME_OBJECT_SHADOW(
	vm_map_entry_t entry,
	vm_object_size_t length,
	bool always)
{
	vm_object_t object;
	vm_object_offset_t offset;

	VM_ENTRY_ASSERT_FIELDS_WRITABLE(entry);

	object = VME_OBJECT(entry);
	offset = VME_OFFSET(entry);
	vm_object_shadow(&object, &offset, length, always);
	if (object != VME_OBJECT(entry)) {
		entry->vme_object_or_delta = VM_OBJECT_PACK(object);
		entry->use_pmap = true;
	}
	if (offset != VME_OFFSET(entry)) {
		VME_OFFSET_SET(entry, offset);
	}
}

extern vm_tag_t vmtaglog_tag; /* Collected from a tunable in vm_resident.c */

static inline bool
vmtaglog_matches(vm_tag_t tag)
{
	switch (vmtaglog_tag) {
	case VM_KERN_MEMORY_NONE:
		return false;
	case VM_KERN_MEMORY_FIRST_DYNAMIC:
		return tag >= VM_KERN_MEMORY_FIRST_DYNAMIC;
	case VM_KERN_MEMORY_ANY:
		return tag != VM_KERN_MEMORY_NONE;
	default:
		return tag == vmtaglog_tag;
	}
}

static inline void
vme_btref_consider_and_set(__unused vm_map_entry_t entry, __unused void *fp)
{
#if VM_BTLOG_TAGS
	if (vmtaglog_matches(VME_ALIAS(entry)) && entry->vme_kernel_object && entry->wired_count) {
		assert(!entry->vme_tag_btref); /* We should have already zeroed and freed the btref if we're here. */
		entry->vme_tag_btref = btref_get(fp, BTREF_GET_NOWAIT);
	}
#endif /* VM_BTLOG_TAGS */
}

static inline void
vme_btref_consider_and_put(__unused vm_map_entry_t entry)
{
#if VM_BTLOG_TAGS
	if (entry->vme_tag_btref && entry->vme_kernel_object && (entry->wired_count == 0) && (entry->user_wired_count == 0)) {
		btref_put(entry->vme_tag_btref);
		entry->vme_tag_btref = 0;
	}
#endif /* VM_BTLOG_TAGS */
}

extern kern_return_t vm_map_copy_adjust_to_target(
	vm_map_copy_t           copy_map,
	vm_map_offset_ut        offset,
	vm_map_size_ut          size,
	vm_map_t                target_map,
	boolean_t               copy,
	vm_map_copy_t           *target_copy_map_p,
	vm_map_offset_t         *overmap_start_p,
	vm_map_offset_t         *overmap_end_p,
	vm_map_offset_t         *trimmed_start_p);

int vm_self_region_page_shift(vm_map_t target_map);
int vm_self_region_page_shift_safely(vm_map_t target_map);

#if __arm64__
extern kern_return_t    vm_map_enter_fourk(
	vm_map_t                map,
	vm_map_offset_t         *address,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_object_t             object,
	vm_object_offset_t      offset,
	boolean_t               needs_copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);
#endif /* __arm64__ */

/* Enter a mapping */
extern kern_return_t    vm_map_enter(
	vm_map_t                map,
	vm_map_offset_t        *address,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_object_t             object,
	vm_object_offset_t      offset,
	boolean_t               needs_copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);


/* Enter a mapping of a memory object */
extern kern_return_t    vm_map_enter_mem_object(
	vm_map_t                map,
	vm_map_offset_ut       *address,
	vm_map_size_ut          size,
	vm_map_offset_ut        mask,
	vm_map_kernel_flags_t   vmk_flags,
	ipc_port_t              port,
	vm_object_offset_ut     offset,
	boolean_t               needs_copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance,
	upl_page_list_ptr_t     page_list,
	unsigned int            page_list_count);

extern kern_return_t    vm_map_remap(
	vm_map_t                target_map,
	vm_map_offset_ut       *address,
	vm_map_size_ut          size,
	vm_map_offset_ut        mask,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_t                src_map,
	vm_map_offset_ut        memory_address,
	boolean_t               copy,
	vm_prot_ut              *cur_protection,
	vm_prot_ut              *max_protection,
	vm_inherit_ut           inheritance);

extern kern_return_t    vm_map_reallocate(
	vm_map_t                map,
	vm_map_address_ut       src,
	vm_map_size_ut          src_size,
	vm_map_address_ut      *dst_inout,
	vm_map_size_ut          dst_size,
	vm_map_offset_ut        align_mask,
	int                     options,
	int                     flags);

extern kern_return_t    vm_map_relocate(
	vm_map_t                map,
	vm_map_address_t        src,
	vm_map_size_t           src_size,
	vm_map_address_t       *dst_inout,
	vm_map_size_t           dst_size,
	vm_map_offset_t         align_mask,
	int                     options,
	vm_map_kernel_flags_t   flags);


/* Add or remove machine-dependent attributes from map regions */
extern kern_return_t    vm_map_machine_attribute(
	vm_map_t                map,
	vm_map_offset_ut        start,
	vm_map_offset_ut        end,
	vm_machine_attribute_t  attribute,
	vm_machine_attribute_val_t *value); /* IN/OUT */

extern kern_return_t    vm_map_msync(
	vm_map_t                map,
	vm_map_address_ut       address,
	vm_map_size_ut          size,
	vm_sync_t               sync_flags);

/* Set paging behavior */
extern kern_return_t    vm_map_behavior_set(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_behavior_t           new_behavior);

/*!
 * @abstract
 * Helper for vm_map_region() to resolve either an entry or a fake guard object
 * hole.
 *
 * @discussion
 * @c vm_map_region_resolve_done() must be called once when done.
 */
extern vm_map_entry_t vm_map_region_resolve_entry(
	vm_map_lock_ctx_t       ctx,
	vm_map_t               *mapp,
	vm_map_address_t        start,
	uint32_t                flags, /* vmrl_sh_flags_t */
	vm_map_entry_t          fake_entry,
	kern_return_t          *kr_out);

/*!
 * @abstract
 * Function to be called for each call to vm_map_region_resolve_entry(),
 * once the caller is done with the returned entry.
 */
extern void vm_map_region_resolve_done(
	vm_map_lock_ctx_t        ctx,
	vm_map_t                *mapp,
	kern_return_t            kr);

extern kern_return_t vm_map_region(
	vm_map_t                 map,
	vm_map_offset_ut        *address,
	vm_map_size_ut          *size,
	vm_region_flavor_t       flavor,
	vm_region_info_t         info,
	mach_msg_type_number_t  *count,
	mach_port_t             *object_name);

extern kern_return_t vm_map_region_recurse_64(
	vm_map_t                 map,
	vm_map_offset_ut        *address,
	vm_map_size_ut          *size,
	natural_t               *nesting_depth,
	vm_region_submap_info_64_t info,
	mach_msg_type_number_t  *count);

/* definitions related to overriding the NX behavior */

extern int override_nx(vm_map_t map, uint32_t user_tag);

extern void vm_map_region_top_walk(
	vm_map_entry_t entry,
	vm_region_top_info_t top);

extern void vm_map_region_walk(
	vm_map_t                        map,
	vm_map_offset_t                 va,
	vm_map_entry_t                  entry,
	vm_object_offset_t              offset,
	vm_object_size_t                range,
	vm_region_extended_info_t       extended,
	boolean_t                       look_for_pages,
	mach_msg_type_number_t count);

extern void vm_map_copy_ledger(
	task_t  old_task,
	task_t  new_task,
	int     ledger_entry);

#endif /* MACH_KERNEL_PRIVATE */

__options_decl(vm_map_destroy_options_t, uint8_t, {
	VM_MAP_DESTROY_DEFAULT                  = 0x0,
#if DEVELOPMENT || DEBUG
	VM_MAP_DESTROY_ALLOW_TRANSPARENT_SUBMAP = 1 << 0,
#endif /* DEVELOPMENT || DEBUG */
});

extern void             vm_map_destroy_options(
	vm_map_t                 map,
	vm_map_destroy_options_t options);

/* Get rid of a map */
extern void             vm_map_destroy(
	vm_map_t                map);

extern void             vm_map_require(
	vm_map_t                map);

extern void             vm_map_copy_require(
	vm_map_copy_t           copy);

#if HAS_MTE
__options_closed_decl(vm_mte_operation_flags_t, uint32_t, {
	/* all operations must have exactly one of these: */
	VM_MTE_OPERATION_TYPE_COPY = 0x1,
	VM_MTE_OPERATION_TYPE_SHARE = 0x2,
	VM_MTE_OPERATION_TYPE_INHERIT_SHARE = 0x4,
	VM_MTE_OPERATION_TYPE_CREATE_UPL = 0x8,
	VM_MTE_OPERATION_TYPE_MASK = VM_MTE_OPERATION_TYPE_COPY | VM_MTE_OPERATION_TYPE_SHARE | VM_MTE_OPERATION_TYPE_INHERIT_SHARE | VM_MTE_OPERATION_TYPE_CREATE_UPL,

	/* all operations except CREATE_UPL require exactly one of these: */
	VM_MTE_OPERATION_DEST_USER = 0x10,
	VM_MTE_OPERATION_DEST_KERNEL = 0x20,
	VM_MTE_OPERATION_DEST_UNKNOWN = 0x40,
	VM_MTE_OPERATION_DEST_INTERNAL = 0x80,
	VM_MTE_OPERATION_DEST_MASK = VM_MTE_OPERATION_DEST_USER | VM_MTE_OPERATION_DEST_KERNEL | VM_MTE_OPERATION_DEST_UNKNOWN | VM_MTE_OPERATION_DEST_INTERNAL,

	/* these flags can be additionally added to any of the above: */
	VM_MTE_OPERATION_IOKIT = 0x100, /* don't throw guard exceptions; IOKit will handle errors */
	VM_MTE_OPERATION_FORK = 0x200, /* apply policies for fork() instead of generic userspace policies */
	VM_MTE_OPERATION_REMAP_EXTRACT = 0x400, /* apply policies for vm_map_remap_extract() */
	VM_MTE_OPERATION_MAKE_MEMORY_ENTRY = 0x800 /* apply policies for mach_make_memory_entry() */
});

__options_closed_decl(option_variant_t, uint8_t, {
	OPTIONAL_NONE,
	OPTIONAL_SOME,
});

#define OPTIONAL_IS_NONE(var) ((var).discriminant == OPTIONAL_NONE)
#define OPTIONAL_IS_SOME(var) ((var).discriminant == OPTIONAL_SOME)

#define DEFINE_OPTIONAL_TYPE(name, T) \
	typedef struct option {\
	        option_variant_t discriminant;\
	        T payload;\
	} optional_##name##_t;\
\
	static inline optional_##name##_t optional_##name##_none(void) {\
	return (optional_##name##_t){\
	                .discriminant = OPTIONAL_NONE,\
	                .payload = NULL,\
	        };\
    }\
\
	static inline optional_##name##_t optional_##name##_some(T payload) {\
	return (optional_##name##_t){\
	                .discriminant = OPTIONAL_SOME,\
	                .payload = payload,\
	        };\
    }\
\
	static inline T optional_##name##_expect(optional_##name##_t optional, const char* message) {\
	        if (!OPTIONAL_IS_SOME(optional)) {\
	                panic("EXPECT(##name##) failed: %s", message);\
	        }\
	        return optional.payload;\
	}\
\
	static inline T optional_##name##_unwrap(optional_##name##_t optional) {\
	                return optional_##name##_expect(optional, "Unwrapped a None ##name##");\
	}


DEFINE_OPTIONAL_TYPE(vm_object, vm_object_t);


/*
 * Since these macro are used in expression contexts, it's not easy to
 * drop in an assertion when an unsupported type is passed in. However, the
 * default error message is pretty clear.
 */
#define OPTIONAL_NONE(var) _Generic((var),\
    vm_object_t:  optional_vm_object_none((var))\
)

#define OPTIONAL_SOME(var) _Generic((var),\
	vm_object_t:  optional_vm_object_some((var))\
)

#define OPTIONAL_UNWRAP(var) _Generic((var),\
	optional_vm_object_t:  optional_vm_object_unwrap((var))\
)

#define OPTIONAL_EXPECT(var, msg) _Generic((var),\
	optional_vm_object_t:  optional_vm_object_expect((var), (msg))\
)

bool vm_map_allow_mte_operation(vm_map_t source_map, vm_map_offset_t addr, vm_size_t size, vm_mte_operation_flags_t flags,
    optional_vm_object_t maybe_source_vm_object);
#endif /* HAS_MTE */

extern kern_return_t    vm_map_copy_extract(
	vm_map_t                src_map,
	vm_map_address_t        src_addr,
	vm_map_size_t           len,
	boolean_t               copy,
	vm_map_copy_t           *copy_result,   /* OUT */
	vm_prot_t               *cur_prot,      /* OUT */
	vm_prot_t               *max_prot,      /* OUT */
	vm_inherit_t            inheritance,
	vm_map_kernel_flags_t   vmk_flags);

#define VM_MAP_COPYIN_SRC_DESTROY        0x00000001
#define VM_MAP_COPYIN_USE_MAXPROT        0x00000002
#define VM_MAP_COPYIN_ENTRY_LIST         0x00000004
#define VM_MAP_COPYIN_PRESERVE_PURGEABLE 0x00000008
#define VM_MAP_COPYIN_FORK               0x00000010
#if HAS_MTE
#define VM_MAP_COPYIN_IOKIT                  0x00000020
#define VM_MAP_COPYIN_DEST_USER              0x00000040
#define VM_MAP_COPYIN_DEST_KERNEL            0x00000080
#define VM_MAP_COPYIN_DEST_UNKNOWN           0x00000100
#define VM_MAP_COPYIN_ALL_FLAGS              0x000001FF
#else /* !HAS_MTE */
#define VM_MAP_COPYIN_ALL_FLAGS              0x0000001F
#endif /* HAS_MTE */

extern kern_return_t    vm_map_copyin_internal(
	vm_map_t                src_map,
	vm_map_address_ut       src_addr_u,
	vm_map_size_ut          len_u,
	int                     flags,
	vm_map_copy_t          *copy_result);   /* OUT */

extern boolean_t        vm_map_tpro_enforcement(
	vm_map_t                map);

extern void vm_map_iokit_mapped_region(
	vm_map_t                map,
	vm_size_t               bytes);

extern void vm_map_iokit_unmapped_region(
	vm_map_t                map,
	vm_size_t               bytes);

extern void             vm_map_range_fork(
	vm_map_t                new_map,
	vm_map_t                old_map);

extern int              vm_map_get_user_range(
	vm_map_t                map,
	vm_map_range_id_t       range_id,
	mach_vm_range_t         range);


#ifdef MACH_KERNEL_PRIVATE

static inline bool
VM_MAP_IS_EXOTIC(
	vm_map_t map __unused)
{
#if __arm64__
	if (pmap_is_exotic(map->pmap)) {
		return true;
	}
#endif /* __arm64__ */
	return false;
}

static inline bool
VM_MAP_IS_ALIEN(
	vm_map_t map __unused)
{
	/*
	 * An "alien" process/task/map/pmap should mostly behave
	 * as it currently would on iOS.
	 */
#if XNU_TARGET_OS_OSX
	if (map->is_alien) {
		return true;
	}
	return false;
#else /* XNU_TARGET_OS_OSX */
	return true;
#endif /* XNU_TARGET_OS_OSX */
}

static inline bool
VM_MAP_POLICY_WX_FAIL(
	vm_map_t map __unused)
{
	if (VM_MAP_IS_ALIEN(map)) {
		return false;
	}
	return true;
}

static inline bool
VM_MAP_POLICY_WX_STRIP_X(
	vm_map_t map __unused)
{
	if (VM_MAP_IS_ALIEN(map)) {
		return true;
	}
	return false;
}

static inline bool
VM_MAP_POLICY_ALLOW_MULTIPLE_JIT(
	vm_map_t map __unused)
{
	if (VM_MAP_IS_ALIEN(map) || map->single_jit) {
		return false;
	}
	return true;
}

static inline bool
VM_MAP_POLICY_ALLOW_JIT_RANDOM_ADDRESS(
	vm_map_t map)
{
	return VM_MAP_IS_ALIEN(map);
}

static inline bool
VM_MAP_POLICY_ALLOW_JIT_INHERIT(
	vm_map_t map __unused)
{
	if (VM_MAP_IS_ALIEN(map)) {
		return false;
	}
	return true;
}

static inline bool
VM_MAP_POLICY_ALLOW_JIT_SHARING(
	vm_map_t map __unused)
{
	if (VM_MAP_IS_ALIEN(map)) {
		return false;
	}
	return true;
}

static inline bool
VM_MAP_POLICY_ALLOW_JIT_COPY(
	vm_map_t map __unused)
{
	if (VM_MAP_IS_ALIEN(map)) {
		return false;
	}
	return true;
}

static inline bool
VM_MAP_POLICY_WRITABLE_SHARED_REGION(
	vm_map_t map __unused)
{
#if __x86_64__
	return true;
#else /* __x86_64__ */
	if (VM_MAP_IS_EXOTIC(map)) {
		return true;
	}
	return false;
#endif /* __x86_64__ */
}

static inline void
vm_prot_to_wimg(unsigned int prot, uint8_t *wimg)
{
	switch (prot) {
	case MAP_MEM_NOOP:                      break;
	case MAP_MEM_IO:                        *wimg = VM_WIMG_IO; break;
	case MAP_MEM_COPYBACK:                  *wimg = VM_WIMG_USE_DEFAULT; break;
	case MAP_MEM_INNERWBACK:                *wimg = VM_WIMG_INNERWBACK; break;
	case MAP_MEM_POSTED:                    *wimg = VM_WIMG_POSTED; break;
	case MAP_MEM_POSTED_REORDERED:          *wimg = VM_WIMG_POSTED_REORDERED; break;
	case MAP_MEM_POSTED_COMBINED_REORDERED: *wimg = VM_WIMG_POSTED_COMBINED_REORDERED; break;
	case MAP_MEM_WTHRU:                     *wimg = VM_WIMG_WTHRU; break;
	case MAP_MEM_WCOMB:                     *wimg = VM_WIMG_WCOMB; break;
	case MAP_MEM_RT:                        *wimg = VM_WIMG_RT; break;
	default:                                break;
	}
}

static inline boolean_t
vm_map_always_shadow(vm_map_t map)
{
	if (map->mapped_in_other_pmaps) {
		/*
		 * This is a submap, mapped in other maps.
		 * Even if a VM object is mapped only once in this submap,
		 * the submap itself could be mapped multiple times,
		 * so vm_object_shadow() should always create a shadow
		 * object, even if the object has only 1 reference.
		 */
		return TRUE;
	}
	return FALSE;
}

extern void
vm_map_sizes(vm_map_t map,
    vm_map_size_t * psize,
    vm_map_size_t * pfree,
    vm_map_size_t * plargest_free);

extern void vm_map_guard_exception(
	vm_map_t                map,
	vm_map_offset_t         address,
	unsigned                reason);

extern void vm_map_synthesize_guard_exception(
	vm_map_t                map,
	thread_t                thread);


/* See the impl for comments on the function */
bool
vm_map_copy_overwrite_can_page_copy(
	vm_map_t map,
	vm_map_entry_t entry,
	vm_object_offset_t offset,
	vm_page_t old_page,
	vm_object_t old_copy_object,
	uint64_t old_copy_version);

/* see comment for this function in vm_map.c */
vm_object_t
vm_map_stabilize_object_for_share(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t entry,
	bool is_mapped_entry,
	bool apply_upl_optimization);

/*
 * Return if we should shadow the object before we change the copy_strategy from
 * COPY_SYMMETRIC to COPY_DELAY.
 */
extern bool
vm_map_should_shadow_to_change_copy_strategy(
	vm_map_lock_ctx_t ctx,
	vm_map_entry_t src_entry,
	bool apply_upl_optimization);

#endif /* MACH_KERNEL_PRIVATE */

extern void
vm_map_set_lock_contention_debug(vm_map_t map, bool enable);

__END_DECLS

#endif  /* _VM_VM_MAP_INTERNAL_H_ */
