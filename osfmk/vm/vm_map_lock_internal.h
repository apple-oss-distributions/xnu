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
#ifndef _VM_VM_MAP_LOCK_H_
#define _VM_VM_MAP_LOCK_H_

#include <stdbool.h>
#include <kern/locks.h>
#include <kern/lock_mtx.h>
#include <vm/vm_map_internal.h>

__BEGIN_DECLS


#if DEVELOPMENT || DEBUG
#define RANGE_LOCK_DEBUG
#endif /* DEVELOPMENT || DEBUG */

#ifdef RANGE_LOCK_DEBUG
#define RANGE_LOCK_ASSERT(cond) assert(cond)
#else
#define RANGE_LOCK_ASSERT(cond)
#endif

#define err_vm_map_lock(e)              (err_vm | err_sub(2) | (e))
/*! denote in a preflight hook that this entry shouldn't be prepared */
#define VMRL_ERR_SKIP_PREPARE           err_vm_map_lock(1)
/*! denote in a preflight hook that the caller wants to wait for unwire */
#define VMRL_ERR_WAIT_FOR_KUNWIRE       err_vm_map_lock(2)
/*! denote in a preflight hook that the caller wants symmetric COW setup */
#define VMRL_ERR_SETUP_SYMMETRIC_COW    err_vm_map_lock(3)
/*! same as VMRL_ERR_SETUP_SYMMETRIC_COW, but the entry on which COW is setup is not clipped */
#define VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP   err_vm_map_lock(4)
/*! denote in a preflight hook that the entry is going to be shared with another map */
#define VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP   err_vm_map_lock(5)
/*! denote in a preflight hook that the entry is going to be shared,
 * that we can clip, and that we should apply UPL optimizations */
#define VMRL_ERR_PREPARE_FOR_SHARE_WITH_UPL   err_vm_map_lock(6)
/*! denote from the lock that a try_lock failed because a lock was already held */
#define VMRL_ERR_LOCK_ALREADY_HELD      err_vm_map_lock(7)


/*
 * Explanation of the two types of submaps:
 * There are two types of submaps supported by the VM today.
 * For both types, nested submaps are disallowed, which means that a submap cannot
 * have an entry that is a submap itself.
 *
 * 1) constant submaps
 * Constant submaps are submaps that have static vm_map_entry_t's.
 * That means once "sealed", there is a guarantee that no vm_map_entry_t in that
 * submap will change in any way. This means no locks need to be held on constant submaps.
 * When descending into a constant submap, address transformation is required
 * (see vm_map_parent_address_to_submap_address).
 * Today's examples of these are the shared cache and the x86 commpage.
 *
 * 2) transparent submaps
 * Transparent submaps are submaps created by kmem_suballoc(). They are mapped
 * only in the kernel_map and use the kernel_pmap. Transparent submaps cannot be
 * mapped in multiple entries. They are guaranteed to have VME_OFFSET(entry) == entry->vme_start
 * for the submap entry, which means there is no address transformation required when descending
 * into them (e.g. address A in a parent map is also address A in the submap). That, combined
 * with the automatic descension by the VM into transparent submaps
 * justify the name "transparent" (they are transparent to clients and the VM).
 * An entry mapping a transparent submap must be atomic and permanent.
 * examples include the ipc_kernel_map submap and the compressor submap
 *
 * The range lock does not permit being called directly on a constant submap
 * once it has been sealed, as it does not lock constant submap entries.
 * Transparent submaps are allowed.
 */


#if MACH_ASSERT

/*
 * Debugging validation of a map when its interlock is locked or unlocked.
 * These checks exist in development builds only.
 * Fast checks (always on) go in the inline functions.
 * Slow checks (enabled by boot-arg) go in the extern functions.
 * We also check mach_assert_enabled() to allow static_if to optimize
 * these fast paths.
 */

extern bool vm_debug_any_options_enabled;

static inline OS_ALWAYS_INLINE void
vm_map_debug_after_lock_fast(vm_map_t map)
{
	if (mach_assert_enabled() && vm_debug_any_options_enabled) {
		(void)map;
	}
}

static inline OS_ALWAYS_INLINE void
vm_map_debug_before_unlock_fast(vm_map_t map)
{
	if (mach_assert_enabled() && vm_debug_any_options_enabled) {
		(void)map;
	}
}

#else  /* not MACH_ASSERT */

#define vm_map_debug_after_lock_fast(map) ({})
#define vm_map_debug_before_unlock_fast(map) ({})

#endif /* not MACH_ASSERT */

#ifndef VM_MAP_LOCK_PRIVATE

/*!
 * @function vm_map_ilk_lock()
 *
 * @brief
 * Takes the interlock of the specified map.
 *
 * @discussion
 * The interlock protects non-atomic variables on the vm_map_t such as
 * the rb-tree or map->size
 */
static inline void
vm_map_ilk_lock(vm_map_t map)
{
	assert(!vm_map_is_sealed(map));
	lck_rw_lock_exclusive(&map->ilock);
	vm_map_debug_after_lock_fast(map);
}

/*!
 * @function vm_map_ilk_unlock()
 *
 * @brief
 * Drops the interlock of the specified map.
 */
static inline void
vm_map_ilk_unlock(vm_map_t map)
{
	assert(!vm_map_is_sealed(map));
	vm_map_debug_before_unlock_fast(map);
	lck_rw_unlock_exclusive(&map->ilock);
}

/*!
 * @function vm_map_ilk_lock_shared()
 *
 * @brief
 * Takes the interlock of the specified map in shared mode.
 *
 * @discussion
 * The interlock protects non-atomic variables on the vm_map_t such as
 * the rb-tree or map->size
 */
static inline void
vm_map_ilk_lock_shared(vm_map_t map)
{
	assert(!vm_map_is_sealed(map));
	lck_rw_lock_shared(&map->ilock);
}

/*!
 * @function vm_map_ilk_unlock_shared()
 *
 * @brief
 * Drops the interlock of the specified map.
 */
static inline void
vm_map_ilk_unlock_shared(vm_map_t map)
{
	assert(!vm_map_is_sealed(map));
	lck_rw_unlock_shared(&map->ilock);
}

/*!
 * @function vm_map_ilk_lock_allow_sealed()
 *
 * @brief
 * Takes the interlock of the specified map, allowed on sealed maps.
 *
 * @discussion
 * This is the same as @c vm_map_ilk_lock(), but allows for sealed maps,
 * which is useful to handle sealing/unsealing transitions.
 */
static inline void
vm_map_ilk_lock_allow_sealed(vm_map_t map)
{
	lck_rw_lock_exclusive(&map->ilock);
	vm_map_debug_after_lock_fast(map);
}

/*!
 * @function vm_map_ilk_unlock_allow_sealed()
 *
 * @brief
 * Drops the interlock of the specified map, allowed on sealed maps.
 *
 * @discussion
 * This is the same as @c vm_map_ilk_unlock(), but allows for sealed maps,
 * which is useful to handle sealing/unsealing transitions.
 */
static inline void
vm_map_ilk_unlock_allow_sealed(vm_map_t map)
{
	vm_map_debug_before_unlock_fast(map);
	lck_rw_unlock_exclusive(&map->ilock);
}

/*!
 * @function vm_map_ilk_sleep()
 *
 * @brief
 * Sleep while releasing the map interlock, waiting for a wakeup on an event.
 * Upon return, the map interlock is held again.
 */
static inline wait_result_t
vm_map_ilk_sleep(vm_map_t map, event_t event, wait_interrupt_t interruptible)
{
	wait_result_t wr;
	vm_map_debug_before_unlock_fast(map);
	wr = lck_rw_sleep(&map->ilock, LCK_SLEEP_DEFAULT,
	    event, interruptible);
	vm_map_debug_after_lock_fast(map);
	return wr;
}

static inline void
assert_vm_map_ilk_owned(vm_map_t map, lck_rw_type_t how)
{
	(void) map;
	if (lck_rw_assert_enabled()) {
		lck_rw_assert_held_type(&map->ilock, how);
	}
}

static inline void
assert_vm_map_ilk_not_owned(vm_map_t map __assert_only)
{
	LCK_RW_ASSERT(&map->ilock, LCK_RW_ASSERT_NOT_OWNED);
}

#else /* !VM_MAP_LOCK_PRIVATE */

/* Internal errors to the vm map/entry locks */
#define VMRL_ERR_RELOOKUP               err_vm_map_lock(0x101)
#define VMRL_ERR_ABORTED                err_vm_map_lock(0x102)
#define VMRL_ERR_NOT_FOUND              err_vm_map_lock(0x103)

#endif /* !VM_MAP_LOCK_PRIVATE */

static inline void
assert_vm_map_ilk_owned_ignore_sealed(vm_map_t map, lck_rw_type_t how)
{
	if (!vm_map_is_sealed_or_will_be_sealed(map) && lck_rw_assert_enabled()) {
		lck_rw_assert_held_type(&map->ilock, how);
	}
}

/*!
 * @function vm_map_has_entry_at_address_ilocked()
 *
 * @brief
 * Checks whether an entry is present in the provided map at the provided
 * address. Should be called with the interlock held, returns with the
 * interlock held. Doesn't drop the interlock.
 */
static inline bool
vm_map_has_entry_at_address_ilocked(
	vm_map_t                map,
	vm_map_offset_t         addr)
{
	return vm_map_lookup(map, addr) != VM_MAP_ENTRY_NULL;
}

/*!
 * @typedef vmrl_flags_t
 *
 * @brief
 * Flags affecting the behavior of acquiring a range lock.
 *
 *
 * <h1>locking mode, exactly one must be selected</h1>
 *
 * @const VMRL_STREAM (ex, sh)
 * For cases where we want to allow holes (for example: vm_map_inherit(),
 * vm_map_delete() when used for termination, and most uses of shared locking),
 * make the lock stream rather than lock the whole range. This means
 * the lock's behavior is not atomic and instead the next entry is locked
 * on advancing entries.
 *
 * Note that when streaming there is no guarantee that entries being returned
 * move "forward" without overlaps as concurrent mutations of the map might
 * cause coalescing concurrently. As a result it is important to query the
 * bounds to apply to the returned entry in code handling entries using
 * @c vm_map_lock_ctx_bounds() or similar.
 *
 * @const VMRL_STREAM_NO_HOLES (ex, sh)
 * Similar to VMRL_STREAM, however, when a hole has been detected,
 * the iteration will fail with KERN_INVALID_ADDRESS.
 *
 * @const VMRL_ATOMIC (ex, sh)
 * Denotes an atomic (i.e. non-streaming) lock. The whole range will be held
 * locked for the entire duration of the operation (from lock to unlock) and
 * holes will not be allowed (attempting to lock a range with holes will return
 * an error).
 *
 * @const VMRL_ATOMIC_ALLOW_HOLES (ex)
 * Similar to @c VMRL_ATOMIC but allows for holes by inserting sentinel entries
 * to denote locked holes.
 *
 * They will be returned during iteration as placeholders that clients must
 * ignore, however.
 *
 * This should only be used to implement fixed overwrite mappings in the context
 * of enter/delete. Other APIs should stream or use VMRL_ATOMIC. This is because
 * sentinel entries take up space that is not available for other allocations,
 * which could potentially cause them to fail spuriously.
 *
 *
 * <h1>shared/exclusive locking, exactly one must be selected</h1>
 *
 * Note that this flag is selected implicitly via the usage of @c VMRL_EX_*
 * versus @c VMRL_SH_* namespaced flags.
 *
 * @const VMRL_SHARED (implicit: sh)
 * Denotes a shared lock.
 *
 * @const VMRL_EXCLUSIVE (implicit: ex)
 * Denotes an exclusive lock.
 *
 *
 * <h1>Entry preparation<h1>
 *
 * @const VMRL_VMO_ALLOCATE (sh)
 * Allocate a vm object if VME_OBJECT(entry) == NULL. Do not resolve CoW.
 *
 * @const VMRL_RESOLVE_COW_AND_OBJ
 * Resolve the vm_object or submap of each entry, which means for
 * 1) entries with a NULL object: allocate one.
 * 2) entries with needs_copy=true: resolve object level or submap level CoW.
 *
 * Clients of the range lock will be given an entry with needs_copy=false and
 * an object or submap associated.
 * This will do pmap unnesting if a submap needs to be resolved. For resolving
 * submap CoW, it essentially copies the submap entries into the top level map
 * and creates a shadow object.
 * For object CoW, it just creates a shadow object.
 *
 * @const VMRL_NO_PMAP_UNNEST (ex)
 * Do not unecessarily pmap unnest any submap entries within the range lock.
 * Those entries will still be pmap_unnested if a clip would need to be performed.
 *
 * <h1>Behavior modifiers<h1>
 *
 * @const VMRL_NO_MIN_MAX_CHECK (ex, sh)
 * Allow the range to go beyond the map [min_offset, max_offset).
 * Without this flag, locks will fail with KERN_INVALID_ADDRESS
 * if the requested range goes beyond this range.
 * This should not be used with VMRL_WHOLE_MAP since they mean similar things.
 *
 * @const VMRL_WHOLE_MAP (ex, sh)
 * Lock the entire virtual address range, including entries beyond
 * [min_offset, max_offset).
 * start and end of the lock must be set to VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END
 * This should not be used with VMRL_NO_MIN_MAX_CHECK since they mean similar things.
 *
 * @const VMRL_SIMPLIFY (ex)
 * Whether entry coalescing/simplification should be attempted.
 * This happens at unlock time for ATOMIC locks and advance or drop time for
 * STREAM locks.
 *
 * @const VMRL_INTERRUPTIBLE (ex, sh)
 * Whether waiting for a lock is interruptible. When interrupted,
 * the lock acquiring or enumeration will fail with KERN_ABORTED.
 *
 * @const VMRL_ILK_LOCKED (ex, sh)
 * Whether the interlock of the map is held at the time
 * of lock acquisition, functions will always return with
 * it unlocked.
 *
 * @const VMRL_TRY_LOCK_ENTRY (ex,sh)
 * Do a vm_entry_try_lock_* on the entry rather than a sleepable lock. If the entry
 * lock being acquired is already held (the trylock failed), VMRL_ERR_LOCK_ALREADY_HELD
 * is returned instead.
 *
 * @const VMRL_SH_NO_DESCEND_TRANSPARENT (sh streaming only)
 * Do not descend into transparent submaps. This may be useful for APIs
 * specifically wanting to examine the structure of the address space in the
 * kernel_map.
 *
 * @const VMRL_DESCEND_INTO_CONSTANT (ex, sh)
 * Whether iteration descends into constant submaps.
 * Descension into transparent submaps happens by default.
 * Exclusive locks:
 *   - Can be made to descend into constant submap by passing
 *     VMRL_EX_DESCEND_INTO_CONSTANT. Even though this an exclusive lock, there
 *     are actually no locks taken in constant submaps. When descended into a
 *     constant submap, the caller must not modify entries.
 * Shared locks:
 *   - Can be made to descend into constant submaps by passing
 *     VMRL_SH_DESCEND_INTO_CONSTANT
 */
__options_decl(vmrl_flags_t, uint32_t, {
	/* enumeration mode */
	_VMRL_NO_HOLES                = 0x00000001,
	_VMRL_ALLOW_HOLES             = 0x00000002,
	_VMRL_STREAM_INTERNAL         = 0x00000004,
	_VMRL_ATOMIC_INTERNAL         = 0x00000008,
	_VMRL_MODE_MASK               = 0x0000000f,

	VMRL_INVALID                  = 0x00000000,
	VMRL_STREAM                   = _VMRL_STREAM_INTERNAL | _VMRL_ALLOW_HOLES,
	VMRL_STREAM_NO_HOLES          = _VMRL_STREAM_INTERNAL | _VMRL_NO_HOLES,
	VMRL_ATOMIC                   = _VMRL_ATOMIC_INTERNAL | _VMRL_NO_HOLES,
	VMRL_ATOMIC_ALLOW_HOLES       = _VMRL_ATOMIC_INTERNAL | _VMRL_ALLOW_HOLES,

	/* exclusive / shared */
	VMRL_SHARED                   = 0x00000010,
	VMRL_EXCLUSIVE                = 0x00000020,

	/* entry stabilization */
	VMRL_RESOLVE_COW_AND_OBJ      = 0x00000040,
	VMRL_VMO_ALLOCATE             = 0x00000080,
	VMRL_NO_PMAP_UNNEST           = 0x00000100,

	/* other flags */
	VMRL_WHOLE_MAP                = 0x00001000,
	VMRL_NO_MIN_MAX_CHECK         = 0x00002000,
	VMRL_SIMPLIFY                 = 0x00004000,
	VMRL_INTERRUPTIBLE            = 0x00008000,
	VMRL_ILK_LOCKED               = 0x00010000,
	VMRL_TRY_LOCK_ENTRY           = 0x00020000,
	VMRL_NO_DESCEND_TRANSPARENT   = 0x00040000,
	VMRL_DESCEND_INTO_CONSTANT    = 0x00080000,

	/*
	 * internal flags set by the implementation only
	 * for the duration of a function call and never persisted.
	 */
	_VMRL_SETUP_COW                = 0x01000000,
	_VMRL_SETUP_COW_NOCLIP         = 0x02000000,
	_VMRL_PREPARE_FOR_SHARE_NOCLIP = 0x04000000,
	_VMRL_PREPARE_FOR_SHARE_WITH_UPL = 0x08000000,

	/* internal flags set by the implementation only */
	_VMRL_SINGLE_ENTRY            = 0x40000000,
	_VMRL_KERNEL_PMAP             = 0x80000000,
});

/*!
 * @typedef vmrl_ex_flags_t
 *
 * @brief
 * Flags affecting the behavior of acquiring an exclusive range lock.
 *
 * @discussion
 * The minimal behavior for the exclusive range lock is to:
 * - clip entries within the [start, end) range being asked,
 * - pmap unnest said entries if necessary.
 */
__options_decl(vmrl_ex_flags_t, uint32_t, {
	/* enumeration mode */
	VMRL_EX_STREAM                = VMRL_EXCLUSIVE | VMRL_STREAM,
	VMRL_EX_STREAM_NO_HOLES       = VMRL_EXCLUSIVE | VMRL_STREAM_NO_HOLES,
	VMRL_EX_ATOMIC                = VMRL_EXCLUSIVE | VMRL_ATOMIC,
	VMRL_EX_ATOMIC_ALLOW_HOLES    = VMRL_EXCLUSIVE | VMRL_ATOMIC_ALLOW_HOLES,

	/* entry stabilization */
	VMRL_EX_RESOLVE_COW_AND_OBJ   = VMRL_RESOLVE_COW_AND_OBJ,
	VMRL_EX_NO_PMAP_UNNEST        = VMRL_NO_PMAP_UNNEST,

	/* other flags */
	VMRL_EX_WHOLE_MAP             = VMRL_WHOLE_MAP,
	VMRL_EX_NO_MIN_MAX_CHECK      = VMRL_NO_MIN_MAX_CHECK,
	VMRL_EX_SIMPLIFY              = VMRL_SIMPLIFY,
	VMRL_EX_INTERRUPTIBLE         = VMRL_INTERRUPTIBLE,
	VMRL_EX_ILK_LOCKED            = VMRL_ILK_LOCKED,
	VMRL_EX_TRY_LOCK_ENTRY        = VMRL_TRY_LOCK_ENTRY,
	VMRL_EX_DESCEND_INTO_CONSTANT = VMRL_DESCEND_INTO_CONSTANT,
});

/*!
 * @typedef vmrl_sh_flags_t
 *
 * @brief
 * Flags affecting the behavior of acquiring a shared range lock.
 *
 * @discussion
 * The default behavior for the shared range lock is to be streaming,
 * (however that isn't true for a downgraded exclusive lock).
 */
__options_decl(vmrl_sh_flags_t, uint32_t, {
	/* enumeration mode */
	VMRL_SH_STREAM                 = VMRL_SHARED | VMRL_STREAM,
	VMRL_SH_STREAM_NO_HOLES        = VMRL_SHARED | VMRL_STREAM_NO_HOLES,
	VMRL_SH_ATOMIC                 = VMRL_SHARED | VMRL_ATOMIC,

	/* entry stabilization */
	VMRL_SH_RESOLVE_COW_AND_OBJ    = VMRL_RESOLVE_COW_AND_OBJ,
	VMRL_SH_VMO_ALLOCATE           = VMRL_VMO_ALLOCATE,

	/* other flags */
	VMRL_SH_WHOLE_MAP              = VMRL_WHOLE_MAP,
	VMRL_SH_NO_MIN_MAX_CHECK       = VMRL_NO_MIN_MAX_CHECK,
	VMRL_SH_INTERRUPTIBLE          = VMRL_INTERRUPTIBLE,
	VMRL_SH_ILK_LOCKED             = VMRL_ILK_LOCKED,
	VMRL_SH_TRY_LOCK_ENTRY         = VMRL_TRY_LOCK_ENTRY,
	VMRL_SH_NO_DESCEND_TRANSPARENT = VMRL_NO_DESCEND_TRANSPARENT,
	VMRL_SH_DESCEND_INTO_CONSTANT  = VMRL_DESCEND_INTO_CONSTANT,
});

/*!
 * @typedef vmrl_find_ex_flags_t
 *
 * @brief
 * Flags affecting the behavior of acquiring an exclusive lock on an entry at or
 * after an address.
 */
__options_decl(vmrl_find_ex_flags_t, uint32_t, {
	VMRL_FIND_EX_DEFAULT          = 0,

	/* entry stabilization */
	VMRL_FIND_EX_RESOLVE_COW_AND_OBJ = VMRL_RESOLVE_COW_AND_OBJ,

	/* other flags */
	VMRL_FIND_EX_NO_MIN_MAX_CHECK = VMRL_NO_MIN_MAX_CHECK,
	VMRL_FIND_EX_INTERRUPTIBLE    = VMRL_INTERRUPTIBLE,
	VMRL_FIND_EX_ILK_LOCKED       = VMRL_ILK_LOCKED,
});

/*!
 * @typedef vmrl_find_sh_flags_t
 *
 * @brief
 * Flags affecting the behavior of acquiring a shared lock on an entry at or
 * after an address.
 */
__options_decl(vmrl_find_sh_flags_t, uint32_t, {
	VMRL_FIND_SH_DEFAULT          = 0,

	/* entry stabilization */
	VMRL_FIND_SH_RESOLVE_COW_AND_OBJ = VMRL_RESOLVE_COW_AND_OBJ,
	VMRL_FIND_SH_VMO_ALLOCATE        = VMRL_VMO_ALLOCATE,

	/* other flags */
	VMRL_FIND_SH_NO_MIN_MAX_CHECK    = VMRL_NO_MIN_MAX_CHECK,
	VMRL_FIND_SH_INTERRUPTIBLE       = VMRL_INTERRUPTIBLE,
	VMRL_FIND_SH_ILK_LOCKED          = VMRL_ILK_LOCKED,
	VMRL_FIND_SH_NO_DESCEND_TRANSPARENT = VMRL_NO_DESCEND_TRANSPARENT,
	VMRL_FIND_SH_DESCEND_INTO_CONSTANT = VMRL_DESCEND_INTO_CONSTANT,
});

/*!
 * @brief
 * The state of descent in submaps.
 */
__enum_decl(vmlc_descend_t, unsigned char, {
	VMLC_NOT_DESCENDED,
	VMLC_IN_TRANSPARENT_SUBMAP,
	VMLC_IN_CONSTANT_SUBMAP,
});

/*!
 * @brief
 * These values should be used in conjunction with VMRL_X_WHOLE_MAP.
 * Their purpose is to alleviate the need from the user to specify the
 * exact limits of the first and last virtual addresses.
 */
#define VMRL_WHOLE_MAP_START (0)
#define VMRL_WHOLE_MAP_END (0)

/* The values are invalid VAs which are meant to fail the checks in
 * __vmrl_context_init() if left unmodified.  */
static_assert(VMRL_WHOLE_MAP_START == VMRL_WHOLE_MAP_END);

/*!
 * @brief
 * These values can be used in conjunction with VMRL_X_NO_OFFSET_CHECK
 * to iterate the map range from the start of the virtual address space
 * or to the end of the virtual address space.
 */
#define VMRL_START_VA(map) (0)
#define VMRL_END_VA(map)  ((vm_map_address_t)(-vm_map_page_size(map)))

typedef struct vm_map_lock_ctx *vm_map_lock_ctx_t;
typedef vm_map_lock_ctx_t vm_map_find_lock_ctx_t;

typedef kern_return_t (^vm_map_lock_preflight_t)(vm_map_lock_ctx_t ctx, vm_map_entry_t entry);

struct vm_map_lock_ctx {
	/*
	 * Denotes the clip that must be applied to the entry range
	 * relative to the current map.
	 * In stream lock vmlc_req_start is updated on every iteration to the current start address
	 */
	mach_vm_address_t       vmlc_req_start;
	mach_vm_address_t       vmlc_req_end;

/* public fields */

	/*!
	 * The map the current entry belongs to,
	 * this might differ from the original map
	 * passed to __vm_map_range_*_lock().
	 */
	vm_map_t                vmlc_map;

	/*! cursor state: the current vm entry */
	vm_map_entry_t          vmlc_vme;

	vm_map_lock_preflight_t vmlc_preflight;

/* private fields */

	/*! the flags passed to the __vm_map_range_*_lock() call */
	vmrl_flags_t            __vmlc_flags;

	/*! is a lock actively held */
	bool                    __vmlc_locked   : 1;
	/*! is this the first iteration */
	bool                    __vmlc_first    : 1;

	/*! Is the lock currently in a submap */
	vmlc_descend_t          __vmlc_descended : 2;

	uint32_t                __vmlc_unused1  : 28;

	union {
		/*! This structure is used for VMRL_STREAM contexts */
		struct {
			/*
			 * The last address that's been processed (or the start
			 * of the range, if we've just started)
			 */
			mach_vm_address_t       last_processed_addr;
			kern_return_t           first_error;
			uint32_t                __vmlc_unused2;
		} __vmlc_streaming;

		/*! This structure is used for VMRL_ATOMIC contexts */
		struct {
			vm_map_entry_t          first_entry;
			mach_vm_address_t       locked_range_start;
			mach_vm_address_t       locked_range_end;
		} __vmlc_atomic;
	};


	/*
	 * If we are descended in a submap, store
	 * start/end/map of the parent map
	 */
	vm_map_address_t        __original_req_start;
	vm_map_address_t        __original_req_end;
	vm_map_t                __original_map;
	vm_map_offset_t         __parent_offset; /* 0 if not descended */
	vm_map_entry_t          __parent_entry;
};


#pragma mark flags acessors

__attribute__((overloadable, always_inline, const))
static inline vmrl_flags_t
__vmrl_flags(vmrl_flags_t flags)
{
	return flags;
}

__attribute__((overloadable, always_inline))
static inline vmrl_flags_t
__vmrl_flags(vm_map_lock_ctx_t ctx)
{
	return ctx->__vmlc_flags;
}

__attribute__((overloadable, always_inline, const))
static inline vmrl_flags_t
__vmrl_flags(vmrl_sh_flags_t flags)
{
	return (vmrl_flags_t)flags;
}

__attribute__((overloadable, always_inline, const))
static inline vmrl_flags_t
__vmrl_flags(vmrl_ex_flags_t flags)
{
	return (vmrl_flags_t)flags;
}

__attribute__((overloadable, always_inline, const))
static inline vmrl_flags_t
__vmrl_flags(vmrl_find_sh_flags_t flags)
{
	return (vmrl_flags_t)flags;
}

__attribute__((overloadable, always_inline, const))
static inline vmrl_flags_t
__vmrl_flags(vmrl_find_ex_flags_t flags)
{
	return (vmrl_flags_t)flags;
}

/*!
 * @brief
 * Returns whether the specified flags or context denote a shared lock.
 */
#define vmrl_is_shared(x) \
	((bool)((__vmrl_flags(x) & (VMRL_SHARED | VMRL_EXCLUSIVE)) == VMRL_SHARED))


/*!
 * @brief
 * Returns whether the specified flags or context denote an exclusive lock.
 */
#define vmrl_is_exclusive(x) \
	((bool)((__vmrl_flags(x) & (VMRL_SHARED | VMRL_EXCLUSIVE)) == VMRL_EXCLUSIVE))

/*!
 * @brief
 * Denotes whether the specified context is for a kernel map.
 */
#define vmrl_is_kernel_pmap(x) \
	((bool)(__vmrl_flags(x) & _VMRL_KERNEL_PMAP))


/*!
 * @brief
 * Returns the mode of the lock (invalid, streaming, stream-no-holes,
 * atomic, or atomic-allow-holes).
 */
#define vmrl_mode(x) \
	(__vmrl_flags(x) & _VMRL_MODE_MASK)


/*!
 * @brief
 * Returns whether the specified flags or context denote a lock in streaming
 * mode.
 */
#define vmrl_is_streaming(x) \
	((bool)(vmrl_mode(x) & (_VMRL_STREAM_INTERNAL)))

/*!
 * @brief
 * Returns whether the specified flags or context denote a lock in atomic
 * mode.
 */
#define vmrl_is_atomic(x) \
	((bool)(vmrl_mode(x) & (_VMRL_ATOMIC_INTERNAL)))

/*!
 * @brief
 * Computes the wait flags (interruptible or not) for the specified flags or
 * context.
 */
#define vmrl_wait_interrupt(x) \
	((__vmrl_flags(x) & VMRL_INTERRUPTIBLE) ? THREAD_ABORTSAFE : THREAD_UNINT)

#pragma mark lock context

/*!
 * @brief
 * Static initializer for map range lock contexts.
 */
#define VM_MAP_LOCK_CTX_INITIALIZER  { }

/*
 * @function vm_map_lock_ctx_init()
 *
 * @brief
 * Initialize a map lock context to an empty state ready to be used for locking.
 */
static inline void
vm_map_lock_ctx_init(vm_map_lock_ctx_t vml_ctx)
{
	*vml_ctx = (struct vm_map_lock_ctx)VM_MAP_LOCK_CTX_INITIALIZER;
}

/*
 * @function assert_vm_map_lock_ctx_unlocked()
 *
 * @brief
 * Helper function to assert that a lock is unlocked.
 *
 * @discussion
 * This should not be called directly,
 * and is called internally by VM_MAP_LOCK_CTX_DECLARE.
 */
static inline void
assert_vm_map_lock_ctx_unlocked(vm_map_lock_ctx_t vml_ctx __assert_only)
{
	assert(!vml_ctx->__vmlc_locked);
}

/*!
 * @brief
 * Declare a lock context called @c name on the stack.
 *
 * @discussion
 * The context can be used for serveral lock acquisition in a row,
 * but the lock must be unlocked on any exit path from the function.
 */
#define VM_MAP_LOCK_CTX_DECLARE(name) \
	__attribute__((cleanup(assert_vm_map_lock_ctx_unlocked))) \
	struct vm_map_lock_ctx private_##name = VM_MAP_LOCK_CTX_INITIALIZER; \
	const vm_map_lock_ctx_t name = &private_##name

/*!
 * @brief
 * Declare a lock context called @c name on the stack for finding a single entry
 * at (or after) an address
 */
#define VM_MAP_FIND_LOCK_CTX_DECLARE(name) \
	__attribute__((cleanup(assert_vm_map_lock_ctx_unlocked))) \
	struct vm_map_lock_ctx private_##name = VM_MAP_LOCK_CTX_INITIALIZER; \
	const vm_map_find_lock_ctx_t name = &private_##name

/*!
 * @brief
 * Sets up the preflight hook in a context.
 *
 * @discussion
 * The preflight hook allows for lockers to add custom behaviors and validation
 * as the lock is being taken.
 *
 * For atomic locks, the preflight outcome will be returned by
 * @c vm_map_range_*_lock(), for streaming locks it is returned via the error
 * parameter of the @c vm_map_range_next_with_error() family of functions.
 * For atomic locks, the preflight is called on every entry during the process
 * of locking the range.
 * For streaming locks, the preflight is called on each entry at advance time.
 *
 * In all cases (incl. transparent submaps or constant submaps with
 * VMRL_DESCEND_INTO_CONSTANT), the preflight hook gets called on any entry that
 * is being iterated.
 *
 * The preflight hook may be called multiple times on the same entry.
 *
 * Preflight hooks are called with the entry locked exclusively for exclusive
 * locks, and at least shared for shared locks.
 *
 * Preflights are run with the interlock held. The intent is for them to make
 * policy checks by reading fields of the entry, or fields of the associated
 * object that are safe to access without the object lock. They should not
 * modify the state of the VM. They should ideally run quickly and not perform
 * any blocking operations such as acquiring an object lock.
 *
 * The preflight hook can return the following values:
 *
 * - KERN_SUCCESS       The entry is accepted.
 *
 * - VMRL_ERR_SKIP_PREPARE
 *                      The entry should not be "prepared" (no unnesting,
 *                      no clipping, etc...).
 *
 *                      This error doesn't stop enumeration and is swallowed,
 *                      and during the enumeration, it is the responsibility
 *                      of the client to notice this entry has not been
 *                      prepared and shouldn't be mutated.
 *
 *                      This error is processed internally by the lock and will
 *                      not be returned to clients of the @c vm_map_range_*_lock()
 *                      or @c vm_map_range_next_with_error() APIs.
 *
 * - VMRL_ERR_WAIT_FOR_KUNWIRE
 *                      The caller desires waiting for the wire count of the
 *                      entry to drop.
 *
 *                      This error doesn't stop enumeration, but the preflight
 *                      hook will be called on this entry again once the
 *                      kernel wire count condition changed. It will also cause
 *                      @c vm_map_range_*_lock() or @c vm_map_range_next_with_error()
 *                      to hang until the wire count drops.
 *
 *                      This error is processed internally by the lock and will
 *                      not be returned to clients of the @c vm_map_range_*_lock()
 *                      or @c vm_map_range_next_with_error() APIs.
 *
 * - VMRL_ERR_SETUP_SYMMETRIC_COW
 *                      The caller requests to setup COW on the entry.
 *                      If the lock is a shared lock, this will temporarily
 *                      take an exclusive lock on the entry.
 *
 * - VMRL_ERR_SETUP_SYMMETRIC_COW_NOCLIP
 *                      Same as VMRL_ERR_SETUP_SYMMETRIC_COW but entries are not clipped
 *                      to the requested range.
 *                      This serves to preserve the behaviour of APIs that have not
 *                      clipped before the range-lock change.
 *                      clipping behaviour is an internal implementation detail, except
 *                      in the case of mach_make_memory_entry() where the effects of
 *                      clipping is exposed to the user due to use of
 *                      vmk_flags.vmkf_copy_single_object. These two _NOCLIP flags
 *                      cater to this case.
 *
 * - VMRL_ERR_PREPARE_FOR_SHARE_NOCLIP
 *                      The caller indicates that the entry is going to be shared
 *                      with another map, but that they do not want the entry to
 *                      be clipped. The lock stabilizes the object for the entry
 *                      and sets is_shared accordingly.
 *                      If the entry is locked shared it will temporarily upgrade to exclusive
 *                      Entries are not clipped to the requested range, see above comment.
 *
 * - VMRL_ERR_PREPARE_FOR_SHARE_WITH_UPL
 *                      The caller indicates that the entry is going to be shared,
 *                      and that it may be clipped.
 *                      The lock stabilizes the object for the entry but does not
 *                      set is_shared.
 *                      If the entry is locked shared it will temporarily upgrade to exclusive
 *
 * - other              An error that stops the enumeration and will be bubbled
 *                      up to callers.
 */
static inline void
vm_map_lock_ctx_set_preflight(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_lock_preflight_t preflight)
{
	assert_vm_map_lock_ctx_unlocked(vml_ctx);
	vml_ctx->vmlc_preflight = preflight;
}

/*!
 * @brief
 * Converts a parent map address to be relative to the currently
 * iterated map (possibly a submap).
 */
static inline vm_map_offset_t
vm_map_lock_ctx_from_parent_address(vm_map_lock_ctx_t ctx, vm_map_address_t addr)
{
	return addr - ctx->__parent_offset;
}

/*!
 * @brief
 * Converts an address relative to the currently iterated map to be relative
 * to the parent map.
 */
static inline vm_map_offset_t
vm_map_lock_ctx_to_parent_address(vm_map_lock_ctx_t ctx, vm_map_address_t addr)
{
	return addr + ctx->__parent_offset;
}

/*!
 * @brief
 * Returns the entry offset for a given address, relative to the currently
 * iterated map (possibly a submap).
 */
static inline vm_map_offset_t
vm_map_lock_ctx_offset_for_address(vm_map_lock_ctx_t ctx, vm_map_address_t addr)
{
	vm_map_entry_t vme = ctx->vmlc_vme;

	/*
	 * the address really should be within the entry,
	 * and within the enumeration range.
	 * (<= because they may want to know about the end addr)
	 */
	assert(ctx->vmlc_req_start <= addr && addr <= ctx->vmlc_req_end);
	assert(vme->vme_start <= addr && addr <= vme->vme_end);

	return VME_OFFSET(vme) + addr - vme->vme_start;
}


/*!
 * @brief
 * Returns the entry offset for a given address relative to the parent map
 * that is currerntly iterated.
 */
static inline vm_map_offset_t
vm_map_lock_ctx_offset_for_parent_address(
	vm_map_lock_ctx_t       ctx,
	vm_map_address_t        addr)
{
	addr = vm_map_lock_ctx_from_parent_address(ctx, addr);
	return vm_map_lock_ctx_offset_for_address(ctx, addr);
}


/*!
 * @brief
 * Return the bounds of the current entry, relative to the currently
 * iterated map (possibly a submap).
 *
 * @discussion
 * This function will take the requested bounds into account,
 * and present the real bounds of the entry that the caller should consider.
 *
 * @param startp        (optional out parameter) the entry start.
 * @param endp          (optional out parameter) the entry end.
 * @param sizep         (optional out parameter) the entry size.
 */
static inline void
vm_map_lock_ctx_bounds(
	vm_map_lock_ctx_t       ctx,
	vm_map_address_t       *startp,
	vm_map_address_t       *endp,
	vm_map_size_t          *sizep)
{
	vm_map_entry_t   vme   = ctx->vmlc_vme;
	vm_map_address_t start = MAX(vme->vme_start, ctx->vmlc_req_start);
	vm_map_address_t end   = MIN(vme->vme_end, ctx->vmlc_req_end);

	if (startp) {
		*startp = start;
	}
	if (endp) {
		*endp = end;
	}
	if (sizep) {
		*sizep = end - start;
	}
}

/*!
 * @brief
 * Return the bounds of the current entry, relative to the currently
 * iterated parent map, regardless of whether the iteration descended
 * into a submap.
 *
 * @discussion
 * This function will take the requested bounds into account,
 * and present the real bounds of the entry that the caller should consider.
 *
 * @param startp        (optional out parameter) the entry start.
 * @param endp          (optional out parameter) the entry end.
 * @param sizep         (optional out parameter) the entry size.
 */
static inline void
vm_map_lock_ctx_bounds_in_parent(
	vm_map_lock_ctx_t       ctx,
	vm_map_address_t       *startp,
	vm_map_address_t       *endp,
	vm_map_size_t          *sizep)
{
	vm_map_lock_ctx_bounds(ctx, startp, endp, sizep);
	if (startp) {
		*startp = vm_map_lock_ctx_to_parent_address(ctx, *startp);
	}
	if (endp) {
		*endp = vm_map_lock_ctx_to_parent_address(ctx, *endp);
	}
}

/*!
 * @brief
 * Return the offsets bounds of the current entry's object or submap.
 *
 * @discussion
 * This function will take the requested bounds into account,
 * and present the real offsets bounds of the object or submap
 * that the caller should consider.
 *
 * @param startp        (optional out parameter) the object/submap start.
 * @param endp          (optional out parameter) the object/submap end.
 * @param sizep         (optional out parameter) the object/submap size.
 */
static inline void
vm_map_lock_ctx_offset_bounds(
	vm_map_lock_ctx_t       ctx,
	vm_object_offset_t     *startp,
	vm_object_offset_t     *endp,
	vm_object_size_t       *sizep)
{
	vm_map_lock_ctx_bounds(ctx, startp, endp, sizep);
	if (startp) {
		*startp = vm_map_lock_ctx_offset_for_address(ctx, *startp);
	}
	if (endp) {
		*endp = vm_map_lock_ctx_offset_for_address(ctx, *endp);
	}
}


#pragma mark lock / unlock

/*!
 * @function vm_map_range_ex_lock()
 *
 * @discussion
 * This function acquires an exclusive range lock for the [start, end) range
 * within the @c map VM map.
 *
 * This function initiates the context cursor to the first entry
 * in the range.
 *
 * Exclusive locks descend into transparent submaps by default and do not
 * descend into constant submaps.
 *
 * @param vml_ctx       the locking context to use.
 * @param map           the map being locked.
 *                      This parameter will be NULLed on success to prevent it
 *                      accidentally being used incorrectly by client code, which
 *                      should instead use vm_map_lock_ctx_get_map()
 * @param start         the beginning of the range to lock
 * @param end           the end of the range to lock
 * @param flags         a set of flags altering the lock behavior
 *
 * @returns
 * - KERN_SUCCESS       the lock was acquired
 *
 * - KERN_ABORTED       the lock wasn't acquired because of the sleep operation
 *                      being interrupted (VMRL_SH_ATOMIC & VMRL_EX_INTERRUPTIBLE only).
 *
 * - KERN_INVALID_ADDRESS
 *                      the lock wasn't acquired because no entry was found
 *                      within [start, end) (impossible for
 *                      VMRL_EX_ATOMIC_ALLOW_HOLES).
 *
 * - KERN_INVALID_ADDRESS
 *                      the lock wasn't acquired because there was a gap within
 *                      [start, end) (only for VMRL_EX_ATOMIC or
 *                      VMRL_EX_STREAM_NO_HOLES).
 *
 * - VMRL_ERR_LOCK_ALREADY_HELD
 *                      the lock wasn't acquired because the entry was already
 *                      locked. (VMRL_SH_ATOMIC & VMRL_EX_TRY_LOCK_ENTRY only)
 *
 * - other              the lock wasn't acquired because preparing the entry
 *                      failed with that error (entry stabilization only).
 *
 * - any error          the lock wasn't acquired because its preflight
 *                      rejected it (vmlc_preflight being set and
 *                      VMRL_EX_ATOMIC only).
 */
__result_use_check
extern kern_return_t vm_map_range_ex_lock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_ex_flags_t         flags)
__attribute__((__diagnose_if__((flags & _VMRL_MODE_MASK) == VMRL_INVALID,
    "no mode selected", "error")));

/*!
 * @function vm_map_range_sh_lock()
 *
 * @discussion
 * This function acquires a shared range lock for the [start, end) range
 * within the @c map VM map.
 *
 * This function initiates the context cursor to the first entry
 * in the range.
 *
 * @param vml_ctx       the locking context to use.
 * @param map           the map being locked.
 *                      This parameter will be NULLed on success to prevent it
 *                      accidentally being used incorrectly by client code, which
 *                      should instead use vm_map_lock_ctx_get_map()
 * @param start         the beginning of the range to lock
 * @param end           the end of the range to lock
 * @param flags         a set of flags altering the lock behavior
 *                      (VMRL_STREAM is implied)
 *
 * @returns
 * - KERN_SUCCESS       the lock was acquired
 *
 * - KERN_ABORTED       the lock wasn't acquired because of the sleep operation
 *                      being interrupted (VMRL_SH_ATOMIC & VMRL_SH_INTERRUPTIBLE only).
 *
 * - KERN_INVALID_ADDRESS
 *                      the lock wasn't acquired because no entry was found
 *                      within [start, end).
 *
 * - KERN_INVALID_ADDRESS
 *                      the lock wasn't acquired because there was a gap within
 *                      [start, end) (only for VMRL_SH_ATOMIC or
 *                      VMRL_SH_STREAM_NO_HOLES).
 *
 * - VMRL_ERR_LOCK_ALREADY_HELD
 *                      the lock wasn't acquired because the entry was already
 *                      locked. (VMRL_SH_ATOMIC & VMRL_SH_TRY_LOCK_ENTRY only)
 *
 * - other              the lock wasn't acquired because preparing the entry
 *                      failed with that error (entry stabilization only).
 *
 * - other              the lock wasn't acquired because its preflight
 *                      rejected it (vmlc_preflight being set only).
 */
__result_use_check
extern kern_return_t vm_map_range_sh_lock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vmrl_sh_flags_t         flags)
__attribute__((__diagnose_if__((flags & _VMRL_MODE_MASK) == VMRL_INVALID,
    "no mode selected", "error")));

/*!
 * @function vm_map_range_ex_to_sh()
 *
 * @brief
 * Downgrades an atomic exclusive held range lock
 * to an atomic shared range lock.
 *
 * @discussion
 * Exclusive range locks can only be downgraded if:
 * - VMRL_EX_STREAM wasn't passed to @c vm_map_range_ex_lock().
 *
 * A downgrade will always happen atomically, meaning that it is
 * guaranteed that no other exclusive locks can come in between
 * the exclusive to shared transition
 *
 * Once downgraded, the shared range lock is _not_ in streaming
 * mode. This nuance is hidden behind the cursor/iterator API.
 *
 * Downgrades should only happen after entirely iterating an exclusive range.
 * They reset the cursor to the beginning of that range.
 *
 * @param vml_ctx       the context passed to @c vm_map_range_ex_lock()
 */
extern void vm_map_range_ex_to_sh(
	vm_map_lock_ctx_t       vml_ctx);

/*!
 * @function vm_map_lock_ctx_from_locked_entries()
 *
 * @brief
 * Configures a context to manage a series of already-exclusive-locked entries.
 *
 * @discussion
 * Once configured, the lock context is indistinguishable from the hypothetical
 * context that @c vm_map_range_ex_lock() would have configured had it been
 * used to atomically lock the same range.
 *
 * @param vml_ctx       the context to be initialized
 * @param map           the map containing the locked entries
 * @param start         the first address in the already-exclusive-locked range
 * @param size          the total size of the range mapped by the locked entries
 */
extern kern_return_t vm_map_lock_ctx_from_locked_entries(
	vm_map_lock_ctx_t   vml_ctx,
	vm_map_t           *map,
	vm_map_address_t    start,
	vm_map_size_t       size);

/*!
 * @function vm_map_range_ex_unlock()
 *
 * @brief
 * Releases an exclusive range lock successfully acquired
 * by @c vm_map_range_ex_lock().
 *
 * @param vml_ctx    the context passed to @c vm_map_range_ex_lock()
 * @param map        the original map passed to the lock call.
 *                   will be written into *map. This should be the original map
 *                   passed to the lock call. It can also be NULL.
 */
extern void vm_map_range_ex_unlock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t               *map);

/*!
 * @function vm_map_range_sh_unlock()
 *
 * @brief
 * Releases a shared range lock successfully acquired
 * by @c vm_map_range_sh_lock().
 *
 * @param vml_ctx    the context passed to @c vm_map_range_sh_lock()
 * @param map        the original map passed to the lock call.
 *                   will be written into *map. This should be the original map
 *                   passed to the lock call. It can also be NULL.
 */
extern void vm_map_range_sh_unlock(
	vm_map_lock_ctx_t       vml_ctx,
	vm_map_t               *map);


#pragma mark range iteration

/*!
 * @function vm_map_range_atomic_next()
 *
 * @abstract
 * Advance the cursor of the lock context.
 *
 * @discussion
 * This function updates the @c vmlc_vme field of the context
 * to the value it returns, locked shared or exclusive according
 * to how the lock was set up.
 *
 * @param vml_ctx       the locking context to use.
 */
extern vm_map_entry_t vm_map_range_atomic_next(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_range_atomic_peek
 *
 * @abstract
 * Returns the same entry that vm_map_range_atomic_next() would, but does not
 * advance the cursor of the lock context.
 *
 * @discussion
 * Unlike @c vm_map_range_atomic_next(), a successful call to this function does
 * not have any side effects, and may peek into an empty lock context.
 *
 * @param vml_ctx       the locking context to use.
 */
extern vm_map_entry_t vm_map_range_atomic_peek(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_range_ex_atomic_pop()
 *
 * @abstract
 * Advance the cursor of the lock context, and remove it from the range lock.
 *
 * @discussion
 * Unlike @c vm_map_range_next(), this function doesn't set
 * the @c vmlc_vme field of the context.
 *
 * Instead, it "removes" the current entry from the range lock and donates
 * it to the client, for the client to unlock. This is useful for interfaces
 * that remove entries from the map, and would confuse the range lock.
 *
 * The responsibility remains on the caller to remove the entry from the map,
 * this function only removes it from the range lock.
 *
 * Calls to @c vm_map_range_ex_atomic_pop should not be intermixed with calls to
 * @c vm_map_range_next or its variants.
 *
 * Note that calling @c vm_map_range_*_unlock() is still mandatory.
 *
 * @param vml_ctx       the locking context to use.
 */
extern vm_map_entry_t vm_map_range_ex_atomic_pop(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_range_atomic_reset()
 *
 * @brief
 * resets the iteration cursor of a range locked in atomic mode.
 *
 * @discussion
 * This is invalid for streaming locks.
 * It will panic due to assertions if called on a streaming lock.
 *
 * @param vml_ctx       the context passed to @c vm_map_range_ex_lock()
 */
extern void vm_map_range_atomic_reset(
	vm_map_lock_ctx_t       vml_ctx);


/*!
 * @function vm_map_range_stream_next_with_error()
 *
 * @abstract
 * Advance the cursor of the lock context.
 *
 * @discussion
 * This function updates the @c vmlc_vme field of the context
 * to the value it returns, locked shared or exclusive according
 * to how the lock was set up.
 *
 * @param vml_ctx
 * the locking context to use.
 *
 * @param kr
 * If a non NULL vm map entry is returned, then `kr` will always be
 * KERN_SUCCCES.
 *
 * Otherwise, the errors that can be returned are:
 *
 * - KERN_SUCCESS       a valid entry was returned,
 *                      or the enumeration finished successfully.
 *
 * - KERN_ABORTED       the range advance failed because some locking operation
 *                      was interrupted (VMRL_*_INTERRUPTIBLE only).
 *
 * - KERN_INVALID_ADDRESS
 *                      the range advance found a hole and stopped the iteration
 *                      (VMRL_STREAM_NO_HOLES only).
 *
 * - VMRL_ERR_LOCK_ALREADY_HELD
 *                      the lock wasn't acquired because the entry was already
 *                      locked. (VMRL_TRY_LOCK_ENTRY only)
 *
 * - other              the range advance failed because some entry preparation
 *                      failed with that error (VMRL_*_RESOLVE only).
 *
 * - other              the lock wasn't acquired because its preflight
 *                      rejected it (vmlc_preflight set only).
 */
extern vm_map_entry_t vm_map_range_stream_next_with_error(
	vm_map_lock_ctx_t       vml_ctx,
	kern_return_t          *kr __attribute__((nonnull))) __result_use_check;

/*!
 * @function vm_map_range_stream_next()
 *
 * @abstract
 * Advance the cursor of the lock context.
 *
 * @discussion
 * This function is a simpler version of @c vm_map_range_next(),
 * for cases when the caller knows it will never return an error.
 * If it would have, this function will panic.
 *
 * @param vml_ctx
 * the locking context to use.
 *
 */
extern vm_map_entry_t vm_map_range_stream_next(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_range_ex_stream_pop_with_error()
 *
 * @abstract
 * Advance the cursor of the lock context, and remove it from the range lock.
 *
 * @discussion
 * Unlike @c vm_map_range_stream_next(), this function doesn't set
 * the @c vmlc_vme field of the context.
 *
 * Instead, it "removes" the current entry from the range lock and donates
 * it to the client, for the client to unlock. This is useful for interfaces
 * that remove entries from the map, and would confuse the range lock.
 *
 * The responsibility remains on the caller to remove the entry from the map,
 * this function only removes it from the range lock.
 *
 * Note that calling @c vm_map_range_*_unlock() is still mandatory.
 *
 * @param vml_ctx       the locking context to use.
 */
extern vm_map_entry_t vm_map_range_ex_stream_pop_with_error(
	vm_map_lock_ctx_t       vml_ctx,
	kern_return_t          *kr __attribute__((nonnull))) __result_use_check;

/*!
 * @function vm_map_range_ex_stream_pop()
 *
 * @abstract
 * Advance the cursor of the lock context, and remove it from the range lock.
 *
 * @discussion
 * This is the same as vm_map_range_ex_stream_pop()
 * for cases when the caller knows that no error will be returned.
 * If it would have, this function will panic.
 */
extern vm_map_entry_t vm_map_range_ex_stream_pop(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_found_entry_ex_pop_curr()
 *
 * @brief
 * Remove an entry locked via @c vm_map_find_entry_ex_locked{,_or_next} from
 * the range lock. The entry remains locked, and it becomes the caller's
 * responsibility to unlock the entry.
 *
 * @param vml_ctx the context passed to
 *                @c vm_map_find_entry_ex_locked{,_or_next}().
 */
extern void vm_map_found_entry_ex_pop_curr(
	vm_map_find_lock_ctx_t  vml_ctx);

/*!
 * @function vm_map_range_stream_drop()
 *
 * @discussion
 * Allows clients of streaming locks to drop the lock on their current entry
 * (typically so they can perform slow, object-level operations) without
 * advancing to the next entry.
 *
 * Subsequent calls to @c vm_map_range_stream_next() are still permitted.
 * The next call to @c vm_map_range_stream_next() will advance to the entry
 * following the end of the entry being unlocked by this call.
 *
 * @param vml_ctx       the locking context to use.
 */
extern void vm_map_range_stream_drop(
	vm_map_lock_ctx_t       vml_ctx);

/*!
 * @function vm_map_range_stream_drop_without_advance()
 *
 * @discussion
 * Similar to @c vm_map_range_stream_drop, but the address the lock is
 * processing is not advanced to the end of the current entry.
 * Instead, the next call to @c vm_map_range_stream_next will lock the entry at
 * the start of the current iteration's lock bounds.
 * This function is used if you need to drop an entry lock for the same range -
 * it's generally uncommon but is used in faulting-like patterns sometimes.
 *
 * @param vml_ctx       the locking context to use.
 */
extern void vm_map_range_stream_drop_without_advance(
	vm_map_lock_ctx_t       vml_ctx);


/*!
 * @function vm_map_range_next_with_error()
 *
 * @abstract
 * Advance the cursor of the lock context.
 *
 * @discussion
 * This function updates the @c vmlc_vme field of the context
 * to the value it returns, locked shared or exclusive according
 * to how the lock was set up.
 *
 * Note: when the caller knows which kind of lock has been setup,
 *       using @c vm_map_range_atomic_next() or
 *       @c vm_map_range_stream_next() directly is preferred.
 *
 * @see @c vm_map_range_stream_next_with_error().
 * @see @c vm_map_range_atomic_next().
 *
 * @param vml_ctx       the locking context to use.
 * @param kr            an out parameter that contains an error.
 *                      @see vm_map_range_stream_next().
 */
extern vm_map_entry_t vm_map_range_next_with_error(
	vm_map_lock_ctx_t       vml_ctx,
	kern_return_t          *kr __attribute__((nonnull))) __result_use_check;

/*!
 * @function vm_map_range_next()
 *
 * @abstract
 * Advance the cursor of the lock context.
 *
 * @discussion
 * This is the same as vm_map_range_next_with_error()
 * for cases when the caller knows that no error will be returned.
 * If it would have, this function will panic.
 */
extern vm_map_entry_t vm_map_range_next(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_range_ex_pop_with_error()
 *
 * @abstract
 * Advance the cursor of the lock context, and remove it from the range lock.
 *
 * @discussion
 * Note: when the caller knows which kind of lock has been setup,
 *       using @c vm_map_range_ex_atomic_pop() or
 *       @c vm_map_range_ex_stream_pop() directly is preferred.
 *
 * @see @c vm_map_range_ex_stream_pop().
 * @see @c vm_map_range_ex_atomic_pop().
 *
 * @param vml_ctx       the locking context to use.
 * @param kr            an out parameter that contains an error.
 *                      @see vm_map_range_stream_next().
 */
extern vm_map_entry_t vm_map_range_ex_pop_with_error(
	vm_map_lock_ctx_t       vml_ctx,
	kern_return_t          *kr __attribute__((nonnull))) __result_use_check;

/*!
 * @function vm_map_range_ex_pop()
 *
 * @abstract
 * Advance the cursor of the lock context, and remove it from the range lock.
 *
 * @discussion
 * This is the same as vm_map_range_ex_pop_with_error()
 * for cases when the caller knows that no error will be returned.
 * If it would have, this function will panic.
 */
extern vm_map_entry_t vm_map_range_ex_pop(
	vm_map_lock_ctx_t       vml_ctx) __result_use_check;

/*!
 * @function vm_map_range_lock_clip_end
 *
 * @discussion
 * Splits a locked entry at @c endaddr.
 *
 * The entry passed in will be set to end at the given address,
 * and copy of the entry inserted after it, remaining locked.
 * If the address requested is after the entry, this function does nothing.
 *
 * The map should be unlocked.
 *
 * The entry must be owned exclusively by the caller.
 *
 * pmap unnesting must have happened prior
 *
 * @param ctx               the lock context
 * @param entry             the entry to be clipped
 * @param endaddr           the address to clip the entry to
 */
extern void vm_map_range_lock_clip_end(
	vm_map_lock_ctx_t       ctx,
	vm_map_entry_t          entry,
	vm_map_offset_t         endaddr);

/*!
 * @function vm_map_range_lock_clip_start
 *
 * @discussion
 * Clips an entry to start at a greater start address.
 *
 * The entry passed in will be set to start at the given address, and a copy
 * of the entry will be inserted before it.
 * If the address requested is after the entry, this function does nothing.
 *
 * The map should be unlocked.
 *
 * The entry must be owned exclusively by the caller.
 *
 * pmap unnesting must have happened prior
 *
 * @param ctx               the lock context
 * @param entry             the entry to be clipped
 * @param startaddr         the address to clip the entry to
 */
extern void vm_map_range_lock_clip_start(
	vm_map_lock_ctx_t       ctx,
	vm_map_entry_t          entry,
	vm_map_offset_t         startaddr);

/*!
 * @function vm_map_found_entry_clip_end_ilocked
 *
 * @discussion
 * Clips an entry locked via @c vm_map_find_entry_sh_locked{,_or_next} to end
 * at a lesser end address.
 *
 * The entry passed in will be set to end at the given address,
 * and a copy of the entry will be inserted after it.
 *
 * The entry must be owned exclusively by the caller.
 * The address requested to clip to must be less than the current end of the entry.
 *
 * Requires the original entry and interlock to be exclusively locked.
 * Returns with the original entry, interlock, and newly-created entry
 * exclusively locked.
 *
 * Since a "found entry" context necessarily contains only a single entry,
 * the new entry is NOT a part of the lock context and it is the caller's
 * responsibility to handle the new entry appropriately.
 *
 * pmap unnesting must have happened prior
 *
 * @param ctx               the context passed to vm_map_find_entry_sh_locked{,_or_next}
 * @param endaddr           the address to clip the entry to
 *
 * @returns a pointer to the newly created and locked entry
 */
extern vm_map_entry_t vm_map_found_entry_clip_end_ilocked(
	vm_map_find_lock_ctx_t  ctx,
	vm_map_offset_t         endaddr);

/*
 * @function vm_map_entry_lock_resolve_symmetric_cow
 *
 * @discussion
 * Resolve symmetric CoW for an entry with needs_copy. The entry must
 * have needs_copy.
 */
extern void vm_map_entry_lock_resolve_symmetric_cow(
	vm_map_t                map,
	vm_map_entry_t          entry);

/*
 * @function vm_map_entry_lock_allocate_object
 *
 * @discussion
 * Allocate a vm_object for an entry with no vm_object.
 */
extern void vm_map_entry_lock_allocate_object(
	vm_map_entry_t          entry,
	vm_map_serial_t         provenance);


#pragma mark Locking one entry at (or after) a fixed address (aka "Single Entry" lock)

/*!
 * @function vm_map_find_entry_sh_locked
 *
 * @brief
 * Share-lock a single entry at a given address.
 *
 * @discussion
 * If an entry exists such that
 * @c entry->vme_start <= @c addr < @c entry->vme_end
 * is is locked, in shared mode.
 *
 * @param vml_ctx the locking context to use.
 * @param map     the map being locked.
 *                This parameter will be NULLed on success to prevent it
 *                accidentally being used incorrectly by client code, which
 *                should instead use vm_map_lock_ctx_get_map()
 * @param addr    the address at which to look for an entry.
 * @param flags   a set of flags altering the lock behavior
 *                (VMRL_SHARED is implied).
 *
 * @returns
 * - KERN_SUCCESS
 *                      if an entry was successfully found and locked. The entry
 *                      can be found at @c vml_ctx->vmlc_vme.
 * - KERN_INVALID_ADDRESS
 *                      if no entry exists at @c addr in @c map.
 * - KERN_ABORTED
 *                      if the lock wasn't acquired because of the sleep
 *                      operation being interrupted (VMRL_SH_INTERRUPTIBLE
 *                      only).
 * - other
 *                      any error returned by the preflight hook.
 *
 * If any error is returned, vml_ctx public fields are not set and no lock is
 * acquired.
 */
__result_use_check
extern kern_return_t vm_map_find_entry_sh_locked(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        addr,
	vmrl_find_sh_flags_t    flags);

/*!
 * @function vm_map_find_entry_ex_locked
 *
 * @brief
 * Exclusively lock a single entry at a given address.
 *
 * @discussion
 * If an entry exists such that
 * @c entry->vme_start <= @c addr < @c entry->vme_end
 * it is exclusively locked.
 *
 * @param vml_ctx the locking context to use.
 * @param map     the map being locked.
 *                This parameter will be NULLed on success to prevent it
 *                accidentally being used incorrectly by client code, which
 *                should instead use vm_map_lock_ctx_get_map()
 * @param addr    the address at which to look for an entry.
 * @param flags   a set of flags altering the lock behavior
 *                (VMRL_EXCLUSIVE is implied).
 *
 * @returns
 * - KERN_SUCCESS
 *                      if an entry was successfully found and locked. The entry
 *                      can be found at @c vml_ctx->vmlc_vme.
 * - KERN_INVALID_ADDRESS
 *                      if no entry exists at @c addr in @c map.
 * - KERN_ABORTED
 *                      if the lock wasn't acquired because of the sleep
 *                      operation being interrupted (VMRL_EX_INTERRUPTIBLE
 *                      only).
 * - other
 *                      any error returned by the preflight hook.
 *
 * If any error is returned, vml_ctx public fields are not set and no lock is
 * acquired.
 */
__result_use_check
extern kern_return_t vm_map_find_entry_ex_locked(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map,
	vm_map_address_t        addr,
	vmrl_find_ex_flags_t    flags);

/*!
 * @function vm_map_found_entry_sh_unlock
 *
 * @brief
 * Unlock an entry locked via @c vm_map_find_entry_sh_locked{,_or_next}.
 *
 * @param vml_ctx    the context passed to
 *                   @c vm_map_find_entry_sh_locked{,_or_next}().
 * @param map     the original map passed to the lock call.
 *                will be written into *map. This should be the original map
 *                passed to the lock call. It can also be NULL.
 */
extern void vm_map_found_entry_sh_unlock(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map);

/*!
 * @function vm_map_found_entry_ex_unlock
 *
 * @brief
 * Unlock an entry locked via @c vm_map_find_entry_ex_locked{,_or_next}.
 *
 * @param vml_ctx the context passed to
 *                @c vm_map_find_entry_ex_locked{,_or_next}().
 * @param map     the original map passed to the lock call.
 *                will be written into *map. This should be the original map
 *                passed to the lock call. It can also be NULL.
 */
extern void vm_map_found_entry_ex_unlock(
	vm_map_find_lock_ctx_t  vml_ctx,
	vm_map_t               *map);

/*!
 * @function vm_map_lock_ctx_is_descended
 *
 * @brief
 * Return if a lock context is descended into a submap
 */
static inline bool
vm_map_lock_ctx_is_descended(vm_map_lock_ctx_t ctx)
{
	return ctx->__vmlc_descended != VMLC_NOT_DESCENDED;
}

/*!
 * @function vm_map_lock_ctx_in_constant_submap
 *
 * @brief
 * Return if a lock context is descended into a constant submap
 */
static inline bool
vm_map_lock_ctx_in_constant_submap(vm_map_lock_ctx_t ctx)
{
	return ctx->__vmlc_descended == VMLC_IN_CONSTANT_SUBMAP;
}

/*!
 * @function vm_map_lock_ctx_get_map
 *
 * @brief
 * Returns the current vm_map_t the iteration is at
 * This may be different from the map the lock was called on
 * in case the lock is descended into a submap.
 */
static inline vm_map_t
vm_map_lock_ctx_get_map(vm_map_lock_ctx_t ctx)
{
	return ctx->vmlc_map;
}

/*!
 * @function vm_map_found_entry_get_entry
 *
 * @brief
 * For a find entry lock, return the currently locked entry.
 * The ctx must be locked.
 */
static inline vm_map_entry_t
vm_map_found_entry_get_entry(vm_map_find_lock_ctx_t ctx)
{
	assert(ctx->__vmlc_locked);
	return ctx->vmlc_vme;
}

/*!
 * @function vm_map_lock_ctx_is_in_needs_copy_submap
 *
 * @brief
 * Return whether the lock context is currently descended into a
 * needs_copy submap.
 */
static inline bool
vm_map_lock_ctx_is_in_needs_copy_submap(vm_map_lock_ctx_t ctx)
{
	if (vm_map_lock_ctx_is_descended(ctx)) {
		return ctx->__parent_entry->needs_copy;
	}
	return false;
}

/*!
 * @function vm_map_lock_ctx_is_in_pmap_nested_submap
 *
 * @brief
 * Return whether the lock context is currently descended into a submap with
 * a nested pmap.
 * See the comment in @vm_range_lock_pmap_unnest_and_clip for more info about
 * what that means.
 */
static inline bool
vm_map_lock_ctx_is_in_pmap_nested_submap(vm_map_lock_ctx_t ctx)
{
	if (vm_map_lock_ctx_is_descended(ctx)) {
		return ctx->__parent_entry->use_pmap;
	}
	return false;
}

/*
 * @function vm_map_lock_ctx_get_parent_entry_window
 *
 * @brief
 * This function should likely only be used for vm_map_region_recurse.
 * It gives the window that the parent entry gives into the submap, in
 * the address coordinates of the submap.
 *
 * *IMPORTANT*
 * @warning
 *  This is regardless of the bounds the lock ctx asked for. That means these
 * bounds may be before/after the requested bounds of the lock ctx
 * (vmlc_req_start/end).
 * That's because this is what vm_map_region_recurse needs, but it is unlikely
 * any other functions would want to go backwards from the range requested.
 */
static inline void
vm_map_lock_ctx_get_parent_entry_window(
	vm_map_lock_ctx_t       ctx,
	vm_map_address_t       *startp,
	vm_map_address_t       *endp)
{
	assert(vm_map_lock_ctx_is_descended(ctx));
	*startp = vm_map_lock_ctx_from_parent_address(ctx, ctx->__parent_entry->vme_start);
	*endp = vm_map_lock_ctx_from_parent_address(ctx, ctx->__parent_entry->vme_end);
}

/*!
 * @function vm_map_range_ex_lock_add_flags
 *
 * @brief
 * Add flags to an exclusive vm_map_range lock.
 */
extern void vm_map_range_ex_lock_add_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_ex_flags_t flags);

/*!
 * @function vm_map_range_ex_lock_remove_flags
 *
 * @brief
 * Remove flags from an exclusive vm_map_range lock.
 */
extern void vm_map_range_ex_lock_remove_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_ex_flags_t flags);

/*!
 * @function vm_map_range_sh_lock_add_flags
 *
 * @brief
 * Add flags to a shared vm_map_range lock.
 */
extern void vm_map_range_sh_lock_add_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_sh_flags_t flags);

/*!
 * @function vm_map_range_ex_lock_remove_flags
 *
 * @brief
 * Remove flags from a shared vm_map_range lock.
 */
extern void vm_map_range_sh_lock_remove_flags(
	vm_map_lock_ctx_t vml_ctx,
	vmrl_sh_flags_t flags);

#pragma mark Simplification

/*!
 * @function vm_map_locked_entry_simplify
 *
 * @brief
 * Attempts to coalesce the provided entry with its neighbors.
 *
 * @warning This is intended for use by functions engaging in manual locking
 *          only. Clients using the range lock should use VMRL_SIMPLIFY. Clients
 *          using the single entry lock (vm_map_find_entry_*) do not need to
 *          simplify today. If the need arises, they should implement
 *          VMRL_SIMPLIFY support for the single entry lock instead of
 *          attempting to make this work with the single entry lock.
 *
 * @param [in] map    The map in which simplification will take place. Its
 *                    interlock should not be held.
 * @param [in] entry  The entry to be simplified. It should be locked. Its
 *                    neighboring entries should not have their locks held
 *                    by the caller.
 *
 * @return The entry resulting from the simplification. It may not be the same
 *         as the one passed in (see rdar://150789194). Callers should stop
 *         using the entry pointer they passed in, and work on this returned
 *         entry instead. It will be locked. No other locks will be returned
 *         held.
 */
__result_use_check
extern vm_map_entry_t
vm_map_locked_entry_simplify(
	vm_map_t                map,
	vm_map_entry_t          entry);


__END_DECLS

#endif /* _VM_VM_MAP_LOCK_H_ */
