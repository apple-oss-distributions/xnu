/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
/**
 * This header file stores the types, and prototypes used strictly by the pmap
 * itself. The public pmap API exported to the rest of the kernel should be
 * located in osfmk/arm64/sptm/pmap/pmap.h.
 *
 * This file will automatically include all of the other internal arm/pmap/
 * headers so .c files will only need to include this one header.
 */
#pragma once

#include <stdint.h>

#include <kern/debug.h>
#include <kern/locks.h>
#include <mach/vm_types.h>
#include <mach_assert.h>

#include <arm/cpu_data.h>
#include <arm64/proc_reg.h>
#include <arm64/sptm/sptm.h>

/**
 * arm64/sptm/pmap/pmap.h and the other /arm/pmap/ internal header files are safe to be
 * included in this file since they shouldn't rely on any of the internal pmap
 * header files (so no circular dependencies). Implementation files will only
 * need to include this one header to get all of the relevant pmap types.
 */
#include <arm64/sptm/pmap/pmap.h>
#include <arm64/sptm/pmap/pmap_data.h>
#include <arm64/sptm/pmap/pmap_pt_geometry.h>

#define PMAP_SUPPORT_PROTOTYPES(__return_type, __function_name, __function_args, __function_index) \
	extern __return_type __function_name##_internal __function_args

/**
 * Global variables exported to the rest of the internal pmap implementation.
 */
extern lck_grp_t pmap_lck_grp;
extern pmap_paddr_t avail_start;
extern pmap_paddr_t avail_end;
extern uint32_t pmap_max_asids;

/**
 * SPTM TODO: The following flag is set up based on the presence and
 *            configuration of the 'sptm-stability-hacks' boot-arg; this
 *            is used in certain codepaths that do not properly function
 *            today in SPTM systems to make the system more stable and fully
 *            able to boot to user space.
 */
extern bool sptm_stability_hacks;

/**
 * Functions exported to the rest of the internal pmap implementation.
 */

extern void pmap_remove_range_options(
	pmap_t, vm_map_address_t, vm_map_address_t, int);

extern void pmap_tte_deallocate(
	pmap_t, vm_offset_t, tt_entry_t *, unsigned int);

#if defined(PVH_FLAG_EXEC)
extern void pmap_set_ptov_ap(unsigned int, unsigned int, boolean_t);
#endif /* defined(PVH_FLAG_EXEC) */

extern pmap_t current_pmap(void);
extern void pmap_tt_ledger_credit(pmap_t, vm_size_t);
extern void pmap_tt_ledger_debit(pmap_t, vm_size_t);

extern void write_pte(pt_entry_t *, pt_entry_t);

/**
 * The qsort function is used by various parts of the pmap but doesn't contain
 * its own header file with prototype so it must be manually extern'd.
 *
 * The `cmpfunc_t` type is a pointer to a function that should return the
 * following:
 *
 * return < 0 for a < b
 *          0 for a == b
 *        > 0 for a > b
 */
typedef int (*cmpfunc_t)(const void *a, const void *b);
extern void qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);

/**
 * Inline and macro functions exported for usage by other pmap modules.
 *
 * In an effort to not cause any performance regressions while breaking up the
 * pmap, I'm keeping all functions originally marked as "static inline", as
 * inline and moving them into header files to be shared across the pmap
 * modules. In reality, many of these functions probably don't need to be inline
 * and can be moved back into a .c file.
 *
 * TODO: rdar://70538514 (PMAP Cleanup: re-evaluate whether inline functions should actually be inline)
 */

/* Helper macro for rounding an address up to a correctly aligned value. */
#define PMAP_ALIGN(addr, align) ((addr) + ((align) - 1) & ~((align) - 1))

/**
 * pmap_data.h must be included before this point so that pmap_lock_mode_t is
 * defined before the rest of the locking code.
 */

/**
 * Initialize a pmap object's reader/writer lock.
 *
 * @param pmap The pmap whose lock to initialize.
 */
static inline void
pmap_lock_init(pmap_t pmap)
{
	lck_rw_init(&pmap->rwlock, &pmap_lck_grp, 0);
}

/**
 * Destroy a pmap object's reader/writer lock.
 *
 * @param pmap The pmap whose lock to destroy.
 */
static inline void
pmap_lock_destroy(pmap_t pmap)
{
	lck_rw_destroy(&pmap->rwlock, &pmap_lck_grp);
}

/**
 * Initialize a pmap object's TXM reader/writer lock.
 *
 * @param pmap The pmap whose TXM lock to initialize.
 */
static inline void
pmap_txmlock_init(pmap_t pmap)
{
	lck_rw_init(&pmap->txm_lck, &pmap_lck_grp, 0);
}

/**
 * Destroy a pmap object's TXM reader/writer lock.
 *
 * @param pmap The pmap whose TXM lock to destroy.
 */
static inline void
pmap_txmlock_destroy(pmap_t pmap)
{
	lck_rw_destroy(&pmap->txm_lck, &pmap_lck_grp);
}

/**
 * Assert that the pmap lock is held in the given mode.
 *
 * @note See pmap_lock() below for an explanation of the special handling
 *       we do for kernel_pmap.
 *
 * @param pmap The pmap whose lock to assert is being held.
 * @param mode The mode the lock should be held in.
 */
static inline void
pmap_assert_locked(__unused pmap_t pmap, __unused pmap_lock_mode_t mode)
{
#if MACH_ASSERT
	if (__improbable(sptm_stability_hacks)) {
		mode = PMAP_LOCK_EXCLUSIVE;
	}

	switch (mode) {
	case PMAP_LOCK_SHARED:
		if (pmap != kernel_pmap) {
			LCK_RW_ASSERT(&pmap->rwlock, LCK_RW_ASSERT_SHARED);
		}
		break;
	case PMAP_LOCK_EXCLUSIVE:
		LCK_RW_ASSERT(&pmap->rwlock, LCK_RW_ASSERT_EXCLUSIVE);
		break;
	case PMAP_LOCK_HELD:
		if (pmap != kernel_pmap) {
			LCK_RW_ASSERT(&pmap->rwlock, LCK_RW_ASSERT_HELD);
		}
		break;
	default:
		panic("%s: Unknown pmap_lock_mode. pmap=%p, mode=%d", __FUNCTION__, pmap, mode);
	}
#endif
}

/**
 * Assert that the pmap lock is held in any mode.
 *
 * @param pmap The pmap whose lock should be held.
 */
__unused static inline void
pmap_assert_locked_any(__unused pmap_t pmap)
{
	if (pmap != kernel_pmap) {
		LCK_RW_ASSERT(&pmap->rwlock, LCK_RW_ASSERT_HELD);
	}
}

/**
 * Acquire a pmap object's reader/writer lock as either shared (read-only) or
 * exclusive (read/write).
 *
 * @note If this function is called to request shared acquisition of the kernel pmap
 *       lock, the lock will not be acquired as a performance optimization.  See the
 *       the explanation in the function body for why this is safe to do.
 *
 * @param pmap The pmap whose lock to acquire.
 * @param mode Whether to grab the lock as shared (read-only) or exclusive (read/write).
 */
static inline void
pmap_lock(pmap_t pmap, pmap_lock_mode_t mode)
{
	if (__improbable(sptm_stability_hacks)) {
		mode = PMAP_LOCK_EXCLUSIVE;
	}

	switch (mode) {
	case PMAP_LOCK_SHARED:
		/**
		 * There are three cases in which we hold the pmap lock exclusive:
		 * 1) Removal of a leaf-level page table during pmap_remove(),
		 *    to prevent concurrent mapping into the to-be-deleted table.
		 * 2) Nesting/unnesting of a region of one pmap into another, to
		 *    both concurrent nesting and concurrent mapping into the nested
		 *    region.
		 * 3) Installing a new page table during pmap_expand(), to prevent
		 *    another thread from concurrently expanding the same pmap at
		 *    the same location.
		 * Of the above, the kernel pmap only participates in 3) (nesting
		 * and table removal are only done for user pmaps).  Because the
		 * exclusive lock in case 3) above is only meant to synchronize
		 * against other instances of case 3), we can effectively elide
		 * shared holders of the kernel pmap because there is no case in
		 * which shared<>exclusive locking of the kernel pmap matters.
		 */
		if (pmap != kernel_pmap) {
			lck_rw_lock_shared(&pmap->rwlock);
		}
		break;
	case PMAP_LOCK_EXCLUSIVE:
		lck_rw_lock_exclusive(&pmap->rwlock);
		break;
	default:
		panic("%s: Unknown pmap_lock_mode. pmap=%p, mode=%d", __func__, pmap, mode);
	}
}

/**
 * Attempt to acquire the pmap lock in the specified mode. If the lock couldn't
 * be acquired, then return immediately instead of spinning.
 *
 * @param pmap The pmap whose lock to attempt to acquire.
 * @param mode Whether to grab the lock as shared (read-only) or exclusive (read/write).
 *
 * @return True if the lock was acquired, false otherwise.
 */
static inline bool
pmap_try_lock(pmap_t pmap, pmap_lock_mode_t mode)
{
	bool ret = false;

	if (__improbable(sptm_stability_hacks)) {
		mode = PMAP_LOCK_EXCLUSIVE;
	}

	switch (mode) {
	case PMAP_LOCK_SHARED:
		if (pmap != kernel_pmap) {
			ret = lck_rw_try_lock_shared(&pmap->rwlock);
		} else {
			ret = true;
		}
		break;
	case PMAP_LOCK_EXCLUSIVE:
		ret = lck_rw_try_lock_exclusive(&pmap->rwlock);
		break;
	default:
		panic("%s: Unknown pmap_lock_mode. pmap=%p, mode=%d", __func__, pmap, mode);
	}

	return ret;
}

/**
 * Attempts to promote an already acquired pmap lock from shared to exclusive.
 *
 * @param pmap The pmap whose lock should be promoted from shared to exclusive.
 *
 * @return True if successfully promoted, otherwise false upon failure in
 *         which case the shared lock is dropped.
 */
static inline bool
pmap_lock_shared_to_exclusive(pmap_t pmap)
{
	pmap_assert_locked(pmap, PMAP_LOCK_SHARED);

	if ((pmap == kernel_pmap) || __improbable(sptm_stability_hacks)) {
		return true;
	}

	return lck_rw_lock_shared_to_exclusive(&pmap->rwlock);
}

/**
 * Release a pmap object's reader/writer lock.
 *
 * @param pmap The pmap whose lock to release.
 * @param mode Which mode the lock should be in at time of release.
 */
static inline void
pmap_unlock(pmap_t pmap, pmap_lock_mode_t mode)
{
	if (__improbable(sptm_stability_hacks)) {
		mode = PMAP_LOCK_EXCLUSIVE;
	}

	switch (mode) {
	case PMAP_LOCK_SHARED:
		if (pmap != kernel_pmap) {
			lck_rw_unlock_shared(&pmap->rwlock);
		}
		break;
	case PMAP_LOCK_EXCLUSIVE:
		lck_rw_unlock_exclusive(&pmap->rwlock);
		break;
	default:
		panic("%s: Unknown pmap_lock_mode. pmap=%p, mode=%d", __func__, pmap, mode);
	}
}
