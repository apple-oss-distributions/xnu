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
 * located in osfmk/arm/pmap.h.
 *
 * This file will automatically include all of the other internal arm/pmap/
 * headers so .c files will only need to include this one header.
 */
#ifndef _ARM_PMAP_PMAP_INTERNAL_H_
#define _ARM_PMAP_PMAP_INTERNAL_H_

#include <stdint.h>

#include <kern/debug.h>
#include <kern/locks.h>
#include <mach/vm_types.h>
#include <mach_assert.h>

#include <arm/cpu_data.h>
#include <arm/proc_reg.h>
#if defined(__arm64__)
#include <arm64/proc_reg.h>
#endif /* defined(__arm64__) */

/**
 * arm/pmap.h and the other /arm/pmap/ internal header files are safe to be
 * included in this file since they shouldn't rely on any of the internal pmap
 * header files (so no circular dependencies). Implementation files will only
 * need to include this one header to get all of the relevant pmap types.
 */
#include <arm/pmap.h>
#include <arm/pmap/pmap_data.h>
#include <arm/pmap/pmap_pt_geometry.h>

#if XNU_MONITOR
/**
 * Temporary macros and prototypes needed to implement the ppl_handler_table.
 *
 * Eventually all calls to these macros will be in pmap_ppl_interface.c and
 * these macros can be moved into that .c file.
 *
 * The <function>_internal() externs in here are also only included to be used
 * by the ppl_handler_table. Once the ppl_handler_table moves into
 * pmap_ppl_interface.c, then these prototypes can be removed (the
 * PMAP_SUPPORT_PROTOTYPES() macro creates these prototypes automatically).
 *
 * TODO: Move PMAP_SUPPORT_PROTOTYPES_*() macros into pmap_ppl_interface.c and
 *       remove these _internal() prototypes.
 */

extern pmap_paddr_t pmap_release_ppl_pages_to_kernel_internal(void);
extern kern_return_t mapping_free_prime_internal(void);

extern void pmap_ledger_verify_size_internal(size_t);
extern ledger_t pmap_ledger_alloc_internal(void);
extern void pmap_ledger_free_internal(ledger_t);

/**
 * This macro generates prototypes for the *_internal functions, which represent
 * the PPL interface. When the PPL is enabled, this will also generate
 * prototypes for the PPL entrypoints (*_ppl), as well as generating the
 * entrypoints themselves.
 *
 * Since these macros generate code, they should only be called from a single
 * implementation file for each PPL entry point.
 */
#define GEN_ASM_NAME(__function_name) _##__function_name##_ppl

#define PMAP_SUPPORT_PROTOTYPES_WITH_ASM_INTERNAL(__return_type, __function_name, __function_args, __function_index, __assembly_function_name) \
	extern __return_type __function_name##_internal __function_args; \
	extern __return_type __function_name##_ppl __function_args; \
	__asm__ (".text \n" \
	         ".align 2 \n" \
	         ".globl " #__assembly_function_name "\n" \
	         #__assembly_function_name ":\n" \
	         "mov x15, " #__function_index "\n" \
	         "b _aprr_ppl_enter\n")

#define PMAP_SUPPORT_PROTOTYPES_WITH_ASM(__return_type, __function_name, __function_args, __function_index, __assembly_function_name) \
	PMAP_SUPPORT_PROTOTYPES_WITH_ASM_INTERNAL(__return_type, __function_name, __function_args, __function_index, __assembly_function_name)

#define PMAP_SUPPORT_PROTOTYPES(__return_type, __function_name, __function_args, __function_index) \
	PMAP_SUPPORT_PROTOTYPES_WITH_ASM(__return_type, __function_name, __function_args, __function_index, GEN_ASM_NAME(__function_name))
#else /* XNU_MONITOR */
#define PMAP_SUPPORT_PROTOTYPES(__return_type, __function_name, __function_args, __function_index) \
	extern __return_type __function_name##_internal __function_args
#endif /* XNU_MONITOR */

/**
 * Global variables exported to the rest of the internal pmap implementation.
 */
extern lck_grp_t pmap_lck_grp;
extern bool hib_entry_pmap_lockdown;
extern pmap_paddr_t avail_start;
extern pmap_paddr_t avail_end;
extern uint32_t pmap_max_asids;

/**
 * Functions exported to the rest of the internal pmap implementation.
 */

#if XNU_MONITOR
extern void pmap_set_xprr_perm(unsigned int, unsigned int, unsigned int);
extern void pa_set_range_xprr_perm(pmap_paddr_t, pmap_paddr_t, unsigned int, unsigned int);
#endif /* XNU_MONITOR */

extern int pmap_remove_range_options(
	pmap_t, vm_map_address_t, pt_entry_t *, pt_entry_t *, vm_map_address_t *, bool *, int);

extern void pmap_tte_deallocate(
	pmap_t, vm_offset_t, vm_offset_t, bool, tt_entry_t *, unsigned int);

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

/**
 * Macro used to ensure that pmap data structures aren't modified during
 * hibernation image copying.
 */
#if HIBERNATION
#define ASSERT_NOT_HIBERNATING() (assertf(!hib_entry_pmap_lockdown, \
	"Attempted to modify PMAP data structures after hibernation image copying has begun."))
#else
#define ASSERT_NOT_HIBERNATING()
#endif /* HIBERNATION */

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
	pmap->rwlock.lck_rw_can_sleep = FALSE;
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
 * Assert that the pmap lock is held in the given mode.
 *
 * @param pmap The pmap whose lock to assert is being held.
 * @param mode The mode the lock should be held in.
 */
static inline void
pmap_assert_locked(__unused pmap_t pmap, __unused pmap_lock_mode_t mode)
{
#if MACH_ASSERT
	switch (mode) {
	case PMAP_LOCK_SHARED:
		lck_rw_assert(&pmap->rwlock, LCK_RW_ASSERT_SHARED);
		break;
	case PMAP_LOCK_EXCLUSIVE:
		lck_rw_assert(&pmap->rwlock, LCK_RW_ASSERT_EXCLUSIVE);
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
#if MACH_ASSERT
	lck_rw_assert(&pmap->rwlock, LCK_RW_ASSERT_HELD);
#endif
}

/**
 * Acquire a pmap object's reader/writer lock as either shared (read-only) or
 * exclusive (read/write).
 *
 * @note Failed attempts to grab the lock will NOT go to sleep, they'll spin
 *       until the lock can be acquired.
 *
 * @param pmap The pmap whose lock to acquire.
 * @param mode Whether to grab the lock as shared (read-only) or exclusive (read/write).
 */
static inline void
pmap_lock(pmap_t pmap, pmap_lock_mode_t mode)
{
#if !XNU_MONITOR
	mp_disable_preemption();
#endif

	switch (mode) {
	case PMAP_LOCK_SHARED:
		lck_rw_lock_shared(&pmap->rwlock);
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

#if !XNU_MONITOR
	mp_disable_preemption();
#endif

	switch (mode) {
	case PMAP_LOCK_SHARED:
		ret = lck_rw_try_lock_shared(&pmap->rwlock);
		break;
	case PMAP_LOCK_EXCLUSIVE:
		ret = lck_rw_try_lock_exclusive(&pmap->rwlock);
		break;
	default:
		panic("%s: Unknown pmap_lock_mode. pmap=%p, mode=%d", __func__, pmap, mode);
	}

	if (!ret) {
#if !XNU_MONITOR
		mp_enable_preemption();
#endif
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

	bool locked = lck_rw_lock_shared_to_exclusive(&pmap->rwlock);

#if !XNU_MONITOR
	if (!locked) {
		mp_enable_preemption();
	}
#endif

	return locked;
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
	switch (mode) {
	case PMAP_LOCK_SHARED:
		lck_rw_unlock_shared(&pmap->rwlock);
		break;
	case PMAP_LOCK_EXCLUSIVE:
		lck_rw_unlock_exclusive(&pmap->rwlock);
		break;
	default:
		panic("%s: Unknown pmap_lock_mode. pmap=%p, mode=%d", __func__, pmap, mode);
	}

#if !XNU_MONITOR
	mp_enable_preemption();
#endif
}

#if __arm64__
/*
 * Disable interrupts and return previous state.
 *
 * The PPL has its own interrupt state facility separately from
 * ml_set_interrupts_enable(), since that function is not part of the
 * PPL, and so doing things like manipulating untrusted data and
 * taking ASTs.
 *
 * @return The previous interrupt state, to be restored with
 *         pmap_interrupts_restore().
 */
static inline uint64_t __attribute__((warn_unused_result)) __used
pmap_interrupts_disable(void)
{
	uint64_t state = __builtin_arm_rsr64("DAIF");

	if ((state & DAIF_STANDARD_DISABLE) != DAIF_STANDARD_DISABLE) {
		__builtin_arm_wsr64("DAIFSet", DAIFSC_STANDARD_DISABLE);
	}

	return state;
}

/*
 * Restore previous interrupt state.
 *
 * @param state The previous interrupt state to restore.
 */
static inline void __used
pmap_interrupts_restore(uint64_t state)
{
	// no unknown bits?
	assert((state & ~DAIF_ALL) == 0);

	if (state != DAIF_STANDARD_DISABLE) {
		__builtin_arm_wsr64("DAIF", state);
	}
}

/*
 * Query interrupt state.
 *
 * ml_get_interrupts_enabled() is safe enough at the time of writing
 * this comment, but because it is not considered part of the PPL, so
 * could change without notice, and because it presently only checks
 * DAIF_IRQ, we have our own version.
 *
 * @return true if interrupts are enable (not fully disabled).
 */

static inline bool __attribute__((warn_unused_result)) __used
pmap_interrupts_enabled(void)
{
	return (__builtin_arm_rsr64("DAIF") & DAIF_STANDARD_DISABLE) != DAIF_STANDARD_DISABLE;
}
#endif /* __arm64__ */

#endif /* _ARM_PMAP_PMAP_INTERNAL_H_ */
