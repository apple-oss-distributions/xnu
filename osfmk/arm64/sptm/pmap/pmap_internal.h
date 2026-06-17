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
	pmap_t, vm_map_address_t, vm_map_address_t, int, const tt_entry_t*);

#if defined(PVH_FLAG_EXEC)
extern void pmap_set_ptov_ap(unsigned int, unsigned int, boolean_t);
#endif /* defined(PVH_FLAG_EXEC) */

extern pmap_t current_pmap(void);
extern void pmap_tt_ledger_credit(pmap_t, vm_size_t, bool);
extern void pmap_tt_ledger_debit(pmap_t, vm_size_t, bool);
extern void pmap_tt_deallocate(pmap_t, pmap_paddr_t, unsigned int);

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
 * Special pmap routines for mapping/unmapping kernel stack redzone pages.
 * These functions bypass epochs and PVH locks and call SPTM directly,
 * as kernel stack pages are single-threaded and don't need synchronization.
 *
 * WARNING: These functions should ONLY be used for kernel stack redzone pages.
 * They skip critical locking and synchronization that normal pmap operations require.
 */

/**
 * Map a kernel stack redzone page directly via SPTM without epochs or PVH locks.
 *
 * @param pmap The kernel pmap (must be kernel_pmap).
 * @param va The virtual address to map.
 * @param pa The physical address to map.
 *
 * @return KERN_SUCCESS if mapping succeeded, KERN_FAILURE otherwise.
 */
kern_return_t pmap_map_stack_page_direct(pmap_t pmap, vm_map_address_t va, pmap_paddr_t pa);

/**
 * Unmap a kernel stack redzone page directly via SPTM without epochs or PVH locks.
 *
 * @param pmap The kernel pmap (must be kernel_pmap).
 * @param va The virtual address to unmap.
 */
void pmap_unmap_stack_page_direct(pmap_t pmap, vm_map_address_t va);
