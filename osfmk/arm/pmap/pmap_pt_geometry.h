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
 * PMAP Page Table Geometry.
 *
 * This header file is used to store the types, and inline functions related to
 * retrieving information about and parsing page table hierarchies.
 *
 * To prevent circular dependencies, this file shouldn't include any of the
 * other internal osfmk/arm/pmap/ header files.
 */
#ifndef _ARM_PMAP_PMAP_PT_GEOMETRY_H_
#define _ARM_PMAP_PMAP_PT_GEOMETRY_H_

#include <stdint.h>

#include <kern/debug.h>
#include <kern/locks.h>
#include <mach/vm_types.h>
#include <mach_assert.h>

#include <arm64/proc_reg.h>

/**
 * arm/pmap.h is safe to be included in this file since it shouldn't rely on any
 * of the internal pmap header files (so no circular dependencies).
 */
#include <arm/pmap.h>

/**
 * Structure representing parameters of a single page table level. An array of
 * these structures are used to represent the geometry for an entire page table
 * hierarchy.
 */
struct page_table_level_info {
	const uint64_t size;
	const uint64_t offmask;
	const uint64_t shift;
	const uint64_t index_mask;
	const uint64_t valid_mask;
	const uint64_t type_mask;
	const uint64_t type_block;
};

/**
 * Operations that are dependent on the type of page table. This is useful, for
 * instance, when dealing with stage 1 vs stage 2 pmaps.
 */
struct page_table_ops {
	bool (*alloc_id)(pmap_t pmap);
	void (*free_id)(pmap_t pmap);
	void (*flush_tlb_region_async)(vm_offset_t va, size_t length, pmap_t pmap, bool last_level_only, bool strong);
	void (*flush_tlb_async)(pmap_t pmap);
	pt_entry_t (*wimg_to_pte)(unsigned int wimg, pmap_paddr_t pa);
};

/**
 * The Page Table Attribute structure is used for both parameterizing the
 * different possible page table geometries, but also for abstracting out the
 * differences between stage 1 and stage 2 page tables. This allows one set of
 * code to seamlessly handle the differences between various address space
 * layouts as well as stage 1 vs stage 2 page tables on the fly. See
 * doc/arm_pmap.md for more details.
 *
 * Instead of accessing the fields in this structure directly, it is recommended
 * to use the page table attribute getter functions defined below.
 */
struct page_table_attr {
	/* Sizes and offsets for each level in the page table hierarchy. */
	const struct page_table_level_info * const pta_level_info;

	/* Operations that are dependent on the type of page table. */
	const struct page_table_ops * const pta_ops;

	/**
	 * The Access Permissions bits have different layouts within a page table
	 * entry depending on whether it's an entry for a stage 1 or stage 2 pmap.
	 *
	 * These fields describe the correct PTE bits to set to get the wanted
	 * permissions for the page tables described by this attribute structure.
	 */
	const uintptr_t ap_ro;
	const uintptr_t ap_rw;
	const uintptr_t ap_rona;
	const uintptr_t ap_rwna;
	const uintptr_t ap_xn;
	const uintptr_t ap_x;

	/* The page table level at which the hierarchy begins. */
	const unsigned int pta_root_level;

	/* The page table level at which the commpage is nested into an address space. */
	const unsigned int pta_commpage_level;

	/* The last level in the page table hierarchy (ARM supports up to four levels). */
	const unsigned int pta_max_level;


	/**
	 * Value to set the Translation Control Register (TCR) to in order to inform
	 * the hardware of this page table geometry.
	 */
	const uint64_t pta_tcr_value;

	/* Page Table/Granule Size. */
	const uint64_t pta_page_size;

	/**
	 * Size (in bytes) of the VA region at the beginning of the address space
	 * into which mappings should not be allowed.
	 */
	const uint64_t pta_pagezero_size;

	/**
	 * How many bits to shift "1" by to get the page table size. Alternatively,
	 * could also be thought of as how many bits make up the page offset in a
	 * virtual address.
	 */
	const uint64_t pta_page_shift;
};

typedef struct page_table_attr pt_attr_t;

/* The default page table attributes for a system. */
extern const struct page_table_attr * const native_pt_attr;
extern const struct page_table_ops native_pt_ops;

/**
 * Macros for getting pmap attributes/operations; not functions for const
 * propagation.
 */
#if ARM_PARAMETERIZED_PMAP

/* The page table attributes are linked to the pmap */
#define pmap_get_pt_attr(pmap) ((pmap)->pmap_pt_attr)
#define pmap_get_pt_ops(pmap) ((pmap)->pmap_pt_attr->pta_ops)

#else /* ARM_PARAMETERIZED_PMAP */

/* The page table attributes are fixed (to allow for const propagation) */
#define pmap_get_pt_attr(pmap) (native_pt_attr)
#define pmap_get_pt_ops(pmap) (&native_pt_ops)

#endif /* ARM_PARAMETERIZED_PMAP */

/* Defines representing a level in a page table hierarchy. */
#define PMAP_TT_L0_LEVEL 0x0
#define PMAP_TT_L1_LEVEL 0x1
#define PMAP_TT_L2_LEVEL 0x2
#define PMAP_TT_L3_LEVEL 0x3

/**
 * Inline functions exported for usage by other pmap modules.
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
 * Keep the following in mind when looking at the available attribute getters:
 *
 * We tend to use standard terms to describe various levels in a page table
 * hierarchy. The "root" level is the top of a hierarchy. The root page table is
 * the one that will programmed into the Translation Table Base Register (TTBR)
 * to inform the hardware of where to begin when performing page table walks.
 * The "twig" level is always one up from the last level, and the "leaf" level
 * is the last page table level in a hierarchy. The leaf page tables always
 * contain block entries, but the higher levels can contain either table or
 * block entries.
 *
 * ARM supports up to four levels of page tables. The levels start at L0 and
 * increase to L3 the deeper into a hierarchy you get, although L0 isn't
 * necessarily always the root level. For example, in a four-level hierarchy,
 * the root would be L0, the twig would be L2, and the leaf would be L3. But for
 * a three-level hierarchy, the root would be L1, the twig would be L2, and the
 * leaf would be L3.
 */
/* Page size getter. */
static inline uint64_t
pt_attr_page_size(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_page_size;
}

/* Pagezero region size getter. */
static inline uint64_t
pt_attr_pagezero_size(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_pagezero_size;
}

/**
 * Return the size of the virtual address space covered by a single TTE at a
 * specified level in the hierarchy.
 */
__unused static inline uint64_t
pt_attr_ln_size(const pt_attr_t * const pt_attr, unsigned int level)
{
	return pt_attr->pta_level_info[level].size;
}

/**
 * Return the page descriptor shift for a specified level in the hierarchy. This
 * shift value can be used to get the index into a page table at this level in
 * the hierarchy from a given virtual address.
 */
__unused static inline uint64_t
pt_attr_ln_shift(const pt_attr_t * const pt_attr, unsigned int level)
{
	return pt_attr->pta_level_info[level].shift;
}

/**
 * Return a mask of the offset for a specified level in the hierarchy.
 *
 * This should be equivalent to the value returned by pt_attr_ln_size() - 1.
 */
static inline uint64_t
pt_attr_ln_offmask(const pt_attr_t * const pt_attr, unsigned int level)
{
	return pt_attr->pta_level_info[level].offmask;
}

/**
 * Return the mask for getting a page table index out of a virtual address for a
 * specified level in the hierarchy. This can be combined with the value
 * returned by pt_attr_ln_shift() to get the index into a page table.
 */
__unused static inline uint64_t
pt_attr_ln_index_mask(const pt_attr_t * const pt_attr, unsigned int level)
{
	return pt_attr->pta_level_info[level].index_mask;
}

/**
 * Return the second to last page table level.
 */
static inline unsigned int
pt_attr_twig_level(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_max_level - 1;
}

/**
 * Return the first page table level. This is what will be programmed into the
 * Translation Table Base Register (TTBR) to inform the hardware of where to
 * begin page table walks.
 */
static inline unsigned int
pt_attr_root_level(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_root_level;
}

/**
 * Return the level at which to nest the commpage pmap into userspace pmaps.
 * Since the commpage is shared across all userspace address maps, memory is
 * saved by sharing the commpage page tables with every userspace pmap. The
 * level at which to nest the commpage is dependent on the page table geometry.
 *
 * Typically this is L1 for 4KB page tables, and L2 for 16KB page tables. In
 * this way, the commpage's L2/L3 page tables are reused in every 4KB task, and
 * the L3 page table is reused in every 16KB task.
 */
static inline unsigned int
pt_attr_commpage_level(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_commpage_level;
}

/**
 * Return the size of the virtual address space covered by a single PTE at the
 * leaf level.
 */
static __unused inline uint64_t
pt_attr_leaf_size(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level].size;
}

/**
 * Return a mask of the offset for a leaf table.
 *
 * This should be equivalent to the value returned by pt_attr_leaf_size() - 1.
 */
static __unused inline uint64_t
pt_attr_leaf_offmask(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level].offmask;
}

/**
 * Return the page descriptor shift for a leaf table entry. This shift value can
 * be used to get the index into a leaf page table from a given virtual address.
 */
static inline uint64_t
pt_attr_leaf_shift(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level].shift;
}

/**
 * Return the mask for getting a leaf table index out of a virtual address. This
 * can be combined with the value returned by pt_attr_leaf_shift() to get the
 * index into a leaf table.
 */
static __unused inline uint64_t
pt_attr_leaf_index_mask(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level].index_mask;
}

/**
 * Return the size of the virtual address space covered by a single TTE at the
 * twig level.
 */
static inline uint64_t
pt_attr_twig_size(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level - 1].size;
}

/**
 * Return a mask of the offset for a twig table.
 *
 * This should be equivalent to the value returned by pt_attr_twig_size() - 1.
 */
static inline uint64_t
pt_attr_twig_offmask(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level - 1].offmask;
}

/**
 * Return the page descriptor shift for a twig table entry. This shift value can
 * be used to get the index into a twig page table from a given virtual address.
 */
static inline uint64_t
pt_attr_twig_shift(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level - 1].shift;
}

/**
 * Return the mask for getting a twig table index out of a virtual address. This
 * can be combined with the value returned by pt_attr_twig_shift() to get the
 * index into a twig table.
 */
static __unused inline uint64_t
pt_attr_twig_index_mask(const pt_attr_t * const pt_attr)
{
	return pt_attr->pta_level_info[pt_attr->pta_max_level - 1].index_mask;
}

/**
 * Return the amount of memory that a leaf table takes up. This is equivalent
 * to the amount of virtual address space covered by a single twig TTE.
 */
static inline uint64_t
pt_attr_leaf_table_size(const pt_attr_t * const pt_attr)
{
	return pt_attr_twig_size(pt_attr);
}

/**
 * Return the offset mask for the memory used by a leaf page table.
 *
 * This should be equivalent to the value returned by pt_attr_twig_size() - 1.
 */
static inline uint64_t
pt_attr_leaf_table_offmask(const pt_attr_t * const pt_attr)
{
	return pt_attr_twig_offmask(pt_attr);
}

/**
 * Return the Access Permissions bits required to specify User and Kernel
 * Read/Write permissions on a PTE in this type of page table hierarchy (stage 1
 * vs stage 2).
 */
static inline uintptr_t
pt_attr_leaf_rw(const pt_attr_t * const pt_attr)
{
	return pt_attr->ap_rw;
}

/**
 * Return the Access Permissions bits required to specify User and Kernel
 * Read-Only permissions on a PTE in this type of page table hierarchy (stage 1
 * vs stage 2).
 */
static inline uintptr_t
pt_attr_leaf_ro(const pt_attr_t * const pt_attr)
{
	return pt_attr->ap_ro;
}

/**
 * Return the Access Permissions bits required to specify just Kernel Read-Only
 * permissions on a PTE in this type of page table hierarchy (stage 1 vs stage
 * 2).
 */
static inline uintptr_t
pt_attr_leaf_rona(const pt_attr_t * const pt_attr)
{
	return pt_attr->ap_rona;
}

/**
 * Return the Access Permissions bits required to specify just Kernel Read/Write
 * permissions on a PTE in this type of page table hierarchy (stage 1 vs stage
 * 2).
 */
static inline uintptr_t
pt_attr_leaf_rwna(const pt_attr_t * const pt_attr)
{
	return pt_attr->ap_rwna;
}

/**
 * Return the mask of the page table entry bits required to set both the
 * privileged and unprivileged execute never bits.
 */
static inline uintptr_t
pt_attr_leaf_xn(const pt_attr_t * const pt_attr)
{
	return pt_attr->ap_xn;
}

/**
 * Return the mask of the page table entry bits required to set just the
 * privileged execute never bit.
 */
static inline uintptr_t
pt_attr_leaf_x(const pt_attr_t * const pt_attr)
{
	return pt_attr->ap_x;
}


/**
 * Return the last level in the page table hierarchy.
 */
static inline unsigned int
pt_attr_leaf_level(const pt_attr_t * const pt_attr)
{
	return pt_attr_twig_level(pt_attr) + 1;
}


/**
 * Return the index into a specific level of page table for a given virtual
 * address.
 *
 * @param pt_attr Page table attribute structure describing the hierarchy.
 * @param addr The virtual address to get the index from.
 * @param pt_level The page table whose index should be returned.
 */
static inline unsigned int
ttn_index(const pt_attr_t * const pt_attr, vm_map_address_t addr, unsigned int pt_level)
{
	const uint64_t index_unshifted = addr & pt_attr_ln_index_mask(pt_attr, pt_level);
	return (unsigned int)(index_unshifted >> pt_attr_ln_shift(pt_attr, pt_level));
}

/**
 * Return the index into a twig page table for a given virtual address.
 *
 * @param pt_attr Page table attribute structure describing the hierarchy.
 * @param addr The virtual address to get the index from.
 */
static inline unsigned int
tte_index(const pt_attr_t * const pt_attr, vm_map_address_t addr)
{
	return ttn_index(pt_attr, addr, PMAP_TT_L2_LEVEL);
}

/**
 * Return the index into a leaf page table for a given virtual address.
 *
 * @param pt_attr Page table attribute structure describing the hierarchy.
 * @param addr The virtual address to get the index from.
 */
static inline unsigned int
pte_index(const pt_attr_t * const pt_attr, vm_map_address_t addr)
{
	return ttn_index(pt_attr, addr, PMAP_TT_L3_LEVEL);
}



/**
 * Given an address and a map, compute the address of the table entry at the
 * specified page table level. If the address is invalid with respect to the map
 * then TT_ENTRY_NULL is returned.
 *
 * @param pmap The pmap whose page tables to parse.
 * @param target_level The page table level at which to stop parsing the
 *                     hierarchy at.
 * @param addr The virtual address to calculate the table indices off of.
 */
static inline tt_entry_t *
pmap_ttne(pmap_t pmap, unsigned int target_level, vm_map_address_t addr)
{
	tt_entry_t *table_ttep = TT_ENTRY_NULL;
	tt_entry_t *ttep = TT_ENTRY_NULL;
	tt_entry_t tte = ARM_TTE_EMPTY;
	unsigned int cur_level;

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if (__improbable((addr < pmap->min) || (addr >= pmap->max))) {
		return TT_ENTRY_NULL;
	}
	/* Start parsing at the root page table. */
	table_ttep = pmap->tte;

	assert(target_level <= pt_attr->pta_max_level);

	for (cur_level = pt_attr->pta_root_level; cur_level <= target_level; cur_level++) {
		ttep = &table_ttep[ttn_index(pt_attr, addr, cur_level)];

		if (cur_level == target_level) {
			break;
		}

		tte = *ttep;

#if MACH_ASSERT
		if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) == (ARM_TTE_TYPE_BLOCK | ARM_TTE_VALID)) {
			panic("%s: Attempt to demote L%u block, tte=0x%llx, pmap=%p, target_level=%u, addr=%p",
			    __func__, cur_level, tte, pmap, target_level, (void*)addr);
		}
#endif
		if ((tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID)) {
			return TT_ENTRY_NULL;
		}

		table_ttep = (tt_entry_t*)phystokv(tte & ARM_TTE_TABLE_MASK);
	}

	return ttep;
}

/**
 * Given an address and a map, compute the address of the level 1 translation
 * table entry. If the address is invalid with respect to the map then
 * TT_ENTRY_NULL is returned.
 *
 * @param pmap The pmap whose page tables to parse.
 * @param addr The virtual address to calculate the table indices off of.
 */
static inline tt_entry_t *
pmap_tt1e(pmap_t pmap, vm_map_address_t addr)
{
	return pmap_ttne(pmap, PMAP_TT_L1_LEVEL, addr);
}

/**
 * Given an address and a map, compute the address of the level 2 translation
 * table entry. If the address is invalid with respect to the map then
 * TT_ENTRY_NULL is returned.
 *
 * @param pmap The pmap whose page tables to parse.
 * @param addr The virtual address to calculate the table indices off of.
 */
static inline tt_entry_t *
pmap_tt2e(pmap_t pmap, vm_map_address_t addr)
{
	return pmap_ttne(pmap, PMAP_TT_L2_LEVEL, addr);
}

/**
 * Given an address and a map, compute the address of the level 3 page table
 * entry. If the address is invalid with respect to the map then PT_ENTRY_NULL
 * is returned.
 *
 * @param pmap The pmap whose page tables to parse.
 * @param addr The virtual address to calculate the table indices off of.
 */
static inline pt_entry_t *
pmap_tt3e(pmap_t pmap, vm_map_address_t addr)
{
	return (pt_entry_t*)pmap_ttne(pmap, PMAP_TT_L3_LEVEL, addr);
}

/**
 * Given an address and a map, compute the address of the twig translation table
 * entry. If the address is invalid with respect to the map then TT_ENTRY_NULL
 * is returned.
 *
 * @param pmap The pmap whose page tables to parse.
 * @param addr The virtual address to calculate the table indices off of.
 */
static inline tt_entry_t *
pmap_tte(pmap_t pmap, vm_map_address_t addr)
{
	return pmap_tt2e(pmap, addr);
}

/**
 * Given an address and a map, compute the address of the leaf page table entry.
 * If the address is invalid with respect to the map then PT_ENTRY_NULL is
 * returned.
 *
 * @param pmap The pmap whose page tables to parse.
 * @param addr The virtual address to calculate the table indices off of.
 */
static inline pt_entry_t *
pmap_pte(pmap_t pmap, vm_map_address_t addr)
{
	return pmap_tt3e(pmap, addr);
}


#endif /* _ARM_PMAP_PMAP_PT_GEOMETRY_H_ */
