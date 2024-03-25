/*
 * Copyright (c) 2011-2022 Apple Inc. All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <mach_assert.h>
#include <mach_ldebug.h>

#include <mach/shared_region.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>
#include <mach/machine/vm_param.h>
#include <mach/machine/vm_types.h>

#include <mach/boolean.h>
#include <kern/bits.h>
#include <kern/ecc.h>
#include <kern/thread.h>
#include <kern/sched.h>
#include <kern/zalloc.h>
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>
#include <kern/spl.h>
#include <kern/startup.h>
#include <kern/trustcache.h>

#include <os/overflow.h>

#include <vm/pmap.h>
#include <vm/pmap_cs.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/cpm.h>

#include <libkern/section_keywords.h>
#include <sys/errno.h>

#include <libkern/amfi/amfi.h>
#include <sys/trusted_execution_monitor.h>
#include <sys/trust_caches.h>
#include <sys/code_signing.h>

#include <machine/atomic.h>
#include <machine/thread.h>
#include <machine/lowglobals.h>

#include <arm/caches_internal.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_capabilities.h>
#include <arm/cpu_number.h>
#include <arm/machine_cpu.h>
#include <arm/misc_protos.h>
#include <arm64/sptm/pmap/pmap_internal.h>
#include <arm/trap_internal.h>

#include <arm64/proc_reg.h>
#include <pexpert/arm64/boot.h>
#include <arm64/ppl/uat.h>
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
#include <arm64/amcc_rorgn.h>
#endif // defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)

#include <pexpert/device_tree.h>

#include <san/kasan.h>
#include <sys/cdefs.h>

#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#endif

#ifdef CONFIG_XNUPOST
#include <tests/xnupost.h>
#endif


#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif /* HIBERNATION */

#define PMAP_ROOT_ALLOC_SIZE (ARM_PGBYTES)

#define ARRAY_LEN(x) (sizeof (x) / sizeof (x[0]))

/**
 * Per-CPU data used to do setup and post-processing for SPTM calls.
 * On the setup side, this structure is used to store parameters for batched SPTM operations.
 * These parameters may be large (upwards of 1K), and given that SPTM calls are generally
 * issued from preemption-disabled contexts anyway, it's better to store them in per-CPU
 * data rather than the local stack.
 * On the post-processing side, this structure exposes a pointer to the SPTM's per-CPU array
 * of 'prev_ptes', that is the prior value encountered in each PTE at the time of the SPTM's
 * atomic update of that PTE.
 */
pmap_sptm_percpu_data_t PERCPU_DATA(pmap_sptm_percpu);

/**
 * Boot-arg to enable/disable the use of XNU_KERNEL_RESTRICTED and XNU_PGZ
 * types in SPTM.
 */
#if XNU_TARGET_OS_IOS
TUNABLE(bool, use_xnu_restricted, "xnu_restricted", true);
#else
TUNABLE(bool, use_xnu_restricted, "xnu_restricted", false);
#endif // XNU_TARGET_OS_IOS

extern u_int32_t random(void); /* from <libkern/libkern.h> */

static bool alloc_asid(pmap_t pmap);
static void free_asid(pmap_t pmap);
static void flush_mmu_tlb_region_asid_async(vm_offset_t va, size_t length, pmap_t pmap, bool last_level_only);
static pt_entry_t wimg_to_pte(unsigned int wimg, pmap_paddr_t pa);

const struct page_table_ops native_pt_ops =
{
	.alloc_id = alloc_asid,
	.free_id = free_asid,
	.flush_tlb_region_async = flush_mmu_tlb_region_asid_async,
	.wimg_to_pte = wimg_to_pte,
};

const struct page_table_level_info pmap_table_level_info_16k[] =
{
	[0] = {
		.size       = ARM_16K_TT_L0_SIZE,
		.offmask    = ARM_16K_TT_L0_OFFMASK,
		.shift      = ARM_16K_TT_L0_SHIFT,
		.index_mask = ARM_16K_TT_L0_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[1] = {
		.size       = ARM_16K_TT_L1_SIZE,
		.offmask    = ARM_16K_TT_L1_OFFMASK,
		.shift      = ARM_16K_TT_L1_SHIFT,
		.index_mask = ARM_16K_TT_L1_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[2] = {
		.size       = ARM_16K_TT_L2_SIZE,
		.offmask    = ARM_16K_TT_L2_OFFMASK,
		.shift      = ARM_16K_TT_L2_SHIFT,
		.index_mask = ARM_16K_TT_L2_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[3] = {
		.size       = ARM_16K_TT_L3_SIZE,
		.offmask    = ARM_16K_TT_L3_OFFMASK,
		.shift      = ARM_16K_TT_L3_SHIFT,
		.index_mask = ARM_16K_TT_L3_INDEX_MASK,
		.valid_mask = ARM_PTE_TYPE_VALID,
		.type_mask  = ARM_PTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_L3BLOCK
	}
};

const struct page_table_level_info pmap_table_level_info_4k[] =
{
	[0] = {
		.size       = ARM_4K_TT_L0_SIZE,
		.offmask    = ARM_4K_TT_L0_OFFMASK,
		.shift      = ARM_4K_TT_L0_SHIFT,
		.index_mask = ARM_4K_TT_L0_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[1] = {
		.size       = ARM_4K_TT_L1_SIZE,
		.offmask    = ARM_4K_TT_L1_OFFMASK,
		.shift      = ARM_4K_TT_L1_SHIFT,
		.index_mask = ARM_4K_TT_L1_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[2] = {
		.size       = ARM_4K_TT_L2_SIZE,
		.offmask    = ARM_4K_TT_L2_OFFMASK,
		.shift      = ARM_4K_TT_L2_SHIFT,
		.index_mask = ARM_4K_TT_L2_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[3] = {
		.size       = ARM_4K_TT_L3_SIZE,
		.offmask    = ARM_4K_TT_L3_OFFMASK,
		.shift      = ARM_4K_TT_L3_SHIFT,
		.index_mask = ARM_4K_TT_L3_INDEX_MASK,
		.valid_mask = ARM_PTE_TYPE_VALID,
		.type_mask  = ARM_PTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_L3BLOCK
	}
};

const struct page_table_attr pmap_pt_attr_4k = {
	.pta_level_info = pmap_table_level_info_4k,
	.pta_root_level = (T0SZ_BOOT - 16) / 9,
#if __ARM_MIXED_PAGE_SIZE__
	.pta_commpage_level = PMAP_TT_L2_LEVEL,
#else /* __ARM_MIXED_PAGE_SIZE__ */
#if __ARM_16K_PG__
	.pta_commpage_level = PMAP_TT_L2_LEVEL,
#else /* __ARM_16K_PG__ */
	.pta_commpage_level = PMAP_TT_L1_LEVEL,
#endif /* __ARM_16K_PG__ */
#endif /* __ARM_MIXED_PAGE_SIZE__ */
	.pta_max_level  = PMAP_TT_L3_LEVEL,
	.pta_ops = &native_pt_ops,
	.ap_ro = ARM_PTE_AP(AP_RORO),
	.ap_rw = ARM_PTE_AP(AP_RWRW),
	.ap_rona = ARM_PTE_AP(AP_RONA),
	.ap_rwna = ARM_PTE_AP(AP_RWNA),
	.ap_xn = ARM_PTE_PNX | ARM_PTE_NX,
	.ap_x = ARM_PTE_PNX,
#if __ARM_MIXED_PAGE_SIZE__
	.pta_tcr_value  = TCR_EL1_4KB,
#endif /* __ARM_MIXED_PAGE_SIZE__ */
	.pta_page_size  = 4096,
	.pta_page_shift = 12,
};

const struct page_table_attr pmap_pt_attr_16k = {
	.pta_level_info = pmap_table_level_info_16k,
	.pta_root_level = PMAP_TT_L1_LEVEL,
	.pta_commpage_level = PMAP_TT_L2_LEVEL,
	.pta_max_level  = PMAP_TT_L3_LEVEL,
	.pta_ops = &native_pt_ops,
	.ap_ro = ARM_PTE_AP(AP_RORO),
	.ap_rw = ARM_PTE_AP(AP_RWRW),
	.ap_rona = ARM_PTE_AP(AP_RONA),
	.ap_rwna = ARM_PTE_AP(AP_RWNA),
	.ap_xn = ARM_PTE_PNX | ARM_PTE_NX,
	.ap_x = ARM_PTE_PNX,
#if __ARM_MIXED_PAGE_SIZE__
	.pta_tcr_value  = TCR_EL1_16KB,
#endif /* __ARM_MIXED_PAGE_SIZE__ */
	.pta_page_size  = 16384,
	.pta_page_shift = 14,
};

#if __ARM_16K_PG__
const struct page_table_attr * const native_pt_attr = &pmap_pt_attr_16k;
#else /* !__ARM_16K_PG__ */
const struct page_table_attr * const native_pt_attr = &pmap_pt_attr_4k;
#endif /* !__ARM_16K_PG__ */


#if MACH_ASSERT
int vm_footprint_suspend_allowed = 1;

extern int pmap_ledgers_panic;
extern int pmap_ledgers_panic_leeway;

#endif /* MACH_ASSERT */

#if DEVELOPMENT || DEBUG
#define PMAP_FOOTPRINT_SUSPENDED(pmap) \
	(current_thread()->pmap_footprint_suspended)
#else /* DEVELOPMENT || DEBUG */
#define PMAP_FOOTPRINT_SUSPENDED(pmap) (FALSE)
#endif /* DEVELOPMENT || DEBUG */


/*
 * Represents a tlb range that will be flushed before returning from the pmap.
 * Used by phys_attribute_clear_range to defer flushing pages in this range until
 * the end of the operation, and to accumulate batched operations for submission
 * to the SPTM as a performance optimization.
 */
typedef struct pmap_tlb_flush_range {
	/* Address space in which the flush region resides */
	pmap_t ptfr_pmap;

	/* Page-aligned beginning of the flush region */
	vm_map_address_t ptfr_start;

	/* Page-aligned non-inclusive end of the flush region */
	vm_map_address_t ptfr_end;

	/**
	 * Address of current PTE position in ptfr_pmap's [ptfr_start, ptfr_end) region.
	 * This is meant to be set up by the caller of pmap_page_protect_options_with_flush_range()
	 * or arm_force_fast_fault_with_flush_range(), and used by those functions to determine
	 * when a given mapping can be added to the SPTM's per-CPU region templates array vs.
	 * the more complex task of adding it to the disjoint ops array.
	 */
	pt_entry_t *current_ptep;

	/**
	 * Starting VA for any not-yet-submitted per-CPU region templates.  This is meant to be
	 * set up by the caller of pmap_page_protect_options_with_flush_range() or
	 * arm_force_fast_fault_with_flush_range() and used by pmap_multipage_op_submit_region()
	 * when issuing the SPTM call to purge any pending region ops.
	 */
	vm_map_address_t pending_region_start;

	/**
	 * Number of entries in the per-CPU SPTM region templates array which have not
	 * yet been submitted to the SPTM.
	 */
	unsigned int pending_region_entries;

	/**
	 * Indicates whether at least one region entry was added to the per-CPU region ops
	 * array since the last time this field was checked.  Intended to be cleared by the
	 * caller.
	 */
	bool region_entry_added;

	/**
	 * Marker for the current paddr "header" entry in the per-CPU SPTM disjoint ops array.
	 * This field is intended to be modified only by pmap_multipage_op_submit_disjoint()
	 * and pmap_multipage_op_add_page(), and should be treated as opaque by callers
	 * of those functions.
	 */
	sptm_update_disjoint_multipage_op_t *current_header;

	/**
	 * Position in the per-CPU SPTM ops array of the first ordinary
	 * sptm_disjoint_op_t entry following [current_header].  This is the starting
	 * point at which mappings should be inserted for the page described by
	 * [current_header].
	 */
	unsigned int current_header_first_mapping_index;

	/**
	 * Number of entries in the per-CPU SPTM disjoint ops array, including paddr headers,
	 * which have not yet been submitted to the SPTM.
	 */
	unsigned int pending_disjoint_entries;

	/**
	 * Total entries submitted to the SPTM for the current flush range.
	 * This field is used by the preemption check interval logic on the
	 * phys_attribute_clear_range() path to determine when sufficient
	 * forward progress has been made to check for and (if necessary)
	 * handle pending preemption.
	 */
	unsigned int submitted_entries;

	/**
	 * Indicates whether the top-level caller needs to flush the TLB for
	 * the region in [ptfr_pmap] described by [ptfr_start, ptfr_end).
	 * This will be set if the SPTM indicates that it needed to alter
	 * any valid mapping within this region and SPTM_UPDATE_DEFER_TLBI
	 * was passed to the relevant SPTM call(s).
	 */
	bool ptfr_flush_needed;
} pmap_tlb_flush_range_t;



/* Virtual memory region for early allocation */
#define VREGION1_HIGH_WINDOW    (PE_EARLY_BOOT_VA)
#define VREGION1_START          ((VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK) - VREGION1_HIGH_WINDOW)
#define VREGION1_SIZE           (trunc_page(VM_MAX_KERNEL_ADDRESS - (VREGION1_START)))

extern uint8_t bootstrap_pagetables[];

extern unsigned int not_in_kdp;

extern vm_offset_t first_avail;

extern vm_offset_t     virtual_space_start;     /* Next available kernel VA */
extern vm_offset_t     virtual_space_end;       /* End of kernel address space */
extern vm_offset_t     static_memory_end;

extern const vm_map_address_t physmap_base;
extern const vm_map_address_t physmap_end;

extern int maxproc, hard_maxproc;

extern bool sdsb_io_rgns_present;

vm_address_t MARK_AS_PMAP_DATA image4_slab = 0;
vm_address_t MARK_AS_PMAP_DATA image4_late_slab = 0;

/* The number of address bits one TTBR can cover. */
#define PGTABLE_ADDR_BITS (64ULL - T0SZ_BOOT)

/*
 * The bounds on our TTBRs.  These are for sanity checking that
 * an address is accessible by a TTBR before we attempt to map it.
 */

/* The level of the root of a page table. */
const uint64_t arm64_root_pgtable_level = (3 - ((PGTABLE_ADDR_BITS - 1 - ARM_PGSHIFT) / (ARM_PGSHIFT - TTE_SHIFT)));

/* The number of entries in the root TT of a page table. */
const uint64_t arm64_root_pgtable_num_ttes = (2 << ((PGTABLE_ADDR_BITS - 1 - ARM_PGSHIFT) % (ARM_PGSHIFT - TTE_SHIFT)));

struct pmap     kernel_pmap_store MARK_AS_PMAP_DATA;
const pmap_t    kernel_pmap = &kernel_pmap_store;

static SECURITY_READ_ONLY_LATE(zone_t) pmap_zone;  /* zone of pmap structures */

MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmaps_lock, 0);
queue_head_t    map_pmap_list MARK_AS_PMAP_DATA;

typedef struct tt_free_entry {
	struct tt_free_entry    *next;
} tt_free_entry_t;

unsigned int    inuse_user_ttepages_count MARK_AS_PMAP_DATA = 0; /* non-root, non-leaf user pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_user_ptepages_count MARK_AS_PMAP_DATA = 0; /* leaf user pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_user_tteroot_count MARK_AS_PMAP_DATA = 0;  /* root user pagetables, in units of PMAP_ROOT_ALLOC_SIZE */
unsigned int    inuse_kernel_ttepages_count MARK_AS_PMAP_DATA = 0; /* non-root, non-leaf kernel pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_kernel_ptepages_count MARK_AS_PMAP_DATA = 0; /* leaf kernel pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_kernel_tteroot_count MARK_AS_PMAP_DATA = 0; /* root kernel pagetables, in units of PMAP_ROOT_ALLOC_SIZE */
_Atomic unsigned int inuse_iommu_pages_count[SPTM_IOMMUS_N_IDS] = {0}; /* number of active pages for each IOMMU class */

SECURITY_READ_ONLY_LATE(tt_entry_t *) invalid_tte  = 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t) invalid_ttep = 0;

SECURITY_READ_ONLY_LATE(tt_entry_t *) cpu_tte  = 0;                     /* set by arm_vm_init() - keep out of bss */
SECURITY_READ_ONLY_LATE(pmap_paddr_t) cpu_ttep = 0;                     /* set by arm_vm_init() - phys tte addr */

/* Lock group used for all pmap object locks. */
lck_grp_t pmap_lck_grp MARK_AS_PMAP_DATA;

#if DEVELOPMENT || DEBUG
int nx_enabled = 1;                                     /* enable no-execute protection */
int allow_data_exec  = 0;                               /* No apps may execute data */
int allow_stack_exec = 0;                               /* No apps may execute from the stack */
unsigned long pmap_asid_flushes MARK_AS_PMAP_DATA = 0;
unsigned long pmap_asid_hits MARK_AS_PMAP_DATA = 0;
unsigned long pmap_asid_misses MARK_AS_PMAP_DATA = 0;
#else /* DEVELOPMENT || DEBUG */
const int nx_enabled = 1;                                       /* enable no-execute protection */
const int allow_data_exec  = 0;                         /* No apps may execute data */
const int allow_stack_exec = 0;                         /* No apps may execute from the stack */
#endif /* DEVELOPMENT || DEBUG */

/**
 * This variable is set true during hibernation entry to protect pmap data structures
 * during image copying, and reset false on hibernation exit.
 */
bool hib_entry_pmap_lockdown MARK_AS_PMAP_DATA = false;

#if MACH_ASSERT
static void pmap_check_ledgers(pmap_t pmap);
#else
static inline void
pmap_check_ledgers(__unused pmap_t pmap)
{
}
#endif /* MACH_ASSERT */

/**
 * This helper function ensures that potentially-long-running batched PPL operations are
 * called in preemptible context before entering the PPL, so that the PPL call may
 * periodically exit to allow pending urgent ASTs to be taken.
 */
static inline void
pmap_verify_preemptible(void)
{
	assert(preemption_enabled() || (startup_phase < STARTUP_SUB_EARLY_BOOT));
}

SIMPLE_LOCK_DECLARE(phys_backup_lock, 0);

SECURITY_READ_ONLY_LATE(pmap_paddr_t)   vm_first_phys = (pmap_paddr_t) 0;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)   vm_last_phys = (pmap_paddr_t) 0;

SECURITY_READ_ONLY_LATE(boolean_t)      pmap_initialized = FALSE;       /* Has pmap_init completed? */

SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm_pmap_max_offset_default  = 0x0;

/* end of shared region + 512MB for various purposes */
#define ARM64_MIN_MAX_ADDRESS (SHARED_REGION_BASE_ARM64 + SHARED_REGION_SIZE_ARM64 + 0x20000000)
_Static_assert((ARM64_MIN_MAX_ADDRESS > SHARED_REGION_BASE_ARM64) && (ARM64_MIN_MAX_ADDRESS <= MACH_VM_MAX_ADDRESS),
    "Minimum address space size outside allowable range");

// Max offset is 15.375GB for devices with "large" memory config
#define ARM64_MAX_OFFSET_DEVICE_LARGE (ARM64_MIN_MAX_ADDRESS + 0x138000000)
// Max offset is 11.375GB for devices with "small" memory config
#define ARM64_MAX_OFFSET_DEVICE_SMALL (ARM64_MIN_MAX_ADDRESS + 0x38000000)


_Static_assert((ARM64_MAX_OFFSET_DEVICE_LARGE > ARM64_MIN_MAX_ADDRESS) && (ARM64_MAX_OFFSET_DEVICE_LARGE <= MACH_VM_MAX_ADDRESS),
    "Large device address space size outside allowable range");
_Static_assert((ARM64_MAX_OFFSET_DEVICE_SMALL > ARM64_MIN_MAX_ADDRESS) && (ARM64_MAX_OFFSET_DEVICE_SMALL <= MACH_VM_MAX_ADDRESS),
    "Small device address space size outside allowable range");

#  ifdef XNU_TARGET_OS_OSX
SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm64_pmap_max_offset_default = MACH_VM_MAX_ADDRESS;
#  else
SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm64_pmap_max_offset_default = 0x0;
#  endif

#if PMAP_PANIC_DEV_WIMG_ON_MANAGED && (DEVELOPMENT || DEBUG)
SECURITY_READ_ONLY_LATE(boolean_t)   pmap_panic_dev_wimg_on_managed = TRUE;
#else
SECURITY_READ_ONLY_LATE(boolean_t)   pmap_panic_dev_wimg_on_managed = FALSE;
#endif

MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(asid_lock, 0);
SECURITY_READ_ONLY_LATE(uint32_t) pmap_max_asids = 0;
SECURITY_READ_ONLY_LATE(static bitmap_t*) asid_bitmap;
#if !HAS_16BIT_ASID
static bitmap_t asid_plru_bitmap[BITMAP_LEN(MAX_HW_ASIDS)] MARK_AS_PMAP_DATA;
static uint64_t asid_plru_generation[BITMAP_LEN(MAX_HW_ASIDS)] MARK_AS_PMAP_DATA = {0};
static uint64_t asid_plru_gencount MARK_AS_PMAP_DATA = 0;
SECURITY_READ_ONLY_LATE(int) pmap_asid_plru = 1;
#else
static uint16_t last_allocated_asid = 0;
#endif /* !HAS_16BIT_ASID */


SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage_default_table;
//SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage32_default_table;
#if __ARM_MIXED_PAGE_SIZE__
SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage_4k_table;
//SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage32_4k_table;
#endif
SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage_data_pa = 0;
SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage_text_pa = 0;
SECURITY_READ_ONLY_LATE(static pmap_paddr_t) commpage_ro_data_pa = 0;

/* PTE Define Macros */

#ifndef SPTM_PTE_IN_FLIGHT_MARKER
/* SPTM TODO: Get rid of this once we export SPTM_PTE_IN_FLIGHT_MARKER from the SPTM. */
#define SPTM_PTE_IN_FLIGHT_MARKER 0x80U
#endif /* SPTM_PTE_IN_FLIGHT_MARKER */

/**
 * Determine whether a PTE has been marked as compressed.  This function also panics if
 * the PTE contains bits that shouldn't be present in a compressed PTE, which is most of them.
 *
 * @param pte the PTE contents to check
 * @param ptep the address of the PTE contents, for diagnostic purposes only
 *
 * @return true if the PTE is compressed, false otherwise
 */
static inline bool
pte_is_compressed(pt_entry_t pte, pt_entry_t *ptep)
{
	const bool compressed = (((pte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE_FAULT) && (pte & ARM_PTE_COMPRESSED));
	/**
	 * Check for bits that shouldn't be present in a compressed PTE.  This is everything except the
	 * compressed/compressed-alt bits, as well as the SPTM's in-flight marker which may be set while
	 * the SPTM is in the process of flushing the TLBs after marking a previously-valid PTE as
	 * compressed.
	 */
	if (__improbable(compressed && (pte & ~(ARM_PTE_COMPRESSED_MASK | SPTM_PTE_IN_FLIGHT_MARKER)))) {
		panic("compressed PTE %p 0x%llx has extra bits 0x%llx: corrupted?",
		    ptep, pte, pte & ~(ARM_PTE_COMPRESSED_MASK | SPTM_PTE_IN_FLIGHT_MARKER));
	}
	return compressed;
}

#define pte_is_wired(pte)                                                               \
	(((pte) & ARM_PTE_WIRED_MASK) == ARM_PTE_WIRED)

#define pte_was_writeable(pte) \
	(((pte) & ARM_PTE_WRITEABLE) == ARM_PTE_WRITEABLE)

#define pte_set_was_writeable(pte, was_writeable) \
	do {                                         \
	        if ((was_writeable)) {               \
	                (pte) |= ARM_PTE_WRITEABLE;  \
	        } else {                             \
	                (pte) &= ~ARM_PTE_WRITEABLE; \
	        }                                    \
	} while(0)


/**
 * Updated wired-mapping accountings in the PTD and ledger.
 *
 * @param pmap The pmap against which to update accounting
 * @param pte_p The PTE whose wired state is being changed
 * @param wired Indicates whether the PTE is being wired or unwired.
 */
static inline void
pte_update_wiredcnt(pmap_t pmap, pt_entry_t *pte_p, boolean_t wired)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	unsigned short *ptd_wiredcnt_ptr = &(ptep_get_info(pte_p)->wiredcnt);
	if (wired) {
		if (__improbable(os_atomic_inc_orig(ptd_wiredcnt_ptr, relaxed) == UINT16_MAX)) {
			panic("pmap %p (pte %p): wired count overflow", pmap, pte_p);
		}
		pmap_ledger_credit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
	} else {
		if (__improbable(os_atomic_dec_orig(ptd_wiredcnt_ptr, relaxed) == 0)) {
			panic("pmap %p (pte %p): wired count underflow", pmap, pte_p);
		}
		pmap_ledger_debit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
	}
}

/*
 * Synchronize updates to PTEs that were previously invalid or had the AF bit cleared,
 * therefore not requiring TLBI.  Use a store-load barrier to ensure subsequent loads
 * will observe the updated PTE.
 */
#define FLUSH_PTE()                                                                     \
	__builtin_arm_dmb(DMB_ISH);

/*
 * Synchronize updates to PTEs that were previously valid and thus may be cached in
 * TLBs.  DSB is required to ensure the PTE stores have completed prior to the ensuing
 * TLBI.  This should only require a store-store barrier, as subsequent accesses in
 * program order will not issue until the DSB completes.  Prior loads may be reordered
 * after the barrier, but their behavior should not be materially affected by the
 * reordering.  For fault-driven PTE updates such as COW, PTE contents should not
 * matter for loads until the access is re-driven well after the TLB update is
 * synchronized.   For "involuntary" PTE access restriction due to paging lifecycle,
 * we should be in a position to handle access faults.  For "voluntary" PTE access
 * restriction due to unmapping or protection, the decision to restrict access should
 * have a data dependency on prior loads in order to avoid a data race.
 */
#define FLUSH_PTE_STRONG()                                                             \
	__builtin_arm_dsb(DSB_ISHST);

/**
 * Write enough page table entries to map a single VM page. On systems where the
 * VM page size does not match the hardware page size, multiple page table
 * entries will need to be written.
 *
 * @note This function does not emit a barrier to ensure these page table writes
 *       have completed before continuing. This is commonly needed. In the case
 *       where a DMB or DSB barrier is needed, then use the write_pte() and
 *       write_pte_strong() functions respectively instead of this one.
 *
 * @param ptep Pointer to the first page table entry to update.
 * @param pte The value to write into each page table entry. In the case that
 *            multiple PTEs are updated to a non-empty value, then the address
 *            in this value will automatically be incremented for each PTE
 *            write.
 */
static void
write_pte_fast(pt_entry_t *ptep, pt_entry_t pte)
{
	/**
	 * The PAGE_SHIFT (and in turn, the PAGE_RATIO) can be a variable on some
	 * systems, which is why it's checked at runtime instead of compile time.
	 * The "unreachable" warning needs to be suppressed because it still is a
	 * compile time constant on some systems.
	 */
	__unreachable_ok_push
	if (TEST_PAGE_RATIO_4) {
		if (((uintptr_t)ptep) & 0x1f) {
			panic("%s: PTE write is unaligned, ptep=%p, pte=%p",
			    __func__, ptep, (void*)pte);
		}

		if ((pte & ~ARM_PTE_COMPRESSED_MASK) == ARM_PTE_EMPTY) {
			/**
			 * If we're writing an empty/compressed PTE value, then don't
			 * auto-increment the address for each PTE write.
			 */
			*ptep = pte;
			*(ptep + 1) = pte;
			*(ptep + 2) = pte;
			*(ptep + 3) = pte;
		} else {
			*ptep = pte;
			*(ptep + 1) = pte | 0x1000;
			*(ptep + 2) = pte | 0x2000;
			*(ptep + 3) = pte | 0x3000;
		}
	} else {
		*ptep = pte;
	}
	__unreachable_ok_pop
}

/**
 * Writes enough page table entries to map a single VM page and then ensures
 * those writes complete by executing a Data Memory Barrier.
 *
 * @note The DMB issued by this function is not strong enough to protect against
 *       TLB invalidates from being reordered above the PTE writes. If a TLBI
 *       instruction is going to immediately be called after this write, it's
 *       recommended to call write_pte_strong() instead of this function.
 *
 * See the function header for write_pte_fast() for more details on the
 * parameters.
 */
void
write_pte(pt_entry_t *ptep, pt_entry_t pte)
{
	write_pte_fast(ptep, pte);
	FLUSH_PTE();
}

/**
 * Retrieve the pmap structure for the thread running on the current CPU.
 */
pmap_t
current_pmap()
{
	const pmap_t current = vm_map_pmap(current_thread()->map);
	assert(current != NULL);
	return current;
}

#if DEVELOPMENT || DEBUG

/*
 * Trace levels are controlled by a bitmask in which each
 * level can be enabled/disabled by the (1<<level) position
 * in the boot arg
 * Level 0: PPL extension functionality
 * Level 1: pmap lifecycle (create/destroy/switch)
 * Level 2: mapping lifecycle (enter/remove/protect/nest/unnest)
 * Level 3: internal state management (attributes/fast-fault)
 * Level 4-7: TTE traces for paging levels 0-3.  TTBs are traced at level 4.
 */

SECURITY_READ_ONLY_LATE(unsigned int) pmap_trace_mask = 0;

#define PMAP_TRACE(level, ...) \
	if (__improbable((1 << (level)) & pmap_trace_mask)) { \
	        KDBG_RELEASE(__VA_ARGS__); \
	}
#else /* DEVELOPMENT || DEBUG */

#define PMAP_TRACE(level, ...)

#endif /* DEVELOPMENT || DEBUG */


/*
 * Internal function prototypes (forward declarations).
 */

static vm_map_size_t pmap_user_va_size(pmap_t pmap);

static void pmap_set_reference(ppnum_t pn);

pmap_paddr_t pmap_vtophys(pmap_t pmap, addr64_t va);

static kern_return_t pmap_expand(
	pmap_t, vm_map_address_t, unsigned int options, unsigned int level);

static void pmap_remove_range(pmap_t, vm_map_address_t, vm_map_address_t);

static tt_entry_t *pmap_tt1_allocate(pmap_t, uint8_t);

static void pmap_tt1_deallocate(pmap_t, tt_entry_t *);

static kern_return_t pmap_tt_allocate(
	pmap_t, tt_entry_t **, unsigned int, unsigned int);

const unsigned int arm_hardware_page_size = ARM_PGBYTES;
const unsigned int arm_pt_desc_size = sizeof(pt_desc_t);
const unsigned int arm_pt_root_size = PMAP_ROOT_ALLOC_SIZE;

static void pmap_unmap_commpage(
	pmap_t pmap);

static boolean_t
pmap_is_64bit(pmap_t);


static void pmap_flush_tlb_for_paddr_async(pmap_paddr_t);

static void pmap_update_pp_attr_wimg_bits_locked(unsigned int, unsigned int);

static boolean_t arm_clear_fast_fault(
	ppnum_t ppnum,
	vm_prot_t fault_type,
	uintptr_t pvh,
	pt_entry_t *pte_p,
	pp_attr_t attrs_to_clear);

static void pmap_trim_self(pmap_t pmap);
static void pmap_trim_subord(pmap_t subord);


/*
 * Temporary prototypes, while we wait for pmap_enter to move to taking an
 * address instead of a page number.
 */
kern_return_t
pmap_enter(
	pmap_t pmap,
	vm_map_address_t v,
	ppnum_t pn,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	pmap_mapping_type_t mapping_type);

static kern_return_t
pmap_enter_addr(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	pmap_mapping_type_t mapping_type);

kern_return_t
pmap_enter_options_addr(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	__unused void   *arg,
	pmap_mapping_type_t mapping_type);

#ifdef CONFIG_XNUPOST
kern_return_t pmap_test(void);
#endif /* CONFIG_XNUPOST */

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	arm_fast_fault, (pmap_t pmap,
	vm_map_address_t va,
	vm_prot_t fault_type,
	bool was_af_fault,
	bool from_user), ARM_FAST_FAULT_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	boolean_t,
	arm_force_fast_fault, (ppnum_t ppnum,
	vm_prot_t allow_mode,
	int options), ARM_FORCE_FAST_FAULT_INDEX);

MARK_AS_PMAP_TEXT static boolean_t
arm_force_fast_fault_with_flush_range(
	ppnum_t ppnum,
	vm_prot_t allow_mode,
	int options,
	locked_pvh_t *locked_pvh,
	pp_attr_t bits_to_clear,
	pmap_tlb_flush_range_t *flush_range);

PMAP_SUPPORT_PROTOTYPES(
	bool,
	pmap_batch_set_cache_attributes, (
		upl_page_info_array_t user_page_list,
		unsigned int page_cnt,
		unsigned int cacheattr,
		bool update_attr_table), PMAP_BATCH_SET_CACHE_ATTRIBUTES_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_change_wiring, (pmap_t pmap,
	vm_map_address_t v,
	boolean_t wired), PMAP_CHANGE_WIRING_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	pmap_t,
	pmap_create_options, (ledger_t ledger,
	vm_map_size_t size,
	unsigned int flags,
	kern_return_t * kr), PMAP_CREATE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_destroy, (pmap_t pmap), PMAP_DESTROY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_enter_options, (pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	pmap_mapping_type_t mapping_type), PMAP_ENTER_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	pmap_paddr_t,
	pmap_find_pa, (pmap_t pmap,
	addr64_t va), PMAP_FIND_PA_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_insert_commpage, (pmap_t pmap), PMAP_INSERT_COMMPAGE_INDEX);


PMAP_SUPPORT_PROTOTYPES(
	boolean_t,
	pmap_is_empty, (pmap_t pmap,
	vm_map_offset_t va_start,
	vm_map_offset_t va_end), PMAP_IS_EMPTY_INDEX);


PMAP_SUPPORT_PROTOTYPES(
	unsigned int,
	pmap_map_cpu_windows_copy, (ppnum_t pn,
	vm_prot_t prot,
	unsigned int wimg_bits), PMAP_MAP_CPU_WINDOWS_COPY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_ro_zone_memcpy, (zone_id_t zid,
	vm_offset_t va,
	vm_offset_t offset,
	const vm_offset_t new_data,
	vm_size_t new_data_size), PMAP_RO_ZONE_MEMCPY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	uint64_t,
	pmap_ro_zone_atomic_op, (zone_id_t zid,
	vm_offset_t va,
	vm_offset_t offset,
	zro_atomic_op_t op,
	uint64_t value), PMAP_RO_ZONE_ATOMIC_OP_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_ro_zone_bzero, (zone_id_t zid,
	vm_offset_t va,
	vm_offset_t offset,
	vm_size_t size), PMAP_RO_ZONE_BZERO_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	vm_map_offset_t,
	pmap_nest, (pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size,
	vm_map_offset_t vrestart,
	kern_return_t * krp), PMAP_NEST_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_page_protect_options, (ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options,
	void *arg), PMAP_PAGE_PROTECT_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	vm_map_address_t,
	pmap_protect_options, (pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	vm_prot_t prot,
	unsigned int options,
	void *args), PMAP_PROTECT_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_query_page_info, (pmap_t pmap,
	vm_map_offset_t va,
	int *disp_p), PMAP_QUERY_PAGE_INFO_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	mach_vm_size_t,
	pmap_query_resident, (pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	mach_vm_size_t * compressed_bytes_p), PMAP_QUERY_RESIDENT_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_reference, (pmap_t pmap), PMAP_REFERENCE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	vm_map_address_t,
	pmap_remove_options, (pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options), PMAP_REMOVE_OPTIONS_INDEX);


PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_cache_attributes, (ppnum_t pn,
	unsigned int cacheattr,
	bool update_attr_table), PMAP_SET_CACHE_ATTRIBUTES_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_update_compressor_page, (ppnum_t pn,
	unsigned int prev_cacheattr, unsigned int new_cacheattr), PMAP_UPDATE_COMPRESSOR_PAGE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_nested, (pmap_t pmap), PMAP_SET_NESTED_INDEX);

#if MACH_ASSERT
PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_process, (pmap_t pmap,
	int pid,
	char *procname), PMAP_SET_PROCESS_INDEX);
#endif

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_unmap_cpu_windows_copy, (unsigned int index), PMAP_UNMAP_CPU_WINDOWS_COPY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	vm_map_offset_t,
	pmap_unnest_options, (pmap_t grand,
	addr64_t vaddr,
	uint64_t size,
	vm_map_offset_t vrestart,
	unsigned int option), PMAP_UNNEST_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	phys_attribute_set, (ppnum_t pn,
	unsigned int bits), PHYS_ATTRIBUTE_SET_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	phys_attribute_clear, (ppnum_t pn,
	unsigned int bits,
	int options,
	void *arg), PHYS_ATTRIBUTE_CLEAR_INDEX);

#if __ARM_RANGE_TLBI__
PMAP_SUPPORT_PROTOTYPES(
	vm_map_address_t,
	phys_attribute_clear_range, (pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	unsigned int bits,
	unsigned int options), PHYS_ATTRIBUTE_CLEAR_RANGE_INDEX);
#endif /* __ARM_RANGE_TLBI__ */


PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_switch, (pmap_t pmap), PMAP_SWITCH_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_clear_user_ttb, (void), PMAP_CLEAR_USER_TTB_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_vm_map_cs_enforced, (pmap_t pmap, bool new_value), PMAP_SET_VM_MAP_CS_ENFORCED_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_tpro, (pmap_t pmap), PMAP_SET_TPRO_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_jit_entitled, (pmap_t pmap), PMAP_SET_JIT_ENTITLED_INDEX);

#if __has_feature(ptrauth_calls) && (defined(XNU_TARGET_OS_OSX) || (DEVELOPMENT || DEBUG))
PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_disable_user_jop, (pmap_t pmap), PMAP_DISABLE_USER_JOP_INDEX);
#endif /* __has_feature(ptrauth_calls) && (defined(XNU_TARGET_OS_OSX) || (DEVELOPMENT || DEBUG)) */

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_trim, (pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size), PMAP_TRIM_INDEX);

#if HAS_APPLE_PAC
PMAP_SUPPORT_PROTOTYPES(
	void *,
	pmap_sign_user_ptr, (void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key), PMAP_SIGN_USER_PTR);
PMAP_SUPPORT_PROTOTYPES(
	void *,
	pmap_auth_user_ptr, (void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key), PMAP_AUTH_USER_PTR);
#endif /* HAS_APPLE_PAC */


void pmap_footprint_suspend(vm_map_t    map,
    boolean_t   suspend);
PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_footprint_suspend, (vm_map_t map,
	boolean_t suspend),
	PMAP_FOOTPRINT_SUSPEND_INDEX);





/*
 * The low global vector page is mapped at a fixed alias.
 * Since the page size is 16k for H8 and newer we map the globals to a 16k
 * aligned address. Readers of the globals (e.g. lldb, panic server) need
 * to check both addresses anyway for backward compatibility. So for now
 * we leave H6 and H7 where they were.
 */
#if (ARM_PGSHIFT == 14)
#define LOWGLOBAL_ALIAS         (LOW_GLOBAL_BASE_ADDRESS + 0x4000)
#else
#define LOWGLOBAL_ALIAS         (LOW_GLOBAL_BASE_ADDRESS + 0x2000)
#endif

static inline void
PMAP_ZINFO_PALLOC(
	pmap_t pmap, int bytes)
{
	pmap_ledger_credit(pmap, task_ledgers.tkm_private, bytes);
}

static inline void
PMAP_ZINFO_PFREE(
	pmap_t pmap,
	int bytes)
{
	pmap_ledger_debit(pmap, task_ledgers.tkm_private, bytes);
}

void
pmap_tt_ledger_credit(
	pmap_t          pmap,
	vm_size_t       size)
{
	if (pmap != kernel_pmap) {
		pmap_ledger_credit(pmap, task_ledgers.phys_footprint, size);
		pmap_ledger_credit(pmap, task_ledgers.page_table, size);
	}
}

void
pmap_tt_ledger_debit(
	pmap_t          pmap,
	vm_size_t       size)
{
	if (pmap != kernel_pmap) {
		pmap_ledger_debit(pmap, task_ledgers.phys_footprint, size);
		pmap_ledger_debit(pmap, task_ledgers.page_table, size);
	}
}

static inline void
pmap_update_plru(uint16_t asid_index __unused)
{
#if !HAS_16BIT_ASID
	if (__probable(pmap_asid_plru)) {
		unsigned plru_index = asid_index >> 6;
		if (__improbable(os_atomic_andnot(&asid_plru_bitmap[plru_index], (1ULL << (asid_index & 63)), relaxed) == 0)) {
			asid_plru_generation[plru_index] = ++asid_plru_gencount;
			asid_plru_bitmap[plru_index] = ((plru_index == 0) ? ~1ULL : UINT64_MAX);
		}
	}
#endif /* !HAS_16BIT_ASID */
}

static bool
alloc_asid(pmap_t pmap)
{
	int vasid = -1;

	pmap_simple_lock(&asid_lock);

#if !HAS_16BIT_ASID
	if (__probable(pmap_asid_plru)) {
		unsigned plru_index = 0;
		uint64_t lowest_gen = asid_plru_generation[0];
		uint64_t lowest_gen_bitmap = asid_plru_bitmap[0];
		for (unsigned i = 1; i < (sizeof(asid_plru_generation) / sizeof(asid_plru_generation[0])); ++i) {
			if (asid_plru_generation[i] < lowest_gen) {
				plru_index = i;
				lowest_gen = asid_plru_generation[i];
				lowest_gen_bitmap = asid_plru_bitmap[i];
			}
		}

		for (; plru_index < BITMAP_LEN(pmap_max_asids); plru_index += (MAX_HW_ASIDS >> 6)) {
			uint64_t temp_plru = lowest_gen_bitmap & asid_bitmap[plru_index];
			if (temp_plru) {
				vasid = (plru_index << 6) + lsb_first(temp_plru);
#if DEVELOPMENT || DEBUG
				++pmap_asid_hits;
#endif
				break;
			}
		}
	}
#else
	/**
	 * For 16-bit ASID targets, we assume a 1:1 correspondence between ASIDs and active tasks and
	 * therefore allocate directly from the ASID bitmap instead of using the pLRU allocator.
	 * However, we first try to allocate starting from the position of the most-recently allocated
	 * ASID.  This is done both as an allocator performance optimization (as it avoids crowding the
	 * lower bit positions and then re-checking those same lower positions every time we allocate
	 * an ASID) as well as a security mitigation to increase the temporal distance between ASID
	 * reuse.  This increases the difficulty of leveraging ASID reuse to train branch predictor
	 * logic, without requiring prohibitively expensive RCTX instructions.
	 */
	vasid = bitmap_lsb_next(&asid_bitmap[0], pmap_max_asids, last_allocated_asid);
#endif /* !HAS_16BIT_ASID */
	if (__improbable(vasid < 0)) {
		// bitmap_first() returns highest-order bits first, but a 0-based scheme works
		// slightly better with the collision detection scheme used by pmap_switch_internal().
		vasid = bitmap_lsb_first(&asid_bitmap[0], pmap_max_asids);
#if DEVELOPMENT || DEBUG
		++pmap_asid_misses;
#endif
	}
	if (__improbable(vasid < 0)) {
		pmap_simple_unlock(&asid_lock);
		return false;
	}
	assert((uint32_t)vasid < pmap_max_asids);
	assert(bitmap_test(&asid_bitmap[0], (unsigned int)vasid));
	bitmap_clear(&asid_bitmap[0], (unsigned int)vasid);
	const uint16_t hw_asid = (uint16_t)(vasid & (MAX_HW_ASIDS - 1));
#if HAS_16BIT_ASID
	last_allocated_asid = hw_asid;
#endif /* HAS_16BIT_ASID */
	pmap_simple_unlock(&asid_lock);
	assert(hw_asid != 0); // Should never alias kernel ASID
	pmap->asid = (uint16_t)vasid;
	pmap_update_plru(hw_asid);
	return true;
}

static void
free_asid(pmap_t pmap)
{
	const uint16_t vasid = os_atomic_xchg(&pmap->asid, 0, relaxed);
	if (__improbable(vasid == 0)) {
		return;
	}

#if !HAS_16BIT_ASID
	if (pmap_asid_plru) {
		const uint16_t hw_asid = vasid & (MAX_HW_ASIDS - 1);
		os_atomic_or(&asid_plru_bitmap[hw_asid >> 6], (1ULL << (hw_asid & 63)), relaxed);
	}
#endif /* !HAS_16BIT_ASID */
	pmap_simple_lock(&asid_lock);
	assert(!bitmap_test(&asid_bitmap[0], vasid));
	bitmap_set(&asid_bitmap[0], vasid);
	pmap_simple_unlock(&asid_lock);
}


boolean_t
pmap_valid_address(
	pmap_paddr_t addr)
{
	return pa_valid(addr);
}






/*
 *      Map memory at initialization.  The physical addresses being
 *      mapped are not managed and are never unmapped.
 *
 *      For now, VM is already on, we only need to map the
 *      specified memory.
 */
vm_map_address_t
pmap_map(
	vm_map_address_t virt,
	vm_offset_t start,
	vm_offset_t end,
	vm_prot_t prot,
	unsigned int flags)
{
	kern_return_t   kr;
	vm_size_t       ps;

	ps = PAGE_SIZE;
	while (start < end) {
		kr = pmap_enter(kernel_pmap, virt, (ppnum_t)atop(start),
		    prot, VM_PROT_NONE, flags, FALSE, PMAP_MAPPING_TYPE_INFER);

		if (kr != KERN_SUCCESS) {
			panic("%s: failed pmap_enter, "
			    "virt=%p, start_addr=%p, end_addr=%p, prot=%#x, flags=%#x",
			    __FUNCTION__,
			    (void *) virt, (void *) start, (void *) end, prot, flags);
		}

		virt += ps;
		start += ps;
	}
	return virt;
}

/**
 * Force the permission of a PTE to be kernel RO if a page has XNU_PROTECTED_IO type.
 *
 * @param paddr The physical address of the page.
 * @param tmplate The PTE value to be evaluated.
 *
 * @return A new PTE value with permission bits modified.
 */
static inline
pt_entry_t
pmap_force_pte_kernel_ro_if_protected_io(pmap_paddr_t paddr, pt_entry_t tmplate)
{
	/**
	 * When requesting RW mappings to an XNU_PROTECTED_IO frame, downgrade
	 * the mapping to RO. This is required because IOKit relies on this
	 * behavior currently in the PPL.
	 */
	const sptm_frame_type_t frame_type = sptm_get_frame_type(paddr);
	if (frame_type == XNU_PROTECTED_IO) {
		/* SPTM to own the page by converting KERN_RW to PPL_RW. */
		const uint64_t xprr_perm = pte_to_xprr_perm(tmplate);
		switch (xprr_perm) {
		case XPRR_KERN_RO_PERM:
			break;
		case XPRR_KERN_RW_PERM:
			tmplate &= ~ARM_PTE_XPRR_MASK;
			tmplate |= xprr_perm_to_pte(XPRR_KERN_RO_PERM);
			break;
		default:
			panic("%s: Unsupported xPRR perm %llu for pte 0x%llx", __func__, xprr_perm, (uint64_t)tmplate);
		}
	}

	return tmplate;
}

vm_map_address_t
pmap_map_bd_with_options(
	vm_map_address_t virt,
	vm_offset_t start,
	vm_offset_t end,
	vm_prot_t prot,
	int32_t options)
{
	pt_entry_t      tmplate;
	vm_map_address_t vaddr;
	vm_offset_t     paddr;
	pt_entry_t      mem_attr;

	switch (options & PMAP_MAP_BD_MASK) {
	case PMAP_MAP_BD_WCOMB:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITECOMB);
		mem_attr |= ARM_PTE_SH(SH_OUTER_MEMORY);
		break;
	case PMAP_MAP_BD_POSTED:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED);
		break;
	case PMAP_MAP_BD_POSTED_REORDERED:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_REORDERED);
		break;
	case PMAP_MAP_BD_POSTED_COMBINED_REORDERED:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED);
		break;
	default:
		mem_attr = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
		break;
	}

	tmplate = ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA) |
	    mem_attr | ARM_PTE_TYPE | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_AF;

#if __ARM_KERNEL_PROTECT__
	tmplate |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

	vaddr = virt;
	paddr = start;
	while (paddr < end) {
		__assert_only sptm_return_t ret = sptm_map_page(kernel_pmap->ttep, vaddr, pmap_force_pte_kernel_ro_if_protected_io(paddr, tmplate) | pa_to_pte(paddr));
		assert((ret == SPTM_SUCCESS) || (ret == SPTM_MAP_VALID));

		vaddr += PAGE_SIZE;
		paddr += PAGE_SIZE;
	}

	return vaddr;
}

/*
 *      Back-door routine for mapping kernel VM at initialization.
 *      Useful for mapping memory outside the range
 *      [vm_first_phys, vm_last_phys] (i.e., devices).
 *      Otherwise like pmap_map.
 */
vm_map_address_t
pmap_map_bd(
	vm_map_address_t virt,
	vm_offset_t start,
	vm_offset_t end,
	vm_prot_t prot)
{
	return pmap_map_bd_with_options(virt, start, end, prot, 0);
}

/*
 *      Back-door routine for mapping kernel VM at initialization.
 *      Useful for mapping memory specific physical addresses in early
 *      boot (i.e., before kernel_map is initialized).
 *
 *      Maps are in the VM_HIGH_KERNEL_WINDOW area.
 */

vm_map_address_t
pmap_map_high_window_bd(
	vm_offset_t pa_start,
	vm_size_t len,
	vm_prot_t prot)
{
	pt_entry_t              *ptep, pte;
	vm_map_address_t        va_start = VREGION1_START;
	vm_map_address_t        va_max = VREGION1_START + VREGION1_SIZE;
	vm_map_address_t        va_end;
	vm_map_address_t        va;
	vm_size_t               offset;

	offset = pa_start & PAGE_MASK;
	pa_start -= offset;
	len += offset;

	if (len > (va_max - va_start)) {
		panic("%s: area too large, "
		    "pa_start=%p, len=%p, prot=0x%x",
		    __FUNCTION__,
		    (void*)pa_start, (void*)len, prot);
	}

scan:
	for (; va_start < va_max; va_start += PAGE_SIZE) {
		ptep = pmap_pte(kernel_pmap, va_start);
		assert(!pte_is_compressed(*ptep, ptep));
		if (*ptep == ARM_PTE_TYPE_FAULT) {
			break;
		}
	}
	if (va_start > va_max) {
		panic("%s: insufficient pages, "
		    "pa_start=%p, len=%p, prot=0x%x",
		    __FUNCTION__,
		    (void*)pa_start, (void*)len, prot);
	}

	for (va_end = va_start + PAGE_SIZE; va_end < va_start + len; va_end += PAGE_SIZE) {
		ptep = pmap_pte(kernel_pmap, va_end);
		assert(!pte_is_compressed(*ptep, ptep));
		if (*ptep != ARM_PTE_TYPE_FAULT) {
			va_start = va_end + PAGE_SIZE;
			goto scan;
		}
	}

	for (va = va_start; va < va_end; va += PAGE_SIZE, pa_start += PAGE_SIZE) {
		ptep = pmap_pte(kernel_pmap, va);
		pte = pa_to_pte(pa_start)
		    | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_NX | ARM_PTE_PNX
		    | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA)
		    | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT)
		    | ARM_PTE_SH(SH_OUTER_MEMORY);
#if __ARM_KERNEL_PROTECT__
		pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
		__assert_only sptm_return_t ret = sptm_map_page(kernel_pmap->ttep, va, pte);
		assert((ret == SPTM_SUCCESS) || (ret == SPTM_MAP_VALID));
	}
#if KASAN
	kasan_notify_address(va_start, len);
#endif
	return va_start;
}

/*
 * pmap_get_arm64_prot
 *
 * return effective armv8 VMSA block protections including
 * table AP/PXN/XN overrides of a pmap entry
 *
 */

uint64_t
pmap_get_arm64_prot(
	pmap_t pmap,
	vm_offset_t addr)
{
	tt_entry_t tte = 0;
	unsigned int level = 0;
	uint64_t tte_type = 0;
	uint64_t effective_prot_bits = 0;
	uint64_t aggregate_tte = 0;
	uint64_t table_ap_bits = 0, table_xn = 0, table_pxn = 0;
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	for (level = pt_attr->pta_root_level; level <= pt_attr->pta_max_level; level++) {
		tte = *pmap_ttne(pmap, level, addr);

		if (!(tte & ARM_TTE_VALID)) {
			return 0;
		}

		tte_type = tte & ARM_TTE_TYPE_MASK;

		if ((tte_type == ARM_TTE_TYPE_BLOCK) ||
		    (level == pt_attr->pta_max_level)) {
			/* Block or page mapping; both have the same protection bit layout. */
			break;
		} else if (tte_type == ARM_TTE_TYPE_TABLE) {
			/* All of the table bits we care about are overrides, so just OR them together. */
			aggregate_tte |= tte;
		}
	}

	table_ap_bits = ((aggregate_tte >> ARM_TTE_TABLE_APSHIFT) & AP_MASK);
	table_xn = (aggregate_tte & ARM_TTE_TABLE_XN);
	table_pxn = (aggregate_tte & ARM_TTE_TABLE_PXN);

	/* Start with the PTE bits. */
	effective_prot_bits = tte & (ARM_PTE_APMASK | ARM_PTE_NX | ARM_PTE_PNX);

	/* Table AP bits mask out block/page AP bits */
	effective_prot_bits &= ~(ARM_PTE_AP(table_ap_bits));

	/* XN/PXN bits can be OR'd in. */
	effective_prot_bits |= (table_xn ? ARM_PTE_NX : 0);
	effective_prot_bits |= (table_pxn ? ARM_PTE_PNX : 0);

	return effective_prot_bits;
}

/*
 *	Bootstrap the system enough to run with virtual memory.
 *
 *	The early VM initialization code has already allocated
 *	the first CPU's translation table and made entries for
 *	all the one-to-one mappings to be found there.
 *
 *	We must set up the kernel pmap structures, the
 *	physical-to-virtual translation lookup tables for the
 *	physical memory to be managed (between avail_start and
 *	avail_end).
 *
 *	Map the kernel's code and data, and allocate the system page table.
 *	Page_size must already be set.
 *
 *	Parameters:
 *	first_avail	first available physical page -
 *			   after kernel page tables
 *	avail_start	PA of first managed physical page
 *	avail_end	PA of last managed physical page
 */

void
pmap_bootstrap(
	vm_offset_t vstart)
{
	vm_map_offset_t maxoffset;

	lck_grp_init(&pmap_lck_grp, "pmap", LCK_GRP_ATTR_NULL);

#if DEVELOPMENT || DEBUG
	if (PE_parse_boot_argn("pmap_trace", &pmap_trace_mask, sizeof(pmap_trace_mask))) {
		kprintf("Kernel traces for pmap operations enabled\n");
	}
#endif

	/*
	 *	Initialize the kernel pmap.
	 */
#if ARM_PARAMETERIZED_PMAP
	kernel_pmap->pmap_pt_attr = native_pt_attr;
#endif /* ARM_PARAMETERIZED_PMAP */
#if HAS_APPLE_PAC
	kernel_pmap->disable_jop = 0;
#endif /* HAS_APPLE_PAC */
	kernel_pmap->tte = cpu_tte;
	kernel_pmap->ttep = cpu_ttep;
	kernel_pmap->min = UINT64_MAX - (1ULL << (64 - T1SZ_BOOT)) + 1;
	kernel_pmap->max = UINTPTR_MAX;
	os_atomic_init(&kernel_pmap->ref_count, 1);
	kernel_pmap->nx_enabled = TRUE;
	kernel_pmap->is_64bit = TRUE;
#if CONFIG_ROSETTA
	kernel_pmap->is_rosetta = FALSE;
#endif

#if ARM_PARAMETERIZED_PMAP
	kernel_pmap->pmap_pt_attr = native_pt_attr;
#endif /* ARM_PARAMETERIZED_PMAP */

	kernel_pmap->nested_region_addr = 0x0ULL;
	kernel_pmap->nested_region_size = 0x0ULL;
	kernel_pmap->nested_region_unnested_table_bitmap = NULL;
	kernel_pmap->type = PMAP_TYPE_KERNEL;

	kernel_pmap->asid = 0;

	pmap_lock_init(kernel_pmap);

	pmap_max_asids = SPTMArgs->num_asids;

	const vm_size_t asid_table_size = sizeof(*asid_bitmap) * BITMAP_LEN(pmap_max_asids);

	/**
	 * Bootstrap the core pmap data structures (e.g., pv_head_table,
	 * pp_attr_table, etc). This function will use `avail_start` to allocate
	 * space for these data structures.
	 * */
	pmap_data_bootstrap();

	/**
	 * Bootstrap any necessary UAT data structures and values needed from the device tree.
	 */
	uat_bootstrap();

	/**
	 * Don't make any assumptions about the alignment of avail_start before this
	 * point (i.e., pmap_data_bootstrap() performs allocations).
	 */
	avail_start = PMAP_ALIGN(avail_start, __alignof(bitmap_t));

	const pmap_paddr_t pmap_struct_start = avail_start;

	asid_bitmap = (bitmap_t*)phystokv(avail_start);
	avail_start = round_page(avail_start + asid_table_size);

	memset((char *)phystokv(pmap_struct_start), 0, avail_start - pmap_struct_start);

	queue_init(&map_pmap_list);
	queue_enter(&map_pmap_list, kernel_pmap, pmap_t, pmaps);

	virtual_space_start = vstart;
	virtual_space_end = VM_MAX_KERNEL_ADDRESS;

	bitmap_full(&asid_bitmap[0], pmap_max_asids);
	// Clear the ASIDs which will alias the reserved kernel ASID of 0
	for (unsigned int i = 0; i < pmap_max_asids; i += MAX_HW_ASIDS) {
		bitmap_clear(&asid_bitmap[0], i);
	}
#if !HAS_16BIT_ASID
	/**
	 * Align the range of available hardware ASIDs to a multiple of 64 to enable the
	 * masking used by the PLRU scheme.  This means we must handle the case in which
	 * the returned hardware ASID is 0, which we do by clearing all vASIDs that will
	 * alias the kernel ASID.
	 */
	pmap_max_asids = pmap_max_asids & ~63ul;
	if (__improbable(pmap_max_asids == 0)) {
		panic("%s: insufficient number of ASIDs (%u) supplied by SPTM", __func__, (unsigned int)pmap_max_asids);
	}
	pmap_asid_plru = (pmap_max_asids > MAX_HW_ASIDS);
	PE_parse_boot_argn("pmap_asid_plru", &pmap_asid_plru, sizeof(pmap_asid_plru));
	_Static_assert(sizeof(asid_plru_bitmap[0] == sizeof(uint64_t)), "bitmap_t is not a 64-bit integer");
	_Static_assert((MAX_HW_ASIDS % 64) == 0, "MAX_HW_ASIDS is not divisible by 64");
	bitmap_full(&asid_plru_bitmap[0], MAX_HW_ASIDS);
	bitmap_clear(&asid_plru_bitmap[0], 0);
#endif /* !HAS_16BIT_ASID */


	if (PE_parse_boot_argn("arm_maxoffset", &maxoffset, sizeof(maxoffset))) {
		maxoffset = trunc_page(maxoffset);
		if ((maxoffset >= pmap_max_offset(FALSE, ARM_PMAP_MAX_OFFSET_MIN))
		    && (maxoffset <= pmap_max_offset(FALSE, ARM_PMAP_MAX_OFFSET_MAX))) {
			arm_pmap_max_offset_default = maxoffset;
		}
	}
	if (PE_parse_boot_argn("arm64_maxoffset", &maxoffset, sizeof(maxoffset))) {
		maxoffset = trunc_page(maxoffset);
		if ((maxoffset >= pmap_max_offset(TRUE, ARM_PMAP_MAX_OFFSET_MIN))
		    && (maxoffset <= pmap_max_offset(TRUE, ARM_PMAP_MAX_OFFSET_MAX))) {
			arm64_pmap_max_offset_default = maxoffset;
		}
	}

	PE_parse_boot_argn("pmap_panic_dev_wimg_on_managed", &pmap_panic_dev_wimg_on_managed, sizeof(pmap_panic_dev_wimg_on_managed));


#if MACH_ASSERT
	PE_parse_boot_argn("vm_footprint_suspend_allowed",
	    &vm_footprint_suspend_allowed,
	    sizeof(vm_footprint_suspend_allowed));
#endif /* MACH_ASSERT */

#if KASAN
	/* Shadow the CPU copy windows, as they fall outside of the physical aperture */
	kasan_map_shadow(CPUWINDOWS_BASE, CPUWINDOWS_TOP - CPUWINDOWS_BASE, true);
#endif /* KASAN */

	/**
	 * Ensure that avail_start is always left on a page boundary. The calling
	 * code might not perform any alignment before allocating page tables so
	 * this is important.
	 */
	avail_start = round_page(avail_start);
}

/**
 * Helper for creating a populated commpage table
 *
 * In order to avoid burning extra pages on mapping the commpage, we create a
 * dedicated table hierarchy for the commpage.  We forcibly nest the translation tables from
 * this pmap into other pmaps.  The level we will nest at depends on the MMU configuration (page
 * size, TTBR range, etc). Typically, this is at L1 for 4K tasks and L2 for 16K tasks.
 *
 * @note that this is NOT "the nested pmap" (which is used to nest the shared cache).
 *
 * @param rw_va Virtual address at which to insert a mapping to the kernel R/W commpage
 * @param ro_va Virtual address at which to insert a mapping to the kernel R/O commpage
 * @param rw_pa Physical address of kernel R/W commpage
 * @param ro_pa Physical address of kernel R/O commpage, may be 0 if not supported in this
 *              configuration
 * @param rx_pa Physical address of user executable (and kernel R/O) commpage, may be 0 if
 *              not supported in this configuration
 * @param pmap_create_flags Control flags for the temporary pmap created by this function
 *
 * @return the physical address of the created commpage table, typed as
 *         XNU_PAGE_TABLE_COMMPAGE and containing all relevant commpage mappings.
 */
static pmap_paddr_t
pmap_create_commpage_table(vm_map_address_t rw_va, vm_map_address_t ro_va,
    pmap_paddr_t rw_pa, pmap_paddr_t ro_pa, pmap_paddr_t rx_pa, unsigned int pmap_create_flags)
{
	pmap_t temp_commpage_pmap = pmap_create_options(NULL, 0, pmap_create_flags);
	assert(temp_commpage_pmap != NULL);
	assert(rw_pa != 0);
	const pt_attr_t *pt_attr = pmap_get_pt_attr(temp_commpage_pmap);

	/*
	 * We only use pmap_expand to expand the pmap up to the commpage nesting level.  At that level
	 * and beyond, all the newly created tables will be nested directly into the userspace region
	 * for each process, and as such they must be of the dedicated SPTM commpage table type so that
	 * the SPTM can enforce the commpage security model which forbids random replacement of commpage
	 * mappings.
	 */
	kern_return_t kr = pmap_expand(temp_commpage_pmap, rw_va, 0, pt_attr_commpage_level(pt_attr));
	assert(kr == KERN_SUCCESS);

	pmap_paddr_t commpage_table_pa = 0;
	for (unsigned int i = pt_attr_commpage_level(pt_attr); i < pt_attr_leaf_level(pt_attr); i++) {
		pmap_paddr_t new_table = 0;
		kr = pmap_page_alloc(&new_table, 0);
		assert((kr == KERN_SUCCESS) && (new_table != 0));
		if (commpage_table_pa == 0) {
			commpage_table_pa = new_table;
		}

		sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
		retype_params.level = (sptm_pt_level_t)pt_attr_leaf_level(pt_attr);
		sptm_retype(new_table, XNU_DEFAULT, XNU_PAGE_TABLE_COMMPAGE, retype_params);

		const sptm_tte_t table_tte = (new_table & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID;
		sptm_map_table(temp_commpage_pmap->ttep, rw_va, (sptm_pt_level_t)i, table_tte);
	}

	/*
	 * Note the lack of ARM_PTE_NG here: commpage mappings are at fixed addresses and
	 * frequently accessed, so we map them global to avoid unnecessary TLB pressure.
	 */
	static const sptm_pte_t commpage_pte_template = ARM_PTE_TYPE_VALID
	    | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK)
	    | ARM_PTE_SH(SH_INNER_MEMORY) | ARM_PTE_PNX
	    | ARM_PTE_AP(AP_RORO) | ARM_PTE_AF;

	sptm_return_t sptm_ret = sptm_map_page(temp_commpage_pmap->ttep, rw_va,
	    commpage_pte_template | ARM_PTE_NX | pa_to_pte(rw_pa));
	assert(sptm_ret == SPTM_SUCCESS);

	if (ro_pa != 0) {
		assert((ro_va & ~pt_attr_twig_offmask(pt_attr)) == (rw_va & ~pt_attr_twig_offmask(pt_attr)));
		sptm_ret = sptm_map_page(temp_commpage_pmap->ttep, ro_va,
		    commpage_pte_template | ARM_PTE_NX | pa_to_pte(ro_pa));
		assert(sptm_ret == SPTM_SUCCESS);
	}

	if (rx_pa != 0) {
		/*
		 * The data comm page is in a pre-reserved L3 VA range and the text commpage
		 * is slid in the same L3 as the data commpage.  It is either outside the
		 * max of user VA or is pre-reserved in the vm_map_exec(). This means that
		 * it is reserved and unavailable to mach VM for future mappings.
		 */
		const int num_ptes = pt_attr_leaf_size(pt_attr) >> PTE_SHIFT;
		vm_map_address_t rx_va;
		do {
			int text_leaf_index = random() % num_ptes;

			// Generate a VA for the commpage text with the same root and twig index as data
			// comm page, but with new leaf index we've just generated.
			rx_va = (rw_va & ~pt_attr_leaf_index_mask(pt_attr));
			rx_va |= (text_leaf_index << pt_attr_leaf_shift(pt_attr));
		} while ((rx_va == rw_va) || (rx_va == ro_va)); // Try again if we collide (should be unlikely)

		sptm_ret = sptm_map_page(temp_commpage_pmap->ttep, rx_va, commpage_pte_template | pa_to_pte(rx_pa));
		assert(sptm_ret == SPTM_SUCCESS);
	}

	sptm_unmap_table(temp_commpage_pmap->ttep, rw_va, (sptm_pt_level_t)pt_attr_commpage_level(pt_attr));
	pmap_destroy(temp_commpage_pmap);

	return commpage_table_pa;
}

/**
 * Helper for creating all commpage tables applicable to the current configuration.
 *
 * @note This function is intended to be called during bootstrap.
 * @note This function assumes that pmap_create_commpages has already executed, and therefore
 *       the commpage_*_pa variables have been assigned to their final values.  commpage_data_pa
 *       is the kernel RW commpage and is assumed to be present on all configurations, so it
 *       therefore must be non-zero at this point.  The other variables are considered optional
 *       depending upon configuration and may be zero.
 */
void pmap_prepare_commpages(void);
void
pmap_prepare_commpages(void)
{
	sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
	assert(commpage_data_pa != 0);
	sptm_retype(commpage_data_pa, XNU_DEFAULT, XNU_COMMPAGE_RW, retype_params);
	if (commpage_ro_data_pa != 0) {
		sptm_retype(commpage_ro_data_pa, XNU_DEFAULT, XNU_COMMPAGE_RO, retype_params);
	}
	if (commpage_text_pa != 0) {
		sptm_retype(commpage_text_pa, XNU_DEFAULT, XNU_COMMPAGE_RX, retype_params);
	}

	/*
	 * User mapping of comm page text section for 64 bit mapping only
	 *
	 * We don't insert the text commpage into the 32 bit mapping because we don't want
	 * 32-bit user processes to get this page mapped in, they should never call into
	 * this page.
	 */
	commpage_default_table = pmap_create_commpage_table(_COMM_PAGE64_BASE_ADDRESS, _COMM_PAGE64_RO_ADDRESS,
	    commpage_data_pa, commpage_ro_data_pa, commpage_text_pa, 0);

	/*
	 * SPTM TODO: Enable this, along with the appropriate 32-bit commpage address checks and flushes in the
	 * SPTM, if we ever need to support arm64_32 processes in the SPTM.
	 *
	 * commpage32_default_table = pmap_create_commpage_table(_COMM_PAGE32_BASE_ADDRESS, _COMM_PAGE32_RO_ADDRESS,
	 *    commpage_data_pa, commpage_ro_data_pa, 0, 0);
	 */
#if __ARM_MIXED_PAGE_SIZE__
#if !CONFIG_SPTM /* SPTM TODO: remove once the SPTM supports 4K address spaces */
	commpage_4k_table = pmap_create_commpage_table(_COMM_PAGE64_BASE_ADDRESS, _COMM_PAGE64_RO_ADDRESS,
	    commpage_data_pa, commpage_ro_data_pa, 0, PMAP_CREATE_FORCE_4K_PAGES);

	/*
	 * SPTM TODO: Enable this, along with the appropriate 32-bit commpage address checks and flushes in the
	 * SPTM, if we ever need to support arm64_32 processes in the SPTM.
	 * commpage32_4k_table = pmap_create_commpage_table(_COMM_PAGE32_BASE_ADDRESS, _COMM_PAGE32_RO_ADDRESS,
	 *    commpage_data_pa, commpage_ro_data_pa, 0, PMAP_CREATE_FORCE_4K_PAGES);
	 */
#endif /* !CONFIG_SPTM */
#endif /* __ARM_MIXED_PAGE_SIZE__ */

}

void
pmap_virtual_space(
	vm_offset_t *startp,
	vm_offset_t *endp
	)
{
	*startp = virtual_space_start;
	*endp = virtual_space_end;
}


boolean_t
pmap_virtual_region(
	unsigned int region_select,
	vm_map_offset_t *startp,
	vm_map_size_t *size
	)
{
	boolean_t       ret = FALSE;
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	if (region_select == 0) {
		/*
		 * In this config, the bootstrap mappings should occupy their own L2
		 * TTs, as they should be immutable after boot.  Having the associated
		 * TTEs and PTEs in their own pages allows us to lock down those pages,
		 * while allowing the rest of the kernel address range to be remapped.
		 */
		*startp = LOW_GLOBAL_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK;
#if defined(ARM_LARGE_MEMORY)
		*size = ((KERNEL_PMAP_HEAP_RANGE_START - *startp) & ~PAGE_MASK);
#else
		*size = ((VM_MAX_KERNEL_ADDRESS - *startp) & ~PAGE_MASK);
#endif
		ret = TRUE;
	}

#if defined(ARM_LARGE_MEMORY)
	if (region_select == 1) {
		*startp = VREGION1_START;
		*size = VREGION1_SIZE;
		ret = TRUE;
	}
#endif
#else /* !(defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)) */
#if defined(ARM_LARGE_MEMORY)
	/* For large memory systems with no KTRR/CTRR such as virtual machines */
	if (region_select == 0) {
		*startp = LOW_GLOBAL_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK;
		*size = ((KERNEL_PMAP_HEAP_RANGE_START - *startp) & ~PAGE_MASK);
		ret = TRUE;
	}

	if (region_select == 1) {
		*startp = VREGION1_START;
		*size = VREGION1_SIZE;
		ret = TRUE;
	}
#else /* !defined(ARM_LARGE_MEMORY) */
	unsigned long low_global_vr_mask = 0;
	vm_map_size_t low_global_vr_size = 0;

	if (region_select == 0) {
		/* Round to avoid overlapping with the V=P area; round to at least the L2 block size. */
		if (!TEST_PAGE_SIZE_4K) {
			*startp = gVirtBase & 0xFFFFFFFFFE000000;
			*size = ((virtual_space_start - (gVirtBase & 0xFFFFFFFFFE000000)) + ~0xFFFFFFFFFE000000) & 0xFFFFFFFFFE000000;
		} else {
			*startp = gVirtBase & 0xFFFFFFFFFF800000;
			*size = ((virtual_space_start - (gVirtBase & 0xFFFFFFFFFF800000)) + ~0xFFFFFFFFFF800000) & 0xFFFFFFFFFF800000;
		}
		ret = TRUE;
	}
	if (region_select == 1) {
		*startp = VREGION1_START;
		*size = VREGION1_SIZE;
		ret = TRUE;
	}
	/* We need to reserve a range that is at least the size of an L2 block mapping for the low globals */
	if (!TEST_PAGE_SIZE_4K) {
		low_global_vr_mask = 0xFFFFFFFFFE000000;
		low_global_vr_size = 0x2000000;
	} else {
		low_global_vr_mask = 0xFFFFFFFFFF800000;
		low_global_vr_size = 0x800000;
	}

	if (((gVirtBase & low_global_vr_mask) != LOW_GLOBAL_BASE_ADDRESS) && (region_select == 2)) {
		*startp = LOW_GLOBAL_BASE_ADDRESS;
		*size = low_global_vr_size;
		ret = TRUE;
	}

	if (region_select == 3) {
		/* In this config, we allow the bootstrap mappings to occupy the same
		 * page table pages as the heap.
		 */
		*startp = VM_MIN_KERNEL_ADDRESS;
		*size = LOW_GLOBAL_BASE_ADDRESS - *startp;
		ret = TRUE;
	}
#endif /* defined(ARM_LARGE_MEMORY) */
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */
	return ret;
}

/*
 * Routines to track and allocate physical pages during early boot.
 * On most systems that memory runs from first_avail through to avail_end
 * with no gaps.
 *
 * If the system supports ECC and ecc_bad_pages_count > 0, we
 * need to skip those pages.
 */

static unsigned int avail_page_count = 0;
static bool need_ram_ranges_init = true;


/**
 * Checks to see if a given page is in
 * the array of known bad pages
 *
 * @param ppn page number to check
 */
bool
pmap_is_bad_ram(__unused ppnum_t ppn)
{
	return false;
}

/**
 * Prepare bad ram pages to be skipped.
 */

/*
 * Initialize the count of available pages. No lock needed here,
 * as this code is called while kernel boot up is single threaded.
 */
static void
initialize_ram_ranges(void)
{
	pmap_paddr_t first = first_avail;
	pmap_paddr_t end = avail_end;

	assert(first <= end);
	assert(first == (first & ~PAGE_MASK));
	assert(end == (end & ~PAGE_MASK));
	avail_page_count = atop(end - first);

	need_ram_ranges_init = false;
}

unsigned int
pmap_free_pages(
	void)
{
	if (need_ram_ranges_init) {
		initialize_ram_ranges();
	}
	return avail_page_count;
}

unsigned int
pmap_free_pages_span(
	void)
{
	if (need_ram_ranges_init) {
		initialize_ram_ranges();
	}
	return (unsigned int)atop(avail_end - first_avail);
}


boolean_t
pmap_next_page_hi(
	ppnum_t            * pnum,
	__unused boolean_t might_free)
{
	return pmap_next_page(pnum);
}


boolean_t
pmap_next_page(
	ppnum_t *pnum)
{
	if (need_ram_ranges_init) {
		initialize_ram_ranges();
	}


	if (first_avail != avail_end) {
		*pnum = (ppnum_t)atop(first_avail);
		first_avail += PAGE_SIZE;
		assert(avail_page_count > 0);
		--avail_page_count;
		return TRUE;
	}
	assert(avail_page_count == 0);
	return FALSE;
}




/*
 *	Initialize the pmap module.
 *	Called by vm_init, to initialize any structures that the pmap
 *	system needs to map virtual memory.
 */
void
pmap_init(
	void)
{
	/*
	 *	Protect page zero in the kernel map.
	 *	(can be overruled by permanent transltion
	 *	table entries at page zero - see arm_vm_init).
	 */
	vm_protect(kernel_map, 0, PAGE_SIZE, TRUE, VM_PROT_NONE);

	pmap_initialized = TRUE;

	/*
	 *	Create the zone of physical maps
	 *	and the physical-to-virtual entries.
	 */
	pmap_zone = zone_create_ext("pmap", sizeof(struct pmap),
	    ZC_ZFREE_CLEARMEM, ZONE_ID_PMAP, NULL);


	/*
	 *	Initialize the pmap object (for tracking the vm_page_t
	 *	structures for pages we allocate to be page tables in
	 *	pmap_expand().
	 */
	_vm_object_allocate(mem_size, pmap_object);
	pmap_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	/*
	 *	Initialize the TXM VM object in the same way as the
	 *	PMAP VM object.
	 */
	_vm_object_allocate(mem_size, txm_vm_object);
	txm_vm_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	/*
	 * The values of [hard_]maxproc may have been scaled, make sure
	 * they are still less than the value of pmap_max_asids.
	 */
	if ((uint32_t)maxproc > pmap_max_asids) {
		maxproc = pmap_max_asids;
	}
	if ((uint32_t)hard_maxproc > pmap_max_asids) {
		hard_maxproc = pmap_max_asids;
	}
}

/**
 * Verify that a given physical page contains no mappings (outside of the
 * default physical aperture mapping).
 *
 * @param ppnum Physical page number to check there are no mappings to.
 *
 * @return True if there are no mappings, false otherwise or if the page is not
 *         kernel-managed.
 */
bool
pmap_verify_free(ppnum_t ppnum)
{
	const pmap_paddr_t pa = ptoa(ppnum);

	assert(pa != vm_page_fictitious_addr);

	/* Only mappings to kernel-managed physical memory are tracked. */
	if (!pa_valid(pa)) {
		return false;
	}

	const unsigned int pai = pa_index(pa);

	return pvh_test_type(pai_to_pvh(pai), PVH_TYPE_NULL);
}

#if MACH_ASSERT
/**
 * Verify that a given physical page contains no mappings (outside of the
 * default physical aperture mapping) and if it does, then panic.
 *
 * @note It's recommended to use pmap_verify_free() directly when operating in
 *       the PPL since the PVH lock isn't getting grabbed here (due to this code
 *       normally being called from outside of the PPL, and the pv_head_table
 *       can't be modified outside of the PPL).
 *
 * @param ppnum Physical page number to check there are no mappings to.
 */
void
pmap_assert_free(ppnum_t ppnum)
{
	const pmap_paddr_t pa = ptoa(ppnum);

	/* Only mappings to kernel-managed physical memory are tracked. */
	if (__probable(!pa_valid(pa) || pmap_verify_free(ppnum))) {
		return;
	}

	const unsigned int pai = pa_index(pa);
	const uintptr_t pvh = pai_to_pvh(pai);

	/**
	 * This function is always called from outside of the PPL. Because of this,
	 * the PVH entry can't be locked. This function is generally only called
	 * before the VM reclaims a physical page and shouldn't be creating new
	 * mappings. Even if a new mapping is created while parsing the hierarchy,
	 * the worst case is that the system will panic in another way, and we were
	 * already about to panic anyway.
	 */

	/**
	 * Since pmap_verify_free() returned false, that means there is at least one
	 * mapping left. Let's get some extra info on the first mapping we find to
	 * dump in the panic string (the common case is that there is one spare
	 * mapping that was never unmapped).
	 */
	pt_entry_t *first_ptep = PT_ENTRY_NULL;

	if (pvh_test_type(pvh, PVH_TYPE_PTEP)) {
		first_ptep = pvh_ptep(pvh);
	} else if (pvh_test_type(pvh, PVH_TYPE_PVEP)) {
		pv_entry_t *pvep = pvh_pve_list(pvh);

		/* Each PVE can contain multiple PTEs. Let's find the first one. */
		for (int pve_ptep_idx = 0; pve_ptep_idx < PTE_PER_PVE; pve_ptep_idx++) {
			first_ptep = pve_get_ptep(pvep, pve_ptep_idx);
			if (first_ptep != PT_ENTRY_NULL) {
				break;
			}
		}

		/* The PVE should have at least one valid PTE. */
		assert(first_ptep != PT_ENTRY_NULL);
	} else if (pvh_test_type(pvh, PVH_TYPE_PTDP)) {
		panic("%s: Physical page is being used as a page table at PVH %p (pai: %d)",
		    __func__, (void*)pvh, pai);
	} else {
		/**
		 * The mapping disappeared between here and the pmap_verify_free() call.
		 * The only way that can happen is if the VM was racing this call with
		 * a call that unmaps PTEs. Operations on this page should not be
		 * occurring at the same time as this check, and unfortunately we can't
		 * lock the PVH entry to prevent it, so just panic instead.
		 */
		panic("%s: Mapping was detected but is now gone. Is the VM racing this "
		    "call with an operation that unmaps PTEs? PVH %p (pai: %d)",
		    __func__, (void*)pvh, pai);
	}

	/* Panic with a unique string identifying the first bad mapping and owner. */
	{
		/* First PTE is mapped by the main CPUs. */
		pmap_t pmap = ptep_get_pmap(first_ptep);
		const char *type = (pmap == kernel_pmap) ? "Kernel" : "User";

		panic("%s: Found at least one mapping to %#llx. First PTEP (%p) is a "
		    "%s CPU mapping (pmap: %p)",
		    __func__, (uint64_t)pa, first_ptep, type, pmap);
	}
}
#endif



static vm_size_t
pmap_root_alloc_size(pmap_t pmap)
{
#pragma unused(pmap)
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	unsigned int root_level = pt_attr_root_level(pt_attr);
	return ((pt_attr_ln_index_mask(pt_attr, root_level) >> pt_attr_ln_shift(pt_attr, root_level)) + 1) * sizeof(tt_entry_t);
}

/*
 *	Create and return a physical map.
 *
 *	If the size specified for the map
 *	is zero, the map is an actual physical
 *	map, and may be referenced by the
 *	hardware.
 *
 *	If the size specified is non-zero,
 *	the map will be used in software only, and
 *	is bounded by that size.
 */
MARK_AS_PMAP_TEXT pmap_t
pmap_create_options_internal(
	ledger_t ledger,
	vm_map_size_t size,
	unsigned int flags,
	kern_return_t *kr)
{
	unsigned        tte_index_max;
	pmap_t          p;
	bool is_64bit = flags & PMAP_CREATE_64BIT;
#if defined(HAS_APPLE_PAC)
	bool disable_jop = flags & PMAP_CREATE_DISABLE_JOP;
#endif /* defined(HAS_APPLE_PAC) */
	kern_return_t   local_kr = KERN_SUCCESS;
	__unused uint8_t sptm_root_flags = SPTM_ROOT_PT_FLAGS_DEFAULT;
	TXMAddressSpaceFlags_t txm_flags = kTXMAddressSpaceFlagInit;

	if (size != 0) {
		{
			// Size parameter should only be set for stage 2.
			return PMAP_NULL;
		}
	}

	if (0 != (flags & ~PMAP_CREATE_KNOWN_FLAGS)) {
		return PMAP_NULL;
	}

	/*
	 *	Allocate a pmap struct from the pmap_zone.  Then allocate
	 *	the translation table of the right size for the pmap.
	 */
	if ((p = (pmap_t) zalloc(pmap_zone)) == PMAP_NULL) {
		local_kr = KERN_RESOURCE_SHORTAGE;
		goto pmap_create_fail;
	}

	p->ledger = ledger;


	p->pmap_vm_map_cs_enforced = false;
	p->min = 0;


#if CONFIG_ROSETTA
	if (flags & PMAP_CREATE_ROSETTA) {
		p->is_rosetta = TRUE;
	} else {
		p->is_rosetta = FALSE;
	}
#endif /* CONFIG_ROSETTA */
#if defined(HAS_APPLE_PAC)
	p->disable_jop = disable_jop;

	if (p->disable_jop) {
		sptm_root_flags &= ~SPTM_ROOT_PT_FLAG_JOP;
	}
#endif /* defined(HAS_APPLE_PAC) */

	p->nested_region_true_start = 0;
	p->nested_region_true_end = ~0;

	p->nx_enabled = true;
	p->is_64bit = is_64bit;
	p->nested_pmap = PMAP_NULL;
	p->type = PMAP_TYPE_USER;

#if ARM_PARAMETERIZED_PMAP
	/* Default to the native pt_attr */
	p->pmap_pt_attr = native_pt_attr;
#endif /* ARM_PARAMETERIZED_PMAP */
#if __ARM_MIXED_PAGE_SIZE__
	if (flags & PMAP_CREATE_FORCE_4K_PAGES) {
		p->pmap_pt_attr = &pmap_pt_attr_4k;
		panic("SPTM TODO: 4K address spaces not yet supported by SPTM");
	}
#endif /* __ARM_MIXED_PAGE_SIZE__ */
	p->max = pmap_user_va_size(p);

	if (!pmap_get_pt_ops(p)->alloc_id(p)) {
		local_kr = KERN_NO_SPACE;
		goto id_alloc_fail;
	}

	pmap_lock_init(p);

	p->tt_entry_free = (tt_entry_t *)0;
	tte_index_max = ((unsigned)pmap_root_alloc_size(p) / sizeof(tt_entry_t));

	p->tte = pmap_tt1_allocate(p, sptm_root_flags);
	if (!(p->tte)) {
		local_kr = KERN_RESOURCE_SHORTAGE;
		goto tt1_alloc_fail;
	}

	p->ttep = kvtophys_nofail((vm_offset_t)p->tte);
	PMAP_TRACE(4, PMAP_CODE(PMAP__TTE), VM_KERNEL_ADDRHIDE(p), VM_KERNEL_ADDRHIDE(p->min), VM_KERNEL_ADDRHIDE(p->max), p->ttep);

	/*
	 *  initialize the rest of the structure
	 */
	p->nested_region_addr = 0x0ULL;
	p->nested_region_size = 0x0ULL;
	p->nested_region_unnested_table_bitmap = NULL;

	p->nested_has_no_bounds_ref = false;
	p->nested_no_bounds_refcnt = 0;
	p->nested_bounds_set = false;


#if MACH_ASSERT
	p->pmap_pid = 0;
	strlcpy(p->pmap_procname, "<nil>", sizeof(p->pmap_procname));
#endif /* MACH_ASSERT */
#if DEVELOPMENT || DEBUG
	p->footprint_was_suspended = FALSE;
#endif /* DEVELOPMENT || DEBUG */

	os_atomic_init(&p->ref_count, 1);
	pmap_simple_lock(&pmaps_lock);
	queue_enter(&map_pmap_list, p, pmap_t, pmaps);
	pmap_simple_unlock(&pmaps_lock);

	/**
	 * The SPTM pmap's concurrency model can sometimes allow ledger balances to transiently
	 * go negative.  Note that we still check overall ledger balance on pmap destruction.
	 */
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.phys_footprint);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.internal);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.internal_compressed);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.iokit_mapped);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.alternate_accounting);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.alternate_accounting_compressed);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.external);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.reusable);
	ledger_disable_panic_on_negative(p->ledger, task_ledgers.wired_mem);

	if (flags & PMAP_CREATE_TEST) {
		txm_flags |= kTXMAddressSpaceFlagTest;
	}

	/*
	 *	Complete initialization for the TXM address space. This needs to be done
	 *	after the SW ASID has been registered with the SPTM.
	 */
	pmap_txmlock_init(p);
	txm_register_address_space(p, p->asid, txm_flags);
	p->txm_trust_level = kCSTrustUntrusted;

	return p;

tt1_alloc_fail:
	pmap_get_pt_ops(p)->free_id(p);
id_alloc_fail:
	zfree(pmap_zone, p);
pmap_create_fail:
	*kr = local_kr;
	return PMAP_NULL;
}

pmap_t
pmap_create_options(
	ledger_t ledger,
	vm_map_size_t size,
	unsigned int flags)
{
	pmap_t pmap;
	kern_return_t kr = KERN_SUCCESS;

	PMAP_TRACE(1, PMAP_CODE(PMAP__CREATE) | DBG_FUNC_START, size, flags);

	ledger_reference(ledger);

	pmap = pmap_create_options_internal(ledger, size, flags, &kr);

	if (pmap == PMAP_NULL) {
		ledger_dereference(ledger);
	}

	PMAP_TRACE(1, PMAP_CODE(PMAP__CREATE) | DBG_FUNC_END, VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), PMAP_HWASID(pmap));

	return pmap;
}

#if MACH_ASSERT
MARK_AS_PMAP_TEXT void
pmap_set_process_internal(
	__unused pmap_t pmap,
	__unused int pid,
	__unused char *procname)
{
	if (pmap == NULL || pmap->pmap_pid == -1) {
		return;
	}

	validate_pmap_mutable(pmap);

	pmap->pmap_pid = pid;
	strlcpy(pmap->pmap_procname, procname, sizeof(pmap->pmap_procname));
}
#endif /* MACH_ASSERT */

#if MACH_ASSERT
void
pmap_set_process(
	pmap_t pmap,
	int pid,
	char *procname)
{
	pmap_set_process_internal(pmap, pid, procname);
}
#endif /* MACH_ASSERT */

/*
 * pmap_deallocate_all_leaf_tts:
 *
 * Recursive function for deallocating all leaf TTEs.  Walks the given TT,
 * removing and deallocating all TTEs.
 */
MARK_AS_PMAP_TEXT static void
pmap_deallocate_all_leaf_tts(pmap_t pmap, tt_entry_t * first_ttep, vm_map_address_t va, unsigned level)
{
	tt_entry_t tte = ARM_TTE_EMPTY;
	tt_entry_t * ttep = NULL;
	tt_entry_t * last_ttep = NULL;

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const uint64_t size = pt_attr->pta_level_info[level].size;

	assert(level < pt_attr_leaf_level(pt_attr));

	last_ttep = &first_ttep[ttn_index(pt_attr, ~0, level)];

	for (ttep = first_ttep; ttep <= last_ttep; ttep++, va += size) {
		tte = *ttep;

		if (!(tte & ARM_TTE_VALID)) {
			continue;
		}

		if ((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_BLOCK) {
			panic("%s: found block mapping, ttep=%p, tte=%p, "
			    "pmap=%p, first_ttep=%p, level=%u",
			    __FUNCTION__, ttep, (void *)tte,
			    pmap, first_ttep, level);
		}

		/* Must be valid, type table */
		if (level < pt_attr_twig_level(pt_attr)) {
			/* If we haven't reached the twig level, recurse to the next level. */
			pmap_deallocate_all_leaf_tts(pmap, (tt_entry_t *)phystokv((tte) & ARM_TTE_TABLE_MASK), va, level + 1);
		}

		/* Remove the TTE. */
		pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
		pmap_tte_deallocate(pmap, va, ttep, level);
	}
}

/*
 * We maintain stats and ledgers so that a task's physical footprint is:
 * phys_footprint = ((internal - alternate_accounting)
 *                   + (internal_compressed - alternate_accounting_compressed)
 *                   + iokit_mapped
 *                   + purgeable_nonvolatile
 *                   + purgeable_nonvolatile_compressed
 *                   + page_table)
 * where "alternate_accounting" includes "iokit" and "purgeable" memory.
 */

/*
 *	Retire the given physical map from service.
 *	Should only be called if the map contains
 *	no valid mappings.
 */
MARK_AS_PMAP_TEXT void
pmap_destroy_internal(
	pmap_t pmap)
{
	if (pmap == PMAP_NULL) {
		return;
	}

	validate_pmap(pmap);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	int32_t ref_count = os_atomic_dec(&pmap->ref_count, relaxed);
	if (ref_count > 0) {
		return;
	} else if (__improbable(ref_count < 0)) {
		panic("pmap %p: refcount underflow", pmap);
	} else if (__improbable(pmap == kernel_pmap)) {
		panic("pmap %p: attempt to destroy kernel pmap", pmap);
	} else if (__improbable(pmap->type == PMAP_TYPE_COMMPAGE)) {
		panic("pmap %p: attempt to destroy commpage pmap", pmap);
	}

	/*
	 *	Complete all clean up required for TXM. This needs to happen before the
	 *	SW ASID has been unregistered with the SPTM.
	 */
	txm_unregister_address_space(pmap);
	pmap_txmlock_destroy(pmap);

	/**
	 * Drain any concurrent retype-sensitive SPTM operations.  This is needed to
	 * ensure that we don't unmap and retype the page tables while those operations
	 * are still finishing on other CPUs, leading to an SPTM violation.  In particular,
	 * the multipage batched cacheability/attribute update code may issue SPTM calls
	 * without holding the relevant PVH or pmap locks, so we can't guarantee those
	 * calls have actually completed despite observing refcnt == 0.
	 *
	 * At this point, we CAN guarantee that:
	 * 1) All prior PTE removals required to empty the pmap have completed and
	 *    been synchronized with DSB, *except* the commpage removal which doesn't
	 *    involve pages that can ever be retyped.  Subsequent calls not already
	 *    in the retype epoch will no longer observe these mappings..
	 * 2) The pmap now has a zero refcount, so in a correctly functioning system
	 *    no further mappings will be requested for it.
	 */
	pmap_retype_epoch_prepare_drain();

	pmap_unmap_commpage(pmap);

	pmap_simple_lock(&pmaps_lock);
	queue_remove(&map_pmap_list, pmap, pmap_t, pmaps);
	pmap_simple_unlock(&pmaps_lock);

	pmap_retype_epoch_drain();

	pmap_trim_self(pmap);

	/*
	 *	Free the memory maps, then the
	 *	pmap structure.
	 */
	pmap_deallocate_all_leaf_tts(pmap, pmap->tte, pmap->min, pt_attr_root_level(pt_attr));



	if (pmap->tte) {
		pmap_tt1_deallocate(pmap, pmap->tte);
		pmap->tte = (tt_entry_t *) NULL;
		pmap->ttep = 0;
	}

	assert((tt_free_entry_t*)pmap->tt_entry_free == NULL);

	if (pmap->type != PMAP_TYPE_NESTED) {
		/* return its asid to the pool */
		pmap_get_pt_ops(pmap)->free_id(pmap);
		if (pmap->nested_pmap != NULL) {
			/* release the reference we hold on the nested pmap */
			pmap_destroy_internal(pmap->nested_pmap);
		}
	}

	pmap_check_ledgers(pmap);

	if (pmap->nested_region_unnested_table_bitmap) {
		bitmap_free(pmap->nested_region_unnested_table_bitmap, pmap->nested_region_size >> pt_attr_twig_shift(pt_attr));
	}

	pmap_lock_destroy(pmap);
	zfree(pmap_zone, pmap);
}

void
pmap_destroy(
	pmap_t pmap)
{
	PMAP_TRACE(1, PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_START, VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), PMAP_HWASID(pmap));

	ledger_t ledger = pmap->ledger;

	pmap_destroy_internal(pmap);

	ledger_dereference(ledger);

	PMAP_TRACE(1, PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_END);
}


/*
 *	Add a reference to the specified pmap.
 */
MARK_AS_PMAP_TEXT void
pmap_reference_internal(
	pmap_t pmap)
{
	if (pmap != PMAP_NULL) {
		validate_pmap_mutable(pmap);
		os_atomic_inc(&pmap->ref_count, relaxed);
	}
}

void
pmap_reference(
	pmap_t pmap)
{
	pmap_reference_internal(pmap);
}

static tt_entry_t *
pmap_tt1_allocate(pmap_t pmap, uint8_t sptm_root_flags)
{
	pmap_paddr_t pa = 0;
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	const kern_return_t ret = pmap_page_alloc(&pa, PMAP_PAGE_NOZEROFILL);

	if (ret != KERN_SUCCESS) {
		return (tt_entry_t *)0;
	}

	/**
	 * Drain the epochs to ensure any lingering batched operations that may have taken
	 * an in-flight reference to this page are complete.
	 */
	pmap_retype_epoch_prepare_drain();

	assert(pa);

	/* Always report root allocations in units of PMAP_ROOT_ALLOC_SIZE, which can be obtained by sysctl arm_pt_root_size.
	 * Depending on the device, this can vary between 512b and 16K. */
	OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));
	pmap_tt_ledger_credit(pmap, PAGE_SIZE);

	sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
	retype_params.attr_idx = (pt_attr_page_size(pt_attr) == 4096) ? SPTM_PT_GEOMETRY_4K : SPTM_PT_GEOMETRY_16K;
	retype_params.flags = sptm_root_flags;
	retype_params.asid = pmap->asid;

	pmap_retype_epoch_drain();

	sptm_retype(pa, XNU_DEFAULT, XNU_USER_ROOT_TABLE, retype_params);

	return (tt_entry_t *) phystokv(pa);
}

static void
pmap_tt1_deallocate(
	pmap_t pmap,
	tt_entry_t *tt)
{
	pmap_paddr_t pa = kvtophys_nofail((vm_offset_t)tt);

	sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
	sptm_retype(pa, pmap->type == PMAP_TYPE_NESTED ? XNU_SHARED_ROOT_TABLE : XNU_USER_ROOT_TABLE,
	    XNU_DEFAULT, retype_params);
	pmap_page_free(pa);

	OSAddAtomic(-1, (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));
	pmap_tt_ledger_debit(pmap, PAGE_SIZE);
}

MARK_AS_PMAP_TEXT static kern_return_t
pmap_tt_allocate(
	pmap_t pmap,
	tt_entry_t **ttp,
	unsigned int level,
	unsigned int options)
{
	pmap_paddr_t pa;
	*ttp = NULL;

#if 0
	/*
	 * SPTM TODO: We'll probably want to bring back this logic in slightly modified form once
	 * the SPTM fully supports 4K page tables on 16K devices.
	 */
	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
	if ((tt_free_entry_t *)pmap->tt_entry_free != NULL) {
		tt_free_entry_t *tt_free_cur, *tt_free_next;

		tt_free_cur = ((tt_free_entry_t *)pmap->tt_entry_free);
		tt_free_next = tt_free_cur->next;
		tt_free_cur->next = NULL;
		*ttp = (tt_entry_t *)tt_free_cur;
		pmap->tt_entry_free = (tt_entry_t *)tt_free_next;
	}
	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
#endif

	if (*ttp == NULL) {
		const unsigned int alloc_flags =
		    (options & PMAP_OPTIONS_NOWAIT) ? PMAP_PAGE_ALLOCATE_NOWAIT : 0;

		/* Allocate a VM page to be used as the page table. */
		if (pmap_page_alloc(&pa, alloc_flags) != KERN_SUCCESS) {
			return KERN_RESOURCE_SHORTAGE;
		}

		pt_desc_t *ptdp = ptd_alloc(pmap, alloc_flags);
		if (ptdp == NULL) {
			pmap_page_free(pa);
			return KERN_RESOURCE_SHORTAGE;
		}

		/**
		 * Drain the epochs to ensure any lingering batched operations that may have taken
		 * an in-flight reference to this page are complete.
		 */
		pmap_retype_epoch_prepare_drain();

		if (level < pt_attr_leaf_level(pmap_get_pt_attr(pmap))) {
			OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_ttepages_count : &inuse_user_ttepages_count));
		} else {
			OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_ptepages_count : &inuse_user_ptepages_count));
		}

		pmap_tt_ledger_credit(pmap, PAGE_SIZE);

		PMAP_ZINFO_PALLOC(pmap, PAGE_SIZE);

		/* Clear all PVH flags when using a page for a PTD to avoid tripping unexpected page flag usage checks. */
		pvh_store_head_unlocked(pa_index(pa), (uintptr_t)ptdp & ~PVH_HIGH_FLAGS, PVH_TYPE_PTDP);

		sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
		retype_params.level = (sptm_pt_level_t)level;

		/**
		 * SPTM TODO: To reduce the cost of draining and retyping, consider caching freed page table pages
		 * in a small per-CPU bucket and reusing them in preference to calling pmap_page_alloc() above.
		 */
		pmap_retype_epoch_drain();
		sptm_retype(pa, XNU_DEFAULT,
		    pmap->type == PMAP_TYPE_NESTED ? XNU_PAGE_TABLE_SHARED : XNU_PAGE_TABLE, retype_params);

#if 0
		/*
		 * SPTM TODO: We'll probably want to bring back this logic in slightly modified form once
		 * the SPTM fully supports 4K page tables on 16K devices.
		 */
		uint64_t pmap_page_size = pt_attr_page_size(pmap_get_pt_attr(pmap));
		if (PAGE_SIZE > pmap_page_size) {
			vm_address_t    va;
			vm_address_t    va_end;

			pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

			for (va_end = phystokv(pa) + PAGE_SIZE, va = phystokv(pa) + pmap_page_size; va < va_end; va = va + pmap_page_size) {
				((tt_free_entry_t *)va)->next = (tt_free_entry_t *)pmap->tt_entry_free;
				pmap->tt_entry_free = (tt_entry_t *)va;
			}
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
		}
#endif

		*ttp = (tt_entry_t *)phystokv(pa);
	}

	assert(*ttp);

	return KERN_SUCCESS;
}


static void
pmap_tt_deallocate(
	pmap_t pmap,
	tt_entry_t *ttp,
	unsigned int level)
{
	pt_desc_t *ptdp;
	vm_offset_t     free_page = 0;
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	ptdp = ptep_get_ptd(ttp);
	ptdp->va[ptd_get_index(ptdp, ttp)] = (vm_offset_t)-1;

	const uint16_t refcnt = sptm_get_page_table_refcnt(kvtophys_nofail((vm_offset_t)ttp));

	if (__improbable(refcnt != 0)) {
		panic("pmap_tt_deallocate(): ptdp %p, count %d", ptdp, refcnt);
	}

#if 0
	/*
	 * SPTM TODO: We'll probably want to bring back this logic in slightly modified form once
	 * the SPTM fully supports 4K page tables on 16K devices.
	 */
	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

	unsigned i;
	unsigned pt_acc_cnt;
	unsigned max_pt_index = PAGE_SIZE / pt_attr_page_size(pt_attr);
	for (i = 0, pt_acc_cnt = 0; i < max_pt_index; i++) {
		pt_acc_cnt += ptdp->ptd_info[i].refcnt;
	}

	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

	if (pt_acc_cnt == 0) {
		tt_free_entry_t *tt_free_list = (tt_free_entry_t *)&pmap->tt_entry_free;
		unsigned pt_free_entry_cnt = 1;

		while (pt_free_entry_cnt < max_pt_index && tt_free_list) {
			tt_free_entry_t *tt_free_list_next;

			tt_free_list_next = tt_free_list->next;
			if ((((vm_offset_t)tt_free_list_next) - ((vm_offset_t)ttp & ~PAGE_MASK)) < PAGE_SIZE) {
				pt_free_entry_cnt++;
			}
			tt_free_list = tt_free_list_next;
		}
		if (pt_free_entry_cnt == max_pt_index) {
			tt_free_entry_t *tt_free_list_cur;

			free_page = (vm_offset_t)ttp & ~PAGE_MASK;
			tt_free_list = (tt_free_entry_t *)&pmap->tt_entry_free;
			tt_free_list_cur = (tt_free_entry_t *)&pmap->tt_entry_free;

			while (tt_free_list_cur) {
				tt_free_entry_t *tt_free_list_next;

				tt_free_list_next = tt_free_list_cur->next;
				if ((((vm_offset_t)tt_free_list_next) - free_page) < PAGE_SIZE) {
					tt_free_list->next = tt_free_list_next->next;
				} else {
					tt_free_list = tt_free_list_next;
				}
				tt_free_list_cur = tt_free_list_next;
			}
		} else {
			((tt_free_entry_t *)ttp)->next = (tt_free_entry_t *)pmap->tt_entry_free;
			pmap->tt_entry_free = ttp;
		}
	} else {
		((tt_free_entry_t *)ttp)->next = (tt_free_entry_t *)pmap->tt_entry_free;
		pmap->tt_entry_free = ttp;
	}

	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
#else
	free_page = (vm_offset_t)ttp & ~PAGE_MASK;
#endif
	if (free_page != 0) {
		pmap_paddr_t pa = kvtophys_nofail(free_page);

		sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
		sptm_retype(pa, pmap->type == PMAP_TYPE_NESTED ? XNU_PAGE_TABLE_SHARED : XNU_PAGE_TABLE,
		    XNU_DEFAULT, retype_params);
		ptd_deallocate(ptep_get_ptd((pt_entry_t*)free_page));
		pvh_store_head_unlocked(pa_index(pa), 0, PVH_TYPE_NULL);
		pmap_page_free(pa);
		if (level < pt_attr_leaf_level(pt_attr)) {
			OSAddAtomic(-1, (pmap == kernel_pmap ? &inuse_kernel_ttepages_count : &inuse_user_ttepages_count));
		} else {
			OSAddAtomic(-1, (pmap == kernel_pmap ? &inuse_kernel_ptepages_count : &inuse_user_ptepages_count));
		}
		PMAP_ZINFO_PFREE(pmap, PAGE_SIZE);
		pmap_tt_ledger_debit(pmap, PAGE_SIZE);
	}
}

/**
 * Check table refcounts after clearing a translation table entry pointing to that table
 *
 * @note If the cleared TTE points to a leaf table, then that leaf table
 *       must have a refcnt of zero before the TTE can be removed.
 *
 * @param pmap The pmap containing the page table whose TTE is being removed.
 * @param tte Value stored in the TTE prior to clearing it
 * @param level The level of the page table that contains the TTE being removed
 */
static void
pmap_tte_check_refcounts(
	pmap_t pmap,
	tt_entry_t tte,
	unsigned int level)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	/**
	 * Remember, the passed in "level" parameter refers to the level above the
	 * table that's getting removed (e.g., removing an L2 TTE will unmap an L3
	 * page table).
	 */
	const bool remove_leaf_table = (level == pt_attr_twig_level(pt_attr));

	unsigned short refcnt = 0;

	/**
	 * It's possible that a concurrent pmap_disconnect() operation may need to reference
	 * a PTE on the pagetable page to be removed.  A full disconnect() may have cleared
	 * one or more PTEs on this page but not yet dropped the refcount, which would cause
	 * us to panic in this function on a non-zero refcount.  Moreover, it's possible for
	 * a disconnect-to-compress operation to set the compressed marker on a PTE, and
	 * for pmap_remove_range_options() to concurrently observe that marker, clear it, and
	 * drop the pagetable refcount accordingly, without taking any PVH locks that could
	 * synchronize it against the disconnect operation.  If that removal caused the
	 * refcount to reach zero, the pagetable page could be freed before the disconnect
	 * operation is finished using the relevant pagetable descriptor.
	 * Address these cases by waiting until all CPUs have been observed to not be
	 * executing pmap_disconnect().
	 */
	if (remove_leaf_table) {
		bitmap_t active_disconnects[BITMAP_LEN(MAX_CPUS)];
		const int max_cpu = ml_get_max_cpu_number();
		bitmap_full(&active_disconnects[0], max_cpu + 1);
		bool inflight_disconnect;

		/*
		 * Ensure the ensuing load of per-CPU inflight_disconnect is not speculated
		 * ahead of any prior PTE load which may have observed the effect of a
		 * concurrent disconnect operation.  An acquire fence is required for this;
		 * a load-acquire operation is insufficient.
		 */
		os_atomic_thread_fence(acquire);
		do {
			inflight_disconnect = false;
			for (int i = bitmap_first(&active_disconnects[0], max_cpu + 1);
			    i >= 0;
			    i = bitmap_next(&active_disconnects[0], i)) {
				const pmap_cpu_data_t *cpu_data = pmap_get_remote_cpu_data(i);
				if (cpu_data == NULL) {
					continue;
				}
				if (os_atomic_load_exclusive(&cpu_data->inflight_disconnect, relaxed)) {
					__builtin_arm_wfe();
					inflight_disconnect = true;
					continue;
				}
				os_atomic_clear_exclusive();
				bitmap_clear(&active_disconnects[0], (unsigned int)i);
			}
		} while (inflight_disconnect);
		/* Ensure the refcount is observed after any observation of inflight_disconnect */
		os_atomic_thread_fence(acquire);
		refcnt = sptm_get_page_table_refcnt(tte_to_pa(tte));
	}

#if MACH_ASSERT
	/**
	 * On internal devices, always do the page table consistency check
	 * regardless of page table level or the actual refcnt value.
	 */
	{
#else /* MACH_ASSERT */
	/**
	 * Only perform the page table consistency check when deleting leaf page
	 * tables and it seems like there might be valid/compressed mappings
	 * leftover.
	 */
	if (__improbable(remove_leaf_table && refcnt != 0)) {
#endif /* MACH_ASSERT */

		/**
		 * There are multiple problems that can arise as a non-zero refcnt:
		 * 1. A bug in the refcnt management logic.
		 * 2. A memory stomper or hardware failure.
		 * 3. The VM forgetting to unmap all of the valid mappings in an address
		 *    space before destroying a pmap.
		 *
		 * By looping over the page table and determining how many valid or
		 * compressed entries there actually are, we can narrow down which of
		 * these three cases is causing this panic. If the expected refcnt
		 * (valid + compressed) and the actual refcnt don't match then the
		 * problem is probably either a memory corruption issue (if the
		 * non-empty entries don't match valid+compressed, that could also be a
		 * sign of corruption) or refcnt management bug. Otherwise, there
		 * actually are leftover mappings and the higher layers of xnu are
		 * probably at fault.
		 */
		const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
		pt_entry_t *bpte = ((pt_entry_t *) (ttetokv(tte) & ~(pmap_page_size - 1)));

		pt_entry_t *ptep = bpte;
		unsigned short wiredcnt = ptep_get_info((pt_entry_t*)ttetokv(tte))->wiredcnt;
		unsigned short non_empty = 0, valid = 0, comp = 0;
		for (unsigned int i = 0; i < (pmap_page_size / sizeof(*ptep)); i++, ptep++) {
			/* Keep track of all non-empty entries to detect memory corruption. */
			if (__improbable(*ptep != ARM_PTE_EMPTY)) {
				non_empty++;
			}

			if (__improbable(pte_is_compressed(*ptep, ptep))) {
				comp++;
			} else if (__improbable((*ptep & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE)) {
				valid++;
			}
		}

#if MACH_ASSERT
		/**
		 * On internal machines, panic whenever a page table getting deleted has
		 * leftover mappings (valid or otherwise) or a leaf page table has a
		 * non-zero refcnt.
		 */
		if (__improbable((non_empty != 0) || (remove_leaf_table && ((refcnt != 0) || (wiredcnt != 0))))) {
#else /* MACH_ASSERT */
		/* We already know the leaf page-table has a non-zero refcnt, so panic. */
		{
#endif /* MACH_ASSERT */
			panic("%s: Found inconsistent state in soon to be deleted L%d table: %d valid, "
			    "%d compressed, %d non-empty, refcnt=%d, wiredcnt=%d, L%d tte=%#llx, pmap=%p, bpte=%p", __func__,
			    level + 1, valid, comp, non_empty, refcnt, wiredcnt, level, (uint64_t)tte, pmap, bpte);
		}
	}
}

/**
 * Remove translation table entry pointing to a nested shared region table
 *
 * @note The TTE to clear out is expected to point to a leaf table with a refcnt
 *       of zero.
 *
 * @param pmap The user pmap containing the nested page table whose TTE is being removed.
 * @param va_start Beginning of the VA range mapped by the table being removed, for TLB maintenance.
 * @param ttep Pointer to the TTE that should be cleared out.
 */
static void
pmap_tte_trim(
	pmap_t pmap,
	vm_offset_t va_start,
	tt_entry_t *ttep)
{
	pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);
	assert(ttep != NULL);
	const tt_entry_t tte = *ttep;
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if (__improbable(tte == ARM_TTE_EMPTY)) {
		panic("%s: L%d TTE is already empty. Potential double unmap or memory "
		    "stomper? pmap=%p ttep=%p", __func__, pt_attr_twig_level(pt_attr), pmap, ttep);
	}

	sptm_unnest_region(pmap->ttep, pmap->nested_pmap->ttep, va_start, pt_attr_twig_size(pt_attr) >> pt_attr->pta_page_shift);

	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);

	pmap_tte_check_refcounts(pmap, tte, pt_attr_twig_level(pt_attr));
}

/**
 * Remove a translation table entry.
 *
 * @note If the TTE to clear out points to a leaf table, then that leaf table
 *       must have a mapping refcount of zero before the TTE can be removed.
 * @note This function expects to be called with pmap locked exclusive, and will
 *       return with pmap unlocked.
 *
 * @param pmap The pmap containing the page table whose TTE is being removed.
 * @param va_start Beginning of the VA range mapped by the table being removed, for TLB maintenance.
 * @param ttep Pointer to the TTE that should be cleared out.
 * @param level The level of the page table that contains the TTE to be removed.
 */
static void
pmap_tte_remove(
	pmap_t pmap,
	vm_offset_t va_start,
	tt_entry_t *ttep,
	unsigned int level)
{
	pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);
	assert(ttep != NULL);
	const tt_entry_t tte = *ttep;

	if (__improbable(tte == ARM_TTE_EMPTY)) {
		panic("%s: L%d TTE is already empty. Potential double unmap or memory "
		    "stomper? pmap=%p ttep=%p", __func__, level, pmap, ttep);
	}

	sptm_unmap_table(pmap->ttep, va_start, (sptm_pt_level_t)level);

	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);

	pmap_tte_check_refcounts(pmap, tte, level);
}

/**
 * Given a pointer to an entry within a `level` page table, delete the
 * page table at `level` + 1 that is represented by that entry. For instance,
 * to delete an unused L3 table, `ttep` would be a pointer to the L2 entry that
 * contains the PA of the L3 table, and `level` would be "2".
 *
 * @note If the table getting deallocated is a leaf table, then that leaf table
 *       must have a mapping refcount of zero before getting deallocated.
 * @note This function expects to be called with pmap locked exclusive and will
 *       return with pmap unlocked.
 *
 * @param pmap The pmap that owns the page table to be deallocated.
 * @param va_start Beginning of the VA range mapped by the table being removed, for TLB maintenance.
 * @param ttep Pointer to the `level` TTE to remove.
 * @param level The level of the table that contains an entry pointing to the
 *              table to be removed. The deallocated page table will be a
 *              `level` + 1 table (so if `level` is 2, then an L3 table will be
 *              deleted).
 */
void
pmap_tte_deallocate(
	pmap_t pmap,
	vm_offset_t va_start,
	tt_entry_t *ttep,
	unsigned int level)
{
	tt_entry_t tte;

	pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);

	tte = *ttep;

	if (tte_get_ptd(tte)->pmap != pmap) {
		panic("%s: Passed in pmap doesn't own the page table to be deleted ptd=%p ptd->pmap=%p pmap=%p",
		    __func__, tte_get_ptd(tte), tte_get_ptd(tte)->pmap, pmap);
	}

	assertf((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE, "%s: invalid TTE %p (0x%llx)",
	    __func__, ttep, (unsigned long long)tte);

	/* pmap_tte_remove() will drop the pmap lock */
	pmap_tte_remove(pmap, va_start, ttep, level);

	pmap_tt_deallocate(pmap, (tt_entry_t *) phystokv(tte_to_pa(tte)), level + 1);
}

/*
 *	Remove a range of hardware page-table entries.
 *	The range is given as the first (inclusive)
 *	and last (exclusive) virtual addresses mapped by
 *      the PTE region to be removed.
 *
 *	The pmap must be locked shared.
 *	If the pmap is not the kernel pmap, the range must lie
 *	entirely within one pte-page. Assumes that the pte-page exists.
 *
 *	Returns the number of PTE changed
 */
MARK_AS_PMAP_TEXT static void
pmap_remove_range(
	pmap_t pmap,
	vm_map_address_t va,
	vm_map_address_t end)
{
	pmap_remove_range_options(pmap, va, end, PMAP_OPTIONS_REMOVE);
}

MARK_AS_PMAP_TEXT void
pmap_remove_range_options(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options)
{
	const unsigned int sptm_flags = ((options & PMAP_OPTIONS_REMOVE) ? SPTM_REMOVE_COMPRESSED : 0);
	unsigned int num_removed = 0;
	unsigned int num_external = 0, num_internal = 0, num_reusable = 0;
	unsigned int num_alt_internal = 0;
	unsigned int num_compressed = 0, num_alt_compressed = 0;
	unsigned short num_unwired = 0;
	bool need_strong_sync = false;

	/*
	 * The pmap lock should be held here.  It will only be held shared in most if not all cases.
	 */
	pmap_assert_locked(pmap, PMAP_LOCK_HELD);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const uint64_t pmap_page_size = PAGE_RATIO * pt_attr_page_size(pt_attr);
	const uint64_t pmap_page_shift = pt_attr_leaf_shift(pt_attr);
	vm_map_address_t va = start;
	pt_entry_t *cpte = pmap_pte(pmap, va);
	assert(cpte != NULL);

	while (va < end) {
		/**
		 * We may need to sleep when taking the PVH lock below, and our pmap_pv_remove()
		 * call below may also place the lock in sleep mode if processing a large PV list.
		 * We therefore can't leave preemption disabled across that code, which means we
		 * can't directly use the per-CPU prev_ptes array in that code.  Since that code
		 * only cares about the physical address stored in each prev_ptes entry, we'll
		 * use a local array to stash off only the 4-byte physical address index in order
		 * to reduce stack usage.
		 */
		unsigned int pai_list[SPTM_MAPPING_LIMIT];
		_Static_assert(SPTM_MAPPING_LIMIT <= 64,
		    "SPTM_MAPPING_LIMIT value causes excessive stack usage for pai_list");

		unsigned int num_mappings = (end - va) >> pmap_page_shift;
		if (num_mappings > SPTM_MAPPING_LIMIT) {
			num_mappings = SPTM_MAPPING_LIMIT;
		}

		/**
		 * Disable preemption to ensure that we can safely access per-CPU mapping data after
		 * issuing the SPTM call.
		 */
		disable_preemption();
		/**
		 * Enter the retype epoch for the batched unmap operation.  This is necessary because we
		 * cannot reasonably hold the PVH locks for all pages mapped by the region during this
		 * call, so a concurrent pmap_page_protect() operation against one of those pages may
		 * race this call.  That should be perfectly fine as far as the PTE updates are concerned,
		 * but if pmap_page_protect() then needs to retype the page, an SPTM violation may result
		 * if it does not first drain our epoch.
		 */
		pmap_retype_epoch_enter();
		sptm_unmap_region(pmap->ttep, va, num_mappings, sptm_flags);
		pmap_retype_epoch_exit();

		sptm_pte_t *prev_ptes = PERCPU_GET(pmap_sptm_percpu)->sptm_prev_ptes;
		for (unsigned int i = 0; i < num_mappings; ++i, ++cpte) {
			const pt_entry_t prev_pte = prev_ptes[i];

			if (pte_is_compressed(prev_pte, cpte)) {
				if (options & PMAP_OPTIONS_REMOVE) {
					++num_compressed;
					if (prev_pte & ARM_PTE_COMPRESSED_ALT) {
						++num_alt_compressed;
					}
				}
				pai_list[i] = INVALID_PAI;
				continue;
			} else if ((prev_pte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT) {
				pai_list[i] = INVALID_PAI;
				continue;
			}

			if (pte_is_wired(prev_pte)) {
				num_unwired++;
			}

			const pmap_paddr_t pa = pte_to_pa(prev_pte);

			if (__improbable(!pa_valid(pa))) {
				pai_list[i] = INVALID_PAI;
				continue;
			}
			pai_list[i] = pa_index(pa);
		}

		enable_preemption();
		cpte -= num_mappings;

		for (unsigned int i = 0; i < num_mappings; ++i, ++cpte) {
			if (pai_list[i] == INVALID_PAI) {
				continue;
			}
			locked_pvh_t locked_pvh;
			if (__improbable(options & PMAP_OPTIONS_NOPREEMPT)) {
				locked_pvh = pvh_lock_nopreempt(pai_list[i]);
			} else {
				locked_pvh = pvh_lock(pai_list[i]);
			}

			bool is_internal, is_altacct;
			pv_remove_return_t remove_status = pmap_remove_pv(pmap, cpte, &locked_pvh, &is_internal, &is_altacct);

			switch (remove_status) {
			case PV_REMOVE_SUCCESS:
				++num_removed;
				if (is_altacct) {
					assert(is_internal);
					num_internal++;
					num_alt_internal++;
				} else if (is_internal) {
					if (ppattr_test_reusable(pai_list[i])) {
						num_reusable++;
					} else {
						num_internal++;
					}
				} else {
					num_external++;
				}
				break;
			default:
				/*
				 * PVE already removed; this can happen due to a concurrent pmap_disconnect()
				 * executing before we grabbed the PVH lock.
				 */
				break;
			}

			pvh_unlock(&locked_pvh);
		}

		va += (num_mappings << pmap_page_shift);
	}

	if (__improbable(need_strong_sync)) {
		arm64_sync_tlb(true);
	}

	/*
	 *	Update the counts
	 */
	pmap_ledger_debit(pmap, task_ledgers.phys_mem, num_removed * pmap_page_size);

	if (pmap != kernel_pmap) {
		if (num_unwired != 0) {
			ptd_info_t * const ptd_info = ptep_get_info(cpte - 1);
			if (__improbable(os_atomic_sub_orig(&ptd_info->wiredcnt, num_unwired, relaxed) < num_unwired)) {
				panic("%s: pmap %p VA [0x%llx, 0x%llx) (ptd info %p) wired count underflow", __func__, pmap,
				    (unsigned long long)start, (unsigned long long)end, ptd_info);
			}
		}

		/* update ledgers */
		pmap_ledger_debit(pmap, task_ledgers.external, (num_external) * pmap_page_size);
		pmap_ledger_debit(pmap, task_ledgers.reusable, (num_reusable) * pmap_page_size);
		pmap_ledger_debit(pmap, task_ledgers.wired_mem, (num_unwired) * pmap_page_size);
		pmap_ledger_debit(pmap, task_ledgers.internal, (num_internal) * pmap_page_size);
		pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, (num_alt_internal) * pmap_page_size);
		pmap_ledger_debit(pmap, task_ledgers.alternate_accounting_compressed, (num_alt_compressed) * pmap_page_size);
		pmap_ledger_debit(pmap, task_ledgers.internal_compressed, (num_compressed) * pmap_page_size);
		/* make needed adjustments to phys_footprint */
		pmap_ledger_debit(pmap, task_ledgers.phys_footprint,
		    ((num_internal -
		    num_alt_internal) +
		    (num_compressed -
		    num_alt_compressed)) * pmap_page_size);
	}
}


/*
 *	Remove the given range of addresses
 *	from the specified map.
 *
 *	It is assumed that the start and end are properly
 *	rounded to the hardware page size.
 */
void
pmap_remove(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end)
{
	pmap_remove_options(pmap, start, end, PMAP_OPTIONS_REMOVE);
}

MARK_AS_PMAP_TEXT vm_map_address_t
pmap_remove_options_internal(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options)
{
	vm_map_address_t eva = end;
	tt_entry_t     *tte_p;
	bool            unlock = true;

	if (__improbable(end < start)) {
		panic("%s: invalid address range %p, %p", __func__, (void*)start, (void*)end);
	}
	if (__improbable(pmap->type == PMAP_TYPE_COMMPAGE)) {
		panic("%s: attempt to remove mappings from commpage pmap %p", __func__, pmap);
	}

	validate_pmap_mutable(pmap);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	pmap_lock_mode_t lock_mode = PMAP_LOCK_SHARED;
	pmap_lock(pmap, lock_mode);

	tte_p = pmap_tte(pmap, start);

	if ((tte_p == NULL) || ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_FAULT)) {
		goto done;
	}

	assertf((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE, "%s: invalid TTE %p (0x%llx) for pmap %p va 0x%llx",
	    __func__, tte_p, (unsigned long long)*tte_p, pmap, (unsigned long long)start);

	pmap_remove_range_options(pmap, start, end, options);

	if (pmap->type != PMAP_TYPE_USER) {
		goto done;
	}

	uint16_t refcnt = sptm_get_page_table_refcnt(tte_to_pa(*tte_p));
	if (__improbable(refcnt == 0)) {
		ptd_info_t *ptd_info = ptep_get_info((pt_entry_t*)ttetokv(*tte_p));
		os_atomic_inc(&ptd_info->wiredcnt, relaxed); // Prevent someone else from freeing the table if we need to drop the lock
		if (!pmap_lock_shared_to_exclusive(pmap)) {
			pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
		}
		lock_mode = PMAP_LOCK_EXCLUSIVE;
		refcnt = sptm_get_page_table_refcnt(tte_to_pa(*tte_p));
		if ((os_atomic_dec(&ptd_info->wiredcnt, relaxed) == 0) && (refcnt == 0)) {
			/**
			 * Drain any concurrent retype-sensitive SPTM operations.  This is needed to
			 * ensure that we don't unmap the page table and retype it while those operations
			 * are still finishing on other CPUs, leading to an SPTM violation.  In particular,
			 * the multipage batched cacheability/attribute update code may issue SPTM calls
			 * without holding the relevant PVH or pmap locks, so we can't guarantee those
			 * calls have actually completed despite observing refcnt == 0.
			 *
			 * At this point, we CAN guarantee that:
			 * 1) All prior PTE removals required to produce refcnt == 0 have
			 *    completed and been synchronized for all observers by DSB, and the
			 *    relevant PV list entries removed.  Subsequent calls not already in the
			 *    retype epoch will no longer observe these mappings.
			 * 2) We now hold the pmap lock exclusive, so there will be no further attempt
			 *    to enter mappings in this page table before it is unmapped.
			 */
			pmap_retype_epoch_prepare_drain();
			pmap_retype_epoch_drain();
			pmap_tte_deallocate(pmap, start, tte_p, pt_attr_twig_level(pt_attr));
			unlock = false; // pmap_tte_deallocate() has dropped the lock
		}
	}
done:
	if (unlock) {
		pmap_unlock(pmap, lock_mode);
	}

	return eva;
}

void
pmap_remove_options(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	int options)
{
	vm_map_address_t va;

	if (pmap == PMAP_NULL) {
		return;
	}

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	PMAP_TRACE(2, PMAP_CODE(PMAP__REMOVE) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(start),
	    VM_KERNEL_ADDRHIDE(end));

#if MACH_ASSERT
	if ((start | end) & pt_attr_leaf_offmask(pt_attr)) {
		panic("pmap_remove_options() pmap %p start 0x%llx end 0x%llx",
		    pmap, (uint64_t)start, (uint64_t)end);
	}
	if ((end < start) || (start < pmap->min) || (end > pmap->max)) {
		panic("pmap_remove_options(): invalid address range, pmap=%p, start=0x%llx, end=0x%llx",
		    pmap, (uint64_t)start, (uint64_t)end);
	}
#endif

	/*
	 * We allow single-page requests to execute non-preemptibly,
	 * as it doesn't make sense to sample AST_URGENT for a single-page
	 * operation, and there are a couple of special use cases that
	 * require a non-preemptible single-page operation.
	 */
	if ((end - start) > (pt_attr_page_size(pt_attr) * PAGE_RATIO)) {
		pmap_verify_preemptible();
	}

	/*
	 *      Invalidate the translation buffer first
	 */
	va = start;
	while (va < end) {
		vm_map_address_t l;

		l = ((va + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr));
		if (l > end) {
			l = end;
		}

		va = pmap_remove_options_internal(pmap, va, l, options);
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__REMOVE) | DBG_FUNC_END);
}


/*
 *	Remove phys addr if mapped in specified map
 */
void
pmap_remove_some_phys(
	__unused pmap_t map,
	__unused ppnum_t pn)
{
	/* Implement to support working set code */
}

/*
 * Implementation of PMAP_SWITCH_USER that Mach VM uses to
 * switch a thread onto a new vm_map.
 */
void
pmap_switch_user(thread_t thread, vm_map_t new_map)
{
	pmap_t new_pmap = new_map->pmap;


	thread->map = new_map;
	pmap_set_pmap(new_pmap, thread);

}
void
pmap_set_pmap(
	pmap_t pmap,
	__unused thread_t thread)
{
	pmap_switch(pmap);
}

MARK_AS_PMAP_TEXT void
pmap_switch_internal(
	pmap_t pmap)
{
	validate_pmap_mutable(pmap);
	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const uint16_t asid_index = PMAP_HWASID(pmap);
	if (__improbable((asid_index == 0) && (pmap != kernel_pmap))) {
		panic("%s: attempt to activate pmap with invalid ASID %p", __func__, pmap);
	}

#if __ARM_KERNEL_PROTECT__
	asid_index >>= 1;
#endif

	if (asid_index > 0) {
		pmap_update_plru(asid_index);
	}

	sptm_switch_root(pmap->ttep);
}

void
pmap_switch(
	pmap_t pmap)
{
	PMAP_TRACE(1, PMAP_CODE(PMAP__SWITCH) | DBG_FUNC_START, VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), PMAP_HWASID(pmap));
	pmap_switch_internal(pmap);
	PMAP_TRACE(1, PMAP_CODE(PMAP__SWITCH) | DBG_FUNC_END);
}

void
pmap_page_protect(
	ppnum_t ppnum,
	vm_prot_t prot)
{
	pmap_page_protect_options(ppnum, prot, 0, NULL);
}

/**
 *  Helper function for performing per-mapping accounting following an SPTM disjoint unmap request.
 *
 * @note [pmap] cannot be the kernel pmap. This is because we do not maintain a ledger in the
 *       kernel pmap.
 *
 * @param pmap The pmap that contained the mapping
 * @param pai The physical page index mapped by the mapping
 * @param is_compressed Indicates whether the operation was an unmap-to-compress vs. a full unmap
 * @param is_internal Indicates whether the mapping was for an internal (aka anonymous) VM page
 * @param is_altacct Indicates whether the mapping was subject to alternate accounting.
 */
static void
pmap_disjoint_unmap_accounting(pmap_t pmap, unsigned int pai, bool is_compressed, bool is_internal, bool is_altacct)
{
	const pt_attr_t *const pt_attr = pmap_get_pt_attr(pmap);
	pvh_assert_locked(pai);

	assert(pmap != kernel_pmap);

	if (is_internal &&
	    !is_altacct &&
	    ppattr_test_reusable(pai)) {
		pmap_ledger_debit(pmap, task_ledgers.reusable, pt_attr_page_size(pt_attr) * PAGE_RATIO);
	} else if (!is_internal) {
		pmap_ledger_debit(pmap, task_ledgers.external, pt_attr_page_size(pt_attr) * PAGE_RATIO);
	}

	if (is_altacct) {
		assert(is_internal);
		pmap_ledger_debit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		if (is_compressed) {
			pmap_ledger_credit(pmap, task_ledgers.internal_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			pmap_ledger_credit(pmap, task_ledgers.alternate_accounting_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		}
	} else if (ppattr_test_reusable(pai)) {
		assert(is_internal);
		if (is_compressed) {
			pmap_ledger_credit(pmap, task_ledgers.internal_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			/* was not in footprint, but is now */
			pmap_ledger_credit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		}
	} else if (is_internal) {
		pmap_ledger_debit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);

		/*
		 * Update all stats related to physical footprint, which only
		 * deals with internal pages.
		 */
		if (is_compressed) {
			/*
			 * This removal is only being done so we can send this page to
			 * the compressor; therefore it mustn't affect total task footprint.
			 */
			pmap_ledger_credit(pmap, task_ledgers.internal_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		} else {
			/*
			 * This internal page isn't going to the compressor, so adjust stats to keep
			 * phys_footprint up to date.
			 */
			pmap_ledger_debit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		}
	} else {
		/* external page: no impact on ledgers */
	}
}

/**
 * Helper function for issuing a disjoint unmap request to the SPTM and performing
 * related accounting.  This function uses the 'prev_ptes' list generated by
 * the sptm_unmap_disjoint() call to determine whether said call altered the
 * relevant PTEs in a manner that would require accounting updates.
 *
 * @param pa The physical address against which the disjoint unmap will be issued.
 * @param num_mappings The number of disjoint mappings for the SPTM to update.
 *                     The per-CPU sptm_ops array should contain the same number
 *                     of individual disjoint requests.
 */
static void
pmap_disjoint_unmap(pmap_paddr_t pa, unsigned int num_mappings)
{
	const unsigned int pai = pa_index(pa);

	pvh_assert_locked(pai);

	assert(num_mappings <= SPTM_MAPPING_LIMIT);

	assert(get_preemption_level() > 0);
	pmap_sptm_percpu_data_t *sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);

	sptm_unmap_disjoint(pa, sptm_pcpu->sptm_ops_pa, num_mappings);

	for (unsigned int cur_mapping = 0; cur_mapping < num_mappings; ++cur_mapping) {
		pt_entry_t prev_pte = sptm_pcpu->sptm_prev_ptes[cur_mapping];

		pt_desc_t * const ptdp = sptm_pcpu->sptm_ptds[cur_mapping];
		const pmap_t pmap = ptdp->pmap;

		assertf(((prev_pte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT) ||
		    (pte_to_pa(prev_pte) == pa), "%s: prev_pte 0x%llx does not map pa 0x%llx",
		    __func__, (unsigned long long)prev_pte, (unsigned long long)pa);

		const pt_attr_t *const pt_attr = pmap_get_pt_attr(pmap);
		pmap_ledger_debit(pmap, task_ledgers.phys_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);

		if (pmap != kernel_pmap) {
			/*
			 * If the prior PTE is invalid (which may happen due to a concurrent remove operation),
			 * the compressed marker won't be written so we shouldn't account the mapping as compressed.
			 */
			const bool is_compressed = (((prev_pte & ARM_PTE_TYPE_MASK) != ARM_PTE_TYPE_FAULT) &&
			    ((sptm_pcpu->sptm_ops[cur_mapping].pte_template & ARM_PTE_COMPRESSED_MASK) != 0));
			const bool is_internal = (sptm_pcpu->sptm_acct_flags[cur_mapping] & PMAP_SPTM_FLAG_INTERNAL) != 0;
			const bool is_altacct = (sptm_pcpu->sptm_acct_flags[cur_mapping] & PMAP_SPTM_FLAG_ALTACCT) != 0;

			/*
			 * The rule is that accounting related to PTE contents (wired, PTD refcount)
			 * must be updated by whoever clears the PTE, while accounting related to physical page
			 * attributes must be updated by whoever clears the PVE.  We therefore always call
			 * pmap_disjoint_unmap_accounting() here since we're removing the PVE, but only update
			 * wired/PTD accounting if the prior PTE was valid.
			 */
			pmap_disjoint_unmap_accounting(pmap, pai, is_compressed, is_internal, is_altacct);

			if ((prev_pte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT) {
				continue;
			}

			if (pte_is_wired(prev_pte)) {
				pmap_ledger_debit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				if (__improbable(os_atomic_dec_orig(&sptm_pcpu->sptm_ptd_info[cur_mapping]->wiredcnt, relaxed) == 0)) {
					panic("%s: over-unwire of ptdp %p, ptd info %p", __func__,
					    ptdp, sptm_pcpu->sptm_ptd_info[cur_mapping]);
				}
			}
		}
	}
}

/**
 * The following two functions, pmap_multipage_op_submit_disjoint() and
 * pmap_multipage_op_add_page(), are intended to allow callers to manage batched SPTM
 * operations that may span multiple physical pages.  They are intended to operate in
 * a way that allows callers such as pmap_page_protect_options_with_flush_range() to
 * insert mappings into the per-CPU SPTM disjoint ops array in the same manner that
 * they would for an ordinary single-page operation.
 * Functions such as pmap_page_protect_options_with_flush_range() operate on a single
 * physical page but may be passed a non-NULL flush_range object to indicate that the
 * call is part of a larger batched operation which may span multiple physical pages.
 * In that scenario, these functions are intended to be used as follows:
 * 1) Call pmap_multipage_op_add_page() to insert a "header" for the page into the per-
 *    CPU SPTM ops array.  Use the return value from this call as the starting index
 *    at which to add ordinary mapping entries into the same array.
 * 2) Insert sptm_disjoint_op_t entries into the ops array in the normal manner until
 *    the array is full, the SPTM options required for the upcoming sequence of pages
 *    need to change, or the current mapping matches flush_range->current_ptep.
 *    In the latter case, pmap_insert_flush_range_template() may instead be used
 *    to insert the mapping into the per-CPU SPTM region templates array.  See the
 *    documentation for pmap_insert_flush_range_template() below.
 * 3) If the array is full, call pmap_multipage_op_submit_disjoint() and return to step 1).
 * 4) If the SPTM options need to change, call pmap_multipage_op_add_page() to insert
 *    a new header with the updated options and, using the return value as the new
 *    insertion point for the ops array, resume step 2).
 * 5) Upon completion, if there are any pending not-yet-submitted mappings, do not
 *    submit those mappings to the SPTM as would ordinarily be done for a single-page
 *    call.  These trailing mappings will be submitted as part of the next batch,
 *    or by the next-higher caller if the range operation is complete.
 *
 * Note that, as a performance optimization, the caller may track the insertion
 * point in the disjoint ops array locally (i.e. without incrementing
 * flush_range->pending_disjoint_entries on every iteration, as long as it takes care to do the
 * following:
 * 1) Initialize and update that insertion point as described in steps 1) and 4) above.
 * 2) Pass the updated insertion point as the 'pending_disjoint_entries' parameter into the calls
 *    in steps 3) and 4) above.
 * 3) Update flush_range->pending_disjoint_entries with the locally-maintained value along with
 *    step 5) above.
 */

/**
 * Submit any pending disjoint multi-page mapping updates to the SPTM.
 *
 * @note This function must be called with preemption disabled, and will drop
 *       the preemption-disable count upon submitting to the SPTM.
 * @note [pending_disjoint_entries] must include *all* pending entries in the SPTM ops array,
 *       including physical address "header" entries.
 * @note This function automatically updates the per_paddr_header.num_mappings field
 *       for the most recent physical address header in the SPTM ops array to its final
 *       value.
 *
 * @param pending_disjoint_entries The number of not-yet-submitted mappings according to the caller.
 *                        This value may be greater than [flush_range]->pending_disjoint_entries if
 *                        the caller has inserted mappings into the ops array without
 *                        updating [flush_range]->pending_disjoint_entries, in which case this
 *                        function will update [flush_range]->pending_disjoint_entries with the
 *                        caller's value.
 * @param flush_range The object tracking the current state of the multipage disjoint
 *                    operation.
 */
static inline void
pmap_multipage_op_submit_disjoint(unsigned int pending_disjoint_entries, pmap_tlb_flush_range_t *flush_range)
{
	/**
	 * Reconcile the number of pending entries as tracked by the caller with the
	 * number of pending entries tracked by flush_range.  If the caller's value is
	 * greater, we assume the caller has inserted locally-tracked mappings into the
	 * array without directly updating flush_range->pending_disjoint_entries.  Otherwise, we
	 * assume the caller has no locally-tracked mappings and is simply trying to
	 * purge any pending mappings from a prior call sequence.
	 */
	if (pending_disjoint_entries > flush_range->pending_disjoint_entries) {
		flush_range->pending_disjoint_entries = pending_disjoint_entries;
	} else {
		assert(pending_disjoint_entries == 0);
	}
	if (flush_range->pending_disjoint_entries != 0) {
		assert(get_preemption_level() > 0);
		/**
		 * Compute the correct number of mappings for the most recent paddr
		 * header based on the current position in the SPTM ops array.
		 */
		flush_range->current_header->per_paddr_header.num_mappings =
		    flush_range->pending_disjoint_entries - flush_range->current_header_first_mapping_index;
		const sptm_return_t sptm_return = sptm_update_disjoint_multipage(
			PERCPU_GET(pmap_sptm_percpu)->sptm_ops_pa, flush_range->pending_disjoint_entries);

		/**
		 * We may be submitting the batch and exiting the epoch partway through
		 * processing the PV list for a page.  That's fine, because in that case we'll
		 * hold the PV lock for that page, which will prevent mappings of that page from
		 * being disconnected and will prevent the completion of pmap_remove() against
		 * any of those mappings, thus also guaranteeing the relevant page table pages
		 * can't be freed.  The epoch still protects mappings for any prior page in
		 * the batch, whose PV locks are no longer held.
		 */
		pmap_retype_epoch_exit();
		enable_preemption();
		flush_range->submitted_entries += flush_range->pending_disjoint_entries;
		flush_range->pending_disjoint_entries = 0;
		if (sptm_return == SPTM_UPDATE_DELAYED_TLBI) {
			flush_range->ptfr_flush_needed = true;
		}
	}
}

/**
 * Insert a new physical address "header" entry into the per-CPU SPTM ops array for a
 * multi-page SPTM operation.  It is expected that the caller will subsequently add
 * mapping entries for this physical address into the array.
 *
 * @note This function will disable preemption upon creation of the first paddr header
 *       (index 0 in the per-CPU SPTM ops array) and it is expected that
 *       pmap_multipage_op_submit() will subsequently be called on the same CPU.
 * @note Before inserting the new header, this function automatically updates the
 *       per_paddr_header.num_mappings field for the previous physical address header
 *       (if present) in the SPTM ops array to its final value.
 *
 * @param phys The physical address for which to insert a header entry.
 * @param pending_disjoint_entries The number of not-yet-submitted mappings according to the caller.
 *                        This value may be greater than [flush_range]->pending_disjoint_entries if
 *                        the caller has inserted mappings into the ops array without
 *                        updating [flush_range]->pending_disjoint_entries, in which case this
 *                        function will update [flush_range]->pending_disjoint_entries with the
 *                        caller's value.
 * @param sptm_update_options SPTM_UPDATE_* flags to pass to the SPTM call.
 *                            SPTM_UPDATE_SKIP_PAPT is automatically inserted by this
 *                            function.
 * @param flush_range The object tracking the current state of the multipage operation.
 *
 * @return The starting index at which the caller should insert mapping entries into the
 *         per-CPU SPTM ops array.
 */
static inline unsigned int
pmap_multipage_op_add_page(
	pmap_paddr_t phys,
	unsigned int pending_disjoint_entries,
	uint32_t sptm_update_options,
	pmap_tlb_flush_range_t *flush_range)
{
	/**
	 * Reconcile the number of pending entries as tracked by the caller with the
	 * number of pending entries tracked by flush_range.  If the caller's value is
	 * greater, we assume the caller has inserted locally-tracked mappings into the
	 * array without directly updating flush_range->pending_disjoint_entries.  Otherwise, we
	 * assume the caller has no locally-tracked mappings and is adding its paddr
	 * header for the first time.
	 */
	if (pending_disjoint_entries > flush_range->pending_disjoint_entries) {
		flush_range->pending_disjoint_entries = pending_disjoint_entries;
	} else {
		assert(pending_disjoint_entries == 0);
	}
	if (flush_range->pending_disjoint_entries >= (SPTM_MAPPING_LIMIT - 1)) {
		/**
		 * If the SPTM ops array is either full or only has space for the paddr
		 * header, there won't be room for mapping entries, so submit the pending
		 * mappings to the SPTM now.
		 */
		pmap_multipage_op_submit_disjoint(pending_disjoint_entries, flush_range);
	}
	pending_disjoint_entries = flush_range->pending_disjoint_entries;

	sptm_update_options |= SPTM_UPDATE_SKIP_PAPT;
	if (pending_disjoint_entries == 0) {
		disable_preemption();
		/**
		 * Enter the retype epoch while we gather the disjoint update arguments
		 * and issue the SPTM call.  Since this operation may cover multiple physical
		 * pages, we may construct the argument array and invoke the SPTM without holding
		 * all relevant PVH locks or pmap locks.  We therefore need to record that we are
		 * collecting and modifying mapping state so that e.g. pmap_page_protect() does
		 * not attempt to retype the underlying pages and pmap_remove() does not attempt
		 * to free the page tables used for these mappings without first draining our epoch.
		 */
		pmap_retype_epoch_enter();
		flush_range->pending_disjoint_entries = 1;
	} else {
		/**
		 * Before inserting the new header, update the prior header's number
		 * of paddr-specific mappings to its final value.
		 */
		assert(flush_range->current_header != NULL);
		flush_range->current_header->per_paddr_header.num_mappings =
		    pending_disjoint_entries - flush_range->current_header_first_mapping_index;
	}
	sptm_disjoint_op_t *sptm_ops = PERCPU_GET(pmap_sptm_percpu)->sptm_ops;
	flush_range->current_header = (sptm_update_disjoint_multipage_op_t*)&sptm_ops[pending_disjoint_entries];
	flush_range->current_header_first_mapping_index = ++pending_disjoint_entries;
	flush_range->current_header->per_paddr_header.paddr = phys;
	flush_range->current_header->per_paddr_header.num_mappings = 0;
	flush_range->current_header->per_paddr_header.options = sptm_update_options;

	return pending_disjoint_entries;
}

/**
 * The following two functions, pmap_multipage_op_submit_region() and
 * pmap_insert_flush_range_template(), are meant to be used in a similar fashion
 * to pmap_multipage_op_submit_disjoint() and pmap_multipage_op_add_page(),
 * but for the specific case in which a given mapping within a PV list happens
 * to map the current VA within a VA region being operated on by
 * phys_attribute_clear_range().  This allows the pmap to further optimize
 * the SPTM calls by using sptm_update_region() to modify all mappings within
 * the VA region, which requires far fewer table walks than a disjoint operation.
 * Since the starting VA of the region, the owning pmap, and the insertion point
 * within the per-CPU region templates array are already known, these functions
 * don't require the special "header" entry or the complex array position tracking
 * of their disjoint equivalents above.
 * Note that these functions may be used together with the disjoint functions above;
 * these functions can be used for the "primary" mappings corresponding to the VA
 * region being manipulated by the VM layer, while the disjoint functions can be
 * used for any alias mappings of the underlying pages which fall outside that
 * VA region.
 */

/**
 * Submit any pending region-based templates for the specified flush_range.
 *
 * @note This function must be called with preemption disabled, and will drop
 *       the preemption-disable count upon submitting to the SPTM.
 *
 * @param flush_range The object tracking the current state of the region operation.
 */
static inline void
pmap_multipage_op_submit_region(pmap_tlb_flush_range_t *flush_range)
{
	if (flush_range->pending_region_entries != 0) {
		assert(get_preemption_level() > 0);
		pmap_assert_locked(flush_range->ptfr_pmap, PMAP_LOCK_SHARED);
		/**
		 * If there are any pending disjoint entries, we're already in a retype epoch.
		 * For disjoint entries, we need to hold the epoch during the entire time we
		 * construct the disjoint ops array because those ops may point to some arbitrary
		 * pmap and we need to ensure the relevant page tables and even the pmap itself
		 * aren't concurrently reclaimed while our ops array points to them.
		 * But for a region op like this, we know we already hold the relevant pmap lock
		 * so none of the above can happen concurrently.  We therefore only need to hold
		 * the epoch across the SPTM call itself to prevent a concurrent unmap operation
		 * from attempting to retype the mapped pages while our SPTM call has them in-
		 * flight.
		 */
		if (flush_range->pending_disjoint_entries == 0) {
			pmap_retype_epoch_enter();
		}
		const sptm_return_t sptm_return = sptm_update_region(flush_range->ptfr_pmap->ttep,
		    flush_range->pending_region_start, flush_range->pending_region_entries,
		    PERCPU_GET(pmap_sptm_percpu)->sptm_templates_pa,
		    SPTM_UPDATE_PERMS_AND_WAS_WRITABLE | SPTM_UPDATE_AF | SPTM_UPDATE_DEFER_TLBI);
		if (flush_range->pending_disjoint_entries == 0) {
			pmap_retype_epoch_exit();
		}
		enable_preemption();
		flush_range->submitted_entries += flush_range->pending_region_entries;
		flush_range->pending_region_start += (flush_range->pending_region_entries <<
		        pmap_get_pt_attr(flush_range->ptfr_pmap)->pta_page_shift);
		flush_range->pending_region_entries = 0;
		if (sptm_return == SPTM_UPDATE_DELAYED_TLBI) {
			flush_range->ptfr_flush_needed = true;
		}
	}
}

/**
 * Insert a PTE template into the per-CPU SPTM region ops array.
 * This is meant to be used as a performance optimization for the case in which a given
 * mapping being processed by a function such as pmap_page_protect_options_with_flush_range()
 * happens to map the current iteration position within [flush_range]'s VA region.
 * In this case the mapping can be inserted as a region-based template rather than a disjoint
 * operation as would be done in the general case.  The idea is that region-based SPTM
 * operations are significantly less expensive than disjoint operations, because each region
 * operation only requires a single page table walk at the beginning vs. a table walk for
 * each mapping in the disjoint case.  Since the majority of mappings processed by a flush
 * range operation belong to the main flush range VA region (i.e. alias mappings outside
 * the region are less common), the performance improvement can be significant.
 *
 * @note This function will disable preemption upon inserting the first entry into the
 *       per-CPU templates array, and will re-enable preemption upon submitting the region
 *       operation to the SPTM.
 *
 * @param template The PTE template to insert into the per-CPU templates array.
 * @param flush_range The object tracking the current state of the region operation.
 *
 * @return True if the region operation was submitted to the SPTM, false otherwise.
 */
static inline bool
pmap_insert_flush_range_template(pt_entry_t template, pmap_tlb_flush_range_t *flush_range)
{
	if (flush_range->pending_region_entries == 0) {
		disable_preemption();
	}
	flush_range->region_entry_added = true;
	PERCPU_GET(pmap_sptm_percpu)->sptm_templates[flush_range->pending_region_entries++] = template;
	if (flush_range->pending_region_entries == SPTM_MAPPING_LIMIT) {
		pmap_multipage_op_submit_region(flush_range);
		return true;
	}
	return false;
}

/**
 * Wrapper function for submitting any pending operations, region-based or disjoint,
 * tracked by a flush range object.  This is meant to be used by the top-level caller that
 * iterates over the flush range's VA region and calls functions such as
 * pmap_page_protect_options_with_flush_range() or arm_force_fast_fault_with_flush_range()
 * to construct the relevant SPTM operations arrays.
 *
 * @param flush_range The object tracking the current state of region and/or disjoint operations.
 */
static inline void
pmap_multipage_op_submit(pmap_tlb_flush_range_t *flush_range)
{
	pmap_multipage_op_submit_disjoint(0, flush_range);
	pmap_multipage_op_submit_region(flush_range);
}

/**
 * This is an internal-only flag that indicates the caller of pmap_page_protect_options_with_flush_range()
 * is removing/updating all mappings in preparation for a retype operation.  In this case
 * pmap_page_protect_options() will assume (and assert) that the PVH lock for the physical page is held
 * by the calller, and will perform the necessary retype epoch drain prior to returning.
 */
#define PMAP_OPTIONS_PPO_PENDING_RETYPE 0x80000000
_Static_assert(PMAP_OPTIONS_PPO_PENDING_RETYPE & PMAP_OPTIONS_RESERVED_MASK,
    "PMAP_OPTIONS_PPO_PENDING_RETYPE outside reserved encoding space");

/**
 * Lower the permission for all mappings to a given page. If VM_PROT_NONE is specified,
 * the mappings will be removed.
 *
 * @param ppnum Page number to lower the permission of.
 * @param prot The permission to lower to.
 * @param options PMAP_OPTIONS_NOFLUSH indicates TLBI flush is not needed.
 *                PMAP_OPTIONS_PPO_PENDING_RETYPE indicates the PVH lock for ppnum is
 *                already locked and a retype epoch drain shold be performed.
 *                PMAP_OPTIONS_COMPRESSOR indicates the function is called by the
 *                VM compressor.
 * @param locked_pvh If non-NULL, this indicates the PVH lock for [ppnum] is already locked
 *                   by the caller.  This is an input/output parameter which may be updated
 *                   to reflect a new PV head value to be passed to a later call to pvh_unlock().
 * @param flush_range When present, this function will skip the TLB flush for the
 *                    mappings that are covered by the range, leaving that to be
 *                    done later by the caller.  It may also avoid submitting mapping
 *                    updates directly to the SPTM, instead accumulating them in a
 *                    per-CPU array to be submitted later by the caller.
 *
 * @note PMAP_OPTIONS_NOFLUSH and flush_range cannot both be specified.
 */
MARK_AS_PMAP_TEXT static void
pmap_page_protect_options_with_flush_range(
	ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options,
	locked_pvh_t *locked_pvh,
	pmap_tlb_flush_range_t *flush_range)
{
	pmap_paddr_t phys = ptoa(ppnum);
	locked_pvh_t local_locked_pvh = {.pvh = 0};
	pv_entry_t *pve_p = NULL;
	pv_entry_t *pveh_p = NULL;
	pv_entry_t *pvet_p = NULL;
	pt_entry_t *pte_p = NULL;
	pv_entry_t *new_pve_p = NULL;
	pt_entry_t *new_pte_p = NULL;

	bool remove = false;
	unsigned int pvh_cnt = 0;
	unsigned int num_mappings = 0;

	assert(ppnum != vm_page_fictitious_addr);

	/**
	 * Assert that PMAP_OPTIONS_NOFLUSH and flush_range cannot both be specified.
	 *
	 * PMAP_OPTIONS_NOFLUSH indicates there is no need of flushing the TLB in the entire operation, and
	 * flush_range indicates the caller requests deferral of the TLB flushing. Fundemantally, the two
	 * semantics conflict with each other, so assert they are not both true.
	 */
	assert(!(flush_range && (options & PMAP_OPTIONS_NOFLUSH)));

	/* Only work with managed pages. */
	if (!pa_valid(phys)) {
		return;
	}

	/*
	 * Determine the new protection.
	 */
	switch (prot) {
	case VM_PROT_ALL:
		return;         /* nothing to do */
	case VM_PROT_READ:
	case VM_PROT_READ | VM_PROT_EXECUTE:
		break;
	default:
		/* PPL security model requires that we flush TLBs before we exit if the page may be recycled. */
		options = options & ~PMAP_OPTIONS_NOFLUSH;
		remove = true;
		break;
	}

	/**
	 * We don't support cross-page batching (indicated by flush_range being non-NULL) for removals,
	 * as removals must use the SPTM prev_ptes array for accounting, which isn't supported for cross-
	 * page batches.
	 */
	assert((flush_range == NULL) || !remove);

	unsigned int pai = pa_index(phys);
	if (__probable(locked_pvh == NULL)) {
		if (flush_range != NULL) {
			/**
			 * If we're partway through processing a multi-page batched call,
			 * preemption will already be disabled so we can't simply call
			 * pvh_lock() which may block.  Instead, we first try to acquire
			 * the lock without waiting, which in most cases should succeed.
			 * If it fails, we submit the pending batched operations to re-
			 * enable preemption and then acquire the lock normally.
			 */
			local_locked_pvh = pvh_try_lock(pai);
			if (__improbable(!pvh_try_lock_success(&local_locked_pvh))) {
				pmap_multipage_op_submit(flush_range);
				local_locked_pvh = pvh_lock(pai);
			}
		} else {
			local_locked_pvh = pvh_lock(pai);
		}
	} else {
		local_locked_pvh = *locked_pvh;
	}
	assert(local_locked_pvh.pvh != 0);
	pvh_assert_locked(pai);

	bool pvh_lock_sleep_mode_needed = false;

	/*
	 * PVH should be locked before accessing per-CPU data, as we're relying on the lock
	 * to disable preemption.
	 */
	pmap_cpu_data_t *pmap_cpu_data = NULL;
	pmap_sptm_percpu_data_t *sptm_pcpu = NULL;
	sptm_disjoint_op_t *sptm_ops = NULL;
	pt_desc_t **sptm_ptds = NULL;
	ptd_info_t **sptm_ptd_info = NULL;

	/* BEGIN IGNORE CODESTYLE */

	/**
	 * This would also work as a block, with the above variables declared using the
	 * __block qualifier, but the extra runtime overhead of block syntax (e.g.
	 * dereferencing __block variables through stack forwarding pointers) isn't needed
	 * here, as we never need to use this code sequence as a closure.
	 */
	#define PPO_PERCPU_INIT() do { \
	        disable_preemption(); \
	        pmap_cpu_data = pmap_get_cpu_data(); \
	        sptm_pcpu = PERCPU_GET(pmap_sptm_percpu); \
	        sptm_ops = sptm_pcpu->sptm_ops; \
	        sptm_ptds = sptm_pcpu->sptm_ptds; \
	        sptm_ptd_info = sptm_pcpu->sptm_ptd_info; \
	        if (remove) { \
	                os_atomic_store(&pmap_cpu_data->inflight_disconnect, true, relaxed); \
			/* \
			 * Ensure the store to inflight_disconnect will be observed before any of the
			 * ensuing PTE/refcount stores in this function.  This flag is used to avoid
			 * a race in which the VM may clear a pmap's mappings and destroy the pmap on
			 * another CPU, in between this function's clearing a PTE and dropping the
			 * corresponding pagetable refcount.  That can lead to a panic if the
			 * destroying thread observes a non-zero refcount.  For this we need a store-
			 * store barrier; a store-release operation would not be sufficient.
			 */ \
	                os_atomic_thread_fence(release); \
	        } \
	} while (0)

	/* END IGNORE CODESTYLE */


	PPO_PERCPU_INIT();

	pv_entry_t **pve_pp = NULL;

	if (pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(local_locked_pvh.pvh);
	} else if (pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_PVEP)) {
		pve_p = pvh_pve_list(local_locked_pvh.pvh);
		pveh_p = pve_p;
	} else if (__improbable(!pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_NULL))) {
		panic("%s: invalid PV head 0x%llx for PA 0x%llx", __func__, (uint64_t)local_locked_pvh.pvh, (uint64_t)phys);
	}

	int pve_ptep_idx = 0;
	const bool compress = (options & PMAP_OPTIONS_COMPRESSOR);

	/*
	 * We need to keep track of whether a particular PVE list contains IOMMU
	 * mappings when removing entries, because we should only remove CPU
	 * mappings. If a PVE list contains at least one IOMMU mapping, we keep
	 * it around.
	 */
	bool iommu_mapping_in_pve = false;

	/**
	 * With regard to TLBI, there are three cases:
	 *
	 * 1. PMAP_OPTIONS_NOFLUSH is specified. In such case, SPTM doesn't need to flush TLB and neither does pmap.
	 * 2. PMAP_OPTIONS_NOFLUSH is not specified, but flush_range is, indicating the caller intends to flush TLB
	 *    itself (with range TLBI). In such case, we check the flush_range limits and only issue the TLBI if a
	 *    mapping is out of the range.
	 * 3. Neither PMAP_OPTIONS_NOFLUSH nor a valid flush_range pointer is specified. In such case, we should just
	 *    let SPTM handle TLBI flushing.
	 */
	const bool defer_tlbi = (options & PMAP_OPTIONS_NOFLUSH) || flush_range;
	const uint32_t sptm_update_options = SPTM_UPDATE_PERMS_AND_WAS_WRITABLE | (defer_tlbi ? SPTM_UPDATE_DEFER_TLBI : 0);

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto protect_skip_pve;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			iommu_mapping_in_pve = true;
			if (__improbable(remove && (options & PMAP_OPTIONS_COMPRESSOR))) {
				const iommu_instance_t iommu = ptep_get_iommu(pte_p);
				panic("%s: attempt to compress ppnum 0x%x owned by iommu driver "
				    "%u (token: %#x), pve_p=%p", __func__, ppnum, GET_IOMMU_ID(iommu),
				    GET_IOMMU_TOKEN(iommu), pve_p);
			}
			if (remove && (pve_p == PV_ENTRY_NULL)) {
				/*
				 * We've found an IOMMU entry and it's the only entry in the PV list.
				 * We don't discard IOMMU entries, so simply set up the new PV list to
				 * contain the single IOMMU PTE and exit the loop.
				 */
				new_pte_p = pte_p;
				break;
			}
			goto protect_skip_pve;
		}
#endif

		if (__improbable(pvh_lock_sleep_mode_needed)) {
			if (remove) {
				/**
				 * Clear the in-flight disconnect indicator for the current CPU, as we've
				 * already submitted any prior pending SPTM operations, and we're about to
				 * briefly re-enable preemption which may cause this thread to be migrated.
				 */
				os_atomic_store(&pmap_cpu_data->inflight_disconnect, false, release);
			}
			/**
			 * Undo the explicit preemption disable done in the last call to PPO_PER_CPU_INIT().
			 * If the PVH lock is placed in sleep mode, we can't rely on it to disable preemption,
			 * so we need these explicit preemption twiddles to ensure we don't get migrated off-
			 * core while processing SPTM per-CPU data.  At the same time, we also want preemption
			 * to briefly be re-enabled every SPTM_MAPPING_LIMIT mappings so that any pending
			 * urgent ASTs can be handled.
			 */
			enable_preemption();
			pvh_lock_enter_sleep_mode(&local_locked_pvh);
			pvh_lock_sleep_mode_needed = false;
			PPO_PERCPU_INIT();
		}

		const pt_entry_t spte = os_atomic_load(pte_p, relaxed);

		if (__improbable(!remove && ((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT))) {
			goto protect_skip_pve;
		}

		pt_desc_t *ptdp = NULL;
		pmap_t pmap = NULL;
		vm_map_address_t va = 0;

		if ((flush_range != NULL) && (pte_p == flush_range->current_ptep)) {
			/**
			 * If the current mapping matches the flush range's current iteration position,
			 * there's no need to do the work of getting the PTD.  We already know the pmap,
			 * and the VA is implied by flush_range->pending_region_start.
			 */
			pmap = flush_range->ptfr_pmap;
		} else {
			ptdp = ptep_get_ptd(pte_p);
			pmap = ptdp->pmap;
			va = ptd_get_va(ptdp, pte_p);
		}

		if (__improbable((pmap == NULL) ||
		    (((spte & ARM_PTE_TYPE_MASK) != ARM_PTE_TYPE_FAULT) && (atop(pte_to_pa(spte)) != ppnum)))) {
#if MACH_ASSERT
			if ((pmap != NULL) && (pve_p != PV_ENTRY_NULL) && (kern_feature_override(KF_PMAPV_OVRD) == FALSE)) {
				/* Temporarily set PTEP to NULL so that the logic below doesn't pick it up as duplicate. */
				pt_entry_t *temp_ptep = pve_get_ptep(pve_p, pve_ptep_idx);
				pve_set_ptep(pve_p, pve_ptep_idx, PT_ENTRY_NULL);

				pv_entry_t *check_pvep = pve_p;

				do {
					if (pve_find_ptep_index(check_pvep, pte_p) != -1) {
						panic_plain("%s: duplicate pve entry ptep=%p pmap=%p, pvh=%p, "
						    "pvep=%p, pai=0x%x", __func__, pte_p, pmap, (void*)local_locked_pvh.pvh, pve_p, pai);
					}
				} while ((check_pvep = pve_next(check_pvep)) != PV_ENTRY_NULL);

				/* Restore previous PTEP value. */
				pve_set_ptep(pve_p, pve_ptep_idx, temp_ptep);
			}
#endif
			panic("%s: bad PVE pte_p=%p pmap=%p prot=%d options=%u, pvh=%p, pveh_p=%p, pve_p=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x",
			    __func__, pte_p, pmap, prot, options, (void*)local_locked_pvh.pvh, pveh_p, pve_p, (uint64_t)*pte_p, (uint64_t)va, ppnum);
		}

		pt_entry_t pte_template = ARM_PTE_EMPTY;

		if (ptdp != NULL) {
			/**
			 * If the PTD is NULL, we're adding the current mapping to the pending region templates instead of the
			 * pending disjoint ops, so we don't need to do flush range disjoint op management.
			 */
			if (flush_range != NULL) {
				/**
				 * Insert a "header" entry for this physical page into the SPTM disjoint ops array.
				 * We do this in three cases:
				 * 1) We're at the beginning of the SPTM ops array (num_mappings == 0, flush_range->pending_disjoint_entries == 0).
				 * 2) We may not be at the beginning of the SPTM ops array, but we are about to add the first operation
				 *    for this physical page (num_mappings == 0, flush_range->pending_disjoint_entries == ?).
				 * 3) We need to change the options passed to the SPTM for a run of one or more mappings.  Specifically,
				 *    if we encounter a run of mappings that reside outside the VA region of our flush_range, or that
				 *    belong to a pmap other than the one targeted by our flush_range, we should ask the SPTM to flush
				 *    the TLB for us (i.e., clear SPTM_UPDATE_DEFER_TLBI), but only for those specific mappings.
				 */
				uint32_t per_mapping_sptm_update_options = sptm_update_options;
				if ((flush_range->ptfr_pmap != pmap) || (va >= flush_range->ptfr_end) || (va < flush_range->ptfr_start)) {
					per_mapping_sptm_update_options &= ~SPTM_UPDATE_DEFER_TLBI;
				}
				if ((num_mappings == 0) ||
				    (flush_range->current_header->per_paddr_header.options != per_mapping_sptm_update_options)) {
					num_mappings = pmap_multipage_op_add_page(phys, num_mappings, per_mapping_sptm_update_options, flush_range);
				}
			}

			sptm_ops[num_mappings].root_pt_paddr = pmap->ttep;
			sptm_ops[num_mappings].vaddr = va;
		}

		/* Remove the mapping if new protection is NONE */
		if (remove) {
			sptm_ptds[num_mappings] = ptdp;
			sptm_ptd_info[num_mappings] = ptd_get_info(ptdp, pte_p);
			sptm_pcpu->sptm_acct_flags[num_mappings] = 0;
			if (pmap != kernel_pmap) {
				const bool is_internal = ppattr_pve_is_internal(pai, pve_p, pve_ptep_idx);
				const bool is_altacct = ppattr_pve_is_altacct(pai, pve_p, pve_ptep_idx);

				if (is_internal) {
					sptm_pcpu->sptm_acct_flags[num_mappings] |= PMAP_SPTM_FLAG_INTERNAL;
					ppattr_pve_clr_internal(pai, pve_p, pve_ptep_idx);
				}
				if (is_altacct) {
					sptm_pcpu->sptm_acct_flags[num_mappings] |= PMAP_SPTM_FLAG_ALTACCT;
					ppattr_pve_clr_altacct(pai, pve_p, pve_ptep_idx);
				}
				if (compress && is_internal) {
					pte_template = ARM_PTE_COMPRESSED;
					if (is_altacct) {
						pte_template |= ARM_PTE_COMPRESSED_ALT;
					}
				}
			}
			/* Remove this CPU mapping from PVE list. */
			if (pve_p != PV_ENTRY_NULL) {
				pve_set_ptep(pve_p, pve_ptep_idx, PT_ENTRY_NULL);
			}
		} else {
			const pt_attr_t *const pt_attr = pmap_get_pt_attr(pmap);

			if (pmap == kernel_pmap) {
				pte_template = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
			} else {
				pte_template = ((spte & ~ARM_PTE_APMASK) | pt_attr_leaf_ro(pt_attr));
			}

			/*
			 * We must at least clear the 'was writeable' flag, as we're at least revoking write access,
			 * meaning that the VM is effectively requesting that subsequent write accesses to these mappings
			 * go through vm_fault() instead of being handled by arm_fast_fault().
			 */
			pte_set_was_writeable(pte_template, false);

			/*
			 * While the naive implementation of this would serve to add execute
			 * permission, this is not how the VM uses this interface, or how
			 * x86_64 implements it.  So ignore requests to add execute permissions.
			 */
#if DEVELOPMENT || DEBUG
			if ((!(prot & VM_PROT_EXECUTE) && nx_enabled && pmap->nx_enabled) ||
			    (pte_to_xprr_perm(spte) == XPRR_USER_TPRO_PERM))
#else
			if (!(prot & VM_PROT_EXECUTE) ||
			    (pte_to_xprr_perm(spte) == XPRR_USER_TPRO_PERM))
#endif
			{
				pte_template |= pt_attr_leaf_xn(pt_attr);
			}
		}

		if (ptdp != NULL) {
			sptm_ops[num_mappings].pte_template = pte_template;
			++num_mappings;
			if (num_mappings == SPTM_MAPPING_LIMIT) {
				if (remove) {
					pmap_disjoint_unmap(phys, num_mappings);
				} else if (flush_range == NULL) {
					sptm_update_disjoint(phys, sptm_pcpu->sptm_ops_pa, num_mappings, sptm_update_options);
				} else {
					/**
					 * We submit both the pending disjoint and pending region ops whenever
					 * either category reaches the mapping limit.  Having pending operations
					 * in either category will keep preemption disabled, and we want to ensure
					 * that we can at least temporarily re-enable preemption every
					 * SPTM_MAPPING_LIMIT mappings.
					 */
					pmap_multipage_op_submit_disjoint(num_mappings, flush_range);
					pmap_multipage_op_submit_region(flush_range);
				}
				pvh_lock_sleep_mode_needed = true;
				num_mappings = 0;
			}
		} else if (pmap_insert_flush_range_template(pte_template, flush_range)) {
			/* See comment above for why we also submit pending disjoint ops when we hit the region limit. */
			pmap_multipage_op_submit_disjoint(num_mappings, flush_range);
			pvh_lock_sleep_mode_needed = true;
			num_mappings = 0;
		}

protect_skip_pve:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;

			if (remove) {
				/**
				 * If there are any IOMMU mappings in the PVE list, preserve
				 * those mappings in a new PVE list (new_pve_p) which will later
				 * become the new PVH entry. Keep track of the CPU mappings in
				 * pveh_p/pvet_p so they can be deallocated later.
				 */
				if (iommu_mapping_in_pve) {
					iommu_mapping_in_pve = false;
					pv_entry_t *temp_pve_p = pve_next(pve_p);
					pve_remove(&local_locked_pvh, pve_pp, pve_p);
					if (pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_PVEP)) {
						pveh_p = pvh_pve_list(local_locked_pvh.pvh);
					} else {
						assert(pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_NULL));
						pveh_p = PV_ENTRY_NULL;
					}
					pve_p->pve_next = new_pve_p;
					new_pve_p = pve_p;
					pve_p = temp_pve_p;
					continue;
				} else {
					pvet_p = pve_p;
					pvh_cnt++;
				}
			}

			pve_pp = pve_next_ptr(pve_p);
			pve_p = pve_next(pve_p);
			iommu_mapping_in_pve = false;
		}
	}

	if (num_mappings != 0) {
		if (remove) {
			pmap_disjoint_unmap(phys, num_mappings);
		} else if (flush_range == NULL) {
			sptm_update_disjoint(phys, sptm_pcpu->sptm_ops_pa, num_mappings, sptm_update_options);
		} else {
			/* Resync the pending mapping state in flush_range with our local state. */
			assert(num_mappings >= flush_range->pending_disjoint_entries);
			flush_range->pending_disjoint_entries = num_mappings;
		}
	}

	if (remove) {
		os_atomic_store(&pmap_cpu_data->inflight_disconnect, false, release);
	}

	/**
	 * Undo the explicit disable_preemption() done in PPO_PERCPU_INIT().
	 * Note that enable_preemption() decrements a per-thread counter, so if
	 * we happen to still hold the PVH lock in spin mode then preemption won't
	 * actually be re-enabled until we drop the lock (which also decrements
	 * the per-thread counter.
	 */
	enable_preemption();

	/* if we removed a bunch of entries, take care of them now */
	if (remove) {
		/**
		 * If we (or our caller as indicated by PMAP_OPTIONS_PPO_PENDING_RETYPE) will
		 * be retyping the page, we need to drain the epochs to ensure that concurrent
		 * calls to batched operations such as pmap_remove() and the various multipage
		 * attribute update functions have finished consuming mappings of this page.
		 */
		const bool needs_retyping = pmap_prepare_unmapped_page_for_retype(phys);
		if ((options & PMAP_OPTIONS_PPO_PENDING_RETYPE) && !needs_retyping) {
			/**
			 * pmap_prepare_unmapped_page_for_retype() will only return true if
			 * the page belongs to a certain set of types that need to be auto-
			 * retyped back to XNU_DEFAULT when they are unmapped.  But if the
			 * caller indicated that it's going to retype the page, we need
			 * to drain the epochs regardless of the current page type.
			 */
			pmap_retype_epoch_prepare_drain();
		}
		if (new_pve_p != PV_ENTRY_NULL) {
			pvh_update_head(&local_locked_pvh, new_pve_p, PVH_TYPE_PVEP);
		} else if (new_pte_p != PT_ENTRY_NULL) {
			pvh_update_head(&local_locked_pvh, new_pte_p, PVH_TYPE_PTEP);
		} else {
			pvh_set_flags(&local_locked_pvh, 0);
			pvh_update_head(&local_locked_pvh, PV_ENTRY_NULL, PVH_TYPE_NULL);
		}

		/* If removing the last mapping to a specially-protected page, retype the page back to XNU_DEFAULT. */
		const bool retype_needed = pmap_retype_unmapped_page(phys);
		if ((options & PMAP_OPTIONS_PPO_PENDING_RETYPE) && !retype_needed) {
			pmap_retype_epoch_drain();
		}
	}

	if (__probable(locked_pvh == NULL)) {
		pvh_unlock(&local_locked_pvh);
	} else {
		*locked_pvh = local_locked_pvh;
	}

	if (remove && (pvet_p != PV_ENTRY_NULL)) {
		assert(pveh_p != PV_ENTRY_NULL);
		pv_list_free(pveh_p, pvet_p, pvh_cnt);
	}
}

MARK_AS_PMAP_TEXT void
pmap_page_protect_options_internal(
	ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options,
	void *arg)
{
	if (arg != NULL) {
		/*
		 * This is a legacy argument from pre-ARM era that the VM layer passes in to hint that it will call
		 * pmap_flush() later to flush the TLB. On ARM platforms, however, pmap_flush() is not implemented,
		 * as it's typically more efficient to perform the TLB flushing inline with the page table updates
		 * themselves. Therefore, if the argument is non-NULL, pmap will take care of TLB flushing itself
		 * by clearing PMAP_OPTIONS_NOFLUSH.
		 */
		options &= ~PMAP_OPTIONS_NOFLUSH;
	}
	pmap_page_protect_options_with_flush_range(ppnum, prot, options, NULL, NULL);
}

void
pmap_page_protect_options(
	ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options,
	void *arg)
{
	pmap_paddr_t    phys = ptoa(ppnum);

	assert(ppnum != vm_page_fictitious_addr);

	/* Only work with managed pages. */
	if (!pa_valid(phys)) {
		return;
	}

	/*
	 * Determine the new protection.
	 */
	if (prot == VM_PROT_ALL) {
		return;         /* nothing to do */
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_START, ppnum, prot);

	pmap_page_protect_options_internal(ppnum, prot, options, arg);

	PMAP_TRACE(2, PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_END);
}


#if __has_feature(ptrauth_calls) && (defined(XNU_TARGET_OS_OSX) || (DEVELOPMENT || DEBUG))
MARK_AS_PMAP_TEXT void
pmap_disable_user_jop_internal(pmap_t pmap)
{
	if (pmap == kernel_pmap) {
		panic("%s: called with kernel_pmap", __func__);
	}
	validate_pmap_mutable(pmap);
	sptm_configure_root(pmap->ttep, 0, SPTM_ROOT_PT_FLAG_JOP);
	pmap->disable_jop = true;
}

void
pmap_disable_user_jop(pmap_t pmap)
{
	pmap_disable_user_jop_internal(pmap);
}
#endif /* __has_feature(ptrauth_calls) && (defined(XNU_TARGET_OS_OSX) || (DEVELOPMENT || DEBUG)) */

/*
 * Indicates if the pmap layer enforces some additional restrictions on the
 * given set of protections.
 */
bool
pmap_has_prot_policy(__unused pmap_t pmap, __unused bool translated_allow_execute, __unused vm_prot_t prot)
{
	return false;
}

/*
 *	Set the physical protection on the
 *	specified range of this map as requested.
 *	VERY IMPORTANT: Will not increase permissions.
 *	VERY IMPORTANT: Only pmap_enter() is allowed to grant permissions.
 */
void
pmap_protect(
	pmap_t pmap,
	vm_map_address_t b,
	vm_map_address_t e,
	vm_prot_t prot)
{
	pmap_protect_options(pmap, b, e, prot, 0, NULL);
}

static bool
pmap_protect_strong_sync(unsigned int num_mappings __unused)
{
	return false;
}

MARK_AS_PMAP_TEXT vm_map_address_t
pmap_protect_options_internal(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	vm_prot_t prot,
	unsigned int options,
	__unused void *args)
{
	pt_entry_t       *pte_p;
	bool             set_NX = true;
	bool             set_XO = false;
	bool             should_have_removed = false;
	bool             need_strong_sync = false;

	/* Validate the pmap input before accessing its data. */
	validate_pmap_mutable(pmap);

	const pt_attr_t *const pt_attr = pmap_get_pt_attr(pmap);

	if (__improbable((end < start) || (end > ((start + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr))))) {
		panic("%s: invalid address range %p, %p", __func__, (void*)start, (void*)end);
	}

#if DEVELOPMENT || DEBUG
	if (options & PMAP_OPTIONS_PROTECT_IMMEDIATE) {
		if ((prot & VM_PROT_ALL) == VM_PROT_NONE) {
			should_have_removed = true;
		}
	} else
#endif
	{
		/* Determine the new protection. */
		switch (prot) {
		case VM_PROT_EXECUTE:
			set_XO = true;
			OS_FALLTHROUGH;
		case VM_PROT_READ:
		case VM_PROT_READ | VM_PROT_EXECUTE:
			break;
		case VM_PROT_READ | VM_PROT_WRITE:
		case VM_PROT_ALL:
			return end;         /* nothing to do */
		default:
			should_have_removed = true;
		}
	}

	if (__improbable(should_have_removed)) {
		panic("%s: should have been a remove operation, "
		    "pmap=%p, start=%p, end=%p, prot=%#x, options=%#x, args=%p",
		    __FUNCTION__,
		    pmap, (void *)start, (void *)end, prot, options, args);
	}

#if DEVELOPMENT || DEBUG
	bool force_write = false;
	if ((options & PMAP_OPTIONS_PROTECT_IMMEDIATE) && (prot & VM_PROT_WRITE)) {
		force_write = true;
	}
	if ((prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled)
#else
	if ((prot & VM_PROT_EXECUTE))
#endif
	{
		set_NX = false;
	} else {
		set_NX = true;
	}

	const uint64_t pmap_page_size = PAGE_RATIO * pt_attr_page_size(pt_attr);
	vm_map_address_t va = start;
	vm_map_address_t sptm_start_va = start;
	unsigned int num_mappings = 0;

	pmap_lock(pmap, PMAP_LOCK_SHARED);

	pte_p = pmap_pte(pmap, start);

	if (pte_p == NULL) {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
		return end;
	}

	pmap_sptm_percpu_data_t *sptm_pcpu = NULL;
#if DEVELOPMENT || DEBUG
	if (!force_write)
#endif
	{
		disable_preemption();
		sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
	}

	pt_entry_t tmplate = ARM_PTE_EMPTY;

	if (pmap == kernel_pmap) {
#if DEVELOPMENT || DEBUG
		if (force_write) {
			tmplate = ARM_PTE_AP(AP_RWNA);
		} else
#endif
		{
			tmplate = ARM_PTE_AP(AP_RONA);
		}
	} else {
#if DEVELOPMENT || DEBUG
		if (force_write) {
			assert(pmap->type != PMAP_TYPE_NESTED);
			tmplate = pt_attr_leaf_rw(pt_attr);
		} else
#endif
		if (set_XO) {
			tmplate = pt_attr_leaf_rona(pt_attr);
		} else {
			tmplate = pt_attr_leaf_ro(pt_attr);
		}
	}

	if (set_NX) {
		tmplate |= pt_attr_leaf_xn(pt_attr);
	}

	while (va < end) {
		pt_entry_t spte = ARM_PTE_EMPTY;

		/**
		 * Removing "NX" would grant "execute" access immediately, bypassing any
		 * checks VM might want to do in its soft fault path.
		 * pmap_protect() and co. are not allowed to increase access permissions,
		 * except in the PMAP_PROTECT_OPTIONS_IMMEDIATE internal-only case.
		 * Therefore, if we are not explicitly clearing execute permissions, inherit
		 * the existing permissions.
		 */
		if (!set_NX) {
			spte = os_atomic_load(pte_p, relaxed);
			if (__improbable((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT)) {
				tmplate |= pt_attr_leaf_xn(pt_attr);
			} else {
				tmplate |= (spte & ARM_PTE_XMASK);
			}
		}

#if DEVELOPMENT || DEBUG
		/*
		 * PMAP_OPTIONS_PROTECT_IMMEDIATE is an internal-only option that's intended to
		 * provide a "backdoor" to allow normally write-protected compressor pages to be
		 * be temporarily written without triggering expensive write faults.
		 * SPTM TODO: Given the intended use of this flag, we may be able to relax some
		 * of our assumptions below when it comes to ref/mod accounting, and we may be
		 * able to avoid holding the PVH lock across the SPTM mapping operation and the
		 * ref/mod updates.  This will be important if we move to a batched SPTM mapping
		 * API.
		 */
		if (force_write) {
			if (spte == ARM_PTE_EMPTY) {
				spte = os_atomic_load(pte_p, relaxed);
			}

			/* A concurrent remove or disconnect may have cleared the PTE. */
			if (__improbable((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT)) {
				goto pmap_protect_insert_mapping;
			}

			/* Inherit permissions and "was_writeable" from the template. */
			spte = (spte & ~(ARM_PTE_APMASK | ARM_PTE_XMASK | ARM_PTE_WRITEABLE)) |
			    (tmplate & (ARM_PTE_APMASK | ARM_PTE_XMASK | ARM_PTE_WRITEABLE));

			/* Access flag should be set for any immediate change in protections */
			spte |= ARM_PTE_AF;
			const pmap_paddr_t pa = pte_to_pa(spte);
			const unsigned int pai = pa_index(pa);
			locked_pvh_t locked_pvh;
			if (pa_valid(pa)) {
				locked_pvh = pvh_lock(pai);
				ppattr_modify_bits(pai, PP_ATTR_REFFAULT | PP_ATTR_MODFAULT,
				    PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
			}

			__assert_only const sptm_return_t sptm_status = sptm_map_page(pmap->ttep, va, spte);

			/*
			 * We don't expect the VM to be concurrently removing these compressor mappings.
			 * If it does for some reason, we can check for SPTM_MAP_FLUSH_PENDING and continue
			 * the main loop.
			 */
			assert((sptm_status == SPTM_SUCCESS) || (sptm_status == SPTM_MAP_VALID));

			if (pa_valid(pa)) {
				pvh_unlock(&locked_pvh);
			}
		}

pmap_protect_insert_mapping:
#endif /* DEVELOPMENT || DEBUG */

		va += pmap_page_size;
		++pte_p;

#if DEVELOPMENT || DEBUG
		if (!force_write)
#endif
		{
			sptm_pcpu->sptm_templates[num_mappings] = tmplate;
			++num_mappings;
			if (num_mappings == SPTM_MAPPING_LIMIT) {
				/**
				 * Enter the retype epoch for the batched update operation.  This is necessary because we
				 * cannot reasonably hold the PVH locks for all pages mapped by the region during this
				 * call, so a concurrent pmap_page_protect() operation against one of those pages may
				 * race this call.  That should be perfectly fine as far as the PTE updates are concerned,
				 * but if pmap_page_protect() then needs to retype the page, an SPTM violation may result
				 * if it does not first drain our epoch.
				 */
				pmap_retype_epoch_enter();
				sptm_update_region(pmap->ttep, sptm_start_va, num_mappings, sptm_pcpu->sptm_templates_pa,
				    SPTM_UPDATE_PERMS_AND_WAS_WRITABLE);
				pmap_retype_epoch_exit();
				need_strong_sync = need_strong_sync || pmap_protect_strong_sync(num_mappings);

				/* Temporarily re-enable preemption to allow any urgent ASTs to be processed. */
				enable_preemption();
				num_mappings = 0;
				sptm_start_va = va;
				disable_preemption();
				sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
			}
		}
	}

	/* This won't happen in the force_write case as we should never increment num_mappings. */
	if (num_mappings != 0) {
		pmap_retype_epoch_enter();
		sptm_update_region(pmap->ttep, sptm_start_va, num_mappings, sptm_pcpu->sptm_templates_pa,
		    SPTM_UPDATE_PERMS_AND_WAS_WRITABLE);
		pmap_retype_epoch_exit();
		need_strong_sync = need_strong_sync || pmap_protect_strong_sync(num_mappings);
	}

#if DEVELOPMENT || DEBUG
	if (!force_write)
#endif
	{
		enable_preemption();
	}
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
	if (__improbable(need_strong_sync)) {
		arm64_sync_tlb(true);
	}
	return va;
}

void
pmap_protect_options(
	pmap_t pmap,
	vm_map_address_t b,
	vm_map_address_t e,
	vm_prot_t prot,
	unsigned int options,
	__unused void *args)
{
	vm_map_address_t l, beg;

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if ((b | e) & pt_attr_leaf_offmask(pt_attr)) {
		panic("pmap_protect_options() pmap %p start 0x%llx end 0x%llx",
		    pmap, (uint64_t)b, (uint64_t)e);
	}

	/*
	 * We allow single-page requests to execute non-preemptibly,
	 * as it doesn't make sense to sample AST_URGENT for a single-page
	 * operation, and there are a couple of special use cases that
	 * require a non-preemptible single-page operation.
	 */
	if ((e - b) > (pt_attr_page_size(pt_attr) * PAGE_RATIO)) {
		pmap_verify_preemptible();
	}

#if DEVELOPMENT || DEBUG
	if (options & PMAP_OPTIONS_PROTECT_IMMEDIATE) {
		if ((prot & VM_PROT_ALL) == VM_PROT_NONE) {
			pmap_remove_options(pmap, b, e, options);
			return;
		}
	} else
#endif
	{
		/* Determine the new protection. */
		switch (prot) {
		case VM_PROT_EXECUTE:
		case VM_PROT_READ:
		case VM_PROT_READ | VM_PROT_EXECUTE:
			break;
		case VM_PROT_READ | VM_PROT_WRITE:
		case VM_PROT_ALL:
			return;         /* nothing to do */
		default:
			pmap_remove_options(pmap, b, e, options);
			return;
		}
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__PROTECT) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(b),
	    VM_KERNEL_ADDRHIDE(e));

	beg = b;

	while (beg < e) {
		l = ((beg + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr));

		if (l > e) {
			l = e;
		}

		beg = pmap_protect_options_internal(pmap, beg, l, prot, options, args);
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__PROTECT) | DBG_FUNC_END);
}

/**
 * Inserts an arbitrary number of physical pages ("block") in a pmap.
 *
 * @param pmap pmap to insert the pages into.
 * @param va virtual address to map the pages into.
 * @param pa page number of the first physical page to map.
 * @param size block size, in number of pages.
 * @param prot mapping protection attributes.
 * @param attr flags to pass to pmap_enter().
 *
 * @return KERN_SUCCESS.
 */
kern_return_t
pmap_map_block(
	pmap_t pmap,
	addr64_t va,
	ppnum_t pa,
	uint32_t size,
	vm_prot_t prot,
	int attr,
	unsigned int flags)
{
	return pmap_map_block_addr(pmap, va, ((pmap_paddr_t)pa) << PAGE_SHIFT, size, prot, attr, flags);
}

/**
 * Inserts an arbitrary number of physical pages ("block") in a pmap.
 * As opposed to pmap_map_block(), this function takes
 * a physical address as an input and operates using the
 * page size associated with the input pmap.
 *
 * @param pmap pmap to insert the pages into.
 * @param va virtual address to map the pages into.
 * @param pa physical address of the first physical page to map.
 * @param size block size, in number of pages.
 * @param prot mapping protection attributes.
 * @param attr flags to pass to pmap_enter().
 *
 * @return KERN_SUCCESS.
 */
kern_return_t
pmap_map_block_addr(
	pmap_t pmap,
	addr64_t va,
	pmap_paddr_t pa,
	uint32_t size,
	vm_prot_t prot,
	int attr,
	unsigned int flags)
{
#if __ARM_MIXED_PAGE_SIZE__
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
#else
	const uint64_t pmap_page_size = PAGE_SIZE;
#endif

	for (ppnum_t page = 0; page < size; page++) {
		if (pmap_enter_addr(pmap, va, pa, prot, VM_PROT_NONE, attr, TRUE, PMAP_MAPPING_TYPE_INFER) != KERN_SUCCESS) {
			panic("%s: failed pmap_enter_addr, "
			    "pmap=%p, va=%#llx, pa=%llu, size=%u, prot=%#x, flags=%#x",
			    __FUNCTION__,
			    pmap, va, (uint64_t)pa, size, prot, flags);
		}

		va += pmap_page_size;
		pa += pmap_page_size;
	}

	return KERN_SUCCESS;
}

kern_return_t
pmap_enter_addr(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	pmap_mapping_type_t mapping_type)
{
	return pmap_enter_options_addr(pmap, v, pa, prot, fault_type, flags, wired, 0, NULL, mapping_type);
}

/*
 *	Insert the given physical page (p) at
 *	the specified virtual address (v) in the
 *	target physical map with the protection requested.
 *
 *	If specified, the page will be wired down, meaning
 *	that the related pte can not be reclaimed.
 *
 *	NB:  This is the only routine which MAY NOT lazy-evaluate
 *	or lose information.  That is, this routine must actually
 *	insert this page into the given map eventually (must make
 *	forward progress eventually.
 */
kern_return_t
pmap_enter(
	pmap_t pmap,
	vm_map_address_t v,
	ppnum_t pn,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	pmap_mapping_type_t mapping_type)
{
	return pmap_enter_addr(pmap, v, ((pmap_paddr_t)pn) << PAGE_SHIFT, prot, fault_type, flags, wired, mapping_type);
}

/*
 * Attempt to update a PTE constructed by pmap_enter_options().
 *
 * @note performs no page table or accounting modifications, nor any lasting SPTM page type modification, on failure.
 * @note expects to be called with preemption disabled to guarantee safe access to SPTM per-CPU data.
 *
 * @param pmap The pmap representing the address space in which to store the new PTE
 * @param pte_p The physical aperture KVA of the PTE to store
 * @param new_pte The new value to store in *pte_p
 * @param v The virtual address mapped by pte_p
 * @param locked_pvh Input/Output parameter pointing to a wrapped pv_head_table entry returned by
 *        a previous call to pvh_lock().  *locked_pvh will be updated if existing mappings
 *        need to be disconnected prior to retyping.
 * @param old_pte Returns the prior PTE contents, iff the PTE is successfully updated
 * @param options bitmask of PMAP_OPTIONS_* flags passed to pmap_enter_options().
 * @param mapping_type The type of the new mapping, this defines which SPTM frame type to use.
 *
 * @return SPTM_SUCCESS iff able to successfully update *pte_p to new_pte via sptm_map_page(),
 *         SPTM_MAP_VALID if an existing mapping was successfully upgraded via sptm_map_page(),
 *         SPTM_MAP_FLUSH_PENDING if the TLB flush of a previous mapping is still in-flight and
 *             the mapping operation should be retried, or if the mapping operation should be retried
 *             because we had to temporarily re-enable preemption which would invalidate caller-held
 *             per-CPU data.
 *         Otherwise an appropriate SPTM or TXM error code; in these cases the mapping should not be
 *             retried and the caller should return an error.
 */
static inline sptm_return_t
pmap_enter_pte(
	pmap_t pmap,
	pt_entry_t *pte_p,
	pt_entry_t new_pte,
	locked_pvh_t *locked_pvh,
	pt_entry_t *old_pte,
	vm_map_address_t v,
	unsigned int options,
	pmap_mapping_type_t mapping_type)
{
	sptm_pte_t prev_pte;
	bool changed_wiring = false;
	bool txm_enforced = false;

	assert(pte_p != NULL);
	assert(old_pte != NULL);

	/* SPTM TODO: handle PAGE_RATIO_4 configurations if those devices remain supported. */

	assert(get_preemption_level() > 0);
	const pmap_paddr_t pa = pte_to_pa(new_pte);
	sptm_frame_type_t prev_frame_type = XNU_DEFAULT;
	sptm_frame_type_t new_frame_type = XNU_DEFAULT;

	/*
	 * If the caller specified a mapping type of PMAP_MAPPINGS_TYPE_INFER, then we
	 * keep the existing logic of deriving the SPTM frame type from the XPRR permissions.
	 *
	 * If the caller specified another mapping type, we simply follow that. This refactor was
	 * needed for the XNU_KERNEL_RESTRICTED work, and it also allows us to be more precise at
	 * what we want. It's better to let the caller specify the mapping type rather than use the
	 * permissions for that.
	 *
	 * In the future, we should move entirely to use pmap_mapping_type_t; see rdar://114886323.
	 */
	if (mapping_type != PMAP_MAPPING_TYPE_INFER) {
		switch (mapping_type) {
		case PMAP_MAPPING_TYPE_DEFAULT:
			new_frame_type = (sptm_frame_type_t)mapping_type;
			break;
		case PMAP_MAPPING_TYPE_ROZONE:
			assert(((pmap == kernel_pmap) && zone_spans_ro_va(v, v + pt_attr_page_size(pmap_get_pt_attr(pmap)))));
			new_frame_type = (sptm_frame_type_t)mapping_type;
			break;
		case PMAP_MAPPING_TYPE_RESTRICTED:
			if (use_xnu_restricted) {
				new_frame_type = (sptm_frame_type_t)mapping_type;
			} else {
				new_frame_type = XNU_DEFAULT;
			}
			break;
		default:
			panic("invalid mapping type: %d", mapping_type);
		}
	} else if (__improbable(pte_to_xprr_perm(new_pte) == XPRR_USER_JIT_PERM)) {
		/*
		 * Always check for XPRR_USER_JIT_PERM before we check for anything else. When using
		 * RWX permissions, the only allowed type is XNU_USER_JIT, regardless of any other
		 * flags which the VM may have provided.
		 *
		 * TODO: Assert that the PMAP_OPTIONS_XNU_USER_DEBUG flag isn't set when entering
		 * this case. We can't do this for now because this might trigger on some macOS
		 * systems where applications use MAP_JIT with RW/RX permissions, and then later
		 * switch to RWX (which will cause a switch to XNU_USER_JIT from XNU_USER_DEBUG
		 * but the VM will still have PMAP_OPTIONS_XNU_USER_DEBUG set). If the VM can
		 * catch this case, and remove PMAP_OPTIONS_XNU_USER_DEBUG when an application
		 * switches to RWX, then we can start asserting this requirement.
		 */
		new_frame_type = XNU_USER_JIT;
	} else if (__improbable(options & PMAP_OPTIONS_XNU_USER_DEBUG)) {
		/*
		 * Both XNU_USER_DEBUG and XNU_USER_EXEC allow RX permissions. Given that, we must
		 * test for PMAP_OPTIONS_XNU_USER_DEBUG before we test for XNU_USER_EXEC since the
		 * XNU_USER_DEBUG type overlays the XNU_USER_EXEC type.
		 */
		new_frame_type = XNU_USER_DEBUG;
	} else if (pte_to_xprr_perm(new_pte) == XPRR_USER_RX_PERM) {
		new_frame_type = XNU_USER_EXEC;
	}

	if (__improbable(new_frame_type != XNU_DEFAULT)) {
		prev_frame_type = sptm_get_frame_type(pa);
	}

	if (__improbable(new_frame_type != prev_frame_type)) {
		/**
		 * Remove all existing mappings prior to retyping, so that we can safely retype without having to worry
		 * about a concurrent operation on one of those mappings triggering an SPTM violation.  In particular,
		 * pmap_remove() may clear a mapping to this page without holding its PVH lock.  This approach works
		 * because we hold the PVH lock during this call, and any attempt to enter a new mapping for the page
		 * will also need to grab the PVH lock and call this function.
		 */
		pmap_page_protect_options_with_flush_range((ppnum_t)atop(pa), VM_PROT_NONE,
		    PMAP_OPTIONS_PPO_PENDING_RETYPE, locked_pvh, NULL);
		/**
		 * In the unlikely event that pmap_page_protect_options_with_flush_range() had to process
		 * an excessively long PV list, it will have enabled preemption by placing the PVH lock
		 * in sleep mode.  In this case, we may have been migrated to a different CPU, and caller
		 * assumptions about the state of per-CPU data (such as per-CPU PVE availability) will no
		 * longer hold true.  Ask the caller to retry by pretending we encountered a pending flush.
		 */
		if (__improbable(preemption_enabled())) {
			return SPTM_MAP_FLUSH_PENDING;
		}
		sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
		/* Reload the existing frame type, as pmap_page_protect_options() may have changed it back to XNU_DEFAULT. */
		sptm_retype(pa, sptm_get_frame_type(pa), new_frame_type, retype_params);
	}

	/* TXMTODO: Switch this to read the type configuration table */
	switch (new_frame_type) {
	case XNU_USER_EXEC:
	case XNU_USER_JIT:
	case XNU_USER_DEBUG:
	case XNU_COMMPAGE_RX:
		/* TXMTODO: Start acquiring the lock once the PMAP lock can sleep */
		// pmap_txm_acquire_shared_lock(pmap);
		txm_enforced = true;
		break;

	default:
		break;
	}

	const sptm_return_t sptm_status = sptm_map_page(pmap->ttep, v, new_pte);

	if (txm_enforced == true) {
		/* TXMTODO: Start releasing the lock once we start acquiring it */
		// pmap_txm_release_shared_lock(pmap);
	}

	if (__improbable((sptm_status != SPTM_SUCCESS) && (sptm_status != SPTM_MAP_VALID))) {
		/*
		 * We should always undo our previous retype, even if the SPTM returned SPTM_MAP_FLUSH_PENDING as
		 * opposed to a TXM error.  In the case of SPTM_MAP_FLUSH_PENDING, pmap_enter() will drop the PVH
		 * lock before turning around to retry the mapping operation.  It may then be possible for the
		 * mapping state of the page to change such that our next attempt to map it will fail with a TXM
		 * error, so if we were to leave the new type in place here we would then have lost our record
		 * of the previous type and would effectively leave the page in an inconsistent state.
		 */
		if (__improbable(new_frame_type != prev_frame_type)) {
			sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
			sptm_retype(pa, new_frame_type, prev_frame_type, retype_params);
		}
		return sptm_status;
	}

	*old_pte = prev_pte = PERCPU_GET(pmap_sptm_percpu)->sptm_prev_ptes[0];

	if (prev_pte != new_pte) {
		changed_wiring = pte_is_compressed(prev_pte, pte_p) ?
		    (new_pte & ARM_PTE_WIRED) != 0 :
		    (new_pte & ARM_PTE_WIRED) != (prev_pte & ARM_PTE_WIRED);

		if ((pmap != kernel_pmap) && changed_wiring) {
			pte_update_wiredcnt(pmap, pte_p, (new_pte & ARM_PTE_WIRED) != 0);
		}

		PMAP_TRACE(4 + pt_attr_leaf_level(pmap_get_pt_attr(pmap)), PMAP_CODE(PMAP__TTE),
		    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(v),
		    VM_KERNEL_ADDRHIDE(v + (pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO)), new_pte);
	}

	return sptm_status;
}

MARK_AS_PMAP_TEXT static pt_entry_t
wimg_to_pte(unsigned int wimg, pmap_paddr_t pa)
{
	pt_entry_t pte;

	switch (wimg & (VM_WIMG_MASK)) {
	case VM_WIMG_IO:
		// Map DRAM addresses with VM_WIMG_IO as Device-GRE instead of
		// Device-nGnRnE. On H14+, accesses to them can be reordered by
		// AP, while preserving the security benefits of using device
		// mapping against side-channel attacks. On pre-H14 platforms,
		// the accesses will still be strongly ordered.
		if (is_dram_addr(pa)) {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED);
		} else {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
		}
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_RT:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_RT);
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_POSTED:
		if (is_dram_addr(pa)) {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED);
		} else {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED);
		}
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_POSTED_REORDERED:
		if (is_dram_addr(pa)) {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED);
		} else {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_REORDERED);
		}
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_POSTED_COMBINED_REORDERED:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED);
#if HAS_FEAT_XS
		if (!is_dram_addr(pa)) {
			pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED_XS);
		}
#endif /* HAS_FEAT_XS */
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_WCOMB:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITECOMB);
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_WTHRU:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITETHRU);
		pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
		break;
	case VM_WIMG_COPYBACK:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK);
		pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
		break;
	case VM_WIMG_INNERWBACK:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_INNERWRITEBACK);
		pte |= ARM_PTE_SH(SH_INNER_MEMORY);
		break;
	default:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
		pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
	}

	return pte;
}


/*
 * Construct a PTE (and the physical page attributes) for the given virtual to
 * physical mapping.
 *
 * This function has no side effects and is safe to call so that it is safe to
 * call while attempting a pmap_enter transaction.
 */
MARK_AS_PMAP_TEXT static pt_entry_t
pmap_construct_pte(
	const pmap_t pmap,
	vm_map_address_t va,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	boolean_t wired,
	const pt_attr_t* const pt_attr,
	uint16_t *pp_attr_bits /* OUTPUT */
	)
{
	bool set_NX = false, set_XO = false;
	pt_entry_t pte = pa_to_pte(pa) | ARM_PTE_TYPE;
	assert(pp_attr_bits != NULL);
	*pp_attr_bits = 0;

	if (wired) {
		pte |= ARM_PTE_WIRED;
	}

#if DEVELOPMENT || DEBUG
	if ((prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled)
#else
	if ((prot & VM_PROT_EXECUTE))
#endif
	{
		set_NX = false;
	} else {
		set_NX = true;
	}

	if (prot == VM_PROT_EXECUTE) {
		set_XO = true;

	}

	if (set_NX) {
		pte |= pt_attr_leaf_xn(pt_attr);
	} else {
		if (pmap == kernel_pmap) {
			pte |= ARM_PTE_NX;
		} else {
			pte |= pt_attr_leaf_x(pt_attr);
		}
	}

	if (pmap == kernel_pmap) {
#if __ARM_KERNEL_PROTECT__
		pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
		if (prot & VM_PROT_WRITE) {
			pte |= ARM_PTE_AP(AP_RWNA);
			*pp_attr_bits |= PP_ATTR_MODIFIED | PP_ATTR_REFERENCED;
		} else {
			pte |= ARM_PTE_AP(AP_RONA);
			*pp_attr_bits |= PP_ATTR_REFERENCED;
		}
	} else {
		if (pmap->type != PMAP_TYPE_NESTED) {
			pte |= ARM_PTE_NG;
		} else if ((pmap->nested_region_unnested_table_bitmap)
		    && (va >= pmap->nested_region_addr)
		    && (va < (pmap->nested_region_addr + pmap->nested_region_size))) {
			unsigned int index = (unsigned int)((va - pmap->nested_region_addr)  >> pt_attr_twig_shift(pt_attr));

			if ((pmap->nested_region_unnested_table_bitmap)
			    && bitmap_test(pmap->nested_region_unnested_table_bitmap, index)) {
				pte |= ARM_PTE_NG;
			}
		}
		if (prot & VM_PROT_WRITE) {
			assert(pmap->type != PMAP_TYPE_NESTED);
			if (pa_valid(pa) && (!ppattr_pa_test_bits(pa, PP_ATTR_MODIFIED))) {
				if (fault_type & VM_PROT_WRITE) {
					pte |= pt_attr_leaf_rw(pt_attr);
					*pp_attr_bits |= PP_ATTR_REFERENCED | PP_ATTR_MODIFIED;
				} else {
					pte |= pt_attr_leaf_ro(pt_attr);
					/*
					 * Mark the page as MODFAULT so that a subsequent write
					 * may be handled through arm_fast_fault().
					 */
					*pp_attr_bits |= PP_ATTR_REFERENCED | PP_ATTR_MODFAULT;
					pte_set_was_writeable(pte, true);
				}
			} else {
				pte |= pt_attr_leaf_rw(pt_attr);
				*pp_attr_bits |= (PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
			}
		} else {
			if (set_XO) {
				pte |= pt_attr_leaf_rona(pt_attr);
			} else {
				pte |= pt_attr_leaf_ro(pt_attr);
			}
			*pp_attr_bits |= PP_ATTR_REFERENCED;
		}
	}

	pte |= ARM_PTE_AF;
	return pte;
}

MARK_AS_PMAP_TEXT kern_return_t
pmap_enter_options_internal(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	pmap_mapping_type_t mapping_type)
{
	ppnum_t         pn = (ppnum_t)atop(pa);
	pt_entry_t      *pte_p;
	unsigned int    wimg_bits;
	bool            committed = false;
	kern_return_t   kr = KERN_SUCCESS;
	uint16_t pp_attr_bits;
	volatile uint16_t *wiredcnt = NULL;
	pv_free_list_t *local_pv_free;

	validate_pmap_mutable(pmap);

	/**
	 * Prepare for the SPTM call early by prefetching the relavant FTEs. Cache misses
	 * in SPTM accessing these turn out to contribute to a large portion of delay on
	 * the critical path. Technically, sptm_prefetch_fte may not find an FTE associated
	 * with pa and return LIBSPTM_FAILURE. However, we are okay with that as it's only
	 * a best-effort performance optimization.
	 */
	sptm_prefetch_fte(pmap->ttep);
	sptm_prefetch_fte(pa);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if ((v) & pt_attr_leaf_offmask(pt_attr)) {
		panic("pmap_enter_options() pmap %p v 0x%llx",
		    pmap, (uint64_t)v);
	}

	if (__improbable((pmap == kernel_pmap) && (v >= CPUWINDOWS_BASE) && (v < CPUWINDOWS_TOP))) {
		panic("pmap_enter_options() kernel pmap %p v 0x%llx belongs to [CPUWINDOWS_BASE: 0x%llx, CPUWINDOWS_TOP: 0x%llx)",
		    pmap, (uint64_t)v, (uint64_t)CPUWINDOWS_BASE, (uint64_t)CPUWINDOWS_TOP);
	}

	if ((pa) & pt_attr_leaf_offmask(pt_attr)) {
		panic("pmap_enter_options() pmap %p pa 0x%llx",
		    pmap, (uint64_t)pa);
	}

	/* The PA should not extend beyond the architected physical address space */
	pa &= ARM_PTE_PAGE_MASK;

	if ((prot & VM_PROT_EXECUTE) && (pmap == kernel_pmap)) {
#if defined(KERNEL_INTEGRITY_CTRR) && defined(CONFIG_XNUPOST)
		extern vm_offset_t ctrr_test_page;
		if (__probable(v != ctrr_test_page))
#endif
		panic("pmap_enter_options(): attempt to add executable mapping to kernel_pmap");
	}
	assert(pn != vm_page_fictitious_addr);

	pmap_lock(pmap, PMAP_LOCK_SHARED);

	/*
	 *	Expand pmap to include this pte.  Assume that
	 *	pmap is always expanded to include enough hardware
	 *	pages to map one VM page.
	 */
	while ((pte_p = pmap_pte(pmap, v)) == PT_ENTRY_NULL) {
		/* Must unlock to expand the pmap. */
		pmap_unlock(pmap, PMAP_LOCK_SHARED);

		kr = pmap_expand(pmap, v, options, pt_attr_leaf_level(pt_attr));

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		pmap_lock(pmap, PMAP_LOCK_SHARED);
	}

	if (options & PMAP_OPTIONS_NOENTER) {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
		return KERN_SUCCESS;
	}

	/*
	 * Since we may not hold the pmap lock exclusive, updating the pte is
	 * done via a cmpxchg loop.
	 * We need to be careful about modifying non-local data structures before commiting
	 * the new pte since we may need to re-do the transaction.
	 */
	const pt_entry_t prev_pte = os_atomic_load(pte_p, relaxed);

	if (((prev_pte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE) && (pte_to_pa(prev_pte) != pa)) {
		/*
		 * There is already a mapping here & it's for a different physical page.
		 * First remove that mapping.
		 * We assume that we can leave the pmap lock held for shared access rather
		 * than exclusive access here, because we assume that the VM won't try to
		 * simultaneously map the same VA to multiple different physical pages.
		 * If that assumption is violated, sptm_map_page() will panic as the architecture
		 * does not allow the output address of a mapping to be changed without a break-
		 * before-make sequence.
		 */
		pmap_remove_range(pmap, v, v + PAGE_SIZE);
	}

	if (pmap != kernel_pmap) {
		ptd_info_t *ptd_info = ptep_get_info(pte_p);
		wiredcnt = &ptd_info->wiredcnt;
	}

	while (!committed) {
		pt_entry_t spte = ARM_PTE_TYPE_FAULT;
		pv_alloc_return_t pv_status = PV_ALLOC_SUCCESS;
		bool skip_footprint_debit = false;

		/*
		 * The XO index is used for TPRO mappings. To avoid exposing them as --x,
		 * the VM code tracks VM_MAP_TPRO requests and couples them with the proper
		 * read-write protection. The PMAP layer though still needs to use the right
		 * index, which is the older XO-now-TPRO one and that is specially selected
		 * here thanks to PMAP_OPTIONS_MAP_TPRO.
		 *
		 * Note that pmap_construct_pte() may check the nested region ASID bitmap,
		 * which needs to happen at every iteration of the commit loop in case we
		 * previously dropped the pmap lock.
		 */
		pt_entry_t pte = pmap_construct_pte(pmap, v, pa,
		    ((options & PMAP_OPTIONS_MAP_TPRO) ? VM_PROT_RORW_TP : prot), fault_type, wired, pt_attr, &pp_attr_bits);

		if (pa_valid(pa)) {
			unsigned int pai;
			boolean_t   is_altacct = FALSE, is_internal = FALSE, is_reusable = FALSE, is_external = FALSE;

			is_internal = FALSE;
			is_altacct = FALSE;

			pai = pa_index(pa);
			locked_pvh_t locked_pvh;

			if (__improbable(options & PMAP_OPTIONS_NOPREEMPT)) {
				locked_pvh = pvh_lock_nopreempt(pai);
			} else {
				locked_pvh = pvh_lock(pai);
			}

			/*
			 * Make sure that the current per-cpu PV free list has
			 * enough entries (2 in the worst-case scenario) to handle the enter_pv
			 * if the transaction succeeds. At this point, preemption has either
			 * been disabled by the caller or by pvh_lock() above.
			 * Note that we can still be interrupted, but a primary
			 * interrupt handler can never enter the pmap.
			 */
			assert(get_preemption_level() > 0);
			local_pv_free = &pmap_get_cpu_data()->pv_free;
			const bool allocation_required = !pvh_test_type(locked_pvh.pvh, PVH_TYPE_NULL) &&
			    !(pvh_test_type(locked_pvh.pvh, PVH_TYPE_PTEP) && pvh_ptep(locked_pvh.pvh) == pte_p);

			if (__improbable(allocation_required && (local_pv_free->count < 2))) {
				pv_entry_t *new_pve_p[2] = {PV_ENTRY_NULL};
				int new_allocated_pves = 0;

				while (new_allocated_pves < 2) {
					local_pv_free = &pmap_get_cpu_data()->pv_free;
					pv_status = pv_alloc(pmap, PMAP_LOCK_SHARED, options, &new_pve_p[new_allocated_pves], &locked_pvh, wiredcnt);
					if (pv_status == PV_ALLOC_FAIL) {
						break;
					} else if (pv_status == PV_ALLOC_RETRY) {
						/*
						 * In the case that pv_alloc() had to grab a new page of PVEs,
						 * it will have dropped the pmap lock while doing so.
						 * On non-PPL devices, dropping the lock re-enables preemption so we may
						 * be on a different CPU now.
						 */
						local_pv_free = &pmap_get_cpu_data()->pv_free;
					} else {
						/* If we've gotten this far then a node should've been allocated. */
						assert(new_pve_p[new_allocated_pves] != PV_ENTRY_NULL);

						new_allocated_pves++;
					}
				}

				for (int i = 0; i < new_allocated_pves; i++) {
					pv_free(new_pve_p[i]);
				}
			}

			if (pv_status == PV_ALLOC_FAIL) {
				pvh_unlock(&locked_pvh);
				kr = KERN_RESOURCE_SHORTAGE;
				break;
			} else if (pv_status == PV_ALLOC_RETRY) {
				pvh_unlock(&locked_pvh);
				/* We dropped the pmap and PVH locks to allocate. Retry transaction. */
				continue;
			}

			if ((flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT))) {
				wimg_bits = (flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT));
			} else {
				wimg_bits = pmap_cache_attributes(pn);
			}

			/**
			 * We may be retrying this operation after dropping the PVH lock.
			 * Cache attributes for the physical page may have changed while the lock
			 * was dropped, so update PTE cache attributes on each loop iteration.
			 */
			pte |= pmap_get_pt_ops(pmap)->wimg_to_pte(wimg_bits, pa);


			const sptm_return_t sptm_status = pmap_enter_pte(pmap, pte_p, pte, &locked_pvh, &spte, v, options, mapping_type);
			assert(committed == false);
			if ((sptm_status == SPTM_SUCCESS) || (sptm_status == SPTM_MAP_VALID)) {
				committed = true;
			} else if (sptm_status == SPTM_MAP_FLUSH_PENDING) {
				pvh_unlock(&locked_pvh);
				continue;
			} else if (sptm_status == SPTM_MAP_CODESIGN_ERROR) {
				pvh_unlock(&locked_pvh);
				kr = KERN_CODESIGN_ERROR;
				break;
			} else {
				pvh_unlock(&locked_pvh);
				kr = KERN_FAILURE;
				break;
			}
			const bool had_valid_mapping = (sptm_status == SPTM_MAP_VALID);
			/* End of transaction. Commit pv changes, pa bits, and memory accounting. */
			if (!had_valid_mapping) {
				pv_entry_t *new_pve_p = PV_ENTRY_NULL;
				int pve_ptep_idx = 0;
				pv_status = pmap_enter_pv(pmap, pte_p, options, PMAP_LOCK_SHARED, &locked_pvh, &new_pve_p, &pve_ptep_idx);
				/* We did all the allocations up top. So this shouldn't be able to fail. */
				if (pv_status != PV_ALLOC_SUCCESS) {
					panic("%s: unexpected pmap_enter_pv ret code: %d. new_pve_p=%p pmap=%p",
					    __func__, pv_status, new_pve_p, pmap);
				}

				if (pmap != kernel_pmap) {
					if (options & PMAP_OPTIONS_INTERNAL) {
						ppattr_pve_set_internal(pai, new_pve_p, pve_ptep_idx);
						if ((options & PMAP_OPTIONS_ALT_ACCT) ||
						    PMAP_FOOTPRINT_SUSPENDED(pmap)) {
							/*
							 * Make a note to ourselves that this
							 * mapping is using alternative
							 * accounting. We'll need this in order
							 * to know which ledger to debit when
							 * the mapping is removed.
							 *
							 * The altacct bit must be set while
							 * the pv head is locked. Defer the
							 * ledger accounting until after we've
							 * dropped the lock.
							 */
							ppattr_pve_set_altacct(pai, new_pve_p, pve_ptep_idx);
							is_altacct = TRUE;
						}
					}
					if (ppattr_test_reusable(pai) &&
					    !is_altacct) {
						is_reusable = TRUE;
					} else if (options & PMAP_OPTIONS_INTERNAL) {
						is_internal = TRUE;
					} else {
						is_external = TRUE;
					}
				}
			}

			pvh_unlock(&locked_pvh);

			if (pp_attr_bits != 0) {
				ppattr_pa_set_bits(pa, pp_attr_bits);
			}

			if (!had_valid_mapping && (pmap != kernel_pmap)) {
				pmap_ledger_credit(pmap, task_ledgers.phys_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);

				if (is_internal) {
					/*
					 * Make corresponding adjustments to
					 * phys_footprint statistics.
					 */
					pmap_ledger_credit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);
					if (is_altacct) {
						/*
						 * If this page is internal and
						 * in an IOKit region, credit
						 * the task's total count of
						 * dirty, internal IOKit pages.
						 * It should *not* count towards
						 * the task's total physical
						 * memory footprint, because
						 * this entire region was
						 * already billed to the task
						 * at the time the mapping was
						 * created.
						 *
						 * Put another way, this is
						 * internal++ and
						 * alternate_accounting++, so
						 * net effect on phys_footprint
						 * is 0. That means: don't
						 * touch phys_footprint here.
						 */
						pmap_ledger_credit(pmap, task_ledgers.alternate_accounting, pt_attr_page_size(pt_attr) * PAGE_RATIO);
					} else {
						if (pte_is_compressed(spte, pte_p) && !(spte & ARM_PTE_COMPRESSED_ALT)) {
							/* Replacing a compressed page (with internal accounting). No change to phys_footprint. */
							skip_footprint_debit = true;
						} else {
							pmap_ledger_credit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);
						}
					}
				}
				if (is_reusable) {
					pmap_ledger_credit(pmap, task_ledgers.reusable, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				} else if (is_external) {
					pmap_ledger_credit(pmap, task_ledgers.external, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				}
			}
		} else {
			if (prot & VM_PROT_EXECUTE) {
				kr = KERN_FAILURE;
				break;
			}

			wimg_bits = pmap_cache_attributes(pn);
			if ((flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT))) {
				wimg_bits = (wimg_bits & (~VM_WIMG_MASK)) | (flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT));
			}

			pte |= pmap_get_pt_ops(pmap)->wimg_to_pte(wimg_bits, pa);


			/**
			 * pmap_enter_pte() expects to be called with preemption disabled so it can access
			 * the per-CPU prev_ptes array.
			 */
			disable_preemption();
			const sptm_return_t sptm_status = pmap_enter_pte(pmap, pte_p, pte, NULL, &spte, v, options, mapping_type);
			enable_preemption();
			assert(committed == false);
			if ((sptm_status == SPTM_SUCCESS) || (sptm_status == SPTM_MAP_VALID)) {
				committed = true;

				/**
				 * If there was already a valid pte here then we reuse its
				 * reference on the ptd and drop the one that we took above.
				 */
			} else if (__improbable(sptm_status != SPTM_MAP_FLUSH_PENDING)) {
				panic("%s: Unexpected SPTM return code %u for non-managed PA 0x%llx", __func__, (unsigned int)sptm_status, (unsigned long long)pa);
			}
		}
		if (committed) {
			if (pte_is_compressed(spte, pte_p)) {
				assert(pmap != kernel_pmap);

				/* One less "compressed" */
				pmap_ledger_debit(pmap, task_ledgers.internal_compressed,
				    pt_attr_page_size(pt_attr) * PAGE_RATIO);

				if (spte & ARM_PTE_COMPRESSED_ALT) {
					pmap_ledger_debit(pmap, task_ledgers.alternate_accounting_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				} else if (!skip_footprint_debit) {
					/* Was part of the footprint */
					pmap_ledger_debit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				}
			}
		}
	}

	pmap_unlock(pmap, PMAP_LOCK_SHARED);

	if (kr == KERN_CODESIGN_ERROR) {
		/* Print any logs from TXM */
		txm_print_logs();
	}
	return kr;
}

kern_return_t
pmap_enter_options_addr(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	__unused void   *arg,
	pmap_mapping_type_t mapping_type)
{
	kern_return_t kr = KERN_FAILURE;


	PMAP_TRACE(2, PMAP_CODE(PMAP__ENTER) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(v), pa, prot);

	kr = pmap_enter_options_internal(pmap, v, pa, prot, fault_type, flags, wired, options, mapping_type);

	PMAP_TRACE(2, PMAP_CODE(PMAP__ENTER) | DBG_FUNC_END, kr);

	return kr;
}

kern_return_t
pmap_enter_options(
	pmap_t pmap,
	vm_map_address_t v,
	ppnum_t pn,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	__unused void   *arg,
	pmap_mapping_type_t mapping_type)
{
	return pmap_enter_options_addr(pmap, v, ((pmap_paddr_t)pn) << PAGE_SHIFT, prot,
	           fault_type, flags, wired, options, arg, mapping_type);
}

/*
 *	Routine:	pmap_change_wiring
 *	Function:	Change the wiring attribute for a map/virtual-address
 *			pair.
 *	In/out conditions:
 *			The mapping must already exist in the pmap.
 */
MARK_AS_PMAP_TEXT void
pmap_change_wiring_internal(
	pmap_t pmap,
	vm_map_address_t v,
	boolean_t wired)
{
	pt_entry_t     *pte_p, prev_pte;

	validate_pmap_mutable(pmap);

	pmap_lock(pmap, PMAP_LOCK_SHARED);

	const pt_entry_t new_wiring = (wired ? ARM_PTE_WIRED : 0);

	pte_p = pmap_pte(pmap, v);
	if (pte_p == PT_ENTRY_NULL) {
		if (!wired) {
			/*
			 * The PTE may have already been cleared by a disconnect/remove operation, and the L3 table
			 * may have been freed by a remove operation.
			 */
			goto pmap_change_wiring_return;
		} else {
			panic("%s: Attempt to wire nonexistent PTE for pmap %p", __func__, pmap);
		}
	}

	disable_preemption();
	pmap_sptm_percpu_data_t *sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
	sptm_pcpu->sptm_templates[0] = (*pte_p & ~ARM_PTE_WIRED) | new_wiring;

	pmap_retype_epoch_enter();
	sptm_update_region(pmap->ttep, v, 1, sptm_pcpu->sptm_templates_pa, SPTM_UPDATE_SW_WIRED);
	pmap_retype_epoch_exit();

	prev_pte = os_atomic_load(&sptm_pcpu->sptm_prev_ptes[0], relaxed);
	enable_preemption();

	if ((prev_pte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT) {
		goto pmap_change_wiring_return;
	}

	if ((pmap != kernel_pmap) && (wired != pte_is_wired(prev_pte))) {
		pte_update_wiredcnt(pmap, pte_p, wired);
	}

pmap_change_wiring_return:
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
}

void
pmap_change_wiring(
	pmap_t pmap,
	vm_map_address_t v,
	boolean_t wired)
{
	pmap_change_wiring_internal(pmap, v, wired);
}

MARK_AS_PMAP_TEXT pmap_paddr_t
pmap_find_pa_internal(
	pmap_t pmap,
	addr64_t va)
{
	pmap_paddr_t    pa = 0;

	validate_pmap(pmap);

	if (pmap != kernel_pmap) {
		pmap_lock(pmap, PMAP_LOCK_SHARED);
	}

	pa = pmap_vtophys(pmap, va);

	if (pmap != kernel_pmap) {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
	}

	return pa;
}

pmap_paddr_t
pmap_find_pa_nofault(pmap_t pmap, addr64_t va)
{
	pmap_paddr_t pa = 0;

	if (pmap == kernel_pmap) {
		pa = mmu_kvtop(va);
	} else if ((current_thread()->map) && (pmap == vm_map_pmap(current_thread()->map))) {
		/*
		 * Note that this doesn't account for PAN: mmu_uvtop() may return a valid
		 * translation even if PAN would prevent kernel access through the translation.
		 * It's therefore assumed the UVA will be accessed in a PAN-disabled context.
		 */
		pa = mmu_uvtop(va);
	}
	return pa;
}

pmap_paddr_t
pmap_find_pa(
	pmap_t pmap,
	addr64_t va)
{
	pmap_paddr_t pa = pmap_find_pa_nofault(pmap, va);

	if (pa != 0) {
		return pa;
	}

	if (not_in_kdp) {
		return pmap_find_pa_internal(pmap, va);
	} else {
		return pmap_vtophys(pmap, va);
	}
}

ppnum_t
pmap_find_phys_nofault(
	pmap_t pmap,
	addr64_t va)
{
	ppnum_t ppn;
	ppn = atop(pmap_find_pa_nofault(pmap, va));
	return ppn;
}

ppnum_t
pmap_find_phys(
	pmap_t pmap,
	addr64_t va)
{
	ppnum_t ppn;
	ppn = atop(pmap_find_pa(pmap, va));
	return ppn;
}

/**
 * Translate a kernel virtual address into a physical address.
 *
 * @param va The kernel virtual address to translate. Does not work on user
 *           virtual addresses.
 *
 * @return The physical address if the translation was successful, or zero if
 *         no valid mappings were found for the given virtual address.
 */
pmap_paddr_t
kvtophys(vm_offset_t va)
{
	sptm_paddr_t pa;

	if (sptm_kvtophys(va, &pa) != LIBSPTM_SUCCESS) {
		return 0;
	}

	return pa;
}

/**
 * Variant of kvtophys that can't fail. If no mapping is found or the mapping
 * points to a non-kernel-managed physical page, then this call will panic().
 *
 * @note The output of this function is guaranteed to be a kernel-managed
 *       physical page, which means it's safe to pass the output directly to
 *       pa_index() to create a physical address index for various pmap data
 *       structures.
 *
 * @param va The kernel virtual address to translate. Does not work on user
 *           virtual addresses.
 *
 * @return The translated physical address for the given virtual address.
 */
pmap_paddr_t
kvtophys_nofail(vm_offset_t va)
{
	pmap_paddr_t pa;

	if (__improbable(sptm_kvtophys(va, &pa) != LIBSPTM_SUCCESS)) {
		panic("%s: VA->PA translation failed for va %p", __func__, (void *)va);
	}

	return pa;
}

pmap_paddr_t
pmap_vtophys(
	pmap_t pmap,
	addr64_t va)
{
	if ((va < pmap->min) || (va >= pmap->max)) {
		return 0;
	}

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	tt_entry_t * ttp = NULL;
	tt_entry_t * ttep = NULL;
	tt_entry_t   tte = ARM_TTE_EMPTY;
	pmap_paddr_t pa = 0;
	unsigned int cur_level;

	ttp = pmap->tte;

	for (cur_level = pt_attr_root_level(pt_attr); cur_level <= pt_attr_leaf_level(pt_attr); cur_level++) {
		ttep = &ttp[ttn_index(pt_attr, va, cur_level)];

		tte = *ttep;

		const uint64_t valid_mask = pt_attr->pta_level_info[cur_level].valid_mask;
		const uint64_t type_mask = pt_attr->pta_level_info[cur_level].type_mask;
		const uint64_t type_block = pt_attr->pta_level_info[cur_level].type_block;
		const uint64_t offmask = pt_attr->pta_level_info[cur_level].offmask;

		if ((tte & valid_mask) != valid_mask) {
			return (pmap_paddr_t) 0;
		}

		/* This detects both leaf entries and intermediate block mappings. */
		if ((tte & type_mask) == type_block) {
			pa = ((tte & ARM_TTE_PA_MASK & ~offmask) | (va & offmask));
			break;
		}

		ttp = (tt_entry_t*)phystokv(tte & ARM_TTE_TABLE_MASK);
	}

	return pa;
}

/*
 *	pmap_init_pte_page - Initialize a page table page.
 */
MARK_AS_PMAP_TEXT void
pmap_init_pte_page(
	pmap_t pmap,
	pt_entry_t *pte_p,
	vm_offset_t va,
	unsigned int ttlevel,
	boolean_t alloc_ptd)
{
	pt_desc_t   *ptdp = NULL;
	unsigned int pai = pa_index(kvtophys_nofail((vm_offset_t)pte_p));
	const uintptr_t pvh = pai_to_pvh(pai);

	if (pvh_test_type(pvh, PVH_TYPE_NULL)) {
		if (alloc_ptd) {
			/*
			 * This path should only be invoked from arm_vm_init.  If we are emulating 16KB pages
			 * on 4KB hardware, we may already have allocated a page table descriptor for a
			 * bootstrap request, so we check for an existing PTD here.
			 */
			ptdp = ptd_alloc(pmap, PMAP_PAGE_ALLOCATE_NOWAIT);
			if (ptdp == NULL) {
				panic("%s: unable to allocate PTD", __func__);
			}
			/* Clear all PVH flags when using a page for a PTD to avoid tripping unexpected page flag usage checks. */
			pvh_store_head_unlocked(pai, (uintptr_t)ptdp & ~PVH_HIGH_FLAGS, PVH_TYPE_PTDP);
		} else {
			panic("pmap_init_pte_page(): no PTD for pte_p %p", pte_p);
		}
	} else if (pvh_test_type(pvh, PVH_TYPE_PTDP)) {
		ptdp = pvh_ptd(pvh);
	} else {
		panic("pmap_init_pte_page(): invalid PVH type for pte_p %p", pte_p);
	}

	// pagetable zero-fill and barrier should be guaranteed by the SPTM
	ptd_info_init(ptdp, pmap, va, ttlevel, pte_p);
}

/*
 * This function guarantees that a pmap has the necessary page tables in place
 * to map the specified VA.  If necessary, it will allocate new tables at any
 * non-root level in the hierarchy (the root table is always already allocated
 * and stored in the pmap).
 *
 * @note This function is expected to be called without any pmap or PVH lock
 *       held.
 *
 * @note It is possible for an L3 table newly allocated by this function to be
 *       deleted by another thread before control returns to the caller, iff that
 *       table is an ordinary userspace table.  Callers that use this function
 *       to allocate new user L3 tables are therefore expected to keep calling
 *       this function until they observe a successful L3 PTE lookup with the pmap
 *       lock held.  As long as it does not drop the pmap lock, the caller may
 *       then safely use the looked-up L3 table.  See the use of this function in
 *       pmap_enter_options_internal() for an example.
 *
 * @param pmap The pmap for which to ensure mapping space is present.
 * @param v The virtual address for which to ensure mapping space is present
 *          in [pmap].
 * @param options Flags to pass to pmap_tt_allocate() if a new table needs to be
 *                allocated.  The only valid option is PMAP_OPTIONS_NOWAIT, which
 *                specifies that the allocation must not block.
 * @param level The maximum paging level for which to ensure a table is present.
 *
 * @return KERN_INVALID_ADDRESS if [v] is outside the pmap's mappable range,
 *         KERN_RESOURCE_SHORTAGE if a new table can't be allocated,
 *         KERN_SUCCESS otherwise.
 */
MARK_AS_PMAP_TEXT static kern_return_t
pmap_expand(
	pmap_t pmap,
	vm_map_address_t v,
	unsigned int options,
	unsigned int level)
{
	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if (__improbable((v < pmap->min) || (v >= pmap->max))) {
		return KERN_INVALID_ADDRESS;
	}
	pmap_paddr_t pa;
	const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
	const uint64_t table_align_mask = (PAGE_SIZE / pmap_page_size) - 1;
	unsigned int ttlevel = pt_attr_root_level(pt_attr);
	tt_entry_t *table_ttep = pmap->tte;
	tt_entry_t *ttep;
	tt_entry_t old_tte = ARM_TTE_EMPTY;

	pa = 0x0ULL;

	for (; ttlevel < level; ttlevel++) {
		/**
		 * If the previous iteration didn't allocate a new table, obtain the table from the previous TTE.
		 * Doing this step at the beginning of the loop instead of the end (which would make it part of
		 * the prior iteration) avoids the possibility of executing this step to extract an L3 table KVA
		 * from an L2 TTE, which would be useless because there would be no next iteration to make use
		 * of the table KVA.
		 */
		if (table_ttep == NULL) {
			assert((old_tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) == (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID));
			table_ttep = (tt_entry_t*)phystokv(old_tte & ARM_TTE_TABLE_MASK);
		}

		/**
		 * We don't need to hold the pmap lock while walking the paging hierarchy.  Only L3 tables are
		 * allowed to be dynamically removed, and only for regular user pmaps at that.  We may allocate
		 * a new L3 table below, but we will only access L0-L2 tables, so there's no risk of a table
		 * being deleted while we are using it for the next level(s) of lookup.
		 */
		ttep = &table_ttep[ttn_index(pt_attr, v, ttlevel)];
		old_tte = os_atomic_load(ttep, relaxed);
		table_ttep = NULL;
		if ((old_tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID)) {
			tt_entry_t new_tte, *new_ttep;
			while (pmap_tt_allocate(pmap, &new_ttep, ttlevel + 1, options | PMAP_PAGE_NOZEROFILL) != KERN_SUCCESS) {
				if (options & PMAP_OPTIONS_NOWAIT) {
					return KERN_RESOURCE_SHORTAGE;
				}
				VM_PAGE_WAIT();
			}
			/* Grab the pmap lock to ensure we don't try to concurrently map different tables at the same TTE. */
			pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
			old_tte = os_atomic_load(ttep, relaxed);
			if ((old_tte & (ARM_TTE_TYPE_MASK | ARM_TTE_VALID)) != (ARM_TTE_TYPE_TABLE | ARM_TTE_VALID)) {
				pmap_init_pte_page(pmap, (pt_entry_t *) new_ttep, v, ttlevel + 1, FALSE);
				pa = kvtophys_nofail((vm_offset_t)new_ttep);
				/*
				 * If the table is going to map a kernel RO zone VA region, then we must
				 * upgrade its SPTM type to XNU_PAGE_TABLE_ROZONE.  The SPTM's type system
				 * requires the table to be transitioned through XNU_DEFAULT for refcount
				 * enforcement, which is fine since this path is expected to execute only
				 * once during boot.
				 */
				if (__improbable(ttlevel == pt_attr_twig_level(pt_attr)) &&
				    (pmap == kernel_pmap) && zone_spans_ro_va(v, v + PAGE_SIZE)) {
					sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
					sptm_retype(pa, XNU_PAGE_TABLE, XNU_DEFAULT, retype_params);
					retype_params.level = (sptm_pt_level_t)pt_attr_leaf_level(pt_attr);
					sptm_retype(pa, XNU_DEFAULT, XNU_PAGE_TABLE_ROZONE, retype_params);
				}
				new_tte = (pa & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID;
				sptm_map_table(pmap->ttep, v, (sptm_pt_level_t)ttlevel, new_tte);
				PMAP_TRACE(4 + ttlevel, PMAP_CODE(PMAP__TTE), VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(v & ~pt_attr_ln_offmask(pt_attr, ttlevel)),
				    VM_KERNEL_ADDRHIDE((v & ~pt_attr_ln_offmask(pt_attr, ttlevel)) + pt_attr_ln_size(pt_attr, ttlevel)), new_tte);
				/**
				 * If we need to set up multiple TTEs mapping different parts of the same page
				 * (e.g. because we're carving multiple 4K page tables out of a 16K native page,
				 * determine which of the grouped TTEs is the one that we need to follow for the
				 * next level of the table walk.
				 */
				table_ttep = new_ttep + ((((uintptr_t)ttep / sizeof(tt_entry_t)) & table_align_mask) *
				    (pmap_page_size / sizeof(tt_entry_t)));
				pa = 0x0ULL;
				new_ttep = (tt_entry_t *)NULL;
			}
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);

			if (new_ttep != (tt_entry_t *)NULL) {
				pmap_tt_deallocate(pmap, new_ttep, ttlevel + 1);
				new_ttep = (tt_entry_t *)NULL;
			}
		}
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	pmap_gc
 *	Function:
 *              Pmap garbage collection
 *		Called by the pageout daemon when pages are scarce.
 *
 */
void
pmap_gc(void)
{
	/*
	 * TODO: as far as I can tell this has never been implemented to do anything meaninful.
	 * We can't just destroy any old pmap on the chance that it may be active on a CPU
	 * or may contain wired mappings.  However, it may make sense to scan the pmap VM
	 * object here, and for each page consult the SPTM frame table and if necessary
	 * the PTD in the PV head table.  If the frame table indicates the page is a leaf
	 * page table page and the PTD indicates it has no wired mappings, we can call
	 * pmap_remove() on the VA region mapped by the page and therein return the page
	 * to the VM.
	 */
}

/*
 *      By default, don't attempt pmap GC more frequently
 *      than once / 1 minutes.
 */

void
compute_pmap_gc_throttle(
	void *arg __unused)
{
}

/*
 * pmap_attribute_cache_sync(vm_offset_t pa)
 *
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */

kern_return_t
pmap_attribute_cache_sync(
	ppnum_t pp,
	vm_size_t size,
	__unused vm_machine_attribute_t attribute,
	__unused vm_machine_attribute_val_t * value)
{
	if (size > PAGE_SIZE) {
		panic("pmap_attribute_cache_sync size: 0x%llx", (uint64_t)size);
	} else {
		cache_sync_page(pp);
	}

	return KERN_SUCCESS;
}

/*
 * pmap_sync_page_data_phys(ppnum_t pp)
 *
 * Invalidates all of the instruction cache on a physical page and
 * pushes any dirty data from the data cache for the same physical page
 */
void
pmap_sync_page_data_phys(
	ppnum_t pp)
{
	cache_sync_page(pp);
}

/*
 * pmap_sync_page_attributes_phys(ppnum_t pp)
 *
 * Write back and invalidate all cachelines on a physical page.
 */
void
pmap_sync_page_attributes_phys(
	ppnum_t pp)
{
	flush_dcache((vm_offset_t) (pp << PAGE_SHIFT), PAGE_SIZE, TRUE);
}

#if CONFIG_COREDUMP
/* temporary workaround */
boolean_t
coredumpok(
	vm_map_t map,
	mach_vm_offset_t va)
{
	pt_entry_t     *pte_p;
	pt_entry_t      spte;

	pte_p = pmap_pte(map->pmap, va);
	if (0 == pte_p) {
		return FALSE;
	}
	if (vm_map_entry_has_device_pager(map, va)) {
		return FALSE;
	}
	spte = *pte_p;
	return (spte & ARM_PTE_ATTRINDXMASK) == ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
}
#endif

void
fillPage(
	ppnum_t pn,
	unsigned int fill)
{
	unsigned int   *addr;
	int             count;

	addr = (unsigned int *) phystokv(ptoa(pn));
	count = PAGE_SIZE / sizeof(unsigned int);
	while (count--) {
		*addr++ = fill;
	}
}

extern void     mapping_set_mod(ppnum_t pn);

void
mapping_set_mod(
	ppnum_t pn)
{
	pmap_set_modify(pn);
}

extern void     mapping_set_ref(ppnum_t pn);

void
mapping_set_ref(
	ppnum_t pn)
{
	pmap_set_reference(pn);
}

/*
 * Clear specified attribute bits.
 *
 * Try to force an arm_fast_fault() for all mappings of
 * the page - to force attributes to be set again at fault time.
 * If the forcing succeeds, clear the cached bits at the head.
 * Otherwise, something must have been wired, so leave the cached
 * attributes alone.
 */
MARK_AS_PMAP_TEXT static void
phys_attribute_clear_with_flush_range(
	ppnum_t         pn,
	unsigned int    bits,
	int             options,
	void            *arg,
	pmap_tlb_flush_range_t *flush_range)
{
	pmap_paddr_t    pa = ptoa(pn);
	vm_prot_t       allow_mode = VM_PROT_ALL;

	if ((arg != NULL) || (flush_range != NULL)) {
		options = options & ~PMAP_OPTIONS_NOFLUSH;
	}

	if (__improbable((options & PMAP_OPTIONS_FF_WIRED) != 0)) {
		panic("phys_attribute_clear(%#010x,%#010x,%#010x,%p,%p): "
		    "invalid options",
		    pn, bits, options, arg, flush_range);
	}

	if (__improbable((bits & PP_ATTR_MODIFIED) &&
	    (options & PMAP_OPTIONS_NOFLUSH))) {
		panic("phys_attribute_clear(%#010x,%#010x,%#010x,%p,%p): "
		    "should not clear 'modified' without flushing TLBs",
		    pn, bits, options, arg, flush_range);
	}

	assert(pn != vm_page_fictitious_addr);

	if (options & PMAP_OPTIONS_CLEAR_WRITE) {
		assert(bits == PP_ATTR_MODIFIED);

		pmap_page_protect_options_with_flush_range(pn, (VM_PROT_ALL & ~VM_PROT_WRITE), options, NULL, flush_range);
		/*
		 * We short circuit this case; it should not need to
		 * invoke arm_force_fast_fault, so just clear the modified bit.
		 * pmap_page_protect has taken care of resetting
		 * the state so that we'll see the next write as a fault to
		 * the VM (i.e. we don't want a fast fault).
		 */
		ppattr_pa_clear_bits(pa, (pp_attr_t)bits);
		return;
	}
	if (bits & PP_ATTR_REFERENCED) {
		allow_mode &= ~(VM_PROT_READ | VM_PROT_EXECUTE);
	}
	if (bits & PP_ATTR_MODIFIED) {
		allow_mode &= ~VM_PROT_WRITE;
	}

	if (bits == PP_ATTR_NOENCRYPT) {
		/*
		 * We short circuit this case; it should not need to
		 * invoke arm_force_fast_fault, so just clear and
		 * return.  On ARM, this bit is just a debugging aid.
		 */
		ppattr_pa_clear_bits(pa, (pp_attr_t)bits);
		return;
	}

	arm_force_fast_fault_with_flush_range(pn, allow_mode, options, NULL, (pp_attr_t)bits, flush_range);
}

MARK_AS_PMAP_TEXT void
phys_attribute_clear_internal(
	ppnum_t         pn,
	unsigned int    bits,
	int             options,
	void            *arg)
{
	phys_attribute_clear_with_flush_range(pn, bits, options, arg, NULL);
}

#if __ARM_RANGE_TLBI__

MARK_AS_PMAP_TEXT static vm_map_address_t
phys_attribute_clear_twig_internal(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	unsigned int bits,
	unsigned int options,
	pmap_tlb_flush_range_t *flush_range)
{
	pmap_assert_locked(pmap, PMAP_LOCK_SHARED);
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	assert(end >= start);
	assert((end - start) <= pt_attr_twig_size(pt_attr));
	const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
	vm_map_address_t va = start;
	pt_entry_t     *pte_p, *start_pte_p, *end_pte_p, *curr_pte_p;
	tt_entry_t     *tte_p;
	tte_p = pmap_tte(pmap, start);

	/**
	 * It's possible that this portion of our VA region has never been paged in, in which case
	 * there may not be a valid twig or leaf table here.  It's also possible the leaf table may
	 * have been unmapped while we had the pmap lock dropped to handle a pending preemption, so
	 * in either case just submit whatever we've already accumulated since there's going to be
	 * a discontinuity in the region.
	 */
	if ((tte_p == (tt_entry_t *) NULL) || ((*tte_p & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE)) {
		pmap_multipage_op_submit_region(flush_range);
		return end;
	}

	pte_p = (pt_entry_t *) ttetokv(*tte_p);

	start_pte_p = &pte_p[pte_index(pt_attr, start)];
	end_pte_p = start_pte_p + ((end - start) >> pt_attr_leaf_shift(pt_attr));
	assert(end_pte_p >= start_pte_p);
	for (curr_pte_p = start_pte_p; curr_pte_p < end_pte_p; curr_pte_p++, va += pmap_page_size) {
		if (flush_range->pending_region_entries == 0) {
			flush_range->pending_region_start = va;
		} else {
			assertf((flush_range->pending_region_start +
			    (flush_range->pending_region_entries * pmap_page_size)) == va,
			    "pending_region_start 0x%llx + 0x%lx pages != va 0%llx",
			    (unsigned long long)flush_range->pending_region_start,
			    (unsigned long)flush_range->pending_region_entries,
			    (unsigned long long)va);
		}
		flush_range->current_ptep = curr_pte_p;
		const pt_entry_t spte = os_atomic_load(curr_pte_p, relaxed);
		const pmap_paddr_t pa = pte_to_pa(spte);
		if (((spte & ARM_PTE_TYPE_MASK) != ARM_PTE_TYPE_FAULT) && pa_valid(pa)) {
			/* The PTE maps a managed page, so do the appropriate PV list-based permission changes. */
			const ppnum_t pn = (ppnum_t) atop(pa);
			phys_attribute_clear_with_flush_range(pn, bits, options, NULL, flush_range);
			if (__probable(flush_range->region_entry_added)) {
				flush_range->region_entry_added = false;
			} else {
				/**
				 * It's possible that some other thread removed the mapping between our check
				 * of the PTE above and taking the PVH lock in the
				 * phys_attribute_clear_with_flush_range() path.  In that case we have a
				 * discontinuity in the region to update, so just submit any pending region
				 * templates and start a new region op on the next iteration.
				 */
				pmap_multipage_op_submit_region(flush_range);
			}
		} else if (__improbable((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT)) {
			/**
			 * We've found an invalid mapping, so we have a discontinuity in the the region to
			 * update.  Handle this by submitting any pending region templates and starting a new
			 * region on the next iteration.  In theory we could instead handle this by installing
			 * a "safe" (AF bit cleared, minimal permissions) PTE template; the SPTM would just
			 * ignore the update on finding an invalid mapping in the PTE.  But we don't know
			 * what a "safe" template will be in all cases: for example, JIT regions require all
			 * mapping to either be invalid or to have full RWX permissions.
			 */
			pmap_multipage_op_submit_region(flush_range);
		} else if (pmap_insert_flush_range_template(spte, flush_range)) {
			/**
			 * We've found a mapping to a non-managed page, so just insert the existing
			 * PTE into the pending region ops since we don't manage attributes for non-managed
			 * pages.
			 * If pmap_insert_flush_range_template() returns true, indicating that it reached
			 * the mapping limit and submitted the SPTM call, then we also submit any pending
			 * disjoint ops.  Having pending operations in either category will keep preemption
			 * disabled, and we want to ensure that we can at least temporarily
			 * re-enable preemption every SPTM_MAPPING_LIMIT mappings.
			 */
			pmap_multipage_op_submit_disjoint(0, flush_range);
		}
	}

	/* SPTM region ops can't span L3 table boundaries, so submit any pending region templates now. */
	pmap_multipage_op_submit_region(flush_range);
	return end;
}

MARK_AS_PMAP_TEXT vm_map_address_t
phys_attribute_clear_range_internal(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	unsigned int bits,
	unsigned int options)
{
	if (__improbable(end < start)) {
		panic("%s: invalid address range %p, %p", __func__, (void*)start, (void*)end);
	}
	validate_pmap_mutable(pmap);

	vm_map_address_t va = start;
	pmap_tlb_flush_range_t flush_range = {
		.ptfr_pmap = pmap,
		.ptfr_start = start,
		.ptfr_end = end,
		.current_ptep = NULL,
		.pending_region_start = 0,
		.pending_region_entries = 0,
		.region_entry_added = false,
		.current_header = NULL,
		.current_header_first_mapping_index = 0,
		.submitted_entries = 0,
		.pending_disjoint_entries = 0,
		.ptfr_flush_needed = false
	};

	pmap_lock(pmap, PMAP_LOCK_SHARED);
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	while (va < end) {
		vm_map_address_t curr_end;

		curr_end = ((va + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr));
		if (curr_end > end) {
			curr_end = end;
		}

		va = phys_attribute_clear_twig_internal(pmap, va, curr_end, bits, options, &flush_range);
	}
	pmap_multipage_op_submit(&flush_range);
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
	assert((flush_range.pending_disjoint_entries == 0) && (flush_range.pending_region_entries == 0));
	if (flush_range.ptfr_flush_needed) {
		pmap_get_pt_ops(pmap)->flush_tlb_region_async(
			flush_range.ptfr_start,
			flush_range.ptfr_end - flush_range.ptfr_start,
			flush_range.ptfr_pmap,
			true);
		sync_tlb_flush();
	}
	return va;
}

static void
phys_attribute_clear_range(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	unsigned int bits,
	unsigned int options)
{
	/*
	 * We allow single-page requests to execute non-preemptibly,
	 * as it doesn't make sense to sample AST_URGENT for a single-page
	 * operation, and there are a couple of special use cases that
	 * require a non-preemptible single-page operation.
	 */
	if ((end - start) > (pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO)) {
		pmap_verify_preemptible();
	}
	__assert_only const int preemption_level = get_preemption_level();

	PMAP_TRACE(3, PMAP_CODE(PMAP__ATTRIBUTE_CLEAR_RANGE) | DBG_FUNC_START, bits);

	phys_attribute_clear_range_internal(pmap, start, end, bits, options);

	PMAP_TRACE(3, PMAP_CODE(PMAP__ATTRIBUTE_CLEAR_RANGE) | DBG_FUNC_END);

	assert(preemption_level == get_preemption_level());
}
#endif /* __ARM_RANGE_TLBI__ */

static void
phys_attribute_clear(
	ppnum_t         pn,
	unsigned int    bits,
	int             options,
	void            *arg)
{
	/*
	 * Do we really want this tracepoint?  It will be extremely chatty.
	 * Also, should we have a corresponding trace point for the set path?
	 */
	PMAP_TRACE(3, PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_START, pn, bits);

	phys_attribute_clear_internal(pn, bits, options, arg);

	PMAP_TRACE(3, PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_END);
}

/*
 *	Set specified attribute bits.
 *
 *	Set cached value in the pv head because we have
 *	no per-mapping hardware support for referenced and
 *	modify bits.
 */
MARK_AS_PMAP_TEXT void
phys_attribute_set_internal(
	ppnum_t pn,
	unsigned int bits)
{
	pmap_paddr_t    pa = ptoa(pn);
	assert(pn != vm_page_fictitious_addr);

	ppattr_pa_set_bits(pa, (uint16_t)bits);

	return;
}

static void
phys_attribute_set(
	ppnum_t pn,
	unsigned int bits)
{
	phys_attribute_set_internal(pn, bits);
}


/*
 *	Check specified attribute bits.
 *
 *	use the software cached bits (since no hw support).
 */
static boolean_t
phys_attribute_test(
	ppnum_t pn,
	unsigned int bits)
{
	pmap_paddr_t    pa = ptoa(pn);
	assert(pn != vm_page_fictitious_addr);
	return ppattr_pa_test_bits(pa, (pp_attr_t)bits);
}


/*
 *	Set the modify/reference bits on the specified physical page.
 */
void
pmap_set_modify(ppnum_t pn)
{
	phys_attribute_set(pn, PP_ATTR_MODIFIED);
}


/*
 *	Clear the modify bits on the specified physical page.
 */
void
pmap_clear_modify(
	ppnum_t pn)
{
	phys_attribute_clear(pn, PP_ATTR_MODIFIED, 0, NULL);
}


/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page is modified
 *	by any physical maps.
 */
boolean_t
pmap_is_modified(
	ppnum_t pn)
{
	return phys_attribute_test(pn, PP_ATTR_MODIFIED);
}


/*
 *	Set the reference bit on the specified physical page.
 */
static void
pmap_set_reference(
	ppnum_t pn)
{
	phys_attribute_set(pn, PP_ATTR_REFERENCED);
}

/*
 *	Clear the reference bits on the specified physical page.
 */
void
pmap_clear_reference(
	ppnum_t pn)
{
	phys_attribute_clear(pn, PP_ATTR_REFERENCED, 0, NULL);
}


/*
 *	pmap_is_referenced:
 *
 *	Return whether or not the specified physical page is referenced
 *	by any physical maps.
 */
boolean_t
pmap_is_referenced(
	ppnum_t pn)
{
	return phys_attribute_test(pn, PP_ATTR_REFERENCED);
}

/*
 * pmap_get_refmod(phys)
 *  returns the referenced and modified bits of the specified
 *  physical page.
 */
unsigned int
pmap_get_refmod(
	ppnum_t pn)
{
	return ((phys_attribute_test(pn, PP_ATTR_MODIFIED)) ? VM_MEM_MODIFIED : 0)
	       | ((phys_attribute_test(pn, PP_ATTR_REFERENCED)) ? VM_MEM_REFERENCED : 0);
}

static inline unsigned int
pmap_clear_refmod_mask_to_modified_bits(const unsigned int mask)
{
	return ((mask & VM_MEM_MODIFIED) ? PP_ATTR_MODIFIED : 0) |
	       ((mask & VM_MEM_REFERENCED) ? PP_ATTR_REFERENCED : 0);
}

/*
 * pmap_clear_refmod(phys, mask)
 *  clears the referenced and modified bits as specified by the mask
 *  of the specified physical page.
 */
void
pmap_clear_refmod_options(
	ppnum_t         pn,
	unsigned int    mask,
	unsigned int    options,
	void            *arg)
{
	unsigned int    bits;

	bits = pmap_clear_refmod_mask_to_modified_bits(mask);
	phys_attribute_clear(pn, bits, options, arg);
}

/*
 * Perform pmap_clear_refmod_options on a virtual address range.
 * The operation will be performed in bulk & tlb flushes will be coalesced
 * if possible.
 *
 * Returns true if the operation is supported on this platform.
 * If this function returns false, the operation is not supported and
 * nothing has been modified in the pmap.
 */
bool
pmap_clear_refmod_range_options(
	pmap_t pmap __unused,
	vm_map_address_t start __unused,
	vm_map_address_t end __unused,
	unsigned int mask __unused,
	unsigned int options __unused)
{
#if __ARM_RANGE_TLBI__
	unsigned int    bits;
	bits = pmap_clear_refmod_mask_to_modified_bits(mask);
	phys_attribute_clear_range(pmap, start, end, bits, options);
	return true;
#else /* __ARM_RANGE_TLBI__ */
#pragma unused(pmap, start, end, mask, options)
	/*
	 * This operation allows the VM to bulk modify refmod bits on a virtually
	 * contiguous range of addresses. This is large performance improvement on
	 * platforms that support ranged tlbi instructions. But on older platforms,
	 * we can only flush per-page or the entire asid. So we currently
	 * only support this operation on platforms that support ranged tlbi.
	 * instructions. On other platforms, we require that
	 * the VM modify the bits on a per-page basis.
	 */
	return false;
#endif /* __ARM_RANGE_TLBI__ */
}

void
pmap_clear_refmod(
	ppnum_t pn,
	unsigned int mask)
{
	pmap_clear_refmod_options(pn, mask, 0, NULL);
}

unsigned int
pmap_disconnect_options(
	ppnum_t pn,
	unsigned int options,
	void *arg)
{
	if ((options & PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED)) {
		/*
		 * On ARM, the "modified" bit is managed by software, so
		 * we know up-front if the physical page is "modified",
		 * without having to scan all the PTEs pointing to it.
		 * The caller should have made the VM page "busy" so noone
		 * should be able to establish any new mapping and "modify"
		 * the page behind us.
		 */
		if (pmap_is_modified(pn)) {
			/*
			 * The page has been modified and will be sent to
			 * the VM compressor.
			 */
			options |= PMAP_OPTIONS_COMPRESSOR;
		} else {
			/*
			 * The page hasn't been modified and will be freed
			 * instead of compressed.
			 */
		}
	}

	/* disconnect the page */
	pmap_page_protect_options(pn, 0, options, arg);

	/* return ref/chg status */
	return pmap_get_refmod(pn);
}

/*
 *	Routine:
 *		pmap_disconnect
 *
 *	Function:
 *		Disconnect all mappings for this page and return reference and change status
 *		in generic format.
 *
 */
unsigned int
pmap_disconnect(
	ppnum_t pn)
{
	pmap_page_protect(pn, 0);       /* disconnect the page */
	return pmap_get_refmod(pn);   /* return ref/chg status */
}

boolean_t
pmap_has_managed_page(ppnum_t first, ppnum_t last)
{
	if (ptoa(first) >= vm_last_phys) {
		return FALSE;
	}
	if (ptoa(last) < vm_first_phys) {
		return FALSE;
	}

	return TRUE;
}

/*
 * The state maintained by the noencrypt functions is used as a
 * debugging aid on ARM.  This incurs some overhead on the part
 * of the caller.  A special case check in phys_attribute_clear
 * (the most expensive path) currently minimizes this overhead,
 * but stubbing these functions out on RELEASE kernels yields
 * further wins.
 */
boolean_t
pmap_is_noencrypt(
	ppnum_t pn)
{
#if DEVELOPMENT || DEBUG
	boolean_t result = FALSE;

	if (!pa_valid(ptoa(pn))) {
		return FALSE;
	}

	result = (phys_attribute_test(pn, PP_ATTR_NOENCRYPT));

	return result;
#else
#pragma unused(pn)
	return FALSE;
#endif
}

void
pmap_set_noencrypt(
	ppnum_t pn)
{
#if DEVELOPMENT || DEBUG
	if (!pa_valid(ptoa(pn))) {
		return;
	}

	phys_attribute_set(pn, PP_ATTR_NOENCRYPT);
#else
#pragma unused(pn)
#endif
}

void
pmap_clear_noencrypt(
	ppnum_t pn)
{
#if DEVELOPMENT || DEBUG
	if (!pa_valid(ptoa(pn))) {
		return;
	}

	phys_attribute_clear(pn, PP_ATTR_NOENCRYPT, 0, NULL);
#else
#pragma unused(pn)
#endif
}

void
pmap_lock_phys_page(ppnum_t pn)
{
	unsigned int    pai;
	pmap_paddr_t    phys = ptoa(pn);

	if (pa_valid(phys)) {
		pai = pa_index(phys);
		__unused const locked_pvh_t locked_pvh = pvh_lock(pai);
	} else {
		simple_lock(&phys_backup_lock, LCK_GRP_NULL);
	}
}


void
pmap_unlock_phys_page(ppnum_t pn)
{
	unsigned int    pai;
	pmap_paddr_t    phys = ptoa(pn);

	if (pa_valid(phys)) {
		pai = pa_index(phys);
		locked_pvh_t locked_pvh = {.pvh = pai_to_pvh(pai), .pai = pai};
		pvh_unlock(&locked_pvh);
	} else {
		simple_unlock(&phys_backup_lock);
	}
}

MARK_AS_PMAP_TEXT void
pmap_clear_user_ttb_internal(void)
{
	set_mmu_ttb(invalid_ttep & TTBR_BADDR_MASK);
}

void
pmap_clear_user_ttb(void)
{
	PMAP_TRACE(3, PMAP_CODE(PMAP__CLEAR_USER_TTB) | DBG_FUNC_START, NULL, 0, 0);
	pmap_clear_user_ttb_internal();
	PMAP_TRACE(3, PMAP_CODE(PMAP__CLEAR_USER_TTB) | DBG_FUNC_END);
}

/**
 * Set up a "fast fault", or a page fault that won't go through the VM layer on
 * a page. This is primarily used to manage ref/mod bits in software. Depending
 * on the value of allow_mode, the next read and/or write of the page will fault
 * and the ref/mod bits will be updated.
 *
 * @param ppnum Page number to set up a fast fault on.
 * @param allow_mode VM_PROT_NONE will cause the next read and write access to
 *                   fault.
 *                   VM_PROT_READ will only cause the next write access to fault.
 *                   Other values are undefined.
 * @param options PMAP_OPTIONS_NOFLUSH indicates TLBI flush is not needed.
 *                PMAP_OPTIONS_FF_WIRED forces a fast fault even on wired pages.
 *                PMAP_OPTIONS_SET_REUSABLE/PMAP_OPTIONS_CLEAR_REUSABLE updates
 *                the global reusable bit of the page.
 * @param locked_pvh If non-NULL, this indicates the PVH lock for [ppnum] is already locked
 *                   by the caller.  This is an input/output parameter which may be updated
 *                   to reflect a new PV head value to be passed to a later call to pvh_unlock().
 * @param bits_to_clear Mask of additional pp_attr_t bits to clear for the physical
 *                      page, iff this function completes successfully and returns
 *                      TRUE.  This is typically some combination of
 *                      the referenced, modified, and noencrypt bits.
 * @param flush_range When present, this function will skip the TLB flush for the
 *                    mappings that are covered by the range, leaving that to be
 *                    done later by the caller.  It may also avoid submitting mapping
 *                    updates directly to the SPTM, instead accumulating them in a
 *                    per-CPU array to be submitted later by the caller.
 *
 * @return TRUE if the fast fault was successfully configured for all mappings
 *         of the page, FALSE otherwise (e.g. if wired mappings are present and
 *         PMAP_OPTIONS_FF_WIRED was not passed).
 *
 * @note PMAP_OPTIONS_NOFLUSH and flush_range cannot both be specified.
 *
 * @warning PMAP_OPTIONS_FF_WIRED should only be used with pages accessible from
 *          EL0.  The kernel may assume that accesses to wired, kernel-owned pages
 *          won't fault.
 */
MARK_AS_PMAP_TEXT static boolean_t
arm_force_fast_fault_with_flush_range(
	ppnum_t         ppnum,
	vm_prot_t       allow_mode,
	int             options,
	locked_pvh_t   *locked_pvh,
	pp_attr_t       bits_to_clear,
	pmap_tlb_flush_range_t *flush_range)
{
	pmap_paddr_t     phys = ptoa(ppnum);
	pv_entry_t      *pve_p;
	pt_entry_t      *pte_p;
	unsigned int     pai;
	boolean_t        result;
	unsigned int     num_mappings = 0;
	bool             ref_fault;
	bool             mod_fault;
	bool             clear_write_fault = false;
	bool             ref_aliases_mod = false;

	assert(ppnum != vm_page_fictitious_addr);

	/**
	 * Assert that PMAP_OPTIONS_NOFLUSH and flush_range cannot both be specified.
	 *
	 * PMAP_OPTIONS_NOFLUSH indicates there is no need of flushing the TLB in the entire operation, and
	 * flush_range indicates the caller requests deferral of the TLB flushing. Fundemantally, the two
	 * semantics conflict with each other, so assert they are not both true.
	 */
	assert(!(flush_range && (options & PMAP_OPTIONS_NOFLUSH)));

	if (!pa_valid(phys)) {
		return FALSE;   /* Not a managed page. */
	}

	result = TRUE;
	ref_fault = false;
	mod_fault = false;
	pai = pa_index(phys);
	locked_pvh_t local_locked_pvh = {.pvh = 0};
	if (__probable(locked_pvh == NULL)) {
		if (flush_range != NULL) {
			/**
			 * If we're partway through processing a multi-page batched call,
			 * preemption will already be disabled so we can't simply call
			 * pvh_lock() which may block.  Instead, we first try to acquire
			 * the lock without waiting, which in most cases should succeed.
			 * If it fails, we submit the pending batched operations to re-
			 * enable preemption and then acquire the lock normally.
			 */
			local_locked_pvh = pvh_try_lock(pai);
			if (__improbable(!pvh_try_lock_success(&local_locked_pvh))) {
				pmap_multipage_op_submit(flush_range);
				local_locked_pvh = pvh_lock(pai);
			}
		} else {
			local_locked_pvh = pvh_lock(pai);
		}
	} else {
		local_locked_pvh = *locked_pvh;
	}
	assert(local_locked_pvh.pvh != 0);
	pvh_assert_locked(pai);

	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	if (pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(local_locked_pvh.pvh);
	} else if (pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_PVEP)) {
		pve_p = pvh_pve_list(local_locked_pvh.pvh);
	} else if (__improbable(!pvh_test_type(local_locked_pvh.pvh, PVH_TYPE_NULL))) {
		panic("%s: invalid PV head 0x%llx for PA 0x%llx", __func__, (uint64_t)local_locked_pvh.pvh, (uint64_t)phys);
	}

	const bool is_reusable = ppattr_test_reusable(pai);

	bool pvh_lock_sleep_mode_needed = false;
	pmap_sptm_percpu_data_t *sptm_pcpu = NULL;
	sptm_disjoint_op_t *sptm_ops = NULL;

	/**
	 * This would also work as a block, with the above variables declared using the
	 * __block qualifier, but the extra runtime overhead of block syntax (e.g.
	 * dereferencing __block variables through stack forwarding pointers) isn't needed
	 * here, as we never need to use this code sequence as a closure.
	 */
	#define FFF_PERCPU_INIT() do { \
	        disable_preemption(); \
	        sptm_pcpu = PERCPU_GET(pmap_sptm_percpu); \
	        sptm_ops = sptm_pcpu->sptm_ops; \
	} while (0)

	FFF_PERCPU_INIT();

	int pve_ptep_idx = 0;

	/**
	 * With regard to TLBI, there are three cases:
	 *
	 * 1. PMAP_OPTIONS_NOFLUSH is specified. In such case, SPTM doesn't need to flush TLB and neither does pmap.
	 * 2. PMAP_OPTIONS_NOFLUSH is not specified, but flush_range is, indicating the caller intends to flush TLB
	 *    itself (with range TLBI). In such case, we check the flush_range limits and only issue the TLBI if a
	 *    mapping is out of the range.
	 * 3. Neither PMAP_OPTIONS_NOFLUSH nor a valid flush_range pointer is specified. In such case, we should just
	 *    let SPTM handle TLBI flushing.
	 */
	const bool defer_tlbi = (options & PMAP_OPTIONS_NOFLUSH) || flush_range;
	const uint32_t sptm_update_options = SPTM_UPDATE_PERMS_AND_WAS_WRITABLE | SPTM_UPDATE_AF | (defer_tlbi ? SPTM_UPDATE_DEFER_TLBI : 0);

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		pt_entry_t       spte;
		pt_entry_t       tmplate;

		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto fff_skip_pve;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto fff_skip_pve;
		}
#endif
		spte = os_atomic_load(pte_p, relaxed);
		if (pte_is_compressed(spte, pte_p)) {
			panic("pte is COMPRESSED: pte_p=%p ppnum=0x%x", pte_p, ppnum);
		}

		pt_desc_t *ptdp = NULL;
		pmap_t pmap = NULL;
		vm_map_address_t va = 0;

		if ((flush_range != NULL) && (pte_p == flush_range->current_ptep)) {
			/**
			 * If the current mapping matches the flush range's current iteration position,
			 * there's no need to do the work of getting the PTD.  We already know the pmap,
			 * and the VA is implied by flush_range->pending_region_start.
			 */
			pmap = flush_range->ptfr_pmap;
		} else {
			ptdp = ptep_get_ptd(pte_p);
			pmap = ptdp->pmap;
			va = ptd_get_va(ptdp, pte_p);
			assert(va >= pmap->min && va < pmap->max);
		}

		const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

		/* update pmap stats and ledgers */
		const bool is_internal = ppattr_pve_is_internal(pai, pve_p, pve_ptep_idx);
		const bool is_altacct = ppattr_pve_is_altacct(pai, pve_p, pve_ptep_idx);
		if (is_altacct) {
			/*
			 * We do not track "reusable" status for
			 * "alternate accounting" mappings.
			 */
		} else if ((options & PMAP_OPTIONS_CLEAR_REUSABLE) &&
		    is_reusable &&
		    is_internal &&
		    pmap != kernel_pmap) {
			/* one less "reusable" */
			pmap_ledger_debit(pmap, task_ledgers.reusable, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			/* one more "internal" */
			pmap_ledger_credit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			pmap_ledger_credit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);

			/*
			 * Since the page is being marked non-reusable, we assume that it will be
			 * modified soon.  Avoid the cost of another trap to handle the fast
			 * fault when we next write to this page.
			 */
			clear_write_fault = true;
		} else if ((options & PMAP_OPTIONS_SET_REUSABLE) &&
		    !is_reusable &&
		    is_internal &&
		    pmap != kernel_pmap) {
			/* one more "reusable" */
			pmap_ledger_credit(pmap, task_ledgers.reusable, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			pmap_ledger_debit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			pmap_ledger_debit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);
		}

		// A concurrent pmap_remove() may have cleared the PTE
		if (__improbable((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT)) {
			goto fff_skip_pve;
		}

		bool wiredskip = pte_is_wired(spte) &&
		    ((options & PMAP_OPTIONS_FF_WIRED) == 0);

		if (wiredskip) {
			result = FALSE;
			goto fff_skip_pve;
		}

		if (__improbable(pvh_lock_sleep_mode_needed)) {
			/**
			 * Undo the explicit preemption disable done in the last call to FFF_PER_CPU_INIT().
			 * If the PVH lock is placed in sleep mode, we can't rely on it to disable preemption,
			 * so we need these explicit preemption twiddles to ensure we don't get migrated off-
			 * core while processing SPTM per-CPU data.  At the same time, we also want preemption
			 * to briefly be re-enabled every SPTM_MAPPING_LIMIT mappings so that any pending
			 * urgent ASTs can be handled.
			 */
			enable_preemption();
			pvh_lock_enter_sleep_mode(&local_locked_pvh);
			pvh_lock_sleep_mode_needed = false;
			FFF_PERCPU_INIT();
		}

		tmplate = spte;

		if ((allow_mode & VM_PROT_READ) != VM_PROT_READ) {
			/* read protection sets the pte to fault */
			tmplate =  tmplate & ~ARM_PTE_AF;
			ref_fault = true;
		}
		if ((allow_mode & VM_PROT_WRITE) != VM_PROT_WRITE) {
			/* take away write permission if set */
			if (pmap == kernel_pmap) {
				if ((tmplate & ARM_PTE_APMASK) == ARM_PTE_AP(AP_RWNA)) {
					tmplate = ((tmplate & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
					pte_set_was_writeable(tmplate, true);
					mod_fault = true;
				}
			} else {
				if ((tmplate & ARM_PTE_APMASK) == pt_attr_leaf_rw(pt_attr)) {
					tmplate = ((tmplate & ~ARM_PTE_APMASK) | pt_attr_leaf_ro(pt_attr));
					pte_set_was_writeable(tmplate, true);
					mod_fault = true;
				}
			}
		}

		if (ptdp != NULL) {
			/**
			 * If the PTD is NULL, we're adding the current mapping to the pending region templates instead of the
			 * pending disjoint ops, so we don't need to do flush range disjoint op management.
			 */
			if (flush_range != NULL) {
				/**
				 * Insert a "header" entry for this physical page into the SPTM disjoint ops array.
				 * We do this in three cases:
				 * 1) We're at the beginning of the SPTM ops array (num_mappings == 0, flush_range->pending_disjoint_entries == 0).
				 * 2) We may not be at the beginning of the SPTM ops array, but we are about to add the first operation
				 *    for this physical page (num_mappings == 0, flush_range->pending_disjoint_entries == ?).
				 * 3) We need to change the options passed to the SPTM for a run of one or more mappings.  Specifically,
				 *    if we encounter a run of mappings that reside outside the VA region of our flush_range, or that
				 *    belong to a pmap other than the one targeted by our flush_range, we should ask the SPTM to flush
				 *    the TLB for us (i.e., clear SPTM_UPDATE_DEFER_TLBI), but only for those specific mappings.
				 */
				uint32_t per_mapping_sptm_update_options = sptm_update_options;
				if ((flush_range->ptfr_pmap != pmap) || (va >= flush_range->ptfr_end) || (va < flush_range->ptfr_start)) {
					per_mapping_sptm_update_options &= ~SPTM_UPDATE_DEFER_TLBI;
				}
				if ((num_mappings == 0) ||
				    (flush_range->current_header->per_paddr_header.options != per_mapping_sptm_update_options)) {
					num_mappings = pmap_multipage_op_add_page(phys, num_mappings, per_mapping_sptm_update_options, flush_range);
				}
			}

			sptm_ops[num_mappings].root_pt_paddr = pmap->ttep;
			sptm_ops[num_mappings].vaddr = va;
			sptm_ops[num_mappings].pte_template = tmplate;

			++num_mappings;

			if (num_mappings == SPTM_MAPPING_LIMIT) {
				if (flush_range == NULL) {
					sptm_update_disjoint(phys, sptm_pcpu->sptm_ops_pa, num_mappings, sptm_update_options);
				} else {
					/**
					 * We submit both the pending disjoint and pending region ops whenever
					 * either category reaches the mapping limit.  Having pending operations
					 * in either category will keep preemption disabled, and we want to ensure
					 * that we can at least temporarily re-enable preemption every
					 * SPTM_MAPPING_LIMIT mappings.
					 */
					pmap_multipage_op_submit_disjoint(num_mappings, flush_range);
					pmap_multipage_op_submit_region(flush_range);
				}
				pvh_lock_sleep_mode_needed = true;
				num_mappings = 0;
			}
		} else if (pmap_insert_flush_range_template(tmplate, flush_range)) {
			/* See comment above for why we also submit pending disjoint ops when we hit the region limit. */
			pmap_multipage_op_submit_disjoint(num_mappings, flush_range);
			pvh_lock_sleep_mode_needed = true;
			num_mappings = 0;
		}
fff_skip_pve:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}

	if (num_mappings != 0) {
		sptm_return_t sptm_ret;

		if (flush_range == NULL) {
			sptm_ret = sptm_update_disjoint(phys, sptm_pcpu->sptm_ops_pa, num_mappings, sptm_update_options);
		} else {
			/* Resync the pending mapping state in flush_range with our local state. */
			assert(num_mappings >= flush_range->pending_disjoint_entries);
			flush_range->pending_disjoint_entries = num_mappings;
		}
	}

	/**
	 * Undo the explicit disable_preemption() done in FFF_PERCPU_INIT().
	 * Note that enable_preemption() decrements a per-thread counter, so if
	 * we happen to still hold the PVH lock in spin mode then preemption won't
	 * actually be re-enabled until we drop the lock (which also decrements
	 * the per-thread counter.
	 */
	enable_preemption();

	/*
	 * If we are using the same approach for ref and mod
	 * faults on this PTE, do not clear the write fault;
	 * this would cause both ref and mod to be set on the
	 * page again, and prevent us from taking ANY read/write
	 * fault on the mapping.
	 */
	if (clear_write_fault && !ref_aliases_mod) {
		arm_clear_fast_fault(ppnum, VM_PROT_WRITE, local_locked_pvh.pvh, PT_ENTRY_NULL, 0);
	}

	pp_attr_t attrs_to_clear = (result ? bits_to_clear : 0);
	pp_attr_t attrs_to_set = 0;
	/* update global "reusable" status for this page */
	if ((options & PMAP_OPTIONS_CLEAR_REUSABLE) && is_reusable) {
		attrs_to_clear |= PP_ATTR_REUSABLE;
	} else if ((options & PMAP_OPTIONS_SET_REUSABLE) && !is_reusable) {
		attrs_to_set |= PP_ATTR_REUSABLE;
	}

	if (mod_fault) {
		attrs_to_set |= PP_ATTR_MODFAULT;
	}
	if (ref_fault) {
		attrs_to_set |= PP_ATTR_REFFAULT;
	}

	if (attrs_to_set | attrs_to_clear) {
		ppattr_modify_bits(pai, attrs_to_clear, attrs_to_set);
	}

	if (__probable(locked_pvh == NULL)) {
		pvh_unlock(&local_locked_pvh);
	} else {
		*locked_pvh = local_locked_pvh;
	}
	return result;
}

MARK_AS_PMAP_TEXT boolean_t
arm_force_fast_fault_internal(
	ppnum_t         ppnum,
	vm_prot_t       allow_mode,
	int             options)
{
	if (__improbable((options & (PMAP_OPTIONS_FF_LOCKED | PMAP_OPTIONS_FF_WIRED | PMAP_OPTIONS_NOFLUSH)) != 0)) {
		panic("arm_force_fast_fault(0x%x, 0x%x, 0x%x): invalid options", ppnum, allow_mode, options);
	}
	return arm_force_fast_fault_with_flush_range(ppnum, allow_mode, options, NULL, 0, NULL);
}

/*
 *	Routine:	arm_force_fast_fault
 *
 *	Function:
 *		Force all mappings for this page to fault according
 *		to the access modes allowed, so we can gather ref/modify
 *		bits again.
 */

boolean_t
arm_force_fast_fault(
	ppnum_t         ppnum,
	vm_prot_t       allow_mode,
	int             options,
	__unused void   *arg)
{
	pmap_paddr_t    phys = ptoa(ppnum);

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(phys)) {
		return FALSE;   /* Not a managed page. */
	}

	return arm_force_fast_fault_internal(ppnum, allow_mode, options);
}

/**
 * Clear pending force fault for at most SPTM_MAPPING_LIMIT mappings for this
 * page based on the observed fault type, and update the appropriate ref/modify
 * bits for the physical page. This typically involves adding write permissions
 * back for write faults and setting the Access Flag for both read/write faults
 * (since the lack of those things is what caused the fault in the first place).
 *
 * @note Only SPTM_MAPPING_LIMIT number of mappings can be modified in a single
 *       arm_clear_fast_fault() call to prevent excessive PVH lock contention as
 *       the PVH lock should be held for `ppnum` already. If a fault is
 *       subsequently taken on a mapping we haven't processed, arm_fast_fault()
 *       will call this function with a non-NULL pte_p to perform a targeted
 *       fixup.
 *
 * @param ppnum Page number of the page to clear a pending force fault on.
 * @param fault_type The type of access/fault that triggered us wanting to clear
 *                   the pending force fault status. This determines how we
 *                   modify the PTE to not cause a fault in the future and also
 *                   whether we mark the PTE as referenced or modified.
 *                   Typically a write fault would cause the page to be marked
 *                   as referenced and modified, and a read fault would only
 *                   cause the page to be marked as referenced.
 * @param pvh pv_head_table entry value for [ppnum] returned by a previous call
 *            to pvh_lock().
 * @param pte_p If this value is non-PT_ENTRY_NULL then only this specified PTE
 *              will be modified. If it is PT_ENTRY_NULL, then every mapping to
 *              `ppnum` will be modified.
 * @param attrs_to_clear Mask of additional pp_attr_t bits to clear for the physical
 *                       page upon completion of this function.  This is typically
 *                       some combination of the REFFAULT and MODFAULT bits.
 *
 * @return TRUE if any PTEs were modified, FALSE otherwise.
 */
MARK_AS_PMAP_TEXT static boolean_t
arm_clear_fast_fault(
	ppnum_t ppnum,
	vm_prot_t fault_type,
	uintptr_t pvh,
	pt_entry_t *pte_p,
	pp_attr_t attrs_to_clear)
{
	const pmap_paddr_t pa = ptoa(ppnum);
	pv_entry_t     *pve_p;
	boolean_t       result;
	unsigned int    num_mappings = 0;
	pp_attr_t       attrs_to_set = 0;

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(pa)) {
		return FALSE;   /* Not a managed page. */
	}

	result = FALSE;
	pve_p = PV_ENTRY_NULL;
	if (pte_p == PT_ENTRY_NULL) {
		if (pvh_test_type(pvh, PVH_TYPE_PTEP)) {
			pte_p = pvh_ptep(pvh);
		} else if (pvh_test_type(pvh, PVH_TYPE_PVEP)) {
			pve_p = pvh_pve_list(pvh);
		} else if (__improbable(!pvh_test_type(pvh, PVH_TYPE_NULL))) {
			panic("%s: invalid PV head 0x%llx for PA 0x%llx", __func__, (uint64_t)pvh, (uint64_t)pa);
		}
	}

	disable_preemption();
	pmap_sptm_percpu_data_t *sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
	sptm_disjoint_op_t *sptm_ops = sptm_pcpu->sptm_ops;

	int pve_ptep_idx = 0;

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		pt_entry_t spte;
		pt_entry_t tmplate;

		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto cff_skip_pve;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto cff_skip_pve;
		}
#endif
		spte = os_atomic_load(pte_p, relaxed);
		// A concurrent pmap_remove() may have cleared the PTE
		if (__improbable((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT)) {
			goto cff_skip_pve;
		}

		const pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		const vm_map_address_t va = ptd_get_va(ptdp, pte_p);

		assert(va >= pmap->min && va < pmap->max);

		tmplate = spte;

		if ((fault_type & VM_PROT_WRITE) && (pte_was_writeable(spte))) {
			{
				if (pmap == kernel_pmap) {
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RWNA));
				} else {
					assert(pmap->type != PMAP_TYPE_NESTED);
					tmplate = ((spte & ~ARM_PTE_APMASK) | pt_attr_leaf_rw(pmap_get_pt_attr(pmap)));
				}
			}

			tmplate |= ARM_PTE_AF;

			pte_set_was_writeable(tmplate, false);
			attrs_to_set |= (PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
		} else if ((fault_type & VM_PROT_READ) && ((spte & ARM_PTE_AF) != ARM_PTE_AF)) {
			tmplate = spte | ARM_PTE_AF;

			{
				attrs_to_set |= PP_ATTR_REFERENCED;
			}
		}

		assert(spte != ARM_PTE_TYPE_FAULT);

		if (spte != tmplate) {
			sptm_ops[num_mappings].root_pt_paddr = pmap->ttep;
			sptm_ops[num_mappings].vaddr = va;
			sptm_ops[num_mappings].pte_template = tmplate;
			++num_mappings;
			result = TRUE;
		}

		if (num_mappings == SPTM_MAPPING_LIMIT) {
			sptm_update_disjoint(pa, sptm_pcpu->sptm_ops_pa, num_mappings,
			    SPTM_UPDATE_PERMS_AND_WAS_WRITABLE | SPTM_UPDATE_AF);
			num_mappings = 0;
			/*
			 * We've reached the limit of mappings that can be processed in a single arm_clear_fast_fault()
			 * call.  Bail out here to avoid excessive PVH lock duration on the fault path.  If a fault is
			 * subsequently taken on a mapping we haven't processed, arm_fast_fault() will call this
			 * function with a non-NULL pte_p to perform a targeted fixup.
			 */
			break;
		}

cff_skip_pve:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}

	if (num_mappings != 0) {
		assert(result == TRUE);
		sptm_update_disjoint(pa, sptm_pcpu->sptm_ops_pa, num_mappings,
		    SPTM_UPDATE_PERMS_AND_WAS_WRITABLE | SPTM_UPDATE_AF);
	}

	if (attrs_to_set | attrs_to_clear) {
		ppattr_modify_bits(pa_index(pa), attrs_to_clear, attrs_to_set);
	}
	enable_preemption();

	return result;
}

/*
 * Determine if the fault was induced by software tracking of
 * modify/reference bits.  If so, re-enable the mapping (and set
 * the appropriate bits).
 *
 * Returns KERN_SUCCESS if the fault was induced and was
 * successfully handled.
 *
 * Returns KERN_FAILURE if the fault was not induced and
 * the function was unable to deal with it.
 *
 * Returns KERN_PROTECTION_FAILURE if the pmap layer explictly
 * disallows this type of access.
 */
MARK_AS_PMAP_TEXT kern_return_t
arm_fast_fault_internal(
	pmap_t pmap,
	vm_map_address_t va,
	vm_prot_t fault_type,
	__unused bool was_af_fault,
	__unused bool from_user)
{
	kern_return_t   result = KERN_FAILURE;
	pt_entry_t     *ptep;
	pt_entry_t      spte = ARM_PTE_TYPE_FAULT;
	locked_pvh_t    locked_pvh = {.pvh = 0};
	unsigned int    pai;
	pmap_paddr_t    pa;
	validate_pmap_mutable(pmap);

	if (__probable(preemption_enabled())) {
		pmap_lock(pmap, PMAP_LOCK_SHARED);
	} else if (__improbable(!pmap_try_lock(pmap, PMAP_LOCK_SHARED))) {
		/**
		 * In certain cases, arm_fast_fault() may be invoked with preemption disabled
		 * on the copyio path.  In theses cases the (in-kernel) caller expects that any
		 * faults taken against the user address may not be handled successfully
		 * (vm_fault() allows non-preemptible callers with the possibility that the
		 * fault may not be successfully handled) and will result in the copyio operation
		 * returning EFAULT.  It is then the caller's responsibility to retry the copyio
		 * operation in a preemptible context.
		 *
		 * For these cases attempting to acquire the sleepable lock will panic, so
		 * we simply make a best effort and return failure just as the VM does if we
		 * can't acquire the lock without sleeping.
		 */
		return result;
	}

	/*
	 * If the entry doesn't exist, is completely invalid, or is already
	 * valid, we can't fix it here.
	 */

	const uint64_t pmap_page_size = pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO;
	ptep = pmap_pte(pmap, va & ~(pmap_page_size - 1));
	if (ptep != PT_ENTRY_NULL) {
		while (true) {
			spte = os_atomic_load(ptep, relaxed);

			pa = pte_to_pa(spte);

			if ((spte == ARM_PTE_TYPE_FAULT) ||
			    pte_is_compressed(spte, ptep)) {
				pmap_unlock(pmap, PMAP_LOCK_SHARED);
				return result;
			}

			if (!pa_valid(pa)) {
				const sptm_frame_type_t frame_type = sptm_get_frame_type(pa);
				if (frame_type == XNU_PROTECTED_IO) {
					result = KERN_PROTECTION_FAILURE;
				}
				pmap_unlock(pmap, PMAP_LOCK_SHARED);
				return result;
			}
			pai = pa_index(pa);
			/**
			 * Check for preemption disablement and in that case use pvh_try_lock()
			 * for the same reason we use pmap_try_lock() above.
			 */
			if (__probable(preemption_enabled())) {
				locked_pvh = pvh_lock(pai);
			} else {
				locked_pvh = pvh_try_lock(pai);
				if (__improbable(!pvh_try_lock_success(&locked_pvh))) {
					pmap_unlock(pmap, PMAP_LOCK_SHARED);
					return result;
				}
			}
			assert(locked_pvh.pvh != 0);
			if (os_atomic_load(ptep, relaxed) == spte) {
				/*
				 * Double-check the spte value, as we care about the AF bit.
				 * It's also possible that pmap_page_protect() transitioned the
				 * PTE to compressed/empty before we grabbed the PVH lock.
				 */
				break;
			}
			pvh_unlock(&locked_pvh);
		}
	} else {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
		return result;
	}


	if (result == KERN_SUCCESS) {
		goto ff_cleanup;
	}

	pp_attr_t attrs = os_atomic_load(&pp_attr_table[pai], relaxed);
	if ((attrs & PP_ATTR_REFFAULT) || ((fault_type & VM_PROT_WRITE) && (attrs & PP_ATTR_MODFAULT))) {
		/*
		 * An attempted access will always clear ref/mod fault state, as
		 * appropriate for the fault type.  arm_clear_fast_fault will
		 * update the associated PTEs for the page as appropriate; if
		 * any PTEs are updated, we redrive the access.  If the mapping
		 * does not actually allow for the attempted access, the
		 * following fault will (hopefully) fail to update any PTEs, and
		 * thus cause arm_fast_fault to decide that it failed to handle
		 * the fault.
		 */
		pp_attr_t attrs_to_clear = 0;
		if (attrs & PP_ATTR_REFFAULT) {
			attrs_to_clear |= PP_ATTR_REFFAULT;
		}
		if ((fault_type & VM_PROT_WRITE) && (attrs & PP_ATTR_MODFAULT)) {
			attrs_to_clear |= PP_ATTR_MODFAULT;
		}

		if (arm_clear_fast_fault((ppnum_t)atop(pa), fault_type, locked_pvh.pvh, PT_ENTRY_NULL, attrs_to_clear)) {
			/*
			 * Should this preserve KERN_PROTECTION_FAILURE?  The
			 * cost of not doing so is a another fault in a case
			 * that should already result in an exception.
			 */
			result = KERN_SUCCESS;
		}
	}

	/*
	 * If the PTE already has sufficient permissions, we can report the fault as handled.
	 * This may happen, for example, if multiple threads trigger roughly simultaneous faults
	 * on mappings of the same page
	 */
	if ((result == KERN_FAILURE) && (spte & ARM_PTE_AF)) {
		uintptr_t ap_ro, ap_rw, ap_x;
		if (pmap == kernel_pmap) {
			ap_ro = ARM_PTE_AP(AP_RONA);
			ap_rw = ARM_PTE_AP(AP_RWNA);
			ap_x = ARM_PTE_NX;
		} else {
			ap_ro = pt_attr_leaf_ro(pmap_get_pt_attr(pmap));
			ap_rw = pt_attr_leaf_rw(pmap_get_pt_attr(pmap));
			ap_x = pt_attr_leaf_x(pmap_get_pt_attr(pmap));
		}
		/*
		 * NOTE: this doesn't currently handle user-XO mappings. Depending upon the
		 * hardware they may be xPRR-protected, in which case they'll be handled
		 * by the is_pte_xprr_protected() case above.  Additionally, the exception
		 * handling path currently does not call arm_fast_fault() without at least
		 * VM_PROT_READ in fault_type.
		 */
		if (((spte & ARM_PTE_APMASK) == ap_rw) ||
		    (!(fault_type & VM_PROT_WRITE) && ((spte & ARM_PTE_APMASK) == ap_ro))) {
			if (!(fault_type & VM_PROT_EXECUTE) || ((spte & ARM_PTE_XMASK) == ap_x)) {
				result = KERN_SUCCESS;
			}
		}
	}

	if ((result == KERN_FAILURE) && arm_clear_fast_fault((ppnum_t)atop(pa), fault_type, locked_pvh.pvh, ptep, 0)) {
		/*
		 * A prior arm_clear_fast_fault() operation may have returned early due to
		 * another pending PV list operation or an excessively large PV list.
		 * Attempt a targeted fixup of the PTE that caused the fault to avoid repeatedly
		 * taking a fault on the same mapping.
		 */
		result = KERN_SUCCESS;
	}

ff_cleanup:

	pvh_unlock(&locked_pvh);
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
	return result;
}

kern_return_t
arm_fast_fault(
	pmap_t pmap,
	vm_map_address_t va,
	vm_prot_t fault_type,
	bool was_af_fault,
	__unused bool from_user)
{
	kern_return_t   result = KERN_FAILURE;

	if (va < pmap->min || va >= pmap->max) {
		return result;
	}

	PMAP_TRACE(3, PMAP_CODE(PMAP__FAST_FAULT) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(va), fault_type,
	    from_user);


	result = arm_fast_fault_internal(pmap, va, fault_type, was_af_fault, from_user);

	PMAP_TRACE(3, PMAP_CODE(PMAP__FAST_FAULT) | DBG_FUNC_END, result);

	return result;
}

void
pmap_copy_page(
	ppnum_t psrc,
	ppnum_t pdst)
{
	bcopy_phys((addr64_t) (ptoa(psrc)),
	    (addr64_t) (ptoa(pdst)),
	    PAGE_SIZE);
}


/*
 *	pmap_copy_page copies the specified (machine independent) pages.
 */
void
pmap_copy_part_page(
	ppnum_t psrc,
	vm_offset_t src_offset,
	ppnum_t pdst,
	vm_offset_t dst_offset,
	vm_size_t len)
{
	bcopy_phys((addr64_t) (ptoa(psrc) + src_offset),
	    (addr64_t) (ptoa(pdst) + dst_offset),
	    len);
}


/*
 *	pmap_zero_page zeros the specified (machine independent) page.
 */
void
pmap_zero_page(
	ppnum_t pn)
{
	assert(pn != vm_page_fictitious_addr);
	bzero_phys((addr64_t) ptoa(pn), PAGE_SIZE);
}

/*
 *	pmap_zero_part_page
 *	zeros the specified (machine independent) part of a page.
 */
void
pmap_zero_part_page(
	ppnum_t pn,
	vm_offset_t offset,
	vm_size_t len)
{
	assert(pn != vm_page_fictitious_addr);
	assert(offset + len <= PAGE_SIZE);
	bzero_phys((addr64_t) (ptoa(pn) + offset), len);
}

void
pmap_map_globals(
	void)
{
	pt_entry_t      pte;

	pte = pa_to_pte(kvtophys_nofail((vm_offset_t)&lowGlo)) | AP_RONA | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_AF | ARM_PTE_TYPE;
#if __ARM_KERNEL_PROTECT__
	pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
	pte |= ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK);
	pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
	sptm_map_page(kernel_pmap->ttep, LOWGLOBAL_ALIAS, pte);

#if KASAN
	kasan_notify_address(LOWGLOBAL_ALIAS, PAGE_SIZE);
#endif
}

vm_offset_t
pmap_cpu_windows_copy_addr(int cpu_num, unsigned int index)
{
	if (__improbable(index >= CPUWINDOWS_MAX)) {
		panic("%s: invalid index %u", __func__, index);
	}
	return (vm_offset_t)(CPUWINDOWS_BASE + (PAGE_SIZE * ((CPUWINDOWS_MAX * cpu_num) + index)));
}

MARK_AS_PMAP_TEXT unsigned int
pmap_map_cpu_windows_copy_internal(
	ppnum_t pn,
	vm_prot_t prot,
	unsigned int wimg_bits)
{
	pt_entry_t      *ptep = NULL, pte;
	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();
	unsigned int    cpu_num;
	unsigned int    cpu_window_index;
	vm_offset_t     cpu_copywindow_vaddr = 0;
	bool            need_strong_sync = false;

	assert(get_preemption_level() > 0);
	cpu_num = pmap_cpu_data->cpu_number;

	for (cpu_window_index = 0; cpu_window_index < CPUWINDOWS_MAX; cpu_window_index++) {
		cpu_copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_num, cpu_window_index);
		ptep = pmap_pte(kernel_pmap, cpu_copywindow_vaddr);
		assert(!pte_is_compressed(*ptep, ptep));
		if (*ptep == ARM_PTE_TYPE_FAULT) {
			break;
		}
	}
	if (__improbable(cpu_window_index == CPUWINDOWS_MAX)) {
		panic("%s: out of windows", __func__);
	}

	pte = pa_to_pte(ptoa(pn)) | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_NX | ARM_PTE_PNX;
#if __ARM_KERNEL_PROTECT__
	pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
	pte |= wimg_to_pte(wimg_bits, ptoa(pn));

	if (prot & VM_PROT_WRITE) {
		pte |= ARM_PTE_AP(AP_RWNA);
	} else {
		pte |= ARM_PTE_AP(AP_RONA);
	}

	/*
	 * It's expected to be safe for an interrupt handler to nest copy-window usage with the
	 * active thread on a CPU, as long as a sufficient number of copy windows are available.
	 * --If the interrupt handler executes before the active thread creates the per-CPU mapping,
	 *   or after the active thread completely removes the mapping, it may use the same mapping
	 *   but will finish execution and tear down the mapping without the thread needing to know.
	 * --If the interrupt handler executes after the active thread creates the per-CPU mapping,
	 *   it will observe the valid mapping and use a different copy window.
	 * --If the interrupt handler executes after the active thread clears the PTE in
	 *   pmap_unmap_cpu_windows_copy() but before the active thread flushes the TLB, the code
	 *   for computing cpu_window_index above will observe the PTE_INVALID_IN_FLIGHT token set
	 *   by the SPTM, and will select a different index.
	 */
	const sptm_return_t sptm_status = sptm_map_page(kernel_pmap->ttep, cpu_copywindow_vaddr, pte);
	if (__improbable(sptm_status != SPTM_SUCCESS)) {
		panic("%s: failed to map CPU copy-window VA 0x%llx with SPTM status %d",
		    __func__, (unsigned long long)cpu_copywindow_vaddr, sptm_status);
	}

	/*
	 * Clean up any pending strong TLB flush for the same window in a thread we may have
	 * interrupted.
	 */
	if (__improbable(pmap_cpu_data->copywindow_strong_sync[cpu_window_index])) {
		arm64_sync_tlb(true);
	}
	pmap_cpu_data->copywindow_strong_sync[cpu_window_index] = need_strong_sync;

	return cpu_window_index;
}

unsigned int
pmap_map_cpu_windows_copy(
	ppnum_t pn,
	vm_prot_t prot,
	unsigned int wimg_bits)
{
	return pmap_map_cpu_windows_copy_internal(pn, prot, wimg_bits);
}

MARK_AS_PMAP_TEXT void
pmap_unmap_cpu_windows_copy_internal(
	unsigned int index)
{
	unsigned int    cpu_num;
	vm_offset_t     cpu_copywindow_vaddr = 0;
	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();

	assert(index < CPUWINDOWS_MAX);
	assert(get_preemption_level() > 0);

	cpu_num = pmap_cpu_data->cpu_number;

	cpu_copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_num, index);
	/* Issue full-system DSB to ensure prior operations on the per-CPU window
	 * (which are likely to have been on I/O memory) are complete before
	 * tearing down the mapping. */
	__builtin_arm_dsb(DSB_SY);
	sptm_unmap_region(kernel_pmap->ttep, cpu_copywindow_vaddr, 1, 0);
	if (__improbable(pmap_cpu_data->copywindow_strong_sync[index])) {
		arm64_sync_tlb(true);
		pmap_cpu_data->copywindow_strong_sync[index] = false;
	}
}

void
pmap_unmap_cpu_windows_copy(
	unsigned int index)
{
	return pmap_unmap_cpu_windows_copy_internal(index);
}

/*
 * Indicate that a pmap is intended to be used as a nested pmap
 * within one or more larger address spaces.  This must be set
 * before pmap_nest() is called with this pmap as the 'subordinate'.
 */
MARK_AS_PMAP_TEXT void
pmap_set_nested_internal(
	pmap_t pmap)
{
	validate_pmap_mutable(pmap);
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	if (__improbable(pmap->type != PMAP_TYPE_USER)) {
		panic("%s: attempt to nest unsupported pmap %p of type 0x%hhx",
		    __func__, pmap, pmap->type);
	}
	pmap->type = PMAP_TYPE_NESTED;
	sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
	retype_params.attr_idx = (pt_attr_page_size(pt_attr) == 4096) ? SPTM_PT_GEOMETRY_4K : SPTM_PT_GEOMETRY_16K;
	sptm_retype(pmap->ttep, XNU_USER_ROOT_TABLE, XNU_SHARED_ROOT_TABLE, retype_params);
	pmap_get_pt_ops(pmap)->free_id(pmap);
}

void
pmap_set_nested(
	pmap_t pmap)
{
	pmap_set_nested_internal(pmap);
}

bool
pmap_is_nested(
	pmap_t pmap)
{
	return pmap->type == PMAP_TYPE_NESTED;
}

/*
 * pmap_trim_range(pmap, start, end)
 *
 * pmap  = pmap to operate on
 * start = start of the range
 * end   = end of the range
 *
 * Attempts to deallocate TTEs for the given range in the nested range.
 */
MARK_AS_PMAP_TEXT static void
pmap_trim_range(
	pmap_t pmap,
	addr64_t start,
	addr64_t end)
{
	addr64_t cur;
	addr64_t nested_region_start;
	addr64_t nested_region_end;
	addr64_t adjusted_start;
	addr64_t adjusted_end;
	addr64_t adjust_offmask;
	tt_entry_t * tte_p;
	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if (__improbable(end < start)) {
		panic("%s: invalid address range, "
		    "pmap=%p, start=%p, end=%p",
		    __func__,
		    pmap, (void*)start, (void*)end);
	}

	nested_region_start = pmap->nested_region_addr;
	nested_region_end = nested_region_start + pmap->nested_region_size;

	if (__improbable((start < nested_region_start) || (end > nested_region_end))) {
		panic("%s: range outside nested region %p-%p, "
		    "pmap=%p, start=%p, end=%p",
		    __func__, (void *)nested_region_start, (void *)nested_region_end,
		    pmap, (void*)start, (void*)end);
	}

	/* Contract the range to TT page boundaries. */
	adjust_offmask = pt_attr_leaf_table_offmask(pt_attr);
	adjusted_start = ((start + adjust_offmask) & ~adjust_offmask);
	adjusted_end = end & ~adjust_offmask;

	/* Iterate over the range, trying to remove TTEs. */
	for (cur = adjusted_start; (cur < adjusted_end) && (cur >= adjusted_start); cur += pt_attr_twig_size(pt_attr)) {
		pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

		tte_p = pmap_tte(pmap, cur);

		if ((tte_p != NULL) && ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE)) {
			/* pmap_tte_deallocate()/pmap_tte_trim() will drop the pmap lock */
			if ((pmap->type == PMAP_TYPE_NESTED) && (sptm_get_page_table_refcnt(tte_to_pa(*tte_p)) == 0)) {
				/* Deallocate for the nested map. */
				pmap_tte_deallocate(pmap, cur, tte_p, pt_attr_twig_level(pt_attr));
			} else if (pmap->type == PMAP_TYPE_USER) {
				/**
				 * Just remove for the parent map. If the leaf table pointed
				 * to by the TTE being removed (owned by the nested pmap)
				 * has any mappings, then this call will panic. This
				 * enforces the policy that tables being trimmed must be
				 * empty to prevent possible use-after-free attacks.
				 */
				pmap_tte_trim(pmap, cur, tte_p);
			} else {
				panic("%s: Unsupported pmap type for nesting %p %d", __func__, pmap, pmap->type);
			}
		} else {
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
		}
	}

	/* Remove empty L2 TTs. */
	adjusted_start = ((start + pt_attr_ln_offmask(pt_attr, PMAP_TT_L1_LEVEL)) & ~pt_attr_ln_offmask(pt_attr, PMAP_TT_L1_LEVEL));
	adjusted_end = end & ~pt_attr_ln_offmask(pt_attr, PMAP_TT_L1_LEVEL);

	for (cur = adjusted_start; (cur < adjusted_end) && (cur >= adjusted_start);
	    cur += pt_attr_ln_size(pt_attr, PMAP_TT_L1_LEVEL)) {
		/* For each L1 entry in our range... */
		pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

		bool remove_tt1e = true;
		tt_entry_t * tt1e_p = pmap_tt1e(pmap, cur);
		tt_entry_t * tt2e_start;
		tt_entry_t * tt2e_end;
		tt_entry_t * tt2e_p;
		tt_entry_t tt1e;

		if (tt1e_p == NULL) {
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
			continue;
		}

		tt1e = *tt1e_p;

		if (tt1e == ARM_TTE_TYPE_FAULT) {
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
			continue;
		}

		tt2e_start = &((tt_entry_t*) phystokv(tt1e & ARM_TTE_TABLE_MASK))[0];
		tt2e_end = &tt2e_start[pt_attr_page_size(pt_attr) / sizeof(*tt2e_start)];

		for (tt2e_p = tt2e_start; tt2e_p < tt2e_end; tt2e_p++) {
			if (*tt2e_p != ARM_TTE_TYPE_FAULT) {
				/*
				 * If any TTEs are populated, don't remove the
				 * L1 TT.
				 */
				remove_tt1e = false;
			}
		}

		if (remove_tt1e) {
			pmap_tte_deallocate(pmap, cur, tt1e_p, PMAP_TT_L1_LEVEL);
		} else {
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
		}
	}
}

/*
 * pmap_trim_internal(grand, subord, vstart, size)
 *
 * grand  = pmap subord is nested in
 * subord = nested pmap
 * vstart = start of the used range in grand
 * size   = size of the used range
 *
 * Attempts to trim the shared region page tables down to only cover the given
 * range in subord and grand.
 */
MARK_AS_PMAP_TEXT void
pmap_trim_internal(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size)
{
	addr64_t vend;
	addr64_t adjust_offmask;

	if (__improbable(os_add_overflow(vstart, size, &vend))) {
		panic("%s: grand addr wraps around, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx",
		    __func__, grand, subord, (void*)vstart, size);
	}

	validate_pmap_mutable(grand);
	validate_pmap(subord);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(grand);

	pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);

	if (__improbable(subord->type != PMAP_TYPE_NESTED)) {
		panic("%s: subord is of non-nestable type 0x%hhx, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx",
		    __func__, subord->type, grand, subord, (void*)vstart, size);
	}

	if (__improbable(grand->type != PMAP_TYPE_USER)) {
		panic("%s: grand is of unsupprted type 0x%hhx for nesting, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx",
		    __func__, grand->type, grand, subord, (void*)vstart, size);
	}

	if (__improbable(grand->nested_pmap != subord)) {
		panic("%s: grand->nested != subord, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx",
		    __func__, grand, subord, (void*)vstart, size);
	}

	if (__improbable((size != 0) &&
	    ((vstart < grand->nested_region_addr) || (vend > (grand->nested_region_addr + grand->nested_region_size))))) {
		panic("%s: grand range not in nested region, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx",
		    __func__, grand, subord, (void*)vstart, size);
	}


	if (!grand->nested_has_no_bounds_ref) {
		assert(subord->nested_bounds_set);

		if (!grand->nested_bounds_set) {
			/* Inherit the bounds from subord. */
			grand->nested_region_true_start = subord->nested_region_true_start;
			grand->nested_region_true_end = subord->nested_region_true_end;
			grand->nested_bounds_set = true;
		}

		pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
		return;
	}

	if ((!subord->nested_bounds_set) && size) {
		adjust_offmask = pt_attr_leaf_table_offmask(pt_attr);

		subord->nested_region_true_start = vstart;
		subord->nested_region_true_end = vend;
		subord->nested_region_true_start &= ~adjust_offmask;

		if (__improbable(os_add_overflow(subord->nested_region_true_end, adjust_offmask, &subord->nested_region_true_end))) {
			panic("%s: padded true end wraps around, "
			    "grand=%p, subord=%p, vstart=%p, size=%#llx",
			    __func__, grand, subord, (void*)vstart, size);
		}

		subord->nested_region_true_end &= ~adjust_offmask;
		subord->nested_bounds_set = true;
	}

	if (subord->nested_bounds_set) {
		/* Inherit the bounds from subord. */
		grand->nested_region_true_start = subord->nested_region_true_start;
		grand->nested_region_true_end = subord->nested_region_true_end;
		grand->nested_bounds_set = true;

		/* If we know the bounds, we can trim the pmap. */
		grand->nested_has_no_bounds_ref = false;
		pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
	} else {
		/* Don't trim if we don't know the bounds. */
		pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
		return;
	}

	/* Trim grand to only cover the given range. */
	pmap_trim_range(grand, grand->nested_region_addr, grand->nested_region_true_start);
	pmap_trim_range(grand, grand->nested_region_true_end, (grand->nested_region_addr + grand->nested_region_size));

	/* Try to trim subord. */
	pmap_trim_subord(subord);
}

MARK_AS_PMAP_TEXT static void
pmap_trim_self(pmap_t pmap)
{
	if (pmap->nested_has_no_bounds_ref && pmap->nested_pmap) {
		/* If we have a no bounds ref, we need to drop it. */
		pmap_lock(pmap->nested_pmap, PMAP_LOCK_SHARED);
		pmap->nested_has_no_bounds_ref = false;
		boolean_t nested_bounds_set = pmap->nested_pmap->nested_bounds_set;
		vm_map_offset_t nested_region_true_start = pmap->nested_pmap->nested_region_true_start;
		vm_map_offset_t nested_region_true_end = pmap->nested_pmap->nested_region_true_end;
		pmap_unlock(pmap->nested_pmap, PMAP_LOCK_SHARED);

		if (nested_bounds_set) {
			pmap_trim_range(pmap, pmap->nested_region_addr, nested_region_true_start);
			pmap_trim_range(pmap, nested_region_true_end, (pmap->nested_region_addr + pmap->nested_region_size));
		}
		/*
		 * Try trimming the nested pmap, in case we had the
		 * last reference.
		 */
		pmap_trim_subord(pmap->nested_pmap);
	}
}

/*
 * pmap_trim_subord(grand, subord)
 *
 * grand  = pmap that we have nested subord in
 * subord = nested pmap we are attempting to trim
 *
 * Trims subord if possible
 */
MARK_AS_PMAP_TEXT static void
pmap_trim_subord(pmap_t subord)
{
	bool contract_subord = false;

	pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);

	subord->nested_no_bounds_refcnt--;

	if ((subord->nested_no_bounds_refcnt == 0) && (subord->nested_bounds_set)) {
		/* If this was the last no bounds reference, trim subord. */
		contract_subord = true;
	}

	pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);

	if (contract_subord) {
		pmap_trim_range(subord, subord->nested_region_addr, subord->nested_region_true_start);
		pmap_trim_range(subord, subord->nested_region_true_end, subord->nested_region_addr + subord->nested_region_size);
	}
}

void
pmap_trim(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size)
{
	pmap_trim_internal(grand, subord, vstart, size);
}

#if HAS_APPLE_PAC

void *
pmap_sign_user_ptr(void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key)
{
	void *res = NULL;
	uint64_t current_intr_state = pmap_interrupts_disable();

	uint64_t saved_jop_state = ml_enable_user_jop_key(jop_key);
	__compiler_materialize_and_prevent_reordering_on(value);
	res = sptm_sign_user_pointer(value, key, discriminator, jop_key);
	__compiler_materialize_and_prevent_reordering_on(res);
	ml_disable_user_jop_key(jop_key, saved_jop_state);

	pmap_interrupts_restore(current_intr_state);

	return res;
}

void *
pmap_auth_user_ptr(void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key)
{
	void *res = NULL;
	uint64_t current_intr_state = pmap_interrupts_disable();

	uint64_t saved_jop_state = ml_enable_user_jop_key(jop_key);
	__compiler_materialize_and_prevent_reordering_on(value);
	res = sptm_auth_user_pointer(value, key, discriminator, jop_key);
	__compiler_materialize_and_prevent_reordering_on(res);
	ml_disable_user_jop_key(jop_key, saved_jop_state);

	pmap_interrupts_restore(current_intr_state);

	return res;
}
#endif /* HAS_APPLE_PAC */

/*
 * Marker to indicate the phase of operation for a re-entered pmap_[un]nest() call.
 * This flag is supplied in the low-order bit of the 'vrestart' param as well as
 * the return value, to indicate where a preempted [un]nest operation should resume.
 * When the return value contains the ending address of the nested region with
 * PMAP_NEST_SPTM in the low-order bit, the operation has completed.
 */
#define PMAP_NEST_PHASE_MASK ((vm_map_offset_t)0x3)
#define PMAP_NEST_SUBORD ((vm_map_offset_t) 0x0) /* Processing PTEs within the nested pmap */
#define PMAP_NEST_GRAND ((vm_map_offset_t) 0x1) /* Processing TTEs within the nesting pmap */
#define PMAP_NEST_SPTM ((vm_map_offset_t) 0x2) /* Issuing final sptm_[un]nest_region call */

/*
 *	kern_return_t pmap_nest(grand, subord, vstart, size)
 *
 *	grand  = the pmap that we will nest subord into
 *	subord = the pmap that goes into the grand
 *	vstart  = start of range in pmap to be inserted
 *	size   = Size of nest area (up to 16TB)
 *
 *	Inserts a pmap into another.  This is used to implement shared segments.
 *
 */

/**
 * Embeds a range of mappings from one pmap ('subord') into another ('grand')
 * by inserting the twig-level TTEs from 'subord' directly into 'grand'.
 * This function operates in 3 main phases:
 * 1. Bookkeeping to ensure tracking structures for the nested region are set up.
 * 2. Expansion of subord to ensure the required leaf-level page table pages for
 *    the mapping range are present in subord.
 * 3. Expansion of grand to ensure the required twig-level page table pages for
 *    the mapping range are present in grand.
 * 4. Invoke sptm_nest_region() to copy the relevant TTEs from subord to grand.
 *
 * This function may return early due to pending AST_URGENT preemption; if so
 * it will indicate the need to be re-entered.
 *
 * @param grand pmap to insert the TTEs into.  Must be a user pmap.
 * @param subord pmap from which to extract the TTEs.  Must be a nested pmap.
 * @param vstart twig-aligned virtual address for the beginning of the nesting range
 * @param size twig-aligned size of the nesting range
 * @param vrestart the twig-aligned starting address of the current call.  May contain
 *        PMAP_NEST_SUBORD, PMAP_NEST_GRAND or PMAP_NEST_SPTM in bit 0:1 to indicate
 *        the operation should skip to step 3) or 4) above.
 * @param krp Should be initialized to KERN_SUCCESS by caller, will be set to
 *        KERN_RESOURCE_SHORTAGE on allocation failure.
 *
 * @return the virtual address at which to restart the operation, possibly including
 *         PMAP_NEST_GRAND or PMAP_NEST_SPTM to indicate the phase at which to restart.
 *         If (vstart + size) | PMAP_NEST_SPTM is returned, the operation completed.
 */
MARK_AS_PMAP_TEXT vm_map_offset_t
pmap_nest_internal(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size,
	vm_map_offset_t vrestart,
	kern_return_t *krp)
{
	kern_return_t kr = KERN_FAILURE;
	vm_map_offset_t vaddr;
	tt_entry_t     *stte_p;
	tt_entry_t     *gtte_p;
	bitmap_t       *nested_region_unnested_table_bitmap;
	int             expand_options = 0;
	bool            deref_subord = true;

	addr64_t vend;
	if (__improbable(os_add_overflow(vstart, size, &vend))) {
		panic("%s: %p grand addr wraps around: 0x%llx + 0x%llx", __func__, grand, vstart, size);
	}
	if (__improbable(((vrestart & ~PMAP_NEST_PHASE_MASK) > vend) ||
	    ((vrestart & ~PMAP_NEST_PHASE_MASK) < vstart))) {
		panic("%s: vrestart 0x%llx is outside range [0x%llx, 0x%llx)", __func__,
		    (unsigned long long)vrestart, (unsigned long long)vstart, (unsigned long long)vend);
	}

	assert(krp != NULL);
	validate_pmap_mutable(grand);
	validate_pmap(subord);
	if (__improbable(os_atomic_inc_orig(&subord->ref_count, relaxed) <= 0)) {
		panic("%s: invalid subordinate pmap %p", __func__, subord);
	}

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(grand);
	if (__improbable(pmap_get_pt_attr(subord) != pt_attr)) {
		panic("%s: attempt to nest pmap %p into pmap %p with mismatched attributes", __func__, subord, grand);
	}

	if (__improbable(((size | vstart | (vrestart & ~PMAP_NEST_PHASE_MASK)) &
	    (pt_attr_leaf_table_offmask(pt_attr))) != 0x0ULL)) {
		panic("pmap_nest() pmap %p unaligned nesting request 0x%llx, 0x%llx, 0x%llx",
		    grand, vstart, size, (unsigned long long)vrestart);
	}

	if (__improbable(subord->type != PMAP_TYPE_NESTED)) {
		panic("%s: subordinate pmap %p is of non-nestable type 0x%hhx", __func__, subord, subord->type);
	}

	if (__improbable(grand->type != PMAP_TYPE_USER)) {
		panic("%s: grand pmap %p is of unsupported type 0x%hhx for nesting", __func__, grand, grand->type);
	}

	/**
	 * Use an acquire barrier to ensure that subsequent loads of nested_region_* fields are not
	 * speculated ahead of the load of nested_region_unnested_table_bitmap, so that if we observe a non-NULL
	 * nested_region_unnested_table_bitmap then we can be sure the other fields have been initialized as well.
	 */
	if (os_atomic_load(&subord->nested_region_unnested_table_bitmap, acquire) == NULL) {
		uint64_t nested_region_unnested_table_bits = size >> pt_attr_twig_shift(pt_attr);

		if (__improbable((nested_region_unnested_table_bits > UINT_MAX))) {
			panic("%s: bitmap allocation size %llu will truncate, "
			    "grand=%p, subord=%p, vstart=0x%llx, size=%llx",
			    __func__, nested_region_unnested_table_bits,
			    grand, subord, vstart, size);
		}

		nested_region_unnested_table_bitmap = bitmap_alloc((uint) nested_region_unnested_table_bits);

		pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);
		if (subord->nested_region_unnested_table_bitmap == NULL) {
			subord->nested_region_addr = vstart;
			subord->nested_region_size = (mach_vm_offset_t) size;
			sptm_configure_shared_region(subord->ttep, vstart, size >> pt_attr->pta_page_shift);

			/**
			 * Ensure that the rest of the subord->nested_region_* fields are
			 * initialized and visible before setting the nested_region_unnested_table_bitmap
			 * field (which is used as the flag to say that the rest are initialized).
			 */
			os_atomic_store(&subord->nested_region_unnested_table_bitmap, nested_region_unnested_table_bitmap, release);
			nested_region_unnested_table_bitmap = NULL;
		}
		pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
		if (nested_region_unnested_table_bitmap != NULL) {
			bitmap_free(nested_region_unnested_table_bitmap, nested_region_unnested_table_bits);
		}
	}

	assertf(subord->nested_region_addr == vstart, "%s: pmap %p nested region addr 0x%llx doesn't match vstart 0x%llx",
	    __func__, subord, (unsigned long long)subord->nested_region_addr, (unsigned long long)vstart);
	assertf(subord->nested_region_size == size, "%s: pmap %p nested region size 0x%llx doesn't match size 0x%llx",
	    __func__, subord, (unsigned long long)subord->nested_region_size, (unsigned long long)size);

	pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);

	if (os_atomic_cmpxchg(&grand->nested_pmap, PMAP_NULL, subord, relaxed)) {
		/*
		 * If this is grand's first nesting operation, keep the reference on subord.
		 * It will be released by pmap_destroy_internal() when grand is destroyed.
		 */
		deref_subord = false;

		if (!subord->nested_bounds_set) {
			/*
			 * We are nesting without the shared regions bounds
			 * being known.  We'll have to trim the pmap later.
			 */
			grand->nested_has_no_bounds_ref = true;
			subord->nested_no_bounds_refcnt++;
		}

		grand->nested_region_addr = vstart;
		grand->nested_region_size = (mach_vm_offset_t) size;
	} else {
		if (__improbable(grand->nested_pmap != subord)) {
			panic("pmap_nest() pmap %p has a nested pmap", grand);
		} else if (__improbable(grand->nested_region_addr > vstart)) {
			panic("pmap_nest() pmap %p : attempt to nest outside the nested region", grand);
		} else if ((grand->nested_region_addr + grand->nested_region_size) < vend) {
			grand->nested_region_size = (mach_vm_offset_t)(vstart - grand->nested_region_addr + size);
		}
	}

	vaddr = vrestart & ~PMAP_NEST_PHASE_MASK;
	if (vaddr < subord->nested_region_true_start) {
		vaddr = subord->nested_region_true_start;
	}

	addr64_t true_end = vend;
	if (true_end > subord->nested_region_true_end) {
		true_end = subord->nested_region_true_end;
	}

	if ((vrestart & PMAP_NEST_PHASE_MASK) >= PMAP_NEST_GRAND) {
		goto nest_grand;
	}
	while (vaddr < true_end) {
		stte_p = pmap_tte(subord, vaddr);
		if (stte_p == PT_ENTRY_NULL || *stte_p == ARM_TTE_EMPTY) {
			pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
			kr = pmap_expand(subord, vaddr, expand_options, pt_attr_leaf_level(pt_attr));

			if (kr != KERN_SUCCESS) {
				pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);
				goto done;
			}

			pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);
		}
		vaddr += pt_attr_twig_size(pt_attr);
		vrestart = vaddr;
	}

	/*
	 * copy TTEs from subord pmap into grand pmap
	 */

	vaddr = (vm_map_offset_t) vstart;
	if (vaddr < subord->nested_region_true_start) {
		vaddr = subord->nested_region_true_start;
	}
	vrestart = vaddr | PMAP_NEST_GRAND;

nest_grand:
	pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
	pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);

	if ((vrestart & PMAP_NEST_PHASE_MASK) >= PMAP_NEST_SPTM) {
		goto nest_sptm;
	}

	while (vaddr < true_end) {
		gtte_p = pmap_tte(grand, vaddr);
		if (gtte_p == PT_ENTRY_NULL) {
			pmap_unlock(grand, PMAP_LOCK_EXCLUSIVE);
			kr = pmap_expand(grand, vaddr, expand_options, pt_attr_twig_level(pt_attr));
			pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);

			if (kr != KERN_SUCCESS) {
				goto done;
			}
		}

		vaddr += pt_attr_twig_size(pt_attr);
		vrestart = vaddr | PMAP_NEST_GRAND;
	}

	vaddr = (vm_map_offset_t) vstart;

	/*
	 * It is possible to have a preempted nest operation execute concurrently
	 * with a trim operation that sets nested_region_true_start.  In this case,
	 * update the nesting bounds.  This is useful both as a performance
	 * optimization and to prevent an attempt to nest a just-trimmed TTE,
	 * which will trigger an SPTM violation.
	 * Note that pmap_trim() may concurrently update grand's bounds as we are
	 * making these checks, but in that case pmap_trim_range() has not yet
	 * been called on grand and will wait for us to drop grand's lock, so it
	 * should see any TTEs we've nested here and clear them appropriately.
	 */
	if (vaddr < subord->nested_region_true_start) {
		vaddr = subord->nested_region_true_start;
	}
	if (vaddr < grand->nested_region_true_start) {
		vaddr = grand->nested_region_true_start;
	}
	if (true_end > subord->nested_region_true_end) {
		true_end = subord->nested_region_true_end;
	}
	if (true_end > grand->nested_region_true_end) {
		true_end = grand->nested_region_true_end;
	}
	vrestart = vaddr | PMAP_NEST_SPTM;

nest_sptm:

	while (vaddr < true_end) {
		/*
		 * The SPTM requires the run of TTE updates to all reside within the same L2 page, so the region
		 * we supply to the SPTM can't span multiple L1 TTEs.
		 */
		vm_map_offset_t vlim = ((vaddr + pt_attr_ln_size(pt_attr, PMAP_TT_L1_LEVEL)) & ~pt_attr_ln_offmask(pt_attr, PMAP_TT_L1_LEVEL));
		if (vlim > true_end) {
			vlim = true_end;
		}
		sptm_nest_region(grand->ttep, subord->ttep, vaddr, (vlim - vaddr) >> pt_attr->pta_page_shift);
		vaddr = vlim;
		vrestart = vaddr | PMAP_NEST_SPTM;
	}
	vrestart = vend | PMAP_NEST_SPTM;

	kr = KERN_SUCCESS;
done:
	pmap_unlock(grand, PMAP_LOCK_EXCLUSIVE);
	if (kr != KERN_SUCCESS) {
		*krp = kr;
	}
	if (deref_subord) {
		pmap_destroy_internal(subord);
	}
	return vrestart;
}

kern_return_t
pmap_nest(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_map_offset_t vaddr = (vm_map_offset_t)vstart;
	vm_map_offset_t vend = vaddr + size;
	vm_map_offset_t vlast = vaddr;

	PMAP_TRACE(2, PMAP_CODE(PMAP__NEST) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(subord),
	    VM_KERNEL_ADDRHIDE(vstart));

	pmap_verify_preemptible();
	while (vaddr != (vend | PMAP_NEST_SPTM)) {
		vaddr = pmap_nest_internal(grand, subord, vstart, size, vaddr, &kr);
		if (kr != KERN_SUCCESS) {
			break;
		} else if (vaddr == vlast) {
			panic("%s: failed to make forward progress from 0x%llx to 0x%llx at 0x%llx",
			    __func__, (unsigned long long)vstart, (unsigned long long)vend, (unsigned long long)vaddr);
		}
		vlast = vaddr;
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__NEST) | DBG_FUNC_END, kr);

	return kr;
}

/*
 *	kern_return_t pmap_unnest(grand, vaddr)
 *
 *	grand  = the pmap that will have the virtual range unnested
 *	vaddr  = start of range in pmap to be unnested
 *	size   = size of range in pmap to be unnested
 *
 */

kern_return_t
pmap_unnest(
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size)
{
	return pmap_unnest_options(grand, vaddr, size, 0);
}

/**
 * Undoes a prior pmap_nest() operation by removing a range of nesting mappings
 * from a top-level pmap ('grand').  The corresponding mappings in the nested
 * pmap will be marked non-global to avoid TLB conflicts with pmaps that may
 * still have the region nested.  The mappings in 'grand' will be left empty
 * with the assumption that they will be demand-filled by subsequent access faults.
 *
 * This function operates in 2 main phases:
 * 1. Iteration over the nested pmap's mappings for the specified range to mark
 *    them non-global.
 * 2. Calling the SPTM to clear the twig-level TTEs for the address range in grand.
 *
 * This function may return early due to pending AST_URGENT preemption; if so
 * it will indicate the need to be re-entered.
 *
 * @param grand pmap from which to unnest mappings
 * @param vaddr twig-aligned virtual address for the beginning of the nested range
 * @param size twig-aligned size of the nested range
 * @param vrestart the page-aligned starting address of the current call.  May contain
 *        PMAP_NEST_SUBORD or PMAP_NEST_SPTM in bit 0:1 to indicate the operation should
 *        skip to step 2) above.
 * @param option Extra control flags; may contain PMAP_UNNEST_CLEAN to indicate that
 *        grand is being torn down and step 1) above is not needed.
 *
 * @return the virtual address at which to restart the operation, possibly including
 *         PMAP_NEST_SPTM to indicate the phase at which to restart.  If
 *         (vaddr + size) | PMAP_NEST_SPTM is returned, the operation completed.
 */
MARK_AS_PMAP_TEXT vm_map_offset_t
pmap_unnest_options_internal(
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size,
	vm_map_offset_t vrestart,
	unsigned int option)
{
	vm_map_offset_t start;
	vm_map_offset_t addr;
	unsigned int    current_index;
	unsigned int    start_index;
	unsigned int    max_index;

	addr64_t vend;
	addr64_t true_end;
	if (__improbable(os_add_overflow(vaddr, size, &vend))) {
		panic("%s: %p vaddr wraps around: 0x%llx + 0x%llx", __func__, grand, vaddr, size);
	}
	if (__improbable(((vrestart & ~PMAP_NEST_PHASE_MASK) > vend) ||
	    ((vrestart & ~PMAP_NEST_PHASE_MASK) < vaddr))) {
		panic("%s: vrestart 0x%llx is outside range [0x%llx, 0x%llx)", __func__,
		    (unsigned long long)vrestart, (unsigned long long)vaddr, (unsigned long long)vend);
	}

	validate_pmap_mutable(grand);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(grand);

	if (__improbable(((size | vaddr) & pt_attr_twig_offmask(pt_attr)) != 0x0ULL)) {
		panic("%s: unaligned base address 0x%llx or size 0x%llx", __func__,
		    (unsigned long long)vaddr, (unsigned long long)size);
	}

	if (__improbable(grand->nested_pmap == NULL)) {
		panic("%s: %p has no nested pmap", __func__, grand);
	}

	true_end = vend;
	if (true_end > grand->nested_pmap->nested_region_true_end) {
		true_end = grand->nested_pmap->nested_region_true_end;
	}

	if (((option & PMAP_UNNEST_CLEAN) == 0) && ((vrestart & PMAP_NEST_PHASE_MASK) == PMAP_NEST_SUBORD)) {
		if ((vaddr < grand->nested_region_addr) || (vend > (grand->nested_region_addr + grand->nested_region_size))) {
			panic("%s: %p: unnest request to not-fully-nested region [%p, %p)", __func__, grand, (void*)vaddr, (void*)vend);
		}

		/*
		 * SPTM TODO: I suspect we may be able to hold the nested pmap lock exclusive here.
		 * We would need to use atomic_bitmap_set below where we currently use bitmap_test + bitmap_set.
		 * The risk is that a concurrent pmap_enter() against the nested pmap could observe the relevant
		 * bit in the nested region bitmap to be clear, but could then create the (global) mapping after
		 * we've made our SPTM sweep below to set NG.  In that case we could end up with a mix of global
		 * and non-global mappings for the same VA region and thus a TLB conflict.  I'm uncertain if the
		 * VM would allow these operation to happen concurrently.  Even if it does, we could still do
		 * something fancier here such as waiting for concurrent pmap_enter() to drain after updating
		 * the bitmap.
		 */
		pmap_lock(grand->nested_pmap, PMAP_LOCK_EXCLUSIVE);

		disable_preemption();
		pmap_sptm_percpu_data_t *sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
		unsigned int num_mappings = 0;
		start = vrestart;
		if (start < grand->nested_pmap->nested_region_true_start) {
			start = grand->nested_pmap->nested_region_true_start;
		}
		start_index = (unsigned int)((start - grand->nested_region_addr) >> pt_attr_twig_shift(pt_attr));
		max_index = (unsigned int)((true_end - grand->nested_region_addr) >> pt_attr_twig_shift(pt_attr));

		for (current_index = start_index, addr = start; current_index < max_index; current_index++) {
			pt_entry_t  *bpte, *cpte;

			vm_map_offset_t vlim = (addr + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr);

			bpte = pmap_pte(grand->nested_pmap, addr);

			/*
			 * If we've re-entered this function partway through unnesting a leaf region, the
			 * 'unnest' bit will be set in the ASID bitmap, but we won't have finished updating
			 * the run of PTEs.  We therefore also need to check for a non-twig-aligned starting
			 * address.
			 */
			if (!bitmap_test(grand->nested_pmap->nested_region_unnested_table_bitmap, current_index) ||
			    (addr & pt_attr_twig_offmask(pt_attr))) {
				/*
				 * We've marked the 'twig' region as being unnested.  Every mapping entered within
				 * the nested pmap in this region will now be marked non-global.  Do this
				 * before marking any of the PTEs within the region as non-global to avoid
				 * the possibility of pmap_enter() subsequently inserting a global mapping
				 * in the region, which could lead to a TLB conflict if a non-global entry
				 * is later inserted for the same VA in a pmap which has fully unnested this
				 * region.
				 */
				bitmap_set(grand->nested_pmap->nested_region_unnested_table_bitmap, current_index);
				for (cpte = bpte; (bpte != NULL) && (addr < vlim); cpte += PAGE_RATIO) {
					pt_entry_t  spte = os_atomic_load(cpte, relaxed);

					if ((spte & ARM_PTE_TYPE_MASK) != ARM_PTE_TYPE_FAULT) {
						spte |= ARM_PTE_NG;
					}

					addr += (pt_attr_page_size(pt_attr) * PAGE_RATIO);
					vrestart = addr;

					sptm_pcpu->sptm_templates[num_mappings] = spte;
					++num_mappings;

					if (num_mappings == SPTM_MAPPING_LIMIT) {
						pmap_retype_epoch_enter();
						sptm_update_region(grand->nested_pmap->ttep, start, num_mappings,
						    sptm_pcpu->sptm_templates_pa, SPTM_UPDATE_NG);
						pmap_retype_epoch_exit();
						enable_preemption();
						num_mappings = 0;
						start = addr;
						disable_preemption();
						sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
					}
				}
			}
			/**
			 * The SPTM does not allow region updates to span multiple leaf page tables, so request
			 * any remaining updates up to vlim before moving to the next page table page.
			 */
			if (num_mappings != 0) {
				pmap_retype_epoch_enter();
				sptm_update_region(grand->nested_pmap->ttep, start, num_mappings,
				    sptm_pcpu->sptm_templates_pa, SPTM_UPDATE_NG);
				pmap_retype_epoch_exit();
				enable_preemption();
				num_mappings = 0;
				disable_preemption();
				sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
			}
			addr = start = vlim;
			vrestart = addr;
		}

		if (num_mappings != 0) {
			pmap_retype_epoch_enter();
			sptm_update_region(grand->nested_pmap->ttep, start, num_mappings,
			    sptm_pcpu->sptm_templates_pa, SPTM_UPDATE_NG);
			pmap_retype_epoch_exit();
		}

		enable_preemption();
		pmap_unlock(grand->nested_pmap, PMAP_LOCK_EXCLUSIVE);
		if (current_index < max_index) {
			return vrestart;
		}
	}

	/*
	 * invalidate all pdes for segment at vaddr in pmap grand
	 */
	if ((vrestart & PMAP_NEST_PHASE_MASK) >= PMAP_NEST_SPTM) {
		addr = vrestart & ~PMAP_NEST_PHASE_MASK;
		if (__improbable(addr & pt_attr_twig_offmask(pt_attr)) != 0x0ULL) {
			panic("%s: unaligned vrestart 0x%llx", __func__, (unsigned long long)addr);
		}
	} else {
		addr = vaddr;
		vrestart = vaddr | PMAP_NEST_SPTM;
	}

	pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);

	if (addr < grand->nested_pmap->nested_region_true_start) {
		addr = grand->nested_pmap->nested_region_true_start;
	}

	if (true_end > grand->nested_pmap->nested_region_true_end) {
		true_end = grand->nested_pmap->nested_region_true_end;
	}

	while (addr < true_end) {
		vm_map_offset_t vlim = ((addr + pt_attr_ln_size(pt_attr, PMAP_TT_L1_LEVEL)) & ~pt_attr_ln_offmask(pt_attr, PMAP_TT_L1_LEVEL));
		if (vlim > true_end) {
			vlim = true_end;
		}
		sptm_unnest_region(grand->ttep, grand->nested_pmap->ttep, addr, (vlim - addr) >> pt_attr->pta_page_shift);
		addr = vlim;
		vrestart = addr | PMAP_NEST_SPTM;
	}

	vrestart = vend | PMAP_NEST_SPTM;

	pmap_unlock(grand, PMAP_LOCK_EXCLUSIVE);

	return vrestart;
}

kern_return_t
pmap_unnest_options(
	pmap_t grand,
	addr64_t vaddr,
	uint64_t size,
	unsigned int option)
{
	vm_map_offset_t vrestart = (vm_map_offset_t)vaddr;
	vm_map_offset_t vend = vaddr + size;
	vm_map_offset_t vlast = vrestart;

	PMAP_TRACE(2, PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(vaddr));

	pmap_verify_preemptible();
	while (vrestart != (vend | PMAP_NEST_SPTM)) {
		vrestart = pmap_unnest_options_internal(grand, vaddr, size, vrestart, option);
		if (vrestart == vlast) {
			panic("%s: failed to make forward progress from 0x%llx to 0x%llx at 0x%llx",
			    __func__, (unsigned long long)vaddr, (unsigned long long)vend, (unsigned long long)vrestart);
		}
		vlast = vrestart;
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_END, KERN_SUCCESS);

	return KERN_SUCCESS;
}

boolean_t
pmap_adjust_unnest_parameters(
	__unused pmap_t p,
	__unused vm_map_offset_t *s,
	__unused vm_map_offset_t *e)
{
	return TRUE; /* to get to log_unnest_badness()... */
}

#if PMAP_FORK_NEST
/**
 * Perform any necessary pre-nesting of the parent's shared region at fork()
 * time.
 *
 * @note This should only be called from vm_map_fork().
 *
 * @param old_pmap The pmap of the parent task.
 * @param new_pmap The pmap of the child task.
 * @param nesting_start An output parameter that is updated with the start
 *                      address of the range that was pre-nested
 * @param nesting_end An output parameter that is updated with the end
 *                      address of the range that was pre-nested
 *
 * @return KERN_SUCCESS if the pre-nesting was succesfully completed.
 *         KERN_INVALID_ARGUMENT if the arguments were not valid.
 */
kern_return_t
pmap_fork_nest(
	pmap_t old_pmap,
	pmap_t new_pmap,
	vm_map_offset_t *nesting_start,
	vm_map_offset_t *nesting_end)
{
	if (old_pmap == NULL || new_pmap == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (old_pmap->nested_pmap == NULL) {
		return KERN_SUCCESS;
	}
	pmap_nest(new_pmap,
	    old_pmap->nested_pmap,
	    old_pmap->nested_region_addr,
	    old_pmap->nested_region_size);
	assertf(new_pmap->nested_pmap == old_pmap->nested_pmap &&
	    new_pmap->nested_region_addr == old_pmap->nested_region_addr &&
	    new_pmap->nested_region_size == old_pmap->nested_region_size,
	    "nested new (%p,0x%llx,0x%llx) old (%p,0x%llx,0x%llx)",
	    new_pmap->nested_pmap,
	    new_pmap->nested_region_addr,
	    new_pmap->nested_region_size,
	    old_pmap->nested_pmap,
	    old_pmap->nested_region_addr,
	    old_pmap->nested_region_size);
	*nesting_start = old_pmap->nested_region_addr;
	*nesting_end = *nesting_start + old_pmap->nested_region_size;
	return KERN_SUCCESS;
}
#endif /* PMAP_FORK_NEST */

/*
 * disable no-execute capability on
 * the specified pmap
 */
#if DEVELOPMENT || DEBUG
void
pmap_disable_NX(
	pmap_t pmap)
{
	pmap->nx_enabled = FALSE;
}
#else
void
pmap_disable_NX(
	__unused pmap_t pmap)
{
}
#endif

/*
 * flush a range of hardware TLB entries.
 * NOTE: assumes the smallest TLB entry in use will be for
 * an ARM small page (4K).
 */

#if __ARM_RANGE_TLBI__
#define ARM64_RANGE_TLB_FLUSH_THRESHOLD 1
#define ARM64_FULL_TLB_FLUSH_THRESHOLD  ARM64_TLB_RANGE_MAX_PAGES
#else
#define ARM64_FULL_TLB_FLUSH_THRESHOLD  256
#endif // __ARM_RANGE_TLBI__

static void
flush_mmu_tlb_region_asid_async(
	vm_offset_t va,
	size_t length,
	pmap_t pmap,
	bool last_level_only __unused)
{
	unsigned long pmap_page_shift = pt_attr_leaf_shift(pmap_get_pt_attr(pmap));
	const uint64_t pmap_page_size = 1ULL << pmap_page_shift;
	ppnum_t npages = (ppnum_t)(length >> pmap_page_shift);
	const uint16_t asid = PMAP_HWASID(pmap);

	if (npages > ARM64_FULL_TLB_FLUSH_THRESHOLD) {
		boolean_t       flush_all = FALSE;

		if ((asid == 0) || (pmap->type == PMAP_TYPE_NESTED)) {
			flush_all = TRUE;
		}
		if (flush_all) {
			flush_mmu_tlb_async();
		} else {
			flush_mmu_tlb_asid_async((uint64_t)asid << TLBI_ASID_SHIFT, false);
		}
		return;
	}
#if __ARM_RANGE_TLBI__
	if (npages > ARM64_RANGE_TLB_FLUSH_THRESHOLD) {
		va = generate_rtlbi_param(npages, asid, va, pmap_page_shift);
		if (pmap->type == PMAP_TYPE_NESTED) {
			flush_mmu_tlb_allrange_async(va, last_level_only, false);
		} else {
			flush_mmu_tlb_range_async(va, last_level_only, false);
		}
		return;
	}
#endif
	vm_offset_t end = tlbi_asid(asid) | tlbi_addr(va + length);
	va = tlbi_asid(asid) | tlbi_addr(va);

	if (pmap->type == PMAP_TYPE_NESTED) {
		flush_mmu_tlb_allentries_async(va, end, pmap_page_size, last_level_only, false);
	} else {
		flush_mmu_tlb_entries_async(va, end, pmap_page_size, last_level_only, false);
	}
}

void
flush_mmu_tlb_region(
	vm_offset_t va,
	unsigned length)
{
	flush_mmu_tlb_region_asid_async(va, length, kernel_pmap, true);
	sync_tlb_flush();
}

unsigned int
pmap_cache_attributes(
	ppnum_t pn)
{
	pmap_paddr_t    paddr;
	unsigned int    pai;
	unsigned int    result;
	pp_attr_t       pp_attr_current;

	paddr = ptoa(pn);

	assert(vm_last_phys > vm_first_phys); // Check that pmap has been bootstrapped

	if (!pa_valid(paddr)) {
		pmap_io_range_t *io_rgn = pmap_find_io_attr(paddr);
		return (io_rgn == NULL) ? VM_WIMG_IO : io_rgn->wimg;
	}

	result = VM_WIMG_DEFAULT;

	pai = pa_index(paddr);

	pp_attr_current = pp_attr_table[pai];
	if (pp_attr_current & PP_ATTR_WIMG_MASK) {
		result = pp_attr_current & PP_ATTR_WIMG_MASK;
	}
	return result;
}

MARK_AS_PMAP_TEXT static void
pmap_sync_wimg(ppnum_t pn, unsigned int wimg_bits_prev, unsigned int wimg_bits_new)
{
	if ((wimg_bits_prev != wimg_bits_new)
	    && ((wimg_bits_prev == VM_WIMG_COPYBACK)
	    || ((wimg_bits_prev == VM_WIMG_INNERWBACK)
	    && (wimg_bits_new != VM_WIMG_COPYBACK))
	    || ((wimg_bits_prev == VM_WIMG_WTHRU)
	    && ((wimg_bits_new != VM_WIMG_COPYBACK) || (wimg_bits_new != VM_WIMG_INNERWBACK))))) {
		pmap_sync_page_attributes_phys(pn);
	}

	if ((wimg_bits_new == VM_WIMG_RT) && (wimg_bits_prev != VM_WIMG_RT)) {
		pmap_force_dcache_clean(phystokv(ptoa(pn)), PAGE_SIZE);
	}
}

MARK_AS_PMAP_TEXT __unused void
pmap_update_compressor_page_internal(ppnum_t pn, unsigned int prev_cacheattr, unsigned int new_cacheattr)
{
	pmap_paddr_t paddr = ptoa(pn);

	if (__improbable(!pa_valid(paddr))) {
		panic("%s called on non-managed page 0x%08x", __func__, pn);
	}

	pmap_set_cache_attributes_internal(pn, new_cacheattr, false);

	pmap_sync_wimg(pn, prev_cacheattr & VM_WIMG_MASK, new_cacheattr & VM_WIMG_MASK);
}

void *
pmap_map_compressor_page(ppnum_t pn)
{
	unsigned int cacheattr = pmap_cache_attributes(pn) & VM_WIMG_MASK;
	if (cacheattr != VM_WIMG_DEFAULT) {
		pmap_update_compressor_page_internal(pn, cacheattr, VM_WIMG_DEFAULT);
	}

	return (void*)phystokv(ptoa(pn));
}

void
pmap_unmap_compressor_page(ppnum_t pn __unused, void *kva __unused)
{
	unsigned int cacheattr = pmap_cache_attributes(pn) & VM_WIMG_MASK;
	if (cacheattr != VM_WIMG_DEFAULT) {
		pmap_update_compressor_page_internal(pn, VM_WIMG_DEFAULT, cacheattr);
	}
}

/**
 * Flushes TLB entries associated with the page specified by paddr, but do not
 * issue barriers yet.
 *
 * @param paddr The physical address to be flushed from TLB. Must be a managed address.
 */
static void
pmap_flush_tlb_for_paddr_async(pmap_paddr_t paddr)
{
	/* Flush the physical aperture mappings. */
	const vm_offset_t kva = phystokv(paddr);
	flush_mmu_tlb_region_asid_async(kva, PAGE_SIZE, kernel_pmap, true);

	/* Flush the mappings tracked in the ptes. */
	const unsigned int pai = pa_index(paddr);
	locked_pvh_t locked_pvh = pvh_lock(pai);

	pt_entry_t *pte_p = PT_ENTRY_NULL;
	pv_entry_t *pve_p = PV_ENTRY_NULL;

	if (pvh_test_type(locked_pvh.pvh, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(locked_pvh.pvh);
	} else if (pvh_test_type(locked_pvh.pvh, PVH_TYPE_PVEP)) {
		pve_p = pvh_pve_list(locked_pvh.pvh);
		pte_p = PT_ENTRY_NULL;
	}

	unsigned int nptes = 0;
	int pve_ptep_idx = 0;
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto flush_tlb_skip_pte;
			}
		}

		if (__improbable(nptes == SPTM_MAPPING_LIMIT)) {
			pvh_lock_enter_sleep_mode(&locked_pvh);
		}
		++nptes;
#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto flush_tlb_skip_pte;
		}
#endif /* PVH_FLAG_IOMMU */
		const pmap_t pmap = ptep_get_pmap(pte_p);
		const vm_map_address_t va = ptep_get_va(pte_p);

		pmap_get_pt_ops(pmap)->flush_tlb_region_async(va, pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO, pmap, true);

flush_tlb_skip_pte:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}
	pvh_unlock(&locked_pvh);
}

/**
 * Updates the pp_attr_table entry indexed by pai with cacheattr atomically.
 *
 * @param pai The Physical Address Index of the entry.
 * @param cacheattr The new cache attribute.
 */
MARK_AS_PMAP_TEXT static void
pmap_update_pp_attr_wimg_bits_locked(unsigned int pai, unsigned int cacheattr)
{
	pvh_assert_locked(pai);

	pp_attr_t pp_attr_current, pp_attr_template;
	do {
		pp_attr_current = pp_attr_table[pai];
		pp_attr_template = (pp_attr_current & ~PP_ATTR_WIMG_MASK) | PP_ATTR_WIMG(cacheattr);

		/**
		 * WIMG bits should only be updated under the PVH lock, but we should do
		 * this in a CAS loop to avoid losing simultaneous updates to other bits like refmod.
		 */
	} while (!OSCompareAndSwap16(pp_attr_current, pp_attr_template, &pp_attr_table[pai]));
}

/**
 * Structure for tracking where we are during the collection of mappings for batch
 * cache attribute updates.
 *
 * @note We need to track where in the per-cpu ops table we are filling the next mappings into,
 *       because the collection routine can return with a not completely filled ops table when
 *       it exhausts the PV list for a page. In such case, the remaining slots in the ops table
 *       will be used for mappings of the next page.
 *
 * @note We also need to record where we are in the PV list, because the collection routine can
 *       also return when the ops table is filled but it's still in the middle of the PV list.
 *       Those remaining items in the PV list need to be handled by the next batch operation in
 *       a new ops table.
 */
typedef struct {
	/* Where we are in the sptm ops table. */
	unsigned int sptm_ops_index;

	/**
	 * The last collected physical address from the previous full ops array (and in turn, SPTM
	 * call). This is used to know whether the SPTM call for the latest full ops table should
	 * skip updating the PAPT mapping (seeing as the last call would have handled updating it).
	 */
	pmap_paddr_t last_table_last_papt_pa;

	/**
	 * Where we are in the pv list.
	 *
	 * When ptep is non-null, there's only one mapping to the page and the ptep is the address
	 * of it.
	 *
	 * When pvep is non-null, there's more than one mapping and the mappings are tracked by the
	 * PV list.
	 *
	 * When they are both null, it indicates we are collecting for a new page and the collection
	 * function will initialize them to be one of the two states above.
	 *
	 * It is undefined when they are both non-null.
	 */
	pt_entry_t *ptep;
	pv_entry_t *pvep;
	unsigned int pve_ptep_idx;
} pmap_sptm_update_cache_attr_ops_collect_state_t;

/**
 * Reports whether there is any pending ops in an sptm cache attr ops table.
 *
 * @param state A pmap_sptm_update_cache_attr_ops_collect_state_t structure.
 *
 * @return True if there's any outstanding cache attr op.
 *         False otherwise.
 */
static inline bool
pmap_is_sptm_update_cache_attr_ops_pending(pmap_sptm_update_cache_attr_ops_collect_state_t state)
{
	return state.sptm_ops_index > 0;
}

/**
 * Struct for encoding the collection status into pmap_sptm_update_cache_attr_ops_collect()'s
 * return value indicating what kind of attention it needs.
 */
typedef enum {
	OPS_COLLECT_NOTHING = 0x0,

	/* The ops table is full, and the caller should commit the table to SPTM. */
	OPS_COLLECT_RETURN_FULL_TABLE = 0x1,

	/**
	 * The page has its mappings completely collected, and the caller should
	 * pass in a new page next time.
	 */
	OPS_COLLECT_RETURN_COMPLETED_PAGE = 0x2,
} pmap_sptm_update_cache_attr_ops_collect_return_t;

/**
 * Collects mappings of a physical page into an SPTM ops table for cache attribute updates.
 *
 * @note This routine returns either when the ops table is full or the page represented by
 *       pa has no more mapping to collect. The caller should call this routine again with
 *       a fresh ops table, or a new page, or both, depending on the return code.
 *
 * @note The PVH lock needs to be held for pa.
 *
 * @param state Tracks the state of PV list traversal and SPTM ops table filling. It is used
 *              by this routine to save the progress of the collection.
 * @param sptm_ops Pointer to the SPTM ops table.
 * @param pa The physical address whose mappings are to be collected.
 * @param attributes The new cache attributes.
 *
 * @return A pmap_sptm_update_cache_attr_ops_collect_return_t that encodes what the caller
 *         should do before calling this routine again. See the inline comments around
 *         pmap_sptm_update_cache_attr_ops_collect_return_t for details.
 */
static pmap_sptm_update_cache_attr_ops_collect_return_t
pmap_sptm_update_cache_attr_ops_collect(
	pmap_sptm_update_cache_attr_ops_collect_state_t *state,
	sptm_update_disjoint_multipage_op_t *sptm_ops,
	pmap_paddr_t pa,
	unsigned int attributes)
{
	if (state == NULL || sptm_ops == NULL) {
		panic("%s: unexpected null arguments - state: %p, sptm_ops: %p", __func__, state, sptm_ops);
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__COLLECT_CACHE_OPS) | DBG_FUNC_START, pa, attributes, state->sptm_ops_index);

	/* Copy the states into local variables. */
	unsigned int sptm_ops_index = state->sptm_ops_index;
	pmap_paddr_t last_table_last_papt_pa = state->last_table_last_papt_pa;
	pv_entry_t *pvep = state->pvep;
	pt_entry_t *ptep = state->ptep;
	unsigned int pve_ptep_idx = state->pve_ptep_idx;

	unsigned int pai = pa_index(pa);

	/* We should at least have one free slot in the ops table. */
	assert(sptm_ops_index < SPTM_MAPPING_LIMIT);

	/* The PVH lock for pa has to be locked. */
	pvh_assert_locked(pai);

	/* If pvep and ptep are both null in the state, it's a new page. Initialize the states. */
	if (pvep == PV_ENTRY_NULL && ptep == PT_ENTRY_NULL) {
		const uintptr_t pvh = pai_to_pvh(pai);
		if (pvh_test_type(pvh, PVH_TYPE_PVEP)) {
			ptep = PT_ENTRY_NULL;
			pvep = pvh_pve_list(pvh);
			pve_ptep_idx = 0;
		} else if (pvh_test_type(pvh, PVH_TYPE_PTEP)) {
			ptep  = pvh_ptep(pvh);
			pvep = PV_ENTRY_NULL;
			pve_ptep_idx = 0;
		}
	}

	/**
	 * The first entry filled in is always the PAPT header entry:
	 *
	 * 1) In the case of a fresh ops table, the first entry has to be a PAPT header.
	 * 2) In the case of a fresh page, we need to insert a new PAPT header to request
	 *    SPTM to operate on a new page.
	 *
	 * Remember the index of the PAPT header here so that we can update the number
	 * of mappings field later when we finish collecting.
	 */
	const unsigned int papt_sptm_ops_index = sptm_ops_index;
	unsigned int num_mappings = 0;

	/* Assemble the PTE template for the PAPT mapping. */
	const vm_address_t kva = phystokv(pa);
	const pt_entry_t *papt_ptep = pmap_pte(kernel_pmap, kva);

	pt_entry_t template = os_atomic_load(papt_ptep, relaxed);
	template &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
	template |= wimg_to_pte(attributes, pa);

	/* Fill in the PAPT header entry. */
	sptm_ops[papt_sptm_ops_index].per_paddr_header.paddr = pa;
	sptm_ops[papt_sptm_ops_index].per_paddr_header.papt_pte_template = template;
	sptm_ops[papt_sptm_ops_index].per_paddr_header.options = SPTM_UPDATE_SH | SPTM_UPDATE_MAIR | SPTM_UPDATE_DEFER_TLBI;

	if ((papt_sptm_ops_index == 0) && (pa == last_table_last_papt_pa)) {
		/**
		 * If the previous SPTM call was made with an ops table that already included
		 * updating the PA of the page that this table starts with, then we can assume
		 * that call already updated the PAPT and we can safely skip it in this
		 * upcoming one.
		 */
		sptm_ops[0].per_paddr_header.options |= SPTM_UPDATE_SKIP_PAPT;
	}

	sptm_ops_index++;

	/**
	 * Main loop for collecting the mappings into the ops table. It terminates either
	 * when the ops table is full or the PV list is exhausted.
	 */
	while ((sptm_ops_index < SPTM_MAPPING_LIMIT) && (pvep != PV_ENTRY_NULL || ptep != PT_ENTRY_NULL)) {
		/**
		 * Update ptep. There are really two cases here:
		 *
		 * 1) pvep is PV_ENTRY_NULL. In this case, ptep holds the pointer to
		 *    the only mapping to the page.
		 * 2) pvep is not PV_ENTRY_NULL. In such case, ptep is updated accroding to
		 *    pvep and pve_ptep_idx.
		 */
		if (pvep != PV_ENTRY_NULL) {
			ptep = pve_get_ptep(pvep, pve_ptep_idx);

			/* This pve is empty, so skip to next one. */
			if (ptep == PT_ENTRY_NULL) {
				goto sucaoc_skip_pte;
			}
		}

#ifdef PVH_FLAG_IOMMU
		/* Skip IOMMU pteps. */
		if (pvh_ptep_is_iommu(ptep)) {
			goto sucaoc_skip_pte;
		}
#endif
		/* Assemble the PTE template for the mapping. */
		const vm_address_t va = ptep_get_va(ptep);
		const pmap_t pmap = ptep_get_pmap(ptep);

		template = os_atomic_load(ptep, relaxed);
		template &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
		template |= pmap_get_pt_ops(pmap)->wimg_to_pte(attributes, pa);

		/* Fill into the ops table. */
		sptm_ops[sptm_ops_index].disjoint_op.root_pt_paddr = pmap->ttep;
		sptm_ops[sptm_ops_index].disjoint_op.vaddr = va;
		sptm_ops[sptm_ops_index].disjoint_op.pte_template = template;

		/* Move the sptm ops table cursor. */
		sptm_ops_index++;

		/* Increment the mappings counter. */
		num_mappings++;

sucaoc_skip_pte:
		/**
		 * Reset ptep to PT_ENTRY_NULL to keep the loop precondition of either ptep
		 * or pvep is nonnull (not both, not neither) true.
		 */
		ptep = PT_ENTRY_NULL;

		/* Advance to next pvep if we have exhausted the pteps in it. */
		if ((pvep != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pvep = pve_next(pvep);
		}
	}

	/* Update the PAPT header for the number of mappings. */
	sptm_ops[papt_sptm_ops_index].per_paddr_header.num_mappings = num_mappings;

	const bool full_table = (sptm_ops_index >= SPTM_MAPPING_LIMIT);
	const bool collection_done_for_page = (pvep == PV_ENTRY_NULL && ptep == PT_ENTRY_NULL);

	/**
	 * The ops table is full, so the caller should now invoke the SPTM before calling
	 * into this function again.
	 */
	if (full_table) {
		/* Update last_table_last_papt_pa to be the pa collected in this call. */
		last_table_last_papt_pa = pa;

		/* Reset sptm_ops_index. */
		sptm_ops_index = 0;
	}

	/* Copy the updated collection states back to the parameter structure. */
	state->sptm_ops_index = sptm_ops_index;
	state->last_table_last_papt_pa = last_table_last_papt_pa;
	state->pvep = pvep;
	state->ptep = ptep;
	state->pve_ptep_idx = pve_ptep_idx;

	/* Assemble the return value. */
	pmap_sptm_update_cache_attr_ops_collect_return_t retval = OPS_COLLECT_NOTHING;

	if (full_table) {
		retval |= OPS_COLLECT_RETURN_FULL_TABLE;
	}

	if (collection_done_for_page) {
		retval |= OPS_COLLECT_RETURN_COMPLETED_PAGE;
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__COLLECT_CACHE_OPS) | DBG_FUNC_END, pa, attributes, sptm_ops_index);

	return retval;
}

/* At least one PAPT header plus one mapping. */
static_assert(SPTM_MAPPING_LIMIT >= 2);

/**
 * Returns if a cache attribute is allowed (on managed pages).
 *
 * @param attributes A 32-bit value whose VM_WIMG_MASK bits represent the
 *                   cache attribute.
 *
 * @return True if the cache attribute is allowed on managed pages.
 *         False otherwise.
 */
static bool
pmap_is_cache_attribute_allowed(unsigned int attributes)
{
	if (pmap_panic_dev_wimg_on_managed) {
		switch (attributes & VM_WIMG_MASK) {
		/* supported on DRAM, but slow, so we disallow */
		case VM_WIMG_IO:                        // nGnRnE
		case VM_WIMG_POSTED:                    // nGnRE

		/* unsupported on DRAM */
		case VM_WIMG_POSTED_REORDERED:          // nGRE
		case VM_WIMG_POSTED_COMBINED_REORDERED: // GRE
			return false;

		default:
			return true;
		}
	}

	return true;
}

/**
 * Batch updates the cache attributes of a list of pages in three passes.
 *
 * In pass one, the pp_attr_table and the pte are updated (by SPTM) for the pages in the list.
 * In pass two, TLB entries are flushed for each page in the list if necessary.
 * In pass three, caches are cleaned for each page in the list if necessary.
 *
 * @param user_page_list List of pages to be updated.
 * @param page_cnt Number of pages in total in user_page_list.
 * @param cacheattr The new cache attributes.
 * @param update_attr_table Whether the pp_attr_table should be updated. This is useful for compressor
 *                          pages where it's desired to keep the old WIMG bits.
 *
 * @return True on success.
 */
bool
pmap_batch_set_cache_attributes_internal(
	upl_page_info_array_t user_page_list,
	unsigned int page_cnt,
	unsigned int cacheattr,
	bool update_attr_table)
{
	uint64_t page_index = 0;
	bool tlb_flush_pass_needed = false;
	bool rt_cache_flush_pass_needed = false;
	bool preemption_disabled = false;

	PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE1, page_index);

	pmap_sptm_percpu_data_t *sptm_pcpu = NULL;
	sptm_update_disjoint_multipage_op_t *sptm_ops = NULL;

	pmap_sptm_update_cache_attr_ops_collect_state_t state = {0};

	while (page_index < page_cnt) {
		const ppnum_t pn = user_page_list[page_index].phys_addr;
		const pmap_paddr_t paddr = ptoa(pn);

		/**
		 * Skip if the page is not managed.
		 *
		 * We don't panic here because sometimes the user just blindly pass in
		 * pages that are not managed. We need to handle that gracefully.
		 */
		if (!pa_valid(paddr)) {
			page_index++;
			continue;
		}

		const unsigned int pai = pa_index(paddr);
		locked_pvh_t locked_pvh = {.pvh = 0};

		if (pmap_is_sptm_update_cache_attr_ops_pending(state)) {
			/**
			 * If we're partway through processing a multi-page batched call,
			 * preemption will already be disabled so we can't simply call
			 * pvh_lock() which may block.  Instead, we first try to acquire
			 * the lock without waiting, which in most cases should succeed.
			 * If it fails, we submit the pending batched operations to re-
			 * enable preemption and then acquire the lock normally.
			 */
			locked_pvh = pvh_try_lock(pai);
			if (__improbable(!pvh_try_lock_success(&locked_pvh))) {
				assert(preemption_disabled);
				const sptm_return_t sptm_ret = sptm_update_disjoint_multipage(sptm_pcpu->sptm_ops_pa, state.sptm_ops_index);
				pmap_retype_epoch_exit();
				enable_preemption();
				preemption_disabled = false;
				if (sptm_ret == SPTM_UPDATE_DELAYED_TLBI) {
					tlb_flush_pass_needed = true;
				}
				state.sptm_ops_index = 0;
				locked_pvh = pvh_lock(pai);
			}
		} else {
			locked_pvh = pvh_lock(pai);
		}
		assert(locked_pvh.pvh != 0);

		const pp_attr_t pp_attr_current = pp_attr_table[pai];

		unsigned int wimg_bits_prev = VM_WIMG_DEFAULT;
		if (pp_attr_current & PP_ATTR_WIMG_MASK) {
			wimg_bits_prev = pp_attr_current & PP_ATTR_WIMG_MASK;
		}

		const pp_attr_t pp_attr_template = (pp_attr_current & ~PP_ATTR_WIMG_MASK) | PP_ATTR_WIMG(cacheattr);

		unsigned int wimg_bits_new = VM_WIMG_DEFAULT;
		if (pp_attr_template & PP_ATTR_WIMG_MASK) {
			wimg_bits_new = pp_attr_template & PP_ATTR_WIMG_MASK;
		}

		/**
		 * When update_attr_table is false, we know that wimg_bits_prev read from pp_attr_table is not to be trusted,
		 * and we should force update the cache attribute.
		 */
		const bool force_update = !update_attr_table;
		/* Update the cache attributes in PTE and PP_ATTR table. */
		if ((wimg_bits_new != wimg_bits_prev) || force_update) {
			if (!pmap_is_cache_attribute_allowed(cacheattr)) {
				panic("%s: trying to use unsupported VM_WIMG type for managed page, VM_WIMG=%x, pn=%#x",
				    __func__, cacheattr & VM_WIMG_MASK, pn);
			}

			/* Update PP_ATTR_TABLE */
			if (update_attr_table) {
				pmap_update_pp_attr_wimg_bits_locked(pai, cacheattr);
			}

			bool mapping_collection_done = false;
			bool pvh_lock_sleep_mode_needed = false;
			do {
				if (__improbable(pvh_lock_sleep_mode_needed)) {
					assert(!preemption_disabled);
					pvh_lock_enter_sleep_mode(&locked_pvh);
					pvh_lock_sleep_mode_needed = false;
				}

				/* Disable preemption to use the per-CPU structure safely. */
				if (!preemption_disabled) {
					preemption_disabled = true;
					disable_preemption();
					/**
					 * Enter the retype epoch while we gather the disjoint update arguments
					 * and issue the SPTM call.  Since this operation may cover multiple physical
					 * pages, we may construct the argument array and invoke the SPTM without holding
					 * all relevant PVH locks, we need to record that we are collecting and modifying
					 * mapping state so that e.g. pmap_page_protect() does not attempt to retype the
					 * underlying pages and pmap_remove() does not attempt to free the page tables
					 * used for these mappings without first draining our epoch.
					 */
					pmap_retype_epoch_enter();

					sptm_pcpu = PERCPU_GET(pmap_sptm_percpu);
					sptm_ops = (sptm_update_disjoint_multipage_op_t *) sptm_pcpu->sptm_ops;
				}

				/* The return value indicates if we should call into SPTM in this iteration. */
				pmap_sptm_update_cache_attr_ops_collect_return_t retval =
				    pmap_sptm_update_cache_attr_ops_collect(&state, sptm_ops, paddr, cacheattr);

				/* The collection routine should only return if it needs attention. */
				assert(retval != OPS_COLLECT_NOTHING);

				/* Gather information for next step from the return value. */
				mapping_collection_done = retval & OPS_COLLECT_RETURN_COMPLETED_PAGE;
				const bool call_sptm = retval & OPS_COLLECT_RETURN_FULL_TABLE;

				if (call_sptm) {
					/* Call into SPTM with this SPTM ops table. */
					sptm_return_t sptm_ret = sptm_update_disjoint_multipage(sptm_pcpu->sptm_ops_pa, SPTM_MAPPING_LIMIT);
					/**
					 * We may be submitting the batch and exiting the epoch partway through
					 * processing the PV list for a page.  That's fine, because in that case we'll
					 * hold the PV lock for that page, which will prevent mappings of that page from
					 * being disconnected and will prevent the completion of pmap_remove() against
					 * any of those mappings, thus also guaranteeing the relevant page table pages
					 * can't be freed.  The epoch still protects mappings for any prior page in
					 * the batch, whose PV locks are no longer held.
					 */
					pmap_retype_epoch_exit();
					/**
					 * Balance out the explicit disable_preemption() made either at the beginning of
					 * the function or on a prior iteration of the loop that placed the PVH lock in
					 * sleep mode.  Note that enable_preemption() decrements a per-thread counter,
					 * so if we still happen to hold the PVH lock in spin mode preemption won't
					 * actually be re-enabled until we switch the lock over to sleep mode on
					 * the next iteration.
					 */
					enable_preemption();
					preemption_disabled = false;
					pvh_lock_sleep_mode_needed = true;

					if (sptm_ret == SPTM_UPDATE_DELAYED_TLBI) {
						tlb_flush_pass_needed = true;
					}
				}

				/* We cannot be in a situation where we didn't call into SPTM while also having not finished walking the pv list. */
				assert(call_sptm || mapping_collection_done);
			} while (!mapping_collection_done);

			/**
			 * We could technically force the cache flush pass here when force_update is true, but
			 * since the compressor mapping/unmapping path handles cache flushing itself, it's fine
			 * leaving this as is.
			 */
			if (wimg_bits_new == VM_WIMG_RT && wimg_bits_prev != VM_WIMG_RT) {
				rt_cache_flush_pass_needed = true;
			}
		}

		pvh_unlock(&locked_pvh);
		page_index++;
	}

	if (pmap_is_sptm_update_cache_attr_ops_pending(state)) {
		assert(preemption_disabled);
		sptm_return_t sptm_ret = sptm_update_disjoint_multipage(sptm_pcpu->sptm_ops_pa, state.sptm_ops_index);
		pmap_retype_epoch_exit();
		if (sptm_ret == SPTM_UPDATE_DELAYED_TLBI) {
			tlb_flush_pass_needed = true;
		}

		/**
		 * This is the last sptm_update_cache_attr() call whatsoever, so it's
		 * okay not to update the state variables.
		 */

		enable_preemption();
	} else if (preemption_disabled) {
		pmap_retype_epoch_exit();
		enable_preemption();
	}

	if (tlb_flush_pass_needed) {
		page_index = 0;

		/* Sync the PTE writes before potential TLB/Cache flushes. */
		FLUSH_PTE_STRONG();

		/**
		 * Pass 2: for each physical page and for each mapping, we need to flush
		 * the TLB for it.
		 */
		PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE2, page_index);
		while (page_index < page_cnt) {
			const ppnum_t pn = user_page_list[page_index].phys_addr;

			const pmap_paddr_t paddr = ptoa(pn);
			if (!pa_valid(paddr)) {
				page_index++;
				continue;
			}

			pmap_flush_tlb_for_paddr_async(paddr);

			page_index++;
		}

#if HAS_FEAT_XS
		/* With FEAT_XS, ordinary DSBs drain the prefetcher. */
		arm64_sync_tlb(false);
#else
		/**
		 * For targets that distinguish between mild and strong DSB, mild DSB
		 * will not drain the prefetcher.  This can lead to prefetch-driven
		 * cache fills that defeat the uncacheable requirement of the RT memory type.
		 * In those cases, strong DSB must instead be employed to drain the prefetcher.
		 */
		arm64_sync_tlb((cacheattr & VM_WIMG_MASK) == VM_WIMG_RT);
#endif
	}

	if (rt_cache_flush_pass_needed) {
		page_index = 0;

		/* Pass 3: Flush the cache if the page is recently set to RT */
		PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE3, page_index);
		/**
		 * We disable preemption to ensure we are not preempted
		 * in the state where DC by VA instructions remain enabled.
		 */
		disable_preemption();

		assert(get_preemption_level() > 0);

#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
		/**
		 * On APPLEVIRTUALPLATFORM, HID register accesses cause a synchronous exception
		 * and the host will handle cache maintenance for it. So we don't need to
		 * worry about enabling the ops here for AVP.
		 */
		enable_dc_mva_ops();
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM */

		while (page_index < page_cnt) {
			const pmap_paddr_t paddr = ptoa(user_page_list[page_index].phys_addr);

			if (!pa_valid(paddr)) {
				page_index++;
				continue;
			}

			CleanPoC_DcacheRegion_Force_nopreempt_nohid(phystokv(paddr), PAGE_SIZE);

			page_index++;

			if (__improbable(pmap_pending_preemption() && (page_index < page_cnt))) {
#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
				disable_dc_mva_ops();
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM */
				enable_preemption();
				assert(preemption_enabled());
				disable_preemption();
#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
				enable_dc_mva_ops();
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM */
			}
		}

#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
		disable_dc_mva_ops();
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM */

		enable_preemption();
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE4, page_index);

	return true;
}

/**
 * Batch updates the cache attributes of a list of pages. This is a wrapper for
 * the ppl call on PPL-enabled platforms or the _internal helper on other platforms.
 *
 * @param user_page_list List of pages to be updated.
 * @param page_cnt Number of pages in total in user_page_list.
 * @param cacheattr The new cache attribute.
 *
 * @return Success if true is returned.
 */
bool
pmap_batch_set_cache_attributes(
	upl_page_info_array_t user_page_list,
	unsigned int page_cnt,
	unsigned int cacheattr)
{
	PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING) | DBG_FUNC_START, page_cnt, cacheattr, 0xCECC0DE0);

	/* Verify we are being called from a preemptible context. */
	pmap_verify_preemptible();

	pmap_batch_set_cache_attributes_internal(user_page_list, page_cnt, cacheattr, true);

	PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING) | DBG_FUNC_END, page_cnt, cacheattr, 0xCECC0DEF);
	return true;
}

MARK_AS_PMAP_TEXT void
pmap_set_cache_attributes_internal(
	ppnum_t pn,
	unsigned int cacheattr,
	bool update_attr_table)
{
	upl_page_info_t single_page_upl = { .phys_addr = pn };

	pmap_batch_set_cache_attributes_internal(&single_page_upl, 1, cacheattr, update_attr_table);
}

void
pmap_set_cache_attributes(
	ppnum_t pn,
	unsigned int cacheattr)
{
	pmap_set_cache_attributes_internal(pn, cacheattr, true);
}

void
pmap_create_commpages(vm_map_address_t *kernel_data_addr, vm_map_address_t *kernel_text_addr,
    vm_map_address_t *kernel_ro_data_addr, vm_map_address_t *user_text_addr)
{
	pmap_paddr_t data_pa = 0; // data address
	pmap_paddr_t ro_data_pa = 0; // kernel read-only data address
	pmap_paddr_t text_pa = 0; // text address

	*kernel_data_addr = 0;
	*kernel_text_addr = 0;
	*user_text_addr = 0;

	kern_return_t kr = pmap_page_alloc(&data_pa, PMAP_PAGE_ALLOCATE_NONE);
	assert(kr == KERN_SUCCESS);

	kr = pmap_page_alloc(&ro_data_pa, PMAP_PAGE_ALLOCATE_NONE);
	assert(kr == KERN_SUCCESS);

#if CONFIG_ARM_PFZ
	kr = pmap_page_alloc(&text_pa, PMAP_PAGE_ALLOCATE_NONE);
	assert(kr == KERN_SUCCESS);
#endif

	/* For manipulation in kernel, go straight to physical page */
	commpage_data_pa = data_pa;
	*kernel_data_addr = phystokv(data_pa);
	assert(commpage_ro_data_pa == 0);
	commpage_ro_data_pa = ro_data_pa;
	*kernel_ro_data_addr = phystokv(ro_data_pa);
	assert(commpage_text_pa == 0);
	commpage_text_pa = text_pa;
	*kernel_text_addr = (text_pa ? phystokv(text_pa) : 0);
}


/*
 * Asserts to ensure that the TTEs we nest to map the shared page do not overlap
 * with user controlled TTEs for regions that aren't explicitly reserved by the
 * VM (e.g., _COMM_PAGE64_NESTING_START/_COMM_PAGE64_BASE_ADDRESS).
 */
#if (ARM_PGSHIFT == 14)
/**
 * Ensure that 64-bit devices with 32-bit userspace VAs (arm64_32) can nest the
 * commpage completely above the maximum 32-bit userspace VA.
 */
static_assert((_COMM_PAGE32_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK) >= VM_MAX_ADDRESS);
static_assert(_COMM_PAGE64_NESTING_START == SPTM_ARM64_COMMPAGE_REGION_START);
static_assert(_COMM_PAGE64_NESTING_SIZE == SPTM_ARM64_COMMPAGE_REGION_SIZE);

/**
 * Normally there'd be an assert to check that 64-bit devices with 64-bit
 * userspace VAs can nest the commpage completely above the maximum 64-bit
 * userpace VA, but that technically isn't true on macOS. On those systems, the
 * commpage lives within the userspace VA range, but is protected by the VM as
 * a reserved region (see vm_reserved_regions[] definition for more info).
 */

#elif (ARM_PGSHIFT == 12)
/**
 * Ensure that 64-bit devices using 4K pages can nest the commpage completely
 * above the maximum userspace VA.
 */
static_assert((_COMM_PAGE64_BASE_ADDRESS & ~ARM_TT_L1_OFFMASK) >= MACH_VM_MAX_ADDRESS);
#else
#error Nested shared page mapping is unsupported on this config
#endif

MARK_AS_PMAP_TEXT kern_return_t
pmap_insert_commpage_internal(
	pmap_t pmap)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_offset_t commpage_vaddr;
	pt_entry_t *ttep;
	pmap_paddr_t commpage_table = commpage_default_table;

	/* Validate the pmap input before accessing its data. */
	validate_pmap_mutable(pmap);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const unsigned int commpage_level = pt_attr_commpage_level(pt_attr);

#if __ARM_MIXED_PAGE_SIZE__
#if !__ARM_16K_PG__
	/* The following code assumes that commpage_pmap_default is a 16KB pmap. */
	#error "pmap_insert_commpage_internal requires a 16KB default kernel page size when __ARM_MIXED_PAGE_SIZE__ is enabled"
#endif /* !__ARM_16K_PG__ */

	/* Choose the correct shared page pmap to use. */
	const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
	if (pmap_page_size == 4096) {
		if (pmap_is_64bit(pmap)) {
			commpage_table = commpage_4k_table;
		} else {
			panic("32-bit commpage not currently supported for SPTM configurations");
			//commpage_table = commpage32_4k_table;
		}
	} else if (pmap_page_size != 16384) {
		panic("No commpage table exists for the wanted page size: %llu", pmap_page_size);
	} else
#endif /* __ARM_MIXED_PAGE_SIZE__ */
	{
		if (pmap_is_64bit(pmap)) {
			commpage_table = commpage_default_table;
		} else {
			panic("32-bit commpage not currently supported for SPTM configurations");
			//commpage_table = commpage32_default_table;
		}
	}

#if _COMM_PAGE_AREA_LENGTH != PAGE_SIZE
#error We assume a single page.
#endif

	if (pmap_is_64bit(pmap)) {
		commpage_vaddr = _COMM_PAGE64_BASE_ADDRESS;
	} else {
		commpage_vaddr = _COMM_PAGE32_BASE_ADDRESS;
	}


	pmap_lock(pmap, PMAP_LOCK_SHARED);

	/*
	 * For 4KB pages, we either "nest" at the level one page table (1GB) or level
	 * two (2MB) depending on the address space layout. For 16KB pages, each level
	 * one entry is 64GB, so we must go to the second level entry (32MB) in order
	 * to "nest".
	 *
	 * Note: This is not "nesting" in the shared cache sense. This definition of
	 * nesting just means inserting pointers to pre-allocated tables inside of
	 * the passed in pmap to allow us to share page tables (which map the shared
	 * page) for every task. This saves at least one page of memory per process
	 * compared to creating new page tables in every process for mapping the
	 * shared page.
	 */

	/**
	 * Allocate the twig page tables if needed, and slam a pointer to the shared
	 * page's tables into place.
	 */
	while ((ttep = pmap_ttne(pmap, commpage_level, commpage_vaddr)) == TT_ENTRY_NULL) {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);

		kr = pmap_expand(pmap, commpage_vaddr, 0, commpage_level);

		if (kr != KERN_SUCCESS) {
			panic("Failed to pmap_expand for commpage, pmap=%p", pmap);
		}

		pmap_lock(pmap, PMAP_LOCK_SHARED);
	}

	if (*ttep != ARM_PTE_EMPTY) {
		panic("%s: Found something mapped at the commpage address?!", __FUNCTION__);
	}

	sptm_map_table(pmap->ttep, commpage_vaddr, (sptm_pt_level_t)commpage_level,
	    (commpage_table & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID);

	pmap_unlock(pmap, PMAP_LOCK_SHARED);

	return kr;
}

static void
pmap_unmap_commpage(
	pmap_t pmap)
{
	pt_entry_t *ptep;
	vm_offset_t commpage_vaddr;

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const unsigned int commpage_level = pt_attr_commpage_level(pt_attr);
	__assert_only pmap_paddr_t commpage_pa = commpage_data_pa;

	if (pmap_is_64bit(pmap)) {
		commpage_vaddr = _COMM_PAGE64_BASE_ADDRESS;
	} else {
		commpage_vaddr = _COMM_PAGE32_BASE_ADDRESS;
	}


	ptep = pmap_pte(pmap, commpage_vaddr);

	if (ptep == NULL) {
		return;
	}

	/* It had better be mapped to the shared page. */
	if (pte_to_pa(*ptep) != commpage_pa) {
		panic("%s: non-commpage PA 0x%llx mapped at VA 0x%llx in pmap %p; expected 0x%llx",
		    __func__, (unsigned long long)pte_to_pa(*ptep), (unsigned long long)commpage_vaddr,
		    pmap, (unsigned long long)commpage_pa);
	}

	sptm_unmap_table(pmap->ttep, commpage_vaddr, (sptm_pt_level_t)commpage_level);
}

void
pmap_insert_commpage(
	pmap_t pmap)
{
	pmap_insert_commpage_internal(pmap);
}

static boolean_t
pmap_is_64bit(
	pmap_t pmap)
{
	return pmap->is_64bit;
}

bool
pmap_is_exotic(
	pmap_t pmap __unused)
{
	return false;
}


/* ARMTODO -- an implementation that accounts for
 * holes in the physical map, if any.
 */
boolean_t
pmap_valid_page(
	ppnum_t pn)
{
	return pa_valid(ptoa(pn));
}

boolean_t
pmap_bootloader_page(
	ppnum_t pn)
{
	pmap_paddr_t paddr = ptoa(pn);

	if (pa_valid(paddr)) {
		return FALSE;
	}
	pmap_io_range_t *io_rgn = pmap_find_io_attr(paddr);
	return (io_rgn != NULL) && (io_rgn->wimg & PMAP_IO_RANGE_CARVEOUT);
}

MARK_AS_PMAP_TEXT boolean_t
pmap_is_empty_internal(
	pmap_t pmap,
	vm_map_offset_t va_start,
	vm_map_offset_t va_end)
{
	vm_map_offset_t block_start, block_end;
	tt_entry_t *tte_p;

	if (pmap == NULL) {
		return TRUE;
	}

	validate_pmap(pmap);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	unsigned int initial_not_in_kdp = not_in_kdp;

	if ((pmap != kernel_pmap) && (initial_not_in_kdp)) {
		pmap_lock(pmap, PMAP_LOCK_SHARED);
	}


	/* TODO: This will be faster if we increment ttep at each level. */
	block_start = va_start;

	while (block_start < va_end) {
		pt_entry_t     *bpte_p, *epte_p;
		pt_entry_t     *pte_p;

		block_end = (block_start + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr);
		if (block_end > va_end) {
			block_end = va_end;
		}

		tte_p = pmap_tte(pmap, block_start);
		if ((tte_p != PT_ENTRY_NULL)
		    && ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE)) {
			pte_p = (pt_entry_t *) ttetokv(*tte_p);
			bpte_p = &pte_p[pte_index(pt_attr, block_start)];
			epte_p = &pte_p[pte_index(pt_attr, block_end)];

			for (pte_p = bpte_p; pte_p < epte_p; pte_p++) {
				if (*pte_p != ARM_PTE_EMPTY) {
					if ((pmap != kernel_pmap) && (initial_not_in_kdp)) {
						pmap_unlock(pmap, PMAP_LOCK_SHARED);
					}
					return FALSE;
				}
			}
		}
		block_start = block_end;
	}

	if ((pmap != kernel_pmap) && (initial_not_in_kdp)) {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
	}

	return TRUE;
}

boolean_t
pmap_is_empty(
	pmap_t pmap,
	vm_map_offset_t va_start,
	vm_map_offset_t va_end)
{
	return pmap_is_empty_internal(pmap, va_start, va_end);
}

vm_map_offset_t
pmap_max_offset(
	boolean_t               is64,
	unsigned int    option)
{
	return (is64) ? pmap_max_64bit_offset(option) : pmap_max_32bit_offset(option);
}

vm_map_offset_t
pmap_max_64bit_offset(
	__unused unsigned int option)
{
	vm_map_offset_t max_offset_ret = 0;

	const vm_map_offset_t min_max_offset = ARM64_MIN_MAX_ADDRESS; // end of shared region + 512MB for various purposes
	if (option == ARM_PMAP_MAX_OFFSET_DEFAULT) {
		max_offset_ret = arm64_pmap_max_offset_default;
	} else if (option == ARM_PMAP_MAX_OFFSET_MIN) {
		max_offset_ret = min_max_offset;
	} else if (option == ARM_PMAP_MAX_OFFSET_MAX) {
		max_offset_ret = MACH_VM_MAX_ADDRESS;
	} else if (option == ARM_PMAP_MAX_OFFSET_DEVICE) {
		if (arm64_pmap_max_offset_default) {
			max_offset_ret = arm64_pmap_max_offset_default;
		} else if (max_mem > 0xC0000000) {
			// devices with > 3GB of memory
			max_offset_ret = ARM64_MAX_OFFSET_DEVICE_LARGE;
		} else if (max_mem > 0x40000000) {
			// devices with > 1GB and <= 3GB of memory
			max_offset_ret = ARM64_MAX_OFFSET_DEVICE_SMALL;
		} else {
			// devices with <= 1 GB of memory
			max_offset_ret = min_max_offset;
		}
	} else if (option == ARM_PMAP_MAX_OFFSET_JUMBO) {
		if (arm64_pmap_max_offset_default) {
			// Allow the boot-arg to override jumbo size
			max_offset_ret = arm64_pmap_max_offset_default;
		} else {
			max_offset_ret = MACH_VM_MAX_ADDRESS;     // Max offset is 64GB for pmaps with special "jumbo" blessing
		}
	} else {
		panic("pmap_max_64bit_offset illegal option 0x%x", option);
	}

	assert(max_offset_ret <= MACH_VM_MAX_ADDRESS);
	if (option != ARM_PMAP_MAX_OFFSET_DEFAULT) {
		assert(max_offset_ret >= min_max_offset);
	}

	return max_offset_ret;
}

vm_map_offset_t
pmap_max_32bit_offset(
	unsigned int option)
{
	vm_map_offset_t max_offset_ret = 0;

	if (option == ARM_PMAP_MAX_OFFSET_DEFAULT) {
		max_offset_ret = arm_pmap_max_offset_default;
	} else if (option == ARM_PMAP_MAX_OFFSET_MIN) {
		max_offset_ret = VM_MAX_ADDRESS;
	} else if (option == ARM_PMAP_MAX_OFFSET_MAX) {
		max_offset_ret = VM_MAX_ADDRESS;
	} else if (option == ARM_PMAP_MAX_OFFSET_DEVICE) {
		if (arm_pmap_max_offset_default) {
			max_offset_ret = arm_pmap_max_offset_default;
		} else if (max_mem > 0x20000000) {
			max_offset_ret = VM_MAX_ADDRESS;
		} else {
			max_offset_ret = VM_MAX_ADDRESS;
		}
	} else if (option == ARM_PMAP_MAX_OFFSET_JUMBO) {
		max_offset_ret = VM_MAX_ADDRESS;
	} else {
		panic("pmap_max_32bit_offset illegal option 0x%x", option);
	}

	assert(max_offset_ret <= MACH_VM_MAX_ADDRESS);
	return max_offset_ret;
}

#if CONFIG_DTRACE
/*
 * Constrain DTrace copyin/copyout actions
 */
extern kern_return_t dtrace_copyio_preflight(addr64_t);
extern kern_return_t dtrace_copyio_postflight(addr64_t);

kern_return_t
dtrace_copyio_preflight(
	__unused addr64_t va)
{
	if (current_map() == kernel_map) {
		return KERN_FAILURE;
	} else {
		return KERN_SUCCESS;
	}
}

kern_return_t
dtrace_copyio_postflight(
	__unused addr64_t va)
{
	return KERN_SUCCESS;
}
#endif /* CONFIG_DTRACE */


void
pmap_flush_context_init(__unused pmap_flush_context *pfc)
{
}


void
pmap_flush(
	__unused pmap_flush_context *cpus_to_flush)
{
	/* not implemented yet */
	return;
}

/**
 * Perform basic validation checks on the destination only and
 * corresponding offset/sizes prior to writing to a read only allocation.
 *
 * @note Should be called before writing to an allocation from the read
 * only allocator.
 *
 * @param zid The ID of the zone the allocation belongs to.
 * @param va VA of element being modified (destination).
 * @param offset Offset being written to, in the element.
 * @param new_data_size Size of modification.
 *
 */

MARK_AS_PMAP_TEXT static void
pmap_ro_zone_validate_element_dst(
	zone_id_t           zid,
	vm_offset_t         va,
	vm_offset_t         offset,
	vm_size_t           new_data_size)
{
	if (__improbable((zid < ZONE_ID__FIRST_RO) || (zid > ZONE_ID__LAST_RO))) {
		panic("%s: ZoneID %u outside RO range %u - %u", __func__, zid,
		    ZONE_ID__FIRST_RO, ZONE_ID__LAST_RO);
	}

	vm_size_t elem_size = zone_ro_size_params[zid].z_elem_size;

	/* Check element is from correct zone and properly aligned */
	zone_require_ro(zid, elem_size, (void*)va);

	if (__improbable(new_data_size > (elem_size - offset))) {
		panic("%s: New data size %lu too large for elem size %lu at addr %p",
		    __func__, (uintptr_t)new_data_size, (uintptr_t)elem_size, (void*)va);
	}
	if (__improbable(offset >= elem_size)) {
		panic("%s: Offset %lu too large for elem size %lu at addr %p",
		    __func__, (uintptr_t)offset, (uintptr_t)elem_size, (void*)va);
	}
}


/**
 * Perform basic validation checks on the source, destination and
 * corresponding offset/sizes prior to writing to a read only allocation.
 *
 * @note Should be called before writing to an allocation from the read
 * only allocator.
 *
 * @param zid The ID of the zone the allocation belongs to.
 * @param va VA of element being modified (destination).
 * @param offset Offset being written to, in the element.
 * @param new_data Pointer to new data (source).
 * @param new_data_size Size of modification.
 *
 */

MARK_AS_PMAP_TEXT static void
pmap_ro_zone_validate_element(
	zone_id_t           zid,
	vm_offset_t         va,
	vm_offset_t         offset,
	const vm_offset_t   new_data,
	vm_size_t           new_data_size)
{
	vm_offset_t sum = 0;

	if (__improbable(os_add_overflow(new_data, new_data_size, &sum))) {
		panic("%s: Integer addition overflow %p + %lu = %lu",
		    __func__, (void*)new_data, (uintptr_t)new_data_size, (uintptr_t)sum);
	}

	pmap_ro_zone_validate_element_dst(zid, va, offset, new_data_size);
}

/**
 * Function to configure RO zone access permissions for a forthcoming write operation.
 */
static void
pmap_ro_zone_prepare_write(void)
{
}

/**
 * Function to indicate that a preceding RO zone write operation is complete.
 */
static void
pmap_ro_zone_complete_write(void)
{
}

/**
 * Function to align an address or size to the required RO zone mapping alignment.
 *
 * For the SPTM the RO zone region must be aligned on a twig boundary so that at least
 * the last-level kernel pagetable can be of the appropriate SPTM RO zone table type,
 * which allows the SPTM to enforce RO zone mapping permission restrictions.
 *
 * @param value the address or size to be aligned.
 *
 * @return the aligned value
 */
vm_offset_t
pmap_ro_zone_align(vm_offset_t value)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(kernel_pmap);
	return PMAP_ALIGN(value, pt_attr_twig_size(pt_attr));
}

/**
 * Function to copy kauth_cred from new_data to kv.
 * Function defined in "kern_prot.c"
 *
 * @note Will be removed upon completion of
 * <rdar://problem/72635194> Compiler PAC support for memcpy.
 *
 * @param kv Address to copy new data to.
 * @param new_data Pointer to new data.
 *
 */

extern void
kauth_cred_copy(const uintptr_t kv, const uintptr_t new_data);

/**
 * Zalloc-specific memcpy that writes through the physical aperture
 * and ensures the element being modified is from a read-only zone.
 *
 * @note Designed to work only with the zone allocator's read-only submap.
 *
 * @param zid The ID of the zone to allocate from.
 * @param va VA of element to be modified.
 * @param offset Offset from element.
 * @param new_data Pointer to new data.
 * @param new_data_size	Size of modification.
 *
 */

void
pmap_ro_zone_memcpy(
	zone_id_t           zid,
	vm_offset_t         va,
	vm_offset_t         offset,
	const vm_offset_t   new_data,
	vm_size_t           new_data_size)
{
	pmap_ro_zone_memcpy_internal(zid, va, offset, new_data, new_data_size);
}

MARK_AS_PMAP_TEXT void
pmap_ro_zone_memcpy_internal(
	zone_id_t             zid,
	vm_offset_t           va,
	vm_offset_t           offset,
	const vm_offset_t     new_data,
	vm_size_t             new_data_size)
{
	const pmap_paddr_t pa = kvtophys_nofail(va + offset);

	if (!new_data || new_data_size == 0) {
		return;
	}

	pmap_ro_zone_validate_element(zid, va, offset, new_data, new_data_size);
	pmap_ro_zone_prepare_write();
	memcpy((void*)phystokv(pa), (void*)new_data, new_data_size);
	pmap_ro_zone_complete_write();
}

/**
 * Zalloc-specific function to atomically mutate fields of an element that
 * belongs to a read-only zone, via the physcial aperture.
 *
 * @note Designed to work only with the zone allocator's read-only submap.
 *
 * @param zid The ID of the zone the element belongs to.
 * @param va VA of element to be modified.
 * @param offset Offset in element.
 * @param op Atomic operation to perform.
 * @param value	Mutation value.
 *
 */

uint64_t
pmap_ro_zone_atomic_op(
	zone_id_t             zid,
	vm_offset_t           va,
	vm_offset_t           offset,
	zro_atomic_op_t       op,
	uint64_t              value)
{
	return pmap_ro_zone_atomic_op_internal(zid, va, offset, op, value);
}

MARK_AS_PMAP_TEXT uint64_t
pmap_ro_zone_atomic_op_internal(
	zone_id_t             zid,
	vm_offset_t           va,
	vm_offset_t           offset,
	zro_atomic_op_t       op,
	uint64_t              value)
{
	const pmap_paddr_t pa = kvtophys_nofail(va + offset);
	vm_size_t value_size = op & 0xf;

	pmap_ro_zone_validate_element_dst(zid, va, offset, value_size);
	pmap_ro_zone_prepare_write();
	value = __zalloc_ro_mut_atomic(phystokv(pa), op, value);
	pmap_ro_zone_complete_write();

	return value;
}

/**
 * bzero for allocations from read only zones, that writes through the
 * physical aperture.
 *
 * @note This is called by the zfree path of all allocations from read
 * only zones.
 *
 * @param zid The ID of the zone the allocation belongs to.
 * @param va VA of element to be zeroed.
 * @param offset Offset in the element.
 * @param size	Size of allocation.
 *
 */

void
pmap_ro_zone_bzero(
	zone_id_t       zid,
	vm_offset_t     va,
	vm_offset_t     offset,
	vm_size_t       size)
{
	pmap_ro_zone_bzero_internal(zid, va, offset, size);
}

MARK_AS_PMAP_TEXT void
pmap_ro_zone_bzero_internal(
	zone_id_t       zid,
	vm_offset_t     va,
	vm_offset_t     offset,
	vm_size_t       size)
{
	const pmap_paddr_t pa = kvtophys_nofail(va + offset);
	pmap_ro_zone_validate_element(zid, va, offset, 0, size);
	pmap_ro_zone_prepare_write();
	bzero((void*)phystokv(pa), size);
	pmap_ro_zone_complete_write();
}

#define PMAP_RESIDENT_INVALID   ((mach_vm_size_t)-1)

MARK_AS_PMAP_TEXT mach_vm_size_t
pmap_query_resident_internal(
	pmap_t                  pmap,
	vm_map_address_t        start,
	vm_map_address_t        end,
	mach_vm_size_t          *compressed_bytes_p)
{
	mach_vm_size_t  resident_bytes = 0;
	mach_vm_size_t  compressed_bytes = 0;

	pt_entry_t     *bpte, *epte;
	pt_entry_t     *pte_p;
	tt_entry_t     *tte_p;

	if (pmap == NULL) {
		return PMAP_RESIDENT_INVALID;
	}

	validate_pmap(pmap);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	/* Ensure that this request is valid, and addresses exactly one TTE. */
	if (__improbable((start % pt_attr_page_size(pt_attr)) ||
	    (end % pt_attr_page_size(pt_attr)))) {
		panic("%s: address range %p, %p not page-aligned to 0x%llx", __func__, (void*)start, (void*)end, pt_attr_page_size(pt_attr));
	}

	if (__improbable((end < start) || (end > ((start + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr))))) {
		panic("%s: invalid address range %p, %p", __func__, (void*)start, (void*)end);
	}

	pmap_lock(pmap, PMAP_LOCK_SHARED);
	tte_p = pmap_tte(pmap, start);
	if (tte_p == (tt_entry_t *) NULL) {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
		return PMAP_RESIDENT_INVALID;
	}
	if ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		pte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte = &pte_p[pte_index(pt_attr, start)];
		epte = &pte_p[pte_index(pt_attr, end)];

		for (; bpte < epte; bpte++) {
			if (pte_is_compressed(*bpte, bpte)) {
				compressed_bytes += pt_attr_page_size(pt_attr);
			} else if (pa_valid(pte_to_pa(*bpte))) {
				resident_bytes += pt_attr_page_size(pt_attr);
			}
		}
	}
	pmap_unlock(pmap, PMAP_LOCK_SHARED);

	if (compressed_bytes_p) {
		*compressed_bytes_p += compressed_bytes;
	}

	return resident_bytes;
}

mach_vm_size_t
pmap_query_resident(
	pmap_t                  pmap,
	vm_map_address_t        start,
	vm_map_address_t        end,
	mach_vm_size_t          *compressed_bytes_p)
{
	mach_vm_size_t          total_resident_bytes;
	mach_vm_size_t          compressed_bytes;
	vm_map_address_t        va;


	if (pmap == PMAP_NULL) {
		if (compressed_bytes_p) {
			*compressed_bytes_p = 0;
		}
		return 0;
	}

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	total_resident_bytes = 0;
	compressed_bytes = 0;

	PMAP_TRACE(3, PMAP_CODE(PMAP__QUERY_RESIDENT) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(start),
	    VM_KERNEL_ADDRHIDE(end));

	va = start;
	while (va < end) {
		vm_map_address_t l;
		mach_vm_size_t resident_bytes;

		l = ((va + pt_attr_twig_size(pt_attr)) & ~pt_attr_twig_offmask(pt_attr));

		if (l > end) {
			l = end;
		}
		resident_bytes = pmap_query_resident_internal(pmap, va, l, compressed_bytes_p);
		if (resident_bytes == PMAP_RESIDENT_INVALID) {
			break;
		}

		total_resident_bytes += resident_bytes;

		va = l;
	}

	if (compressed_bytes_p) {
		*compressed_bytes_p = compressed_bytes;
	}

	PMAP_TRACE(3, PMAP_CODE(PMAP__QUERY_RESIDENT) | DBG_FUNC_END,
	    total_resident_bytes);

	return total_resident_bytes;
}

#if MACH_ASSERT
static void
pmap_check_ledgers(
	pmap_t pmap)
{
	int     pid;
	char    *procname;

	if (pmap->pmap_pid == 0 || pmap->pmap_pid == -1) {
		/*
		 * This pmap was not or is no longer fully associated
		 * with a task (e.g. the old pmap after a fork()/exec() or
		 * spawn()).  Its "ledger" still points at a task that is
		 * now using a different (and active) address space, so
		 * we can't check that all the pmap ledgers are balanced here.
		 *
		 * If the "pid" is set, that means that we went through
		 * pmap_set_process() in task_terminate_internal(), so
		 * this task's ledger should not have been re-used and
		 * all the pmap ledgers should be back to 0.
		 */
		return;
	}

	pid = pmap->pmap_pid;
	procname = pmap->pmap_procname;

	vm_map_pmap_check_ledgers(pmap, pmap->ledger, pid, procname);
}
#endif /* MACH_ASSERT */

void
pmap_advise_pagezero_range(__unused pmap_t p, __unused uint64_t a)
{
}

/**
 * The minimum shared region nesting size is used by the VM to determine when to
 * break up large mappings to nested regions. The smallest size that these
 * mappings can be broken into is determined by what page table level those
 * regions are being nested in at and the size of the page tables.
 *
 * For instance, if a nested region is nesting at L2 for a process utilizing
 * 16KB page tables, then the minimum nesting size would be 32MB (size of an L2
 * block entry).
 *
 * @param pmap The target pmap to determine the block size based on whether it's
 *             using 16KB or 4KB page tables.
 */
uint64_t
pmap_shared_region_size_min(__unused pmap_t pmap)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	/**
	 * We always nest the shared region at L2 (32MB for 16KB pages, 2MB for
	 * 4KB pages). This means that a target pmap will contain L2 entries that
	 * point to shared L3 page tables in the shared region pmap.
	 */
	return pt_attr_twig_size(pt_attr);
}

boolean_t
pmap_enforces_execute_only(
	pmap_t pmap)
{
	return pmap != kernel_pmap;
}

MARK_AS_PMAP_TEXT void
pmap_set_vm_map_cs_enforced_internal(
	pmap_t pmap,
	bool new_value)
{
	validate_pmap_mutable(pmap);
	pmap->pmap_vm_map_cs_enforced = new_value;
}

void
pmap_set_vm_map_cs_enforced(
	pmap_t pmap,
	bool new_value)
{
	pmap_set_vm_map_cs_enforced_internal(pmap, new_value);
}

extern int cs_process_enforcement_enable;
bool
pmap_get_vm_map_cs_enforced(
	pmap_t pmap)
{
	if (cs_process_enforcement_enable) {
		return true;
	}
	return pmap->pmap_vm_map_cs_enforced;
}

MARK_AS_PMAP_TEXT void
pmap_set_jit_entitled_internal(
	__unused pmap_t pmap)
{
}

void
pmap_set_jit_entitled(
	pmap_t pmap)
{
	pmap_set_jit_entitled_internal(pmap);
}

bool
pmap_get_jit_entitled(
	__unused pmap_t pmap)
{
	return false;
}

MARK_AS_PMAP_TEXT void
pmap_set_tpro_internal(
	__unused pmap_t pmap)
{
	return;
}

void
pmap_set_tpro(
	pmap_t pmap)
{
	pmap_set_tpro_internal(pmap);
}

bool
pmap_get_tpro(
	__unused pmap_t pmap)
{
	return false;
}

uint64_t pmap_query_page_info_retries MARK_AS_PMAP_DATA;

MARK_AS_PMAP_TEXT kern_return_t
pmap_query_page_info_internal(
	pmap_t          pmap,
	vm_map_offset_t va,
	int             *disp_p)
{
	pmap_paddr_t    pa;
	int             disp;
	unsigned int    pai;
	pt_entry_t      *pte_p;
	pv_entry_t      *pve_p;

	if (pmap == PMAP_NULL || pmap == kernel_pmap) {
		*disp_p = 0;
		return KERN_INVALID_ARGUMENT;
	}

	validate_pmap(pmap);
	pmap_lock(pmap, PMAP_LOCK_SHARED);

try_again:
	disp = 0;

	pte_p = pmap_pte(pmap, va);
	if (pte_p == PT_ENTRY_NULL) {
		goto done;
	}

	const pt_entry_t pte = os_atomic_load(pte_p, relaxed);
	pa = pte_to_pa(pte);
	if (pa == 0) {
		if (pte_is_compressed(pte, pte_p)) {
			disp |= PMAP_QUERY_PAGE_COMPRESSED;
			if (pte & ARM_PTE_COMPRESSED_ALT) {
				disp |= PMAP_QUERY_PAGE_COMPRESSED_ALTACCT;
			}
		}
	} else {
		disp |= PMAP_QUERY_PAGE_PRESENT;
		pai = pa_index(pa);
		if (!pa_valid(pa)) {
			goto done;
		}
		locked_pvh_t locked_pvh = pvh_lock(pai);
		if (__improbable(pte != os_atomic_load(pte_p, relaxed))) {
			/* something changed: try again */
			pvh_unlock(&locked_pvh);
			pmap_query_page_info_retries++;
			goto try_again;
		}
		pve_p = PV_ENTRY_NULL;
		int pve_ptep_idx = 0;
		if (pvh_test_type(locked_pvh.pvh, PVH_TYPE_PVEP)) {
			pve_p = pvh_pve_list(locked_pvh.pvh);
			while (pve_p != PV_ENTRY_NULL &&
			    (pve_ptep_idx = pve_find_ptep_index(pve_p, pte_p)) == -1) {
				pve_p = pve_next(pve_p);
			}
		}

		if (ppattr_pve_is_altacct(pai, pve_p, pve_ptep_idx)) {
			disp |= PMAP_QUERY_PAGE_ALTACCT;
		} else if (ppattr_test_reusable(pai)) {
			disp |= PMAP_QUERY_PAGE_REUSABLE;
		} else if (ppattr_pve_is_internal(pai, pve_p, pve_ptep_idx)) {
			disp |= PMAP_QUERY_PAGE_INTERNAL;
		}
		pvh_unlock(&locked_pvh);
	}

done:
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
	*disp_p = disp;
	return KERN_SUCCESS;
}

kern_return_t
pmap_query_page_info(
	pmap_t          pmap,
	vm_map_offset_t va,
	int             *disp_p)
{
	return pmap_query_page_info_internal(pmap, va, disp_p);
}



uint32_t
pmap_user_va_bits(pmap_t pmap __unused)
{
#if __ARM_MIXED_PAGE_SIZE__
	uint64_t tcr_value = pmap_get_pt_attr(pmap)->pta_tcr_value;
	return 64 - ((tcr_value >> TCR_T0SZ_SHIFT) & TCR_TSZ_MASK);
#else
	return 64 - T0SZ_BOOT;
#endif
}

uint32_t
pmap_kernel_va_bits(void)
{
	return 64 - T1SZ_BOOT;
}

static vm_map_size_t
pmap_user_va_size(pmap_t pmap)
{
	return 1ULL << pmap_user_va_bits(pmap);
}


bool
pmap_in_ppl(void)
{
	return false;
}

MARK_AS_PMAP_TEXT void
pmap_footprint_suspend_internal(
	vm_map_t        map,
	boolean_t       suspend)
{
#if DEVELOPMENT || DEBUG
	if (suspend) {
		current_thread()->pmap_footprint_suspended = TRUE;
		map->pmap->footprint_was_suspended = TRUE;
	} else {
		current_thread()->pmap_footprint_suspended = FALSE;
	}
#else /* DEVELOPMENT || DEBUG */
	(void) map;
	(void) suspend;
#endif /* DEVELOPMENT || DEBUG */
}

void
pmap_footprint_suspend(
	vm_map_t map,
	boolean_t suspend)
{
	pmap_footprint_suspend_internal(map, suspend);
}

void
pmap_nop(pmap_t pmap)
{
	validate_pmap_mutable(pmap);
}

pmap_t
pmap_txm_kernel_pmap(void)
{
	return kernel_pmap;
}

TXMAddressSpace_t*
pmap_txm_addr_space(const pmap_t pmap)
{
	if (pmap) {
		return pmap->txm_addr_space;
	}

	/*
	 * When the passed in PMAP is NULL, it means the caller wishes to operate
	 * on the current_pmap(). We could resolve and return that, but it is actually
	 * safer to return NULL since these TXM interfaces also accept NULL inputs
	 * which causes TXM to resolve to the current_pmap() equivalent internally.
	 */
	return NULL;
}

void
pmap_txm_set_addr_space(
	pmap_t pmap,
	TXMAddressSpace_t *txm_addr_space)
{
	assert(pmap != NULL);

	if (pmap->txm_addr_space && txm_addr_space) {
		/* Attempted to overwrite the address space in the PMAP */
		panic("attempted ovewrite of TXM address space: %p | %p | %p",
		    pmap, pmap->txm_addr_space, txm_addr_space);
	} else if (!pmap->txm_addr_space && !txm_addr_space) {
		/* This should never happen */
		panic("attempted NULL overwrite of TXM address space: %p", pmap);
	}

	pmap->txm_addr_space = txm_addr_space;
}

void
pmap_txm_set_trust_level(
	pmap_t pmap,
	CSTrust_t trust_level)
{
	assert(pmap != NULL);

	CSTrust_t current_trust = pmap->txm_trust_level;
	if (current_trust != kCSTrustUntrusted) {
		panic("attempted to overwrite TXM trust on the pmap: %p", pmap);
	}

	pmap->txm_trust_level = trust_level;
}

kern_return_t
pmap_txm_get_trust_level_kdp(
	pmap_t pmap,
	CSTrust_t *trust_level)
{
	if (pmap == NULL) {
		return KERN_INVALID_ARGUMENT;
	} else if (ml_validate_nofault((vm_offset_t)pmap, sizeof(*pmap)) == false) {
		return KERN_INVALID_ARGUMENT;
	}

	if (trust_level != NULL) {
		*trust_level = pmap->txm_trust_level;
	}
	return KERN_SUCCESS;
}

static pmap_t
_pmap_txm_resolve_pmap(pmap_t pmap)
{
	if (pmap == NULL) {
		pmap = current_pmap();
		if (pmap == kernel_pmap) {
			return NULL;
		}
	}

	return pmap;
}

void
pmap_txm_acquire_shared_lock(pmap_t pmap)
{
	pmap = _pmap_txm_resolve_pmap(pmap);
	if (!pmap) {
		return;
	}

	lck_rw_lock_shared(&pmap->txm_lck);
}

void
pmap_txm_release_shared_lock(pmap_t pmap)
{
	pmap = _pmap_txm_resolve_pmap(pmap);
	if (!pmap) {
		return;
	}

	lck_rw_unlock_shared(&pmap->txm_lck);
}

void
pmap_txm_acquire_exclusive_lock(pmap_t pmap)
{
	pmap = _pmap_txm_resolve_pmap(pmap);
	if (!pmap) {
		return;
	}

	lck_rw_lock_exclusive(&pmap->txm_lck);
}

void
pmap_txm_release_exclusive_lock(pmap_t pmap)
{
	pmap = _pmap_txm_resolve_pmap(pmap);
	if (!pmap) {
		return;
	}

	lck_rw_unlock_exclusive(&pmap->txm_lck);
}

static void
_pmap_txm_transfer_page(const pmap_paddr_t addr)
{
	sptm_retype_params_t retype_params = {
		.raw = SPTM_RETYPE_PARAMS_NULL
	};

	/* Retype through the SPTM */
	sptm_retype(addr, XNU_DEFAULT, TXM_DEFAULT, retype_params);
}

/**
 * Prepare a page for retyping to TXM_DEFAULT by clearing its
 * internal flags.
 *
 * @param pa Physical address of the page.
 */
static inline void
_pmap_txm_retype_prepare(const pmap_paddr_t pa)
{
	const sptm_retype_params_t retype_params = {
		.raw = SPTM_RETYPE_PARAMS_NULL
	};

	/**
	 * SPTM allows XNU_DEFAULT pages to request deferral of TLB flushing
	 * when their PTE is updated, which is an important performance
	 * optimization. However, this also allows an attacker controlled
	 * XNU to exploit a read reference with a stale write-enabled PTE in
	 * TLB. This is fine as long as the page is not retyped and the damage
	 * will be contained within XNU domain. However, when such a page needs
	 * to be retyped, SPTM has to make sure there's no outstanding
	 * reference, or there's no history of deferring TLBIs. Internally,
	 * SPTM maintains a flag tracking past deferred TLBIs that only gets
	 * cleared on retyping with no outstanding reference. Therefore, we
	 * do a dummy retype to XNU_DEFAULT itself to clear the internal flag,
	 * before we actually transfer this page to TXM domain. To make sure
	 * SPTM won't throw a violation, all the mappings to the page have to
	 * be removed before calling this.
	 */
	sptm_retype(pa, XNU_DEFAULT, XNU_DEFAULT, retype_params);
}

/**
 * Transfer an XNU owned page to TXM domain.
 *
 * @param addr Kernel virtual address of the page. It has to be page size
 *             aligned.
 */
void
pmap_txm_transfer_page(const vm_address_t addr)
{
	assert((addr & PAGE_MASK) == 0);

	const pmap_paddr_t pa = kvtophys_nofail(addr);
	const unsigned int pai = pa_index(pa);

	/* Lock the PVH lock to prevent concurrent updates to the mappings during the self retype below. */
	locked_pvh_t locked_pvh = pvh_lock(pai);

	/* Disconnect the mapping to assure SPTM of no pending TLBI. */
	pmap_page_protect_options_with_flush_range((ppnum_t)atop(pa), VM_PROT_NONE,
	    PMAP_OPTIONS_PPO_PENDING_RETYPE, &locked_pvh, NULL);

	/* Self retype to clear the SPTM internal flags tracking delayed TLBIs for revoked writes. */
	_pmap_txm_retype_prepare(pa);

	pvh_unlock(&locked_pvh);

	/* XNU needs to hold an RO reference to the page despite the ownership being transferred to TXM. */
	pmap_enter_addr(kernel_pmap, addr, pa, VM_PROT_READ, VM_PROT_NONE, 0, true, PMAP_MAPPING_TYPE_INFER);

	/* Finally, retype the page to TXM_DEFAULT. */
	_pmap_txm_transfer_page(pa);
}

struct vm_object txm_vm_object_storage VM_PAGE_PACKED_ALIGNED;
SECURITY_READ_ONLY_LATE(vm_object_t) txm_vm_object = &txm_vm_object_storage;

_Static_assert(sizeof(vm_map_address_t) == sizeof(pmap_paddr_t),
    "sizeof(vm_map_address_t) != sizeof(pmap_paddr_t)");

vm_map_address_t
pmap_txm_allocate_page(void)
{
	pmap_paddr_t phys_addr = 0;
	vm_page_t page = VM_PAGE_NULL;
	boolean_t thread_vm_privileged = false;

	/* We are allowed to allocate privileged memory */
	thread_vm_privileged = set_vm_privilege(true);

	/* Allocate a page from the VM free list */
	while ((page = vm_page_grab()) == VM_PAGE_NULL) {
		VM_PAGE_WAIT();
	}

	/* Wire all of the pages allocated for TXM */
	vm_page_lock_queues();
	vm_page_wire(page, VM_KERN_MEMORY_SECURITY, TRUE);
	vm_page_unlock_queues();

	phys_addr = (pmap_paddr_t)ptoa(VM_PAGE_GET_PHYS_PAGE(page));
	if (phys_addr == 0) {
		panic("invalid VM page allocated for TXM: %llu", phys_addr);
	}

	/* Add the physical page to the TXM VM object */
	vm_object_lock(txm_vm_object);
	vm_page_insert_wired(
		page,
		txm_vm_object,
		phys_addr - gPhysBase,
		VM_KERN_MEMORY_SECURITY);
	vm_object_unlock(txm_vm_object);

	/* Reset thread privilege */
	set_vm_privilege(thread_vm_privileged);

	/* Retype the page */
	_pmap_txm_transfer_page(phys_addr);

	return phys_addr;
}

int
pmap_cs_configuration(void)
{
	code_signing_config_t config = 0;

	/* Compute the code signing configuration */
	code_signing_configuration(NULL, &config);

	return (int)config;
}

bool
pmap_performs_stage2_translations(
	__unused pmap_t pmap)
{
	return false;
}

bool
pmap_has_iofilter_protected_write(void)
{
	return false;
}

__attribute__((__noreturn__))
void
pmap_iofilter_protected_write(__unused vm_address_t addr, __unused uint64_t value, __unused uint64_t width)
{
	panic("%s to be implemented on SPTM.", __FUNCTION__);
}

void * __attribute__((noreturn))
pmap_claim_reserved_ppl_page(void)
{
	panic("%s: function not supported in this environment", __FUNCTION__);
}

void __attribute__((noreturn))
pmap_free_reserved_ppl_page(void __unused *kva)
{
	panic("%s: function not supported in this environment", __FUNCTION__);
}

bool
pmap_lookup_in_loaded_trust_caches(__unused const uint8_t cdhash[CS_CDHASH_LEN])
{
	kern_return_t kr = query_trust_cache(
		kTCQueryTypeLoadable,
		cdhash,
		NULL);

	if (kr == KERN_SUCCESS) {
		return true;
	}
	return false;
}

uint32_t
pmap_lookup_in_static_trust_cache(__unused const uint8_t cdhash[CS_CDHASH_LEN])
{
	TrustCacheQueryToken_t query_token = {0};
	kern_return_t kr = KERN_NOT_FOUND;
	uint64_t flags = 0;
	uint8_t hash_type = 0;

	kr = query_trust_cache(
		kTCQueryTypeStatic,
		cdhash,
		&query_token);

	if (kr == KERN_SUCCESS) {
		amfi->TrustCache.queryGetFlags(&query_token, &flags);
		amfi->TrustCache.queryGetHashType(&query_token, &hash_type);

		return (TC_LOOKUP_FOUND << TC_LOOKUP_RESULT_SHIFT) |
		       (hash_type << TC_LOOKUP_HASH_TYPE_SHIFT) |
		       ((uint8_t)flags << TC_LOOKUP_FLAGS_SHIFT);
	}

	return 0;
}

#if DEVELOPMENT || DEBUG

struct page_table_dump_header {
	uint64_t pa;
	uint64_t num_entries;
	uint64_t start_va;
	uint64_t end_va;
};

static kern_return_t
pmap_dump_page_tables_recurse(pmap_t pmap,
    const tt_entry_t *ttp,
    unsigned int cur_level,
    unsigned int level_mask,
    uint64_t start_va,
    void *buf_start,
    void *buf_end,
    size_t *bytes_copied)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	uint64_t num_entries = pt_attr_page_size(pt_attr) / sizeof(*ttp);

	uint64_t size = pt_attr->pta_level_info[cur_level].size;
	uint64_t valid_mask = pt_attr->pta_level_info[cur_level].valid_mask;
	uint64_t type_mask = pt_attr->pta_level_info[cur_level].type_mask;
	uint64_t type_block = pt_attr->pta_level_info[cur_level].type_block;

	void *bufp = (uint8_t*)buf_start + *bytes_copied;

	if (cur_level == pt_attr_root_level(pt_attr)) {
		start_va &= ~(pt_attr->pta_level_info[cur_level].offmask);
		num_entries = pmap_root_alloc_size(pmap) / sizeof(tt_entry_t);
	}

	uint64_t tt_size = num_entries * sizeof(tt_entry_t);
	const tt_entry_t *tt_end = &ttp[num_entries];

	if (((vm_offset_t)buf_end - (vm_offset_t)bufp) < (tt_size + sizeof(struct page_table_dump_header))) {
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}

	if (level_mask & (1U << cur_level)) {
		struct page_table_dump_header *header = (struct page_table_dump_header*)bufp;
		header->pa = kvtophys_nofail((vm_offset_t)ttp);
		header->num_entries = num_entries;
		header->start_va = start_va;
		header->end_va = start_va + (num_entries * size);

		bcopy(ttp, (uint8_t*)bufp + sizeof(*header), tt_size);
		*bytes_copied = *bytes_copied + sizeof(*header) + tt_size;
	}
	uint64_t current_va = start_va;

	for (const tt_entry_t *ttep = ttp; ttep < tt_end; ttep++, current_va += size) {
		tt_entry_t tte = *ttep;

		if (!(tte & valid_mask)) {
			continue;
		}

		if ((tte & type_mask) == type_block) {
			continue;
		} else {
			if (cur_level >= pt_attr_leaf_level(pt_attr)) {
				panic("%s: corrupt entry %#llx at %p, "
				    "ttp=%p, cur_level=%u, bufp=%p, buf_end=%p",
				    __FUNCTION__, tte, ttep,
				    ttp, cur_level, bufp, buf_end);
			}

			const tt_entry_t *next_tt = (const tt_entry_t*)phystokv(tte & ARM_TTE_TABLE_MASK);

			kern_return_t recurse_result = pmap_dump_page_tables_recurse(pmap, next_tt, cur_level + 1,
			    level_mask, current_va, buf_start, buf_end, bytes_copied);

			if (recurse_result != KERN_SUCCESS) {
				return recurse_result;
			}
		}
	}

	return KERN_SUCCESS;
}

kern_return_t
pmap_dump_page_tables(pmap_t pmap, void *bufp, void *buf_end, unsigned int level_mask, size_t *bytes_copied)
{
	if (not_in_kdp) {
		panic("pmap_dump_page_tables must only be called from kernel debugger context");
	}
	return pmap_dump_page_tables_recurse(pmap, pmap->tte, pt_attr_root_level(pmap_get_pt_attr(pmap)),
	           level_mask, pmap->min, bufp, buf_end, bytes_copied);
}

#else /* DEVELOPMENT || DEBUG */

kern_return_t
pmap_dump_page_tables(pmap_t pmap __unused, void *bufp __unused, void *buf_end __unused,
    unsigned int level_mask __unused, size_t *bytes_copied __unused)
{
	return KERN_NOT_SUPPORTED;
}
#endif /* !(DEVELOPMENT || DEBUG) */


#ifdef CONFIG_XNUPOST
static volatile bool pmap_test_took_fault = false;

static bool
pmap_test_fault_handler(arm_saved_state_t * state)
{
	bool retval                 = false;
	uint32_t esr                = get_saved_state_esr(state);
	esr_exception_class_t class = ESR_EC(esr);
	fault_status_t fsc          = ISS_IA_FSC(ESR_ISS(esr));

	if ((class == ESR_EC_DABORT_EL1) &&
	    ((fsc == FSC_PERMISSION_FAULT_L3) || (fsc == FSC_ACCESS_FLAG_FAULT_L3))) {
		pmap_test_took_fault = true;
		/* return to the instruction immediately after the call to NX page */
		set_saved_state_pc(state, get_saved_state_pc(state) + 4);
		retval = true;
	}

	return retval;
}

// Disable KASAN instrumentation, as the test pmap's TTBR0 space will not be in the shadow map
static NOKASAN bool
pmap_test_access(pmap_t pmap, vm_map_address_t va, bool should_fault, bool is_write)
{
	pmap_t old_pmap = NULL;

	pmap_test_took_fault = false;

	/*
	 * We're potentially switching pmaps without using the normal thread
	 * mechanism; disable interrupts and preemption to avoid any unexpected
	 * memory accesses.
	 */
	uint64_t old_int_state = pmap_interrupts_disable();
	mp_disable_preemption();

	if (pmap != NULL) {
		old_pmap = current_pmap();
		pmap_switch(pmap);

		/* Disable PAN; pmap shouldn't be the kernel pmap. */
#if __ARM_PAN_AVAILABLE__
		__builtin_arm_wsr("pan", 0);
#endif /* __ARM_PAN_AVAILABLE__ */
	}

	ml_expect_fault_begin(pmap_test_fault_handler, va);

	if (is_write) {
		*((volatile uint64_t*)(va)) = 0xdec0de;
	} else {
		volatile uint64_t tmp = *((volatile uint64_t*)(va));
		(void)tmp;
	}

	/* Save the fault bool, and undo the gross stuff we did. */
	bool took_fault = pmap_test_took_fault;
	ml_expect_fault_end();

	if (pmap != NULL) {
#if __ARM_PAN_AVAILABLE__
		__builtin_arm_wsr("pan", 1);
#endif /* __ARM_PAN_AVAILABLE__ */

		pmap_switch(old_pmap);
	}

	mp_enable_preemption();
	pmap_interrupts_restore(old_int_state);
	bool retval = (took_fault == should_fault);
	return retval;
}

static bool
pmap_test_read(pmap_t pmap, vm_map_address_t va, bool should_fault)
{
	bool retval = pmap_test_access(pmap, va, should_fault, false);

	if (!retval) {
		T_FAIL("%s: %s, "
		    "pmap=%p, va=%p, should_fault=%u",
		    __func__, should_fault ? "did not fault" : "faulted",
		    pmap, (void*)va, (unsigned)should_fault);
	}

	return retval;
}

static bool
pmap_test_write(pmap_t pmap, vm_map_address_t va, bool should_fault)
{
	bool retval = pmap_test_access(pmap, va, should_fault, true);

	if (!retval) {
		T_FAIL("%s: %s, "
		    "pmap=%p, va=%p, should_fault=%u",
		    __func__, should_fault ? "did not fault" : "faulted",
		    pmap, (void*)va, (unsigned)should_fault);
	}

	return retval;
}

static bool
pmap_test_check_refmod(pmap_paddr_t pa, unsigned int should_be_set)
{
	unsigned int should_be_clear = (~should_be_set) & (VM_MEM_REFERENCED | VM_MEM_MODIFIED);
	unsigned int bits = pmap_get_refmod((ppnum_t)atop(pa));

	bool retval = (((bits & should_be_set) == should_be_set) && ((bits & should_be_clear) == 0));

	if (!retval) {
		T_FAIL("%s: bits=%u, "
		    "pa=%p, should_be_set=%u",
		    __func__, bits,
		    (void*)pa, should_be_set);
	}

	return retval;
}

static __attribute__((noinline)) bool
pmap_test_read_write(pmap_t pmap, vm_map_address_t va, bool allow_read, bool allow_write)
{
	bool retval = (pmap_test_read(pmap, va, !allow_read) | pmap_test_write(pmap, va, !allow_write));
	return retval;
}

static int
pmap_test_test_config(unsigned int flags)
{
	T_LOG("running pmap_test_test_config flags=0x%X", flags);
	unsigned int map_count = 0;
	unsigned long page_ratio = 0;
	pmap_t pmap = pmap_create_options(NULL, 0, flags);

	if (!pmap) {
		panic("Failed to allocate pmap");
	}

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	uintptr_t native_page_size = pt_attr_page_size(native_pt_attr);
	uintptr_t pmap_page_size = pt_attr_page_size(pt_attr);
	uintptr_t pmap_twig_size = pt_attr_twig_size(pt_attr);

	if (pmap_page_size <= native_page_size) {
		page_ratio = native_page_size / pmap_page_size;
	} else {
		/*
		 * We claim to support a page_ratio of less than 1, which is
		 * not currently supported by the pmap layer; panic.
		 */
		panic("%s: page_ratio < 1, native_page_size=%lu, pmap_page_size=%lu"
		    "flags=%u",
		    __func__, native_page_size, pmap_page_size,
		    flags);
	}

	if (PAGE_RATIO > 1) {
		/*
		 * The kernel is deliberately pretending to have 16KB pages.
		 * The pmap layer has code that supports this, so pretend the
		 * page size is larger than it is.
		 */
		pmap_page_size = PAGE_SIZE;
		native_page_size = PAGE_SIZE;
	}

	/*
	 * Get two pages from the VM; one to be mapped wired, and one to be
	 * mapped nonwired.
	 */
	vm_page_t unwired_vm_page = vm_page_grab();
	vm_page_t wired_vm_page = vm_page_grab();

	if ((unwired_vm_page == VM_PAGE_NULL) || (wired_vm_page == VM_PAGE_NULL)) {
		panic("Failed to grab VM pages");
	}

	ppnum_t pn = VM_PAGE_GET_PHYS_PAGE(unwired_vm_page);
	ppnum_t wired_pn = VM_PAGE_GET_PHYS_PAGE(wired_vm_page);

	pmap_paddr_t pa = ptoa(pn);
	pmap_paddr_t wired_pa = ptoa(wired_pn);

	/*
	 * We'll start mappings at the second twig TT.  This keeps us from only
	 * using the first entry in each TT, which would trivially be address
	 * 0; one of the things we will need to test is retrieving the VA for
	 * a given PTE.
	 */
	vm_map_address_t va_base = pmap_twig_size;
	vm_map_address_t wired_va_base = ((2 * pmap_twig_size) - pmap_page_size);

	if (wired_va_base < (va_base + (page_ratio * pmap_page_size))) {
		/*
		 * Not exactly a functional failure, but this test relies on
		 * there being a spare PTE slot we can use to pin the TT.
		 */
		panic("Cannot pin translation table");
	}

	/*
	 * Create the wired mapping; this will prevent the pmap layer from
	 * reclaiming our test TTs, which would interfere with this test
	 * ("interfere" -> "make it panic").
	 */
	pmap_enter_addr(pmap, wired_va_base, wired_pa, VM_PROT_READ, VM_PROT_READ, 0, true, PMAP_MAPPING_TYPE_INFER);

	T_LOG("Validate that kernel cannot write to SPTM memory.");
	pt_entry_t * ptep = pmap_pte(pmap, va_base);
	pmap_test_write(NULL, (vm_map_address_t)ptep, true);

	/*
	 * Create read-only mappings of the nonwired page; if the pmap does
	 * not use the same page size as the kernel, create multiple mappings
	 * so that the kernel page is fully mapped.
	 */
	for (map_count = 0; map_count < page_ratio; map_count++) {
		pmap_enter_addr(pmap, va_base + (pmap_page_size * map_count), pa + (pmap_page_size * (map_count)),
		    VM_PROT_READ, VM_PROT_READ, 0, false, PMAP_MAPPING_TYPE_INFER);
	}

	/* Validate that all the PTEs have the expected PA and VA. */
	for (map_count = 0; map_count < page_ratio; map_count++) {
		ptep = pmap_pte(pmap, va_base + (pmap_page_size * map_count));

		if (pte_to_pa(*ptep) != (pa + (pmap_page_size * map_count))) {
			T_FAIL("Unexpected pa=%p, expected %p, map_count=%u",
			    (void*)pte_to_pa(*ptep), (void*)(pa + (pmap_page_size * map_count)), map_count);
		}

		if (ptep_get_va(ptep) != (va_base + (pmap_page_size * map_count))) {
			T_FAIL("Unexpected va=%p, expected %p, map_count=%u",
			    (void*)ptep_get_va(ptep), (void*)(va_base + (pmap_page_size * map_count)), map_count);
		}
	}

	T_LOG("Validate that reads to our mapping do not fault.");
	pmap_test_read(pmap, va_base, false);

	T_LOG("Validate that writes to our mapping fault.");
	pmap_test_write(pmap, va_base, true);

	T_LOG("Make the first mapping writable.");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false, PMAP_MAPPING_TYPE_INFER);

	T_LOG("Validate that writes to our mapping do not fault.");
	pmap_test_write(pmap, va_base, false);

	/*
	 * For page ratios of greater than 1: validate that writes to the other
	 * mappings still fault.  Remove the mappings afterwards (we're done
	 * with page ratio testing).
	 */
	for (map_count = 1; map_count < page_ratio; map_count++) {
		pmap_test_write(pmap, va_base + (pmap_page_size * map_count), true);
		pmap_remove(pmap, va_base + (pmap_page_size * map_count), va_base + (pmap_page_size * map_count) + pmap_page_size);
	}

	/* Remove remaining mapping */
	pmap_remove(pmap, va_base, va_base + pmap_page_size);

	T_LOG("Make the first mapping execute-only");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_EXECUTE, VM_PROT_EXECUTE, 0, false, PMAP_MAPPING_TYPE_INFER);


	T_LOG("Validate that reads to our mapping do not fault.");
	pmap_test_read(pmap, va_base, false);

	T_LOG("Validate that reads to our mapping do not fault.");
	pmap_test_read(pmap, va_base, false);

	T_LOG("Validate that writes to our mapping fault.");
	pmap_test_write(pmap, va_base, true);

	pmap_remove(pmap, va_base, va_base + pmap_page_size);

	T_LOG("Mark the page unreferenced and unmodified.");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_test_check_refmod(pa, 0);

	/*
	 * Begin testing the ref/mod state machine.  Re-enter the mapping with
	 * different protection/fault_type settings, and confirm that the
	 * ref/mod state matches our expectations at each step.
	 */
	T_LOG("!ref/!mod: read, no fault.  Expect ref/!mod");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ, VM_PROT_NONE, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("!ref/!mod: read, read fault.  Expect ref/!mod");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ, VM_PROT_READ, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("!ref/!mod: rw, read fault.  Expect ref/!mod");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("ref/!mod: rw, read fault.  Expect ref/!mod");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("!ref/!mod: rw, rw fault.  Expect ref/mod");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED | VM_MEM_MODIFIED);

	/*
	 * Shared memory testing; we'll have two mappings; one read-only,
	 * one read-write.
	 */
	vm_map_address_t rw_base = va_base;
	vm_map_address_t ro_base = va_base + pmap_page_size;

	pmap_enter_addr(pmap, rw_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_enter_addr(pmap, ro_base, pa, VM_PROT_READ, VM_PROT_READ, 0, false, PMAP_MAPPING_TYPE_INFER);

	/*
	 * Test that we take faults as expected for unreferenced/unmodified
	 * pages.  Also test the arm_fast_fault interface, to ensure that
	 * mapping permissions change as expected.
	 */
	T_LOG("!ref/!mod: expect no access");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_test_read_write(pmap, ro_base, false, false);
	pmap_test_read_write(pmap, rw_base, false, false);

	T_LOG("Read fault; expect !ref/!mod -> ref/!mod, read access");
	arm_fast_fault(pmap, rw_base, VM_PROT_READ, false, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, false);

	T_LOG("Write fault; expect ref/!mod -> ref/mod, read and write access");
	arm_fast_fault(pmap, rw_base, VM_PROT_READ | VM_PROT_WRITE, false, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED | VM_MEM_MODIFIED);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, true);

	T_LOG("Write fault; expect !ref/!mod -> ref/mod, read and write access");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	arm_fast_fault(pmap, rw_base, VM_PROT_READ | VM_PROT_WRITE, false, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED | VM_MEM_MODIFIED);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, true);

	T_LOG("RW protect both mappings; should not change protections.");
	pmap_protect(pmap, ro_base, ro_base + pmap_page_size, VM_PROT_READ | VM_PROT_WRITE);
	pmap_protect(pmap, rw_base, rw_base + pmap_page_size, VM_PROT_READ | VM_PROT_WRITE);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, true);

	T_LOG("Read protect both mappings; RW mapping should become RO.");
	pmap_protect(pmap, ro_base, ro_base + pmap_page_size, VM_PROT_READ);
	pmap_protect(pmap, rw_base, rw_base + pmap_page_size, VM_PROT_READ);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, false);

	T_LOG("RW protect the page; mappings should not change protections.");
	pmap_enter_addr(pmap, rw_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false, PMAP_MAPPING_TYPE_INFER);
	pmap_page_protect(pn, VM_PROT_ALL);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, true);

	T_LOG("Read protect the page; RW mapping should become RO.");
	pmap_page_protect(pn, VM_PROT_READ);
	pmap_test_read_write(pmap, ro_base, true, false);
	pmap_test_read_write(pmap, rw_base, true, false);

	T_LOG("Validate that disconnect removes all known mappings of the page.");
	pmap_disconnect(pn);
	if (!pmap_verify_free(pn)) {
		T_FAIL("Page still has mappings");
	}

#if defined(ARM_LARGE_MEMORY)
#define PMAP_TEST_LARGE_MEMORY_VA 64 * (1ULL << 40) /* 64 TB */

	T_LOG("Create new wired mapping in the extended address space enabled by ARM_LARGE_MEMORY.");
	pmap_enter_addr(pmap, PMAP_TEST_LARGE_MEMORY_VA, wired_pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, true, PMAP_MAPPING_TYPE_INFER);
	pmap_test_read_write(pmap, PMAP_TEST_LARGE_MEMORY_VA, true, true);
	pmap_remove(pmap, PMAP_TEST_LARGE_MEMORY_VA, PMAP_TEST_LARGE_MEMORY_VA + pmap_page_size);
#endif /* ARM_LARGE_MEMORY */

	T_LOG("Remove the wired mapping, so we can tear down the test map.");
	pmap_remove(pmap, wired_va_base, wired_va_base + pmap_page_size);
	pmap_destroy(pmap);

	T_LOG("Release the pages back to the VM.");
	vm_page_lock_queues();
	vm_page_free(unwired_vm_page);
	vm_page_free(wired_vm_page);
	vm_page_unlock_queues();

	T_LOG("Testing successful!");
	return 0;
}

kern_return_t
pmap_test(void)
{
	T_LOG("Starting pmap_tests");
	int flags = 0;
	flags |= PMAP_CREATE_64BIT;

#if __ARM_MIXED_PAGE_SIZE__ && !CONFIG_SPTM
	T_LOG("Testing VM_PAGE_SIZE_4KB");
	pmap_test_test_config(flags | PMAP_CREATE_FORCE_4K_PAGES);
	T_LOG("Testing VM_PAGE_SIZE_16KB");
	pmap_test_test_config(flags);
#else /* __ARM_MIXED_PAGE_SIZE__ */
	pmap_test_test_config(flags);
#endif /* __ARM_MIXED_PAGE_SIZE__ */

	T_PASS("completed pmap_test successfully");
	return KERN_SUCCESS;
}
#endif /* CONFIG_XNUPOST */

/*
 * The following function should never make it to RELEASE code, since
 * it provides a way to get the PPL to modify text pages.
 */
#if DEVELOPMENT || DEBUG

/**
 * Forcibly overwrite executable text with an illegal instruction.
 *
 * @note Only used for xnu unit testing.
 *
 * @param pa The physical address to corrupt.
 *
 * @return KERN_SUCCESS on success.
 */
kern_return_t
pmap_test_text_corruption(pmap_paddr_t pa __unused)
{
	/*
	 * SPTM TODO: implement an SPTM version of this.
	 * The physical apertue is owned by the SPTM and text
	 * pages have RO physical aperture mappings.
	 */
	return KERN_SUCCESS;
}

#endif /* DEVELOPMENT || DEBUG */
