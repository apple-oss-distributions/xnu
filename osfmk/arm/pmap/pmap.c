/*
 * Copyright (c) 2011-2021 Apple Inc. All rights reserved.
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

#include <libkern/img4/interface.h>
#include <libkern/amfi/amfi.h>
#include <libkern/section_keywords.h>
#include <sys/errno.h>
#include <sys/trust_caches.h>

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
#include <arm/pmap/pmap_internal.h>
#include <arm/trap.h>

#include <arm64/proc_reg.h>
#include <pexpert/arm64/boot.h>
#include <arm64/ppl/sart.h>
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

#ifdef __ARM64_PMAP_SUBPAGE_L1__
#define PMAP_ROOT_ALLOC_SIZE (((ARM_TT_L1_INDEX_MASK >> ARM_TT_L1_SHIFT) + 1) * sizeof(tt_entry_t))
#else
#define PMAP_ROOT_ALLOC_SIZE (ARM_PGBYTES)
#endif

#if __ARM_VMSA__ != 8
#error Unknown __ARM_VMSA__
#endif

#define ARRAY_LEN(x) (sizeof (x) / sizeof (x[0]))

extern u_int32_t random(void); /* from <libkern/libkern.h> */

static bool alloc_asid(pmap_t pmap);
static void free_asid(pmap_t pmap);
static void flush_mmu_tlb_region_asid_async(vm_offset_t va, size_t length, pmap_t pmap, bool last_level_only);
static void flush_mmu_tlb_full_asid_async(pmap_t pmap);
static pt_entry_t wimg_to_pte(unsigned int wimg, pmap_paddr_t pa);

static const struct page_table_ops native_pt_ops =
{
	.alloc_id = alloc_asid,
	.free_id = free_asid,
	.flush_tlb_region_async = flush_mmu_tlb_region_asid_async,
	.flush_tlb_async = flush_mmu_tlb_full_asid_async,
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


SECURITY_READ_ONLY_LATE(int) srd_fused = 0;

/*
 * Represents a tlb range that will be flushed before exiting
 * the ppl.
 * Used by phys_attribute_clear_range to defer flushing pages in
 * this range until the end of the operation.
 */
typedef struct pmap_tlb_flush_range {
	pmap_t ptfr_pmap;
	vm_map_address_t ptfr_start;
	vm_map_address_t ptfr_end;
	bool ptfr_flush_needed;
} pmap_tlb_flush_range_t;

#if XNU_MONITOR
/*
 * PPL External References.
 */
extern vm_offset_t   segPPLDATAB;
extern unsigned long segSizePPLDATA;
extern vm_offset_t   segPPLTEXTB;
extern unsigned long segSizePPLTEXT;
extern vm_offset_t   segPPLDATACONSTB;
extern unsigned long segSizePPLDATACONST;


/*
 * PPL Global Variables
 */

#if (DEVELOPMENT || DEBUG) || CONFIG_CSR_FROM_DT
/* Indicates if the PPL will enforce mapping policies; set by -unsafe_kernel_text */
SECURITY_READ_ONLY_LATE(boolean_t) pmap_ppl_disable = FALSE;
#else
const boolean_t pmap_ppl_disable = FALSE;
#endif

/*
 * Indicates if the PPL has started applying APRR.
 * This variable is accessed from various assembly trampolines, so be sure to change
 * those if you change the size or layout of this variable.
 */
boolean_t pmap_ppl_locked_down MARK_AS_PMAP_DATA = FALSE;

extern void *pmap_stacks_start;
extern void *pmap_stacks_end;

#endif /* !XNU_MONITOR */



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
MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(tt1_lock, 0);
queue_head_t    map_pmap_list MARK_AS_PMAP_DATA;

typedef struct tt_free_entry {
	struct tt_free_entry    *next;
} tt_free_entry_t;

#define TT_FREE_ENTRY_NULL      ((tt_free_entry_t *) 0)

tt_free_entry_t *free_page_size_tt_list MARK_AS_PMAP_DATA;
unsigned int    free_page_size_tt_count MARK_AS_PMAP_DATA;
unsigned int    free_page_size_tt_max MARK_AS_PMAP_DATA;
#define FREE_PAGE_SIZE_TT_MAX   4
tt_free_entry_t *free_two_page_size_tt_list MARK_AS_PMAP_DATA;
unsigned int    free_two_page_size_tt_count MARK_AS_PMAP_DATA;
unsigned int    free_two_page_size_tt_max MARK_AS_PMAP_DATA;
#define FREE_TWO_PAGE_SIZE_TT_MAX       4
tt_free_entry_t *free_tt_list MARK_AS_PMAP_DATA;
unsigned int    free_tt_count MARK_AS_PMAP_DATA;
unsigned int    free_tt_max MARK_AS_PMAP_DATA;

#define TT_FREE_ENTRY_NULL      ((tt_free_entry_t *) 0)

unsigned int    inuse_user_ttepages_count MARK_AS_PMAP_DATA = 0;        /* non-root, non-leaf user pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_user_ptepages_count MARK_AS_PMAP_DATA = 0;        /* leaf user pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_user_tteroot_count MARK_AS_PMAP_DATA = 0;  /* root user pagetables, in units of PMAP_ROOT_ALLOC_SIZE */
unsigned int    inuse_kernel_ttepages_count MARK_AS_PMAP_DATA = 0; /* non-root, non-leaf kernel pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_kernel_ptepages_count MARK_AS_PMAP_DATA = 0; /* leaf kernel pagetable pages, in units of PAGE_SIZE */
unsigned int    inuse_kernel_tteroot_count MARK_AS_PMAP_DATA = 0; /* root kernel pagetables, in units of PMAP_ROOT_ALLOC_SIZE */

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
#if defined(__arm64__)
#  ifdef XNU_TARGET_OS_OSX
SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm64_pmap_max_offset_default = MACH_VM_MAX_ADDRESS;
#  else
SECURITY_READ_ONLY_LATE(vm_map_offset_t) arm64_pmap_max_offset_default = 0x0;
#  endif
#endif /* __arm64__ */

#if PMAP_PANIC_DEV_WIMG_ON_MANAGED && (DEVELOPMENT || DEBUG)
SECURITY_READ_ONLY_LATE(boolean_t)   pmap_panic_dev_wimg_on_managed = TRUE;
#else
SECURITY_READ_ONLY_LATE(boolean_t)   pmap_panic_dev_wimg_on_managed = FALSE;
#endif

MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(asid_lock, 0);
SECURITY_READ_ONLY_LATE(uint32_t) pmap_max_asids = 0;
SECURITY_READ_ONLY_LATE(int) pmap_asid_plru = 1;
SECURITY_READ_ONLY_LATE(uint16_t) asid_chunk_size = 0;
SECURITY_READ_ONLY_LATE(static bitmap_t*) asid_bitmap;
static bitmap_t asid_plru_bitmap[BITMAP_LEN(MAX_HW_ASIDS)] MARK_AS_PMAP_DATA;
static uint64_t asid_plru_generation[BITMAP_LEN(MAX_HW_ASIDS)] MARK_AS_PMAP_DATA = {0};
static uint64_t asid_plru_gencount MARK_AS_PMAP_DATA = 0;


#if __ARM_MIXED_PAGE_SIZE__
SECURITY_READ_ONLY_LATE(pmap_t) sharedpage_pmap_4k;
#endif
SECURITY_READ_ONLY_LATE(pmap_t) sharedpage_pmap_default;
SECURITY_READ_ONLY_LATE(static vm_address_t) sharedpage_text_kva = 0;
SECURITY_READ_ONLY_LATE(static vm_address_t) sharedpage_ro_data_kva = 0;

/* PTE Define Macros */

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

static inline void
pte_set_wired(pmap_t pmap, pt_entry_t *ptep, boolean_t wired)
{
	if (wired) {
		*ptep |= ARM_PTE_WIRED;
	} else {
		*ptep &= ~ARM_PTE_WIRED;
	}
	/*
	 * Do not track wired page count for kernel pagetable pages.  Kernel mappings are
	 * not guaranteed to have PTDs in the first place, and kernel pagetable pages are
	 * never reclaimed.
	 */
	if (pmap == kernel_pmap) {
		return;
	}
	unsigned short *ptd_wiredcnt_ptr;
	ptd_wiredcnt_ptr = &(ptep_get_info(ptep)->wiredcnt);
	if (wired) {
		os_atomic_add(ptd_wiredcnt_ptr, (unsigned short)1, relaxed);
	} else {
		unsigned short prev_wired = os_atomic_sub_orig(ptd_wiredcnt_ptr, (unsigned short)1, relaxed);
		if (__improbable(prev_wired == 0)) {
			panic("pmap %p (pte %p): wired count underflow", pmap, ptep);
		}
	}
}

#define PMAP_UPDATE_TLBS(pmap, s, e, strong, last_level_only) {                                       \
	pmap_get_pt_ops(pmap)->flush_tlb_region_async(s, (size_t)((e) - (s)), pmap, last_level_only); \
	arm64_sync_tlb(strong);                                                                        \
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
 * Writes enough page table entries to map a single VM page and then ensures
 * those writes complete by executing a Data Synchronization Barrier. This
 * barrier provides stronger guarantees than the DMB executed by write_pte().
 *
 * @note This function is useful if you're going to immediately flush the TLB
 *       after making the PTE write. A DSB is required to protect against the
 *       TLB invalidate being reordered before the PTE write.
 *
 * See the function header for write_pte_fast() for more details on the
 * parameters.
 */
static void
write_pte_strong(pt_entry_t *ptep, pt_entry_t pte)
{
	write_pte_fast(ptep, pte);
	FLUSH_PTE_STRONG();
}

/**
 * Retrieve the pmap structure for the thread running on the current CPU.
 */
pmap_t
current_pmap()
{
	const pmap_t current = vm_map_pmap(current_thread()->map);

	assert(current != NULL);

#if XNU_MONITOR
	/**
	 * On PPL-enabled systems, it's important that PPL policy decisions aren't
	 * decided by kernel-writable memory. This function is used in various parts
	 * of the PPL, and besides validating that the pointer returned by this
	 * function is indeed a pmap structure, it's also important to ensure that
	 * it's actually the current thread's pmap. This is because different pmaps
	 * will have access to different entitlements based on the code signature of
	 * their loaded process. So if a different user pmap is set in the current
	 * thread structure (in an effort to bypass code signing restrictions), even
	 * though the structure would validate correctly as it is a real pmap
	 * structure, it should fail here.
	 *
	 * This only needs to occur for user pmaps because the kernel pmap's root
	 * page table is always the same as TTBR1 (it's set during bootstrap and not
	 * changed so it'd be redundant to check), and its code signing fields are
	 * always set to NULL. The PMAP CS logic won't operate on the kernel pmap so
	 * it shouldn't be possible to set those fields. Due to that, an attacker
	 * setting the current thread's pmap to the kernel pmap as a way to bypass
	 * this check won't accomplish anything as it doesn't provide any extra code
	 * signing entitlements.
	 */
	if ((current != kernel_pmap) &&
	    ((get_mmu_ttb() & TTBR_BADDR_MASK) != (current->ttep))) {
		panic_plain("%s: Current thread's pmap doesn't match up with TTBR0 "
		    "%#llx %#llx", __func__, get_mmu_ttb(), current->ttep);
	}
#endif /* XNU_MONITOR */

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

static void pmap_switch_user_ttb(pmap_t pmap, pmap_cpu_data_t *cpu_data_ptr);

static kern_return_t pmap_expand(
	pmap_t, vm_map_address_t, unsigned int options, unsigned int level);

static int pmap_remove_range(
	pmap_t, vm_map_address_t, pt_entry_t *, pt_entry_t *);

static tt_entry_t *pmap_tt1_allocate(
	pmap_t, vm_size_t, unsigned int);

#define PMAP_TT_ALLOCATE_NOWAIT         0x1

static void pmap_tt1_deallocate(
	pmap_t, tt_entry_t *, vm_size_t, unsigned int);

#define PMAP_TT_DEALLOCATE_NOBLOCK      0x1

static kern_return_t pmap_tt_allocate(
	pmap_t, tt_entry_t **, unsigned int, unsigned int);

#define PMAP_TT_ALLOCATE_NOWAIT         0x1

const unsigned int arm_hardware_page_size = ARM_PGBYTES;
const unsigned int arm_pt_desc_size = sizeof(pt_desc_t);
const unsigned int arm_pt_root_size = PMAP_ROOT_ALLOC_SIZE;

#define PMAP_TT_DEALLOCATE_NOBLOCK      0x1


static void pmap_unmap_sharedpage(
	pmap_t pmap);

static boolean_t
pmap_is_64bit(pmap_t);


static void pmap_flush_tlb_for_paddr_locked_async(pmap_paddr_t);

static void pmap_update_pp_attr_wimg_bits_locked(unsigned int, unsigned int);

static bool pmap_update_cache_attributes_locked(
	ppnum_t, unsigned, bool);

static boolean_t arm_clear_fast_fault(
	ppnum_t ppnum,
	vm_prot_t fault_type,
	pt_entry_t *pte_p);

static void pmap_trim_self(pmap_t pmap);
static void pmap_trim_subord(pmap_t subord);


/*
 * Temporary prototypes, while we wait for pmap_enter to move to taking an
 * address instead of a page number.
 */
static kern_return_t
pmap_enter_addr(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired);

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
	__unused void   *arg);

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
	pmap_tlb_flush_range_t *flush_range);

/**
 * Definition of the states driving the batch cache attributes update
 * state machine.
 */
typedef struct {
	uint64_t page_index : 32,           /* The page index to be operated on */
	    state : 8,                      /* The current state of the update machine */
	    tlb_flush_pass_needed : 1,      /* Tracking whether the tlb flush pass is necessary */
	    rt_cache_flush_pass_needed : 1, /* Tracking whether the cache flush pass is necessary */
	:0;
} batch_set_cache_attr_state_t;

/* Possible values of the "state" field. */
#define PMAP_BATCH_SET_CACHE_ATTRIBUTES_UPDATE_PASS             1
#define PMAP_BATCH_SET_CACHE_ATTRIBUTES_TLBFLUSH_PASS           2
#define PMAP_BATCH_SET_CACHE_ATTRIBUTES_CACHEFLUSH_PASS         3
#define PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE                    4

static_assert(sizeof(batch_set_cache_attr_state_t) == sizeof(uint64_t));

PMAP_SUPPORT_PROTOTYPES(
	batch_set_cache_attr_state_t,
	pmap_batch_set_cache_attributes, (
#if XNU_MONITOR
		volatile upl_page_info_t *user_page_list,
#else /* !XNU_MONITOR */
		upl_page_info_array_t user_page_list,
#endif /* XNU_MONITOR */
		batch_set_cache_attr_state_t state,
		unsigned int page_cnt,
		unsigned int cacheattr), PMAP_BATCH_SET_CACHE_ATTRIBUTES_INDEX);

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
	unsigned int options), PMAP_ENTER_OPTIONS_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	pmap_paddr_t,
	pmap_find_pa, (pmap_t pmap,
	addr64_t va), PMAP_FIND_PA_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_insert_sharedpage, (pmap_t pmap), PMAP_INSERT_SHAREDPAGE_INDEX);


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
	unsigned int cacheattr), PMAP_SET_CACHE_ATTRIBUTES_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_update_compressor_page, (ppnum_t pn,
	unsigned int prev_cacheattr, unsigned int new_cacheattr), PMAP_UPDATE_COMPRESSOR_PAGE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_nested, (pmap_t pmap), PMAP_SET_NESTED_INDEX);

#if MACH_ASSERT || XNU_MONITOR
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

#if __has_feature(ptrauth_calls) && defined(XNU_TARGET_OS_OSX)
PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_disable_user_jop, (pmap_t pmap), PMAP_DISABLE_USER_JOP_INDEX);
#endif /* __has_feature(ptrauth_calls) && defined(XNU_TARGET_OS_OSX) */

/* Definition of the states used by pmap_trim(). */
typedef enum {
	/* Validates the inputs and computes the bounds of the pmaps. This state can also jump directly to DONE state in some cases. */
	PMAP_TRIM_STATE_START = 0,

	/* Trims the range from the start of the shared region to the "true" start of that of the grand pmap. */
	PMAP_TRIM_STATE_GRAND_BEFORE,

	/* Trims the range from the "true" end of the shared region to the end of that of the grand pmap. */
	PMAP_TRIM_STATE_GRAND_AFTER,

	/* Decreases the subord's "no-bound" reference by one. If that becomes zero, trims the subord. */
	PMAP_TRIM_STATE_SUBORD,

	/* Marks that trimming is finished. */
	PMAP_TRIM_STATE_DONE,

	/* Sentry enum for sanity checks. */
	PMAP_TRIM_STATE_COUNT,
} pmap_trim_state_t;

PMAP_SUPPORT_PROTOTYPES(
	pmap_trim_state_t,
	pmap_trim, (pmap_t grand, pmap_t subord, addr64_t vstart, uint64_t size, pmap_trim_state_t state), PMAP_TRIM_INDEX);

#if HAS_APPLE_PAC
PMAP_SUPPORT_PROTOTYPES(
	void *,
	pmap_sign_user_ptr, (void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key), PMAP_SIGN_USER_PTR);
PMAP_SUPPORT_PROTOTYPES(
	void *,
	pmap_auth_user_ptr, (void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key), PMAP_AUTH_USER_PTR);
#endif /* HAS_APPLE_PAC */




PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_load_trust_cache_with_type, (TCType_t type,
	const vm_address_t pmap_img4_payload,
	const vm_size_t pmap_img4_payload_len,
	const vm_address_t img4_manifest,
	const vm_size_t img4_manifest_len,
	const vm_address_t img4_aux_manifest,
	const vm_size_t img4_aux_manifest_len), PMAP_LOAD_TRUST_CACHE_WITH_TYPE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_toggle_developer_mode, (bool state), PMAP_TOGGLE_DEVELOPER_MODE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_query_trust_cache, (TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t * query_token), PMAP_QUERY_TRUST_CACHE_INDEX);

#if PMAP_CS_INCLUDE_CODE_SIGNING

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_register_provisioning_profile, (const vm_address_t payload_addr,
	const vm_size_t payload_size), PMAP_REGISTER_PROVISIONING_PROFILE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_unregister_provisioning_profile, (pmap_cs_profile_t * profile_obj),
	PMAP_UNREGISTER_PROVISIONING_PROFILE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_associate_provisioning_profile, (pmap_cs_code_directory_t * cd_entry,
	pmap_cs_profile_t * profile_obj),
	PMAP_ASSOCIATE_PROVISIONING_PROFILE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_disassociate_provisioning_profile, (pmap_cs_code_directory_t * cd_entry),
	PMAP_DISASSOCIATE_PROVISIONING_PROFILE_INDEX);

#endif

PMAP_SUPPORT_PROTOTYPES(
	uint32_t,
	pmap_lookup_in_static_trust_cache, (const uint8_t cdhash[CS_CDHASH_LEN]), PMAP_LOOKUP_IN_STATIC_TRUST_CACHE_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	bool,
	pmap_lookup_in_loaded_trust_caches, (const uint8_t cdhash[CS_CDHASH_LEN]), PMAP_LOOKUP_IN_LOADED_TRUST_CACHES_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_compilation_service_cdhash, (const uint8_t cdhash[CS_CDHASH_LEN]),
	PMAP_SET_COMPILATION_SERVICE_CDHASH_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	bool,
	pmap_match_compilation_service_cdhash, (const uint8_t cdhash[CS_CDHASH_LEN]),
	PMAP_MATCH_COMPILATION_SERVICE_CDHASH_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_set_local_signing_public_key, (const uint8_t public_key[PMAP_ECC_P384_PUBLIC_KEY_SIZE]),
	PMAP_SET_LOCAL_SIGNING_PUBLIC_KEY_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_unrestrict_local_signing, (const uint8_t cdhash[CS_CDHASH_LEN]),
	PMAP_UNRESTRICT_LOCAL_SIGNING_INDEX);

PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_nop, (pmap_t pmap), PMAP_NOP_INDEX);

void pmap_footprint_suspend(vm_map_t    map,
    boolean_t   suspend);
PMAP_SUPPORT_PROTOTYPES(
	void,
	pmap_footprint_suspend, (vm_map_t map,
	boolean_t suspend),
	PMAP_FOOTPRINT_SUSPEND_INDEX);





#if DEVELOPMENT || DEBUG
PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	pmap_test_text_corruption, (pmap_paddr_t),
	PMAP_TEST_TEXT_CORRUPTION_INDEX);
#endif /* DEVELOPMENT || DEBUG */

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


long long alloc_tteroot_count __attribute__((aligned(8))) MARK_AS_PMAP_DATA = 0LL;
long long alloc_ttepages_count __attribute__((aligned(8))) MARK_AS_PMAP_DATA = 0LL;
long long alloc_ptepages_count __attribute__((aligned(8))) MARK_AS_PMAP_DATA = 0LL;

#if XNU_MONITOR

#if __has_feature(ptrauth_calls)
#define __ptrauth_ppl_handler __ptrauth(ptrauth_key_function_pointer, true, 0)
#else
#define __ptrauth_ppl_handler
#endif

/*
 * Table of function pointers used for PPL dispatch.
 */
const void * __ptrauth_ppl_handler const ppl_handler_table[PMAP_COUNT] = {
	[ARM_FAST_FAULT_INDEX] = arm_fast_fault_internal,
	[ARM_FORCE_FAST_FAULT_INDEX] = arm_force_fast_fault_internal,
	[MAPPING_FREE_PRIME_INDEX] = mapping_free_prime_internal,
	[PHYS_ATTRIBUTE_CLEAR_INDEX] = phys_attribute_clear_internal,
	[PHYS_ATTRIBUTE_SET_INDEX] = phys_attribute_set_internal,
	[PMAP_BATCH_SET_CACHE_ATTRIBUTES_INDEX] = pmap_batch_set_cache_attributes_internal,
	[PMAP_CHANGE_WIRING_INDEX] = pmap_change_wiring_internal,
	[PMAP_CREATE_INDEX] = pmap_create_options_internal,
	[PMAP_DESTROY_INDEX] = pmap_destroy_internal,
	[PMAP_ENTER_OPTIONS_INDEX] = pmap_enter_options_internal,
	[PMAP_FIND_PA_INDEX] = pmap_find_pa_internal,
	[PMAP_INSERT_SHAREDPAGE_INDEX] = pmap_insert_sharedpage_internal,
	[PMAP_IS_EMPTY_INDEX] = pmap_is_empty_internal,
	[PMAP_MAP_CPU_WINDOWS_COPY_INDEX] = pmap_map_cpu_windows_copy_internal,
	[PMAP_RO_ZONE_MEMCPY_INDEX] = pmap_ro_zone_memcpy_internal,
	[PMAP_RO_ZONE_ATOMIC_OP_INDEX] = pmap_ro_zone_atomic_op_internal,
	[PMAP_RO_ZONE_BZERO_INDEX] = pmap_ro_zone_bzero_internal,
	[PMAP_MARK_PAGE_AS_PMAP_PAGE_INDEX] = pmap_mark_page_as_ppl_page_internal,
	[PMAP_NEST_INDEX] = pmap_nest_internal,
	[PMAP_PAGE_PROTECT_OPTIONS_INDEX] = pmap_page_protect_options_internal,
	[PMAP_PROTECT_OPTIONS_INDEX] = pmap_protect_options_internal,
	[PMAP_QUERY_PAGE_INFO_INDEX] = pmap_query_page_info_internal,
	[PMAP_QUERY_RESIDENT_INDEX] = pmap_query_resident_internal,
	[PMAP_REFERENCE_INDEX] = pmap_reference_internal,
	[PMAP_REMOVE_OPTIONS_INDEX] = pmap_remove_options_internal,
	[PMAP_SET_CACHE_ATTRIBUTES_INDEX] = pmap_set_cache_attributes_internal,
	[PMAP_UPDATE_COMPRESSOR_PAGE_INDEX] = pmap_update_compressor_page_internal,
	[PMAP_SET_NESTED_INDEX] = pmap_set_nested_internal,
	[PMAP_SET_PROCESS_INDEX] = pmap_set_process_internal,
	[PMAP_SWITCH_INDEX] = pmap_switch_internal,
	[PMAP_CLEAR_USER_TTB_INDEX] = pmap_clear_user_ttb_internal,
	[PMAP_UNMAP_CPU_WINDOWS_COPY_INDEX] = pmap_unmap_cpu_windows_copy_internal,
	[PMAP_UNNEST_OPTIONS_INDEX] = pmap_unnest_options_internal,
	[PMAP_FOOTPRINT_SUSPEND_INDEX] = pmap_footprint_suspend_internal,
	[PMAP_CPU_DATA_INIT_INDEX] = pmap_cpu_data_init_internal,
	[PMAP_RELEASE_PAGES_TO_KERNEL_INDEX] = pmap_release_ppl_pages_to_kernel_internal,
	[PMAP_SET_VM_MAP_CS_ENFORCED_INDEX] = pmap_set_vm_map_cs_enforced_internal,
	[PMAP_SET_JIT_ENTITLED_INDEX] = pmap_set_jit_entitled_internal,
	[PMAP_SET_TPRO_INDEX] = pmap_set_tpro_internal,
	[PMAP_LOOKUP_IN_STATIC_TRUST_CACHE_INDEX] = pmap_lookup_in_static_trust_cache_internal,
	[PMAP_LOOKUP_IN_LOADED_TRUST_CACHES_INDEX] = pmap_lookup_in_loaded_trust_caches_internal,
	[PMAP_SET_COMPILATION_SERVICE_CDHASH_INDEX] = pmap_set_compilation_service_cdhash_internal,
	[PMAP_MATCH_COMPILATION_SERVICE_CDHASH_INDEX] = pmap_match_compilation_service_cdhash_internal,
	[PMAP_SET_LOCAL_SIGNING_PUBLIC_KEY_INDEX] = pmap_set_local_signing_public_key_internal,
	[PMAP_UNRESTRICT_LOCAL_SIGNING_INDEX] = pmap_unrestrict_local_signing_internal,
	[PMAP_LOAD_TRUST_CACHE_WITH_TYPE_INDEX] = pmap_load_trust_cache_with_type_internal,
	[PMAP_QUERY_TRUST_CACHE_INDEX] = pmap_query_trust_cache_internal,
	[PMAP_TOGGLE_DEVELOPER_MODE_INDEX] = pmap_toggle_developer_mode_internal,
#if PMAP_CS_INCLUDE_CODE_SIGNING
	[PMAP_REGISTER_PROVISIONING_PROFILE_INDEX] = pmap_register_provisioning_profile_internal,
	[PMAP_UNREGISTER_PROVISIONING_PROFILE_INDEX] = pmap_unregister_provisioning_profile_internal,
	[PMAP_ASSOCIATE_PROVISIONING_PROFILE_INDEX] = pmap_associate_provisioning_profile_internal,
	[PMAP_DISASSOCIATE_PROVISIONING_PROFILE_INDEX] = pmap_disassociate_provisioning_profile_internal,
#endif
	[PMAP_TRIM_INDEX] = pmap_trim_internal,
	[PMAP_LEDGER_VERIFY_SIZE_INDEX] = pmap_ledger_verify_size_internal,
	[PMAP_LEDGER_ALLOC_INDEX] = pmap_ledger_alloc_internal,
	[PMAP_LEDGER_FREE_INDEX] = pmap_ledger_free_internal,
#if HAS_APPLE_PAC
	[PMAP_SIGN_USER_PTR] = pmap_sign_user_ptr_internal,
	[PMAP_AUTH_USER_PTR] = pmap_auth_user_ptr_internal,
#endif /* HAS_APPLE_PAC */
#if __ARM_RANGE_TLBI__
	[PHYS_ATTRIBUTE_CLEAR_RANGE_INDEX] = phys_attribute_clear_range_internal,
#endif /* __ARM_RANGE_TLBI__ */
#if __has_feature(ptrauth_calls) && defined(XNU_TARGET_OS_OSX)
	[PMAP_DISABLE_USER_JOP_INDEX] = pmap_disable_user_jop_internal,
#endif /* __has_feature(ptrauth_calls) && defined(XNU_TARGET_OS_OSX) */
	[PMAP_NOP_INDEX] = pmap_nop_internal,

#if DEVELOPMENT || DEBUG
	[PMAP_TEST_TEXT_CORRUPTION_INDEX] = pmap_test_text_corruption_internal,
#endif /* DEVELOPMENT || DEBUG */

};
#endif

#if XNU_MONITOR
/**
 * A convenience function for setting protections on a single physical
 * aperture or static region mapping without invalidating the TLB.
 *
 * @note This function does not perform any TLB invalidations. That must be done
 *       separately to be able to safely use the updated mapping.
 *
 * @note This function understands the difference between the VM page size and
 *       the kernel page size and will update multiple PTEs if the sizes differ.
 *       In other words, enough PTEs will always get updated to change the
 *       permissions on a PAGE_SIZE amount of memory.
 *
 * @note The PVH lock for the physical page represented by this mapping must
 *       already be locked.
 *
 * @note This function assumes the caller has already verified that the PTE
 *       pointer does indeed point to a physical aperture or static region page
 *       table. Please validate your inputs before passing it along to this
 *       function.
 *
 * @param ptep Pointer to the physical aperture or static region page table to
 *             update with a new XPRR index.
 * @param expected_perm The XPRR index that is expected to already exist at the
 *                      current mapping. If the current index doesn't match this
 *                      then the system will panic.
 * @param new_perm The new XPRR index to update the mapping with.
 */
MARK_AS_PMAP_TEXT static void
pmap_set_pte_xprr_perm(
	pt_entry_t * const ptep,
	unsigned int expected_perm,
	unsigned int new_perm)
{
	assert(ptep != NULL);

	pt_entry_t spte = *ptep;
	pvh_assert_locked(pa_index(pte_to_pa(spte)));

	if (__improbable((new_perm > XPRR_MAX_PERM) || (expected_perm > XPRR_MAX_PERM))) {
		panic_plain("%s: invalid XPRR index, ptep=%p, new_perm=%u, expected_perm=%u",
		    __func__, ptep, new_perm, expected_perm);
	}

	/**
	 * The PTE involved should be valid, should not have the hint bit set, and
	 * should have the expected XPRR index.
	 */
	if (__improbable((spte & ARM_PTE_TYPE_MASK) == ARM_PTE_TYPE_FAULT)) {
		panic_plain("%s: physical aperture or static region PTE is invalid, "
		    "ptep=%p, spte=%#llx, new_perm=%u, expected_perm=%u",
		    __func__, ptep, spte, new_perm, expected_perm);
	}

	if (__improbable(spte & ARM_PTE_HINT_MASK)) {
		panic_plain("%s: physical aperture or static region PTE has hint bit "
		    "set, ptep=%p, spte=0x%llx, new_perm=%u, expected_perm=%u",
		    __func__, ptep, spte, new_perm, expected_perm);
	}

	if (__improbable(pte_to_xprr_perm(spte) != expected_perm)) {
		panic("%s: perm=%llu does not match expected_perm, spte=0x%llx, "
		    "ptep=%p, new_perm=%u, expected_perm=%u",
		    __func__, pte_to_xprr_perm(spte), spte, ptep, new_perm, expected_perm);
	}

	pt_entry_t template = spte;
	template &= ~ARM_PTE_XPRR_MASK;
	template |= xprr_perm_to_pte(new_perm);

	write_pte_strong(ptep, template);
}

/**
 * Update the protections on a single physical aperture mapping and invalidate
 * the TLB so the mapping can be used.
 *
 * @note The PVH lock for the physical page must already be locked.
 *
 * @param pai The physical address index of the page whose physical aperture
 *            mapping will be updated with new permissions.
 * @param expected_perm The XPRR index that is expected to already exist at the
 *                      current mapping. If the current index doesn't match this
 *                      then the system will panic.
 * @param new_perm The new XPRR index to update the mapping with.
 */
MARK_AS_PMAP_TEXT void
pmap_set_xprr_perm(
	unsigned int pai,
	unsigned int expected_perm,
	unsigned int new_perm)
{
	pvh_assert_locked(pai);

	const vm_offset_t kva = phystokv(vm_first_phys + (pmap_paddr_t)ptoa(pai));
	pt_entry_t * const ptep = pmap_pte(kernel_pmap, kva);

	pmap_set_pte_xprr_perm(ptep, expected_perm, new_perm);

	native_pt_ops.flush_tlb_region_async(kva, PAGE_SIZE, kernel_pmap, true);
	sync_tlb_flush();
}

/**
 * Update the protections on a range of physical aperture or static region
 * mappings and invalidate the TLB so the mappings can be used.
 *
 * @note Static region mappings can only be updated before machine_lockdown().
 *       Physical aperture mappings can be updated at any time.
 *
 * @param start The starting virtual address of the static region or physical
 *              aperture range whose permissions will be updated.
 * @param end The final (inclusive) virtual address of the static region or
 *            physical aperture range whose permissions will be updated.
 * @param expected_perm The XPRR index that is expected to already exist at the
 *                      current mappings. If the current indices don't match
 *                      this then the system will panic.
 * @param new_perm The new XPRR index to update the mappings with.
 */
MARK_AS_PMAP_TEXT static void
pmap_set_range_xprr_perm(
	vm_address_t start,
	vm_address_t end,
	unsigned int expected_perm,
	unsigned int new_perm)
{
	/**
	 * Validate our arguments; any invalid argument will be grounds for a panic.
	 */
	if (__improbable((start | end) & ARM_PGMASK)) {
		panic_plain("%s: start or end not page aligned, "
		    "start=%p, end=%p, new_perm=%u, expected_perm=%u",
		    __func__, (void *)start, (void *)end, new_perm, expected_perm);
	}

	if (__improbable(start > end)) {
		panic("%s: start > end, start=%p, end=%p, new_perm=%u, expected_perm=%u",
		    __func__, (void *)start, (void *)end, new_perm, expected_perm);
	}

	const bool in_physmap = (start >= physmap_base) && (end < physmap_end);
	const bool in_static = (start >= gVirtBase) && (end < static_memory_end);

	if (__improbable(!(in_physmap || in_static))) {
		panic_plain("%s: address not in static region or physical aperture, "
		    "start=%p, end=%p, new_perm=%u, expected_perm=%u",
		    __func__, (void *)start, (void *)end, new_perm, expected_perm);
	}

	if (__improbable((new_perm > XPRR_MAX_PERM) || (expected_perm > XPRR_MAX_PERM))) {
		panic_plain("%s: invalid XPRR index, "
		    "start=%p, end=%p, new_perm=%u, expected_perm=%u",
		    __func__, (void *)start, (void *)end, new_perm, expected_perm);
	}

	/*
	 * Walk over the PTEs for the given range, and set the protections on those
	 * PTEs. Each iteration of this loop will update all of the leaf PTEs within
	 * one twig entry (whichever twig entry currently maps "va").
	 */
	vm_address_t va = start;
	while (va < end) {
		/**
		 * Get the last VA that the twig entry for "va" maps. All of the leaf
		 * PTEs from va to tte_va_end will have their permissions updated.
		 */
		vm_address_t tte_va_end =
		    (va + pt_attr_twig_size(native_pt_attr)) & ~pt_attr_twig_offmask(native_pt_attr);

		if (tte_va_end > end) {
			tte_va_end = end;
		}

		tt_entry_t *ttep = pmap_tte(kernel_pmap, va);

		if (ttep == NULL) {
			panic_plain("%s: physical aperture or static region tte is NULL, "
			    "start=%p, end=%p, new_perm=%u, expected_perm=%u",
			    __func__, (void *)start, (void *)end, new_perm, expected_perm);
		}

		tt_entry_t tte = *ttep;

		if ((tte & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE) {
			panic_plain("%s: tte=0x%llx is not a table type entry, "
			    "start=%p, end=%p, new_perm=%u, expected_perm=%u", __func__,
			    tte, (void *)start, (void *)end, new_perm, expected_perm);
		}

		/* Walk over the given L3 page table page and update the PTEs. */
		pt_entry_t * const ptep = (pt_entry_t *)ttetokv(tte);
		pt_entry_t * const begin_ptep = &ptep[pte_index(native_pt_attr, va)];
		const uint64_t num_ptes = (tte_va_end - va) >> pt_attr_leaf_shift(native_pt_attr);
		pt_entry_t * const end_ptep = begin_ptep + num_ptes;

		/**
		 * The current PTE pointer is incremented by the page ratio (ratio of
		 * VM page size to kernel hardware page size) because one call to
		 * pmap_set_pte_xprr_perm() will update all PTE entries required to map
		 * a PAGE_SIZE worth of hardware pages.
		 */
		for (pt_entry_t *cur_ptep = begin_ptep; cur_ptep < end_ptep;
		    cur_ptep += PAGE_RATIO, va += PAGE_SIZE) {
			unsigned int pai = pa_index(pte_to_pa(*cur_ptep));
			pvh_lock(pai);
			pmap_set_pte_xprr_perm(cur_ptep, expected_perm, new_perm);
			pvh_unlock(pai);
		}

		va = tte_va_end;
	}

	PMAP_UPDATE_TLBS(kernel_pmap, start, end, false, true);
}

#endif /* XNU_MONITOR */

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
pmap_update_plru(uint16_t asid_index)
{
	if (__probable(pmap_asid_plru)) {
		unsigned plru_index = asid_index >> 6;
		if (__improbable(os_atomic_andnot(&asid_plru_bitmap[plru_index], (1ULL << (asid_index & 63)), relaxed) == 0)) {
			asid_plru_generation[plru_index] = ++asid_plru_gencount;
			asid_plru_bitmap[plru_index] = ((plru_index == (MAX_HW_ASIDS >> 6)) ? ~(1ULL << 63) : UINT64_MAX);
		}
	}
}

static bool
alloc_asid(pmap_t pmap)
{
	int vasid = -1;
	uint16_t hw_asid;

	pmap_simple_lock(&asid_lock);

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

		for (; plru_index < BITMAP_LEN(pmap_max_asids); plru_index += ((MAX_HW_ASIDS + 1) >> 6)) {
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
	pmap_simple_unlock(&asid_lock);
	hw_asid = (uint16_t)(vasid % asid_chunk_size);
	pmap->sw_asid = (uint8_t)(vasid / asid_chunk_size);
	if (__improbable(hw_asid == MAX_HW_ASIDS)) {
		/* If we took a PLRU "miss" and ended up with a hardware ASID we can't actually support,
		 * reassign to a reserved VASID. */
		assert(pmap->sw_asid < UINT8_MAX);
		pmap->sw_asid = UINT8_MAX;
		/* Allocate from the high end of the hardware ASID range to reduce the likelihood of
		 * aliasing with vital system processes, which are likely to have lower ASIDs. */
		hw_asid = MAX_HW_ASIDS - 1 - (uint16_t)(vasid / asid_chunk_size);
		assert(hw_asid < MAX_HW_ASIDS);
	}
	pmap_update_plru(hw_asid);
	hw_asid += 1;  // Account for ASID 0, which is reserved for the kernel
#if __ARM_KERNEL_PROTECT__
	hw_asid <<= 1;  // We're really handing out 2 hardware ASIDs, one for EL0 and one for EL1 access
#endif
	pmap->hw_asid = hw_asid;
	return true;
}

static void
free_asid(pmap_t pmap)
{
	unsigned int vasid;
	uint16_t hw_asid = os_atomic_xchg(&pmap->hw_asid, 0, relaxed);
	if (__improbable(hw_asid == 0)) {
		return;
	}

#if __ARM_KERNEL_PROTECT__
	hw_asid >>= 1;
#endif
	hw_asid -= 1;

	if (__improbable(pmap->sw_asid == UINT8_MAX)) {
		vasid = ((MAX_HW_ASIDS - 1 - hw_asid) * asid_chunk_size) + MAX_HW_ASIDS;
	} else {
		vasid = ((unsigned int)pmap->sw_asid * asid_chunk_size) + hw_asid;
	}

	if (__probable(pmap_asid_plru)) {
		os_atomic_or(&asid_plru_bitmap[hw_asid >> 6], (1ULL << (hw_asid & 63)), relaxed);
	}
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
		    prot, VM_PROT_NONE, flags, FALSE);

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

vm_map_address_t
pmap_map_bd_with_options(
	vm_map_address_t virt,
	vm_offset_t start,
	vm_offset_t end,
	vm_prot_t prot,
	int32_t options)
{
	pt_entry_t      tmplate;
	pt_entry_t     *ptep;
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

	tmplate = pa_to_pte(start) | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA) |
	    mem_attr | ARM_PTE_TYPE | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_AF;
#if __ARM_KERNEL_PROTECT__
	tmplate |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

	vaddr = virt;
	paddr = start;
	while (paddr < end) {
		ptep = pmap_pte(kernel_pmap, vaddr);
		if (ptep == PT_ENTRY_NULL) {
			panic("%s: no PTE for vaddr=%p, "
			    "virt=%p, start=%p, end=%p, prot=0x%x, options=0x%x",
			    __FUNCTION__, (void*)vaddr,
			    (void*)virt, (void*)start, (void*)end, prot, options);
		}

		assert(!ARM_PTE_IS_COMPRESSED(*ptep, ptep));
		write_pte_strong(ptep, tmplate);

		pte_increment_pa(tmplate);
		vaddr += PAGE_SIZE;
		paddr += PAGE_SIZE;
	}

	if (end >= start) {
		flush_mmu_tlb_region(virt, (unsigned)(end - start));
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
	pt_entry_t      tmplate;
	pt_entry_t              *ptep;
	vm_map_address_t vaddr;
	vm_offset_t             paddr;

	/* not cacheable and not buffered */
	tmplate = pa_to_pte(start)
	    | ARM_PTE_TYPE | ARM_PTE_AF | ARM_PTE_NX | ARM_PTE_PNX
	    | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWNA : AP_RONA)
	    | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
#if __ARM_KERNEL_PROTECT__
	tmplate |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */

	vaddr = virt;
	paddr = start;
	while (paddr < end) {
		ptep = pmap_pte(kernel_pmap, vaddr);
		if (ptep == PT_ENTRY_NULL) {
			panic("pmap_map_bd");
		}
		assert(!ARM_PTE_IS_COMPRESSED(*ptep, ptep));
		write_pte_strong(ptep, tmplate);

		pte_increment_pa(tmplate);
		vaddr += PAGE_SIZE;
		paddr += PAGE_SIZE;
	}

	if (end >= start) {
		flush_mmu_tlb_region(virt, (unsigned)(end - start));
	}

	return vaddr;
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
		assert(!ARM_PTE_IS_COMPRESSED(*ptep, ptep));
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
		assert(!ARM_PTE_IS_COMPRESSED(*ptep, ptep));
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
		    | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT);
		pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
#if __ARM_KERNEL_PROTECT__
		pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
		write_pte_strong(ptep, pte);
	}
	PMAP_UPDATE_TLBS(kernel_pmap, va_start, va_start + len, false, true);
#if KASAN
	kasan_notify_address(va_start, len);
#endif
	return va_start;
}

static uint32_t
pmap_compute_max_asids(void)
{
	DTEntry entry;
	void const *prop = NULL;
	uint32_t max_asids;
	int err;
	unsigned int prop_size;

	err = SecureDTLookupEntry(NULL, "/defaults", &entry);
	assert(err == kSuccess);

	if (kSuccess != SecureDTGetProperty(entry, "pmap-max-asids", &prop, &prop_size)) {
		/* TODO: consider allowing maxproc limits to be scaled earlier so that
		 * we can choose a more flexible default value here. */
		return MAX_ASIDS;
	}

	if (prop_size != sizeof(max_asids)) {
		panic("pmap-max-asids property is not a 32-bit integer");
	}

	max_asids = *((uint32_t const *)prop);
	/* Round up to the nearest 64 to make things a bit easier for the Pseudo-LRU allocator. */
	max_asids = (max_asids + 63) & ~63UL;

	if (((max_asids + MAX_HW_ASIDS) / (MAX_HW_ASIDS + 1)) > MIN(MAX_HW_ASIDS, UINT8_MAX)) {
		/* currently capped by size of pmap->sw_asid */
		panic("pmap-max-asids too large");
	}
	if (max_asids == 0) {
		panic("pmap-max-asids cannot be zero");
	}
	return max_asids;
}

#if __arm64__
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
#endif /* __arm64__ */

static void
pmap_set_srd_fusing()
{
	DTEntry entry;
	uint32_t const *prop = NULL;
	int err;
	unsigned int prop_size = 0;

	err = SecureDTLookupEntry(NULL, "/chosen", &entry);
	if (err != kSuccess) {
		panic("PMAP: no chosen DT node");
	}

	if (kSuccess == SecureDTGetProperty(entry, "research-enabled", (const void**)&prop, &prop_size)) {
		if (prop_size == sizeof(uint32_t)) {
			srd_fused = *prop;
		}
	}

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("srd_fusing", &srd_fused, sizeof(srd_fused));
#endif
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

	pmap_set_srd_fusing();

#if XNU_MONITOR

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("-unsafe_kernel_text", &pmap_ppl_disable, sizeof(pmap_ppl_disable));
#endif

#if CONFIG_CSR_FROM_DT
	if (csr_unsafe_kernel_text) {
		pmap_ppl_disable = true;
	}
#endif /* CONFIG_CSR_FROM_DT */

#endif /* XNU_MONITOR */

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
#if XNU_MONITOR
	os_atomic_init(&kernel_pmap->nested_count, 0);
#endif
	kernel_pmap->nx_enabled = TRUE;
#ifdef  __arm64__
	kernel_pmap->is_64bit = TRUE;
#else
	kernel_pmap->is_64bit = FALSE;
#endif
#if CONFIG_ROSETTA
	kernel_pmap->is_rosetta = FALSE;
#endif

#if ARM_PARAMETERIZED_PMAP
	kernel_pmap->pmap_pt_attr = native_pt_attr;
#endif /* ARM_PARAMETERIZED_PMAP */

	kernel_pmap->nested_region_addr = 0x0ULL;
	kernel_pmap->nested_region_size = 0x0ULL;
	kernel_pmap->nested_region_asid_bitmap = NULL;
	kernel_pmap->nested_region_asid_bitmap_size = 0x0UL;
	kernel_pmap->type = PMAP_TYPE_KERNEL;

	kernel_pmap->hw_asid = 0;
	kernel_pmap->sw_asid = 0;

	pmap_lock_init(kernel_pmap);

	pmap_max_asids = pmap_compute_max_asids();
	pmap_asid_plru = (pmap_max_asids > MAX_HW_ASIDS);
	PE_parse_boot_argn("pmap_asid_plru", &pmap_asid_plru, sizeof(pmap_asid_plru));
	/* Align the range of available hardware ASIDs to a multiple of 64 to enable the
	 * masking used by the PLRU scheme.  This means we must handle the case in which
	 * the returned hardware ASID is MAX_HW_ASIDS, which we do in alloc_asid() and free_asid(). */
	_Static_assert(sizeof(asid_plru_bitmap[0] == sizeof(uint64_t)), "bitmap_t is not a 64-bit integer");
	_Static_assert(((MAX_HW_ASIDS + 1) % 64) == 0, "MAX_HW_ASIDS + 1 is not divisible by 64");
	asid_chunk_size = (pmap_asid_plru ? (MAX_HW_ASIDS + 1) : MAX_HW_ASIDS);

	const vm_size_t asid_table_size = sizeof(*asid_bitmap) * BITMAP_LEN(pmap_max_asids);

	/**
	 * Bootstrap the core pmap data structures (e.g., pv_head_table,
	 * pp_attr_table, etc). This function will use `avail_start` to allocate
	 * space for these data structures.
	 */
	pmap_data_bootstrap();

	/**
	 * Bootstrap any necessary UAT data structures and values needed from the device tree.
	 */
	uat_bootstrap();


	/**
	 * Bootstrap any necessary SART data structures and values needed from the device tree.
	 */
	sart_bootstrap();

	/**
	 * Don't make any assumptions about the alignment of avail_start before this
	 * point (i.e., pmap_data_bootstrap() performs allocations).
	 */
	avail_start = PMAP_ALIGN(avail_start, __alignof(bitmap_t));

	const pmap_paddr_t pmap_struct_start = avail_start;

	asid_bitmap = (bitmap_t*)phystokv(avail_start);
	avail_start = round_page(avail_start + asid_table_size);

	memset((char *)phystokv(pmap_struct_start), 0, avail_start - pmap_struct_start);

	vm_first_phys = gPhysBase;
	vm_last_phys = trunc_page(avail_end);

	queue_init(&map_pmap_list);
	queue_enter(&map_pmap_list, kernel_pmap, pmap_t, pmaps);
	free_page_size_tt_list = TT_FREE_ENTRY_NULL;
	free_page_size_tt_count = 0;
	free_page_size_tt_max = 0;
	free_two_page_size_tt_list = TT_FREE_ENTRY_NULL;
	free_two_page_size_tt_count = 0;
	free_two_page_size_tt_max = 0;
	free_tt_list = TT_FREE_ENTRY_NULL;
	free_tt_count = 0;
	free_tt_max = 0;

	virtual_space_start = vstart;
	virtual_space_end = VM_MAX_KERNEL_ADDRESS;

	bitmap_full(&asid_bitmap[0], pmap_max_asids);
	bitmap_full(&asid_plru_bitmap[0], MAX_HW_ASIDS);
	// Clear the highest-order bit, which corresponds to MAX_HW_ASIDS + 1
	asid_plru_bitmap[MAX_HW_ASIDS >> 6] = ~(1ULL << 63);



	if (PE_parse_boot_argn("arm_maxoffset", &maxoffset, sizeof(maxoffset))) {
		maxoffset = trunc_page(maxoffset);
		if ((maxoffset >= pmap_max_offset(FALSE, ARM_PMAP_MAX_OFFSET_MIN))
		    && (maxoffset <= pmap_max_offset(FALSE, ARM_PMAP_MAX_OFFSET_MAX))) {
			arm_pmap_max_offset_default = maxoffset;
		}
	}
#if defined(__arm64__)
	if (PE_parse_boot_argn("arm64_maxoffset", &maxoffset, sizeof(maxoffset))) {
		maxoffset = trunc_page(maxoffset);
		if ((maxoffset >= pmap_max_offset(TRUE, ARM_PMAP_MAX_OFFSET_MIN))
		    && (maxoffset <= pmap_max_offset(TRUE, ARM_PMAP_MAX_OFFSET_MAX))) {
			arm64_pmap_max_offset_default = maxoffset;
		}
	}
#endif

	PE_parse_boot_argn("pmap_panic_dev_wimg_on_managed", &pmap_panic_dev_wimg_on_managed, sizeof(pmap_panic_dev_wimg_on_managed));


#if PMAP_CS_PPL_MONITOR
	/* Initialize the PPL trust cache read-write lock */
	lck_rw_init(&ppl_trust_cache_rt_lock, &pmap_lck_grp, 0);
	ppl_trust_cache_rt_lock.lck_rw_can_sleep = FALSE;
#endif

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

#if XNU_MONITOR

static inline void
pa_set_range_monitor(pmap_paddr_t start_pa, pmap_paddr_t end_pa)
{
	pmap_paddr_t cur_pa;
	for (cur_pa = start_pa; cur_pa < end_pa; cur_pa += ARM_PGBYTES) {
		assert(pa_valid(cur_pa));
		ppattr_pa_set_monitor(cur_pa);
	}
}

void
pa_set_range_xprr_perm(pmap_paddr_t start_pa,
    pmap_paddr_t end_pa,
    unsigned int expected_perm,
    unsigned int new_perm)
{
	vm_offset_t start_va = phystokv(start_pa);
	vm_offset_t end_va = start_va + (end_pa - start_pa);

	pa_set_range_monitor(start_pa, end_pa);
	pmap_set_range_xprr_perm(start_va, end_va, expected_perm, new_perm);
}

static void
pmap_lockdown_kc(void)
{
	extern vm_offset_t vm_kernelcache_base;
	extern vm_offset_t vm_kernelcache_top;
	pmap_paddr_t start_pa = kvtophys_nofail(vm_kernelcache_base);
	pmap_paddr_t end_pa = start_pa + (vm_kernelcache_top - vm_kernelcache_base);
	pmap_paddr_t cur_pa = start_pa;
	vm_offset_t cur_va = vm_kernelcache_base;
	while (cur_pa < end_pa) {
		vm_size_t range_size = end_pa - cur_pa;
		vm_offset_t ptov_va = phystokv_range(cur_pa, &range_size);
		if (ptov_va != cur_va) {
			/*
			 * If the physical address maps back to a virtual address that is non-linear
			 * w.r.t. the kernelcache, that means it corresponds to memory that will be
			 * reclaimed by the OS and should therefore not be locked down.
			 */
			cur_pa += range_size;
			cur_va += range_size;
			continue;
		}
		unsigned int pai = pa_index(cur_pa);
		pv_entry_t **pv_h  = pai_to_pvh(pai);

		vm_offset_t pvh_flags = pvh_get_flags(pv_h);

		if (__improbable(pvh_flags & PVH_FLAG_LOCKDOWN_MASK)) {
			panic("pai %d already locked down", pai);
		}

		pvh_set_flags(pv_h, pvh_flags | PVH_FLAG_LOCKDOWN_KC);
		cur_pa += ARM_PGBYTES;
		cur_va += ARM_PGBYTES;
	}
#if defined(KERNEL_INTEGRITY_CTRR) && defined(CONFIG_XNUPOST)
	extern uint64_t ctrr_ro_test;
	extern uint64_t ctrr_nx_test;
	pmap_paddr_t exclude_pages[] = {kvtophys_nofail((vm_offset_t)&ctrr_ro_test), kvtophys_nofail((vm_offset_t)&ctrr_nx_test)};
	for (unsigned i = 0; i < (sizeof(exclude_pages) / sizeof(exclude_pages[0])); ++i) {
		pv_entry_t **pv_h  = pai_to_pvh(pa_index(exclude_pages[i]));
		pvh_set_flags(pv_h, pvh_get_flags(pv_h) & ~PVH_FLAG_LOCKDOWN_KC);
	}
#endif
}

void
pmap_static_allocations_done(void)
{
	pmap_paddr_t monitor_start_pa;
	pmap_paddr_t monitor_end_pa;

	/*
	 * Protect the bootstrap (V=P and V->P) page tables.
	 *
	 * These bootstrap allocations will be used primarily for page tables.
	 * If we wish to secure the page tables, we need to start by marking
	 * these bootstrap allocations as pages that we want to protect.
	 */
	monitor_start_pa = kvtophys_nofail((vm_offset_t)&bootstrap_pagetables);
	monitor_end_pa = monitor_start_pa + BOOTSTRAP_TABLE_SIZE;

	/* The bootstrap page tables are mapped RW at boostrap. */
	pa_set_range_xprr_perm(monitor_start_pa, monitor_end_pa, XPRR_KERN_RW_PERM, XPRR_KERN_RO_PERM);

	/*
	 * We use avail_start as a pointer to the first address that has not
	 * been reserved for bootstrap, so we know which pages to give to the
	 * virtual memory layer.
	 */
	monitor_start_pa = BootArgs->topOfKernelData;
	monitor_end_pa = avail_start;

	/* The other bootstrap allocations are mapped RW at bootstrap. */
	pa_set_range_xprr_perm(monitor_start_pa, monitor_end_pa, XPRR_KERN_RW_PERM, XPRR_PPL_RW_PERM);

	/*
	 * The RO page tables are mapped RW in arm_vm_init() and later restricted
	 * to RO in arm_vm_prot_finalize(), which is called after this function.
	 * Here we only need to mark the underlying physical pages as PPL-owned to ensure
	 * they can't be allocated for other uses.  We don't need a special xPRR
	 * protection index, as there is no PPL_RO index, and these pages are ultimately
	 * protected by KTRR/CTRR.  Furthermore, use of PPL_RW for these pages would
	 * expose us to a functional issue on H11 devices where CTRR shifts the APRR
	 * lookup table index to USER_XO before APRR is applied, leading the hardware
	 * to believe we are dealing with an user XO page upon performing a translation.
	 */
	monitor_start_pa = kvtophys_nofail((vm_offset_t)&ropagetable_begin);
	monitor_end_pa = monitor_start_pa + ((vm_offset_t)&ropagetable_end - (vm_offset_t)&ropagetable_begin);
	pa_set_range_monitor(monitor_start_pa, monitor_end_pa);

	monitor_start_pa = kvtophys_nofail(segPPLDATAB);
	monitor_end_pa = monitor_start_pa + segSizePPLDATA;

	/* PPL data is RW for the PPL, RO for the kernel. */
	pa_set_range_xprr_perm(monitor_start_pa, monitor_end_pa, XPRR_KERN_RW_PERM, XPRR_PPL_RW_PERM);

	monitor_start_pa = kvtophys_nofail(segPPLTEXTB);
	monitor_end_pa = monitor_start_pa + segSizePPLTEXT;

	/* PPL text is RX for the PPL, RO for the kernel. */
	pa_set_range_xprr_perm(monitor_start_pa, monitor_end_pa, XPRR_KERN_RX_PERM, XPRR_PPL_RX_PERM);


	/*
	 * In order to support DTrace, the save areas for the PPL must be
	 * writable.  This is due to the fact that DTrace will try to update
	 * register state.
	 */
	if (pmap_ppl_disable) {
		vm_offset_t monitor_start_va = phystokv(ppl_cpu_save_area_start);
		vm_offset_t monitor_end_va = monitor_start_va + (ppl_cpu_save_area_end - ppl_cpu_save_area_start);

		pmap_set_range_xprr_perm(monitor_start_va, monitor_end_va, XPRR_PPL_RW_PERM, XPRR_KERN_RW_PERM);
	}


	if (segSizePPLDATACONST > 0) {
		monitor_start_pa = kvtophys_nofail(segPPLDATACONSTB);
		monitor_end_pa = monitor_start_pa + segSizePPLDATACONST;

		pa_set_range_xprr_perm(monitor_start_pa, monitor_end_pa, XPRR_KERN_RO_PERM, XPRR_KERN_RO_PERM);
	}

	/*
	 * Mark the original physical aperture mapping for the PPL stack pages RO as an additional security
	 * precaution.  The real RW mappings are at a different location with guard pages.
	 */
	pa_set_range_xprr_perm(pmap_stacks_start_pa, pmap_stacks_end_pa, XPRR_PPL_RW_PERM, XPRR_KERN_RO_PERM);

	/* Prevent remapping of the kernelcache */
	pmap_lockdown_kc();
}

void
pmap_lockdown_ppl(void)
{
	/* Mark the PPL as being locked down. */

	mp_disable_preemption(); // for _nopreempt locking operations
	pmap_ppl_lockdown_page(sharedpage_ro_data_kva, PVH_FLAG_LOCKDOWN_KC, false);
	if (sharedpage_text_kva != 0) {
		pmap_ppl_lockdown_page_with_prot(sharedpage_text_kva, PVH_FLAG_LOCKDOWN_KC,
		    false, VM_PROT_READ | VM_PROT_EXECUTE);
	}
	mp_enable_preemption();

	/* Write-protect the kernel RO commpage. */
#error "XPRR configuration error"
}
#endif /* XNU_MONITOR */

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
	*startp = LOW_GLOBAL_BASE_ADDRESS & ~ARM_TT_L2_OFFMASK;
	if (region_select == 0) {
		*size = ((KERNEL_PMAP_HEAP_RANGE_START - *startp) & ~PAGE_MASK);
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
	pv_entry_t **pvh = pai_to_pvh(pai);

	return pvh_test_type(pvh, PVH_TYPE_NULL);
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
	pv_entry_t **pvh = pai_to_pvh(pai);

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
		    __func__, pvh, pai);
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
		    __func__, pvh, pai);
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
	unsigned        i;
	unsigned        tte_index_max;
	pmap_t          p;
	bool is_64bit = flags & PMAP_CREATE_64BIT;
#if defined(HAS_APPLE_PAC)
	bool disable_jop = flags & PMAP_CREATE_DISABLE_JOP;
#endif /* defined(HAS_APPLE_PAC) */
	kern_return_t   local_kr = KERN_SUCCESS;

	if (size != 0) {
		{
			// Size parameter should only be set for stage 2.
			return PMAP_NULL;
		}
	}

	if (0 != (flags & ~PMAP_CREATE_KNOWN_FLAGS)) {
		return PMAP_NULL;
	}

#if XNU_MONITOR
	if ((local_kr = pmap_alloc_pmap(&p)) != KERN_SUCCESS) {
		goto pmap_create_fail;
	}

	assert(p != PMAP_NULL);

	if (ledger) {
		pmap_ledger_validate(ledger);
		pmap_ledger_retain(ledger);
	}
#else
	/*
	 *	Allocate a pmap struct from the pmap_zone.  Then allocate
	 *	the translation table of the right size for the pmap.
	 */
	if ((p = (pmap_t) zalloc(pmap_zone)) == PMAP_NULL) {
		local_kr = KERN_RESOURCE_SHORTAGE;
		goto pmap_create_fail;
	}
#endif

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


#if XNU_MONITOR
	p->tte = pmap_tt1_allocate(p, pmap_root_alloc_size(p), PMAP_TT_ALLOCATE_NOWAIT);
#else
	p->tte = pmap_tt1_allocate(p, pmap_root_alloc_size(p), 0);
#endif
	if (!(p->tte)) {
		local_kr = KERN_RESOURCE_SHORTAGE;
		goto tt1_alloc_fail;
	}

	p->ttep = ml_static_vtop((vm_offset_t)p->tte);
	PMAP_TRACE(4, PMAP_CODE(PMAP__TTE), VM_KERNEL_ADDRHIDE(p), VM_KERNEL_ADDRHIDE(p->min), VM_KERNEL_ADDRHIDE(p->max), p->ttep);

	/* nullify the translation table */
	for (i = 0; i < tte_index_max; i++) {
		p->tte[i] = ARM_TTE_TYPE_FAULT;
	}

	FLUSH_PTE();

	/*
	 *  initialize the rest of the structure
	 */
	p->nested_region_addr = 0x0ULL;
	p->nested_region_size = 0x0ULL;
	p->nested_region_asid_bitmap = NULL;
	p->nested_region_asid_bitmap_size = 0x0UL;

	p->nested_has_no_bounds_ref = false;
	p->nested_no_bounds_refcnt = 0;
	p->nested_bounds_set = false;


#if MACH_ASSERT
	p->pmap_stats_assert = TRUE;
	p->pmap_pid = 0;
	strlcpy(p->pmap_procname, "<nil>", sizeof(p->pmap_procname));
#endif /* MACH_ASSERT */
#if DEVELOPMENT || DEBUG
	p->footprint_was_suspended = FALSE;
#endif /* DEVELOPMENT || DEBUG */

#if XNU_MONITOR
	os_atomic_init(&p->nested_count, 0);
	assert(os_atomic_load(&p->ref_count, relaxed) == 0);
	/* Ensure prior updates to the new pmap are visible before the non-zero ref_count is visible */
	os_atomic_thread_fence(release);
#endif
	os_atomic_init(&p->ref_count, 1);
	pmap_simple_lock(&pmaps_lock);
	queue_enter(&map_pmap_list, p, pmap_t, pmaps);
	pmap_simple_unlock(&pmaps_lock);

	return p;

tt1_alloc_fail:
	pmap_get_pt_ops(p)->free_id(p);
id_alloc_fail:
#if XNU_MONITOR
	pmap_free_pmap(p);

	if (ledger) {
		pmap_ledger_release(ledger);
	}
#else
	zfree(pmap_zone, p);
#endif
pmap_create_fail:
#if XNU_MONITOR
	pmap_pin_kernel_pages((vm_offset_t)kr, sizeof(*kr));
#endif
	*kr = local_kr;
#if XNU_MONITOR
	pmap_unpin_kernel_pages((vm_offset_t)kr, sizeof(*kr));
#endif
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

#if XNU_MONITOR
	for (;;) {
		pmap = pmap_create_options_ppl(ledger, size, flags, &kr);
		if (kr != KERN_RESOURCE_SHORTAGE) {
			break;
		}
		assert(pmap == PMAP_NULL);
		pmap_alloc_page_for_ppl(0);
		kr = KERN_SUCCESS;
	}
#else
	pmap = pmap_create_options_internal(ledger, size, flags, &kr);
#endif

	if (pmap == PMAP_NULL) {
		ledger_dereference(ledger);
	}

	PMAP_TRACE(1, PMAP_CODE(PMAP__CREATE) | DBG_FUNC_END, VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), pmap->hw_asid);

	return pmap;
}

#if XNU_MONITOR
/*
 * This symbol remains in place when the PPL is enabled so that the dispatch
 * table does not change from development to release configurations.
 */
#endif
#if MACH_ASSERT || XNU_MONITOR
MARK_AS_PMAP_TEXT void
pmap_set_process_internal(
	__unused pmap_t pmap,
	__unused int pid,
	__unused char *procname)
{
#if MACH_ASSERT
	if (pmap == NULL || pmap->pmap_pid == -1) {
		return;
	}

	validate_pmap_mutable(pmap);

	pmap->pmap_pid = pid;
	strlcpy(pmap->pmap_procname, procname, sizeof(pmap->pmap_procname));
	if (pmap_ledgers_panic_leeway) {
		/*
		 * XXX FBDP
		 * Some processes somehow trigger some issues that make
		 * the pmap stats and ledgers go off track, causing
		 * some assertion failures and ledger panics.
		 * Turn off the sanity checks if we allow some ledger leeway
		 * because of that.  We'll still do a final check in
		 * pmap_check_ledgers() for discrepancies larger than the
		 * allowed leeway after the address space has been fully
		 * cleaned up.
		 */
		pmap->pmap_stats_assert = FALSE;
		ledger_disable_panic_on_negative(pmap->ledger,
		    task_ledgers.phys_footprint);
		ledger_disable_panic_on_negative(pmap->ledger,
		    task_ledgers.internal);
		ledger_disable_panic_on_negative(pmap->ledger,
		    task_ledgers.internal_compressed);
		ledger_disable_panic_on_negative(pmap->ledger,
		    task_ledgers.iokit_mapped);
		ledger_disable_panic_on_negative(pmap->ledger,
		    task_ledgers.alternate_accounting);
		ledger_disable_panic_on_negative(pmap->ledger,
		    task_ledgers.alternate_accounting_compressed);
	}
#endif /* MACH_ASSERT */
}
#endif /* MACH_ASSERT || XNU_MONITOR */

#if MACH_ASSERT
void
pmap_set_process(
	pmap_t pmap,
	int pid,
	char *procname)
{
#if XNU_MONITOR
	pmap_set_process_ppl(pmap, pid, procname);
#else
	pmap_set_process_internal(pmap, pid, procname);
#endif
}
#endif /* MACH_ASSERT */

/*
 * pmap_deallocate_all_leaf_tts:
 *
 * Recursive function for deallocating all leaf TTEs.  Walks the given TT,
 * removing and deallocating all TTEs.
 */
MARK_AS_PMAP_TEXT static void
pmap_deallocate_all_leaf_tts(pmap_t pmap, tt_entry_t * first_ttep, unsigned level)
{
	tt_entry_t tte = ARM_TTE_EMPTY;
	tt_entry_t * ttep = NULL;
	tt_entry_t * last_ttep = NULL;

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	assert(level < pt_attr_leaf_level(pt_attr));

	last_ttep = &first_ttep[ttn_index(pt_attr, ~0, level)];

	for (ttep = first_ttep; ttep <= last_ttep; ttep++) {
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
			pmap_deallocate_all_leaf_tts(pmap, (tt_entry_t *)phystokv((tte) & ARM_TTE_TABLE_MASK), level + 1);
		}

		/* Remove the TTE. */
		pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
		pmap_tte_deallocate(pmap, 0, 0, false, ttep, level);
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

#if XNU_MONITOR
	/*
	 * Issue a store-load barrier to ensure the checks of nested_count and the per-CPU
	 * pmaps below will not be speculated ahead of the decrement of ref_count above.
	 * That ensures that if the pmap is currently in use elsewhere, this path will
	 * either observe it in use and panic, or PMAP_VALIDATE_MUTABLE will observe a
	 * ref_count of 0 and panic.
	 */
	os_atomic_thread_fence(seq_cst);
	if (__improbable(os_atomic_load(&pmap->nested_count, relaxed) != 0)) {
		panic("pmap %p: attempt to destroy while nested", pmap);
	}
	const int max_cpu = ml_get_max_cpu_number();
	for (unsigned int i = 0; i <= max_cpu; ++i) {
		const pmap_cpu_data_t *cpu_data = pmap_get_remote_cpu_data(i);
		if (cpu_data == NULL) {
			continue;
		}
		if (__improbable(os_atomic_load(&cpu_data->inflight_pmap, relaxed) == pmap)) {
			panic("pmap %p: attempting to destroy while in-flight on cpu %llu", pmap, (uint64_t)i);
		} else if (__improbable(os_atomic_load(&cpu_data->active_pmap, relaxed) == pmap)) {
			panic("pmap %p: attempting to destroy while active on cpu %llu", pmap, (uint64_t)i);
		}
	}
#endif
	pmap_unmap_sharedpage(pmap);

	pmap_simple_lock(&pmaps_lock);
	queue_remove(&map_pmap_list, pmap, pmap_t, pmaps);
	pmap_simple_unlock(&pmaps_lock);

	pmap_trim_self(pmap);

	/*
	 *	Free the memory maps, then the
	 *	pmap structure.
	 */
	pmap_deallocate_all_leaf_tts(pmap, pmap->tte, pt_attr_root_level(pt_attr));



	if (pmap->tte) {
		pmap_tt1_deallocate(pmap, pmap->tte, pmap_root_alloc_size(pmap), 0);
		pmap->tte = (tt_entry_t *) NULL;
		pmap->ttep = 0;
	}

	assert((tt_free_entry_t*)pmap->tt_entry_free == NULL);

	if (__improbable(pmap->type == PMAP_TYPE_NESTED)) {
		pmap_get_pt_ops(pmap)->flush_tlb_region_async(pmap->nested_region_addr, pmap->nested_region_size, pmap, false);
		sync_tlb_flush();
	} else {
		pmap_get_pt_ops(pmap)->flush_tlb_async(pmap);
		sync_tlb_flush();
		/* return its asid to the pool */
		pmap_get_pt_ops(pmap)->free_id(pmap);
		if (pmap->nested_pmap != NULL) {
#if XNU_MONITOR
			os_atomic_dec(&pmap->nested_pmap->nested_count, relaxed);
#endif
			/* release the reference we hold on the nested pmap */
			pmap_destroy_internal(pmap->nested_pmap);
		}
	}

	pmap_check_ledgers(pmap);

	if (pmap->nested_region_asid_bitmap) {
#if XNU_MONITOR
		pmap_pages_free(kvtophys_nofail((vm_offset_t)(pmap->nested_region_asid_bitmap)), PAGE_SIZE);
#else
		kfree_data(pmap->nested_region_asid_bitmap,
		    pmap->nested_region_asid_bitmap_size * sizeof(unsigned int));
#endif
	}

#if XNU_MONITOR
	if (pmap->ledger) {
		pmap_ledger_release(pmap->ledger);
	}

	pmap_lock_destroy(pmap);
	pmap_free_pmap(pmap);
#else
	pmap_lock_destroy(pmap);
	zfree(pmap_zone, pmap);
#endif
}

void
pmap_destroy(
	pmap_t pmap)
{
	PMAP_TRACE(1, PMAP_CODE(PMAP__DESTROY) | DBG_FUNC_START, VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), pmap->hw_asid);

	ledger_t ledger = pmap->ledger;

#if XNU_MONITOR
	pmap_destroy_ppl(pmap);

	pmap_ledger_check_balance(pmap);
#else
	pmap_destroy_internal(pmap);
#endif

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
#if XNU_MONITOR
	pmap_reference_ppl(pmap);
#else
	pmap_reference_internal(pmap);
#endif
}

static tt_entry_t *
pmap_tt1_allocate(
	pmap_t          pmap,
	vm_size_t       size,
	unsigned        option)
{
	tt_entry_t      *tt1 = NULL;
	tt_free_entry_t *tt1_free;
	pmap_paddr_t    pa;
	vm_address_t    va;
	vm_address_t    va_end;
	kern_return_t   ret;

	if ((size < PAGE_SIZE) && (size != PMAP_ROOT_ALLOC_SIZE)) {
		size = PAGE_SIZE;
	}

	pmap_simple_lock(&tt1_lock);
	if ((size == PAGE_SIZE) && (free_page_size_tt_count != 0)) {
		free_page_size_tt_count--;
		tt1 = (tt_entry_t *)free_page_size_tt_list;
		free_page_size_tt_list = ((tt_free_entry_t *)tt1)->next;
	} else if ((size == 2 * PAGE_SIZE) && (free_two_page_size_tt_count != 0)) {
		free_two_page_size_tt_count--;
		tt1 = (tt_entry_t *)free_two_page_size_tt_list;
		free_two_page_size_tt_list = ((tt_free_entry_t *)tt1)->next;
	} else if ((size < PAGE_SIZE) && (free_tt_count != 0)) {
		free_tt_count--;
		tt1 = (tt_entry_t *)free_tt_list;
		free_tt_list = (tt_free_entry_t *)((tt_free_entry_t *)tt1)->next;
	}

	pmap_simple_unlock(&tt1_lock);

	if (tt1 != NULL) {
		pmap_tt_ledger_credit(pmap, size);
		return (tt_entry_t *)tt1;
	}

	ret = pmap_pages_alloc_zeroed(&pa, (unsigned)((size < PAGE_SIZE)? PAGE_SIZE : size), ((option & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0));

	if (ret == KERN_RESOURCE_SHORTAGE) {
		return (tt_entry_t *)0;
	}

#if XNU_MONITOR
	assert(pa);
#endif

	if (size < PAGE_SIZE) {
		va = phystokv(pa) + size;
		tt_free_entry_t *local_free_list = (tt_free_entry_t*)va;
		tt_free_entry_t *next_free = NULL;
		for (va_end = phystokv(pa) + PAGE_SIZE; va < va_end; va = va + size) {
			tt1_free = (tt_free_entry_t *)va;
			tt1_free->next = next_free;
			next_free = tt1_free;
		}
		pmap_simple_lock(&tt1_lock);
		local_free_list->next = free_tt_list;
		free_tt_list = next_free;
		free_tt_count += ((PAGE_SIZE / size) - 1);
		if (free_tt_count > free_tt_max) {
			free_tt_max = free_tt_count;
		}
		pmap_simple_unlock(&tt1_lock);
	}

	/* Always report root allocations in units of PMAP_ROOT_ALLOC_SIZE, which can be obtained by sysctl arm_pt_root_size.
	 * Depending on the device, this can vary between 512b and 16K. */
	OSAddAtomic((uint32_t)(size / PMAP_ROOT_ALLOC_SIZE), (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));
	OSAddAtomic64(size / PMAP_ROOT_ALLOC_SIZE, &alloc_tteroot_count);
	pmap_tt_ledger_credit(pmap, size);

	return (tt_entry_t *) phystokv(pa);
}

static void
pmap_tt1_deallocate(
	pmap_t pmap,
	tt_entry_t *tt,
	vm_size_t size,
	unsigned option)
{
	tt_free_entry_t *tt_entry;

	if ((size < PAGE_SIZE) && (size != PMAP_ROOT_ALLOC_SIZE)) {
		size = PAGE_SIZE;
	}

	tt_entry = (tt_free_entry_t *)tt;
	assert(not_in_kdp);
	pmap_simple_lock(&tt1_lock);

	if (size < PAGE_SIZE) {
		free_tt_count++;
		if (free_tt_count > free_tt_max) {
			free_tt_max = free_tt_count;
		}
		tt_entry->next = free_tt_list;
		free_tt_list = tt_entry;
	}

	if (size == PAGE_SIZE) {
		free_page_size_tt_count++;
		if (free_page_size_tt_count > free_page_size_tt_max) {
			free_page_size_tt_max = free_page_size_tt_count;
		}
		tt_entry->next = free_page_size_tt_list;
		free_page_size_tt_list = tt_entry;
	}

	if (size == 2 * PAGE_SIZE) {
		free_two_page_size_tt_count++;
		if (free_two_page_size_tt_count > free_two_page_size_tt_max) {
			free_two_page_size_tt_max = free_two_page_size_tt_count;
		}
		tt_entry->next = free_two_page_size_tt_list;
		free_two_page_size_tt_list = tt_entry;
	}

	if (option & PMAP_TT_DEALLOCATE_NOBLOCK) {
		pmap_simple_unlock(&tt1_lock);
		pmap_tt_ledger_debit(pmap, size);
		return;
	}

	while (free_page_size_tt_count > FREE_PAGE_SIZE_TT_MAX) {
		free_page_size_tt_count--;
		tt = (tt_entry_t *)free_page_size_tt_list;
		free_page_size_tt_list = ((tt_free_entry_t *)tt)->next;

		pmap_simple_unlock(&tt1_lock);

		pmap_pages_free(ml_static_vtop((vm_offset_t)tt), PAGE_SIZE);

		OSAddAtomic(-(int32_t)(PAGE_SIZE / PMAP_ROOT_ALLOC_SIZE), (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));

		pmap_simple_lock(&tt1_lock);
	}

	while (free_two_page_size_tt_count > FREE_TWO_PAGE_SIZE_TT_MAX) {
		free_two_page_size_tt_count--;
		tt = (tt_entry_t *)free_two_page_size_tt_list;
		free_two_page_size_tt_list = ((tt_free_entry_t *)tt)->next;

		pmap_simple_unlock(&tt1_lock);

		pmap_pages_free(ml_static_vtop((vm_offset_t)tt), 2 * PAGE_SIZE);

		OSAddAtomic(-2 * (int32_t)(PAGE_SIZE / PMAP_ROOT_ALLOC_SIZE), (pmap == kernel_pmap ? &inuse_kernel_tteroot_count : &inuse_user_tteroot_count));

		pmap_simple_lock(&tt1_lock);
	}
	pmap_simple_unlock(&tt1_lock);
	pmap_tt_ledger_debit(pmap, size);
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

	if (*ttp == NULL) {
		pt_desc_t       *ptdp;

		/*
		 *  Allocate a VM page for the level x page table entries.
		 */
		while (pmap_pages_alloc_zeroed(&pa, PAGE_SIZE, ((options & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0)) != KERN_SUCCESS) {
			if (options & PMAP_OPTIONS_NOWAIT) {
				return KERN_RESOURCE_SHORTAGE;
			}
			VM_PAGE_WAIT();
		}

		while ((ptdp = ptd_alloc(pmap)) == NULL) {
			if (options & PMAP_OPTIONS_NOWAIT) {
				pmap_pages_free(pa, PAGE_SIZE);
				return KERN_RESOURCE_SHORTAGE;
			}
			VM_PAGE_WAIT();
		}

		if (level < pt_attr_leaf_level(pmap_get_pt_attr(pmap))) {
			OSAddAtomic64(1, &alloc_ttepages_count);
			OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_ttepages_count : &inuse_user_ttepages_count));
		} else {
			OSAddAtomic64(1, &alloc_ptepages_count);
			OSAddAtomic(1, (pmap == kernel_pmap ? &inuse_kernel_ptepages_count : &inuse_user_ptepages_count));
		}

		pmap_tt_ledger_credit(pmap, PAGE_SIZE);

		PMAP_ZINFO_PALLOC(pmap, PAGE_SIZE);

		pvh_update_head_unlocked(pai_to_pvh(pa_index(pa)), ptdp, PVH_TYPE_PTDP);
		/* Clear all PVH flags when using a page for a PTD to avoid tripping unexpected page flag usage checks. */
		pvh_set_flags(pai_to_pvh(pa_index(pa)), 0);

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

		*ttp = (tt_entry_t *)phystokv(pa);
	}

#if XNU_MONITOR
	assert(*ttp);
#endif

	return KERN_SUCCESS;
}


static void
pmap_tt_deallocate(
	pmap_t pmap,
	tt_entry_t *ttp,
	unsigned int level)
{
	pt_desc_t *ptdp;
	ptd_info_t *ptd_info;
	unsigned pt_acc_cnt;
	unsigned i;
	vm_offset_t     free_page = 0;
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	unsigned max_pt_index = PAGE_SIZE / pt_attr_page_size(pt_attr);

	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

	ptdp = ptep_get_ptd(ttp);
	ptd_info = ptd_get_info(ptdp, ttp);

	ptdp->va[ptd_get_index(ptdp, ttp)] = (vm_offset_t)-1;

	if ((level < pt_attr_leaf_level(pt_attr)) && (ptd_info->refcnt == PT_DESC_REFCOUNT)) {
		ptd_info->refcnt = 0;
	}

	if (__improbable(ptd_info->refcnt != 0)) {
		panic("pmap_tt_deallocate(): ptdp %p, count %d", ptdp, ptd_info->refcnt);
	}

	for (i = 0, pt_acc_cnt = 0; i < max_pt_index; i++) {
		pt_acc_cnt += ptdp->ptd_info[i].refcnt;
	}

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

	if (free_page != 0) {
		ptd_deallocate(ptep_get_ptd((pt_entry_t*)free_page));
		*(pt_desc_t **)pai_to_pvh(pa_index(ml_static_vtop(free_page))) = NULL;
		pmap_pages_free(ml_static_vtop(free_page), PAGE_SIZE);
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
 * Safely clear out a translation table entry.
 *
 * @note If the TTE to clear out points to a leaf table, then that leaf table
 *       must have a refcnt of zero before the TTE can be removed.
 * @note This function expects to be called with pmap locked exclusive, and will
 *       return with pmap unlocked.
 *
 * @param pmap The pmap containing the page table whose TTE is being removed.
 * @param va_start Beginning of the VA range mapped by the table being removed, for TLB maintenance
 * @param va_end Non-inclusive end of the VA range mapped by the table being removed, for TLB maintenance
 * @param need_strong_sync Indicates whether strong DSB should be used to synchronize TLB maintenance
 * @param ttep Pointer to the TTE that should be cleared out.
 * @param level The level of the page table that contains the TTE to be removed.
 */
static void
pmap_tte_remove(
	pmap_t pmap,
	vm_offset_t va_start,
	vm_offset_t va_end,
	bool need_strong_sync,
	tt_entry_t *ttep,
	unsigned int level)
{
	pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const tt_entry_t tte = *ttep;

	if (__improbable(tte == ARM_TTE_EMPTY)) {
		panic("%s: L%d TTE is already empty. Potential double unmap or memory "
		    "stomper? pmap=%p ttep=%p", __func__, level, pmap, ttep);
	}

	*ttep = (tt_entry_t) 0;
	FLUSH_PTE_STRONG();
	// If given a VA range, we're being asked to flush the TLB before the table in ttep is freed.
	if (va_end > va_start) {
		PMAP_UPDATE_TLBS(pmap, va_start, va_end, need_strong_sync, false);
	}

	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);

	/**
	 * Remember, the passed in "level" parameter refers to the level above the
	 * table that's getting removed (e.g., removing an L2 TTE will unmap an L3
	 * page table).
	 */
	const bool remove_leaf_table = (level == pt_attr_twig_level(pt_attr));

	/**
	 * Non-leaf pagetables don't track active references in the PTD and instead
	 * use a sentinel refcount.  If we're removing a leaf pagetable, we'll load
	 * the real refcount below.
	 */
	unsigned short refcnt = PT_DESC_REFCOUNT;

	/*
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
		refcnt = os_atomic_load(&(ptep_get_info((pt_entry_t*)ttetokv(tte))->refcnt), relaxed);
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
		unsigned short non_empty = 0, valid = 0, comp = 0;
		for (unsigned int i = 0; i < (pmap_page_size / sizeof(*ptep)); i++, ptep++) {
			/* Keep track of all non-empty entries to detect memory corruption. */
			if (__improbable(*ptep != ARM_PTE_EMPTY)) {
				non_empty++;
			}

			if (__improbable(ARM_PTE_IS_COMPRESSED(*ptep, ptep))) {
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
		if (__improbable((non_empty != 0) || (remove_leaf_table && refcnt != 0))) {
#else /* MACH_ASSERT */
		/* We already know the leaf page-table has a non-zero refcnt, so panic. */
		{
#endif /* MACH_ASSERT */
			panic("%s: Found inconsistent state in soon to be deleted L%d table: %d valid, "
			    "%d compressed, %d non-empty, refcnt=%d, L%d tte=%#llx, pmap=%p, bpte=%p", __func__,
			    level + 1, valid, comp, non_empty, refcnt, level, (uint64_t)tte, pmap, bpte);
		}
	}
}

/**
 * Given a pointer to an entry within a `level` page table, delete the
 * page table at `level` + 1 that is represented by that entry. For instance,
 * to delete an unused L3 table, `ttep` would be a pointer to the L2 entry that
 * contains the PA of the L3 table, and `level` would be "2".
 *
 * @note If the table getting deallocated is a leaf table, then that leaf table
 *       must have a refcnt of zero before getting deallocated. All other levels
 *       must have a refcnt of PT_DESC_REFCOUNT in their page table descriptor.
 * @note This function expects to be called with pmap locked exclusive and will
 *       return with pmap unlocked.
 *
 * @param pmap The pmap that owns the page table to be deallocated.
 * @param va_start Beginning of the VA range mapped by the table being removed, for TLB maintenance
 * @param va_end Non-inclusive end of the VA range mapped by the table being removed, for TLB maintenance
 * @param need_strong_sync Indicates whether strong DSB should be used to synchronize TLB maintenance
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
	vm_offset_t va_end,
	bool need_strong_sync,
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
	pmap_tte_remove(pmap, va_start, va_end, need_strong_sync, ttep, level);

	pmap_tt_deallocate(pmap, (tt_entry_t *) phystokv(tte_to_pa(tte)), level + 1);
}

/*
 *	Remove a range of hardware page-table entries.
 *	The entries given are the first (inclusive)
 *	and last (exclusive) entries for the VM pages.
 *	The virtual address is the va for the first pte.
 *
 *	The pmap must be locked.
 *	If the pmap is not the kernel pmap, the range must lie
 *	entirely within one pte-page.  This is NOT checked.
 *	Assumes that the pte-page exists.
 *
 *	Returns the number of PTE changed
 */
MARK_AS_PMAP_TEXT static int
pmap_remove_range(
	pmap_t pmap,
	vm_map_address_t va,
	pt_entry_t *bpte,
	pt_entry_t *epte)
{
	bool need_strong_sync = false;
	int num_changed = pmap_remove_range_options(pmap, va, bpte, epte, NULL,
	    &need_strong_sync, PMAP_OPTIONS_REMOVE);
	if (num_changed > 0) {
		PMAP_UPDATE_TLBS(pmap, va,
		    va + (pt_attr_page_size(pmap_get_pt_attr(pmap)) * (epte - bpte)), need_strong_sync, true);
	}
	return num_changed;
}


#ifdef PVH_FLAG_EXEC

/*
 *	Update the access protection bits of the physical aperture mapping for a page.
 *	This is useful, for example, in guranteeing that a verified executable page
 *	has no writable mappings anywhere in the system, including the physical
 *	aperture.  flush_tlb_async can be set to true to avoid unnecessary TLB
 *	synchronization overhead in cases where the call to this function is
 *	guaranteed to be followed by other TLB operations.
 */
void
pmap_set_ptov_ap(unsigned int pai __unused, unsigned int ap __unused, boolean_t flush_tlb_async __unused)
{
#if __ARM_PTE_PHYSMAP__
	pvh_assert_locked(pai);
	vm_offset_t kva = phystokv(vm_first_phys + (pmap_paddr_t)ptoa(pai));
	pt_entry_t *pte_p = pmap_pte(kernel_pmap, kva);

	pt_entry_t tmplate = *pte_p;
	if ((tmplate & ARM_PTE_APMASK) == ARM_PTE_AP(ap)) {
		return;
	}
	tmplate = (tmplate & ~ARM_PTE_APMASK) | ARM_PTE_AP(ap);
	if (tmplate & ARM_PTE_HINT_MASK) {
		panic("%s: physical aperture PTE %p has hint bit set, va=%p, pte=0x%llx",
		    __func__, pte_p, (void *)kva, tmplate);
	}
	write_pte_strong(pte_p, tmplate);
	flush_mmu_tlb_region_asid_async(kva, PAGE_SIZE, kernel_pmap, true);
	if (!flush_tlb_async) {
		sync_tlb_flush();
	}
#endif
}
#endif /* defined(PVH_FLAG_EXEC) */



MARK_AS_PMAP_TEXT int
pmap_remove_range_options(
	pmap_t pmap,
	vm_map_address_t va,
	pt_entry_t *bpte,
	pt_entry_t *epte,
	vm_map_address_t *eva,
	bool *need_strong_sync __unused,
	int options)
{
	pt_entry_t     *cpte;
	size_t          npages = 0;
	int             num_removed, num_unwired;
	int             num_pte_changed;
	unsigned int    pai = 0;
	pmap_paddr_t    pa;
	int             num_external, num_internal, num_reusable;
	int             num_alt_internal;
	uint64_t        num_compressed, num_alt_compressed;
	int16_t         refcnt = 0;

	pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	uint64_t pmap_page_size = PAGE_RATIO * pt_attr_page_size(pt_attr);

	if (__improbable((uintptr_t)epte > (((uintptr_t)bpte + pmap_page_size) & ~(pmap_page_size - 1)))) {
		panic("%s: PTE range [%p, %p) in pmap %p crosses page table boundary", __func__, bpte, epte, pmap);
	}

	if (__improbable(pmap->type == PMAP_TYPE_COMMPAGE)) {
		panic("%s: attempt to remove mappings from commpage pmap %p", __func__, pmap);
	}

	num_removed = 0;
	num_unwired = 0;
	num_pte_changed = 0;
	num_external = 0;
	num_internal = 0;
	num_reusable = 0;
	num_compressed = 0;
	num_alt_internal = 0;
	num_alt_compressed = 0;

#if XNU_MONITOR
	bool ro_va = false;
	if (__improbable((pmap == kernel_pmap) && (eva != NULL) && zone_spans_ro_va(va, *eva))) {
		ro_va = true;
	}
#endif
	for (cpte = bpte; cpte < epte;
	    cpte += PAGE_RATIO, va += pmap_page_size) {
		pt_entry_t      spte;
		boolean_t       managed = FALSE;

		/*
		 * Check for pending preemption on every iteration: the PV list may be arbitrarily long,
		 * so we need to be as aggressive as possible in checking for preemption when we can.
		 */
		if (__improbable((eva != NULL) && npages++ && pmap_pending_preemption())) {
			*eva = va;
			break;
		}

		spte = *((volatile pt_entry_t*)cpte);

		while (!managed) {
			if (pmap != kernel_pmap &&
			    (options & PMAP_OPTIONS_REMOVE) &&
			    (ARM_PTE_IS_COMPRESSED(spte, cpte))) {
				/*
				 * "pmap" must be locked at this point,
				 * so this should not race with another
				 * pmap_remove_range() or pmap_enter().
				 */

				/* one less "compressed"... */
				num_compressed++;
				if (spte & ARM_PTE_COMPRESSED_ALT) {
					/* ... but it used to be "ALTACCT" */
					num_alt_compressed++;
				}

				/* clear marker */
				write_pte_fast(cpte, ARM_PTE_TYPE_FAULT);
				/*
				 * "refcnt" also accounts for
				 * our "compressed" markers,
				 * so let's update it here.
				 */
				--refcnt;
				spte = *((volatile pt_entry_t*)cpte);
			}
			/*
			 * It may be possible for the pte to transition from managed
			 * to unmanaged in this timeframe; for now, elide the assert.
			 * We should break out as a consequence of checking pa_valid.
			 */
			//assert(!ARM_PTE_IS_COMPRESSED(spte));
			pa = pte_to_pa(spte);
			if (!pa_valid(pa)) {
#if XNU_MONITOR
				unsigned int cacheattr = pmap_cache_attributes((ppnum_t)atop(pa));
#endif
#if XNU_MONITOR
				if (__improbable((cacheattr & PP_ATTR_MONITOR) &&
				    (pte_to_xprr_perm(spte) != XPRR_KERN_RO_PERM) && !pmap_ppl_disable)) {
					panic("%s: attempt to remove mapping of writable PPL-protected I/O address 0x%llx",
					    __func__, (uint64_t)pa);
				}
#endif
				break;
			}
			pai = pa_index(pa);
			pvh_lock(pai);
			spte = *((volatile pt_entry_t*)cpte);
			pa = pte_to_pa(spte);
			if (pai == pa_index(pa)) {
				managed = TRUE;
				break; // Leave pai locked as we will unlock it after we free the PV entry
			}
			pvh_unlock(pai);
		}

		if (ARM_PTE_IS_COMPRESSED(*cpte, cpte)) {
			/*
			 * There used to be a valid mapping here but it
			 * has already been removed when the page was
			 * sent to the VM compressor, so nothing left to
			 * remove now...
			 */
			continue;
		}

		/* remove the translation, do not flush the TLB */
		if (*cpte != ARM_PTE_TYPE_FAULT) {
			assertf(!ARM_PTE_IS_COMPRESSED(*cpte, cpte), "unexpected compressed pte %p (=0x%llx)", cpte, (uint64_t)*cpte);
			assertf((*cpte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE, "invalid pte %p (=0x%llx)", cpte, (uint64_t)*cpte);
#if MACH_ASSERT
			if (managed && (pmap != kernel_pmap) && (ptep_get_va(cpte) != va)) {
				panic("pmap_remove_range_options(): VA mismatch: cpte=%p ptd=%p pte=0x%llx va=0x%llx, cpte va=0x%llx",
				    cpte, ptep_get_ptd(cpte), (uint64_t)*cpte, (uint64_t)va, (uint64_t)ptep_get_va(cpte));
			}
#endif
			write_pte_fast(cpte, ARM_PTE_TYPE_FAULT);
			num_pte_changed++;
		}

		if ((spte != ARM_PTE_TYPE_FAULT) &&
		    (pmap != kernel_pmap)) {
			assertf(!ARM_PTE_IS_COMPRESSED(spte, cpte), "unexpected compressed pte %p (=0x%llx)", cpte, (uint64_t)spte);
			assertf((spte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE, "invalid pte %p (=0x%llx)", cpte, (uint64_t)spte);
			--refcnt;
		}

		if (pte_is_wired(spte)) {
			pte_set_wired(pmap, cpte, 0);
			num_unwired++;
		}
		/*
		 * if not managed, we're done
		 */
		if (!managed) {
			continue;
		}

#if XNU_MONITOR
		if (__improbable(ro_va)) {
			pmap_ppl_unlockdown_page_locked(pai, PVH_FLAG_LOCKDOWN_RO, true);
		}
#endif

		/*
		 * find and remove the mapping from the chain for this
		 * physical address.
		 */
		bool is_internal, is_altacct;
		pmap_remove_pv(pmap, cpte, pai, true, &is_internal, &is_altacct);

		if (is_altacct) {
			assert(is_internal);
			num_internal++;
			num_alt_internal++;
			if (!pvh_test_type(pai_to_pvh(pai), PVH_TYPE_PTEP)) {
				ppattr_clear_altacct(pai);
				ppattr_clear_internal(pai);
			}
		} else if (is_internal) {
			if (ppattr_test_reusable(pai)) {
				num_reusable++;
			} else {
				num_internal++;
			}
			if (!pvh_test_type(pai_to_pvh(pai), PVH_TYPE_PTEP)) {
				ppattr_clear_internal(pai);
			}
		} else {
			num_external++;
		}
		pvh_unlock(pai);
		num_removed++;
	}

	/*
	 *	Update the counts
	 */
	pmap_ledger_debit(pmap, task_ledgers.phys_mem, num_removed * pmap_page_size);

	if (pmap != kernel_pmap) {
		if ((refcnt != 0) && (OSAddAtomic16(refcnt, (SInt16 *) &(ptep_get_info(bpte)->refcnt)) <= 0)) {
			panic("pmap_remove_range_options: over-release of ptdp %p for pte [%p, %p)", ptep_get_ptd(bpte), bpte, epte);
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

	/* flush the ptable entries we have written */
	if (num_pte_changed > 0) {
		FLUSH_PTE_STRONG();
	}

	return num_pte_changed;
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
	pt_entry_t     *bpte, *epte;
	pt_entry_t     *pte_p;
	tt_entry_t     *tte_p;
	int             remove_count = 0;
	bool            need_strong_sync = false;
	bool            unlock = true;

	if (__improbable(end < start)) {
		panic("%s: invalid address range %p, %p", __func__, (void*)start, (void*)end);
	}

	validate_pmap_mutable(pmap);

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

	tte_p = pmap_tte(pmap, start);

	if (tte_p == (tt_entry_t *) NULL) {
		goto done;
	}

	if ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		pte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte = &pte_p[pte_index(pt_attr, start)];
		epte = bpte + ((end - start) >> pt_attr_leaf_shift(pt_attr));

		/*
		 * This check is really intended to ensure that mappings in a nested pmap can't be removed
		 * through a top-level user pmap, although it's also a useful sanity check for other pmap types.
		 * Note that kernel page tables may not have PTDs, so we can't use the check there.
		 */
		if (__improbable((pmap->type != PMAP_TYPE_KERNEL) && (ptep_get_pmap(bpte) != pmap))) {
			panic("%s: attempt to remove mappings owned by pmap %p through pmap %p, starting at pte %p",
			    __func__, ptep_get_pmap(bpte), pmap, bpte);
		}

		remove_count = pmap_remove_range_options(pmap, start, bpte, epte, &eva,
		    &need_strong_sync, options);

		if ((pmap->type == PMAP_TYPE_USER) && (ptep_get_info(pte_p)->refcnt == 0)) {
			pmap_tte_deallocate(pmap, start, eva, need_strong_sync, tte_p, pt_attr_twig_level(pt_attr));
			remove_count = 0; // pmap_tte_deallocate has flushed the TLB for us
			unlock = false; // pmap_tte_deallocate() has dropped the lock
		}
	}

done:
	if (unlock) {
		pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
	}

	if (remove_count > 0) {
		PMAP_UPDATE_TLBS(pmap, start, eva, need_strong_sync, true);
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

#if XNU_MONITOR
		va = pmap_remove_options_ppl(pmap, va, l, options);

		pmap_ledger_check_balance(pmap);
#else
		va = pmap_remove_options_internal(pmap, va, l, options);
#endif
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
#if     !__ARM_USER_PROTECT__
	__unused
#endif
	thread_t        thread)
{
	pmap_switch(pmap);
#if __ARM_USER_PROTECT__
	thread->machine.uptw_ttb = ((unsigned int) pmap->ttep) | TTBR_SETUP;
	thread->machine.asid = pmap->hw_asid;
#endif
}

static void
pmap_flush_core_tlb_asid_async(pmap_t pmap)
{
	flush_core_tlb_asid_async(((uint64_t) pmap->hw_asid) << TLBI_ASID_SHIFT);
}

static inline bool
pmap_user_ttb_is_clear(void)
{
	return get_mmu_ttb() == (invalid_ttep & TTBR_BADDR_MASK);
}

MARK_AS_PMAP_TEXT void
pmap_switch_internal(
	pmap_t pmap)
{
	pmap_cpu_data_t *cpu_data_ptr = pmap_get_cpu_data();
#if XNU_MONITOR
	os_atomic_store(&cpu_data_ptr->active_pmap, pmap, relaxed);
#endif
	validate_pmap_mutable(pmap);
	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	uint16_t asid_index = pmap->hw_asid;
	bool do_asid_flush = false;
	bool do_commpage_flush = false;

	if (__improbable((asid_index == 0) && (pmap != kernel_pmap))) {
		panic("%s: attempt to activate pmap with invalid ASID %p", __func__, pmap);
	}
#if __ARM_KERNEL_PROTECT__
	asid_index >>= 1;
#endif

	pmap_t                    last_nested_pmap = cpu_data_ptr->cpu_nested_pmap;
	__unused const pt_attr_t *last_nested_pmap_attr = cpu_data_ptr->cpu_nested_pmap_attr;
	__unused vm_map_address_t last_nested_region_addr = cpu_data_ptr->cpu_nested_region_addr;
	__unused vm_map_offset_t  last_nested_region_size = cpu_data_ptr->cpu_nested_region_size;
	bool do_shared_region_flush = ((pmap != kernel_pmap) && (last_nested_pmap != NULL) && (pmap->nested_pmap != last_nested_pmap));
	bool break_before_make = do_shared_region_flush;

	if ((pmap_max_asids > MAX_HW_ASIDS) && (asid_index > 0)) {
		asid_index -= 1;
		pmap_update_plru(asid_index);

		/* Paranoia. */
		assert(asid_index < (sizeof(cpu_data_ptr->cpu_sw_asids) / sizeof(*cpu_data_ptr->cpu_sw_asids)));

		/* Extract the "virtual" bits of the ASIDs (which could cause us to alias). */
		uint8_t new_sw_asid = pmap->sw_asid;
		uint8_t last_sw_asid = cpu_data_ptr->cpu_sw_asids[asid_index];

		if (new_sw_asid != last_sw_asid) {
			/*
			 * If the virtual ASID of the new pmap does not match the virtual ASID
			 * last seen on this CPU for the physical ASID (that was a mouthful),
			 * then this switch runs the risk of aliasing.  We need to flush the
			 * TLB for this phyiscal ASID in this case.
			 */
			cpu_data_ptr->cpu_sw_asids[asid_index] = new_sw_asid;
			do_asid_flush = true;
			break_before_make = true;
		}
	}

#if __ARM_MIXED_PAGE_SIZE__
	if (pt_attr->pta_tcr_value != get_tcr()) {
		break_before_make = true;
	}
#endif
#if __ARM_MIXED_PAGE_SIZE__
	/*
	 * For mixed page size configurations, we need to flush the global commpage mappings from
	 * the TLB when transitioning between address spaces with different page sizes.  Otherwise
	 * it's possible for a TLB fill against the incoming commpage to produce a TLB entry which
	 * which partially overlaps a TLB entry from the outgoing commpage, leading to a TLB
	 * conflict abort or other unpredictable behavior.
	 */
	if (pt_attr_leaf_shift(pt_attr) != cpu_data_ptr->commpage_page_shift) {
		do_commpage_flush = true;
	}
	if (do_commpage_flush) {
		break_before_make = true;
	}
#endif
	if (__improbable(break_before_make && !pmap_user_ttb_is_clear())) {
		PMAP_TRACE(1, PMAP_CODE(PMAP__CLEAR_USER_TTB), VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), pmap->hw_asid);
		pmap_clear_user_ttb_internal();
	}

	/* If we're switching to a different nested pmap (i.e. shared region), we'll need
	 * to flush the userspace mappings for that region.  Those mappings are global
	 * and will not be protected by the ASID.  It should also be cheaper to flush the
	 * entire local TLB rather than to do a broadcast MMU flush by VA region. */
	if (__improbable(do_shared_region_flush)) {
#if __ARM_RANGE_TLBI__
		uint64_t page_shift_prev = pt_attr_leaf_shift(last_nested_pmap_attr);
		vm_map_offset_t npages_prev = last_nested_region_size >> page_shift_prev;

		/* NOTE: here we flush the global TLB entries for the previous nested region only.
		 * There may still be non-global entries that overlap with the incoming pmap's
		 * nested region.  On Apple SoCs at least, this is acceptable.  Those non-global entries
		 * must necessarily belong to a different ASID than the incoming pmap, or they would
		 * be flushed in the do_asid_flush case below.  This will prevent them from conflicting
		 * with the incoming pmap's nested region.  However, the ARMv8 ARM is not crystal clear
		 * on whether such a global/inactive-nonglobal overlap is acceptable, so we may need
		 * to consider additional invalidation here in the future. */
		if (npages_prev <= ARM64_TLB_RANGE_PAGES) {
			flush_core_tlb_allrange_async(generate_rtlbi_param((ppnum_t)npages_prev, 0, last_nested_region_addr, page_shift_prev));
		} else {
			do_asid_flush = false;
			flush_core_tlb_async();
		}
#else
		do_asid_flush = false;
		flush_core_tlb_async();
#endif // __ARM_RANGE_TLBI__
	}

#if __ARM_MIXED_PAGE_SIZE__
	if (__improbable(do_commpage_flush)) {
		const uint64_t commpage_shift = cpu_data_ptr->commpage_page_shift;
		const uint64_t rtlbi_param = generate_rtlbi_param((ppnum_t)_COMM_PAGE64_NESTING_SIZE >> commpage_shift,
		    0, _COMM_PAGE64_NESTING_START, commpage_shift);
		flush_core_tlb_allrange_async(rtlbi_param);
	}
#endif
	if (__improbable(do_asid_flush)) {
		pmap_flush_core_tlb_asid_async(pmap);
#if DEVELOPMENT || DEBUG
		os_atomic_inc(&pmap_asid_flushes, relaxed);
#endif
	}
	if (__improbable(do_asid_flush || do_shared_region_flush || do_commpage_flush)) {
		sync_tlb_flush_local();
	}

	pmap_switch_user_ttb(pmap, cpu_data_ptr);
}

void
pmap_switch(
	pmap_t pmap)
{
	PMAP_TRACE(1, PMAP_CODE(PMAP__SWITCH) | DBG_FUNC_START, VM_KERNEL_ADDRHIDE(pmap), PMAP_VASID(pmap), pmap->hw_asid);
#if XNU_MONITOR
	pmap_switch_ppl(pmap);
#else
	pmap_switch_internal(pmap);
#endif
	PMAP_TRACE(1, PMAP_CODE(PMAP__SWITCH) | DBG_FUNC_END);
}

void
pmap_page_protect(
	ppnum_t ppnum,
	vm_prot_t prot)
{
	pmap_page_protect_options(ppnum, prot, 0, NULL);
}

/*
 *	Routine:	pmap_page_protect_options
 *
 *	Function:
 *		Lower the permission for all mappings to a given
 *		page.
 */
MARK_AS_PMAP_TEXT static void
pmap_page_protect_options_with_flush_range(
	ppnum_t ppnum,
	vm_prot_t prot,
	unsigned int options,
	pmap_tlb_flush_range_t *flush_range)
{
	pmap_paddr_t    phys = ptoa(ppnum);
	pv_entry_t    **pv_h;
	pv_entry_t     *pve_p, *orig_pve_p;
	pv_entry_t     *pveh_p;
	pv_entry_t     *pvet_p;
	pt_entry_t     *pte_p, *orig_pte_p;
	pv_entry_t     *new_pve_p;
	pt_entry_t     *new_pte_p;
	vm_offset_t     pvh_flags;
	unsigned int    pai;
	bool            remove;
	bool            set_NX;
	unsigned int    pvh_cnt = 0;
	unsigned int    pass1_updated = 0;
	unsigned int    pass2_updated = 0;

	assert(ppnum != vm_page_fictitious_addr);

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
		remove = false;
		break;
	default:
		/* PPL security model requires that we flush TLBs before we exit if the page may be recycled. */
		options = options & ~PMAP_OPTIONS_NOFLUSH;
		remove = true;
		break;
	}

	pmap_cpu_data_t *pmap_cpu_data = NULL;
	if (remove) {
#if !XNU_MONITOR
		mp_disable_preemption();
#endif
		pmap_cpu_data = pmap_get_cpu_data();
		os_atomic_store(&pmap_cpu_data->inflight_disconnect, true, relaxed);
		/*
		 * Ensure the store to inflight_disconnect will be observed before any of the
		 * ensuing PTE/refcount stores in this function.  This flag is used to avoid
		 * a race in which the VM may clear a pmap's mappings and destroy the pmap on
		 * another CPU, in between this function's clearing a PTE and dropping the
		 * corresponding pagetable refcount.  That can lead to a panic if the
		 * destroying thread observes a non-zero refcount.  For this we need a store-
		 * store barrier; a store-release operation would not be sufficient.
		 */
		os_atomic_thread_fence(release);
	}

	pai = pa_index(phys);
	pvh_lock(pai);
	pv_h = pai_to_pvh(pai);
	pvh_flags = pvh_get_flags(pv_h);

#if XNU_MONITOR
	if (__improbable(remove && (pvh_flags & PVH_FLAG_LOCKDOWN_MASK))) {
		panic("%d is locked down (%#llx), cannot remove", pai, (uint64_t)pvh_get_flags(pv_h));
	}
	if (__improbable(ppattr_pa_test_monitor(phys))) {
		panic("%s: PA 0x%llx belongs to PPL.", __func__, (uint64_t)phys);
	}
#endif


	orig_pte_p = pte_p = PT_ENTRY_NULL;
	orig_pve_p = pve_p = PV_ENTRY_NULL;
	pveh_p = PV_ENTRY_NULL;
	pvet_p = PV_ENTRY_NULL;
	new_pve_p = PV_ENTRY_NULL;
	new_pte_p = PT_ENTRY_NULL;


	if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
		orig_pte_p = pte_p = pvh_ptep(pv_h);
	} else if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		orig_pve_p = pve_p = pvh_pve_list(pv_h);
		pveh_p = pve_p;
	} else if (__improbable(!pvh_test_type(pv_h, PVH_TYPE_NULL))) {
		panic("%s: invalid PV head 0x%llx for PA 0x%llx", __func__, (uint64_t)(*pv_h), (uint64_t)phys);
	}

	/* Pass 1: Update all CPU PTEs and accounting info as necessary */
	int pve_ptep_idx = 0;

	/*
	 * issue_tlbi is used to indicate that this function will need to issue at least one TLB
	 * invalidation during pass 2.  tlb_flush_needed only indicates that PTE permissions have
	 * changed and that a TLB flush will be needed *at some point*, so we'll need to call
	 * FLUSH_PTE_STRONG() to synchronize prior PTE updates.  In the case of a flush_range
	 * operation, TLB invalidation may be handled by the caller so it's possible for
	 * tlb_flush_needed to be true while issue_tlbi is false.
	 */
	bool issue_tlbi = false;
	bool tlb_flush_needed = false;
	const bool compress = (options & PMAP_OPTIONS_COMPRESSOR);
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		pt_entry_t tmplate = ARM_PTE_TYPE_FAULT;
		bool update = false;

		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto protect_skip_pve_pass1;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
#if XNU_MONITOR
			if (__improbable(pvh_flags & PVH_FLAG_LOCKDOWN_MASK)) {
				panic("pmap_page_protect: ppnum 0x%x locked down, cannot be owned by iommu %p, pve_p=%p",
				    ppnum, ptep_get_iommu(pte_p), pve_p);
			}
#endif
			if (remove && (options & PMAP_OPTIONS_COMPRESSOR)) {
				panic("pmap_page_protect: attempt to compress ppnum 0x%x owned by iommu %p, pve_p=%p",
				    ppnum, ptep_get_iommu(pte_p), pve_p);
			}
			goto protect_skip_pve_pass1;
		}
#endif
		const pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		const vm_map_address_t va = ptd_get_va(ptdp, pte_p);

		if (__improbable((pmap == NULL) || (atop(pte_to_pa(*pte_p)) != ppnum))) {
#if MACH_ASSERT
			if ((pmap != NULL) && (pve_p != PV_ENTRY_NULL) && (kern_feature_override(KF_PMAPV_OVRD) == FALSE)) {
				/* Temporarily set PTEP to NULL so that the logic below doesn't pick it up as duplicate. */
				pt_entry_t *temp_ptep = pve_get_ptep(pve_p, pve_ptep_idx);
				pve_set_ptep(pve_p, pve_ptep_idx, PT_ENTRY_NULL);

				pv_entry_t *check_pvep = pve_p;

				do {
					if (pve_find_ptep_index(check_pvep, pte_p) != -1) {
						panic_plain("%s: duplicate pve entry ptep=%p pmap=%p, pvh=%p, "
						    "pvep=%p, pai=0x%x", __func__, pte_p, pmap, pv_h, pve_p, pai);
					}
				} while ((check_pvep = pve_next(check_pvep)) != PV_ENTRY_NULL);

				/* Restore previous PTEP value. */
				pve_set_ptep(pve_p, pve_ptep_idx, temp_ptep);
			}
#endif
			panic("pmap_page_protect: bad pve entry pte_p=%p pmap=%p prot=%d options=%u, pv_h=%p, pveh_p=%p, pve_p=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x",
			    pte_p, pmap, prot, options, pv_h, pveh_p, pve_p, (uint64_t)*pte_p, (uint64_t)va, ppnum);
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

		/* Remove the mapping if new protection is NONE */
		if (remove) {
			const bool is_internal = ppattr_pve_is_internal(pai, pve_p, pve_ptep_idx);
			const bool is_altacct = ppattr_pve_is_altacct(pai, pve_p, pve_ptep_idx);
			const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
			pt_entry_t spte = *pte_p;

			if (pte_is_wired(spte)) {
				pte_set_wired(pmap, pte_p, 0);
				spte = *pte_p;
				if (pmap != kernel_pmap) {
					pmap_ledger_debit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				}
			}

			assertf(atop(pte_to_pa(spte)) == ppnum, "unexpected value 0x%llx for pte %p mapping ppnum 0x%x",
			    (uint64_t)spte, pte_p, ppnum);

			if (compress && is_internal && (pmap != kernel_pmap)) {
				assert(!ARM_PTE_IS_COMPRESSED(*pte_p, pte_p));
				/* mark this PTE as having been "compressed" */
				tmplate = ARM_PTE_COMPRESSED;
				if (is_altacct) {
					tmplate |= ARM_PTE_COMPRESSED_ALT;
				}
			} else {
				tmplate = ARM_PTE_TYPE_FAULT;
			}

			assert(spte != tmplate);
			write_pte_fast(pte_p, tmplate);
			update = true;
			++pass1_updated;

			pmap_ledger_debit(pmap, task_ledgers.phys_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);

			if (pmap != kernel_pmap) {
				if (ppattr_test_reusable(pai) &&
				    is_internal &&
				    !is_altacct) {
					pmap_ledger_debit(pmap, task_ledgers.reusable, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				} else if (!is_internal) {
					pmap_ledger_debit(pmap, task_ledgers.external, pt_attr_page_size(pt_attr) * PAGE_RATIO);
				}

				if (is_altacct) {
					assert(is_internal);
					pmap_ledger_debit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);
					pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, pt_attr_page_size(pt_attr) * PAGE_RATIO);
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
						pmap_ledger_credit(pmap, task_ledgers.alternate_accounting_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
					}
					ppattr_pve_clr_internal(pai, pve_p, pve_ptep_idx);
					ppattr_pve_clr_altacct(pai, pve_p, pve_ptep_idx);
				} else if (ppattr_test_reusable(pai)) {
					assert(is_internal);
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, pt_attr_page_size(pt_attr) * PAGE_RATIO);
						/* was not in footprint, but is now */
						pmap_ledger_credit(pmap, task_ledgers.phys_footprint, pt_attr_page_size(pt_attr) * PAGE_RATIO);
					}
					ppattr_pve_clr_internal(pai, pve_p, pve_ptep_idx);
				} else if (is_internal) {
					pmap_ledger_debit(pmap, task_ledgers.internal, pt_attr_page_size(pt_attr) * PAGE_RATIO);

					/*
					 * Update all stats related to physical footprint, which only
					 * deals with internal pages.
					 */
					if (options & PMAP_OPTIONS_COMPRESSOR) {
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
					ppattr_pve_clr_internal(pai, pve_p, pve_ptep_idx);
				} else {
					/* external page: no impact on ledgers */
				}
			}
			assert((pve_p == PV_ENTRY_NULL) || !pve_get_altacct(pve_p, pve_ptep_idx));
		} else {
			pt_entry_t spte = *pte_p;
			const pt_attr_t *const pt_attr = pmap_get_pt_attr(pmap);

			if (pmap == kernel_pmap) {
				tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
			} else {
				tmplate = ((spte & ~ARM_PTE_APMASK) | pt_attr_leaf_ro(pt_attr));
			}

			/*
			 * While the naive implementation of this would serve to add execute
			 * permission, this is not how the VM uses this interface, or how
			 * x86_64 implements it.  So ignore requests to add execute permissions.
			 */
			if (set_NX) {
				tmplate |= pt_attr_leaf_xn(pt_attr);
			}


			assert(spte != ARM_PTE_TYPE_FAULT);
			assert(!ARM_PTE_IS_COMPRESSED(spte, pte_p));

			if (spte != tmplate) {
				/*
				 * Mark the PTE so that we'll know this mapping requires a TLB flush in pass 2.
				 * This allows us to avoid unnecessary flushing e.g. for COW aliases that didn't
				 * require permission updates.  We use the ARM_PTE_WRITEABLE bit as that bit
				 * should always be cleared by this function.
				 */
				pte_set_was_writeable(tmplate, true);
				write_pte_fast(pte_p, tmplate);
				update = true;
				++pass1_updated;
			} else if (pte_was_writeable(tmplate)) {
				/*
				 * We didn't change any of the relevant permission bits in the PTE, so we don't need
				 * to flush the TLB, but we do want to clear the "was_writeable" flag.  When revoking
				 * write access to a page, this function should always at least clear that flag for
				 * all PTEs, as the VM is effectively requesting that subsequent write accesses to
				 * these mappings go through vm_fault().  We therefore don't want those accesses to
				 * be handled through arm_fast_fault().
				 */
				pte_set_was_writeable(tmplate, false);
				write_pte_fast(pte_p, tmplate);
			}
		}

		if (!issue_tlbi && update && !(options & PMAP_OPTIONS_NOFLUSH)) {
			tlb_flush_needed = true;
			if (remove || !flush_range || (flush_range->ptfr_pmap != pmap) ||
			    (va >= flush_range->ptfr_end) || (va < flush_range->ptfr_start)) {
				issue_tlbi = true;
			}
		}
protect_skip_pve_pass1:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}

	if (tlb_flush_needed) {
		FLUSH_PTE_STRONG();
	}

	if (!remove && !issue_tlbi) {
		goto protect_finish;
	}

	/* Pass 2: Invalidate TLBs and update the list to remove CPU mappings */
	pv_entry_t **pve_pp = pv_h;
	pve_p = orig_pve_p;
	pte_p = orig_pte_p;
	pve_ptep_idx = 0;

	/*
	 * We need to keep track of whether a particular PVE list contains IOMMU
	 * mappings when removing entries, because we should only remove CPU
	 * mappings. If a PVE list contains at least one IOMMU mapping, we keep
	 * it around.
	 */
	bool iommu_mapping_in_pve = false;
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto protect_skip_pve_pass2;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			iommu_mapping_in_pve = true;
			if (remove && (pve_p == PV_ENTRY_NULL)) {
				/*
				 * We've found an IOMMU entry and it's the only entry in the PV list.
				 * We don't discard IOMMU entries, so simply set up the new PV list to
				 * contain the single IOMMU PTE and exit the loop.
				 */
				new_pte_p = pte_p;
				break;
			}
			goto protect_skip_pve_pass2;
		}
#endif
		pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		const vm_map_address_t va = ptd_get_va(ptdp, pte_p);

		if (remove) {
			if (!compress && (pmap != kernel_pmap)) {
				/*
				 * We must wait to decrement the refcount until we're completely finished using the PTE
				 * on this path.  Otherwise, if we happened to drop the refcount to zero, a concurrent
				 * pmap_remove() call might observe the zero refcount and free the pagetable out from
				 * under us.
				 */
				if (OSAddAtomic16(-1, (SInt16 *) &(ptd_get_info(ptdp, pte_p)->refcnt)) <= 0) {
					panic("pmap_page_protect_options(): over-release of ptdp %p for pte %p", ptep_get_ptd(pte_p), pte_p);
				}
			}
			/* Remove this CPU mapping from PVE list. */
			if (pve_p != PV_ENTRY_NULL) {
				pve_set_ptep(pve_p, pve_ptep_idx, PT_ENTRY_NULL);
			}
		} else {
			pt_entry_t spte = *pte_p;
			if (pte_was_writeable(spte)) {
				pte_set_was_writeable(spte, false);
				write_pte_fast(pte_p, spte);
			} else {
				goto protect_skip_pve_pass2;
			}
		}
		++pass2_updated;
		if (remove || !flush_range || (flush_range->ptfr_pmap != pmap) ||
		    (va >= flush_range->ptfr_end) || (va < flush_range->ptfr_start)) {
			pmap_get_pt_ops(pmap)->flush_tlb_region_async(va,
			    pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO, pmap, true);
		}

protect_skip_pve_pass2:
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
					pve_remove(pv_h, pve_pp, pve_p);
					pveh_p = pvh_pve_list(pv_h);
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

protect_finish:

#ifdef PVH_FLAG_EXEC
	if (remove && (pvh_get_flags(pv_h) & PVH_FLAG_EXEC)) {
		pmap_set_ptov_ap(pai, AP_RWNA, tlb_flush_needed);
	}
#endif
	if (__improbable(pass1_updated != pass2_updated)) {
		panic("%s: first pass (%u) and second pass (%u) disagree on updated mappings",
		    __func__, pass1_updated, pass2_updated);
	}
	/* if we removed a bunch of entries, take care of them now */
	if (remove) {
		if (new_pve_p != PV_ENTRY_NULL) {
			pvh_update_head(pv_h, new_pve_p, PVH_TYPE_PVEP);
			pvh_set_flags(pv_h, pvh_flags);
		} else if (new_pte_p != PT_ENTRY_NULL) {
			pvh_update_head(pv_h, new_pte_p, PVH_TYPE_PTEP);
			pvh_set_flags(pv_h, pvh_flags);
		} else {
			pvh_update_head(pv_h, PV_ENTRY_NULL, PVH_TYPE_NULL);
		}
	}

	if (flush_range && tlb_flush_needed) {
		if (!remove) {
			flush_range->ptfr_flush_needed = true;
			tlb_flush_needed = false;
		}
	}

	/*
	 * If we removed PV entries, ensure prior TLB flushes are complete before we drop the PVH
	 * lock to allow the backing pages to be repurposed.  This is a security precaution, aimed
	 * primarily at XNU_MONITOR configurations, to reduce the likelihood of an attacker causing
	 * a page to be repurposed while it is still live in the TLBs.
	 */
	if (remove && tlb_flush_needed) {
		sync_tlb_flush();
	}

	pvh_unlock(pai);

	if (remove) {
		os_atomic_store(&pmap_cpu_data->inflight_disconnect, false, release);
#if !XNU_MONITOR
		mp_enable_preemption();
#endif
	}

	if (!remove && tlb_flush_needed) {
		sync_tlb_flush();
	}

	if (remove && (pvet_p != PV_ENTRY_NULL)) {
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
		 * If the argument is non-NULL, the VM layer is conveying its intention that the TLBs should
		 * ultimately be flushed.  The nature of ARM TLB maintenance is such that we can flush the
		 * TLBs much more precisely if we do so inline with the pagetable updates, and PPL security
		 * model requires that we not exit the PPL without performing required TLB flushes anyway.
		 * In that case, force the flush to take place.
		 */
		options &= ~PMAP_OPTIONS_NOFLUSH;
	}
	pmap_page_protect_options_with_flush_range(ppnum, prot, options, NULL);
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

#if XNU_MONITOR
	pmap_page_protect_options_ppl(ppnum, prot, options, arg);
#else
	pmap_page_protect_options_internal(ppnum, prot, options, arg);
#endif

	PMAP_TRACE(2, PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_END);
}


#if __has_feature(ptrauth_calls) && defined(XNU_TARGET_OS_OSX)
MARK_AS_PMAP_TEXT void
pmap_disable_user_jop_internal(pmap_t pmap)
{
	if (pmap == kernel_pmap) {
		panic("%s: called with kernel_pmap", __func__);
	}
	validate_pmap_mutable(pmap);
	pmap->disable_jop = true;
}

void
pmap_disable_user_jop(pmap_t pmap)
{
#if XNU_MONITOR
	pmap_disable_user_jop_ppl(pmap);
#else
	pmap_disable_user_jop_internal(pmap);
#endif
}
#endif /* __has_feature(ptrauth_calls) && defined(XNU_TARGET_OS_OSX) */

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

MARK_AS_PMAP_TEXT vm_map_address_t
pmap_protect_options_internal(
	pmap_t pmap,
	vm_map_address_t start,
	vm_map_address_t end,
	vm_prot_t prot,
	unsigned int options,
	__unused void *args)
{
	tt_entry_t      *tte_p;
	pt_entry_t      *bpte_p, *epte_p;
	pt_entry_t      *pte_p;
	boolean_t        set_NX = TRUE;
	boolean_t        set_XO = FALSE;
	boolean_t        should_have_removed = FALSE;
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
			should_have_removed = TRUE;
		}
	} else
#endif
	{
		/* Determine the new protection. */
		switch (prot) {
		case VM_PROT_EXECUTE:
			set_XO = TRUE;
			OS_FALLTHROUGH;
		case VM_PROT_READ:
		case VM_PROT_READ | VM_PROT_EXECUTE:
			break;
		case VM_PROT_READ | VM_PROT_WRITE:
		case VM_PROT_ALL:
			return end;         /* nothing to do */
		default:
			should_have_removed = TRUE;
		}
	}

	if (should_have_removed) {
		panic("%s: should have been a remove operation, "
		    "pmap=%p, start=%p, end=%p, prot=%#x, options=%#x, args=%p",
		    __FUNCTION__,
		    pmap, (void *)start, (void *)end, prot, options, args);
	}

#if DEVELOPMENT || DEBUG
	if ((prot & VM_PROT_EXECUTE) || !nx_enabled || !pmap->nx_enabled)
#else
	if ((prot & VM_PROT_EXECUTE))
#endif
	{
		set_NX = FALSE;
	} else {
		set_NX = TRUE;
	}

	const uint64_t pmap_page_size = PAGE_RATIO * pt_attr_page_size(pt_attr);
	vm_map_address_t va = start;
	unsigned int npages = 0;

	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

	tte_p = pmap_tte(pmap, start);

	if ((tte_p != (tt_entry_t *) NULL) && (*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		bpte_p = (pt_entry_t *) ttetokv(*tte_p);
		bpte_p = &bpte_p[pte_index(pt_attr, start)];
		epte_p = bpte_p + ((end - start) >> pt_attr_leaf_shift(pt_attr));
		pte_p = bpte_p;

		for (pte_p = bpte_p;
		    pte_p < epte_p;
		    pte_p += PAGE_RATIO, va += pmap_page_size) {
			++npages;
			if (__improbable(!(npages % PMAP_DEFAULT_PREEMPTION_CHECK_PAGE_INTERVAL) &&
			    pmap_pending_preemption())) {
				break;
			}
			pt_entry_t spte;
#if DEVELOPMENT || DEBUG
			boolean_t  force_write = FALSE;
#endif

			spte = *((volatile pt_entry_t*)pte_p);

			if ((spte == ARM_PTE_TYPE_FAULT) ||
			    ARM_PTE_IS_COMPRESSED(spte, pte_p)) {
				continue;
			}

			pmap_paddr_t    pa;
			unsigned int    pai = 0;
			boolean_t       managed = FALSE;

			while (!managed) {
				/*
				 * It may be possible for the pte to transition from managed
				 * to unmanaged in this timeframe; for now, elide the assert.
				 * We should break out as a consequence of checking pa_valid.
				 */
				// assert(!ARM_PTE_IS_COMPRESSED(spte));
				pa = pte_to_pa(spte);
				if (!pa_valid(pa)) {
					break;
				}
				pai = pa_index(pa);
				pvh_lock(pai);
				spte = *((volatile pt_entry_t*)pte_p);
				pa = pte_to_pa(spte);
				if (pai == pa_index(pa)) {
					managed = TRUE;
					break; // Leave the PVH locked as we will unlock it after we free the PTE
				}
				pvh_unlock(pai);
			}

			if ((spte == ARM_PTE_TYPE_FAULT) ||
			    ARM_PTE_IS_COMPRESSED(spte, pte_p)) {
				continue;
			}

			pt_entry_t      tmplate;

			if (pmap == kernel_pmap) {
#if DEVELOPMENT || DEBUG
				if ((options & PMAP_OPTIONS_PROTECT_IMMEDIATE) && (prot & VM_PROT_WRITE)) {
					force_write = TRUE;
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RWNA));
				} else
#endif
				{
					tmplate = ((spte & ~ARM_PTE_APMASK) | ARM_PTE_AP(AP_RONA));
				}
			} else {
#if DEVELOPMENT || DEBUG
				if ((options & PMAP_OPTIONS_PROTECT_IMMEDIATE) && (prot & VM_PROT_WRITE)) {
					assert(pmap->type != PMAP_TYPE_NESTED);
					force_write = TRUE;
					tmplate = ((spte & ~ARM_PTE_APMASK) | pt_attr_leaf_rw(pt_attr));
				} else
#endif
				{
					tmplate = ((spte & ~ARM_PTE_APMASK) | pt_attr_leaf_ro(pt_attr));
				}
			}

			/*
			 * XXX Removing "NX" would
			 * grant "execute" access
			 * immediately, bypassing any
			 * checks VM might want to do
			 * in its soft fault path.
			 * pmap_protect() and co. are
			 * not allowed to increase
			 * access permissions.
			 */
			if (set_NX) {
				tmplate |= pt_attr_leaf_xn(pt_attr);
			} else {
				if (pmap == kernel_pmap) {
					/* do NOT clear "PNX"! */
					tmplate |= ARM_PTE_NX;
				} else {
					/* do NOT clear "NX"! */
					tmplate |= pt_attr_leaf_x(pt_attr);
					if (set_XO) {
						tmplate &= ~ARM_PTE_APMASK;
						tmplate |= pt_attr_leaf_rona(pt_attr);
					}
				}
			}

#if DEVELOPMENT || DEBUG
			if (force_write) {
				/*
				 * TODO: Run CS/Monitor checks here.
				 */
				if (managed) {
					/*
					 * We are marking the page as writable,
					 * so we consider it to be modified and
					 * referenced.
					 */
					ppattr_pa_set_bits(pa, PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
					tmplate |= ARM_PTE_AF;

					if (ppattr_test_reffault(pai)) {
						ppattr_clear_reffault(pai);
					}

					if (ppattr_test_modfault(pai)) {
						ppattr_clear_modfault(pai);
					}
				}
			} else if (options & PMAP_OPTIONS_PROTECT_IMMEDIATE) {
				/*
				 * An immediate request for anything other than
				 * write should still mark the page as
				 * referenced if managed.
				 */
				if (managed) {
					ppattr_pa_set_bits(pa, PP_ATTR_REFERENCED);
					tmplate |= ARM_PTE_AF;

					if (ppattr_test_reffault(pai)) {
						ppattr_clear_reffault(pai);
					}
				}
			}
#endif

			/* We do not expect to write fast fault the entry. */
			pte_set_was_writeable(tmplate, false);

			write_pte_fast(pte_p, tmplate);

			if (managed) {
				pvh_assert_locked(pai);
				pvh_unlock(pai);
			}
		}
		FLUSH_PTE_STRONG();
		PMAP_UPDATE_TLBS(pmap, start, va, need_strong_sync, true);
	} else {
		va = end;
	}

	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
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

#if XNU_MONITOR
		beg = pmap_protect_options_ppl(pmap, beg, l, prot, options, args);
#else
		beg = pmap_protect_options_internal(pmap, beg, l, prot, options, args);
#endif
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
		if (pmap_enter_addr(pmap, va, pa, prot, VM_PROT_NONE, attr, TRUE) != KERN_SUCCESS) {
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
	boolean_t wired)
{
	return pmap_enter_options_addr(pmap, v, pa, prot, fault_type, flags, wired, 0, NULL);
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
	boolean_t wired)
{
	return pmap_enter_addr(pmap, v, ((pmap_paddr_t)pn) << PAGE_SHIFT, prot, fault_type, flags, wired);
}

/*
 * Attempt to commit the pte.
 * Succeeds iff able to change *pte_p from old_pte to new_pte.
 * Performs no page table or accounting writes on failures.
 */
static inline bool
pmap_enter_pte(pmap_t pmap, pt_entry_t *pte_p, pt_entry_t *old_pte, pt_entry_t new_pte, vm_map_address_t v)
{
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	bool success = false, changed_wiring = false;

	__unreachable_ok_push
	if (TEST_PAGE_RATIO_4) {
		/*
		 * 16K virtual pages w/ 4K hw pages.
		 * We actually need to update 4 ptes here which can't easily be done atomically.
		 * As a result we require the exclusive pmap lock.
		 */
		pmap_assert_locked(pmap, PMAP_LOCK_EXCLUSIVE);
		*old_pte = *pte_p;
		if (*old_pte == new_pte) {
			/* Another thread completed this operation. Nothing to do here. */
			success = true;
		} else if (pa_valid(pte_to_pa(new_pte)) && pte_to_pa(*old_pte) != pte_to_pa(new_pte) &&
		    (*old_pte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE) {
			/* pte has been modified by another thread and we hold the wrong PVH lock. Retry. */
			success = false;
		} else {
			write_pte_fast(pte_p, new_pte);
			success = true;
		}
	} else {
		success = os_atomic_cmpxchgv(pte_p, *old_pte, new_pte, old_pte, acq_rel);
	}
	__unreachable_ok_pop

	if (success && *old_pte != new_pte) {
		if ((*old_pte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE) {
			FLUSH_PTE_STRONG();
			PMAP_UPDATE_TLBS(pmap, v, v + (pt_attr_page_size(pt_attr) * PAGE_RATIO), false, true);
		} else {
			FLUSH_PTE();
			__builtin_arm_isb(ISB_SY);
		}
		changed_wiring = ARM_PTE_IS_COMPRESSED(*old_pte, pte_p) ?
		    (new_pte & ARM_PTE_WIRED) != 0 :
		    (new_pte & ARM_PTE_WIRED) != (*old_pte & ARM_PTE_WIRED);

		if (pmap != kernel_pmap && changed_wiring) {
			SInt16  *ptd_wiredcnt_ptr = (SInt16 *)&(ptep_get_info(pte_p)->wiredcnt);
			if (new_pte & ARM_PTE_WIRED) {
				OSAddAtomic16(1, ptd_wiredcnt_ptr);
				pmap_ledger_credit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			} else {
				OSAddAtomic16(-1, ptd_wiredcnt_ptr);
				pmap_ledger_debit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			}
		}

		PMAP_TRACE(4 + pt_attr_leaf_level(pt_attr), PMAP_CODE(PMAP__TTE), VM_KERNEL_ADDRHIDE(pmap),
		    VM_KERNEL_ADDRHIDE(v), VM_KERNEL_ADDRHIDE(v + (pt_attr_page_size(pt_attr) * PAGE_RATIO)), new_pte);
	}
	return success;
}

MARK_AS_PMAP_TEXT static pt_entry_t
wimg_to_pte(unsigned int wimg, __unused pmap_paddr_t pa)
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
#if HAS_UCNORMAL_MEM
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITECOMB);
#else
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE);
#endif
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_POSTED:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED);
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_POSTED_REORDERED:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_REORDERED);
		pte |= ARM_PTE_NX | ARM_PTE_PNX;
		break;
	case VM_WIMG_POSTED_COMBINED_REORDERED:
		pte = ARM_PTE_ATTRINDX(CACHE_ATTRINDX_POSTED_COMBINED_REORDERED);
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
		} else if ((pmap->nested_region_asid_bitmap)
		    && (va >= pmap->nested_region_addr)
		    && (va < (pmap->nested_region_addr + pmap->nested_region_size))) {
			unsigned int index = (unsigned int)((va - pmap->nested_region_addr)  >> pt_attr_twig_shift(pt_attr));

			if ((pmap->nested_region_asid_bitmap)
			    && testbit(index, (int *)pmap->nested_region_asid_bitmap)) {
				pte |= ARM_PTE_NG;
			}
		}
		if (prot & VM_PROT_WRITE) {
			assert(pmap->type != PMAP_TYPE_NESTED);
			if (pa_valid(pa) && (!ppattr_pa_test_bits(pa, PP_ATTR_MODIFIED))) {
				if (fault_type & VM_PROT_WRITE) {
					if (set_XO) {
						pte |= pt_attr_leaf_rwna(pt_attr);
					} else {
						pte |= pt_attr_leaf_rw(pt_attr);
					}
					*pp_attr_bits |= PP_ATTR_REFERENCED | PP_ATTR_MODIFIED;
				} else {
					if (set_XO) {
						pte |= pt_attr_leaf_rona(pt_attr);
					} else {
						pte |= pt_attr_leaf_ro(pt_attr);
					}
					/*
					 * Mark the page as MODFAULT so that a subsequent write
					 * may be handled through arm_fast_fault().
					 */
					*pp_attr_bits |= PP_ATTR_REFERENCED | PP_ATTR_MODFAULT;
					pte_set_was_writeable(pte, true);
				}
			} else {
				if (set_XO) {
					pte |= pt_attr_leaf_rwna(pt_attr);
				} else {
					pte |= pt_attr_leaf_rw(pt_attr);
				}
				*pp_attr_bits |= PP_ATTR_REFERENCED;
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
	unsigned int options)
{
	ppnum_t         pn = (ppnum_t)atop(pa);
	pt_entry_t      pte;
	pt_entry_t      spte;
	pt_entry_t      *pte_p;
	bool            refcnt_updated;
	bool            wiredcnt_updated;
	bool            ro_va = false;
	unsigned int    wimg_bits;
	bool            committed = false, drop_refcnt = false, had_valid_mapping = false, skip_footprint_debit = false;
	pmap_lock_mode_t lock_mode = PMAP_LOCK_SHARED;
	kern_return_t   kr = KERN_SUCCESS;
	uint16_t pp_attr_bits;
	volatile uint16_t *refcnt;
	volatile uint16_t *wiredcnt;
	pv_free_list_t *local_pv_free;

	validate_pmap_mutable(pmap);

#if XNU_MONITOR
	if (__improbable((options & PMAP_OPTIONS_NOWAIT) == 0)) {
		panic("pmap_enter_options() called without PMAP_OPTIONS_NOWAIT set");
	}
#endif

	__unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

	if ((v) & pt_attr_leaf_offmask(pt_attr)) {
		panic("pmap_enter_options() pmap %p v 0x%llx",
		    pmap, (uint64_t)v);
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
	if (__improbable((pmap == kernel_pmap) && zone_spans_ro_va(v, v + pt_attr_page_size(pt_attr)))) {
		if (__improbable(prot != VM_PROT_READ)) {
			panic("%s: attempt to map RO zone VA 0x%llx with prot 0x%x",
			    __func__, (unsigned long long)v, prot);
		}
		ro_va = true;
	}
	assert(pn != vm_page_fictitious_addr);

	refcnt_updated = false;
	wiredcnt_updated = false;

	if ((prot & VM_PROT_EXECUTE) || TEST_PAGE_RATIO_4) {
		/*
		 * We need to take the lock exclusive here because of SPLAY_FIND in pmap_cs_enforce.
		 *
		 * See rdar://problem/59655632 for thoughts on synchronization and the splay tree
		 */
		lock_mode = PMAP_LOCK_EXCLUSIVE;
	}

	if (!pmap_lock_preempt(pmap, lock_mode)) {
		return KERN_ABORTED;
	}

	/*
	 *	Expand pmap to include this pte.  Assume that
	 *	pmap is always expanded to include enough hardware
	 *	pages to map one VM page.
	 */
	while ((pte_p = pmap_pte(pmap, v)) == PT_ENTRY_NULL) {
		/* Must unlock to expand the pmap. */
		pmap_unlock(pmap, lock_mode);

		kr = pmap_expand(pmap, v, options, pt_attr_leaf_level(pt_attr));

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		if (!pmap_lock_preempt(pmap, lock_mode)) {
			return KERN_ABORTED;
		}
	}

	if (options & PMAP_OPTIONS_NOENTER) {
		pmap_unlock(pmap, lock_mode);
		return KERN_SUCCESS;
	}

	/*
	 * Since we may not hold the pmap lock exclusive, updating the pte is
	 * done via a cmpxchg loop.
	 * We need to be careful about modifying non-local data structures before commiting
	 * the new pte since we may need to re-do the transaction.
	 */
	spte = os_atomic_load(pte_p, relaxed);
	while (!committed) {
		refcnt = NULL;
		wiredcnt = NULL;
		pv_alloc_return_t pv_status = PV_ALLOC_SUCCESS;
		had_valid_mapping = (spte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE;

		if (pmap != kernel_pmap) {
			ptd_info_t *ptd_info = ptep_get_info(pte_p);
			refcnt = &ptd_info->refcnt;
			wiredcnt = &ptd_info->wiredcnt;
			/*
			 * This check is really intended to ensure that mappings in a nested pmap can't be inserted
			 * through a top-level user pmap, which would allow a non-global mapping to be inserted into a shared
			 * region pmap and leveraged into a TLB-based write gadget (rdar://91504354).
			 * It's also a useful sanity check for other pmap types, but note that kernel page tables may not
			 * have PTDs, so we can't use the check there.
			 */
			if (__improbable(ptep_get_pmap(pte_p) != pmap)) {
				panic("%s: attempt to enter mapping at pte %p owned by pmap %p through pmap %p",
				    __func__, pte_p, ptep_get_pmap(pte_p), pmap);
			}
			/*
			 * Bump the wired count to keep the PTE page from being reclaimed.  We need this because
			 * we may drop the PVH and pmap locks later in pmap_enter() if we need to allocate
			 * or acquire the pmap lock exclusive.
			 */
			if (!wiredcnt_updated) {
				OSAddAtomic16(1, (volatile int16_t*)wiredcnt);
				wiredcnt_updated = true;
			}
			if (!refcnt_updated) {
				OSAddAtomic16(1, (volatile int16_t*)refcnt);
				refcnt_updated = true;
				drop_refcnt = true;
			}
		}

		if (had_valid_mapping && (pte_to_pa(spte) != pa)) {
			/*
			 * There is already a mapping here & it's for a different physical page.
			 * First remove that mapping.
			 *
			 * This requires that we take the pmap lock exclusive in order to call pmap_remove_range.
			 */
			if (lock_mode == PMAP_LOCK_SHARED) {
				if (pmap_lock_shared_to_exclusive(pmap)) {
					lock_mode = PMAP_LOCK_EXCLUSIVE;
				} else {
					/*
					 * We failed to upgrade to an exclusive lock.
					 * As a result we no longer hold the lock at all,
					 * so we need to re-acquire it and restart the transaction.
					 */
					pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
					lock_mode = PMAP_LOCK_EXCLUSIVE;
					/* pmap might have changed after we dropped the lock. Try again. */
					spte = os_atomic_load(pte_p, relaxed);
					continue;
				}
			}
			pmap_remove_range(pmap, v, pte_p, pte_p + PAGE_RATIO);
			spte = ARM_PTE_TYPE_FAULT;
			assert(os_atomic_load(pte_p, acquire) == ARM_PTE_TYPE_FAULT);
		}

		/*
		 * The XO index is used for TPRO mappings. To avoid exposing them as --x,
		 * the VM code tracks VM_MAP_TPRO requests and couples them with the proper
		 * read-write protection. The PMAP layer though still needs to use the right
		 * index, which is the older XO-now-TPRO one and that is specially selected
		 * here thanks to PMAP_OPTIONS_MAP_TPRO.
		 */
		if (options & PMAP_OPTIONS_MAP_TPRO) {
			pte = pmap_construct_pte(pmap, v, pa, VM_PROT_RORW_TP, fault_type, wired, pt_attr, &pp_attr_bits);
		} else {
			pte = pmap_construct_pte(pmap, v, pa, prot, fault_type, wired, pt_attr, &pp_attr_bits);
		}

		if (pa_valid(pa)) {
			unsigned int pai;
			boolean_t   is_altacct = FALSE, is_internal = FALSE, is_reusable = FALSE, is_external = FALSE;

			is_internal = FALSE;
			is_altacct = FALSE;

			pai = pa_index(pa);

			pvh_lock(pai);

			/*
			 * Make sure that the current per-cpu PV free list has
			 * enough entries (2 in the worst-case scenario) to handle the enter_pv
			 * if the transaction succeeds. We're either in the
			 * PPL (which can't be preempted) or we've explicitly disabled preemptions.
			 * Note that we can still be interrupted, but a primary
			 * interrupt handler can never enter the pmap.
			 */
#if !XNU_MONITOR
			assert(get_preemption_level() > 0);
#endif
			local_pv_free = &pmap_get_cpu_data()->pv_free;
			pv_entry_t **pv_h = pai_to_pvh(pai);
			const bool allocation_required = !pvh_test_type(pv_h, PVH_TYPE_NULL) &&
			    !(pvh_test_type(pv_h, PVH_TYPE_PTEP) && pvh_ptep(pv_h) == pte_p);

			if (__improbable(allocation_required && (local_pv_free->count < 2))) {
				pv_entry_t *new_pve_p[2] = {PV_ENTRY_NULL};
				int new_allocated_pves = 0;

				while (new_allocated_pves < 2) {
					local_pv_free = &pmap_get_cpu_data()->pv_free;
					pv_status = pv_alloc(pmap, pai, lock_mode, options, &new_pve_p[new_allocated_pves]);
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
				pvh_unlock(pai);
				kr = KERN_RESOURCE_SHORTAGE;
				break;
			} else if (pv_status == PV_ALLOC_RETRY) {
				pvh_unlock(pai);
				/* We dropped the pmap and PVH locks to allocate. Retry transaction. */
				spte = os_atomic_load(pte_p, relaxed);
				continue;
			}

			if ((flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT))) {
				wimg_bits = (flags & (VM_WIMG_MASK | VM_WIMG_USE_DEFAULT));
			} else {
				wimg_bits = pmap_cache_attributes(pn);
			}

			/* We may be retrying this operation after dropping the PVH lock.
			 * Cache attributes for the physical page may have changed while the lock
			 * was dropped, so clear any cache attributes we may have previously set
			 * in the PTE template. */
			pte &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
			pte |= pmap_get_pt_ops(pmap)->wimg_to_pte(wimg_bits, pa);

#if XNU_MONITOR
			/* The regular old kernel is not allowed to remap PPL pages. */
			if (__improbable(ppattr_pa_test_monitor(pa))) {
				panic("%s: page belongs to PPL, "
				    "pmap=%p, v=0x%llx, pa=%p, prot=0x%x, fault_type=0x%x, flags=0x%x, wired=%u, options=0x%x",
				    __FUNCTION__,
				    pmap, v, (void*)pa, prot, fault_type, flags, wired, options);
			}

			if (__improbable(pvh_get_flags(pai_to_pvh(pai)) & PVH_FLAG_LOCKDOWN_MASK)) {
				panic("%s: page locked down, "
				    "pmap=%p, v=0x%llx, pa=%p, prot=0x%x, fault_type=0x%x, flags=0x%x, wired=%u, options=0x%x",
				    __FUNCTION__,
				    pmap, v, (void *)pa, prot, fault_type, flags, wired, options);
			}
#endif



			committed = pmap_enter_pte(pmap, pte_p, &spte, pte, v);
			if (!committed) {
				pvh_unlock(pai);
				continue;
			}
			had_valid_mapping = (spte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE;
			/* End of transaction. Commit pv changes, pa bits, and memory accounting. */

			assert(!had_valid_mapping || (pte_to_pa(spte) == pa));
			/*
			 * If there was already a valid pte here then we reuse its reference
			 * on the ptd and drop the one that we took above.
			 */
			drop_refcnt = had_valid_mapping;

			if (!had_valid_mapping) {
				pv_entry_t *new_pve_p = PV_ENTRY_NULL;
				int pve_ptep_idx = 0;
				pv_status = pmap_enter_pv(pmap, pte_p, pai, options, lock_mode, &new_pve_p, &pve_ptep_idx);
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

			pvh_unlock(pai);

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
						if (ARM_PTE_IS_COMPRESSED(spte, pte_p) && !(spte & ARM_PTE_COMPRESSED_ALT)) {
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

#if XNU_MONITOR
			if ((wimg_bits & PP_ATTR_MONITOR) && !pmap_ppl_disable) {
				uint64_t xprr_perm = pte_to_xprr_perm(pte);
				switch (xprr_perm) {
				case XPRR_KERN_RO_PERM:
					break;
				case XPRR_KERN_RW_PERM:
					pte &= ~ARM_PTE_XPRR_MASK;
					pte |= xprr_perm_to_pte(XPRR_PPL_RW_PERM);
					break;
				default:
					panic("Unsupported xPRR perm %llu for pte 0x%llx", xprr_perm, (uint64_t)pte);
				}
			}
#endif
			committed = pmap_enter_pte(pmap, pte_p, &spte, pte, v);
			if (committed) {
				had_valid_mapping = (spte & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE;
				assert(!had_valid_mapping || (pte_to_pa(spte) == pa));

				/**
				 * If there was already a valid pte here then we reuse its
				 * reference on the ptd and drop the one that we took above.
				 */
				drop_refcnt = had_valid_mapping;
			}
		}
		if (committed) {
			if (ARM_PTE_IS_COMPRESSED(spte, pte_p)) {
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
				/* The old entry held a reference so drop the extra one that we took above. */
				drop_refcnt = true;
			}
		}
	}

	if (drop_refcnt && refcnt != NULL) {
		assert(refcnt_updated);
		if (OSAddAtomic16(-1, (volatile int16_t*)refcnt) <= 0) {
			panic("pmap_enter(): over-release of ptdp %p for pte %p", ptep_get_ptd(pte_p), pte_p);
		}
	}

	if (wiredcnt_updated && (OSAddAtomic16(-1, (volatile int16_t*)wiredcnt) <= 0)) {
		panic("pmap_enter(): over-unwire of ptdp %p for pte %p", ptep_get_ptd(pte_p), pte_p);
	}

	pmap_unlock(pmap, lock_mode);

	if (__improbable(ro_va && kr == KERN_SUCCESS)) {
		pmap_phys_write_disable(v);
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
	__unused void   *arg)
{
	kern_return_t kr = KERN_FAILURE;


	PMAP_TRACE(2, PMAP_CODE(PMAP__ENTER) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(v), pa, prot);


	const bool nowait_requested = (options & PMAP_OPTIONS_NOWAIT) != 0;
	do {
#if XNU_MONITOR
		kr = pmap_enter_options_ppl(pmap, v, pa, prot, fault_type, flags, wired, options | PMAP_OPTIONS_NOWAIT);
#else
		kr = pmap_enter_options_internal(pmap, v, pa, prot, fault_type, flags, wired, options);
#endif

		if (kr == KERN_RESOURCE_SHORTAGE) {
#if XNU_MONITOR
			pmap_alloc_page_for_ppl(nowait_requested ? PMAP_PAGES_ALLOCATE_NOWAIT : 0);
#endif
			if (nowait_requested) {
				break;
			}
		}
	} while (kr == KERN_RESOURCE_SHORTAGE || kr == KERN_ABORTED);

#if XNU_MONITOR
	pmap_ledger_check_balance(pmap);
#endif

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
	__unused void   *arg)
{
	return pmap_enter_options_addr(pmap, v, ((pmap_paddr_t)pn) << PAGE_SHIFT, prot, fault_type, flags, wired, options, arg);
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
	pt_entry_t     *pte_p;
	pmap_paddr_t    pa;

	validate_pmap_mutable(pmap);

	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

	const pt_attr_t * pt_attr = pmap_get_pt_attr(pmap);

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
	/*
	 * Use volatile loads to prevent the compiler from collapsing references to 'pa' back to loads of pte_p
	 * until we've grabbed the final PVH lock; PTE contents may change during this time.
	 */
	pa = pte_to_pa(*((volatile pt_entry_t*)pte_p));

	while (pa_valid(pa)) {
		pmap_paddr_t new_pa;

		pvh_lock(pa_index(pa));
		new_pa = pte_to_pa(*((volatile pt_entry_t*)pte_p));

		if (pa == new_pa) {
			break;
		}

		pvh_unlock(pa_index(pa));
		pa = new_pa;
	}

	/* PTE checks must be performed after acquiring the PVH lock (if applicable for the PA) */
	if ((*pte_p == ARM_PTE_EMPTY) || (ARM_PTE_IS_COMPRESSED(*pte_p, pte_p))) {
		if (!wired) {
			/* PTE cleared by prior remove/disconnect operation */
			goto pmap_change_wiring_cleanup;
		} else {
			panic("%s: Attempt to wire empty/compressed PTE %p (=0x%llx) for pmap %p",
			    __func__, pte_p, (uint64_t)*pte_p, pmap);
		}
	}

	assertf((*pte_p & ARM_PTE_TYPE_VALID) == ARM_PTE_TYPE, "invalid pte %p (=0x%llx)", pte_p, (uint64_t)*pte_p);
	if (wired != pte_is_wired(*pte_p)) {
		pte_set_wired(pmap, pte_p, wired);
		if (pmap != kernel_pmap) {
			if (wired) {
				pmap_ledger_credit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			} else if (!wired) {
				pmap_ledger_debit(pmap, task_ledgers.wired_mem, pt_attr_page_size(pt_attr) * PAGE_RATIO);
			}
		}
	}

pmap_change_wiring_cleanup:
	if (pa_valid(pa)) {
		pvh_unlock(pa_index(pa));
	}

pmap_change_wiring_return:
	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
}

void
pmap_change_wiring(
	pmap_t pmap,
	vm_map_address_t v,
	boolean_t wired)
{
#if XNU_MONITOR
	pmap_change_wiring_ppl(pmap, v, wired);

	pmap_ledger_check_balance(pmap);
#else
	pmap_change_wiring_internal(pmap, v, wired);
#endif
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
#if XNU_MONITOR
		return pmap_find_pa_ppl(pmap, va);
#else
		return pmap_find_pa_internal(pmap, va);
#endif
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
	/**
	 * Attempt to do the translation first in hardware using the AT (address
	 * translation) instruction. This will attempt to use the MMU to do the
	 * translation for us.
	 */
	pmap_paddr_t pa = mmu_kvtop(va);

	if (pa) {
		return pa;
	}

	/* If the MMU can't find the mapping, then manually walk the page tables. */
	return pmap_vtophys(kernel_pmap, va);
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
	pmap_paddr_t pa = kvtophys(va);

	if (!pa_valid(pa)) {
		panic("%s: Invalid or non-kernel-managed physical page returned, "
		    "pa: %#llx, va: %p", __func__, (uint64_t)pa, (void *)va);
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
	pv_entry_t **pvh = pai_to_pvh(pa_index(ml_static_vtop((vm_offset_t)pte_p)));

	if (pvh_test_type(pvh, PVH_TYPE_NULL)) {
		if (alloc_ptd) {
			/*
			 * This path should only be invoked from arm_vm_init.  If we are emulating 16KB pages
			 * on 4KB hardware, we may already have allocated a page table descriptor for a
			 * bootstrap request, so we check for an existing PTD here.
			 */
			ptdp = ptd_alloc(pmap);
			if (ptdp == NULL) {
				panic("%s: unable to allocate PTD", __func__);
			}
			pvh_update_head_unlocked(pvh, ptdp, PVH_TYPE_PTDP);
			/* Clear all PVH flags when using a page for a PTD to avoid tripping unexpected page flag usage checks. */
			pvh_set_flags(pvh, 0);
		} else {
			panic("pmap_init_pte_page(): pte_p %p", pte_p);
		}
	} else if (pvh_test_type(pvh, PVH_TYPE_PTDP)) {
		ptdp = pvh_ptd(pvh);
	} else {
		panic("pmap_init_pte_page(): invalid PVH type for pte_p %p", pte_p);
	}

	// below barrier ensures previous updates to the page are visible to PTW before
	// it is linked to the PTE of previous level
	__builtin_arm_dmb(DMB_ISHST);
	ptd_info_init(ptdp, pmap, va, ttlevel, pte_p);
}

/*
 *	Routine:	pmap_expand
 *
 *	Expands a pmap to be able to map the specified virtual address.
 *
 *	Allocates new memory for the default (COARSE) translation table
 *	entry, initializes all the pte entries to ARM_PTE_TYPE_FAULT and
 *	also allocates space for the corresponding pv entries.
 *
 *	Nothing should be locked.
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
	pmap_paddr_t    pa;
	unsigned int    ttlevel = pt_attr_root_level(pt_attr);
	tt_entry_t              *tte_p;
	tt_entry_t              *tt_p;

	pa = 0x0ULL;
	tt_p =  (tt_entry_t *)NULL;

	for (; ttlevel < level; ttlevel++) {
		pmap_lock(pmap, PMAP_LOCK_SHARED);

		if (pmap_ttne(pmap, ttlevel + 1, v) == PT_ENTRY_NULL) {
			pmap_unlock(pmap, PMAP_LOCK_SHARED);
			while (pmap_tt_allocate(pmap, &tt_p, ttlevel + 1, ((options & PMAP_TT_ALLOCATE_NOWAIT)? PMAP_PAGES_ALLOCATE_NOWAIT : 0)) != KERN_SUCCESS) {
				if (options & PMAP_OPTIONS_NOWAIT) {
					return KERN_RESOURCE_SHORTAGE;
				}
#if XNU_MONITOR
				panic("%s: failed to allocate tt, "
				    "pmap=%p, v=%p, options=0x%x, level=%u",
				    __FUNCTION__,
				    pmap, (void *)v, options, level);
#else
				VM_PAGE_WAIT();
#endif
			}
			pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
			if ((pmap_ttne(pmap, ttlevel + 1, v) == PT_ENTRY_NULL)) {
				pmap_init_pte_page(pmap, (pt_entry_t *) tt_p, v, ttlevel + 1, FALSE);
				pa = kvtophys_nofail((vm_offset_t)tt_p);
				tte_p = pmap_ttne(pmap, ttlevel, v);
				*tte_p = (pa & ARM_TTE_TABLE_MASK) | ARM_TTE_TYPE_TABLE | ARM_TTE_VALID;
				PMAP_TRACE(4 + ttlevel, PMAP_CODE(PMAP__TTE), VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(v & ~pt_attr_ln_offmask(pt_attr, ttlevel)),
				    VM_KERNEL_ADDRHIDE((v & ~pt_attr_ln_offmask(pt_attr, ttlevel)) + pt_attr_ln_size(pt_attr, ttlevel)), *tte_p);
				pa = 0x0ULL;
				tt_p = (tt_entry_t *)NULL;
			}
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
		} else {
			pmap_unlock(pmap, PMAP_LOCK_SHARED);
		}

		if (tt_p != (tt_entry_t *)NULL) {
			pmap_tt_deallocate(pmap, tt_p, ttlevel + 1);
			tt_p = (tt_entry_t *)NULL;
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
	 * or may contain wired mappings.  However, with the relatively recent change to
	 * make pmap_page_reclaim() non-fatal in the event that it doesn't find an eligible
	 * page, it may make sense to call that function here.
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

#if XNU_MONITOR
	if (__improbable(bits & PP_ATTR_PPL_OWNED_BITS)) {
		panic("%s: illegal request, "
		    "pn=%u, bits=%#x, options=%#x, arg=%p, flush_range=%p",
		    __FUNCTION__,
		    pn, bits, options, arg, flush_range);
	}
#endif
	if ((arg != NULL) || (flush_range != NULL)) {
		options = options & ~PMAP_OPTIONS_NOFLUSH;
	}

	if (__improbable((bits & PP_ATTR_MODIFIED) &&
	    (options & PMAP_OPTIONS_NOFLUSH))) {
		panic("phys_attribute_clear(0x%x,0x%x,0x%x,%p,%p): "
		    "should not clear 'modified' without flushing TLBs\n",
		    pn, bits, options, arg, flush_range);
	}

	assert(pn != vm_page_fictitious_addr);

	if (options & PMAP_OPTIONS_CLEAR_WRITE) {
		assert(bits == PP_ATTR_MODIFIED);

		pmap_page_protect_options_with_flush_range(pn, (VM_PROT_ALL & ~VM_PROT_WRITE), options, flush_range);
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

	if (arm_force_fast_fault_with_flush_range(pn, allow_mode, options, flush_range)) {
		ppattr_pa_clear_bits(pa, (pp_attr_t)bits);
	}
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
	unsigned int npages = 0;

	if (tte_p == (tt_entry_t *) NULL) {
		return end;
	}

	if ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
		pte_p = (pt_entry_t *) ttetokv(*tte_p);

		start_pte_p = &pte_p[pte_index(pt_attr, start)];
		end_pte_p = start_pte_p + ((end - start) >> pt_attr_leaf_shift(pt_attr));
		assert(end_pte_p >= start_pte_p);
		for (curr_pte_p = start_pte_p; curr_pte_p < end_pte_p; curr_pte_p++, va += pmap_page_size) {
			if (__improbable(npages++ && pmap_pending_preemption())) {
				return va;
			}
			pmap_paddr_t pa = pte_to_pa(*((volatile pt_entry_t*)curr_pte_p));
			if (pa_valid(pa)) {
				ppnum_t pn = (ppnum_t) atop(pa);
				phys_attribute_clear_with_flush_range(pn, bits, options, NULL, flush_range);
			}
		}
	}
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
		if ((va < curr_end) || pmap_pending_preemption()) {
			break;
		}
	}
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
	if (flush_range.ptfr_flush_needed) {
		flush_range.ptfr_end = va;
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

	PMAP_TRACE(3, PMAP_CODE(PMAP__ATTRIBUTE_CLEAR_RANGE) | DBG_FUNC_START, bits);

	while (start < end) {
#if XNU_MONITOR
		start = phys_attribute_clear_range_ppl(pmap, start, end, bits, options);
#else
		start = phys_attribute_clear_range_internal(pmap, start, end, bits, options);
#endif
	}

	PMAP_TRACE(3, PMAP_CODE(PMAP__ATTRIBUTE_CLEAR_RANGE) | DBG_FUNC_END);
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

#if XNU_MONITOR
	phys_attribute_clear_ppl(pn, bits, options, arg);
#else
	phys_attribute_clear_internal(pn, bits, options, arg);
#endif

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

#if XNU_MONITOR
	if (bits & PP_ATTR_PPL_OWNED_BITS) {
		panic("%s: illegal request, "
		    "pn=%u, bits=%#x",
		    __FUNCTION__,
		    pn, bits);
	}
#endif

	ppattr_pa_set_bits(pa, (uint16_t)bits);

	return;
}

static void
phys_attribute_set(
	ppnum_t pn,
	unsigned int bits)
{
#if XNU_MONITOR
	phys_attribute_set_ppl(pn, bits);
#else
	phys_attribute_set_internal(pn, bits);
#endif
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

#if XNU_MONITOR
boolean_t
pmap_is_monitor(ppnum_t pn)
{
	assert(pa_valid(ptoa(pn)));
	return phys_attribute_test(pn, PP_ATTR_MONITOR);
}
#endif

void
pmap_lock_phys_page(ppnum_t pn)
{
#if !XNU_MONITOR
	unsigned int    pai;
	pmap_paddr_t    phys = ptoa(pn);

	if (pa_valid(phys)) {
		pai = pa_index(phys);
		pvh_lock(pai);
	} else
#else
	(void)pn;
#endif
	{ simple_lock(&phys_backup_lock, LCK_GRP_NULL);}
}


void
pmap_unlock_phys_page(ppnum_t pn)
{
#if !XNU_MONITOR
	unsigned int    pai;
	pmap_paddr_t    phys = ptoa(pn);

	if (pa_valid(phys)) {
		pai = pa_index(phys);
		pvh_unlock(pai);
	} else
#else
	(void)pn;
#endif
	{ simple_unlock(&phys_backup_lock);}
}

MARK_AS_PMAP_TEXT static void
pmap_switch_user_ttb(pmap_t pmap, pmap_cpu_data_t *cpu_data_ptr)
{
	if (pmap != kernel_pmap) {
		cpu_data_ptr->cpu_nested_pmap = pmap->nested_pmap;
		cpu_data_ptr->cpu_nested_pmap_attr = (cpu_data_ptr->cpu_nested_pmap == NULL) ?
		    NULL : pmap_get_pt_attr(cpu_data_ptr->cpu_nested_pmap);
		cpu_data_ptr->cpu_nested_region_addr = pmap->nested_region_addr;
		cpu_data_ptr->cpu_nested_region_size = pmap->nested_region_size;
#if __ARM_MIXED_PAGE_SIZE__
		cpu_data_ptr->commpage_page_shift = pt_attr_leaf_shift(pmap_get_pt_attr(pmap));
#endif
	}


#if __ARM_MIXED_PAGE_SIZE__
	if ((pmap != kernel_pmap) && (pmap_get_pt_attr(pmap)->pta_tcr_value != get_tcr())) {
		set_tcr(pmap_get_pt_attr(pmap)->pta_tcr_value);
	}
#endif /* __ARM_MIXED_PAGE_SIZE__ */


	if (pmap != kernel_pmap) {
		set_mmu_ttb((pmap->ttep & TTBR_BADDR_MASK) | (((uint64_t)pmap->hw_asid) << TTBR_ASID_SHIFT));
	} else if (!pmap_user_ttb_is_clear()) {
		pmap_clear_user_ttb_internal();
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
#if XNU_MONITOR
	pmap_clear_user_ttb_ppl();
#else
	pmap_clear_user_ttb_internal();
#endif
	PMAP_TRACE(3, PMAP_CODE(PMAP__CLEAR_USER_TTB) | DBG_FUNC_END);
}


#if defined(__arm64__)
/*
 * Marker for use in multi-pass fast-fault PV list processing.
 * ARM_PTE_COMPRESSED should never otherwise be set on PTEs processed by
 * these functions, as compressed PTEs should never be present in PV lists.
 * Note that this only holds true for arm64; for arm32 we don't have enough
 * SW bits in the PTE, so the same bit does double-duty as the COMPRESSED
 * and WRITEABLE marker depending on whether the PTE is valid.
 */
#define ARM_PTE_FF_MARKER ARM_PTE_COMPRESSED
_Static_assert(ARM_PTE_COMPRESSED != ARM_PTE_WRITEABLE, "compressed bit aliases writeable");
_Static_assert(ARM_PTE_COMPRESSED != ARM_PTE_WIRED, "compressed bit aliases wired");
#endif


MARK_AS_PMAP_TEXT static boolean_t
arm_force_fast_fault_with_flush_range(
	ppnum_t         ppnum,
	vm_prot_t       allow_mode,
	int             options,
	pmap_tlb_flush_range_t *flush_range)
{
	pmap_paddr_t     phys = ptoa(ppnum);
	pv_entry_t      *pve_p;
	pt_entry_t      *pte_p;
	unsigned int     pai;
	unsigned int     pass1_updated = 0;
	unsigned int     pass2_updated = 0;
	boolean_t        result;
	pv_entry_t     **pv_h;
	bool             is_reusable;
	bool             ref_fault;
	bool             mod_fault;
	bool             clear_write_fault = false;
	bool             ref_aliases_mod = false;
	bool             mustsynch = ((options & PMAP_OPTIONS_FF_LOCKED) == 0);

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(phys)) {
		return FALSE;   /* Not a managed page. */
	}

	result = TRUE;
	ref_fault = false;
	mod_fault = false;
	pai = pa_index(phys);
	if (__probable(mustsynch)) {
		pvh_lock(pai);
	}
	pv_h = pai_to_pvh(pai);

#if XNU_MONITOR
	if (__improbable(ppattr_pa_test_monitor(phys))) {
		panic("%s: PA 0x%llx belongs to PPL.", __func__, (uint64_t)phys);
	}
#endif
	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(pv_h);
	} else if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_pve_list(pv_h);
	} else if (__improbable(!pvh_test_type(pv_h, PVH_TYPE_NULL))) {
		panic("%s: invalid PV head 0x%llx for PA 0x%llx", __func__, (uint64_t)(*pv_h), (uint64_t)phys);
	}

	is_reusable = ppattr_test_reusable(pai);

	/*
	 * issue_tlbi is used to indicate that this function will need to issue at least one TLB
	 * invalidation during pass 2.  tlb_flush_needed only indicates that PTE permissions have
	 * changed and that a TLB flush will be needed *at some point*, so we'll need to call
	 * FLUSH_PTE_STRONG() to synchronize prior PTE updates.  In the case of a flush_range
	 * operation, TLB invalidation may be handled by the caller so it's possible for
	 * tlb_flush_needed to be true while issue_tlbi is false.
	 */
	bool issue_tlbi = false;
	bool tlb_flush_needed = false;

	pv_entry_t *orig_pve_p = pve_p;
	pt_entry_t *orig_pte_p = pte_p;
	int pve_ptep_idx = 0;

	/*
	 * Pass 1: Make any necessary PTE updates, marking PTEs that will require
	 * TLB invalidation in pass 2.
	 */
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		pt_entry_t       spte;
		pt_entry_t       tmplate;

		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto fff_skip_pve_pass1;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto fff_skip_pve_pass1;
		}
#endif
		if (*pte_p == ARM_PTE_EMPTY) {
			panic("pte is empty: pte_p=%p ppnum=0x%x", pte_p, ppnum);
		}
		if (ARM_PTE_IS_COMPRESSED(*pte_p, pte_p)) {
			panic("pte is COMPRESSED: pte_p=%p ppnum=0x%x", pte_p, ppnum);
		}

		const pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		const vm_map_address_t va = ptd_get_va(ptdp, pte_p);
		const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

		assert(va >= pmap->min && va < pmap->max);

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

		bool wiredskip = pte_is_wired(*pte_p) &&
		    ((options & PMAP_OPTIONS_FF_WIRED) == 0);

		if (wiredskip) {
			result = FALSE;
			goto fff_skip_pve_pass1;
		}

		spte = *pte_p;
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

#if MACH_ASSERT && XNU_MONITOR
		if (is_pte_xprr_protected(pmap, spte)) {
			if (pte_to_xprr_perm(spte) != pte_to_xprr_perm(tmplate)) {
				panic("%s: attempted to mutate an xPRR mapping pte_p=%p, pmap=%p, pv_h=%p, pve_p=%p, pte=0x%llx, tmplate=0x%llx, va=0x%llx, "
				    "ppnum=0x%x, options=0x%x, allow_mode=0x%x",
				    __FUNCTION__, pte_p, pmap, pv_h, pve_p, (unsigned long long)spte, (unsigned long long)tmplate, (unsigned long long)va,
				    ppnum, options, allow_mode);
			}
		}
#endif /* MACH_ASSERT && XNU_MONITOR */

		if (result && (tmplate != spte)) {
			if ((spte & (~ARM_PTE_WRITEABLE)) != (tmplate & (~ARM_PTE_WRITEABLE)) &&
			    !(options & PMAP_OPTIONS_NOFLUSH)) {
				tlb_flush_needed = true;
				if (!flush_range || (flush_range->ptfr_pmap != pmap) ||
				    va >= flush_range->ptfr_end || va < flush_range->ptfr_start) {
#ifdef ARM_PTE_FF_MARKER
					assert(!(spte & ARM_PTE_FF_MARKER));
					tmplate |= ARM_PTE_FF_MARKER;
					++pass1_updated;
#endif
					issue_tlbi = true;
				}
			}
			write_pte_fast(pte_p, tmplate);
		}

fff_skip_pve_pass1:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}

	if (tlb_flush_needed) {
		FLUSH_PTE_STRONG();
	}

	if (!issue_tlbi) {
		goto fff_finish;
	}

	/* Pass 2: Issue any required TLB invalidations */
	pve_p = orig_pve_p;
	pte_p = orig_pte_p;
	pve_ptep_idx = 0;

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto fff_skip_pve_pass2;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto fff_skip_pve_pass2;
		}
#endif

#ifdef ARM_PTE_FF_MARKER
		pt_entry_t spte = *pte_p;

		if (!(spte & ARM_PTE_FF_MARKER)) {
			goto fff_skip_pve_pass2;
		} else {
			spte &= (~ARM_PTE_FF_MARKER);
			/* No need to synchronize with the TLB flush; we're changing a SW-managed bit */
			write_pte_fast(pte_p, spte);
			++pass2_updated;
		}
#endif
		const pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		const vm_map_address_t va = ptd_get_va(ptdp, pte_p);

		if (!flush_range || (flush_range->ptfr_pmap != pmap) ||
		    (va >= flush_range->ptfr_end) || (va < flush_range->ptfr_start)) {
			pmap_get_pt_ops(pmap)->flush_tlb_region_async(va,
			    pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO, pmap, true);
		}

fff_skip_pve_pass2:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}

fff_finish:
	if (__improbable(pass1_updated != pass2_updated)) {
		panic("%s: first pass (%u) and second pass (%u) disagree on updated mappings",
		    __func__, pass1_updated, pass2_updated);
	}

	/*
	 * If we are using the same approach for ref and mod
	 * faults on this PTE, do not clear the write fault;
	 * this would cause both ref and mod to be set on the
	 * page again, and prevent us from taking ANY read/write
	 * fault on the mapping.
	 */
	if (clear_write_fault && !ref_aliases_mod) {
		arm_clear_fast_fault(ppnum, VM_PROT_WRITE, PT_ENTRY_NULL);
	}
	if (tlb_flush_needed) {
		if (flush_range) {
			/* Delayed flush. Signal to the caller that the flush is needed. */
			flush_range->ptfr_flush_needed = true;
		} else {
			sync_tlb_flush();
		}
	}

	/* update global "reusable" status for this page */
	if ((options & PMAP_OPTIONS_CLEAR_REUSABLE) && is_reusable) {
		ppattr_clear_reusable(pai);
	} else if ((options & PMAP_OPTIONS_SET_REUSABLE) && !is_reusable) {
		ppattr_set_reusable(pai);
	}

	if (mod_fault) {
		ppattr_set_modfault(pai);
	}
	if (ref_fault) {
		ppattr_set_reffault(pai);
	}
	if (__probable(mustsynch)) {
		pvh_unlock(pai);
	}
	return result;
}

MARK_AS_PMAP_TEXT boolean_t
arm_force_fast_fault_internal(
	ppnum_t         ppnum,
	vm_prot_t       allow_mode,
	int             options)
{
	if (__improbable((options & (PMAP_OPTIONS_FF_LOCKED | PMAP_OPTIONS_NOFLUSH)) != 0)) {
		panic("arm_force_fast_fault(0x%x, 0x%x, 0x%x): invalid options", ppnum, allow_mode, options);
	}
	return arm_force_fast_fault_with_flush_range(ppnum, allow_mode, options, NULL);
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

#if XNU_MONITOR
	return arm_force_fast_fault_ppl(ppnum, allow_mode, options);
#else
	return arm_force_fast_fault_internal(ppnum, allow_mode, options);
#endif
}

/*
 *	Routine:	arm_clear_fast_fault
 *
 *	Function:
 *		Clear pending force fault for all mappings for this page based on
 *		the observed fault type, update ref/modify bits.
 */
MARK_AS_PMAP_TEXT static boolean_t
arm_clear_fast_fault(
	ppnum_t ppnum,
	vm_prot_t fault_type,
	pt_entry_t *pte_p)
{
	pmap_paddr_t    pa = ptoa(ppnum);
	pv_entry_t     *pve_p;
	unsigned int    pai;
	boolean_t       result;
	bool            tlb_flush_needed = false;
	pv_entry_t    **pv_h;
	unsigned int    npve = 0;
	unsigned int    pass1_updated = 0;
	unsigned int    pass2_updated = 0;

	assert(ppnum != vm_page_fictitious_addr);

	if (!pa_valid(pa)) {
		return FALSE;   /* Not a managed page. */
	}

	result = FALSE;
	pai = pa_index(pa);
	pvh_assert_locked(pai);
	pv_h = pai_to_pvh(pai);

	pve_p = PV_ENTRY_NULL;
	if (pte_p == PT_ENTRY_NULL) {
		if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
			pte_p = pvh_ptep(pv_h);
		} else if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
			pve_p = pvh_pve_list(pv_h);
		} else if (__improbable(!pvh_test_type(pv_h, PVH_TYPE_NULL))) {
			panic("%s: invalid PV head 0x%llx for PA 0x%llx", __func__, (uint64_t)(*pv_h), (uint64_t)pa);
		}
	}

	pv_entry_t *orig_pve_p = pve_p;
	pt_entry_t *orig_pte_p = pte_p;
	int pve_ptep_idx = 0;

	/*
	 * Pass 1: Make any necessary PTE updates, marking PTEs that will require
	 * TLB invalidation in pass 2.
	 */
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		pt_entry_t spte;
		pt_entry_t tmplate;

		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto cff_skip_pve_pass1;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto cff_skip_pve_pass1;
		}
#endif
		if (*pte_p == ARM_PTE_EMPTY) {
			panic("pte is empty: pte_p=%p ppnum=0x%x", pte_p, ppnum);
		}

		const pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		__assert_only const vm_map_address_t va = ptd_get_va(ptdp, pte_p);

		assert(va >= pmap->min && va < pmap->max);

		spte = *pte_p;
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
			ppattr_pa_set_bits(pa, PP_ATTR_REFERENCED | PP_ATTR_MODIFIED);
		} else if ((fault_type & VM_PROT_READ) && ((spte & ARM_PTE_AF) != ARM_PTE_AF)) {
			tmplate = spte | ARM_PTE_AF;

			{
				ppattr_pa_set_bits(pa, PP_ATTR_REFERENCED);
			}
		}

#if MACH_ASSERT && XNU_MONITOR
		if (is_pte_xprr_protected(pmap, spte)) {
			if (pte_to_xprr_perm(spte) != pte_to_xprr_perm(tmplate)) {
				panic("%s: attempted to mutate an xPRR mapping pte_p=%p, pmap=%p, pv_h=%p, pve_p=%p, pte=0x%llx, tmplate=0x%llx, va=0x%llx, "
				    "ppnum=0x%x, fault_type=0x%x",
				    __FUNCTION__, pte_p, pmap, pv_h, pve_p, (unsigned long long)spte, (unsigned long long)tmplate, (unsigned long long)va,
				    ppnum, fault_type);
			}
		}
#endif /* MACH_ASSERT && XNU_MONITOR */

		assert(spte != ARM_PTE_TYPE_FAULT);
		if (spte != tmplate) {
			if ((spte & (~ARM_PTE_WRITEABLE)) != (tmplate & (~ARM_PTE_WRITEABLE))) {
#ifdef ARM_PTE_FF_MARKER
				assert(!(spte & ARM_PTE_FF_MARKER));
				tmplate |= ARM_PTE_FF_MARKER;
				++pass1_updated;
#endif
				tlb_flush_needed = true;
			}
			write_pte_fast(pte_p, tmplate);
			result = TRUE;
		}

cff_skip_pve_pass1:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
			++npve;
			if (__improbable(npve == PMAP_MAX_PV_LIST_CHUNK_SIZE)) {
				break;
			}
		}
	}

	if (!tlb_flush_needed) {
		goto cff_finish;
	}

	FLUSH_PTE_STRONG();

	/* Pass 2: Issue any required TLB invalidations */
	pve_p = orig_pve_p;
	pte_p = orig_pte_p;
	pve_ptep_idx = 0;
	npve = 0;

	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto cff_skip_pve_pass2;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto cff_skip_pve_pass2;
		}
#endif

#ifdef ARM_PTE_FF_MARKER
		pt_entry_t spte = *pte_p;

		if (!(spte & ARM_PTE_FF_MARKER)) {
			goto cff_skip_pve_pass2;
		} else {
			spte &= (~ARM_PTE_FF_MARKER);
			/* No need to synchronize with the TLB flush; we're changing a SW-managed bit */
			write_pte_fast(pte_p, spte);
			++pass2_updated;
		}
#endif
		const pt_desc_t * const ptdp = ptep_get_ptd(pte_p);
		const pmap_t pmap = ptdp->pmap;
		const vm_map_address_t va = ptd_get_va(ptdp, pte_p);

		pmap_get_pt_ops(pmap)->flush_tlb_region_async(va, pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO, pmap, true);

cff_skip_pve_pass2:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
			++npve;
			if (__improbable(npve == PMAP_MAX_PV_LIST_CHUNK_SIZE)) {
				break;
			}
		}
	}

cff_finish:
	if (__improbable(pass1_updated != pass2_updated)) {
		panic("%s: first pass (%u) and second pass (%u) disagree on updated mappings",
		    __func__, pass1_updated, pass2_updated);
	}
	if (tlb_flush_needed) {
		sync_tlb_flush();
	}
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
 *
 * Returns KERN_ABORTED if the pmap lock is taken and a
 * preemption is pending.
 *
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
	unsigned int    pai;
	pmap_paddr_t    pa;
	validate_pmap_mutable(pmap);

	if (!pmap_lock_preempt(pmap, PMAP_LOCK_SHARED)) {
		return KERN_ABORTED;
	}

	/*
	 * If the entry doesn't exist, is completely invalid, or is already
	 * valid, we can't fix it here.
	 */

	const uint64_t pmap_page_size = pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO;
	ptep = pmap_pte(pmap, va & ~(pmap_page_size - 1));
	if (ptep != PT_ENTRY_NULL) {
		while (true) {
			spte = *((volatile pt_entry_t*)ptep);

			pa = pte_to_pa(spte);

			if ((spte == ARM_PTE_TYPE_FAULT) ||
			    ARM_PTE_IS_COMPRESSED(spte, ptep)) {
				pmap_unlock(pmap, PMAP_LOCK_SHARED);
				return result;
			}

			if (!pa_valid(pa)) {
				pmap_unlock(pmap, PMAP_LOCK_SHARED);
#if XNU_MONITOR
				if (pmap_cache_attributes((ppnum_t)atop(pa)) & PP_ATTR_MONITOR) {
					return KERN_PROTECTION_FAILURE;
				} else
#endif
				return result;
			}
			pai = pa_index(pa);
			pvh_lock(pai);
			if (*ptep == spte) {
				/*
				 * Double-check the spte value, as we care about the AF bit.
				 * It's also possible that pmap_page_protect() transitioned the
				 * PTE to compressed/empty before we grabbed the PVH lock.
				 */
				break;
			}
			pvh_unlock(pai);
		}
	} else {
		pmap_unlock(pmap, PMAP_LOCK_SHARED);
		return result;
	}


	if ((result != KERN_SUCCESS) &&
	    ((ppattr_test_reffault(pai)) || ((fault_type & VM_PROT_WRITE) && ppattr_test_modfault(pai)))) {
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
		if (ppattr_test_reffault(pai)) {
			ppattr_clear_reffault(pai);
		}
		if ((fault_type & VM_PROT_WRITE) && ppattr_test_modfault(pai)) {
			ppattr_clear_modfault(pai);
		}

		if (arm_clear_fast_fault((ppnum_t)atop(pa), fault_type, PT_ENTRY_NULL)) {
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

	if ((result == KERN_FAILURE) && arm_clear_fast_fault((ppnum_t)atop(pa), fault_type, ptep)) {
		/*
		 * A prior arm_clear_fast_fault() operation may have returned early due to
		 * another pending PV list operation or an excessively large PV list.
		 * Attempt a targeted fixup of the PTE that caused the fault to avoid repeatedly
		 * taking a fault on the same mapping.
		 */
		result = KERN_SUCCESS;
	}

	pvh_unlock(pai);
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

	do {
#if XNU_MONITOR
		result = arm_fast_fault_ppl(pmap, va, fault_type, was_af_fault, from_user);
#else
		result = arm_fast_fault_internal(pmap, va, fault_type, was_af_fault, from_user);
#endif
	} while (result == KERN_ABORTED);

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
	pt_entry_t      *ptep, pte;

	ptep = pmap_pte(kernel_pmap, LOWGLOBAL_ALIAS);
	assert(ptep != PT_ENTRY_NULL);
	assert(*ptep == ARM_PTE_EMPTY);

	pte = pa_to_pte(ml_static_vtop((vm_offset_t)&lowGlo)) | AP_RONA | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_AF | ARM_PTE_TYPE;
#if __ARM_KERNEL_PROTECT__
	pte |= ARM_PTE_NG;
#endif /* __ARM_KERNEL_PROTECT__ */
	pte |= ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK);
	pte |= ARM_PTE_SH(SH_OUTER_MEMORY);
	*ptep = pte;
	FLUSH_PTE();
	PMAP_UPDATE_TLBS(kernel_pmap, LOWGLOBAL_ALIAS, LOWGLOBAL_ALIAS + PAGE_SIZE, false, true);

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
	unsigned int    i;
	vm_offset_t     cpu_copywindow_vaddr = 0;
	bool            need_strong_sync = false;

#if XNU_MONITOR
	unsigned int    cacheattr = (!pa_valid(ptoa(pn) & ARM_PTE_PAGE_MASK) ? pmap_cache_attributes(pn) : 0);
	need_strong_sync = ((cacheattr & PMAP_IO_RANGE_STRONG_SYNC) != 0);
#endif

#if XNU_MONITOR
#ifdef  __ARM_COHERENT_IO__
	if (__improbable(pa_valid(ptoa(pn) & ARM_PTE_PAGE_MASK) && !pmap_ppl_disable)) {
		panic("%s: attempted to map a managed page, "
		    "pn=%u, prot=0x%x, wimg_bits=0x%x",
		    __FUNCTION__,
		    pn, prot, wimg_bits);
	}
	if (__improbable((cacheattr & PP_ATTR_MONITOR) && (prot != VM_PROT_READ) && !pmap_ppl_disable)) {
		panic("%s: attempt to map PPL-protected I/O address 0x%llx as writable", __func__, (uint64_t)ptoa(pn));
	}

#else /* __ARM_COHERENT_IO__ */
#error CPU copy windows are not properly supported with both the PPL and incoherent IO
#endif /* __ARM_COHERENT_IO__ */
#endif /* XNU_MONITOR */
	cpu_num = pmap_cpu_data->cpu_number;

	for (i = 0; i < CPUWINDOWS_MAX; i++) {
		cpu_copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_num, i);
		ptep = pmap_pte(kernel_pmap, cpu_copywindow_vaddr);
		assert(!ARM_PTE_IS_COMPRESSED(*ptep, ptep));
		if (*ptep == ARM_PTE_TYPE_FAULT) {
			break;
		}
	}
	if (i == CPUWINDOWS_MAX) {
		panic("pmap_map_cpu_windows_copy: out of window");
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

	write_pte_fast(ptep, pte);
	/*
	 * Invalidate tlb. Cover nested cpu_copywindow_vaddr usage with the interrupted context
	 * in pmap_unmap_cpu_windows_copy() after clearing the pte and before tlb invalidate.
	 */
	FLUSH_PTE_STRONG();
	PMAP_UPDATE_TLBS(kernel_pmap, cpu_copywindow_vaddr, cpu_copywindow_vaddr + PAGE_SIZE, pmap_cpu_data->copywindow_strong_sync[i], true);
	pmap_cpu_data->copywindow_strong_sync[i] = need_strong_sync;

	return i;
}

unsigned int
pmap_map_cpu_windows_copy(
	ppnum_t pn,
	vm_prot_t prot,
	unsigned int wimg_bits)
{
#if XNU_MONITOR
	return pmap_map_cpu_windows_copy_ppl(pn, prot, wimg_bits);
#else
	return pmap_map_cpu_windows_copy_internal(pn, prot, wimg_bits);
#endif
}

MARK_AS_PMAP_TEXT void
pmap_unmap_cpu_windows_copy_internal(
	unsigned int index)
{
	pt_entry_t      *ptep;
	unsigned int    cpu_num;
	vm_offset_t     cpu_copywindow_vaddr = 0;
	pmap_cpu_data_t *pmap_cpu_data = pmap_get_cpu_data();

	cpu_num = pmap_cpu_data->cpu_number;

	cpu_copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_num, index);
	/* Issue full-system DSB to ensure prior operations on the per-CPU window
	 * (which are likely to have been on I/O memory) are complete before
	 * tearing down the mapping. */
	__builtin_arm_dsb(DSB_SY);
	ptep = pmap_pte(kernel_pmap, cpu_copywindow_vaddr);
	write_pte_strong(ptep, ARM_PTE_TYPE_FAULT);
	PMAP_UPDATE_TLBS(kernel_pmap, cpu_copywindow_vaddr, cpu_copywindow_vaddr + PAGE_SIZE, pmap_cpu_data->copywindow_strong_sync[index], true);
}

void
pmap_unmap_cpu_windows_copy(
	unsigned int index)
{
#if XNU_MONITOR
	return pmap_unmap_cpu_windows_copy_ppl(index);
#else
	return pmap_unmap_cpu_windows_copy_internal(index);
#endif
}

#if XNU_MONITOR

MARK_AS_PMAP_TEXT void
pmap_invoke_with_page(
	ppnum_t page_number,
	void *ctx,
	void (*callback)(void *ctx, ppnum_t page_number, const void *page))
{
	#pragma unused(page_number, ctx, callback)
}

/*
 * Loop over every pmap_io_range (I/O ranges marked as owned by
 * the PPL in the device tree) and conditionally call callback() on each range
 * that needs to be included in the hibernation image.
 *
 * @param ctx      Will be passed as-is into the callback method. Use NULL if no
 *                 context is needed in the callback.
 * @param callback Callback function invoked on each range (gated by flag).
 */
MARK_AS_PMAP_TEXT void
pmap_hibernate_invoke(void *ctx, void (*callback)(void *ctx, uint64_t addr, uint64_t len))
{
	extern const pmap_io_range_t* io_attr_table;
	extern const unsigned int num_io_rgns;
	for (unsigned int i = 0; i < num_io_rgns; ++i) {
		if (io_attr_table[i].wimg & PMAP_IO_RANGE_NEEDS_HIBERNATING) {
			callback(ctx, io_attr_table[i].addr, io_attr_table[i].len);
		}
	}
}

/**
 * Set the HASHED pv_head_table flag for the passed in physical page if it's a
 * PPL-owned page. Otherwise, do nothing.
 *
 * @param addr Physical address of the page to set the HASHED flag on.
 */
MARK_AS_PMAP_TEXT void
pmap_set_ppl_hashed_flag(const pmap_paddr_t addr)
{
	/* Ignore non-managed kernel memory. */
	if (!pa_valid(addr)) {
		return;
	}

	const unsigned int pai = pa_index(addr);
	if (pp_attr_table[pai] & PP_ATTR_MONITOR) {
		pv_entry_t **pv_h = pai_to_pvh(pai);

		/* Mark that the PPL-owned page has been hashed into the hibernation image. */
		pvh_lock(pai);
		pvh_set_flags(pv_h, pvh_get_flags(pv_h) | PVH_FLAG_HASHED);
		pvh_unlock(pai);
	}
}

/**
 * Loop through every physical page in the system and clear out the HASHED flag
 * on every PPL-owned page. That flag is used to keep track of which pages have
 * been hashed into the hibernation image during the hibernation entry process.
 *
 * The HASHED flag needs to be cleared out between hibernation cycles because the
 * pv_head_table and pp_attr_table's might have been copied into the hibernation
 * image with the HASHED flag set on certain pages. It's important to clear the
 * HASHED flag to ensure that the enforcement of all PPL-owned memory being hashed
 * into the hibernation image can't be compromised across hibernation cycles.
 */
MARK_AS_PMAP_TEXT void
pmap_clear_ppl_hashed_flag_all(void)
{
	const unsigned int last_index = pa_index(vm_last_phys);
	pv_entry_t **pv_h = NULL;

	for (int pai = 0; pai < last_index; ++pai) {
		pv_h = pai_to_pvh(pai);

		/* Test for PPL-owned pages that have the HASHED flag set in its pv_head_table entry. */
		if ((pvh_get_flags(pv_h) & PVH_FLAG_HASHED) &&
		    (pp_attr_table[pai] & PP_ATTR_MONITOR)) {
			pvh_lock(pai);
			pvh_set_flags(pv_h, pvh_get_flags(pv_h) & ~PVH_FLAG_HASHED);
			pvh_unlock(pai);
		}
	}
}

/**
 * Enforce that all PPL-owned pages were hashed into the hibernation image. The
 * ppl_hib driver will call this after all wired pages have been copied into the
 * hibernation image.
 */
MARK_AS_PMAP_TEXT void
pmap_check_ppl_hashed_flag_all(void)
{
	const unsigned int last_index = pa_index(vm_last_phys);
	pv_entry_t **pv_h = NULL;

	for (int pai = 0; pai < last_index; ++pai) {
		pv_h = pai_to_pvh(pai);

		/**
		 * The PMAP stacks are explicitly not saved into the image so skip checking
		 * the pages that contain the PMAP stacks.
		 */
		const bool is_pmap_stack = (pai >= pa_index(pmap_stacks_start_pa)) &&
		    (pai < pa_index(pmap_stacks_end_pa));

		if (!is_pmap_stack &&
		    (pp_attr_table[pai] & PP_ATTR_MONITOR) &&
		    !(pvh_get_flags(pv_h) & PVH_FLAG_HASHED)) {
			panic("Found PPL-owned page that was not hashed into the hibernation image: pai %d", pai);
		}
	}
}

#endif /* XNU_MONITOR */

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
	if (__improbable(pmap->type != PMAP_TYPE_USER)) {
		panic("%s: attempt to nest unsupported pmap %p of type 0x%hhx",
		    __func__, pmap, pmap->type);
	}
	pmap->type = PMAP_TYPE_NESTED;
	pmap_get_pt_ops(pmap)->free_id(pmap);
}

void
pmap_set_nested(
	pmap_t pmap)
{
#if XNU_MONITOR
	pmap_set_nested_ppl(pmap);
#else
	pmap_set_nested_internal(pmap);
#endif
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
	pt_entry_t * pte_p;
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
			pte_p = (pt_entry_t *) ttetokv(*tte_p);

			/* pmap_tte_deallocate()/pmap_tte_remove() will drop the pmap lock */
			if ((pmap->type == PMAP_TYPE_NESTED) && (ptep_get_info(pte_p)->refcnt == 0)) {
				/* Deallocate for the nested map. */
				pmap_tte_deallocate(pmap, cur, cur + PAGE_SIZE, false, tte_p, pt_attr_twig_level(pt_attr));
			} else if (pmap->type == PMAP_TYPE_USER) {
				/**
				 * Just remove for the parent map. If the leaf table pointed
				 * to by the TTE being removed (owned by the nested pmap)
				 * has any mappings, then this call will panic. This
				 * enforces the policy that tables being trimmed must be
				 * empty to prevent possible use-after-free attacks.
				 */
				pmap_tte_remove(pmap, cur, cur + PAGE_SIZE, false, tte_p, pt_attr_twig_level(pt_attr));
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

	for (cur = adjusted_start; (cur < adjusted_end) && (cur >= adjusted_start); cur += pt_attr_ln_size(pt_attr, PMAP_TT_L1_LEVEL)) {
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
			pmap_tte_deallocate(pmap, cur, cur + PAGE_SIZE, false, tt1e_p, PMAP_TT_L1_LEVEL);
		} else {
			pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
		}
	}
}

/**
 * State machine for multi-step pmap trimming. Trimming is the action of
 * deallocating the TTEs of the shared region of pmaps down to a given range.
 * On PPL-enabled systems, this needs to be done in multiple steps to avoid
 * disabling preemption for too long. These steps include computing the bounds
 * of the shared region, trimming the head of the "grand", trimming the tail of
 * the "grand", and trimming the "subord". Some of the steps can be skipped under
 * different conditions.
 *
 * @param grand the pmap in which the pages are nested
 * @param subord the pmap from which the pages are shared, or nested
 * @param vstart start of the used range in "grand"
 * @param size size of the used range
 * @param state the current state of the state machine
 *
 * @return the next state of the state machine, to be used in the next call
 *         into this function.
 */
MARK_AS_PMAP_TEXT pmap_trim_state_t
pmap_trim_internal(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size,
	pmap_trim_state_t state)
{
	/* Validation needs to be done regardless of state. */
	addr64_t vend;

	if (__improbable(os_add_overflow(vstart, size, &vend))) {
		panic("%s: grand addr wraps around, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, grand, subord, (void*)vstart, size, state);
	}

	validate_pmap_mutable(grand);
	validate_pmap(subord);

	if (__improbable(subord->type != PMAP_TYPE_NESTED)) {
		panic("%s: subord is of non-nestable type 0x%hhx, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, subord->type, grand, subord, (void*)vstart, size, state);
	}

	if (__improbable(grand->type != PMAP_TYPE_USER)) {
		panic("%s: grand is of unsupprted type 0x%hhx for nesting, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, grand->type, grand, subord, (void*)vstart, size, state);
	}

	if (__improbable(grand->nested_pmap != subord)) {
		panic("%s: grand->nested != subord, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, grand, subord, (void*)vstart, size, state);
	}

	if (__improbable((size != 0) &&
	    ((vstart < grand->nested_region_addr) || (vend > (grand->nested_region_addr + grand->nested_region_size))))) {
		panic("%s: grand range not in nested region, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, grand, subord, (void*)vstart, size, state);
	}

	/* Trimming starts with figuring out the bounds for the grand. */
	if (state == PMAP_TRIM_STATE_START) {
		pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);

		/**
		 * The "nested_has_no_bounds_ref" flag is set by `pmap_nest()` if the subord is nested into
		 * the grand when the bounds are not known yet. Therefore, if it is not set, either any nesting
		 * has not happened, or trimming has been done, or nesting has been done with bounds known so
		 * the "extra" region was not nested in the first place. Anyway, trimming is not needed so
		 * we exit early with PMAP_TRIM_STATE_DONE.
		 */
		if (!grand->nested_has_no_bounds_ref) {
			assert(subord->nested_bounds_set);

			/* Nothing to do if the grand already has bounds set, otherwise inherit from the subord. */
			if (!grand->nested_bounds_set) {
				/* Inherit the bounds from subord. */
				grand->nested_region_true_start = subord->nested_region_true_start;
				grand->nested_region_true_end = subord->nested_region_true_end;
				grand->nested_bounds_set = true;
			}

			pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);

			/* Now that the grand has bounds, we are done. */
			return PMAP_TRIM_STATE_DONE;
		}

		/* If the subord doesn't have bounds set yet, compute them from vstart and a non-zero size. */
		if ((!subord->nested_bounds_set) && size) {
			const pt_attr_t * const pt_attr = pmap_get_pt_attr(grand);
			const addr64_t adjust_offmask = pt_attr_leaf_table_offmask(pt_attr);

			subord->nested_region_true_start = vstart;
			subord->nested_region_true_end = vend;
			subord->nested_region_true_start &= ~adjust_offmask;

			if (__improbable(os_add_overflow(subord->nested_region_true_end, adjust_offmask, &subord->nested_region_true_end))) {
				panic("%s: padded true end wraps around, "
				    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
				    __func__, grand, subord, (void*)vstart, size, state);
			}

			subord->nested_region_true_end &= ~adjust_offmask;
			subord->nested_bounds_set = true;
		}

		/* If the subord has bounds set now, let the grand inherit and continue to trim. Otherwise, we are done. */
		if (subord->nested_bounds_set) {
			/* Inherit the bounds from subord. */
			grand->nested_region_true_start = subord->nested_region_true_start;
			grand->nested_region_true_end = subord->nested_region_true_end;
			grand->nested_bounds_set = true;

			/* If we know the bounds, we can trim the pmap. */
			grand->nested_has_no_bounds_ref = false;
			pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);

			state = PMAP_TRIM_STATE_GRAND_BEFORE;
		} else {
			/* Don't trim if we don't know the bounds. */
			pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);

			return PMAP_TRIM_STATE_DONE;
		}
	}

	/* Sanity check here: we are ready to trim, do we know the bounds yet? */
	if (!grand->nested_bounds_set) {
		panic("%s: !grand->nested_bounds_set, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, grand, subord, (void*)vstart, size, state);
	}

	if (state == PMAP_TRIM_STATE_GRAND_BEFORE) {
		pmap_trim_range(grand, grand->nested_region_addr, grand->nested_region_true_start);

#if XNU_MONITOR
		if (pmap_pending_preemption()) {
			return PMAP_TRIM_STATE_GRAND_AFTER;
		}
#endif

		state = PMAP_TRIM_STATE_GRAND_AFTER;
	}

	if (state == PMAP_TRIM_STATE_GRAND_AFTER) {
		pmap_trim_range(grand, grand->nested_region_true_end, (grand->nested_region_addr + grand->nested_region_size));

#if XNU_MONITOR
		if (pmap_pending_preemption()) {
			return PMAP_TRIM_STATE_SUBORD;
		}
#endif

		state = PMAP_TRIM_STATE_SUBORD;
	}

	/* START state is guaranteed to compute the bounds for the subord. */
	if (!subord->nested_bounds_set) {
		panic("%s: !subord->nested_bounds_set, "
		    "grand=%p, subord=%p, vstart=%p, size=%#llx, state=%u",
		    __func__, grand, subord, (void*)vstart, size, state);
	}

	if (state == PMAP_TRIM_STATE_SUBORD) {
		pmap_trim_subord(subord);
	}

	return PMAP_TRIM_STATE_DONE;
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

/**
 * Deallocates the TTEs of the shared region of pmaps down to a given range.
 * On PPL-enabled systems, this needs to be done in multiple steps to avoid
 * disabling preemption for too long.
 *
 * @note When we load the shared region we always create pages tables for the
 *       entire region. In practice, the shared cache may use just a portion
 *       of that. Before we know the bounds of the shared region, it can
 *       already be mapped into processes. Therefore, once the bounds are
 *       known, "trimming" comes in handy to remove the unnecessary page
 *       tables in the processes the shared region is mapped in, and eventually
 *       those in the shared region itself. Note that the shared region must
 *       be trimmed after the user processes because it has the L3 entries
 *       everyone else is pointing to.
 *
 * @param grand the pmap in which the pages are nested
 * @param subord the pmap from which the pages are shared, or nested
 * @param vstart start of the used range in "grand"
 * @param size size of the used range
 */
void
pmap_trim(
	pmap_t grand,
	pmap_t subord,
	addr64_t vstart,
	uint64_t size)
{
	pmap_trim_state_t state = PMAP_TRIM_STATE_START;

#if XNU_MONITOR
	/* On PPL systems, drives the state machine until its done. */
	while (state != PMAP_TRIM_STATE_DONE) {
		__assert_only pmap_trim_state_t old_state = state;
		state = pmap_trim_ppl(grand, subord, vstart, size, state);

		/* Are we making progress? */
		assert(old_state != state);
	}

	pmap_ledger_check_balance(grand);
	pmap_ledger_check_balance(subord);
#else
	state = pmap_trim_internal(grand, subord, vstart, size, state);

	/* On non-PPL systems, we expect the implementation to finish in one call. */
	assert(state == PMAP_TRIM_STATE_DONE);
#endif
}

#if HAS_APPLE_PAC
void *
pmap_sign_user_ptr_internal(void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key)
{
	void *res = NULL;
	uint64_t current_intr_state = pmap_interrupts_disable();

	uint64_t saved_jop_state = ml_enable_user_jop_key(jop_key);
	switch (key) {
	case ptrauth_key_asia:
		res = ptrauth_sign_unauthenticated(value, ptrauth_key_asia, discriminator);
		break;
	case ptrauth_key_asda:
		res = ptrauth_sign_unauthenticated(value, ptrauth_key_asda, discriminator);
		break;
	default:
		panic("attempt to sign user pointer without process independent key");
	}
	ml_disable_user_jop_key(jop_key, saved_jop_state);

	pmap_interrupts_restore(current_intr_state);

	return res;
}

void *
pmap_sign_user_ptr(void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key)
{
	return pmap_sign_user_ptr_internal(value, key, discriminator, jop_key);
}

void *
pmap_auth_user_ptr_internal(void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key)
{
	if ((key != ptrauth_key_asia) && (key != ptrauth_key_asda)) {
		panic("attempt to auth user pointer without process independent key");
	}

	void *res = NULL;
	uint64_t current_intr_state = pmap_interrupts_disable();

	uint64_t saved_jop_state = ml_enable_user_jop_key(jop_key);
	res = ml_auth_ptr_unchecked(value, key, discriminator);
	ml_disable_user_jop_key(jop_key, saved_jop_state);

	pmap_interrupts_restore(current_intr_state);

	return res;
}

void *
pmap_auth_user_ptr(void *value, ptrauth_key key, uint64_t discriminator, uint64_t jop_key)
{
	return pmap_auth_user_ptr_internal(value, key, discriminator, jop_key);
}
#endif /* HAS_APPLE_PAC */

/*
 * Marker to indicate that a pmap_[un]nest() operation has finished operating on
 * the 'subordinate' pmap and has begun operating on the 'grand' pmap.  This
 * flag is supplied in the low-order bit of the 'vrestart' param as well as the
 * return value, to indicate where a preempted [un]nest operation should resume.
 * When the return value contains the ending address of the nested region with
 * PMAP_NEST_GRAND in the low-order bit, the operation has completed.
 */
#define PMAP_NEST_GRAND ((vm_map_offset_t) 0x1)

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
 * 3. Copying of twig-level TTEs from subord to grand, such that grand ultimately
 *    contains pointers to subord's leaf-level pagetable pages for the specified
 *    VA range.
 *
 * This function may return early due to pending AST_URGENT preemption; if so
 * it will indicate the need to be re-entered.
 *
 * @param grand pmap to insert the TTEs into.  Must be a user pmap.
 * @param subord pmap from which to extract the TTEs.  Must be a nested pmap.
 * @param vstart twig-aligned virtual address for the beginning of the nesting range
 * @param size twig-aligned size of the nesting range
 * @param vrestart the twig-aligned starting address of the current call.  May contain
 *        PMAP_NEST_GRAND in bit 0 to indicate the operation should skip to step 3) above.
 * @param krp Should be initialized to KERN_SUCCESS by caller, will be set to
 *        KERN_RESOURCE_SHORTAGE on allocation failure.
 *
 * @return the virtual address at which to restart the operation, possibly including
 *         PMAP_NEST_GRAND to indicate the phase at which to restart.  If
 *         (vstart + size) | PMAP_NEST_GRAND is returned, the operation completed.
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
	unsigned int    nested_region_asid_bitmap_size;
	unsigned int*   nested_region_asid_bitmap;
	int             expand_options = 0;
	bool            deref_subord = true;

	addr64_t vend;
	if (__improbable(os_add_overflow(vstart, size, &vend))) {
		panic("%s: %p grand addr wraps around: 0x%llx + 0x%llx", __func__, grand, vstart, size);
	}
	if (__improbable(((vrestart & ~PMAP_NEST_GRAND) > vend) ||
	    ((vrestart & ~PMAP_NEST_GRAND) < vstart))) {
		panic("%s: vrestart 0x%llx is outside range [0x%llx, 0x%llx)", __func__,
		    (unsigned long long)vrestart, (unsigned long long)vstart, (unsigned long long)vend);
	}

	assert(krp != NULL);
	validate_pmap_mutable(grand);
	validate_pmap(subord);
#if XNU_MONITOR
	/*
	 * Ordering is important here.  validate_pmap() has already ensured subord is a
	 * PPL-controlled pmap pointer, but it could have already been destroyed or could
	 * be in the process of being destroyed.  If destruction is already committed,
	 * then the check of ref_count below will cover us.  If destruction is initiated
	 * during or after this call, then pmap_destroy() will catch the non-zero
	 * nested_count.
	 */
	os_atomic_inc(&subord->nested_count, relaxed);
	os_atomic_thread_fence(seq_cst);
#endif
	if (__improbable(os_atomic_inc_orig(&subord->ref_count, relaxed) <= 0)) {
		panic("%s: invalid subordinate pmap %p", __func__, subord);
	}

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(grand);
	if (__improbable(pmap_get_pt_attr(subord) != pt_attr)) {
		panic("%s: attempt to nest pmap %p into pmap %p with mismatched attributes", __func__, subord, grand);
	}

#if XNU_MONITOR
	expand_options |= PMAP_TT_ALLOCATE_NOWAIT;
#endif

	if (__improbable(((size | vstart | (vrestart & ~PMAP_NEST_GRAND)) &
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

	if (subord->nested_region_asid_bitmap == NULL) {
		nested_region_asid_bitmap_size  = (unsigned int)(size >> pt_attr_twig_shift(pt_attr)) / (sizeof(unsigned int) * NBBY);

#if XNU_MONITOR
		pmap_paddr_t pa = 0;

		if (__improbable((nested_region_asid_bitmap_size * sizeof(unsigned int)) > PAGE_SIZE)) {
			panic("%s: nested_region_asid_bitmap_size=%u will not fit in a page, "
			    "grand=%p, subord=%p, vstart=0x%llx, size=%llx",
			    __FUNCTION__, nested_region_asid_bitmap_size,
			    grand, subord, vstart, size);
		}

		kr = pmap_pages_alloc_zeroed(&pa, PAGE_SIZE, PMAP_PAGES_ALLOCATE_NOWAIT);

		if (kr != KERN_SUCCESS) {
			goto nest_cleanup;
		}

		assert(pa);

		nested_region_asid_bitmap = (unsigned int *)phystokv(pa);
#else
		nested_region_asid_bitmap = kalloc_data(
			nested_region_asid_bitmap_size * sizeof(unsigned int),
			Z_WAITOK | Z_ZERO);
#endif

		pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);
		if (subord->nested_region_asid_bitmap == NULL) {
			subord->nested_region_asid_bitmap_size = nested_region_asid_bitmap_size;
			subord->nested_region_addr = vstart;
			subord->nested_region_size = (mach_vm_offset_t) size;

			/**
			 * Ensure that the rest of the subord->nested_region_* fields are
			 * initialized and visible before setting the nested_region_asid_bitmap
			 * field (which is used as the flag to say that the rest are initialized).
			 */
			__builtin_arm_dmb(DMB_ISHST);
			subord->nested_region_asid_bitmap = nested_region_asid_bitmap;
			nested_region_asid_bitmap = NULL;
		}
		pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
		if (nested_region_asid_bitmap != NULL) {
#if XNU_MONITOR
			pmap_pages_free(kvtophys_nofail((vm_offset_t)nested_region_asid_bitmap), PAGE_SIZE);
#else
			kfree_data(nested_region_asid_bitmap,
			    nested_region_asid_bitmap_size * sizeof(unsigned int));
#endif
		}
	}

	/**
	 * Ensure subsequent reads of the subord->nested_region_* fields don't get
	 * speculated before their initialization.
	 */
	__builtin_arm_dmb(DMB_ISHLD);

	if ((subord->nested_region_addr + subord->nested_region_size) < vend) {
		uint64_t        new_size;
		unsigned int    new_nested_region_asid_bitmap_size;
		unsigned int*   new_nested_region_asid_bitmap;

		nested_region_asid_bitmap = NULL;
		nested_region_asid_bitmap_size = 0;
		new_size =  vend - subord->nested_region_addr;

		/* We explicitly add 1 to the bitmap allocation size in order to avoid issues with truncation. */
		new_nested_region_asid_bitmap_size  = (unsigned int)((new_size >> pt_attr_twig_shift(pt_attr)) / (sizeof(unsigned int) * NBBY)) + 1;

#if XNU_MONITOR
		pmap_paddr_t pa = 0;

		if (__improbable((new_nested_region_asid_bitmap_size * sizeof(unsigned int)) > PAGE_SIZE)) {
			panic("%s: new_nested_region_asid_bitmap_size=%u will not fit in a page, "
			    "grand=%p, subord=%p, vstart=0x%llx, new_size=%llx",
			    __FUNCTION__, new_nested_region_asid_bitmap_size,
			    grand, subord, vstart, new_size);
		}

		kr = pmap_pages_alloc_zeroed(&pa, PAGE_SIZE, PMAP_PAGES_ALLOCATE_NOWAIT);

		if (kr != KERN_SUCCESS) {
			goto nest_cleanup;
		}

		assert(pa);

		new_nested_region_asid_bitmap = (unsigned int *)phystokv(pa);
#else
		new_nested_region_asid_bitmap = kalloc_data(
			new_nested_region_asid_bitmap_size * sizeof(unsigned int),
			Z_WAITOK | Z_ZERO);
#endif
		pmap_lock(subord, PMAP_LOCK_EXCLUSIVE);
		if (subord->nested_region_size < new_size) {
			bcopy(subord->nested_region_asid_bitmap,
			    new_nested_region_asid_bitmap, subord->nested_region_asid_bitmap_size);
			nested_region_asid_bitmap_size  = subord->nested_region_asid_bitmap_size;
			nested_region_asid_bitmap = subord->nested_region_asid_bitmap;
			subord->nested_region_asid_bitmap = new_nested_region_asid_bitmap;
			subord->nested_region_asid_bitmap_size = new_nested_region_asid_bitmap_size;
			subord->nested_region_size = new_size;
			new_nested_region_asid_bitmap = NULL;
		}
		pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
		if (nested_region_asid_bitmap != NULL) {
#if XNU_MONITOR
			pmap_pages_free(kvtophys_nofail((vm_offset_t)nested_region_asid_bitmap), PAGE_SIZE);
#else
			kfree_data(nested_region_asid_bitmap,
			    nested_region_asid_bitmap_size * sizeof(unsigned int));
#endif
		}
		if (new_nested_region_asid_bitmap != NULL) {
#if XNU_MONITOR
			pmap_pages_free(kvtophys_nofail((vm_offset_t)new_nested_region_asid_bitmap), PAGE_SIZE);
#else
			kfree_data(new_nested_region_asid_bitmap,
			    new_nested_region_asid_bitmap_size * sizeof(unsigned int));
#endif
		}
	}

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

	vaddr = vrestart & ~PMAP_NEST_GRAND;
	if (vaddr < subord->nested_region_true_start) {
		vaddr = subord->nested_region_true_start;
	}

	addr64_t true_end = vend;
	if (true_end > subord->nested_region_true_end) {
		true_end = subord->nested_region_true_end;
	}
	__unused unsigned int ttecount = 0;

	if (vrestart & PMAP_NEST_GRAND) {
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
		++ttecount;
		if (__improbable(!(ttecount % PMAP_DEFAULT_PREEMPTION_CHECK_PAGE_INTERVAL) &&
		    pmap_pending_preemption())) {
			pmap_unlock(subord, PMAP_LOCK_EXCLUSIVE);
			kr = KERN_SUCCESS;
			pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);
			goto done;
		}
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
	while (vaddr < true_end) {
		stte_p = pmap_tte(subord, vaddr);
		gtte_p = pmap_tte(grand, vaddr);
		if (gtte_p == PT_ENTRY_NULL) {
			pmap_unlock(grand, PMAP_LOCK_EXCLUSIVE);
			kr = pmap_expand(grand, vaddr, expand_options, pt_attr_twig_level(pt_attr));
			pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);

			if (kr != KERN_SUCCESS) {
				goto done;
			}

			gtte_p = pmap_tt2e(grand, vaddr);
		}
		/* Don't leak a page table page.  Don't violate break-before-make. */
		if (__improbable(*gtte_p != ARM_TTE_EMPTY)) {
			panic("%s: attempting to overwrite non-empty TTE %p in pmap %p",
			    __func__, gtte_p, grand);
		}
		*gtte_p = *stte_p;

		vaddr += pt_attr_twig_size(pt_attr);
		vrestart = vaddr | PMAP_NEST_GRAND;
		++ttecount;
		if (__improbable(!(ttecount % PMAP_DEFAULT_PREEMPTION_CHECK_PAGE_INTERVAL) &&
		    pmap_pending_preemption())) {
			break;
		}
	}
	if (vaddr >= true_end) {
		vrestart = vend | PMAP_NEST_GRAND;
	}

	kr = KERN_SUCCESS;
done:

	FLUSH_PTE();
	__builtin_arm_isb(ISB_SY);

	pmap_unlock(grand, PMAP_LOCK_EXCLUSIVE);
#if XNU_MONITOR
nest_cleanup:
	if (kr != KERN_SUCCESS) {
		pmap_pin_kernel_pages((vm_offset_t)krp, sizeof(*krp));
		*krp = kr;
		pmap_unpin_kernel_pages((vm_offset_t)krp, sizeof(*krp));
	}
#else
	if (kr != KERN_SUCCESS) {
		*krp = kr;
	}
#endif
	if (deref_subord) {
#if XNU_MONITOR
		os_atomic_dec(&subord->nested_count, relaxed);
#endif
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
	__unused vm_map_offset_t vlast = vaddr;

	PMAP_TRACE(2, PMAP_CODE(PMAP__NEST) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(subord),
	    VM_KERNEL_ADDRHIDE(vstart));

	pmap_verify_preemptible();
#if XNU_MONITOR
	while (vaddr != (vend | PMAP_NEST_GRAND)) {
		vaddr = pmap_nest_ppl(grand, subord, vstart, size, vaddr, &kr);
		if (kr == KERN_RESOURCE_SHORTAGE) {
			pmap_alloc_page_for_ppl(0);
			kr = KERN_SUCCESS;
		} else if (kr != KERN_SUCCESS) {
			break;
		} else if (vaddr == vlast) {
			panic("%s: failed to make forward progress from 0x%llx to 0x%llx at 0x%llx",
			    __func__, (unsigned long long)vstart, (unsigned long long)vend, (unsigned long long)vaddr);
		}
		vlast = vaddr;
	}

	pmap_ledger_check_balance(grand);
	pmap_ledger_check_balance(subord);
#else
	while ((vaddr != (vend | PMAP_NEST_GRAND)) && (kr == KERN_SUCCESS)) {
		vaddr = pmap_nest_internal(grand, subord, vstart, size, vaddr, &kr);
	}
#endif

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
 * 2. Clearing of the twig-level TTEs for the address range in grand.
 *
 * This function may return early due to pending AST_URGENT preemption; if so
 * it will indicate the need to be re-entered.
 *
 * @param grand pmap from which to unnest mappings
 * @param vaddr twig-aligned virtual address for the beginning of the nested range
 * @param size twig-aligned size of the nested range
 * @param vrestart the page-aligned starting address of the current call.  May contain
 *        PMAP_NEST_GRAND in bit 0 to indicate the operation should skip to step 2) above.
 * @param option Extra control flags; may contain PMAP_UNNEST_CLEAN to indicate that
 *        grand is being torn down and step 1) above is not needed.
 *
 * @return the virtual address at which to restart the operation, possibly including
 *         PMAP_NEST_GRAND to indicate the phase at which to restart.  If
 *         (vaddr + size) | PMAP_NEST_GRAND is returned, the operation completed.
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
	tt_entry_t     *tte_p;
	unsigned int    current_index;
	unsigned int    start_index;
	unsigned int    max_index;
	unsigned int    entry_count = 0;

	addr64_t vend;
	addr64_t true_end;
	if (__improbable(os_add_overflow(vaddr, size, &vend))) {
		panic("%s: %p vaddr wraps around: 0x%llx + 0x%llx", __func__, grand, vaddr, size);
	}
	if (__improbable(((vrestart & ~PMAP_NEST_GRAND) > vend) ||
	    ((vrestart & ~PMAP_NEST_GRAND) < vaddr))) {
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

	if (((option & PMAP_UNNEST_CLEAN) == 0) && !(vrestart & PMAP_NEST_GRAND)) {
		if ((vaddr < grand->nested_region_addr) || (vend > (grand->nested_region_addr + grand->nested_region_size))) {
			panic("%s: %p: unnest request to not-fully-nested region [%p, %p)", __func__, grand, (void*)vaddr, (void*)vend);
		}

		pmap_lock(grand->nested_pmap, PMAP_LOCK_EXCLUSIVE);

		start = vrestart;
		if (start < grand->nested_pmap->nested_region_true_start) {
			start = grand->nested_pmap->nested_region_true_start;
		}
		start_index = (unsigned int)((start - grand->nested_region_addr) >> pt_attr_twig_shift(pt_attr));
		max_index = (unsigned int)((true_end - grand->nested_region_addr) >> pt_attr_twig_shift(pt_attr));
		bool flush_tlb = false;

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
			if (!testbit(current_index, (int *)grand->nested_pmap->nested_region_asid_bitmap) ||
			    (addr & pt_attr_twig_offmask(pt_attr))) {
				/*
				 * Mark the 'twig' region as being unnested.  Every mapping entered within
				 * the nested pmap in this region will now be marked non-global.  Do this
				 * before marking any of the PTEs within the region as non-global to avoid
				 * the possibility of pmap_enter() subsequently inserting a global mapping
				 * in the region, which could lead to a TLB conflict if a non-global entry
				 * is later inserted for the same VA in a pmap which has fully unnested this
				 * region.
				 */
				setbit(current_index, (int *)grand->nested_pmap->nested_region_asid_bitmap);
				for (cpte = bpte; (bpte != NULL) && (addr < vlim); cpte += PAGE_RATIO) {
					pmap_paddr_t    pa;
					unsigned int    pai = 0;
					boolean_t               managed = FALSE;
					pt_entry_t  spte;

					if ((*cpte != ARM_PTE_TYPE_FAULT)
					    && (!ARM_PTE_IS_COMPRESSED(*cpte, cpte))) {
						spte = *((volatile pt_entry_t*)cpte);
						while (!managed) {
							pa = pte_to_pa(spte);
							if (!pa_valid(pa)) {
								break;
							}
							pai = pa_index(pa);
							pvh_lock(pai);
							spte = *((volatile pt_entry_t*)cpte);
							pa = pte_to_pa(spte);
							if (pai == pa_index(pa)) {
								managed = TRUE;
								break; // Leave the PVH locked as we'll unlock it after we update the PTE
							}
							pvh_unlock(pai);
						}

						if (((spte & ARM_PTE_NG) != ARM_PTE_NG)) {
							write_pte_fast(cpte, (spte | ARM_PTE_NG));
							flush_tlb = true;
						}

						if (managed) {
							pvh_assert_locked(pai);
							pvh_unlock(pai);
						}
					}

					addr += (pt_attr_page_size(pt_attr) * PAGE_RATIO);
					vrestart = addr;
					++entry_count;
					if (__improbable(!(entry_count % PMAP_DEFAULT_PREEMPTION_CHECK_PAGE_INTERVAL) &&
					    pmap_pending_preemption())) {
						goto unnest_subord_done;
					}
				}
			}
			addr = vlim;
			vrestart = addr;
			++entry_count;
			if (__improbable(!(entry_count % PMAP_DEFAULT_PREEMPTION_CHECK_PAGE_INTERVAL) &&
			    pmap_pending_preemption())) {
				break;
			}
		}

unnest_subord_done:
		if (flush_tlb) {
			FLUSH_PTE_STRONG();
			PMAP_UPDATE_TLBS(grand->nested_pmap, start, vrestart, false, true);
		}

		pmap_unlock(grand->nested_pmap, PMAP_LOCK_EXCLUSIVE);
		if (current_index < max_index) {
			return vrestart;
		}
	}

	pmap_lock(grand, PMAP_LOCK_EXCLUSIVE);

	/*
	 * invalidate all pdes for segment at vaddr in pmap grand
	 */
	if (vrestart & PMAP_NEST_GRAND) {
		addr = vrestart & ~PMAP_NEST_GRAND;
		if (__improbable(addr & pt_attr_twig_offmask(pt_attr)) != 0x0ULL) {
			panic("%s: unaligned vrestart 0x%llx", __func__, (unsigned long long)addr);
		}
	} else {
		addr = vaddr;
		vrestart = vaddr | PMAP_NEST_GRAND;
	}

	if (addr < grand->nested_pmap->nested_region_true_start) {
		addr = grand->nested_pmap->nested_region_true_start;
	}

	while (addr < true_end) {
		tte_p = pmap_tte(grand, addr);
		/*
		 * The nested pmap may have been trimmed before pmap_nest() completed for grand,
		 * so it's possible that a region we're trying to unnest may not have been
		 * nested in the first place.
		 */
		if (tte_p != NULL) {
			*tte_p = ARM_TTE_TYPE_FAULT;
		}
		addr += pt_attr_twig_size(pt_attr);
		vrestart = addr | PMAP_NEST_GRAND;
		++entry_count;
		if (__improbable(!(entry_count % PMAP_DEFAULT_PREEMPTION_CHECK_PAGE_INTERVAL) &&
		    pmap_pending_preemption())) {
			break;
		}
	}
	if (addr >= true_end) {
		vrestart = vend | PMAP_NEST_GRAND;
	}

	FLUSH_PTE_STRONG();
	PMAP_UPDATE_TLBS(grand, start, addr, false, false);

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
	__unused vm_map_offset_t vlast = vrestart;

	PMAP_TRACE(2, PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(vaddr));

	pmap_verify_preemptible();
	while (vrestart != (vend | PMAP_NEST_GRAND)) {
#if XNU_MONITOR
		vrestart = pmap_unnest_options_ppl(grand, vaddr, size, vrestart, option);
		if (vrestart == vlast) {
			panic("%s: failed to make forward progress from 0x%llx to 0x%llx at 0x%llx",
			    __func__, (unsigned long long)vaddr, (unsigned long long)vend, (unsigned long long)vrestart);
		}
		vlast = vrestart;
#else
		vrestart = pmap_unnest_options_internal(grand, vaddr, size, vrestart, option);
#endif
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

#define ARM_FULL_TLB_FLUSH_THRESHOLD 64

#if __ARM_RANGE_TLBI__
#define ARM64_RANGE_TLB_FLUSH_THRESHOLD 1
#define ARM64_FULL_TLB_FLUSH_THRESHOLD  ARM64_TLB_RANGE_PAGES
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
	uint32_t    asid;

	asid = pmap->hw_asid;

	if (npages > ARM64_FULL_TLB_FLUSH_THRESHOLD) {
		boolean_t       flush_all = FALSE;

		if ((asid == 0) || (pmap->type == PMAP_TYPE_NESTED)) {
			flush_all = TRUE;
		}
		if (flush_all) {
			flush_mmu_tlb_async();
		} else {
			flush_mmu_tlb_asid_async((uint64_t)asid << TLBI_ASID_SHIFT);
		}
		return;
	}
#if __ARM_RANGE_TLBI__
	if (npages > ARM64_RANGE_TLB_FLUSH_THRESHOLD) {
		va = generate_rtlbi_param(npages, asid, va, pmap_page_shift);
		if (pmap->type == PMAP_TYPE_NESTED) {
			flush_mmu_tlb_allrange_async(va, last_level_only);
		} else {
			flush_mmu_tlb_range_async(va, last_level_only);
		}
		return;
	}
#endif
	vm_offset_t end = tlbi_asid(asid) | tlbi_addr(va + length);
	va = tlbi_asid(asid) | tlbi_addr(va);

	if (pmap->type == PMAP_TYPE_NESTED) {
		flush_mmu_tlb_allentries_async(va, end, pmap_page_size, last_level_only);
	} else {
		flush_mmu_tlb_entries_async(va, end, pmap_page_size, last_level_only);
	}
}

MARK_AS_PMAP_TEXT static void
flush_mmu_tlb_full_asid_async(pmap_t pmap)
{
	flush_mmu_tlb_asid_async((uint64_t)(pmap->hw_asid) << TLBI_ASID_SHIFT);
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
	const unsigned int pai = pa_index(paddr);

	if (__improbable(!pa_valid(paddr))) {
		panic("%s called on non-managed page 0x%08x", __func__, pn);
	}

	pvh_lock(pai);

#if XNU_MONITOR
	if (__improbable(ppattr_pa_test_monitor(paddr))) {
		panic("%s invoked on PPL page 0x%08x", __func__, pn);
	}
#endif

	pmap_update_cache_attributes_locked(pn, new_cacheattr, true);

	pvh_unlock(pai);

	pmap_sync_wimg(pn, prev_cacheattr & VM_WIMG_MASK, new_cacheattr & VM_WIMG_MASK);
}

void *
pmap_map_compressor_page(ppnum_t pn)
{
#if __ARM_PTE_PHYSMAP__
	unsigned int cacheattr = pmap_cache_attributes(pn) & VM_WIMG_MASK;
	if (cacheattr != VM_WIMG_DEFAULT) {
#if XNU_MONITOR
		pmap_update_compressor_page_ppl(pn, cacheattr, VM_WIMG_DEFAULT);
#else
		pmap_update_compressor_page_internal(pn, cacheattr, VM_WIMG_DEFAULT);
#endif
	}
#endif
	return (void*)phystokv(ptoa(pn));
}

void
pmap_unmap_compressor_page(ppnum_t pn __unused, void *kva __unused)
{
#if __ARM_PTE_PHYSMAP__
	unsigned int cacheattr = pmap_cache_attributes(pn) & VM_WIMG_MASK;
	if (cacheattr != VM_WIMG_DEFAULT) {
#if XNU_MONITOR
		pmap_update_compressor_page_ppl(pn, VM_WIMG_DEFAULT, cacheattr);
#else
		pmap_update_compressor_page_internal(pn, VM_WIMG_DEFAULT, cacheattr);
#endif
	}
#endif
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

	batch_set_cache_attr_state_t states;
	states.page_index = 0;
	states.state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_UPDATE_PASS;
	states.tlb_flush_pass_needed = false;
	states.rt_cache_flush_pass_needed = false;

	/* Verify we are being called from a preemptible context. */
	pmap_verify_preemptible();

	while (states.state != PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE) {
#if XNU_MONITOR
		states = pmap_batch_set_cache_attributes_ppl((volatile upl_page_info_t *) user_page_list, states, page_cnt, cacheattr);
#else /* !XNU_MONITOR */
		states = pmap_batch_set_cache_attributes_internal(user_page_list, states, page_cnt, cacheattr);
#endif /* XNU_MONITOR */
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING) | DBG_FUNC_END, page_cnt, cacheattr, 0xCECC0DEF);
	return true;
}

/**
 * Flushes TLB entries associated with the page numbered by pn, but do not
 * issue barriers yet.
 *
 * @param paddr The physical address to be flushed from TLB. Must be a managed address.
 */
MARK_AS_PMAP_TEXT static void
pmap_flush_tlb_for_paddr_locked_async(pmap_paddr_t paddr)
{
#if __ARM_PTE_PHYSMAP__
	/* Flush the physical aperture mappings. */
	const vm_offset_t kva = phystokv(paddr);
	flush_mmu_tlb_region_asid_async(kva, PAGE_SIZE, kernel_pmap, true);
#endif /* __ARM_PTE_PHYSMAP__ */

	/* Flush the mappings tracked in the ptes. */
	const unsigned int pai = pa_index(paddr);
	pv_entry_t **pv_h = pai_to_pvh(pai);

	pt_entry_t *pte_p = PT_ENTRY_NULL;
	pv_entry_t *pve_p = PV_ENTRY_NULL;

	pvh_assert_locked(pai);

	if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(pv_h);
	} else if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_pve_list(pv_h);
		pte_p = PT_ENTRY_NULL;
	}

	int pve_ptep_idx = 0;
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto flush_tlb_skip_pte;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto flush_tlb_skip_pte;
		}
#endif /* PVH_FLAG_IOMMU */
		pmap_t pmap = ptep_get_pmap(pte_p);
		vm_map_address_t va = ptep_get_va(pte_p);

		pmap_get_pt_ops(pmap)->flush_tlb_region_async(va, pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO, pmap, true);

flush_tlb_skip_pte:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}
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
 * Batch updates the cache attributes of a list of pages in three passes.
 *
 * In pass one, the pp_attr_table and the pte are updated for the pages in the list.
 * In pass two, TLB entries are flushed for each page in the list if necessary.
 * In pass three, caches are cleaned for each page in the list if necessary.
 *
 * When running in PPL, this function may decide to return to the caller in response
 * to AST_URGENT.
 *
 * @param user_page_list List of pages to be updated.
 * @param states The state of the state machine. See definition of batch_set_cache_attr_state_t.
 * @param page_cnt Number of pages in total in user_page_list.
 * @param cacheattr The new cache attributes.
 *
 * @return The new state of the state machine.
 */
MARK_AS_PMAP_TEXT batch_set_cache_attr_state_t
pmap_batch_set_cache_attributes_internal(
#if XNU_MONITOR
	volatile upl_page_info_t *user_page_list,
#else /* !XNU_MONITOR */
	upl_page_info_array_t user_page_list,
#endif /* XNU_MONITOR */
	batch_set_cache_attr_state_t states,
	unsigned int page_cnt,
	unsigned int cacheattr)
{
	uint64_t page_index = states.page_index;
	uint64_t state = states.state;
	bool tlb_flush_pass_needed = !!(states.tlb_flush_pass_needed);
	bool rt_cache_flush_pass_needed = !!(states.rt_cache_flush_pass_needed);

	/* For verifying progress. */
	__assert_only const uint64_t page_index_old = page_index;
	__assert_only const uint64_t state_old = state;

	/* Assert page_index and state are within their range. */
	if (!(page_index < page_cnt && state < PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE)) {
		panic("%s: invalid input; page_index: %llu, page_cnt: %u, state: %llu", __func__, page_index, page_cnt, state);
	}

	if (state == PMAP_BATCH_SET_CACHE_ATTRIBUTES_UPDATE_PASS) {
		PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE1, page_index);
		/* Update cache attributes of the pages until there's an urgent AST or it's done. */
		while (page_index < page_cnt) {
			const ppnum_t pn = user_page_list[page_index].phys_addr;
			const pmap_paddr_t paddr = ptoa(pn);

			if (!pa_valid(paddr)) {
				panic("%s: page is not managed; addr: 0x%016llx", __func__, paddr);
			}

			const unsigned int pai = pa_index(paddr);

			/* Lock the page. */
			pvh_lock(pai);

#if XNU_MONITOR
			if (ppattr_pa_test_monitor(paddr)) {
				panic("%s invoked on PPL page 0x%llx", __func__, (uint64_t)paddr);
			}
#endif /* XNU_MONITOR */
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

			/* Update the cache attributes in PTE. */
			if (wimg_bits_new != wimg_bits_prev) {
				tlb_flush_pass_needed |= pmap_update_cache_attributes_locked(pn, cacheattr, false);
			}

			if (wimg_bits_new == VM_WIMG_RT && wimg_bits_prev != VM_WIMG_RT) {
				rt_cache_flush_pass_needed = true;
			}

			pmap_update_pp_attr_wimg_bits_locked(pai, cacheattr);
			pvh_unlock(pai);

			page_index++;

#if XNU_MONITOR
			/**
			 * Check for AST_URGENT every page, as the pve list search in cache
			 * update can take non-constant time.
			 */
			if (__improbable(pmap_pending_preemption() && (page_index < page_cnt))) {
				goto pbscai_exit;
			}
#endif /* XNU_MONITOR */
		}

		/* page_index == page_cnt && !pmap_pending_preemption() */
		if (tlb_flush_pass_needed) {
			state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_TLBFLUSH_PASS;
		} else if (rt_cache_flush_pass_needed) {
			state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_CACHEFLUSH_PASS;
		} else {
			state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE;
		}
		page_index = 0;

		/* Sync the PTE writes before potential TLB/Cache flushes. */
		FLUSH_PTE_STRONG();

#if XNU_MONITOR
		if (__improbable(pmap_pending_preemption())) {
			goto pbscai_exit;
		}
#endif /* XNU_MONITOR */
	}

	if (state == PMAP_BATCH_SET_CACHE_ATTRIBUTES_TLBFLUSH_PASS) {
		/**
		 * Pass 2: for each physical page and for each mapping, we need to flush
		 * the TLB for it.
		 */
		PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE2, page_index);
		while (page_index < page_cnt) {
			const ppnum_t pn = user_page_list[page_index].phys_addr;

			const pmap_paddr_t paddr = ptoa(pn);
			if (!pa_valid(paddr)) {
				panic("%s: page is not managed; addr: 0x%016llx", __func__, paddr);
			}

			const unsigned int pai = pa_index(paddr);

			pvh_lock(pai);
			pmap_flush_tlb_for_paddr_locked_async(paddr);
			pvh_unlock(pai);

			page_index++;

#if XNU_MONITOR
			/**
			 * Check for AST_URGENT every page, as the pve list search in cache
			 * update can take non-constant time.
			 */
			if (__improbable(pmap_pending_preemption() && (page_index < page_cnt))) {
				goto pbscai_exit;
			}
#endif /* XNU_MONITOR */
		}

		arm64_sync_tlb((cacheattr & VM_WIMG_MASK) == VM_WIMG_RT);

		if (rt_cache_flush_pass_needed) {
			state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_CACHEFLUSH_PASS;
		} else {
			state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE;
		}
		page_index = 0;

#if XNU_MONITOR
		if (__improbable(pmap_pending_preemption())) {
			goto pbscai_exit;
		}
#endif /* XNU_MONITOR */
	}

	if (state == PMAP_BATCH_SET_CACHE_ATTRIBUTES_CACHEFLUSH_PASS) {
		/* Pass 3: Flush the cache if the page is recently set to RT */
		PMAP_TRACE(2, PMAP_CODE(PMAP__BATCH_UPDATE_CACHING), page_cnt, cacheattr, 0xCECC0DE3, page_index);
#if !XNU_MONITOR
		/**
		 * On non-PPL platforms, we disable preemption to ensure we are not preempted
		 * in the state where DC by VA instructions remain enabled.
		 */
		disable_preemption();
#endif /* !XNU_MONITOR */

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
				panic("%s: page is not managed; addr: 0x%016llx", __func__, paddr);
			}

			CleanPoC_DcacheRegion_Force_nopreempt_nohid(phystokv(paddr), PAGE_SIZE);

			page_index++;

#if XNU_MONITOR
			if (__improbable(pmap_pending_preemption() && (page_index < page_cnt))) {
#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
				disable_dc_mva_ops();
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM */
				goto pbscai_exit;
			}
#endif /* XNU_MONITOR */
		}

#if defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM
		disable_dc_mva_ops();
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) && !APPLEVIRTUALPLATFORM */

#if !XNU_MONITOR
		enable_preemption();
#endif /* !XNU_MONITOR */

		state = PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE;
		page_index = 0;
	}

#if XNU_MONITOR
pbscai_exit:
#endif /* XNU_MONITOR */
	/* Assert page_index and state are within their range. */
	assert(page_index < page_cnt || state == PMAP_BATCH_SET_CACHE_ATTRIBUTES_DONE);

	/* Make sure we are making progress in this call. */
	assert(page_index > page_index_old || state > state_old);

	batch_set_cache_attr_state_t states_new;
	states_new.page_index = page_index;
	states_new.state = state;
	states_new.tlb_flush_pass_needed = tlb_flush_pass_needed ? 1 : 0;
	states_new.rt_cache_flush_pass_needed = rt_cache_flush_pass_needed ? 1 : 0;
	return states_new;
}

MARK_AS_PMAP_TEXT static void
pmap_set_cache_attributes_priv(
	ppnum_t pn,
	unsigned int cacheattr,
	boolean_t external __unused)
{
	pmap_paddr_t    paddr;
	unsigned int    pai;
	pp_attr_t       pp_attr_current;
	pp_attr_t       pp_attr_template;
	unsigned int    wimg_bits_prev, wimg_bits_new;

	paddr = ptoa(pn);

	if (!pa_valid(paddr)) {
		return;                         /* Not a managed page. */
	}

	if (cacheattr & VM_WIMG_USE_DEFAULT) {
		cacheattr = VM_WIMG_DEFAULT;
	}

	pai = pa_index(paddr);

	pvh_lock(pai);

#if XNU_MONITOR
	if (external && ppattr_pa_test_monitor(paddr)) {
		panic("%s invoked on PPL page 0x%llx", __func__, (uint64_t)paddr);
	} else if (!external && !ppattr_pa_test_monitor(paddr)) {
		panic("%s invoked on non-PPL page 0x%llx", __func__, (uint64_t)paddr);
	}
#endif

	do {
		pp_attr_current = pp_attr_table[pai];
		wimg_bits_prev = VM_WIMG_DEFAULT;
		if (pp_attr_current & PP_ATTR_WIMG_MASK) {
			wimg_bits_prev = pp_attr_current & PP_ATTR_WIMG_MASK;
		}

		pp_attr_template = (pp_attr_current & ~PP_ATTR_WIMG_MASK) | PP_ATTR_WIMG(cacheattr & (VM_WIMG_MASK));

		/**
		 * WIMG bits should only be updated under the PVH lock, but we should do
		 * this in a CAS loop to avoid losing simultaneous updates to other bits like refmod.
		 */
	} while (!OSCompareAndSwap16(pp_attr_current, pp_attr_template, &pp_attr_table[pai]));

	wimg_bits_new = VM_WIMG_DEFAULT;
	if (pp_attr_template & PP_ATTR_WIMG_MASK) {
		wimg_bits_new = pp_attr_template & PP_ATTR_WIMG_MASK;
	}

	if (wimg_bits_new != wimg_bits_prev) {
		pmap_update_cache_attributes_locked(pn, cacheattr, true);
	}

	pvh_unlock(pai);

	pmap_sync_wimg(pn, wimg_bits_prev, wimg_bits_new);
}

MARK_AS_PMAP_TEXT void
pmap_set_cache_attributes_internal(
	ppnum_t pn,
	unsigned int cacheattr)
{
	pmap_set_cache_attributes_priv(pn, cacheattr, TRUE);
}

void
pmap_set_cache_attributes(
	ppnum_t pn,
	unsigned int cacheattr)
{
#if XNU_MONITOR
	pmap_set_cache_attributes_ppl(pn, cacheattr);
#else
	pmap_set_cache_attributes_internal(pn, cacheattr);
#endif
}

/**
 * Updates the page numbered ppnum to have attribute specified by attributes.
 * If a TLB flush is necessary, it will be performed if perform_tlbi is true.
 * The necessity of the TLB flush is returned in case this function is called
 * in a batched manner and the TLB flush is intended to be done at a different
 * timing.
 *
 * @param ppnum Page Number of the page to be updated.
 * @param attributes The new cache attributes.
 * @param perform_tlbi When a TLB flush is needed, whether to perform the tlbi
 *        immediately.
 *
 * @return Returns true if a TLB flush is needed for this update regardless of
 *         whether a flush has occurred already.
 */
MARK_AS_PMAP_TEXT bool
pmap_update_cache_attributes_locked(
	ppnum_t ppnum,
	unsigned attributes,
	bool perform_tlbi)
{
	pmap_paddr_t    phys = ptoa(ppnum);
	pv_entry_t      *pve_p;
	pt_entry_t      *pte_p;
	pv_entry_t      **pv_h;
	pt_entry_t      tmplate;
	unsigned int    pai;
	boolean_t       tlb_flush_needed = false;

	PMAP_TRACE(2, PMAP_CODE(PMAP__UPDATE_CACHING) | DBG_FUNC_START, ppnum, attributes);

	if (pmap_panic_dev_wimg_on_managed) {
		switch (attributes & VM_WIMG_MASK) {
		case VM_WIMG_IO:                        // nGnRnE
		case VM_WIMG_POSTED:                    // nGnRE
		/* supported on DRAM, but slow, so we disallow */

		case VM_WIMG_POSTED_REORDERED:          // nGRE
		case VM_WIMG_POSTED_COMBINED_REORDERED: // GRE
			/* unsupported on DRAM */

			panic("%s: trying to use unsupported VM_WIMG type for managed page, VM_WIMG=%x, ppnum=%#x",
			    __FUNCTION__, attributes & VM_WIMG_MASK, ppnum);
			break;

		default:
			/* not device type memory, all good */

			break;
		}
	}

#if __ARM_PTE_PHYSMAP__
	vm_offset_t kva = phystokv(phys);
	pte_p = pmap_pte(kernel_pmap, kva);

	tmplate = *pte_p;
	tmplate &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
#if XNU_MONITOR
	tmplate |= (wimg_to_pte(attributes, phys) & ~ARM_PTE_XPRR_MASK);
#else
	tmplate |= wimg_to_pte(attributes, phys);
#endif
	if (tmplate & ARM_PTE_HINT_MASK) {
		panic("%s: physical aperture PTE %p has hint bit set, va=%p, pte=0x%llx",
		    __FUNCTION__, pte_p, (void *)kva, tmplate);
	}

	if (perform_tlbi) {
		write_pte_strong(pte_p, tmplate);
		flush_mmu_tlb_region_asid_async(kva, PAGE_SIZE, kernel_pmap, true);
	} else {
		write_pte_fast(pte_p, tmplate);
	}
	tlb_flush_needed = true;
#endif

	pai = pa_index(phys);

	pv_h = pai_to_pvh(pai);

	pte_p = PT_ENTRY_NULL;
	pve_p = PV_ENTRY_NULL;
	if (pvh_test_type(pv_h, PVH_TYPE_PTEP)) {
		pte_p = pvh_ptep(pv_h);
	} else if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
		pve_p = pvh_pve_list(pv_h);
		pte_p = PT_ENTRY_NULL;
	}

	int pve_ptep_idx = 0;
	while ((pve_p != PV_ENTRY_NULL) || (pte_p != PT_ENTRY_NULL)) {
		vm_map_address_t va;
		pmap_t          pmap;

		if (pve_p != PV_ENTRY_NULL) {
			pte_p = pve_get_ptep(pve_p, pve_ptep_idx);
			if (pte_p == PT_ENTRY_NULL) {
				goto cache_skip_pve;
			}
		}

#ifdef PVH_FLAG_IOMMU
		if (pvh_ptep_is_iommu(pte_p)) {
			goto cache_skip_pve;
		}
#endif
		pmap = ptep_get_pmap(pte_p);
		va = ptep_get_va(pte_p);

		tmplate = *pte_p;
		tmplate &= ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK);
		tmplate |= pmap_get_pt_ops(pmap)->wimg_to_pte(attributes, phys);

		if (perform_tlbi) {
			write_pte_strong(pte_p, tmplate);
			pmap_get_pt_ops(pmap)->flush_tlb_region_async(va, pt_attr_page_size(pmap_get_pt_attr(pmap)) * PAGE_RATIO, pmap, true);
		} else {
			write_pte_fast(pte_p, tmplate);
		}
		tlb_flush_needed = true;

cache_skip_pve:
		pte_p = PT_ENTRY_NULL;
		if ((pve_p != PV_ENTRY_NULL) && (++pve_ptep_idx == PTE_PER_PVE)) {
			pve_ptep_idx = 0;
			pve_p = pve_next(pve_p);
		}
	}
	if (perform_tlbi && tlb_flush_needed) {
		arm64_sync_tlb((attributes & VM_WIMG_MASK) == VM_WIMG_RT);
	}

	PMAP_TRACE(2, PMAP_CODE(PMAP__UPDATE_CACHING) | DBG_FUNC_END, ppnum, attributes);

	return tlb_flush_needed;
}

/**
 * Mark a pmap as being dedicated to use for a commpage mapping.
 * The pmap itself will never be activated on a CPU; its mappings will
 * only be embedded in userspace pmaps at a fixed virtual address.
 *
 * @param pmap the pmap to mark as belonging to a commpage.
 */
static void
pmap_set_commpage(pmap_t pmap)
{
#if XNU_MONITOR
	assert(!pmap_ppl_locked_down);
#endif
	assert(pmap->type == PMAP_TYPE_USER);
	pmap->type = PMAP_TYPE_COMMPAGE;
	/*
	 * Free the pmap's ASID.  This pmap should not ever be directly
	 * activated in a CPU's TTBR.  Freeing the ASID will not only reduce
	 * ASID space contention but will also cause pmap_switch() to panic
	 * if an attacker tries to activate this pmap.  Disable preemption to
	 * accommodate the *_nopreempt spinlock in free_asid().
	 */
	mp_disable_preemption();
	pmap_get_pt_ops(pmap)->free_id(pmap);
	mp_enable_preemption();
}

static void
pmap_update_tt3e(
	pmap_t pmap,
	vm_address_t address,
	tt_entry_t template)
{
	tt_entry_t *ptep, pte;

	ptep = pmap_tt3e(pmap, address);
	if (ptep == NULL) {
		panic("%s: no ptep?", __FUNCTION__);
	}

	pte = *ptep;
	pte = tte_to_pa(pte) | template;
	write_pte_strong(ptep, pte);
}

/* Note absence of non-global bit */
#define PMAP_COMM_PAGE_PTE_TEMPLATE (ARM_PTE_TYPE_VALID \
	        | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK) \
	        | ARM_PTE_SH(SH_INNER_MEMORY) | ARM_PTE_NX \
	        | ARM_PTE_PNX | ARM_PTE_AP(AP_RORO) | ARM_PTE_AF)

/* Note absence of non-global bit and no-execute bit.  */
#define PMAP_COMM_PAGE_TEXT_PTE_TEMPLATE (ARM_PTE_TYPE_VALID \
	        | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_WRITEBACK) \
	        | ARM_PTE_SH(SH_INNER_MEMORY) | ARM_PTE_PNX \
	        | ARM_PTE_AP(AP_RORO) | ARM_PTE_AF)

void
pmap_create_sharedpages(vm_map_address_t *kernel_data_addr, vm_map_address_t *kernel_text_addr,
    vm_map_address_t *kernel_ro_data_addr, vm_map_address_t *user_text_addr)
{
	kern_return_t kr;
	pmap_paddr_t data_pa = 0; // data address
	pmap_paddr_t ro_data_pa = 0; // kernel read-only data address
	pmap_paddr_t text_pa = 0; // text address

	*kernel_data_addr = 0;
	*kernel_text_addr = 0;
	*user_text_addr = 0;

#if XNU_MONITOR
	data_pa = pmap_alloc_page_for_kern(0);
	assert(data_pa);
	memset((char *) phystokv(data_pa), 0, PAGE_SIZE);
	ro_data_pa = pmap_alloc_page_for_kern(0);
	assert(ro_data_pa);
	memset((char *) phystokv(ro_data_pa), 0, PAGE_SIZE);
#if CONFIG_ARM_PFZ
	text_pa = pmap_alloc_page_for_kern(0);
	assert(text_pa);
	memset((char *) phystokv(text_pa), 0, PAGE_SIZE);
#endif

#else /* XNU_MONITOR */
	(void) pmap_pages_alloc_zeroed(&data_pa, PAGE_SIZE, 0);
	/*
	 * For non-PPL devices, we have neither page lockdown nor a physical aperture
	 * mapped at page granularity, so a separate page for kernel RO data would not
	 * be useful.
	 */
	ro_data_pa = data_pa;
#if CONFIG_ARM_PFZ
	(void) pmap_pages_alloc_zeroed(&text_pa, PAGE_SIZE, 0);
#endif

#endif /* XNU_MONITOR */

	/*
	 * In order to avoid burning extra pages on mapping the shared page, we
	 * create a dedicated pmap for the shared page.  We forcibly nest the
	 * translation tables from this pmap into other pmaps.  The level we
	 * will nest at depends on the MMU configuration (page size, TTBR range,
	 * etc). Typically, this is at L1 for 4K tasks and L2 for 16K tasks.
	 *
	 * Note that this is NOT "the nested pmap" (which is used to nest the
	 * shared cache).
	 *
	 * Note that we update parameters of the entry for our unique needs (NG
	 * entry, etc.).
	 */
	sharedpage_pmap_default = pmap_create_options(NULL, 0x0, 0);
	assert(sharedpage_pmap_default != NULL);
	pmap_set_commpage(sharedpage_pmap_default);

	/* The user 64-bit mappings... */
	kr = pmap_enter_addr(sharedpage_pmap_default, _COMM_PAGE64_BASE_ADDRESS, data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_default, _COMM_PAGE64_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	kr = pmap_enter_addr(sharedpage_pmap_default, _COMM_PAGE64_RO_ADDRESS, ro_data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_default, _COMM_PAGE64_RO_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);
#if CONFIG_ARM_PFZ
	/* User mapping of comm page text section for 64 bit mapping only
	 *
	 * We don't insert it into the 32 bit mapping because we don't want 32 bit
	 * user processes to get this page mapped in, they should never call into
	 * this page.
	 *
	 * The data comm page is in a pre-reserved L3 VA range and the text commpage
	 * is slid in the same L3 as the data commpage.  It is either outside the
	 * max of user VA or is pre-reserved in the vm_map_exec(). This means that
	 * it is reserved and unavailable to mach VM for future mappings.
	 */
	const pt_attr_t * const pt_attr = pmap_get_pt_attr(sharedpage_pmap_default);
	int num_ptes = pt_attr_leaf_size(pt_attr) >> PTE_SHIFT;

	vm_map_address_t commpage_text_va = 0;

	do {
		int text_leaf_index = random() % num_ptes;

		// Generate a VA for the commpage text with the same root and twig index as data
		// comm page, but with new leaf index we've just generated.
		commpage_text_va = (_COMM_PAGE64_BASE_ADDRESS & ~pt_attr_leaf_index_mask(pt_attr));
		commpage_text_va |= (text_leaf_index << pt_attr_leaf_shift(pt_attr));
	} while ((commpage_text_va == _COMM_PAGE64_BASE_ADDRESS) || (commpage_text_va == _COMM_PAGE64_RO_ADDRESS)); // Try again if we collide (should be unlikely)

	// Assert that this is empty
	__assert_only pt_entry_t *ptep = pmap_pte(sharedpage_pmap_default, commpage_text_va);
	assert(ptep != PT_ENTRY_NULL);
	assert(*ptep == ARM_TTE_EMPTY);

	// At this point, we've found the address we want to insert our comm page at
	kr = pmap_enter_addr(sharedpage_pmap_default, commpage_text_va, text_pa, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	// Mark it as global page R/X so that it doesn't get thrown out on tlb flush
	pmap_update_tt3e(sharedpage_pmap_default, commpage_text_va, PMAP_COMM_PAGE_TEXT_PTE_TEMPLATE);

	*user_text_addr = commpage_text_va;
#endif

	/* ...and the user 32-bit mappings. */
	kr = pmap_enter_addr(sharedpage_pmap_default, _COMM_PAGE32_BASE_ADDRESS, data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_default, _COMM_PAGE32_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	kr = pmap_enter_addr(sharedpage_pmap_default, _COMM_PAGE32_RO_ADDRESS, ro_data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_default, _COMM_PAGE32_RO_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);
#if __ARM_MIXED_PAGE_SIZE__
	/**
	 * To handle 4K tasks a new view/pmap of the shared page is needed. These are a
	 * new set of page tables that point to the exact same 16K shared page as
	 * before. Only the first 4K of the 16K shared page is mapped since that's
	 * the only part that contains relevant data.
	 */
	sharedpage_pmap_4k = pmap_create_options(NULL, 0x0, PMAP_CREATE_FORCE_4K_PAGES);
	assert(sharedpage_pmap_4k != NULL);
	pmap_set_commpage(sharedpage_pmap_4k);

	/* The user 64-bit mappings... */
	kr = pmap_enter_addr(sharedpage_pmap_4k, _COMM_PAGE64_BASE_ADDRESS, data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_4k, _COMM_PAGE64_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	kr = pmap_enter_addr(sharedpage_pmap_4k, _COMM_PAGE64_RO_ADDRESS, ro_data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_4k, _COMM_PAGE64_RO_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	/* ...and the user 32-bit mapping. */
	kr = pmap_enter_addr(sharedpage_pmap_4k, _COMM_PAGE32_BASE_ADDRESS, data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_4k, _COMM_PAGE32_BASE_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);

	kr = pmap_enter_addr(sharedpage_pmap_4k, _COMM_PAGE32_RO_ADDRESS, ro_data_pa, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, TRUE);
	assert(kr == KERN_SUCCESS);
	pmap_update_tt3e(sharedpage_pmap_4k, _COMM_PAGE32_RO_ADDRESS, PMAP_COMM_PAGE_PTE_TEMPLATE);
#endif

	/* For manipulation in kernel, go straight to physical page */
	*kernel_data_addr = phystokv(data_pa);
	assert(sharedpage_ro_data_kva == 0);
	*kernel_ro_data_addr = sharedpage_ro_data_kva = phystokv(ro_data_pa);
	assert(sharedpage_text_kva == 0);
	*kernel_text_addr = sharedpage_text_kva = (text_pa ? phystokv(text_pa) : 0);
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
pmap_insert_sharedpage_internal(
	pmap_t pmap)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_offset_t sharedpage_vaddr;
	pt_entry_t *ttep, *src_ttep;
	int options = 0;
	pmap_t sharedpage_pmap = sharedpage_pmap_default;

	/* Validate the pmap input before accessing its data. */
	validate_pmap_mutable(pmap);

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const unsigned int sharedpage_level = pt_attr_commpage_level(pt_attr);

#if __ARM_MIXED_PAGE_SIZE__
#if !__ARM_16K_PG__
	/* The following code assumes that sharedpage_pmap_default is a 16KB pmap. */
	#error "pmap_insert_sharedpage_internal requires a 16KB default kernel page size when __ARM_MIXED_PAGE_SIZE__ is enabled"
#endif /* !__ARM_16K_PG__ */

	/* Choose the correct shared page pmap to use. */
	const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
	if (pmap_page_size == 16384) {
		sharedpage_pmap = sharedpage_pmap_default;
	} else if (pmap_page_size == 4096) {
		sharedpage_pmap = sharedpage_pmap_4k;
	} else {
		panic("No shared page pmap exists for the wanted page size: %llu", pmap_page_size);
	}
#endif /* __ARM_MIXED_PAGE_SIZE__ */

#if XNU_MONITOR
	options |= PMAP_OPTIONS_NOWAIT;
#endif /* XNU_MONITOR */

#if _COMM_PAGE_AREA_LENGTH != PAGE_SIZE
#error We assume a single page.
#endif

	if (pmap_is_64bit(pmap)) {
		sharedpage_vaddr = _COMM_PAGE64_BASE_ADDRESS;
	} else {
		sharedpage_vaddr = _COMM_PAGE32_BASE_ADDRESS;
	}


	pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

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
	while ((ttep = pmap_ttne(pmap, sharedpage_level, sharedpage_vaddr)) == TT_ENTRY_NULL) {
		pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);

		kr = pmap_expand(pmap, sharedpage_vaddr, options, sharedpage_level);

		if (kr != KERN_SUCCESS) {
#if XNU_MONITOR
			if (kr == KERN_RESOURCE_SHORTAGE) {
				return kr;
			} else
#endif
			{
				panic("Failed to pmap_expand for commpage, pmap=%p", pmap);
			}
		}

		pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);
	}

	if (*ttep != ARM_PTE_EMPTY) {
		panic("%s: Found something mapped at the commpage address?!", __FUNCTION__);
	}

	src_ttep = pmap_ttne(sharedpage_pmap, sharedpage_level, sharedpage_vaddr);

	*ttep = *src_ttep;
	FLUSH_PTE_STRONG();

	pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);

	return kr;
}

static void
pmap_unmap_sharedpage(
	pmap_t pmap)
{
	pt_entry_t *ttep;
	vm_offset_t sharedpage_vaddr;
	pmap_t sharedpage_pmap = sharedpage_pmap_default;

	const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);
	const unsigned int sharedpage_level = pt_attr_commpage_level(pt_attr);

#if __ARM_MIXED_PAGE_SIZE__
#if !__ARM_16K_PG__
	/* The following code assumes that sharedpage_pmap_default is a 16KB pmap. */
	#error "pmap_unmap_sharedpage requires a 16KB default kernel page size when __ARM_MIXED_PAGE_SIZE__ is enabled"
#endif /* !__ARM_16K_PG__ */

	/* Choose the correct shared page pmap to use. */
	const uint64_t pmap_page_size = pt_attr_page_size(pt_attr);
	if (pmap_page_size == 16384) {
		sharedpage_pmap = sharedpage_pmap_default;
	} else if (pmap_page_size == 4096) {
		sharedpage_pmap = sharedpage_pmap_4k;
	} else {
		panic("No shared page pmap exists for the wanted page size: %llu", pmap_page_size);
	}
#endif /* __ARM_MIXED_PAGE_SIZE__ */

#if _COMM_PAGE_AREA_LENGTH != PAGE_SIZE
#error We assume a single page.
#endif

	if (pmap_is_64bit(pmap)) {
		sharedpage_vaddr = _COMM_PAGE64_BASE_ADDRESS;
	} else {
		sharedpage_vaddr = _COMM_PAGE32_BASE_ADDRESS;
	}


	ttep = pmap_ttne(pmap, sharedpage_level, sharedpage_vaddr);

	if (ttep == NULL) {
		return;
	}

	/* It had better be mapped to the shared page. */
	if (*ttep != ARM_TTE_EMPTY && *ttep != *pmap_ttne(sharedpage_pmap, sharedpage_level, sharedpage_vaddr)) {
		panic("%s: Something other than commpage mapped in shared page slot?", __FUNCTION__);
	}

	*ttep = ARM_TTE_EMPTY;
	FLUSH_PTE_STRONG();

	flush_mmu_tlb_region_asid_async(sharedpage_vaddr, PAGE_SIZE, pmap, false);
	sync_tlb_flush();
}

void
pmap_insert_sharedpage(
	pmap_t pmap)
{
#if XNU_MONITOR
	kern_return_t kr = KERN_FAILURE;

	while ((kr = pmap_insert_sharedpage_ppl(pmap)) == KERN_RESOURCE_SHORTAGE) {
		pmap_alloc_page_for_ppl(0);
	}

	pmap_ledger_check_balance(pmap);

	if (kr != KERN_SUCCESS) {
		panic("%s: failed to insert the shared page, kr=%d, "
		    "pmap=%p",
		    __FUNCTION__, kr,
		    pmap);
	}
#else
	pmap_insert_sharedpage_internal(pmap);
#endif
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
#if XNU_MONITOR
	return pmap_is_empty_ppl(pmap, va_start, va_end);
#else
	return pmap_is_empty_internal(pmap, va_start, va_end);
#endif
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

#if defined(__arm64__)
	#define ARM64_MIN_MAX_ADDRESS (SHARED_REGION_BASE_ARM64 + SHARED_REGION_SIZE_ARM64 + 0x20000000) // end of shared region + 512MB for various purposes
	_Static_assert((ARM64_MIN_MAX_ADDRESS > SHARED_REGION_BASE_ARM64) && (ARM64_MIN_MAX_ADDRESS <= MACH_VM_MAX_ADDRESS),
	    "Minimum address space size outside allowable range");
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
			max_offset_ret = min_max_offset + 0x138000000; // Max offset is 13.375GB for devices with > 3GB of memory
		} else if (max_mem > 0x40000000) {
			max_offset_ret = min_max_offset + 0x38000000;  // Max offset is 9.375GB for devices with > 1GB and <= 3GB of memory
		} else {
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
	assert(max_offset_ret >= min_max_offset);
#else
	panic("Can't run pmap_max_64bit_offset on non-64bit architectures");
#endif

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

#if XNU_MONITOR

/*
 * Enforce that the address range described by kva and nbytes is not currently
 * PPL-owned, and won't become PPL-owned while pinned.  This is to prevent
 * unintentionally writing to PPL-owned memory.
 */
void
pmap_pin_kernel_pages(vm_offset_t kva, size_t nbytes)
{
	vm_offset_t end;
	if (os_add_overflow(kva, nbytes, &end)) {
		panic("%s(%p, 0x%llx): overflow", __func__, (void*)kva, (uint64_t)nbytes);
	}
	for (vm_offset_t ckva = trunc_page(kva); ckva < end; ckva = round_page(ckva + 1)) {
		pmap_paddr_t pa = kvtophys_nofail(ckva);
		pp_attr_t attr;
		unsigned int pai = pa_index(pa);
		if (ckva == phystokv(pa)) {
			panic("%s(%p): attempt to pin static mapping for page 0x%llx", __func__, (void*)kva, (uint64_t)pa);
		}
		do {
			attr = pp_attr_table[pai] & ~PP_ATTR_NO_MONITOR;
			if (attr & PP_ATTR_MONITOR) {
				panic("%s(%p): physical page 0x%llx belongs to PPL", __func__, (void*)kva, (uint64_t)pa);
			}
		} while (!OSCompareAndSwap16(attr, attr | PP_ATTR_NO_MONITOR, &pp_attr_table[pai]));
	}
}

void
pmap_unpin_kernel_pages(vm_offset_t kva, size_t nbytes)
{
	vm_offset_t end;
	if (os_add_overflow(kva, nbytes, &end)) {
		panic("%s(%p, 0x%llx): overflow", __func__, (void*)kva, (uint64_t)nbytes);
	}
	for (vm_offset_t ckva = trunc_page(kva); ckva < end; ckva = round_page(ckva + 1)) {
		pmap_paddr_t pa = kvtophys_nofail(ckva);

		if (!(pp_attr_table[pa_index(pa)] & PP_ATTR_NO_MONITOR)) {
			panic("%s(%p): physical page 0x%llx not pinned", __func__, (void*)kva, (uint64_t)pa);
		}
		assert(!(pp_attr_table[pa_index(pa)] & PP_ATTR_MONITOR));
		ppattr_pa_clear_no_monitor(pa);
	}
}

/**
 * Lock down a page, making all mappings read-only, and preventing further
 * mappings or removal of this particular kva's mapping. Effectively, it makes
 * the physical page at kva immutable (see the ppl_writable parameter for an
 * exception to this).
 *
 * @param kva Valid address to any mapping of the physical page to lockdown.
 * @param lockdown_flag Bit within PVH_FLAG_LOCKDOWN_MASK specifying the lockdown reason
 * @param ppl_writable True if the PPL should still be able to write to the page
 *                     using the physical aperture mapping. False will make the
 *                     page read-only for both the kernel and PPL in the
 *                     physical aperture.
 */

MARK_AS_PMAP_TEXT static void
pmap_ppl_lockdown_page(vm_address_t kva, uint64_t lockdown_flag, bool ppl_writable)
{
	pmap_ppl_lockdown_page_with_prot(kva, lockdown_flag, ppl_writable, VM_PROT_READ);
}

/**
 * Lock down a page, giving all mappings the specified maximum permissions, and
 * preventing further mappings or removal of this particular kva's mapping.
 * Effectively, it makes the physical page at kva immutable (see the ppl_writable
 * parameter for an exception to this).
 *
 * @param kva Valid address to any mapping of the physical page to lockdown.
 * @param lockdown_flag Bit within PVH_FLAG_LOCKDOWN_MASK specifying the lockdown reason
 * @param ppl_writable True if the PPL should still be able to write to the page
 *                     using the physical aperture mapping. False will make the
 *                     page read-only for both the kernel and PPL in the
 *                     physical aperture.
 * @param prot Maximum permissions to allow in existing alias mappings
 */
MARK_AS_PMAP_TEXT static void
pmap_ppl_lockdown_page_with_prot(vm_address_t kva, uint64_t lockdown_flag, bool ppl_writable, vm_prot_t prot)
{
	const pmap_paddr_t pa = kvtophys_nofail(kva);
	const unsigned int pai = pa_index(pa);

	assert(lockdown_flag & PVH_FLAG_LOCKDOWN_MASK);
	pvh_lock(pai);
	pv_entry_t **pvh = pai_to_pvh(pai);
	const vm_offset_t pvh_flags = pvh_get_flags(pvh);

	if (__improbable(ppattr_pa_test_monitor(pa))) {
		panic("%s: %#lx (page %llx) belongs to PPL", __func__, kva, pa);
	}

	if (__improbable(pvh_flags & (PVH_FLAG_LOCKDOWN_MASK | PVH_FLAG_EXEC))) {
		panic("%s: %#lx already locked down/executable (%#llx)",
		    __func__, kva, (uint64_t)pvh_flags);
	}


	pvh_set_flags(pvh, pvh_flags | lockdown_flag);

	/* Update the physical aperture mapping to prevent kernel write access. */
	const unsigned int new_xprr_perm =
	    (ppl_writable) ? XPRR_PPL_RW_PERM : XPRR_KERN_RO_PERM;
	pmap_set_xprr_perm(pai, XPRR_KERN_RW_PERM, new_xprr_perm);

	pvh_unlock(pai);

	pmap_page_protect_options_internal((ppnum_t)atop(pa), prot, 0, NULL);

	/**
	 * Double-check that the mapping didn't change physical addresses before the
	 * LOCKDOWN flag was set (there is a brief window between the above
	 * kvtophys() and pvh_lock() calls where the mapping could have changed).
	 *
	 * This doesn't solve the ABA problem, but this doesn't have to since once
	 * the pvh_lock() is grabbed no new mappings can be created on this physical
	 * page without the LOCKDOWN flag already set (so any future mappings can
	 * only be RO, and no existing mappings can be removed).
	 */
	if (kvtophys_nofail(kva) != pa) {
		panic("%s: Physical address of mapping changed while setting LOCKDOWN "
		    "flag %#lx %#llx", __func__, kva, (uint64_t)pa);
	}
}

/**
 * Helper for releasing a page from being locked down to the PPL, making it writable to the
 * kernel once again.
 *
 * @note This must be paired with a pmap_ppl_lockdown_page() call. Any attempts
 *       to unlockdown a page that was never locked down, will panic.
 *
 * @param pai physical page index to release from lockdown.  PVH lock for this page must be held.
 * @param lockdown_flag Bit within PVH_FLAG_LOCKDOWN_MASK specifying the lockdown reason
 * @param ppl_writable This must match whatever `ppl_writable` parameter was
 *                     passed to the paired pmap_ppl_lockdown_page() call. Any
 *                     deviation will result in a panic.
 */
MARK_AS_PMAP_TEXT static void
pmap_ppl_unlockdown_page_locked(unsigned int pai, uint64_t lockdown_flag, bool ppl_writable)
{
	pvh_assert_locked(pai);
	pv_entry_t **pvh = pai_to_pvh(pai);
	const vm_offset_t pvh_flags = pvh_get_flags(pvh);

	if (__improbable(!(pvh_flags & lockdown_flag))) {
		panic("%s: unlockdown attempt on not locked down pai %d, type=0x%llx, PVH flags=0x%llx",
		    __func__, pai, (unsigned long long)lockdown_flag, (unsigned long long)pvh_flags);
	}


	pvh_set_flags(pvh, pvh_flags & ~lockdown_flag);

	/* Restore the pre-lockdown physical aperture mapping permissions. */
	const unsigned int old_xprr_perm =
	    (ppl_writable) ? XPRR_PPL_RW_PERM : XPRR_KERN_RO_PERM;
	pmap_set_xprr_perm(pai, old_xprr_perm, XPRR_KERN_RW_PERM);
}

/**
 * Release a page from being locked down to the PPL, making it writable to the
 * kernel once again.
 *
 * @note This must be paired with a pmap_ppl_lockdown_page() call. Any attempts
 *       to unlockdown a page that was never locked down, will panic.
 *
 * @param kva Valid address to any mapping of the physical page to unlockdown.
 * @param lockdown_flag Bit within PVH_FLAG_LOCKDOWN_MASK specifying the lockdown reason
 * @param ppl_writable This must match whatever `ppl_writable` parameter was
 *                     passed to the paired pmap_ppl_lockdown_page() call. Any
 *                     deviation will result in a panic.
 */
MARK_AS_PMAP_TEXT static void
pmap_ppl_unlockdown_page(vm_address_t kva, uint64_t lockdown_flag, bool ppl_writable)
{
	const pmap_paddr_t pa = kvtophys_nofail(kva);
	const unsigned int pai = pa_index(pa);

	assert(lockdown_flag & PVH_FLAG_LOCKDOWN_MASK);
	pvh_lock(pai);
	pmap_ppl_unlockdown_page_locked(pai, lockdown_flag, ppl_writable);
	pvh_unlock(pai);
}

#else /* XNU_MONITOR */

void __unused
pmap_pin_kernel_pages(vm_offset_t kva __unused, size_t nbytes __unused)
{
}

void __unused
pmap_unpin_kernel_pages(vm_offset_t kva __unused, size_t nbytes __unused)
{
}

#endif /* !XNU_MONITOR */


MARK_AS_PMAP_TEXT static inline void
pmap_cs_lockdown_pages(vm_address_t kva, vm_size_t size, bool ppl_writable)
{
#if XNU_MONITOR
	pmap_ppl_lockdown_pages(kva, size, PVH_FLAG_LOCKDOWN_CS, ppl_writable);
#else
	pmap_ppl_lockdown_pages(kva, size, 0, ppl_writable);
#endif
}

MARK_AS_PMAP_TEXT static inline void
pmap_cs_unlockdown_pages(vm_address_t kva, vm_size_t size, bool ppl_writable)
{
#if XNU_MONITOR
	pmap_ppl_unlockdown_pages(kva, size, PVH_FLAG_LOCKDOWN_CS, ppl_writable);
#else
	pmap_ppl_unlockdown_pages(kva, size, 0, ppl_writable);
#endif
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
 * Ensure that physical page is locked down and pinned, before writing to it.
 *
 * @note Should be called before writing to an allocation from the read
 * only allocator. This function pairs with pmap_ro_zone_unlock_phy_page,
 * ensure that it is called after the modification.
 *
 *
 * @param pa Physical address of the element being modified.
 * @param va Virtual address of element being modified.
 * @param size Size of the modification.
 *
 */

MARK_AS_PMAP_TEXT static void
pmap_ro_zone_lock_phy_page(
	const pmap_paddr_t  pa,
	vm_offset_t         va,
	vm_size_t           size)
{
	const unsigned int pai = pa_index(pa);
	pvh_lock(pai);

	/* Ensure that the physical page is locked down */
#if XNU_MONITOR
	pv_entry_t **pvh = pai_to_pvh(pai);
	if (!(pvh_get_flags(pvh) & PVH_FLAG_LOCKDOWN_RO)) {
		panic("%s: Physical page not locked down %llx", __func__, pa);
	}
#endif /* XNU_MONITOR */

	/* Ensure page can't become PPL-owned memory before the memcpy occurs */
	pmap_pin_kernel_pages(va, size);
}

/**
 * Unlock and unpin physical page after writing to it.
 *
 * @note Should be called after writing to an allocation from the read
 * only allocator. This function pairs with pmap_ro_zone_lock_phy_page,
 * ensure that it has been called prior to the modification.
 *
 * @param pa Physical address of the element that was modified.
 * @param va Virtual address of element that was modified.
 * @param size Size of the modification.
 *
 */

MARK_AS_PMAP_TEXT static void
pmap_ro_zone_unlock_phy_page(
	const pmap_paddr_t  pa,
	vm_offset_t         va,
	vm_size_t           size)
{
	const unsigned int pai = pa_index(pa);
	pmap_unpin_kernel_pages(va, size);
	pvh_unlock(pai);
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
#if XNU_MONITOR
	pmap_ro_zone_memcpy_ppl(zid, va, offset, new_data, new_data_size);
#else /* XNU_MONITOR */
	pmap_ro_zone_memcpy_internal(zid, va, offset, new_data, new_data_size);
#endif /* XNU_MONITOR */
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
	pmap_ro_zone_lock_phy_page(pa, va, new_data_size);
	memcpy((void*)phystokv(pa), (void*)new_data, new_data_size);
	pmap_ro_zone_unlock_phy_page(pa, va, new_data_size);
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
#if XNU_MONITOR
	return pmap_ro_zone_atomic_op_ppl(zid, va, offset, op, value);
#else /* XNU_MONITOR */
	return pmap_ro_zone_atomic_op_internal(zid, va, offset, op, value);
#endif /* XNU_MONITOR */
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
	pmap_ro_zone_lock_phy_page(pa, va, value_size);
	value = __zalloc_ro_mut_atomic(phystokv(pa), op, value);
	pmap_ro_zone_unlock_phy_page(pa, va, value_size);

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
#if XNU_MONITOR
	pmap_ro_zone_bzero_ppl(zid, va, offset, size);
#else /* XNU_MONITOR */
	pmap_ro_zone_bzero_internal(zid, va, offset, size);
#endif /* XNU_MONITOR */
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
	pmap_ro_zone_lock_phy_page(pa, va, size);
	bzero((void*)phystokv(pa), size);
	pmap_ro_zone_unlock_phy_page(pa, va, size);
}

/**
 * Removes write access from the Physical Aperture.
 *
 * @note For non-PPL devices, it simply makes all virtual mappings RO.
 * @note Designed to work only with the zone allocator's read-only submap.
 *
 * @param va VA of the page to restore write access to.
 *
 */
MARK_AS_PMAP_TEXT static void
pmap_phys_write_disable(vm_address_t va)
{
#if XNU_MONITOR
	pmap_ppl_lockdown_page(va, PVH_FLAG_LOCKDOWN_RO, true);
#else /* XNU_MONITOR */
	pmap_page_protect(atop_kernel(kvtophys(va)), VM_PROT_READ);
#endif /* XNU_MONITOR */
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
			if (ARM_PTE_IS_COMPRESSED(*bpte, bpte)) {
				compressed_bytes += pt_attr_page_size(pt_attr);
			} else if (pa_valid(pte_to_pa(*bpte))) {
				resident_bytes += pt_attr_page_size(pt_attr);
			}
		}
	}
	pmap_unlock(pmap, PMAP_LOCK_SHARED);

	if (compressed_bytes_p) {
		pmap_pin_kernel_pages((vm_offset_t)compressed_bytes_p, sizeof(*compressed_bytes_p));
		*compressed_bytes_p += compressed_bytes;
		pmap_unpin_kernel_pages((vm_offset_t)compressed_bytes_p, sizeof(*compressed_bytes_p));
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
#if XNU_MONITOR
		resident_bytes = pmap_query_resident_ppl(pmap, va, l, compressed_bytes_p);
#else
		resident_bytes = pmap_query_resident_internal(pmap, va, l, compressed_bytes_p);
#endif
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
#if XNU_MONITOR
	pmap_set_vm_map_cs_enforced_ppl(pmap, new_value);
#else
	pmap_set_vm_map_cs_enforced_internal(pmap, new_value);
#endif
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
	return;
}

void
pmap_set_jit_entitled(
	pmap_t pmap)
{
#if XNU_MONITOR
	pmap_set_jit_entitled_ppl(pmap);
#else
	pmap_set_jit_entitled_internal(pmap);
#endif
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
#if XNU_MONITOR
	pmap_set_tpro_ppl(pmap);
#else /* XNU_MONITOR */
	pmap_set_tpro_internal(pmap);
#endif /* XNU_MONITOR */
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
	pt_entry_t      *pte_p, pte;
	pv_entry_t      **pv_h, *pve_p;

	if (pmap == PMAP_NULL || pmap == kernel_pmap) {
		pmap_pin_kernel_pages((vm_offset_t)disp_p, sizeof(*disp_p));
		*disp_p = 0;
		pmap_unpin_kernel_pages((vm_offset_t)disp_p, sizeof(*disp_p));
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
	pte = *(volatile pt_entry_t*)pte_p;
	pa = pte_to_pa(pte);
	if (pa == 0) {
		if (ARM_PTE_IS_COMPRESSED(pte, pte_p)) {
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
		pvh_lock(pai);
		if (pte != *(volatile pt_entry_t*)pte_p) {
			/* something changed: try again */
			pvh_unlock(pai);
			pmap_query_page_info_retries++;
			goto try_again;
		}
		pv_h = pai_to_pvh(pai);
		pve_p = PV_ENTRY_NULL;
		int pve_ptep_idx = 0;
		if (pvh_test_type(pv_h, PVH_TYPE_PVEP)) {
			pve_p = pvh_pve_list(pv_h);
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
		pvh_unlock(pai);
	}

done:
	pmap_unlock(pmap, PMAP_LOCK_SHARED);
	pmap_pin_kernel_pages((vm_offset_t)disp_p, sizeof(*disp_p));
	*disp_p = disp;
	pmap_unpin_kernel_pages((vm_offset_t)disp_p, sizeof(*disp_p));
	return KERN_SUCCESS;
}

kern_return_t
pmap_query_page_info(
	pmap_t          pmap,
	vm_map_offset_t va,
	int             *disp_p)
{
#if XNU_MONITOR
	return pmap_query_page_info_ppl(pmap, va, disp_p);
#else
	return pmap_query_page_info_internal(pmap, va, disp_p);
#endif
}



static vm_map_size_t
pmap_user_va_size(pmap_t pmap __unused)
{
#if __ARM_MIXED_PAGE_SIZE__
	uint64_t tcr_value = pmap_get_pt_attr(pmap)->pta_tcr_value;
	return 1ULL << (64 - ((tcr_value >> TCR_T0SZ_SHIFT) & TCR_TSZ_MASK));
#else
	return 1ULL << (64 - T0SZ_BOOT);
#endif
}



bool
pmap_in_ppl(void)
{
	// Unsupported
	return false;
}

bool
pmap_has_ppl(void)
{
	// Unsupported
	return false;
}

__attribute__((__noreturn__))
void
pmap_iofilter_protected_write(__unused vm_address_t addr, __unused uint64_t value, __unused uint64_t width)
{
	panic("%s called on an unsupported platform.", __FUNCTION__);
}

void *
pmap_claim_reserved_ppl_page(void)
{
	// Unsupported
	return NULL;
}

void
pmap_free_reserved_ppl_page(void __unused *kva)
{
	// Unsupported
}


#if PMAP_CS_PPL_MONITOR

/* Immutable part of the trust cache runtime */
SECURITY_READ_ONLY_LATE(TrustCacheRuntime_t) ppl_trust_cache_rt;

/* Mutable part of the trust cache runtime */
MARK_AS_PMAP_DATA TrustCacheMutableRuntime_t ppl_trust_cache_mut_rt;

/* Lock for the trust cache runtime */
MARK_AS_PMAP_DATA decl_lck_rw_data(, ppl_trust_cache_rt_lock);

MARK_AS_PMAP_TEXT kern_return_t
pmap_load_trust_cache_with_type_internal(
	TCType_t type,
	const vm_address_t pmap_img4_payload, const vm_size_t pmap_img4_payload_len,
	const vm_address_t img4_manifest, const vm_size_t img4_manifest_len,
	const vm_address_t img4_aux_manifest, const vm_size_t img4_aux_manifest_len)
{
	kern_return_t ret = KERN_DENIED;
	pmap_img4_payload_t *payload = NULL;
	size_t img4_payload_len = 0;
	size_t payload_len_aligned = 0;
	size_t manifest_len_aligned = 0;

	/* Ignore the auxiliary manifest until we add support for it */
	(void)img4_aux_manifest;
	(void)img4_aux_manifest_len;


	/* Image4 interface needs to be available */
	if (img4if == NULL) {
		panic("image4 interface not available");
	}

	/* AMFI interface needs to be available */
	if (amfi == NULL) {
		panic("amfi interface not available");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 1) {
		/* AMFI change hasn't landed in the build */
		pmap_cs_log_error("unable to load trust cache (type: %u): interface not supported", type);
		return KERN_NOT_SUPPORTED;
	}

#if PMAP_CS_INCLUDE_CODE_SIGNING
	if (pmap_cs) {
		if ((type == kTCTypeStatic) || (type == kTCTypeEngineering) || (type == kTCTypeLegacy)) {
			panic("trust cache type not loadable from interface: %u", type);
		} else if (type >= kTCTypeTotal) {
			panic("attempted to load an unsupported trust cache type: %u", type);
		}

		/* Validate entitlement for the calling process */
		if (TCTypeConfig[type].entitlementValue != NULL) {
			const bool entitlement_satisfied = check_entitlement_pmap(
				NULL,
				"com.apple.private.pmap.load-trust-cache",
				TCTypeConfig[type].entitlementValue,
				false,
				true);

			if (entitlement_satisfied == false) {
				panic("attempted to load trust cache without entitlement: %u", type);
			}
		}
	}
#endif

	/* AppleImage4 validation uses CoreCrypto -- requires a spare page */
	ret = pmap_reserve_ppl_page();
	if (ret != KERN_SUCCESS) {
		if (ret != KERN_RESOURCE_SHORTAGE) {
			pmap_cs_log_error("unable to load trust cache (type: %u): unable to reserve page", type);
		}
		return ret;
	}

	/* Align the passed in lengths to the page size -- round_page is overflow safe */
	payload_len_aligned = round_page(pmap_img4_payload_len);
	manifest_len_aligned = round_page(img4_manifest_len);

	/* Ensure we have valid data passed in */
	pmap_cs_assert_addr(pmap_img4_payload, payload_len_aligned, false, false);
	pmap_cs_assert_addr(img4_manifest, manifest_len_aligned, false, false);

	/*
	 * Lockdown the data passed in. The pmap image4 payload also contains the trust cache
	 * data structure used by libTrustCache to manage the payload. We need to be able to
	 * write to that data structure, so we keep the payload PPL writable.
	 */
	pmap_cs_lockdown_pages(pmap_img4_payload, payload_len_aligned, true);
	pmap_cs_lockdown_pages(img4_manifest, manifest_len_aligned, false);

	/* Should be safe to read from this now */
	payload = (pmap_img4_payload_t*)pmap_img4_payload;

	/* Acquire a writable version of the trust cache data structure */
	TrustCache_t *trust_cache = &payload->trust_cache;
	trust_cache = (TrustCache_t*)phystokv(kvtophys_nofail((vm_offset_t)trust_cache));

	/* Calculate the correct length of the img4 payload */
	if (os_sub_overflow(pmap_img4_payload_len, sizeof(pmap_img4_payload_t), &img4_payload_len)) {
		panic("underflow on the img4_payload_len: %lu", pmap_img4_payload_len);
	}

	/* Exclusively lock the runtime */
	lck_rw_lock_exclusive(&ppl_trust_cache_rt_lock);

	/* Load the trust cache */
	TCReturn_t tc_ret = interface->load(
		&ppl_trust_cache_rt,
		type,
		trust_cache,
		(const uintptr_t)payload->img4_payload, img4_payload_len,
		(const uintptr_t)img4_manifest, img4_manifest_len);

	/* Unlock the runtime */
	lck_rw_unlock_exclusive(&ppl_trust_cache_rt_lock);

	if (tc_ret.error == kTCReturnSuccess) {
		ret = KERN_SUCCESS;
	} else {
		if (tc_ret.error == kTCReturnDuplicate) {
			ret = KERN_ALREADY_IN_SET;
		} else {
			pmap_cs_log_error("unable to load trust cache (TCReturn: 0x%02X | 0x%02X | %u)",
			    tc_ret.component, tc_ret.error, tc_ret.uniqueError);

			ret = KERN_FAILURE;
		}

		/* Unlock the payload data */
		pmap_cs_unlockdown_pages(pmap_img4_payload, payload_len_aligned, true);
		trust_cache = NULL;
		payload = NULL;
	}

	/* Unlock the manifest since it is no longer needed */
	pmap_cs_unlockdown_pages(img4_manifest, manifest_len_aligned, false);

	/* Return the CoreCrypto reserved page back to the free list */
	pmap_release_reserved_ppl_page();

	return ret;
}

kern_return_t
pmap_load_trust_cache_with_type(
	TCType_t type,
	const vm_address_t pmap_img4_payload, const vm_size_t pmap_img4_payload_len,
	const vm_address_t img4_manifest, const vm_size_t img4_manifest_len,
	const vm_address_t img4_aux_manifest, const vm_size_t img4_aux_manifest_len)
{
	kern_return_t ret = KERN_DENIED;

	ret = pmap_load_trust_cache_with_type_ppl(
		type,
		pmap_img4_payload, pmap_img4_payload_len,
		img4_manifest, img4_manifest_len,
		img4_aux_manifest, img4_aux_manifest_len);

	while (ret == KERN_RESOURCE_SHORTAGE) {
		/* Allocate a page from the free list */
		pmap_alloc_page_for_ppl(0);

		/* Attempt the call again */
		ret = pmap_load_trust_cache_with_type_ppl(
			type,
			pmap_img4_payload, pmap_img4_payload_len,
			img4_manifest, img4_manifest_len,
			img4_aux_manifest, img4_aux_manifest_len);
	}

	return ret;
}

MARK_AS_PMAP_TEXT kern_return_t
pmap_query_trust_cache_safe(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token)
{
	kern_return_t ret = KERN_NOT_FOUND;

	/* AMFI interface needs to be available */
	if (amfi == NULL) {
		panic("amfi interface not available");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 1) {
		/* AMFI change hasn't landed in the build */
		pmap_cs_log_error("unable to query trust cache: interface not supported");
		return KERN_NOT_SUPPORTED;
	}

	/* Validate the query type preemptively */
	if (query_type >= kTCQueryTypeTotal) {
		pmap_cs_log_error("unable to query trust cache: invalid query type: %u", query_type);
		return KERN_INVALID_ARGUMENT;
	}

	/* Lock the runtime as shared */
	lck_rw_lock_shared(&ppl_trust_cache_rt_lock);

	TCReturn_t tc_ret = interface->query(
		&ppl_trust_cache_rt,
		query_type,
		cdhash,
		query_token);

	/* Unlock the runtime */
	lck_rw_unlock_shared(&ppl_trust_cache_rt_lock);

	if (tc_ret.error == kTCReturnSuccess) {
		ret = KERN_SUCCESS;
	} else if (tc_ret.error == kTCReturnNotFound) {
		ret = KERN_NOT_FOUND;
	} else {
		ret = KERN_FAILURE;
		pmap_cs_log_error("trust cache query failed (TCReturn: 0x%02X | 0x%02X | %u)",
		    tc_ret.component, tc_ret.error, tc_ret.uniqueError);
	}

	return ret;
}

MARK_AS_PMAP_TEXT kern_return_t
pmap_query_trust_cache_internal(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token)
{
	kern_return_t ret = KERN_NOT_FOUND;
	TrustCacheQueryToken_t query_token_safe = {0};
	uint8_t cdhash_safe[kTCEntryHashSize] = {0};

	/* Copy in the CDHash into PPL storage */
	memcpy(cdhash_safe, cdhash, kTCEntryHashSize);

	/* Query through the safe API since we're in the PPL now */
	ret = pmap_query_trust_cache_safe(query_type, cdhash_safe, &query_token_safe);

	if (query_token != NULL) {
		pmap_pin_kernel_pages((vm_offset_t)query_token, sizeof(*query_token));
		memcpy((void*)query_token, (void*)&query_token_safe, sizeof(*query_token));
		pmap_unpin_kernel_pages((vm_offset_t)query_token, sizeof(*query_token));
	}

	return ret;
}

kern_return_t
pmap_query_trust_cache(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token)
{
	kern_return_t ret = KERN_NOT_FOUND;

	ret = pmap_query_trust_cache_ppl(
		query_type,
		cdhash,
		query_token);

	return ret;
}

MARK_AS_PMAP_DATA bool ppl_developer_mode_set =  false;
MARK_AS_PMAP_DATA bool ppl_developer_mode_storage = false;

MARK_AS_PMAP_TEXT void
pmap_toggle_developer_mode_internal(
	bool state)
{
	bool state_set = os_atomic_load(&ppl_developer_mode_set, relaxed);

	/*
	 * Only the following state transitions are allowed:
	 * -- not set --> false
	 * -- not set --> true
	 * -- true --> false
	 * -- true --> true
	 * -- false --> false
	 *
	 * We never allow false --> true transitions.
	 */
	bool current = os_atomic_load(&ppl_developer_mode_storage, relaxed);

	if ((current == false) && (state == true) && state_set) {
		panic("PMAP_CS: attempted to enable developer mode incorrectly");
	}

	/* We're going to update the developer mode state, so update this first */
	os_atomic_store(&ppl_developer_mode_set, true, relaxed);

	/* Update the developer mode state on the system */
	os_atomic_store(&ppl_developer_mode_storage, state, release);
}

void
pmap_toggle_developer_mode(
	bool state)
{
	pmap_toggle_developer_mode_ppl(state);
}

#endif /* PMAP_CS_PPL_MONITOR */

#if PMAP_CS_INCLUDE_CODE_SIGNING

static int
pmap_cs_profiles_rbtree_compare(
	void *profile0,
	void *profile1)
{
	if (profile0 < profile1) {
		return -1;
	} else if (profile0 > profile1) {
		return 1;
	}
	return 0;
}

/* Red-black tree for managing provisioning profiles */
MARK_AS_PMAP_DATA static
RB_HEAD(pmap_cs_profiles_rbtree, _pmap_cs_profile) pmap_cs_registered_profiles;

RB_PROTOTYPE(pmap_cs_profiles_rbtree, _pmap_cs_profile, link, pmap_cs_profiles_rbtree_compare);
RB_GENERATE(pmap_cs_profiles_rbtree, _pmap_cs_profile, link, pmap_cs_profiles_rbtree_compare);

/* Lock for the profile red-black tree */
MARK_AS_PMAP_DATA decl_lck_rw_data(, pmap_cs_profiles_rbtree_lock);

void
pmap_initialize_provisioning_profiles(void)
{
	/* Initialize the profiles red-black tree lock */
	lck_rw_init(&pmap_cs_profiles_rbtree_lock, &pmap_lck_grp, 0);
	pmap_cs_profiles_rbtree_lock.lck_rw_can_sleep = FALSE;

	/* Initialize the red-black tree itself */
	RB_INIT(&pmap_cs_registered_profiles);

	printf("initialized PPL provisioning profile data\n");
}

static bool
pmap_is_testflight_profile(
	pmap_cs_profile_t *profile_obj)
{
	const char *entitlement_name = "beta-reports-active";
	const size_t entitlement_length = strlen(entitlement_name);
	CEQueryOperation_t query[2] = {0};

	/* If the profile provisions no entitlements, then it isn't a test flight one */
	if (profile_obj->entitlements_ctx == NULL) {
		return false;
	}

	/* Build our CoreEntitlements query */
	query[0].opcode = kCEOpSelectKey;
	memcpy(query[0].parameters.stringParameter.data, entitlement_name, entitlement_length);
	query[0].parameters.stringParameter.length = entitlement_length;
	query[1] = CEMatchBool(true);

	CEError_t ce_err = amfi->CoreEntitlements.ContextQuery(
		profile_obj->entitlements_ctx,
		query, 2);

	if (ce_err == amfi->CoreEntitlements.kNoError) {
		return true;
	}

	return false;
}

static bool
pmap_is_development_profile(
	pmap_cs_profile_t *profile_obj)
{
	/* Check for UPP */
	const der_vm_context_t upp_ctx = amfi->CoreEntitlements.der_vm_execute(
		*profile_obj->profile_ctx,
		CESelectDictValue("ProvisionsAllDevices"));
	if (amfi->CoreEntitlements.der_vm_context_is_valid(upp_ctx) == true) {
		if (amfi->CoreEntitlements.der_vm_bool_from_context(upp_ctx) == true) {
			pmap_cs_log_info("%p: [UPP] non-development profile", profile_obj);
			return false;
		}
	}

	/* Check for TestFlight profile */
	if (pmap_is_testflight_profile(profile_obj) == true) {
		pmap_cs_log_info("%p: [TestFlight] non-development profile", profile_obj);
		return false;
	}

	pmap_cs_log_info("%p: development profile", profile_obj);
	return true;
}

static kern_return_t
pmap_initialize_profile_entitlements(
	pmap_cs_profile_t *profile_obj)
{
	const der_vm_context_t entitlements_der_ctx = amfi->CoreEntitlements.der_vm_execute(
		*profile_obj->profile_ctx,
		CESelectDictValue("Entitlements"));

	if (amfi->CoreEntitlements.der_vm_context_is_valid(entitlements_der_ctx) == false) {
		memset(&profile_obj->entitlements_ctx_storage, 0, sizeof(struct CEQueryContext));
		profile_obj->entitlements_ctx = NULL;

		pmap_cs_log_info("%p: profile provisions no entitlements", profile_obj);
		return KERN_NOT_FOUND;
	}

	const uint8_t *der_start = entitlements_der_ctx.state.der_start;
	const uint8_t *der_end = entitlements_der_ctx.state.der_end;

	CEValidationResult ce_result = {0};
	CEError_t ce_err = amfi->CoreEntitlements.Validate(
		pmap_cs_core_entitlements_runtime,
		&ce_result,
		der_start, der_end);
	if (ce_err != amfi->CoreEntitlements.kNoError) {
		pmap_cs_log_error("unable to validate profile entitlements: %s",
		    amfi->CoreEntitlements.GetErrorString(ce_err));

		return KERN_ABORTED;
	}

	struct CEQueryContext query_ctx = {0};
	ce_err = amfi->CoreEntitlements.AcquireUnmanagedContext(
		pmap_cs_core_entitlements_runtime,
		ce_result,
		&query_ctx);
	if (ce_err != amfi->CoreEntitlements.kNoError) {
		pmap_cs_log_error("unable to acquire context for profile entitlements: %s",
		    amfi->CoreEntitlements.GetErrorString(ce_err));

		return KERN_ABORTED;
	}

	/* Setup the entitlements context within the profile object */
	profile_obj->entitlements_ctx_storage = query_ctx;
	profile_obj->entitlements_ctx = &profile_obj->entitlements_ctx_storage;

	pmap_cs_log_info("%p: profile entitlements successfully setup", profile_obj);
	return KERN_SUCCESS;
}

kern_return_t
pmap_register_provisioning_profile_internal(
	const vm_address_t payload_addr,
	const vm_size_t payload_size)
{
	kern_return_t ret = KERN_DENIED;
	pmap_cs_profile_t *profile_obj = NULL;
	pmap_profile_payload_t *profile_payload = NULL;
	vm_size_t max_profile_blob_size = 0;
	const uint8_t *profile_content = NULL;
	size_t profile_content_length = 0;


	/* CoreTrust validation uses CoreCrypto -- requires a spare page */
	ret = pmap_reserve_ppl_page();
	if (ret != KERN_SUCCESS) {
		if (ret != KERN_RESOURCE_SHORTAGE) {
			pmap_cs_log_error("unable to register profile: unable to reserve page: %d", ret);
		}
		return ret;
	}

	/* Ensure we have valid data passed in */
	pmap_cs_assert_addr(payload_addr, payload_size, false, false);

	/*
	 * Lockdown the data passed in. The pmap profile payload also contains the profile
	 * data structure used by the PPL to manage the payload. We need to be able to write
	 * to that data structure, so we keep the payload PPL writable.
	 */
	pmap_cs_lockdown_pages(payload_addr, payload_size, true);

	/* Should be safe to read from this now */
	profile_payload = (pmap_profile_payload_t*)payload_addr;

	/* Ensure the profile blob size provided is valid */
	if (os_sub_overflow(payload_size, sizeof(*profile_payload), &max_profile_blob_size)) {
		panic("PMAP_CS: underflow on the max_profile_blob_size: %lu", payload_size);
	} else if (profile_payload->profile_blob_size > max_profile_blob_size) {
		panic("PMAP_CS: overflow on the profile_blob_size: %lu", profile_payload->profile_blob_size);
	}

#if PMAP_CS_INCLUDE_INTERNAL_CODE
	const bool allow_development_root_cert = true;
#else
	const bool allow_development_root_cert = false;
#endif

	int ct_result = coretrust->CTEvaluateProvisioningProfile(
		profile_payload->profile_blob, profile_payload->profile_blob_size,
		allow_development_root_cert,
		&profile_content, &profile_content_length);

	/* Release the PPL page allocated for CoreCrypto */
	pmap_release_reserved_ppl_page();

	if (ct_result != 0) {
		panic("PMAP_CS: profile does not validate through CoreTrust: %d", ct_result);
	} else if ((profile_content == NULL) || profile_content_length == 0) {
		panic("PMAP_CS: profile does not have any content: %p | %lu",
		    profile_content, profile_content_length);
	}

	der_vm_context_t profile_ctx_storage = amfi->CoreEntitlements.der_vm_context_create(
		pmap_cs_core_entitlements_runtime,
		CCDER_CONSTRUCTED_SET,
		false,
		profile_content, profile_content + profile_content_length);
	if (amfi->CoreEntitlements.der_vm_context_is_valid(profile_ctx_storage) == false) {
		panic("PMAP_CS: unable to create a CoreEntitlements context for the profile");
	}

	/* Acquire a writable version of the profile data structure */
	profile_obj = &profile_payload->profile_obj_storage;
	profile_obj = (pmap_cs_profile_t*)phystokv(kvtophys_nofail((vm_offset_t)profile_obj));

	profile_obj->original_payload = profile_payload;
	profile_obj->profile_ctx_storage = profile_ctx_storage;
	profile_obj->profile_ctx = &profile_obj->profile_ctx_storage;
	os_atomic_store(&profile_obj->reference_count, 0, release);

	/* Setup the entitlements provisioned by the profile */
	ret = pmap_initialize_profile_entitlements(profile_obj);
	if ((ret != KERN_SUCCESS) && (ret != KERN_NOT_FOUND)) {
		panic("PMAP_CS: fatal error while setting up profile entitlements: %d", ret);
	}

	/* Setup properties of the profile */
	profile_obj->development_profile = pmap_is_development_profile(profile_obj);

	/* Mark as validated since it passed all checks */
	profile_obj->profile_validated = true;

	/* Add the profile to the red-black tree */
	lck_rw_lock_exclusive(&pmap_cs_profiles_rbtree_lock);
	if (RB_INSERT(pmap_cs_profiles_rbtree, &pmap_cs_registered_profiles, profile_obj) != NULL) {
		panic("PMAP_CS: Anomaly, profile already exists in the tree: %p", profile_obj);
	}
	lck_rw_unlock_exclusive(&pmap_cs_profiles_rbtree_lock);

	pmap_cs_log_info("%p: profile successfully registered", profile_obj);
	return KERN_SUCCESS;
}

kern_return_t
pmap_register_provisioning_profile(
	const vm_address_t payload_addr,
	const vm_size_t payload_size)
{
	kern_return_t ret = KERN_DENIED;

	ret = pmap_register_provisioning_profile_ppl(
		payload_addr,
		payload_size);

	while (ret == KERN_RESOURCE_SHORTAGE) {
		/* Allocate a page from the free list */
		pmap_alloc_page_for_ppl(0);

		/* Attempt the call again */
		ret = pmap_register_provisioning_profile_ppl(
			payload_addr,
			payload_size);
	}

	return ret;
}

kern_return_t
pmap_unregister_provisioning_profile_internal(
	pmap_cs_profile_t *profile_obj)
{
	kern_return_t ret = KERN_DENIED;

	/* Lock the red-black tree exclusively */
	lck_rw_lock_exclusive(&pmap_cs_profiles_rbtree_lock);

	if (RB_FIND(pmap_cs_profiles_rbtree, &pmap_cs_registered_profiles, profile_obj) == NULL) {
		panic("PMAP_CS: unregistering an unknown profile: %p", profile_obj);
	}

	uint32_t reference_count = os_atomic_load(&profile_obj->reference_count, acquire);
	if (reference_count != 0) {
		ret = KERN_FAILURE;
		goto exit;
	}

	/* Remove the profile from the red-black tree */
	RB_REMOVE(pmap_cs_profiles_rbtree, &pmap_cs_registered_profiles, profile_obj);

	/* Unregistration was a success */
	ret = KERN_SUCCESS;

exit:
	/* Unlock the red-black tree */
	lck_rw_unlock_exclusive(&pmap_cs_profiles_rbtree_lock);

	if (ret == KERN_SUCCESS) {
		/* Get the original payload address */
		const pmap_profile_payload_t *profile_payload = profile_obj->original_payload;
		const vm_address_t payload_addr = (const vm_address_t)profile_payload;

		/* Get the original payload size */
		vm_size_t payload_size = profile_payload->profile_blob_size + sizeof(*profile_payload);
		payload_size = round_page(payload_size);

		/* Unlock the profile payload */
		pmap_cs_unlockdown_pages(payload_addr, payload_size, true);
		pmap_cs_log_info("%p: profile successfully unregistered: %p | %lu", profile_obj,
		    profile_payload, payload_size);

		profile_obj = NULL;
	}
	return ret;
}

kern_return_t
pmap_unregister_provisioning_profile(
	pmap_cs_profile_t *profile_obj)
{
	return pmap_unregister_provisioning_profile_ppl(profile_obj);
}

kern_return_t
pmap_associate_provisioning_profile_internal(
	pmap_cs_code_directory_t *cd_entry,
	pmap_cs_profile_t *profile_obj)
{
	kern_return_t ret = KERN_DENIED;

	/* Acquire the lock on the code directory */
	pmap_cs_lock_code_directory(cd_entry);

	if (cd_entry->trust != PMAP_CS_UNTRUSTED) {
		pmap_cs_log_error("disallowing profile association with verified signature");
		goto exit;
	} else if (cd_entry->profile_obj != NULL) {
		pmap_cs_log_error("disallowing multiple profile associations with signature");
		goto exit;
	}

	/* Lock the red-black tree as shared */
	lck_rw_lock_shared(&pmap_cs_profiles_rbtree_lock);

	if (RB_FIND(pmap_cs_profiles_rbtree, &pmap_cs_registered_profiles, profile_obj) == NULL) {
		panic("PMAP_CS: associating an unknown profile: %p", profile_obj);
	} else if (profile_obj->profile_validated == false) {
		panic("PMAP_CS: attempted association with unverified profile: %p", profile_obj);
	}

	/* Associate the profile with the signature */
	cd_entry->profile_obj = profile_obj;

	/* Increment the reference count on the profile object */
	uint32_t reference_count = os_atomic_add(&profile_obj->reference_count, 1, relaxed);
	if (reference_count == 0) {
		panic("PMAP_CS: overflow on reference count for profile: %p", profile_obj);
	}

	/* Unlock the red-black tree */
	lck_rw_unlock_shared(&pmap_cs_profiles_rbtree_lock);

	/* Association was a success */
	pmap_cs_log_info("associated profile %p with signature %p", profile_obj, cd_entry);
	ret = KERN_SUCCESS;

exit:
	lck_rw_unlock_exclusive(&cd_entry->rwlock);

	return ret;
}

kern_return_t
pmap_associate_provisioning_profile(
	pmap_cs_code_directory_t *cd_entry,
	pmap_cs_profile_t *profile_obj)
{
	return pmap_associate_provisioning_profile_ppl(cd_entry, profile_obj);
}

kern_return_t
pmap_disassociate_provisioning_profile_internal(
	pmap_cs_code_directory_t *cd_entry)
{
	pmap_cs_profile_t *profile_obj = NULL;
	kern_return_t ret = KERN_DENIED;

	/* Acquire the lock on the code directory */
	pmap_cs_lock_code_directory(cd_entry);

	if (cd_entry->trust == PMAP_CS_UNTRUSTED) {
		panic("PMAP_CS: profile disassociation not allowed on unverified signatures");
	}

	if (cd_entry->profile_obj == NULL) {
		ret = KERN_NOT_FOUND;
		goto exit;
	}
	profile_obj = cd_entry->profile_obj;

	/* Disassociate the profile from the signature */
	cd_entry->profile_obj = NULL;

	/* Disassociation was a success */
	ret = KERN_SUCCESS;

exit:
	lck_rw_unlock_exclusive(&cd_entry->rwlock);

	if (ret == KERN_SUCCESS) {
		/* Decrement the reference count on the profile object */
		uint32_t reference_count = os_atomic_sub(&profile_obj->reference_count, 1, release);
		if (reference_count == UINT32_MAX) {
			panic("PMAP_CS: underflow on reference count for profile: %p", profile_obj);
		}
		pmap_cs_log_info("disassociated profile %p from signature %p", profile_obj, cd_entry);
	}
	return ret;
}

kern_return_t
pmap_disassociate_provisioning_profile(
	pmap_cs_code_directory_t *cd_entry)
{
	return pmap_disassociate_provisioning_profile_ppl(cd_entry);
}

#endif /* PMAP_CS_INCLUDE_CODE_SIGNING */

MARK_AS_PMAP_TEXT bool
pmap_lookup_in_loaded_trust_caches_internal(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	kern_return_t kr = KERN_NOT_FOUND;

#if PMAP_CS_PPL_MONITOR
	/*
	 * If we have the PPL monitor, then this function can only be called from
	 * within the PPL. Calling it directly would've caused a panic, so we can
	 * assume that we're in the PPL here.
	 */
	uint8_t cdhash_safe[CS_CDHASH_LEN];
	memcpy(cdhash_safe, cdhash, CS_CDHASH_LEN);

	kr = pmap_query_trust_cache_safe(
		kTCQueryTypeLoadable,
		cdhash_safe,
		NULL);
#else
	kr = query_trust_cache(
		kTCQueryTypeLoadable,
		cdhash,
		NULL);
#endif

	if (kr == KERN_SUCCESS) {
		return true;
	}
	return false;
}

bool
pmap_lookup_in_loaded_trust_caches(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
#if XNU_MONITOR
	return pmap_lookup_in_loaded_trust_caches_ppl(cdhash);
#else
	return pmap_lookup_in_loaded_trust_caches_internal(cdhash);
#endif
}

MARK_AS_PMAP_TEXT uint32_t
pmap_lookup_in_static_trust_cache_internal(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	TrustCacheQueryToken_t query_token = {0};
	kern_return_t kr = KERN_NOT_FOUND;
	uint64_t flags = 0;
	uint8_t hash_type = 0;

#if PMAP_CS_PPL_MONITOR
	/*
	 * If we have the PPL monitor, then this function can only be called from
	 * within the PPL. Calling it directly would've caused a panic, so we can
	 * assume that we're in the PPL here.
	 */
	uint8_t cdhash_safe[CS_CDHASH_LEN];
	memcpy(cdhash_safe, cdhash, CS_CDHASH_LEN);

	kr = pmap_query_trust_cache_safe(
		kTCQueryTypeStatic,
		cdhash_safe,
		&query_token);
#else
	kr = query_trust_cache(
		kTCQueryTypeStatic,
		cdhash,
		&query_token);
#endif

	if (kr == KERN_SUCCESS) {
		amfi->TrustCache.queryGetFlags(&query_token, &flags);
		amfi->TrustCache.queryGetHashType(&query_token, &hash_type);

		return (TC_LOOKUP_FOUND << TC_LOOKUP_RESULT_SHIFT) |
		       (hash_type << TC_LOOKUP_HASH_TYPE_SHIFT) |
		       ((uint8_t)flags << TC_LOOKUP_FLAGS_SHIFT);
	}

	return 0;
}

uint32_t
pmap_lookup_in_static_trust_cache(const uint8_t cdhash[CS_CDHASH_LEN])
{
#if XNU_MONITOR
	return pmap_lookup_in_static_trust_cache_ppl(cdhash);
#else
	return pmap_lookup_in_static_trust_cache_internal(cdhash);
#endif
}

MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmap_compilation_service_cdhash_lock, 0);
MARK_AS_PMAP_DATA uint8_t pmap_compilation_service_cdhash[CS_CDHASH_LEN] = { 0 };

MARK_AS_PMAP_TEXT void
pmap_set_compilation_service_cdhash_internal(const uint8_t cdhash[CS_CDHASH_LEN])
{

	pmap_simple_lock(&pmap_compilation_service_cdhash_lock);
	memcpy(pmap_compilation_service_cdhash, cdhash, CS_CDHASH_LEN);
	pmap_simple_unlock(&pmap_compilation_service_cdhash_lock);

	pmap_cs_log_info("Added Compilation Service CDHash through the PPL: 0x%02X 0x%02X 0x%02X 0x%02X", cdhash[0], cdhash[1], cdhash[2], cdhash[4]);
}

MARK_AS_PMAP_TEXT bool
pmap_match_compilation_service_cdhash_internal(const uint8_t cdhash[CS_CDHASH_LEN])
{
	bool match = false;

	pmap_simple_lock(&pmap_compilation_service_cdhash_lock);
	if (bcmp(pmap_compilation_service_cdhash, cdhash, CS_CDHASH_LEN) == 0) {
		match = true;
	}
	pmap_simple_unlock(&pmap_compilation_service_cdhash_lock);

	if (match) {
		pmap_cs_log_info("Matched Compilation Service CDHash through the PPL");
	}

	return match;
}

void
pmap_set_compilation_service_cdhash(const uint8_t cdhash[CS_CDHASH_LEN])
{
#if XNU_MONITOR
	pmap_set_compilation_service_cdhash_ppl(cdhash);
#else
	pmap_set_compilation_service_cdhash_internal(cdhash);
#endif
}

bool
pmap_match_compilation_service_cdhash(const uint8_t cdhash[CS_CDHASH_LEN])
{
#if XNU_MONITOR
	return pmap_match_compilation_service_cdhash_ppl(cdhash);
#else
	return pmap_match_compilation_service_cdhash_internal(cdhash);
#endif
}

/*
 * As part of supporting local signing on the device, we need the PMAP layer
 * to store the local signing key so that PMAP_CS can validate with it. We
 * store it at the PMAP layer such that it is accessible to both AMFI and
 * PMAP_CS should they need it.
 */
MARK_AS_PMAP_DATA static bool pmap_local_signing_public_key_set = false;
MARK_AS_PMAP_DATA static uint8_t pmap_local_signing_public_key[PMAP_ECC_P384_PUBLIC_KEY_SIZE] = { 0 };

MARK_AS_PMAP_TEXT void
pmap_set_local_signing_public_key_internal(const uint8_t public_key[PMAP_ECC_P384_PUBLIC_KEY_SIZE])
{
	bool key_set = false;

	/*
	 * os_atomic_cmpxchg returns true in case the exchange was successful. For us,
	 * a successful exchange means that the local signing public key has _not_ been
	 * set. In case the key has been set, we panic as we would never expect the
	 * kernel to attempt to set the key more than once.
	 */
	key_set = !os_atomic_cmpxchg(&pmap_local_signing_public_key_set, false, true, relaxed);

	if (key_set) {
		panic("attempted to set the local signing public key multiple times");
	}

	memcpy(pmap_local_signing_public_key, public_key, PMAP_ECC_P384_PUBLIC_KEY_SIZE);
	pmap_cs_log_info("set local signing public key");
}

void
pmap_set_local_signing_public_key(const uint8_t public_key[PMAP_ECC_P384_PUBLIC_KEY_SIZE])
{
#if XNU_MONITOR
	return pmap_set_local_signing_public_key_ppl(public_key);
#else
	return pmap_set_local_signing_public_key_internal(public_key);
#endif
}

uint8_t*
pmap_get_local_signing_public_key(void)
{
	bool key_set = os_atomic_load(&pmap_local_signing_public_key_set, relaxed);

	if (key_set) {
		return pmap_local_signing_public_key;
	}

	return NULL;
}

/*
 * Locally signed applications need to be explicitly authorized by an entitled application
 * before we allow them to run.
 */
MARK_AS_PMAP_DATA static uint8_t pmap_local_signing_cdhash[CS_CDHASH_LEN] = {0};
MARK_AS_PMAP_DATA SIMPLE_LOCK_DECLARE(pmap_local_signing_cdhash_lock, 0);

MARK_AS_PMAP_TEXT void
pmap_unrestrict_local_signing_internal(
	const uint8_t cdhash[CS_CDHASH_LEN])
{

	pmap_simple_lock(&pmap_local_signing_cdhash_lock);
	memcpy(pmap_local_signing_cdhash, cdhash, sizeof(pmap_local_signing_cdhash));
	pmap_simple_unlock(&pmap_local_signing_cdhash_lock);

	pmap_cs_log_debug("unrestricted local signing for CDHash: 0x%02X%02X%02X%02X%02X...",
	    cdhash[0], cdhash[1], cdhash[2], cdhash[3], cdhash[4]);
}

void
pmap_unrestrict_local_signing(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
#if XNU_MONITOR
	return pmap_unrestrict_local_signing_ppl(cdhash);
#else
	return pmap_unrestrict_local_signing_internal(cdhash);
#endif
}

#if PMAP_CS
MARK_AS_PMAP_TEXT static void
pmap_restrict_local_signing(void)
{
	pmap_simple_lock(&pmap_local_signing_cdhash_lock);
	memset(pmap_local_signing_cdhash, 0, sizeof(pmap_local_signing_cdhash));
	pmap_simple_unlock(&pmap_local_signing_cdhash_lock);
}

MARK_AS_PMAP_TEXT static bool
pmap_local_signing_restricted(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	pmap_simple_lock(&pmap_local_signing_cdhash_lock);
	int ret = memcmp(pmap_local_signing_cdhash, cdhash, sizeof(pmap_local_signing_cdhash));
	pmap_simple_unlock(&pmap_local_signing_cdhash_lock);

	return ret != 0;
}

MARK_AS_PMAP_TEXT bool
pmap_cs_query_entitlements_internal(
	pmap_t pmap,
	CEQuery_t query,
	size_t queryLength,
	CEQueryContext_t finalContext)
{
	struct pmap_cs_code_directory *cd_entry = NULL;
	bool ret = false;

	if (!pmap_cs) {
		panic("PMAP_CS: cannot query for entitlements as pmap_cs is turned off");
	}

	/*
	 * When a pmap has not been passed in, we assume the caller wants to check the
	 * entitlements on the current user space process.
	 */
	if (pmap == NULL) {
		pmap = current_pmap();
	}

	if (pmap == kernel_pmap) {
		/*
		 * Instead of panicking we will just return false.
		 */
		return false;
	}

	if (query == NULL || queryLength > 64) {
		panic("PMAP_CS: bogus entitlements query");
	} else {
		pmap_cs_assert_addr((vm_address_t)query, sizeof(CEQueryOperation_t) * queryLength, false, true);
	}

	if (finalContext != NULL) {
		pmap_cs_assert_addr((vm_address_t)finalContext, sizeof(*finalContext), false, false);
	}

	validate_pmap(pmap);
	pmap_lock(pmap, PMAP_LOCK_SHARED);

	cd_entry = pmap_cs_code_directory_from_region(pmap->pmap_cs_main);
	if (cd_entry == NULL) {
		pmap_cs_log_error("attempted to query entitlements from an invalid pmap or a retired code directory");
		goto out;
	}

	if (cd_entry->ce_ctx == NULL) {
		pmap_cs_log_debug("%s: code signature doesn't have any entitlements", cd_entry->identifier);
		goto out;
	}

	der_vm_context_t executionContext = cd_entry->ce_ctx->der_context;

	for (size_t op = 0; op < queryLength; op++) {
		executionContext = amfi->CoreEntitlements.der_vm_execute(executionContext, query[op]);
	}

	if (amfi->CoreEntitlements.der_vm_context_is_valid(executionContext)) {
		ret = true;
		if (finalContext != NULL) {
			pmap_pin_kernel_pages((vm_offset_t)finalContext, sizeof(*finalContext));
			finalContext->der_context = executionContext;
			pmap_unpin_kernel_pages((vm_offset_t)finalContext, sizeof(*finalContext));
		}
	} else {
		ret = false;
	}

out:
	if (cd_entry) {
		lck_rw_unlock_shared(&cd_entry->rwlock);
		cd_entry = NULL;
	}
	pmap_unlock(pmap, PMAP_LOCK_SHARED);

	return ret;
}
#endif

bool
pmap_query_entitlements(
	__unused pmap_t pmap,
	__unused CEQuery_t query,
	__unused size_t queryLength,
	__unused CEQueryContext_t finalContext)
{
#if !PMAP_SUPPORTS_ENTITLEMENT_CHECKS
	panic("PMAP_CS: do not use this API without checking for \'#if PMAP_SUPPORTS_ENTITLEMENT_CHECKS\'");
#else

#if XNU_MONITOR
	return pmap_cs_query_entitlements_ppl(pmap, query, queryLength, finalContext);
#else
	return pmap_cs_query_entitlements_internal(pmap, query, queryLength, finalContext);
#endif

#endif /* !PMAP_SUPPORTS_ENTITLEMENT_CHECKS */
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
#if XNU_MONITOR
	pmap_footprint_suspend_ppl(map, suspend);
#else
	pmap_footprint_suspend_internal(map, suspend);
#endif
}

MARK_AS_PMAP_TEXT void
pmap_nop_internal(pmap_t pmap __unused)
{
	validate_pmap_mutable(pmap);
}

void
pmap_nop(pmap_t pmap)
{
#if XNU_MONITOR
	pmap_nop_ppl(pmap);
#else
	pmap_nop_internal(pmap);
#endif
}

#if defined(__arm64__) && (DEVELOPMENT || DEBUG)

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
		num_entries = pmap_root_alloc_size(pmap) / sizeof(tt_entry_t);
	}

	uint64_t tt_size = num_entries * sizeof(tt_entry_t);
	const tt_entry_t *tt_end = &ttp[num_entries];

	if (((vm_offset_t)buf_end - (vm_offset_t)bufp) < (tt_size + sizeof(struct page_table_dump_header))) {
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}

	if (level_mask & (1U << cur_level)) {
		struct page_table_dump_header *header = (struct page_table_dump_header*)bufp;
		header->pa = ml_static_vtop((vm_offset_t)ttp);
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

#else /* defined(__arm64__) && (DEVELOPMENT || DEBUG) */

kern_return_t
pmap_dump_page_tables(pmap_t pmap __unused, void *bufp __unused, void *buf_end __unused,
    unsigned int level_mask __unused, size_t *bytes_copied __unused)
{
	return KERN_NOT_SUPPORTED;
}
#endif /* defined(__arm64__) && (DEVELOPMENT || DEBUG) */


#ifdef CONFIG_XNUPOST
#ifdef __arm64__
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
	pmap_enter_addr(pmap, wired_va_base, wired_pa, VM_PROT_READ, VM_PROT_READ, 0, true);

#if XNU_MONITOR
	/*
	 * If the PPL is enabled, make sure that the kernel cannot write
	 * to PPL memory.
	 */
	if (!pmap_ppl_disable) {
		T_LOG("Validate that kernel cannot write to PPL memory.");
		pt_entry_t * ptep = pmap_pte(pmap, va_base);
		pmap_test_write(NULL, (vm_map_address_t)ptep, true);
	}
#endif

	/*
	 * Create read-only mappings of the nonwired page; if the pmap does
	 * not use the same page size as the kernel, create multiple mappings
	 * so that the kernel page is fully mapped.
	 */
	for (map_count = 0; map_count < page_ratio; map_count++) {
		pmap_enter_addr(pmap, va_base + (pmap_page_size * map_count), pa + (pmap_page_size * (map_count)), VM_PROT_READ, VM_PROT_READ, 0, false);
	}

	/* Validate that all the PTEs have the expected PA and VA. */
	for (map_count = 0; map_count < page_ratio; map_count++) {
		pt_entry_t * ptep = pmap_pte(pmap, va_base + (pmap_page_size * map_count));

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
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false);

	T_LOG("Validate that writes to our mapping do not fault.");
	pmap_test_write(pmap, va_base, false);


	T_LOG("Make the first mapping execute-only");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_EXECUTE, VM_PROT_EXECUTE, 0, false);


	T_LOG("Validate that reads to our mapping do not fault.");
	pmap_test_read(pmap, va_base, false);

	T_LOG("Validate that writes to our mapping fault.");
	pmap_test_write(pmap, va_base, true);


	/*
	 * For page ratios of greater than 1: validate that writes to the other
	 * mappings still fault.  Remove the mappings afterwards (we're done
	 * with page ratio testing).
	 */
	for (map_count = 1; map_count < page_ratio; map_count++) {
		pmap_test_write(pmap, va_base + (pmap_page_size * map_count), true);
		pmap_remove(pmap, va_base + (pmap_page_size * map_count), va_base + (pmap_page_size * map_count) + pmap_page_size);
	}

	T_LOG("Mark the page unreferenced and unmodified.");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_test_check_refmod(pa, 0);

	/*
	 * Begin testing the ref/mod state machine.  Re-enter the mapping with
	 * different protection/fault_type settings, and confirm that the
	 * ref/mod state matches our expectations at each step.
	 */
	T_LOG("!ref/!mod: read, no fault.  Expect ref/!mod");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ, VM_PROT_NONE, 0, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("!ref/!mod: read, read fault.  Expect ref/!mod");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ, VM_PROT_READ, 0, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("!ref/!mod: rw, read fault.  Expect ref/!mod");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, 0, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("ref/!mod: rw, read fault.  Expect ref/!mod");
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ, 0, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED);

	T_LOG("!ref/!mod: rw, rw fault.  Expect ref/mod");
	pmap_clear_refmod(pn, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
	pmap_enter_addr(pmap, va_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false);
	pmap_test_check_refmod(pa, VM_MEM_REFERENCED | VM_MEM_MODIFIED);

	/*
	 * Shared memory testing; we'll have two mappings; one read-only,
	 * one read-write.
	 */
	vm_map_address_t rw_base = va_base;
	vm_map_address_t ro_base = va_base + pmap_page_size;

	pmap_enter_addr(pmap, rw_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false);
	pmap_enter_addr(pmap, ro_base, pa, VM_PROT_READ, VM_PROT_READ, 0, false);

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
	pmap_enter_addr(pmap, rw_base, pa, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0, false);
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
#endif /* __arm64__ */

kern_return_t
pmap_test(void)
{
	T_LOG("Starting pmap_tests");
#ifdef __arm64__
	int flags = 0;
	flags |= PMAP_CREATE_64BIT;

#if __ARM_MIXED_PAGE_SIZE__
	T_LOG("Testing VM_PAGE_SIZE_4KB");
	pmap_test_test_config(flags | PMAP_CREATE_FORCE_4K_PAGES);
	T_LOG("Testing VM_PAGE_SIZE_16KB");
	pmap_test_test_config(flags);
#else /* __ARM_MIXED_PAGE_SIZE__ */
	pmap_test_test_config(flags);
#endif /* __ARM_MIXED_PAGE_SIZE__ */

#endif /* __arm64__ */
	T_PASS("completed pmap_test successfully");
	return KERN_SUCCESS;
}
#endif /* CONFIG_XNUPOST */

/*
 * The following function should never make it to RELEASE code, since
 * it provides a way to get the PPL to modify text pages.
 */
#if DEVELOPMENT || DEBUG

#define ARM_UNDEFINED_INSN 0xe7f000f0
#define ARM_UNDEFINED_INSN_THUMB 0xde00

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
pmap_test_text_corruption(pmap_paddr_t pa)
{
#if XNU_MONITOR
	return pmap_test_text_corruption_ppl(pa);
#else /* XNU_MONITOR */
	return pmap_test_text_corruption_internal(pa);
#endif /* XNU_MONITOR */
}

MARK_AS_PMAP_TEXT kern_return_t
pmap_test_text_corruption_internal(pmap_paddr_t pa)
{
	vm_offset_t va = phystokv(pa);
	unsigned int pai = pa_index(pa);

	assert(pa_valid(pa));

	pvh_lock(pai);

	pv_entry_t **pv_h  = pai_to_pvh(pai);
	assert(!pvh_test_type(pv_h, PVH_TYPE_NULL));
#if defined(PVH_FLAG_EXEC)
	const bool need_ap_twiddle = pvh_get_flags(pv_h) & PVH_FLAG_EXEC;

	if (need_ap_twiddle) {
		pmap_set_ptov_ap(pai, AP_RWNA, FALSE);
	}
#endif /* defined(PVH_FLAG_EXEC) */

	/*
	 * The low bit in an instruction address indicates a THUMB instruction
	 */
	if (va & 1) {
		va &= ~(vm_offset_t)1;
		*(uint16_t *)va = ARM_UNDEFINED_INSN_THUMB;
	} else {
		*(uint32_t *)va = ARM_UNDEFINED_INSN;
	}

#if defined(PVH_FLAG_EXEC)
	if (need_ap_twiddle) {
		pmap_set_ptov_ap(pai, AP_RONA, FALSE);
	}
#endif /* defined(PVH_FLAG_EXEC) */

	InvalidatePoU_IcacheRegion(va, sizeof(uint32_t));

	pvh_unlock(pai);

	return KERN_SUCCESS;
}

#endif /* DEVELOPMENT || DEBUG */
