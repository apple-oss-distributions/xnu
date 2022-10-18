/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

#include <stdint.h>
#include <string.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <kern/assert.h>
#include <machine/machine_routines.h>
#include <kern/thread.h>
#include <kern/simple_lock.h>
#include <kern/debug.h>
#include <mach/mach_vm.h>
#include <mach/vm_param.h>
#include <libkern/libkern.h>
#include <sys/queue.h>
#include <vm/pmap.h>
#include "kasan.h"
#include "kasan_internal.h"
#include "memintrinsics.h"

#include <pexpert/device_tree.h>
#include <pexpert/arm64/boot.h>
#include <arm64/tlb.h>

#include <libkern/kernel_mach_header.h>

#if KASAN_CLASSIC
#include "kasan-classic-arm64.h"
#elif KASAN_TBI
#include "kasan-tbi-arm64.h"
_Static_assert((KASAN_TBI_ADDR_SIZE > VM_KERNEL_POINTER_SIGNIFICANT_BITS), "Kernel pointers leave no room for tagging");
#else /* KASAN_CLASSIC || KASAN_TBI */
#error "No model defined for the shadow table"
#endif /* KASAN_CLASSIC || KASAN_TBI */

#if KASAN_LIGHT
extern bool kasan_zone_maps_owned(vm_address_t, vm_size_t);
#endif /* KASAN_LIGHT */

extern thread_t kasan_lock_holder;

extern uint64_t *cpu_tte;
extern unsigned long gVirtBase, gPhysBase;

typedef uint64_t pmap_paddr_t;
extern vm_map_address_t phystokv(pmap_paddr_t pa);

vm_offset_t physmap_vbase;
vm_offset_t physmap_vtop;

vm_offset_t shadow_pbase;
vm_offset_t shadow_ptop;
#if HIBERNATION
// if we're building a kernel with hibernation support, hibernate_write_image depends on this symbol
vm_offset_t shadow_pnext;
#else
static vm_offset_t shadow_pnext;
#endif

static vm_offset_t unmutable_valid_access_page;
static vm_offset_t bootstrap_pgtable_phys;

extern vm_offset_t intstack, intstack_top;
extern vm_offset_t excepstack, excepstack_top;

static lck_ticket_t kasan_vm_lock;

void kasan_bootstrap(boot_args *, vm_offset_t pgtable);

_Static_assert(KASAN_OFFSET == KASAN_OFFSET_ARM64, "KASan inconsistent shadow offset");
_Static_assert(VM_MAX_KERNEL_ADDRESS < KASAN_SHADOW_MIN, "KASan shadow overlaps with kernel VM");
_Static_assert((VM_MIN_KERNEL_ADDRESS >> KASAN_SCALE) + KASAN_OFFSET_ARM64 >= KASAN_SHADOW_MIN, "KASan shadow does not cover kernel VM");
_Static_assert((VM_MAX_KERNEL_ADDRESS >> KASAN_SCALE) + KASAN_OFFSET_ARM64 < KASAN_SHADOW_MAX, "KASan shadow does not cover kernel VM");

#define KASAN_ARM64_MAP_STATIC_VALID_PAGE       0x1
#define KASAN_ARM64_PREALLOCATE_L1L2            0x2
#define KASAN_ARM64_NO_PHYSMAP                  0x4

#define KASAN_ARM64_MAP                         (0)
#define KASAN_ARM64_STATIC_VALID_MAP            (KASAN_ARM64_MAP | KASAN_ARM64_MAP_STATIC_VALID_PAGE)
#define KASAN_ARM64_PREALLOCATE_TRANSLATION     (KASAN_ARM64_PREALLOCATE_L1L2)
#define KASAN_ARM64_MAP_EARLY                   (KASAN_ARM64_MAP | KASAN_ARM64_NO_PHYSMAP)
#define KASAN_ARM64_MAP_STATIC_EARLY            (KASAN_ARM64_STATIC_VALID_MAP | KASAN_ARM64_NO_PHYSMAP)


/*
 * KASAN runs both early on, when the 1:1 mapping hasn't been established yet,
 * and later when memory management is fully set up. This internal version of
 * phystokv switches between accessing physical memory directly and using the
 * physmap.
 */
static vm_map_address_t
kasan_arm64_phystokv(uintptr_t pa, bool early)
{
	return early ? (pa) : phystokv(pa);
}

/*
 * Physical pages used to back up the shadow table are stolen early on at
 * boot and later managed in a fairly simple, linear, fashion.
 */
static uintptr_t
kasan_arm64_alloc_page(void)
{
	if (shadow_pnext + ARM_PGBYTES >= shadow_ptop) {
		panic("KASAN: OOM");
	}

	uintptr_t mem = shadow_pnext;
	shadow_pnext += ARM_PGBYTES;
	shadow_pages_used++;

	return mem;
}

static uintptr_t
kasan_arm64_alloc_zero_page(bool early)
{
	uintptr_t mem = kasan_arm64_alloc_page();
	__nosan_bzero((void *)kasan_arm64_phystokv(mem, early), ARM_PGBYTES);
	return mem;
}

static uintptr_t
kasan_arm64_alloc_valid_page(bool early)
{
	uintptr_t mem = kasan_arm64_alloc_page();
	kasan_impl_fill_valid_range(kasan_arm64_phystokv(mem, early), ARM_PGBYTES);
	return mem;
}

static void
kasan_arm64_align_to_page(vm_offset_t *addrp, vm_offset_t *sizep)
{
	vm_offset_t addr_aligned = vm_map_trunc_page(*addrp, ARM_PGMASK);
	*sizep = vm_map_round_page(*sizep + (*addrp - addr_aligned), ARM_PGMASK);
	*addrp = addr_aligned;
}

static uint64_t *
kasan_arm64_lookup_l1(uint64_t *base, vm_offset_t address)
{
	return base + ((address & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);
}

static uint64_t *
kasan_arm64_lookup_l2(uint64_t *base, vm_offset_t address)
{
	return base + ((address & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);
}

static uint64_t *
kasan_arm64_lookup_l3(uint64_t *base, vm_offset_t address)
{
	return base + ((address & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT);
}

/*
 * kasan_arm_pte_map() is the hearth of the arch-specific handling of the shadow
 * table. It walks the existing page tables that map shadow ranges and
 * allocates/creates valid entries as required. Options are:
 *  - static_valid: instead of creating a new backing shadow page, point to
 *    the 'full valid access' one created early at boot.
 *  - preallocate_translation_only: do not add the final shadow table entry, but
 *    only add the L1/L2 pages for a valid translation.
 *  - early: xnu is running before the VM is fully setup, so handle physical
 *    address directly instead of going through the physmap.
 */
static void
kasan_arm64_pte_map(vm_offset_t shadow_base, uint64_t *base, uint8_t options)
{
	bool early = options & KASAN_ARM64_NO_PHYSMAP;
	uint64_t *pte;

	/* lookup L1 entry */
	pte = kasan_arm64_lookup_l1(base, shadow_base);
	if (*pte & ARM_TTE_VALID) {
		assert((*pte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE);
	} else {
		*pte = ((uint64_t)kasan_arm64_alloc_zero_page(early)
		    & ARM_TTE_TABLE_MASK) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
	}

	base = (uint64_t *)kasan_arm64_phystokv(*pte & ARM_TTE_TABLE_MASK, early);

	/* lookup L2 entry */
	pte = kasan_arm64_lookup_l2(base, shadow_base);
	if (*pte & ARM_TTE_VALID) {
		assert((*pte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE);
	} else {
		*pte = ((uint64_t)kasan_arm64_alloc_zero_page(early)
		    & ARM_TTE_TABLE_MASK) | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE;
	}

	base = (uint64_t *)kasan_arm64_phystokv(*pte & ARM_TTE_TABLE_MASK, early);

	if (options & KASAN_ARM64_PREALLOCATE_L1L2) {
		return;
	}

	bool static_valid = options & KASAN_ARM64_MAP_STATIC_VALID_PAGE;

	/* lookup L3 entry */
	pte = kasan_arm64_lookup_l3(base, shadow_base);

	if (*pte & ARM_PTE_TYPE_VALID) {
		bool pte_rona = (*pte & ARM_PTE_APMASK) == ARM_PTE_AP(AP_RONA);
		if (!pte_rona || static_valid) {
			return;
		}
	}

	/* create new L3 entry */
	uint64_t newpte;
	if (static_valid) {
		/* map the zero page RO */
		newpte = (uint64_t)unmutable_valid_access_page | ARM_PTE_AP(AP_RONA);
	} else {
		newpte = (uint64_t)kasan_arm64_alloc_valid_page(early) | ARM_PTE_AP(AP_RWNA);
	}

	newpte |= ARM_PTE_TYPE_VALID
	    | ARM_PTE_AF
	    | ARM_PTE_SH(SH_OUTER_MEMORY)
	    | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT)
	    | ARM_PTE_NX
	    | ARM_PTE_PNX;
	*pte = newpte;
}

static void
kasan_map_shadow_internal(vm_offset_t address, vm_size_t size, uint8_t options)
{
	size = (size + KASAN_SIZE_ALIGNMENT) & ~KASAN_SIZE_ALIGNMENT;
	vm_offset_t shadow_base = vm_map_trunc_page(SHADOW_FOR_ADDRESS(address), ARM_PGMASK);
	vm_offset_t shadow_top = vm_map_round_page(SHADOW_FOR_ADDRESS(address + size), ARM_PGMASK);

	assert(shadow_base >= KASAN_SHADOW_MIN && shadow_top <= KASAN_SHADOW_MAX);
	assert((size & KASAN_SIZE_ALIGNMENT) == 0);

	for (; shadow_base < shadow_top; shadow_base += ARM_PGBYTES) {
		kasan_arm64_pte_map(shadow_base, cpu_tte, options);
	}

	flush_mmu_tlb();
}

void
kasan_map_shadow(vm_offset_t address, vm_size_t size, bool static_valid)
{
	uint8_t options = KASAN_ARM64_MAP;

	if (static_valid) {
		options |= KASAN_ARM64_MAP_STATIC_VALID_PAGE;
#if KASAN_LIGHT
	} else if (!kasan_zone_maps_owned(address, size)) {
		options |= KASAN_ARM64_MAP_STATIC_VALID_PAGE;
#endif /* KASAN_LIGHT */
	}

	kasan_map_shadow_internal(address, size, options);
}

/*
 * TODO: mappings here can be reclaimed after kasan_init()
 */
static void
kasan_arm64_do_map_shadow_early(vm_offset_t address, vm_size_t size, uint8_t options)
{
	kasan_arm64_align_to_page(&address, &size);
	vm_size_t j;

	for (j = 0; j < size; j += ARM_PGBYTES) {
		vm_offset_t virt_shadow_target = (vm_offset_t)SHADOW_FOR_ADDRESS(address + j);

		assert(virt_shadow_target >= KASAN_SHADOW_MIN);
		assert(virt_shadow_target < KASAN_SHADOW_MAX);

		kasan_arm64_pte_map(virt_shadow_target, (uint64_t *)bootstrap_pgtable_phys, options);
	}

	flush_mmu_tlb();
}


static void
kasan_map_shadow_early(vm_offset_t address, vm_size_t size)
{
	kasan_arm64_do_map_shadow_early(address, size, KASAN_ARM64_MAP_EARLY);
}

static void
kasan_map_shadow_static_early(vm_offset_t address, vm_size_t size)
{
	kasan_arm64_do_map_shadow_early(address, size, KASAN_ARM64_MAP_STATIC_EARLY);
}

void
kasan_arch_init(void)
{
	/* Map the physical aperture */
	kasan_map_shadow(physmap_vbase, physmap_vtop - physmap_vbase, true);

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	/* Pre-allocate all the L3 page table pages to avoid triggering KTRR */
	kasan_map_shadow_internal(VM_MIN_KERNEL_ADDRESS,
	    VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS + 1, KASAN_ARM64_PREALLOCATE_TRANSLATION);
#endif
}

/*
 * Steal memory for the shadow, and shadow map the bootstrap page tables so we can
 * run until kasan_init(). Called while running with identity (V=P) map active.
 */
void
kasan_bootstrap(boot_args *args, vm_offset_t pgtable)
{
	uintptr_t tosteal;
	/* Base address for the virtual identity mapping */
	vm_address_t p2v = args->virtBase - args->physBase;

	vm_address_t pbase = args->physBase;
	vm_address_t ptop = args->topOfKernelData;
	kernel_vbase = args->virtBase;
	kernel_vtop = kernel_vbase + ptop - pbase;

	/* Reserve physical memory at the end for KASAN shadow table and quarantines */
	tosteal = (args->memSize * STOLEN_MEM_PERCENT) / 100 + STOLEN_MEM_BYTES;
	tosteal = vm_map_trunc_page(tosteal, ARM_PGMASK);

	/* Make it disappear from xnu view */
	args->memSize -= tosteal;

	shadow_pbase = vm_map_round_page(pbase + args->memSize, ARM_PGMASK);
	shadow_ptop = shadow_pbase + tosteal;
	shadow_pnext = shadow_pbase;
	shadow_pages_total = (uint32_t)((shadow_ptop - shadow_pbase) / ARM_PGBYTES);

	/*
	 * Set aside a page to represent all those regions that allow any
	 * access and that won't mutate over their lifetime.
	 */
	unmutable_valid_access_page = kasan_arm64_alloc_page();
	kasan_impl_fill_valid_range(unmutable_valid_access_page, ARM_PGBYTES);

	/* Shadow the KVA bootstrap mapping: start of kernel Mach-O to end of physical */
	bootstrap_pgtable_phys = pgtable;
	/* Blanket map all of what we got from iBoot, as we'd later do in kasan_init() */
	kasan_map_shadow_static_early(kernel_vbase, args->memSize);

	vm_offset_t intstack_virt = (vm_offset_t)&intstack + p2v;
	vm_offset_t excepstack_virt = (vm_offset_t)&excepstack + p2v;
	vm_offset_t intstack_size = (vm_offset_t)&intstack_top - (vm_offset_t)&intstack;
	vm_offset_t excepstack_size = (vm_offset_t)&excepstack_top - (vm_offset_t)&excepstack;

	kasan_map_shadow_early(intstack_virt, intstack_size);
	kasan_map_shadow_early(excepstack_virt, excepstack_size);

	/* Upgrade the deviceTree mapping if necessary */
	if ((vm_offset_t)args->deviceTreeP - p2v < (vm_offset_t)&_mh_execute_header) {
		kasan_map_shadow_early((vm_offset_t)args->deviceTreeP, args->deviceTreeLength);
	}
}

bool
kasan_is_shadow_mapped(uintptr_t shadowp)
{
	uint64_t *pte;
	uint64_t *base = cpu_tte;

	assert(shadowp >= KASAN_SHADOW_MIN);
	assert(shadowp < KASAN_SHADOW_MAX);

	/* lookup L1 entry */
	pte = kasan_arm64_lookup_l1(base, shadowp);
	if (!(*pte & ARM_TTE_VALID)) {
		return false;
	}
	base = (uint64_t *)phystokv(*pte & ARM_TTE_TABLE_MASK);

	/* lookup L2 entry */
	pte = kasan_arm64_lookup_l2(base, shadowp);
	if (!(*pte & ARM_TTE_VALID)) {
		return false;
	}
	base = (uint64_t *)phystokv(*pte & ARM_TTE_TABLE_MASK);

	/* lookup L3 entry */
	pte = kasan_arm64_lookup_l3(base, shadowp);
	if (!(*pte & ARM_PTE_TYPE_VALID)) {
		return false;
	}

	return true;
}

void
kasan_lock_init(void)
{
	lck_ticket_init(&kasan_vm_lock, LCK_GRP_NULL);
}

/*
 * KASAN may be called from interrupt context, so we disable interrupts to
 * ensure atomicity manipulating the global objects.
 */
void
kasan_lock(boolean_t *b)
{
	*b = ml_set_interrupts_enabled(false);
	lck_ticket_lock(&kasan_vm_lock, LCK_GRP_NULL);
	kasan_lock_holder = current_thread();
}

void
kasan_unlock(boolean_t b)
{
	kasan_lock_holder = THREAD_NULL;
	lck_ticket_unlock(&kasan_vm_lock);
	ml_set_interrupts_enabled(b);
}
