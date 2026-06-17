/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 */
/*
 *	File:	vm/vm_page.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Resident memory management module.
 */
#include <debug.h>
#include <libkern/OSDebug.h>

#include <mach/clock_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <mach/sdt.h>
#include <kern/counter.h>
#include <kern/exclaves_memory.h>
#include <kern/host_statistics.h>
#include <kern/sched_prim.h>
#include <kern/policy_internal.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <kern/zalloc_internal.h>
#include <kern/ledger.h>
#include <kern/ecc.h>
#include <vm/pmap.h>
#include <vm/vm_init_xnu.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_pageout_internal.h>
#include <vm/vm_kern_xnu.h>                 /* kmem_alloc() */
#include <vm/vm_compressor_pager_internal.h>
#include <kern/misc_protos.h>
#include <mach_debug/zone_info.h>
#include <vm/cpm_internal.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <san/kasan.h>
#include <vm/vm_log.h>

#include <libkern/coreanalytics/coreanalytics.h>
#include <libkern/kernel_mach_header.h>
#include <kern/backtrace.h>
#include <kern/telemetry.h>

#include <vm/vm_protos_internal.h>
#include <vm/memory_object.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_compressor_internal.h>
#include <vm/vm_iokit.h>
#include <vm/vm_object_internal.h>
#if HAS_MTE
#include <arm64/mte.h>
#include <vm/vm_mteinfo_internal.h>
#endif /* HAS_MTE */
#include <vm/vm_map_lock_internal.h>

#if defined (__x86_64__)
#include <i386/misc_protos.h>
#endif

#if CONFIG_SPTM
#include <arm64/sptm/sptm.h>
#endif

#if CONFIG_PHANTOM_CACHE
#include <vm/vm_phantom_cache_internal.h>
#endif

#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#include <machine/pal_hibernate.h>
#endif /* HIBERNATION */

#if CONFIG_SECLUDED_MEMORY
static_assert(!XNU_VM_HAS_LOPAGE,
    "VM_PAGE_ON_SECLUDED_Q and VM_PAGE_ON_FREE_LOPAGE_Q alias");
#endif

#include <sys/kdebug.h>

#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#endif
#if defined(__arm64__)
#include <arm/cpu_internal.h>
#endif /* defined(__arm64__) */

/*
 * During single threaded early boot we don't initialize all pages.
 * This avoids some delay during boot. They'll be initialized and
 * added to the free list as needed or after we are multithreaded by
 * what becomes the pageout thread.
 *
 * This slows down booting the DEBUG kernel, particularly on
 * large memory systems, but is worthwhile in deterministically
 * trapping uninitialized memory usage.
 */
#if DEBUG
static TUNABLE(uint32_t, fillval, "fill", 0xDEB8F177);
#else
static TUNABLE(uint32_t, fillval, "fill", 0);
#endif

#if MACH_ASSERT

TUNABLE(bool, vm_check_refs_on_alloc, "vm_check_refs_on_alloc", false);

#endif /* MACH_ASSERT */

extern boolean_t vm_pageout_running;
extern thread_t  vm_pageout_scan_thread;
extern bool vps_dynamic_priority_enabled;

const uint16_t vm_page_inactive_states =
    BIT(VM_PAGE_ON_INACTIVE_INTERNAL_Q) |
    BIT(VM_PAGE_ON_INACTIVE_EXTERNAL_Q) |
    BIT(VM_PAGE_ON_INACTIVE_CLEANED_Q);

const uint16_t vm_page_active_or_inactive_states =
    vm_page_inactive_states |
#if CONFIG_SECLUDED_MEMORY
    BIT(VM_PAGE_ON_SECLUDED_Q) |
#endif /* CONFIG_SECLUDED_MEMORY */
    BIT(VM_PAGE_ON_ACTIVE_Q);

const uint16_t vm_page_non_speculative_pageable_states =
    vm_page_active_or_inactive_states |
    BIT(VM_PAGE_ON_THROTTLED_Q);

const uint16_t vm_page_pageable_states =
    vm_page_non_speculative_pageable_states |
    BIT(VM_PAGE_ON_SPECULATIVE_Q);

#if CONFIG_SECLUDED_MEMORY
struct vm_page_secluded_data vm_page_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
#if HIBERNATION
static bool hibernate_rebuild_needed = false;
#endif /* HIBERNATION */

extern struct memory_object_pager_ops shared_region_pager_ops;



struct vm_page_pcpu PERCPU_DATA(vm_page_pcpu);
SCALABLE_COUNTER_DEFINE(vm_cpu_free_count);
boolean_t       hibernate_cleaning_in_progress = FALSE;

atomic_counter_t vm_guard_count;

#if XNU_VM_HAS_LOPAGE
/*
 * this interface exists to support hardware controllers
 * incapable of generating DMAs with more than 32 bits
 * of address on platforms with physical memory > 4G...
 */
vm_page_queue_head_t    vm_lopage_queue_free VM_PAGE_PACKED_ALIGNED;
uint32_t        vm_lopage_free_count   = 0;
uint32_t        vm_lopage_free_limit   = 0;
uint32_t        vm_lopage_lowater      = 0;
bool            vm_lopage_refill       = false;
bool            vm_lopage_needed       = false;
unsigned int    vm_lopages_allocated_q = 0;
unsigned int    vm_lopages_allocated_cpm_success = 0;
unsigned int    vm_lopages_allocated_cpm_failed = 0;
#endif /* XNU_VM_HAS_LOPAGE */


int             speculative_age_index = 0;
int             speculative_steal_index = 0;
struct vm_speculative_age_q vm_page_queue_speculative[VM_PAGE_RESERVED_SPECULATIVE_AGE_Q + 1];

boolean_t       hibernation_vmqueues_inspection = FALSE; /* Tracks if the hibernation code is looking at the VM queues.
                                                          * Updated and checked behind the vm_page_queues_lock. */

static void             vm_page_free_prepare(vm_page_t  page);

#if HAS_MTE
void                    vm_page_wire_boot_tags(void);
#endif /* HAS_MTE */

static void vm_tag_init(void);

/* for debugging purposes */
SECURITY_READ_ONLY_EARLY(uint32_t) vm_packed_from_vm_pages_array_mask =
    VM_PAGE_PACKED_FROM_ARRAY;
SECURITY_READ_ONLY_EARLY(vm_packing_params_t) vm_page_packing_params =
    VM_PACKING_PARAMS(VM_PAGE_PACKED_PTR);
SECURITY_READ_ONLY_EARLY(vm_packing_params_t) vme_packing_params =
    VM_PACKING_PARAMS(VME_PACKED_PTR);
SECURITY_READ_ONLY_EARLY(vm_packing_params_t) vmn_packing_params =
    VM_PACKING_PARAMS(VMN_PACKED_PTR);


/*
 *	Associated with page of user-allocatable memory is a
 *	page structure.
 */

/*
 *	These variables record the values returned by vm_page_bootstrap,
 *	for debugging purposes.  The implementation of pmap_steal_memory
 *	and pmap_startup here also uses them internally.
 */

vm_offset_t virtual_space_start;
vm_offset_t virtual_space_end;
uint32_t        vm_page_pages;

/*
 *	The vm_page_lookup() routine, which provides for fast
 *	(virtual memory object, offset) to page lookup, employs
 *	the following hash table.  The vm_page_{insert,remove}
 *	routines install and remove associations in the table.
 *	[This table is often called the virtual-to-physical,
 *	or VP, table.]
 */
typedef struct {
	vm_page_packed_t page_list;
#if     MACH_PAGE_HASH_STATS
	int             cur_count;              /* current count */
	int             hi_count;               /* high water mark */
#endif /* MACH_PAGE_HASH_STATS */
} vm_page_bucket_t;


#define BUCKETS_PER_LOCK        4

SECURITY_READ_ONLY_LATE(vm_page_bucket_t *) vm_page_buckets;                /* Array of buckets */
SECURITY_READ_ONLY_LATE(unsigned int)       vm_page_bucket_count = 0;       /* How big is array? */
SECURITY_READ_ONLY_LATE(unsigned int)       vm_page_hash_mask;              /* Mask for hash function */
SECURITY_READ_ONLY_LATE(unsigned int)       vm_page_hash_shift;             /* Shift for hash function */
SECURITY_READ_ONLY_LATE(uint32_t)           vm_page_bucket_hash;            /* Basic bucket hash */
SECURITY_READ_ONLY_LATE(unsigned int)       vm_page_bucket_lock_count = 0;  /* How big is array of locks? */

#ifndef VM_TAG_ACTIVE_UPDATE
#error VM_TAG_ACTIVE_UPDATE
#endif
#ifndef VM_TAG_SIZECLASSES
#error VM_TAG_SIZECLASSES
#endif

/* for debugging */
SECURITY_READ_ONLY_LATE(bool) vm_tag_active_update = VM_TAG_ACTIVE_UPDATE;
SECURITY_READ_ONLY_LATE(hw_lck_ticket_t *) vm_page_bucket_locks;

vm_allocation_site_t            vm_allocation_sites_static[VM_KERN_MEMORY_FIRST_DYNAMIC + 1];
vm_allocation_site_t *          vm_allocation_sites[VM_MAX_TAG_VALUE];
#if VM_TAG_SIZECLASSES
static vm_allocation_zone_total_t **vm_allocation_zone_totals;
#endif /* VM_TAG_SIZECLASSES */

vm_tag_t vm_allocation_tag_highest;

#if VM_PAGE_BUCKETS_CHECK
boolean_t vm_page_buckets_check_ready = FALSE;
#if VM_PAGE_FAKE_BUCKETS
vm_page_bucket_t *vm_page_fake_buckets; /* decoy buckets */
vm_map_offset_t vm_page_fake_buckets_start, vm_page_fake_buckets_end;
#endif /* VM_PAGE_FAKE_BUCKETS */
#endif /* VM_PAGE_BUCKETS_CHECK */

#if     MACH_PAGE_HASH_STATS
/* This routine is only for debug.  It is intended to be called by
 * hand by a developer using a kernel debugger.  This routine prints
 * out vm_page_hash table statistics to the kernel debug console.
 */
void
hash_debug(void)
{
	int     i;
	int     numbuckets = 0;
	int     highsum = 0;
	int     maxdepth = 0;

	for (i = 0; i < vm_page_bucket_count; i++) {
		if (vm_page_buckets[i].hi_count) {
			numbuckets++;
			highsum += vm_page_buckets[i].hi_count;
			if (vm_page_buckets[i].hi_count > maxdepth) {
				maxdepth = vm_page_buckets[i].hi_count;
			}
		}
	}
	printf("Total number of buckets: %d\n", vm_page_bucket_count);
	printf("Number used buckets:     %d = %d%%\n",
	    numbuckets, 100 * numbuckets / vm_page_bucket_count);
	printf("Number unused buckets:   %d = %d%%\n",
	    vm_page_bucket_count - numbuckets,
	    100 * (vm_page_bucket_count - numbuckets) / vm_page_bucket_count);
	printf("Sum of bucket max depth: %d\n", highsum);
	printf("Average bucket depth:    %d.%2d\n",
	    highsum / vm_page_bucket_count,
	    highsum % vm_page_bucket_count);
	printf("Maximum bucket depth:    %d\n", maxdepth);
}
#endif /* MACH_PAGE_HASH_STATS */

/*
 *	The virtual page size is currently implemented as a runtime
 *	variable, but is constant once initialized using vm_set_page_size.
 *	This initialization must be done in the machine-dependent
 *	bootstrap sequence, before calling other machine-independent
 *	initializations.
 *
 *	All references to the virtual page size outside this
 *	module must use the PAGE_SIZE, PAGE_MASK and PAGE_SHIFT
 *	constants.
 */
#if defined(__arm64__)
vm_size_t       page_size;
vm_size_t       page_mask;
int             page_shift;
#else
vm_size_t       page_size  = PAGE_SIZE;
vm_size_t       page_mask  = PAGE_MASK;
int             page_shift = PAGE_SHIFT;
#endif

SECURITY_READ_ONLY_LATE(vm_page_t) vm_pages;
#if XNU_VM_HAS_DELAYED_PAGES
vm_page_t                          vm_pages_end;
uint32_t                           vm_pages_count;
#else
SECURITY_READ_ONLY_LATE(vm_page_t) vm_pages_end;
SECURITY_READ_ONLY_LATE(uint32_t)  vm_pages_count;
#endif /* XNU_VM_HAS_DELAYED_PAGES */
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
SECURITY_READ_ONLY_LATE(ppnum_t)   vm_pages_first_pnum;
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */
#if HAS_MTE
SECURITY_READ_ONLY_LATE(vm_page_t) vm_pages_tag_storage;
SECURITY_READ_ONLY_LATE(vm_page_t) vm_pages_tag_storage_end;
#endif /* HAS_MTE */
#if CONFIG_SPTM
/*
 * When used, these 128bit (MAX_COLORS bits) masks represent a "cluster"
 * of contiguous free physical pages.
 *
 * For each cluster, there is an enqueue "index", which is -1 when there is no
 * free page in the cluster, or the index in [0, 128) of the page that is
 * enqueued on the vm_page_free_queue to represent the entire cluster.
 *
 * Grouping pages this way has the double nice effect to reduce doubly linked
 * list (the worst data structure known to man when considering cache misses)
 * manipulations, and also to mechanically make the VM serve more "contiguous"
 * pages naturally.
 */
static_assert(XNU_VM_HAS_LINEAR_PAGES_ARRAY);
SECURITY_READ_ONLY_LATE(__uint128_t *) _vm_pages_free_masks;
SECURITY_READ_ONLY_LATE(int8_t *)      _vm_pages_free_enqueue_idx;
#endif /* CONFIG_SPTM */


/*
 *	Resident pages that represent real memory
 *	are allocated from a set of free lists,
 *	one per color.
 */
SECURITY_READ_ONLY_LATE(unsigned int) vm_colors;
SECURITY_READ_ONLY_LATE(unsigned int) vm_color_mask; /* mask is == (vm_colors-1) */
unsigned int    vm_cache_geometry_colors = 0;   /* set by hw dependent code during startup */
unsigned int    vm_free_magazine_refill_limit = 0;

struct vm_page_free_queue vm_page_queue_free;

unsigned int    vm_page_free_wanted;
unsigned int    vm_page_free_wanted_privileged;
#if CONFIG_SECLUDED_MEMORY
unsigned int    vm_page_free_wanted_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
unsigned int    vm_page_free_count;

unsigned int    vm_page_realtime_count;

/*
 *	Occasionally, the virtual memory system uses
 *	resident page structures that do not refer to
 *	real pages, for example to leave a page with
 *	important state information in the VP table.
 *
 *	These page structures are allocated the way
 *	most other kernel structures are.
 */
SECURITY_READ_ONLY_LATE(zone_t) vm_page_zone;
vm_locks_array_t vm_page_locks;

LCK_ATTR_DECLARE(vm_page_lck_attr, 0, 0);
LCK_GRP_DECLARE(vm_page_lck_grp_free, "vm_page_free");
LCK_GRP_DECLARE(vm_page_lck_grp_queue, "vm_page_queue");
LCK_GRP_DECLARE(vm_page_lck_grp_local, "vm_page_queue_local");
LCK_GRP_DECLARE(vm_page_lck_grp_purge, "vm_page_purge");
LCK_GRP_DECLARE(vm_page_lck_grp_bucket, "vm_page_bucket");
LCK_SPIN_DECLARE_ATTR(vm_objects_wired_lock, &vm_page_lck_grp_bucket, &vm_page_lck_attr);
LCK_TICKET_DECLARE(vm_allocation_sites_lock, &vm_page_lck_grp_bucket);

unsigned int    vm_page_local_q_soft_limit = 250;
unsigned int    vm_page_local_q_hard_limit = 500;
struct vpl     *__zpercpu vm_page_local_q;

/* N.B. Guard and fictitious pages must not
 * be assigned a zero phys_page value.
 */
/*
 *	Fictitious pages don't have a physical address,
 *	but we must initialize phys_page to something.
 *	For debugging, this should be a strange value
 *	that the pmap module can recognize in assertions.
 */
const ppnum_t vm_page_fictitious_addr = (ppnum_t) -1;

/*
 *	Guard pages are not accessible so they don't
 *      need a physical address, but we need to enter
 *	one in the pmap.
 *	Let's make it recognizable and make sure that
 *	we don't use a real physical page with that
 *	physical address.
 */
const ppnum_t vm_page_guard_addr = (ppnum_t) -2;

/*
 *	Resident page structures are also chained on
 *	queues that are used by the page replacement
 *	system (pageout daemon).  These queues are
 *	defined here, but are shared by the pageout
 *	module.  The inactive queue is broken into
 *	file backed and anonymous for convenience as the
 *	pageout daemon often assignes a higher
 *	importance to anonymous pages (less likely to pick)
 */
vm_page_queue_head_t    vm_page_queue_active VM_PAGE_PACKED_ALIGNED;
vm_page_queue_head_t    vm_page_queue_inactive VM_PAGE_PACKED_ALIGNED;
#if CONFIG_SECLUDED_MEMORY
vm_page_queue_head_t    vm_page_queue_secluded VM_PAGE_PACKED_ALIGNED;
#endif /* CONFIG_SECLUDED_MEMORY */
vm_page_queue_head_t    vm_page_queue_anonymous VM_PAGE_PACKED_ALIGNED;  /* inactive memory queue for anonymous pages */
vm_page_queue_head_t    vm_page_queue_throttled VM_PAGE_PACKED_ALIGNED;

queue_head_t    vm_objects_wired;

vm_page_queue_head_t    vm_page_queue_donate VM_PAGE_PACKED_ALIGNED;
uint32_t        vm_page_donate_mode;
uint32_t        vm_page_donate_target, vm_page_donate_target_high, vm_page_donate_target_low;
uint32_t        vm_page_donate_count;
bool            vm_page_donate_queue_ripe;


vm_page_queue_head_t    vm_page_queue_background VM_PAGE_PACKED_ALIGNED;
uint32_t        vm_page_background_target;
uint32_t        vm_page_background_target_snapshot;
uint32_t        vm_page_background_count;
uint64_t        vm_page_background_promoted_count;

uint32_t        vm_page_background_internal_count;
uint32_t        vm_page_background_external_count;

uint32_t        vm_page_background_mode;
uint32_t        vm_page_background_exclude_external;

unsigned int    vm_page_active_count;
unsigned int    vm_page_inactive_count;
unsigned int    vm_page_kernelcache_count;
#if CONFIG_SECLUDED_MEMORY
unsigned int    vm_page_secluded_count;
unsigned int    vm_page_secluded_count_free;
unsigned int    vm_page_secluded_count_inuse;
unsigned int    vm_page_secluded_count_over_target;
#endif /* CONFIG_SECLUDED_MEMORY */
unsigned int    vm_page_anonymous_count;
unsigned int    vm_page_throttled_count;
unsigned int    vm_page_speculative_count;

unsigned int    vm_page_wire_count;
unsigned int    vm_page_wire_count_on_boot = 0;
unsigned int    vm_page_stolen_count = 0;
unsigned int    vm_page_wire_count_initial;
unsigned int    vm_page_gobble_count = 0;
unsigned int    vm_page_kern_lpage_count = 0;

uint64_t        booter_size;  /* external so it can be found in core dumps */

#define VM_PAGE_WIRE_COUNT_WARNING      0
#define VM_PAGE_GOBBLE_COUNT_WARNING    0

SCALABLE_COUNTER_DEFINE(vm_page_purgeable_count);
SCALABLE_COUNTER_DEFINE(vm_page_purgeable_wired_count);
uint64_t        vm_page_purged_count = 0;    /* total count of purged pages */

unsigned int    vm_page_xpmapped_external_count = 0;
SCALABLE_COUNTER_DEFINE(vm_page_external_count);
SCALABLE_COUNTER_DEFINE(vm_page_internal_count);
unsigned int    vm_page_pageable_external_count = 0;
unsigned int    vm_page_pageable_internal_count = 0;

#if DEVELOPMENT || DEBUG
unsigned int    vm_page_speculative_recreated = 0;
unsigned int    vm_page_speculative_created = 0;
unsigned int    vm_page_speculative_used = 0;
#endif

_Atomic unsigned int vm_page_shared_region_count = 0;

_Atomic unsigned int vm_page_swapped_count = 0;
_Atomic uint64_t vm_page_swap_count = 0;

vm_page_queue_head_t    vm_page_queue_cleaned VM_PAGE_PACKED_ALIGNED;

unsigned int    vm_page_cleaned_count = 0;

uint64_t        max_valid_dma_address = 0xffffffffffffffffULL;
ppnum_t         max_valid_low_ppnum = PPNUM_MAX;


/*
 *	Several page replacement parameters are also
 *	shared with this module, so that page allocation
 *	can trigger the pageout daemon.
 */
unsigned int    vm_page_free_target = 0;
unsigned int    vm_page_free_min = 0;
unsigned int    vm_page_throttle_limit = 0;
unsigned int    vm_page_inactive_target = 0;
#if CONFIG_SECLUDED_MEMORY
unsigned int    vm_page_secluded_target = 0;
#endif /* CONFIG_SECLUDED_MEMORY */
unsigned int    vm_page_anonymous_min = 0;
unsigned int    vm_page_free_reserved = 0;


/*
 *	The VM system has a couple of heuristics for deciding
 *	that pages are "uninteresting" and should be placed
 *	on the inactive queue as likely candidates for replacement.
 *	These variables let the heuristics be controlled at run-time
 *	to make experimentation easier.
 */

boolean_t vm_page_deactivate_hint = TRUE;

struct vm_page_stats_reusable vm_page_stats_reusable;

/*
 *	vm_set_page_size:
 *
 *	Sets the page size, perhaps based upon the memory
 *	size.  Must be called before any use of page-size
 *	dependent functions.
 *
 *	Sets page_shift and page_mask from page_size.
 */
void
vm_set_page_size(void)
{
	page_size  = PAGE_SIZE;
	page_mask  = PAGE_MASK;
	page_shift = PAGE_SHIFT;

	if ((page_mask & page_size) != 0) {
		panic("vm_set_page_size: page size not a power of two");
	}

	for (page_shift = 0;; page_shift++) {
		if ((1U << page_shift) == page_size) {
			break;
		}
	}
}

#if HAS_MTE

bool
vm_page_is_tag_storage_pnum(vm_page_t mem, ppnum_t pnum)
{
	return pmap_in_tag_storage_range(pnum) &&
	       !mteinfo_tag_storage_disabled(mem);
}

#endif

/*
 * @abstract
 * Given a page, returns the memory class of that page.
 */
static vm_memory_class_t
vm_page_get_memory_class(vm_page_t mem __unused, ppnum_t pnum __unused)
{
	assert(!vm_page_is_fictitious(mem));

#if XNU_VM_HAS_LOPAGE
	if (mem->vmp_lopage) {
		return VM_MEMORY_CLASS_LOPAGE;
	}
#endif /* XNU_VM_HAS_LOPAGE */
#if HAS_MTE
	if (mem->vmp_using_mte) {
		return VM_MEMORY_CLASS_TAGGED;
	} else if (!mte_enabled() || !pmap_in_tag_storage_range(pnum)) {
		return VM_MEMORY_CLASS_REGULAR;
	} else if (mteinfo_tag_storage_disabled(mem)) {
		return VM_MEMORY_CLASS_DEAD_TAG_STORAGE;
	} else {
		return VM_MEMORY_CLASS_TAG_STORAGE;
	}
#else /* !HAS_MTE */
	return VM_MEMORY_CLASS_REGULAR;
#endif /* !HAS_MTE */
}

/*
 * vm_page_is_restricted:
 *
 * Checks if a given vm_page_t is a restricted page.
 */
inline bool
vm_page_is_restricted(vm_page_t mem)
{
	ppnum_t pn = VM_PAGE_GET_PHYS_PAGE(mem);
	return pmap_is_page_restricted(pn);
}

#ifdef __x86_64__

#define MAX_CLUMP_SIZE      16
#define DEFAULT_CLUMP_SIZE  4

unsigned int vm_clump_size, vm_clump_mask, vm_clump_shift, vm_clump_promote_threshold;

#if DEVELOPMENT || DEBUG
unsigned long vm_clump_stats[MAX_CLUMP_SIZE + 1];
unsigned long vm_clump_allocs, vm_clump_inserts, vm_clump_inrange, vm_clump_promotes;

static inline void
vm_clump_update_stats(unsigned int c)
{
	assert(c <= vm_clump_size);
	if (c > 0 && c <= vm_clump_size) {
		vm_clump_stats[c] += c;
	}
	vm_clump_allocs += c;
}
#endif  /*  if DEVELOPMENT || DEBUG */

/* Called once to setup the VM clump knobs */
static void
vm_page_setup_clump( void )
{
	unsigned int override, n;

	vm_clump_size = DEFAULT_CLUMP_SIZE;
	if (PE_parse_boot_argn("clump_size", &override, sizeof(override))) {
		vm_clump_size = override;
	}

	if (vm_clump_size > MAX_CLUMP_SIZE) {
		panic("vm_page_setup_clump:: clump_size is too large!");
	}
	if (vm_clump_size < 1) {
		panic("vm_page_setup_clump:: clump_size must be >= 1");
	}
	if ((vm_clump_size & (vm_clump_size - 1)) != 0) {
		panic("vm_page_setup_clump:: clump_size must be a power of 2");
	}

	vm_clump_promote_threshold = vm_clump_size;
	vm_clump_mask = vm_clump_size - 1;
	for (vm_clump_shift = 0, n = vm_clump_size; n > 1; n >>= 1, vm_clump_shift++) {
		;
	}

#if DEVELOPMENT || DEBUG
	bzero(vm_clump_stats, sizeof(vm_clump_stats));
	vm_clump_allocs = vm_clump_inserts = vm_clump_inrange = vm_clump_promotes = 0;
#endif  /*  if DEVELOPMENT || DEBUG */
}

#endif /* __x86_64__ */

void
vm_page_free_queue_init(vm_page_free_queue_t free_queue)
{
	for (unsigned int color = 0; color < MAX_COLORS; color++) {
		vm_page_queue_init(&free_queue->vmpfq_queues[color].qhead);
	}
}

/*!
 * @function vm_page_free_queue_for_class()
 *
 * @abstract
 * Returns the appropriate free queue for the given class and page color.
 */
__pure2
static vm_page_queue_t
vm_page_free_queue_for_class(vm_memory_class_t mem_class, unsigned int color)
{
	switch (mem_class) {
	case VM_MEMORY_CLASS_REGULAR:
#if HAS_MTE
	case VM_MEMORY_CLASS_TAGGED:
	case VM_MEMORY_CLASS_TAG_STORAGE:
		if (mte_enabled()) {
			return NULL;
		}
		OS_FALLTHROUGH;
	case VM_MEMORY_CLASS_DEAD_TAG_STORAGE:
#endif
		return &vm_page_queue_free.vmpfq_queues[color].qhead;
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		return &vm_lopage_queue_free;
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
	case VM_MEMORY_CLASS_SECLUDED:
		return &vm_page_queue_secluded;
#endif
	}
}

__pure2
static bool
vm_page_free_queue_has_colors(vm_memory_class_t mem_class)
{
	switch (mem_class) {
	case VM_MEMORY_CLASS_REGULAR:
#if HAS_MTE
	case VM_MEMORY_CLASS_TAGGED:
	case VM_MEMORY_CLASS_TAG_STORAGE:
	case VM_MEMORY_CLASS_DEAD_TAG_STORAGE:
#endif
		return true;
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		return false;
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
	case VM_MEMORY_CLASS_SECLUDED:
		return false;
#endif
	}
}


#if CONFIG_SECLUDED_MEMORY

static bool
vm_page_secluded_pool_eligible(vm_memory_class_t class)
{
	switch (class) {
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		return false;
#endif /* XNU_VM_HAS_LOPAGE */
#if HAS_MTE
	case VM_MEMORY_CLASS_TAG_STORAGE:
	case VM_MEMORY_CLASS_TAGGED:
		return false;
#endif /* HAS_MTE */
	default:
		return true;
	}
}

static bool
vm_page_secluded_pool_depleted(void)
{
	if (vm_page_free_count <= vm_page_free_reserved) {
		return false;
	}
	if (num_tasks_can_use_secluded_mem) {
		return false;
	}
	return vm_page_secluded_count < vm_page_secluded_target;
}

#endif /* CONFIG_SECLUDED_MEMORY */
#if HIBERNATION

__attribute__((overloadable))
static void
vm_page_free_queue_foreach(vm_page_queue_t queue, void (^block)(vm_page_t))
{
	vm_page_t page;

	vm_page_queue_iterate(queue, page, vmp_pageq) {
		block(page);
	}
}

__attribute__((overloadable))
static void
vm_page_free_queue_foreach(vm_page_free_queue_t queue, void (^block)(vm_page_t))
{
	for (unsigned int color = 0; color < vm_colors; color++) {
		vm_page_free_queue_foreach(&queue->vmpfq_queues[color].qhead, block);
	}
}

#endif /* HIBERNATION */
#if CONFIG_SPTM

static inline uint32_t
vm_pages_free_mask_len(void)
{
	extern pmap_paddr_t real_avail_end;

	uint64_t pnums = atop(real_avail_end) - pmap_first_pnum;
	static_assert(8 * sizeof(__uint128_t) == MAX_COLORS);
	return (uint32_t)((pnums + MAX_COLORS - 1) / MAX_COLORS);
}

static inline int8_t
vm_pages_free_mask_bit(ppnum_t pnum)
{
	return (int8_t)(pnum & (MAX_COLORS - 1));
}

static inline uint32_t
vm_pages_free_mask_index(ppnum_t pnum)
{
	return (pnum - pmap_first_pnum) / MAX_COLORS;
}

__pure2
static inline __uint128_t *
vm_pages_free_masks(void)
{
	return _vm_pages_free_masks;
}

__pure2
static inline bitmap_t *
vm_pages_free_masks_as_bitmap(uint32_t index)
{
	/*
	 * this conversion is gross but helps with codegen for bit-wise
	 * accesses where the __uint128_t type is really yielding poor code.
	 *
	 * This conversion is only legal on little endian architectures.
	 */
#ifndef __LITTLE_ENDIAN__
#error unsupported configuration
#endif
	return (bitmap_t *)(_vm_pages_free_masks + index);
}

__pure2
static inline int8_t *
vm_pages_free_enqueue_idx(uint32_t index)
{
	return &_vm_pages_free_enqueue_idx[index];
}

/*!
 * @brief
 * Return the position of the next bit in "circular" order for a given cluster
 * of pages, starting at and including @c bit.
 */
static inline int8_t
vm_pages_free_mask_next_bit(uint32_t index, int8_t bit)
{
	__uint128_t value = vm_pages_free_masks()[index];
	__uint128_t mask  = ((__uint128_t)1 << bit) - 1;

	if (value == 0) {
		return -1;
	}

	if (value & ~mask) {
		value &= ~mask;
	}
	if ((uint64_t)value) {
		return (int8_t)__builtin_ctzll((uint64_t)value);
	}
	return 64 + (int8_t)__builtin_ctzll((uint64_t)(value >> 64));
}

static inline bool
vm_pages_free_mask_test(uint32_t index, int8_t bit)
{
	return bitmap_test(vm_pages_free_masks_as_bitmap(index), bit);
}

static inline void
vm_pages_free_mask_set(uint32_t index, int8_t bit)
{
	assert(!vm_pages_free_mask_test(index, bit));
	bitmap_set(vm_pages_free_masks_as_bitmap(index), bit);
}

static inline void
vm_pages_free_mask_clear(uint32_t index, int8_t bit)
{
	assert(vm_pages_free_mask_test(index, bit));
	bitmap_clear(vm_pages_free_masks_as_bitmap(index), bit);
}

#endif /* CONFIG_SPTM */

__attribute__((always_inline))
void
vm_page_free_queue_enter(vm_memory_class_t class, vm_page_t mem, ppnum_t pnum)
{
	bool            enter_first;
	unsigned int    color;
	vm_page_queue_t queue;

	if (startup_phase >= STARTUP_SUB_KMEM) {
		LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);
	}

	assert(!pmap_is_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem)));
	assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0 &&
	    mem->vmp_listq.next == 0 && mem->vmp_listq.prev == 0 &&
	    mem->vmp_specialq.next == 0 && mem->vmp_specialq.prev == 0 &&
	    mem->vmp_next_m == 0 &&
	    mem->vmp_object == 0 &&
	    mem->vmp_wire_count == 0 &&
	    mem->vmp_busy &&
	    !mem->vmp_tabled &&
	    !mem->vmp_laundry &&
	    !mem->vmp_pmapped &&
	    !mem->vmp_wpmapped &&
	    !mem->vmp_realtime);

	switch (class) {
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		mem->vmp_q_state     = VM_PAGE_ON_FREE_LOPAGE_Q;
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;
		mem->vmp_lopage      = true;
		mem->vmp_canonical   = true;
		enter_first          = true;
		break;
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
	case VM_MEMORY_CLASS_SECLUDED:
		if (startup_phase >= STARTUP_SUB_KMEM) {
			LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
		}
#if HAS_MTE
		assert(!mem->vmp_using_mte);
#endif /* HAS_MTE */
		mem->vmp_q_state     = VM_PAGE_ON_SECLUDED_Q;
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;
		mem->vmp_lopage      = false;
		mem->vmp_canonical   = true;
		enter_first          = true;
		break;
#endif
	default:
		mem->vmp_q_state     = VM_PAGE_ON_FREE_Q;
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;
		mem->vmp_lopage      = false;
		mem->vmp_canonical   = true;
		enter_first          = false;
		break;
	}

#if HAS_MTE
	if (mte_enabled()) {
		switch (class) {
		case VM_MEMORY_CLASS_REGULAR:
			return mteinfo_covered_page_set_free(pnum, false);
		case VM_MEMORY_CLASS_TAGGED:
			return mteinfo_covered_page_set_free(pnum, true);
		case VM_MEMORY_CLASS_TAG_STORAGE:
			return mteinfo_tag_storage_set_inactive(mem, false);
		default:
			break;
		}
	}
#endif /* HAS_MTE */

	color = VM_PAGE_GET_COLOR_PNUM(pnum);
	queue = vm_page_free_queue_for_class(class, color);
#if CONFIG_SPTM
	if (class == VM_MEMORY_CLASS_REGULAR && vm_pages_free_masks()) {
		uint32_t index = vm_pages_free_mask_index(pnum);
		int8_t   bit   = vm_pages_free_mask_bit(pnum);

		if (vm_pages_free_masks()[index] == 0) {
			vm_page_queue_enter(queue, mem, vmp_pageq);
			*vm_pages_free_enqueue_idx(index) = bit;
		}
		vm_pages_free_mask_set(index, bit);
	} else
#endif /* CONFIG_SPTM */
	if (enter_first) {
		vm_page_queue_enter_first(queue, mem, vmp_pageq);
	} else {
#if defined(__x86_64__)
		vm_page_queue_enter_clump(queue, mem);
#else
		vm_page_queue_enter(queue, mem, vmp_pageq);
#endif
	}

	switch (class) {
	case VM_MEMORY_CLASS_REGULAR:
		VM_COUNTER_INC(&vm_page_queue_free.vmpfq_count);
		VM_COUNTER_INC(&vm_page_free_count);
		break;
#if HAS_MTE
	case VM_MEMORY_CLASS_DEAD_TAG_STORAGE:
		VM_COUNTER_INC(&vm_page_queue_free.vmpfq_count);
		VM_COUNTER_INC(&vm_page_free_unmanaged_tag_storage_count);
		/* these do not participate to the vm page free count */
		break;
#endif
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		VM_COUNTER_INC(&vm_lopage_free_count);
		if (vm_lopage_free_count >= vm_lopage_free_limit) {
			vm_lopage_refill = false;
		}
		break;
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
	case VM_MEMORY_CLASS_SECLUDED:
		vm_page_secluded_count++;
		vm_page_secluded_count_free++;
		VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();
		break;
#endif /* CONFIG_SECLUDED_MEMORY */
	default:
		__builtin_unreachable();
	}
}

/*!
 * @typedef vmp_free_list_result_t
 *
 * @discussion
 * This data structure is used by vm_page_free_queue_add_list to track
 * how many pages were freed to which free lists, so that it can then drive
 * which waiters we are going to wake up.
 *
 * uint8_t counters are enough because we never free more than 64 pages at
 * a time, and this allows for the data structure to be passed by register.
 */
typedef struct {
	uint8_t vmpr_regular;
#if HAS_MTE
	uint8_t vmpr_taggable;
	uint8_t vmpr_tag_storage;
#endif /* HAS_MTE */
	uint8_t vmpr_lopage;
#if CONFIG_SECLUDED_MEMORY
	uint8_t vmpr_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
} vmp_free_list_result_t;

/*!
 * @abstract
 * Returns whether there are any threads blocked in VM_PAGE_WAIT().
 *
 * @discussion
 * The page free queue lock must be held.
 */
static bool
vm_page_free_queue_has_any_waiters(void)
{
	uint32_t result = 0;

	result |= vm_page_free_wanted;
	result |= vm_page_free_wanted_privileged;
#if HAS_MTE
	result |= vm_page_free_wanted_tagged;
	result |= vm_page_free_wanted_tagged_privileged;
#endif /* HAS_MTE */
#if CONFIG_SECLUDED_MEMORY
	result |= vm_page_free_wanted_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */

	return result != 0;
}

void
vm_page_free_wakeup(event_t event, uint32_t n)
{
	if (vps_dynamic_priority_enabled) {
		if (n == UINT32_MAX) {
			wakeup_all_with_inheritor(event, THREAD_AWAKENED);
		} else {
			while (n-- > 0) {
				wakeup_one_with_inheritor(event, THREAD_AWAKENED,
				    LCK_WAKE_DO_NOT_TRANSFER_PUSH, NULL);
			}
		}
	} else {
		thread_wakeup_nthreads(event, n);
	}
}

/*!
 * @abstract
 * Helper to wakeup threads in VM_PAGE_WAIT() given
 * a vm_page_free_queue_enter_list() result.
 *
 * @discussion
 * The page free queue lock must be held, and is unlocked on return.
 *
 * @param vmpr          The result of a vm_page_free_queue_enter_list() call.
 */
__attribute__((noinline))
static void
vm_page_free_queue_handle_wakeups_and_unlock(vmp_free_list_result_t vmpr)
{
	unsigned int    need_wakeup = 0;
	unsigned int    need_priv_wakeup = 0;
#if CONFIG_SECLUDED_MEMORY
	unsigned int    need_wakeup_secluded = 0;
#endif /* CONFIG_SECLUDED_MEMORY */
	unsigned int    unpriv_limit;
#if HAS_MTE
	unsigned int    need_tagged_wakeup = 0;
	unsigned int    need_priv_tagged_wakeup = 0;
	unsigned int    unpriv_tagged_limit;
	unsigned int    n;
	bool            wakeup_refill_thread = false;
#endif /* HAS_MTE */

#define DONATE_TO_WAITERS(wake, count, waiters_count, limit)  ({ \
	uint32_t __n = MIN(MIN(waiters_count, vmpr.count), limit);              \
	waiters_count -= __n;                                                   \
	vmpr.count    -= __n;                                                   \
	wake          += __n;                                                   \
	__n;                                                                    \
})

	/*
	 *	Step 1: privileged waiters get to be satisfied first
	 */
#if HAS_MTE
	if (vm_page_free_wanted_tagged_privileged) {
		DONATE_TO_WAITERS(need_priv_tagged_wakeup,
		    vmpr_taggable, vm_page_free_wanted_tagged_privileged,
		    UINT32_MAX);

		/*
		 * If we will not wake up privileged threads, and there are
		 * tagged privileged waiters, we need the refill thread to do
		 * an emergency activation or reclaim to fulfill this need.
		 *
		 * We need to at least have 2 extra free pages because the
		 * reclaim path might require to relocate a page to give us one.
		 */
		if (!need_priv_tagged_wakeup &&
		    vm_page_free_count >= vm_page_free_taggable_count + 2) {
			wakeup_refill_thread = true;
		}
	}
#endif /* HAS_MTE */
	if (vm_page_free_wanted_privileged) {
		DONATE_TO_WAITERS(need_priv_wakeup,
		    vmpr_regular, vm_page_free_wanted_privileged,
		    UINT32_MAX);
#if HAS_MTE
		DONATE_TO_WAITERS(need_priv_wakeup,
		    vmpr_taggable, vm_page_free_wanted_privileged,
		    UINT32_MAX);
#endif /* HAS_MTE */
	}


	/*
	 *	Step 2: the privileged reserve needs to be replenished
	 *
	 *	Let's make sure that we only wake up regular threads
	 *	for free pages above the reserve threshold.
	 */
	if (vm_page_free_count <= vm_page_free_reserved) {
		unpriv_limit = 0;
	} else {
		unpriv_limit = vm_page_free_count - vm_page_free_reserved;
	}
#if HAS_MTE
	if (vm_page_free_taggable_count <= vm_page_free_reserved) {
		unpriv_tagged_limit = 0;
	} else {
		unpriv_tagged_limit = vm_page_free_taggable_count -
		    vm_page_free_reserved;
	}
#endif /* HAS_MTE */

	/*
	 *	Step 3: satisfy secluded waiters, using the secluded pool first,
	 *	regular pages second.
	 */
#if CONFIG_SECLUDED_MEMORY
	if (vm_page_free_wanted_secluded) {
		DONATE_TO_WAITERS(need_wakeup_secluded,
		    vmpr_secluded, vm_page_free_wanted_secluded,
		    UINT32_MAX);
		unpriv_limit -= DONATE_TO_WAITERS(need_wakeup_secluded,
		    vmpr_regular, vm_page_free_wanted_secluded,
		    unpriv_limit);

		if (vm_page_free_wanted_secluded == 0) {
			need_wakeup_secluded = UINT32_MAX;
		}
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	/*
	 *	Step 4: satisfy regular demand last.
	 */
#if HAS_MTE
	if (vm_page_free_wanted_tagged) {
		n = DONATE_TO_WAITERS(need_tagged_wakeup,
		    vmpr_taggable, vm_page_free_wanted_tagged,
		    MIN(unpriv_limit, unpriv_tagged_limit));

		unpriv_limit -= n;
		unpriv_tagged_limit -= n;

		if (vm_page_free_wanted_tagged == 0) {
			need_tagged_wakeup = UINT32_MAX;
		} else if (vm_page_free_count >=
		    MAX(vm_page_free_taggable_count + 2, vm_page_free_min)) {
			/*
			 * If we still have tagged waiters, and that rebalancing
			 * pages would get us above vm_page_free_min, then wake
			 * up the refill thread to help do that rebalance.
			 */
			wakeup_refill_thread = true;
		}
	}
#endif /* HAS_MTE */
	if (vm_page_free_wanted) {
		unpriv_limit -= DONATE_TO_WAITERS(need_wakeup,
		    vmpr_regular, vm_page_free_wanted,
		    unpriv_limit);
#if HAS_MTE
		n = DONATE_TO_WAITERS(need_wakeup,
		    vmpr_taggable, vm_page_free_wanted,
		    MIN(unpriv_limit, unpriv_tagged_limit));

		unpriv_limit -= n;
		unpriv_tagged_limit -= n;
#endif /* HAS_MTE */
		if (vm_page_free_wanted == 0) {
			need_wakeup = UINT32_MAX;
		}
	}

	/*
	 * We have updated waiter counts, and if that release page happens
	 * from the context of a thread that's super low priority we might
	 * starve waking up privileged threads.
	 *
	 * While we hold the free page lock, such threads would wake us up via
	 * the mutex priority inheritance mechanism, but as soon as we drop the
	 * lock all bets are off.
	 *
	 * To avoid this priority inversion that could really hurt the VM,
	 * disable preemption until we've woken up everyone.
	 */
	disable_preemption();
	vm_free_page_unlock();

	/*
	 * Dispatch privileged wakeups
	 *
	 * There shouldn't be that many VM-privileged threads,
	 * so let's wake them all up, even if we don't quite
	 * have enough pages to satisfy them all.
	 */
	if (need_priv_wakeup) {
		vm_page_free_wakeup(&vm_page_free_wanted_privileged,
		    UINT32_MAX);
	}
	if (need_wakeup) {
		vm_page_free_wakeup(&vm_page_free_count, need_wakeup);
	}
#if HAS_MTE
	if (need_priv_tagged_wakeup) {
		vm_page_free_wakeup(&vm_page_free_wanted_tagged_privileged,
		    UINT32_MAX);
	}
	if (need_tagged_wakeup) {
		vm_page_free_wakeup(&vm_page_free_wanted_tagged,
		    need_tagged_wakeup);
	}
	if (wakeup_refill_thread) {
		mteinfo_wake_fill_thread();
	}
#endif /* HAS_MTE */
#if CONFIG_SECLUDED_MEMORY
	if (need_wakeup_secluded) {
		vm_page_free_wakeup(&vm_page_free_wanted_secluded,
		    need_wakeup_secluded);
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	enable_preemption();

#undef DONATE_TO_WAITERS
}

/*
 * @abstract
 * Given a list of pages, put each page on whichever global free queue is
 * appropriate.
 *
 * @discussion
 * Must be called with the VM free page lock unlocked.
 *
 * The list must contain less than 255 elements.
 */
#if HAS_MTE
/*
 * To put it more bluntly: this will demux pages onto the free tag storage
 * queue or the global free queue, as appropriate.  If we start freeing tagged
 * pages onto the free tagged queue, this function should be updated to deal
 * with that too.
 */
#endif /* HAS_MTE */
static void
vm_page_free_queue_enter_list(vm_page_list_t list, vmp_release_options_t opts)
{
	bool                   page_queues_unlock = false;
	bool                   page_queues_locked = false;
	bool                   do_secluded = false;
	vmp_free_list_result_t result = { };
	vm_page_t              mem;

	LCK_MTX_ASSERT(&vm_page_queue_lock,
	    (opts & VMP_RELEASE_Q_LOCKED)
	    ? LCK_MTX_ASSERT_OWNED
	    : LCK_MTX_ASSERT_NOTOWNED);

	/*
	 * Hibernation and startup do not really need the lock because
	 * these are single threaded paths, so from the PoV of that function,
	 * it's as if VMP_RELEASE_Q_LOCKED was passed.
	 */
	page_queues_locked = (opts & (VMP_RELEASE_STARTUP |
	    VMP_RELEASE_HIBERNATE |
	    VMP_RELEASE_Q_LOCKED));

#if CONFIG_SECLUDED_MEMORY
	do_secluded = vm_page_secluded_pool_depleted();
#if HAS_MTE
	if (do_secluded && list.vmpl_has_tagged &&
	    (opts & VMP_RELEASE_Q_LOCKED) == 0) {
		/*
		 * Try to do the untagging so that pages become eligible
		 * for the secluded pool while holding the least amount
		 * of locks possible.
		 *
		 * This does mean we shouldn't do this retyping if the page
		 * queue lock is held for real. The only path doing this
		 * right now is vm_page_free() which is one page at a time,
		 * so it's probably "fine" to not contribute these to the
		 * secluded pool.
		 *
		 * Note that we don't update `vmp_using_mte` or the list
		 * `vmpl_has_[un]tagged` fields until we have the free queue
		 * lock. We also need to update MTE Info about these
		 * tagging changes.
		 */
		const unified_page_list_t pmap_batch_list = {
			.page_slist = list.vmpl_head,
			.type = UNIFIED_PAGE_LIST_TYPE_VM_PAGE_LIST,
		};

		pmap_unmake_tagged_pages(&pmap_batch_list);
	}
#endif /* HAS_MTE */
#endif /* CONFIG_SECLUDED_MEMORY */

	if (!page_queues_locked && (list.vmpl_has_realtime || do_secluded)) {
		vm_page_lock_queues();
		page_queues_locked = true;
		page_queues_unlock = true;
	}

	if (opts & VMP_RELEASE_STARTUP) {
		LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);
	} else {
		vm_free_page_lock_spin();
	}

#if CONFIG_SECLUDED_MEMORY && HAS_MTE
	if (do_secluded && list.vmpl_has_tagged &&
	    (opts & VMP_RELEASE_Q_LOCKED) == 0) {
		/*
		 * Update the pages and list metadata, as well as MTE Info.
		 *
		 * Since secluded pages are managed separately from the global
		 * free queue, we don't want MTE Info to think these pages are
		 * free, so we just clear the tagging.
		 */
		vm_page_list_foreach(mem, list) {
			if (mem->vmp_using_mte) {
				mteinfo_covered_page_clear_tagged(VM_PAGE_GET_PHYS_PAGE(mem));
			}
			mem->vmp_using_mte = false;
		}
		list.vmpl_has_tagged = false;
		list.vmpl_has_untagged = true;
	}
#endif /* CONFIG_SECLUDED_MEMORY && HAS_MTE */

	vm_page_list_foreach_consume(mem, &list) {
		ppnum_t pnum = VM_PAGE_GET_PHYS_PAGE(mem);
		vm_memory_class_t class = vm_page_get_memory_class(mem, pnum);

		if (mem->vmp_realtime) {
			mem->vmp_realtime = false;
			VM_COUNTER_DEC(&vm_page_realtime_count);
		}

#if XNU_VM_HAS_LOPAGE
		if ((class == VM_MEMORY_CLASS_REGULAR ||
		    class == VM_MEMORY_CLASS_LOPAGE) &&
		    vm_lopage_refill &&
		    vm_lopage_free_count < vm_lopage_free_limit &&
		    pnum < max_valid_low_ppnum) {
			class = VM_MEMORY_CLASS_LOPAGE;
		} else {
			class = VM_MEMORY_CLASS_REGULAR;
		}
#endif /* XNU_VM_HAS_LOPAGE */

#if CONFIG_SECLUDED_MEMORY
		/*
		 * XXX FBDP TODO: also avoid refilling secluded queue
		 * when some IOKit objects are already grabbing from it...
		 */
		if (page_queues_locked &&
		    vm_page_secluded_pool_eligible(class) &&
		    vm_page_secluded_pool_depleted()) {
			class = VM_MEMORY_CLASS_SECLUDED;
		}
#endif /* CONFIG_SECLUDED_MEMORY */

		vm_page_free_queue_enter(class, mem, pnum);

		switch (class) {
		case VM_MEMORY_CLASS_REGULAR:
#if HAS_MTE
			if (mte_enabled() && mteinfo_covered_page_taggable(pnum)) {
				result.vmpr_taggable++;
				break;
			}
			OS_FALLTHROUGH;
		case VM_MEMORY_CLASS_DEAD_TAG_STORAGE:
#endif /* HAS_MTE */
			result.vmpr_regular++;
			break;
#if HAS_MTE
		case VM_MEMORY_CLASS_TAGGED:
			result.vmpr_taggable++;
			break;
		case VM_MEMORY_CLASS_TAG_STORAGE:
			result.vmpr_tag_storage++;
			break;
#endif /* HAS_MTE */
#if XNU_VM_HAS_LOPAGE
		case VM_MEMORY_CLASS_LOPAGE:
			result.vmpr_lopage++;
			break;
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
		case VM_MEMORY_CLASS_SECLUDED:
			result.vmpr_secluded++;
			continue;
#endif /* CONFIG_SECLUDED_MEMORY */
		}
	}

	if (page_queues_unlock) {
		vm_page_unlock_queues();
	}

	vm_pageout_vminfo.vm_page_pages_freed += list.vmpl_count;
	VM_DEBUG_CONSTANT_EVENT(vm_page_release, DBG_VM_PAGE_RELEASE,
	    DBG_FUNC_NONE, list.vmpl_count, 0, 0, 0);

	if (opts & VMP_RELEASE_STARTUP) {
		/*
		 * On purpose skip the VM_CHECK_MEMORYSTATUS,
		 * pmap_startup() will do it,
		 * and the caller holds the free queue lock the whole time.
		 */
		return;
	}

	if (vm_page_free_queue_has_any_waiters()) {
		vm_page_free_queue_handle_wakeups_and_unlock(result);
	} else {
		vm_free_page_unlock();
	}

	if ((opts & VMP_RELEASE_HIBERNATE) == 0) {
		/*
		 * Skip VM_CHECK_MEMORYSTATUS here as
		 * hibernate_rebuild_vm_structs() will run it after the last flush.
		 */
		VM_CHECK_MEMORYSTATUS;
	}
}

__attribute__((always_inline))
void
vm_page_free_queue_remove(
	vm_memory_class_t       class,
	vm_page_t               mem,
	ppnum_t                 pnum,
	vm_page_q_state_t       q_state)
{
	unsigned int    color;
	vm_page_queue_t queue;

	if (startup_phase >= STARTUP_SUB_KMEM) {
		LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);
	}

	mem->vmp_q_state = q_state;

#if HAS_MTE
	if (mte_enabled()) {
		switch (class) {
		case VM_MEMORY_CLASS_REGULAR:
			return mteinfo_covered_page_set_used(pnum, false);
		case VM_MEMORY_CLASS_TAGGED:
			return mteinfo_covered_page_set_used(pnum, true);
		case VM_MEMORY_CLASS_TAG_STORAGE:
			return mteinfo_tag_storage_set_claimed(mem);
		default:
			break;
		}
	}
#endif /* HAS_MTE */

	color = VM_PAGE_GET_COLOR_PNUM(pnum);
	queue = vm_page_free_queue_for_class(class, color);
#if CONFIG_SPTM
	if (class == VM_MEMORY_CLASS_REGULAR && vm_pages_free_masks()) {
		uint32_t index = vm_pages_free_mask_index(pnum);
		int8_t   bit   = vm_pages_free_mask_bit(pnum);

		vm_pages_free_mask_clear(index, bit);
		if (*vm_pages_free_enqueue_idx(index) == bit) {
			vm_page_queue_remove(queue, mem, vmp_pageq);
			bit = vm_pages_free_mask_next_bit(index, bit);
			*vm_pages_free_enqueue_idx(index) = bit;

			if (bit != -1) {
				assert(vm_pages_free_mask_test(index, bit));
				pnum  = (pnum & -MAX_COLORS) + bit;
				mem   = vm_page_find_canonical(pnum);
				color = VM_PAGE_GET_COLOR_PNUM(pnum);
				queue = vm_page_free_queue_for_class(class, color);
				vm_page_queue_enter(queue, mem, vmp_pageq);
			}
		}
	} else
#endif /* CONFIG_SPTM */
	{
		vm_page_queue_remove(queue, mem, vmp_pageq);
	}

	switch (class) {
	case VM_MEMORY_CLASS_REGULAR:
		VM_COUNTER_DEC(&vm_page_queue_free.vmpfq_count);
		VM_COUNTER_DEC(&vm_page_free_count);
		break;
#if HAS_MTE
	case VM_MEMORY_CLASS_DEAD_TAG_STORAGE:
		VM_COUNTER_DEC(&vm_page_queue_free.vmpfq_count);
		VM_COUNTER_DEC(&vm_page_free_unmanaged_tag_storage_count);
		/* these do not participate to the vm page free count */
		break;
#endif /* HAS_MTE */
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		VM_COUNTER_DEC(&vm_lopage_free_count);
		vm_lopages_allocated_q += 1;
		if (vm_lopage_free_count < vm_lopage_lowater) {
			vm_lopage_refill = true;
		}
		break;
#endif /* XNU_VM_HAS_LOPAGE */
	default:
		__builtin_unreachable();
	}
}

vm_page_list_t
vm_page_free_queue_grab(
	vm_page_pcpu_t          vmp_pcpu,
	vm_grab_options_t       options __unused,
	vm_memory_class_t       class,
	unsigned int            num_pages,
	vm_page_q_state_t       q_state)
{
	unsigned int   color;
#if defined(__x86_64__)
	unsigned int   clump_end = 1;
	unsigned int   sub_count = 0;
#endif /* __x86_64__ */
	vm_page_list_t list      = { };

	if (startup_phase >= STARTUP_SUB_KMEM) {
		LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);
	}
	assert(get_preemption_level() != 0);
	assert3u(q_state, <, VM_PAGE_NUM_Q_STATES);

#if HAS_MTE
	if (mte_enabled() && class != VM_MEMORY_CLASS_DEAD_TAG_STORAGE) {
		return mteinfo_free_queue_grab(vmp_pcpu, options, class, num_pages, q_state);
	}
#endif /* HAS_MTE */

	color  = vmp_pcpu->start_color;

	/* Get the pages. */
	while (list.vmpl_count < num_pages) {
		uint32_t        color_offset = 1;
		vm_page_queue_t queue;
		vm_page_t       mem;

		queue = vm_page_free_queue_for_class(class, color);
		if (!vm_page_free_queue_has_colors(class)) {
			assert(!vm_page_queue_empty(queue));
			color_offset = 0;
		}
		while (vm_page_queue_empty(queue)) {
			color = (color + 1) & vm_color_mask;
			queue = vm_page_free_queue_for_class(class, color);
		}

#if defined(__x86_64__)
		if (class == VM_MEMORY_CLASS_REGULAR) {
			/*
			 * x86_64 uses a bespoke free queue scheme, where the free path
			 * tries to cluster clumps of contiguous pages together on
			 * the free queue to optimize for the platform's memory
			 * controller.
			 */
			vm_page_queue_remove_first_with_clump(queue, mem, clump_end);
			sub_count++;
			if (clump_end) {
#if DEVELOPMENT || DEBUG
				vm_clump_update_stats(sub_count);
#endif /* !DEVELOPMENT && !DEBUG */
				sub_count = 0;
			} else {
				/* Only change colors at the end of a clump. */
				color_offset = 0;
			}
		} else
#endif /* !defined(__x86_64__) */
		{
			/* Other targets default to rotating colors after each pop. */
			vm_page_queue_remove_first(queue, mem, vmp_pageq);
		}

#if CONFIG_SPTM
		if (vm_pages_free_masks()) {
			ppnum_t   pnum       = VM_PAGE_GET_PHYS_PAGE(mem);
			ppnum_t   first_pnum = pnum & -MAX_COLORS;
			uint32_t  index      = vm_pages_free_mask_index(pnum);
			int8_t    bit        = vm_pages_free_mask_bit(pnum);

			for (;;) {
				vm_pages_free_mask_clear(index, bit);
				mem->vmp_q_state = q_state;
				vm_page_list_push(&list, mem);

				bit = (bit + 1) & (MAX_COLORS - 1);

				if (!vm_pages_free_mask_test(index, bit) ||
				    num_pages <= list.vmpl_count) {
					break;
				}
				mem = vm_page_find_canonical(first_pnum + bit);
			}

			color = bit & vm_color_mask;

			bit = vm_pages_free_mask_next_bit(index, bit);
			*vm_pages_free_enqueue_idx(index) = bit;

			if (bit != -1) {
				assert(vm_pages_free_mask_test(index, bit));
				mem   = vm_page_find_canonical(first_pnum + bit);
				queue = vm_page_free_queue_for_class(class,
				    bit & vm_color_mask);
				vm_page_queue_enter_first(queue, mem, vmp_pageq);
			}
		} else
#endif /* CONFIG_SPTM */
		{
			/* Set the page to the client's desired queue state. */
			mem->vmp_q_state = q_state;
			vm_page_list_push(&list, mem);

			color = (color + color_offset) & vm_color_mask;
		}
	}

	switch (class) {
	case VM_MEMORY_CLASS_REGULAR:
		VM_COUNTER_SUB(&vm_page_queue_free.vmpfq_count, list.vmpl_count);
		VM_COUNTER_SUB(&vm_page_free_count, list.vmpl_count);
		break;
#if HAS_MTE
	case VM_MEMORY_CLASS_DEAD_TAG_STORAGE:
		VM_COUNTER_SUB(&vm_page_queue_free.vmpfq_count, list.vmpl_count);
		VM_COUNTER_SUB(&vm_page_free_unmanaged_tag_storage_count, list.vmpl_count);
		/* these do not participate to the vm page free count */
		break;
#endif /* HAS_MTE */
#if XNU_VM_HAS_LOPAGE
	case VM_MEMORY_CLASS_LOPAGE:
		VM_COUNTER_SUB(&vm_lopage_free_count, list.vmpl_count);
		vm_lopages_allocated_q += list.vmpl_count;
		if (vm_lopage_free_count < vm_lopage_lowater) {
			vm_lopage_refill = true;
		}
		break;
#endif /* XNU_VM_HAS_LOPAGE */
	default:
		__builtin_unreachable();
	}

	/* Record the next page color the CPU should try to get. */
	vmp_pcpu->start_color = color;
#if defined(__x86_64__) && (DEVELOPMENT || DEBUG)
	vm_clump_update_stats(sub_count);
#endif /* defined(__x86_64__) && (DEVELOPMENT || DEBUG) */

	return list;
}


#define COLOR_GROUPS_TO_STEAL   4

/* Called once during statup, once the cache geometry is known.
 */
static void
vm_page_set_colors( void )
{
	unsigned int    n, override;

#if defined (__x86_64__)
	/* adjust #colors because we need to color outside the clump boundary */
	vm_cache_geometry_colors >>= vm_clump_shift;
#endif
	if (PE_parse_boot_argn("colors", &override, sizeof(override))) {                /* colors specified as a boot-arg? */
		n = override;
	} else if (vm_cache_geometry_colors) {                  /* do we know what the cache geometry is? */
		n = vm_cache_geometry_colors;
	} else {
		n = DEFAULT_COLORS;                             /* use default if all else fails */
	}
	if (n == 0) {
		n = 1;
	}
	if (n > MAX_COLORS) {
		n = MAX_COLORS;
	}

	/* the count must be a power of 2  */
	if ((n & (n - 1)) != 0) {
		n = DEFAULT_COLORS;                             /* use default if all else fails */
	}
	vm_colors = n;
	vm_color_mask = n - 1;

	vm_free_magazine_refill_limit = vm_colors * COLOR_GROUPS_TO_STEAL;

#if defined (__x86_64__)
	/* adjust for reduction in colors due to clumping and multiple cores */
	if (real_ncpus) {
		vm_free_magazine_refill_limit *= (vm_clump_size * real_ncpus);
	}
#endif
}

#if XNU_VM_HAS_DELAYED_PAGES

static uint32_t vm_delayed_count = 0;    /* when non-zero, indicates we may have more pages to init */
static ppnum_t delay_above_pnum = PPNUM_MAX;

/*
 * For x86 first 8 Gig initializes quickly and gives us lots of lowmem + mem above to start off with.
 * If ARM ever uses delayed page initialization, this value may need to be quite different.
 */
#define DEFAULT_DELAY_ABOVE_PHYS_GB (8)

/*
 * When we have to dip into more delayed pages due to low memory, free up
 * a large chunk to get things back to normal. This avoids contention on the
 * delayed code allocating page by page.
 */
#define VM_DELAY_PAGE_CHUNK ((1024 * 1024 * 1024) / PAGE_SIZE)

/*
 * Get and initialize the next delayed page.
 */
__attribute__((noinline))
static vm_page_t
vm_get_delayed_page(vm_grab_options_t grab_options)
{
	vm_page_t p;
	ppnum_t   pnum;

	/*
	 * Get a new page if we have one.
	 */
	vm_free_page_lock();
	if (vm_delayed_count == 0) {
		vm_free_page_unlock();
		return NULL;
	}

	if (!pmap_next_page(&pnum)) {
		vm_delayed_count = 0;
		vm_free_page_unlock();
		return NULL;
	}


	assert(vm_delayed_count > 0);
	--vm_delayed_count;

#if defined(__x86_64__)
	/* x86 cluster code requires increasing phys_page in vm_pages[] */
	if (vm_pages_count > 0) {
		assert(pnum > vm_page_get(vm_pages_count - 1)->vmp_phys_page);
	}
#endif
	p = vm_page_get(vm_pages_count);
	assert(p < vm_pages_end);
	vm_page_init(p, pnum);
	++vm_pages_count;
	++vm_page_pages;
	vm_free_page_unlock();

	/*
	 * These pages were initially counted as wired, undo that now.
	 */
	if (grab_options & VM_PAGE_GRAB_Q_LOCK_HELD) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	} else {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
		vm_page_lockspin_queues();
	}
	--vm_page_wire_count;
	--vm_page_wire_count_initial;
	if (vm_page_wire_count_on_boot != 0) {
		--vm_page_wire_count_on_boot;
	}
	if (!(grab_options & VM_PAGE_GRAB_Q_LOCK_HELD)) {
		vm_page_unlock_queues();
	}


	if (fillval) {
		fillPage(pnum, fillval);
	}
	return p;
}

/*
 * Free all remaining delayed pages to the free lists.
 */
void
vm_free_delayed_pages(void)
{
	vm_page_t   p;
	vm_page_t   list = NULL;
	uint_t      cnt = 0;
	vm_offset_t start_free_va;
	int64_t     free_size;

	while ((p = vm_get_delayed_page(VM_PAGE_GRAB_OPTIONS_NONE)) != NULL) {
		if (vm_himemory_mode) {
			vm_page_release(p, VMP_RELEASE_NONE);
		} else {
			p->vmp_snext = list;
			list = p;
		}
		++cnt;
	}

	/*
	 * Free the pages in reverse order if not himemory mode.
	 * Hence the low memory pages will be first on free lists. (LIFO)
	 */
	while (list != NULL) {
		p = list;
		list = p->vmp_snext;
		p->vmp_snext = NULL;
		vm_page_release(p, VMP_RELEASE_NONE);
	}
#if DEVELOPMENT || DEBUG
	kprintf("vm_free_delayed_pages: initialized %d free pages\n", cnt);
#endif

	/*
	 * Free up any unused full pages at the end of the vm_pages[] array
	 */
	start_free_va = round_page((vm_offset_t)vm_page_get(vm_pages_count));

#if defined(__x86_64__)
	/*
	 * Since x86 might have used large pages for vm_pages[], we can't
	 * free starting in the middle of a partially used large page.
	 */
	if (pmap_query_pagesize(kernel_pmap, start_free_va) == I386_LPGBYTES) {
		start_free_va = ((start_free_va + I386_LPGMASK) & ~I386_LPGMASK);
	}
#endif
	if (start_free_va < (vm_offset_t)vm_pages_end) {
		free_size = trunc_page((vm_offset_t)vm_pages_end - start_free_va);
		if (free_size > 0) {
			ml_static_mfree(start_free_va, (vm_offset_t)free_size);
			vm_pages_end = (void *)start_free_va;

			/*
			 * Note there's no locking here, as only this thread will ever change this value.
			 * The reader, vm_page_diagnose, doesn't grab any locks for the counts it looks at.
			 */
			vm_page_stolen_count -= (free_size >> PAGE_SHIFT);

#if DEVELOPMENT || DEBUG
			kprintf("Freeing final unused %ld bytes from vm_pages[] at 0x%lx\n",
			    (long)free_size, (long)start_free_va);
#endif
		}
	}
}

/*
 * Try and free up enough delayed pages to match a contig memory allocation.
 */
static void
vm_free_delayed_pages_contig(
	uint_t    npages,
	ppnum_t   max_pnum,
	ppnum_t   pnum_mask)
{
	vm_page_t p;
	ppnum_t   pnum;
	uint_t    cnt = 0;

	/*
	 * Treat 0 as the absolute max page number.
	 */
	if (max_pnum == 0) {
		max_pnum = PPNUM_MAX;
	}

	/*
	 * Free till we get a properly aligned start page
	 */
	for (;;) {
		p = vm_get_delayed_page(VM_PAGE_GRAB_OPTIONS_NONE);
		if (p == NULL) {
			return;
		}
		pnum = VM_PAGE_GET_PHYS_PAGE(p);
		vm_page_release(p, VMP_RELEASE_NONE);
		if (pnum >= max_pnum) {
			return;
		}
		if ((pnum & pnum_mask) == 0) {
			break;
		}
	}

	/*
	 * Having a healthy pool of free pages will help performance. We don't
	 * want to fall back to the delayed code for every page allocation.
	 */
	if (vm_page_free_count < VM_DELAY_PAGE_CHUNK) {
		npages += VM_DELAY_PAGE_CHUNK;
	}

	/*
	 * Now free up the pages
	 */
	for (cnt = 1; cnt < npages; ++cnt) {
		p = vm_get_delayed_page(VM_PAGE_GRAB_OPTIONS_NONE);
		if (p == NULL) {
			return;
		}
		vm_page_release(p, VMP_RELEASE_NONE);
	}
}

#endif /* XNU_VM_HAS_DELAYED_PAGES */

#define ROUNDUP_NEXTP2(X) (1U << (32 - __builtin_clz((X) - 1)))

void
vm_page_init_local_q(unsigned int num_cpus)
{
	struct vpl *t_local_q;

	/*
	 * no point in this for a uni-processor system
	 */
	if (num_cpus >= 2) {
		ml_cpu_info_t cpu_info;

		/*
		 * Force the allocation alignment to a cacheline,
		 * because the `vpl` struct has a lock and will be taken
		 * cross CPU so we want to isolate the rest of the per-CPU
		 * data to avoid false sharing due to this lock being taken.
		 */

		ml_cpu_get_info(&cpu_info);

		t_local_q = zalloc_percpu_permanent(sizeof(struct vpl),
		    cpu_info.cache_line_size - 1);

		zpercpu_foreach(lq, t_local_q) {
			VPL_LOCK_INIT(lq, &vm_page_lck_grp_local, &vm_page_lck_attr);
			vm_page_queue_init(&lq->vpl_queue);
		}

		/* make the initialization visible to all cores */
		os_atomic_store(&vm_page_local_q, t_local_q, release);
	}
}

/*
 * vm_init_before_launchd
 *
 * This should be called right before launchd is loaded.
 */
void
vm_init_before_launchd(void)
{
	vm_page_lockspin_queues();
	vm_page_wire_count_on_boot = vm_page_wire_count;
	vm_page_unlock_queues();
}


/*
 *	vm_page_bootstrap:
 *
 *	Initializes the resident memory module.
 *
 *	Allocates memory for the page cells, and
 *	for the object/offset-to-page hash table headers.
 *	Each page cell is initialized and placed on the free list.
 *	Returns the range of available kernel virtual memory.
 */
__startup_func
void
vm_page_bootstrap(
	vm_offset_t             *startp,
	vm_offset_t             *endp)
{
	unsigned int            i;
	unsigned int            log1;
	unsigned int            log2;
	unsigned int            size;

	/*
	 *	Initialize the page queues.
	 */

	lck_mtx_init(&vm_page_queue_free_lock, &vm_page_lck_grp_free, &vm_page_lck_attr);
	lck_mtx_init(&vm_page_queue_lock, &vm_page_lck_grp_queue, &vm_page_lck_attr);
	lck_mtx_init(&vm_purgeable_queue_lock, &vm_page_lck_grp_purge, &vm_page_lck_attr);

	for (i = 0; i < PURGEABLE_Q_TYPE_MAX; i++) {
		int group;

		purgeable_queues[i].token_q_head = 0;
		purgeable_queues[i].token_q_tail = 0;
		for (group = 0; group < NUM_VOLATILE_GROUPS; group++) {
			queue_init(&purgeable_queues[i].objq[group]);
		}

		purgeable_queues[i].type = i;
		purgeable_queues[i].new_pages = 0;
#if MACH_ASSERT
		purgeable_queues[i].debug_count_tokens = 0;
		purgeable_queues[i].debug_count_objects = 0;
#endif
	}
	;
	purgeable_nonvolatile_count = 0;
	queue_init(&purgeable_nonvolatile_queue);

	vm_page_free_queue_init(&vm_page_queue_free);
#if XNU_VM_HAS_LOPAGE
	vm_page_queue_init(&vm_lopage_queue_free);
#endif /* XNU_VM_HAS_LOPAGE */
	vm_page_queue_init(&vm_page_queue_active);
	vm_page_queue_init(&vm_page_queue_inactive);
#if CONFIG_SECLUDED_MEMORY
	vm_page_queue_init(&vm_page_queue_secluded);
#endif /* CONFIG_SECLUDED_MEMORY */
	vm_page_queue_init(&vm_page_queue_cleaned);
	vm_page_queue_init(&vm_page_queue_throttled);
	vm_page_queue_init(&vm_page_queue_anonymous);
	queue_init(&vm_objects_wired);

	for (i = 0; i <= vm_page_max_speculative_age_q; i++) {
		vm_page_queue_init(&vm_page_queue_speculative[i].age_q);

		vm_page_queue_speculative[i].age_ts.tv_sec = 0;
		vm_page_queue_speculative[i].age_ts.tv_nsec = 0;
	}

	vm_page_queue_init(&vm_page_queue_donate);
	vm_page_queue_init(&vm_page_queue_background);

	vm_page_background_count = 0;
	vm_page_background_internal_count = 0;
	vm_page_background_external_count = 0;
	vm_page_background_promoted_count = 0;

	vm_page_background_target = (unsigned int)(atop_64(max_mem) / 25);

	if (vm_page_background_target > VM_PAGE_BACKGROUND_TARGET_MAX) {
		vm_page_background_target = VM_PAGE_BACKGROUND_TARGET_MAX;
	}

#if    defined(__LP64__)
	vm_page_background_mode = VM_PAGE_BG_ENABLED;
	vm_page_donate_mode = VM_PAGE_DONATE_ENABLED;
#else
	vm_page_background_mode = VM_PAGE_BG_DISABLED;
	vm_page_donate_mode = VM_PAGE_DONATE_DISABLED;
#endif
	vm_page_background_exclude_external = 0;

	PE_parse_boot_argn("vm_page_bg_mode", &vm_page_background_mode, sizeof(vm_page_background_mode));
	PE_parse_boot_argn("vm_page_bg_exclude_external", &vm_page_background_exclude_external, sizeof(vm_page_background_exclude_external));
	PE_parse_boot_argn("vm_page_bg_target", &vm_page_background_target, sizeof(vm_page_background_target));

	if (vm_page_background_mode != VM_PAGE_BG_DISABLED && vm_page_background_mode != VM_PAGE_BG_ENABLED) {
		vm_page_background_mode = VM_PAGE_BG_DISABLED;
	}

	PE_parse_boot_argn("vm_page_donate_mode", &vm_page_donate_mode, sizeof(vm_page_donate_mode));
	if (vm_page_donate_mode != VM_PAGE_DONATE_DISABLED && vm_page_donate_mode != VM_PAGE_DONATE_ENABLED) {
		vm_page_donate_mode = VM_PAGE_DONATE_DISABLED;
	}

	vm_page_donate_target_high = VM_PAGE_DONATE_TARGET_HIGHWATER;
	vm_page_donate_target_low = VM_PAGE_DONATE_TARGET_LOWWATER;
	vm_page_donate_target = vm_page_donate_target_high;
	vm_page_donate_count = 0;

	vm_page_free_wanted = 0;
	vm_page_free_wanted_privileged = 0;
#if CONFIG_SECLUDED_MEMORY
	vm_page_free_wanted_secluded = 0;
#endif /* CONFIG_SECLUDED_MEMORY */

#if defined (__x86_64__)
	/* this must be called before vm_page_set_colors() */
	vm_page_setup_clump();
#endif

	vm_page_set_colors();

	for (vm_tag_t t = 0; t < VM_KERN_MEMORY_FIRST_DYNAMIC; t++) {
		vm_allocation_sites_static[t].refcount = 2;
		vm_allocation_sites_static[t].tag = t;
		vm_allocation_sites[t] = &vm_allocation_sites_static[t];
	}
	vm_allocation_sites_static[VM_KERN_MEMORY_FIRST_DYNAMIC].refcount = 2;
	vm_allocation_sites_static[VM_KERN_MEMORY_FIRST_DYNAMIC].tag = VM_KERN_MEMORY_ANY;
	vm_allocation_sites[VM_KERN_MEMORY_ANY] = &vm_allocation_sites_static[VM_KERN_MEMORY_FIRST_DYNAMIC];

	/*
	 *	Steal memory for the map and zone subsystems.
	 *
	 *	make sure initialize_ram_ranges() has run before we steal pages for the first time on arm
	 */
	(void)pmap_free_pages();

	kernel_startup_initialize_upto(STARTUP_SUB_PMAP_STEAL);

	/*
	 *	Allocate (and initialize) the virtual-to-physical
	 *	table hash buckets.
	 *
	 *	The number of buckets should be a power of two to
	 *	get a good hash function.  The following computation
	 *	chooses the first power of two that is greater
	 *	than the number of physical pages in the system.
	 */

	vm_page_bucket_count      = 1u << fls(pmap_free_pages());
	vm_page_hash_mask         = vm_page_bucket_count - 1;
	vm_page_bucket_lock_count = (vm_page_bucket_count + BUCKETS_PER_LOCK - 1) / BUCKETS_PER_LOCK;

	/*
	 *	Calculate object shift value for hashing algorithm:
	 *		O = log2(sizeof(struct vm_object))
	 *		B = log2(vm_page_bucket_count)
	 *	        hash shifts the object left by
	 *		B/2 - O
	 */
	size = vm_page_bucket_count;
	for (log1 = 0; size > 1; log1++) {
		size /= 2;
	}
	size = sizeof(struct vm_object);
	for (log2 = 0; size > 1; log2++) {
		size /= 2;
	}
	vm_page_hash_shift = log1 / 2 - log2 + 1;

	vm_page_bucket_hash = 1 << ((log1 + 1) >> 1);           /* Get (ceiling of sqrt of table size) */
	vm_page_bucket_hash |= 1 << ((log1 + 1) >> 2);          /* Get (ceiling of quadroot of table size) */
	vm_page_bucket_hash |= 1;                                                       /* Set bit and add 1 - always must be 1 to insure unique series */

	if (vm_page_hash_mask & vm_page_bucket_count) {
		printf("vm_page_bootstrap: WARNING -- strange page hash\n");
	}

#if VM_PAGE_BUCKETS_CHECK
#if VM_PAGE_FAKE_BUCKETS
	/*
	 * Allocate a decoy set of page buckets, to detect
	 * any stomping there.
	 */
	vm_page_fake_buckets = (vm_page_bucket_t *)
	    pmap_steal_memory(vm_page_bucket_count *
	    sizeof(vm_page_bucket_t), 0);
	vm_page_fake_buckets_start = (vm_map_offset_t) vm_page_fake_buckets;
	vm_page_fake_buckets_end =
	    vm_map_round_page((vm_page_fake_buckets_start +
	    (vm_page_bucket_count *
	    sizeof(vm_page_bucket_t))),
	    PAGE_MASK);
	char *cp;
	for (cp = (char *)vm_page_fake_buckets_start;
	    cp < (char *)vm_page_fake_buckets_end;
	    cp++) {
		*cp = 0x5a;
	}
#endif /* VM_PAGE_FAKE_BUCKETS */
#endif /* VM_PAGE_BUCKETS_CHECK */

	kernel_debug_string_early("vm_page_buckets");
	vm_page_buckets = (vm_page_bucket_t *)
	    pmap_steal_memory(vm_page_bucket_count *
	    sizeof(vm_page_bucket_t), 0);

	kernel_debug_string_early("vm_page_bucket_locks");
	vm_page_bucket_locks = (hw_lck_ticket_t *)
	    pmap_steal_memory(vm_page_bucket_lock_count *
	    sizeof(hw_lck_ticket_t), 0);

	for (i = 0; i < vm_page_bucket_count; i++) {
		vm_page_bucket_t *bucket = &vm_page_buckets[i];

		bucket->page_list = VM_PAGE_PACK_PTR(VM_PAGE_NULL);
#if     MACH_PAGE_HASH_STATS
		bucket->cur_count = 0;
		bucket->hi_count = 0;
#endif /* MACH_PAGE_HASH_STATS */
	}

	for (i = 0; i < vm_page_bucket_lock_count; i++) {
		hw_lck_ticket_init(&vm_page_bucket_locks[i], &vm_page_lck_grp_bucket);
	}

	vm_tag_init();

#if VM_PAGE_BUCKETS_CHECK
	vm_page_buckets_check_ready = TRUE;
#endif /* VM_PAGE_BUCKETS_CHECK */

	/*
	 *	Machine-dependent code allocates the resident page table.
	 *	It uses vm_page_init to initialize the page frames.
	 *	The code also returns to us the virtual space available
	 *	to the kernel.  We don't trust the pmap module
	 *	to get the alignment right.
	 */

	kernel_debug_string_early("pmap_startup");
	pmap_startup(&virtual_space_start, &virtual_space_end);
	virtual_space_start = round_page(virtual_space_start);
	virtual_space_end = trunc_page(virtual_space_end);

	*startp = virtual_space_start;
	*endp = virtual_space_end;

	/*
	 *	Compute the initial "wire" count.
	 *	Up until now, the pages which have been set aside are not under
	 *	the VM system's control, so although they aren't explicitly
	 *	wired, they nonetheless can't be moved. At this moment,
	 *	all VM managed pages are "free", courtesy of pmap_startup.
	 */
	assert((unsigned int) atop_64(max_mem) == atop_64(max_mem));
	vm_page_wire_count = ((unsigned int) atop_64(max_mem)) -
	    vm_page_free_count - vm_lopage_free_count;
#if CONFIG_SECLUDED_MEMORY
	vm_page_wire_count -= vm_page_secluded_count;
#endif
#if HAS_MTE
	/*
	 * Discount any tag storage pages that we have set aside in
	 * vm_page_release_startup().
	 */
	vm_page_wire_count -= pmap_tag_storage_in_range_count();
#endif
	vm_page_wire_count_initial = vm_page_wire_count;

	/* capture this for later use */
	booter_size = ml_get_booter_memory_size();

	printf("vm_page_bootstrap: %d free pages, %d wired pages"
#if XNU_VM_HAS_DELAYED_PAGES
	    ", (up to %d of which are delayed free)"
#endif /* XNU_VM_HAS_DELAYED_PAGES */
	    "%c",
	    vm_page_free_count,
	    vm_page_wire_count,
#if XNU_VM_HAS_DELAYED_PAGES
	    vm_delayed_count,
#endif /* XNU_VM_HAS_DELAYED_PAGES */
	    '\n');

	kernel_debug_string_early("vm_page_bootstrap complete");
}

#ifndef MACHINE_PAGES
/*
 * This is the early boot time allocator for data structures needed to bootstrap the VM system.
 * On x86 it will allocate large pages if size is sufficiently large. We don't need to do this
 * on ARM yet, due to the combination of a large base page size and smaller RAM devices.
 */
__static_testable void *
pmap_steal_memory_internal(
	vm_size_t size,
	vm_size_t alignment,
	boolean_t might_free,
	unsigned int flags,
	pmap_mapping_type_t mapping_type)
{
	kern_return_t kr;
	vm_offset_t addr;
	vm_offset_t end = 0;
	vm_offset_t map_addr;
	ppnum_t phys_page;
	unsigned int pmap_flags;

	if (size > UINT64_MAX - sizeof(void *)) {
		panic("pmap_steal_memory(): size: 0x%lx", size);
	}
	/*
	 * Size needs to be aligned to word size.
	 */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	/*
	 * Alignment defaults to word size if not specified.
	 */
	if (alignment == 0) {
		alignment = sizeof(void*);
	}

	/*
	 * Alignment must be no greater than a page and must be a power of two.
	 */
	assert(alignment <= PAGE_SIZE);
	assert((alignment & (alignment - 1)) == 0);

	/*
	 * On the first call, get the initial values for virtual address space
	 * and page align them.
	 */
	if (virtual_space_start == virtual_space_end) {
		pmap_virtual_space(&virtual_space_start, &virtual_space_end);
		virtual_space_start = round_page(virtual_space_start);
		virtual_space_end = trunc_page(virtual_space_end);

#if defined(__x86_64__)
		/*
		 * Release remaining unused section of preallocated KVA and the 4K page tables
		 * that map it. This makes the VA available for large page mappings.
		 */
		Idle_PTs_release(virtual_space_start, virtual_space_end);
#endif
	}

	/*
	 * Allocate the virtual space for this request. On x86, we'll align to a large page
	 * address if the size is big enough to back with at least 1 large page.
	 */
#if defined(__x86_64__)
	if (size >= I386_LPGBYTES) {
		virtual_space_start = ((virtual_space_start + I386_LPGMASK) & ~I386_LPGMASK);
	}
#endif
	virtual_space_start = (virtual_space_start + (alignment - 1)) & ~(alignment - 1);
	addr = virtual_space_start;
	virtual_space_start += size;

	//kprintf("pmap_steal_memory: %08lX - %08lX; size=%08lX\n", (long)addr, (long)virtual_space_start, (long)size);	/* (TEST/DEBUG) */

	/*
	 * Allocate and map physical pages to back the new virtual space.
	 */
	map_addr = round_page(addr);
	if (os_add_overflow(addr, size, &end)) {
		panic("pmap_steal_memory() overflow, addr: %lx, size: 0x%lx", addr, size);
	}
	while (map_addr < end) {
#if defined(__x86_64__)
		/*
		 * Back with a large page if properly aligned on x86
		 */
		if ((map_addr & I386_LPGMASK) == 0 &&
		    map_addr + I386_LPGBYTES <= addr + size &&
		    pmap_pre_expand_large(kernel_pmap, map_addr) == KERN_SUCCESS &&
		    pmap_next_page_large(&phys_page) == KERN_SUCCESS) {
			kr = pmap_enter(kernel_pmap, map_addr, phys_page,
			    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE,
			    VM_WIMG_USE_DEFAULT | VM_MEM_SUPERPAGE, FALSE, mapping_type);

			if (kr != KERN_SUCCESS) {
				panic("pmap_steal_memory: pmap_enter() large failed, new_addr=%#lx, phys_page=%u",
				    (unsigned long)map_addr, phys_page);
			}
			map_addr += I386_LPGBYTES;
			vm_page_wire_count += I386_LPGBYTES >> PAGE_SHIFT;
			vm_page_stolen_count += I386_LPGBYTES >> PAGE_SHIFT;
			vm_page_kern_lpage_count++;
			continue;
		}
#endif

		if (!pmap_next_page_hi(&phys_page, might_free)) {
			panic("pmap_steal_memory() size: 0x%llx", (uint64_t)size);
		}

#if defined(__x86_64__)
		pmap_pre_expand(kernel_pmap, map_addr);
#endif
		pmap_flags = flags ? flags : VM_WIMG_USE_DEFAULT;

#if HAS_MTE
		if (pmap_flags & VM_MEM_MAP_MTE) {
			mteinfo_covered_page_set_stolen_tagged(phys_page);
			pmap_make_tagged_page(phys_page);
			/* Force the canonical tag. */
			mte_store_tag((void *)phystokv(ptoa(phys_page)), PAGE_SIZE);
		}
#endif /* HAS_MTE */

		kr = pmap_enter(kernel_pmap, map_addr, phys_page,
		    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE,
		    pmap_flags, FALSE, mapping_type);

		if (kr != KERN_SUCCESS) {
			panic("pmap_steal_memory() pmap_enter failed, map_addr=%#lx, phys_page=%u",
			    (unsigned long)map_addr, phys_page);
		}
		map_addr += PAGE_SIZE;

		/*
		 * Account for newly stolen memory
		 */
		vm_page_wire_count++;
		vm_page_stolen_count++;
	}

#if defined(__x86_64__)
	/*
	 * The call with might_free is currently the last use of pmap_steal_memory*().
	 * Notify the pmap layer to record which high pages were allocated so far.
	 */
	if (might_free) {
		pmap_hi_pages_done();
	}
#endif
#if KASAN
	kasan_notify_address(round_page(addr), size);
#endif
	return (void *) addr;
}

__mockable void *
pmap_steal_memory(
	vm_size_t size,
	vm_size_t alignment)
{
	return pmap_steal_memory_internal(size, alignment, FALSE, 0, PMAP_MAPPING_TYPE_RESTRICTED);
}

__mockable void *
pmap_steal_freeable_memory(
	vm_size_t size)
{
	return pmap_steal_memory_internal(size, 0, TRUE, 0, PMAP_MAPPING_TYPE_RESTRICTED);
}

#if HAS_MTE
void *
pmap_steal_zone_memory(
	vm_size_t size,
	vm_size_t alignment)
{
	return pmap_steal_memory_internal(size, alignment, FALSE, VM_MEM_MAP_MTE, PMAP_MAPPING_TYPE_RESTRICTED);
}
#endif /* HAS_MTE */


#if CONFIG_SECLUDED_MEMORY
/* boot-args to control secluded memory */
TUNABLE_DT(unsigned int, secluded_mem_mb, "/defaults", "kern.secluded_mem_mb", "secluded_mem_mb", 0, TUNABLE_DT_NONE);
/* IOKit can use secluded memory */
TUNABLE(bool, secluded_for_iokit, "secluded_for_iokit", true);
/* apps can use secluded memory */
TUNABLE(bool, secluded_for_apps, "secluded_for_apps", true);
/* filecache can use seclude memory */
TUNABLE(secluded_filecache_mode_t, secluded_for_filecache, "secluded_for_filecache", SECLUDED_FILECACHE_RDONLY);
uint64_t secluded_shutoff_trigger = 0;
uint64_t secluded_shutoff_headroom = 150 * 1024 * 1024; /* original value from N56 */
#endif /* CONFIG_SECLUDED_MEMORY */


#if defined(__arm64__)
extern void patch_low_glo_vm_page_info(void *, void *, uint32_t);
#endif

void vm_page_release_startup(vm_page_t mem);
__mockable void
pmap_startup(
	vm_offset_t     *startp,
	vm_offset_t     *endp)
{
	unsigned int    npages;
	ppnum_t         phys_page;
	uint64_t        mem_sz;
	uint64_t        start_ns;
	uint64_t        now_ns;
	uint32_t        divisor;
#if XNU_VM_HAS_DELAYED_PAGES
	uint_t          low_page_count = 0;
#endif /* XNU_VM_HAS_DELAYED_PAGES */

	/*
	 * make sure we are aligned on a 64 byte boundary
	 * for VM_PAGE_PACK_PTR (it clips off the low-order
	 * 6 bits of the pointer)
	 */
	if (virtual_space_start != virtual_space_end) {
		virtual_space_start = round_page(virtual_space_start);
	}

	/*
	 * We calculate how many page frames we will have
	 * and then allocate the page structures in one chunk.
	 *
	 * Note that the calculation here doesn't take into account
	 * the memory needed to map what's being allocated, i.e. the page
	 * table entries. So the actual number of pages we get will be
	 * less than this. To do someday: include that in the computation.
	 *
	 * Also for ARM, we don't use the count of free_pages, but rather the
	 * range from last page to first page (ignore holes due to retired pages).
	 */

	/*
	 * Initialize and release the page frames.
	 */
	kernel_debug_string_early("page_frame_init");
	absolutetime_to_nanoseconds(mach_absolute_time(), &start_ns);
	if (fillval) {
		kprintf("Filling vm_pages with pattern: 0x%x\n", fillval);
	}

#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
	mem_sz  = ptoa(pmap_free_pages_span());
#if HAS_MTE
	if (!mte_enabled())
#endif /* HAS_MTE */
#if CONFIG_SPTM
	{
		uint32_t count = vm_pages_free_mask_len();

		_vm_pages_free_masks = pmap_steal_memory(count *
		    sizeof(__uint128_t), sizeof(__uint128_t));
		_vm_pages_free_enqueue_idx = pmap_steal_memory(count, sizeof(uint8_t));
		bzero(_vm_pages_free_masks, count * sizeof(__uint128_t));
		memset(_vm_pages_free_enqueue_idx, 0xff, count);
	}
#endif /* CONFIG_SPTM */
#else
	mem_sz  = ptoa(pmap_free_pages());
#endif
	mem_sz += round_page(virtual_space_start) - virtual_space_start;   /* Account for any slop */
	divisor = PAGE_SIZE + sizeof(struct vm_page);
	npages  = (uint32_t)((mem_sz + divisor - 1) / divisor); /* scaled to include the vm_page_ts */


	vm_pages     = pmap_steal_freeable_memory(npages * sizeof(struct vm_page));
	vm_pages_end = vm_page_get(npages);

#if CONFIG_SECLUDED_MEMORY
	/*
	 * Figure out how much secluded memory to have before we start
	 * release pages to free lists.
	 * The default, if specified nowhere else, is no secluded mem.
	 */
	vm_page_secluded_target = (unsigned int)atop_64(secluded_mem_mb * 1024ULL * 1024ULL);

	/*
	 * Allow a really large app to effectively use secluded memory until it exits.
	 */
	if (vm_page_secluded_target != 0) {
		/*
		 * Get an amount from boot-args, else use 1/2 of max_mem.
		 * 1/2 max_mem was chosen from a Peace daemon tentpole test which
		 * used munch to induce jetsam thrashing of false idle daemons on N56.
		 */
		int secluded_shutoff_mb;
		if (PE_parse_boot_argn("secluded_shutoff_mb", &secluded_shutoff_mb,
		    sizeof(secluded_shutoff_mb))) {
			secluded_shutoff_trigger = (uint64_t)secluded_shutoff_mb * 1024 * 1024;
		} else {
			secluded_shutoff_trigger = max_mem / 2;
		}

		/* ensure the headroom value is sensible and avoid underflows */
		assert(secluded_shutoff_trigger == 0 || secluded_shutoff_trigger > secluded_shutoff_headroom);
	}
#endif /* CONFIG_SECLUDED_MEMORY */

#if defined(__x86_64__)

	/*
	 * Decide how much memory we delay freeing at boot time.
	 */
	uint32_t delay_above_gb;
	if (!PE_parse_boot_argn("delay_above_gb", &delay_above_gb, sizeof(delay_above_gb))) {
		delay_above_gb = DEFAULT_DELAY_ABOVE_PHYS_GB;
	}

	if (delay_above_gb == 0) {
		delay_above_pnum = PPNUM_MAX;
	} else {
		delay_above_pnum = delay_above_gb * (1024 * 1024 * 1024 / PAGE_SIZE);
	}

	/* make sure we have sane breathing room: 1G above low memory */
	if (delay_above_pnum <= max_valid_low_ppnum) {
		delay_above_pnum = max_valid_low_ppnum + ((1024 * 1024 * 1024) >> PAGE_SHIFT);
	}

	if (delay_above_pnum < PPNUM_MAX) {
		printf("pmap_startup() delaying init/free of page nums > 0x%x\n", delay_above_pnum);
	}

#endif /* defined(__x86_64__) */


	vm_free_page_lock();

	for (uint32_t i = 0; i < npages && pmap_next_page(&phys_page); i++) {
#if XNU_VM_HAS_DELAYED_PAGES
		if (phys_page < max_valid_low_ppnum) {
			++low_page_count;
		}

		/* Are we at high enough pages to delay the rest? */
		if (low_page_count > vm_lopage_free_limit &&
		    phys_page > delay_above_pnum) {
			vm_delayed_count = pmap_free_pages();
			assert3u(vm_pages_count + vm_delayed_count, <=, npages);
			break;
		}
#endif /* XNU_VM_HAS_DELAYED_PAGES */

#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
		if (i == 0) {
			vm_pages_first_pnum = phys_page;
			patch_low_glo_vm_page_info(vm_pages, vm_pages_end,
			    vm_pages_first_pnum);
#if HAS_MTE
			if (mte_enabled()) {
				vm_pages_tag_storage = vm_page_get(
					(mte_tag_storage_start_pnum - vm_pages_first_pnum));
				vm_pages_tag_storage_end = vm_tag_storage_page_get(mte_tag_storage_count);
				assert3p(vm_pages_tag_storage_end, <=, vm_pages_end);
			}
#endif /* HAS_MTE */
		}
#else
		/* The x86 clump freeing code requires increasing ppn's to work correctly */
		if (i > 0) {
			assert(phys_page > vm_page_get(i - 1)->vmp_phys_page);
		}
#endif /* !XNU_VM_HAS_LINEAR_PAGES_ARRAY */

		++vm_pages_count;
		vm_page_init(vm_page_get(i), phys_page);
		if (fillval) {
			fillPage(phys_page, fillval);
		}
		if (vm_himemory_mode) {
			vm_page_release_startup(vm_page_get(i));
		}
	}

	vm_page_pages = vm_pages_count; /* used to report to user space */

	if (!vm_himemory_mode) {
		for (uint32_t i = npages; i-- > 0;) {
			/* skip retired pages */
			if (!VMP_ERROR_GET(vm_page_get(i))) {
				vm_page_release_startup(vm_page_get(i));
			}
		}
	}

	vm_free_page_unlock();

	absolutetime_to_nanoseconds(mach_absolute_time(), &now_ns);
	printf("pmap_startup() init/release time: %lld microsec\n",
	    (now_ns - start_ns) / NSEC_PER_USEC);
#if XNU_VM_HAS_DELAYED_PAGES
	printf("pmap_startup() delayed init/release of %d pages\n",
	    vm_delayed_count);
#endif /* XNU_VM_HAS_DELAYED_PAGES */

	/*
	 * Validate packing will work properly.  This needs to be done last
	 * after vm_pages_count has been computed.
	 */
	if (npages >= VM_PAGE_PACKED_FROM_ARRAY) {
		panic("pmap_startup(): too many pages to support vm_page packing");
	}
	if ((vm_page_t)VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(vm_pages)) != vm_pages) {
		panic("VM_PAGE_PACK_PTR failed on vm_pages - %p", vm_pages);
	}
	if ((vm_page_t)VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(vm_page_get(vm_pages_count - 1))) !=
	    vm_page_get(vm_pages_count - 1)) {
		panic("VM_PAGE_PACK_PTR failed on vm_pages_end - %p",
		    vm_page_get(vm_pages_count - 1));
	}

	VM_CHECK_MEMORYSTATUS;

	/*
	 * We have to re-align virtual_space_start,
	 * because pmap_steal_memory has been using it.
	 */
	virtual_space_start = round_page(virtual_space_start);
	*startp = virtual_space_start;
	*endp = virtual_space_end;
}
#endif  /* MACHINE_PAGES */

/*
 * Create the zone that represents the vm_pages[] array. Nothing ever allocates
 * or frees to this zone. It's just here for reporting purposes via zprint command.
 * This needs to be done after all initially delayed pages are put on the free lists.
 */
void
vm_pages_array_finalize(void)
{
	(void)zone_create_ext("vm pages array", sizeof(struct vm_page),
	    ZC_KASAN_NOREDZONE | ZC_KASAN_NOQUARANTINE, ZONE_ID_VM_PAGES, ^(zone_t z) {
		uint64_t vm_page_zone_pages, vm_page_array_zone_data_size;

		zone_set_exhaustible(z, 0, true);
		/*
		 * Reflect size and usage information for vm_pages[].
		 */

		z->z_elems_avail = (uint32_t)(vm_pages_end - vm_pages);
		z->z_elems_free = z->z_elems_avail - vm_pages_count;
		zpercpu_get_cpu(z->z_stats, 0)->zs_mem_allocated =
		vm_pages_count * sizeof(struct vm_page);
		vm_page_array_zone_data_size = (uint64_t)vm_pages_end - (uint64_t)vm_pages;
		vm_page_zone_pages = atop(round_page((vm_offset_t)vm_page_array_zone_data_size));
		z->z_wired_cur += vm_page_zone_pages;
		z->z_wired_hwm = z->z_wired_cur;
		z->z_va_cur = z->z_wired_cur;
		/* since zone accounts for these, take them out of stolen */
		VM_PAGE_MOVE_STOLEN(vm_page_zone_pages);
	});
}

/*
 * Create the vm_pages zone. This is used for the vm_page structures for the pages
 * that are scavanged from other boot time usages by ml_static_mfree(). As such,
 * this needs to happen in early VM bootstrap.
 */

__startup_func
static void
vm_page_module_init(void)
{
	vm_size_t vm_page_with_ppnum_size;

	/*
	 * Since the pointers to elements in this zone will be packed, they
	 * must have appropriate size. Not strictly what sizeof() reports.
	 */
	vm_page_with_ppnum_size =
	    (sizeof(struct vm_page_with_ppnum) + (VM_PAGE_PACKED_PTR_ALIGNMENT - 1)) &
	    ~(VM_PAGE_PACKED_PTR_ALIGNMENT - 1);

	vm_page_zone = zone_create_ext("vm pages", vm_page_with_ppnum_size,
	    ZC_ALIGNMENT_REQUIRED | ZC_VM,
	    ZONE_ID_ANY, ^(zone_t z) {
		/*
		 * The number "10" is a small number that is larger than the number
		 * of fictitious pages that any single caller will attempt to allocate
		 * without blocking.
		 *
		 * The largest such number at the moment is kmem_alloc()
		 * when 2 guard pages are asked. 10 is simply a somewhat larger number,
		 * taking into account the 50% hysteresis the zone allocator uses.
		 *
		 * Note: this works at all because the zone allocator
		 *       doesn't ever allocate fictitious pages.
		 */
		zone_raise_reserve(z, 10);
	});
}
STARTUP(ZALLOC, STARTUP_RANK_SECOND, vm_page_module_init);

#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
/*
 * Radix tree of pages within the [pmap_first_pnum, vm_pages_first_pnum) range,
 * in order to support page lookup by pnum (@see vm_page_find_canonical()),
 * which corresponds to pages returned to the VM via @c ml_static_mfree().
 *
 * Kernel vm pages are never freed, which means that this data structure
 * is insert only.
 *
 * Empirically we have about 4-5k such pages, typically in only few rather dense
 * contiguous spans, inside a range of roughly 32k pnums.
 *
 * A radix tree works well with the distribution of keys, but also allows for
 * a straightforward lockless lookup path.
 */

#define VM_PAGE_RADIX_FANOUT_SHIFT  8
#define VM_PAGE_RADIX_FANOUT        (1u << VM_PAGE_RADIX_FANOUT_SHIFT)

typedef uint32_t vm_page_radix_ptr_t;

typedef struct vm_page_radix_node {
	vm_page_radix_ptr_t     vmpr_array[VM_PAGE_RADIX_FANOUT];
} *vm_page_radix_node_t;

static LCK_GRP_DECLARE(vm_pages_radix_lock_grp, "VM pages radix");
static LCK_MTX_DECLARE(vm_pages_radix_lock, &vm_pages_radix_lock_grp);

static SECURITY_READ_ONLY_LATE(uintptr_t) vm_pages_radix_root;
static uint32_t vm_pages_radix_count;

static vm_page_radix_node_t
vm_page_radix_node_unpack(vm_page_radix_ptr_t ptr)
{
	return (vm_page_radix_node_t)VM_UNPACK_POINTER(ptr, VM_PAGE_PACKED_PTR);
}

static vm_page_radix_ptr_t
vm_page_radix_node_pack(vm_page_radix_node_t node)
{
	vm_offset_t ptr = (vm_offset_t)node;

	VM_ASSERT_POINTER_PACKABLE(ptr, VM_PAGE_PACKED_PTR);
	return (vm_page_radix_ptr_t)VM_PACK_POINTER(ptr, VM_PAGE_PACKED_PTR);
}

static uint32_t
vm_page_radix_key(uint32_t level, uint32_t index)
{
	uint32_t key = index >> (VM_PAGE_RADIX_FANOUT_SHIFT * level);

	return key & (VM_PAGE_RADIX_FANOUT - 1);
}

static vm_page_radix_ptr_t *
vm_page_radix_slot(vm_page_radix_node_t node, uint32_t level, uint32_t index)
{
	return node->vmpr_array + vm_page_radix_key(level, index);
}

__startup_func
__attribute__((noinline))
static vm_page_radix_node_t
vm_pages_radix_init_root(uint32_t *levelp)
{
	uint32_t max_index = vm_pages_first_pnum - pmap_first_pnum - 1;
	vm_page_radix_node_t root;
	uint32_t level;
	vm_size_t size;

	/*
	 * Init a top-level node right away, to cover any index within
	 * [0, vm_pages_first_pnum - pmap_first_pnum)
	 */
	level = (fls(max_index | 1) - 1) / VM_PAGE_RADIX_FANOUT_SHIFT;
	size  = (vm_page_radix_key(level, max_index) + 1) *
	    sizeof(vm_page_radix_ptr_t);

	root  = zalloc_permanent(size, ZALIGN_64);

	/*
	 * Pack the level into the root pointer low bits,
	 * so that pointer and level can be read atomically.
	 *
	 * See vm_pages_radix_load_root().
	 */
	os_atomic_store(&vm_pages_radix_root, (uintptr_t)root | level, release);

	*levelp = level;
	return root;
}

static vm_page_radix_node_t
vm_pages_radix_node_alloc(vm_page_radix_ptr_t *slot)
{
	vm_page_radix_node_t node;

	node = zalloc_permanent(sizeof(struct vm_page_radix_node),
	    VM_PAGE_PACKED_PTR_ALIGNMENT - 1);
	os_atomic_store(slot, vm_page_radix_node_pack(node), release);
	return node;
}

static vm_page_radix_node_t
vm_pages_radix_load_root(uint32_t *level)
{
	const uintptr_t VM_PAGE_RADIX_LEVEL_MASK = 0x7ul;

	uintptr_t root = os_atomic_load(&vm_pages_radix_root, dependency);

	*level = root & VM_PAGE_RADIX_LEVEL_MASK;
	root &= ~VM_PAGE_RADIX_LEVEL_MASK;
	return (vm_page_radix_node_t)root;
}

vm_page_t
vm_pages_radix_next(uint32_t *cursor, ppnum_t *pnum)
{
	const uint32_t max_index = vm_pages_first_pnum - pmap_first_pnum;
	vm_page_radix_node_t node;
	uint32_t level, index;

	index  = *cursor;
	node   = vm_pages_radix_load_root(&level);

	if (node == NULL) {
		return VM_PAGE_NULL;
	}

	while (index < max_index) {
		vm_page_radix_ptr_t *slot = vm_page_radix_slot(node, level, index);
		vm_page_radix_ptr_t  ptr  = os_atomic_load(slot, dependency);

		if (ptr == 0) {
			uint32_t stride = 1 << (VM_PAGE_RADIX_FANOUT_SHIFT * level);

			index = (index + stride) & -stride;
			if (vm_page_radix_key(level, index) == 0) {
				/* restart lookup at the top */
				node = vm_pages_radix_load_root(&level);
			}
		} else if (level > 0) {
			node   = vm_page_radix_node_unpack(ptr);
			level -= 1;
		} else {
			*cursor = index + 1;
			if (pnum) {
				*pnum = pmap_first_pnum + index;
			}
			return (vm_page_t)VM_PAGE_UNPACK_PTR(ptr);
		}
	}

	if (pnum) {
		*pnum = 0;
	}
	return VM_PAGE_NULL;
}

#if DEBUG || DEVELOPMENT

static int
vm_page_radix_verify_test(int64_t in __unused, int64_t *out)
{
	uint32_t count = 0;
	vm_page_t mem;

	lck_mtx_lock(&vm_pages_radix_lock);

	vm_pages_radix_for_each(mem) {
		count++;
		assert(mem == vm_page_find_canonical(VM_PAGE_GET_PHYS_PAGE(mem)));
	}

	assert(count == vm_pages_radix_count);

	lck_mtx_unlock(&vm_pages_radix_lock);

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(vm_page_radix_verify, vm_page_radix_verify_test);

#endif /* DEBUG || DEVELOPMENT */

__attribute__((noinline))
static void
vm_pages_radix_insert(ppnum_t pnum, vm_page_t page)
{
	vm_page_radix_ptr_t *slot;
	vm_page_radix_node_t node;
	uint32_t level, index;

	assert(!vm_page_in_array(page));
	index = pnum - pmap_first_pnum;

	lck_mtx_lock(&vm_pages_radix_lock);

	node = vm_pages_radix_load_root(&level);
	if (node == NULL) {
		node = vm_pages_radix_init_root(&level);
	}

	for (; level > 0; level--) {
		slot = vm_page_radix_slot(node, level, index);
		if (*slot == 0) {
			node = vm_pages_radix_node_alloc(slot);
		} else {
			node = vm_page_radix_node_unpack(*slot);
		}
	}

	slot = vm_page_radix_slot(node, 0, index);
	assert(*slot == 0);
	os_atomic_store(slot, VM_PAGE_PACK_PTR(page), release);
	vm_pages_radix_count++;

	lck_mtx_unlock(&vm_pages_radix_lock);
}

__abortlike
static void
vm_page_for_ppnum_panic(ppnum_t pnum)
{
	if (pnum < pmap_first_pnum) {
		panic("physical page is before the start of DRAM: %#x < %#x)",
		    pnum, pmap_first_pnum);
	}
	panic("physical page is beyond the end of managed DRAM: %#x >= %#x)",
	    pnum, vm_pages_first_pnum + vm_pages_count);
}

__mockable vm_page_t
vm_page_find_canonical(ppnum_t pnum)
{
	vm_page_radix_ptr_t *slot;
	vm_page_radix_node_t node;
	vm_page_radix_ptr_t  ptr;
	uint32_t level, index;

	if (pnum < pmap_first_pnum) {
		vm_page_for_ppnum_panic(pnum);
	}

	if (pnum >= vm_pages_first_pnum + vm_pages_count) {
		/*
		 * We could receive requests for pages which are beyond the xnu's managed space. (eg: ECC errors)
		 * These need to be handled gracefully, so we return VM_PAGE_NULL here.
		 */
		return VM_PAGE_NULL;
	}

	if (__probable(pnum >= vm_pages_first_pnum)) {
		return vm_page_get(pnum - vm_pages_first_pnum);
	}

	index = pnum - pmap_first_pnum;
	node  = vm_pages_radix_load_root(&level);

	for (; node && level > 0; level--) {
		slot = vm_page_radix_slot(node, level, index);
		ptr  = os_atomic_load(slot, dependency);
		node = vm_page_radix_node_unpack(ptr);
	}

	if (__probable(node)) {
		slot = vm_page_radix_slot(node, 0, index);
		ptr  = os_atomic_load(slot, dependency);
		return (vm_page_t)VM_PAGE_UNPACK_PTR(ptr);
	}

	return VM_PAGE_NULL;
}

#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */

/*!
 * @function vm_page_create()
 *
 * @brief
 * Common helper for all vm_page_create* functions.
 */
vm_page_t
vm_page_create(ppnum_t phys_page, bool canonical, zalloc_flags_t flags)
{
	vm_page_t m;

	m = zalloc_flags(vm_page_zone, flags);
	if (m) {
		vm_page_init(m, phys_page);
		if (phys_page == vm_page_guard_addr) {
			counter_inc(&vm_guard_count);
		}
	}
	if (canonical) {
		assert((flags & (Z_NOWAIT | Z_NOPAGEWAIT)) == 0);
		m->vmp_canonical = true;
#if HAS_MTE
		m->vmp_using_mte = pmap_is_tagged_page(phys_page);
#endif /* HAS_MTE */
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
		vm_pages_radix_insert(phys_page, m);
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */
		vm_free_page_lock();
		vm_page_pages++;
		vm_free_page_unlock();
	}
	return m;
}

/*
 *	Routine:	vm_page_create_canonical
 *	Purpose:
 *		After the VM system is up, machine-dependent code
 *		may stumble across more physical memory.  For example,
 *		memory that it was reserving for a frame buffer.
 *		vm_page_create_canonical turns this memory into available pages.
 */

void
vm_page_create_canonical(ppnum_t phys_page)
{
	vm_page_t m;

	m = vm_page_create(phys_page, true, Z_WAITOK);
	vm_page_release(m, VMP_RELEASE_NONE);
}


/*
 *	vm_page_hash:
 *
 *	Distributes the object/offset key pair among hash buckets.
 *
 *	NOTE:	The bucket count must be a power of 2
 */
#define vm_page_hash(object, offset) (\
	( (natural_t)((uintptr_t)object * vm_page_bucket_hash) + ((uint32_t)atop_64(offset) ^ vm_page_bucket_hash))\
	 & vm_page_hash_mask)

static void
vm_page_hash_insert_locked(vm_page_bucket_t *bucket, vm_page_t mem)
{
	mem->vmp_next_m = bucket->page_list;
	mem->vmp_hashed = true;
	bucket->page_list = VM_PAGE_PACK_PTR(mem);
}

static void
vm_page_hash_remove_locked(vm_page_packed_t *prev, vm_page_t mem)
{
	*prev = mem->vmp_next_m;
	mem->vmp_next_m = VM_PAGE_PACK_PTR(NULL);
	mem->vmp_hashed = false;
}

/*
 * Lookup a page in a given bucket.
 *
 * This function is called under extremely unusual locking behavior.
 * Specifically, hw_lck_ticket_unlock_after_lookup is used with the return value
 * of this function. That means that any loads in this function expecting to be
 * protected by the bucket locks must be directly necessary to get the `mem`
 * returned by this function.
 * We can't do writes protected by the lock.
 *
 * If we remove the data dependent locking, we can probably merge this with
 * @c vm_page_hash_lookup_and_remove_locked as they are very similar code.
 */
static vm_page_t
vm_page_hash_lookup_data_dependent_locked(
	vm_page_bucket_t       *bucket,
	vm_object_t             object,
	vm_object_offset_t      offset)
{
	vm_page_object_t  packed = VM_PAGE_PACK_OBJECT(object);
	vm_page_packed_t *prev   = &bucket->page_list;

	while (*prev) {
		vm_page_t mem = (vm_page_t)(VM_PAGE_UNPACK_PTR(*prev));

		if (mem->vmp_object == packed && mem->vmp_offset == offset) {
			return mem;
		}
		prev = &mem->vmp_next_m;
	}

	return VM_PAGE_NULL;
}

/*
 * Lookup a page in a given bucket and remove it from that bucket.
 */
static vm_page_t
vm_page_hash_lookup_and_remove_locked(
	vm_page_bucket_t       *bucket,
	vm_object_t             object,
	vm_object_offset_t      offset)
{
	vm_page_object_t  packed = VM_PAGE_PACK_OBJECT(object);
	vm_page_packed_t *prev   = &bucket->page_list;

	while (*prev) {
		vm_page_t mem = (vm_page_t)(VM_PAGE_UNPACK_PTR(*prev));

		if (mem->vmp_object == packed && mem->vmp_offset == offset) {
			vm_page_hash_remove_locked(prev, mem);
			return mem;
		}
		prev = &mem->vmp_next_m;
	}

	return VM_PAGE_NULL;
}

static void
vm_page_hash_remove(vm_page_t mem, vm_object_t object)
{
	vm_page_packed_t  packed  = VM_PAGE_PACK_PTR(mem);
	uint32_t          hash_id = vm_page_hash(object, mem->vmp_offset);
	vm_page_bucket_t *bucket  = &vm_page_buckets[hash_id];
	hw_lck_ticket_t  *lock    = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];
	vm_page_packed_t *prev    = &bucket->page_list;

	/*
	 *	Remove from the object_object/offset hash table
	 */

	hw_lck_ticket_lock(lock, &vm_page_lck_grp_bucket);
	while (*prev != packed) {
		prev = &((vm_page_t)VM_PAGE_UNPACK_PTR(*prev))->vmp_next_m;
	}

	vm_page_hash_remove_locked(prev, mem);
#if     MACH_PAGE_HASH_STATS
	bucket->cur_count--;
#endif /* MACH_PAGE_HASH_STATS */
	hw_lck_ticket_unlock(lock);
}

void
vm_page_hash_insert(vm_page_t mem, vm_object_t object, vm_object_offset_t offset)
{
	uint32_t          hash_id = vm_page_hash(object, offset);
	vm_page_bucket_t *bucket  = &vm_page_buckets[hash_id];
	hw_lck_ticket_t  *lock    = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];

	if (object->internal && (offset >= object->vo_size)) {
		panic("(page=%p,obj=%p,off=0x%llx,size=0x%llx) inserted at offset past object bounds",
		    mem, object, offset, object->vo_size);
	}

	assert(mem->vmp_object == VM_PAGE_PACK_OBJECT(object) &&
	    mem->vmp_offset == offset &&
	    !mem->vmp_hashed);

#if CONFIG_SECLUDED_MEMORY
	if (object->eligible_for_secluded) {
		vm_page_secluded.eligible_for_secluded++;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	/*
	 *	Insert it into the object_object/offset hash table
	 */

	hw_lck_ticket_lock(lock, &vm_page_lck_grp_bucket);
	assert(!vm_page_hash_lookup_data_dependent_locked(bucket, object, offset));

	vm_page_hash_insert_locked(bucket, mem);
#if     MACH_PAGE_HASH_STATS
	if (++bucket->cur_count > bucket->hi_count) {
		bucket->hi_count = bucket->cur_count;
	}
#endif /* MACH_PAGE_HASH_STATS */

	hw_lck_ticket_unlock(lock);
}

static void
vm_page_hash_replace(vm_page_t mem, vm_object_t object, vm_object_offset_t offset)
{
	uint32_t          hash_id = vm_page_hash(object, offset);
	vm_page_bucket_t *bucket  = &vm_page_buckets[hash_id];
	hw_lck_ticket_t  *lock    = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];
	vm_page_t         found_m;

	hw_lck_ticket_lock(lock, &vm_page_lck_grp_bucket);
	found_m = vm_page_hash_lookup_and_remove_locked(bucket, object, offset);
	vm_page_hash_insert_locked(bucket, mem);
	hw_lck_ticket_unlock(lock);

	if (found_m) {
		VM_PAGE_FREE(found_m);
	}
}


/*
 *	vm_page_insert:		[ internal use only ]
 *
 *	Inserts the given mem entry into the object/object-page
 *	table and object list.
 *
 *	The object must be locked.
 */
void
vm_page_insert(
	vm_page_t               mem,
	vm_object_t             object,
	vm_object_offset_t      offset)
{
	vm_page_insert_internal(mem, object, offset, VM_KERN_MEMORY_NONE, VMPI_NONE, NULL);
}

void
vm_page_insert_wired(
	vm_page_t               mem,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_tag_t                tag)
{
	vm_page_insert_internal(mem, object, offset, tag, VMPI_NONE, NULL);
}

void
vm_page_insert_internal(
	vm_page_t               mem,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_tag_t                tag,
	vmpi_flags_t            flags,
	struct vmpi_acct       *delayed_acct)
{
	ledger_t      ledger;
	vmo_ledgers_t lidx;

#if 0
	/*
	 * we may not hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(mem);
#endif

	assertf(page_aligned(offset), "0x%llx\n", offset);

	assert(!VM_PAGE_WIRED(mem) || !vm_page_is_canonical(mem) ||
	    (tag != VM_KERN_MEMORY_NONE));

#if HAS_MTE
	assert_mte_vmo_matches_vmp(object, mem);
#endif /* HAS_MTE */
	vm_object_lock_assert_exclusive(object);
	if (flags & VMPI_Q_LOCKED) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	} else {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
		assert(!VM_PAGE_PAGEABLE(mem));
	}

	/*
	 *	Record the object/offset pair in this page
	 */
	mem->vmp_object = VM_PAGE_PACK_OBJECT(object);
	mem->vmp_offset = offset;

	if (flags & VMPI_REPLACE) {
		assert((flags & VMPI_DELAY_HASH) == 0);
		vm_page_hash_replace(mem, object, offset);
	} else if (flags & VMPI_DELAY_HASH) {
#if MACH_ASSERT
		assert(!object->delayed_page_insert);
		object->delayed_page_insert = true;
#endif /* MACH_ASSERT */
	} else {
		vm_page_hash_insert(mem, object, offset);
	}

	{
		unsigned int    cache_attr;

		cache_attr = object->wimg_bits & VM_WIMG_MASK;

#if HAS_MTE
		/*
		 * Set the cache attributes if it's neither the default atttributes
		 * nor it's WIMG_MTE because we would have already set it before
		 * inserting the page into this object. There is no need to take
		 * the set hit.
		 *
		 *
		 */
		if (cache_attr == VM_WIMG_MTE) {
			if (vm_object_is_mte_mappable_with_page(object, mem)) {
				/*
				 * By now, we expect non-fictitious pages to have been made
				 * tagged. This should happen in mteinfo_page_list_fix_tagging()
				 * when the page is inserted onto the per-CPU free tagged queue.
				 */
				assert(mem->vmp_using_mte);
				assert(pmap_cache_attributes(VM_PAGE_GET_PHYS_PAGE(mem)) == VM_WIMG_MTE);
			} else {
				/*
				 * We don't want the object for fictitious pages to have its
				 * cache attributes set if the object is MTE.
				 */
			}
		} else
#endif /* HAS_MTE */
		if (cache_attr != VM_WIMG_USE_DEFAULT) {
			PMAP_SET_CACHE_ATTR(mem, object, cache_attr,
			    (flags & VMPI_BATCH_PMAP_OP));
		}
	}

	/*
	 *	Now link into the object's list of backed pages.
	 */
	vm_page_queue_enter(&object->memq, mem, vmp_listq);
	object->memq_hint = mem;
	mem->vmp_tabled = TRUE;

	/*
	 *	Show that the object has one more resident page.
	 */

	object->resident_page_count++;
	if (VM_PAGE_WIRED(mem)) {
		assert(mem->vmp_wire_count > 0);
		VM_OBJECT_WIRED_PAGE_UPDATE_START(object);
		VM_OBJECT_WIRED_PAGE_ADD(object, mem);
		VM_OBJECT_WIRED_PAGE_UPDATE_END(object, tag);
	}
	assert(object->resident_page_count >= object->wired_page_count);

#if COMPRESSOR_PAGEOUT_CHEADS_MAX_COUNT > 1
	vm_object_set_chead_hint(object);
#endif

	if (object->object_is_shared_cache &&
	    object->pager != NULL &&
	    object->pager->mo_pager_ops == &shared_region_pager_ops) {
		assert(!object->internal);
		VM_COUNTER_ATOMIC_INC(&vm_page_shared_region_count);
	}

	if (delayed_acct) {
		delayed_acct->vmpi_inserted++;
	} else if (object->internal) {
		counter_inc(&vm_page_internal_count);
	} else {
		counter_inc(&vm_page_external_count);
	}

	/*
	 * It wouldn't make sense to insert a "reusable" page in
	 * an object (the page would have been marked "reusable" only
	 * at the time of a madvise(MADV_FREE_REUSABLE) if it was already
	 * in the object at that time).
	 * But a page could be inserted in a "all_reusable" object, if
	 * something faults it in (a vm_read() from another task or a
	 * "use-after-free" issue in user space, for example).  It can
	 * also happen if we're relocating a page from that object to
	 * a different physical page during a physically-contiguous
	 * allocation.
	 */
	assert(!mem->vmp_reusable);
	if (delayed_acct == NULL && object->all_reusable) {
		os_atomic_inc(&vm_page_stats_reusable.reusable_count, relaxed);
	}

	ledger = VM_OBJECT_LEDGER(object);
	if (ledger && delayed_acct == NULL) {
		lidx = vm_object_ledger_tag_ledgers(object);
		disable_preemption();
	}

	if (ledger &&
	    object->internal &&
	    (object->purgable == VM_PURGABLE_NONVOLATILE ||
	    object->purgable == VM_PURGABLE_DENY ||
	    VM_PAGE_WIRED(mem))) {
		if (delayed_acct) {
			delayed_acct->vmpi_nonvolatile++;
		} else {
			/* more non-volatile bytes */
			ledger_credit_nopreempt(ledger,
			    lidx.vmo_nonvolatile, PAGE_SIZE);
			ledger_credit_nopreempt(ledger,
			    lidx.vmo_footprint, PAGE_SIZE);
		}
	} else if (ledger &&
	    object->internal &&
	    (object->purgable == VM_PURGABLE_VOLATILE ||
	    object->purgable == VM_PURGABLE_EMPTY)) {
		assert(!VM_PAGE_WIRED(mem));
		if (delayed_acct) {
			delayed_acct->vmpi_volatile++;
		} else {
			/* more volatile bytes */
			ledger_credit_nopreempt(ledger,
			    lidx.vmo_volatile, PAGE_SIZE);
		}
	} else if (ledger &&
	    !object->internal &&
	    object->vo_ledger_tag &&
	    VM_PAGE_WIRED(mem)) {
		if (delayed_acct) {
			delayed_acct->vmpi_external_wired++;
		} else {
			ledger_credit_nopreempt(ledger,
			    lidx.vmo_external_wired, PAGE_SIZE);
			ledger_credit_nopreempt(ledger,
			    lidx.vmo_footprint, PAGE_SIZE);
		}
	}

	if (ledger && delayed_acct == NULL) {
		enable_preemption();
	}

	if (object->purgable == VM_PURGABLE_VOLATILE) {
		if (VM_PAGE_WIRED(mem)) {
			counter_inc(&vm_page_purgeable_wired_count);
		} else {
			counter_inc(&vm_page_purgeable_count);
		}
	} else if (object->purgable == VM_PURGABLE_EMPTY &&
	    mem->vmp_q_state == VM_PAGE_ON_THROTTLED_Q) {
		/*
		 * This page belongs to a purged VM object but hasn't
		 * been purged (because it was "busy").
		 * It's in the "throttled" queue and hence not
		 * visible to vm_pageout_scan().  Move it to a pageable
		 * queue, so that it can eventually be reclaimed, instead
		 * of lingering in the "empty" object.
		 */
		if ((flags & VMPI_Q_LOCKED) == 0) {
			vm_page_lockspin_queues();
		}
		vm_page_deactivate(mem);
		if ((flags & VMPI_Q_LOCKED) == 0) {
			vm_page_unlock_queues();
		}
	}

#if HAS_MTE
	/*
	 * If adding pages to the compressor object, account for whether it's
	 * tag storage or not.
	 */
	if (object == compressor_object) {
		if (vm_page_is_tag_storage(mem)) {
			counter_inc(&compressor_tag_storage_pages_in_pool);
		} else {
			counter_inc(&compressor_non_tag_storage_pages_in_pool);
		}
	}
#endif /* HAS_MTE */

#if VM_OBJECT_TRACKING_OP_MODIFIED
	if (vm_object_tracking_btlog &&
	    object->internal &&
	    object->resident_page_count == 0 &&
	    object->pager == NULL &&
	    object->shadow != NULL &&
	    object->shadow->vo_copy == object) {
		btlog_record(vm_object_tracking_btlog, object,
		    VM_OBJECT_TRACKING_OP_MODIFIED,
		    btref_get(__builtin_frame_address(0), 0));
	}
#endif /* VM_OBJECT_TRACKING_OP_MODIFIED */
}

void
vm_page_insert_flush_accounting(vm_object_t object, struct vmpi_acct *acct)
{
	if (acct->vmpi_inserted) {
		disable_preemption();

		if (object->internal) {
			counter_add_preemption_disabled(&vm_page_internal_count,
			    acct->vmpi_inserted);
		} else {
			counter_add_preemption_disabled(&vm_page_external_count,
			    acct->vmpi_inserted);
		}

		if (object->all_reusable) {
			os_atomic_add(&vm_page_stats_reusable.reusable_count,
			    acct->vmpi_inserted, relaxed);
		}

		if (acct->vmpi_nonvolatile ||
		    acct->vmpi_volatile ||
		    acct->vmpi_external_wired) {
			ledger_t      ledger;
			vmo_ledgers_t lidx;

			ledger = VM_OBJECT_LEDGER(object);
			lidx   = vm_object_ledger_tag_ledgers(object);
			assert(ledger && object->internal);

			if (acct->vmpi_nonvolatile) {
				/* more non-volatile bytes */
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_nonvolatile,
				    ptoa(acct->vmpi_nonvolatile));
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_footprint,
				    ptoa(acct->vmpi_nonvolatile));
			}
			if (acct->vmpi_volatile) {
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_volatile,
				    ptoa(acct->vmpi_volatile));
			}
			if (acct->vmpi_external_wired) {
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_external_wired,
				    ptoa(acct->vmpi_external_wired));
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_footprint,
				    ptoa(acct->vmpi_external_wired));
			}
		}

		enable_preemption();
	}
}

/*
 *	vm_page_remove:		[ internal use only ]
 *
 *	Removes the given mem entry from the object/offset-page
 *	table and the object page list.
 *
 *	The object must be locked.
 */

void
vm_page_remove(vm_page_t mem)
{
	vm_object_t   m_object;
	ledger_t      ledger;
	vmo_ledgers_t lidx;

	m_object = VM_PAGE_OBJECT(mem);

	vm_object_lock_assert_exclusive(m_object);
	assert(mem->vmp_tabled);
	assert(!mem->vmp_cleaning);
	assert(!mem->vmp_laundry);

	if (VM_PAGE_PAGEABLE(mem)) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	}
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(mem);
#endif
	/*
	 *	Now remove from the object's list of backed pages.
	 */

	if (mem->vmp_hashed) {
		vm_page_hash_remove(mem, m_object);
	}
	vm_page_remove_internal(mem);

	/*
	 *	And show that the object has one fewer resident
	 *	page.
	 */

	assert(m_object->resident_page_count > 0);
	m_object->resident_page_count--;

	if (m_object->object_is_shared_cache &&
	    m_object->pager != NULL &&
	    m_object->pager->mo_pager_ops == &shared_region_pager_ops) {
		assert(!m_object->internal);
		VM_COUNTER_ATOMIC_DEC(&vm_page_shared_region_count);
	}

	if (m_object->internal) {
		counter_dec(&vm_page_internal_count);
	} else {
		counter_dec(&vm_page_external_count);

		if (mem->vmp_xpmapped) {
			assert(vm_page_xpmapped_external_count);
			OSAddAtomic(-1, &vm_page_xpmapped_external_count);
		}
	}
	if (!m_object->internal &&
	    m_object->cached_list.next &&
	    m_object->cached_list.prev) {
		if (m_object->resident_page_count == 0) {
			vm_object_cache_remove(m_object);
		}
	}

	if (VM_PAGE_WIRED(mem)) {
		assert(mem->vmp_wire_count > 0);
		VM_OBJECT_WIRED_PAGE_UPDATE_START(m_object);
		VM_OBJECT_WIRED_PAGE_REMOVE(m_object, mem);
		VM_OBJECT_WIRED_PAGE_UPDATE_END(m_object, m_object->wire_tag);
	}
	assert(m_object->resident_page_count >=
	    m_object->wired_page_count);
	if (mem->vmp_reusable) {
		assert(m_object->reusable_page_count > 0);
		m_object->reusable_page_count--;
		assert(m_object->reusable_page_count <=
		    m_object->resident_page_count);
		mem->vmp_reusable = FALSE;
		OSAddAtomic(-1, &vm_page_stats_reusable.reusable_count);
		vm_page_stats_reusable.reused_remove++;
	} else if (m_object->all_reusable) {
		OSAddAtomic(-1, &vm_page_stats_reusable.reusable_count);
		vm_page_stats_reusable.reused_remove++;
	}

	ledger = VM_OBJECT_LEDGER(m_object);
	if (ledger) {
		lidx = vm_object_ledger_tag_ledgers(m_object);
		disable_preemption();
	}

	if (ledger &&
	    m_object->internal &&
	    (m_object->purgable == VM_PURGABLE_NONVOLATILE ||
	    m_object->purgable == VM_PURGABLE_DENY ||
	    VM_PAGE_WIRED(mem))) {
		/* less non-volatile bytes */
		ledger_debit_nopreempt(ledger,
		    lidx.vmo_nonvolatile, PAGE_SIZE);
		ledger_debit_nopreempt(ledger,
		    lidx.vmo_footprint, PAGE_SIZE);
	} else if (ledger &&
	    m_object->internal &&
	    (m_object->purgable == VM_PURGABLE_VOLATILE ||
	    m_object->purgable == VM_PURGABLE_EMPTY)) {
		assert(!VM_PAGE_WIRED(mem));
		/* less volatile bytes */
		ledger_debit_nopreempt(ledger,
		    lidx.vmo_volatile, PAGE_SIZE);
	} else if (ledger &&
	    !m_object->internal &&
	    m_object->vo_ledger_tag &&
	    VM_PAGE_WIRED(mem)) {
		ledger_credit_nopreempt(ledger,
		    lidx.vmo_external_wired, PAGE_SIZE);
		ledger_credit_nopreempt(ledger,
		    lidx.vmo_footprint, PAGE_SIZE);
	}

	if (ledger) {
		enable_preemption();
	}

	if (m_object->purgable == VM_PURGABLE_VOLATILE) {
		if (VM_PAGE_WIRED(mem)) {
			counter_dec(&vm_page_purgeable_wired_count);
		} else {
			counter_dec(&vm_page_purgeable_count);
		}
	}

#if HAS_MTE
	/*
	 * If removing pages from the compressor object, account for whether it's
	 * tag storage or not.
	 */
	if (m_object == compressor_object) {
		if (vm_page_is_tag_storage(mem)) {
			counter_dec(&compressor_tag_storage_pages_in_pool);
		} else {
			counter_dec(&compressor_non_tag_storage_pages_in_pool);
		}
	}

	assert_mte_vmo_matches_vmp(m_object, mem);
	if (!vm_object_is_mte_mappable(m_object)) {
#endif /* HAS_MTE */
	if (m_object->set_cache_attr == TRUE) {
		pmap_set_cache_attributes(VM_PAGE_GET_PHYS_PAGE(mem), 0);
	}
#if HAS_MTE
}
#endif /* HAS_MTE */

	mem->vmp_tabled = FALSE;
	mem->vmp_object = 0;
	mem->vmp_offset = (vm_object_offset_t) -1;
}


/*
 *	vm_page_lookup:
 *
 *	Returns the page associated with the object/offset
 *	pair specified; if none is found, VM_PAGE_NULL is returned.
 *
 *	The object must be locked.  No side effects.
 */

#define VM_PAGE_HASH_LOOKUP_THRESHOLD   10

#if DEBUG_VM_PAGE_LOOKUP

struct {
	uint64_t        vpl_total;
	uint64_t        vpl_empty_obj;
	uint64_t        vpl_bucket_NULL;
	uint64_t        vpl_hit_hint;
	uint64_t        vpl_hit_hint_next;
	uint64_t        vpl_hit_hint_prev;
	uint64_t        vpl_fast;
	uint64_t        vpl_slow;
	uint64_t        vpl_hit;
	uint64_t        vpl_miss;

	uint64_t        vpl_fast_elapsed;
	uint64_t        vpl_slow_elapsed;
} vm_page_lookup_stats __attribute__((aligned(8)));

#endif

#define KDP_VM_PAGE_WALK_MAX    1000

vm_page_t
kdp_vm_page_lookup(
	vm_object_t             object,
	vm_object_offset_t      offset)
{
	vm_page_t cur_page;
	int num_traversed = 0;

	if (not_in_kdp) {
		panic("panic: kdp_vm_page_lookup done outside of kernel debugger");
	}

	vm_page_queue_iterate(&object->memq, cur_page, vmp_listq) {
		if (cur_page->vmp_offset == offset) {
			return cur_page;
		}
		num_traversed++;

		if (num_traversed >= KDP_VM_PAGE_WALK_MAX) {
			return VM_PAGE_NULL;
		}
	}

	return VM_PAGE_NULL;
}

vm_page_t
vm_page_lookup(vm_object_t object, vm_object_offset_t offset)
{
	vm_page_t               mem;
	vm_page_bucket_t       *bucket;
	vm_page_queue_entry_t   qe;
	hw_lck_ticket_t        *bucket_lock = NULL;
	uint32_t                hash_id;
#if DEBUG_VM_PAGE_LOOKUP
	uint64_t                start, elapsed;

	OSAddAtomic64(1, &vm_page_lookup_stats.vpl_total);
#endif

	vm_object_lock_assert_held(object);
	assertf(page_aligned(offset), "offset 0x%llx\n", offset);

	if (object->resident_page_count == 0) {
#if DEBUG_VM_PAGE_LOOKUP
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_empty_obj);
#endif
		return VM_PAGE_NULL;
	}

	mem = object->memq_hint;

	if (mem != VM_PAGE_NULL) {
		assert(VM_PAGE_OBJECT(mem) == object);

		if (mem->vmp_offset == offset) {
#if DEBUG_VM_PAGE_LOOKUP
			OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit_hint);
#endif
			return mem;
		}
		qe = (vm_page_queue_entry_t)vm_page_queue_next(&mem->vmp_listq);

		if (!vm_page_queue_end(&object->memq, qe)) {
			vm_page_t       next_page;

			next_page = (vm_page_t)((uintptr_t)qe);
			assert(VM_PAGE_OBJECT(next_page) == object);

			if (next_page->vmp_offset == offset) {
				object->memq_hint = next_page; /* new hint */
#if DEBUG_VM_PAGE_LOOKUP
				OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit_hint_next);
#endif
				return next_page;
			}
		}
		qe = (vm_page_queue_entry_t)vm_page_queue_prev(&mem->vmp_listq);

		if (!vm_page_queue_end(&object->memq, qe)) {
			vm_page_t prev_page;

			prev_page = (vm_page_t)((uintptr_t)qe);
			assert(VM_PAGE_OBJECT(prev_page) == object);

			if (prev_page->vmp_offset == offset) {
				object->memq_hint = prev_page; /* new hint */
#if DEBUG_VM_PAGE_LOOKUP
				OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit_hint_prev);
#endif
				return prev_page;
			}
		}
	}
	/*
	 * Search the hash table for this object/offset pair
	 */
	hash_id = vm_page_hash(object, offset);
	bucket = &vm_page_buckets[hash_id];

	/*
	 * since we hold the object lock, we are guaranteed that no
	 * new pages can be inserted into this object... this in turn
	 * guarantess that the page we're looking for can't exist
	 * if the bucket it hashes to is currently NULL even when looked
	 * at outside the scope of the hash bucket lock... this is a
	 * really cheap optimiztion to avoid taking the lock
	 */
	if (!bucket->page_list) {
#if DEBUG_VM_PAGE_LOOKUP
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_bucket_NULL);
#endif
		return VM_PAGE_NULL;
	}

#if DEBUG_VM_PAGE_LOOKUP
	start = mach_absolute_time();
#endif
	if (object->resident_page_count <= VM_PAGE_HASH_LOOKUP_THRESHOLD) {
		/*
		 * on average, it's roughly 3 times faster to run a short memq list
		 * than to take the spin lock and go through the hash list
		 */
		mem = (vm_page_t)vm_page_queue_first(&object->memq);

		while (!vm_page_queue_end(&object->memq, (vm_page_queue_entry_t)mem)) {
			if (mem->vmp_offset == offset) {
				break;
			}

			mem = (vm_page_t)vm_page_queue_next(&mem->vmp_listq);
		}
		if (vm_page_queue_end(&object->memq, (vm_page_queue_entry_t)mem)) {
			mem = NULL;
		}
	} else {
		bucket_lock = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];

		/*
		 * This lookup is extremely performance sensitive: in the
		 * zerofill path, the release barrier in the regular call to
		 * hw_lck_ticket_unlock() can stall when there is an in flight
		 * vm_page_zero_fill().
		 *
		 * To avoid having to synchronize with these in flight stores,
		 * given that the only thing we do is a read-only lookup of
		 * a page (mem), we can use hw_lck_ticket_unlock_after_lookup()
		 * which only orders "mem" with unlock but doesn't have an
		 * actual release barrier and allows for the vm_page_zero_fill()
		 * stores to bleed past this code.
		 *
		 * On arm64 devices this is a crucial optimization on the
		 * zerofill path that can yield 10-20% wins on a zerofill
		 * benchmark (and significant wins on macro benchmarks that
		 * happen to zerofill a lot).
		 */
		hw_lck_ticket_lock(bucket_lock, &vm_page_lck_grp_bucket);
		mem = vm_page_hash_lookup_data_dependent_locked(bucket, object, offset);
		hw_lck_ticket_unlock_after_lookup(bucket_lock, mem);
	}

#if DEBUG_VM_PAGE_LOOKUP
	elapsed = mach_absolute_time() - start;

	if (bucket_lock) {
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_slow);
		OSAddAtomic64(elapsed, &vm_page_lookup_stats.vpl_slow_elapsed);
	} else {
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_fast);
		OSAddAtomic64(elapsed, &vm_page_lookup_stats.vpl_fast_elapsed);
	}
	if (mem != VM_PAGE_NULL) {
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit);
	} else {
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_miss);
	}
#endif
	if (mem != VM_PAGE_NULL) {
		assert(VM_PAGE_OBJECT(mem) == object);

		object->memq_hint = mem;
	}
	return mem;
}


/*
 *	vm_page_rename:
 *
 *	Move the given memory entry from its
 *	current object to the specified target object/offset.
 *
 *	The object must be locked.
 */
void
vm_page_rename(
	vm_page_t               mem,
	vm_object_t             new_object,
	vm_object_offset_t      new_offset)
{
	boolean_t       internal_to_external, external_to_internal;
	vm_tag_t        tag;
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

	assert(m_object != new_object);
	assert(m_object);

	/*
	 *	Changes to mem->vmp_object require the page lock because
	 *	the pageout daemon uses that lock to get the object.
	 */
	vm_page_lockspin_queues();

	internal_to_external = FALSE;
	external_to_internal = FALSE;

	if (mem->vmp_q_state == VM_PAGE_ON_ACTIVE_LOCAL_Q) {
		/*
		 * it's much easier to get the vm_page_pageable_xxx accounting correct
		 * if we first move the page to the active queue... it's going to end
		 * up there anyway, and we don't do vm_page_rename's frequently enough
		 * for this to matter.
		 */
		vm_page_queues_remove(mem, FALSE);
		vm_page_activate(mem);
	}
	if (VM_PAGE_PAGEABLE(mem)) {
		if (m_object->internal && !new_object->internal) {
			internal_to_external = TRUE;
		}
		if (!m_object->internal && new_object->internal) {
			external_to_internal = TRUE;
		}
	}

	tag = m_object->wire_tag;
	vm_page_remove(mem);
	vm_page_insert_internal(mem, new_object, new_offset, tag, VMPI_Q_LOCKED, NULL);

	if (internal_to_external) {
		vm_page_pageable_internal_count--;
		vm_page_pageable_external_count++;
	} else if (external_to_internal) {
		vm_page_pageable_external_count--;
		vm_page_pageable_internal_count++;
	}

	vm_page_unlock_queues();
}

/*
 *	vm_page_init:
 *
 *	Initialize the fields in a new page.
 *	This takes a structure with random values and initializes it
 *	so that it can be given to vm_page_release or vm_page_insert.
 */
void
vm_page_init(vm_page_t mem, ppnum_t phys_page)
{
	assert(phys_page);

#if DEBUG
	if ((phys_page != vm_page_fictitious_addr) && (phys_page != vm_page_guard_addr)) {
		if (!(pmap_valid_page(phys_page))) {
			panic("vm_page_init: non-DRAM phys_page 0x%x", phys_page);
		}
	}
#endif /* DEBUG */

	/*
	 * Initialize the fields of the vm_page. If adding any new fields to vm_page,
	 * try to use initial values which match 0. This minimizes the number of writes
	 * needed for boot-time initialization.
	 */
	assert(VM_PAGE_NOT_ON_Q == 0);
	assert(sizeof(*mem) % sizeof(uintptr_t) == 0);
	*mem = (struct vm_page) {
		.vmp_offset      = (vm_object_offset_t)-1,
		.vmp_q_state     = VM_PAGE_NOT_ON_Q,
		.vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY,
		.vmp_canonical   = vm_page_in_array(mem),
		.vmp_busy        = true,
	};

	VM_PAGE_INIT_PHYS_PAGE(mem, phys_page);

#if 0
	/*
	 * we're leaving this turned off for now... currently pages
	 * come off the free list and are either immediately dirtied/referenced
	 * due to zero-fill or COW faults, or are used to read or write files...
	 * in the file I/O case, the UPL mechanism takes care of clearing
	 * the state of the HW ref/mod bits in a somewhat fragile way.
	 * Since we may change the way this works in the future (to toughen it up),
	 * I'm leaving this as a reminder of where these bits could get cleared
	 */

	/*
	 * make sure both the h/w referenced and modified bits are
	 * clear at this point... we are especially dependent on
	 * not finding a 'stale' h/w modified in a number of spots
	 * once this page goes back into use
	 */
	pmap_clear_refmod(phys_page, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
#endif
}

vm_page_t
vm_page_create_fictitious(void)
{
	return vm_page_create(vm_page_fictitious_addr, false, Z_WAITOK);
}

vm_page_t
vm_page_create_guard(bool canwait)
{
	return vm_page_create(vm_page_guard_addr, false, canwait ? Z_WAITOK : Z_NOWAIT);
}

vm_page_t
vm_page_create_private(ppnum_t base_page)
{
	assert(base_page != vm_page_fictitious_addr &&
	    base_page != vm_page_guard_addr);
	return vm_page_create(base_page, false, Z_WAITOK);
}

bool
vm_page_is_canonical(const struct vm_page *m)
{
	return m->vmp_canonical;
}

bool
vm_page_is_fictitious(const struct vm_page *m)
{
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
	if (vm_page_in_array(m)) {
		return false;
	}
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */
	switch (VM_PAGE_GET_PHYS_PAGE(m)) {
	case vm_page_guard_addr:
	case vm_page_fictitious_addr:
		return true;
	default:
		return false;
	}
}

bool
vm_page_is_guard(const struct vm_page *m)
{
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
	if (vm_page_in_array(m)) {
		return false;
	}
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */
	return VM_PAGE_GET_PHYS_PAGE(m) == vm_page_guard_addr;
}

bool
vm_page_is_private(const struct vm_page *m)
{
	return !vm_page_is_canonical(m) && !vm_page_is_fictitious(m);
}

void
vm_page_make_private(vm_page_t m, ppnum_t base_page)
{
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(VM_PAGE_GET_PHYS_PAGE(m) == vm_page_fictitious_addr);

	VM_PAGE_SET_PHYS_PAGE(m, base_page);
}

void
vm_page_reset_private(vm_page_t m)
{
	assert(vm_page_is_private(m));

	VM_PAGE_SET_PHYS_PAGE(m, vm_page_fictitious_addr);
}

/*
 *	vm_page_release_fictitious:
 *
 *	Release a fictitious page to the zone pool
 */
static void
vm_page_release_fictitious(vm_page_t m)
{
	assert((m->vmp_q_state == VM_PAGE_NOT_ON_Q) || VM_PAGE_WIRED(m));
	assert(vm_page_is_fictitious(m));
	assert(!m->vmp_realtime);

	if (vm_page_is_guard(m)) {
		counter_dec(&vm_guard_count);
	}
	zfree(vm_page_zone, m);
}

/*
 *	vm_pool_low():
 *
 *	Return true if it is not likely that a non-vm_privileged thread
 *	can get memory without blocking.  Advisory only, since the
 *	situation may change under us.
 */
bool
vm_pool_low(void)
{
	/* No locking, at worst we will fib. */
	return vm_page_free_count <= vm_page_free_reserved;
}

boolean_t vm_darkwake_mode = FALSE;

/*
 * vm_update_darkwake_mode():
 *
 * Tells the VM that the system is in / out of darkwake.
 *
 * Today, the VM only lowers/raises the background queue target
 * so as to favor consuming more/less background pages when
 * darwake is ON/OFF.
 *
 * We might need to do more things in the future.
 */

void
vm_update_darkwake_mode(boolean_t darkwake_mode)
{
#if XNU_TARGET_OS_OSX && defined(__arm64__)
#pragma unused(darkwake_mode)
	assert(vm_darkwake_mode == FALSE);
	/*
	 * Darkwake mode isn't supported for AS macOS.
	 */
	return;
#else /* XNU_TARGET_OS_OSX && __arm64__ */
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);

	vm_page_lockspin_queues();

	if (vm_darkwake_mode == darkwake_mode) {
		/*
		 * No change.
		 */
		vm_page_unlock_queues();
		return;
	}

	vm_darkwake_mode = darkwake_mode;

	if (vm_darkwake_mode == TRUE) {
		/* save background target to restore later */
		vm_page_background_target_snapshot = vm_page_background_target;

		/* target is set to 0...no protection for background pages */
		vm_page_background_target = 0;
	} else if (vm_darkwake_mode == FALSE) {
		if (vm_page_background_target_snapshot) {
			vm_page_background_target = vm_page_background_target_snapshot;
		}
	}
	vm_page_unlock_queues();
#endif
}

void
vm_page_update_special_state(vm_page_t mem)
{
	if (mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR || mem->vmp_on_specialq == VM_PAGE_SPECIAL_Q_EMPTY) {
		return;
	}

	switch (mem->vmp_on_specialq) {
	case VM_PAGE_SPECIAL_Q_BG:
	{
		task_t  my_task = current_task_early();

		if (vm_page_background_mode == VM_PAGE_BG_DISABLED) {
			return;
		}

		if (my_task) {
			if (task_get_darkwake_mode(my_task)) {
				return;
			}
		}

		if (my_task) {
			if (proc_get_effective_task_policy(my_task, TASK_POLICY_DARWIN_BG)) {
				return;
			}
		}
		vm_page_lockspin_queues();

		vm_page_background_promoted_count++;

		vm_page_remove_from_specialq(mem);
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;

		vm_page_unlock_queues();
		break;
	}

	case VM_PAGE_SPECIAL_Q_DONATE:
	{
		task_t  my_task = current_task_early();

		if (vm_page_donate_mode == VM_PAGE_DONATE_DISABLED) {
			return;
		}

		if (my_task->donates_own_pages == false) {
			vm_page_lockspin_queues();

			vm_page_remove_from_specialq(mem);
			mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;

			vm_page_unlock_queues();
		}
		break;
	}

	default:
	{
		assert(VM_PAGE_UNPACK_PTR(mem->vmp_specialq.next) == (uintptr_t)NULL &&
		    VM_PAGE_UNPACK_PTR(mem->vmp_specialq.prev) == (uintptr_t)NULL);
		break;
	}
	}
}


void
vm_page_assign_special_state(vm_page_t mem, vm_page_specialq_t mode)
{
	if (mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
		return;
	}

	switch (mode) {
	case VM_PAGE_SPECIAL_Q_BG:
	{
		if (vm_page_background_mode == VM_PAGE_BG_DISABLED) {
			return;
		}

		task_t  my_task = current_task_early();

		if (my_task) {
			if (task_get_darkwake_mode(my_task)) {
				mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_BG;
				return;
			}
		}

		if (my_task) {
			mem->vmp_on_specialq = (proc_get_effective_task_policy(my_task, TASK_POLICY_DARWIN_BG) ? VM_PAGE_SPECIAL_Q_BG : VM_PAGE_SPECIAL_Q_EMPTY);
		}
		break;
	}

	case VM_PAGE_SPECIAL_Q_DONATE:
	{
		if (vm_page_donate_mode == VM_PAGE_DONATE_DISABLED) {
			return;
		}
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_DONATE;
		break;
	}

	default:
		break;
	}
}


void
vm_page_remove_from_specialq(vm_page_t mem)
{
	vm_object_t     m_object;

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	switch (mem->vmp_on_specialq) {
	case VM_PAGE_SPECIAL_Q_BG:
	{
		if (mem->vmp_specialq.next && mem->vmp_specialq.prev) {
			vm_page_queue_remove(&vm_page_queue_background, mem, vmp_specialq);

			mem->vmp_specialq.next = 0;
			mem->vmp_specialq.prev = 0;

			vm_page_background_count--;

			m_object = VM_PAGE_OBJECT(mem);

			if (m_object->internal) {
				vm_page_background_internal_count--;
			} else {
				vm_page_background_external_count--;
			}
		}
		break;
	}

	case VM_PAGE_SPECIAL_Q_DONATE:
	{
		if (mem->vmp_specialq.next && mem->vmp_specialq.prev) {
			vm_page_queue_remove((vm_page_queue_head_t*)&vm_page_queue_donate, mem, vmp_specialq);
			mem->vmp_specialq.next = 0;
			mem->vmp_specialq.prev = 0;
			vm_page_donate_count--;
			if (vm_page_donate_queue_ripe && (vm_page_donate_count < vm_page_donate_target)) {
				assert(vm_page_donate_target == vm_page_donate_target_low);
				vm_page_donate_target = vm_page_donate_target_high;
				vm_page_donate_queue_ripe = false;
			}
		}

		break;
	}

	default:
	{
		assert(VM_PAGE_UNPACK_PTR(mem->vmp_specialq.next) == (uintptr_t)NULL &&
		    VM_PAGE_UNPACK_PTR(mem->vmp_specialq.prev) == (uintptr_t)NULL);
		break;
	}
	}
}


void
vm_page_add_to_specialq(vm_page_t mem, boolean_t first)
{
	vm_object_t     m_object;

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (mem->vmp_specialq.next && mem->vmp_specialq.prev) {
		return;
	}

	switch (mem->vmp_on_specialq) {
	case VM_PAGE_SPECIAL_Q_BG:
	{
		if (vm_page_background_mode == VM_PAGE_BG_DISABLED) {
			return;
		}

		m_object = VM_PAGE_OBJECT(mem);

		if (vm_page_background_exclude_external && !m_object->internal) {
			return;
		}

		if (first == TRUE) {
			vm_page_queue_enter_first(&vm_page_queue_background, mem, vmp_specialq);
		} else {
			vm_page_queue_enter(&vm_page_queue_background, mem, vmp_specialq);
		}
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_BG;

		vm_page_background_count++;

		if (m_object->internal) {
			vm_page_background_internal_count++;
		} else {
			vm_page_background_external_count++;
		}
		break;
	}

	case VM_PAGE_SPECIAL_Q_DONATE:
	{
		if (first == TRUE) {
			vm_page_queue_enter_first((vm_page_queue_head_t*)&vm_page_queue_donate, mem, vmp_specialq);
		} else {
			vm_page_queue_enter((vm_page_queue_head_t*)&vm_page_queue_donate, mem, vmp_specialq);
		}
		vm_page_donate_count++;
		if (!vm_page_donate_queue_ripe && (vm_page_donate_count > vm_page_donate_target)) {
			assert(vm_page_donate_target == vm_page_donate_target_high);
			vm_page_donate_target = vm_page_donate_target_low;
			vm_page_donate_queue_ripe = true;
		}
		mem->vmp_on_specialq = VM_PAGE_SPECIAL_Q_DONATE;
		break;
	}

	default:
		break;
	}
}

/*!
 * @brief
 * Prepares a page that has been successfully grabbed for the caller.
 *
 * @discussion
 * This function will update accounting, emit tracements, ...
 */
__static_testable vm_page_t
vm_page_grab_finalize(vm_grab_options_t grab_options __kdebug_only, vm_page_t mem)
{
	task_t task;

#if MACH_ASSERT
	/*
	 * For all free pages, no matter their provenance...
	 * ensure they are not referenced anywhere,
	 * and their state is clean.
	 */
	if (vm_check_refs_on_alloc) {
		pmap_recycle_page(VM_PAGE_GET_PHYS_PAGE(mem));
	}
	assert(!pmap_is_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem)));
	assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0 &&
	    mem->vmp_listq.next == 0 && mem->vmp_listq.prev == 0 &&
	    mem->vmp_specialq.next == 0 && mem->vmp_specialq.prev == 0 &&
	    mem->vmp_next_m == 0 &&
	    mem->vmp_object == 0 &&
	    mem->vmp_wire_count == 0 &&
	    mem->vmp_busy &&
	    !mem->vmp_tabled &&
	    !mem->vmp_laundry &&
	    !mem->vmp_pmapped &&
	    !mem->vmp_wpmapped &&
	    !mem->vmp_realtime);
#endif /* MACH_ASSERT */

	mem->vmp_q_state = VM_PAGE_NOT_ON_Q;
	VM_PAGE_ZERO_PAGEQ_ENTRY(mem);

#if HAS_MTE
	if (!(grab_options & VM_PAGE_GRAB_ALLOW_TAG_STORAGE)) {
		assert(!vm_page_is_tag_storage(mem));
	}
	if (grab_options & VM_PAGE_GRAB_MTE) {
		assert(mem->vmp_using_mte);
		counter_inc(&vm_mte_tagged_pages_grabbed);
		VM_DEBUG_EVENT(vm_page_grab, DBG_VM_PAGE_GRAB_MTE,
		    DBG_FUNC_NONE, grab_options, 0, 0, 0);
	} else
#endif /* HAS_MTE */
	{
#if HAS_MTE
		if (mem->vmp_using_mte) {
			counter_inc(&vm_mte_tagged_pages_grabbed_for_untagged);
		}
#endif /* HAS_MTE */
		VM_DEBUG_EVENT(vm_page_grab, DBG_VM_PAGE_GRAB,
		    DBG_FUNC_NONE, grab_options, 0, 0, 0);
	}

	ledger_credit(current_thread()->t_ledger,
	    task_ledgers.pages_grabbed, 1);
	counter_inc(&vm_page_grab_count);

	task = current_task_early();
	if (task != TASK_NULL && task != kernel_task) {
		/*
		 * tag:DONATE this is where the donate state of the page
		 * is decided according to what task grabs it
		 */
		if (task->donates_own_pages) {
			vm_page_assign_special_state(mem, VM_PAGE_SPECIAL_Q_DONATE);
		} else {
			vm_page_assign_special_state(mem, VM_PAGE_SPECIAL_Q_BG);
		}
	}

	if (grab_options & VM_PAGE_GRAB_ZERO_FILL) {
		vm_page_zero_fill(mem);
	}
	return mem;
}

#if __x86_64__
/*
 * This can be switched to FALSE to help debug drivers
 * that are having problems with memory > 4G.
 */
boolean_t       vm_himemory_mode = TRUE;
#endif /* __x86_64__ */

#if XNU_VM_HAS_LOPAGE

vm_page_t
vm_page_grablo(vm_grab_options_t options)
{
	vm_page_t mem = VM_PAGE_NULL;

	if (!vm_lopage_needed) {
		return vm_page_grab_options(options);
	}

	vm_free_page_lock_spin();
	if (vm_lopage_free_count) {
#if LCK_MTX_USE_ARCH
		/*
		 * Intel locks do not really always disable preemption
		 * for lck_mtx_lock_spin(), and vm_page_free_queue_grab()
		 * really want that.
		 */
		disable_preemption();
#endif
		mem = vm_page_free_queue_grab(PERCPU_GET(vm_page_pcpu), options,
		    VM_MEMORY_CLASS_LOPAGE, 1, VM_PAGE_NOT_ON_Q).vmpl_head;
#if LCK_MTX_USE_ARCH
		enable_preemption();
#endif
	}
	vm_free_page_unlock();

	if (mem == VM_PAGE_NULL) {
		if (cpm_allocate(PAGE_SIZE, &mem, atop(PPNUM_MAX), 0, FALSE, KMA_LOMEM) != KERN_SUCCESS) {
			vm_free_page_lock_spin();
			vm_lopages_allocated_cpm_failed++;
			vm_free_page_unlock();

			return VM_PAGE_NULL;
		}
		assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);

		mem->vmp_busy = TRUE;

		vm_page_lockspin_queues();

		mem->vmp_gobbled = FALSE;
		vm_page_gobble_count--;
		vm_page_wire_count--;

		vm_lopages_allocated_cpm_success++;
		vm_page_unlock_queues();
	}

	return vm_page_grab_finalize(options, mem);
}

#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY

/*!
 * @brief
 * Attempt to allocate a page from the secluded queue
 *
 * @discussion
 * This function will check that the caller is eligible
 * for the secluded pool, and if not, return VM_PAGE_NULL.
 */
__attribute__((noinline))
static vm_page_t
vm_page_grab_secluded(vm_grab_options_t grab_options)
{
	vm_page_t       mem;
	vm_object_t     object;
	int             refmod_state;

#if HAS_MTE
	if (grab_options & VM_PAGE_GRAB_MTE) {
		return VM_PAGE_NULL;
	}
#endif /* HAS_MTE */
	if (vm_page_secluded_count == 0) {
		return VM_PAGE_NULL;
	}

	if (grab_options & VM_PAGE_GRAB_SECLUDED) {
		vm_page_secluded.grab_for_iokit++;
	} else if (!task_can_use_secluded_mem(current_task(), TRUE)) {
		return VM_PAGE_NULL;
	}


	/* secluded queue is protected by the VM page queue lock */
	vm_page_lock_queues();

	if (vm_page_secluded_count == 0) {
		/* no secluded pages to grab... */
		vm_page_unlock_queues();
		return VM_PAGE_NULL;
	}

#if 00
	/* can we grab from the secluded queue? */
	if (vm_page_secluded_count > vm_page_secluded_target ||
	    (vm_page_secluded_count > 0 &&
	    task_can_use_secluded_mem(current_task(), TRUE))) {
		/* OK */
	} else {
		/* can't grab from secluded queue... */
		vm_page_unlock_queues();
		return VM_PAGE_NULL;
	}
#endif

	/* we can grab a page from secluded queue! */
	assert((vm_page_secluded_count_free +
	    vm_page_secluded_count_inuse) ==
	    vm_page_secluded_count);
	if (current_task()->task_can_use_secluded_mem) {
		assert(num_tasks_can_use_secluded_mem > 0);
	}
	assert(!vm_page_queue_empty(&vm_page_queue_secluded));
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	mem = (vm_page_t)vm_page_queue_first(&vm_page_queue_secluded);
	assert(mem->vmp_q_state == VM_PAGE_ON_SECLUDED_Q);
	vm_page_queues_remove(mem, TRUE);

	object = VM_PAGE_OBJECT(mem);

	assert(!vm_page_is_fictitious(mem));
	assert(!VM_PAGE_WIRED(mem));
	if (object == VM_OBJECT_NULL) {
		/* free for grab! */
		vm_page_unlock_queues();
		vm_page_secluded.grab_success_free++;
		goto out_success;
	}

	assert(!object->internal);
//	vm_page_pageable_external_count--;

	if (!vm_object_lock_try(object)) {
//		printf("SECLUDED: page %p: object %p locked\n", mem, object);
		vm_page_secluded.grab_failure_locked++;
reactivate_secluded_page:
		vm_page_activate(mem);
		vm_page_unlock_queues();
		return VM_PAGE_NULL;
	}
	if (mem->vmp_busy ||
	    mem->vmp_cleaning ||
	    mem->vmp_laundry) {
		/* can't steal page in this state... */
		vm_object_unlock(object);
		vm_page_secluded.grab_failure_state++;
		goto reactivate_secluded_page;
	}
	if (mem->vmp_realtime) {
		/* don't steal pages used by realtime threads... */
		vm_object_unlock(object);
		vm_page_secluded.grab_failure_realtime++;
		goto reactivate_secluded_page;
	}

	mem->vmp_busy = TRUE;
	refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));
	if (refmod_state & VM_MEM_REFERENCED) {
		mem->vmp_reference = TRUE;
	}
	if (refmod_state & VM_MEM_MODIFIED) {
		SET_PAGE_DIRTY(mem, FALSE);
	}
	if (mem->vmp_dirty || mem->vmp_precious) {
		/* can't grab a dirty page; re-activate */
//		printf("SECLUDED: dirty page %p\n", mem);
		vm_page_wakeup_done(object, mem);
		vm_page_secluded.grab_failure_dirty++;
		vm_object_unlock(object);
		goto reactivate_secluded_page;
	}
	if (mem->vmp_reference) {
		/* it's been used but we do need to grab a page... */
	}

	vm_page_unlock_queues();

	/* finish what vm_page_free() would have done... */
	vm_page_free_prepare_object(mem);
	vm_object_unlock(object);
	object = VM_OBJECT_NULL;

	pmap_clear_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
	vm_page_secluded.grab_success_other++;

out_success:

	if (grab_options & VM_PAGE_GRAB_SECLUDED) {
		vm_page_secluded.grab_for_iokit_success++;
	}
	return mem;
}

uint64_t
vm_page_secluded_drain(void)
{
	vm_page_t local_freeq;
	int local_freed;
	uint64_t num_reclaimed;
	unsigned int saved_secluded_count, saved_secluded_target;

	num_reclaimed = 0;
	local_freeq = NULL;
	local_freed = 0;

	vm_page_lock_queues();

	saved_secluded_count = vm_page_secluded_count;
	saved_secluded_target = vm_page_secluded_target;
	vm_page_secluded_target = 0;
	VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();
	while (vm_page_secluded_count) {
		vm_page_t secluded_page;

		assert((vm_page_secluded_count_free +
		    vm_page_secluded_count_inuse) ==
		    vm_page_secluded_count);
		secluded_page = (vm_page_t)vm_page_queue_first(&vm_page_queue_secluded);
		assert(secluded_page->vmp_q_state == VM_PAGE_ON_SECLUDED_Q);

		vm_page_queues_remove(secluded_page, FALSE);
		assert(!vm_page_is_fictitious(secluded_page));
		assert(!VM_PAGE_WIRED(secluded_page));

		if (secluded_page->vmp_object == 0) {
			/* transfer to free queue */
			assert(secluded_page->vmp_busy);
			secluded_page->vmp_snext = local_freeq;
			local_freeq = secluded_page;
			local_freed += 1;
		} else {
			/* transfer to head of active queue */
			vm_page_enqueue_active(secluded_page, FALSE);
			secluded_page = VM_PAGE_NULL;
		}
		num_reclaimed++;
	}
	vm_page_secluded_target = saved_secluded_target;
	VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();

//	printf("FBDP %s:%d secluded_count %d->%d, target %d, reclaimed %lld\n", __FUNCTION__, __LINE__, saved_secluded_count, vm_page_secluded_count, vm_page_secluded_target, num_reclaimed);

	vm_page_unlock_queues();

	if (local_freed) {
		vm_page_free_list(local_freeq, TRUE);
		local_freeq = NULL;
		local_freed = 0;
	}

	return num_reclaimed;
}

#endif /* CONFIG_SECLUDED_MEMORY */

/*!
 * @brief
 * Attempts to allocate a page from the specified per-cpu page queue.
 */
static vm_page_t
vm_page_grab_from_cpu(
	vm_grab_options_t      *options,
	vm_page_t              *zf_page,
	vm_page_t              *cpu_list,
	scalable_counter_t     *counter)
{
	vm_page_t mem = VM_PAGE_NULL;

	if ((*options & VM_PAGE_GRAB_ZERO_FILL) && (mem = *zf_page)) {
		*zf_page = VM_PAGE_NULL;
		*options &= ~VM_PAGE_GRAB_ZERO_FILL;
	} else if ((mem = _vm_page_list_pop(cpu_list)) == VM_PAGE_NULL) {
		return VM_PAGE_NULL;
	}

#if HIBERNATION
	if (hibernate_rebuild_needed) {
		panic("should not modify cpu->free_pages while hibernating");
	}
#endif /* HIBERNATION */
	counter_dec_preemption_disabled(counter);
	return mem;
}

#if HAS_MTE
/*!
 * @brief
 * Attempts to allocate pages from free tag storage percpu queue.
 */
static vm_page_t
vm_page_grab_claimed_from_cpu(vm_page_pcpu_t pcpu, vm_grab_options_t options)
{
	vm_page_t mem = VM_PAGE_NULL;

	if (!(options & VM_PAGE_GRAB_ALLOW_TAG_STORAGE)) {
		return VM_PAGE_NULL;
	}

	if (vm_page_queue_empty(&pcpu->free_claimed_pages)) {
		return VM_PAGE_NULL;
	}

	lck_ticket_lock(&pcpu->free_claimed_lock, &vm_page_lck_grp_bucket);

	if (!vm_page_queue_empty(&pcpu->free_claimed_pages)) {
		vm_page_queue_remove_first(&pcpu->free_claimed_pages,
		    mem, vmp_pageq);
		counter_dec_preemption_disabled(&vm_cpu_free_claimed_count);
		counter_inc(&vm_cpu_claimed_count);
		/* must be done immediately to synchronize with stealing */
		mem->vmp_q_state  = VM_PAGE_NOT_ON_Q;
		mem->vmp_local_id = 0;
	}

	lck_ticket_unlock(&pcpu->free_claimed_lock);

	return mem;
}
#endif /* HAS_MTE */

/*!
 * @brief
 * Attempts to allocate pages from free queues, and to populate the per-cpu
 * queue as a side effect.
 *
 * @discussion
 * This function will take the properties of the allocating thread into account
 * to decide how many pages it can allocate.
 *
 * If the free queues are depleted, then it will return VM_PAGE_NULL.
 */
__attribute__((noinline))
static vm_page_t
vm_page_grab_slow(vm_grab_options_t grab_options)
{
#if HAS_MTE
	unsigned int        mte_draw = 0;
	unsigned int        mte_slop = 0;
#endif /* HAS_MTE */
	unsigned int        target   = vm_free_magazine_refill_limit;
	vm_memory_class_t   class    = VM_MEMORY_CLASS_REGULAR;
	vm_page_t           mem      = VM_PAGE_NULL;
	vm_page_list_t      list     = { };
	vm_page_pcpu_t      vmp_pcpu = NULL;
	vm_page_t          *zf_page  = NULL;
	vm_page_t          *cpu_list = NULL;
	scalable_counter_t *counter  = NULL;

	vm_free_page_lock_spin();
#if LCK_MTX_USE_ARCH
	/* Intel does't disable preemption with vm_free_page_lock_spin() */
	disable_preemption();
#endif /* LCK_MTX_USE_ARCH */
	vmp_pcpu = PERCPU_GET(vm_page_pcpu);
	zf_page  = &vmp_pcpu->free_zero_page;
	cpu_list = &vmp_pcpu->free_pages;
	counter  = &vm_cpu_free_count;
#if HAS_MTE
	if (grab_options & VM_PAGE_GRAB_MTE) {
again:
		zf_page  = &vmp_pcpu->free_tagged_zero_page;
		cpu_list = &vmp_pcpu->free_tagged_pages;
		counter  = &vm_cpu_free_tagged_count;
		target   = vm_free_magazine_refill_limit / 2;
		class    = VM_MEMORY_CLASS_TAGGED;
		mte_slop = 0;
	} else if (grab_options & VM_PAGE_GRAB_ALLOW_TAG_STORAGE) {
		/*
		 * Note that this is the last time we'll explicitly try to grab
		 * free, claimable pages. If it comes down to it, we'll grab either
		 * normal or dead tag storage pages in vm_page_free_queue_grab()
		 * and hopefully refill the per-CPU free claimable queue.
		 */
		mem = vm_page_grab_claimed_from_cpu(vmp_pcpu, grab_options);
		if (mem != VM_PAGE_NULL) {
			vm_free_page_unlock();
			return mem;
		}
	}
#endif /* HAS_MTE */

	if (grab_options & VM_PAGE_GRAB_PRIME) {
		mem = *cpu_list ? VM_PAGE_PRIMED : VM_PAGE_NULL;
	} else {
		mem = vm_page_grab_from_cpu(&grab_options,
		    zf_page, cpu_list, counter);
	}
	if (mem != VM_PAGE_NULL) {
#if LCK_MTX_USE_ARCH
		enable_preemption();
#endif /* LCK_MTX_USE_ARCH */
		vm_free_page_unlock();
		return mem;
	}

	if (vm_page_free_count <= vm_page_free_reserved) {
		if ((grab_options & VM_PAGE_GRAB_VM_PRIV) == 0) {
			target = 0;
		} else if (vm_page_free_count == 0) {
			target = 0;
		} else {
			target = 1;
		}
	} else {
		target = MIN(target, vm_page_free_count - vm_page_free_reserved);
	}
#if HAS_MTE
	if (grab_options & VM_PAGE_GRAB_MTE) {
		mte_draw = target;
		target   = 0;
		if (vm_page_free_taggable_count < mte_draw + vm_page_free_min &&
		    vm_page_free_count >= mte_draw + vm_page_free_min &&
		    !(grab_options & VM_PAGE_GRAB_Q_LOCK_HELD)) {
			/*
			 * If the mte draw is such that we deplete our reserves,
			 * but there are enough free untaggable pages available,
			 * attempt to activate pages in order to rebalance
			 * toward the taggable pool.
			 *
			 * If the operation succeeds, the free page queue lock
			 * was dropped and we need to re-take it from the top.
			 */
			if (mteinfo_tag_storage_try_activate(mte_draw +
			    vm_page_free_min - vm_page_free_taggable_count,
			    /* lock_spin */ true)) {
				vmp_pcpu = PERCPU_GET(vm_page_pcpu);
				goto again;
			}
		}
	} else if (target > vm_page_free_count - vm_page_free_taggable_count) {
		mte_draw = target - (vm_page_free_count - vm_page_free_taggable_count);
		target   = (vm_page_free_count - vm_page_free_taggable_count);
	} else {
		mte_draw = 0;
	}

	if (vm_page_free_taggable_count <= vm_page_free_reserved) {
		if ((grab_options & VM_PAGE_GRAB_VM_PRIV) == 0) {
			mte_draw = 0;
		} else if (vm_page_free_taggable_count == 0) {
			mte_draw = 0;
		} else if (target) {
			mte_draw = 0;
		} else {
			mte_draw = 1;
		}
	} else {
		mte_draw = MIN(mte_draw,
		    vm_page_free_taggable_count - vm_page_free_reserved);
	}

	target += mte_draw;
#endif /* HAS_MTE */

#if HIBERNATION
	if (target > 0 && hibernate_rebuild_needed) {
		panic("should not modify CPU free_pages while hibernating");
	}
#endif /* HIBERNATION */

	/*
	 * Convert the lock hold into a mutex, to signal to waiters that the
	 * lock may be held for longer.
	 */
#if !LCK_MTX_USE_ARCH
	disable_preemption();
#endif /* !LCK_MTX_USE_ARCH */
	vm_free_page_lock_convert();

	if (target != 0) {
		list = vm_page_free_queue_grab(vmp_pcpu, grab_options,
		    class, target, VM_PAGE_ON_FREE_LOCAL_Q);
	}

#if VM_PAGE_WIRE_COUNT_WARNING
	if (vm_page_wire_count >= VM_PAGE_WIRE_COUNT_WARNING) {
		printf("mk: vm_page_grab(): high wired page count of %d\n",
		    vm_page_wire_count);
	}
#endif
#if VM_PAGE_GOBBLE_COUNT_WARNING
	if (vm_page_gobble_count >= VM_PAGE_GOBBLE_COUNT_WARNING) {
		printf("mk: vm_page_grab(): high gobbled page count of %d\n",
		    vm_page_gobble_count);
	}
#endif

	if (vm_page_free_count < vm_page_free_min && !vm_pageout_running) {
		thread_wakeup(&vm_page_free_wanted);
	}

	vm_free_page_unlock();

	VM_CHECK_MEMORYSTATUS;

	if (list.vmpl_head) {
#if HAS_MTE
		mteinfo_page_list_fix_tagging(class, &list);
#endif /* HAS_MTE */
		/* Steal a page off the list for the caller. */

		if (grab_options & VM_PAGE_GRAB_PRIME) {
			mem = VM_PAGE_PRIMED;
		} else {
			mem = vm_page_list_pop(&list);
		}

		/* Add the remaining pages to the CPU's free list. */
		assert(*cpu_list == VM_PAGE_NULL);
		counter_add_preemption_disabled(counter, list.vmpl_count);

		if ((grab_options & VM_PAGE_GRAB_PRIME) && !*zf_page &&
		    (*zf_page = vm_page_list_pop(&list))) {
			vm_page_zero_fill(*zf_page);
		}
		*cpu_list = list.vmpl_head;
		counter_add_preemption_disabled(counter, list.vmpl_count);
	}

	enable_preemption();

	return mem;
}

__mockable vm_page_t
vm_page_grab_options(vm_grab_options_t options)
{
	vm_page_pcpu_t      vmp_pcpu = NULL;
	vm_page_t          *zf_page  = NULL;
	vm_page_t          *cpu_list = NULL;
	scalable_counter_t *counter  = &vm_cpu_free_count;
	vm_page_t           mem      = VM_PAGE_NULL;

	if (current_thread()->options & TH_OPT_VMPRIV) {
		options |= VM_PAGE_GRAB_VM_PRIV;
	}

restart:
	/*
	 *	Step 1: look at the CPU magazines.
	 */

	disable_preemption();
	vmp_pcpu = PERCPU_GET(vm_page_pcpu);
	zf_page  = &vmp_pcpu->free_zero_page;
	cpu_list = &vmp_pcpu->free_pages;

#if HAS_MTE
	if (options & VM_PAGE_GRAB_MTE) {
		counter  = &vm_cpu_free_tagged_count;
		zf_page  = &vmp_pcpu->free_tagged_zero_page;
		cpu_list = &vmp_pcpu->free_tagged_pages;
	}

	if (options & VM_PAGE_GRAB_ALLOW_TAG_STORAGE) {
		mem = vm_page_grab_claimed_from_cpu(vmp_pcpu, options);
	}
	if (mem == VM_PAGE_NULL) {
		mem = vm_page_grab_from_cpu(&options,
		    zf_page, cpu_list, counter);
	}
#else
	mem = vm_page_grab_from_cpu(&options,
	    zf_page, cpu_list, counter);
#endif /* HAS_MTE */
	enable_preemption();

	if (mem != VM_PAGE_NULL) {
		return vm_page_grab_finalize(options, mem);
	}

#if XNU_VM_HAS_DELAYED_PAGES
	/*
	 *	If free count is low and we have delayed pages from early boot,
	 *	get one of those instead.
	 */
	if (__improbable(vm_delayed_count > 0 &&
	    vm_page_free_count <= vm_page_free_target)) {
		mem = vm_get_delayed_page(options);
		if (mem != VM_PAGE_NULL) {
			return vm_page_grab_finalize(options, mem);
		}
	}
#endif /* XNU_VM_HAS_DELAYED_PAGES */


	/*
	 *	Step 2: Try to promote pages from the free queues,
	 *	        or the secluded queue if appropriate.
	 */

	mem = vm_page_grab_slow(options);
	if (mem != VM_PAGE_NULL) {
		return vm_page_grab_finalize(options, mem);
	}

#if CONFIG_SECLUDED_MEMORY
	mem = vm_page_grab_secluded(options);
	if (mem != VM_PAGE_NULL) {
		return vm_page_grab_finalize(options, mem);
	}
#endif /* CONFIG_SECLUDED_MEMORY */


	/*
	 *	Step 3: Privileged threads block and retry, others fail.
	 */

#if HAS_MTE
	if (options & VM_PAGE_GRAB_MTE) {
		current_thread()->page_wait_class = VM_MEMORY_CLASS_TAGGED;
	} else {
		current_thread()->page_wait_class = VM_MEMORY_CLASS_REGULAR;
	}
#endif /* HAS_MTE */
	if ((options & (VM_PAGE_GRAB_NOPAGEWAIT | VM_PAGE_GRAB_VM_PRIV)) ==
	    VM_PAGE_GRAB_VM_PRIV) {
		VM_PAGE_WAIT();
		goto restart;
	}

	return VM_PAGE_NULL;
}

vm_grab_options_t
vm_page_grab_options_for_object(vm_object_t object __unused)
{
	vm_grab_options_t options = VM_PAGE_GRAB_OPTIONS_NONE;

#if CONFIG_SECLUDED_MEMORY
	if (object->can_grab_secluded) {
		options |= VM_PAGE_GRAB_SECLUDED;
	}
#endif /* CONFIG_SECLUDED_MEMORY */
#if HAS_MTE
	if (vm_object_is_mte_mappable(object)) {
		options |= VM_PAGE_GRAB_MTE;
	}
#endif /* HAS_MTE */

	return options;
}

__attribute__((always_inline))
void
vm_page_grab_prime(void)
{
	vm_page_pcpu_t vmp_pcpu;
	vm_page_t     *zfp;
	vm_page_t      mem;
#if HAS_MTE
	vm_page_t      tmem;
#endif /* HAS_MTE */

	disable_preemption();
	vmp_pcpu = PERCPU_GET(vm_page_pcpu);

	zfp = &vmp_pcpu->free_zero_page;
	if (!*zfp && (*zfp = _vm_page_list_pop(&vmp_pcpu->free_pages))) {
		vm_page_zero_fill(*zfp);
	}
	mem = vmp_pcpu->free_pages;
#if HAS_MTE

	zfp = &vmp_pcpu->free_tagged_zero_page;
	if (!*zfp && (*zfp = _vm_page_list_pop(&vmp_pcpu->free_tagged_pages))) {
		vm_page_zero_fill(*zfp);
	}
	tmem = vmp_pcpu->free_tagged_pages;
#endif /* HAS_MTE */
	enable_preemption();

	if (mem == VM_PAGE_NULL) {
		(void)vm_page_grab_slow(VM_PAGE_GRAB_NOPAGEWAIT |
		    VM_PAGE_GRAB_PRIME);
	}
#if HAS_MTE
	if (tmem == VM_PAGE_NULL) {
		(void)vm_page_grab_slow(VM_PAGE_GRAB_NOPAGEWAIT |
		    VM_PAGE_GRAB_PRIME | VM_PAGE_GRAB_MTE);
	}
#endif
}

/*!
 * @function vm_page_free_queue_steal()
 *
 * @abstract
 * Steal a given page from the free queues.
 *
 * @discussion
 * The given page must be in the given free queue, or state may be corrupted.
 *
 * Internally, the free queue is not synchronized, so any locking must be done
 * outside of this function.
 *
 * This function, like vm_page_grab(), takes care of waking up
 * page out scan as needed.
 */
static void
vm_page_free_queue_steal(vm_grab_options_t options, vm_page_t mem)
{
	ppnum_t           pnum  = VM_PAGE_GET_PHYS_PAGE(mem);
	vm_memory_class_t class = vm_page_get_memory_class(mem, pnum);

	assert(mem->vmp_q_state == VM_PAGE_ON_FREE_Q);
	assert(!mem->vmp_lopage && mem->vmp_busy);

	vm_page_free_queue_remove(class, mem, pnum, VM_PAGE_NOT_ON_Q);
	vm_page_grab_finalize(options, mem);

	if (vm_page_free_count < vm_page_free_min && !vm_pageout_running) {
		thread_wakeup(&vm_page_free_wanted);
	}
}

#if HAS_MTE
/*!
 * @function _vm_page_wait_wakeup_fill_thread()
 *
 * @abstract
 * Given the number of waiters, return whether the MTE fill thread should
 * wake up.
 *
 * @discussion
 * The idea is to wake up the MTE fill thread without explicitly triggering
 * pageout_scan(), which means @c vm_page_free_count must be at least
 * @c vm_page_free_min. On top of that, it's possible that tag storage pages
 * may get relocated, which means that some free untagged pages will be needed
 * to activate a tag storage page. This function uses the naive, pessimistic
 * heuristic that a given tag storage page does not have many free covered
 * pages, and some number of those tag storage pages will need to be relocated.
 *
 * The free queue lock should be held during this function.
 *
 * @param n_waiters					The number of waiters for tagged memory.
 *
 * @returns							Whether the system has enough free pages to
 *                                  wake up the MTE fill thread.
 */
static bool
_vm_page_wait_wakeup_fill_thread(uint32_t n_waiters)
{
	LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);
	return vm_page_free_count > vm_page_free_min + (3 * n_waiters) / 2;
}
#endif /* HAS_MTE */

/*
 *	vm_page_wait:
 *
 *	Wait for a page to become available.
 *	If there are plenty of free pages, then we don't sleep.
 *
 *	Returns:
 *		TRUE:  There may be another page, try again
 *		FALSE: We were interrupted out of our wait, don't try again
 */

boolean_t
vm_page_wait(int interruptible)
{
	/*
	 *	We can't use vm_page_free_reserved to make this
	 *	determination.  Consider: some thread might
	 *	need to allocate two pages.  The first allocation
	 *	succeeds, the second fails.  After the first page is freed,
	 *	a call to vm_page_wait must really block.
	 */
	kern_return_t wait_result   = THREAD_NOT_WAITING;
	thread_t      cur_thread    = current_thread();
	bool          is_privileged = cur_thread->options & TH_OPT_VMPRIV;
	bool          need_wakeup   = false;
	event_t       wait_event    = NULL;
#if HAS_MTE
	bool              wakeup_refill_thread = false;
#endif /* HAS_MTE */

	vm_free_page_lock_spin();

#if HAS_MTE
	if (cur_thread->page_wait_class == VM_MEMORY_CLASS_TAGGED) {
		if (is_privileged) {
			if (vm_page_free_taggable_count) {
				vm_free_page_unlock();
				goto out;
			}

			if (vm_page_free_wanted_tagged_privileged++ == 0) {
				need_wakeup = true;
			}

			wait_event = (event_t)&vm_page_free_wanted_tagged_privileged;
		} else if (vm_page_free_taggable_count >= vm_page_free_target) {
			vm_free_page_unlock();
			goto out;
		} else {
			if (vm_page_free_wanted_tagged++ == 0) {
				wakeup_refill_thread = true;
			}

			wait_event = (event_t)&vm_page_free_wanted_tagged;
		}
	} else
#endif /* !HAS_MTE */
	if (is_privileged) {
		if (vm_page_free_count) {
			vm_free_page_unlock();
			goto out;
		}

		if (vm_page_free_wanted_privileged++ == 0) {
			need_wakeup = true;
		}

		wait_event = (event_t)&vm_page_free_wanted_privileged;
	} else if (vm_page_free_count >= vm_page_free_target) {
		vm_free_page_unlock();
		goto out;
#if CONFIG_SECLUDED_MEMORY
	} else if (secluded_for_apps &&
	    task_can_use_secluded_mem(current_task(), FALSE)) {
#if 00
		/* XXX FBDP: need pageq lock for this... */
		/* XXX FBDP: might wait even if pages available, */
		/* XXX FBDP: hopefully not for too long... */
		if (vm_page_secluded_count > 0) {
			vm_free_page_unlock();
			goto out;
		}
#endif
		if (vm_page_free_wanted_secluded++ == 0) {
			need_wakeup = true;
		}

		wait_event = (event_t)&vm_page_free_wanted_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
	} else {
		if (vm_page_free_wanted++ == 0) {
			need_wakeup = true;
		}

		wait_event = (event_t)&vm_page_free_count;
	}

#if HAS_MTE
	/*
	 * If we're here, it means that the free taggable count is low.
	 * If there are enough free pages in the system, we can ask the
	 * fill thread to convert some free untagged pages to free tagged
	 * pages. Otherwise, we will wake up pageout_scan(), which will
	 * free pages, and on the free path, the fill thread will get woken up
	 * (see vm_page_free_queue_handle_wakeups_and_unlock()).
	 *
	 * The fill thread will run or not run under a variety of conditions
	 * (see mteinfo_tag_storage_active_should_refill() for more details),
	 * but what's relevant here is that the fill thread will run so long
	 * as there are tagged waiters. We should at least ensure that the
	 * system has enough free untagged memory to service the existing
	 * tagged waiters.
	 */
	if (wakeup_refill_thread) {
		uint32_t total_tagged_waiters = vm_page_free_wanted_tagged +
		    +vm_page_free_wanted_tagged_privileged;
		if (_vm_page_wait_wakeup_fill_thread(total_tagged_waiters)) {
			/* If there are enough pages for all tagged waiters. */
		} else {
			/*
			 * Otherwise, wake up pageout_scan(), and the fill thread will
			 * run later.
			 */
			wakeup_refill_thread = false;
			need_wakeup = true;
		}
	}

#endif /* HAS_MTE */
	if (vm_pageout_running) {
		need_wakeup = false;
	}

	/*
	 * We don't do a vm_pageout_scan wakeup if we already have
	 * some waiters because vm_pageout_scan checks for waiters
	 * before it returns and does so behind the vm_page_queue_free_lock,
	 * which we own when we bump the waiter counts.
	 */

	if (vps_dynamic_priority_enabled) {
		/*
		 * We are waking up vm_pageout_scan here. If it needs
		 * the vm_page_queue_free_lock before we unlock it
		 * we'll end up just blocking and incur an extra
		 * context switch. Could be a perf. issue.
		 */

#if HAS_MTE
		if (cur_thread->page_wait_class != VM_MEMORY_CLASS_REGULAR) {
			panic("vm_page_wait does not support MTE+vps_dynamic_priority_enabled");
		}
#endif /* HAS_MTE */
		if (need_wakeup) {
			thread_wakeup((event_t)&vm_page_free_wanted);
		}

		/*
		 * LD: This event is going to get recorded every time because
		 * we don't get back THREAD_WAITING from lck_mtx_sleep_with_inheritor.
		 * We just block in that routine.
		 */
		VM_DEBUG_CONSTANT_EVENT(vm_page_wait_block, DBG_VM_PAGE_WAIT_BLOCK, DBG_FUNC_START,
		    vm_page_free_wanted_privileged,
		    vm_page_free_wanted,
#if CONFIG_SECLUDED_MEMORY
		    vm_page_free_wanted_secluded,
#else /* CONFIG_SECLUDED_MEMORY */
		    0,
#endif /* CONFIG_SECLUDED_MEMORY */
		    0);
		wait_result =  lck_mtx_sleep_with_inheritor(&vm_page_queue_free_lock,
		    LCK_SLEEP_UNLOCK,
		    wait_event,
		    vm_pageout_scan_thread,
		    interruptible,
		    0);
	} else {
		wait_result = assert_wait(wait_event, interruptible);

		vm_free_page_unlock();

		if (need_wakeup) {
			thread_wakeup((event_t)&vm_page_free_wanted);
		}
#if HAS_MTE
		if (wakeup_refill_thread) {
			assert(!need_wakeup);
			mteinfo_wake_fill_thread();
		}
#endif /* HAS_MTE */

		if (wait_result != THREAD_WAITING) {
			goto out;
		}

#if HAS_MTE
		if (cur_thread->page_wait_class == VM_MEMORY_CLASS_TAGGED) {
			VM_DEBUG_CONSTANT_EVENT(vm_page_wait_block,
			    DBG_VM_PAGE_MTE_WAIT_BLOCK,
			    DBG_FUNC_START,
			    vm_page_free_wanted_tagged_privileged,
			    vm_page_free_wanted_tagged,
			    0,
			    0);
			wait_result = thread_block(THREAD_CONTINUE_NULL);
			VM_DEBUG_CONSTANT_EVENT(vm_page_wait_block,
			    DBG_VM_PAGE_MTE_WAIT_BLOCK, DBG_FUNC_END, 0, 0, 0, 0);
			goto out;
		}
#endif /* HAS_MTE */

		VM_DEBUG_CONSTANT_EVENT(vm_page_wait_block,
		    DBG_VM_PAGE_WAIT_BLOCK,
		    DBG_FUNC_START,
		    vm_page_free_wanted_privileged,
		    vm_page_free_wanted,
#if CONFIG_SECLUDED_MEMORY
		    vm_page_free_wanted_secluded,
#else /* CONFIG_SECLUDED_MEMORY */
		    0,
#endif /* CONFIG_SECLUDED_MEMORY */
		    0);
		wait_result = thread_block(THREAD_CONTINUE_NULL);
		VM_DEBUG_CONSTANT_EVENT(vm_page_wait_block,
		    DBG_VM_PAGE_WAIT_BLOCK, DBG_FUNC_END, 0, 0, 0, 0);
	}

out:
#if HAS_MTE
	cur_thread->page_wait_class = VM_MEMORY_CLASS_REGULAR;
#endif /* HAS_MTE */
	return (wait_result == THREAD_AWAKENED) || (wait_result == THREAD_NOT_WAITING);
}

/*
 *	vm_page_free_prepare:
 *
 *	Removes page from any queue it may be on
 *	and disassociates it from its VM object.
 *
 *	Object and page queues must be locked prior to entry.
 */
static void
vm_page_free_prepare(
	vm_page_t       mem)
{
	vm_page_free_prepare_queues(mem);
	vm_page_free_prepare_object(mem);
#if CONFIG_SPTM
	/**
	 * The pmap should retype frames as necessary when pmap_recycle_page()
	 * is called. In order to catch potential cases where this does not
	 * happen, add an appropriate assert here. This code should be
	 * executed on every frame that is about to be released to the VM.
	 */
	const sptm_paddr_t paddr = ((uint64_t)VM_PAGE_GET_PHYS_PAGE(mem)) << PAGE_SHIFT;
	__unused const sptm_frame_type_t frame_type = sptm_get_frame_type(paddr);

	assert(frame_type == XNU_DEFAULT);
#endif /* CONFIG_SPTM */

#if HAS_MTE
	/*
	 * At this point, any busy bit on `mem` has been cleared. If the refill
	 * thread wanted this page, update the cell state from PINNED to CLAIMED.
	 *
	 * We only expect to come through here when swap-ins/outs have erred.
	 */
	if (mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR && mem->vmp_ts_wanted) {
		mteinfo_tag_storage_wakeup(mem, false);
	}
#endif /* HAS_MTE */
}


void
vm_page_free_prepare_queues(
	vm_page_t       mem)
{
	vm_object_t     m_object;

	VM_PAGE_CHECK(mem);

	assert(mem->vmp_q_state != VM_PAGE_ON_FREE_Q);
	assert(!mem->vmp_cleaning);
	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	if (m_object) {
		vm_object_lock_assert_exclusive(m_object);
	}
	if (mem->vmp_laundry) {
		/*
		 * We may have to free a page while it's being laundered
		 * if we lost its pager (due to a forced unmount, for example).
		 * We need to call vm_pageout_steal_laundry() before removing
		 * the page from its VM object, so that we can remove it
		 * from its pageout queue and adjust the laundry accounting
		 */
		vm_pageout_steal_laundry(mem, TRUE);
	}

	vm_page_queues_remove(mem, TRUE);

	if (mem->vmp_realtime) {
		mem->vmp_realtime = false;
		VM_COUNTER_DEC(&vm_page_realtime_count);
	}

	if (VM_PAGE_WIRED(mem)) {
		assert(mem->vmp_wire_count > 0);

		if (m_object) {
			ledger_t      ledger;
			vmo_ledgers_t lidx;

			VM_OBJECT_WIRED_PAGE_UPDATE_START(m_object);
			VM_OBJECT_WIRED_PAGE_REMOVE(m_object, mem);
			VM_OBJECT_WIRED_PAGE_UPDATE_END(m_object, m_object->wire_tag);

			assert(m_object->resident_page_count >=
			    m_object->wired_page_count);

			if (m_object->purgable == VM_PURGABLE_VOLATILE) {
				counter_inc(&vm_page_purgeable_count);
				counter_dec(&vm_page_purgeable_wired_count);
			}
			if (m_object->internal &&
			    (m_object->purgable == VM_PURGABLE_VOLATILE ||
			    m_object->purgable == VM_PURGABLE_EMPTY) &&
			    (ledger = VM_OBJECT_LEDGER(m_object))) {
				lidx = vm_object_ledger_tag_ledgers(m_object);

				disable_preemption();
				/*
				 * While wired, this page was accounted
				 * as "non-volatile" but it should now
				 * be accounted as "volatile".
				 */
				/* one less "non-volatile"... */
				ledger_debit_nopreempt(ledger,
				    lidx.vmo_nonvolatile, PAGE_SIZE);
				ledger_debit_nopreempt(ledger,
				    lidx.vmo_footprint, PAGE_SIZE);
				/* one more "volatile" */
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_volatile, PAGE_SIZE);
				enable_preemption();
			}
		}
		if (vm_page_is_canonical(mem)) {
			vm_page_wire_count--;
		}

#if HAS_MTE
		mteinfo_decrement_wire_count(mem, true);
#endif /* HAS_MTE */

		mem->vmp_q_state = VM_PAGE_NOT_ON_Q;
		mem->vmp_wire_count = 0;
		assert(!mem->vmp_gobbled);
	} else if (mem->vmp_gobbled) {
		if (vm_page_is_canonical(mem)) {
			vm_page_wire_count--;
		}
		vm_page_gobble_count--;
	}
}

/*
 * like vm_page_init, but we have to preserve fields related to phys page
 */
inline static void
vm_page_reset_canonical(vm_page_t mem)
{
	*mem = (struct vm_page){
		.vmp_offset      = (vm_object_offset_t)-1,
		.vmp_q_state     = VM_PAGE_NOT_ON_Q,
		.vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY,
#if XNU_VM_HAS_LOPAGE
		.vmp_lopage      = mem->vmp_lopage,
#endif /* XNU_VM_HAS_LOPAGE */
		.vmp_canonical   = true,
		.vmp_busy        = true,
		.vmp_realtime    = mem->vmp_realtime,
#if HAS_MTE
		.vmp_using_mte   = mem->vmp_using_mte,
#endif
#if !XNU_VM_HAS_LINEAR_PAGES_ARRAY
		.vmp_phys_page   = mem->vmp_phys_page,
#endif /* !XNU_VM_HAS_LINEAR_PAGES_ARRAY */
	};
	/* ECC information is out of `struct vm_page` and preserved */
}

void
vm_page_free_prepare_object(vm_page_t mem)
{
	if (mem->vmp_tabled) {
		vm_page_remove(mem);  /* clears tabled, object, offset */
	}
	vm_page_wakeup(VM_OBJECT_NULL, mem);               /* clears wanted */

	if (vm_page_is_private(mem)) {
		vm_page_reset_private(mem);
	}
	if (vm_page_is_canonical(mem)) {
		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0 &&
		    mem->vmp_listq.next == 0 && mem->vmp_listq.prev == 0 &&
		    mem->vmp_specialq.next == 0 && mem->vmp_specialq.prev == 0 &&
		    mem->vmp_next_m == 0);

		pmap_recycle_page(VM_PAGE_GET_PHYS_PAGE(mem));

		vm_page_reset_canonical(mem);
	}
}

/*
 *	vm_page_release:
 *
 *	Return a page to the free list.
 *
 *	Keep in sync with vm_page_free_list().
 */

void
vm_page_release(vm_page_t mem, vmp_release_options_t options)
{
	if (options & VMP_RELEASE_Q_LOCKED) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	} else {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
	}

	assert(vm_page_is_canonical(mem));
	assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);

	if ((options & VMP_RELEASE_SKIP_FREE_CHECK) == 0) {
		pmap_recycle_page(VM_PAGE_GET_PHYS_PAGE(mem));
	}

	pmap_clear_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));


	vm_page_free_queue_enter_list(vm_page_list_for_page(mem), options);
}

/*
 * This version of vm_page_release() is used only at startup
 * when we are single-threaded and pages are being released
 * for the first time. Hence, no locking or unnecessary checks are made.
 * Note: VM_CHECK_MEMORYSTATUS invoked by the caller.
 */
void
vm_page_release_startup(vm_page_t mem)
{
#if HAS_MTE
	if (pmap_in_tag_storage_range(VM_PAGE_GET_PHYS_PAGE(mem)) && mte_enabled()) {
		/*
		 * Add the MTE tag page to the FREE_MTE_TAG queue.  These pages
		 * can be used/claimed for other purposes (other than tag pages)
		 * provided that they can be reclaimed quickly without waiting
		 * on I/O, e.g. readonly/clean file pages.
		 */
		mteinfo_tag_storage_release_startup(mem);
		return;
	}
#endif /* HAS_MTE */
	vm_page_free_queue_enter_list(vm_page_list_for_page(mem),
	    VMP_RELEASE_STARTUP);
}

/*
 *	vm_page_free:
 *
 *	Returns the given page to the free list,
 *	disassociating it with any VM object.
 *
 *	Object and page queues must be locked prior to entry.
 */
void
vm_page_free(vm_page_t mem)
{
	vm_page_free_prepare(mem);

	if (vm_page_is_canonical(mem)) {
		/* page queues are locked */
		vm_page_release(mem, VMP_RELEASE_Q_LOCKED |
		    VMP_RELEASE_SKIP_FREE_CHECK);
	} else {
		vm_page_release_fictitious(mem);
	}
}


void
vm_page_free_unlocked(vm_page_t mem)
{
	vm_page_lockspin_queues();
	vm_page_free_prepare_queues(mem);
	vm_page_unlock_queues();

	vm_page_free_prepare_object(mem);

	if (vm_page_is_canonical(mem)) {
		/* page queues are not locked */
		vm_page_release(mem, VMP_RELEASE_SKIP_FREE_CHECK);
	} else {
		vm_page_release_fictitious(mem);
	}
}


/*
 * Free a list of pages.  The list can be up to several hundred pages,
 * as blocked up by vm_pageout_scan().
 * The big win is not having to take the free list lock once
 * per page.
 *
 * The VM page queues lock (vm_page_queue_lock) should NOT be held.
 * The VM page free queues lock (vm_page_queue_free_lock) should NOT be held.
 *
 * Keep in sync with vm_page_release().
 */
void
vm_page_free_list(vm_page_t freeq, bool prepare_object)
{
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
	LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_NOTOWNED);

	while (freeq) {
		vm_page_list_t list = { };

		while (list.vmpl_count < VMP_FREE_BATCH_SIZE && freeq) {
			vm_page_t mem = _vm_page_list_pop(&freeq);

			assert((mem->vmp_q_state == VM_PAGE_NOT_ON_Q) || VM_PAGE_WIRED(mem));

			if (prepare_object) {
				vm_page_free_prepare_object(mem);
			}

			if (vm_page_is_fictitious(mem)) {
				vm_page_release_fictitious(mem);
				continue;
			}

			if (!prepare_object) {
				/* vm_page_free_prepare_object() checked it */
				pmap_recycle_page(VM_PAGE_GET_PHYS_PAGE(mem));
			}

			pmap_clear_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));


			/*
			 * IMPORTANT: we can't set the page "free" here
			 * because that would make the page eligible for
			 * a physically-contiguous allocation (see
			 * vm_page_find_contiguous()) right away (we don't
			 * hold the vm_page_queue_free lock).  That would
			 * cause trouble because the page is not actually
			 * in the free queue yet...
			 */

			vm_page_list_push(&list, mem);
		}

		if (list.vmpl_count) {
			vm_page_free_queue_enter_list(list, VMP_RELEASE_NONE);
		}
	}
}


/*
 *	vm_page_wire:
 *
 *	Mark this page as wired down by yet
 *	another map, removing it from paging queues
 *	as necessary.
 *
 *	The page's object and the page queues must be locked.
 */


void
vm_page_wire(
	vm_page_t mem,
	vm_tag_t           tag,
	boolean_t          check_memorystatus)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

//	dbgLog(current_thread(), mem->vmp_offset, m_object, 1);	/* (TEST/DEBUG) */

	VM_PAGE_CHECK(mem);
	if (m_object) {
		vm_object_lock_assert_exclusive(m_object);
	} else {
		/*
		 * In theory, the page should be in an object before it
		 * gets wired, since we need to hold the object lock
		 * to update some fields in the page structure.
		 * However, some code (i386 pmap, for example) might want
		 * to wire a page before it gets inserted into an object.
		 * That's somewhat OK, as long as nobody else can get to
		 * that page and update it at the same time.
		 */
	}
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	if (!VM_PAGE_WIRED(mem)) {
		if (mem->vmp_laundry) {
			vm_pageout_steal_laundry(mem, TRUE);
		}

		vm_page_queues_remove(mem, TRUE);

		assert(mem->vmp_wire_count == 0);
		mem->vmp_q_state = VM_PAGE_IS_WIRED;

#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
		if (mem->vmp_unmodified_ro == true) {
			/* Object and PageQ locks are held*/
			mem->vmp_unmodified_ro = false;
			os_atomic_dec(&compressor_ro_uncompressed, relaxed);
			vm_object_compressor_pager_state_clr(VM_PAGE_OBJECT(mem), mem->vmp_offset);
		}
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */

		if (m_object) {
			ledger_t      ledger;
			vmo_ledgers_t lidx;

			VM_OBJECT_WIRED_PAGE_UPDATE_START(m_object);
			VM_OBJECT_WIRED_PAGE_ADD(m_object, mem);
			VM_OBJECT_WIRED_PAGE_UPDATE_END(m_object, tag);

			assert(m_object->resident_page_count >=
			    m_object->wired_page_count);
			if (m_object->purgable == VM_PURGABLE_VOLATILE) {
				counter_dec(&vm_page_purgeable_count);
				counter_inc(&vm_page_purgeable_wired_count);
			}

			if (m_object->internal &&
			    (m_object->purgable == VM_PURGABLE_VOLATILE ||
			    m_object->purgable == VM_PURGABLE_EMPTY) &&
			    (ledger = VM_OBJECT_LEDGER(m_object))) {
				lidx = vm_object_ledger_tag_ledgers(m_object);

				disable_preemption();
				/* less volatile bytes */
				ledger_debit_nopreempt(ledger,
				    lidx.vmo_volatile, PAGE_SIZE);
				/* more not-quite-volatile bytes */
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_nonvolatile, PAGE_SIZE);
				ledger_credit_nopreempt(ledger,
				    lidx.vmo_footprint, PAGE_SIZE);
				enable_preemption();
			}

			if (m_object->all_reusable) {
				/*
				 * Wired pages are not counted as "re-usable"
				 * in "all_reusable" VM objects, so nothing
				 * to do here.
				 */
			} else if (mem->vmp_reusable) {
				/*
				 * This page is not "re-usable" when it's
				 * wired, so adjust its state and the
				 * accounting.
				 */
				vm_page_lockconvert_queues();
				vm_object_reuse_pages(m_object,
				    mem->vmp_offset,
				    mem->vmp_offset + PAGE_SIZE_64,
				    FALSE);
			}
		}
		assert(!mem->vmp_reusable);

		if (vm_page_is_canonical(mem) && !mem->vmp_gobbled) {
			vm_page_wire_count++;
		}
		if (mem->vmp_gobbled) {
			vm_page_gobble_count--;
		}
		mem->vmp_gobbled = FALSE;

		if (check_memorystatus == TRUE) {
			VM_CHECK_MEMORYSTATUS;
		}
	}
	assert(!mem->vmp_gobbled);
	assert(VM_PAGE_WIRED(mem));
	mem->vmp_wire_count++;

#if HAS_MTE
	if (mem->vmp_wire_count == 1 && tag != VM_KERN_MEMORY_MTAG) {
		/*
		 * Only notify Mte Info if the caller isn't
		 * mteinfo_tag_storage_wire_locked().
		 */
		mteinfo_increment_wire_count(mem);
	}
#endif /* HAS_MTE */

	if (__improbable(mem->vmp_wire_count == 0)) {
		panic("vm_page_wire(%p): wire_count overflow", mem);
	}
	VM_PAGE_CHECK(mem);
}

/*
 *	vm_page_unwire:
 *
 *	Release one wiring of this page, potentially
 *	enabling it to be paged again.
 *
 *	The page's object and the page queues must be locked.
 */
void
vm_page_unwire(
	vm_page_t       mem,
	boolean_t       queueit)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

//	dbgLog(current_thread(), mem->vmp_offset, m_object, 0);	/* (TEST/DEBUG) */

	VM_PAGE_CHECK(mem);
	assert(VM_PAGE_WIRED(mem));
	assert(mem->vmp_wire_count > 0);
	assert(!mem->vmp_gobbled);
	assert(m_object != VM_OBJECT_NULL);
	vm_object_lock_assert_exclusive(m_object);
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	if (--mem->vmp_wire_count == 0) {
		ledger_t      ledger;
		vmo_ledgers_t lidx;

		mem->vmp_q_state = VM_PAGE_NOT_ON_Q;

		VM_OBJECT_WIRED_PAGE_UPDATE_START(m_object);
		VM_OBJECT_WIRED_PAGE_REMOVE(m_object, mem);
		VM_OBJECT_WIRED_PAGE_UPDATE_END(m_object, m_object->wire_tag);
		if (vm_page_is_canonical(mem)) {
			vm_page_wire_count--;
		}

#if HAS_MTE
		mteinfo_decrement_wire_count(mem, true);
#endif /* HAS_MTE */

		assert(m_object->resident_page_count >=
		    m_object->wired_page_count);
		if (m_object->purgable == VM_PURGABLE_VOLATILE) {
			counter_inc(&vm_page_purgeable_count);
			counter_dec(&vm_page_purgeable_wired_count);
		}
		if (m_object->internal &&
		    (m_object->purgable == VM_PURGABLE_VOLATILE ||
		    m_object->purgable == VM_PURGABLE_EMPTY) &&
		    (ledger = VM_OBJECT_LEDGER(m_object))) {
			lidx = vm_object_ledger_tag_ledgers(m_object);

			disable_preemption();
			/* more volatile bytes */
			ledger_credit_nopreempt(ledger,
			    lidx.vmo_volatile, PAGE_SIZE);
			/* less not-quite-volatile bytes */
			ledger_debit_nopreempt(ledger,
			    lidx.vmo_nonvolatile, PAGE_SIZE);
			ledger_debit_nopreempt(ledger,
			    lidx.vmo_footprint, PAGE_SIZE);
			enable_preemption();
		}
		assert(!is_kernel_object(m_object));
		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);

		if (queueit == TRUE) {
			if (m_object->purgable == VM_PURGABLE_EMPTY) {
				vm_page_deactivate(mem);
			} else {
				vm_page_activate(mem);
			}
		}

		VM_CHECK_MEMORYSTATUS;
	}
	VM_PAGE_CHECK(mem);
}

/*
 *	vm_page_deactivate:
 *
 *	Returns the given page to the inactive list,
 *	indicating that no physical maps have access
 *	to this page.  [Used by the physical mapping system.]
 *
 *	The page queues must be locked.
 */
void
vm_page_deactivate(
	vm_page_t       m)
{
	vm_page_deactivate_internal(m, TRUE);
}


void
vm_page_deactivate_internal(
	vm_page_t       m,
	boolean_t       clear_hw_reference)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(m);

	VM_PAGE_CHECK(m);
	assert(!is_kernel_object(m_object));
	assert(!vm_page_is_guard(m));

//	dbgLog(VM_PAGE_GET_PHYS_PAGE(m), vm_page_free_count, vm_page_wire_count, 6);	/* (TEST/DEBUG) */
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 *	This page is no longer very interesting.  If it was
	 *	interesting (active or inactive/referenced), then we
	 *	clear the reference bit and (re)enter it in the
	 *	inactive queue.  Note wired pages should not have
	 *	their reference bit cleared.
	 */
	assert( !(m->vmp_absent && !m->vmp_unusual));

	if (m->vmp_gobbled) {           /* can this happen? */
		assert( !VM_PAGE_WIRED(m));

		if (vm_page_is_canonical(m)) {
			vm_page_wire_count--;
		}
		vm_page_gobble_count--;
		m->vmp_gobbled = FALSE;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->vmp_laundry || !vm_page_is_canonical(m) ||
	    (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) ||
	    VM_PAGE_WIRED(m)) {
		return;
	}
	if (!m->vmp_absent && clear_hw_reference == TRUE) {
		vm_page_lockconvert_queues();
		pmap_clear_reference(VM_PAGE_GET_PHYS_PAGE(m));
	}

	m->vmp_reference = FALSE;
	m->vmp_no_cache = FALSE;

	if (!VM_PAGE_INACTIVE(m)) {
		vm_page_queues_remove(m, FALSE);

		if (!VM_DYNAMIC_PAGING_ENABLED() &&
		    m->vmp_dirty && m_object->internal &&
		    (m_object->purgable == VM_PURGABLE_DENY ||
		    m_object->purgable == VM_PURGABLE_NONVOLATILE ||
		    m_object->purgable == VM_PURGABLE_VOLATILE)) {
			vm_page_check_pageable_safe(m);
			vm_page_queue_enter(&vm_page_queue_throttled, m, vmp_pageq);
			m->vmp_q_state = VM_PAGE_ON_THROTTLED_Q;
			vm_page_throttled_count++;
		} else {
			if (m_object->named &&
			    os_ref_get_count_raw(&m_object->ref_count) == 1) {
				vm_page_speculate(m, FALSE);
#if DEVELOPMENT || DEBUG
				vm_page_speculative_recreated++;
#endif
			} else {
				vm_page_enqueue_inactive(m, FALSE);
			}
		}
	}
}

/*
 * vm_page_enqueue_cleaned
 *
 * Put the page on the cleaned queue, mark it cleaned, etc.
 * Being on the cleaned queue (and having m->clean_queue set)
 * does ** NOT ** guarantee that the page is clean!
 *
 * Call with the queues lock held.
 */

void
vm_page_enqueue_cleaned(vm_page_t m)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(m);

	assert(!vm_page_is_guard(m));
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(!(m->vmp_absent && !m->vmp_unusual));

	if (VM_PAGE_WIRED(m)) {
		return;
	}

	if (m->vmp_gobbled) {
		if (vm_page_is_canonical(m)) {
			vm_page_wire_count--;
		}
		vm_page_gobble_count--;
		m->vmp_gobbled = FALSE;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->vmp_laundry || !vm_page_is_canonical(m) ||
	    (m->vmp_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) ||
	    (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q)) {
		return;
	}
	vm_page_queues_remove(m, FALSE);

	vm_page_check_pageable_safe(m);
	vm_page_queue_enter(&vm_page_queue_cleaned, m, vmp_pageq);
	m->vmp_q_state = VM_PAGE_ON_INACTIVE_CLEANED_Q;
	vm_page_cleaned_count++;

	vm_page_inactive_count++;
	if (m_object->internal) {
		vm_page_pageable_internal_count++;
	} else {
		vm_page_pageable_external_count++;
	}
	vm_page_add_to_specialq(m, TRUE);
	VM_PAGEOUT_DEBUG(vm_pageout_enqueued_cleaned, 1);
}

/*
 *	vm_page_activate:
 *
 *	Put the specified page on the active list (if appropriate).
 *
 *	The page queues must be locked.
 */

void
vm_page_activate(
	vm_page_t       m)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(m);

	VM_PAGE_CHECK(m);
#ifdef  FIXME_4778297
	assert(!is_kernel_object(m_object));
#endif
	assert(!vm_page_is_guard(m));
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert( !(m->vmp_absent && !m->vmp_unusual));

	if (m->vmp_gobbled) {
		assert( !VM_PAGE_WIRED(m));
		if (vm_page_is_canonical(m)) {
			vm_page_wire_count--;
		}
		vm_page_gobble_count--;
		m->vmp_gobbled = FALSE;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->vmp_laundry || !vm_page_is_canonical(m) ||
	    (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q)) {
		return;
	}

#if DEBUG
	if (m->vmp_q_state == VM_PAGE_ON_ACTIVE_Q) {
		panic("vm_page_activate: already active");
	}
#endif

	if (m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
		DTRACE_VM2(pgrec, int, 1, (uint64_t *), NULL);
		DTRACE_VM2(pgfrec, int, 1, (uint64_t *), NULL);
	}

	/*
	 * A freshly activated page should be promoted in the donation queue.
	 * So we remove it here while preserving its hint and we will enqueue
	 * it again in vm_page_enqueue_active.
	 */
	vm_page_queues_remove(m, ((m->vmp_on_specialq == VM_PAGE_SPECIAL_Q_DONATE) ? TRUE : FALSE));

	if (!VM_PAGE_WIRED(m)) {
		vm_page_check_pageable_safe(m);
		if (!VM_DYNAMIC_PAGING_ENABLED() &&
		    m->vmp_dirty && m_object->internal &&
		    (m_object->purgable == VM_PURGABLE_DENY ||
		    m_object->purgable == VM_PURGABLE_NONVOLATILE ||
		    m_object->purgable == VM_PURGABLE_VOLATILE)) {
			vm_page_queue_enter(&vm_page_queue_throttled, m, vmp_pageq);
			m->vmp_q_state = VM_PAGE_ON_THROTTLED_Q;
			vm_page_throttled_count++;
		} else {
#if CONFIG_SECLUDED_MEMORY
			if (secluded_for_filecache &&
			    vm_page_secluded_target != 0 &&
			    num_tasks_can_use_secluded_mem == 0 &&
			    m_object->eligible_for_secluded &&
			    !m->vmp_realtime) {
				vm_page_queue_enter(&vm_page_queue_secluded, m, vmp_pageq);
				m->vmp_q_state = VM_PAGE_ON_SECLUDED_Q;
				vm_page_secluded_count++;
				VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();
				vm_page_secluded_count_inuse++;
				assert(!m_object->internal);
//				vm_page_pageable_external_count++;
			} else
#endif /* CONFIG_SECLUDED_MEMORY */
			vm_page_enqueue_active(m, FALSE);
		}
		m->vmp_reference = TRUE;
		m->vmp_no_cache = FALSE;
	}
	VM_PAGE_CHECK(m);
}


/*
 *      vm_page_speculate:
 *
 *      Put the specified page on the speculative list (if appropriate).
 *
 *      The page queues must be locked.
 */
void
vm_page_speculate(
	vm_page_t       m,
	boolean_t       new)
{
	struct vm_speculative_age_q     *aq;
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(m);

	VM_PAGE_CHECK(m);
	vm_page_check_pageable_safe(m);

	assert(!vm_page_is_guard(m));
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(!(m->vmp_absent && !m->vmp_unusual));

	if (m_object->internal) {
		vm_page_deactivate(m);
		return;
	}
	assert(m_object->internal == FALSE);

	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->vmp_laundry || !vm_page_is_canonical(m) ||
	    (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q)) {
		return;
	}

	vm_page_queues_remove(m, FALSE);

	if (!VM_PAGE_WIRED(m)) {
		mach_timespec_t         ts;
		clock_sec_t sec;
		clock_nsec_t nsec;

		clock_get_system_nanotime(&sec, &nsec);
		ts.tv_sec = (unsigned int) sec;
		ts.tv_nsec = nsec;

		if (vm_page_speculative_count == 0) {
			speculative_age_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
			speculative_steal_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;

			aq = &vm_page_queue_speculative[speculative_age_index];

			/*
			 * set the timer to begin a new group
			 */
			aq->age_ts.tv_sec = vm_pageout_state.vm_page_speculative_q_age_ms / 1000;
			aq->age_ts.tv_nsec = (vm_pageout_state.vm_page_speculative_q_age_ms % 1000) * 1000 * NSEC_PER_USEC;

			ADD_MACH_TIMESPEC(&aq->age_ts, &ts);
		} else {
			aq = &vm_page_queue_speculative[speculative_age_index];

			if (CMP_MACH_TIMESPEC(&ts, &aq->age_ts) >= 0) {
				speculative_age_index++;

				if (speculative_age_index > vm_page_max_speculative_age_q) {
					speculative_age_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
				}
				if (speculative_age_index == speculative_steal_index) {
					speculative_steal_index = speculative_age_index + 1;

					if (speculative_steal_index > vm_page_max_speculative_age_q) {
						speculative_steal_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
					}
				}
				aq = &vm_page_queue_speculative[speculative_age_index];

				if (!vm_page_queue_empty(&aq->age_q)) {
					vm_page_speculate_ageit(aq);
				}

				aq->age_ts.tv_sec = vm_pageout_state.vm_page_speculative_q_age_ms / 1000;
				aq->age_ts.tv_nsec = (vm_pageout_state.vm_page_speculative_q_age_ms % 1000) * 1000 * NSEC_PER_USEC;

				ADD_MACH_TIMESPEC(&aq->age_ts, &ts);
			}
		}
		vm_page_enqueue_tail(&aq->age_q, &m->vmp_pageq);
		m->vmp_q_state = VM_PAGE_ON_SPECULATIVE_Q;
		vm_page_speculative_count++;
		vm_page_pageable_external_count++;

		if (new == TRUE) {
			vm_object_lock_assert_exclusive(m_object);

			m_object->pages_created++;
#if DEVELOPMENT || DEBUG
			vm_page_speculative_created++;
#endif
		}
	}
	VM_PAGE_CHECK(m);
}


/*
 * move pages from the specified aging bin to
 * the speculative bin that pageout_scan claims from
 *
 *      The page queues must be locked.
 */
void
vm_page_speculate_ageit(struct vm_speculative_age_q *aq)
{
	struct vm_speculative_age_q     *sq;
	vm_page_t       t;

	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	if (vm_page_queue_empty(&sq->age_q)) {
		sq->age_q.next = aq->age_q.next;
		sq->age_q.prev = aq->age_q.prev;

		t = (vm_page_t)VM_PAGE_UNPACK_PTR(sq->age_q.next);
		t->vmp_pageq.prev = VM_PAGE_PACK_PTR(&sq->age_q);

		t = (vm_page_t)VM_PAGE_UNPACK_PTR(sq->age_q.prev);
		t->vmp_pageq.next = VM_PAGE_PACK_PTR(&sq->age_q);
	} else {
		t = (vm_page_t)VM_PAGE_UNPACK_PTR(sq->age_q.prev);
		t->vmp_pageq.next = aq->age_q.next;

		t = (vm_page_t)VM_PAGE_UNPACK_PTR(aq->age_q.next);
		t->vmp_pageq.prev = sq->age_q.prev;

		t = (vm_page_t)VM_PAGE_UNPACK_PTR(aq->age_q.prev);
		t->vmp_pageq.next = VM_PAGE_PACK_PTR(&sq->age_q);

		sq->age_q.prev = aq->age_q.prev;
	}
	vm_page_queue_init(&aq->age_q);
}


void
vm_page_lru(
	vm_page_t       m)
{
	VM_PAGE_CHECK(m);
	assert(!is_kernel_object(VM_PAGE_OBJECT(m)));
	assert(!vm_page_is_guard(m));

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (m->vmp_q_state == VM_PAGE_ON_INACTIVE_EXTERNAL_Q) {
		/*
		 * we don't need to do all the other work that
		 * vm_page_queues_remove and vm_page_enqueue_inactive
		 * bring along for the ride
		 */
		assert(!m->vmp_laundry);
		assert(!vm_page_is_private(m));

		m->vmp_no_cache = FALSE;

		vm_page_queue_remove(&vm_page_queue_inactive, m, vmp_pageq);
		vm_page_queue_enter(&vm_page_queue_inactive, m, vmp_pageq);

		return;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->vmp_laundry || vm_page_is_private(m) ||
	    (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) ||
	    VM_PAGE_WIRED(m)) {
		return;
	}

	m->vmp_no_cache = FALSE;

	vm_page_queues_remove(m, FALSE);

	vm_page_enqueue_inactive(m, FALSE);
}


void
vm_page_reactivate_all_throttled(void)
{
	vm_page_t       first_throttled, last_throttled;
	vm_page_t       first_active;
	vm_page_t       m;
	int             extra_active_count;
	int             extra_internal_count, extra_external_count;
	vm_object_t     m_object;

	if (!VM_DYNAMIC_PAGING_ENABLED()) {
		return;
	}

	extra_active_count = 0;
	extra_internal_count = 0;
	extra_external_count = 0;
	vm_page_lock_queues();
	if (!vm_page_queue_empty(&vm_page_queue_throttled)) {
		/*
		 * Switch "throttled" pages to "active".
		 */
		vm_page_queue_iterate(&vm_page_queue_throttled, m, vmp_pageq) {
			VM_PAGE_CHECK(m);
			assert(m->vmp_q_state == VM_PAGE_ON_THROTTLED_Q);

			m_object = VM_PAGE_OBJECT(m);

			extra_active_count++;
			if (m_object->internal) {
				extra_internal_count++;
			} else {
				extra_external_count++;
			}

			m->vmp_q_state = VM_PAGE_ON_ACTIVE_Q;
			VM_PAGE_CHECK(m);
			vm_page_add_to_specialq(m, FALSE);
		}

		/*
		 * Transfer the entire throttled queue to a regular LRU page queues.
		 * We insert it at the head of the active queue, so that these pages
		 * get re-evaluated by the LRU algorithm first, since they've been
		 * completely out of it until now.
		 */
		first_throttled = (vm_page_t) vm_page_queue_first(&vm_page_queue_throttled);
		last_throttled = (vm_page_t) vm_page_queue_last(&vm_page_queue_throttled);
		first_active = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);
		if (vm_page_queue_empty(&vm_page_queue_active)) {
			vm_page_queue_active.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_throttled);
		} else {
			first_active->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_throttled);
		}
		vm_page_queue_active.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_throttled);
		first_throttled->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(&vm_page_queue_active);
		last_throttled->vmp_pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_active);

#if DEBUG
		printf("reactivated %d throttled pages\n", vm_page_throttled_count);
#endif
		vm_page_queue_init(&vm_page_queue_throttled);
		/*
		 * Adjust the global page counts.
		 */
		vm_page_active_count += extra_active_count;
		vm_page_pageable_internal_count += extra_internal_count;
		vm_page_pageable_external_count += extra_external_count;
		vm_page_throttled_count = 0;
	}
	assert(vm_page_throttled_count == 0);
	assert(vm_page_queue_empty(&vm_page_queue_throttled));
	vm_page_unlock_queues();
}


/*
 * move pages from the indicated local queue to the global active queue
 * its ok to fail if we're below the hard limit and force == FALSE
 * the nolocks == TRUE case is to allow this function to be run on
 * the hibernate path
 */

void
vm_page_reactivate_local(uint32_t lid, boolean_t force, boolean_t nolocks)
{
	struct vpl      *lq;
	vm_page_t       first_local, last_local;
	vm_page_t       first_active;
	vm_page_t       m;
	uint32_t        count = 0;
	uint32_t        internal_count __kdebug_only;
	uint32_t        external_count __kdebug_only;
	bool            hit_hard_limit;

	if (vm_page_local_q == NULL) {
		return;
	}

	lq = zpercpu_get_cpu(vm_page_local_q, lid);

	if (nolocks == FALSE) {
		hit_hard_limit = lq->vpl_count >= vm_page_local_q_hard_limit;
		if (!hit_hard_limit && !force) {
			if (!vm_page_trylockspin_queues()) {
				return;
			}
		} else {
			vm_page_lockspin_queues();
		}

		VPL_LOCK(&lq->vpl_lock);
	}

	KDBG(VMDBG_CODE(DBG_VM_PAGE_LOCAL_TO_GLOBAL_ACTIVE) | DBG_FUNC_START,
	    lid, hit_hard_limit, force);

	if (lq->vpl_count) {
		/*
		 * Switch "local" pages to "active".
		 */
		assert(!vm_page_queue_empty(&lq->vpl_queue));

		vm_page_queue_iterate(&lq->vpl_queue, m, vmp_pageq) {
			VM_PAGE_CHECK(m);
			vm_page_check_pageable_safe(m);
			assert(m->vmp_q_state == VM_PAGE_ON_ACTIVE_LOCAL_Q);
			assert(!vm_page_is_fictitious(m));

			if (m->vmp_local_id != lid) {
				panic("vm_page_reactivate_local: found vm_page_t(%p) with wrong cpuid", m);
			}

			m->vmp_local_id = 0;
			m->vmp_q_state = VM_PAGE_ON_ACTIVE_Q;
			VM_PAGE_CHECK(m);
			vm_page_add_to_specialq(m, FALSE);
			count++;
		}
		if (count != lq->vpl_count) {
			panic("vm_page_reactivate_local: count = %d, vm_page_local_count = %d", count, lq->vpl_count);
		}

		/*
		 * Transfer the entire local queue to a regular LRU page queues.
		 */
		first_local = (vm_page_t) vm_page_queue_first(&lq->vpl_queue);
		last_local = (vm_page_t) vm_page_queue_last(&lq->vpl_queue);
		first_active = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);

		if (vm_page_queue_empty(&vm_page_queue_active)) {
			vm_page_queue_active.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
		} else {
			first_active->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
		}
		vm_page_queue_active.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_local);
		first_local->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(&vm_page_queue_active);
		last_local->vmp_pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_active);

		vm_page_queue_init(&lq->vpl_queue);
		/*
		 * Adjust the global page counts.
		 */
		vm_page_active_count += lq->vpl_count;
		vm_page_pageable_internal_count += lq->vpl_internal_count;
		vm_page_pageable_external_count += lq->vpl_external_count;

		internal_count = lq->vpl_internal_count;
		external_count = lq->vpl_external_count;

		lq->vpl_count = 0;
		lq->vpl_internal_count = 0;
		lq->vpl_external_count = 0;
	}
	assert(vm_page_queue_empty(&lq->vpl_queue));

	if (nolocks == FALSE) {
		VPL_UNLOCK(&lq->vpl_lock);

		vm_page_balance_inactive(count / 4);
		vm_page_unlock_queues();
	}

	KDBG(VMDBG_CODE(DBG_VM_PAGE_LOCAL_TO_GLOBAL_ACTIVE) | DBG_FUNC_END,
	    count, internal_count, external_count);
}

/*
 *	vm_page_part_zero_fill:
 *
 *	Zero-fill a part of the page.
 */
#define PMAP_ZERO_PART_PAGE_IMPLEMENTED
void
vm_page_part_zero_fill(
	vm_page_t       m,
	vm_offset_t     m_pa,
	vm_size_t       len)
{
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(m);
#endif

#ifdef PMAP_ZERO_PART_PAGE_IMPLEMENTED
	pmap_zero_part_page(VM_PAGE_GET_PHYS_PAGE(m), m_pa, len);
#else
	vm_page_t       tmp;
	while (1) {
		tmp = vm_page_grab();
		if (tmp == VM_PAGE_NULL) {
			vm_page_wait(THREAD_UNINT);
			continue;
		}
		break;
	}
	pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(tmp));
	if (m_pa != 0) {
		vm_page_part_copy(m, 0, tmp, 0, m_pa);
	}
	if ((m_pa + len) < PAGE_SIZE) {
		vm_page_part_copy(m, m_pa + len, tmp,
		    m_pa + len, PAGE_SIZE - (m_pa + len));
	}
	vm_page_copy(tmp, m);
	VM_PAGE_FREE(tmp);
#endif
}

/*!
 * @function vm_page_zero_fill
 *
 * @abstract
 * Zero-fill the specified page.
 *
 * @param m		The page to zero.
 */
void
vm_page_zero_fill(vm_page_t m)
{
	pmap_zero_page_with_options(VM_PAGE_GET_PHYS_PAGE(m),
#if HAS_MTE
	    m->vmp_using_mte ? cppvZeroPageTags :
#endif /* HAS_MTE */
	    0);
#if HAS_MTE
	if (m->vmp_using_mte) {
		KDBG(VMDBG_CODE(DBG_VM_PAGE_MTE_ZFOD) | DBG_FUNC_NONE);
	}
#endif /* HAS_MTE */
	counter_inc(&vm_statistics_zero_fill_count);
	DTRACE_VM2(zfod, int, 1, (uint64_t *), NULL);
}

/*
 *	vm_page_part_copy:
 *
 *	copy part of one page to another
 *
 *	This function is currently only consumed downstream of a
 *	vm_map_copy_overwrite(). The implementation has a simpler contract
 *	than vm_page_copy() as there's a restricted set of cases that
 *	are allowed to be overwriteable. If vm_map_entry_is_overwriteable()
 *	is expanded, this function may have to be adjusted.
 */
void
vm_page_part_copy(
	vm_page_t       src_m,
	vm_offset_t     src_pa,
	vm_page_t       dst_m,
	vm_offset_t     dst_pa,
	vm_size_t       len)
{
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(src_m);
	VM_PAGE_CHECK(dst_m);
#endif

	/*
	 * Copying from/into restricted pages is a security issue,
	 * as it allows for restricted pages' policies bypass.
	 */
	if (vm_page_is_restricted(src_m)) {
		panic("%s: cannot copy from a restricted page", __func__);
	}

	if (vm_page_is_restricted(dst_m)) {
		panic("%s: cannot copy into a restricted page", __func__);
	}

#if HAS_MTE
	/*
	 * As an example of a necessary expansion for vm_page_part_copy(),
	 * MTE objects are currently not overwriteable, but whenever
	 * rdar://134375521 ([VM MTE] Handle overwriting of MTE objects)
	 * gets dealt with, we'll have to update the call down here to pass
	 * the right flags to bcopy_phys().
	 */
#endif /* HAS_MTE */

	pmap_copy_part_page(VM_PAGE_GET_PHYS_PAGE(src_m), src_pa,
	    VM_PAGE_GET_PHYS_PAGE(dst_m), dst_pa, len);
}

/*
 *	vm_page_copy:
 *
 *	Copy one page to another
 */

int vm_page_copy_cs_validations = 0;
int vm_page_copy_cs_tainted = 0;

void
vm_page_copy(
	vm_page_t       src_m,
	vm_page_t       dest_m)
{
	vm_object_t     src_m_object;
	int             options = 0;

	src_m_object = VM_PAGE_OBJECT(src_m);

#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(src_m);
	VM_PAGE_CHECK(dest_m);
#endif
	vm_object_lock_assert_held(src_m_object);

	/*
	 * Copying from/into restricted pages is a security issue,
	 * as it allows for restricted pages' policies bypass.
	 */
	if (vm_page_is_restricted(src_m)) {
		panic("%s: cannot copy from a restricted page", __func__);
	}

	if (vm_page_is_restricted(dest_m)) {
		panic("%s: cannot copy into a restricted page", __func__);
	}

	if (src_m_object != VM_OBJECT_NULL &&
	    src_m_object->code_signed) {
		/*
		 * We're copying a page from a code-signed object.
		 * Whoever ends up mapping the copy page might care about
		 * the original page's integrity, so let's validate the
		 * source page now.
		 */
		vm_page_copy_cs_validations++;
		vm_page_validate_cs(src_m, PAGE_SIZE, 0);
#if DEVELOPMENT || DEBUG
		DTRACE_VM4(codesigned_copy,
		    vm_object_t, src_m_object,
		    vm_object_offset_t, src_m->vmp_offset,
		    int, src_m->vmp_cs_validated,
		    int, src_m->vmp_cs_tainted);
#endif /* DEVELOPMENT || DEBUG */
	}

	/*
	 * Propagate the cs_tainted bit to the copy page. Do not propagate
	 * the cs_validated bit.
	 */
	dest_m->vmp_cs_tainted = src_m->vmp_cs_tainted;
	dest_m->vmp_cs_nx = src_m->vmp_cs_nx;
	if (dest_m->vmp_cs_tainted) {
		vm_page_copy_cs_tainted++;
	}

#if HAS_MTE
	/*
	 * vm_page_copy-ing from an untagged page into a tagged page
	 * would happen with tag checking disabled and actually potentially be
	 * an MTE violation.
	 */
	if (!src_m->vmp_using_mte && dest_m->vmp_using_mte) {
		panic("Attempt to write to an MTE tagged page through the physical aperture");
	}

	if (src_m->vmp_using_mte) {
		/* If we are copying from an MTE-enabled page, disable tag checking */
		options |= cppvDisableTagCheck;

		if (dest_m->vmp_using_mte) {
			/*
			 * If both source and destination are tagged, this means that we are
			 * either CoWing or relocating a page. Tags need to follow along.
			 */
			options |= cppvCopyTags;
		}
	}
#endif /* HAS_MTE */

	dest_m->vmp_error = VMP_ERROR_GET(src_m); /* sliding src_m might have failed... */
	pmap_copy_page(VM_PAGE_GET_PHYS_PAGE(src_m), VM_PAGE_GET_PHYS_PAGE(dest_m), options);
}

#if MACH_ASSERT
static void
_vm_page_print(
	vm_page_t       p)
{
	printf("vm_page %p: \n", p);
	printf("  pageq: next=%p prev=%p\n",
	    (vm_page_t)VM_PAGE_UNPACK_PTR(p->vmp_pageq.next),
	    (vm_page_t)VM_PAGE_UNPACK_PTR(p->vmp_pageq.prev));
	printf("  listq: next=%p prev=%p\n",
	    (vm_page_t)(VM_PAGE_UNPACK_PTR(p->vmp_listq.next)),
	    (vm_page_t)(VM_PAGE_UNPACK_PTR(p->vmp_listq.prev)));
	printf("  next=%p\n", (vm_page_t)(VM_PAGE_UNPACK_PTR(p->vmp_next_m)));
	printf("  object=%p offset=0x%llx\n", VM_PAGE_OBJECT(p), p->vmp_offset);
	printf("  wire_count=%u\n", p->vmp_wire_count);
	printf("  q_state=%u\n", p->vmp_q_state);

	printf("  %slaundry, %sref, %sgobbled, %sprivate\n",
	    (p->vmp_laundry ? "" : "!"),
	    (p->vmp_reference ? "" : "!"),
	    (p->vmp_gobbled ? "" : "!"),
	    (vm_page_is_private(p) ? "" : "!"));
	printf("  %sbusy, %swanted, %stabled, %sfictitious, %spmapped, %swpmapped\n",
	    (p->vmp_busy ? "" : "!"),
	    (p->vmp_wanted ? "" : "!"),
	    (p->vmp_tabled ? "" : "!"),
	    (vm_page_is_fictitious(p) ? "" : "!"),
	    (p->vmp_pmapped ? "" : "!"),
	    (p->vmp_wpmapped ? "" : "!"));
	printf("  %sfree_when_done, %sabsent, %serror, %sdirty, %scleaning, %sprecious, %sclustered\n",
	    (p->vmp_free_when_done ? "" : "!"),
	    (p->vmp_absent ? "" : "!"),
	    (VMP_ERROR_GET(p) ? "" : "!"),
	    (p->vmp_dirty ? "" : "!"),
	    (p->vmp_cleaning ? "" : "!"),
	    (p->vmp_precious ? "" : "!"),
	    (p->vmp_clustered ? "" : "!"));
	printf("  %soverwriting, %srestart, %sunusual\n",
	    (p->vmp_overwriting ? "" : "!"),
	    (p->vmp_restart ? "" : "!"),
	    (p->vmp_unusual ? "" : "!"));
	printf("  cs_validated=%d, cs_tainted=%d, cs_nx=%d, %sno_cache\n",
	    p->vmp_cs_validated,
	    p->vmp_cs_tainted,
	    p->vmp_cs_nx,
	    (p->vmp_no_cache ? "" : "!"));

	printf("phys_page=0x%x\n", VM_PAGE_GET_PHYS_PAGE(p));
}

/*
 *	Check that the list of pages is ordered by
 *	ascending physical address and has no holes.
 */
static int
vm_page_verify_contiguous(
	vm_page_t       pages,
	unsigned int    npages)
{
	vm_page_t               m;
	unsigned int            page_count;
	vm_offset_t             prev_addr;

	prev_addr = VM_PAGE_GET_PHYS_PAGE(pages);
	page_count = 1;
	for (m = NEXT_PAGE(pages); m != VM_PAGE_NULL; m = NEXT_PAGE(m)) {
		if (VM_PAGE_GET_PHYS_PAGE(m) != prev_addr + 1) {
			printf("m %p prev_addr 0x%lx, current addr 0x%x\n",
			    m, (long)prev_addr, VM_PAGE_GET_PHYS_PAGE(m));
			printf("pages %p page_count %d npages %d\n", pages, page_count, npages);
			panic("vm_page_verify_contiguous:  not contiguous!");
		}
		prev_addr = VM_PAGE_GET_PHYS_PAGE(m);
		++page_count;
	}
	if (page_count != npages) {
		printf("pages %p actual count 0x%x but requested 0x%x\n",
		    pages, page_count, npages);
		panic("vm_page_verify_contiguous:  count error");
	}
	return 1;
}


/*
 *	Check the free lists for proper length etc.
 */
static boolean_t vm_page_verify_this_free_list_enabled = FALSE;
static unsigned int
vm_page_verify_free_list(
	vm_page_queue_head_t    *vm_page_queue,
	unsigned int    color,
	vm_page_t       look_for_page,
	boolean_t       expect_page)
{
	unsigned int    npages;
	vm_page_t       m;
	vm_page_t       prev_m;
	boolean_t       found_page;

	if (!vm_page_verify_this_free_list_enabled) {
		return 0;
	}

	found_page = FALSE;
	npages = 0;
	prev_m = (vm_page_t)((uintptr_t)vm_page_queue);

	vm_page_queue_iterate(vm_page_queue, m, vmp_pageq) {
		if (m == look_for_page) {
			found_page = TRUE;
		}
		if ((vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.prev) != prev_m) {
			panic("vm_page_verify_free_list(color=%u, npages=%u): page %p corrupted prev ptr %p instead of %p",
			    color, npages, m, (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.prev), prev_m);
		}
		if (!m->vmp_busy) {
			panic("vm_page_verify_free_list(color=%u, npages=%u): page %p not busy",
			    color, npages, m);
		}
		if (color != (unsigned int) -1) {
			if (VM_PAGE_GET_COLOR(m) != color) {
				panic("vm_page_verify_free_list(color=%u, npages=%u): page %p wrong color %u instead of %u",
				    color, npages, m, VM_PAGE_GET_COLOR(m), color);
			}
			if (m->vmp_q_state != VM_PAGE_ON_FREE_Q) {
				panic("vm_page_verify_free_list(color=%u, npages=%u): page %p - expecting q_state == VM_PAGE_ON_FREE_Q, found %d",
				    color, npages, m, m->vmp_q_state);
			}
		} else {
			if (m->vmp_q_state != VM_PAGE_ON_FREE_LOCAL_Q) {
				panic("vm_page_verify_free_list(npages=%u): local page %p - expecting q_state == VM_PAGE_ON_FREE_LOCAL_Q, found %d",
				    npages, m, m->vmp_q_state);
			}
		}
		++npages;
		prev_m = m;
	}
	if (look_for_page != VM_PAGE_NULL) {
		unsigned int other_color;

		if (expect_page && !found_page) {
			printf("vm_page_verify_free_list(color=%u, npages=%u): page %p not found phys=%u\n",
			    color, npages, look_for_page, VM_PAGE_GET_PHYS_PAGE(look_for_page));
			_vm_page_print(look_for_page);
			for (other_color = 0;
			    other_color < vm_colors;
			    other_color++) {
				if (other_color == color) {
					continue;
				}
				vm_page_verify_free_list(&vm_page_queue_free.vmpfq_queues[other_color].qhead,
				    other_color, look_for_page, FALSE);
			}
#if XNU_VM_HAS_LOPAGE
			if (color == (unsigned int) -1) {
				vm_page_verify_free_list(&vm_lopage_queue_free,
				    (unsigned int) -1, look_for_page, FALSE);
			}
#endif /* XNU_VM_HAS_LOPAGE */
			panic("vm_page_verify_free_list(color=%u)", color);
		}
		if (!expect_page && found_page) {
			printf("vm_page_verify_free_list(color=%u, npages=%u): page %p found phys=%u\n",
			    color, npages, look_for_page, VM_PAGE_GET_PHYS_PAGE(look_for_page));
		}
	}
	return npages;
}

static boolean_t vm_page_verify_all_free_lists_enabled = FALSE;
static void
vm_page_verify_free_lists( void )
{
	unsigned int    color, npages, nlopages;
	boolean_t       toggle = TRUE;

	if (!vm_page_verify_all_free_lists_enabled) {
		return;
	}

	npages = 0;
	nlopages = 0;

	vm_free_page_lock();

	if (vm_page_verify_this_free_list_enabled == TRUE) {
		/*
		 * This variable has been set globally for extra checking of
		 * each free list Q. Since we didn't set it, we don't own it
		 * and we shouldn't toggle it.
		 */
		toggle = FALSE;
	}

	if (toggle == TRUE) {
		vm_page_verify_this_free_list_enabled = TRUE;
	}

	for (color = 0; color < vm_colors; color++) {
		npages += vm_page_verify_free_list(&vm_page_queue_free.vmpfq_queues[color].qhead,
		    color, VM_PAGE_NULL, FALSE);
	}
#if XNU_VM_HAS_LOPAGE
	nlopages = vm_page_verify_free_list(&vm_lopage_queue_free,
	    (unsigned int) -1,
	    VM_PAGE_NULL, FALSE);
#endif /* XNU_VM_HAS_LOPAGE */
	if (npages != vm_page_free_count || nlopages != vm_lopage_free_count) {
		panic("vm_page_verify_free_lists:  "
		    "npages %u free_count %d nlopages %u lo_free_count %u",
		    npages, vm_page_free_count, nlopages, vm_lopage_free_count);
	}

	if (toggle == TRUE) {
		vm_page_verify_this_free_list_enabled = FALSE;
	}

	vm_free_page_unlock();
}

#endif  /* MACH_ASSERT */

extern boolean_t(*volatile consider_buffer_cache_collect)(int);

/*
 *	CONTIGUOUS PAGE ALLOCATION AND HELPER FUNCTIONS
 */

/*
 * Helper function used to determine if a page can be relocated
 * A page is relocatable if it is in a stable non-transient state
 * and if the page being relocated is compatible with the reason for reloc
 * The page queue lock must be held, and the object lock too, if the page
 * is in an object.
 */
boolean_t
vm_page_is_relocatable(vm_page_t m, vm_relocate_reason_t reloc_reason)
{

	if (VM_PAGE_WIRED(m) || m->vmp_gobbled || m->vmp_laundry || m->vmp_wanted ||
	    m->vmp_cleaning || m->vmp_overwriting || m->vmp_free_when_done) {
		/*
		 * Page is in a transient state
		 * or a state we don't want to deal with.
		 */
		return FALSE;
	} else if ((m->vmp_q_state == VM_PAGE_NOT_ON_Q) ||
	    (m->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q) ||
#if XNU_VM_HAS_LOPAGE
	    (m->vmp_q_state == VM_PAGE_ON_FREE_LOPAGE_Q) ||
#endif /* XNU_VM_HAS_LOPAGE */
	    (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q)) {
		/*
		 * Page needs to be on one of our queues (other then the pageout or special
		 * free queues) or it needs to belong to the compressor pool (which is now
		 * indicated by vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR and falls out from
		 * the check for VM_PAGE_NOT_ON_Q) in order for it to be stable behind the
		 * locks we hold at this point...
		 */
		return FALSE;
	} else if ((m->vmp_q_state != VM_PAGE_ON_FREE_Q) &&
	    (!m->vmp_tabled || m->vmp_busy)) {
		/*
		 * pages on the free list are always 'busy'
		 * so we couldn't test for 'busy' in the check
		 * for the transient states... pages that are
		 * 'free' are never 'tabled', so we also couldn't
		 * test for 'tabled'.  So we check here to make
		 * sure that a non-free page is not busy and is
		 * tabled on an object...
		 */
		return FALSE;
	}

	/*
	 * Lastly, check the page against the relocation reason; the page may
	 * be in a relocatable state, but not be a page we WANT to relocate for
	 * the caller's use case.
	 */
	switch (reloc_reason) {
#if HAS_MTE
	case VM_RELOCATE_REASON_TAG_STORAGE_RECLAIM:
	{
		/*
		 * Relocating the content of tag storage pages so the
		 * fill thread can reclaim a page is perfectly valid,
		 * unless the page is busy.
		 */
		if (m->vmp_busy) {
			return FALSE;
		}
		break;
	}
	case VM_RELOCATE_REASON_TAG_STORAGE_WIRE:
#endif /* HAS_MTE */
	case VM_RELOCATE_REASON_CONTIGUOUS:
	{
#if HAS_MTE
		/*
		 * Tag storage pages may be needed for tag storage.  Because
		 * the contiguous allocator is likely being used for wired
		 * allocations, this page is not eligible to be relocated in
		 * this case.
		 */
		if (vm_page_is_tag_storage(m)) {
			return FALSE;
		}
#endif /* HAS_MTE */
		break;
	}

	default:
	{
		panic("Invalid relocation reason %u", reloc_reason);
		__builtin_unreachable();
	}
	}

	return TRUE;
}

/*
 * Free up the given page by possibily relocating its contents to a new page
 * If the page is on an object the object lock must be held.
 *
 * Whether or not the page is considered relocatable is contingent on the
 * reason it is being relocated.
 *
 * Return the new page back to the caller if requested, as done in
 * vm_object_iopl_wire_full().
 *
 * The VM page queues lock must also be held.
 *
 * @returns
 * - KERN_SUCCESS               if the relocation was successful.
 * - KERN_INVALID_OBJECT        if @c m1's object is VM_OBJECT_NULL.
 * - KERN_FAILURE               if the reolcation failed due to @c m1's state.
 * - KERN_RESOURCE_SHORTAGE     if no page could be allocated to relocate @c m1.
 */
kern_return_t
vm_page_relocate(
	vm_page_t            m1,
	int                 *compressed_pages,
	vm_relocate_reason_t reloc_reason,
	vm_page_t*           new_page)
{
	int refmod = 0;
	vm_object_t object = VM_PAGE_OBJECT(m1);
	kern_return_t kr;

	switch (reloc_reason) {
	case VM_RELOCATE_REASON_CONTIGUOUS:
	{
#if HAS_MTE
		/*
		 * The contiguous allocator should not be considering tag
		 * storage pages.
		 */
		assert(!vm_page_is_tag_storage(m1));
#endif /* HAS_MTE */
		break;
	}
#if HAS_MTE
	case VM_RELOCATE_REASON_TAG_STORAGE_RECLAIM:
	{
		/*
		 * If we are trying to reclaim tag storage, we should be
		 * relocating a tag storage page.
		 */
		assert(vm_page_is_tag_storage(m1));
		if (m1->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
			vm_page_tag_storage_compressor_relocation_count++;
		}
		break;
	}
	case VM_RELOCATE_REASON_TAG_STORAGE_WIRE:
	{
		assert(vm_page_is_tag_storage(m1) && m1->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);
		vm_page_tag_storage_wire_relocation_count++;
		break;
	}
#endif /* HAS_MTE */
	default:
	{
		panic("Unrecognized relocation reason %u\n", reloc_reason);
		break;
	}
	}

	if (object == VM_OBJECT_NULL) {
		return KERN_INVALID_OBJECT;
	}

	vm_object_lock_assert_held(object);

	if (VM_PAGE_WIRED(m1) ||
	    m1->vmp_gobbled ||
	    m1->vmp_laundry ||
	    m1->vmp_wanted ||
	    m1->vmp_cleaning ||
	    m1->vmp_overwriting ||
	    m1->vmp_free_when_done ||
	    m1->vmp_busy ||
	    m1->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) {
		return KERN_FAILURE;
	}

	boolean_t disconnected = FALSE;
	boolean_t reusable = FALSE;

	/*
	 * Pages from reusable objects can be reclaimed directly.
	 */
	if ((m1->vmp_reusable || object->all_reusable) &&
	    m1->vmp_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q && !m1->vmp_dirty &&
	    !m1->vmp_reference) {
		/*
		 * reusable page...
		 */

		refmod = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m1));
		disconnected = TRUE;
		if (refmod == 0) {
			/*
			 * ... not reused: can steal without relocating contents.
			 */
			reusable = TRUE;
		}
	}

	if ((m1->vmp_pmapped && !reusable) || m1->vmp_dirty || m1->vmp_precious) {
		vm_grab_options_t grab_options = VM_PAGE_GRAB_Q_LOCK_HELD;
		vm_object_offset_t offset;
		int copy_page_options = 0;

#if HAS_MTE
		if (m1->vmp_using_mte) {
			grab_options |= VM_PAGE_GRAB_MTE;
			copy_page_options |= cppvCopyTags;
		}
#endif /* HAS_MTE */
		/* page is not reusable, we need to allocate a new page
		 * and move its contents there.
		 */
		vm_page_t m2 = vm_page_grab_options(grab_options);

		if (m2 == VM_PAGE_NULL) {
			return KERN_RESOURCE_SHORTAGE;
		}

		if (!disconnected) {
			if (m1->vmp_pmapped) {
				refmod = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m1));
			} else {
				refmod = 0;
			}
		}

#if HAS_MTE
		assert(m1->vmp_using_mte == m2->vmp_using_mte);
		if (m1->vmp_using_mte) {
			assert(pmap_is_tagged_page(VM_PAGE_GET_PHYS_PAGE(m2)));
			copy_page_options |= (cppvCopyTags | cppvDisableTagCheck);
		}
#endif /* HAS_MTE */
		/* copy the page's contents */
		pmap_copy_page(VM_PAGE_GET_PHYS_PAGE(m1), VM_PAGE_GET_PHYS_PAGE(m2), copy_page_options);

		/* copy the page's state */
		assert(!VM_PAGE_WIRED(m1));
		assert(m1->vmp_q_state != VM_PAGE_ON_FREE_Q);
		assert(m1->vmp_q_state != VM_PAGE_ON_PAGEOUT_Q);
		assert(!m1->vmp_laundry);
		m2->vmp_reference = m1->vmp_reference;
		assert(!m1->vmp_gobbled);
		m2->vmp_no_cache = m1->vmp_no_cache;
		m2->vmp_xpmapped = 0;
		assert(!m1->vmp_busy);
		assert(!m1->vmp_wanted);
		assert(vm_page_is_canonical(m1));
		m2->vmp_pmapped = m1->vmp_pmapped; /* should flush cache ? */
		m2->vmp_wpmapped = m1->vmp_wpmapped;
		assert(!m1->vmp_free_when_done);
		m2->vmp_absent = m1->vmp_absent;
		m2->vmp_error = VMP_ERROR_GET(m1);
		m2->vmp_dirty = m1->vmp_dirty;
		assert(!m1->vmp_cleaning);
		m2->vmp_precious = m1->vmp_precious;
		m2->vmp_clustered = m1->vmp_clustered;
		assert(!m1->vmp_overwriting);
		m2->vmp_restart = m1->vmp_restart;
		m2->vmp_unusual = m1->vmp_unusual;
		m2->vmp_cs_validated = m1->vmp_cs_validated;
		m2->vmp_cs_tainted = m1->vmp_cs_tainted;
		m2->vmp_cs_nx = m1->vmp_cs_nx;

		m2->vmp_realtime = m1->vmp_realtime;
		m1->vmp_realtime = false;

		/*
		 * If m1 had really been reusable,
		 * we would have just stolen it, so
		 * let's not propagate its "reusable"
		 * bit and assert that m2 is not
		 * marked as "reusable".
		 */
		// m2->vmp_reusable	= m1->vmp_reusable;
		assert(!m2->vmp_reusable);

		// assert(!m1->vmp_lopage);

		if (m1->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
			m2->vmp_q_state = VM_PAGE_USED_BY_COMPRESSOR;
			/*
			 * We just grabbed m2 up above and so it isn't
			 * going to be on any special Q as yet and so
			 * we don't need to 'remove' it from the special
			 * queues. Just resetting the state should be enough.
			 */
			m2->vmp_on_specialq = VM_PAGE_SPECIAL_Q_EMPTY;
		}

		/*
		 * page may need to be flushed if
		 * it is marshalled into a UPL
		 * that is going to be used by a device
		 * that doesn't support coherency
		 */
		m2->vmp_written_by_kernel = TRUE;

		/*
		 * make sure we clear the ref/mod state
		 * from the pmap layer... else we risk
		 * inheriting state from the last time
		 * this page was used...
		 */
		pmap_clear_refmod(VM_PAGE_GET_PHYS_PAGE(m2),
		    VM_MEM_MODIFIED | VM_MEM_REFERENCED);

		if (refmod & VM_MEM_REFERENCED) {
			m2->vmp_reference = TRUE;
		}
		if (refmod & VM_MEM_MODIFIED) {
			SET_PAGE_DIRTY(m2, TRUE);
		}
		offset = m1->vmp_offset;

		/*
		 * completely cleans up the state
		 * of the page so that it is ready
		 * to be put onto the free list, or
		 * for this purpose it looks like it
		 * just came off of the free list
		 */
		vm_page_free_prepare(m1);

		/*
		 * now put the substitute page on the object
		 */
		vm_page_insert_internal(m2, object, offset, VM_KERN_MEMORY_NONE,
		    VMPI_Q_LOCKED, NULL);

		/*
		 * Return the relocated vm_page_t if the caller wants to know.
		 */
		if (new_page) {
			*new_page = m2;
		}

		if (m2->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
			m2->vmp_pmapped = TRUE;
			m2->vmp_wpmapped = TRUE;

			kr = pmap_enter_check(kernel_pmap, (vm_map_offset_t)m2->vmp_offset, m2,
			    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, TRUE);

			assert(kr == KERN_SUCCESS);

			if (compressed_pages) {
				++*compressed_pages;
			}
		} else {
			/* relocated page was not used by the compressor
			 * put it on either the active or inactive lists */
			if (m2->vmp_reference) {
				vm_page_activate(m2);
			} else {
				vm_page_deactivate(m2);
			}
		}

		/* unset the busy flag (pages on the free queue are busy) and notify if wanted */
		vm_page_wakeup_done(object, m2);
	} else {
		assert(m1->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);

		/*
		 * completely cleans up the state
		 * of the page so that it is ready
		 * to be put onto the free list, or
		 * for this purpose it looks like it
		 * just came off of the free list
		 */
		vm_page_free_prepare(m1);

		if (new_page) {
			vm_page_t m2;
			vm_object_offset_t offset;
			vm_grab_options_t grab_options = VM_PAGE_GRAB_Q_LOCK_HELD;

			/* The caller still wanted a page, so let's give them a new one. */
			offset = m1->vmp_offset;
#if HAS_MTE
			if (m1->vmp_using_mte) {
				grab_options |= VM_PAGE_GRAB_MTE;
			}
#endif /* HAS_MTE */
			m2 = vm_page_grab_options(grab_options);

			if (m2 == VM_PAGE_NULL) {
				return KERN_RESOURCE_SHORTAGE;
			}

			/*
			 * make sure we clear the ref/mod state
			 * from the pmap layer... else we risk
			 * inheriting state from the last time
			 * this page was used...
			 */
			pmap_clear_refmod(VM_PAGE_GET_PHYS_PAGE(m2),
			    VM_MEM_MODIFIED | VM_MEM_REFERENCED);

			offset = m1->vmp_offset;

			/*
			 * now put the substitute page on the object
			 */
			vm_page_insert_internal(m2, object, offset,
			    VM_KERN_MEMORY_NONE, VMPI_Q_LOCKED, NULL);

			*new_page = m2;
		}
	}

	/* we're done here */
	return KERN_SUCCESS;
}

/*
 *	CONTIGUOUS PAGE ALLOCATION
 *
 *	Find a region large enough to contain at least n pages
 *	of contiguous physical memory.
 *
 *	This is done by traversing the vm_page_t array in a linear fashion
 *	we assume that the vm_page_t array has the avaiable physical pages in an
 *	ordered, ascending list... this is currently true of all our implementations
 *      and must remain so... there can be 'holes' in the array...  we also can
 *	no longer tolerate the vm_page_t's in the list being 'freed' and reclaimed
 *      which use to happen via 'vm_page_convert'... that function was no longer
 *      being called and was removed...
 *
 *	The basic flow consists of stabilizing some of the interesting state of
 *	a vm_page_t behind the vm_page_queue and vm_page_free locks... we start our
 *	sweep at the beginning of the array looking for pages that meet our criterea
 *	for a 'stealable' page... currently we are pretty conservative... if the page
 *	meets this criterea and is physically contiguous to the previous page in the 'run'
 *      we keep developing it.  If we hit a page that doesn't fit, we reset our state
 *	and start to develop a new run... if at this point we've already considered
 *      at least MAX_CONSIDERED_BEFORE_YIELD pages, we'll drop the 2 locks we hold,
 *	and mutex_pause (which will yield the processor), to keep the latency low w/r
 *	to other threads trying to acquire free pages (or move pages from q to q),
 *	and then continue from the spot we left off... we only make 1 pass through the
 *	array.  Once we have a 'run' that is long enough, we'll go into the loop which
 *      which steals the pages from the queues they're currently on... pages on the free
 *	queue can be stolen directly... pages that are on any of the other queues
 *	must be removed from the object they are tabled on... this requires taking the
 *      object lock... we do this as a 'try' to prevent deadlocks... if the 'try' fails
 *	or if the state of the page behind the vm_object lock is no longer viable, we'll
 *	dump the pages we've currently stolen back to the free list, and pick up our
 *	scan from the point where we aborted the 'current' run.
 *
 *
 *	Requirements:
 *		- neither vm_page_queue nor vm_free_list lock can be held on entry
 *
 *	Returns a pointer to a list of gobbled/wired pages or VM_PAGE_NULL.
 *
 * Algorithm:
 */

#define MAX_CONSIDERED_BEFORE_YIELD     1000


#define RESET_STATE_OF_RUN()    \
	MACRO_BEGIN             \
	prevcontaddr = -2;      \
	start_pnum = -1;        \
	free_considered = 0;    \
	substitute_needed = 0;  \
	npages = 0;             \
	MACRO_END

/*
 * Can we steal in-use (i.e. not free) pages when searching for
 * physically-contiguous pages ?
 */
#define VM_PAGE_FIND_CONTIGUOUS_CAN_STEAL 1

static unsigned int vm_page_find_contiguous_last_idx = 0, vm_page_lomem_find_contiguous_last_idx = 0;
#if DEBUG
int vm_page_find_contig_debug = 0;
#endif

static vm_page_t
vm_page_find_contiguous(
	unsigned int    contig_pages,
	ppnum_t         max_pnum,
	ppnum_t         pnum_mask,
	boolean_t       wire,
	int             flags)
{
	vm_page_list_t  list = { };
	ppnum_t         prevcontaddr = 0;
	ppnum_t         start_pnum = 0;
	unsigned int    npages = 0, considered = 0, scanned = 0;
	unsigned int    page_idx = 0, start_idx = 0, last_idx = 0, orig_last_idx = 0;
	unsigned int    idx_last_contig_page_found = 0;
	int             free_considered = 0, free_available = 0;
	int             substitute_needed = 0;
	int             zone_gc_called = 0;
	boolean_t       wrapped;
	kern_return_t   kr;
#if DEBUG
	clock_sec_t     tv_start_sec = 0, tv_end_sec = 0;
	clock_usec_t    tv_start_usec = 0, tv_end_usec = 0;
#endif

	int             yielded = 0;
	int             dumped_run = 0;
	int             stolen_pages = 0;
	int             compressed_pages = 0;


	if (contig_pages == 0) {
		return VM_PAGE_NULL;
	}

full_scan_again:

#if MACH_ASSERT
	vm_page_verify_free_lists();
#endif
#if DEBUG
	clock_get_system_microtime(&tv_start_sec, &tv_start_usec);
#endif
	c_page_replacement_allowed_start();

#if XNU_VM_HAS_DELAYED_PAGES
	/*
	 * If there are still delayed pages, try to free up some that match.
	 */
	if (__improbable(vm_delayed_count != 0 && contig_pages != 0)) {
		vm_free_delayed_pages_contig(contig_pages, max_pnum, pnum_mask);
	}
#endif /* XNU_VM_HAS_DELAYED_PAGES */

	vm_page_lock_queues();
	vm_free_page_lock();

	RESET_STATE_OF_RUN();

	scanned = 0;
	considered = 0;
	free_available = vm_page_free_count - vm_page_free_reserved;

	wrapped = FALSE;

	if (flags & KMA_LOMEM) {
		idx_last_contig_page_found = vm_page_lomem_find_contiguous_last_idx;
	} else {
		idx_last_contig_page_found =  vm_page_find_contiguous_last_idx;
	}

	orig_last_idx = idx_last_contig_page_found;
	last_idx = orig_last_idx;

	for (page_idx = last_idx, start_idx = last_idx;
	    npages < contig_pages && page_idx < vm_pages_count;
	    page_idx++) {
		vm_page_t m = NULL;

retry:
		if (wrapped &&
		    npages == 0 &&
		    page_idx >= orig_last_idx) {
			/*
			 * We're back where we started and we haven't
			 * found any suitable contiguous range.  Let's
			 * give up.
			 */
			break;
		}
		scanned++;
		m = vm_page_get(page_idx);

		assert(vm_page_is_canonical(m));

		if (max_pnum && VM_PAGE_GET_PHYS_PAGE(m) > max_pnum) {
			/* no more low pages... */
			break;
		}
		if (!npages & ((VM_PAGE_GET_PHYS_PAGE(m) & pnum_mask) != 0)) {
			/*
			 * not aligned
			 */
			RESET_STATE_OF_RUN();
		} else if (!vm_page_is_relocatable(m,
		    VM_RELOCATE_REASON_CONTIGUOUS)) {
			/*
			 * page is not relocatable */
			RESET_STATE_OF_RUN();
		} else {
			if (VM_PAGE_GET_PHYS_PAGE(m) != prevcontaddr + 1) {
				if ((VM_PAGE_GET_PHYS_PAGE(m) & pnum_mask) != 0) {
					RESET_STATE_OF_RUN();
					goto did_consider;
				} else {
					npages = 1;
					start_idx = page_idx;
					start_pnum = VM_PAGE_GET_PHYS_PAGE(m);
				}
			} else {
				npages++;
			}
			prevcontaddr = VM_PAGE_GET_PHYS_PAGE(m);

			VM_PAGE_CHECK(m);
			if (m->vmp_q_state == VM_PAGE_ON_FREE_Q) {
				free_considered++;
			} else {
				/*
				 * This page is not free.
				 * If we can't steal used pages,
				 * we have to give up this run
				 * and keep looking.
				 * Otherwise, we might need to
				 * move the contents of this page
				 * into a substitute page.
				 */
#if VM_PAGE_FIND_CONTIGUOUS_CAN_STEAL
				if (m->vmp_pmapped || m->vmp_dirty || m->vmp_precious) {
					substitute_needed++;
				}
#else
				RESET_STATE_OF_RUN();
#endif
			}

			if ((free_considered + substitute_needed) > free_available) {
				/*
				 * if we let this run continue
				 * we will end up dropping the vm_page_free_count
				 * below the reserve limit... we need to abort
				 * this run, but we can at least re-consider this
				 * page... thus the jump back to 'retry'
				 */
				RESET_STATE_OF_RUN();

				if (free_available && considered <= MAX_CONSIDERED_BEFORE_YIELD) {
					considered++;
					goto retry;
				}
				/*
				 * free_available == 0
				 * so can't consider any free pages... if
				 * we went to retry in this case, we'd
				 * get stuck looking at the same page
				 * w/o making any forward progress
				 * we also want to take this path if we've already
				 * reached our limit that controls the lock latency
				 */
			}
		}
did_consider:
		if (considered > MAX_CONSIDERED_BEFORE_YIELD && npages <= 1) {
			c_page_replacement_allowed_end();

			vm_free_page_unlock();
			vm_page_unlock_queues();

			mutex_pause(0);

			c_page_replacement_allowed_start();

			vm_page_lock_queues();
			vm_free_page_lock();

			RESET_STATE_OF_RUN();
			/*
			 * reset our free page limit since we
			 * dropped the lock protecting the vm_page_free_queue
			 */
			free_available = vm_page_free_count - vm_page_free_reserved;
			considered = 0;

			yielded++;

			goto retry;
		}
		considered++;
	} /* main for-loop end */

	if (npages != contig_pages) {
		if (!wrapped) {
			/*
			 * We didn't find a contiguous range but we didn't
			 * start from the very first page.
			 * Start again from the very first page.
			 */
			RESET_STATE_OF_RUN();
			if (flags & KMA_LOMEM) {
				idx_last_contig_page_found  = vm_page_lomem_find_contiguous_last_idx = 0;
			} else {
				idx_last_contig_page_found = vm_page_find_contiguous_last_idx = 0;
			}
			last_idx = 0;
			page_idx = last_idx;
			wrapped = TRUE;
			goto retry;
		}
		vm_free_page_unlock();
	} else {
		vm_page_t m1;
		unsigned int cur_idx;
		unsigned int tmp_start_idx;
		vm_object_t locked_object = VM_OBJECT_NULL;
		bool abort_run = false;

		assert(page_idx - start_idx == contig_pages);

		tmp_start_idx = start_idx;

		/*
		 * first pass through to pull the free pages
		 * off of the free queue so that in case we
		 * need substitute pages, we won't grab any
		 * of the free pages in the run... we'll clear
		 * the 'free' bit in the 2nd pass, and even in
		 * an abort_run case, we'll collect all of the
		 * free pages in this run and return them to the free list
		 */
		while (start_idx < page_idx) {
			vm_grab_options_t options = VM_PAGE_GRAB_OPTIONS_NONE;

			m1 = vm_page_get(start_idx++);

#if !VM_PAGE_FIND_CONTIGUOUS_CAN_STEAL
			assert(m1->vmp_q_state == VM_PAGE_ON_FREE_Q);
#endif
			if (m1->vmp_q_state == VM_PAGE_ON_FREE_Q) {
				vm_page_free_queue_steal(options, m1);
			}
		}
		if (flags & KMA_LOMEM) {
			vm_page_lomem_find_contiguous_last_idx = page_idx;
		} else {
			vm_page_find_contiguous_last_idx = page_idx;
		}

		/*
		 * we can drop the free queue lock at this point since
		 * we've pulled any 'free' candidates off of the list
		 * we need it dropped so that we can do a vm_page_grab
		 * when substituing for pmapped/dirty pages
		 */
		vm_free_page_unlock();

		start_idx = tmp_start_idx;
		cur_idx = page_idx - 1;

		while (start_idx++ < page_idx) {
			/*
			 * must go through the list from back to front
			 * so that the page list is created in the
			 * correct order - low -> high phys addresses
			 */
			m1 = vm_page_get(cur_idx--);

			if (m1->vmp_object == 0) {
				/*
				 * page has already been removed from
				 * the free list in the 1st pass
				 */
				assert(m1->vmp_q_state == VM_PAGE_NOT_ON_Q);
				assert(m1->vmp_offset == (vm_object_offset_t) -1);
				assert(m1->vmp_busy);
				assert(!m1->vmp_wanted);
				assert(!m1->vmp_laundry);
			} else {
				/*
				 * try to relocate/steal the page
				 */
				if (abort_run) {
					continue;
				}

				assert(m1->vmp_q_state != VM_PAGE_NOT_ON_Q);

				vm_object_t object = VM_PAGE_OBJECT(m1);

				if (object != locked_object) {
					if (locked_object) {
						vm_object_unlock(locked_object);
						locked_object = VM_OBJECT_NULL;
					}
					if (vm_object_lock_try(object)) {
						locked_object = object;
					} else {
						/* object must be locked to relocate its pages */
						tmp_start_idx = cur_idx;
						abort_run = true;
						continue;
					}
				}

				kr = vm_page_relocate(m1, &compressed_pages, VM_RELOCATE_REASON_CONTIGUOUS, NULL);
				if (kr != KERN_SUCCESS) {
					if (locked_object) {
						vm_object_unlock(locked_object);
						locked_object = VM_OBJECT_NULL;
					}
					tmp_start_idx = cur_idx;
					abort_run = true;
					continue;
				}

				stolen_pages++;
			}

			/* m1 is ours at this point ... */

			if (m1->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR) {
				/*
				 * The Q state is preserved on m1 because vm_page_queues_remove doesn't
				 * change it for pages marked as used-by-compressor.
				 */
				vm_page_assign_special_state(m1, VM_PAGE_SPECIAL_Q_BG);
			}
			VM_PAGE_ZERO_PAGEQ_ENTRY(m1);
			vm_page_list_push(&list, m1);
		}

		if (locked_object) {
			vm_object_unlock(locked_object);
			locked_object = VM_OBJECT_NULL;
		}

		if (abort_run) {
			/*
			 * want the index of the last
			 * page in this run that was
			 * successfully 'stolen', so back
			 * it up 1 for the auto-decrement on use
			 * and 1 more to bump back over this page
			 */
			page_idx = tmp_start_idx + 2;
			if (page_idx >= vm_pages_count) {
				if (wrapped) {
					if (list.vmpl_count) {
						vm_page_unlock_queues();
						vm_page_free_list(list.vmpl_head, FALSE);
						vm_page_lock_queues();
						list = (vm_page_list_t){ };
					}
					dumped_run++;
					goto done_scanning;
				}
				page_idx = last_idx = 0;
				wrapped = TRUE;
			}
			abort_run = false;

			/*
			 * We didn't find a contiguous range but we didn't
			 * start from the very first page.
			 * Start again from the very first page.
			 */
			RESET_STATE_OF_RUN();

			if (flags & KMA_LOMEM) {
				idx_last_contig_page_found  = vm_page_lomem_find_contiguous_last_idx = page_idx;
			} else {
				idx_last_contig_page_found = vm_page_find_contiguous_last_idx = page_idx;
			}

			last_idx = page_idx;

			if (list.vmpl_count) {
				vm_page_unlock_queues();
				vm_page_free_list(list.vmpl_head, FALSE);
				vm_page_lock_queues();
				list = (vm_page_list_t){ };
			}
			dumped_run++;

			vm_free_page_lock();
			/*
			 * reset our free page limit since we
			 * dropped the lock protecting the vm_page_free_queue
			 */
			free_available = vm_page_free_count - vm_page_free_reserved;
			goto retry;
		}
#if HAS_MTE
		else if (list.vmpl_has_tagged) {
			const unified_page_list_t pmap_batch_list = {
				.page_slist = list.vmpl_head,
				.type = UNIFIED_PAGE_LIST_TYPE_VM_PAGE_LIST,
			};

			/*
			 * We successfully found a contiguous range we could
			 * steal all the pages from.  As a last step, make
			 * certain all pages are regular pages, or convert
			 * any non-regular pages to regular pages.
			 */
			vm_page_unlock_queues();

			/* Make any tagged pages we stole non-tagged. */
			pmap_unmake_tagged_pages(&pmap_batch_list);

			vm_free_page_lock();

			/* Mark any tagged pages we stole as non-tagged. */
			vm_page_list_foreach(m1, list) {
				if (m1->vmp_using_mte) {
					ppnum_t pnum = VM_PAGE_GET_PHYS_PAGE(m1);

					m1->vmp_using_mte = false;
					mteinfo_covered_page_clear_tagged(pnum);
				}
			}
			list.vmpl_has_tagged = false;
			list.vmpl_has_untagged = true;

			vm_free_page_unlock();
			vm_page_lock_queues();
		}
#endif /* HAS_MTE */

		vm_page_list_foreach(m1, list) {
			assert(m1->vmp_q_state == VM_PAGE_NOT_ON_Q);
			assert(m1->vmp_wire_count == 0);

			if (wire == TRUE) {
				m1->vmp_wire_count++;
				m1->vmp_q_state = VM_PAGE_IS_WIRED;

#if HAS_MTE
				if (m1->vmp_wire_count == 1) {
					mteinfo_increment_wire_count(m1);
				}
#endif /* HAS_MTE */
			} else {
				m1->vmp_gobbled = TRUE;
			}
		}
		if (wire == FALSE) {
			vm_page_gobble_count += npages;
		}

		/*
		 * gobbled pages are also counted as wired pages
		 */
		vm_page_wire_count += npages;

		assert(vm_page_verify_contiguous(list.vmpl_head, npages));
	}
done_scanning:
	c_page_replacement_allowed_end();

	vm_page_unlock_queues();

#if DEBUG
	clock_get_system_microtime(&tv_end_sec, &tv_end_usec);

	tv_end_sec -= tv_start_sec;
	if (tv_end_usec < tv_start_usec) {
		tv_end_sec--;
		tv_end_usec += 1000000;
	}
	tv_end_usec -= tv_start_usec;
	if (tv_end_usec >= 1000000) {
		tv_end_sec++;
		tv_end_sec -= 1000000;
	}
	if (vm_page_find_contig_debug) {
		printf("%s(num=%d,low=%d): found %d pages at 0x%llx in %ld.%06ds...  started at %d...  scanned %d pages...  yielded %d times...  dumped run %d times... stole %d pages... stole %d compressed pages\n",
		    __func__, contig_pages, max_pnum, npages, (vm_object_offset_t)start_pnum << PAGE_SHIFT,
		    (long)tv_end_sec, tv_end_usec, orig_last_idx,
		        scanned, yielded, dumped_run, stolen_pages, compressed_pages);
	}

#endif
#if MACH_ASSERT
	vm_page_verify_free_lists();
#endif
	if (list.vmpl_count == 0 && zone_gc_called < 2) {
		printf("%s(num=%d,low=%d): found %d pages at 0x%llx...scanned %d pages...  yielded %d times...  dumped run %d times... stole %d pages... stole %d compressed pages... wired count is %d\n",
		    __func__, contig_pages, max_pnum, npages, (vm_object_offset_t)start_pnum << PAGE_SHIFT,
		        scanned, yielded, dumped_run, stolen_pages, compressed_pages, vm_page_wire_count);

		if (consider_buffer_cache_collect != NULL) {
			(void)(*consider_buffer_cache_collect)(1);
		}

		zone_gc(zone_gc_called ? ZONE_GC_DRAIN : ZONE_GC_TRIM);

		zone_gc_called++;

		printf("vm_page_find_contiguous: zone_gc called... wired count is %d\n", vm_page_wire_count);
		goto full_scan_again;
	}

	return list.vmpl_head;
}

/*
 *	Allocate a list of contiguous, wired pages.
 */
__mockable kern_return_t
cpm_allocate(
	vm_size_t       size,
	vm_page_t       *list,
	ppnum_t         max_pnum,
	ppnum_t         pnum_mask,
	boolean_t       wire,
	int             flags)
{
	vm_page_t               pages;
	unsigned int            npages;

	if (size % PAGE_SIZE != 0) {
		return KERN_INVALID_ARGUMENT;
	}

	npages = (unsigned int) (size / PAGE_SIZE);
	if (npages != size / PAGE_SIZE) {
		/* 32-bit overflow */
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Obtain a pointer to a subset of the free
	 *	list large enough to satisfy the request;
	 *	the region will be physically contiguous.
	 */
	pages = vm_page_find_contiguous(npages, max_pnum, pnum_mask, wire, flags);

	if (pages == VM_PAGE_NULL) {
		return KERN_NO_SPACE;
	}
	/*
	 * determine need for wakeups
	 */
	if (vm_page_free_count < vm_page_free_min) {
		vm_free_page_lock();
		if (vm_pageout_running == FALSE) {
			vm_free_page_unlock();
			thread_wakeup((event_t) &vm_page_free_wanted);
		} else {
			vm_free_page_unlock();
		}
	}

	VM_CHECK_MEMORYSTATUS;

	/*
	 *	The CPM pages should now be available and
	 *	ordered by ascending physical address.
	 */
	assert(vm_page_verify_contiguous(pages, npages));

	if (flags & KMA_ZERO) {
		for (vm_page_t m = pages; m; m = NEXT_PAGE(m)) {
			pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(m));
		}
	}

	*list = pages;
	return KERN_SUCCESS;
}


unsigned int vm_max_delayed_work_limit = DEFAULT_DELAYED_WORK_LIMIT;

/*
 * when working on a 'run' of pages, it is necessary to hold
 * the vm_page_queue_lock (a hot global lock) for certain operations
 * on the page... however, the majority of the work can be done
 * while merely holding the object lock... in fact there are certain
 * collections of pages that don't require any work brokered by the
 * vm_page_queue_lock... to mitigate the time spent behind the global
 * lock, go to a 2 pass algorithm... collect pages up to DELAYED_WORK_LIMIT
 * while doing all of the work that doesn't require the vm_page_queue_lock...
 * then call vm_page_do_delayed_work to acquire the vm_page_queue_lock and do the
 * necessary work for each page... we will grab the busy bit on the page
 * if it's not already held so that vm_page_do_delayed_work can drop the object lock
 * if it can't immediately take the vm_page_queue_lock in order to compete
 * for the locks in the same order that vm_pageout_scan takes them.
 * the operation names are modeled after the names of the routines that
 * need to be called in order to make the changes very obvious in the
 * original loop
 *
 * On certain configurations, this function may return failure if any of
 * the pages in the run has a mapping state that doesn't allow the specified
 * operation.  In that case, it will still fully process the run of pages
 * in order to avoid requiring the caller to partially undo the work done
 * here.
 */

kern_return_t
vm_page_do_delayed_work(
	vm_object_t     object,
	vm_tag_t        tag,
	struct vm_page_delayed_work *dwp,
	int             dw_count)
{
	kern_return_t   kr = KERN_SUCCESS;
	int             j;
	vm_page_t       m;
	vm_page_t       local_free_q = VM_PAGE_NULL;

	/*
	 * pageout_scan takes the vm_page_lock_queues first
	 * then tries for the object lock... to avoid what
	 * is effectively a lock inversion, we'll go to the
	 * trouble of taking them in that same order... otherwise
	 * if this object contains the majority of the pages resident
	 * in the UBC (or a small set of large objects actively being
	 * worked on contain the majority of the pages), we could
	 * cause the pageout_scan thread to 'starve' in its attempt
	 * to find pages to move to the free queue, since it has to
	 * successfully acquire the object lock of any candidate page
	 * before it can steal/clean it.
	 */
	if (!vm_page_trylock_queues()) {
		vm_object_unlock(object);

		/*
		 * "Turnstile enabled vm_pageout_scan" can be runnable
		 * for a very long time without getting on a core.
		 * If this is a higher priority thread it could be
		 * waiting here for a very long time respecting the fact
		 * that pageout_scan would like its object after VPS does
		 * a mutex_pause(0).
		 * So we cap the number of yields in the vm_object_lock_avoid()
		 * case to a single mutex_pause(0) which will give vm_pageout_scan
		 * 10us to run and grab the object if needed.
		 */
		vm_page_lock_queues();

		for (j = 0;; j++) {
			if ((!vm_object_lock_avoid(object) ||
			    (vps_dynamic_priority_enabled && (j > 0))) &&
			    _vm_object_lock_try(object)) {
				break;
			}
			vm_page_unlock_queues();
			mutex_pause(j);
			vm_page_lock_queues();
		}
	}
	for (j = 0; j < dw_count; j++, dwp++) {
		m = dwp->dw_m;

		if (dwp->dw_mask & DW_vm_pageout_throttle_up) {
			vm_pageout_throttle_up(m);
		}
#if CONFIG_PHANTOM_CACHE
		if (dwp->dw_mask & DW_vm_phantom_cache_update) {
			vm_phantom_cache_update(m);
		}
#endif
		if (dwp->dw_mask & DW_vm_page_wire) {
			vm_page_wire(m, tag, FALSE);
			if (dwp->dw_mask & DW_vm_page_iopl_wire) {
#if CONFIG_SPTM
				/*
				 * The SPTM's security model prevents us from allowing writable I/O
				 * mappings of executable pages.  We need to check that here,
				 * in the same place that we set VM_PAGE_IS_IOPL_WIRED, because this
				 * function may have transiently dropped the VM object lock
				 * before reaching this point, which means that frontloading
				 * this check in the caller may not work in all cases.
				 */
				if ((dwp->dw_mask & DW_vm_page_iopl_wire_write) && PMAP_PAGE_IS_USER_EXECUTABLE(m)) {
					if (kr == KERN_SUCCESS) {
						kr = KERN_PROTECTION_FAILURE;
						vm_map_guard_exception(current_map(), VM_PAGE_GET_PHYS_PAGE(m), kGUARD_EXC_SEC_IOPL_ON_EXEC_PAGE);
						ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM,
						    KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_IOPL_ON_EXEC_PAGE),
						    (uintptr_t)(VM_PAGE_GET_PHYS_PAGE(m)));
					}
				} else {
					m->vmp_q_state = VM_PAGE_IS_IOPL_WIRED;
				}
#else
				m->vmp_q_state = VM_PAGE_IS_IOPL_WIRED;
#endif /* CONFIG_SPTM */
			}
		} else if (dwp->dw_mask & DW_vm_page_unwire) {
			boolean_t       queueit;

			queueit = (dwp->dw_mask & (DW_vm_page_free | DW_vm_page_deactivate_internal)) ? FALSE : TRUE;

			vm_page_unwire(m, queueit);
		}
		if (dwp->dw_mask & DW_vm_page_free) {
			vm_page_free_prepare_queues(m);

			assert(m->vmp_pageq.next == 0 && m->vmp_pageq.prev == 0);
			/*
			 * Add this page to our list of reclaimed pages,
			 * to be freed later.
			 */
			m->vmp_snext = local_free_q;
			local_free_q = m;
		} else {
			if (dwp->dw_mask & DW_vm_page_deactivate_internal) {
				vm_page_deactivate_internal(m, FALSE);
			} else if (dwp->dw_mask & DW_vm_page_activate) {
				if (m->vmp_q_state != VM_PAGE_ON_ACTIVE_Q) {
					vm_page_activate(m);
				}
			} else if (dwp->dw_mask & DW_vm_page_speculate) {
				vm_page_speculate(m, TRUE);
			} else if (dwp->dw_mask & DW_enqueue_cleaned) {
				/*
				 * if we didn't hold the object lock and did this,
				 * we might disconnect the page, then someone might
				 * soft fault it back in, then we would put it on the
				 * cleaned queue, and so we would have a referenced (maybe even dirty)
				 * page on that queue, which we don't want
				 */
				int refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));

				if ((refmod_state & VM_MEM_REFERENCED)) {
					/*
					 * this page has been touched since it got cleaned; let's activate it
					 * if it hasn't already been
					 */
					VM_PAGEOUT_DEBUG(vm_pageout_enqueued_cleaned, 1);
					VM_PAGEOUT_DEBUG(vm_pageout_cleaned_reactivated, 1);

					if (m->vmp_q_state != VM_PAGE_ON_ACTIVE_Q) {
						vm_page_activate(m);
					}
				} else {
					m->vmp_reference = FALSE;
					vm_page_enqueue_cleaned(m);
				}
			} else if (dwp->dw_mask & DW_vm_page_lru) {
				vm_page_lru(m);
			} else if (dwp->dw_mask & DW_VM_PAGE_QUEUES_REMOVE) {
				if (m->vmp_q_state != VM_PAGE_ON_PAGEOUT_Q) {
					vm_page_queues_remove(m, TRUE);
				}
			}
			if (dwp->dw_mask & DW_set_reference) {
				m->vmp_reference = TRUE;
			} else if (dwp->dw_mask & DW_clear_reference) {
				m->vmp_reference = FALSE;
			}

			if (dwp->dw_mask & DW_move_page) {
				if (m->vmp_q_state != VM_PAGE_ON_PAGEOUT_Q) {
					vm_page_queues_remove(m, FALSE);

					assert(!is_kernel_object(VM_PAGE_OBJECT(m)));

					vm_page_enqueue_inactive(m, FALSE);
				}
			}
			if (dwp->dw_mask & DW_clear_busy) {
				m->vmp_busy = FALSE;
			}

			if (dwp->dw_mask & DW_PAGE_WAKEUP) {
				vm_page_wakeup(object, m);
			}
#if HAS_MTE
			if (dwp->dw_mask & DW_vm_page_wakeup_tag_storage) {
				assert(m->vmp_ts_wanted);
				mteinfo_tag_storage_wakeup(m, false);
			}
#endif /* HAS_MTE */
		}
	}
	vm_page_unlock_queues();

	if (local_free_q) {
		vm_page_free_list(local_free_q, TRUE);
	}

	VM_CHECK_MEMORYSTATUS;

	return kr;
}

__abortlike
static void
__vm_page_alloc_list_failed_panic(
	vm_size_t       page_count,
	kma_flags_t     flags,
	kern_return_t   kr)
{
	panic("vm_page_alloc_list(%zd, 0x%x) failed unexpectedly with %d",
	    (size_t)page_count, flags, kr);
}

kern_return_t
vm_page_alloc_list(vm_size_t page_count, kma_flags_t flags, vm_page_t *list)
{
	vm_page_t       page_list = VM_PAGE_NULL;
	vm_page_t       mem;
	kern_return_t   kr = KERN_SUCCESS;
	int             page_grab_count = 0;

	for (vm_size_t i = 0; i < page_count; i++) {
		for (;;) {
			vm_grab_options_t options = VM_PAGE_GRAB_OPTIONS_NONE;

#if HAS_MTE
			if (flags & KMA_TAG) {
				options |= VM_PAGE_GRAB_MTE;
			}
			if (vm_mte_tag_storage_for_compressor && (flags & KMA_COMPRESSOR)) {
				/*
				 * These pages will be used in the compressor pool.
				 * Prefer tag storage pages for these allocations.
				 */
				options |= VM_PAGE_GRAB_ALLOW_TAG_STORAGE;
			}
#endif /* HAS_MTE */
			if (flags & KMA_NOPAGEWAIT) {
				options |= VM_PAGE_GRAB_NOPAGEWAIT;
			}
			if (flags & KMA_LOMEM) {
				mem = vm_page_grablo(options);
			} else {
				mem = vm_page_grab_options(options);
			}

			if (mem != VM_PAGE_NULL) {
				break;
			}

			if (flags & KMA_NOPAGEWAIT) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			if ((flags & KMA_LOMEM) && vm_lopage_needed) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}

			/* VM privileged threads should have waited in vm_page_grab() and not get here. */
			assert(!(current_thread()->options & TH_OPT_VMPRIV));

			if ((flags & KMA_NOFAIL) == 0 && ptoa_64(page_count) > max_mem / 4) {
				uint64_t unavailable = ptoa_64(vm_page_wire_count + vm_page_free_target);
				if (unavailable > max_mem || ptoa_64(page_count) > (max_mem - unavailable)) {
					kr = KERN_RESOURCE_SHORTAGE;
					goto out;
				}
			}
			VM_PAGE_WAIT();
		}

		page_grab_count++;
		mem->vmp_snext = page_list;
		page_list = mem;
	}

	if ((KMA_ZERO | KMA_NOENCRYPT) & flags) {
		for (mem = page_list; mem; mem = mem->vmp_snext) {
			pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(mem));
		}
	}

out:
	ledger_credit(current_thread()->t_ledger,
	    task_ledgers.pages_grabbed_kern, page_grab_count);
	counter_inc(&vm_page_grab_count_kern);

	if (kr == KERN_SUCCESS) {
		*list = page_list;
	} else if (flags & KMA_NOFAIL) {
		__vm_page_alloc_list_failed_panic(page_count, flags, kr);
	} else {
		vm_page_free_list(page_list, FALSE);
	}

	return kr;
}

void
vm_page_set_offset(vm_page_t page, vm_object_offset_t offset)
{
	page->vmp_offset = offset;
}

vm_page_t
vm_page_get_next(vm_page_t page)
{
	return page->vmp_snext;
}

vm_object_offset_t
vm_page_get_offset(vm_page_t page)
{
	return page->vmp_offset;
}

ppnum_t
vm_page_get_phys_page(vm_page_t page)
{
	return VM_PAGE_GET_PHYS_PAGE(page);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if HIBERNATION

static uint32_t hibernate_teardown_vm_structs(hibernate_page_list_t *, hibernate_page_list_t *);

struct hibernate_statistics {
	int hibernate_considered;
	int hibernate_reentered_on_q;
	int hibernate_found_dirty;
	int hibernate_skipped_cleaning;
	int hibernate_skipped_transient;
	int hibernate_skipped_precious;
	int hibernate_skipped_external;
	int hibernate_queue_nolock;
	int hibernate_queue_paused;
	int hibernate_throttled;
	int hibernate_throttle_timeout;
	int hibernate_drained;
	int hibernate_drain_timeout;
	int cd_lock_failed;
	int cd_found_precious;
	int cd_found_wired;
	int cd_found_busy;
	int cd_found_unusual;
	int cd_found_cleaning;
	int cd_found_laundry;
	int cd_found_dirty;
	int cd_found_xpmapped;
	int cd_skipped_xpmapped;
	int cd_local_free;
	int cd_total_free;
	int cd_vm_page_wire_count;
	int cd_vm_struct_pages_unneeded;
	int cd_pages;
	int cd_discarded;
	int cd_count_wire;
} hibernate_stats;

#if CONFIG_SPTM
/**
 * On SPTM-based systems don't save any executable pages into the hibernation
 * image. The SPTM has stronger guarantees around not allowing write access to
 * the executable pages than on older systems, which prevents XNU from being
 * able to restore any pages mapped as executable.
 */
#define HIBERNATE_XPMAPPED_LIMIT        0ULL
#else /* CONFIG_SPTM */
/*
 * clamp the number of 'xpmapped' pages we'll sweep into the hibernation image
 * so that we don't overrun the estimated image size, which would
 * result in a hibernation failure.
 *
 * We use a size value instead of pages because we don't want to take up more space
 * on disk if the system has a 16K page size vs 4K. Also, we are not guaranteed
 * to have that additional space available.
 *
 * Since this was set at 40000 pages on X86 we are going to use 160MB as our
 * xpmapped size.
 */
#define HIBERNATE_XPMAPPED_LIMIT        ((160 * 1024 * 1024ULL) / PAGE_SIZE)
#endif /* CONFIG_SPTM */

static int
hibernate_drain_pageout_queue(struct vm_pageout_queue *q)
{
	wait_result_t   wait_result;

	vm_page_lock_queues();

	while (!vm_page_queue_empty(&q->pgo_pending)) {
		q->pgo_draining = TRUE;

		assert_wait_timeout((event_t) (&q->pgo_laundry + 1), THREAD_INTERRUPTIBLE, 5000, 1000 * NSEC_PER_USEC);

		vm_page_unlock_queues();

		wait_result = thread_block(THREAD_CONTINUE_NULL);

		if (wait_result == THREAD_TIMED_OUT && !vm_page_queue_empty(&q->pgo_pending)) {
			hibernate_stats.hibernate_drain_timeout++;

			if (q == &vm_pageout_queue_external) {
				return 0;
			}

			return 1;
		}
		vm_page_lock_queues();

		hibernate_stats.hibernate_drained++;
	}
	vm_page_unlock_queues();

	return 0;
}


boolean_t hibernate_skip_external = FALSE;

static int
hibernate_flush_queue(vm_page_queue_head_t *q, int qcount)
{
	vm_page_t       m;
	vm_object_t     l_object = NULL;
	vm_object_t     m_object = NULL;
	int             refmod_state = 0;
	int             try_failed_count = 0;
	int             retval = 0;
	int             current_run = 0;
	struct  vm_pageout_queue *iq;
	struct  vm_pageout_queue *eq;
	struct  vm_pageout_queue *tq;

	KDBG(IOKDBG_CODE(DBG_HIBERNATE, 4) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(q), qcount);

	iq = &vm_pageout_queue_internal;
	eq = &vm_pageout_queue_external;

	vm_page_lock_queues();

	while (qcount && !vm_page_queue_empty(q)) {
		if (current_run++ == 1000) {
			if (hibernate_should_abort()) {
				retval = 1;
				break;
			}
			current_run = 0;
		}

		m = (vm_page_t) vm_page_queue_first(q);
		m_object = VM_PAGE_OBJECT(m);

		/*
		 * check to see if we currently are working
		 * with the same object... if so, we've
		 * already got the lock
		 */
		if (m_object != l_object) {
			/*
			 * the object associated with candidate page is
			 * different from the one we were just working
			 * with... dump the lock if we still own it
			 */
			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}
			/*
			 * Try to lock object; since we've alread got the
			 * page queues lock, we can only 'try' for this one.
			 * if the 'try' fails, we need to do a mutex_pause
			 * to allow the owner of the object lock a chance to
			 * run...
			 */
			if (!vm_object_lock_try_scan(m_object)) {
				if (try_failed_count > 20) {
					hibernate_stats.hibernate_queue_nolock++;

					goto reenter_pg_on_q;
				}

				vm_page_unlock_queues();
				mutex_pause(try_failed_count++);
				vm_page_lock_queues();

				hibernate_stats.hibernate_queue_paused++;
				continue;
			} else {
				l_object = m_object;
			}
		}
		if (!m_object->alive || m->vmp_cleaning || m->vmp_laundry || m->vmp_busy || m->vmp_absent || VMP_ERROR_GET(m)) {
			/*
			 * page is not to be cleaned
			 * put it back on the head of its queue
			 */
			if (m->vmp_cleaning) {
				hibernate_stats.hibernate_skipped_cleaning++;
			} else {
				hibernate_stats.hibernate_skipped_transient++;
			}

			goto reenter_pg_on_q;
		}
		if (m_object->vo_copy == VM_OBJECT_NULL) {
			if (m_object->purgable == VM_PURGABLE_VOLATILE || m_object->purgable == VM_PURGABLE_EMPTY) {
				/*
				 * let the normal hibernate image path
				 * deal with these
				 */
				goto reenter_pg_on_q;
			}
		}
		if (!m->vmp_dirty && m->vmp_pmapped) {
			refmod_state = pmap_get_refmod(VM_PAGE_GET_PHYS_PAGE(m));

			if ((refmod_state & VM_MEM_MODIFIED)) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		} else {
			refmod_state = 0;
		}

		if (!m->vmp_dirty) {
			/*
			 * page is not to be cleaned
			 * put it back on the head of its queue
			 */
			if (m->vmp_precious) {
				hibernate_stats.hibernate_skipped_precious++;
			}

			goto reenter_pg_on_q;
		}

		if (hibernate_skip_external == TRUE && !m_object->internal) {
			hibernate_stats.hibernate_skipped_external++;

			goto reenter_pg_on_q;
		}
		tq = NULL;

		if (m_object->internal) {
			if (VM_PAGE_Q_THROTTLED(iq)) {
				tq = iq;
			}
		} else if (VM_PAGE_Q_THROTTLED(eq)) {
			tq = eq;
		}

		if (tq != NULL) {
			wait_result_t   wait_result;
			int             wait_count = 5;

			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}

			while (retval == 0) {
				tq->pgo_throttled = TRUE;

				assert_wait_timeout((event_t) &tq->pgo_laundry, THREAD_INTERRUPTIBLE, 1000, 1000 * NSEC_PER_USEC);

				vm_page_unlock_queues();

				wait_result = thread_block(THREAD_CONTINUE_NULL);

				vm_page_lock_queues();

				if (wait_result != THREAD_TIMED_OUT) {
					break;
				}
				if (!VM_PAGE_Q_THROTTLED(tq)) {
					break;
				}

				if (hibernate_should_abort()) {
					retval = 1;
				}

				if (--wait_count == 0) {
					hibernate_stats.hibernate_throttle_timeout++;

					if (tq == eq) {
						hibernate_skip_external = TRUE;
						break;
					}
					retval = 1;
				}
			}
			if (retval) {
				break;
			}

			hibernate_stats.hibernate_throttled++;

			continue;
		}
		/*
		 * we've already factored out pages in the laundry which
		 * means this page can't be on the pageout queue so it's
		 * safe to do the vm_page_queues_remove
		 */
		vm_page_queues_remove(m, TRUE);

		if (m_object->internal == TRUE) {
			pmap_disconnect_options(VM_PAGE_GET_PHYS_PAGE(m), PMAP_OPTIONS_COMPRESSOR, NULL);
		}

		vm_pageout_cluster(m);

		hibernate_stats.hibernate_found_dirty++;

		goto next_pg;

reenter_pg_on_q:
		vm_page_queue_remove(q, m, vmp_pageq);
		vm_page_queue_enter(q, m, vmp_pageq);

		hibernate_stats.hibernate_reentered_on_q++;
next_pg:
		hibernate_stats.hibernate_considered++;

		qcount--;
		try_failed_count = 0;
	}
	if (l_object != NULL) {
		vm_object_unlock(l_object);
		l_object = NULL;
	}

	vm_page_unlock_queues();

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 4) | DBG_FUNC_END, hibernate_stats.hibernate_found_dirty, retval, 0, 0, 0);

	return retval;
}


static int
hibernate_flush_dirty_pages(int pass)
{
	struct vm_speculative_age_q     *aq;
	uint32_t        i;

	if (vm_page_local_q) {
		zpercpu_foreach_cpu(lid) {
			vm_page_reactivate_local(lid, TRUE, FALSE);
		}
	}

	for (i = 0; i <= vm_page_max_speculative_age_q; i++) {
		int             qcount;
		vm_page_t       m;

		aq = &vm_page_queue_speculative[i];

		if (vm_page_queue_empty(&aq->age_q)) {
			continue;
		}
		qcount = 0;

		vm_page_lockspin_queues();

		vm_page_queue_iterate(&aq->age_q, m, vmp_pageq) {
			qcount++;
		}
		vm_page_unlock_queues();

		if (qcount) {
			if (hibernate_flush_queue(&aq->age_q, qcount)) {
				return 1;
			}
		}
	}
	if (hibernate_flush_queue(&vm_page_queue_inactive, vm_page_inactive_count - vm_page_anonymous_count - vm_page_cleaned_count)) {
		return 1;
	}
	/* XXX FBDP TODO: flush secluded queue */
	if (hibernate_flush_queue(&vm_page_queue_anonymous, vm_page_anonymous_count)) {
		return 1;
	}
	if (hibernate_flush_queue(&vm_page_queue_cleaned, vm_page_cleaned_count)) {
		return 1;
	}
	if (hibernate_drain_pageout_queue(&vm_pageout_queue_internal)) {
		return 1;
	}

	if (pass == 1) {
		vm_compressor_record_warmup_start();
	}

	if (hibernate_flush_queue(&vm_page_queue_active, vm_page_active_count)) {
		if (pass == 1) {
			vm_compressor_record_warmup_end();
		}
		return 1;
	}
	if (hibernate_drain_pageout_queue(&vm_pageout_queue_internal)) {
		if (pass == 1) {
			vm_compressor_record_warmup_end();
		}
		return 1;
	}
	if (pass == 1) {
		vm_compressor_record_warmup_end();
	}

	if (hibernate_skip_external == FALSE && hibernate_drain_pageout_queue(&vm_pageout_queue_external)) {
		return 1;
	}

	return 0;
}


void
hibernate_reset_stats(void)
{
	bzero(&hibernate_stats, sizeof(struct hibernate_statistics));
}


int
hibernate_flush_memory(void)
{
	int     retval;

	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 3) | DBG_FUNC_START, vm_page_free_count, 0, 0, 0, 0);

	hibernate_cleaning_in_progress = TRUE;
	hibernate_skip_external = FALSE;

	if ((retval = hibernate_flush_dirty_pages(1)) == 0) {
		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 10) | DBG_FUNC_START, VM_PAGE_COMPRESSOR_COUNT, 0, 0, 0, 0);

		vm_compressor_flush();

		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 10) | DBG_FUNC_END, VM_PAGE_COMPRESSOR_COUNT, 0, 0, 0, 0);

		if (consider_buffer_cache_collect != NULL) {
			unsigned int orig_wire_count;

			KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 7) | DBG_FUNC_START, 0, 0, 0, 0, 0);
			orig_wire_count = vm_page_wire_count;

			(void)(*consider_buffer_cache_collect)(1);
			zone_gc(ZONE_GC_DRAIN);

			HIBLOG("hibernate_flush_memory: buffer_cache_gc freed up %d wired pages\n", orig_wire_count - vm_page_wire_count);

			KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 7) | DBG_FUNC_END, orig_wire_count - vm_page_wire_count, 0, 0, 0, 0);
		}
	}
	hibernate_cleaning_in_progress = FALSE;

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 3) | DBG_FUNC_END, vm_page_free_count, hibernate_stats.hibernate_found_dirty, retval, 0, 0);

	if (retval) {
		HIBLOG("hibernate_flush_memory() failed to finish - vm_page_compressor_count(%d)\n", VM_PAGE_COMPRESSOR_COUNT);
	}


	HIBPRINT("hibernate_flush_memory() considered(%d) reentered_on_q(%d) found_dirty(%d)\n",
	    hibernate_stats.hibernate_considered,
	    hibernate_stats.hibernate_reentered_on_q,
	    hibernate_stats.hibernate_found_dirty);
	HIBPRINT("   skipped_cleaning(%d) skipped_transient(%d) skipped_precious(%d) skipped_external(%d) queue_nolock(%d)\n",
	    hibernate_stats.hibernate_skipped_cleaning,
	    hibernate_stats.hibernate_skipped_transient,
	    hibernate_stats.hibernate_skipped_precious,
	    hibernate_stats.hibernate_skipped_external,
	    hibernate_stats.hibernate_queue_nolock);
	HIBPRINT("   queue_paused(%d) throttled(%d) throttle_timeout(%d) drained(%d) drain_timeout(%d)\n",
	    hibernate_stats.hibernate_queue_paused,
	    hibernate_stats.hibernate_throttled,
	    hibernate_stats.hibernate_throttle_timeout,
	    hibernate_stats.hibernate_drained,
	    hibernate_stats.hibernate_drain_timeout);

	return retval;
}


static void
hibernate_page_list_zero(hibernate_page_list_t *list)
{
	uint32_t             bank;
	hibernate_bitmap_t * bitmap;

	bitmap = &list->bank_bitmap[0];
	for (bank = 0; bank < list->bank_count; bank++) {
		uint32_t last_bit;

		bzero((void *) &bitmap->bitmap[0], bitmap->bitmapwords << 2);
		// set out-of-bound bits at end of bitmap.
		last_bit = ((bitmap->last_page - bitmap->first_page + 1) & 31);
		if (last_bit) {
			bitmap->bitmap[bitmap->bitmapwords - 1] = (0xFFFFFFFF >> last_bit);
		}

		bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
	}
}

static boolean_t
hibernate_consider_discard(vm_page_t m, boolean_t preflight)
{
	vm_object_t object = NULL;
	int                  refmod_state;
	boolean_t            discard = FALSE;

	do{
		if (vm_page_is_private(m)) {
			panic("hibernate_consider_discard: private");
		}

		object = VM_PAGE_OBJECT(m);

		if (!vm_object_lock_try(object)) {
			object = NULL;
			if (!preflight) {
				hibernate_stats.cd_lock_failed++;
			}
			break;
		}
		if (VM_PAGE_WIRED(m)) {
			if (!preflight) {
				hibernate_stats.cd_found_wired++;
			}
			break;
		}
		if (m->vmp_precious) {
			if (!preflight) {
				hibernate_stats.cd_found_precious++;
			}
			break;
		}
		if (m->vmp_busy || !object->alive) {
			/*
			 *	Somebody is playing with this page.
			 */
			if (!preflight) {
				hibernate_stats.cd_found_busy++;
			}
			break;
		}
		if (m->vmp_absent || m->vmp_unusual || VMP_ERROR_GET(m)) {
			/*
			 * If it's unusual in anyway, ignore it
			 */
			if (!preflight) {
				hibernate_stats.cd_found_unusual++;
			}
			break;
		}
		if (m->vmp_cleaning) {
			if (!preflight) {
				hibernate_stats.cd_found_cleaning++;
			}
			break;
		}
		if (m->vmp_laundry) {
			if (!preflight) {
				hibernate_stats.cd_found_laundry++;
			}
			break;
		}
		if (!m->vmp_dirty) {
			refmod_state = pmap_get_refmod(VM_PAGE_GET_PHYS_PAGE(m));

			if (refmod_state & VM_MEM_REFERENCED) {
				m->vmp_reference = TRUE;
			}
			if (refmod_state & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		}

		/*
		 * If it's clean or purgeable we can discard the page on wakeup.
		 */
		discard = (!m->vmp_dirty)
		    || (VM_PURGABLE_VOLATILE == object->purgable)
		    || (VM_PURGABLE_EMPTY == object->purgable);


		if (discard == FALSE) {
			if (!preflight) {
				hibernate_stats.cd_found_dirty++;
			}
		} else if (m->vmp_xpmapped && m->vmp_reference && !object->internal) {
			if (hibernate_stats.cd_found_xpmapped < HIBERNATE_XPMAPPED_LIMIT) {
				if (!preflight) {
					hibernate_stats.cd_found_xpmapped++;
				}
				discard = FALSE;
			} else {
				if (!preflight) {
					hibernate_stats.cd_skipped_xpmapped++;
				}
			}
		}
	}while (FALSE);

	if (object) {
		vm_object_unlock(object);
	}

	return discard;
}


static void
hibernate_discard_page(vm_page_t m)
{
	vm_object_t m_object;

	if (m->vmp_absent || m->vmp_unusual || VMP_ERROR_GET(m)) {
		/*
		 * If it's unusual in anyway, ignore
		 */
		return;
	}

	m_object = VM_PAGE_OBJECT(m);

#if MACH_ASSERT || DEBUG
	if (!vm_object_lock_try(m_object)) {
		panic("hibernate_discard_page(%p) !vm_object_lock_try", m);
	}
#else
	/* No need to lock page queue for token delete, hibernate_vm_unlock()
	 *  makes sure these locks are uncontended before sleep */
#endif /* MACH_ASSERT || DEBUG */

	if (m->vmp_pmapped == TRUE) {
		__unused int refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
	}

	if (m->vmp_laundry) {
		panic("hibernate_discard_page(%p) laundry", m);
	}
	if (vm_page_is_private(m)) {
		panic("hibernate_discard_page(%p) private", m);
	}
	if (vm_page_is_fictitious(m)) {
		panic("hibernate_discard_page(%p) fictitious", m);
	}

	if (VM_PURGABLE_VOLATILE == m_object->purgable) {
		/* object should be on a queue */
		assert((m_object->objq.next != NULL) && (m_object->objq.prev != NULL));
		purgeable_q_t old_queue = vm_purgeable_object_remove(m_object);
		assert(old_queue);
		if (m_object->purgeable_when_ripe) {
			vm_purgeable_token_delete_first(old_queue);
		}
		vm_object_lock_assert_exclusive(m_object);
		VM_OBJECT_SET_PURGABLE(m_object, VM_PURGABLE_EMPTY);

		/*
		 * Purgeable ledgers:  pages of VOLATILE and EMPTY objects are
		 * accounted in the "volatile" ledger, so no change here.
		 * We have to update vm_page_purgeable_count, though, since we're
		 * effectively purging this object.
		 */
		unsigned int delta;
		assert(m_object->resident_page_count >= m_object->wired_page_count);
		delta = (m_object->resident_page_count - m_object->wired_page_count);
		assert(delta > 0);
		counter_add(&vm_page_purgeable_count, -(int64_t)delta);
	}

	vm_page_free(m);

#if MACH_ASSERT || DEBUG
	vm_object_unlock(m_object);
#endif  /* MACH_ASSERT || DEBUG */
}

/*
 *  Grab locks for hibernate_page_list_setall()
 */
void
hibernate_vm_lock_queues(void)
{
	vm_object_lock(compressor_object);
	vm_page_lock_queues();
	vm_free_page_lock();
	lck_mtx_lock(&vm_purgeable_queue_lock);

	if (vm_page_local_q) {
		zpercpu_foreach(lq, vm_page_local_q) {
			VPL_LOCK(&lq->vpl_lock);
		}
	}
}

void
hibernate_vm_unlock_queues(void)
{
	if (vm_page_local_q) {
		zpercpu_foreach(lq, vm_page_local_q) {
			VPL_UNLOCK(&lq->vpl_lock);
		}
	}
	lck_mtx_unlock(&vm_purgeable_queue_lock);
	vm_free_page_unlock();
	vm_page_unlock_queues();
	vm_object_unlock(compressor_object);
}

#if CONFIG_SPTM
static bool
hibernate_sptm_should_force_page_to_wired_pagelist(vm_page_t vmp)
{
	const sptm_paddr_t paddr = ptoa_64(VM_PAGE_GET_PHYS_PAGE(vmp));
	const sptm_frame_type_t frame_type = sptm_get_frame_type(paddr);
	const vm_object_t vmp_objp = VM_PAGE_OBJECT(vmp);

	return frame_type == XNU_USER_JIT || frame_type == XNU_USER_DEBUG ||
	       (frame_type == XNU_USER_EXEC && vmp_objp->internal == TRUE);
}
#endif

/*
 *  Bits zero in the bitmaps => page needs to be saved. All pages default to be saved,
 *  pages known to VM to not need saving are subtracted.
 *  Wired pages to be saved are present in page_list_wired, pageable in page_list.
 */

void
hibernate_page_list_setall(hibernate_page_list_t * page_list,
    hibernate_page_list_t * page_list_wired,
    hibernate_page_list_t * page_list_pal,
    boolean_t preflight,
    boolean_t will_discard,
    uint32_t * pagesOut)
{
	uint64_t start, end, nsec;
	vm_page_t m;
	vm_page_t next;
	__block uint32_t pages = page_list->page_count;
	__block uint32_t count_wire = pages;
	uint32_t count_anonymous = 0, count_throttled = 0, count_compressor = 0;
	uint32_t count_inactive = 0, count_active = 0, count_speculative = 0, count_cleaned = 0;
	uint32_t count_discard_active    = 0;
	uint32_t count_discard_inactive  = 0;
	uint32_t count_retired = 0;
	uint32_t count_discard_cleaned   = 0;
	uint32_t count_discard_purgeable = 0;
	uint32_t count_discard_speculative = 0;
	uint32_t count_discard_vm_struct_pages = 0;
	uint32_t             bank;
	hibernate_bitmap_t * bitmap;
	hibernate_bitmap_t * bitmap_wired;
	boolean_t                    discard_all;
	boolean_t            discard = FALSE;

	HIBLOG("hibernate_page_list_setall(preflight %d) start\n", preflight);

	if (preflight) {
		page_list       = NULL;
		page_list_wired = NULL;
		page_list_pal   = NULL;
		discard_all     = FALSE;
	} else {
		discard_all     = will_discard;
	}

#if MACH_ASSERT || DEBUG
	if (!preflight) {
		assert(hibernate_vm_locks_are_safe());
		vm_page_lock_queues();
		if (vm_page_local_q) {
			zpercpu_foreach(lq, vm_page_local_q) {
				VPL_LOCK(&lq->vpl_lock);
			}
		}
	}
#endif  /* MACH_ASSERT || DEBUG */


	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 8) | DBG_FUNC_START, count_wire, 0, 0, 0, 0);

	clock_get_uptime(&start);

	if (!preflight) {
		hibernate_page_list_zero(page_list);
		hibernate_page_list_zero(page_list_wired);
		hibernate_page_list_zero(page_list_pal);

		hibernate_stats.cd_vm_page_wire_count = vm_page_wire_count;
		hibernate_stats.cd_pages = pages;
	}

	if (vm_page_local_q) {
		zpercpu_foreach_cpu(lid) {
			vm_page_reactivate_local(lid, TRUE, !preflight);
		}
	}

	if (preflight) {
		vm_object_lock(compressor_object);
		vm_page_lock_queues();
		vm_free_page_lock();
	}

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	hibernation_vmqueues_inspection = TRUE;

	__auto_type hib_free_boilerplate = ^(vm_page_t page) {
		assert((page->vmp_q_state == VM_PAGE_ON_FREE_Q) ||
#if XNU_VM_HAS_LOPAGE
	    (page->vmp_q_state == VM_PAGE_ON_FREE_LOPAGE_Q) ||
#endif /* XNU_VM_HAS_LOPAGE */
	    (page->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q));

		pages--;
		count_wire--;

		if (!preflight) {
			hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(page));
			hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(page));

			hibernate_stats.cd_total_free++;

			if (page->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q) {
				hibernate_stats.cd_local_free++;
			}
		}
	};

	if (!preflight) {
		percpu_foreach(vmp_pcpu, vm_page_pcpu) {
			_vm_page_list_foreach(m, vmp_pcpu->free_pages) {
				assert(m->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q);
				hib_free_boilerplate(m);
			}
#if HAS_MTE
			_vm_page_list_foreach(m, vmp_pcpu->free_tagged_pages) {
				assert(m->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q);
				hib_free_boilerplate(m);
			}
			vm_page_queue_iterate(&vmp_pcpu->free_claimed_pages,
			    m, vmp_pageq) {
				assert(m->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q);
				hib_free_boilerplate(m);
			}
#endif /* HAS_MTE */
		}
	}

#if CONFIG_SPTM
	if (vm_pages_free_masks()) {
		uint32_t  bits = vm_pages_free_mask_len() * MAX_COLORS;
		bitmap_t *map  = vm_pages_free_masks_as_bitmap(0);

		for (int bit = bitmap_first(map, bits);
		    bit >= 0; bit = bitmap_next(map, bit)) {
			ppnum_t   pnum = pmap_first_pnum + bit;
			vm_page_t mem  = vm_page_find_canonical(pnum);

			hib_free_boilerplate(mem);
		}
	} else
#endif /* CONFIG_SPTM */
	{
		vm_page_free_queue_foreach(&vm_page_queue_free, hib_free_boilerplate);
	}
#if HAS_MTE
	mteinfo_free_queue_foreach(hib_free_boilerplate);
#endif /* HAS_MTE */
#if XNU_VM_HAS_LOPAGE
	vm_page_free_queue_foreach(&vm_lopage_queue_free, hib_free_boilerplate);
#endif /* XNU_VM_HAS_LOPAGE */

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_throttled);
	while (m && !vm_page_queue_end(&vm_page_queue_throttled, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_THROTTLED_Q);

		next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		discard = FALSE;
		if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode)
		    && hibernate_consider_discard(m, preflight)) {
			if (!preflight) {
				hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
			count_discard_inactive++;
			discard = discard_all;
		} else {
			count_throttled++;
		}
		count_wire--;
		if (!preflight) {
			hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
		}

		if (discard) {
			hibernate_discard_page(m);
		}
		m = next;
	}

	m = (vm_page_t)vm_page_queue_first(&vm_page_queue_anonymous);
	while (m && !vm_page_queue_end(&vm_page_queue_anonymous, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q);
		bool force_to_wired_list = false;       /* Default to NOT forcing page into the wired page list */
#if CONFIG_SPTM
		force_to_wired_list = hibernate_sptm_should_force_page_to_wired_pagelist(m);
#endif
		next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		discard = FALSE;
		if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) &&
		    hibernate_consider_discard(m, preflight)) {
			if (!preflight) {
				hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_inactive++;
			}
			discard = discard_all;
		} else {
			/*
			 * If the page must be force-added to the wired page list, prevent it from appearing
			 * in the unwired page list.
			 */
			if (force_to_wired_list) {
				if (!preflight) {
					hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
				}
			} else {
				count_anonymous++;
			}
		}
		/*
		 * If the page is NOT being forced into the wired page list, remove it from the
		 * wired page list here.
		 */
		if (!force_to_wired_list) {
			count_wire--;
			if (!preflight) {
				hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
		}
		if (discard) {
			hibernate_discard_page(m);
		}
		m = next;
	}

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_cleaned);
	while (m && !vm_page_queue_end(&vm_page_queue_cleaned, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q);

		next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		discard = FALSE;
		if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) &&
		    hibernate_consider_discard(m, preflight)) {
			if (!preflight) {
				hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_cleaned++;
			}
			discard = discard_all;
		} else {
			count_cleaned++;
		}
		count_wire--;
		if (!preflight) {
			hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
		}
		if (discard) {
			hibernate_discard_page(m);
		}
		m = next;
	}

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);
	while (m && !vm_page_queue_end(&vm_page_queue_active, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_ACTIVE_Q);
		bool force_to_wired_list = false;       /* Default to NOT forcing page into the wired page list */
#if CONFIG_SPTM
		force_to_wired_list = hibernate_sptm_should_force_page_to_wired_pagelist(m);
#endif
		next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		discard = FALSE;
		if ((kIOHibernateModeDiscardCleanActive & gIOHibernateMode) &&
		    hibernate_consider_discard(m, preflight)) {
			if (!preflight) {
				hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_active++;
			}
			discard = discard_all;
		} else {
			/*
			 * If the page must be force-added to the wired page list, prevent it from appearing
			 * in the unwired page list.
			 */
			if (force_to_wired_list) {
				if (!preflight) {
					hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
				}
			} else {
				count_active++;
			}
		}
		/*
		 * If the page is NOT being forced into the wired page list, remove it from the
		 * wired page list here.
		 */
		if (!force_to_wired_list) {
			count_wire--;
			if (!preflight) {
				hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
		}
		if (discard) {
			hibernate_discard_page(m);
		}
		m = next;
	}

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);
	while (m && !vm_page_queue_end(&vm_page_queue_inactive, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_EXTERNAL_Q);
		bool force_to_wired_list = false;        /* Default to NOT forcing page into the wired page list */
#if CONFIG_SPTM
		force_to_wired_list = hibernate_sptm_should_force_page_to_wired_pagelist(m);
#endif
		next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		discard = FALSE;
		if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) &&
		    hibernate_consider_discard(m, preflight)) {
			if (!preflight) {
				hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_inactive++;
			}
			discard = discard_all;
		} else {
			/*
			 * If the page must be force-added to the wired page list, prevent it from appearing
			 * in the unwired page list.
			 */
			if (force_to_wired_list) {
				if (!preflight) {
					hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
				}
			} else {
				count_inactive++;
			}
		}
		/*
		 * If the page is NOT being forced into the wired page list, remove it from the
		 * wired page list here.
		 */
		if (!force_to_wired_list) {
			count_wire--;
			if (!preflight) {
				hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
		}
		if (discard) {
			hibernate_discard_page(m);
		}
		m = next;
	}
	/* XXX FBDP TODO: secluded queue */

	for (uint32_t i = 0; i <= vm_page_max_speculative_age_q; i++) {
		m = (vm_page_t) vm_page_queue_first(&vm_page_queue_speculative[i].age_q);
		while (m && !vm_page_queue_end(&vm_page_queue_speculative[i].age_q, (vm_page_queue_entry_t)m)) {
			assertf(m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q,
			    "Bad page: %p (0x%x:0x%x) on queue %d has state: %d (Discard: %d, Preflight: %d)",
			    m, m->vmp_pageq.next, m->vmp_pageq.prev, i, m->vmp_q_state, discard, preflight);

			next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
			discard = FALSE;
			if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) &&
			    hibernate_consider_discard(m, preflight)) {
				if (!preflight) {
					hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
				}
				count_discard_speculative++;
				discard = discard_all;
			} else {
				count_speculative++;
			}
			count_wire--;
			if (!preflight) {
				hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
			}
			if (discard) {
				hibernate_discard_page(m);
			}
			m = next;
		}
	}

	vm_page_queue_iterate(&compressor_object->memq, m, vmp_listq) {
		assert(m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR);

		count_compressor++;
		count_wire--;
		if (!preflight) {
			hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
		}
	}


	if (preflight == FALSE && discard_all == TRUE) {
		KDBG(IOKDBG_CODE(DBG_HIBERNATE, 12) | DBG_FUNC_START);

		HIBLOG("hibernate_teardown started\n");
		count_discard_vm_struct_pages = hibernate_teardown_vm_structs(page_list, page_list_wired);
		HIBLOG("hibernate_teardown completed - discarded %d\n", count_discard_vm_struct_pages);

		pages -= count_discard_vm_struct_pages;
		count_wire -= count_discard_vm_struct_pages;

		hibernate_stats.cd_vm_struct_pages_unneeded = count_discard_vm_struct_pages;

		KDBG(IOKDBG_CODE(DBG_HIBERNATE, 12) | DBG_FUNC_END);
	}

	if (!preflight) {
		// pull wired from hibernate_bitmap
		bitmap = &page_list->bank_bitmap[0];
		bitmap_wired = &page_list_wired->bank_bitmap[0];
		for (bank = 0; bank < page_list->bank_count; bank++) {
			for (uint32_t i = 0; i < bitmap->bitmapwords; i++) {
				bitmap->bitmap[i] = bitmap->bitmap[i] | ~bitmap_wired->bitmap[i];
			}
			bitmap = (hibernate_bitmap_t *)&bitmap->bitmap[bitmap->bitmapwords];
			bitmap_wired = (hibernate_bitmap_t *) &bitmap_wired->bitmap[bitmap_wired->bitmapwords];
		}
	}

	// machine dependent adjustments
	hibernate_page_list_setall_machine(page_list, page_list_wired, preflight, &pages);

	if (!preflight) {
		hibernate_stats.cd_count_wire = count_wire;
		hibernate_stats.cd_discarded = count_discard_active +
		    count_discard_inactive + count_discard_purgeable +
		    count_discard_speculative + count_discard_cleaned +
		    count_discard_vm_struct_pages;
	}

	clock_get_uptime(&end);
	absolutetime_to_nanoseconds(end - start, &nsec);
	HIBLOG("hibernate_page_list_setall time: %qd ms\n", nsec / 1000000ULL);

	HIBLOG("pages %d, wire %d, act %d, inact %d, cleaned %d spec %d, "
	    "zf %d, throt %d, compr %d, xpmapped %d\n"
	    "  %s discard act %d inact %d purgeable %d "
	    "spec %d cleaned %d retired %d\n",
	    pages, count_wire, count_active, count_inactive, count_cleaned, count_speculative,
	    count_anonymous, count_throttled, count_compressor, hibernate_stats.cd_found_xpmapped,
	    discard_all ? "did" : "could",
	    count_discard_active, count_discard_inactive, count_discard_purgeable,
	    count_discard_speculative, count_discard_cleaned, count_retired);

	if (hibernate_stats.cd_skipped_xpmapped) {
		HIBLOG("WARNING: hibernate_page_list_setall skipped %d xpmapped pages\n",
		    hibernate_stats.cd_skipped_xpmapped);
	}

	*pagesOut = pages - count_discard_active - count_discard_inactive -
	    count_discard_purgeable - count_discard_speculative -
	    count_discard_cleaned - count_retired;

	if (preflight && will_discard) {
		*pagesOut -= count_compressor + count_throttled +
		    count_anonymous + count_inactive + count_cleaned +
		    count_speculative + count_active;

		/*
		 * We try to keep max HIBERNATE_XPMAPPED_LIMIT pages around in the hibernation image
		 * even if these are clean and so we need to size the hibernation image accordingly.
		 *
		 * NB: We have to assume all HIBERNATE_XPMAPPED_LIMIT pages might show up because 'dirty'
		 * xpmapped pages aren't distinguishable from other 'dirty' pages in preflight. So we might
		 * only see part of the xpmapped pages if we look at 'cd_found_xpmapped' which solely tracks
		 * clean xpmapped pages.
		 *
		 * Since these pages are all cleaned by the time we are in the post-preflight phase, we might
		 * see a much larger number in 'cd_found_xpmapped' now than we did in the preflight phase
		 */
		*pagesOut +=  HIBERNATE_XPMAPPED_LIMIT;
	}

	hibernation_vmqueues_inspection = FALSE;

#if MACH_ASSERT || DEBUG
	if (!preflight) {
		if (vm_page_local_q) {
			zpercpu_foreach(lq, vm_page_local_q) {
				VPL_UNLOCK(&lq->vpl_lock);
			}
		}
		vm_page_unlock_queues();
	}
#endif  /* MACH_ASSERT || DEBUG */

	if (preflight) {
		vm_free_page_unlock();
		vm_page_unlock_queues();
		vm_object_unlock(compressor_object);
	}

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 8) | DBG_FUNC_END, count_wire, *pagesOut, 0, 0, 0);
}

void
hibernate_page_list_discard(hibernate_page_list_t * page_list)
{
	uint64_t  start, end, nsec;
	vm_page_t m;
	vm_page_t next;
	uint32_t  i;
	uint32_t  count_discard_active    = 0;
	uint32_t  count_discard_inactive  = 0;
	uint32_t  count_discard_purgeable = 0;
	uint32_t  count_discard_cleaned   = 0;
	uint32_t  count_discard_speculative = 0;


#if MACH_ASSERT || DEBUG
	vm_page_lock_queues();
	if (vm_page_local_q) {
		zpercpu_foreach(lq, vm_page_local_q) {
			VPL_LOCK(&lq->vpl_lock);
		}
	}
#endif  /* MACH_ASSERT || DEBUG */

	clock_get_uptime(&start);

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_anonymous);
	while (m && !vm_page_queue_end(&vm_page_queue_anonymous, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q);

		next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m))) {
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_inactive++;
			}
			hibernate_discard_page(m);
		}
		m = next;
	}

	for (i = 0; i <= vm_page_max_speculative_age_q; i++) {
		m = (vm_page_t) vm_page_queue_first(&vm_page_queue_speculative[i].age_q);
		while (m && !vm_page_queue_end(&vm_page_queue_speculative[i].age_q, (vm_page_queue_entry_t)m)) {
			assert(m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q);

			next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
			if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m))) {
				count_discard_speculative++;
				hibernate_discard_page(m);
			}
			m = next;
		}
	}

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);
	while (m && !vm_page_queue_end(&vm_page_queue_inactive, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_EXTERNAL_Q);

		next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m))) {
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_inactive++;
			}
			hibernate_discard_page(m);
		}
		m = next;
	}
	/* XXX FBDP TODO: secluded queue */

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);
	while (m && !vm_page_queue_end(&vm_page_queue_active, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_ACTIVE_Q);

		next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m))) {
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_active++;
			}
			hibernate_discard_page(m);
		}
		m = next;
	}

	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_cleaned);
	while (m && !vm_page_queue_end(&vm_page_queue_cleaned, (vm_page_queue_entry_t)m)) {
		assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q);

		next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->vmp_pageq.next);
		if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m))) {
			if (m->vmp_dirty) {
				count_discard_purgeable++;
			} else {
				count_discard_cleaned++;
			}
			hibernate_discard_page(m);
		}
		m = next;
	}

#if MACH_ASSERT || DEBUG
	if (vm_page_local_q) {
		zpercpu_foreach(lq, vm_page_local_q) {
			VPL_UNLOCK(&lq->vpl_lock);
		}
	}
	vm_page_unlock_queues();
#endif  /* MACH_ASSERT || DEBUG */

	clock_get_uptime(&end);
	absolutetime_to_nanoseconds(end - start, &nsec);
	HIBLOG("hibernate_page_list_discard time: %qd ms, discarded act %d inact %d purgeable %d spec %d cleaned %d\n",
	    nsec / 1000000ULL,
	    count_discard_active, count_discard_inactive, count_discard_purgeable, count_discard_speculative, count_discard_cleaned);
}

boolean_t       hibernate_paddr_map_inited = FALSE;
unsigned int    hibernate_teardown_last_valid_compact_indx = -1;
vm_page_t       hibernate_rebuild_hash_list = NULL;

unsigned int    hibernate_teardown_found_tabled_pages = 0;
unsigned int    hibernate_teardown_found_created_pages = 0;
unsigned int    hibernate_teardown_found_free_pages = 0;
unsigned int    hibernate_teardown_vm_page_free_count;


struct ppnum_mapping {
	struct ppnum_mapping    *ppnm_next;
	ppnum_t                 ppnm_base_paddr;
	unsigned int            ppnm_sindx;
	unsigned int            ppnm_eindx;
};

struct ppnum_mapping    *ppnm_head;
struct ppnum_mapping    *ppnm_last_found = NULL;


void
hibernate_create_paddr_map(void)
{
	unsigned int    i;
	ppnum_t         next_ppnum_in_run = 0;
	struct ppnum_mapping *ppnm = NULL;

	if (hibernate_paddr_map_inited == FALSE) {
		for (i = 0; i < vm_pages_count; i++) {
			if (ppnm) {
				ppnm->ppnm_eindx = i;
			}

			if (ppnm == NULL || VM_PAGE_GET_PHYS_PAGE(vm_page_get(i)) != next_ppnum_in_run) {
				ppnm = zalloc_permanent_type(struct ppnum_mapping);

				ppnm->ppnm_next = ppnm_head;
				ppnm_head = ppnm;

				ppnm->ppnm_sindx = i;
				ppnm->ppnm_base_paddr = VM_PAGE_GET_PHYS_PAGE(vm_page_get(i));
			}
			next_ppnum_in_run = VM_PAGE_GET_PHYS_PAGE(vm_page_get(i)) + 1;
		}
		ppnm->ppnm_eindx = vm_pages_count;

		hibernate_paddr_map_inited = TRUE;
	}
}

static ppnum_t
hibernate_lookup_paddr(unsigned int indx)
{
	struct ppnum_mapping *ppnm = NULL;

	ppnm = ppnm_last_found;

	if (ppnm) {
		if (indx >= ppnm->ppnm_sindx && indx < ppnm->ppnm_eindx) {
			goto done;
		}
	}
	for (ppnm = ppnm_head; ppnm; ppnm = ppnm->ppnm_next) {
		if (indx >= ppnm->ppnm_sindx && indx < ppnm->ppnm_eindx) {
			ppnm_last_found = ppnm;
			break;
		}
	}
	if (ppnm == NULL) {
		panic("hibernate_lookup_paddr of %d failed", indx);
	}
done:
	return ppnm->ppnm_base_paddr + (indx - ppnm->ppnm_sindx);
}


static uint32_t
hibernate_mark_as_unneeded(addr64_t saddr, addr64_t eaddr, hibernate_page_list_t *page_list, hibernate_page_list_t *page_list_wired)
{
	addr64_t        saddr_aligned;
	addr64_t        eaddr_aligned;
	addr64_t        addr;
	ppnum_t         paddr;
	unsigned int    mark_as_unneeded_pages = 0;

	saddr_aligned = (saddr + PAGE_MASK_64) & ~PAGE_MASK_64;
	eaddr_aligned = eaddr & ~PAGE_MASK_64;

	for (addr = saddr_aligned; addr < eaddr_aligned; addr += PAGE_SIZE_64) {
		paddr = pmap_find_phys(kernel_pmap, addr);

		assert(paddr);

		hibernate_page_bitset(page_list, TRUE, paddr);
		hibernate_page_bitset(page_list_wired, TRUE, paddr);

		mark_as_unneeded_pages++;
	}
	return mark_as_unneeded_pages;
}


static void
hibernate_hash_insert_page(vm_page_t mem)
{
	uint32_t        hash_id;
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

	assert(mem->vmp_hashed);
	assert(m_object);
	assert(mem->vmp_offset != (vm_object_offset_t) -1);

	/*
	 *	Insert it into the object_object/offset hash table
	 */
	hash_id = vm_page_hash(m_object, mem->vmp_offset);
	vm_page_hash_insert_locked(&vm_page_buckets[hash_id], mem);
}


static void
hibernate_free_range_flush(vm_page_list_t *list)
{
	vm_page_free_queue_enter_list(*list, VMP_RELEASE_HIBERNATE);
	*list = (vm_page_list_t){ };
}

static void
hibernate_free_range(vm_page_list_t *list, int sindx, int eindx)
{
	for (; sindx < eindx; sindx++) {
		vm_page_t mem  = vm_page_get(sindx);
		ppnum_t   pnum = hibernate_lookup_paddr(sindx);

		vm_page_init(mem, pnum);
#if HAS_MTE
		mem->vmp_using_mte = pmap_is_tagged_page(pnum);
#endif /* HAS_MTE */
		vm_page_list_push(list, mem);

		/* Max batch size of these lists is 255 due to vmp_free_list_result_t */
		if (list->vmpl_count >= UINT8_MAX) {
			hibernate_free_range_flush(list);
		}
	}
}

void
hibernate_rebuild_vm_structs(void)
{
	int             cindx, sindx, eindx;
	vm_page_list_t  list = { };
	vm_page_t       mem, tmem, mem_next;
	AbsoluteTime    startTime, endTime;
	uint64_t        nsec;

	if (!hibernate_rebuild_needed) {
		return;
	}

	KDBG(IOKDBG_CODE(DBG_HIBERNATE, 13) | DBG_FUNC_START);
	HIBLOG("hibernate_rebuild started\n");

	clock_get_uptime(&startTime);

	pal_hib_rebuild_pmap_structs();

	bzero(&vm_page_buckets[0], vm_page_bucket_count * sizeof(vm_page_bucket_t));
	eindx = vm_pages_count;

	/*
	 * Mark all the vm_pages[] that have not been initialized yet as being
	 * transient. This is needed to ensure that buddy page search is corrrect.
	 * Without this random data in these vm_pages[] can trip the buddy search
	 */
	for (int i = hibernate_teardown_last_valid_compact_indx + 1; i < eindx; ++i) {
		vm_page_get(i)->vmp_q_state = VM_PAGE_NOT_ON_Q;
	}

	for (cindx = hibernate_teardown_last_valid_compact_indx; cindx >= 0; cindx--) {
		mem = vm_page_get(cindx);
		assert(mem->vmp_q_state != VM_PAGE_ON_FREE_Q);
		/*
		 * hibernate_teardown_vm_structs leaves the location where
		 * this vm_page_t must be located in "next".
		 */
		tmem = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->vmp_next_m));
		mem->vmp_next_m = VM_PAGE_PACK_PTR(NULL);
		assert(tmem >= mem);

		sindx = (int)(tmem - vm_page_get(0));

		if (mem != tmem) {
			/*
			 * this vm_page_t was moved by hibernate_teardown_vm_structs,
			 * so move it back to its real location
			 */
			*tmem = *mem;
			mem = tmem;
		}
		if (mem->vmp_hashed) {
			hibernate_hash_insert_page(mem);
		}
		/*
		 * the 'hole' between this vm_page_t and the previous
		 * vm_page_t we moved needs to be initialized as
		 * a range of free vm_page_t's
		 */
		hibernate_free_range(&list, sindx + 1, eindx);

		eindx = sindx;
	}
	hibernate_free_range(&list, 0, sindx);
	hibernate_free_range_flush(&list);

	VM_CHECK_MEMORYSTATUS;

	assert(vm_page_free_count == hibernate_teardown_vm_page_free_count);

	/*
	 * process the list of vm_page_t's that were entered in the hash,
	 * but were not located in the vm_pages arrary... these are
	 * vm_page_t's that were created on the fly (i.e. fictitious)
	 */
	for (mem = hibernate_rebuild_hash_list; mem; mem = mem_next) {
		mem_next = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->vmp_next_m));

		mem->vmp_next_m = 0;
		hibernate_hash_insert_page(mem);
	}
	hibernate_rebuild_hash_list = NULL;

	clock_get_uptime(&endTime);
	SUB_ABSOLUTETIME(&endTime, &startTime);
	absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("hibernate_rebuild completed - took %qd msecs\n", nsec / 1000000ULL);

	hibernate_rebuild_needed = false;

	KDBG(IOKDBG_CODE(DBG_HIBERNATE, 13) | DBG_FUNC_END);
}

static uint32_t
hibernate_teardown_vm_structs(hibernate_page_list_t *page_list, hibernate_page_list_t *page_list_wired)
{
	unsigned int    compact_target_indx;
	unsigned int    mark_as_unneeded_pages = 0;
	unsigned int    unneeded_vm_page_bucket_pages = 0;
	unsigned int    unneeded_vm_pages_pages = 0;
	unsigned int    unneeded_pmap_pages = 0;
	addr64_t        start_of_unneeded = 0;
	addr64_t        end_of_unneeded = 0;


	if (hibernate_should_abort()) {
		return 0;
	}

	hibernate_rebuild_needed = true;

	HIBLOG("hibernate_teardown: wired_pages %d, free_pages %d, "
	    "active_pages %d, inactive_pages %d, speculative_pages %d, "
	    "cleaned_pages %d, compressor_pages %d\n",
	    vm_page_wire_count, vm_page_free_count,
	    vm_page_active_count, vm_page_inactive_count, vm_page_speculative_count,
	    vm_page_cleaned_count, compressor_object->resident_page_count);

	for (uint32_t i = 0; i < vm_page_bucket_count; i++) {
		vm_page_bucket_t *bucket = &vm_page_buckets[i];
		vm_page_t mem, mem_next;

		for (mem = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list)); mem != VM_PAGE_NULL; mem = mem_next) {
			assert(mem->vmp_hashed);

			mem_next = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->vmp_next_m));

			if (!vm_page_in_array(mem)) {
				mem->vmp_next_m = VM_PAGE_PACK_PTR(hibernate_rebuild_hash_list);
				hibernate_rebuild_hash_list = mem;
			}
		}
	}
	unneeded_vm_page_bucket_pages = hibernate_mark_as_unneeded((addr64_t)&vm_page_buckets[0],
	    (addr64_t)&vm_page_buckets[vm_page_bucket_count], page_list, page_list_wired);
	mark_as_unneeded_pages += unneeded_vm_page_bucket_pages;

	hibernate_teardown_vm_page_free_count = vm_page_free_count;

	compact_target_indx = 0;

	vm_free_page_lock();

	for (uint32_t i = 0; i < vm_pages_count; i++) {
		vm_page_t         mem   = vm_page_get(i);
		ppnum_t           pnum  = VM_PAGE_GET_PHYS_PAGE(mem);
		vm_memory_class_t class = vm_page_get_memory_class(mem, pnum);

		if (mem->vmp_q_state == VM_PAGE_ON_FREE_Q) {
			vm_page_free_queue_remove(class, mem, pnum,
			    VM_PAGE_ON_FREE_Q);
			hibernate_teardown_found_free_pages++;

			if (vm_page_get(compact_target_indx)->vmp_q_state != VM_PAGE_ON_FREE_Q) {
				compact_target_indx = i;
			}
		} else {
			/*
			 * record this vm_page_t's original location
			 * we need this even if it doesn't get moved
			 * as an indicator to the rebuild function that
			 * we don't have to move it
			 */
			mem->vmp_next_m = VM_PAGE_PACK_PTR(mem);

			if (vm_page_get(compact_target_indx)->vmp_q_state == VM_PAGE_ON_FREE_Q) {
				/*
				 * we've got a hole to fill, so
				 * move this vm_page_t to it's new home
				 */
				*vm_page_get(compact_target_indx) = *mem;
				mem->vmp_q_state = VM_PAGE_ON_FREE_Q;

				hibernate_teardown_last_valid_compact_indx = compact_target_indx;
				compact_target_indx++;
			} else {
				hibernate_teardown_last_valid_compact_indx = i;
			}
		}
	}

	vm_free_page_unlock();

	unneeded_vm_pages_pages = hibernate_mark_as_unneeded(
		(addr64_t)vm_page_get(hibernate_teardown_last_valid_compact_indx + 1),
		(addr64_t)vm_page_get(vm_pages_count - 1),
		page_list, page_list_wired);
	mark_as_unneeded_pages += unneeded_vm_pages_pages;

	pal_hib_teardown_pmap_structs(&start_of_unneeded, &end_of_unneeded);

	if (start_of_unneeded) {
		unneeded_pmap_pages = hibernate_mark_as_unneeded(start_of_unneeded,
		    end_of_unneeded, page_list, page_list_wired);
		mark_as_unneeded_pages += unneeded_pmap_pages;
	}
	HIBLOG("hibernate_teardown: mark_as_unneeded_pages %d, %d, %d\n",
	    unneeded_vm_page_bucket_pages, unneeded_vm_pages_pages, unneeded_pmap_pages);

	return mark_as_unneeded_pages;
}

#endif /* HIBERNATION */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if VM_PAGE_BUCKETS_CHECK
void
vm_page_buckets_check(void)
{
	unsigned int i;
	vm_page_t p;
	unsigned int p_hash;
	vm_page_bucket_t *bucket;
	hw_lck_ticket_t *bucket_lock;

	if (!vm_page_buckets_check_ready) {
		return;
	}

#if HIBERNATION
	if (hibernate_rebuild_needed ||
	    hibernate_rebuild_hash_list) {
		panic("BUCKET_CHECK: hibernation in progress: "
		    "rebuild_needed=%d rebuild_hash_list=%p\n",
		    hibernate_rebuild_needed,
		    hibernate_rebuild_hash_list);
	}
#endif /* HIBERNATION */

#if VM_PAGE_FAKE_BUCKETS
	char *cp;
	for (cp = (char *) vm_page_fake_buckets_start;
	    cp < (char *) vm_page_fake_buckets_end;
	    cp++) {
		if (*cp != 0x5a) {
			panic("BUCKET_CHECK: corruption at %p in fake buckets "
			    "[0x%llx:0x%llx]\n",
			    cp,
			    (uint64_t) vm_page_fake_buckets_start,
			    (uint64_t) vm_page_fake_buckets_end);
		}
	}
#endif /* VM_PAGE_FAKE_BUCKETS */

	for (i = 0; i < vm_page_bucket_count; i++) {
		vm_object_t     p_object;

		bucket = &vm_page_buckets[i];
		if (!bucket->page_list) {
			continue;
		}

		bucket_lock = &vm_page_bucket_locks[i / BUCKETS_PER_LOCK];
		hw_lck_ticket_lock(bucket_lock, &vm_page_lck_grp_bucket);
		p = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list));

		while (p != VM_PAGE_NULL) {
			p_object = VM_PAGE_OBJECT(p);

			if (!p->vmp_hashed) {
				panic("BUCKET_CHECK: page %p (%p,0x%llx) "
				    "hash %d in bucket %d at %p "
				    "is not hashed\n",
				    p, p_object, p->vmp_offset,
				    p_hash, i, bucket);
			}
			p_hash = vm_page_hash(p_object, p->vmp_offset);
			if (p_hash != i) {
				panic("BUCKET_CHECK: corruption in bucket %d "
				    "at %p: page %p object %p offset 0x%llx "
				    "hash %d\n",
				    i, bucket, p, p_object, p->vmp_offset,
				    p_hash);
			}
			p = (vm_page_t)(VM_PAGE_UNPACK_PTR(p->vmp_next_m));
		}
		hw_lck_ticket_unlock(bucket_lock);
	}

//	printf("BUCKET_CHECK: checked buckets\n");
}
#endif /* VM_PAGE_BUCKETS_CHECK */

/*
 * 'vm_fault_enter' will place newly created pages (zero-fill and COW) onto the
 * local queues if they exist... its the only spot in the system where we add pages
 * to those queues...  once on those queues, those pages can only move to one of the
 * global page queues or the free queues... they NEVER move from local q to local q.
 * the 'local' state is stable when vm_page_queues_remove is called since we're behind
 * the global vm_page_queue_lock at this point...  we still need to take the local lock
 * in case this operation is being run on a different CPU then the local queue's identity,
 * but we don't have to worry about the page moving to a global queue or becoming wired
 * while we're grabbing the local lock since those operations would require the global
 * vm_page_queue_lock to be held, and we already own it.
 *
 * this is why its safe to utilze the wire_count field in the vm_page_t as the local_id...
 * 'wired' and local are ALWAYS mutually exclusive conditions.
 */

void
vm_page_queues_remove(vm_page_t mem, boolean_t remove_from_specialq)
{
	boolean_t       was_pageable = TRUE;
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (mem->vmp_q_state == VM_PAGE_NOT_ON_Q) {
		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);
		if (remove_from_specialq == TRUE) {
			vm_page_remove_from_specialq(mem);
		}
		/*if (mem->vmp_on_specialq != VM_PAGE_SPECIAL_Q_EMPTY) {
		 *       assert(mem->vmp_specialq.next != 0);
		 *       assert(mem->vmp_specialq.prev != 0);
		 *  } else {*/
		if (mem->vmp_on_specialq == VM_PAGE_SPECIAL_Q_EMPTY) {
			assert(mem->vmp_specialq.next == 0);
			assert(mem->vmp_specialq.prev == 0);
		}
		return;
	}

	if (mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);
		assert(mem->vmp_specialq.next == 0 &&
		    mem->vmp_specialq.prev == 0 &&
		    mem->vmp_on_specialq == VM_PAGE_SPECIAL_Q_EMPTY);
		return;
	}
	if (VM_PAGE_WIRED(mem)) {
		/*
		 * might put these guys on a list for debugging purposes
		 * if we do, we'll need to remove this assert
		 */
		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);
		assert(mem->vmp_specialq.next == 0 &&
		    mem->vmp_specialq.prev == 0);
		/*
		 * Recall that vmp_on_specialq also means a request to put
		 * it on the special Q. So we don't want to reset that bit
		 * just because a wiring request came in. We might want to
		 * put it on the special queue post-unwiring.
		 *
		 * &&
		 * mem->vmp_on_specialq == VM_PAGE_SPECIAL_Q_EMPTY);
		 */
		return;
	}

	assert(m_object != compressor_object);
	assert(!is_kernel_object(m_object));
	assert(!vm_page_is_fictitious(mem));

	switch (mem->vmp_q_state) {
	case VM_PAGE_ON_ACTIVE_LOCAL_Q:
	{
		struct vpl      *lq;

		lq = zpercpu_get_cpu(vm_page_local_q, mem->vmp_local_id);
		VPL_LOCK(&lq->vpl_lock);
		vm_page_queue_remove(&lq->vpl_queue, mem, vmp_pageq);
		mem->vmp_local_id = 0;
		lq->vpl_count--;
		if (m_object->internal) {
			lq->vpl_internal_count--;
		} else {
			lq->vpl_external_count--;
		}
		VPL_UNLOCK(&lq->vpl_lock);
		was_pageable = FALSE;
		break;
	}
	case VM_PAGE_ON_ACTIVE_Q:
	{
		vm_page_queue_remove(&vm_page_queue_active, mem, vmp_pageq);
		vm_page_active_count--;
		break;
	}

	case VM_PAGE_ON_INACTIVE_INTERNAL_Q:
	{
		assert(m_object->internal == TRUE);

		vm_page_inactive_count--;
		vm_page_queue_remove(&vm_page_queue_anonymous, mem, vmp_pageq);
		vm_page_anonymous_count--;

		vm_purgeable_q_advance_all();
		vm_page_balance_inactive(3);
		break;
	}

	case VM_PAGE_ON_INACTIVE_EXTERNAL_Q:
	{
		assert(m_object->internal == FALSE);

		vm_page_inactive_count--;
		vm_page_queue_remove(&vm_page_queue_inactive, mem, vmp_pageq);
		vm_purgeable_q_advance_all();
		vm_page_balance_inactive(3);
		break;
	}

	case VM_PAGE_ON_INACTIVE_CLEANED_Q:
	{
		assert(m_object->internal == FALSE);

		vm_page_inactive_count--;
		vm_page_queue_remove(&vm_page_queue_cleaned, mem, vmp_pageq);
		vm_page_cleaned_count--;
		vm_page_balance_inactive(3);
		break;
	}

	case VM_PAGE_ON_THROTTLED_Q:
	{
		assert(m_object->internal == TRUE);

		vm_page_queue_remove(&vm_page_queue_throttled, mem, vmp_pageq);
		vm_page_throttled_count--;
		was_pageable = FALSE;
		break;
	}

	case VM_PAGE_ON_SPECULATIVE_Q:
	{
		assert(m_object->internal == FALSE);

		vm_page_remque(&mem->vmp_pageq);
		vm_page_speculative_count--;
		vm_page_balance_inactive(3);
		break;
	}

#if CONFIG_SECLUDED_MEMORY
	case VM_PAGE_ON_SECLUDED_Q:
	{
		vm_page_queue_remove(&vm_page_queue_secluded, mem, vmp_pageq);
		vm_page_secluded_count--;
		VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();
		if (m_object == VM_OBJECT_NULL) {
			vm_page_secluded_count_free--;
			was_pageable = FALSE;
		} else {
			assert(!m_object->internal);
			vm_page_secluded_count_inuse--;
			was_pageable = FALSE;
//			was_pageable = TRUE;
		}
		break;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	default:
	{
		/*
		 *	if (mem->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q)
		 *              NOTE: vm_page_queues_remove does not deal with removing pages from the pageout queue...
		 *              the caller is responsible for determing if the page is on that queue, and if so, must
		 *              either first remove it (it needs both the page queues lock and the object lock to do
		 *              this via vm_pageout_steal_laundry), or avoid the call to vm_page_queues_remove
		 *
		 *	we also don't expect to encounter VM_PAGE_ON_FREE_Q, VM_PAGE_ON_FREE_LOCAL_Q, VM_PAGE_ON_FREE_LOPAGE_Q
		 *	or any of the undefined states
		 */
		panic("vm_page_queues_remove - bad page q_state (%p, %d)", mem, mem->vmp_q_state);
		break;
	}
	}
	VM_PAGE_ZERO_PAGEQ_ENTRY(mem);
	mem->vmp_q_state = VM_PAGE_NOT_ON_Q;

	if (remove_from_specialq == TRUE) {
		vm_page_remove_from_specialq(mem);
	}
	if (was_pageable) {
		if (m_object->internal) {
			vm_page_pageable_internal_count--;
		} else {
			vm_page_pageable_external_count--;
		}
	}
}

void
vm_page_remove_internal(vm_page_t page)
{
	vm_object_t __object = VM_PAGE_OBJECT(page);
	if (page == __object->memq_hint) {
		vm_page_t       __new_hint;
		vm_page_queue_entry_t   __qe;
		__qe = (vm_page_queue_entry_t)vm_page_queue_next(&page->vmp_listq);
		if (vm_page_queue_end(&__object->memq, __qe)) {
			__qe = (vm_page_queue_entry_t)vm_page_queue_prev(&page->vmp_listq);
			if (vm_page_queue_end(&__object->memq, __qe)) {
				__qe = NULL;
			}
		}
		__new_hint = (vm_page_t)((uintptr_t) __qe);
		__object->memq_hint = __new_hint;
	}
	vm_page_queue_remove(&__object->memq, page, vmp_listq);
#if CONFIG_SECLUDED_MEMORY
	if (__object->eligible_for_secluded) {
		vm_page_secluded.eligible_for_secluded--;
	}
#endif /* CONFIG_SECLUDED_MEMORY */
#if HAS_MTE
	assert_mte_vmo_matches_vmp(__object, page);
#endif /* HAS_MTE */
}

void
vm_page_enqueue_inactive(vm_page_t mem, boolean_t first)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(!vm_page_is_fictitious(mem));
	assert(!mem->vmp_laundry);
	assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);
	vm_page_check_pageable_safe(mem);

	if (m_object->internal) {
		mem->vmp_q_state = VM_PAGE_ON_INACTIVE_INTERNAL_Q;

		if (first == TRUE) {
			vm_page_queue_enter_first(&vm_page_queue_anonymous, mem, vmp_pageq);
		} else {
			vm_page_queue_enter(&vm_page_queue_anonymous, mem, vmp_pageq);
		}

		vm_page_anonymous_count++;
		vm_page_pageable_internal_count++;
	} else {
		mem->vmp_q_state = VM_PAGE_ON_INACTIVE_EXTERNAL_Q;

		if (first == TRUE) {
			vm_page_queue_enter_first(&vm_page_queue_inactive, mem, vmp_pageq);
		} else {
			vm_page_queue_enter(&vm_page_queue_inactive, mem, vmp_pageq);
		}

		vm_page_pageable_external_count++;
	}
	vm_page_inactive_count++;
	token_new_pagecount++;

	vm_page_add_to_specialq(mem, FALSE);
}

void
vm_page_enqueue_active(vm_page_t mem, boolean_t first)
{
	vm_object_t     m_object;

	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(!vm_page_is_fictitious(mem));
	assert(!mem->vmp_laundry);
	assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);
	vm_page_check_pageable_safe(mem);

	mem->vmp_q_state = VM_PAGE_ON_ACTIVE_Q;
	if (first == TRUE) {
		vm_page_queue_enter_first(&vm_page_queue_active, mem, vmp_pageq);
	} else {
		vm_page_queue_enter(&vm_page_queue_active, mem, vmp_pageq);
	}
	vm_page_active_count++;

	if (m_object->internal) {
		vm_page_pageable_internal_count++;
	} else {
		vm_page_pageable_external_count++;
	}

	vm_page_add_to_specialq(mem, FALSE);
	vm_page_balance_inactive(3);
}

/*
 * Pages from special kernel objects shouldn't
 * be placed on pageable queues.
 */
void
vm_page_check_pageable_safe(vm_page_t page)
{
	vm_object_t     page_object;

	page_object = VM_PAGE_OBJECT(page);

	if (is_kernel_object(page_object)) {
		panic("vm_page_check_pageable_safe: trying to add page"
		    "from a kernel object to pageable queue");
	}

	if (page_object == compressor_object) {
		panic("vm_page_check_pageable_safe: trying to add page"
		    "from compressor object (%p) to pageable queue", compressor_object);
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* wired page diagnose
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <libkern/OSKextLibPrivate.h>

#define KA_SIZE(namelen, subtotalscount)        \
	(sizeof(struct vm_allocation_site) + (namelen) + 1 + ((subtotalscount) * sizeof(struct vm_allocation_total)))

#define KA_NAME(alloc)  \
	((char *)(&(alloc)->subtotals[(alloc->subtotalscount)]))

#define KA_NAME_LEN(alloc)      \
    (VM_TAG_NAME_LEN_MAX & (alloc->flags >> VM_TAG_NAME_LEN_SHIFT))

vm_tag_t
vm_tag_bt(void)
{
	uintptr_t* frameptr;
	uintptr_t* frameptr_next;
	uintptr_t retaddr;
	uintptr_t kstackb, kstackt;
	const vm_allocation_site_t * site;
	thread_t cthread;
	kern_allocation_name_t name;

	cthread = current_thread();
	if (__improbable(cthread == NULL)) {
		return VM_KERN_MEMORY_OSFMK;
	}

	if ((name = thread_get_kernel_state(cthread)->allocation_name)) {
		if (!name->tag) {
			vm_tag_alloc(name);
		}
		return name->tag;
	}

	kstackb = cthread->kernel_stack;
	kstackt = kstackb + kernel_stack_size;

	/* Load stack frame pointer (EBP on x86) into frameptr */
	frameptr = __builtin_frame_address(0);
	site = NULL;
	while (frameptr != NULL) {
		/* Verify thread stack bounds */
		if (((uintptr_t)(frameptr + 2) > kstackt) || ((uintptr_t)frameptr < kstackb)) {
			break;
		}

		/* Next frame pointer is pointed to by the previous one */
		frameptr_next = (uintptr_t*) *frameptr;
#if defined(HAS_APPLE_PAC)
		frameptr_next = ptrauth_strip(frameptr_next, ptrauth_key_frame_pointer);
#endif

		/* Pull return address from one spot above the frame pointer */
		retaddr = *(frameptr + 1);

#if defined(HAS_APPLE_PAC)
		retaddr = (uintptr_t) ptrauth_strip((void *)retaddr, ptrauth_key_return_address);
#endif

		if (((retaddr < vm_kernel_builtinkmod_text_end) && (retaddr >= vm_kernel_builtinkmod_text))
		    || !kernel_text_contains(retaddr)) {
			site = OSKextGetAllocationSiteForCaller(retaddr);
			break;
		}
		frameptr = frameptr_next;
	}

	if (site) {
		return site->tag;
	}

#if MACH_ASSERT
	/*
	 * Kernel tests appear here as unrecognized call sites and would get
	 * no memory tag. Give them a default tag to prevent panics later.
	 */
	if (thread_get_test_option(test_option_vm_prevent_wire_tag_panic)) {
		return VM_KERN_MEMORY_OSFMK;
	}
#endif

	return VM_KERN_MEMORY_NONE;
}

static uint64_t free_tag_bits[VM_MAX_TAG_VALUE / 64];

void
vm_tag_alloc_locked(vm_allocation_site_t * site, vm_allocation_site_t ** releasesiteP)
{
	vm_tag_t tag;
	uint64_t avail;
	uint32_t idx;
	vm_allocation_site_t * prev;

	if (site->tag) {
		return;
	}

	idx = 0;
	while (TRUE) {
		avail = free_tag_bits[idx];
		if (avail) {
			tag = (vm_tag_t)__builtin_clzll(avail);
			avail &= ~(1ULL << (63 - tag));
			free_tag_bits[idx] = avail;
			tag += (idx << 6);
			break;
		}
		idx++;
		if (idx >= ARRAY_COUNT(free_tag_bits)) {
			for (idx = 0; idx < ARRAY_COUNT(vm_allocation_sites); idx++) {
				prev = vm_allocation_sites[idx];
				if (!prev) {
					continue;
				}
				if (!KA_NAME_LEN(prev)) {
					continue;
				}
				if (!prev->tag) {
					continue;
				}
				if (prev->total) {
					continue;
				}
				if (1 != prev->refcount) {
					continue;
				}

				assert(idx == prev->tag);
				tag = (vm_tag_t)idx;
				prev->tag = VM_KERN_MEMORY_NONE;
				*releasesiteP = prev;
				break;
			}
			if (idx >= ARRAY_COUNT(vm_allocation_sites)) {
				tag = VM_KERN_MEMORY_ANY;
			}
			break;
		}
	}
	site->tag = tag;

	OSAddAtomic16(1, &site->refcount);

	if (VM_KERN_MEMORY_ANY != tag) {
		vm_allocation_sites[tag] = site;
	}

	if (tag > vm_allocation_tag_highest) {
		vm_allocation_tag_highest = tag;
	}
}

static void
vm_tag_free_locked(vm_tag_t tag)
{
	uint64_t avail;
	uint32_t idx;
	uint64_t bit;

	if (VM_KERN_MEMORY_ANY == tag) {
		return;
	}

	idx = (tag >> 6);
	avail = free_tag_bits[idx];
	tag &= 63;
	bit = (1ULL << (63 - tag));
	assert(!(avail & bit));
	free_tag_bits[idx] = (avail | bit);
}

static void
vm_tag_init(void)
{
	vm_tag_t tag;
	for (tag = VM_KERN_MEMORY_FIRST_DYNAMIC; tag < VM_KERN_MEMORY_ANY; tag++) {
		vm_tag_free_locked(tag);
	}

	for (tag = VM_KERN_MEMORY_ANY + 1; tag < VM_MAX_TAG_VALUE; tag++) {
		vm_tag_free_locked(tag);
	}
}

vm_tag_t
vm_tag_alloc(vm_allocation_site_t * site)
{
	vm_allocation_site_t * releasesite;

	if (!site->tag) {
		releasesite = NULL;
		lck_ticket_lock(&vm_allocation_sites_lock, &vm_page_lck_grp_bucket);
		vm_tag_alloc_locked(site, &releasesite);
		lck_ticket_unlock(&vm_allocation_sites_lock);
		if (releasesite) {
			kern_allocation_name_release(releasesite);
		}
	}

	return site->tag;
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */
#define VM_KERN_MEMORY_ELEM(name) [VM_KERN_MEMORY_##name] = "VM_KERN_MEMORY_" #name
const char *vm_kern_memory_names[] = {
	VM_KERN_MEMORY_ELEM(NONE),
	VM_KERN_MEMORY_ELEM(OSFMK),
	VM_KERN_MEMORY_ELEM(BSD),
	VM_KERN_MEMORY_ELEM(IOKIT),
	VM_KERN_MEMORY_ELEM(LIBKERN),
	VM_KERN_MEMORY_ELEM(OSKEXT),
	VM_KERN_MEMORY_ELEM(KEXT),
	VM_KERN_MEMORY_ELEM(IPC),
	VM_KERN_MEMORY_ELEM(STACK),
	VM_KERN_MEMORY_ELEM(CPU),
	VM_KERN_MEMORY_ELEM(PMAP),
	VM_KERN_MEMORY_ELEM(PTE),
	VM_KERN_MEMORY_ELEM(ZONE),
	VM_KERN_MEMORY_ELEM(KALLOC),
	VM_KERN_MEMORY_ELEM(COMPRESSOR),
	VM_KERN_MEMORY_ELEM(COMPRESSED_DATA),
	VM_KERN_MEMORY_ELEM(PHANTOM_CACHE),
	VM_KERN_MEMORY_ELEM(WAITQ),
	VM_KERN_MEMORY_ELEM(DIAG),
	VM_KERN_MEMORY_ELEM(LOG),
	VM_KERN_MEMORY_ELEM(FILE),
	VM_KERN_MEMORY_ELEM(MBUF),
	VM_KERN_MEMORY_ELEM(UBC),
	VM_KERN_MEMORY_ELEM(SECURITY),
	VM_KERN_MEMORY_ELEM(MLOCK),
	VM_KERN_MEMORY_ELEM(REASON),
	VM_KERN_MEMORY_ELEM(SKYWALK),
	VM_KERN_MEMORY_ELEM(LTABLE),
	VM_KERN_MEMORY_ELEM(HV),
	VM_KERN_MEMORY_ELEM(KALLOC_DATA),
	VM_KERN_MEMORY_ELEM(RETIRED),
	VM_KERN_MEMORY_ELEM(KALLOC_TYPE),
	VM_KERN_MEMORY_ELEM(TRIAGE),
	VM_KERN_MEMORY_ELEM(RECOUNT),
	VM_KERN_MEMORY_ELEM(MTAG),
	VM_KERN_MEMORY_ELEM(EXCLAVES),
	VM_KERN_MEMORY_ELEM(EXCLAVES_SHARED),
	VM_KERN_MEMORY_ELEM(KALLOC_SHARED),
	VM_KERN_MEMORY_ELEM(CPUTRACE),
};

_Static_assert(ARRAY_SIZE(vm_kern_memory_names) == VM_KERN_MEMORY_FIRST_DYNAMIC,
    "vm_kern_memory_names must map all counter tags");

#define VM_KERN_COUNT_ELEM(name) [VM_KERN_COUNT_##name] = "VM_KERN_COUNT_" #name
const char *vm_kern_count_names[] = {
	VM_KERN_COUNT_ELEM(MANAGED),
	VM_KERN_COUNT_ELEM(RESERVED),
	VM_KERN_COUNT_ELEM(WIRED),
	VM_KERN_COUNT_ELEM(WIRED_MANAGED),
	VM_KERN_COUNT_ELEM(STOLEN),
	VM_KERN_COUNT_ELEM(LOPAGE),
	VM_KERN_COUNT_ELEM(MAP_KERNEL),
	VM_KERN_COUNT_ELEM(MAP_ZONE),
	VM_KERN_COUNT_ELEM(MAP_KALLOC_LARGE),
	VM_KERN_COUNT_ELEM(WIRED_BOOT),
	VM_KERN_COUNT_ELEM(BOOT_STOLEN),
	VM_KERN_COUNT_ELEM(WIRED_STATIC_KERNELCACHE),
	VM_KERN_COUNT_ELEM(MAP_KALLOC_LARGE_DATA),
	VM_KERN_COUNT_ELEM(MAP_KERNEL_DATA),
	VM_KERN_COUNT_ELEM(EXCLAVES_CARVEOUT),
};

#if VM_BTLOG_TAGS
#define VM_KERN_MEMORY_STR_MAX_LEN (32)
TUNABLE_STR(vmtaglog, VM_KERN_MEMORY_STR_MAX_LEN, "vmtaglog", "");
#define VM_TAG_BTLOG_SIZE (16u << 10)

btlog_t vmtaglog_btlog;
vm_tag_t vmtaglog_tag;

static void
vm_tag_log(vm_object_t object, int64_t delta, void *fp)
{
	if (is_kernel_object(object)) {
		/* kernel object backtraces are tracked in vm entries */
		return;
	}
	if (delta > 0) {
		btref_t ref = btref_get(fp, BTREF_GET_NOWAIT);
		btlog_record(vmtaglog_btlog, object, 0, ref);
	} else if (object->wired_page_count == 0) {
		btlog_erase(vmtaglog_btlog, object);
	}
}

_Static_assert(ARRAY_SIZE(vm_kern_count_names) == VM_KERN_COUNTER_COUNT,
    "vm_kern_count_names must map all counter tags");

static vm_tag_t
vm_tag_str_to_idx(char tagstr[VM_KERN_MEMORY_STR_MAX_LEN])
{
	for (vm_tag_t i = VM_KERN_MEMORY_OSFMK; i < ARRAY_SIZE(vm_kern_memory_names); i++) {
		if (!strncmp(vm_kern_memory_names[i], tagstr, VM_KERN_MEMORY_STR_MAX_LEN)) {
			return i;
		}
	}

	if (!strncmp("dynamic", tagstr, VM_KERN_MEMORY_STR_MAX_LEN)) {
		return VM_KERN_MEMORY_FIRST_DYNAMIC;
	}

	if (!strncmp("any", tagstr, VM_KERN_MEMORY_STR_MAX_LEN)) {
		return VM_KERN_MEMORY_ANY;
	}

	printf("Unable to find vm tag %s for btlog\n", tagstr);
	return VM_KERN_MEMORY_NONE;
}

__startup_func
static void
vm_btlog_init(void)
{
	vmtaglog_tag = vm_tag_str_to_idx(vmtaglog);

	if (vmtaglog_tag != VM_KERN_MEMORY_NONE) {
		vmtaglog_btlog = btlog_create(BTLOG_HASH, VM_TAG_BTLOG_SIZE, 0);
	}
}
STARTUP(ZALLOC, STARTUP_RANK_FIRST, vm_btlog_init);
#endif /* VM_BTLOG_TAGS */

void
vm_tag_update_size(vm_tag_t tag, int64_t delta, vm_object_t object)
{
	assert(VM_KERN_MEMORY_NONE != tag && tag < VM_MAX_TAG_VALUE);

	kern_allocation_update_size(vm_allocation_sites[tag], delta, object);
}

uint64_t
vm_tag_get_size(vm_tag_t tag)
{
	vm_allocation_site_t *allocation;

	assert(VM_KERN_MEMORY_NONE != tag && tag < VM_MAX_TAG_VALUE);

	allocation = vm_allocation_sites[tag];
	return allocation ? os_atomic_load(&allocation->total, relaxed) : 0;
}

void
kern_allocation_update_size(kern_allocation_name_t allocation, int64_t delta, __unused vm_object_t object)
{
	uint64_t value;

	value = os_atomic_add(&allocation->total, delta, relaxed);
	if (delta < 0) {
		assertf(value + (uint64_t)-delta > value,
		    "tag %d, site %p", allocation->tag, allocation);
	}

#if DEBUG || DEVELOPMENT
	/* release to publish the new total */
	os_atomic_max(&allocation->peak, value, release);
#endif /* DEBUG || DEVELOPMENT */

	if (value == (uint64_t)delta && !allocation->tag) {
		vm_tag_alloc(allocation);
	}

#if VM_BTLOG_TAGS
	if (vmtaglog_matches(allocation->tag) && object) {
		vm_tag_log(object, delta, __builtin_frame_address(0));
	}
#endif /* VM_BTLOG_TAGS */
}

#if DEBUG || DEVELOPMENT

void
vm_tag_reset_all_peaks(void)
{
	vm_log("resetting peak size for all kernel tags\n");
	for (vm_tag_t tag = 0; tag <= vm_allocation_tag_highest; tag++) {
		vm_tag_reset_peak(tag);
	}
}

kern_return_t
vm_tag_reset_peak(vm_tag_t tag)
{
	if (tag > vm_allocation_tag_highest) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_allocation_site_t *site = vm_allocation_sites[tag];
	vm_log_info("resetting peak size for kernel tag %s\n",
	    KA_NAME(site));

	uint64_t new_peak = os_atomic_load(&site->total, relaxed);
	/* acquire updates to the total */
	os_atomic_min(&site->peak, new_peak, acquire);

	return KERN_SUCCESS;
}

#endif /* DEBUG || DEVELOPMENT */

#if VM_TAG_SIZECLASSES

void
vm_allocation_zones_init(void)
{
	vm_offset_t   addr;
	vm_size_t     size;

	const vm_tag_t early_tags[] = {
		VM_KERN_MEMORY_DIAG,
		VM_KERN_MEMORY_KALLOC,
		VM_KERN_MEMORY_KALLOC_DATA,
		VM_KERN_MEMORY_KALLOC_SHARED,
		VM_KERN_MEMORY_KALLOC_TYPE,
		VM_KERN_MEMORY_LIBKERN,
		VM_KERN_MEMORY_OSFMK,
		VM_KERN_MEMORY_RECOUNT,
	};

	size = VM_MAX_TAG_VALUE * sizeof(vm_allocation_zone_total_t * *)
	    + ARRAY_COUNT(early_tags) * VM_TAG_SIZECLASSES * sizeof(vm_allocation_zone_total_t);

	kmem_alloc(kernel_map, &addr, round_page(size),
	    KMA_NOFAIL | KMA_KOBJECT | KMA_ZERO | KMA_PERMANENT,
	    VM_KERN_MEMORY_DIAG);

	vm_allocation_zone_totals = (vm_allocation_zone_total_t **) addr;
	addr += VM_MAX_TAG_VALUE * sizeof(vm_allocation_zone_total_t * *);

	// prepopulate early tag ranges so allocations
	// in vm_tag_update_zone_size() and early boot won't recurse
	for (size_t i = 0; i < ARRAY_COUNT(early_tags); i++) {
		vm_allocation_zone_totals[early_tags[i]] = (vm_allocation_zone_total_t *)addr;
		addr += VM_TAG_SIZECLASSES * sizeof(vm_allocation_zone_total_t);
	}
}

__attribute__((noinline))
static vm_tag_t
vm_tag_zone_stats_alloc(vm_tag_t tag, zalloc_flags_t flags)
{
	vm_allocation_zone_total_t *stats;
	vm_size_t size = sizeof(*stats) * VM_TAG_SIZECLASSES;

	flags = Z_VM_TAG(Z_ZERO | flags, VM_KERN_MEMORY_DIAG);
	stats = kalloc_data(size, flags);
	if (!stats) {
		return VM_KERN_MEMORY_NONE;
	}
	if (!os_atomic_cmpxchg(&vm_allocation_zone_totals[tag], NULL, stats, release)) {
		kfree_data(stats, size);
	}
	return tag;
}

vm_tag_t
vm_tag_will_update_zone(vm_tag_t tag, uint32_t zflags)
{
	assert(VM_KERN_MEMORY_NONE != tag);
	assert(tag < VM_MAX_TAG_VALUE);

	if (__probable(vm_allocation_zone_totals[tag])) {
		return tag;
	}
	return vm_tag_zone_stats_alloc(tag, zflags);
}

void
vm_tag_update_zone_size(vm_tag_t tag, uint32_t zidx, long delta)
{
	vm_allocation_zone_total_t *stats;
	vm_size_t value;

	assert(VM_KERN_MEMORY_NONE != tag);
	assert(tag < VM_MAX_TAG_VALUE);

	if (zidx >= VM_TAG_SIZECLASSES) {
		return;
	}

	stats = vm_allocation_zone_totals[tag];
	assert(stats);
	stats += zidx;

	value = os_atomic_add(&stats->vazt_total, delta, relaxed);
	if (delta < 0) {
		assertf((long)value >= 0, "zidx %d, tag %d, %p", zidx, tag, stats);
		return;
	} else if (os_atomic_load(&stats->vazt_peak, relaxed) < value) {
		os_atomic_max(&stats->vazt_peak, value, relaxed);
	}
}

#endif /* VM_TAG_SIZECLASSES */

void
kern_allocation_update_subtotal(kern_allocation_name_t allocation, vm_tag_t subtag, int64_t delta)
{
	kern_allocation_name_t other;
	struct vm_allocation_total * total;
	uint32_t subidx;

	assert(VM_KERN_MEMORY_NONE != subtag);
	lck_ticket_lock(&vm_allocation_sites_lock, &vm_page_lck_grp_bucket);
	for (subidx = 0; subidx < allocation->subtotalscount; subidx++) {
		total = &allocation->subtotals[subidx];
		if (subtag == total->tag) {
			break;
		}
	}
	if (subidx >= allocation->subtotalscount) {
		for (subidx = 0; subidx < allocation->subtotalscount; subidx++) {
			total = &allocation->subtotals[subidx];
			if ((VM_KERN_MEMORY_NONE == total->tag)
			    || !total->total) {
				total->tag = (vm_tag_t)subtag;
				break;
			}
		}
	}
	assert(subidx < allocation->subtotalscount);
	if (subidx >= allocation->subtotalscount) {
		lck_ticket_unlock(&vm_allocation_sites_lock);
		return;
	}
	if (delta < 0) {
		assertf(total->total >= ((uint64_t)-delta), "name %p", allocation);
	}
	OSAddAtomic64(delta, &total->total);
	lck_ticket_unlock(&vm_allocation_sites_lock);

	other = vm_allocation_sites[subtag];
	assert(other);
	if (delta < 0) {
		assertf(other->mapped >= ((uint64_t)-delta), "other %p", other);
	}
	OSAddAtomic64(delta, &other->mapped);
}

const char *
kern_allocation_get_name(kern_allocation_name_t allocation)
{
	return KA_NAME(allocation);
}

kern_allocation_name_t
kern_allocation_name_allocate(const char * name, uint16_t subtotalscount)
{
	kern_allocation_name_t allocation;
	uint16_t namelen;

	namelen = (uint16_t)strnlen(name, MACH_MEMORY_INFO_NAME_MAX_LEN - 1);

	allocation = kalloc_data(KA_SIZE(namelen, subtotalscount), Z_WAITOK | Z_ZERO);
	allocation->refcount       = 1;
	allocation->subtotalscount = subtotalscount;
	allocation->flags          = (uint16_t)(namelen << VM_TAG_NAME_LEN_SHIFT);
	strlcpy(KA_NAME(allocation), name, namelen + 1);

	vm_tag_alloc(allocation);
	return allocation;
}

void
kern_allocation_name_release(kern_allocation_name_t allocation)
{
	assert(allocation->refcount > 0);
	if (1 == OSAddAtomic16(-1, &allocation->refcount)) {
		kfree_data(allocation,
		    KA_SIZE(KA_NAME_LEN(allocation), allocation->subtotalscount));
	}
}

#if !VM_TAG_ACTIVE_UPDATE
static void
vm_page_count_object(mach_memory_info_t * info, unsigned int __unused num_info, vm_object_t object)
{
	if (!object->wired_page_count) {
		return;
	}
	if (!is_kernel_object(object)) {
		assert(object->wire_tag < num_info);
		info[object->wire_tag].size += ptoa_64(object->wired_page_count);
	}
}

typedef void (*vm_page_iterate_proc)(mach_memory_info_t * info,
    unsigned int num_info, vm_object_t object);

static void
vm_page_iterate_purgeable_objects(mach_memory_info_t * info, unsigned int num_info,
    vm_page_iterate_proc proc, purgeable_q_t queue,
    int group)
{
	vm_object_t object;

	for (object = (vm_object_t) queue_first(&queue->objq[group]);
	    !queue_end(&queue->objq[group], (queue_entry_t) object);
	    object = (vm_object_t) queue_next(&object->objq)) {
		proc(info, num_info, object);
	}
}

static void
vm_page_iterate_objects(mach_memory_info_t * info, unsigned int num_info,
    vm_page_iterate_proc proc)
{
	vm_object_t     object;

	lck_spin_lock_grp(&vm_objects_wired_lock, &vm_page_lck_grp_bucket);
	queue_iterate(&vm_objects_wired,
	    object,
	    vm_object_t,
	    wired_objq)
	{
		proc(info, num_info, object);
	}
	lck_spin_unlock(&vm_objects_wired_lock);
}
#endif /* ! VM_TAG_ACTIVE_UPDATE */

static uint64_t
process_account(mach_memory_info_t * info, unsigned int num_info,
    uint64_t zones_collectable_bytes, bool redact_info __unused)
{
	size_t                 namelen;
	unsigned int           idx, count, nextinfo;
	vm_allocation_site_t * site;
	lck_ticket_lock(&vm_allocation_sites_lock, &vm_page_lck_grp_bucket);

	for (idx = 0; idx <= vm_allocation_tag_highest; idx++) {
		site = vm_allocation_sites[idx];
		if (!site) {
			continue;
		}
		info[idx].mapped = site->mapped;
		info[idx].tag    = site->tag;
		info[idx].size   = site->total;
#if DEBUG || DEVELOPMENT
		info[idx].peak   = site->peak;
#endif /* DEBUG || DEVELOPMENT */
		info[idx].flags |= VM_KERN_SITE_WIRED;
		if (idx < VM_KERN_MEMORY_FIRST_DYNAMIC) {
			info[idx].site   = idx;
			info[idx].flags |= VM_KERN_SITE_TAG;
			if (VM_KERN_MEMORY_ZONE == idx) {
				info[idx].flags |= VM_KERN_SITE_HIDE;
				info[idx].flags &= ~VM_KERN_SITE_WIRED;
				info[idx].collectable_bytes = zones_collectable_bytes;
			}
			info[idx].flags |= VM_KERN_SITE_NAMED;
			strlcpy(info[idx].name, vm_kern_memory_names[idx], MACH_MEMORY_INFO_NAME_MAX_LEN);
		} else if ((namelen = (VM_TAG_NAME_LEN_MAX & (site->flags >> VM_TAG_NAME_LEN_SHIFT)))) {
			info[idx].site   = 0;
			info[idx].flags |= VM_KERN_SITE_NAMED;
			if (namelen > sizeof(info[idx].name)) {
				namelen = sizeof(info[idx].name);
			}
			strncpy(&info[idx].name[0], KA_NAME(site), namelen);
		} else if (VM_TAG_KMOD & site->flags) {
			info[idx].site   = OSKextGetKmodIDForSite(site, NULL, 0);
			info[idx].flags |= VM_KERN_SITE_KMOD;
		} else {
			info[idx].site   = VM_KERNEL_UNSLIDE(site);
			info[idx].flags |= VM_KERN_SITE_KERNEL;
		}
	}

	nextinfo = (vm_allocation_tag_highest + 1);
	count    = nextinfo;
	if (count >= num_info) {
		count = num_info;
	}

	for (idx = 0; idx < count; idx++) {
		site = vm_allocation_sites[idx];
		if (!site) {
			continue;
		}
#if VM_TAG_SIZECLASSES
		vm_allocation_zone_total_t * zone;
		unsigned int                 zidx;

		if (!redact_info
		    && vm_allocation_zone_totals
		    && (zone = vm_allocation_zone_totals[idx])
		    && (nextinfo < num_info)) {
			for (zidx = 0; zidx < VM_TAG_SIZECLASSES; zidx++) {
				if (!zone[zidx].vazt_peak) {
					continue;
				}
				info[nextinfo]        = info[idx];
				info[nextinfo].zone   = zone_index_from_tag_index(zidx);
				info[nextinfo].flags  &= ~VM_KERN_SITE_WIRED;
				info[nextinfo].flags  |= VM_KERN_SITE_ZONE;
				info[nextinfo].flags  |= VM_KERN_SITE_KALLOC;
				info[nextinfo].size   = zone[zidx].vazt_total;
				info[nextinfo].peak   = zone[zidx].vazt_peak;
				info[nextinfo].mapped = 0;
				nextinfo++;
			}
		}
#endif /* VM_TAG_SIZECLASSES */
		if (site->subtotalscount) {
			uint64_t mapped, mapcost, take;
			uint32_t sub;
			vm_tag_t alloctag;

			info[idx].size = site->total;
			mapped = info[idx].size;
			info[idx].mapped = mapped;
			mapcost = 0;
			for (sub = 0; sub < site->subtotalscount; sub++) {
				alloctag = site->subtotals[sub].tag;
				assert(alloctag < num_info);
				if (info[alloctag].name[0] && alloctag >= VM_KERN_MEMORY_FIRST_DYNAMIC) {
					continue;
				}
				take = site->subtotals[sub].total;
				if (take > info[alloctag].size) {
					take = info[alloctag].size;
				}
				if (take > mapped) {
					take = mapped;
				}
				info[alloctag].mapped  -= take;
				info[alloctag].size    -= take;
				mapped                 -= take;
				mapcost                += take;
			}
			info[idx].size = mapcost;
		}
	}
	lck_ticket_unlock(&vm_allocation_sites_lock);

	return 0;
}

uint32_t
vm_page_diagnose_estimate(void)
{
	vm_allocation_site_t * site;
	uint32_t               count = zone_view_count;
	uint32_t               idx;

	lck_ticket_lock(&vm_allocation_sites_lock, &vm_page_lck_grp_bucket);
	for (idx = 0; idx < VM_MAX_TAG_VALUE; idx++) {
		site = vm_allocation_sites[idx];
		if (!site) {
			continue;
		}
		count++;
#if VM_TAG_SIZECLASSES
		if (vm_allocation_zone_totals) {
			vm_allocation_zone_total_t * zone;
			zone = vm_allocation_zone_totals[idx];
			if (!zone) {
				continue;
			}
			for (uint32_t zidx = 0; zidx < VM_TAG_SIZECLASSES; zidx++) {
				count += (zone[zidx].vazt_peak != 0);
			}
		}
#endif
	}
	lck_ticket_unlock(&vm_allocation_sites_lock);

	/* some slop for new tags created */
	count += 8;
	count += VM_KERN_COUNTER_COUNT;

	return count;
}

static void
vm_page_diagnose_zone_stats(mach_memory_info_t *info, zone_stats_t zstats,
    bool percpu)
{
	zpercpu_foreach(zs, zstats) {
		info->size += zs->zs_mem_allocated - zs->zs_mem_freed;
	}
	if (percpu) {
		info->size *= zpercpu_count();
	}
	info->flags |= VM_KERN_SITE_NAMED | VM_KERN_SITE_ZONE_VIEW;
}

static void
vm_page_add_info(
	mach_memory_info_t     *info,
	zone_stats_t            stats,
	bool                    per_cpu,
	const char             *parent_heap_name,
	const char             *parent_zone_name,
	const char             *view_name)
{
	vm_page_diagnose_zone_stats(info, stats, per_cpu);
	snprintf(info->name, sizeof(info->name),
	    "%s%s[%s]", parent_heap_name, parent_zone_name, view_name);
}

static void
vm_page_diagnose_zone(mach_memory_info_t *info, zone_t z)
{
	vm_page_add_info(info, z->z_stats, z->z_percpu, zone_heap_name(z),
	    z->z_name, "raw");
}

static void
vm_page_add_view(
	mach_memory_info_t     *info,
	zone_stats_t            stats,
	const char             *parent_heap_name,
	const char             *parent_zone_name,
	const char             *view_name)
{
	vm_page_add_info(info, stats, false, parent_heap_name, parent_zone_name,
	    view_name);
}

static uint32_t
vm_page_diagnose_heap_views(
	mach_memory_info_t     *info,
	kalloc_heap_t           kh,
	const char             *parent_heap_name,
	const char             *parent_zone_name)
{
	uint32_t i = 0;

	while (kh) {
		vm_page_add_view(info + i, kh->kh_stats, parent_heap_name,
		    parent_zone_name, kh->kh_name);
		kh = kh->kh_views;
		i++;
	}
	return i;
}

static uint32_t
vm_page_diagnose_heap(mach_memory_info_t *info, kalloc_heap_t kheap)
{
	uint32_t i = 0;

	for (; i < KHEAP_NUM_ZONES; i++) {
		vm_page_diagnose_zone(info + i, zone_by_id(kheap->kh_zstart + i));
	}

	i += vm_page_diagnose_heap_views(info + i, kheap->kh_views, kheap->kh_name,
	    NULL);
	return i;
}

static int
vm_page_diagnose_kt_heaps(mach_memory_info_t *info)
{
	uint32_t idx = 0;
	vm_page_add_view(info + idx, KHEAP_KT_VAR->kh_stats, KHEAP_KT_VAR->kh_name,
	    "", "raw");
	idx++;

	for (uint32_t i = 0; i < KT_VAR_MAX_HEAPS; i++) {
		struct kheap_info heap = kalloc_type_heap_array[i];
		char heap_num_tmp[MAX_ZONE_NAME] = "";
		const char *heap_num;

		snprintf(&heap_num_tmp[0], MAX_ZONE_NAME, "%u", i);
		heap_num = &heap_num_tmp[0];

		for (kalloc_type_var_view_t ktv = heap.kt_views; ktv;
		    ktv = (kalloc_type_var_view_t) ktv->kt_next) {
			if (ktv->kt_stats && ktv->kt_stats != KHEAP_KT_VAR->kh_stats) {
				vm_page_add_view(info + idx, ktv->kt_stats, KHEAP_KT_VAR->kh_name,
				    heap_num, ktv->kt_name);
				idx++;
			}
		}

		idx += vm_page_diagnose_heap_views(info + idx, heap.kh_views,
		    KHEAP_KT_VAR->kh_name, heap_num);
	}

	return idx;
}

kern_return_t
vm_page_diagnose(mach_memory_info_t * info, unsigned int num_info, uint64_t zones_collectable_bytes, bool redact_info)
{
	uint64_t                 wired_size;
	uint64_t                 wired_managed_size;
	uint64_t                 wired_reserved_size;
	mach_memory_info_t     * counts;
	uint32_t                 i;

	bzero(info, num_info * sizeof(mach_memory_info_t));

	if (!vm_page_wire_count_initial) {
		return KERN_ABORTED;
	}

	wired_size          = ptoa_64(vm_page_wire_count);
	wired_reserved_size = ptoa_64(vm_page_wire_count_initial - vm_page_stolen_count);
#if XNU_TARGET_OS_OSX
	wired_size          += ptoa_64(vm_lopage_free_count + vm_page_throttled_count);
	wired_reserved_size += ptoa_64(vm_page_throttled_count);
#endif /* XNU_TARGET_OS_OSX */
#if CONFIG_EXCLAVES
	wired_reserved_size -= exclaves_carveout_size + exclaves_bundle_size;
#endif /* CONFIG_EXCLAVES */
	wired_managed_size  = ptoa_64(vm_page_wire_count - vm_page_wire_count_initial);

	wired_size += booter_size;

	assert(num_info >= VM_KERN_COUNTER_COUNT);
	num_info -= VM_KERN_COUNTER_COUNT;
	counts = &info[num_info];

#define SET_COUNT(xcount, xsize, xflags) MACRO_BEGIN \
    counts[xcount].tag   = VM_MAX_TAG_VALUE + xcount;   \
    counts[xcount].site  = (xcount);                            \
    counts[xcount].size  = (xsize);                                 \
    counts[xcount].mapped  = (xsize);                           \
    counts[xcount].flags = VM_KERN_SITE_COUNTER | VM_KERN_SITE_NAMED | xflags; \
    strlcpy(counts[xcount].name, vm_kern_count_names[xcount], MACH_MEMORY_INFO_NAME_MAX_LEN); \
    MACRO_END;

	SET_COUNT(VM_KERN_COUNT_MANAGED, ptoa_64(vm_page_pages), 0);
	SET_COUNT(VM_KERN_COUNT_WIRED, wired_size, 0);
	SET_COUNT(VM_KERN_COUNT_WIRED_MANAGED, wired_managed_size, 0);
	SET_COUNT(VM_KERN_COUNT_RESERVED, wired_reserved_size, VM_KERN_SITE_WIRED);
	SET_COUNT(VM_KERN_COUNT_STOLEN, ptoa_64(vm_page_stolen_count), VM_KERN_SITE_WIRED);
	SET_COUNT(VM_KERN_COUNT_LOPAGE, ptoa_64(vm_lopage_free_count), VM_KERN_SITE_WIRED);
	SET_COUNT(VM_KERN_COUNT_WIRED_BOOT, ptoa_64(vm_page_wire_count_on_boot), 0);
	SET_COUNT(VM_KERN_COUNT_BOOT_STOLEN, booter_size, VM_KERN_SITE_WIRED);
	SET_COUNT(VM_KERN_COUNT_WIRED_STATIC_KERNELCACHE, ptoa_64(vm_page_kernelcache_count), 0);
#if CONFIG_EXCLAVES
	SET_COUNT(VM_KERN_COUNT_EXCLAVES_CARVEOUT, exclaves_carveout_size + exclaves_bundle_size, VM_KERN_SITE_WIRED);
#endif /* CONFIG_EXCLAVES */

#define SET_MAP(xcount, xsize, xfree, xlargest) MACRO_BEGIN \
    counts[xcount].site    = (xcount);                  \
    counts[xcount].size    = (xsize);                   \
    counts[xcount].mapped  = (xsize);                   \
    counts[xcount].free    = (xfree);                   \
    counts[xcount].largest = (xlargest);                \
    counts[xcount].flags   = VM_KERN_SITE_COUNTER | VM_KERN_SITE_NAMED; \
    strlcpy(counts[xcount].name, vm_kern_count_names[xcount], MACH_MEMORY_INFO_NAME_MAX_LEN); \
    MACRO_END;

	vm_map_size_t map_size, map_free, map_largest;

	vm_map_sizes(kernel_map, &map_size, &map_free, &map_largest);
	SET_MAP(VM_KERN_COUNT_MAP_KERNEL, map_size, map_free, map_largest);

	zone_map_sizes(&map_size, &map_free, &map_largest);
	SET_MAP(VM_KERN_COUNT_MAP_ZONE, map_size, map_free, map_largest);

	assert(num_info >= zone_view_count);
	num_info -= zone_view_count;
	counts = &info[num_info];
	i = 0;

	if (!redact_info) {
		if (zone_is_data_buffers_kheap(KHEAP_DATA_PRIVATE->kh_heap_id)) {
			i += vm_page_diagnose_heap(counts + i, KHEAP_DATA_PRIVATE);
		}
		if (zone_is_data_shared_kheap(KHEAP_DATA_SHARED->kh_heap_id)) {
			i += vm_page_diagnose_heap(counts + i, KHEAP_DATA_SHARED);
		}

		if (KHEAP_KT_VAR->kh_heap_id == KHEAP_ID_KT_VAR) {
			i += vm_page_diagnose_kt_heaps(counts + i);
		}
		assert(i <= zone_view_count);

		zone_index_foreach(zidx) {
			zone_t z = &zone_array[zidx];
			zone_security_flags_t zsflags = zone_security_array[zidx];
			zone_view_t zv = z->z_views;

			if (zv == NULL) {
				continue;
			}

			zone_stats_t zv_stats_head = z->z_stats;
			bool has_raw_view = false;

			for (; zv; zv = zv->zv_next) {
				/*
				 * kalloc_types that allocate from the same zone are linked
				 * as views. Only print the ones that have their own stats.
				 */
				if (zv->zv_stats == zv_stats_head) {
					continue;
				}
				has_raw_view = true;
				vm_page_diagnose_zone_stats(counts + i, zv->zv_stats,
				    z->z_percpu);
				snprintf(counts[i].name, sizeof(counts[i].name), "%s%s[%s]",
				    zone_heap_name(z), z->z_name, zv->zv_name);
				i++;
				assert(i <= zone_view_count);
			}

			/*
			 * Print raw views for non kalloc or kalloc_type zones
			 */
			bool kalloc_type = zsflags.z_kalloc_type;
			if ((zsflags.z_kheap_id == KHEAP_ID_NONE && !kalloc_type) ||
			    (kalloc_type && has_raw_view)) {
				vm_page_diagnose_zone(counts + i, z);
				i++;
				assert(i <= zone_view_count);
			}
		}
	}

	process_account(info, num_info, zones_collectable_bytes, redact_info);

	return KERN_SUCCESS;
}

#if DEBUG || DEVELOPMENT

kern_return_t
vm_kern_allocation_info(uintptr_t addr, vm_size_t * size, vm_tag_t * tag, vm_size_t * zone_size)
{
	kern_return_t  ret;
	vm_size_t      zsize;
	vm_map_entry_t entry;
	vm_map_t map = kernel_map;

	vmlp_api_start(VM_KERN_ALLOCATION_INFO);

	zsize = zone_element_info((void *) addr, tag);
	if (zsize) {
		*zone_size = *size = zsize;
		vmlp_api_end(VM_KERN_ALLOCATION_INFO, KERN_SUCCESS);
		return KERN_SUCCESS;
	}

	*zone_size = 0;

	VM_MAP_FIND_LOCK_CTX_DECLARE(ctx);
	vm_map_lock_ctx_set_preflight(
		ctx,
		^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
		/*
		 * Because this function only works on kernel maps, we will run the
		 * preflight even in child entries in submaps, since those submaps
		 * are transparent. And we don't need to translate the address in
		 * transparent submaps, so we can use `addr` directly.
		 */
		if (vme->vme_start != addr) {
		        return KERN_INVALID_ADDRESS;
		}
		return KERN_SUCCESS;
	});
	ret = vm_map_find_entry_sh_locked(ctx, &map, addr,
	    VMRL_FIND_SH_NO_MIN_MAX_CHECK);
	if (ret != KERN_SUCCESS) {
		vmlp_api_end(VM_KERN_ALLOCATION_INFO, ret);
		return ret;
	}
	entry = vm_map_found_entry_get_entry(ctx);

	*tag = (vm_tag_t)VME_ALIAS(entry);
	*size = (entry->vme_end - addr);
	ret = KERN_SUCCESS;

	vm_map_found_entry_sh_unlock(ctx, &map);

	vmlp_api_end(VM_KERN_ALLOCATION_INFO, ret);
	return ret;
}

// some DEBUG/DEVELOPMENT code to get a process to page out its shared cache TEXT pages,
// only used for DK driver in LPW testing
uint64_t
vm_task_evict_shared_cache(task_t task)
{
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr;
	vm_map_t                     map;
	vm_object_t                  textObject, shadow;
	vm_map_entry_t               entry;
	vm_object_offset_t           textOffset, textSize;
	uint64_t                     count;

	count = counter_load(&task->pageins);
	map = get_task_map(task);

	kr = vm_map_range_sh_lock(ctx, &map, VMRL_WHOLE_MAP_START, VMRL_WHOLE_MAP_END,
	    VMRL_SH_STREAM | VMRL_SH_WHOLE_MAP | VMRL_SH_DESCEND_INTO_CONSTANT);
	if (kr != KERN_SUCCESS) {
		assert(kr == KERN_INVALID_ADDRESS); /* No entries in map */
		return count;
	}

	while ((entry = vm_map_range_stream_next(ctx))) {
		if ((ctx->__vmlc_descended != VMLC_NOT_DESCENDED) &&
		    ((VM_PROT_EXECUTE | VM_PROT_READ) == entry->protection)) {
			break; /* we found the entry we wanted */
		}
	}
	if (entry == VM_MAP_ENTRY_NULL) {
		/* didn't find a single entry we're interested in */
		vm_map_range_sh_unlock(ctx, &map);
		return count;
	}
	textObject = VME_OBJECT(entry);
	vm_object_lock(textObject);
	while ((shadow = textObject->shadow)) {
		vm_object_lock(shadow);
		vm_object_unlock(textObject);
		textObject = shadow;
	}
	vm_object_reference_locked(textObject);
	vm_object_unlock(textObject);
	textOffset = VME_OFFSET(entry);
	textSize   = entry->vme_end - entry->vme_start;

	vm_map_range_sh_unlock(ctx, &map);

	vm_object_sync(textObject, textOffset, textSize, true, false, false);
	vm_object_deallocate(textObject);

	return count;
}

uint64_t
vm_task_pageins(task_t task)
{
	return counter_load(&task->pageins);
}

#endif /* DEBUG || DEVELOPMENT */

uint32_t
vm_tag_get_kext(vm_tag_t tag, char * name, vm_size_t namelen)
{
	vm_allocation_site_t * site;
	uint32_t               kmodId;

	kmodId = 0;
	lck_ticket_lock(&vm_allocation_sites_lock, &vm_page_lck_grp_bucket);
	if ((site = vm_allocation_sites[tag])) {
		if (VM_TAG_KMOD & site->flags) {
			kmodId = OSKextGetKmodIDForSite(site, name, namelen);
		}
	}
	lck_ticket_unlock(&vm_allocation_sites_lock);

	return kmodId;
}


#if CONFIG_SECLUDED_MEMORY
/*
 * Note that there's no locking around other accesses to vm_page_secluded_target.
 * That should be OK, since these are the only place where it can be changed after
 * initialization. Other users (like vm_pageout) may see the wrong value briefly,
 * but will eventually get the correct value. This brief mismatch is OK as pageout
 * and page freeing will auto-adjust the vm_page_secluded_count to match the target
 * over time.
 */
unsigned int vm_page_secluded_suppress_cnt = 0;
unsigned int vm_page_secluded_save_target;

LCK_GRP_DECLARE(secluded_suppress_slock_grp, "secluded_suppress_slock");
LCK_SPIN_DECLARE(secluded_suppress_slock, &secluded_suppress_slock_grp);

void
start_secluded_suppression(task_t task)
{
	if (task->task_suppressed_secluded) {
		return;
	}
	lck_spin_lock(&secluded_suppress_slock);
	if (!task->task_suppressed_secluded && vm_page_secluded_suppress_cnt++ == 0) {
		task->task_suppressed_secluded = TRUE;
		vm_page_secluded_save_target = vm_page_secluded_target;
		vm_page_secluded_target = 0;
		VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();
	}
	lck_spin_unlock(&secluded_suppress_slock);
}

void
stop_secluded_suppression(task_t task)
{
	lck_spin_lock(&secluded_suppress_slock);
	if (task->task_suppressed_secluded && --vm_page_secluded_suppress_cnt == 0) {
		task->task_suppressed_secluded = FALSE;
		vm_page_secluded_target = vm_page_secluded_save_target;
		VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE();
	}
	lck_spin_unlock(&secluded_suppress_slock);
}

#endif /* CONFIG_SECLUDED_MEMORY */

/*
 * Move the list of retired pages on the vm_page_queue_retired to
 * their final resting place on retired_pages_object.
 */
void
vm_retire_boot_pages(void)
{
}

/*
 * This holds the reported physical address if an ECC error leads to a panic.
 * SMC will store it in PMU SRAM under the 'sECC' key.
 */
uint64_t ecc_panic_physical_address = 0;

