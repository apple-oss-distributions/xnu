/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	vm/vm_page.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Resident memory system definitions.
 */

#ifndef _VM_VM_PAGE_H_
#define _VM_VM_PAGE_H_

#include <debug.h>
#include <stdbool.h>
#include <vm/vm_options.h>
#include <vm/vm_protos.h>
#include <vm/vm_far.h>
#include <mach/boolean.h>
#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <mach/memory_object_types.h> /* for VMP_CS_BITS... */
#include <kern/thread.h>
#include <kern/queue.h>
#include <kern/locks.h>
#include <sys/kern_memorystatus_xnu.h>

#if __x86_64__
#define XNU_VM_HAS_DELAYED_PAGES        1
#define XNU_VM_HAS_LOPAGE               1
#define XNU_VM_HAS_LINEAR_PAGES_ARRAY   0
#else
#define XNU_VM_HAS_DELAYED_PAGES        0
#define XNU_VM_HAS_LOPAGE               0
#define XNU_VM_HAS_LINEAR_PAGES_ARRAY   1
#endif


#if HAS_MTE
static_assert(!XNU_VM_HAS_DELAYED_PAGES, "MTE and delayed pages aren't compatible");
static_assert(XNU_VM_HAS_LINEAR_PAGES_ARRAY, "MTE requires linear vm_pages[]");
#endif /* HAS_MTE */

/*
 * in order to make the size of a vm_page_t 64 bytes (cache line size for both arm64 and x86_64)
 * we'll keep the next_m pointer packed... as long as the kernel virtual space where we allocate
 * vm_page_t's from doesn't span more then 256 Gbytes, we're safe.   There are live tests in the
 * vm_page_t array allocation and the zone init code to determine if we can safely pack and unpack
 * pointers from the 2 ends of these spaces
 */
typedef uint32_t        vm_page_packed_t;

struct vm_page_packed_queue_entry {
	vm_page_packed_t        next;          /* next element */
	vm_page_packed_t        prev;          /* previous element */
};

typedef struct vm_page_packed_queue_entry       *vm_page_queue_t;
typedef struct vm_page_packed_queue_entry       vm_page_queue_head_t;
typedef struct vm_page_packed_queue_entry       vm_page_queue_chain_t;
typedef struct vm_page_packed_queue_entry       *vm_page_queue_entry_t;

typedef vm_page_packed_t                        vm_page_object_t;


/*
 * vm_relocate_reason_t:
 * A type to describe why a page relocation is being attempted.  Depending on
 * the reason, certain pages may or may not be relocatable.
 *
 * VM_RELOCATE_REASON_CONTIGUOUS:
 * The relocation is on behalf of the contiguous allocator; it is likely to be
 * wired, so do not consider pages that cannot be wired for any reason.
 */
#if HAS_MTE
/*
 * VM_RELOCATE_REASON_TAG_STORAGE_RECLAIM:
 * The relocation is to free up a tag storage range page, so that it can be
 * used for tag storage.
 *
 * VM_RELOCATE_REASON_TAG_STORAGE_WIRE:
 * The relocation is because a codepath is trying or is about to try to wire a
 * tag storage page.  The relocation code will relax requirements around the
 * page state needed to be relocatable.
 *
 * NOTE: For now, tag storage pages will be considered wireable... but in the
 * future, tag storage pages will not be considered wireable.
 * VM_RELOCATE_REASON_TAG_STORAGE_WIRE exists in anticipation of this.
 */
#endif /* HAS_MTE */
__enum_closed_decl(vm_relocate_reason_t, unsigned int, {
	VM_RELOCATE_REASON_CONTIGUOUS,
#if HAS_MTE
	VM_RELOCATE_REASON_TAG_STORAGE_RECLAIM,
	VM_RELOCATE_REASON_TAG_STORAGE_WIRE,
#endif /* HAS_MTE */

	VM_RELOCATE_REASON_COUNT,
});

/*!
 * @typedef vm_memory_class_t
 *
 * @abstract
 * A type to describe what kind of memory a page represents.
 *
 * @const VM_MEMORY_CLASS_REGULAR
 * Normal memory, which should participate in the normal page lifecycle.
 *
 * @const VM_MEMORY_CLASS_LOPAGE
 * this exists to support hardware controllers
 * incapable of generating DMAs with more than 32 bits
 * of address on platforms with physical memory > 4G...
 *
 * @const VM_MEMORY_CLASS_SECLUDED
 * Denotes memory must be put on the secluded queue,
 * this is not returned by @c vm_page_get_memory_class().
 */
#if HAS_MTE
/*
 * @const VM_MEMORY_CLASS_TAGGED
 * MTE tagged memory, which should participate in the lifecycle for tagged
 * pages.  Pages may move between this and the VM_MEMORY_CLASS_REGULAR classes,
 * dynamically.
 *
 * @const VM_MEMORY_CLASS_TAG_STORAGE
 * MTE tag storage memory, which should participate in the lifecycle for tag
 * storage pages.  Note that this is NOT the same as being in the tag storage
 * region; some pages in the tag storage region will be classified as regular
 * pages, because the system will never use them for tag storage.
 *
 * @const VM_MEMORY_CLASS_DEAD_TAG_STORAGE
 * MTE tag storage that is either recursive or for unmanaged memory
 * that must always be used as regular memory and can never be taggable.
 */
#endif /* HAS_MTE */
__enum_closed_decl(vm_memory_class_t, uint8_t, {
	VM_MEMORY_CLASS_REGULAR,
#if HAS_MTE
	VM_MEMORY_CLASS_TAGGED,
	VM_MEMORY_CLASS_TAG_STORAGE,
	VM_MEMORY_CLASS_DEAD_TAG_STORAGE,
#endif /* HAS_MTE */
#if XNU_VM_HAS_LOPAGE
	VM_MEMORY_CLASS_LOPAGE,
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
	VM_MEMORY_CLASS_SECLUDED,
#endif
});

/* pages of compressed data */
#define VM_PAGE_COMPRESSOR_COUNT os_atomic_load(&compressor_object->resident_page_count, relaxed)

/*
 *	Management of resident (logical) pages.
 *
 *	A small structure is kept for each resident
 *	page, indexed by page number.  Each structure
 *	is an element of several lists:
 *
 *		A hash table bucket used to quickly
 *		perform object/offset lookups
 *
 *		A list of all pages for a given object,
 *		so they can be quickly deactivated at
 *		time of deallocation.
 *
 *		An ordered list of pages due for pageout.
 *
 *	In addition, the structure contains the object
 *	and offset to which this page belongs (for pageout),
 *	and sundry status bits.
 *
 *	Fields in this structure are locked either by the lock on the
 *	object that the page belongs to (O) or by the lock on the page
 *	queues (P).  [Some fields require that both locks be held to
 *	change that field; holding either lock is sufficient to read.]
 */

#define VM_PAGE_NULL            ((vm_page_t) 0)
#define VM_PAGE_PRIMED          ((vm_page_t) ~0)

__enum_closed_decl(vm_page_q_state_t, uint8_t, {
	VM_PAGE_NOT_ON_Q                = 0,    /* page is not present on any queue, nor is it wired... mainly a transient state */
	VM_PAGE_IS_WIRED                = 1,    /* page is currently wired */
	VM_PAGE_USED_BY_COMPRESSOR      = 2,    /* page is in use by the compressor to hold compressed data */
	VM_PAGE_ON_FREE_Q               = 3,    /* page is on the main free queue */
	VM_PAGE_ON_FREE_LOCAL_Q         = 4,    /* page is on one of the per-CPU free queues */
#if XNU_VM_HAS_LOPAGE
	VM_PAGE_ON_FREE_LOPAGE_Q        = 5,    /* page is on the lopage pool free list */
#endif /* XNU_VM_HAS_LOPAGE */
#if CONFIG_SECLUDED_MEMORY
	VM_PAGE_ON_SECLUDED_Q           = 5,    /* page is on secluded queue */
#endif /* CONFIG_SECLUDED_MEMORY */
	VM_PAGE_ON_THROTTLED_Q          = 6,    /* page is on the throttled queue... we stash anonymous pages here when not paging */
	VM_PAGE_ON_PAGEOUT_Q            = 7,    /* page is on one of the pageout queues (internal/external) awaiting processing */
	VM_PAGE_ON_SPECULATIVE_Q        = 8,    /* page is on one of the speculative queues */
	VM_PAGE_ON_ACTIVE_LOCAL_Q       = 9,    /* page has recently been created and is being held in one of the per-CPU local queues */
	VM_PAGE_ON_ACTIVE_Q             = 10,   /* page is in global active queue */
	VM_PAGE_ON_INACTIVE_INTERNAL_Q  = 11,   /* page is on the inactive internal queue a.k.a.  anonymous queue */
	VM_PAGE_ON_INACTIVE_EXTERNAL_Q  = 12,   /* page in on the inactive external queue a.k.a.  file backed queue */
	VM_PAGE_ON_INACTIVE_CLEANED_Q   = 13,   /* page has been cleaned to a backing file and is ready to be stolen */
	VM_PAGE_IS_IOPL_WIRED           = 14,   /* page has been wired for an I/O UPL; object lock must be held when transitioning into/out of this state. */
	VM_PAGE_NUM_Q_STATES
});

_Static_assert(VM_PAGE_NUM_Q_STATES <= 16, "Too many vm_page_q_state_t values to fit in 4-bit vmp_q_state field");

__enum_closed_decl(vm_page_specialq_t, uint8_t, {
	VM_PAGE_SPECIAL_Q_EMPTY         = 0,
	VM_PAGE_SPECIAL_Q_BG            = 1,
	VM_PAGE_SPECIAL_Q_DONATE        = 2,
	VM_PAGE_SPECIAL_Q_FG            = 3,
});

#define VM_PAGE_INACTIVE(m)                     bit_test(vm_page_inactive_states, (m)->vmp_q_state)
#define VM_PAGE_ACTIVE_OR_INACTIVE(m)           bit_test(vm_page_active_or_inactive_states, (m)->vmp_q_state)
#define VM_PAGE_NON_SPECULATIVE_PAGEABLE(m)     bit_test(vm_page_non_speculative_pageable_states, (m)->vmp_q_state)
#define VM_PAGE_PAGEABLE(m)                     bit_test(vm_page_pageable_states, (m)->vmp_q_state)

extern const uint16_t vm_page_inactive_states;
extern const uint16_t vm_page_active_or_inactive_states;
extern const uint16_t vm_page_non_speculative_pageable_states;
extern const uint16_t vm_page_pageable_states;


/*
 * The structure itself. See the block comment above for what (O) and (P) mean.
 */
struct vm_page {
	union {
		vm_page_queue_chain_t   vmp_pageq;      /* queue info for FIFO queue or free list (P) */
		struct vm_page         *vmp_snext;
	};
	vm_page_queue_chain_t           vmp_specialq;   /* anonymous pages in the special queues (P) */

	vm_page_queue_chain_t           vmp_listq;      /* all pages in same object (O) */
	vm_page_packed_t                vmp_next_m;     /* VP bucket link (O) */

	vm_page_object_t                vmp_object;     /* which object am I in (O&P) */
	vm_object_offset_t              vmp_offset;     /* offset into that object (O,P) */


	/*
	 * Either the current page wire count,
	 * or the local queue id (if local queues are enabled).
	 *
	 * See the comments at 'vm_page_queues_remove'
	 * as to why this is safe to do.
	 */
	union {
		uint16_t                vmp_wire_count;
		uint16_t                vmp_local_id;
	};

	/*
	 * The following word of flags used to be protected by the "page queues" lock.
	 * That's no longer true and what lock, if any, is needed may depend on the
	 * value of vmp_q_state.
	 *
	 * This bitfield is kept in its own struct to prevent coalescing
	 * with the next one (which C allows the compiler to do) as they
	 * are under different locking domains
	 */
	struct {
		vm_page_q_state_t       vmp_q_state:4;      /* which q is the page on (P) */
		vm_page_specialq_t      vmp_on_specialq:2;
		uint8_t                 vmp_lopage:1;
		uint8_t                 vmp_canonical:1;    /* this page is a canonical kernel page (immutable) */
	};
	struct {
		uint8_t                 vmp_gobbled:1;      /* page used internally (P) */
		uint8_t                 vmp_laundry:1;      /* page is being cleaned now (P)*/
		uint8_t                 vmp_no_cache:1;     /* page is not to be cached and should */
		                                            /* be reused ahead of other pages (P) */
		uint8_t                 vmp_reference:1;    /* page has been used (P) */
		uint8_t                 vmp_realtime:1;     /* page used by realtime thread (P) */
#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
		uint8_t                 vmp_unmodified_ro:1;/* Tracks if an anonymous page is modified after a decompression (O&P).*/
#else
		uint8_t                 __vmp_reserved1:1;
#endif
#if HAS_MTE
		uint8_t                 vmp_ts_wanted:1;    /* This tag storage page is wanted for reclaim (O&P) */
#else
		uint8_t                 __vmp_reserved2:1;
#endif
		uint8_t                 __vmp_reserved3:1;
	};

	/*
	 * The following word of flags is protected by the "VM object" lock.
	 *
	 * IMPORTANT: the "vmp_pmapped", "vmp_xpmapped" and "vmp_clustered" bits can be modified while holding the
	 * VM object "shared" lock + the page lock provided through the pmap_lock_phys_page function.
	 * This is done in vm_fault_enter() and the CONSUME_CLUSTERED macro.
	 * It's also ok to modify them behind just the VM object "exclusive" lock.
	 */
	unsigned int    vmp_busy:1,           /* page is in transit (O) */
	    vmp_wanted:1,                     /* someone is waiting for page (O) */
	    vmp_tabled:1,                     /* page is in VP table (O) */
	    vmp_hashed:1,                     /* page is in vm_page_buckets[] (O) + the bucket lock */
#if HAS_MTE
	/*
	 * Whether the page is tagged (O)
	 *
	 * This bit is modified in 3 cases:
	 *
	 * - while the page is on the free queue (vmp_q_state ==
	 *   VM_PAGE_ON_FREE_Q) with the free queue lock held;
	 *
	 * - when the page is in limbo on its way to the free queue
	 *   (vmp_q_state == VM_PAGE_NOT_ON_Q, vmp_busy == true)
	 *   by the thread owning exclusive access to this page;
	 *
	 * - when the page is on a free local queue (vmp_q_state ==
	 *   VM_PAGE_ON_FREE_LOCAL_Q), by the CPU owning that queue under
	 *   preemption disabled.
	 *
	 * Observing this bit as a result is always stable
	 * under the object lock (O).
	 */
	    vmp_using_mte : 1,
#else
	__vmp_unused : 1,
#endif /* HAS_MTE */
	vmp_clustered:1,                      /* page is not the faulted page (O) or (O-shared AND pmap_page) */
	    vmp_pmapped:1,                    /* page has at some time been entered into a pmap (O) or */
	                                      /* (O-shared AND pmap_page) */
	    vmp_xpmapped:1,                   /* page has been entered with execute permission (O) or */
	                                      /* (O-shared AND pmap_page) */
	    vmp_wpmapped:1,                   /* page has been entered at some point into a pmap for write (O) */
	    vmp_free_when_done:1,             /* page is to be freed once cleaning is completed (O) */
	    vmp_absent:1,                     /* Data has been requested, but is not yet available (O) */
	    vmp_error:1,                      /* Data manager was unable to provide data due to error (O) */
	    vmp_dirty:1,                      /* Page must be cleaned (O) */
	    vmp_cleaning:1,                   /* Page clean has begun (O) */
	    vmp_precious:1,                   /* Page is precious; data must be returned even if clean (O) */
	    vmp_overwriting:1,                /* Request to unlock has been made without having data. (O) */
	                                      /* [See vm_fault_page_overwrite] */
	    vmp_restart:1,                    /* Page was pushed higher in shadow chain by copy_call-related pagers */
	                                      /* start again at top of chain */
	    vmp_unusual:1,                    /* Page is absent, error, restart or page locked */
	    vmp_cs_validated:VMP_CS_BITS,     /* code-signing: page was checked */
	    vmp_cs_tainted:VMP_CS_BITS,       /* code-signing: page is tainted */
	    vmp_cs_nx:VMP_CS_BITS,            /* code-signing: page is nx */
	    vmp_reusable:1,
	    vmp_written_by_kernel:1;          /* page was written by kernel (i.e. decompressed) */

#if !XNU_VM_HAS_LINEAR_PAGES_ARRAY
	/*
	 * Physical number of the page
	 *
	 * Setting this value to or away from vm_page_fictitious_addr
	 * must be done with (P) held
	 */
	ppnum_t                         vmp_phys_page;
#endif /* !XNU_VM_HAS_LINEAR_PAGES_ARRAY */
};

/*!
 * @var vm_pages
 * The so called VM pages array
 *
 * @var vm_pages_end
 * The pointer past the last valid page in the VM pages array.
 *
 * @var vm_pages_count
 * The number of elements in the VM pages array.
 * (vm_pages + vm_pages_count == vm_pages_end).
 *
 * @var vm_pages_first_pnum
 * For linear page arrays, the pnum of the first page in the array.
 * In other words VM_PAGE_GET_PHYS_PAGE(&vm_pages_array()[0]).
 */
extern vm_page_t        vm_pages_end;
extern uint32_t         vm_pages_count;
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
extern ppnum_t          vm_pages_first_pnum;
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */


/**
 * Internal accessor which returns the raw vm_pages pointer.
 *
 * This pointer must not be indexed directly. Use vm_page_get instead when
 * indexing into the array.
 *
 * __pure2 helps explain to the compiler that the value vm_pages is a constant.
 */
__pure2
static inline struct vm_page *
vm_pages_array_internal(void)
{
	extern vm_page_t vm_pages;
	return vm_pages;
}

/**
 * Get a pointer to page at index i.
 *
 * This getter is the only legal way to index into the vm_pages array.
 */
__pure2
static inline vm_page_t
vm_page_get(uint32_t i)
{
	return VM_FAR_ADD_PTR_UNBOUNDED(vm_pages_array_internal(), i);
}

#if HAS_MTE

/**
 * Internal accessor which returns the raw vm_array_tag_storage pointer,
 * which is a pointer inside the VM pages array pointing to the first tag
 * storage page.
 *
 * This pointer must not be indexed directly. Use vm_tag_storage_page_get()
 * instead when indexing into the array.
 *
 * __pure2 helps explain to the compiler that the value vm_pages is a constant.
 */
__pure2
static inline struct vm_page *
vm_pages_tag_storage_array_internal(void)
{
	extern vm_page_t vm_pages_tag_storage;
	return vm_pages_tag_storage;
}

/**
 * Get a pointer to tag storage page at index i.
 *
 * This getter is the only legal way to index into the vm_pages_tag_storage array.
 */
__pure2
static inline vm_page_t
vm_tag_storage_page_get(uint32_t i)
{
	return VM_FAR_ADD_PTR_UNBOUNDED(vm_pages_tag_storage_array_internal(), i);
}

__pure2
static inline bool
vm_page_in_tag_storage_array(const struct vm_page *m)
{
	extern vm_page_t vm_pages_tag_storage_end;
	return vm_pages_tag_storage_array_internal() <= m &&
	       m < vm_pages_tag_storage_end;
}

#endif /* HAS_MTE */

__pure2
static inline bool
vm_page_in_array(const struct vm_page *m)
{
	return vm_pages_array_internal() <= m && m < vm_pages_end;
}

#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
struct vm_page_with_ppnum {
	struct vm_page          vmp_page;
	ppnum_t                 vmp_phys_page;
};

/*!
 * @abstract
 * Looks up the canonical kernel page for a given physical page number.
 *
 * @discussion
 * This function may return VM_PAGE_NULL for kernel pages that aren't managed
 * by the VM.
 *
 * @param pnum          The page number to lookup.  It must be within
 *                      [pmap_first_pnum, vm_pages_first_pnum + vm_pages_count)
 */
extern vm_page_t vm_page_find_canonical(ppnum_t pnum) __pure2;

extern vm_page_t vm_pages_radix_next(uint32_t *cursor, ppnum_t *pnum);

#define vm_pages_radix_for_each(mem) \
	for (uint32_t __index = 0; ((mem) = vm_pages_radix_next(&__index, NULL)); )

#define vm_pages_radix_for_each_pnum(pnum) \
	for (uint32_t __index = 0; vm_pages_radix_next(&__index, &pnum); )

#else
#define vm_page_with_ppnum vm_page
#endif /* !XNU_VM_HAS_LINEAR_PAGES_ARRAY */
typedef struct vm_page_with_ppnum *vm_page_with_ppnum_t;

static inline ppnum_t
VM_PAGE_GET_PHYS_PAGE(const struct vm_page *m)
{
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
	if (vm_page_in_array(m)) {
		uintptr_t index = (uintptr_t)(m - vm_pages_array_internal());

		return (ppnum_t)(vm_pages_first_pnum + index);
	}
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */
	return ((const struct vm_page_with_ppnum *)m)->vmp_phys_page;
}

static inline void
VM_PAGE_INIT_PHYS_PAGE(struct vm_page *m, ppnum_t pnum)
{
#if XNU_VM_HAS_LINEAR_PAGES_ARRAY
	if (vm_page_in_array(m)) {
		assert(pnum == VM_PAGE_GET_PHYS_PAGE(m));
		return;
	}
#endif /* XNU_VM_HAS_LINEAR_PAGES_ARRAY */
	((vm_page_with_ppnum_t)(m))->vmp_phys_page = pnum;
}

static inline void
VM_PAGE_SET_PHYS_PAGE(struct vm_page *m, ppnum_t pnum)
{
	assert(!vm_page_in_array(m) && !m->vmp_canonical);
	((vm_page_with_ppnum_t)(m))->vmp_phys_page = pnum;
}

#if defined(__x86_64__)
extern unsigned int     vm_clump_mask, vm_clump_shift;
#define VM_PAGE_GET_CLUMP_PNUM(pn)      ((pn) >> vm_clump_shift)
#define VM_PAGE_GET_CLUMP(m)            VM_PAGE_GET_CLUMP_PNUM(VM_PAGE_GET_PHYS_PAGE(m))
#define VM_PAGE_GET_COLOR_PNUM(pn)      (VM_PAGE_GET_CLUMP_PNUM(pn) & vm_color_mask)
#define VM_PAGE_GET_COLOR(m)            VM_PAGE_GET_COLOR_PNUM(VM_PAGE_GET_PHYS_PAGE(m))
#else
#define VM_PAGE_GET_COLOR_PNUM(pn)      ((pn) & vm_color_mask)
#define VM_PAGE_GET_COLOR(m)            VM_PAGE_GET_COLOR_PNUM(VM_PAGE_GET_PHYS_PAGE(m))
#endif

/*
 * Parameters for pointer packing
 *
 *
 * VM Pages pointers might point to:
 *
 * 1. VM_PAGE_PACKED_ALIGNED aligned kernel globals,
 *
 * 2. VM_PAGE_PACKED_ALIGNED aligned heap allocated vm pages
 *
 * 3. entries in the vm_pages array (whose entries aren't VM_PAGE_PACKED_ALIGNED
 *    aligned).
 *
 *
 * The current scheme uses 31 bits of storage and 6 bits of shift using the
 * VM_PACK_POINTER() scheme for (1-2), and packs (3) as an index within the
 * vm_pages array, setting the top bit (VM_PAGE_PACKED_FROM_ARRAY).
 *
 * This scheme gives us a reach of 128G from VM_MIN_KERNEL_AND_KEXT_ADDRESS.
 */
#define VM_VPLQ_ALIGNMENT               128
#define VM_PAGE_PACKED_PTR_ALIGNMENT    64              /* must be a power of 2 */
#define VM_PAGE_PACKED_ALIGNED          __attribute__((aligned(VM_PAGE_PACKED_PTR_ALIGNMENT)))
#define VM_PAGE_PACKED_PTR_BITS         31
#define VM_PAGE_PACKED_PTR_SHIFT        6
#define VM_PAGE_PACKED_PTR_BASE         ((uintptr_t)VM_MIN_KERNEL_AND_KEXT_ADDRESS)
#define VM_PAGE_PACKED_FROM_ARRAY       0x80000000

static inline vm_page_packed_t
vm_page_pack_ptr(uintptr_t p)
{
	if (vm_page_in_array(__unsafe_forge_single(vm_page_t, p))) {
		ptrdiff_t diff = (vm_page_t)p - vm_pages_array_internal();
		assert((vm_page_t)p == vm_page_get((uint32_t)diff));
		return (vm_page_packed_t)(diff | VM_PAGE_PACKED_FROM_ARRAY);
	}

	VM_ASSERT_POINTER_PACKABLE(p, VM_PAGE_PACKED_PTR);
	vm_offset_t packed = VM_PACK_POINTER(p, VM_PAGE_PACKED_PTR);
	return CAST_DOWN_EXPLICIT(vm_page_packed_t, packed);
}


static inline uintptr_t
vm_page_unpack_ptr(uintptr_t p)
{
	if (p >= VM_PAGE_PACKED_FROM_ARRAY) {
		p &= ~VM_PAGE_PACKED_FROM_ARRAY;
		assert(p < (uintptr_t)vm_pages_count);
		return (uintptr_t)vm_page_get((uint32_t)p);
	}

	return VM_UNPACK_POINTER(p, VM_PAGE_PACKED_PTR);
}


#define VM_PAGE_PACK_PTR(p)     vm_page_pack_ptr((uintptr_t)(p))
#define VM_PAGE_UNPACK_PTR(p)   vm_page_unpack_ptr((uintptr_t)(p))

#define VM_OBJECT_PACK(o)       (VM_ASSERT_POINTER_PACKABLE((uintptr_t)(o), VM_PAGE_PACKED_PTR), \
	                        (vm_page_object_t)VM_PACK_POINTER((uintptr_t)(o), VM_PAGE_PACKED_PTR))

#define VM_OBJECT_UNPACK(p)     ((vm_object_t)VM_UNPACK_POINTER(p, VM_PAGE_PACKED_PTR))

#define VM_PAGE_OBJECT(p)       VM_OBJECT_UNPACK((p)->vmp_object)
#define VM_PAGE_PACK_OBJECT(o)  VM_OBJECT_PACK(o)


#define VM_PAGE_ZERO_PAGEQ_ENTRY(p)     \
MACRO_BEGIN                             \
	(p)->vmp_snext = 0;             \
MACRO_END


#define VM_PAGE_CONVERT_TO_QUEUE_ENTRY(p)       VM_PAGE_PACK_PTR(p)


/*!
 * @abstract
 * The type for free queue heads that live in the kernel __DATA segment.
 *
 * @discussion
 * This type must be used so that the queue is properly aligned
 * for the VM Page packing to be able to represent pointers to this queue.
 */
typedef struct vm_page_queue_free_head {
	vm_page_queue_head_t    qhead;
} VM_PAGE_PACKED_ALIGNED *vm_page_queue_free_head_t;

/*
 *	Macro:	vm_page_queue_init
 *	Function:
 *		Initialize the given queue.
 *	Header:
 *	void vm_page_queue_init(q)
 *		vm_page_queue_t	q;	\* MODIFIED *\
 */
#define vm_page_queue_init(q)               \
MACRO_BEGIN                                 \
	VM_ASSERT_POINTER_PACKABLE((vm_offset_t)(q), VM_PAGE_PACKED_PTR); \
	(q)->next = VM_PAGE_PACK_PTR(q);        \
	(q)->prev = VM_PAGE_PACK_PTR(q);        \
MACRO_END


/*
 * Macro: vm_page_queue_enter
 * Function:
 *     Insert a new element at the tail of the vm_page queue.
 * Header:
 *     void vm_page_queue_enter(q, elt, field)
 *         queue_t q;
 *         vm_page_t elt;
 *         <field> is the list field in vm_page_t
 *
 * This macro's arguments have to match the generic "queue_enter()" macro which is
 * what is used for this on 32 bit kernels.
 */
#define vm_page_queue_enter(head, elt, field)                       \
MACRO_BEGIN                                                         \
	vm_page_packed_t __pck_elt = VM_PAGE_PACK_PTR(elt);         \
	vm_page_packed_t __pck_head = VM_PAGE_PACK_PTR(head);       \
	vm_page_packed_t __pck_prev = (head)->prev;                 \
                                                                    \
	if (__pck_head == __pck_prev) {                             \
	        (head)->next = __pck_elt;                           \
	} else {                                                    \
	        vm_page_t __prev;                                   \
	        __prev = (vm_page_t)VM_PAGE_UNPACK_PTR(__pck_prev); \
	        __prev->field.next = __pck_elt;                     \
	}                                                           \
	(elt)->field.prev = __pck_prev;                             \
	(elt)->field.next = __pck_head;                             \
	(head)->prev = __pck_elt;                                   \
MACRO_END


#if defined(__x86_64__)
/*
 * These are helper macros for vm_page_queue_enter_clump to assist
 * with conditional compilation (release / debug / development)
 */
#if DEVELOPMENT || DEBUG

#define __DEBUG_CHECK_BUDDIES(__prev, __p, field)                                             \
MACRO_BEGIN                                                                                   \
	if (__prev != NULL) {                                                                 \
	        assert(__p == (vm_page_t)VM_PAGE_UNPACK_PTR(__prev->next));                   \
	        assert(__prev == (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(__p->field.prev)); \
	}                                                                                     \
MACRO_END

#define __DEBUG_VERIFY_LINKS(__first, __n_free, __last_next)                    \
MACRO_BEGIN                                                                     \
	unsigned int __i;                                                       \
	vm_page_queue_entry_t __tmp;                                            \
	for (__i = 0, __tmp = __first; __i < __n_free; __i++) {                 \
	        __tmp = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(__tmp->next); \
	}                                                                       \
	assert(__tmp == __last_next);                                           \
MACRO_END

#define __DEBUG_STAT_INCREMENT_INRANGE              vm_clump_inrange++
#define __DEBUG_STAT_INCREMENT_INSERTS              vm_clump_inserts++
#define __DEBUG_STAT_INCREMENT_PROMOTES(__n_free)   vm_clump_promotes+=__n_free

#else

#define __DEBUG_CHECK_BUDDIES(__prev, __p, field)
#define __DEBUG_VERIFY_LINKS(__first, __n_free, __last_next)
#define __DEBUG_STAT_INCREMENT_INRANGE
#define __DEBUG_STAT_INCREMENT_INSERTS
#define __DEBUG_STAT_INCREMENT_PROMOTES(__n_free)

#endif  /* if DEVELOPMENT || DEBUG */

#endif

/*
 * Macro: vm_page_queue_enter_first
 * Function:
 *     Insert a new element at the head of the vm_page queue.
 * Header:
 *     void queue_enter_first(q, elt, , field)
 *         queue_t q;
 *         vm_page_t elt;
 *         <field> is the linkage field in vm_page
 *
 * This macro's arguments have to match the generic "queue_enter_first()" macro which is
 * what is used for this on 32 bit kernels.
 */
#define vm_page_queue_enter_first(head, elt, field)                 \
MACRO_BEGIN                                                         \
	vm_page_packed_t __pck_next = (head)->next;                 \
	vm_page_packed_t __pck_head = VM_PAGE_PACK_PTR(head);       \
	vm_page_packed_t __pck_elt = VM_PAGE_PACK_PTR(elt);         \
                                                                    \
	if (__pck_head == __pck_next) {                             \
	        (head)->prev = __pck_elt;                           \
	} else {                                                    \
	        vm_page_t __next;                                   \
	        __next = (vm_page_t)VM_PAGE_UNPACK_PTR(__pck_next); \
	        __next->field.prev = __pck_elt;                     \
	}                                                           \
                                                                    \
	(elt)->field.next = __pck_next;                             \
	(elt)->field.prev = __pck_head;                             \
	(head)->next = __pck_elt;                                   \
MACRO_END


/*
 * Macro:	vm_page_queue_remove
 * Function:
 *     Remove an arbitrary page from a vm_page queue.
 * Header:
 *     void vm_page_queue_remove(q, qe, field)
 *         arguments as in vm_page_queue_enter
 *
 * This macro's arguments have to match the generic "queue_enter()" macro which is
 * what is used for this on 32 bit kernels.
 */
#define vm_page_queue_remove(head, elt, field)                          \
MACRO_BEGIN                                                             \
	vm_page_packed_t __pck_next = (elt)->field.next;                \
	vm_page_packed_t __pck_prev = (elt)->field.prev;                \
	vm_page_t        __next = (vm_page_t)VM_PAGE_UNPACK_PTR(__pck_next); \
	vm_page_t        __prev = (vm_page_t)VM_PAGE_UNPACK_PTR(__pck_prev); \
                                                                        \
	if ((void *)(head) == (void *)__next) {                         \
	        (head)->prev = __pck_prev;                              \
	} else {                                                        \
	        __next->field.prev = __pck_prev;                        \
	}                                                               \
                                                                        \
	if ((void *)(head) == (void *)__prev) {                         \
	        (head)->next = __pck_next;                              \
	} else {                                                        \
	        __prev->field.next = __pck_next;                        \
	}                                                               \
                                                                        \
	(elt)->field.next = 0;                                          \
	(elt)->field.prev = 0;                                          \
MACRO_END


/*
 * Macro: vm_page_queue_remove_first
 *
 * Function:
 *     Remove and return the entry at the head of a vm_page queue.
 *
 * Header:
 *     vm_page_queue_remove_first(head, entry, field)
 *     N.B. entry is returned by reference
 *
 * This macro's arguments have to match the generic "queue_remove_first()" macro which is
 * what is used for this on 32 bit kernels.
 */
#define vm_page_queue_remove_first(head, entry, field)            \
MACRO_BEGIN                                                       \
	vm_page_packed_t __pck_head = VM_PAGE_PACK_PTR(head);     \
	vm_page_packed_t __pck_next;                              \
	vm_page_t        __next;                                  \
                                                                  \
	(entry) = (vm_page_t)VM_PAGE_UNPACK_PTR((head)->next);    \
	__pck_next = (entry)->field.next;                         \
	__next = (vm_page_t)VM_PAGE_UNPACK_PTR(__pck_next);       \
                                                                  \
	if (__pck_head == __pck_next) {                           \
	        (head)->prev = __pck_head;                        \
	} else {                                                  \
	        __next->field.prev = __pck_head;                  \
	}                                                         \
                                                                  \
	(head)->next = __pck_next;                                \
	(entry)->field.next = 0;                                  \
	(entry)->field.prev = 0;                                  \
MACRO_END


#if defined(__x86_64__)
/*
 * Macro:  vm_page_queue_remove_first_with_clump
 * Function:
 *     Remove and return the entry at the head of the free queue
 *     end is set to 1 to indicate that we just returned the last page in a clump
 *
 * Header:
 *     vm_page_queue_remove_first_with_clump(head, entry, end)
 *     entry is returned by reference
 *     end is returned by reference
 */
#define vm_page_queue_remove_first_with_clump(head, entry, end)              \
MACRO_BEGIN                                                                  \
	vm_page_packed_t __pck_head = VM_PAGE_PACK_PTR(head);                \
	vm_page_packed_t __pck_next;                                         \
	vm_page_t        __next;                                             \
                                                                             \
	(entry) = (vm_page_t)VM_PAGE_UNPACK_PTR((head)->next);               \
	__pck_next = (entry)->vmp_pageq.next;                                \
	__next = (vm_page_t)VM_PAGE_UNPACK_PTR(__pck_next);                  \
                                                                             \
	(end) = 0;                                                           \
	if (__pck_head == __pck_next) {                                      \
	        (head)->prev = __pck_head;                                   \
	        (end) = 1;                                                   \
	} else {                                                             \
	        __next->vmp_pageq.prev = __pck_head;                         \
	        if (VM_PAGE_GET_CLUMP(entry) != VM_PAGE_GET_CLUMP(__next)) { \
	                (end) = 1;                                           \
	        }                                                            \
	}                                                                    \
                                                                             \
	(head)->next = __pck_next;                                           \
	(entry)->vmp_pageq.next = 0;                                         \
	(entry)->vmp_pageq.prev = 0;                                         \
MACRO_END
#endif

/*
 *	Macro:	vm_page_queue_end
 *	Function:
 *	Tests whether a new entry is really the end of
 *		the queue.
 *	Header:
 *		boolean_t vm_page_queue_end(q, qe)
 *			vm_page_queue_t q;
 *			vm_page_queue_entry_t qe;
 */
#define vm_page_queue_end(q, qe)        ((q) == (qe))


/*
 *	Macro:	vm_page_queue_empty
 *	Function:
 *		Tests whether a queue is empty.
 *	Header:
 *		boolean_t vm_page_queue_empty(q)
 *			vm_page_queue_t q;
 */
#define vm_page_queue_empty(q)          vm_page_queue_end((q), ((vm_page_queue_entry_t)vm_page_queue_first(q)))



/*
 *	Macro:	vm_page_queue_first
 *	Function:
 *		Returns the first entry in the queue,
 *	Header:
 *		uintpr_t vm_page_queue_first(q)
 *			vm_page_queue_t q;	\* IN *\
 */
#define vm_page_queue_first(q)          (VM_PAGE_UNPACK_PTR((q)->next))



/*
 *	Macro:		vm_page_queue_last
 *	Function:
 *		Returns the last entry in the queue.
 *	Header:
 *		vm_page_queue_entry_t queue_last(q)
 *			queue_t	q;		\* IN *\
 */
#define vm_page_queue_last(q)           (VM_PAGE_UNPACK_PTR((q)->prev))



/*
 *	Macro:	vm_page_queue_next
 *	Function:
 *		Returns the entry after an item in the queue.
 *	Header:
 *		uintpr_t vm_page_queue_next(qc)
 *			vm_page_queue_t qc;
 */
#define vm_page_queue_next(qc)          (VM_PAGE_UNPACK_PTR((qc)->next))



/*
 *	Macro:	vm_page_queue_prev
 *	Function:
 *		Returns the entry before an item in the queue.
 *	Header:
 *		uinptr_t vm_page_queue_prev(qc)
 *			vm_page_queue_t qc;
 */
#define vm_page_queue_prev(qc)          (VM_PAGE_UNPACK_PTR((qc)->prev))



/*
 *	Macro:	vm_page_queue_iterate
 *	Function:
 *		iterate over each item in a vm_page queue.
 *		Generates a 'for' loop, setting elt to
 *		each item in turn (by reference).
 *	Header:
 *		vm_page_queue_iterate(q, elt, field)
 *			queue_t q;
 *			vm_page_t elt;
 *			<field> is the chain field in vm_page_t
 */
#define vm_page_queue_iterate(head, elt, field)                       \
	for ((elt) = (vm_page_t)vm_page_queue_first(head);            \
	    !vm_page_queue_end((head), (vm_page_queue_entry_t)(elt)); \
	    (elt) = (vm_page_t)vm_page_queue_next(&(elt)->field))     \


/*
 * VM_PAGE_MIN_SPECULATIVE_AGE_Q through vm_page_max_speculative_age_q
 * represents a set of aging bins that are 'protected'...
 *
 * VM_PAGE_SPECULATIVE_AGED_Q is a list of the speculative pages that have
 * not yet been 'claimed' but have been aged out of the protective bins
 * this occurs in vm_page_speculate when it advances to the next bin
 * and discovers that it is still occupied... at that point, all of the
 * pages in that bin are moved to the VM_PAGE_SPECULATIVE_AGED_Q.  the pages
 * in that bin are all guaranteed to have reached at least the maximum age
 * we allow for a protected page... they can be older if there is no
 * memory pressure to pull them from the bin, or there are no new speculative pages
 * being generated to push them out.
 * this list is the one that vm_pageout_scan will prefer when looking
 * for pages to move to the underweight free list
 *
 * vm_page_max_speculative_age_q * VM_PAGE_SPECULATIVE_Q_AGE_MS
 * defines the amount of time a speculative page is normally
 * allowed to live in the 'protected' state (i.e. not available
 * to be stolen if vm_pageout_scan is running and looking for
 * pages)...  however, if the total number of speculative pages
 * in the protected state exceeds our limit (defined in vm_pageout.c)
 * and there are none available in VM_PAGE_SPECULATIVE_AGED_Q, then
 * vm_pageout_scan is allowed to steal pages from the protected
 * bucket even if they are underage.
 *
 * vm_pageout_scan is also allowed to pull pages from a protected
 * bin if the bin has reached the "age of consent" we've set
 */
#define VM_PAGE_RESERVED_SPECULATIVE_AGE_Q      40
#define VM_PAGE_DEFAULT_MAX_SPECULATIVE_AGE_Q   10
#define VM_PAGE_MIN_SPECULATIVE_AGE_Q   1
#define VM_PAGE_SPECULATIVE_AGED_Q      0

#define VM_PAGE_SPECULATIVE_Q_AGE_MS    500

struct vm_speculative_age_q {
	/*
	 * memory queue for speculative pages via clustered pageins
	 */
	vm_page_queue_head_t    age_q;
	mach_timespec_t age_ts;
} VM_PAGE_PACKED_ALIGNED;



extern
struct vm_speculative_age_q     vm_page_queue_speculative[];

extern int                      speculative_steal_index;
extern int                      speculative_age_index;
extern unsigned int             vm_page_speculative_q_age_ms;
extern unsigned int             vm_page_max_speculative_age_q;


typedef struct vm_locks_array {
	char    pad  __attribute__ ((aligned(64)));
	lck_mtx_t       vm_page_queue_lock2 __attribute__ ((aligned(64)));
	lck_mtx_t       vm_page_queue_free_lock2 __attribute__ ((aligned(64)));
	char    pad2  __attribute__ ((aligned(64)));
} vm_locks_array_t;


#define VM_PAGE_WIRED(m)        (((m)->vmp_q_state == VM_PAGE_IS_WIRED) || ((m)->vmp_q_state == VM_PAGE_IS_IOPL_WIRED))
#define VM_PAGE_IOPL_WIRED(m)   ((m)->vmp_q_state == VM_PAGE_IS_IOPL_WIRED)
#define NEXT_PAGE(m)            ((m)->vmp_snext)
#define NEXT_PAGE_PTR(m)        (&(m)->vmp_snext)

/*!
 * @abstract
 * Represents a singly linked list of pages with a count.
 *
 * @discussion
 * This type is used as a way to exchange transient collections of VM pages
 * by various subsystems.
 *
 * This type is designed to be less than sizeof(_Complex) which means
 * it that can be passed by value efficiently (either as a function argument
 * or its result).
 *
 *
 * @field vmpl_head
 * The head of the list, or VM_PAGE_NULL.
 *
 * @field vmpl_count
 * How many pages are on that list.
 *
 * @field vmpl_has_realtime
 * At least one page on the list has vmp_realtime set.
 */
#if HAS_MTE
/*
 * @field vmpl_has_untagged
 * Whether there are pages with the @c vmp_using_mte property unset on it.
 *
 * It can be used by callers to know that they need to adjust the tagging
 * properties of the list with @c pmap_{un,}make_tagged_pages().
 *
 * @field vmpl_has_tagged
 * Whether there are pages with the @c vmp_using_mte property set on it.
 *
 * It can be used by callers to know that they need to adjust the tagging
 * properties of the list with @c pmap_{un,}make_tagged_pages().
 */
#endif
typedef struct {
	vm_page_t vmpl_head;
	uint32_t  vmpl_count;
	bool      vmpl_has_realtime;
#if HAS_MTE
	bool      vmpl_has_untagged;
	bool      vmpl_has_tagged;
#endif
} vm_page_list_t;


/*!
 * @abstract
 * Low level function that pushes a page on a naked singly linked list of VM
 * pages.
 *
 * @param head          The list head.
 * @param mem           The page to push on the list.
 */
static inline void
_vm_page_list_push(vm_page_t *head, vm_page_t mem)
{
	NEXT_PAGE(mem) = *head;
	*head = mem;
}

/*!
 * @abstract
 * Pushes a page onto a VM page list, adjusting its properties.
 *
 * @param list          The VM page list to push onto
 * @param mem           The page to push on the list.
 */
static inline void
vm_page_list_push(vm_page_list_t *list, vm_page_t mem)
{
	_vm_page_list_push(&list->vmpl_head, mem);
	list->vmpl_count++;
	if (mem->vmp_realtime) {
		list->vmpl_has_realtime = true;
	}
#if HAS_MTE
	if (mem->vmp_using_mte) {
		list->vmpl_has_tagged = true;
	} else {
		list->vmpl_has_untagged = true;
	}
#endif
}

/*!
 * @abstract
 * Conveniency function that creates a VM page list from a single page.
 *
 * @param mem           The VM page to put on the list.
 */
static inline vm_page_list_t
vm_page_list_for_page(vm_page_t mem)
{
	assert(NEXT_PAGE(mem) == VM_PAGE_NULL);
	return (vm_page_list_t){
		       .vmpl_head  = mem,
		       .vmpl_count = 1,
		       .vmpl_has_realtime = mem->vmp_realtime,
#if HAS_MTE
		       .vmpl_has_untagged = !mem->vmp_using_mte,
		       .vmpl_has_tagged = mem->vmp_using_mte,
#endif
	};
}

/*!
 * @abstract
 * Low level function that pops a page from a naked singly linked list of VM
 * pages.
 *
 * @param head          The list head.
 *
 * @returns             The first page that was on the list
 *                      or VM_PAGE_NULL if it was empty.
 */
static inline vm_page_t
_vm_page_list_pop(vm_page_t *head)
{
	vm_page_t mem = *head;

	if (mem) {
		*head = NEXT_PAGE(mem);
		VM_PAGE_ZERO_PAGEQ_ENTRY(mem);
	}

	return mem;
}

/*!
 * @abstract
 * Pops a page from a VM page list, adjusting its properties.
 *
 * @param list          The VM page list to pop from.
 *
 * @returns             The first page that was on the list
 *                      or VM_PAGE_NULL if it was empty.
 */
static inline vm_page_t
vm_page_list_pop(vm_page_list_t *list)
{
	if (list->vmpl_head) {
		list->vmpl_count--;
		return _vm_page_list_pop(&list->vmpl_head);
	}
	*list = (vm_page_list_t){ };
	return VM_PAGE_NULL;
}


/*!
 * @abstract
 * Reverses a list of VM pages in place.
 *
 * @param list          The VM page list to reverse.
 */
static inline void
vm_page_list_reverse(vm_page_list_t *list)
{
	vm_page_t cur, next;

	cur = list->vmpl_head;
	list->vmpl_head = NULL;

	while (cur) {
		next = NEXT_PAGE(cur);
		_vm_page_list_push(&list->vmpl_head, cur);
		cur = next;
	}
}


/*!
 * @abstract
 * Low level iterator over all pages on a naked singly linked list
 * of VM pages.
 *
 * @discussion
 * Mutating the list during enumeration is undefined.
 *
 * @param mem           The variable to use for iteration.
 * @param head          The list head.
 */
#define _vm_page_list_foreach(mem, list) \
	for ((mem) = (list); (mem); (mem) = NEXT_PAGE(mem))


/*!
 * @abstract
 * Iterator over a VM page list.
 *
 * @discussion
 * Mutating the list during enumeration is undefined.
 *
 * @param mem           The variable to use for iteration.
 * @param head          The list head.
 */
#define vm_page_list_foreach(mem, list) \
	_vm_page_list_foreach(mem, (list).vmpl_head)


/*!
 * @abstract
 * Low level iterator over all pages on a naked singly linked list
 * of VM pages, that also consumes the list as it iterates.
 *
 * @discussion
 * Each element is removed from the list as it is being iterated.
 *
 * @param mem           The variable to use for iteration.
 * @param head          The list head.
 */
#define _vm_page_list_foreach_consume(mem, list) \
	while (((mem) = _vm_page_list_pop((list))))

/*!
 * @abstract
 * Iterator over a VM page list, that consumes the list.
 *
 * @discussion
 * Each element is removed from the list as it is being iterated.
 *
 * @param mem           The variable to use for iteration.
 * @param head          The list head.
 */
#define vm_page_list_foreach_consume(mem, list) \
	while (((mem) = vm_page_list_pop((list))))


/*
 * XXX	The unusual bit should not be necessary.  Most of the bit
 * XXX	fields above really want to be masks.
 */

/*
 *	For debugging, this macro can be defined to perform
 *	some useful check on a page structure.
 *	INTENTIONALLY left as a no-op so that the
 *	current call-sites can be left intact for future uses.
 */

#define VM_PAGE_CHECK(mem)                      \
	MACRO_BEGIN                             \
	MACRO_END

/*     Page coloring:
 *
 *     The free page list is actually n lists, one per color,
 *     where the number of colors is a function of the machine's
 *     cache geometry set at system initialization.  To disable
 *     coloring, set vm_colors to 1 and vm_color_mask to 0.
 *     The boot-arg "colors" may be used to override vm_colors.
 *     Note that there is little harm in having more colors than needed.
 */

#define MAX_COLORS      128
#define DEFAULT_COLORS  32

/*
 * Page free queue type.  Abstracts the notion of a free queue of pages, that
 * contains free pages of a particular memory class, and maintains a count of
 * the number of pages in the free queue.
 *
 * Pages in the queue will be marked VM_PAGE_ON_FREE_Q when they are added to
 * the free queue, and VM_PAGE_NOT_ON_Q when they are removed.
 *
 * These free queues will color pages, consistent with MachVMs color mask.
 */
typedef struct vm_page_free_queue {
	struct vm_page_queue_free_head vmpfq_queues[MAX_COLORS];
	uint32_t                       vmpfq_count;
} *vm_page_free_queue_t;

extern unsigned int    vm_colors;              /* must be in range 1..MAX_COLORS */
extern unsigned int    vm_color_mask;          /* must be (vm_colors-1) */
extern unsigned int    vm_cache_geometry_colors; /* optimal #colors based on cache geometry */
extern unsigned int    vm_free_magazine_refill_limit;

/*
 * Wired memory is a very limited resource and we can't let users exhaust it
 * and deadlock the entire system.  We enforce the following limits:
 *
 * vm_per_task_user_wire_limit
 *      how much memory can be user-wired in one user task
 *
 * vm_global_user_wire_limit (default: same as vm_per_task_user_wire_limit)
 *      how much memory can be user-wired in all user tasks
 *
 * These values are set to defaults based on the number of pages managed
 * by the VM system. They can be overriden via sysctls.
 * See kmem_set_user_wire_limits for details on the default values.
 *
 * Regardless of the amount of memory in the system, we never reserve
 * more than VM_NOT_USER_WIREABLE_MAX bytes as unlockable.
 */
#define VM_NOT_USER_WIREABLE_MAX (32ULL*1024*1024*1024)     /* 32GB */

extern vm_map_size_t   vm_per_task_user_wire_limit;
extern vm_map_size_t   vm_global_user_wire_limit;
extern uint64_t        vm_add_wire_count_over_global_limit;
extern uint64_t        vm_add_wire_count_over_user_limit;

/*
 *	Each pageable resident page falls into one of three lists:
 *
 *	free
 *		Available for allocation now.  The free list is
 *		actually an array of lists, one per color.
 *	inactive
 *		Not referenced in any map, but still has an
 *		object/offset-page mapping, and may be dirty.
 *		This is the list of pages that should be
 *		paged out next.  There are actually two
 *		inactive lists, one for pages brought in from
 *		disk or other backing store, and another
 *		for "zero-filled" pages.  See vm_pageout_scan()
 *		for the distinction and usage.
 *	active
 *		A list of pages which have been placed in
 *		at least one physical map.  This list is
 *		ordered, in LRU-like fashion.
 */


#define VPL_LOCK_SPIN 1

struct vpl {
	vm_page_queue_head_t    vpl_queue;
	unsigned int    vpl_count;
	unsigned int    vpl_internal_count;
	unsigned int    vpl_external_count;
	lck_spin_t      vpl_lock;
};

extern
struct vpl     * /* __zpercpu */ vm_page_local_q;
extern
unsigned int    vm_page_local_q_soft_limit;
extern
unsigned int    vm_page_local_q_hard_limit;
extern
vm_locks_array_t vm_page_locks;

extern
vm_page_queue_head_t    vm_page_queue_active;   /* active memory queue */
extern
vm_page_queue_head_t    vm_page_queue_inactive; /* inactive memory queue for normal pages */
#if CONFIG_SECLUDED_MEMORY
extern
vm_page_queue_head_t    vm_page_queue_secluded; /* reclaimable pages secluded for Camera */
#endif /* CONFIG_SECLUDED_MEMORY */
extern
vm_page_queue_head_t    vm_page_queue_cleaned; /* clean-queue inactive memory */
extern
vm_page_queue_head_t    vm_page_queue_anonymous;        /* inactive memory queue for anonymous pages */
extern
vm_page_queue_head_t    vm_page_queue_throttled;        /* memory queue for throttled pageout pages */

extern
queue_head_t    vm_objects_wired;
extern
lck_spin_t      vm_objects_wired_lock;

#define VM_PAGE_DONATE_DISABLED     0
#define VM_PAGE_DONATE_ENABLED      1
extern
uint32_t        vm_page_donate_mode;
extern
bool        vm_page_donate_queue_ripe;

#define VM_PAGE_BACKGROUND_TARGET_MAX   50000
#define VM_PAGE_BG_DISABLED     0
#define VM_PAGE_BG_ENABLED     1

extern
vm_page_queue_head_t    vm_page_queue_background;
extern
uint64_t        vm_page_background_promoted_count;
extern
uint32_t        vm_page_background_count;
extern
uint32_t        vm_page_background_target;
extern
uint32_t        vm_page_background_internal_count;
extern
uint32_t        vm_page_background_external_count;
extern
uint32_t        vm_page_background_mode;
extern
uint32_t        vm_page_background_exclude_external;

extern
vm_page_queue_head_t    vm_page_queue_donate;
extern
uint32_t        vm_page_donate_count;
extern
uint32_t        vm_page_donate_target_low;
extern
uint32_t        vm_page_donate_target_high;
#define VM_PAGE_DONATE_TARGET_LOWWATER  (100)
#define VM_PAGE_DONATE_TARGET_HIGHWATER ((unsigned int)(atop_64(max_mem) / 8))

extern
vm_offset_t     first_phys_addr;        /* physical address for first_page */
extern
vm_offset_t     last_phys_addr;         /* physical address for last_page */

extern
unsigned int    vm_page_free_count;     /* How many pages are free? (sum of all colors) */
extern
unsigned int    vm_page_active_count;   /* How many pages are active? */
extern
unsigned int    vm_page_inactive_count; /* How many pages are inactive? */
extern
unsigned int vm_page_kernelcache_count; /* How many pages are used for the kernelcache? */
extern
unsigned int vm_page_realtime_count;    /* How many pages are used by realtime threads? */
#if CONFIG_SECLUDED_MEMORY
extern
unsigned int    vm_page_secluded_count; /* How many pages are secluded? */
extern
unsigned int    vm_page_secluded_count_free; /* how many of them are free? */
extern
unsigned int    vm_page_secluded_count_inuse; /* how many of them are in use? */
/*
 * We keep filling the secluded pool with new eligible pages and
 * we can overshoot our target by a lot.
 * When there's memory pressure, vm_pageout_scan() will re-balance the queues,
 * pushing the extra secluded pages to the active or free queue.
 * Since these "over target" secluded pages are actually "available", jetsam
 * should consider them as such, so make them visible to jetsam via the
 * "vm_page_secluded_count_over_target" counter and update it whenever we
 * update vm_page_secluded_count or vm_page_secluded_target.
 */
extern
unsigned int    vm_page_secluded_count_over_target;
#define VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE()                     \
	MACRO_BEGIN                                                     \
	if (vm_page_secluded_count > vm_page_secluded_target) {         \
	        vm_page_secluded_count_over_target =                    \
	                (vm_page_secluded_count - vm_page_secluded_target); \
	} else {                                                        \
	        vm_page_secluded_count_over_target = 0;                 \
	}                                                               \
	MACRO_END
#define VM_PAGE_SECLUDED_COUNT_OVER_TARGET() vm_page_secluded_count_over_target
#else /* CONFIG_SECLUDED_MEMORY */
#define VM_PAGE_SECLUDED_COUNT_OVER_TARGET_UPDATE() \
	MACRO_BEGIN                                 \
	MACRO_END
#define VM_PAGE_SECLUDED_COUNT_OVER_TARGET() 0
#endif /* CONFIG_SECLUDED_MEMORY */
extern
unsigned int    vm_page_cleaned_count; /* How many pages are in the clean queue? */
extern
unsigned int    vm_page_throttled_count;/* How many inactives are throttled */
extern
unsigned int    vm_page_speculative_count;      /* How many speculative pages are unclaimed? */
extern unsigned int     vm_page_pageable_internal_count;
extern unsigned int     vm_page_pageable_external_count;
extern
unsigned int    vm_page_xpmapped_external_count;        /* How many pages are mapped executable? */
SCALABLE_COUNTER_DECLARE(vm_page_external_count);       /* How many pages are file-backed? */
SCALABLE_COUNTER_DECLARE(vm_page_internal_count);       /* How many pages are file-backed? */
extern
unsigned int    vm_page_wire_count;             /* How many pages are wired? */
extern
unsigned int    vm_page_wire_count_initial;     /* How many pages wired at startup */
extern
unsigned int    vm_page_wire_count_on_boot;     /* even earlier than _initial */
extern
unsigned int    vm_page_free_target;    /* How many do we want free? */
extern
unsigned int    vm_page_free_min;       /* When to wakeup pageout */
extern
unsigned int    vm_page_throttle_limit; /* When to throttle new page creation */
extern
unsigned int    vm_page_inactive_target;/* How many do we want inactive? */
#if CONFIG_SECLUDED_MEMORY
extern
unsigned int    vm_page_secluded_target;/* How many do we want secluded? */
#endif /* CONFIG_SECLUDED_MEMORY */
extern
unsigned int    vm_page_anonymous_min;  /* When it's ok to pre-clean */
extern
unsigned int    vm_page_free_reserved;  /* How many pages reserved to do pageout */
extern
unsigned int    vm_page_gobble_count;
extern
unsigned int    vm_page_stolen_count;   /* Count of stolen pages not acccounted in zones */
extern
unsigned int    vm_page_kern_lpage_count;   /* Count of large pages used in early boot */


#if DEVELOPMENT || DEBUG
extern
unsigned int    vm_page_speculative_used;
#endif

SCALABLE_COUNTER_DECLARE(vm_page_purgeable_count);      /* How many pages are purgeable now ? */
SCALABLE_COUNTER_DECLARE(vm_page_purgeable_wired_count);/* How many purgeable pages are wired now ? */
extern uint64_t        vm_page_purged_count;            /* How many pages got purged so far ? */

extern
_Atomic unsigned int vm_page_swapped_count;
/* How many pages are swapped to disk? */

extern
_Atomic uint64_t vm_page_swap_count;
/* How many pages of compressed data are present in the swapfile? */

extern
_Atomic unsigned int vm_page_shared_region_count;
/* How many resident pages are backed by a shared region pager? */

extern unsigned int     vm_page_free_wanted;
/* how many threads are waiting for memory */

extern unsigned int     vm_page_free_wanted_privileged;
/* how many VM privileged threads are waiting for memory */
#if CONFIG_SECLUDED_MEMORY
extern unsigned int     vm_page_free_wanted_secluded;
/* how many threads are waiting for secluded memory */
#endif /* CONFIG_SECLUDED_MEMORY */

extern const ppnum_t    vm_page_fictitious_addr;
/* (fake) phys_addr of fictitious pages */

extern const ppnum_t    vm_page_guard_addr;
/* (fake) phys_addr of guard pages */


extern boolean_t        vm_page_deactivate_hint;

#if __x86_64__
/*
 * Defaults to true, so highest memory is used first.
 */
extern boolean_t        vm_himemory_mode;
#else
#define vm_himemory_mode TRUE
#endif

#if XNU_VM_HAS_LOPAGE
extern bool             vm_lopage_needed;
extern bool             vm_lopage_refill;
extern uint32_t         vm_lopage_free_count;
extern uint32_t         vm_lopage_free_limit;
extern uint32_t         vm_lopage_lowater;
#else
#define vm_lopage_needed        0
#define vm_lopage_free_count    0
#endif
extern uint64_t         max_valid_dma_address;
extern ppnum_t          max_valid_low_ppnum;

/*!
 * @abstract
 * Options that alter the behavior of vm_page_grab_options().
 *
 * @const VM_PAGE_GRAB_OPTIONS_NONE
 * The default value when no other specific options are required.
 *
 * @const VM_PAGE_GRAB_Q_LOCK_HELD
 * Denotes the caller is holding the vm page queues lock held.
 *
 * @const VM_PAGE_GRAB_NOPAGEWAIT
 * Denotes that the caller never wants @c vm_page_grab_options() to call
 * @c VM_PAGE_WAIT(), even if the thread is privileged.
 *
 * @const VM_PAGE_GRAB_VM_PRIV
 * The caller thread is VM privileged.
 *
 * @const VM_PAGE_GRAB_PRIME
 * The caller doesn't expect to receive a VM page, it just means for the per-cpu
 * queues to be primed. @c VM_PAGE_PRIMED will be returned if priming was
 * successful.
 *
 * @const VM_PAGE_GRAB_ZERO_FILL
 * Grab a zero filled page (or zero fill the page returned)
 *
 * @const VM_PAGE_GRAB_SECLUDED
 * The caller is eligible to the secluded pool.
 */
#if HAS_MTE
/*
 * @const VM_PAGE_GRAB_MTE
 * The grabbed page must have MTE tagging enabled.
 *
 * @const VM_PAGE_GRAB_ALLOW_TAG_STORAGE
 * The grabbed page can be a claimed tag storage page.
 */
#endif
__enum_decl(vm_grab_options_t, uint32_t, {
	VM_PAGE_GRAB_OPTIONS_NONE       = 0x00000000,
	VM_PAGE_GRAB_Q_LOCK_HELD        = 0x00000001,
	VM_PAGE_GRAB_NOPAGEWAIT         = 0x00000002,
	VM_PAGE_GRAB_VM_PRIV            = 0x00000004,
	VM_PAGE_GRAB_PRIME              = 0x00000008,
	VM_PAGE_GRAB_ZERO_FILL          = 0x00000010,

	/* architecture/platform-specific flags */
#if CONFIG_SECLUDED_MEMORY
	VM_PAGE_GRAB_SECLUDED           = 0x00010000,
#endif /* CONFIG_SECLUDED_MEMORY */
#if HAS_MTE
	VM_PAGE_GRAB_MTE                = 0x00020000,
	VM_PAGE_GRAB_ALLOW_TAG_STORAGE  = 0x00040000,
#endif /* HAS_MTE */
});

/*
 * Prototypes for functions exported by this module.
 */

extern void             vm_page_init_local_q(unsigned int num_cpus);

extern vm_page_t        vm_page_create(ppnum_t phys_page, bool canonical, zalloc_flags_t flags);
extern void             vm_page_create_canonical(ppnum_t pnum);

extern void             vm_page_create_retired(ppnum_t pn);

#if XNU_VM_HAS_DELAYED_PAGES
extern void             vm_free_delayed_pages(void);
#endif /* XNU_VM_HAS_DELAYED_PAGES */

extern void             vm_pages_array_finalize(void);

extern void             vm_page_reactivate_all_throttled(void);

extern void vm_pressure_response(void);

#define AVAILABLE_NON_COMPRESSED_MEMORY         (vm_page_active_count + vm_page_inactive_count + vm_page_free_count + vm_page_speculative_count)
#define AVAILABLE_MEMORY                        (AVAILABLE_NON_COMPRESSED_MEMORY + VM_PAGE_COMPRESSOR_COUNT)

#if CONFIG_JETSAM

#define VM_CHECK_MEMORYSTATUS \
	memorystatus_update_available_page_count( \
	        vm_page_pageable_external_count + \
	        vm_page_free_count +              \
	        VM_PAGE_SECLUDED_COUNT_OVER_TARGET() + \
	        (VM_DYNAMIC_PAGING_ENABLED() ? 0 : (uint32_t)counter_load(&vm_page_purgeable_count)) \
	        )

#else /* CONFIG_JETSAM */

#if !XNU_TARGET_OS_OSX

#define VM_CHECK_MEMORYSTATUS do {} while(0)

#else /* !XNU_TARGET_OS_OSX */

#define VM_CHECK_MEMORYSTATUS memorystatus_update_available_page_count(AVAILABLE_NON_COMPRESSED_MEMORY)

#endif /* !XNU_TARGET_OS_OSX */

#endif /* CONFIG_JETSAM */

#define vm_page_queue_lock (vm_page_locks.vm_page_queue_lock2)
#define vm_page_queue_free_lock (vm_page_locks.vm_page_queue_free_lock2)

#ifdef MACH_KERNEL_PRIVATE
static inline void
vm_page_lock_queues(void)
{
	lck_mtx_lock(&vm_page_queue_lock);
}

static inline boolean_t
vm_page_trylock_queues(void)
{
	boolean_t ret;
	ret = lck_mtx_try_lock(&vm_page_queue_lock);
	return ret;
}

static inline void
vm_page_unlock_queues(void)
{
	lck_mtx_unlock(&vm_page_queue_lock);
}

static inline void
vm_page_lockspin_queues(void)
{
	lck_mtx_lock_spin(&vm_page_queue_lock);
}

static inline boolean_t
vm_page_trylockspin_queues(void)
{
	boolean_t ret;
	ret = lck_mtx_try_lock_spin(&vm_page_queue_lock);
	return ret;
}

extern void kdp_vm_page_sleep_find_owner(
	event64_t          wait_event,
	thread_waitinfo_t *waitinfo);

#endif /* MACH_KERNEL_PRIVATE */

extern unsigned int vm_max_delayed_work_limit;

#if CONFIG_SECLUDED_MEMORY
extern uint64_t secluded_shutoff_trigger;
extern uint64_t secluded_shutoff_headroom;
extern void start_secluded_suppression(task_t);
extern void stop_secluded_suppression(task_t);
#endif /* CONFIG_SECLUDED_MEMORY */

#endif  /* _VM_VM_PAGE_H_ */
