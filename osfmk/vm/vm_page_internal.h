/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_PAGE_INTERNAL_H_
#define _VM_VM_PAGE_INTERNAL_H_

#include <sys/cdefs.h>
#include <vm/vm_page.h>

__BEGIN_DECLS
#ifdef XNU_KERNEL_PRIVATE

struct vm_page_queue_free_head {
	vm_page_queue_head_t    qhead;
} VM_PAGE_PACKED_ALIGNED;

extern struct vm_page_queue_free_head  vm_page_queue_free[MAX_COLORS];

static inline int
VMP_CS_FOR_OFFSET(
	vm_map_offset_t fault_phys_offset)
{
	assertf(fault_phys_offset < PAGE_SIZE &&
	    !(fault_phys_offset & FOURK_PAGE_MASK),
	    "offset 0x%llx\n", (uint64_t)fault_phys_offset);
	return 1 << (fault_phys_offset >> FOURK_PAGE_SHIFT);
}
static inline bool
VMP_CS_VALIDATED(
	vm_page_t p,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset)
{
	assertf(fault_page_size <= PAGE_SIZE,
	    "fault_page_size 0x%llx fault_phys_offset 0x%llx\n",
	    (uint64_t)fault_page_size, (uint64_t)fault_phys_offset);
	if (fault_page_size == PAGE_SIZE) {
		return p->vmp_cs_validated == VMP_CS_ALL_TRUE;
	}
	return p->vmp_cs_validated & VMP_CS_FOR_OFFSET(fault_phys_offset);
}
static inline bool
VMP_CS_TAINTED(
	vm_page_t p,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset)
{
	assertf(fault_page_size <= PAGE_SIZE,
	    "fault_page_size 0x%llx fault_phys_offset 0x%llx\n",
	    (uint64_t)fault_page_size, (uint64_t)fault_phys_offset);
	if (fault_page_size == PAGE_SIZE) {
		return p->vmp_cs_tainted != VMP_CS_ALL_FALSE;
	}
	return p->vmp_cs_tainted & VMP_CS_FOR_OFFSET(fault_phys_offset);
}
static inline bool
VMP_CS_NX(
	vm_page_t p,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset)
{
	assertf(fault_page_size <= PAGE_SIZE,
	    "fault_page_size 0x%llx fault_phys_offset 0x%llx\n",
	    (uint64_t)fault_page_size, (uint64_t)fault_phys_offset);
	if (fault_page_size == PAGE_SIZE) {
		return p->vmp_cs_nx != VMP_CS_ALL_FALSE;
	}
	return p->vmp_cs_nx & VMP_CS_FOR_OFFSET(fault_phys_offset);
}
static inline void
VMP_CS_SET_VALIDATED(
	vm_page_t p,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset,
	boolean_t value)
{
	assertf(fault_page_size <= PAGE_SIZE,
	    "fault_page_size 0x%llx fault_phys_offset 0x%llx\n",
	    (uint64_t)fault_page_size, (uint64_t)fault_phys_offset);
	if (value) {
		if (fault_page_size == PAGE_SIZE) {
			p->vmp_cs_validated = VMP_CS_ALL_TRUE;
		}
		p->vmp_cs_validated |= VMP_CS_FOR_OFFSET(fault_phys_offset);
	} else {
		if (fault_page_size == PAGE_SIZE) {
			p->vmp_cs_validated = VMP_CS_ALL_FALSE;
		}
		p->vmp_cs_validated &= ~VMP_CS_FOR_OFFSET(fault_phys_offset);
	}
}
static inline void
VMP_CS_SET_TAINTED(
	vm_page_t p,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset,
	boolean_t value)
{
	assertf(fault_page_size <= PAGE_SIZE,
	    "fault_page_size 0x%llx fault_phys_offset 0x%llx\n",
	    (uint64_t)fault_page_size, (uint64_t)fault_phys_offset);
	if (value) {
		if (fault_page_size == PAGE_SIZE) {
			p->vmp_cs_tainted = VMP_CS_ALL_TRUE;
		}
		p->vmp_cs_tainted |= VMP_CS_FOR_OFFSET(fault_phys_offset);
	} else {
		if (fault_page_size == PAGE_SIZE) {
			p->vmp_cs_tainted = VMP_CS_ALL_FALSE;
		}
		p->vmp_cs_tainted &= ~VMP_CS_FOR_OFFSET(fault_phys_offset);
	}
}
static inline void
VMP_CS_SET_NX(
	vm_page_t p,
	vm_map_size_t fault_page_size,
	vm_map_offset_t fault_phys_offset,
	boolean_t value)
{
	assertf(fault_page_size <= PAGE_SIZE,
	    "fault_page_size 0x%llx fault_phys_offset 0x%llx\n",
	    (uint64_t)fault_page_size, (uint64_t)fault_phys_offset);
	if (value) {
		if (fault_page_size == PAGE_SIZE) {
			p->vmp_cs_nx = VMP_CS_ALL_TRUE;
		}
		p->vmp_cs_nx |= VMP_CS_FOR_OFFSET(fault_phys_offset);
	} else {
		if (fault_page_size == PAGE_SIZE) {
			p->vmp_cs_nx = VMP_CS_ALL_FALSE;
		}
		p->vmp_cs_nx &= ~VMP_CS_FOR_OFFSET(fault_phys_offset);
	}
}


#if defined(__LP64__)
static __inline__ void
vm_page_enqueue_tail(
	vm_page_queue_t         que,
	vm_page_queue_entry_t   elt)
{
	vm_page_queue_entry_t   old_tail;

	old_tail = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(que->prev);
	elt->next = VM_PAGE_PACK_PTR(que);
	elt->prev = que->prev;
	que->prev = old_tail->next = VM_PAGE_PACK_PTR(elt);
}

static __inline__ void
vm_page_remque(
	vm_page_queue_entry_t elt)
{
	vm_page_queue_entry_t next;
	vm_page_queue_entry_t prev;
	vm_page_packed_t      next_pck = elt->next;
	vm_page_packed_t      prev_pck = elt->prev;

	next = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(next_pck);

	/* next may equal prev (and the queue head) if elt was the only element */
	prev = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(prev_pck);

	next->prev = prev_pck;
	prev->next = next_pck;

	elt->next = 0;
	elt->prev = 0;
}

#if defined(__x86_64__)
/*
 * Insert a new page into a free queue and clump pages within the same 16K boundary together
 */
static inline void
vm_page_queue_enter_clump(
	vm_page_queue_t       head,
	vm_page_t             elt)
{
	vm_page_queue_entry_t first = NULL;    /* first page in the clump */
	vm_page_queue_entry_t last = NULL;     /* last page in the clump */
	vm_page_queue_entry_t prev = NULL;
	vm_page_queue_entry_t next;
	uint_t                n_free = 1;
	extern unsigned int   vm_clump_size, vm_clump_promote_threshold;
	extern unsigned long  vm_clump_allocs, vm_clump_inserts, vm_clump_inrange, vm_clump_promotes;

	/*
	 * If elt is part of the vm_pages[] array, find its neighboring buddies in the array.
	 */
	if (vm_page_in_array(elt)) {
		vm_page_t p;
		uint_t    i;
		uint_t    n;
		ppnum_t   clump_num;

		first = last = (vm_page_queue_entry_t)elt;
		clump_num = VM_PAGE_GET_CLUMP(elt);
		n = VM_PAGE_GET_PHYS_PAGE(elt) & vm_clump_mask;

		/*
		 * Check for preceeding vm_pages[] entries in the same chunk
		 */
		for (i = 0, p = elt - 1; i < n && vm_page_get(0) <= p; i++, p--) {
			if (p->vmp_q_state == VM_PAGE_ON_FREE_Q && clump_num == VM_PAGE_GET_CLUMP(p)) {
				if (prev == NULL) {
					prev = (vm_page_queue_entry_t)p;
				}
				first = (vm_page_queue_entry_t)p;
				n_free++;
			}
		}

		/*
		 * Check the following vm_pages[] entries in the same chunk
		 */
		for (i = n + 1, p = elt + 1; i < vm_clump_size && p < vm_page_get(vm_pages_count); i++, p++) {
			if (p->vmp_q_state == VM_PAGE_ON_FREE_Q && clump_num == VM_PAGE_GET_CLUMP(p)) {
				if (last == (vm_page_queue_entry_t)elt) {               /* first one only */
					__DEBUG_CHECK_BUDDIES(prev, p, vmp_pageq);
				}

				if (prev == NULL) {
					prev = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(p->vmp_pageq.prev);
				}
				last = (vm_page_queue_entry_t)p;
				n_free++;
			}
		}
		__DEBUG_STAT_INCREMENT_INRANGE;
	}

	/* if elt is not part of vm_pages or if 1st page in clump, insert at tail */
	if (prev == NULL) {
		prev = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(head->prev);
	}

	/* insert the element */
	next = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(prev->next);
	elt->vmp_pageq.next = prev->next;
	elt->vmp_pageq.prev = next->prev;
	prev->next = next->prev = VM_PAGE_PACK_PTR(elt);
	__DEBUG_STAT_INCREMENT_INSERTS;

	/*
	 * Check if clump needs to be promoted to head.
	 */
	if (n_free >= vm_clump_promote_threshold && n_free > 1) {
		vm_page_queue_entry_t first_prev;

		first_prev = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(first->prev);

		/* If not at head already */
		if (first_prev != head) {
			vm_page_queue_entry_t last_next;
			vm_page_queue_entry_t head_next;

			last_next = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(last->next);

			/* verify that the links within the clump are consistent */
			__DEBUG_VERIFY_LINKS(first, n_free, last_next);

			/* promote clump to head */
			first_prev->next = last->next;
			last_next->prev = first->prev;
			first->prev = VM_PAGE_PACK_PTR(head);
			last->next = head->next;

			head_next = (vm_page_queue_entry_t)VM_PAGE_UNPACK_PTR(head->next);
			head_next->prev = VM_PAGE_PACK_PTR(last);
			head->next = VM_PAGE_PACK_PTR(first);
			__DEBUG_STAT_INCREMENT_PROMOTES(n_free);
		}
	}
}
#endif /* __x86_64__ */
#endif /* __LP64__ */


extern  void    vm_page_assign_special_state(vm_page_t mem, int mode);
extern  void    vm_page_update_special_state(vm_page_t mem);
extern  void    vm_page_add_to_specialq(vm_page_t mem, boolean_t first);
extern  void    vm_page_remove_from_specialq(vm_page_t mem);


/*
 * Prototypes for functions exported by this module.
 */
extern void             vm_page_bootstrap(
	vm_offset_t     *startp,
	vm_offset_t     *endp);

extern vm_page_t        kdp_vm_page_lookup(
	vm_object_t             object,
	vm_object_offset_t      offset);

extern vm_page_t        vm_page_lookup(
	vm_object_t             object,
	vm_object_offset_t      offset);

/*!
 * @abstract
 * Creates a fictitious page.
 *
 * @discussion
 * This function never returns VM_PAGE_NULL;
 *
 * Pages made by this function have the @c vm_page_fictitious_addr
 * fake physical address.
 */
extern vm_page_t        vm_page_create_fictitious(void);

/*!
 * @abstract
 * Returns a kernel guard page (used by @c kmem_alloc_guard()).
 *
 * @discussion
 * Pages returned by this function have the @c vm_page_guard_addr
 * fake physical address.
 *
 * @param canwait       Whether the caller can wait, if true,
 *                      this function never returns VM_PAGE_NULL.
 */
extern vm_page_t        vm_page_create_guard(bool canwait);

/*!
 * @abstract
 * Create a private VM page.
 *
 * @discussion
 * These pages allow for non canonical references to the same physical page.
 * Its @c VM_PAGE_GET_PHYS_PAGE() will be @c base_page.
 *
 * Such pages must not be released back to the free queues directly,
 * @c vm_page_reset_private() must be called first.
 *
 * This function never returns VM_PAGE_NULL
 *
 * @param base_page     The physical page this private page represents.
 */
extern vm_page_t        vm_page_create_private(ppnum_t base_page);

/*!
 * @abstract
 * Returns whether this is the canonical page for a regular managed kernel page.
 *
 * @discussion
 * A kernel page is the canonical @c vm_page_t for a given pmap managed physical
 * page.  These pages are made at startup, or when @c ml_static_mfree() is
 * called, and are never freed.
 *
 * Its @c VM_PAGE_GET_PHYS_PAGE() will be a valid @c ppnum_t value.
 *
 * A page can either be:
 * - a canonical page (@c vm_page_is_canonical())
 * - a fictitious page (@c vm_page_is_fictitious()),
 *   of which guard pages are a special case (@c vm_page_is_guard())
 * - a private page (@c vm_page_is_private())
 */
extern bool             vm_page_is_canonical(const struct vm_page *m) __pure2;

/*!
 * @abstract
 * Returns whether this page is fictitious (made by @c vm_page_create_guard()
 * or by @c vm_page_create_fictitious()).
 *
 * @discussion
 * A page can either be:
 * - a canonical page (@c vm_page_is_canonical())
 * - a fictitious page (@c vm_page_is_fictitious()),
 *   of which guard pages are a special case (@c vm_page_is_guard())
 * - a private page (@c vm_page_is_private())
 */
extern bool             vm_page_is_fictitious(const struct vm_page *m);

/*!
 * @abstract
 * Returns whether this is a kernel guard page that was made by
 * @c vm_page_create_guard().
 */
extern bool             vm_page_is_guard(const struct vm_page *m) __pure2;

/*!
 * @abstract
 * Returns whether a page is private (made by @c vm_page_create_private(),
 * or converted from a fictitious page by @c vm_page_make_private()).
 *
 * @discussion
 * A page can either be:
 * - a canonical page (@c vm_page_is_canonical())
 * - a fictitious page (@c vm_page_is_fictitious()),
 *   of which guard pages are a special case (@c vm_page_is_guard())
 * - a private page (@c vm_page_is_private())
 */
extern bool             vm_page_is_private(const struct vm_page *m);

/*!
 * @abstract
 * Converts a fictitious page made by @c vm_page_create_fictitious()
 * into a private page.
 *
 * @param m             The fictitious page to convert into a private one.
 * @param base_page     The physical page that this page will represent
 *                      (@c vm_page_create_private()).
 */
extern void             vm_page_make_private(vm_page_t m, ppnum_t base_page);

/*!
 * @abstract
 * Converts a private page into a fictitious page (as if made by
 * @c vm_page_create_fictitious()).
 *
 * @discussion
 * Private pages can't be released with @c vm_page_release()
 * without being turned into a fictitious page first using this function.
 */
extern void             vm_page_reset_private(vm_page_t m);

extern bool             vm_pool_low(void);

extern vm_page_t        vm_page_grab(void);
extern vm_page_t        vm_page_grab_options(int flags);

#define VM_PAGE_GRAB_OPTIONS_NONE 0x00000000
#if CONFIG_SECLUDED_MEMORY
#define VM_PAGE_GRAB_SECLUDED     0x00000001
#endif /* CONFIG_SECLUDED_MEMORY */
#define VM_PAGE_GRAB_Q_LOCK_HELD  0x00000002

extern vm_page_t        vm_page_grablo(void);

extern void             vm_page_release(
	vm_page_t       page,
	boolean_t       page_queues_locked);

extern boolean_t        vm_page_wait(
	int             interruptible );

extern void             vm_page_init(
	vm_page_t       page,
	ppnum_t         phys_page);

extern void             vm_page_free(
	vm_page_t       page);

extern void             vm_page_free_unlocked(
	vm_page_t       page,
	boolean_t       remove_from_hash);

/*
 * vm_page_get_memory_class:
 * Given a page, returns the memory class of that page.
 */
extern vm_memory_class_t        vm_page_get_memory_class(
	vm_page_t               page);

/*
 * vm_page_steal_free_page:
 * Given a VM_PAGE_ON_FREE_Q page, steals it from its free queue.
 */
extern void                     vm_page_steal_free_page(
	vm_page_t               page,
	vm_remove_reason_t      remove_reason);

/*!
 * @typedef vmp_free_list_result_t
 *
 * @discussion
 * This data structure is used by vm_page_put_list_on_free_queue to track
 * how many pages were freed to which free lists, so that it can then drive
 * which waiters we are going to wake up.
 *
 * uint8_t counters are enough because we never free more than 64 pages at
 * a time, and this allows for the data structure to be passed by register.
 */
typedef struct {
	uint8_t vmpr_regular;
	uint8_t vmpr_lopage;
#if CONFIG_SECLUDED_MEMORY
	uint8_t vmpr_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
} vmp_free_list_result_t;

/*
 * vm_page_put_list_on_free_queue:
 * Given a list of pages, put each page on whichever global free queue is
 * appropriate.
 *
 * Must be called with the VM free page lock held.
 */
extern vmp_free_list_result_t vm_page_put_list_on_free_queue(
	vm_page_t       list,
	bool            page_queues_locked);

extern void             vm_page_balance_inactive(
	int             max_to_move);

extern void             vm_page_activate(
	vm_page_t       page);

extern void             vm_page_deactivate(
	vm_page_t       page);

extern void             vm_page_deactivate_internal(
	vm_page_t       page,
	boolean_t       clear_hw_reference);

extern void             vm_page_enqueue_cleaned(vm_page_t page);

extern void             vm_page_lru(
	vm_page_t       page);

extern void             vm_page_speculate(
	vm_page_t       page,
	boolean_t       new);

extern void             vm_page_speculate_ageit(
	struct vm_speculative_age_q *aq);

extern void             vm_page_reactivate_local(uint32_t lid, boolean_t force, boolean_t nolocks);

extern void             vm_page_rename(
	vm_page_t               page,
	vm_object_t             new_object,
	vm_object_offset_t      new_offset);

extern void             vm_page_insert(
	vm_page_t               page,
	vm_object_t             object,
	vm_object_offset_t      offset);

extern void             vm_page_insert_wired(
	vm_page_t               page,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_tag_t                tag);


extern void             vm_page_insert_internal(
	vm_page_t               page,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_tag_t                tag,
	boolean_t               queues_lock_held,
	boolean_t               insert_in_hash,
	boolean_t               batch_pmap_op,
	boolean_t               delayed_accounting,
	uint64_t                *delayed_ledger_update);

extern void             vm_page_replace(
	vm_page_t               mem,
	vm_object_t             object,
	vm_object_offset_t      offset);

extern void             vm_page_remove(
	vm_page_t       page,
	boolean_t       remove_from_hash);

extern void             vm_page_zero_fill(
	vm_page_t       page);

extern void             vm_page_part_zero_fill(
	vm_page_t       m,
	vm_offset_t     m_pa,
	vm_size_t       len);

extern void             vm_page_copy(
	vm_page_t       src_page,
	vm_page_t       dest_page);

extern void             vm_page_part_copy(
	vm_page_t       src_m,
	vm_offset_t     src_pa,
	vm_page_t       dst_m,
	vm_offset_t     dst_pa,
	vm_size_t       len);

extern void             vm_page_wire(
	vm_page_t       page,
	vm_tag_t        tag,
	boolean_t       check_memorystatus);

extern void             vm_page_unwire(
	vm_page_t       page,
	boolean_t       queueit);

extern void             vm_set_page_size(void);

extern void             vm_page_validate_cs(
	vm_page_t       page,
	vm_map_size_t   fault_page_size,
	vm_map_offset_t fault_phys_offset);

extern void             vm_page_validate_cs_mapped(
	vm_page_t       page,
	vm_map_size_t   fault_page_size,
	vm_map_offset_t fault_phys_offset,
	const void      *kaddr);
extern void             vm_page_validate_cs_mapped_slow(
	vm_page_t       page,
	const void      *kaddr);
extern void             vm_page_validate_cs_mapped_chunk(
	vm_page_t       page,
	const void      *kaddr,
	vm_offset_t     chunk_offset,
	vm_size_t       chunk_size,
	boolean_t       *validated,
	unsigned        *tainted);

extern void             vm_page_free_prepare_queues(
	vm_page_t       page);

extern void             vm_page_free_prepare_object(
	vm_page_t       page,
	boolean_t       remove_from_hash);

extern wait_result_t    vm_page_sleep(
	vm_object_t        object,
	vm_page_t          m,
	wait_interrupt_t   interruptible,
	lck_sleep_action_t action);

extern void             vm_page_wakeup(
	vm_object_t        object,
	vm_page_t          m);

extern void             vm_page_wakeup_done(
	vm_object_t        object,
	vm_page_t          m);

typedef struct page_worker_token {
	thread_pri_floor_t pwt_floor_token;
	bool pwt_did_register_inheritor;
} page_worker_token_t;

extern void             vm_page_wakeup_done_with_inheritor(
	vm_object_t        object,
	vm_page_t          m,
	page_worker_token_t *token);

extern void             page_worker_register_worker(
	event_t            event,
	page_worker_token_t *out_token);

extern boolean_t        vm_page_is_relocatable(
	vm_page_t            m,
	vm_relocate_reason_t reloc_reason);

extern kern_return_t    vm_page_relocate(
	vm_page_t            m1,
	int *                compressed_pages,
	vm_relocate_reason_t reason,
	vm_page_t*           new_page);

extern bool             vm_page_is_restricted(
	vm_page_t mem);

/*
 * Functions implemented as macros. m->vmp_wanted and m->vmp_busy are
 * protected by the object lock.
 */

#if !XNU_TARGET_OS_OSX
#define SET_PAGE_DIRTY(m, set_pmap_modified)                            \
	        MACRO_BEGIN                                             \
	        vm_page_t __page__ = (m);                               \
	        if (__page__->vmp_pmapped == TRUE &&                    \
	            __page__->vmp_wpmapped == TRUE &&                   \
	            __page__->vmp_dirty == FALSE &&                     \
	            (set_pmap_modified)) {                              \
	                pmap_set_modify(VM_PAGE_GET_PHYS_PAGE(__page__)); \
	        }                                                       \
	        __page__->vmp_dirty = TRUE;                             \
	        MACRO_END
#else /* !XNU_TARGET_OS_OSX */
#define SET_PAGE_DIRTY(m, set_pmap_modified)                            \
	        MACRO_BEGIN                                             \
	        vm_page_t __page__ = (m);                               \
	        __page__->vmp_dirty = TRUE;                             \
	        MACRO_END
#endif /* !XNU_TARGET_OS_OSX */

#define VM_PAGE_FREE(p)                         \
	        MACRO_BEGIN                     \
	        vm_page_free_unlocked(p, TRUE); \
	        MACRO_END


#define VM_PAGE_WAIT()          ((void)vm_page_wait(THREAD_UNINT))

static inline void
vm_free_page_lock(void)
{
	lck_mtx_lock(&vm_page_queue_free_lock);
}

static inline void
vm_free_page_lock_spin(void)
{
	lck_mtx_lock_spin(&vm_page_queue_free_lock);
}

static inline void
vm_free_page_lock_convert(void)
{
	lck_mtx_convert_spin(&vm_page_queue_free_lock);
}

static inline void
vm_free_page_unlock(void)
{
	lck_mtx_unlock(&vm_page_queue_free_lock);
}


#define vm_page_lockconvert_queues()    lck_mtx_convert_spin(&vm_page_queue_lock)


#ifdef  VPL_LOCK_SPIN
extern lck_grp_t vm_page_lck_grp_local;

#define VPL_LOCK_INIT(vlq, vpl_grp, vpl_attr) lck_spin_init(&vlq->vpl_lock, vpl_grp, vpl_attr)
#define VPL_LOCK(vpl) lck_spin_lock_grp(vpl, &vm_page_lck_grp_local)
#define VPL_UNLOCK(vpl) lck_spin_unlock(vpl)
#else
#define VPL_LOCK_INIT(vlq, vpl_grp, vpl_attr) lck_mtx_init(&vlq->vpl_lock, vpl_grp, vpl_attr)
#define VPL_LOCK(vpl) lck_mtx_lock_spin(vpl)
#define VPL_UNLOCK(vpl) lck_mtx_unlock(vpl)
#endif

#if DEVELOPMENT || DEBUG
#define VM_PAGE_SPECULATIVE_USED_ADD()                          \
	MACRO_BEGIN                                             \
	OSAddAtomic(1, &vm_page_speculative_used);              \
	MACRO_END
#else
#define VM_PAGE_SPECULATIVE_USED_ADD()
#endif

#define VM_PAGE_CONSUME_CLUSTERED(mem)                          \
	MACRO_BEGIN                                             \
	ppnum_t	__phys_page;                                    \
	__phys_page = VM_PAGE_GET_PHYS_PAGE(mem);               \
	pmap_lock_phys_page(__phys_page);                       \
	if (mem->vmp_clustered) {                               \
	        vm_object_t o;                                  \
	        o = VM_PAGE_OBJECT(mem);                        \
	        assert(o);                                      \
	        o->pages_used++;                                \
	        mem->vmp_clustered = FALSE;                     \
	        VM_PAGE_SPECULATIVE_USED_ADD();                 \
	}                                                       \
	pmap_unlock_phys_page(__phys_page);                     \
	MACRO_END


#define VM_PAGE_COUNT_AS_PAGEIN(mem)                            \
	MACRO_BEGIN                                             \
	{                                                       \
	vm_object_t o;                                          \
	o = VM_PAGE_OBJECT(mem);                                \
	DTRACE_VM2(pgin, int, 1, (uint64_t *), NULL);           \
	counter_inc(&current_task()->pageins);                  \
	if (o->internal) {                                      \
	        DTRACE_VM2(anonpgin, int, 1, (uint64_t *), NULL);       \
	} else {                                                \
	        DTRACE_VM2(fspgin, int, 1, (uint64_t *), NULL); \
	}                                                       \
	}                                                       \
	MACRO_END


/* adjust for stolen pages accounted elsewhere */
#define VM_PAGE_MOVE_STOLEN(page_count)                         \
	MACRO_BEGIN                                             \
	vm_page_stolen_count -=	(page_count);                   \
	vm_page_wire_count_initial -= (page_count);             \
	MACRO_END

kern_return_t
pmap_enter_object_options_check(
	pmap_t           pmap,
	vm_map_address_t virtual_address,
	vm_map_offset_t  fault_phys_offset,
	vm_object_t      object,
	ppnum_t          pn,
	vm_prot_t        protection,
	vm_prot_t        fault_type,
	boolean_t        wired,
	unsigned int     options);

extern kern_return_t pmap_enter_options_check(
	pmap_t           pmap,
	vm_map_address_t virtual_address,
	vm_map_offset_t  fault_phys_offset,
	vm_page_t        page,
	vm_prot_t        protection,
	vm_prot_t        fault_type,
	boolean_t        wired,
	unsigned int     options);

extern kern_return_t pmap_enter_check(
	pmap_t           pmap,
	vm_map_address_t virtual_address,
	vm_page_t        page,
	vm_prot_t        protection,
	vm_prot_t        fault_type,
	boolean_t        wired);

#define DW_vm_page_unwire               0x01
#define DW_vm_page_wire                 0x02
#define DW_vm_page_free                 0x04
#define DW_vm_page_activate             0x08
#define DW_vm_page_deactivate_internal  0x10
#define DW_vm_page_speculate            0x20
#define DW_vm_page_lru                  0x40
#define DW_vm_pageout_throttle_up       0x80
#define DW_PAGE_WAKEUP                  0x100
#define DW_clear_busy                   0x200
#define DW_clear_reference              0x400
#define DW_set_reference                0x800
#define DW_move_page                    0x1000
#define DW_VM_PAGE_QUEUES_REMOVE        0x2000
#define DW_enqueue_cleaned              0x4000
#define DW_vm_phantom_cache_update      0x8000

struct vm_page_delayed_work {
	vm_page_t       dw_m;
	int             dw_mask;
};

#define DEFAULT_DELAYED_WORK_LIMIT      32

struct vm_page_delayed_work_ctx {
	struct vm_page_delayed_work dwp[DEFAULT_DELAYED_WORK_LIMIT];
	thread_t                    delayed_owner;
};

void vm_page_do_delayed_work(vm_object_t object, vm_tag_t tag, struct vm_page_delayed_work *dwp, int dw_count);

#define DELAYED_WORK_LIMIT(max) ((vm_max_delayed_work_limit >= max ? max : vm_max_delayed_work_limit))

/*
 * vm_page_do_delayed_work may need to drop the object lock...
 * if it does, we need the pages it's looking at to
 * be held stable via the busy bit, so if busy isn't already
 * set, we need to set it and ask vm_page_do_delayed_work
 * to clear it and wakeup anyone that might have blocked on
 * it once we're done processing the page.
 */

#define VM_PAGE_ADD_DELAYED_WORK(dwp, mem, dw_cnt)              \
	MACRO_BEGIN                                             \
	if (mem->vmp_busy == FALSE) {                           \
	        mem->vmp_busy = TRUE;                           \
	        if ( !(dwp->dw_mask & DW_vm_page_free))         \
	                dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP); \
	}                                                       \
	dwp->dw_m = mem;                                        \
	dwp++;                                                  \
	dw_cnt++;                                               \
	MACRO_END


//todo int
extern vm_page_t vm_object_page_grab(vm_object_t);

//todo int
#if VM_PAGE_BUCKETS_CHECK
extern void vm_page_buckets_check(void);
#endif /* VM_PAGE_BUCKETS_CHECK */

//todo int
extern void vm_page_queues_remove(vm_page_t mem, boolean_t remove_from_specialq);
extern void vm_page_remove_internal(vm_page_t page);
extern void vm_page_enqueue_inactive(vm_page_t mem, boolean_t first);
extern void vm_page_enqueue_active(vm_page_t mem, boolean_t first);
extern void vm_page_check_pageable_safe(vm_page_t page);
//end int

//todo int
extern void vm_retire_boot_pages(void);

//todo all int

#define VMP_ERROR_GET(p) ((p)->vmp_error)


#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS

#endif  /* _VM_VM_PAGE_INTERNAL_H_ */
