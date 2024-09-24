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
	extern unsigned int   vm_pages_count;
	extern unsigned int   vm_clump_size, vm_clump_mask, vm_clump_shift, vm_clump_promote_threshold;
	extern unsigned long  vm_clump_allocs, vm_clump_inserts, vm_clump_inrange, vm_clump_promotes;

	/*
	 * If elt is part of the vm_pages[] array, find its neighboring buddies in the array.
	 */
	if (vm_page_array_beginning_addr <= elt && elt < &vm_pages[vm_pages_count]) {
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
		for (i = 0, p = elt - 1; i < n && vm_page_array_beginning_addr <= p; i++, p--) {
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
		for (i = n + 1, p = elt + 1; i < vm_clump_size && p < &vm_pages[vm_pages_count]; i++, p++) {
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

extern vm_page_t        vm_page_grab_fictitious(boolean_t canwait);

extern vm_page_t        vm_page_grab_guard(boolean_t canwait);

extern void             vm_page_release_fictitious(
	vm_page_t page);

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
	ppnum_t         phys_page,
	boolean_t       lopage);

extern void             vm_page_free(
	vm_page_t       page);

extern void             vm_page_free_unlocked(
	vm_page_t       page,
	boolean_t       remove_from_hash);

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

extern kern_return_t pmap_enter_check(
	pmap_t           pmap,
	vm_map_address_t virtual_address,
	vm_page_t        page,
	vm_prot_t        protection,
	vm_prot_t        fault_type,
	unsigned int     flags,
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


//todo int

#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS

#endif  /* _VM_VM_PAGE_INTERNAL_H_ */
