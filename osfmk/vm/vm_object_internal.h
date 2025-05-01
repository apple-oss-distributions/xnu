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

#ifndef _VM_VM_OBJECT_INTERNAL_H_
#define _VM_VM_OBJECT_INTERNAL_H_

#ifdef XNU_KERNEL_PRIVATE
#include <vm/vm_object_xnu.h>

#if VM_OBJECT_TRACKING
#include <libkern/OSDebug.h>
#include <kern/btlog.h>
extern void vm_object_tracking_init(void);
extern btlog_t vm_object_tracking_btlog;
#define VM_OBJECT_TRACKING_NUM_RECORDS  50000
#define VM_OBJECT_TRACKING_OP_CREATED   1
#define VM_OBJECT_TRACKING_OP_MODIFIED  2
#define VM_OBJECT_TRACKING_OP_TRUESHARE 3
#endif /* VM_OBJECT_TRACKING */

#if VM_OBJECT_ACCESS_TRACKING
extern uint64_t vm_object_access_tracking_reads;
extern uint64_t vm_object_access_tracking_writes;
extern void vm_object_access_tracking(vm_object_t object,
    int *access_tracking,
    uint32_t *access_tracking_reads,
    uint32_t *acess_tracking_writes);
#endif /* VM_OBJECT_ACCESS_TRACKING */

extern uint16_t vm_object_pagein_throttle;

/*
 *	Object locking macros
 */

#define vm_object_lock_init(object)                                     \
	lck_rw_init(&(object)->Lock, &vm_object_lck_grp,                \
	            (is_kernel_object(object) ?                         \
	             &kernel_object_lck_attr :                          \
	             (((object) == compressor_object) ?                 \
	             &compressor_object_lck_attr :                      \
	              &vm_object_lck_attr)))
#define vm_object_lock_destroy(object)  lck_rw_destroy(&(object)->Lock, &vm_object_lck_grp)

#define vm_object_lock_try_scan(object) _vm_object_lock_try(object)

/*
 * CAUTION: the following vm_object_lock_assert_held*() macros merely
 * check if anyone is holding the lock, but the holder may not necessarily
 * be the caller...
 */
#define vm_object_lock_assert_held(object) \
	LCK_RW_ASSERT(&(object)->Lock, LCK_RW_ASSERT_HELD)
#define vm_object_lock_assert_shared(object) \
	LCK_RW_ASSERT(&(object)->Lock, LCK_RW_ASSERT_SHARED)
#define vm_object_lock_assert_exclusive(object) \
	LCK_RW_ASSERT(&(object)->Lock, LCK_RW_ASSERT_EXCLUSIVE)
#define vm_object_lock_assert_notheld(object) \
	LCK_RW_ASSERT(&(object)->Lock, LCK_RW_ASSERT_NOTHELD)


static inline void
VM_OBJECT_SET_PAGER_CREATED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->pager_created = value;
}
static inline void
VM_OBJECT_SET_PAGER_INITIALIZED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->pager_initialized = value;
}
static inline void
VM_OBJECT_SET_PAGER_READY(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->pager_ready = value;
}
static inline void
VM_OBJECT_SET_PAGER_TRUSTED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->pager_trusted = value;
}
static inline void
VM_OBJECT_SET_CAN_PERSIST(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->can_persist = value;
}
static inline void
VM_OBJECT_SET_INTERNAL(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->internal = value;
}
static inline void
VM_OBJECT_SET_PRIVATE(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->private = value;
}
static inline void
VM_OBJECT_SET_PAGEOUT(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->pageout = value;
}
static inline void
VM_OBJECT_SET_ALIVE(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->alive = value;
}
static inline void
VM_OBJECT_SET_PURGABLE(
	vm_object_t object,
	unsigned int value)
{
	vm_object_lock_assert_exclusive(object);
	object->purgable = value;
	assert3u(object->purgable, ==, value);
}
static inline void
VM_OBJECT_SET_PURGEABLE_ONLY_BY_KERNEL(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->purgeable_only_by_kernel = value;
}
static inline void
VM_OBJECT_SET_PURGEABLE_WHEN_RIPE(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->purgeable_when_ripe = value;
}
static inline void
VM_OBJECT_SET_SHADOWED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->shadowed = value;
}
static inline void
VM_OBJECT_SET_TRUE_SHARE(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->true_share = value;
}
static inline void
VM_OBJECT_SET_TERMINATING(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->terminating = value;
}
static inline void
VM_OBJECT_SET_NAMED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->named = value;
}
static inline void
VM_OBJECT_SET_SHADOW_SEVERED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->shadow_severed = value;
}
static inline void
VM_OBJECT_SET_PHYS_CONTIGUOUS(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->phys_contiguous = value;
}
static inline void
VM_OBJECT_SET_NOPHYSCACHE(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->nophyscache = value;
}
static inline void
VM_OBJECT_SET_FOR_REALTIME(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->for_realtime = value;
}
static inline void
VM_OBJECT_SET_NO_PAGER_REASON(
	vm_object_t object,
	unsigned int value)
{
	vm_object_lock_assert_exclusive(object);
	object->no_pager_reason = value;
	assert3u(object->no_pager_reason, ==, value);
}
#if FBDP_DEBUG_OBJECT_NO_PAGER
static inline void
VM_OBJECT_SET_FBDP_TRACKED(
	vm_object_t object,
	bool value)
{
	vm_object_lock_assert_exclusive(object);
	object->fbdp_tracked = value;
}
#endif /* FBDP_DEBUG_OBJECT_NO_PAGER */

/*
 *	Declare procedures that operate on VM objects.
 */

__private_extern__ void         vm_object_bootstrap(void);

__private_extern__ void         vm_object_reaper_init(void);

__private_extern__ vm_object_t  vm_object_allocate(vm_object_size_t size);

__private_extern__ void    _vm_object_allocate(vm_object_size_t size,
    vm_object_t object);

__private_extern__ void vm_object_set_size(
	vm_object_t             object,
	vm_object_size_t        outer_size,
	vm_object_size_t        inner_size);

static inline void
vm_object_reference_locked(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	os_ref_retain_locked_raw(&object->ref_count, &vm_object_refgrp);
}

static inline void
vm_object_reference_shared(vm_object_t object)
{
	vm_object_lock_assert_shared(object);
	os_ref_retain_raw(&object->ref_count, &vm_object_refgrp);
}

__private_extern__ void         vm_object_reference(
	vm_object_t     object);

#if     !MACH_ASSERT

#define vm_object_reference(object)                     \
MACRO_BEGIN                                             \
	vm_object_t RObject = (object);                 \
	if (RObject) {                                  \
	        vm_object_lock_shared(RObject);         \
	        vm_object_reference_shared(RObject);    \
	        vm_object_unlock(RObject);              \
	}                                               \
MACRO_END

#endif  /* MACH_ASSERT */

__private_extern__ void         vm_object_deallocate(
	vm_object_t     object);

__private_extern__ void         vm_object_pmap_protect(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	pmap_t                  pmap,
	vm_map_size_t           pmap_page_size,
	vm_map_offset_t         pmap_start,
	vm_prot_t               prot);

__private_extern__ void         vm_object_pmap_protect_options(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	pmap_t                  pmap,
	vm_map_size_t           pmap_page_size,
	vm_map_offset_t         pmap_start,
	vm_prot_t               prot,
	int                     options);

__private_extern__ void         vm_object_page_remove(
	vm_object_t             object,
	vm_object_offset_t      start,
	vm_object_offset_t      end);

__private_extern__ void         vm_object_deactivate_pages(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	boolean_t               kill_page,
	boolean_t               reusable_page,
	boolean_t               kill_no_write,
	struct pmap             *pmap,
/* XXX TODO4K: need pmap_page_size here too? */
	vm_map_offset_t         pmap_offset);

__private_extern__ void vm_object_reuse_pages(
	vm_object_t             object,
	vm_object_offset_t      start_offset,
	vm_object_offset_t      end_offset,
	boolean_t               allow_partial_reuse);

__private_extern__ kern_return_t vm_object_zero(
	vm_object_t             object,
	vm_object_offset_t      cur_offset,
	vm_object_offset_t      end_offset);

__private_extern__ uint64_t     vm_object_purge(
	vm_object_t              object,
	int                      flags);

__private_extern__ kern_return_t vm_object_purgable_control(
	vm_object_t     object,
	vm_purgable_t   control,
	int             *state);

__private_extern__ kern_return_t vm_object_get_page_counts(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	unsigned int            *resident_page_count,
	unsigned int            *dirty_page_count);

__private_extern__ boolean_t    vm_object_coalesce(
	vm_object_t             prev_object,
	vm_object_t             next_object,
	vm_object_offset_t      prev_offset,
	vm_object_offset_t      next_offset,
	vm_object_size_t        prev_size,
	vm_object_size_t        next_size);

__private_extern__ boolean_t    vm_object_shadow(
	vm_object_t             *object,
	vm_object_offset_t      *offset,
	vm_object_size_t        length,
	boolean_t               always_shadow);

__private_extern__ void         vm_object_collapse(
	vm_object_t             object,
	vm_object_offset_t      offset,
	boolean_t               can_bypass);

__private_extern__ boolean_t    vm_object_copy_quickly(
	vm_object_t             object,
	vm_object_offset_t      src_offset,
	vm_object_size_t        size,
	boolean_t               *_src_needs_copy,
	boolean_t               *_dst_needs_copy);

__private_extern__ kern_return_t        vm_object_copy_strategically(
	vm_object_t             src_object,
	vm_object_offset_t      src_offset,
	vm_object_size_t        size,
	bool                    forking,
	vm_object_t             *dst_object,
	vm_object_offset_t      *dst_offset,
	boolean_t               *dst_needs_copy);

__private_extern__ kern_return_t        vm_object_copy_slowly(
	vm_object_t             src_object,
	vm_object_offset_t      src_offset,
	vm_object_size_t        size,
	boolean_t               interruptible,
	vm_object_t             *_result_object);

__private_extern__ vm_object_t  vm_object_copy_delayed(
	vm_object_t             src_object,
	vm_object_offset_t      src_offset,
	vm_object_size_t        size,
	boolean_t               src_object_shared);

__private_extern__ kern_return_t        vm_object_destroy(
	vm_object_t                                     object,
	vm_object_destroy_reason_t   reason);

__private_extern__ void         vm_object_compressor_pager_create(
	vm_object_t     object);

/*
 * Query whether the provided object,offset reside in the compressor. The
 * caller must hold the object lock and ensure that the object,offset under
 * inspection is not in the process of being paged in/out (i.e. no busy
 * backing page)
 */
__private_extern__ vm_external_state_t vm_object_compressor_pager_state_get(
	vm_object_t        object,
	vm_object_offset_t offset);

/*
 * Clear the compressor slot corresponding to an object,offset. The caller
 * must hold the object lock (exclusive) and ensure that the object,offset
 * under inspection is not in the process of being paged in/out (i.e. no busy
 * backing page)
 */
__private_extern__ void vm_object_compressor_pager_state_clr(
	vm_object_t        object,
	vm_object_offset_t offset);

__private_extern__ kern_return_t vm_object_upl_request(
	vm_object_t             object,
	vm_object_offset_t      offset,
	upl_size_t              size,
	upl_t                   *upl,
	upl_page_info_t         *page_info,
	unsigned int            *count,
	upl_control_flags_t     flags,
	vm_tag_t            tag);

__private_extern__ kern_return_t vm_object_transpose(
	vm_object_t             object1,
	vm_object_t             object2,
	vm_object_size_t        transpose_size);

__private_extern__ boolean_t vm_object_sync(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	boolean_t               should_flush,
	boolean_t               should_return,
	boolean_t               should_iosync);

__private_extern__ kern_return_t vm_object_update(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	vm_object_offset_t      *error_offset,
	int                     *io_errno,
	memory_object_return_t  should_return,
	int                     flags,
	vm_prot_t               prot);

__private_extern__ kern_return_t vm_object_lock_request(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size,
	memory_object_return_t  should_return,
	int                     flags,
	vm_prot_t               prot);



__private_extern__ vm_object_t  vm_object_memory_object_associate(
	memory_object_t         pager,
	vm_object_t             object,
	vm_object_size_t        size,
	boolean_t               check_named);


__private_extern__ void vm_object_cluster_size(
	vm_object_t             object,
	vm_object_offset_t      *start,
	vm_size_t               *length,
	vm_object_fault_info_t  fault_info,
	uint32_t                *io_streaming);

__private_extern__ kern_return_t vm_object_populate_with_private(
	vm_object_t             object,
	vm_object_offset_t      offset,
	ppnum_t                 phys_page,
	vm_size_t               size);

__private_extern__ void vm_object_change_wimg_mode(
	vm_object_t             object,
	unsigned int            wimg_mode);

extern kern_return_t vm_object_page_op(
	vm_object_t             object,
	vm_object_offset_t      offset,
	int                     ops,
	ppnum_t                 *phys_entry,
	int                     *flags);

extern kern_return_t vm_object_range_op(
	vm_object_t             object,
	vm_object_offset_t      offset_beg,
	vm_object_offset_t      offset_end,
	int                     ops,
	uint32_t                *range);


__private_extern__ void         vm_object_reap_pages(
	vm_object_t object,
	int     reap_type);
#define REAP_REAP       0
#define REAP_TERMINATE  1
#define REAP_PURGEABLE  2
#define REAP_DATA_FLUSH 3

#if CONFIG_FREEZE

__private_extern__ uint32_t
vm_object_compressed_freezer_pageout(
	vm_object_t     object, uint32_t dirty_budget);

__private_extern__ void
vm_object_compressed_freezer_done(
	void);

#endif /* CONFIG_FREEZE */

__private_extern__ void
vm_object_pageout(
	vm_object_t     object);

/*
 *	Event waiting handling
 */
__enum_closed_decl(vm_object_wait_reason_t, uint8_t, {
	VM_OBJECT_EVENT_PAGER_INIT = 0,
	VM_OBJECT_EVENT_PAGER_READY = 1,
	VM_OBJECT_EVENT_PAGING_IN_PROGRESS = 2,
	VM_OBJECT_EVENT_MAPPING_IN_PROGRESS = 3,
	VM_OBJECT_EVENT_UNBLOCKED = 4,
	VM_OBJECT_EVENT_PAGING_ONLY_IN_PROGRESS = 5,
	VM_OBJECT_EVENT_PAGEIN_THROTTLE = 6,
});
#define VM_OBJECT_EVENT_MAX VM_OBJECT_EVENT_PAGEIN_THROTTLE
/* 7 bits in "all_wanted" */
_Static_assert(VM_OBJECT_EVENT_MAX < 7,
    "vm_object_wait_reason_t must fit in all_wanted");
/*
 * @c vm_object_sleep uses (object + wait_reason) as the wait event, ensure
 * this does not colide with the object lock.
 */
_Static_assert(VM_OBJECT_EVENT_MAX < offsetof(struct vm_object, Lock),
    "Wait reason collides with vm_object->Lock");

extern wait_result_t vm_object_sleep(
	vm_object_t             object,
	vm_object_wait_reason_t reason,
	wait_interrupt_t        interruptible,
	lck_sleep_action_t      action);


static inline void
vm_object_set_wanted(
	vm_object_t             object,
	vm_object_wait_reason_t reason)
{
	vm_object_lock_assert_exclusive(object);
	assert(reason >= 0 && reason <= VM_OBJECT_EVENT_MAX);

	object->all_wanted |= (1 << reason);
}

static inline bool
vm_object_wanted(
	vm_object_t             object,
	vm_object_wait_reason_t event)
{
	vm_object_lock_assert_held(object);
	assert(event >= 0 && event <= VM_OBJECT_EVENT_MAX);

	return object->all_wanted & (1 << event);
}

extern void vm_object_wakeup(
	vm_object_t             object,
	vm_object_wait_reason_t reason);

/*
 *	Routines implemented as macros
 */
#ifdef VM_PIP_DEBUG
#include <libkern/OSDebug.h>
#define VM_PIP_DEBUG_BEGIN(object)                                      \
	MACRO_BEGIN                                                     \
	int pip = ((object)->paging_in_progress +                       \
	           (object)->activity_in_progress);                     \
	if (pip < VM_PIP_DEBUG_MAX_REFS) {                              \
	        (void) OSBacktrace(&(object)->pip_holders[pip].pip_retaddr[0], \
	                           VM_PIP_DEBUG_STACK_FRAMES);          \
	}                                                               \
	MACRO_END
#else   /* VM_PIP_DEBUG */
#define VM_PIP_DEBUG_BEGIN(object)
#endif  /* VM_PIP_DEBUG */

static inline void
vm_object_activity_begin(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	VM_PIP_DEBUG_BEGIN(object);
	if (os_inc_overflow(&object->activity_in_progress)) {
		panic("vm_object_activity_begin(%p): overflow\n", object);
	}
}

static inline void
vm_object_activity_end(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	if (os_dec_overflow(&object->activity_in_progress)) {
		panic("vm_object_activity_end(%p): underflow\n", object);
	}
	if (object->paging_in_progress == 0 &&
	    object->activity_in_progress == 0) {
		vm_object_wakeup((object),
		    VM_OBJECT_EVENT_PAGING_IN_PROGRESS);
	}
}

static inline void
vm_object_paging_begin(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	VM_PIP_DEBUG_BEGIN((object));
	if (os_inc_overflow(&object->paging_in_progress)) {
		panic("vm_object_paging_begin(%p): overflow\n", object);
	}
}

static inline void
vm_object_paging_end(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	if (os_dec_overflow(&object->paging_in_progress)) {
		panic("vm_object_paging_end(%p): underflow\n", object);
	}
	/*
	 * NB: This broadcast can be noisy, especially because all threads
	 * receiving the wakeup are given a priority floor. In the future, it
	 * would be great to utilize a primitive which can arbitrate
	 * the priority of all waiters and only issue as many wakeups as can be
	 * serviced.
	 */
	if (object->paging_in_progress == vm_object_pagein_throttle - 1) {
		vm_object_wakeup(object, VM_OBJECT_EVENT_PAGEIN_THROTTLE);
	}
	if (object->paging_in_progress == 0) {
		vm_object_wakeup(object, VM_OBJECT_EVENT_PAGING_ONLY_IN_PROGRESS);
		if (object->activity_in_progress == 0) {
			vm_object_wakeup((object),
			    VM_OBJECT_EVENT_PAGING_IN_PROGRESS);
		}
	}
}

/* Wait for *all* paging and activities on this object to complete */
extern wait_result_t vm_object_paging_wait(vm_object_t object, wait_interrupt_t interruptible);
/* Wait for *all* paging on this object to complete */
extern wait_result_t vm_object_paging_only_wait(vm_object_t object, wait_interrupt_t interruptible);
/* Wait for the number of page-ins on this object to fall below the throttle limit */
extern wait_result_t vm_object_paging_throttle_wait(vm_object_t object, wait_interrupt_t interruptible);

static inline void
vm_object_mapping_begin(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	assert(!object->mapping_in_progress);
	object->mapping_in_progress = TRUE;
}

static inline void
vm_object_mapping_end(vm_object_t object)
{
	vm_object_lock_assert_exclusive(object);
	assert(object->mapping_in_progress);
	object->mapping_in_progress = FALSE;
	vm_object_wakeup(object,
	    VM_OBJECT_EVENT_MAPPING_IN_PROGRESS);
}

extern wait_result_t vm_object_mapping_wait(vm_object_t object, wait_interrupt_t interruptible);

#define vm_object_round_page(x) (((vm_object_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define vm_object_trunc_page(x) ((vm_object_offset_t)(x) & ~((signed)PAGE_MASK))

extern void     vm_object_cache_add(vm_object_t);
extern void     vm_object_cache_remove(vm_object_t);
extern int      vm_object_cache_evict(int, int);

#define VM_OBJECT_OWNER_DISOWNED ((task_t) -1)
#define VM_OBJECT_OWNER_UNCHANGED ((task_t) -2)
#define VM_OBJECT_OWNER(object)                                         \
	((object == VM_OBJECT_NULL ||                                   \
	  ((object)->purgable == VM_PURGABLE_DENY &&                    \
	   (object)->vo_ledger_tag == 0) ||                             \
	  (object)->vo_owner == TASK_NULL)                              \
	 ? TASK_NULL    /* not owned */                                 \
	 : (((object)->vo_owner == VM_OBJECT_OWNER_DISOWNED)            \
	    ? kernel_task /* disowned -> kernel */                      \
	    : (object)->vo_owner)) /* explicit owner */                 \


extern void     vm_object_ledger_tag_ledgers(
	vm_object_t object,
	int *ledger_idx_volatile,
	int *ledger_idx_nonvolatile,
	int *ledger_idx_volatile_compressed,
	int *ledger_idx_nonvolatile_compressed,
	int *ledger_idx_composite,
	int *ledger_idx_external_wired,
	boolean_t *do_footprint);

extern kern_return_t vm_object_ownership_change(
	vm_object_t object,
	int new_ledger_tag,
	task_t new_owner,
	int new_ledger_flags,
	boolean_t task_objq_locked);


// LP64todo: all the current tools are 32bit, obviously never worked for 64b
// so probably should be a real 32b ID vs. ptr.
// Current users just check for equality
#define VM_OBJECT_ID(o) ((uint32_t)(uintptr_t)VM_KERNEL_ADDRHASH((o)))

static inline void
VM_OBJECT_COPY_SET(
	vm_object_t object,
	vm_object_t copy)
{
	vm_object_lock_assert_exclusive(object);
	object->vo_copy = copy;
	if (copy != VM_OBJECT_NULL) {
		object->vo_copy_version++;
	}
}

#endif /* XNU_KERNEL_PRIVATE */

#endif  /* _VM_VM_OBJECT_INTERNAL_H_ */
