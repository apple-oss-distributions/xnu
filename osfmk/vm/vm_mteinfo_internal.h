/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_MTEINFO_INTERNAL_H_
#define _VM_VM_MTEINFO_INTERNAL_H_

#include <stdint.h>
#include <kern/kcdata.h>
#include <mach/vm_param.h>
#ifndef VM_MTE_FF_VERIFY
#include <vm/vm_page.h>
#if MACH_KERNEL_PRIVATE
#include <vm/vm_page_internal.h>
#endif
#endif /* VM_MTE_FF_VERIFY */

__BEGIN_DECLS
#if HAS_MTE

#pragma mark Types

struct vm_page;

/*!
 * @typedef mte_cell_state_t
 *
 * @abstract
 * This type denotes the state of a cell, which influences which queue it
 * belongs to.
 *
 * @discussion
 * For any given state untagged covered pages associated with a tag storage page
 * (or its cell) can be allocated.  However, tagged covered pages can only be
 * allocated if the associated tag storage cell is in the MTE_STATE_ACTIVE
 * state.
 *
 * @const MTE_STATE_DISABLED
 * This cell is disabled from being selected as a tag storage page.
 *
 * This can happen for:
 * - recursive tag storage,
 * - tag storage for iBoot carveouts,
 * - tag storage for unmanaged memory not using MTE,
 * - pages with ECC errors that have been retired.
 *
 * In the first two cases, the page is usable for regular untaggable usage,
 * and is on the global free queue, in the latter case the page is retired
 * and unusable.
 *
 * @const MTE_STATE_PINNED
 * The tag storage page is currently used as non tag storage, and a reclaim was
 * attempted and failed due to the page being pinned (most likely wired).
 *
 * This state is discovered lazily by the refill thread as it would be expensive
 * to maintain explicitly. It serves as a way to not attempt reclaiming the same
 * pages over and over again when they are in a state that doesn't permit it.
 *
 * This page shall have no covered pages with MTE enabled (the SPTM will
 * enforce this).
 *
 * @const MTE_STATE_DEACTIVATING
 * List of pages in the process of being deactivated (from MTE_STATE_ACTIVE).
 *
 * This page might transiently have pages with MTE enabled,
 * however none should be in use.
 *
 * @const MTE_STATE_CLAIMED
 * The tag storage page is currently used as non tag storage, and is typically
 * typed XNU_DEFAULT (though nothing prevents other uses, provided the usage is
 * relocatable).
 *
 * This page shall have no covered pages with MTE enabled (the SPTM will
 * enforce this).
 *
 * @const MTE_STATE_INACTIVE
 * The tag storage page is currently completely free and unused, and is typed
 * XNU_DEFAULT.
 *
 * This page shall have no covered pages with MTE enabled (the SPTM will
 * enforce this).
 *
 * @const MTE_STATE_RECLAIMING
 * List of pages which used to be in MTE_STATE_CLAIMED state, that the fill
 * thread is attempting to relocate.
 *
 * This page shall have no covered pages with MTE enabled (the SPTM must
 * enforce this).
 *
 * @const MTE_STATE_ACTIVATING
 * List of pages in the process of being activated (from MTE_STATE_INACTIVE).
 *
 * This page shall have no covered pages with MTE enabled (the SPTM must
 * enforce this).
 *
 * @const MTE_STATE_ACTIVE
 * The tag storage page is currently typed XNU_TAG_STORAGE and might have
 * covered pages with MTE enabled.
 */
__enum_closed_decl(mte_cell_state_t, uint8_t, {
	MTE_STATE_DISABLED,
	MTE_STATE_PINNED,
	MTE_STATE_DEACTIVATING,
	MTE_STATE_CLAIMED,
	MTE_STATE_INACTIVE,
	MTE_STATE_RECLAIMING,
	MTE_STATE_ACTIVATING,
	MTE_STATE_ACTIVE,
});

/*!
 * @const MTE_BUCKETS_COUNT_MAX
 * The maximum number of buckets in a cell list.
 *
 * Cell list buckets are a function of the number of free covered pages
 * associated with the tag storage pages being considered:
 *  - bucket 0: no free covered page.
 *  - bucket 1: 1 to 8 free covered pages.
 *  - bucket 2: 9 to 16 free covered pages.
 *  - bucket 3: 17 to 24 free covered pages.
 *  - bucket 4: 25 to 32 free covered pages.
 */
#define MTE_BUCKETS_COUNT_MAX           5

/*!
 * @typedef mte_cell_list_idx_t
 *
 * @abstract
 * Represents the index of a cell list inside the mteinfo data structure.
 *
 * @discussion
 * The order of these values matter:
 * - Lists with single buckets must be first
 * - Active lists must be last
 */
__enum_closed_decl(mte_cell_list_idx_t, uint32_t, {
	MTE_LIST_DISABLED_IDX           = MTE_STATE_DISABLED,
	MTE_LIST_PINNED_IDX             = MTE_STATE_PINNED,
	MTE_LIST_DEACTIVATING_IDX       = MTE_STATE_DEACTIVATING,
	MTE_LIST_CLAIMED_IDX            = MTE_STATE_CLAIMED,
	MTE_LIST_INACTIVE_IDX           = MTE_STATE_INACTIVE,
	MTE_LIST_RECLAIMING_IDX         = MTE_STATE_RECLAIMING,
	MTE_LIST_ACTIVATING_IDX         = MTE_STATE_ACTIVATING,
	MTE_LIST_ACTIVE_0_IDX           = MTE_STATE_ACTIVE,
	MTE_LIST_ACTIVE_IDX             = MTE_STATE_ACTIVE + 1,

	MTE_LISTS_COUNT,
});

/*!
 * @typedef mte_cell_list_t
 *
 * @abstract
 * This data structure represents a segregated list of page queues.
 *
 * @discussion
 * The list is segregated per number of free pages. Each segregation queue is
 * called a "bucket".
 *
 * @field mask
 * Mask of all the non empty buckets in this list.
 *
 * @field count
 * Total number of cells on the list
 *
 * @field buckets
 * A vector of queues this list covers. The number of buckets depends on the
 * list and can range from 1 to MTE_BUCKETS_COUNT_MAX
 */
typedef struct mte_cell_list {
	uint32_t                        mask;
	uint32_t                        count;
	struct mte_cell_queue_head     *buckets;
} *mte_cell_list_t;

/*!
 * @abstract
 * Indices for the mte free queue buckets.
 *
 * @discussion
 * This bucketing is designed to order allocations:
 *
 * - untagged allocations will consider buckets in ascending order from
 *   @c MTE_FREE_UNTAGGABLE through @c MTE_FREE_UNTAGGABLE_ACTIVATING.
 *
 * - tagged allocations will consider buckets in descending order from
 *   @c MTE_FREE_ACTIVE_3 through MTE_FREE_ACTIVE_0.
 *
 * Said another way: lower indices denote buckets where untagged allocations are
 * more desirable and higher indices buckets where tagged allocations are more
 * desirable.
 *
 *
 * @const MTE_FREE_UNTAGGABLE_0
 * The bucket for pages with disabled, pinned, deactivating tag storage
 * pages, or claimed with 16 or less associated free pages.
 *
 * @const MTE_FREE_UNTAGGABLE_1
 * The bucket for claimed pages with 17 or more associated free pages or
 * inactive pages with 16 or less associated free pages.
 *
 * @const MTE_FREE_UNTAGGABLE_2
 * The bucket for pages with inactive tag storage pages which have 17 associated
 * covered free pages or more.
 *
 *
 * @const MTE_FREE_UNTAGGABLE_ACTIVATING
 * The bucket for pages with activating or reclaiming tag storage pages.
 *
 * This bucket is kept "last" because the system has selected these pages
 * for upgrading into the active pools either from inactive or claimed
 * as being the best current candidates. In other words, once the activation
 * is finished, we expect these pages to fall into a high @c MTE_FREE_ACTIVE_*
 * bucket.
 *
 * These transitions are unfortunately not atomic and the untagged workloads
 * can tap into these during the transitions defeating the purpose of the
 * upgrades, so by making them last, we protect them from untagged allocations.
 *
 *
 * @const MTE_FREE_NOT_QUEUED
 * This a pseudo bucket for tag storage pages with no free pages.
 */
__enum_closed_decl(mte_free_queue_idx_t, uint32_t, {
	MTE_FREE_UNTAGGABLE_0,
	MTE_FREE_UNTAGGABLE_1,
	MTE_FREE_UNTAGGABLE_2,
	MTE_FREE_ACTIVE_0,
	MTE_FREE_ACTIVE_1,
	MTE_FREE_ACTIVE_2,
	MTE_FREE_ACTIVE_3,
	MTE_FREE_UNTAGGABLE_ACTIVATING,
	MTE_FREE_NOT_QUEUED,
});


#pragma mark Counters and Globals

/*!
 * The cell lists, in mte_cell_list_idx_t order.
 *
 * Each list contains this many buckets:
 *  - MTE_LIST_DISABLED_IDX:    1
 *  - MTE_LIST_PINNED_IDX:      1
 *  - MTE_LIST_CLAIMED_IDX:     MTE_BUCKETS_COUNT_MAX
 *  - MTE_LIST_INACTIVE_IDX:    MTE_BUCKETS_COUNT_MAX
 *  - MTE_LIST_RECLAIMING_IDX:  1
 *  - MTE_LIST_ACTIVATING_IDX:  1
 *  - MTE_LIST_ACTIVE_0_IDX:    MTE_BUCKETS_COUNT_MAX
 *  - MTE_LIST_ACTIVE_IDX:      1
 */
extern struct mte_cell_list mte_info_lists[MTE_LISTS_COUNT];

/*!
 * The MTE free queues.
 */
extern struct vm_page_free_queue mte_free_queues[MTE_FREE_NOT_QUEUED];

#ifndef VM_MTE_FF_VERIFY

/*!
 * @var vm_cpu_free_count
 * Scalable counter of the number of free pages CPU free list.
 * (not an MTE concept but here for the sake of vm_unix.c)
 *
 * @var vm_cpu_free_tagged_count
 * Scalable counter of the number of free tagged pages on CPU free lists.
 *
 * @var vm_cpu_free_tagged_count
 * Scalable counter of the number of free claimed pages on CPU free lists.
 *
 * @var vm_mte_tagged_pages_grabbed
 * Scalable counter of the number of tagged pages grabbed, cumulative.
 *
 * @var vm_mte_tagged_pages_grabbed_for_untagged
 * Scalable counter of the number of tagged pages grabbed to service untagged
 * demand, cumulative.
 *
 * @var vm_mte_inline_ts_activated_count
 * Scalable counter of the number of tag storage pages activated for tagged
 * memory.
 */
SCALABLE_COUNTER_DECLARE(vm_cpu_free_count);
SCALABLE_COUNTER_DECLARE(vm_cpu_free_tagged_count);
SCALABLE_COUNTER_DECLARE(vm_cpu_free_claimed_count);
SCALABLE_COUNTER_DECLARE(vm_mte_tagged_pages_grabbed);
SCALABLE_COUNTER_DECLARE(vm_mte_tagged_pages_grabbed_for_untagged);
SCALABLE_COUNTER_DECLARE(vm_mte_inline_ts_activated_count);

#endif /* VM_MTE_FF_VERIFY */

/*!
 * @var vm_page_free_taggable_count
 * Number of free pages in the MTE_FREE_ACTIVE_* MTE free queue buckets.
 *
 * @var vm_page_free_unmanaged_tag_storage_count
 * Number of free unmanaged tag storage pages. These do not participate in the
 * global free count.
 *
 * @var vm_page_recursive_tag_storage_count
 * Number of recursive tag storage pages.
 * These should be VM_MEMORY_CLASS_DEAD_TAG_STORAGE.
 *
 * @var vm_page_retired_tag_storage_count
 * Number of retired tag storage pages.
 * These should be unusable pages due to ECC errors.
 *
 * @var vm_page_unmanaged_tag_storage_count
 * Number of unmanaged tag storage pages.
 * These should be VM_MEMORY_CLASS_DEAD_TAG_STORAGE.
 *
 * @var vm_page_wired_tag_storage_count
 * Number of tag storage range pages that are wired (note: this is not
 * current the number of VM_MEMORY_CLASS_TAG_STORAGE pages that are wired).
 *
 * @var vm_page_tagged_count
 * Number of tagged pages in use.
 *
 * @var vm_mte_refill_thread_wakeups
 * The number of times the refill thread was woken up.
 *
 * @var vm_page_tag_storage_activation_count
 * Number of activation (inactive/claimed -> active) transitions ever done.
 *
 * @var vm_page_tag_storage_deactivation_count
 * Number of deactivation (active -> inactive) transitions ever done.
 *
 * @var vm_page_tag_storage_reclaim_from_cpu_count
 * Number of times a claimed tag storage page was successfully reclaimed from
 * a cpu free list.
 *
 * @var vm_page_tag_storage_reclaim_success_count
 * Number of times a claimed tag storage page was successfully reclaimed.
 *
 * @var vm_page_tag_storage_reclaim_failure_count
 * Number of times a claimed tag storage page failed to be reclaimed.
 *
 * @var vm_page_tag_storage_reclaim_wired_failure_count
 * Number of times a claimed tag storage page failed to be reclaimed because it
 * was wired.
 *
 * @var vm_page_tag_storage_wire_relocation_count
 * Number of relocations of tag storage pages due to wiring.
 *
 * @var vm_page_tag_storage_reclaim_compressor_failure_count
 * Number of times a claimed tag storage page failed to be reclaimed because it
 * was used in the compressor pool and getting swapped out.
 *
 * @var vm_page_tag_storage_compressor_relocation_count
 * Number of relocations of tag storage pages due to the compressor.
 *
 * @var vm_page_free_wanted_tagged
 * Number of threads that are waiting for covered tagged pages.  Also the event
 * those threads wait on.
 *
 * @var vm_page_free_wanted_tagged_privileged
 * Number privileged threads that are waiting for covered tagged pages.  Also
 * the event those threads wait on.
 */
extern uint32_t vm_page_free_taggable_count;
extern uint32_t vm_page_free_unmanaged_tag_storage_count;
extern uint32_t vm_page_recursive_tag_storage_count;
extern uint32_t vm_page_retired_tag_storage_count;
extern uint32_t vm_page_unmanaged_tag_storage_count;
extern uint32_t vm_page_wired_tag_storage_count;
extern uint32_t vm_page_tagged_count;
extern uint64_t vm_mte_refill_thread_wakeups;
extern uint64_t vm_page_tag_storage_activation_count;
extern uint64_t vm_page_tag_storage_deactivation_count;
extern uint64_t vm_page_tag_storage_reclaim_from_cpu_count;
extern uint64_t vm_page_tag_storage_reclaim_success_count;
extern uint64_t vm_page_tag_storage_reclaim_failure_count;
extern uint64_t vm_page_tag_storage_reclaim_wired_failure_count;
extern uint64_t vm_page_tag_storage_wire_relocation_count;
extern uint64_t vm_page_tag_storage_reclaim_compressor_failure_count;
extern uint64_t vm_page_tag_storage_compressor_relocation_count;
extern uint32_t vm_page_free_wanted_tagged;
extern uint32_t vm_page_free_wanted_tagged_privileged;

/*!
 * @abstract
 * Counters for MEMINFO tracepoints.
 *
 * @var vm_mte_refill_ts_considered_count
 * Number of tag storage pages the refill thread has considered.
 *
 * @var vm_mte_refill_ts_activated_count
 * Number of tag storage pages for normal tagged memory the refill thread has
 * activated.
 *
 * @var vm_mte_refill_ts_deactivated_count
 * Number of tag storage pages for normal tagged memory the refill thread has
 * deactivated.
 */
extern uint32_t vm_mte_refill_ts_considered_count;
extern uint64_t vm_mte_refill_ts_activated_count;
extern uint64_t vm_mte_refill_ts_deactivated_count;

#ifndef VM_MTE_FF_VERIFY
/*!
 * @var vm_cpu_claimed_count
 * Scalable counter of the number of claimed tag storage pages allocated.
 */
SCALABLE_COUNTER_DECLARE(vm_cpu_claimed_count);
#endif /* VM_MTE_FF_VERIFY */

/*!
 * @var vm_page_tag_storage_reserved
 * Number of free tag storage pages reserved for the fill thread.
 */
extern uint32_t vm_page_tag_storage_reserved;

/*!
 * @var vm_mte_tag_storage_for_compressor
 * Whether we use tag storage pages for the compressor pool.
 */
extern bool vm_mte_tag_storage_for_compressor;

/*!
 * @var vm_mte_tag_storage_for_vm_tags_mask
 * Which VM tags can use tag storage.
 */
extern bitmap_t vm_mte_tag_storage_for_vm_tags_mask[BITMAP_LEN(VM_MEMORY_COUNT)];

/*!
 * @abstract
 * Compute the current number of claimable tag storage pages.
 */
extern uint32_t mteinfo_claimable_count(void);

#if MACH_KERNEL_PRIVATE
#pragma mark Tag storage space state machine

/*!
 * @function mteinfo_tag_storage_disabled()
 *
 * @abstract
 * Returns whether a tag storage page is disabled.
 *
 * @discussion
 * Unlike other mteinfo_* functions, this can be called without the free queue
 * lock held because disabling pages is a one way transition after lockdown,
 * and before lockdown the kernel is single threaded.
 *
 * @param page  The pointer to a page inside the tag storage space.
 */
extern bool mteinfo_tag_storage_disabled(const struct vm_page *page);


/*!
 * @function mteinfo_tag_storage_is_active()
 *
 * @abstract
 * Returns whether a tag storage page is active.
 *
 * @param page  The pointer to a page inside the tag storage space.
 */
extern bool mteinfo_tag_storage_is_active(const struct vm_page *page);


/*!
 * @function mteinfo_tag_storage_set_retired()
 *
 * @abstract
 * Mark a tag storage page as retired due to ECC errors.
 *
 * @param page  The pointer to a page inside the tag storage space.
 */
extern void mteinfo_tag_storage_set_retired(struct vm_page *page);

/*!
 * @function mteinfo_tag_storage_set_inactive()
 *
 * @abstract
 * Mark a tag storage page as inactive.
 *
 * @param page  The pointer to a page inside the tag storage space.
 * @param init  This is the initial "inactive" transition.
 */
extern void mteinfo_tag_storage_set_inactive(struct vm_page *page, bool init);

/*!
 * @function mteinfo_tag_storage_set_claimed()
 *
 * @abstract
 * Mark a tag storage page as claimed for regular memory usage.
 *
 * @discussion
 * The tag storage page must be either inactive or reclaiming.
 *
 * @param page  The pointer to a page inside the tag storage space.
 */
extern void mteinfo_tag_storage_set_claimed(struct vm_page *page);

/*!
 * @function mteinfo_tag_storage_wakeup()
 *
 * @abstract
 * Mark a tag storage page as no longer pinned.
 *
 * @discussion
 * The tag storage page must be in the pinned state.
 * The page queues lock must be held.
 *
 * @param page          The pointer to a page inside the tag storage space.
 * @param fq_locked     Whether the page free queue lock is held.
 */
extern void mteinfo_tag_storage_wakeup(struct vm_page *page, bool fq_locked);


#pragma mark Covered pages state machine

/*!
 * @function mteinfo_covered_page_taggable()
 *
 * @abstract
 * Returns whether a specified covered page has an active tag storage page
 * associated.
 *
 * @param pnum  A page number outside of the tag storage space.
 */
extern bool mteinfo_covered_page_taggable(ppnum_t pnum);

/*!
 * @function mteinfo_covered_page_set_free()
 *
 * @abstract
 * Mark the specified untagged page as free in its tag storage tracking metadata.
 *
 * @param pnum          A page number outside of the tag storage space.
 * @param tagged        Whether the page will was used as tagged.
 */
extern void mteinfo_covered_page_set_free(ppnum_t pnum, bool tagged);

/*!
 * @function mteinfo_covered_page_set_used()
 *
 * @abstract
 * Mark the specified untagged page as used in its tag storage tracking metadata.
 *
 * @param pnum          A page number outside of the tag storage space.
 * @param tagged        Whether the page will be used as tagged.
 */
extern void mteinfo_covered_page_set_used(ppnum_t pnum, bool tagged);

/*!
 * @function mteinfo_covered_page_set_stolen_tagged()
 *
 * @abstract
 * Mark the specified page as using MTE in its tag storage tracking metadata.
 *
 * @discussion
 * These pages are expected to be "stolen" in that bootstrap has allocated them
 * through bootstrap allocation strategies (see: bump allocation) before MachVM
 * is properly initialized and able to call into this module properly.  Because
 * of this, bootstrap will call into this method to directly tell the module
 * that the page is used as tagged now.
 *
 * @param pnum  A page number outside of the tag storage space,
 *              the page must be used.
 */
__startup_func
extern void mteinfo_covered_page_set_stolen_tagged(ppnum_t pnum);

/*!
 * @function mteinfo_covered_page_clear_tagged()
 *
 * @abstract
 * Mark the specified page as no longer using MTE in its tag storage tracking
 * metadata, while remaining "in use".
 *
 * @param pnum  A page number outside of the tag storage space,
 *              the page must be used.
 */
extern void mteinfo_covered_page_clear_tagged(ppnum_t pnum);


#pragma mark Activate

/*!
 * @function mteinfo_tag_storage_try_activate()
 *
 * @abstract
 * Try to activate tag storage pages in order to make a certain amount of
 * covered taggable pages available.
 *
 * @discussion
 * This must be called with the page free queue lock held.
 * This function will have dropped the free queue lock if it returns true.
 *
 * @param target        how many covered taggable free pages to try to generate
 *                      as a result of this activation.
 * @param spin_mode     whether to take the free page queue lock in spin mode.
 *
 * @returns             whether the page free queue lock was dropped
 *                      (in which case it means pages have been activated,
 *                      either by this thread or another we synchronized with).
 */
extern bool mteinfo_tag_storage_try_activate(uint32_t target, bool spin_mode);


#pragma mark Refill

/*!
 * @function mteinfo_wake_fill_thread()
 *
 * @abstract
 * Wake the fill thread if it has not already been woken.
 */
extern void mteinfo_wake_fill_thread(void);


#pragma mark Alloc

/*!
 * @function mteinfo_free_queue_grab()
 *
 * @abstract
 * Gets pages from the MTE free queue.
 *
 * @discussion
 * Clients cannot get more pages than the free queue has; attempting to do so
 * will cause a panic.
 *
 * @param vmp_pcpu      The per-cpu vm page structure for the current CPU.
 * @param options       The grab options.
 * @param mem_class     The memory class to allocate from.
 * @param num_pages     The number of pages to grab.
 * @param q_state       The vmp_q_state to set on the page.
 *
 * @returns
 * A list of pages; the list will be at least num_pages long.
 */
extern vm_page_list_t mteinfo_free_queue_grab(
	vm_page_pcpu_t          vmp_pcpu,
	vm_grab_options_t       options,
	vm_memory_class_t       mem_class,
	unsigned int            num_pages,
	vm_page_q_state_t       q_state);


/*!
 * @function mteinfo_page_list_fix_tagging()
 *
 * @abstract
 * Fix the tagging for a list returned by @c mteinfo_free_queue_grab().
 *
 * @discussion
 * Preemption must be disabled (under the same preemption disabled
 * hold as the call to @c mteinfo_free_queue_grab() that preceded).
 *
 * @param mem_class     The memory class being allocated.
 * @param list          The list returned by mteinfo_free_queue_grab().
 */
extern void mteinfo_page_list_fix_tagging(
	vm_memory_class_t       mem_class,
	vm_page_list_t         *list);


#pragma mark Bootstrap API

extern void mteinfo_init(uint32_t num_tag_pages);

#if HIBERNATION

/*!
 * @abstract
 * Iterate all free pages from the MTE free queue (covered or tag storage).
 */
extern void mteinfo_free_queue_foreach(void (^block)(vm_page_t));

#endif /* HIBERNATION */

/*!
 * @function mteinfo_tag_storage_release_startup()
 *
 * @abstract
 * Marks a tag storage page active or inactive, as appropriate.
 *
 * @discussion
 * The tag storage page does not have to be active, but none of its covered
 * pages may have been made tagged.  If the tag storage page was active, then
 * it will be put on a list to be added to the mte_tags_object by @see
 * mteinfo_tag_storage_startup_list_flush.
 *
 * @param page
 * The tag storage page to be marked.
 */
__startup_func
extern void mteinfo_tag_storage_release_startup(vm_page_t page);

#endif /* MACH_KERNEL_PRIVATE */
#pragma mark Counter methods

/*!
 * @function mteinfo_tag_storage_fragmentation()
 *
 * @abstract
 * Computed value returning the tag storage fragmentation
 * in parts per thousand.
 *
 * @param actual        Whether to show the "actual" fragmentation
 *                      or what is achievable assuming enough memory
 *                      pressure.
 */
extern uint32_t mteinfo_tag_storage_fragmentation(bool actual);

/*!
 * @function mteinfo_tag_storage_active()
 *
 * @abstract
 * Computed value returning the number of active tag storage pages (including
 * those without any tags).
 */
extern uint32_t mteinfo_tag_storage_active(void);

/*!
 * @function mteinfo_tag_storage_active_locked()
 *
 * @abstract
 * Computed value returning the number of active tag storage pages, excluding
 * those with no covered pages.
 */
extern uint32_t mteinfo_tag_storage_active_locked(void);

/*!
 * @function mteinfo_tag_storage_active_zero_locked()
 *
 * @abstract
 * Computed value returning the number of "active" tag storage pages which
 * currently hold no tags but have not been retyped.
 */
extern uint32_t mteinfo_tag_storage_active_zero_locked(void);

/*!
 * @function mteinfo_tag_storage_unused_locked()
 *
 * @abstract
 * Computed value returning the number of tag storage pages in an inactive,
 * transitioning, or free state.
 */
extern uint32_t mteinfo_tag_storage_free_locked(void);

/*!
 * @function mteinfo_tag_storage_nontags_wired_locked()
 *
 * @abstract
 * Computed value returning the number of claimed, allocated, wired tag storage pages.
 */
extern uint32_t mteinfo_tag_storage_nontags_wired_locked(void);

/*!
 * @function mteinfo_tag_storage_nontags_unwired_locked()
 *
 * @abstract
 * Computed value returning the number of claimed, allocated, unwired tag storage pages.
 */
extern uint32_t mteinfo_tag_storage_nontags_pageable_locked(void);

/*!
 * @function mteinfo_tag_storage_free_pages_for_covered()
 *
 * @abstract
 * Returns the number of covered pages that are free for the tag storage page
 * associated with this page.
 *
 * @param page  The pointer to a page outside of the tag storage space.
 */
extern uint32_t mteinfo_tag_storage_free_pages_for_covered(const struct vm_page *page);

/*!
 * @function mteinfo_increment_wire_count()
 *
 * @abstract
 * Increment the wired tag storage page counter if the given page is tag
 * storage.
 *
 * @discussion
 * This currently considers all pages in the tag storage range to be tag
 * storage, whether or not they are VM_MEMORY_CLASS_TAG_STORAGE.  This is due
 * to how the other page counters are initialized; currently they account for
 * all tag storage range pages.
 *
 * Note that the callers should make sure the reason for wiring isn't because
 * the page is used for tag storage by checking against the VM_KERN_MEMORY_MTAG
 * tag which is used in that case.
 *
 * @param page
 * The page being wired.
 */
extern void mteinfo_increment_wire_count(vm_page_t page);

/*!
 * @function mteinfo_decrement_wire_count()
 *
 * @abstract
 * Decrement the wired tag storage page counter if the given page is tag
 * storage.
 *
 * @discussion
 * This currently considers all pages in the tag storage range to be tag
 * storage, whether or not they are VM_MEMORY_CLASS_TAG_STORAGE.  This is due
 * to how the other page counters are initialized; currently they account for
 * all tag storage range pages.
 *
 * Note that this function is a no-op if the page was associated with the
 * mte_tags_object as it means its wiring was because it's used for tag storage.
 *
 * @param page          The page being wired.
 * @param pqs_locked    Whether the page queues locked is held
 *                      (possibly in spin mode).
 */
extern void mteinfo_decrement_wire_count(vm_page_t page, bool pqs_locked);

#ifndef VM_MTE_FF_VERIFY
/*!
 * @function mteinfo_vm_tag_can_use_tag_storage()
 *
 * @abstract
 * Determine if a given VM tag is eligible to dip into tag storage.
 *
 * @param vm_tag		The VM tag in question.
 */
extern bool mteinfo_vm_tag_can_use_tag_storage(vm_tag_t vm_tag);
/*!
 * @function kdp_mteinfo_snapshot()
 *
 * @abstract
 * Snapshot the current state of all tag storage pages.
 *
 * @discussion
 * Can only be called from debugger context.
 *
 * @param cells        Array of struct mte_cell_info (from kcdata.h)
 * @param count        Size of the array, must match mte_tag_storage_count
 */
extern void kdp_mteinfo_snapshot(struct mte_info_cell __counted_by(count) *cells, size_t count);


#endif /* VM_MTE_FF_VERIFY */

#if DEBUG || DEVELOPMENT
/*!
 * @function mteinfo_covered_page_is_kernel_tagged()
 *
 * @abstract
 * Get the MTE tag data page of a covered page, as well as the internal offset
 * to the tag data within the tag page.
 *
 * @param pnum          The covered page in question.
 * @param offset_to_tag_data  Output parameter to return the offset to the
 *                      covered page's data within the tag data page.
 *
 * @return The MTE tag data page of the covered page, or NULL if the covered
 *         page is not taggable.
 *
 */
extern vm_page_t mteinfo_tag_page_from_covered_page(
	ppnum_t pnum,
	vm_offset_t * offset_to_tag_data);
#endif /* DEBUG || DEVELOPMENT */
#endif /* HAS_MTE */
__END_DECLS

#endif /* _VM_VM_MTEINFO_INTERNAL_H_ */
