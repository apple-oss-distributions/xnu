/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

/* Guard header includes, so that the userspace test can include this file. */
#include <os/atomic_private.h>
#ifndef VM_MTE_FF_VERIFY
#include <debug.h>
#include <mach_assert.h>

#include <kern/bits.h>
#include <kern/kcdata.h>
#include <kern/queue.h>

#include <mach/sdt.h>

#include <vm/pmap.h>
#include <vm/vm_compressor_internal.h>
#include <vm/vm_kern.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_page_internal.h>
#include <vm/vm_pageout.h>
#include <vm/vm_mteinfo_internal.h>

extern lck_grp_t vm_page_lck_grp_bucket;

#endif /* VM_MTE_FF_VERIFY */
#pragma mark Documentation
#if HAS_MTE

/*
 * VM MTE Info
 * ===========
 *
 * The top level goal of this code is to implement the policies managing the
 * selection of tag storage pages on the system, in order to:
 * - Minimize the number of live tag storage pages at any given time;
 * - Maximize occupancy (the number of covered pages using MTE compared to tag
 *   storage pages actually being used for tag storage).
 *
 *
 * Physical Memory Layout
 * ----------------------
 *
 * The diagram below describes the general layout of the physical memory. iBoot
 * will determine the placement of the tag storage region, at the end of the
 * managed address space.
 *
 * As a result, the tag storage space is always part of the vm_pages array.
 * However, several things should be noted:
 *
 * - The last tag storage pages cover unmanaged DRAM at the end of physical
 *   memory, as well as the tag storage space itself, and will never be used as
 *   tag storage memory by the system (the unmanaged space will not be MTE'd,
 *   and the tag storage space will never itself use MTE).
 *
 * - The first tag storage pages also cover unmanaged DRAM space at the
 *   beginning of physical memory, but might be used for tagging due to early
 *   boot code.  However, these first tag storage pages will not be used for
 *   tag storage space dynamically by the system.
 *
 * - The beginning of the tag region space is always aligned to a 32 page
 *   boundary; however the start of the vm_pages array is not. As a result,
 *   there is a cluster of 32 pages that possibly crosses this boundary. This
 *   is relevant because dynamic tag storage management only functions for
 *   taggable pages inside the vm_pages array.
 *
 *
 *                            ┌────────────┐─╮
 *                            │    P_n+31  │ │
 *                            ├────────────┤ │
 *                            ╎     ...    ╎ │
 *                            ├────────────┤ │
 *                            │     P_n    │ │
 *                            ├────────────┤─╯
 *                            │            │
 *                            ╎            ╎
 *                            ╎     ...    ╎
 *                            ╎            ╎
 *                            │            │
 *   mte_tag_storage_end ─ ─ ─├────────────┤ ─ ─ ─ vm_pages_end
 *              ┬             │TTTTTTTTTTTT│ Tag storage for pages [n:n+31]
 *              │             ├────────────┤
 *              │             │            │
 *              │             ╎     ...    ╎
 *              │             │            │
 *              │             ├────────────┤
 *       1/32   │             │TTTTTTTTTTTT│ Tag storage for pages [i:i+31]
 *      of DRAM │             ├────────────┤
 *              │             │            │
 *              │             ╎     ...    ╎
 *              │             │            │
 *              │             ├────────────┤
 *              │             │TTTTTTTTTTTT│ Tag storage for pages [32:63]
 *              │             ├────────────┤
 *              ┴             │TTTTTTTTTTTT│ Tag storage for pages [0:31]
 * mte_tag_storage_start ─ ─ ─├────────────┤─╮
 *                            │    P_i+31  │ │
 *                            ├────────────┤ │
 *                            ╎     ...    ╎ │
 *                            ├────────────┤ │
 *                            │     P_i    │ │
 *                            ├────────────┤─╯
 *                            │            │
 *                            ╎            ╎
 *                            ╎     ...    ╎
 *                            ╎            ╎
 *                            │            │
 *                            ├────────────┤─╮
 *                            │            │ │
 *                            ╎     ...    ╎ │
 *                            ├────────────┤ │ ─ ─ vm_pages
 *                            ╎     ...    ╎ │
 *                            │            │ │
 *                            │────────────┤─╯
 *                            │            │
 *                            ╎            ╎
 *                            ╎     ...    ╎
 *                            ╎            ╎
 *                            │            │
 *                            ├────────────┤─╮
 *                            │    P_31    │ │
 *                            ├────────────┤ │
 *                            ╎     ...    ╎ │
 *                            ├────────────┤ │
 *                            │    P_0     │ │
 *  pmap_first_pnum        ─ ─└────────────┘─╯ ─ ─ gDramBase
 *                           Physical Memory
 *
 *
 * Tag storage and cells
 * ~~~~~~~~~~~~~~~~~~~~~
 *
 * Tag storage pages require metadata to track their state machine, in order to
 * not grow the vm_page_t data structure for all pages on the system when only
 * 1/32 of them are tag storage.
 *
 * The metadata is stored into a data structure called the MTE cell
 * (@see cell_t) which is queued into the so called MTE Info data structure
 * (@see @c mte_info_lists).
 *
 * The documentation of this file happily calls a cell a tag storage page and
 * vice versa as result, since the mapping is 1:1.
 *
 *
 * Tag storage state machine
 * ~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Disabled is a special state: this is the state cells start in,
 * and never transition back to unless there is an ECC error.
 *
 * The state diagram involving "Disabled" looks like this:
 *
 *     ╭──────────────╮          ╭───╴K.3╶──╮          ╔══════════════╗
 *     │  RECLAIMING  ┼───╮      │          v     ╭───>║    ACTIVE    ║
 *     ╰──────────────╯  K.1   ╔═╪════════════╗  I.1   ╚══════════════╝
 *                        ├───>║   DISABLED   ╫───┤
 *      ╔═════════════╗  K.2   ╚══════════════╝  I.2   ╔══════════════╗
 *      ║   CLAIMED   ╫───╯      ^          ^     ╰───>║   INACTIVE   ║
 *      ╚═══════════╪═╝          │          │          ╚═╪════════════╝
 *                  ╰────╴U.1╶───╯          ╰───╴U.2╶────╯
 *
 *   ╔═╗ Double bar square boxes         ╭─╮ Single bar round boxes
 *   ╚═╝ denote stable states.           ╰─╯ denote transitionary states.
 *
 *
 * Initialization (I.1, I.2)
 *
 *   This is performed by mteinfo_tag_storage_release_startup()
 *   This function might decide to leave pages as disabled.
 *
 * Unmanaged discovery (U.1, U.2)
 *
 *   This is performed at lockdown by mteinfo_tag_storage_unmanaged_discover()
 *   to discover tag storage that covers pages that will never have a canonical
 *   vm_page_t made for them, which are effectively unmanaged.
 *
 * Retirement (K.1, K.2, K.3)
 *
 *   This is performed by mteinfo_tag_storage_set_retired(),
 *   itself called by vm_page_retire() which can only happen
 *   for pages that were never created (the cell will be DISABLED),
 *   or on the tag storage claimed page free path (the cell
 *   will either be RECLAIMING or CLAIMED).
 *
 *
 * The rest of the tag storage state machine looks like this:
 *
 *                            ╭──────────────╮
 *               ╭────╴D.2╶───┼ DEACTIVATING │<───╴D.1╶────╮
 *               │      a     ╰──────────────╯      a      │
 *               v                                         │
 *  ╔══════════════╗          ╭──────────────╮           ╔═╪════════════╗
 *  ║   INACTIVE   ╫──╴A.1╶──>│  ACTIVATING  ┼───╴A.2╶──>║    ACTIVE    ║<─╮
 *  ╚════════════╪═╝   i/a    ╰──────────────╯    i/a    ╚══════════════╝  │
 *    ^          │                                                         │
 *    │          │                                                         │
 *    │          │                          ╔════════════╗                 │
 *    │          │              ╭───╴B.2╶───╫   PINNED   ║<───╴B.1╶───╮    │
 *    │          │              │     i     ╚════════════╝      a     │   R.2
 *    │          │              │                                     │    a
 *    │          │              │          ╭─────╴R.x╶─────╮          │    │
 *    │          │              v          v       a       │          │    │
 *    │          │            ╔═════════════╗            ╭─┼──────────┼─╮  │
 *    │          ╰────╴C.1╶──>║   CLAIMED   ╫────╴R.1╶──>│  RECLAIMING  ┼──╯
 *    │                 i     ╚═╪═══════════╝      a     ╰─┼────────────╯
 *    │                         │                          │
 *    ╰──────────╴F.1╶──────────╯<─────────╴F.2╶───────────╯
 *                 i                         i
 *
 *   ╔═╗ Double bar square boxes         ╭─╮ Single bar round boxes
 *   ╚═╝ denote stable states.           ╰─╯ denote transitionary states.
 *
 *    a  the transition can be done by the refill thread (async)
 *    i  the transition can be done inline by any thread.
 *
 *
 * Activation (A.1, A.2)
 *
 *   [A.1 inline] is performed by mteinfo_tag_storage_try_activate() by
 *   vm_page_grab_slow() if the current grab would deplete the taggable
 *   space too much and that there seem to be an ample reserve of free
 *   pages.
 *
 *   This path however will limit itself to pages that are really worth
 *   activating (17+ free associated pages, which coincide with the first 3
 *   mteinfo buckets for MTE_STATE_INACTIVE).
 *
 *
 *   [A.1 async] is performed by mteinfo_tag_storage_active_refill() when it
 *   decides that activating pages is the best strategy to get more taggable
 *   pages.  It will only do so if [R.1 async] isn't more profitable.
 *
 *
 *   [A.2 inline/async] is performed by mteinfo_tag_storage_activate_locked()
 *   on the results of [A.1 inline/async]. The most notable thing to mention
 *   is until the tag pages are fully activated, no tagged page can be
 *   allocated, and if the thread doing this operation inline is a low priority
 *   thread, this could cause starvation due to priority inversions.
 *
 *   To prevent this issue, turnstiles are used for the inline case so that
 *   there's a single activator at a time with priority inversion avoidance.
 *   The async path doesn't use this as it is a very high priority thread,
 *   and is meant to run in case of emergencies.
 *
 *
 * Deactivation (D.1, D.2)
 *
 *   [D.1 async] is performed by mteinfo_tag_storage_drain(). The refill
 *   thread will invoke this function after it is done with activations.
 *
 *   This phase will only drain active(0.0) pages, meaning pages that are active
 *   but have no free pages associated with it nor MTE pages. Having such pages
 *   on the system is a sign of untagged memory pressure, and it's probably
 *   a good idea to free that tag storage page so it can be used for untagged
 *   purposes (i.e., become claimed).
 *
 *   It will drain pages until the @c mte_claimable_queue has a healthy level.
 *
 *   This transition is triggered lazily from the @c mteinfo_free_queue_grab()
 *   path when untagged pages have been allocated and tapped into the taggable
 *   space, and that system conditions permit
 *   (see @c mteinfo_tag_storage_should_drain()).
 *
 *   [D.2 async] is performed by mteinfo_tag_storage_drain_flush(),
 *   which is called by mteinfo_tag_storage_drain() on the results
 *   of [D.1 async]
 *
 *
 * Allocation/Claiming (C.1)
 *
 *   [C.1 inline] is performed by @c mteinfo_tag_storage_claimable_refill()
 *   from the context of any @c mteinfo_free_queue_grab() (tagged or regular).
 *   The path relies on @c mteinfo_tag_storage_claimable_should_refill() to
 *   opportunistically determine whether there are sufficiently many inactive
 *   tag storage pages eligible to be claimed that amortizing the cost of taking
 *   the spinlock which protects the per-cpu queue is worth it.
 *
 *   It is done unconditionally otherwise, as the reclaim thread can steal
 *   from these queues. The @c vm_page_grab_options() fastpath knows how
 *   to draw from this directly.
 *
 *
 * Freeing (F.1, F.2)
 *
 *   [F.1 inline] is performed by page free paths who eventually call into
 *   @c vm_page_free_queue_enter(VM_MEMORY_CLASS_TAG_STORAGE).
 *
 *   [F.2 inline] is the exact same transition but for the case when the refill
 *   thread was attempting to reclaim this page (it had performed [R.1 async]).
 *   It is worth nothing that on paper, the [C.1 inline] transition could happen
 *   again before the refill thread notices.
 *
 *
 * Reclaiming (R.1, R.2, R.x, B.1, B.2)
 *
 *   [R.1 async] is performed by mteinfo_tag_storage_active_refill() when it
 *   decides that reclaiming (stealing) pages is the best strategy to get more
 *   taggable pages. It will only do so if [A.1 async] isn't more profitable.
 *
 *   Once pages have been marked as reclaiming, it will attempt to either steal
 *   the page from the cpu free queue, or attempt a relocation.
 *
 *   [R.2 async] is exactly the same as [A.2 async], being performed by
 *   mteinfo_tag_storage_activate_locked() on the results of [R.1 async].
 *   The major difference however is that it is done one page at a time.
 *
 *   [B.1 async] is performed by @c mteinfo_reclaim_tag_storage_page() when
 *   the relocating a claimed page failed due to the page being pinned.
 *   In which case, the tag storage page is marked with @c vmp_ts_wanted bit.
 *
 *   [B.2 inline] is performed by @c mteinfo_tag_storage_wakeup() when threads
 *   notice that @c vmp_ts_wanted is set and that the condition causing it to be
 *   set has cleared.
 *
 *   [R.x async] is performed when stealing the page was otherwise not
 *   successful (in @c mteinfo_reclaim_tag_storage_page() or
 *   @c mteinfo_tag_storage_flush_reclaiming()).
 */


#pragma mark Types

/*!
 * @typedef cell_state_mask_t
 *
 * @abstract
 * Mask/bit-field version of the @c mte_cell_state_t bit in order to do assertions.
 */
__options_decl(cell_state_mask_t, uint32_t, {
	MTE_MASK_DISABLED       = BIT(MTE_STATE_DISABLED),
	MTE_MASK_PINNED         = BIT(MTE_STATE_PINNED),
	MTE_MASK_DEACTIVATING   = BIT(MTE_STATE_DEACTIVATING),
	MTE_MASK_CLAIMED        = BIT(MTE_STATE_CLAIMED),
	MTE_MASK_INACTIVE       = BIT(MTE_STATE_INACTIVE),
	MTE_MASK_RECLAIMING     = BIT(MTE_STATE_RECLAIMING),
	MTE_MASK_ACTIVATING     = BIT(MTE_STATE_ACTIVATING),
	MTE_MASK_ACTIVE         = BIT(MTE_STATE_ACTIVE),
});

#define MTE_FF_CELL_INDEX_BITS          24 /* Number of bits for a cell index */
#define MTE_FF_CELL_PAGE_COUNT_BITS     6  /* Number of bits for a page count */
#define MTE_FF_CELL_STATE_BITS          3

/*!
 * @typedef cell_idx_t
 *
 * @abstract
 * Represents the index of a cell in the cell array (when positive), or a queue
 * head (when negative).
 *
 * @discussion
 * This type only has @c MTE_FF_CELL_INDEX_BITS worth of significant bits.
 * Given that one bit is used to denote queues, it means we can support systems
 * with up to:
 * - 2^(MTE_FF_CELL_INDEX_BITS - 1) tag storage pages,
 * - 2^(MTE_FF_CELL_INDEX_BITS + 4) pages,
 * - 2^(MTE_FF_CELL_INDEX_BITS + 4 + PAGE_SHIFT) bytes.
 *
 * On a 16KB system (PAGE_SHIFT == 14) and with MTE_FF_CELL_INDEX_BITS == 24,
 * this covers 2^42 == 4TB of physical memory.
 */
typedef int32_t cell_idx_t;

typedef uint32_t cell_count_t;

/*!
 * @typedef cell_t
 *
 * @abstract
 * This data structure contains the metadata associated with a tag storage page,
 * and its covered pages in the mteinfo tracking data structure.
 *
 * @discussion
 * Here are some important invariants for this data structure:
 * - mte_page_count + popcount(free_mask) <= MTE_PAGES_PER_TAG_PAGE
 * - mte_page_count must be 0 unless state is DISABLED or ACTIVE.
 *
 * @field prev
 * Linkage to the prev cell (as an index in the cell array).
 *
 * @field next
 * Linkage to the next cell (as an index in the cell array).
 *
 * @field enqueue_pos
 * If @c free_mask isn't 0, this contains the index of the free covered page
 * which represents this cell in the mte free queues (@see @c mte_free_queues[]).
 *
 * @field mte_page_count
 * The number of pages covered with this tag storage page, that are currently
 * used and tagged.
 *
 * @field state
 * The current state of the tag storage page this cell represents.
 * @see mte_cell_state_t.
 *
 * @field free_mask
 * A bitmask where each bit set corresponds to an associated covered page that
 * is free (tagged or not).
 *
 * @field cell_count
 * When the cell is a queue head, the number of cells enqueued on this bucket.
 */
#pragma pack(4)
typedef struct {
	cell_idx_t              prev : MTE_FF_CELL_INDEX_BITS;
	cell_idx_t              next : MTE_FF_CELL_INDEX_BITS;
	cell_count_t            enqueue_pos : MTE_FF_CELL_PAGE_COUNT_BITS;
	cell_count_t            mte_page_count : MTE_FF_CELL_PAGE_COUNT_BITS;
	mte_cell_state_t        state : MTE_FF_CELL_STATE_BITS;
	uint8_t                 __unused_bits : 1;
	union {
		uint32_t        free_mask;
		uint32_t        cell_count;
	};
} cell_t;
#pragma pack()

static_assert(sizeof(cell_t) == 12);
static_assert(MTE_STATE_ACTIVE < (1u << MTE_FF_CELL_STATE_BITS));
static_assert(MTE_PAGES_PER_TAG_PAGE <= (1 << MTE_FF_CELL_PAGE_COUNT_BITS));

/*!
 * @typedef mte_cell_queue_t
 *
 * @abstract
 * This data structure represents a particular queue/bucket of cells.
 */
typedef struct mte_cell_queue_head {
	cell_t          head;
} *mte_cell_queue_t;

/*!
 * @typedef mte_cell_bucket_t
 *
 * @abstract
 * Represents the index of a bucket inside of a list.
 */
__enum_decl(mte_cell_bucket_t, uint32_t, {
	MTE_BUCKET_0,
	MTE_BUCKET_1_8,
	MTE_BUCKET_9_16,
	MTE_BUCKET_17_24,
	MTE_BUCKET_25_32,

	_MTE_BUCKET_COUNT,
});

static_assert(_MTE_BUCKET_COUNT == MTE_BUCKETS_COUNT_MAX);

#define MTE_QUEUES_COUNT \
	(1 /* disabled */ + \
	 1 /* pinned */ + \
	 MTE_BUCKETS_COUNT_MAX /* claimed */ + \
	 MTE_BUCKETS_COUNT_MAX /* inactive */ + \
	 1 /* deactivating */ + \
	 1 /* reclaiming */ + \
	 1 /* activating */ + \
	 MTE_BUCKETS_COUNT_MAX /* active_0 */ + \
	 1 /* active */ )


#pragma mark Behavioral boot-args

/*
 * Boot-arg to enable/disable the interface for grabbing tag storage pages.
 * This exists in case tunables or settings for tag storage management expose
 * us to page shortages or system hangs due to wired tag storage pages.  This
 * boot-arg should allow us to bypass any such issues.
 */
static TUNABLE(bool, vm_mte_enable_tag_storage_grab, "mte_ts_grab", true);

/*
 * Boot-args controlling the draining down of tag storage space
 *
 * @var vm_page_tag_storage_reserved
 * How many tag storage pages the inactive_0 queue needs to preserve
 * at all times.
 */
TUNABLE(uint32_t, vm_page_tag_storage_reserved, "mte_ts_grab_rsv", 100);

/*
 * Boot-arg controlling how many inactive tag storage pages the system needs to
 * have before we'll allow inactive tag storage pages to be claimed regardless
 * of how many free pages they cover.
 */
TUNABLE_DT_DEV_WRITEABLE(uint32_t, vm_page_tag_storage_inactive_target,
    "/defaults", "kern.mte_tag_storage_inactive_target", "mte_ts_nctv_tgt",
    24576, TUNABLE_DT_NONE); /* 1/32 of 12GB, in pages */

/*
 * Boot-arg to enable/disable grabbing tag storage pages for the compressor
 * pool.
 */
TUNABLE(bool, vm_mte_tag_storage_for_compressor, "mte_ts_compressor", true);

#ifndef VM_MTE_FF_VERIFY
/*
 * Boot-arg to enable/disable grabbing tag storage pages for specific VM tags.
 * Note that the string length was somewhat arbitrarily chosen, so if the use
 * case arises, we may need to bump that up...
 *
 * We currently allow allocations with the following VM tags to use tag storage:
 *  - VM_MEMORY_MALLOC_SMALL  (2)
 *  - VM_MEMORY_MALLOC_TINY   (7)
 *  - VM_MEMORY_MALLOC_NANO   (11)
 *  - VM_MEMORY_STACK         (30)
 *  - VM_MEMORY_TCMALLOC      (53)
 *  - APPLICATION_SPECIFIC_14 (253)
 *  - APPLICATION_SPECIFIC_16 (255)
 *
 * These tags were chosen because they have been observed to rarely ever become
 * wired on real systems.
 *
 * See vm_statistics.h for other potential candidates.
 */
static TUNABLE_STR(vm_mte_tag_storage_for_vm_tags, 256, "mte_ts_vmtag", "2,7,11,30,53,253,255,");
#endif /* VM_MTE_FF_VERIFY */

#pragma mark Counters and Globals

struct mte_cell_list mte_info_lists[MTE_LISTS_COUNT];

static SECURITY_READ_ONLY_LATE(cell_t *) mte_info_cells;

#ifndef VM_MTE_FF_VERIFY
/*
 * Fill thread state.  The wake state of the thread is tracked to minimize
 * scheduler interactions.  Guarded with the free page lock.
 */
static sched_cond_atomic_t fill_thread_cond = SCHED_COND_INIT;
static SECURITY_READ_ONLY_LATE(thread_t) vm_mte_fill_thread = THREAD_NULL;
static thread_t vm_mte_activator = THREAD_NULL;
static bool vm_mte_activator_waiters = false;

SCALABLE_COUNTER_DEFINE(vm_cpu_free_tagged_count);
SCALABLE_COUNTER_DEFINE(vm_cpu_free_claimed_count);
SCALABLE_COUNTER_DEFINE(vm_mte_tagged_pages_grabbed);
SCALABLE_COUNTER_DEFINE(vm_mte_tagged_pages_grabbed_for_untagged);
SCALABLE_COUNTER_DEFINE(vm_mte_inline_ts_activated_count);
#endif

/*
 * Free taggable pages queue, per-cpu queues, and its counters.
 *
 * guarded by the free page lock
 */
uint32_t vm_page_free_taggable_count;
uint32_t vm_page_free_unmanaged_tag_storage_count;
uint32_t vm_page_tagged_count; /* Total tagged covered pages. */
uint32_t vm_page_free_wanted_tagged = 0;
uint32_t vm_page_free_wanted_tagged_privileged = 0;

/*
 * Statistics exposed through MEMINFO tracepoints.
 */
uint32_t vm_mte_refill_ts_considered_count = 0;
uint64_t vm_mte_refill_ts_activated_count = 0;
uint64_t vm_mte_refill_ts_deactivated_count = 0;

/*
 * Counters for tag storage pages we will just give to the system permanently
 * for use as regular memory.  These could technically be a subset of the
 * claimed tag storage, but counting them separately is useful because they
 * will have a different page lifecycle than the claimed tag storage pages...
 * as when freed, these pages will go to the regular free queues.
 *
 * These shouldn't be mutated after bootstrap... so they have no lock.
 */
uint32_t vm_page_recursive_tag_storage_count;
uint32_t vm_page_retired_tag_storage_count;
uint32_t vm_page_unmanaged_tag_storage_count;

/*
 * The wired tag storage page count is guarded by the page queues lock.  This
 * counter is diagnostic; it exists to inform investigations about reclaim
 * efficiency.
 */
uint32_t vm_page_wired_tag_storage_count;

/*
 * Diagnostic counters for reclamation; describes how many times reclamation
 * attempts have succeeded or failed (as well as a breakout for failures due to
 * the page being wired).  Guarded by the free page lock.
 */
uint64_t vm_mte_refill_thread_wakeups;
uint64_t vm_page_tag_storage_activation_count;
uint64_t vm_page_tag_storage_deactivation_count;
uint64_t vm_page_tag_storage_reclaim_from_cpu_count;
uint64_t vm_page_tag_storage_reclaim_success_count;
uint64_t vm_page_tag_storage_reclaim_failure_count;
uint64_t vm_page_tag_storage_reclaim_wired_failure_count;
uint64_t vm_page_tag_storage_wire_relocation_count;
uint64_t vm_page_tag_storage_reclaim_compressor_failure_count;
uint64_t vm_page_tag_storage_compressor_relocation_count;

#ifndef VM_MTE_FF_VERIFY
/*
 * Diagnostic counter for reclamation describing the number of tag storage
 * pages that have ever been allocated as claimed. Note that this value
 * only increases.
 */
SCALABLE_COUNTER_DEFINE(vm_cpu_claimed_count);
#endif /* VM_MTE_FF_VERIFY */

/*
 * Array of 4 64-bit masks for which VM tags can use tag storage.
 * There are a total of 256 VM tags.
 * This shouldn't be mutated after bootstrap... so it has no lock.
 */
bitmap_t vm_mte_tag_storage_for_vm_tags_mask[BITMAP_LEN(VM_MEMORY_COUNT)];

#pragma mark cell_idx_t

__pure2
static bool
cell_idx_is_queue(cell_idx_t idx)
{
	return idx < 0;
}

__pure2
static cell_t *
cell_from_idx(cell_idx_t idx)
{
	return &mte_info_cells[idx];
}

__pure2
__attribute__((overloadable))
static cell_idx_t
cell_idx(const cell_t *cell)
{
	return (cell_idx_t)(cell - mte_info_cells);
}

__pure2
__attribute__((overloadable))
static cell_idx_t
cell_idx(mte_cell_queue_t queue)
{
	return cell_idx(&queue->head);
}

__pure2
static cell_count_t
cell_free_page_count(cell_t cell)
{
	return __builtin_popcountll(cell.free_mask);
}

__pure2
static ppnum_t
cell_first_covered_pnum(const cell_t *cell)
{
	return pmap_first_pnum + cell_idx(cell) * MTE_PAGES_PER_TAG_PAGE;
}


#pragma mark mte_cell_queue_t

/*
 * Based on the existing queue code in XNU.  Look at <kern/queue.h> for the
 * original code; done here due to the custom linkages.
 */

static cell_idx_t
cell_queue_first_idx(mte_cell_queue_t queue)
{
	return queue->head.next;
}

static cell_idx_t
cell_queue_last_idx(mte_cell_queue_t queue)
{
	return queue->head.prev;
}

static cell_t *
cell_queue_first(mte_cell_queue_t queue)
{
	return cell_from_idx(cell_queue_first_idx(queue));
}

static uint32_t
cell_queue_count(mte_cell_queue_t queue)
{
	return queue->head.cell_count;
}


static bool
cell_queue_insert_tail(mte_cell_queue_t queue, cell_t *cell)
{
	cell_idx_t qidx = cell_idx(queue);
	cell_idx_t tidx = cell_queue_last_idx(queue);
	cell_t    *tail = cell_from_idx(tidx);

	if (tail->next != qidx) {
		__queue_element_linkage_invalid(tail);
	}

	cell->next = qidx;
	cell->prev = tidx;
	queue->head.prev = tail->next = cell_idx(cell);

	/* If the original tail was the queue, then it was empty. */
	return cell_idx_is_queue(tidx);
}

static bool
cell_queue_remove(cell_t *cell)
{
	cell_idx_t pidx = cell->prev;
	cell_idx_t nidx = cell->next;
	cell_idx_t cidx = cell_idx(cell);
	cell_t    *prev = cell_from_idx(pidx);
	cell_t    *next = cell_from_idx(nidx);

	if (prev->next != cidx || next->prev != cidx) {
		__queue_element_linkage_invalid(cell);
	}

	next->prev = pidx;
	prev->next = nidx;
	/* No linkage cleanup because cells are never dequeued at rest. */

	/*
	 * If the prev and next indices are the same, then this is the head
	 * index, and the queue became empty
	 */

	return pidx == nidx;
}

#define cell_queue_foreach(it, q) \
	for (cell_t *it = cell_queue_first(q); \
	     it != &(q)->head; \
	     it = cell_from_idx(it->next))

#define cell_queue_foreach_safe(it, q) \
	for (cell_t *__next_it, *it = cell_queue_first(q); \
	     it != &(q)->head && (__next_it = cell_from_idx(it->next), 1); \
	     it = __next_it)


#pragma mark MTE free queue

/*
 * The MTE free queue is a multi-dimensioned queue that replaces the
 * vm_page_free_queue for covered pages on MTE targets.
 *
 * It is an array of colored free queues indexed by @c mte_free_queue_idx_t.
 *
 *
 * A queue of tag storage pages
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * When a tag storage page has no associated free covered pages, no page is
 * enqueued on the MTE free queue. However when a tag storage page has one or
 * more free covered pages, then there is exactly one of those pages is enqueued
 * on the MTE free queues.
 *
 * The chosen representative for the cell is remembered on the cell of the
 * associated tag storage @c cell_t::enqueue_pos value.
 *
 *
 * Enqueue / dequeue algorithm
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This chosen representative makes the cluster available for its page color,
 * and only this color, despite other colors being possibly available for this
 * tag storage page.
 *
 * When removing a free page from the MTE queue, if the page being grabbed
 * was the enqueued candidate, then the next enqueued candidate is chosen
 * as the next free page in bitmask "circular" order
 * (@see mteinfo_free_queue_next_bit()).
 *
 * As a result, by "pushing" the page forward this way, the tag storage page
 * will be made available through all colors that it can provide.
 *
 *
 * Allocation stability and bucket selection
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * The free queues are ordered as follows:
 *
 *   {claimed/disabled} -> {inactive_0, inactive_1} ->
 *   {active_0, active_1, active_2, active_3} -> {activating}
 *
 * This order is carefully selected to have the following crucial properties:
 *
 * - allocating untagged pages chooses buckets "left to right"
 *   (in increasing free queue index order).
 *
 * - allocating tagged pages chooses active buckets "right to left"
 *   (in decreasing free queue index from the active_* queues).
 *
 * - when allocating untagged pages, the impact on the tag storage page will
 *   be that it stays in the same free queue or moves "down" in the free queue
 *   indices order.
 *
 * - when allocating tagged pages, the impact on the tag storage page will
 *   be that it stays in the same free queue or moves "up" in the free queue
 *   indices order.
 *
 * This is important and allows for a nice optimization: if a tag storage page
 * was found to be a good candidate for a given grab operation, it will always
 * stay a "best" candidate until it has no free pages left, which allows for
 * allocations of contiguous spans of pages at once
 * (@see mteinfo_free_queue_grab()).
 *
 * Lastly, in order to find the first free bucket quickly,
 * @c mte_claimable_queue is a bitmask where a bit being set means that the
 * corresponding bucket has at least one queue non empty.
 *
 *
 * Tag Storage Free queue
 * ~~~~~~~~~~~~~~~~~~~~~~
 *
 * Tag storage pages can only be claimed if they are inactive, via the [C.1]
 * transition. Pages become inactive via Deactivation [D.*].
 *
 * However, as we mentioned, the MTE free queues only contain covered pages, and
 * not their associated tag storage pages. We do not want to claim tag storage
 * pages too aggressively, as doing so could obstruct the Activation [A.*]
 * transition when tagged pages are required.
 *
 * Usually, in situations with memory pressure, this tradeoff is balanced by
 * restricting the [C.1] transition to inactive tag storage pages covering at
 * most 8 free pages. These pages are unlikely to be profitable activation
 * candidates, and their lack of free covered pages demonstrates the existence
 * of untagged memory pressure on the system.
 *
 * However, *all* inactive tag storage pages may be claimed via [C.1] when the
 * system is determined to have an excess of inactive tag storage pages. The
 * definition of "excess" is controlled by the "mte_ts_nctv_tgt" boot-arg.
 *
 * Tag storage pages are always claimed from the lowest index non-empty inactive
 * bucket (i.e., in order of fewest-to-most free covered pages). Thus, those tag
 * storage pages with <= 8 free covered pages will always be claimed first, even
 * when the inactive target is exceeded.
 *
 * The @c mteinfo_free_queue_grab() code will promote these to a per-cpu
 * free queue that in turn the @c vm_page_grab_options() fastpath can tap into
 * as another opportunistic source of pages.
 */
struct vm_page_free_queue mte_free_queues[MTE_FREE_NOT_QUEUED];
static uint32_t mte_free_queue_mask;

/*!
 * @abstract
 * Computes the proper mte free queue index for a given cell.
 */
__pure2
static mte_free_queue_idx_t
mteinfo_free_queue_idx(cell_t cell)
{
	uint32_t free   = cell_free_page_count(cell);
	uint32_t tagged = cell.mte_page_count;
	uint32_t used   = MTE_PAGES_PER_TAG_PAGE - free - tagged;
	uint32_t n;

	if (cell.free_mask == 0) {
		return MTE_FREE_NOT_QUEUED;
	}

	switch (cell.state) {
	case MTE_STATE_DISABLED:
	case MTE_STATE_PINNED:
	case MTE_STATE_DEACTIVATING:
		return MTE_FREE_UNTAGGABLE_0;

	case MTE_STATE_CLAIMED:
	case MTE_STATE_INACTIVE:
		/*
		 * This is "clever" code to map:
		 * MTE_FREE_UNTAGGABLE_0: Claimed[0-16]
		 * MTE_FREE_UNTAGGABLE_1: Claimed[16-32], Inactive[0-16]
		 * MTE_FREE_UNTAGGABLE_2: Inactive[16-32]
		 */
		n = MTE_FREE_UNTAGGABLE_0 + cell.state - MTE_STATE_CLAIMED;
		static_assert(MTE_STATE_INACTIVE == MTE_STATE_CLAIMED + 1);
		return n + (free > MTE_PAGES_PER_TAG_PAGE / 2);

	case MTE_STATE_RECLAIMING:
	case MTE_STATE_ACTIVATING:
		return MTE_FREE_UNTAGGABLE_ACTIVATING;

	case MTE_STATE_ACTIVE:
		break;
	}

	/*
	 * Empirically this seems to give decent fragmentation results
	 * with alternating MTE/non-MTE workloads.
	 *
	 * This tries to find a balance between favoring buckets with mte pages
	 * allocated and to penalize buckets with untagged pages allocated,
	 * while keeping buckets with the most free pages on the fence.
	 *
	 * The distribution it generates can be printed by running the
	 * "active_buckets" subtest of tests/vm/vm_mteinfo.c
	 */

	n  = tagged + free / 5;
	n -= MIN(n, used) / 3;
	return MTE_FREE_ACTIVE_0 + fls(n / 4);
}

static vm_page_queue_t
mteinfo_free_queue_head(mte_free_queue_idx_t idx, uint32_t color)
{
	return &mte_free_queues[idx].vmpfq_queues[color].qhead;
}

/*!
 * @abstract
 * Computes the next bit in "circular" mask order
 *
 * @discussion
 * This computes the next bit set in @c mask that is larger or equal
 * to @c bit, or if none exist, then the smallest bit set in @c mask.
 *
 * This means that for a mask with positions mask={1, 5, 6, 10} set,
 * the "next" bit for:
 * - 4 is 5,
 * - 10 is 10,
 * - 12 is 1.
 *
 * @param mask        The mask to scan. The mask must be non 0.
 * @param bit         The bit to scan from.
 * @returns           The next bit set in "circular" order.
 */
static cell_count_t
mteinfo_free_queue_next_bit(uint32_t mask, cell_count_t bit)
{
	cell_count_t cur = bit % MTE_PAGES_PER_TAG_PAGE;

	mask = (mask >> cur) | (mask << (32 - cur));
	bit += ffs(mask) - 1;

	return bit % MTE_PAGES_PER_TAG_PAGE;
}

/*!
 * @abstract
 * Backend for CELL_UPDATE() to manage update/requeues to the mte free queue.
 *
 * @param cell        The new state of the cell.
 * @param orig        The original state of the cell.
 * @param oidx        The original free queue index for the cell.
 * @param nidx        The new free queue index for the cell.
 */
__attribute__((noinline))
static void
mteinfo_free_queue_requeue(
	cell_t                 *cell,
	const cell_t            orig,
	mte_free_queue_idx_t    oidx,
	mte_free_queue_idx_t    nidx)
{
	ppnum_t         first_pnum = cell_first_covered_pnum(cell);
	vm_page_queue_t queue;
	cell_count_t    bit = orig.enqueue_pos;
	vm_page_t       mem;

	if (oidx == MTE_FREE_NOT_QUEUED && nidx == MTE_FREE_NOT_QUEUED) {
		cell->enqueue_pos = -1;
		return;
	}

	if (oidx != MTE_FREE_NOT_QUEUED) {
		mem   = vm_page_find_canonical(first_pnum + bit);
		queue = mteinfo_free_queue_head(oidx,
		    (first_pnum + bit) & vm_color_mask);
		assert(bit_test(orig.free_mask, bit));

		vm_page_queue_remove(queue, mem, vmp_pageq);
		VM_COUNTER_DEC(&mte_free_queues[oidx].vmpfq_count);
		if (mte_free_queues[oidx].vmpfq_count == 0) {
			bit_clear(mte_free_queue_mask, oidx);
		}
	}

	if (nidx == MTE_FREE_NOT_QUEUED) {
		cell->enqueue_pos = -1;
	} else {
		bit   = mteinfo_free_queue_next_bit(cell->free_mask, bit);
		mem   = vm_page_find_canonical(first_pnum + bit);
		queue = mteinfo_free_queue_head(nidx,
		    (first_pnum + bit) & vm_color_mask);
		assert(bit_test(cell->free_mask, bit));

		cell->enqueue_pos = bit;
		vm_page_queue_enter_first(queue, mem, vmp_pageq);
		if (mte_free_queues[nidx].vmpfq_count == 0) {
			bit_set(mte_free_queue_mask, nidx);
		}
		VM_COUNTER_INC(&mte_free_queues[nidx].vmpfq_count);
	}
}


#pragma mark mte_cell_list_t

__pure2
static mte_cell_bucket_t
cell_list_idx_buckets(mte_cell_list_idx_t idx)
{
	switch (idx) {
	case MTE_LIST_INACTIVE_IDX:
	case MTE_LIST_CLAIMED_IDX:
	case MTE_LIST_ACTIVE_0_IDX:
		return MTE_BUCKETS_COUNT_MAX;
	default:
		return 1;
	}
}

__pure2
static mte_cell_list_idx_t
cell_list_idx(const cell_t cell)
{
	if (cell.state != MTE_STATE_ACTIVE || cell.mte_page_count == 0) {
		return (mte_cell_list_idx_t)cell.state;
	}

	return MTE_LIST_ACTIVE_IDX;
}

__pure2
static mte_cell_bucket_t
cell_list_bucket(const cell_t cell)
{
	if (cell_list_idx_buckets(cell_list_idx(cell)) > 1) {
		return (cell_free_page_count(cell) + 7) / 8;
	}
	return 0;
}

__attribute__((noinline))
static void
cell_list_requeue(
	cell_t                 *cell,
	mte_cell_list_idx_t     oidx,
	mte_cell_bucket_t       obucket,
	mte_cell_list_idx_t     nidx,
	mte_cell_bucket_t       nbucket)
{
	mte_cell_list_t olist = &mte_info_lists[oidx];
	mte_cell_list_t nlist = &mte_info_lists[nidx];

	if (cell_queue_remove(cell)) {
		bit_clear(olist->mask, obucket);
	}

	if (cell_queue_insert_tail(&nlist->buckets[nbucket], cell)) {
		bit_set(nlist->mask, nbucket);
	}

	olist->buckets[obucket].head.cell_count--;
	nlist->buckets[nbucket].head.cell_count++;

	if (olist != nlist) {
		olist->count--;
		nlist->count++;
	}
}

static cell_t *
cell_list_find_page_internal(
	mte_cell_list_idx_t     lidx,
	mte_cell_bucket_t       bucket,
	vm_page_t              *tag_page,
	bool                    first_page /* otherwise, last page. */)
{
	mte_cell_list_t  list = &mte_info_lists[lidx];
	uint32_t         mask = list->mask & (first_page ? bits_mask(bucket + 1) : ~bits_mask(bucket));
	mte_cell_queue_t queue;

	if (__improbable(mask == 0)) {
		*tag_page = VM_PAGE_NULL;
		return NULL;
	}

	queue = &list->buckets[(first_page ? ffs(mask) : fls(mask)) - 1];
	*tag_page = vm_tag_storage_page_get(cell_queue_first_idx(queue));

	return cell_queue_first(queue);
}

/*!
 * @abstract
 * Find a page in the first non-empty bucket that is smaller than the
 * specified bucket index. The page is taken from the head of the bucket.
 *
 * @param lidx          The list index to scan.
 * @param max_bucket    The maximum bucket index to consider (inclusive).
 * @param tag_page      The tag page associated with the returned cell.
 * @returns             The cell that was found or NULL.
 */
static inline cell_t *
cell_list_find_first_page(
	mte_cell_list_idx_t     lidx,
	mte_cell_bucket_t       max_bucket,
	vm_page_t              *tag_page)
{
	return cell_list_find_page_internal(lidx, max_bucket, tag_page, true);
}

/*!
 * @abstract
 * Find a page in the last non-empty bucket that is larger than the
 * specified bucket index. The page is taken from the head of the bucket.
 *
 * @param lidx          The list index to scan.
 * @param min_bucket    The minimum bucket index to consider (inclusive).
 * @param tag_page      The tag page associated with the returned cell.
 * @returns             The cell that was found or NULL.
 */
static inline cell_t *
cell_list_find_last_page(
	mte_cell_list_idx_t     lidx,
	mte_cell_bucket_t       min_bucket,
	vm_page_t              *tag_page)
{
	return cell_list_find_page_internal(lidx, min_bucket, tag_page, false);
}


#pragma mark Tag storage space state machine

/*!
 * Assert that a cell is in one of the states specified by the mask.
 */
#define assert_cell_state(cell, mask) \
	release_assert(((mask) & (1 << (cell)->state)) != 0)

/*!
 * Perform an arbitrary update on a cell, and update the MTE info queues
 * accordingly.
 *
 * This should be used this way:
 *
 * <code>
 *   // Preflights and asserts here
 *   assert_cell_state(cell_var, ...);
 *
 *   CELL_UPDATE(cell_var, cleared_bit, {
 *       // Mutations of cell_var here
 *       cell_var->state = ...;
 *   });
 * </code>
 *
 * @param cell          The cell to update.
 * @param cleared_bit   The bit that was cleared or -1
 * @param mut           Code that mutates its argument, and performs the
 *                      required update.
 */
#define CELL_UPDATE(cell, cleared_bit, ...)  ({                             \
	mte_cell_list_idx_t  __ol, __nl;                                        \
	mte_cell_bucket_t    __ob, __nb;                                        \
	mte_free_queue_idx_t __oi, __ni;                                        \
	cell_t              *__cell = (cell);                                   \
	cell_t               __orig = *__cell;                                  \
                                                                            \
	__ol  = cell_list_idx(__orig);                                          \
	__ob  = cell_list_bucket(__orig);                                       \
	__oi  = mteinfo_free_queue_idx(__orig);                                 \
                                                                            \
	__VA_ARGS__;                                                            \
                                                                            \
	__nl  = cell_list_idx(*__cell);                                         \
	__nb  = cell_list_bucket(*__cell);                                      \
	__ni  = mteinfo_free_queue_idx(*__cell);                                \
                                                                            \
	if (__ol != __nl || __ob != __nb) {                                     \
	        cell_list_requeue(__cell, __ol, __ob, __nl, __nb);              \
	}                                                                       \
	if (__oi != __ni || (cleared_bit)) {                                    \
	        mteinfo_free_queue_requeue(__cell, __orig, __oi, __ni);         \
	}                                                                       \
})

__pure2
static cell_t *
cell_from_tag_storage_page(const struct vm_page *page)
{
	cell_idx_t pidx;

	pidx = (cell_idx_t)(page - vm_pages_tag_storage_array_internal());
	return cell_from_idx(pidx);
}

__pure2
__attribute__((overloadable))
static cell_t *
cell_from_covered_ppnum(ppnum_t pnum)
{
	cell_idx_t cidx = (pnum - pmap_first_pnum) / MTE_PAGES_PER_TAG_PAGE;

	return cell_from_idx(cidx);
}

__pure2
__attribute__((overloadable))
static cell_t *
cell_from_covered_ppnum(ppnum_t pnum, vm_page_t *tag_page)
{
	cell_idx_t cidx = (pnum - pmap_first_pnum) / MTE_PAGES_PER_TAG_PAGE;

	*tag_page = vm_tag_storage_page_get(cidx);
	return cell_from_idx(cidx);
}

/*!
 * @function mteinfo_tag_storage_set_active()
 *
 * @abstract
 * Mark a tag storage page as active.
 *
 * @discussion
 * The page should be disabled (initial activation) or activating.
 *
 * @param tag_page      The pointer to a page inside the tag storage space.
 * @param mte_count     How many covered pages are used and tagged for @c tag_page.
 * @param init          Whether this is the initial transition.
 * @returns             The number of covered pages this made taggable.
 */
static uint32_t
mteinfo_tag_storage_set_active(vm_page_t tag_page, uint32_t mte_count, bool init)
{
	cell_t      *cell = cell_from_tag_storage_page(tag_page);
	cell_count_t free_page_count = cell_free_page_count(*cell);

	assert(mte_count + free_page_count <= MTE_PAGES_PER_TAG_PAGE);
	if (init) {
		assert_cell_state(cell,
		    /* [I.1] */ MTE_MASK_DISABLED);
	} else {
		assert_cell_state(cell,
		    /* [R.2] */ MTE_MASK_RECLAIMING |
		    /* [A.2] */ MTE_MASK_ACTIVATING);
	}

	VM_COUNTER_ADD(&vm_page_free_taggable_count, free_page_count);
	vm_page_tag_storage_activation_count++;

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_ACTIVE;
		cell->mte_page_count = mte_count;
	});

	return free_page_count;
}

bool
mteinfo_tag_storage_disabled(const struct vm_page *tag_page)
{
	return cell_from_tag_storage_page(tag_page)->state == MTE_STATE_DISABLED;
}

bool
mteinfo_tag_storage_is_active(const struct vm_page *tag_page)
{
	return cell_from_tag_storage_page(tag_page)->state == MTE_STATE_ACTIVE;
}

void
mteinfo_tag_storage_set_retired(vm_page_t tag_page)
{
	cell_t *cell = cell_from_tag_storage_page(tag_page);

	assert(cell->mte_page_count == 0);
	assert_cell_state(cell,
	    /* [K.3] */ MTE_MASK_DISABLED |
	    /* [K.2] */ MTE_MASK_CLAIMED |
	    /* [K.1] */ MTE_MASK_RECLAIMING);

	VM_COUNTER_INC(&vm_page_retired_tag_storage_count);

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_DISABLED;
	});
}

#ifndef VM_MTE_FF_VERIFY
/*!
 * @function mteinfo_tag_storage_set_unmanaged()
 *
 * @abstract
 * Mark a tag storage page as actually being disabled-unmanaged
 *
 * @discussion
 * The tag storage page must be claimed or inactive.
 *
 * @param cell          The cell to mark as disabled.
 * @param tag_page      The tag page corresponding to @c cell.
 */
static void
mteinfo_tag_storage_set_unmanaged(cell_t *cell, vm_page_t tag_page)
{
	bool queue = cell->state == MTE_STATE_INACTIVE;

	assert(cell->mte_page_count == 0);
	assert(cell->free_mask == 0);

	assert_cell_state(cell,
	    /* [U.1] */ MTE_MASK_CLAIMED |
	    /* [U.2] */ MTE_MASK_INACTIVE);

	VM_COUNTER_INC(&vm_page_unmanaged_tag_storage_count);

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_DISABLED;
	});

	if (queue) {
		vm_page_free_queue_enter(VM_MEMORY_CLASS_DEAD_TAG_STORAGE,
		    tag_page, VM_PAGE_GET_PHYS_PAGE(tag_page));
	}
}
#endif /* VM_MTE_FF_VERIFY */

void
mteinfo_tag_storage_set_inactive(vm_page_t tag_page, bool init)
{
	cell_t *cell = cell_from_tag_storage_page(tag_page);

	assert(cell->mte_page_count == 0);
	if (init) {
		assert_cell_state(cell,
		    /* [I.2] */ MTE_MASK_DISABLED);
	} else {
		assert_cell_state(cell,
		    /* [D.2] */ MTE_MASK_DEACTIVATING |
		    /* [F.1] */ MTE_MASK_CLAIMED |
		    /* [F.2] */ MTE_MASK_RECLAIMING);
	}

#ifndef VM_MTE_FF_VERIFY
	if (cell->state == MTE_STATE_CLAIMED) {
		/*
		 * This is to account for [F.1].
		 * For [F.2], we already decremented due to [R.1]
		 */
		counter_dec(&vm_cpu_claimed_count);
	}
#endif /* VM_MTE_FF_VERIFY */

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_INACTIVE;
	});
}

void
mteinfo_tag_storage_set_claimed(vm_page_t tag_page)
{
	cell_t *cell = cell_from_tag_storage_page(tag_page);

	assert(cell->mte_page_count == 0);
	assert_cell_state(cell,
	    /* [C.1] */ MTE_MASK_INACTIVE |
	    /* [R.x] */ MTE_MASK_RECLAIMING);

#ifndef VM_MTE_FF_VERIFY
	if (cell->state == MTE_STATE_RECLAIMING) {
		counter_inc(&vm_cpu_claimed_count);
	}
#endif /* VM_MTE_FF_VERIFY */

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_CLAIMED;
	});
}

/*!
 * @function mteinfo_tag_storage_set_reclaiming()
 *
 * @abstract
 * Mark a tag storage page as being reclaimed.
 *
 * @discussion
 * The tag storage page must be claimed.
 *
 * @param cell          The cell to mark as reclaiming
 */
static void
mteinfo_tag_storage_set_reclaiming(cell_t *cell)
{
	assert(cell->mte_page_count == 0);
	assert_cell_state(cell, /* [R.1] */ MTE_MASK_CLAIMED);

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_RECLAIMING;
	});

#ifndef VM_MTE_FF_VERIFY
	counter_dec(&vm_cpu_claimed_count);
#endif /* VM_MTE_FF_VERIFY */
}

/*!
 * @function mteinfo_tag_storage_flush_reclaiming()
 *
 * @abstract
 * Empties the reclaiming queue, moving all pages on it back to claimed.
 */
static void
mteinfo_tag_storage_flush_reclaiming(void)
{
	mte_cell_list_t  list  = &mte_info_lists[MTE_LIST_RECLAIMING_IDX];
	mte_cell_queue_t queue = &list->buckets[0];
	uint32_t         batch = VMP_FREE_BATCH_SIZE;

	while (cell_queue_count(queue) > 0) {
		cell_idx_t idx      = cell_queue_first_idx(queue);
		cell_t    *cell     = cell_from_idx(idx);

		assert_cell_state(cell, /* [R.x] */ MTE_MASK_RECLAIMING);
		CELL_UPDATE(cell, false, {
			cell->state = MTE_STATE_CLAIMED;
		});

#ifndef VM_MTE_FF_VERIFY
		counter_inc(&vm_cpu_claimed_count);
#endif /* VM_MTE_FF_VERIFY */

		if (--batch == 0 && cell_queue_count(queue)) {
#ifndef VM_MTE_FF_VERIFY
			vm_free_page_unlock();
			vm_free_page_lock_spin();
#endif /* VM_MTE_FF_VERIFY */
			batch = VMP_FREE_BATCH_SIZE;
		}
	}
}

#ifndef VM_MTE_FF_VERIFY

void
mteinfo_tag_storage_wakeup(vm_page_t tag_page, bool fq_locked)
{
	cell_t *cell = cell_from_tag_storage_page(tag_page);

	if (!fq_locked) {
		vm_free_page_lock_spin();
	}

	assert(tag_page->vmp_ts_wanted);
	tag_page->vmp_ts_wanted = false;

	assert_cell_state(cell, /* [B.2] */ MTE_MASK_PINNED);
	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_CLAIMED;
	});

	if (cell->free_mask != 0 &&
	    (vm_page_free_wanted_tagged_privileged || vm_page_free_wanted_tagged)) {
		mteinfo_wake_fill_thread();
	}

	if (!fq_locked) {
		vm_free_page_unlock();
	}

	counter_inc(&vm_cpu_claimed_count);
}

#endif /* VM_MTE_FF_VERIFY */
#pragma mark Covered pages state machine

bool
mteinfo_covered_page_taggable(ppnum_t pnum)
{
	return cell_from_covered_ppnum(pnum)->state == MTE_STATE_ACTIVE;
}

void
mteinfo_covered_page_set_free(ppnum_t pnum, bool tagged)
{
	vm_page_t tag_page;
	cell_t   *cell = cell_from_covered_ppnum(pnum, &tag_page);
	int       bit  = pnum % MTE_PAGES_PER_TAG_PAGE;

	assert(cell->mte_page_count >= tagged);
	assert(!bit_test(cell->free_mask, bit));

	VM_COUNTER_INC(&vm_page_free_count);
	if (cell->state == MTE_STATE_ACTIVE) {
		VM_COUNTER_INC(&vm_page_free_taggable_count);
	}
	if (tagged) {
		VM_COUNTER_DEC(&vm_page_tagged_count);
	}

	CELL_UPDATE(cell, false, {
		cell->mte_page_count -= tagged;
		bit_set(cell->free_mask, bit);
	});
}

void
mteinfo_covered_page_set_used(ppnum_t pnum, bool tagged)
{
	vm_page_t tag_page;
	cell_t   *cell = cell_from_covered_ppnum(pnum, &tag_page);
	int       bit  = pnum % MTE_PAGES_PER_TAG_PAGE;

	assert(cell->mte_page_count + tagged <= MTE_PAGES_PER_TAG_PAGE);
	assert(bit_test(cell->free_mask, bit));

	VM_COUNTER_DEC(&vm_page_free_count);
	if (cell->state == MTE_STATE_ACTIVE) {
		VM_COUNTER_DEC(&vm_page_free_taggable_count);
	}
	if (tagged) {
		VM_COUNTER_INC(&vm_page_tagged_count);
	}

	CELL_UPDATE(cell, true, {
		bit_clear(cell->free_mask, bit);
		cell->mte_page_count += tagged;
	});
}

__startup_func
void
mteinfo_covered_page_set_stolen_tagged(ppnum_t pnum)
{
	vm_page_t tag_page;
	cell_t   *cell = cell_from_covered_ppnum(pnum, &tag_page);

	assert(cell->mte_page_count < MTE_PAGES_PER_TAG_PAGE);
	assert(!bit_test(cell->free_mask, pnum % MTE_PAGES_PER_TAG_PAGE));

	CELL_UPDATE(cell, false, {
		cell->mte_page_count++;
	});
}

void
mteinfo_covered_page_clear_tagged(ppnum_t pnum)
{
	vm_page_t tag_page;
	cell_t   *cell = cell_from_covered_ppnum(pnum, &tag_page);

	assert(cell->mte_page_count > 0);
	assert(!bit_test(cell->free_mask, pnum % MTE_PAGES_PER_TAG_PAGE));

	CELL_UPDATE(cell, false, {
		cell->mte_page_count--;
	});
}

#if DEBUG || DEVELOPMENT
vm_page_t
mteinfo_tag_page_from_covered_page(ppnum_t pnum, vm_offset_t * offset_to_tag_data)
{
	cell_idx_t cidx;
	cell_t *cell;

	if (!mteinfo_covered_page_taggable(pnum)) {
		return NULL;
	}

	cidx = (pnum - pmap_first_pnum) / MTE_PAGES_PER_TAG_PAGE;
	cell = cell_from_idx(cidx);

	vm_page_t tag_page = vm_tag_storage_page_get(cidx);
	assert(vm_page_in_tag_storage_array(tag_page));

	*offset_to_tag_data =
	    (PAGE_SIZE / MTE_PAGES_PER_TAG_PAGE) *                      /* size of tag data */
	    ((pnum - pmap_first_pnum) % MTE_PAGES_PER_TAG_PAGE);        /* index within cell */

	return tag_page;
}
#endif /* DEBUG || DEVELOPMENT */

#pragma mark Activate
#ifndef VM_MTE_FF_VERIFY

/*!
 * @function mteinfo_tag_storage_wire_locked()
 *
 * @abstract
 * Wire the given tag storage page.
 *
 * @discussion
 * The page will be wired as part of mte_tags_object.
 *
 * This must be called with the object lock and the page queues lock held.
 *
 * @param tag_page
 * A tag storage page.
 */
static void
mteinfo_tag_storage_wire_locked(vm_page_t tag_page)
{
	vm_object_offset_t page_addr = ptoa(VM_PAGE_GET_PHYS_PAGE(tag_page));

	assert(tag_page->vmp_wire_count == 0);
	vm_page_wire(tag_page, VM_KERN_MEMORY_MTAG,
	    /* Don't check memory status. */ FALSE);

	vm_page_insert_internal(tag_page, mte_tags_object, page_addr,
	    VM_KERN_MEMORY_MTAG, VMPI_Q_LOCKED, NULL);
}

/*!
 * @function mteinfo_tag_storage_select_activating()
 *
 * @abstract
 * Select tag storage pages to activate toward a certain number of free covered
 * pages to make taggable.
 *
 * @discussion
 * The caller must make sure there's at least one page to activate for the
 * selected buckets.
 *
 * @param target        how many covered taggable free pages to try to generate
 *                      as a result of this activation.
 * @param bucket        which inactive bucket to start drawing from
 *
 * @returns             the list of tag storage pages to activate
 *                      with mteinfo_tag_storage_activate_locked().
 */
static vm_page_list_t
mteinfo_tag_storage_select_activating(uint32_t target, mte_cell_bucket_t bucket)
{
	vm_page_list_t list      = { };
	vm_page_t      tag_page  = VM_PAGE_NULL;
	cell_t        *cell      = NULL;
	uint32_t       total     = 0;
	uint32_t       covered   = 0;

	/*
	 * Convert the lock hold into a mutex, to signal to waiters that the
	 * lock may be held for longer.
	 */
	vm_free_page_lock_convert();

	do {
		cell = cell_list_find_last_page(MTE_LIST_INACTIVE_IDX,
		    bucket, &tag_page);
		if (tag_page == VM_PAGE_NULL) {
			break;
		}

		assert_cell_state(cell, /* [A.1] */ MTE_MASK_INACTIVE);
		CELL_UPDATE(cell, false, {
			cell->state = MTE_STATE_ACTIVATING;
		});

		covered = cell_free_page_count(*cell);
		total  += covered;

		KDBG(VMDBG_CODE(DBG_VM_TAG_PAGE_INACTIVE) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRHIDE(tag_page), covered);

		tag_page->vmp_q_state = VM_PAGE_NOT_ON_Q;
		vm_page_list_push(&list, tag_page);
	} while (total < target);

	return list;
}

/*!
 * @function mteinfo_tag_storage_activate_locked()
 *
 * @abstract
 * Activate a list of tag storage pages in reclaiming or activating state.
 *
 * @discussion
 * The page free queue lock must be held, however it is dropped and retaken by
 * this function.
 *
 * @param list          the list of pages to activate.
 * @param spin_mode     whether to take the free page queue lock in spin mode.
 *
 * @returns             how many covered pages have been made taggable.
 */
static uint32_t
mteinfo_tag_storage_activate_locked(vm_page_list_t list, bool spin_mode)
{
	vm_page_t tag_page  = VM_PAGE_NULL;
	uint32_t  result, total;

	vm_free_page_unlock();

	/*
	 * First, retype the pages and add them to the MTE object.
	 */

	vm_page_list_foreach(tag_page, list) {
		ppnum_t tag_pnum = VM_PAGE_GET_PHYS_PAGE(tag_page);

		assert(vm_page_is_tag_storage_pnum(tag_page, tag_pnum));
		pmap_make_tag_storage_page(tag_pnum);
	}

	vm_object_lock(mte_tags_object);
	vm_page_lock_queues();
	vm_page_list_foreach(tag_page, list) {
		vm_page_t save_snext = NEXT_PAGE(tag_page);

		NEXT_PAGE(tag_page) = VM_PAGE_NULL;
		mteinfo_tag_storage_wire_locked(tag_page);
		NEXT_PAGE(tag_page) = save_snext;
	}
	vm_page_unlock_queues();
	vm_object_unlock(mte_tags_object);

	if (spin_mode) {
		vm_free_page_lock_spin();
	} else {
		vm_free_page_lock();
	}

	/*
	 * Second, mark all the pages as active now, which makes the
	 * covered pages available for taggable allocation.
	 *
	 * And recompute how many taggable pages we really freed,
	 * as allocations/free of untagged pages could have made
	 * progress while we dropped the free page queue lock.
	 */

	total = 0;
	vm_page_list_foreach_consume(tag_page, &list) {
		total += mteinfo_tag_storage_set_active(tag_page, 0, false);
	}
	result = total;


	/*
	 * Last perform wakeups.
	 *
	 * 1. wake up other activators
	 * 2. wake up privileged waiters
	 * 3. wake up regular waiters
	 *
	 * We do not need to consider secluded pools, or other waiters because
	 * we never prevent them from allocating the pages associated with
	 * the tag storage we are activating during this process. Which is why
	 * we don't use vm_page_free_queue_handle_wakeups_and_unlock() but
	 * instead have this simplified implementation.
	 */

	if (vm_mte_activator_waiters) {
		vm_mte_activator_waiters = false;
		wakeup_all_with_inheritor(&vm_mte_activator_waiters,
		    THREAD_AWAKENED);
	}

	if (vm_page_free_wanted_tagged_privileged && total) {
		if (total < vm_page_free_wanted_tagged_privileged) {
			vm_page_free_wanted_tagged_privileged -= total;
			total = 0;
		} else {
			total -= vm_page_free_wanted_tagged_privileged;
			vm_page_free_wanted_tagged_privileged = 0;
		}
		vm_page_free_wakeup(&vm_page_free_wanted_tagged_privileged,
		    UINT32_MAX);
	}

	if (vm_page_free_wanted_tagged && total) {
		uint32_t wakeup = 0;

		if (total < vm_page_free_wanted_tagged) {
			wakeup = total;
			vm_page_free_wanted_tagged -= total;
			total  = 0;
		} else {
			total -= vm_page_free_wanted_tagged;
			vm_page_free_wanted_tagged = 0;
			wakeup = UINT32_MAX;
		}
		vm_page_free_wakeup(&vm_page_free_wanted_tagged, wakeup);
	}

	return result;
}

bool
mteinfo_tag_storage_try_activate(uint32_t target, bool spin_mode)
{
	mte_cell_bucket_t first_bucket = MTE_BUCKET_17_24;
	thread_t          thread_self  = current_thread();
	vm_page_list_t    list         = { };

	/*
	 * We only draw from buckets covering more than half of the pages free.
	 * We do not want to do buckets that are less full, as this is too slow
	 * for the inline path and will rely on the refill thread instead.
	 */

	if (mte_info_lists[MTE_LIST_INACTIVE_IDX].mask < BIT(first_bucket)) {
		return false;
	}

	if (vm_mte_activator) {
		/*
		 * We only allow one thread activating pages at a time,
		 * only wait if we the caller can't make progress without
		 * this though.
		 *
		 * We do not need to consider that the waiters is privileged
		 * for the wait however, because activation isn't affected
		 * by TH_OPT_VMPRIV.
		 */

		if (vm_page_free_taggable_count > vm_page_free_reserved) {
			return false;
		}
		if (vm_page_free_taggable_count > 0 &&
		    (thread_self->options & TH_OPT_VMPRIV)) {
			return false;
		}

		vm_mte_activator_waiters = true;
		lck_mtx_sleep_with_inheritor(&vm_page_queue_free_lock,
		    spin_mode ? LCK_SLEEP_SPIN : LCK_SLEEP_DEFAULT,
		    &vm_mte_activator_waiters, vm_mte_activator,
		    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);

		return true;
	}

	vm_mte_activator = thread_self;
	list = mteinfo_tag_storage_select_activating(target, first_bucket);
	mteinfo_tag_storage_activate_locked(list, spin_mode);
	vm_mte_activator = THREAD_NULL;

	return true;
}


#pragma mark Deactivate

/*!
 * @abstract
 * Returns whether the active(0.0) bucket should be drained to make inactive
 * pages.
 *
 * @param for_wakeup    Whether the question is to wakeup the refill thread
 *                      (true) or decide whether the refill thread should keep
 *                      going (false).
 */
static bool
mteinfo_tag_storage_should_drain(bool for_wakeup)
{
	mte_cell_list_t active_0  = &mte_info_lists[MTE_LIST_ACTIVE_0_IDX];
	uint32_t        threshold = VMP_FREE_BATCH_SIZE * (for_wakeup ? 2 : 1);

	if (!vm_mte_enable_tag_storage_grab) {
		return false;
	}

	if (mteinfo_claimable_count() >= vm_free_magazine_refill_limit) {
		return false;
	}

	if (active_0->count <= vm_page_tag_storage_reserved) {
		return false;
	}

	return cell_queue_count(&active_0->buckets[0]) >= threshold;
}

/*
 * @function mteinfo_tag_storage_deactivate_barrier()
 *
 * @abstract
 * Wait until all possible untagging operations that could make deactivation
 * invalid have finished.
 *
 * @discussion
 * Before we can do any deactivation we must make sure
 * that no CPU has untagging activity in flight.
 *
 * See mteinfo_free_queue_grab() and mteinfo_page_list_fix_tagging().
 */
static void
mteinfo_tag_storage_deactivate_barrier(void)
{
	vm_page_pcpu_t this_cpu = PERCPU_GET(vm_page_pcpu);

	assert(get_preemption_level() > 0);

	percpu_foreach(it, vm_page_pcpu) {
		if (it == this_cpu) {
			/*
			 * A thread is allowed to both have pending untagging
			 * going on and a page to deactivate.
			 *
			 * As a result, ignore the current core's suspension
			 * state as it is harmless as long as the core commits
			 * to untagging before it does its deactivations.
			 *
			 * If a thread fails to do that, this will reliably
			 * panic in SPTM, so the risk of silent bugs is rather
			 * unlikely.
			 */
			continue;
		}

		if (os_atomic_load(&it->deactivate_suspend, relaxed)) {
			hw_wait_while_equals32(&it->deactivate_suspend, 1);
		}
	}
	os_atomic_thread_fence(seq_cst);
}

/*!
 * @abstract
 * Flush a list of deactivating page storage.
 *
 * @discussion
 * The page free queue lock must be held, but will be dropped while this
 * function operates.
 *
 * @param list          The list of pages in @c MTE_STATE_DEACTIVATING state.
 */
static void
mteinfo_tag_storage_drain_flush(vm_page_list_t list)
{
	vm_page_t tag_page = VM_PAGE_NULL;

	mteinfo_tag_storage_deactivate_barrier();

	vm_free_page_unlock();

	vm_object_lock(mte_tags_object);
	vm_page_lock_queues();

	vm_page_list_foreach(tag_page, list) {
		vm_page_t save_next = NEXT_PAGE(tag_page);


		/*
		 * The unwiring path expects the page linkage to be
		 * NULL, so transiently make it NULL.  We'll restore
		 * the linkage after the unwire is done.
		 */

		NEXT_PAGE(tag_page) = VM_PAGE_NULL;
		vm_page_unwire(tag_page,
		    /* Don't put the page into aging queues. */ FALSE);
		vm_page_remove(tag_page);
		NEXT_PAGE(tag_page) = save_next;
	}

	vm_page_unlock_queues();
	vm_object_unlock(mte_tags_object);

	vm_page_list_foreach(tag_page, list) {
		pmap_unmake_tag_storage_page(VM_PAGE_GET_PHYS_PAGE(tag_page));
	}

	vm_free_page_lock_spin();

	vm_page_tag_storage_deactivation_count += list.vmpl_count;

	vm_page_list_foreach_consume(tag_page, &list) {
		vm_page_free_queue_enter(VM_MEMORY_CLASS_TAG_STORAGE,
		    tag_page, VM_PAGE_GET_PHYS_PAGE(tag_page));
	}
}

/*!
 * @function mteinfo_tag_storage_drain()
 *
 * @abstract
 * Attempt to drain the active(0.0) bucket of pages since these are always
 * wasted.
 *
 * @discussion
 * This is one of the core routines of the fill thread.
 *
 * @returns
 * How many tag storage pages were deactivated.
 */
static uint32_t
mteinfo_tag_storage_drain(void)
{
	mte_cell_list_t  active_0 = &mte_info_lists[MTE_LIST_ACTIVE_0_IDX];
	mte_cell_queue_t bucket_0 = &active_0->buckets[0];
	vm_page_t        tag_page = VM_PAGE_NULL;
	cell_t          *cell     = NULL;
	uint32_t         total    = 0;
	vm_page_list_t   list     = { };

	LCK_MTX_ASSERT_OWNED_SPIN(&vm_page_queue_free_lock);

	while (mteinfo_tag_storage_should_drain(false)) {
		tag_page   = vm_tag_storage_page_get(cell_queue_first_idx(bucket_0));
		cell       = cell_queue_first(bucket_0);

		assert(cell->free_mask == 0);
		assert_cell_state(cell, /* [D.1] */ MTE_MASK_ACTIVE);
		CELL_UPDATE(cell, false, {
			cell->state = MTE_STATE_DEACTIVATING;
		});

		vm_page_list_push(&list, tag_page);

		if (list.vmpl_count >= VMP_FREE_BATCH_SIZE) {
			total += list.vmpl_count;
			mteinfo_tag_storage_drain_flush(list);
			list   = (vm_page_list_t){ };
		}

		vm_mte_refill_ts_deactivated_count++;
	}

	if (list.vmpl_count) {
		total += list.vmpl_count;
		mteinfo_tag_storage_drain_flush(list);
	}

	return total;
}


#pragma mark Reclaim

/*!
 * @abstract
 * Attempt to steal a tag page from a per cpu claimed free queue.
 *
 * @discussion
 * The caller must have checked that the tag_page is on a local free queue,
 * even if this check is racy.
 *
 * @param tag_page      A tag storage page appearing to sit on a per cpu queue.
 *
 * @returns             Whether stealing was successful (true) or not (false).
 */
static bool
mteinfo_reclaim_tag_storage_page_try_pcpu(vm_page_t tag_page)
{
	vm_page_pcpu_t vmp_pcpu;
	uint16_t       cpu;

	cpu      = os_atomic_load(&tag_page->vmp_local_id, relaxed);
	vmp_pcpu = PERCPU_GET_WITH_BASE(other_percpu_base(cpu), vm_page_pcpu);

	lck_ticket_lock(&vmp_pcpu->free_claimed_lock, &vm_page_lck_grp_bucket);

	if (tag_page->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q &&
	    tag_page->vmp_local_id == cpu) {
		vm_page_queue_remove(&vmp_pcpu->free_claimed_pages,
		    tag_page, vmp_pageq);
		tag_page->vmp_q_state  = VM_PAGE_NOT_ON_Q;
		tag_page->vmp_local_id = 0;
		counter_dec_preemption_disabled(&vm_cpu_free_claimed_count);
	} else {
		tag_page = VM_PAGE_NULL;
	}

	lck_ticket_unlock(&vmp_pcpu->free_claimed_lock);

	return tag_page != VM_PAGE_NULL;
}

/*!
 * @function mteinfo_reclaim_tag_storage_page()
 *
 * @abstract
 * Attempt to reclaim a claimed tag storage page.
 *
 * @discussion
 * This will try to reclaim a tag storage page by relocating its contents to a
 * different page, so that the tag storage page becomes (effectively) free.
 *
 * This expects a claimed tag storage page, and on success, will finish with
 * the page in the reclaimed state.  On failure, no guarantees are made about
 * the state of the page (due to locking operations); the page could still be
 * claimed, or reclamation may have failed because the page became free in the
 * interim.  However, if the page was not in a relocatable state, this function
 * will not force it out of the reclaiming state, so that the client can choose
 * when and why the page is returned to claimed.
 *
 * This function is called with the free page queue lock in spin mode and
 * returns with it held in spin mode.
 *
 * @param tag_page
 * The claimed tag storage page to try reclaiming.
 *
 * @returns
 * - KERN_SUCCESS               success,
 *
 * - KERN_INVALID_OBJECT        the page has no object set
 *
 * - KERN_NOT_WAITING           the state of the cell/tag page changed
 *                              during evaluation.
 *
 * - KERN_ABORTED               the tag page was wired. reclaiming it was
 *                              aborted and it was marked as MTE_STATE_PINNED.
 *
 * - KERN_RESOURCE_SHORTAGE     from vm_page_relocate(): relocation failed due
 *                              to being out of replacement memory.
 *
 * - KERN_FAILURE               from vm_page_relocate(): relocation failed due
 *                              to the page not being currently relocatable.
 */
static kern_return_t
mteinfo_reclaim_tag_storage_page(vm_page_t tag_page)
{
	cell_t *cell = cell_from_tag_storage_page(tag_page);
	kern_return_t kr = KERN_FAILURE;
	vm_object_t object;
	bool compressor_locked = false;
	bool vm_object_trylock_failed = false;

	/* We need to try and reclaim the tag storage page. */
	mteinfo_tag_storage_set_reclaiming(cell);

	if (tag_page->vmp_q_state == VM_PAGE_ON_FREE_LOCAL_Q &&
	    mteinfo_reclaim_tag_storage_page_try_pcpu(tag_page)) {
		vm_page_tag_storage_reclaim_from_cpu_count++;
		vm_page_tag_storage_reclaim_success_count++;

		KDBG(VMDBG_CODE(DBG_VM_TAG_PAGE_CLAIMED) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRHIDE(tag_page),
		    mteinfo_tag_storage_free_pages_for_covered(tag_page));

		return KERN_SUCCESS;
	}

	vm_free_page_unlock();

	/*
	 * Snoop the vmp_q_state. If the page is currently used by the compressor
	 * (VM_PAGE_USED_BY_COMPRESSOR), we'll grab the global compressor lock
	 * for write (c_page_replacement_allowed_start()) and the compressor
	 * object lock.
	 *
	 * Typically, we can't know that the object will be stable
	 * without grabbing the object or page queues lock (see the comment on
	 * "relocation lock dance" below), but we know that the compressor object
	 * is stable. So, we do _not_ need to grab the page queues and object locks
	 * in the wrong order. This ensures that we will wait our turn in case
	 * someone else is using the compressor object lock, and there is no chance
	 * the reclaim will fail because we can't acquire the right locks.
	 *
	 * The contiguous memory allocator grabs this lock before the page queues
	 * and object lock, so we must do the same here.
	 */
	if (tag_page->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
		assert(vm_mte_tag_storage_for_compressor);
		c_page_replacement_allowed_start();
		vm_object_lock(compressor_object);
		compressor_locked = true;

		/*
		 * The page state transitions into and out of VM_PAGE_USED_BY_COMPRESSOR
		 * happen under the compressor object, so now the page state is stable.
		 */
		if (tag_page->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR) {
			/*
			 * The page was removed from the compressor pool. It could be
			 * in any state now, but it's probably free and unusable. Give up.
			 */
			vm_object_unlock(compressor_object);
			c_page_replacement_allowed_end();
			compressor_locked = false;
			vm_free_page_lock_spin();
			kr = KERN_FAILURE;
			goto locks_acquired;
		}
	}

	/*
	 * Do the relocation lock dance.  This is a little odd; because we're
	 * starting with a page, and trying to look up the object, we need the
	 * queues lock to keep the object from being deallocated or changed.
	 *
	 * This means we need to get the object lock after the queues lock;
	 * this inverts the lock ordering, so we can only TRY the object lock.
	 */
	vm_page_lock_queues();

	object = VM_PAGE_OBJECT(tag_page);
	if (compressor_locked) {
		assert(object == compressor_object);
	}

	if (object == VM_OBJECT_NULL) {
		/* [PH] XXX: Can this even happen? */
		kr = KERN_INVALID_OBJECT;
		goto release_locks;
	} else if (!compressor_locked && !vm_object_lock_try_scan(object)) {
		/*
		 * hopefully the next time we drain reclaiming pages taking
		 * that object lock will work.
		 */
		vm_object_trylock_failed = true;
		kr = KERN_NOT_WAITING;
		goto release_locks;
	} else if (VM_PAGE_OBJECT(tag_page) != object) {
		/*
		 * vm_page_insert_internal() doesn't require the page queue lock
		 * to be held if the page is wired, so the object could change
		 * under us.
		 */
		vm_object_unlock(object);

		kr = KERN_NOT_WAITING;
		goto release_locks;
	}

	/*
	 * Now that all the locking is out of the way,
	 * see if the page is actually relocatable.
	 */
	if (VM_PAGE_WIRED(tag_page) ||
	    (tag_page->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR && tag_page->vmp_busy)) {
		/*
		 * TODO: Relocation fails when one of these conditions is met:
		 *
		 *     VM_PAGE_WIRED(tag_page)
		 *     tag_page->vmp_gobbled
		 *     tag_page->vmp_laundry
		 *     tag_page->vmp_wanted
		 *     tag_page->vmp_cleaning
		 *     tag_page->vmp_overwriting
		 *     tag_page->vmp_free_when_done
		 *     tag_page->vmp_busy
		 *     tag_page->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q
		 *
		 * We only handle VM_PAGE_WIRED() and when the tag page is being
		 * swapped out (from usage in the compressor pool) for now,
		 * because these are the most likely, but we should use vmp_ts_wanted
		 * for all cases.
		 *
		 * We would need to find all places in the kernel that alter
		 * this condition, to notice that a relocation was attempted
		 * (vmp_ts_wanted is set) and call mteinfo_tag_storage_wakeup().
		 */

		/*
		 * Take the page free lock before setting vmp_ts_wanted,
		 * before we drop the object lock, otherwise
		 * mteinfo_tag_storage_wakeup() might see vmp_ts_wanted
		 * before the transition to MTE_STATE_PINNED has happened.
		 *
		 * Note that we should do nothing if the cell is no longer in
		 * the MTE_STATE_RECLAIMING state, which could hypothetically
		 * happen since we dropped the free queue lock above.
		 */
		vm_free_page_lock_spin();

		if (cell->state == MTE_STATE_RECLAIMING) {
			assert(tag_page->vmp_ts_wanted == false);
			tag_page->vmp_ts_wanted = true;
			kr = KERN_ABORTED;
		} else {
			kr = KERN_NOT_WAITING;
		}

		vm_object_unlock(object);
		vm_page_unlock_queues();
		if (compressor_locked) {
			c_page_replacement_allowed_end();
			compressor_locked = false;
		}

		if (kr == KERN_ABORTED) {
			assert_cell_state(cell, /* [B.1] */ MTE_MASK_RECLAIMING);
			CELL_UPDATE(cell, false, {
				cell->state = MTE_STATE_PINNED;
			});
			if (tag_page->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
				vm_page_tag_storage_reclaim_compressor_failure_count++;
			} else {
				vm_page_tag_storage_reclaim_wired_failure_count++;
			}
		}

		goto locks_acquired;
	} else if ((*vm_mte_tag_storage_for_vm_tags) &&
	    !vm_page_is_relocatable(tag_page, VM_RELOCATE_REASON_TAG_STORAGE_RECLAIM)) {
		/*
		 * If we're allowing tag storage pages to be used for specific VM tags,
		 * those pages could be unrelocatable for reasons we haven't
		 * expected. We're also assuming that if a tag storage page were to
		 * be unrelocatable for whatever reason, it's (at the very least) not
		 * because the page is wired or involved in an IO that could take a
		 * long time, so hopefully it won't be unavailable for too long, and
		 * the fill thread won't churn over the same set of unavailable claimed
		 * pages.
		 *
		 * We'll just skip over this page and move it back to claiming at the
		 * bottom of this function.
		 */
		kr = KERN_NOT_WAITING;
		vm_object_unlock(object);
	} else {
		kr = vm_page_relocate(tag_page, NULL,
		    VM_RELOCATE_REASON_TAG_STORAGE_RECLAIM, NULL);
		vm_object_unlock(object);

		assert(kr != KERN_ABORTED);
	}

release_locks:
	if (compressor_locked) {
		c_page_replacement_allowed_end();
	}
	vm_page_unlock_queues();
	if (vm_object_trylock_failed && vm_object_lock_avoid(object)) {
		/*
		 * We failed to lock the VM object, and pageout_scan
		 * wants this object. Back off for a little bit.
		 *
		 * Note that the VM object may no longer be valid after releasing
		 * the VM object lock, but `vm_object_lock_avoid` only compares
		 * pointers and doesn't dereference them, so it's fine.
		 */
		mutex_pause(2);
	}
	vm_free_page_lock_spin();


locks_acquired:
	/*
	 * Assert that all codepaths leading up to this point have the lock
	 * held in spin mode (and therefore, preemption disabled).
	 */
	LCK_MTX_ASSERT_OWNED_SPIN(&vm_page_queue_free_lock);

	if (kr == KERN_SUCCESS) {
		vm_page_tag_storage_reclaim_success_count++;

		/* We relocated the page.  Now we can use it. */
		if (cell->state != MTE_STATE_RECLAIMING) {
			/*
			 * The page was manipulated while we were relocating
			 * it.  This likely means it was freed and reallocated
			 * between us dropping the free page lock and getting
			 * the queues lock.
			 *
			 * This should be ludicrously rare, and should still
			 * mean that the page is claimed (otherwise relocate
			 * would have failed).  Set to reclaiming for client
			 * consistency.
			 *
			 * In the state diagram this corresponds to other
			 * threads having performed [F.2 inline] followed
			 * by [C.1 inline], possibly multiple times.
			 */
			mteinfo_tag_storage_set_reclaiming(cell);
		}

		KDBG(VMDBG_CODE(DBG_VM_TAG_PAGE_CLAIMED) | DBG_FUNC_NONE,
		    VM_KERNEL_ADDRHIDE(tag_page),
		    mteinfo_tag_storage_free_pages_for_covered(tag_page));

		assert(tag_page->vmp_q_state == VM_PAGE_NOT_ON_Q);
	} else {
		vm_page_tag_storage_reclaim_failure_count++;

		if (kr == KERN_RESOURCE_SHORTAGE || kr == KERN_NOT_WAITING) {
			/*
			 * If there was no available page to relocate the tag
			 * storage page to, or that some race happened that
			 * changed the page state under our feet, just put the
			 * page back as claimed if it's still reclaiming.
			 *
			 * It will as a result get reconsidered more quickly...
			 * it WAS our best candidate, after all.
			 */
			if (cell->state == MTE_STATE_RECLAIMING) {
				mteinfo_tag_storage_set_claimed(tag_page);
			}
		}
	}

	return kr;
}


#pragma mark Refill Thread

/*!
 * @abstract
 * Returns whether the refill thread should keep refilling the active pool.
 *
 * @discussion
 * If we're below the free target, and there are no tagged waiters of any kind,
 * avoid activating any pages if the untagged pool is not extremely healthy.
 */
static inline bool
mteinfo_tag_storage_active_should_refill(void)
{
	if (vm_page_free_taggable_count >= vm_page_free_target) {
		return false;
	}

	if (vm_page_free_taggable_count <= vm_page_free_reserved) {
		return true;
	}

	if (vm_page_free_wanted_tagged_privileged || vm_page_free_wanted_tagged) {
		return true;
	}

	/*
	 * 16/15 is ~1.07: we define "healthy" as at least 7% excess pages
	 * over the target.
	 *
	 * We want some slop because a system under pressure will sometimes go
	 * above @c vm_page_free_target and we want to avoid thrashing.
	 */
	return vm_page_free_count * 15ull >= vm_page_free_target * 16ull;
}

/*!
 * @function mteinfo_tag_storage_active_refill()
 *
 * @abstract
 * Attempt to fill the global free tagged covered page queue.
 *
 * @discussion
 * This is one of the core routines of the fill thread.  It will attempt to get
 * the global free tagged covered page queue to or above a target value.  It
 * will also wake threads waiting for more of these pages as appropriate.
 *
 * This function is called with the free page queue lock held in spin mode
 * and returns with it held in spin mode.
 *
 * @param taggablep     How many free taggable pages have been added.
 * @returns             The number of tag storage pages this function activated.
 */
static uint32_t
mteinfo_tag_storage_active_refill(uint32_t *taggablep)
{
	mte_cell_list_t  claimed_list  = &mte_info_lists[MTE_LIST_CLAIMED_IDX];
	mte_cell_list_t  inactive_list = &mte_info_lists[MTE_LIST_INACTIVE_IDX];
	uint32_t         taggable      = 0;
	uint32_t         activated     = 0;
	uint32_t         considered    = 0;

	LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);

	while (mteinfo_tag_storage_active_should_refill()) {
		mte_cell_bucket_t i_bucket = 0;
		mte_cell_bucket_t c_bucket = 0;
		vm_page_list_t    list     = { };
		kern_return_t     kr       = KERN_SUCCESS;

		/*
		 *	Step 1: try to activate or reclaim pages.
		 *
		 *	Pick the pool between inactive and claimed that will
		 *	make us progress the fastest (picking inactive over
		 *	claimed for equivalent buckets, given that reclaiming
		 *	is more expensive).
		 *
		 *	In particular always pick active buckets over reclaiming
		 *	pages if they have more than 50% of the pages free.
		 */

		if (inactive_list->mask) {
			i_bucket = fls(inactive_list->mask) - 1;
		} else {
			i_bucket = 0;
		}
		if (claimed_list->mask) {
			c_bucket = fls(claimed_list->mask) - 1;
		} else {
			c_bucket = 0;
		}

		if (i_bucket && i_bucket >= MIN(MTE_BUCKET_17_24, c_bucket)) {
			list = mteinfo_tag_storage_select_activating(VMP_FREE_BATCH_SIZE,
			    MIN(i_bucket, MTE_BUCKET_17_24));
		} else if (c_bucket > MTE_BUCKET_0) {
			mte_cell_queue_t queue = &claimed_list->buckets[c_bucket];
			cell_idx_t       idx   = cell_queue_first_idx(queue);
			vm_page_t        page  = vm_tag_storage_page_get(idx);

			kr = mteinfo_reclaim_tag_storage_page(page);
			if (kr == KERN_SUCCESS) {
				list = vm_page_list_for_page(page);
			}
		} else {
			/*
			 * There is no progress we can do here because we do not
			 * have good candidates to activate or reclaim.
			 *
			 * As a result, even if the system has free untaggable
			 * pages, they can't be converted to taggable either
			 * because they're permanently untaggable, or beacuse
			 * their associated tag storage can't be reclaimed.
			 *
			 * Waiting in VM_PAGE_WAIT() below sounds appealing
			 * but will result in busy loops, so we should just
			 * go park and wait until some page free is saving us
			 * via the "wakeup_refill_thread" cases in
			 * @c vm_page_free_queue_handle_wakeups_and_unlock().
			 */
			break;
		}

		considered += list.vmpl_count;

		if (kr == KERN_SUCCESS) {
			activated += list.vmpl_count;
			taggable += mteinfo_tag_storage_activate_locked(list,
			    /* spin-mode */ true);
			continue;
		}

		/*
		 *	Step 2: wait if needed
		 *
		 *	KERN_RESOURCE_SHORTAGE means that we were out of pages
		 *	to relocate or tag storage candidates.
		 *
		 *	Other errors are relocation failures and we can just
		 *	retry immediately.
		 */

		if (kr == KERN_RESOURCE_SHORTAGE) {
			/*
			 * There was no good candidate tag storage page.  Wait
			 * on the VM to make new pages available.
			 *
			 * TODO: This isn't a great solution; the VM doesn't
			 * understand what we are actually waiting on.  This
			 * should converge eventually due to VM activity... but
			 * the bigger picture fix is to make all free pages
			 * eligible for MTE.  Then our only significant concern
			 * around tag storage pages will be tag storage pages
			 * with ECC errors, which should be a small number.
			 */
			vm_free_page_unlock();
			current_thread()->page_wait_class = VM_MEMORY_CLASS_REGULAR;
			VM_PAGE_WAIT();
			vm_free_page_lock_spin();

			/*
			 * We waited above, the system conditions changed,
			 * flush our reclaiming queue.
			 */
			mteinfo_tag_storage_flush_reclaiming();
		}
	}

	mteinfo_tag_storage_flush_reclaiming();

	*taggablep += taggable;
	vm_mte_refill_ts_considered_count += considered;
	return activated;
}

/*!
 * @function mteinfo_fill_continue()
 *
 * @abstract
 * Continuation for the MTE fill thread.
 *
 * @discussion
 * The MTE fill thread manages the global free queue of covered tagged pages,
 * and moving tag storage pages between the active and inactive states.
 *
 * @param param
 * Unused.
 *
 * @param wr
 * Unused.
 */
__dead2
static void
mteinfo_fill_continue(void *param __unused, wait_result_t wr __unused)
{
#if CONFIG_THREAD_GROUPS
	static bool _fill_thread_self_inited;

	if (!_fill_thread_self_inited) {
		thread_group_vm_add();
		_fill_thread_self_inited = true;
	}
#endif /* CONFIG_THREAD_GROUPS */

	(void)sched_cond_ack(&fill_thread_cond);
	vm_mte_refill_thread_wakeups++;

	for (;;) {
		uint32_t added = 0;
		uint32_t activated = 0;
		uint32_t deactivated = 0;

		VM_DEBUG_CONSTANT_EVENT(, DBG_VM_REFILL_MTE, DBG_FUNC_START,
		    0, 0, 0, 0);

		/*
		 * NB: We take the free queue lock in spin mode here because there are
		 * a number of operations that occur during active_refill and drain
		 * that requires preemption to be disabled. For example:
		 *  - in active_refill: if the fill thread tries to reclaim a tag
		 *    storage page, it first tries to steal a free tag storage page
		 *    from the local free queue.
		 *  - in drain: when flushing the queue of deactivating tag storage
		 *    pages, the fill thread waits for all cores to finish any untagging
		 *    before proceeding. See mteinfo_tag_storage_deactivate_barrier().
		 *
		 * Coupling enabling/disabling preemption with acquiring/releasing the
		 * free queue lock is easier than managing preemption by hand, so all
		 * instances of free queue lock acquisition must be done in spin mode.
		 */
		vm_free_page_lock_spin();

		activated   += mteinfo_tag_storage_active_refill(&added);
		deactivated += mteinfo_tag_storage_drain();

		vm_free_page_unlock();

		VM_DEBUG_CONSTANT_EVENT(, DBG_VM_REFILL_MTE, DBG_FUNC_END,
		    added, activated, deactivated, 0);

		sched_cond_wait_parameter(&fill_thread_cond, THREAD_UNINT,
		    mteinfo_fill_continue, NULL);
	}
}

void
mteinfo_wake_fill_thread(void)
{
	if (mte_enabled()) {
		sched_cond_signal(&fill_thread_cond, vm_mte_fill_thread);
	}
}


#pragma mark Alloc

/*!
 * @abstract
 * Compute the current number of claimable tag storage pages.
 *
 * @discussion
 * All inactive pages are theoretically claimable when there's an excessive
 * (defined in terms of vm_page_tag_storage_inactive_target) number of
 * inactive tag storage pages. Additionally, inactive pages covering <= 8 free
 * pages are always claimable.
 *
 * Because pages are always claimed in sorted order (fewest to most free covered
 * pages), the maximum of these two counts is used to avoid double-counting.
 */
inline uint32_t
mteinfo_claimable_count(void)
{
	mte_cell_list_t inactive_list = &mte_info_lists[MTE_LIST_INACTIVE_IDX];
	if (inactive_list->buckets == NULL) {
		return 0;
	}
	uint32_t excess_count =
	    inactive_list->count > vm_page_tag_storage_inactive_target ?
	    inactive_list->count - vm_page_tag_storage_inactive_target : 0;
	uint32_t regular_count =
	    inactive_list->buckets[MTE_BUCKET_1_8].head.cell_count +
	    inactive_list->buckets[MTE_BUCKET_0].head.cell_count;

	return MAX(regular_count, excess_count);
}

/*!
 * @abstract
 * Returns whether @c mteinfo_free_queue_grab() should refill the per-cpu
 * claimable queue.
 *
 * @discussion
 * The policy is to refill if the queue is empty and that the claimable
 * queue has a full batch of @c VMP_FREE_BATCH_SIZE free pages.
 *
 * This is chosen so that the taking of the spinlock it implies is amortized
 * well and reduce thrashing.
 *
 * The function must be called with preemption disabled.
 *
 * @param vmp_pcpu      The per-cpu vm page structure for the current CPU.
 */
static bool
mteinfo_tag_storage_claimable_should_refill(vm_page_pcpu_t vmp_pcpu)
{
	if (__improbable(!vm_mte_enable_tag_storage_grab)) {
		return false;
	}

	if (!vm_page_queue_empty(&vmp_pcpu->free_claimed_pages)) {
		return false;
	}

	return mteinfo_claimable_count() >= VMP_FREE_BATCH_SIZE;
}

/*!
 * @abstract
 * Refill the current CPU's claimed free queue.
 *
 * @discussion
 * This is done opportunistically by @c mteinfo_free_queue_grab()
 * When it notices that it should refill the per-CPU claimable queue
 * (see @mteinfo_tag_storage_claimable_should_refill()).
 *
 * The function must be called with preemption disabled.
 *
 * @param vmp_pcpu      The per-cpu vm page structure for the current CPU.
 * @param target        The number of tag storage pages to grab.
 */
static void
mteinfo_tag_storage_claimable_refill(
	vm_page_pcpu_t          vmp_pcpu,
	uint32_t                target)
{
	const int       cpu = cpu_number();
	vm_page_t       mem;

	lck_ticket_lock_nopreempt(&vmp_pcpu->free_claimed_lock,
	    &vm_page_lck_grp_bucket);

	for (uint32_t i = target; i-- > 0;) {
		/*
		 * Use the inactive tag storage page with the fewest free covered pages.
		 */
		(void) cell_list_find_first_page(MTE_LIST_INACTIVE_IDX, MTE_BUCKET_25_32, &mem);
		assert(mem != VM_PAGE_NULL);

		assert(mem->vmp_q_state == VM_PAGE_ON_FREE_Q);
		mteinfo_tag_storage_set_claimed(mem);
		mem->vmp_q_state = VM_PAGE_ON_FREE_LOCAL_Q;
		mem->vmp_local_id = (uint16_t)cpu;
		vm_page_queue_enter(&vmp_pcpu->free_claimed_pages, mem, vmp_pageq);
	}

	lck_ticket_unlock_nopreempt(&vmp_pcpu->free_claimed_lock);

	counter_add_preemption_disabled(&vm_cpu_free_claimed_count,
	    target);
}

vm_page_list_t
mteinfo_free_queue_grab(
	vm_page_pcpu_t          vmp_pcpu,
	vm_grab_options_t       options,
	vm_memory_class_t       class,
	unsigned int            num_pages,
	vm_page_q_state_t       q_state)
{
	unsigned int         color;
	vm_page_list_t       list = { };
	mte_free_queue_idx_t idx;

	assert(!vmp_pcpu->deactivate_suspend && get_preemption_level() > 0);

	if (class == VM_MEMORY_CLASS_REGULAR) {
		/*
		 * VM_MEMORY_CLASS_DEAD_TAG_STORAGE is not part of
		 * vm_page_free_count, which means the caller didn't take them
		 * into account when making this allocation ask.
		 *
		 * As a result do not respect num_pages. However these are
		 * different than the regular claimable pool because we can
		 * always safely wire them.
		 */
		if (vm_page_queue_free.vmpfq_count) {
			list = vm_page_free_queue_grab(vmp_pcpu, options,
			    VM_MEMORY_CLASS_DEAD_TAG_STORAGE,
			    MIN(vm_free_magazine_refill_limit / 2,
			    vm_page_queue_free.vmpfq_count), q_state);
		}

		assert(num_pages <= vm_page_free_count);
	} else {
		assert(num_pages <= vm_page_free_taggable_count);
	}

	color  = vmp_pcpu->start_color;

	if (mteinfo_tag_storage_claimable_should_refill(vmp_pcpu)) {
		mteinfo_tag_storage_claimable_refill(vmp_pcpu, VMP_FREE_BATCH_SIZE);
	}

	while (list.vmpl_count < num_pages) {
		vm_page_queue_t queue;
		cell_count_t bit;
		vm_page_t tag_page;
		vm_page_t mem;
		uint32_t count;
		ppnum_t first_pnum;
		cell_t orig;
		cell_t *cell;

		/*
		 * Select which queue we dequeue from
		 *
		 * Regular allocations can allocate from any bucket.
		 * Tagged allocations must draw from an MTE_FREE_ACTIVE_* one.
		 */

		if (class == VM_MEMORY_CLASS_REGULAR) {
			idx = ffs(mte_free_queue_mask) - 1;
		} else {
			uint32_t mask = mte_free_queue_mask;

			mask &= BIT(MTE_FREE_ACTIVE_0) |
			    BIT(MTE_FREE_ACTIVE_1) |
			    BIT(MTE_FREE_ACTIVE_2) |
			    BIT(MTE_FREE_ACTIVE_3);

			assert(mask);
			idx = fls(mask) - 1;
		}

		queue = mteinfo_free_queue_head(idx, color);
		while (vm_page_queue_empty(queue)) {
			color = (color + 1) & vm_color_mask;
			queue = mteinfo_free_queue_head(idx, color);
		}

		/*
		 * Dequeue the linkage, find the page of the right color.
		 */

		vm_page_queue_remove_first(queue, mem, vmp_pageq);

		VM_COUNTER_DEC(&mte_free_queues[idx].vmpfq_count);
		if (mte_free_queues[idx].vmpfq_count == 0) {
			bit_clear(mte_free_queue_mask, idx);
		}

		first_pnum = VM_PAGE_GET_PHYS_PAGE(mem) & -MTE_PAGES_PER_TAG_PAGE;
		cell       = cell_from_covered_ppnum(first_pnum, &tag_page);
		orig       = *cell;
		bit        = orig.enqueue_pos;
		count      = 0;
		assert((orig.enqueue_pos & vm_color_mask) ==
		    color % MTE_PAGES_PER_TAG_PAGE);

		/*
		 * Dequeue a span of covered pages from that tag storage
		 *
		 * If we have a contiguous run of free pages and we need more,
		 * we know this tag storage page is going to be the one we pick
		 * next.
		 */

		for (;;) {
			assert(bit_test(orig.free_mask, bit));
			bit_clear(cell->free_mask, bit);

			mem->vmp_q_state = q_state;
			vm_page_list_push(&list, mem);

			count += 1;
			bit   += 1;

			if (!bit_test(cell->free_mask, bit) ||
			    list.vmpl_count >= num_pages) {
				break;
			}

			mem = vm_page_find_canonical(first_pnum + bit);
		}

		color = (color + count) & vm_color_mask;

		/*
		 * Update counters (see mteinfo_covered_page_set_used())
		 */

		VM_COUNTER_SUB(&vm_page_free_count, count);
		if (idx >= MTE_FREE_ACTIVE_0 && idx <= MTE_FREE_ACTIVE_3) {
			VM_COUNTER_SUB(&vm_page_free_taggable_count, count);
		}
		if (class != VM_MEMORY_CLASS_REGULAR) {
			VM_COUNTER_ADD(&vm_page_tagged_count, count);
			cell->mte_page_count += count;
		}

		/*
		 * Requeue the tag storage (tail end of CELL_UPDATE())
		 */

		if (cell_list_idx(orig) != cell_list_idx(*cell) ||
		    cell_list_bucket(orig) != cell_list_bucket(*cell)) {
			cell_list_requeue(cell,
			    cell_list_idx(orig), cell_list_bucket(orig),
			    cell_list_idx(*cell), cell_list_bucket(*cell));
		}

		mteinfo_free_queue_requeue(cell, orig, MTE_FREE_NOT_QUEUED,
		    mteinfo_free_queue_idx(*cell));
	}

	vmp_pcpu->start_color = color;

	/*
	 * Some existing driver/IOKit code deals badly with getting physically
	 * contiguous memory... which this alloc code is rather likely to
	 * provide by accident immediately after boot.
	 *
	 * To avoid hitting issues related to this, we'll invert the order of
	 * the list we return.  This code should be removed once we've tracked
	 * down the various driver issues.
	 */
	vm_page_list_reverse(&list);

	if (class == VM_MEMORY_CLASS_REGULAR && list.vmpl_has_tagged) {
		/*
		 * We are pulling pages from the taggable free queue
		 * to use them as untagged.
		 *
		 * This breaks the invariant that pages with vmp_using_mte
		 * set are either free pages on the free queue that were left
		 * tagged after being freed (covered by the cell "free_mask"),
		 * or used tagged pages (covered by the cell "mte_page_count"
		 * counter).
		 *
		 * The caller has allocated these pages from the free queue
		 * (clearing the proper "free_mask" bit) but didn't increment
		 * the "mte_page_count". It will then proceed with untagging
		 * these pages without holding any locks, and doesn't want to
		 * re-take the free page queue lock for book-keeping.
		 *
		 * As a result, invariants are broken for a little while,
		 * and we need to suspend the deactivation path that someone
		 * has currently broken this invariant on this core until
		 * the untagging is finished, otherwise, the deactivating
		 * thread would not consider these pages as tagged, and would
		 * retype the page to XNU_DEFAULT causing an SPTM panic.
		 *
		 * mteinfo_page_list_fix_tagging() will resume deactivations
		 * when it is called on the same core.
		 *
		 * mteinfo_tag_storage_deactivate_barrier() is called by any
		 * path performing a deactivation to synchronize with this.
		 */
		os_atomic_store(&vmp_pcpu->deactivate_suspend, 1,
		    compiler_acquire);
	}

	/*
	 * If pulling untagged pages tapped above the active(0) pool,
	 * and there are "active(0)" pages around, then we wake up
	 * the refill thread to drain this pool in order to make some
	 * claimable pages available.
	 */
	if (vm_mte_enable_tag_storage_grab &&
	    class == VM_MEMORY_CLASS_REGULAR &&
	    idx >= MTE_FREE_ACTIVE_0 &&
	    mteinfo_tag_storage_should_drain(true)) {
		mteinfo_wake_fill_thread();
	}

	return list;
}

void
mteinfo_page_list_fix_tagging(vm_memory_class_t class, vm_page_list_t *list)
{
	const unified_page_list_t pmap_batch_list = {
		.page_slist = list->vmpl_head,
		.type = UNIFIED_PAGE_LIST_TYPE_VM_PAGE_LIST,
	};
	vm_page_pcpu_t vmp_pcpu = PERCPU_GET(vm_page_pcpu);
	vm_page_t mem;

	assert(get_preemption_level() > 0);

	if (class == VM_MEMORY_CLASS_REGULAR && list->vmpl_has_tagged) {
		pmap_unmake_tagged_pages(&pmap_batch_list);
		vm_page_list_foreach(mem, *list) {
			mem->vmp_using_mte = false;
		}

		/*
		 * Invariants related to tagged pages are resolved,
		 * we can allow deactivations again.
		 */
		os_atomic_store(&vmp_pcpu->deactivate_suspend, 0, release);
	}

	if (class == VM_MEMORY_CLASS_TAGGED && list->vmpl_has_untagged) {
		pmap_make_tagged_pages(&pmap_batch_list);
		vm_page_list_foreach(mem, *list) {
			mem->vmp_using_mte = true;
		}
	}

	assert(!vmp_pcpu->deactivate_suspend);
}

#endif /* VM_MTE_FF_VERIFY */
#pragma mark Bootstrap

static mte_cell_queue_t
cell_list_init(
	mte_cell_queue_t        qhp,
	mte_cell_state_t        state,
	mte_cell_list_idx_t     lidx)
{
	mte_cell_bucket_t buckets = cell_list_idx_buckets(lidx);

	mte_info_lists[lidx].buckets = qhp;

	for (mte_cell_bucket_t i = 0; i < buckets; i++, qhp++) {
		qhp->head = (cell_t){
			.prev = cell_idx(qhp),
			.next = cell_idx(qhp),
			.state = state,
			.enqueue_pos = -1,
		};
	}

	return qhp;
}

__startup_func
void
mteinfo_init(uint32_t num_tag_pages)
{
	assert(2 * num_tag_pages < (1UL << MTE_FF_CELL_INDEX_BITS));
	assert(atop(mte_tag_storage_end - mte_tag_storage_start) == num_tag_pages);
	assert(num_tag_pages == mte_tag_storage_count);

	vm_size_t size = sizeof(cell_t) * (MTE_QUEUES_COUNT + num_tag_pages);
	mte_cell_queue_t queue;
	mte_cell_list_t list;

	queue = pmap_steal_memory(size, 8);
	mte_info_cells = &(queue + MTE_QUEUES_COUNT)->head;

	queue = cell_list_init(queue, MTE_STATE_DISABLED, MTE_LIST_DISABLED_IDX);
	queue = cell_list_init(queue, MTE_STATE_PINNED, MTE_LIST_PINNED_IDX);
	queue = cell_list_init(queue, MTE_STATE_DEACTIVATING, MTE_LIST_DEACTIVATING_IDX);
	queue = cell_list_init(queue, MTE_STATE_CLAIMED, MTE_LIST_CLAIMED_IDX);
	queue = cell_list_init(queue, MTE_STATE_INACTIVE, MTE_LIST_INACTIVE_IDX);
	queue = cell_list_init(queue, MTE_STATE_RECLAIMING, MTE_LIST_RECLAIMING_IDX);
	queue = cell_list_init(queue, MTE_STATE_ACTIVATING, MTE_LIST_ACTIVATING_IDX);
	queue = cell_list_init(queue, MTE_STATE_ACTIVE, MTE_LIST_ACTIVE_0_IDX);
	queue = cell_list_init(queue, MTE_STATE_ACTIVE, MTE_LIST_ACTIVE_IDX);

	assert(&queue->head == mte_info_cells);

	/*
	 * Quickly create a list of all possible cells and place it into the
	 * disabled queue.
	 */

	for (cell_idx_t i = 0; i < num_tag_pages; i++) {
		*cell_from_idx(i) = (cell_t){
			.prev = i - 1,
			.next = i + 1,
			.enqueue_pos = -1,
			.mte_page_count = 0,
			.state = MTE_STATE_DISABLED,
		};
	}

	list = &mte_info_lists[MTE_LIST_DISABLED_IDX];
	queue = &list->buckets[0];
	queue->head.next = 0;
	queue->head.prev = num_tag_pages - 1;
	queue->head.cell_count = num_tag_pages;
	cell_from_idx(0)->prev = cell_idx(queue);
	cell_from_idx(num_tag_pages - 1)->next = cell_idx(queue);
	bit_set(list->mask, 0);
	list->count = num_tag_pages;

	for (mte_free_queue_idx_t idx = MTE_FREE_UNTAGGABLE_0;
	    idx < MTE_FREE_NOT_QUEUED; idx++) {
		for (uint32_t i = 0; i < MAX_COLORS; i++) {
			vm_page_queue_init(mteinfo_free_queue_head(idx, i));
		}
	}
}

#if HIBERNATION

void
mteinfo_free_queue_foreach(void (^block)(vm_page_t))
{
	for (cell_idx_t cidx = 0; cidx < mte_tag_storage_count; cidx++) {
		cell_t  *cell = cell_from_idx(cidx);
		ppnum_t  pnum = cell_first_covered_pnum(cell);
		uint32_t mask = cell->free_mask;

		while (mask) {
			block(vm_page_find_canonical(pnum + ffs(mask) - 1));
			mask &= mask - 1;
		}

		if (cell->state == MTE_STATE_INACTIVE) {
			block(vm_tag_storage_page_get(cidx));
		}
	}
}

#endif /* HIBERNATION */
#ifndef VM_MTE_FF_VERIFY

/* List that tracks tag storage pages until mte_tags_object is initialized. */
__startup_data
static vm_page_list_t mte_tag_storage_startup_list;

void
mteinfo_tag_storage_release_startup(vm_page_t tag_page)
{
	cell_t           *cell       = cell_from_tag_storage_page(tag_page);
	ppnum_t           tag_pnum   = VM_PAGE_GET_PHYS_PAGE(tag_page);
	ppnum_t           first_pnum = cell_first_covered_pnum(cell);
	vm_memory_class_t class      = VM_MEMORY_CLASS_TAG_STORAGE;
	bool              deactivate = true;
	uint32_t          mte_count  = 0;
	uint32_t          desired_active = (mte_tag_storage_count - mte_tag_storage_discarded) / 8;


	/*
	 * If this is a tag storage page we won't even classify as tag
	 * storage.  Just give it to the normal free queues.
	 *
	 * Otherwise, keep about a 1/8 of the tag storage page around,
	 * it should be vastly sufficient to boot. The refill thread
	 * and various passive policies will let it rebalance later.
	 *
	 * Note that this code implicitly relies on the fact that
	 * the tag storage is toward the end of the vm pages array:
	 * we only keep tag storage around that have 32 pages free,
	 * but pages that haven't been created yet appear as "used".
	 */

	assert(pmap_is_tag_storage_page(tag_pnum));

	if (pmap_tag_storage_is_discarded(tag_pnum)) {
		mteinfo_tag_storage_set_retired(tag_page);
		return;
	} else if (pmap_tag_storage_is_recursive(tag_pnum)) {
		VM_COUNTER_INC(&vm_page_recursive_tag_storage_count);
		class = VM_MEMORY_CLASS_DEAD_TAG_STORAGE;
	} else if (pmap_tag_storage_is_unmanaged(tag_pnum)) {
		VM_COUNTER_INC(&vm_page_unmanaged_tag_storage_count);
		class = VM_MEMORY_CLASS_DEAD_TAG_STORAGE;
	} else {
		for (uint32_t i = 0; i < MTE_PAGES_PER_TAG_PAGE; i++) {
			mte_count += pmap_is_tagged_page(first_pnum + i);
		}

		if (cell_free_page_count(*cell) == MTE_PAGES_PER_TAG_PAGE &&
		    (mteinfo_tag_storage_active_locked() +
		    mteinfo_tag_storage_active_zero_locked()) <
		    desired_active) {
			deactivate = false;
		} else if (mte_count) {
			deactivate = false;
		}
	}

	if (deactivate) {
		pmap_unmake_tag_storage_page(tag_pnum);
		if (class == VM_MEMORY_CLASS_DEAD_TAG_STORAGE) {
			vm_page_free_queue_enter(class, tag_page, tag_pnum);
		} else {
			tag_page->vmp_q_state = VM_PAGE_ON_FREE_Q;
			mteinfo_tag_storage_set_inactive(tag_page, true);
		}
		return;
	}

	mteinfo_tag_storage_set_active(tag_page, mte_count, true);
	vm_page_list_push(&mte_tag_storage_startup_list, tag_page);
}

/*!
 * @function mteinfo_tag_storage_startup_list_flush()
 *
 * @abstract
 * Adds active tag storage pages to the mte_tags_object.
 *
 * @discussion
 * Adds the list of active tag storage pages updated by @see
 * mteinfo_tag_storage_release_startup to the mte_tags_object.  This must be
 * called at some point after the last @see mteinfo_tag_storage_release_startup
 * call.
 */
__startup_func
static void
mteinfo_tag_storage_startup_list_flush(void)
{
	vm_page_t page;

	vm_object_lock(mte_tags_object);
	vm_page_lock_queues();

	vm_page_list_foreach_consume(page, &mte_tag_storage_startup_list) {
		mteinfo_tag_storage_wire_locked(page);
	}

	vm_page_unlock_queues();
	vm_object_unlock(mte_tags_object);
}
STARTUP(KMEM, STARTUP_RANK_FIRST, mteinfo_tag_storage_startup_list_flush);

/*!
 * @abstract
 * Initializes the percpu mte queues and locks.
 */
__startup_func
static void
mteinfo_tag_storage_lock_init(void)
{
	percpu_foreach(vmp_pcpu, vm_page_pcpu) {
		lck_ticket_init(&vmp_pcpu->free_claimed_lock,
		    &vm_page_lck_grp_bucket);
		vm_page_queue_init(&vmp_pcpu->free_claimed_pages);
	}
}
STARTUP(PERCPU, STARTUP_RANK_MIDDLE, mteinfo_tag_storage_lock_init);

/*!
 * @function mteinfo_init_fill_thread
 *
 * @abstract
 * Creates the MTE fill thread.
 */
__startup_func
static void
mteinfo_init_fill_thread(void)
{
	kern_return_t result;

	if (!mte_enabled()) {
		return;
	}

	result = kernel_thread_start_priority(mteinfo_fill_continue, NULL, BASEPRI_VM,
	    &vm_mte_fill_thread);

	if (result != KERN_SUCCESS) {
		panic("Failed to create MTE fill thread.");
	}

	thread_set_thread_name(vm_mte_fill_thread, "VM_mte_fill");
	thread_deallocate(vm_mte_fill_thread);
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, mteinfo_init_fill_thread);

static ppnum_t
mteinfo_tag_storage_mark_unmanaged_range(cell_idx_t idx, ppnum_t pnum)
{
	cell_t    *end_cell = cell_from_covered_ppnum(pnum);
	cell_idx_t end_idx  = cell_idx(end_cell);
	bool       locked   = false;

	for (; idx < end_idx; idx++) {
		cell_t *cell = cell_from_idx(idx);
		vm_page_t tag_page = vm_tag_storage_page_get(idx);

		if (!locked) {
			vm_free_page_lock_spin();
			locked = true;
		}

		if (pmap_tag_storage_is_discarded(VM_PAGE_GET_PHYS_PAGE(tag_page))) {
			mteinfo_tag_storage_set_retired(tag_page);
			continue;
		}

		if (cell->mte_page_count != 0) {
			/*
			 * This can happen if some tagged pmap steal
			 * has not ml_static_mfree()d these pages back
			 */
			continue;
		}

		if (cell->state == MTE_STATE_DISABLED) {
			/*
			 * Probably an ECC retired page.
			 */
			continue;
		}

		mteinfo_tag_storage_set_unmanaged(cell,
		    vm_tag_storage_page_get(idx));
	}

	if (locked) {
		vm_free_page_unlock();
	}

	return end_idx + 1;
}

static void
mteinfo_tag_storage_unmanaged_discover(void)
{
	uint32_t   count   = vm_page_unmanaged_tag_storage_count;
	cell_idx_t cur_idx = 0;
	ppnum_t    pnum;

	if (!mte_enabled()) {
		return;
	}

	vm_pages_radix_for_each_pnum(pnum) {
		cur_idx = mteinfo_tag_storage_mark_unmanaged_range(cur_idx, pnum);
	}
	mteinfo_tag_storage_mark_unmanaged_range(cur_idx,
	    vm_pages_first_pnum);

	printf("MTE: discovered %d tag storage pages for unmanaged memory\n",
	    vm_page_unmanaged_tag_storage_count - count);
}
STARTUP(LOCKDOWN, STARTUP_RANK_LAST, mteinfo_tag_storage_unmanaged_discover);

extern boolean_t get_range_bounds(char *c, int64_t *lower, int64_t *upper);
static void
mteinfo_tag_storage_process_vm_tags(void)
{
	char *vm_tags_str;

	if (!vm_mte_enable_tag_storage_grab) {
		return;
	}

	vm_tags_str = vm_mte_tag_storage_for_vm_tags;
	while (*vm_tags_str) {
		uint64_t loop_end;
		boolean_t ret;
		int64_t start = 1, end = VM_MEMORY_COUNT;

		ret = get_range_bounds(vm_tags_str, &start, &end);
		loop_end = (ret) ? end : start;
		for (int64_t i = start; i <= loop_end; i++) {
			bitmap_set(vm_mte_tag_storage_for_vm_tags_mask, (uint)i);
		}

		/* Skip to the next ',' */
		while (*vm_tags_str != ',') {
			if (*vm_tags_str == '\0') {
				break;
			}
			vm_tags_str++;
		}

		if (*vm_tags_str == ',') {
			vm_tags_str++;
		} else {
			assert(*vm_tags_str == '\0');
			break;
		}
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, mteinfo_tag_storage_process_vm_tags);

#pragma mark Counter methods

uint32_t
mteinfo_tag_storage_fragmentation(bool actual)
{
	uint32_t ts_active;
	uint32_t value;

	vm_free_page_lock_spin();
	ts_active = mteinfo_tag_storage_active_locked();
	if (actual) {
		ts_active += mteinfo_tag_storage_active_zero_locked();
	}
	if (ts_active) {
		value  = 1000 * vm_page_tagged_count;
		value /= (ts_active * MTE_PAGES_PER_TAG_PAGE);
	} else {
		value  = 1000;
	}
	vm_free_page_unlock();

	return 1000 - value;
}

uint32_t
mteinfo_tag_storage_nontags_wired_locked(void)
{
	return vm_page_wired_tag_storage_count;
}

uint32_t
mteinfo_tag_storage_nontags_pageable_locked(void)
{
	uint32_t total = mte_info_lists[MTE_LIST_CLAIMED_IDX].count +
	    mte_info_lists[MTE_LIST_DISABLED_IDX].count +
	    mte_info_lists[MTE_LIST_PINNED_IDX].count;
	/* Exclude free claimed and unmanaged pages */
	uint32_t free = vm_page_free_unmanaged_tag_storage_count +
	    (uint32_t)counter_load(&vm_cpu_free_claimed_count);
	/*
	 * Subtract all the wired pages from consideration. MTE_LIST_PINNED_IDX is not
	 * comprehensive and is updated lazily.
	 */
	uint32_t wired = vm_page_wired_tag_storage_count;

	return total - free - wired;
}

uint32_t
mteinfo_tag_storage_free_locked(void)
{
	return mte_info_lists[MTE_LIST_INACTIVE_IDX].count +
	       /*
	        * Count all the transient states as "free" since they are
	        * transitioning between free states.
	        */
	       mte_info_lists[MTE_LIST_RECLAIMING_IDX].count +
	       mte_info_lists[MTE_LIST_DEACTIVATING_IDX].count +
	       mte_info_lists[MTE_LIST_ACTIVATING_IDX].count +
	       /*
	        * NB: In practice, not all active-0 pages will be reclaimable, so
	        * this is a slight overestimate of "free" tag storage pages, but is
	        * the best we can do without iterating over the pages.
	        */
	       mte_info_lists[MTE_LIST_ACTIVE_0_IDX].count +
	       /* The below comprise a subset of CLAIMED and DISABLED */
	       vm_page_free_unmanaged_tag_storage_count +
	       (uint32_t)counter_load(&vm_cpu_free_claimed_count);
}

uint32_t
mteinfo_tag_storage_active_zero_locked(void)
{
	return mte_info_lists[MTE_LIST_ACTIVE_0_IDX].count;
}

uint32_t
mteinfo_tag_storage_active_locked(void)
{
	return mte_info_lists[MTE_LIST_ACTIVE_IDX].count;
}

uint32_t
mteinfo_tag_storage_active(void)
{
	uint32_t active;

	vm_free_page_lock_spin();
	active = mteinfo_tag_storage_active_locked() +
	    mteinfo_tag_storage_active_zero_locked();
	vm_free_page_unlock();
	return active;
}

uint32_t
mteinfo_tag_storage_free_pages_for_covered(const struct vm_page *page)
{
	ppnum_t pnum = VM_PAGE_GET_PHYS_PAGE(page);

	return cell_free_page_count(*cell_from_covered_ppnum(pnum));
}

void
mteinfo_increment_wire_count(vm_page_t tag_page)
{
	if (vm_page_in_tag_storage_array(tag_page) &&
	    vm_page_is_tag_storage(tag_page)) {
		VM_COUNTER_ATOMIC_INC(&vm_page_wired_tag_storage_count);

		DTRACE_VM1(vm_tag_storage_wired, vm_page_t, tag_page);
	}
}

void
mteinfo_decrement_wire_count(vm_page_t tag_page, bool pqs_locked)
{
	LCK_MTX_ASSERT(&vm_page_queue_lock,
	    pqs_locked ? LCK_MTX_ASSERT_OWNED : LCK_MTX_ASSERT_NOTOWNED);
	LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_NOTOWNED);

	if (vm_page_in_tag_storage_array(tag_page) &&
	    VM_PAGE_OBJECT(tag_page) != mte_tags_object &&
	    vm_page_is_tag_storage(tag_page)) {
		VM_COUNTER_ATOMIC_DEC(&vm_page_wired_tag_storage_count);

		DTRACE_VM1(vm_tag_storage_unwired, vm_page_t, tag_page);

		if (tag_page->vmp_ts_wanted) {
			/*
			 * Many callers have the page queue lock held in spin
			 * when calling this, and mteinfo_tag_storage_wakeup()
			 * needs to acquire a mutex.
			 */
			if (pqs_locked) {
				vm_page_lockconvert_queues();
			}
			mteinfo_tag_storage_wakeup(tag_page, false);
		}
	}
}

bool
mteinfo_vm_tag_can_use_tag_storage(vm_tag_t vm_tag)
{
	return bitmap_test(vm_mte_tag_storage_for_vm_tags_mask, (uint)vm_tag);
}


void
kdp_mteinfo_snapshot(struct mte_info_cell * __counted_by(count) cells, size_t count)
{
	release_assert(count == mte_tag_storage_count);

	if (not_in_kdp) {
		panic("panic: kdp_mteinfo_fill called outside of kernel debugger");
	}

	for (cell_idx_t cidx = 0; cidx < mte_tag_storage_count; cidx++) {
		cell_t  *cell = cell_from_idx(cidx);
		ppnum_t  pnum = cell_first_covered_pnum(cell);
		vm_page_t mem;
		uint8_t wired_count = 0, wired_tagged_count = 0, kernel_wired_tagged_count = 0;

		for (ppnum_t i = 0; i < MTE_PAGES_PER_TAG_PAGE; i++) {
			mem = vm_page_find_canonical(pnum + i);
			if (mem && VM_PAGE_WIRED(mem)) {
				wired_count++;
				if (mem->vmp_using_mte) {
					if (VM_PAGE_OBJECT(mem) == kernel_object_tagged) {
						kernel_wired_tagged_count++;
					} else {
						wired_tagged_count++;
					}
				}
			}
		}

		cells[cidx] = (struct mte_info_cell) {
			.mic_state = cell->state,
			.mic_tagged_count = cell->mte_page_count,
			.mic_free_count = (uint8_t)cell_free_page_count(*cell),
			.mic_wired_count = wired_count,
			.mic_wired_tagged_count = wired_tagged_count,
			.mic_kernel_wired_tagged_count = kernel_wired_tagged_count
		};
	}
}
#endif /* VM_MTE_FF_VERIFY */

#endif /* HAS_MTE */
