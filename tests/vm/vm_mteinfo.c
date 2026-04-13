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

#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <os/overflow.h>

#pragma clang attribute push(__attribute__((noinline, optnone)), apply_to=function)

#include "../osfmk/kern/bits.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.mteinfo"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG_VM_PREFERRED);

#define DEVELOPMENT 0
#define DEBUG 0
#define XNU_KERNEL_PRIVATE 1
#define HAS_MTE 1
#define VM_MTE_FF_VERIFY 1
#define VM_PAGE_PACKED_ALIGNED
#define VMP_FREE_BATCH_SIZE  64

/* Fake out some common XNU macros and defines. */
#define SECURITY_READ_ONLY_LATE(type) __used type
#define __startup_func
#define MTE_PAGES_PER_TAG_PAGE        32
#define MAX_COLORS                   128

TAILQ_HEAD(vm_page_queue_head, vm_page);
typedef struct vm_page_queue_head vm_page_queue_head_t;
typedef struct vm_page_queue_head *vm_page_queue_t;
typedef struct vm_page_queue_free_head {
	vm_page_queue_head_t    qhead;
} *vm_page_queue_free_head_t;

typedef struct vm_page_free_queue {
	struct vm_page_queue_free_head vmpfq_queues[MAX_COLORS];
	uint32_t                       vmpfq_count;
} *vm_page_free_queue_t;

/*
 * TODO: Handle this in a way that doesn't break when using other TUNABLE_*
 *       variants in the real vm_mteinfo.c file.
 */
#define TUNABLE(t, var, name, value) t var = value
#define TUNABLE_DT_DEV_WRITEABLE(type_t, var, dt_base, dt_name, boot_arg, default_value, flags) type_t var = default_value

typedef struct vm_page {
	TAILQ_ENTRY(vm_page) vmp_pageq;
	uint16_t             vmp_mtefq_sel;
	uint16_t             vmp_using_mte;
	ppnum_t              ppnum;
} *vm_page_t;

#define vm_page_queue_init(q)                   TAILQ_INIT(q)
#define vm_page_queue_empty(q)                  TAILQ_EMPTY(q)
#define vm_page_queue_remove(q, e, link)        TAILQ_REMOVE(q, e, link)
#define vm_page_queue_remove_first(q, e, link)  ({ (e) = TAILQ_FIRST(q); TAILQ_REMOVE(q, e, link); })
#define vm_page_queue_enter(q, e, link)         TAILQ_INSERT_TAIL(q, e, link)
#define vm_page_queue_enter_first(q, e, link)   TAILQ_INSERT_HEAD(q, e, link)

#define release_assert(...)                     assert(__VA_ARGS__)

#define VM_PAGE_NULL ((vm_page_t)0)
#define VM_PAGE_GET_PHYS_PAGE(page) \
	(page)->ppnum

#define VM_COUNTER_SUB(counter, value)  ({ \
	__auto_type __counter = (counter);                                      \
	T_QUIET; T_ASSERT_FALSE(os_sub_overflow(*__counter, value, __counter),  \
	    "no overflow");                                                     \
	*__counter;                                                             \
})

#define VM_COUNTER_ADD(counter, value)  ({ \
	__auto_type __counter = (counter);                                      \
	T_QUIET; T_ASSERT_FALSE(os_add_overflow(*__counter, value, __counter),  \
	    "no overflow");                                                     \
	*__counter;                                                             \
})

#define VM_COUNTER_DEC(counter)  VM_COUNTER_SUB(counter, 1)
#define VM_COUNTER_INC(counter)  VM_COUNTER_ADD(counter, 1)

#define ptoa(x) ((unsigned long long)(x) << 14)
#define atop(x) ((unsigned long long)(x) >> 14)

static void
__queue_element_linkage_invalid(void *e)
{
	T_ASSERT_FAIL("Invalid queue linkage at %p", e);
}

/*
 * MTE and VM globals taken over by the test.  A few values are chosen
 * deliberately, but most are arbitrary.
 */

/* A stand-in for gDramBase.  Make it non-zero to be nontrivial. */
static const ppnum_t   pmap_first_pnum = 42 * MAX_COLORS;

/*
 * Fake the vm pages array
 *
 * For the sake of the test we pretend everything is in the array,
 * in the real kernel the data structure needs lookups for the
 * [pmap_first_pnum, vm_pages_first_pnum) range.
 *
 * It doesn't affect testing materially though.
 */
static const uint32_t  vm_pages_count = 8 * 1024;
static struct vm_page  vm_pages[vm_pages_count];
static const vm_page_t vm_pages_end = vm_pages + vm_pages_count;
static const uint32_t  vm_color_mask = 63;

static const uint32_t  mte_tag_storage_count = vm_pages_count / MTE_PAGES_PER_TAG_PAGE;
static const uint32_t  mte_tag_storage_start_pnum = pmap_first_pnum + vm_pages_count - mte_tag_storage_count;
static const uint64_t  mte_tag_storage_start = ptoa(mte_tag_storage_start_pnum);
static const uint64_t  mte_tag_storage_end   = ptoa(pmap_first_pnum + vm_pages_count);
static const vm_page_t vm_pages_tag_storage  = vm_pages_end - mte_tag_storage_count;

/* This tag storage page will always be disabled due to an ECC error. */
static const ppnum_t  mte_tag_storage_ecc_disabled = atop(mte_tag_storage_start) + 200;

static uint32_t vm_page_free_count;

static bool
pmap_in_tag_storage_range(ppnum_t pnum)
{
	uint64_t addr = ptoa(pnum);

	return (mte_tag_storage_start <= addr) && (addr < mte_tag_storage_end);
}

static void *
pmap_steal_memory(vm_size_t size, vm_size_t align)
{
	void *ptr = NULL;

	if (posix_memalign(&ptr, align, size) == 0) {
		return ptr;
	}

	return NULL;
}


__pure2
static inline vm_page_t
vm_pages_tag_storage_array_internal(void)
{
	return vm_pages_tag_storage;
}

__pure2
static inline vm_page_t
vm_tag_storage_page_get(uint32_t i)
{
	return &vm_pages_tag_storage[i];
}

static inline struct vm_page *
vm_page_find_canonical(ppnum_t pnum)
{
	return &vm_pages[pnum - pmap_first_pnum];
}

/*
 * Now that the necessary gunk is in place to pretend we are the kernel...
 * directly include the kernel mteinfo files.
 */
#include "../osfmk/vm/vm_mteinfo_internal.h"
#include "../osfmk/vm/vm_mteinfo.c"

static char const *const cell_states[] = {
	[MTE_STATE_DISABLED]     = "disabled",
	[MTE_STATE_PINNED]       = "pinned",
	[MTE_STATE_DEACTIVATING] = "deactivating",
	[MTE_STATE_CLAIMED]      = "claimed",
	[MTE_STATE_INACTIVE]     = "inactive",
	[MTE_STATE_RECLAIMING]   = "reclaiming",
	[MTE_STATE_ACTIVATING]   = "activating",
	[MTE_STATE_ACTIVE]       = "active",
};

static bool
cell_queue_empty(mte_cell_queue_t queue)
{
	return cell_idx_is_queue(queue->head.next);
}

static mte_cell_state_t
cell_state_from_list_idx(mte_cell_list_idx_t idx)
{
	if (idx < MTE_LIST_ACTIVE_0_IDX) {
		return (mte_cell_state_t)idx;
	}

	return MTE_STATE_ACTIVE;
}

static ppnum_t
covered_page(cell_idx_t idx, uint32_t slot)
{
	ppnum_t pnum = pmap_first_pnum + (idx * MTE_PAGES_PER_TAG_PAGE);

	assert(pnum >= pmap_first_pnum);
	assert(pnum < pmap_first_pnum + vm_pages_count);

	return pnum + slot;
}

static void
verify_cell_mark(cell_t *cell, mte_cell_state_t state)
{
	T_QUIET; T_ASSERT_EQ(state, (int)cell->state,
	    "correct state for cell %p", cell);
	T_QUIET; T_ASSERT_FALSE(cell->__unused_bits,
	    "cell %p not seen yet", cell);
	cell->__unused_bits = true;
}

static void
verify_cell_clear(cell_t *cell)
{
	T_QUIET; T_ASSERT_TRUE(cell->__unused_bits,
	    "cell %p already seen", cell);
	cell->__unused_bits = false;
}

static void
verify_cell_mte_page_count(cell_t *cell, mte_cell_list_idx_t lidx)
{
	switch (cell->state) {
	case MTE_STATE_DISABLED:
	case MTE_STATE_PINNED:
	case MTE_STATE_DEACTIVATING:
	case MTE_STATE_RECLAIMING:
	case MTE_STATE_ACTIVATING:
		/* can be any mte count */
		break;

	case MTE_STATE_CLAIMED:
	case MTE_STATE_INACTIVE:
		T_QUIET; T_ASSERT_EQ(0, (int)cell->mte_page_count,
		    "correct mte page count (cell %d)", cell_idx(cell));
		break;
	default:
		T_QUIET; T_ASSERT_EQ(lidx - MTE_LIST_ACTIVE_0_IDX,
		    (int)cell->mte_page_count != 0,
		    "correct mte page count (cell %d)", cell_idx(cell));
		break;
	}
}

static void
verify_cell_queue(
	mte_cell_queue_t    queue,
	mte_cell_state_t    state,
	mte_cell_list_idx_t lidx,
	mte_cell_bucket_t   bucket)
{
	cell_t *head = &queue->head;
	cell_t *prev = head;

	verify_cell_mark(head, state);

	T_QUIET; T_ASSERT_EQ(0, (int)head->mte_page_count,
	    "correct mte page count (cell %d)", cell_idx(head));

	cell_queue_foreach(cell, queue) {
		verify_cell_mark(cell, state);

		T_QUIET; T_ASSERT_EQ(prev, cell_from_idx(cell->prev),
		    "valid linkage");
		verify_cell_mte_page_count(cell, lidx);

		prev = cell;
	}
}

static void
verify_cell_list(mte_cell_state_t state, mte_cell_list_idx_t idx)
{
	mte_cell_bucket_t n    = cell_list_idx_buckets(idx);
	mte_cell_list_t   list = &mte_info_lists[idx];

	T_QUIET; T_ASSERT_LE(list->mask, (uint32_t)bits_mask(n),
	    "mask has less than %d bits set", n);

	for (mte_cell_bucket_t i = 0; i < n; i++) {
		mte_cell_queue_t q = &list->buckets[i];

		if (cell_queue_empty(q)) {
			T_QUIET; T_ASSERT_FALSE(list->mask & BIT(i),
			    "bucket %d.%d is empty", idx, i);
		} else {
			T_QUIET; T_ASSERT_TRUE(list->mask & BIT(i),
			    "bucket %d.%d is non empty", idx, i);
		}

		verify_cell_queue(q, state, idx, i);
	}
}

static void
verify_mte_info(void)
{
	uint64_t count = 0;

	verify_cell_list(MTE_STATE_DISABLED, MTE_LIST_DISABLED_IDX);
	verify_cell_list(MTE_STATE_PINNED, MTE_LIST_PINNED_IDX);
	verify_cell_list(MTE_STATE_DEACTIVATING, MTE_LIST_DEACTIVATING_IDX);
	verify_cell_list(MTE_STATE_CLAIMED, MTE_LIST_CLAIMED_IDX);
	verify_cell_list(MTE_STATE_INACTIVE, MTE_LIST_INACTIVE_IDX);
	verify_cell_list(MTE_STATE_RECLAIMING, MTE_LIST_RECLAIMING_IDX);
	verify_cell_list(MTE_STATE_ACTIVATING, MTE_LIST_ACTIVATING_IDX);
	verify_cell_list(MTE_STATE_ACTIVE, MTE_LIST_ACTIVE_0_IDX);
	verify_cell_list(MTE_STATE_ACTIVE, MTE_LIST_ACTIVE_IDX);

	for (cell_idx_t i = -MTE_QUEUES_COUNT; i < (cell_idx_t)mte_tag_storage_count; i++) {
		verify_cell_clear(cell_from_idx(i));
	}

	for (uint32_t i = 0; i < MTE_LISTS_COUNT; i++) {
		count += mte_info_lists[i].count;
	}
	T_QUIET; T_ASSERT_EQ(count, (uint64_t)mte_tag_storage_count, "cell count");
}

static void
verify_cell_in_list(cell_t *cell, mte_cell_list_idx_t idx)
{
	mte_cell_bucket_t bucket = cell_list_bucket(*cell);
	mte_cell_queue_t queue = &mte_info_lists[idx].buckets[bucket];

	T_QUIET; T_ASSERT_EQ(cell_state_from_list_idx(idx), (int)cell->state,
	    "correct state for cell %p", cell);

	cell_queue_foreach(it, queue) {
		if (cell == it) {
			T_PASS("cell %p found in list %d.%d", cell, idx, bucket);
			return;
		}
	}

	T_ASSERT_FAIL("cell %p not found in list %d.%d", cell, idx, bucket);
}

static void
print_cell(cell_t *cellp)
{
	printf("      cell (%p) { index: %d, free: %d, mte: %d, next: %d, prev: %d }\n",
	    cellp, cell_idx(cellp), cell_free_page_count(*cellp), cellp->mte_page_count,
	    cellp->next, cellp->prev);
}

static void
print_cell_queue(mte_cell_list_idx_t idx, mte_cell_queue_t queue, mte_cell_bucket_t bucket)
{
	cell_t head = queue->head;

	printf("    %s[%d.%d] queue (%p) { index: %d, next: %d, prev: %d }\n",
	    cell_states[head.state], idx, bucket,
	    queue, cell_idx(queue), head.next, head.prev);

	cell_queue_foreach(cell, queue) {
		print_cell(cell);
	}
}

static void
print_cell_list(mte_cell_list_idx_t idx)
{
	mte_cell_bucket_t n    = cell_list_idx_buckets(idx);
	mte_cell_list_t   list = &mte_info_lists[idx];
	cell_t            head = list->buckets[0].head;

	printf("  %s[%d] list (%p) { mask: 0x%08x }\n",
	    cell_states[head.state], idx, list, list->mask);

	for (mte_cell_bucket_t i = 0; i < n; i++) {
		print_cell_queue(idx, &list->buckets[i], i);
	}

	printf("\n");
}

static void
print_mte_info(void)
{
	printf("MTE Info\n");

	print_cell_list(MTE_LIST_DISABLED_IDX);
	print_cell_list(MTE_LIST_PINNED_IDX);
	print_cell_list(MTE_LIST_CLAIMED_IDX);
	print_cell_list(MTE_LIST_INACTIVE_IDX);
	print_cell_list(MTE_LIST_DEACTIVATING_IDX);
	print_cell_list(MTE_LIST_RECLAIMING_IDX);
	print_cell_list(MTE_LIST_ACTIVATING_IDX);
	print_cell_list(MTE_LIST_ACTIVE_0_IDX);
	print_cell_list(MTE_LIST_ACTIVE_IDX);
}

static void
print_mte_info_on_failure(void)
{
	if (mte_info_cells) {
		print_mte_info();
	}
}

static void
test_setup(bool skip_free_pages)
{
	static bool atend_done;

	/*
	 * This a hack: if the test asserts in the middle, mte_info_cells will
	 * not be freed, and be printed.
	 */
	if (!atend_done) {
		T_ATEND(print_mte_info_on_failure);
		atend_done = true;
	}

	T_QUIET; T_ASSERT_FALSE(mte_info_cells, "test_teardown was forgotten");

	mteinfo_init(mte_tag_storage_count);

	/* Simulate vm_page_release_startup() */
	for (uint32_t i = 0; i < vm_pages_count; i++) {
		ppnum_t   pnum = i + pmap_first_pnum;
		vm_page_t mem  = &vm_pages[i];

		mem->ppnum = pnum;

		if (pnum == mte_tag_storage_ecc_disabled) {
			/* Skip this page; it is "broken." */
		} else if (pmap_in_tag_storage_range(pnum)) {
			/* TODO: Simulate early boot pre-set pages. */
			mteinfo_tag_storage_set_inactive(mem, true);
		} else if (!skip_free_pages) {
			mteinfo_covered_page_set_free(pnum, false);
		}
	}
}

static void
test_teardown(void)
{
	free(mte_info_cells - MTE_QUEUES_COUNT);
	mte_info_cells = NULL;
}

static void
t_set_activating(cell_idx_t idx)
{
	cell_t   *cell     = cell_from_idx(idx);

	assert_cell_state(cell, MTE_MASK_INACTIVE);

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_ACTIVATING;
	});
}

static void
t_set_deactivating(cell_idx_t idx)
{
	cell_t   *cell     = cell_from_idx(idx);

	assert_cell_state(cell, MTE_MASK_ACTIVE);

	CELL_UPDATE(cell, false, {
		cell->state = MTE_STATE_DEACTIVATING;
	});
}

static void
t_set_reclaiming(cell_idx_t idx)
{
	cell_t   *cell     = cell_from_idx(idx);

	mteinfo_tag_storage_set_reclaiming(cell);
}


T_DECL(init, "check that initialization sets up the data structure correctly")
{
	vm_page_t tag_page;
	cell_t *cell;

	test_setup(false);

	verify_mte_info();

	verify_cell_in_list(cell_from_covered_ppnum(pmap_first_pnum),
	    MTE_LIST_INACTIVE_IDX);

	tag_page = vm_page_find_canonical(mte_tag_storage_ecc_disabled);
	verify_cell_in_list(cell_from_tag_storage_page(tag_page),
	    MTE_LIST_DISABLED_IDX);

	cell = cell_from_covered_ppnum(mte_tag_storage_start_pnum) - 1;
	/* cell before last first tag storage is normal */
	verify_cell_in_list(cell, MTE_LIST_INACTIVE_IDX);
	/* first self referential page has "nothing free" (for now) */
	verify_cell_in_list(cell + 1, MTE_LIST_INACTIVE_IDX);

	verify_cell_in_list(cell_from_idx(100), MTE_LIST_INACTIVE_IDX);

	test_teardown();
}

T_DECL(cell_list, "checks cells migrations between lists")
{
	cell_idx_t cidx = 0;

	test_setup(false);

	T_LOG("active <-> inactive transitions");
	{
		cidx = 100;
		t_set_activating(cidx);
		mteinfo_tag_storage_set_active(&vm_pages_tag_storage[cidx], 0, false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_ACTIVE_0_IDX);

		t_set_deactivating(cidx);
		mteinfo_tag_storage_set_inactive(&vm_pages_tag_storage[cidx], false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_INACTIVE_IDX);

		cidx = 101;
		t_set_activating(cidx);
		mteinfo_tag_storage_set_active(&vm_pages_tag_storage[cidx], 0, false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_ACTIVE_0_IDX);

		cidx = 102;
		t_set_activating(cidx);
		mteinfo_tag_storage_set_active(&vm_pages_tag_storage[cidx], 0, false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_ACTIVE_0_IDX);

		cidx = 103;
		t_set_activating(cidx);
		mteinfo_tag_storage_set_active(&vm_pages_tag_storage[cidx], 0, false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_ACTIVE_0_IDX);

		cidx = 101;
		t_set_deactivating(cidx);
		mteinfo_tag_storage_set_inactive(&vm_pages_tag_storage[cidx], false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_INACTIVE_IDX);
	}

	T_LOG("inactive <-> claimed <-> reclaiming transitions");
	{
		for (cidx = 110; cidx < 120; cidx++) {
			mteinfo_tag_storage_set_claimed(&vm_pages_tag_storage[cidx]);
			verify_mte_info();
			verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_CLAIMED_IDX);
		}

		cidx = 111;
		mteinfo_tag_storage_set_inactive(&vm_pages_tag_storage[cidx], false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_INACTIVE_IDX);

		for (cidx = 115; cidx < 120; cidx++) {
			t_set_reclaiming(cidx);
			verify_mte_info();
			verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_RECLAIMING_IDX);
		}

		cidx = 115;
		mteinfo_tag_storage_set_inactive(&vm_pages_tag_storage[cidx], false);
		verify_mte_info();
		verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_INACTIVE_IDX);

		mteinfo_tag_storage_flush_reclaiming();
		verify_mte_info();
		for (cidx = 116; cidx < 120; cidx++) {
			verify_cell_in_list(cell_from_idx(cidx), MTE_LIST_CLAIMED_IDX);
		}
	}

	test_teardown();
}

static void
test_cell_queue_add_rm_free_pages(cell_idx_t cidx, mte_cell_list_idx_t lidx)
{
	cell_t *cell = cell_from_idx(cidx);

	for (int i = MTE_PAGES_PER_TAG_PAGE - cell->mte_page_count; i-- > 0;) {
		mteinfo_covered_page_set_used(covered_page(cidx, i), false);
		verify_mte_info();
		verify_cell_in_list(cell, lidx);
	}

	for (int i = 0; i < MTE_PAGES_PER_TAG_PAGE - cell->mte_page_count; i++) {
		mteinfo_covered_page_set_free(covered_page(cidx, i), false);
		verify_mte_info();
		verify_cell_in_list(cell, lidx);
	}
}

T_DECL(cell_queue, "checks cells migrations between queues")
{
	cell_idx_t cidx = 100;

	test_setup(false);

	T_LOG("disabled");
	test_cell_queue_add_rm_free_pages(200, MTE_LIST_DISABLED_IDX);

	T_LOG("inactive");
	test_cell_queue_add_rm_free_pages(cidx, MTE_LIST_INACTIVE_IDX);

	T_LOG("claimed");
	mteinfo_tag_storage_set_claimed(&vm_pages_tag_storage[cidx]);
	test_cell_queue_add_rm_free_pages(cidx, MTE_LIST_CLAIMED_IDX);

	T_LOG("reclaiming");
	t_set_reclaiming(cidx);
	test_cell_queue_add_rm_free_pages(cidx, MTE_LIST_RECLAIMING_IDX);

	mteinfo_tag_storage_set_inactive(&vm_pages_tag_storage[cidx], false);

	t_set_activating(cidx);
	mteinfo_tag_storage_set_active(&vm_pages_tag_storage[cidx], 0, false);

	for (int i = 0; i <= MTE_PAGES_PER_TAG_PAGE; i++) {
		T_LOG("active[%d]", i);

		if (i != 0) {
			mteinfo_covered_page_set_used(covered_page(cidx,
			    MTE_PAGES_PER_TAG_PAGE - i), true);
		}

		test_cell_queue_add_rm_free_pages(cidx,
		    i ? MTE_LIST_ACTIVE_IDX : MTE_LIST_ACTIVE_0_IDX);
		verify_mte_info();

		if (i == MTE_PAGES_PER_TAG_PAGE) {
			verify_cell_in_list(cell_from_idx(cidx),
			    MTE_LIST_ACTIVE_IDX);
		}
	}

	test_teardown();
}

T_DECL(find_tag, "validate the policies around finding tag storage pages")
{
#define T_ASSERT_FIND_TAG(how, idx, msg, ...) \
	T_ASSERT_EQ((long)idx, cell_list_find_last_page(MTE_LIST_##how##_IDX, 1, &tag_page) - \
	    mte_info_cells, msg, ## __VA_ARGS__)

#define T_ASSERT_FIND_NO_TAG(how, msg, ...) \
	T_ASSERT_EQ(NULL, cell_list_find_last_page(MTE_LIST_##how##_IDX, 1, &tag_page), \
	    msg, ## __VA_ARGS__)

	/* We set no pages as "free." */
	test_setup(true);
	vm_page_t tag_page;

	T_ASSERT_FIND_NO_TAG(CLAIMED, "nothing to find");
	T_ASSERT_FIND_NO_TAG(INACTIVE, "nothing to find");

	/* Play with claimed pages. */
	mteinfo_tag_storage_set_claimed(&vm_pages_tag_storage[30]);
	T_ASSERT_FIND_NO_TAG(CLAIMED, "nothing to find");

	mteinfo_covered_page_set_free(covered_page(30, 0), false);
	T_ASSERT_FIND_TAG(CLAIMED, 30, "should find claimed %d", 30);

	mteinfo_tag_storage_set_claimed(&vm_pages_tag_storage[31]);
	for (uint32_t i = 0; i < 8; i++) {
		mteinfo_covered_page_set_free(covered_page(31, i), false);
		T_ASSERT_FIND_TAG(CLAIMED, 30, "should still find claimed %d", 30);
	}

	mteinfo_covered_page_set_free(covered_page(31, 16), false);
	T_ASSERT_FIND_TAG(CLAIMED, 31, "should now find claimed %d", 31);

	/* Play with inactive pages. */
	verify_cell_in_list(cell_from_idx(40), MTE_LIST_INACTIVE_IDX);
	verify_cell_in_list(cell_from_idx(41), MTE_LIST_INACTIVE_IDX);
	T_ASSERT_FIND_NO_TAG(INACTIVE, "nothing to find");

	mteinfo_covered_page_set_free(covered_page(40, 0), false);
	T_ASSERT_FIND_TAG(INACTIVE, 40, "should find inactive %d", 40);

	/* More free pages. */
	for (uint32_t i = 0; i < 8; i++) {
		mteinfo_covered_page_set_free(covered_page(41, i), false);
		T_ASSERT_FIND_TAG(INACTIVE, 40, "should still find inactive %d", 40);
	}

	mteinfo_covered_page_set_free(covered_page(41, 16), false);
	T_ASSERT_FIND_TAG(INACTIVE, 41, "should now find inactive %d", 41);

	test_teardown();
#undef T_ASSERT_FIND_TAG
#undef T_ASSERT_FIND_NO_TAG
}

#pragma clang attribute pop

static cell_t
cell_with(uint32_t tagged, uint32_t free)
{
	return (cell_t){
		       .mte_page_count = tagged,
		       .free_mask = (uint32_t)bits_mask(free),
		       .state = MTE_STATE_ACTIVE,
	};
}

static mte_free_queue_idx_t
t_active_bucket(cell_t cell)
{
#if 1
	uint32_t free   = cell_free_page_count(cell);
	uint32_t tagged = cell.mte_page_count;
	uint32_t used   = 32 - tagged - free;
	uint32_t n;

	n  = tagged + free / 3;
	n -= MIN(n, used) / 2;
	return MTE_FREE_ACTIVE_0 + fls(n / 4);
#else
	return mteinfo_free_queue_idx(cell);
#endif
}

static int
t_bucket_to_color(unsigned bucket)
{
	if (bucket < MTE_FREE_ACTIVE_0 ||
	    bucket >= MTE_FREE_UNTAGGABLE_ACTIVATING) {
		return 1; /* dark red */
	}
	return bucket - MTE_FREE_ACTIVE_0 + 2;
}

T_DECL(active_buckets, "helper to print/chose buckets", T_META_ENABLED(false))
{
	/*
	 * 64 is enough for everybody,
	 * we're not doing security here after all are we?
	 */
	char buf[64];

	for (unsigned tagged = 0; tagged < 32; tagged++) {
		for (unsigned free = 1; free <= 32 - tagged; free++) {
			cell_t cell = cell_with(tagged, free);
			mte_free_queue_idx_t b = t_active_bucket(cell);

			T_QUIET; T_EXPECT_GE(b, MTE_FREE_ACTIVE_0,
			    "valid bucket for %d.%d", tagged, free);
			T_QUIET; T_EXPECT_LT(b, MTE_FREE_UNTAGGABLE_ACTIVATING,
			    "valid bucket for %d.%d", tagged, free);
		}
	}

	for (mte_free_queue_idx_t b = MTE_FREE_ACTIVE_0;
	    b < MTE_FREE_UNTAGGABLE_ACTIVATING; b++) {
		unsigned column = 0;

		printf("\n\033[38;5;%d;mBucket %d:\033[0m",
		    t_bucket_to_color(b), b - MTE_FREE_ACTIVE_0);

		for (unsigned tagged = 0; tagged < 32; tagged++) {
			unsigned first_free = ~0u, last_free = 0;

			for (unsigned free = 1; free <= 32 - tagged; free++) {
				cell_t cell = cell_with(tagged, free);

				if (t_active_bucket(cell) == b) {
					last_free = free;
					first_free = MIN(free, first_free);
				}
			}

			if (first_free > 32) {
				continue;
			}

			if (column == 0) {
				puts("");
			}

			if (first_free == 1 && tagged + last_free == 32) {
				snprintf(buf, sizeof(buf), "%2d.*", tagged);
			} else if (first_free == last_free) {
				snprintf(buf, sizeof(buf), "%2d.%d",
				    tagged, first_free);
			} else if (tagged + last_free == 32) {
				snprintf(buf, sizeof(buf), "%2d.%d+",
				    tagged, first_free);
			} else {
				snprintf(buf, sizeof(buf), "%2d.[%d-%d]",
				    tagged, first_free, last_free);
			}
			printf("  %-10s", buf);

			if (++column == 6) {
				column = 0;
			}
		}
		puts("");
	}

	puts("\n"
	    "                  \033[1mfree pages\033[0m\n"
	    "                 1        2         3\n"
	    "  \033[1mmte\033[0m  ....5....0....5....0....5....0.2");

	for (unsigned tagged = 0; tagged < 32; tagged += 2) {
		printf(" %2d-%-2d ", tagged, tagged + 1);

		for (unsigned free = 1;; free++) {
			unsigned b_0, b_1;

			b_0 = t_active_bucket(cell_with(tagged, free));
			if (tagged + 1 + free > 32) {
				printf("\033[49;38;5;%d;m▀\033[0m\n",
				    t_bucket_to_color(b_0));
				break;
			}

			b_1 = t_active_bucket(cell_with(tagged + 1, free));
			printf("\033[38;5;%d;48;5;%d;m▀",
			    t_bucket_to_color(b_0),
			    t_bucket_to_color(b_1));
		}
	}

	puts("\033[0m");
}
