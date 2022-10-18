/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <kern/compact_id.h>
#include <kern/locks.h>
#include <kern/thread.h>

static LCK_GRP_DECLARE(compact_id_lck_grp, "compact_id");

#define compact_id_table_sleep(table) \
	lck_mtx_sleep_with_inheritor(&(table)->cidt_lock, \
	    LCK_SLEEP_DEFAULT, (event_t)(table), (table)->cidt_allocator, \
	    THREAD_UNINT, TIMEOUT_WAIT_FOREVER)
#define compact_id_table_wake(table) \
	wakeup_all_with_inheritor((event_t)(table), THREAD_AWAKENED)

static inline uint32_t
compact_id_prev_max(uint32_t idx)
{
	/*
	 * |BASE|BASE|2BASE|4BASE|...|2^(index-2)BASE|2^(index-1)BASE|
	 *   0    1     2     3          index - 1        index
	 *
	 * the maximum number of values that can be stored on all
	 * entries previous to table_index is:
	 * CTID_BASE_TABLE * 2^(table_index - 1)
	 * for table_index greater then 0.
	 */
	return idx ? COMPACT_ID_COUNT_BASE << (idx - 1) : 0;
}

static uint32_t
compact_id_slab_size(uint32_t table_index)
{
	if (table_index == 0) {
		return COMPACT_ID_COUNT_BASE;
	}
	return COMPACT_ID_COUNT_BASE << (table_index - 1);
}

static uint32_t
compact_id_slab_index(compact_id_t cid)
{
	/*
	 * The first 2 entries have size COMPACT_ID_COUNT_BASE,
	 * all others have size COMPACT_ID_COUNT_BASE * 2^(i - 1).
	 *
	 * If you get the the number of the most significant 0s
	 * on COMPACT_ID_COUNT_BASE and you subtract how many there
	 * are in cidt, you get the index in the table.
	 */
	cid |= COMPACT_ID_COUNT_BASE - 1;
	return __builtin_clz(COMPACT_ID_COUNT_BASE) - __builtin_clz(cid) + 1;
}

void
compact_id_table_init(compact_id_table_t table)
{
	/* lck_group_init knows about what this function does */
	lck_mtx_init(&table->cidt_lock, &compact_id_lck_grp, LCK_ATTR_NULL);
}

void **
compact_id_resolve(compact_id_table_t table, compact_id_t cid)
{
	return table->cidt_array[compact_id_slab_index(cid)] + cid;
}

__attribute__((noinline))
static void
compact_id_table_grow(compact_id_table_t table, uint32_t idx)
{
	uint32_t size;

	/*
	 * Let's check if is someone is already
	 * allocating memory.
	 */
	if (table->cidt_allocator != NULL) {
		table->cidt_waiters = true;
		compact_id_table_sleep(table);
		return;
	}

	/*
	 * We need to allocate more memory.
	 * Let's unlock and notify
	 * other thread who is allocating.
	 */
	table->cidt_allocator = current_thread();
	compact_id_table_unlock(table);

	size = compact_id_slab_size(idx);
	table->cidt_bitmap[idx] = zalloc_permanent(BITMAP_SIZE(size), ZALIGN(bitmap_t));
	table->cidt_array[idx]  = zalloc_permanent(size * sizeof(thread_t), ZALIGN_PTR);
	/*
	 * Note: because we expect lookups to be common,
	 *       cidt_array isn't the real array but shifted
	 *       so that dereferencing it with the compact ID
	 *       works for any slab.
	 */
	table->cidt_array[idx] -= compact_id_prev_max(idx);
	bitmap_full(table->cidt_bitmap[idx], size);

	compact_id_table_lock(table);
	assert(table->cidt_allocator == current_thread());
	table->cidt_allocator = NULL;
	if (table->cidt_waiters) {
		table->cidt_waiters = false;
		compact_id_table_wake(table);
	}
}

compact_id_t
compact_id_get_locked(
	compact_id_table_t      table,
	compact_id_t            limit,
	void                   *value)
{
	compact_id_t cid;
	uint32_t slab_size;
	uint32_t idx = 0;
	int bit_index;

again:
	idx = compact_id_slab_index(table->cidt_first_free);
	for (; idx < COMPACT_ID_SLAB_COUNT; idx++) {
		bitmap_t *map = table->cidt_bitmap[idx];
		void    **arr = table->cidt_array[idx];

		if (arr == NULL) {
			compact_id_table_grow(table, idx);
			goto again;
		}

		slab_size = compact_id_slab_size(idx);
		bit_index = bitmap_lsb_first(map, slab_size);
		if (bit_index >= 0) {
			cid = compact_id_prev_max(idx) + bit_index;
			if (cid > limit) {
				break;
			}

			table->cidt_count++;
			table->cidt_first_free = cid + 1;
			bitmap_clear(map, bit_index);
			assert(arr[cid] == NULL);
			arr[cid] = value;
			return cid;
		}
	}

	panic("table %p ran out of compact IDs", table);
}

compact_id_t
compact_id_get(
	compact_id_table_t      table,
	compact_id_t            limit,
	void                   *value)
{
	compact_id_t cid;

	compact_id_table_lock(table);
	cid = compact_id_get_locked(table, limit, value);
	compact_id_table_unlock(table);
	return cid;
}

void *
compact_id_put(compact_id_table_t table, compact_id_t cid)
{
	uint32_t  idx = compact_id_slab_index(cid);
	bitmap_t *map = table->cidt_bitmap[idx];
	void    **arr = table->cidt_array[idx];
	void *value;

	compact_id_table_lock(table);
	value = arr[cid];
	arr[cid] = NULL;
	bitmap_set(map, cid - compact_id_prev_max(idx));
	if (cid < table->cidt_first_free) {
		table->cidt_first_free = cid;
	}
	table->cidt_count--;
	compact_id_table_unlock(table);

	return value;
}

void
compact_id_for_each(
	compact_id_table_t      table,
	uint32_t                stride,
	bool                  (^cb)(void *v))
{
	const uint64_t pause_init = stride;
	uint64_t pause = pause_init;

	compact_id_table_lock(table);
	for (uint32_t sidx = 0; sidx < COMPACT_ID_SLAB_COUNT; sidx++) {
		void    **arr = table->cidt_array[sidx];
		uint32_t  size = compact_id_slab_size(sidx);
		uint32_t  prev = compact_id_prev_max(sidx);

		if (arr == NULL) {
			break;
		}
		for (compact_id_t cid = prev; cid < prev + size; cid++) {
			if (arr[cid] == NULL) {
				continue;
			}
			if (!cb(arr[cid])) {
				break;
			}
			if (pause-- == 0) {
				compact_id_table_unlock(table);
				pause = pause_init;
				compact_id_table_lock(table);
			}
		}
	}
	compact_id_table_unlock(table);
}

void
compact_id_table_lock(compact_id_table_t table)
{
	lck_mtx_lock(&table->cidt_lock);
}

void
compact_id_table_unlock(compact_id_table_t table)
{
	lck_mtx_unlock(&table->cidt_lock);
}
