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

#ifndef _KERN_COMPACT_ID_H_
#define _KERN_COMPACT_ID_H_

#include <stdbool.h>
#include <stdint.h>
#include <kern/bits.h>
#include <kern/startup.h>
#include <kern/locks.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

#define COMPACT_ID_SHIFT_BASE     (10)
#define COMPACT_ID_COUNT_BASE     (1u << COMPACT_ID_SHIFT_BASE)
#define COMPACT_ID_SLAB_COUNT     (12)
#define COMPACT_ID_MAX            ((COMPACT_ID_COUNT_BASE << (COMPACT_ID_SLAB_COUNT - 1)) - 1u)

typedef uint32_t                  compact_id_t;
typedef struct compact_id_table  *compact_id_table_t;

/*
 * @struct compact_id_table
 *
 * @discussion
 * A compact ID table contains an array of COMPACT_ID_SLAB_COUNT
 * compact_id_slab slabs.
 *
 * Each slab contains a different number of values, depending on its position
 * within the cidt_slabs.
 *
 * The entries in the table are never deallocated once created,
 * which allows to access the table without holding a lock.
 *
 * Slots within each slab can be re-used once an association
 * with a prior value has been released.
 *
 * The first 2 entries will have COMPACT_ID_COUNT_BASE entries,
 * all others will have size COMPACT_ID_COUNT_BASE * 2^(index - 1).
 *
 * |BASE|BASE|2BASE|4BASE|...|2^(MAX-2)BASE|
 *   0    1     2     3          MAX-1
 *
 * This can allow a maximum capacity of BASE(2^(MAX-1)) values
 *
 * Because COMPACT_ID_COUNT_BASE is a power of 2, it lets us
 * lookup into the tables very efficiently: each table slab
 * contains all the compact IDs between subsequent power of 2
 * of COMPACT_ID_COUNT_BASE.
 *
 * |0 -> (B-1)|B -> (2B-1)|2B -> (4B-1)|...|2^(MAX-2)B -> ((2^(MAX-1)B)-1)|
 *      0          1            2                        MAX-1
 *
 * By observing the most significant bit of a given compact ID,
 * we can compute its slab index very efficiently:
 *
 * slab_index = clz(COMPACT_ID_COUNT_BASE) - clz(ctid | (COMPACT_ID_COUNT_BASE - 1)) + 1
 *
 * Note: because we expect lookups to be common,
 *       cidt_array isn't the real array but shifted
 *       so that dereferencing it with the compact ID
 *       works for any slab.
 */
struct compact_id_table {
	/*
	 * slabs first saves one instruction per compact_id_resolve()
	 */
	void                  **cidt_array[COMPACT_ID_SLAB_COUNT];
	bitmap_t               *cidt_bitmap[COMPACT_ID_SLAB_COUNT];
	lck_mtx_t               cidt_lock;
	struct thread          *cidt_allocator;
	bool                    cidt_waiters;
	uint32_t                cidt_count;
	compact_id_t            cidt_first_free;
};

extern void compact_id_table_init(
	compact_id_table_t      table);

extern void **compact_id_resolve(
	compact_id_table_t      table,
	compact_id_t            compact_id) __pure2;

extern compact_id_t compact_id_get_locked(
	compact_id_table_t      table,
	compact_id_t            limit,
	void                   *value);

extern compact_id_t compact_id_get(
	compact_id_table_t      table,
	compact_id_t            limit,
	void                   *value);

extern void *compact_id_put(
	compact_id_table_t      table,
	compact_id_t            compact_id);

extern void compact_id_for_each(
	compact_id_table_t      table,
	uint32_t                stride,
	bool                  (^cb)(void *v));

extern void compact_id_table_lock(
	compact_id_table_t      table);

extern void compact_id_table_unlock(
	compact_id_table_t      table);

#define COMPACT_ID_TABLE_DEFINE(class, var) \
	static void *var##_array0[COMPACT_ID_COUNT_BASE];                       \
	static bitmap_t var##_bits0[BITMAP_LEN(COMPACT_ID_COUNT_BASE)] = {      \
	        [0 ... BITMAP_LEN(COMPACT_ID_COUNT_BASE) - 1] = ~0ull,          \
	};                                                                      \
	class struct compact_id_table var = {                                   \
	        .cidt_bitmap[0] = var##_bits0,                                  \
	        .cidt_array[0]  = var##_array0,                                 \
	};                                                                      \
	STARTUP_ARG(LOCKS, STARTUP_RANK_THIRD, compact_id_table_init, &var)

#pragma GCC visibility pop
__END_DECLS

#endif /* _KERN_COMPACT_ID_H_ */
