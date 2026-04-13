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

#ifndef _KERN_SCHED_COMMON_H_
#define _KERN_SCHED_COMMON_H_

#include <stdint.h>

#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/qsort.h>
#include <kern/smp.h>

/* How many psets the system is configured to use. Only values less than
 * sched_num_psets are considered valid pset IDs. */
extern uint8_t sched_num_psets;

#if __AMP__

/*
 * sched_pset_search_order_t
 *
 * Used for storing a computed search order of pset ids, relative to a
 * scanning pset not included in the list.
 *
 * Storing/accessing the search order atomically avoids issues caused
 * by editing the search order while processors are in the middle of
 * traversing it, for example causing them to miss a pset or visit a
 * particular pset more than once. Instead, the search order should be
 * read atomically before traversing, so that new edits are ignored by
 * that processor until its traversal is complete.
 */
typedef union {
	pset_id_t spso_search_order[MAX_PSETS - 1];
	unsigned __int128 spso_packed;
} sched_pset_search_order_t;

static_assert(sizeof(sched_pset_search_order_t) <= sizeof(unsigned __int128),
    "(MAX_PSETS - 1) * 8 bits fits in 128 bits, allowing sched_pset_search_order_t fields "
    "to be accessed atomically");

typedef struct processor_set *processor_set_t;

/*
 * sched_pset_search_order_sort_data_t
 *
 * Pset data used when generating search orders, expected to be
 * populated for each pset before calling sched_pset_search_order_compute()
 */
typedef struct {
	processor_set_t spsosd_src_pset;
	uint64_t spsosd_migration_weight;
	pset_id_t spsosd_dst_pset_id;
} sched_pset_search_order_sort_data_t;

/*
 * sched_pset_search_order_sort_cmpfunc_t
 *
 * Expected to compare two sched_pset_search_order_sort_data_t pointers,
 * for the purpose of generating a pset search order.
 */
typedef cmpfunc_t sched_pset_search_order_sort_cmpfunc_t;

/*
 * sched_pset_search_order_compute()
 *
 * Generates a pset search order by sorting the per-pset search order datas
 * using the given comparator.
 */
void
sched_pset_search_order_compute(sched_pset_search_order_t *search_order_out,
    sched_pset_search_order_sort_data_t *datas, size_t num_datas,
    sched_pset_search_order_sort_cmpfunc_t cmp);

/* Represents an empty search order; used in early boot. */
#define SCHED_PSET_SEARCH_ORDER_INIT ((sched_pset_search_order_t) \
	{ .spso_search_order = {PSET_ID_INVALID}})

/* Options specifying how to iterate the search order */
__options_decl(sched_pset_iterate_state_options_t, uint32_t, {
	SCHED_PSET_ITERATE_STATE_OPTIONS_NONE      = 0x0,
	SCHED_PSET_ITERATE_STATE_OPTIONS_REVERSE   = 0x1,
});

/*
 * sched_pset_iterate_state_t
 *
 * Used for tracking state across calls to sched_iterate_psets_ordered()
 * for the same search order traversal, and for returning the current pset_id.
 */
typedef struct {
	int spis_search_index;
	sched_pset_search_order_t spis_cached_search_order;
	pset_id_t spis_pset_id; // out
	sched_pset_iterate_state_options_t spis_options; // in
	int spis_valid_len;
} sched_pset_iterate_state_t;

#define SCHED_PSET_ITERATE_STATE_INIT ((sched_pset_iterate_state_t) \
    { .spis_search_index = -1, .spis_options = SCHED_PSET_ITERATE_STATE_OPTIONS_NONE })

/*
 * sched_iterate_psets_ordered()
 *
 * Routine to iterate through candidate psets based on a given search_order
 * and starting from starting_pset.
 * Returns true if iteration continues and another candidate pset was found,
 * which will be stored at istate->spis_pset_id. Returns false and
 * istate->spis_pset_id of -1 once iteration is complete. Iterate state should
 * start out initialized to SCHED_PSET_ITERATE_STATE_INIT.
 */
bool
sched_iterate_psets_ordered(processor_set_t starting_pset, sched_pset_search_order_t *search_order,
    uint64_t candidate_map, sched_pset_iterate_state_t *istate);

/*
 * sched_is_standard_topology()
 *
 * Returns whether the scheduler topology matches the device tree (i.e., the CPU
 * config has not been modified).
 */
bool
sched_is_standard_topology(void);

#endif /* __AMP__ */

#endif /* _KERN_SCHED_COMMON_H_ */
