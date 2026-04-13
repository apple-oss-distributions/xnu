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

#include <stdint.h>

#include <os/atomic_private.h>
#include <kern/processor.h>

#include <kern/sched_common.h>

SECURITY_READ_ONLY_LATE(uint8_t) sched_num_psets = UINT8_MAX;
static_assert(MAX_PSETS < UINT8_MAX, "UINT8_MAX is used as a sentinel to indicate sched_num_psets is not initialized.");

#if __AMP__

void
sched_pset_search_order_compute(sched_pset_search_order_t *search_order_out,
    sched_pset_search_order_sort_data_t *datas, size_t num_datas,
    sched_pset_search_order_sort_cmpfunc_t cmp)
{
	qsort(datas, num_datas, sizeof(sched_pset_search_order_sort_data_t), cmp);
	sched_pset_search_order_t search_order;
	for (int i = 0; i < num_datas; i++) {
		search_order.spso_search_order[i] = datas[i].spsosd_dst_pset_id;
	}
	for (int i = (int)num_datas; i < sched_num_psets - 1; i++) {
		/*
		 * If fewer sort datas were passed in than the number of psets minus
		 * 1 (AKA the maximum length of a pset search order), then mark the
		 * remaining slots at the end with an invalid pset id.
		 */
		search_order.spso_search_order[i] = PSET_ID_INVALID;
	}
	os_atomic_store_wide(&search_order_out->spso_packed, search_order.spso_packed, relaxed);
}

static bool
sched_iterate_psets_ordered_reversed(processor_set_t starting_pset,
    uint64_t candidate_map, sched_pset_iterate_state_t *istate)
{
	assert3u(istate->spis_options, &, SCHED_PSET_ITERATE_STATE_OPTIONS_REVERSE);
	while ((istate->spis_search_index < sched_num_psets)) {
		int pset_id;
		if (istate->spis_search_index == -1) {
			/* In case search order does not include all psets, count how many it does have. */
			istate->spis_valid_len = 0;
			while ((istate->spis_cached_search_order.spso_search_order[istate->spis_valid_len] != PSET_ID_INVALID)
			    && (istate->spis_valid_len <= (sched_num_psets - 2))) {
				istate->spis_valid_len++;
			}
			istate->spis_search_index = 0;
		}
		if (istate->spis_search_index > istate->spis_valid_len) {
			return false;
		} else if (istate->spis_search_index == istate->spis_valid_len) {
			/* Return starting_pset last */
			pset_id = starting_pset->pset_id;
		} else {
			int index = istate->spis_valid_len - 1 - istate->spis_search_index;
			assert3s(index, >=, 0);
			pset_id = istate->spis_cached_search_order.spso_search_order[index];
			assert3s(pset_id, !=, PSET_ID_INVALID);
			assert3u(pset_id, !=, starting_pset->pset_id);
		}
		istate->spis_search_index++;
		if (bit_test(candidate_map, pset_id)) {
			istate->spis_pset_id = (pset_id_t)pset_id;
			return true;
		}
	}
	istate->spis_pset_id = PSET_ID_INVALID;
	return false;
}

bool
sched_iterate_psets_ordered(processor_set_t starting_pset, sched_pset_search_order_t *search_order,
    uint64_t candidate_map, sched_pset_iterate_state_t *istate)
{
	if (candidate_map == 0) {
		istate->spis_pset_id = PSET_ID_INVALID;
		return false;
	}
	if (istate->spis_search_index == -1) {
		istate->spis_cached_search_order =
		    (sched_pset_search_order_t)os_atomic_load_wide(&search_order->spso_packed, relaxed);
	}
	bool reverse = (istate->spis_options & SCHED_PSET_ITERATE_STATE_OPTIONS_REVERSE);
	if (reverse) {
		return sched_iterate_psets_ordered_reversed(starting_pset, candidate_map, istate);
	} else {
		while (istate->spis_search_index < sched_num_psets - 1) {
			int pset_id;
			if (istate->spis_search_index == -1) {
				pset_id = starting_pset->pset_id;
			} else {
				int index = istate->spis_search_index;
				assert3s(index, >=, 0);
				pset_id = istate->spis_cached_search_order.spso_search_order[index];
				if (pset_id == PSET_ID_INVALID) {
					/* The given search order does not include all psets */
					break;
				}
				assert3u(pset_id, !=, starting_pset->pset_id);
			}
			istate->spis_search_index++;
			if (bit_test(candidate_map, pset_id)) {
				istate->spis_pset_id = (pset_id_t)pset_id;
				return true;
			}
		}
		istate->spis_pset_id = PSET_ID_INVALID;
		return false;
	}
}

bool
sched_is_standard_topology(void)
{
	extern bool cpu_config_modified;
	return !cpu_config_modified;
}

#endif /* __AMP__ */
