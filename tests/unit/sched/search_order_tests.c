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

#include <darwintest.h>
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/sched_common.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.scheduler.unit"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("m_zinn"),
	T_META_RUN_CONCURRENTLY(false)
	);


T_DECL(empty_search_order, "test iteration over an empty search order")
{
	struct processor_set starting_pset = {
		.pset_id = 0,
	};

	sched_pset_search_order_t order = SCHED_PSET_SEARCH_ORDER_INIT;
	uint64_t candidate_map = 0b1;

	/* Forward iteration. */
	{
		sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;

		T_ASSERT_TRUE(sched_iterate_psets_ordered(&starting_pset, &order, candidate_map, &istate), "Forward iteration should succeed on the first call.");
		T_ASSERT_EQ(istate.spis_pset_id, 0, "First visited pset should be the starting pset.");

		T_ASSERT_FALSE(sched_iterate_psets_ordered(&starting_pset, &order, candidate_map, &istate), "Forward iteration should stop on the second call.");
	}

	/* Reverse iteration. */
	{
		sched_pset_iterate_state_t istate = SCHED_PSET_ITERATE_STATE_INIT;
		istate.spis_options = SCHED_PSET_ITERATE_STATE_OPTIONS_REVERSE;

		T_ASSERT_TRUE(sched_iterate_psets_ordered(&starting_pset, &order, candidate_map, &istate), "Reverse iteration should succeed on the first call.");
		T_ASSERT_EQ(istate.spis_pset_id, 0, "First visited pset should be the starting pset.");

		T_ASSERT_FALSE(sched_iterate_psets_ordered(&starting_pset, &order, candidate_map, &istate), "Reverse iteration should stop on the second call.");
	}
}
