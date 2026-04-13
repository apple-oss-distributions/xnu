/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include "mocks/std_safe.h"
#include "unit_test_utils.h"
#include "fibers/fibers.h"
#include <kern/locks_internal.h>

extern int ut_mocks_use_fibers;

static struct fibers_queue mcs_queue;

T_MOCK_F(lck_mcs_node_t,
lck_mcs_enqueue, (
	lck_mcs_id_t           * link,
	lck_mcs_mode_t          mode,
	void                   *lock,
	hw_spin_policy_t        pol), (link, mode, lock, pol))
{
	if (ut_mocks_use_fibers) {
		fibers_queue_push(&mcs_queue, fibers_current);
		if (fibers_queue_peek(&mcs_queue) != fibers_current) {
			fibers_choose_next(FIBER_WAIT);
		}
		return NULL;
	} else {
		return lck_mcs_enqueue(link, mode, lock, pol);
	}
}

T_MOCK_F(void,
lck_mcs_dequeue, (
	lck_mcs_node_t node,
	lck_mcs_id_t *link,
	lck_mcs_mode_t mode), (node, link, mode))
{
	if (ut_mocks_use_fibers) {
		fiber_t removed = fibers_queue_peek(&mcs_queue);
		FIBERS_ASSERT(removed == fibers_current, "lck_mcs_dequeue: expected that the thread dequeuing was the top of the mcs queue");
		fibers_queue_pop(&mcs_queue, fibers_queue_count(&mcs_queue) - 1);
		fiber_t awakened = fibers_queue_peek(&mcs_queue);
		if (awakened) {
			FIBERS_ASSERT(awakened->state == FIBER_WAIT, "lck_mcs_dequeue: new holder %d is not FIBER_WAIT", awakened->id);
			fibers_queue_push(&fibers_run_queue, awakened);
			fibers_may_yield_internal();
		}
	} else {
		return lck_mcs_dequeue(node, link, mode);
	}
}
