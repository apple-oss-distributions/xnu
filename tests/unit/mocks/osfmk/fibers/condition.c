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

#include "condition.h"
#include "random.h"

// Note: Unlike other fibers API, fibers_may_yield_internal_with_reason is not called before and after
// fibers_condition_* operations. It is duty of the caller to do so (see mock_thread.c).

void
fibers_condition_wakeup_one(fibers_condition_t *cond)
{
	fibers_condition_wakeup_some(cond, 1, NULL, NULL);
}

int
fibers_condition_wakeup_some(fibers_condition_t *cond, int num_fibers, void (*callback)(void *, fiber_t), void *arg)
{
	if (num_fibers < 0 || num_fibers > cond->wait_queue.count) {
		num_fibers = cond->wait_queue.count;
	}

	unsigned int num_awakened = 0;
	while (num_fibers > 0) {
		fiber_t target = fibers_queue_pop(&cond->wait_queue, random_below(cond->wait_queue.count));
		FIBERS_ASSERT(target->state == FIBER_WAIT, "fibers_condition_wakeup_some: waking up %d that is not FIBER_WAIT", target->id);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waking up %d waiting on condition %p", target->id, cond);
		if (callback) {
			callback(arg, target);
		}
		fibers_queue_push(&fibers_run_queue, target);
		--num_fibers;
		num_awakened++;
	}

	return num_fibers;
}

void
fibers_condition_wait(fibers_condition_t *cond)
{
	FIBERS_LOG(FIBERS_LOG_DEBUG, "waiting on condition %p", cond);
	FIBERS_ASSERT(fibers_current->may_yield_disabled == 0, "fibers_condition_wait: waiting on a condition with fibers_current->may_yield_disabled not 0");

	fibers_queue_push(&cond->wait_queue, fibers_current);
	fibers_choose_next(FIBER_WAIT);
}

void
fibers_condition_destroy(fibers_condition_t *cond)
{
	FIBERS_LOG(FIBERS_LOG_DEBUG, "destroy condition %p", cond);
	FIBERS_ASSERT(cond->wait_queue.count == 0, "fibers_mutex_destroy: tried to destroy condition with non empty wait queue");
}

fiber_t
fibers_condition_identify(fibers_condition_t *cond)
{
	FIBERS_LOG(FIBERS_LOG_DEBUG, "identify from wait queue of %d fibers", cond->wait_queue.count);
	if (cond->wait_queue.count == 0) {
		return NULL;
	}
	size_t index = random_below(cond->wait_queue.count);
	fiber_t iter = cond->wait_queue.top;
	while (iter != NULL) {
		if (index == 0) {
			return iter;
		}
		index--;
		iter = iter->next;
	}
	FIBERS_ASSERT(false, "fibers_condition_identify: unreachable");
	return NULL;
}

bool
fibers_condition_wakeup_identified(fibers_condition_t *cond, fiber_t target)
{
	if (!fibers_queue_remove(&cond->wait_queue, target)) {
		return false;
	}

	FIBERS_ASSERT(target->state == FIBER_WAIT, "fibers_condition_wakeup_identified: waking up %d that is not FIBER_WAIT", target->id);
	FIBERS_LOG(FIBERS_LOG_DEBUG, "waking up %d waiting on condition %p", target->id, cond);
	fibers_queue_push(&fibers_run_queue, target);

	return true;
}
