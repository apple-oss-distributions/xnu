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

#include "mutex.h"
#include "random.h"

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/signal.h>

#ifdef __BUILDING_WITH_TSAN__
#include <sanitizer/tsan_interface.h>
#endif

void
fibers_mutex_init(fibers_mutex_t *mtx)
{
	mtx->holder = 0;
	mtx->wait_queue = (struct fibers_queue){0, 0};
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_create(mtx, __tsan_mutex_not_static);
#endif
}

static void
fibers_mutex_lock_helper(fibers_mutex_t *mtx, bool check_may_yield)
{
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_lock(mtx, 0);
#endif

	if (mtx->holder) {
		FIBERS_ASSERT(mtx->holder != fibers_current, "fibers_mutex_lock_helper: tried to lock mutex already held by %d", mtx->holder->id);
		// TODO rdar://150846598 add support for recursive locks
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waiting on mutex %p locked by %d", mtx, mtx->holder->id);
		if (check_may_yield) {
			// check for mutexes but not spinlocks
			FIBERS_ASSERT(fibers_current->may_yield_disabled == 0, "fibers_mutex_lock_helper: waiting on a mutex with fibers_current->may_yield_disabled not 0");
		}

		fibers_queue_push(&mtx->wait_queue, fibers_current);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_pre_divert(mtx, 0);
#endif
		fibers_choose_next(FIBER_WAIT);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_divert(mtx, 0);
#endif
		FIBERS_ASSERT(mtx->holder == fibers_current, "fibers_mutex_lock_helper: waken up without being the holder of %p", mtx);
	} else {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "locking mutex %p", mtx);
		mtx->holder = fibers_current;
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_lock(mtx, 0, 0);
#endif

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_LOCK);
}

static void
fibers_mutex_unlock_helper(fibers_mutex_t *mtx, bool fifo)
{
	FIBERS_ASSERT(mtx->holder == fibers_current, "fibers_mutex_unlock_helper: tried to unlock mutex held by %d", mtx->holder ? mtx->holder->id : -1);
	FIBERS_LOG(FIBERS_LOG_DEBUG, "unlocking mutex %p", mtx);

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_unlock(mtx, 0);
#endif

	mtx->holder = NULL;

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_unlock(mtx, 0);
#endif

	if (mtx->wait_queue.count) {
		fiber_t new_holder = fibers_queue_pop(&mtx->wait_queue, fifo ? 0 : random_below(mtx->wait_queue.count));
		FIBERS_ASSERT(new_holder->state == FIBER_WAIT, "fibers_mutex_unlock_helper: new holder %d is not FIBER_WAIT", new_holder->id);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waking up %d waiting on mutex %p", new_holder->id, mtx);
		mtx->holder = new_holder;

		fibers_queue_push(&fibers_run_queue, new_holder);
	}

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

static int
fibers_mutex_try_lock_helper(fibers_mutex_t *mtx)
{
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_lock(mtx, __tsan_mutex_try_lock);
#endif

	if (mtx->holder) {
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_lock(mtx, __tsan_mutex_try_lock | __tsan_mutex_try_lock_failed, 0);
#endif
		return EBUSY;
	} else {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "locking mutex %p", mtx);
		mtx->holder = fibers_current;
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_lock(mtx, __tsan_mutex_try_lock, 0);
#endif
	return 0;
}

void
fibers_mutex_lock(fibers_mutex_t *mtx, bool check_may_yield)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);
	fibers_mutex_lock_helper(mtx, check_may_yield);
}

void
fibers_mutex_unlock(fibers_mutex_t *mtx)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);
	fibers_mutex_unlock_helper(mtx, false);
}

void
fibers_mutex_unlock_fifo(fibers_mutex_t *mtx)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);
	fibers_mutex_unlock_helper(mtx, true);
}

int
fibers_mutex_try_lock(fibers_mutex_t *mtx)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);
	int err = fibers_mutex_try_lock_helper(mtx);
	fibers_may_yield_internal_with_reason(err == 0 ? FIBERS_YIELD_REASON_MUTEX_DID_LOCK : FIBERS_YIELD_REASON_MUTEX_TRY_LOCK_FAIL);
	return err;
}

void
fibers_mutex_destroy(fibers_mutex_t *mtx)
{
	FIBERS_ASSERT(mtx->holder == NULL, "fibers_mutex_destroy: tried to destroy mutex held by %d", mtx->holder->id);
	FIBERS_ASSERT(mtx->wait_queue.count == 0, "fibers_mutex_destroy: tried to destroy mutex with non empty wait queue");

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_destroy(mtx, __tsan_mutex_not_static);
#endif

	fibers_may_yield_internal();
}
