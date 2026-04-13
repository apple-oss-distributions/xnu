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

#include "rwlock.h"
#include "random.h"

#include <sys/errno.h>
#include <sys/types.h>

#ifdef __BUILDING_WITH_TSAN__
#include <sanitizer/tsan_interface.h>
#endif

void
fibers_rwlock_init(fibers_rwlock_t *rwlock)
{
	rwlock->writer_active = NULL;
	rwlock->reader_count = 0;
	rwlock->reader_wait_queue = (struct fibers_queue){0, 0};
	rwlock->writer_wait_queue = (struct fibers_queue){0, 0};

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_create(rwlock, __tsan_mutex_not_static);
#endif
}

static void
fibers_rwlock_rdlock_helper(fibers_rwlock_t *rwlock, bool check_may_yield)
{
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_lock(rwlock, __tsan_mutex_read_lock);
#endif

	// stop a reader if there are writers waiting (RANGELOCKINGTODO rdar://150845975 use the PRNG to choose?)
	if (rwlock->writer_active != NULL || rwlock->writer_wait_queue.count > 0) {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waiting for read lock %p (writer %p active, %d writers waiting)",
		    rwlock, rwlock->writer_active, rwlock->writer_wait_queue.count);
		if (check_may_yield) {
			FIBERS_ASSERT(fibers_current->may_yield_disabled == 0, "fibers_rwlock_rdlock_helper: waiting on rwlock with fibers_current->may_yield_disabled not 0");
		}

		fibers_queue_push(&rwlock->reader_wait_queue, fibers_current);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_pre_divert(rwlock, 0);
#endif
		fibers_choose_next(FIBER_WAIT);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_divert(rwlock, 0);
#endif
		FIBERS_ASSERT(rwlock->writer_active == NULL, "fibers_rwlock_rdlock_helper: woken up while writer %d still active", rwlock->writer_active ? rwlock->writer_active->id : -1);
	} else {
		rwlock->reader_count++;
		FIBERS_LOG(FIBERS_LOG_DEBUG, "acquired read lock %p (now %u readers)", rwlock, rwlock->reader_count);
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_lock(rwlock, __tsan_mutex_read_lock, 0);
#endif

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_LOCK);
}

static int
fibers_rwlock_try_rdlock_helper(fibers_rwlock_t *rwlock)
{
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_lock(rwlock, __tsan_mutex_try_read_lock);
#endif

	if (rwlock->writer_active != NULL || rwlock->writer_wait_queue.count > 0) {
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_lock(rwlock, __tsan_mutex_try_read_lock | __tsan_mutex_try_read_lock_failed, 0);
#endif
		return EBUSY;
	} else {
		rwlock->reader_count++;
		FIBERS_LOG(FIBERS_LOG_DEBUG, "try acquired read lock %p (now %u readers)", rwlock, rwlock->reader_count);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_lock(rwlock, __tsan_mutex_try_read_lock, 0);
#endif
		return 0;
	}
}

static void
fibers_rwlock_wrlock_helper(fibers_rwlock_t *rwlock, bool check_may_yield)
{
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_lock(rwlock, 0);
#endif

	if (rwlock->writer_active != NULL || rwlock->reader_count > 0) {
		FIBERS_ASSERT(rwlock->writer_active != fibers_current, "fibers_rwlock_wrlock_helper: recursive write lock attempted by %d", fibers_current->id);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waiting for write lock %p (writer %p active, %u readers active)",
		    rwlock, rwlock->writer_active, rwlock->reader_count);
		if (check_may_yield) {
			FIBERS_ASSERT(fibers_current->may_yield_disabled == 0, "fibers_rwlock_wrlock_helper: waiting on rwlock with fibers_current->may_yield_disabled not 0");
		}

		fibers_queue_push(&rwlock->writer_wait_queue, fibers_current);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_pre_divert(rwlock, 0);
#endif
		fibers_choose_next(FIBER_WAIT);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_divert(rwlock, 0);
#endif
		FIBERS_ASSERT(rwlock->writer_active == fibers_current, "fibers_rwlock_wrlock_helper: woken up but not writer holder (%p != %p)", rwlock->writer_active, fibers_current);
		FIBERS_ASSERT(rwlock->reader_count == 0, "fibers_rwlock_wrlock_helper: woken up as writer but %u readers still active?", rwlock->reader_count);
	} else {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "acquired write lock %p", rwlock);
		rwlock->writer_active = fibers_current;
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_lock(rwlock, 0, 0);
#endif

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_LOCK);
}

static int
fibers_rwlock_try_wrlock_helper(fibers_rwlock_t *rwlock)
{
#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_lock(rwlock, __tsan_mutex_try_lock);
#endif

	if (rwlock->writer_active != NULL || rwlock->reader_count > 0) {
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_lock(rwlock, __tsan_mutex_try_lock | __tsan_mutex_try_lock_failed, 0);
#endif
		return EBUSY;
	} else {
		// Acquire write lock
		FIBERS_LOG(FIBERS_LOG_DEBUG, "try acquired write lock %p", rwlock);
		rwlock->writer_active = fibers_current;
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_lock(rwlock, __tsan_mutex_try_lock, 0);
#endif
		return 0;
	}
}

static void
fibers_rwlock_rdunlock_helper(fibers_rwlock_t *rwlock)
{
	FIBERS_ASSERT(rwlock->writer_active == NULL, "fibers_rwlock_rdunlock_helper: trying to read-unlock while writer %d active", rwlock->writer_active ? rwlock->writer_active->id : -1);
	FIBERS_ASSERT(rwlock->reader_count > 0, "fibers_rwlock_rdunlock_helper: trying to read-unlock with zero readers");

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_unlock(rwlock, __tsan_mutex_read_lock);
#endif

	rwlock->reader_count--;
	FIBERS_LOG(FIBERS_LOG_DEBUG, "released read lock %p (readers remaining %u)", rwlock, rwlock->reader_count);

	// if last reader out and writers are waiting, wake one writer
	if (rwlock->reader_count == 0 && rwlock->writer_wait_queue.count > 0) {
		fiber_t new_writer = fibers_queue_pop(&rwlock->writer_wait_queue, random_below(rwlock->writer_wait_queue.count));
		FIBERS_ASSERT(new_writer->state == FIBER_WAIT, "fibers_rwlock_rdunlock_helper: woken writer %d is not FIBER_WAIT", new_writer->id);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waking up writer %d waiting on rwlock %p", new_writer->id, rwlock);
		rwlock->writer_active = new_writer;

		fibers_queue_push(&fibers_run_queue, new_writer);
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_unlock(rwlock, __tsan_mutex_read_lock);
#endif

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

static void
fibers_rwlock_wrunlock_helper(fibers_rwlock_t *rwlock)
{
	FIBERS_ASSERT(rwlock->writer_active == fibers_current, "fibers_rwlock_wrunlock_helper: trying to write-unlock lock not held by current fiber %d (holder %d)", fibers_current->id, rwlock->writer_active ? rwlock->writer_active->id : -1);
	FIBERS_ASSERT(rwlock->reader_count == 0, "fibers_rwlock_wrunlock_helper: trying to write-unlock while %u readers active?", rwlock->reader_count);

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_unlock(rwlock, 0);
#endif

	FIBERS_LOG(FIBERS_LOG_DEBUG, "releasing write lock %p", rwlock);
	rwlock->writer_active = NULL;

	if (rwlock->writer_wait_queue.count > 0) {
		fiber_t new_writer = fibers_queue_pop(&rwlock->writer_wait_queue, random_below(rwlock->writer_wait_queue.count));
		FIBERS_ASSERT(new_writer->state == FIBER_WAIT, "fibers_rwlock_wrunlock_helper: woken writer %d is not FIBER_WAIT", new_writer->id);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waking up writer %d waiting on rwlock %p", new_writer->id, rwlock);
		rwlock->writer_active = new_writer;

		fibers_queue_push(&fibers_run_queue, new_writer);
	} else if (rwlock->reader_wait_queue.count > 0) {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "waking up %d readers waiting on rwlock %p", rwlock->reader_wait_queue.count, rwlock);

		unsigned int initial_count = rwlock->reader_wait_queue.count;
		while (rwlock->reader_wait_queue.count > 0) {
			fiber_t new_reader = fibers_queue_pop(&rwlock->reader_wait_queue, random_below(rwlock->reader_wait_queue.count));
			FIBERS_ASSERT(new_reader->state == FIBER_WAIT, "fibers_rwlock_wrunlock_helper: woken reader %d is not FIBER_WAIT", new_reader->id);
			rwlock->reader_count++;

			fibers_queue_push(&fibers_run_queue, new_reader);
		}
		FIBERS_ASSERT(rwlock->reader_count == initial_count, "fibers_rwlock_wrunlock_helper: reader count mismatch after waking readers (%u != %u)", rwlock->reader_count, initial_count);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "rwlock %p now held by %u readers", rwlock, rwlock->reader_count);
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_unlock(rwlock, 0);
#endif

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

void
fibers_rwlock_rdlock(fibers_rwlock_t *rwlock, bool check_may_yield)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);
	fibers_rwlock_rdlock_helper(rwlock, check_may_yield);
}

void
fibers_rwlock_wrlock(fibers_rwlock_t *rwlock, bool check_may_yield)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);
	fibers_rwlock_wrlock_helper(rwlock, check_may_yield);
}

int
fibers_rwlock_try_rdlock(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);
	int err = fibers_rwlock_try_rdlock_helper(rwlock);
	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_MUTEX |
		FIBERS_YIELD_REASON_ERROR_IF(err != 0));
	return err;
}

int
fibers_rwlock_try_wrlock(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);
	int err = fibers_rwlock_try_wrlock_helper(rwlock);
	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_MUTEX |
		FIBERS_YIELD_REASON_ERROR_IF(err != 0));
	return err;
}

void
fibers_rwlock_rdunlock(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);
	fibers_rwlock_rdunlock_helper(rwlock);
}

void
fibers_rwlock_wrunlock(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);
	fibers_rwlock_wrunlock_helper(rwlock);
}

void
fibers_rwlock_unlock(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);
	if (rwlock->writer_active) {
		fibers_rwlock_wrunlock_helper(rwlock);
	} else {
		fibers_rwlock_rdunlock_helper(rwlock);
	}
}

void
fibers_rwlock_destroy(fibers_rwlock_t *rwlock)
{
	FIBERS_ASSERT(rwlock->writer_active == NULL, "fibers_rwlock_destroy: tried to destroy rwlock with active writer %d", rwlock->writer_active ? rwlock->writer_active->id : -1);
	FIBERS_ASSERT(rwlock->reader_count == 0, "fibers_rwlock_destroy: tried to destroy rwlock with %u active readers", rwlock->reader_count);
	FIBERS_ASSERT(rwlock->reader_wait_queue.count == 0, "fibers_rwlock_destroy: tried to destroy rwlock with %d waiting readers", rwlock->reader_wait_queue.count);
	FIBERS_ASSERT(rwlock->writer_wait_queue.count == 0, "fibers_rwlock_destroy: tried to destroy rwlock with %d waiting writers", rwlock->writer_wait_queue.count);

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_destroy(rwlock, __tsan_mutex_not_static);
#endif

	fibers_may_yield_internal_with_reason(
		FIBERS_YIELD_REASON_MUTEX |
		FIBERS_YIELD_REASON_MUTEX_DESTROY |
		FIBERS_YIELD_REASON_ORDER_POST);
}

bool
fibers_rwlock_upgrade(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_with_prob(FIBERS_INTERNAL_YIELD_PROB);

	FIBERS_ASSERT(rwlock->writer_active == NULL, "fibers_rwlock_upgrade: trying to upgrade lock while writer %d active", rwlock->writer_active ? rwlock->writer_active->id : -1);
	FIBERS_ASSERT(rwlock->reader_count > 0, "fibers_rwlock_upgrade: trying to upgrade with zero readers");

	// if another fiber want to upgrade fail, release the lock and bail out
	if (rwlock->flags & FIBERS_RWLOCK_WANT_UPGRADE) {
		fibers_rwlock_rdunlock_helper(rwlock);
		return false;
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_unlock(rwlock, __tsan_mutex_read_lock);
#endif

	// mark that we want to upgrade and we arrived here first
	rwlock->flags |= FIBERS_RWLOCK_WANT_UPGRADE;
	rwlock->reader_count--;

	// wait for the other readers to finish
	if (rwlock->reader_count > 0) {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "fibers_rwlock_upgrade: waiting for remaining readers (%u) to finish on rwlock %p", rwlock->reader_count, rwlock);

		fibers_queue_push(&rwlock->writer_wait_queue, fibers_current);

#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_pre_divert(rwlock, 0);
#endif
		fibers_choose_next(FIBER_WAIT);
#ifdef __BUILDING_WITH_TSAN__
		__tsan_mutex_post_divert(rwlock, 0);
#endif

		// when we wake up, we should be the only ones holding the lock.
		FIBERS_ASSERT(rwlock->writer_active == fibers_current, "fibers_rwlock_upgrade: woken up but not writer holder (%p != %p)", rwlock->writer_active, fibers_current);
		FIBERS_ASSERT(rwlock->reader_count == 0, "fibers_rwlock_upgrade: woken up as writer but %u readers still active?", rwlock->reader_count);
	} else {
		// we were the only reader, so we can immediately become the writer.
		FIBERS_LOG(FIBERS_LOG_DEBUG, "fibers_rwlock_upgrade: no other readers, acquiring write lock %p", rwlock);
		rwlock->writer_active = fibers_current;
	}

	rwlock->flags &= ~FIBERS_RWLOCK_WANT_UPGRADE;

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_unlock(rwlock, __tsan_mutex_read_lock);
	__tsan_mutex_pre_lock(rwlock, 0);
	__tsan_mutex_post_lock(rwlock, 0, 0);
#endif
	fibers_may_yield_with_prob(FIBERS_INTERNAL_YIELD_PROB);

	return true;
}

void
fibers_rwlock_downgrade(fibers_rwlock_t *rwlock)
{
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);

	FIBERS_ASSERT(rwlock->writer_active == fibers_current, "fibers_rwlock_downgrade: trying to downgrade lock not held exclusively by current fiber %d (holder %d)", fibers_current->id, rwlock->writer_active ? rwlock->writer_active->id : -1);
	FIBERS_ASSERT(rwlock->reader_count == 0, "fibers_rwlock_downgrade: trying to downgrade while %u readers unexpectedly active?", rwlock->reader_count);

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_pre_unlock(rwlock, 0);
#endif

	FIBERS_LOG(FIBERS_LOG_DEBUG, "downgrading write lock %p to read lock", rwlock);

	// release the write hold, acquire a read hold for the current fiber
	rwlock->writer_active = NULL;
	rwlock->reader_count = 1;

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_unlock(rwlock, 0);
	__tsan_mutex_pre_lock(rwlock, __tsan_mutex_read_lock);
#endif

	if (rwlock->reader_wait_queue.count > 0) {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "downgrade: waking up %d readers waiting on rwlock %p", rwlock->reader_wait_queue.count, rwlock);
		unsigned int initial_woken_count = rwlock->reader_wait_queue.count;
		unsigned int readers_woken = 0;
		while (rwlock->reader_wait_queue.count > 0) {
			fiber_t new_reader = fibers_queue_pop(&rwlock->reader_wait_queue, random_below(rwlock->reader_wait_queue.count));
			FIBERS_ASSERT(new_reader->state == FIBER_WAIT, "fibers_rwlock_downgrade: woken reader %d is not FIBER_WAIT", new_reader->id);
			rwlock->reader_count++;
			readers_woken++;
			fibers_queue_push(&fibers_run_queue, new_reader);
			// TSan: Each woken reader will execute its post_lock upon resuming.
		}
		FIBERS_ASSERT(readers_woken == initial_woken_count, "fibers_rwlock_downgrade: reader wakeup count mismatch (%u != %u)", readers_woken, initial_woken_count);
		FIBERS_LOG(FIBERS_LOG_DEBUG, "rwlock %p now held by %u readers after downgrade", rwlock, rwlock->reader_count);
	} else {
		FIBERS_LOG(FIBERS_LOG_DEBUG, "rwlock %p now held by 1 reader (self) after downgrade", rwlock);
	}

#ifdef __BUILDING_WITH_TSAN__
	__tsan_mutex_post_lock(rwlock, __tsan_mutex_read_lock, 0);
#endif

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

void
fibers_rwlock_assert(fibers_rwlock_t *rwlock, unsigned int type)
{
	fiber_t current = fibers_current;
	bool condition_met = false;
	const char *fail_msg = "Unknown assertion failure";

	switch (type) {
	case FIBERS_RWLOCK_ASSERT_SHARED:
		if (rwlock->reader_count > 0 && rwlock->writer_active == NULL) {
			condition_met = true;
		} else {
			fail_msg = "Lock not held in shared mode";
		}
		break;

	case FIBERS_RWLOCK_ASSERT_EXCLUSIVE:
		if (rwlock->writer_active == current && rwlock->reader_count == 0) {
			condition_met = true;
		} else {
			fail_msg = "Lock not held exclusively by current fiber";
		}
		break;

	case FIBERS_RWLOCK_ASSERT_HELD:
		if ((rwlock->reader_count > 0 && rwlock->writer_active == NULL) ||
		    (rwlock->writer_active == current && rwlock->reader_count == 0)) {
			condition_met = true;
		} else {
			fail_msg = "Lock not held by current fiber (exclusively) or any fiber (shared)";
		}
		break;

	case FIBERS_RWLOCK_ASSERT_NOTHELD:
		if (rwlock->reader_count == 0 && rwlock->writer_active == NULL) {
			condition_met = true;
		} else {
			fail_msg = "Lock is held";
		}
		break;

	case FIBERS_RWLOCK_ASSERT_NOT_OWNED:
		if (rwlock->writer_active != current) {
			condition_met = true;
		} else {
			fail_msg = "Lock is held exclusively by current fiber";
		}
		break;

	default:
		fail_msg = "Unknown assertion type requested";
		break;
	}

	FIBERS_ASSERT(
		condition_met,
		"fibers_rwlock_assert(%p) failed: type=0x%x (%s). State: writer=%d, readers=%u", (void *)rwlock, type, fail_msg,
		rwlock->writer_active ? rwlock->writer_active->id : -1,
		rwlock->reader_count
		);
}
