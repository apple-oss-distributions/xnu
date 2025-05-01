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

#include <kern/assert.h>
#include <kern/epoch_sync.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/turnstile.h>

#include <os/atomic.h>
#include <os/hash.h>
#include <os/overflow.h>

#include <sys/kdebug.h>

#include <stdint.h>
#include <stdbool.h>

#include <kern/block_hint.h>

#define ES_INVALID_ID UINT64_MAX

/*
 * Combine space and ID into a unique identifier.
 * The ID passed in must leave the top byte clear.
 */
#define ES_UNIQUE_ID(space, id) ({                                        \
	assert3u(id >> 56, ==, 0); /* IDs must have the top byte clear */ \
	(id | ((uint64_t)space << 56));                                   \
})

static LCK_GRP_DECLARE(esync_lckgrp, "esync");
os_refgrp_decl(static, esync_refgrp, "esync", NULL);

typedef struct {
	uint64_t          es_id;            /* Synchronization ID. */
	struct turnstile *es_turnstile;     /* Associated turnstile. */
	esync_policy_t    es_policy;        /* Determines turnstile policy. */
	lck_spin_t        es_lock;          /* Interlock. */
	os_refcnt_t       es_refcnt;        /* Reference count for lifecycle. */
	queue_chain_t     es_link;          /* Link for hash table. */
} esync_t;

#pragma mark - Hash Table Implementation -

static LCK_GRP_DECLARE(ht_lck_grp, "ht");

typedef struct {
	queue_head_t  htb_head;
	lck_spin_t    htb_lock;
} ht_bucket_t;

typedef struct ht {
	const uint32_t  ht_size;
	ht_bucket_t    *ht_bucket;
} ht_t;

/*
 * Eventually it would be better to have "clients" just dynamically allocate
 * these as needed and not only support two static ID spaces.
 */

#define NBUCKETS_QUEUE 512
static ht_t exclaves_queue_ht = {
	.ht_size = NBUCKETS_QUEUE,
	.ht_bucket = &(ht_bucket_t[NBUCKETS_QUEUE]){}[0],
};

#define NBUCKETS_THREAD 64
static ht_t exclaves_thread_ht = {
	.ht_size = NBUCKETS_THREAD,
	.ht_bucket = &(ht_bucket_t[NBUCKETS_THREAD]){}[0],
};

#if DEVELOPMENT || DEBUG

#define NBUCKETS_TEST 8
static ht_t esync_test_ht = {
	.ht_size = NBUCKETS_TEST,
	.ht_bucket = &(ht_bucket_t[NBUCKETS_TEST]){}[0],
};
#endif /* DEVELOPMENT || DEBUG */


static ht_t *
space_to_ht(esync_space_t space)
{
	switch (space) {
	case ESYNC_SPACE_EXCLAVES_Q:
		return &exclaves_queue_ht;

	case ESYNC_SPACE_EXCLAVES_T:
		return &exclaves_thread_ht;

#if DEVELOPMENT || DEBUG
	case ESYNC_SPACE_TEST:
		return &esync_test_ht;
#endif /* DEVELOPMENT || DEBUG */

	default:
		panic("unknown epoch sync space");
	}
}

static __startup_func void
ht_startup_init(ht_t *ht)
{
	for (uint32_t i = 0; i < ht->ht_size; i++) {
		queue_init(&ht->ht_bucket[i].htb_head);
		lck_spin_init(&ht->ht_bucket[i].htb_lock, &ht_lck_grp, NULL);
	}
}
STARTUP_ARG(LOCKS, STARTUP_RANK_LAST, ht_startup_init, &exclaves_queue_ht);
STARTUP_ARG(LOCKS, STARTUP_RANK_LAST, ht_startup_init, &exclaves_thread_ht);

static inline ht_bucket_t *
ht_get_bucket(ht_t *ht, const uint64_t key)
{
	assert3u((ht->ht_size & (ht->ht_size - 1)), ==, 0);

	const uint32_t idx = os_hash_jenkins(&key, sizeof(key)) & (ht->ht_size - 1);
	return &ht->ht_bucket[idx];
}

static esync_t *
ht_put(ht_t *ht, const uint64_t key, esync_t *new_value)
{
	/* 'new_value' shouldn't be part of an existing queue. */
	assert3p(new_value->es_link.next, ==, NULL);
	assert3p(new_value->es_link.prev, ==, NULL);

	ht_bucket_t *bucket = ht_get_bucket(ht, key);

	lck_spin_lock_grp(&bucket->htb_lock, &ht_lck_grp);

	esync_t *value = NULL;
	esync_t *elem = NULL;
	qe_foreach_element(elem, &bucket->htb_head, es_link) {
		if (elem->es_id != key) {
			continue;
		}

		lck_spin_lock_grp(&elem->es_lock, &esync_lckgrp);
		if (elem->es_id == key) {
			value = elem;
			break;
		}
		lck_spin_unlock(&elem->es_lock);
	}

	if (value == NULL) {
		value = new_value;
		lck_spin_lock_grp(&value->es_lock, &esync_lckgrp);
		enqueue(&bucket->htb_head, &value->es_link);
	}

	lck_spin_unlock(&bucket->htb_lock);

	return value;
}

static void
ht_remove(ht_t *ht, const uint64_t key, esync_t *value)
{
	ht_bucket_t *bucket = ht_get_bucket(ht, key);

	lck_spin_lock_grp(&bucket->htb_lock, &ht_lck_grp);
	remqueue(&value->es_link);
	lck_spin_unlock(&bucket->htb_lock);

	assert3p(value->es_link.next, ==, NULL);
	assert3p(value->es_link.prev, ==, NULL);
}

static esync_t *
ht_get(ht_t *ht, const uint64_t key)
{
	ht_bucket_t *bucket = ht_get_bucket(ht, key);

	lck_spin_lock_grp(&bucket->htb_lock, &ht_lck_grp);

	esync_t *value = NULL;
	esync_t *elem = NULL;
	qe_foreach_element(elem, &bucket->htb_head, es_link) {
		if (elem->es_id != key) {
			continue;
		}

		lck_spin_lock_grp(&elem->es_lock, &esync_lckgrp);
		if (elem->es_id == key) {
			value = elem;
			break;
		}
		lck_spin_unlock(&elem->es_lock);
	}

	lck_spin_unlock(&bucket->htb_lock);

	return value;
}

#pragma mark - Epoch Sync Implementation -

/*
 * Allocate a backing object.
 */
static esync_t *
esync_alloc(const uint64_t id, const esync_policy_t policy)
{
	assert3u(id, !=, ES_INVALID_ID);

	esync_t *sync = kalloc_type(esync_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	assert3p(sync, !=, NULL);

	sync->es_id = id;
	sync->es_turnstile = TURNSTILE_NULL;
	sync->es_policy = policy;

	lck_spin_init(&sync->es_lock, &esync_lckgrp, NULL);

	os_ref_init_count(&sync->es_refcnt, &esync_refgrp, 1);

	return sync;
}

/*
 * Free a backing object.
 */
static void
esync_free(esync_t *sync)
{
	LCK_SPIN_ASSERT(&sync->es_lock, LCK_ASSERT_NOTOWNED);
	assert3p(sync->es_turnstile, ==, TURNSTILE_NULL);
	assert3u(os_ref_get_count(&sync->es_refcnt), ==, 0);

	lck_spin_destroy(&sync->es_lock, &esync_lckgrp);

	kfree_type(esync_t, sync);
}

/*
 * Stop using 'sync'. Drop the ref count and possibly remove it from the hash
 * table and free it.  Free up an unused entry if not NULL.
 * Called with the object locked.
 */
static void
esync_put(ht_t *ht, esync_t *sync, esync_t *to_be_freed)
{
	os_ref_count_t cnt = 0;

	LCK_SPIN_ASSERT(&sync->es_lock, LCK_ASSERT_OWNED);

	/* The last owner will remove it from the hash table. */
	cnt = os_ref_get_count(&sync->es_refcnt);
	if (cnt == 2) {
		/*
		 * Make sure no other thread will match it during the window
		 * where the lock is dropped but before it's been removed from
		 * the hash table (lookups are protected by es_lock as called
		 * from esync_acquire).
		 */
		const uint64_t id = sync->es_id;
		sync->es_id = ES_INVALID_ID;
		lck_spin_unlock(&sync->es_lock);

		ht_remove(ht, id, sync);

		/* Drop the ref associated with the hash table. */
		(void) os_ref_release(&sync->es_refcnt);

		/* Drop the final refcnt and free it. */
		os_ref_release_last(&sync->es_refcnt);

		/*
		 * Before freeing (and potentially taking another lock), call
		 * turnstile_cleanup().
		 */
		turnstile_cleanup();
		esync_free(sync);
	} else {
		cnt = os_ref_release_locked(&sync->es_refcnt);
		assert3u(cnt, >=, 2);
		lck_spin_unlock(&sync->es_lock);
		turnstile_cleanup();
	}

	/* An unused entry, free it. */
	if (to_be_freed != NULL) {
		os_ref_release_last(&to_be_freed->es_refcnt);
		esync_free(to_be_freed);
	}
}

/*
 * Get an object associated with 'id'. If there isn't one already, allocate one
 * and insert it.
 * Returns with the object locked and a +1 on the refcount.
 */
static esync_t *
esync_get(ht_t *ht, const uint64_t id, const esync_policy_t policy,
    esync_t **const to_be_freed)
{
	esync_t *new = esync_alloc(id, policy);
	esync_t *sync = ht_put(ht, id, new);

	/*
	 * See if the newly allocated entry was inserted. If so, then there's
	 * nothing extra to clean up later (in case cleanup is needed, it must
	 * be done later as the spinlock is held at this point).
	 * ht_put consumes the refcount of new if the entry was inserted.
	 */
	*to_be_freed = (sync != new) ? new : NULL;

	/*
	 * The policy of the sync object should always match. i.e. the
	 * consumer of the esync interfaces must guarantee that all waiters use
	 * the same policy.
	 */
	assert3u(sync->es_policy, ==, policy);

	os_ref_retain_locked(&sync->es_refcnt);

	LCK_SPIN_ASSERT(&sync->es_lock, LCK_ASSERT_OWNED);
	return sync;
}

/*
 * Update the epoch counter with a new epoch.
 * Returns true if the epoch was newer or equal to the existing epoch.
 */
static bool
esync_update_epoch(const uint64_t epoch, os_atomic(uint64_t) *counter)
{
	uint64_t old, new;

	return os_atomic_rmw_loop(counter, old, new, acq_rel, {
		if (old > epoch) {
		        os_atomic_rmw_loop_give_up();
		}
		new = epoch;
	}) == 1;
}


static void
esync_wait_set_block_hint(const esync_space_t space, const esync_policy_t policy)
{
	thread_t self = current_thread();

	switch (space) {
	case ESYNC_SPACE_EXCLAVES_Q:
	case ESYNC_SPACE_EXCLAVES_T:
		switch (policy) {
		case ESYNC_POLICY_KERNEL:
			thread_set_pending_block_hint(self, kThreadWaitExclaveCore);
			return;
		case ESYNC_POLICY_USER:
			thread_set_pending_block_hint(self, kThreadWaitExclaveKit);
			return;
		default:
			return;
		}
	default:
		return;
	}
}

void
kdp_esync_find_owner(struct waitq *waitq, event64_t event,
    thread_waitinfo_t *waitinfo)
{
	const esync_t *esync = (esync_t *)event;
	waitinfo->context = esync->es_id;

	if (waitq_held(waitq)) {
		return;
	}

	const struct turnstile *turnstile = waitq_to_turnstile(waitq);
	waitinfo->owner = thread_tid(turnstile->ts_inheritor);
}

/*
 * Block until esync_wake() is called on this id.
 * The epoch is incremented by the client on wakes. If the epoch is stale, then
 * don't block and return immediately.
 * Can allocate a new epoch synchronization object if needed.
 * Will only use "owner" if the epoch is fresh.
 */
wait_result_t
esync_wait(esync_space_t space, const uint64_t id, const uint64_t epoch,
    os_atomic(uint64_t) *counter, const ctid_t owner_ctid,
    const esync_policy_t policy, const wait_interrupt_t interruptible)
{
	assert3u(id, !=, ES_INVALID_ID);
	const uint64_t unique_id = ES_UNIQUE_ID(space, id);

	ht_t *ht = space_to_ht(space);

	esync_t *to_be_freed = NULL;
	esync_t *sync = esync_get(ht, unique_id, policy, &to_be_freed);

	LCK_SPIN_ASSERT(&sync->es_lock, LCK_ASSERT_OWNED);

	const bool fresh_epoch = esync_update_epoch(epoch, counter);
	if (!fresh_epoch) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC,
		    MACH_EPOCH_SYNC_WAIT_STALE), unique_id, epoch, NULL);
		esync_put(ht, sync, to_be_freed);
		return THREAD_NOT_WAITING;
	}

	/*
	 * It is safe to lookup the thread from the ctid here as the lock is
	 * held and the epoch is fresh.
	 * ctid and hence tid may be 0.
	 */
	thread_t owner_thread = ctid_get_thread(owner_ctid);
	uint64_t tid = thread_tid(owner_thread);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC, MACH_EPOCH_SYNC_WAIT) |
	    DBG_FUNC_START, unique_id, epoch, tid);

	assert(sync->es_policy == ESYNC_POLICY_KERNEL ||
	    sync->es_policy == ESYNC_POLICY_USER);
	turnstile_type_t tt = sync->es_policy == ESYNC_POLICY_KERNEL ?
	    TURNSTILE_EPOCH_KERNEL : TURNSTILE_EPOCH_USER;
	struct turnstile *ts = turnstile_prepare((uintptr_t)sync,
	    &sync->es_turnstile, TURNSTILE_NULL, tt);

	/*
	 * owner_thread may not be set, that's fine, the inheritor will be
	 * cleared.
	 */
	turnstile_update_inheritor(ts, owner_thread,
	    (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	esync_wait_set_block_hint(space, policy);

	wait_result_t wr = waitq_assert_wait64(&ts->ts_waitq,
	    CAST_EVENT64_T(sync), interruptible, TIMEOUT_WAIT_FOREVER);

	lck_spin_unlock(&sync->es_lock);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	if (wr == THREAD_WAITING) {
		wr = thread_block(THREAD_CONTINUE_NULL);
	}

	lck_spin_lock(&sync->es_lock);

	turnstile_complete((uintptr_t)sync, &sync->es_turnstile, NULL, tt);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC, MACH_EPOCH_SYNC_WAIT) |
	    DBG_FUNC_END, wr);

	/* Drops the lock, refcount and possibly frees sync. */
	esync_put(ht, sync, to_be_freed);

	return wr;
}

/*
 * Wake up a waiter. Pre-posted wakes (wakes which happen when there is no
 * active waiter) just return. The epoch is always updated.
 */
kern_return_t
esync_wake(esync_space_t space, const uint64_t id, const uint64_t epoch,
    os_atomic(uint64_t) *counter, const esync_wake_mode_t mode,
    const ctid_t ctid)
{
	assert3u(id, !=, ES_INVALID_ID);
	assert(
		mode == ESYNC_WAKE_ONE ||
		mode == ESYNC_WAKE_ALL ||
		mode == ESYNC_WAKE_ONE_WITH_OWNER ||
		mode == ESYNC_WAKE_THREAD);

	ht_t *ht = space_to_ht(space);
	const uint64_t unique_id = ES_UNIQUE_ID(space, id);

	kern_return_t kr = KERN_FAILURE;

	/*
	 * Update the epoch regardless of whether there's a waiter or not. (If
	 * there's no waiter, there will be no sync object).
	 * The epoch is read by waiters under the object lock to ensure that it
	 * doesn't miss a wake.
	 */
	(void) esync_update_epoch(epoch, counter);

	esync_t *sync = ht_get(ht, unique_id);
	if (sync == NULL) {
		/* Drop pre-posted WAKEs. */
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC,
		    MACH_EPOCH_SYNC_WAKE_NO_WAITERS), unique_id,
		    epoch, mode);
		return KERN_NOT_WAITING;
	}
	LCK_SPIN_ASSERT(&sync->es_lock, LCK_ASSERT_OWNED);

	os_ref_retain_locked(&sync->es_refcnt);

	assert(sync->es_policy == ESYNC_POLICY_KERNEL ||
	    sync->es_policy == ESYNC_POLICY_USER);
	turnstile_type_t tt = sync->es_policy == ESYNC_POLICY_KERNEL ?
	    TURNSTILE_EPOCH_KERNEL : TURNSTILE_EPOCH_USER;
	struct turnstile *ts = turnstile_prepare((uintptr_t)sync,
	    &sync->es_turnstile, TURNSTILE_NULL, tt);

	/* ctid and hence tid may be 0. */
	thread_t thread = ctid_get_thread(ctid);
	uint64_t tid = thread_tid(thread);

	switch (mode) {
	case ESYNC_WAKE_ONE:
		/* The woken thread is the new inheritor. */
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC,
		    MACH_EPOCH_SYNC_WAKE_ONE), unique_id, epoch);
		kr = waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(sync),
		    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);
		break;

	case ESYNC_WAKE_ALL:
		/* The inheritor is cleared. */
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC,
		    MACH_EPOCH_SYNC_WAKE_ALL), unique_id, epoch);
		kr = waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(sync),
		    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);
		break;

	case ESYNC_WAKE_ONE_WITH_OWNER:
		/* The specified thread is the new inheritor (may be NULL). */
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC,
		    MACH_EPOCH_SYNC_WAKE_ONE_WITH_OWNER), unique_id, epoch, tid);
		kr = waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(sync),
		    THREAD_AWAKENED, WAITQ_WAKEUP_DEFAULT);
		turnstile_update_inheritor(ts, thread,
		    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD);
		break;

	case ESYNC_WAKE_THREAD:
		/* No new inheritor. Wake the specified thread (if waiting). */
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EPOCH_SYNC,
		    MACH_EPOCH_SYNC_WAKE_THREAD), unique_id, epoch, tid);
		kr = waitq_wakeup64_thread(&ts->ts_waitq, CAST_EVENT64_T(sync),
		    thread, WAITQ_WAKEUP_DEFAULT);
	}

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);

	turnstile_complete((uintptr_t)sync, &sync->es_turnstile, NULL, tt);

	/* Drops the lock, refcount and possibly frees sync. */
	esync_put(ht, sync, NULL);

	assert(kr == KERN_SUCCESS || kr == KERN_NOT_WAITING);
	return kr;
}

#if DEVELOPMENT || DEBUG

#pragma mark - Tests -

/* For SYSCTL_TEST_REGISTER. */
#include <kern/startup.h>

/*
 * Delay for a random amount up to ~1/2ms.
 */
static void
random_delay(void)
{
	extern void read_random(void* buffer, u_int numBytes);
	uint64_t random = 0;
	read_random(&random, sizeof(random));
	delay(random % 512);
}

/*
 * Basic mutex-like primitive to test the epoch synchronization primitives.
 */

/* Counter for the "client"-side. */
static os_atomic(uint64_t) client_counter = 0;

/* Counter for the "server"-side. */
static os_atomic(uint64_t) server_counter = 0;

/*
 * The lock object stores 0 when not held and the thread's CTID when held.
 * If there's an active waiter, bit 32 is set.
 */
#define OWNER(x) ((x) & ((1ull << 32) - 1))
#define WAITER_BIT (1ull << 32)

/* The "mutex" itself. */
static uint64_t test_mutex;


STARTUP_ARG(LOCKS, STARTUP_RANK_LAST, ht_startup_init, &esync_test_ht);

/*
 * Grab the lock.
 * If already held, set a waiters bit and call esync_wait.
 * On acquisition, if there are still waiters, set the waiters bit when taking
 * the lock.
 */
static void
test_lock(uint64_t *lock)
{
	/* Counter to keep track of the number of active waiters. */
	static os_atomic(uint32_t) test_waiter_count = 0;

	const ctid_t ctid = thread_get_ctid(current_thread());
	uint64_t old = 0;
	uint64_t new = ctid;

	while (true) {
		/* Try to grab the lock. */
		if (os_atomic_cmpxchgv(lock, 0, new, &old, relaxed) == 1) {
			return;
		}

		/* Failed to grab the lock, add a waiter bit and wait. */
		do {
			uint64_t epoch = os_atomic_load(&client_counter, acquire);

			if (os_atomic_cmpxchgv(lock, old, old | WAITER_BIT, &old, relaxed) == 1) {
				os_atomic_inc(&test_waiter_count, acq_rel);

				random_delay();
				const wait_result_t wr = esync_wait(ESYNC_SPACE_TEST, (uint32_t)(uintptr_t)lock, epoch,
				    &server_counter, OWNER(old), ESYNC_POLICY_KERNEL, THREAD_UNINT);
				assert(wr == THREAD_NOT_WAITING || wr == THREAD_AWAKENED);
				random_delay();

				/*
				 * When acquiring the lock, if there are waiters make sure to
				 * set the waiters bit.
				 */
				new = ctid;
				if (os_atomic_dec(&test_waiter_count, acq_rel) != 0) {
					new |= WAITER_BIT;
				}
				break;
			}
		} while (old != 0);
	}
}

/*
 * Drop the lock.
 */
static void
test_unlock(uint64_t *lock)
{
	const ctid_t ctid = thread_get_ctid(current_thread());

	/* Drop the lock. */
	uint64_t old = os_atomic_xchg(lock, 0, relaxed);
	assert3u(OWNER(old), ==, ctid);

	uint64_t epoch = os_atomic_inc(&client_counter, release);

	if ((old & WAITER_BIT) != 0) {
		random_delay();
		(void) esync_wake(ESYNC_SPACE_TEST, (uint32_t)(uintptr_t)lock, epoch,
		    &server_counter, ESYNC_WAKE_ONE, 0);
		random_delay();
	}
}


/* Count to keep track of completed test threads. */
static os_atomic(uint64_t) test_complete_count = 0;

static void
test_lock_unlock(__unused void *arg, __unused int a)
{
	for (int c = 0; c < 10; c++) {
		test_lock(&test_mutex);
		random_delay();
		test_unlock(&test_mutex);
	}

	os_atomic_inc(&test_complete_count, relaxed);
}

static LCK_MTX_DECLARE(esync_test_mtx, &esync_lckgrp);

/* Wait then wake. */
static int
esync_test(int64_t count, int64_t *out)
{
	kern_return_t ret;
	thread_t *thread = kalloc_type(thread_t, count,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	printf("%s: STARTING\n", __func__);

	lck_mtx_lock(&esync_test_mtx);

	for (int64_t i = 0; i < count; i++) {
		ret = kernel_thread_start_priority(test_lock_unlock, NULL,
		    BASEPRI_DEFAULT, &thread[i]);
		assert3u(ret, ==, KERN_SUCCESS);
	}

	/* Wait for completion. */
	while (test_complete_count != count) {
		delay(100000);
	}

	os_atomic_store(&test_complete_count, 0, relaxed);

	/* Drop the thread refs. */
	for (int i = 0; i < count; i++) {
		thread_deallocate(thread[i]);
	}

	os_atomic_store(&server_counter, 0, relaxed);
	os_atomic_store(&client_counter, 0, relaxed);

	lck_mtx_unlock(&esync_test_mtx);

	printf("%s: SUCCESS\n", __func__);

	kfree_type(thread_t, count, thread);

	*out = 1;

	return 0;
}

SYSCTL_TEST_REGISTER(esync_test, esync_test);

/*
 * Block the caller on an interruptible wait. The thread must be terminated in
 * order for this test to return.
 */
static int
esync_test_wait(__unused int64_t in, __unused int64_t *out)
{
	os_atomic(uint64_t) counter = 0;

	printf("%s: STARTING\n", __func__);

	wait_result_t wr = esync_wait(ESYNC_SPACE_TEST, 0, 0, &counter, 0,
	    ESYNC_POLICY_USER, THREAD_INTERRUPTIBLE);
	if (wr != THREAD_INTERRUPTED) {
		printf("%s: FAILURE - unexpected wait result (%d)\n", __func__, wr);
		*out = -1;
		return 0;
	}

	printf("%s: SUCCESS\n", __func__);

	*out = 1;

	return 0;
}

SYSCTL_TEST_REGISTER(esync_test_wait, esync_test_wait);

#endif /* DEVELOPMENT  || DEBUG */
