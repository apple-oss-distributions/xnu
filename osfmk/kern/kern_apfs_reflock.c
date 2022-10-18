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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <kern/kalloc.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <kern/kern_apfs_reflock.h>

KALLOC_TYPE_DEFINE(KT_KERN_APFSREFLOCK, struct kern_apfs_reflock, KT_PRIV_ACCT);

static_assert(sizeof(struct kern_apfs_reflock) == sizeof(uint64_t));

void
kern_apfs_reflock_init(kern_apfs_reflock_t reflock)
{
	reflock->kern_apfs_rl_data.cond64_data = 0;
}

void
kern_apfs_reflock_destroy(kern_apfs_reflock_t reflock)
{
	if (reflock->kern_apfs_rl_data.cond64_data == KERN_APFS_REFLOCK_DESTROYED) {
		panic("kern_apfs_reflock_t %p was already destroyed", reflock);
	}
	if (reflock->kern_apfs_rl_allocated == 1) {
		panic("kern_apfs_reflock_t %p was allocated. kern_apfs_reflock_free should be called instead of kern_apfs_reflock_destroy", reflock);
	}
	if (reflock->kern_apfs_rl_owner != 0) {
		panic("kern_apfs_reflock_t %p: destroying a reflock currently locked by ctid %d", reflock, reflock->kern_apfs_rl_owner);
	}
	if (reflock->kern_apfs_rl_wake != 0) {
		panic("kern_apfs_reflock_t %p: destroying a reflock with threads currently waiting or in the process of waiting", reflock);
	}
	assert(reflock->kern_apfs_rl_allow_force == 0);
	assert(reflock->kern_apfs_rl_waiters == 0);
	assert(reflock->kern_apfs_rl_delayed_free == 0);
	reflock->kern_apfs_rl_data.cond64_data = KERN_APFS_REFLOCK_DESTROYED;
}

kern_apfs_reflock_t
kern_apfs_reflock_alloc_init(void)
{
	kern_apfs_reflock_t reflock = zalloc_flags(KT_KERN_APFSREFLOCK, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	reflock->kern_apfs_rl_allocated = 1;
	return reflock;
}

static void
kern_apfs_reflock_free_internal(kern_apfs_reflock_t reflock)
{
	assert(reflock->kern_apfs_rl_waiters == 0);
	assert(reflock->kern_apfs_rl_owner == 0);
	assert(reflock->kern_apfs_rl_allow_force == 0);
	assert(reflock->kern_apfs_rl_wake == 0);
	assert(reflock->kern_apfs_rl_allocated == 1);
	assert(reflock->kern_apfs_rl_delayed_free == 1);

	zfree(KT_KERN_APFSREFLOCK, reflock);
}

static void inline
kern_apfs_reflock_check_valid(kern_apfs_reflock_t reflock)
{
	if (reflock->kern_apfs_rl_data.cond64_data == KERN_APFS_REFLOCK_DESTROYED) {
		panic("reflock %p was destoryed", reflock);
	}
	if (reflock->kern_apfs_rl_allocated == 1 && reflock->kern_apfs_rl_delayed_free == 1) {
		panic("reflock %p used after request for free", reflock);
	}
}

void
kern_apfs_reflock_free(kern_apfs_reflock_t reflock)
{
	struct kern_apfs_reflock old_reflock, new_reflock;

	if (reflock->kern_apfs_rl_allocated == 0) {
		panic("kern_apfs_reflock_t %p was not allocated. kern_apfs_reflock_destroy should be called instead of kern_apfs_reflock_free", reflock);
	}

	/*
	 * This could be concurrent with kern_apfs_reflock_wait_for_unlock
	 */
	os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, release, {
		new_reflock = old_reflock;

		if (reflock->kern_apfs_rl_delayed_free == 1) {
		        panic("kern_apfs_reflock_t %p is already in the process of being freed", reflock);
		}
		if (reflock->kern_apfs_rl_owner != 0) {
		        panic("kern_apfs_reflock_t %p: freeing a reflock currently locked by ctid %d", reflock, reflock->kern_apfs_rl_owner);
		}
		assert(reflock->kern_apfs_rl_wake == 0);
		assert(reflock->kern_apfs_rl_allow_force == 0);

		new_reflock.kern_apfs_rl_delayed_free = 1;
	});

	if (new_reflock.kern_apfs_rl_waiters == 0) {
		kern_apfs_reflock_free_internal(reflock);
	}
}

bool
kern_apfs_reflock_try_get_ref(struct kern_apfs_reflock *reflock, kern_apfs_reflock_in_flags_t in_flags, kern_apfs_reflock_out_flags_t *out_flags)
{
	struct kern_apfs_reflock old_reflock, new_reflock;
	ctid_t my_ctid = thread_get_ctid(current_thread());
	bool acquired = false;
	bool locked = false;
	bool will_wait = (in_flags & KERN_APFS_REFLOCK_IN_WILL_WAIT) != 0;
	bool force = (in_flags & KERN_APFS_REFLOCK_IN_FORCE) != 0;
	bool try_lock = (in_flags & KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST) != 0;

	if (force && try_lock) {
		panic("Cannot use KERN_APFS_REFLOCK_IN_FORCE and KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST together");
	}

	kern_apfs_reflock_check_valid(reflock);
	*out_flags = KERN_APFS_REFLOCK_OUT_DEFAULT;

	os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, acquire, {
		new_reflock = old_reflock;
		locked = false;
		/*
		 * Check if refcount modifications are halted by
		 * a thread that is holding the lock.
		 */
		if (old_reflock.kern_apfs_rl_owner != 0 &&
		!(force && old_reflock.kern_apfs_rl_allow_force == 1)) {
		        acquired = false;
		        if (will_wait && reflock->kern_apfs_rl_allocated == 1) {
		                /*
		                 * We need to remember how many threads
		                 * will call wait_unlock so that
		                 * in case a free happens the last waiter
		                 * leaving the wait_unlock will free the reflock.
		                 */
		                if (old_reflock.kern_apfs_rl_waiters == KERN_APFS_REFLOCK_MAXWAITERS) {
		                        panic("kern_apfs_reflock: too many waiters for %p thread %p", reflock, current_thread());
				}
		                new_reflock.kern_apfs_rl_waiters = old_reflock.kern_apfs_rl_waiters + 1;
			} else {
		                /*
		                 * Caller does not want to wait or we do not need to remember how many waiters there are.
		                 */
		                os_atomic_rmw_loop_give_up(break);
			}
		} else {
		        acquired = true;
		        if (old_reflock.kern_apfs_rl_count == KERN_APFS_REFLOCK_MAXREFCOUNT) {
		                panic("kern_apfs_reflock: too many refs for %p thread %p", reflock, current_thread());
			}
		        new_reflock.kern_apfs_rl_count = old_reflock.kern_apfs_rl_count + 1;
		        if (try_lock && new_reflock.kern_apfs_rl_count == 1) {
		                new_reflock.kern_apfs_rl_owner = my_ctid;
		                new_reflock.kern_apfs_rl_allow_force = 0;
		                locked = true;
			}
		}
	});

	if (locked) {
		assert(acquired == true);
		assert((in_flags & KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST) != 0);
		*out_flags |= KERN_APFS_REFLOCK_OUT_LOCKED;
	}

	return acquired;
}

bool
kern_apfs_reflock_try_put_ref(kern_apfs_reflock_t reflock, kern_apfs_reflock_in_flags_t in_flags, kern_apfs_reflock_out_flags_t *out_flags)
{
	struct kern_apfs_reflock old_reflock, new_reflock;
	ctid_t my_ctid = thread_get_ctid(current_thread());
	bool released = false;
	bool last_release = false;
	bool locked = false;
	bool will_wait = (in_flags & KERN_APFS_REFLOCK_IN_WILL_WAIT) != 0;
	bool force = (in_flags & KERN_APFS_REFLOCK_IN_FORCE) != 0;
	bool try_lock = (in_flags & KERN_APFS_REFLOCK_IN_LOCK_IF_LAST) != 0;

	if (force && try_lock) {
		panic("Cannot use KERN_APFS_REFLOCK_IN_FORCE and KERN_APFS_REFLOCK_IN_LOCK_IF_LAST together");
	}

	kern_apfs_reflock_check_valid(reflock);
	*out_flags = KERN_APFS_REFLOCK_OUT_DEFAULT;

	os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, release, {
		if (old_reflock.kern_apfs_rl_count == 0) {
		        panic("kern_apfs_reflock: over releasing reflock %p thread %p", reflock, current_thread());
		}

		new_reflock = old_reflock;
		locked = false;
		last_release = false;

		/*
		 * Check if refcount modifications are halted by
		 * a thread that is holding the lock.
		 */
		if (old_reflock.kern_apfs_rl_owner != 0 &&
		!(force && old_reflock.kern_apfs_rl_allow_force == 1)) {
		        released = false;
		        if (will_wait && reflock->kern_apfs_rl_allocated == 1) {
		                /*
		                 * We need to remember how many threads
		                 * will call wait_unlock so that
		                 * in case a free happens the last waiters
		                 * leaving the wait_unlock will free the reflock.
		                 */
		                if (old_reflock.kern_apfs_rl_waiters == KERN_APFS_REFLOCK_MAXWAITERS) {
		                        panic("kern_apfs_reflock: too many waiters for %p thread %p", reflock, current_thread());
				}
		                new_reflock.kern_apfs_rl_waiters = old_reflock.kern_apfs_rl_waiters + 1;
			} else {
		                /*
		                 * Caller does not want to wait or we do not need to remember how many waiters there are.
		                 */
		                os_atomic_rmw_loop_give_up(break);
			}
		} else {
		        released = true;
		        new_reflock.kern_apfs_rl_count = old_reflock.kern_apfs_rl_count - 1;
		        if (new_reflock.kern_apfs_rl_count == 0) {
		                last_release = true;
		                if (try_lock) {
		                        new_reflock.kern_apfs_rl_owner = my_ctid;
		                        new_reflock.kern_apfs_rl_allow_force = 0;
		                        locked = true;
				}
			}
		}
	});

	if (locked) {
		assert(released == true);
		assert((in_flags & KERN_APFS_REFLOCK_IN_LOCK_IF_LAST) != 0);
		*out_flags |= KERN_APFS_REFLOCK_OUT_LOCKED;
	}

	if (locked || last_release) {
		os_atomic_thread_fence(acquire);
	}

	return released;
}

bool
kern_apfs_reflock_try_lock(kern_apfs_reflock_t reflock, kern_apfs_reflock_in_flags_t in_flags, uint32_t *refcount_when_lock)
{
	struct kern_apfs_reflock old_reflock, new_reflock;
	ctid_t my_ctid = thread_get_ctid(current_thread());
	bool acquired = false;
	bool allow_force = (in_flags & KERN_APFS_REFLOCK_IN_ALLOW_FORCE) != 0;
	bool will_wait = (in_flags & KERN_APFS_REFLOCK_IN_WILL_WAIT) != 0;
	uint32_t refcount = 0;

	kern_apfs_reflock_check_valid(reflock);

	os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, acquire, {
		new_reflock = old_reflock;
		/*
		 * Check if a thread is already holding the lock.
		 */
		if (old_reflock.kern_apfs_rl_owner != 0) {
		        if (old_reflock.kern_apfs_rl_owner == my_ctid) {
		                panic("Trying to lock a reflock owned by the same thread %p, reflock %p", current_thread(), reflock);
			}
		        acquired = false;
		        if (will_wait && reflock->kern_apfs_rl_allocated == 1) {
		                /*
		                 * We need to remember how many threads
		                 * will call wait_unlock so that
		                 * in case a free happens the last waiter
		                 * leaving the wait_unlock will free the reflock.
		                 */
		                if (old_reflock.kern_apfs_rl_waiters == KERN_APFS_REFLOCK_MAXWAITERS) {
		                        panic("kern_apfs_reflock: too many waiters for %p thread %p", reflock, current_thread());
				}
		                new_reflock.kern_apfs_rl_waiters = old_reflock.kern_apfs_rl_waiters + 1;
			} else {
		                /*
		                 * Caller does not want to wait or we do not need to remember how many waiters there are.
		                 */
		                os_atomic_rmw_loop_give_up(break);
			}
		} else {
		        acquired = true;
		        refcount = old_reflock.kern_apfs_rl_count;
		        new_reflock.kern_apfs_rl_owner = my_ctid;
		        if (allow_force) {
		                new_reflock.kern_apfs_rl_allow_force = 1;
			} else {
		                new_reflock.kern_apfs_rl_allow_force = 0;
			}
		}
	});

	if (acquired && refcount_when_lock != NULL) {
		*refcount_when_lock = refcount;
	}

	return acquired;
}

wait_result_t
kern_apfs_reflock_wait_for_unlock(kern_apfs_reflock_t reflock, wait_interrupt_t interruptible, uint64_t deadline)
{
	struct kern_apfs_reflock old_reflock, new_reflock;
	ctid_t my_ctid = thread_get_ctid(current_thread());
	wait_result_t ret;
	bool wait = false;
	bool free = false;

	os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, relaxed, {
		new_reflock = old_reflock;
		free = false;

		/*
		 * Be sure that kern_apfs_rl_waiters were incremented
		 * before waiting.
		 */
		if (old_reflock.kern_apfs_rl_allocated == 1 && old_reflock.kern_apfs_rl_waiters == 0) {
		        panic("kern_apfs_reflock: kern_apfs_rl_waiters are 0 when trying to wait reflock %p thread %p. Probably a try* function with a positive will_wait wasn't called before waiting.", reflock, current_thread());
		}

		/*
		 * Check if a thread is still holding the lock.
		 */
		if (old_reflock.kern_apfs_rl_owner != 0) {
		        if (old_reflock.kern_apfs_rl_owner == my_ctid) {
		                panic("Trying to wait on a reflock owned by the same thread %p, reflock %p", current_thread(), reflock);
			}
		        /*
		         * Somebody is holding the lock.
		         * Notify we have seen this, and we
		         * are intentioned to wait.
		         */
		        new_reflock.kern_apfs_rl_wake = 1;
		        wait = true;
		} else {
		        /*
		         * Lock not held, do not wait.
		         */
		        wait = false;
		        if (old_reflock.kern_apfs_rl_allocated == 1) {
		                new_reflock.kern_apfs_rl_waiters = old_reflock.kern_apfs_rl_waiters - 1;
		                if (old_reflock.kern_apfs_rl_delayed_free == 1 && new_reflock.kern_apfs_rl_waiters == 0) {
		                        free = true;
				}
			} else {
		                os_atomic_rmw_loop_give_up(break);
			}
		}
	});

	if (free) {
		assert(wait == false);
		kern_apfs_reflock_free_internal(reflock);
		return KERN_NOT_WAITING;
	}

	if (!wait) {
		return KERN_NOT_WAITING;
	}

	/*
	 * We want to sleep only if we see an owner still set and if the wakeup flag is set.
	 * If the owner observed is different from the one saved we want to not sleep.
	 */
	ret = cond_sleep_with_inheritor64_mask((cond_swi_var_t) reflock, new_reflock.kern_apfs_rl_data, KERN_APFS_SLEEP_DEBOUNCE_MASK, interruptible, deadline);

	/*
	 * In case reflock was allocated we need to remove
	 * ourselves from the waiters
	 */
	if (new_reflock.kern_apfs_rl_allocated == 1) {
		os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, acquire, {
			new_reflock = old_reflock;
			assert(old_reflock.kern_apfs_rl_waiters > 0);
			new_reflock.kern_apfs_rl_waiters = old_reflock.kern_apfs_rl_waiters - 1;
		});
	}

	if (new_reflock.kern_apfs_rl_delayed_free == 1 && new_reflock.kern_apfs_rl_waiters == 0) {
		kern_apfs_reflock_free_internal(reflock);
	}

	return ret;
}

void
kern_apfs_reflock_unlock(kern_apfs_reflock_t reflock)
{
	struct kern_apfs_reflock old_reflock, new_reflock;
	ctid_t my_ctid = thread_get_ctid(current_thread());
	bool waiters = false;

	kern_apfs_reflock_check_valid(reflock);

	os_atomic_rmw_loop(&reflock->kern_apfs_rl_data.cond64_data, old_reflock.kern_apfs_rl_data.cond64_data, new_reflock.kern_apfs_rl_data.cond64_data, release, {
		if (old_reflock.kern_apfs_rl_owner != my_ctid) {
		        panic("Unlocking swiref_t %p from thread ctid %u owned by ctid %u", reflock, my_ctid, old_reflock.kern_apfs_rl_owner);
		}

		new_reflock = old_reflock;
		/* Check if anybody is waiting for the unlock */
		if (old_reflock.kern_apfs_rl_wake == 1) {
		        waiters = true;
		        new_reflock.kern_apfs_rl_wake = 0;
		} else {
		        waiters = false;
		}
		new_reflock.kern_apfs_rl_owner = 0;
		new_reflock.kern_apfs_rl_allow_force = 0;
	});

	if (waiters) {
		cond_wakeup_all_with_inheritor((cond_swi_var_t) reflock, THREAD_AWAKENED);
	}
}

uint64_t
kern_apfs_reflock_read_ref(kern_apfs_reflock_t reflock)
{
	struct kern_apfs_reflock reflock_value;

	kern_apfs_reflock_check_valid(reflock);

	reflock_value.kern_apfs_rl_data.cond64_data = os_atomic_load(&reflock->kern_apfs_rl_data.cond64_data, relaxed);

	return reflock_value.kern_apfs_rl_count;
}
