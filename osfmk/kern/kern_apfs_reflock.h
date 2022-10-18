/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _KERN_APFS_REFLOCK_H_
#define _KERN_APFS_REFLOCK_H_

#include <sys/cdefs.h>
#include <kern/kern_types.h>
#include <kern/locks.h>

/*
 * kern_apfs_reflock_t is an object that provides a refcount protected by an embedded lock.
 * Manipulating the refcount is expected to be the most common operation on this object;
 * the refcount can be changed (incremented or decremented) when the lock is not held.
 * Some users might require to halt the refcount manipulation while some operations
 * are in progress. To express this, kern_apfs_reflock_t allow to lock the object providing
 * mutual exclusion between those operations and the refcount.
 * When the object is locked all new lock requests, increments and decrements of the kern_apfs_reflock_t
 * will fail, and the user can choose to wait for the object to be unlocked.
 * The thread that locked the object will inherit the priority push of all the
 * threads waiting for it to be unlocked.
 * Further, refcount transitions 0->1 and 1->0, allow to atomically lock the reflock
 * providing the possibility to cleanup/initialize the state.
 */

#ifdef KERNEL_PRIVATE

#if XNU_KERNEL_PRIVATE
#define KERN_APFS_REFLOCK_WAITERS_BIT 16
#define KERN_APFS_REFLOCK_REFCOUNT_BIT (64 - (SWI_COND_OWNER_BITS + KERN_APFS_REFLOCK_WAITERS_BIT + 4))
#define KERN_APFS_REFLOCK_MAXREFCOUNT ((1ull << KERN_APFS_REFLOCK_REFCOUNT_BIT) - 1)
#define KERN_APFS_REFLOCK_MAXWAITERS ((1ull << KERN_APFS_REFLOCK_WAITERS_BIT) - 1)
#define KERN_APFS_REFLOCK_DESTROYED (~(0ull))

/*
 * Mask to debounce the sleep. Needs to be kept up to date with kern_apfs_reflock.
 * Equivalent to:
 * mask = {.kern_apfs_rl_owner = ((1 << SWI_COND_OWNER_BITS) - 1),
 *         .kern_apfs_rl_delayed_free = 1,
 *         .kern_apfs_rl_wake = 1,
 *         .kern_apfs_rl_allocated = 1,
 *         .kern_apfs_rl_allow_force = 1};
 */

#define KERN_APFS_SLEEP_DEBOUNCE_MASK ((uint64_t)0xf0000fffff)

typedef struct kern_apfs_reflock {
	union {
		cond_swi_var64_s kern_apfs_rl_data;
		struct {
			uint64_t kern_apfs_rl_owner: SWI_COND_OWNER_BITS,
			    kern_apfs_rl_waiters: KERN_APFS_REFLOCK_WAITERS_BIT,
			    kern_apfs_rl_delayed_free: 1,
			    kern_apfs_rl_wake: 1,
			    kern_apfs_rl_allocated: 1,
			    kern_apfs_rl_allow_force: 1,
			    kern_apfs_rl_count: KERN_APFS_REFLOCK_REFCOUNT_BIT;
		};
	};
} *kern_apfs_reflock_t;


#else /* XNU_KERNEL_PRIVATE */
typedef struct kern_apfs_reflock {
	uint64_t opaque;
} *kern_apfs_reflock_t;
#endif /* XNU_KERNEL_PRIVATE */

__options_decl(kern_apfs_reflock_in_flags_t, uint32_t, {
	KERN_APFS_REFLOCK_IN_DEFAULT =       0x0,
	KERN_APFS_REFLOCK_IN_LOCK_IF_LAST =  0x1,
	KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST = 0x2,
	KERN_APFS_REFLOCK_IN_WILL_WAIT =     0x4,
	KERN_APFS_REFLOCK_IN_FORCE =         0x8,
	KERN_APFS_REFLOCK_IN_ALLOW_FORCE =  0x10,
});

__options_decl(kern_apfs_reflock_out_flags_t, uint32_t, {
	KERN_APFS_REFLOCK_OUT_DEFAULT =      0x0,
	KERN_APFS_REFLOCK_OUT_LOCKED =       0x1,
});

__BEGIN_DECLS

/*
 * Name: kern_apfs_reflock_data
 *
 * Description: declares a kern_apfs_reflock variable with specified storage class.
 *              The reflock will be stored in this variable and it is the caller's responsibility
 *              to ensure that this variable's memory is going to be accessible by all threads that will use
 *              the kern_apfs_reflock.
 *              Every kern_apfs_reflock function will require a pointer to this variable as parameter.
 *
 *              The variable needs to be initialized once with kern_apfs_reflock_init() and destroyed once with
 *              kern_apfs_reflock_destroy() when not needed anymore.
 *
 * Args:
 *   Arg1: storage class.
 *   Arg2: variable name.
 */
#define kern_apfs_reflock_data(class, name)   class struct kern_apfs_reflock name

/*
 * Name: kern_apfs_reflock_init
 *
 * Description: initializes a kern_apfs_reflock_t.
 *
 * Args:
 *   Arg1: kern_apfs_reflock object.
 *
 * Conditions: the memory pointed by kern_apfs_reflock_t needs to be available
 *             while any of the other functions are executed.
 *             It is the caller responsibility to guarantee that all functions call
 *             executed on the kern_apfs_reflock have terminated before freeing it,
 *             including possible kern_apfs_reflock_wait_for_unlock(). If it is not possible
 *             to safely synchronize kern_apfs_reflock_wait_for_unlock() calls
 *             kern_apfs_reflock_alloc_init() should be used instead.
 */
void kern_apfs_reflock_init(kern_apfs_reflock_t reflock);

/*
 * Name: kern_apfs_reflock_destroy
 *
 * Description: destroys a kern_apfs_reflock_t.
 *
 * Args:
 *   Arg1: kern_apfs_reflock object.
 *
 * Conditions: the object must have been previously initialized with kern_apfs_reflock_init.
 *             Any access past this point to the kern_apfs_reflock will be considered invalid.
 */
void kern_apfs_reflock_destroy(kern_apfs_reflock_t reflock);

/*
 * Name: kern_apfs_reflock_alloc_init
 *
 * Description: allocates a kern_apfs_reflock_t.
 *
 * Returns: allocated kern_apfs_reflock_t.
 *
 * Conditions: It is the caller responsibility to guarantee that all functions call
 *             executed on the kern_apfs_reflock_t returned by this function
 *             (except for kern_apfs_reflock_wait_for_unlock()) have terminated before freeing it.
 *             It is safe to execute concurrent or later kern_apfs_reflock_wait_for_unlock()
 *             calls as long as the matching kern_apfs_reflock_try_get_ref(),
 *             kern_apfs_reflock_try_put_ref() or kern_apfs_reflock_try_lock() was executed before
 *             the call to kern_apfs_reflock_free(). In this case the free of the object will be delegated
 *             to the last concurrent kern_apfs_reflock_wait_for_unlock() executed.
 */
kern_apfs_reflock_t kern_apfs_reflock_alloc_init(void);

/*
 * Name: kern_apfs_reflock_free
 *
 * Description: frees and destroys a kern_apfs_reflock_t.
 *
 * Args:
 *   Arg1: kern_apfs_reflock object.
 *
 * Conditions: It is the caller responsability to guarantee that all functions call
 *             executed on the kern_apfs_reflock_t (except kern_apfs_reflock_wait_for_unlock())
 *             have terminated before freeing it.
 *             It is safe to execute concurrent or later kern_apfs_reflock_wait_for_unlock()
 *             calls as long as the matching kern_apfs_reflock_try_get_ref(),
 *             kern_apfs_reflock_try_put_ref() or kern_apfs_reflock_try_lock() was executed before
 *             the call to kern_apfs_reflock_free(). In this case the free of the object will be delegated
 *             to the last concurrent kern_apfs_reflock_wait_for_unlock() executed.
 */
void kern_apfs_reflock_free(kern_apfs_reflock_t reflock);

/*
 * Name: kern_apfs_reflock_try_get_ref
 *
 * Description: tries to get a reference on the kern_apfs_reflock.
 *              The operation will succeed if the lock on the object is not held.
 *              In case of failure the caller can choose to wait for the lock to unlock
 *              with a subsequent call to kern_apfs_reflock_wait_for_unlock().
 *
 * Args:
 *   Arg1: kern_apfs_reflock object.
 *   Arg2: in flags can be a combination of:
 *         - KERN_APFS_REFLOCK_IN_DEFAULT       for default behaviour.
 *         - KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST will lock the reflock if the refcount was incremented
 *                                              in the "init" transition, so from 0->1.
 *         - KERN_APFS_REFLOCK_IN_WILL_WAIT     if the try_get() fails, then the thread will call kern_apfs_reflock_wait_for_unlock().
 *                                              kern_apfs_reflock_wait_for_unlock() cannot be called after this function fails if this
 *                                              flag was not set.
 *         - KERN_APFS_REFLOCK_IN_FORCE         if the reflock was locked from a kern_apfs_reflock_try_lock() with KERN_APFS_REFLOCK_IN_ALLOW_FORCE
 *                                              this flag will allow to get the reference even if the object is locked.
 *                                              Even with this flag set the function might fail if the reflock was locked from a
 *                                              kern_apfs_reflock_try_get_ref() or kern_apfs_reflock_try_put_ref().
 *         NOTE: KERN_APFS_REFLOCK_IN_FORCE and KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST cannot be used together.
 *   Arg3: out flags:
 *        - KERN_APFS_REFLOCK_OUT_DEFAULT       if the lock was not acquired.
 *        - KERN_APFS_REFLOCK_OUT_LOCKED        if the lock was acquired.
 *
 * Returns: true if the reference was acquired, false otherwise.
 *          If KERN_APFS_REFLOCK_IN_LOCK_IF_FIRST was set and the reference was successfully acquired, out_flags will indicate if the
 *          lock was acquired.
 *
 *
 * Conditions: If KERN_APFS_REFLOCK_IN_WILL_WAIT was set, a kern_apfs_reflock_wait_for_unlock()
 *             needs to be called in case of failure.
 *             If KERN_APFS_REFLOCK_OUT_LOCKED is returned on the out_flags a corresponding kern_apfs_reflock_wait_for_unlock() needs to be called
 *             by the same thread and the thread cannot execute in userspace until the unlock is called.
 */
bool kern_apfs_reflock_try_get_ref(kern_apfs_reflock_t reflock, kern_apfs_reflock_in_flags_t in_flags, kern_apfs_reflock_out_flags_t *out_flags);

/*
 * Name: kern_apfs_reflock_try_put_ref
 *
 * Description: tries to put a reference on the kern_apfs_reflock.
 *              The operation will succeed if the lock on the object is not held.
 *              In case of failure the caller can choose to wait for the lock to unlock
 *              with a subsequent call to kern_apfs_reflock_wait_for_unlock().
 *
 * Args:
 *   Arg1: kern_apfs_reflock object.
 *   Arg2: in flags can be a combination of:
 *         - KERN_APFS_REFLOCK_IN_DEFAULT       for default behaviour.
 *         - KERN_APFS_REFLOCK_IN_LOCK_IF_LAST  will lock the reflock if the refcount was decremented
 *                                              in the "cleanup" transition, so from 1->0.
 *         - KERN_APFS_REFLOCK_IN_WILL_WAIT     if the try_put() fails, then the thread will call kern_apfs_reflock_wait_for_unlock().
 *                                              kern_apfs_reflock_wait_for_unlock() cannot be called after this function fails if this
 *                                              flag was not set.
 *         - KERN_APFS_REFLOCK_IN_FORCE         if the reflock was locked from a kern_apfs_reflock_try_lock() with KERN_APFS_REFLOCK_IN_ALLOW_FORCE
 *                                              this flag will allow to put the reference even if the object is locked.
 *                                              Even with this flag set the function might fail if the reflock was locked from a
 *                                              kern_apfs_reflock_try_get_ref() or kern_apfs_reflock_try_put_ref().
 *         NOTE: KERN_APFS_REFLOCK_IN_FORCE and KERN_APFS_REFLOCK_IN_LOCK_IF_LAST cannot be used together.
 *   Arg3: out flags:
 *        - KERN_APFS_REFLOCK_OUT_DEFAULT       if the lock was not acquired.
 *        - KERN_APFS_REFLOCK_OUT_LOCKED        if the lock was acquired.
 *
 * Returns: true if the reference was successfully decremented, false otherwise.
 *          If KERN_APFS_REFLOCK_IN_LOCK_IF_LAST was set and the reference was successfully decremented, out_flags will indicate if the
 *          lock was acquired.
 *
 *
 * Conditions: If KERN_APFS_REFLOCK_IN_WILL_WAIT was set, a kern_apfs_reflock_wait_for_unlock()
 *             needs to be called in case of failure.
 *             If KERN_APFS_REFLOCK_OUT_LOCKED is returned on the out_flags a corresponding kern_apfs_reflock_wait_for_unlock() needs to be called
 *             by the same theread and the thread cannot execute in userspace until the unlock is called.
 *
 */
bool kern_apfs_reflock_try_put_ref(kern_apfs_reflock_t reflock, kern_apfs_reflock_in_flags_t in_flags, kern_apfs_reflock_out_flags_t *out_flags);

/*
 * Name: kern_apfs_reflock_try_lock
 *
 * Description: tries to acquire the lock on the kern_apfs_reflock.
 *              The operation will succeed if the lock on the object is not held.
 *              In case of failure the caller can choose to wait for the lock to unlock
 *              with a subsequent call to kern_apfs_reflock_wait_for_unlock().
 *
 * Args:
 *   Arg1: kern_apfs_reflock object.
 *   Arg2: in flags can be a combination of:
 *         - KERN_APFS_REFLOCK_IN_DEFAULT       for default behaviour.
 *         - KERN_APFS_REFLOCK_IN_WILL_WAIT     if the try_lock() fails, then the thread will call kern_apfs_reflock_wait_for_unlock().
 *                                              kern_apfs_reflock_wait_for_unlock() cannot be called after this function fails if this
 *                                              flag was not set.
 *         - KERN_APFS_REFLOCK_IN_ALLOW_FORCE   if this flag is set, kern_apfs_reflock_try_put_ref() and kern_apfs_reflock_try_get_ref() with
 *                                              flag KERN_APFS_REFLOCK_IN_FORCE set will succed even after this call locked the reflock.
 *
 *   Arg3: refcount_when_lock pointer into which return the value of the refcount at the moment of lock.
 *
 * Returns: true if the lock was acquired, false otherwise.
 *
 * Conditions: If KERN_APFS_REFLOCK_IN_WILL_WAIT was set, a kern_apfs_reflock_wait_for_unlock()
 *             needs to be called in case of failure.
 *             If the lock was acquired a subsequent kern_apfs_reflock_unlock() by the same theread and
 *             the thread cannot execute in userspace until the unlock is called.
 *             Recursive locking is not allowed.
 */
bool kern_apfs_reflock_try_lock(kern_apfs_reflock_t reflock, kern_apfs_reflock_in_flags_t in_flags, uint32_t *refcount_when_lock);

/*
 * Name: kern_apfs_reflock_wait_for_unlock
 *
 * Description: waits for the lock to be unlocked.
 *              While waiting the priority of this thread will contribute
 *              to the priority push of the owner of the reflock.
 *              NOTE: it is not guaranteed that by the time this calls
 *              returns the reflock is unlocked, as it might have been re-locked
 *              after the current thread has been woken up.
 *              If needed, the matching kern_apfs_reflock_try_get_ref(), kern_apfs_reflock_try_put_ref() or
 *              kern_apfs_reflock_try_lock() should be re-driven after this function.
 *
 * Args:
 *   Arg1: reflock object.
 *   Arg2: interruptible flag for wait.
 *   Arg3: deadline for wait.
 *
 * Returns: result of the wait.
 *          THREAD_AWAKENED - normal wakeup
 *          THREAD_TIMED_OUT - timeout expired
 *          THREAD_INTERRUPTED - aborted/interrupted
 *          THREAD_NOT_WAITING - thread didn't need to wait
 */
wait_result_t kern_apfs_reflock_wait_for_unlock(kern_apfs_reflock_t reflock, wait_interrupt_t interruptible, uint64_t deadline);

/*
 * Name: kern_apfs_reflock_unlock
 *
 * Description: unlocks a reflock obj.
 *
 * Args:
 *   Arg1: reflock object.
 *
 * Conditions: the same thread that locked the object needs to unlock it.
 */
void kern_apfs_reflock_unlock(kern_apfs_reflock_t reflock);

/*
 * Name: kern_apfs_reflock_read_ref
 *
 * Description: reads the refcount counter.
 *              Note: using this function is racy, as the refcount can change
 *              after this function reads it. Its usage is discouraged.
 *
 * Args:
 *   Arg1: reflock object.
 *
 * Returns: refcount value.
 */
uint64_t kern_apfs_reflock_read_ref(kern_apfs_reflock_t reflock);
__END_DECLS

#endif /* KERNEL_PRIVATE */
#endif /* _KERN_APFS_REFLOCK_H_ */
