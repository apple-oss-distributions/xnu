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

#ifndef _KERN_RW_LOCK_H_
#define _KERN_RW_LOCK_H_

#include <kern/lock_types.h>
#include <kern/lock_group.h>
#include <kern/lock_attr.h>

#ifdef  XNU_KERNEL_PRIVATE
#include <kern/startup.h>
#endif /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef  MACH_KERNEL_PRIVATE

typedef union {
	struct {
		uint16_t        shared_count;       /* No. of shared granted request */
		uint16_t
		    interlock:              1,      /* Interlock */
		    priv_excl:              1,      /* priority for Writer */
		    want_upgrade:           1,      /* Read-to-write upgrade waiting */
		    want_excl:              1,      /* Writer is waiting, or locked for write */
		    r_waiting:              1,      /* Someone is sleeping on lock */
		    w_waiting:              1,      /* Writer is sleeping on lock */
		    can_sleep:              1,      /* Can attempts to lock go to sleep? */
		    _pad2:                  8,      /* padding */
		    tag_valid:              1;      /* Field is actually a tag, not a bitfield */
#if __arm64__
		uint32_t        _pad4;
#endif
	};
	struct {
		uint32_t        data;               /* Single word version of bitfields and shared count */
#if __arm64__
		uint32_t        lck_rw_pad4;
#endif
	};
} lck_rw_word_t;

typedef struct {
	lck_rw_word_t   word;
	thread_t        lck_rw_owner __kernel_data_semantics;
} lck_rw_t;     /* arm: 8  arm64: 16 x86: 16 */

#define lck_rw_shared_count     word.shared_count
#define lck_rw_interlock        word.interlock
#define lck_rw_priv_excl        word.priv_excl
#define lck_rw_want_upgrade     word.want_upgrade
#define lck_rw_want_excl        word.want_excl
#define lck_r_waiting           word.r_waiting
#define lck_w_waiting           word.w_waiting
#define lck_rw_can_sleep        word.can_sleep
#define lck_rw_data             word.data
// tag and data reference the same memory. When the tag_valid bit is set,
// the data word should be treated as a tag instead of a bitfield.
#define lck_rw_tag_valid        word.tag_valid
#define lck_rw_tag              word.data

#define LCK_RW_SHARED_READER_OFFSET      0
#define LCK_RW_INTERLOCK_BIT            16
#define LCK_RW_PRIV_EXCL_BIT            17
#define LCK_RW_WANT_UPGRADE_BIT         18
#define LCK_RW_WANT_EXCL_BIT            19
#define LCK_RW_R_WAITING_BIT            20
#define LCK_RW_W_WAITING_BIT            21
#define LCK_RW_CAN_SLEEP_BIT            22
//                                      23-30
#define LCK_RW_TAG_VALID_BIT            31

#define LCK_RW_INTERLOCK                (1U << LCK_RW_INTERLOCK_BIT)
#define LCK_RW_R_WAITING                (1U << LCK_RW_R_WAITING_BIT)
#define LCK_RW_W_WAITING                (1U << LCK_RW_W_WAITING_BIT)
#define LCK_RW_WANT_UPGRADE             (1U << LCK_RW_WANT_UPGRADE_BIT)
#define LCK_RW_WANT_EXCL                (1U << LCK_RW_WANT_EXCL_BIT)
#define LCK_RW_TAG_VALID                (1U << LCK_RW_TAG_VALID_BIT)
#define LCK_RW_PRIV_EXCL                (1U << LCK_RW_PRIV_EXCL_BIT)
#define LCK_RW_SHARED_MASK              (0xffff << LCK_RW_SHARED_READER_OFFSET)
#define LCK_RW_SHARED_READER            (0x1 << LCK_RW_SHARED_READER_OFFSET)

#define LCK_RW_TAG_DESTROYED            ((LCK_RW_TAG_VALID | 0xdddddeadu))      /* lock marked as Destroyed */

#else /* MACH_KERNEL_PRIVATE */

#ifdef  KERNEL_PRIVATE
// TODO does this need pragma pack(1)?
typedef struct {
	uintptr_t       opaque[2] __kernel_data_semantics;
} lck_rw_t;
#else /* KERNEL_PRIVATE */
typedef struct __lck_rw_t__     lck_rw_t;
#endif /* KERNEL_PRIVATE */
#endif /* MACH_KERNEL_PRIVATE */

#if DEVELOPMENT || DEBUG
#ifdef XNU_KERNEL_PRIVATE

#define DEBUG_RW                        1
#define LCK_RW_EXPECTED_MAX_NUMBER      3       /* Expected number per thread of concurrently held rw_lock */

#if __LP64__
#define LCK_RW_CALLER_PACKED_BITS   48
#define LCK_RW_CALLER_PACKED_SHIFT   0
#define LCK_RW_CALLER_PACKED_BASE    0
#else
#define LCK_RW_CALLER_PACKED_BITS   32
#define LCK_RW_CALLER_PACKED_SHIFT   0
#define LCK_RW_CALLER_PACKED_BASE    0
#endif

_Static_assert(!VM_PACKING_IS_BASE_RELATIVE(LCK_RW_CALLER_PACKED),
    "Make sure the rwlde_caller_packed pointer packing is based on arithmetic shifts");


struct __attribute__ ((packed)) rw_lock_debug_entry {
	lck_rw_t      *rwlde_lock;                                       // rw_lock held
	int8_t        rwlde_mode_count;                                  // -1 is held in write mode, positive value is the recursive read count
#if __LP64__
	uintptr_t     rwlde_caller_packed: LCK_RW_CALLER_PACKED_BITS;    // caller that created the entry
#else
	uintptr_t     rwlde_caller_packed;                               // caller that created the entry
#endif
};
typedef struct rw_lock_debug {
	struct rw_lock_debug_entry rwld_locks[LCK_RW_EXPECTED_MAX_NUMBER]; /* rw_lock debug info of currently held locks */
	uint8_t                    rwld_locks_saved : 7,                   /* number of locks saved in rwld_locks */
	    rwld_overflow : 1;                                             /* lock_entry was full, so it might be inaccurate */
	uint32_t                   rwld_locks_acquired;                    /* number of locks acquired */
} rw_lock_debug_t;

_Static_assert(LCK_RW_EXPECTED_MAX_NUMBER <= 127, "LCK_RW_EXPECTED_MAX_NUMBER bigger than rwld_locks_saved");

#endif /* XNU_KERNEL_PRIVATE */
#endif /* DEVELOPMENT || DEBUG */

typedef unsigned int     lck_rw_type_t;

#define LCK_RW_TYPE_SHARED              0x01
#define LCK_RW_TYPE_EXCLUSIVE           0x02

#define decl_lck_rw_data(class, name)   class lck_rw_t name

#if XNU_KERNEL_PRIVATE
/*
 * Auto-initializing rw-locks declarations
 * ------------------------------------
 *
 * Unless you need to configure your locks in very specific ways,
 * there is no point creating explicit lock attributes. For most
 * static locks, this declaration macro can be used:
 *
 * - LCK_RW_DECLARE.
 *
 * For cases when some particular attributes need to be used,
 * LCK_RW_DECLARE_ATTR takes a variable declared with
 * LCK_ATTR_DECLARE as an argument.
 */

struct lck_rw_startup_spec {
	lck_rw_t                *lck;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

extern void             lck_rw_startup_init(
	struct lck_rw_startup_spec *spec);

#define LCK_RW_DECLARE_ATTR(var, grp, attr) \
	lck_rw_t var; \
	static __startup_data struct lck_rw_startup_spec \
	__startup_lck_rw_spec_ ## var = { &var, grp, attr }; \
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_FOURTH, lck_rw_startup_init, \
	    &__startup_lck_rw_spec_ ## var)

#define LCK_RW_DECLARE(var, grp) \
	LCK_RW_DECLARE_ATTR(var, grp, LCK_ATTR_NULL)

#define LCK_RW_ASSERT_SHARED    0x01
#define LCK_RW_ASSERT_EXCLUSIVE 0x02
#define LCK_RW_ASSERT_HELD      0x03
#define LCK_RW_ASSERT_NOTHELD   0x04
#endif /* XNU_KERNEL_PRIVATE */

#if MACH_ASSERT
#define LCK_RW_ASSERT(lck, type) lck_rw_assert((lck),(type))
#else /* MACH_ASSERT */
#define LCK_RW_ASSERT(lck, type)
#endif /* MACH_ASSERT */

#if DEBUG
#define LCK_RW_ASSERT_DEBUG(lck, type) lck_rw_assert((lck),(type))
#else /* DEBUG */
#define LCK_RW_ASSERT_DEBUG(lck, type)
#endif /* DEBUG */

/*!
 * @function lck_rw_alloc_init
 *
 * @abstract
 * Allocates and initializes a rw_lock_t.
 *
 * @discussion
 * The function can block. See lck_rw_init() for initialization details.
 *
 * @param grp           lock group to associate with the lock.
 * @param attr          lock attribute to initialize the lock.
 *
 * @returns             NULL or the allocated lock
 */
extern lck_rw_t         *lck_rw_alloc_init(
	lck_grp_t               *grp,
	lck_attr_t              *attr);

/*!
 * @function lck_rw_init
 *
 * @abstract
 * Initializes a rw_lock_t.
 *
 * @discussion
 * Usage statistics for the lock are going to be added to the lock group provided.
 *
 * The lock attribute can be LCK_ATTR_NULL or an attribute can be allocated with
 * lck_attr_alloc_init. So far however none of the attribute settings are supported.
 *
 * @param lck           lock to initialize.
 * @param grp           lock group to associate with the lock.
 * @param attr          lock attribute to initialize the lock.
 */
extern void             lck_rw_init(
	lck_rw_t                *lck,
	lck_grp_t               *grp,
	lck_attr_t              *attr);

/*!
 * @function lck_rw_free
 *
 * @abstract
 * Frees a rw_lock previously allocated with lck_rw_alloc_init().
 *
 * @discussion
 * The lock must be not held by any thread.
 *
 * @param lck           rw_lock to free.
 */
extern void             lck_rw_free(
	lck_rw_t                *lck,
	lck_grp_t               *grp);

/*!
 * @function lck_rw_destroy
 *
 * @abstract
 * Destroys a rw_lock previously initialized with lck_rw_init().
 *
 * @discussion
 * The lock must be not held by any thread.
 *
 * @param lck           rw_lock to destroy.
 */
extern void             lck_rw_destroy(
	lck_rw_t                *lck,
	lck_grp_t               *grp);

/*!
 * @function lck_rw_lock
 *
 * @abstract
 * Locks a rw_lock with the specified type.
 *
 * @discussion
 * See lck_rw_lock_shared() or lck_rw_lock_exclusive() for more details.
 *
 * @param lck           rw_lock to lock.
 * @param lck_rw_type   LCK_RW_TYPE_SHARED or LCK_RW_TYPE_EXCLUSIVE
 */
extern void             lck_rw_lock(
	lck_rw_t                *lck,
	lck_rw_type_t           lck_rw_type);

/*!
 * @function lck_rw_try_lock
 *
 * @abstract
 * Tries to locks a rw_lock with the specified type.
 *
 * @discussion
 * This function will return and not wait/block in case the lock is already held.
 * See lck_rw_try_lock_shared() or lck_rw_try_lock_exclusive() for more details.
 *
 * @param lck           rw_lock to lock.
 * @param lck_rw_type   LCK_RW_TYPE_SHARED or LCK_RW_TYPE_EXCLUSIVE
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
extern boolean_t        lck_rw_try_lock(
	lck_rw_t                *lck,
	lck_rw_type_t           lck_rw_type);

/*!
 * @function lck_rw_unlock
 *
 * @abstract
 * Unlocks a rw_lock previously locked with lck_rw_type.
 *
 * @discussion
 * The lock must be unlocked by the same thread it was locked from.
 * The type of the lock/unlock have to match, unless an upgrade/downgrade was performed while
 * holding the lock.
 *
 * @param lck           rw_lock to unlock.
 * @param lck_rw_type   LCK_RW_TYPE_SHARED or LCK_RW_TYPE_EXCLUSIVE
 */
extern void             lck_rw_unlock(
	lck_rw_t                *lck,
	lck_rw_type_t           lck_rw_type);

/*!
 * @function lck_rw_lock_shared
 *
 * @abstract
 * Locks a rw_lock in shared mode.
 *
 * @discussion
 * This function can block.
 * Multiple threads can acquire the lock in shared mode at the same time, but only one thread at a time
 * can acquire it in exclusive mode.
 * If the lock is held in shared mode and there are no writers waiting, a reader will be able to acquire
 * the lock without waiting.
 * If the lock is held in shared mode and there is at least a writer waiting, a reader will wait
 * for all the writers to make progress.
 * NOTE: the thread cannot return to userspace while the lock is held. Recursive locking is not supported.
 *
 * @param lck           rw_lock to lock.
 */
extern void             lck_rw_lock_shared(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_lock_shared_to_exclusive
 *
 * @abstract
 * Upgrades a rw_lock held in shared mode to exclusive.
 *
 * @discussion
 * This function can block.
 * Only one reader at a time can upgrade to exclusive mode. If the upgrades fails the function will
 * return with the lock not held.
 * The caller needs to hold the lock in shared mode to upgrade it.
 *
 * @param lck           rw_lock already held in shared mode to upgrade.
 *
 * @returns TRUE if the lock was upgraded, FALSE if it was not possible.
 *          If the function was not able to upgrade the lock, the lock will be dropped
 *          by the function.
 */
extern boolean_t        lck_rw_lock_shared_to_exclusive(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_unlock_shared
 *
 * @abstract
 * Unlocks a rw_lock previously locked in shared mode.
 *
 * @discussion
 * The same thread that locked the lock needs to unlock it.
 *
 * @param lck           rw_lock held in shared mode to unlock.
 */
extern void             lck_rw_unlock_shared(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_lock_exclusive
 *
 * @abstract
 * Locks a rw_lock in exclusive mode.
 *
 * @discussion
 * This function can block.
 * Multiple threads can acquire the lock in shared mode at the same time, but only one thread at a time
 * can acquire it in exclusive mode.
 * NOTE: the thread cannot return to userspace while the lock is held. Recursive locking is not supported.
 *
 * @param lck           rw_lock to lock.
 */
extern void             lck_rw_lock_exclusive(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_lock_exclusive_to_shared
 *
 * @abstract
 * Downgrades a rw_lock held in exclusive mode to shared.
 *
 * @discussion
 * The caller needs to hold the lock in exclusive mode to be able to downgrade it.
 *
 * @param lck           rw_lock already held in exclusive mode to downgrade.
 */
extern void             lck_rw_lock_exclusive_to_shared(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_unlock_exclusive
 *
 * @abstract
 * Unlocks a rw_lock previously locked in exclusive mode.
 *
 * @discussion
 * The same thread that locked the lock needs to unlock it.
 *
 * @param lck           rw_lock held in exclusive mode to unlock.
 */
extern void             lck_rw_unlock_exclusive(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_sleep
 *
 * @abstract
 * Assert_wait on an event while holding the rw_lock.
 *
 * @discussion
 * the flags can decide how to re-acquire the lock upon wake up
 * (LCK_SLEEP_SHARED, or LCK_SLEEP_EXCLUSIVE, or LCK_SLEEP_UNLOCK)
 * and if the priority needs to be kept boosted until the lock is
 * re-acquired (LCK_SLEEP_PROMOTED_PRI).
 *
 * @param lck                   rw_lock to use to synch the assert_wait.
 * @param lck_sleep_action      flags.
 * @param event                 event to assert_wait on.
 * @param interruptible         wait type.
 */
extern wait_result_t    lck_rw_sleep(
	lck_rw_t                *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible);

/*!
 * @function lck_rw_sleep_deadline
 *
 * @abstract
 * Assert_wait_deadline on an event while holding the rw_lock.
 *
 * @discussion
 * the flags can decide how to re-acquire the lock upon wake up
 * (LCK_SLEEP_SHARED, or LCK_SLEEP_EXCLUSIVE, or LCK_SLEEP_UNLOCK)
 * and if the priority needs to be kept boosted until the lock is
 * re-acquired (LCK_SLEEP_PROMOTED_PRI).
 *
 * @param lck                   rw_lock to use to synch the assert_wait.
 * @param lck_sleep_action      flags.
 * @param event                 event to assert_wait on.
 * @param interruptible         wait type.
 * @param deadline              maximum time after which being woken up
 */
extern wait_result_t    lck_rw_sleep_deadline(
	lck_rw_t                *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

#ifdef  XNU_KERNEL_PRIVATE
/*!
 * @function lck_rw_assert
 *
 * @abstract
 * Asserts the rw_lock is held.
 *
 * @discussion
 * read-write locks do not have a concept of ownership when held in shared mode,
 * so this function merely asserts that someone is holding the lock, not necessarily the caller.
 * However if rw_lock_debug is on, a best effort mechanism to track the owners is in place, and
 * this function can be more accurate.
 * Type can be LCK_RW_ASSERT_SHARED, LCK_RW_ASSERT_EXCLUSIVE, LCK_RW_ASSERT_HELD
 * LCK_RW_ASSERT_NOTHELD.
 *
 * @param lck   rw_lock to check.
 * @param type  assert type
 */
extern void             lck_rw_assert(
	lck_rw_t                *lck,
	unsigned int            type);

/*!
 * @function kdp_lck_rw_lock_is_acquired_exclusive
 *
 * @abstract
 * Checks if a rw_lock is held exclusevely.
 *
 * @discussion
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *
 * @param lck   lock to check
 *
 * @returns TRUE if the lock is held exclusevely
 */
extern boolean_t        kdp_lck_rw_lock_is_acquired_exclusive(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_lock_exclusive_check_contended
 *
 * @abstract
 * Locks a rw_lock in exclusive mode.
 *
 * @discussion
 * This routine IS EXPERIMENTAL.
 * It's only used for the vm object lock, and use for other subsystems is UNSUPPORTED.
 * Note that the return value is ONLY A HEURISTIC w.r.t. the lock's contention.
 *
 * @param lck           rw_lock to lock.
 *
 * @returns Returns TRUE if the thread spun or blocked while attempting to acquire the lock, FALSE
 *          otherwise.
 */
extern bool             lck_rw_lock_exclusive_check_contended(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_lock_yield_shared
 *
 * @abstract
 * Yields a rw_lock held in shared mode.
 *
 * @discussion
 * This function can block.
 * Yields the lock in case there are writers waiting.
 * The yield will unlock, block, and re-lock the lock in shared mode.
 *
 * @param lck           rw_lock already held in shared mode to yield.
 * @param force_yield   if set to true it will always yield irrespective of the lock status
 *
 * @returns TRUE if the lock was yield, FALSE otherwise
 */
extern boolean_t        lck_rw_lock_yield_shared(
	lck_rw_t                *lck,
	boolean_t               force_yield);
#endif /* XNU_KERNEL_PRIVATE */

#if MACH_KERNEL_PRIVATE

/*!
 * @function lck_rw_clear_promotion
 *
 * @abstract
 * Undo priority promotions when the last rw_lock
 * is released by a thread (if a promotion was active).
 *
 * @param thread        thread to demote.
 * @param trace_obj     object reason for the demotion.
 */
extern void             lck_rw_clear_promotion(
	thread_t                thread,
	uintptr_t               trace_obj);

/*!
 * @function lck_rw_set_promotion_locked
 *
 * @abstract
 * Callout from context switch if the thread goes
 * off core with a positive rwlock_count.
 *
 * @discussion
 * Called at splsched with the thread locked.
 *
 * @param thread        thread to promote.
 */
extern void             lck_rw_set_promotion_locked(
	thread_t                thread);

#endif /* MACH_KERNEL_PRIVATE */

#ifdef  KERNEL_PRIVATE
/*!
 * @function lck_rw_try_lock_shared
 *
 * @abstract
 * Tries to locks a rw_lock in read mode.
 *
 * @discussion
 * This function will return and not block in case the lock is already held.
 * See lck_rw_lock_shared for more details.
 *
 * @param lck           rw_lock to lock.
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
extern boolean_t        lck_rw_try_lock_shared(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_try_lock_exclusive
 *
 * @abstract
 * Tries to locks a rw_lock in write mode.
 *
 * @discussion
 * This function will return and not block in case the lock is already held.
 * See lck_rw_lock_exclusive for more details.
 *
 * @param lck           rw_lock to lock.
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
extern boolean_t        lck_rw_try_lock_exclusive(
	lck_rw_t                *lck);

/*!
 * @function lck_rw_done
 *
 * @abstract
 * Force unlocks a rw_lock without consistency checks.
 *
 * @discussion
 * Do not use unless sure you can avoid consistency checks.
 *
 * @param lck           rw_lock to unlock.
 */
extern lck_rw_type_t    lck_rw_done(
	lck_rw_t                *lck);
#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_RW_LOCK_H_ */
