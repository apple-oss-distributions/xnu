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

#if XNU_KERNEL_PRIVATE

#define XNU_LCK_RW_DEFAULT_TO_NEW  0

#endif
#if MACH_KERNEL_PRIVATE

/*!
 * @typedef lck_rw_word_t
 *
 * @abstract
 * The lock state for a kernel reader writer lock.
 *
 * @field x_tail
 * The tail for an MCS queue of cores trying to acquire the exclusive-lock.
 *
 * @field valid
 * Bit that should be set to 1 if the lock is properly initialized.
 *
 * @field x_bias
 * Whether exclusive/writer biased (true)
 * or the lock is shared/reader biased (false)
 *
 * @field no_sleep
 * The lock is meant to be used in spin mode always and will never sleep.
 * This is somewhat similar to @c lck_mtx_lock_spin_always() in spirit.
 * This mode is enabled by using the @c LCK_ATTR_RW_NO_SLEEP attribute,
 * and using the lck_rw_*_spin() functions only.
 *
 * @field s_waiters
 * Whether there are any shared waiters
 * (either on the waitq or committed to get to it).
 *
 * @field u_waiter
 * Whether there is an upgrade waiter
 * (either on the waitq or committed to get to it).
 *
 * @field x_waiters
 * Whether there are any exclusive waiters.
 * (either on the waitq or committed to get to it).
 *
 * @field x_urgent
 * Whether there are any exclusive waiters with a priority > MINPRI_FLOOR.
 *
 * @field u_wanted
 * Whether there is a thread wanting to upgrade the lock.
 *
 * @self x_locked
 * Whether the lock is exclusively locked.
 *
 * @field r_count
 * If @c x_locked is false, represents the number of shared lock holders,
 * otherwise the value is garbage.
 *
 * This field must be last so that overflows of the read count
 * do not parturb other bits.
 */
typedef union {
	struct {
		uint16_t        x_tail;

		/* lock configuration bits: these 8 bits are constant */
		bool            valid     : 1;
		bool            x_bias    : 1;
		bool            no_sleep  : 1;
		uint8_t         __config  : 5;

		/* lock waiting bits: describes the state of the wait queues */
		uint8_t         __waiting : 4;
		bool            s_waiters : 1;
		bool            u_waiter  : 1;
		bool            x_waiters : 1;
		bool            x_urgent  : 1;

		/*
		 * lock32 covered bits
		 */
		bool            u_wanted  : 1;
		bool            x_locked  : 1;
		uint32_t        r_count   : 30;
	};
	struct {
		uint16_t        tail16;
		uint8_t         config8;
		uint8_t         wait8;
		uint32_t        lock32;
	};
	uint64_t                lock64;
} lck_rw_word_t;

typedef struct lck_rw_s {
	uint32_t                lck_rw_grp  : LCK_GRP_ID_BITS;
	uint32_t                lck_rw_type : LCK_TYPE_BITS;
	uint32_t                lck_rw_owner;
	lck_rw_word_t           lck_rw;
} lck_rw_new_t;

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
	};
	uint32_t        data;                       /* Single word version of bitfields and shared count */
} lck_rw_word_old_t;

typedef struct lck_rw_old_s {
	uint32_t                lck_rw_unused : 24; /* tsid one day ... */
	uint32_t                lck_rw_type   :  8; /* LCK_TYPE_RW */
	uint32_t                lck_rw_owner;       /* ctid_t */
	lck_rw_word_old_t       lck_rw;
	uint32_t                lck_rw_padding;
} lck_rw_old_t;

#define lck_rw_shared_count     lck_rw.shared_count
#define lck_rw_interlock        lck_rw.interlock
#define lck_rw_priv_excl        lck_rw.priv_excl
#define lck_rw_want_upgrade     lck_rw.want_upgrade
#define lck_rw_want_excl        lck_rw.want_excl
#define lck_r_waiting           lck_rw.r_waiting
#define lck_w_waiting           lck_rw.w_waiting
#define lck_rw_can_sleep        lck_rw.can_sleep
#define lck_rw_data             lck_rw.data
// tag and data reference the same memory. When the tag_valid bit is set,
// the data word should be treated as a tag instead of a bitfield.
#define lck_rw_tag_valid        lck_rw.tag_valid
#define lck_rw_tag              lck_rw.data

#if CONFIG_DTRACE
#define DTRACE_RW_SHARED                0x0     /* reader */
#define DTRACE_RW_EXCL                  0x1     /* writer */
#define DTRACE_RW_NOFLAG                0x0     /* not applicable */
#endif

#elif XNU_KERNEL_PRIVATE

typedef struct {
	uintptr_t               opaque[2] __kernel_data_semantics;
} lck_rw_new_t;

typedef struct {
	uintptr_t               opaque[2] __kernel_data_semantics;
} lck_rw_old_t;

#elif KERNEL_PRIVATE

typedef struct {
	uintptr_t               opaque[2] __kernel_data_semantics;
} lck_rw_t;

#else /* @KERNEL_PRIVATE */

typedef struct __lck_rw_t__     lck_rw_t;

#endif /* !KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE
#if XNU_LCK_RW_DEFAULT_TO_NEW

#define __lck_rw_other_extern   extern __attribute__((overloadable))
#define __lck_rw_old_func       __attribute__((overloadable))
typedef lck_rw_old_t            lck_rw_other_t;

#define __lck_rw_new_func
typedef lck_rw_new_t            lck_rw_t;

#else

#define __lck_rw_other_extern   extern __attribute__((overloadable))
#define __lck_rw_new_func       __attribute__((overloadable))
typedef lck_rw_new_t            lck_rw_other_t;

#define __lck_rw_old_func
typedef lck_rw_old_t            lck_rw_t;

#endif
#endif /* XNU_KERNEL_PRIVATE */

#define decl_lck_rw_data(class, name)   class lck_rw_t name


#pragma mark alloc/init/destroy/free

/*
 * Auto-initializing rw-locks declarations
 * ------------------------------------
 *
 * Unless you need to configure your locks in very specific ways,
 * there is no point creating explicit lock attributes. For most
 * static locks, this declaration macro can be used:
 *
 * - LCK_RW_DEFINE.
 *
 * For cases when some particular attributes need to be used,
 * LCK_RW_DEFINE_ATTR takes a variable declared with
 * LCK_ATTR_DEFINE as an argument.
 */

#define LCK_RW_DEFINE_ATTR(var, grp, attr) \
	lck_rw_t var; \
	static __startup_data struct lck_rw_startup_spec \
	__startup_lck_rw_spec_ ## var = { &var, grp, attr }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_FOURTH, lck_rw_startup_init, \
	    &__startup_lck_rw_spec_ ## var)

#define LCK_RW_DEFINE(var, grp) \
	LCK_RW_DEFINE_ATTR(var, grp, LCK_ATTR_NULL)

#define LCK_RW_OLD_DEFINE(var, grp) \
	lck_rw_old_t var; \
	static __startup_data struct lck_rw_old_startup_spec \
	__startup_lck_rw_spec_ ## var = { &var, grp, NULL }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_FOURTH, lck_rw_old_startup_init, \
	    &__startup_lck_rw_spec_ ## var)

#define LCK_RW_NEW_DEFINE(var, grp) \
	lck_rw_new_t var; \
	static __startup_data struct lck_rw_new_startup_spec \
	__startup_lck_rw_spec_ ## var = { &var, grp, NULL }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_FOURTH, lck_rw_new_startup_init, \
	    &__startup_lck_rw_spec_ ## var)

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


/* obsolete names, use LCK_RW_DEFINE* instead */
#define LCK_RW_DECLARE_ATTR(...)  LCK_RW_DEFINE_ATTR(__VA_ARGS__)
#define LCK_RW_DECLARE(...)       LCK_RW_DEFINE(__VA_ARGS__)


#pragma mark generic interfaces

__enum_closed_decl(lck_rw_type_t, uint32_t, {
#if XNU_KERNEL_PRIVATE
	LCK_RW_TYPE_NONE                = 0,
#endif
	LCK_RW_TYPE_SHARED              = 1,
	LCK_RW_TYPE_EXCLUSIVE           = 2,
#if XNU_KERNEL_PRIVATE
	LCK_RW_TYPE_SHARED_SPIN         = 3,
	LCK_RW_TYPE_EXCLUSIVE_SPIN      = 4,
	LCK_RW_TYPE_ANY                 = UINT32_MAX,
#endif
});

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
 * Tries to lock a rw_lock with the specified type.
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
	lck_rw_type_t           lck_rw_type) __result_use_check;

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

#ifdef KERNEL_PRIVATE

/*!
 * @function lck_rw_done
 *
 * @abstract
 * Force unlocks a rw_lock without consistency checks.
 *
 * @discussion
 * Do not use unless you are sure you can avoid consistency checks.
 *
 * @param lck           rw_lock to unlock.
 */
extern lck_rw_type_t    lck_rw_done(
	lck_rw_t                *lck);

#endif /* KERNEL_PRIVATE */
#pragma mark shared locking

/*!
 * @function lck_rw_lock_shared
 *
 * @abstract
 * Locks a rw_lock in shared mode.
 *
 * @discussion
 * This function can block.
 *
 * Multiple threads can acquire the lock in shared mode at the same time,
 * but only one thread at a time can acquire it in exclusive mode.
 *
 * If the lock is held in shared mode and there are no writers waiting,
 * a reader will be able to acquire the lock without waiting.
 *
 * If the lock is held in shared mode and there is at least a writer waiting,
 * a reader will wait for all the writers to make progress.
 *
 * NOTE: the thread cannot return to userspace while the lock is held.
 *       Recursive locking is not supported.
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
 * Only one reader at a time can upgrade to exclusive mode.
 *
 * If the upgrade fails the function will return with the lock not held.
 *
 * The caller needs to hold the lock in shared mode to upgrade it.
 *
 * @param lck           rw_lock already held in shared mode to upgrade.
 *
 * @returns TRUE if the lock was upgraded, FALSE if it was not possible.
 *          If the function was not able to upgrade the lock, the lock will be dropped
 *          by the function.
 */
#if XNU_KERNEL_PRIVATE
__result_use_check
#endif /* XNU_KERNEL_PRIVATE */
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

#ifdef KERNEL_PRIVATE

/*!
 * @function lck_rw_try_lock_shared
 *
 * @abstract
 * Tries to lock a rw_lock in read mode.
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
	lck_rw_t                *lck) __result_use_check;

#endif /* KERNEL_PRIVATE */
#pragma mark exclusive locking

/*!
 * @function lck_rw_lock_exclusive
 *
 * @abstract
 * Locks a rw_lock in exclusive mode.
 *
 * @discussion
 * This function can block.
 *
 * Multiple threads can acquire the lock in shared mode at the same time,
 * but only one thread at a time can acquire it in exclusive mode.
 *
 * NOTE: the thread cannot return to userspace while the lock is held.
 *       Recursive locking is not supported.
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
 * This function never blocks.
 *
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

#ifdef KERNEL_PRIVATE

/*!
 * @function lck_rw_try_lock_exclusive
 *
 * @abstract
 * Tries to lock a rw_lock in write mode.
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
	lck_rw_t                *lck) __result_use_check;


#endif /* KERNEL_PRIVATE */
#pragma mark assertions
#ifdef KERNEL_PRIVATE

#define LCK_RW_ASSERT_SHARED    0x01
#define LCK_RW_ASSERT_EXCLUSIVE 0x02
#define LCK_RW_ASSERT_HELD      0x03
#define LCK_RW_ASSERT_NOTHELD   0x04
#define LCK_RW_ASSERT_NOT_OWNED 0x05

/*!
 * @function lck_rw_assert
 *
 * @abstract
 * Asserts the rw_lock is held.
 *
 * @discussion
 * read-write locks do not have a concept of ownership when held in shared mode,
 * so this function merely asserts that someone is holding the lock,
 * not necessarily the caller.
 *
 * However if rw_lock_debug is on, a best effort mechanism to track the owners
 * is in place, and this function can be more accurate.
 *
 * Type can be LCK_RW_ASSERT_SHARED, LCK_RW_ASSERT_EXCLUSIVE, LCK_RW_ASSERT_HELD
 * LCK_RW_ASSERT_NOTHELD, and LCK_RW_ASSERT_NOT_OWNED.
 *
 * @param lck   rw_lock to check.
 * @param type  assert type
 */
extern void             lck_rw_assert(
	lck_rw_t               *lck,
	unsigned int            type);

#if MACH_ASSERT
#define LCK_RW_ASSERT(lck, type)       MACH_ASSERT_DO(lck_rw_assert(lck, type))
#else
#define LCK_RW_ASSERT(lck, type)       ((void)(lck), (void)(type))
#endif

#endif /* KERNEL_PRIVATE */
#if XNU_KERNEL_PRIVATE
__exported_push_hidden

/*!
 * @abstract
 * Asserts that the lock is held with the specified type
 *
 * @discussion
 * Unlike lck_rw_assert() the argument is an @c lck_rw_type_t which is
 * consistent with the arguments to @c lck_rw_lock().
 */
extern void             lck_rw_assert_held_type(
	lck_rw_new_t            *lck,
	lck_rw_type_t            type);

#if MACH_ASSERT
#define LCK_RW_ASSERT_TYPE(lck, type)  MACH_ASSERT_DO(lck_rw_assert_type(lck, type))
#else
#define LCK_RW_ASSERT_TYPE(lck, type)   ((void)(lck), (void)(type))
#endif

__exported_pop
#endif /* XNU_KERNEL_PRIVATE */
#pragma mark sleeping

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


#ifdef XNU_KERNEL_PRIVATE
__exported_push_hidden
#pragma mark - XNU Only
#pragma mark spinning mode


/*!
 * @abstract
 * Tries to acquire a lock in shared spin mode.
 *
 * @discussion
 * Behaves like @c lck_rw_try_lock_shared(),
 * but also disables preemption on success.
 *
 * The lock must be unlocked with @c lck_rw_unlock_shared_spin(),
 * or converted to a non spin lock hold using @c lck_rw_convert_nospin(),
 * and then unlocked using @c lck_rw_unlock_shared().
 */
extern bool             lck_rw_try_lock_shared_spin(
	lck_rw_new_t            *lck) __result_use_check;

/*!
 * @abstract
 * Acquires a lock in shared spin mode.
 *
 * @discussion
 * This function can block.
 *
 * Behaves like @c lck_rw_lock_shared(), but also disables preemption.
 *
 * The lock must be unlocked with @c lck_rw_unlock_shared_spin(),
 * or converted to a non spin lock hold using @c lck_rw_convert_nospin(),
 * and then unlocked using @c lck_rw_unlock_shared().
 */
extern void             lck_rw_lock_shared_spin(
	lck_rw_new_t            *lck);

/*!
 * @abstract
 * Attempts to upgrade a reader-writer lock acquired in shared spin mode to
 * exclusive spin mode.
 *
 * @discussion
 * This function can block.
 *
 * Behaves like @c lck_rw_lock_shared_to_exclusive(),
 * but also disables preemption.
 *
 * On success the lock will be held in exclusive spin mode,
 * on failure the lock will be unlocked and preemption reenabled.
 *
 * Note: there is no @c lck_rw_lock_exclusive_to_shared_spin() function because
 *       lck_rw_lock_exclusive_to_shared() never blocks and is preemption
 *       disabled safe.
 */
extern bool             lck_rw_lock_shared_to_exclusive_spin(
	lck_rw_new_t            *lck) __result_use_check;

/*!
 * @abstract
 * Unlocks a lock acquired in shared spin mode.
 *
 * @discussion
 * Behaves like @c lck_rw_unlock_shared(), but also reenables preemption.
 */
extern void             lck_rw_unlock_shared_spin(
	lck_rw_new_t            *lck);


/*!
 * @abstract
 * Tries to acquire a lock in exclusive spin mode.
 *
 * @discussion
 * Behaves like @c lck_rw_try_lock_exclusive(),
 * but also disables preemption on success.
 *
 * The lock must be unlocked with @c lck_rw_unlock_exclusive_spin(),
 * or converted to a non spin lock hold using @c lck_rw_convert_nospin(),
 * and then unlocked using @c lck_rw_unlock_exclusive().
 */
extern void             lck_rw_lock_exclusive_spin(
	lck_rw_new_t            *lck);

/*!
 * @abstract
 * Acquires a lock in exclusive spin mode.
 *
 * @discussion
 * This function can block.
 *
 * Behaves like @c lck_rw_lock_exclusive(), but also disables preemption.
 *
 * The lock must be unlocked with @c lck_rw_unlock_exclusive_spin(),
 * or converted to a non spin lock hold using @c lck_rw_convert_nospin(),
 * and then unlocked using @c lck_rw_unlock_exclusive().
 */
extern bool             lck_rw_try_lock_exclusive_spin(
	lck_rw_new_t            *lck) __result_use_check;

/*!
 * @abstract
 * Unlocks a lock acquired in exclusive spin mode.
 *
 * @discussion
 * Behaves like @c lck_rw_unlock_exclusive(), but also reenables preemption.
 */
extern void             lck_rw_unlock_exclusive_spin(
	lck_rw_new_t            *lck);


/*!
 * @abstract
 * Converts a lock hold from spin mode (exclusive or shared) to non spin.
 *
 * @discussion
 * The lock must have been acquired with @c lck_rw_lock_shared_spin()
 * or @c lck_rw_lock_exclusive_spin().
 */
extern void             lck_rw_convert_nospin(
	lck_rw_new_t            *lck);

/*!
 * @abstract
 * Converts a lock hold to spin mode (exclusive or shared) from non spin.
 *
 * @discussion
 * The lock must have been acquired with @c lck_rw_lock_shared()
 * or @c lck_rw_lock_exclusive().
 */
extern void             lck_rw_convert_spin(
	lck_rw_new_t            *lck);



#pragma mark yielding

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
extern bool             lck_rw_lock_yield_shared(
	lck_rw_t                *lck,
	boolean_t               force_yield);

/*!
 * @function lck_rw_lock_would_yield_shared
 *
 * @abstract
 * Check whether a rw_lock currently held in shared mode would be yielded
 *
 * @discussion
 * This function can be used when lck_rw_lock_yield_shared would be
 * inappropriate due to the need to perform additional housekeeping
 * prior to any yield or when the caller may wish to prematurely terminate
 * an operation rather than resume it after regaining the lock.
 *
 * @param lck           rw_lock already held in shared mode to test for possible yield.
 *
 * @returns TRUE if the lock would be yielded, FALSE otherwise
 */
extern bool             lck_rw_lock_would_yield_shared(
	lck_rw_t                *lck);



__enum_decl(lck_rw_yield_t, uint32_t, {
	LCK_RW_YIELD_WRITERS_ONLY,
	LCK_RW_YIELD_ANY_WAITER,
	LCK_RW_YIELD_ALWAYS,
});

/*!
 * @function lck_rw_lock_yield_exclusive
 *
 * @abstract
 * Yields a rw_lock held in exclusive mode.
 *
 * @discussion
 * This function can block.
 * Yields the lock in case there are writers waiting.
 * The yield will unlock, block, and re-lock the lock in exclusive mode.
 *
 * @param lck           rw_lock already held in exclusive mode to yield.
 * @param mode          when to yield.
 *
 * @returns TRUE if the lock was yield, FALSE otherwise
 */
extern bool             lck_rw_lock_yield_exclusive(
	lck_rw_t                *lck,
	lck_rw_yield_t          mode);

/*!
 * @function lck_rw_lock_would_yield_exclusive
 *
 *
 * @abstract
 * Check whether a rw_lock currently held in exclusive mode would be yielded
 *
 * @discussion
 * This function can be used when lck_rw_lock_yield_exclusive would be
 * inappropriate due to the need to perform additional housekeeping
 * prior to any yield or when the caller may wish to prematurely terminate
 * an operation rather than resume it after regaining the lock.
 *
 * @param lck           rw_lock already held in exclusive mode to yield.
 * @param mode          conditions for a possible yield
 *
 * @returns TRUE if the lock would be yielded, FALSE otherwise
 */
extern bool             lck_rw_lock_would_yield_exclusive(
	lck_rw_t                *lck,
	lck_rw_yield_t          mode);

/*!
 * @abstract
 * Returns whether a lock currently has on core adaptive spinners.
 */
extern bool             lck_rw_has_exclusive_spinners(
	lck_rw_new_t            *lck) __result_use_check;


#pragma mark lock with block
#if MACH_KERNEL_PRIVATE

/*!
 * @function lck_rw_lock_shared_b
 *
 * @abstract
 * Locks a rw_lock in shared mode. Returns early if the lock can't be acquired
 * and the specified block returns true.
 *
 * @discussion
 * Identical to lck_rw_lock_shared() but can return early if the lock can't be
 * acquired and the specified block returns true. The block is called
 * repeatedly when waiting to acquire the lock.
 * Should only be called when the lock cannot sleep (i.e. when
 * lock->lck_rw_can_sleep is false).
 *
 * @param lock           rw_lock to lock.
 * @param lock_pause     block invoked while waiting to acquire lock
 *
 * @returns              Returns TRUE if the lock is successfully taken,
 *                       FALSE if the block returns true and the lock has
 *                       not been acquired.
 */
extern boolean_t        lck_rw_lock_shared_b(
	lck_rw_old_t           * lock,
	bool                  (^lock_pause)(void)) __result_use_check;

/*!
 * @function lck_rw_lock_exclusive_b
 *
 * @abstract
 * Locks a rw_lock in exclusive mode. Returns early if the lock can't be acquired
 * and the specified block returns true.
 *
 * @discussion
 * Identical to lck_rw_lock_exclusive() but can return early if the lock can't be
 * acquired and the specified block returns true. The block is called
 * repeatedly when waiting to acquire the lock.
 * Should only be called when the lock cannot sleep (i.e. when
 * lock->lck_rw_can_sleep is false).
 *
 * @param lock           rw_lock to lock.
 * @param lock_pause     block invoked while waiting to acquire lock
 *
 * @returns              Returns TRUE if the lock is successfully taken,
 *                       FALSE if the block returns true and the lock has
 *                       not been acquired.
 */
extern boolean_t lck_rw_lock_exclusive_b(
	lck_rw_old_t           * lock,
	bool                  (^lock_pause)(void)) __result_use_check;

#endif /* MACH_KERNEL_PRIVATE */
#pragma mark promotion
#if MACH_KERNEL_PRIVATE

/*!
 * @function kdp_lck_rw_lock_is_acquired_exclusive
 *
 * @abstract
 * Checks if a rw_lock is held exclusively.
 *
 * @discussion
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *
 * @param lck   lock to check
 *
 * @returns TRUE if the lock is held exclusively
 */
extern boolean_t        kdp_lck_rw_lock_is_acquired_exclusive(
	lck_rw_t                *lck) __result_use_check;


/*!
 * @function lck_rw_lock_count_inc
 *
 * @abstract
 * Increments the number of rwlock held by the (current) thread.
 */
extern void lck_rw_lock_count_inc(
	thread_t                thread,
	const void             *lock);

/*!
 * @function lck_rw_lock_count_dec
 *
 * @abstract
 * Decrements the number of rwlock held by the (current) thread.
 */
extern void lck_rw_lock_count_dec(
	thread_t                thread,
	const void             *lock);

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
#pragma mark implementation details

struct lck_rw_startup_spec {
	lck_rw_t                *lck;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

struct lck_rw_old_startup_spec {
	lck_rw_old_t            *lck;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

struct lck_rw_new_startup_spec {
	lck_rw_new_t            *lck;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

extern void             lck_rw_startup_init(
	struct lck_rw_startup_spec *spec);

extern void             lck_rw_old_startup_init(
	struct lck_rw_old_startup_spec *spec);

extern void             lck_rw_new_startup_init(
	struct lck_rw_new_startup_spec *spec);


/*!
 * @function lck_rw_is_contended_for_kdbg
 *
 * Check if a lock_rw is contended. The definition of contended used by this
 * function is that the lock is not completely unlocked with no waiters.
 */
extern bool lck_rw_is_contended_for_kdbg(
	lck_rw_new_t * lck);


#if MACH_ASSERT

#define LCK_RW_EXPECTED_MAX_NUMBER      4       /* Expected number per thread of concurrently held rw_lock */

struct __attribute__ ((packed)) rw_lock_debug_entry {
	lck_rw_t      *rwlde_lock;            // rw_lock held
	int8_t        rwlde_mode_count;       // -1 is held in write mode, positive value is the recursive read count
	int32_t       rwlde_caller_packed;    // caller that created the entry
};
typedef struct rw_lock_debug {
	struct rw_lock_debug_entry rwld_locks[LCK_RW_EXPECTED_MAX_NUMBER]; /* rw_lock debug info of currently held locks */
	uint8_t                    rwld_locks_saved : 7,                   /* number of locks saved in rwld_locks */
	    rwld_overflow : 1;                                             /* lock_entry was full, so it might be inaccurate */
	uint32_t                   rwld_locks_acquired;                    /* number of locks acquired */
} *rw_lock_debug_t;

STATIC_IF_KEY_DECLARE_TRUE(lck_rw_debug);

#define lck_rw_assert_enabled()         improbable_static_if(lck_rw_debug)

extern void lck_rw_dbg_assert_canlock_slow(
	void                   *lck,
	lck_rw_type_t           type);

extern void lck_rw_dbg_assert_held_slow(
	void                   *lck,
	lck_rw_type_t           type);

extern void lck_rw_dbg_add_slow(
	void                   *lck,
	lck_rw_type_t           type,
	uintptr_t               caller);

extern void lck_rw_dbg_modify_slow(
	void                   *lck,
	lck_rw_type_t           type,
	uintptr_t               caller);

extern void lck_rw_dbg_remove_slow(
	void                   *lck,
	lck_rw_type_t           type);

#define LCK_RW_DBG_CALL(c, ...) ({ \
	if (lck_rw_assert_enabled()) {                                          \
	        c(__VA_ARGS__);                                                 \
	}                                                                       \
})

#else

#define lck_rw_assert_enabled()         0
#define LCK_RW_DBG_CALL(c, ...)         ((void)0)

#endif

#define lck_rw_dbg_assert_canlock(...) \
	LCK_RW_DBG_CALL(lck_rw_dbg_assert_canlock_slow, __VA_ARGS__)
#define lck_rw_dbg_assert_held(...) \
	LCK_RW_DBG_CALL(lck_rw_dbg_assert_held_slow, __VA_ARGS__)
#define lck_rw_dbg_add(...) \
	LCK_RW_DBG_CALL(lck_rw_dbg_add_slow, __VA_ARGS__)
#define lck_rw_dbg_modify(...) \
	LCK_RW_DBG_CALL(lck_rw_dbg_modify_slow, __VA_ARGS__)
#define lck_rw_dbg_remove(...) \
	LCK_RW_DBG_CALL(lck_rw_dbg_remove_slow, __VA_ARGS__)

__lck_rw_other_extern void           lck_rw_init(lck_rw_other_t *, lck_grp_t *, lck_attr_t *);
__lck_rw_other_extern void           lck_rw_destroy(lck_rw_other_t *, lck_grp_t *);
__lck_rw_other_extern void           lck_rw_lock(lck_rw_other_t *, lck_rw_type_t);
__lck_rw_other_extern boolean_t      lck_rw_try_lock(lck_rw_other_t *, lck_rw_type_t) __result_use_check;
__lck_rw_other_extern void           lck_rw_unlock(lck_rw_other_t *, lck_rw_type_t);
__lck_rw_other_extern void           lck_rw_lock_shared(lck_rw_other_t *);
__lck_rw_other_extern boolean_t      lck_rw_lock_shared_to_exclusive(lck_rw_other_t *) __result_use_check;
__lck_rw_other_extern void           lck_rw_unlock_shared(lck_rw_other_t *);
__lck_rw_other_extern void           lck_rw_lock_exclusive(lck_rw_other_t *);
__lck_rw_other_extern void           lck_rw_lock_exclusive_to_shared(lck_rw_other_t *);
__lck_rw_other_extern void           lck_rw_unlock_exclusive(lck_rw_other_t *);
__lck_rw_other_extern wait_result_t  lck_rw_sleep(lck_rw_other_t *, lck_sleep_action_t, event_t, wait_interrupt_t);
__lck_rw_other_extern wait_result_t  lck_rw_sleep_deadline(lck_rw_other_t *, lck_sleep_action_t, event_t, wait_interrupt_t, uint64_t);
__lck_rw_other_extern boolean_t      kdp_lck_rw_lock_is_acquired_exclusive(lck_rw_other_t *) __result_use_check;
__lck_rw_other_extern bool           lck_rw_lock_yield_shared(lck_rw_other_t *, boolean_t);
__lck_rw_other_extern bool           lck_rw_lock_would_yield_shared(lck_rw_other_t *);
__lck_rw_other_extern bool           lck_rw_lock_yield_exclusive(lck_rw_other_t *, lck_rw_yield_t);
__lck_rw_other_extern bool           lck_rw_lock_would_yield_exclusive(lck_rw_other_t *, lck_rw_yield_t);
__lck_rw_other_extern boolean_t      lck_rw_try_lock_shared(lck_rw_other_t *) __result_use_check;
__lck_rw_other_extern boolean_t      lck_rw_try_lock_exclusive(lck_rw_other_t *) __result_use_check;
__lck_rw_other_extern lck_rw_type_t  lck_rw_done(lck_rw_other_t *);
__lck_rw_other_extern void           lck_rw_assert(lck_rw_other_t *, unsigned int);
__lck_rw_other_extern wait_result_t  lck_rw_sleep_with_inheritor(lck_rw_other_t *, lck_sleep_action_t, event_t, thread_t, wait_interrupt_t, uint64_t);

__exported_pop
#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_RW_LOCK_H_ */
