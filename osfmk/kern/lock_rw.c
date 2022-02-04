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
#include <debug.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>

KALLOC_TYPE_DEFINE(KT_LCK_RW, lck_rw_t, KT_PRIV_ACCT);

#define LCK_RW_WRITER_EVENT(lck)                (event_t)((uintptr_t)(lck)+1)
#define LCK_RW_READER_EVENT(lck)                (event_t)((uintptr_t)(lck)+2)
#define WRITE_EVENT_TO_RWLOCK(event)            ((lck_rw_t *)((uintptr_t)(event)-1))
#define READ_EVENT_TO_RWLOCK(event)             ((lck_rw_t *)((uintptr_t)(event)-2))

#if CONFIG_DTRACE
#define DTRACE_RW_SHARED        0x0     //reader
#define DTRACE_RW_EXCL          0x1     //writer
#define DTRACE_NO_FLAG          0x0     //not applicable
#endif  /* CONFIG_DTRACE */

#define LCK_RW_LCK_EXCLUSIVE_CODE       0x100
#define LCK_RW_LCK_EXCLUSIVE1_CODE      0x101
#define LCK_RW_LCK_SHARED_CODE          0x102
#define LCK_RW_LCK_SH_TO_EX_CODE        0x103
#define LCK_RW_LCK_SH_TO_EX1_CODE       0x104
#define LCK_RW_LCK_EX_TO_SH_CODE        0x105

#if __x86_64__
#define LCK_RW_LCK_EX_WRITER_SPIN_CODE  0x106
#define LCK_RW_LCK_EX_WRITER_WAIT_CODE  0x107
#define LCK_RW_LCK_EX_READER_SPIN_CODE  0x108
#define LCK_RW_LCK_EX_READER_WAIT_CODE  0x109
#define LCK_RW_LCK_SHARED_SPIN_CODE     0x110
#define LCK_RW_LCK_SHARED_WAIT_CODE     0x111
#define LCK_RW_LCK_SH_TO_EX_SPIN_CODE   0x112
#define LCK_RW_LCK_SH_TO_EX_WAIT_CODE   0x113
#endif

#define lck_rw_ilk_lock(lock)   hw_lock_bit  ((hw_lock_bit_t*)(&(lock)->lck_rw_tag), LCK_RW_INTERLOCK_BIT, LCK_GRP_NULL)
#define lck_rw_ilk_unlock(lock) hw_unlock_bit((hw_lock_bit_t*)(&(lock)->lck_rw_tag), LCK_RW_INTERLOCK_BIT)

#define ordered_load_rw(lock)                   os_atomic_load(&(lock)->lck_rw_data, compiler_acq_rel)
#define ordered_store_rw(lock, value)           os_atomic_store(&(lock)->lck_rw_data, (value), compiler_acq_rel)
#define ordered_load_rw_owner(lock)             os_atomic_load(&(lock)->lck_rw_owner, compiler_acq_rel)
#define ordered_store_rw_owner(lock, value)     os_atomic_store(&(lock)->lck_rw_owner, (value), compiler_acq_rel)

#ifdef DEBUG_RW
static TUNABLE(bool, lck_rw_recursive_shared_assert_74048094, "lck_rw_recursive_shared_assert", false);
SECURITY_READ_ONLY_EARLY(vm_packing_params_t) rwlde_caller_packing_params =
    VM_PACKING_PARAMS(LCK_RW_CALLER_PACKED);
#define rw_lock_debug_disabled()                ((LcksOpts & disLkRWDebug) == disLkRWDebug)

#define set_rwlde_caller_packed(entry, caller)          ((entry)->rwlde_caller_packed = VM_PACK_POINTER((vm_offset_t)caller, LCK_RW_CALLER_PACKED))
#define get_rwlde_caller(entry)                         ((void*)VM_UNPACK_POINTER(entry->rwlde_caller_packed, LCK_RW_CALLER_PACKED))

#endif /* DEBUG_RW */

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
lck_rw_t *
lck_rw_alloc_init(
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	lck_rw_t *lck;

	lck = zalloc_flags(KT_LCK_RW, Z_WAITOK | Z_ZERO);
	lck_rw_init(lck, grp, attr);
	return lck;
}

/*!
 * @function lck_rw_init
 *
 * @abstract
 * Initializes a rw_lock_t.
 *
 * @discussion
 * Usage statistics for the lock are going to be added to the lock group provided.
 *
 * The lock attribute can be used to specify the lock contention behaviour.
 * RW_WRITER_PRIORITY is the default behaviour (LCK_ATTR_NULL defaults to RW_WRITER_PRIORITY)
 * and lck_attr_rw_shared_priority() can be used to set the behaviour to RW_SHARED_PRIORITY.
 *
 * RW_WRITER_PRIORITY gives priority to the writers upon contention with the readers;
 * if the lock is held and a writer starts waiting for the lock, readers will not be able
 * to acquire the lock until all writers stop contending. Readers could
 * potentially starve.
 * RW_SHARED_PRIORITY gives priority to the readers upon contention with the writers:
 * unleass the lock is held in exclusive mode, readers will always be able to acquire the lock.
 * Readers can lock a shared lock even if there are writers waiting. Writers could potentially
 * starve.
 *
 * @param lck           lock to initialize.
 * @param grp           lock group to associate with the lock.
 * @param attr          lock attribute to initialize the lock.
 *
 */
void
lck_rw_init(
	lck_rw_t        *lck,
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	if (attr == LCK_ATTR_NULL) {
		attr = &LockDefaultLckAttr;
	}
	memset(lck, 0, sizeof(lck_rw_t));
	lck->lck_rw_can_sleep = TRUE;
	if ((attr->lck_attr_val & LCK_ATTR_RW_SHARED_PRIORITY) == 0) {
		lck->lck_rw_priv_excl = TRUE;
	}

	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_RW);
}

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
void
lck_rw_free(
	lck_rw_t        *lck,
	lck_grp_t       *grp)
{
	lck_rw_destroy(lck, grp);
	zfree(KT_LCK_RW, lck);
}

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
void
lck_rw_destroy(
	lck_rw_t        *lck,
	lck_grp_t       *grp)
{
	if (lck->lck_rw_tag == LCK_RW_TAG_DESTROYED) {
		panic("Destroying previously destroyed lock %p", lck);
	}
	lck_rw_assert(lck, LCK_RW_ASSERT_NOTHELD);

	lck->lck_rw_tag = LCK_RW_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_RW);
	lck_grp_deallocate(grp);
	return;
}

#ifdef DEBUG_RW

/*
 * Best effort mechanism to debug rw_locks.
 *
 * This mechanism is in addition to the owner checks. The owner is set
 * only when the lock is held in exclusive mode so the checks do not cover
 * the cases in which the lock is held in shared mode.
 *
 * This mechanism tentatively stores the rw_lock acquired and its debug
 * information on the thread struct.
 * Just up to LCK_RW_EXPECTED_MAX_NUMBER rw lock debug information can be stored.
 *
 * NOTE: LCK_RW_EXPECTED_MAX_NUMBER is the expected number of rw_locks held
 * at the same time. If a thread holds more than this number of rw_locks we
 * will start losing debug information.
 * Increasing LCK_RW_EXPECTED_MAX_NUMBER will increase the probability we will
 * store the debug information but it will require more memory per thread
 * and longer lock/unlock time.
 *
 * If an empty slot is found for the debug information, we record the lock
 * otherwise we set the overflow threshold flag.
 *
 * If we reached the overflow threshold we might stop asserting because we cannot be sure
 * anymore if the lock was acquired or not.
 *
 * Even if we reached the overflow threshold, we try to store the debug information
 * for the new locks acquired. This can be useful in core dumps to debug
 * possible return to userspace without unlocking and to find possible readers
 * holding the lock.
 */
void
rw_lock_init(void)
{
	if (kern_feature_override(KF_RW_LOCK_DEBUG_OVRD)) {
		LcksOpts |= disLkRWDebug;
	}
}

static inline struct rw_lock_debug_entry *
find_lock_in_savedlocks(lck_rw_t* lock, rw_lock_debug_t *rw_locks_held)
{
	int i;
	for (i = 0; i < LCK_RW_EXPECTED_MAX_NUMBER; i++) {
		struct rw_lock_debug_entry *existing = &rw_locks_held->rwld_locks[i];
		if (existing->rwlde_lock == lock) {
			return existing;
		}
	}

	return NULL;
}

__abortlike
static void
rwlock_slot_panic(rw_lock_debug_t *rw_locks_held)
{
	panic("No empty slot found in %p slot_used %d", rw_locks_held, rw_locks_held->rwld_locks_saved);
}

static inline struct rw_lock_debug_entry *
find_empty_slot(rw_lock_debug_t *rw_locks_held)
{
	int i;
	for (i = 0; i < LCK_RW_EXPECTED_MAX_NUMBER; i++) {
		struct rw_lock_debug_entry *entry = &rw_locks_held->rwld_locks[i];
		if (entry->rwlde_lock == NULL) {
			return entry;
		}
	}
	rwlock_slot_panic(rw_locks_held);
}

__abortlike
static void
canlock_rwlock_panic(lck_rw_t* lock, thread_t thread, struct rw_lock_debug_entry *entry)
{
	panic("RW lock %p already held by %p caller %p mode_count %d state 0x%x owner 0x%p ",
	    lock, thread, get_rwlde_caller(entry), entry->rwlde_mode_count,
	    ordered_load_rw(lock), ordered_load_rw_owner(lock));
}

static inline void
assert_canlock_rwlock(lck_rw_t* lock, thread_t thread, lck_rw_type_t type)
{
	rw_lock_debug_t *rw_locks_held = &thread->rw_lock_held;

	if (__probable(rw_lock_debug_disabled() || (rw_locks_held->rwld_locks_acquired == 0))) {
		//no locks saved, safe to lock
		return;
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__improbable(entry != NULL)) {
		boolean_t can_be_shared_recursive;
		if (lck_rw_recursive_shared_assert_74048094) {
			can_be_shared_recursive = (lock->lck_rw_priv_excl == 0);
		} else {
			/* currently rw_lock_shared is called recursively,
			 * until the code is fixed allow to lock
			 * recursively in shared mode
			 */
			can_be_shared_recursive = TRUE;
		}
		if ((type == LCK_RW_TYPE_SHARED) && can_be_shared_recursive && entry->rwlde_mode_count >= 1) {
			return;
		}
		canlock_rwlock_panic(lock, thread, entry);
	}
}

__abortlike
static void
held_rwlock_notheld_panic(lck_rw_t* lock, thread_t thread)
{
	panic("RW lock %p not held by %p", lock, thread);
}

__abortlike
static void
held_rwlock_notheld_with_info_panic(lck_rw_t* lock, thread_t thread, lck_rw_type_t type, struct rw_lock_debug_entry *entry)
{
	if (type == LCK_RW_TYPE_EXCLUSIVE) {
		panic("RW lock %p not held in exclusive by %p caller %p read %d state 0x%x owner 0x%p ",
		    lock, thread, get_rwlde_caller(entry), entry->rwlde_mode_count,
		    ordered_load_rw(lock), ordered_load_rw_owner(lock));
	} else {
		panic("RW lock %p not held in shared by %p caller %p read %d state 0x%x owner 0x%p ",
		    lock, thread, get_rwlde_caller(entry), entry->rwlde_mode_count,
		    ordered_load_rw(lock), ordered_load_rw_owner(lock));
	}
}

static inline void
assert_held_rwlock(lck_rw_t* lock, thread_t thread, lck_rw_type_t type)
{
	rw_lock_debug_t *rw_locks_held = &thread->rw_lock_held;

	if (__probable(rw_lock_debug_disabled())) {
		return;
	}

	if (__improbable(rw_locks_held->rwld_locks_acquired == 0 || rw_locks_held->rwld_locks_saved == 0)) {
		if (rw_locks_held->rwld_locks_acquired == 0 || rw_locks_held->rwld_overflow == 0) {
			held_rwlock_notheld_panic(lock, thread);
		}
		return;
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__probable(entry != NULL)) {
		if (type == LCK_RW_TYPE_EXCLUSIVE && entry->rwlde_mode_count != -1) {
			held_rwlock_notheld_with_info_panic(lock, thread, type, entry);
		} else {
			if (type == LCK_RW_TYPE_SHARED && entry->rwlde_mode_count <= 0) {
				held_rwlock_notheld_with_info_panic(lock, thread, type, entry);
			}
		}
	} else {
		if (rw_locks_held->rwld_overflow == 0) {
			held_rwlock_notheld_panic(lock, thread);
		}
	}
}

static inline void
change_held_rwlock(lck_rw_t* lock, thread_t thread, lck_rw_type_t typeFrom, void* caller)
{
	rw_lock_debug_t *rw_locks_held = &thread->rw_lock_held;

	if (__probable(rw_lock_debug_disabled())) {
		return;
	}

	if (__improbable(rw_locks_held->rwld_locks_saved == 0)) {
		if (rw_locks_held->rwld_overflow == 0) {
			held_rwlock_notheld_panic(lock, thread);
		}
		return;
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__probable(entry != NULL)) {
		if (typeFrom == LCK_RW_TYPE_SHARED) {
			//We are upgrading
			assertf(entry->rwlde_mode_count == 1,
			    "RW lock %p not held by a single shared when upgrading "
			    "by %p caller %p read %d state 0x%x owner 0x%p ",
			    lock, thread, get_rwlde_caller(entry), entry->rwlde_mode_count,
			    ordered_load_rw(lock), ordered_load_rw_owner(lock));
			entry->rwlde_mode_count = -1;
			set_rwlde_caller_packed(entry, caller);
		} else {
			//We are downgrading
			assertf(entry->rwlde_mode_count == -1,
			    "RW lock %p not held in write mode when downgrading "
			    "by %p caller %p read %d state 0x%x owner 0x%p ",
			    lock, thread, get_rwlde_caller(entry), entry->rwlde_mode_count,
			    ordered_load_rw(lock), ordered_load_rw_owner(lock));
			entry->rwlde_mode_count = 1;
			set_rwlde_caller_packed(entry, caller);
		}
		return;
	}

	if (rw_locks_held->rwld_overflow == 0) {
		held_rwlock_notheld_panic(lock, thread);
	}

	if (rw_locks_held->rwld_locks_saved == LCK_RW_EXPECTED_MAX_NUMBER) {
		//array is full
		return;
	}

	struct rw_lock_debug_entry *null_entry = find_empty_slot(rw_locks_held);
	null_entry->rwlde_lock = lock;
	set_rwlde_caller_packed(null_entry, caller);
	if (typeFrom == LCK_RW_TYPE_SHARED) {
		null_entry->rwlde_mode_count = -1;
	} else {
		null_entry->rwlde_mode_count = 1;
	}
	rw_locks_held->rwld_locks_saved++;
}

__abortlike
static void
add_held_rwlock_too_many_panic(thread_t thread)
{
	panic("RW lock too many rw locks held, rwld_locks_acquired maxed out for thread %p", thread);
}

static inline void
add_held_rwlock(lck_rw_t* lock, thread_t thread, lck_rw_type_t type, void* caller)
{
	rw_lock_debug_t *rw_locks_held = &thread->rw_lock_held;
	struct rw_lock_debug_entry *null_entry;

	if (__probable(rw_lock_debug_disabled())) {
		return;
	}

	if (__improbable(rw_locks_held->rwld_locks_acquired == UINT32_MAX)) {
		add_held_rwlock_too_many_panic(thread);
	}
	rw_locks_held->rwld_locks_acquired++;

	if (type == LCK_RW_TYPE_EXCLUSIVE) {
		if (__improbable(rw_locks_held->rwld_locks_saved == LCK_RW_EXPECTED_MAX_NUMBER)) {
			//array is full
			rw_locks_held->rwld_overflow = 1;
			return;
		}
		null_entry = find_empty_slot(rw_locks_held);
		null_entry->rwlde_lock = lock;
		set_rwlde_caller_packed(null_entry, caller);
		null_entry->rwlde_mode_count = -1;
		rw_locks_held->rwld_locks_saved++;
		return;
	} else {
		if (__probable(rw_locks_held->rwld_locks_saved == 0)) {
			//array is empty
			goto add_shared;
		}

		boolean_t allow_shared_recursive;
		if (lck_rw_recursive_shared_assert_74048094) {
			allow_shared_recursive = (lock->lck_rw_priv_excl == 0);
		} else {
			allow_shared_recursive = TRUE;
		}
		if (allow_shared_recursive) {
			//It could be already locked in shared mode
			struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
			if (entry != NULL) {
				assert(entry->rwlde_mode_count > 0);
				assertf(entry->rwlde_mode_count != INT8_MAX,
				    "RW lock %p with too many recursive shared held "
				    "from %p caller %p read %d state 0x%x owner 0x%p",
				    lock, thread, get_rwlde_caller(entry), entry->rwlde_mode_count,
				    ordered_load_rw(lock), ordered_load_rw_owner(lock));
				entry->rwlde_mode_count += 1;
				return;
			}
		}

		//none of the locks were a match
		//try to add a new entry
		if (__improbable(rw_locks_held->rwld_locks_saved == LCK_RW_EXPECTED_MAX_NUMBER)) {
			//array is full
			rw_locks_held->rwld_overflow = 1;
			return;
		}

add_shared:
		null_entry = find_empty_slot(rw_locks_held);
		null_entry->rwlde_lock = lock;
		set_rwlde_caller_packed(null_entry, caller);
		null_entry->rwlde_mode_count = 1;
		rw_locks_held->rwld_locks_saved++;
	}
}

static inline void
remove_held_rwlock(lck_rw_t* lock, thread_t thread, lck_rw_type_t type)
{
	rw_lock_debug_t *rw_locks_held = &thread->rw_lock_held;

	if (__probable(rw_lock_debug_disabled())) {
		return;
	}

	if (__improbable(rw_locks_held->rwld_locks_acquired == 0)) {
		return;
	}
	rw_locks_held->rwld_locks_acquired--;

	if (rw_locks_held->rwld_locks_saved == 0) {
		assert(rw_locks_held->rwld_overflow == 1);
		goto out;
	}

	struct rw_lock_debug_entry *entry = find_lock_in_savedlocks(lock, rw_locks_held);
	if (__probable(entry != NULL)) {
		if (type == LCK_RW_TYPE_EXCLUSIVE) {
			assert(entry->rwlde_mode_count == -1);
			entry->rwlde_mode_count = 0;
		} else {
			assert(entry->rwlde_mode_count > 0);
			entry->rwlde_mode_count--;
			if (entry->rwlde_mode_count > 0) {
				goto out;
			}
		}
		entry->rwlde_caller_packed = 0;
		entry->rwlde_lock = NULL;
		rw_locks_held->rwld_locks_saved--;
	} else {
		assert(rw_locks_held->rwld_overflow == 1);
	}

out:
	if (rw_locks_held->rwld_locks_acquired == 0) {
		rw_locks_held->rwld_overflow = 0;
	}
	return;
}
#endif /* DEBUG_RW */

/*
 * We disable interrupts while holding the RW interlock to prevent an
 * interrupt from exacerbating hold time.
 * Hence, local helper functions lck_interlock_lock()/lck_interlock_unlock().
 */
static inline boolean_t
lck_interlock_lock(
	lck_rw_t        *lck)
{
	boolean_t       istate;

	istate = ml_set_interrupts_enabled(FALSE);
	lck_rw_ilk_lock(lck);
	return istate;
}

static inline void
lck_interlock_unlock(
	lck_rw_t        *lck,
	boolean_t       istate)
{
	lck_rw_ilk_unlock(lck);
	ml_set_interrupts_enabled(istate);
}

static inline void
lck_rw_inc_thread_count(
	thread_t thread)
{
	__assert_only uint32_t prev_rwlock_count;

	prev_rwlock_count = thread->rwlock_count++;
#if MACH_ASSERT
	/*
	 * Set the ast to check that the
	 * rwlock_count is going to be set to zero when
	 * going back to userspace.
	 * Set it only once when we increment it for the first time.
	 */
	if (prev_rwlock_count == 0) {
		act_set_debug_assert();
	}
#endif
}

/*
 * compute the deadline to spin against when
 * waiting for a change of state on a lck_rw_t
 */
static inline uint64_t
lck_rw_deadline_for_spin(
	lck_rw_t        *lck)
{
	lck_rw_word_t   word;

	word.data = ordered_load_rw(lck);
	if (word.can_sleep) {
		if (word.r_waiting || word.w_waiting || (word.shared_count > machine_info.max_cpus)) {
			/*
			 * there are already threads waiting on this lock... this
			 * implies that they have spun beyond their deadlines waiting for
			 * the desired state to show up so we will not bother spinning at this time...
			 *   or
			 * the current number of threads sharing this lock exceeds our capacity to run them
			 * concurrently and since all states we're going to spin for require the rw_shared_count
			 * to be at 0, we'll not bother spinning since the latency for this to happen is
			 * unpredictable...
			 */
			return mach_absolute_time();
		}
		return mach_absolute_time() + os_atomic_load(&MutexSpin, relaxed);
	} else {
		return mach_absolute_time() + (100000LL * 1000000000LL);
	}
}

/*
 * This inline is used when busy-waiting for an rw lock.
 * If interrupts were disabled when the lock primitive was called,
 * we poll the IPI handler for pending tlb flushes in x86.
 */
static inline void
lck_rw_lock_pause(
	boolean_t       interrupts_enabled)
{
#if X86_64
	if (!interrupts_enabled) {
		handle_pending_TLB_flushes();
	}
	cpu_pause();
#else
	(void) interrupts_enabled;
	wait_for_event();
#endif
}

static boolean_t
lck_rw_drain_status(
	lck_rw_t        *lock,
	uint32_t        status_mask,
	boolean_t       wait)
{
	uint64_t        deadline = 0;
	uint32_t        data;
	boolean_t       istate = FALSE;

	if (wait) {
		deadline = lck_rw_deadline_for_spin(lock);
#if __x86_64__
		istate = ml_get_interrupts_enabled();
#endif
	}

	for (;;) {
#if __x86_64__
		data = os_atomic_load(&lock->lck_rw_data, relaxed);
#else
		data = load_exclusive32(&lock->lck_rw_data, memory_order_acquire_smp);
#endif
		if ((data & status_mask) == 0) {
			break;
		}
		if (wait) {
			lck_rw_lock_pause(istate);
		} else {
			atomic_exchange_abort();
		}
		if (!wait || (mach_absolute_time() >= deadline)) {
			return FALSE;
		}
	}
	atomic_exchange_abort();
	return TRUE;
}

/*
 * Spin while interlock is held.
 */
static inline void
lck_rw_interlock_spin(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_relaxed);
		if (data & LCK_RW_INTERLOCK) {
#if __x86_64__
			cpu_pause();
#else
			wait_for_event();
#endif
		} else {
			atomic_exchange_abort();
			return;
		}
	}
}

#define LCK_RW_GRAB_WANT        0
#define LCK_RW_GRAB_SHARED      1

static boolean_t
lck_rw_grab(
	lck_rw_t        *lock,
	int             mode,
	boolean_t       wait)
{
	uint64_t        deadline = 0;
	uint32_t        data, prev;
	boolean_t       do_exch, istate = FALSE;

	if (wait) {
		deadline = lck_rw_deadline_for_spin(lock);
#if __x86_64__
		istate = ml_get_interrupts_enabled();
#endif
	}

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		do_exch = FALSE;
		if (mode == LCK_RW_GRAB_WANT) {
			if ((data & LCK_RW_WANT_EXCL) == 0) {
				data |= LCK_RW_WANT_EXCL;
				do_exch = TRUE;
			}
		} else {        // LCK_RW_GRAB_SHARED
			if (((data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) == 0) ||
			    (((data & LCK_RW_SHARED_MASK)) && ((data & LCK_RW_PRIV_EXCL) == 0))) {
				data += LCK_RW_SHARED_READER;
				do_exch = TRUE;
			}
		}
		if (do_exch) {
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				return TRUE;
			}
		} else {
			if (wait) {
				lck_rw_lock_pause(istate);
			} else {
				atomic_exchange_abort();
			}
			if (!wait || (mach_absolute_time() >= deadline)) {
				return FALSE;
			}
		}
	}
}

static void
lck_rw_lock_exclusive_gen(
	lck_rw_t        *lock)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	lck_rw_word_t           word;
	int                     slept = 0;
	boolean_t               gotlock = 0;
	boolean_t               not_shared_or_upgrade = 0;
	wait_result_t           res = 0;
	boolean_t               istate;

#if     CONFIG_DTRACE
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_excl_spin, dtrace_rwl_excl_block, dtrace_ls_enabled = FALSE;
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
#endif

	__assert_only thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner != current_thread(), "Lock already held state=0x%x, owner=%p",
	    ordered_load_rw(lock), owner);

#ifdef DEBUG_RW
	/*
	 * Best effort attempt to check that this thread
	 * is not already holding the lock (this checks read mode too).
	 */
	assert_canlock_rwlock(lock, current_thread(), LCK_RW_TYPE_EXCLUSIVE);
#endif /* DEBUG_RW */

	/*
	 *	Try to acquire the lck_rw_want_excl bit.
	 */
	while (!lck_rw_grab(lock, LCK_RW_GRAB_WANT, FALSE)) {
#if     CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] != 0);
			dtrace_rwl_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_excl_spin || dtrace_rwl_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lock->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		gotlock = lck_rw_grab(lock, LCK_RW_GRAB_WANT, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, gotlock, 0);

		if (gotlock) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		word.data = ordered_load_rw(lock);
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);
			word.data = ordered_load_rw(lock);

			if (word.want_excl) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);
				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				word.want_excl = 1;
				ordered_store_rw(lock, word.data);
				lck_interlock_unlock(lock, istate);
				break;
			}
		}
	}
	/*
	 * Wait for readers (and upgrades) to finish...
	 */
	while (!lck_rw_drain_status(lock, LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE, FALSE)) {
#if     CONFIG_DTRACE
		/*
		 * Either sleeping or spinning is happening, start
		 * a timing of our delay interval now.  If we set it
		 * to -1 we don't have accurate data so we cannot later
		 * decide to record a dtrace spin or sleep event.
		 */
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] != 0);
			dtrace_rwl_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_excl_spin || dtrace_rwl_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lock->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		not_shared_or_upgrade = lck_rw_drain_status(lock, LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, not_shared_or_upgrade, 0);

		if (not_shared_or_upgrade) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		word.data = ordered_load_rw(lock);
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);
			word.data = ordered_load_rw(lock);

			if (word.shared_count != 0 || word.want_upgrade) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lock, istate);
				/*
				 * must own the lock now, since we checked for
				 * readers or upgrade owner behind the interlock
				 * no need for a call to 'lck_rw_drain_status'
				 */
				break;
			}
		}
	}

#if     CONFIG_DTRACE
	/*
	 * Decide what latencies we suffered that are Dtrace events.
	 * If we have set wait_interval, then we either spun or slept.
	 * At least we get out from under the interlock before we record
	 * which is the best we can do here to minimize the impact
	 * of the tracing.
	 * If we have set wait_interval to -1, then dtrace was not enabled when we
	 * started sleeping/spinning so we don't record this event.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_SPIN, lock,
			    mach_absolute_time() - wait_interval, 1);
		} else {
			/*
			 * For the blocking case, we also record if when we blocked
			 * it was held for read or write, and how many readers.
			 * Notice that above we recorded this before we dropped
			 * the interlock so the count is accurate.
			 */
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_BLOCK, lock,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, 1);
#endif  /* CONFIG_DTRACE */
}

#define LCK_RW_LOCK_EXCLUSIVE_TAS(lck) (atomic_test_and_set32(&(lck)->lck_rw_data, \
	    (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK), \
	    LCK_RW_WANT_EXCL, memory_order_acquire_smp, FALSE))
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
 * @param lock           rw_lock to lock.
 *
 * @returns Returns TRUE if the thread spun or blocked while attempting to acquire the lock, FALSE
 *          otherwise.
 */
bool
lck_rw_lock_exclusive_check_contended(
	lck_rw_t        *lock)
{
	thread_t        thread = current_thread();
	bool            contended  = false;

	if (lock->lck_rw_can_sleep) {
		lck_rw_inc_thread_count(thread);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	if (LCK_RW_LOCK_EXCLUSIVE_TAS(lock)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */
	} else {
		contended = true;
		lck_rw_lock_exclusive_gen(lock);
	}
	__assert_only thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);

	ordered_store_rw_owner(lock, thread);

#ifdef DEBUG_RW
	add_held_rwlock(lock, thread, LCK_RW_TYPE_EXCLUSIVE, __builtin_return_address(0));
#endif /* DEBUG_RW */
	return contended;
}

__attribute__((always_inline))
static void
lck_rw_lock_exclusive_internal_inline(
	lck_rw_t        *lock,
	void            *caller)
{
#pragma unused(caller)
	thread_t        thread = current_thread();

	if (lock->lck_rw_can_sleep) {
		lck_rw_inc_thread_count(thread);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	if (LCK_RW_LOCK_EXCLUSIVE_TAS(lock)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */
	} else {
		lck_rw_lock_exclusive_gen(lock);
	}

	__assert_only thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);

	ordered_store_rw_owner(lock, thread);

#if DEBUG_RW
	add_held_rwlock(lock, thread, LCK_RW_TYPE_EXCLUSIVE, caller);
#endif /* DEBUG_RW */
}

__attribute__((noinline))
static void
lck_rw_lock_exclusive_internal(
	lck_rw_t        *lock,
	void            *caller)
{
	lck_rw_lock_exclusive_internal_inline(lock, caller);
}

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
 * @param lock           rw_lock to lock.
 */
void
lck_rw_lock_exclusive(
	lck_rw_t        *lock)
{
	lck_rw_lock_exclusive_internal_inline(lock, __builtin_return_address(0));
}

/*
 *	Routine:	lck_rw_lock_shared_gen
 *	Function:
 *		Fast path code has determined that this lock
 *		is held exclusively... this is where we spin/block
 *		until we can acquire the lock in the shared mode
 */
static void
lck_rw_lock_shared_gen(
	lck_rw_t        *lck)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	lck_rw_word_t           word;
	boolean_t               gotlock = 0;
	int                     slept = 0;
	wait_result_t           res = 0;
	boolean_t               istate;

#if     CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_shared_spin, dtrace_rwl_shared_block, dtrace_ls_enabled = FALSE;
#endif /* CONFIG_DTRACE */

	__assert_only thread_t owner = ordered_load_rw_owner(lck);
	assertf(owner != current_thread(), "Lock already held state=0x%x, owner=%p",
	    ordered_load_rw(lck), owner);
#ifdef DEBUG_RW
	/*
	 * Best effort attempt to check that this thread
	 * is not already holding the lock in shared mode.
	 */
	assert_canlock_rwlock(lck, current_thread(), LCK_RW_TYPE_SHARED);
#endif

	while (!lck_rw_grab(lck, LCK_RW_GRAB_SHARED, FALSE)) {
#if     CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_shared_spin = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_SPIN] != 0);
			dtrace_rwl_shared_block = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_shared_spin || dtrace_rwl_shared_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lck->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, 0, 0);

		gotlock = lck_rw_grab(lck, LCK_RW_GRAB_SHARED, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, gotlock, 0);

		if (gotlock) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock for read
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {
			istate = lck_interlock_lock(lck);

			word.data = ordered_load_rw(lck);
			if ((word.want_excl || word.want_upgrade) &&
			    ((word.shared_count == 0) || word.priv_excl)) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_START,
				    trace_lck, word.want_excl, word.want_upgrade, 0, 0);

				word.r_waiting = 1;
				ordered_store_rw(lck, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockRead);
				res = assert_wait(LCK_RW_READER_EVENT(lck),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_END,
				    trace_lck, res, slept, 0, 0);
			} else {
				word.shared_count++;
				ordered_store_rw(lck, word.data);
				lck_interlock_unlock(lck, istate);
				break;
			}
		}
	}

#if     CONFIG_DTRACE
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 0,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lck, 0);
#endif  /* CONFIG_DTRACE */
}

__attribute__((always_inline))
static void
lck_rw_lock_shared_internal_inline(
	lck_rw_t        *lock,
	void            *caller)
{
#pragma unused(caller)

	uint32_t        data, prev;
	thread_t        thread = current_thread();
	__assert_only thread_t owner;
#ifdef DEBUG_RW
	boolean_t       check_canlock = TRUE;
#endif

	if (lock->lck_rw_can_sleep) {
		lck_rw_inc_thread_count(thread);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK)) {
			atomic_exchange_abort();
			lck_rw_lock_shared_gen(lock);
			goto locked;
		}
#ifdef DEBUG_RW
		if ((data & LCK_RW_SHARED_MASK) == 0) {
			/*
			 * If the lock is uncontended,
			 * we do not need to check if we can lock it
			 */
			check_canlock = FALSE;
		}
#endif
		data += LCK_RW_SHARED_READER;
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
#ifdef DEBUG_RW
	if (check_canlock) {
		/*
		 * Best effort attempt to check that this thread
		 * is not already holding the lock (this checks read mode too).
		 */
		assert_canlock_rwlock(lock, thread, LCK_RW_TYPE_SHARED);
	}
#endif
locked:
	owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif  /* CONFIG_DTRACE */

#ifdef DEBUG_RW
	add_held_rwlock(lock, thread, LCK_RW_TYPE_SHARED, caller);
#endif /* DEBUG_RW */
}

__attribute__((noinline))
static void
lck_rw_lock_shared_internal(
	lck_rw_t        *lock,
	void            *caller)
{
	lck_rw_lock_shared_internal_inline(lock, caller);
}

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
 * for all the writers to make progress if the lock was initialized with the default settings. Instead if
 * RW_SHARED_PRIORITY was selected at initialization time, a reader will never wait if the lock is held
 * in shared mode.
 * NOTE: the thread cannot return to userspace while the lock is held. Recursive locking is not supported.
 *
 * @param lock           rw_lock to lock.
 */
void
lck_rw_lock_shared(
	lck_rw_t        *lock)
{
	lck_rw_lock_shared_internal_inline(lock, __builtin_return_address(0));
}

/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_failure
 *	Function:
 *		Fast path code has already dropped our read
 *		count and determined that someone else owns 'lck_rw_want_upgrade'
 *		if 'lck_rw_shared_count' == 0, its also already dropped 'lck_w_waiting'
 *		all we need to do here is determine if a wakeup is needed
 */
static boolean_t
lck_rw_lock_shared_to_exclusive_failure(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	thread_t        thread = current_thread();
	uint32_t        rwlock_count;

	if ((prior_lock_state & LCK_RW_W_WAITING) &&
	    ((prior_lock_state & LCK_RW_SHARED_MASK) == LCK_RW_SHARED_READER)) {
		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released the read lock, wake
		 *	him up if he's blocked waiting
		 */
		thread_wakeup(LCK_RW_WRITER_EVENT(lck));
	}

	/* Check if dropping the lock means that we need to unpromote */
	if (lck->lck_rw_can_sleep) {
		rwlock_count = thread->rwlock_count--;
	} else {
		rwlock_count = UINT32_MAX;
	}

	if (rwlock_count == 0) {
		panic("rw lock count underflow for thread %p", thread);
	}

	if ((rwlock_count == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		/* sched_flags checked without lock, but will be rechecked while clearing */
		lck_rw_clear_promotion(thread, unslide_for_kdebug(lck));
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), lck->lck_rw_shared_count, lck->lck_rw_want_upgrade, 0, 0);

#ifdef DEBUG_RW
	remove_held_rwlock(lck, thread, LCK_RW_TYPE_SHARED);
#endif /* DEBUG_RW */

	return FALSE;
}

/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_success
 *	Function:
 *		the fast path code has already dropped our read
 *		count and successfully acquired 'lck_rw_want_upgrade'
 *		we just need to wait for the rest of the readers to drain
 *		and then we can return as the exclusive holder of this lock
 */
static void
lck_rw_lock_shared_to_exclusive_success(
	lck_rw_t        *lock)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	int                     slept = 0;
	lck_rw_word_t           word;
	wait_result_t           res;
	boolean_t               istate;
	boolean_t               not_shared;

#if     CONFIG_DTRACE
	uint64_t                wait_interval = 0;
	int                     readers_at_sleep = 0;
	boolean_t               dtrace_ls_initialized = FALSE;
	boolean_t               dtrace_rwl_shared_to_excl_spin, dtrace_rwl_shared_to_excl_block, dtrace_ls_enabled = FALSE;
#endif

	while (!lck_rw_drain_status(lock, LCK_RW_SHARED_MASK, FALSE)) {
		word.data = ordered_load_rw(lock);
#if     CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_shared_to_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN] != 0);
			dtrace_rwl_shared_to_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_shared_to_excl_spin || dtrace_rwl_shared_to_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = word.shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, word.shared_count, 0, 0, 0);

		not_shared = lck_rw_drain_status(lock, LCK_RW_SHARED_MASK, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, lock->lck_rw_shared_count, 0, 0, 0);

		if (not_shared) {
			break;
		}

		/*
		 * if we get here, the spin deadline in lck_rw_wait_on_status()
		 * has expired w/o the rw_shared_count having drained to 0
		 * check to see if we're allowed to do a thread_block
		 */
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);

			word.data = ordered_load_rw(lock);
			if (word.shared_count != 0) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_START,
				    trace_lck, word.shared_count, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockUpgrade);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_END,
				    trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lock, istate);
				break;
			}
		}
	}
#if     CONFIG_DTRACE
	/*
	 * We infer whether we took the sleep/spin path above by checking readers_at_sleep.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, lock, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, lock,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 1);
#endif
}

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
 * @param lock           rw_lock already held in shared mode to upgrade.
 *
 * @returns TRUE if the lock was upgraded, FALSE if it was not possible.
 *          If the function was not able to upgrade the lock, the lock will be dropped
 *          by the function.
 */
boolean_t
lck_rw_lock_shared_to_exclusive(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;

	assertf(lock->lck_rw_priv_excl != 0, "lock %p thread %p", lock, current_thread());

#if DEBUG_RW
	thread_t thread = current_thread();
	assert_held_rwlock(lock, thread, LCK_RW_TYPE_SHARED);
#endif /* DEBUG_RW */

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_WANT_UPGRADE) {
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0) {         /* we were the last reader */
				data &= ~(LCK_RW_W_WAITING);            /* so clear the wait indicator */
			}
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				return lck_rw_lock_shared_to_exclusive_failure(lock, prev);
			}
		} else {
			data |= LCK_RW_WANT_UPGRADE;            /* ask for WANT_UPGRADE */
			data -= LCK_RW_SHARED_READER;           /* and shed our read count */
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				break;
			}
		}
		cpu_pause();
	}
	/* we now own the WANT_UPGRADE */
	if (data & LCK_RW_SHARED_MASK) {        /* check to see if all of the readers are drained */
		lck_rw_lock_shared_to_exclusive_success(lock);  /* if not, we need to go wait */
	}
	__assert_only thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);

	ordered_store_rw_owner(lock, current_thread());
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 0);
#endif  /* CONFIG_DTRACE */

#if DEBUG_RW
	change_held_rwlock(lock, thread, LCK_RW_TYPE_SHARED, __builtin_return_address(0));
#endif /* DEBUG_RW */
	return TRUE;
}

/*
 *      Routine:        lck_rw_lock_exclusive_to_shared_gen
 *      Function:
 *		Fast path has already dropped
 *		our exclusive state and bumped lck_rw_shared_count
 *		all we need to do here is determine if anyone
 *		needs to be awakened.
 */
static void
lck_rw_lock_exclusive_to_shared_gen(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state,
	void            *caller)
{
#pragma unused(caller)
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	lck_rw_word_t   fake_lck;

	/*
	 * prior_lock state is a snapshot of the 1st word of the
	 * lock in question... we'll fake up a pointer to it
	 * and carefully not access anything beyond whats defined
	 * in the first word of a lck_rw_t
	 */
	fake_lck.data = prior_lock_state;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_START,
	    trace_lck, fake_lck->want_excl, fake_lck->want_upgrade, 0, 0);

	/*
	 * don't wake up anyone waiting to take the lock exclusively
	 * since we hold a read count... when the read count drops to 0,
	 * the writers will be woken.
	 *
	 * wake up any waiting readers if we don't have any writers waiting,
	 * or the lock is NOT marked as rw_priv_excl (writers have privilege)
	 */
	if (!(fake_lck.priv_excl && fake_lck.w_waiting) && fake_lck.r_waiting) {
		thread_wakeup(LCK_RW_READER_EVENT(lck));
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_END,
	    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, lck->lck_rw_shared_count, 0);

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck, 0);
#endif

#if DEBUG_RW
	thread_t        thread = current_thread();
	change_held_rwlock(lck, thread, LCK_RW_TYPE_EXCLUSIVE, caller);
#endif /* DEBUG_RW */
}

/*!
 * @function lck_rw_lock_exclusive_to_shared
 *
 * @abstract
 * Downgrades a rw_lock held in exclusive mode to shared.
 *
 * @discussion
 * The caller needs to hold the lock in exclusive mode to be able to downgrade it.
 *
 * @param lock           rw_lock already held in exclusive mode to downgrade.
 */
void
lck_rw_lock_exclusive_to_shared(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;

	assertf(lock->lck_rw_owner == current_thread(), "state=0x%x, owner=%p", lock->lck_rw_data, lock->lck_rw_owner);
	ordered_store_rw_owner(lock, THREAD_NULL);
	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);    /* wait for interlock to clear */
			continue;
		}
		data += LCK_RW_SHARED_READER;
		if (data & LCK_RW_WANT_UPGRADE) {
			data &= ~(LCK_RW_WANT_UPGRADE);
		} else {
			data &= ~(LCK_RW_WANT_EXCL);
		}
		if (!((prev & LCK_RW_W_WAITING) && (prev & LCK_RW_PRIV_EXCL))) {
			data &= ~(LCK_RW_W_WAITING);
		}
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_release_smp)) {
			break;
		}
		cpu_pause();
	}
	lck_rw_lock_exclusive_to_shared_gen(lock, prev, __builtin_return_address(0));
}

/*
 * Very sad hack, but the codegen for lck_rw_lock
 * is very unhappy with the combination of __builtin_return_address()
 * and a noreturn function. For some reason it adds more frames
 * than it should. rdar://76570684
 */
void
_lck_rw_lock_type_panic(lck_rw_t *lck, lck_rw_type_t lck_rw_type);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
__attribute__((noinline, weak))
void
_lck_rw_lock_type_panic(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	panic("lck_rw_lock(): Invalid RW lock type: %x for lock %p", lck_rw_type, lck);
}
#pragma clang diagnostic pop

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
void
lck_rw_lock(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		return lck_rw_lock_shared_internal(lck, __builtin_return_address(0));
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_lock_exclusive_internal(lck, __builtin_return_address(0));
	}
	_lck_rw_lock_type_panic(lck, lck_rw_type);
}

__attribute__((always_inline))
static boolean_t
lck_rw_try_lock_shared_internal_inline(
	lck_rw_t        *lock,
	void            *caller)
{
#pragma unused(caller)

	uint32_t        data, prev;
	thread_t        thread = current_thread();
#ifdef DEBUG_RW
	boolean_t       check_canlock = TRUE;
#endif

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;             /* lock is busy */
		}
#ifdef DEBUG_RW
		if ((data & LCK_RW_SHARED_MASK) == 0) {
			/*
			 * If the lock is uncontended,
			 * we do not need to check if we can lock it
			 */
			check_canlock = FALSE;
		}
#endif
		data += LCK_RW_SHARED_READER;     /* Increment reader refcount */
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
#ifdef DEBUG_RW
	if (check_canlock) {
		/*
		 * Best effort attempt to check that this thread
		 * is not already holding the lock (this checks read mode too).
		 */
		assert_canlock_rwlock(lock, thread, LCK_RW_TYPE_SHARED);
	}
#endif
	__assert_only thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);

	if (lock->lck_rw_can_sleep) {
		lck_rw_inc_thread_count(thread);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif  /* CONFIG_DTRACE */

#ifdef DEBUG_RW
	add_held_rwlock(lock, thread, LCK_RW_TYPE_SHARED, caller);
#endif /* DEBUG_RW */
	return TRUE;
}

__attribute__((noinline))
static boolean_t
lck_rw_try_lock_shared_internal(
	lck_rw_t        *lock,
	void            *caller)
{
	return lck_rw_try_lock_shared_internal_inline(lock, caller);
}

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
 * @param lock           rw_lock to lock.
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
boolean_t
lck_rw_try_lock_shared(
	lck_rw_t        *lock)
{
	return lck_rw_try_lock_shared_internal_inline(lock, __builtin_return_address(0));
}

__attribute__((always_inline))
static boolean_t
lck_rw_try_lock_exclusive_internal_inline(
	lck_rw_t        *lock,
	void            *caller)
{
#pragma unused(caller)
	uint32_t        data, prev;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;
		}
		data |= LCK_RW_WANT_EXCL;
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
	thread_t thread = current_thread();

	if (lock->lck_rw_can_sleep) {
		lck_rw_inc_thread_count(thread);
	} else if (get_preemption_level() == 0) {
		panic("Taking non-sleepable RW lock with preemption enabled");
	}

	__assert_only thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);

	ordered_store_rw_owner(lock, thread);
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */

#ifdef DEBUG_RW
	add_held_rwlock(lock, thread, LCK_RW_TYPE_EXCLUSIVE, caller);
#endif /* DEBUG_RW */
	return TRUE;
}

__attribute__((noinline))
static boolean_t
lck_rw_try_lock_exclusive_internal(
	lck_rw_t        *lock,
	void            *caller)
{
	return lck_rw_try_lock_exclusive_internal_inline(lock, caller);
}

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
 * @param lock           rw_lock to lock.
 *
 * @returns TRUE if the lock is successfully acquired, FALSE in case it was already held.
 */
boolean_t
lck_rw_try_lock_exclusive(
	lck_rw_t        *lock)
{
	return lck_rw_try_lock_exclusive_internal_inline(lock, __builtin_return_address(0));
}

/*
 * Very sad hack, but the codegen for lck_rw_try_lock
 * is very unhappy with the combination of __builtin_return_address()
 * and a noreturn function. For some reason it adds more frames
 * than it should. rdar://76570684
 */
boolean_t
_lck_rw_try_lock_type_panic(lck_rw_t *lck, lck_rw_type_t lck_rw_type);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
__attribute__((noinline, weak))
boolean_t
_lck_rw_try_lock_type_panic(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	panic("lck_rw_lock(): Invalid RW lock type: %x for lock %p", lck_rw_type, lck);
}
#pragma clang diagnostic pop

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
boolean_t
lck_rw_try_lock(
	lck_rw_t        *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		return lck_rw_try_lock_shared_internal(lck, __builtin_return_address(0));
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_try_lock_exclusive_internal(lck, __builtin_return_address(0));
	}
	return _lck_rw_try_lock_type_panic(lck, lck_rw_type);
}

/*
 *      Routine:        lck_rw_done_gen
 *
 *	prior_lock_state is the value in the 1st
 *      word of the lock at the time of a successful
 *	atomic compare and exchange with the new value...
 *      it represents the state of the lock before we
 *	decremented the rw_shared_count or cleared either
 *      rw_want_upgrade or rw_want_write and
 *	the lck_x_waiting bits...  since the wrapper
 *      routine has already changed the state atomically,
 *	we just need to decide if we should
 *	wake up anyone and what value to return... we do
 *	this by examining the state of the lock before
 *	we changed it
 */
static lck_rw_type_t
lck_rw_done_gen(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	lck_rw_word_t   fake_lck;
	lck_rw_type_t   lock_type;
	thread_t        thread;
	uint32_t        rwlock_count;

	/*
	 * prior_lock state is a snapshot of the 1st word of the
	 * lock in question... we'll fake up a pointer to it
	 * and carefully not access anything beyond whats defined
	 * in the first word of a lck_rw_t
	 */
	fake_lck.data = prior_lock_state;

	if (fake_lck.shared_count <= 1) {
		if (fake_lck.w_waiting) {
			thread_wakeup(LCK_RW_WRITER_EVENT(lck));
		}

		if (!(fake_lck.priv_excl && fake_lck.w_waiting) && fake_lck.r_waiting) {
			thread_wakeup(LCK_RW_READER_EVENT(lck));
		}
	}
	if (fake_lck.shared_count) {
		lock_type = LCK_RW_TYPE_SHARED;
	} else {
		lock_type = LCK_RW_TYPE_EXCLUSIVE;
	}

	/* Check if dropping the lock means that we need to unpromote */
	thread = current_thread();
	if (fake_lck.can_sleep) {
		rwlock_count = thread->rwlock_count--;
	} else {
		rwlock_count = UINT32_MAX;
	}

	if (rwlock_count == 0) {
		panic("rw lock count underflow for thread %p", thread);
	}

	if ((rwlock_count == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		/* sched_flags checked without lock, but will be rechecked while clearing */
		lck_rw_clear_promotion(thread, unslide_for_kdebug(lck));
	}
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, lock_type == LCK_RW_TYPE_SHARED ? 0 : 1);
#endif

#ifdef DEBUG_RW
	remove_held_rwlock(lck, thread, lock_type);
#endif /* DEBUG_RW */
	return lock_type;
}

/*!
 * @function lck_rw_done
 *
 * @abstract
 * Force unlocks a rw_lock without consistency checks.
 *
 * @discussion
 * Do not use unless sure you can avoid consistency checks.
 *
 * @param lock           rw_lock to unlock.
 */
lck_rw_type_t
lck_rw_done(
	lck_rw_t        *lock)
{
	uint32_t        data, prev;
	boolean_t       once = FALSE;

#ifdef DEBUG_RW
	/*
	 * Best effort attempt to check that this thread
	 * is holding the lock.
	 */
	thread_t thread = current_thread();
	assert_held_rwlock(lock, thread, 0);
#endif /* DEBUG_RW */
	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {          /* wait for interlock to clear */
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_SHARED_MASK) {        /* lock is held shared */
			assertf(lock->lck_rw_owner == THREAD_NULL, "state=0x%x, owner=%p", lock->lck_rw_data, lock->lck_rw_owner);
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0) { /* if reader count has now gone to 0, check for waiters */
				goto check_waiters;
			}
		} else {                                        /* if reader count == 0, must be exclusive lock */
			if (data & LCK_RW_WANT_UPGRADE) {
				data &= ~(LCK_RW_WANT_UPGRADE);
			} else {
				if (data & LCK_RW_WANT_EXCL) {
					data &= ~(LCK_RW_WANT_EXCL);
				} else {                                /* lock is not 'owned', panic */
					panic("Releasing non-exclusive RW lock without a reader refcount!");
				}
			}
			if (!once) {
				// Only check for holder and clear it once
				assertf(lock->lck_rw_owner == current_thread(), "state=0x%x, owner=%p", lock->lck_rw_data, lock->lck_rw_owner);
				ordered_store_rw_owner(lock, THREAD_NULL);
				once = TRUE;
			}
check_waiters:
			/*
			 * test the original values to match what
			 * lck_rw_done_gen is going to do to determine
			 * which wakeups need to happen...
			 *
			 * if !(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting)
			 */
			if (prev & LCK_RW_W_WAITING) {
				data &= ~(LCK_RW_W_WAITING);
				if ((prev & LCK_RW_PRIV_EXCL) == 0) {
					data &= ~(LCK_RW_R_WAITING);
				}
			} else {
				data &= ~(LCK_RW_R_WAITING);
			}
		}
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_release_smp)) {
			break;
		}
		cpu_pause();
	}
	return lck_rw_done_gen(lock, prev);
}

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
void
lck_rw_unlock_shared(
	lck_rw_t        *lck)
{
	lck_rw_type_t   ret;

	assertf(lck->lck_rw_owner == THREAD_NULL, "state=0x%x, owner=%p", lck->lck_rw_data, lck->lck_rw_owner);
	assertf(lck->lck_rw_shared_count > 0, "shared_count=0x%x", lck->lck_rw_shared_count);
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_SHARED) {
		panic("lck_rw_unlock_shared(): lock %p held in mode: %d", lck, ret);
	}
}

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
void
lck_rw_unlock_exclusive(
	lck_rw_t        *lck)
{
	lck_rw_type_t   ret;

	assertf(lck->lck_rw_owner == current_thread(), "state=0x%x, owner=%p", lck->lck_rw_data, lck->lck_rw_owner);
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_EXCLUSIVE) {
		panic("lck_rw_unlock_exclusive(): lock %p held in mode: %d", lck, ret);
	}
}

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
void
lck_rw_unlock(
	lck_rw_t         *lck,
	lck_rw_type_t    lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		lck_rw_unlock_shared(lck);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		lck_rw_unlock_exclusive(lck);
	} else {
		panic("lck_rw_unlock(): Invalid RW lock type: %d", lck_rw_type);
	}
}

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
void
lck_rw_assert(
	lck_rw_t        *lck,
	unsigned int    type)
{
#if DEBUG_RW
	thread_t thread = current_thread();
#endif /* DEBUG_RW */

	switch (type) {
	case LCK_RW_ASSERT_SHARED:
		if ((lck->lck_rw_shared_count != 0) &&
		    (lck->lck_rw_owner == THREAD_NULL)) {
#if DEBUG_RW
			assert_held_rwlock(lck, thread, LCK_RW_TYPE_SHARED);
#endif /* DEBUG_RW */
			return;
		}
		break;
	case LCK_RW_ASSERT_EXCLUSIVE:
		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_shared_count == 0) &&
		    (lck->lck_rw_owner == current_thread())) {
#if DEBUG_RW
			assert_held_rwlock(lck, thread, LCK_RW_TYPE_EXCLUSIVE);
#endif /* DEBUG_RW */
			return;
		}
		break;
	case LCK_RW_ASSERT_HELD:
		if (lck->lck_rw_shared_count != 0) {
#if DEBUG_RW
			assert_held_rwlock(lck, thread, LCK_RW_TYPE_SHARED);
#endif /* DEBUG_RW */
			return;         // Held shared
		}
		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_owner == current_thread())) {
#if DEBUG_RW
			assert_held_rwlock(lck, thread, LCK_RW_TYPE_EXCLUSIVE);
#endif /* DEBUG_RW */
			return;         // Held exclusive
		}
		break;
	case LCK_RW_ASSERT_NOTHELD:
		if ((lck->lck_rw_shared_count == 0) &&
		    !(lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_owner == THREAD_NULL)) {
#ifdef DEBUG_RW
			assert_canlock_rwlock(lck, thread, LCK_RW_TYPE_EXCLUSIVE);
#endif /* DEBUG_RW */
			return;
		}
		break;
	default:
		break;
	}
	panic("rw lock (%p)%s held (mode=%u)", lck, (type == LCK_RW_ASSERT_NOTHELD ? "" : " not"), type);
}

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
boolean_t
kdp_lck_rw_lock_is_acquired_exclusive(
	lck_rw_t        *lck)
{
	if (not_in_kdp) {
		panic("panic: rw lock exclusive check done outside of kernel debugger");
	}
	return ((lck->lck_rw_want_upgrade || lck->lck_rw_want_excl) && (lck->lck_rw_shared_count == 0)) ? TRUE : FALSE;
}

void
kdp_rwlck_find_owner(
	__unused struct waitq   *waitq,
	event64_t               event,
	thread_waitinfo_t       *waitinfo)
{
	lck_rw_t        *rwlck = NULL;
	switch (waitinfo->wait_type) {
	case kThreadWaitKernelRWLockRead:
		rwlck = READ_EVENT_TO_RWLOCK(event);
		break;
	case kThreadWaitKernelRWLockWrite:
	case kThreadWaitKernelRWLockUpgrade:
		rwlck = WRITE_EVENT_TO_RWLOCK(event);
		break;
	default:
		panic("%s was called with an invalid blocking type", __FUNCTION__);
		break;
	}
	if (rwlck->lck_rw_owner) {
		thread_require(rwlck->lck_rw_owner);
	}
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(rwlck);
	waitinfo->owner = thread_tid(rwlck->lck_rw_owner);
}

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
boolean_t
lck_rw_lock_yield_shared(
	lck_rw_t        *lck,
	boolean_t       force_yield)
{
	lck_rw_word_t   word;

	lck_rw_assert(lck, LCK_RW_ASSERT_SHARED);

	word.data = ordered_load_rw(lck);
	if (word.want_excl || word.want_upgrade || force_yield) {
		lck_rw_unlock_shared(lck);
		mutex_pause(2);
		lck_rw_lock_shared(lck);
		return TRUE;
	}

	return FALSE;
}

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
wait_result_t
lck_rw_sleep(
	lck_rw_t                *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	wait_result_t           res;
	lck_rw_type_t           lck_rw_type;
	thread_pri_floor_t      token;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * Although we are dropping the RW lock, the intent in most cases
		 * is that this thread remains as an observer, since it may hold
		 * some secondary resource, but must yield to avoid deadlock. In
		 * this situation, make sure that the thread is boosted to the
		 * ceiling while blocked, so that it can re-acquire the
		 * RW lock at that priority.
		 */
		token = thread_priority_floor_start();
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
				lck_rw_lock(lck, lck_rw_type);
			} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
				lck_rw_lock_exclusive(lck);
			} else {
				lck_rw_lock_shared(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		(void)lck_rw_done(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	return res;
}

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
wait_result_t
lck_rw_sleep_deadline(
	lck_rw_t                *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t           res;
	lck_rw_type_t           lck_rw_type;
	thread_pri_floor_t      token;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		token = thread_priority_floor_start();
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
				lck_rw_lock(lck, lck_rw_type);
			} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
				lck_rw_lock_exclusive(lck);
			} else {
				lck_rw_lock_shared(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		(void)lck_rw_done(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	return res;
}

/*
 * Reader-writer lock promotion
 *
 * We support a limited form of reader-writer
 * lock promotion whose effects are:
 *
 *   * Qualifying threads have decay disabled
 *   * Scheduler priority is reset to a floor of
 *     of their statically assigned priority
 *     or MINPRI_RWLOCK
 *
 * The rationale is that lck_rw_ts do not have
 * a single owner, so we cannot apply a directed
 * priority boost from all waiting threads
 * to all holding threads without maintaining
 * lists of all shared owners and all waiting
 * threads for every lock.
 *
 * Instead (and to preserve the uncontended fast-
 * path), acquiring (or attempting to acquire)
 * a RW lock in shared or exclusive lock increments
 * a per-thread counter. Only if that thread stops
 * making forward progress (for instance blocking
 * on a mutex, or being preempted) do we consult
 * the counter and apply the priority floor.
 * When the thread becomes runnable again (or in
 * the case of preemption it never stopped being
 * runnable), it has the priority boost and should
 * be in a good position to run on the CPU and
 * release all RW locks (at which point the priority
 * boost is cleared).
 *
 * Care must be taken to ensure that priority
 * boosts are not retained indefinitely, since unlike
 * mutex priority boosts (where the boost is tied
 * to the mutex lifecycle), the boost is tied
 * to the thread and independent of any particular
 * lck_rw_t. Assertions are in place on return
 * to userspace so that the boost is not held
 * indefinitely.
 *
 * The routines that increment/decrement the
 * per-thread counter should err on the side of
 * incrementing any time a preemption is possible
 * and the lock would be visible to the rest of the
 * system as held (so it should be incremented before
 * interlocks are dropped/preemption is enabled, or
 * before a CAS is executed to acquire the lock).
 *
 */

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
void
lck_rw_clear_promotion(
	thread_t thread,
	uintptr_t trace_obj)
{
	assert(thread->rwlock_count == 0);

	/* Cancel any promotions if the thread had actually blocked while holding a RW lock */
	spl_t s = splsched();
	thread_lock(thread);

	if (thread->sched_flags & TH_SFLAG_RW_PROMOTED) {
		sched_thread_unpromote_reason(thread, TH_SFLAG_RW_PROMOTED, trace_obj);
	}

	thread_unlock(thread);
	splx(s);
}

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
void
lck_rw_set_promotion_locked(thread_t thread)
{
	if (LcksOpts & disLkRWPrio) {
		return;
	}

	assert(thread->rwlock_count > 0);

	if (!(thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		sched_thread_promote_reason(thread, TH_SFLAG_RW_PROMOTED, 0);
	}
}

#if __x86_64__
void lck_rw_clear_promotions_x86(thread_t thread);
/*
 * On return to userspace, this routine is called from assembly
 * if the rwlock_count is somehow imbalanced
 */
#if MACH_LDEBUG
__dead2
#endif /* MACH_LDEBUG */
void
lck_rw_clear_promotions_x86(thread_t thread)
{
#if MACH_LDEBUG
	/* It's fatal to leave a RW lock locked and return to userspace */
	panic("%u rw lock(s) held on return to userspace for thread %p", thread->rwlock_count, thread);
#else
	/* Paper over the issue */
	thread->rwlock_count = 0;
	lck_rw_clear_promotion(thread, 0);
#endif /* MACH_LDEBUG */
}
#endif /* __x86_64__ */
