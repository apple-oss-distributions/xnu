/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#define VM_MAP_LOCK_PRIVATE 1
#define LOCK_PRIVATE 1

#include <kern/locks_internal.h>
#include <kern/lock_group.h>
#include <kern/lock_stat.h>
#include <kern/lock_rw.h> /* lck_rw_lock_count_{inc,dec} */
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <os/hash.h>
#include <vm/vm_stackshot_utils_xnu.h>


static_assert(sizeof(vm_entry_lock_t) == sizeof(uint32_t));

#define VM_ENTRY_LCK_FMT        "<v:%d c:%c%c w:%c%c %c/%d>"

#define VM_ENTRY_LCK_FMT_ARGS(ostate) \
	ostate.vmel_valid, \
	ostate.vmel_needs_coalesce  ? 'c' : '-', \
	ostate.vmel_kunwire_waiters ? 'k' : '-', \
	ostate.vmel_excl_waiters    ? 'x' : '-', \
	ostate.vmel_shared_waiters  ? 's' : '-', \
	ostate.vmel_excl_locked     ? 'x' : '-', \
	ostate.vmel_read_count

/*
 * VM Map Entry lock
 * =================
 *
 * Note: the algorithm comes with a formal specification
 *       in tools/tla/vmelock.tla
 *
 *
 * This lock is a bespoke reader writer lock that supports for the lock
 * to go disappear during wait, and understands the semantics of a VM map entry.
 *
 * It is based on the algorithm of the regular reader writer lock,
 * with a few simplifications:
 *
 * - upgrade doesn't wait and instead fails early, as a full retry is not
 *   extremely costly for any of the current callers, and that blocking
 *   upgrade makes the state machine much more complex;
 *
 * - urgent waiters aren't treated specially as the broadcast technique
 *   is not compatible with the entry going away;
 *
 * - exclusive-to-exclusive performs lock handoffs as a way to guarantee
 *   that the entry is alive, otherwise exclusive waiters would have to
 *   re-lookup the entry each time they are woken up which is undesirable.
 *
 */

static inline vm_entry_lock_t
VMEL_INVALID_STATE(vmel_invalid_reason_t reason)
{
	return (vm_entry_lock_t) {
		       .vmel_valid2         = false,
		       .vmel_invalid_reason = reason,
	};
}

static const vm_entry_lock_t VMEL_KUNWIRE_BIT = {
	.vmel_kunwire_waiters   = true,
};
static const vm_entry_lock_t VMEL_COALESCE_BIT = {
	.vmel_needs_coalesce    = true,
};

static const vm_entry_lock_t VMEL_SWAITERS_BIT = {
	.vmel_shared_waiters    = true,
};
static const vm_entry_lock_t VMEL_XWAITERS_BIT = {
	.vmel_excl_waiters      = true,
};

static const vm_entry_lock_t VMEL_UNLOCKED_STATE = {
	.vmel_valid             = true,
};
static const vm_entry_lock_t VMEL_XLOCKED_STATE = {
	.vmel_valid             = true,
	.vmel_excl_locked       = true,
};
static const vm_entry_lock_t VMEL_SLOCKED1_STATE = {
	.vmel_valid             = true,
	.vmel_read_count        = 1,
};
static const vm_entry_lock_t VMEL_ONE_READ_COUNT = {
	.vmel_read_count        = 1,
};

static_assert(sizeof(vm_entry_lock_t) == sizeof(uint32_t));

static LCK_GRP_DECLARE(vm_entry_lock_grp, "vm_entry_lock");
__used
static const uint32_t vme_xtail_hash_size = 8u << (32 - __builtin_clz(MAX_CPUS));
static lck_mcs_id_t vme_xtail_hash[vme_xtail_hash_size];


#pragma mark helpers

static vm_entry_lock_t
__vm_entry_lock_state(vm_map_entry_t entry)
{
	return os_atomic_load(&entry->vme_lock, relaxed);
}

static hw_spin_timeout_status_t
lck_vme_lock_timeout_panic(void *_entry, hw_spin_timeout_t to, hw_spin_state_t st)
{
	vm_map_entry_t  entry = _entry;
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	panic("VM entry %p lock " HW_SPIN_TIMEOUT_FMT "; " VM_ENTRY_LCK_FMT ", "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    entry, HW_SPIN_TIMEOUT_ARG(to, st), VM_ENTRY_LCK_FMT_ARGS(state),
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy lck_vme_timeout_policy = {
	.hwsp_name              = "vm_entry_lock_t (adaptive spin)",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = lck_vme_lock_timeout_panic,
};


__abortlike
static void
__vm_entry_lock_valid_panic(vm_map_entry_t entry, vm_entry_lock_t ostate)
{
	panic("VM entry %p lock is unexpectedly valid " VM_ENTRY_LCK_FMT,
	    entry, VM_ENTRY_LCK_FMT_ARGS(ostate));
}

__abortlike
static void
__vm_entry_lock_invalid_panic(vm_map_entry_t entry, vm_entry_lock_t ostate)
{
	panic("VM entry %p lock is invalid (%#hx) " VM_ENTRY_LCK_FMT,
	    entry, ostate.vmel_invalid_reason, VM_ENTRY_LCK_FMT_ARGS(ostate));
}

__abortlike
static void
__vm_entry_lock_shared_overflow_panic(vm_map_entry_t entry, vm_entry_lock_t ostate)
{
	panic("VM entry %p lock shared lock overflow " VM_ENTRY_LCK_FMT,
	    entry, VM_ENTRY_LCK_FMT_ARGS(ostate));
}

__abortlike
static void
__vm_entry_lock_unowned_panic(vm_map_entry_t entry, vm_entry_lock_t ostate)
{
	thread_t self = current_thread();

	if (!ostate.vmel_valid) {
		__vm_entry_lock_invalid_panic(entry, ostate);
	}
	panic("VM entry %p unexpectedly not owned by thread %p/0x%x " VM_ENTRY_LCK_FMT,
	    entry, self, self->ctid, VM_ENTRY_LCK_FMT_ARGS(ostate));
}

__abortlike
static void
__vm_entry_lock_invalid_reason_mismatch_panic(
	vm_map_entry_t entry,
	vm_entry_lock_t ostate,
	vmel_invalid_reason_t allowed_reasons)
{
	panic("VM entry %p lock invalid reason (%#hx) not allowed (%#hx) " VM_ENTRY_LCK_FMT,
	    entry,
	    ostate.vmel_invalid_reason,
	    allowed_reasons,
	    VM_ENTRY_LCK_FMT_ARGS(ostate));
}

__pure2
static inline lck_mcs_id_t *
__vm_entry_lock_xtail(vm_map_entry_t entry)
{
	uint32_t hash = os_hash_kernel_pointer(&entry->vme_lock);

	return &vme_xtail_hash[hash % vme_xtail_hash_size];
}

static void
__vm_entry_stackshot_hint_asserts(__unused block_hint_t hint)
{
	static_assert(3 <= sizeof(vm_entry_lock_t));
	static_assert(kThreadWaitVMEntryExclEvent + 2 ==
	    kThreadWaitVMEntryKUnwireEvent);
	static_assert(kThreadWaitVMEntryExclEvent + 1 ==
	    kThreadWaitVMEntrySharedEvent);
	assert3s(hint, >=, kThreadWaitVMEntryExclEvent);
	assert3s(hint, <=, kThreadWaitVMEntryKUnwireEvent);
}

static inline event64_t
__vm_entry_event(vm_map_entry_t entry, block_hint_t hint)
{
	uint32_t delta = hint + 1 - kThreadWaitVMEntryExclEvent;

	__vm_entry_stackshot_hint_asserts(hint);
	return CAST_EVENT64_T(&entry->vme_lock) + delta;
}

vm_map_entry_t
kdp_vm_entry_from_event(event64_t event, block_hint_t hint)
{
	uint32_t delta = hint + 1 - kThreadWaitVMEntryExclEvent;
	vm_entry_lock_t *lock;

	__vm_entry_stackshot_hint_asserts(hint);

	lock = (vm_entry_lock_t *)((uintptr_t)event - delta);
	return __container_of(lock, struct vm_map_entry, vme_lock);
}

static inline bool
__vm_entry_owned_exclusively(vm_entry_lock_t state)
{
	return state.vmel_excl_locked;
}

static inline bool
__vm_entry_owned_shared(vm_entry_lock_t state)
{
	return !state.vmel_excl_locked && state.vmel_read_count != 0;
}

#if MAP_ENTRY_LOCK_DEBUG
#define __vm_entry_lock_init_owner(entry, owner)         ((entry)->vme_owner = (owner))
#define __vm_entry_lock_assert_owner(entry, owner)       assert((entry)->vme_owner == (owner))
#define __vm_entry_lock_assert_not_owner(entry, owner)   assert((entry)->vme_owner != (owner))
#else
#define __vm_entry_lock_init_owner(entry, owner)         ((void)(entry), (void)(owner))
#define __vm_entry_lock_assert_owner(entry, owner)       ((void)(entry), (void)(owner))
#define __vm_entry_lock_assert_not_owner(entry, owner)   ((void)(entry), (void)(owner))
#endif

static inline void
__vm_entry_lock_set_owner(vm_map_entry_t entry, thread_t owner)
{
	__vm_entry_lock_assert_owner(entry, THREAD_NULL);
	__vm_entry_lock_init_owner(entry, owner);
}

static inline void
__vm_entry_lock_clear_owner(vm_map_entry_t entry, thread_t owner)
{
	__vm_entry_lock_assert_owner(entry, owner);
	__vm_entry_lock_init_owner(entry, THREAD_NULL);
}


#if CONFIG_DTRACE

static inline enum lockstat_probe_id
__vm_entry_block_probe_id(block_hint_t hint)
{
	if (hint == kThreadWaitVMEntrySharedEvent) {
		return LS_LCK_RW_LOCK_SHARED_BLOCK;
	}
	return LS_LCK_RW_LOCK_EXCL_BLOCK;
}

static inline enum lockstat_probe_id
__vm_entry_spin_probe_id(block_hint_t hint)
{
	if (hint == kThreadWaitVMEntrySharedEvent) {
		return LS_LCK_RW_LOCK_SHARED_SPIN;
	}
	return LS_LCK_RW_LOCK_EXCL_SPIN;
}

#define VM_ENTRY_BLOCK_BEGIN(entry, hint) \
	lck_time_stat_begin(__vm_entry_block_probe_id(hint))

#define VM_ENTRY_BLOCK_END(entry, hint, start) \
	lck_time_stat_record_grp(__vm_entry_block_probe_id(hint), \
	    &entry->vme_lock, &vm_entry_lock_grp, start);

#define VM_ENTRY_SPIN_END(lck, hint, start) \
	lck_time_stat_record_grp(__vm_entry_spin_probe_id(hint), \
	    &entry->vme_lock, &vm_entry_lock_grp, start);
#else
#define VM_ENTRY_BLOCK_BEGIN(entry, hint)               0ull
#define VM_ENTRY_BLOCK_END(entry, hint, start)          ((void)start)
#define VM_ENTRY_SPIN_END(entry, hint, start)           ((void)start)
#endif


#pragma mark waitq integration

static bool
__vm_entry_lock_set_waiters(
	vm_map_entry_t          entry,
	vm_entry_lock_t         state,
	vm_entry_lock_t         mask)
{
	return (state.vmel_data & mask.vmel_data) == mask.vmel_data ||
	       os_atomic_cmpxchg(&entry->vme_lock.vmel_data, state.vmel_data,
	           state.vmel_data | mask.vmel_data, relaxed);
}

__attribute__((noinline, warn_unused_result))
static bool
__vm_entry_lock_assert_wait(
	vm_map_entry_t          entry,
	wait_interrupt_t        how,
	thread_t                self,
	block_hint_t            hint,
	vm_entry_lock_t         mask)
{
	event64_t       event = __vm_entry_event(entry, hint);
	struct waitq   *waitq = global_eventq(event);
	vm_entry_lock_t state;
	bool            waiting;
	spl_t           spl;

	spl = splsched();
	waitq_lock(waitq);

	/*
	 *	Now that we are under the wait queue lock, do not block
	 *	if the bit we set got cleared (normal rwlock algorithm),
	 *	or if the lock could be taken.
	 *
	 *	__vm_entry_lock_shared_wakeup() can't clear the waiters
	 *	bit if it's set and couldn't dequeue a thread, because
	 *	it has to assume that the entry is freed. But as a result,
	 *	it might fail to wake up a thread that was on its way to
	 *	wait as an exclusive waiter if it caught it before it went into
	 *	assert wait.
	 *
	 *	Informally: if there's someone holding the lock that person
	 *	will wakeup someone eventually and there's a guarantee of
	 *	forward progress. But if there is not, we might be going into
	 *	a forever hanging place.
	 */
	state   = __vm_entry_lock_state(entry);
	waiting = (state.vmel_data & mask.vmel_data) == mask.vmel_data &&
	    (state.vmel_excl_locked || state.vmel_read_count);

	if (waiting) {
		thread_set_pending_block_hint(self, hint);
		waitq_assert_wait64_locked(waitq, event,
		    how | THREAD_WAIT_NOREPORT_USER,
		    TIMEOUT_URGENCY_SYS_NORMAL, TIMEOUT_WAIT_FOREVER,
		    TIMEOUT_NO_LEEWAY, self);
	}

	waitq_unlock(waitq);
	splx(spl);

	return waiting;
}

/*!
 * Wait for the given entry's lock to be available.
 *
 * The interlock must be held on entry. It may be dropped while waiting.
 * It will be held again on exit.
 *
 * On exit, the entry may or may not be valid, and we may or may not be the owner
 * of the entry's lock.
 *
 * @returns
 * - KERN_SUCCESS      - the entry is either locked, or ready to be locked.
 * - KERN_LOCK_OWNED   - the entry was handed of the lock.
 *                       (only for reason == VM_ENTRY_EXCL_EVENT)
 * - VMRL_ERR_RELOOKUP - relookup the entry. the pointer to the entry may
 *                       or may not be valid.
 * - VMRL_ERR_ABORTED  - (how=THREAD_ABORTSAFE only) The wait was aborted.
 */
__attribute__((noinline, warn_unused_result))
static kern_return_t
__vm_entry_lock_block(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	block_hint_t            hint __kdebug_only)
{
	thread_pri_floor_t token;
	uint64_t           timestamp = map->unlink_timestamp;
	uint64_t           start;
	wait_result_t      wr;

	start = VM_ENTRY_BLOCK_BEGIN(entry, hint);
	token = thread_priority_floor_start();
	if (!vm_map_is_sealed(map)) {
		lck_rw_unlock(&map->ilock, map_held);
	}

	wr = thread_block(THREAD_CONTINUE_NULL);

	if (!vm_map_is_sealed(map)) {
		lck_rw_lock(&map->ilock, map_held);
	}
	thread_priority_floor_end(&token);
	VM_ENTRY_BLOCK_END(entry, hint, start);

	if (wr == THREAD_INTERRUPTED) {
		return VMRL_ERR_ABORTED;
	}

	if (wr == THREAD_AWAKENED) {
		/*
		 * For exclusive waiters, there are two ways we can be woken up.
		 * We can either be woken up when all waiters are invalidated in
		 * __vm_entry_wakeup_all_waiters, in which case we were awoken
		 * with THREAD_RESTART and everyone waiting on the lock was
		 * awoken.  In that case, we still need to do the timestamp and
		 * bounds checks as the entry could have been deleted/clipped.
		 *
		 * Or we can be woken up when the previous exclusive owner
		 * unlocks, in which case we were awoken with THREAD_AWAKENED.
		 * In this case the previous owner should have handed off
		 * ownership of the lock via ctid to us.
		 *
		 * This handoff/THREAD_RESTART dance avoids the case where we
		 * are the only exclusive waiter, are woken up, and then go
		 * away, while leaving vmel_excl_waiters = 1. The handoff lets
		 * us safely dereference the entry.
		 *
		 * Another option instead of a handoff would be if there are
		 * exclusive waiters, wake up all exclusive and shared waiters
		 * on unlock, but that was deemed worse for perf.
		 */
		assert(hint == kThreadWaitVMEntryExclEvent);
		return KERN_LOCK_OWNED;
	}

	/* No lock handoff. Fall through to the timestamp check */
	assert(wr == THREAD_RESTART);

	/*
	 * The unlink_timestamp being unchanged tells us no entries have been
	 * removed from the map. That means we can safely dereference the old
	 * entry pointer and look to see if the address we want to lock is within
	 * the bounds of the entry.
	 */
	if (timestamp == map->unlink_timestamp &&
	    entry->vme_start <= addr && addr < entry->vme_end) {
		return KERN_SUCCESS;
	}

	return VMRL_ERR_RELOOKUP;
}

static void
__vm_entry_lock_wakeup_all(vm_map_entry_t entry, block_hint_t hint)
{
	event64_t     event = __vm_entry_event(entry, hint);
	struct waitq *waitq = global_eventq(event);

	waitq_wakeup64_all(waitq, event, THREAD_RESTART, WAITQ_WAKEUP_DEFAULT);
}

__attribute__((noinline))
static void
__vm_entry_lock_shared_broadcast(vm_map_entry_t entry)
{
	event64_t     event = __vm_entry_event(entry, kThreadWaitVMEntrySharedEvent);
	struct waitq *waitq = global_eventq(event);
	spl_t         spl;

	spl   = splsched();
	waitq_lock(waitq);

	os_atomic_andnot(&entry->vme_lock.vmel_data,
	    VMEL_SWAITERS_BIT.vmel_data, relaxed);

	waitq_wakeup64_all_locked(waitq, event, THREAD_RESTART,
	    WAITQ_UNLOCK | waitq_flags_splx(spl));
}

void
vm_entry_lock_invalidate(vm_map_entry_t entry, vmel_invalid_reason_t reason)
{
	RANGE_LOCK_ASSERT(__builtin_popcount(reason) == 1);
	vm_entry_lock_t state;
	state = os_atomic_load(&entry->vme_lock, relaxed);

	if (!state.vmel_valid) {
		__vm_entry_lock_invalid_panic(entry, state);
	}

	if (!__vm_entry_owned_exclusively(state)) {
		__vm_entry_lock_unowned_panic(entry, state);
	}

	release_assert(!state.vmel_excl_waiters);
	release_assert(!state.vmel_shared_waiters);

	/*
	 * This verifies that the state is what we loaded above. If the CAS
	 * fails, then that means that someone else has modified this lock
	 * concurrently. No one else should have a reference to a lock that is
	 * being invalidated.
	 */
	bool contended = !os_atomic_cmpxchg(&entry->vme_lock, state,
	    VMEL_INVALID_STATE(reason), relaxed);
	release_assert(!contended);

	lck_rw_lock_count_dec(current_thread(), &entry->vme_lock);
}

void
vm_entry_lock_reinvalidate(
	vm_map_entry_t entry,
	vmel_invalid_reason_t allowed_reasons,
	vmel_invalid_reason_t new_reason)
{
	RANGE_LOCK_ASSERT(__builtin_popcount(new_reason) == 1);
	vm_entry_lock_t state;
	state = os_atomic_load(&entry->vme_lock, relaxed);

	if (state.vmel_valid) {
		__vm_entry_lock_valid_panic(entry, state);
	}

	RANGE_LOCK_ASSERT(__builtin_popcount(state.vmel_invalid_reason) == 1);
	if ((state.vmel_invalid_reason & allowed_reasons) == 0) {
		__vm_entry_lock_invalid_reason_mismatch_panic(
			entry, state, allowed_reasons);
	}

	release_assert(!state.vmel_excl_waiters);
	release_assert(!state.vmel_shared_waiters);

	bool contended = !os_atomic_cmpxchg(&entry->vme_lock, state,
	    VMEL_INVALID_STATE(new_reason), relaxed);
	release_assert(!contended);
}

bool
vm_entry_lock_is_valid(vm_map_entry_t entry)
{
	return (bool)__vm_entry_lock_state(entry).vmel_valid;
}

vmel_invalid_reason_t
vm_entry_lock_invalid_reason(vm_map_entry_t entry)
{
	return __vm_entry_lock_state(entry).vmel_invalid_reason;
}

#pragma mark slowpaths (dtrace)
#if CONFIG_DTRACE

__attribute__((noinline))
static void
vmel_lock_s_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE,
	    &entry->vme_lock, DTRACE_RW_SHARED);
}

__attribute__((noinline))
static void
vmel_try_lock_s_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE,
	    &entry->vme_lock, DTRACE_RW_SHARED);
}

__attribute__((noinline))
static void
vmel_unlock_s_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE,
	    &entry->vme_lock, DTRACE_RW_SHARED);
}

__attribute__((noinline))
static void
vmel_lock_s2x_success_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE,
	    &entry->vme_lock, true);
}

__attribute__((noinline))
static void
vmel_lock_x_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE,
	    &entry->vme_lock, DTRACE_RW_EXCL);
}

__attribute__((noinline))
static void
vmel_try_lock_x_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE,
	    &entry->vme_lock, DTRACE_RW_EXCL);
}

__attribute__((noinline))
static void
vmel_unlock_x_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE,
	    &entry->vme_lock, DTRACE_RW_EXCL);
}

__attribute__((noinline))
static void
vmel_lock_x2s_slow(vm_map_entry_t entry)
{
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE,
	    &entry->vme_lock, DTRACE_RW_NOFLAG);
}

#define VMEL_SLOWPATH(...) ({ \
	if (__improbable(lck_debug_state.lds_value)) {                          \
	        __VA_ARGS__;                                                    \
	}                                                                       \
})

#else

#define VMEL_SLOWPATH(...)              ((void)0)

#endif
#pragma mark vm_entry_*_exclusive

static inline bool
__vm_entry_can_lock_exclusive(vm_entry_lock_t state)
{
	return state.vmel_lock16 == VMEL_UNLOCKED_STATE.vmel_lock16;
}

static bool
__vm_entry_lock_exclusive_try(vm_map_entry_t entry, bool pretest)
{
	uint16_t uw = VMEL_UNLOCKED_STATE.vmel_lock16;
	uint16_t lw = VMEL_XLOCKED_STATE.vmel_lock16;

	if (pretest) {
		return lock_cmpxchg(&entry->vme_lock.vmel_lock16, uw, lw, acquire);
	}
	return os_atomic_cmpxchg(&entry->vme_lock.vmel_lock16, uw, lw, acquire);
}

__attribute__((noinline))
static void
__vm_entry_lock_exclusive_wakeup(vm_map_entry_t entry, vm_entry_lock_t state)
{
	vm_entry_lock_t ostate, nstate;
	thread_t        thread;
	event64_t       event;
	struct waitq   *waitq;
	spl_t           spl;

again:
	/*
	 *	Step 1: deal with writers
	 *
	 *	Our lock is writer biased, so we want to wake up writers first.
	 *
	 *	If we find an exclusive waiter, hand the lock off to it and wake
	 *	it up, leaving both the {excl,shared}_waiters bit unmodified.
	 *	Otherwise, clear the excl_waiters bit and move on to step 2.
	 */
	if (state.vmel_excl_waiters) {
		event = __vm_entry_event(entry, kThreadWaitVMEntryExclEvent);
		waitq = global_eventq(event);
		spl   = splsched();
		waitq_lock(waitq);

		thread = waitq_wakeup64_identify_locked(waitq, event,
		    WAITQ_KEEP_LOCKED, NULL);

		if (thread == THREAD_NULL) {
			state.vmel_data = os_atomic_andnot(&entry->vme_lock.vmel_data,
			    VMEL_XWAITERS_BIT.vmel_data, relaxed);
		}

		waitq_unlock(waitq);
		splx(spl);

		if (thread) {
			__vm_entry_lock_set_owner(entry, thread);
			os_atomic_thread_fence(release);
			waitq_resume_identified_thread(waitq, thread,
			    THREAD_AWAKENED, WAITQ_WAKEUP_DEFAULT);
			return;
		}
	}

	/*
	 *	Step 2: deal with readers
	 *
	 *	We must atomically unlock the lock and clear the shared_waiters
	 *	bit, while making sure no one is concurrently setting the
	 *	excl_waiters bit.
	 *
	 *	If we fail to observe excl_waiters being set, because the lock
	 *	is writer biased, readers might go straight back to sleep,
	 *	but no one will ever wake up that writer.
	 *
	 *	This can unfortunately lead to spurious wakeups.
	 */
	if (state.vmel_shared_waiters) {
		event = __vm_entry_event(entry, kThreadWaitVMEntrySharedEvent);
		waitq = global_eventq(event);
		spl   = splsched();
		waitq_lock(waitq);
	}

	nstate = (vm_entry_lock_t){
		.vmel_state8 = state.vmel_state8,
	};
	nstate.vmel_valid = state.vmel_valid;

	if (!os_atomic_cmpxchgv(&entry->vme_lock, state, nstate, &ostate, release)) {
		if (state.vmel_shared_waiters) {
			waitq_unlock(waitq);
			splx(spl);
		}
		state = ostate;
		goto again;
	}

	if (state.vmel_shared_waiters) {
		waitq_wakeup64_all_locked(waitq, event, THREAD_RESTART,
		    WAITQ_UNLOCK | waitq_flags_splx(spl));
	}
}

__attribute__((always_inline))
static bool
__vm_entry_lock_exclusive_contended_step(
	vm_map_entry_t          entry,
	thread_t                self,
	wait_interrupt_t        how,
	lck_adaptive_spin_ctx_t ctx)
{
	hw_spin_policy_t  pol  = &lck_vme_timeout_policy;
	lck_mcs_id_t     *link = __vm_entry_lock_xtail(entry);

	block_hint_t      hint = kThreadWaitVMEntryExclEvent;
	vm_entry_lock_t   mask = VMEL_XWAITERS_BIT;
	vm_entry_lock_t   state;
	lck_mcs_node_t    node;
	bool              success;

	lock_disable_preemption_for_thread(self);
	lck_adaptive_spin_start(ctx);

	node = lck_mcs_enqueue(link, LCK_MCS_SLEEPABLE, entry, pol);

	for (;;) {
		state.vmel_data = lock_load_exclusive(&entry->vme_lock.vmel_data,
		    relaxed);

		if (!state.vmel_valid) {
			__vm_entry_lock_invalid_panic(entry, state);
		}

		if (__vm_entry_can_lock_exclusive(state)) {
			if (__vm_entry_lock_exclusive_try(entry, false)) {
				success = true;
				break;
			}
			continue;
		}

		lck_adaptive_spin_wait_for_event(ctx);
		lck_adaptive_spin_step(ctx);

		if (ctx->expired &&
		    __vm_entry_lock_set_waiters(entry, state, mask) &&
		    __vm_entry_lock_assert_wait(entry, how, self, hint, mask)) {
			success = false;
			break;
		}
	}

	lck_mcs_dequeue(node, link, LCK_MCS_SLEEPABLE);
	VM_ENTRY_SPIN_END(entry, hint, ctx->start);
	lock_enable_preemption();

	return success;
}

__attribute__((cold, noinline))
static kern_return_t
__vm_entry_lock_exclusive_contended(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how)
{
	thread_t self = current_thread();
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);

	while (!__vm_entry_lock_exclusive_contended_step(entry, self, how, &ctx)) {
		block_hint_t  hint = kThreadWaitVMEntryExclEvent;
		kern_return_t kr;

		kr = __vm_entry_lock_block(map, map_held, entry, addr, hint);

		/*
		 * If this is a lock handoff case, check that the lock is still
		 * within bounds, if not, unlock and ask the caller to relookup.
		 */
		if (kr == KERN_LOCK_OWNED) {
			vm_entry_lock_t state;

			state = os_atomic_load(&entry->vme_lock, acquire);
			assert(state.vmel_excl_locked);

			if (entry->vme_start <= addr && addr < entry->vme_end) {
				__vm_entry_lock_assert_owner(entry, self);
				break;
			}

			__vm_entry_lock_clear_owner(entry, self);
			__vm_entry_lock_exclusive_wakeup(entry, state);
			kr = VMRL_ERR_RELOOKUP;
		}

		if (__improbable(kr != KERN_SUCCESS)) {
			return kr;
		}

		lck_adaptive_spin_reset(&ctx);
	}

	lck_rw_lock_count_inc(self, &entry->vme_lock);
	VMEL_SLOWPATH(vmel_lock_x_slow(entry));
	return KERN_SUCCESS;
}

__mockable kern_return_t
vm_entry_lock_exclusive(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how)
{
	assert_vm_map_ilk_owned_ignore_sealed(map, map_held);

	if (__probable(__vm_entry_lock_exclusive_try(entry, true))) {
		__vm_entry_lock_set_owner(entry, current_thread());
		lck_rw_lock_count_inc(current_thread(), &entry->vme_lock);
		VMEL_SLOWPATH(vmel_lock_x_slow(entry));
		return KERN_SUCCESS;
	}

	return __vm_entry_lock_exclusive_contended(map, map_held, entry, addr, how);
}

__mockable bool
vm_entry_try_lock_exclusive(vm_map_entry_t entry)
{
	if (__probable(__vm_entry_lock_exclusive_try(entry, true))) {
		__vm_entry_lock_set_owner(entry, current_thread());
		lck_rw_lock_count_inc(current_thread(), &entry->vme_lock);
		VMEL_SLOWPATH(vmel_try_lock_x_slow(entry));
		return true;
	}

	/*
	 * If we ever implement SMR for the vm_map_store, we may want this to
	 * not panic for VMEL_INVALID_REASON_ENTRY_DESTROYED.
	 */
	vm_entry_assert_lock_is_valid(entry);
	return false;
}

__mockable void
vm_entry_unlock_exclusive(vm_map_t map __unused, vm_map_entry_t entry)
{
	vm_entry_lock_t ostate, nstate;

	if (__improbable(VME_IS_SENTINEL(entry))) {
		panic("Attempting to unlock a sentinel entry.");
	}

	__vm_entry_lock_clear_owner(entry, current_thread());

	os_atomic_rmw_loop(&entry->vme_lock.vmel_data,
	    ostate.vmel_data, nstate.vmel_data, release, {
		if (ostate.vmel_wait8) {
		        os_atomic_rmw_loop_give_up({
				__vm_entry_lock_exclusive_wakeup(entry, ostate);
			});
		}
		nstate = ostate;
		nstate.vmel_excl_locked = false;
		nstate.vmel_read_count  = 0;
	});

	lck_rw_lock_count_dec(current_thread(), &entry->vme_lock);
	VMEL_SLOWPATH(vmel_unlock_x_slow(entry));
}

__mockable void
vm_entry_lock_exclusive_to_shared(vm_map_entry_t entry)
{
	vm_entry_lock_t ostate, nstate;

	__vm_entry_lock_clear_owner(entry, current_thread());

	os_atomic_rmw_loop(&entry->vme_lock.vmel_data,
	    ostate.vmel_data, nstate.vmel_data, release, {
		nstate = ostate;
		nstate.vmel_excl_locked = false;
		nstate.vmel_read_count  = 1;
	});

	if (!ostate.vmel_valid || !__vm_entry_owned_exclusively(ostate)) {
		__vm_entry_lock_unowned_panic(entry, ostate);
	}
	if (ostate.vmel_shared_waiters && !ostate.vmel_excl_waiters) {
		/*
		 * If we have shared waiters wake them up. Only do this if there
		 * are no exclusive waiters to preserve the writer-bias.
		 */
		__vm_entry_lock_shared_broadcast(entry);
	}

	VMEL_SLOWPATH(vmel_lock_x2s_slow(entry));
}


#pragma mark vm_entry_*_shared

static inline bool
__vm_entry_can_lock_shared(vm_entry_lock_t state)
{
	return state.vmel_valid && !state.vmel_excl_locked;
}

static bool
__vm_entry_lock_shared_try(vm_map_entry_t entry, bool pretest)
{
	vm_entry_lock_t state;

	if (pretest &&
	    !__vm_entry_can_lock_shared(__vm_entry_lock_state(entry))) {
		return false;
	}

#if __arm64__ && __ARM_ARCH_8_3__
	/* see comment in lck_rw_lock_s_try() */
	state.vmel_data = os_atomic_add_orig(&entry->vme_lock.vmel_data,
	    VMEL_ONE_READ_COUNT.vmel_data, relaxed);
	os_atomic_load(&entry->vme_lock.vmel_data, acquire);
#else
	state.vmel_data = os_atomic_add_orig(&entry->vme_lock.vmel_data,
	    VMEL_ONE_READ_COUNT.vmel_data, acquire);
#endif

	if (~state.vmel_read_count == 0) {
		__vm_entry_lock_shared_overflow_panic(entry, state);
	}

	if (__improbable(__vm_entry_can_lock_shared(state) &&
	    state.vmel_shared_waiters && !state.vmel_excl_waiters)) {
		__vm_entry_lock_shared_broadcast(entry);
	}

	return __vm_entry_can_lock_shared(state);
}

__attribute__((cold, noinline))
static void
__vm_entry_lock_shared_wakeup(vm_map_entry_t entry, vm_entry_lock_t state)
{
	if (state.vmel_excl_waiters) {
		__vm_entry_lock_wakeup_all(entry, kThreadWaitVMEntryExclEvent);
	}

	if (state.vmel_shared_waiters) {
		__vm_entry_lock_wakeup_all(entry, kThreadWaitVMEntrySharedEvent);
	}
}

__attribute__((always_inline))
static bool
__vm_entry_lock_shared_contended_step(
	vm_map_entry_t          entry,
	thread_t                self,
	wait_interrupt_t        how,
	lck_adaptive_spin_ctx_t ctx)
{
	block_hint_t    hint = kThreadWaitVMEntrySharedEvent;
	vm_entry_lock_t mask = VMEL_SWAITERS_BIT;
	vm_entry_lock_t state;
	bool            success;

	lock_disable_preemption_for_thread(self);
	lck_adaptive_spin_start(ctx);

	for (;;) {
		state.vmel_data = lock_load_exclusive(&entry->vme_lock.vmel_data,
		    relaxed);

		if (!state.vmel_valid) {
			__vm_entry_lock_invalid_panic(entry, state);
		}

		if (__vm_entry_can_lock_shared(state)) {
			if (__vm_entry_lock_shared_try(entry, false)) {
				success = true;
				break;
			}
			continue;
		}

		lck_adaptive_spin_wait_for_event(ctx);
		lck_adaptive_spin_step(ctx);

		if (ctx->expired &&
		    __vm_entry_lock_set_waiters(entry, state, mask) &&
		    __vm_entry_lock_assert_wait(entry, how, self, hint, mask)) {
			success = false;
			break;
		}
	}

	VM_ENTRY_SPIN_END(entry, hint, ctx->start);
	lock_enable_preemption();

	return success;
}

__attribute__((cold, noinline))
static kern_return_t
__vm_entry_lock_shared_contended(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how)
{
	thread_t self = current_thread();
	LCK_ADAPTIVE_SPIN_CTX_DECL(ctx);

	while (!__vm_entry_lock_shared_contended_step(entry, self, how, &ctx)) {
		block_hint_t  hint = kThreadWaitVMEntrySharedEvent;
		kern_return_t kr;

		kr = __vm_entry_lock_block(map, map_held, entry, addr, hint);
		if (__improbable(kr != KERN_SUCCESS)) {
			return kr;
		}

		lck_adaptive_spin_reset(&ctx);
	}

	lck_rw_lock_count_inc(self, &entry->vme_lock);
	VMEL_SLOWPATH(vmel_lock_s_slow(entry));
	return KERN_SUCCESS;
}

__mockable kern_return_t
vm_entry_lock_shared(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how)
{
	assert_vm_map_ilk_owned_ignore_sealed(map, map_held);

	if (__probable(__vm_entry_lock_shared_try(entry, true))) {
		lck_rw_lock_count_inc(current_thread(), &entry->vme_lock);
		VMEL_SLOWPATH(vmel_lock_s_slow(entry));
		return KERN_SUCCESS;
	}

	return __vm_entry_lock_shared_contended(map, map_held, entry, addr, how);
}

__mockable bool
vm_entry_try_lock_shared(vm_map_entry_t entry)
{
	if (__probable(__vm_entry_lock_shared_try(entry, true))) {
		lck_rw_lock_count_inc(current_thread(), &entry->vme_lock);
		VMEL_SLOWPATH(vmel_try_lock_s_slow(entry));
		return true;
	}

	/*
	 * If we ever implement SMR for the vm_map_store, we may want this to
	 * not panic for VMEL_INVALID_REASON_ENTRY_DESTROYED.
	 */
	vm_entry_assert_lock_is_valid(entry);
	return false;
}

__mockable void
vm_entry_unlock_shared(vm_map_t map __unused, vm_map_entry_t entry)
{
	vm_entry_lock_t waiters_mask = {
		.vmel_excl_waiters   = true,
		.vmel_shared_waiters = true,
	};
	vm_entry_lock_t state;

	state.vmel_data = os_atomic_sub(&entry->vme_lock.vmel_data,
	    VMEL_ONE_READ_COUNT.vmel_data, release);

	if (state.vmel_lock16 == VMEL_UNLOCKED_STATE.vmel_lock16 &&
	    (state.vmel_data & waiters_mask.vmel_data)) {
		__vm_entry_lock_shared_wakeup(entry, state);
	}

	lck_rw_lock_count_dec(current_thread(), &entry->vme_lock);
	VMEL_SLOWPATH(vmel_unlock_s_slow(entry));
}

__mockable bool
vm_entry_lock_try_shared_to_exclusive(vm_map_entry_t entry)
{
	vm_entry_lock_t ostate, nstate;

	os_atomic_rmw_loop(&entry->vme_lock.vmel_lock16,
	    ostate.vmel_lock16, nstate.vmel_lock16, acq_rel, {
		nstate = ostate;
		if (nstate.vmel_lock16 == VMEL_SLOCKED1_STATE.vmel_lock16) {
		        nstate.vmel_lock16 = VMEL_XLOCKED_STATE.vmel_lock16;
		} else {
		        nstate.vmel_read_count -= 1;
		}
	});

	if (!ostate.vmel_valid || !__vm_entry_owned_shared(ostate)) {
		__vm_entry_lock_unowned_panic(entry, ostate);
	}

	if (nstate.vmel_excl_locked) {
		__vm_entry_lock_set_owner(entry, current_thread());
		VMEL_SLOWPATH(vmel_lock_s2x_success_slow(entry));
	} else {
		lck_rw_lock_count_dec(current_thread(), &entry->vme_lock);
		VMEL_SLOWPATH(vmel_unlock_s_slow(entry));
	}

	return nstate.vmel_excl_locked;
}


#pragma mark state bits (needs coalesce, kunwire)

bool
vm_entry_needs_coalesce(vm_map_entry_t entry)
{
	return entry->vme_lock.vmel_needs_coalesce;
}

void
vm_entry_update_needs_coalesce(vm_map_entry_t entry, bool value)
{
	if (value) {
		os_atomic_or(&entry->vme_lock.vmel_state8,
		    VMEL_COALESCE_BIT.vmel_state8, relaxed);
	} else {
		os_atomic_andnot(&entry->vme_lock.vmel_state8,
		    VMEL_COALESCE_BIT.vmel_state8, relaxed);
	}
}

kern_return_t
vm_entry_unlock_and_wait_for_kunwire(
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how)
{
	block_hint_t hint = kThreadWaitVMEntryKUnwireEvent;
	thread_t     self = current_thread();

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	os_atomic_or(&entry->vme_lock.vmel_state8,
	    VMEL_KUNWIRE_BIT.vmel_state8, relaxed);
	(void)__vm_entry_lock_assert_wait(entry, how, self, hint,
	    VMEL_KUNWIRE_BIT);

	vm_entry_unlock_exclusive(map, entry);

	return __vm_entry_lock_block(map, map_held, entry, addr, hint);
}

void
vm_entry_wakeup_kunwire_waiters(vm_map_entry_t entry)
{
	block_hint_t    hint = kThreadWaitVMEntryKUnwireEvent;
	vm_entry_lock_t mask = VMEL_KUNWIRE_BIT;
	vm_entry_lock_t state;

	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	state.vmel_data = os_atomic_andnot_orig(&entry->vme_lock.vmel_data,
	    mask.vmel_data, relaxed);

	if (state.vmel_data & mask.vmel_data) {
		__vm_entry_lock_wakeup_all(entry, hint);
	}
}


#pragma mark invalidation

static void
__vm_entry_wakeup_all_waiters(vm_map_entry_t entry, vm_entry_lock_t state)
{
	/* Make sure we are the owner of this state */
	if (!state.vmel_valid || !__vm_entry_owned_exclusively(state)) {
		__vm_entry_lock_unowned_panic(entry, state);
	}

	/*
	 * And wakeup everyone with THREAD_RESTART. Any wakeups using
	 * THREAD_RESTART must wake all waiters.
	 */
	if (state.vmel_excl_waiters) {
		__vm_entry_lock_wakeup_all(entry, kThreadWaitVMEntryExclEvent);
	}
	if (state.vmel_shared_waiters) {
		__vm_entry_lock_wakeup_all(entry, kThreadWaitVMEntrySharedEvent);
	}
	if (state.vmel_kunwire_waiters) {
		__vm_entry_lock_wakeup_all(entry, kThreadWaitVMEntryKUnwireEvent);
	}
}

void
vm_entry_invalidate_waiters(vm_map_t map, vm_map_entry_t entry)
{
	const vm_entry_lock_t VMEL_WAITERS_MASK = {
		.vmel_kunwire_waiters = true,
		.vmel_excl_waiters    = true,
		.vmel_shared_waiters  = true,
	};
	vm_entry_lock_t state;

	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_EXCLUSIVE);

	state.vmel_data = os_atomic_andnot_orig(&entry->vme_lock.vmel_data,
	    VMEL_WAITERS_MASK.vmel_data, relaxed);

	__vm_entry_wakeup_all_waiters(entry, state);
}


#pragma mark init / destroy

void
vm_entry_lock_init_invalid(vm_map_entry_t entry, vmel_invalid_reason_t reason)
{
	RANGE_LOCK_ASSERT(__builtin_popcount(reason) == 1);
	os_atomic_init(&entry->vme_lock, VMEL_INVALID_STATE(reason));
	__vm_entry_lock_init_owner(entry, THREAD_NULL);
}

void
vm_map_header_init_invalid_lock(struct vm_map_header *hdr)
{
	os_atomic_init(&hdr->links.lock, VMEL_INVALID_STATE(VMEL_INVALID_REASON_MAP_HEADER));
}

void
vm_entry_lock_init_locked_exclusive(vm_map_t map __unused, vm_map_entry_t entry)
{
	os_atomic_init(&entry->vme_lock, VMEL_XLOCKED_STATE);
	__vm_entry_lock_init_owner(entry, current_thread());

	lck_rw_lock_count_inc(current_thread(), &entry->vme_lock);
	VMEL_SLOWPATH(vmel_lock_x_slow(entry));
}

void
vm_entry_lock_destroy_invalid(vm_map_entry_t entry)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	__vm_entry_lock_assert_owner(entry, THREAD_NULL);
	if (state.vmel_valid) {
		__vm_entry_lock_valid_panic(entry, state);
	}

	vm_entry_lock_reinvalidate(entry, VMEL_INVALID_REASON_ANY,
	    VMEL_INVALID_REASON_ENTRY_DESTROYED);
}

__mockable void
vm_entry_unlock_exclusive_and_destroy(vm_map_t map __unused, vm_map_entry_t entry)
{
	vm_entry_lock_t state;

	__vm_entry_lock_clear_owner(entry, current_thread());
	state = os_atomic_xchg(&entry->vme_lock,
	    VMEL_INVALID_STATE(VMEL_INVALID_REASON_ENTRY_DESTROYED),
	    release);

	if (!state.vmel_valid) {
		__vm_entry_lock_invalid_panic(entry, state);
	}

	if (!__vm_entry_owned_exclusively(state)) {
		__vm_entry_lock_unowned_panic(entry, state);
	}

	__vm_entry_wakeup_all_waiters(entry, state);

	lck_rw_lock_count_dec(current_thread(), &entry->vme_lock);
	VMEL_SLOWPATH(vmel_unlock_x_slow(entry));
}


#pragma mark assertions

void
vm_entry_assert_lock_is_valid(vm_map_entry_t entry)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (!state.vmel_valid) {
		__vm_entry_lock_invalid_panic(entry, state);
	}
}

void
vm_entry_assert_lock_is_invalid(
	vm_map_entry_t entry,
	vmel_invalid_reason_t allowed_reasons)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (state.vmel_valid) {
		__vm_entry_lock_valid_panic(entry, state);
	}

	RANGE_LOCK_ASSERT(__builtin_popcount(state.vmel_invalid_reason) == 1);
	if ((state.vmel_invalid_reason & allowed_reasons) == 0) {
		__vm_entry_lock_invalid_reason_mismatch_panic(entry, state,
		    allowed_reasons);
	}
}

void
vm_entry_assert_owner(vm_map_entry_t entry)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (!state.vmel_valid) {
		if (state.vmel_invalid_reason == VMEL_INVALID_REASON_FAKE_ENTRY) {
			return;
		}
		__vm_entry_lock_invalid_panic(entry, state);
	}

	if (__vm_entry_owned_exclusively(state)) {
		__vm_entry_lock_assert_owner(entry, current_thread());
		return;
	}
	if (__vm_entry_owned_shared(state)) {
		return;
	}

	__vm_entry_lock_unowned_panic(entry, state);
}

void
vm_entry_assert_excl_owner(vm_map_entry_t entry)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (!state.vmel_valid) {
		if (state.vmel_invalid_reason == VMEL_INVALID_REASON_FAKE_ENTRY) {
			return;
		}
		__vm_entry_lock_invalid_panic(entry, state);
	}

	if (__vm_entry_owned_exclusively(state)) {
		__vm_entry_lock_assert_owner(entry, current_thread());
		return;
	}

	__vm_entry_lock_unowned_panic(entry, state);
}

void
vm_entry_assert_fields_writable(vm_map_entry_t entry)
{
	vm_entry_lock_t state = os_atomic_load(&entry->vme_lock, relaxed);

	if (state.vmel_valid) {
		vm_entry_assert_excl_owner(entry);
	} else {
		vm_entry_assert_lock_is_invalid(entry,
		    VMEL_INVALID_REASON_COPY_ENTRY);
	}
}

void
vm_entry_assert_shared_owner(vm_map_entry_t entry)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (!state.vmel_valid) {
		if (state.vmel_invalid_reason == VMEL_INVALID_REASON_FAKE_ENTRY) {
			return;
		}
		__vm_entry_lock_invalid_panic(entry, state);
	}

	if (__vm_entry_owned_shared(state)) {
		return;
	}

	__vm_entry_lock_unowned_panic(entry, state);
}

void
vm_entry_assert_not_owner(vm_map_entry_t entry __unused)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (!state.vmel_valid) {
		__vm_entry_lock_invalid_panic(entry, state);
	}
	/*
	 * Currently, we can't do anything to see if we are the owner or not.
	 * That's because we only store whether the lock is exclusively locked,
	 * not the ctid.
	 */
	__vm_entry_lock_assert_not_owner(entry, current_thread());
}

bool
kdp_vm_entry_lock_is_acquired_exclusive(vm_map_entry_t entry)
{
	vm_entry_lock_t state = __vm_entry_lock_state(entry);

	if (not_in_kdp) {
		panic("panic: kdp_vm_entry_lock_is_acquired_exclusive check done outside of kernel debugger");
	}

	return state.vmel_excl_locked;
}

/* num_readers of the given entry. Also helps determine if it's read-locked at all (by returning 0). */
uint32_t
kdp_vm_entry_lock_read_count(vm_map_entry_t entry)
{
	if (not_in_kdp) {
		panic("panic: kdp_vm_entry_lock_read_count check done outside of kernel debugger");
	}

	vm_entry_lock_t state = os_atomic_load(&entry->vme_lock, relaxed);
	return state.vmel_read_count;
}


#pragma mark race tests
#if DEVELOPMENT || DEBUG

#include <kern/mach_param.h>

#define NUM_ENTRIES 2
struct vm_entry_lock_stress_ctx {
	vm_map_entry_t entries[NUM_ENTRIES];
	vm_map_t map;
};

int random();

void
vm_map_entry_free_locked(vm_map_t map, vm_map_entry_t entry);


static inline void
vm_map_ilk_lock(vm_map_t map)
{
	lck_rw_lock_exclusive(&map->ilock);
}

static inline void
vm_map_ilk_unlock(vm_map_t map)
{
	lck_rw_unlock_exclusive(&map->ilock);
}

static inline void
vm_map_ilk_lock_if_not_held(vm_map_t map, bool *ilocked)
{
	if (!(*ilocked)) {
		vm_map_ilk_lock(map);
		*ilocked = true;
	}
}

static inline void
vm_map_ilk_unlock_if_held(vm_map_t map, bool *ilocked)
{
	if (*ilocked) {
		vm_map_ilk_unlock(map);
		*ilocked = false;
	}
}

__enum_closed_decl(lock_operation_t, unsigned char, {
	/* Basic OPS */
	EXCLUSIVE = 0,
	SHARED,

	/* Try locks */
	TRY_SHARED,
	TRY_EXCLUSIVE,

	/* Special ones */
	SHARED_UPGRADE,
	EXCLUSIVE_DOWNGRADE,
	EXCLUSIVE_AND_WIRE,
	EXCLUSIVE_UNLOCK_AND_DESTROY,

	LAST_VALUE,
});

static vm_map_entry_t
vm_entry_lock_stress_add_entry(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
	vm_map_entry_t entry  = vm_map_entry_create_locked(map, start, end);

	vm_map_store_insert(map, entry);

	vm_entry_unlock_exclusive(map, entry);

	return entry;
}

static void
vm_entry_lock_stress_setup_ctx(struct vm_entry_lock_stress_ctx * ctx)
{
	ctx->map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);

	vm_map_ilk_lock(ctx->map);
	for (int i = 0; i < NUM_ENTRIES; i++) {
		vm_map_address_t start = PAGE_SIZE * (10 + i);
		vm_map_address_t end = start + PAGE_SIZE;
		vm_map_entry_t entry = vm_entry_lock_stress_add_entry(ctx->map, start, end);
		entry->protection = 0;
		ctx->entries[i] = entry;
	}
	vm_map_ilk_unlock(ctx->map);
}

static void
vm_entry_lock_stress_test_race(struct vm_entry_lock_stress_ctx * ctx)
{
	kern_return_t kr;
	vm_map_t map = ctx->map;
	bool xlocked = false;
	bool slocked = false;
	bool ilocked = false;

	/*
	 * Randomly:
	 *
	 * 1) Select a lock mode
	 *
	 * 2) An entry in the map
	 *
	 * 3) Whether to do an vm_entry_invalidate_waiters
	 *
	 * 4) Whether to retake the ilk for unlocking the entry (the
	 * reduction of concurrency has shown to be useful)
	 */
	lock_operation_t mode = random() % LAST_VALUE;
	int entry_to_test = random() % NUM_ENTRIES;
	bool invalidate = (random() % 10) == 0;
	bool retake_ilock = (random() % 5) == 0;

	vm_map_ilk_lock(map);
	ilocked = true;

	vm_map_entry_t entry = ctx->entries[entry_to_test];
	vm_map_address_t __unused start = entry->vme_start;
	vm_map_address_t __unused end = entry->vme_end;

	/*
	 * Stage 1:
	 * Initially lock the entry
	 */
	switch (mode) {
	case EXCLUSIVE_UNLOCK_AND_DESTROY:
	case EXCLUSIVE:
	case EXCLUSIVE_AND_WIRE:
		kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry,
		    entry->vme_start, 0);
		if (kr == KERN_SUCCESS) {
			xlocked = true;
		}
		break;
	case SHARED:
		kr = vm_entry_lock_shared(map, LCK_RW_TYPE_EXCLUSIVE,
		    entry, entry->vme_start, 0);
		if (kr == KERN_SUCCESS) {
			slocked = true;
		}
		break;
	case SHARED_UPGRADE:
		kr = vm_entry_lock_shared(map, LCK_RW_TYPE_EXCLUSIVE,
		    entry, entry->vme_start, 0);
		if (kr == KERN_SUCCESS) {
			xlocked = vm_entry_lock_try_shared_to_exclusive(entry);
		}
		break;
	case EXCLUSIVE_DOWNGRADE:
		kr = vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE,
		    entry, entry->vme_start, 0);
		if (kr == KERN_SUCCESS) {
			vm_entry_lock_exclusive_to_shared(entry);
			slocked = true;
		}
		break;
	case TRY_SHARED:
		slocked = vm_entry_try_lock_shared(entry);
		break;
	case TRY_EXCLUSIVE:
		xlocked = vm_entry_try_lock_exclusive(entry);
		break;
	case LAST_VALUE:
		panic("Unexpected mode");
	}

	vm_map_ilk_unlock(map);
	ilocked = false;

	/*
	 * Stage 2:
	 * If the entry is locked, do any operations we want to.
	 * Unlock the entry.
	 */
	if (xlocked || slocked) {
		assert(current_thread()->rwlock_count == 1);

		if (retake_ilock) {
			vm_map_ilk_lock_if_not_held(map, &ilocked);
		}

		if (invalidate && xlocked) {
			vm_map_ilk_lock_if_not_held(map, &ilocked);
			/*
			 * This sort of mimics clipping, although it
			 * doesn't actually change the entry bounds
			 */
			vm_entry_invalidate_waiters(map, entry);

			if (!retake_ilock) {
				vm_map_ilk_unlock(map);
				ilocked = false;
			}
		}

		switch (mode) {
		case EXCLUSIVE_AND_WIRE:
			vm_entry_wakeup_kunwire_waiters(entry);
			OS_FALLTHROUGH;
		case EXCLUSIVE:
		case SHARED_UPGRADE:
		case TRY_EXCLUSIVE:
			vm_entry_unlock_exclusive(map, entry);
			break;
		case TRY_SHARED:
		case SHARED:
		case EXCLUSIVE_DOWNGRADE:
			vm_entry_unlock_shared(map, entry);
			break;
		case EXCLUSIVE_UNLOCK_AND_DESTROY:
			vm_map_ilk_lock_if_not_held(map, &ilocked);
			vm_map_store_remove(map, entry,
			    VMS_REMOVE_FREE_ENTRY | VMS_REMOVE_FREE_SLOTS);
			ctx->entries[entry_to_test] =
			    vm_entry_lock_stress_add_entry(map, start, end);
			break;
		case LAST_VALUE:
			panic("Unexpected mode");
		}

		vm_map_ilk_unlock_if_held(map, &ilocked);
	}

	assert(current_thread()->rwlock_count == 0);
}

struct vm_entry_lock_stress_ctx * entry_lock_test_ctx;
static int entry_threads_waiting = 0;

static LCK_GRP_DECLARE(_entry_lock_stress_test, "range lock test");
static LCK_MTX_DECLARE(entry_lock_stress_test_mtx, &_entry_lock_stress_test);

static struct vm_entry_lock_stress_ctx *
vm_entry_lock_stress_get_ctx(void)
{
	lck_mtx_lock(&entry_lock_stress_test_mtx);
	if (!entry_lock_test_ctx) {
		entry_lock_test_ctx = kalloc_type(struct vm_entry_lock_stress_ctx, Z_ZERO | Z_WAITOK);
		vm_entry_lock_stress_setup_ctx(entry_lock_test_ctx);
	}
	lck_mtx_unlock(&entry_lock_stress_test_mtx);
	return entry_lock_test_ctx;
}

static int
vm_entry_lock_stress_wait_for_threads(
	int * thread_wait_count,
	int target_wait_count,
	event_t event)
{
	int ret = assert_wait(event, THREAD_UNINT);
	assert(ret == THREAD_WAITING);
	int waiters = os_atomic_inc(thread_wait_count, release);
	if (waiters == target_wait_count) {
		os_atomic_store(thread_wait_count, 0, release);

		clear_wait(current_thread(), THREAD_AWAKENED);
		thread_wakeup(event);
	} else {
		ret = thread_block(THREAD_CONTINUE_NULL);
		assert(ret == THREAD_AWAKENED);
	}
	return waiters;
}


void
unpack_threads_and_iterations(
	uint64_t  packed_threads_and_iters,
	uint32_t *threads,
	uint32_t *iterations);

static int
vm_entry_lock_stress_test(int64_t packed_thread_and_iters, int64_t *out)
{
	uint32_t num_threads_to_wait_for;
	uint32_t num_races_to_test;

	unpack_threads_and_iterations((uint64_t) packed_thread_and_iters,
	    &num_threads_to_wait_for, &num_races_to_test);

	if (num_threads_to_wait_for > task_threadmax) {
		return KERN_INVALID_ARGUMENT;
	}
	struct vm_entry_lock_stress_ctx * test_ctx = vm_entry_lock_stress_get_ctx();

	vm_entry_lock_stress_wait_for_threads(&entry_threads_waiting,
	    (int) num_threads_to_wait_for, (event_t) test_ctx);

	for (uint32_t i = 0; i < num_races_to_test; i++) {
		vm_entry_lock_stress_test_race(test_ctx);
	}

	*out = 1;
	return 0;
}

SYSCTL_TEST_REGISTER(vm_entry_lock_stress_test, vm_entry_lock_stress_test);

#endif /* DEVELOPMENT || DEBUG */
