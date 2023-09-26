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

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>
#include <kern/locks_internal.h>
#include <kern/lock_stat.h>
#include <kern/lock_ptr.h>

#include <mach/mach_time.h>
#include <mach/machine/sdt.h>
#include <mach/vm_param.h>

#include <machine/cpu_data.h>
#include <machine/machine_cpu.h>


#pragma mark hw_lck_ptr_t: helpers

static_assert(VM_KERNEL_POINTER_SIGNIFICANT_BITS < HW_LCK_PTR_BITS,
    "sign extension of lck_ptr_bits does the right thing");

static inline void
__hw_lck_ptr_encode(hw_lck_ptr_t *lck, const void *ptr)
{
	lck->lck_ptr_bits = (intptr_t)ptr;
#if CONFIG_KERNEL_TAGGING
	lck->lck_ptr_tag  = vm_memtag_extract_tag((vm_offset_t)ptr);
#endif /* CONFIG_KERNEL_TAGGING */
}

__abortlike
static void
__hw_lck_ptr_invalid_panic(hw_lck_ptr_t *lck)
{
	hw_lck_ptr_t tmp = os_atomic_load(lck, relaxed);

	panic("Invalid/destroyed ptr spinlock %p: <%p %d 0x%04x>",
	    lck, __hw_lck_ptr_value(tmp), tmp.lck_ptr_locked,
	    tmp.lck_ptr_mcs_tail);
}

__attribute__((always_inline, overloadable))
static inline bool
hw_lck_ptr_take_slowpath(hw_lck_ptr_t tmp)
{
	hw_lck_ptr_t check_bits = {
#if CONFIG_DTRACE
		.lck_ptr_stats  = true,
#endif /* CONFIG_DTRACE */
	};
	unsigned long take_slowpath = 0;

	take_slowpath = tmp.lck_ptr_value & check_bits.lck_ptr_value;
#if CONFIG_DTRACE
	take_slowpath |= lockstat_enabled();
#endif /* CONFIG_DTRACE */
	return take_slowpath;
}


#pragma mark hw_lck_ptr_t: init/destroy

void
hw_lck_ptr_init(hw_lck_ptr_t *lck, void *val, lck_grp_t *grp)
{
	hw_lck_ptr_t init = { };

#if LCK_GRP_USE_ARG
	if (grp) {
#if CONFIG_DTRACE
		if (grp->lck_grp_attr_id & LCK_GRP_ATTR_STAT) {
			init.lck_ptr_stats = true;
		}
#endif /* CONFIG_DTRACE */
		lck_grp_reference(grp, &grp->lck_grp_spincnt);
	}
#endif /* LCK_GRP_USE_ARG */

	__hw_lck_ptr_encode(&init, val);
	os_atomic_init(lck, init);
}

void
hw_lck_ptr_destroy(hw_lck_ptr_t *lck, lck_grp_t *grp)
{
	hw_lck_ptr_t tmp = os_atomic_load(lck, relaxed);

	if (tmp.lck_ptr_locked || tmp.lck_ptr_mcs_tail) {
		__hw_lck_ptr_invalid_panic(lck);
	}
#if LCK_GRP_USE_ARG
	if (grp) {
		lck_grp_deallocate(grp, &grp->lck_grp_spincnt);
	}
#endif /* LCK_GRP_USE_ARG */

	/* make clients spin forever, and use an invalid MCS ID */
	tmp.lck_ptr_locked   = true;
	tmp.lck_ptr_stats    = false;
	tmp.lck_ptr_mcs_tail = 0xffff;
	os_atomic_store(lck, tmp, relaxed);
}

bool
hw_lck_ptr_held(hw_lck_ptr_t *lck)
{
	return os_atomic_load(lck, relaxed).lck_ptr_locked;
}


#pragma mark hw_lck_ptr_t: hw_lck_ptr_lock

__abortlike
static hw_spin_timeout_status_t
hw_lck_ptr_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	hw_lck_ptr_t *lck = _lock;
	hw_lck_ptr_t tmp;

	tmp  = os_atomic_load(lck, relaxed);
	panic("Ptr spinlock[%p] " HW_SPIN_TIMEOUT_FMT "; "
	    "ptr_value: %p, mcs_tail: 0x%04x, "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    lck, HW_SPIN_TIMEOUT_ARG(to, st),
	    __hw_lck_ptr_value(tmp), tmp.lck_ptr_mcs_tail,
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy hw_lck_ptr_spin_policy = {
	.hwsp_name              = "hw_lck_ptr_lock",
	.hwsp_timeout_atomic    = &lock_panic_timeout,
	.hwsp_op_timeout        = hw_lck_ptr_timeout_panic,
};


static void * __attribute__((noinline))
hw_lck_ptr_contended(hw_lck_ptr_t *lck LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_spin_policy_t  pol = &hw_lck_ptr_spin_policy;
	hw_spin_timeout_t to  = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss  = { };

	hw_lck_ptr_t      value, nvalue;
	lck_mcs_id_t      pidx;
	lck_spin_txn_t    txn;

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t          spin_start;

	lck_grp_spin_update_miss(lck LCK_GRP_ARG(grp));
	if (__improbable(lck_grp_spin_spin_enabled(lck LCK_GRP_ARG(grp)))) {
		spin_start = mach_absolute_time();
	}
#endif /* LOCK_STATS || CONFIG_DTRACE */

	/*
	 *	Take a spot in the MCS queue,
	 *	and then spin until we're at the head of it.
	 */

	txn = lck_spin_txn_begin(lck);

	pidx = os_atomic_xchg(&lck->lck_ptr_mcs_tail, txn.txn_mcs_id, release);
	if (pidx) {
		lck_spin_mcs_t pnode;
		unsigned long ready;

		pnode = lck_spin_mcs_decode(pidx);
		os_atomic_store(&pnode->lsm_next, txn.txn_slot, relaxed);

		while (!hw_spin_wait_until(&txn.txn_slot->lsm_ready, ready, ready)) {
			hw_spin_should_keep_spinning(lck, pol, to, &ss);
		}
	}

	/*
	 *	We're now the first in line, wait for the lock bit
	 *	to look ready and take it.
	 */
	do {
		while (!hw_spin_wait_until(&lck->lck_ptr_value,
		    value.lck_ptr_value, value.lck_ptr_locked == 0)) {
			hw_spin_should_keep_spinning(lck, pol, to, &ss);
		}

		nvalue = value;
		nvalue.lck_ptr_locked = true;
		if (nvalue.lck_ptr_mcs_tail == txn.txn_mcs_id) {
			nvalue.lck_ptr_mcs_tail = 0;
		}
	} while (!os_atomic_cmpxchg(lck, value, nvalue, acquire));

	/*
	 *	We now have the lock, let's cleanup the MCS state.
	 *
	 *	If there is a node after us, notify that it
	 *	is at the head of the interlock queue.
	 *
	 *	Then, clear the MCS node.
	 */
	if (value.lck_ptr_mcs_tail != txn.txn_mcs_id) {
		lck_spin_mcs_t nnode;

		while (!hw_spin_wait_until(&txn.txn_slot->lsm_next, nnode, nnode)) {
			hw_spin_should_keep_spinning(lck, pol, to, &ss);
		}

		os_atomic_store(&nnode->lsm_ready, 1, relaxed);
	}

	lck_spin_txn_end(&txn);

#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(spin_start)) {
		lck_grp_spin_update_spin(lck LCK_GRP_ARG(grp),
		    mach_absolute_time() - spin_start);
	}
#endif /* CONFIG_DTRACE || LCK_GRP_STAT */

	return __hw_lck_ptr_value(value);
}

#if CONFIG_DTRACE
__attribute__((noinline))
#else /* !CONFIG_DTRACE */
__attribute__((always_inline))
#endif /* !CONFIG_DTRACE */
static void *
hw_lck_ptr_lock_slow(
	hw_lck_ptr_t           *lck,
	hw_lck_ptr_t            tmp
	LCK_GRP_ARG(lck_grp_t  *grp))
{
	lck_grp_spin_update_held(lck LCK_GRP_ARG(grp));
	return __hw_lck_ptr_value(tmp);
}

static inline void *
hw_lck_ptr_lock_fastpath(hw_lck_ptr_t *lck LCK_GRP_ARG(lck_grp_t *grp))
{
	hw_lck_ptr_t lock_bit = { .lck_ptr_locked = 1 };
	hw_lck_ptr_t tmp;

	tmp = os_atomic_load(lck, relaxed);
	if (__probable(tmp.lck_ptr_locked == 0 && tmp.lck_ptr_mcs_tail == 0)) {
		tmp.lck_ptr_value = os_atomic_or_orig(&lck->lck_ptr_value,
		    lock_bit.lck_ptr_value, acquire);
		if (__probable(tmp.lck_ptr_locked == 0)) {
			if (__probable(!hw_lck_ptr_take_slowpath(tmp))) {
				return __hw_lck_ptr_value(tmp);
			}
			return hw_lck_ptr_lock_slow(lck, tmp LCK_GRP_ARG(grp));
		}
	}

	return hw_lck_ptr_contended(lck LCK_GRP_ARG(grp));
}

void *
hw_lck_ptr_lock_nopreempt(hw_lck_ptr_t *lck, lck_grp_t *grp)
{
	return hw_lck_ptr_lock_fastpath(lck LCK_GRP_ARG(grp));
}

void *
hw_lck_ptr_lock(hw_lck_ptr_t *lck, lck_grp_t *grp)
{
	lock_disable_preemption_for_thread(current_thread());
	return hw_lck_ptr_lock_fastpath(lck LCK_GRP_ARG(grp));
}



#pragma mark hw_lck_ptr_t: hw_lck_ptr_unlock

#if CONFIG_DTRACE
__attribute__((noinline))
static void
hw_lck_ptr_unlock_slow(
	hw_lck_ptr_t           *lck,
	bool                    do_preempt
	LCK_GRP_ARG(lck_grp_t  *grp))
{
	if (do_preempt) {
		lock_enable_preemption();
	}
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lck,
	    (uintptr_t)LCK_GRP_PROBEARG(grp));
}
#endif /* CONFIG_DTRACE */

static inline void
hw_lck_ptr_unlock_fastpath(
	hw_lck_ptr_t           *lck,
	void                   *val,
	bool                    do_preempt
	LCK_GRP_ARG(lck_grp_t  *grp))
{
	hw_lck_ptr_t curv;
	hw_lck_ptr_t xorv = { };

	/*
	 * compute the value to xor in order to unlock + change the pointer
	 * value, but leaving the lck_ptr_stats and lck_ptr_mcs_tail unmodified.
	 *
	 * (the latter might change while we unlock and this avoids a CAS loop.
	 */
	curv = atomic_load_explicit((hw_lck_ptr_t _Atomic *)lck,
	    memory_order_relaxed);

	curv.lck_ptr_stats = false;
	curv.lck_ptr_mcs_tail = 0;

	__hw_lck_ptr_encode(&xorv, val);
	xorv.lck_ptr_value ^= curv.lck_ptr_value;

	curv.lck_ptr_value =
	    os_atomic_xor(&lck->lck_ptr_value, xorv.lck_ptr_value, release);

#if CONFIG_DTRACE
	if (__improbable(hw_lck_ptr_take_slowpath(curv))) {
		return hw_lck_ptr_unlock_slow(lck, do_preempt LCK_GRP_ARG(grp));
	}
#endif /* CONFIG_DTRACE */

	if (do_preempt) {
		lock_enable_preemption();
	}
}

void
hw_lck_ptr_unlock_nopreempt(hw_lck_ptr_t *lck, void *val, lck_grp_t *grp)
{
	hw_lck_ptr_unlock_fastpath(lck, val, false LCK_GRP_ARG(grp));
}

void
hw_lck_ptr_unlock(hw_lck_ptr_t *lck, void *val, lck_grp_t *grp)
{
	hw_lck_ptr_unlock_fastpath(lck, val, true LCK_GRP_ARG(grp));
}


#pragma mark hw_lck_ptr_t: hw_lck_ptr_wait_for_value

static void __attribute__((noinline))
hw_lck_ptr_wait_for_value_contended(
	hw_lck_ptr_t           *lck,
	void                   *val
	LCK_GRP_ARG(lck_grp_t  *grp))
{
	hw_spin_policy_t  pol = &hw_lck_ptr_spin_policy;
	hw_spin_timeout_t to  = hw_spin_compute_timeout(pol);
	hw_spin_state_t   ss  = { };
	hw_lck_ptr_t      tmp;

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t          spin_start;

	if (__improbable(lck_grp_spin_spin_enabled(lck LCK_GRP_ARG(grp)))) {
		spin_start = mach_absolute_time();
	}
#endif /* LOCK_STATS || CONFIG_DTRACE */

	while (__improbable(!hw_spin_wait_until(&lck->lck_ptr_value,
	    tmp.lck_ptr_value, __hw_lck_ptr_value(tmp) == val))) {
		hw_spin_should_keep_spinning(lck, pol, to, &ss);
	}

#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(spin_start)) {
		lck_grp_spin_update_spin(lck LCK_GRP_ARG(grp),
		    mach_absolute_time() - spin_start);
	}
#endif /* CONFIG_DTRACE || LCK_GRP_STAT */

	os_atomic_thread_fence(acquire);
}

void
hw_lck_ptr_wait_for_value(
	hw_lck_ptr_t           *lck,
	void                   *val,
	lck_grp_t              *grp)
{
	hw_lck_ptr_t tmp = os_atomic_load(lck, acquire);

	if (__probable(__hw_lck_ptr_value(tmp) == val)) {
		return;
	}

	hw_lck_ptr_wait_for_value_contended(lck, val LCK_GRP_ARG(grp));
}
