/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
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
 * Mach Operating System Copyright (c) 1991,1990,1989,1988,1987 Carnegie
 * Mellon University All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright notice
 * and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof, and that
 * both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION.
 * CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 * Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 * School of Computer Science Carnegie Mellon University Pittsburgh PA
 * 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon the
 * rights to redistribute these changes.
 */
/*
 *	File:	kern/lock.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Locking primitives implementation
 */

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>

#include <mach/machine/sdt.h>

#include <kern/locks_internal.h>
#include <kern/zalloc.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_hygiene.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <kern/kcdata.h>
#include <kern/percpu.h>
#include <kern/hvg_hypercall.h>
#include <string.h>
#include <arm/cpu_internal.h>
#include <os/hash.h>
#include <arm/cpu_data.h>

#include <arm/cpu_data_internal.h>
#include <arm64/proc_reg.h>
#include <arm/smp.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>

#include <pexpert/pexpert.h>

#include <sys/kdebug.h>

#define ANY_LOCK_DEBUG  (USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

// Panic in tests that check lock usage correctness
// These are undesirable when in a panic or a debugger is runnning.
#define LOCK_CORRECTNESS_PANIC() (kernel_debugger_entry_count == 0)

/* Forwards */

extern unsigned int not_in_kdp;

MACHINE_TIMEOUT(lock_panic_timeout, "lock-panic",
    0xc00000 /* 12.5 m ticks ~= 524ms with 24MHz OSC */, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

#define NOINLINE                __attribute__((noinline))

#define interrupts_disabled(mask) (mask & DAIF_IRQF)

KALLOC_TYPE_DEFINE(KT_LCK_SPIN, lck_spin_t, KT_PRIV_ACCT);

#pragma GCC visibility push(hidden)
/*
 * atomic exchange API is a low level abstraction of the operations
 * to atomically read, modify, and write a pointer.  This abstraction works
 * for both Intel and ARMv8.1 compare and exchange atomic instructions as
 * well as the ARM exclusive instructions.
 *
 * atomic_exchange_begin() - begin exchange and retrieve current value
 * atomic_exchange_complete() - conclude an exchange
 * atomic_exchange_abort() - cancel an exchange started with atomic_exchange_begin()
 */
uint32_t
load_exclusive32(uint32_t *target, enum memory_order ord)
{
	uint32_t        value;

	if (_os_atomic_mo_has_acquire(ord)) {
		value = __builtin_arm_ldaex(target);    // ldaxr
	} else {
		value = __builtin_arm_ldrex(target);    // ldxr
	}

	return value;
}

boolean_t
store_exclusive32(uint32_t *target, uint32_t value, enum memory_order ord)
{
	boolean_t err;

	if (_os_atomic_mo_has_release(ord)) {
		err = __builtin_arm_stlex(value, target);       // stlxr
	} else {
		err = __builtin_arm_strex(value, target);       // stxr
	}

	return !err;
}

uint32_t
atomic_exchange_begin32(uint32_t *target, uint32_t *previous, enum memory_order ord)
{
	uint32_t        val;

#if !OS_ATOMIC_USE_LLSC
	ord = memory_order_relaxed;
#endif
	val = load_exclusive32(target, ord);
	*previous = val;
	return val;
}

boolean_t
atomic_exchange_complete32(uint32_t *target, uint32_t previous, uint32_t newval, enum memory_order ord)
{
#if !OS_ATOMIC_USE_LLSC
	return __c11_atomic_compare_exchange_strong((_Atomic uint32_t *)target, &previous, newval, ord, memory_order_relaxed);
#else
	(void)previous;         // Previous not needed, monitor is held
	return store_exclusive32(target, newval, ord);
#endif
}

void
atomic_exchange_abort(void)
{
	os_atomic_clear_exclusive();
}

boolean_t
atomic_test_and_set32(uint32_t *target, uint32_t test_mask, uint32_t set_mask, enum memory_order ord, boolean_t wait)
{
	uint32_t                value, prev;

	for (;;) {
		value = atomic_exchange_begin32(target, &prev, ord);
		if (value & test_mask) {
			if (wait) {
				wait_for_event();       // Wait with monitor held
			} else {
				atomic_exchange_abort();        // Clear exclusive monitor
			}
			return FALSE;
		}
		value |= set_mask;
		if (atomic_exchange_complete32(target, prev, value, ord)) {
			return TRUE;
		}
	}
}

#pragma GCC visibility pop

#if CONFIG_PV_TICKET
__startup_func
void
lck_init_pv(void)
{
	uint32_t pvtck = 1;
	PE_parse_boot_argn("pvticket", &pvtck, sizeof(pvtck));
	if (pvtck == 0) {
		return;
	}
	has_lock_pv = hvg_is_hcall_available(HVG_HCALL_VCPU_WFK) &&
	    hvg_is_hcall_available(HVG_HCALL_VCPU_KICK);
}
STARTUP(LOCKS, STARTUP_RANK_FIRST, lck_init_pv);
#endif


#pragma mark lck_spin_t
#if LCK_SPIN_IS_TICKET_LOCK

lck_spin_t *
lck_spin_alloc_init(lck_grp_t *grp, lck_attr_t *attr)
{
	lck_spin_t *lck;

	lck = zalloc(KT_LCK_SPIN);
	lck_spin_init(lck, grp, attr);
	return lck;
}

void
lck_spin_free(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_spin_destroy(lck, grp);
	zfree(KT_LCK_SPIN, lck);
}

void
lck_spin_init(lck_spin_t *lck, lck_grp_t *grp, __unused lck_attr_t *attr)
{
	lck_ticket_init(lck, grp);
}

/*
 * arm_usimple_lock is a lck_spin_t without a group or attributes
 */
MARK_AS_HIBERNATE_TEXT void inline
arm_usimple_lock_init(simple_lock_t lck, __unused unsigned short initial_value)
{
	lck_ticket_init((lck_ticket_t *)lck, LCK_GRP_NULL);
}

void
lck_spin_assert(const lck_spin_t *lock, unsigned int type)
{
	if (type == LCK_ASSERT_OWNED) {
		lck_ticket_assert_owned(lock);
	} else if (type == LCK_ASSERT_NOTOWNED) {
		lck_ticket_assert_not_owned(lock);
	} else {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}
}

void
lck_spin_lock(lck_spin_t *lock)
{
	lck_ticket_lock(lock, LCK_GRP_NULL);
}

void
lck_spin_lock_nopreempt(lck_spin_t *lock)
{
	lck_ticket_lock_nopreempt(lock, LCK_GRP_NULL);
}

int
lck_spin_try_lock(lck_spin_t *lock)
{
	return lck_ticket_lock_try(lock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_nopreempt(lck_spin_t *lock)
{
	return lck_ticket_lock_try_nopreempt(lock, LCK_GRP_NULL);
}

void
lck_spin_unlock(lck_spin_t *lock)
{
	lck_ticket_unlock(lock);
}

void
lck_spin_destroy(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_ticket_destroy(lck, grp);
}

/*
 * those really should be in an alias file instead,
 * but you can't make that conditional.
 *
 * it will be good enough for perf evals for now
 *
 * we also can't make aliases for symbols that
 * are in alias files like lck_spin_init and friends,
 * so this suffers double jump penalties for kexts
 * (LTO does the right thing for XNU).
 */
#define make_alias(a, b) asm(".globl _" #a "\n" ".set   _" #a ", _" #b "\n")
make_alias(lck_spin_lock_grp, lck_ticket_lock);
make_alias(lck_spin_lock_nopreempt_grp, lck_ticket_lock_nopreempt);
make_alias(lck_spin_try_lock_grp, lck_ticket_lock_try);
make_alias(lck_spin_try_lock_nopreempt_grp, lck_ticket_lock_try_nopreempt);
make_alias(lck_spin_unlock_nopreempt, lck_ticket_unlock_nopreempt);
make_alias(kdp_lck_spin_is_acquired, kdp_lck_ticket_is_acquired);
#undef make_alias

#else /* !LCK_SPIN_IS_TICKET_LOCK */

#if DEVELOPMENT || DEBUG
__abortlike
static void
__lck_spin_invalid_panic(lck_spin_t *lck)
{
	const char *how = "Invalid";

	if (lck->type == LCK_SPIN_TYPE_DESTROYED ||
	    lck->lck_spin_data == LCK_SPIN_TAG_DESTROYED) {
		how = "Destroyed";
	}

	panic("%s spinlock %p: <0x%016lx 0x%16lx>",
	    how, lck, lck->lck_spin_data, lck->type);
}

static inline void
lck_spin_verify(lck_spin_t *lck)
{
	if (lck->type != LCK_SPIN_TYPE ||
	    lck->lck_spin_data == LCK_SPIN_TAG_DESTROYED) {
		__lck_spin_invalid_panic(lck);
	}
}
#else /* DEVELOPMENT || DEBUG */
#define lck_spin_verify(lck)            ((void)0)
#endif /* DEVELOPMENT || DEBUG */

lck_spin_t *
lck_spin_alloc_init(lck_grp_t *grp, lck_attr_t *attr)
{
	lck_spin_t *lck;

	lck = zalloc(KT_LCK_SPIN);
	lck_spin_init(lck, grp, attr);
	return lck;
}

void
lck_spin_free(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_spin_destroy(lck, grp);
	zfree(KT_LCK_SPIN, lck);
}

void
lck_spin_init(lck_spin_t *lck, lck_grp_t *grp, __unused lck_attr_t *attr)
{
	lck->type = LCK_SPIN_TYPE;
	hw_lock_init(&lck->hwlock);
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_spincnt);
	}
}

/*
 * arm_usimple_lock is a lck_spin_t without a group or attributes
 */
MARK_AS_HIBERNATE_TEXT void inline
arm_usimple_lock_init(simple_lock_t lck, __unused unsigned short initial_value)
{
	lck->type = LCK_SPIN_TYPE;
	hw_lock_init(&lck->hwlock);
}

void
lck_spin_assert(const lck_spin_t *lock, unsigned int type)
{
	thread_t thread, holder;

	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}

	holder = HW_LOCK_STATE_TO_THREAD(lock->lck_spin_data);
	thread = current_thread();
	if (type == LCK_ASSERT_OWNED) {
		if (holder == 0) {
			panic("Lock not owned %p = %p", lock, holder);
		}
		if (holder != thread) {
			panic("Lock not owned by current thread %p = %p", lock, holder);
		}
	} else if (type == LCK_ASSERT_NOTOWNED) {
		if (holder != THREAD_NULL && holder == thread) {
			panic("Lock owned by current thread %p = %p", lock, holder);
		}
	} else {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}
}

void
lck_spin_lock(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_lock(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	hw_lock_lock(&lock->hwlock, grp);
}

void
lck_spin_lock_nopreempt(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_lock_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	hw_lock_lock_nopreempt(&lock->hwlock, grp);
}

int
lck_spin_try_lock(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	return hw_lock_try(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	return hw_lock_try(&lock->hwlock, grp);
}

int
lck_spin_try_lock_nopreempt(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	return hw_lock_try_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	lck_spin_verify(lock);
	return hw_lock_try_nopreempt(&lock->hwlock, grp);
}

void
lck_spin_unlock(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_unlock(&lock->hwlock);
}

void
lck_spin_unlock_nopreempt(lck_spin_t *lock)
{
	lck_spin_verify(lock);
	hw_lock_unlock_nopreempt(&lock->hwlock);
}

void
lck_spin_destroy(lck_spin_t *lck, lck_grp_t *grp)
{
	lck_spin_verify(lck);
	*lck = (lck_spin_t){
		.lck_spin_data = LCK_SPIN_TAG_DESTROYED,
		.type = LCK_SPIN_TYPE_DESTROYED,
	};
	if (grp) {
		lck_grp_deallocate(grp, &grp->lck_grp_spincnt);
	}
}

/*
 * Routine: kdp_lck_spin_is_acquired
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_spin_is_acquired(lck_spin_t *lck)
{
	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	return ((lck->lck_spin_data & ~LCK_SPIN_TAG_DESTROYED) != 0) ? TRUE:FALSE;
}

#endif /* !LCK_SPIN_IS_TICKET_LOCK */

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t l,
	unsigned short tag)
{
	simple_lock_init((simple_lock_t) l, tag);
}


/*
 *	Acquire a usimple_lock.
 *
 *	Returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_lock)(
	usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
	simple_lock((simple_lock_t) l, LCK_GRP_PROBEARG(grp));
}


/*
 *	Release a usimple_lock.
 *
 *	Returns with preemption enabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_unlock)(
	usimple_lock_t l)
{
	simple_unlock((simple_lock_t)l);
}


/*
 *	Conditionally acquire a usimple_lock.
 *
 *	On success, returns with preemption disabled.
 *	On failure, returns with preemption in the same state
 *	as when first invoked.  Note that the hw_lock routines
 *	are responsible for maintaining preemption state.
 *
 *	XXX No stats are gathered on a miss; I preserved this
 *	behavior from the original assembly-language code, but
 *	doesn't it make sense to log misses?  XXX
 */
unsigned
int
(usimple_lock_try)(
	usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
	return simple_lock_try((simple_lock_t) l, grp);
}
