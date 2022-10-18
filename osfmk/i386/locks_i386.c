/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 *	File:	kern/lock.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Locking primitives implementation
 */

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>

#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <string.h>

#include <i386/machine_routines.h> /* machine_timeout_suspended() */
#include <i386/tsc.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <i386/mp.h>
#include <machine/atomic.h>
#include <sys/kdebug.h>
#if LCK_MTX_USE_ARCH
#include <i386/locks_i386_inlines.h>
#endif /* LCK_MTX_USE_ARCH */
#include <kern/cpu_number.h>
#include <os/hash.h>
#include <i386/cpuid.h>

#define ANY_LOCK_DEBUG  (USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

uint64_t _Atomic lock_panic_timeout = 0xf000000;  /* 251e6 TSC ticks */

/* Forwards */

#if     USLOCK_DEBUG
/*
 *	Perform simple lock checks.
 */
int     uslock_check = 1;
int     max_lock_loops  = 100000000;
decl_simple_lock_data(extern, printf_lock);
decl_simple_lock_data(extern, panic_lock);
#endif  /* USLOCK_DEBUG */

extern unsigned int not_in_kdp;

#if !LCK_GRP_USE_ARG
#define usimple_lock_nopreempt(lck, grp) \
	usimple_lock_nopreempt(lck)
#define usimple_lock_try_nopreempt(lck, grp) \
	usimple_lock_try_nopreempt(lck)
#endif
static void usimple_lock_nopreempt(usimple_lock_t, lck_grp_t *);
static unsigned int usimple_lock_try_nopreempt(usimple_lock_t, lck_grp_t *);

/*
 *	We often want to know the addresses of the callers
 *	of the various lock routines.  However, this information
 *	is only used for debugging and statistics.
 */
typedef void    *pc_t;
#define INVALID_PC      ((void *) VM_MAX_KERNEL_ADDRESS)
#define INVALID_THREAD  ((void *) VM_MAX_KERNEL_ADDRESS)
#if     ANY_LOCK_DEBUG
#define OBTAIN_PC(pc)   ((pc) = GET_RETURN_PC())
#define DECL_PC(pc)     pc_t pc;
#else   /* ANY_LOCK_DEBUG */
#define DECL_PC(pc)
#ifdef  lint
/*
 *	Eliminate lint complaints about unused local pc variables.
 */
#define OBTAIN_PC(pc)   ++pc
#else   /* lint */
#define OBTAIN_PC(pc)
#endif  /* lint */
#endif  /* USLOCK_DEBUG */

KALLOC_TYPE_DEFINE(KT_LCK_SPIN, lck_spin_t, KT_PRIV_ACCT);

#if LCK_MTX_USE_ARCH
KALLOC_TYPE_DEFINE(KT_LCK_MTX, lck_mtx_t, KT_PRIV_ACCT);
#endif /* LCK_MTX_USE_ARCH */

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
atomic_exchange_begin32(uint32_t *target, uint32_t *previous, enum memory_order ord)
{
	uint32_t        val;

	(void)ord;                      // Memory order not used
	val = os_atomic_load(target, relaxed);
	*previous = val;
	return val;
}

boolean_t
atomic_exchange_complete32(uint32_t *target, uint32_t previous, uint32_t newval, enum memory_order ord)
{
	return __c11_atomic_compare_exchange_strong((_Atomic uint32_t *)target, &previous, newval, ord, memory_order_relaxed);
}

void
atomic_exchange_abort(void)
{
}

boolean_t
atomic_test_and_set32(uint32_t *target, uint32_t test_mask, uint32_t set_mask, enum memory_order ord, boolean_t wait)
{
	uint32_t        value, prev;

	for (;;) {
		value = atomic_exchange_begin32(target, &prev, ord);
		if (value & test_mask) {
			if (wait) {
				cpu_pause();
			} else {
				atomic_exchange_abort();
			}
			return FALSE;
		}
		value |= set_mask;
		if (atomic_exchange_complete32(target, prev, value, ord)) {
			return TRUE;
		}
	}
}

/*
 *	Portable lock package implementation of usimple_locks.
 */

#if     USLOCK_DEBUG
#define USLDBG(stmt)    stmt
void            usld_lock_init(usimple_lock_t, unsigned short);
void            usld_lock_pre(usimple_lock_t, pc_t);
void            usld_lock_post(usimple_lock_t, pc_t);
void            usld_unlock(usimple_lock_t, pc_t);
void            usld_lock_try_pre(usimple_lock_t, pc_t);
void            usld_lock_try_post(usimple_lock_t, pc_t);
int             usld_lock_common_checks(usimple_lock_t, char *);
#else   /* USLOCK_DEBUG */
#define USLDBG(stmt)
#endif  /* USLOCK_DEBUG */

#if LCK_MTX_USE_ARCH
/*
 * Forward definitions
 */

static void lck_mtx_unlock_wakeup_tail(lck_mtx_t *mutex, uint32_t state);
static void lck_mtx_interlock_lock(lck_mtx_t *mutex, uint32_t *new_state);
static void lck_mtx_interlock_lock_clear_flags(lck_mtx_t *mutex, uint32_t and_flags, uint32_t *new_state);
static int lck_mtx_interlock_try_lock_set_flags(lck_mtx_t *mutex, uint32_t or_flags, uint32_t *new_state);
static boolean_t lck_mtx_lock_wait_interlock_to_clear(lck_mtx_t *lock, uint32_t *new_state);
static boolean_t lck_mtx_try_lock_wait_interlock_to_clear(lck_mtx_t *lock, uint32_t *new_state);
#endif /* LCK_MTX_USE_ARCH */


/*
 *      Routine:        lck_spin_alloc_init
 */
lck_spin_t *
lck_spin_alloc_init(
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	lck_spin_t *lck;

	lck = zalloc(KT_LCK_SPIN);
	lck_spin_init(lck, grp, attr);
	return lck;
}

/*
 *      Routine:        lck_spin_free
 */
void
lck_spin_free(
	lck_spin_t      *lck,
	lck_grp_t       *grp)
{
	lck_spin_destroy(lck, grp);
	zfree(KT_LCK_SPIN, lck);
}

/*
 *      Routine:        lck_spin_init
 */
void
lck_spin_init(
	lck_spin_t      *lck,
	lck_grp_t       *grp,
	__unused lck_attr_t     *attr)
{
	usimple_lock_init((usimple_lock_t) lck, 0);
	if (grp) {
		lck_grp_reference(grp, &grp->lck_grp_spincnt);
	}
}

/*
 *      Routine:        lck_spin_destroy
 */
void
lck_spin_destroy(
	lck_spin_t      *lck,
	lck_grp_t       *grp)
{
	if (lck->interlock == LCK_SPIN_TAG_DESTROYED) {
		return;
	}
	lck->interlock = LCK_SPIN_TAG_DESTROYED;
	if (grp) {
		lck_grp_deallocate(grp, &grp->lck_grp_spincnt);
	}
	return;
}

/*
 *      Routine:        lck_spin_lock
 */
void
lck_spin_lock_grp(
	lck_spin_t      *lck,
	lck_grp_t       *grp)
{
#pragma unused(grp)
	usimple_lock((usimple_lock_t) lck, grp);
}

void
lck_spin_lock(
	lck_spin_t      *lck)
{
	usimple_lock((usimple_lock_t) lck, NULL);
}

void
lck_spin_lock_nopreempt(
	lck_spin_t      *lck)
{
	usimple_lock_nopreempt((usimple_lock_t) lck, NULL);
}

void
lck_spin_lock_nopreempt_grp(
	lck_spin_t      *lck,
	lck_grp_t       *grp)
{
#pragma unused(grp)
	usimple_lock_nopreempt((usimple_lock_t) lck, grp);
}

/*
 *      Routine:        lck_spin_unlock
 */
void
lck_spin_unlock(
	lck_spin_t      *lck)
{
	usimple_unlock((usimple_lock_t) lck);
}

void
lck_spin_unlock_nopreempt(
	lck_spin_t      *lck)
{
	usimple_unlock_nopreempt((usimple_lock_t) lck);
}

boolean_t
lck_spin_try_lock_grp(
	lck_spin_t      *lck,
	lck_grp_t       *grp)
{
#pragma unused(grp)
	boolean_t lrval = (boolean_t)usimple_lock_try((usimple_lock_t) lck, grp);
#if     DEVELOPMENT || DEBUG
	if (lrval) {
		pltrace(FALSE);
	}
#endif
	return lrval;
}


/*
 *      Routine:        lck_spin_try_lock
 */
boolean_t
lck_spin_try_lock(
	lck_spin_t      *lck)
{
	boolean_t lrval = (boolean_t)usimple_lock_try((usimple_lock_t) lck, LCK_GRP_NULL);
#if     DEVELOPMENT || DEBUG
	if (lrval) {
		pltrace(FALSE);
	}
#endif
	return lrval;
}

int
lck_spin_try_lock_nopreempt(
	lck_spin_t      *lck)
{
	boolean_t lrval = (boolean_t)usimple_lock_try_nopreempt((usimple_lock_t) lck, LCK_GRP_NULL);
#if     DEVELOPMENT || DEBUG
	if (lrval) {
		pltrace(FALSE);
	}
#endif
	return lrval;
}

int
lck_spin_try_lock_nopreempt_grp(
	lck_spin_t      *lck,
	lck_grp_t       *grp)
{
#pragma unused(grp)
	boolean_t lrval = (boolean_t)usimple_lock_try_nopreempt((usimple_lock_t) lck, grp);
#if     DEVELOPMENT || DEBUG
	if (lrval) {
		pltrace(FALSE);
	}
#endif
	return lrval;
}

/*
 *	Routine:	lck_spin_assert
 */
void
lck_spin_assert(lck_spin_t *lock, unsigned int type)
{
	thread_t thread, holder;
	uintptr_t state;

	if (__improbable(type != LCK_ASSERT_OWNED && type != LCK_ASSERT_NOTOWNED)) {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}

	state = lock->interlock;
	holder = (thread_t)state;
	thread = current_thread();
	if (type == LCK_ASSERT_OWNED) {
		if (__improbable(holder == THREAD_NULL)) {
			panic("Lock not owned %p = %lx", lock, state);
		}
		if (__improbable(holder != thread)) {
			panic("Lock not owned by current thread %p = %lx", lock, state);
		}
	} else if (type == LCK_ASSERT_NOTOWNED) {
		if (__improbable(holder != THREAD_NULL)) {
			if (holder == thread) {
				panic("Lock owned by current thread %p = %lx", lock, state);
			}
		}
	}
}

/*
 *      Routine: kdp_lck_spin_is_acquired
 *      NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *      Returns: TRUE if lock is acquired.
 */
boolean_t
kdp_lck_spin_is_acquired(lck_spin_t *lck)
{
	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	return (lck->interlock != 0)? TRUE : FALSE;
}

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t  l,
	__unused unsigned short tag)
{
	USLDBG(usld_lock_init(l, tag));
	hw_lock_init(&l->interlock);
}

static hw_spin_timeout_status_t
usimple_lock_acquire_timeout_panic(void *_lock, hw_spin_timeout_t to, hw_spin_state_t st)
{
	usimple_lock_t l = _lock;
	uintptr_t lowner;
	lck_spinlock_to_info_t lsti;

	if (machine_timeout_suspended()) {
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	lowner = (uintptr_t)l->interlock.lock_data;
	lsti = lck_spinlock_timeout_hit(l, lowner);

	panic("Spinlock[%p] " HW_SPIN_TIMEOUT_FMT " ;"
	    "lock owner thread=0x%lx, current_thread: %p, "
	    "lock owner active on CPU %d, "
	    HW_SPIN_TIMEOUT_DETAILS_FMT,
	    l, HW_SPIN_TIMEOUT_ARG(to, st),
	    lowner, current_thread(), lsti->owner_cpu,
	    HW_SPIN_TIMEOUT_DETAILS_ARG(to, st));
}

static const struct hw_spin_policy usimple_lock_spin_policy = {
	.hwsp_name              = "usimple_lock_t",
	.hwsp_timeout           = &LockTimeOutTSC,
	.hwsp_op_timeout        = usimple_lock_acquire_timeout_panic,
};

/*
 *	Acquire a usimple_lock.
 *
 *	Returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_lock)(
	usimple_lock_t  l
	LCK_GRP_ARG(lck_grp_t *grp))
{
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_lock_pre(l, pc));

	(void)hw_lock_to(&l->interlock, &usimple_lock_spin_policy, grp);
#if DEVELOPMENT || DEBUG
	pltrace(FALSE);
#endif

	USLDBG(usld_lock_post(l, pc));
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, l, 0, (uintptr_t)LCK_GRP_PROBEARG(grp));
#endif
}

/*
 *	Acquire a usimple_lock_nopreempt
 *
 *	Called and returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
static void
usimple_lock_nopreempt(
	usimple_lock_t  l,
	lck_grp_t *grp)
{
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_lock_pre(l, pc));

	(void)hw_lock_to_nopreempt(&l->interlock, &usimple_lock_spin_policy, grp);

#if DEVELOPMENT || DEBUG
	pltrace(FALSE);
#endif

	USLDBG(usld_lock_post(l, pc));
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, l, 0, (uintptr_t)LCK_GRP_PROBEARG(grp));
#endif
}


/*
 *	Release a usimple_lock.
 *
 *	Returns with preemption enabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
usimple_unlock(
	usimple_lock_t  l)
{
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_unlock(l, pc));
#if DEVELOPMENT || DEBUG
	pltrace(TRUE);
#endif
	hw_lock_unlock(&l->interlock);
}

/*
 *	Release a usimple_unlock_nopreempt.
 *
 *	Called and returns with preemption enabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
usimple_unlock_nopreempt(
	usimple_lock_t  l)
{
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_unlock(l, pc));
#if DEVELOPMENT || DEBUG
	pltrace(TRUE);
#endif
	hw_lock_unlock_nopreempt(&l->interlock);
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
unsigned int
usimple_lock_try(
	usimple_lock_t  l,
	lck_grp_t *grp)
{
	unsigned int    success;
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_lock_try_pre(l, pc));
	if ((success = hw_lock_try(&l->interlock, grp))) {
#if DEVELOPMENT || DEBUG
		pltrace(FALSE);
#endif
		USLDBG(usld_lock_try_post(l, pc));
	}
	return success;
}

/*
 *	Conditionally acquire a usimple_lock.
 *
 *	Called and returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 *
 *	XXX No stats are gathered on a miss; I preserved this
 *	behavior from the original assembly-language code, but
 *	doesn't it make sense to log misses?  XXX
 */
static unsigned int
usimple_lock_try_nopreempt(
	usimple_lock_t  l,
	lck_grp_t *grp)
{
	unsigned int    success;
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_lock_try_pre(l, pc));
	if ((success = hw_lock_try_nopreempt(&l->interlock, grp))) {
#if DEVELOPMENT || DEBUG
		pltrace(FALSE);
#endif
		USLDBG(usld_lock_try_post(l, pc));
	}
	return success;
}

/*
 * Acquire a usimple_lock while polling for pending cpu signals
 * and spinning on a lock.
 *
 */
unsigned
int
(usimple_lock_try_lock_mp_signal_safe_loop_deadline)(usimple_lock_t l,
    uint64_t deadline
    LCK_GRP_ARG(lck_grp_t *grp))
{
	boolean_t istate = ml_get_interrupts_enabled();

	if (deadline < mach_absolute_time()) {
		return 0;
	}

	while (!simple_lock_try(l, grp)) {
		if (!istate) {
			cpu_signal_handler(NULL);
		}

		if (deadline < mach_absolute_time()) {
			return 0;
		}

		cpu_pause();
	}

	return 1;
}

void
(usimple_lock_try_lock_loop)(usimple_lock_t l
    LCK_GRP_ARG(lck_grp_t *grp))
{
	/* When the lock is not contended, grab the lock and go. */
	if (!simple_lock_try(l, grp)) {
		usimple_lock_try_lock_mp_signal_safe_loop_deadline(l, ULLONG_MAX, grp);
	}
}

unsigned
int
(usimple_lock_try_lock_mp_signal_safe_loop_duration)(usimple_lock_t l,
    uint64_t duration
    LCK_GRP_ARG(lck_grp_t *grp))
{
	uint64_t deadline;
	uint64_t base_at;
	uint64_t duration_at;

	/* Fast track for uncontended locks */
	if (simple_lock_try(l, grp)) {
		return 1;
	}

	base_at = mach_absolute_time();

	nanoseconds_to_absolutetime(duration, &duration_at);
	deadline = base_at + duration_at;
	if (deadline < base_at) {
		/* deadline has overflowed, make it saturate */
		deadline = ULLONG_MAX;
	}

	return usimple_lock_try_lock_mp_signal_safe_loop_deadline(l, deadline, grp);
}

#if     USLOCK_DEBUG
/*
 *	States of a usimple_lock.  The default when initializing
 *	a usimple_lock is setting it up for debug checking.
 */
#define USLOCK_CHECKED          0x0001          /* lock is being checked */
#define USLOCK_TAKEN            0x0002          /* lock has been taken */
#define USLOCK_INIT             0xBAA0          /* lock has been initialized */
#define USLOCK_INITIALIZED      (USLOCK_INIT|USLOCK_CHECKED)
#define USLOCK_CHECKING(l)      (uslock_check &&                        \
	                         ((l)->debug.state & USLOCK_CHECKED))

/*
 *	Initialize the debugging information contained
 *	in a usimple_lock.
 */
void
usld_lock_init(
	usimple_lock_t  l,
	__unused unsigned short tag)
{
	if (l == USIMPLE_LOCK_NULL) {
		panic("lock initialization:  null lock pointer");
	}
	l->lock_type = USLOCK_TAG;
	l->debug.state = uslock_check ? USLOCK_INITIALIZED : 0;
	l->debug.lock_cpu = l->debug.unlock_cpu = 0;
	l->debug.lock_pc = l->debug.unlock_pc = INVALID_PC;
	l->debug.lock_thread = l->debug.unlock_thread = INVALID_THREAD;
	l->debug.duration[0] = l->debug.duration[1] = 0;
	l->debug.unlock_cpu = l->debug.unlock_cpu = 0;
	l->debug.unlock_pc = l->debug.unlock_pc = INVALID_PC;
	l->debug.unlock_thread = l->debug.unlock_thread = INVALID_THREAD;
}


/*
 *	These checks apply to all usimple_locks, not just
 *	those with USLOCK_CHECKED turned on.
 */
int
usld_lock_common_checks(
	usimple_lock_t  l,
	char            *caller)
{
	if (l == USIMPLE_LOCK_NULL) {
		panic("%s:  null lock pointer", caller);
	}
	if (l->lock_type != USLOCK_TAG) {
		panic("%s:  %p is not a usimple lock, 0x%x", caller, l, l->lock_type);
	}
	if (!(l->debug.state & USLOCK_INIT)) {
		panic("%s:  %p is not an initialized lock, 0x%x", caller, l, l->debug.state);
	}
	return USLOCK_CHECKING(l);
}


/*
 *	Debug checks on a usimple_lock just before attempting
 *	to acquire it.
 */
/* ARGSUSED */
void
usld_lock_pre(
	usimple_lock_t  l,
	pc_t            pc)
{
	char    caller[] = "usimple_lock";


	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

/*
 *	Note that we have a weird case where we are getting a lock when we are]
 *	in the process of putting the system to sleep. We are running with no
 *	current threads, therefore we can't tell if we are trying to retake a lock
 *	we have or someone on the other processor has it.  Therefore we just
 *	ignore this test if the locking thread is 0.
 */

	if ((l->debug.state & USLOCK_TAKEN) && l->debug.lock_thread &&
	    l->debug.lock_thread == (void *) current_thread()) {
		printf("%s:  lock %p already locked (at %p) by",
		    caller, l, l->debug.lock_pc);
		printf(" current thread %p (new attempt at pc %p)\n",
		    l->debug.lock_thread, pc);
		panic("%s", caller);
	}
	mp_disable_preemption();
	mp_enable_preemption();
}


/*
 *	Debug checks on a usimple_lock just after acquiring it.
 *
 *	Pre-emption has been disabled at this point,
 *	so we are safe in using cpu_number.
 */
void
usld_lock_post(
	usimple_lock_t  l,
	pc_t            pc)
{
	unsigned int mycpu;
	char    caller[] = "successful usimple_lock";


	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED)) {
		panic("%s:  lock %p became uninitialized",
		    caller, l);
	}
	if ((l->debug.state & USLOCK_TAKEN)) {
		panic("%s:  lock 0x%p became TAKEN by someone else",
		    caller, l);
	}

	mycpu = (unsigned int)cpu_number();
	assert(mycpu <= UCHAR_MAX);

	l->debug.lock_thread = (void *)current_thread();
	l->debug.state |= USLOCK_TAKEN;
	l->debug.lock_pc = pc;
	l->debug.lock_cpu = (unsigned char)mycpu;
}


/*
 *	Debug checks on a usimple_lock just before
 *	releasing it.  Note that the caller has not
 *	yet released the hardware lock.
 *
 *	Preemption is still disabled, so there's
 *	no problem using cpu_number.
 */
void
usld_unlock(
	usimple_lock_t  l,
	pc_t            pc)
{
	unsigned int mycpu;
	char    caller[] = "usimple_unlock";


	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

	mycpu = cpu_number();
	assert(mycpu <= UCHAR_MAX);

	if (!(l->debug.state & USLOCK_TAKEN)) {
		panic("%s:  lock 0x%p hasn't been taken",
		    caller, l);
	}
	if (l->debug.lock_thread != (void *) current_thread()) {
		panic("%s:  unlocking lock 0x%p, owned by thread %p",
		    caller, l, l->debug.lock_thread);
	}
	if (l->debug.lock_cpu != mycpu) {
		printf("%s:  unlocking lock 0x%p on cpu 0x%x",
		    caller, l, mycpu);
		printf(" (acquired on cpu 0x%x)\n", l->debug.lock_cpu);
		panic("%s", caller);
	}

	l->debug.unlock_thread = l->debug.lock_thread;
	l->debug.lock_thread = INVALID_PC;
	l->debug.state &= ~USLOCK_TAKEN;
	l->debug.unlock_pc = pc;
	l->debug.unlock_cpu = (unsigned char)mycpu;
}


/*
 *	Debug checks on a usimple_lock just before
 *	attempting to acquire it.
 *
 *	Preemption isn't guaranteed to be disabled.
 */
void
usld_lock_try_pre(
	usimple_lock_t  l,
	__unused pc_t   pc)
{
	char    caller[] = "usimple_lock_try";

	if (!usld_lock_common_checks(l, caller)) {
		return;
	}
}


/*
 *	Debug checks on a usimple_lock just after
 *	successfully attempting to acquire it.
 *
 *	Preemption has been disabled by the
 *	lock acquisition attempt, so it's safe
 *	to use cpu_number.
 */
void
usld_lock_try_post(
	usimple_lock_t  l,
	pc_t            pc)
{
	unsigned int mycpu;
	char    caller[] = "successful usimple_lock_try";

	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED)) {
		panic("%s:  lock 0x%p became uninitialized",
		    caller, l);
	}
	if ((l->debug.state & USLOCK_TAKEN)) {
		panic("%s:  lock 0x%p became TAKEN by someone else",
		    caller, l);
	}

	mycpu = cpu_number();
	assert(mycpu <= UCHAR_MAX);

	l->debug.lock_thread = (void *) current_thread();
	l->debug.state |= USLOCK_TAKEN;
	l->debug.lock_pc = pc;
	l->debug.lock_cpu = (unsigned char)mycpu;
}
#endif  /* USLOCK_DEBUG */
#if LCK_MTX_USE_ARCH

/*
 * Slow path routines for lck_mtx locking and unlocking functions.
 *
 * These functions were previously implemented in x86 assembly,
 * and some optimizations are in place in this c code to obtain a compiled code
 * as performant and compact as the assembly version.
 *
 * To avoid to inline these functions on the fast path, all functions directly called by
 * the fast paths have the __attribute__((noinline)) specified. Also they are all implemented
 * in such a way the fast path can tail call into them. In this way the return address
 * does not need to be pushed on the caller stack and stack optimization can happen on the caller.
 *
 * Slow path code is structured in such a way there are no calls to functions that will return
 * on the context of the caller function, i.e. all functions called are or tail call functions
 * or inline functions. The number of arguments of the tail call functions are less then six,
 * so that they can be passed over registers and do not need to be pushed on stack.
 * This allows the compiler to not create a stack frame for the functions.
 *
 * __improbable and __probable are used to compile the slow path code in such a way
 * the fast path case will be on a sequence of instructions with as less jumps as possible,
 * to make this case the most optimized even if falling through the slow path.
 */

/*
 * Intel lock invariants:
 *
 * lck_mtx_waiters: contains the count of threads currently in the mutex waitqueue
 *
 * The lock owner is promoted to the max priority of all its waiters only if it
 * was a lower priority when it acquired or was an owner when a waiter waited.
 * Max priority is capped at MAXPRI_PROMOTE.
 *
 * The last waiter will not be promoted as it is woken up, but the last
 * lock owner may not have been the last thread to have been woken up depending on the
 * luck of the draw.  Therefore a last-owner may still have the promoted-on-wakeup
 * flag set.
 *
 * TODO: Figure out an algorithm for stopping a lock holder which is already at the right
 *       priority from dropping priority in the future without having to take thread lock
 *       on acquire.
 */

/*
 *      Routine:        lck_mtx_alloc_init
 */
lck_mtx_t *
lck_mtx_alloc_init(
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	lck_mtx_t *lck;

	lck = zalloc(KT_LCK_MTX);
	lck_mtx_init(lck, grp, attr);
	return lck;
}

/*
 *      Routine:        lck_mtx_free
 */
void
lck_mtx_free(
	lck_mtx_t       *lck,
	lck_grp_t       *grp)
{
	lck_mtx_destroy(lck, grp);
	zfree(KT_LCK_MTX, lck);
}

/*
 *      Routine:        lck_mtx_init
 */
void
lck_mtx_init(
	lck_mtx_t       *lck,
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	if (attr == LCK_ATTR_NULL) {
		attr = &lck_attr_default;
	}

	*lck = (lck_mtx_t){
		.lck_mtx_grp = grp->lck_grp_attr_id,
	};

	if (__improbable((attr->lck_attr_val & LCK_ATTR_DEBUG) ||
	    (grp->lck_grp_attr_id & LCK_GRP_ATTR_DEBUG))) {
		lck->lck_mtx_profile = 1;
	}

	lck_grp_reference(grp, &grp->lck_grp_mtxcnt);
}

/*
 *      Routine:        lck_mtx_destroy
 */
void
lck_mtx_destroy(
	lck_mtx_t       *lck,
	lck_grp_t       *grp)
{
	if (lck->lck_mtx_state == LCK_MTX_TAG_DESTROYED) {
		return;
	}
#if MACH_LDEBUG
	lck_mtx_assert(lck, LCK_MTX_ASSERT_NOTOWNED);
#endif
	ordered_store_mtx_state_release(lck, LCK_MTX_TAG_DESTROYED);
	lck_grp_deallocate(grp, &grp->lck_grp_mtxcnt);
}


#if DEVELOPMENT | DEBUG
__attribute__((noinline))
void
lck_mtx_owner_check_panic(
	lck_mtx_t       *lock)
{
	thread_t owner = ctid_get_thread_unsafe(lock->lck_mtx_owner);
	panic("Mutex unlock attempted from non-owner thread. Owner=%p lock=%p", owner, lock);
}
#endif

/*
 * Routine:     lck_mtx_unlock_slow
 *
 * Unlocks a mutex held by current thread.
 *
 * It will wake up waiters if necessary.
 *
 * Interlock can be held.
 */
__attribute__((noinline))
void
lck_mtx_unlock_slow(
	lck_mtx_t       *lock)
{
	thread_t        thread;
	uint32_t        state;

	state = ordered_load_mtx_state(lock);

	thread = current_thread();

#if DEVELOPMENT | DEBUG
	if (__improbable(lock->lck_mtx_owner != thread->ctid)) {
		lck_mtx_owner_check_panic(lock);
	}
#endif

	/* check if it is held as a spinlock */
	if (__improbable((state & LCK_MTX_MLOCKED_MSK) == 0)) {
		goto unlock;
	}

	lck_mtx_interlock_lock_clear_flags(lock, LCK_MTX_MLOCKED_MSK, &state);

unlock:
	/* preemption disabled, interlock held and mutex not held */

	/* clear owner */
	ordered_store_mtx_owner(lock, 0);

	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
#if     MACH_LDEBUG
		if (thread) {
			thread->mutex_count--;
		}
#endif
		return lck_mtx_unlock_wakeup_tail(lock, state);
	}

	/* release interlock, promotion and clear spin flag */
	state &= (~(LCK_MTX_ILOCKED_MSK | LCK_MTX_SPIN_MSK));
	ordered_store_mtx_state_release(lock, state);           /* since I own the interlock, I don't need an atomic update */

#if     MACH_LDEBUG
	/* perform lock statistics after drop to prevent delay */
	if (thread) {
		thread->mutex_count--;          /* lock statistic */
	}
#endif  /* MACH_LDEBUG */

	/* re-enable preemption */
	lck_mtx_unlock_finish_inline(lock, state);
}

#define LCK_MTX_LCK_WAIT_CODE           0x20
#define LCK_MTX_LCK_WAKEUP_CODE         0x21
#define LCK_MTX_LCK_SPIN_CODE           0x22
#define LCK_MTX_LCK_ACQUIRE_CODE        0x23
#define LCK_MTX_LCK_DEMOTE_CODE         0x24

/*
 * Routine:    lck_mtx_unlock_wakeup_tail
 *
 * Invoked on unlock when there is
 * contention, i.e. the assembly routine sees
 * that mutex->lck_mtx_waiters != 0
 *
 * neither the mutex or interlock is held
 *
 * Note that this routine might not be called if there are pending
 * waiters which have previously been woken up, and they didn't
 * end up boosting the old owner.
 *
 * assembly routine previously did the following to mutex:
 * (after saving the state in prior_lock_state)
 *      decremented lck_mtx_waiters if nonzero
 *
 * This function needs to be called as a tail call
 * to optimize the compiled code.
 */
__attribute__((noinline))
static void
lck_mtx_unlock_wakeup_tail(
	lck_mtx_t       *mutex,
	uint32_t        state)
{
	struct turnstile *ts;

	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(mutex);
	kern_return_t did_wake;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAKEUP_CODE) | DBG_FUNC_START,
	    trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);

	ts = turnstile_prepare_hash((uintptr_t)mutex, TURNSTILE_KERNEL_MUTEX);

	did_wake = waitq_wakeup64_one(&ts->ts_waitq, LCK_MTX_EVENT(mutex),
	    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);
	assert(did_wake == KERN_SUCCESS);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete_hash((uintptr_t)mutex, TURNSTILE_KERNEL_MUTEX);

	state -= LCK_MTX_WAITER;
	state &= (~(LCK_MTX_SPIN_MSK | LCK_MTX_ILOCKED_MSK));
	ordered_store_mtx_state_release(mutex, state);

	assert(current_thread()->turnstile != NULL);

	turnstile_cleanup();

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAKEUP_CODE) | DBG_FUNC_END,
	    trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);

	lck_mtx_unlock_finish_inline(mutex, state);
}

/*
 * Routine:     lck_mtx_lock_acquire_x86
 *
 * Invoked on acquiring the mutex when there is
 * contention (i.e. the assembly routine sees that
 * that mutex->lck_mtx_waiters != 0
 *
 * mutex is owned...  interlock is held... preemption is disabled
 */
__attribute__((always_inline))
static void
lck_mtx_lock_acquire_inline(
	lck_mtx_t       *mutex,
	struct turnstile *ts)
{
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(mutex);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_ACQUIRE_CODE) | DBG_FUNC_START,
	    trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);

	if (mutex->lck_mtx_waiters > 0) {
		if (ts == NULL) {
			ts = turnstile_prepare_hash((uintptr_t)mutex, TURNSTILE_KERNEL_MUTEX);
		}

		turnstile_update_inheritor(ts, current_thread(),
		    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD);
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	}

	if (ts != NULL) {
		turnstile_complete_hash((uintptr_t)mutex, TURNSTILE_KERNEL_MUTEX);
	}

	assert(current_thread()->turnstile != NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_ACQUIRE_CODE) | DBG_FUNC_END,
	    trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);
}

void
lck_mtx_lock_acquire_x86(
	lck_mtx_t       *mutex)
{
	return lck_mtx_lock_acquire_inline(mutex, NULL);
}

/*
 * Tail call helpers for lock functions that perform
 * lck_mtx_lock_acquire followed by the caller's finish routine, to optimize
 * the caller's compiled code.
 */

__attribute__((noinline))
static void
lck_mtx_lock_acquire_tail(
	lck_mtx_t       *mutex,
	struct turnstile *ts)
{
	lck_mtx_lock_acquire_inline(mutex, ts);
	lck_mtx_lock_finish_inline_with_cleanup(mutex, ordered_load_mtx_state(mutex));
}

__attribute__((noinline))
static boolean_t
lck_mtx_try_lock_acquire_tail(
	lck_mtx_t       *mutex)
{
	lck_mtx_lock_acquire_inline(mutex, NULL);
	lck_mtx_try_lock_finish_inline(mutex, ordered_load_mtx_state(mutex));

	return TRUE;
}

__attribute__((noinline))
static void
lck_mtx_convert_spin_acquire_tail(
	lck_mtx_t       *mutex)
{
	lck_mtx_lock_acquire_inline(mutex, NULL);
	lck_mtx_convert_spin_finish_inline(mutex, ordered_load_mtx_state(mutex));
}

static void
lck_mtx_ilk_unlock(
	lck_mtx_t       *mutex)
{
	lck_mtx_ilk_unlock_inline(mutex, ordered_load_mtx_state(mutex));
}

static inline void
lck_mtx_interlock_lock_set_and_clear_flags(
	lck_mtx_t *mutex,
	uint32_t xor_flags,
	uint32_t and_flags,
	uint32_t *new_state)
{
	uint32_t state, prev;
	state = *new_state;

	for (;;) {
		/* have to wait for interlock to clear */
		while (__improbable(state & (LCK_MTX_ILOCKED_MSK | xor_flags))) {
			cpu_pause();
			state = ordered_load_mtx_state(mutex);
		}
		prev = state;                                   /* prev contains snapshot for exchange */
		state |= LCK_MTX_ILOCKED_MSK | xor_flags;       /* pick up interlock */
		state &= ~and_flags;                            /* clear flags */

		disable_preemption();
		if (os_atomic_cmpxchg(&mutex->lck_mtx_state, prev, state, acquire)) {
			break;
		}
		enable_preemption();
		cpu_pause();
		state = ordered_load_mtx_state(mutex);
	}
	*new_state = state;
	return;
}

static inline void
lck_mtx_interlock_lock_clear_flags(
	lck_mtx_t *mutex,
	uint32_t and_flags,
	uint32_t *new_state)
{
	return lck_mtx_interlock_lock_set_and_clear_flags(mutex, 0, and_flags, new_state);
}

static inline void
lck_mtx_interlock_lock(
	lck_mtx_t *mutex,
	uint32_t *new_state)
{
	return lck_mtx_interlock_lock_set_and_clear_flags(mutex, 0, 0, new_state);
}

static inline int
lck_mtx_interlock_try_lock_set_flags(
	lck_mtx_t *mutex,
	uint32_t or_flags,
	uint32_t *new_state)
{
	uint32_t state, prev;
	state = *new_state;

	/* have to wait for interlock to clear */
	if (state & (LCK_MTX_ILOCKED_MSK | or_flags)) {
		return 0;
	}
	prev = state;                                   /* prev contains snapshot for exchange */
	state |= LCK_MTX_ILOCKED_MSK | or_flags;        /* pick up interlock */
	disable_preemption();
	if (os_atomic_cmpxchg(&mutex->lck_mtx_state, prev, state, acquire)) {
		*new_state = state;
		return 1;
	}

	enable_preemption();
	return 0;
}

__attribute__((noinline))
static void
lck_mtx_lock_contended(
	lck_mtx_t *lock,
	bool       profile,
	boolean_t *first_miss)
{
	lck_mtx_spinwait_ret_type_t ret;
	uint32_t state;
	thread_t thread;
	struct turnstile *ts = NULL;

try_again:

	if (profile) {
		LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, first_miss);
	}

	ret = lck_mtx_lock_spinwait_x86(lock);
	state = ordered_load_mtx_state(lock);
	switch (ret) {
	case LCK_MTX_SPINWAIT_NO_SPIN:
		/*
		 * owner not on core, lck_mtx_lock_spinwait_x86 didn't even
		 * try to spin.
		 */
		/* just fall through case LCK_MTX_SPINWAIT_SPUN */
		OS_FALLTHROUGH;
	case LCK_MTX_SPINWAIT_SPUN_HIGH_THR:
	case LCK_MTX_SPINWAIT_SPUN_OWNER_NOT_CORE:
	case LCK_MTX_SPINWAIT_SPUN_NO_WINDOW_CONTENTION:
	case LCK_MTX_SPINWAIT_SPUN_SLIDING_THR:
		/*
		 * mutex not acquired but lck_mtx_lock_spinwait_x86 tried to spin
		 * interlock not held
		 */
		lck_mtx_interlock_lock(lock, &state);
		assert(state & LCK_MTX_ILOCKED_MSK);

		if (state & LCK_MTX_MLOCKED_MSK) {
			if (profile) {
				LCK_MTX_PROF_WAIT(lock, lock->lck_mtx_grp,
				    ret == LCK_MTX_SPINWAIT_NO_SPIN, first_miss);
			}
			lck_mtx_lock_wait_x86(lock, &ts);
			/*
			 * interlock is not held here.
			 */
			goto try_again;
		} else {
			/* grab the mutex */
			state |= LCK_MTX_MLOCKED_MSK;
			ordered_store_mtx_state_release(lock, state);
			thread = current_thread();
			ordered_store_mtx_owner(lock, thread->ctid);
#if     MACH_LDEBUG
			if (thread) {
				thread->mutex_count++;
			}
#endif  /* MACH_LDEBUG */
		}

		break;
	case LCK_MTX_SPINWAIT_ACQUIRED:
		/*
		 * mutex has been acquired by lck_mtx_lock_spinwait_x86
		 * interlock is held and preemption disabled
		 * owner is set and mutex marked as locked
		 * statistics updated too
		 */
		break;
	default:
		panic("lck_mtx_lock_spinwait_x86 returned %d for mutex %p", ret, lock);
	}

	/*
	 * interlock is already acquired here
	 */

	/* mutex has been acquired */
	if (state & LCK_MTX_WAITERS_MSK) {
		/*
		 * lck_mtx_lock_acquire_tail will call
		 * turnstile_complete.
		 */
		return lck_mtx_lock_acquire_tail(lock, ts);
	}

	if (ts != NULL) {
		turnstile_complete_hash((uintptr_t)lock, TURNSTILE_KERNEL_MUTEX);
	}

	assert(current_thread()->turnstile != NULL);

	/* release the interlock */
	lck_mtx_lock_finish_inline_with_cleanup(lock, ordered_load_mtx_state(lock));
}

/*
 * Helper noinline functions for calling
 * panic to optimize compiled code.
 */

__attribute__((noinline)) __abortlike
static void
lck_mtx_destroyed(
	lck_mtx_t       *lock)
{
	panic("trying to interlock destroyed mutex (%p)", lock);
}

__attribute__((noinline))
static boolean_t
lck_mtx_try_destroyed(
	lck_mtx_t       *lock)
{
	panic("trying to interlock destroyed mutex (%p)", lock);
	return FALSE;
}

__attribute__((always_inline))
static boolean_t
lck_mtx_lock_wait_interlock_to_clear(
	lck_mtx_t       *lock,
	uint32_t*        new_state)
{
	uint32_t state;

	for (;;) {
		cpu_pause();
		state = ordered_load_mtx_state(lock);
		if (!(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
			*new_state = state;
			return TRUE;
		}
		if (state & LCK_MTX_MLOCKED_MSK) {
			/* if it is held as mutex, just fail */
			return FALSE;
		}
	}
}

__attribute__((always_inline))
static boolean_t
lck_mtx_try_lock_wait_interlock_to_clear(
	lck_mtx_t       *lock,
	uint32_t*        new_state)
{
	uint32_t state;

	for (;;) {
		cpu_pause();
		state = ordered_load_mtx_state(lock);
		if (state & (LCK_MTX_MLOCKED_MSK | LCK_MTX_SPIN_MSK)) {
			/* if it is held as mutex or spin, just fail */
			return FALSE;
		}
		if (!(state & LCK_MTX_ILOCKED_MSK)) {
			*new_state = state;
			return TRUE;
		}
	}
}

/*
 * Routine:	lck_mtx_lock_slow
 *
 * Locks a mutex for current thread.
 * If the lock is contended this function might
 * sleep.
 *
 * Called with interlock not held.
 */
__attribute__((noinline))
void
lck_mtx_lock_slow(
	lck_mtx_t       *lock)
{
	bool            profile;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);
	profile = (state & LCK_MTX_PROFILE_MSK);

	if (__improbable(profile)) {
		if (state & LCK_MTX_SPIN_MSK) {
			/* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
			assert(state & LCK_MTX_ILOCKED_MSK);
			LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &first_miss);
		}
	}

	/* is the interlock or mutex held */
	if (__improbable(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
		/*
		 * Note: LCK_MTX_TAG_DESTROYED has
		 *       LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK set.
		 */

		/* is the mutex already held */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))) {
			/* no, must have been the mutex */
			return lck_mtx_lock_contended(lock, profile, &first_miss);
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_destroyed(lock);
		}
	}

	/* no - can't be DESTROYED or locked */
	while (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_MLOCKED_MSK, &state))) {
		if (!lck_mtx_lock_wait_interlock_to_clear(lock, &state)) {
			return lck_mtx_lock_contended(lock, profile, &first_miss);
		}
	}

	/* lock and interlock acquired */

	/* record owner of mutex */
	ordered_store_mtx_owner(lock, current_thread()->ctid);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif
	/*
	 * Check if there are waiters to
	 * inherit their priority.
	 */
	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
		return lck_mtx_lock_acquire_tail(lock, NULL);
	}

	/* release the interlock */
	lck_mtx_lock_finish_inline(lock, ordered_load_mtx_state(lock));
}

__attribute__((noinline))
boolean_t
lck_mtx_try_lock_slow(
	lck_mtx_t       *lock)
{
	bool            profile;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);
	profile = (state & LCK_MTX_PROFILE_MSK);

	/* is the interlock or mutex held */
	if (__improbable(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
		/*
		 * Note: LCK_MTX_TAG_DESTROYED has
		 *       LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK set.
		 */

		/* is the mutex already held */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))) {
			return FALSE;
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_try_destroyed(lock);
		}

		if (!lck_mtx_try_lock_wait_interlock_to_clear(lock, &state)) {
			if (__improbable(profile)) {
				LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &first_miss);
			}
			return FALSE;
		}
	}

	if (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_MLOCKED_MSK, &state))) {
		if (__improbable(profile)) {
			LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &first_miss);
		}
		return FALSE;
	}

	/* lock and interlock acquired */

	/* record owner of mutex */
	ordered_store_mtx_owner(lock, current_thread()->ctid);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif
	/*
	 * Check if there are waiters to
	 * inherit their priority.
	 */
	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
		return lck_mtx_try_lock_acquire_tail(lock);
	}

	/* release the interlock */
	lck_mtx_try_lock_finish_inline(lock, ordered_load_mtx_state(lock));

	return TRUE;
}

__attribute__((noinline))
void
lck_mtx_lock_spin_slow(
	lck_mtx_t       *lock)
{
	bool            profile;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);
	profile = (state & LCK_MTX_PROFILE_MSK);

	if (__improbable(profile)) {
		if (state & LCK_MTX_SPIN_MSK) {
			/* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
			assert(state & LCK_MTX_ILOCKED_MSK);
			LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &first_miss);
		}
	}

	/* is interlock or mutex held */
	if (__improbable(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
		/*
		 * Note: LCK_MTX_TAG_DESTROYED has
		 *       LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK set.
		 */

		/* is the mutex already held */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))) {
			/* no, must have been the mutex */
			return lck_mtx_lock_contended(lock, profile, &first_miss);
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_destroyed(lock);
		}
	}

	bool acquired = true;

#if CONFIG_DTRACE
	uint64_t spin_start;

	if (__probable(lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_SPIN_MSK, &state))) {
		goto past_spin;
	}

	spin_start = LCK_MTX_SPIN_SPIN_BEGIN();
#endif /* CONFIG_DTRACE */

	/* note - can't be DESTROYED or locked */
	/* note - preemption is not disabled while spinning */
	while (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_SPIN_MSK, &state))) {
		if (!lck_mtx_lock_wait_interlock_to_clear(lock, &state)) {
			acquired = false;
			break;
		}
	}

	LCK_MTX_SPIN_SPIN_END(lock, lock->lck_mtx_grp, spin_start);
#if CONFIG_DTRACE
past_spin:
#endif /* CONFIG_DTRACE */

	if (__improbable(!acquired)) {
		return lck_mtx_lock_contended(lock, profile, &first_miss);
	}

	/* lock as spinlock and interlock acquired */

	/* record owner of mutex */
	ordered_store_mtx_owner(lock, current_thread()->ctid);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif
	LCK_MTX_ACQUIRED(lock, lock->lck_mtx_grp, true, profile);

	/* return with the interlock held and preemption disabled */
	return;
}

__attribute__((noinline))
boolean_t
lck_mtx_try_lock_spin_slow(
	lck_mtx_t       *lock)
{
	bool            profile;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);
	profile = (state & LCK_MTX_PROFILE_MSK);

	/* is the interlock or mutex held */
	if (__improbable(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
		/*
		 * Note: LCK_MTX_TAG_DESTROYED has
		 *       LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK set.
		 */

		/* is the mutex already held */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))) {
			return FALSE;
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_try_destroyed(lock);
		}
	}

	/* note - can't be DESTROYED or locked */
	if (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_SPIN_MSK, &state))) {
		if (__improbable(profile)) {
			LCK_MTX_PROF_MISS(lock, lock->lck_mtx_grp, &first_miss);
		}
		return FALSE;
	}

	/* lock and interlock acquired */

	/* record owner of mutex */
	ordered_store_mtx_owner(lock, current_thread()->ctid);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_SPIN_ACQUIRE, lock, 0);
#endif
	return TRUE;
}

__attribute__((noinline))
void
lck_mtx_convert_spin(
	lck_mtx_t       *lock)
{
	uint32_t state;

	state = ordered_load_mtx_state(lock);

	assertf(lock->lck_mtx_owner == current_thread()->ctid,
	    "lock %p not owned by thread ctid %d (current owner %d)",
	    lock, current_thread()->ctid, lock->lck_mtx_owner);

	if (__improbable(state & LCK_MTX_MLOCKED_MSK)) {
		/* already owned as a mutex, just return */
		return;
	}

	assert(get_preemption_level() > 0);
	assert(state & LCK_MTX_ILOCKED_MSK);
	assert(state & LCK_MTX_SPIN_MSK);

	/*
	 * Check if there are waiters to
	 * inherit their priority.
	 */
	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
		return lck_mtx_convert_spin_acquire_tail(lock);
	}

	lck_mtx_convert_spin_finish_inline(lock, ordered_load_mtx_state(lock));

	return;
}

static inline boolean_t
lck_mtx_lock_grab_mutex(
	lck_mtx_t       *lock)
{
	uint32_t state;

	state = ordered_load_mtx_state(lock);

	if (!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_MLOCKED_MSK, &state)) {
		return FALSE;
	}

	/* lock and interlock acquired */

	/* record owner of mutex */
	ordered_store_mtx_owner(lock, current_thread()->ctid);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif
	return TRUE;
}

__attribute__((noinline))
void
lck_mtx_assert(
	lck_mtx_t       *lock,
	unsigned int    type)
{
	thread_t thread;
	uint32_t state;

	thread = current_thread();
	state = ordered_load_mtx_state(lock);

	if (type == LCK_MTX_ASSERT_OWNED) {
		if ((lock->lck_mtx_owner != thread->ctid) ||
		    !(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
			panic("mutex (%p) not owned", lock);
		}
	} else {
		assert(type == LCK_MTX_ASSERT_NOTOWNED);
		if (lock->lck_mtx_owner == thread->ctid) {
			panic("mutex (%p) owned", lock);
		}
	}
}

/*
 * Routine:     lck_mtx_lock_spinwait_x86
 *
 * Invoked trying to acquire a mutex when there is contention but
 * the holder is running on another processor. We spin for up to a maximum
 * time waiting for the lock to be released.
 *
 * Called with the interlock unlocked.
 * returns LCK_MTX_SPINWAIT_ACQUIRED if mutex acquired
 * returns LCK_MTX_SPINWAIT_SPUN if we spun
 * returns LCK_MTX_SPINWAIT_NO_SPIN if we didn't spin due to the holder not running
 */
__attribute__((noinline))
lck_mtx_spinwait_ret_type_t
lck_mtx_lock_spinwait_x86(
	lck_mtx_t       *mutex)
{
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(mutex);
	ctid_t          owner, prev_owner;
	uint64_t        window_deadline, sliding_deadline, high_deadline;
	uint64_t        spin_start, start_time, cur_time, avg_hold_time, bias, delta;
	lck_mtx_spinwait_ret_type_t             retval = LCK_MTX_SPINWAIT_SPUN_HIGH_THR;
	int             loopcount = 0;
	int             total_hold_time_samples, window_hold_time_samples, unfairness;
	uint            prev_owner_cpu;
	bool            adjust;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_START,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(ctid_get_thread_unsafe(mutex->lck_mtx_owner)),
	    mutex->lck_mtx_waiters, 0, 0);

	spin_start = LCK_MTX_ADAPTIVE_SPIN_BEGIN();
	start_time = mach_absolute_time();

	/*
	 * window_deadline represents the "learning" phase.
	 * The thread collects statistics about the lock during
	 * window_deadline and then it makes a decision on whether to spin more
	 * or block according to the concurrency behavior
	 * observed.
	 *
	 * Every thread can spin at least low_MutexSpin.
	 */
	window_deadline = start_time + low_MutexSpin;
	/*
	 * Sliding_deadline is the adjusted spin deadline
	 * computed after the "learning" phase.
	 */
	sliding_deadline = window_deadline;
	/*
	 * High_deadline is a hard deadline. No thread
	 * can spin more than this deadline.
	 */
	if (high_MutexSpin >= 0) {
		high_deadline = start_time + high_MutexSpin;
	} else {
		high_deadline = start_time + low_MutexSpin * real_ncpus;
	}

	/*
	 * Do not know yet which is the owner cpu.
	 * Initialize prev_owner_cpu with next cpu.
	 */
	prev_owner_cpu = (cpu_number() + 1) % real_ncpus;
	total_hold_time_samples = 0;
	window_hold_time_samples = 0;
	avg_hold_time = 0;
	adjust = TRUE;
	bias = (os_hash_kernel_pointer(mutex) + cpu_number()) % real_ncpus;

	prev_owner = mutex->lck_mtx_owner;

	/*
	 * Spin while:
	 *   - mutex is locked, and
	 *   - it's locked as a spin lock, and
	 *   - owner is running on another processor, and
	 *   - we haven't spun for long enough.
	 */
	do {
		/*
		 * Try to acquire the lock.
		 */
		if (__probable(lck_mtx_lock_grab_mutex(mutex))) {
			retval = LCK_MTX_SPINWAIT_ACQUIRED;
			break;
		}

		cur_time = mach_absolute_time();

		/*
		 * Never spin past high_deadline.
		 */
		if (cur_time >= high_deadline) {
			retval = LCK_MTX_SPINWAIT_SPUN_HIGH_THR;
			break;
		}

		/*
		 * Check if owner is on core. If not block.
		 */
		owner = mutex->lck_mtx_owner;
		if (owner) {
			uint32_t i = prev_owner_cpu;
			bool     owner_on_core = false;

			disable_preemption();
			owner = mutex->lck_mtx_owner;

			/*
			 * For scalability we want to check if the owner is on core
			 * without locking the mutex interlock.
			 * If we do not lock the mutex interlock, the owner that we see might be
			 * invalid, so we cannot dereference it. Therefore we cannot check
			 * any field of the thread to tell us if it is on core.
			 * Check if the thread that is running on the other cpus matches the owner.
			 */
			if (owner) {
				thread_t owner_thread = ctid_get_thread_unsafe(owner);

				do {
					if ((cpu_data_ptr[i] != NULL) && (cpu_data_ptr[i]->cpu_active_thread == owner_thread)) {
						owner_on_core = true;
						break;
					}
					if (++i >= real_ncpus) {
						i = 0;
					}
				} while (i != prev_owner_cpu);
			}

			enable_preemption();

			if (owner == 0) {
				/* nothing to do, we didn't find an owner */
			} else if (owner_on_core) {
				prev_owner_cpu = i;
			} else {
				prev_owner = owner;
				owner = mutex->lck_mtx_owner;
				if (owner == prev_owner) {
					/*
					 * Owner is not on core.
					 * Stop spinning.
					 */
					if (loopcount == 0) {
						retval = LCK_MTX_SPINWAIT_NO_SPIN;
					} else {
						retval = LCK_MTX_SPINWAIT_SPUN_OWNER_NOT_CORE;
					}
					break;
				}
				/*
				 * Fall through if the owner changed while we were scanning.
				 * The new owner could potentially be on core, so loop
				 * again.
				 */
			}
		}

		/*
		 * Save how many times we see the owner changing.
		 * We can roughly estimate the mutex hold
		 * time and the fairness with that.
		 */
		if (owner != prev_owner) {
			prev_owner = owner;
			total_hold_time_samples++;
			window_hold_time_samples++;
		}

		/*
		 * Learning window expired.
		 * Try to adjust the sliding_deadline.
		 */
		if (cur_time >= window_deadline) {
			/*
			 * If there was not contention during the window
			 * stop spinning.
			 */
			if (window_hold_time_samples < 1) {
				retval = LCK_MTX_SPINWAIT_SPUN_NO_WINDOW_CONTENTION;
				break;
			}

			if (adjust) {
				/*
				 * For a fair lock, we'd wait for at most (NCPU-1) periods,
				 * but the lock is unfair, so let's try to estimate by how much.
				 */
				unfairness = total_hold_time_samples / real_ncpus;

				if (unfairness == 0) {
					/*
					 * We observed the owner changing `total_hold_time_samples` times which
					 * let us estimate the average hold time of this mutex for the duration
					 * of the spin time.
					 * avg_hold_time = (cur_time - start_time) / total_hold_time_samples;
					 *
					 * In this case spin at max avg_hold_time * (real_ncpus - 1)
					 */
					delta = cur_time - start_time;
					sliding_deadline = start_time + (delta * (real_ncpus - 1)) / total_hold_time_samples;
				} else {
					/*
					 * In this case at least one of the other cpus was able to get the lock twice
					 * while I was spinning.
					 * We could spin longer but it won't necessarily help if the system is unfair.
					 * Try to randomize the wait to reduce contention.
					 *
					 * We compute how much time we could potentially spin
					 * and distribute it over the cpus.
					 *
					 * bias is an integer between 0 and real_ncpus.
					 * distributed_increment = ((high_deadline - cur_time) / real_ncpus) * bias
					 */
					delta = high_deadline - cur_time;
					sliding_deadline = cur_time + ((delta * bias) / real_ncpus);
					adjust = FALSE;
				}
			}

			window_deadline += low_MutexSpin;
			window_hold_time_samples = 0;
		}

		/*
		 * Stop spinning if we past
		 * the adjusted deadline.
		 */
		if (cur_time >= sliding_deadline) {
			retval = LCK_MTX_SPINWAIT_SPUN_SLIDING_THR;
			break;
		}

		if (mutex->lck_mtx_owner != 0) {
			cpu_pause();
		}

		loopcount++;
	} while (TRUE);

	LCK_MTX_ADAPTIVE_SPIN_END(mutex, mutex->lck_mtx_grp, spin_start);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_END,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(ctid_get_thread_unsafe(mutex->lck_mtx_owner)),
	    mutex->lck_mtx_waiters, retval, 0);

	return retval;
}



/*
 * Routine:     lck_mtx_lock_wait_x86
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * preemption disabled...
 * returns it unlocked and with preemption enabled
 *
 * lck_mtx_waiters is 1:1 with a wakeup needing to occur.
 *      A runnable waiter can exist between wait and acquire
 *      without a waiters count being set.
 *      This allows us to never make a spurious wakeup call.
 *
 * Priority:
 *      This avoids taking the thread lock if the owning thread is the same priority.
 *      This optimizes the case of same-priority threads contending on a lock.
 *      However, that allows the owning thread to drop in priority while holding the lock,
 *      because there is no state that the priority change can notice that
 *      says that the targeted thread holds a contended mutex.
 *
 *      One possible solution: priority changes could look for some atomic tag
 *      on the thread saying 'holding contended lock', and then set up a promotion.
 *      Needs a story for dropping that promotion - the last contended unlock
 *      has to notice that this has happened.
 */
__attribute__((noinline))
void
lck_mtx_lock_wait_x86(
	lck_mtx_t       *mutex,
	struct turnstile **ts)
{
	thread_t self = current_thread();
	uint64_t sleep_start;

	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(mutex);

	thread_t holder = ctid_get_thread(mutex->lck_mtx_owner);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(holder),
	    mutex->lck_mtx_waiters, 0, 0);
	sleep_start = LCK_MTX_BLOCK_BEGIN();

	mutex->lck_mtx_waiters++;

	/*
	 * lck_mtx_lock_wait_x86 might be called on a loop. Call prepare just once and reuse
	 * the same turnstile while looping, the matching turnstile compleate will be called
	 * by lck_mtx_lock_contended when finally acquiring the lock.
	 */
	if (*ts == NULL) {
		*ts = turnstile_prepare_hash((uintptr_t)mutex, TURNSTILE_KERNEL_MUTEX);
	}

	struct turnstile *turnstile = *ts;
	thread_set_pending_block_hint(self, kThreadWaitKernelMutex);
	turnstile_update_inheritor(turnstile, holder, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	waitq_assert_wait64(&turnstile->ts_waitq, LCK_MTX_EVENT(mutex), THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);

	lck_mtx_ilk_unlock(mutex);

	turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_NOT_HELD);

	thread_block(THREAD_CONTINUE_NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(ctid_get_thread_unsafe(mutex->lck_mtx_owner)),
	    mutex->lck_mtx_waiters, 0, 0);

	LCK_MTX_BLOCK_END(mutex, mutex->lck_mtx_grp, sleep_start);
}

/*
 *      Routine: kdp_lck_mtx_lock_spin_is_acquired
 *      NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *      Returns: TRUE if lock is acquired.
 */
boolean_t
kdp_lck_mtx_lock_spin_is_acquired(lck_mtx_t     *lck)
{
	if (not_in_kdp) {
		panic("panic: kdp_lck_mtx_lock_spin_is_acquired called outside of kernel debugger");
	}

	if (lck->lck_mtx_ilocked || lck->lck_mtx_mlocked) {
		return TRUE;
	}

	return FALSE;
}

void
kdp_lck_mtx_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	lck_mtx_t * mutex = LCK_EVENT_TO_MUTEX(event);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(mutex);
	waitinfo->owner   = thread_tid(ctid_get_thread(mutex->lck_mtx_owner));
}

#endif /* LCK_MTX_USE_ARCH */
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
	has_lock_pv = cpuid_vmm_present() &&
	    (cpuid_vmm_get_kvm_features() & CPUID_KVM_FEATURE_PV_UNHALT) != 0;
}
STARTUP(LOCKS, STARTUP_RANK_FIRST, lck_init_pv);
#endif
