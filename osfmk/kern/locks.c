/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <string.h>

#include <sys/kdebug.h>

#define LCK_MTX_SLEEP_CODE              0
#define LCK_MTX_SLEEP_DEADLINE_CODE     1
#define LCK_MTX_LCK_WAIT_CODE           2
#define LCK_MTX_UNLCK_WAKEUP_CODE       3

#if MACH_LDEBUG
#define ALIGN_TEST(p, t) do{if((uintptr_t)p&(sizeof(t)-1)) __builtin_trap();}while(0)
#else
#define ALIGN_TEST(p, t) do{}while(0)
#endif

#define NOINLINE                __attribute__((noinline))

#define ordered_load_hw(lock)          os_atomic_load(&(lock)->lock_data, compiler_acq_rel)
#define ordered_store_hw(lock, value)  os_atomic_store(&(lock)->lock_data, (value), compiler_acq_rel)

KALLOC_TYPE_DEFINE(KT_GATE, gate_t, KT_PRIV_ACCT);

struct lck_spinlock_to_info PERCPU_DATA(lck_spinlock_to_info);
volatile lck_spinlock_to_info_t lck_spinlock_timeout_in_progress;
queue_head_t     lck_grp_queue;
unsigned int     lck_grp_cnt;

decl_lck_mtx_data(, lck_grp_lock);
static lck_mtx_ext_t lck_grp_lock_ext;

SECURITY_READ_ONLY_LATE(boolean_t) spinlock_timeout_panic = TRUE;

/* Obtain "lcks" options:this currently controls lock statistics */
TUNABLE(uint32_t, LcksOpts, "lcks", 0);

KALLOC_TYPE_DEFINE(KT_LCK_GRP_ATTR, lck_grp_attr_t, KT_PRIV_ACCT);

KALLOC_TYPE_DEFINE(KT_LCK_GRP, lck_grp_t, KT_PRIV_ACCT);

KALLOC_TYPE_DEFINE(KT_LCK_ATTR, lck_attr_t, KT_PRIV_ACCT);

lck_grp_t       LockCompatGroup;
SECURITY_READ_ONLY_LATE(lck_attr_t)      LockDefaultLckAttr;

#if CONFIG_DTRACE
#if defined (__x86_64__)
uint32_t _Atomic dtrace_spin_threshold = 500; // 500ns
#define lock_enable_preemption enable_preemption
#elif defined(__arm__) || defined(__arm64__)
MACHINE_TIMEOUT32(dtrace_spin_threshold, "dtrace-spin-threshold",
    0xC /* 12 ticks == 500ns with 24MHz OSC */, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
#endif
#endif

uintptr_t
unslide_for_kdebug(void* object)
{
	if (__improbable(kdebug_enable)) {
		return VM_KERNEL_UNSLIDE_OR_PERM(object);
	} else {
		return 0;
	}
}

__startup_func
static void
lck_mod_init(void)
{
	queue_init(&lck_grp_queue);

	/*
	 * Need to bootstrap the LockCompatGroup instead of calling lck_grp_init() here. This avoids
	 * grabbing the lck_grp_lock before it is initialized.
	 */

	bzero(&LockCompatGroup, sizeof(lck_grp_t));
	(void) strncpy(LockCompatGroup.lck_grp_name, "Compatibility APIs", LCK_GRP_MAX_NAME);

	LockCompatGroup.lck_grp_attr = LCK_ATTR_NONE;

	if (LcksOpts & enaLkStat) {
		LockCompatGroup.lck_grp_attr |= LCK_GRP_ATTR_STAT;
	}
	if (LcksOpts & enaLkTimeStat) {
		LockCompatGroup.lck_grp_attr |= LCK_GRP_ATTR_TIME_STAT;
	}

	os_ref_init(&LockCompatGroup.lck_grp_refcnt, NULL);

	enqueue_tail(&lck_grp_queue, (queue_entry_t)&LockCompatGroup);
	lck_grp_cnt = 1;

	lck_attr_setdefault(&LockDefaultLckAttr);

	lck_mtx_init_ext(&lck_grp_lock, &lck_grp_lock_ext, &LockCompatGroup, &LockDefaultLckAttr);

#if DEBUG_RW
	rw_lock_init();
#endif /* DEBUG_RW */
}
STARTUP(LOCKS_EARLY, STARTUP_RANK_FIRST, lck_mod_init);

/*
 * Routine:	lck_grp_attr_alloc_init
 */

lck_grp_attr_t  *
lck_grp_attr_alloc_init(
	void)
{
	lck_grp_attr_t  *attr;

	attr = zalloc(KT_LCK_GRP_ATTR);
	lck_grp_attr_setdefault(attr);
	return attr;
}


/*
 * Routine:	lck_grp_attr_setdefault
 */

void
lck_grp_attr_setdefault(
	lck_grp_attr_t  *attr)
{
	if (LcksOpts & enaLkStat) {
		attr->grp_attr_val = LCK_GRP_ATTR_STAT;
	} else {
		attr->grp_attr_val = 0;
	}
}


/*
 * Routine:     lck_grp_attr_setstat
 */

void
lck_grp_attr_setstat(
	lck_grp_attr_t  *attr)
{
#pragma unused(attr)
	os_atomic_or(&attr->grp_attr_val, LCK_GRP_ATTR_STAT, relaxed);
}


/*
 * Routine:     lck_grp_attr_free
 */

void
lck_grp_attr_free(
	lck_grp_attr_t  *attr)
{
	zfree(KT_LCK_GRP_ATTR, attr);
}


/*
 * Routine: lck_grp_alloc_init
 */

lck_grp_t *
lck_grp_alloc_init(
	const char*     grp_name,
	lck_grp_attr_t  *attr)
{
	lck_grp_t       *grp;

	grp = zalloc(KT_LCK_GRP);
	lck_grp_init(grp, grp_name, attr);
	return grp;
}

/*
 * Routine: lck_grp_init
 */

void
lck_grp_init(lck_grp_t * grp, const char * grp_name, lck_grp_attr_t * attr)
{
	/* make sure locking infrastructure has been initialized */
	assert(lck_grp_cnt > 0);

	bzero((void *)grp, sizeof(lck_grp_t));

	(void)strlcpy(grp->lck_grp_name, grp_name, LCK_GRP_MAX_NAME);

	if (attr != LCK_GRP_ATTR_NULL) {
		grp->lck_grp_attr = attr->grp_attr_val;
	} else {
		grp->lck_grp_attr = 0;
		if (LcksOpts & enaLkStat) {
			grp->lck_grp_attr |= LCK_GRP_ATTR_STAT;
		}
		if (LcksOpts & enaLkTimeStat) {
			grp->lck_grp_attr |= LCK_GRP_ATTR_TIME_STAT;
		}
	}

	if (grp->lck_grp_attr & LCK_GRP_ATTR_STAT) {
		lck_grp_stats_t *stats = &grp->lck_grp_stats;

#if LOCK_STATS
		lck_grp_stat_enable(&stats->lgss_spin_held);
		lck_grp_stat_enable(&stats->lgss_spin_miss);
#endif /* LOCK_STATS */

		lck_grp_stat_enable(&stats->lgss_mtx_held);
		lck_grp_stat_enable(&stats->lgss_mtx_miss);
		lck_grp_stat_enable(&stats->lgss_mtx_direct_wait);
		lck_grp_stat_enable(&stats->lgss_mtx_wait);
	}
	if (grp->lck_grp_attr & LCK_GRP_ATTR_TIME_STAT) {
#if LOCK_STATS
		lck_grp_stats_t *stats = &grp->lck_grp_stats;
		lck_grp_stat_enable(&stats->lgss_spin_spin);
#endif /* LOCK_STATS */
	}

	os_ref_init(&grp->lck_grp_refcnt, NULL);

	lck_mtx_lock(&lck_grp_lock);
	enqueue_tail(&lck_grp_queue, (queue_entry_t)grp);
	lck_grp_cnt++;
	lck_mtx_unlock(&lck_grp_lock);
}

/*
 * Routine:     lck_grp_free
 */

void
lck_grp_free(
	lck_grp_t       *grp)
{
	lck_mtx_lock(&lck_grp_lock);
	lck_grp_cnt--;
	(void)remque((queue_entry_t)grp);
	lck_mtx_unlock(&lck_grp_lock);
	lck_grp_deallocate(grp);
}


/*
 * Routine:     lck_grp_reference
 */

void
lck_grp_reference(
	lck_grp_t       *grp)
{
	os_ref_retain(&grp->lck_grp_refcnt);
}


/*
 * Routine:     lck_grp_deallocate
 */

void
lck_grp_deallocate(
	lck_grp_t       *grp)
{
	if (os_ref_release(&grp->lck_grp_refcnt) != 0) {
		return;
	}

	zfree(KT_LCK_GRP, grp);
}

/*
 * Routine:	lck_grp_lckcnt_incr
 */

void
lck_grp_lckcnt_incr(
	lck_grp_t       *grp,
	lck_type_t      lck_type)
{
	unsigned int    *lckcnt;

	switch (lck_type) {
	case LCK_TYPE_SPIN:
		lckcnt = &grp->lck_grp_spincnt;
		break;
	case LCK_TYPE_MTX:
		lckcnt = &grp->lck_grp_mtxcnt;
		break;
	case LCK_TYPE_RW:
		lckcnt = &grp->lck_grp_rwcnt;
		break;
	case LCK_TYPE_TICKET:
		lckcnt = &grp->lck_grp_ticketcnt;
		break;
	default:
		return panic("lck_grp_lckcnt_incr(): invalid lock type: %d", lck_type);
	}

	os_atomic_inc(lckcnt, relaxed);
}

/*
 * Routine:	lck_grp_lckcnt_decr
 */

void
lck_grp_lckcnt_decr(
	lck_grp_t       *grp,
	lck_type_t      lck_type)
{
	unsigned int    *lckcnt;
	int             updated;

	switch (lck_type) {
	case LCK_TYPE_SPIN:
		lckcnt = &grp->lck_grp_spincnt;
		break;
	case LCK_TYPE_MTX:
		lckcnt = &grp->lck_grp_mtxcnt;
		break;
	case LCK_TYPE_RW:
		lckcnt = &grp->lck_grp_rwcnt;
		break;
	case LCK_TYPE_TICKET:
		lckcnt = &grp->lck_grp_ticketcnt;
		break;
	default:
		panic("lck_grp_lckcnt_decr(): invalid lock type: %d", lck_type);
		return;
	}

	updated = os_atomic_dec(lckcnt, relaxed);
	assert(updated >= 0);
}

/*
 * Routine:	lck_attr_alloc_init
 */

lck_attr_t *
lck_attr_alloc_init(
	void)
{
	lck_attr_t      *attr;

	attr = zalloc(KT_LCK_ATTR);
	lck_attr_setdefault(attr);
	return attr;
}


/*
 * Routine:	lck_attr_setdefault
 */

void
lck_attr_setdefault(
	lck_attr_t      *attr)
{
#if __arm__ || __arm64__
	/* <rdar://problem/4404579>: Using LCK_ATTR_DEBUG here causes panic at boot time for arm */
	attr->lck_attr_val =  LCK_ATTR_NONE;
#elif __i386__ || __x86_64__
#if     !DEBUG
	if (LcksOpts & enaLkDeb) {
		attr->lck_attr_val =  LCK_ATTR_DEBUG;
	} else {
		attr->lck_attr_val =  LCK_ATTR_NONE;
	}
#else
	attr->lck_attr_val =  LCK_ATTR_DEBUG;
#endif  /* !DEBUG */
#else
#error Unknown architecture.
#endif  /* __arm__ */
}


/*
 * Routine:	lck_attr_setdebug
 */
void
lck_attr_setdebug(
	lck_attr_t      *attr)
{
	os_atomic_or(&attr->lck_attr_val, LCK_ATTR_DEBUG, relaxed);
}

/*
 * Routine:	lck_attr_setdebug
 */
void
lck_attr_cleardebug(
	lck_attr_t      *attr)
{
	os_atomic_andnot(&attr->lck_attr_val, LCK_ATTR_DEBUG, relaxed);
}


/*
 * Routine:	lck_attr_rw_shared_priority
 */
void
lck_attr_rw_shared_priority(
	lck_attr_t      *attr)
{
	os_atomic_or(&attr->lck_attr_val, LCK_ATTR_RW_SHARED_PRIORITY, relaxed);
}


/*
 * Routine:	lck_attr_free
 */
void
lck_attr_free(
	lck_attr_t      *attr)
{
	zfree(KT_LCK_ATTR, attr);
}

static __abortlike void
__lck_require_preemption_disabled_panic(void *lock)
{
	panic("Attempt to take no-preempt lock %p in preemptible context", lock);
}

static inline void
__lck_require_preemption_disabled(void *lock, thread_t self __unused)
{
	if (__improbable(!lock_preemption_disabled_for_thread(self))) {
		__lck_require_preemption_disabled_panic(lock);
	}
}

/*
 * Routine:	hw_lock_init
 *
 *	Initialize a hardware lock.
 */
MARK_AS_HIBERNATE_TEXT void
hw_lock_init(hw_lock_t lock)
{
	ordered_store_hw(lock, 0);
}

__result_use_check
static inline bool
hw_lock_trylock_contended(hw_lock_t lock, uintptr_t newval)
{
#if OS_ATOMIC_USE_LLSC
	uintptr_t oldval;
	os_atomic_rmw_loop(&lock->lock_data, oldval, newval, acquire, {
		if (oldval != 0) {
		        wait_for_event(); // clears the monitor so we don't need give_up()
		        return false;
		}
	});
	return true;
#else // !OS_ATOMIC_USE_LLSC
#if OS_ATOMIC_HAS_LLSC
	uintptr_t oldval = os_atomic_load_exclusive(&lock->lock_data, relaxed);
	if (oldval != 0) {
		wait_for_event(); // clears the monitor so we don't need give_up()
		return false;
	}
#elif LOCK_PRETEST
	if (ordered_load_hw(lock) != 0) {
		return false;
	}
#endif
	return os_atomic_cmpxchg(&lock->lock_data, 0, newval, acquire);
#endif // !OS_ATOMIC_USE_LLSC
}

__attribute__((always_inline))
void
lck_spinlock_timeout_set_orig_owner(uintptr_t owner)
{
#if DEBUG || DEVELOPMENT
	PERCPU_GET(lck_spinlock_to_info)->owner_thread_orig = owner & ~0x7ul;
#else
	(void)owner;
#endif
}

lck_spinlock_to_info_t
lck_spinlock_timeout_hit(void *lck, uintptr_t owner)
{
	lck_spinlock_to_info_t lsti = PERCPU_GET(lck_spinlock_to_info);

	/* strip possible bits used by the lock implementations */
	owner &= ~0x7ul;

	lsti->lock = lck;
	lsti->owner_thread_cur = owner;
	lsti->owner_cpu = ~0u;
	os_atomic_store(&lck_spinlock_timeout_in_progress, lsti, release);

	if (owner == 0) {
		/* if the owner isn't known, just bail */
		goto out;
	}

	for (uint32_t i = 0; i <= ml_early_cpu_max_number(); i++) {
		cpu_data_t *data = cpu_datap(i);
		if (data && (uintptr_t)data->cpu_active_thread == owner) {
			lsti->owner_cpu = i;
			os_atomic_store(&lck_spinlock_timeout_in_progress, lsti, release);
#if __x86_64__
			if ((uint32_t)cpu_number() != i) {
				/* Cause NMI and panic on the owner's cpu */
				NMIPI_panic(cpu_to_cpumask(i), SPINLOCK_TIMEOUT);
			}
#endif
			break;
		}
	}

out:
	return lsti;
}

/*
 * Routine:	hw_lock_trylock_mask_allow_invalid
 *
 *	Tries to acquire a lock of possibly even unmapped memory.
 *	It assumes a valid lock MUST have another bit set (different from
 *	the one being set to lock).
 */
__result_use_check
extern hw_lock_status_t
hw_lock_trylock_mask_allow_invalid(uint32_t *lock, uint32_t mask);

__result_use_check
static inline bool
hw_lock_trylock_bit(uint32_t *target, unsigned int bit, bool wait)
{
	uint32_t mask = 1u << bit;

#if OS_ATOMIC_USE_LLSC || !OS_ATOMIC_HAS_LLSC
	uint32_t oldval, newval;
	os_atomic_rmw_loop(target, oldval, newval, acquire, {
		newval = oldval | mask;
		if (__improbable(oldval & mask)) {
#if OS_ATOMIC_HAS_LLSC
		        if (wait) {
		                wait_for_event(); // clears the monitor so we don't need give_up()
			} else {
		                os_atomic_clear_exclusive();
			}
#else
		        if (wait) {
		                cpu_pause();
			}
#endif
		        return false;
		}
	});
	return true;
#else
	uint32_t oldval = os_atomic_load_exclusive(target, relaxed);
	if (__improbable(oldval & mask)) {
		if (wait) {
			wait_for_event(); // clears the monitor so we don't need give_up()
		} else {
			os_atomic_clear_exclusive();
		}
		return false;
	}
	return (os_atomic_or_orig(target, mask, acquire) & mask) == 0;
#endif // !OS_ATOMIC_USE_LLSC && OS_ATOMIC_HAS_LLSC
}

static hw_lock_timeout_status_t
hw_lock_timeout_panic(void *_lock, uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(interrupt_time)

	hw_lock_t lock  = _lock;
	uintptr_t owner = lock->lock_data & ~0x7ul;
	lck_spinlock_to_info_t lsti;

	if (!spinlock_timeout_panic) {
		/* keep spinning rather than panicing */
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	if (pmap_in_ppl()) {
		/*
		 * This code is used by the PPL and can't write to globals.
		 */
		panic("Spinlock[%p] timeout after %llu ticks; "
		    "current owner: %p, "
		    "start time: %llu, now: %llu, timeout: %llu",
		    lock, now - start, (void *)owner,
		    start, now, timeout);
	}

	// Capture the actual time spent blocked, which may be higher than the timeout
	// if a misbehaving interrupt stole this thread's CPU time.
	lsti = lck_spinlock_timeout_hit(lock, owner);
	panic("Spinlock[%p] timeout after %llu ticks; "
	    "current owner: %p (on cpu %d), "
#if DEBUG || DEVELOPMENT
	    "initial owner: %p, "
#endif /* DEBUG || DEVELOPMENT */
#if INTERRUPT_MASKED_DEBUG
	    "interrupt time: %llu, "
#endif /* INTERRUPT_MASKED_DEBUG */
	    "start time: %llu, now: %llu, timeout: %llu",
	    lock, now - start,
	    (void *)lsti->owner_thread_cur, lsti->owner_cpu,
#if DEBUG || DEVELOPMENT
	    (void *)lsti->owner_thread_orig,
#endif /* DEBUG || DEVELOPMENT */
#if INTERRUPT_MASKED_DEBUG
	    interrupt_time,
#endif /* INTERRUPT_MASKED_DEBUG */
	    start, now, timeout);
}

static hw_lock_timeout_status_t
hw_lock_bit_timeout_panic(void *_lock, uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(interrupt_time)

	hw_lock_t lock  = _lock;
	uintptr_t state = lock->lock_data;

	if (!spinlock_timeout_panic) {
		/* keep spinning rather than panicing */
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	panic("Spinlock[%p] timeout after %llu ticks; "
	    "current state: %p, "
#if INTERRUPT_MASKED_DEBUG
	    "interrupt time: %llu, "
#endif /* INTERRUPT_MASKED_DEBUG */
	    "start time: %llu, now: %llu, timeout: %llu",
	    lock, now - start, (void*) state,
#if INTERRUPT_MASKED_DEBUG
	    interrupt_time,
#endif /* INTERRUPT_MASKED_DEBUG */
	    start, now, timeout);
}

/*
 *	Routine: hw_lock_lock_contended
 *
 *	Spin until lock is acquired or timeout expires.
 *	timeout is in mach_absolute_time ticks. Called with
 *	preemption disabled.
 */
static hw_lock_status_t NOINLINE
hw_lock_lock_contended(hw_lock_t lock, thread_t thread, uintptr_t data, uint64_t timeout,
    hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(thread)

	uint64_t        end = 0, start = 0, interrupts = 0;
	uint64_t        default_timeout = os_atomic_load(&lock_panic_timeout, relaxed);
	bool            has_timeout = timeout > 0 || default_timeout > 0;

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_spin_spin_enabled(lock LCK_GRP_ARG(grp));

	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* CONFIG_DTRACE || LOCK_STATS */

	if (!pmap_in_ppl()) {
		/*
		 * This code is used by the PPL and can't write to globals.
		 */
		lck_spinlock_timeout_set_orig_owner(lock->lock_data);
	}
	if (has_timeout && timeout == 0) {
		timeout = default_timeout;
	}
#if INTERRUPT_MASKED_DEBUG
	bool measure_interrupts = !pmap_in_ppl() && ml_get_interrupts_enabled();
	uint64_t start_interrupts = 0;
#endif /* INTERRUPT_MASKED_DEBUG */
	for (;;) {
		for (uint32_t i = 0; i < LOCK_SNOOP_SPINS; i++) {
			cpu_pause();
			if (hw_lock_trylock_contended(lock, data)) {
#if CONFIG_DTRACE || LOCK_STATS
				if (__improbable(stat_enabled)) {
					lck_grp_spin_update_spin(lock LCK_GRP_ARG(grp),
					    mach_absolute_time() - begin);
				}
				lck_grp_spin_update_miss(lock LCK_GRP_ARG(grp));
				lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */
				return HW_LOCK_ACQUIRED;
			}
		}
		if (has_timeout) {
			uint64_t now = ml_get_timebase();
			if (end == 0) {
#if INTERRUPT_MASKED_DEBUG
				if (measure_interrupts) {
					start_interrupts = thread->machine.int_time_mt;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				start = now;
				end = now + timeout;
			} else if (now < end) {
				/* keep spinning */
			} else {
#if INTERRUPT_MASKED_DEBUG
				if (measure_interrupts) {
					interrupts = thread->machine.int_time_mt - start_interrupts;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				if (handler(lock, timeout, start, now, interrupts)) {
					/* push the deadline */
					end += timeout;
				} else {
#if CONFIG_DTRACE || LOCK_STATS
					if (__improbable(stat_enabled)) {
						lck_grp_spin_update_spin(lock LCK_GRP_ARG(grp),
						    mach_absolute_time() - begin);
					}
					lck_grp_spin_update_miss(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */
					return HW_LOCK_CONTENDED;
				}
			}
		}
	}
}

void *
hw_wait_while_equals(void **address, void *current)
{
	void *v;
	uint64_t end = 0;
	uint64_t timeout = os_atomic_load(&lock_panic_timeout, relaxed);

#if INTERRUPT_MASKED_DEBUG
	bool measure_interrupts = !pmap_in_ppl() && ml_get_interrupts_enabled();
	thread_t thread = current_thread();
	uint64_t interrupts = 0;
	uint64_t start_interrupts = 0;
#endif /* INTERRUPT_MASKED_DEBUG */

	for (;;) {
		for (int i = 0; i < LOCK_SNOOP_SPINS; i++) {
			cpu_pause();
#if OS_ATOMIC_HAS_LLSC
			v = os_atomic_load_exclusive(address, relaxed);
			if (__probable(v != current)) {
				os_atomic_clear_exclusive();
				return v;
			}
			wait_for_event();
#else
			v = os_atomic_load(address, relaxed);
			if (__probable(v != current)) {
				return v;
			}
#endif // OS_ATOMIC_HAS_LLSC
		}
		if (timeout > 0) {
			if (end == 0) {
				end = ml_get_timebase() + timeout;
#if INTERRUPT_MASKED_DEBUG
				if (measure_interrupts) {
					start_interrupts = thread->machine.int_time_mt;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
			} else if (ml_get_timebase() >= end) {
#if INTERRUPT_MASKED_DEBUG
				if (measure_interrupts) {
					interrupts = thread->machine.int_time_mt - start_interrupts;
					panic("Wait while equals timeout @ *%p == %p, interrupt_time %llu", address, v, interrupts);
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				panic("Wait while equals timeout @ *%p == %p", address, v);
			}
		}
	}
}

__result_use_check
static inline hw_lock_status_t
hw_lock_to_internal(hw_lock_t lock, thread_t thread, uint64_t timeout,
    hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp))
{
	uintptr_t state = LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK;

	if (__probable(hw_lock_trylock_contended(lock, state))) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	return hw_lock_lock_contended(lock, thread, state, timeout, handler LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_lock
 *
 *	Acquire lock, spinning until it becomes available,
 *	return with preemption disabled.
 */
void
(hw_lock_lock)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	lock_disable_preemption_for_thread(thread);
	(void)hw_lock_to_internal(lock, thread, 0, hw_lock_timeout_panic LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_lock_nopreempt
 *
 *	Acquire lock, spinning until it becomes available.
 */
void
(hw_lock_lock_nopreempt)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	__lck_require_preemption_disabled(lock, thread);
	(void)hw_lock_to_internal(lock, thread, 0, hw_lock_timeout_panic LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_to
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	Timeout is in mach_absolute_time ticks, return with
 *	preemption disabled.
 */
unsigned
int
(hw_lock_to)(hw_lock_t lock, uint64_t timeout, hw_lock_timeout_handler_t handler
    LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	lock_disable_preemption_for_thread(thread);
	return (unsigned)hw_lock_to_internal(lock, thread, timeout, handler LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_to_nopreempt
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	Timeout is in mach_absolute_time ticks, called and return with
 *	preemption disabled.
 */
unsigned
int
(hw_lock_to_nopreempt)(hw_lock_t lock, uint64_t timeout,
    hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	__lck_require_preemption_disabled(lock, thread);
	return (unsigned)hw_lock_to_internal(lock, thread, timeout, handler LCK_GRP_ARG(grp));
}

__result_use_check
static inline unsigned int
hw_lock_try_internal(hw_lock_t lock, thread_t thread LCK_GRP_ARG(lck_grp_t *grp))
{
	int success = 0;

#if LOCK_PRETEST
	if (__improbable(ordered_load_hw(lock) != 0)) {
		return 0;
	}
#endif  // LOCK_PRETEST

	success = os_atomic_cmpxchg(&lock->lock_data, 0,
	    LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK, acquire);

	if (success) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
	}
	return success;
}

/*
 *	Routine: hw_lock_try
 *
 *	returns with preemption disabled on success.
 */
unsigned
int
(hw_lock_try)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	lock_disable_preemption_for_thread(thread);
	unsigned int success = hw_lock_try_internal(lock, thread LCK_GRP_ARG(grp));
	if (!success) {
		lock_enable_preemption();
	}
	return success;
}

unsigned
int
(hw_lock_try_nopreempt)(hw_lock_t lock LCK_GRP_ARG(lck_grp_t *grp))
{
	thread_t thread = current_thread();
	__lck_require_preemption_disabled(lock, thread);
	return hw_lock_try_internal(lock, thread LCK_GRP_ARG(grp));
}

/*
 *	Routine: hw_lock_unlock
 *
 *	Unconditionally release lock, release preemption level.
 */
static inline void
hw_lock_unlock_internal(hw_lock_t lock)
{
	os_atomic_store(&lock->lock_data, 0, release);
#if __arm__ || __arm64__
	// ARM tests are only for open-source exclusion
	set_event();
#endif  // __arm__ || __arm64__
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
}

void
(hw_lock_unlock)(hw_lock_t lock)
{
	hw_lock_unlock_internal(lock);
	lock_enable_preemption();
}

void
(hw_lock_unlock_nopreempt)(hw_lock_t lock)
{
	hw_lock_unlock_internal(lock);
}

/*
 *	Routine hw_lock_held, doesn't change preemption state.
 *	N.B.  Racy, of course.
 */
unsigned int
hw_lock_held(hw_lock_t lock)
{
	return ordered_load_hw(lock) != 0;
}

static hw_lock_status_t NOINLINE
hw_lock_bit_to_contended(
	hw_lock_bit_t *lock,
	uint32_t       bit,
	uint64_t       timeout,
	hw_lock_timeout_handler_t handler,
	bool           validate
	LCK_GRP_ARG(lck_grp_t *grp))
{
	uint64_t        end = 0, start = 0, interrupts = 0;
	uint64_t        default_timeout = os_atomic_load(&lock_panic_timeout, relaxed);
	bool            has_timeout = timeout > 0 || default_timeout > 0;

	hw_lock_status_t rc;
	uint32_t        mask = 1u << bit;

#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_spin_spin_enabled(lock LCK_GRP_ARG(grp));

	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* LOCK_STATS || CONFIG_DTRACE */

	if (has_timeout && timeout == 0) {
		timeout = default_timeout;
	}
#if INTERRUPT_MASKED_DEBUG
	bool measure_interrupts = !pmap_in_ppl() && ml_get_interrupts_enabled();
	thread_t thread = current_thread();
	uint64_t start_interrupts = 0;
#endif /* INTERRUPT_MASKED_DEBUG */
	for (;;) {
		for (int i = 0; i < LOCK_SNOOP_SPINS; i++) {
			// Always load-exclusive before wfe
			// This grabs the monitor and wakes up on a release event
			if (validate) {
				rc = hw_lock_trylock_mask_allow_invalid(lock, mask);
				if (rc == HW_LOCK_INVALID) {
					lock_enable_preemption();
					return rc;
				}
			} else {
				rc = hw_lock_trylock_bit(lock, bit, true);
			}
			if (rc == HW_LOCK_ACQUIRED) {
				lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
				goto end;
			}
		}
		if (has_timeout) {
			uint64_t now = ml_get_timebase();
			if (end == 0) {
#if INTERRUPT_MASKED_DEBUG
				if (measure_interrupts) {
					start_interrupts = thread->machine.int_time_mt;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				start = now;
				end = now + timeout;
			} else if (now < end) {
				/* keep spinning */
			} else {
#if INTERRUPT_MASKED_DEBUG
				if (measure_interrupts) {
					interrupts = thread->machine.int_time_mt - start_interrupts;
				}
#endif /* INTERRUPT_MASKED_DEBUG */
				if (handler(lock, timeout, start, now, interrupts)) {
					/* push the deadline */
					end += timeout;
				} else {
					assert(rc == HW_LOCK_CONTENDED);
					break;
				}
			}
		}
	}

end:
#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(stat_enabled)) {
		lck_grp_spin_update_spin(lock LCK_GRP_ARG(grp),
		    mach_absolute_time() - begin);
	}
	lck_grp_spin_update_miss(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LCK_GRP_STAT */
	return rc;
}

__result_use_check
static inline unsigned int
hw_lock_bit_to_internal(hw_lock_bit_t *lock, unsigned int bit, uint64_t timeout,
    hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp))
{
	if (__probable(hw_lock_trylock_bit(lock, bit, true))) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	return (unsigned)hw_lock_bit_to_contended(lock, bit, timeout, handler,
	           false LCK_GRP_ARG(grp));
}

unsigned
int
(hw_lock_bit_to)(hw_lock_bit_t * lock, unsigned int bit, uint64_t timeout,
    hw_lock_timeout_handler_t handler LCK_GRP_ARG(lck_grp_t *grp))
{
	_disable_preemption();
	return hw_lock_bit_to_internal(lock, bit, timeout, handler LCK_GRP_ARG(grp));
}

void
(hw_lock_bit)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	_disable_preemption();
	(void)hw_lock_bit_to_internal(lock, bit, 0, hw_lock_bit_timeout_panic LCK_GRP_ARG(grp));
}

void
(hw_lock_bit_nopreempt)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	__lck_require_preemption_disabled(lock, current_thread());
	(void)hw_lock_bit_to_internal(lock, bit, 0, hw_lock_bit_timeout_panic LCK_GRP_ARG(grp));
}


hw_lock_status_t
(hw_lock_bit_to_allow_invalid)(hw_lock_bit_t * lock, unsigned int bit,
    uint64_t timeout, hw_lock_timeout_handler_t handler
    LCK_GRP_ARG(lck_grp_t *grp))
{
	int rc;

	_disable_preemption();

	rc = hw_lock_trylock_mask_allow_invalid(lock, 1u << bit);
	if (__probable(rc == HW_LOCK_ACQUIRED)) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
		return HW_LOCK_ACQUIRED;
	}

	if (__probable(rc == HW_LOCK_CONTENDED)) {
		return hw_lock_bit_to_contended(lock, bit, timeout, handler,
		           true LCK_GRP_ARG(grp));
	}

	lock_enable_preemption();
	return HW_LOCK_INVALID;
}

unsigned
int
(hw_lock_bit_try)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	boolean_t success = false;

	_disable_preemption();
	success = hw_lock_trylock_bit(lock, bit, false);
	if (!success) {
		lock_enable_preemption();
	}

	if (success) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
	}

	return success;
}

static inline void
hw_unlock_bit_internal(hw_lock_bit_t *lock, unsigned int bit)
{
	os_atomic_andnot(lock, 1u << bit, release);
#if __arm__
	set_event();
#endif
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lock, bit);
#endif
}

/*
 *	Routine:	hw_unlock_bit
 *
 *		Release spin-lock. The second parameter is the bit number to test and set.
 *		Decrement the preemption level.
 */
void
hw_unlock_bit(hw_lock_bit_t * lock, unsigned int bit)
{
	hw_unlock_bit_internal(lock, bit);
	lock_enable_preemption();
}

void
hw_unlock_bit_nopreempt(hw_lock_bit_t * lock, unsigned int bit)
{
	__lck_require_preemption_disabled(lock, current_thread());
	hw_unlock_bit_internal(lock, bit);
}

/*
 * Routine:	lck_spin_sleep
 */
wait_result_t
lck_spin_sleep_grp(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	lck_grp_t               *grp)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			lck_spin_lock_grp(lck, grp);
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_spin_unlock(lck);
	}

	return res;
}

wait_result_t
lck_spin_sleep(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	return lck_spin_sleep_grp(lck, lck_sleep_action, event, interruptible, LCK_GRP_NULL);
}

/*
 * Routine:	lck_spin_sleep_deadline
 */
wait_result_t
lck_spin_sleep_deadline(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			lck_spin_lock(lck);
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_spin_unlock(lck);
	}

	return res;
}

/*
 * Routine:	lck_mtx_sleep
 */
wait_result_t
lck_mtx_sleep(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	wait_result_t           res;
	thread_pri_floor_t      token;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * We get a priority floor
		 * during the time that this thread is asleep, so that when it
		 * is re-awakened (and not yet contending on the mutex), it is
		 * runnable at a reasonably high priority.
		 */
		token = thread_priority_floor_start();
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN)) {
				lck_mtx_lock_spin(lck);
			} else if ((lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS)) {
				lck_mtx_lock_spin_always(lck);
			} else {
				lck_mtx_lock(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_mtx_unlock(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}


/*
 * Routine:	lck_mtx_sleep_deadline
 */
wait_result_t
lck_mtx_sleep_deadline(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t           res;
	thread_pri_floor_t      token;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * See lck_mtx_sleep().
		 */
		token = thread_priority_floor_start();
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN)) {
				lck_mtx_lock_spin(lck);
			} else {
				lck_mtx_lock(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_mtx_unlock(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread_priority_floor_end(&token);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * Lock Boosting Invariants:
 *
 * The lock owner is always promoted to the max priority of all its waiters.
 * Max priority is capped at MAXPRI_PROMOTE.
 *
 * The last waiter is not given a promotion when it wakes up or acquires the lock.
 * When the last waiter is waking up, a new contender can always come in and
 * steal the lock without having to wait for the last waiter to make forward progress.
 */

/*
 * Routine: lck_mtx_lock_wait
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * returns it unlocked.
 *
 * Always aggressively sets the owning thread to promoted,
 * even if it's the same or higher priority
 * This prevents it from lowering its own priority while holding a lock
 *
 * TODO: Come up with a more efficient way to handle same-priority promotions
 *      <rdar://problem/30737670> ARM mutex contention logic could avoid taking the thread lock
 */
void
lck_mtx_lock_wait(
	lck_mtx_t                       *lck,
	thread_t                        holder,
	struct turnstile                **ts)
{
	thread_t                thread = current_thread();
	lck_mtx_t               *mutex = lck;
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(lck);

#if     CONFIG_DTRACE
	uint64_t                sleep_start = 0;

	if (lockstat_probemap[LS_LCK_MTX_LOCK_BLOCK] || lockstat_probemap[LS_LCK_MTX_EXT_LOCK_BLOCK]) {
		sleep_start = mach_absolute_time();
	}
#endif

#if LOCKS_INDIRECT_ALLOW
	if (__improbable(lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT)) {
		mutex = &lck->lck_mtx_ptr->lck_mtx;
	}
#endif /* LOCKS_INDIRECT_ALLOW */

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START,
	    trace_lck, (uintptr_t)thread_tid(thread), 0, 0, 0);

	mutex->lck_mtx_waiters++;

	if (*ts == NULL) {
		*ts = turnstile_prepare((uintptr_t)mutex, NULL, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
	}

	struct turnstile *turnstile = *ts;
	thread_set_pending_block_hint(thread, kThreadWaitKernelMutex);
	turnstile_update_inheritor(turnstile, holder, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	waitq_assert_wait64(&turnstile->ts_waitq, CAST_EVENT64_T(LCK_MTX_EVENT(mutex)), THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);

	lck_mtx_ilk_unlock(mutex);

	turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_NOT_HELD);

	thread_block(THREAD_CONTINUE_NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
#if     CONFIG_DTRACE
	/*
	 * Record the DTrace lockstat probe for blocking, block time
	 * measured from when we were entered.
	 */
	if (sleep_start) {
#if LOCKS_INDIRECT_ALLOW
		if (lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT) {
			LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_BLOCK, lck,
			    mach_absolute_time() - sleep_start);
		} else
#endif /* LOCKS_INDIRECT_ALLOW */
		{
			LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_BLOCK, lck,
			    mach_absolute_time() - sleep_start);
		}
	}
#endif
}

/*
 * Routine:     lck_mtx_lock_acquire
 *
 * Invoked on acquiring the mutex when there is
 * contention.
 *
 * Returns the current number of waiters.
 *
 * Called with the interlock locked.
 */
int
lck_mtx_lock_acquire(
	lck_mtx_t               *lck,
	struct turnstile        *ts)
{
	thread_t                thread = current_thread();
	lck_mtx_t               *mutex = lck;

#if LOCKS_INDIRECT_ALLOW
	if (__improbable(lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT)) {
		mutex = &lck->lck_mtx_ptr->lck_mtx;
	}
#endif /* LOCKS_INDIRECT_ALLOW */

	if (mutex->lck_mtx_waiters > 0) {
		if (ts == NULL) {
			ts = turnstile_prepare((uintptr_t)mutex, NULL, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
		}

		turnstile_update_inheritor(ts, thread, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	}

	if (ts != NULL) {
		turnstile_complete((uintptr_t)mutex, NULL, NULL, TURNSTILE_KERNEL_MUTEX);
	}

	return mutex->lck_mtx_waiters;
}

/*
 * Routine:     lck_mtx_unlock_wakeup
 *
 * Invoked on unlock when there is contention.
 *
 * Called with the interlock locked.
 *
 * NOTE: callers should call turnstile_clenup after
 * dropping the interlock.
 */
boolean_t
lck_mtx_unlock_wakeup(
	lck_mtx_t                       *lck,
	thread_t                        holder)
{
	thread_t                thread = current_thread();
	lck_mtx_t               *mutex = lck;
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(lck);
	struct turnstile *ts;
	kern_return_t did_wake;

#if LOCKS_INDIRECT_ALLOW
	if (__improbable(lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT)) {
		mutex = &lck->lck_mtx_ptr->lck_mtx;
	}
#endif /* LOCKS_INDIRECT_ALLOW */


	if (thread != holder) {
		panic("lck_mtx_unlock_wakeup: mutex %p holder %p", mutex, holder);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_START,
	    trace_lck, (uintptr_t)thread_tid(thread), 0, 0, 0);

	assert(mutex->lck_mtx_waiters > 0);

	ts = turnstile_prepare((uintptr_t)mutex, NULL, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	if (mutex->lck_mtx_waiters > 1) {
		/* WAITQ_PROMOTE_ON_WAKE will call turnstile_update_inheritor on the wokenup thread */
		did_wake = waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(LCK_MTX_EVENT(mutex)), THREAD_AWAKENED, WAITQ_PROMOTE_ON_WAKE);
	} else {
		did_wake = waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(LCK_MTX_EVENT(mutex)), THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
		turnstile_update_inheritor(ts, NULL, TURNSTILE_IMMEDIATE_UPDATE);
	}
	assert(did_wake == KERN_SUCCESS);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete((uintptr_t)mutex, NULL, NULL, TURNSTILE_KERNEL_MUTEX);

	mutex->lck_mtx_waiters--;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);

	return mutex->lck_mtx_waiters > 0;
}

/*
 * Routine:     mutex_pause
 *
 * Called by former callers of simple_lock_pause().
 */
#define MAX_COLLISION_COUNTS    32
#define MAX_COLLISION   8

unsigned int max_collision_count[MAX_COLLISION_COUNTS];

uint32_t collision_backoffs[MAX_COLLISION] = {
	10, 50, 100, 200, 400, 600, 800, 1000
};


void
mutex_pause(uint32_t collisions)
{
	wait_result_t wait_result;
	uint32_t        back_off;

	if (collisions >= MAX_COLLISION_COUNTS) {
		collisions = MAX_COLLISION_COUNTS - 1;
	}
	max_collision_count[collisions]++;

	if (collisions >= MAX_COLLISION) {
		collisions = MAX_COLLISION - 1;
	}
	back_off = collision_backoffs[collisions];

	wait_result = assert_wait_timeout((event_t)mutex_pause, THREAD_UNINT, back_off, NSEC_PER_USEC);
	assert(wait_result == THREAD_WAITING);

	wait_result = thread_block(THREAD_CONTINUE_NULL);
	assert(wait_result == THREAD_TIMED_OUT);
}


unsigned int mutex_yield_wait = 0;
unsigned int mutex_yield_no_wait = 0;

void
lck_mtx_yield(
	lck_mtx_t   *lck)
{
	int     waiters;

#if DEBUG
	lck_mtx_assert(lck, LCK_MTX_ASSERT_OWNED);
#endif /* DEBUG */

#if LOCKS_INDIRECT_ALLOW
	if (__improbable(lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT)) {
		waiters = lck->lck_mtx_ptr->lck_mtx.lck_mtx_waiters;
	} else
#endif /* LOCKS_INDIRECT_ALLOW */
	{
		waiters = lck->lck_mtx_waiters;
	}

	if (!waiters) {
		mutex_yield_no_wait++;
	} else {
		mutex_yield_wait++;
		lck_mtx_unlock(lck);
		mutex_pause(0);
		lck_mtx_lock(lck);
	}
}

kern_return_t
host_lockgroup_info(
	host_t                                  host,
	lockgroup_info_array_t  *lockgroup_infop,
	mach_msg_type_number_t  *lockgroup_infoCntp)
{
	lockgroup_info_t        *lockgroup_info_base;
	lockgroup_info_t        *lockgroup_info;
	vm_offset_t                     lockgroup_info_addr;
	vm_size_t                       lockgroup_info_size;
	vm_size_t                       lockgroup_info_vmsize;
	lck_grp_t                       *lck_grp;
	unsigned int            i;
	vm_map_copy_t           copy;
	kern_return_t           kr;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	lck_mtx_lock(&lck_grp_lock);

	lockgroup_info_size = lck_grp_cnt * sizeof(*lockgroup_info);
	lockgroup_info_vmsize = round_page(lockgroup_info_size);
	kr = kmem_alloc_pageable(ipc_kernel_map,
	    &lockgroup_info_addr, lockgroup_info_vmsize, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&lck_grp_lock);
		return kr;
	}

	lockgroup_info_base = (lockgroup_info_t *) lockgroup_info_addr;
	lck_grp = (lck_grp_t *)queue_first(&lck_grp_queue);
	lockgroup_info = lockgroup_info_base;

	for (i = 0; i < lck_grp_cnt; i++) {
		lockgroup_info->lock_spin_cnt = lck_grp->lck_grp_spincnt;
		lockgroup_info->lock_rw_cnt = lck_grp->lck_grp_rwcnt;
		lockgroup_info->lock_mtx_cnt = lck_grp->lck_grp_mtxcnt;

#if LOCK_STATS
		lockgroup_info->lock_spin_held_cnt = lck_grp->lck_grp_stats.lgss_spin_held.lgs_count;
		lockgroup_info->lock_spin_miss_cnt = lck_grp->lck_grp_stats.lgss_spin_miss.lgs_count;
#endif /* LOCK_STATS */

		// Historically on x86, held was used for "direct wait" and util for "held"
		lockgroup_info->lock_mtx_util_cnt = lck_grp->lck_grp_stats.lgss_mtx_held.lgs_count;
		lockgroup_info->lock_mtx_held_cnt = lck_grp->lck_grp_stats.lgss_mtx_direct_wait.lgs_count;
		lockgroup_info->lock_mtx_miss_cnt = lck_grp->lck_grp_stats.lgss_mtx_miss.lgs_count;
		lockgroup_info->lock_mtx_wait_cnt = lck_grp->lck_grp_stats.lgss_mtx_wait.lgs_count;

		(void) strncpy(lockgroup_info->lockgroup_name, lck_grp->lck_grp_name, LOCKGROUP_MAX_NAME);

		lck_grp = (lck_grp_t *)(queue_next((queue_entry_t)(lck_grp)));
		lockgroup_info++;
	}

	*lockgroup_infoCntp = lck_grp_cnt;
	lck_mtx_unlock(&lck_grp_lock);

	if (lockgroup_info_size != lockgroup_info_vmsize) {
		bzero((char *)lockgroup_info, lockgroup_info_vmsize - lockgroup_info_size);
	}

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)lockgroup_info_addr,
	    (vm_map_size_t)lockgroup_info_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*lockgroup_infop = (lockgroup_info_t *) copy;

	return KERN_SUCCESS;
}

/*
 * sleep_with_inheritor and wakeup_with_inheritor KPI
 *
 * Functions that allow to sleep on an event and use turnstile to propagate the priority of the sleeping threads to
 * the latest thread specified as inheritor.
 *
 * The inheritor management is delegated to the caller, the caller needs to store a thread identifier to provide to this functions to specified upon whom
 * direct the push. The inheritor cannot run in user space while holding a push from an event. Therefore is the caller responsibility to call a
 * wakeup_with_inheritor from inheritor before running in userspace or specify another inheritor before letting the old inheritor run in userspace.
 *
 * sleep_with_inheritor requires to hold a locking primitive while invoked, but wakeup_with_inheritor and change_sleep_inheritor don't require it.
 *
 * Turnstile requires a non blocking primitive as interlock to synchronize the turnstile data structure manipulation, threfore sleep_with_inheritor, change_sleep_inheritor and
 * wakeup_with_inheritor will require the same interlock to manipulate turnstiles.
 * If sleep_with_inheritor is associated with a locking primitive that can block (like lck_mtx_t or lck_rw_t), an handoff to a non blocking primitive is required before
 * invoking any turnstile operation.
 *
 * All functions will save the turnstile associated with the event on the turnstile kernel hash table and will use the the turnstile kernel hash table bucket
 * spinlock as the turnstile interlock. Because we do not want to hold interrupt disabled while holding the bucket interlock a new turnstile kernel hash table
 * is instantiated for this KPI to manage the hash without interrupt disabled.
 * Also:
 * - all events on the system that hash on the same bucket will contend on the same spinlock.
 * - every event will have a dedicated wait_queue.
 *
 * Different locking primitives can be associated with sleep_with_inheritor as long as the primitive_lock() and primitive_unlock() functions are provided to
 * sleep_with_inheritor_turnstile to perform the handoff with the bucket spinlock.
 */

kern_return_t
wakeup_with_inheritor_and_turnstile_type(event_t event, turnstile_type_t type, wait_result_t result, bool wake_one, lck_wake_action_t action, thread_t *thread_wokenup)
{
	uint32_t index;
	struct turnstile *ts = NULL;
	kern_return_t ret = KERN_NOT_WAITING;
	int priority;
	thread_t wokeup;

	/*
	 * the hash bucket spinlock is used as turnstile interlock
	 */
	turnstile_hash_bucket_lock((uintptr_t)event, &index, type);

	ts = turnstile_prepare((uintptr_t)event, NULL, TURNSTILE_NULL, type);

	if (wake_one) {
		if (action == LCK_WAKE_DEFAULT) {
			priority = WAITQ_PROMOTE_ON_WAKE;
		} else {
			assert(action == LCK_WAKE_DO_NOT_TRANSFER_PUSH);
			priority = WAITQ_ALL_PRIORITIES;
		}

		/*
		 * WAITQ_PROMOTE_ON_WAKE will call turnstile_update_inheritor
		 * if it finds a thread
		 */
		wokeup = waitq_wakeup64_identify(&ts->ts_waitq, CAST_EVENT64_T(event), result, priority);
		if (wokeup != NULL) {
			if (thread_wokenup != NULL) {
				*thread_wokenup = wokeup;
			} else {
				thread_deallocate_safe(wokeup);
			}
			ret = KERN_SUCCESS;
			if (action == LCK_WAKE_DO_NOT_TRANSFER_PUSH) {
				goto complete;
			}
		} else {
			if (thread_wokenup != NULL) {
				*thread_wokenup = NULL;
			}
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
			ret = KERN_NOT_WAITING;
		}
	} else {
		ret = waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
		turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
	}

	/*
	 * turnstile_update_inheritor_complete could be called while holding the interlock.
	 * In this case the new inheritor or is null, or is a thread that is just been woken up
	 * and have not blocked because it is racing with the same interlock used here
	 * after the wait.
	 * So there is no chain to update for the new inheritor.
	 *
	 * However unless the current thread is the old inheritor,
	 * old inheritor can be blocked and requires a chain update.
	 *
	 * The chain should be short because kernel turnstiles cannot have user turnstiles
	 * chained after them.
	 *
	 * We can anyway optimize this by asking turnstile to tell us
	 * if old inheritor needs an update and drop the lock
	 * just in that case.
	 */
	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

complete:
	turnstile_complete((uintptr_t)event, NULL, NULL, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();

	return ret;
}

static wait_result_t
sleep_with_inheritor_and_turnstile_type(event_t event,
    thread_t inheritor,
    wait_interrupt_t interruptible,
    uint64_t deadline,
    turnstile_type_t type,
    void (^primitive_lock)(void),
    void (^primitive_unlock)(void))
{
	wait_result_t ret;
	uint32_t index;
	struct turnstile *ts = NULL;

	/*
	 * the hash bucket spinlock is used as turnstile interlock,
	 * lock it before releasing the primitive lock
	 */
	turnstile_hash_bucket_lock((uintptr_t)event, &index, type);

	primitive_unlock();

	ts = turnstile_prepare((uintptr_t)event, NULL, TURNSTILE_NULL, type);

	thread_set_pending_block_hint(current_thread(), kThreadWaitSleepWithInheritor);
	/*
	 * We need TURNSTILE_DELAYED_UPDATE because we will call
	 * waitq_assert_wait64 after.
	 */
	turnstile_update_inheritor(ts, inheritor, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	ret = waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(event), interruptible, deadline);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	/*
	 * Update new and old inheritor chains outside the interlock;
	 */
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	if (ret == THREAD_WAITING) {
		ret = thread_block(THREAD_CONTINUE_NULL);
	}

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

	turnstile_complete((uintptr_t)event, NULL, NULL, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();

	primitive_lock();

	return ret;
}

kern_return_t
change_sleep_inheritor_and_turnstile_type(event_t event,
    thread_t inheritor,
    turnstile_type_t type)
{
	uint32_t index;
	struct turnstile *ts = NULL;
	kern_return_t ret =  KERN_SUCCESS;
	/*
	 * the hash bucket spinlock is used as turnstile interlock
	 */
	turnstile_hash_bucket_lock((uintptr_t)event, &index, type);

	ts = turnstile_prepare((uintptr_t)event, NULL, TURNSTILE_NULL, type);

	if (!turnstile_has_waiters(ts)) {
		ret = KERN_NOT_WAITING;
	}

	/*
	 * We will not call an assert_wait later so use TURNSTILE_IMMEDIATE_UPDATE
	 */
	turnstile_update_inheritor(ts, inheritor, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	/*
	 * update the chains outside the interlock
	 */
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	turnstile_hash_bucket_lock((uintptr_t)NULL, &index, type);

	turnstile_complete((uintptr_t)event, NULL, NULL, type);

	turnstile_hash_bucket_unlock((uintptr_t)NULL, &index, type, 0);

	turnstile_cleanup();

	return ret;
}

typedef void (^void_block_void)(void);

/*
 * sleep_with_inheritor functions with lck_mtx_t as locking primitive.
 */

wait_result_t
lck_mtx_sleep_with_inheritor_and_turnstile_type(lck_mtx_t *lock, lck_sleep_action_t lck_sleep_action, event_t event, thread_t inheritor, wait_interrupt_t interruptible, uint64_t deadline, turnstile_type_t type)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{;},
		           ^{lck_mtx_unlock(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN) {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{lck_mtx_lock_spin(lock);},
		           ^{lck_mtx_unlock(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS) {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{lck_mtx_lock_spin_always(lock);},
		           ^{lck_mtx_unlock(lock);});
	} else {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{lck_mtx_lock(lock);},
		           ^{lck_mtx_unlock(lock);});
	}
}

/*
 * Name: lck_spin_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_spin_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
lck_spin_sleep_with_inheritor(
	lck_spin_t *lock,
	lck_sleep_action_t lck_sleep_action,
	event_t event,
	thread_t inheritor,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile_type(event, inheritor,
		           interruptible, deadline, TURNSTILE_SLEEP_INHERITOR,
		           ^{}, ^{ lck_spin_unlock(lock); });
	} else {
		return sleep_with_inheritor_and_turnstile_type(event, inheritor,
		           interruptible, deadline, TURNSTILE_SLEEP_INHERITOR,
		           ^{ lck_spin_lock(lock); }, ^{ lck_spin_unlock(lock); });
	}
}

/*
 * Name: lck_ticket_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_ticket_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
lck_ticket_sleep_with_inheritor(
	lck_ticket_t *lock,
	lck_grp_t *grp,
	lck_sleep_action_t lck_sleep_action,
	event_t event,
	thread_t inheritor,
	wait_interrupt_t interruptible,
	uint64_t deadline)
{
	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile_type(event, inheritor,
		           interruptible, deadline, TURNSTILE_SLEEP_INHERITOR,
		           ^{}, ^{ lck_ticket_unlock(lock); });
	} else {
		return sleep_with_inheritor_and_turnstile_type(event, inheritor,
		           interruptible, deadline, TURNSTILE_SLEEP_INHERITOR,
		           ^{ lck_ticket_lock(lock, grp); }, ^{ lck_ticket_unlock(lock); });
	}
}

/*
 * Name: lck_mtx_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK, LCK_SLEEP_SPIN, LCK_SLEEP_SPIN_ALWAYS.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
lck_mtx_sleep_with_inheritor(lck_mtx_t *lock, lck_sleep_action_t lck_sleep_action, event_t event, thread_t inheritor, wait_interrupt_t interruptible, uint64_t deadline)
{
	return lck_mtx_sleep_with_inheritor_and_turnstile_type(lock, lck_sleep_action, event, inheritor, interruptible, deadline, TURNSTILE_SLEEP_INHERITOR);
}

/*
 * sleep_with_inheritor functions with lck_rw_t as locking primitive.
 */

wait_result_t
lck_rw_sleep_with_inheritor_and_turnstile_type(lck_rw_t *lock, lck_sleep_action_t lck_sleep_action, event_t event, thread_t inheritor, wait_interrupt_t interruptible, uint64_t deadline, turnstile_type_t type)
{
	__block lck_rw_type_t lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;

	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{;},
		           ^{lck_rw_type = lck_rw_done(lock);});
	} else if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{lck_rw_lock(lock, lck_rw_type);},
		           ^{lck_rw_type = lck_rw_done(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{lck_rw_lock_exclusive(lock);},
		           ^{lck_rw_type = lck_rw_done(lock);});
	} else {
		return sleep_with_inheritor_and_turnstile_type(event,
		           inheritor,
		           interruptible,
		           deadline,
		           type,
		           ^{lck_rw_lock_shared(lock);},
		           ^{lck_rw_type = lck_rw_done(lock);});
	}
}

/*
 * Name: lck_rw_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_SHARED, LCK_SLEEP_EXCLUSIVE.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
wait_result_t
lck_rw_sleep_with_inheritor(lck_rw_t *lock, lck_sleep_action_t lck_sleep_action, event_t event, thread_t inheritor, wait_interrupt_t interruptible, uint64_t deadline)
{
	return lck_rw_sleep_with_inheritor_and_turnstile_type(lock, lck_sleep_action, event, inheritor, interruptible, deadline, TURNSTILE_SLEEP_INHERITOR);
}

/*
 * wakeup_with_inheritor functions are independent from the locking primitive.
 */

/*
 * Name: wakeup_one_with_inheritor
 *
 * Description: wake up one waiter for event if any. The thread woken up will be the one with the higher sched priority waiting on event.
 *              The push for the event will be transferred from the last inheritor to the woken up thread if LCK_WAKE_DEFAULT is specified.
 *              If LCK_WAKE_DO_NOT_TRANSFER_PUSH is specified the push will not be transferred.
 *
 * Args:
 *   Arg1: event to wake from.
 *   Arg2: wait result to pass to the woken up thread.
 *   Arg3: wake flag. LCK_WAKE_DEFAULT or LCK_WAKE_DO_NOT_TRANSFER_PUSH.
 *   Arg4: pointer for storing the thread wokenup.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: The new inheritor wokenup cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *             A reference for the wokenup thread is acquired.
 *             NOTE: this cannot be called from interrupt context.
 */
kern_return_t
wakeup_one_with_inheritor(event_t event, wait_result_t result, lck_wake_action_t action, thread_t *thread_wokenup)
{
	return wakeup_with_inheritor_and_turnstile_type(event,
	           TURNSTILE_SLEEP_INHERITOR,
	           result,
	           TRUE,
	           action,
	           thread_wokenup);
}

/*
 * Name: wakeup_all_with_inheritor
 *
 * Description: wake up all waiters waiting for event. The old inheritor will lose the push.
 *
 * Args:
 *   Arg1: event to wake from.
 *   Arg2: wait result to pass to the woken up threads.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: NOTE: this cannot be called from interrupt context.
 */
kern_return_t
wakeup_all_with_inheritor(event_t event, wait_result_t result)
{
	return wakeup_with_inheritor_and_turnstile_type(event,
	           TURNSTILE_SLEEP_INHERITOR,
	           result,
	           FALSE,
	           0,
	           NULL);
}

/*
 * change_sleep_inheritor is independent from the locking primitive.
 */

/*
 * Name: change_sleep_inheritor
 *
 * Description: Redirect the push of the waiting threads of event to the new inheritor specified.
 *
 * Args:
 *   Arg1: event to redirect the push.
 *   Arg2: new inheritor for event.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: In case of success, the new inheritor cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *             NOTE: this cannot be called from interrupt context.
 */
kern_return_t
change_sleep_inheritor(event_t event, thread_t inheritor)
{
	return change_sleep_inheritor_and_turnstile_type(event,
	           inheritor,
	           TURNSTILE_SLEEP_INHERITOR);
}

void
kdp_sleep_with_inheritor_find_owner(struct waitq * waitq, __unused event64_t event, thread_waitinfo_t * waitinfo)
{
	assert(waitinfo->wait_type == kThreadWaitSleepWithInheritor);
	assert(waitq_is_turnstile_queue(waitq));
	waitinfo->owner = 0;
	waitinfo->context = 0;

	if (waitq_held(waitq)) {
		return;
	}

	struct turnstile *turnstile = waitq_to_turnstile(waitq);
	assert(turnstile->ts_inheritor_flags & TURNSTILE_INHERITOR_THREAD);
	waitinfo->owner = thread_tid(turnstile->ts_inheritor);
}

#define GATE_TYPE        3
#define GATE_ILOCK_BIT   0
#define GATE_WAITERS_BIT 1

#define GATE_ILOCK (1 << GATE_ILOCK_BIT)
#define GATE_WAITERS (1 << GATE_WAITERS_BIT)

#define gate_ilock(gate) hw_lock_bit((hw_lock_bit_t*)(&(gate)->gt_data), GATE_ILOCK_BIT, LCK_GRP_NULL)
#define gate_iunlock(gate) hw_unlock_bit((hw_lock_bit_t*)(&(gate)->gt_data), GATE_ILOCK_BIT)
#define gate_has_waiter_bit(state) ((state & GATE_WAITERS) != 0)
#define ordered_load_gate(gate) os_atomic_load(&(gate)->gt_data, compiler_acq_rel)
#define ordered_store_gate(gate, value)  os_atomic_store(&(gate)->gt_data, value, compiler_acq_rel)

#define GATE_THREAD_MASK (~(uintptr_t)(GATE_ILOCK | GATE_WAITERS))
#define GATE_STATE_TO_THREAD(state) (thread_t)((state) & GATE_THREAD_MASK)
#define GATE_STATE_MASKED(state) (uintptr_t)((state) & GATE_THREAD_MASK)
#define GATE_THREAD_TO_STATE(thread) ((uintptr_t)(thread))

#define GATE_DESTROYED GATE_STATE_MASKED(0xdeadbeefdeadbeef)

#define GATE_EVENT(gate)     ((event_t) gate)
#define EVENT_TO_GATE(event) ((gate_t *) event)

typedef void (*void_func_void)(void);

__abortlike
static void
gate_verify_tag_panic(gate_t *gate)
{
	panic("Gate used is invalid. gate %p data %lx turnstile %p refs %d flags %x ", gate, gate->gt_data, gate->gt_turnstile, gate->gt_refs, gate->gt_flags);
}

__abortlike
static void
gate_verify_destroy_panic(gate_t *gate)
{
	panic("Gate used was destroyed. gate %p data %lx turnstile %p refs %d flags %x", gate, gate->gt_data, gate->gt_turnstile, gate->gt_refs, gate->gt_flags);
}

static void
gate_verify(gate_t *gate)
{
	if (gate->gt_type != GATE_TYPE) {
		gate_verify_tag_panic(gate);
	}
	if (GATE_STATE_MASKED(gate->gt_data) == GATE_DESTROYED) {
		gate_verify_destroy_panic(gate);
	}

	assert(gate->gt_refs > 0);
}

__abortlike
static void
gate_already_owned_panic(gate_t *gate, thread_t holder)
{
	panic("Trying to close a gate already closed gate %p holder %p current_thread %p", gate, holder, current_thread());
}

static kern_return_t
gate_try_close(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	kern_return_t ret;
	thread_t thread = current_thread();

	gate_verify(gate);

	if (os_atomic_cmpxchg(&gate->gt_data, 0, GATE_THREAD_TO_STATE(thread), acquire)) {
		return KERN_SUCCESS;
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	if (holder == NULL) {
		assert(gate_has_waiter_bit(state) == FALSE);

		state = GATE_THREAD_TO_STATE(current_thread());
		state |= GATE_ILOCK;
		ordered_store_gate(gate, state);
		ret = KERN_SUCCESS;
	} else {
		if (holder == current_thread()) {
			gate_already_owned_panic(gate, holder);
		}
		ret = KERN_FAILURE;
	}

	gate_iunlock(gate);
	return ret;
}

static void
gate_close(gate_t* gate)
{
	uintptr_t state;
	thread_t holder;
	thread_t thread = current_thread();

	gate_verify(gate);

	if (os_atomic_cmpxchg(&gate->gt_data, 0, GATE_THREAD_TO_STATE(thread), acquire)) {
		return;
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	if (holder != NULL) {
		gate_already_owned_panic(gate, holder);
	}

	assert(gate_has_waiter_bit(state) == FALSE);

	state = GATE_THREAD_TO_STATE(thread);
	state |= GATE_ILOCK;
	ordered_store_gate(gate, state);

	gate_iunlock(gate);
}

static void
gate_open_turnstile(gate_t *gate)
{
	struct turnstile *ts = NULL;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
	waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(GATE_EVENT(gate)), THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
	turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);
	/*
	 * We can do the cleanup while holding the interlock.
	 * It is ok because:
	 * 1. current_thread is the previous inheritor and it is running
	 * 2. new inheritor is NULL.
	 * => No chain of turnstiles needs to be updated.
	 */
	turnstile_cleanup();
}

__abortlike
static void
gate_not_owned_panic(gate_t *gate, thread_t holder, bool open)
{
	if (open) {
		panic("Trying to open a gate %p owned by %p from current_thread %p", gate, holder, current_thread());
	} else {
		panic("Trying to handoff a gate %p owned by %p from current_thread %p", gate, holder, current_thread());
	}
}

static void
gate_open(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	bool waiters;
	thread_t thread = current_thread();

	gate_verify(gate);
	if (os_atomic_cmpxchg(&gate->gt_data, GATE_THREAD_TO_STATE(thread), 0, release)) {
		return;
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);
	waiters = gate_has_waiter_bit(state);

	if (holder != thread) {
		gate_not_owned_panic(gate, holder, true);
	}

	if (waiters) {
		gate_open_turnstile(gate);
	}

	state = GATE_ILOCK;
	ordered_store_gate(gate, state);

	gate_iunlock(gate);
}

static kern_return_t
gate_handoff_turnstile(gate_t *gate,
    int flags,
    thread_t *thread_woken_up,
    bool *waiters)
{
	struct turnstile *ts = NULL;
	kern_return_t ret = KERN_FAILURE;
	thread_t hp_thread;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
	/*
	 * Wake up the higest priority thread waiting on the gate
	 */
	hp_thread = waitq_wakeup64_identify(&ts->ts_waitq, CAST_EVENT64_T(GATE_EVENT(gate)), THREAD_AWAKENED, WAITQ_PROMOTE_ON_WAKE);

	if (hp_thread != NULL) {
		/*
		 * In this case waitq_wakeup64_identify has called turnstile_update_inheritor for us
		 */
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		*thread_woken_up = hp_thread;
		*waiters = turnstile_has_waiters(ts);
		/*
		 * Note: hp_thread is the new holder and the new inheritor.
		 * In case there are no more waiters, it doesn't need to be the inheritor
		 * and it shouldn't be it by the time it finishes the wait, so that its next open or
		 * handoff can go through the fast path.
		 * We could set the inheritor to NULL here, or the new holder itself can set it
		 * on its way back from the sleep. In the latter case there are more chanses that
		 * new waiters will come by, avoiding to do the opearation at all.
		 */
		ret = KERN_SUCCESS;
	} else {
		/*
		 * waiters can have been woken up by an interrupt and still not
		 * have updated gate->waiters, so we couldn't find them on the waitq.
		 * Update the inheritor to NULL here, so that the current thread can return to userspace
		 * indipendently from when the interrupted waiters will finish the wait.
		 */
		if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
			turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		}
		// there are no waiters.
		ret = KERN_NOT_WAITING;
	}

	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);

	/*
	 * We can do the cleanup while holding the interlock.
	 * It is ok because:
	 * 1. current_thread is the previous inheritor and it is running
	 * 2. new inheritor is NULL or it is a just wokenup thread that will race acquiring the lock
	 *    of the gate before trying to sleep.
	 * => No chain of turnstiles needs to be updated.
	 */
	turnstile_cleanup();

	return ret;
}

static kern_return_t
gate_handoff(gate_t *gate,
    int flags)
{
	kern_return_t ret;
	thread_t new_holder = NULL;
	uintptr_t state;
	thread_t holder;
	bool waiters;
	thread_t thread = current_thread();

	assert(flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS || flags == GATE_HANDOFF_DEFAULT);
	gate_verify(gate);

	if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
		if (os_atomic_cmpxchg(&gate->gt_data, GATE_THREAD_TO_STATE(thread), 0, release)) {
			//gate opened but there were no waiters, so return KERN_NOT_WAITING.
			return KERN_NOT_WAITING;
		}
	}

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);
	waiters = gate_has_waiter_bit(state);

	if (holder != current_thread()) {
		gate_not_owned_panic(gate, holder, false);
	}

	if (waiters) {
		ret = gate_handoff_turnstile(gate, flags, &new_holder, &waiters);
		if (ret == KERN_SUCCESS) {
			state = GATE_THREAD_TO_STATE(new_holder);
			if (waiters) {
				state |= GATE_WAITERS;
			}
		} else {
			if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
				state = 0;
			}
		}
	} else {
		if (flags == GATE_HANDOFF_OPEN_IF_NO_WAITERS) {
			state = 0;
		}
		ret = KERN_NOT_WAITING;
	}
	state |= GATE_ILOCK;
	ordered_store_gate(gate, state);

	gate_iunlock(gate);

	if (new_holder) {
		thread_deallocate(new_holder);
	}
	return ret;
}

static void_func_void
gate_steal_turnstile(gate_t *gate,
    thread_t new_inheritor)
{
	struct turnstile *ts = NULL;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	turnstile_update_inheritor(ts, new_inheritor, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);

	/*
	 * turnstile_cleanup might need to update the chain of the old holder.
	 * This operation should happen without the turnstile interlock held.
	 */
	return turnstile_cleanup;
}

__abortlike
static void
gate_not_closed_panic(gate_t *gate, bool wait)
{
	if (wait) {
		panic("Trying to wait on a not closed gate %p from current_thread %p", gate, current_thread());
	} else {
		panic("Trying to steal a not closed gate %p from current_thread %p", gate, current_thread());
	}
}

static void
gate_steal(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	thread_t thread = current_thread();
	bool waiters;

	void_func_void func_after_interlock_unlock;

	gate_verify(gate);

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);
	waiters = gate_has_waiter_bit(state);

	if (holder == NULL) {
		gate_not_closed_panic(gate, false);
	}

	state = GATE_THREAD_TO_STATE(thread) | GATE_ILOCK;
	if (waiters) {
		state |= GATE_WAITERS;
		ordered_store_gate(gate, state);
		func_after_interlock_unlock = gate_steal_turnstile(gate, thread);
		gate_iunlock(gate);

		func_after_interlock_unlock();
	} else {
		ordered_store_gate(gate, state);
		gate_iunlock(gate);
	}
}

static void_func_void
gate_wait_turnstile(gate_t *gate,
    wait_interrupt_t interruptible,
    uint64_t deadline,
    thread_t holder,
    wait_result_t* wait,
    bool* waiters)
{
	struct turnstile *ts;
	uintptr_t state;

	ts = turnstile_prepare((uintptr_t)gate, &gate->gt_turnstile, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	turnstile_update_inheritor(ts, holder, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));
	waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(GATE_EVENT(gate)), interruptible, deadline);

	gate_iunlock(gate);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	*wait = thread_block(THREAD_CONTINUE_NULL);

	gate_ilock(gate);

	*waiters = turnstile_has_waiters(ts);

	if (!*waiters) {
		/*
		 * We want to enable the fast path as soon as we see that there are no more waiters.
		 * On the fast path the holder will not do any turnstile operations.
		 * Set the inheritor as NULL here.
		 *
		 * NOTE: if it was an open operation that woke this thread up, the inheritor has
		 * already been set to NULL.
		 */
		state = ordered_load_gate(gate);
		holder = GATE_STATE_TO_THREAD(state);
		if (holder &&
		    ((*wait != THREAD_AWAKENED) ||     // thread interrupted or timedout
		    holder == current_thread())) {     // thread was woken up and it is the new holder
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL, TURNSTILE_IMMEDIATE_UPDATE);
			turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);
		}
	}

	turnstile_complete((uintptr_t)gate, &gate->gt_turnstile, NULL, TURNSTILE_KERNEL_MUTEX);

	/*
	 * turnstile_cleanup might need to update the chain of the old holder.
	 * This operation should happen without the turnstile primitive interlock held.
	 */
	return turnstile_cleanup;
}

static void
gate_free_internal(gate_t *gate)
{
	zfree(KT_GATE, gate);
}

__abortlike
static void
gate_too_many_refs_panic(gate_t *gate)
{
	panic("Too many refs taken on gate. gate %p data %lx turnstile %p refs %d flags %x", gate, gate->gt_data, gate->gt_turnstile, gate->gt_refs, gate->gt_flags);
}

static gate_wait_result_t
gate_wait(gate_t* gate,
    wait_interrupt_t interruptible,
    uint64_t deadline,
    void (^primitive_unlock)(void),
    void (^primitive_lock)(void))
{
	gate_wait_result_t ret;
	void_func_void func_after_interlock_unlock;
	wait_result_t wait_result;
	uintptr_t state;
	thread_t holder;
	bool waiters;

	gate_verify(gate);

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	if (holder == NULL) {
		gate_not_closed_panic(gate, true);
	}

	/*
	 * Get a ref on the gate so it will not
	 * be freed while we are coming back from the sleep.
	 */
	if (gate->gt_refs == UINT16_MAX) {
		gate_too_many_refs_panic(gate);
	}
	gate->gt_refs++;
	state |= GATE_WAITERS;
	ordered_store_gate(gate, state);

	/*
	 * Release the primitive lock before any
	 * turnstile operation. Turnstile
	 * does not support a blocking primitive as
	 * interlock.
	 *
	 * In this way, concurrent threads will be
	 * able to acquire the primitive lock
	 * but still will wait for me through the
	 * gate interlock.
	 */
	primitive_unlock();

	func_after_interlock_unlock = gate_wait_turnstile(    gate,
	    interruptible,
	    deadline,
	    holder,
	    &wait_result,
	    &waiters);

	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	switch (wait_result) {
	case THREAD_INTERRUPTED:
	case THREAD_TIMED_OUT:
		assert(holder != current_thread());

		if (waiters) {
			state |= GATE_WAITERS;
		} else {
			state &= ~GATE_WAITERS;
		}
		ordered_store_gate(gate, state);

		if (wait_result == THREAD_INTERRUPTED) {
			ret = GATE_INTERRUPTED;
		} else {
			ret = GATE_TIMED_OUT;
		}
		break;
	default:
		/*
		 * Note it is possible that even if the gate was handed off to
		 * me, someone called gate_steal() before I woke up.
		 *
		 * As well as it is possible that the gate was opened, but someone
		 * closed it while I was waking up.
		 *
		 * In both cases we return GATE_OPENED, as the gate was opened to me
		 * at one point, it is the caller responsibility to check again if
		 * the gate is open.
		 */
		if (holder == current_thread()) {
			ret = GATE_HANDOFF;
		} else {
			ret = GATE_OPENED;
		}
		break;
	}

	assert(gate->gt_refs > 0);
	uint32_t ref = --gate->gt_refs;
	bool to_free = gate->gt_alloc;
	gate_iunlock(gate);

	if (GATE_STATE_MASKED(state) == GATE_DESTROYED) {
		if (to_free == true) {
			assert(!waiters);
			if (ref == 0) {
				gate_free_internal(gate);
			}
			ret = GATE_OPENED;
		} else {
			gate_verify_destroy_panic(gate);
		}
	}

	/*
	 * turnstile func that needs to be executed without
	 * holding the primitive interlock
	 */
	func_after_interlock_unlock();

	primitive_lock();

	return ret;
}

static void
gate_assert(gate_t *gate, int flags)
{
	uintptr_t state;
	thread_t holder;

	gate_verify(gate);

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	switch (flags) {
	case GATE_ASSERT_CLOSED:
		assert(holder != NULL);
		break;
	case GATE_ASSERT_OPEN:
		assert(holder == NULL);
		break;
	case GATE_ASSERT_HELD:
		assert(holder == current_thread());
		break;
	default:
		panic("invalid %s flag %d", __func__, flags);
	}

	gate_iunlock(gate);
}

enum {
	GT_INIT_DEFAULT = 0,
	GT_INIT_ALLOC
};

static void
gate_init(gate_t *gate, uint type)
{
	bzero(gate, sizeof(gate_t));

	gate->gt_data = 0;
	gate->gt_turnstile = NULL;
	gate->gt_refs = 1;
	switch (type) {
	case GT_INIT_ALLOC:
		gate->gt_alloc = 1;
		break;
	default:
		gate->gt_alloc = 0;
		break;
	}
	gate->gt_type = GATE_TYPE;
	gate->gt_flags_pad = 0;
}

static gate_t*
gate_alloc_init(void)
{
	gate_t *gate;
	gate = zalloc_flags(KT_GATE, Z_WAITOK | Z_NOFAIL);
	gate_init(gate, GT_INIT_ALLOC);
	return gate;
}

__abortlike
static void
gate_destroy_owned_panic(gate_t *gate, thread_t holder)
{
	panic("Trying to destroy a gate owned by %p. Gate %p", holder, gate);
}

__abortlike
static void
gate_destroy_waiter_panic(gate_t *gate)
{
	panic("Trying to destroy a gate with waiters. Gate %p data %lx turnstile %p", gate, gate->gt_data, gate->gt_turnstile);
}

static uint16_t
gate_destroy_internal(gate_t *gate)
{
	uintptr_t state;
	thread_t holder;
	uint16_t ref;

	gate_ilock(gate);
	state = ordered_load_gate(gate);
	holder = GATE_STATE_TO_THREAD(state);

	/*
	 * The gate must be open
	 * and all the threads must
	 * have been woken up by this time
	 */
	if (holder != NULL) {
		gate_destroy_owned_panic(gate, holder);
	}
	if (gate_has_waiter_bit(state)) {
		gate_destroy_waiter_panic(gate);
	}

	assert(gate->gt_refs > 0);

	ref = --gate->gt_refs;

	/*
	 * Mark the gate as destroyed.
	 * The interlock bit still need
	 * to be available to let the
	 * last wokenup threads to clear
	 * the wait.
	 */
	state = GATE_DESTROYED;
	state |= GATE_ILOCK;
	ordered_store_gate(gate, state);
	gate_iunlock(gate);
	return ref;
}

__abortlike
static void
gate_destroy_panic(gate_t *gate)
{
	panic("Trying to destroy a gate that was allocated by gate_alloc_init(). gate_free() should be used instead, gate %p thread %p", gate, current_thread());
}

static void
gate_destroy(gate_t *gate)
{
	gate_verify(gate);
	if (gate->gt_alloc == 1) {
		gate_destroy_panic(gate);
	}
	gate_destroy_internal(gate);
}

__abortlike
static void
gate_free_panic(gate_t *gate)
{
	panic("Trying to free a gate that was not allocated by gate_alloc_init(), gate %p thread %p", gate, current_thread());
}

static void
gate_free(gate_t *gate)
{
	uint16_t ref;

	gate_verify(gate);

	if (gate->gt_alloc == 0) {
		gate_free_panic(gate);
	}

	ref = gate_destroy_internal(gate);
	/*
	 * Some of the threads waiting on the gate
	 * might still need to run after being woken up.
	 * They will access the gate to cleanup the
	 * state, so we cannot free it.
	 * The last waiter will free the gate in this case.
	 */
	if (ref == 0) {
		gate_free_internal(gate);
	}
}

/*
 * Name: lck_rw_gate_init
 *
 * Description: initializes a variable declared with decl_lck_rw_gate_data.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 */
void
lck_rw_gate_init(lck_rw_t *lock, gate_t *gate)
{
	(void) lock;
	gate_init(gate, GT_INIT_DEFAULT);
}

/*
 * Name: lck_rw_gate_alloc_init
 *
 * Description: allocates and initializes a gate_t.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *
 * Returns:
 *         gate_t allocated.
 */
gate_t*
lck_rw_gate_alloc_init(lck_rw_t *lock)
{
	(void) lock;
	return gate_alloc_init();
}

/*
 * Name: lck_rw_gate_destroy
 *
 * Description: destroys a variable previously initialized
 *              with lck_rw_gate_init().
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 */
void
lck_rw_gate_destroy(lck_rw_t *lock, gate_t *gate)
{
	(void) lock;
	gate_destroy(gate);
}

/*
 * Name: lck_rw_gate_free
 *
 * Description: destroys and tries to free a gate previously allocated
 *              with lck_rw_gate_alloc_init().
 *              The gate free might be delegated to the last thread returning
 *              from the gate_wait().
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate obtained with lck_rw_gate_alloc_init().
 */
void
lck_rw_gate_free(lck_rw_t *lock, gate_t *gate)
{
	(void) lock;
	gate_free(gate);
}

/*
 * Name: lck_rw_gate_try_close
 *
 * Description: Tries to close the gate.
 *              In case of success the current thread will be set as
 *              the holder of the gate.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *
 * Returns:
 *          KERN_SUCCESS in case the gate was successfully closed. The current thread is the new holder
 *          of the gate.
 *          A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *          to wake up possible waiters on the gate before returning to userspace.
 *          If the intent is to conditionally probe the gate before waiting, the lock must not be dropped
 *          between the calls to lck_rw_gate_try_close() and lck_rw_gate_wait().
 *
 *          KERN_FAILURE in case the gate was already closed. Will panic if the current thread was already the holder of the gate.
 *          lck_rw_gate_wait() should be called instead if the intent is to unconditionally wait on this gate.
 *          The calls to lck_rw_gate_try_close() and lck_rw_gate_wait() should
 *          be done without dropping the lock that is protecting the gate in between.
 */
int
lck_rw_gate_try_close(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	return gate_try_close(gate);
}

/*
 * Name: lck_rw_gate_close
 *
 * Description: Closes the gate. The current thread will be set as
 *              the holder of the gate. Will panic if the gate is already closed.
 *              A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be open.
 *
 */
void
lck_rw_gate_close(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	return gate_close(gate);
}

/*
 * Name: lck_rw_gate_open
 *
 * Description: Opens the gate and wakes up possible waiters.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 */
void
lck_rw_gate_open(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	gate_open(gate);
}

/*
 * Name: lck_rw_gate_handoff
 *
 * Description: Tries to transfer the ownership of the gate. The waiter with highest sched
 *              priority will be selected as the new holder of the gate, and woken up,
 *              with the gate remaining in the closed state throughout.
 *              If no waiters are present, the gate will be kept closed and KERN_NOT_WAITING
 *              will be returned.
 *              GATE_HANDOFF_OPEN_IF_NO_WAITERS flag can be used to specify if the gate should be opened in
 *              case no waiters were found.
 *
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: flags - GATE_HANDOFF_DEFAULT or GATE_HANDOFF_OPEN_IF_NO_WAITERS
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 * Returns:
 *          KERN_SUCCESS in case one of the waiters became the new holder.
 *          KERN_NOT_WAITING in case there were no waiters.
 *
 */
kern_return_t
lck_rw_gate_handoff(__assert_only lck_rw_t *lock, gate_t *gate, gate_handoff_flags_t flags)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	return gate_handoff(gate, flags);
}

/*
 * Name: lck_rw_gate_steal
 *
 * Description: Set the current ownership of the gate. It sets the current thread as the
 *              new holder of the gate.
 *              A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *              NOTE: the previous holder should not call lck_rw_gate_open() or lck_rw_gate_handoff()
 *              anymore.
 *
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be closed and the current thread must not already be the holder.
 *
 */
void
lck_rw_gate_steal(__assert_only lck_rw_t *lock, gate_t *gate)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	gate_steal(gate);
}

/*
 * Name: lck_rw_gate_wait
 *
 * Description: Waits for the current thread to become the holder of the gate or for the
 *              gate to become open. An interruptible mode and deadline can be specified
 *              to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_SHARED, LCK_SLEEP_EXCLUSIVE, LCK_SLEEP_UNLOCK.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The gate must be closed.
 *
 * Returns: Reason why the thread was woken up.
 *          GATE_HANDOFF - the current thread was handed off the ownership of the gate.
 *                         A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on.
 *                         to wake up possible waiters on the gate before returning to userspace.
 *          GATE_OPENED - the gate was opened by the holder.
 *          GATE_TIMED_OUT - the thread was woken up by a timeout.
 *          GATE_INTERRUPTED - the thread was interrupted while sleeping.
 */
gate_wait_result_t
lck_rw_gate_wait(lck_rw_t *lock, gate_t *gate, lck_sleep_action_t lck_sleep_action, wait_interrupt_t interruptible, uint64_t deadline)
{
	__block lck_rw_type_t lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;

	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{;});
	} else if (!(lck_sleep_action & (LCK_SLEEP_SHARED | LCK_SLEEP_EXCLUSIVE))) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{lck_rw_lock(lock, lck_rw_type);});
	} else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{lck_rw_lock_exclusive(lock);});
	} else {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_rw_type = lck_rw_done(lock);},
		           ^{lck_rw_lock_shared(lock);});
	}
}

/*
 * Name: lck_rw_gate_assert
 *
 * Description: asserts that the gate is in the specified state.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: flags to specified assert type.
 *         GATE_ASSERT_CLOSED - the gate is currently closed
 *         GATE_ASSERT_OPEN - the gate is currently opened
 *         GATE_ASSERT_HELD - the gate is currently closed and the current thread is the holder
 */
void
lck_rw_gate_assert(__assert_only lck_rw_t *lock, gate_t *gate, gate_assert_flags_t flags)
{
	LCK_RW_ASSERT(lock, LCK_RW_ASSERT_HELD);

	gate_assert(gate, flags);
	return;
}

/*
 * Name: lck_mtx_gate_init
 *
 * Description: initializes a variable declared with decl_lck_mtx_gate_data.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 */
void
lck_mtx_gate_init(lck_mtx_t *lock, gate_t *gate)
{
	(void) lock;
	gate_init(gate, GT_INIT_DEFAULT);
}

/*
 * Name: lck_mtx_gate_alloc_init
 *
 * Description: allocates and initializes a gate_t.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *
 * Returns:
 *         gate_t allocated.
 */
gate_t*
lck_mtx_gate_alloc_init(lck_mtx_t *lock)
{
	(void) lock;
	return gate_alloc_init();
}

/*
 * Name: lck_mtx_gate_destroy
 *
 * Description: destroys a variable previously initialized
 *              with lck_mtx_gate_init().
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 */
void
lck_mtx_gate_destroy(lck_mtx_t *lock, gate_t *gate)
{
	(void) lock;
	gate_destroy(gate);
}

/*
 * Name: lck_mtx_gate_free
 *
 * Description: destroys and tries to free a gate previously allocated
 *	        with lck_mtx_gate_alloc_init().
 *              The gate free might be delegated to the last thread returning
 *              from the gate_wait().
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate obtained with lck_rw_gate_alloc_init().
 */
void
lck_mtx_gate_free(lck_mtx_t *lock, gate_t *gate)
{
	(void) lock;
	gate_free(gate);
}

/*
 * Name: lck_mtx_gate_try_close
 *
 * Description: Tries to close the gate.
 *              In case of success the current thread will be set as
 *              the holder of the gate.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *
 * Returns:
 *          KERN_SUCCESS in case the gate was successfully closed. The current thread is the new holder
 *          of the gate.
 *          A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *          to wake up possible waiters on the gate before returning to userspace.
 *          If the intent is to conditionally probe the gate before waiting, the lock must not be dropped
 *          between the calls to lck_mtx_gate_try_close() and lck_mtx_gate_wait().
 *
 *          KERN_FAILURE in case the gate was already closed. Will panic if the current thread was already the holder of the gate.
 *          lck_mtx_gate_wait() should be called instead if the intent is to unconditionally wait on this gate.
 *          The calls to lck_mtx_gate_try_close() and lck_mtx_gate_wait() should
 *          be done without dropping the lock that is protecting the gate in between.
 */
int
lck_mtx_gate_try_close(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	return gate_try_close(gate);
}

/*
 * Name: lck_mtx_gate_close
 *
 * Description: Closes the gate. The current thread will be set as
 *              the holder of the gate. Will panic if the gate is already closed.
 *              A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be open.
 *
 */
void
lck_mtx_gate_close(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	return gate_close(gate);
}

/*
 * Name: lck_mtx_gate_open
 *
 * Description: Opens of the gate and wakes up possible waiters.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 */
void
lck_mtx_gate_open(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	gate_open(gate);
}

/*
 * Name: lck_mtx_gate_handoff
 *
 * Description: Tries to transfer the ownership of the gate. The waiter with highest sched
 *              priority will be selected as the new holder of the gate, and woken up,
 *              with the gate remaining in the closed state throughout.
 *              If no waiters are present, the gate will be kept closed and KERN_NOT_WAITING
 *              will be returned.
 *              GATE_HANDOFF_OPEN_IF_NO_WAITERS flag can be used to specify if the gate should be opened in
 *              case no waiters were found.
 *
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: flags - GATE_HANDOFF_DEFAULT or GATE_HANDOFF_OPEN_IF_NO_WAITERS
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 * Returns:
 *          KERN_SUCCESS in case one of the waiters became the new holder.
 *          KERN_NOT_WAITING in case there were no waiters.
 *
 */
kern_return_t
lck_mtx_gate_handoff(__assert_only lck_mtx_t *lock, gate_t *gate, gate_handoff_flags_t flags)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	return gate_handoff(gate, flags);
}

/*
 * Name: lck_mtx_gate_steal
 *
 * Description: Steals the ownership of the gate. It sets the current thread as the
 *              new holder of the gate.
 *              A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *              NOTE: the previous holder should not call lck_mtx_gate_open() or lck_mtx_gate_handoff()
 *              anymore.
 *
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be closed and the current thread must not already be the holder.
 *
 */
void
lck_mtx_gate_steal(__assert_only lck_mtx_t *lock, gate_t *gate)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	gate_steal(gate);
}

/*
 * Name: lck_mtx_gate_wait
 *
 * Description: Waits for the current thread to become the holder of the gate or for the
 *              gate to become open. An interruptible mode and deadline can be specified
 *              to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK, LCK_SLEEP_SPIN, LCK_SLEEP_SPIN_ALWAYS.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The gate must be closed.
 *
 * Returns: Reason why the thread was woken up.
 *          GATE_HANDOFF - the current thread was handed off the ownership of the gate.
 *                         A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *                         to wake up possible waiters on the gate before returning to userspace.
 *          GATE_OPENED - the gate was opened by the holder.
 *          GATE_TIMED_OUT - the thread was woken up by a timeout.
 *          GATE_INTERRUPTED - the thread was interrupted while sleeping.
 */
gate_wait_result_t
lck_mtx_gate_wait(lck_mtx_t *lock, gate_t *gate, lck_sleep_action_t lck_sleep_action, wait_interrupt_t interruptible, uint64_t deadline)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{;});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{lck_mtx_lock_spin(lock);});
	} else if (lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS) {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{lck_mtx_lock_spin_always(lock);});
	} else {
		return gate_wait(gate,
		           interruptible,
		           deadline,
		           ^{lck_mtx_unlock(lock);},
		           ^{lck_mtx_lock(lock);});
	}
}

/*
 * Name: lck_mtx_gate_assert
 *
 * Description: asserts that the gate is in the specified state.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: flags to specified assert type.
 *         GATE_ASSERT_CLOSED - the gate is currently closed
 *         GATE_ASSERT_OPEN - the gate is currently opened
 *         GATE_ASSERT_HELD - the gate is currently closed and the current thread is the holder
 */
void
lck_mtx_gate_assert(__assert_only lck_mtx_t *lock, gate_t *gate, gate_assert_flags_t flags)
{
	LCK_MTX_ASSERT(lock, LCK_MTX_ASSERT_OWNED);

	gate_assert(gate, flags);
}

#pragma mark - LCK_*_DECLARE support

__startup_func
void
lck_grp_attr_startup_init(struct lck_grp_attr_startup_spec *sp)
{
	lck_grp_attr_t *attr = sp->grp_attr;
	lck_grp_attr_setdefault(attr);
	attr->grp_attr_val |= sp->grp_attr_set_flags;
	attr->grp_attr_val &= ~sp->grp_attr_clear_flags;
}

__startup_func
void
lck_grp_startup_init(struct lck_grp_startup_spec *sp)
{
	lck_grp_init(sp->grp, sp->grp_name, sp->grp_attr);
}

__startup_func
void
lck_attr_startup_init(struct lck_attr_startup_spec *sp)
{
	lck_attr_t *attr = sp->lck_attr;
	lck_attr_setdefault(attr);
	attr->lck_attr_val |= sp->lck_attr_set_flags;
	attr->lck_attr_val &= ~sp->lck_attr_clear_flags;
}

__startup_func
void
lck_spin_startup_init(struct lck_spin_startup_spec *sp)
{
	lck_spin_init(sp->lck, sp->lck_grp, sp->lck_attr);
}

__startup_func
void
lck_mtx_startup_init(struct lck_mtx_startup_spec *sp)
{
	if (sp->lck_ext) {
		lck_mtx_init_ext(sp->lck, sp->lck_ext, sp->lck_grp, sp->lck_attr);
	} else {
		lck_mtx_init(sp->lck, sp->lck_grp, sp->lck_attr);
	}
}

__startup_func
void
lck_rw_startup_init(struct lck_rw_startup_spec *sp)
{
	lck_rw_init(sp->lck, sp->lck_grp, sp->lck_attr);
}

__startup_func
void
usimple_lock_startup_init(struct usimple_lock_startup_spec *sp)
{
	simple_lock_init(sp->lck, sp->lck_init_arg);
}
