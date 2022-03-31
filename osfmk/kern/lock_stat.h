/*
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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
#ifndef _KERN_LOCKSTAT_H
#define _KERN_LOCKSTAT_H

#include <machine/locks.h>
#include <machine/atomic.h>
#include <kern/lock_group.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

/*
 * DTrace lockstat probe definitions
 *
 */

enum lockstat_probe_id {
	/* Spinlocks */
	LS_LCK_SPIN_LOCK_ACQUIRE,
	LS_LCK_SPIN_LOCK_SPIN,
	LS_LCK_SPIN_UNLOCK_RELEASE,

	/*
	 * Mutexes can also have interlock-spin events, which are
	 * unique to our lock implementation.
	 */
	LS_LCK_MTX_LOCK_ACQUIRE,
	LS_LCK_MTX_LOCK_BLOCK,
	LS_LCK_MTX_LOCK_ADAPTIVE_SPIN,
	LS_LCK_MTX_LOCK_SPIN_SPIN,
	LS_LCK_MTX_LOCK_SPIN_ACQUIRE,
	LS_LCK_MTX_LOCK_ILK_SPIN,
	LS_LCK_MTX_TRY_LOCK_ACQUIRE,
	LS_LCK_MTX_TRY_LOCK_SPIN_ACQUIRE,
	LS_LCK_MTX_UNLOCK_RELEASE,

	/*
	 * Provide a parallel set for indirect mutexes
	 */
	LS_LCK_MTX_EXT_LOCK_ACQUIRE,
	LS_LCK_MTX_EXT_LOCK_BLOCK,
	LS_LCK_MTX_EXT_LOCK_SPIN_SPIN,
	LS_LCK_MTX_EXT_LOCK_ADAPTIVE_SPIN,
	LS_LCK_MTX_EXT_LOCK_ILK_SPIN,
	LS_LCK_MTX_EXT_UNLOCK_RELEASE,

	/*
	 * Reader-writer locks support a blocking upgrade primitive, as
	 * well as the possibility of spinning on the interlock.
	 */
	LS_LCK_RW_LOCK_SHARED_ACQUIRE,
	LS_LCK_RW_LOCK_SHARED_BLOCK,
	LS_LCK_RW_LOCK_SHARED_SPIN,

	LS_LCK_RW_LOCK_EXCL_ACQUIRE,
	LS_LCK_RW_LOCK_EXCL_BLOCK,
	LS_LCK_RW_LOCK_EXCL_SPIN,

	LS_LCK_RW_DONE_RELEASE,

	LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE,
	LS_LCK_RW_TRY_LOCK_SHARED_SPIN,

	LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE,
	LS_LCK_RW_TRY_LOCK_EXCL_ILK_SPIN,

	LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE,
	LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN,
	LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK,

	LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE,
	LS_LCK_RW_LOCK_EXCL_TO_SHARED_ILK_SPIN,

	/* Ticket lock */
	LS_LCK_TICKET_LOCK_ACQUIRE,
	LS_LCK_TICKET_LOCK_RELEASE,
	LS_LCK_TICKET_LOCK_SPIN,

	LS_NPROBES
};

#if XNU_KERNEL_PRIVATE

extern void lck_grp_stat_enable(lck_grp_stat_t *stat);

extern void lck_grp_stat_disable(lck_grp_stat_t *stat);

extern bool lck_grp_stat_enabled(lck_grp_stat_t *stat);

#if CONFIG_DTRACE
/*
 * Time threshold before dtrace lockstat spin
 * probes are triggered
 */
extern machine_timeout32_t dtrace_spin_threshold;
extern uint32_t lockstat_probemap[LS_NPROBES];

extern void dtrace_probe(uint32_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t);
extern void lockprof_invoke(lck_grp_t*, lck_grp_stat_t*, uint64_t);

/*
 * Macros to record lockstat probes.
 */
#define LOCKSTAT_RECORD4(probe, lp, arg0, arg1, arg2, arg3)             \
	{                                                                   \
	        uint32_t id;                                                \
	        if (__improbable(id = lockstat_probemap[(probe)])) {        \
	                dtrace_probe(id, (uintptr_t)(lp), (arg0),           \
	                    (arg1), (arg2), (arg3));                        \
	        }                                                           \
	}
#define LOCKSTAT_RECORD_(probe, lp, arg0, arg1, arg2, arg3, ...) LOCKSTAT_RECORD4(probe, lp, arg0, arg1, arg2, arg3)
#define LOCKSTAT_RECORD__(probe, lp, arg0, arg1, arg2, arg3, ...) LOCKSTAT_RECORD_(probe, lp, arg0, arg1, arg2, arg3)
#define LOCKSTAT_RECORD(probe, lp, ...) LOCKSTAT_RECORD__(probe, lp, ##__VA_ARGS__, 0, 0, 0, 0)

#endif /* CONFIG_DTRACE */
#endif /* XNU_KERNEL_PRIVATE */
#if MACH_KERNEL_PRIVATE

#if LOCK_STATS
extern void __lck_grp_spin_update_held(lck_grp_t *grp);
extern void __lck_grp_spin_update_miss(lck_grp_t *grp);
extern void __lck_grp_spin_update_spin(lck_grp_t *grp, uint64_t time);
extern void __lck_grp_ticket_update_held(lck_grp_t *grp);
extern void __lck_grp_ticket_update_miss(lck_grp_t *grp);
extern void __lck_grp_ticket_update_spin(lck_grp_t *grp, uint64_t time);
#define LOCK_STATS_CALL(fn, ...)  fn(__VA_ARGS__)
#else
#define LOCK_STATS_CALL(fn, ...) ((void)0)
#endif

static inline void
lck_grp_spin_update_held(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, lock, (uintptr_t)LCK_GRP_PROBEARG(grp));
#endif
	LOCK_STATS_CALL(__lck_grp_spin_update_held, grp);
}

static inline void
lck_grp_spin_update_miss(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
	LOCK_STATS_CALL(__lck_grp_spin_update_miss, grp);
}

static inline void
lck_grp_spin_update_spin(void *lock LCK_GRP_ARG(lck_grp_t *grp), uint64_t time)
{
#pragma unused(lock, time)
#if CONFIG_DTRACE
	if (time > os_atomic_load(&dtrace_spin_threshold, relaxed)) {
		LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_SPIN, lock, time LCK_GRP_ARG((uintptr_t)grp));
	}
#endif /* CONFIG_DTRACE */
	LOCK_STATS_CALL(__lck_grp_spin_update_spin, grp, time);
}

static inline bool
lck_grp_spin_spin_enabled(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
	bool enabled = false;
#if CONFIG_DTRACE
	enabled |= lockstat_probemap[LS_LCK_SPIN_LOCK_SPIN] != 0;
#endif /* CONFIG_DTRACE */
#if LOCK_STATS
	enabled |= (grp && lck_grp_stat_enabled(&grp->lck_grp_stats.lgss_spin_spin));
#endif /* LOCK_STATS */
	return enabled;
}

static inline void
lck_grp_ticket_update_held(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_TICKET_LOCK_ACQUIRE, lock, (uintptr_t)LCK_GRP_PROBEARG(grp));
#endif
	LOCK_STATS_CALL(__lck_grp_ticket_update_held, grp);
}

static inline void
lck_grp_ticket_update_miss(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
	LOCK_STATS_CALL(__lck_grp_ticket_update_miss, grp);
}

static inline bool
lck_grp_ticket_spin_enabled(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
	bool enabled = false;
#if CONFIG_DTRACE
	enabled |= lockstat_probemap[LS_LCK_TICKET_LOCK_SPIN] != 0;
#endif /* CONFIG_DTRACE */
#if LOCK_STATS
	enabled |= (grp && lck_grp_stat_enabled(&grp->lck_grp_stats.lgss_ticket_spin));
#endif /* LOCK_STATS */
	return enabled;
}

static inline void
lck_grp_ticket_update_spin(void *lock LCK_GRP_ARG(lck_grp_t *grp), uint64_t time)
{
#pragma unused(lock, time)
#if CONFIG_DTRACE
	if (time > os_atomic_load(&dtrace_spin_threshold, relaxed)) {
		LOCKSTAT_RECORD(LS_LCK_TICKET_LOCK_SPIN, lock, time LCK_GRP_ARG((uintptr_t)grp));
	}
#endif /* CONFIG_DTRACE */
	LOCK_STATS_CALL(__lck_grp_ticket_update_spin, grp, time);
}

#if __x86_64__
/*
 * N.B.: On x86, statistics are currently recorded for all indirect mutexes.
 * Also, only the acquire attempt count (GRP_MTX_STAT_UTIL) is maintained
 * as a 64-bit quantity (the new x86 specific statistics are also maintained
 * as 32-bit quantities).
 *
 * Enable this preprocessor define to record the first miss alone
 * By default, we count every miss, hence multiple misses may be
 * recorded for a single lock acquire attempt via lck_mtx_lock
 */
#undef LOG_FIRST_MISS_ALONE

extern void __lck_grp_mtx_update_miss(lck_grp_t *grp);
extern void __lck_grp_mtx_update_direct_wait(lck_grp_t *grp);
extern void __lck_grp_mtx_update_wait(lck_grp_t *grp);
extern void __lck_grp_mtx_update_held(lck_grp_t *grp);

static inline void
lck_grp_mtx_update_miss(struct _lck_mtx_ext_ *lock, int *first_miss)
{
#pragma unused(first_miss)
#if LOG_FIRST_MISS_ALONE
	if (*first_miss & 1) {
		return;
	}
	*first_miss |= 1;
#endif /* LOG_FIRST_MISS_ALONE */
	__lck_grp_mtx_update_miss(lock->lck_mtx_grp);
}

static void inline
lck_grp_mtx_update_direct_wait(struct _lck_mtx_ext_ *lock)
{
	__lck_grp_mtx_update_direct_wait(lock->lck_mtx_grp);
}

static void inline
lck_grp_mtx_update_wait(struct _lck_mtx_ext_ *lock, int *first_miss)
{
#pragma unused(first_miss)
#if LOG_FIRST_MISS_ALONE
	if (*first_miss & 2) {
		return;
	}
	*first_miss |= 2;
#endif /* LOG_FIRST_MISS_ALONE */
	__lck_grp_mtx_update_wait(lock->lck_mtx_grp);
}

static void inline
lck_grp_mtx_update_held(struct _lck_mtx_ext_ *lock)
{
	__lck_grp_mtx_update_held(lock->lck_mtx_grp);
}

#endif /* __x86_64__ */
#endif /* MACH_KERNEL_PRIVATE */

#pragma GCC visibility pop
__END_DECLS

#endif /* _KERN_LOCKSTAT_H */
