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
#include <kern/lock_mtx.h>

__BEGIN_DECLS
#pragma GCC visibility push(hidden)

#if XNU_KERNEL_PRIVATE

/*
 * DTrace lockstat probe definitions
 *
 */

enum lockstat_probe_id {
	LS_NO_PROBE,

	/* Spinlocks */
	LS_LCK_SPIN_LOCK_ACQUIRE,
	LS_LCK_SPIN_LOCK_SPIN,
	LS_LCK_SPIN_UNLOCK_RELEASE,

	/*
	 * Mutexes can also have interlock-spin events, which are
	 * unique to our lock implementation.
	 */
	LS_LCK_MTX_LOCK_ACQUIRE,
	LS_LCK_MTX_LOCK_SPIN_ACQUIRE,
	LS_LCK_MTX_TRY_LOCK_ACQUIRE,
	LS_LCK_MTX_TRY_LOCK_SPIN_ACQUIRE,
	LS_LCK_MTX_UNLOCK_RELEASE,

	LS_LCK_MTX_LOCK_BLOCK,
	LS_LCK_MTX_LOCK_ADAPTIVE_SPIN,
	LS_LCK_MTX_LOCK_SPIN_SPIN,


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

#if CONFIG_DTRACE
/*
 * Time threshold before dtrace lockstat spin
 * probes are triggered
 */
extern machine_timeout_t dtrace_spin_threshold;
extern uint32_t lockstat_probemap[LS_NPROBES];

extern void lck_grp_stat_enable(lck_grp_stat_t *stat);

extern void lck_grp_stat_disable(lck_grp_stat_t *stat);

extern bool lck_grp_stat_enabled(lck_grp_stat_t *stat);

extern void lck_grp_stat_inc(lck_grp_t *grp, lck_grp_stat_t *stat, bool always);

#endif /* CONFIG_DTRACE */
#endif /* XNU_KERNEL_PRIVATE */
#if MACH_KERNEL_PRIVATE
#if CONFIG_DTRACE

extern void dtrace_probe(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static inline void
lockprof_probe(lck_grp_t *grp, lck_grp_stat_t *stat, uint64_t val)
{
	dtrace_probe(stat->lgs_probeid, (uintptr_t)grp, val, 0, 0, 0);
}

__attribute__((always_inline))
static inline void
lockstat_probe(
	enum lockstat_probe_id  pid,
	const void             *lock,
	uint64_t                arg0,
	uint64_t                arg1,
	uint64_t                arg2,
	uint64_t                arg3)
{
	uint32_t id = lockstat_probemap[pid];

	if (__improbable(id)) {
		dtrace_probe(id, (uintptr_t)lock, arg0, arg1, arg2, arg3);
	}
}

__pure2
static inline uint32_t
lockstat_enabled(void)
{
	return lck_debug_state.lds_value;
}

/*
 * Macros to record lockstat probes.
 */
#define LOCKSTAT_RECORD_(probe, lp, arg0, arg1, arg2, arg3, ...) \
	lockstat_probe(probe, lp, arg0, arg1, arg2, arg3)
#define LOCKSTAT_RECORD__(probe, lp, arg0, arg1, arg2, arg3, ...) \
	LOCKSTAT_RECORD_(probe, lp, arg0, arg1, arg2, arg3)
#define LOCKSTAT_RECORD(probe, lp, ...) \
	LOCKSTAT_RECORD__(probe, lp, ##__VA_ARGS__, 0, 0, 0, 0)

__attribute__((always_inline, overloadable))
static inline bool
__lck_time_stat_enabled(enum lockstat_probe_id lspid, uint32_t grp_attr_id)
{
	if (__improbable(grp_attr_id & LCK_GRP_ATTR_TIME_STAT)) {
		return true;
	}
	if (__improbable(lspid && lockstat_probemap[lspid])) {
		return true;
	}
	return false;
}

__attribute__((always_inline, overloadable))
static inline bool
__lck_time_stat_enabled(enum lockstat_probe_id lspid, lck_grp_t *grp)
{
	uint32_t grp_attr_id = grp ? grp->lck_grp_attr_id : 0;

	return __lck_time_stat_enabled(lspid, grp_attr_id);
}

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

static inline enum lockstat_probe_id
lck_mtx_acquire_probe(bool spin, bool try_lock)
{
	if (spin) {
		if (try_lock) {
			return LS_LCK_MTX_TRY_LOCK_SPIN_ACQUIRE;
		}
		return LS_LCK_MTX_LOCK_SPIN_ACQUIRE;
	} else {
		if (try_lock) {
			return LS_LCK_MTX_TRY_LOCK_ACQUIRE;
		}
		return LS_LCK_MTX_LOCK_ACQUIRE;
	}
}

__attribute__((cold))
__header_always_inline void
lck_mtx_prof_probe(
	enum lockstat_probe_id  id,
	lck_mtx_t              *mtx,
	uint32_t                grp_attr_id,
	bool                    profile)
{
#pragma unused(mtx)
	if (profile) {
		lck_grp_t *grp = LCK_GRP_NULL;

		switch (id) {
		case LS_LCK_MTX_LOCK_ACQUIRE:
		case LS_LCK_MTX_LOCK_SPIN_ACQUIRE:
		case LS_LCK_MTX_TRY_LOCK_ACQUIRE:
		case LS_LCK_MTX_TRY_LOCK_SPIN_ACQUIRE:
			grp = lck_grp_resolve(grp_attr_id);
			__builtin_assume(grp != NULL);
			lck_grp_stat_inc(grp, &grp->lck_grp_stats.lgss_mtx_held, true);
			break;
		default:
			break;
		}
	}
	LOCKSTAT_RECORD(id, mtx, (uintptr_t)lck_grp_resolve(grp_attr_id));
}

#define lck_mtx_time_stat_begin(id) ({ \
	uint64_t __start = 0;                                                   \
	if (__lck_time_stat_enabled(id, LCK_GRP_NULL)) {                        \
	        __start = ml_get_timebase();                                    \
	        __builtin_assume(__start != 0);                                 \
	}                                                                       \
	__start;                                                                \
})

extern void lck_mtx_time_stat_record(
	enum lockstat_probe_id  id,
	lck_mtx_t              *mtx,
	uint32_t                grp_attr_id,
	uint64_t                start);

/*
 * Enable this preprocessor define to record the first miss alone
 * By default, we count every miss, hence multiple misses may be
 * recorded for a single lock acquire attempt via lck_mtx_lock
 */
#define LCK_MTX_LOCK_FIRST_MISS_ONLY 0

static inline void
LCK_MTX_PROF_MISS(lck_mtx_t *mtx, uint32_t grp_attr_id, int *first_miss)
{
	lck_grp_t *grp = lck_grp_resolve(grp_attr_id);

#pragma unused(mtx, grp, first_miss)
#if LCK_MTX_LOCK_FIRST_MISS_ONLY
	if (*first_miss & 1) {
		return;
	}
	*first_miss |= 1;
#endif /* LCK_MTX_LOCK_FIRST_MISS_ONLY */
	lck_grp_stat_inc(grp, &grp->lck_grp_stats.lgss_mtx_miss, true);
}

static void inline
LCK_MTX_PROF_WAIT(
	lck_mtx_t              *mtx,
	uint32_t                grp_attr_id,
	bool                    direct_wait,
	int                    *first_miss)
{
	lck_grp_t *grp = lck_grp_resolve(grp_attr_id);

#pragma unused(mtx, first_miss)
#if LCK_MTX_LOCK_FIRST_MISS_ONLY
	if (*first_miss & 2) {
		return;
	}
	*first_miss |= 2;
#endif /* LCK_MTX_LOCK_FIRST_MISS_ONLY */
	if (direct_wait) {
		lck_grp_stat_inc(grp, &grp->lck_grp_stats.lgss_mtx_direct_wait, true);
	} else {
		lck_grp_stat_inc(grp, &grp->lck_grp_stats.lgss_mtx_wait, true);
	}
}

#else /* !CONFIG_DTRACE */

#define lockstat_enabled(probe, lock, ...)                      0u
#define LOCKSTAT_RECORD(probe, lock, ...)                       ((void)0)

#define __lck_time_stat_enabled(lspid, grp)                     false
#define lck_mtx_prof_probe(id, mtx, grp, profile)               ((void)0)
#define lck_mtx_time_stat_begin(id)                             0ull
#define lck_mtx_time_stat_record(id, lck, grp, start)           ((void)(start))

#endif /* !CONFIG_DTRACE */

static inline void
lck_grp_spin_update_held(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, lock, (uintptr_t)LCK_GRP_PROBEARG(grp));
	LOCK_STATS_CALL(__lck_grp_spin_update_held, grp);
#endif /* CONFIG_DTRACE */
}

static inline void
lck_grp_spin_update_miss(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
#if CONFIG_DTRACE
	LOCK_STATS_CALL(__lck_grp_spin_update_miss, grp);
#endif /* CONFIG_DTRACE */
}

static inline void
lck_grp_spin_update_spin(void *lock LCK_GRP_ARG(lck_grp_t *grp), uint64_t time)
{
#pragma unused(lock, time)
#if CONFIG_DTRACE
	if (time > os_atomic_load(&dtrace_spin_threshold, relaxed)) {
		LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_SPIN, lock, time LCK_GRP_ARG((uintptr_t)grp));
	}
	LOCK_STATS_CALL(__lck_grp_spin_update_spin, grp, time);
#endif /* CONFIG_DTRACE */
}

static inline bool
lck_grp_spin_spin_enabled(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
	bool enabled = __lck_time_stat_enabled(LS_LCK_SPIN_LOCK_SPIN, LCK_GRP_PROBEARG(grp));
#if CONFIG_DTRACE && LOCK_STATS
	enabled |= (grp && lck_grp_stat_enabled(&grp->lck_grp_stats.lgss_spin_spin));
#endif /* CONFIG_DTRACE && LOCK_STATS */
	return enabled;
}

static inline void
lck_grp_ticket_update_held(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_TICKET_LOCK_ACQUIRE, lock, (uintptr_t)LCK_GRP_PROBEARG(grp));
	LOCK_STATS_CALL(__lck_grp_ticket_update_held, grp);
#endif /* CONFIG_DTRACE */
}

static inline void
lck_grp_ticket_update_miss(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
#if CONFIG_DTRACE
	LOCK_STATS_CALL(__lck_grp_ticket_update_miss, grp);
#endif /* CONFIG_DTRACE */
}

static inline bool
lck_grp_ticket_spin_enabled(void *lock LCK_GRP_ARG(lck_grp_t *grp))
{
#pragma unused(lock)
	bool enabled = __lck_time_stat_enabled(LS_LCK_TICKET_LOCK_SPIN, LCK_GRP_PROBEARG(grp));
#if CONFIG_DTRACE && LOCK_STATS
	enabled |= (grp && lck_grp_stat_enabled(&grp->lck_grp_stats.lgss_ticket_spin));
#endif /* CONFIG_DTRACE && LOCK_STATS */
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
	LOCK_STATS_CALL(__lck_grp_ticket_update_spin, grp, time);
#endif /* CONFIG_DTRACE */
}

/*
 * Mutexes
 */
#define LCK_MTX_ACQUIRED(mtx, grp, spin, profile) \
	lck_mtx_prof_probe(lck_mtx_acquire_probe(spin, false), mtx, grp, profile)

#define LCK_MTX_TRY_ACQUIRED(mtx, grp, spin, profile) \
	lck_mtx_prof_probe(lck_mtx_acquire_probe(spin, true), mtx, grp, profile)

#define LCK_MTX_RELEASED(mtx, grp, profile) \
	lck_mtx_prof_probe(LS_LCK_MTX_UNLOCK_RELEASE, mtx, grp, profile)

#define LCK_MTX_BLOCK_BEGIN() \
	lck_mtx_time_stat_begin(LS_LCK_MTX_LOCK_BLOCK)

#define LCK_MTX_BLOCK_END(mtx, grp, start) \
	lck_mtx_time_stat_record(LS_LCK_MTX_LOCK_BLOCK, mtx, grp, start)

#define LCK_MTX_ADAPTIVE_SPIN_BEGIN() \
	lck_mtx_time_stat_begin(LS_LCK_MTX_LOCK_ADAPTIVE_SPIN)

#define LCK_MTX_ADAPTIVE_SPIN_END(mtx, grp, start) \
	lck_mtx_time_stat_record(LS_LCK_MTX_LOCK_ADAPTIVE_SPIN, mtx, grp, start)

#define LCK_MTX_SPIN_SPIN_BEGIN() \
	lck_mtx_time_stat_begin(LS_LCK_MTX_LOCK_SPIN_SPIN)

#define LCK_MTX_SPIN_SPIN_END(mtx, grp, start) \
	lck_mtx_time_stat_record(LS_LCK_MTX_LOCK_SPIN_SPIN, mtx, grp, start)

#endif /* MACH_KERNEL_PRIVATE */

#pragma GCC visibility pop
__END_DECLS

#endif /* _KERN_LOCKSTAT_H */
