/*
 * Copyright (c) 2018-2021 Apple Computer, Inc. All rights reserved.
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
#ifndef _KERN_LOCK_GROUP_H
#define _KERN_LOCK_GROUP_H

#include <kern/queue.h>
#include <kern/lock_types.h>
#if XNU_KERNEL_PRIVATE
#include <kern/startup.h>
#include <os/refcnt.h>
#endif /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS

/*!
 * @typedef lck_grp_t
 *
 * @abstract
 * The opaque type of a lock group.
 *
 * @discussion
 * A lock group is used to denote a set of locks that serve
 * a similar purpose, and hold an equivalent "rank" in the lock hierarchy.
 *
 * This structure can then provide some statistics and anchor checks
 * in development kernels for an entire family of locks.
 */
typedef struct _lck_grp_        lck_grp_t;
#define LCK_GRP_NULL            ((lck_grp_t *)NULL)

/*!
 * @typedef lck_grp_attr_t
 *
 * @abstract
 * The opaque type for attributes to a group.
 *
 * @discussion
 * A lock group attribute is meant to configure
 * a group, as a group configuration becomes
 * immutable once made.
 */
typedef struct _lck_grp_attr_   lck_grp_attr_t;
#define LCK_GRP_ATTR_NULL       ((lck_grp_attr_t *)NULL)

extern lck_grp_attr_t  *lck_grp_attr_alloc_init(
	void);

extern void             lck_grp_attr_setdefault(
	lck_grp_attr_t         *attr);

extern void             lck_grp_attr_setstat(
	lck_grp_attr_t         *attr);

extern void             lck_grp_attr_free(
	lck_grp_attr_t         *attr);

extern lck_grp_t       *lck_grp_alloc_init(
	const char             *grp_name,
	lck_grp_attr_t         *attr);

extern void             lck_grp_free(
	lck_grp_t              *grp);

#if XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)

/*
 * Arguments wrapped in LCK_GRP_ARG() will be elided
 * when LOCK_STATS is not set.
 *
 * Arguments wrapped with LCK_GRP_PROBEARG() will be
 * NULL when LOCK_STATS is not set
 */
#if LOCK_STATS
#if !CONFIG_DTRACE
#error invalid configuration: LOCK_STATS needs dtrace
#endif
#define LCK_GRP_ARG(expr)       , expr
#define LCK_GRP_PROBEARG(grp)   grp
#define LCK_GRP_USE_ARG         1
#else
#define LCK_GRP_ARG(expr)
#define LCK_GRP_PROBEARG(grp)   LCK_GRP_NULL
#define LCK_GRP_USE_ARG         0
#endif /* LOCK_STATS */

__enum_decl(lck_debug_feature_t, uint32_t, {
	LCK_DEBUG_LOCKSTAT,
	LCK_DEBUG_LOCKPROF,

	LCK_DEBUG_MAX,
});

extern uint32_t LcksOpts;

extern struct lck_debug_state {
	uint32_t                lds_value;
	long                    lds_counts[LCK_DEBUG_MAX];
} lck_debug_state;

__options_decl(lck_grp_options_t, uint32_t, {
	LCK_GRP_ATTR_NONE       = 0x00000000,

#if MACH_KERNEL_PRIVATE
	LCK_GRP_ATTR_ID_MASK    = 0x0000ffff,
	LCK_GRP_ATTR_STAT       = 0x00010000, /* enable non time stats         */
	LCK_GRP_ATTR_TIME_STAT  = 0x00020000, /* enable time stats             */
	LCK_GRP_ATTR_DEBUG      = 0x00040000, /* profile locks of this group   */
	LCK_GRP_ATTR_ALLOCATED  = 0x80000000,
#endif
});

#if CONFIG_DTRACE
typedef struct _lck_grp_stat_ {
	uint64_t lgs_count;
	uint32_t lgs_enablings;
	/*
	 * Protected by dtrace_lock
	 */
	uint32_t lgs_probeid;
	uint64_t lgs_limit;
} lck_grp_stat_t;

typedef struct _lck_grp_stats_ {
	lck_grp_stat_t          lgss_spin_held;
	lck_grp_stat_t          lgss_spin_miss;
	lck_grp_stat_t          lgss_spin_spin;

	lck_grp_stat_t          lgss_ticket_held;
	lck_grp_stat_t          lgss_ticket_miss;
	lck_grp_stat_t          lgss_ticket_spin;

	lck_grp_stat_t          lgss_mtx_held;
	lck_grp_stat_t          lgss_mtx_direct_wait;
	lck_grp_stat_t          lgss_mtx_miss;
	lck_grp_stat_t          lgss_mtx_wait;
} lck_grp_stats_t;
#endif /* CONFIG_DTRACE */

#define LCK_GRP_MAX_NAME        64

struct _lck_grp_ {
	os_ref_atomic_t         lck_grp_refcnt;
	uint32_t                lck_grp_attr_id;
	uint32_t                lck_grp_spincnt;
	uint32_t                lck_grp_ticketcnt;
	uint32_t                lck_grp_mtxcnt;
	uint32_t                lck_grp_rwcnt;
	char                    lck_grp_name[LCK_GRP_MAX_NAME];
#if CONFIG_DTRACE
	lck_grp_stats_t         lck_grp_stats;
#endif /* CONFIG_DTRACE */
};

struct _lck_grp_attr_ {
	lck_grp_options_t       grp_attr_val;
};

struct lck_grp_spec {
	lck_grp_t              *grp;
	char                    grp_name[LCK_GRP_MAX_NAME];
	lck_grp_options_t       grp_flags;
};

/*
 * Auto-initializing lock group declarations
 * -----------------------------------------
 *
 * Use LCK_GRP_DECLARE to declare an automatically initialized group.
 */
#define LCK_GRP_DECLARE_ATTR(var, name, flags) \
	__PLACE_IN_SECTION("__DATA,__lock_grp") lck_grp_t var; \
	static __startup_data struct lck_grp_spec \
	__startup_lck_grp_spec_ ## var = { &var, name, flags }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_SECOND, lck_grp_startup_init, \
	    &__startup_lck_grp_spec_ ## var)

#define LCK_GRP_DECLARE(var, name) \
	LCK_GRP_DECLARE_ATTR(var, name, LCK_GRP_ATTR_NONE);

extern bool             lck_grp_has_stats(
	lck_grp_t              *grp);

extern void             lck_grp_startup_init(
	struct lck_grp_spec    *spec);

extern void             lck_grp_init(
	lck_grp_t              *grp,
	const char*             grp_name,
	lck_grp_attr_t         *attr);

extern lck_grp_t       *lck_grp_init_flags(
	lck_grp_t              *grp,
	const char*             grp_name,
	lck_grp_options_t       grp_flags);

extern lck_grp_t       *lck_grp_resolve(
	uint32_t                grp_attr_id) __pure2;

extern void             lck_grp_assert_id(
	lck_grp_t              *grp,
	uint32_t                grp_attr_id);
#if DEBUG || DEVELOPMENT
#define LCK_GRP_ASSERT_ID(...)  lck_grp_assert_id(__VA_ARGS__)
#else
#define LCK_GRP_ASSERT_ID(...)  ((void)0)
#endif

extern void             lck_grp_reference(
	lck_grp_t              *grp,
	uint32_t               *cnt);

extern void             lck_grp_deallocate(
	lck_grp_t              *grp,
	uint32_t               *cnt);

extern void             lck_grp_foreach(
	bool                  (^block)(lck_grp_t *));


extern void             lck_grp_enable_feature(
	lck_debug_feature_t     feat);

extern void             lck_grp_disable_feature(
	lck_debug_feature_t     feat);

__pure2
static inline uint32_t
lck_opts_get(void)
{
	return LcksOpts;
}

#pragma GCC visibility pop


#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_GROUP_H */
