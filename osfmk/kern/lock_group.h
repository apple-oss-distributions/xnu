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
 */
typedef struct _lck_grp_        lck_grp_t;
#define LCK_GRP_NULL            ((lck_grp_t *)NULL)

/*!
 * @typedef lck_grp_attr_t
 *
 * @abstract
 * The opaque type for attributes to a group.
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
#define LCK_GRP_ARG(expr)       , expr
#define LCK_GRP_PROBEARG(grp)   grp
#else
#define LCK_GRP_ARG(expr)
#define LCK_GRP_PROBEARG(grp)   LCK_GRP_NULL
#endif /* LOCK_STATS */

extern uint32_t LcksOpts;

__options_decl(lck_grp_options_t, uint32_t, {
	LCK_GRP_ATTR_NONE       = 0x00000000,

#if MACH_KERNEL_PRIVATE
	LCK_GRP_ATTR_STAT       = 0x00000001,
	LCK_GRP_ATTR_TIME_STAT  = 0x00000002,
	LCK_GRP_ATTR_ALLOCATED  = 0x00000004,
#endif
});

typedef struct _lck_grp_stat_ {
	uint64_t lgs_count;
	uint32_t lgs_enablings;
#if CONFIG_DTRACE
	/*
	 * Protected by dtrace_lock
	 */
	uint32_t lgs_probeid;
	uint64_t lgs_limit;
#endif /* CONFIG_DTRACE */
} lck_grp_stat_t;

typedef struct _lck_grp_stats_ {
#if LOCK_STATS
	lck_grp_stat_t          lgss_spin_held;
	lck_grp_stat_t          lgss_spin_miss;
	lck_grp_stat_t          lgss_spin_spin;
	lck_grp_stat_t          lgss_ticket_held;
	lck_grp_stat_t          lgss_ticket_miss;
	lck_grp_stat_t          lgss_ticket_spin;
#endif /* LOCK_STATS */

	lck_grp_stat_t          lgss_mtx_held;
	lck_grp_stat_t          lgss_mtx_direct_wait;
	lck_grp_stat_t          lgss_mtx_miss;
	lck_grp_stat_t          lgss_mtx_wait;
} lck_grp_stats_t;

#define LCK_GRP_MAX_NAME        64

typedef struct _lck_grp_ {
	queue_chain_t           lck_grp_link;
	os_refcnt_t             lck_grp_refcnt;
	uint32_t                lck_grp_spincnt;
	uint32_t                lck_grp_ticketcnt;
	uint32_t                lck_grp_mtxcnt;
	uint32_t                lck_grp_rwcnt;
	lck_grp_options_t       lck_grp_attr;
	char                    lck_grp_name[LCK_GRP_MAX_NAME];
	lck_grp_stats_t         lck_grp_stats;
} lck_grp_t;

typedef struct _lck_grp_attr_ {
	lck_grp_options_t       grp_attr_val;
} lck_grp_attr_t;

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
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_THIRD, lck_grp_startup_init, \
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

extern void             lck_grp_reference(
	lck_grp_t              *grp,
	uint32_t               *cnt);

extern void             lck_grp_deallocate(
	lck_grp_t              *grp,
	uint32_t               *cnt);

extern void             lck_grp_foreach(
	bool                  (^block)(lck_grp_t *));

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_GROUP_H */
