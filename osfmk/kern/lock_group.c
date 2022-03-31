/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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

#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/lock_stat.h>
#include <os/atomic_private.h>

static KALLOC_TYPE_DEFINE(KT_LCK_GRP_ATTR, lck_grp_attr_t, KT_PRIV_ACCT);
static KALLOC_TYPE_DEFINE(KT_LCK_GRP, lck_grp_t, KT_PRIV_ACCT);
static KALLOC_TYPE_DEFINE(KT_LCK_ATTR, lck_attr_t, KT_PRIV_ACCT);

SECURITY_READ_ONLY_LATE(lck_attr_t) LockDefaultLckAttr;
static SECURITY_READ_ONLY_LATE(lck_grp_attr_t) lck_grp_attr_default;
static lck_grp_t lck_grp_compat_grp;
queue_head_t     lck_grp_queue;
unsigned int     lck_grp_cnt;
static LCK_MTX_DECLARE(lck_grp_lock, &lck_grp_compat_grp);

#pragma mark lock group attributes

lck_grp_attr_t  *
lck_grp_attr_alloc_init(void)
{
	lck_grp_attr_t  *attr;

	attr = zalloc(KT_LCK_GRP_ATTR);
	lck_grp_attr_setdefault(attr);
	return attr;
}

void
lck_grp_attr_setdefault(lck_grp_attr_t *attr)
{
	attr->grp_attr_val = lck_grp_attr_default.grp_attr_val;
}

void
lck_grp_attr_setstat(lck_grp_attr_t *attr __unused)
{
	attr->grp_attr_val |= LCK_GRP_ATTR_STAT;
}


void
lck_grp_attr_free(lck_grp_attr_t *attr)
{
	zfree(KT_LCK_GRP_ATTR, attr);
}

#pragma mark lock groups

__startup_func
static void
lck_group_init(void)
{
	queue_init(&lck_grp_queue);

	if (LcksOpts & enaLkStat) {
		lck_grp_attr_default.grp_attr_val |= LCK_GRP_ATTR_STAT;
	}
	if (LcksOpts & enaLkTimeStat) {
		lck_grp_attr_default.grp_attr_val |= LCK_GRP_ATTR_TIME_STAT;
	}

#if __arm__ || __arm64__
	/* <rdar://problem/4404579>: Using LCK_ATTR_DEBUG here causes panic at boot time for arm */
	LcksOpts &= ~enaLkDeb;
#endif
	if (LcksOpts & enaLkDeb) {
		LockDefaultLckAttr.lck_attr_val = LCK_ATTR_DEBUG;
	} else {
		LockDefaultLckAttr.lck_attr_val = LCK_ATTR_NONE;
	}

	lck_grp_init(&lck_grp_compat_grp, "Compatibility APIs",
	    &lck_grp_attr_default);
}
STARTUP(LOCKS_EARLY, STARTUP_RANK_FIRST, lck_group_init);

__startup_func
void
lck_grp_startup_init(struct lck_grp_spec *sp)
{
	lck_grp_init_flags(sp->grp, sp->grp_name, sp->grp_flags |
	    lck_grp_attr_default.grp_attr_val);
}

bool
lck_grp_has_stats(lck_grp_t *grp)
{
	return grp->lck_grp_attr & LCK_GRP_ATTR_STAT;
}

lck_grp_t *
lck_grp_alloc_init(const char *grp_name, lck_grp_attr_t *attr)
{
	lck_grp_t *grp;

	if (attr == LCK_GRP_ATTR_NULL) {
		attr = &lck_grp_attr_default;
	}
	grp = zalloc(KT_LCK_GRP);
	lck_grp_init_flags(grp, grp_name,
	    attr->grp_attr_val | LCK_GRP_ATTR_ALLOCATED);
	return grp;
}

void
lck_grp_init(lck_grp_t *grp, const char *grp_name, lck_grp_attr_t *attr)
{
	if (attr == LCK_GRP_ATTR_NULL) {
		attr = &lck_grp_attr_default;
	}
	lck_grp_init_flags(grp, grp_name, attr->grp_attr_val);
}

lck_grp_t *
lck_grp_init_flags(lck_grp_t *grp, const char *grp_name, lck_grp_options_t flags)
{
	bzero(grp, sizeof(lck_grp_t));

	(void)strlcpy(grp->lck_grp_name, grp_name, LCK_GRP_MAX_NAME);

	grp->lck_grp_attr = flags;

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

	if (startup_phase >= STARTUP_SUB_LOCKS) {
		lck_mtx_lock(&lck_grp_lock);
	}

	enqueue_tail(&lck_grp_queue, &grp->lck_grp_link);
	lck_grp_cnt++;

	if (startup_phase >= STARTUP_SUB_LOCKS) {
		lck_mtx_unlock(&lck_grp_lock);
	}

	return grp;
}

static void
lck_grp_destroy(lck_grp_t *grp)
{
	lck_mtx_lock(&lck_grp_lock);
	lck_grp_cnt--;
	remque(&grp->lck_grp_link);
	lck_mtx_unlock(&lck_grp_lock);
	zfree(KT_LCK_GRP, grp);
}

void
lck_grp_free(lck_grp_t *grp)
{
	lck_grp_deallocate(grp, NULL);
}


void
lck_grp_reference(lck_grp_t *grp, uint32_t *cnt)
{
	if (cnt) {
		os_atomic_inc(cnt, relaxed);
	}
	if (grp->lck_grp_attr & LCK_GRP_ATTR_ALLOCATED) {
		os_ref_retain(&grp->lck_grp_refcnt);
	}
}

void
lck_grp_deallocate(lck_grp_t *grp, uint32_t *cnt)
{
	if (cnt) {
		os_atomic_dec(cnt, relaxed);
	}
	if ((grp->lck_grp_attr & LCK_GRP_ATTR_ALLOCATED) &&
	    os_ref_release(&grp->lck_grp_refcnt) == 0) {
		lck_grp_destroy(grp);
	}
}

static void
lck_grp_foreach_locked(bool (^block)(lck_grp_t *))
{
	lck_grp_t *grp;

	qe_foreach_element(grp, &lck_grp_queue, lck_grp_link) {
		if (!block(grp)) {
			return;
		}
	}
}


void
lck_grp_foreach(bool (^block)(lck_grp_t *))
{
	lck_mtx_lock(&lck_grp_lock);
	lck_grp_foreach_locked(block);
	lck_mtx_unlock(&lck_grp_lock);
}

kern_return_t
host_lockgroup_info(
	host_t                   host,
	lockgroup_info_array_t  *lockgroup_infop,
	mach_msg_type_number_t  *lockgroup_infoCntp)
{
	lockgroup_info_t *info;
	vm_offset_t       addr;
	vm_size_t         size, used;
	vm_size_t         vmsize, vmused;
	uint32_t          needed;
	__block uint32_t  count = 0;
	vm_map_copy_t     copy;
	kern_return_t     kr;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	needed = os_atomic_load(&lck_grp_cnt, relaxed);

	for (;;) {
		size   = needed * sizeof(lockgroup_info_t);
		vmsize = vm_map_round_page(size, VM_MAP_PAGE_MASK(ipc_kernel_map));
		kr     = kernel_memory_allocate(ipc_kernel_map, &addr, vmsize,
		    0, KMA_ZERO, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		lck_mtx_lock(&lck_grp_lock);
		if (needed >= lck_grp_cnt) {
			break;
		}
		needed = lck_grp_cnt;
		lck_mtx_unlock(&lck_grp_lock);

		kmem_free(ipc_kernel_map, addr, vmsize);
	}

	info = (lockgroup_info_t *)addr;

	lck_grp_foreach_locked(^bool (lck_grp_t *grp) {
		info[count].lock_spin_cnt = grp->lck_grp_spincnt;
		info[count].lock_rw_cnt   = grp->lck_grp_rwcnt;
		info[count].lock_mtx_cnt  = grp->lck_grp_mtxcnt;

#if LOCK_STATS
		info[count].lock_spin_held_cnt = grp->lck_grp_stats.lgss_spin_held.lgs_count;
		info[count].lock_spin_miss_cnt = grp->lck_grp_stats.lgss_spin_miss.lgs_count;
#endif /* LOCK_STATS */

		// Historically on x86, held was used for "direct wait" and util for "held"
		info[count].lock_mtx_util_cnt = grp->lck_grp_stats.lgss_mtx_held.lgs_count;
		info[count].lock_mtx_held_cnt = grp->lck_grp_stats.lgss_mtx_direct_wait.lgs_count;
		info[count].lock_mtx_miss_cnt = grp->lck_grp_stats.lgss_mtx_miss.lgs_count;
		info[count].lock_mtx_wait_cnt = grp->lck_grp_stats.lgss_mtx_wait.lgs_count;

		memcpy(info[count].lockgroup_name, grp->lck_grp_name, LOCKGROUP_MAX_NAME);

		count++;
		return true;
	});

	lck_mtx_unlock(&lck_grp_lock);

	/*
	 * We might have found less groups than `needed`
	 * get rid of the excess now:
	 * - [0, used) is what we want to return
	 * - [0, size) is what we allocated
	 */
	used   = count * sizeof(lockgroup_info_t);
	vmused = vm_map_round_page(used, VM_MAP_PAGE_MASK(ipc_kernel_map));

	if (vmused < vmsize) {
		kmem_free(ipc_kernel_map, addr + vmused, vmsize - vmused);
	}

	kr = vm_map_unwire(ipc_kernel_map, addr, addr + vmused, FALSE);
	assert(kr == KERN_SUCCESS);

	kr = vm_map_copyin(ipc_kernel_map, addr, used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*lockgroup_infop = (lockgroup_info_t *)copy;
	*lockgroup_infoCntp = count;

	return KERN_SUCCESS;
}

#pragma mark lock attributes

__startup_func
void
lck_attr_startup_init(struct lck_attr_startup_spec *sp)
{
	lck_attr_t *attr = sp->lck_attr;
	lck_attr_setdefault(attr);
	attr->lck_attr_val |= sp->lck_attr_set_flags;
	attr->lck_attr_val &= ~sp->lck_attr_clear_flags;
}

lck_attr_t *
lck_attr_alloc_init(void)
{
	lck_attr_t      *attr;

	attr = zalloc(KT_LCK_ATTR);
	lck_attr_setdefault(attr);
	return attr;
}


void
lck_attr_setdefault(lck_attr_t *attr)
{
	attr->lck_attr_val = LockDefaultLckAttr.lck_attr_val;
}


void
lck_attr_setdebug(lck_attr_t *attr)
{
	os_atomic_or(&attr->lck_attr_val, LCK_ATTR_DEBUG, relaxed);
}

void
lck_attr_cleardebug(lck_attr_t *attr)
{
	os_atomic_andnot(&attr->lck_attr_val, LCK_ATTR_DEBUG, relaxed);
}

void
lck_attr_rw_shared_priority(lck_attr_t *attr)
{
	os_atomic_or(&attr->lck_attr_val, LCK_ATTR_RW_SHARED_PRIORITY, relaxed);
}


void
lck_attr_free(lck_attr_t *attr)
{
	zfree(KT_LCK_ATTR, attr);
}
#pragma mark lock stat

void
lck_grp_stat_enable(lck_grp_stat_t *stat)
{
	/* callers ensure this is properly synchronized */
	stat->lgs_enablings++;
}

void
lck_grp_stat_disable(lck_grp_stat_t *stat)
{
	stat->lgs_enablings--;
}

bool
lck_grp_stat_enabled(lck_grp_stat_t *stat)
{
	return stat->lgs_enablings != 0;
}

#if CONFIG_DTRACE || LOCK_STATS
#if LOCK_STATS || __x86_64__

static inline void
lck_grp_inc_stats(lck_grp_t *grp, lck_grp_stat_t *stat)
{
#pragma unused(grp)
	if (lck_grp_stat_enabled(stat)) {
		__unused uint64_t val = os_atomic_inc_orig(&stat->lgs_count, relaxed);
#if CONFIG_DTRACE && LOCK_STATS
		if (__improbable(stat->lgs_limit && (val % (stat->lgs_limit)) == 0)) {
			lockprof_invoke(grp, stat, val);
		}
#endif /* CONFIG_DTRACE && LOCK_STATS */
	}
}

#endif
#if LOCK_STATS

static inline void
lck_grp_inc_time_stats(lck_grp_t *grp, lck_grp_stat_t *stat, uint64_t time)
{
	if (lck_grp_stat_enabled(stat)) {
		__unused uint64_t val = os_atomic_add_orig(&stat->lgs_count, time, relaxed);
#if CONFIG_DTRACE
		if (__improbable(stat->lgs_limit)) {
			while (__improbable(time > stat->lgs_limit)) {
				time -= stat->lgs_limit;
				lockprof_invoke(grp, stat, val);
			}
			if (__improbable(((val % stat->lgs_limit) + time) > stat->lgs_limit)) {
				lockprof_invoke(grp, stat, val);
			}
		}
#endif /* CONFIG_DTRACE */
	}
}

void
__lck_grp_spin_update_held(lck_grp_t *grp)
{
	if (grp) {
		lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_spin_held);
	}
}

void
__lck_grp_spin_update_miss(lck_grp_t *grp)
{
	if (grp) {
		lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_spin_miss);
	}
}

void
__lck_grp_spin_update_spin(lck_grp_t *grp, uint64_t time)
{
	if (grp) {
		lck_grp_stat_t *stat = &grp->lck_grp_stats.lgss_spin_spin;
		lck_grp_inc_time_stats(grp, stat, time);
	}
}

void
__lck_grp_ticket_update_held(lck_grp_t *grp)
{
	if (grp) {
		lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_ticket_held);
	}
}

void
__lck_grp_ticket_update_miss(lck_grp_t *grp)
{
	if (grp) {
		lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_ticket_miss);
	}
}

void
__lck_grp_ticket_update_spin(lck_grp_t *grp, uint64_t time)
{
	if (grp) {
		lck_grp_stat_t *stat = &grp->lck_grp_stats.lgss_ticket_spin;
		lck_grp_inc_time_stats(grp, stat, time);
	}
}

#endif /* LOCK_STATS */
#if __x86_64__

void
__lck_grp_mtx_update_miss(lck_grp_t *grp)
{
	lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_mtx_miss);
}

void
__lck_grp_mtx_update_direct_wait(lck_grp_t *grp)
{
	lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_mtx_direct_wait);
}

void
__lck_grp_mtx_update_wait(lck_grp_t *grp)
{
	lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_mtx_wait);
}

void
__lck_grp_mtx_update_held(lck_grp_t *grp)
{
	lck_grp_inc_stats(grp, &grp->lck_grp_stats.lgss_mtx_held);
}

#endif /* __x86_64__ */
#endif /* CONFIG_DTRACE || LOCK_STATS */
