/*
 * Copyright (c) 2015-2020 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
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
 * un-comment the following lines to debug the link/prepost tables
 * NOTE: this expands each element by ~40 bytes
 */
//#define KEEP_WAITQ_LINK_STATS
//#define KEEP_WAITQ_PREPOST_STATS

#include <kern/ast.h>
#include <kern/backtrace.h>
#include <kern/kern_types.h>
#include <kern/ltable.h>
#include <kern/mach_param.h>
#include <kern/percpu.h>
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <kern/simple_lock.h>
#include <kern/spl.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/policy_internal.h>
#include <kern/turnstile.h>

#include <os/hash.h>
#include <libkern/section_keywords.h>
#include <mach/sync_policy.h>
#include <vm/vm_kern.h>

#include <sys/kdebug.h>

#if defined(KEEP_WAITQ_LINK_STATS) || defined(KEEP_WAITQ_PREPOST_STATS)
#  if !CONFIG_LTABLE_STATS
#    error "You must configure LTABLE_STATS to use WAITQ_[LINK|PREPOST]_STATS"
#  endif
#  if !CONFIG_WAITQ_STATS
#    error "You must configure WAITQ_STATS to use WAITQ_[LINK|PREPOST]_STATS"
#  endif
#endif

#if CONFIG_WAITQ_DEBUG
#define wqdbg(fmt, ...) \
	printf("WQ[%s]:  " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define wqdbg(fmt, ...) do { } while (0)
#endif

#ifdef WAITQ_VERBOSE_DEBUG
#define wqdbg_v(fmt, ...) \
	printf("WQ[v:%s]:  " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define wqdbg_v(fmt, ...) do { } while (0)
#endif

#define wqinfo(fmt, ...) \
	printf("WQ[%s]: " fmt "\n", __func__,  ## __VA_ARGS__)

#define wqerr(fmt, ...) \
	printf("WQ[%s] ERROR: " fmt "\n", __func__, ## __VA_ARGS__)

/* waitq prepost cache */
#define WQP_CACHE_MAX   50
struct wqp_cache {
	uint64_t        head;
	unsigned int    avail;
};
static struct wqp_cache PERCPU_DATA(wqp_cache);

#define P2ROUNDUP(x, align) (-(-((uint32_t)(x)) & -(align)))
#define ROUNDDOWN(x, y)  (((x)/(y))*(y))


#if CONFIG_LTABLE_STATS || CONFIG_WAITQ_STATS
static __inline__ void waitq_grab_backtrace(uintptr_t bt[NWAITQ_BTFRAMES], int skip);
#endif

LCK_GRP_DECLARE(waitq_lck_grp, "waitq");

#define DEFAULT_MIN_FREE_TABLE_ELEM    100
static uint32_t g_min_free_table_elem;
static uint32_t g_min_free_cache;


/* ----------------------------------------------------------------------
 *
 * waitq reference helpers
 *
 * ---------------------------------------------------------------------- */

/* note: WAITQ_REF_NULL is considered a pointer */
static inline bool
wqr_is_ptr(waitq_ref_t ref)
{
	return (ref.wqr_value & 1) == 0;
}

__attribute__((overloadable))
static inline waitq_ref_t
wqr_make(const void *ptr)
{
	return (waitq_ref_t){ .wqr_value = (intptr_t)ptr };
}

__attribute__((overloadable))
static inline waitq_ref_t
wqr_make(uint64_t lid)
{
	return (waitq_ref_t){ .wqr_value = lid };
}

static inline bool
wqr_is_equal(waitq_ref_t ref, uint64_t ltable_id)
{
	return ref.wqr_value == ltable_id;
}

static inline bool
wqr_is_null(waitq_ref_t ref)
{
	return ref.wqr_value == 0;
}

static inline void *
wqr_ptr_raw(waitq_ref_t ref)
{
	return (void *)(intptr_t)ref.wqr_value;
}

static inline void *
wqr_ptr(waitq_ref_t ref)
{
	if (wqr_is_ptr(ref)) {
		return wqr_ptr_raw(ref);
	}
	return NULL;
}

/* ----------------------------------------------------------------------
 *
 * SetID Link Table Implementation
 *
 * ---------------------------------------------------------------------- */
static struct link_table g_wqlinktable;

enum wq_link_type {
	WQL_WQS     = LT_ELEM,
	WQL_LINK    = LT_LINK,
};

struct waitq_link {
	struct lt_elem wqte;

	union {
		/* wqt_type == WQL_WQS (LT_ELEM) */
		struct waitq_set *wql_set;

		/* wqt_type == WQL_LINK (LT_LINK) */
		struct {
			waitq_ref_t   wql_next;
			uint64_t      wql_node;
		};
	};
#ifdef KEEP_WAITQ_LINK_STATS
	thread_t  sl_alloc_th;
	task_t    sl_alloc_task;
	uintptr_t sl_alloc_bt[NWAITQ_BTFRAMES];
	uint64_t  sl_alloc_ts;
	uintptr_t sl_invalidate_bt[NWAITQ_BTFRAMES];
	uint64_t  sl_invalidate_ts;
	uintptr_t sl_mkvalid_bt[NWAITQ_BTFRAMES];
	uint64_t  sl_mkvalid_ts;
	uint64_t  sl_free_ts;
#endif
};
#if !defined(KEEP_WAITQ_LINK_STATS)
static_assert((sizeof(struct waitq_link) & (sizeof(struct waitq_link) - 1)) == 0,
    "waitq_link struct must be a power of two!");
#endif

#define wql_refcnt(link) \
	(lt_bits_refcnt((link)->wqte.lt_bits))

#define wql_type(link) \
	(lt_bits_type((link)->wqte.lt_bits))

#define wql_mkvalid(link) \
	do { \
	        lt_elem_mkvalid(&(link)->wqte); \
	        wql_do_mkvalid_stats(&(link)->wqte); \
	} while (0)

#define wql_is_valid(link) \
	lt_bits_valid((link)->wqte.lt_bits)

#define wql_setid wqte.lt_id
#define wql_count wqte.lt_next_idx

#define WQL_WQS_POISON         ((void *)(0xf00df00d))
#define WQL_LINK_POISON        (0x0bad0badffffffffull)

static KALLOC_TYPE_DEFINE(waitq_link_zone, struct waitq_link, KT_PRIV_ACCT);

static void
wql_poison(struct link_table *table, struct lt_elem *elem)
{
	struct waitq_link *link = (struct waitq_link *)elem;
	(void)table;

	switch (wql_type(link)) {
	case WQL_WQS:
		link->wql_set = WQL_WQS_POISON;
		break;
	case WQL_LINK:
		link->wql_next.wqr_value = WQL_LINK_POISON;
		link->wql_node = WQL_LINK_POISON;
		break;
	default:
		break;
	}
#ifdef KEEP_WAITQ_LINK_STATS
	memset(link->sl_alloc_bt, 0, sizeof(link->sl_alloc_bt));
	link->sl_alloc_ts = 0;
	memset(link->sl_mkvalid_bt, 0, sizeof(link->sl_mkvalid_bt));
	link->sl_mkvalid_ts = 0;

	link->sl_alloc_th = THREAD_NULL;
	/* leave the sl_alloc_task in place for debugging */

	link->sl_free_ts = mach_absolute_time();
#endif
}

#ifdef KEEP_WAITQ_LINK_STATS
static __inline__ void
wql_do_alloc_stats(struct lt_elem *elem)
{
	if (elem) {
		struct waitq_link *link = (struct waitq_link *)elem;
		memset(link->sl_alloc_bt, 0, sizeof(link->sl_alloc_bt));
		waitq_grab_backtrace(link->sl_alloc_bt, 0);
		link->sl_alloc_th = current_thread();
		link->sl_alloc_task = current_task();

		assert(link->sl_alloc_ts == 0);
		link->sl_alloc_ts = mach_absolute_time();

		memset(link->sl_invalidate_bt, 0, sizeof(link->sl_invalidate_bt));
		link->sl_invalidate_ts = 0;
	}
}

static __inline__ void
wql_do_invalidate_stats(struct lt_elem *elem)
{
	struct waitq_link *link = (struct waitq_link *)elem;

	if (!elem) {
		return;
	}

	assert(link->sl_mkvalid_ts > 0);

	memset(link->sl_invalidate_bt, 0, sizeof(link->sl_invalidate_bt));
	link->sl_invalidate_ts = mach_absolute_time();
	waitq_grab_backtrace(link->sl_invalidate_bt, 0);
}

static __inline__ void
wql_do_mkvalid_stats(struct lt_elem *elem)
{
	struct waitq_link *link = (struct waitq_link *)elem;

	if (!elem) {
		return;
	}

	memset(link->sl_mkvalid_bt, 0, sizeof(link->sl_mkvalid_bt));
	link->sl_mkvalid_ts = mach_absolute_time();
	waitq_grab_backtrace(link->sl_mkvalid_bt, 0);
}
#else
#define wql_do_alloc_stats(e)
#define wql_do_invalidate_stats(e)
#define wql_do_mkvalid_stats(e)
#endif /* KEEP_WAITQ_LINK_STATS */

static void
wql_init(void)
{
	uint32_t tablesz = 0, max_links = 0;

	if (PE_parse_boot_argn("wql_tsize", &tablesz, sizeof(tablesz)) != TRUE) {
		tablesz = (uint32_t)g_lt_max_tbl_size;
	}

	tablesz = P2ROUNDUP(tablesz, PAGE_SIZE);
	max_links = tablesz / sizeof(struct waitq_link);
	assert(max_links > 0 && tablesz > 0);

	/* we have a restricted index range */
	if (max_links > (LT_IDX_MAX + 1)) {
		max_links = LT_IDX_MAX + 1;
	}

	wqinfo("init linktable with max:%d elements (%d bytes)",
	    max_links, tablesz);
	ltable_init(&g_wqlinktable, "wqslab.wql", max_links,
	    sizeof(struct waitq_link), wql_poison);
}

static struct waitq_link *
wql_alloc_link(int type)
{
	struct lt_elem *elem;

	elem = ltable_alloc_elem(&g_wqlinktable, type, 1, 0);
	wql_do_alloc_stats(elem);
	return (struct waitq_link *)elem;
}

static void
wql_realloc_link(struct waitq_link *link, int type)
{
	ltable_realloc_elem(&g_wqlinktable, &link->wqte, type);
#ifdef KEEP_WAITQ_LINK_STATS
	memset(link->sl_alloc_bt, 0, sizeof(link->sl_alloc_bt));
	link->sl_alloc_ts = 0;
	wql_do_alloc_stats(&link->wqte);

	memset(link->sl_invalidate_bt, 0, sizeof(link->sl_invalidate_bt));
	link->sl_invalidate_ts = 0;
#endif
}

static void
wql_invalidate(struct waitq_link *link)
{
	lt_elem_invalidate(&link->wqte);
	wql_do_invalidate_stats(&link->wqte);
}

static bool
wql_link_valid(uint64_t setid)
{
	return ltable_elem_valid(&g_wqlinktable, setid);
}

static struct waitq_link *
wql_get_link(uint64_t setid)
{
	struct lt_elem *elem;

	elem = ltable_get_elem(&g_wqlinktable, setid);
	if (!elem) {
		return NULL;
	}
	return __container_of(elem, struct waitq_link, wqte);
}

static void
wql_put_link(struct waitq_link *link)
{
	if (!link) {
		return;
	}
	ltable_put_elem(&g_wqlinktable, (struct lt_elem *)link);
}

/*
 * waitq links form a list hanging from the waitq `waitq_set_id` field.
 *
 * When the waitq is member of 0 or 1 set, it looks like this:
 *
 *      ┌───────────────┐
 *      │               │
 *      │ waitq_set_id  ┼───> set or WAITQ_REF_NULL
 *      │               │
 *      └───────────────┘
 *
 * When the waitq is member of 2 or more sets, then it looks like this:
 *
 *      ┌───────────────┐
 *      │               │
 *      │ waitq_set_id  │
 *      │               │
 *      └───────┼───────┘
 *              │
 *              v
 *        ┌───────────┐   ┌───────────┐   ┌───────────┐
 *        │ wql_count │   │           │   │           │
 *        │ wql_next  ┼──>│ wql_next  ┼──>│ wql_next  ┼──────┐
 *        │ wql_node  │   │ wql_node  │   │ wql_node  │      │
 *        └─────┼─────┘   └─────┼─────┘   └─────┼─────┘      │
 *              │               │               │            │
 *              v               v               v            v
 *             set             set             set          set
 *
 *
 * when WQL_LINK elements are used that way, they are never made valid,
 * and have their refcount to 1. No one should try to resolve those
 * using ltable_get_elem().
 */
#define waitq_foreach_link(it, ref) \
	for (struct waitq_link *it = wqr_ptr(ref); it; it = wqr_ptr(it->wql_next))

#define waitq_foreach_link_safe(it, ref) \
	for (struct waitq_link *__tmp_##it = NULL, *it = wqr_ptr(ref); \
	    (it ? (__tmp_##it = wqr_ptr(it->wql_next), 1) : 0); \
	    it = __tmp_##it)

static int
__wql_found_set(uint64_t setid, int (^cb)(struct waitq_link *))
{
	struct waitq_link *link = wql_get_link(setid);
	int ret = WQ_ITERATE_CONTINUE;

	if (link) {
		ret = cb(link);
		wql_put_link(link);
	}

	return ret;
}

static int
wql_walk_sets(struct waitq *waitq, int (^cb)(struct waitq_link *))
{
	waitq_ref_t root_ref = waitq->waitq_set_id;
	int ret = WQ_ITERATE_CONTINUE;

	if (wqr_is_null(root_ref)) {
		return ret;
	}

	if (!wqr_is_ptr(root_ref)) {
		return __wql_found_set(root_ref.wqr_value, cb);
	}

	waitq_foreach_link(link, root_ref) {
		ret = __wql_found_set(link->wql_node, cb);
		if (ret != WQ_ITERATE_CONTINUE) {
			return ret;
		}
		if (!wqr_is_ptr(link->wql_next)) {
			return __wql_found_set(link->wql_next.wqr_value, cb);
		}
	}

	__builtin_unreachable();
}


/* ----------------------------------------------------------------------
 *
 * Prepost Link Table Implementation
 *
 * ---------------------------------------------------------------------- */
static struct link_table g_prepost_table;

enum wq_prepost_type {
	WQP_FREE  = LT_FREE,
	WQP_WQ    = LT_ELEM,
	WQP_POST  = LT_LINK,
};

struct wq_prepost {
	struct lt_elem wqte;

	union {
		/* wqt_type == WQP_WQ (LT_ELEM) */
		struct {
			struct waitq *wqp_wq_ptr;
		} wqp_wq;
		/* wqt_type == WQP_POST (LT_LINK) */
		struct {
			uint64_t      wqp_next_id;
			uint64_t      wqp_wq_id;
		} wqp_post;
	};
#ifdef KEEP_WAITQ_PREPOST_STATS
	thread_t  wqp_alloc_th;
	task_t    wqp_alloc_task;
	uintptr_t wqp_alloc_bt[NWAITQ_BTFRAMES];
#endif
};
#if !defined(KEEP_WAITQ_PREPOST_STATS)
static_assert((sizeof(struct wq_prepost) & (sizeof(struct wq_prepost) - 1)) == 0,
    "wq_prepost struct must be a power of two!");
#endif

#define wqp_refcnt(wqp) \
	(lt_bits_refcnt((wqp)->wqte.lt_bits))

#define wqp_type(wqp) \
	(lt_bits_type((wqp)->wqte.lt_bits))

#define wqp_set_valid(wqp) \
	lt_elem_mkvalid(&(wqp)->wqte)

#define wqp_is_valid(wqp) \
	lt_bits_valid((wqp)->wqte.lt_bits)

#define wqp_prepostid wqte.lt_id

#define WQP_WQ_POISON              (0x0bad0badffffffffull)
#define WQP_POST_POISON            (0xf00df00df00df00d)

static void
wqp_poison(struct link_table *table, struct lt_elem *elem)
{
	struct wq_prepost *wqp = (struct wq_prepost *)elem;
	(void)table;

	switch (wqp_type(wqp)) {
	case WQP_WQ:
		break;
	case WQP_POST:
		wqp->wqp_post.wqp_next_id = WQP_POST_POISON;
		wqp->wqp_post.wqp_wq_id = WQP_POST_POISON;
		break;
	default:
		break;
	}
}

#ifdef KEEP_WAITQ_PREPOST_STATS
static __inline__ void
wqp_do_alloc_stats(struct lt_elem *elem)
{
	if (!elem) {
		return;
	}

	struct wq_prepost *wqp = (struct wq_prepost *)elem;
	uintptr_t alloc_bt[sizeof(wqp->wqp_alloc_bt)];

	waitq_grab_backtrace(alloc_bt, NWAITQ_BTFRAMES);

	/* be sure the take stats for _all_ allocated objects */
	for (;;) {
		memcpy(wqp->wqp_alloc_bt, alloc_bt, sizeof(alloc_bt));
		wqp->wqp_alloc_th = current_thread();
		wqp->wqp_alloc_task = current_task();
		wqp = (struct wq_prepost *)lt_elem_list_next(&g_prepost_table, &wqp->wqte);
		if (!wqp) {
			break;
		}
	}
}
#else
#define wqp_do_alloc_stats(e)
#endif /* KEEP_WAITQ_LINK_STATS */

static void
wqp_init(void)
{
	uint32_t tablesz = 0, max_wqp = 0;

	if (PE_parse_boot_argn("wqp_tsize", &tablesz, sizeof(tablesz)) != TRUE) {
		tablesz = (uint32_t)g_lt_max_tbl_size;
	}

	tablesz = P2ROUNDUP(tablesz, PAGE_SIZE);
	max_wqp = tablesz / sizeof(struct wq_prepost);
	assert(max_wqp > 0 && tablesz > 0);

	/* we have a restricted index range */
	if (max_wqp > (LT_IDX_MAX + 1)) {
		max_wqp = LT_IDX_MAX + 1;
	}

	wqinfo("init prepost table with max:%d elements (%d bytes)",
	    max_wqp, tablesz);
	ltable_init(&g_prepost_table, "wqslab.prepost", max_wqp,
	    sizeof(struct wq_prepost), wqp_poison);
}

/*
 * Refill the per-CPU cache.
 */
static void
wq_prepost_refill_cpu_cache(uint32_t nalloc)
{
	struct lt_elem *new_head, *old_head;
	struct wqp_cache *cache;

	/* require preemption enabled to allocate elements */
	if (get_preemption_level() != 0) {
		return;
	}

	new_head = ltable_alloc_elem(&g_prepost_table,
	    LT_RESERVED, nalloc, 1);
	if (new_head == NULL) {
		return;
	}

	disable_preemption();
	cache = PERCPU_GET(wqp_cache);

	/* check once more before putting these elements on the list */
	if (cache->avail >= WQP_CACHE_MAX) {
		lt_elem_list_release(&g_prepost_table, new_head, LT_RESERVED);
		goto out;
	}

	assert((cache->avail == 0) == (cache->head == 0));

	cache->avail += nalloc;
	if (cache->head == 0) {
		cache->head = new_head->lt_id.id;
		goto out;
	}

	old_head = lt_elem_list_first(&g_prepost_table, cache->head);
	(void)lt_elem_list_link(&g_prepost_table, new_head, old_head);
	cache->head = new_head->lt_id.id;

out:
	enable_preemption();
}

static void
wq_prepost_ensure_free_space(void)
{
	uint32_t free_elem;
	uint32_t min_free;
	struct wqp_cache *cache;

	if (g_min_free_cache == 0) {
		g_min_free_cache = (WQP_CACHE_MAX * ml_wait_max_cpus());
	}

	/*
	 * Ensure that we always have a pool of per-CPU prepost elements
	 */
	disable_preemption();
	cache = PERCPU_GET(wqp_cache);
	free_elem = cache->avail;
	enable_preemption();

	if (free_elem < (WQP_CACHE_MAX / 3)) {
		wq_prepost_refill_cpu_cache(WQP_CACHE_MAX - free_elem);
	}

	/*
	 * Now ensure that we have a sufficient amount of free table space
	 */
	free_elem = g_prepost_table.nelem - g_prepost_table.used_elem;
	min_free = g_min_free_table_elem + g_min_free_cache;
	if (free_elem < min_free) {
		/*
		 * we don't hold locks on these values, so check for underflow
		 */
		if (g_prepost_table.used_elem <= g_prepost_table.nelem) {
			wqdbg_v("Forcing table growth: nelem=%d, used=%d, min_free=%d+%d",
			    g_prepost_table.nelem, g_prepost_table.used_elem,
			    g_min_free_table_elem, g_min_free_cache);
			ltable_grow(&g_prepost_table, min_free);
		}
	}
}

static struct wq_prepost *
wq_prepost_alloc(int type, int nelem)
{
	struct lt_elem *elem;
	struct wq_prepost *wqp;
	struct wqp_cache *cache;

	if (type != LT_RESERVED) {
		goto do_alloc;
	}
	if (nelem == 0) {
		return NULL;
	}

	/*
	 * First try to grab the elements from the per-CPU cache if we are
	 * allocating RESERVED elements
	 */
	disable_preemption();
	cache = PERCPU_GET(wqp_cache);
	if (nelem <= (int)cache->avail) {
		struct lt_elem *first, *next = NULL;
		int nalloc = nelem;

		cache->avail -= nelem;

		/* grab the first element */
		first = lt_elem_list_first(&g_prepost_table, cache->head);

		/* find the last element and re-adjust the cache head */
		for (elem = first; elem != NULL && nalloc > 0; elem = next) {
			next = lt_elem_list_next(&g_prepost_table, elem);
			if (--nalloc == 0) {
				/* terminate the allocated list */
				elem->lt_next_idx = LT_IDX_MAX;
				break;
			}
		}
		assert(nalloc == 0);
		if (!next) {
			cache->head = 0;
		} else {
			cache->head = next->lt_id.id;
		}
		/* assert that we don't have mis-matched book keeping */
		assert((cache->avail == 0) == (cache->head == 0));
		enable_preemption();
		elem = first;
		goto out;
	}
	enable_preemption();

do_alloc:
	/* fall-back to standard table allocation */
	elem = ltable_alloc_elem(&g_prepost_table, type, nelem, 0);
	if (!elem) {
		return NULL;
	}

out:
	wqp = (struct wq_prepost *)elem;
	wqp_do_alloc_stats(elem);
	return wqp;
}

static void
wq_prepost_invalidate(struct wq_prepost *wqp)
{
	lt_elem_invalidate(&wqp->wqte);
}

static struct wq_prepost *
wq_prepost_get(uint64_t wqp_id)
{
	struct lt_elem *elem;

	elem = ltable_get_elem(&g_prepost_table, wqp_id);
	return (struct wq_prepost *)elem;
}

static void
wq_prepost_put(struct wq_prepost *wqp)
{
	ltable_put_elem(&g_prepost_table, (struct lt_elem *)wqp);
}

static int
wq_prepost_rlink(struct wq_prepost *parent, struct wq_prepost *child)
{
	return lt_elem_list_link(&g_prepost_table, &parent->wqte, &child->wqte);
}

static struct wq_prepost *
wq_prepost_get_rnext(struct wq_prepost *head)
{
	struct lt_elem *elem;
	struct wq_prepost *wqp;
	uint64_t id;

	elem = lt_elem_list_next(&g_prepost_table, &head->wqte);
	if (!elem) {
		return NULL;
	}
	id = elem->lt_id.id;
	elem = ltable_get_elem(&g_prepost_table, id);

	if (!elem) {
		return NULL;
	}
	wqp = (struct wq_prepost *)elem;
	if (elem->lt_id.id != id ||
	    wqp_type(wqp) != WQP_POST ||
	    wqp->wqp_post.wqp_next_id != head->wqp_prepostid.id) {
		ltable_put_elem(&g_prepost_table, elem);
		return NULL;
	}

	return wqp;
}

static void
wq_prepost_reset_rnext(struct wq_prepost *wqp)
{
	wqp->wqte.lt_next_idx = LT_IDX_MAX;
}


/**
 * remove 'wqp' from the prepost list on 'wqset'
 *
 * Conditions:
 *	wqset is locked
 *	caller holds a reference on wqp (and is responsible to release it)
 *
 * Result:
 *	wqp is invalidated, wqset is potentially updated with a new
 *	prepost ID, and the next element of the prepost list may be
 *	consumed as well (if the list contained only 2 objects)
 */
static int
wq_prepost_remove(struct waitq_set *wqset, struct wq_prepost *wqp)
{
	int more_posts = 1;
	uint64_t next_id = wqp->wqp_post.wqp_next_id;
	uint64_t wqp_id = wqp->wqp_prepostid.id;
	struct wq_prepost *prev_wqp, *next_wqp;

	assert(wqset->wqset_q.waitq_portset);
	assert(wqp_type(wqp) == WQP_POST);

	if (next_id == wqp_id) {
		/* the list is singular and becoming empty */
		wqset->wqset_prepost_id = 0;
		more_posts = 0;
		goto out;
	}

	prev_wqp = wq_prepost_get_rnext(wqp);
	assert(prev_wqp != NULL);
	assert(prev_wqp->wqp_post.wqp_next_id == wqp_id);
	assert(prev_wqp->wqp_prepostid.id != wqp_id);
	assert(wqp_type(prev_wqp) == WQP_POST);

	if (prev_wqp->wqp_prepostid.id == next_id) {
		/*
		 * There are two items in the list, and we're removing one. We
		 * only need to keep the WQP_WQ pointer from 'prev_wqp'
		 */
		wqset->wqset_prepost_id = prev_wqp->wqp_post.wqp_wq_id;
		wq_prepost_invalidate(prev_wqp);
		wq_prepost_put(prev_wqp);
		more_posts = 0;
		goto out;
	}

	/* prev->next = next */
	prev_wqp->wqp_post.wqp_next_id = next_id;

	/* next->prev = prev */
	next_wqp = wq_prepost_get(next_id);
	assert(next_wqp != NULL);
	assert(next_wqp != wqp);
	assert(next_wqp != prev_wqp);
	assert(wqp_type(next_wqp) == WQP_POST);

	wq_prepost_reset_rnext(next_wqp);
	wq_prepost_rlink(next_wqp, prev_wqp);

	/* If we remove the head of the list, update the wqset */
	if (wqp_id == wqset->wqset_prepost_id) {
		wqset->wqset_prepost_id = next_id;
	}

	wq_prepost_put(prev_wqp);
	wq_prepost_put(next_wqp);

out:
	wq_prepost_reset_rnext(wqp);
	wq_prepost_invalidate(wqp);
	return more_posts;
}

static struct wq_prepost *
wq_prepost_rfirst(uint64_t id)
{
	struct lt_elem *elem;
	elem = lt_elem_list_first(&g_prepost_table, id);
	wqp_do_alloc_stats(elem);
	return (struct wq_prepost *)(void *)elem;
}

static struct wq_prepost *
wq_prepost_rpop(uint64_t *id, int type)
{
	struct lt_elem *elem;
	elem = lt_elem_list_pop(&g_prepost_table, id, type);
	wqp_do_alloc_stats(elem);
	return (struct wq_prepost *)(void *)elem;
}

static void
wq_prepost_release_rlist(struct wq_prepost *wqp)
{
	int nelem = 0;
	struct wqp_cache *cache;
	struct lt_elem *elem;

	if (!wqp) {
		return;
	}

	elem = &wqp->wqte;

	/*
	 * These are reserved elements: release them back to the per-cpu pool
	 * if our cache is running low.
	 */
	disable_preemption();
	cache = PERCPU_GET(wqp_cache);
	if (cache->avail < WQP_CACHE_MAX) {
		struct lt_elem *tmp = NULL;
		if (cache->head != 0) {
			tmp = lt_elem_list_first(&g_prepost_table, cache->head);
		}
		nelem = lt_elem_list_link(&g_prepost_table, elem, tmp);
		cache->head = elem->lt_id.id;
		cache->avail += nelem;
		enable_preemption();
		return;
	}
	enable_preemption();

	/* release these elements back to the main table */
	nelem = lt_elem_list_release(&g_prepost_table, elem, LT_RESERVED);

#if CONFIG_WAITQ_STATS
	g_prepost_table.nreserved_releases += 1;
	OSDecrementAtomic64(&g_prepost_table.nreservations);
#endif
}

typedef int (^wqp_callback_t)(struct wq_prepost *wqp, struct waitq *waitq);

/**
 * iterate over a chain of preposts associated with a waitq set.
 *
 * Conditions:
 *	wqset is locked
 *
 * Notes:
 *	This loop performs automatic prepost chain management / culling, and
 *	may reset or adjust the waitq set's prepost ID pointer. If you don't
 *	want this extra processing, you can use wq_prepost_iterate().
 */
static int
wq_prepost_foreach_locked(struct waitq_set *wqset, wqp_callback_t cb)
{
	int ret = WQ_ITERATE_SUCCESS;
	struct wq_prepost *wqp, *tmp_wqp;

	assert(cb != NULL);
	assert(wqset->wqset_q.waitq_portset);

	if (!wqset->wqset_prepost_id) {
		return WQ_ITERATE_SUCCESS;
	}

restart:
	wqp = wq_prepost_get(wqset->wqset_prepost_id);
	if (!wqp) {
		/*
		 * The prepost object is no longer valid, reset the waitq
		 * set's prepost id.
		 */
		wqset->wqset_prepost_id = 0;
		return WQ_ITERATE_SUCCESS;
	}

	if (wqp_type(wqp) == WQP_WQ) {
		uint64_t __assert_only wqp_id = wqp->wqp_prepostid.id;

		ret = cb(wqp, wqp->wqp_wq.wqp_wq_ptr);

		switch (ret) {
		case WQ_ITERATE_INVALIDATE_CONTINUE:
			/* the caller wants to remove the only prepost here */
			assert(wqp_id == wqset->wqset_prepost_id);
			wqset->wqset_prepost_id = 0;
			OS_FALLTHROUGH;
		case WQ_ITERATE_CONTINUE:
			wq_prepost_put(wqp);
			ret = WQ_ITERATE_SUCCESS;
			break;
		case WQ_ITERATE_RESTART:
			wq_prepost_put(wqp);
			OS_FALLTHROUGH;
		case WQ_ITERATE_DROPPED:
			goto restart;
		default:
			wq_prepost_put(wqp);
			break;
		}
		return ret;
	}

	assert(wqp->wqp_prepostid.id == wqset->wqset_prepost_id);
	assert(wqp_type(wqp) == WQP_POST);

	/*
	 * At this point we know we have a list of POST objects.
	 * Grab a handle to the last element in the list and start
	 * the iteration.
	 */
	tmp_wqp = wq_prepost_get_rnext(wqp);
	assert(tmp_wqp != NULL && wqp_type(tmp_wqp) == WQP_POST);

	uint64_t last_id = tmp_wqp->wqp_prepostid.id;
	wq_prepost_put(tmp_wqp);

	ret = WQ_ITERATE_SUCCESS;
	for (;;) {
		uint64_t wqp_id, first_id, next_id;

		wqp_id = wqp->wqp_prepostid.id;
		first_id = wqset->wqset_prepost_id;
		next_id = wqp->wqp_post.wqp_next_id;

		/* grab the WQP_WQ object this _POST points to */
		tmp_wqp = wq_prepost_get(wqp->wqp_post.wqp_wq_id);
		if (!tmp_wqp) {
			/*
			 * This WQP_POST object points to an invalid
			 * WQP_WQ object - remove the POST object from
			 * the list.
			 */
			if (wq_prepost_remove(wqset, wqp) == 0) {
				wq_prepost_put(wqp);
				goto restart;
			}
			goto next_prepost;
		}
		assert(wqp_type(tmp_wqp) == WQP_WQ);
		/*
		 * make the callback: note that this could remove 'wqp' or
		 * drop the lock on our waitq set. We need to re-validate
		 * our state when this function returns.
		 */
		ret = cb(wqp, tmp_wqp->wqp_wq.wqp_wq_ptr);
		wq_prepost_put(tmp_wqp);

		switch (ret) {
		case WQ_ITERATE_CONTINUE:
			/* continue iteration */
			break;
		case WQ_ITERATE_INVALIDATE_CONTINUE:
			assert(next_id == wqp->wqp_post.wqp_next_id);
			if (wq_prepost_remove(wqset, wqp) == 0) {
				wq_prepost_put(wqp);
				goto restart;
			}
			goto next_prepost;
		case WQ_ITERATE_RESTART:
			wq_prepost_put(wqp);
			OS_FALLTHROUGH;
		case WQ_ITERATE_DROPPED:
			/* the callback dropped the ref to wqp: just restart */
			goto restart;
		default:
			/* break out of the iteration for some other reason */
			goto finish_prepost_foreach;
		}

		/*
		 * the set lock may have been dropped during callback,
		 * if something looks different, restart the prepost iteration
		 */
		if (!wqp_is_valid(wqp) ||
		    (wqp->wqp_post.wqp_next_id != next_id) ||
		    wqset->wqset_prepost_id != first_id) {
			wq_prepost_put(wqp);
			goto restart;
		}

next_prepost:
		/* this was the last object in the list */
		if (wqp_id == last_id) {
			break;
		}

		/* get the next object */
		tmp_wqp = wq_prepost_get(next_id);
		if (!tmp_wqp) {
			/*
			 * At this point we've already checked our state
			 * after the callback (which may have dropped the set
			 * lock). If we find an invalid member of the list
			 * then something is wrong.
			 */
			panic("Invalid WQP_POST member 0x%llx in waitq set "
			    "0x%llx prepost list (first:%llx, "
			    "wqp:%p)",
			    next_id, wqset->wqset_id, first_id, wqp);
		}
		wq_prepost_put(wqp);
		wqp = tmp_wqp;

		assert(wqp_type(wqp) == WQP_POST);
	}

finish_prepost_foreach:
	wq_prepost_put(wqp);
	if (ret == WQ_ITERATE_CONTINUE) {
		ret = WQ_ITERATE_SUCCESS;
	}

	return ret;
}

/**
 * Perform a simple loop over a chain of prepost objects
 *
 * Conditions:
 *	If 'prepost_id' is associated with a waitq (set) then that object must
 *	be locked before calling this function.
 *	Callback function, 'cb', must be able to handle a NULL wqset pointer
 *	and a NULL waitq pointer!
 *
 * Notes:
 *	This prepost chain iteration will _not_ automatically adjust any chain
 *	element or linkage. This is the responsibility of the caller! If you
 *	want automatic prepost chain management (at a cost of extra CPU time),
 *	you can use: wq_prepost_foreach_locked().
 */
static int
wq_prepost_iterate(uint64_t prepost_id, wqp_callback_t cb)
{
	int ret;
	struct wq_prepost *wqp;

	if (!prepost_id) {
		return WQ_ITERATE_SUCCESS;
	}

	wqp = wq_prepost_get(prepost_id);
	if (!wqp) {
		return WQ_ITERATE_SUCCESS;
	}

	if (wqp_type(wqp) == WQP_WQ) {
		ret = cb(wqp, wqp->wqp_wq.wqp_wq_ptr);
		if (ret != WQ_ITERATE_DROPPED) {
			wq_prepost_put(wqp);
		}
		return ret;
	}

	assert(wqp->wqp_prepostid.id == prepost_id);
	assert(wqp_type(wqp) == WQP_POST);

	/* at this point we know we have a list of POST objects */
	uint64_t next_id;

	ret = WQ_ITERATE_CONTINUE;
	do {
		struct wq_prepost *tmp_wqp;
		struct waitq *wq = NULL;

		next_id = wqp->wqp_post.wqp_next_id;

		/* grab the WQP_WQ object this _POST points to */
		tmp_wqp = wq_prepost_get(wqp->wqp_post.wqp_wq_id);
		if (tmp_wqp) {
			assert(wqp_type(tmp_wqp) == WQP_WQ);
			wq = tmp_wqp->wqp_wq.wqp_wq_ptr;
		}

		ret = cb(wqp, wq);
		if (tmp_wqp) {
			wq_prepost_put(tmp_wqp);
		}

		if (ret != WQ_ITERATE_CONTINUE) {
			break;
		}

		tmp_wqp = wq_prepost_get(next_id);
		if (!tmp_wqp) {
			/*
			 * the chain is broken: nothing we can do here besides
			 * bail from the iteration.
			 */
			ret = WQ_ITERATE_ABORTED;
			break;
		}

		wq_prepost_put(wqp);
		wqp = tmp_wqp;

		assert(wqp_type(wqp) == WQP_POST);
	} while (next_id != prepost_id);

	if (ret != WQ_ITERATE_DROPPED) {
		wq_prepost_put(wqp);
	}

	if (ret == WQ_ITERATE_CONTINUE) {
		ret = WQ_ITERATE_SUCCESS;
	}
	return ret;
}


/**
 * checks if 'waitq' has already preposted on 'wqset'
 *
 * Parameters:
 *	waitq    The waitq that's preposting
 *	wqset    The set onto which waitq may be preposted
 *
 * Conditions:
 *	both waitq and wqset are locked
 *
 * Returns non-zero if 'waitq' has already preposted to 'wqset'
 */
static bool
wq_is_preposted_on_set(struct waitq *waitq, struct waitq_set *wqset)
{
	__block bool did_prepost = false;

	assert(wqset->wqset_q.waitq_portset);

	/*
	 * If the set's only prepost matches the waitq's prepost ID,
	 * then it obviously already preposted to the set.
	 */
	if (waitq->waitq_prepost_id != 0 &&
	    wqset->wqset_prepost_id == waitq->waitq_prepost_id) {
		return true;
	}

	/* use full prepost iteration: always trim the list */
	wq_prepost_foreach_locked(wqset,
	    ^(struct wq_prepost *wqp __unused, struct waitq *found_wq) {
		if (found_wq == waitq) {
		        did_prepost = true;
		}
		return WQ_ITERATE_CONTINUE;
	});

	return did_prepost;
}

static struct wq_prepost *
wq_get_prepost_obj(uint64_t *reserved, int type)
{
	struct wq_prepost *wqp = NULL;
	/*
	 * don't fail just because the caller doesn't have enough
	 * reservations, we've kept a low-water mark on the prepost table,
	 * so there should be some available for us.
	 */
	if (reserved && *reserved) {
		wqp = wq_prepost_rpop(reserved, type);
		assert(wqp->wqte.lt_id.idx < g_prepost_table.nelem);
	} else {
		/*
		 * TODO: if in interrupt context, grab from a special
		 *       region / reserved list!
		 */
		wqp = wq_prepost_alloc(type, 1);
	}

	if (wqp == NULL) {
		panic("Couldn't allocate prepost object!");
	}
	return wqp;
}


/**
 * prepost a waitq onto a waitq set
 *
 * Parameters:
 *	wqset    The set onto which waitq will be preposted
 *	waitq    The waitq that's preposting
 *	reserved List (lt_elem_list_ style) of pre-allocated prepost elements
 *	         Could be NULL
 *
 * Conditions:
 *	both wqset and waitq are locked
 *
 * Notes:
 *	If reserved is NULL, this may block on prepost table growth.
 */
static void
wq_prepost_do_post_locked(struct waitq_set *wqset,
    struct waitq *waitq,
    uint64_t *reserved)
{
	struct wq_prepost *wqp_post, *wqp_head, *wqp_tail;

	assert(waitq_held(waitq) && waitq_held(&wqset->wqset_q));

	if (!wqset->wqset_q.waitq_portset) {
		wqset->wqset_prepost_id = WQSET_PREPOSTED_ANON;
		return;
	}

	/*
	 * nothing to do if it's already preposted:
	 * note that this also culls any invalid prepost objects
	 */
	if (wq_is_preposted_on_set(waitq, wqset)) {
		return;
	}

	assert(waitqs_is_linked(wqset));

	/*
	 * This function is called because an event is being posted to 'waitq'.
	 * We need a prepost object associated with this queue. Allocate one
	 * now if the waitq isn't already associated with one.
	 */
	if (waitq->waitq_prepost_id == 0) {
		struct wq_prepost *wqp;
		wqp = wq_get_prepost_obj(reserved, WQP_WQ);
		wqp->wqp_wq.wqp_wq_ptr = waitq;
		wqp_set_valid(wqp);
		waitq->waitq_prepost_id = wqp->wqp_prepostid.id;
		wq_prepost_put(wqp);
	}

#if CONFIG_LTABLE_STATS
	g_prepost_table.npreposts += 1;
#endif

	wqdbg_v("preposting waitq %p (0x%llx) to set 0x%llx",
	    (void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq),
	    waitq->waitq_prepost_id, wqset->wqset_id);

	if (wqset->wqset_prepost_id == 0) {
		/* the set has no previous preposts */
		wqset->wqset_prepost_id = waitq->waitq_prepost_id;
		return;
	}

	wqp_head = wq_prepost_get(wqset->wqset_prepost_id);
	if (!wqp_head) {
		/* the previous prepost has become invalid */
		wqset->wqset_prepost_id = waitq->waitq_prepost_id;
		return;
	}

	assert(wqp_head->wqp_prepostid.id == wqset->wqset_prepost_id);

	/*
	 * If we get here, we're going to need at least one new wq_prepost
	 * object. If the previous wqset_prepost_id points to a WQP_WQ, we
	 * actually need to allocate 2 wq_prepost objects because the WQP_WQ
	 * is tied to the waitq and shared across all sets.
	 */
	wqp_post = wq_get_prepost_obj(reserved, WQP_POST);

	wqp_post->wqp_post.wqp_wq_id = waitq->waitq_prepost_id;
	wqdbg_v("POST 0x%llx :: WQ 0x%llx", wqp_post->wqp_prepostid.id,
	    waitq->waitq_prepost_id);

	if (wqp_type(wqp_head) == WQP_WQ) {
		/*
		 * We must replace the wqset_prepost_id with a pointer
		 * to two new WQP_POST objects
		 */
		uint64_t wqp_id = wqp_head->wqp_prepostid.id;
		wqdbg_v("set 0x%llx previous had 1 WQ prepost (0x%llx): "
		    "replacing with two POST preposts",
		    wqset->wqset_id, wqp_id);

		/* drop the old reference */
		wq_prepost_put(wqp_head);

		/* grab another new object (the 2nd of two) */
		wqp_head = wq_get_prepost_obj(reserved, WQP_POST);

		/* point this one to the original WQP_WQ object */
		wqp_head->wqp_post.wqp_wq_id = wqp_id;
		wqdbg_v("POST 0x%llx :: WQ 0x%llx",
		    wqp_head->wqp_prepostid.id, wqp_id);

		/* link it to the new wqp_post object allocated earlier */
		wqp_head->wqp_post.wqp_next_id = wqp_post->wqp_prepostid.id;
		/* make the list a double-linked and circular */
		wq_prepost_rlink(wqp_head, wqp_post);

		/*
		 * Finish setting up the new prepost: point it back to the
		 * POST object we allocated to replace the original wqset
		 * WQ prepost object
		 */
		wqp_post->wqp_post.wqp_next_id = wqp_head->wqp_prepostid.id;
		wq_prepost_rlink(wqp_post, wqp_head);

		/* mark objects valid, and reset the wqset prepost list head */
		wqp_set_valid(wqp_head);
		wqp_set_valid(wqp_post);
		wqset->wqset_prepost_id = wqp_head->wqp_prepostid.id;

		/* release both references */
		wq_prepost_put(wqp_head);
		wq_prepost_put(wqp_post);

		wqdbg_v("set 0x%llx: 0x%llx/0x%llx -> 0x%llx/0x%llx -> 0x%llx",
		    wqset->wqset_id, wqset->wqset_prepost_id,
		    wqp_head->wqp_prepostid.id, wqp_head->wqp_post.wqp_next_id,
		    wqp_post->wqp_prepostid.id,
		    wqp_post->wqp_post.wqp_next_id);
		return;
	}

	assert(wqp_type(wqp_head) == WQP_POST);

	/*
	 * Add the new prepost to the end of the prepost list
	 */
	wqp_tail = wq_prepost_get_rnext(wqp_head);
	assert(wqp_tail != NULL);
	assert(wqp_tail->wqp_post.wqp_next_id == wqset->wqset_prepost_id);

	/*
	 * link the head to the new tail
	 * NOTE: this needs to happen first in case wqp_tail == wqp_head
	 */
	wq_prepost_reset_rnext(wqp_head);
	wq_prepost_rlink(wqp_head, wqp_post);

	/* point the new object to the list head, and list tail */
	wqp_post->wqp_post.wqp_next_id = wqp_head->wqp_prepostid.id;
	wq_prepost_rlink(wqp_post, wqp_tail);

	/* point the last item in the waitq set's list to the new object */
	wqp_tail->wqp_post.wqp_next_id = wqp_post->wqp_prepostid.id;

	wqp_set_valid(wqp_post);

	wq_prepost_put(wqp_head);
	wq_prepost_put(wqp_tail);
	wq_prepost_put(wqp_post);

	wqdbg_v("set 0x%llx (wqp:0x%llx) last_prepost:0x%llx, "
	    "new_prepost:0x%llx->0x%llx", wqset->wqset_id,
	    wqset->wqset_prepost_id, wqp_head->wqp_prepostid.id,
	    wqp_post->wqp_prepostid.id, wqp_post->wqp_post.wqp_next_id);
}


/* ----------------------------------------------------------------------
 *
 * Stats collection / reporting
 *
 * ---------------------------------------------------------------------- */
#if CONFIG_LTABLE_STATS && CONFIG_WAITQ_STATS
static void
wq_table_stats(struct link_table *table, struct wq_table_stats *stats)
{
	stats->version = WAITQ_STATS_VERSION;
	stats->table_elements = table->nelem;
	stats->table_used_elems = table->used_elem;
	stats->table_elem_sz = table->elem_sz;
	stats->table_slabs = table->nslabs;
	stats->table_slab_sz = table->slab_sz;

	stats->table_num_allocs = table->nallocs;
	stats->table_num_preposts = table->npreposts;
	stats->table_num_reservations = table->nreservations;

	stats->table_max_used = table->max_used;
	stats->table_avg_used = table->avg_used;
	stats->table_max_reservations = table->max_reservations;
	stats->table_avg_reservations = table->avg_reservations;
}

void
waitq_link_stats(struct wq_table_stats *stats)
{
	if (!stats) {
		return;
	}
	wq_table_stats(&g_wqlinktable, stats);
}

void
waitq_prepost_stats(struct wq_table_stats *stats)
{
	wq_table_stats(&g_prepost_table, stats);
}
#endif


/* ----------------------------------------------------------------------
 *
 * Global Wait Queues
 *
 * ---------------------------------------------------------------------- */

static struct waitq g_boot_waitq;
static SECURITY_READ_ONLY_LATE(struct waitq *) global_waitqs = &g_boot_waitq;
static SECURITY_READ_ONLY_LATE(uint32_t) g_num_waitqs = 1;

/*
 * Zero out the used MSBs of the event.
 */
#define _CAST_TO_EVENT_MASK(event)   ((waitq_flags_t)(event) & ((1ul << _EVENT_MASK_BITS) - 1ul))

static __inline__ uint32_t
waitq_hash(char *key, size_t length)
{
	uint32_t hash = os_hash_jenkins(key, length);

	hash &= (g_num_waitqs - 1);
	return hash;
}

/* return a global waitq pointer corresponding to the given event */
struct waitq *
_global_eventq(char *event, size_t event_length)
{
	return &global_waitqs[waitq_hash(event, event_length)];
}

/* return an indexed global waitq pointer */
struct waitq *
global_waitq(int index)
{
	return &global_waitqs[index % g_num_waitqs];
}


#if CONFIG_LTABLE_STATS || CONFIG_WAITQ_STATS
/* this global is for lldb */
const uint32_t g_nwaitq_btframes = NWAITQ_BTFRAMES;

static __inline__ void
waitq_grab_backtrace(uintptr_t bt[NWAITQ_BTFRAMES], int skip)
{
	uintptr_t buf[NWAITQ_BTFRAMES + skip];
	if (skip < 0) {
		skip = 0;
	}
	memset(buf, 0, (NWAITQ_BTFRAMES + skip) * sizeof(uintptr_t));
	backtrace(buf, g_nwaitq_btframes + skip, NULL, NULL);
	memcpy(&bt[0], &buf[skip], NWAITQ_BTFRAMES * sizeof(uintptr_t));
}
#else /* no stats */
#define waitq_grab_backtrace(...)
#endif

#if CONFIG_WAITQ_STATS

struct wq_stats g_boot_stats;
struct wq_stats *g_waitq_stats = &g_boot_stats;

static __inline__ struct wq_stats *
waitq_global_stats(struct waitq *waitq)
{
	struct wq_stats *wqs;
	uint32_t idx;

	if (!waitq_is_global(waitq)) {
		return NULL;
	}

	idx = (uint32_t)(((uintptr_t)waitq - (uintptr_t)global_waitqs) / sizeof(*waitq));
	assert(idx < g_num_waitqs);
	wqs = &g_waitq_stats[idx];
	return wqs;
}

static __inline__ void
waitq_stats_count_wait(struct waitq *waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->waits++;
		waitq_grab_backtrace(wqs->last_wait, 2);
	}
}

static __inline__ void
waitq_stats_count_wakeup(struct waitq *waitq, int n)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		if (n > 0) {
			wqs->wakeups += n;
			waitq_grab_backtrace(wqs->last_wakeup, 2);
		} else {
			wqs->failed_wakeups++;
			waitq_grab_backtrace(wqs->last_failed_wakeup, 2);
		}
	}
}

static __inline__ void
waitq_stats_count_clear_wakeup(struct waitq *waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->wakeups++;
		wqs->clears++;
		waitq_grab_backtrace(wqs->last_wakeup, 2);
	}
}
#else /* !CONFIG_WAITQ_STATS */
#define waitq_stats_count_wait(q)         do { } while (0)
#define waitq_stats_count_wakeup(q, n)    do { } while (0)
#define waitq_stats_count_clear_wakeup(q) do { } while (0)
#endif

bool
waitq_is_valid(struct waitq *waitq)
{
	return waitq_valid(waitq);
}

bool
waitq_set_is_valid(struct waitq_set *wqset)
{
	return waitq_valid(&wqset->wqset_q) && waitqs_is_set(wqset);
}

bool
waitq_is_global(struct waitq *waitq)
{
	return waitq >= global_waitqs && waitq < global_waitqs + g_num_waitqs;
}

bool
waitq_irq_safe(struct waitq *waitq)
{
	/* global wait queues have this bit set on initialization */
	return waitq->waitq_irq;
}

static inline bool
waitq_empty(struct waitq *wq)
{
	if (waitq_is_turnstile_queue(wq)) {
		return priority_queue_empty(&wq->waitq_prio_queue);
	} else if (waitq_is_turnstile_proxy(wq)) {
		struct turnstile *ts = wq->waitq_ts;
		return ts == TURNSTILE_NULL ||
		       priority_queue_empty(&ts->ts_waitq.waitq_prio_queue);
	} else {
		return queue_empty(&wq->waitq_queue);
	}
}

static struct waitq *
waitq_get_safeq(struct waitq *waitq)
{
	/* Check if it's a port waitq */
	if (waitq_is_turnstile_proxy(waitq)) {
		struct turnstile *ts = waitq->waitq_ts;
		return ts ? &ts->ts_waitq : NULL;
	}
	return global_eventq(waitq);
}

static uint32_t
waitq_hash_size(void)
{
	uint32_t hsize, queues;

	if (PE_parse_boot_argn("wqsize", &hsize, sizeof(hsize))) {
		return hsize;
	}

	queues = thread_max / 5;
	hsize = P2ROUNDUP(queues * sizeof(struct waitq), PAGE_SIZE);

	return hsize;
}

/*
 * Since the priority ordered waitq uses basepri as the
 * ordering key assert that this value fits in a uint8_t.
 */
static_assert(MAXPRI <= UINT8_MAX);

static inline void
waitq_thread_insert(struct waitq *safeq, thread_t thread,
    struct waitq *wq, event64_t event)
{
	if (waitq_is_turnstile_queue(safeq)) {
		turnstile_stats_update(0, TSU_TURNSTILE_BLOCK_COUNT, NULL);
		turnstile_waitq_add_thread_priority_queue(safeq, thread);
	} else {
		turnstile_stats_update(0, TSU_REGULAR_WAITQ_BLOCK_COUNT, NULL);
		/*
		 * Realtime threads get priority for wait queue placements.
		 * This allows wait_queue_wakeup_one to prefer a waiting
		 * realtime thread, similar in principle to performing
		 * a wait_queue_wakeup_all and allowing scheduler prioritization
		 * to run the realtime thread, but without causing the
		 * lock contention of that scenario.
		 */
		if (thread->sched_pri >= BASEPRI_REALTIME ||
		    !safeq->waitq_fifo ||
		    thread->options & TH_OPT_VMPRIV) {
			enqueue_head(&safeq->waitq_queue, &thread->wait_links);
		} else {
			enqueue_tail(&safeq->waitq_queue, &thread->wait_links);
		}
	}

	/* mark the event and real waitq, even if enqueued on a global safeq */
	thread->wait_event = event;
	thread->waitq = wq;
}

/**
 * clear the thread-related waitq state
 *
 * Conditions:
 *	'thread' is locked
 */
static inline void
thread_clear_waitq_state(thread_t thread)
{
	thread->waitq = NULL;
	thread->wait_event = NO_EVENT64;
	thread->at_safe_point = FALSE;
}

static inline void
waitq_thread_remove(struct waitq *wq, thread_t thread)
{
	if (waitq_is_turnstile_queue(wq)) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    (TURNSTILE_CODE(TURNSTILE_HEAP_OPERATIONS,
		    (THREAD_REMOVED_FROM_TURNSTILE_WAITQ))) | DBG_FUNC_NONE,
		    VM_KERNEL_UNSLIDE_OR_PERM(waitq_to_turnstile(wq)),
		    thread_tid(thread), 0, 0, 0);
		priority_queue_remove(&wq->waitq_prio_queue,
		    &thread->wait_prioq_links);
	} else {
		remqueue(&thread->wait_links);
		if (waitq_is_global(wq) && waitq_empty(wq)) {
			wq->waitq_eventmask = 0;
		}
	}

	thread_clear_waitq_state(thread);
}

void
waitq_bootstrap(void)
{
	kern_return_t kret;
	uint32_t whsize, qsz, tmp32;

	g_min_free_table_elem = DEFAULT_MIN_FREE_TABLE_ELEM;
	if (PE_parse_boot_argn("wqt_min_free", &tmp32, sizeof(tmp32)) == TRUE) {
		g_min_free_table_elem = tmp32;
	}
	wqdbg("Minimum free table elements: %d", tmp32);

	/*
	 * Determine the amount of memory we're willing to reserve for
	 * the waitqueue hash table
	 */
	whsize = waitq_hash_size();

	/* Determine the number of waitqueues we can fit. */
	qsz = sizeof(struct waitq);
	whsize = ROUNDDOWN(whsize, qsz);
	g_num_waitqs = whsize / qsz;

	/*
	 * The hash algorithm requires that this be a power of 2, so we
	 * just mask off all the low-order bits.
	 */
	for (uint32_t i = 0; i < 31; i++) {
		uint32_t bit = (1 << i);
		if ((g_num_waitqs & bit) == g_num_waitqs) {
			break;
		}
		g_num_waitqs &= ~bit;
	}
	assert(g_num_waitqs > 0);

	/* Now determine how much memory we really need. */
	whsize = P2ROUNDUP(g_num_waitqs * qsz, PAGE_SIZE);

	wqdbg("allocating %d global queues  (%d bytes)", g_num_waitqs, whsize);
	kret = kernel_memory_allocate(kernel_map, (vm_offset_t *)&global_waitqs,
	    whsize, 0, KMA_KOBJECT | KMA_NOPAGEWAIT, VM_KERN_MEMORY_WAITQ);
	if (kret != KERN_SUCCESS || global_waitqs == NULL) {
		panic("kernel_memory_allocate() failed to alloc global_waitqs"
		    ", error: %d, whsize: 0x%x", kret, whsize);
	}

#if CONFIG_WAITQ_STATS
	whsize = P2ROUNDUP(g_num_waitqs * sizeof(struct wq_stats), PAGE_SIZE);
	kret = kernel_memory_allocate(kernel_map, (vm_offset_t *)&g_waitq_stats,
	    whsize, 0, KMA_KOBJECT | KMA_NOPAGEWAIT, VM_KERN_MEMORY_WAITQ);
	if (kret != KERN_SUCCESS || global_waitqs == NULL) {
		panic("kernel_memory_allocate() failed to alloc g_waitq_stats"
		    ", error: %d, whsize: 0x%x", kret, whsize);
	}
	memset(g_waitq_stats, 0, whsize);
#endif

	for (uint32_t i = 0; i < g_num_waitqs; i++) {
		waitq_init(&global_waitqs[i], SYNC_POLICY_FIFO | SYNC_POLICY_DISABLE_IRQ);
	}

	/* initialize the global waitq link table */
	wql_init();

	/* initialize the global waitq prepost table */
	wqp_init();
}


/* ----------------------------------------------------------------------
 *
 * Wait Queue Implementation
 *
 * ---------------------------------------------------------------------- */

/*
 * Double the standard lock timeout, because wait queues tend
 * to iterate over a number of threads - locking each.  If there is
 * a problem with a thread lock, it normally times out at the wait
 * queue level first, hiding the real problem.
 */
/* For x86, the hardware timeout is in TSC units. */
#if defined(__i386__) || defined(__x86_64__)
#define waitq_timeout (2 * LockTimeOutTSC)
#else
#define waitq_timeout (2 * os_atomic_load(&LockTimeOut, relaxed))
#endif

static hw_lock_timeout_status_t
waitq_timeout_handler(void *_lock, uint64_t timeout, uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(interrupt_time)

	lck_spinlock_to_info_t lsti;
	hw_lck_ticket_t *lck = _lock;
	hw_lck_ticket_t tmp;
	struct waitq  *wq = __container_of(lck, struct waitq, waitq_interlock);

	if (machine_timeout_suspended()) {
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	lsti = lck_spinlock_timeout_hit(lck, 0);
	tmp.tcurnext = os_atomic_load(&lck->tcurnext, relaxed);

	panic("waitq(%p) lock timeout after %llu ticks; cpu=%d, "
	    "cticket: 0x%x, nticket: 0x%x, waiting for 0x%x"
#if INTERRUPT_MASKED_DEBUG
	    "interrupt time: %llu, "
#endif /* INTERRUPT_MASKED_DEBUG */
	    "start time: %llu, now: %llu, timeout: %llu",
	    wq, now - start, cpu_number(),
	    tmp.cticket, tmp.nticket, lsti->extra,
#if INTERRUPT_MASKED_DEBUG
	    interrupt_time,
#endif /* INTERRUPT_MASKED_DEBUG */
	    start, now, timeout);
}

void
waitq_lock(struct waitq *wq)
{
	(void)hw_lck_ticket_lock_to(&wq->waitq_interlock,
	    waitq_timeout, waitq_timeout_handler, &waitq_lck_grp);
#if defined(__x86_64__)
	pltrace(FALSE);
#endif
}

bool
waitq_lock_allow_invalid(struct waitq *wq)
{
	hw_lock_status_t rc;

	rc = hw_lck_ticket_lock_allow_invalid(&wq->waitq_interlock,
	    waitq_timeout, waitq_timeout_handler, &waitq_lck_grp);

#if defined(__x86_64__)
	if (rc == HW_LOCK_ACQUIRED) {
		pltrace(FALSE);
	}
#endif
	return rc == HW_LOCK_ACQUIRED;
}

void
waitq_unlock(struct waitq *wq)
{
	assert(waitq_held(wq));
#if defined(__x86_64__)
	pltrace(TRUE);
#endif
	hw_lck_ticket_unlock(&wq->waitq_interlock);
}


typedef thread_t (^waitq_select_cb)(struct waitq *waitq, thread_t thread);

struct waitq_select_args {
	/* input parameters */
	event64_t        event;
	waitq_select_cb  select_cb;
	int              priority;
	wait_result_t    result;
	waitq_options_t  options;

	uint64_t        *reserved_preposts;

	/* output parameters */
	queue_head_t     threadq;
	uint32_t         max_threads;
	uint32_t         nthreads;
	spl_t            spl;
};

static void do_waitq_select_n_locked(struct waitq *, struct waitq_select_args *args);
static void waitq_select_queue_flush(struct waitq *, struct waitq_select_args *args);

/**
 * callback invoked once for every waitq set to which a waitq belongs
 *
 * Conditions:
 *	the posted waitq is locked.
 *	'link' points to a valid waitq set
 *
 * Notes:
 *	Takes the waitq set lock on the set pointed to by 'link'
 *	Calls do_waitq_select_n_locked().
 *	If no threads were selected, it preposts the input waitq
 *	onto the waitq set pointed to by 'link'.
 */
static int
waitq_select_walk_cb(struct waitq_link *link, struct waitq *waitq,
    struct waitq_select_args *args)
{
	struct waitq_set *wqset = link->wql_set;
	int ret = WQ_ITERATE_CONTINUE;

	assert(!waitq_irq_safe(&wqset->wqset_q));

	if (queue_empty(&args->threadq)) {
		waitq_set_lock(wqset);
	} else if (!waitq_set_lock_try(wqset)) {
		/*
		 * We are holding several thread locks,
		 * and failed to acquire this waitq set lock.
		 *
		 * It is possible that another core is holding that
		 * (non IRQ-safe) waitq set lock, while an interrupt
		 * is trying to grab the thread lock of ones of those threads.
		 *
		 * In order to avoid deadlocks, let's flush out the queue
		 * of threads, and then we know we're safe.
		 *
		 * Note: this code will never run if `max_threads` is 1
		 *       because we should not even reach this point.
		 *
		 *       It is critical because the `identify` variants
		 *       will not want their queue flushed.
		 */
		assert(args->max_threads > 1);
		waitq_select_queue_flush(waitq, args);
		waitq_set_lock(wqset);
	}

	/*
	 * verify that the link wasn't invalidated just before
	 * we were able to take the lock.
	 */
	if (wqset->wqset_id != link->wql_setid.id) {
		goto out_unlock;
	}

	assert(waitqs_is_linked(wqset));

	/*
	 * Find any threads waiting on this wait queue set.
	 */
	do_waitq_select_n_locked(&wqset->wqset_q, args);

	if (args->nthreads == 0 && args->event == NO_EVENT64) {
		/* No thread selected: prepost 'waitq' to 'wqset' */
		wq_prepost_do_post_locked(wqset, waitq, args->reserved_preposts);

		/* If this is a port-set, callout to the IPC subsystem */
		if (wqset->wqset_q.waitq_portset) {
			ipc_pset_prepost(wqset, waitq);
		}
	} else if (args->nthreads >= args->max_threads) {
		/* break out of the setid walk */
		ret = WQ_ITERATE_FOUND;
	}

out_unlock:
	waitq_set_unlock(wqset);
	return ret;
}

/**
 * Routine to iterate over the waitq for non-priority ordered waitqs
 *
 * Conditions:
 *	args->waitq (and the posted waitq) is locked
 *
 * Notes:
 *	Uses the optional select callback function to refine the selection
 *	of one or more threads from a waitq. The select callback is invoked
 *	once for every thread that is found to be waiting on the input args->waitq.
 *
 *	If one or more threads are selected, this may disable interrupts.
 *	The previous interrupt state is returned in args->spl and should
 *	be used in a call to splx() if threads are returned to the caller.
 */
static thread_t
waitq_queue_iterate_locked(struct waitq *safeq, struct waitq *waitq,
    struct waitq_select_args *args, waitq_flags_t *remaining_eventmask)
{
	thread_t thread = THREAD_NULL;
	thread_t first_thread = THREAD_NULL;

	qe_foreach_element_safe(thread, &safeq->waitq_queue, wait_links) {
		thread_t t = THREAD_NULL;
		assert_thread_magic(thread);

		/*
		 * For non-priority ordered waitqs, we allow multiple events to be
		 * mux'ed into the same waitq. Also safeqs may contain threads from
		 * multiple waitqs. Only pick threads that match the
		 * requested wait event.
		 */
		if (thread->waitq == waitq && thread->wait_event == args->event) {
			t = thread;
			if (first_thread == THREAD_NULL) {
				first_thread = thread;
			}

			/* allow the caller to futher refine the selection */
			if (args->select_cb) {
				t = args->select_cb(waitq, thread);
			}
			if (t != THREAD_NULL) {
				args->nthreads += 1;
				if (args->nthreads == 1 && safeq == waitq) {
					args->spl = splsched();
				}
				thread_lock(t);
				thread_clear_waitq_state(t);
				re_queue_tail(&args->threadq, &t->wait_links);
				/* only enqueue up to 'max' threads */
				if (args->nthreads >= args->max_threads) {
					break;
				}
			}
		}
		/* thread wasn't selected so track its event */
		if (t == THREAD_NULL) {
			*remaining_eventmask |= (thread->waitq != safeq) ?
			    _CAST_TO_EVENT_MASK(thread->waitq) : _CAST_TO_EVENT_MASK(thread->wait_event);
		}
	}

	return first_thread;
}

/**
 * Routine to iterate and remove threads from priority ordered waitqs
 *
 * Conditions:
 *	args->waitq (and the posted waitq) is locked
 *
 * Notes:
 *	The priority ordered waitqs only support maximum priority element removal.
 *
 *	Also, the implementation makes sure that all threads in a priority ordered
 *	waitq are waiting on the same wait event. This is not necessarily true for
 *	non-priority ordered waitqs. If one or more threads are selected, this may
 *	disable interrupts. The previous interrupt state is returned in args->spl
 *	and should be used in a call to splx() if threads are returned to the caller.
 *
 *	In the future, we could support priority ordered waitqs with multiple wait
 *	events in the same queue. The way to implement that would be to keep removing
 *	elements from the waitq and if the event does not match the requested one,
 *	add it to a local list. This local list of elements needs to be re-inserted
 *	into the priority queue at the end and the select_cb return value &
 *	remaining_eventmask would need to be handled appropriately. The implementation
 *	is not very efficient but would work functionally.
 */
static thread_t
waitq_prioq_iterate_locked(struct waitq *safeq, struct waitq *waitq,
    struct waitq_select_args *args, waitq_flags_t *remaining_eventmask)
{
	thread_t first_thread = THREAD_NULL;
	thread_t thread = THREAD_NULL;

	/*
	 * The only possible values for remaining_eventmask for the priority queue
	 * waitq are either 0 (for the remove all threads case) or the original
	 * safeq->waitq_eventmask (for the lookup/remove one thread cases).
	 */
	*remaining_eventmask = safeq->waitq_eventmask;

	while (args->nthreads < args->max_threads) {
		if (priority_queue_empty(&(safeq->waitq_prio_queue))) {
			*remaining_eventmask = 0;
			break;
		}

		thread = priority_queue_remove_max(&safeq->waitq_prio_queue,
		    struct thread, wait_prioq_links);

		/*
		 * Ensure the wait event matches since priority ordered waitqs do not
		 * support multiple events in the same waitq.
		 */
		assert((thread->waitq == waitq) && (thread->wait_event == args->event));

		if (args->select_cb) {
			/*
			 * Call the select_cb passed into the waitq_select args. The callback
			 * updates the select_ctx with information about the highest priority
			 * thread which is eventually used by the caller.
			 */
			thread_t __assert_only ret_thread = args->select_cb(waitq, thread);
			assert(ret_thread == thread);
		}

		if (first_thread == THREAD_NULL) {
			first_thread = thread;
			/*
			 * turnstile_kernel_update_inheritor_on_wake_locked will lock
			 * first_thread, so call it before locking it.
			 */
			if (args->priority == WAITQ_PROMOTE_ON_WAKE &&
			    first_thread != THREAD_NULL &&
			    waitq_is_turnstile_queue(safeq)) {
				turnstile_kernel_update_inheritor_on_wake_locked(waitq_to_turnstile(safeq),
				    (turnstile_inheritor_t)first_thread, TURNSTILE_INHERITOR_THREAD);
			}
		}

		/* Add the thread to the result thread list */
		args->nthreads += 1;
		if (args->nthreads == 1 && safeq == waitq) {
			args->spl = splsched();
		}
		thread_lock(thread);
		thread_clear_waitq_state(thread);
		enqueue_tail(&args->threadq, &(thread->wait_links));
	}

	return first_thread;
}

/**
 * generic thread selection from a waitq (and sets to which the waitq belongs)
 *
 * Conditions:
 *	'waitq' (and the posted waitq) is locked
 *
 * Notes:
 *	Uses the optional select callback function to refine the selection
 *	of one or more threads from a waitq and any set to which the waitq
 *	belongs. The select callback is invoked once for every thread that
 *	is found to be waiting on the input args->waitq.
 *
 *	If one or more threads are selected, this may disable interrupts.
 *	The previous interrupt state is returned in args->spl and should
 *	be used in a call to splx() if threads are returned to the caller.
 */
static void
do_waitq_select_n_locked(struct waitq *waitq, struct waitq_select_args *args)
{
	thread_t first_thread = THREAD_NULL;
	struct waitq *safeq;
	waitq_flags_t remaining_eventmask = 0;
	waitq_flags_t eventmask;

	if (!waitq_irq_safe(waitq)) {
		/* JMM - add flag to waitq to avoid global lookup if no waiters */
		eventmask = _CAST_TO_EVENT_MASK(waitq);
		safeq = waitq_get_safeq(waitq);
		if (safeq == NULL) {
			/*
			 * in the WQT_TSPROXY case, if there's no turnstile,
			 * there's no queue and no waiters, so we can move straight
			 * to the waitq set recursion
			 */
			goto handle_waitq_set;
		}

		if (args->nthreads == 0) {
			args->spl = splsched();
		}
		waitq_lock(safeq);
	} else {
		eventmask = _CAST_TO_EVENT_MASK(args->event);
		safeq = waitq;
	}

	/*
	 * If the safeq doesn't have an eventmask (not global) or the event
	 * we're looking for IS set in its eventmask, then scan the threads
	 * in that queue for ones that match the original <waitq,event> pair.
	 */
	if (!waitq_is_global(safeq) ||
	    (safeq->waitq_eventmask & eventmask) == eventmask) {
		if (waitq_is_turnstile_queue(safeq)) {
			first_thread = waitq_prioq_iterate_locked(safeq, waitq,
			    args, &remaining_eventmask);
		} else {
			first_thread = waitq_queue_iterate_locked(safeq, waitq,
			    args, &remaining_eventmask);
		}

		/*
		 * Update the eventmask of global queues we just scanned:
		 * - If we selected all the threads in the queue, we can clear its
		 *   eventmask.
		 *
		 * - If we didn't find enough threads to fill our needs, then we can
		 *   assume we looked at every thread in the queue and the mask we
		 *   computed is complete - so reset it.
		 */
		if (waitq_is_global(safeq)) {
			if (waitq_empty(safeq)) {
				safeq->waitq_eventmask = 0;
			} else if (args->nthreads < args->max_threads) {
				safeq->waitq_eventmask = remaining_eventmask;
			}
		}
	}

	/*
	 * Grab the first thread in the queue if no other thread was selected.
	 * We can guarantee that no one has manipulated this thread because
	 * it's waiting on the given waitq, and we have that waitq locked.
	 */
	if (args->nthreads == 0 && first_thread != THREAD_NULL) {
		/* we know this is the first (and only) thread */
		args->nthreads += 1;
		if (safeq == waitq) {
			args->spl = splsched();
		}

		thread_lock(first_thread);
		waitq_thread_remove(safeq, first_thread);
		enqueue_tail(&args->threadq, &first_thread->wait_links);
	}

	/* unlock the safe queue if we locked one above */
	if (safeq != waitq) {
		waitq_unlock(safeq);
		if (args->nthreads == 0) {
			splx(args->spl);
			args->spl = 0;
		}
	}

	if (args->nthreads >= args->max_threads) {
		return;
	}

handle_waitq_set:
	/*
	 * If this waitq is a member of any wait queue sets, we need to look
	 * for waiting thread(s) in any of those sets, and prepost all sets that
	 * don't have active waiters.
	 *
	 * We do not need to recurse into sets for non NO_EVENT64 events,
	 * threads never wait on sets with a non 0 event.
	 */
	if (args->event == NO_EVENT64) {
		wql_walk_sets(waitq, ^(struct waitq_link *lnk){
			return waitq_select_walk_cb(lnk, waitq, args);
		});
	}
}

static void
waitq_select_args_prepare(struct waitq_select_args *args)
{
	queue_init(&args->threadq);
}

/**
 * link walk callback invoked once for each set to which a waitq belongs
 *
 * Conditions:
 *	initial waitq is locked
 *	thread is unlocked
 *
 * Notes:
 *	This may disable interrupts and early-out of the full DAG link walk by
 *	returning WQ_ITERATE_FOUND. In this case, the returned thread has
 *	been removed from the waitq, it's waitq state has been reset, and the
 *	caller is responsible to call splx() with the returned interrupt state
 *	in ctx->spl.
 */
static int
waitq_select_thread_cb(struct waitq_set *wqset, thread_t thread,
    event64_t event, spl_t *spl)
{
	struct waitq *wqsetq;
	struct waitq *safeq;
	spl_t s;

	wqsetq = &wqset->wqset_q;
	assert(!waitq_irq_safe(wqsetq));

	waitq_set_lock(wqset);

	s = splsched();

	/* find and lock the interrupt-safe waitq the thread is thought to be on */
	safeq = waitq_get_safeq(wqsetq);
	waitq_lock(safeq);

	thread_lock(thread);

	if ((thread->waitq == wqsetq) && (thread->wait_event == event)) {
		waitq_thread_remove(wqsetq, thread);
		waitq_unlock(safeq);
		waitq_set_unlock(wqset);
		/*
		 * thread still locked,
		 * return non-zero to break out of WQS walk
		 */
		*spl = s;
		return WQ_ITERATE_FOUND;
	}

	thread_unlock(thread);
	waitq_set_unlock(wqset);
	waitq_unlock(safeq);
	splx(s);

	return WQ_ITERATE_CONTINUE;
}

/**
 * returns KERN_SUCCESS and locks 'thread' if-and-only-if 'thread' is waiting
 * on 'waitq' (or any set to which waitq belongs) for 'event'
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is unlocked
 */
static kern_return_t
waitq_select_thread_locked(struct waitq *waitq, event64_t event,
    thread_t thread, spl_t *spl)
{
	struct waitq *safeq;
	kern_return_t kr;
	spl_t s;

	/* Find and lock the interrupts disabled queue the thread is actually on */
	if (!waitq_irq_safe(waitq)) {
		safeq = waitq_get_safeq(waitq);
		if (safeq == NULL) {
			/*
			 * in the WQT_TSPROXY case, if there's no turnstile,
			 * there's no queue and no waiters, so we can move straight
			 * to the waitq set recursion
			 */
			goto handle_waitq_set;
		}

		s = splsched();
		waitq_lock(safeq);
	} else {
		s = splsched();
		safeq = waitq;
	}

	thread_lock(thread);

	if ((thread->waitq == waitq) && (thread->wait_event == event)) {
		waitq_thread_remove(safeq, thread);
		*spl = s;
		/* thread still locked */
		return KERN_SUCCESS;
	}

	thread_unlock(thread);

	if (safeq != waitq) {
		waitq_unlock(safeq);
	}

	splx(s);

handle_waitq_set:
	if (event != NO_EVENT64) {
		/*
		 * We do not need to recurse into sets for non NO_EVENT64
		 * events, threads never wait on sets with a non 0 event.
		 */
		return KERN_NOT_WAITING;
	}

	/*
	 * The thread may be waiting on a wait queue set to which
	 * the input 'waitq' belongs. Go look for the thread in
	 * all wait queue sets. If it's there, we'll remove it
	 * because it's equivalent to waiting directly on the input waitq.
	 */
	kr = wql_walk_sets(waitq, ^(struct waitq_link *lnk){
		return waitq_select_thread_cb(lnk->wql_set,
		thread, event, spl);
	});

	/* we found a thread, return success */
	return kr == WQ_ITERATE_FOUND ? KERN_SUCCESS : KERN_NOT_WAITING;
}

/**
 * declare a thread's intent to wait on 'waitq' for 'wait_event'
 *
 * Conditions:
 *	'waitq' is locked
 */
wait_result_t
waitq_assert_wait64_locked(struct waitq *waitq,
    event64_t wait_event,
    wait_interrupt_t interruptible,
    wait_timeout_urgency_t urgency,
    uint64_t deadline,
    uint64_t leeway,
    thread_t thread)
{
	wait_result_t wait_result;
	struct waitq *safeq;
	uintptr_t eventmask;
	spl_t s;


	/*
	 * Warning: Do _not_ place debugging print statements here.
	 *          The waitq is locked!
	 */
	assert(!thread->started || thread == current_thread());

	if (thread->waitq != NULL) {
		panic("thread already waiting on %p", thread->waitq);
	}

	if (waitq_is_set(waitq)) {
		struct waitq_set *wqset = (struct waitq_set *)waitq;
		bool found = false;

		assert(wait_event == NO_EVENT64);

		/*
		 * early-out if the thread is waiting on a wait queue set
		 * that has already been pre-posted.
		 */
		if (wqset->wqset_q.waitq_portset) {
			int ret;

			/*
			 * Run through the list of potential preposts. Because
			 * this is a hot path, we short-circuit the iteration
			 * if we find just one prepost object.
			 */
			ret = wq_prepost_foreach_locked(wqset,
			    ^(struct wq_prepost *wqp, struct waitq *wq) {
				(void)wqp; (void)wq;
				return WQ_ITERATE_FOUND;
			});
			found = ret == WQ_ITERATE_FOUND;
		} else if (wqset->wqset_prepost_id == WQSET_PREPOSTED_ANON) {
			found = true;
		}

		if (found) {
			s = splsched();
			thread_lock(thread);
			thread->wait_result = THREAD_AWAKENED;
			thread_unlock(thread);
			splx(s);
			return THREAD_AWAKENED;
		}
	}

	s = splsched();

	/*
	 * If already dealing with an irq safe wait queue, we are all set.
	 * Otherwise, determine a global queue to use and lock it.
	 */
	if (!waitq_irq_safe(waitq)) {
		safeq = waitq_get_safeq(waitq);
		if (__improbable(safeq == NULL)) {
			panic("Trying to assert_wait on a turnstile proxy "
			    "that hasn't been donated one (waitq: %p)", waitq);
		}
		eventmask = _CAST_TO_EVENT_MASK(waitq);
		waitq_lock(safeq);
	} else {
		safeq = waitq;
		eventmask = _CAST_TO_EVENT_MASK(wait_event);
	}

	/* lock the thread now that we have the irq-safe waitq locked */
	thread_lock(thread);

	/*
	 * This is the extent to which we currently take scheduling attributes
	 * into account.  If the thread is vm priviledged, we stick it at
	 * the front of the queue.  Later, these queues will honor the policy
	 * value set at waitq_init time.
	 */
	wait_result = thread_mark_wait_locked(thread, interruptible);
	/* thread->wait_result has been set */
	if (wait_result == THREAD_WAITING) {
		waitq_thread_insert(safeq, thread, waitq, wait_event);

		if (deadline != 0) {
			boolean_t act;

			act = timer_call_enter_with_leeway(&thread->wait_timer,
			    NULL,
			    deadline, leeway,
			    urgency, FALSE);
			if (!act) {
				thread->wait_timer_active++;
			}
			thread->wait_timer_is_set = TRUE;
		}

		if (waitq_is_global(safeq)) {
			safeq->waitq_eventmask |= eventmask;
		}

		waitq_stats_count_wait(waitq);
	}

	/* unlock the thread */
	thread_unlock(thread);

	/* update the inheritor's thread priority if the waitq is embedded in turnstile */
	if (waitq_is_turnstile_queue(safeq) && wait_result == THREAD_WAITING) {
		turnstile_recompute_priority_locked(waitq_to_turnstile(safeq));
		turnstile_update_inheritor_locked(waitq_to_turnstile(safeq));
	}

	/* unlock the safeq if we locked it here */
	if (safeq != waitq) {
		waitq_unlock(safeq);
	}

	splx(s);

	return wait_result;
}

/**
 * remove 'thread' from its current blocking state on 'waitq'
 *
 * Conditions:
 *	'thread' is locked
 *
 * Notes:
 *	This function is only used by clear_wait_internal in sched_prim.c
 *	(which itself is called by the timer wakeup path and clear_wait()).
 *
 *	If true is returned, then the thread has been pulled successfuly.
 *
 *	If false is returned, then behavior depends on the
 *	CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID being enabled or not.
 *	When CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID is set,
 *	then waitq_pull_thread_locked() failing is final,
 *	else it just means the waitq lock couldn't be taken
 *	and it needs to be retried.
 */
bool
waitq_pull_thread_locked(struct waitq *waitq, thread_t thread)
{
	struct waitq *safeq;

	assert_thread_magic(thread);
	assert(thread->waitq == waitq);

	/* Find the interrupts disabled queue thread is waiting on */
	if (!waitq_irq_safe(waitq)) {
		safeq = waitq_get_safeq(waitq);
		if (__improbable(safeq == NULL)) {
			panic("Trying to clear_wait on a turnstile proxy "
			    "that hasn't been donated one (waitq: %p)", waitq);
		}
	} else {
		safeq = waitq;
	}

	/* thread is already locked so have to try for the waitq lock */
	if (!waitq_lock_try(safeq)) {
#if CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID
		/*
		 * When CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID is on,
		 * all IRQ-safe wait queues are either either global,
		 * or allocated from zones which support using
		 * waitq_lock_allow_invalid().
		 *
		 * We hence can resolve the locking inversion safely.
		 */
		bool locked;

		thread_unlock(thread);
		locked = waitq_lock_allow_invalid(safeq);
		thread_lock(thread);
		if (waitq != thread->waitq) {
			/*
			 * the waitq this thread was waiting on either is invalid,
			 * or changed, or both. Either way, we're done.
			 */
			if (locked) {
				waitq_unlock(safeq);
			}
			return false;
		}
		if (__improbable(!locked)) {
			panic("Thread %p is blocked on an invalid waitq %p",
			    thread, waitq);
		}
#else
		return false;
#endif /* CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID */
	}

	waitq_thread_remove(safeq, thread);
	waitq_stats_count_clear_wakeup(waitq);
	waitq_unlock(safeq);
	return true;
}


static inline void
maybe_adjust_thread_pri(thread_t thread, int priority,
    __kdebug_only struct waitq *waitq)
{
	/*
	 * If the caller is requesting the waitq subsystem to promote the
	 * priority of the awoken thread, then boost the thread's priority to
	 * the default WAITQ_BOOST_PRIORITY (if it's not already equal or
	 * higher priority).  This boost must be removed via a call to
	 * waitq_clear_promotion_locked before the thread waits again.
	 *
	 * WAITQ_PROMOTE_PRIORITY is -2.
	 * Anything above 0 represents a mutex promotion.
	 * The default 'no action' value is -1.
	 * TODO: define this in a header
	 */
	if (priority == WAITQ_PROMOTE_PRIORITY) {
		uintptr_t trace_waitq = 0;
		if (__improbable(kdebug_enable)) {
			trace_waitq = VM_KERNEL_UNSLIDE_OR_PERM(waitq);
		}

		sched_thread_promote_reason(thread, TH_SFLAG_WAITQ_PROMOTED, trace_waitq);
	}
}

static void
waitq_select_queue_flush(struct waitq *waitq, struct waitq_select_args *args)
{
	thread_t thread = THREAD_NULL;
	__assert_only kern_return_t kr;

	qe_foreach_element_safe(thread, &args->threadq, wait_links) {
		remqueue(&thread->wait_links);
		maybe_adjust_thread_pri(thread, args->priority, waitq);
		kr = thread_go(thread, args->result, args->options);
		assert(kr == KERN_SUCCESS);
		thread_unlock(thread);
	}
}

/*
 * Clear a potential thread priority promotion from a waitq wakeup
 * with WAITQ_PROMOTE_PRIORITY.
 *
 * This must be called on the thread which was woken up with TH_SFLAG_WAITQ_PROMOTED.
 */
void
waitq_clear_promotion_locked(struct waitq *waitq, thread_t thread)
{
	spl_t s = 0;

	assert(waitq_held(waitq));
	assert(thread != THREAD_NULL);
	assert(thread == current_thread());

	/* This flag is only cleared by the thread itself, so safe to check outside lock */
	if ((thread->sched_flags & TH_SFLAG_WAITQ_PROMOTED) != TH_SFLAG_WAITQ_PROMOTED) {
		return;
	}

	if (!waitq_irq_safe(waitq)) {
		s = splsched();
	}
	thread_lock(thread);

	sched_thread_unpromote_reason(thread, TH_SFLAG_WAITQ_PROMOTED, 0);

	thread_unlock(thread);
	if (!waitq_irq_safe(waitq)) {
		splx(s);
	}
}

/**
 * wakeup all threads waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts
 *	and re-adjust thread priority of each awoken thread.
 *
 *	If the input 'lock_state' == WAITQ_UNLOCK then the waitq will have
 *	been unlocked before calling thread_go() on any returned threads, and
 *	is guaranteed to be unlocked upon function return.
 */
kern_return_t
waitq_wakeup64_all_locked(struct waitq *waitq,
    event64_t wake_event,
    wait_result_t result,
    uint64_t *reserved_preposts,
    int priority,
    waitq_lock_state_t lock_state)
{
	struct waitq_select_args args = {
		.event = wake_event,
		.priority = priority,
		.reserved_preposts = reserved_preposts,
		.max_threads = UINT32_MAX,
		.result = result,
		.options = WQ_OPTION_NONE,
	};

	assert(waitq_held(waitq));

	waitq_select_args_prepare(&args);
	do_waitq_select_n_locked(waitq, &args);
	waitq_stats_count_wakeup(waitq, args.nthreads);

	if (lock_state == WAITQ_UNLOCK) {
		waitq_unlock(waitq);
	}

	waitq_select_queue_flush(waitq, &args);

	if (args.nthreads > 0) {
		splx(args.spl);
		return KERN_SUCCESS;
	}

	return KERN_NOT_WAITING;
}

/**
 * wakeup one thread waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts.
 */
kern_return_t
waitq_wakeup64_one_locked(struct waitq *waitq,
    event64_t wake_event,
    wait_result_t result,
    uint64_t *reserved_preposts,
    int priority,
    waitq_lock_state_t lock_state,
    waitq_options_t option)
{
	struct waitq_select_args args = {
		.event = wake_event,
		.priority = priority,
		.reserved_preposts = reserved_preposts,
		.max_threads = 1,
		.result = result,
		.options = option,
	};

	assert(waitq_held(waitq));

	waitq_select_args_prepare(&args);
	do_waitq_select_n_locked(waitq, &args);
	waitq_stats_count_wakeup(waitq, args.nthreads);

	if (lock_state == WAITQ_UNLOCK) {
		waitq_unlock(waitq);
	}

	waitq_select_queue_flush(waitq, &args);

	if (args.nthreads > 0) {
		splx(args.spl);
		return KERN_SUCCESS;
	}

	return KERN_NOT_WAITING;
}

/**
 * wakeup one thread waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Returns:
 *	A locked, runnable thread.
 *	If return value is non-NULL, interrupts have also
 *	been disabled, and the caller is responsible to call
 *	splx() with the returned '*spl' value.
 */
thread_t
waitq_wakeup64_identify_locked(struct waitq     *waitq,
    event64_t        wake_event,
    wait_result_t    result,
    spl_t            *spl,
    uint64_t         *reserved_preposts,
    int              priority,
    waitq_lock_state_t lock_state)
{
	struct waitq_select_args args = {
		.event = wake_event,
		.priority = priority,
		.reserved_preposts = reserved_preposts,
		.max_threads = 1,
	};
	thread_t thread = THREAD_NULL;

	assert(waitq_held(waitq));

	waitq_select_args_prepare(&args);
	do_waitq_select_n_locked(waitq, &args);
	waitq_stats_count_wakeup(waitq, args.nthreads);

	if (lock_state == WAITQ_UNLOCK) {
		waitq_unlock(waitq);
	}

	if (args.nthreads > 0) {
		kern_return_t __assert_only ret;

		thread = qe_dequeue_head(&args.threadq, struct thread, wait_links);
		assert(args.nthreads == 1 && queue_empty(&args.threadq));

		maybe_adjust_thread_pri(thread, priority, waitq);
		ret = thread_go(thread, result, WQ_OPTION_NONE);
		assert(ret == KERN_SUCCESS);
		*spl = args.spl;
	}

	return thread; /* locked if not NULL (caller responsible for spl) */
}

/**
 * wakeup a specific thread iff it's waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is unlocked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts
 *
 *	If the input lock_state == WAITQ_UNLOCK then the waitq will have been
 *	unlocked before calling thread_go() if 'thread' is to be awoken, and
 *	is guaranteed to be unlocked upon function return.
 */
kern_return_t
waitq_wakeup64_thread_locked(struct waitq *waitq,
    event64_t wake_event,
    thread_t thread,
    wait_result_t result,
    waitq_lock_state_t lock_state)
{
	kern_return_t ret;
	spl_t th_spl;

	assert(waitq_held(waitq));
	assert_thread_magic(thread);

	/*
	 * See if the thread was still waiting there.  If so, it got
	 * dequeued and returned locked.
	 */
	ret = waitq_select_thread_locked(waitq, wake_event, thread, &th_spl);
	waitq_stats_count_wakeup(waitq, ret == KERN_SUCCESS ? 1 : 0);

	if (lock_state == WAITQ_UNLOCK) {
		waitq_unlock(waitq);
	}

	if (ret != KERN_SUCCESS) {
		return KERN_NOT_WAITING;
	}

	ret = thread_go(thread, result, WQ_OPTION_NONE);
	assert(ret == KERN_SUCCESS);
	thread_unlock(thread);
	splx(th_spl);

	return ret;
}



/* ----------------------------------------------------------------------
 *
 * In-Kernel API
 *
 * ---------------------------------------------------------------------- */

#if CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID && MACH_ASSERT
/*
 * CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID relies on waitq memory to always
 * be one of:
 * - a waitq
 * - zeroed memory
 * - unmapped memory
 *
 * This function allows to assert that this generally looks true.
 */
#include <kern/zalloc_internal.h>

extern char __data_segment_start[] __SEGMENT_START_SYM("__DATA");
extern char __data_segment_end[] __SEGMENT_END_SYM("__DATA");

static inline bool
waitq_is_in_kernel_data_or_adequate_zone(struct waitq *waitq)
{
	zone_id_t zid;

	if (waitq_is_global(waitq)) {
		return true;
	}

	zid = zone_id_for_native_element(waitq, sizeof(*waitq));
	if (zid != ZONE_ID_INVALID) {
		return zone_security_array[zid].z_va_sequester &&
		       zone_array[zid].kasan_noquarantine;
	}

	const char *dataStart;
	const char *dataEnd;

#if PLATFORM_MACOS // 78481451
	unsigned long sz;
	dataStart = getsegdatafromheader(&_mh_execute_header, "__DATA", &sz);
	dataEnd = dataStart + sz;
#else
	dataStart = __data_segment_start;
	dataEnd = __data_segment_end;
#endif

	/* sfi, thread calls, ... */
	return dataStart <= (char *)waitq && (char *)(waitq + 1) <= dataEnd;
}
#endif

/**
 * initialize a waitq object
 */
void
waitq_init(struct waitq *waitq, int policy)
{
	assert(waitq != NULL);
	assert((policy & SYNC_POLICY_FIXED_PRIORITY) == 0);

#if CONFIG_WAITQ_IRQSAFE_ALLOW_INVALID
	if (policy & SYNC_POLICY_DISABLE_IRQ) {
		assert(waitq_is_in_kernel_data_or_adequate_zone(waitq));
	}
#endif

	waitq->waitq_fifo = ((policy & SYNC_POLICY_REVERSED) == 0);
	waitq->waitq_irq = !!(policy & SYNC_POLICY_DISABLE_IRQ);
	if (policy & SYNC_POLICY_TURNSTILE_PROXY) {
		waitq->waitq_type = WQT_TSPROXY;
	} else {
		waitq->waitq_type = WQT_QUEUE;
	}
	waitq->waitq_turnstile = !!(policy & SYNC_POLICY_TURNSTILE);
	waitq->waitq_eventmask = 0;

	waitq->waitq_set_id = WAITQ_REF_NULL;
	waitq->waitq_prepost_id = 0;

	if (waitq_is_turnstile_queue(waitq)) {
		/* For turnstile, initialize it as a priority queue */
		priority_queue_init(&waitq->waitq_prio_queue);
		assert(waitq->waitq_fifo == 0);
	} else if (policy & SYNC_POLICY_TURNSTILE_PROXY) {
		waitq->waitq_ts = TURNSTILE_NULL;
		waitq->waitq_tspriv = NULL;
	} else {
		queue_init(&waitq->waitq_queue);
	}

	if (policy & SYNC_POLICY_INIT_LOCKED) {
		hw_lck_ticket_init_locked(&waitq->waitq_interlock, &waitq_lck_grp);
	} else {
		hw_lck_ticket_init(&waitq->waitq_interlock, &waitq_lck_grp);
	}
}

/**
 * cleanup any link/prepost table resources associated with a waitq
 */
void
waitq_deinit(struct waitq *waitq)
{
	assert(!waitq_is_set(waitq));

	if (waitq_valid(waitq)) {
		/*
		 * We must invalidate under the lock as many waitqs
		 * use this invalidation state for their logic (see ports)
		 * and changing it outside of a lock hold might mess
		 * the state machine of the enclosing object.
		 */
		waitq_lock(waitq);
		waitq_invalidate(waitq);
		if (waitq_irq_safe(waitq)) {
			waitq_unlock(waitq);
		} else {
			waitq_unlink_all_unlock(waitq);
		}
	}

	hw_lck_ticket_destroy(&waitq->waitq_interlock, true, &waitq_lck_grp);

	/*
	 * it is the responsibility of the waitq client to wake up all waiters
	 */
#if MACH_ASSERT
	if (waitq_is_turnstile_queue(waitq)) {
		assert(priority_queue_empty(&waitq->waitq_prio_queue));
	} else if (waitq_is_turnstile_proxy(waitq)) {
		assert(waitq->waitq_ts == TURNSTILE_NULL);
	} else if (waitq_is_queue(waitq)) {
		assert(queue_empty(&waitq->waitq_queue));
	} else {
		assert(waitq->waitq_type == WQT_INVALID);
	}
#endif // MACH_ASSERT
}

/**
 * Invalidate a waitq.
 *
 * It is the responsibility of the caller to make sure that:
 * - all waiters are woken up
 * - linkages and preposts are cleared (non IRQ Safe waitqs).
 */
void
waitq_invalidate(struct waitq *waitq)
{
	hw_lck_ticket_invalidate(&waitq->waitq_interlock);
}

/**
 * invalidate the given wq_prepost chain
 */
static void
wqset_clear_prepost_chain(uint64_t prepost_id)
{
	if (prepost_id == WQSET_PREPOSTED_ANON) {
		return;
	}

	(void)wq_prepost_iterate(prepost_id,
	    ^(struct wq_prepost *wqp, struct waitq __unused *waitq) {
		if (wqp_type(wqp) == WQP_POST) {
		        wq_prepost_invalidate(wqp);
		}
		return WQ_ITERATE_CONTINUE;
	});
}

/**
 * initialize a waitq set object
 */
void
waitq_set_init(struct waitq_set *wqset, int policy)
{
	memset(wqset, 0, sizeof(*wqset));

	waitq_init(&wqset->wqset_q, policy);
	wqset->wqset_q.waitq_portset = (policy & SYNC_POLICY_PORT_SET) != 0;
	wqset->wqset_q.waitq_type = WQT_SET;

	/* Lazy allocate the link only when an actual id is needed.  */
	wqset->wqset_id = WQSET_NOT_LINKED;
}

void
waitq_set_reset_anon_prepost(struct waitq_set *wqset)
{
	assert(waitq_set_is_valid(wqset) && !wqset->wqset_q.waitq_portset);
	wqset->wqset_prepost_id = 0;
}

#if DEVELOPMENT || DEBUG
int
sysctl_helper_waitq_set_nelem(void)
{
	return ltable_nelem(&g_wqlinktable);
}
#endif

/**
 * initialize a waitq set link.
 *
 * Conditions:
 *	may block
 *	locks and unlocks the waiq set lock
 *
 */
void
waitq_set_lazy_init_link(struct waitq_set *wqset)
{
	struct waitq_link *link;

	assert(get_preemption_level() == 0 && waitq_wait_possible(current_thread()));

	waitq_set_lock(wqset);
	if (wqset->wqset_id != WQSET_NOT_LINKED) {
		waitq_set_unlock(wqset);
		return;
	}

	waitq_set_unlock(wqset);

	link = wql_alloc_link(WQL_WQS);
	if (!link) {
		panic("Can't allocate link object for waitq set: %p", wqset);
	}

	link->wql_set = wqset;

	waitq_set_lock(wqset);
	if (wqset->wqset_id == WQSET_NOT_LINKED) {
		assert(waitq_set_is_valid(wqset));
		wql_mkvalid(link);
		wqset->wqset_id = link->wql_setid.id;
	}
	waitq_set_unlock(wqset);

	wql_put_link(link);
}

/**
 * clear out / release any resources associated with a waitq set
 *
 * Conditions:
 *	may block
 *	waitqset is locked
 * Note:
 *	This will render the waitq set invalid, and it must
 *	be re-initialized with waitq_set_init before it can be used again
 */
void
waitq_set_deinit_and_unlock(struct waitq_set *wqset)
{
	struct waitq_link *link = NULL;
	uint64_t set_id, prepost_id;

	assert(waitqs_is_set(wqset));

	set_id = wqset->wqset_id;

	if (waitqs_is_linked(wqset)) {
		/* grab the set's link object */
		link = wql_get_link(set_id);
		if (link) {
			wql_invalidate(link);
		}
	}

	/*
	 * always clear the wqset_id, including WQSET_NOT_LINKED,
	 * so that waitq_set_lazy_init_link() does nothing
	 * once a set is invalidated (because of course,
	 * port-sets do that).
	 */
	wqset->wqset_id = 0;

	/*
	 * This set may have a lot of preposts, or may have been a member of
	 * many other sets. To minimize spinlock hold times, we clear out the
	 * waitq set data structure under the lock-hold, but don't clear any
	 * table objects. We keep handles to the prepost and set linkage
	 * objects and free those outside the critical section.
	 */
	prepost_id = wqset->wqset_prepost_id;
	if (prepost_id) {
		assert(link != NULL);
		wqset->wqset_prepost_id = 0;
	}

	wqset->wqset_q.waitq_fifo = 0;
	waitq_invalidate(&wqset->wqset_q);

	/* don't clear the 'waitq_irq' bit: it's used in locking! */
	wqset->wqset_q.waitq_eventmask = 0;

	waitq_set_unlock(wqset);

	/* drop / unlink all the prepost table objects */
	if (prepost_id) {
		wqset_clear_prepost_chain(prepost_id);
	}

	if (link) {
		/*
		 * wql_walk_sets may race with us for access to the waitq set.
		 * If wql_walk_sets has a reference to the set, then we should wait
		 * until the link's refcount goes to 1 (our reference) before we exit
		 * this function. That way we ensure that the waitq set memory will
		 * remain valid even though it's been cleared out.
		 */
		while (wql_refcnt(link) > 1) {
			delay(1);
		}
		wql_put_link(link);
	}

	hw_lck_ticket_destroy(&wqset->wqset_q.waitq_interlock, true, &waitq_lck_grp);
}


/**
 * clear out / release any resources associated with a waitq set
 *
 * Conditions:
 *	may block
 * Note:
 *	This will render the waitq set invalid, and it must
 *	be re-initialized with waitq_set_init before it can be used again
 */
void
waitq_set_deinit(struct waitq_set *wqset)
{
	if (!waitqs_is_set(wqset)) {
		panic("trying to de-initialize an invalid wqset @%p", wqset);
	}

	assert(!waitq_irq_safe(&wqset->wqset_q));

	waitq_set_lock(wqset);

	waitq_set_deinit_and_unlock(wqset);
}

/**
 * clear all preposts originating from 'waitq'
 *
 * Conditions:
 *	'waitq' locked
 *	may (rarely) spin waiting for another on-core thread to
 *	release the last reference to the waitq's prepost link object
 *
 * NOTE:
 *	If this function needs to spin, it will drop the waitq lock!
 *	The return value of the function indicates whether or not this
 *	happened: 1 == lock was dropped, 0 == lock held
 */
int
waitq_clear_prepost_locked(struct waitq *waitq)
{
	struct wq_prepost *wqp;
	int dropped_lock = 0;

	assert(!waitq_irq_safe(waitq));

	if (waitq->waitq_prepost_id == 0) {
		return 0;
	}

	wqp = wq_prepost_get(waitq->waitq_prepost_id);
	waitq->waitq_prepost_id = 0;
	if (wqp) {
		wqdbg_v("invalidate prepost 0x%llx (refcnt:%d)",
		    wqp->wqp_prepostid.id, wqp_refcnt(wqp));
		wq_prepost_invalidate(wqp);
		while (wqp_refcnt(wqp) > 1) {
			/*
			 * Some other thread must have raced us to grab a link
			 * object reference before we invalidated it. This
			 * means that they are probably trying to access the
			 * waitq to which the prepost object points. We need
			 * to wait here until the other thread drops their
			 * reference. We know that no one else can get a
			 * reference (the object has been invalidated), and
			 * that prepost references are short-lived (dropped on
			 * a call to wq_prepost_put). We also know that no one
			 * blocks while holding a reference therefore the
			 * other reference holder must be on-core. We'll just
			 * sit and wait for the other reference to be dropped.
			 */
			disable_preemption();

			waitq_unlock(waitq);
			dropped_lock = 1;
			/*
			 * don't yield here, just spin and assume the other
			 * consumer is already on core...
			 */
			delay(1);

			waitq_lock(waitq);

			enable_preemption();
		}

		wq_prepost_put(wqp);
	}

	return dropped_lock;
}

/**
 * return a the waitq's prepost object ID (allocate if necessary)
 *
 * Conditions:
 *	'waitq' is unlocked
 */
uint64_t
waitq_get_prepost_id(struct waitq *waitq)
{
	struct wq_prepost *wqp;
	uint64_t wqp_id = 0;

	if (!waitq_valid(waitq)) {
		return 0;
	}

	assert(waitq_is_queue(waitq) || waitq_is_turnstile_proxy(waitq));
	assert(!waitq_irq_safe(waitq));

	waitq_lock(waitq);

	if (!waitq_valid(waitq)) {
		goto out_unlock;
	}

	if (waitq->waitq_prepost_id) {
		wqp_id = waitq->waitq_prepost_id;
		goto out_unlock;
	}

	/* don't hold a spinlock while allocating a prepost object */
	waitq_unlock(waitq);

	wqp = wq_prepost_alloc(WQP_WQ, 1);
	if (!wqp) {
		return 0;
	}

	/* re-acquire the waitq lock */
	waitq_lock(waitq);

	if (!waitq_valid(waitq)) {
		wq_prepost_put(wqp);
		wqp_id = 0;
		goto out_unlock;
	}

	if (waitq->waitq_prepost_id) {
		/* we were beat by someone else */
		wq_prepost_put(wqp);
		wqp_id = waitq->waitq_prepost_id;
		goto out_unlock;
	}

	wqp->wqp_wq.wqp_wq_ptr = waitq;

	wqp_set_valid(wqp);
	wqp_id = wqp->wqp_prepostid.id;
	waitq->waitq_prepost_id = wqp_id;

	wq_prepost_put(wqp);

out_unlock:
	waitq_unlock(waitq);

	return wqp_id;
}


/**
 * determine if 'waitq' is a member of 'wqset'
 *
 * Conditions:
 *  'waitq' is locked
 *	'wqset' is not locked
 *	may disable and re-enable interrupts while locking 'waitq'
 */
bool
waitq_member_locked(struct waitq *waitq, struct waitq_set *wqset)
{
	waitq_ref_t root_ref = waitq->waitq_set_id;
	uint64_t setid = wqset->wqset_id;

	if (!waitqs_is_linked(wqset) || wqr_is_null(root_ref)) {
		return false;
	}

	if (!wqr_is_ptr(root_ref)) {
		return wqr_is_equal(root_ref, setid);
	}

	waitq_foreach_link(link, root_ref) {
		if (link->wql_node == setid) {
			return true;
		}
		if (!wqr_is_ptr(link->wql_next)) {
			return wqr_is_equal(link->wql_next, setid);
		}
	}

	__builtin_unreachable();
}

__abortlike
static void
__waitq_link_arguments_panic(struct waitq *waitq, struct waitq_set *wqset)
{
	if (!waitq_valid(waitq) || waitq_irq_safe(waitq)) {
		panic("Invalid waitq: %p", waitq);
	}
	if (!waitq_is_queue(waitq) && !waitq_is_turnstile_proxy(waitq)) {
		panic("Invalid waitq type: %p:%d", waitq, waitq->waitq_type);
	}
	panic("Invalid waitq-set: %p", wqset);
}

static inline void
__waitq_link_arguments_validate(struct waitq *waitq, struct waitq_set *wqset)
{
	if (!waitq_valid(waitq) || waitq_irq_safe(waitq) ||
	    (!waitq_is_queue(waitq) && !waitq_is_turnstile_proxy(waitq)) ||
	    !waitqs_is_set(wqset)) {
		__waitq_link_arguments_panic(waitq, wqset);
	}
}

__abortlike
static void
__waitq_invalid_panic(struct waitq *waitq)
{
	panic("Invalid waitq: %p", waitq);
}


static void
__waitq_validate(struct waitq *waitq)
{
	if (!waitq_valid(waitq)) {
		__waitq_invalid_panic(waitq);
	}
}

/**
 * pre-allocate a waitq link structure from the link table
 */
waitq_ref_t
waitq_link_reserve(void)
{
	return wqr_make(zalloc_flags(waitq_link_zone, Z_WAITOK | Z_ZERO));
}

/**
 * release a pre-allocated waitq link structure
 */
void
waitq_link_release(waitq_ref_t ref)
{
	struct waitq_link *link = wqr_ptr_raw(ref);

	if (link) {
		zfree(waitq_link_zone, link);
#if CONFIG_LTABLE_STATS
		g_wqlinktable.nreserved_releases += 1;
#endif
	}
}

/**
 * link 'waitq' to 'wqset' using the 'link' structure
 *
 * Conditions:
 *	'waitq' is locked
 *	caller should have a reference to the 'link' object,
 *	that this function consumes
 */
static kern_return_t
waitq_link_internal(struct waitq *waitq, struct waitq_set *wqset,
    waitq_ref_t link_ref)
{
	waitq_ref_t *refp;
	uint64_t setid = wqset->wqset_id;
	uint64_t *dead_ref = NULL;

	assert(waitq_held(waitq));
	assert(waitqs_is_linked(wqset));

	/*
	 * If the waitq_set_id field is empty, then this waitq is not
	 * a member of any other set. All we have to do is update the
	 * field.
	 */
	refp = &waitq->waitq_set_id;
	if (wqr_is_null(*refp)) {
		*refp = wqr_make(setid);
		waitq_link_release(link_ref);
		return KERN_SUCCESS;
	}

	/*
	 * Check to see if it's already a member of the set.
	 * Similar to waitq_member_locked() but remember
	 * the last invalid ref we met to try to reuse it.
	 *
	 * This allows us not to have to do any expensive
	 * ltable get/set operations, while still being able to "GC" links.
	 */
	for (;;) {
		if (wqr_is_ptr(*refp)) {
			struct waitq_link *tmp = wqr_ptr_raw(*refp);

			if (!wql_link_valid(tmp->wql_node)) {
				dead_ref = &tmp->wql_node;
			} else if (tmp->wql_node == setid) {
				waitq_link_release(link_ref);
				return KERN_ALREADY_IN_SET;
			}

			refp = &tmp->wql_next;
		} else {
			if (!wql_link_valid(refp->wqr_value)) {
				dead_ref = &refp->wqr_value;
			} else if (wqr_is_equal(*refp, setid)) {
				waitq_link_release(link_ref);
				return KERN_ALREADY_IN_SET;
			}
			break;
		}
	}

	/*
	 * This wait queue is _not_ a member of the given set.
	 *
	 * If we found an empty "ref" during traversal, reuse it,
	 * else use our previously allocated link object,
	 * and hook it up to the wait queue.
	 *
	 * Note that it's possible that one or more of the wait queue sets to
	 * which the wait queue belongs was invalidated before we allocated
	 * this link object. That's OK because the next time we use that
	 * object we'll just ignore it.
	 */

	if (dead_ref) {
		*dead_ref = setid;
		waitq_link_release(link_ref);
		return KERN_SUCCESS;
	}

	waitq_ref_t root_ref = waitq->waitq_set_id;
	struct waitq_link *link = wqr_ptr_raw(link_ref);

	if (wqr_is_ptr(root_ref)) {
		struct waitq_link *root = wqr_ptr_raw(root_ref);

		link->wql_count = root->wql_count + 1;
		root->wql_count = LT_IDX_MAX;
	} else {
		link->wql_count = 2;
	}
	link->wql_next = root_ref;
	link->wql_node = setid;
	link->wqte.lt_bits = WQL_LINK << LT_BITS_TYPE_SHIFT;

	waitq->waitq_set_id = link_ref;

	return KERN_SUCCESS;
}

/**
 * link 'waitq' to 'wqset'
 *
 * Conditions:
 *	if 'lock_state' contains WAITQ_SHOULD_LOCK, 'waitq' must be unlocked.
 *	Otherwise, 'waitq' must be locked.
 *
 *	may (rarely) block on link table allocation if the table has to grow,
 *	and no 'reserved_link' object is passed.
 *
 *	may block and acquire wqset lock if the wqset passed has no link.
 *
 * Notes:
 *	The caller can guarantee that this function will never block by
 *	- pre-allocating a link table object and passing its ID in 'reserved_link'
 *      - and pre-allocating the waitq set link calling waitq_set_lazy_init_link.
 *      It is not possible to provide a reserved_link without having also linked
 *	the wqset.
 */
kern_return_t
waitq_link(struct waitq *waitq, struct waitq_set *wqset,
    waitq_lock_state_t lock_state, waitq_ref_t *reserved_link)
{
	kern_return_t kr;
	waitq_ref_t link;
	int should_lock = (lock_state == WAITQ_SHOULD_LOCK);

	__waitq_link_arguments_validate(waitq, wqset);

	wqdbg_v("Link waitq %p to wqset 0x%llx",
	    (void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), wqset->wqset_id);

	/*
	 * We _might_ need a new link object here, so we'll grab outside
	 * the lock because the alloc call _might_ block.
	 *
	 * If the caller reserved a link beforehand, then wql_get_link
	 * is guaranteed not to block because the caller holds an extra
	 * reference to the link which, in turn, hold a reference to the
	 * link table.
	 */
	if (!reserved_link || wqr_is_null(*reserved_link)) {
		if (!waitqs_is_linked(wqset)) {
			waitq_set_lazy_init_link(wqset);
		}

		link = waitq_link_reserve();
	} else {
		link = *reserved_link;
		/* always consume the caller's reference */
		*reserved_link = WAITQ_REF_NULL;
	}

	if (should_lock) {
		waitq_lock(waitq);
	}

	/* consumes link */
	kr = waitq_link_internal(waitq, wqset, link);

	if (should_lock) {
		waitq_unlock(waitq);
	}

	return kr;
}

/**
 * unlink 'waitq' from all wqsets and then link to 'newset'
 *
 * Conditions:
 *	waitq locked on entry, unlocked on return
 */
static void
waitq_unlink_all_unlock_internal(struct waitq *waitq, waitq_ref_t newset)
{
	waitq_ref_t old_set_id;

	assert(!waitq_irq_safe(waitq));

	old_set_id = waitq->waitq_set_id;
	waitq->waitq_set_id = newset;

	if (wqr_is_null(old_set_id)) {
		waitq_unlock(waitq);
	} else {
		/*
		 * invalidate the prepost entry for this waitq.
		 *
		 * This may drop and re-acquire the waitq lock,
		 * but that's OK because if it was added to another set
		 * and preposted to that set in the time we drop the lock,
		 * the state will remain consistent.
		 */
		(void)waitq_clear_prepost_locked(waitq);
		waitq_unlock(waitq);

		waitq_foreach_link_safe(link, old_set_id) {
			waitq_link_release(wqr_make(link));
		}
	}
}

/**
 * unlink 'waitq' from all sets to which it belongs
 *
 * Conditions:
 *	'waitq' is locked on entry
 *	returns with waitq lock dropped
 *
 * Notes:
 *	may (rarely) spin (see waitq_clear_prepost_locked)
 */
void
waitq_unlink_all_unlock(struct waitq *waitq)
{
	assert(!waitq_irq_safe(waitq));

	wqdbg_v("unlink waitq %p from all sets",
	    (void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq));

	waitq_unlink_all_unlock_internal(waitq, WAITQ_REF_NULL);
}

/**
 * unlink 'waitq' from all wqsets and then link to 'wqset'
 *
 * Conditions:
 *	waitq locked on entry, unlocked on return
 */
void
waitq_unlink_all_relink_unlock(struct waitq *waitq, struct waitq_set *wqset)
{
	__waitq_link_arguments_validate(waitq, wqset);

	wqdbg_v("Link waitq %p to wqset 0x%llx",
	    (void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), wqset->wqset_id);

	waitq_unlink_all_unlock_internal(waitq, wqr_make(wqset->wqset_id));
}

/**
 * clear out any prepost from waitq into wqset
 *
 * TODO: this could be more efficient than a linear search of
 *       the waitq set's prepost list.
 */
static void
waitq_unlink_prepost(struct waitq_set *wqset, struct waitq *unlink_wq)
{
	assert(!waitq_irq_safe(&wqset->wqset_q));

	if (!wqset->wqset_q.waitq_portset) {
		assert(wqset->wqset_prepost_id == 0 ||
		    wqset->wqset_prepost_id == WQSET_PREPOSTED_ANON);
		return;
	}

	waitq_set_lock(wqset);

	(void)wq_prepost_iterate(wqset->wqset_prepost_id,
	    ^(struct wq_prepost *wqp, struct waitq *waitq) {
		if (waitq != unlink_wq) {
		        return WQ_ITERATE_CONTINUE;
		}

		if (wqp_type(wqp) == WQP_WQ) {
		        /* this is the only prepost on this wait queue set */
		        assert(wqp->wqp_prepostid.id == wqset->wqset_prepost_id);
		        wqdbg_v("unlink wqp (WQ) 0x%llx", wqp->wqp_prepostid.id);
		        wqset->wqset_prepost_id = 0;
		} else {
		        /*
		         * The prepost object 'wqp' points to a waitq which
		         * should no longer be preposted to 'wqset'.
		         *
		         * We can remove the prepost object from the list and
		         * break out of the iteration.
		         */
		        wq_prepost_remove(wqset, wqp);
		}
		return WQ_ITERATE_BREAK;
	});

	waitq_set_unlock(wqset);
}

/**
 * unlink 'waitq' from 'wqset'
 *
 * Conditions:
 *	'waitq' is locked
 *	'wqset' is _not_ locked
 *	may (rarely) spin in prepost clear and drop/re-acquire 'waitq' lock
 *	(see waitq_clear_prepost_locked)
 */
kern_return_t
waitq_unlink_locked(struct waitq *waitq, struct waitq_set *wqset)
{
	waitq_ref_t root_ref;
	uint64_t setid;

	__waitq_link_arguments_validate(waitq, wqset);

	root_ref = waitq->waitq_set_id;

	if (wqr_is_null(root_ref)) {
		assert(waitq->waitq_prepost_id == 0);
		return KERN_NOT_IN_SET;
	}

	if (!waitqs_is_linked(wqset)) {
		/*
		 * No link has been allocated for the wqset,
		 * so no waitq could have been linked to it.
		 */
		return KERN_NOT_IN_SET;
	}

	setid = wqset->wqset_id;
	if (wqr_is_equal(root_ref, setid)) {
		/*
		 * This was the only set to which the waitq belonged: we can
		 * safely release the waitq's prepost object. It doesn't
		 * matter if this function drops and re-acquires the lock
		 * because we're not manipulating waitq state any more.
		 */
		waitq->waitq_set_id = WAITQ_REF_NULL;
		(void)waitq_clear_prepost_locked(waitq);
		return KERN_SUCCESS;
	}

	if (!wqr_is_ptr(root_ref)) {
		return KERN_NOT_IN_SET;
	}

	/*
	 * This waitq is member than strictly more than one set.
	 * Walk them all, in a fashion similar to SLIST_FOREACH_PREVPTR().
	 */

	waitq_ref_t *prev_next_p;
	struct waitq_link *root, *link, *next;
	uint32_t n;

	prev_next_p = &waitq->waitq_set_id;
	link = wqr_ptr_raw(root_ref);
	n = link->wql_count;

	for (;;) {
		if (link->wql_node == setid) {
			break;
		}
		if (wqr_is_equal(link->wql_next, setid)) {
			break;
		}
		if (!wqr_is_ptr(link->wql_next)) {
			return KERN_NOT_IN_SET;
		}

		next = wqr_ptr_raw(link->wql_next);
		if (wql_link_valid(link->wql_node)) {
			prev_next_p = &link->wql_next;
		} else {
			/*
			 * Opportunistically cull the list from dead nodes.
			 *
			 * This is about making sure the list doesn't
			 * grow unbounded, so we take shortcuts:
			 *
			 * - we use the racy wql_link_valid() rather than
			 *   a get/put() pair which is more expensive,
			 *
			 * - we don't try removing the link if the dead setid
			 *   is the tail one as it's slightly more complicated
			 *   to unlink.
			 */
			assert(n >= 3);
			root = wqr_ptr_raw(waitq->waitq_set_id);
			root->wql_count = --n;

			waitq_link_release(wqr_make(link));
			*prev_next_p = wqr_make(next);
		}
		link = next;
	}

	/*
	 * We found a link matching this waitq set
	 *
	 * 1. pop and free the element
	 * 2. update the wql_count (if we will keep a list)
	 * 3. cleanup the possible prepost of the waitq into the set
	 */

	if (link->wql_node == setid) {
		*prev_next_p = link->wql_next;
	} else {
		*prev_next_p = wqr_make(link->wql_node);
	}

	assert(n >= 2);
	if (n > 2) {
		root = wqr_ptr_raw(waitq->waitq_set_id);
		root->wql_count = n - 1;
	}

	waitq_link_release(wqr_make(link));

	waitq_unlink_prepost(wqset, waitq);
	return KERN_SUCCESS;
}

/**
 * unlink 'waitq' from 'wqset'
 *
 * Conditions:
 *	neither 'waitq' nor 'wqset' is locked
 *	may disable and re-enable interrupts
 *	may (rarely) spin in prepost clear
 *	(see waitq_clear_prepost_locked)
 */
kern_return_t
waitq_unlink(struct waitq *waitq, struct waitq_set *wqset)
{
	kern_return_t kr = KERN_SUCCESS;

	assert(waitqs_is_set(wqset));

	/*
	 * we allow the waitq to be invalid because the caller may be trying
	 * to clear out old/dirty state
	 */
	if (!waitq_valid(waitq)) {
		return KERN_INVALID_ARGUMENT;
	}

	wqdbg_v("unlink waitq %p from set 0x%llx",
	    (void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), wqset->wqset_id);

	assert(!waitq_irq_safe(waitq));

	waitq_lock(waitq);

	kr = waitq_unlink_locked(waitq, wqset);

	waitq_unlock(waitq);
	return kr;
}

/**
 * unlink a waitq from a waitq set, but reference the waitq by its prepost ID
 *
 * Conditions:
 *	'wqset' is unlocked
 *	wqp_id may be valid or invalid
 */
void
waitq_unlink_by_prepost_id(uint64_t wqp_id, struct waitq_set *wqset)
{
	struct wq_prepost *wqp;

	disable_preemption();
	wqp = wq_prepost_get(wqp_id);
	if (wqp) {
		struct waitq *wq;

		wq = wqp->wqp_wq.wqp_wq_ptr;

		/*
		 * lock the waitq, then release our prepost ID reference, then
		 * unlink the waitq from the wqset: this ensures that we don't
		 * hold a prepost ID reference during the unlink, but we also
		 * complete the unlink operation atomically to avoid a race
		 * with waitq_unlink[_all].
		 */
		assert(!waitq_irq_safe(wq));

		waitq_lock(wq);
		wq_prepost_put(wqp);

		if (!waitq_valid(wq)) {
			/* someone already tore down this waitq! */
			waitq_unlock(wq);
			enable_preemption();
			return;
		}

		/* this _may_ drop the wq lock, but that's OK */
		waitq_unlink_locked(wq, wqset);

		waitq_unlock(wq);
	}
	enable_preemption();
}


/**
 * reference and lock a waitq by its prepost ID
 *
 * Conditions:
 *	wqp_id may be valid or invalid
 *
 * Returns:
 *	a locked waitq if wqp_id was valid
 *	NULL on failure
 */
struct waitq *
waitq_lock_by_prepost_id(uint64_t wqp_id)
{
	struct waitq *wq = NULL;
	struct wq_prepost *wqp;

	disable_preemption();
	wqp = wq_prepost_get(wqp_id);
	if (wqp) {
		wq = wqp->wqp_wq.wqp_wq_ptr;

		assert(!waitq_irq_safe(wq));

		waitq_lock(wq);
		wq_prepost_put(wqp);

		if (!waitq_valid(wq)) {
			/* someone already tore down this waitq! */
			waitq_unlock(wq);
			enable_preemption();
			return NULL;
		}
	}
	enable_preemption();
	return wq;
}

/**
 * unlink all waitqs from 'wqset'
 *
 * Conditions:
 *	'wqset' is locked on entry
 *	'wqset' is unlocked on exit and spl is restored
 *
 * Note:
 *	may (rarely) spin/block (see waitq_clear_prepost_locked)
 */
kern_return_t
waitq_set_unlink_all_unlock(struct waitq_set *wqset)
{
	struct waitq_link *link;
	uint64_t prepost_id;

	wqdbg_v("unlink all queues from set 0x%llx", wqset->wqset_id);

	/*
	 * This operation does not require interaction with any of the set's
	 * constituent wait queues. All we have to do is invalidate the SetID
	 */

	if (waitqs_is_linked(wqset)) {
		/* invalidate and re-alloc the link object first */
		link = wql_get_link(wqset->wqset_id);

		/* we may have raced with a waitq_set_deinit: handle this */
		if (!link) {
			waitq_set_unlock(wqset);
			return KERN_SUCCESS;
		}

		wql_invalidate(link);

		/* re-alloc the object to get a new generation ID */
		wql_realloc_link(link, WQL_WQS);
		link->wql_set = wqset;

		wqset->wqset_id = link->wql_setid.id;
		wql_mkvalid(link);
		wql_put_link(link);
	}

	/* clear any preposts attached to this set */
	prepost_id = wqset->wqset_prepost_id;
	wqset->wqset_prepost_id = 0;

	waitq_set_unlock(wqset);

	/* drop / unlink all the prepost table objects */
	if (prepost_id) {
		wqset_clear_prepost_chain(prepost_id);
	}

	return KERN_SUCCESS;
}

static int
waitq_alloc_prepost_reservation(int nalloc, struct waitq *waitq,
    int *did_unlock, struct wq_prepost **wqp)
{
	struct wq_prepost *tmp;
	struct wqp_cache *cache;

	*did_unlock = 0;

	/*
	 * Before we unlock the waitq, check the per-processor prepost object
	 * cache to see if there's enough there for us. If so, do the
	 * allocation, keep the lock and save an entire iteration over the set
	 * linkage!
	 */
	if (waitq) {
		disable_preemption();
		cache = PERCPU_GET(wqp_cache);
		if (nalloc <= (int)cache->avail) {
			goto do_alloc;
		}
		enable_preemption();

		/* unlock the waitq to perform the allocation */
		*did_unlock = 1;
		waitq_unlock(waitq);
	}

do_alloc:
	tmp = wq_prepost_alloc(LT_RESERVED, nalloc);
	if (!tmp) {
		panic("Couldn't reserve %d preposts for waitq @%p (wqp@%p)",
		    nalloc, waitq, *wqp);
	}
	if (*wqp) {
		/* link the two lists */
		int __assert_only rc;
		rc = wq_prepost_rlink(tmp, *wqp);
		assert(rc == nalloc);
	}
	*wqp = tmp;

	/*
	 * If the caller can block, then enforce a minimum-free table element
	 * policy here. This helps ensure that we will have enough prepost
	 * objects for callers such as selwakeup() that can be called with
	 * spin locks held.
	 */
	if (get_preemption_level() == 0) {
		wq_prepost_ensure_free_space();
	}

	if (waitq) {
		if (*did_unlock == 0) {
			/* decrement the preemption count if alloc from cache */
			enable_preemption();
		} else {
			/* otherwise: re-lock the waitq */
			waitq_lock(waitq);
		}
	}

	return nalloc;
}

static int
waitq_count_prepost_reservation(struct waitq *waitq, int extra, int keep_locked)
{
	waitq_ref_t root_ref;
	int npreposts = extra;

	/*
	 * If the waitq is not currently part of a set, and we're not asked to
	 * keep the waitq locked then we'll want to have 3 in reserve
	 * just-in-case it becomes part of a set while we unlock and reserve.
	 * We may need up to 1 object for the waitq, and 2 for the set.
	 */
	root_ref = waitq->waitq_set_id;
	if (wqr_is_null(root_ref)) {
		if (!keep_locked) {
			npreposts += 3;
		}
	} else {
		/* this queue has never been preposted before */
		if (waitq->waitq_prepost_id == 0) {
			npreposts += 3;
		}

		/*
		 * Count the worst-case number of prepost objects that
		 * may be needed during a wakeup_all.
		 */
		if (wqr_is_ptr(root_ref)) {
			struct waitq_link *link = wqr_ptr(root_ref);

			npreposts += 2 * link->wql_count;
		} else {
			npreposts += 2;
		}
	}

	return npreposts;
}


/**
 * pre-allocate prepost objects for 'waitq'
 *
 * Conditions:
 *	'waitq' is not locked
 *
 * Returns:
 *	panic on error
 *
 *	0 on success, '*reserved' is set to the head of a singly-linked
 *	list of pre-allocated prepost objects.
 *
 * Notes:
 *	If 'lock_state' is WAITQ_KEEP_LOCKED, this function performs the pre-allocation
 *	atomically and returns 'waitq' locked.
 *
 *	This function attempts to pre-allocate precisely enough prepost
 *	objects based on the current set membership of 'waitq'. If the
 *	operation is performed atomically, then the caller
 *	is guaranteed to have enough pre-allocated prepost object to avoid
 *	any (rare) blocking in the wakeup path.
 */
uint64_t
waitq_prepost_reserve(struct waitq *waitq, int extra,
    waitq_lock_state_t lock_state)
{
	uint64_t reserved = 0;
	struct wq_prepost *wqp = NULL;
	int nalloc = 0, npreposts = 0;
	int keep_locked = (lock_state == WAITQ_KEEP_LOCKED);
	int unlocked = 0;

	wqdbg_v("Attempting to reserve prepost linkages for waitq %p (extra:%d)",
	    (void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), extra);

	if (waitq == NULL && extra > 0) {
		/*
		 * Simple prepost object allocation:
		 * we'll add 2 more because the waitq might need an object,
		 * and the set itself may need a new POST object in addition
		 * to the number of preposts requested by the caller
		 */
		nalloc = waitq_alloc_prepost_reservation(extra + 2, NULL,
		    &unlocked, &wqp);
		assert(nalloc == extra + 2);
		return wqp->wqp_prepostid.id;
	}

	assert(lock_state == WAITQ_KEEP_LOCKED || lock_state == WAITQ_UNLOCK);

	assert(!waitq_irq_safe(waitq));

	waitq_lock(waitq);

	npreposts = waitq_count_prepost_reservation(waitq, extra, keep_locked);
	if (npreposts) {
		do {
			/* this _may_ unlock and relock the waitq! */
			nalloc = waitq_alloc_prepost_reservation(npreposts - nalloc,
			    waitq, &unlocked, &wqp);

			if (!unlocked) {
				break;
			}

			npreposts = waitq_count_prepost_reservation(waitq, extra,
			    keep_locked);
		} while (npreposts > nalloc);
	}

	if (!keep_locked) {
		waitq_unlock(waitq);
	}
	if (wqp) {
		reserved = wqp->wqp_prepostid.id;
	}

	return reserved;
}

/**
 * release a linked list of prepost objects allocated via _prepost_reserve
 *
 * Conditions:
 *	may (rarely) spin waiting for prepost table growth memcpy
 */
void
waitq_prepost_release_reserve(uint64_t id)
{
	struct wq_prepost *wqp;

	wqdbg_v("releasing reserved preposts starting at: 0x%llx", id);

	wqp = wq_prepost_rfirst(id);
	if (!wqp) {
		return;
	}

	wq_prepost_release_rlist(wqp);
}


/* ----------------------------------------------------------------------
 *
 * Iteration: waitq -> sets / waitq_set -> preposts
 *
 * ---------------------------------------------------------------------- */

/**
 * call external iterator function for each prepost object in wqset
 *
 * Conditions:
 *	Called from wq_prepost_foreach_locked
 *	(wqset locked, waitq _not_ locked)
 */
static int
wqset_iterate_prepost_cb(struct waitq_set *wqset,
    struct wq_prepost *wqp, struct waitq *waitq, int (^it)(struct waitq *))
{
	uint64_t wqp_id;
	int ret;

	(void)wqp;

	/*
	 * This is a bit tricky. The 'wqset' is locked, but the 'waitq' is not.
	 * Taking the 'waitq' lock is a lock order violation, so we need to be
	 * careful. We also must realize that we may have taken a reference to
	 * the 'wqp' just as the associated waitq was being torn down (or
	 * clearing all its preposts) - see waitq_clear_prepost_locked(). If
	 * the 'wqp' is valid and we can get the waitq lock, then we are good
	 * to go. If not, we need to back off, check that the 'wqp' hasn't
	 * been invalidated, and try to re-take the locks.
	 */
	assert(!waitq_irq_safe(waitq));

	if (waitq_lock_try(waitq)) {
		goto call_iterator;
	}

	if (!wqp_is_valid(wqp)) {
		return WQ_ITERATE_RESTART;
	}

	/* We are passed a prepost object with a reference on it. If neither
	 * the waitq set nor the waitq require interrupts disabled, then we
	 * may block on the delay(1) call below. We can't hold a prepost
	 * object reference while blocking, so we have to give that up as well
	 * and re-acquire it when we come back.
	 */
	wqp_id = wqp->wqp_prepostid.id;
	wq_prepost_put(wqp);
	waitq_set_unlock(wqset);
	wqdbg_v("dropped set:%p lock waiting for wqp:%p (0x%llx -> wq:%p)",
	    wqset, wqp, wqp->wqp_prepostid.id, waitq);
	delay(1);
	waitq_set_lock(wqset);
	wqp = wq_prepost_get(wqp_id);
	if (!wqp) {
		/* someone cleared preposts while we slept! */
		return WQ_ITERATE_DROPPED;
	}

	/*
	 * TODO:
	 * This differs slightly from the logic in ipc_mqueue.c:
	 * ipc_mqueue_receive_on_thread(). There, if the waitq lock
	 * can't be obtained, the prepost link is placed on the back of
	 * the chain, and the iteration starts from the beginning. Here,
	 * we just restart from the beginning.
	 */
	return WQ_ITERATE_RESTART;

call_iterator:
	if (!wqp_is_valid(wqp)) {
		ret = WQ_ITERATE_RESTART;
		goto out_unlock;
	}

	/* call the external callback */
	ret = it(waitq);

	if (ret == WQ_ITERATE_BREAK_KEEP_LOCKED) {
		ret = WQ_ITERATE_BREAK;
		goto out;
	}

out_unlock:
	waitq_unlock(waitq);
out:
	return ret;
}

/**
 * iterator over all preposts in the given wqset
 *
 * Conditions:
 *      'wqset' is locked
 */
int
waitq_set_iterate_preposts(struct waitq_set *wqset, waitq_iterator_t it)
{
	assert(waitq_held(&wqset->wqset_q));

	return wq_prepost_foreach_locked(wqset,
	           ^(struct wq_prepost *wqp, struct waitq *waitq){
		return wqset_iterate_prepost_cb(wqset, wqp, waitq, it);
	});
}


/* ----------------------------------------------------------------------
 *
 * Higher-level APIs
 *
 * ---------------------------------------------------------------------- */


/**
 * declare a thread's intent to wait on 'waitq' for 'wait_event'
 *
 * Conditions:
 *	'waitq' is not locked
 */
wait_result_t
waitq_assert_wait64(struct waitq *waitq,
    event64_t wait_event,
    wait_interrupt_t interruptible,
    uint64_t deadline)
{
	thread_t thread = current_thread();
	wait_result_t ret;
	spl_t s = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		s = splsched();
	}

	waitq_lock(waitq);
	ret = waitq_assert_wait64_locked(waitq, wait_event, interruptible,
	    TIMEOUT_URGENCY_SYS_NORMAL,
	    deadline, TIMEOUT_NO_LEEWAY, thread);
	waitq_unlock(waitq);

	if (waitq_irq_safe(waitq)) {
		splx(s);
	}

	return ret;
}

/**
 * declare a thread's intent to wait on 'waitq' for 'wait_event'
 *
 * Conditions:
 *	'waitq' is not locked
 *	will disable and re-enable interrupts while locking current_thread()
 */
wait_result_t
waitq_assert_wait64_leeway(struct waitq *waitq,
    event64_t wait_event,
    wait_interrupt_t interruptible,
    wait_timeout_urgency_t urgency,
    uint64_t deadline,
    uint64_t leeway)
{
	wait_result_t ret;
	thread_t thread = current_thread();
	spl_t s = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		s = splsched();
	}

	waitq_lock(waitq);
	ret = waitq_assert_wait64_locked(waitq, wait_event, interruptible,
	    urgency, deadline, leeway, thread);
	waitq_unlock(waitq);

	if (waitq_irq_safe(waitq)) {
		splx(s);
	}

	return ret;
}

/**
 * wakeup a single thread from a waitq that's waiting for a given event
 *
 * Conditions:
 *	'waitq' is not locked
 *	may (rarely) block if 'waitq' is non-global and a member of 1 or more sets
 *	may disable and re-enable interrupts
 *
 * Notes:
 *	will _not_ block if waitq is global (or not a member of any set)
 */
kern_return_t
waitq_wakeup64_one(struct waitq *waitq, event64_t wake_event,
    wait_result_t result, int priority)
{
	kern_return_t kr;
	uint64_t reserved_preposts = 0;
	spl_t spl = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		spl = splsched();
		waitq_lock(waitq);
	} else if (wake_event != NO_EVENT64) {
		waitq_lock(waitq);
	} else {
		/*
		 * reserve preposts in addition to locking waitq
		 * only non global wait queues for the NO_EVENT64
		 * will prepost.
		 */
		reserved_preposts = waitq_prepost_reserve(waitq, 0,
		    WAITQ_KEEP_LOCKED);
	}


	/* waitq is locked upon return */
	kr = waitq_wakeup64_one_locked(waitq, wake_event, result,
	    &reserved_preposts, priority, WAITQ_UNLOCK, WQ_OPTION_NONE);

	if (waitq_irq_safe(waitq)) {
		splx(spl);
	}

	/* release any left-over prepost object (won't block/lock anything) */
	waitq_prepost_release_reserve(reserved_preposts);

	return kr;
}

/**
 * wakeup all threads from a waitq that are waiting for a given event
 *
 * Conditions:
 *	'waitq' is not locked
 *	may (rarely) block if 'waitq' is non-global and a member of 1 or more sets
 *	may disable and re-enable interrupts
 *
 * Notes:
 *	will _not_ block if waitq is global (or not a member of any set)
 */
kern_return_t
waitq_wakeup64_all(struct waitq *waitq, event64_t wake_event,
    wait_result_t result, int priority)
{
	kern_return_t ret;
	uint64_t reserved_preposts = 0;
	spl_t spl = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		spl = splsched();
		waitq_lock(waitq);
	} else if (wake_event != NO_EVENT64) {
		waitq_lock(waitq);
	} else {
		/*
		 * reserve preposts in addition to locking waitq
		 * only non global wait queues for the NO_EVENT64
		 * will prepost.
		 */
		reserved_preposts = waitq_prepost_reserve(waitq, 0,
		    WAITQ_KEEP_LOCKED);
	}

	ret = waitq_wakeup64_all_locked(waitq, wake_event, result,
	    &reserved_preposts, priority, WAITQ_UNLOCK);

	if (waitq_irq_safe(waitq)) {
		splx(spl);
	}

	waitq_prepost_release_reserve(reserved_preposts);

	return ret;
}

/**
 * wakeup a specific thread iff it's waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is not locked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts
 */
kern_return_t
waitq_wakeup64_thread(struct waitq *waitq, event64_t wake_event,
    thread_t thread, wait_result_t result)
{
	kern_return_t ret;
	spl_t s, th_spl;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		s = splsched();
	}
	waitq_lock(waitq);

	ret = waitq_select_thread_locked(waitq, wake_event, thread, &th_spl);
	waitq_stats_count_wakeup(waitq, ret == KERN_SUCCESS ? 1 : 0);

	/* on success, returns 'thread' locked */

	waitq_unlock(waitq);

	if (ret == KERN_SUCCESS) {
		ret = thread_go(thread, result, WQ_OPTION_NONE);
		assert(ret == KERN_SUCCESS);
		thread_unlock(thread);
		splx(th_spl);
	} else {
		ret = KERN_NOT_WAITING;
	}

	if (waitq_irq_safe(waitq)) {
		splx(s);
	}

	return ret;
}

/**
 * wakeup a single thread from a waitq that's waiting for a given event
 * and return a reference to that thread
 * returns THREAD_NULL if no thread was waiting
 *
 * Conditions:
 *	'waitq' is not locked
 *	may (rarely) block if 'waitq' is non-global and a member of 1 or more sets
 *	may disable and re-enable interrupts
 *
 * Notes:
 *	will _not_ block if waitq is global (or not a member of any set)
 */
thread_t
waitq_wakeup64_identify(struct waitq *waitq, event64_t wake_event,
    wait_result_t result, int priority)
{
	uint64_t reserved_preposts = 0;
	spl_t thread_spl = 0;
	thread_t thread;
	spl_t spl = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		spl = splsched();
		waitq_lock(waitq);
	} else if (wake_event != NO_EVENT64) {
		waitq_lock(waitq);
	} else {
		/*
		 * reserve preposts in addition to locking waitq
		 * only non global wait queues for the NO_EVENT64
		 * will prepost.
		 */
		reserved_preposts = waitq_prepost_reserve(waitq, 0,
		    WAITQ_KEEP_LOCKED);
	}

	thread = waitq_wakeup64_identify_locked(waitq, wake_event, result,
	    &thread_spl, &reserved_preposts,
	    priority, WAITQ_UNLOCK);
	/* waitq is unlocked, thread is locked */

	if (thread != THREAD_NULL) {
		thread_reference(thread);
		thread_unlock(thread);
		splx(thread_spl);
	}

	if (waitq_irq_safe(waitq)) {
		splx(spl);
	}

	/* release any left-over prepost object (won't block/lock anything) */
	waitq_prepost_release_reserve(reserved_preposts);

	/* returns +1 ref to running thread or THREAD_NULL */
	return thread;
}

#pragma mark - tests
#if DEBUG || DEVELOPMENT

#include <ipc/ipc_pset.h>
#include <sys/errno.h>

#define MAX_GLOBAL_TEST_QUEUES 64
static struct waitq wqt_waitq_array[MAX_GLOBAL_TEST_QUEUES];
static bool wqt_running;
static bool wqt_init;

static bool
wqt_start(const char *test, int64_t *out)
{
	if (os_atomic_xchg(&wqt_running, true, acquire)) {
		*out = 0;
		return false;
	}

	if (!wqt_init) {
		wqt_init = true;
		for (int i = 0; i < MAX_GLOBAL_TEST_QUEUES; i++) {
			waitq_init(&wqt_waitq_array[i], SYNC_POLICY_FIFO);
		}
	}

	printf("[WQ] starting %s\n", test);
	return true;
}

static int
wqt_end(const char *test, int64_t *out)
{
	os_atomic_store(&wqt_running, false, release);
	printf("[WQ] done %s\n", test);
	*out = 1;
	return 0;
}

static struct waitq *
wqt_wq(uint32_t index)
{
	return &wqt_waitq_array[index];
}

static uint32_t
wqt_idx(struct waitq *waitq)
{
	assert(waitq >= wqt_waitq_array &&
	    waitq < wqt_waitq_array + MAX_GLOBAL_TEST_QUEUES);
	return (uint32_t)(waitq - wqt_waitq_array);
}

__attribute__((overloadable))
static uint64_t
wqt_bit(uint32_t index)
{
	return 1ull << index;
}

__attribute__((overloadable))
static uint64_t
wqt_bit(struct waitq *waitq)
{
	return wqt_bit(wqt_idx(waitq));
}

static struct waitq_set *
wqt_wqset_create(void)
{
	struct waitq_set *wqset;

	wqset = &ipc_pset_alloc_special(ipc_space_kernel)->ips_wqset;
	if (!waitqs_is_linked(wqset)) {
		waitq_set_lazy_init_link(wqset);
	}
	printf("[WQ]: created waitq set 0x%llx\n", wqset->wqset_id);
	return wqset;
}

static void
wqt_wqset_free(struct waitq_set *wqset)
{
	waitq_set_lock(wqset);
	ipc_pset_destroy(ipc_space_kernel,
	    __container_of(wqset, struct ipc_pset, ips_wqset));
}

static void
wqt_link(uint32_t index, struct waitq_set *wqset, kern_return_t want)
{
	struct waitq *waitq = wqt_wq(index);
	waitq_ref_t reserved_link;
	kern_return_t kr;

	printf("[WQ]: linking waitq [%d] to global wqset (0x%llx)\n",
	    index, wqset->wqset_id);
	reserved_link = waitq_link_reserve();
	kr = waitq_link(waitq, wqset, WAITQ_SHOULD_LOCK, &reserved_link);
	waitq_link_release(reserved_link);

	printf("[WQ]:\tkr=%d\texpected=%d\n", kr, want);
	assert(kr == want);
}

static void
wqt_unlink(uint32_t index, struct waitq_set *wqset, kern_return_t want)
{
	struct waitq *waitq = wqt_wq(index);
	kern_return_t kr;

	printf("[WQ]: unlinking waitq [%d] from global wqset (0x%llx)\n",
	    index, wqset->wqset_id);
	kr = waitq_unlink(waitq, wqset);
	printf("[WQ]: \tkr=%d\n", kr);
	assert(kr == want);
}

static void
wqt_wakeup_one(uint32_t index, event64_t event64, kern_return_t want)
{
	kern_return_t kr;

	printf("[WQ]: Waking one thread on waitq [%d] event:0x%llx\n",
	    index, event64);
	kr = waitq_wakeup64_one(wqt_wq(index), event64,
	    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
	printf("[WQ]: \tkr=%d\n", kr);
	assert(kr == want);
}

static void
wqt_clear_preposts(uint32_t idx)
{
	waitq_lock(wqt_wq(idx));
	(void)waitq_clear_prepost_locked(wqt_wq(idx));
	waitq_unlock(wqt_wq(idx));
}

static void
wqt_expect_preposts(struct waitq_set *wqset, uint64_t preposts)
{
	/* make sure we find all preposts on wqset1 */
	__block uint64_t found = 0;

	waitq_set_lock(wqset);
	waitq_set_iterate_preposts(wqset, ^(struct waitq *waitq) {
		printf("[WQ]: found prepost %d\n", wqt_idx(waitq));
		assertf((found & wqt_bit(waitq)) == 0,
		"found waitq %d twice", wqt_idx(waitq));
		found |= wqt_bit(waitq);
		return WQ_ITERATE_CONTINUE;
	});
	waitq_set_unlock(wqset);

	assertf(found == preposts, "preposts expected 0x%llx, but got 0x%llx",
	    preposts, found);
}

static int
waitq_basic_test(__unused int64_t in, int64_t *out)
{
	struct waitq_set *wqset;

	if (!wqt_start(__func__, out)) {
		return EBUSY;
	}

	wqset = wqt_wqset_create();
	wqt_link(10, wqset, KERN_SUCCESS);
	wqt_link(10, wqset, KERN_ALREADY_IN_SET);
	wqt_link(11, wqset, KERN_SUCCESS);
	wqt_link(11, wqset, KERN_ALREADY_IN_SET);
	wqt_link(12, wqset, KERN_SUCCESS);
	wqt_link(12, wqset, KERN_ALREADY_IN_SET);

	wqt_wakeup_one(10, NO_EVENT64, KERN_NOT_WAITING);
	wqt_wakeup_one(12, NO_EVENT64, KERN_NOT_WAITING);

	wqt_expect_preposts(wqset, wqt_bit(10) | wqt_bit(12));
	wqt_clear_preposts(10);

	wqt_expect_preposts(wqset, wqt_bit(12));
	wqt_clear_preposts(12);

	wqt_expect_preposts(wqset, 0);

	wqt_unlink(12, wqset, KERN_SUCCESS);
	wqt_unlink(12, wqset, KERN_NOT_IN_SET);
	wqt_unlink(11, wqset, KERN_SUCCESS);
	wqt_unlink(10, wqset, KERN_SUCCESS);
	wqt_wqset_free(wqset);

	return wqt_end(__func__, out);
}
SYSCTL_TEST_REGISTER(waitq_basic, waitq_basic_test);
#endif /* DEBUG || DEVELOPMENT */
