/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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

#include <kern/ast.h>
#include <kern/backtrace.h>
#include <kern/kern_types.h>
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

/*!
 * @const waitq_set_unlink_batch
 *
 * @brief
 * How many links are unhooked under a single set lock hold.
 *
 * @discussion
 * Holding a waitq set lock for too long can cause
 * extreme contention (when a set is being torn down concurrently
 * to messages being sent to ports who used to belong to that set).
 *
 * In order to fight this, large wait queue sets will drop
 * and reacquire their lock for each unlinking batch.
 */
static TUNABLE(uint32_t, waitq_set_unlink_batch, "waitq_set_unlink_batch", 64);

/*!
 * @const WQL_PREPOST_MARKER
 *
 * @brief
 * Marker set in the @c wql_wqs field of wait queue linkages to denote that
 * this linkage has preposted to its wait queue set already.
 *
 * @discussion
 * This bit is manipulated under both the wait queue and the wait queue set
 * locks, and is used for two purposes:
 *
 * - for port set queues, it denotes in which circle queue the linkage
 *   is queued on (@c waitq_set::wqset_links or @c waitq_set::wqset_preposts)
 *
 * - as an optimization during pre-post to not walk sets this link already
 *   preposted to.
 */
#define WQL_PREPOST_MARKER 1ul

#if __LP64__
/*!
 * @struct waitq_link_hdr
 *
 * @brief
 * Common "header" between all linkages, in order to find the waitq_set
 * of this linkage.
 *
 * @discussion
 * Due to unfortunate alignment constraints on @c queue_chain_t,
 * this is wildly different for LP64 and ILP32.
 *
 * Do note that `wql
 */
struct waitq_link_hdr {
	uintptr_t       wql_wqs;
};

/*!
 * @struct waitq_sellink
 *
 * @brief
 * Linkages used for select waitq queues to select wait queue sets.
 *
 * @discussion
 * Select linkages are one way (queue to set) for two reasons:
 *
 * 1. select doesn't use the wait queue subsystem to discover which file
 *    descriptor woke up the set (it will instead scan all fds again),
 *
 * 2. all linkages are unhooked on each syscall return, so we minimize
 *    work to be done to be as quick as possible, using a fast invalidation
 *    scheme based on unique identifiers and sequestering
 *    (see @c select_set_nextid()).
 */
struct waitq_sellink {
	uintptr_t       wql_wqs;
	struct waitq_link_list_entry wql_next;
	uint64_t        wql_setid;
};

/*!
 * @struct waitq_link
 *
 * @brief
 * Linkages used for port wait queues and port-set wait queue sets.
 *
 * @discussion
 * Those linkages go both ways so that receiving messages through a port-set
 * can quickly find ports that preposted to the set.
 *
 * It also means that unhooking linkages cannot be lazy.
 */
struct waitq_link {
	uintptr_t       wql_wqs;       /**< wait queue set for this link      */
	queue_chain_t   wql_qlink;     /**< linkage through the waitq list    */
	queue_chain_t   wql_slink;     /**< linkage through the wqset list    */
	struct waitq   *wql_wq;        /**< wait queue for this link          */
};
#else
struct waitq_link_hdr {
	uint64_t        __wql_padding;
	uintptr_t       wql_wqs;
};

struct waitq_sellink {
	struct waitq_link_list_entry wql_next;
	uintptr_t       __wql_padding;
	uintptr_t       wql_wqs;
	uint64_t        wql_setid;
};

struct waitq_link {
	queue_chain_t   wql_qlink;
	uintptr_t       wql_wqs;
	struct waitq   *wql_wq;
	queue_chain_t   wql_slink;
};
#endif

static_assert(offsetof(struct waitq_link_hdr, wql_wqs) ==
    offsetof(struct waitq_sellink, wql_wqs));
static_assert(offsetof(struct waitq_link_hdr, wql_wqs) ==
    offsetof(struct waitq_link, wql_wqs));
static_assert(sizeof(struct waitq) <= WQ_OPAQUE_SIZE, "waitq structure size mismatch");
static_assert(__alignof(struct waitq) == WQ_OPAQUE_ALIGN, "waitq structure alignment mismatch");

static KALLOC_TYPE_DEFINE(waitq_sellink_zone, struct waitq_sellink, KT_PRIV_ACCT);
static KALLOC_TYPE_DEFINE(waitq_link_zone, struct waitq_link, KT_PRIV_ACCT);
ZONE_DEFINE_ID(ZONE_ID_SELECT_SET, "select_set", struct select_set,
    ZC_SEQUESTER | ZC_KASAN_NOQUARANTINE | ZC_ZFREE_CLEARMEM);

static LCK_GRP_DECLARE(waitq_lck_grp, "waitq");

static uint64_t PERCPU_DATA(select_setid);
struct waitq select_conflict_queue;

#pragma mark waitq links

static inline bool
waitq_is_sellink(waitq_type_t type)
{
	return type == WQT_SELECT || type == WQT_SELECT_SET;
}

static inline bool
wql_sellink_valid(struct select_set *selset, struct waitq_sellink *link)
{
	return waitq_valid(selset) && selset->selset_id == link->wql_setid;
}

static waitq_t
wql_wqs(waitq_link_t link)
{
	return (waitq_t){ (void *)(link.wqlh->wql_wqs & ~WQL_PREPOST_MARKER) };
}

static bool
wql_wqs_preposted(waitq_link_t link)
{
	return link.wqlh->wql_wqs & WQL_PREPOST_MARKER;
}

static void
wql_wqs_mark_preposted(waitq_link_t link)
{
	assert(!wql_wqs_preposted(link));
	link.wqlh->wql_wqs |= WQL_PREPOST_MARKER;
}

static void
wql_wqs_clear_preposted(waitq_link_t link)
{
	assert(wql_wqs_preposted(link));
	link.wqlh->wql_wqs &= ~WQL_PREPOST_MARKER;
}

static circle_queue_t
wql_wqs_queue(struct waitq_set *wqs, struct waitq_link *link)
{
	return wql_wqs_preposted(link) ? &wqs->wqset_preposts : &wqs->wqset_links;
}

static void
wql_list_push(waitq_link_list_t *list, waitq_link_t link)
{
	link.wqls->wql_next.next = list->next;
	list->next = &link.wqls->wql_next;
}

static inline struct waitq_sellink *
wql_list_elem(struct waitq_link_list_entry *e)
{
	return e ? __container_of(e, struct waitq_sellink, wql_next) : NULL;
}

/*!
 * @function wql_list_next()
 *
 * @brief
 * Helper function to implement wait queue link list enumeration.
 *
 * @param e             in: pointer to the current element,
 *                      out: pointer to the next element or NULL
 * @param end           which element to stop enumeration at (NULL for lists,
 *                      or the first element enumerated for circle queues).
 * @returns true        (makes writing for(;;) based enumerators easier).
 */
static inline bool
wql_list_next(struct waitq_link_list_entry **e, struct waitq_link_list_entry *end)
{
	if (*e == NULL || (*e)->next == end) {
		*e = NULL;
	} else {
		*e = (*e)->next;
	}
	return true;
}

#define __wql_list_foreach(it, head, end) \
	for (struct waitq_link_list_entry *__it = (head)->next, *__end = end; \
	    ((it) = wql_list_elem(__it)); wql_list_next(&__it, __end))

#define wql_list_foreach(it, head) \
	__wql_list_foreach(it, head, NULL)

#define wql_list_foreach_safe(it, head) \
	for (struct waitq_link_list_entry *__it = (head)->next;                \
	    ((it) = wql_list_elem(__it)) && wql_list_next(&__it, NULL); )

/*
 * Gross hack: passing `__it` to `__wql_list_foreach` makes it stop whether
 * we circle back to the first element or NULL (whichever comes first).
 *
 * This allows to have a single enumeration function oblivious to whether
 * we enumerate a circle queue or a sellink list.
 */
#define waitq_link_foreach(link, waitq) \
	__wql_list_foreach((link).wqls, &(waitq).wq_q->waitq_sellinks, __it)

static_assert(offsetof(struct waitq, waitq_sellinks) ==
    offsetof(struct waitq, waitq_links));
static_assert(offsetof(struct waitq_sellink, wql_next) ==
    offsetof(struct waitq_link, wql_qlink.next));

static struct waitq_link *
wql_find(struct waitq *waitq, waitq_t wqset)
{
	struct waitq_link *link;

	cqe_foreach_element(link, &waitq->waitq_links, wql_qlink) {
		if (waitq_same(wql_wqs(link), wqset)) {
			return link;
		}
	}

	return NULL;
}

waitq_link_t
waitq_link_alloc(waitq_type_t type)
{
	waitq_link_t link;

	if (waitq_is_sellink(type)) {
		link.wqls = zalloc_flags(waitq_sellink_zone, Z_WAITOK | Z_ZERO);
	} else {
		link.wqll = zalloc_flags(waitq_link_zone, Z_WAITOK | Z_ZERO);
	}
	return link;
}

void
waitq_link_free(waitq_type_t type, waitq_link_t link)
{
	if (waitq_is_sellink(type)) {
		return zfree(waitq_sellink_zone, link.wqls);
	} else {
		return zfree(waitq_link_zone, link.wqll);
	}
}

void
waitq_link_free_list(waitq_type_t type, waitq_link_list_t *free_l)
{
	waitq_link_t link;

	wql_list_foreach_safe(link.wqls, free_l) {
		waitq_link_free(type, link);
	}

	free_l->next = NULL;
}


#pragma mark global wait queues

static __startup_data struct waitq g_boot_waitq;
static SECURITY_READ_ONLY_LATE(struct waitq *) global_waitqs = &g_boot_waitq;
static SECURITY_READ_ONLY_LATE(uint32_t) g_num_waitqs = 1;

/*
 * Zero out the used MSBs of the event.
 */
#define _CAST_TO_EVENT_MASK(event) \
	((waitq_flags_t)(event) & ((1ul << _EVENT_MASK_BITS) - 1ul))

static inline uint32_t
waitq_hash(char *key, size_t length)
{
	return os_hash_jenkins(key, length) & (g_num_waitqs - 1);
}

/* return a global waitq pointer corresponding to the given event */
struct waitq *
_global_eventq(char *event, size_t event_length)
{
	return &global_waitqs[waitq_hash(event, event_length)];
}

bool
waitq_is_valid(waitq_t waitq)
{
	return waitq_valid(waitq);
}

static inline bool
waitq_is_global(waitq_t waitq)
{
	if (waitq_type(waitq) != WQT_QUEUE) {
		return false;
	}
	return waitq.wq_q >= global_waitqs && waitq.wq_q < global_waitqs + g_num_waitqs;
}

static inline bool
waitq_empty(waitq_t wq)
{
	struct turnstile *ts;

	switch (waitq_type(wq)) {
	case WQT_TURNSTILE:
		return priority_queue_empty(&wq.wq_q->waitq_prio_queue);
	case WQT_PORT:
		ts = wq.wq_q->waitq_ts;
		return ts == TURNSTILE_NULL ||
		       priority_queue_empty(&ts->ts_waitq.waitq_prio_queue);
	case WQT_QUEUE:
	case WQT_SELECT:
	case WQT_PORT_SET:
	case WQT_SELECT_SET:
		return circle_queue_empty(&wq.wq_q->waitq_queue);

	default:
		return true;
	}
}

#if CONFIG_WAITQ_STATS
#define NWAITQ_BTFRAMES 5

struct wq_stats {
	uint64_t waits;
	uint64_t wakeups;
	uint64_t clears;
	uint64_t failed_wakeups;

	uintptr_t last_wait[NWAITQ_BTFRAMES];
	uintptr_t last_wakeup[NWAITQ_BTFRAMES];
	uintptr_t last_failed_wakeup[NWAITQ_BTFRAMES];
};

/* this global is for lldb */
const uint32_t g_nwaitq_btframes = NWAITQ_BTFRAMES;
struct wq_stats g_boot_stats;
struct wq_stats *g_waitq_stats = &g_boot_stats;

static __inline__ void
waitq_grab_backtrace(uintptr_t bt[NWAITQ_BTFRAMES], unsigned skip)
{
	uintptr_t buf[NWAITQ_BTFRAMES + skip];

	memset(buf, 0, (NWAITQ_BTFRAMES + skip) * sizeof(uintptr_t));
	backtrace(buf, g_nwaitq_btframes + skip, NULL, NULL);
	memcpy(&bt[0], &buf[skip], NWAITQ_BTFRAMES * sizeof(uintptr_t));
}

static __inline__ struct wq_stats *
waitq_global_stats(waitq_t waitq)
{
	struct wq_stats *wqs;
	uint32_t idx;

	if (!waitq_is_global(waitq)) {
		return NULL;
	}

	idx = (uint32_t)(waitq.wq_q - global_waitqs);
	assert(idx < g_num_waitqs);
	wqs = &g_waitq_stats[idx];
	return wqs;
}

static __inline__ void
waitq_stats_count_wait(waitq_t waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->waits++;
		waitq_grab_backtrace(wqs->last_wait, 2);
	}
}

static __inline__ void
waitq_stats_count_wakeup(waitq_t waitq, int n)
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
waitq_stats_count_clear_wakeup(waitq_t waitq)
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

static struct waitq *
waitq_get_safeq(waitq_t waitq)
{
	if (waitq_type(waitq) == WQT_PORT) {
		struct turnstile *ts = waitq.wq_q->waitq_ts;
		return ts ? &ts->ts_waitq : NULL;
	}

	uint32_t hash = os_hash_kernel_pointer(waitq.wq_q);
	return &global_waitqs[hash & (g_num_waitqs - 1)];
}

/*
 * Since the priority ordered waitq uses basepri as the
 * ordering key assert that this value fits in a uint8_t.
 */
static_assert(MAXPRI <= UINT8_MAX);

static inline void
waitq_thread_insert(struct waitq *safeq, thread_t thread,
    waitq_t wq, event64_t event)
{
	if (waitq_type(safeq) == WQT_TURNSTILE) {
		turnstile_stats_update(0, TSU_TURNSTILE_BLOCK_COUNT, NULL);
		turnstile_waitq_add_thread_priority_queue(safeq, thread);
	} else {
		turnstile_stats_update(0, TSU_REGULAR_WAITQ_BLOCK_COUNT, NULL);
		/*
		 * This is the extent to which we currently take scheduling
		 * attributes into account:
		 *
		 * - If the thread is vm privileged, we stick it at the front
		 *   of the queue, later, these queues will honor the policy
		 *   value set at waitq_init time.
		 *
		 * - Realtime threads get priority for wait queue placements.
		 *   This allows wait_queue_wakeup_one to prefer a waiting
		 *   realtime thread, similar in principle to performing
		 *   a wait_queue_wakeup_all and allowing scheduler
		 *   prioritization to run the realtime thread, but without
		 *   causing the lock contention of that scenario.
		 */
		if (thread->sched_pri >= BASEPRI_REALTIME ||
		    !safeq->waitq_fifo ||
		    (thread->options & TH_OPT_VMPRIV)) {
			circle_enqueue_head(&safeq->waitq_queue, &thread->wait_links);
		} else {
			circle_enqueue_tail(&safeq->waitq_queue, &thread->wait_links);
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
	thread->waitq.wq_q = NULL;
	thread->wait_event = NO_EVENT64;
	thread->at_safe_point = FALSE;
}

static inline void
waitq_thread_remove(waitq_t wq, thread_t thread)
{
	if (waitq_type(wq) == WQT_TURNSTILE) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    (TURNSTILE_CODE(TURNSTILE_HEAP_OPERATIONS,
		    (THREAD_REMOVED_FROM_TURNSTILE_WAITQ))) | DBG_FUNC_NONE,
		    VM_KERNEL_UNSLIDE_OR_PERM(waitq_to_turnstile(wq.wq_q)),
		    thread_tid(thread), 0, 0, 0);
		priority_queue_remove(&wq.wq_q->waitq_prio_queue,
		    &thread->wait_prioq_links);
	} else {
		circle_dequeue(&wq.wq_q->waitq_queue, &thread->wait_links);
		if (waitq_is_global(wq) && waitq_empty(wq)) {
			wq.wq_q->waitq_eventmask = 0;
		}
	}

	thread_clear_waitq_state(thread);
}

__startup_func
static void
waitq_bootstrap(void)
{
	const uint32_t qsz = sizeof(struct waitq);
	vm_offset_t whsize;
	int cpu = 0;

	/*
	 * Determine the amount of memory we're willing to reserve for
	 * the waitqueue hash table
	 */
	if (!PE_parse_boot_argn("wqsize", &whsize, sizeof(whsize))) {
		whsize = round_page(thread_max * qsz / 5);
	}

	/*
	 * Determine the number of waitqueues we can fit.
	 * The hash algorithm requires that this be a power of 2.
	 */
	g_num_waitqs = 0x80000000u >> __builtin_clzl(whsize / qsz);
	assert(g_num_waitqs > 0);
	whsize = round_page(g_num_waitqs * qsz);

	kmem_alloc(kernel_map, (vm_offset_t *)&global_waitqs, whsize,
	    KMA_NOFAIL | KMA_KOBJECT | KMA_NOPAGEWAIT | KMA_PERMANENT,
	    VM_KERN_MEMORY_WAITQ);

#if CONFIG_WAITQ_STATS
	whsize = round_page(g_num_waitqs * sizeof(struct wq_stats));
	kmem_alloc(kernel_map, (vm_offset_t *)&g_waitq_stats, whsize,
	    KMA_NOFAIL | KMA_KOBJECT | KMA_NOPAGEWAIT | KMA_ZERO | KMA_PERMANENT,
	    VM_KERN_MEMORY_WAITQ);
#endif

	for (uint32_t i = 0; i < g_num_waitqs; i++) {
		waitq_init(&global_waitqs[i], WQT_QUEUE, SYNC_POLICY_FIFO);
	}

	waitq_init(&select_conflict_queue, WQT_SELECT, SYNC_POLICY_FIFO);

	percpu_foreach(setid, select_setid) {
		/* is not cpu_number() but CPUs haven't been numbered yet */
		*setid = cpu++;
	}
}
STARTUP(MACH_IPC, STARTUP_RANK_FIRST, waitq_bootstrap);


#pragma mark locking

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
waitq_timeout_handler(void *_lock, uint64_t timeout,
    uint64_t start, uint64_t now, uint64_t interrupt_time)
{
#pragma unused(interrupt_time)

	lck_spinlock_to_info_t lsti;
	hw_lck_ticket_t *lck = _lock;
	hw_lck_ticket_t tmp;
	struct waitq *wq = __container_of(lck, struct waitq, waitq_interlock);

	if (machine_timeout_suspended()) {
		return HW_LOCK_TIMEOUT_CONTINUE;
	}

	lsti = lck_spinlock_timeout_hit(lck, 0);
	tmp.tcurnext = os_atomic_load(&lck->tcurnext, relaxed);

	panic("waitq(%p) lock timeout after %llu ticks; cpu=%d, "
	    "cticket: 0x%x, nticket: 0x%x, waiting for 0x%x, "
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
waitq_invalidate(waitq_t waitq)
{
	hw_lck_ticket_invalidate(&waitq.wq_q->waitq_interlock);
}

bool
waitq_held(waitq_t wq)
{
	return hw_lck_ticket_held(&wq.wq_q->waitq_interlock);
}

void
waitq_lock(waitq_t wq)
{
	(void)hw_lck_ticket_lock_to(&wq.wq_q->waitq_interlock,
	    waitq_timeout, waitq_timeout_handler, &waitq_lck_grp);
#if defined(__x86_64__)
	pltrace(FALSE);
#endif
}

bool
waitq_lock_try(waitq_t wq)
{
	bool rc = hw_lck_ticket_lock_try(&wq.wq_q->waitq_interlock, &waitq_lck_grp);

#if defined(__x86_64__)
	if (rc) {
		pltrace(FALSE);
	}
#endif
	return rc;
}

bool
waitq_lock_reserve(waitq_t wq, uint32_t *ticket)
{
	return hw_lck_ticket_reserve(&wq.wq_q->waitq_interlock, ticket, &waitq_lck_grp);
}

static hw_lock_status_t
waitq_lock_reserve_allow_invalid(waitq_t wq, uint32_t *ticket)
{
	return hw_lck_ticket_reserve_allow_invalid(&wq.wq_q->waitq_interlock,
	           ticket, &waitq_lck_grp);
}

void
waitq_lock_wait(waitq_t wq, uint32_t ticket)
{
	(void)hw_lck_ticket_wait(&wq.wq_q->waitq_interlock, ticket,
	    waitq_timeout, waitq_timeout_handler, &waitq_lck_grp);
#if defined(__x86_64__)
	pltrace(FALSE);
#endif
}

bool
waitq_lock_allow_invalid(waitq_t wq)
{
	hw_lock_status_t rc;

	rc = hw_lck_ticket_lock_allow_invalid(&wq.wq_q->waitq_interlock,
	    waitq_timeout, waitq_timeout_handler, &waitq_lck_grp);

#if defined(__x86_64__)
	if (rc == HW_LOCK_ACQUIRED) {
		pltrace(FALSE);
	}
#endif
	return rc == HW_LOCK_ACQUIRED;
}

void
waitq_unlock(waitq_t wq)
{
	assert(waitq_held(wq));
#if defined(__x86_64__)
	pltrace(TRUE);
#endif
	hw_lck_ticket_unlock(&wq.wq_q->waitq_interlock);
}


#pragma mark assert_wait / wakeup

typedef thread_t (^waitq_select_cb)(struct waitq *waitq, thread_t thread);

struct waitq_select_args {
	/* input parameters */
	event64_t            event;
	waitq_select_cb      select_cb;
	int                  priority;
	wait_result_t        result;
	waitq_options_t      options;

	/* output parameters */
	uint32_t             max_threads;
	uint32_t             nthreads;
	spl_t                spl;
	circle_queue_head_t  threadq;
};

static inline void
maybe_adjust_thread_pri(thread_t thread, int priority,
    __kdebug_only waitq_t waitq)
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
			trace_waitq = VM_KERNEL_UNSLIDE_OR_PERM(waitq.wq_q);
		}

		sched_thread_promote_reason(thread, TH_SFLAG_WAITQ_PROMOTED, trace_waitq);
	}
}

static void
waitq_select_queue_flush(waitq_t waitq, struct waitq_select_args *args)
{
	thread_t thread = THREAD_NULL;
	__assert_only kern_return_t kr;

	cqe_foreach_element_safe(thread, &args->threadq, wait_links) {
		circle_dequeue(&args->threadq, &thread->wait_links);
		maybe_adjust_thread_pri(thread, args->priority, waitq);
		kr = thread_go(thread, args->result, args->options);
		assert(kr == KERN_SUCCESS);
		thread_unlock(thread);
	}
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

	cqe_foreach_element_safe(thread, &safeq->waitq_queue, wait_links) {
		thread_t t = THREAD_NULL;
		assert_thread_magic(thread);

		/*
		 * For non-priority ordered waitqs, we allow multiple events to be
		 * mux'ed into the same waitq. Also safeqs may contain threads from
		 * multiple waitqs. Only pick threads that match the
		 * requested wait event.
		 */
		if (waitq_same(thread->waitq, waitq) && thread->wait_event == args->event) {
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
				circle_dequeue(&safeq->waitq_queue, &thread->wait_links);
				circle_enqueue_tail(&args->threadq, &t->wait_links);
				/* only enqueue up to 'max' threads */
				if (args->nthreads >= args->max_threads) {
					break;
				}
			}
		}

		/* thread wasn't selected so track its event */
		if (t == THREAD_NULL) {
			*remaining_eventmask |= waitq_same(thread->waitq, safeq)
			    ? _CAST_TO_EVENT_MASK(thread->wait_event)
			    : _CAST_TO_EVENT_MASK(thread->waitq.wq_q);
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
		assert(waitq_same(thread->waitq, waitq) && (thread->wait_event == args->event));

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
			    waitq_type(safeq) == WQT_TURNSTILE) {
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
		circle_enqueue_tail(&args->threadq, &thread->wait_links);
	}

	return first_thread;
}

/**
 * @function do_waitq_select_n_locked_queue
 *
 * @brief
 * Selects threads waiting on a wait queue.
 *
 * @discussion
 * @c waitq is locked.
 * If @c waitq is a set, then the wait queue posting to it is locked too.
 *
 * Uses the optional select callback function to refine the selection
 * of one or more threads from a waitq.
 *
 * The select callback is invoked once for every thread that
 * is found to be waiting on the input args->waitq.
 *
 * If one or more threads are selected, this may disable interrupts.
 * The previous interrupt state is returned in args->spl and should
 * be used in a call to splx() if threads are returned to the caller.
 */
static void
do_waitq_select_n_locked_queue(waitq_t waitq, struct waitq_select_args *args)
{
	thread_t first_thread = THREAD_NULL;
	struct waitq *safeq;
	waitq_flags_t remaining_eventmask = 0;
	waitq_flags_t eventmask;

	if (waitq_irq_safe(waitq)) {
		eventmask = _CAST_TO_EVENT_MASK(args->event);
		safeq = waitq.wq_q;
	} else {
		/* JMM - add flag to waitq to avoid global lookup if no waiters */
		eventmask = _CAST_TO_EVENT_MASK(waitq.wq_q);
		safeq = waitq_get_safeq(waitq);
		if (safeq == NULL) {
			return;
		}

		if (args->nthreads == 0) {
			args->spl = splsched();
		}
		waitq_lock(safeq);
	}

	/*
	 * If the safeq doesn't have an eventmask (not global) or the event
	 * we're looking for IS set in its eventmask, then scan the threads
	 * in that queue for ones that match the original <waitq,event> pair.
	 */
	if (waitq_type(safeq) == WQT_TURNSTILE) {
		first_thread = waitq_prioq_iterate_locked(safeq, waitq.wq_q,
		    args, &remaining_eventmask);
	} else if (!waitq_is_global(safeq) ||
	    (safeq->waitq_eventmask & eventmask) == eventmask) {
		first_thread = waitq_queue_iterate_locked(safeq, waitq.wq_q,
		    args, &remaining_eventmask);

		/*
		 * Update the eventmask of global queues we just scanned:
		 * - If we selected all the threads in the queue,
		 *   we can clear its eventmask.
		 *
		 * - If we didn't find enough threads to fill our needs,
		 *   then we can assume we looked at every thread in the queue
		 *   and the mask we computed is complete - so reset it.
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
		if (safeq == waitq.wq_q) {
			args->spl = splsched();
		}

		thread_lock(first_thread);
		waitq_thread_remove(safeq, first_thread);
		circle_enqueue_tail(&args->threadq, &first_thread->wait_links);
	}

	/* unlock the safe queue if we locked one above */
	if (!waitq_same(waitq, safeq)) {
		waitq_unlock(safeq);
		if (args->nthreads == 0) {
			splx(args->spl);
			args->spl = 0;
		}
	}
}

/**
 * @function do_waitq_link_select_n_locked()
 *
 * @brief
 * Selects threads waiting on any set a wait queue belongs to,
 * or preposts the wait queue onto them.
 *
 * @discussion
 * @c waitq is locked.
 */
__attribute__((noinline))
static void
do_waitq_select_n_locked_sets(waitq_t waitq, struct waitq_select_args *args)
{
	waitq_type_t wq_type = waitq_type(waitq);
	waitq_link_t link;
	hw_lock_status_t st;
	uint32_t ticket;

	assert(args->event == NO_EVENT64);
	assert(waitq_preposts(waitq));

	waitq_link_foreach(link, waitq) {
		waitq_t wqset = wql_wqs(link);

		if (wql_wqs_preposted(link)) {
			/*
			 * The wql_wqs_preposted() bit is cleared
			 * under both the wq/wqset lock.
			 *
			 * If the wqset is still preposted,
			 * we really won't find threads there.
			 *
			 * Just mark the waitq as preposted and move on.
			 */
			if (wq_type == WQT_PORT) {
				waitq.wq_q->waitq_preposted = true;
			}
			continue;
		}

		if (wq_type == WQT_SELECT) {
			/*
			 * If PGZ picked this select set,
			 * translate it to the real address
			 *
			 * If it is still a select set
			 * (the slot could have been reused),
			 * then keep using it for the rest of the logic.
			 *
			 * Even in the extremely unlikely case where
			 * the slot was reused for another select_set,
			 * the `wql_sellink_valid` check below will
			 * take care of debouncing it. But we must
			 * forget the original pointer we read
			 * so that we unlock the proper object.
			 */
			wqset.wqs_sel = pgz_decode_allow_invalid(wqset.wqs_sel,
			    ZONE_ID_SELECT_SET);
			if (!wqset.wqs_sel) {
				continue;
			}
			st = waitq_lock_reserve_allow_invalid(wqset, &ticket);
			if (st == HW_LOCK_INVALID) {
				continue;
			}
		} else {
			static_assert(HW_LOCK_CONTENDED == 0);
			st = waitq_lock_reserve(wqset, &ticket);
		}
		if (st == HW_LOCK_CONTENDED) {
			if (!circle_queue_empty(&args->threadq)) {
				/*
				 * We are holding several thread locks.
				 *
				 * If we fail to acquire this waitq set lock,
				 * it is possible that another core is holding
				 * that (non IRQ-safe) waitq set lock,
				 * while an interrupt is trying to grab the
				 * thread lock of ones of those threads.
				 *
				 * In order to avoid deadlocks, flush out
				 * the queue of threads.
				 *
				 * Note: this code will never run for `identify`
				 *       variants (when `max_threads` is 1).
				 */
				assert(args->max_threads > 1);
				waitq_select_queue_flush(waitq, args);
			}
			waitq_lock_wait(wqset, ticket);
		}

		if (wq_type == WQT_SELECT) {
			if (!wql_sellink_valid(wqset.wqs_sel, link.wqls)) {
				goto out_unlock;
			}
		} else if (!waitq_valid(wqset)) {
			goto out_unlock;
		}

		/*
		 * Find any threads waiting on this wait queue set as a queue.
		 */
		do_waitq_select_n_locked_queue(wqset, args);

		if (args->nthreads == 0) {
			/* No thread selected: prepost 'waitq' to 'wqset' */
			wql_wqs_mark_preposted(link);
			if (wq_type == WQT_SELECT) {
				wqset.wqs_sel->selset_preposted = true;
			} else {
				waitq.wq_q->waitq_preposted = true;
				circle_dequeue(&wqset.wqs_set->wqset_links,
				    &link.wqll->wql_slink);
				circle_enqueue_tail(&wqset.wqs_set->wqset_preposts,
				    &link.wqll->wql_slink);
				ipc_pset_prepost(wqset.wqs_set, waitq.wq_q);
			}
		}

out_unlock:
		waitq_unlock(wqset);

		if (args->nthreads >= args->max_threads) {
			break;
		}
	}
}

/**
 * @function do_waitq_select_n_locked
 *
 * @brief
 * Selects threads waiting on a wait queue, or preposts it.
 *
 * @discussion
 * @c waitq is locked.
 *
 * Recurses into all sets this wait queue belongs to.
 */
static void
do_waitq_select_n_locked(waitq_t waitq, struct waitq_select_args *args)
{
	do_waitq_select_n_locked_queue(waitq, args);

	if (args->nthreads >= args->max_threads) {
		/* already enough threads found */
		return;
	}

	if (args->event != NO_EVENT64 || !waitq_preposts(waitq)) {
		/* this wakeup should not recurse into sets */
		return;
	}

	do_waitq_select_n_locked_sets(waitq, args);
}

static inline bool
waitq_is_preposted_set(waitq_t waitq)
{
	switch (waitq_type(waitq)) {
	case WQT_PORT_SET:
		return waitq_set_first_prepost(waitq.wqs_set, WQS_PREPOST_PEEK) != NULL;

	case WQT_SELECT_SET:
		return waitq.wqs_sel->selset_preposted;

	default:
		return false;
	}
}

wait_result_t
waitq_assert_wait64_locked(waitq_t waitq,
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

	switch (waitq_type(waitq)) {
	case WQT_PORT:
	case WQT_SELECT:
	case WQT_PORT_SET:
	case WQT_SELECT_SET:
		assert(wait_event == NO_EVENT64);
		break;
	default:
		assert(wait_event != NO_EVENT64);
		break;
	}

	/*
	 * Warning: Do _not_ place debugging print statements here.
	 *          The waitq is locked!
	 */
	assert(!thread->started || thread == current_thread());

	if (!waitq_wait_possible(thread)) {
		panic("thread already waiting on %p", thread->waitq.wq_q);
	}

	s = splsched();

	/*
	 * early-out if the thread is waiting on a wait queue set
	 * that has already been pre-posted.
	 *
	 * Note: waitq_is_preposted_set() may unlock the waitq-set
	 */
	if (waitq_is_preposted_set(waitq)) {
		thread_lock(thread);
		thread->wait_result = THREAD_AWAKENED;
		thread_unlock(thread);
		splx(s);
		return THREAD_AWAKENED;
	}

	/*
	 * If already dealing with an irq safe wait queue, we are all set.
	 * Otherwise, determine a global queue to use and lock it.
	 */
	if (waitq_irq_safe(waitq)) {
		safeq = waitq.wq_q;
		eventmask = _CAST_TO_EVENT_MASK(wait_event);
	} else {
		safeq = waitq_get_safeq(waitq);
		if (__improbable(safeq == NULL)) {
			panic("Trying to assert_wait on a turnstile proxy "
			    "that hasn't been donated one (waitq: %p)", waitq.wq_q);
		}
		eventmask = _CAST_TO_EVENT_MASK(waitq.wq_q);
		waitq_lock(safeq);
	}

	/* lock the thread now that we have the irq-safe waitq locked */
	thread_lock(thread);

	wait_result = thread_mark_wait_locked(thread, interruptible);
	/* thread->wait_result has been set */
	if (wait_result == THREAD_WAITING) {
		waitq_thread_insert(safeq, thread, waitq, wait_event);

		if (deadline != 0) {
			boolean_t act;

			act = timer_call_enter_with_leeway(thread->wait_timer,
			    NULL,
			    deadline, leeway,
			    urgency, FALSE);
			if (!act) {
				thread->wait_timer_active++;
			}
			thread->wait_timer_is_set = TRUE;
		}

		if (waitq_is_global(safeq)) {
			safeq->waitq_eventmask |= (waitq_flags_t)eventmask;
		}

		waitq_stats_count_wait(waitq);
	}

	/* unlock the thread */
	thread_unlock(thread);

	/* update the inheritor's thread priority if the waitq is embedded in turnstile */
	if (waitq_type(safeq) == WQT_TURNSTILE && wait_result == THREAD_WAITING) {
		turnstile_recompute_priority_locked(waitq_to_turnstile(safeq));
		turnstile_update_inheritor_locked(waitq_to_turnstile(safeq));
	}

	/* unlock the safeq if we locked it here */
	if (!waitq_same(waitq, safeq)) {
		waitq_unlock(safeq);
	}

	splx(s);

	return wait_result;
}

bool
waitq_pull_thread_locked(waitq_t waitq, thread_t thread)
{
	struct waitq *safeq;
	uint32_t ticket;

	assert_thread_magic(thread);

	/* Find the interrupts disabled queue thread is waiting on */
	if (waitq_irq_safe(waitq)) {
		safeq = waitq.wq_q;
	} else {
		safeq = waitq_get_safeq(waitq);
		if (__improbable(safeq == NULL)) {
			panic("Trying to clear_wait on a turnstile proxy "
			    "that hasn't been donated one (waitq: %p)", waitq.wq_q);
		}
	}

	/*
	 * thread is already locked so have to try for the waitq lock.
	 *
	 * We can't wait for the waitq lock under the thread lock,
	 * however we can reserve our slot in the lock queue,
	 * and if that reservation requires waiting, we are guaranteed
	 * that this waitq can't die until we got our turn!
	 */
	if (!waitq_lock_reserve(safeq, &ticket)) {
		thread_unlock(thread);
		waitq_lock_wait(safeq, ticket);
		thread_lock(thread);

		if (!waitq_same(waitq, thread->waitq)) {
			/*
			 * While we were waiting for our reservation the thread
			 * stopped waiting on this waitq, bail out.
			 */
			waitq_unlock(safeq);
			return false;
		}
	}

	waitq_thread_remove(safeq, thread);
	waitq_stats_count_clear_wakeup(waitq);
	waitq_unlock(safeq);
	return true;
}


void
waitq_clear_promotion_locked(waitq_t waitq, thread_t thread)
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

kern_return_t
waitq_wakeup64_all_locked(waitq_t waitq,
    event64_t wake_event,
    wait_result_t result,
    int priority,
    waitq_lock_state_t lock_state)
{
	struct waitq_select_args args = {
		.event = wake_event,
		.priority = priority,
		.max_threads = UINT32_MAX,
		.result = result,
		.options = WQ_OPTION_NONE,
	};

	assert(waitq_held(waitq));

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

kern_return_t
waitq_wakeup64_one_locked(waitq_t waitq,
    event64_t wake_event,
    wait_result_t result,
    int priority,
    waitq_lock_state_t lock_state,
    waitq_options_t option)
{
	struct waitq_select_args args = {
		.event = wake_event,
		.priority = priority,
		.max_threads = 1,
		.result = result,
		.options = option,
	};

	assert(waitq_held(waitq));

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

thread_t
waitq_wakeup64_identify_locked(waitq_t waitq,
    event64_t        wake_event,
    wait_result_t    result,
    spl_t            *spl,
    int              priority,
    waitq_lock_state_t lock_state)
{
	struct waitq_select_args args = {
		.event = wake_event,
		.priority = priority,
		.max_threads = 1,
	};
	thread_t thread = THREAD_NULL;

	assert(waitq_held(waitq));

	do_waitq_select_n_locked(waitq, &args);
	waitq_stats_count_wakeup(waitq, args.nthreads);

	if (lock_state == WAITQ_UNLOCK) {
		waitq_unlock(waitq);
	}

	if (args.nthreads > 0) {
		kern_return_t __assert_only ret;

		thread = cqe_dequeue_head(&args.threadq, struct thread, wait_links);
		assert(args.nthreads == 1 && circle_queue_empty(&args.threadq));

		maybe_adjust_thread_pri(thread, priority, waitq);
		ret = thread_go(thread, result, WQ_OPTION_NONE);
		assert(ret == KERN_SUCCESS);
		*spl = args.spl;
	}

	return thread; /* locked if not NULL (caller responsible for spl) */
}

kern_return_t
waitq_wakeup64_thread_and_unlock(struct waitq *waitq, event64_t event,
    thread_t thread, wait_result_t result)
{
	kern_return_t ret = KERN_NOT_WAITING;

	assert(waitq_irq_safe(waitq));
	assert(waitq_held(waitq));
	assert_thread_magic(thread);

	/*
	 * See if the thread was still waiting there.  If so, it got
	 * dequeued and returned locked.
	 */
	thread_lock(thread);

	if (waitq_same(thread->waitq, waitq) && thread->wait_event == event) {
		waitq_thread_remove(waitq, thread);
		ret = KERN_SUCCESS;
	}
	waitq_stats_count_wakeup(waitq, ret == KERN_SUCCESS ? 1 : 0);

	waitq_unlock(waitq);

	if (ret == KERN_SUCCESS) {
		ret = thread_go(thread, result, WQ_OPTION_NONE);
		assert(ret == KERN_SUCCESS);
	}

	thread_unlock(thread);

	return ret;
}


#pragma mark waitq

__attribute__((always_inline))
void
waitq_init(waitq_t waitq, waitq_type_t type, int policy)
{
	assert((policy & SYNC_POLICY_FIXED_PRIORITY) == 0);

	*waitq.wq_q = (struct waitq){
		.waitq_type  = type,
		.waitq_fifo  = ((policy & SYNC_POLICY_REVERSED) == 0),
	};

	switch (type) {
	case WQT_INVALID:
		__builtin_trap();

	case WQT_TURNSTILE:
		/* For turnstile, initialize it as a priority queue */
		priority_queue_init(&waitq.wq_q->waitq_prio_queue);
		assert(waitq.wq_q->waitq_fifo == 0);
		break;

	case WQT_PORT:
		waitq.wq_q->waitq_ts = TURNSTILE_NULL;
		break;

	case WQT_PORT_SET:
		circle_queue_init(&waitq.wqs_set->wqset_preposts);
		OS_FALLTHROUGH;
	case WQT_SELECT_SET:
	case WQT_QUEUE:
	case WQT_SELECT:
		circle_queue_init(&waitq.wq_q->waitq_queue);
		break;
	}

	if (policy & SYNC_POLICY_INIT_LOCKED) {
		hw_lck_ticket_init_locked(&waitq.wq_q->waitq_interlock, &waitq_lck_grp);
	} else {
		hw_lck_ticket_init(&waitq.wq_q->waitq_interlock, &waitq_lck_grp);
	}
}

void
waitq_deinit(waitq_t waitq)
{
	waitq_type_t type = waitq_type(waitq);

	switch (type) {
	case WQT_QUEUE:
		assert(circle_queue_empty(&waitq.wq_q->waitq_queue));
		waitq_invalidate(waitq);
		break;

	case WQT_TURNSTILE:
		assert(priority_queue_empty(&waitq.wq_q->waitq_prio_queue));
		assert(waitq.wq_q->waitq_inheritor == TURNSTILE_INHERITOR_NULL);
		waitq_invalidate(waitq);
		break;

	case WQT_PORT:
		assert(waitq.wq_q->waitq_ts == TURNSTILE_NULL);
		assert(circle_queue_empty(&waitq.wq_q->waitq_links));
		break;

	case WQT_SELECT:
		assert(waitq.wq_q->waitq_sellinks.next == NULL);
		assert(circle_queue_empty(&waitq.wqs_set->wqset_queue));
		break;

	case WQT_PORT_SET:
		assert(circle_queue_empty(&waitq.wqs_set->wqset_queue));
		assert(circle_queue_empty(&waitq.wqs_set->wqset_links));
		assert(circle_queue_empty(&waitq.wqs_set->wqset_preposts));
		break;

	default:
		panic("invalid wait type: %p/%d", waitq.wq_q, type);
	}

	/*
	 * The waitq must have been invalidated, or hw_lck_ticket_destroy()
	 * below won't wait for reservations from waitq_lock_reserve(),
	 * waitq_lock_reserve_allow_invalid() or waitq_lock_allow_invalid().
	 */
	assert(!waitq_valid(waitq.wqs_set));
	hw_lck_ticket_destroy(&waitq.wq_q->waitq_interlock, &waitq_lck_grp);
}


#pragma mark port-set sets

void
waitq_set_unlink_all_locked(struct waitq_set *wqset, waitq_link_list_t *free_l)
{
	uint32_t batch = waitq_set_unlink_batch;

	waitq_invalidate(wqset);

	for (;;) {
		struct waitq_link *link;
		queue_entry_t elt;
		circle_queue_t q;
		struct waitq *wq;
		uint32_t ticket;
		bool stable = true;

		if (!circle_queue_empty(&wqset->wqset_links)) {
			q = &wqset->wqset_links;
		} else if (!circle_queue_empty(&wqset->wqset_preposts)) {
			q = &wqset->wqset_preposts;
		} else {
			break;
		}

		if (batch-- == 0) {
			waitq_unlock(wqset);
			waitq_lock(wqset);
			batch = waitq_set_unlink_batch;
			continue;
		}

		elt  = circle_queue_first(q);
		link = cqe_element(elt, struct waitq_link, wql_slink);
		wq   = link->wql_wq;

		if (__improbable(!waitq_lock_reserve(wq, &ticket))) {
			waitq_unlock(wqset);
			waitq_lock_wait(wq, ticket);
			waitq_lock(wqset);
			stable = (elt == circle_queue_first(q) && link->wql_wq == wq);
		}

		if (stable) {
			circle_dequeue(q, &link->wql_slink);
			circle_dequeue(&wq->waitq_links, &link->wql_qlink);
			wql_list_push(free_l, link);
		}

		waitq_unlock(wq);
	}
}

void
waitq_clear_prepost_locked(struct waitq *waitq)
{
	assert(waitq_type(waitq) == WQT_PORT);
	waitq->waitq_preposted = false;
}

void
waitq_set_foreach_member_locked(struct waitq_set *wqs, void (^cb)(struct waitq *))
{
	struct waitq_link *link;

	cqe_foreach_element(link, &wqs->wqset_links, wql_slink) {
		cb(link->wql_wq);
	}

	cqe_foreach_element(link, &wqs->wqset_preposts, wql_slink) {
		cb(link->wql_wq);
	}
}

__abortlike
static void
__waitq_link_arguments_panic(struct waitq *waitq, struct waitq_set *wqset)
{
	if (!waitq_valid(waitq)) {
		panic("Invalid waitq: %p", waitq);
	}
	if (waitq_type(waitq) != WQT_PORT) {
		panic("Invalid waitq type: %p:%d", waitq, waitq->waitq_type);
	}
	panic("Invalid waitq-set: %p", wqset);
}

static inline void
__waitq_link_arguments_validate(struct waitq *waitq, struct waitq_set *wqset)
{
	if (!waitq_valid(waitq) ||
	    waitq_type(waitq) != WQT_PORT ||
	    waitq_type(wqset) != WQT_PORT_SET) {
		__waitq_link_arguments_panic(waitq, wqset);
	}
}

__abortlike
static void
__waitq_invalid_panic(waitq_t waitq)
{
	panic("Invalid waitq: %p", waitq.wq_q);
}

static void
__waitq_validate(waitq_t waitq)
{
	if (!waitq_valid(waitq)) {
		__waitq_invalid_panic(waitq);
	}
}

kern_return_t
waitq_link_locked(struct waitq *waitq, struct waitq_set *wqset,
    waitq_link_t *linkp)
{
	assert(linkp->wqlh);

	__waitq_link_arguments_validate(waitq, wqset);

	if (wql_find(waitq, wqset)) {
		return KERN_ALREADY_IN_SET;
	}

	linkp->wqll->wql_wq = waitq;
	linkp->wqll->wql_wqs = (uintptr_t)wqset;

	if (waitq_valid(wqset)) {
		circle_enqueue_tail(&wqset->wqset_links, &linkp->wqll->wql_slink);
		circle_enqueue_tail(&waitq->waitq_links, &linkp->wqll->wql_qlink);
		*linkp = WQL_NULL;
	}

	return KERN_SUCCESS;
}

kern_return_t
waitq_link_prepost_locked(struct waitq *waitq, struct waitq_set *wqset)
{
	struct waitq_link *link;

	__waitq_link_arguments_validate(waitq, wqset);

	link = wql_find(waitq, wqset);
	if (link == NULL) {
		return KERN_NOT_IN_SET;
	}

	if (!wql_wqs_preposted(link)) {
		wql_wqs_mark_preposted(link);
		waitq->waitq_preposted = true;
		circle_dequeue(&wqset->wqset_links, &link->wql_slink);
		circle_enqueue_tail(&wqset->wqset_preposts, &link->wql_slink);
		ipc_pset_prepost(wqset, waitq);
	}

	return KERN_SUCCESS;
}

waitq_link_t
waitq_unlink_locked(struct waitq *waitq, struct waitq_set *wqset)
{
	struct waitq_link *link;

	__waitq_link_arguments_validate(waitq, wqset);

	link = wql_find(waitq, wqset);
	if (link) {
		circle_dequeue(wql_wqs_queue(wqset, link), &link->wql_slink);
		circle_dequeue(&waitq->waitq_links, &link->wql_qlink);
	}

	return (waitq_link_t){ .wqll = link };
}

void
waitq_unlink_all_locked(struct waitq *waitq, struct waitq_set *except_wqset,
    waitq_link_list_t *free_l)
{
	struct waitq_link *kept_link = NULL;
	struct waitq_link *link;

	assert(waitq_type(waitq) == WQT_PORT);

	cqe_foreach_element_safe(link, &waitq->waitq_links, wql_qlink) {
		waitq_t wqs = wql_wqs(link);

		if (wqs.wqs_set == except_wqset) {
			kept_link = link;
			continue;
		}

		waitq_lock(wqs);
		circle_dequeue(wql_wqs_queue(wqs.wqs_set, link),
		    &link->wql_slink);
		wql_list_push(free_l, link);
		waitq_unlock(wqs);
	}

	circle_queue_init(&waitq->waitq_links);
	if (kept_link) {
		circle_enqueue_tail(&waitq->waitq_links, &kept_link->wql_qlink);
	}
}

struct waitq *
waitq_set_first_prepost(struct waitq_set *wqset, wqs_prepost_flags_t flags)
{
	circle_queue_t q = &wqset->wqset_preposts;
	queue_entry_t elt;
	struct waitq_link *link;
	struct waitq *wq;
	uint32_t ticket;

	if (__improbable(!waitq_valid(wqset))) {
		return NULL;
	}

	while (!circle_queue_empty(q)) {
		elt  = circle_queue_first(q);
		link = cqe_element(elt, struct waitq_link, wql_slink);
		wq   = link->wql_wq;

		if (__improbable(!waitq_lock_reserve(wq, &ticket))) {
			waitq_unlock(wqset);
			waitq_lock_wait(wq, ticket);
			waitq_lock(wqset);
			if (!waitq_valid(wqset)) {
				waitq_unlock(wq);
				return NULL;
			}

			if (elt != circle_queue_first(q) || link->wql_wq != wq) {
				waitq_unlock(wq);
				continue;
			}
		}

		if (wq->waitq_preposted) {
			if ((flags & WQS_PREPOST_PEEK) == 0) {
				circle_queue_rotate_head_forward(q);
			}
			if ((flags & WQS_PREPOST_LOCK) == 0) {
				waitq_unlock(wq);
			}
			return wq;
		}

		/*
		 * We found a link that is no longer preposted,
		 * someone must have called waitq_clear_prepost_locked()
		 * and this set just only noticed.
		 */
		wql_wqs_clear_preposted(link);
		waitq_unlock(wq);

		circle_dequeue(q, &link->wql_slink);
		circle_enqueue_tail(&wqset->wqset_links, &link->wql_slink);
	}

	return NULL;
}


#pragma mark select sets

/**
 * @function select_set_nextid()
 *
 * @brief
 * Generate a unique ID for a select set "generation"
 *
 * @discussion
 * This mixes the CPU number with a monotonic clock
 * (in order to avoid contention on a global atomic).
 *
 * In order for select sets to be invalidated very quickly,
 * they do not have backward linkages to their member queues.
 *
 * Instead, each time a new @c select() "pass" is initiated,
 * a new ID is generated, which is copied onto the @c waitq_sellink
 * links at the time of link.
 *
 * The zone for select sets is sequestered, which allows for select
 * wait queues to speculatively lock their set during prepost
 * and use this ID to debounce wakeups and avoid spurious wakeups
 * (as an "optimization" because select recovers from spurious wakeups,
 * we just want those to be very rare).
 */
__attribute__((always_inline))
static inline uint64_t
select_set_nextid(bool preemption_enabled)
{
	/* waitq_bootstrap() set the low byte to a unique value per CPU */
	static_assert(MAX_CPUS <= 256);
	const uint64_t inc = 256;
	uint64_t id;

#ifdef __x86_64__
	/* uncontended atomics are slower than disabling preemption on Intel */
	if (preemption_enabled) {
		disable_preemption();
	}
	id = (*PERCPU_GET(select_setid) += inc);
	if (preemption_enabled) {
		enable_preemption();
	}
#else
	/*
	 * if preemption is enabled this might update another CPU's
	 * setid, which will be rare but is acceptable, it still
	 * produces a unique select ID.
	 *
	 * We chose this because the uncontended atomics on !intel
	 * are faster than disabling/reenabling preemption.
	 */
	(void)preemption_enabled;
	id = os_atomic_add(PERCPU_GET(select_setid), inc, relaxed);
#endif

	return id;
}

struct select_set *
select_set_alloc(void)
{
	struct select_set *selset;
	selset = zalloc_id(ZONE_ID_SELECT_SET, Z_ZERO | Z_WAITOK | Z_NOFAIL);

	waitq_init(selset, WQT_SELECT_SET, SYNC_POLICY_FIFO);
	selset->selset_id = select_set_nextid(true);

	return selset;
}

__abortlike
static void
__select_set_link_arguments_panic(struct waitq *waitq, struct select_set *set)
{
	if (!waitq_valid(waitq)) {
		panic("Invalid waitq: %p", waitq);
	}
	if (waitq_type(waitq) != WQT_SELECT) {
		panic("Invalid waitq type: %p:%d", waitq, waitq->waitq_type);
	}
	panic("Invalid waitq-set: %p", set);
}

static inline void
__select_set_link_arguments_validate(struct waitq *waitq, struct select_set *set)
{
	if (!waitq_valid(waitq) ||
	    waitq_type(waitq) != WQT_SELECT ||
	    waitq_type(set) != WQT_SELECT_SET) {
		__select_set_link_arguments_panic(waitq, set);
	}
}

void
select_set_link(struct waitq *waitq, struct select_set *set,
    waitq_link_t *linkp)
{
	struct waitq_sellink *link;

	__select_set_link_arguments_validate(waitq, set);

	waitq_lock(waitq);

	if (waitq == &select_conflict_queue) {
		waitq_lock(set);
		set->selset_conflict = true;
		waitq_unlock(set);
	}

	wql_list_foreach(link, &waitq->waitq_sellinks) {
		if (waitq_same(wql_wqs(link), set)) {
			goto found;
		}
	}

	link = linkp->wqls;
	*linkp = WQL_NULL;
	wql_list_push(&waitq->waitq_sellinks, link);

found:
	link->wql_wqs = (uintptr_t)set;
	link->wql_setid = set->selset_id;
	waitq_unlock(waitq);
}

static void
select_set_unlink_conflict_queue(struct select_set *set)
{
	struct waitq_link_list_entry **prev;
	struct waitq_sellink *link;

	waitq_lock(&select_conflict_queue);

	/*
	 * We know the conflict queue is hooked,
	 * so find the linkage and free it.
	 */
	prev = &select_conflict_queue.waitq_sellinks.next;
	for (;;) {
		assert(*prev);
		link = wql_list_elem(*prev);
		if (waitq_same(wql_wqs(link), set)) {
			*prev = link->wql_next.next;
			break;
		}
		prev = &link->wql_next.next;
	}

	waitq_unlock(&select_conflict_queue);

	waitq_link_free(WQT_SELECT_SET, link);
}

static void
__select_set_reset(struct select_set *set, bool invalidate)
{
	if (set->selset_conflict) {
		select_set_unlink_conflict_queue(set);
	}

	waitq_lock(set);
	if (invalidate) {
		waitq_invalidate(set);
	}
	set->selset_id = select_set_nextid(false);
	set->selset_preposted = 0;
	set->selset_conflict = 0;
	waitq_unlock(set);
}

void
select_set_reset(struct select_set *set)
{
	__select_set_reset(set, false);
}

void
select_set_free(struct select_set *set)
{
	__select_set_reset(set, true);
	hw_lck_ticket_destroy(&set->selset_interlock, &waitq_lck_grp);
	zfree_id(ZONE_ID_SELECT_SET, set);
}

void
select_waitq_wakeup_and_deinit(
	struct waitq           *waitq,
	event64_t               wake_event,
	wait_result_t           result,
	int                     priority)
{
	waitq_link_list_t free_l = { };

	if (waitq_is_valid(waitq)) {
		assert(waitq_type(waitq) == WQT_SELECT);

		waitq_lock(waitq);

		waitq_wakeup64_all_locked(waitq, wake_event, result,
		    priority, WAITQ_KEEP_LOCKED);

		waitq_invalidate(waitq);
		free_l = waitq->waitq_sellinks;
		waitq->waitq_sellinks.next = NULL;

		waitq_unlock(waitq);

		waitq_link_free_list(WQT_SELECT, &free_l);

		waitq_deinit(waitq);
	}
}

#pragma mark assert_wait / wakeup (high level)

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
	    TIMEOUT_URGENCY_SYS_NORMAL, deadline, TIMEOUT_NO_LEEWAY, thread);

	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq)) {
		splx(s);
	}

	return ret;
}

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

kern_return_t
waitq_wakeup64_one(struct waitq *waitq, event64_t wake_event,
    wait_result_t result, int priority)
{
	kern_return_t kr;
	spl_t spl = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		spl = splsched();
	}
	waitq_lock(waitq);

	/* waitq is locked upon return */
	kr = waitq_wakeup64_one_locked(waitq, wake_event, result,
	    priority, WAITQ_UNLOCK, WQ_OPTION_NONE);

	if (waitq_irq_safe(waitq)) {
		splx(spl);
	}

	return kr;
}

kern_return_t
waitq_wakeup64_all(waitq_t waitq, event64_t wake_event,
    wait_result_t result, int priority)
{
	kern_return_t ret;
	spl_t spl = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		spl = splsched();
	}
	waitq_lock(waitq);

	ret = waitq_wakeup64_all_locked(waitq, wake_event, result,
	    priority, WAITQ_UNLOCK);

	if (waitq_irq_safe(waitq)) {
		splx(spl);
	}

	return ret;
}

kern_return_t
waitq_wakeup64_thread(struct waitq *waitq, event64_t event,
    thread_t thread, wait_result_t result)
{
	spl_t s = splsched();
	kern_return_t ret;

	__waitq_validate(waitq);
	assert(waitq_irq_safe(waitq));
	waitq_lock(waitq);

	ret = waitq_wakeup64_thread_and_unlock(waitq, event, thread, result);

	splx(s);

	return ret;
}

thread_t
waitq_wakeup64_identify(waitq_t waitq, event64_t wake_event,
    wait_result_t result, int priority)
{
	spl_t thread_spl = 0;
	thread_t thread;
	spl_t spl = 0;

	__waitq_validate(waitq);

	if (waitq_irq_safe(waitq)) {
		spl = splsched();
	}
	waitq_lock(waitq);

	thread = waitq_wakeup64_identify_locked(waitq, wake_event, result,
	    &thread_spl, priority, WAITQ_UNLOCK);
	/* waitq is unlocked, thread is locked */

	if (thread != THREAD_NULL) {
		thread_reference(thread);
		thread_unlock(thread);
		splx(thread_spl);
	}

	if (waitq_irq_safe(waitq)) {
		splx(spl);
	}

	/* returns +1 ref to running thread or THREAD_NULL */
	return thread;
}


#pragma mark tests
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
			waitq_init(&wqt_waitq_array[i], WQT_PORT, SYNC_POLICY_FIFO);
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
	printf("[WQ]: created waitq set %p\n", wqset);
	return wqset;
}

static void
wqt_wqset_free(struct waitq_set *wqset)
{
	printf("[WQ]: destroying waitq set %p\n", wqset);
	waitq_lock(wqset);
	ipc_pset_destroy(ipc_space_kernel,
	    __container_of(wqset, struct ipc_pset, ips_wqset));
}

static void
wqt_link(uint32_t index, struct waitq_set *wqset, kern_return_t want)
{
	struct waitq *waitq = wqt_wq(index);
	waitq_link_t link = waitq_link_alloc(WQT_PORT_SET);
	kern_return_t kr;

	printf("[WQ]: linking waitq [%d] to global wqset (%p)\n", index, wqset);

	waitq_lock(waitq);
	waitq_lock(wqset);
	kr = waitq_link_locked(waitq, wqset, &link);
	waitq_unlock(wqset);
	waitq_unlock(waitq);

	if (link.wqlh) {
		waitq_link_free(WQT_PORT_SET, link);
	}

	printf("[WQ]:\tkr=%d\texpected=%d\n", kr, want);
	assert(kr == want);
}

static void
wqt_unlink(uint32_t index, struct waitq_set *wqset, kern_return_t want)
{
	struct waitq *waitq = wqt_wq(index);
	waitq_link_t link;
	kern_return_t kr;

	printf("[WQ]: unlinking waitq [%d] from global wqset (%p)\n",
	    index, wqset);

	waitq_lock(waitq);
	waitq_lock(wqset);
	link = waitq_unlink_locked(waitq, wqset);
	waitq_unlock(wqset);
	waitq_unlock(waitq);

	if (link.wqlh) {
		waitq_link_free(WQT_PORT_SET, link);
		kr = KERN_SUCCESS;
	} else {
		kr = KERN_NOT_IN_SET;
	}

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
wqt_preposts_gc_locked(struct waitq_set *wqset)
{
	circle_queue_t q = &wqset->wqset_preposts;
	struct waitq_link *link;
	uint32_t ticket;

again:
	cqe_foreach_element_safe(link, q, wql_slink) {
		struct waitq *wq = link->wql_wq;

		if (!waitq_lock_reserve(wq, &ticket)) {
			waitq_unlock(wqset);
			waitq_lock_wait(wq, ticket);
			waitq_lock(wqset);
			waitq_unlock(wq);
			/* the list was possibly mutated, restart */
			goto again;
		}

		if (!wq->waitq_preposted) {
			wql_wqs_clear_preposted(link);
			circle_dequeue(q, &link->wql_slink);
			circle_enqueue_tail(&wqset->wqset_links, &link->wql_slink);
		}

		waitq_unlock(wq);
	}
}

static void
wqt_expect_preposts(struct waitq_set *wqset, uint64_t preposts)
{
	struct waitq_link *link;
	uint64_t found = 0;

	waitq_lock(wqset);

	wqt_preposts_gc_locked(wqset);

	cqe_foreach_element(link, &wqset->wqset_preposts, wql_slink) {
		struct waitq *waitq = link->wql_wq;

		printf("[WQ]: found prepost %d\n", wqt_idx(waitq));
		assertf((found & wqt_bit(waitq)) == 0,
		    "found waitq %d twice", wqt_idx(waitq));
		found |= wqt_bit(waitq);
	}

	waitq_unlock(wqset);

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
