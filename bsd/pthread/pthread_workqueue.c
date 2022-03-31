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
/* Copyright (c) 1995-2018 Apple, Inc. All Rights Reserved */

#include <sys/cdefs.h>

#include <kern/assert.h>
#include <kern/ast.h>
#include <kern/clock.h>
#include <kern/cpu_data.h>
#include <kern/kern_types.h>
#include <kern/policy_internal.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>    /* for thread_exception_return */
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/zalloc.h>
#include <mach/kern_return.h>
#include <mach/mach_param.h>
#include <mach/mach_port.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/sync_policy.h>
#include <mach/task.h>
#include <mach/thread_act.h> /* for thread_resume */
#include <mach/thread_policy.h>
#include <mach/thread_status.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <machine/atomic.h>
#include <machine/machine_routines.h>
#include <machine/smp.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>

#include <sys/eventvar.h>
#include <sys/kdebug.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/param.h>
#include <sys/proc_info.h>      /* for fill_procworkqueue */
#include <sys/proc_internal.h>
#include <sys/pthread_shims.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ulock.h> /* for ulock_owner_value_to_port_name */

#include <pthread/bsdthread_private.h>
#include <pthread/workqueue_syscalls.h>
#include <pthread/workqueue_internal.h>
#include <pthread/workqueue_trace.h>

#include <os/log.h>

static void workq_unpark_continue(void *uth, wait_result_t wr) __dead2;
static void workq_schedule_creator(proc_t p, struct workqueue *wq,
    workq_kern_threadreq_flags_t flags);

static bool workq_threadreq_admissible(struct workqueue *wq, struct uthread *uth,
    workq_threadreq_t req);

static uint32_t workq_constrained_allowance(struct workqueue *wq,
    thread_qos_t at_qos, struct uthread *uth, bool may_start_timer);

static bool _wq_cooperative_queue_refresh_best_req_qos(struct workqueue *wq);

static bool workq_thread_is_busy(uint64_t cur_ts,
    _Atomic uint64_t *lastblocked_tsp);

static int workq_sysctl_handle_usecs SYSCTL_HANDLER_ARGS;

static bool
workq_schedule_delayed_thread_creation(struct workqueue *wq, int flags);

static inline void
workq_lock_spin(struct workqueue *wq);

static inline void
workq_unlock(struct workqueue *wq);

#pragma mark globals

struct workq_usec_var {
	uint32_t usecs;
	uint64_t abstime;
};

#define WORKQ_SYSCTL_USECS(var, init) \
	        static struct workq_usec_var var = { .usecs = init }; \
	        SYSCTL_OID(_kern, OID_AUTO, var##_usecs, \
	                        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &var, 0, \
	                        workq_sysctl_handle_usecs, "I", "")

static LCK_GRP_DECLARE(workq_lck_grp, "workq");
os_refgrp_decl(static, workq_refgrp, "workq", NULL);

static ZONE_DEFINE(workq_zone_workqueue, "workq.wq",
    sizeof(struct workqueue), ZC_NONE);
static ZONE_DEFINE(workq_zone_threadreq, "workq.threadreq",
    sizeof(struct workq_threadreq_s), ZC_CACHING);

static struct mpsc_daemon_queue workq_deallocate_queue;

WORKQ_SYSCTL_USECS(wq_stalled_window, WQ_STALLED_WINDOW_USECS);
WORKQ_SYSCTL_USECS(wq_reduce_pool_window, WQ_REDUCE_POOL_WINDOW_USECS);
WORKQ_SYSCTL_USECS(wq_max_timer_interval, WQ_MAX_TIMER_INTERVAL_USECS);
static uint32_t wq_max_threads              = WORKQUEUE_MAXTHREADS;
static uint32_t wq_max_constrained_threads  = WORKQUEUE_MAXTHREADS / 8;
static uint32_t wq_init_constrained_limit   = 1;
static uint16_t wq_death_max_load;
static uint32_t wq_max_parallelism[WORKQ_NUM_QOS_BUCKETS];

/*
 * This is not a hard limit but the max size we want to aim to hit across the
 * entire cooperative pool. We can oversubscribe the pool due to non-cooperative
 * workers and the max we will oversubscribe the pool by, is a total of
 * wq_max_cooperative_threads * WORKQ_NUM_QOS_BUCKETS.
 */
static uint32_t wq_max_cooperative_threads;

static inline uint32_t
wq_cooperative_queue_max_size(struct workqueue *wq)
{
	return wq->wq_cooperative_queue_has_limited_max_size ? 1 : wq_max_cooperative_threads;
}

#pragma mark sysctls

static int
workq_sysctl_handle_usecs SYSCTL_HANDLER_ARGS
{
#pragma unused(arg2)
	struct workq_usec_var *v = arg1;
	int error = sysctl_handle_int(oidp, &v->usecs, 0, req);
	if (error || !req->newptr) {
		return error;
	}
	clock_interval_to_absolutetime_interval(v->usecs, NSEC_PER_USEC,
	    &v->abstime);
	return 0;
}

SYSCTL_INT(_kern, OID_AUTO, wq_max_threads, CTLFLAG_RW | CTLFLAG_LOCKED,
    &wq_max_threads, 0, "");

SYSCTL_INT(_kern, OID_AUTO, wq_max_constrained_threads, CTLFLAG_RW | CTLFLAG_LOCKED,
    &wq_max_constrained_threads, 0, "");

static int
wq_limit_cooperative_threads_for_proc SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int input_pool_size = 0;
	int changed;
	int error = 0;

	error = sysctl_io_number(req, 0, sizeof(int), &input_pool_size, &changed);
	if (error || !changed) {
		return error;
	}

#define WQ_COOPERATIVE_POOL_SIZE_DEFAULT 0
#define WQ_COOPERATIVE_POOL_SIZE_STRICT_PER_QOS -1
/* Not available currently, but sysctl interface is designed to allow these
 * extra parameters:
 *		WQ_COOPERATIVE_POOL_SIZE_STRICT : -2 (across all bucket)
 *		WQ_COOPERATIVE_POOL_SIZE_CUSTOM : [1, 512]
 */

	if (input_pool_size != WQ_COOPERATIVE_POOL_SIZE_DEFAULT
	    && input_pool_size != WQ_COOPERATIVE_POOL_SIZE_STRICT_PER_QOS) {
		error = EINVAL;
		goto out;
	}

	proc_t p = req->p;
	struct workqueue *wq = proc_get_wqptr(p);

	if (wq != NULL) {
		workq_lock_spin(wq);
		if (wq->wq_reqcount > 0 || wq->wq_nthreads > 0) {
			// Hackily enforce that the workqueue is still new (no requests or
			// threads)
			error = ENOTSUP;
		} else {
			wq->wq_cooperative_queue_has_limited_max_size = (input_pool_size == WQ_COOPERATIVE_POOL_SIZE_STRICT_PER_QOS);
		}
		workq_unlock(wq);
	} else {
		/* This process has no workqueue, calling this syctl makes no sense */
		return ENOTSUP;
	}

out:
	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, wq_limit_cooperative_threads,
    CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_WR | CTLFLAG_LOCKED | CTLTYPE_INT, 0, 0,
    wq_limit_cooperative_threads_for_proc,
    "I", "Modify the max pool size of the cooperative pool");

#pragma mark p_wqptr

#define WQPTR_IS_INITING_VALUE ((struct workqueue *)~(uintptr_t)0)

static struct workqueue *
proc_get_wqptr_fast(struct proc *p)
{
	return os_atomic_load(&p->p_wqptr, relaxed);
}

struct workqueue *
proc_get_wqptr(struct proc *p)
{
	struct workqueue *wq = proc_get_wqptr_fast(p);
	return wq == WQPTR_IS_INITING_VALUE ? NULL : wq;
}

static void
proc_set_wqptr(struct proc *p, struct workqueue *wq)
{
	wq = os_atomic_xchg(&p->p_wqptr, wq, release);
	if (wq == WQPTR_IS_INITING_VALUE) {
		proc_lock(p);
		thread_wakeup(&p->p_wqptr);
		proc_unlock(p);
	}
}

static bool
proc_init_wqptr_or_wait(struct proc *p)
{
	struct workqueue *wq;

	proc_lock(p);
	wq = os_atomic_load(&p->p_wqptr, relaxed);

	if (wq == NULL) {
		os_atomic_store(&p->p_wqptr, WQPTR_IS_INITING_VALUE, relaxed);
		proc_unlock(p);
		return true;
	}

	if (wq == WQPTR_IS_INITING_VALUE) {
		assert_wait(&p->p_wqptr, THREAD_UNINT);
		proc_unlock(p);
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		proc_unlock(p);
	}
	return false;
}

static inline event_t
workq_parked_wait_event(struct uthread *uth)
{
	return (event_t)&uth->uu_workq_stackaddr;
}

static inline void
workq_thread_wakeup(struct uthread *uth)
{
	thread_wakeup_thread(workq_parked_wait_event(uth), get_machthread(uth));
}

#pragma mark wq_thactive

#if defined(__LP64__)
// Layout is:
//   127 - 115 : 13 bits of zeroes
//   114 - 112 : best QoS among all pending constrained requests
//   111 -   0 : MGR, AUI, UI, IN, DF, UT, BG+MT buckets every 16 bits
#define WQ_THACTIVE_BUCKET_WIDTH 16
#define WQ_THACTIVE_QOS_SHIFT    (7 * WQ_THACTIVE_BUCKET_WIDTH)
#else
// Layout is:
//   63 - 61 : best QoS among all pending constrained requests
//   60      : Manager bucket (0 or 1)
//   59 -  0 : AUI, UI, IN, DF, UT, BG+MT buckets every 10 bits
#define WQ_THACTIVE_BUCKET_WIDTH 10
#define WQ_THACTIVE_QOS_SHIFT    (6 * WQ_THACTIVE_BUCKET_WIDTH + 1)
#endif
#define WQ_THACTIVE_BUCKET_MASK  ((1U << WQ_THACTIVE_BUCKET_WIDTH) - 1)
#define WQ_THACTIVE_BUCKET_HALF  (1U << (WQ_THACTIVE_BUCKET_WIDTH - 1))

static_assert(sizeof(wq_thactive_t) * CHAR_BIT - WQ_THACTIVE_QOS_SHIFT >= 3,
    "Make sure we have space to encode a QoS");

static inline wq_thactive_t
_wq_thactive(struct workqueue *wq)
{
	return os_atomic_load_wide(&wq->wq_thactive, relaxed);
}

static inline uint8_t
_wq_bucket(thread_qos_t qos)
{
	// Map both BG and MT to the same bucket by over-shifting down and
	// clamping MT and BG together.
	switch (qos) {
	case THREAD_QOS_MAINTENANCE:
		return 0;
	default:
		return qos - 2;
	}
}

#define WQ_THACTIVE_BEST_CONSTRAINED_REQ_QOS(tha) \
	        ((thread_qos_t)((tha) >> WQ_THACTIVE_QOS_SHIFT))

static inline thread_qos_t
_wq_thactive_best_constrained_req_qos(struct workqueue *wq)
{
	// Avoid expensive atomic operations: the three bits we're loading are in
	// a single byte, and always updated under the workqueue lock
	wq_thactive_t v = *(wq_thactive_t *)&wq->wq_thactive;
	return WQ_THACTIVE_BEST_CONSTRAINED_REQ_QOS(v);
}

static void
_wq_thactive_refresh_best_constrained_req_qos(struct workqueue *wq)
{
	thread_qos_t old_qos, new_qos;
	workq_threadreq_t req;

	req = priority_queue_max(&wq->wq_constrained_queue,
	    struct workq_threadreq_s, tr_entry);
	new_qos = req ? req->tr_qos : THREAD_QOS_UNSPECIFIED;
	old_qos = _wq_thactive_best_constrained_req_qos(wq);
	if (old_qos != new_qos) {
		long delta = (long)new_qos - (long)old_qos;
		wq_thactive_t v = (wq_thactive_t)delta << WQ_THACTIVE_QOS_SHIFT;
		/*
		 * We can do an atomic add relative to the initial load because updates
		 * to this qos are always serialized under the workqueue lock.
		 */
		v = os_atomic_add(&wq->wq_thactive, v, relaxed);
#ifdef __LP64__
		WQ_TRACE_WQ(TRACE_wq_thactive_update, wq, (uint64_t)v,
		    (uint64_t)(v >> 64), 0);
#else
		WQ_TRACE_WQ(TRACE_wq_thactive_update, wq, v, 0, 0);
#endif
	}
}

static inline wq_thactive_t
_wq_thactive_offset_for_qos(thread_qos_t qos)
{
	uint8_t bucket = _wq_bucket(qos);
	__builtin_assume(bucket < WORKQ_NUM_BUCKETS);
	return (wq_thactive_t)1 << (bucket * WQ_THACTIVE_BUCKET_WIDTH);
}

static inline wq_thactive_t
_wq_thactive_inc(struct workqueue *wq, thread_qos_t qos)
{
	wq_thactive_t v = _wq_thactive_offset_for_qos(qos);
	return os_atomic_add_orig(&wq->wq_thactive, v, relaxed);
}

static inline wq_thactive_t
_wq_thactive_dec(struct workqueue *wq, thread_qos_t qos)
{
	wq_thactive_t v = _wq_thactive_offset_for_qos(qos);
	return os_atomic_sub_orig(&wq->wq_thactive, v, relaxed);
}

static inline void
_wq_thactive_move(struct workqueue *wq,
    thread_qos_t old_qos, thread_qos_t new_qos)
{
	wq_thactive_t v = _wq_thactive_offset_for_qos(new_qos) -
	    _wq_thactive_offset_for_qos(old_qos);
	os_atomic_add(&wq->wq_thactive, v, relaxed);
	wq->wq_thscheduled_count[_wq_bucket(old_qos)]--;
	wq->wq_thscheduled_count[_wq_bucket(new_qos)]++;
}

static inline uint32_t
_wq_thactive_aggregate_downto_qos(struct workqueue *wq, wq_thactive_t v,
    thread_qos_t qos, uint32_t *busycount, uint32_t *max_busycount)
{
	uint32_t count = 0, active;
	uint64_t curtime;

	assert(WORKQ_THREAD_QOS_MIN <= qos && qos <= WORKQ_THREAD_QOS_MAX);

	if (busycount) {
		curtime = mach_absolute_time();
		*busycount = 0;
	}
	if (max_busycount) {
		*max_busycount = THREAD_QOS_LAST - qos;
	}

	uint8_t i = _wq_bucket(qos);
	v >>= i * WQ_THACTIVE_BUCKET_WIDTH;
	for (; i < WORKQ_NUM_QOS_BUCKETS; i++, v >>= WQ_THACTIVE_BUCKET_WIDTH) {
		active = v & WQ_THACTIVE_BUCKET_MASK;
		count += active;

		if (busycount && wq->wq_thscheduled_count[i] > active) {
			if (workq_thread_is_busy(curtime, &wq->wq_lastblocked_ts[i])) {
				/*
				 * We only consider the last blocked thread for a given bucket
				 * as busy because we don't want to take the list lock in each
				 * sched callback. However this is an approximation that could
				 * contribute to thread creation storms.
				 */
				(*busycount)++;
			}
		}
	}

	return count;
}

static inline void
_wq_cooperative_queue_scheduled_count_dec(struct workqueue *wq, thread_qos_t qos)
{
	__assert_only uint8_t old_scheduled_count = wq->wq_cooperative_queue_scheduled_count[_wq_bucket(qos)]--;
	assert(old_scheduled_count > 0);
}

static inline void
_wq_cooperative_queue_scheduled_count_inc(struct workqueue *wq, thread_qos_t qos)
{
	__assert_only uint8_t old_scheduled_count = wq->wq_cooperative_queue_scheduled_count[_wq_bucket(qos)]++;
	assert(old_scheduled_count < UINT8_MAX);
}

#pragma mark wq_flags

static inline uint32_t
_wq_flags(struct workqueue *wq)
{
	return os_atomic_load(&wq->wq_flags, relaxed);
}

static inline bool
_wq_exiting(struct workqueue *wq)
{
	return _wq_flags(wq) & WQ_EXITING;
}

bool
workq_is_exiting(struct proc *p)
{
	struct workqueue *wq = proc_get_wqptr(p);
	return !wq || _wq_exiting(wq);
}


#pragma mark workqueue lock

static bool
workq_lock_is_acquired_kdp(struct workqueue *wq)
{
	return kdp_lck_ticket_is_acquired(&wq->wq_lock);
}

static inline void
workq_lock_spin(struct workqueue *wq)
{
	lck_ticket_lock(&wq->wq_lock, &workq_lck_grp);
}

static inline void
workq_lock_held(struct workqueue *wq)
{
	LCK_TICKET_ASSERT_OWNED(&wq->wq_lock);
}

static inline bool
workq_lock_try(struct workqueue *wq)
{
	return lck_ticket_lock_try(&wq->wq_lock, &workq_lck_grp);
}

static inline void
workq_unlock(struct workqueue *wq)
{
	lck_ticket_unlock(&wq->wq_lock);
}

#pragma mark idle thread lists

#define WORKQ_POLICY_INIT(qos) \
	        (struct uu_workq_policy){ .qos_req = qos, .qos_bucket = qos }

static inline thread_qos_t
workq_pri_bucket(struct uu_workq_policy req)
{
	return MAX(MAX(req.qos_req, req.qos_max), req.qos_override);
}

static inline thread_qos_t
workq_pri_override(struct uu_workq_policy req)
{
	return MAX(workq_pri_bucket(req), req.qos_bucket);
}

static inline bool
workq_thread_needs_params_change(workq_threadreq_t req, struct uthread *uth)
{
	workq_threadreq_param_t cur_trp, req_trp = { };

	cur_trp.trp_value = uth->uu_save.uus_workq_park_data.workloop_params;
	if (req->tr_flags & WORKQ_TR_FLAG_WL_PARAMS) {
		req_trp = kqueue_threadreq_workloop_param(req);
	}

	/*
	 * CPU percent flags are handled separately to policy changes, so ignore
	 * them for all of these checks.
	 */
	uint16_t cur_flags = (cur_trp.trp_flags & ~TRP_CPUPERCENT);
	uint16_t req_flags = (req_trp.trp_flags & ~TRP_CPUPERCENT);

	if (!req_flags && !cur_flags) {
		return false;
	}

	if (req_flags != cur_flags) {
		return true;
	}

	if ((req_flags & TRP_PRIORITY) && req_trp.trp_pri != cur_trp.trp_pri) {
		return true;
	}

	if ((req_flags & TRP_POLICY) && req_trp.trp_pol != cur_trp.trp_pol) {
		return true;
	}

	return false;
}

static inline bool
workq_thread_needs_priority_change(workq_threadreq_t req, struct uthread *uth)
{
	if (workq_thread_needs_params_change(req, uth)) {
		return true;
	}

	if (req->tr_qos != workq_pri_override(uth->uu_workq_pri)) {
		return true;
	}

#if CONFIG_PREADOPT_TG
	thread_group_qos_t tg = kqr_preadopt_thread_group(req);
	if (KQWL_HAS_VALID_PREADOPTED_TG(tg)) {
		/*
		 * Ideally, we'd add check here to see if thread's preadopt TG is same
		 * as the thread requests's thread group and short circuit if that is
		 * the case. But in the interest of keeping the code clean and not
		 * taking the thread lock here, we're going to skip this. We will
		 * eventually shortcircuit once we try to set the preadoption thread
		 * group on the thread.
		 */
		return true;
	}
#endif

	return false;
}

static void
workq_thread_update_bucket(proc_t p, struct workqueue *wq, struct uthread *uth,
    struct uu_workq_policy old_pri, struct uu_workq_policy new_pri,
    bool force_run)
{
	thread_qos_t old_bucket = old_pri.qos_bucket;
	thread_qos_t new_bucket = workq_pri_bucket(new_pri);

	if (old_bucket != new_bucket) {
		_wq_thactive_move(wq, old_bucket, new_bucket);
	}

	new_pri.qos_bucket = new_bucket;
	uth->uu_workq_pri = new_pri;

	if (workq_pri_override(old_pri) != new_bucket) {
		thread_set_workq_override(get_machthread(uth), new_bucket);
	}

	if (wq->wq_reqcount && (old_bucket > new_bucket || force_run)) {
		int flags = WORKQ_THREADREQ_CAN_CREATE_THREADS;
		if (old_bucket > new_bucket) {
			/*
			 * When lowering our bucket, we may unblock a thread request,
			 * but we can't drop our priority before we have evaluated
			 * whether this is the case, and if we ever drop the workqueue lock
			 * that would cause a priority inversion.
			 *
			 * We hence have to disallow thread creation in that case.
			 */
			flags = 0;
		}
		workq_schedule_creator(p, wq, flags);
	}
}

/*
 * Sets/resets the cpu percent limits on the current thread. We can't set
 * these limits from outside of the current thread, so this function needs
 * to be called when we're executing on the intended
 */
static void
workq_thread_reset_cpupercent(workq_threadreq_t req, struct uthread *uth)
{
	assert(uth == current_uthread());
	workq_threadreq_param_t trp = { };

	if (req && (req->tr_flags & WORKQ_TR_FLAG_WL_PARAMS)) {
		trp = kqueue_threadreq_workloop_param(req);
	}

	if (uth->uu_workq_flags & UT_WORKQ_CPUPERCENT) {
		/*
		 * Going through disable when we have an existing CPU percent limit
		 * set will force the ledger to refill the token bucket of the current
		 * thread. Removing any penalty applied by previous thread use.
		 */
		thread_set_cpulimit(THREAD_CPULIMIT_DISABLE, 0, 0);
		uth->uu_workq_flags &= ~UT_WORKQ_CPUPERCENT;
	}

	if (trp.trp_flags & TRP_CPUPERCENT) {
		thread_set_cpulimit(THREAD_CPULIMIT_BLOCK, trp.trp_cpupercent,
		    (uint64_t)trp.trp_refillms * NSEC_PER_SEC);
		uth->uu_workq_flags |= UT_WORKQ_CPUPERCENT;
	}
}

/* Called with the workq lock held */
static void
workq_thread_reset_pri(struct workqueue *wq, struct uthread *uth,
    workq_threadreq_t req, bool unpark)
{
	thread_t th = get_machthread(uth);
	thread_qos_t qos = req ? req->tr_qos : WORKQ_THREAD_QOS_CLEANUP;
	workq_threadreq_param_t trp = { };
	int priority = 31;
	int policy = POLICY_TIMESHARE;

	if (req && (req->tr_flags & WORKQ_TR_FLAG_WL_PARAMS)) {
		trp = kqueue_threadreq_workloop_param(req);
	}

	uth->uu_workq_pri = WORKQ_POLICY_INIT(qos);
	uth->uu_workq_flags &= ~UT_WORKQ_OUTSIDE_QOS;

	if (unpark) {
		uth->uu_save.uus_workq_park_data.workloop_params = trp.trp_value;
		// qos sent out to userspace (may differ from uu_workq_pri on param threads)
		uth->uu_save.uus_workq_park_data.qos = qos;
	}

	if (qos == WORKQ_THREAD_QOS_MANAGER) {
		uint32_t mgr_pri = wq->wq_event_manager_priority;
		assert(trp.trp_value == 0); // manager qos and thread policy don't mix

		if (mgr_pri & _PTHREAD_PRIORITY_SCHED_PRI_FLAG) {
			mgr_pri &= _PTHREAD_PRIORITY_SCHED_PRI_MASK;
			thread_set_workq_pri(th, THREAD_QOS_UNSPECIFIED, mgr_pri,
			    POLICY_TIMESHARE);
			return;
		}

		qos = _pthread_priority_thread_qos(mgr_pri);
	} else {
		if (trp.trp_flags & TRP_PRIORITY) {
			qos = THREAD_QOS_UNSPECIFIED;
			priority = trp.trp_pri;
			uth->uu_workq_flags |= UT_WORKQ_OUTSIDE_QOS;
		}

		if (trp.trp_flags & TRP_POLICY) {
			policy = trp.trp_pol;
		}
	}

#if CONFIG_PREADOPT_TG
	if (req && (req->tr_flags & WORKQ_TR_FLAG_WORKLOOP)) {
		/*
		 * We cannot safely read and borrow the reference from the kqwl since it
		 * can disappear from under us at any time due to the max-ing logic in
		 * kqueue_set_preadopted_thread_group.
		 *
		 * As such, we do the following dance:
		 *
		 * 1) cmpxchng and steal the kqwl's preadopt thread group and leave
		 * behind with (NULL + QoS). At this point, we have the reference
		 * to the thread group from the kqwl.
		 * 2) Have the thread set the preadoption thread group on itself.
		 * 3) cmpxchng from (NULL + QoS) which we set earlier in (1), back to
		 * thread_group + QoS. ie we try to give the reference back to the kqwl.
		 * If we fail, that's because a higher QoS thread group was set on the
		 * kqwl in kqueue_set_preadopted_thread_group in which case, we need to
		 * go back to (1).
		 */

		_Atomic(struct thread_group *) * tg_loc = kqr_preadopt_thread_group_addr(req);

		thread_group_qos_t old_tg, new_tg;
		int ret = 0;
again:
		ret = os_atomic_rmw_loop(tg_loc, old_tg, new_tg, relaxed, {
			if (!KQWL_HAS_VALID_PREADOPTED_TG(old_tg)) {
			        os_atomic_rmw_loop_give_up(break);
			}

			/*
			 * Leave the QoS behind - kqueue_set_preadopted_thread_group will
			 * only modify it if there is a higher QoS thread group to attach
			 */
			new_tg = (thread_group_qos_t) ((uintptr_t) old_tg & KQWL_PREADOPT_TG_QOS_MASK);
		});

		if (ret) {
			/*
			 * We successfully took the ref from the kqwl so set it on the
			 * thread now
			 */
			thread_set_preadopt_thread_group(th, KQWL_GET_PREADOPTED_TG(old_tg));

			thread_group_qos_t thread_group_to_expect = new_tg;
			thread_group_qos_t thread_group_to_set = old_tg;

			os_atomic_rmw_loop(tg_loc, old_tg, new_tg, relaxed, {
				if (old_tg != thread_group_to_expect) {
				        /*
				         * There was an intervening write to the kqwl_preadopt_tg,
				         * and it has a higher QoS than what we are working with
				         * here. Abandon our current adopted thread group and redo
				         * the full dance
				         */
				        thread_group_deallocate_safe(KQWL_GET_PREADOPTED_TG(thread_group_to_set));
				        os_atomic_rmw_loop_give_up(goto again);
				}

				new_tg = thread_group_to_set;
			});
		} else {
			/* Nothing valid on the kqwl, just clear what's on the thread */
			thread_set_preadopt_thread_group(th, NULL);
		}
	} else {
		/* Not even a kqwl, clear what's on the thread */
		thread_set_preadopt_thread_group(th, NULL);
	}
#endif
	thread_set_workq_pri(th, qos, priority, policy);
}

/*
 * Called by kevent with the NOTE_WL_THREAD_REQUEST knote lock held,
 * every time a servicer is being told about a new max QoS.
 */
void
workq_thread_set_max_qos(struct proc *p, workq_threadreq_t kqr)
{
	struct uu_workq_policy old_pri, new_pri;
	struct uthread *uth = current_uthread();
	struct workqueue *wq = proc_get_wqptr_fast(p);
	thread_qos_t qos = kqr->tr_kq_qos_index;

	if (uth->uu_workq_pri.qos_max == qos) {
		return;
	}

	workq_lock_spin(wq);
	old_pri = new_pri = uth->uu_workq_pri;
	new_pri.qos_max = qos;
	workq_thread_update_bucket(p, wq, uth, old_pri, new_pri, false);
	workq_unlock(wq);
}

#pragma mark idle threads accounting and handling

static inline struct uthread *
workq_oldest_killable_idle_thread(struct workqueue *wq)
{
	struct uthread *uth = TAILQ_LAST(&wq->wq_thidlelist, workq_uthread_head);

	if (uth && !uth->uu_save.uus_workq_park_data.has_stack) {
		uth = TAILQ_PREV(uth, workq_uthread_head, uu_workq_entry);
		if (uth) {
			assert(uth->uu_save.uus_workq_park_data.has_stack);
		}
	}
	return uth;
}

static inline uint64_t
workq_kill_delay_for_idle_thread(struct workqueue *wq)
{
	uint64_t delay = wq_reduce_pool_window.abstime;
	uint16_t idle = wq->wq_thidlecount;

	/*
	 * If we have less than wq_death_max_load threads, have a 5s timer.
	 *
	 * For the next wq_max_constrained_threads ones, decay linearly from
	 * from 5s to 50ms.
	 */
	if (idle <= wq_death_max_load) {
		return delay;
	}

	if (wq_max_constrained_threads > idle - wq_death_max_load) {
		delay *= (wq_max_constrained_threads - (idle - wq_death_max_load));
	}
	return delay / wq_max_constrained_threads;
}

static inline bool
workq_should_kill_idle_thread(struct workqueue *wq, struct uthread *uth,
    uint64_t now)
{
	uint64_t delay = workq_kill_delay_for_idle_thread(wq);
	return now - uth->uu_save.uus_workq_park_data.idle_stamp > delay;
}

static void
workq_death_call_schedule(struct workqueue *wq, uint64_t deadline)
{
	uint32_t wq_flags = os_atomic_load(&wq->wq_flags, relaxed);

	if (wq_flags & (WQ_EXITING | WQ_DEATH_CALL_SCHEDULED)) {
		return;
	}
	os_atomic_or(&wq->wq_flags, WQ_DEATH_CALL_SCHEDULED, relaxed);

	WQ_TRACE_WQ(TRACE_wq_death_call | DBG_FUNC_NONE, wq, 1, 0, 0);

	/*
	 * <rdar://problem/13139182> Due to how long term timers work, the leeway
	 * can't be too short, so use 500ms which is long enough that we will not
	 * wake up the CPU for killing threads, but short enough that it doesn't
	 * fall into long-term timer list shenanigans.
	 */
	thread_call_enter_delayed_with_leeway(wq->wq_death_call, NULL, deadline,
	    wq_reduce_pool_window.abstime / 10,
	    THREAD_CALL_DELAY_LEEWAY | THREAD_CALL_DELAY_USER_BACKGROUND);
}

/*
 * `decrement` is set to the number of threads that are no longer dying:
 * - because they have been resuscitated just in time (workq_pop_idle_thread)
 * - or have been killed (workq_thread_terminate).
 */
static void
workq_death_policy_evaluate(struct workqueue *wq, uint16_t decrement)
{
	struct uthread *uth;

	assert(wq->wq_thdying_count >= decrement);
	if ((wq->wq_thdying_count -= decrement) > 0) {
		return;
	}

	if (wq->wq_thidlecount <= 1) {
		return;
	}

	if ((uth = workq_oldest_killable_idle_thread(wq)) == NULL) {
		return;
	}

	uint64_t now = mach_absolute_time();
	uint64_t delay = workq_kill_delay_for_idle_thread(wq);

	if (now - uth->uu_save.uus_workq_park_data.idle_stamp > delay) {
		WQ_TRACE_WQ(TRACE_wq_thread_terminate | DBG_FUNC_START,
		    wq, wq->wq_thidlecount, 0, 0);
		wq->wq_thdying_count++;
		uth->uu_workq_flags |= UT_WORKQ_DYING;
		if ((uth->uu_workq_flags & UT_WORKQ_IDLE_CLEANUP) == 0) {
			workq_thread_wakeup(uth);
		}
		return;
	}

	workq_death_call_schedule(wq,
	    uth->uu_save.uus_workq_park_data.idle_stamp + delay);
}

void
workq_thread_terminate(struct proc *p, struct uthread *uth)
{
	struct workqueue *wq = proc_get_wqptr_fast(p);

	workq_lock_spin(wq);
	TAILQ_REMOVE(&wq->wq_thrunlist, uth, uu_workq_entry);
	if (uth->uu_workq_flags & UT_WORKQ_DYING) {
		WQ_TRACE_WQ(TRACE_wq_thread_terminate | DBG_FUNC_END,
		    wq, wq->wq_thidlecount, 0, 0);
		workq_death_policy_evaluate(wq, 1);
	}
	if (wq->wq_nthreads-- == wq_max_threads) {
		/*
		 * We got under the thread limit again, which may have prevented
		 * thread creation from happening, redrive if there are pending requests
		 */
		if (wq->wq_reqcount) {
			workq_schedule_creator(p, wq, WORKQ_THREADREQ_CAN_CREATE_THREADS);
		}
	}
	workq_unlock(wq);

	thread_deallocate(get_machthread(uth));
}

static void
workq_kill_old_threads_call(void *param0, void *param1 __unused)
{
	struct workqueue *wq = param0;

	workq_lock_spin(wq);
	WQ_TRACE_WQ(TRACE_wq_death_call | DBG_FUNC_START, wq, 0, 0, 0);
	os_atomic_andnot(&wq->wq_flags, WQ_DEATH_CALL_SCHEDULED, relaxed);
	workq_death_policy_evaluate(wq, 0);
	WQ_TRACE_WQ(TRACE_wq_death_call | DBG_FUNC_END, wq, 0, 0, 0);
	workq_unlock(wq);
}

static struct uthread *
workq_pop_idle_thread(struct workqueue *wq, uint16_t uu_flags,
    bool *needs_wakeup)
{
	struct uthread *uth;

	if ((uth = TAILQ_FIRST(&wq->wq_thidlelist))) {
		TAILQ_REMOVE(&wq->wq_thidlelist, uth, uu_workq_entry);
	} else {
		uth = TAILQ_FIRST(&wq->wq_thnewlist);
		TAILQ_REMOVE(&wq->wq_thnewlist, uth, uu_workq_entry);
	}
	TAILQ_INSERT_TAIL(&wq->wq_thrunlist, uth, uu_workq_entry);

	assert((uth->uu_workq_flags & UT_WORKQ_RUNNING) == 0);
	uth->uu_workq_flags |= UT_WORKQ_RUNNING | uu_flags;

	/* A thread is never woken up as part of the cooperative pool */
	assert((uu_flags & UT_WORKQ_COOPERATIVE) == 0);

	if ((uu_flags & UT_WORKQ_OVERCOMMIT) == 0) {
		wq->wq_constrained_threads_scheduled++;
	}
	wq->wq_threads_scheduled++;
	wq->wq_thidlecount--;

	if (__improbable(uth->uu_workq_flags & UT_WORKQ_DYING)) {
		uth->uu_workq_flags ^= UT_WORKQ_DYING;
		workq_death_policy_evaluate(wq, 1);
		*needs_wakeup = false;
	} else if (uth->uu_workq_flags & UT_WORKQ_IDLE_CLEANUP) {
		*needs_wakeup = false;
	} else {
		*needs_wakeup = true;
	}
	return uth;
}

/*
 * Called by thread_create_workq_waiting() during thread initialization, before
 * assert_wait, before the thread has been started.
 */
event_t
workq_thread_init_and_wq_lock(task_t task, thread_t th)
{
	struct uthread *uth = get_bsdthread_info(th);

	uth->uu_workq_flags = UT_WORKQ_NEW;
	uth->uu_workq_pri = WORKQ_POLICY_INIT(THREAD_QOS_LEGACY);
	uth->uu_workq_thport = MACH_PORT_NULL;
	uth->uu_workq_stackaddr = 0;
	uth->uu_workq_pthread_kill_allowed = 0;

	thread_set_tag(th, THREAD_TAG_PTHREAD | THREAD_TAG_WORKQUEUE);
	thread_reset_workq_qos(th, THREAD_QOS_LEGACY);

	workq_lock_spin(proc_get_wqptr_fast(get_bsdtask_info(task)));
	return workq_parked_wait_event(uth);
}

/**
 * Try to add a new workqueue thread.
 *
 * - called with workq lock held
 * - dropped and retaken around thread creation
 * - return with workq lock held
 */
static bool
workq_add_new_idle_thread(proc_t p, struct workqueue *wq)
{
	mach_vm_offset_t th_stackaddr;
	kern_return_t kret;
	thread_t th;

	wq->wq_nthreads++;

	workq_unlock(wq);

	vm_map_t vmap = get_task_map(p->task);

	kret = pthread_functions->workq_create_threadstack(p, vmap, &th_stackaddr);
	if (kret != KERN_SUCCESS) {
		WQ_TRACE_WQ(TRACE_wq_thread_create_failed | DBG_FUNC_NONE, wq,
		    kret, 1, 0);
		goto out;
	}

	kret = thread_create_workq_waiting(p->task, workq_unpark_continue, &th);
	if (kret != KERN_SUCCESS) {
		WQ_TRACE_WQ(TRACE_wq_thread_create_failed | DBG_FUNC_NONE, wq,
		    kret, 0, 0);
		pthread_functions->workq_destroy_threadstack(p, vmap, th_stackaddr);
		goto out;
	}

	// thread_create_workq_waiting() will return with the wq lock held
	// on success, because it calls workq_thread_init_and_wq_lock() above

	struct uthread *uth = get_bsdthread_info(th);

	wq->wq_creations++;
	wq->wq_thidlecount++;
	uth->uu_workq_stackaddr = (user_addr_t)th_stackaddr;
	TAILQ_INSERT_TAIL(&wq->wq_thnewlist, uth, uu_workq_entry);

	WQ_TRACE_WQ(TRACE_wq_thread_create | DBG_FUNC_NONE, wq, 0, 0, 0);
	return true;

out:
	workq_lock_spin(wq);
	/*
	 * Do not redrive here if we went under wq_max_threads again,
	 * it is the responsibility of the callers of this function
	 * to do so when it fails.
	 */
	wq->wq_nthreads--;
	return false;
}

static inline bool
workq_thread_is_overcommit(struct uthread *uth)
{
	return (uth->uu_workq_flags & UT_WORKQ_OVERCOMMIT) != 0;
}

static inline bool
workq_thread_is_nonovercommit(struct uthread *uth)
{
	return (uth->uu_workq_flags & (UT_WORKQ_OVERCOMMIT | UT_WORKQ_COOPERATIVE)) == 0;
}

static inline bool
workq_thread_is_cooperative(struct uthread *uth)
{
	return (uth->uu_workq_flags & UT_WORKQ_COOPERATIVE) != 0;
}

static inline void
workq_thread_set_type(struct uthread *uth, uint16_t flags)
{
	uth->uu_workq_flags &= ~(UT_WORKQ_OVERCOMMIT | UT_WORKQ_COOPERATIVE);
	uth->uu_workq_flags |= flags;
}


#define WORKQ_UNPARK_FOR_DEATH_WAS_IDLE 0x1

__attribute__((noreturn, noinline))
static void
workq_unpark_for_death_and_unlock(proc_t p, struct workqueue *wq,
    struct uthread *uth, uint32_t death_flags, uint32_t setup_flags)
{
	thread_qos_t qos = workq_pri_override(uth->uu_workq_pri);
	bool first_use = uth->uu_workq_flags & UT_WORKQ_NEW;

	if (qos > WORKQ_THREAD_QOS_CLEANUP) {
		workq_thread_reset_pri(wq, uth, NULL, /*unpark*/ true);
		qos = WORKQ_THREAD_QOS_CLEANUP;
	}

	workq_thread_reset_cpupercent(NULL, uth);

	if (death_flags & WORKQ_UNPARK_FOR_DEATH_WAS_IDLE) {
		wq->wq_thidlecount--;
		if (first_use) {
			TAILQ_REMOVE(&wq->wq_thnewlist, uth, uu_workq_entry);
		} else {
			TAILQ_REMOVE(&wq->wq_thidlelist, uth, uu_workq_entry);
		}
	}
	TAILQ_INSERT_TAIL(&wq->wq_thrunlist, uth, uu_workq_entry);

	workq_unlock(wq);

	if (setup_flags & WQ_SETUP_CLEAR_VOUCHER) {
		__assert_only kern_return_t kr;
		kr = thread_set_voucher_name(MACH_PORT_NULL);
		assert(kr == KERN_SUCCESS);
	}

	uint32_t flags = WQ_FLAG_THREAD_NEWSPI | qos | WQ_FLAG_THREAD_PRIO_QOS;
	thread_t th = get_machthread(uth);
	vm_map_t vmap = get_task_map(p->task);

	if (!first_use) {
		flags |= WQ_FLAG_THREAD_REUSE;
	}

	pthread_functions->workq_setup_thread(p, th, vmap, uth->uu_workq_stackaddr,
	    uth->uu_workq_thport, 0, WQ_SETUP_EXIT_THREAD, flags);
	__builtin_unreachable();
}

bool
workq_is_current_thread_updating_turnstile(struct workqueue *wq)
{
	return wq->wq_turnstile_updater == current_thread();
}

__attribute__((always_inline))
static inline void
workq_perform_turnstile_operation_locked(struct workqueue *wq,
    void (^operation)(void))
{
	workq_lock_held(wq);
	wq->wq_turnstile_updater = current_thread();
	operation();
	wq->wq_turnstile_updater = THREAD_NULL;
}

static void
workq_turnstile_update_inheritor(struct workqueue *wq,
    turnstile_inheritor_t inheritor,
    turnstile_update_flags_t flags)
{
	if (wq->wq_inheritor == inheritor) {
		return;
	}
	wq->wq_inheritor = inheritor;
	workq_perform_turnstile_operation_locked(wq, ^{
		turnstile_update_inheritor(wq->wq_turnstile, inheritor,
		flags | TURNSTILE_IMMEDIATE_UPDATE);
		turnstile_update_inheritor_complete(wq->wq_turnstile,
		TURNSTILE_INTERLOCK_HELD);
	});
}

static void
workq_push_idle_thread(proc_t p, struct workqueue *wq, struct uthread *uth,
    uint32_t setup_flags)
{
	uint64_t now = mach_absolute_time();
	bool is_creator = (uth == wq->wq_creator);

	if (workq_thread_is_cooperative(uth)) {
		assert(!is_creator);

		thread_qos_t thread_qos = uth->uu_workq_pri.qos_bucket;
		_wq_cooperative_queue_scheduled_count_dec(wq, thread_qos);

		/* Before we get here, we always go through
		 * workq_select_threadreq_or_park_and_unlock. If we got here, it means
		 * that we went through the logic in workq_threadreq_select which
		 * did the refresh for the next best cooperative qos while
		 * excluding the current thread - we shouldn't need to do it again.
		 */
		assert(_wq_cooperative_queue_refresh_best_req_qos(wq) == false);
	} else if (workq_thread_is_nonovercommit(uth)) {
		assert(!is_creator);

		wq->wq_constrained_threads_scheduled--;
	}

	uth->uu_workq_flags &= ~(UT_WORKQ_RUNNING | UT_WORKQ_OVERCOMMIT | UT_WORKQ_COOPERATIVE);
	TAILQ_REMOVE(&wq->wq_thrunlist, uth, uu_workq_entry);
	wq->wq_threads_scheduled--;

	if (is_creator) {
		wq->wq_creator = NULL;
		WQ_TRACE_WQ(TRACE_wq_creator_select, wq, 3, 0,
		    uth->uu_save.uus_workq_park_data.yields);
	}

	if (wq->wq_inheritor == get_machthread(uth)) {
		assert(wq->wq_creator == NULL);
		if (wq->wq_reqcount) {
			workq_turnstile_update_inheritor(wq, wq, TURNSTILE_INHERITOR_WORKQ);
		} else {
			workq_turnstile_update_inheritor(wq, TURNSTILE_INHERITOR_NULL, 0);
		}
	}

	if (uth->uu_workq_flags & UT_WORKQ_NEW) {
		assert(is_creator || (_wq_flags(wq) & WQ_EXITING));
		TAILQ_INSERT_TAIL(&wq->wq_thnewlist, uth, uu_workq_entry);
		wq->wq_thidlecount++;
		return;
	}

	if (!is_creator) {
		_wq_thactive_dec(wq, uth->uu_workq_pri.qos_bucket);
		wq->wq_thscheduled_count[_wq_bucket(uth->uu_workq_pri.qos_bucket)]--;
		uth->uu_workq_flags |= UT_WORKQ_IDLE_CLEANUP;
	}

	uth->uu_save.uus_workq_park_data.idle_stamp = now;

	struct uthread *oldest = workq_oldest_killable_idle_thread(wq);
	uint16_t cur_idle = wq->wq_thidlecount;

	if (cur_idle >= wq_max_constrained_threads ||
	    (wq->wq_thdying_count == 0 && oldest &&
	    workq_should_kill_idle_thread(wq, oldest, now))) {
		/*
		 * Immediately kill threads if we have too may of them.
		 *
		 * And swap "place" with the oldest one we'd have woken up.
		 * This is a relatively desperate situation where we really
		 * need to kill threads quickly and it's best to kill
		 * the one that's currently on core than context switching.
		 */
		if (oldest) {
			oldest->uu_save.uus_workq_park_data.idle_stamp = now;
			TAILQ_REMOVE(&wq->wq_thidlelist, oldest, uu_workq_entry);
			TAILQ_INSERT_HEAD(&wq->wq_thidlelist, oldest, uu_workq_entry);
		}

		WQ_TRACE_WQ(TRACE_wq_thread_terminate | DBG_FUNC_START,
		    wq, cur_idle, 0, 0);
		wq->wq_thdying_count++;
		uth->uu_workq_flags |= UT_WORKQ_DYING;
		uth->uu_workq_flags &= ~UT_WORKQ_IDLE_CLEANUP;
		workq_unpark_for_death_and_unlock(p, wq, uth, 0, setup_flags);
		__builtin_unreachable();
	}

	struct uthread *tail = TAILQ_LAST(&wq->wq_thidlelist, workq_uthread_head);

	cur_idle += 1;
	wq->wq_thidlecount = cur_idle;

	if (cur_idle >= wq_death_max_load && tail &&
	    tail->uu_save.uus_workq_park_data.has_stack) {
		uth->uu_save.uus_workq_park_data.has_stack = false;
		TAILQ_INSERT_TAIL(&wq->wq_thidlelist, uth, uu_workq_entry);
	} else {
		uth->uu_save.uus_workq_park_data.has_stack = true;
		TAILQ_INSERT_HEAD(&wq->wq_thidlelist, uth, uu_workq_entry);
	}

	if (!tail) {
		uint64_t delay = workq_kill_delay_for_idle_thread(wq);
		workq_death_call_schedule(wq, now + delay);
	}
}

#pragma mark thread requests

static inline bool
workq_tr_is_overcommit(workq_tr_flags_t tr_flags)
{
	return (tr_flags & WORKQ_TR_FLAG_OVERCOMMIT) != 0;
}

static inline bool
workq_tr_is_nonovercommit(workq_tr_flags_t tr_flags)
{
	return (tr_flags & (WORKQ_TR_FLAG_OVERCOMMIT | WORKQ_TR_FLAG_COOPERATIVE)) == 0;
}

static inline bool
workq_tr_is_cooperative(workq_tr_flags_t tr_flags)
{
	return (tr_flags & WORKQ_TR_FLAG_COOPERATIVE) != 0;
}

#define workq_threadreq_is_overcommit(req) workq_tr_is_overcommit((req)->tr_flags)
#define workq_threadreq_is_nonovercommit(req) workq_tr_is_nonovercommit((req)->tr_flags)
#define workq_threadreq_is_cooperative(req) workq_tr_is_cooperative((req)->tr_flags)

static inline int
workq_priority_for_req(workq_threadreq_t req)
{
	thread_qos_t qos = req->tr_qos;

	if (req->tr_flags & WORKQ_TR_FLAG_WL_OUTSIDE_QOS) {
		workq_threadreq_param_t trp = kqueue_threadreq_workloop_param(req);
		assert(trp.trp_flags & TRP_PRIORITY);
		return trp.trp_pri;
	}
	return thread_workq_pri_for_qos(qos);
}

static inline struct priority_queue_sched_max *
workq_priority_queue_for_req(struct workqueue *wq, workq_threadreq_t req)
{
	assert(!workq_tr_is_cooperative(req->tr_flags));

	if (req->tr_flags & WORKQ_TR_FLAG_WL_OUTSIDE_QOS) {
		return &wq->wq_special_queue;
	} else if (workq_tr_is_overcommit(req->tr_flags)) {
		return &wq->wq_overcommit_queue;
	} else {
		return &wq->wq_constrained_queue;
	}
}


/* Calculates the number of threads scheduled >= the input QoS */
static uint64_t
workq_num_cooperative_threads_scheduled_to_qos(struct workqueue *wq, thread_qos_t qos)
{
	workq_lock_held(wq);

	uint64_t num_cooperative_threads = 0;

	for (thread_qos_t cur_qos = WORKQ_THREAD_QOS_MAX; cur_qos >= qos; cur_qos--) {
		uint8_t bucket = _wq_bucket(cur_qos);
		num_cooperative_threads += wq->wq_cooperative_queue_scheduled_count[bucket];
	}

	return num_cooperative_threads;
}

static uint64_t
workq_num_cooperative_threads_scheduled_total(struct workqueue *wq)
{
	return workq_num_cooperative_threads_scheduled_to_qos(wq, WORKQ_THREAD_QOS_MIN);
}

#if DEBUG || DEVELOPMENT
static bool
workq_has_cooperative_thread_requests(struct workqueue *wq)
{
	for (thread_qos_t qos = WORKQ_THREAD_QOS_MAX; qos >= WORKQ_THREAD_QOS_MIN; qos--) {
		uint8_t bucket = _wq_bucket(qos);
		if (!STAILQ_EMPTY(&wq->wq_cooperative_queue[bucket])) {
			return true;
		}
	}

	return false;
}
#endif

/*
 * Determines the next QoS bucket we should service next in the cooperative
 * pool. This function will always return a QoS for cooperative pool as long as
 * there are requests to be serviced.
 *
 * Unlike the other thread pools, for the cooperative thread pool the schedule
 * counts for the various buckets in the pool affect the next best request for
 * it.
 *
 * This function is called in the following contexts:
 *
 * a) When determining the best thread QoS for cooperative bucket for the
 * creator/thread reuse
 *
 * b) Once (a) has happened and thread has bound to a thread request, figuring
 * out whether the next best request for this pool has changed so that creator
 * can be scheduled.
 *
 * Returns true if the cooperative queue's best qos changed from previous
 * value.
 */
static bool
_wq_cooperative_queue_refresh_best_req_qos(struct workqueue *wq)
{
	workq_lock_held(wq);

	thread_qos_t old_best_req_qos = wq->wq_cooperative_queue_best_req_qos;

	/* We determine the next best cooperative thread request based on the
	 * following:
	 *
	 * 1. Take the MAX of the following:
	 *		a) Highest qos with pending TRs such that number of scheduled
	 *		threads so far with >= qos is < wq_max_cooperative_threads
	 *		b) Highest qos bucket with pending TRs but no scheduled threads for that bucket
	 *
	 * 2. If the result of (1) is UN, then we pick the highest priority amongst
	 * pending thread requests in the pool.
	 *
	 */
	thread_qos_t highest_qos_with_no_scheduled = THREAD_QOS_UNSPECIFIED;
	thread_qos_t highest_qos_req_with_width = THREAD_QOS_UNSPECIFIED;

	thread_qos_t highest_qos_req = THREAD_QOS_UNSPECIFIED;

	int scheduled_count_till_qos = 0;

	for (thread_qos_t qos = WORKQ_THREAD_QOS_MAX; qos >= WORKQ_THREAD_QOS_MIN; qos--) {
		uint8_t bucket = _wq_bucket(qos);
		uint8_t scheduled_count_for_bucket = wq->wq_cooperative_queue_scheduled_count[bucket];
		scheduled_count_till_qos += scheduled_count_for_bucket;

		if (!STAILQ_EMPTY(&wq->wq_cooperative_queue[bucket])) {
			if (qos > highest_qos_req) {
				highest_qos_req = qos;
			}
			/*
			 * The pool isn't saturated for threads at and above this QoS, and
			 * this qos bucket has pending requests
			 */
			if (scheduled_count_till_qos < wq_cooperative_queue_max_size(wq)) {
				if (qos > highest_qos_req_with_width) {
					highest_qos_req_with_width = qos;
				}
			}

			/*
			 * There are no threads scheduled for this bucket but there
			 * is work pending, give it at least 1 thread
			 */
			if (scheduled_count_for_bucket == 0) {
				if (qos > highest_qos_with_no_scheduled) {
					highest_qos_with_no_scheduled = qos;
				}
			}
		}
	}

	wq->wq_cooperative_queue_best_req_qos = MAX(highest_qos_with_no_scheduled, highest_qos_req_with_width);
	if (wq->wq_cooperative_queue_best_req_qos == THREAD_QOS_UNSPECIFIED) {
		wq->wq_cooperative_queue_best_req_qos = highest_qos_req;
	}

#if DEBUG || DEVELOPMENT
	/* Assert that if we are showing up the next best req as UN, then there
	 * actually is no thread request in the cooperative pool buckets */
	if (wq->wq_cooperative_queue_best_req_qos == THREAD_QOS_UNSPECIFIED) {
		assert(!workq_has_cooperative_thread_requests(wq));
	}
#endif

	return old_best_req_qos != wq->wq_cooperative_queue_best_req_qos;
}

/*
 * Returns whether or not the input thread (or creator thread if uth is NULL)
 * should be allowed to work as part of the cooperative pool for the <input qos>
 * bucket.
 *
 * This function is called in a bunch of places:
 *		a) Quantum expires for a thread and it is part of the cooperative pool
 *		b) When trying to pick a thread request for the creator thread to
 *		represent.
 *		c) When a thread is trying to pick a thread request to actually bind to
 *		and service.
 *
 * Called with workq lock held.
 */

#define WQ_COOPERATIVE_POOL_UNSATURATED 1
#define WQ_COOPERATIVE_BUCKET_UNSERVICED 2
#define WQ_COOPERATIVE_POOL_SATURATED_UP_TO_QOS 3

static bool
workq_cooperative_allowance(struct workqueue *wq, thread_qos_t qos, struct uthread *uth,
    bool may_start_timer)
{
	workq_lock_held(wq);

	bool exclude_thread_as_scheduled = false;
	bool passed_admissions = false;
	uint8_t bucket = _wq_bucket(qos);

	if (uth && workq_thread_is_cooperative(uth)) {
		exclude_thread_as_scheduled = true;
		_wq_cooperative_queue_scheduled_count_dec(wq, uth->uu_workq_pri.qos_bucket);
	}

	/*
	 * We have not saturated the pool yet, let this thread continue
	 */
	uint64_t total_cooperative_threads;
	total_cooperative_threads = workq_num_cooperative_threads_scheduled_total(wq);
	if (total_cooperative_threads < wq_cooperative_queue_max_size(wq)) {
		passed_admissions = true;
		WQ_TRACE(TRACE_wq_cooperative_admission | DBG_FUNC_NONE,
		    total_cooperative_threads, qos, passed_admissions,
		    WQ_COOPERATIVE_POOL_UNSATURATED);
		goto out;
	}

	/*
	 * Without this thread, nothing is servicing the bucket which has pending
	 * work
	 */
	uint64_t bucket_scheduled = wq->wq_cooperative_queue_scheduled_count[bucket];
	if (bucket_scheduled == 0 &&
	    !STAILQ_EMPTY(&wq->wq_cooperative_queue[bucket])) {
		passed_admissions = true;
		WQ_TRACE(TRACE_wq_cooperative_admission | DBG_FUNC_NONE,
		    total_cooperative_threads, qos, passed_admissions,
		    WQ_COOPERATIVE_BUCKET_UNSERVICED);
		goto out;
	}

	/*
	 * If number of threads at the QoS bucket >= input QoS exceeds the max we want
	 * for the pool, deny this thread
	 */
	uint64_t aggregate_down_to_qos = workq_num_cooperative_threads_scheduled_to_qos(wq, qos);
	passed_admissions = (aggregate_down_to_qos < wq_cooperative_queue_max_size(wq));
	WQ_TRACE(TRACE_wq_cooperative_admission | DBG_FUNC_NONE, aggregate_down_to_qos,
	    qos, passed_admissions, WQ_COOPERATIVE_POOL_SATURATED_UP_TO_QOS);

	if (!passed_admissions && may_start_timer) {
		workq_schedule_delayed_thread_creation(wq, 0);
	}

out:
	if (exclude_thread_as_scheduled) {
		_wq_cooperative_queue_scheduled_count_inc(wq, uth->uu_workq_pri.qos_bucket);
	}
	return passed_admissions;
}

/*
 * returns true if the best request for the pool changed as a result of
 * enqueuing this thread request.
 */
static bool
workq_threadreq_enqueue(struct workqueue *wq, workq_threadreq_t req)
{
	assert(req->tr_state == WORKQ_TR_STATE_NEW);

	req->tr_state = WORKQ_TR_STATE_QUEUED;
	wq->wq_reqcount += req->tr_count;

	if (req->tr_qos == WORKQ_THREAD_QOS_MANAGER) {
		assert(wq->wq_event_manager_threadreq == NULL);
		assert(req->tr_flags & WORKQ_TR_FLAG_KEVENT);
		assert(req->tr_count == 1);
		wq->wq_event_manager_threadreq = req;
		return true;
	}

	if (workq_threadreq_is_cooperative(req)) {
		assert(req->tr_qos != WORKQ_THREAD_QOS_MANAGER);
		assert(req->tr_qos != WORKQ_THREAD_QOS_ABOVEUI);

		struct workq_threadreq_tailq *bucket = &wq->wq_cooperative_queue[_wq_bucket(req->tr_qos)];
		STAILQ_INSERT_TAIL(bucket, req, tr_link);

		return _wq_cooperative_queue_refresh_best_req_qos(wq);
	}

	struct priority_queue_sched_max *q = workq_priority_queue_for_req(wq, req);

	priority_queue_entry_set_sched_pri(q, &req->tr_entry,
	    workq_priority_for_req(req), false);

	if (priority_queue_insert(q, &req->tr_entry)) {
		if (workq_threadreq_is_nonovercommit(req)) {
			_wq_thactive_refresh_best_constrained_req_qos(wq);
		}
		return true;
	}
	return false;
}

/*
 * returns true if one of the following is true (so as to update creator if
 * needed):
 *
 * (a) the next highest request of the pool we dequeued the request from changed
 * (b) the next highest requests of the pool the current thread used to be a
 * part of, changed
 *
 * For overcommit, special and constrained pools, the next highest QoS for each
 * pool just a MAX of pending requests so tracking (a) is sufficient.
 *
 * But for cooperative thread pool, the next highest QoS for the pool depends on
 * schedule counts in the pool as well. So if the current thread used to be
 * cooperative in it's previous logical run ie (b), then that can also affect
 * cooperative pool's next best QoS requests.
 */
static bool
workq_threadreq_dequeue(struct workqueue *wq, workq_threadreq_t req,
    bool cooperative_sched_count_changed)
{
	wq->wq_reqcount--;

	bool next_highest_request_changed = false;

	if (--req->tr_count == 0) {
		if (req->tr_qos == WORKQ_THREAD_QOS_MANAGER) {
			assert(wq->wq_event_manager_threadreq == req);
			assert(req->tr_count == 0);
			wq->wq_event_manager_threadreq = NULL;

			/* If a cooperative thread was the one which picked up the manager
			 * thread request, we need to reevaluate the cooperative pool
			 * anyways.
			 */
			if (cooperative_sched_count_changed) {
				_wq_cooperative_queue_refresh_best_req_qos(wq);
			}
			return true;
		}

		if (workq_threadreq_is_cooperative(req)) {
			assert(req->tr_qos != WORKQ_THREAD_QOS_MANAGER);
			assert(req->tr_qos != WORKQ_THREAD_QOS_ABOVEUI);
			/* Account for the fact that BG and MT are coalesced when
			 * calculating best request for cooperative pool
			 */
			assert(_wq_bucket(req->tr_qos) == _wq_bucket(wq->wq_cooperative_queue_best_req_qos));

			struct workq_threadreq_tailq *bucket = &wq->wq_cooperative_queue[_wq_bucket(req->tr_qos)];
			__assert_only workq_threadreq_t head = STAILQ_FIRST(bucket);

			assert(head == req);
			STAILQ_REMOVE_HEAD(bucket, tr_link);

			/*
			 * If the request we're dequeueing is cooperative, then the sched
			 * counts definitely changed.
			 */
			assert(cooperative_sched_count_changed);
		}

		/*
		 * We want to do the cooperative pool refresh after dequeueing a
		 * cooperative thread request if any (to combine both effects into 1
		 * refresh operation)
		 */
		if (cooperative_sched_count_changed) {
			next_highest_request_changed = _wq_cooperative_queue_refresh_best_req_qos(wq);
		}

		if (!workq_threadreq_is_cooperative(req)) {
			/*
			 * All other types of requests are enqueued in priority queues
			 */

			if (priority_queue_remove(workq_priority_queue_for_req(wq, req),
			    &req->tr_entry)) {
				next_highest_request_changed |= true;
				if (workq_threadreq_is_nonovercommit(req)) {
					_wq_thactive_refresh_best_constrained_req_qos(wq);
				}
			}
		}
	}

	return next_highest_request_changed;
}

static void
workq_threadreq_destroy(proc_t p, workq_threadreq_t req)
{
	req->tr_state = WORKQ_TR_STATE_CANCELED;
	if (req->tr_flags & (WORKQ_TR_FLAG_WORKLOOP | WORKQ_TR_FLAG_KEVENT)) {
		kqueue_threadreq_cancel(p, req);
	} else {
		zfree(workq_zone_threadreq, req);
	}
}

#pragma mark workqueue thread creation thread calls

static inline bool
workq_thread_call_prepost(struct workqueue *wq, uint32_t sched, uint32_t pend,
    uint32_t fail_mask)
{
	uint32_t old_flags, new_flags;

	os_atomic_rmw_loop(&wq->wq_flags, old_flags, new_flags, acquire, {
		if (__improbable(old_flags & (WQ_EXITING | sched | pend | fail_mask))) {
		        os_atomic_rmw_loop_give_up(return false);
		}
		if (__improbable(old_flags & WQ_PROC_SUSPENDED)) {
		        new_flags = old_flags | pend;
		} else {
		        new_flags = old_flags | sched;
		}
	});

	return (old_flags & WQ_PROC_SUSPENDED) == 0;
}

#define WORKQ_SCHEDULE_DELAYED_THREAD_CREATION_RESTART 0x1

static bool
workq_schedule_delayed_thread_creation(struct workqueue *wq, int flags)
{
	assert(!preemption_enabled());

	if (!workq_thread_call_prepost(wq, WQ_DELAYED_CALL_SCHEDULED,
	    WQ_DELAYED_CALL_PENDED, WQ_IMMEDIATE_CALL_PENDED |
	    WQ_IMMEDIATE_CALL_SCHEDULED)) {
		return false;
	}

	uint64_t now = mach_absolute_time();

	if (flags & WORKQ_SCHEDULE_DELAYED_THREAD_CREATION_RESTART) {
		/* do not change the window */
	} else if (now - wq->wq_thread_call_last_run <= wq->wq_timer_interval) {
		wq->wq_timer_interval *= 2;
		if (wq->wq_timer_interval > wq_max_timer_interval.abstime) {
			wq->wq_timer_interval = (uint32_t)wq_max_timer_interval.abstime;
		}
	} else if (now - wq->wq_thread_call_last_run > 2 * wq->wq_timer_interval) {
		wq->wq_timer_interval /= 2;
		if (wq->wq_timer_interval < wq_stalled_window.abstime) {
			wq->wq_timer_interval = (uint32_t)wq_stalled_window.abstime;
		}
	}

	WQ_TRACE_WQ(TRACE_wq_start_add_timer, wq, wq->wq_reqcount,
	    _wq_flags(wq), wq->wq_timer_interval);

	thread_call_t call = wq->wq_delayed_call;
	uintptr_t arg = WQ_DELAYED_CALL_SCHEDULED;
	uint64_t deadline = now + wq->wq_timer_interval;
	if (thread_call_enter1_delayed(call, (void *)arg, deadline)) {
		panic("delayed_call was already enqueued");
	}
	return true;
}

static void
workq_schedule_immediate_thread_creation(struct workqueue *wq)
{
	assert(!preemption_enabled());

	if (workq_thread_call_prepost(wq, WQ_IMMEDIATE_CALL_SCHEDULED,
	    WQ_IMMEDIATE_CALL_PENDED, 0)) {
		WQ_TRACE_WQ(TRACE_wq_start_add_timer, wq, wq->wq_reqcount,
		    _wq_flags(wq), 0);

		uintptr_t arg = WQ_IMMEDIATE_CALL_SCHEDULED;
		if (thread_call_enter1(wq->wq_immediate_call, (void *)arg)) {
			panic("immediate_call was already enqueued");
		}
	}
}

void
workq_proc_suspended(struct proc *p)
{
	struct workqueue *wq = proc_get_wqptr(p);

	if (wq) {
		os_atomic_or(&wq->wq_flags, WQ_PROC_SUSPENDED, relaxed);
	}
}

void
workq_proc_resumed(struct proc *p)
{
	struct workqueue *wq = proc_get_wqptr(p);
	uint32_t wq_flags;

	if (!wq) {
		return;
	}

	wq_flags = os_atomic_andnot_orig(&wq->wq_flags, WQ_PROC_SUSPENDED |
	    WQ_DELAYED_CALL_PENDED | WQ_IMMEDIATE_CALL_PENDED, relaxed);
	if ((wq_flags & WQ_EXITING) == 0) {
		disable_preemption();
		if (wq_flags & WQ_IMMEDIATE_CALL_PENDED) {
			workq_schedule_immediate_thread_creation(wq);
		} else if (wq_flags & WQ_DELAYED_CALL_PENDED) {
			workq_schedule_delayed_thread_creation(wq,
			    WORKQ_SCHEDULE_DELAYED_THREAD_CREATION_RESTART);
		}
		enable_preemption();
	}
}

/**
 * returns whether lastblocked_tsp is within wq_stalled_window usecs of now
 */
static bool
workq_thread_is_busy(uint64_t now, _Atomic uint64_t *lastblocked_tsp)
{
	uint64_t lastblocked_ts = os_atomic_load_wide(lastblocked_tsp, relaxed);
	if (now <= lastblocked_ts) {
		/*
		 * Because the update of the timestamp when a thread blocks
		 * isn't serialized against us looking at it (i.e. we don't hold
		 * the workq lock), it's possible to have a timestamp that matches
		 * the current time or that even looks to be in the future relative
		 * to when we grabbed the current time...
		 *
		 * Just treat this as a busy thread since it must have just blocked.
		 */
		return true;
	}
	return (now - lastblocked_ts) < wq_stalled_window.abstime;
}

static void
workq_add_new_threads_call(void *_p, void *flags)
{
	proc_t p = _p;
	struct workqueue *wq = proc_get_wqptr(p);
	uint32_t my_flag = (uint32_t)(uintptr_t)flags;

	/*
	 * workq_exit() will set the workqueue to NULL before
	 * it cancels thread calls.
	 */
	if (!wq) {
		return;
	}

	assert((my_flag == WQ_DELAYED_CALL_SCHEDULED) ||
	    (my_flag == WQ_IMMEDIATE_CALL_SCHEDULED));

	WQ_TRACE_WQ(TRACE_wq_add_timer | DBG_FUNC_START, wq, _wq_flags(wq),
	    wq->wq_nthreads, wq->wq_thidlecount);

	workq_lock_spin(wq);

	wq->wq_thread_call_last_run = mach_absolute_time();
	os_atomic_andnot(&wq->wq_flags, my_flag, release);

	/* This can drop the workqueue lock, and take it again */
	workq_schedule_creator(p, wq, WORKQ_THREADREQ_CAN_CREATE_THREADS);

	workq_unlock(wq);

	WQ_TRACE_WQ(TRACE_wq_add_timer | DBG_FUNC_END, wq, 0,
	    wq->wq_nthreads, wq->wq_thidlecount);
}

#pragma mark thread state tracking

static void
workq_sched_callback(int type, thread_t thread)
{
	thread_ro_t tro = get_thread_ro(thread);
	struct uthread *uth = get_bsdthread_info(thread);
	struct workqueue *wq = proc_get_wqptr(tro->tro_proc);
	thread_qos_t req_qos, qos = uth->uu_workq_pri.qos_bucket;
	wq_thactive_t old_thactive;
	bool start_timer = false;

	if (qos == WORKQ_THREAD_QOS_MANAGER) {
		return;
	}

	switch (type) {
	case SCHED_CALL_BLOCK:
		old_thactive = _wq_thactive_dec(wq, qos);
		req_qos = WQ_THACTIVE_BEST_CONSTRAINED_REQ_QOS(old_thactive);

		/*
		 * Remember the timestamp of the last thread that blocked in this
		 * bucket, it used used by admission checks to ignore one thread
		 * being inactive if this timestamp is recent enough.
		 *
		 * If we collide with another thread trying to update the
		 * last_blocked (really unlikely since another thread would have to
		 * get scheduled and then block after we start down this path), it's
		 * not a problem.  Either timestamp is adequate, so no need to retry
		 */
		os_atomic_store_wide(&wq->wq_lastblocked_ts[_wq_bucket(qos)],
		    thread_last_run_time(thread), relaxed);

		if (req_qos == THREAD_QOS_UNSPECIFIED) {
			/*
			 * No pending request at the moment we could unblock, move on.
			 */
		} else if (qos < req_qos) {
			/*
			 * The blocking thread is at a lower QoS than the highest currently
			 * pending constrained request, nothing has to be redriven
			 */
		} else {
			uint32_t max_busycount, old_req_count;
			old_req_count = _wq_thactive_aggregate_downto_qos(wq, old_thactive,
			    req_qos, NULL, &max_busycount);
			/*
			 * If it is possible that may_start_constrained_thread had refused
			 * admission due to being over the max concurrency, we may need to
			 * spin up a new thread.
			 *
			 * We take into account the maximum number of busy threads
			 * that can affect may_start_constrained_thread as looking at the
			 * actual number may_start_constrained_thread will see is racy.
			 *
			 * IOW at NCPU = 4, for IN (req_qos = 1), if the old req count is
			 * between NCPU (4) and NCPU - 2 (2) we need to redrive.
			 */
			uint32_t conc = wq_max_parallelism[_wq_bucket(qos)];
			if (old_req_count <= conc && conc <= old_req_count + max_busycount) {
				start_timer = workq_schedule_delayed_thread_creation(wq, 0);
			}
		}
		if (__improbable(kdebug_enable)) {
			__unused uint32_t old = _wq_thactive_aggregate_downto_qos(wq,
			    old_thactive, qos, NULL, NULL);
			WQ_TRACE_WQ(TRACE_wq_thread_block | DBG_FUNC_START, wq,
			    old - 1, qos | (req_qos << 8),
			    wq->wq_reqcount << 1 | start_timer);
		}
		break;

	case SCHED_CALL_UNBLOCK:
		/*
		 * we cannot take the workqueue_lock here...
		 * an UNBLOCK can occur from a timer event which
		 * is run from an interrupt context... if the workqueue_lock
		 * is already held by this processor, we'll deadlock...
		 * the thread lock for the thread being UNBLOCKED
		 * is also held
		 */
		old_thactive = _wq_thactive_inc(wq, qos);
		if (__improbable(kdebug_enable)) {
			__unused uint32_t old = _wq_thactive_aggregate_downto_qos(wq,
			    old_thactive, qos, NULL, NULL);
			req_qos = WQ_THACTIVE_BEST_CONSTRAINED_REQ_QOS(old_thactive);
			WQ_TRACE_WQ(TRACE_wq_thread_block | DBG_FUNC_END, wq,
			    old + 1, qos | (req_qos << 8),
			    wq->wq_threads_scheduled);
		}
		break;
	}
}

#pragma mark workq lifecycle

void
workq_reference(struct workqueue *wq)
{
	os_ref_retain(&wq->wq_refcnt);
}

static void
workq_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	struct workqueue *wq;
	struct turnstile *ts;

	wq = mpsc_queue_element(e, struct workqueue, wq_destroy_link);
	assert(dq == &workq_deallocate_queue);

	turnstile_complete((uintptr_t)wq, &wq->wq_turnstile, &ts, TURNSTILE_WORKQS);
	assert(ts);
	turnstile_cleanup();
	turnstile_deallocate(ts);

	lck_ticket_destroy(&wq->wq_lock, &workq_lck_grp);
	zfree(workq_zone_workqueue, wq);
}

static void
workq_deallocate(struct workqueue *wq)
{
	if (os_ref_release_relaxed(&wq->wq_refcnt) == 0) {
		workq_deallocate_queue_invoke(&wq->wq_destroy_link,
		    &workq_deallocate_queue);
	}
}

void
workq_deallocate_safe(struct workqueue *wq)
{
	if (__improbable(os_ref_release_relaxed(&wq->wq_refcnt) == 0)) {
		mpsc_daemon_enqueue(&workq_deallocate_queue, &wq->wq_destroy_link,
		    MPSC_QUEUE_DISABLE_PREEMPTION);
	}
}

/**
 * Setup per-process state for the workqueue.
 */
int
workq_open(struct proc *p, __unused struct workq_open_args *uap,
    __unused int32_t *retval)
{
	struct workqueue *wq;
	int error = 0;

	if ((p->p_lflag & P_LREGISTER) == 0) {
		return EINVAL;
	}

	if (wq_init_constrained_limit) {
		uint32_t limit, num_cpus = ml_wait_max_cpus();

		/*
		 * set up the limit for the constrained pool
		 * this is a virtual pool in that we don't
		 * maintain it on a separate idle and run list
		 */
		limit = num_cpus * WORKQUEUE_CONSTRAINED_FACTOR;

		if (limit > wq_max_constrained_threads) {
			wq_max_constrained_threads = limit;
		}

		if (wq_max_threads > WQ_THACTIVE_BUCKET_HALF) {
			wq_max_threads = WQ_THACTIVE_BUCKET_HALF;
		}
		if (wq_max_threads > CONFIG_THREAD_MAX - 20) {
			wq_max_threads = CONFIG_THREAD_MAX - 20;
		}

		wq_death_max_load = (uint16_t)fls(num_cpus) + 1;

		for (thread_qos_t qos = WORKQ_THREAD_QOS_MIN; qos <= WORKQ_THREAD_QOS_MAX; qos++) {
			wq_max_parallelism[_wq_bucket(qos)] =
			    qos_max_parallelism(qos, QOS_PARALLELISM_COUNT_LOGICAL);
		}

		wq_max_cooperative_threads = num_cpus;

		wq_init_constrained_limit = 0;
	}

	if (proc_get_wqptr(p) == NULL) {
		if (proc_init_wqptr_or_wait(p) == FALSE) {
			assert(proc_get_wqptr(p) != NULL);
			goto out;
		}

		wq = zalloc_flags(workq_zone_workqueue, Z_WAITOK | Z_ZERO);

		os_ref_init_count(&wq->wq_refcnt, &workq_refgrp, 1);

		// Start the event manager at the priority hinted at by the policy engine
		thread_qos_t mgr_priority_hint = task_get_default_manager_qos(current_task());
		pthread_priority_t pp = _pthread_priority_make_from_thread_qos(mgr_priority_hint, 0, 0);
		wq->wq_event_manager_priority = (uint32_t)pp;
		wq->wq_timer_interval = (uint32_t)wq_stalled_window.abstime;
		wq->wq_proc = p;
		turnstile_prepare((uintptr_t)wq, &wq->wq_turnstile, turnstile_alloc(),
		    TURNSTILE_WORKQS);

		TAILQ_INIT(&wq->wq_thrunlist);
		TAILQ_INIT(&wq->wq_thnewlist);
		TAILQ_INIT(&wq->wq_thidlelist);
		priority_queue_init(&wq->wq_overcommit_queue);
		priority_queue_init(&wq->wq_constrained_queue);
		priority_queue_init(&wq->wq_special_queue);
		for (int bucket = 0; bucket < WORKQ_NUM_QOS_BUCKETS; bucket++) {
			STAILQ_INIT(&wq->wq_cooperative_queue[bucket]);
		}

		/* We are only using the delayed thread call for the constrained pool
		 * which can't have work at >= UI QoS and so we can be fine with a
		 * UI QoS thread call.
		 */
		wq->wq_delayed_call = thread_call_allocate_with_qos(
			workq_add_new_threads_call, p, THREAD_QOS_USER_INTERACTIVE,
			THREAD_CALL_OPTIONS_ONCE);
		wq->wq_immediate_call = thread_call_allocate_with_options(
			workq_add_new_threads_call, p, THREAD_CALL_PRIORITY_KERNEL,
			THREAD_CALL_OPTIONS_ONCE);
		wq->wq_death_call = thread_call_allocate_with_options(
			workq_kill_old_threads_call, wq,
			THREAD_CALL_PRIORITY_USER, THREAD_CALL_OPTIONS_ONCE);

		lck_ticket_init(&wq->wq_lock, &workq_lck_grp);

		WQ_TRACE_WQ(TRACE_wq_create | DBG_FUNC_NONE, wq,
		    VM_KERNEL_ADDRHIDE(wq), 0, 0);
		proc_set_wqptr(p, wq);
	}
out:

	return error;
}

/*
 * Routine:	workq_mark_exiting
 *
 * Function:	Mark the work queue such that new threads will not be added to the
 *		work queue after we return.
 *
 * Conditions:	Called against the current process.
 */
void
workq_mark_exiting(struct proc *p)
{
	struct workqueue *wq = proc_get_wqptr(p);
	uint32_t wq_flags;
	workq_threadreq_t mgr_req;

	if (!wq) {
		return;
	}

	WQ_TRACE_WQ(TRACE_wq_pthread_exit | DBG_FUNC_START, wq, 0, 0, 0);

	workq_lock_spin(wq);

	wq_flags = os_atomic_or_orig(&wq->wq_flags, WQ_EXITING, relaxed);
	if (__improbable(wq_flags & WQ_EXITING)) {
		panic("workq_mark_exiting called twice");
	}

	/*
	 * Opportunistically try to cancel thread calls that are likely in flight.
	 * workq_exit() will do the proper cleanup.
	 */
	if (wq_flags & WQ_IMMEDIATE_CALL_SCHEDULED) {
		thread_call_cancel(wq->wq_immediate_call);
	}
	if (wq_flags & WQ_DELAYED_CALL_SCHEDULED) {
		thread_call_cancel(wq->wq_delayed_call);
	}
	if (wq_flags & WQ_DEATH_CALL_SCHEDULED) {
		thread_call_cancel(wq->wq_death_call);
	}

	mgr_req = wq->wq_event_manager_threadreq;
	wq->wq_event_manager_threadreq = NULL;
	wq->wq_reqcount = 0; /* workq_schedule_creator must not look at queues */
	wq->wq_creator = NULL;
	workq_turnstile_update_inheritor(wq, TURNSTILE_INHERITOR_NULL, 0);

	workq_unlock(wq);

	if (mgr_req) {
		kqueue_threadreq_cancel(p, mgr_req);
	}
	/*
	 * No one touches the priority queues once WQ_EXITING is set.
	 * It is hence safe to do the tear down without holding any lock.
	 */
	priority_queue_destroy(&wq->wq_overcommit_queue,
	    struct workq_threadreq_s, tr_entry, ^(workq_threadreq_t e){
		workq_threadreq_destroy(p, e);
	});
	priority_queue_destroy(&wq->wq_constrained_queue,
	    struct workq_threadreq_s, tr_entry, ^(workq_threadreq_t e){
		workq_threadreq_destroy(p, e);
	});
	priority_queue_destroy(&wq->wq_special_queue,
	    struct workq_threadreq_s, tr_entry, ^(workq_threadreq_t e){
		workq_threadreq_destroy(p, e);
	});

	WQ_TRACE(TRACE_wq_pthread_exit | DBG_FUNC_END, 0, 0, 0, 0);
}

/*
 * Routine:	workq_exit
 *
 * Function:	clean up the work queue structure(s) now that there are no threads
 *		left running inside the work queue (except possibly current_thread).
 *
 * Conditions:	Called by the last thread in the process.
 *		Called against current process.
 */
void
workq_exit(struct proc *p)
{
	struct workqueue *wq;
	struct uthread *uth, *tmp;

	wq = os_atomic_xchg(&p->p_wqptr, NULL, relaxed);
	if (wq != NULL) {
		thread_t th = current_thread();

		WQ_TRACE_WQ(TRACE_wq_workqueue_exit | DBG_FUNC_START, wq, 0, 0, 0);

		if (thread_get_tag(th) & THREAD_TAG_WORKQUEUE) {
			/*
			 * <rdar://problem/40111515> Make sure we will no longer call the
			 * sched call, if we ever block this thread, which the cancel_wait
			 * below can do.
			 */
			thread_sched_call(th, NULL);
		}

		/*
		 * Thread calls are always scheduled by the proc itself or under the
		 * workqueue spinlock if WQ_EXITING is not yet set.
		 *
		 * Either way, when this runs, the proc has no threads left beside
		 * the one running this very code, so we know no thread call can be
		 * dispatched anymore.
		 */
		thread_call_cancel_wait(wq->wq_delayed_call);
		thread_call_cancel_wait(wq->wq_immediate_call);
		thread_call_cancel_wait(wq->wq_death_call);
		thread_call_free(wq->wq_delayed_call);
		thread_call_free(wq->wq_immediate_call);
		thread_call_free(wq->wq_death_call);

		/*
		 * Clean up workqueue data structures for threads that exited and
		 * didn't get a chance to clean up after themselves.
		 *
		 * idle/new threads should have been interrupted and died on their own
		 */
		TAILQ_FOREACH_SAFE(uth, &wq->wq_thrunlist, uu_workq_entry, tmp) {
			thread_t mth = get_machthread(uth);
			thread_sched_call(mth, NULL);
			thread_deallocate(mth);
		}
		assert(TAILQ_EMPTY(&wq->wq_thnewlist));
		assert(TAILQ_EMPTY(&wq->wq_thidlelist));

		WQ_TRACE_WQ(TRACE_wq_destroy | DBG_FUNC_END, wq,
		    VM_KERNEL_ADDRHIDE(wq), 0, 0);

		workq_deallocate(wq);

		WQ_TRACE(TRACE_wq_workqueue_exit | DBG_FUNC_END, 0, 0, 0, 0);
	}
}


#pragma mark bsd thread control

bool
bsdthread_part_of_cooperative_workqueue(struct uthread *uth)
{
	return (workq_thread_is_cooperative(uth) || workq_thread_is_nonovercommit(uth)) &&
	       (uth->uu_workq_pri.qos_bucket != WORKQ_THREAD_QOS_MANAGER);
}

static bool
_pthread_priority_to_policy(pthread_priority_t priority,
    thread_qos_policy_data_t *data)
{
	data->qos_tier = _pthread_priority_thread_qos(priority);
	data->tier_importance = _pthread_priority_relpri(priority);
	if (data->qos_tier == THREAD_QOS_UNSPECIFIED || data->tier_importance > 0 ||
	    data->tier_importance < THREAD_QOS_MIN_TIER_IMPORTANCE) {
		return false;
	}
	return true;
}

static int
bsdthread_set_self(proc_t p, thread_t th, pthread_priority_t priority,
    mach_port_name_t voucher, enum workq_set_self_flags flags)
{
	struct uthread *uth = get_bsdthread_info(th);
	struct workqueue *wq = proc_get_wqptr(p);

	kern_return_t kr;
	int unbind_rv = 0, qos_rv = 0, voucher_rv = 0, fixedpri_rv = 0;
	bool is_wq_thread = (thread_get_tag(th) & THREAD_TAG_WORKQUEUE);

	if (flags & WORKQ_SET_SELF_WQ_KEVENT_UNBIND) {
		if (!is_wq_thread) {
			unbind_rv = EINVAL;
			goto qos;
		}

		if (uth->uu_workq_pri.qos_bucket == WORKQ_THREAD_QOS_MANAGER) {
			unbind_rv = EINVAL;
			goto qos;
		}

		workq_threadreq_t kqr = uth->uu_kqr_bound;
		if (kqr == NULL) {
			unbind_rv = EALREADY;
			goto qos;
		}

		if (kqr->tr_flags & WORKQ_TR_FLAG_WORKLOOP) {
			unbind_rv = EINVAL;
			goto qos;
		}

		kqueue_threadreq_unbind(p, kqr);
	}

qos:
	if (flags & WORKQ_SET_SELF_QOS_FLAG) {
		thread_qos_policy_data_t new_policy;

		if (!_pthread_priority_to_policy(priority, &new_policy)) {
			qos_rv = EINVAL;
			goto voucher;
		}

		if (!is_wq_thread) {
			/*
			 * Threads opted out of QoS can't change QoS
			 */
			if (!thread_has_qos_policy(th)) {
				qos_rv = EPERM;
				goto voucher;
			}
		} else if (uth->uu_workq_pri.qos_bucket == WORKQ_THREAD_QOS_MANAGER ||
		    uth->uu_workq_pri.qos_bucket == WORKQ_THREAD_QOS_ABOVEUI) {
			/*
			 * Workqueue manager threads or threads above UI can't change QoS
			 */
			qos_rv = EINVAL;
			goto voucher;
		} else {
			/*
			 * For workqueue threads, possibly adjust buckets and redrive thread
			 * requests.
			 *
			 * Transitions allowed:
			 *
			 * overcommit --> non-overcommit
			 * overcommit --> overcommit
			 * non-overcommit --> non-overcommit
			 * non-overcommit --> overcommit (to be deprecated later)
			 * cooperative --> cooperative
			 *
			 * All other transitions aren't allowed so reject them.
			 */
			if (workq_thread_is_overcommit(uth) && _pthread_priority_is_cooperative(priority)) {
				qos_rv = EINVAL;
				goto voucher;
			} else if (workq_thread_is_cooperative(uth) && !_pthread_priority_is_cooperative(priority)) {
				qos_rv = EINVAL;
				goto voucher;
			} else if (workq_thread_is_nonovercommit(uth) && _pthread_priority_is_cooperative(priority)) {
				qos_rv = EINVAL;
				goto voucher;
			}

			struct uu_workq_policy old_pri, new_pri;
			bool force_run = false;

			workq_lock_spin(wq);

			old_pri = new_pri = uth->uu_workq_pri;
			new_pri.qos_req = (thread_qos_t)new_policy.qos_tier;

			/* Adjust schedule counts for various types of transitions */

			/* overcommit -> non-overcommit */
			if (workq_thread_is_overcommit(uth) && _pthread_priority_is_nonovercommit(priority)) {
				workq_thread_set_type(uth, 0);
				wq->wq_constrained_threads_scheduled++;

				/* non-overcommit -> overcommit */
			} else if (workq_thread_is_nonovercommit(uth) && _pthread_priority_is_overcommit(priority)) {
				workq_thread_set_type(uth, UT_WORKQ_OVERCOMMIT);
				force_run = (wq->wq_constrained_threads_scheduled-- == wq_max_constrained_threads);

				/* cooperative -> cooperative */
			} else if (workq_thread_is_cooperative(uth)) {
				_wq_cooperative_queue_scheduled_count_dec(wq, old_pri.qos_bucket);
				_wq_cooperative_queue_scheduled_count_inc(wq, workq_pri_bucket(new_pri));

				/* We're changing schedule counts within cooperative pool, we
				 * need to refresh best cooperative QoS logic again */
				force_run = _wq_cooperative_queue_refresh_best_req_qos(wq);
			}

			/* This will also call schedule_creator if needed */
			workq_thread_update_bucket(p, wq, uth, old_pri, new_pri, force_run);
			workq_unlock(wq);

			if (workq_thread_is_overcommit(uth)) {
				thread_disarm_workqueue_quantum(th);
			} else {
				/* If the thread changed QoS buckets, the quantum duration
				 * may have changed too */
				thread_arm_workqueue_quantum(th);
			}
		}

		kr = thread_policy_set_internal(th, THREAD_QOS_POLICY,
		    (thread_policy_t)&new_policy, THREAD_QOS_POLICY_COUNT);
		if (kr != KERN_SUCCESS) {
			qos_rv = EINVAL;
		}
	}

voucher:
	if (flags & WORKQ_SET_SELF_VOUCHER_FLAG) {
		kr = thread_set_voucher_name(voucher);
		if (kr != KERN_SUCCESS) {
			voucher_rv = ENOENT;
			goto fixedpri;
		}
	}

fixedpri:
	if (qos_rv) {
		goto done;
	}
	if (flags & WORKQ_SET_SELF_FIXEDPRIORITY_FLAG) {
		thread_extended_policy_data_t extpol = {.timeshare = 0};

		if (is_wq_thread) {
			/* Not allowed on workqueue threads */
			fixedpri_rv = ENOTSUP;
			goto done;
		}

		kr = thread_policy_set_internal(th, THREAD_EXTENDED_POLICY,
		    (thread_policy_t)&extpol, THREAD_EXTENDED_POLICY_COUNT);
		if (kr != KERN_SUCCESS) {
			fixedpri_rv = EINVAL;
			goto done;
		}
	} else if (flags & WORKQ_SET_SELF_TIMESHARE_FLAG) {
		thread_extended_policy_data_t extpol = {.timeshare = 1};

		if (is_wq_thread) {
			/* Not allowed on workqueue threads */
			fixedpri_rv = ENOTSUP;
			goto done;
		}

		kr = thread_policy_set_internal(th, THREAD_EXTENDED_POLICY,
		    (thread_policy_t)&extpol, THREAD_EXTENDED_POLICY_COUNT);
		if (kr != KERN_SUCCESS) {
			fixedpri_rv = EINVAL;
			goto done;
		}
	}

done:
	if (qos_rv && voucher_rv) {
		/* Both failed, give that a unique error. */
		return EBADMSG;
	}

	if (unbind_rv) {
		return unbind_rv;
	}

	if (qos_rv) {
		return qos_rv;
	}

	if (voucher_rv) {
		return voucher_rv;
	}

	if (fixedpri_rv) {
		return fixedpri_rv;
	}


	return 0;
}

static int
bsdthread_add_explicit_override(proc_t p, mach_port_name_t kport,
    pthread_priority_t pp, user_addr_t resource)
{
	thread_qos_t qos = _pthread_priority_thread_qos(pp);
	if (qos == THREAD_QOS_UNSPECIFIED) {
		return EINVAL;
	}

	thread_t th = port_name_to_thread(kport,
	    PORT_INTRANS_THREAD_IN_CURRENT_TASK);
	if (th == THREAD_NULL) {
		return ESRCH;
	}

	int rv = proc_thread_qos_add_override(p->task, th, 0, qos, TRUE,
	    resource, THREAD_QOS_OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE);

	thread_deallocate(th);
	return rv;
}

static int
bsdthread_remove_explicit_override(proc_t p, mach_port_name_t kport,
    user_addr_t resource)
{
	thread_t th = port_name_to_thread(kport,
	    PORT_INTRANS_THREAD_IN_CURRENT_TASK);
	if (th == THREAD_NULL) {
		return ESRCH;
	}

	int rv = proc_thread_qos_remove_override(p->task, th, 0, resource,
	    THREAD_QOS_OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE);

	thread_deallocate(th);
	return rv;
}

static int
workq_thread_add_dispatch_override(proc_t p, mach_port_name_t kport,
    pthread_priority_t pp, user_addr_t ulock_addr)
{
	struct uu_workq_policy old_pri, new_pri;
	struct workqueue *wq = proc_get_wqptr(p);

	thread_qos_t qos_override = _pthread_priority_thread_qos(pp);
	if (qos_override == THREAD_QOS_UNSPECIFIED) {
		return EINVAL;
	}

	thread_t thread = port_name_to_thread(kport,
	    PORT_INTRANS_THREAD_IN_CURRENT_TASK);
	if (thread == THREAD_NULL) {
		return ESRCH;
	}

	struct uthread *uth = get_bsdthread_info(thread);
	if ((thread_get_tag(thread) & THREAD_TAG_WORKQUEUE) == 0) {
		thread_deallocate(thread);
		return EPERM;
	}

	WQ_TRACE_WQ(TRACE_wq_override_dispatch | DBG_FUNC_NONE,
	    wq, thread_tid(thread), 1, pp);

	thread_mtx_lock(thread);

	if (ulock_addr) {
		uint32_t val;
		int rc;
		/*
		 * Workaround lack of explicit support for 'no-fault copyin'
		 * <rdar://problem/24999882>, as disabling preemption prevents paging in
		 */
		disable_preemption();
		rc = copyin_atomic32(ulock_addr, &val);
		enable_preemption();
		if (rc == 0 && ulock_owner_value_to_port_name(val) != kport) {
			goto out;
		}
	}

	workq_lock_spin(wq);

	old_pri = uth->uu_workq_pri;
	if (old_pri.qos_override >= qos_override) {
		/* Nothing to do */
	} else if (thread == current_thread()) {
		new_pri = old_pri;
		new_pri.qos_override = qos_override;
		workq_thread_update_bucket(p, wq, uth, old_pri, new_pri, false);
	} else {
		uth->uu_workq_pri.qos_override = qos_override;
		if (qos_override > workq_pri_override(old_pri)) {
			thread_set_workq_override(thread, qos_override);
		}
	}

	workq_unlock(wq);

out:
	thread_mtx_unlock(thread);
	thread_deallocate(thread);
	return 0;
}

static int
workq_thread_reset_dispatch_override(proc_t p, thread_t thread)
{
	struct uu_workq_policy old_pri, new_pri;
	struct workqueue *wq = proc_get_wqptr(p);
	struct uthread *uth = get_bsdthread_info(thread);

	if ((thread_get_tag(thread) & THREAD_TAG_WORKQUEUE) == 0) {
		return EPERM;
	}

	WQ_TRACE_WQ(TRACE_wq_override_reset | DBG_FUNC_NONE, wq, 0, 0, 0);

	workq_lock_spin(wq);
	old_pri = new_pri = uth->uu_workq_pri;
	new_pri.qos_override = THREAD_QOS_UNSPECIFIED;
	workq_thread_update_bucket(p, wq, uth, old_pri, new_pri, false);
	workq_unlock(wq);
	return 0;
}

static int
workq_thread_allow_kill(__unused proc_t p, thread_t thread, bool enable)
{
	if (!(thread_get_tag(thread) & THREAD_TAG_WORKQUEUE)) {
		// If the thread isn't a workqueue thread, don't set the
		// kill_allowed bit; however, we still need to return 0
		// instead of an error code since this code is executed
		// on the abort path which needs to not depend on the
		// pthread_t (returning an error depends on pthread_t via
		// cerror_nocancel)
		return 0;
	}
	struct uthread *uth = get_bsdthread_info(thread);
	uth->uu_workq_pthread_kill_allowed = enable;
	return 0;
}

static int
bsdthread_get_max_parallelism(thread_qos_t qos, unsigned long flags,
    int *retval)
{
	static_assert(QOS_PARALLELISM_COUNT_LOGICAL ==
	    _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL, "logical");
	static_assert(QOS_PARALLELISM_REALTIME ==
	    _PTHREAD_QOS_PARALLELISM_REALTIME, "realtime");
	static_assert(QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE ==
	    _PTHREAD_QOS_PARALLELISM_CLUSTER_SHARED_RSRC, "cluster shared resource");

	if (flags & ~(QOS_PARALLELISM_REALTIME | QOS_PARALLELISM_COUNT_LOGICAL | QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE)) {
		return EINVAL;
	}

	/* No units are present */
	if (flags & QOS_PARALLELISM_CLUSTER_SHARED_RESOURCE) {
		return ENOTSUP;
	}

	if (flags & QOS_PARALLELISM_REALTIME) {
		if (qos) {
			return EINVAL;
		}
	} else if (qos == THREAD_QOS_UNSPECIFIED || qos >= THREAD_QOS_LAST) {
		return EINVAL;
	}

	*retval = qos_max_parallelism(qos, flags);
	return 0;
}

static int
bsdthread_dispatch_apply_attr(__unused struct proc *p, thread_t thread,
    unsigned long flags, uint64_t value1, __unused uint64_t value2)
{
	uint32_t apply_worker_index;
	kern_return_t kr;

	switch (flags) {
	case _PTHREAD_DISPATCH_APPLY_ATTR_CLUSTER_SHARED_RSRC_SET:
		apply_worker_index = (uint32_t)value1;
		kr = thread_shared_rsrc_policy_set(thread, apply_worker_index, CLUSTER_SHARED_RSRC_TYPE_RR, SHARED_RSRC_POLICY_AGENT_DISPATCH);
		/*
		 * KERN_INVALID_POLICY indicates that the thread was trying to bind to a
		 * cluster which it was not eligible to execute on.
		 */
		return (kr == KERN_SUCCESS) ? 0 : ((kr == KERN_INVALID_POLICY) ? ENOTSUP : EINVAL);
	case _PTHREAD_DISPATCH_APPLY_ATTR_CLUSTER_SHARED_RSRC_CLEAR:
		kr = thread_shared_rsrc_policy_clear(thread, CLUSTER_SHARED_RSRC_TYPE_RR, SHARED_RSRC_POLICY_AGENT_DISPATCH);
		return (kr == KERN_SUCCESS) ? 0 : EINVAL;
	default:
		return EINVAL;
	}
}

#define ENSURE_UNUSED(arg) \
	        ({ if ((arg) != 0) { return EINVAL; } })

int
bsdthread_ctl(struct proc *p, struct bsdthread_ctl_args *uap, int *retval)
{
	switch (uap->cmd) {
	case BSDTHREAD_CTL_QOS_OVERRIDE_START:
		return bsdthread_add_explicit_override(p, (mach_port_name_t)uap->arg1,
		           (pthread_priority_t)uap->arg2, uap->arg3);
	case BSDTHREAD_CTL_QOS_OVERRIDE_END:
		ENSURE_UNUSED(uap->arg3);
		return bsdthread_remove_explicit_override(p, (mach_port_name_t)uap->arg1,
		           (user_addr_t)uap->arg2);

	case BSDTHREAD_CTL_QOS_OVERRIDE_DISPATCH:
		return workq_thread_add_dispatch_override(p, (mach_port_name_t)uap->arg1,
		           (pthread_priority_t)uap->arg2, uap->arg3);
	case BSDTHREAD_CTL_QOS_OVERRIDE_RESET:
		return workq_thread_reset_dispatch_override(p, current_thread());

	case BSDTHREAD_CTL_SET_SELF:
		return bsdthread_set_self(p, current_thread(),
		           (pthread_priority_t)uap->arg1, (mach_port_name_t)uap->arg2,
		           (enum workq_set_self_flags)uap->arg3);

	case BSDTHREAD_CTL_QOS_MAX_PARALLELISM:
		ENSURE_UNUSED(uap->arg3);
		return bsdthread_get_max_parallelism((thread_qos_t)uap->arg1,
		           (unsigned long)uap->arg2, retval);
	case BSDTHREAD_CTL_WORKQ_ALLOW_KILL:
		ENSURE_UNUSED(uap->arg2);
		ENSURE_UNUSED(uap->arg3);
		return workq_thread_allow_kill(p, current_thread(), (bool)uap->arg1);
	case BSDTHREAD_CTL_DISPATCH_APPLY_ATTR:
		return bsdthread_dispatch_apply_attr(p, current_thread(),
		           (unsigned long)uap->arg1, (uint64_t)uap->arg2,
		           (uint64_t)uap->arg3);
	case BSDTHREAD_CTL_SET_QOS:
	case BSDTHREAD_CTL_QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD:
	case BSDTHREAD_CTL_QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET:
		/* no longer supported */
		return ENOTSUP;

	default:
		return EINVAL;
	}
}

#pragma mark workqueue thread manipulation

static void __dead2
workq_unpark_select_threadreq_or_park_and_unlock(proc_t p, struct workqueue *wq,
    struct uthread *uth, uint32_t setup_flags);

static void __dead2
workq_select_threadreq_or_park_and_unlock(proc_t p, struct workqueue *wq,
    struct uthread *uth, uint32_t setup_flags);

static void workq_setup_and_run(proc_t p, struct uthread *uth, int flags) __dead2;

#if KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD
static inline uint64_t
workq_trace_req_id(workq_threadreq_t req)
{
	struct kqworkloop *kqwl;
	if (req->tr_flags & WORKQ_TR_FLAG_WORKLOOP) {
		kqwl = __container_of(req, struct kqworkloop, kqwl_request);
		return kqwl->kqwl_dynamicid;
	}

	return VM_KERNEL_ADDRHIDE(req);
}
#endif

/**
 * Entry point for libdispatch to ask for threads
 */
static int
workq_reqthreads(struct proc *p, uint32_t reqcount, pthread_priority_t pp, bool cooperative)
{
	thread_qos_t qos = _pthread_priority_thread_qos(pp);
	struct workqueue *wq = proc_get_wqptr(p);
	uint32_t unpaced, upcall_flags = WQ_FLAG_THREAD_NEWSPI;
	int ret = 0;

	if (wq == NULL || reqcount <= 0 || reqcount > UINT16_MAX ||
	    qos == THREAD_QOS_UNSPECIFIED) {
		ret = EINVAL;
		goto exit;
	}

	WQ_TRACE_WQ(TRACE_wq_wqops_reqthreads | DBG_FUNC_NONE,
	    wq, reqcount, pp, cooperative);

	workq_threadreq_t req = zalloc(workq_zone_threadreq);
	priority_queue_entry_init(&req->tr_entry);
	req->tr_state = WORKQ_TR_STATE_NEW;
	req->tr_qos   = qos;
	workq_tr_flags_t tr_flags = 0;

	if (pp & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
		tr_flags |= WORKQ_TR_FLAG_OVERCOMMIT;
		upcall_flags |= WQ_FLAG_THREAD_OVERCOMMIT;
	}

	if (cooperative) {
		tr_flags |= WORKQ_TR_FLAG_COOPERATIVE;
		upcall_flags |= WQ_FLAG_THREAD_COOPERATIVE;

		if (reqcount > 1) {
			ret = ENOTSUP;
			goto free_and_exit;
		}
	}

	/* A thread request cannot be both overcommit and cooperative */
	if (workq_tr_is_cooperative(tr_flags) &&
	    workq_tr_is_overcommit(tr_flags)) {
		ret = EINVAL;
		goto free_and_exit;
	}
	req->tr_flags = tr_flags;

	WQ_TRACE_WQ(TRACE_wq_thread_request_initiate | DBG_FUNC_NONE,
	    wq, workq_trace_req_id(req), req->tr_qos, reqcount);

	workq_lock_spin(wq);
	do {
		if (_wq_exiting(wq)) {
			goto unlock_and_exit;
		}

		/*
		 * When userspace is asking for parallelism, wakeup up to (reqcount - 1)
		 * threads without pacing, to inform the scheduler of that workload.
		 *
		 * The last requests, or the ones that failed the admission checks are
		 * enqueued and go through the regular creator codepath.
		 *
		 * If there aren't enough threads, add one, but re-evaluate everything
		 * as conditions may now have changed.
		 */
		unpaced = reqcount - 1;

		if (reqcount > 1) {
			/* We don't handle asking for parallelism on the cooperative
			 * workqueue just yet */
			assert(!workq_threadreq_is_cooperative(req));

			if (workq_threadreq_is_nonovercommit(req)) {
				unpaced = workq_constrained_allowance(wq, qos, NULL, false);
				if (unpaced >= reqcount - 1) {
					unpaced = reqcount - 1;
				}
			}
		}

		/*
		 * This path does not currently handle custom workloop parameters
		 * when creating threads for parallelism.
		 */
		assert(!(req->tr_flags & WORKQ_TR_FLAG_WL_PARAMS));

		/*
		 * This is a trimmed down version of workq_threadreq_bind_and_unlock()
		 */
		while (unpaced > 0 && wq->wq_thidlecount) {
			struct uthread *uth;
			bool needs_wakeup;
			uint8_t uu_flags = UT_WORKQ_EARLY_BOUND;

			if (workq_tr_is_overcommit(req->tr_flags)) {
				uu_flags |= UT_WORKQ_OVERCOMMIT;
			}

			uth = workq_pop_idle_thread(wq, uu_flags, &needs_wakeup);

			_wq_thactive_inc(wq, qos);
			wq->wq_thscheduled_count[_wq_bucket(qos)]++;
			workq_thread_reset_pri(wq, uth, req, /*unpark*/ true);
			wq->wq_fulfilled++;

			uth->uu_save.uus_workq_park_data.upcall_flags = upcall_flags;
			uth->uu_save.uus_workq_park_data.thread_request = req;
			if (needs_wakeup) {
				workq_thread_wakeup(uth);
			}
			unpaced--;
			reqcount--;
		}
	} while (unpaced && wq->wq_nthreads < wq_max_threads &&
	    workq_add_new_idle_thread(p, wq));

	if (_wq_exiting(wq)) {
		goto unlock_and_exit;
	}

	req->tr_count = (uint16_t)reqcount;
	if (workq_threadreq_enqueue(wq, req)) {
		/* This can drop the workqueue lock, and take it again */
		workq_schedule_creator(p, wq, WORKQ_THREADREQ_CAN_CREATE_THREADS);
	}
	workq_unlock(wq);
	return 0;

unlock_and_exit:
	workq_unlock(wq);
free_and_exit:
	zfree(workq_zone_threadreq, req);
exit:
	return ret;
}

bool
workq_kern_threadreq_initiate(struct proc *p, workq_threadreq_t req,
    struct turnstile *workloop_ts, thread_qos_t qos,
    workq_kern_threadreq_flags_t flags)
{
	struct workqueue *wq = proc_get_wqptr_fast(p);
	struct uthread *uth = NULL;

	assert(req->tr_flags & (WORKQ_TR_FLAG_WORKLOOP | WORKQ_TR_FLAG_KEVENT));

	if (req->tr_flags & WORKQ_TR_FLAG_WL_OUTSIDE_QOS) {
		workq_threadreq_param_t trp = kqueue_threadreq_workloop_param(req);
		qos = thread_workq_qos_for_pri(trp.trp_pri);
		if (qos == THREAD_QOS_UNSPECIFIED) {
			qos = WORKQ_THREAD_QOS_ABOVEUI;
		}
	}

	assert(req->tr_state == WORKQ_TR_STATE_IDLE);
	priority_queue_entry_init(&req->tr_entry);
	req->tr_count = 1;
	req->tr_state = WORKQ_TR_STATE_NEW;
	req->tr_qos   = qos;

	WQ_TRACE_WQ(TRACE_wq_thread_request_initiate | DBG_FUNC_NONE, wq,
	    workq_trace_req_id(req), qos, 1);

	if (flags & WORKQ_THREADREQ_ATTEMPT_REBIND) {
		/*
		 * we're called back synchronously from the context of
		 * kqueue_threadreq_unbind from within workq_thread_return()
		 * we can try to match up this thread with this request !
		 */
		uth = current_uthread();
		assert(uth->uu_kqr_bound == NULL);
	}

	workq_lock_spin(wq);
	if (_wq_exiting(wq)) {
		req->tr_state = WORKQ_TR_STATE_IDLE;
		workq_unlock(wq);
		return false;
	}

	if (uth && workq_threadreq_admissible(wq, uth, req)) {
		/* This is the case of the rebind - we were about to park and unbind
		 * when more events came so keep the binding.
		 */
		assert(uth != wq->wq_creator);

		if (uth->uu_workq_pri.qos_bucket != req->tr_qos) {
			_wq_thactive_move(wq, uth->uu_workq_pri.qos_bucket, req->tr_qos);
			workq_thread_reset_pri(wq, uth, req, /*unpark*/ false);
		}
		/*
		 * We're called from workq_kern_threadreq_initiate()
		 * due to an unbind, with the kq req held.
		 */
		WQ_TRACE_WQ(TRACE_wq_thread_logical_run | DBG_FUNC_START, wq,
		    workq_trace_req_id(req), req->tr_flags, 0);
		wq->wq_fulfilled++;

		kqueue_threadreq_bind(p, req, get_machthread(uth), 0);
	} else {
		if (workloop_ts) {
			workq_perform_turnstile_operation_locked(wq, ^{
				turnstile_update_inheritor(workloop_ts, wq->wq_turnstile,
				TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_TURNSTILE);
				turnstile_update_inheritor_complete(workloop_ts,
				TURNSTILE_INTERLOCK_HELD);
			});
		}

		bool reevaluate_creator_thread_group = false;
#if CONFIG_PREADOPT_TG
		reevaluate_creator_thread_group = (flags & WORKQ_THREADREQ_REEVALUATE_PREADOPT_TG);
#endif
		/* We enqueued the highest priority item or we may need to reevaluate if
		 * the creator needs a thread group pre-adoption */
		if (workq_threadreq_enqueue(wq, req) || reevaluate_creator_thread_group) {
			workq_schedule_creator(p, wq, flags);
		}
	}

	workq_unlock(wq);

	return true;
}

void
workq_kern_threadreq_modify(struct proc *p, workq_threadreq_t req,
    thread_qos_t qos, workq_kern_threadreq_flags_t flags)
{
	struct workqueue *wq = proc_get_wqptr_fast(p);
	bool make_overcommit = false;

	if (req->tr_flags & WORKQ_TR_FLAG_WL_OUTSIDE_QOS) {
		/* Requests outside-of-QoS shouldn't accept modify operations */
		return;
	}

	workq_lock_spin(wq);

	assert(req->tr_qos != WORKQ_THREAD_QOS_MANAGER);
	assert(req->tr_flags & (WORKQ_TR_FLAG_KEVENT | WORKQ_TR_FLAG_WORKLOOP));

	if (req->tr_state == WORKQ_TR_STATE_BINDING) {
		kqueue_threadreq_bind(p, req, req->tr_thread, 0);
		workq_unlock(wq);
		return;
	}

	if (flags & WORKQ_THREADREQ_MAKE_OVERCOMMIT) {
		/* TODO (rokhinip): We come into this code path for kqwl thread
		 * requests. kqwl requests cannot be cooperative.
		 */
		assert(!workq_threadreq_is_cooperative(req));

		make_overcommit = workq_threadreq_is_nonovercommit(req);
	}

	if (_wq_exiting(wq) || (req->tr_qos == qos && !make_overcommit)) {
		workq_unlock(wq);
		return;
	}

	assert(req->tr_count == 1);
	if (req->tr_state != WORKQ_TR_STATE_QUEUED) {
		panic("Invalid thread request (%p) state %d", req, req->tr_state);
	}

	WQ_TRACE_WQ(TRACE_wq_thread_request_modify | DBG_FUNC_NONE, wq,
	    workq_trace_req_id(req), qos, 0);

	struct priority_queue_sched_max *pq = workq_priority_queue_for_req(wq, req);
	workq_threadreq_t req_max;

	/*
	 * Stage 1: Dequeue the request from its priority queue.
	 *
	 * If we dequeue the root item of the constrained priority queue,
	 * maintain the best constrained request qos invariant.
	 */
	if (priority_queue_remove(pq, &req->tr_entry)) {
		if (workq_threadreq_is_nonovercommit(req)) {
			_wq_thactive_refresh_best_constrained_req_qos(wq);
		}
	}

	/*
	 * Stage 2: Apply changes to the thread request
	 *
	 * If the item will not become the root of the priority queue it belongs to,
	 * then we need to wait in line, just enqueue and return quickly.
	 */
	if (__improbable(make_overcommit)) {
		req->tr_flags ^= WORKQ_TR_FLAG_OVERCOMMIT;
		pq = workq_priority_queue_for_req(wq, req);
	}
	req->tr_qos = qos;

	req_max = priority_queue_max(pq, struct workq_threadreq_s, tr_entry);
	if (req_max && req_max->tr_qos >= qos) {
		priority_queue_entry_set_sched_pri(pq, &req->tr_entry,
		    workq_priority_for_req(req), false);
		priority_queue_insert(pq, &req->tr_entry);
		workq_unlock(wq);
		return;
	}

	/*
	 * Stage 3: Reevaluate whether we should run the thread request.
	 *
	 * Pretend the thread request is new again:
	 * - adjust wq_reqcount to not count it anymore.
	 * - make its state WORKQ_TR_STATE_NEW (so that workq_threadreq_bind_and_unlock
	 *   properly attempts a synchronous bind)
	 */
	wq->wq_reqcount--;
	req->tr_state = WORKQ_TR_STATE_NEW;

	/* We enqueued the highest priority item or we may need to reevaluate if
	 * the creator needs a thread group pre-adoption if the request got a new TG */
	bool reevaluate_creator_tg = false;

#if CONFIG_PREADOPT_TG
	reevaluate_creator_tg = (flags & WORKQ_THREADREQ_REEVALUATE_PREADOPT_TG);
#endif

	if (workq_threadreq_enqueue(wq, req) || reevaluate_creator_tg) {
		workq_schedule_creator(p, wq, flags);
	}
	workq_unlock(wq);
}

void
workq_kern_threadreq_lock(struct proc *p)
{
	workq_lock_spin(proc_get_wqptr_fast(p));
}

void
workq_kern_threadreq_unlock(struct proc *p)
{
	workq_unlock(proc_get_wqptr_fast(p));
}

void
workq_kern_threadreq_update_inheritor(struct proc *p, workq_threadreq_t req,
    thread_t owner, struct turnstile *wl_ts,
    turnstile_update_flags_t flags)
{
	struct workqueue *wq = proc_get_wqptr_fast(p);
	turnstile_inheritor_t inheritor;

	assert(req->tr_qos != WORKQ_THREAD_QOS_MANAGER);
	assert(req->tr_flags & WORKQ_TR_FLAG_WORKLOOP);
	workq_lock_held(wq);

	if (req->tr_state == WORKQ_TR_STATE_BINDING) {
		kqueue_threadreq_bind(p, req, req->tr_thread,
		    KQUEUE_THREADERQ_BIND_NO_INHERITOR_UPDATE);
		return;
	}

	if (_wq_exiting(wq)) {
		inheritor = TURNSTILE_INHERITOR_NULL;
	} else {
		if (req->tr_state != WORKQ_TR_STATE_QUEUED) {
			panic("Invalid thread request (%p) state %d", req, req->tr_state);
		}

		if (owner) {
			inheritor = owner;
			flags |= TURNSTILE_INHERITOR_THREAD;
		} else {
			inheritor = wq->wq_turnstile;
			flags |= TURNSTILE_INHERITOR_TURNSTILE;
		}
	}

	workq_perform_turnstile_operation_locked(wq, ^{
		turnstile_update_inheritor(wl_ts, inheritor, flags);
	});
}

void
workq_kern_threadreq_redrive(struct proc *p, workq_kern_threadreq_flags_t flags)
{
	struct workqueue *wq = proc_get_wqptr_fast(p);

	workq_lock_spin(wq);
	workq_schedule_creator(p, wq, flags);
	workq_unlock(wq);
}

/*
 * Always called at AST by the thread on itself
 *
 * Upon quantum expiry, the workqueue subsystem evaluates its state and decides
 * on what the thread should do next. The TSD value is always set by the thread
 * on itself in the kernel and cleared either by userspace when it acks the TSD
 * value and takes action, or by the thread in the kernel when the quantum
 * expires again.
 */
void
workq_kern_quantum_expiry_reevaluate(proc_t proc, thread_t thread)
{
	struct uthread *uth = get_bsdthread_info(thread);

	if (uth->uu_workq_flags & UT_WORKQ_DYING) {
		return;
	}

	if (!thread_supports_cooperative_workqueue(thread)) {
		panic("Quantum expired for thread that doesn't support cooperative workqueue");
	}

	thread_qos_t qos = uth->uu_workq_pri.qos_bucket;
	if (qos == THREAD_QOS_UNSPECIFIED) {
		panic("Thread should not have workq bucket of QoS UN");
	}

	assert(thread_has_expired_workqueue_quantum(thread, false));

	struct workqueue *wq = proc_get_wqptr(proc);
	assert(wq != NULL);

	/*
	 * For starters, we're just going to evaluate and see if we need to narrow
	 * the pool and tell this thread to park if needed. In the future, we'll
	 * evaluate and convey other workqueue state information like needing to
	 * pump kevents, etc.
	 */
	uint64_t flags = 0;

	workq_lock_spin(wq);

	if (workq_thread_is_cooperative(uth)) {
		if (!workq_cooperative_allowance(wq, qos, uth, false)) {
			flags |= PTHREAD_WQ_QUANTUM_EXPIRY_NARROW;
		} else {
			/* In the future, when we have kevent hookups for the cooperative
			 * pool, we need fancier logic for what userspace should do. But
			 * right now, only userspace thread requests exist - so we'll just
			 * tell userspace to shuffle work items */
			flags |= PTHREAD_WQ_QUANTUM_EXPIRY_SHUFFLE;
		}
	} else if (workq_thread_is_nonovercommit(uth)) {
		if (!workq_constrained_allowance(wq, qos, uth, false)) {
			flags |= PTHREAD_WQ_QUANTUM_EXPIRY_NARROW;
		}
	}
	workq_unlock(wq);

	WQ_TRACE(TRACE_wq_quantum_expiry_reevaluate, flags, 0, 0, 0);

	kevent_set_workq_quantum_expiry_user_tsd(proc, thread, flags);

	/* We have conveyed to userspace about what it needs to do upon quantum
	 * expiry, now rearm the workqueue quantum again */
	thread_arm_workqueue_quantum(get_machthread(uth));
}

void
workq_schedule_creator_turnstile_redrive(struct workqueue *wq, bool locked)
{
	if (locked) {
		workq_schedule_creator(NULL, wq, WORKQ_THREADREQ_NONE);
	} else {
		workq_schedule_immediate_thread_creation(wq);
	}
}

static int
workq_thread_return(struct proc *p, struct workq_kernreturn_args *uap,
    struct workqueue *wq)
{
	thread_t th = current_thread();
	struct uthread *uth = get_bsdthread_info(th);
	workq_threadreq_t kqr = uth->uu_kqr_bound;
	workq_threadreq_param_t trp = { };
	int nevents = uap->affinity, error;
	user_addr_t eventlist = uap->item;

	if (((thread_get_tag(th) & THREAD_TAG_WORKQUEUE) == 0) ||
	    (uth->uu_workq_flags & UT_WORKQ_DYING)) {
		return EINVAL;
	}

	if (eventlist && nevents && kqr == NULL) {
		return EINVAL;
	}

	/* reset signal mask on the workqueue thread to default state */
	if (uth->uu_sigmask != (sigset_t)(~workq_threadmask)) {
		proc_lock(p);
		uth->uu_sigmask = ~workq_threadmask;
		proc_unlock(p);
	}

	if (kqr && kqr->tr_flags & WORKQ_TR_FLAG_WL_PARAMS) {
		/*
		 * Ensure we store the threadreq param before unbinding
		 * the kqr from this thread.
		 */
		trp = kqueue_threadreq_workloop_param(kqr);
	}

	/*
	 * Freeze the base pri while we decide the fate of this thread.
	 *
	 * Either:
	 * - we return to user and kevent_cleanup will have unfrozen the base pri,
	 * - or we proceed to workq_select_threadreq_or_park_and_unlock() who will.
	 */
	thread_freeze_base_pri(th);

	if (kqr) {
		uint32_t upcall_flags = WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_REUSE;
		if (kqr->tr_flags & WORKQ_TR_FLAG_WORKLOOP) {
			upcall_flags |= WQ_FLAG_THREAD_WORKLOOP | WQ_FLAG_THREAD_KEVENT;
		} else {
			upcall_flags |= WQ_FLAG_THREAD_KEVENT;
		}
		if (uth->uu_workq_pri.qos_bucket == WORKQ_THREAD_QOS_MANAGER) {
			upcall_flags |= WQ_FLAG_THREAD_EVENT_MANAGER;
		} else {
			if (workq_thread_is_overcommit(uth)) {
				upcall_flags |= WQ_FLAG_THREAD_OVERCOMMIT;
			}
			if (uth->uu_workq_flags & UT_WORKQ_OUTSIDE_QOS) {
				upcall_flags |= WQ_FLAG_THREAD_OUTSIDEQOS;
			} else {
				upcall_flags |= uth->uu_workq_pri.qos_req |
				    WQ_FLAG_THREAD_PRIO_QOS;
			}
		}
		error = pthread_functions->workq_handle_stack_events(p, th,
		    get_task_map(p->task), uth->uu_workq_stackaddr,
		    uth->uu_workq_thport, eventlist, nevents, upcall_flags);
		if (error) {
			assert(uth->uu_kqr_bound == kqr);
			return error;
		}

		// pthread is supposed to pass KEVENT_FLAG_PARKING here
		// which should cause the above call to either:
		// - not return
		// - return an error
		// - return 0 and have unbound properly
		assert(uth->uu_kqr_bound == NULL);
	}

	WQ_TRACE_WQ(TRACE_wq_runthread | DBG_FUNC_END, wq, uap->options, 0, 0);

	thread_sched_call(th, NULL);
	thread_will_park_or_terminate(th);
#if CONFIG_WORKLOOP_DEBUG
	UU_KEVENT_HISTORY_WRITE_ENTRY(uth, { .uu_error = -1, });
#endif

	workq_lock_spin(wq);
	WQ_TRACE_WQ(TRACE_wq_thread_logical_run | DBG_FUNC_END, wq, 0, 0, 0);
	uth->uu_save.uus_workq_park_data.workloop_params = trp.trp_value;
	workq_select_threadreq_or_park_and_unlock(p, wq, uth,
	    WQ_SETUP_CLEAR_VOUCHER);
	__builtin_unreachable();
}

/**
 * Multiplexed call to interact with the workqueue mechanism
 */
int
workq_kernreturn(struct proc *p, struct workq_kernreturn_args *uap, int32_t *retval)
{
	int options = uap->options;
	int arg2 = uap->affinity;
	int arg3 = uap->prio;
	struct workqueue *wq = proc_get_wqptr(p);
	int error = 0;

	if ((p->p_lflag & P_LREGISTER) == 0) {
		return EINVAL;
	}

	switch (options) {
	case WQOPS_QUEUE_NEWSPISUPP: {
		/*
		 * arg2 = offset of serialno into dispatch queue
		 * arg3 = kevent support
		 */
		int offset = arg2;
		if (arg3 & 0x01) {
			// If we get here, then userspace has indicated support for kevent delivery.
		}

		p->p_dispatchqueue_serialno_offset = (uint64_t)offset;
		break;
	}
	case WQOPS_QUEUE_REQTHREADS: {
		/*
		 * arg2 = number of threads to start
		 * arg3 = priority
		 */
		error = workq_reqthreads(p, arg2, arg3, false);
		break;
	}
	/* For requesting threads for the cooperative pool */
	case WQOPS_QUEUE_REQTHREADS2: {
		/*
		 * arg2 = number of threads to start
		 * arg3 = priority
		 */
		error = workq_reqthreads(p, arg2, arg3, true);
		break;
	}
	case WQOPS_SET_EVENT_MANAGER_PRIORITY: {
		/*
		 * arg2 = priority for the manager thread
		 *
		 * if _PTHREAD_PRIORITY_SCHED_PRI_FLAG is set,
		 * the low bits of the value contains a scheduling priority
		 * instead of a QOS value
		 */
		pthread_priority_t pri = arg2;

		if (wq == NULL) {
			error = EINVAL;
			break;
		}

		/*
		 * Normalize the incoming priority so that it is ordered numerically.
		 */
		if (pri & _PTHREAD_PRIORITY_SCHED_PRI_FLAG) {
			pri &= (_PTHREAD_PRIORITY_SCHED_PRI_MASK |
			    _PTHREAD_PRIORITY_SCHED_PRI_FLAG);
		} else {
			thread_qos_t qos = _pthread_priority_thread_qos(pri);
			int relpri = _pthread_priority_relpri(pri);
			if (relpri > 0 || relpri < THREAD_QOS_MIN_TIER_IMPORTANCE ||
			    qos == THREAD_QOS_UNSPECIFIED) {
				error = EINVAL;
				break;
			}
			pri &= ~_PTHREAD_PRIORITY_FLAGS_MASK;
		}

		/*
		 * If userspace passes a scheduling priority, that wins over any QoS.
		 * Userspace should takes care not to lower the priority this way.
		 */
		workq_lock_spin(wq);
		if (wq->wq_event_manager_priority < (uint32_t)pri) {
			wq->wq_event_manager_priority = (uint32_t)pri;
		}
		workq_unlock(wq);
		break;
	}
	case WQOPS_THREAD_KEVENT_RETURN:
	case WQOPS_THREAD_WORKLOOP_RETURN:
	case WQOPS_THREAD_RETURN: {
		error = workq_thread_return(p, uap, wq);
		break;
	}

	case WQOPS_SHOULD_NARROW: {
		/*
		 * arg2 = priority to test
		 * arg3 = unused
		 */
		thread_t th = current_thread();
		struct uthread *uth = get_bsdthread_info(th);
		if (((thread_get_tag(th) & THREAD_TAG_WORKQUEUE) == 0) ||
		    (uth->uu_workq_flags & (UT_WORKQ_DYING | UT_WORKQ_OVERCOMMIT))) {
			error = EINVAL;
			break;
		}

		thread_qos_t qos = _pthread_priority_thread_qos(arg2);
		if (qos == THREAD_QOS_UNSPECIFIED) {
			error = EINVAL;
			break;
		}
		workq_lock_spin(wq);
		bool should_narrow = !workq_constrained_allowance(wq, qos, uth, false);
		workq_unlock(wq);

		*retval = should_narrow;
		break;
	}
	case WQOPS_SETUP_DISPATCH: {
		/*
		 * item = pointer to workq_dispatch_config structure
		 * arg2 = sizeof(item)
		 */
		struct workq_dispatch_config cfg;
		bzero(&cfg, sizeof(cfg));

		error = copyin(uap->item, &cfg, MIN(sizeof(cfg), (unsigned long) arg2));
		if (error) {
			break;
		}

		if (cfg.wdc_flags & ~WORKQ_DISPATCH_SUPPORTED_FLAGS ||
		    cfg.wdc_version < WORKQ_DISPATCH_MIN_SUPPORTED_VERSION) {
			error = ENOTSUP;
			break;
		}

		/* Load fields from version 1 */
		p->p_dispatchqueue_serialno_offset = cfg.wdc_queue_serialno_offs;

		/* Load fields from version 2 */
		if (cfg.wdc_version >= 2) {
			p->p_dispatchqueue_label_offset = cfg.wdc_queue_label_offs;
		}

		break;
	}
	default:
		error = EINVAL;
		break;
	}

	return error;
}

/*
 * We have no work to do, park ourselves on the idle list.
 *
 * Consumes the workqueue lock and does not return.
 */
__attribute__((noreturn, noinline))
static void
workq_park_and_unlock(proc_t p, struct workqueue *wq, struct uthread *uth,
    uint32_t setup_flags)
{
	assert(uth == current_uthread());
	assert(uth->uu_kqr_bound == NULL);
	workq_push_idle_thread(p, wq, uth, setup_flags); // may not return

	workq_thread_reset_cpupercent(NULL, uth);

#if CONFIG_PREADOPT_TG
	/* Clear the preadoption thread group on the thread.
	 *
	 * Case 1:
	 *		Creator thread which never picked up a thread request. We set a
	 *		preadoption thread group on creator threads but if it never picked
	 *		up a thread request and didn't go to userspace, then the thread will
	 *		park with a preadoption thread group but no explicitly adopted
	 *		voucher or work interval.
	 *
	 *		We drop the preadoption thread group here before proceeding to park.
	 *		Note - we may get preempted when we drop the workq lock below.
	 *
	 * Case 2:
	 *		Thread picked up a thread request and bound to it and returned back
	 *		from userspace and is parking. At this point, preadoption thread
	 *		group should be NULL since the thread has unbound from the thread
	 *		request. So this operation should be a no-op.
	 */
	thread_set_preadopt_thread_group(get_machthread(uth), NULL);
#endif

	if ((uth->uu_workq_flags & UT_WORKQ_IDLE_CLEANUP) &&
	    !(uth->uu_workq_flags & UT_WORKQ_DYING)) {
		workq_unlock(wq);

		/*
		 * workq_push_idle_thread() will unset `has_stack`
		 * if it wants us to free the stack before parking.
		 */
		if (!uth->uu_save.uus_workq_park_data.has_stack) {
			pthread_functions->workq_markfree_threadstack(p,
			    get_machthread(uth), get_task_map(p->task),
			    uth->uu_workq_stackaddr);
		}

		/*
		 * When we remove the voucher from the thread, we may lose our importance
		 * causing us to get preempted, so we do this after putting the thread on
		 * the idle list.  Then, when we get our importance back we'll be able to
		 * use this thread from e.g. the kevent call out to deliver a boosting
		 * message.
		 *
		 * Note that setting the voucher to NULL will not clear the preadoption
		 * thread since this thread could have become the creator again and
		 * perhaps acquired a preadoption thread group.
		 */
		__assert_only kern_return_t kr;
		kr = thread_set_voucher_name(MACH_PORT_NULL);
		assert(kr == KERN_SUCCESS);

		workq_lock_spin(wq);
		uth->uu_workq_flags &= ~UT_WORKQ_IDLE_CLEANUP;
		setup_flags &= ~WQ_SETUP_CLEAR_VOUCHER;
	}

	WQ_TRACE_WQ(TRACE_wq_thread_logical_run | DBG_FUNC_END, wq, 0, 0, 0);

	if (uth->uu_workq_flags & UT_WORKQ_RUNNING) {
		/*
		 * While we'd dropped the lock to unset our voucher, someone came
		 * around and made us runnable.  But because we weren't waiting on the
		 * event their thread_wakeup() was ineffectual.  To correct for that,
		 * we just run the continuation ourselves.
		 */
		workq_unpark_select_threadreq_or_park_and_unlock(p, wq, uth, setup_flags);
		__builtin_unreachable();
	}

	if (uth->uu_workq_flags & UT_WORKQ_DYING) {
		workq_unpark_for_death_and_unlock(p, wq, uth,
		    WORKQ_UNPARK_FOR_DEATH_WAS_IDLE, setup_flags);
		__builtin_unreachable();
	}

	/* Disarm the workqueue quantum since the thread is now idle */
	thread_disarm_workqueue_quantum(get_machthread(uth));

	thread_set_pending_block_hint(get_machthread(uth), kThreadWaitParkedWorkQueue);
	assert_wait(workq_parked_wait_event(uth), THREAD_INTERRUPTIBLE);
	workq_unlock(wq);
	thread_block(workq_unpark_continue);
	__builtin_unreachable();
}

static inline bool
workq_may_start_event_mgr_thread(struct workqueue *wq, struct uthread *uth)
{
	/*
	 * There's an event manager request and either:
	 * - no event manager currently running
	 * - we are re-using the event manager
	 */
	return wq->wq_thscheduled_count[_wq_bucket(WORKQ_THREAD_QOS_MANAGER)] == 0 ||
	       (uth && uth->uu_workq_pri.qos_bucket == WORKQ_THREAD_QOS_MANAGER);
}

static uint32_t
workq_constrained_allowance(struct workqueue *wq, thread_qos_t at_qos,
    struct uthread *uth, bool may_start_timer)
{
	assert(at_qos != WORKQ_THREAD_QOS_MANAGER);
	uint32_t count = 0;

	uint32_t max_count = wq->wq_constrained_threads_scheduled;
	if (uth && workq_thread_is_nonovercommit(uth)) {
		/*
		 * don't count the current thread as scheduled
		 */
		assert(max_count > 0);
		max_count--;
	}
	if (max_count >= wq_max_constrained_threads) {
		WQ_TRACE_WQ(TRACE_wq_constrained_admission | DBG_FUNC_NONE, wq, 1,
		    wq->wq_constrained_threads_scheduled,
		    wq_max_constrained_threads);
		/*
		 * we need 1 or more constrained threads to return to the kernel before
		 * we can dispatch additional work
		 */
		return 0;
	}
	max_count -= wq_max_constrained_threads;

	/*
	 * Compute a metric for many how many threads are active.  We find the
	 * highest priority request outstanding and then add up the number of active
	 * threads in that and all higher-priority buckets.  We'll also add any
	 * "busy" threads which are not currently active but blocked recently enough
	 * that we can't be sure that they won't be unblocked soon and start
	 * being active again.
	 *
	 * We'll then compare this metric to our max concurrency to decide whether
	 * to add a new thread.
	 */

	uint32_t busycount, thactive_count;

	thactive_count = _wq_thactive_aggregate_downto_qos(wq, _wq_thactive(wq),
	    at_qos, &busycount, NULL);

	if (uth && uth->uu_workq_pri.qos_bucket != WORKQ_THREAD_QOS_MANAGER &&
	    at_qos <= uth->uu_workq_pri.qos_bucket) {
		/*
		 * Don't count this thread as currently active, but only if it's not
		 * a manager thread, as _wq_thactive_aggregate_downto_qos ignores active
		 * managers.
		 */
		assert(thactive_count > 0);
		thactive_count--;
	}

	count = wq_max_parallelism[_wq_bucket(at_qos)];
	if (count > thactive_count + busycount) {
		count -= thactive_count + busycount;
		WQ_TRACE_WQ(TRACE_wq_constrained_admission | DBG_FUNC_NONE, wq, 2,
		    thactive_count, busycount);
		return MIN(count, max_count);
	} else {
		WQ_TRACE_WQ(TRACE_wq_constrained_admission | DBG_FUNC_NONE, wq, 3,
		    thactive_count, busycount);
	}

	if (may_start_timer) {
		/*
		 * If this is called from the add timer, we won't have another timer
		 * fire when the thread exits the "busy" state, so rearm the timer.
		 */
		workq_schedule_delayed_thread_creation(wq, 0);
	}

	return 0;
}

static bool
workq_threadreq_admissible(struct workqueue *wq, struct uthread *uth,
    workq_threadreq_t req)
{
	if (req->tr_qos == WORKQ_THREAD_QOS_MANAGER) {
		return workq_may_start_event_mgr_thread(wq, uth);
	}
	if (workq_threadreq_is_cooperative(req)) {
		return workq_cooperative_allowance(wq, req->tr_qos, uth, true);
	}
	if (workq_threadreq_is_nonovercommit(req)) {
		return workq_constrained_allowance(wq, req->tr_qos, uth, true);
	}

	return true;
}

/*
 * Called from the context of selecting thread requests for threads returning
 * from userspace or creator thread
 */
static workq_threadreq_t
workq_cooperative_queue_best_req(struct workqueue *wq, struct uthread *uth)
{
	workq_lock_held(wq);

	/*
	 * If the current thread is cooperative, we need to exclude it as part of
	 * cooperative schedule count since this thread is looking for a new
	 * request. Change in the schedule count for cooperative pool therefore
	 * requires us to reeevaluate the next best request for it.
	 */
	if (uth && workq_thread_is_cooperative(uth)) {
		_wq_cooperative_queue_scheduled_count_dec(wq, uth->uu_workq_pri.qos_bucket);

		(void) _wq_cooperative_queue_refresh_best_req_qos(wq);

		_wq_cooperative_queue_scheduled_count_inc(wq, uth->uu_workq_pri.qos_bucket);
	} else {
		/*
		 * The old value that was already precomputed should be safe to use -
		 * add an assert that asserts that the best req QoS doesn't change in
		 * this case
		 */
		assert(_wq_cooperative_queue_refresh_best_req_qos(wq) == false);
	}

	thread_qos_t qos = wq->wq_cooperative_queue_best_req_qos;

	/* There are no eligible requests in the cooperative pool */
	if (qos == THREAD_QOS_UNSPECIFIED) {
		return NULL;
	}
	assert(qos != WORKQ_THREAD_QOS_ABOVEUI);
	assert(qos != WORKQ_THREAD_QOS_MANAGER);

	uint8_t bucket = _wq_bucket(qos);
	assert(!STAILQ_EMPTY(&wq->wq_cooperative_queue[bucket]));

	return STAILQ_FIRST(&wq->wq_cooperative_queue[bucket]);
}

static workq_threadreq_t
workq_threadreq_select_for_creator(struct workqueue *wq)
{
	workq_threadreq_t req_qos, req_pri, req_tmp, req_mgr;
	thread_qos_t qos = THREAD_QOS_UNSPECIFIED;
	uint8_t pri = 0;

	/*
	 * Compute the best priority request, and ignore the turnstile for now
	 */

	req_pri = priority_queue_max(&wq->wq_special_queue,
	    struct workq_threadreq_s, tr_entry);
	if (req_pri) {
		pri = (uint8_t)priority_queue_entry_sched_pri(&wq->wq_special_queue,
		    &req_pri->tr_entry);
	}

	/*
	 * Handle the manager thread request. The special queue might yield
	 * a higher priority, but the manager always beats the QoS world.
	 */

	req_mgr = wq->wq_event_manager_threadreq;
	if (req_mgr && workq_may_start_event_mgr_thread(wq, NULL)) {
		uint32_t mgr_pri = wq->wq_event_manager_priority;

		if (mgr_pri & _PTHREAD_PRIORITY_SCHED_PRI_FLAG) {
			mgr_pri &= _PTHREAD_PRIORITY_SCHED_PRI_MASK;
		} else {
			mgr_pri = thread_workq_pri_for_qos(
				_pthread_priority_thread_qos(mgr_pri));
		}

		return mgr_pri >= pri ? req_mgr : req_pri;
	}

	/*
	 * Compute the best QoS Request, and check whether it beats the "pri" one
	 *
	 * Start by comparing the overcommit and the cooperative pool
	 */
	req_qos = priority_queue_max(&wq->wq_overcommit_queue,
	    struct workq_threadreq_s, tr_entry);
	if (req_qos) {
		qos = req_qos->tr_qos;
	}

	req_tmp = workq_cooperative_queue_best_req(wq, NULL);
	if (req_tmp && qos <= req_tmp->tr_qos) {
		/*
		 * Cooperative TR is better between overcommit and cooperative.  Note
		 * that if qos is same between overcommit and cooperative, we choose
		 * cooperative.
		 *
		 * Pick cooperative pool if it passes the admissions check
		 */
		if (workq_cooperative_allowance(wq, req_tmp->tr_qos, NULL, true)) {
			req_qos = req_tmp;
			qos = req_qos->tr_qos;
		}
	}

	/*
	 * Compare the best QoS so far - either from overcommit or from cooperative
	 * pool - and compare it with the constrained pool
	 */
	req_tmp = priority_queue_max(&wq->wq_constrained_queue,
	    struct workq_threadreq_s, tr_entry);

	if (req_tmp && qos < req_tmp->tr_qos) {
		/*
		 * Constrained pool is best in QoS between overcommit, cooperative
		 * and constrained. Now check how it fairs against the priority case
		 */
		if (pri && pri >= thread_workq_pri_for_qos(req_tmp->tr_qos)) {
			return req_pri;
		}

		if (workq_constrained_allowance(wq, req_tmp->tr_qos, NULL, true)) {
			/*
			 * If the constrained thread request is the best one and passes
			 * the admission check, pick it.
			 */
			return req_tmp;
		}
	}

	/*
	 * Compare the best of the QoS world with the priority
	 */
	if (pri && (!qos || pri >= thread_workq_pri_for_qos(qos))) {
		return req_pri;
	}

	if (req_qos) {
		return req_qos;
	}

	/*
	 * If we had no eligible request but we have a turnstile push,
	 * it must be a non overcommit thread request that failed
	 * the admission check.
	 *
	 * Just fake a BG thread request so that if the push stops the creator
	 * priority just drops to 4.
	 */
	if (turnstile_workq_proprietor_of_max_turnstile(wq->wq_turnstile, NULL)) {
		static struct workq_threadreq_s workq_sync_push_fake_req = {
			.tr_qos = THREAD_QOS_BACKGROUND,
		};

		return &workq_sync_push_fake_req;
	}

	return NULL;
}

/*
 * Returns true if this caused a change in the schedule counts of the
 * cooperative pool
 */
static bool
workq_adjust_cooperative_constrained_schedule_counts(struct workqueue *wq,
    struct uthread *uth, thread_qos_t old_thread_qos, workq_tr_flags_t tr_flags)
{
	workq_lock_held(wq);

	/*
	 * Row: thread type
	 * Column: Request type
	 *
	 *					overcommit		non-overcommit		cooperative
	 * overcommit			X				case 1				case 2
	 * cooperative		case 3				case 4				case 5
	 * non-overcommit	case 6					X				case 7
	 *
	 * Move the thread to the right bucket depending on what state it currently
	 * has and what state the thread req it picks, is going to have.
	 *
	 * Note that the creator thread is an overcommit thread.
	 */
	thread_qos_t new_thread_qos = uth->uu_workq_pri.qos_bucket;

	/*
	 * Anytime a cooperative bucket's schedule count changes, we need to
	 * potentially refresh the next best QoS for that pool when we determine
	 * the next request for the creator
	 */
	bool cooperative_pool_sched_count_changed = false;

	if (workq_thread_is_overcommit(uth)) {
		if (workq_tr_is_nonovercommit(tr_flags)) {
			// Case 1: thread is overcommit, req is non-overcommit
			wq->wq_constrained_threads_scheduled++;
		} else if (workq_tr_is_cooperative(tr_flags)) {
			// Case 2: thread is overcommit, req is cooperative
			_wq_cooperative_queue_scheduled_count_inc(wq, new_thread_qos);
			cooperative_pool_sched_count_changed = true;
		}
	} else if (workq_thread_is_cooperative(uth)) {
		if (workq_tr_is_overcommit(tr_flags)) {
			// Case 3: thread is cooperative, req is overcommit
			_wq_cooperative_queue_scheduled_count_dec(wq, old_thread_qos);
		} else if (workq_tr_is_nonovercommit(tr_flags)) {
			// Case 4: thread is cooperative, req is non-overcommit
			_wq_cooperative_queue_scheduled_count_dec(wq, old_thread_qos);
			wq->wq_constrained_threads_scheduled++;
		} else {
			// Case 5: thread is cooperative, req is also cooperative
			assert(workq_tr_is_cooperative(tr_flags));
			_wq_cooperative_queue_scheduled_count_dec(wq, old_thread_qos);
			_wq_cooperative_queue_scheduled_count_inc(wq, new_thread_qos);
		}
		cooperative_pool_sched_count_changed = true;
	} else {
		if (workq_tr_is_overcommit(tr_flags)) {
			// Case 6: Thread is non-overcommit, req is overcommit
			wq->wq_constrained_threads_scheduled--;
		} else if (workq_tr_is_cooperative(tr_flags)) {
			// Case 7: Thread is non-overcommit, req is cooperative
			wq->wq_constrained_threads_scheduled--;
			_wq_cooperative_queue_scheduled_count_inc(wq, new_thread_qos);
			cooperative_pool_sched_count_changed = true;
		}
	}

	return cooperative_pool_sched_count_changed;
}

static workq_threadreq_t
workq_threadreq_select(struct workqueue *wq, struct uthread *uth)
{
	workq_threadreq_t req_qos, req_pri, req_tmp, req_mgr;
	uintptr_t proprietor;
	thread_qos_t qos = THREAD_QOS_UNSPECIFIED;
	uint8_t pri = 0;

	if (uth == wq->wq_creator) {
		uth = NULL;
	}

	/*
	 * Compute the best priority request (special or turnstile)
	 */

	pri = (uint8_t)turnstile_workq_proprietor_of_max_turnstile(wq->wq_turnstile,
	    &proprietor);
	if (pri) {
		struct kqworkloop *kqwl = (struct kqworkloop *)proprietor;
		req_pri = &kqwl->kqwl_request;
		if (req_pri->tr_state != WORKQ_TR_STATE_QUEUED) {
			panic("Invalid thread request (%p) state %d",
			    req_pri, req_pri->tr_state);
		}
	} else {
		req_pri = NULL;
	}

	req_tmp = priority_queue_max(&wq->wq_special_queue,
	    struct workq_threadreq_s, tr_entry);
	if (req_tmp && pri < priority_queue_entry_sched_pri(&wq->wq_special_queue,
	    &req_tmp->tr_entry)) {
		req_pri = req_tmp;
		pri = (uint8_t)priority_queue_entry_sched_pri(&wq->wq_special_queue,
		    &req_tmp->tr_entry);
	}

	/*
	 * Handle the manager thread request. The special queue might yield
	 * a higher priority, but the manager always beats the QoS world.
	 */

	req_mgr = wq->wq_event_manager_threadreq;
	if (req_mgr && workq_may_start_event_mgr_thread(wq, uth)) {
		uint32_t mgr_pri = wq->wq_event_manager_priority;

		if (mgr_pri & _PTHREAD_PRIORITY_SCHED_PRI_FLAG) {
			mgr_pri &= _PTHREAD_PRIORITY_SCHED_PRI_MASK;
		} else {
			mgr_pri = thread_workq_pri_for_qos(
				_pthread_priority_thread_qos(mgr_pri));
		}

		return mgr_pri >= pri ? req_mgr : req_pri;
	}

	/*
	 * Compute the best QoS Request, and check whether it beats the "pri" one
	 */

	req_qos = priority_queue_max(&wq->wq_overcommit_queue,
	    struct workq_threadreq_s, tr_entry);
	if (req_qos) {
		qos = req_qos->tr_qos;
	}

	req_tmp = workq_cooperative_queue_best_req(wq, uth);
	if (req_tmp && qos <= req_tmp->tr_qos) {
		/*
		 * Cooperative TR is better between overcommit and cooperative.  Note
		 * that if qos is same between overcommit and cooperative, we choose
		 * cooperative.
		 *
		 * Pick cooperative pool if it passes the admissions check
		 */
		if (workq_cooperative_allowance(wq, req_tmp->tr_qos, uth, true)) {
			req_qos = req_tmp;
			qos = req_qos->tr_qos;
		}
	}

	/*
	 * Compare the best QoS so far - either from overcommit or from cooperative
	 * pool - and compare it with the constrained pool
	 */
	req_tmp = priority_queue_max(&wq->wq_constrained_queue,
	    struct workq_threadreq_s, tr_entry);

	if (req_tmp && qos < req_tmp->tr_qos) {
		/*
		 * Constrained pool is best in QoS between overcommit, cooperative
		 * and constrained. Now check how it fairs against the priority case
		 */
		if (pri && pri >= thread_workq_pri_for_qos(req_tmp->tr_qos)) {
			return req_pri;
		}

		if (workq_constrained_allowance(wq, req_tmp->tr_qos, uth, true)) {
			/*
			 * If the constrained thread request is the best one and passes
			 * the admission check, pick it.
			 */
			return req_tmp;
		}
	}

	if (req_pri && (!qos || pri >= thread_workq_pri_for_qos(qos))) {
		return req_pri;
	}

	return req_qos;
}

/*
 * The creator is an anonymous thread that is counted as scheduled,
 * but otherwise without its scheduler callback set or tracked as active
 * that is used to make other threads.
 *
 * When more requests are added or an existing one is hurried along,
 * a creator is elected and setup, or the existing one overridden accordingly.
 *
 * While this creator is in flight, because no request has been dequeued,
 * already running threads have a chance at stealing thread requests avoiding
 * useless context switches, and the creator once scheduled may not find any
 * work to do and will then just park again.
 *
 * The creator serves the dual purpose of informing the scheduler of work that
 * hasn't be materialized as threads yet, and also as a natural pacing mechanism
 * for thread creation.
 *
 * By being anonymous (and not bound to anything) it means that thread requests
 * can be stolen from this creator by threads already on core yielding more
 * efficient scheduling and reduced context switches.
 */
static void
workq_schedule_creator(proc_t p, struct workqueue *wq,
    workq_kern_threadreq_flags_t flags)
{
	workq_threadreq_t req;
	struct uthread *uth;
	bool needs_wakeup;

	workq_lock_held(wq);
	assert(p || (flags & WORKQ_THREADREQ_CAN_CREATE_THREADS) == 0);

again:
	uth = wq->wq_creator;

	if (!wq->wq_reqcount) {
		/*
		 * There is no thread request left.
		 *
		 * If there is a creator, leave everything in place, so that it cleans
		 * up itself in workq_push_idle_thread().
		 *
		 * Else, make sure the turnstile state is reset to no inheritor.
		 */
		if (uth == NULL) {
			workq_turnstile_update_inheritor(wq, TURNSTILE_INHERITOR_NULL, 0);
		}
		return;
	}

	req = workq_threadreq_select_for_creator(wq);
	if (req == NULL) {
		/*
		 * There isn't a thread request that passes the admission check.
		 *
		 * If there is a creator, do not touch anything, the creator will sort
		 * it out when it runs.
		 *
		 * Else, set the inheritor to "WORKQ" so that the turnstile propagation
		 * code calls us if anything changes.
		 */
		if (uth == NULL) {
			workq_turnstile_update_inheritor(wq, wq, TURNSTILE_INHERITOR_WORKQ);
		}
		return;
	}


	if (uth) {
		/*
		 * We need to maybe override the creator we already have
		 */
		if (workq_thread_needs_priority_change(req, uth)) {
			WQ_TRACE_WQ(TRACE_wq_creator_select | DBG_FUNC_NONE,
			    wq, 1, uthread_tid(uth), req->tr_qos);
			workq_thread_reset_pri(wq, uth, req, /*unpark*/ true);
		}
		assert(wq->wq_inheritor == get_machthread(uth));
	} else if (wq->wq_thidlecount) {
		/*
		 * We need to unpark a creator thread
		 */
		wq->wq_creator = uth = workq_pop_idle_thread(wq, UT_WORKQ_OVERCOMMIT,
		    &needs_wakeup);
		/* Always reset the priorities on the newly chosen creator */
		workq_thread_reset_pri(wq, uth, req, /*unpark*/ true);
		workq_turnstile_update_inheritor(wq, get_machthread(uth),
		    TURNSTILE_INHERITOR_THREAD);
		WQ_TRACE_WQ(TRACE_wq_creator_select | DBG_FUNC_NONE,
		    wq, 2, uthread_tid(uth), req->tr_qos);
		uth->uu_save.uus_workq_park_data.fulfilled_snapshot = wq->wq_fulfilled;
		uth->uu_save.uus_workq_park_data.yields = 0;
		if (needs_wakeup) {
			workq_thread_wakeup(uth);
		}
	} else {
		/*
		 * We need to allocate a thread...
		 */
		if (__improbable(wq->wq_nthreads >= wq_max_threads)) {
			/* out of threads, just go away */
			flags = WORKQ_THREADREQ_NONE;
		} else if (flags & WORKQ_THREADREQ_SET_AST_ON_FAILURE) {
			act_set_astkevent(current_thread(), AST_KEVENT_REDRIVE_THREADREQ);
		} else if (!(flags & WORKQ_THREADREQ_CAN_CREATE_THREADS)) {
			/* This can drop the workqueue lock, and take it again */
			workq_schedule_immediate_thread_creation(wq);
		} else if (workq_add_new_idle_thread(p, wq)) {
			goto again;
		} else {
			workq_schedule_delayed_thread_creation(wq, 0);
		}

		/*
		 * If the current thread is the inheritor:
		 *
		 * If we set the AST, then the thread will stay the inheritor until
		 * either the AST calls workq_kern_threadreq_redrive(), or it parks
		 * and calls workq_push_idle_thread().
		 *
		 * Else, the responsibility of the thread creation is with a thread-call
		 * and we need to clear the inheritor.
		 */
		if ((flags & WORKQ_THREADREQ_SET_AST_ON_FAILURE) == 0 &&
		    wq->wq_inheritor == current_thread()) {
			workq_turnstile_update_inheritor(wq, TURNSTILE_INHERITOR_NULL, 0);
		}
	}
}

/**
 * Same as workq_unpark_select_threadreq_or_park_and_unlock,
 * but do not allow early binds.
 *
 * Called with the base pri frozen, will unfreeze it.
 */
__attribute__((noreturn, noinline))
static void
workq_select_threadreq_or_park_and_unlock(proc_t p, struct workqueue *wq,
    struct uthread *uth, uint32_t setup_flags)
{
	workq_threadreq_t req = NULL;
	bool is_creator = (wq->wq_creator == uth);
	bool schedule_creator = false;

	if (__improbable(_wq_exiting(wq))) {
		WQ_TRACE_WQ(TRACE_wq_select_threadreq | DBG_FUNC_NONE, wq, 0, 0, 0);
		goto park;
	}

	if (wq->wq_reqcount == 0) {
		WQ_TRACE_WQ(TRACE_wq_select_threadreq | DBG_FUNC_NONE, wq, 1, 0, 0);
		goto park;
	}

	req = workq_threadreq_select(wq, uth);
	if (__improbable(req == NULL)) {
		WQ_TRACE_WQ(TRACE_wq_select_threadreq | DBG_FUNC_NONE, wq, 2, 0, 0);
		goto park;
	}

	thread_qos_t old_thread_bucket = uth->uu_workq_pri.qos_bucket;
	uint8_t tr_flags = req->tr_flags;
	struct turnstile *req_ts = kqueue_threadreq_get_turnstile(req);

	/*
	 * Attempt to setup ourselves as the new thing to run, moving all priority
	 * pushes to ourselves.
	 *
	 * If the current thread is the creator, then the fact that we are presently
	 * running is proof that we'll do something useful, so keep going.
	 *
	 * For other cases, peek at the AST to know whether the scheduler wants
	 * to preempt us, if yes, park instead, and move the thread request
	 * turnstile back to the workqueue.
	 */
	if (req_ts) {
		workq_perform_turnstile_operation_locked(wq, ^{
			turnstile_update_inheritor(req_ts, get_machthread(uth),
			TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD);
			turnstile_update_inheritor_complete(req_ts,
			TURNSTILE_INTERLOCK_HELD);
		});
	}

	/* accounting changes of aggregate thscheduled_count and thactive which has
	 * to be paired with the workq_thread_reset_pri below so that we have
	 * uth->uu_workq_pri match with thactive.
	 *
	 * This is undone when the thread parks */
	if (is_creator) {
		WQ_TRACE_WQ(TRACE_wq_creator_select, wq, 4, 0,
		    uth->uu_save.uus_workq_park_data.yields);
		wq->wq_creator = NULL;
		_wq_thactive_inc(wq, req->tr_qos);
		wq->wq_thscheduled_count[_wq_bucket(req->tr_qos)]++;
	} else if (old_thread_bucket != req->tr_qos) {
		_wq_thactive_move(wq, old_thread_bucket, req->tr_qos);
	}
	workq_thread_reset_pri(wq, uth, req, /*unpark*/ true);

	/*
	 * Make relevant accounting changes for pool specific counts.
	 *
	 * The schedule counts changing can affect what the next best request
	 * for cooperative thread pool is if this request is dequeued.
	 */
	bool cooperative_sched_count_changed =
	    workq_adjust_cooperative_constrained_schedule_counts(wq, uth,
	    old_thread_bucket, tr_flags);

	if (workq_tr_is_overcommit(tr_flags)) {
		workq_thread_set_type(uth, UT_WORKQ_OVERCOMMIT);
	} else if (workq_tr_is_cooperative(tr_flags)) {
		workq_thread_set_type(uth, UT_WORKQ_COOPERATIVE);
	} else {
		workq_thread_set_type(uth, 0);
	}

	if (__improbable(thread_unfreeze_base_pri(get_machthread(uth)) && !is_creator)) {
		if (req_ts) {
			workq_perform_turnstile_operation_locked(wq, ^{
				turnstile_update_inheritor(req_ts, wq->wq_turnstile,
				TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_TURNSTILE);
				turnstile_update_inheritor_complete(req_ts,
				TURNSTILE_INTERLOCK_HELD);
			});
		}
		WQ_TRACE_WQ(TRACE_wq_select_threadreq | DBG_FUNC_NONE, wq, 3, 0, 0);
		goto park_thawed;
	}

	/*
	 * We passed all checks, dequeue the request, bind to it, and set it up
	 * to return to user.
	 */
	WQ_TRACE_WQ(TRACE_wq_thread_logical_run | DBG_FUNC_START, wq,
	    workq_trace_req_id(req), tr_flags, 0);
	wq->wq_fulfilled++;
	schedule_creator = workq_threadreq_dequeue(wq, req,
	    cooperative_sched_count_changed);

	workq_thread_reset_cpupercent(req, uth);

	if (tr_flags & (WORKQ_TR_FLAG_KEVENT | WORKQ_TR_FLAG_WORKLOOP)) {
		kqueue_threadreq_bind_prepost(p, req, uth);
		req = NULL;
	} else if (req->tr_count > 0) {
		req = NULL;
	}

	if (uth->uu_workq_flags & UT_WORKQ_NEW) {
		uth->uu_workq_flags ^= UT_WORKQ_NEW;
		setup_flags |= WQ_SETUP_FIRST_USE;
	}

	/* If one of the following is true, call workq_schedule_creator (which also
	 * adjusts priority of existing creator):
	 *
	 *	  - We are the creator currently so the wq may need a new creator
	 *	  - The request we're binding to is the highest priority one, existing
	 *	  creator's priority might need to be adjusted to reflect the next
	 *	  highest TR
	 */
	if (is_creator || schedule_creator) {
		/* This can drop the workqueue lock, and take it again */
		workq_schedule_creator(p, wq, WORKQ_THREADREQ_CAN_CREATE_THREADS);
	}

	workq_unlock(wq);

	if (req) {
		zfree(workq_zone_threadreq, req);
	}

	/*
	 * Run Thread, Run!
	 */
	uint32_t upcall_flags = WQ_FLAG_THREAD_NEWSPI;
	if (uth->uu_workq_pri.qos_bucket == WORKQ_THREAD_QOS_MANAGER) {
		upcall_flags |= WQ_FLAG_THREAD_EVENT_MANAGER;
	} else if (workq_tr_is_overcommit(tr_flags)) {
		upcall_flags |= WQ_FLAG_THREAD_OVERCOMMIT;
	} else if (workq_tr_is_cooperative(tr_flags)) {
		upcall_flags |= WQ_FLAG_THREAD_COOPERATIVE;
	}
	if (tr_flags & WORKQ_TR_FLAG_KEVENT) {
		upcall_flags |= WQ_FLAG_THREAD_KEVENT;
		assert((upcall_flags & WQ_FLAG_THREAD_COOPERATIVE) == 0);
	}

	if (tr_flags & WORKQ_TR_FLAG_WORKLOOP) {
		upcall_flags |= WQ_FLAG_THREAD_WORKLOOP | WQ_FLAG_THREAD_KEVENT;
	}
	uth->uu_save.uus_workq_park_data.upcall_flags = upcall_flags;

	if (tr_flags & (WORKQ_TR_FLAG_KEVENT | WORKQ_TR_FLAG_WORKLOOP)) {
		kqueue_threadreq_bind_commit(p, get_machthread(uth));
	} else {
#if CONFIG_PREADOPT_TG
		/*
		 * The thread may have a preadopt thread group on it already because it
		 * got tagged with it as a creator thread. So we need to make sure to
		 * clear that since we don't have preadoption for anonymous thread
		 * requests
		 */
		thread_set_preadopt_thread_group(get_machthread(uth), NULL);
#endif
	}

	workq_setup_and_run(p, uth, setup_flags);
	__builtin_unreachable();

park:
	thread_unfreeze_base_pri(get_machthread(uth));
park_thawed:
	workq_park_and_unlock(p, wq, uth, setup_flags);
}

/**
 * Runs a thread request on a thread
 *
 * - if thread is THREAD_NULL, will find a thread and run the request there.
 *   Otherwise, the thread must be the current thread.
 *
 * - if req is NULL, will find the highest priority request and run that.  If
 *   it is not NULL, it must be a threadreq object in state NEW.  If it can not
 *   be run immediately, it will be enqueued and moved to state QUEUED.
 *
 *   Either way, the thread request object serviced will be moved to state
 *   BINDING and attached to the uthread.
 *
 * Should be called with the workqueue lock held.  Will drop it.
 * Should be called with the base pri not frozen.
 */
__attribute__((noreturn, noinline))
static void
workq_unpark_select_threadreq_or_park_and_unlock(proc_t p, struct workqueue *wq,
    struct uthread *uth, uint32_t setup_flags)
{
	if (uth->uu_workq_flags & UT_WORKQ_EARLY_BOUND) {
		if (uth->uu_workq_flags & UT_WORKQ_NEW) {
			setup_flags |= WQ_SETUP_FIRST_USE;
		}
		uth->uu_workq_flags &= ~(UT_WORKQ_NEW | UT_WORKQ_EARLY_BOUND);
		/*
		 * This pointer is possibly freed and only used for tracing purposes.
		 */
		workq_threadreq_t req = uth->uu_save.uus_workq_park_data.thread_request;
		workq_unlock(wq);
		WQ_TRACE_WQ(TRACE_wq_thread_logical_run | DBG_FUNC_START, wq,
		    VM_KERNEL_ADDRHIDE(req), 0, 0);
		(void)req;

		workq_setup_and_run(p, uth, setup_flags);
		__builtin_unreachable();
	}

	thread_freeze_base_pri(get_machthread(uth));
	workq_select_threadreq_or_park_and_unlock(p, wq, uth, setup_flags);
}

static bool
workq_creator_should_yield(struct workqueue *wq, struct uthread *uth)
{
	thread_qos_t qos = workq_pri_override(uth->uu_workq_pri);

	if (qos >= THREAD_QOS_USER_INTERACTIVE) {
		return false;
	}

	uint32_t snapshot = uth->uu_save.uus_workq_park_data.fulfilled_snapshot;
	if (wq->wq_fulfilled == snapshot) {
		return false;
	}

	uint32_t cnt = 0, conc = wq_max_parallelism[_wq_bucket(qos)];
	if (wq->wq_fulfilled - snapshot > conc) {
		/* we fulfilled more than NCPU requests since being dispatched */
		WQ_TRACE_WQ(TRACE_wq_creator_yield, wq, 1,
		    wq->wq_fulfilled, snapshot);
		return true;
	}

	for (uint8_t i = _wq_bucket(qos); i < WORKQ_NUM_QOS_BUCKETS; i++) {
		cnt += wq->wq_thscheduled_count[i];
	}
	if (conc <= cnt) {
		/* We fulfilled requests and have more than NCPU scheduled threads */
		WQ_TRACE_WQ(TRACE_wq_creator_yield, wq, 2,
		    wq->wq_fulfilled, snapshot);
		return true;
	}

	return false;
}

/**
 * parked thread wakes up
 */
__attribute__((noreturn, noinline))
static void
workq_unpark_continue(void *parameter __unused, wait_result_t wr __unused)
{
	thread_t th = current_thread();
	struct uthread *uth = get_bsdthread_info(th);
	proc_t p = current_proc();
	struct workqueue *wq = proc_get_wqptr_fast(p);

	workq_lock_spin(wq);

	if (wq->wq_creator == uth && workq_creator_should_yield(wq, uth)) {
		/*
		 * If the number of threads we have out are able to keep up with the
		 * demand, then we should avoid sending this creator thread to
		 * userspace.
		 */
		uth->uu_save.uus_workq_park_data.fulfilled_snapshot = wq->wq_fulfilled;
		uth->uu_save.uus_workq_park_data.yields++;
		workq_unlock(wq);
		thread_yield_with_continuation(workq_unpark_continue, NULL);
		__builtin_unreachable();
	}

	if (__probable(uth->uu_workq_flags & UT_WORKQ_RUNNING)) {
		workq_unpark_select_threadreq_or_park_and_unlock(p, wq, uth, WQ_SETUP_NONE);
		__builtin_unreachable();
	}

	if (__probable(wr == THREAD_AWAKENED)) {
		/*
		 * We were set running, but for the purposes of dying.
		 */
		assert(uth->uu_workq_flags & UT_WORKQ_DYING);
		assert((uth->uu_workq_flags & UT_WORKQ_NEW) == 0);
	} else {
		/*
		 * workaround for <rdar://problem/38647347>,
		 * in case we do hit userspace, make sure calling
		 * workq_thread_terminate() does the right thing here,
		 * and if we never call it, that workq_exit() will too because it sees
		 * this thread on the runlist.
		 */
		assert(wr == THREAD_INTERRUPTED);
		wq->wq_thdying_count++;
		uth->uu_workq_flags |= UT_WORKQ_DYING;
	}

	workq_unpark_for_death_and_unlock(p, wq, uth,
	    WORKQ_UNPARK_FOR_DEATH_WAS_IDLE, WQ_SETUP_NONE);
	__builtin_unreachable();
}

__attribute__((noreturn, noinline))
static void
workq_setup_and_run(proc_t p, struct uthread *uth, int setup_flags)
{
	thread_t th = get_machthread(uth);
	vm_map_t vmap = get_task_map(p->task);

	if (setup_flags & WQ_SETUP_CLEAR_VOUCHER) {
		/*
		 * For preemption reasons, we want to reset the voucher as late as
		 * possible, so we do it in two places:
		 *   - Just before parking (i.e. in workq_park_and_unlock())
		 *   - Prior to doing the setup for the next workitem (i.e. here)
		 *
		 * Those two places are sufficient to ensure we always reset it before
		 * it goes back out to user space, but be careful to not break that
		 * guarantee.
		 *
		 * Note that setting the voucher to NULL will not clear the preadoption
		 * thread group on this thread
		 */
		__assert_only kern_return_t kr;
		kr = thread_set_voucher_name(MACH_PORT_NULL);
		assert(kr == KERN_SUCCESS);
	}

	uint32_t upcall_flags = uth->uu_save.uus_workq_park_data.upcall_flags;
	if (!(setup_flags & WQ_SETUP_FIRST_USE)) {
		upcall_flags |= WQ_FLAG_THREAD_REUSE;
	}

	if (uth->uu_workq_flags & UT_WORKQ_OUTSIDE_QOS) {
		/*
		 * For threads that have an outside-of-QoS thread priority, indicate
		 * to userspace that setting QoS should only affect the TSD and not
		 * change QOS in the kernel.
		 */
		upcall_flags |= WQ_FLAG_THREAD_OUTSIDEQOS;
	} else {
		/*
		 * Put the QoS class value into the lower bits of the reuse_thread
		 * register, this is where the thread priority used to be stored
		 * anyway.
		 */
		upcall_flags |= uth->uu_save.uus_workq_park_data.qos |
		    WQ_FLAG_THREAD_PRIO_QOS;
	}

	if (uth->uu_workq_thport == MACH_PORT_NULL) {
		/* convert_thread_to_port_pinned() consumes a reference */
		thread_reference(th);
		/* Convert to immovable/pinned thread port, but port is not pinned yet */
		ipc_port_t port = convert_thread_to_port_pinned(th);
		/* Atomically, pin and copy out the port */
		uth->uu_workq_thport = ipc_port_copyout_send_pinned(port, get_task_ipcspace(p->task));
	}

	/* Thread has been set up to run, arm its next workqueue quantum or disarm
	 * if it is no longer supporting that */
	if (thread_supports_cooperative_workqueue(th)) {
		thread_arm_workqueue_quantum(th);
	} else {
		thread_disarm_workqueue_quantum(th);
	}

	/*
	 * Call out to pthread, this sets up the thread, pulls in kevent structs
	 * onto the stack, sets up the thread state and then returns to userspace.
	 */
	WQ_TRACE_WQ(TRACE_wq_runthread | DBG_FUNC_START,
	    proc_get_wqptr_fast(p), 0, 0, 0);

	if (workq_thread_is_cooperative(uth)) {
		thread_sched_call(th, NULL);
	} else {
		thread_sched_call(th, workq_sched_callback);
	}

	pthread_functions->workq_setup_thread(p, th, vmap, uth->uu_workq_stackaddr,
	    uth->uu_workq_thport, 0, setup_flags, upcall_flags);

	__builtin_unreachable();
}

#pragma mark misc

int
fill_procworkqueue(proc_t p, struct proc_workqueueinfo * pwqinfo)
{
	struct workqueue *wq = proc_get_wqptr(p);
	int error = 0;
	int     activecount;

	if (wq == NULL) {
		return EINVAL;
	}

	/*
	 * This is sometimes called from interrupt context by the kperf sampler.
	 * In that case, it's not safe to spin trying to take the lock since we
	 * might already hold it.  So, we just try-lock it and error out if it's
	 * already held.  Since this is just a debugging aid, and all our callers
	 * are able to handle an error, that's fine.
	 */
	bool locked = workq_lock_try(wq);
	if (!locked) {
		return EBUSY;
	}

	wq_thactive_t act = _wq_thactive(wq);
	activecount = _wq_thactive_aggregate_downto_qos(wq, act,
	    WORKQ_THREAD_QOS_MIN, NULL, NULL);
	if (act & _wq_thactive_offset_for_qos(WORKQ_THREAD_QOS_MANAGER)) {
		activecount++;
	}
	pwqinfo->pwq_nthreads = wq->wq_nthreads;
	pwqinfo->pwq_runthreads = activecount;
	pwqinfo->pwq_blockedthreads = wq->wq_threads_scheduled - activecount;
	pwqinfo->pwq_state = 0;

	if (wq->wq_constrained_threads_scheduled >= wq_max_constrained_threads) {
		pwqinfo->pwq_state |= WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT;
	}

	if (wq->wq_nthreads >= wq_max_threads) {
		pwqinfo->pwq_state |= WQ_EXCEEDED_TOTAL_THREAD_LIMIT;
	}

	workq_unlock(wq);
	return error;
}

boolean_t
workqueue_get_pwq_exceeded(void *v, boolean_t *exceeded_total,
    boolean_t *exceeded_constrained)
{
	proc_t p = v;
	struct proc_workqueueinfo pwqinfo;
	int err;

	assert(p != NULL);
	assert(exceeded_total != NULL);
	assert(exceeded_constrained != NULL);

	err = fill_procworkqueue(p, &pwqinfo);
	if (err) {
		return FALSE;
	}
	if (!(pwqinfo.pwq_state & WQ_FLAGS_AVAILABLE)) {
		return FALSE;
	}

	*exceeded_total = (pwqinfo.pwq_state & WQ_EXCEEDED_TOTAL_THREAD_LIMIT);
	*exceeded_constrained = (pwqinfo.pwq_state & WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT);

	return TRUE;
}

uint32_t
workqueue_get_pwq_state_kdp(void * v)
{
	static_assert((WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT << 17) ==
	    kTaskWqExceededConstrainedThreadLimit);
	static_assert((WQ_EXCEEDED_TOTAL_THREAD_LIMIT << 17) ==
	    kTaskWqExceededTotalThreadLimit);
	static_assert((WQ_FLAGS_AVAILABLE << 17) == kTaskWqFlagsAvailable);
	static_assert((WQ_FLAGS_AVAILABLE | WQ_EXCEEDED_TOTAL_THREAD_LIMIT |
	    WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT) == 0x7);

	if (v == NULL) {
		return 0;
	}

	proc_t p = v;
	struct workqueue *wq = proc_get_wqptr(p);

	if (wq == NULL || workq_lock_is_acquired_kdp(wq)) {
		return 0;
	}

	uint32_t pwq_state = WQ_FLAGS_AVAILABLE;

	if (wq->wq_constrained_threads_scheduled >= wq_max_constrained_threads) {
		pwq_state |= WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT;
	}

	if (wq->wq_nthreads >= wq_max_threads) {
		pwq_state |= WQ_EXCEEDED_TOTAL_THREAD_LIMIT;
	}

	return pwq_state;
}

void
workq_init(void)
{
	clock_interval_to_absolutetime_interval(wq_stalled_window.usecs,
	    NSEC_PER_USEC, &wq_stalled_window.abstime);
	clock_interval_to_absolutetime_interval(wq_reduce_pool_window.usecs,
	    NSEC_PER_USEC, &wq_reduce_pool_window.abstime);
	clock_interval_to_absolutetime_interval(wq_max_timer_interval.usecs,
	    NSEC_PER_USEC, &wq_max_timer_interval.abstime);

	thread_deallocate_daemon_register_queue(&workq_deallocate_queue,
	    workq_deallocate_queue_invoke);
}
