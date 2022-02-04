/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1999,2000 Jonathan Lemon <jlemon@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/sys/sys/eventvar.h,v 1.1.2.2 2000/07/18 21:49:12 jlemon Exp $
 */

#ifndef _SYS_EVENTVAR_H_
#define _SYS_EVENTVAR_H_

#include <sys/event.h>
#include <sys/select.h>
#include <kern/kern_types.h>
#include <kern/waitq.h>

#if defined(XNU_KERNEL_PRIVATE)

typedef int (*kevent_callback_t)(struct kevent_qos_s *, struct kevent_ctx_s *);

#include <stdint.h>
#include <kern/locks.h>
#include <mach/thread_policy.h>
#include <pthread/workqueue_internal.h>
#include <os/refcnt.h>

/*
 * Lock ordering:
 *
 * The kqueue locking order can follow a few different patterns:
 *
 * Standard file-based kqueues (from above):
 *     proc fd lock -> kq lock -> kq-waitq-set lock -> thread lock
 *
 * WorkQ/WorkLoop kqueues (from above):
 *     proc fd lock -> kq lock -> workq lock -> thread lock
 *
 * Whenever kqueues interact with source locks, it drops all of its own
 * locks in exchange for a use-reference on the knote used to synchronize
 * with the source code. When those sources post events from below, they
 * have the following lock hierarchy.
 *
 * Standard file-based kqueues (from below):
 *     XXX lock -> kq lock -> kq-waitq-set lock -> thread lock
 *
 * WorkQ/WorkLoop kqueues (from below):
 *     XXX lock -> kq lock -> workq lock -> thread lock
 */

#define KQEXTENT        256             /* linear growth by this amount */

struct knote_lock_ctx {
	struct knote               *knlc_knote;
	thread_t                    knlc_thread;
	uintptr_t                   knlc_waiters;
	LIST_ENTRY(knote_lock_ctx)  knlc_link;
#if DEBUG || DEVELOPMENT
#define KNOTE_LOCK_CTX_UNLOCKED 0
#define KNOTE_LOCK_CTX_LOCKED   1
#define KNOTE_LOCK_CTX_WAITING  2
	int knlc_state;
#endif
};
LIST_HEAD(knote_locks, knote_lock_ctx);

#if DEBUG || DEVELOPMENT
/*
 * KNOTE_LOCK_CTX(name) is a convenience macro to define a knote lock context on
 * the stack named `name`. In development kernels, it uses tricks to make sure
 * not locks was still held when exiting the C-scope that contains this context.
 */
static inline void
knote_lock_ctx_chk(struct knote_lock_ctx *knlc)
{
	/* evil hackery to make sure no one forgets to unlock */
	assert(knlc->knlc_state == KNOTE_LOCK_CTX_UNLOCKED);
}
#define KNOTE_LOCK_CTX(n) \
	struct knote_lock_ctx n __attribute__((cleanup(knote_lock_ctx_chk))); \
	n.knlc_state = KNOTE_LOCK_CTX_UNLOCKED
#else
#define KNOTE_LOCK_CTX(n) \
	struct knote_lock_ctx n
#endif


__options_decl(kq_state_t, uint16_t, {
	KQ_SLEEP          = 0x0002, /* thread is waiting for events */
	KQ_PROCWAIT       = 0x0004, /* thread waiting for processing */
	KQ_KEV32          = 0x0008, /* kq is used with 32-bit events */
	KQ_KEV64          = 0x0010, /* kq is used with 64-bit events */
	KQ_KEV_QOS        = 0x0020, /* kq events carry QoS info */
	KQ_WORKQ          = 0x0040, /* KQ is bound to process workq */
	KQ_WORKLOOP       = 0x0080, /* KQ is part of a workloop */
	KQ_PROCESSING     = 0x0100, /* KQ is being processed */
	KQ_DRAIN          = 0x0200, /* kq is draining */
	KQ_DYNAMIC        = 0x0800, /* kqueue is dynamically managed */
	KQ_R2K_ARMED      = 0x1000, /* ast notification armed */
	KQ_HAS_TURNSTILE  = 0x2000, /* this kqueue has a turnstile */
});

/*
 * kqueue - common core definition of a kqueue
 *
 *          No real structures are allocated of this type. They are
 *          either kqfile objects or kqworkq objects - each of which is
 *          derived from this definition.
 */
struct kqueue {
	lck_spin_t          kq_lock;      /* kqueue lock */
	kq_state_t          kq_state;     /* state of the kq */
	uint16_t            kq_level;     /* nesting level of the kqfile */
	uint32_t            kq_count;     /* number of queued events */
	struct proc        *kq_p;         /* process containing kqueue */
	struct knote_locks  kq_knlocks;   /* list of knote locks held */
};

/*
 * kqfile - definition of a typical kqueue opened as a file descriptor
 *          via the kqueue() system call.
 *
 *          Adds selinfo support to the base kqueue definition, as these
 *          fds can be fed into select().
 */
struct kqfile {
	struct kqueue       kqf_kqueue;     /* common kqueue core */
	struct kqtailq      kqf_queue;      /* queue of woken up knotes */
	struct kqtailq      kqf_suppressed; /* suppression queue */
	struct selinfo      kqf_sel;        /* parent select/kqueue info */
#define kqf_lock     kqf_kqueue.kq_lock
#define kqf_state    kqf_kqueue.kq_state
#define kqf_level    kqf_kqueue.kq_level
#define kqf_count    kqf_kqueue.kq_count
#define kqf_p        kqf_kqueue.kq_p
};

#define QOS_INDEX_KQFILE   0          /* number of qos levels in a file kq */

/*
 * WorkQ kqueues need to request threads to service the triggered
 * knotes in the queue.  These threads are brought up on a
 * effective-requested-QoS basis. Knotes are segregated based on
 * that value - calculated by computing max(event-QoS, kevent-QoS).
 * Only one servicing thread is requested at a time for all the
 * knotes at a given effective-requested-QoS.
 */

#if !defined(KQWQ_QOS_MANAGER)
#define KQWQ_QOS_MANAGER (THREAD_QOS_LAST)
#endif

#if !defined(KQWQ_NBUCKETS)
#define KQWQ_NBUCKETS    (KQWQ_QOS_MANAGER)
#endif

/*
 * kqworkq - definition of a private kqueue used to coordinate event
 *           handling for pthread work queues.
 *
 *           These have per-qos processing queues and state to coordinate with
 *           the pthread kext to ask for threads at corresponding pthread priority
 *           values.
 */
struct kqworkq {
	struct kqueue       kqwq_kqueue;
	struct kqtailq      kqwq_queue[KQWQ_NBUCKETS];       /* array of queues */
	struct kqtailq      kqwq_suppressed[KQWQ_NBUCKETS];  /* Per-QoS suppression queues */
	workq_threadreq_s   kqwq_request[KQWQ_NBUCKETS];     /* per-QoS request states */
};

#define kqwq_lock        kqwq_kqueue.kq_lock
#define kqwq_state       kqwq_kqueue.kq_state
#define kqwq_waitq_hook  kqwq_kqueue.kq_waitq_hook
#define kqwq_count       kqwq_kqueue.kq_count
#define kqwq_p           kqwq_kqueue.kq_p

/*
 * WorkLoop kqueues need to request a thread to service the triggered
 * knotes in the queue.  The thread is brought up on a
 * effective-requested-QoS basis. Knotes are segregated based on
 * that value. Once a request is made, it cannot be undone.  If
 * events with higher QoS arrive after, they are stored in their
 * own queues and an override applied to the original request based
 * on the delta between the two QoS values.
 */

#if !defined(KQWL_NBUCKETS)
#define KQWL_NBUCKETS    (THREAD_QOS_LAST - 1)
#endif

/*
 * kqworkloop - definition of a private kqueue used to coordinate event
 *              handling for pthread workloops.
 *
 *              Workloops vary from workqs in that only a single thread is ever
 *              requested to service a workloop at a time.  But unlike workqs,
 *              workloops may be "owned" by user-space threads that are
 *              synchronously draining an event off the workloop. In those cases,
 *              any overrides have to be applied to the owner until it relinqueshes
 *              ownership.
 *
 *      NOTE:   "lane" support is TBD.
 */

#if CONFIG_PREADOPT_TG_DEBUG
__options_decl(kqwl_preadopt_tg_op_t, uint8_t, {
	KQWL_PREADOPT_OP_SERVICER_BIND = 0x01,
	KQWL_PREADOPT_OP_SERVICER_REBIND = 0x02,
	KQWL_PREADOPT_OP_SERVICER_UNBIND = 0x3,
	KQWL_PREADOPT_OP_INCOMING_IPC = 0x4,
});
#endif

#if CONFIG_PREADOPT_TG
/*
 * We have this typedef to distinguish when there is a thread_qos_t embedded
 * in the last 3 bits inside the pointer
 */
typedef struct thread_group *thread_group_qos_t;

/* The possible states for kqwl_preadopt_tg:
 *
 * 1) Valid thread group with a QoS masked in the last 3 bits.
 * 2) A known constant value (enumerated below). For these known constant
 * values, no QoS is merged into them.
 *
 * @const KQWL_PREADOPTED_TG_NULL
 *		NULL implies that the kqwl is capable of preadopting a thread group and it
 *              hasn't got such a thread group to preadopt
 * @const KQWL_PREADOPTED_TG_SENTINEL
 *		SENTINEL is set when the kqwl is no longer capable of preadopting a thread
 *              group because it has bound to a servicer - the reference of the thread group
 *              is passed to the servicer
 * @const KQWL_PREADOPTED_TG_PROCESSED
 *		PROCESSED is set when the kqwl's servicer has processed and preadopted the
 *              thread group of the first EVFILT_MACHPORT knote that it is going to deliver
 *              to userspace.
 * @const KQWL_PREADOPTED_TG_NEVER
 *		NEVER is set when the kqwl is not capable of preadopting a thread
 *		group because it is an app
 */

#define KQWL_PREADOPTED_TG_NULL ((struct thread_group *) 0)
#define KQWL_PREADOPTED_TG_SENTINEL ((struct thread_group *) -1)
#define KQWL_PREADOPTED_TG_PROCESSED ((struct thread_group *) -2)
#define KQWL_PREADOPTED_TG_NEVER ((struct thread_group *) -3)

#define KQWL_ENCODE_PREADOPTED_TG_QOS(tg, qos) \
	        (struct thread_group *) ((uintptr_t) tg | (uintptr_t) qos);

#define KQWL_PREADOPT_TG_MASK ~((uint64_t) THREAD_QOS_LAST)
#define KQWL_GET_PREADOPTED_TG(tg) \
	        (struct thread_group *)(((uintptr_t) tg) & KQWL_PREADOPT_TG_MASK)

#define KQWL_PREADOPT_TG_QOS_MASK ((uint64_t) THREAD_QOS_LAST)
#define KQWL_GET_PREADOPTED_TG_QOS(tg) \
	        (thread_qos_t) (((uintptr_t) tg) & KQWL_PREADOPT_TG_QOS_MASK)

#define KQWL_CAN_ADOPT_PREADOPT_TG(tg) \
	        ((tg != KQWL_PREADOPTED_TG_SENTINEL) && \
	        (tg != KQWL_PREADOPTED_TG_NEVER) && \
	        (tg != KQWL_PREADOPTED_TG_PROCESSED))


#define KQWL_HAS_VALID_PREADOPTED_TG(tg) \
	        ((tg != KQWL_PREADOPTED_TG_NULL) && \
	        (tg != KQWL_PREADOPTED_TG_SENTINEL) && \
	        (tg != KQWL_PREADOPTED_TG_NEVER) && \
	        (tg != KQWL_PREADOPTED_TG_PROCESSED) && \
	        (KQWL_GET_PREADOPTED_TG(tg) != NULL))

struct thread_group *
kqr_preadopt_thread_group(workq_threadreq_t req);

_Atomic(struct thread_group *) *
kqr_preadopt_thread_group_addr(workq_threadreq_t req);

#endif


struct kqworkloop {
	struct kqueue       kqwl_kqueue;                  /* queue of events */
	struct kqtailq      kqwl_queue[KQWL_NBUCKETS];    /* array of queues */
	struct kqtailq      kqwl_suppressed;              /* Per-QoS suppression queues */
	workq_threadreq_s   kqwl_request;                 /* thread request state */
#if CONFIG_PREADOPT_TG
	_Atomic thread_group_qos_t      kqwl_preadopt_tg;
#endif

	lck_spin_t          kqwl_statelock;               /* state/debounce lock */
	thread_t            kqwl_owner;                   /* current [sync] owner thread */
	os_ref_atomic_t     kqwl_retains;                 /* retain references */
	thread_qos_t        kqwl_wakeup_qos;              /* QoS/override woke */

#if CONFIG_PREADOPT_TG
	/* The point of the kqwl_preadopt_tg_needs_redrive bit is to be able to
	 * coordinate which thread is going to push information about modifications
	 * to the kqwl_preadopt_thread group on the kqwl, to the workqueue
	 * subsystem. This coordination is needed because the preadoption thread
	 * group is set on the kqwl in the filter call without the kqlock.
	 *
	 * As such, if there is another thread holding the kqlock at this time and
	 * observes the write to the preadoption thread group and the need for a
	 * redrive request, that thread will take the responsibility of pushing that
	 * information down to the workqueue subsystem, thereby ack-ing the request.
	 *
	 * Otherwise, the original thread which modified the kqwl, will do so when
	 * it gets the kqlock.
	 *
	 * Note: Only a 1 single bit is required here but the 2 bytes here were
	 * wasted in packing so I've created a new atomic field for it. Only the
	 * bottom bit is being used, the remaining bits can be reused for other
	 * purposes.
	 */
#define KQWL_PREADOPT_TG_NEEDS_REDRIVE (uint16_t) 0x1
#define KQWL_PREADOPT_TG_CLEAR_REDRIVE (uint16_t) 0x0
	_Atomic uint16_t                        kqwl_preadopt_tg_needs_redrive;
#endif

#if CONFIG_PREADOPT_TG_DEBUG
	/* Keep track of history of events that happened to the kqworkloop wrt to tg preadoption */
#define KQWL_PREADOPT_TG_HISTORY_COUNT 32
#define KQWL_PREADOPT_TG_HISTORY_WRITE_ENTRY(kqwl, ...)  ({\
	        struct kqworkloop *__kqwl = (kqwl); \
	        unsigned int __index = os_atomic_inc_orig(&__kqwl->kqwl_preadopt_tg_history_index, relaxed); \
	                struct kqwl_preadopt_tg _preadopt_tg = { mach_approximate_time(), __VA_ARGS__}; \
	        __kqwl->kqwl_preadopt_tg_history[__index % KQWL_PREADOPT_TG_HISTORY_COUNT] = \
	                        (struct kqwl_preadopt_tg) _preadopt_tg; \
	})

	struct kqwl_preadopt_tg {
		uint64_t time;
		kqwl_preadopt_tg_op_t op;
		struct thread_group *old_preadopt_tg;
		struct thread_group *new_preadopt_tg;
	} kqwl_preadopt_tg_history[KQWL_PREADOPT_TG_HISTORY_COUNT];
	unsigned int kqwl_preadopt_tg_history_index;
#else
#define KQWL_PREADOPT_TG_HISTORY_WRITE_ENTRY(kqwl, ...)
#endif /* CONFIG_PREADOPT_TG_DEBUG */

	struct turnstile   *kqwl_turnstile;               /* turnstile for sync IPC/waiters */
	kqueue_id_t         kqwl_dynamicid;               /* dynamic identity */
	uint64_t            kqwl_params;                  /* additional parameters */
	LIST_ENTRY(kqworkloop) kqwl_hashlink;             /* linkage for search list */
#if CONFIG_WORKLOOP_DEBUG
#define KQWL_HISTORY_COUNT 32
#define KQWL_HISTORY_WRITE_ENTRY(kqwl, ...) ({ \
	        struct kqworkloop *__kqwl = (kqwl); \
	        unsigned int __index = os_atomic_inc_orig(&__kqwl->kqwl_index, relaxed); \
	        __kqwl->kqwl_history[__index % KQWL_HISTORY_COUNT] = \
	                        (struct kqwl_history)__VA_ARGS__; \
	})
	struct kqwl_history {
		thread_t updater;  /* Note: updates can be reordered */
		thread_t servicer;
		thread_t old_owner;
		thread_t new_owner;

		uint64_t kev_ident;
		int16_t  error;
		uint16_t kev_flags;
		uint32_t kev_fflags;

		uint64_t kev_mask;
		uint64_t kev_value;
		uint64_t in_value;
	} kqwl_history[KQWL_HISTORY_COUNT];
	unsigned int kqwl_index;
#endif // CONFIG_WORKLOOP_DEBUG
};
LIST_HEAD(kqwllist, kqworkloop);

typedef union {
	struct kqueue       *kq;
	struct kqworkq      *kqwq;
	struct kqfile       *kqf;
	struct kqworkloop   *kqwl;
} __attribute__((transparent_union)) kqueue_t;

#define kqwl_lock        kqwl_kqueue.kq_lock
#define kqwl_state       kqwl_kqueue.kq_state
#define kqwl_waitq_hook  kqwl_kqueue.kq_waitq_hook
#define kqwl_count       kqwl_kqueue.kq_count
#define kqwl_p           kqwl_kqueue.kq_p

#define KQ_WORKLOOP_RETAINS_MAX UINT32_MAX

extern void kqueue_threadreq_unbind(struct proc *p, workq_threadreq_t);

// called with the kq req held
#define KQUEUE_THREADERQ_BIND_NO_INHERITOR_UPDATE 0x1
extern void kqueue_threadreq_bind(struct proc *p, workq_threadreq_t req,
    thread_t thread, unsigned int flags);

struct turnstile *kqueue_threadreq_get_turnstile(workq_threadreq_t kqr);

// called with the wq lock held
extern void
kqueue_threadreq_bind_prepost(struct proc *p, workq_threadreq_t req,
    struct uthread *uth);

// called with no lock held
extern void kqueue_threadreq_bind_commit(struct proc *p, thread_t thread);

extern void kqueue_threadreq_cancel(struct proc *p, workq_threadreq_t req);

// lock not held as kqwl_params is immutable after creation
extern workq_threadreq_param_t kqueue_threadreq_workloop_param(workq_threadreq_t req);

extern struct kqueue *kqueue_alloc(struct proc *);
extern void kqueue_dealloc(struct kqueue *);
extern void kqworkq_dealloc(struct kqworkq *kqwq);

extern void knotes_dealloc(struct proc *);
extern void kqworkloops_dealloc(struct proc *);

extern int kevent_register(struct kqueue *, struct kevent_qos_s *,
    struct knote **);
extern int kqueue_scan(struct kqueue *, int flags,
    struct kevent_ctx_s *, kevent_callback_t);
extern int kqueue_stat(struct kqueue *, void *, int, proc_t);

extern void kevent_set_workq_quantum_expiry_user_tsd(proc_t p, thread_t t,
    uint64_t flags);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* !_SYS_EVENTVAR_H_ */
