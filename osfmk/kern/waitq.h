/*
 * Copyright (c) 2014-2021 Apple Computer, Inc. All rights reserved.
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
#ifndef _WAITQ_H_
#define _WAITQ_H_
#ifdef  KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <mach/sync_policy.h>
#include <mach/kern_return.h>           /* for kern_return_t */

#include <kern/kern_types.h>            /* for wait_queue_t */
#include <kern/queue.h>
#include <kern/assert.h>

#include <sys/cdefs.h>

#ifdef XNU_KERNEL_PRIVATE
/* priority queue static asserts fail for __ARM64_ARCH_8_32__ kext builds */
#include <kern/priority_queue.h>
#ifdef MACH_KERNEL_PRIVATE
#include <kern/spl.h>
#include <kern/ticket_lock.h>
#include <kern/circle_queue.h>
#include <kern/mpsc_queue.h>

#include <machine/cpu_number.h>
#include <machine/machine_routines.h> /* machine_timeout_suspended() */
#endif /* MACH_KERNEL_PRIVATE */
#endif /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma GCC visibility push(hidden)

/*!
 * @enum waitq_wakeup_flags_t
 *
 * @const WAITQ_DEFAULT
 * Use the default behavior for wakeup.
 *
 * @const WAITQ_UPDATE_INHERITOR
 * If the wait queue is a turnstile,
 * set its inheritor to the woken up thread,
 * or clear the inheritor if the last thread is woken up.
 *
 #if MACH_KERNEL_PRIVATE
 * @const WAITQ_PROMOTE_PRIORITY (Mach IPC only)
 * Promote the woken up thread(s) with a MINPRI_WAITQ floor,
 * until it calls waitq_clear_promotion_locked().
 *
 * @const WAITQ_UNLOCK (waitq_wakeup64_*_locked only)
 * Unlock the wait queue before any thread_go() is called for woken up threads.
 *
 * @const WAITQ_KEEP_LOCKED (waitq_wakeup64_*_locked only)
 * Keep the wait queue locked for this call.
 *
 * @const WAITQ_HANDOFF (waitq_wakeup64_one, waitq_wakeup64_identify*)
 * Attempt a handoff to the woken up thread.
 #endif
 */
__options_decl(waitq_wakeup_flags_t, uint32_t, {
	WAITQ_WAKEUP_DEFAULT    = 0x0000,
	WAITQ_UPDATE_INHERITOR  = 0x0001,
#if MACH_KERNEL_PRIVATE
	WAITQ_PROMOTE_PRIORITY  = 0x0002,
	WAITQ_UNLOCK            = 0x0004,
	WAITQ_KEEP_LOCKED       = 0x0000,
	WAITQ_HANDOFF           = 0x0008,
#endif /* MACH_KERNEL_PRIVATE */
});

/* Opaque sizes and alignment used for struct verification */
#if __arm__ || __arm64__
	#define WQ_OPAQUE_ALIGN   __BIGGEST_ALIGNMENT__
	#if __arm__
		#define WQ_OPAQUE_SIZE   32
	#else
		#define WQ_OPAQUE_SIZE   40
	#endif
#elif __x86_64__
	#define WQ_OPAQUE_ALIGN   8
	#define WQ_OPAQUE_SIZE   48
#else
	#error Unknown size requirement
#endif

#ifdef __cplusplus
#define __waitq_transparent_union
#else
#define __waitq_transparent_union __attribute__((__transparent_union__))
#endif

/**
 * @typedef waitq_t
 *
 * @brief
 * This is an abstract typedef used to denote waitq APIs that can be called
 * on any kind of wait queue (or wait queue set).
 */
typedef union {
	struct waitq      *wq_q;
	struct waitq_set  *wqs_set;
	struct select_set *wqs_sel;
} __waitq_transparent_union waitq_t;

#if !MACH_KERNEL_PRIVATE

/*
 * The opaque waitq structure is here mostly for AIO and selinfo,
 * but could potentially be used by other BSD subsystems.
 */
struct waitq {
	char opaque[WQ_OPAQUE_SIZE];
} __attribute__((aligned(WQ_OPAQUE_ALIGN)));

#endif /* MACH_KERNEL_PRIVATE */
#ifdef XNU_KERNEL_PRIVATE

/**
 * @typedef waitq_link_t
 *
 * @brief
 * Union that represents any kind of wait queue link.
 *
 * @discussion
 * Unlike @c waitq_t which can be used safely on its own because
 * @c waitq_type() can return which actual wait queue type is pointed at,
 * @c waitq_link_t can't be used without knowing the type of wait queue
 * (or wait queue set) it refers to.
 */
typedef union {
	struct waitq_link_hdr   *wqlh;
	struct waitq_sellink    *wqls;
	struct waitq_link       *wqll;
} __waitq_transparent_union waitq_link_t;

#define WQL_NULL ((waitq_link_t){ .wqlh = NULL })

/**
 * @typedef waitq_link_list_t
 *
 * @brief
 * List of wait queue links (used for cleanup).
 *
 * @discussion
 * This type is engineered so that the way it links elements is equivalent
 * to the "forward" linking of a circle queue.
 */
typedef struct waitq_link_list_entry {
	struct waitq_link_list_entry *next;
} waitq_link_list_t;

/**
 * @enum waitq_type_t
 *
 * @brief
 * List of all possible wait queue (and wait queue set) types.
 *
 * @description
 * (I) mark IRQ safe queues
 * (P) mark queues that prepost to sets
 * (S) mark wait queue sets
 * (keep those together to allow range checks for irq-safe/sets)
 */
__enum_decl(waitq_type_t, uint32_t, {
	WQT_INVALID     = 0x0,  /**< ( ) invalid type, unintialized           */
	WQT_QUEUE       = 0x1,  /**< (I) general wait queue                   */
	WQT_TURNSTILE   = 0x2,  /**< (I) wait queue used in @c turnstile      */
	WQT_PORT        = 0x3,  /**< (P) wait queue used in @c ipc_port_t     */
	WQT_SELECT      = 0x4,  /**< (P) wait queue used in @c selinfo        */
	WQT_PORT_SET    = 0x5,  /**< (S) wait queue set used in @c ipc_pset_t */
	WQT_SELECT_SET  = 0x6,  /**< (S) wait queue set used for @c select()  */
});

#ifdef MACH_KERNEL_PRIVATE
#pragma mark Mach-only types and helpers

/*
 * The waitq needs WAITQ_FLAGS_BITS, which leaves 27 or 59 bits
 * for the eventmask.
 */
#define WAITQ_FLAGS_BITS   5
#define _EVENT_MASK_BITS   (8 * sizeof(waitq_flags_t) - WAITQ_FLAGS_BITS)

#if __arm64__
typedef uint32_t       waitq_flags_t;
#else
typedef unsigned long  waitq_flags_t;
#endif

/* Make sure the port abuse of bits doesn't overflow the evntmask size */
#define WAITQ_FLAGS_OVERFLOWS(...) \
	(sizeof(struct { waitq_flags_t bits : WAITQ_FLAGS_BITS, __VA_ARGS__; }) \
	> sizeof(waitq_flags_t))

#define WAITQ_FLAGS(prefix, ...) \
	struct {                                                               \
	    waitq_type_t prefix##_type:3;                                      \
	    waitq_flags_t                                                      \
	        prefix##_fifo:1,      /* fifo wakeup policy? */                \
	        prefix##_preposted:1  /* queue was preposted */                \
	            - 2 * WAITQ_FLAGS_OVERFLOWS(__VA_ARGS__),                  \
	        __VA_ARGS__;                                                   \
	}

/*
 * _type:
 *     the waitq type (a WQT_* value)
 *
 * _fifo:
 *    whether the wakeup policy is FIFO or LIFO.
 *
 * _preposted:
 *     o WQT_PORT:       the port message queue is not empty
 *     o WQT_SELECT_SET: has the set been preposted to
 *     o others:         unused
 *
 * _eventmask:
 *     o WQT_QUEUE:      (global queues) mask events being waited on
 *     o WQT_PORT:       many bits (see ipc_port_t)
 *     o WQT_PORT_SET:   port_set index in its space
 *     o WQT_SELECT_SET: selset_conflict (is the conflict queue hooked)
 *     o other:          unused
 *
 * _interlock:
 *     The lock of the waitq/waitq_set
 *
 * _queue/_prio_queue/_ts:
 *     o WQT_QUEUE,
 *       WQT_SELECT,
 *       WQT_PORT_SET,
 *       WQT_SELECT_SET: circle queue of waiting threads
 *     o WQT_TURNSTILE:  priority queue of waiting threads
 *     o WQT_PORT:       pointer to the receive turnstile of the port
 *
 * _links/_inheritor/_sellinks:
 *     o WQT_PORT:       linkages to WQT_PORT_SET waitq sets
 *     o WQT_SELECT:     linkages to WQT_SELECT_SET select sets
 *     o WQT_TURNSTILE:  turnstile inheritor
 *     o WQT_PORT_SET:   WQT_PORT linkages that haven't preposted
 *     o other:          unused
 */
#define WAITQ_HDR(prefix, ...) \
	WAITQ_FLAGS(prefix, __VA_ARGS__);                                      \
	hw_lck_ticket_t         prefix##_interlock;                            \
	uint8_t                 prefix##_padding[sizeof(waitq_flags_t) -       \
	                                         sizeof(hw_lck_ticket_t)];     \
	union {                                                                \
	        circle_queue_head_t             prefix##_queue;                \
	        struct priority_queue_sched_max prefix##_prio_queue;           \
	        struct turnstile               *prefix##_ts;                   \
	};                                                                     \
	union {                                                                \
	        circle_queue_head_t             prefix##_links;                \
	        waitq_link_list_t               prefix##_sellinks;             \
	        void                           *prefix##_inheritor;            \
	        struct mpsc_queue_chain         prefix##_defer;                \
	}

/**
 *	@struct waitq
 *
 *	@discussion
 *	This is the definition of the common event wait queue
 *	that the scheduler APIs understand.  It is used
 *	internally by the gerneralized event waiting mechanism
 *	(assert_wait), and also for items that maintain their
 *	own wait queues (such as ports and semaphores).
 *
 *	It is not published to other kernel components.
 *
 *	NOTE:  Hardware locks are used to protect event wait
 *	queues since interrupt code is free to post events to
 *	them.
 */
struct waitq {
	WAITQ_HDR(waitq, waitq_eventmask:_EVENT_MASK_BITS);
} __attribute__((aligned(WQ_OPAQUE_ALIGN)));

/**
 * @struct waitq_set
 *
 * @brief
 * This is the definition of a waitq set used in port-sets.
 *
 * @discussion
 * The wqset_index field is used to stash the pset index for debugging
 * purposes (not the full name as it would truncate).
 */
struct waitq_set {
	WAITQ_HDR(wqset, wqset_index:_EVENT_MASK_BITS);
	circle_queue_head_t wqset_preposts;
};

/**
 * @struct select_set
 *
 * @brief
 * This is the definition of a waitq set used to back the select syscall.
 */
struct select_set {
	WAITQ_HDR(selset, selset_conflict:1);
	uint64_t selset_id;
};

static inline waitq_type_t
waitq_type(waitq_t wq)
{
	return wq.wq_q->waitq_type;
}

static inline bool
waitq_same(waitq_t wq1, waitq_t wq2)
{
	return wq1.wq_q == wq2.wq_q;
}

static inline bool
waitq_is_null(waitq_t wq)
{
	return wq.wq_q == NULL;
}
#define waitq_wait_possible(thread)   waitq_is_null((thread)->waitq)

static inline bool
waitq_preposts(waitq_t wq)
{
	switch (waitq_type(wq)) {
	case WQT_PORT:
	case WQT_SELECT:
		return true;
	default:
		return false;
	}
}

static inline bool
waitq_irq_safe(waitq_t waitq)
{
	switch (waitq_type(waitq)) {
	case WQT_QUEUE:
	case WQT_TURNSTILE:
		return true;
	default:
		return false;
	}
}

static inline bool
waitq_valid(waitq_t waitq)
{
	return waitq.wq_q && waitq.wq_q->waitq_interlock.lck_valid;
}

/*
 * global waitqs
 */
extern struct waitq *_global_eventq(char *event, size_t event_length);
#define global_eventq(event) _global_eventq((char *)&(event), sizeof(event))

#endif  /* MACH_KERNEL_PRIVATE */
#pragma mark locking

/*!
 * @function waitq_lock()
 *
 * @brief
 * Lock a wait queue or wait queue set.
 *
 * @discussion
 * It is the responsibility of the caller to disable
 * interrupts if the queue is IRQ safe.
 */
extern void waitq_lock(waitq_t wq);

/*!
 * @function waitq_unlock()
 *
 * @brief
 * Unlock a wait queue or wait queue set.
 *
 * @discussion
 * It is the responsibility of the caller to reenable
 * interrupts if the queue is IRQ safe.
 */
extern void waitq_unlock(waitq_t wq);

/**
 * @function waitq_is_valid()
 *
 * @brief
 * Returns whether a wait queue or wait queue set has been invalidated.
 */
extern bool waitq_is_valid(waitq_t wq);

#ifdef MACH_KERNEL_PRIVATE

/**
 * @function waitq_invalidate()
 *
 * @brief
 * Invalidate a waitq.
 *
 * @discussion
 * It is the responsibility of the caller to make sure that:
 * - all waiters are woken up
 * - linkages and preposts are cleared (non IRQ Safe waitqs).
 */
extern void waitq_invalidate(waitq_t wq);

/*!
 * @function waitq_held()
 *
 * @brief
 * Returns whether someone is holding the lock of the specified wait queue.
 */
extern bool waitq_held(waitq_t wq) __result_use_check;

/*!
 * @function waitq_lock_allow_invalid()
 *
 * @brief
 * Lock the specified wait queue if it is valid.
 *
 * @discussion
 * This function allows for the backing memory of the specified wait queue
 * to be unmapped.
 *
 * Combining this with the zone allocator @c ZC_SEQUESTER feature
 * (along with @c ZC_ZFREE_CLEARMEM and @c ZC_KASAN_NOQUARANTINE)
 * allows to create clever schemes (See @c ipc_right_lookup_read()).
 */
extern bool waitq_lock_allow_invalid(waitq_t wq) __result_use_check;

/*!
 * @function waitq_lock_reserve()
 *
 * @brief
 * Reserves the lock of the specified wait queue.
 *
 * @discussion
 * Wait queue locks are "ordered" and a reservation in the lock queue
 * can be acquired. This can be used to resolve certain lock inversions
 * without risks for the memory backing the wait queue to disappear.
 *
 * See <kern/ticket_lock.h> for details.
 *
 * @param wq            the specified wait queue
 * @param ticket        a pointer to memory to hold the reservation
 * @returns
 *     - true if the lock was acquired
 *     - false otherwise, and @c waitq_lock_wait() @em must be called
 *       to wait for this ticket.
 */
extern bool waitq_lock_reserve(waitq_t wq, uint32_t *ticket) __result_use_check;

/*!
 * @function waitq_lock_wait()
 *
 * @brief
 * Wait for a ticket acquired with @c waitq_lock_reserve().
 */
extern void waitq_lock_wait(waitq_t wq, uint32_t ticket);

/*!
 * @function waitq_lock_try()
 *
 * @brief
 * Attempts to acquire the lock of the specified wait queue.
 *
 * @discussion
 * Using @c waitq_lock_try() is discouraged as it leads to inefficient
 * algorithms prone to contention.
 *
 * Schemes based on @c waitq_lock_reserve() / @c waitq_lock_wait() is preferred.
 *
 */
extern bool waitq_lock_try(waitq_t wq) __result_use_check;

#endif /* MACH_KERNEL_PRIVATE */
#pragma mark assert_wait / wakeup

/**
 * @function waitq_assert_wait64()
 *
 * @brief
 * Declare a thread's intent to wait on @c waitq for @c wait_event.
 *
 * @discussion
 * @c waitq must be unlocked
 */
extern wait_result_t waitq_assert_wait64(
	waitq_t                 waitq,
	event64_t               wait_event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

/**
 * @function waitq_assert_wait64_leeway()
 *
 * @brief
 * Declare a thread's intent to wait on @c waitq for @c wait_event.
 *
 * @discussion
 * @c waitq must be unlocked
 */
extern wait_result_t waitq_assert_wait64_leeway(
	waitq_t                 waitq,
	event64_t               wait_event,
	wait_interrupt_t        interruptible,
	wait_timeout_urgency_t  urgency,
	uint64_t                deadline,
	uint64_t                leeway);

/**
 * @function waitq_wakeup64_one()
 *
 * @brief
 * Wakeup a single thread from a waitq that's waiting for a given event.
 *
 * @discussion
 * @c waitq must be unlocked
 */
extern kern_return_t waitq_wakeup64_one(
	waitq_t                 waitq,
	event64_t               wake_event,
	wait_result_t           result,
	waitq_wakeup_flags_t    flags);

/**
 * @functiong waitq_wakeup64_all()
 *
 * @brief
 * Wakeup all threads from a waitq that are waiting for a given event.
 *
 * @description
 * This function will set the inheritor of the wait queue
 * to TURNSTILE_INHERITOR_NULL if it is a turnstile wait queue.
 *
 * @c waitq must be unlocked
 */
extern kern_return_t waitq_wakeup64_all(
	waitq_t                 waitq,
	event64_t               wake_event,
	wait_result_t           result,
	waitq_wakeup_flags_t    flags);

/**
 * @function waitq_wakeup64_identify()
 *
 * @brief
 * Wakeup one thread waiting on 'waitq' for 'wake_event'
 *
 * @discussion
 * @c waitq must be unlocked.
 *
 * May temporarily disable and re-enable interrupts
 *
 * @returns
 *     - THREAD_NULL if no thread was waiting
 *     - a reference to a thread that was waiting on @c waitq.
 */
extern thread_t waitq_wakeup64_identify(
	waitq_t                 waitq,
	event64_t               wake_event,
	wait_result_t           result,
	waitq_wakeup_flags_t    flags);

/**
 * @function waitq_wakeup64_thread()
 *
 * @brief
 * Wakeup a specific thread iff it's waiting on @c waitq for @c wake_event.
 *
 * @discussion
 * @c waitq must be unlocked and must be IRQ safe.
 * @c thread must be unlocked
 *
 * May temporarily disable and re-enable interrupts
 */
extern kern_return_t waitq_wakeup64_thread(
	struct waitq           *waitq,
	event64_t               wake_event,
	thread_t                thread,
	wait_result_t           result);

#pragma mark Mach-only assert_wait / wakeup
#ifdef MACH_KERNEL_PRIVATE

/**
 * @function waitq_clear_promotion_locked()
 *
 * @brief
 * Clear a potential thread priority promotion from a waitq wakeup
 * with @c WAITQ_PROMOTE_PRIORITY.
 *
 * @discussion
 * @c waitq must be locked.
 *
 * This must be called on the thread which was woken up
 * with @c TH_SFLAG_WAITQ_PROMOTED.
 */
extern void waitq_clear_promotion_locked(
	waitq_t                 waitq,
	thread_t                thread);

/**
 * @function waitq_pull_thread_locked()
 *
 * @brief
 * Remove @c thread from its current blocking state on @c waitq.
 *
 * @discussion
 * This function is only used by clear_wait_internal in sched_prim.c
 * (which itself is called by the timer wakeup path and clear_wait()).
 *
 * @c thread must is locked (the function might drop and reacquire the lock).
 *
 * @returns
 *     - true if the thread has been pulled successfuly.
 *     - false otherwise, if the thread was no longer waiting on this waitq.
 */
extern bool waitq_pull_thread_locked(
	waitq_t                 waitq,
	thread_t                thread);

/**
 * @function waitq_assert_wait64_locked()
 *
 * @brief
 * Declare a thread's intent to wait on @c waitq for @c wait_event.
 *
 * @discussion
 * @c waitq must be locked.
 *
 * Note that @c waitq might be unlocked and relocked during this call
 * if it is a waitq set.
 */
extern wait_result_t waitq_assert_wait64_locked(
	waitq_t                 waitq,
	event64_t               wait_event,
	wait_interrupt_t        interruptible,
	wait_timeout_urgency_t  urgency,
	uint64_t                deadline,
	uint64_t                leeway,
	thread_t                thread);

/**
 * @function waitq_wakeup64_all_locked()
 *
 * @brief
 * Wakeup all threads waiting on @c waitq for @c wake_event
 *
 * @discussion
 * @c waitq must be locked.
 *
 * May temporarily disable and re-enable interrupts
 * and re-adjust thread priority of each awoken thread.
 */
extern kern_return_t waitq_wakeup64_all_locked(
	waitq_t                 waitq,
	event64_t               wake_event,
	wait_result_t           result,
	waitq_wakeup_flags_t    flags);

/**
 * @function waitq_wakeup64_one_locked()
 *
 * @brief
 * Wakeup one thread waiting on @c waitq for @c wake_event.
 *
 * @discussion
 * @c waitq must be locked.
 *
 * May temporarily disable and re-enable interrupts.
 */
extern kern_return_t waitq_wakeup64_one_locked(
	waitq_t                 waitq,
	event64_t               wake_event,
	wait_result_t           result,
	waitq_wakeup_flags_t    flags);

/**
 * @function waitq_wakeup64_identify_locked()
 *
 * @brief
 * Wakeup one thread waiting on 'waitq' for 'wake_event'
 *
 * @returns
 *     A locked, runnable thread.  If return value is non-NULL,
 *     interrupts have also been disabled, and the caller
 *     must call @c splx(*spl).
 */
extern thread_t waitq_wakeup64_identify_locked(
	waitq_t                 waitq,
	event64_t               wake_event,
	wait_result_t           result,
	waitq_wakeup_flags_t    flags,
	spl_t                  *spl);

/**
 * @function waitq_wakeup64_thread_and_unlock()
 *
 * @brief
 * Wakeup a specific thread iff it's waiting on @c waitq for @c wake_event.
 *
 * @discussion
 * @c waitq must IRQ safe and locked, unlocked on return.
 * @c thread must be unlocked
 */
extern kern_return_t waitq_wakeup64_thread_and_unlock(
	struct waitq           *waitq,
	event64_t               wake_event,
	thread_t                thread,
	wait_result_t           result);

#endif /* MACH_KERNEL_PRIVATE */
#pragma mark waitq links

/*!
 * @function waitq_link_alloc()
 *
 * @brief
 * Allocates a linkage object to be used with a wait queue of the specified type.
 */
extern waitq_link_t waitq_link_alloc(
	waitq_type_t            type);

/*!
 * @function waitq_link_free()
 *
 * @brief
 * Frees a linkage object that was used with a wait queue of the specified type.
 */
extern void waitq_link_free(
	waitq_type_t            type,
	waitq_link_t            link);

/*!
 * @function waitq_link_free_list()
 *
 * @brief
 * Frees a list of linkage object that was used with a wait queue
 * of the specified type.
 */
extern void waitq_link_free_list(
	waitq_type_t            type,
	waitq_link_list_t      *list);

#pragma mark wait queues lifecycle

/*!
 * @function waitq_init()
 *
 * @brief
 * Initializes a wait queue.
 *
 * @discussion
 * @c type must be a valid type.
 */
extern void waitq_init(
	waitq_t                 waitq,
	waitq_type_t            type,
	int                     policy);

/*!
 * @function waitq_deinit()
 *
 * @brief
 * Destroys a wait queue.
 *
 * @discussion
 * @c waitq can't be a select set.
 */
extern void waitq_deinit(
	waitq_t                 waitq);

#pragma mark port wait queues and port set waitq sets
#ifdef MACH_KERNEL_PRIVATE

/**
 * @function waitq_link_locked()
 *
 * @brief
 * Link the specified port wait queue to a specified port set wait queue set.
 *
 * @discussion
 * This function doesn't handle preposting/waking up the set
 * when the wait queue is already preposted.
 *
 * @param waitq         the port wait queue to link, must be locked.
 * @param wqset         the port set wait queue set to link, must be locked.
 * @param link          a pointer to a link allocated with
 *                      @c waitq_link_alloc(WQT_PORT_SET).
 */
extern kern_return_t waitq_link_locked(
	struct waitq           *waitq,
	struct waitq_set       *wqset,
	waitq_link_t           *link);

/**
 * @function waitq_link_prepost_locked()
 *
 * @brief
 * Force a given link to be preposted.
 *
 * @param waitq         the port wait queue to link, must be locked.
 * @param wqset         the port set wait queue set to link, must be locked.
 */
extern kern_return_t waitq_link_prepost_locked(
	struct waitq           *waitq,
	struct waitq_set       *wqset);

/**
 * @function
 * Unlinks the specified port wait queue from a specified port set wait queue set.
 *
 * @param waitq         the port wait queue to unlink, must be locked.
 * @param wqset         the port set wait queue set to link, must be locked.
 * @returns
 *     - @c WQL_NULL if the port wasn't a member of the set.
 *     - a link to consume with @c waitq_link_free() otherwise.
 */
extern waitq_link_t waitq_unlink_locked(
	struct waitq           *waitq,
	struct waitq_set       *wqset);

/**
 * @function waitq_unlink_all_locked()
 *
 * @brief
 * Unlink the specified wait queue from all sets to which it belongs
 *
 * @param waitq         the port wait queue to link, must be locked.
 * @param except_wqset  do not unlink this wqset.
 * @param free_l        a waitq link list to which links to free will be added.
 *                      the caller must call @c waitq_link_free_list() on it.
 */
extern void waitq_unlink_all_locked(
	struct waitq           *waitq,
	struct waitq_set       *except_wqset,
	waitq_link_list_t      *free_l);

/**
 * @function waitq_set_unlink_all_locked()
 *
 * @brief
 * Unlink all wait queues from this set.
 *
 * @discussion
 * The @c wqset lock might be dropped and reacquired during this call.
 *
 * @param wqset         the port-set wait queue set to unlink, must be locked.
 * @param free_l        a waitq link list to which links to free will be added.
 *                      the caller must call @c waitq_link_free_list() on it.
 */
extern void waitq_set_unlink_all_locked(
	struct waitq_set       *wqset,
	waitq_link_list_t      *free_l);

/**
 * @function waitq_set_foreach_member_locked()
 *
 * @brief
 * Iterate all ports members of a port-set wait queue set.
 *
 * @param wqset         the port-set wait queue set to unlink.
 * @param cb            a block called for each port wait queue in the set.
 *                      those wait queues aren't locked (and can't safely
 *                      be because @c wqset is locked the whole time
 *                      and this would constitute a lock inversion).
 */
extern void waitq_set_foreach_member_locked(
	struct waitq_set       *wqset,
	void                  (^cb)(struct waitq *));

__options_decl(wqs_prepost_flags_t, uint32_t, {
	WQS_PREPOST_PEEK = 0x1,
	WQS_PREPOST_LOCK = 0x2,
});

/**
 * @function waitq_set_first_prepost()
 *
 * @brief
 * Return the first preposted wait queue from the list of preposts of this set.
 *
 * @discussion
 * The @c wqset lock might be dropped and reacquired during this call.
 *
 * @param wqset         the port-set wait queue set to unlink, must be locked.
 * @param flags
 *     - if @c WQS_PREPOST_LOCK is set, the returned wait queue is locked
 *     - if @c WQS_PREPOST_PEEK is set, this function assumes that no event
 *       will be dequeued and the prepost list order is unchanged,
 *       else the returned wait queue is put at the end of the prepost list.
 */
struct waitq *waitq_set_first_prepost(
	struct waitq_set       *wqset,
	wqs_prepost_flags_t    flags);

/**
 * @function waitq_clear_prepost_locked()
 *
 * @brief
 * Clear all preposts originating from the specified wait queue.
 *
 * @discussion
 * @c waitq must be locked.
 *
 * This function only lazily marks the waitq as no longer preposting,
 * and doesn't clear the preposts for two reasons:
 * - it avoids some lock contention by not acquiring the set locks,
 * - it allows for ports that keep receiving messages to keep their slot
 *   in the prepost queue of sets, which improves fairness.
 *
 * Sets it is a member of will discover this when a thread
 * tries to receive through it.
 */
extern void waitq_clear_prepost_locked(
	struct waitq           *waitq);

/**
 * @function ipc_pset_prepost()
 *
 * @brief
 * Upcall from the waitq code to prepost to the kevent subsystem.
 *
 * @discussion
 * Called with the pset and waitq locks held.
 * (in ipc_pset.c).
 */
extern void ipc_pset_prepost(
	struct waitq_set       *wqset,
	struct waitq           *waitq);

#endif /* MACH_KERNEL_PRIVATE */
#pragma mark select wait queues and select port set waitq sets

extern struct waitq select_conflict_queue;

/*!
 * @function select_set_alloc()
 *
 * @brief
 * Allocates a select wait queue set.
 *
 * @discussion
 * select sets assume that they are only manipulated
 * from the context of the thread they belong to.
 */
extern struct select_set *select_set_alloc(void);

/*!
 * @function select_set_free()
 *
 * @brief
 * Frees a select set allocated with @c select_set_alloc().
 */
extern void select_set_free(
	struct select_set      *selset);

/*!
 * @function select_set_link()
 *
 * @brief
 * Links a select wait queue into a select wait queue set.
 *
 * @param waitq       a wait queue of type @c WQT_SELECT.
 * @param selset      a select set
 * @param linkp       a pointer to a linkage allocated
 *                    with @c waitq_link_alloc(WQT_SELECT_SET),
 *                    which gets niled out if the linkage is used.
 */
extern void select_set_link(
	struct waitq           *waitq,
	struct select_set      *selset,
	waitq_link_t           *linkp);

/*!
 * @function select_set_reset()
 *
 * @brief
 * Resets a select set to prepare it for reuse.
 *
 * @discussion
 * This operation is lazy and will not unlink select wait queues
 * from the select set.
 */
extern void select_set_reset(
	struct select_set      *selset);

/*!
 * @function select_waitq_wakeup_and_deinit()
 *
 * @brief
 * Combined wakeup, unlink, and deinit under a single lock hold for select().
 *
 * @discussion
 * @c waitq must be a @c WQT_SELECT queue.
 */
extern void select_waitq_wakeup_and_deinit(
	struct waitq           *waitq,
	event64_t               wake_event,
	wait_result_t           result);

#endif /* XNU_KERNEL_PRIVATE */

#pragma GCC visibility pop

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* KERNEL_PRIVATE */
#endif  /* _WAITQ_H_ */
