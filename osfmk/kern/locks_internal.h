/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _KERN_LOCKS_INTERNAL_H_
#define _KERN_LOCKS_INTERNAL_H_

#define LOCK_PRIVATE 1
#include <sys/cdefs.h>
#include <stdint.h>
#include <kern/ast.h>
#include <kern/startup.h>
#include <kern/percpu.h>
#include <kern/zalloc.h>
#include <kern/lock_types.h>
#include <kern/lock_group.h>
#include <machine/cpu_number.h>
#include <machine/locks.h>
#include <machine/machine_cpu.h>
#include <os/atomic_private.h>

/*
 * This file shares implementation details for XNU lock implementations.
 * It is not meant to be shared with any other part of the code.
 */

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

__exported_push_hidden

/*!
 * @macro hw_spin_wait_until_n()
 *
 * @brief
 * Abstracts the platform specific way to spin around the value
 * of a memory location until a certain condition is met.
 *
 * @param count         how many times to spin without evaluating progress
 * @param ptr           the pointer to the memory location being observed
 * @param load_var      the variable to store the result of the load into
 * @param cond_expr     the stopping condition (can use @c load_var)
 *
 * @returns
 * - 0 if the loop stopped when the counter expired
 * - cond_expr's return value otherwise
 */
#define hw_spin_wait_until_n(count, ptr, load_var, cond_expr)  ({ \
	typeof((cond_expr)) __cond_result;                                      \
                                                                                \
	for (uint32_t __cond_init = (count), __cond_count = __cond_init;        \
	    __probable(__cond_count-- > 0);) {                                  \
	        __hw_spin_wait_load(ptr, load_var, __cond_result, cond_expr);   \
	        if (__probable(__cond_result)) {                                \
	                break;                                                  \
	        }                                                               \
	}                                                                       \
                                                                                \
	__cond_result;                                                          \
})

/*!
 * @macro hw_spin_wait_until()
 *
 * @brief
 * Conveniency wrapper for hw_spin_wait_until_n() with the typical
 * LOCK_SNOOP_SPINS counter for progress evaluation.
 */
#define hw_spin_wait_until(ptr, load_var, cond_expr) \
	hw_spin_wait_until_n(LOCK_SNOOP_SPINS, ptr, load_var, cond_expr)


#if LOCK_PRETEST
#define lock_cmpxchg_pretestv(p, e, g)  ({ \
	__auto_type __e = (e); \
	__auto_type __v = os_atomic_load(p, relaxed); \
	if (__v != __e) { \
	        *(g) = __v; \
	} \
	__v == __e; \
})
#define lock_cmpxchg_pretest(p, e) \
	(os_atomic_load(p, relaxed) == (e))
#define lock_pretest(...)  ({ __VA_ARGS__ })
#else
#define lock_cmpxchg_pretestv(p, e, g)  1
#define lock_cmpxchg_pretest(p, e)      1
#define lock_pretest(...)               1
#endif

/*!
 * @function lock_cmpxchg
 *
 * @brief
 * Similar to os_atomic_cmpxchg() but with a pretest when LOCK_PRETEST is set.
 */
#define lock_cmpxchg(p, e, v, m)  ({ \
	__auto_type _p = (p);                                                   \
	__auto_type _e = (e);                                                   \
	lock_cmpxchg_pretest(_p, _e) && os_atomic_cmpxchg(_p, _e, v, m);        \
})

/*!
 * @function lock_cmpxchgv
 *
 * @brief
 * Similar to os_atomic_cmpxchgv() but with a pretest when LOCK_PRETEST is set.
 */
#define lock_cmpxchgv(p, e, v, g, m)  ({ \
	__auto_type _p = (p);                                                   \
	__auto_type _e = (e);                                                   \
	lock_cmpxchg_pretestv(_p, _e, g) && os_atomic_cmpxchgv(_p, _e, v, g, m);\
})

#if OS_ATOMIC_HAS_LLSC
#define lock_load_exclusive(p, m)               os_atomic_load_exclusive(p, m)
#define lock_wait_for_event()                   wait_for_event()
#define lock_clear_exclusive()                  os_atomic_clear_exclusive()
#define lock_send_event()                       __builtin_arm_sev()
#define lock_store_exclusive(p, ov, nv, m)      os_atomic_store_exclusive(p, nv, m)
#else
#define lock_load_exclusive(p, m)               os_atomic_load(p, relaxed)
#define lock_wait_for_event()                   cpu_pause()
#define lock_clear_exclusive()                  ((void)0)
#define lock_send_event()                       ((void)0)
#define lock_store_exclusive(p, ov, nv, m)      os_atomic_cmpxchg(p, ov, nv, m)
#endif


/*!
 * @enum lck_type_t
 *
 * @brief
 * A one-byte type tag used in byte 3 of locks to be able to identify them.
 */
__enum_decl(lck_type_t, uint8_t, {
	LCK_TYPE_NONE           = 0x00,
	LCK_TYPE_RW             = 0x11,
	LCK_TYPE_MUTEX          = 0x22,
	LCK_TYPE_RW_LEGACY      = 0x33,
	LCK_TYPE_TICKET         = 0x44,
	LCK_TYPE_GATE           = 0x55,
});

/*!
 * @typedef lck_mcs_id_t
 *
 * @brief
 * The type for an MCS node or head ID.
 *
 * @discussion
 * An MCS ID is the combination of a CPU (in the top 14 bits)
 * and a slot (in the low 2 bits).
 */
typedef uint16_t lck_mcs_id_t;

#define LCK_MCS_ID_NULL         ((lck_mcs_id_t)0x0000)
#define LCK_MCS_ID_INVALID      ((lck_mcs_id_t)0xffff)
#define LCK_MCS_ID_CPU_MASK     ((lck_mcs_id_t)0xfffc)
#define LCK_MCS_ID_CPU_SHIFT    2

/*!
 * @typedef lck_mcs_slot_t
 *
 * @abstract
 * The part of an @c lck_mcs_id_t that denotes the MCS node for a given CPU.
 *
 * @const LCK_MCS_SLOT_HEAD
 * The metadata for the 3 other MCS nodes.
 *
 * @const LCK_MCS_SLOT_SLEEPABLE
 * The node for sleepable locks.
 *
 * @const LCK_MCS_SLOT_SPINNING_0
 * The first node for spinning locks.
 *
 * @const LCK_MCS_SLOT_SPINNING_1
 * The second node for spinning locks (can be used in interrupt context).
 */
__enum_closed_decl(lck_mcs_slot_t, lck_mcs_id_t, {
	LCK_MCS_SLOT_HEAD       = 0,
	LCK_MCS_SLOT_SLEEPABLE  = 1,
	LCK_MCS_SLOT_SPINNING_0 = 2,
	LCK_MCS_SLOT_SPINNING_1 = 3,
});

/*!
 * @typedef lck_abort_slot_t
 *
 * @abstract
 * The type for abort counter slots.
 *
 * @discussion
 * These slots are used in a hash table occupying the free space
 * in the MCS head nodes to count how many nodes are currently aborting.
 */
#if MAX_CPUS > UINT8_MAX
typedef uint16_t                lck_abort_slot_t;
#else
typedef uint8_t                 lck_abort_slot_t;
#endif

#define LCK_MCS_HASH_TOP_SIZE   (1u << (31 - __builtin_clz(MAX_CPUS)))
#define LCK_MCS_HASH_ABORT_SIZE (4 * sizeof(long) / sizeof(lck_abort_slot_t))

/*!
 * @typedef lck_mcs_head_t
 *
 * @brief
 * A per-CPU data structure that manages the state of the MCS nodes.
 *
 * @discussion
 * This data structure serves as meta-data for this core, but also doubles
 * as the backing store for hash-tables of abort counters (to support the
 * @c LCK_MCS_ABORTABLE feature).
 *
 * These hash tables utilize @c LCK_MCS_HASH_TOP_SIZE heads (which will be
 * less than the number of slots for SoCs with a number of cores that isn't
 * a power of 2).
 *
 * @field lmh_free_node
 * A pointer to the first spinning MCS node that is free for ths CPU.
 *
 * @field lmh_abort_hash
 * A hash table of abort counters.
 * @c lck_mcs_abort_slot() is used to determine the proper slot.
 */
typedef struct lck_mcs_head {
	struct lck_mcs_node    *lmh_free_node;
	unsigned long           __lmh_unused[3];

	lck_abort_slot_t        lmh_abort_hash[LCK_MCS_HASH_ABORT_SIZE];
} __attribute__((aligned(64))) * lck_mcs_head_t;


/*!
 * @abstract
 * The current status of the node.
 *
 * @const LCK_MCS_NODE_ABORTED
 * The node has been dequeued from the MCS queue and is fully aborted,
 * the caller will clean up the node and fail to get in the queue
 * (lck_mcs_enqueue() will return NULL).
 *
 * @const LCK_MCS_NODE_WAITING
 * The node is in the MCS queue waiting to be either made ready or aborted.
 *
 * @const LCK_MCS_NODE_READY
 * The node is at the head of the MCS queue.
 */
__enum_closed_decl(lck_mcs_status_t, int16_t, {
	LCK_MCS_NODE_ABORTED    = -1,
	LCK_MCS_NODE_WAITING    = 0,
	LCK_MCS_NODE_READY      = 1,
});

/*!
 * @abstract
 * The mode selected for the MCS node at enqueue time.
 *
 * @const LCK_MCS_SLEEPABLE
 * The node is the @c LCK_MCS_SLOT_SLEEPABLE node.
 * Only one of @c LCK_MCS_SLEEPABLE or @c LCK_MCS_SPINNING can be selected.
 *
 * @const LCK_MCS_SPINNING
 * The node is one of the the @c LCK_MCS_SLOT_SPINNING_* nodes.
 * Only one of @c LCK_MCS_SLEEPABLE or @c LCK_MCS_SPINNING can be selected.
 *
 * @const LCK_MCS_ABORTABLE
 * This MCS node is enqueued in an abortable fashion.  All nodes enqueued
 * on a given MCS queue must specify the same value for this option.
 */
__options_closed_decl(lck_mcs_mode_t, uint16_t, {
	LCK_MCS_SLEEPABLE       = 0x00,
	LCK_MCS_SPINNING        = 0x01,
	LCK_MCS_ABORTABLE       = 0x02,
});

/*!
 * @typedef lck_mcs_node_t
 *
 * @brief
 * The type of per-cpu MCS-like nodes used for various spinning wait queues.
 *
 * @discussion
 * Each CPU has three nodes:
 * - one for sleepable locks (such as kernel mutexes or rwlocks),
 * - two for spinning locks (to handle the case where a spinlock is acquired in
 *   interrupt context and might use this reentrantly).
 *
 * In the mutex case, the nodes are used not as a lock as in traditional MCS,
 * but to order waiters. The head of the queue spins against the lock itself,
 * which allows to release the MCS node once the kernel mutex is acquired.
 *
 * @field lmn_link      The pointer to the lock's MCS tail using this node.
 *
 * @field lmn_next      The next MCS node in the MCS regular queue.
 *
 * @field lmn_status    The MCS node status (ready/waiting/aborted).
 * @field lmn_mode      The selected mode for the MCS node at enqueue time.
 * @field lmn_aborting  The node is asking for an abort
 *                      (LCK_MCS_ABORTABLE modes).
 */
typedef struct lck_mcs_node {
	void                   *lmn_link;

	struct lck_mcs_node    *lmn_next;

	lck_mcs_mode_t          lmn_mode;
	lck_mcs_status_t        lmn_status;
	uint32_t                lmn_aborting;

	/*
	 * __lmn_unused1 is used as a marker up to which the node is zeroed.
	 * Fields after __lmn_unused3 are also always "constant".
	 *
	 * Order of these fields matter.
	 */
	unsigned long           __lmn_unused1;
	unsigned long           __lmn_unused2;
	unsigned long           __lmn_unused3;
	unsigned long           __lmn_unused4;
	unsigned long           __lmn_unused5;
} __attribute__((aligned(64))) * lck_mcs_node_t;

typedef union lck_mcs {
	struct lck_mcs_head     mcs_head;
	struct lck_mcs_node     mcs_node;
} *lck_mcs_t;

/*!
 * @var lck_mcs_array
 *
 * @brief
 * An array of nodes to represent the MCS heads/nodes per CPU.
 *
 * @discussion
 * Indices in that array are lck_mcs_id_t indices,
 * where the slot implies the type (LCK_MCS_SLOT_HEAD is an lck_mcs_head_t,
 * others an lck_mcs_node_t).
 *
 * Note: on Apple Silicon, fabric level cachelines are 128 bytes,
 *       and L1 level 64 bytes. This array as a result tries to isolate
 *       each node on its own 64 byte cacheline but also makes sure that
 *       all 4 nodes for a given CPU occupy disjoint fabric cachelines.
 */
__attribute__((aligned(256)))
extern union lck_mcs lck_mcs_array[MAX_CPUS << LCK_MCS_ID_CPU_SHIFT];


static inline lck_mcs_id_t
lck_mcs_id_make(int cpu, lck_mcs_slot_t slot)
{
	return (lck_mcs_id_t)((cpu << LCK_MCS_ID_CPU_SHIFT) | slot);
}

__pure2
static inline lck_mcs_node_t
lck_mcs_node_after_head(lck_mcs_head_t head, int bit)
{
	union lck_mcs *mcs = __container_of(head, union lck_mcs, mcs_head);

	return &mcs[bit].mcs_node;
}

__pure2
__attribute__((overloadable))
static inline lck_mcs_node_t
lck_mcs_node(lck_mcs_id_t mcs_id)
{
	return &lck_mcs_array[mcs_id].mcs_node;
}

__pure2
__attribute__((overloadable))
static inline lck_mcs_node_t
lck_mcs_node(int cpu, lck_mcs_id_t slot)
{
	return &lck_mcs_array[lck_mcs_id_make(cpu, slot)].mcs_node;
}

__pure2
static inline lck_mcs_head_t
lck_mcs_head(lck_mcs_id_t mcs_id)
{
	return &lck_mcs_array[mcs_id].mcs_head;
}

__pure2
static inline lck_mcs_id_t
lck_mcs_node_id(lck_mcs_node_t node)
{
	return (lck_mcs_id_t)(node - &lck_mcs_array[0].mcs_node);
}

__pure2
static inline lck_mcs_id_t
lck_mcs_head_id(lck_mcs_head_t head)
{
	return (lck_mcs_id_t)(head - &lck_mcs_array[0].mcs_head);
}

static inline lck_mcs_head_t
lck_mcs_head_for_cpu(int cpu)
{
	return &lck_mcs_array[lck_mcs_id_make(cpu, LCK_MCS_SLOT_HEAD)].mcs_head;
}

static inline lck_mcs_head_t
lck_mcs_head_for_node(lck_mcs_node_t node)
{
	static_assert(__alignof(lck_mcs_array) == 256);
	static_assert(sizeof(struct lck_mcs_head) == 64);
	static_assert(sizeof(struct lck_mcs_node) == 64);

	/*
	 * because nodes are always 256 bytes aligned,
	 * this transforms any MCS node into the head for a given CPU
	 */
	return (lck_mcs_head_t)((uintptr_t)node & ~0xfful);
}

/*!
 * @abstract
 * Enqueue the caller onto an MCS queue.
 *
 * @discussion
 * This function will spin until the waiter has become the head of the queue,
 * or until the wait has been aborted (for abortable waits), whichever comes
 * first.
 *
 * @param link          A pointer to the MCS queue.
 * @param mode          The MCS queue waiting mode.
 * @param lock          An opaque value for the higher level synchronization
 *                      primitive that owns this MCS queue.
 * @param pol           A pointer to the wait policy for the synchronization
 *                      primitive.
 *
 * @returns
 * - NULL               The wait was aborted, only happens if LCK_MCS_ABORTABLE
 *                      has been passed as part of the mode flags.
 * - a valid node       The node that has become the head of the MCS queue.
 */
extern lck_mcs_node_t lck_mcs_enqueue(
	lck_mcs_id_t           *link,
	lck_mcs_mode_t          mode,
	void                   *lock,
	hw_spin_policy_t        pol);

/*!
 * @abstract
 * Dequeues a node that was returned by @c lck_mcs_enqueue().
 *
 * @discussion
 * This is a high level helper that will perform the right actions to:
 * - dequeue the node from the MCS tail queue properly,
 * - wake up the next waiter,
 * - free the node.
 *
 * Some clients perform the dequeueing from the MCS queue on their own,
 * @c lck_mcs_cleanup() is what they should call.
 *
 * @param node          A valid node returned by @c lck_mcs_enqueue().
 * @param link          A pointer to the MCS queue.
 * @param mode          The MCS queue waiting mode.
 */
extern void lck_mcs_dequeue(
	lck_mcs_node_t          node, /* consumed */
	lck_mcs_id_t           *link,
	lck_mcs_mode_t          mode);

/*!
 * @abstract
 * Perform the cleanup after the head of the MCS queue has been dequeued
 * by the caller.
 *
 * @param node          A valid node returned by @c lck_mcs_enqueue().
 * @param mode          The MCS queue waiting mode.
 * @param wakeup_next   Whether there is a next node to wakeup.
 */
extern void lck_mcs_cleanup(
	lck_mcs_node_t          node /* consumed */,
	lck_mcs_mode_t          mode,
	bool                    wakeup_next);

/*!
 * @abstract
 * A function to call during spin-waits by lead-spinning locking primitives.
 *
 * @param node          A valid node returned by @c lck_mcs_enqueue().
 * @param link          A pointer to the MCS queue.
 * @param mode          The MCS queue waiting mode.
 * @param slotp         A pointer to storage used to memorize the abort slot
 *                      for this MCS queue. This can be NULL if the queue
 *                      is not using abortable waits.
 */
extern void lck_mcs_spin_step(
	lck_mcs_node_t          node,
	lck_mcs_id_t           *link,
	lck_mcs_mode_t          mode,
	lck_abort_slot_t      **slotp);


typedef struct lck_adaptive_spin_ctx {
	ast_t                  *astp;
	lck_abort_slot_t       *abort_slot;
	uint64_t                start;
	uint64_t                deadline;
	uint32_t                snoops;
	uint16_t                backoff;
	bool                    expired;
} *lck_adaptive_spin_ctx_t;


#define LCK_ADAPTIVE_SPIN_CTX_DECL(name) \
	struct lck_adaptive_spin_ctx name = { }

/*!
 * @abstract
 * Record that adaptive spin is starting.
 *
 * @discussion
 * This function must be called right after preemption has been disabled
 * and before the current thread is commiting to any step toward adaptive spin.
 *
 * This will record the timestamp at which it started.
 *
 * For code doing several sessions of adaptive spin, this must be called each
 * time a new session starts.
 */
static inline void
lck_adaptive_spin_start(lck_adaptive_spin_ctx_t ctx)
{
	ctx->astp     = ast_pending();
	ctx->start    = lock_get_timebase();
}

/*!
 * @abstract
 * Pause during an adaptive spin hot loop.
 *
 * @discussion
 * This function will wait for event if the loop hasn't expired yet,
 * otherwise will just clear the monitor and return immediately.
 */
static inline void
lck_adaptive_spin_wait_for_event(lck_adaptive_spin_ctx_t ctx)
{
	if (__improbable(ctx->expired)) {
		lock_clear_exclusive();
	} else {
		lock_wait_for_event();
	}
}

/*!
 * @abstract
 * Function to call during adaptive spin loops regularly.
 *
 * @discussion
 * This function computes whether adaptive spin should be stopped either
 * because:
 * - the current spin deadline is expired;
 * - the adaptive spin session took too long regardless of the current spin time
 *   (which can happen with interrupt storms);
 * - the scheduler sent an urgent preemption request.
 */
static inline void
lck_adaptive_spin_step(lck_adaptive_spin_ctx_t ctx)
{
	uint64_t now;

	if (__improbable(ctx->expired)) {
		ctx->snoops++;
		return;
	}

	if (os_atomic_load(ctx->astp, relaxed) & AST_URGENT) {
		ctx->expired = true;
		return;
	}

	if (ctx->deadline && ctx->snoops++ < LOCK_SNOOP_SPINS_MCS) {
		return;
	}

	now = lock_get_timebase();
	if (ctx->deadline == 0) {
		uint64_t spin = os_atomic_load(&MutexSpin, relaxed);

		/*
		 * Cap the deadline with how long the waiter was in the queue.
		 */
		ctx->deadline = MIN(now + spin,
		    ctx->start + zpercpu_count() * spin);
	}
	ctx->expired = now > ctx->deadline;
	ctx->snoops  = 0;
}

/*!
 * @abstract
 * Reset the adaptive spin structure between sessions.
 *
 * @discussion
 * This function must be called by code that reuses adaptive spin contexts
 * for several sessions before reuse. @c lck_adaptive_spin_start() must still
 * be called when the next session starts.
 */
static inline void
lck_adaptive_spin_reset(lck_adaptive_spin_ctx_t ctx)
{
	ctx->astp     = 0;
	/* keep ctx->abort_slot */
	ctx->start    = 0;
	ctx->deadline = 0;
	ctx->snoops   = 0;
	/* keep ctx->backoff */
	ctx->expired  = false;
}

__exported_pop

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif /* _KERN_LOCKS_INTERNAL_H_ */
