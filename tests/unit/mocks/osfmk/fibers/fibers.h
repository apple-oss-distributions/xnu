/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#pragma once

#include "mocks/std_safe.h"
#include "mocks/osfmk/unit_test_utils.h"

#define FIBERS_DEFAULT_STACK_SIZE 1048576 // 8mb
#define FIBERS_INTERNAL_YIELD_PROB 4 // switch on internal yield points 1/4 of the times
#define FIBERS_DEFAULT_YIELD_PROB 256

/* Configuration variables */
extern int fibers_log_level; // see FIBERS_LOG and the levels FIBERS_LOG_*
extern bool fibers_debug; // Mostly used to collect backtraces at fibers events points. The slowdown is huge.
extern int fibers_abort_on_error; // By default do not stop execution at errors, set to not 0 to abort.
extern uint64_t fibers_may_yield_probability; // FIBERS_DEFAULT_YIELD_PROB by default

#define FIBERS_LOG_WARN  0
#define FIBERS_LOG_INFO  1
#define FIBERS_LOG_DEBUG 2
#define FIBERS_LOG_TRACE 3
#define FIBERS_LOG(level, msg, ...) do {                                                                                                \
	    if (fibers_log_level >= (level)) {                                                                                              \
	        raw_printf("fibers log(%d): current=%d cpu=%u: " msg "\n", (level), (fibers_current ? fibers_current->id : -1 ), fibers_multicpu.executing_cpu, ##__VA_ARGS__);   \
	        if (fibers_debug) print_current_backtrace();                                                                                \
	    }                                                                                                                               \
	} while (0)

typedef struct fiber *fiber_t;

typedef uint32_t fiber_yield_reason_t;

#define FIBERS_YIELD_REASON_ORDER_PRE_SHIFT   (16)
#define FIBERS_YIELD_REASON_ORDER_PRE         (0 << FIBERS_YIELD_REASON_ORDER_PRE_SHIFT)
#define FIBERS_YIELD_REASON_ORDER_POST        (1 << FIBERS_YIELD_REASON_ORDER_PRE_SHIFT)
#define FIBERS_YIELD_REASON_ORDER(x)          ((x) & (1 << FIBERS_YIELD_REASON_ORDER_PRE_SHIFT))

#define FIBERS_YIELD_REASON_ERROR_SHIFT       (17)
#define FIBERS_YIELD_REASON_ERROR             (1 << FIBERS_YIELD_REASON_ERROR_SHIFT)
#define FIBERS_YIELD_REASON_ERROR_IF(x)       ((x) ? FIBERS_YIELD_REASON_ERROR : 0)
#define FIBERS_YIELD_REASON_IS_ERROR(x)       (!!((x) & FIBERS_YIELD_REASON_ERROR))

#define FIBERS_YIELD_REASON_MUTEX_SHIFT       (18)
#define FIBERS_YIELD_REASON_MUTEX_LOCK        (0 << FIBERS_YIELD_REASON_MUTEX_SHIFT)
#define FIBERS_YIELD_REASON_MUTEX_UNLOCK      (1 << FIBERS_YIELD_REASON_MUTEX_SHIFT)
#define FIBERS_YIELD_REASON_MUTEX_DESTROY     (2 << FIBERS_YIELD_REASON_MUTEX_SHIFT)
#define FIBERS_YIELD_REASON_MUTEX_STATE(x)    ((x) & (3 << FIBERS_YIELD_REASON_MUTEX_SHIFT))

#define FIBERS_YIELD_REASON_MEMOP_SHIFT       FIBERS_YIELD_REASON_MUTEX_SHIFT
#define FIBERS_YIELD_REASON_MEMOP_LOAD        FIBERS_YIELD_REASON_MUTEX_LOCK
#define FIBERS_YIELD_REASON_MEMOP_STORE       FIBERS_YIELD_REASON_MUTEX_UNLOCK
#define FIBERS_YIELD_REASON_MEMOP_STATE(x)    FIBERS_YIELD_REASON_MUTEX_STATE(x)

#define FIBERS_YIELD_REASON_CATEGORY(x)       ((x) & 0xffff)
#define FIBERS_YIELD_REASON_UNKNOWN              0
#define FIBERS_YIELD_REASON_MUTEX                1
#define FIBERS_YIELD_REASON_PREEMPTION_CONTROL   2
#define FIBERS_YIELD_REASON_PREEMPTION_TRIGGER   3
#define FIBERS_YIELD_REASON_BLOCKED              4
#define FIBERS_YIELD_REASON_WAKEUP               5
#define FIBERS_YIELD_REASON_CREATE               6
#define FIBERS_YIELD_REASON_JOIN                 7

#define FIBERS_YIELD_REASON_PREEMPTION_WILL_ENABLE (FIBERS_YIELD_REASON_PREEMPTION_CONTROL |   \
	                                            FIBERS_YIELD_REASON_MUTEX_UNLOCK | \
	                                            FIBERS_YIELD_REASON_ORDER_PRE)

#define FIBERS_YIELD_REASON_PREEMPTION_DID_ENABLE  (FIBERS_YIELD_REASON_PREEMPTION_CONTROL |   \
	                                            FIBERS_YIELD_REASON_MUTEX_UNLOCK | \
	                                            FIBERS_YIELD_REASON_ORDER_POST)

#define FIBERS_YIELD_REASON_PREEMPTION_WILL_DISABLE (FIBERS_YIELD_REASON_PREEMPTION_CONTROL | \
	                                             FIBERS_YIELD_REASON_MUTEX_LOCK | \
	                                             FIBERS_YIELD_REASON_ORDER_PRE)

#define FIBERS_YIELD_REASON_PREEMPTION_DID_DISABLE  (FIBERS_YIELD_REASON_PREEMPTION_CONTROL | \
	                                             FIBERS_YIELD_REASON_MUTEX_LOCK | \
	                                             FIBERS_YIELD_REASON_ORDER_POST)

#define FIBERS_YIELD_REASON_MUTEX_WILL_LOCK      (FIBERS_YIELD_REASON_MUTEX |      \
	                                          FIBERS_YIELD_REASON_MUTEX_LOCK | \
	                                          FIBERS_YIELD_REASON_ORDER_PRE)

#define FIBERS_YIELD_REASON_MUTEX_DID_LOCK       (FIBERS_YIELD_REASON_MUTEX |      \
	                                          FIBERS_YIELD_REASON_MUTEX_LOCK | \
	                                          FIBERS_YIELD_REASON_ORDER_POST)

#define FIBERS_YIELD_REASON_MUTEX_TRY_LOCK_FAIL  (FIBERS_YIELD_REASON_MUTEX_DID_LOCK | \
	                                          FIBERS_YIELD_REASON_ERROR)

#define FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK    (FIBERS_YIELD_REASON_MUTEX |        \
	                                          FIBERS_YIELD_REASON_MUTEX_UNLOCK | \
	                                          FIBERS_YIELD_REASON_ORDER_PRE)

#define FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK     (FIBERS_YIELD_REASON_MUTEX |        \
	                                          FIBERS_YIELD_REASON_MUTEX_UNLOCK | \
	                                          FIBERS_YIELD_REASON_ORDER_POST)

#define FIBERS_YIELD_REASON_TRIGGER_LOAD     (FIBERS_YIELD_REASON_PREEMPTION_TRIGGER | \
	                                          FIBERS_YIELD_REASON_MEMOP_LOAD)

#define FIBERS_YIELD_REASON_TRIGGER_STORE     (FIBERS_YIELD_REASON_PREEMPTION_TRIGGER | \
	                                          FIBERS_YIELD_REASON_MEMOP_STORE)

extern fiber_t fibers_current;
extern struct fibers_queue fibers_run_queue;
extern struct fibers_queue fibers_existing_queue;

struct fibers_cpu_state {
	unsigned int cpu_id;
	unsigned int preemption_disabled_count;
	bool interrupts_disabled;
	fiber_t current_fiber;
};

struct fibers_multicpu {
	unsigned int cpu_count;
	struct fibers_cpu_state *cpus;
	unsigned int executing_cpu;
};

#define FIBERS_NO_CPU (unsigned int)(-1)

extern struct fibers_multicpu fibers_multicpu;

extern void fibers_multicpu_init(void);
extern void fibers_multicpu_reset(void);

extern void fibers_set_assigned_cpu(fiber_t fiber, unsigned int cpu_id);
extern unsigned int fibers_get_assigned_cpu(fiber_t fiber);
extern unsigned int fibers_get_executing_cpu(void);

extern void fibers_print_cpu_state(void);

// Exposed for fuzzer reset between iterations
extern int fibers_last_forged_id;
extern void fibers_reset_state(void);

#define FIBERS_ASSERT(expr, msg, ...) do {                                                                                                  \
	    if (!(expr)) {                                                                                                                      \
	        raw_printf("fibers failure: current=%d expr=" #expr ": " msg "\n", (fibers_current ? fibers_current->id : -1 ), ##__VA_ARGS__); \
	        if (fibers_debug) print_current_backtrace();                                                                                    \
	        if (fibers_abort_on_error) abort();                                                                                             \
	    }                                                                                                                                   \
	} while (0)

struct fibers_scheduler_t {
	void (*fibers_choose_next)(void *arg, int state);
	bool (*fibers_should_yield)(void *arg, uint64_t probability, fiber_yield_reason_t reason);
};

extern void fibers_scheduler_get(struct fibers_scheduler_t **scheduler, void **context);
extern void fibers_scheduler_set(struct fibers_scheduler_t *scheduler, void *context);

extern struct fibers_scheduler_t *fibers_scheduler;
extern void *fibers_scheduler_context;

struct fiber {
	int id; /* unique fiber id assigned at creation */
	int state; /* current state */
#define FIBER_RUN  0x1
#define FIBER_STOP 0x2
#define FIBER_WAIT 0x4
#define FIBER_JOIN 0x8
#define FIBER_DEAD 0x10

	int may_yield_disabled;
	int disable_race_checker;

	fiber_t joining; /* waiting for this fiber if FIBER_JOIN */
	fiber_t joiner; /* signal this fiber on termination */
	fiber_t next; /* next fiber on the same queue (run or wait queue) */
	fiber_t next_existing; /* next fiber in the list of existing fibers */

	void* (*start_routine)(void*); /* start routine function pointer */
	void *ret_value; /* return value upon exit */
	jmp_buf env; /* buf to jump when run */
	const void *stack_bottom; /* stack bottom addr, 16 bytes aligned */
	size_t stack_size;

	void *extra; /* per-fiber extra data */
	void (*extra_cleanup_routine)(void*);

	unsigned int assigned_cpu; /* CPU this fiber runs on */
	unsigned int preemption_count; /* number of times preemption has been disabled */

#ifdef __BUILDING_WITH_ASAN__
	void *sanitizer_fake_stack; /* set by asan to track fake stack switches */
	const void *switch_stack; /* stack addr, 16 bytes aligned */
#endif
#ifdef __BUILDING_WITH_TSAN__
	void *tsan_fiber;
#endif
};

static void
fibers_checker_atomic_begin(void)
{
	fibers_current->disable_race_checker++;
}

static void
fibers_checker_atomic_end(void)
{
	fibers_current->disable_race_checker--;
}

struct fibers_queue {
	fiber_t top;
	size_t count;
};

static inline void
fibers_queue_push(struct fibers_queue *queue, fiber_t fiber)
{
	FIBERS_ASSERT(fiber->next == NULL, "fibers_queue_push: already on another queue");
	fiber->next = queue->top;
	queue->top = fiber;
	queue->count++;
}

static inline fiber_t
fibers_queue_pop(struct fibers_queue *queue, size_t index)
{
	FIBERS_ASSERT(queue->count > 0, "fibers_queue_pop: empty queue");
	FIBERS_ASSERT(queue->count > index, "fibers_queue_pop: invalid index");
	fiber_t *iter = &queue->top;
	while (*iter != NULL) {
		if (index == 0) {
			fiber_t fiber = *iter;
			*iter = fiber->next;
			fiber->next = NULL;
			queue->count--;
			return fiber;
		}
		index--;
		iter = &(*iter)->next;
	}
	FIBERS_ASSERT(false, "fibers_queue_pop: unreachable");
	return NULL;
}

static inline fiber_t
fibers_queue_peek(struct fibers_queue *queue)
{
	for (fiber_t *iter = &queue->top;
	    *iter != NULL;
	    iter = &(*iter)->next) {
		if ((*iter)->next == NULL) {
			return *iter;
		}
	}
	return NULL;
}

static inline bool
fibers_queue_contains(struct fibers_queue *queue, fiber_t fiber)
{
	fiber_t iter = queue->top;
	while (iter != NULL) {
		if (iter == fiber) {
			return true;
		}
		iter = iter->next;
	}
	return false;
}

static inline bool
fibers_queue_remove(struct fibers_queue *queue, fiber_t fiber)
{
	fiber_t *iter = &queue->top;
	while (*iter != NULL) {
		if (*iter == fiber) {
			*iter = fiber->next;
			fiber->next = NULL;
			queue->count--;
			return true;
		}
		iter = &(*iter)->next;
	}
	return false;
}

static inline fiber_t
fibers_queue_remove_by_id(struct fibers_queue *queue, int fiber_id)
{
	fiber_t *iter = &queue->top;
	while (*iter != NULL) {
		if ((*iter)->id == fiber_id) {
			fiber_t fiber = *iter;
			*iter = fiber->next;
			fiber->next = NULL;
			queue->count--;
			return fiber;
		}
		iter = &(*iter)->next;
	}
	return NULL;
}

static inline size_t
fibers_queue_count(struct fibers_queue *queue)
{
	fiber_t iter = queue->top;
	size_t count = 0;
	while (iter != NULL) {
		count++;
		iter = iter->next;
	}
	return count;
}

static inline void
fibers_existing_push(fiber_t fiber)
{
	FIBERS_ASSERT(fiber->next_existing == NULL, "fibers_existing_push: already on existing queue");
	fiber->next_existing = fibers_existing_queue.top;
	fibers_existing_queue.top = fiber;
	fibers_existing_queue.count++;
}

static inline bool
fibers_existing_remove(fiber_t fiber)
{
	fiber_t *iter = &fibers_existing_queue.top;
	while (*iter != NULL) {
		if (*iter == fiber) {
			*iter = fiber->next_existing;
			fiber->next_existing = NULL;
			fibers_existing_queue.count--;
			return true;
		}
		iter = &(*iter)->next_existing;
	}
	return false;
}

// Create, exit and join are similar to pthread.
// Detaching is not supported at the moment.
extern fiber_t fibers_create(size_t stack_size, void *(*start_routine)(void*), void *arg);
extern void fibers_exit(void *ret_value);
extern void *fibers_join(fiber_t target);

extern void fibers_switch_to(fiber_t target, int state);
extern void fibers_switch_to_by_id(int target_id, int state);
extern void fibers_switch_top(int state);
extern void fibers_switch_random(int state);
extern void fibers_switch_helper(fiber_t target, int state);
extern void fibers_choose_next(int state);

// Force a context switch
extern void fibers_yield(void);
// Force a context switch to a specific fiber (must be ready to be scheduled)
extern void fibers_yield_to(int fiber_id);
// Context switch with fibers_may_yield_probability
extern bool fibers_may_yield(void);
// Context switch with a default priority for infrastructure
extern bool fibers_may_yield_internal();
// Context switch with a default priority for infrastructure and explicit reason
extern bool fibers_may_yield_internal_with_reason(fiber_yield_reason_t reason);
// Context switch with custom probability
extern bool fibers_may_yield_with_prob(uint64_t probability);
// Context switch with fibers_may_yield_probability and an explicit reason
extern bool fibers_may_yield_with_reason(fiber_yield_reason_t reason);
// Context switch with custom probability and explicit reason
extern bool fibers_may_yield_with_prob_and_reason(uint64_t probability, fiber_yield_reason_t reason);
