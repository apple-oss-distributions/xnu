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

#define _XOPEN_SOURCE // To use *context deprecated API on OSX
#define BSD_KERNEL_PRIVATE

#include "fibers.h"
#include "random.h"

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/signal.h>

// Forward declarations for CPU context switch helpers from mock_thread.c
// YES. It is ugly, fibers should be self-contained, TBD refactor this code in future versions.
extern void mock_thread_switch_cpu_context_out(void *mock_thread_ptr);
extern void mock_thread_switch_cpu_context_in(void *mock_thread_ptr, unsigned int cpu_id);

extern int ut_cpu_count __attribute__((weak));

#ifdef __BUILDING_WITH_TSAN__
#include <sanitizer/tsan_interface.h>
#endif
#ifdef __BUILDING_WITH_ASAN__
#include <sanitizer/asan_interface.h>
#endif

// from ucontext.h
#include <sys/_types/_ucontext.h>
extern void makecontext(ucontext_t *ucp, void (*func)(), int argc, ...);
extern int swapcontext(ucontext_t *oucp, const ucontext_t *ucp);
extern int getcontext(ucontext_t *ucp);
extern int setcontext(const ucontext_t *ucp);

int fibers_log_level;
bool fibers_debug;
int fibers_abort_on_error = 1;

uint64_t fibers_may_yield_probability = FIBERS_DEFAULT_YIELD_PROB;

struct fiber fibers_main = {
	.id = 0,
	.state = FIBER_RUN,
	.assigned_cpu = 0,
};
int fibers_last_forged_id = 0;

fiber_t fibers_current = &fibers_main; /* currently running */
struct fibers_queue fibers_run_queue; /* ready to be scheduled */
struct fibers_queue fibers_existing_queue = { .top = &fibers_main, .count = 1 }; /* existing fibers */

struct fibers_multicpu fibers_multicpu = {
	.cpu_count = 0,
	.cpus = NULL,
	.executing_cpu = 0,
};

// ensure multi-CPU is initialized with at least 1 CPU
__attribute__((constructor))
void
fibers_multicpu_init(void)
{
	if (fibers_multicpu.cpus != NULL) {
		return;
	}

	if (fibers_multicpu.cpu_count == 0) {
		fibers_multicpu.cpu_count = ut_cpu_count ? ut_cpu_count : 1;
	}

	fibers_multicpu.cpus = calloc(fibers_multicpu.cpu_count, sizeof(struct fibers_cpu_state));
	FIBERS_ASSERT(fibers_multicpu.cpus != NULL, "fibers_multicpu_init: failed to allocate CPU state");

	for (unsigned int i = 0; i < fibers_multicpu.cpu_count; i++) {
		fibers_multicpu.cpus[i].cpu_id = i;
		fibers_multicpu.cpus[i].preemption_disabled_count = 0;
		fibers_multicpu.cpus[i].interrupts_disabled = false;
		fibers_multicpu.cpus[i].current_fiber = NULL;
	}

	fibers_multicpu.cpus[0].current_fiber = &fibers_main;
}

void
fibers_multicpu_reset(void)
{
	if (fibers_multicpu.cpus == NULL) {
		return;
	}

	for (unsigned int i = 0; i < fibers_multicpu.cpu_count; i++) {
		fibers_multicpu.cpus[i].preemption_disabled_count = 0;
		fibers_multicpu.cpus[i].interrupts_disabled = false;
		fibers_multicpu.cpus[i].current_fiber = NULL;
	}

	fibers_multicpu.executing_cpu = 0;

	// Restore main fiber to CPU 0 (same as fibers_multicpu_init)
	fibers_multicpu.cpus[0].current_fiber = &fibers_main;
	fibers_main.assigned_cpu = 0;
}

void
fibers_reset_state(void)
{
	// ensure all fibers have been properly cleaned up
	FIBERS_ASSERT(fibers_current == &fibers_main, "fibers_reset_state: fibers_current is not fibers_main");
	FIBERS_ASSERT(fibers_current->preemption_count == 0, "fibers_reset_state: fibers_current preemption_count is not 0");
	FIBERS_ASSERT(fibers_run_queue.count == 0, "fibers_reset_state: run queue not empty (count=%zu)", fibers_run_queue.count);
	FIBERS_ASSERT(fibers_existing_queue.count == 1, "fibers_reset_state: existing queue should have only fibers_main (count=%zu)", fibers_existing_queue.count);
	FIBERS_ASSERT(fibers_existing_queue.top == &fibers_main, "fibers_reset_state: existing queue top is not fibers_main (top=%d)", fibers_existing_queue.top ? fibers_existing_queue.top->id : -1);

	fibers_last_forged_id = 0;
	fibers_multicpu_reset();
}

// update per-CPU state when fiber enters execution
// syncs: assigned_cpu, current_fiber
static inline void
fibers_update_fiber_cpu_state(fiber_t fiber, unsigned int cpu_id)
{
	struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[cpu_id];

	FIBERS_ASSERT(cpu->preemption_disabled_count == 0 || cpu->current_fiber == fiber,
	    "fibers_update_fiber_cpu_state: cannot update CPU %u (preemption disabled, held by fiber %d)",
	    cpu_id, cpu->current_fiber ? cpu->current_fiber->id : -1);
	FIBERS_ASSERT(cpu->interrupts_disabled == false || cpu->current_fiber == fiber,
	    "fibers_update_fiber_cpu_state: cannot update CPU %u (interrupts disabled, held by fiber %d)",
	    cpu_id, cpu->current_fiber ? cpu->current_fiber->id : -1);

	fiber->assigned_cpu = cpu_id;
	cpu->current_fiber = fiber;
}

// clear per-CPU state when fiber releases CPU
static inline void
fibers_clear_cpu_state(unsigned int cpu_id, fiber_t expected_fiber)
{
	struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[cpu_id];

	// if expected_fiber specified, only clear if it matches
	if (expected_fiber != NULL && cpu->current_fiber != expected_fiber) {
		return;
	}

	if (cpu->preemption_disabled_count == 0 && cpu->interrupts_disabled == false) {
		cpu->current_fiber = NULL;
		expected_fiber->assigned_cpu = FIBERS_NO_CPU;
	}
}

void
fibers_set_assigned_cpu(fiber_t fiber, unsigned int cpu_id)
{
	FIBERS_ASSERT(fiber != NULL, "fibers_set_assigned_cpu: NULL fiber");
	FIBERS_ASSERT(cpu_id < fibers_multicpu.cpu_count,
	    "fibers_set_assigned_cpu: CPU ID %u out of range (max %u)",
	    cpu_id, fibers_multicpu.cpu_count - 1);

	unsigned int old_cpu = fiber->assigned_cpu;
	FIBERS_ASSERT(old_cpu == cpu_id || fiber->preemption_count == 0, "fibers_set_assigned_cpu: can't migrate CPU if preemption is disabled");

	// if migrating to a different CPU, clear from old CPU's current_fiber and reset state
	if (old_cpu != cpu_id && old_cpu != FIBERS_NO_CPU) {
		FIBERS_LOG(FIBERS_LOG_TRACE, "migrating %d from cpu %u to %u", fiber->id, old_cpu, cpu_id);
		fibers_clear_cpu_state(old_cpu, fiber);
	}

	fiber->assigned_cpu = cpu_id;
}

unsigned int
fibers_get_assigned_cpu(fiber_t fiber)
{
	return fiber ? fiber->assigned_cpu : 0;
}

unsigned int
fibers_get_executing_cpu(void)
{
	return fibers_multicpu.executing_cpu;
}

void
fibers_print_cpu_state(void)
{
	raw_printf("=== Multi-CPU State ===\n");
	raw_printf("Total CPUs: %u\n", fibers_multicpu.cpu_count);
	raw_printf("Executing CPU: %u\n", fibers_multicpu.executing_cpu);
	raw_printf("\n");

	for (unsigned int i = 0; i < fibers_multicpu.cpu_count; i++) {
		struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[i];
		raw_printf("CPU %u:\n", cpu->cpu_id);

		if (cpu->current_fiber) {
			raw_printf("  Current fiber: %d (state=%d)\n",
			    cpu->current_fiber->id,
			    cpu->current_fiber->state);
		} else {
			raw_printf("  Current fiber: (none)\n");
		}

		raw_printf("  Preemption: %s (count=%u)\n",
		    cpu->preemption_disabled_count > 0 ? "DISABLED" : "enabled",
		    cpu->preemption_disabled_count);
		raw_printf("  Interrupts: %s\n",
		    cpu->interrupts_disabled ? "DISABLED" : "enabled");

		if (i == fibers_multicpu.executing_cpu) {
			raw_printf("  [EXECUTING]\n");
		}
		raw_printf("\n");
	}

	raw_printf("Global fibers_current: %d\n",
	    fibers_current ? fibers_current->id : -1);
	raw_printf("Run queue count: %zu\n", fibers_run_queue.count);
	raw_printf("======================\n");
}

extern struct fibers_scheduler_t fibers_default_scheduler;

struct fibers_scheduler_t *fibers_scheduler = &fibers_default_scheduler;
void *fibers_scheduler_context = 0;

void
fibers_scheduler_get(struct fibers_scheduler_t **scheduler, void **context)
{
	*scheduler = fibers_scheduler;
	*context = fibers_scheduler_context;
}

void
fibers_scheduler_set(struct fibers_scheduler_t *scheduler, void *context)
{
	fibers_scheduler = scheduler;
	fibers_scheduler_context = context;
}

struct fibers_create_trampoline_args {
	fiber_t fiber;
	void *start_routine_arg;
	jmp_buf parent_env;
};

static void
fibers_create_trampoline(int arg1, int arg2)
{
	struct fibers_create_trampoline_args *args = (struct fibers_create_trampoline_args *)(((uintptr_t)arg1 << 32) | (uintptr_t)arg2);
	// Copy fiber and arg to the local scope as by the time start_routine is called the parent fibers_create stack may have been deallocated
	fiber_t fiber = args->fiber;
	void *start_routine_arg = args->start_routine_arg;

    #ifdef __BUILDING_WITH_ASAN__
	__sanitizer_finish_switch_fiber(&fiber->sanitizer_fake_stack, &fiber->switch_stack, &fiber->stack_size);
    #endif

	// setjmp/longjmp are faster context switch primitives compared to swapcontext
	if (setjmp(fiber->env) == 0) {
		// The first time the setjmp is called to save the current context in fiber->env
		// we end un in this branch in which we switch back to fibers_create
		// When the fiber will be scheduled for the first time, setjmp(fiber->env) != 0
		// and thus the execution will continue in the other branch that calls args.start_routine
#ifdef __BUILDING_WITH_ASAN__
		__sanitizer_start_switch_fiber(&fibers_current->sanitizer_fake_stack, fibers_current->switch_stack, fibers_current->stack_size);
#endif
#ifdef __BUILDING_WITH_TSAN__
		__tsan_switch_to_fiber(fibers_current->tsan_fiber, 0);
#endif
		longjmp(args->parent_env, 1337);
	}

    #ifdef __BUILDING_WITH_ASAN__
	__sanitizer_finish_switch_fiber(&fiber->sanitizer_fake_stack, &fiber->switch_stack, &fiber->stack_size);
    #endif

	fibers_current = fiber;

	void *ret_value = fiber->start_routine(start_routine_arg);
	fibers_exit(ret_value);
}

fiber_t
fibers_create(size_t stack_size, void* (*start_routine)(void*), void* arg)
{
	if (fibers_current == &fibers_main && fibers_main.stack_bottom == NULL) {
		// fibers_main has no stack_bottom or stack_size, get them here the first time
		void* stackaddr = pthread_get_stackaddr_np(pthread_self());
		size_t stacksize = pthread_get_stacksize_np(pthread_self());
		fibers_main.stack_bottom = stackaddr - stacksize;
		fibers_main.stack_size = stacksize;

#ifdef __BUILDING_WITH_ASAN__
		fibers_main.switch_stack = fibers_main.stack_bottom;
#endif
#ifdef __BUILDING_WITH_TSAN__
		fibers_main.tsan_fiber = __tsan_get_current_fiber();
		__tsan_set_fiber_name(fibers_main.tsan_fiber, "fiber0");
#endif
	}

	void *stack_addr = malloc(stack_size);

	fiber_t fiber = calloc(1, sizeof(struct fiber));
	fiber->id = ++fibers_last_forged_id;
	FIBERS_ASSERT(fibers_last_forged_id != 0, "fibers_create: new fiber id integer overflow");
	fiber->state = FIBER_STOP;
	fiber->start_routine = start_routine;
	fiber->stack_size = stack_size;
	fiber->stack_bottom = stack_addr;
	FIBERS_ASSERT(fiber->stack_bottom, "fibers_create: stack malloc failed");

	if (fibers_multicpu.cpu_count > 1) {
		// do not assign a CPU at creation, wait for the first ctx switch
		fiber->assigned_cpu = FIBERS_NO_CPU;
	} else {
		fiber->assigned_cpu = 0;
	}
#ifdef __BUILDING_WITH_ASAN__
	fiber->switch_stack = stack_addr;
#endif

#ifdef __BUILDING_WITH_TSAN__
	fiber->tsan_fiber = __tsan_create_fiber(0);
	char tsan_fiber_name[32];
	snprintf(tsan_fiber_name, 32, "fiber%d", fiber->id);
	__tsan_set_fiber_name(fiber->tsan_fiber, tsan_fiber_name);
#endif

	ucontext_t tmp_uc;
	ucontext_t child_uc = {0};
	FIBERS_ASSERT(getcontext(&child_uc) == 0, "fibers_create: getcontext");
	child_uc.uc_stack.ss_sp = stack_addr;
	child_uc.uc_stack.ss_size = stack_size;
	child_uc.uc_link = 0;

	struct fibers_create_trampoline_args trampoline_args = {0};
	trampoline_args.fiber = fiber;
	trampoline_args.start_routine_arg = arg;

	int trampoline_args1 = (int)((uintptr_t)&trampoline_args >> 32);
	int trampoline_args2 = (int)((uintptr_t)&trampoline_args);

	makecontext(&child_uc, (void (*)())fibers_create_trampoline, 2, trampoline_args1, trampoline_args2);

	// switch to the trampoline to setup the setjmp env of the fiber on the newly created stack, then switch back
	// setjmp/longjmp are faster context switch primitives, swapcontext will never be used again for this fiber
	// ref. the ThreadSanitizer fibers example in LLVM at compiler-rt/test/tsan/fiber_longjmp.cpp
	if (setjmp(trampoline_args.parent_env) == 0) {
#ifdef __BUILDING_WITH_ASAN__
		__sanitizer_start_switch_fiber(&fiber->sanitizer_fake_stack, fiber->switch_stack, fiber->stack_size);
#endif
#ifdef __BUILDING_WITH_TSAN__
		__tsan_switch_to_fiber(fiber->tsan_fiber, 0);
#endif
		FIBERS_ASSERT(swapcontext(&tmp_uc, &child_uc) == 0, "fibers_create: swapcontext");
	}

#ifdef __BUILDING_WITH_ASAN__
	// fibers_create_trampoline did not change fibers_current
	__sanitizer_finish_switch_fiber(&fibers_current->sanitizer_fake_stack, &fibers_current->switch_stack, &fibers_current->stack_size);
#endif

	fibers_queue_push(&fibers_run_queue, fiber);
	fibers_existing_push(fiber);

	FIBERS_LOG(FIBERS_LOG_INFO, "fiber %d created", fiber->id);

	/* chance to schedule the newly created fiber */
	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_CREATE);
	return fiber;
}

static void
fibers_dispose(fiber_t fiber)
{
	FIBERS_LOG(FIBERS_LOG_DEBUG, "dispose %d", fiber->id);

	fibers_existing_remove(fiber);

#ifdef __BUILDING_WITH_TSAN__
	__tsan_destroy_fiber(fiber->tsan_fiber);
#endif

	if (fiber->extra_cleanup_routine) {
		fiber->extra_cleanup_routine(fiber->extra);
	}

	if (fiber != &fibers_main) {
		free((void*)fiber->stack_bottom);
	}
	free(fiber);
}

void
fibers_exit(void *ret_value)
{
	FIBERS_ASSERT(fibers_current->may_yield_disabled == 0, "fibers_exit: fibers_current->may_yield_disabled is not 0");
	FIBERS_ASSERT(fibers_current->preemption_count == 0, "fibers_exit: preemption_count is not 0");

	fibers_current->ret_value = ret_value;
	if (fibers_current->joiner) {
		FIBERS_LOG(FIBERS_LOG_INFO, "exiting, joined by %d", fibers_current->joiner->id);
		fibers_queue_push(&fibers_run_queue, fibers_current->joiner);
	} else {
		FIBERS_LOG(FIBERS_LOG_INFO, "exiting, no joiner");
	}

	fibers_choose_next(FIBER_DEAD);
	FIBERS_ASSERT(false, "fibers_exit: unreachable");
}

void *
fibers_join(fiber_t target)
{
	FIBERS_ASSERT(fibers_current->may_yield_disabled == 0, "fibers_join: fibers_current->may_yield_disabled is not 0");

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_JOIN | FIBERS_YIELD_REASON_ORDER_PRE);

	FIBERS_LOG(FIBERS_LOG_INFO, "join %d", target->id);
	if (target->state != FIBER_DEAD) {
		FIBERS_ASSERT(target->joiner == NULL, "fibers_join: %d already joined by %d", target->id, target->joiner->id);

		target->joiner = fibers_current;
		fibers_current->joining = target;

		// RANGELOCKINGTODO rdar://150845975 maybe have a queue for fibers in join to output debug info in case of deadlock
		fibers_choose_next(FIBER_JOIN);
	}

	FIBERS_LOG(FIBERS_LOG_INFO, "finish joining %d", target->id);
	FIBERS_ASSERT(target->state == FIBER_DEAD, "fibers_join: not dead");

	void *ret_value = target->ret_value;
	fibers_dispose(target);

	fibers_may_yield_internal_with_reason(FIBERS_YIELD_REASON_JOIN | FIBERS_YIELD_REASON_ORDER_POST);
	return ret_value;
}

void
fibers_switch_helper(fiber_t target, int state)
{
	unsigned int old_cpu = fibers_multicpu.executing_cpu;
	unsigned int new_cpu = target->assigned_cpu;
	bool cpu_changed = (old_cpu != new_cpu);

	// Do not take the fast path when the target is the current fiber but we still have to migrate CPU
	if (target == fibers_current && !cpu_changed) {
		target->state = FIBER_RUN;
		return;
	}
	FIBERS_LOG(FIBERS_LOG_TRACE, "switch to %d, state=%d new_cpu=%u old_cpu=%u", target->id, state, new_cpu, old_cpu);

	fibers_current->state = state;
	fiber_t save = fibers_current;

	if (fibers_multicpu.cpu_count > 1) {
		if (save->extra) {
			mock_thread_switch_cpu_context_out(save->extra);
		}

		fibers_clear_cpu_state(old_cpu, save);

		fibers_multicpu.executing_cpu = new_cpu;

		fibers_update_fiber_cpu_state(target, new_cpu);

		// update per-CPU data pointers before context switch
		if (target->extra) {
			mock_thread_switch_cpu_context_in(target->extra, new_cpu);
		}
	}

	if (setjmp(save->env) == 0) {
#ifdef __BUILDING_WITH_ASAN__
		__sanitizer_start_switch_fiber(&target->sanitizer_fake_stack, target->switch_stack, target->stack_size);
#endif
#ifdef __BUILDING_WITH_TSAN__
		__tsan_switch_to_fiber(target->tsan_fiber, state == FIBER_DEAD ? 0 : __tsan_switch_to_fiber_no_sync);
#endif
		longjmp(target->env, 1337);
	}
#ifdef __BUILDING_WITH_ASAN__
	__sanitizer_finish_switch_fiber(&save->sanitizer_fake_stack, &save->switch_stack, &save->stack_size);
#endif

	fibers_current = save;
	save->state = FIBER_RUN;
}

void
fibers_choose_next(int state)
{
	fibers_scheduler->fibers_choose_next(fibers_scheduler_context, state);
}

void
fibers_switch_to(fiber_t target, int state)
{
	FIBERS_ASSERT(fibers_queue_remove(&fibers_run_queue, target), "fibers_switch_to");
	fibers_switch_helper(target, state);
}

void
fibers_switch_to_by_id(int target_id, int state)
{
	FIBERS_ASSERT(fibers_multicpu.cpu_count <= 1, "fibers_switch_to_by_id can't be used with multi-cpu");
	fiber_t target = fibers_queue_remove_by_id(&fibers_run_queue, target_id);
	FIBERS_ASSERT(target != NULL, "fibers_switch_to_by_id");
	fibers_switch_helper(target, state);
}

void
fibers_switch_top(int state)
{
	fiber_t target = fibers_queue_pop(&fibers_run_queue, 0);
	fibers_switch_helper(target, state);
}

void
fibers_switch_random(int state)
{
	fiber_t target = fibers_queue_pop(&fibers_run_queue, random_below(fibers_run_queue.count));
	fibers_switch_helper(target, state);
}

void
fibers_yield_to(int fiber_id)
{
	fibers_queue_push(&fibers_run_queue, fibers_current);
	fibers_switch_to_by_id(fiber_id, FIBER_STOP);
}

void
fibers_yield(void)
{
	fibers_may_yield_with_prob_and_reason(1, FIBERS_YIELD_REASON_UNKNOWN);
}

bool
fibers_may_yield_internal(void)
{
	return fibers_may_yield_with_prob_and_reason(FIBERS_INTERNAL_YIELD_PROB, FIBERS_YIELD_REASON_UNKNOWN);
}

bool
fibers_may_yield_internal_with_reason(fiber_yield_reason_t reason)
{
	return fibers_may_yield_with_prob_and_reason(FIBERS_INTERNAL_YIELD_PROB, reason);
}

bool
fibers_may_yield(void)
{
	return fibers_may_yield_with_prob(fibers_may_yield_probability);
}

bool
fibers_may_yield_with_prob(uint64_t probability)
{
	return fibers_may_yield_with_prob_and_reason(probability, FIBERS_YIELD_REASON_UNKNOWN);
}

bool
fibers_may_yield_with_reason(fiber_yield_reason_t reason)
{
	return fibers_may_yield_with_prob_and_reason(fibers_may_yield_probability, reason);
}

bool
fibers_may_yield_with_prob_and_reason(uint64_t probability, fiber_yield_reason_t reason)
{
	if (fibers_current->may_yield_disabled || fibers_run_queue.count == 0) {
		return false;
	}

	if (fibers_scheduler->fibers_should_yield(fibers_scheduler_context, probability, reason)) {
		fibers_queue_push(&fibers_run_queue, fibers_current);
		fibers_choose_next(FIBER_STOP);
		return true;
	}

	return false;
}
