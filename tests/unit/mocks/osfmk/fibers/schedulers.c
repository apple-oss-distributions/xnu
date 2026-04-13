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

#include "schedulers.h"
#include "fibers.h"
#include "random.h"
#include "mocks/osfmk/unit_test_fuzz.h"


static inline bool
fibers_cpu_is_schedulable(unsigned int cpu_id)
{
	struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[cpu_id];

	// if no fiber is holding the CPU, it's free to use
	if (cpu->current_fiber == NULL) {
		return true;
	}


	return !cpu->interrupts_disabled && cpu->preemption_disabled_count == 0;
}

// This assumes fibers_cpu_is_schedulable(cpu_id) is true
static inline bool
fibers_can_schedule_fiber_on_cpu(fiber_t fiber, unsigned int cpu_id)
{
	struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[cpu_id];

	if (fiber->assigned_cpu == FIBERS_NO_CPU) {
		return true;
	}
	if (fiber->preemption_count == 0 && fibers_multicpu.cpus[fiber->assigned_cpu].interrupts_disabled == false) {
		return true;
	}
	if (cpu->current_fiber == fiber) {
		FIBERS_ASSERT(fiber->assigned_cpu == cpu_id, "Assigned CPU mistmatch (%u vs %u)", fiber->assigned_cpu, cpu_id);
		return true;
	}
	return false;
}

/*
 * Default scheduler:
 * 1. Choose a random CPU
 * 2. If preemption disabled: run thread already assigned to that CPU
 * 3. If preemption enabled: run random thread from those assigned to CPUs with preemption enabled
 */
static void
fibers_default_choose_next_multicpu(int state)
{
	struct fibers_queue *queue = &fibers_run_queue;
	unsigned int cpu_count = fibers_multicpu.cpu_count;

	if (queue->count == 0) {
		fibers_print_cpu_state();
		FIBERS_ASSERT(false, "No runnable fibers");
		return;
	}

	unsigned int target_cpu = random_below(cpu_count);
	struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[target_cpu];

	if (!fibers_cpu_is_schedulable(target_cpu)) {
		// CPU locked: must run thread already assigned to this CPU
		fiber_t candidate = cpu->current_fiber;
		if (candidate) {
			FIBERS_ASSERT(candidate->assigned_cpu == target_cpu, "Assigned CPU mismatch (%u vs %u)", candidate->assigned_cpu, target_cpu);
			bool removed = fibers_queue_remove(queue, candidate);
			if (removed) {
				fibers_switch_helper(candidate, state);
				return;
			}
		}
		// no thread assigned to this CPU or the thread not in run queue, try another CPU
		for (unsigned int i = 1; i < cpu_count; i++) {
			unsigned int alt_cpu = (target_cpu + i) % cpu_count;
			struct fibers_cpu_state *alt = &fibers_multicpu.cpus[alt_cpu];

			if (!fibers_cpu_is_schedulable(alt_cpu)) {
				// CPU locked: try the thread assigned to this CPU
				fiber_t candidate = alt->current_fiber;
				if (candidate) {
					FIBERS_ASSERT(candidate->assigned_cpu == alt_cpu, "Assigned CPU mismatch (%u vs %u)", candidate->assigned_cpu, alt_cpu);
					bool removed = fibers_queue_remove(queue, candidate);
					if (removed) {
						fibers_switch_helper(candidate, state);
						return;
					}
				}
			} else {
				// CPU is schedulable
				target_cpu = alt_cpu;
				cpu = alt;
				goto preemption_enabled;
			}
		}

		fibers_print_cpu_state();
		FIBERS_ASSERT(false, "Deadlock, not a single CPU can be scheduled");
		return;
	}

preemption_enabled:
	;
	// pick random thread, reassign to target CPU only if it can migrate
	size_t index = random_below(queue->count);
	fiber_t next = fibers_queue_pop(queue, index);

	// check if can be migrated to the target CPU, if not will run on its assigned CPU
	if (fibers_can_schedule_fiber_on_cpu(next, target_cpu)) {
		fibers_set_assigned_cpu(next, target_cpu);
	}

	// fibers_switch_helper() will update CPU state
	fibers_switch_helper(next, state);
	return;
}

static void
fibers_default_choose_next(__unused void *arg, int state)
{
	if (fibers_multicpu.cpu_count > 1) {
		fibers_default_choose_next_multicpu(state);
	} else {
		// single-CPU: random selection
		fiber_t target = fibers_queue_pop(&fibers_run_queue, random_below(fibers_run_queue.count));
		fibers_set_assigned_cpu(target, 0);
		fibers_switch_helper(target, state);
	}
}

static bool
fibers_default_should_yield(__unused void *arg, uint64_t probability,
    __unused fiber_yield_reason_t reason)
{
	// single-CPU: no yield if interrupts or preemption disabled
	if (fibers_multicpu.cpu_count == 1) {
		struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[0];
		if (cpu->interrupts_disabled || cpu->preemption_disabled_count > 0) {
			return false;
		}
	}
	return probability && random_below(probability) == 0;
}

struct fibers_scheduler_t fibers_default_scheduler = {
	.fibers_choose_next = &fibers_default_choose_next,
	.fibers_should_yield = &fibers_default_should_yield
};

struct fuzzing_scheduler_context {
	fuzzed_data_provider_t fdp;
	int countdown;
};

static void
fibers_fuzzing_scheduler_choose_next_multicpu(
	struct fuzzing_scheduler_context *context, int state)
{
	struct fibers_queue *queue = &fibers_run_queue;
	unsigned int cpu_count = fibers_multicpu.cpu_count;

	if (queue->count == 0) {
		fibers_print_cpu_state();
		FIBERS_ASSERT(false, "No runnable fibers");
		return;
	}

	unsigned int target_cpu;
	if (context->fdp.remaining_bytes > 0) {
		target_cpu = fuzzed_data_provider_consume_integral_in_range(
			&context->fdp, 0, cpu_count - 1);
	} else {
		target_cpu = random_below(cpu_count);
	}
	struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[target_cpu];

	if (!fibers_cpu_is_schedulable(target_cpu)) {
		// CPU locked: must run thread already assigned to this CPU
		fiber_t candidate = cpu->current_fiber;
		if (candidate) {
			FIBERS_ASSERT(candidate->assigned_cpu == target_cpu, "Assigned CPU mismatch (%u vs %u)", candidate->assigned_cpu, target_cpu);
			bool removed = fibers_queue_remove(queue, candidate);
			if (removed) {
				fibers_switch_helper(candidate, state);
				return;
			}
		}
		// no thread assigned to this CPU or the thread not in run queue, try another CPU
		for (unsigned int i = 1; i < cpu_count; i++) {
			unsigned int alt_cpu = (target_cpu + i) % cpu_count;
			struct fibers_cpu_state *alt = &fibers_multicpu.cpus[alt_cpu];

			if (!fibers_cpu_is_schedulable(alt_cpu)) {
				// CPU locked: try the thread assigned to this CPU
				fiber_t candidate = alt->current_fiber;
				if (candidate) {
					FIBERS_ASSERT(candidate->assigned_cpu == alt_cpu, "Assigned CPU mismatch (%u vs %u)", candidate->assigned_cpu, alt_cpu);
					bool removed = fibers_queue_remove(queue, candidate);
					if (removed) {
						fibers_switch_helper(candidate, state);
						return;
					}
				}
			} else {
				// CPU is schedulable
				target_cpu = alt_cpu;
				cpu = alt;
				goto preemption_enabled_fuzz;
			}
		}

		fibers_print_cpu_state();
		FIBERS_ASSERT(false, "Deadlock, not a single CPU can be scheduled");
		return;
	}

preemption_enabled_fuzz:
	;
	// pick random thread, reassign to target CPU only if it can migrate
	size_t index;
	if (context->fdp.remaining_bytes > 0) {
		index = fuzzed_data_provider_consume_integral_in_range(
			&context->fdp, 0, queue->count - 1);
	} else {
		index = queue->count - 1;
	}
	fiber_t next = fibers_queue_pop(queue, index);

	// check if can be migrated to the target CPU, if not will run on its assigned CPU
	if (fibers_can_schedule_fiber_on_cpu(next, target_cpu)) {
		fibers_set_assigned_cpu(next, target_cpu);
	}

	// fibers_switch_helper() will update CPU state
	fibers_switch_helper(next, state);
	return;
}

static void
fibers_fuzzing_scheduler_choose_next(__unused void *ctx, int state)
{
	struct fuzzing_scheduler_context *context = ctx;

	if (fibers_multicpu.cpu_count > 1) {
		fibers_fuzzing_scheduler_choose_next_multicpu(context, state);
	} else {
		// single-CPU: fuzzing selection
		fiber_t target;
		if (context->fdp.remaining_bytes > 0) {
			target = fibers_queue_pop(&fibers_run_queue, fuzzed_data_provider_consume_integral_in_range(&context->fdp, 0, fibers_run_queue.count - 1));
		} else {
			target = fibers_queue_pop(&fibers_run_queue, fibers_run_queue.count - 1);
		}
		fibers_set_assigned_cpu(target, 0);
		fibers_switch_helper(target, state);
	}
}

static bool
fibers_fuzzing_scheduler_should_yield(void *ctx, uint64_t probability, __unused fiber_yield_reason_t reason)
{
	struct fuzzing_scheduler_context *context = ctx;
	if (probability == 0) {
		return false;
	}

	// single-CPU: no yield if interrupts or preemption disabled
	if (fibers_multicpu.cpu_count == 1) {
		struct fibers_cpu_state *cpu = &fibers_multicpu.cpus[0];
		if (cpu->interrupts_disabled || cpu->preemption_disabled_count > 0) {
			return false;
		}
	}

	if (context->countdown > 0) {
		context->countdown--;
		return false;
	}
	if (context->fdp.remaining_bytes > 0) {
		context->countdown = (int)fuzzed_data_provider_consume_integral_in_range(&context->fdp, 0, probability - 1);
	} else {
		context->countdown = probability / 2;
	}
	return true;
}

struct fibers_scheduler_t fibers_fuzzing_scheduler = {
	.fibers_choose_next = &fibers_fuzzing_scheduler_choose_next,
	.fibers_should_yield = &fibers_fuzzing_scheduler_should_yield
};

struct fuzzing_scheduler_context fibers_fuzzing_scheduler_context;

void
fibers_fuzzing_scheduler_setup(const uint8_t *data, size_t size)
{
	fuzzed_data_provider_init(&fibers_fuzzing_scheduler_context.fdp, data, size);
	fibers_fuzzing_scheduler_context.countdown = 0;

	fibers_scheduler_set(&fibers_fuzzing_scheduler, &fibers_fuzzing_scheduler_context);
}

void
fibers_fuzzing_scheduler_cleanup(void)
{
	fibers_fuzzing_scheduler_context.fdp.data_ptr = NULL;
	fibers_fuzzing_scheduler_context.fdp.remaining_bytes = 0;
}
