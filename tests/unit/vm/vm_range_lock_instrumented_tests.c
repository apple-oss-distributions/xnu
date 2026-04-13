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

//
// Theory of Operation
//
// These tests make use of the fibers integration in the unit-tests
// with a custom scheduler used to deterministically race two
// operations, one victim and one aggressor.  The goal is to quickly
// reproduce races that might take extended periods of time to find
// with fuzzers or existing stress tests.  Threading primitives
// are mocked using fibers and are annotated with a number of yield points
// where the scheduler can decide to run a different task.  The custom
// scheduler sweeps across a number of different schedules trying to
// find vulnerable regions of code.  To limit the complexity of the
// scenario we limit the number of times we switch between the victim
// and aggressor.  This can be adjusted per-test to keep run times low
// for automated testing by locally overriding the
// `n_rules` value.  This value can be overridden by
// passing the `-n` command-line option to allow for deeper testing.
//
// The entry points into the scheduler are `scheduler_should_yield`
// and `scheduler_choose_next`.  Should yield looks at the reason for
// the yield and allows us to return early if it is not interesting.
// For example, if we are waking up fibers waiting on a condition
// variable and find none, we can just ignore this yield entirely.
// `scheduler_choose_next` does the work of deciding which fiber to
// yield based on the given schedule.  If it finds a contradiction,
// for example if we are asked to run a blocked thread, the schedule
// under test is automatically adjusted to account for it until we
// find the next working schedule without having to error out and try
// again.
//
// In a failed scenario the schedule under test will be logged.  If a
// more catastrophic failure occurs and the schedule does not print it
// can be inspected through the `current_schedule` variable in LLDB.
// To reproduce a specific failure you can re-run the tests with the
// `-s` flag which allows you to run just the schedule of instance.
// This will allow you to instantly debug the failing scenario.
//

// Attribute no_sanitize disables SanitizerCoverage instrumentation that is used for memory load/store instrumentation when preemption simulation is enabled (FIBERS_PREEMPTION=1)
#pragma clang attribute push(__attribute__((no_sanitize("coverage"))), apply_to=function)

#include <darwintest.h>

#include <stdint.h>
#include <stdlib.h>

#include "mocks/osfmk/fibers/fibers.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_thread.h"
#include "mocks/osfmk/mock_vm.h"
#include "mocks/osfmk/unit_test_utils.h"

#include <mach/mach_vm.h>
#include <sys/queue.h>

#include <vm/vm_fault_xnu.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_page_internal.h>

#include <vm/vm_test_utils_internal.h>

#define UT_MODULE osfmk
UT_USE_FIBERS(1);

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm_range_lock_instrumented"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

// Standard headers are not allowed here so we're declaring some
// utilities for these tests.

extern unsigned int alarm(unsigned int);
extern void *signal(int sig, void (*func)(int));
#define SIGALRM 14

#pragma mark Test Setup

struct range_locking_entry {
	vm_address_t start;
	vm_address_t end;
};

typedef struct {
	vm_map_offset_t         start;
	vm_map_offset_t         end;
	vm_map_kernel_flags_t   flags;
	vm_prot_t               cur_protection;
	vm_prot_t               max_protection;
} test_entry_t;

void
dump_vm_map(vm_map_t map)
{
	printf("Map: %p %i entries", map, map->hdr.nentries);
	vm_map_entry_t entry = vm_map_first_entry(map);
	while (entry != vm_map_to_entry(map)) {
		if (!entry->is_sub_map) {
			printf("Entry %p:[%llx, %llx) prot = %i object = %p", entry, entry->vme_start, entry->vme_end, entry->protection, VME_OBJECT(entry));
		} else {
			printf("Entry %p:[%llx, %llx) prot = %i submap = %p", entry, entry->vme_start, entry->vme_end, entry->protection, VME_SUBMAP(entry));
		}
		entry = entry->vme_next;
	}
}

static void
verify_test_map(vm_map_t map, test_entry_t *entries, unsigned int n_entries)
{
	__block vm_map_offset_t last_end = 0;
	__block unsigned int entry_count = 0;

	// Confirm that the map still looks like the requested map
	(void)vm_map_entries_foreach(map, ^kern_return_t (void *entry) {
		entry_count++;

		vm_map_entry_t vme = entry;
		T_QUIET; T_ASSERT_GE(vme->vme_start, last_end, "Expecting monotonic entries for these tests");
		last_end = vme->vme_end;

		for (unsigned int i = 0; i < n_entries; i++) {
		        if (vme->vme_start == entries[i].start &&
		        vme->vme_end == entries[i].end) {
		                T_QUIET; T_ASSERT_EQ((bool)vme->vme_permanent, (bool)entries[i].flags.vmf_permanent, "Entry maintained permanent flag");
		                T_QUIET; T_ASSERT_EQ((int)vme->protection, (int)entries[i].cur_protection, "Entry preserved current protection");
		                T_QUIET; T_ASSERT_EQ((int)vme->max_protection, (int)entries[i].max_protection, "Entry preserved max protection");
		                return KERN_SUCCESS;
			}
		}
		T_ASSERT_FAIL("Unknown map entry [0x%llx, 0x%llx)", vme->vme_start, vme->vme_end);
		return KERN_FAILURE;
	});

	T_QUIET; T_ASSERT_EQ(entry_count, n_entries, "Unexpected number of entries");
}

static void
setup_test_map(vm_map_t map, test_entry_t *entries, unsigned int n_entries)
{
	for (unsigned int i = 0; i < n_entries; i++) {
		vm_map_offset_t address = entries[i].start;
		vm_map_offset_t size = entries[i].end - entries[i].start;

		kern_return_t kr = vm_map_enter(map, &address, size, 0, entries[i].flags, VM_OBJECT_NULL, 0, false, entries[i].cur_protection, entries[i].max_protection, 0);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Test map setup");
	}

	verify_test_map(map, entries, n_entries);
}

#pragma mark Custom Scheduler

// This controls the number of times we switch between the victim and
// aggressor threads.
static unsigned int n_rules = 6;

// Print schedules.
static bool verbose = false;

// Timeout for live-locks in seconds.  This is the timeout for a
// single schedule so reaching even 1 second is improbable without a
// full loss of forward progress.
static unsigned int timeout = 5;

// The timeout can be disabled for debugging
static bool disable_timeout = false;

// This structure describes a specific schedule.
typedef struct {
	// Each rule is the identifier of a yield point where we should toggle
	// between the victim and aggressor.
	unsigned int *rules;

	// We monitor if the requested switch rule was invoked or not
	// before the scenario completes.  This will allow us to eliminate
	// schedules that don't have any effect.
	bool *switch_occured;

	// Statistics to print when we're done.
	unsigned int n_schedules_tried;
	unsigned int max_depth;
} schedule_t;

schedule_t *current_schedule __used;

static void
schedule_accumulate_depth(schedule_t *schedule, unsigned int i)
{
	schedule->max_depth = (i > schedule->max_depth) ? i : schedule->max_depth;
}

static void
schedule_initialize(schedule_t *schedule)
{
	schedule->rules = calloc(n_rules, sizeof(schedule->rules[0]));
	schedule->switch_occured = calloc(n_rules, sizeof(schedule->switch_occured[0]));

	schedule->n_schedules_tried = 1;
	for (unsigned int i = 0; i < n_rules; i++) {
		schedule->rules[i] = i;
	}
}

static void
schedule_reset_counters(schedule_t *schedule)
{
	for (unsigned int i = 0; i < n_rules; i++) {
		schedule->switch_occured[i] = false;
	}
}

static void
schedule_next(schedule_t *schedule)
{
	schedule->n_schedules_tried++;

	unsigned int i = 1;
	for (; i < n_rules; i++) {
		if (!schedule->switch_occured[i]) {
			break;
		}
	}

	// Record how deep the last executed switch point was.
	schedule_accumulate_depth(schedule, schedule->rules[i - 1]);

	// We need to move the parent forward.
	schedule->rules[i - 1]++;

	for (unsigned int j = i; j < n_rules; j++) {
		schedule->rules[j] = schedule->rules[j - 1] + 1;
	}
}

// The primary scheduler context.
typedef struct {
	fiber_t victim;
	fiber_t aggressor;

	schedule_t *schedule;

	// The current sync point.  Each sync point is a point when the fibers
	// subsystem asks the scheduler to decide on a new thread to schedule.
	unsigned int current_sync_point;

	// Tracks our progress through the schedule's rules.
	unsigned int current_rule;

	// Keep track of which thread we're supposed to have scheduled now.
	bool aggressor_scheduled;

	// Set once the victim completes so that we can stop tracking if the
	// rules apply correctly after this point.
	bool scenario_done;

	// This enable allows us to delay running the rules of the schedule
	// until we've completed the setup of the target vm_map_t and all
	// threads.
	bool scheduling_enabled;
} scheduler_context_t;


static void
scheduler_choose_next(void *context, int state)
{
	scheduler_context_t *ctx = (scheduler_context_t *)context;

	if (!ctx->scheduling_enabled) {
		// Before scheduling is enabled we just want to keep running
		// the same thread.  If that's not possible it's an error.
		assert(fibers_queue_remove(&fibers_run_queue, fibers_current));
		return;
	}

	bool toggle = false; // `toggle` is true iff a rule is being applied and we could switch threads.

	// Indicates that the schedule is valid.  It might not be valid if
	// the desired thread to run is blocked.
	bool valid_schedule = false;

	// Indicates that a thread other than the victim or aggressor ran.
	// This might be a thread that unblocks the victim if it is
	// waiting.  Other threads are only run if the victim and
	// aggressor are unavailable.  They do not count as failures of
	// the schedule because they are not accounted for in the
	// schedule.
	bool other_thread_scheduled = false;

	fiber_t high_priority; // Our first choice of next thread: victim or aggressor.
	fiber_t low_priority; // Our second choice of next thread: victim or aggressor.

	if (!ctx->scenario_done &&
	    ctx->current_rule < n_rules &&
	    ctx->current_sync_point >= ctx->schedule->rules[ctx->current_rule]) {
		// The current rule applies.  Switch threads.
		toggle = true;
	}

	if (toggle ^ ctx->aggressor_scheduled) {
		high_priority = ctx->aggressor;
		low_priority = ctx->victim;
	} else {
		high_priority = ctx->victim;
		low_priority = ctx->aggressor;
	}

	// Choose the next thread based on priority and which threads are
	// runnable.
	fiber_t next = high_priority;
	if (!fibers_queue_remove(&fibers_run_queue, next)) {
		next = low_priority;
		if (!fibers_queue_remove(&fibers_run_queue, next)) {
			next = fibers_queue_pop(&fibers_run_queue, 0);
			other_thread_scheduled = true;
		}
	} else {
		valid_schedule = true;
	}

	// Update the schedule.
	if (!ctx->scenario_done) {
		if (valid_schedule) {
			// If we scheduled the fiber we wanted we move the sync point.
			ctx->current_sync_point++;

			if (toggle && !ctx->scenario_done) {
				ctx->aggressor_scheduled = !ctx->aggressor_scheduled;
				ctx->schedule->switch_occured[ctx->current_rule++] = true;
			}
		} else if (!other_thread_scheduled) {
			// We didn't get the schedule we wanted we still move the sync point.
			ctx->current_sync_point++;

			// But we also need to push the schedule past the invalid schedule.
			for (unsigned int i = ctx->current_rule; i < n_rules; i++) {
				ctx->schedule->rules[i]++;
			}
		}
	}

	// Perform the actual thread switch.
	fibers_switch_helper(next, state);
}

static bool
scheduler_should_yield(__unused void *context, __unused uint64_t probability, fiber_yield_reason_t reason)
{
	if (FIBERS_YIELD_REASON_IS_ERROR(reason)) {
		// The operation reported was a no-op.  For example: a
		// lock was owned so a try lock failed without
		// changing the lock state.
		return false;
	}

	switch (FIBERS_YIELD_REASON_CATEGORY(reason)) {
	case FIBERS_YIELD_REASON_JOIN:
		return false; // A thread being destroyed is not interesting to us.
	case FIBERS_YIELD_REASON_MUTEX:
		// We will ignore some mutex reasons as they are redundant.
		return reason != FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK &&
		       reason != FIBERS_YIELD_REASON_MUTEX_DID_LOCK;
	case FIBERS_YIELD_REASON_PREEMPTION_CONTROL:
		// We will ignore some preemption reasons as they are redundant
		return reason != FIBERS_YIELD_REASON_PREEMPTION_WILL_ENABLE &&
		       reason != FIBERS_YIELD_REASON_PREEMPTION_DID_DISABLE;
	case FIBERS_YIELD_REASON_PREEMPTION_TRIGGER:
		// We do not support preemption simulation
		return false;
	default:
		return true;
	}
}

static struct fibers_scheduler_t scheduler_methods = {
	.fibers_choose_next = &scheduler_choose_next,
	.fibers_should_yield = &scheduler_should_yield
};

#pragma mark Test Infrastructure

typedef vm_map_t (^scenario_setup_t)();    // Initial setup
typedef void (^aggressor_t)(vm_map_t map); // Aggressor task
typedef kern_return_t (^victim_t)(vm_map_t map);    // Victim task
typedef void (^checker_t)(kern_return_t kr, vm_map_t map); // Results checker

typedef struct {
	aggressor_t aggressor_task;
	vm_map_t map;
} aggressor_trampoline_context_t;

static void*
aggressor_trampoline(void *context)
{
	aggressor_trampoline_context_t *ctx = (aggressor_trampoline_context_t *)context;

	ctx->aggressor_task(ctx->map);

	return NULL;
}


static const size_t one_megabyte = 1024 * 1024;

static char *
range_lock_format_schedule(char *buffer, size_t size, schedule_t *schedule)
{
	char *buffer_ptr = buffer;
	for (unsigned int i = 0; i < n_rules; i++) {
		const char *separator = "";
		if (i > 0) {
			separator = " ";
		}
		int written = snprintf(buffer_ptr, size, "%s%d", separator, schedule->rules[i]);
		if (written > 0) {
			size -= written;
			buffer_ptr += written;
		}
	}
	return buffer;
}

static void
range_lock_run_scenario(scenario_setup_t setup_task,
    victim_t victim_task,
    aggressor_t aggressor_task,
    checker_t checker,
    schedule_t *schedule)
{
	current_schedule = schedule;

	if (verbose) {
		char buffer[256];
		T_LOG("Running schedule: %s", range_lock_format_schedule(buffer, sizeof(buffer), schedule));
	}

	// Schedule the alarm to interrupt us on timeout.
	if (!disable_timeout) {
		alarm(timeout);
	}

	T_SETUPBEGIN;

	// Setup the test map
	vm_map_t map = setup_task();

	// Setup the scheduler
	scheduler_context_t scheduler_context = {
		.victim = fibers_current,
		.schedule = schedule,
		.aggressor_scheduled = false,
		.scheduling_enabled = false
	};

	// Install the scheduler into the fibers infrastructure.
	struct fibers_scheduler_t *old_scheduler;
	void *old_scheduler_context;
	fibers_scheduler_get(&old_scheduler, &old_scheduler_context);
	fibers_scheduler_set(&scheduler_methods, &scheduler_context);

	// Setup the aggressor
	aggressor_trampoline_context_t args = {
		.aggressor_task = aggressor_task,
		.map = map
	};

	scheduler_context.aggressor = fibers_create(one_megabyte /* stack_size */, &aggressor_trampoline, &args);

	T_SETUPEND;

	// Now with setup complete we can start scheduling.
	scheduler_context.scheduling_enabled = true;

	// Give the aggressor a chance to jump the queue.
	fibers_may_yield_internal();

	// Run the victim.
	kern_return_t kr = victim_task(map);

	// Stop tracking schedule changes once the victim is complete.
	scheduler_context.scenario_done = true;

	// Wait for threads to complete
	(void)fibers_join(scheduler_context.aggressor);

	// Remove the timeout because the schedule completed.
	if (!disable_timeout) {
		alarm(0);
	}

	// Run the custom checker.
	checker(kr, map);

	// Clean up resources.
	vm_map_destroy(map);

	// Restore the default scheduler.
	fibers_scheduler_set(old_scheduler, old_scheduler_context);

	current_schedule = NULL;
}

static void
range_lock_run_scenarios(scenario_setup_t setup,
    victim_t victim_task,
    aggressor_t aggressor_task,
    checker_t checker)
{
	schedule_t schedule;
	schedule_initialize(&schedule);

	for (;;) {
		schedule_reset_counters(&schedule);
		range_lock_run_scenario(setup, victim_task, aggressor_task, checker, &schedule);

		if (!schedule.switch_occured[0]) {
			// The aggressor was never scheduled so we're done with all
			// schedules for this scenario.
			T_LOG("%u schedules tried\n", schedule.n_schedules_tried);
			T_LOG("%u maximum sync points found\n", schedule.max_depth);
			break;
		}

		schedule_next(&schedule);
	}
}

static void
range_lock_test_report_failing_schedule()
{
	if (current_schedule) {
		char buffer[256] = {};
		T_LOG("Currently executing schedule: %s",
		    range_lock_format_schedule(buffer,
		    sizeof(buffer),
		    current_schedule));
	}
}


static void
print_help(const char *argv0)
{
	printf("<executable> <test_args> -- [-h] [-d] [-n <n_schedule_switches>] [-s <schedule_point> ...]\n");
	printf("    -d                       Disable timeouts.\n");
	printf("    -n <n_schedule_switches> Change the default number of switch points in a schedule.\n");
	printf("    -s <schedule_point> ...  Runs only the provided schedule.   The schedule points must\n");
	printf("                             be monotonically increasing points at which to schedule\n");
	printf("                             switches.  Copy from failing tests to reproduce failures.\n");

	exit(-1);
}

static void
range_lock_timeout_handler(int sig __unused)
{
	T_ASSERT_FAIL("Timeout reached");
}

static void
range_lock_test_run(int argc,
    char *const *argv,
    scenario_setup_t setup,
    victim_t victim_task,
    aggressor_t aggressor_task,
    checker_t checker)
{
	T_ATEND(&range_lock_test_report_failing_schedule);

	extern int fibers_abort_on_error;
	fibers_abort_on_error = 1;

	bool has_custom_schedule = false;
	unsigned int custom_schedule_size = 0;
	schedule_t custom_schedule = {};

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			print_help(argv[0]);
		}
		if (strcmp(argv[i], "-v") == 0) {
			verbose = true;
		} else if (strcmp(argv[i], "-d") == 0) {
			disable_timeout = true;
		} else if (strcmp(argv[i], "-n") == 0) {
			i++;
			if (argc <= i) {
				T_FAIL("Missing integer argument to '-n'");
				print_help(argv[0]);
			}
			n_rules = strtoul(argv[i], NULL, 10);
			if (!n_rules) {
				T_FAIL("Argument to '-n' must be a positive integer");
				print_help(argv[0]);
			}
			T_LOG("Overriding default scheduler switches: %u", n_rules);
		} else if (strcmp(argv[i], "-s") == 0) {
			schedule_initialize(&custom_schedule);
			has_custom_schedule = true;
			i++;
			for (; i < argc; i++) {
				unsigned long switch_point = strtoul(argv[i], NULL, 10);
				if (!switch_point && errno == EINVAL) {
					i--;
					break;
				}
				assert(custom_schedule_size < n_rules);
				custom_schedule.rules[custom_schedule_size++] = switch_point;
			}
			char buffer[256] = {};
			T_LOG("Running single schedule: %s", range_lock_format_schedule(buffer, sizeof(buffer), &custom_schedule));
		} else {
			T_FAIL("Unknown command-line argument: %s", argv[i]);
			print_help(argv[0]);
		}
	}

	signal(SIGALRM, range_lock_timeout_handler);

	if (has_custom_schedule) {
		assert(custom_schedule_size > 0);

		// Fix up the schedule by filling out the rest of the schedule.
		for (unsigned int n = custom_schedule_size; n < n_rules; n++) {
			custom_schedule.rules[n] =
			    custom_schedule.rules[n - 1] + 1;
		}

		range_lock_run_scenario(setup, victim_task, aggressor_task, checker, &custom_schedule);
	} else {
		range_lock_run_scenarios(setup, victim_task, aggressor_task, checker);
	}
}

#pragma mark Test Cases

T_DECL(empty_aggressor, "Empty Aggressor")
{
	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));
		return map;
	};


	aggressor_t aggressor = ^(vm_map_t map) {
		// Empty aggressor
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, 0x20000, 0x40000, VMRL_EX_STREAM);
		if (kr == KERN_SUCCESS) {
			while (vm_map_range_next_with_error(ctx, &kr)) {
				T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");
			}

			vm_map_range_ex_unlock(ctx, &map);
		}
		return kr;
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The range lock operation is expected to succeed");
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};
		verify_test_map(map, entries, countof(entries));
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);
	T_PASS("Empty Aggressor");
}

T_DECL(simple_delete, "Simple Delete")
{
	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));
		return map;
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		vm_map_remove(map, 0x20000, 0x40000);
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, 0x20000, 0x40000, VMRL_EX_STREAM);
		if (kr == KERN_SUCCESS) {
			while (vm_map_range_next_with_error(ctx, &kr)) {
				T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");
			}

			vm_map_range_ex_unlock(ctx, &map);
		}
		return kr;
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS || kr == KERN_INVALID_ADDRESS, "The range lock operation is expected to succeed unless the delete operation fully gets in front.  kr == %d", kr);
		test_entry_t entries[] = {
		};
		verify_test_map(map, entries, countof(entries));
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Simple Delete");
}

static void
clip_range(vm_map_t map, vm_address_t start, vm_address_t end)
{
	// Exclusively lock the range so that we clip.
	VM_MAP_LOCK_CTX_DECLARE(ctx);
	kern_return_t kr = vm_map_range_ex_lock(ctx, &map, start, end, VMRL_EX_STREAM);
	if (kr == KERN_SUCCESS) {
		while (vm_map_range_next_with_error(ctx, &kr)) {
			T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");
		}

		vm_map_range_ex_unlock(ctx, &map);
	}
}

static void
run_one_clip_test(int argc, char *const *argv, vmrl_sh_flags_t flags)
{
	n_rules = 5;

	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0,
				.end = 0x20000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x20000,
				.end = 0x40000,
				// Change the attributes to keep entries from coalescing
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_no_cache = true),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x60000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));
		return map;
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, 0x30000, 0x50000, flags);
		if (kr == KERN_SUCCESS) {
			vm_map_entry_t entry = NULL;
			while ((entry = vm_map_range_next_with_error(ctx, &kr))) {
				T_QUIET; T_ASSERT_LE(entry->vme_start, 0x50000ull, "Check that the starting address is in bounds");
				T_QUIET; T_ASSERT_GE(entry->vme_end, 0x30000ull, "Check that the ending address is in bounds");
			}
			T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");

			vm_map_range_sh_unlock(ctx, &map);
		}
		return kr;
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		clip_range(map, 0x30000, 0x50000);
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The range lock operation is expected to succeed");
		test_entry_t entries[] = {
			{
				.start = 0x000,
				.end = 0x20000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x20000,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_no_cache = true),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x30000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_no_cache = true),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x50000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_no_cache = true),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x50000,
				.end = 0x60000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};
		verify_test_map(map, entries, countof(entries));
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Clipping");
}

T_DECL(clipping, "Clipping")
{
	T_LOG("Run clip test with streaming");
	run_one_clip_test(argc, argv, VMRL_SH_STREAM);
	T_LOG("Run clip test with atomic");
	run_one_clip_test(argc, argv, VMRL_SH_ATOMIC);
}

T_DECL(deleting, "Deleting")
{
	n_rules = 5;

	const size_t max_locked_entries = 16;
	__block size_t n_locked_entries = 0;
	struct range_locking_entry locked_entries_storage[max_locked_entries] = {0};
	struct range_locking_entry *locked_entries = locked_entries_storage;

	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0,
				.end = 0x20000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x20000,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x30000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x60000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));
		return map;
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		n_locked_entries = 0;
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr = vm_map_range_sh_lock(ctx, &map, 0x20000, 0x60000, VMRL_SH_STREAM);
		if (kr == KERN_SUCCESS) {
			vm_map_entry_t entry = NULL;
			while ((entry = vm_map_range_next_with_error(ctx, &kr))) {
				T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");
				T_QUIET; T_ASSERT_LE(entry->vme_start, 0x60000ull, "Check that the starting address is in bounds");
				T_QUIET; T_ASSERT_GE(entry->vme_end, 0x20000ull, "Check that the ending address is in bounds");
				T_QUIET; T_ASSERT_LT(n_locked_entries, max_locked_entries, "Check for entry accumulation overflow");
				locked_entries[n_locked_entries].start = entry->vme_start;
				locked_entries[n_locked_entries].end = entry->vme_end;
				n_locked_entries++;
			}

			vm_map_range_sh_unlock(ctx, &map);
		}
		return kr;
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		vm_map_remove(map, 0x18000, 0x58000);
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The range lock operation is expected to succeed");
		test_entry_t entries[] = {
			{
				.start = 0x000,
				.end = 0x18000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x58000,
				.end = 0x60000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};
		verify_test_map(map, entries, countof(entries));
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Deleting");
}

static void *
run_block(void *arg)
{
	((void (^)(void))arg)();
	return NULL;
}

T_DECL(clipping_into_kunwire, "Clipping Through KUNWIRE")
{
	n_rules = 4;

	const size_t max_locked_entries = 16;
	__block size_t n_locked_entries = 0;
	struct range_locking_entry locked_entries_storage[max_locked_entries] = {0};
	struct range_locking_entry *locked_entries = locked_entries_storage;

	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x60000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));
		return map;
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		n_locked_entries = 0;
		VM_MAP_LOCK_CTX_DECLARE(ctx);

		__block bool unwire_complete = false;

		vm_map_lock_ctx_set_preflight(ctx, ^kern_return_t (vm_map_lock_ctx_t vctx __unused, vm_map_entry_t vme) {
			if (!unwire_complete && vme->vme_start == 0x20000 && vme->vme_end == 0x30000) {
			        unwire_complete = true;
			        return VMRL_ERR_WAIT_FOR_KUNWIRE;
			}
			return KERN_SUCCESS;
		});

		// Create a low priority unblocker.
		fiber_t unblocker = fibers_create(one_megabyte /* stack size */, &run_block, ^() {
			vm_map_t local_map = map;
			VM_MAP_LOCK_CTX_DECLARE(ctx);
			kern_return_t kr = vm_map_range_ex_lock(ctx, &local_map, 0x20000, 0x60000, VMRL_EX_STREAM);
			T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Unblocker");
			vm_map_entry_t entry;
			while ((entry = vm_map_range_next(ctx))) {
			        vm_entry_wakeup_kunwire_waiters(entry);
			}
			vm_map_range_ex_unlock(ctx, &local_map);
		});

		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, 0x20000, 0x60000, VMRL_EX_STREAM);
		if (kr == KERN_SUCCESS) {
			vm_map_entry_t entry = NULL;
			while ((entry = vm_map_range_next_with_error(ctx, &kr))) {
				T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");
				T_QUIET; T_ASSERT_LE(entry->vme_start, 0x60000ull, "Check that the starting address is in bounds");
				T_QUIET; T_ASSERT_GE(entry->vme_end, 0x20000ull, "Check that the ending address is in bounds");
				T_QUIET; T_ASSERT_LT(n_locked_entries, max_locked_entries, "Check for entry accumulation overflow");
				locked_entries[n_locked_entries].start = entry->vme_start;
				locked_entries[n_locked_entries].end = entry->vme_end;
				n_locked_entries++;
			}
			vm_map_range_ex_unlock(ctx, &map);
		}

		fibers_join(unblocker);

		return kr;
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		clip_range(map, 0x18000, 0x58000);
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The range lock operation is expected to succeed");
		test_entry_t entries[] = {
			{
				.start = 0x000,
				.end = 0x18000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x18000,
				.end = 0x20000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x20000,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x58000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x58000,
				.end = 0x60000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};
		verify_test_map(map, entries, countof(entries));
	};


	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Clipping into kunwire");
}

T_DECL(protect_wire_race,
    "Protect-Wire Race - rdar://136676882 (XNU race condition in vm_protect "
    "allows writing to read-only mappings)")
{
	// This is an involved case, lower the default number of switches.
	n_rules = 2;

	// In unit tests these limits default to 0.  We need to raise the
	// limit to be able to wire at all.
	extern vm_map_size_t vm_per_task_user_wire_limit;
	vm_per_task_user_wire_limit = 0x100000000;
	extern uint64_t vm_global_user_wire_limit;
	vm_global_user_wire_limit = 0x100000000;

	// We need to track what these operations tried to do.
	__block bool is_read_only = false;

	const vm_map_address_t read_only_region_start = 0;
	const vm_map_address_t read_only_region_end = read_only_region_start + 0x4000;
	const vm_map_address_t read_write_region_start = read_only_region_end;
	const vm_map_address_t read_write_region_end = read_write_region_start + 0x4000;

	T_MOCK_SET_CALLBACK(
		pmap_protect_options_internal,
		vm_map_address_t, (
			pmap_t pmap,
			vm_map_address_t start,
			vm_map_address_t end,
			vm_prot_t prot,
			unsigned int options,
			void *args), {
		if (start == read_only_region_start) {
		        T_QUIET; T_ASSERT_EQ(end, read_only_region_end, "We only expect the one page to be written");
		        is_read_only = prot == VM_PROT_READ;
		}
		return end;
	});

	T_MOCK_SET_CALLBACK(
		pmap_enter_options_internal,
		kern_return_t, (
			pmap_t pmap,
			vm_map_address_t v,
			pmap_paddr_t pa,
			vm_prot_t prot,
			vm_prot_t fault_type,
			unsigned int flags,
			boolean_t wired,
			unsigned int options,
			pmap_mapping_type_t mapping_type), {
		if (v == read_only_region_start) {
		        is_read_only = prot == VM_PROT_READ;
		}

		return KERN_SUCCESS;
	});

	scenario_setup_t setup = ^vm_map_t () {
		is_read_only = false;

		test_entry_t entries[] = {
			{
				.start = read_only_region_start,
				.end = read_only_region_end,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_purgeable = true,
		    .vmf_no_cache = true),
				.cur_protection = VM_PROT_DEFAULT, // Initially read-write
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = read_write_region_start,
				.end = read_write_region_end,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_purgeable = true),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(
			pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));

		current_task()->map = map;
		current_thread()->map = map;
		return map;
	};

	victim_t victim = ^kern_return_t (vm_map_t map) {
		return vm_map_wire_kernel(map, read_only_region_start, read_write_region_end, VM_PROT_NONE,
	    VM_KERN_MEMORY_MLOCK, true);
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		kern_return_t kr = vm_map_protect(map, read_only_region_start, read_only_region_end, false /* don't set max prot */, VM_PROT_READ);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The protect operation should always succeed");
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The wire operation should always succeed");
		test_entry_t entries[] = {
			{
				.start = read_only_region_start,
				.end = read_only_region_end,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_purgeable = true,
		    .vmf_no_cache = true),
				.cur_protection = VM_PROT_READ, // Expecting vm_map_protect to work.
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = read_write_region_start,
				.end = read_write_region_end,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_purgeable = true),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};
		verify_test_map(map, entries, countof(entries));
		T_QUIET; T_ASSERT_TRUE(is_read_only, "We should see the effects of the protection change at the PMAP layer");
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Protect-Wire Race");
}


T_DECL(vm_map_pmap_unnest_test,
    "Race a pmap unnest which clips against another thread locking only part of it.")
{
	static const vm_map_address_t constant_submap_entry_start = 0x1000000000;
	vm_map_address_t range_start = 0x20000, range_end = 0x40000;

	n_rules = 3;

	const vm_map_offset_t submap_start = 0x2000000ULL;

	bool __block has_unnested;
	scenario_setup_t setup = ^vm_map_t () {
		const vm_map_offset_t submap_end = 0x4000000ULL * 200;
		const unsigned int    n_submap_entries = 3;

		vm_map_t map;
		vm_map_t submap;
		setup_constant_submap(constant_submap_entry_start, submap_start, submap_end, n_submap_entries, &map, &submap);

		has_unnested = false;
		return map;
	};

	// set the global to false when we pmap_unnest
	T_MOCK_SET_CALLBACK(
		pmap_unnest_options,
		kern_return_t, (
			pmap_t grand,
			addr64_t vaddr,
			uint64_t size,
			unsigned int option), {
		has_unnested = true;
		return KERN_SUCCESS;
	});

	aggressor_t aggressor = ^(vm_map_t map) {
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr;

		kr = vm_map_range_ex_lock(ctx, &map, submap_start, submap_start + PAGE_SIZE, VMRL_EX_STREAM);
		assert(kr == KERN_SUCCESS);
		vm_map_entry_t entry = vm_map_range_next(ctx);
		assert(!entry->use_pmap); /* we did unnest */
		vm_map_range_ex_unlock(ctx, &map);
		assert(has_unnested);
	};


	victim_t victim = ^kern_return_t (vm_map_t map){
		kern_return_t kr;
		VM_MAP_LOCK_CTX_DECLARE(ctx);

		kr = vm_map_range_sh_lock(ctx, &map, submap_start + PAGE_SIZE, submap_start + PAGE_SIZE * 2, VMRL_SH_STREAM);
		assert(kr == KERN_SUCCESS);
		vm_map_entry_t entry = vm_map_range_next(ctx);
		/* Verify we never observe a case where the pmap_unnest was not atomic w.r.t setting use_pmap */
		if (has_unnested) {
			assert(!entry->use_pmap);
		} else {
			assert(entry->use_pmap);
		}
		vm_map_range_sh_unlock(ctx, &map);

		return kr;
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS, "We expect no errors here");
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Race pmap_unnesting vs another thread observing the status of the entry's use_pmap");
}

T_DECL(simplify_race,
    "Race Simplify)")
{
	n_rules = 2;

	// Ask the mocks to fail to upgrade locks from shared to exclusive, taking the slow path
	ut_mocks_lock_upgrade_fail = true;

	vm_map_address_t range_start = 0x20000, range_end = 0x40000;

	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_READ,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x30000,
				.end = 0x34000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x34000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_READ,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));

		vm_map_ilk_lock(map);
		vm_map_entry_t entry;

		entry = vm_map_lookup(map, range_start);

		// Fix permissions to allow future simplification
		entry->protection = VM_PROT_DEFAULT;
		entry->vme_next->vme_next->protection = VM_PROT_DEFAULT;

		// Adjust offsets to allow simplification
		VME_OFFSET_SET(entry->vme_next, 0x10000);
		VME_OFFSET_SET(entry->vme_next->vme_next, 0x14000);

		vm_map_ilk_unlock(map);

		return map;
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		// Removing only the last entry allows the removal to
		// proceed when the simplification opens the map lock
		// under contention
		vm_map_remove(map, 0x34000, 0x40000);
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		vm_map_t tmp_map = map;
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, range_start, range_end, VMRL_EX_STREAM | VMRL_EX_SIMPLIFY);
		if (kr == KERN_SUCCESS) {
			vm_map_entry_t entry;
			while ((entry = vm_map_range_next_with_error(ctx, &kr))) {
				T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "Expecting to be able to iterate over all entries");
			}

			vm_map_range_ex_unlock(ctx, &map);
		}
		return kr;
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS || kr == KERN_INVALID_ADDRESS, "The range lock operation is expected to succeed unless the delete operation fully gets in front.  kr == %d", kr);
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x34000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			}
		};
		verify_test_map(map, entries, countof(entries));
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS("Race Simplify");
}



void
stackshot_race(int argc, char *const *argv, vmrl_flags_t flags, bool drop_if_streaming)
{
	__block thread_t locked_thread = NULL;

	scenario_setup_t setup = ^vm_map_t () {
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x30000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x50000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};

		vm_map_t map = vm_map_create_options(NULL, 0, 0xfffffffffffff, 0);
		setup_test_map(map, entries, countof(entries));

		locked_thread = NULL;

		return map;
	};

	not_in_kdp = false;

	aggressor_t aggressor = ^(vm_map_t map) {
		/* We should never see a */
		VM_MAP_LOCK_CTX_DECLARE(ctx);

		/*
		 * Lock the middle entry, causing the other lock call to block.
		 * This is needed because the range lock runs preemption disabled in streaming mode.
		 */
		kern_return_t kr = vm_map_range_ex_lock(ctx, &map, 0x30000, 0x40000, VMRL_EX_ATOMIC);
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock should work");
		vm_map_range_ex_unlock(ctx, &map);

		if (locked_thread && locked_thread->vm_map_lock_ctx_held) {
			vm_map_lock_ctx_t ctx = locked_thread->vm_map_lock_ctx_held;
			if (vmrl_is_streaming(ctx)) {
				if (ctx->vmlc_vme &&
				    !kdp_vm_entry_lock_is_acquired_exclusive(ctx->vmlc_vme) &&
				    kdp_vm_entry_lock_read_count(ctx->vmlc_vme) == 0) {
					T_ASSERT_FAIL("We saw an unlocked streaming entry in stackshot context.");
				}
			} else {
				/* We're atomic. Let's manually iterate all the entries in the map.
				 * This is safe only because we know we're not deleting/clipping entries */
				vm_map_entry_t entry;
				for (entry = vm_map_first_entry(map); entry != vm_map_to_entry(map); entry = entry->vme_next) {
					/* If the entry is in the locked range */
					if (ctx->__vmlc_atomic.locked_range_start <= entry->vme_start &&
					    entry->vme_end <= ctx->__vmlc_atomic.locked_range_end) {
						if (!kdp_vm_entry_lock_is_acquired_exclusive(entry) &&
						    kdp_vm_entry_lock_read_count(entry) == 0) {
							T_ASSERT_FAIL("We saw an unlocked atomic in stackshot context.");
						}
					}
				}
			}
		}
	};

	victim_t victim = ^kern_return_t (vm_map_t map){
		VM_MAP_LOCK_CTX_DECLARE(ctx);
		kern_return_t kr;

		locked_thread = current_thread();

		if (vmrl_is_exclusive(flags)) {
			kr = vm_map_range_ex_lock(ctx, &map, 0x20000, 0x50000, (vmrl_ex_flags_t) flags);
		} else {
			kr = vm_map_range_sh_lock(ctx, &map, 0x20000, 0x50000, (vmrl_sh_flags_t) flags);
		}

		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "lock should work");

		while (vm_map_range_next(ctx)) {
			T_QUIET; T_ASSERT_NE_PTR(locked_thread->vm_map_lock_ctx_held, NULL, "We have a lock context on the thread");
			if (drop_if_streaming && vmrl_is_streaming(ctx)) {
				vm_map_range_stream_drop(ctx);
			}
		}

		if (vmrl_is_exclusive(flags)) {
			vm_map_range_ex_unlock(ctx, &map);
		} else {
			vm_map_range_sh_unlock(ctx, &map);
		}

		return kr;
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "The range lock operation is expected to succeed");
		test_entry_t entries[] = {
			{
				.start = 0x20000,
				.end = 0x30000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x30000,
				.end = 0x40000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
			{
				.start = 0x40000,
				.end = 0x50000,
				.flags = VM_MAP_KERNEL_FLAGS_FIXED(),
				.cur_protection = VM_PROT_DEFAULT,
				.max_protection = VM_PROT_DEFAULT,
			},
		};
		verify_test_map(map, entries, countof(entries));
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);
	T_PASS("Stackshot test didn't have a race.");
}

T_DECL(stackshot_atomic_tests, "Test racing stackshot against atomic locks")
{
	stackshot_race(argc, argv, (vmrl_flags_t) VMRL_EX_ATOMIC, false);
	stackshot_race(argc, argv, (vmrl_flags_t) VMRL_EX_ATOMIC_ALLOW_HOLES, false);
}

T_DECL(stackshot_streaming_tests,
    "Test racing stackshot against streaming locks")
{
	stackshot_race(argc, argv, (vmrl_flags_t) VMRL_EX_STREAM, false);
	stackshot_race(argc, argv, (vmrl_flags_t) VMRL_EX_STREAM, true);
}

/*
 * Due to rdar://142262418, the overwrite must not fail in any case.
 */
T_DECL(vm_map_go_overwrite_terminate,
    "Race an overwrite operation with map termination in guard-object-enabled map")
{
	/*
	 * Select two sizes in different GO size classes.
	 */
	vm_map_offset_t size_big = MiB(4);
	vm_map_offset_t size = KiB(128);
	__block vm_map_offset_t orig_addr = 0;
	__block vm_map_offset_t anywhere_addr = 0;

	/*
	 * No coalescing for this test to make sure our nentries counts are
	 * accurate.
	 */
	T_MOCK_SET_RETVAL(vm_object_coalesce, boolean_t, FALSE);

	/*
	 * Always allocate in the first available slot so that entry addresses
	 * are consistent when we allocate chunks in the same spot.
	 */
	T_MOCK_SET_CALLBACK(vmgo_chunk_select_random_slot, uint32_t, (vm_guard_object_chunk_t chunk), {
		uint64_t bitmap = vmgo_bitmap(chunk);
		for (uint32_t i = 0; i < 64; i++) {
		        if (bit_test(bitmap, i)) {
		                return i;
			}
		}
		T_ASSERT_FAIL("failed to allocate in chunk");
	});

	scenario_setup_t setup = ^vm_map_t () {
		pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);
		vm_map_t map = vm_map_create_options(pmap, 0, 0xfffffffffffff, 0);
		vm_map_guard_object_slab_init(map);

		orig_addr = 0;
		kern_return_t kr = vm_map_enter(map, &orig_addr, size_big, 0,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(), VM_OBJECT_NULL, 0, false,
		    VM_PROT_DEFAULT, VM_PROT_DEFAULT, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Insert original GO");

		return map;
	};

	aggressor_t aggressor = ^(vm_map_t map) {
		vm_map_terminate(map);

		/*
		 * The aggressor will additionally create a new, smaller,
		 * 'ANYWHERE' allocation in the map.
		 * The idea is: if we allow creating new chunks in the same
		 * location, the overwrite may go outside the bounds of the
		 * new, smaller, slot and fail.
		 *
		 * Fill in the beginning of the map to help us allocate at the
		 * right spot, as guard objects don't respect the allocation
		 * hint.
		 */
		vm_test_add_map_entry(map, 0, orig_addr);

		anywhere_addr = 0;
		kern_return_t kr = vm_map_enter(map, &anywhere_addr, size, 0,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(), VM_OBJECT_NULL, 0, false,
		    VM_PROT_DEFAULT, VM_PROT_DEFAULT, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Insert new GO");
	};

	victim_t victim = ^kern_return_t (vm_map_t map) {
		vm_map_offset_t addr = orig_addr;
		kern_return_t kr = vm_map_enter(map, &addr, size_big, 0,
		    VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true),
		    VM_OBJECT_NULL, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
		    0);
		return kr;
	};

	checker_t checker = ^(kern_return_t kr, vm_map_t map) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "the overwrite must not fail in any case (rdar://142262418)");

		if (map->hdr.nentries == 2) {
			T_QUIET; T_ASSERT_EQ(anywhere_addr, orig_addr, "New GO inserted at same location");
		} else {
			T_QUIET; T_ASSERT_EQ(map->hdr.nentries, 3, "the overwrite happened first");
		}
	};

	range_lock_test_run(argc, argv, setup, victim, aggressor, checker);

	T_PASS(__FUNCTION__);
}

#pragma clang attribute pop // no_sanitize("coverage")
