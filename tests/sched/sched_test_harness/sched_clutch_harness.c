// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <stdint.h>
#include <stdio.h>
#include <sys/kdebug.h>

/* Harness interface */
#include "sched_clutch_harness.h"

/*
 * Include non-kernel header dependencies to make up for the equivalent kernel header
 * dependencies which are not safe to compile in a userspace binary
 */
#include <os/overflow.h>
#include <sys/types.h>
#include <os/atomic_private.h>

/* Include kernel header depdencies */
#include "shadow_headers/misc_needed_defines.h"

/* Header for Clutch policy code under-test */
#include <kern/sched_clutch.h>

/* Include non-header dependencies */
void log_tracepoint(uint64_t trace_code, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);
#define KERNEL_DEBUG_CONSTANT_IST(a0, a1, a2, a3, a4, a5, a6) log_tracepoint(a1, a2, a3, a4, a5)
#include "shadow_headers/misc_needed_deps.c"
#include "shadow_headers/sched_prim.c"

/*
 * Mocked HW details
 * For simplicity, we mock a platform with 1 pset comprised of 1 CPU
 */
#define MAX_PSETS 1
#define ml_get_cluster_count() MAX_PSETS
static const uint32_t processor_avail_count = 1;
#define pset_available_cpu_count(x) processor_avail_count
static struct processor_set pset0 = {
	.pset_cluster_id = 0,
};
static struct processor cpu0 = {
	.cpu_id = 0,
	.processor_set = &pset0,
};

/* Mocked-out Clutch functions */
static boolean_t
sched_thread_sched_pri_promoted(thread_t thread)
{
	(void)thread;
	return FALSE;
}

/* Clutch policy code under-test, safe to include now after satisfying its dependencies */
#include <kern/sched_clutch.c>

/* Implementation of sched_clutch_harness.h interface */

int root_bucket_to_highest_pri[TH_BUCKET_SCHED_MAX] = {
	MAXPRI_USER,
	BASEPRI_FOREGROUND,
	BASEPRI_USER_INITIATED,
	BASEPRI_DEFAULT,
	BASEPRI_UTILITY,
	MAXPRI_THROTTLE
};

int clutch_interactivity_score_max = -1;
uint64_t clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX];
uint64_t clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX];
unsigned int CLUTCH_THREAD_SELECT = -1;

/* Track harness allocations so we can free the pointers in impl_cleanup_harness() */
struct list_node {
	struct list_node *next;
	void *ptr;
};
static struct list_node *allocated_list = NULL;

static void
track_allocated(void *ptr)
{
	struct list_node *new_node = malloc(sizeof(struct list_node));
	new_node->ptr = ptr;
	new_node->next = allocated_list;
	allocated_list = new_node;
}

/* Implementation of sched_runqueue_harness.h interface */

static uint64_t unique_tg_id = 0;
static uint64_t unique_thread_id = 0;
#define NUM_LOGGED_TRACE_CODES 1
#define NUM_TRACEPOINT_FIELDS 5
static uint64_t logged_trace_codes[NUM_LOGGED_TRACE_CODES];
#define MAX_LOGGED_TRACEPOINTS 1000
static uint64_t *logged_tracepoints = NULL;
static uint32_t curr_tracepoint_ind = 0;
static uint32_t expect_tracepoint_ind = 0;

void
impl_init_runqueue(void)
{
	/* Init runqueue */
	sched_clutch_init();
	sched_clutch_pset_init(&pset0);
	sched_clutch_processor_init(&cpu0);
	increment_mock_time(100);

	/* Read out Clutch-internal fields for use by the test harness */
	clutch_interactivity_score_max = 2 * sched_clutch_bucket_group_interactive_pri;
	for (int b = TH_BUCKET_FIXPRI; b < TH_BUCKET_SCHED_MAX; b++) {
		clutch_root_bucket_wcel_us[b] = sched_clutch_root_bucket_wcel_us[b] == SCHED_CLUTCH_INVALID_TIME_32 ? 0 : sched_clutch_root_bucket_wcel_us[b];
		clutch_root_bucket_warp_us[b] = sched_clutch_root_bucket_warp_us[b] == SCHED_CLUTCH_INVALID_TIME_32 ? 0 : sched_clutch_root_bucket_warp_us[b];
	}
	CLUTCH_THREAD_SELECT = MACH_SCHED_CLUTCH_THREAD_SELECT;
	logged_trace_codes[0] = MACH_SCHED_CLUTCH_THREAD_SELECT;

	/* Init harness-internal allocators */
	logged_tracepoints = malloc(MAX_LOGGED_TRACEPOINTS * 5 * sizeof(uint64_t));
	track_allocated(logged_tracepoints);
	curr_tracepoint_ind = 0;
	expect_tracepoint_ind = 0;
	unique_tg_id = 0;
	unique_thread_id = 0;
}

struct thread_group *
impl_create_tg(int interactivity_score)
{
	struct thread_group *tg = malloc(sizeof(struct thread_group));
	track_allocated(tg);
	sched_clutch_init_with_thread_group(&tg->tg_sched_clutch, tg);
	if (interactivity_score != -1) {
		for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
			tg->tg_sched_clutch.sc_clutch_groups[bucket].scbg_interactivity_data.scct_count = interactivity_score;
			tg->tg_sched_clutch.sc_clutch_groups[bucket].scbg_interactivity_data.scct_timestamp = mach_absolute_time();
		}
	}
	tg->tg_id = unique_tg_id++;
	return tg;
}

test_thread_t
impl_create_thread(int root_bucket, struct thread_group *tg, int pri)
{
	assert((sched_bucket_t)root_bucket == sched_convert_pri_to_bucket(pri) || (sched_bucket_t)root_bucket == TH_BUCKET_FIXPRI);
	assert(tg != NULL);
	thread_t thread = malloc(sizeof(struct thread));
	track_allocated(thread);
	thread->base_pri = pri;
	thread->sched_pri = pri;
	thread->thread_group = tg;
	thread->th_sched_bucket = root_bucket;
	thread->bound_processor = NULL;
	thread->__runq.runq = PROCESSOR_NULL;
	thread->thread_id = unique_thread_id++;
	return thread;
}

void
impl_set_thread_sched_mode(test_thread_t thread, int mode)
{
	((thread_t)thread)->sched_mode = (sched_mode_t)mode;
}

void
impl_set_thread_processor_bound(test_thread_t thread)
{
	((thread_t)thread)->bound_processor = &cpu0;
}

static test_thread_t curr_thread = NULL;

void
impl_set_thread_current(test_thread_t thread)
{
	curr_thread = thread;
	cpu0.active_thread = thread;
	cpu0.first_timeslice = true;
	/* Equivalent logic of processor_state_update_from_thread() */
	cpu0.current_pri = ((thread_t)thread)->sched_pri;
	cpu0.current_thread_group = ((thread_t)thread)->thread_group;
	cpu0.current_is_bound = ((thread_t)thread)->bound_processor != PROCESSOR_NULL;
}

void
impl_clear_thread_current(void)
{
	curr_thread = NULL;
	cpu0.active_thread = NULL;
}

void
impl_enqueue_thread(test_thread_t thread)
{
	sched_clutch_processor_enqueue(&cpu0, thread, SCHED_TAILQ);
}

test_thread_t
impl_dequeue_thread(void)
{
	return sched_clutch_choose_thread(&cpu0, MINPRI, NULL, 0);
}

test_thread_t
impl_dequeue_thread_compare_current(void)
{
	assert(curr_thread != NULL);
	return sched_clutch_choose_thread(&cpu0, MINPRI, curr_thread, 0);
}

bool
impl_processor_csw_check(void)
{
	assert(curr_thread != NULL);
	ast_t preempt_ast = sched_clutch_processor_csw_check(&cpu0);
	return preempt_ast & AST_PREEMPT;
}

static bool
is_logged_clutch_trace_code(uint64_t clutch_trace_code)
{
	for (int i = 0; i < NUM_LOGGED_TRACE_CODES; i++) {
		if (logged_trace_codes[i] == clutch_trace_code) {
			return true;
		}
	}
	return false;
}

static bool
is_logged_trace_code(uint64_t trace_code)
{
	if (KDBG_EXTRACT_CLASS(trace_code) == DBG_MACH && KDBG_EXTRACT_SUBCLASS(trace_code) == DBG_MACH_SCHED_CLUTCH) {
		if (is_logged_clutch_trace_code(KDBG_EXTRACT_CODE(trace_code))) {
			return true;
		}
	}
	return false;
}

void
log_tracepoint(uint64_t trace_code, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
	if (is_logged_trace_code(trace_code)) {
		if (curr_tracepoint_ind < MAX_LOGGED_TRACEPOINTS) {
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 0] = KDBG_EXTRACT_CODE(trace_code);
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 1] = a2;
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 2] = a3;
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 3] = a4;
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 4] = a5;
		} else if (curr_tracepoint_ind == MAX_LOGGED_TRACEPOINTS) {
			printf("Ran out of pre-allocated memory to log tracepoints (%x points)...will no longer log tracepoints\n",
			    MAX_LOGGED_TRACEPOINTS);
		}
		curr_tracepoint_ind++;
	}
}

void
impl_pop_tracepoint(uint64_t *clutch_trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4)
{
	*clutch_trace_code = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 0];
	*arg1 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 1];
	*arg2 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 2];
	*arg3 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 3];
	*arg4 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 4];
	expect_tracepoint_ind++;
}

void
impl_cleanup_harness(void)
{
	/* Free all of the pointers we tracked in the allocated list */
	struct list_node *curr_node = allocated_list;
	while (curr_node != NULL) {
		free(curr_node->ptr);
		struct list_node *next_node = curr_node->next;
		free(curr_node);
		curr_node = next_node;
	}
	allocated_list = NULL;
}
