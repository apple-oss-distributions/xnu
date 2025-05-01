// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <stdint.h>
#include <stdio.h>
#include <sys/kdebug.h>

/* Harness interface */
#include "sched_clutch_harness.h"

/* Include kernel header depdencies */
#include "shadow_headers/misc_needed_defines.h"

/* Header for Clutch policy code under-test */
#include <kern/sched_clutch.h>

/* Include non-header dependencies */
#define KERNEL_DEBUG_CONSTANT_IST(a0, a1, a2, a3, a4, a5, a6) clutch_impl_log_tracepoint(a1, a2, a3, a4, a5)
#include "shadow_headers/misc_needed_deps.c"
#include "shadow_headers/sched_prim.c"

static test_hw_topology_t curr_hw_topo = {
	.num_psets = 0,
	.psets = NULL,
};
static int _curr_cpu = 0;

unsigned int
ml_get_cluster_count(void)
{
	return (unsigned int)curr_hw_topo.num_psets;
}

/*
 * Mocked HW details
 * For simplicity, we mock a platform with 1 pset comprised of 1 CPU
 */
uint32_t processor_avail_count = 0;

static struct processor_set *psets[MAX_PSETS];
static struct processor *cpus[MAX_CPUS];

/* Boot pset and CPU */
struct processor_set pset0;
struct processor cpu0;

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

/* Implementation of sched_runqueue_harness.h interface */

static test_pset_t single_pset = {
	.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
	.num_cpus = 1,
	.die_id = 0,
};
test_hw_topology_t single_core = {
	.psets = &single_pset,
	.num_psets = 1,
};

static char
test_cpu_type_to_char(test_cpu_type_t cpu_type)
{
	switch (cpu_type) {
	case TEST_CPU_TYPE_PERFORMANCE:
		return 'P';
	case TEST_CPU_TYPE_EFFICIENCY:
		return 'E';
	default:
		return '?';
	}
}

void
clutch_impl_init_topology(test_hw_topology_t hw_topology)
{
	printf("🗺️  Mock HW Topology: %d psets {", hw_topology.num_psets);
	assert(hw_topology.num_psets <= MAX_PSETS);
	int total_cpus = 0;
	for (int i = 0; i < hw_topology.num_psets; i++) {
		assert((total_cpus + hw_topology.psets[i].num_cpus) <= MAX_CPUS);
		if (i == 0) {
			psets[0] = &pset0;
		} else {
			psets[i] = (struct processor_set *)malloc(sizeof(struct processor_set));
		}
		psets[i]->pset_cluster_id = i;
		psets[i]->pset_id = i;
		psets[i]->cpu_set_low = total_cpus;
		psets[i]->cpu_bitmask = 0;
		printf(" (%d: %d %c CPUs)", i, hw_topology.psets[i].num_cpus, test_cpu_type_to_char(hw_topology.psets[i].cpu_type));
		for (int c = total_cpus; c < total_cpus + hw_topology.psets[i].num_cpus; c++) {
			if (c == 0) {
				cpus[0] = &cpu0;
			} else {
				cpus[c] = (struct processor *)malloc(sizeof(struct processor));
			}
			cpus[c]->cpu_id = c;
			cpus[c]->processor_set = psets[i];
			bit_set(psets[i]->cpu_bitmask, c);
			cpus[c]->active_thread = NULL;
		}
		psets[i]->recommended_bitmask = psets[i]->cpu_bitmask;
		psets[i]->cpu_available_map = psets[i]->cpu_bitmask;
		total_cpus += hw_topology.psets[i].num_cpus;
	}
	processor_avail_count = total_cpus;
	printf(" }\n");
}

static uint64_t unique_tg_id = 0;
static uint64_t unique_thread_id = 0;
#define NUM_LOGGED_TRACE_CODES 1
#define NUM_TRACEPOINT_FIELDS 5
static uint64_t logged_trace_codes[NUM_LOGGED_TRACE_CODES];
#define MAX_LOGGED_TRACEPOINTS 10000
static uint64_t *logged_tracepoints = NULL;
static uint32_t curr_tracepoint_ind = 0;
static uint32_t expect_tracepoint_ind = 0;

void
clutch_impl_init_params(void)
{
	/* Read out Clutch-internal fields for use by the test harness */
	clutch_interactivity_score_max = 2 * sched_clutch_bucket_group_interactive_pri;
	for (int b = TH_BUCKET_FIXPRI; b < TH_BUCKET_SCHED_MAX; b++) {
		clutch_root_bucket_wcel_us[b] = sched_clutch_root_bucket_wcel_us[b] == SCHED_CLUTCH_INVALID_TIME_32 ? 0 : sched_clutch_root_bucket_wcel_us[b];
		clutch_root_bucket_warp_us[b] = sched_clutch_root_bucket_warp_us[b] == SCHED_CLUTCH_INVALID_TIME_32 ? 0 : sched_clutch_root_bucket_warp_us[b];
	}
	CLUTCH_THREAD_SELECT = MACH_SCHED_CLUTCH_THREAD_SELECT;
}

void
clutch_impl_init_tracepoints(void)
{
	/* All filter-included tracepoints */
	logged_trace_codes[0] = MACH_SCHED_CLUTCH_THREAD_SELECT;
	/* Init harness-internal allocators */
	logged_tracepoints = malloc(MAX_LOGGED_TRACEPOINTS * 5 * sizeof(uint64_t));
}

struct thread_group *
clutch_impl_create_tg(int interactivity_score)
{
	struct thread_group *tg = malloc(sizeof(struct thread_group));
	sched_clutch_init_with_thread_group(&tg->tg_sched_clutch, tg);
	if (interactivity_score != INITIAL_INTERACTIVITY_SCORE) {
		for (int bucket = TH_BUCKET_SHARE_FG; bucket < TH_BUCKET_SCHED_MAX; bucket++) {
			tg->tg_sched_clutch.sc_clutch_groups[bucket].scbg_interactivity_data.scct_count = interactivity_score;
			tg->tg_sched_clutch.sc_clutch_groups[bucket].scbg_interactivity_data.scct_timestamp = mach_absolute_time();
		}
	}
	tg->tg_id = unique_tg_id++;
	return tg;
}

test_thread_t
clutch_impl_create_thread(int root_bucket, struct thread_group *tg, int pri)
{
	assert((sched_bucket_t)root_bucket == sched_convert_pri_to_bucket(pri) || (sched_bucket_t)root_bucket == TH_BUCKET_FIXPRI);
	assert(tg != NULL);
	thread_t thread = malloc(sizeof(struct thread));
	thread->base_pri = pri;
	thread->sched_pri = pri;
	thread->thread_group = tg;
	thread->th_sched_bucket = root_bucket;
	thread->bound_processor = NULL;
	thread->__runq.runq = PROCESSOR_NULL;
	thread->thread_id = unique_thread_id++;
#if CONFIG_SCHED_EDGE
	thread->th_bound_cluster_enqueued = false;
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		thread->th_shared_rsrc_enqueued[shared_rsrc_type] = false;
		thread->th_shared_rsrc_heavy_user[shared_rsrc_type] = false;
		thread->th_shared_rsrc_heavy_perf_control[shared_rsrc_type] = false;
	}
#endif /* CONFIG_SCHED_EDGE */
	thread->th_bound_cluster_id = THREAD_BOUND_CLUSTER_NONE;
	thread->reason = AST_NONE;
	thread->sched_mode = TH_MODE_TIMESHARE;
	thread->sched_flags = 0;
	return thread;
}
void
clutch_impl_set_thread_sched_mode(test_thread_t thread, int mode)
{
	((thread_t)thread)->sched_mode = (sched_mode_t)mode;
}
void
clutch_impl_set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	((thread_t)thread)->bound_processor = cpus[cpu_id];
}

void
clutch_impl_cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	cpus[cpu_id]->active_thread = thread;
	cpus[cpu_id]->first_timeslice = true;
	/* Equivalent logic of processor_state_update_from_thread() */
	cpus[cpu_id]->current_pri = ((thread_t)thread)->sched_pri;
	cpus[cpu_id]->current_thread_group = ((thread_t)thread)->thread_group;
	cpus[cpu_id]->current_is_bound = ((thread_t)thread)->bound_processor != PROCESSOR_NULL;
}

void
clutch_impl_cpu_clear_thread_current(int cpu_id)
{
	cpus[cpu_id]->active_thread = NULL;
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
clutch_impl_log_tracepoint(uint64_t trace_code, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
	if (is_logged_trace_code(trace_code)) {
		if (curr_tracepoint_ind < MAX_LOGGED_TRACEPOINTS) {
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 0] = KDBG_EXTRACT_CODE(trace_code);
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 1] = a1;
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 2] = a2;
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 3] = a3;
			logged_tracepoints[curr_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 4] = a4;
		} else if (curr_tracepoint_ind == MAX_LOGGED_TRACEPOINTS) {
			printf("Ran out of pre-allocated memory to log tracepoints (%d points)...will no longer log tracepoints\n",
			    MAX_LOGGED_TRACEPOINTS);
		}
		curr_tracepoint_ind++;
	}
}

void
clutch_impl_pop_tracepoint(uint64_t *clutch_trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4)
{
	assert(expect_tracepoint_ind < curr_tracepoint_ind);
	*clutch_trace_code = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 0];
	*arg1 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 1];
	*arg2 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 2];
	*arg3 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 3];
	*arg4 = logged_tracepoints[expect_tracepoint_ind * NUM_TRACEPOINT_FIELDS + 4];
	expect_tracepoint_ind++;
}
