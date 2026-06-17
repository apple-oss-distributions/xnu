// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <stdint.h>
#include <stdio.h>
#include "../../../bsd/sys/kdebug.h" // Want tracecodes from source without searching BSD headers

/* Include kernel header depdencies */
#include "shadow_headers/misc_needed_defines.h"
#include <kern/sched_common.h>

/* Harness interface */
#include "sched_clutch_harness.h"

/* Header for Clutch policy code under-test */
#include <kern/sched_clutch.h>

/* Include non-header dependencies */
#define KERNEL_DEBUG_CONSTANT_IST(a0, a1, a2, a3, a4, a5, a6) clutch_impl_log_tracepoint(a1, a2, a3, a4, a5)
#include "shadow_headers/misc_needed_deps.c"
/* For now, pull in the real sched_prim.c for sched_init(). Eventually, we should
 * onboard enough of that file that we no longer need the mock
 * shadow_headers/sched_prim.c. */
#include <kern/sched_prim.c>
#include "shadow_headers/sched_prim.c"

static int _curr_cpu = 0;

processor_t
current_processor(void)
{
	if (_curr_cpu == 0) {
		/* Assumes boot CPU of id 0 */
		return master_processor;
	} else {
		return processor_array[_curr_cpu];
	}
}

struct ml_topology_cluster topology_cluster_array[MAX_CPU_CLUSTERS];
struct ml_topology_cpu     topology_cpu_array[MAX_CPUS];
struct ml_topology_info    topology_info;

const struct ml_topology_info *
ml_get_topology_info(void)
{
	return &topology_info;
}

struct test_hw_topology single_core = {
	.num_cpus = 1,
	.boot_cpu = 0,
	.cpu_ranges = {
		{
			.cpu_type = TEST_CPU_TYPE_PERFORMANCE,
			.cluster_id = 0,
			.die_id = 0,
			.first_cpu_id = 0,
			.num_cpus = 1,
		}
	}
};

unsigned int
ml_get_cluster_count(void)
{
	return (unsigned int)topology_info.num_clusters;
}

unsigned int
ml_get_cpu_count(void)
{
	return (unsigned int)topology_info.num_cpus;
}

/* Mocked-out Clutch functions */
static boolean_t
sched_thread_sched_pri_promoted(thread_t thread)
{
#pragma unused(thread)
	return FALSE;
}

/* Clutch policy code under-test, safe to include now after satisfying its dependencies */
#include <kern/sched_clutch.c>
#include <kern/sched_common.c>
#include <kern/processor.c>

/* Realtime policy code under-test */
#include <kern/sched_rt.c>

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
const unsigned int CLUTCH_THREAD_SELECT = MACH_SCHED_CLUTCH_THREAD_SELECT;

/* Implementation of sched_runqueue_harness.h interface */

static uint64_t unique_tg_id = 0;
static uint64_t unique_thread_id = 0;
static bool first_boot = true;
static test_pset sched_topology_psets[MAX_PSETS];
static struct test_scheduler_topology sched_topology;

test_sched_topology_t
get_sched_topology(void)
{
	return &sched_topology;
}

const char *
test_cpu_type_to_str(test_cpu_type_t cpu_type)
{
	switch (cpu_type) {
	case TEST_CPU_TYPE_EFFICIENCY:
		return "E";
#if HAS_MCORE
	case TEST_CPU_TYPE_MP_OPTIMIZED:
		return "M";
#endif /* HAS_MCORE */
	case TEST_CPU_TYPE_PERFORMANCE:
		return "P";
	default:
		assert(false);
		return "?";
	}
}

static cluster_type_t
test_cpu_type_to_cluster_type(test_cpu_type_t cpu_type)
{
	switch (cpu_type) {
	case TEST_CPU_TYPE_EFFICIENCY:
		return CLUSTER_TYPE_E;
#if HAS_MCORE
	case TEST_CPU_TYPE_MP_OPTIMIZED:
		return CLUSTER_TYPE_M;
#endif /* HAS_MCORE */
	case TEST_CPU_TYPE_PERFORMANCE:
		return CLUSTER_TYPE_P;
	default:
		assert(false);
		return CLUSTER_TYPE_INVALID;
	}
}

static test_cpu_type_t
pset_type_to_test_cpu_type(pset_type_t pset_type)
{
	switch (pset_type) {
#if __AMP__
	case PSET_AMP_E:
		return TEST_CPU_TYPE_EFFICIENCY;
#if HAS_MCORE
	case PSET_AMP_M:
		return TEST_CPU_TYPE_MP_OPTIMIZED;
#endif /* HAS_MCORE */
	case PSET_AMP_P:
		return TEST_CPU_TYPE_PERFORMANCE;
#else /* !__AMP__ */
	case PSET_SMP:
		return TEST_CPU_TYPE_PERFORMANCE;
#endif /* !__AMP__ */
	default:
		assert(false);
	}
}

test_sched_topology_t
clutch_impl_init_topology(test_hw_topology_t hw_topology)
{
	printf("🗺️  Mock HW Topology: (");
	assert(first_boot); // Not supported to initialize more than one topology
	first_boot = false;
	assert(hw_topology->num_cpus > 0);
	assert(hw_topology->boot_cpu < hw_topology->num_cpus);

	/* Translate the test_hw_topology into ml_topology_info. */
	bzero(topology_cluster_array, sizeof(topology_cluster_array));
	bzero(topology_cpu_array, sizeof(topology_cpu_array));

	uint64_t cpus_found = 0, clusters_found = 0, dies_found = 0;
	unsigned int next_cpu_id = 0, max_cluster_id = 0, max_die_id = 0;
	for (unsigned int range_index = 0; next_cpu_id < hw_topology->num_cpus; range_index++) {
		test_hw_cpu_range range = hw_topology->cpu_ranges[range_index];

		/* Basic range validations. */
		assert(range.cluster_id < MAX_CPU_CLUSTERS);
		assert(range.first_cpu_id + range.num_cpus <= hw_topology->num_cpus);

		/* Ranges should be in order of increasing cluster_id and die_id */
		assert(range_index == 0 || range.die_id >= hw_topology->cpu_ranges[range_index - 1].die_id);
		assert(range_index == 0 || range.cluster_id >= hw_topology->cpu_ranges[range_index - 1].cluster_id);

		/* If another range exists for the same cluster, they must be in the same die. */
		struct ml_topology_cluster *cluster = &topology_cluster_array[range.cluster_id];
		if (bit_test(clusters_found, range.cluster_id)) {
			assert(range.die_id == cluster->die_id);
		}
		cluster->die_id = range.die_id;

		if (range_index > 0) {
			if (range.die_id != hw_topology->cpu_ranges[range_index - 1].die_id) {
				/* new die */
				printf(") (");
			} else if (range.cluster_id != hw_topology->cpu_ranges[range_index - 1].cluster_id) {
				/* new cluster */
				printf(" ");
			}
		}
		printf("%u%s", range.num_cpus, test_cpu_type_to_str(range.cpu_type));

		/* Mark this cluster and die as encountered. */
		bit_set(clusters_found, range.cluster_id);
		max_cluster_id = MAX(max_cluster_id, range.cluster_id);
		bit_set(dies_found, range.die_id);
		max_die_id = MAX(max_die_id, range.die_id);

		for (unsigned int cpu_id = range.first_cpu_id; cpu_id < range.first_cpu_id + range.num_cpus; cpu_id++) {
			/* Mark this cpu as encountered. */
			assert(bit_test(cpus_found, cpu_id) == false);
			bit_set(cpus_found, cpu_id);

			topology_cpu_array[cpu_id] = (struct ml_topology_cpu) {
				.cpu_id = cpu_id,
				.cluster_id = range.cluster_id,
				.die_id = range.die_id,
				.cluster_type = test_cpu_type_to_cluster_type(range.cpu_type),
			};

			bit_set(cluster->cpu_mask, cpu_id);

			if (cpu_id == hw_topology->boot_cpu) {
				topology_info.boot_cpu = &topology_cpu_array[cpu_id];
				topology_info.boot_cluster = cluster;
			}
		}

		cluster->first_cpu_id = lsb_first(cluster->cpu_mask);
		cluster->num_cpus = bit_count(cluster->cpu_mask);

		next_cpu_id += range.num_cpus;
	}
	puts(")");

	topology_info.clusters = topology_cluster_array;
	topology_info.cpus = topology_cpu_array;
	topology_info.num_cpus = hw_topology->num_cpus;

	assert(clusters_found == bits_mask(max_cluster_id + 1)); /* clusters are contiguous, starting with 0 */
	topology_info.max_cluster_id = max_cluster_id;
	topology_info.num_clusters = max_cluster_id + 1;

	assert(dies_found == bits_mask(max_die_id + 1)); /* dies are contiguous, starting with 0 */
	topology_info.max_die_id = max_die_id;

	assert(topology_info.boot_cpu != NULL);
	assert(topology_info.boot_cluster != NULL);

	/* Scheduler initialization. */
	processor_bootstrap();

	sched_init();

	for (int i = 0; i < sched_num_psets; i++) {
		for (int c = lsb_first(pset_array[i]->cpu_bitmask); c >= 0; c = lsb_next(pset_array[i]->cpu_bitmask, c)) {
			if (c != master_processor->cpu_id) {
				processor_t processor = (processor_t)malloc(sizeof(struct processor));
				processor_init(processor, c, pset_array[i]);
			} else {
				SCHED(processor_init)(master_processor);
			}
			struct thread_group *not_real_idle_tg = create_tg(0);
			thread_t idle_thread = clutch_impl_create_thread(TH_BUCKET_SHARE_BG, not_real_idle_tg, IDLEPRI);
			idle_thread->bound_processor = processor_array[c];
			idle_thread->state = (TH_RUN | TH_IDLE);
			processor_array[c]->idle_thread = idle_thread;
			processor_array[c]->active_thread = processor_array[c]->idle_thread;
			pset_update_processor_state(pset_array[i], processor_array[c], PROCESSOR_IDLE);
			processor_avail_count++;
		}
	}
	printf(" }\n");
	/* After mock idle thread creation, reset thread/TG start IDs, as the idle threads shouldn't count! */
	unique_tg_id = 0;
	unique_thread_id = 0;
	if (SCHED(cpu_init_completed) != NULL) {
		SCHED(cpu_init_completed)();
	}
	SCHED(rt_init_completed)();

	for (pset_id_t pset_id = 0; pset_id < sched_num_psets; pset_id++) {
		processor_set_t pset = pset_array[pset_id];
		sched_topology_psets[pset_id] = (test_pset) {
			.cpu_type = pset_type_to_test_cpu_type(pset->pset_type),
			.cluster_id = pset->cluster_id,
			.die_id = topology_info.clusters[pset->cluster_id].die_id,
			.num_cpus = bit_count(pset->cpu_bitmask),
		};
	}
	sched_topology = (struct test_scheduler_topology) {
		.num_psets = sched_num_psets,
		.psets = sched_topology_psets,
	};
	return &sched_topology;
}

#define MAX_LOGGED_TRACE_CODES 10
#define NUM_TRACEPOINT_FIELDS 5
static uint64_t logged_trace_codes[MAX_LOGGED_TRACE_CODES];
static uint32_t logged_trace_codes_ind = 0;
#define MAX_LOGGED_TRACEPOINTS 10000
static uint64_t *logged_tracepoints[MAX_LOGGED_TRACE_CODES];
static uint32_t curr_tracepoint_inds[MAX_LOGGED_TRACE_CODES];
static uint32_t expect_tracepoint_inds[MAX_LOGGED_TRACE_CODES];

void
clutch_impl_init_params(void)
{
	/* Read out Clutch-internal fields for use by the test harness */
	clutch_interactivity_score_max = 2 * sched_clutch_bucket_group_interactive_pri;
	for (int b = TH_BUCKET_FIXPRI; b < TH_BUCKET_SCHED_MAX; b++) {
		clutch_root_bucket_wcel_us[b] = sched_clutch_root_bucket_wcel_us[b] == SCHED_CLUTCH_INVALID_TIME_32 ? 0 : sched_clutch_root_bucket_wcel_us[b];
		clutch_root_bucket_warp_us[b] = sched_clutch_root_bucket_warp_us[b] == SCHED_CLUTCH_INVALID_TIME_32 ? 0 : sched_clutch_root_bucket_warp_us[b];
	}
}

void
clutch_impl_add_logged_trace_code(uint64_t tracepoint)
{
	logged_trace_codes[logged_trace_codes_ind++] = tracepoint;
}

void
clutch_impl_init_tracepoints(void)
{
	/* All filter-included tracepoints */
	clutch_impl_add_logged_trace_code(CLUTCH_THREAD_SELECT);
	/* Init harness-internal allocators */
	for (int i = 0; i < MAX_LOGGED_TRACE_CODES; i++) {
		logged_tracepoints[i] = malloc(MAX_LOGGED_TRACEPOINTS * 5 * sizeof(uint64_t));
		curr_tracepoint_inds[i] = 0;
		expect_tracepoint_inds[i] = 0;
	}
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
	thread->sched_flags = 0;
	thread->thread_group = tg;
	thread->th_sched_bucket = root_bucket;
	thread->bound_processor = NULL;
	thread->__runq.runq = PROCESSOR_NULL;
	queue_chain_init(thread->runq_links);
	thread->thread_id = unique_thread_id++;
#if CONFIG_SCHED_EDGE
	thread->th_bound_pset_enqueued = false;
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		thread->th_shared_rsrc_enqueued[shared_rsrc_type] = false;
		thread->th_shared_rsrc_heavy_user[shared_rsrc_type] = false;
		thread->th_shared_rsrc_heavy_perf_control[shared_rsrc_type] = false;
		thread->th_expired_quantum_on_lower_core = false;
		thread->th_expired_quantum_on_higher_core = false;
	}
#endif /* CONFIG_SCHED_EDGE */
	thread->th_bound_pset_id = THREAD_BOUND_PSET_NONE;
	thread->reason = AST_NONE;
	thread->sched_mode = TH_MODE_TIMESHARE;
	bzero(&thread->realtime, sizeof(thread->realtime));
	thread->last_made_runnable_time = 0;
	thread->state = TH_RUN;
	return thread;
}

void
impl_set_thread_sched_mode(test_thread_t thread, int mode)
{
	((thread_t)thread)->sched_mode = (sched_mode_t)mode;
}

bool
impl_get_thread_is_realtime(test_thread_t thread)
{
	return ((thread_t)thread)->sched_pri >= BASEPRI_RTQUEUES;
}

void
clutch_impl_set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	((thread_t)thread)->bound_processor = processor_array[cpu_id];
}

void
clutch_impl_cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	thread_t old_active_thread = processor_array[cpu_id]->active_thread;
	processor_array[cpu_id]->first_timeslice = TRUE;
	/* Equivalent logic of pset_commit_processor_to_new_thread() */
	pset_update_processor_state(processor_array[cpu_id]->processor_set, processor_array[cpu_id], PROCESSOR_RUNNING);
	if ((thread_t)thread == old_active_thread) {
		processor_state_update_from_running_thread(processor_array[cpu_id], thread, true);
	} else {
		processor_state_update_from_new_thread(processor_array[cpu_id], thread, true);
	}
	processor_array[cpu_id]->active_thread = (thread_t)thread;
	if (((thread_t) thread)->sched_pri >= BASEPRI_RTQUEUES) {
		bit_set(processor_array[cpu_id]->processor_set->realtime_map, cpu_id);
		processor_array[cpu_id]->deadline = ((thread_t) thread)->realtime.deadline;
	} else {
		bit_clear(processor_array[cpu_id]->processor_set->realtime_map, cpu_id);
		processor_array[cpu_id]->deadline = UINT64_MAX;
	}
}

test_thread_t
clutch_impl_cpu_clear_thread_current(int cpu_id)
{
	test_thread_t thread = processor_array[cpu_id]->active_thread;
	processor_array[cpu_id]->active_thread = processor_array[cpu_id]->idle_thread;
	bit_clear(processor_array[cpu_id]->processor_set->realtime_map, cpu_id);
	pset_update_processor_state(processor_array[cpu_id]->processor_set, processor_array[cpu_id], PROCESSOR_IDLE);
	processor_state_update_idle(processor_array[cpu_id]);
	return thread;
}

static bool
is_logged_clutch_trace_code(uint64_t clutch_trace_code)
{
	for (int i = 0; i < logged_trace_codes_ind; i++) {
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

static int
trace_code_to_ind(uint64_t trace_code)
{
	for (int i = 0; i < logged_trace_codes_ind; i++) {
		if (trace_code == logged_trace_codes[i]) {
			return i;
		}
	}
	return -1;
}

void
clutch_impl_log_tracepoint(uint64_t trace_code, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
	if (is_logged_trace_code(trace_code)) {
		int ind = trace_code_to_ind(KDBG_EXTRACT_CODE(trace_code));
		assert(ind >= 0);
		if (curr_tracepoint_inds[ind] < MAX_LOGGED_TRACEPOINTS) {
			logged_tracepoints[ind][curr_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 0] = KDBG_EXTRACT_CODE(trace_code);
			logged_tracepoints[ind][curr_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 1] = a1;
			logged_tracepoints[ind][curr_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 2] = a2;
			logged_tracepoints[ind][curr_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 3] = a3;
			logged_tracepoints[ind][curr_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 4] = a4;
		} else if (curr_tracepoint_inds[ind] == MAX_LOGGED_TRACEPOINTS) {
			printf("Ran out of pre-allocated memory to log tracepoints (%d points)...will no longer log tracepoints\n",
			    MAX_LOGGED_TRACEPOINTS);
		}
		curr_tracepoint_inds[ind]++;
	}
}

void
clutch_impl_pop_tracepoint(uint64_t clutch_trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4)
{
	int ind = trace_code_to_ind(clutch_trace_code);
	if (expect_tracepoint_inds[ind] >= curr_tracepoint_inds[ind]) {
		/* Indicate that there isn't a matching tracepoint drop found to consume */
		*arg1 = -1;
		*arg2 = -1;
		*arg3 = -1;
		*arg4 = -1;
		return;
	}
	assert(logged_tracepoints[ind][expect_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 0] == clutch_trace_code);
	*arg1 = logged_tracepoints[ind][expect_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 1];
	*arg2 = logged_tracepoints[ind][expect_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 2];
	*arg3 = logged_tracepoints[ind][expect_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 3];
	*arg4 = logged_tracepoints[ind][expect_tracepoint_inds[ind] * NUM_TRACEPOINT_FIELDS + 4];
	expect_tracepoint_inds[ind]++;
}

uint64_t
impl_get_thread_tid(test_thread_t thread)
{
	return ((thread_t)thread)->thread_id;
}

#pragma mark - Realtime

static test_thread_t
impl_dequeue_realtime_thread(processor_set_t pset)
{
	thread_t thread = rt_runq_dequeue(&pset->rt_runq);
	pset_update_rt_stealable_state(pset);
	return thread;
}

void
impl_set_thread_realtime(test_thread_t thread, uint32_t period, uint32_t computation, uint32_t constraint, bool preemptible, uint8_t priority_offset, uint64_t deadline)
{
	thread_t t = (thread_t) thread;
	t->realtime.period = period;
	t->realtime.computation = computation;
	t->realtime.constraint = constraint;
	t->realtime.preemptible = preemptible;
	t->realtime.priority_offset = priority_offset;
	t->realtime.deadline = deadline;
}

#pragma mark -- IPI Subsystem

#define MAX_LOGGED_IPIS 10000
typedef struct {
	int cpu_id;
	sched_ipi_type_t ipi_type;
} logged_ipi_t;
static logged_ipi_t logged_ipis[MAX_LOGGED_IPIS];
static uint32_t curr_ipi_ind = 0;
static uint32_t expect_ipi_ind = 0;

void
sched_ipi_perform(processor_t dst, sched_ipi_type_t ipi)
{
	/* Record the IPI type and where we sent it */
	logged_ipis[curr_ipi_ind].cpu_id = dst->cpu_id;
	logged_ipis[curr_ipi_ind].ipi_type = ipi;
	curr_ipi_ind++;
}

int
impl_pset_id_to_cpu_id(pset_id_t pset_id)
{
	return pset_array[pset_id]->cpu_set_low;
}

pset_id_t
impl_cpu_id_to_pset_id(int cpu_id)
{
	for (int p = 0; p < sched_num_psets; p++) {
		if (bit_test(pset_array[p]->cpu_bitmask, cpu_id)) {
			return (pset_id_t)p;
		}
	}
	assert(false); /* cpu does not belong to any pset? */
	return PSET_ID_INVALID;
}
