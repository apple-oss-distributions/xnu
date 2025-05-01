// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include "sched_clutch_harness_impl.c"

void
impl_init_runqueue(void)
{
	/* Init runqueue */
	clutch_impl_init_topology(single_core);
	curr_hw_topo = single_core;
	assert(processor_avail_count == 1);
	sched_clutch_init();
	sched_clutch_pset_init(&pset0);
	sched_clutch_processor_init(&cpu0);
	increment_mock_time(100);
	clutch_impl_init_params();
	clutch_impl_init_tracepoints();
}

struct thread_group *
impl_create_tg(int interactivity_score)
{
	return clutch_impl_create_tg(interactivity_score);
}

test_thread_t
impl_create_thread(int root_bucket, struct thread_group *tg, int pri)
{
	return clutch_impl_create_thread(root_bucket, tg, pri);
}

void
impl_set_thread_sched_mode(test_thread_t thread, int mode)
{
	clutch_impl_set_thread_sched_mode(thread, mode);
}

void
impl_set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	clutch_impl_set_thread_processor_bound(thread, cpu_id);
}

void
impl_cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	clutch_impl_cpu_set_thread_current(cpu_id, thread);
}

void
impl_cpu_clear_thread_current(int cpu_id)
{
	clutch_impl_cpu_clear_thread_current(cpu_id);
}

void
impl_cpu_enqueue_thread(int cpu_id, test_thread_t thread)
{
	sched_clutch_processor_enqueue(cpus[cpu_id], thread, SCHED_TAILQ);
}

test_thread_t
impl_cpu_dequeue_thread(int cpu_id)
{
	return sched_clutch_choose_thread(cpus[cpu_id], MINPRI, NULL, 0);
}

test_thread_t
impl_cpu_dequeue_thread_compare_current(int cpu_id)
{
	assert(cpus[cpu_id]->active_thread != NULL);
	return sched_clutch_choose_thread(cpus[cpu_id], MINPRI, cpus[cpu_id]->active_thread, 0);
}

bool
impl_processor_csw_check(int cpu_id)
{
	ast_t preempt_ast = sched_clutch_processor_csw_check(cpus[cpu_id]);
	return preempt_ast & AST_PREEMPT;
}

void
impl_pop_tracepoint(uint64_t *clutch_trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4)
{
	clutch_impl_pop_tracepoint(clutch_trace_code, arg1, arg2, arg3, arg4);
}
