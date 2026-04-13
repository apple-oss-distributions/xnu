// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include "sched_clutch_harness_impl.c"

void
impl_init_runqueue(void)
{
	/* Init runqueue */
	clutch_impl_init_topology(&single_core);
	assert(processor_avail_count == 1);
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
impl_set_thread_processor_bound(test_thread_t thread, int cpu_id)
{
	clutch_impl_set_thread_processor_bound(thread, cpu_id);
}

void
impl_cpu_set_thread_current(int cpu_id, test_thread_t thread)
{
	clutch_impl_cpu_set_thread_current(cpu_id, thread);
}

test_thread_t
impl_cpu_clear_thread_current(int cpu_id)
{
	return clutch_impl_cpu_clear_thread_current(cpu_id);
}

void
impl_cpu_enqueue_thread(int cpu_id, test_thread_t thread)
{
	if (impl_get_thread_is_realtime(thread)) {
		rt_runq_insert(processor_array[cpu_id], processor_array[cpu_id]->processor_set, (thread_t) thread);
	} else {
		sched_clutch_processor_enqueue(processor_array[cpu_id], (thread_t) thread, SCHED_TAILQ);
	}
}

test_thread_t
impl_cpu_dequeue_thread(int cpu_id)
{
	test_thread_t chosen_thread = sched_rt_choose_thread(processor_array[cpu_id]);
	if (chosen_thread != THREAD_NULL) {
		return chosen_thread;
	}
	/* No realtime threads. */
	return sched_clutch_choose_thread(processor_array[cpu_id], MINPRI, NULL, 0);
}

test_thread_t
impl_cpu_dequeue_thread_compare_current(int cpu_id)
{
	assert(processor_array[cpu_id]->active_thread != NULL);
	assert(impl_get_thread_is_realtime(processor_array[cpu_id]->active_thread) == false); /* should not be called when realtime threads are running */
	return sched_clutch_choose_thread(processor_array[cpu_id], MINPRI, processor_array[cpu_id]->active_thread, 0);
}

bool
impl_processor_csw_check(int cpu_id)
{
	ast_t preempt_ast = sched_clutch_processor_csw_check(processor_array[cpu_id]);
	return preempt_ast & AST_PREEMPT;
}

void
impl_pop_tracepoint(uint64_t clutch_trace_code, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4)
{
	clutch_impl_pop_tracepoint(clutch_trace_code, arg1, arg2, arg3, arg4);
}
