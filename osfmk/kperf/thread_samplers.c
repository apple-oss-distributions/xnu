/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/*  Sample thread data */

#include <kern/debug.h> /* panic */
#include <kern/thread.h> /* thread_* */
#include <kern/policy_internal.h> /* TASK_POLICY_* */
#include <mach/mach_types.h>
#include <sys/errno.h>

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/thread_samplers.h>
#include <kperf/ast.h>

#include <kern/monotonic.h>
#include <machine/monotonic.h>

extern boolean_t stackshot_thread_is_idle_worker_unsafe(thread_t thread);

/*
 * XXX Deprecated, use thread scheduling sampler instead.
 *
 * Taken from AppleProfileGetRunModeOfThread and CHUD.  Still here for
 * backwards compatibility.
 */

#define KPERF_TI_RUNNING   (1U << 0)
#define KPERF_TI_RUNNABLE  (1U << 1)
#define KPERF_TI_WAIT      (1U << 2)
#define KPERF_TI_UNINT     (1U << 3)
#define KPERF_TI_SUSP      (1U << 4)
#define KPERF_TI_TERMINATE (1U << 5)
#define KPERF_TI_IDLE      (1U << 6)

static uint32_t
kperf_thread_info_runmode_legacy(thread_t thread)
{
	uint32_t kperf_state = 0;
	int sched_state = thread->state;
	processor_t last_processor = thread->last_processor;

	if ((last_processor != PROCESSOR_NULL) && (thread == last_processor->active_thread)) {
		kperf_state |= KPERF_TI_RUNNING;
	}
	if (sched_state & TH_RUN) {
		kperf_state |= KPERF_TI_RUNNABLE;
	}
	if (sched_state & TH_WAIT) {
		kperf_state |= KPERF_TI_WAIT;
	}
	if (sched_state & TH_UNINT) {
		kperf_state |= KPERF_TI_UNINT;
	}
	if (sched_state & TH_SUSP) {
		kperf_state |= KPERF_TI_SUSP;
	}
	if (sched_state & TH_TERMINATE) {
		kperf_state |= KPERF_TI_TERMINATE;
	}
	if (sched_state & TH_IDLE) {
		kperf_state |= KPERF_TI_IDLE;
	}

#if defined(XNU_TARGET_OS_OSX)
	/* on desktop, if state is blank, leave not idle set */
	if (kperf_state == 0) {
		return TH_IDLE << 16;
	}
#endif /* defined(XNU_TARGET_OS_OSX) */

	/* high two bytes are inverted mask, low two bytes are normal */
	return ((~kperf_state & 0xffff) << 16) | (kperf_state & 0xffff);
}

void
kperf_thread_info_sample(struct kperf_thread_info *ti, struct kperf_context *context)
{
	thread_t cur_thread = context->cur_thread;

	BUF_INFO(PERF_TI_SAMPLE, (uintptr_t)thread_tid(cur_thread));

	ti->kpthi_pid = context->cur_pid;
	ti->kpthi_tid = thread_tid(cur_thread);
	ti->kpthi_dq_addr = thread_dispatchqaddr(cur_thread);
	ti->kpthi_runmode = kperf_thread_info_runmode_legacy(cur_thread);

	BUF_VERB(PERF_TI_SAMPLE | DBG_FUNC_END);
}

void
kperf_thread_info_log(struct kperf_thread_info *ti)
{
	BUF_DATA(PERF_TI_DATA, ti->kpthi_pid, ti->kpthi_tid /* K64-only */,
	    ti->kpthi_dq_addr, ti->kpthi_runmode);
}

/*
 * Scheduling information reports inputs and outputs of the scheduler state for
 * a thread.
 */

void
kperf_thread_scheduling_sample(struct kperf_thread_scheduling *thsc,
    struct kperf_context *context)
{
	assert(thsc != NULL);
	assert(context != NULL);

	thread_t thread = context->cur_thread;

	BUF_INFO(PERF_TI_SCHEDSAMPLE | DBG_FUNC_START, (uintptr_t)thread_tid(thread));

	struct recount_times_mach times = { 0 };
	if (thread == current_thread()) {
		boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
		times = recount_current_thread_times();
		ml_set_interrupts_enabled(interrupt_state);
	} else {
		times = recount_thread_times(thread);
	}
	thsc->kpthsc_user_time = times.rtm_user;
	thsc->kpthsc_system_time = times.rtm_system;

	thsc->kpthsc_runnable_time = timer_grab(&thread->runnable_timer);
	thsc->kpthsc_state = thread->state;
	thsc->kpthsc_base_priority = thread->base_pri;
	thsc->kpthsc_sched_priority = thread->sched_pri;
	thsc->kpthsc_effective_qos = thread->effective_policy.thep_qos;
	thsc->kpthsc_requested_qos = thread->requested_policy.thrp_qos;
	thsc->kpthsc_requested_qos_override = MAX(thread->requested_policy.thrp_qos_override,
	    thread->requested_policy.thrp_qos_workq_override);
	thsc->kpthsc_requested_qos_promote = thread->requested_policy.thrp_qos_promote;
	thsc->kpthsc_requested_qos_kevent_override = MAX(
		thread->requested_policy.thrp_qos_kevent_override,
		thread->requested_policy.thrp_qos_wlsvc_override);
	thsc->kpthsc_requested_qos_sync_ipc_override = THREAD_QOS_UNSPECIFIED;
	thsc->kpthsc_effective_latency_qos = thread->effective_policy.thep_latency_qos;

	BUF_INFO(PERF_TI_SCHEDSAMPLE | DBG_FUNC_END);
}


void
kperf_thread_scheduling_log(struct kperf_thread_scheduling *thsc)
{
	assert(thsc != NULL);
#if defined(__LP64__)
	BUF_DATA(PERF_TI_SCHEDDATA_2, thsc->kpthsc_user_time,
	    thsc->kpthsc_system_time,
	    (((uint64_t)thsc->kpthsc_base_priority) << 48)
	    | ((uint64_t)thsc->kpthsc_sched_priority << 32)
	    | ((uint64_t)(thsc->kpthsc_state & 0xff) << 24)
	    | (thsc->kpthsc_effective_qos << 6)
	    | (thsc->kpthsc_requested_qos << 3)
	    | thsc->kpthsc_requested_qos_override,
	    ((uint64_t)thsc->kpthsc_effective_latency_qos << 61)
	    | ((uint64_t)thsc->kpthsc_requested_qos_promote << 58)
	    | ((uint64_t)thsc->kpthsc_requested_qos_kevent_override << 55)
	    );
	BUF_DATA(PERF_TI_SCHEDDATA_3, thsc->kpthsc_runnable_time);
#else
	BUF_DATA(PERF_TI_SCHEDDATA1_32, UPPER_32(thsc->kpthsc_user_time),
	    LOWER_32(thsc->kpthsc_user_time),
	    UPPER_32(thsc->kpthsc_system_time),
	    LOWER_32(thsc->kpthsc_system_time)
	    );
	BUF_DATA(PERF_TI_SCHEDDATA2_32_2, (((uint32_t)thsc->kpthsc_base_priority) << 16)
	    | thsc->kpthsc_sched_priority,
	    ((thsc->kpthsc_state & 0xff) << 24)
	    | (thsc->kpthsc_effective_qos << 6)
	    | (thsc->kpthsc_requested_qos << 3)
	    | thsc->kpthsc_requested_qos_override,
	    ((uint32_t)thsc->kpthsc_effective_latency_qos << 29)
	    | ((uint32_t)thsc->kpthsc_requested_qos_promote << 26)
	    | ((uint32_t)thsc->kpthsc_requested_qos_kevent_override << 23)
	    );
	BUF_DATA(PERF_TI_SCHEDDATA3_32, UPPER_32(thsc->kpthsc_runnable_time),
	    LOWER_32(thsc->kpthsc_runnable_time));
#endif /* defined(__LP64__) */
}

/*
 * Snapshot information maintains parity with stackshot information for other,
 * miscellaneous information about threads.
 */

#define KPERF_THREAD_SNAPSHOT_DARWIN_BG    (1U << 0);
#define KPERF_THREAD_SNAPSHOT_PASSIVE_IO   (1U << 1);
#define KPERF_THREAD_SNAPSHOT_GFI          (1U << 2);
#define KPERF_THREAD_SNAPSHOT_IDLE_WQ      (1U << 3);
#define KPERF_THREAD_SNAPSHOT_EXCLAVES_RPC (1U << 4);
/* max is 1U << 7 */

void
kperf_thread_snapshot_sample(struct kperf_thread_snapshot *thsn,
    struct kperf_context *context)
{
	assert(thsn != NULL);
	assert(context != NULL);

	thread_t thread = context->cur_thread;

	BUF_INFO(PERF_TI_SNAPSAMPLE | DBG_FUNC_START, (uintptr_t)thread_tid(thread));

	thsn->kpthsn_last_made_runnable_time = thread->last_made_runnable_time;

	thsn->kpthsn_flags = 0;
	if (thread->effective_policy.thep_darwinbg) {
		thsn->kpthsn_flags |= KPERF_THREAD_SNAPSHOT_DARWIN_BG;
	}
	if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO)) {
		thsn->kpthsn_flags |= KPERF_THREAD_SNAPSHOT_PASSIVE_IO;
	}
	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
		thsn->kpthsn_flags |= KPERF_THREAD_SNAPSHOT_GFI
	}
	if (stackshot_thread_is_idle_worker_unsafe(thread)) {
		thsn->kpthsn_flags |= KPERF_THREAD_SNAPSHOT_IDLE_WQ;
	}
#if CONFIG_EXCLAVES
	if (thread->th_exclaves_state & TH_EXCLAVES_RPC) {
		thsn->kpthsn_flags |= KPERF_THREAD_SNAPSHOT_EXCLAVES_RPC;
	}
#endif /* CONFIG_EXCLAVES */

	thsn->kpthsn_suspend_count = thread->suspend_count;
	/*
	 * Only have room for 8-bits in the trace event, so truncate here.
	 */
	thsn->kpthsn_io_tier = (uint8_t)proc_get_effective_thread_policy(thread, TASK_POLICY_IO);

	BUF_VERB(PERF_TI_SNAPSAMPLE | DBG_FUNC_END);
}

void
kperf_thread_snapshot_log(struct kperf_thread_snapshot *thsn)
{
	assert(thsn != NULL);
#if defined(__LP64__)
	BUF_DATA(PERF_TI_SNAPDATA, thsn->kpthsn_flags | ((uint32_t)(thsn->kpthsn_suspend_count) << 8)
	    | (thsn->kpthsn_io_tier << 24),
	    thsn->kpthsn_last_made_runnable_time);
#else
	BUF_DATA(PERF_TI_SNAPDATA_32, thsn->kpthsn_flags | ((uint32_t)(thsn->kpthsn_suspend_count) << 8)
	    | (thsn->kpthsn_io_tier << 24),
	    UPPER_32(thsn->kpthsn_last_made_runnable_time),
	    LOWER_32(thsn->kpthsn_last_made_runnable_time));
#endif /* defined(__LP64__) */
}

/*
 * Dispatch information only contains the dispatch queue serial number from
 * libdispatch.
 *
 * It's a separate sampler because queue data must be copied in from user space.
 */

void
kperf_thread_dispatch_sample(struct kperf_thread_dispatch *thdi,
    struct kperf_context *context)
{
	assert(thdi != NULL);
	assert(context != NULL);

	thread_t thread = context->cur_thread;

	BUF_INFO(PERF_TI_DISPSAMPLE | DBG_FUNC_START,
	    (uintptr_t)thread_tid(thread));

	task_t task = get_threadtask(thread);
	size_t user_addr_size = task_has_64Bit_addr(task) ? 8 : 4;
	thdi->kpthdi_dq_serialno = 0;
	thdi->kpthdi_dq_label[0] = '\0';
	int error = 0;

	/*
	 * The dispatch queue address points to a struct that contains
	 * information about the dispatch queue.  Use task-level offsets to
	 * find the serial number and label of the dispatch queue.
	 */
	assert(task != kernel_task);
	uint64_t user_dq_key_addr = thread_dispatchqaddr(thread);
	if (user_dq_key_addr == 0) {
		error = ENOENT;
		goto out;
	}

	uint64_t user_dq_addr = 0;
	if ((error = copyin((user_addr_t)user_dq_key_addr, &user_dq_addr,
	    user_addr_size)) != 0) {
		goto out;
	}

	if (user_dq_addr == 0) {
		error = EINVAL;
		goto out;
	}

	uint64_t serialno_offset = get_task_dispatchqueue_serialno_offset(task);
	uint64_t user_dq_serialno_addr = 0;
	if (os_add_overflow(user_dq_addr, serialno_offset,
	    &user_dq_serialno_addr)) {
		error = EOVERFLOW;
		goto out;
	}

	if ((error = copyin((user_addr_t)user_dq_serialno_addr,
	    &(thdi->kpthdi_dq_serialno), user_addr_size)) != 0) {
		goto out;
	}

	uint64_t lbl_offset = get_task_dispatchqueue_label_offset(task);
	if (lbl_offset == 0) {
		error = ENOBUFS;
		goto out;
	}

	uint64_t user_dqlbl_ptr_addr = 0;
	if (os_add_overflow(user_dq_addr, lbl_offset, &user_dqlbl_ptr_addr)) {
		error = EOVERFLOW;
		goto out;
	}

	uint64_t user_dqlbl_addr = 0;
	/*
	 * The label isn't embedded in the struct -- it just holds a
	 * pointer to the label string, NUL-terminated.
	 */
	if ((error = copyin((user_addr_t)user_dqlbl_ptr_addr, &user_dqlbl_addr,
	    user_addr_size)) != 0) {
		goto out;
	}

	vm_size_t copied = 0;
	if ((error = copyinstr((user_addr_t)user_dqlbl_addr,
	    thdi->kpthdi_dq_label, sizeof(thdi->kpthdi_dq_label),
	    &copied)) != 0) {
		goto out;
	}
	thdi->kpthdi_dq_label[sizeof(thdi->kpthdi_dq_label) - 1] = '\0';

out:
	BUF_VERB(PERF_TI_DISPSAMPLE | DBG_FUNC_END, error);
}

int
kperf_thread_dispatch_pend(struct kperf_context *context,
    unsigned int actionid)
{
	return kperf_ast_pend(context->cur_thread, T_KPERF_AST_DISPATCH,
	           actionid);
}

void
kperf_thread_dispatch_log(struct kperf_thread_dispatch *thdi)
{
	assert(thdi != NULL);
#if defined(__LP64__)
	BUF_DATA(PERF_TI_DISPDATA, thdi->kpthdi_dq_serialno);
#else
	BUF_DATA(PERF_TI_DISPDATA_32, UPPER_32(thdi->kpthdi_dq_serialno),
	    LOWER_32(thdi->kpthdi_dq_serialno));
#endif /* defined(__LP64__) */

	if (thdi->kpthdi_dq_label[0] != '\0') {
		kernel_debug_string_simple(PERF_TI_DISPLABEL, thdi->kpthdi_dq_label);
	}
}

/*
 * A bit different from other samplers -- since logging disables interrupts,
 * it's a fine place to sample the thread counters.
 */
void
kperf_thread_inscyc_log(struct kperf_context *context)
{
#if CONFIG_PERVASIVE_CPI
	thread_t cur_thread = current_thread();

	if (context->cur_thread != cur_thread) {
		/* can't safely access another thread's counters */
		return;
	}

	struct recount_usage usage = { 0 };
	struct recount_usage perf_only = { 0 };
	recount_current_thread_usage_perf_only(&usage, &perf_only);
	BUF_DATA(PERF_TI_INSCYCDATA, recount_usage_instructions(&usage),
	    recount_usage_cycles(&usage), recount_usage_instructions(&perf_only),
	    recount_usage_cycles(&perf_only));
#else /* CONFIG_PERVASIVE_CPI */
#pragma unused(context)
#endif /* !CONFIG_PERVASIVE_CPI */
}
