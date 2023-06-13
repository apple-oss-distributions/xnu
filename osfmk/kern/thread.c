/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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
/*
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	kern/thread.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub
 *	Date:	1986
 *
 *	Thread management primitives implementation.
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <mach/time_value.h>
#include <mach/vm_param.h>

#include <machine/thread.h>
#include <machine/pal_routines.h>
#include <machine/limits.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <kern/extmod_statistics.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/restartable.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/coalition.h>
#include <kern/host.h>
#include <kern/zalloc.h>
#include <kern/assert.h>
#include <kern/exc_resource.h>
#include <kern/exc_guard.h>
#include <kern/telemetry.h>
#include <kern/policy_internal.h>
#include <kern/turnstile.h>
#include <kern/sched_clutch.h>
#include <kern/recount.h>
#include <kern/smr.h>
#include <kern/ast.h>
#include <kern/compact_id.h>

#include <corpses/task_corpse.h>
#if KPC
#include <kern/kpc.h>
#endif

#if CONFIG_PERVASIVE_CPI
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* CONFIG_PERVASIVE_CPI */

#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <bank/bank_types.h>

#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>
#include <sys/bsdtask_info.h>
#include <mach/sdt.h>
#include <san/kasan.h>
#include <san/kcov_stksz.h>

#include <stdatomic.h>

#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#include <arm64/proc_reg.h>
#endif /* defined(HAS_APPLE_PAC) */

/*
 * Exported interfaces
 */
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/mach_voucher_server.h>
#include <kern/policy_internal.h>

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

#include <pthread/workqueue_trace.h>

LCK_GRP_DECLARE(thread_lck_grp, "thread");

static SECURITY_READ_ONLY_LATE(zone_t) thread_zone;
ZONE_DEFINE_ID(ZONE_ID_THREAD_RO, "threads_ro", struct thread_ro, ZC_READONLY);

static void thread_port_with_flavor_no_senders(ipc_port_t, mach_port_mscount_t);

IPC_KOBJECT_DEFINE(IKOT_THREAD_CONTROL);
IPC_KOBJECT_DEFINE(IKOT_THREAD_READ,
    .iko_op_no_senders = thread_port_with_flavor_no_senders);
IPC_KOBJECT_DEFINE(IKOT_THREAD_INSPECT,
    .iko_op_no_senders = thread_port_with_flavor_no_senders);

static struct mpsc_daemon_queue thread_stack_queue;
static struct mpsc_daemon_queue thread_terminate_queue;
static struct mpsc_daemon_queue thread_deallocate_queue;
static struct mpsc_daemon_queue thread_exception_queue;
static struct mpsc_daemon_queue thread_backtrace_queue;

decl_simple_lock_data(static, crashed_threads_lock);
static queue_head_t             crashed_threads_queue;

struct thread_exception_elt {
	struct mpsc_queue_chain link;
	exception_type_t        exception_type;
	task_t                  exception_task;
	thread_t                exception_thread;
};

struct thread_backtrace_elt {
	struct mpsc_queue_chain link;
	exception_type_t        exception_type;
	kcdata_object_t         obj;
	exception_port_t        exc_ports[BT_EXC_PORTS_COUNT]; /* send rights */
};

static SECURITY_READ_ONLY_LATE(struct thread) thread_template = {
#if MACH_ASSERT
	.thread_magic               = THREAD_MAGIC,
#endif /* MACH_ASSERT */
	.wait_result                = THREAD_WAITING,
	.options                    = THREAD_ABORTSAFE,
	.state                      = TH_WAIT | TH_UNINT,
	.th_sched_bucket            = TH_BUCKET_RUN,
	.base_pri                   = BASEPRI_DEFAULT,
	.realtime.deadline          = UINT64_MAX,
	.last_made_runnable_time    = THREAD_NOT_RUNNABLE,
	.last_basepri_change_time   = THREAD_NOT_RUNNABLE,
#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	.pri_shift                  = INT8_MAX,
#endif
	/* timers are initialized in thread_bootstrap */
};

#define CTID_SIZE_BIT           20
#define CTID_MASK               ((1u << CTID_SIZE_BIT) - 1)
#define CTID_MAX_THREAD_NUMBER  (CTID_MASK - 1)
static_assert(CTID_MAX_THREAD_NUMBER <= COMPACT_ID_MAX);

#ifndef __LITTLE_ENDIAN__
#error "ctid relies on the ls bits of uint32_t to be populated"
#endif

__startup_data
static struct thread init_thread;
static SECURITY_READ_ONLY_LATE(uint32_t) ctid_nonce;
COMPACT_ID_TABLE_DEFINE(static, ctid_table);

__startup_func
static void
thread_zone_startup(void)
{
	size_t size = sizeof(struct thread);

#ifdef MACH_BSD
	size += roundup(uthread_size, _Alignof(struct thread));
#endif
	thread_zone = zone_create_ext("threads", size,
	    ZC_SEQUESTER | ZC_ZFREE_CLEARMEM, ZONE_ID_THREAD, NULL);
}
STARTUP(ZALLOC, STARTUP_RANK_FOURTH, thread_zone_startup);

static void thread_deallocate_enqueue(thread_t thread);
static void thread_deallocate_complete(thread_t thread);

static void ctid_table_remove(thread_t thread);
static void ctid_table_add(thread_t thread);
static void ctid_table_init(void);

#ifdef MACH_BSD
extern void proc_exit(void *);
extern mach_exception_data_type_t proc_encode_exit_exception_code(void *);
extern uint64_t get_dispatchqueue_offset_from_proc(void *);
extern uint64_t get_return_to_kernel_offset_from_proc(void *p);
extern uint64_t get_wq_quantum_offset_from_proc(void *);
extern int      proc_selfpid(void);
extern void     proc_name(int, char*, int);
extern char *   proc_name_address(void *p);
exception_type_t get_exception_from_corpse_crashinfo(kcdata_descriptor_t corpse_info);
extern void kdebug_proc_name_args(struct proc *proc, long args[static 4]);
#endif /* MACH_BSD */

extern bool bsdthread_part_of_cooperative_workqueue(struct uthread *uth);
extern int disable_exc_resource;
extern int audio_active;
extern int debug_task;
int thread_max = CONFIG_THREAD_MAX;     /* Max number of threads */
int task_threadmax = CONFIG_THREAD_MAX;

static uint64_t         thread_unique_id = 100;

struct _thread_ledger_indices thread_ledgers = { .cpu_time = -1 };
static ledger_template_t thread_ledger_template = NULL;
static void init_thread_ledgers(void);

#if CONFIG_JETSAM
void jetsam_on_ledger_cpulimit_exceeded(void);
#endif

extern int task_thread_soft_limit;

#if DEVELOPMENT || DEBUG
extern int exc_resource_threads_enabled;
#endif /* DEVELOPMENT || DEBUG */

/*
 * Level (in terms of percentage of the limit) at which the CPU usage monitor triggers telemetry.
 *
 * (ie when any thread's CPU consumption exceeds 70% of the limit, start taking user
 *  stacktraces, aka micro-stackshots)
 */
#define CPUMON_USTACKSHOTS_TRIGGER_DEFAULT_PCT 70

/* Percentage. Level at which we start gathering telemetry. */
static TUNABLE(uint8_t, cpumon_ustackshots_trigger_pct,
    "cpumon_ustackshots_trigger_pct", CPUMON_USTACKSHOTS_TRIGGER_DEFAULT_PCT);
void __attribute__((noinline)) SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU(void);
#if DEVELOPMENT || DEBUG
void __attribute__((noinline)) SENDING_NOTIFICATION__TASK_HAS_TOO_MANY_THREADS(task_t, int);
#endif /* DEVELOPMENT || DEBUG */

/*
 * The smallest interval over which we support limiting CPU consumption is 1ms
 */
#define MINIMUM_CPULIMIT_INTERVAL_MS 1

os_refgrp_decl(static, thread_refgrp, "thread", NULL);

static inline void
init_thread_from_template(thread_t thread)
{
	/*
	 * In general, struct thread isn't trivially-copyable, since it may
	 * contain pointers to thread-specific state.  This may be enforced at
	 * compile time on architectures that store authed + diversified
	 * pointers in machine_thread.
	 *
	 * In this specific case, where we're initializing a new thread from a
	 * thread_template, we know all diversified pointers are NULL; these are
	 * safe to bitwise copy.
	 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnontrivial-memaccess"
	memcpy(thread, &thread_template, sizeof(*thread));
#pragma clang diagnostic pop
}

static void
thread_ro_create(task_t parent_task, thread_t th, thread_ro_t tro_tpl)
{
#if __x86_64__
	th->t_task = parent_task;
#endif
	tro_tpl->tro_owner = th;
	tro_tpl->tro_task  = parent_task;
	th->t_tro = zalloc_ro(ZONE_ID_THREAD_RO, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	zalloc_ro_update_elem(ZONE_ID_THREAD_RO, th->t_tro, tro_tpl);
}

static void
thread_ro_destroy(thread_t th)
{
	thread_ro_t tro = get_thread_ro(th);
#if MACH_BSD
	struct ucred *cred = tro->tro_cred;
#endif

	zfree_ro(ZONE_ID_THREAD_RO, tro);
#if MACH_BSD
	if (cred) {
		uthread_cred_free(cred);
	}
#endif
}

#if MACH_BSD
extern void kauth_cred_set(struct ucred **, struct ucred *);

void
thread_ro_update_cred(thread_ro_t tro, struct ucred *ucred)
{
	struct ucred *my_cred = tro->tro_cred;
	if (my_cred != ucred) {
		kauth_cred_set(&my_cred, ucred);
		zalloc_ro_update_field(ZONE_ID_THREAD_RO, tro, tro_cred, &my_cred);
	}
}

void
thread_ro_update_flags(thread_ro_t tro, thread_ro_flags_t add, thread_ro_flags_t clr)
{
	thread_ro_flags_t flags = (tro->tro_flags & ~clr) | add;
	zalloc_ro_update_field(ZONE_ID_THREAD_RO, tro, tro_flags, &flags);
}
#endif

__startup_func
thread_t
thread_bootstrap(void)
{
	/*
	 *	Fill in a template thread for fast initialization.
	 */
	timer_init(&thread_template.runnable_timer);

	init_thread_from_template(&init_thread);
	/* fiddle with init thread to skip asserts in set_sched_pri */
	init_thread.sched_pri = MAXPRI_KERNEL;

	/*
	 * We can't quite use ctid yet, on ARM thread_bootstrap() is called
	 * before we can call random or anything,
	 * so we just make it barely work and it will get fixed up
	 * when the first thread is actually made.
	 */
	*compact_id_resolve(&ctid_table, 0) = &init_thread;
	init_thread.ctid = CTID_MASK;

	return &init_thread;
}

void
thread_machine_init_template(void)
{
	machine_thread_template_init(&thread_template);
}

void
thread_init(void)
{
	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */
	machine_thread_init();

	init_thread_ledgers();
}

boolean_t
thread_is_active(thread_t thread)
{
	return thread->active;
}

void
thread_corpse_continue(void)
{
	thread_t thread = current_thread();

	thread_terminate_internal(thread);

	/*
	 * Handle the thread termination directly
	 * here instead of returning to userspace.
	 */
	assert(thread->active == FALSE);
	thread_ast_clear(thread, AST_APC);
	thread_apc_ast(thread);

	panic("thread_corpse_continue");
	/*NOTREACHED*/
}

__dead2
static void
thread_terminate_continue(void)
{
	panic("thread_terminate_continue");
	/*NOTREACHED*/
}

/*
 *	thread_terminate_self:
 */
void
thread_terminate_self(void)
{
	thread_t    thread = current_thread();
	thread_ro_t tro    = get_thread_ro(thread);
	task_t      task   = tro->tro_task;
	void *bsd_info = get_bsdtask_info(task);
	int threadcnt;

	pal_thread_terminate_self(thread);

	DTRACE_PROC(lwp__exit);

	thread_mtx_lock(thread);

	ipc_thread_disable(thread);

	thread_mtx_unlock(thread);

	thread_sched_call(thread, NULL);

	spl_t s = splsched();
	thread_lock(thread);

	thread_depress_abort_locked(thread);

	/*
	 * Before we take the thread_lock right above,
	 * act_set_ast_reset_pcs() might not yet observe
	 * that the thread is inactive, and could have
	 * requested an IPI Ack.
	 *
	 * Once we unlock the thread, we know that
	 * act_set_ast_reset_pcs() can't fail to notice
	 * that thread->active is false,
	 * and won't set new ones.
	 */
	thread_reset_pcs_ack_IPI(thread);

	thread_unlock(thread);

	splx(s);

#if CONFIG_TASKWATCH
	thead_remove_taskwatch(thread);
#endif /* CONFIG_TASKWATCH */

	work_interval_thread_terminate(thread);

	thread_mtx_lock(thread);

	thread_policy_reset(thread);

	thread_mtx_unlock(thread);

	assert(thread->th_work_interval == NULL);

	bank_swap_thread_bank_ledger(thread, NULL);

	if (kdebug_enable && bsd_hasthreadname(get_bsdthread_info(thread))) {
		char threadname[MAXTHREADNAMESIZE];
		bsd_getthreadname(get_bsdthread_info(thread), threadname);
		kernel_debug_string_simple(TRACE_STRING_THREADNAME_PREV, threadname);
	}

	uthread_cleanup(get_bsdthread_info(thread), tro);

	if (kdebug_enable && bsd_info && !task_is_exec_copy(task)) {
		/* trace out pid before we sign off */
		long dbg_arg1 = 0;
		long dbg_arg2 = 0;

		kdbg_trace_data(get_bsdtask_info(task), &dbg_arg1, &dbg_arg2);
#if CONFIG_PERVASIVE_CPI
		if (kdebug_debugid_enabled(DBG_MT_INSTRS_CYCLES_THR_EXIT)) {
			struct recount_usage usage = { 0 };
			struct recount_usage perf_only = { 0 };
			boolean_t intrs_end = ml_set_interrupts_enabled(FALSE);
			recount_current_thread_usage_perf_only(&usage, &perf_only);
			ml_set_interrupts_enabled(intrs_end);
			KDBG_RELEASE(DBG_MT_INSTRS_CYCLES_THR_EXIT,
			    usage.ru_instructions,
			    usage.ru_cycles,
			    usage.ru_system_time_mach,
			    usage.ru_user_time_mach);
#if __AMP__
			KDBG_RELEASE(DBG_MT_P_INSTRS_CYCLES_THR_EXIT,
			    perf_only.ru_instructions,
			    perf_only.ru_cycles,
			    perf_only.ru_system_time_mach,
			    perf_only.ru_user_time_mach);

#endif // __AMP__
		}
#endif/* CONFIG_PERVASIVE_CPI */
		KDBG_RELEASE(TRACE_DATA_THREAD_TERMINATE_PID, dbg_arg1, dbg_arg2);
	}

	/*
	 * After this subtraction, this thread should never access
	 * task->bsd_info unless it got 0 back from the os_atomic_dec.  It
	 * could be racing with other threads to be the last thread in the
	 * process, and the last thread in the process will tear down the proc
	 * structure and zero-out task->bsd_info.
	 */
	threadcnt = os_atomic_dec(&task->active_thread_count, relaxed);

#if CONFIG_COALITIONS
	/*
	 * Leave the coalitions when last thread of task is exiting and the
	 * task is not a corpse.
	 */
	if (threadcnt == 0 && !task->corpse_info) {
		coalitions_remove_task(task);
	}
#endif

	/*
	 * If we are the last thread to terminate and the task is
	 * associated with a BSD process, perform BSD process exit.
	 */
	if (threadcnt == 0 && bsd_info != NULL) {
		mach_exception_data_type_t subcode = 0;
		if (kdebug_enable) {
			/* since we're the last thread in this process, trace out the command name too */
			long args[4] = { 0 };
			kdebug_proc_name_args(bsd_info, args);
#if CONFIG_PERVASIVE_CPI
			if (kdebug_debugid_enabled(DBG_MT_INSTRS_CYCLES_PROC_EXIT)) {
				struct recount_usage usage = { 0 };
				struct recount_usage perf_only = { 0 };
				recount_current_task_usage_perf_only(&usage, &perf_only);
				KDBG_RELEASE(DBG_MT_INSTRS_CYCLES_PROC_EXIT,
				    usage.ru_instructions,
				    usage.ru_cycles,
				    usage.ru_system_time_mach,
				    usage.ru_user_time_mach);
#if __AMP__
				KDBG_RELEASE(DBG_MT_P_INSTRS_CYCLES_PROC_EXIT,
				    perf_only.ru_instructions,
				    perf_only.ru_cycles,
				    perf_only.ru_system_time_mach,
				    perf_only.ru_user_time_mach);
#endif // __AMP__
			}
#endif/* CONFIG_PERVASIVE_CPI */
			KDBG_RELEASE(TRACE_STRING_PROC_EXIT, args[0], args[1], args[2], args[3]);
		}

		/* Get the exit reason before proc_exit */
		subcode = proc_encode_exit_exception_code(bsd_info);
		proc_exit(bsd_info);
		bsd_info = NULL;
		/*
		 * if there is crash info in task
		 * then do the deliver action since this is
		 * last thread for this task.
		 */
		if (task->corpse_info) {
			/* reset all except task name port */
			ipc_task_reset(task);
			/* enable all task ports (name port unchanged) */
			ipc_task_enable(task);
			exception_type_t etype = get_exception_from_corpse_crashinfo(task->corpse_info);
			task_deliver_crash_notification(task, current_thread(), etype, subcode);
		}
	}

	if (threadcnt == 0) {
		task_lock(task);
		if (task_is_a_corpse_fork(task)) {
			thread_wakeup((event_t)&task->active_thread_count);
		}
		task_unlock(task);
	}

	s = splsched();
	thread_lock(thread);

	/*
	 * Ensure that the depress timer is no longer enqueued,
	 * so the timer can be safely deallocated
	 *
	 * TODO: build timer_call_cancel_wait
	 */

	assert((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) == 0);

	uint32_t delay_us = 1;

	while (thread->depress_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(delay_us++);

		if (delay_us > USEC_PER_SEC) {
			panic("depress timer failed to inactivate!"
			    "thread: %p depress_timer_active: %d",
			    thread, thread->depress_timer_active);
		}

		s = splsched();
		thread_lock(thread);
	}

	/*
	 *	Cancel wait timer, and wait for
	 *	concurrent expirations.
	 */
	if (thread->wait_timer_armed) {
		thread->wait_timer_armed = false;

		if (timer_call_cancel(thread->wait_timer)) {
			thread->wait_timer_active--;
		}
	}

	delay_us = 1;

	while (thread->wait_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(delay_us++);

		if (delay_us > USEC_PER_SEC) {
			panic("wait timer failed to inactivate!"
			    "thread: %p, wait_timer_active: %d, "
			    "wait_timer_armed: %d",
			    thread, thread->wait_timer_active,
			    thread->wait_timer_armed);
		}

		s = splsched();
		thread_lock(thread);
	}

	/*
	 *	If there is a reserved stack, release it.
	 */
	if (thread->reserved_stack != 0) {
		stack_free_reserved(thread);
		thread->reserved_stack = 0;
	}

	/*
	 *	Mark thread as terminating, and block.
	 */
	thread->state |= TH_TERMINATE;
	thread_mark_wait_locked(thread, THREAD_UNINT);

	assert(thread->th_work_interval_flags == TH_WORK_INTERVAL_FLAGS_NONE);
	assert(thread->kern_promotion_schedpri == 0);
	if (thread->rwlock_count > 0) {
		panic("rwlock_count is %d for thread %p, possibly it still holds a rwlock", thread->rwlock_count, thread);
	}
	assert(thread->priority_floor_count == 0);
	assert(thread->handoff_thread == THREAD_NULL);
	assert(thread->th_work_interval == NULL);
	assert(thread->t_rr_state.trr_value == 0);

	assert3u(0, ==, thread->sched_flags &
	    (TH_SFLAG_WAITQ_PROMOTED |
	    TH_SFLAG_RW_PROMOTED |
	    TH_SFLAG_EXEC_PROMOTED |
	    TH_SFLAG_FLOOR_PROMOTED |
	    TH_SFLAG_PROMOTED |
	    TH_SFLAG_DEPRESS));

	thread_unlock(thread);
	/* splsched */

	thread_block((thread_continue_t)thread_terminate_continue);
	/*NOTREACHED*/
}

static bool
thread_ref_release(thread_t thread)
{
	if (thread == THREAD_NULL) {
		return false;
	}

	assert_thread_magic(thread);

	return os_ref_release_raw(&thread->ref_count, &thread_refgrp) == 0;
}

/* Drop a thread refcount safely without triggering a zfree */
void
thread_deallocate_safe(thread_t thread)
{
	if (__improbable(thread_ref_release(thread))) {
		/* enqueue the thread for thread deallocate deamon to call thread_deallocate_complete */
		thread_deallocate_enqueue(thread);
	}
}

void
thread_deallocate(thread_t thread)
{
	if (__improbable(thread_ref_release(thread))) {
		thread_deallocate_complete(thread);
	}
}

void
thread_deallocate_complete(
	thread_t                        thread)
{
	task_t                          task;

	assert_thread_magic(thread);

	assert(os_ref_get_count_raw(&thread->ref_count) == 0);

	if (!(thread->state & TH_TERMINATE2)) {
		panic("thread_deallocate: thread not properly terminated");
	}

	assert(thread->runq == PROCESSOR_NULL);
	assert(!(thread->state & TH_WAKING));

#if KPC
	kpc_thread_destroy(thread);
#endif /* KPC */

	ipc_thread_terminate(thread);

	proc_thread_qos_deallocate(thread);

	task = get_threadtask(thread);

#ifdef MACH_BSD
	uthread_destroy(get_bsdthread_info(thread));
#endif /* MACH_BSD */

	if (thread->t_ledger) {
		ledger_dereference(thread->t_ledger);
	}
	if (thread->t_threadledger) {
		ledger_dereference(thread->t_threadledger);
	}

	assert(thread->turnstile != TURNSTILE_NULL);
	if (thread->turnstile) {
		turnstile_deallocate(thread->turnstile);
	}
	turnstile_compact_id_put(thread->ctsid);

	if (IPC_VOUCHER_NULL != thread->ith_voucher) {
		ipc_voucher_release(thread->ith_voucher);
	}

	kfree_data(thread->thread_io_stats, sizeof(struct io_stat_info));
#if CONFIG_PREADOPT_TG
	if (thread->old_preadopt_thread_group) {
		thread_group_release(thread->old_preadopt_thread_group);
	}

	if (thread->preadopt_thread_group) {
		thread_group_release(thread->preadopt_thread_group);
	}
#endif /* CONFIG_PREADOPT_TG */

	if (thread->kernel_stack != 0) {
		stack_free(thread);
	}

	recount_thread_deinit(&thread->th_recount);

	lck_mtx_destroy(&thread->mutex, &thread_lck_grp);
	machine_thread_destroy(thread);

	task_deallocate_grp(task, TASK_GRP_INTERNAL);

#if MACH_ASSERT
	assert_thread_magic(thread);
	thread->thread_magic = 0;
#endif /* MACH_ASSERT */

	lck_mtx_lock(&tasks_threads_lock);
	assert(terminated_threads_count > 0);
	queue_remove(&terminated_threads, thread, thread_t, threads);
	terminated_threads_count--;
	lck_mtx_unlock(&tasks_threads_lock);

	timer_call_free(thread->depress_timer);
	timer_call_free(thread->wait_timer);

	ctid_table_remove(thread);

	thread_ro_destroy(thread);
	zfree(thread_zone, thread);
}

/*
 *	thread_inspect_deallocate:
 *
 *	Drop a thread inspection reference.
 */
void
thread_inspect_deallocate(
	thread_inspect_t                thread_inspect)
{
	return thread_deallocate((thread_t)thread_inspect);
}

/*
 *	thread_read_deallocate:
 *
 *	Drop a reference on thread read port.
 */
void
thread_read_deallocate(
	thread_read_t                thread_read)
{
	return thread_deallocate((thread_t)thread_read);
}


/*
 *	thread_exception_queue_invoke:
 *
 *	Deliver EXC_{RESOURCE,GUARD} exception
 */
static void
thread_exception_queue_invoke(mpsc_queue_chain_t elm,
    __assert_only mpsc_daemon_queue_t dq)
{
	struct thread_exception_elt *elt;
	task_t task;
	thread_t thread;
	exception_type_t etype;

	assert(dq == &thread_exception_queue);
	elt = mpsc_queue_element(elm, struct thread_exception_elt, link);

	etype = elt->exception_type;
	task = elt->exception_task;
	thread = elt->exception_thread;
	assert_thread_magic(thread);

	kfree_type(struct thread_exception_elt, elt);

	/* wait for all the threads in the task to terminate */
	task_lock(task);
	task_wait_till_threads_terminate_locked(task);
	task_unlock(task);

	/* Consumes the task ref returned by task_generate_corpse_internal */
	task_deallocate(task);
	/* Consumes the thread ref returned by task_generate_corpse_internal */
	thread_deallocate(thread);

	/* Deliver the notification, also clears the corpse. */
	task_deliver_crash_notification(task, thread, etype, 0);
}

static void
thread_backtrace_queue_invoke(mpsc_queue_chain_t elm,
    __assert_only mpsc_daemon_queue_t dq)
{
	struct thread_backtrace_elt *elt;
	kcdata_object_t obj;
	exception_port_t exc_ports[BT_EXC_PORTS_COUNT]; /* send rights */
	exception_type_t etype;

	assert(dq == &thread_backtrace_queue);
	elt = mpsc_queue_element(elm, struct thread_backtrace_elt, link);

	obj = elt->obj;
	memcpy(exc_ports, elt->exc_ports, sizeof(ipc_port_t) * BT_EXC_PORTS_COUNT);
	etype = elt->exception_type;

	kfree_type(struct thread_backtrace_elt, elt);

	/* Deliver to backtrace exception ports */
	exception_deliver_backtrace(obj, exc_ports, etype);

	/*
	 * Release port right and kcdata object refs given by
	 * task_enqueue_exception_with_corpse()
	 */

	for (unsigned int i = 0; i < BT_EXC_PORTS_COUNT; i++) {
		ipc_port_release_send(exc_ports[i]);
	}

	kcdata_object_release(obj);
}

/*
 *	thread_exception_enqueue:
 *
 *	Enqueue a corpse port to be delivered an EXC_{RESOURCE,GUARD}.
 */
void
thread_exception_enqueue(
	task_t          task,
	thread_t        thread,
	exception_type_t etype)
{
	assert(EXC_RESOURCE == etype || EXC_GUARD == etype);
	struct thread_exception_elt *elt = kalloc_type(struct thread_exception_elt, Z_WAITOK | Z_NOFAIL);
	elt->exception_type = etype;
	elt->exception_task = task;
	elt->exception_thread = thread;

	mpsc_daemon_enqueue(&thread_exception_queue, &elt->link,
	    MPSC_QUEUE_DISABLE_PREEMPTION);
}

void
thread_backtrace_enqueue(
	kcdata_object_t  obj,
	exception_port_t ports[static BT_EXC_PORTS_COUNT],
	exception_type_t etype)
{
	struct thread_backtrace_elt *elt = kalloc_type(struct thread_backtrace_elt, Z_WAITOK | Z_NOFAIL);
	elt->obj = obj;
	elt->exception_type = etype;

	memcpy(elt->exc_ports, ports, sizeof(ipc_port_t) * BT_EXC_PORTS_COUNT);

	mpsc_daemon_enqueue(&thread_backtrace_queue, &elt->link,
	    MPSC_QUEUE_DISABLE_PREEMPTION);
}

/*
 *	thread_copy_resource_info
 *
 *	Copy the resource info counters from source
 *	thread to destination thread.
 */
void
thread_copy_resource_info(
	thread_t dst_thread,
	thread_t src_thread)
{
	dst_thread->c_switch = src_thread->c_switch;
	dst_thread->p_switch = src_thread->p_switch;
	dst_thread->ps_switch = src_thread->ps_switch;
	dst_thread->sched_time_save = src_thread->sched_time_save;
	dst_thread->runnable_timer = src_thread->runnable_timer;
	dst_thread->vtimer_user_save = src_thread->vtimer_user_save;
	dst_thread->vtimer_prof_save = src_thread->vtimer_prof_save;
	dst_thread->vtimer_rlim_save = src_thread->vtimer_rlim_save;
	dst_thread->vtimer_qos_save = src_thread->vtimer_qos_save;
	dst_thread->syscalls_unix = src_thread->syscalls_unix;
	dst_thread->syscalls_mach = src_thread->syscalls_mach;
	ledger_rollup(dst_thread->t_threadledger, src_thread->t_threadledger);
	recount_thread_copy(&dst_thread->th_recount, &src_thread->th_recount);
	*dst_thread->thread_io_stats = *src_thread->thread_io_stats;
}

static void
thread_terminate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	thread_t thread = mpsc_queue_element(e, struct thread, mpsc_links);
	task_t task = get_threadtask(thread);

	assert(dq == &thread_terminate_queue);

	task_lock(task);

	/*
	 * if marked for crash reporting, skip reaping.
	 * The corpse delivery thread will clear bit and enqueue
	 * for reaping when done
	 *
	 * Note: the inspection field is set under the task lock
	 *
	 * FIXME[mad]: why enqueue for termination before `inspection` is false ?
	 */
	if (__improbable(thread->inspection)) {
		simple_lock(&crashed_threads_lock, &thread_lck_grp);
		task_unlock(task);

		enqueue_tail(&crashed_threads_queue, &thread->runq_links);
		simple_unlock(&crashed_threads_lock);
		return;
	}

	recount_task_rollup_thread(&task->tk_recount, &thread->th_recount);

	task->total_runnable_time += timer_grab(&thread->runnable_timer);
	task->c_switch += thread->c_switch;
	task->p_switch += thread->p_switch;
	task->ps_switch += thread->ps_switch;

	task->syscalls_unix += thread->syscalls_unix;
	task->syscalls_mach += thread->syscalls_mach;

	task->task_timer_wakeups_bin_1 += thread->thread_timer_wakeups_bin_1;
	task->task_timer_wakeups_bin_2 += thread->thread_timer_wakeups_bin_2;
	task->task_gpu_ns += ml_gpu_stat(thread);
	task->decompressions += thread->decompressions;

	thread_update_qos_cpu_time(thread);

	queue_remove(&task->threads, thread, thread_t, task_threads);
	task->thread_count--;

	/*
	 * If the task is being halted, and there is only one thread
	 * left in the task after this one, then wakeup that thread.
	 */
	if (task->thread_count == 1 && task->halting) {
		thread_wakeup((event_t)&task->halting);
	}

	task_unlock(task);

	lck_mtx_lock(&tasks_threads_lock);
	queue_remove(&threads, thread, thread_t, threads);
	threads_count--;
	queue_enter(&terminated_threads, thread, thread_t, threads);
	terminated_threads_count++;
	lck_mtx_unlock(&tasks_threads_lock);

#if MACH_BSD
	/*
	 * The thread no longer counts against the task's thread count,
	 * we can now wake up any pending joiner.
	 *
	 * Note that the inheritor will be set to `thread` which is
	 * incorrect once it is on the termination queue, however
	 * the termination queue runs at MINPRI_KERNEL which is higher
	 * than any user thread, so this isn't a priority inversion.
	 */
	if (thread_get_tag(thread) & THREAD_TAG_USER_JOIN) {
		struct uthread *uth = get_bsdthread_info(thread);
		mach_port_name_t kport = uthread_joiner_port(uth);

		/*
		 * Clear the port low two bits to tell pthread that thread is gone.
		 */
#ifndef NO_PORT_GEN
		kport &= ~MACH_PORT_MAKE(0, IE_BITS_GEN_MASK + IE_BITS_GEN_ONE);
#else
		kport |= MACH_PORT_MAKE(0, ~(IE_BITS_GEN_MASK + IE_BITS_GEN_ONE));
#endif
		(void)copyoutmap_atomic32(task->map, kport,
		    uthread_joiner_address(uth));
		uthread_joiner_wake(task, uth);
	}
#endif

	thread_deallocate(thread);
}

static void
thread_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	thread_t thread = mpsc_queue_element(e, struct thread, mpsc_links);

	assert(dq == &thread_deallocate_queue);

	thread_deallocate_complete(thread);
}

/*
 *	thread_terminate_enqueue:
 *
 *	Enqueue a terminating thread for final disposition.
 *
 *	Called at splsched.
 */
void
thread_terminate_enqueue(
	thread_t                thread)
{
	KDBG_RELEASE(TRACE_DATA_THREAD_TERMINATE, thread->thread_id);

	mpsc_daemon_enqueue(&thread_terminate_queue, &thread->mpsc_links,
	    MPSC_QUEUE_DISABLE_PREEMPTION);
}

/*
 *	thread_deallocate_enqueue:
 *
 *	Enqueue a thread for final deallocation.
 */
static void
thread_deallocate_enqueue(
	thread_t                thread)
{
	mpsc_daemon_enqueue(&thread_deallocate_queue, &thread->mpsc_links,
	    MPSC_QUEUE_DISABLE_PREEMPTION);
}

/*
 * thread_terminate_crashed_threads:
 * walk the list of crashed threads and put back set of threads
 * who are no longer being inspected.
 */
void
thread_terminate_crashed_threads(void)
{
	thread_t th_remove;

	simple_lock(&crashed_threads_lock, &thread_lck_grp);
	/*
	 * loop through the crashed threads queue
	 * to put any threads that are not being inspected anymore
	 */

	qe_foreach_element_safe(th_remove, &crashed_threads_queue, runq_links) {
		/* make sure current_thread is never in crashed queue */
		assert(th_remove != current_thread());

		if (th_remove->inspection == FALSE) {
			remqueue(&th_remove->runq_links);
			mpsc_daemon_enqueue(&thread_terminate_queue, &th_remove->mpsc_links,
			    MPSC_QUEUE_NONE);
		}
	}

	simple_unlock(&crashed_threads_lock);
}

/*
 *	thread_stack_queue_invoke:
 *
 *	Perform stack allocation as required due to
 *	invoke failures.
 */
static void
thread_stack_queue_invoke(mpsc_queue_chain_t elm,
    __assert_only mpsc_daemon_queue_t dq)
{
	thread_t thread = mpsc_queue_element(elm, struct thread, mpsc_links);

	assert(dq == &thread_stack_queue);

	/* allocate stack with interrupts enabled so that we can call into VM */
	stack_alloc(thread);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_WAIT) | DBG_FUNC_END, thread_tid(thread), 0, 0, 0, 0);

	spl_t s = splsched();
	thread_lock(thread);
	thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	thread_unlock(thread);
	splx(s);
}

/*
 *	thread_stack_enqueue:
 *
 *	Enqueue a thread for stack allocation.
 *
 *	Called at splsched.
 */
void
thread_stack_enqueue(
	thread_t                thread)
{
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_WAIT) | DBG_FUNC_START, thread_tid(thread), 0, 0, 0, 0);
	assert_thread_magic(thread);

	mpsc_daemon_enqueue(&thread_stack_queue, &thread->mpsc_links,
	    MPSC_QUEUE_DISABLE_PREEMPTION);
}

void
thread_daemon_init(void)
{
	kern_return_t   result;

	thread_deallocate_daemon_init();

	thread_deallocate_daemon_register_queue(&thread_terminate_queue,
	    thread_terminate_queue_invoke);

	thread_deallocate_daemon_register_queue(&thread_deallocate_queue,
	    thread_deallocate_queue_invoke);

	smr_register_mpsc_queue();

	ipc_object_deallocate_register_queue();

	simple_lock_init(&crashed_threads_lock, 0);
	queue_init(&crashed_threads_queue);

	result = mpsc_daemon_queue_init_with_thread(&thread_stack_queue,
	    thread_stack_queue_invoke, BASEPRI_PREEMPT_HIGH,
	    "daemon.thread-stack", MPSC_DAEMON_INIT_NONE);
	if (result != KERN_SUCCESS) {
		panic("thread_daemon_init: thread_stack_daemon");
	}

	result = mpsc_daemon_queue_init_with_thread(&thread_exception_queue,
	    thread_exception_queue_invoke, MINPRI_KERNEL,
	    "daemon.thread-exception", MPSC_DAEMON_INIT_NONE);

	if (result != KERN_SUCCESS) {
		panic("thread_daemon_init: thread_exception_daemon");
	}

	result = mpsc_daemon_queue_init_with_thread(&thread_backtrace_queue,
	    thread_backtrace_queue_invoke, MINPRI_KERNEL,
	    "daemon.thread-backtrace", MPSC_DAEMON_INIT_NONE);

	if (result != KERN_SUCCESS) {
		panic("thread_daemon_init: thread_backtrace_daemon");
	}
}

__options_decl(thread_create_internal_options_t, uint32_t, {
	TH_OPTION_NONE          = 0x00,
	TH_OPTION_NOSUSP        = 0x02,
	TH_OPTION_WORKQ         = 0x04,
	TH_OPTION_MAINTHREAD    = 0x08,
});

void
main_thread_set_immovable_pinned(thread_t thread)
{
	ipc_main_thread_set_immovable_pinned(thread);
}

/*
 * Create a new thread.
 * Doesn't start the thread running.
 *
 * Task and tasks_threads_lock are returned locked on success.
 */
static kern_return_t
thread_create_internal(
	task_t                                  parent_task,
	integer_t                               priority,
	thread_continue_t                       continuation,
	void                                    *parameter,
	thread_create_internal_options_t        options,
	thread_t                                *out_thread)
{
	thread_t                  new_thread;
	ipc_thread_init_options_t init_options = IPC_THREAD_INIT_NONE;
	struct thread_ro          tro_tpl = { };
	bool first_thread = false;
	kern_return_t kr = KERN_FAILURE;

	/*
	 *	Allocate a thread and initialize static fields
	 */
	new_thread = zalloc_flags(thread_zone, Z_WAITOK | Z_NOFAIL);

	if (__improbable(current_thread() == &init_thread)) {
		/*
		 * The first thread ever is a global, but because we want to be
		 * able to zone_id_require() threads, we have to stop using the
		 * global piece of memory we used to boostrap the kernel and
		 * jump to a proper thread from a zone.
		 *
		 * This is why that one thread will inherit its original
		 * state differently.
		 *
		 * Also remember this thread in `vm_pageout_scan_thread`
		 * as this is what the first thread ever becomes.
		 *
		 * Also pre-warm the depress timer since the VM pageout scan
		 * daemon might need to use it.
		 */
		assert(vm_pageout_scan_thread == THREAD_NULL);
		vm_pageout_scan_thread = new_thread;

		first_thread = true;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnontrivial-memaccess"
		/* work around 74481146 */
		memcpy(new_thread, &init_thread, sizeof(*new_thread));
#pragma clang diagnostic pop

		/*
		 * Make the ctid table functional
		 */
		ctid_table_init();
		new_thread->ctid = 0;
	} else {
		init_thread_from_template(new_thread);
	}

	if (options & TH_OPTION_MAINTHREAD) {
		init_options |= IPC_THREAD_INIT_MAINTHREAD;
	}

	os_ref_init_count_raw(&new_thread->ref_count, &thread_refgrp, 2);
	machine_thread_create(new_thread, parent_task, first_thread);

	machine_thread_process_signature(new_thread, parent_task);

#ifdef MACH_BSD
	uthread_init(parent_task, get_bsdthread_info(new_thread),
	    &tro_tpl, (options & TH_OPTION_WORKQ) != 0);
	if (!task_is_a_corpse(parent_task)) {
		/*
		 * uthread_init will set tro_cred (with a +1)
		 * and tro_proc for live tasks.
		 */
		assert(tro_tpl.tro_cred && tro_tpl.tro_proc);
	}
#endif  /* MACH_BSD */

	thread_lock_init(new_thread);
	wake_lock_init(new_thread);

	lck_mtx_init(&new_thread->mutex, &thread_lck_grp, LCK_ATTR_NULL);

	ipc_thread_init(parent_task, new_thread, &tro_tpl, init_options);

	thread_ro_create(parent_task, new_thread, &tro_tpl);

	new_thread->continuation = continuation;
	new_thread->parameter = parameter;
	new_thread->inheritor_flags = TURNSTILE_UPDATE_FLAGS_NONE;
	new_thread->requested_policy = default_thread_requested_policy;
	priority_queue_init(&new_thread->sched_inheritor_queue);
	priority_queue_init(&new_thread->base_inheritor_queue);
#if CONFIG_SCHED_CLUTCH
	priority_queue_entry_init(&new_thread->th_clutch_runq_link);
	priority_queue_entry_init(&new_thread->th_clutch_pri_link);
#endif /* CONFIG_SCHED_CLUTCH */

#if CONFIG_SCHED_EDGE
	new_thread->th_bound_cluster_enqueued = false;
	for (cluster_shared_rsrc_type_t shared_rsrc_type = CLUSTER_SHARED_RSRC_TYPE_MIN; shared_rsrc_type < CLUSTER_SHARED_RSRC_TYPE_COUNT; shared_rsrc_type++) {
		new_thread->th_shared_rsrc_enqueued[shared_rsrc_type] = false;
		new_thread->th_shared_rsrc_heavy_user[shared_rsrc_type] = false;
		new_thread->th_shared_rsrc_heavy_perf_control[shared_rsrc_type] = false;
	}
#endif /* CONFIG_SCHED_EDGE */
	new_thread->th_bound_cluster_id = THREAD_BOUND_CLUSTER_NONE;

	/* Allocate I/O Statistics structure */
	new_thread->thread_io_stats = kalloc_data(sizeof(struct io_stat_info),
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

#if KASAN_CLASSIC
	kasan_init_thread(&new_thread->kasan_data);
#endif /* KASAN_CLASSIC */

#if CONFIG_KCOV
	kcov_init_thread(&new_thread->kcov_data);
#endif

#if CONFIG_IOSCHED
	/* Clear out the I/O Scheduling info for AppleFSCompression */
	new_thread->decmp_upl = NULL;
#endif /* CONFIG_IOSCHED */

	new_thread->thread_region_page_shift = 0;

#if DEVELOPMENT || DEBUG
	task_lock(parent_task);
	uint16_t thread_limit = parent_task->task_thread_limit;
	if (exc_resource_threads_enabled &&
	    thread_limit > 0 &&
	    parent_task->thread_count >= thread_limit &&
	    !parent_task->task_has_crossed_thread_limit &&
	    !(task_is_a_corpse(parent_task))) {
		int thread_count = parent_task->thread_count;
		parent_task->task_has_crossed_thread_limit = TRUE;
		task_unlock(parent_task);
		SENDING_NOTIFICATION__TASK_HAS_TOO_MANY_THREADS(parent_task, thread_count);
	} else {
		task_unlock(parent_task);
	}
#endif

	lck_mtx_lock(&tasks_threads_lock);
	task_lock(parent_task);

	/*
	 * Fail thread creation if parent task is being torn down or has too many threads
	 * If the caller asked for TH_OPTION_NOSUSP, also fail if the parent task is suspended
	 */
	if (parent_task->active == 0 || parent_task->halting ||
	    (parent_task->suspend_count > 0 && (options & TH_OPTION_NOSUSP) != 0) ||
	    (parent_task->thread_count >= task_threadmax && parent_task != kernel_task)) {
		task_unlock(parent_task);
		lck_mtx_unlock(&tasks_threads_lock);

		ipc_thread_disable(new_thread);
		ipc_thread_terminate(new_thread);
		kfree_data(new_thread->thread_io_stats,
		    sizeof(struct io_stat_info));
		lck_mtx_destroy(&new_thread->mutex, &thread_lck_grp);
		kr = KERN_FAILURE;
		goto out_thread_cleanup;
	}

	/* Protected by the tasks_threads_lock */
	new_thread->thread_id = ++thread_unique_id;

	ctid_table_add(new_thread);

	/* New threads inherit any default state on the task */
	machine_thread_inherit_taskwide(new_thread, parent_task);

	task_reference_grp(parent_task, TASK_GRP_INTERNAL);

	if (parent_task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
		/*
		 * This task has a per-thread CPU limit; make sure this new thread
		 * gets its limit set too, before it gets out of the kernel.
		 */
		act_set_astledger(new_thread);
	}

	/* Instantiate a thread ledger. Do not fail thread creation if ledger creation fails. */
	if ((new_thread->t_threadledger = ledger_instantiate(thread_ledger_template,
	    LEDGER_CREATE_INACTIVE_ENTRIES)) != LEDGER_NULL) {
		ledger_entry_setactive(new_thread->t_threadledger, thread_ledgers.cpu_time);
	}

	new_thread->t_bankledger = LEDGER_NULL;
	new_thread->t_deduct_bank_ledger_time = 0;
	new_thread->t_deduct_bank_ledger_energy = 0;

	new_thread->t_ledger = parent_task->ledger;
	if (new_thread->t_ledger) {
		ledger_reference(new_thread->t_ledger);
	}

	recount_thread_init(&new_thread->th_recount);

#if defined(CONFIG_SCHED_MULTIQ)
	/* Cache the task's sched_group */
	new_thread->sched_group = parent_task->sched_group;
#endif /* defined(CONFIG_SCHED_MULTIQ) */

	/* Cache the task's map */
	new_thread->map = parent_task->map;

	new_thread->depress_timer = timer_call_alloc(thread_depress_expire, new_thread);
	new_thread->wait_timer = timer_call_alloc(thread_timer_expire, new_thread);

#if KPC
	kpc_thread_create(new_thread);
#endif

	/* Set the thread's scheduling parameters */
	new_thread->sched_mode = SCHED(initial_thread_sched_mode)(parent_task);
	new_thread->max_priority = parent_task->max_priority;
	new_thread->task_priority = parent_task->priority;

#if CONFIG_THREAD_GROUPS
	thread_group_init_thread(new_thread, parent_task);
#endif /* CONFIG_THREAD_GROUPS */

	int new_priority = (priority < 0) ? parent_task->priority: priority;
	new_priority = (priority < 0)? parent_task->priority: priority;
	if (new_priority > new_thread->max_priority) {
		new_priority = new_thread->max_priority;
	}
#if !defined(XNU_TARGET_OS_OSX)
	if (new_priority < MAXPRI_THROTTLE) {
		new_priority = MAXPRI_THROTTLE;
	}
#endif /* !defined(XNU_TARGET_OS_OSX) */

	new_thread->importance = new_priority - new_thread->task_priority;

	sched_set_thread_base_priority(new_thread, new_priority);

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	new_thread->sched_stamp = sched_tick;
#if CONFIG_SCHED_CLUTCH
	new_thread->pri_shift = sched_clutch_thread_pri_shift(new_thread, new_thread->th_sched_bucket);
#else /* CONFIG_SCHED_CLUTCH */
	new_thread->pri_shift = sched_pri_shifts[new_thread->th_sched_bucket];
#endif /* CONFIG_SCHED_CLUTCH */
#endif /* defined(CONFIG_SCHED_TIMESHARE_CORE) */

	if (parent_task->max_priority <= MAXPRI_THROTTLE) {
		sched_thread_mode_demote(new_thread, TH_SFLAG_THROTTLED);
	}

	thread_policy_create(new_thread);

	/* Chain the thread onto the task's list */
	queue_enter(&parent_task->threads, new_thread, thread_t, task_threads);
	parent_task->thread_count++;

	/* So terminating threads don't need to take the task lock to decrement */
	os_atomic_inc(&parent_task->active_thread_count, relaxed);

	queue_enter(&threads, new_thread, thread_t, threads);
	threads_count++;

	new_thread->active = TRUE;
	if (task_is_a_corpse_fork(parent_task)) {
		/* Set the inspection bit if the task is a corpse fork */
		new_thread->inspection = TRUE;
	} else {
		new_thread->inspection = FALSE;
	}
	new_thread->corpse_dup = FALSE;
	new_thread->turnstile = turnstile_alloc();
	new_thread->ctsid = turnstile_compact_id_get();


	*out_thread = new_thread;

	if (kdebug_enable) {
		long args[4] = {};

		kdbg_trace_data(get_bsdtask_info(parent_task), &args[1], &args[3]);

		/*
		 * Starting with 26604425, exec'ing creates a new task/thread.
		 *
		 * NEWTHREAD in the current process has two possible meanings:
		 *
		 * 1) Create a new thread for this process.
		 * 2) Create a new thread for the future process this will become in an
		 * exec.
		 *
		 * To disambiguate these, arg3 will be set to TRUE for case #2.
		 *
		 * The value we need to find (TPF_EXEC_COPY) is stable in the case of a
		 * task exec'ing. The read of t_procflags does not take the proc_lock.
		 */
		args[2] = task_is_exec_copy(parent_task) ? 1 : 0;

		KDBG_RELEASE(TRACE_DATA_NEWTHREAD, (uintptr_t)thread_tid(new_thread),
		    args[1], args[2], args[3]);

		kdebug_proc_name_args(get_bsdtask_info(parent_task), args);
		KDBG_RELEASE(TRACE_STRING_NEWTHREAD, args[0], args[1], args[2],
		    args[3]);
	}

	DTRACE_PROC1(lwp__create, thread_t, *out_thread);

	kr = KERN_SUCCESS;
	goto done;

out_thread_cleanup:
#ifdef MACH_BSD
	{
		struct uthread *ut = get_bsdthread_info(new_thread);

		uthread_cleanup(ut, &tro_tpl);
		uthread_destroy(ut);
	}
#endif  /* MACH_BSD */

	machine_thread_destroy(new_thread);

	thread_ro_destroy(new_thread);
	zfree(thread_zone, new_thread);

done:
	return kr;
}

static kern_return_t
thread_create_with_options_internal(
	task_t                            task,
	thread_t                          *new_thread,
	boolean_t                         from_user,
	thread_create_internal_options_t  options,
	thread_continue_t                 continuation)
{
	kern_return_t           result;
	thread_t                thread;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	if (from_user && current_task() != task &&
	    mac_proc_check_remote_thread_create(task, -1, NULL, 0) != 0) {
		return KERN_DENIED;
	}
#endif

	result = thread_create_internal(task, -1, continuation, NULL, options, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	thread->user_stop_count = 1;
	thread_hold(thread);
	if (task->suspend_count > 0) {
		thread_hold(thread);
	}

	if (from_user) {
		extmod_statistics_incr_thread_create(task);
	}

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	*new_thread = thread;

	return KERN_SUCCESS;
}

kern_return_t
thread_create_immovable(
	task_t                          task,
	thread_t                        *new_thread)
{
	return thread_create_with_options_internal(task, new_thread, FALSE,
	           TH_OPTION_NONE, (thread_continue_t)thread_bootstrap_return);
}

kern_return_t
thread_create_from_user(
	task_t                          task,
	thread_t                        *new_thread)
{
	/* All thread ports are created immovable by default */
	return thread_create_with_options_internal(task, new_thread, TRUE, TH_OPTION_NONE,
	           (thread_continue_t)thread_bootstrap_return);
}

kern_return_t
thread_create_with_continuation(
	task_t                          task,
	thread_t                        *new_thread,
	thread_continue_t               continuation)
{
	return thread_create_with_options_internal(task, new_thread, FALSE, TH_OPTION_NONE, continuation);
}

/*
 * Create a thread that is already started, but is waiting on an event
 */
static kern_return_t
thread_create_waiting_internal(
	task_t                  task,
	thread_continue_t       continuation,
	event_t                 event,
	block_hint_t            block_hint,
	thread_create_internal_options_t options,
	thread_t                *new_thread)
{
	kern_return_t result;
	thread_t thread;
	wait_interrupt_t wait_interrupt = THREAD_INTERRUPTIBLE;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	result = thread_create_internal(task, -1, continuation, NULL,
	    options, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	/* note no user_stop_count or thread_hold here */

	if (task->suspend_count > 0) {
		thread_hold(thread);
	}

	thread_mtx_lock(thread);
	thread_set_pending_block_hint(thread, block_hint);
	if (options & TH_OPTION_WORKQ) {
		thread->static_param = true;
		event = workq_thread_init_and_wq_lock(task, thread);
	} else if (options & TH_OPTION_MAINTHREAD) {
		wait_interrupt = THREAD_UNINT;
	}
	thread_start_in_assert_wait(thread, event, wait_interrupt);
	thread_mtx_unlock(thread);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	*new_thread = thread;

	return KERN_SUCCESS;
}

kern_return_t
main_thread_create_waiting(
	task_t                          task,
	thread_continue_t               continuation,
	event_t                         event,
	thread_t                        *new_thread)
{
	return thread_create_waiting_internal(task, continuation, event,
	           kThreadWaitNone, TH_OPTION_MAINTHREAD, new_thread);
}


static kern_return_t
thread_create_running_internal2(
	task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t                                *new_thread,
	boolean_t                               from_user)
{
	kern_return_t  result;
	thread_t                                thread;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	if (from_user && current_task() != task &&
	    mac_proc_check_remote_thread_create(task, flavor, new_state, new_state_count) != 0) {
		return KERN_DENIED;
	}
#endif

	result = thread_create_internal(task, -1,
	    (thread_continue_t)thread_bootstrap_return, NULL,
	    TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	if (task->suspend_count > 0) {
		thread_hold(thread);
	}

	if (from_user) {
		result = machine_thread_state_convert_from_user(thread, flavor,
		    new_state, new_state_count, NULL, 0, TSSF_FLAGS_NONE);
	}
	if (result == KERN_SUCCESS) {
		result = machine_thread_set_state(thread, flavor, new_state,
		    new_state_count);
	}
	if (result != KERN_SUCCESS) {
		task_unlock(task);
		lck_mtx_unlock(&tasks_threads_lock);

		thread_terminate(thread);
		thread_deallocate(thread);
		return result;
	}

	thread_mtx_lock(thread);
	thread_start(thread);
	thread_mtx_unlock(thread);

	if (from_user) {
		extmod_statistics_incr_thread_create(task);
	}

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	*new_thread = thread;

	return result;
}

/* Prototype, see justification above */
kern_return_t
thread_create_running(
	task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t                                *new_thread);

kern_return_t
thread_create_running(
	task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t                                *new_thread)
{
	return thread_create_running_internal2(
		task, flavor, new_state, new_state_count,
		new_thread, FALSE);
}

kern_return_t
thread_create_running_from_user(
	task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t                                *new_thread)
{
	return thread_create_running_internal2(
		task, flavor, new_state, new_state_count,
		new_thread, TRUE);
}

kern_return_t
thread_create_workq_waiting(
	task_t              task,
	thread_continue_t   continuation,
	thread_t            *new_thread)
{
	/*
	 * Create thread, but don't pin control port just yet, in case someone calls
	 * task_threads() and deallocates pinned port before kernel copyout happens,
	 * which will result in pinned port guard exception. Instead, pin and copyout
	 * atomically during workq_setup_and_run().
	 */
	int options = TH_OPTION_NOSUSP | TH_OPTION_WORKQ;
	return thread_create_waiting_internal(task, continuation, NULL,
	           kThreadWaitParkedWorkQueue, options, new_thread);
}

/*
 *	kernel_thread_create:
 *
 *	Create a thread in the kernel task
 *	to execute in kernel context.
 */
kern_return_t
kernel_thread_create(
	thread_continue_t       continuation,
	void                            *parameter,
	integer_t                       priority,
	thread_t                        *new_thread)
{
	kern_return_t           result;
	thread_t                        thread;
	task_t                          task = kernel_task;

	result = thread_create_internal(task, priority, continuation, parameter,
	    TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	stack_alloc(thread);
	assert(thread->kernel_stack != 0);
#if !defined(XNU_TARGET_OS_OSX)
	if (priority > BASEPRI_KERNEL)
#endif
	thread->reserved_stack = thread->kernel_stack;

	if (debug_task & 1) {
		kprintf("kernel_thread_create: thread = %p continuation = %p\n", thread, continuation);
	}
	*new_thread = thread;

	return result;
}

kern_return_t
kernel_thread_start_priority(
	thread_continue_t       continuation,
	void                            *parameter,
	integer_t                       priority,
	thread_t                        *new_thread)
{
	kern_return_t   result;
	thread_t                thread;

	result = kernel_thread_create(continuation, parameter, priority, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	*new_thread = thread;

	thread_mtx_lock(thread);
	thread_start(thread);
	thread_mtx_unlock(thread);

	return result;
}

kern_return_t
kernel_thread_start(
	thread_continue_t       continuation,
	void                            *parameter,
	thread_t                        *new_thread)
{
	return kernel_thread_start_priority(continuation, parameter, -1, new_thread);
}

/* Separated into helper function so it can be used by THREAD_BASIC_INFO and THREAD_EXTENDED_INFO */
/* it is assumed that the thread is locked by the caller */
static void
retrieve_thread_basic_info(thread_t thread, thread_basic_info_t basic_info)
{
	int     state, flags;

	/* fill in info */

	thread_read_times(thread, &basic_info->user_time,
	    &basic_info->system_time, NULL);

	/*
	 *	Update lazy-evaluated scheduler info because someone wants it.
	 */
	if (SCHED(can_update_priority)(thread)) {
		SCHED(update_priority)(thread);
	}

	basic_info->sleep_time = 0;

	/*
	 *	To calculate cpu_usage, first correct for timer rate,
	 *	then for 5/8 ageing.  The correction factor [3/5] is
	 *	(1/(5/8) - 1).
	 */
	basic_info->cpu_usage = 0;
#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	if (sched_tick_interval) {
		basic_info->cpu_usage = (integer_t)(((uint64_t)thread->cpu_usage
		    * TH_USAGE_SCALE) /     sched_tick_interval);
		basic_info->cpu_usage = (basic_info->cpu_usage * 3) / 5;
	}
#endif

	if (basic_info->cpu_usage > TH_USAGE_SCALE) {
		basic_info->cpu_usage = TH_USAGE_SCALE;
	}

	basic_info->policy = ((thread->sched_mode == TH_MODE_TIMESHARE)?
	    POLICY_TIMESHARE: POLICY_RR);

	flags = 0;
	if (thread->options & TH_OPT_IDLE_THREAD) {
		flags |= TH_FLAGS_IDLE;
	}

	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
		flags |= TH_FLAGS_GLOBAL_FORCED_IDLE;
	}

	if (!thread->kernel_stack) {
		flags |= TH_FLAGS_SWAPPED;
	}

	state = 0;
	if (thread->state & TH_TERMINATE) {
		state = TH_STATE_HALTED;
	} else if (thread->state & TH_RUN) {
		state = TH_STATE_RUNNING;
	} else if (thread->state & TH_UNINT) {
		state = TH_STATE_UNINTERRUPTIBLE;
	} else if (thread->state & TH_SUSP) {
		state = TH_STATE_STOPPED;
	} else if (thread->state & TH_WAIT) {
		state = TH_STATE_WAITING;
	}

	basic_info->run_state = state;
	basic_info->flags = flags;

	basic_info->suspend_count = thread->user_stop_count;

	return;
}

kern_return_t
thread_info_internal(
	thread_t                thread,
	thread_flavor_t                 flavor,
	thread_info_t                   thread_info_out,        /* ptr to OUT array */
	mach_msg_type_number_t  *thread_info_count)     /*IN/OUT*/
{
	spl_t   s;

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (flavor == THREAD_BASIC_INFO) {
		if (*thread_info_count < THREAD_BASIC_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		s = splsched();
		thread_lock(thread);

		retrieve_thread_basic_info(thread, (thread_basic_info_t) thread_info_out);

		thread_unlock(thread);
		splx(s);

		*thread_info_count = THREAD_BASIC_INFO_COUNT;

		return KERN_SUCCESS;
	} else if (flavor == THREAD_IDENTIFIER_INFO) {
		thread_identifier_info_t        identifier_info;

		if (*thread_info_count < THREAD_IDENTIFIER_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		identifier_info = __IGNORE_WCASTALIGN((thread_identifier_info_t)thread_info_out);

		s = splsched();
		thread_lock(thread);

		identifier_info->thread_id = thread->thread_id;
		identifier_info->thread_handle = thread->machine.cthread_self;
		identifier_info->dispatch_qaddr = thread_dispatchqaddr(thread);

		thread_unlock(thread);
		splx(s);
		return KERN_SUCCESS;
	} else if (flavor == THREAD_SCHED_TIMESHARE_INFO) {
		policy_timeshare_info_t         ts_info;

		if (*thread_info_count < POLICY_TIMESHARE_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		ts_info = (policy_timeshare_info_t)thread_info_out;

		s = splsched();
		thread_lock(thread);

		if (thread->sched_mode != TH_MODE_TIMESHARE) {
			thread_unlock(thread);
			splx(s);
			return KERN_INVALID_POLICY;
		}

		ts_info->depressed = (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != 0;
		if (ts_info->depressed) {
			ts_info->base_priority = DEPRESSPRI;
			ts_info->depress_priority = thread->base_pri;
		} else {
			ts_info->base_priority = thread->base_pri;
			ts_info->depress_priority = -1;
		}

		ts_info->cur_priority = thread->sched_pri;
		ts_info->max_priority = thread->max_priority;

		thread_unlock(thread);
		splx(s);

		*thread_info_count = POLICY_TIMESHARE_INFO_COUNT;

		return KERN_SUCCESS;
	} else if (flavor == THREAD_SCHED_FIFO_INFO) {
		if (*thread_info_count < POLICY_FIFO_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		return KERN_INVALID_POLICY;
	} else if (flavor == THREAD_SCHED_RR_INFO) {
		policy_rr_info_t                        rr_info;
		uint32_t quantum_time;
		uint64_t quantum_ns;

		if (*thread_info_count < POLICY_RR_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		rr_info = (policy_rr_info_t) thread_info_out;

		s = splsched();
		thread_lock(thread);

		if (thread->sched_mode == TH_MODE_TIMESHARE) {
			thread_unlock(thread);
			splx(s);

			return KERN_INVALID_POLICY;
		}

		rr_info->depressed = (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != 0;
		if (rr_info->depressed) {
			rr_info->base_priority = DEPRESSPRI;
			rr_info->depress_priority = thread->base_pri;
		} else {
			rr_info->base_priority = thread->base_pri;
			rr_info->depress_priority = -1;
		}

		quantum_time = SCHED(initial_quantum_size)(THREAD_NULL);
		absolutetime_to_nanoseconds(quantum_time, &quantum_ns);

		rr_info->max_priority = thread->max_priority;
		rr_info->quantum = (uint32_t)(quantum_ns / 1000 / 1000);

		thread_unlock(thread);
		splx(s);

		*thread_info_count = POLICY_RR_INFO_COUNT;

		return KERN_SUCCESS;
	} else if (flavor == THREAD_EXTENDED_INFO) {
		thread_basic_info_data_t        basic_info;
		thread_extended_info_t          extended_info = __IGNORE_WCASTALIGN((thread_extended_info_t)thread_info_out);

		if (*thread_info_count < THREAD_EXTENDED_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		s = splsched();
		thread_lock(thread);

		/* NOTE: This mimics fill_taskthreadinfo(), which is the function used by proc_pidinfo() for
		 * the PROC_PIDTHREADINFO flavor (which can't be used on corpses)
		 */
		retrieve_thread_basic_info(thread, &basic_info);
		extended_info->pth_user_time = (((uint64_t)basic_info.user_time.seconds * NSEC_PER_SEC) + ((uint64_t)basic_info.user_time.microseconds * NSEC_PER_USEC));
		extended_info->pth_system_time = (((uint64_t)basic_info.system_time.seconds * NSEC_PER_SEC) + ((uint64_t)basic_info.system_time.microseconds * NSEC_PER_USEC));

		extended_info->pth_cpu_usage = basic_info.cpu_usage;
		extended_info->pth_policy = basic_info.policy;
		extended_info->pth_run_state = basic_info.run_state;
		extended_info->pth_flags = basic_info.flags;
		extended_info->pth_sleep_time = basic_info.sleep_time;
		extended_info->pth_curpri = thread->sched_pri;
		extended_info->pth_priority = thread->base_pri;
		extended_info->pth_maxpriority = thread->max_priority;

		bsd_getthreadname(get_bsdthread_info(thread), extended_info->pth_name);

		thread_unlock(thread);
		splx(s);

		*thread_info_count = THREAD_EXTENDED_INFO_COUNT;

		return KERN_SUCCESS;
	} else if (flavor == THREAD_DEBUG_INFO_INTERNAL) {
#if DEVELOPMENT || DEBUG
		thread_debug_info_internal_t dbg_info;
		if (*thread_info_count < THREAD_DEBUG_INFO_INTERNAL_COUNT) {
			return KERN_NOT_SUPPORTED;
		}

		if (thread_info_out == NULL) {
			return KERN_INVALID_ARGUMENT;
		}

		dbg_info = __IGNORE_WCASTALIGN((thread_debug_info_internal_t)thread_info_out);
		dbg_info->page_creation_count = thread->t_page_creation_count;

		*thread_info_count = THREAD_DEBUG_INFO_INTERNAL_COUNT;
		return KERN_SUCCESS;
#endif /* DEVELOPMENT || DEBUG */
		return KERN_NOT_SUPPORTED;
	}

	return KERN_INVALID_ARGUMENT;
}

static void
_convert_mach_to_time_value(uint64_t time_mach, time_value_t *time)
{
	clock_sec_t  secs;
	clock_usec_t usecs;
	absolutetime_to_microtime(time_mach, &secs, &usecs);
	time->seconds = (typeof(time->seconds))secs;
	time->microseconds = usecs;
}

void
thread_read_times(
	thread_t      thread,
	time_value_t *user_time,
	time_value_t *system_time,
	time_value_t *runnable_time)
{
	if (user_time && system_time) {
		struct recount_times_mach times = recount_thread_times(thread);
		_convert_mach_to_time_value(times.rtm_user, user_time);
		_convert_mach_to_time_value(times.rtm_system, system_time);
	}

	if (runnable_time) {
		uint64_t runnable_time_mach = timer_grab(&thread->runnable_timer);
		_convert_mach_to_time_value(runnable_time_mach, runnable_time);
	}
}

uint64_t
thread_get_runtime_self(void)
{
	/*
	 * Must be guaranteed to stay on the same CPU and not be updated by the
	 * scheduler.
	 */
	boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
	uint64_t time_mach = recount_current_thread_time_mach();
	ml_set_interrupts_enabled(interrupt_state);
	return time_mach;
}

/*
 *	thread_wire_internal:
 *
 *	Specify that the target thread must always be able
 *	to run and to allocate memory.
 */
kern_return_t
thread_wire_internal(
	host_priv_t             host_priv,
	thread_t                thread,
	boolean_t               wired,
	boolean_t               *prev_state)
{
	if (host_priv == NULL || thread != current_thread()) {
		return KERN_INVALID_ARGUMENT;
	}

	if (prev_state) {
		*prev_state = (thread->options & TH_OPT_VMPRIV) != 0;
	}

	if (wired) {
		if (!(thread->options & TH_OPT_VMPRIV)) {
			vm_page_free_reserve(1); /* XXX */
		}
		thread->options |= TH_OPT_VMPRIV;
	} else {
		if (thread->options & TH_OPT_VMPRIV) {
			vm_page_free_reserve(-1); /* XXX */
		}
		thread->options &= ~TH_OPT_VMPRIV;
	}

	return KERN_SUCCESS;
}


/*
 *	thread_wire:
 *
 *	User-api wrapper for thread_wire_internal()
 */
kern_return_t
thread_wire(
	host_priv_t     host_priv,
	thread_t        thread,
	boolean_t       wired)
{
	return thread_wire_internal(host_priv, thread, wired, NULL);
}

boolean_t
is_external_pageout_thread(void)
{
	return current_thread() == pgo_iothread_external_state.pgo_iothread;
}

boolean_t
is_vm_privileged(void)
{
	return current_thread()->options & TH_OPT_VMPRIV ? TRUE : FALSE;
}

boolean_t
set_vm_privilege(boolean_t privileged)
{
	boolean_t       was_vmpriv;

	if (current_thread()->options & TH_OPT_VMPRIV) {
		was_vmpriv = TRUE;
	} else {
		was_vmpriv = FALSE;
	}

	if (privileged != FALSE) {
		current_thread()->options |= TH_OPT_VMPRIV;
	} else {
		current_thread()->options &= ~TH_OPT_VMPRIV;
	}

	return was_vmpriv;
}

void
thread_floor_boost_set_promotion_locked(thread_t thread)
{
	assert(thread->priority_floor_count > 0);

	if (!(thread->sched_flags & TH_SFLAG_FLOOR_PROMOTED)) {
		sched_thread_promote_reason(thread, TH_SFLAG_FLOOR_PROMOTED, 0);
	}
}

/*!  @function thread_priority_floor_start
 *   @abstract boost the current thread priority to floor.
 *   @discussion Increase the priority of the current thread to at least MINPRI_FLOOR.
 *       The boost will be mantained until a corresponding thread_priority_floor_end()
 *       is called. Every call of thread_priority_floor_start() needs to have a corresponding
 *       call to thread_priority_floor_end() from the same thread.
 *       No thread can return to userspace before calling thread_priority_floor_end().
 *
 *       NOTE: avoid to use this function. Try to use gate_t or sleep_with_inheritor()
 *       instead.
 *   @result a token to be given to the corresponding thread_priority_floor_end()
 */
thread_pri_floor_t
thread_priority_floor_start(void)
{
	thread_pri_floor_t ret;
	thread_t thread = current_thread();
	__assert_only uint16_t prev_priority_floor_count;

	assert(thread->priority_floor_count < UINT16_MAX);
	prev_priority_floor_count = thread->priority_floor_count++;
#if MACH_ASSERT
	/*
	 * Set the ast to check that the
	 * priority_floor_count is going to be set to zero when
	 * going back to userspace.
	 * Set it only once when we increment it for the first time.
	 */
	if (prev_priority_floor_count == 0) {
		act_set_debug_assert();
	}
#endif

	ret.thread = thread;
	return ret;
}

/*!  @function thread_priority_floor_end
 *   @abstract ends the floor boost.
 *   @param token the token obtained from thread_priority_floor_start()
 *   @discussion ends the priority floor boost started with thread_priority_floor_start()
 */
void
thread_priority_floor_end(thread_pri_floor_t *token)
{
	thread_t thread = current_thread();

	assert(thread->priority_floor_count > 0);
	assertf(token->thread == thread, "thread_priority_floor_end called from a different thread from thread_priority_floor_start %p %p", thread, token->thread);

	if ((thread->priority_floor_count-- == 1) && (thread->sched_flags & TH_SFLAG_FLOOR_PROMOTED)) {
		spl_t s = splsched();
		thread_lock(thread);

		if (thread->sched_flags & TH_SFLAG_FLOOR_PROMOTED) {
			sched_thread_unpromote_reason(thread, TH_SFLAG_FLOOR_PROMOTED, 0);
		}

		thread_unlock(thread);
		splx(s);
	}

	token->thread = NULL;
}

/*
 * XXX assuming current thread only, for now...
 */
void
thread_guard_violation(thread_t thread,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode, boolean_t fatal)
{
	assert(thread == current_thread());

	/* Don't set up the AST for kernel threads; this check is needed to ensure
	 * that the guard_exc_* fields in the thread structure are set only by the
	 * current thread and therefore, don't require a lock.
	 */
	if (get_threadtask(thread) == kernel_task) {
		return;
	}

	assert(EXC_GUARD_DECODE_GUARD_TYPE(code));

	/*
	 * Use the saved state area of the thread structure
	 * to store all info required to handle the AST when
	 * returning to userspace. It's possible that there is
	 * already a pending guard exception. If it's non-fatal,
	 * it can only be over-written by a fatal exception code.
	 */
	if (thread->guard_exc_info.code && (thread->guard_exc_fatal || !fatal)) {
		return;
	}

	thread->guard_exc_info.code = code;
	thread->guard_exc_info.subcode = subcode;
	thread->guard_exc_fatal = fatal ? 1 : 0;

	spl_t s = splsched();
	thread_ast_set(thread, AST_GUARD);
	ast_propagate(thread);
	splx(s);
}

#if CONFIG_DEBUG_SYSCALL_REJECTION
extern void rejected_syscall_guard_ast(thread_t __unused t, mach_exception_data_type_t code, mach_exception_data_type_t subcode);
#endif /* CONFIG_DEBUG_SYSCALL_REJECTION */

/*
 *	guard_ast:
 *
 *	Handle AST_GUARD for a thread. This routine looks at the
 *	state saved in the thread structure to determine the cause
 *	of this exception. Based on this value, it invokes the
 *	appropriate routine which determines other exception related
 *	info and raises the exception.
 */
void
guard_ast(thread_t t)
{
	const mach_exception_data_type_t
	    code = t->guard_exc_info.code,
	    subcode = t->guard_exc_info.subcode;

	t->guard_exc_info.code = 0;
	t->guard_exc_info.subcode = 0;
	t->guard_exc_fatal = 0;

	switch (EXC_GUARD_DECODE_GUARD_TYPE(code)) {
	case GUARD_TYPE_NONE:
		/* lingering AST_GUARD on the processor? */
		break;
	case GUARD_TYPE_MACH_PORT:
		mach_port_guard_ast(t, code, subcode);
		break;
	case GUARD_TYPE_FD:
		fd_guard_ast(t, code, subcode);
		break;
#if CONFIG_VNGUARD
	case GUARD_TYPE_VN:
		vn_guard_ast(t, code, subcode);
		break;
#endif
	case GUARD_TYPE_VIRT_MEMORY:
		virt_memory_guard_ast(t, code, subcode);
		break;
#if CONFIG_DEBUG_SYSCALL_REJECTION
	case GUARD_TYPE_REJECTED_SC:
		rejected_syscall_guard_ast(t, code, subcode);
		break;
#endif /* CONFIG_DEBUG_SYSCALL_REJECTION */
	default:
		panic("guard_exc_info %llx %llx", code, subcode);
	}
}

static void
thread_cputime_callback(int warning, __unused const void *arg0, __unused const void *arg1)
{
	if (warning == LEDGER_WARNING_ROSE_ABOVE) {
#if CONFIG_TELEMETRY
		/*
		 * This thread is in danger of violating the CPU usage monitor. Enable telemetry
		 * on the entire task so there are micro-stackshots available if and when
		 * EXC_RESOURCE is triggered. We could have chosen to enable micro-stackshots
		 * for this thread only; but now that this task is suspect, knowing what all of
		 * its threads are up to will be useful.
		 */
		telemetry_task_ctl(current_task(), TF_CPUMON_WARNING, 1);
#endif
		return;
	}

#if CONFIG_TELEMETRY
	/*
	 * If the balance has dipped below the warning level (LEDGER_WARNING_DIPPED_BELOW) or
	 * exceeded the limit, turn telemetry off for the task.
	 */
	telemetry_task_ctl(current_task(), TF_CPUMON_WARNING, 0);
#endif

	if (warning == 0) {
		SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU();
	}
}

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU(void)
{
	int          pid                = 0;
	task_t           task                           = current_task();
	thread_t     thread             = current_thread();
	uint64_t     tid                = thread->thread_id;
	const char       *procname          = "unknown";
	time_value_t thread_total_time  = {0, 0};
	time_value_t thread_system_time;
	time_value_t thread_user_time;
	int          action;
	uint8_t      percentage;
	uint32_t     usage_percent = 0;
	uint32_t     interval_sec;
	uint64_t     interval_ns;
	uint64_t     balance_ns;
	boolean_t        fatal = FALSE;
	boolean_t        send_exc_resource = TRUE; /* in addition to RESOURCE_NOTIFY */
	kern_return_t   kr;

#ifdef EXC_RESOURCE_MONITORS
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
#endif /* EXC_RESOURCE_MONITORS */
	struct ledger_entry_info        lei;

	assert(thread->t_threadledger != LEDGER_NULL);

	/*
	 * Extract the fatal bit and suspend the monitor (which clears the bit).
	 */
	task_lock(task);
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_CPUMON) {
		fatal = TRUE;
		send_exc_resource = TRUE;
	}
	/* Only one thread can be here at a time.  Whichever makes it through
	 *  first will successfully suspend the monitor and proceed to send the
	 *  notification.  Other threads will get an error trying to suspend the
	 *  monitor and give up on sending the notification.  In the first release,
	 *  the monitor won't be resumed for a number of seconds, but we may
	 *  eventually need to handle low-latency resume.
	 */
	kr = task_suspend_cpumon(task);
	task_unlock(task);
	if (kr == KERN_INVALID_ARGUMENT) {
		return;
	}

#ifdef MACH_BSD
	pid = proc_selfpid();
	void *bsd_info = get_bsdtask_info(task);
	if (bsd_info != NULL) {
		procname = proc_name_address(bsd_info);
	}
#endif

	thread_get_cpulimit(&action, &percentage, &interval_ns);

	interval_sec = (uint32_t)(interval_ns / NSEC_PER_SEC);

	thread_read_times(thread, &thread_user_time, &thread_system_time, NULL);
	time_value_add(&thread_total_time, &thread_user_time);
	time_value_add(&thread_total_time, &thread_system_time);
	ledger_get_entry_info(thread->t_threadledger, thread_ledgers.cpu_time, &lei);

	/* credit/debit/balance/limit are in absolute time units;
	 *  the refill info is in nanoseconds. */
	absolutetime_to_nanoseconds(lei.lei_balance, &balance_ns);
	if (lei.lei_last_refill > 0) {
		usage_percent = (uint32_t)((balance_ns * 100ULL) / lei.lei_last_refill);
	}

	/* TODO: show task total runtime (via TASK_ABSOLUTETIME_INFO)? */
	printf("process %s[%d] thread %llu caught burning CPU! It used more than %d%% CPU over %u seconds\n",
	    procname, pid, tid, percentage, interval_sec);
	printf("  (actual recent usage: %d%% over ~%llu seconds)\n",
	    usage_percent, (lei.lei_last_refill + NSEC_PER_SEC / 2) / NSEC_PER_SEC);
	printf("  Thread lifetime cpu usage %d.%06ds, (%d.%06d user, %d.%06d sys)\n",
	    thread_total_time.seconds, thread_total_time.microseconds,
	    thread_user_time.seconds, thread_user_time.microseconds,
	    thread_system_time.seconds, thread_system_time.microseconds);
	printf("  Ledger balance: %lld; mabs credit: %lld; mabs debit: %lld\n",
	    lei.lei_balance, lei.lei_credit, lei.lei_debit);
	printf("  mabs limit: %llu; mabs period: %llu ns; last refill: %llu ns%s.\n",
	    lei.lei_limit, lei.lei_refill_period, lei.lei_last_refill,
	    (fatal ? " [fatal violation]" : ""));

	/*
	 *  For now, send RESOURCE_NOTIFY in parallel with EXC_RESOURCE.  Once
	 *  we have logging parity, we will stop sending EXC_RESOURCE (24508922).
	 */

	/* RESOURCE_NOTIFY MIG specifies nanoseconds of CPU time */
	lei.lei_balance = balance_ns;
	absolutetime_to_nanoseconds(lei.lei_limit, &lei.lei_limit);
	trace_resource_violation(RMON_CPUUSAGE_VIOLATED, &lei);
	kr = send_resource_violation(send_cpu_usage_violation, task, &lei,
	    fatal ? kRNFatalLimitFlag : 0);
	if (kr) {
		printf("send_resource_violation(CPU usage, ...): error %#x\n", kr);
	}

#ifdef EXC_RESOURCE_MONITORS
	if (send_exc_resource) {
		if (disable_exc_resource) {
			printf("process %s[%d] thread %llu caught burning CPU! "
			    "EXC_RESOURCE%s supressed by a boot-arg\n",
			    procname, pid, tid, fatal ? " (and termination)" : "");
			return;
		}

		if (audio_active) {
			printf("process %s[%d] thread %llu caught burning CPU! "
			    "EXC_RESOURCE & termination supressed due to audio playback\n",
			    procname, pid, tid);
			return;
		}
	}


	if (send_exc_resource) {
		code[0] = code[1] = 0;
		EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_CPU);
		if (fatal) {
			EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_CPU_MONITOR_FATAL);
		} else {
			EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_CPU_MONITOR);
		}
		EXC_RESOURCE_CPUMONITOR_ENCODE_INTERVAL(code[0], interval_sec);
		EXC_RESOURCE_CPUMONITOR_ENCODE_PERCENTAGE(code[0], percentage);
		EXC_RESOURCE_CPUMONITOR_ENCODE_PERCENTAGE(code[1], usage_percent);
		exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
	}
#endif /* EXC_RESOURCE_MONITORS */

	if (fatal) {
#if CONFIG_JETSAM
		jetsam_on_ledger_cpulimit_exceeded();
#else
		task_terminate_internal(task);
#endif
	}
}

bool os_variant_has_internal_diagnostics(const char *subsystem);

#if DEVELOPMENT || DEBUG
void __attribute__((noinline))
SENDING_NOTIFICATION__TASK_HAS_TOO_MANY_THREADS(task_t task, int thread_count)
{
	mach_exception_data_type_t code[EXCEPTION_CODE_MAX] = {0};
	int pid = task_pid(task);
	char procname[MAXCOMLEN + 1] = "unknown";

	if (pid == 1) {
		/*
		 * Cannot suspend launchd
		 */
		return;
	}

	proc_name(pid, procname, sizeof(procname));

	if (disable_exc_resource) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
		    "supressed by a boot-arg.\n", procname, pid, thread_count);
		return;
	}

	if (!os_variant_has_internal_diagnostics("com.apple.xnu")) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
		    "supressed, internal diagnostics disabled.\n", procname, pid, thread_count);
		return;
	}

	if (audio_active) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
		    "supressed due to audio playback.\n", procname, pid, thread_count);
		return;
	}

	if (!exc_via_corpse_forking) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
		    "supressed due to corpse forking being disabled.\n", procname, pid,
		    thread_count);
		return;
	}

	printf("process %s[%d] crossed thread count high watermark (%d), sending "
	    "EXC_RESOURCE\n", procname, pid, thread_count);

	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_THREADS);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_THREADS_HIGH_WATERMARK);
	EXC_RESOURCE_THREADS_ENCODE_THREADS(code[0], thread_count);

	task_enqueue_exception_with_corpse(task, EXC_RESOURCE, code, EXCEPTION_CODE_MAX, NULL, FALSE);
}
#endif /* DEVELOPMENT || DEBUG */

void
thread_update_io_stats(thread_t thread, int size, int io_flags)
{
	task_t task = get_threadtask(thread);
	int io_tier;

	if (thread->thread_io_stats == NULL || task->task_io_stats == NULL) {
		return;
	}

	if (io_flags & DKIO_READ) {
		UPDATE_IO_STATS(thread->thread_io_stats->disk_reads, size);
		UPDATE_IO_STATS_ATOMIC(task->task_io_stats->disk_reads, size);
	}

	if (io_flags & DKIO_META) {
		UPDATE_IO_STATS(thread->thread_io_stats->metadata, size);
		UPDATE_IO_STATS_ATOMIC(task->task_io_stats->metadata, size);
	}

	if (io_flags & DKIO_PAGING) {
		UPDATE_IO_STATS(thread->thread_io_stats->paging, size);
		UPDATE_IO_STATS_ATOMIC(task->task_io_stats->paging, size);
	}

	io_tier = ((io_flags & DKIO_TIER_MASK) >> DKIO_TIER_SHIFT);
	assert(io_tier < IO_NUM_PRIORITIES);

	UPDATE_IO_STATS(thread->thread_io_stats->io_priority[io_tier], size);
	UPDATE_IO_STATS_ATOMIC(task->task_io_stats->io_priority[io_tier], size);

	/* Update Total I/O Counts */
	UPDATE_IO_STATS(thread->thread_io_stats->total_io, size);
	UPDATE_IO_STATS_ATOMIC(task->task_io_stats->total_io, size);

	if (!(io_flags & DKIO_READ)) {
		DTRACE_IO3(physical_writes, struct task *, task, uint32_t, size, int, io_flags);
		ledger_credit(task->ledger, task_ledgers.physical_writes, size);
	}
}

static void
init_thread_ledgers(void)
{
	ledger_template_t t;
	int idx;

	assert(thread_ledger_template == NULL);

	if ((t = ledger_template_create("Per-thread ledger")) == NULL) {
		panic("couldn't create thread ledger template");
	}

	if ((idx = ledger_entry_add(t, "cpu_time", "sched", "ns")) < 0) {
		panic("couldn't create cpu_time entry for thread ledger template");
	}

	if (ledger_set_callback(t, idx, thread_cputime_callback, NULL, NULL) < 0) {
		panic("couldn't set thread ledger callback for cpu_time entry");
	}

	thread_ledgers.cpu_time = idx;

	ledger_template_complete(t);
	thread_ledger_template = t;
}

/*
 * Returns the amount of (abs) CPU time that remains before the limit would be
 * hit or the amount of time left in the current interval, whichever is smaller.
 * This value changes as CPU time is consumed and the ledgers refilled.
 * Used to limit the quantum of a thread.
 */
uint64_t
thread_cpulimit_remaining(uint64_t now)
{
	thread_t thread = current_thread();

	if ((thread->options &
	    (TH_OPT_PROC_CPULIMIT | TH_OPT_PRVT_CPULIMIT)) == 0) {
		return UINT64_MAX;
	}

	/* Amount of time left in the current interval. */
	const uint64_t interval_remaining =
	    ledger_get_interval_remaining(thread->t_threadledger, thread_ledgers.cpu_time, now);

	/* Amount that can be spent until the limit is hit. */
	const uint64_t remaining =
	    ledger_get_remaining(thread->t_threadledger, thread_ledgers.cpu_time);

	return MIN(interval_remaining, remaining);
}

/*
 * Returns true if a new interval should be started.
 */
bool
thread_cpulimit_interval_has_expired(uint64_t now)
{
	thread_t thread = current_thread();

	if ((thread->options &
	    (TH_OPT_PROC_CPULIMIT | TH_OPT_PRVT_CPULIMIT)) == 0) {
		return false;
	}

	return ledger_get_interval_remaining(thread->t_threadledger,
	           thread_ledgers.cpu_time, now) == 0;
}

/*
 * Balances the ledger and sets the last refill time to `now`.
 */
void
thread_cpulimit_restart(uint64_t now)
{
	thread_t thread = current_thread();

	assert3u(thread->options & (TH_OPT_PROC_CPULIMIT | TH_OPT_PRVT_CPULIMIT), !=, 0);

	ledger_restart(thread->t_threadledger, thread_ledgers.cpu_time, now);
}

/*
 * Returns currently applied CPU usage limit, or 0/0 if none is applied.
 */
int
thread_get_cpulimit(int *action, uint8_t *percentage, uint64_t *interval_ns)
{
	int64_t         abstime = 0;
	uint64_t        limittime = 0;
	thread_t        thread = current_thread();

	*percentage  = 0;
	*interval_ns = 0;
	*action      = 0;

	if (thread->t_threadledger == LEDGER_NULL) {
		/*
		 * This thread has no per-thread ledger, so it can't possibly
		 * have a CPU limit applied.
		 */
		return KERN_SUCCESS;
	}

	ledger_get_period(thread->t_threadledger, thread_ledgers.cpu_time, interval_ns);
	ledger_get_limit(thread->t_threadledger, thread_ledgers.cpu_time, &abstime);

	if ((abstime == LEDGER_LIMIT_INFINITY) || (*interval_ns == 0)) {
		/*
		 * This thread's CPU time ledger has no period or limit; so it
		 * doesn't have a CPU limit applied.
		 */
		return KERN_SUCCESS;
	}

	/*
	 * This calculation is the converse to the one in thread_set_cpulimit().
	 */
	absolutetime_to_nanoseconds(abstime, &limittime);
	*percentage = (uint8_t)((limittime * 100ULL) / *interval_ns);
	assert(*percentage <= 100);

	if (thread->options & TH_OPT_PROC_CPULIMIT) {
		assert((thread->options & TH_OPT_PRVT_CPULIMIT) == 0);

		*action = THREAD_CPULIMIT_BLOCK;
	} else if (thread->options & TH_OPT_PRVT_CPULIMIT) {
		assert((thread->options & TH_OPT_PROC_CPULIMIT) == 0);

		*action = THREAD_CPULIMIT_EXCEPTION;
	} else {
		*action = THREAD_CPULIMIT_DISABLE;
	}

	return KERN_SUCCESS;
}

/*
 * Set CPU usage limit on a thread.
 */
int
thread_set_cpulimit(int action, uint8_t percentage, uint64_t interval_ns)
{
	thread_t        thread = current_thread();
	ledger_t        l;
	uint64_t        limittime = 0;
	uint64_t        abstime = 0;

	assert(percentage <= 100);
	assert(percentage > 0 || action == THREAD_CPULIMIT_DISABLE);

	/*
	 * Disallow any change to the CPU limit if the TH_OPT_FORCED_LEDGER
	 * flag is set.
	 */
	if ((thread->options & TH_OPT_FORCED_LEDGER) != 0) {
		return KERN_FAILURE;
	}

	if (action == THREAD_CPULIMIT_DISABLE) {
		/*
		 * Remove CPU limit, if any exists.
		 */
		if (thread->t_threadledger != LEDGER_NULL) {
			l = thread->t_threadledger;
			ledger_set_limit(l, thread_ledgers.cpu_time, LEDGER_LIMIT_INFINITY, 0);
			ledger_set_action(l, thread_ledgers.cpu_time, LEDGER_ACTION_IGNORE);
			thread->options &= ~(TH_OPT_PROC_CPULIMIT | TH_OPT_PRVT_CPULIMIT);
		}

		return 0;
	}

	if (interval_ns < MINIMUM_CPULIMIT_INTERVAL_MS * NSEC_PER_MSEC) {
		return KERN_INVALID_ARGUMENT;
	}

	l = thread->t_threadledger;
	if (l == LEDGER_NULL) {
		/*
		 * This thread doesn't yet have a per-thread ledger; so create one with the CPU time entry active.
		 */
		if ((l = ledger_instantiate(thread_ledger_template, LEDGER_CREATE_INACTIVE_ENTRIES)) == LEDGER_NULL) {
			return KERN_RESOURCE_SHORTAGE;
		}

		/*
		 * We are the first to create this thread's ledger, so only activate our entry.
		 */
		ledger_entry_setactive(l, thread_ledgers.cpu_time);
		thread->t_threadledger = l;
	}

	/*
	 * The limit is specified as a percentage of CPU over an interval in nanoseconds.
	 * Calculate the amount of CPU time that the thread needs to consume in order to hit the limit.
	 */
	limittime = (interval_ns * percentage) / 100;
	nanoseconds_to_absolutetime(limittime, &abstime);
	ledger_set_limit(l, thread_ledgers.cpu_time, abstime, cpumon_ustackshots_trigger_pct);
	/*
	 * Refill the thread's allotted CPU time every interval_ns nanoseconds.
	 */
	ledger_set_period(l, thread_ledgers.cpu_time, interval_ns);

	if (action == THREAD_CPULIMIT_EXCEPTION) {
		/*
		 * We don't support programming the CPU usage monitor on a task if any of its
		 * threads have a per-thread blocking CPU limit configured.
		 */
		if (thread->options & TH_OPT_PRVT_CPULIMIT) {
			panic("CPU usage monitor activated, but blocking thread limit exists");
		}

		/*
		 * Make a note that this thread's CPU limit is being used for the task-wide CPU
		 * usage monitor. We don't have to arm the callback which will trigger the
		 * exception, because that was done for us in ledger_instantiate (because the
		 * ledger template used has a default callback).
		 */
		thread->options |= TH_OPT_PROC_CPULIMIT;
	} else {
		/*
		 * We deliberately override any CPU limit imposed by a task-wide limit (eg
		 * CPU usage monitor).
		 */
		thread->options &= ~TH_OPT_PROC_CPULIMIT;

		thread->options |= TH_OPT_PRVT_CPULIMIT;
		/* The per-thread ledger template by default has a callback for CPU time */
		ledger_disable_callback(l, thread_ledgers.cpu_time);
		ledger_set_action(l, thread_ledgers.cpu_time, LEDGER_ACTION_BLOCK);
	}

	return 0;
}

void
thread_sched_call(
	thread_t                thread,
	sched_call_t    call)
{
	assert((thread->state & TH_WAIT_REPORT) == 0);
	thread->sched_call = call;
}

uint64_t
thread_tid(
	thread_t        thread)
{
	return thread != THREAD_NULL? thread->thread_id: 0;
}

uint64_t
uthread_tid(
	struct uthread *uth)
{
	if (uth) {
		return thread_tid(get_machthread(uth));
	}
	return 0;
}

uint16_t
thread_set_tag(thread_t th, uint16_t tag)
{
	return thread_set_tag_internal(th, tag);
}

uint16_t
thread_get_tag(thread_t th)
{
	return thread_get_tag_internal(th);
}

uint64_t
thread_last_run_time(thread_t th)
{
	return th->last_run_time;
}

/*
 * Shared resource contention management
 *
 * The scheduler attempts to load balance the shared resource intensive
 * workloads across clusters to ensure that the resource is not heavily
 * contended. The kernel relies on external agents (userspace or
 * performance controller) to identify shared resource heavy threads.
 * The load balancing is achieved based on the scheduler configuration
 * enabled on the platform.
 */


#if CONFIG_SCHED_EDGE

/*
 * On the Edge scheduler, the load balancing is achieved by looking
 * at cluster level shared resource loads and migrating resource heavy
 * threads dynamically to under utilized cluster. Therefore, when a
 * thread is indicated as a resource heavy thread, the policy set
 * routine simply adds a flag to the thread which is looked at by
 * the scheduler on thread migration decisions.
 */

boolean_t
thread_shared_rsrc_policy_get(thread_t thread, cluster_shared_rsrc_type_t type)
{
	return thread->th_shared_rsrc_heavy_user[type] || thread->th_shared_rsrc_heavy_perf_control[type];
}

__options_decl(sched_edge_rsrc_heavy_thread_state, uint32_t, {
	SCHED_EDGE_RSRC_HEAVY_THREAD_SET = 1,
	SCHED_EDGE_RSRC_HEAVY_THREAD_CLR = 2,
});

kern_return_t
thread_shared_rsrc_policy_set(thread_t thread, __unused uint32_t index, cluster_shared_rsrc_type_t type, shared_rsrc_policy_agent_t agent)
{
	spl_t s = splsched();
	thread_lock(thread);

	bool user = (agent == SHARED_RSRC_POLICY_AGENT_DISPATCH) || (agent == SHARED_RSRC_POLICY_AGENT_SYSCTL);
	bool *thread_flags = (user) ? thread->th_shared_rsrc_heavy_user : thread->th_shared_rsrc_heavy_perf_control;
	if (thread_flags[type]) {
		thread_unlock(thread);
		splx(s);
		return KERN_FAILURE;
	}

	thread_flags[type] = true;
	thread_unlock(thread);
	splx(s);

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_RSRC_HEAVY_THREAD) | DBG_FUNC_NONE, SCHED_EDGE_RSRC_HEAVY_THREAD_SET, thread_tid(thread), type, agent);
	if (thread == current_thread()) {
		if (agent == SHARED_RSRC_POLICY_AGENT_PERFCTL_QUANTUM) {
			ast_on(AST_PREEMPT);
		} else {
			assert(agent != SHARED_RSRC_POLICY_AGENT_PERFCTL_CSW);
			thread_block(THREAD_CONTINUE_NULL);
		}
	}
	return KERN_SUCCESS;
}

kern_return_t
thread_shared_rsrc_policy_clear(thread_t thread, cluster_shared_rsrc_type_t type, shared_rsrc_policy_agent_t agent)
{
	spl_t s = splsched();
	thread_lock(thread);

	bool user = (agent == SHARED_RSRC_POLICY_AGENT_DISPATCH) || (agent == SHARED_RSRC_POLICY_AGENT_SYSCTL);
	bool *thread_flags = (user) ? thread->th_shared_rsrc_heavy_user : thread->th_shared_rsrc_heavy_perf_control;
	if (!thread_flags[type]) {
		thread_unlock(thread);
		splx(s);
		return KERN_FAILURE;
	}

	thread_flags[type] = false;
	thread_unlock(thread);
	splx(s);

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED_CLUTCH, MACH_SCHED_EDGE_RSRC_HEAVY_THREAD) | DBG_FUNC_NONE, SCHED_EDGE_RSRC_HEAVY_THREAD_CLR, thread_tid(thread), type, agent);
	if (thread == current_thread()) {
		if (agent == SHARED_RSRC_POLICY_AGENT_PERFCTL_QUANTUM) {
			ast_on(AST_PREEMPT);
		} else {
			assert(agent != SHARED_RSRC_POLICY_AGENT_PERFCTL_CSW);
			thread_block(THREAD_CONTINUE_NULL);
		}
	}
	return KERN_SUCCESS;
}

#else /* CONFIG_SCHED_EDGE */

/*
 * On non-Edge schedulers, the shared resource contention
 * is managed by simply binding threads to specific clusters
 * based on the worker index passed by the agents marking
 * this thread as resource heavy threads. The thread binding
 * approach does not provide any rebalancing opportunities;
 * it can also suffer from scheduling delays if the cluster
 * where the thread is bound is contended.
 */

boolean_t
thread_shared_rsrc_policy_get(__unused thread_t thread, __unused cluster_shared_rsrc_type_t type)
{
	return false;
}

kern_return_t
thread_shared_rsrc_policy_set(thread_t thread, uint32_t index, __unused cluster_shared_rsrc_type_t type, __unused shared_rsrc_policy_agent_t agent)
{
	return thread_bind_cluster_id(thread, index, THREAD_BIND_SOFT | THREAD_BIND_ELIGIBLE_ONLY);
}

kern_return_t
thread_shared_rsrc_policy_clear(thread_t thread, __unused cluster_shared_rsrc_type_t type, __unused shared_rsrc_policy_agent_t agent)
{
	return thread_bind_cluster_id(thread, 0, THREAD_UNBIND);
}

#endif /* CONFIG_SCHED_EDGE */

uint64_t
thread_dispatchqaddr(
	thread_t                thread)
{
	uint64_t        dispatchqueue_addr;
	uint64_t        thread_handle;
	task_t          task;

	if (thread == THREAD_NULL) {
		return 0;
	}

	thread_handle = thread->machine.cthread_self;
	if (thread_handle == 0) {
		return 0;
	}

	task = get_threadtask(thread);
	void *bsd_info = get_bsdtask_info(task);
	if (thread->inspection == TRUE) {
		dispatchqueue_addr = thread_handle + get_task_dispatchqueue_offset(task);
	} else if (bsd_info) {
		dispatchqueue_addr = thread_handle + get_dispatchqueue_offset_from_proc(bsd_info);
	} else {
		dispatchqueue_addr = 0;
	}

	return dispatchqueue_addr;
}


uint64_t
thread_wqquantum_addr(thread_t thread)
{
	uint64_t thread_handle;
	task_t   task;

	if (thread == THREAD_NULL) {
		return 0;
	}

	thread_handle = thread->machine.cthread_self;
	if (thread_handle == 0) {
		return 0;
	}
	task = get_threadtask(thread);

	uint64_t wq_quantum_expiry_offset = get_wq_quantum_offset_from_proc(get_bsdtask_info(task));
	if (wq_quantum_expiry_offset == 0) {
		return 0;
	}

	return wq_quantum_expiry_offset + thread_handle;
}

uint64_t
thread_rettokern_addr(
	thread_t                thread)
{
	uint64_t        rettokern_addr;
	uint64_t        rettokern_offset;
	uint64_t        thread_handle;
	task_t          task;
	void            *bsd_info;

	if (thread == THREAD_NULL) {
		return 0;
	}

	thread_handle = thread->machine.cthread_self;
	if (thread_handle == 0) {
		return 0;
	}
	task = get_threadtask(thread);
	bsd_info = get_bsdtask_info(task);

	if (bsd_info) {
		rettokern_offset = get_return_to_kernel_offset_from_proc(bsd_info);

		/* Return 0 if return to kernel offset is not initialized. */
		if (rettokern_offset == 0) {
			rettokern_addr = 0;
		} else {
			rettokern_addr = thread_handle + rettokern_offset;
		}
	} else {
		rettokern_addr = 0;
	}

	return rettokern_addr;
}

/*
 * Export routines to other components for things that are done as macros
 * within the osfmk component.
 */

void
thread_mtx_lock(thread_t thread)
{
	lck_mtx_lock(&thread->mutex);
}

void
thread_mtx_unlock(thread_t thread)
{
	lck_mtx_unlock(&thread->mutex);
}

void
thread_reference(
	thread_t        thread)
{
	if (thread != THREAD_NULL) {
		zone_id_require(ZONE_ID_THREAD, sizeof(struct thread), thread);
		os_ref_retain_raw(&thread->ref_count, &thread_refgrp);
	}
}

void
thread_require(thread_t thread)
{
	zone_id_require(ZONE_ID_THREAD, sizeof(struct thread), thread);
}

#undef thread_should_halt

boolean_t
thread_should_halt(
	thread_t                th)
{
	return thread_should_halt_fast(th);
}

/*
 * thread_set_voucher_name - reset the voucher port name bound to this thread
 *
 * Conditions:  nothing locked
 */

kern_return_t
thread_set_voucher_name(mach_port_name_t voucher_name)
{
	thread_t thread = current_thread();
	ipc_voucher_t new_voucher = IPC_VOUCHER_NULL;
	ipc_voucher_t voucher;
	ledger_t bankledger = NULL;
	struct thread_group *banktg = NULL;
	uint32_t persona_id = 0;

	if (MACH_PORT_DEAD == voucher_name) {
		return KERN_INVALID_RIGHT;
	}

	/*
	 * agressively convert to voucher reference
	 */
	if (MACH_PORT_VALID(voucher_name)) {
		new_voucher = convert_port_name_to_voucher(voucher_name);
		if (IPC_VOUCHER_NULL == new_voucher) {
			return KERN_INVALID_ARGUMENT;
		}
	}
	bank_get_bank_ledger_thread_group_and_persona(new_voucher, &bankledger, &banktg, &persona_id);

	thread_mtx_lock(thread);
	voucher = thread->ith_voucher;
	thread->ith_voucher_name = voucher_name;
	thread->ith_voucher = new_voucher;
	thread_mtx_unlock(thread);

	bank_swap_thread_bank_ledger(thread, bankledger);
#if CONFIG_THREAD_GROUPS
	thread_group_set_bank(thread, banktg);
#endif /* CONFIG_THREAD_GROUPS */

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_IPC, MACH_THREAD_SET_VOUCHER) | DBG_FUNC_NONE,
	    (uintptr_t)thread_tid(thread),
	    (uintptr_t)voucher_name,
	    VM_KERNEL_ADDRPERM((uintptr_t)new_voucher),
	    persona_id, 0);

	if (IPC_VOUCHER_NULL != voucher) {
		ipc_voucher_release(voucher);
	}

	return KERN_SUCCESS;
}

/*
 *  thread_get_mach_voucher - return a voucher reference for the specified thread voucher
 *
 *  Conditions:  nothing locked
 *
 *  NOTE:       At the moment, there is no distinction between the current and effective
 *		vouchers because we only set them at the thread level currently.
 */
kern_return_t
thread_get_mach_voucher(
	thread_act_t            thread,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t           *voucherp)
{
	ipc_voucher_t           voucher;

	if (THREAD_NULL == thread) {
		return KERN_INVALID_ARGUMENT;
	}

	thread_mtx_lock(thread);
	voucher = thread->ith_voucher;

	if (IPC_VOUCHER_NULL != voucher) {
		ipc_voucher_reference(voucher);
		thread_mtx_unlock(thread);
		*voucherp = voucher;
		return KERN_SUCCESS;
	}

	thread_mtx_unlock(thread);

	*voucherp = IPC_VOUCHER_NULL;
	return KERN_SUCCESS;
}

/*
 *  thread_set_mach_voucher - set a voucher reference for the specified thread voucher
 *
 *  Conditions: callers holds a reference on the voucher.
 *		nothing locked.
 *
 *  We grab another reference to the voucher and bind it to the thread.
 *  The old voucher reference associated with the thread is
 *  discarded.
 */
kern_return_t
thread_set_mach_voucher(
	thread_t                thread,
	ipc_voucher_t           voucher)
{
	ipc_voucher_t old_voucher;
	ledger_t bankledger = NULL;
	struct thread_group *banktg = NULL;
	uint32_t persona_id = 0;

	if (THREAD_NULL == thread) {
		return KERN_INVALID_ARGUMENT;
	}

	bank_get_bank_ledger_thread_group_and_persona(voucher, &bankledger, &banktg, &persona_id);

	thread_mtx_lock(thread);
	/*
	 * Once the thread is started, we will look at `ith_voucher` without
	 * holding any lock.
	 *
	 * Setting the voucher hence can only be done by current_thread() or
	 * before it started. "started" flips under the thread mutex and must be
	 * tested under it too.
	 */
	if (thread != current_thread() && thread->started) {
		thread_mtx_unlock(thread);
		return KERN_INVALID_ARGUMENT;
	}

	ipc_voucher_reference(voucher);
	old_voucher = thread->ith_voucher;
	thread->ith_voucher = voucher;
	thread->ith_voucher_name = MACH_PORT_NULL;
	thread_mtx_unlock(thread);

	bank_swap_thread_bank_ledger(thread, bankledger);
#if CONFIG_THREAD_GROUPS
	thread_group_set_bank(thread, banktg);
#endif /* CONFIG_THREAD_GROUPS */

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_IPC, MACH_THREAD_SET_VOUCHER) | DBG_FUNC_NONE,
	    (uintptr_t)thread_tid(thread),
	    (uintptr_t)MACH_PORT_NULL,
	    VM_KERNEL_ADDRPERM((uintptr_t)voucher),
	    persona_id, 0);

	ipc_voucher_release(old_voucher);

	return KERN_SUCCESS;
}

/*
 *  thread_swap_mach_voucher - swap a voucher reference for the specified thread voucher
 *
 *  Conditions: callers holds a reference on the new and presumed old voucher(s).
 *		nothing locked.
 *
 *  This function is no longer supported.
 */
kern_return_t
thread_swap_mach_voucher(
	__unused thread_t               thread,
	__unused ipc_voucher_t          new_voucher,
	ipc_voucher_t                   *in_out_old_voucher)
{
	/*
	 * Currently this function is only called from a MIG generated
	 * routine which doesn't release the reference on the voucher
	 * addressed by in_out_old_voucher. To avoid leaking this reference,
	 * a call to release it has been added here.
	 */
	ipc_voucher_release(*in_out_old_voucher);
	OS_ANALYZER_SUPPRESS("81787115") return KERN_NOT_SUPPORTED;
}

/*
 *  thread_get_current_voucher_origin_pid - get the pid of the originator of the current voucher.
 */
kern_return_t
thread_get_current_voucher_origin_pid(
	int32_t      *pid)
{
	return thread_get_voucher_origin_pid(current_thread(), pid);
}

/*
 *  thread_get_current_voucher_origin_pid - get the pid of the originator of the current voucher.
 */
kern_return_t
thread_get_voucher_origin_pid(thread_t thread, int32_t *pid)
{
	uint32_t buf_size = sizeof(*pid);
	return mach_voucher_attr_command(thread->ith_voucher,
	           MACH_VOUCHER_ATTR_KEY_BANK,
	           BANK_ORIGINATOR_PID,
	           NULL,
	           0,
	           (mach_voucher_attr_content_t)pid,
	           &buf_size);
}

#if CONFIG_THREAD_GROUPS
/*
 * Returns the current thread's voucher-carried thread group
 *
 * Reference is borrowed from this being the current voucher, so it does NOT
 * return a reference to the group.
 */
struct thread_group *
thread_get_current_voucher_thread_group(thread_t thread)
{
	assert(thread == current_thread());

	if (thread->ith_voucher == NULL) {
		return NULL;
	}

	ledger_t bankledger = NULL;
	struct thread_group *banktg = NULL;

	bank_get_bank_ledger_thread_group_and_persona(thread->ith_voucher, &bankledger, &banktg, NULL);

	return banktg;
}

#endif /* CONFIG_THREAD_GROUPS */

#if CONFIG_COALITIONS

uint64_t
thread_get_current_voucher_resource_coalition_id(thread_t thread)
{
	uint64_t id = 0;
	assert(thread == current_thread());
	if (thread->ith_voucher != NULL) {
		id = bank_get_bank_ledger_resource_coalition_id(thread->ith_voucher);
	}
	return id;
}

#endif /* CONFIG_COALITIONS */

extern struct workqueue *
proc_get_wqptr(void *proc);

static bool
task_supports_cooperative_workqueue(task_t task)
{
	void *bsd_info = get_bsdtask_info(task);

	assert(task == current_task());
	if (bsd_info == NULL) {
		return false;
	}

	uint64_t wq_quantum_expiry_offset = get_wq_quantum_offset_from_proc(bsd_info);
	/* userspace may not yet have called workq_open yet */
	struct workqueue *wq = proc_get_wqptr(bsd_info);

	return (wq != NULL) && (wq_quantum_expiry_offset != 0);
}

/* Not safe to call from scheduler paths - should only be called on self */
bool
thread_supports_cooperative_workqueue(thread_t thread)
{
	struct uthread *uth = get_bsdthread_info(thread);
	task_t task = get_threadtask(thread);

	assert(thread == current_thread());

	return task_supports_cooperative_workqueue(task) &&
	       bsdthread_part_of_cooperative_workqueue(uth);
}

static inline bool
thread_has_armed_workqueue_quantum(thread_t thread)
{
	return thread->workq_quantum_deadline != 0;
}

/*
 * The workq quantum is a lazy timer that is evaluated at 2 specific times in
 * the scheduler:
 *
 * - context switch time
 * - scheduler quantum expiry time.
 *
 * We're currently expressing the workq quantum with a 0.5 scale factor of the
 * scheduler quantum. It is possible that if the workq quantum is rearmed
 * shortly after the scheduler quantum begins, we could have a large delay
 * between when the workq quantum next expires and when it actually is noticed.
 *
 * A potential future improvement for the wq quantum expiry logic is to compare
 * it to the next actual scheduler quantum deadline and expire it if it is
 * within a certain leeway.
 */
static inline uint64_t
thread_workq_quantum_size(thread_t thread)
{
	return (uint64_t) (SCHED(initial_quantum_size)(thread) / 2);
}

/*
 * Always called by thread on itself - either at AST boundary after processing
 * an existing quantum expiry, or when a new quantum is armed before the thread
 * goes out to userspace to handle a thread request
 */
void
thread_arm_workqueue_quantum(thread_t thread)
{
	/*
	 * If the task is not opted into wq quantum notification, or if the thread
	 * is not part of the cooperative workqueue, don't even bother with tracking
	 * the quantum or calculating expiry
	 */
	if (!thread_supports_cooperative_workqueue(thread)) {
		assert(thread->workq_quantum_deadline == 0);
		return;
	}

	assert(current_thread() == thread);
	assert(thread_get_tag(thread) & THREAD_TAG_WORKQUEUE);

	uint64_t current_runtime = thread_get_runtime_self();
	uint64_t deadline = thread_workq_quantum_size(thread) + current_runtime;

	/*
	 * The update of a workqueue quantum should always be followed by the update
	 * of the AST - see explanation in kern/thread.h for synchronization of this
	 * field
	 */
	thread->workq_quantum_deadline = deadline;

	/* We're arming a new quantum, clear any previous expiry notification */
	act_clear_astkevent(thread, AST_KEVENT_WORKQ_QUANTUM_EXPIRED);

	WQ_TRACE(TRACE_wq_quantum_arm, current_runtime, deadline, 0, 0);

	WORKQ_QUANTUM_HISTORY_WRITE_ENTRY(thread, thread->workq_quantum_deadline, true);
}

/* Called by a thread on itself when it is about to park */
void
thread_disarm_workqueue_quantum(thread_t thread)
{
	/* The update of a workqueue quantum should always be followed by the update
	 * of the AST - see explanation in kern/thread.h for synchronization of this
	 * field */
	thread->workq_quantum_deadline = 0;
	act_clear_astkevent(thread, AST_KEVENT_WORKQ_QUANTUM_EXPIRED);

	WQ_TRACE(TRACE_wq_quantum_disarm, 0, 0, 0, 0);

	WORKQ_QUANTUM_HISTORY_WRITE_ENTRY(thread, thread->workq_quantum_deadline, false);
}

/* This is called at context switch time on a thread that may not be self,
 * and at AST time
 */
bool
thread_has_expired_workqueue_quantum(thread_t thread, bool should_trace)
{
	if (!thread_has_armed_workqueue_quantum(thread)) {
		return false;
	}
	/* We do not do a thread_get_runtime_self() here since this function is
	 * called from context switch time or during scheduler quantum expiry and
	 * therefore, we may not be evaluating it on the current thread/self.
	 *
	 * In addition, the timers on the thread have just been updated recently so
	 * we don't need to update them again.
	 */
	uint64_t runtime = recount_thread_time_mach(thread);
	bool expired = runtime > thread->workq_quantum_deadline;

	if (expired && should_trace) {
		WQ_TRACE(TRACE_wq_quantum_expired, runtime, thread->workq_quantum_deadline, 0, 0);
	}

	return expired;
}

/*
 * Called on a thread that is being context switched out or during quantum
 * expiry on self. Only called from scheduler paths.
 */
void
thread_evaluate_workqueue_quantum_expiry(thread_t thread)
{
	if (thread_has_expired_workqueue_quantum(thread, true)) {
		act_set_astkevent(thread, AST_KEVENT_WORKQ_QUANTUM_EXPIRED);
	}
}

boolean_t
thread_has_thread_name(thread_t th)
{
	if (th) {
		return bsd_hasthreadname(get_bsdthread_info(th));
	}

	/*
	 * This is an odd case; clients may set the thread name based on the lack of
	 * a name, but in this context there is no uthread to attach the name to.
	 */
	return FALSE;
}

void
thread_set_thread_name(thread_t th, const char* name)
{
	if (th && name) {
		bsd_setthreadname(get_bsdthread_info(th), name);
	}
}

void
thread_get_thread_name(thread_t th, char* name)
{
	if (!name) {
		return;
	}
	if (th) {
		bsd_getthreadname(get_bsdthread_info(th), name);
	} else {
		name[0] = '\0';
	}
}

void
thread_set_honor_qlimit(thread_t thread)
{
	thread->options |= TH_OPT_HONOR_QLIMIT;
}

void
thread_clear_honor_qlimit(thread_t thread)
{
	thread->options &= (~TH_OPT_HONOR_QLIMIT);
}

/*
 * thread_enable_send_importance - set/clear the SEND_IMPORTANCE thread option bit.
 */
void
thread_enable_send_importance(thread_t thread, boolean_t enable)
{
	if (enable == TRUE) {
		thread->options |= TH_OPT_SEND_IMPORTANCE;
	} else {
		thread->options &= ~TH_OPT_SEND_IMPORTANCE;
	}
}

kern_return_t
thread_get_ipc_propagate_attr(thread_t thread, struct thread_attr_for_ipc_propagation *attr)
{
	int iotier;
	int qos;

	if (thread == NULL || attr == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	iotier = proc_get_effective_thread_policy(thread, TASK_POLICY_IO);
	qos = proc_get_effective_thread_policy(thread, TASK_POLICY_QOS);

	attr->tafip_iotier = iotier;
	attr->tafip_qos = qos;

	return KERN_SUCCESS;
}

/*
 * thread_set_allocation_name - .
 */

kern_allocation_name_t
thread_set_allocation_name(kern_allocation_name_t new_name)
{
	kern_allocation_name_t ret;
	thread_kernel_state_t kstate = thread_get_kernel_state(current_thread());
	ret = kstate->allocation_name;
	// fifo
	if (!new_name || !kstate->allocation_name) {
		kstate->allocation_name = new_name;
	}
	return ret;
}

void *
thread_iokit_tls_get(uint32_t index)
{
	assert(index < THREAD_SAVE_IOKIT_TLS_COUNT);
	return current_thread()->saved.iokit.tls[index];
}

void
thread_iokit_tls_set(uint32_t index, void * data)
{
	assert(index < THREAD_SAVE_IOKIT_TLS_COUNT);
	current_thread()->saved.iokit.tls[index] = data;
}

uint64_t
thread_get_last_wait_duration(thread_t thread)
{
	return thread->last_made_runnable_time - thread->last_run_time;
}

integer_t
thread_kern_get_pri(thread_t thr)
{
	return thr->base_pri;
}

void
thread_kern_set_pri(thread_t thr, integer_t pri)
{
	sched_set_kernel_thread_priority(thr, pri);
}

integer_t
thread_kern_get_kernel_maxpri(void)
{
	return MAXPRI_KERNEL;
}
/*
 *	thread_port_with_flavor_no_senders
 *
 *	Called whenever the Mach port system detects no-senders on
 *	the thread inspect or read port. These ports are allocated lazily and
 *	should be deallocated here when there are no senders remaining.
 */
static void
thread_port_with_flavor_no_senders(
	ipc_port_t          port,
	mach_port_mscount_t mscount __unused)
{
	thread_ro_t tro;
	thread_t thread;
	mach_thread_flavor_t flavor;
	ipc_kobject_type_t kotype;

	ip_mq_lock(port);
	if (port->ip_srights > 0) {
		ip_mq_unlock(port);
		return;
	}
	kotype = ip_kotype(port);
	assert((IKOT_THREAD_READ == kotype) || (IKOT_THREAD_INSPECT == kotype));
	thread = ipc_kobject_get_locked(port, kotype);
	if (thread != THREAD_NULL) {
		thread_reference(thread);
	}
	ip_mq_unlock(port);

	if (thread == THREAD_NULL) {
		/* The thread is exiting or disabled; it will eventually deallocate the port */
		return;
	}

	if (kotype == IKOT_THREAD_READ) {
		flavor = THREAD_FLAVOR_READ;
	} else {
		flavor = THREAD_FLAVOR_INSPECT;
	}

	thread_mtx_lock(thread);
	ip_mq_lock(port);

	/*
	 * If the port is no longer active, then ipc_thread_terminate() ran
	 * and destroyed the kobject already. Just deallocate the task
	 * ref we took and go away.
	 *
	 * It is also possible that several nsrequests are in flight,
	 * only one shall NULL-out the port entry, and this is the one
	 * that gets to dealloc the port.
	 *
	 * Check for a stale no-senders notification. A call to any function
	 * that vends out send rights to this port could resurrect it between
	 * this notification being generated and actually being handled here.
	 */
	tro = get_thread_ro(thread);
	if (!ip_active(port) ||
	    tro->tro_ports[flavor] != port ||
	    port->ip_srights > 0) {
		ip_mq_unlock(port);
		thread_mtx_unlock(thread);
		thread_deallocate(thread);
		return;
	}

	assert(tro->tro_ports[flavor] == port);
	zalloc_ro_clear_field(ZONE_ID_THREAD_RO, tro, tro_ports[flavor]);
	thread_mtx_unlock(thread);

	ipc_kobject_dealloc_port_and_unlock(port, 0, kotype);

	thread_deallocate(thread);
}

/*
 * The 'thread_region_page_shift' is used by footprint
 * to specify the page size that it will use to
 * accomplish its accounting work on the task being
 * inspected. Since footprint uses a thread for each
 * task that it works on, we need to keep the page_shift
 * on a per-thread basis.
 */

int
thread_self_region_page_shift(void)
{
	/*
	 * Return the page shift that this thread
	 * would like to use for its accounting work.
	 */
	return current_thread()->thread_region_page_shift;
}

void
thread_self_region_page_shift_set(
	int pgshift)
{
	/*
	 * Set the page shift that this thread
	 * would like to use for its accounting work
	 * when dealing with a task.
	 */
	current_thread()->thread_region_page_shift = pgshift;
}

__startup_func
static void
ctid_table_init(void)
{
	/*
	 * Pretend the early boot setup didn't exist,
	 * and pick a mangling nonce.
	 */
	*compact_id_resolve(&ctid_table, 0) = THREAD_NULL;
	ctid_nonce = (uint32_t)early_random() & CTID_MASK;
}


/*
 * This maps the [0, CTID_MAX_THREAD_NUMBER] range
 * to [1, CTID_MAX_THREAD_NUMBER + 1 == CTID_MASK]
 * so that in mangled form, '0' is an invalid CTID.
 */
static ctid_t
ctid_mangle(compact_id_t cid)
{
	return (cid == ctid_nonce ? CTID_MASK : cid) ^ ctid_nonce;
}

static compact_id_t
ctid_unmangle(ctid_t ctid)
{
	ctid ^= ctid_nonce;
	return ctid == CTID_MASK ? ctid_nonce : ctid;
}

void
ctid_table_add(thread_t thread)
{
	compact_id_t cid;

	cid = compact_id_get(&ctid_table, CTID_MAX_THREAD_NUMBER, thread);
	thread->ctid = ctid_mangle(cid);
}

void
ctid_table_remove(thread_t thread)
{
	__assert_only thread_t value;

	value = compact_id_put(&ctid_table, ctid_unmangle(thread->ctid));
	assert3p(value, ==, thread);
	thread->ctid = 0;
}

thread_t
ctid_get_thread_unsafe(ctid_t ctid)
{
	if (ctid) {
		return *compact_id_resolve(&ctid_table, ctid_unmangle(ctid));
	}
	return THREAD_NULL;
}

thread_t
ctid_get_thread(ctid_t ctid)
{
	thread_t thread = THREAD_NULL;

	if (ctid) {
		thread = *compact_id_resolve(&ctid_table, ctid_unmangle(ctid));
		assert(thread && thread->ctid == ctid);
	}
	return thread;
}

ctid_t
thread_get_ctid(thread_t thread)
{
	return thread->ctid;
}

/*
 * Adjust code signature dependent thread state.
 *
 * Called to allow code signature dependent adjustments to the thread
 * state. Note that this is usually called twice for the main thread:
 * Once at thread creation by thread_create, when the signature is
 * potentially not attached yet (which is usually the case for the
 * first/main thread of a task), and once after the task's signature
 * has actually been attached.
 *
 */
kern_return_t
thread_process_signature(thread_t thread, task_t task)
{
	return machine_thread_process_signature(thread, task);
}


#if CONFIG_DTRACE
uint32_t
dtrace_get_thread_predcache(thread_t thread)
{
	if (thread != THREAD_NULL) {
		return thread->t_dtrace_predcache;
	} else {
		return 0;
	}
}

int64_t
dtrace_get_thread_vtime(thread_t thread)
{
	if (thread != THREAD_NULL) {
		return thread->t_dtrace_vtime;
	} else {
		return 0;
	}
}

int
dtrace_get_thread_last_cpu_id(thread_t thread)
{
	if ((thread != THREAD_NULL) && (thread->last_processor != PROCESSOR_NULL)) {
		return thread->last_processor->cpu_id;
	} else {
		return -1;
	}
}

int64_t
dtrace_get_thread_tracing(thread_t thread)
{
	if (thread != THREAD_NULL) {
		return thread->t_dtrace_tracing;
	} else {
		return 0;
	}
}

uint16_t
dtrace_get_thread_inprobe(thread_t thread)
{
	if (thread != THREAD_NULL) {
		return thread->t_dtrace_inprobe;
	} else {
		return 0;
	}
}

vm_offset_t
thread_get_kernel_stack(thread_t thread)
{
	if (thread != THREAD_NULL) {
		return thread->kernel_stack;
	} else {
		return 0;
	}
}

#if KASAN
struct kasan_thread_data *
kasan_get_thread_data(thread_t thread)
{
	return &thread->kasan_data;
}
#endif

#if CONFIG_KCOV
kcov_thread_data_t *
kcov_get_thread_data(thread_t thread)
{
	return &thread->kcov_data;
}
#endif

#if CONFIG_STKSZ
/*
 * Returns base of a thread's kernel stack.
 *
 * Coverage sanitizer instruments every function including those that participates in stack handoff between threads.
 * There is a window in which CPU still holds old values but stack has been handed over to anoher thread already.
 * In this window kernel_stack is 0 but CPU still uses the original stack (until contex switch occurs). The original
 * kernel_stack value is preserved in ksancov_stack during this window.
 */
vm_offset_t
kcov_stksz_get_thread_stkbase(thread_t thread)
{
	if (thread != THREAD_NULL) {
		kcov_thread_data_t *data = kcov_get_thread_data(thread);
		if (data->ktd_stksz.kst_stack) {
			return data->ktd_stksz.kst_stack;
		} else {
			return thread->kernel_stack;
		}
	} else {
		return 0;
	}
}

vm_offset_t
kcov_stksz_get_thread_stksize(thread_t thread)
{
	if (thread != THREAD_NULL) {
		return kernel_stack_size;
	} else {
		return 0;
	}
}

void
kcov_stksz_set_thread_stack(thread_t thread, vm_offset_t stack)
{
	kcov_thread_data_t *data = kcov_get_thread_data(thread);
	data->ktd_stksz.kst_stack = stack;
}
#endif /* CONFIG_STKSZ */

int64_t
dtrace_calc_thread_recent_vtime(thread_t thread)
{
	if (thread == THREAD_NULL) {
		return 0;
	}

	struct recount_usage usage = { 0 };
	recount_current_thread_usage(&usage);
	return (int64_t)(usage.ru_system_time_mach + usage.ru_user_time_mach);
}

void
dtrace_set_thread_predcache(thread_t thread, uint32_t predcache)
{
	if (thread != THREAD_NULL) {
		thread->t_dtrace_predcache = predcache;
	}
}

void
dtrace_set_thread_vtime(thread_t thread, int64_t vtime)
{
	if (thread != THREAD_NULL) {
		thread->t_dtrace_vtime = vtime;
	}
}

void
dtrace_set_thread_tracing(thread_t thread, int64_t accum)
{
	if (thread != THREAD_NULL) {
		thread->t_dtrace_tracing = accum;
	}
}

void
dtrace_set_thread_inprobe(thread_t thread, uint16_t inprobe)
{
	if (thread != THREAD_NULL) {
		thread->t_dtrace_inprobe = inprobe;
	}
}

void
dtrace_thread_bootstrap(void)
{
	task_t task = current_task();

	if (task->thread_count == 1) {
		thread_t thread = current_thread();
		if (thread->t_dtrace_flags & TH_DTRACE_EXECSUCCESS) {
			thread->t_dtrace_flags &= ~TH_DTRACE_EXECSUCCESS;
			DTRACE_PROC(exec__success);
			KDBG(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXEC),
			    task_pid(task));
		}
		DTRACE_PROC(start);
	}
	DTRACE_PROC(lwp__start);
}

void
dtrace_thread_didexec(thread_t thread)
{
	thread->t_dtrace_flags |= TH_DTRACE_EXECSUCCESS;
}
#endif /* CONFIG_DTRACE */
