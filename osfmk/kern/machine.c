/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
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
 *	File:	kern/machine.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1987
 *
 *	Support for machine independent machine abstraction.
 */

#include <string.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <mach/host_info.h>
#include <mach/host_reboot.h>
#include <mach/host_priv_server.h>
#include <mach/processor_server.h>
#include <mach/sdt.h>

#include <kern/kern_types.h>
#include <kern/cpu_data.h>
#include <kern/cpu_quiesce.h>
#include <kern/ipc_host.h>
#include <kern/host.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/percpu.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/iotrace.h>

#include <libkern/OSDebug.h>
#if ML_IO_TIMEOUTS_ENABLED
#include <libkern/tree.h>
#endif

#include <pexpert/device_tree.h>

#include <machine/commpage.h>
#include <machine/machine_routines.h>

#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <IOKit/IOPlatformExpert.h>

#if CONFIG_DTRACE
extern void (*dtrace_cpu_state_changed_hook)(int, boolean_t);
#endif

#if defined(__arm64__)
extern void wait_while_mp_kdp_trap(bool check_SIGPdebug);
#endif

#if defined(__x86_64__)
#include <i386/panic_notify.h>
#endif

/*
 *	Exported variables:
 */

struct machine_info     machine_info;

/* Forwards */
static void
processor_doshutdown(processor_t processor);

static void
processor_offline(void * parameter, __unused wait_result_t result);

static void
processor_offline_intstack(processor_t processor) __dead2;

static void
processor_up_update_counts(processor_t processor)
{
	ml_cpu_up_update_counts(processor->cpu_id);

	os_atomic_inc(&processor_avail_count, relaxed);
	if (processor->is_recommended) {
		os_atomic_inc(&processor_avail_count_user, relaxed);
	}
	if (processor->processor_primary == processor) {
		os_atomic_inc(&primary_processor_avail_count, relaxed);
		if (processor->is_recommended) {
			os_atomic_inc(&primary_processor_avail_count_user, relaxed);
		}
	}
	commpage_update_active_cpus();
}

/*
 *	processor_up:
 *
 *	Flag processor as up and running, and available
 *	for scheduling.
 */
void
processor_up(
	processor_t                     processor)
{
	processor_set_t         pset;
	spl_t                           s;

	s = splsched();
	init_ast_check(processor);

#if defined(__arm64__)
	/*
	 * A processor coming online won't have received a SIGPdebug signal
	 * to cause it to spin while a stackshot or panic is taking place,
	 * so spin here on mp_kdp_trap.
	 *
	 * However, since cpu_signal() is not yet enabled for this processor,
	 * there is a race if we have just passed this when a cpu_signal()
	 * is attempted.  The sender will assume the cpu is offline, so it will
	 * not end up spinning anywhere.  See processor_offline() for the fix
	 * for this race.
	 */
	wait_while_mp_kdp_trap(false);
#endif

	pset = processor->processor_set;
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);
	pset_lock(pset);

	++pset->online_processor_count;
	simple_lock(&processor->start_state_lock, LCK_GRP_NULL);
	pset_update_processor_state(pset, processor, PROCESSOR_RUNNING);
	simple_unlock(&processor->start_state_lock);
	bool temporary = processor->shutdown_temporary;
	if (temporary) {
		processor->shutdown_temporary = false;
	} else {
		processor_up_update_counts(processor);
	}
	if (processor->is_recommended) {
		SCHED(pset_made_schedulable)(processor, pset, false);
	}
	pset_unlock(pset);
	ml_cpu_up();
	sched_mark_processor_online_locked(processor, processor->last_startup_reason);
	simple_unlock(&sched_available_cores_lock);
	splx(s);

	thread_wakeup((event_t)&processor->state);

#if CONFIG_DTRACE
	if (dtrace_cpu_state_changed_hook) {
		(*dtrace_cpu_state_changed_hook)(processor->cpu_id, TRUE);
	}
#endif
}
#include <atm/atm_internal.h>

kern_return_t
host_reboot(
	host_priv_t             host_priv,
	int                             options)
{
	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_HOST;
	}

#if DEVELOPMENT || DEBUG
	if (options & HOST_REBOOT_DEBUGGER) {
		Debugger("Debugger");
		return KERN_SUCCESS;
	}
#endif

	if (options & HOST_REBOOT_UPSDELAY) {
		// UPS power cutoff path
		PEHaltRestart( kPEUPSDelayHaltCPU );
	} else {
		halt_all_cpus(!(options & HOST_REBOOT_HALT));
	}

	return KERN_SUCCESS;
}

kern_return_t
processor_assign(
	__unused processor_t            processor,
	__unused processor_set_t        new_pset,
	__unused boolean_t              wait)
{
	return KERN_FAILURE;
}

static void
processor_down_update_counts(processor_t processor)
{
	ml_cpu_down_update_counts(processor->cpu_id);

	os_atomic_dec(&processor_avail_count, relaxed);
	if (processor->is_recommended) {
		os_atomic_dec(&processor_avail_count_user, relaxed);
	}
	if (processor->processor_primary == processor) {
		os_atomic_dec(&primary_processor_avail_count, relaxed);
		if (processor->is_recommended) {
			os_atomic_dec(&primary_processor_avail_count_user, relaxed);
		}
	}
	commpage_update_active_cpus();
}

extern lck_mtx_t processor_updown_lock;

kern_return_t
processor_shutdown(
	processor_t                     processor,
	processor_reason_t              reason,
	uint32_t                        flags)
{
	if (!ml_cpu_can_exit(processor->cpu_id, reason)) {
		/*
		 * Failure if disallowed by arch code.
		 */
		return KERN_NOT_SUPPORTED;
	}

	lck_mtx_lock(&processor_updown_lock);

	kern_return_t mark_ret = sched_mark_processor_offline(processor, reason);
	if (mark_ret != KERN_SUCCESS) {
		/* Must fail or we deadlock */
		lck_mtx_unlock(&processor_updown_lock);
		return KERN_FAILURE;
	}

	ml_cpu_begin_state_transition(processor->cpu_id);
	spl_t s = splsched();
	processor_set_t pset = processor->processor_set;

	pset_lock(pset);
	if (processor->state == PROCESSOR_OFF_LINE) {
		/*
		 * Success if already shutdown.
		 */
		if (processor->shutdown_temporary && !(flags & SHUTDOWN_TEMPORARY)) {
			/* Convert a temporary shutdown into a permanent shutdown */
			processor->shutdown_temporary = false;
			processor_down_update_counts(processor);
		}
		pset_unlock(pset);
		splx(s);
		ml_cpu_end_state_transition(processor->cpu_id);

		lck_mtx_unlock(&processor_updown_lock);
		return KERN_SUCCESS;
	}

	if (processor->shutdown_locked && (reason != REASON_SYSTEM)) {
		/*
		 * Failure if processor is locked against shutdown.
		 */
		pset_unlock(pset);
		splx(s);

		lck_mtx_unlock(&processor_updown_lock);
		return KERN_FAILURE;
	}

	if (processor->state == PROCESSOR_START) {
		pset_unlock(pset);
		splx(s);

		processor_wait_for_start(processor);

		s = splsched();
		pset_lock(pset);
	}

	/*
	 * If the processor is dispatching, let it finish.
	 */
	while (processor->state == PROCESSOR_DISPATCHING) {
		pset_unlock(pset);
		splx(s);
		delay(1);
		s = splsched();
		pset_lock(pset);
	}

	/*
	 * Success if already being shutdown with matching SHUTDOWN_TEMPORARY flag.
	 */
	if ((processor->state == PROCESSOR_SHUTDOWN) || (processor->state == PROCESSOR_PENDING_OFFLINE)) {
		bool success = (flags & SHUTDOWN_TEMPORARY) ? processor->shutdown_temporary : !processor->shutdown_temporary;

		pset_unlock(pset);
		splx(s);
		ml_cpu_end_state_transition(processor->cpu_id);

		lck_mtx_unlock(&processor_updown_lock);
		return success ? KERN_SUCCESS : KERN_FAILURE;
	}

	ml_broadcast_cpu_event(CPU_EXIT_REQUESTED, processor->cpu_id);
	pset_update_processor_state(pset, processor, PROCESSOR_SHUTDOWN);
	processor->last_shutdown_reason = reason;
	if (flags & SHUTDOWN_TEMPORARY) {
		processor->shutdown_temporary = true;
	}
	pset_unlock(pset);

	processor_doshutdown(processor);
	splx(s);

	cpu_exit_wait(processor->cpu_id);

	if (processor != master_processor) {
		s = splsched();
		pset_lock(pset);
		pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
		pset_unlock(pset);
		splx(s);
	}

	ml_cpu_end_state_transition(processor->cpu_id);
	ml_broadcast_cpu_event(CPU_EXITED, processor->cpu_id);
	ml_cpu_power_disable(processor->cpu_id);

	lck_mtx_unlock(&processor_updown_lock);
	return KERN_SUCCESS;
}

/*
 * Called with interrupts disabled.
 */
static void
processor_doshutdown(
	processor_t processor)
{
	thread_t self = current_thread();

	/*
	 *	Get onto the processor to shutdown
	 */
	processor_t prev = thread_bind(processor);
	thread_block(THREAD_CONTINUE_NULL);

	/* interrupts still disabled */
	assert(ml_get_interrupts_enabled() == FALSE);

	assert(processor == current_processor());
	assert(processor->state == PROCESSOR_SHUTDOWN);

#if CONFIG_DTRACE
	if (dtrace_cpu_state_changed_hook) {
		(*dtrace_cpu_state_changed_hook)(processor->cpu_id, FALSE);
	}
#endif

#if defined(__arm64__)
	/*
	 * Catch a processor going offline
	 * while a panic or stackshot is in progress, as it won't
	 * receive a SIGPdebug now that interrupts are disabled.
	 */
	wait_while_mp_kdp_trap(false);
#endif

	ml_cpu_down();

#if HIBERNATION
	if (processor_avail_count < 2) {
		hibernate_vm_lock();
		hibernate_vm_unlock();
	}
#endif

	processor_set_t pset = processor->processor_set;

	pset_lock(pset);
	pset_update_processor_state(pset, processor, PROCESSOR_PENDING_OFFLINE);
	--pset->online_processor_count;
	if (!processor->shutdown_temporary) {
		processor_down_update_counts(processor);
	}
	SCHED(processor_queue_shutdown)(processor);
	/* pset lock dropped */
	SCHED(rt_queue_shutdown)(processor);

	thread_bind(prev);

	/* interrupts still disabled */

	/*
	 * Continue processor shutdown on the processor's idle thread.
	 * The handoff won't fail because the idle thread has a reserved stack.
	 * Switching to the idle thread leaves interrupts disabled,
	 * so we can't accidentally take an interrupt after the context switch.
	 */
	thread_t shutdown_thread = processor->idle_thread;
	shutdown_thread->continuation = processor_offline;
	shutdown_thread->parameter = processor;

	thread_run(self, NULL, NULL, shutdown_thread);
}

/*
 * Called in the context of the idle thread to shut down the processor
 *
 * A shut-down processor looks like it's 'running' the idle thread parked
 * in this routine, but it's actually been powered off and has no hardware state.
 */
static void
processor_offline(
	void * parameter,
	__unused wait_result_t result)
{
	processor_t processor = (processor_t) parameter;
	thread_t self = current_thread();
	__assert_only thread_t old_thread = THREAD_NULL;

	assert(processor == current_processor());
	assert(self->state & TH_IDLE);
	assert(processor->idle_thread == self);
	assert(ml_get_interrupts_enabled() == FALSE);
	assert(self->continuation == NULL);
	assert(processor->processor_offlined == false);
	assert(processor->running_timers_active == false);

	bool enforce_quiesce_safety = gEnforcePlatformActionSafety;

	/*
	 * Scheduling is now disabled for this processor.
	 * Ensure that primitives that need scheduling (like mutexes) know this.
	 */
	if (enforce_quiesce_safety) {
		disable_preemption_without_measurements();
	}

	/* convince slave_main to come back here */
	processor->processor_offlined = true;

	/*
	 * Switch to the interrupt stack and shut down the processor.
	 *
	 * When the processor comes back, it will eventually call load_context which
	 * restores the context saved by machine_processor_shutdown, returning here.
	 */
	old_thread = machine_processor_shutdown(self, processor_offline_intstack, processor);

	/* old_thread should be NULL because we got here through Load_context */
	assert(old_thread == THREAD_NULL);

	assert(processor == current_processor());
	assert(processor->idle_thread == current_thread());

	assert(ml_get_interrupts_enabled() == FALSE);
	assert(self->continuation == NULL);

	/* Extract the machine_param value stashed by slave_main */
	void * machine_param = self->parameter;
	self->parameter = NULL;

	/* Re-initialize the processor */
	slave_machine_init(machine_param);

	assert(processor->processor_offlined == true);
	processor->processor_offlined = false;

	if (enforce_quiesce_safety) {
		enable_preemption();
	}

#if defined(__arm64__)
	/*
	 * See the comments for DebuggerLock in processor_up().
	 *
	 * SIGPdisabled is cleared (to enable cpu_signal() to succeed with this processor)
	 * the first time we take an IPI.  This is triggered by slave_machine_init(), above,
	 * which calls cpu_machine_init()->PE_cpu_machine_init()->PE_cpu_signal() which sends
	 * a self-IPI to ensure that happens when we enable interrupts.  So enable interrupts
	 * here so that cpu_signal() can succeed before we spin on mp_kdp_trap.
	 */
	ml_set_interrupts_enabled(TRUE);

	ml_set_interrupts_enabled(FALSE);

	wait_while_mp_kdp_trap(true);

	/*
	 * At this point,
	 * if a stackshot or panic is in progress, we either spin on mp_kdp_trap
	 * or we sucessfully received a SIGPdebug signal which will cause us to
	 * break out of the spin on mp_kdp_trap and instead
	 * spin next time interrupts are enabled in idle_thread().
	 */
#endif

	/*
	 * Now that the processor is back, invoke the idle thread to find out what to do next.
	 * idle_thread will enable interrupts.
	 */
	thread_block(idle_thread);
	/*NOTREACHED*/
}

/*
 * Complete the shutdown and place the processor offline.
 *
 * Called at splsched in the shutdown context
 * (i.e. on the idle thread, on the interrupt stack)
 *
 * The onlining half of this is done in load_context().
 */
static void
processor_offline_intstack(
	processor_t processor)
{
	assert(processor == current_processor());
	assert(processor->active_thread == current_thread());

	struct recount_snap snap = { 0 };
	recount_snapshot(&snap);
	recount_processor_idle(&processor->pr_recount, &snap);

	cpu_quiescent_counter_leave(processor->last_dispatch);

	PMAP_DEACTIVATE_KERNEL(processor->cpu_id);

	cpu_sleep();
	panic("zombie processor");
	/*NOTREACHED*/
}

kern_return_t
host_get_boot_info(
	host_priv_t         host_priv,
	kernel_boot_info_t  boot_info)
{
	const char *src = "";
	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_HOST;
	}

	/*
	 * Copy first operator string terminated by '\0' followed by
	 *	standardized strings generated from boot string.
	 */
	src = machine_boot_info(boot_info, KERNEL_BOOT_INFO_MAX);
	if (src != boot_info) {
		(void) strncpy(boot_info, src, KERNEL_BOOT_INFO_MAX);
	}

	return KERN_SUCCESS;
}

// These are configured through sysctls.
#if DEVELOPMENT || DEBUG
uint32_t phy_read_panic = 1;
uint32_t phy_write_panic = 1;
uint64_t simulate_stretched_io = 0;
#else
uint32_t phy_read_panic = 0;
uint32_t phy_write_panic = 0;
#endif

#if !defined(__x86_64__)
// The MACHINE_TIMEOUT facility only exists on ARM.
MACHINE_TIMEOUT_WRITEABLE(report_phy_read_delay_to, "report-phy-read-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT_WRITEABLE(report_phy_write_delay_to, "report-phy-write-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT_WRITEABLE(trace_phy_read_delay_to, "trace-phy-read-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT_WRITEABLE(trace_phy_write_delay_to, "trace-phy-write-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

#if SCHED_HYGIENE_DEBUG
/*
 * Note: The interrupt-masked timeout goes through two initializations - one
 * early in boot and one later. Thus this function is also called twice and
 * can't be marked '__startup_func'.
 */
static void
ml_io_init_timeouts(void)
{
	/*
	 * The timeouts may be completely disabled via an override. Check that
	 * last and set the timeouts to zero (disabling) if that's the case.
	 */
	if (kern_feature_override(KF_IO_TIMEOUT_OVRD)) {
		os_atomic_store(&report_phy_write_delay_to, 0, relaxed);
		os_atomic_store(&report_phy_read_delay_to, 0, relaxed);
	}
}

/*
 * It's important that this happens after machine timeouts have initialized so
 * the correct timeouts can be inherited.
 */
STARTUP(TIMEOUTS, STARTUP_RANK_SECOND, ml_io_init_timeouts);
#endif /* SCHED_HYGIENE_DEBUG */

unsigned int report_phy_read_osbt;
unsigned int report_phy_write_osbt;

extern pmap_paddr_t kvtophys(vm_offset_t va);
#endif

#if ML_IO_TIMEOUTS_ENABLED

static LCK_GRP_DECLARE(io_timeout_override_lock_grp, "io_timeout_override");
static LCK_SPIN_DECLARE(io_timeout_override_lock, &io_timeout_override_lock_grp);

struct io_timeout_override_entry {
	RB_ENTRY(io_timeout_override_entry) tree;

	uintptr_t iovaddr_base;
	unsigned int size;
	uint32_t read_timeout;
	uint32_t write_timeout;
};

static inline int
io_timeout_override_cmp(const struct io_timeout_override_entry *a, const struct io_timeout_override_entry *b)
{
	if (a->iovaddr_base < b->iovaddr_base) {
		return -1;
	} else if (a->iovaddr_base > b->iovaddr_base) {
		return 1;
	} else {
		return 0;
	}
}

static RB_HEAD(io_timeout_override, io_timeout_override_entry) io_timeout_override_root;
RB_PROTOTYPE_PREV(io_timeout_override, io_timeout_override_entry, tree, io_timeout_override_cmp);
RB_GENERATE_PREV(io_timeout_override, io_timeout_override_entry, tree, io_timeout_override_cmp);

#endif /* ML_IO_TIMEOUTS_ENABLED */

int
ml_io_increase_timeouts(uintptr_t iovaddr_base, unsigned int size, uint32_t read_timeout_us, uint32_t write_timeout_us)
{
#if ML_IO_TIMEOUTS_ENABLED
	const size_t MAX_SIZE = 4096;
	const uint64_t MAX_TIMEOUT_ABS = UINT32_MAX;

	assert(preemption_enabled());

	int ret = KERN_SUCCESS;

	if (size == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	uintptr_t iovaddr_end;
	if (size > MAX_SIZE || os_add_overflow(iovaddr_base, size - 1, &iovaddr_end)) {
		return KERN_INVALID_ARGUMENT;
	}

	uint64_t read_timeout_abs, write_timeout_abs;
	nanoseconds_to_absolutetime(NSEC_PER_USEC * read_timeout_us, &read_timeout_abs);
	nanoseconds_to_absolutetime(NSEC_PER_USEC * write_timeout_us, &write_timeout_abs);
	if (read_timeout_abs > MAX_TIMEOUT_ABS || write_timeout_abs > MAX_TIMEOUT_ABS) {
		return KERN_INVALID_ARGUMENT;
	}

	struct io_timeout_override_entry *node = kalloc_type(struct io_timeout_override_entry, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	node->iovaddr_base = iovaddr_base;
	node->size = size;
	node->read_timeout = (uint32_t)read_timeout_abs;
	node->write_timeout = (uint32_t)write_timeout_abs;

	/*
	 * Interrupt handlers are allowed to call ml_io_{read,write}*, so
	 * interrupts must be disabled any time io_timeout_override_lock is
	 * held.  Otherwise the CPU could take an interrupt while holding the
	 * lock, invoke an ISR that calls ml_io_{read,write}*, and deadlock
	 * trying to acquire the lock again.
	 */
	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&io_timeout_override_lock);
	if (RB_INSERT(io_timeout_override, &io_timeout_override_root, node)) {
		ret = KERN_INVALID_ARGUMENT;
		goto out;
	}

	/* Check that this didn't create any new overlaps */
	struct io_timeout_override_entry *prev = RB_PREV(io_timeout_override, &io_timeout_override_root, node);
	if (prev && (prev->iovaddr_base + prev->size) > node->iovaddr_base) {
		RB_REMOVE(io_timeout_override, &io_timeout_override_root, node);
		ret = KERN_INVALID_ARGUMENT;
		goto out;
	}
	struct io_timeout_override_entry *next = RB_NEXT(io_timeout_override, &io_timeout_override_root, node);
	if (next && (node->iovaddr_base + node->size) > next->iovaddr_base) {
		RB_REMOVE(io_timeout_override, &io_timeout_override_root, node);
		ret = KERN_INVALID_ARGUMENT;
		goto out;
	}

out:
	lck_spin_unlock(&io_timeout_override_lock);
	ml_set_interrupts_enabled(istate);
	if (ret != KERN_SUCCESS) {
		kfree_type(struct io_timeout_override_entry, node);
	}
	return ret;
#else /* !ML_IO_TIMEOUTS_ENABLED */
#pragma unused(iovaddr_base, size, read_timeout_us, write_timeout_us)
	return KERN_SUCCESS;
#endif
}

int
ml_io_reset_timeouts(uintptr_t iovaddr_base, unsigned int size)
{
#if ML_IO_TIMEOUTS_ENABLED
	assert(preemption_enabled());

	struct io_timeout_override_entry key = { .iovaddr_base = iovaddr_base };

	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&io_timeout_override_lock);
	struct io_timeout_override_entry *node = RB_FIND(io_timeout_override, &io_timeout_override_root, &key);
	if (node) {
		if (node->size == size) {
			RB_REMOVE(io_timeout_override, &io_timeout_override_root, node);
		} else {
			node = NULL;
		}
	}
	lck_spin_unlock(&io_timeout_override_lock);
	ml_set_interrupts_enabled(istate);

	if (!node) {
		return KERN_NOT_FOUND;
	}

	kfree_type(struct io_timeout_override_entry, node);
#else /* !ML_IO_TIMEOUTS_ENABLED */
#pragma unused(iovaddr_base, size)
#endif
	return KERN_SUCCESS;
}

#if ML_IO_TIMEOUTS_ENABLED
static void
override_io_timeouts(uintptr_t vaddr, uint64_t *read_timeout, uint64_t *write_timeout)
{
	assert(!ml_get_interrupts_enabled());

	struct io_timeout_override_entry *node = RB_ROOT(&io_timeout_override_root);

	lck_spin_lock(&io_timeout_override_lock);
	/* RB_FIND() doesn't support custom cmp functions, so we have to open-code our own */
	while (node) {
		if (node->iovaddr_base <= vaddr && vaddr < node->iovaddr_base + node->size) {
			if (read_timeout) {
				*read_timeout = node->read_timeout;
			}
			if (write_timeout) {
				*write_timeout = node->write_timeout;
			}
			break;
		} else if (vaddr < node->iovaddr_base) {
			node = RB_LEFT(node, tree);
		} else {
			node = RB_RIGHT(node, tree);
		}
	}
	lck_spin_unlock(&io_timeout_override_lock);
}
#endif /* ML_IO_TIMEOUTS_ENABLED */

unsigned long long
ml_io_read(uintptr_t vaddr, int size)
{
	unsigned long long result = 0;
	unsigned char s1;
	unsigned short s2;

#ifdef ML_IO_VERIFY_UNCACHEABLE
	uintptr_t const paddr = pmap_verify_noncacheable(vaddr);
#elif defined(ML_IO_TIMEOUTS_ENABLED)
	uintptr_t const paddr = kvtophys(vaddr);
#endif

#ifdef ML_IO_TIMEOUTS_ENABLED
	uint64_t sabs, eabs;
	boolean_t istate, timeread = FALSE;
	uint64_t report_read_delay;
#if __x86_64__
	report_read_delay = report_phy_read_delay;
#else
	report_read_delay = os_atomic_load(&report_phy_read_delay_to, relaxed);
	uint64_t const trace_phy_read_delay = os_atomic_load(&trace_phy_read_delay_to, relaxed);
#endif /* __x86_64__ */

	if (__improbable(report_read_delay != 0)) {
		istate = ml_set_interrupts_enabled(FALSE);
		sabs = mach_absolute_time();
		timeread = TRUE;
	}

#ifdef ML_IO_SIMULATE_STRETCHED_ENABLED
	if (__improbable(timeread && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* ML_IO_SIMULATE_STRETCHED_ENABLED */
#endif /* ML_IO_TIMEOUTS_ENABLED */

	switch (size) {
	case 1:
		s1 = *(volatile unsigned char *)vaddr;
		result = s1;
		break;
	case 2:
		s2 = *(volatile unsigned short *)vaddr;
		result = s2;
		break;
	case 4:
		result = *(volatile unsigned int *)vaddr;
		break;
	case 8:
		result = *(volatile unsigned long long *)vaddr;
		break;
	default:
		panic("Invalid size %d for ml_io_read(%p)", size, (void *)vaddr);
		break;
	}

#ifdef ML_IO_TIMEOUTS_ENABLED
	if (__improbable(timeread == TRUE)) {
		eabs = mach_absolute_time();

		/* Prevent the processor from calling iotrace during its
		 * initialization procedure. */
		if (current_processor()->state == PROCESSOR_RUNNING) {
			iotrace(IOTRACE_IO_READ, vaddr, paddr, size, result, sabs, eabs - sabs);
		}

		if (__improbable((eabs - sabs) > report_read_delay)) {
			uint64_t override = 0;
			override_io_timeouts(vaddr, &override, NULL);

			if (override != 0) {
#if SCHED_HYGIENE_DEBUG
				/*
				 * The IO timeout was overridden. As interrupts are disabled in
				 * order to accurately measure IO time this can cause the
				 * interrupt masked timeout threshold to be exceeded.  If the
				 * interrupt masked debug mode is set to panic, abandon the
				 * measurement. If in trace mode leave it as-is for
				 * observability.
				 */
				if (interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
					ml_spin_debug_clear(current_thread());
				}
#endif
				report_read_delay = override;
			}
		}

		if (__improbable((eabs - sabs) > report_read_delay)) {
			if (phy_read_panic && (machine_timeout_suspended() == FALSE)) {
#if defined(__x86_64__)
				panic_notify();
#endif /* defined(__x86_64__) */
				uint64_t nsec = 0;
				absolutetime_to_nanoseconds(eabs - sabs, &nsec);
				panic("Read from IO vaddr 0x%lx paddr 0x%lx took %llu ns, "
				    "result: 0x%llx (start: %llu, end: %llu), ceiling: %llu",
				    vaddr, paddr, nsec, result, sabs, eabs,
				    report_read_delay);
			}

			(void)ml_set_interrupts_enabled(istate);

			if (report_phy_read_osbt) {
				uint64_t nsec = 0;
				absolutetime_to_nanoseconds(eabs - sabs, &nsec);
				OSReportWithBacktrace("ml_io_read(v=%p, p=%p) size %d result 0x%llx "
				    "took %lluus",
				    (void *)vaddr, (void *)paddr, size, result,
				    nsec / NSEC_PER_USEC);
			}
			DTRACE_PHYSLAT5(physioread, uint64_t, (eabs - sabs),
			    uint64_t, vaddr, uint32_t, size, uint64_t, paddr, uint64_t, result);
		} else if (__improbable(trace_phy_read_delay > 0 && (eabs - sabs) > trace_phy_read_delay)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_MMIO_READ),
			    (eabs - sabs), VM_KERNEL_UNSLIDE_OR_PERM(vaddr), paddr, result);

			(void)ml_set_interrupts_enabled(istate);
		} else {
			(void)ml_set_interrupts_enabled(istate);
		}
	}
#endif /*  ML_IO_TIMEOUTS_ENABLED */
	return result;
}

unsigned int
ml_io_read8(uintptr_t vaddr)
{
	return (unsigned) ml_io_read(vaddr, 1);
}

unsigned int
ml_io_read16(uintptr_t vaddr)
{
	return (unsigned) ml_io_read(vaddr, 2);
}

unsigned int
ml_io_read32(uintptr_t vaddr)
{
	return (unsigned) ml_io_read(vaddr, 4);
}

unsigned long long
ml_io_read64(uintptr_t vaddr)
{
	return ml_io_read(vaddr, 8);
}

/* ml_io_write* */

void
ml_io_write(uintptr_t vaddr, uint64_t val, int size)
{
#ifdef ML_IO_VERIFY_UNCACHEABLE
	uintptr_t const paddr = pmap_verify_noncacheable(vaddr);
#elif defined(ML_IO_TIMEOUTS_ENABLED)
	uintptr_t const paddr = kvtophys(vaddr);
#endif

#ifdef ML_IO_TIMEOUTS_ENABLED
	uint64_t sabs, eabs;
	boolean_t istate, timewrite = FALSE;
	uint64_t report_write_delay;
#if __x86_64__
	report_write_delay = report_phy_write_delay;
#else
	report_write_delay = os_atomic_load(&report_phy_write_delay_to, relaxed);
	uint64_t trace_phy_write_delay = os_atomic_load(&trace_phy_write_delay_to, relaxed);
#endif /* !defined(__x86_64__) */
	if (__improbable(report_write_delay != 0)) {
		istate = ml_set_interrupts_enabled(FALSE);
		sabs = mach_absolute_time();
		timewrite = TRUE;
	}

#ifdef ML_IO_SIMULATE_STRETCHED_ENABLED
	if (__improbable(timewrite && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* ML_IO_TIMEOUTS_ENABLED */

	switch (size) {
	case 1:
		*(volatile uint8_t *)vaddr = (uint8_t)val;
		break;
	case 2:
		*(volatile uint16_t *)vaddr = (uint16_t)val;
		break;
	case 4:
		*(volatile uint32_t *)vaddr = (uint32_t)val;
		break;
	case 8:
		*(volatile uint64_t *)vaddr = (uint64_t)val;
		break;
	default:
		panic("Invalid size %d for ml_io_write(%p, 0x%llx)", size, (void *)vaddr, val);
		break;
	}

#ifdef ML_IO_TIMEOUTS_ENABLED
	if (__improbable(timewrite == TRUE)) {
		eabs = mach_absolute_time();


		/* Prevent the processor from calling iotrace during its
		 * initialization procedure. */
		if (current_processor()->state == PROCESSOR_RUNNING) {
			iotrace(IOTRACE_IO_WRITE, vaddr, paddr, size, val, sabs, eabs - sabs);
		}


		if (__improbable((eabs - sabs) > report_write_delay)) {
			uint64_t override = 0;
			override_io_timeouts(vaddr, NULL, &override);

			if (override != 0) {
#if SCHED_HYGIENE_DEBUG
				/*
				 * The IO timeout was overridden. As interrupts are disabled in
				 * order to accurately measure IO time this can cause the
				 * interrupt masked timeout threshold to be exceeded.  If the
				 * interrupt masked debug mode is set to panic, abandon the
				 * measurement. If in trace mode leave it as-is for
				 * observability.
				 */
				if (interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
					ml_spin_debug_clear(current_thread());
				}
#endif
				report_write_delay = override;
			}
		}

		if (__improbable((eabs - sabs) > report_write_delay)) {
			if (phy_write_panic && (machine_timeout_suspended() == FALSE)) {
#if defined(__x86_64__)
				panic_notify();
#endif /*  defined(__x86_64__) */

				uint64_t nsec = 0;
				absolutetime_to_nanoseconds(eabs - sabs, &nsec);
				panic("Write to IO vaddr %p paddr %p val 0x%llx took %llu ns,"
				    " (start: %llu, end: %llu), ceiling: %llu",
				    (void *)vaddr, (void *)paddr, val, nsec, sabs, eabs,
				    report_write_delay);
			}

			(void)ml_set_interrupts_enabled(istate);

			if (report_phy_write_osbt) {
				uint64_t nsec = 0;
				absolutetime_to_nanoseconds(eabs - sabs, &nsec);
				OSReportWithBacktrace("ml_io_write size %d (v=%p, p=%p, 0x%llx) "
				    "took %lluus",
				    size, (void *)vaddr, (void *)paddr, val, nsec / NSEC_PER_USEC);
			}
			DTRACE_PHYSLAT5(physiowrite, uint64_t, (eabs - sabs),
			    uint64_t, vaddr, uint32_t, size, uint64_t, paddr, uint64_t, val);
		} else if (__improbable(trace_phy_write_delay > 0 && (eabs - sabs) > trace_phy_write_delay)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_MMIO_WRITE),
			    (eabs - sabs), VM_KERNEL_UNSLIDE_OR_PERM(vaddr), paddr, val);

			(void)ml_set_interrupts_enabled(istate);
		} else {
			(void)ml_set_interrupts_enabled(istate);
		}
	}
#endif /* ML_IO_TIMEOUTS_ENABLED */
}

void
ml_io_write8(uintptr_t vaddr, uint8_t val)
{
	ml_io_write(vaddr, val, 1);
}

void
ml_io_write16(uintptr_t vaddr, uint16_t val)
{
	ml_io_write(vaddr, val, 2);
}

void
ml_io_write32(uintptr_t vaddr, uint32_t val)
{
	ml_io_write(vaddr, val, 4);
}

void
ml_io_write64(uintptr_t vaddr, uint64_t val)
{
	ml_io_write(vaddr, val, 8);
}

struct cpu_callback_chain_elem {
	cpu_callback_t                  fn;
	void                            *param;
	struct cpu_callback_chain_elem  *next;
};

static struct cpu_callback_chain_elem *cpu_callback_chain;
static LCK_GRP_DECLARE(cpu_callback_chain_lock_grp, "cpu_callback_chain");
static LCK_SPIN_DECLARE(cpu_callback_chain_lock, &cpu_callback_chain_lock_grp);

void
cpu_event_register_callback(cpu_callback_t fn, void *param)
{
	struct cpu_callback_chain_elem *new_elem;

	new_elem = zalloc_permanent_type(struct cpu_callback_chain_elem);
	if (!new_elem) {
		panic("can't allocate cpu_callback_chain_elem");
	}

	lck_spin_lock(&cpu_callback_chain_lock);
	new_elem->next = cpu_callback_chain;
	new_elem->fn = fn;
	new_elem->param = param;
	os_atomic_store(&cpu_callback_chain, new_elem, release);
	lck_spin_unlock(&cpu_callback_chain_lock);
}

__attribute__((noreturn))
void
cpu_event_unregister_callback(__unused cpu_callback_t fn)
{
	panic("Unfortunately, cpu_event_unregister_callback is unimplemented.");
}

void
ml_broadcast_cpu_event(enum cpu_event event, unsigned int cpu_or_cluster)
{
	struct cpu_callback_chain_elem *cursor;

	cursor = os_atomic_load(&cpu_callback_chain, dependency);
	for (; cursor != NULL; cursor = cursor->next) {
		cursor->fn(cursor->param, event, cpu_or_cluster);
	}
}

// Initialize Machine Timeouts (see the MACHINE_TIMEOUT macro
// definition)

void
machine_timeout_init_with_suffix(const struct machine_timeout_spec *spec, char const *suffix)
{
	if (spec->skip_predicate != NULL && spec->skip_predicate(spec)) {
		// This timeout should be disabled.
		os_atomic_store_wide((uint64_t*)spec->ptr, 0, relaxed);
		return;
	}

	assert(suffix != NULL);
	assert(strlen(spec->name) <= MACHINE_TIMEOUT_MAX_NAME_LEN);

	size_t const suffix_len = strlen(suffix);

	size_t const dt_name_size = MACHINE_TIMEOUT_MAX_NAME_LEN + suffix_len + 1;
	char dt_name[dt_name_size];

	strlcpy(dt_name, spec->name, dt_name_size);
	strlcat(dt_name, suffix, dt_name_size);

	size_t const scale_name_size = MACHINE_TIMEOUT_MAX_NAME_LEN + suffix_len + strlen("-scale") + 1;
	char scale_name[scale_name_size];

	strlcpy(scale_name, spec->name, scale_name_size);
	strlcat(scale_name, suffix, scale_name_size);
	strlcat(scale_name, "-scale", scale_name_size);

	size_t const boot_arg_name_size = MACHINE_TIMEOUT_MAX_NAME_LEN + strlen("ml-timeout-") + suffix_len + 1;
	char boot_arg_name[boot_arg_name_size];

	strlcpy(boot_arg_name, "ml-timeout-", boot_arg_name_size);
	strlcat(boot_arg_name, spec->name, boot_arg_name_size);
	strlcat(boot_arg_name, suffix, boot_arg_name_size);

	size_t const boot_arg_scale_name_size = MACHINE_TIMEOUT_MAX_NAME_LEN +
	    strlen("ml-timeout-") + strlen("-scale") + suffix_len + 1;
	char boot_arg_scale_name[boot_arg_scale_name_size];

	strlcpy(boot_arg_scale_name, "ml-timeout-", boot_arg_scale_name_size);
	strlcat(boot_arg_scale_name, spec->name, boot_arg_scale_name_size);
	strlcat(boot_arg_scale_name, suffix, boot_arg_name_size);
	strlcat(boot_arg_scale_name, "-scale", boot_arg_scale_name_size);


	/*
	 * Determine base value from DT and boot-args.
	 */

	DTEntry base, chosen;

	if (SecureDTLookupEntry(NULL, "/machine-timeouts", &base) != kSuccess) {
		base = NULL;
	}

	if (SecureDTLookupEntry(NULL, "/chosen/machine-timeouts", &chosen) != kSuccess) {
		chosen = NULL;
	}

	uint64_t timeout = spec->default_value;
	bool found = false;

	uint64_t const *data = NULL;
	unsigned int data_size = sizeof(*data);

	/* First look in /machine-timeouts/<name> */
	if (base != NULL && SecureDTGetProperty(base, dt_name, (const void **)&data, &data_size) == kSuccess) {
		if (data_size != sizeof(*data)) {
			panic("%s: unexpected machine timeout data_size %u for /machine-timeouts/%s", __func__, data_size, dt_name);
		}

		timeout = *data;
		found = true;
	}

	/* A value in /chosen/machine-timeouts/<name> overrides */
	if (chosen != NULL && SecureDTGetProperty(chosen, dt_name, (const void **)&data, &data_size) == kSuccess) {
		if (data_size != sizeof(*data)) {
			panic("%s: unexpected machine timeout data_size %u for /chosen/machine-timeouts/%s", __func__, data_size, dt_name);
		}

		timeout = *data;
		found = true;
	}

	/* A boot-arg ml-timeout-<name> overrides */
	uint64_t boot_arg = 0;

	if (PE_parse_boot_argn(boot_arg_name, &boot_arg, sizeof(boot_arg))) {
		timeout = boot_arg;
		found = true;
	}


	/*
	 * Determine scale value from DT and boot-args.
	 */

	uint32_t scale = 1;
	uint32_t const *scale_data;
	unsigned int scale_size = sizeof(scale_data);

	/* If there is a scale factor /machine-timeouts/<name>-scale,
	 * apply it. */
	if (base != NULL && SecureDTGetProperty(base, scale_name, (const void **)&scale_data, &scale_size) == kSuccess) {
		if (scale_size != sizeof(*scale_data)) {
			panic("%s: unexpected machine timeout data_size %u for /machine-timeouts/%s-scale", __func__, scale_size, dt_name);
		}

		scale *= *scale_data;
	}

	/* If there is a scale factor /chosen/machine-timeouts/<name>-scale,
	 * apply it as well. */
	if (chosen != NULL && SecureDTGetProperty(chosen, scale_name, (const void **)&scale_data, &scale_size) == kSuccess) {
		if (scale_size != sizeof(*scale_data)) {
			panic("%s: unexpected machine timeout data_size %u for /chosen/machine-timeouts/%s-scale", __func__,
			    scale_size, dt_name);
		}

		scale *= *scale_data;
	}

	/* Finally, a boot-arg ml-timeout-<name>-scale applies as well. */
	if (PE_parse_boot_argn(boot_arg_scale_name, &boot_arg, sizeof(boot_arg))) {
		scale *= boot_arg;
	}

	static bool global_scale_set;
	static uint32_t global_scale;

	if (!global_scale_set) {
		/* Apply /machine-timeouts/global-scale if present */
		if (SecureDTGetProperty(base, "global-scale", (const void **)&scale_data, &scale_size) == kSuccess) {
			if (scale_size != sizeof(*scale_data)) {
				panic("%s: unexpected machine timeout data_size %u for /machine-timeouts/global-scale", __func__,
				    scale_size);
			}

			global_scale *= *scale_data;
			global_scale_set = true;
		}

		/* Apply /chosen/machine-timeouts/global-scale if present */
		if (SecureDTGetProperty(chosen, "global-scale", (const void **)&scale_data, &scale_size) == kSuccess) {
			if (scale_size != sizeof(*scale_data)) {
				panic("%s: unexpected machine timeout data_size %u for /chosen/machine-timeouts/global-scale", __func__,
				    scale_size);
			}

			global_scale *= *scale_data;
			global_scale_set = true;
		}

		/* Finally, the boot-arg ml-timeout-global-scale applies */
		if (PE_parse_boot_argn("ml-timeout-global-scale", &boot_arg, sizeof(boot_arg))) {
			global_scale *= boot_arg;
			global_scale_set = true;
		}
	}

	if (global_scale_set) {
		scale *= global_scale;
	}

	/* Compute the final timeout, and done. */
	if (found && timeout > 0) {
		/* Only apply inherent unit scale if the value came in
		 * externally. */

		if (spec->unit_scale == MACHINE_TIMEOUT_UNIT_TIMEBASE) {
			uint64_t nanoseconds = timeout / 1000;
			nanoseconds_to_absolutetime(nanoseconds, &timeout);
		} else {
			timeout /= spec->unit_scale;
		}

		if (timeout == 0) {
			/* Ensure unit scaling did not disable the timeout. */
			timeout = 1;
		}
	}

	if (os_mul_overflow(timeout, scale, &timeout)) {
		timeout = UINT64_MAX; // clamp
	}

	os_atomic_store_wide((uint64_t*)spec->ptr, timeout, relaxed);
}

void
machine_timeout_init(const struct machine_timeout_spec *spec)
{
	machine_timeout_init_with_suffix(spec, "");
}

/*
 * Late timeout (re-)initialization, at the end of bsd_init()
 */
void
machine_timeout_bsd_init(void)
{
	char const * const __unused mt_suffix = "-b";
#if SCHED_HYGIENE_DEBUG
	machine_timeout_init_with_suffix(MACHINE_TIMEOUT_SPEC_REF(interrupt_masked_timeout), mt_suffix);
	machine_timeout_init_with_suffix(MACHINE_TIMEOUT_SPEC_REF(sched_preemption_disable_threshold_mt), mt_suffix);

	/*
	 * The io timeouts can inherit from interrupt_masked_timeout.
	 * Re-initialize, as interrupt_masked_timeout may have changed.
	 */
	ml_io_init_timeouts();

	PERCPU_DECL(uint64_t _Atomic, preemption_disable_max_mt);

	/*
	 * Reset the preemption disable stats, so that they are not
	 * polluted by long early boot code.
	 */
	percpu_foreach(max_stat, preemption_disable_max_mt) {
		os_atomic_store(max_stat, 0, relaxed);

		/*
		 * No additional synchronization needed.  The time when we
		 * switch to late boot timeouts is relatively arbitrary
		 * anyway: By now we don't expect any long preemption
		 * disabling anymore. While that is still a clear delineation
		 * for the boot CPU, other CPUs can be in the middle of doing
		 * whatever. So if the missing synchronization causes a new
		 * maximum to be missed on a secondary CPU, it could just as
		 * well have been missed by racing with this function.
		 */
	}

#endif
}

#if ML_IO_TIMEOUTS_ENABLED && CONFIG_XNUPOST
#include <tests/xnupost.h>

extern kern_return_t ml_io_timeout_test(void);

static inline void
ml_io_timeout_test_get_timeouts(uintptr_t vaddr, uint64_t *read_timeout, uint64_t *write_timeout)
{
	*read_timeout = 0;
	*write_timeout = 0;

	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	override_io_timeouts(vaddr, read_timeout, write_timeout);
	ml_set_interrupts_enabled(istate);
}

kern_return_t
ml_io_timeout_test(void)
{
	const size_t SIZE = 16;
	uintptr_t iovaddr_base1 = (uintptr_t)&ml_io_timeout_test;
	uintptr_t iovaddr_base2 = iovaddr_base1 + SIZE;
	uintptr_t vaddr1 = iovaddr_base1 + SIZE / 2;
	uintptr_t vaddr2 = iovaddr_base2 + SIZE / 2;

	const uint64_t READ_TIMEOUT1_US = 50000, WRITE_TIMEOUT1_US = 50001;
	const uint64_t READ_TIMEOUT2_US = 50002, WRITE_TIMEOUT2_US = 50003;
	uint64_t read_timeout1_abs, write_timeout1_abs;
	uint64_t read_timeout2_abs, write_timeout2_abs;
	nanoseconds_to_absolutetime(NSEC_PER_USEC * READ_TIMEOUT1_US, &read_timeout1_abs);
	nanoseconds_to_absolutetime(NSEC_PER_USEC * WRITE_TIMEOUT1_US, &write_timeout1_abs);
	nanoseconds_to_absolutetime(NSEC_PER_USEC * READ_TIMEOUT2_US, &read_timeout2_abs);
	nanoseconds_to_absolutetime(NSEC_PER_USEC * WRITE_TIMEOUT2_US, &write_timeout2_abs);

	int err = ml_io_increase_timeouts(iovaddr_base1, 0, READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_INVALID_ARGUMENT, "Can't set timeout for empty region");

	err = ml_io_increase_timeouts(iovaddr_base1, 4097, READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_INVALID_ARGUMENT, "Can't set timeout for region > 4096 bytes");

	err = ml_io_increase_timeouts(UINTPTR_MAX, SIZE, READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_INVALID_ARGUMENT, "Can't set timeout for overflowed region");

	err = ml_io_increase_timeouts(iovaddr_base1, SIZE, READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Setting timeout for first VA region should succeed");

	err = ml_io_increase_timeouts(iovaddr_base2, SIZE, READ_TIMEOUT2_US, WRITE_TIMEOUT2_US);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Setting timeout for second VA region should succeed");

	err = ml_io_increase_timeouts(iovaddr_base1, SIZE, READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_INVALID_ARGUMENT, "Can't set timeout for same region twice");

	err = ml_io_increase_timeouts(vaddr1, (uint32_t)(vaddr2 - vaddr1), READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_INVALID_ARGUMENT, "Can't set timeout for overlapping regions");

	uint64_t read_timeout, write_timeout;
	ml_io_timeout_test_get_timeouts(vaddr1, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, read_timeout1_abs, "Read timeout for first region");
	T_EXPECT_EQ_ULLONG(write_timeout, write_timeout1_abs, "Write timeout for first region");

	ml_io_timeout_test_get_timeouts(vaddr2, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, read_timeout2_abs, "Read timeout for first region");
	T_EXPECT_EQ_ULLONG(write_timeout, write_timeout2_abs, "Write timeout for first region");

	ml_io_timeout_test_get_timeouts(iovaddr_base2 + SIZE, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, 0, "Read timeout without override");
	T_EXPECT_EQ_ULLONG(write_timeout, 0, "Write timeout without override");

	err = ml_io_reset_timeouts(iovaddr_base1 + 1, SIZE - 1);
	T_EXPECT_EQ_INT(err, KERN_NOT_FOUND, "Can't reset timeout for subregion");

	err = ml_io_reset_timeouts(iovaddr_base2 + SIZE, SIZE);
	T_EXPECT_EQ_INT(err, KERN_NOT_FOUND, "Can't reset timeout for non-existent region");

	err = ml_io_reset_timeouts(iovaddr_base1, SIZE);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Resetting timeout for first VA region should succeed");

	ml_io_timeout_test_get_timeouts(vaddr1, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, 0, "Read timeout for reset region");
	T_EXPECT_EQ_ULLONG(write_timeout, 0, "Write timeout for reset region");

	err = ml_io_reset_timeouts(iovaddr_base1, SIZE);
	T_EXPECT_EQ_INT(err, KERN_NOT_FOUND, "Can't reset timeout for same region twice");

	err = ml_io_reset_timeouts(iovaddr_base2, SIZE);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Resetting timeout for second VA region should succeed");

	return KERN_SUCCESS;
}
#endif /* CONFIG_XNUPOST */
