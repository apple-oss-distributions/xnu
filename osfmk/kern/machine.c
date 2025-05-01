/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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
#if CONFIG_SPTM
#include <arm64/sptm/pmap/pmap_data.h>
#else
#include <arm/pmap/pmap_data.h>
#endif /* CONFIG_SPTM */
#endif /* defined(__arm64__) */

#if defined(__x86_64__)
#include <i386/panic_notify.h>
#endif

#if ML_IO_TIMEOUTS_ENABLED
#if defined(__x86_64__)
#define ml_io_timestamp mach_absolute_time
#else
#define ml_io_timestamp ml_get_timebase
#endif /* __x86_64__ */
#endif /* ML_IO_TIMEOUTS_ENABLED */

/*
 *	Exported variables:
 */

TUNABLE(long, wdt, "wdt", 0);

struct machine_info     machine_info;

/* Forwards */
static void
processor_offline(void * parameter, __unused wait_result_t result);

static void
processor_offline_intstack(processor_t processor) __dead2;


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
	spl_t s = splsched();
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
	 * not end up spinning anywhere.  See processor_cpu_reinit() for the fix
	 * for this race.
	 */
	wait_while_mp_kdp_trap(false);
#endif

	/* Boot CPU coming online for the first time, either at boot or after sleep */
	__assert_only bool is_first_online_processor;

	is_first_online_processor = sched_mark_processor_online(processor,
	    processor->last_startup_reason);

	simple_lock(&processor_start_state_lock, LCK_GRP_NULL);
	assert(processor->processor_instartup == true || is_first_online_processor);
	simple_unlock(&processor_start_state_lock);

	splx(s);

#if defined(__x86_64__)
	ml_cpu_up();
#endif /* defined(__x86_64__) */

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

void
processor_doshutdown(
	processor_t     processor,
	bool            is_final_system_sleep)
{
	lck_mtx_assert(&cluster_powerdown_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&processor_updown_lock, LCK_MTX_ASSERT_OWNED);

	if (!processor->processor_booted) {
		panic("processor %d not booted", processor->cpu_id);
	}

	if (is_final_system_sleep) {
		assert(processor == current_processor());
		assert(processor == master_processor);
		assert(processor_avail_count == 1);
	}

	processor_set_t pset = processor->processor_set;

	ml_cpu_begin_state_transition(processor->cpu_id);

	ml_broadcast_cpu_event(CPU_EXIT_REQUESTED, processor->cpu_id);

#if HIBERNATION
	if (is_final_system_sleep) {
		/*
		 * Ensure the page queues are in a state where the hibernation
		 * code can manipulate them without requiring other threads
		 * to be scheduled.
		 *
		 * This operation can block,
		 * and unlock must be done from the same thread.
		 */
		assert(processor_avail_count < 2);
		hibernate_vm_lock();
	}
#endif

	spl_t s = splsched();
	simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);
	pset_lock(pset);

	assert(processor->state != PROCESSOR_START);
	assert(processor->state != PROCESSOR_PENDING_OFFLINE);
	assert(processor->state != PROCESSOR_OFF_LINE);

	assert(!processor->processor_inshutdown);
	processor->processor_inshutdown = true;

	assert(processor->processor_offline_state == PROCESSOR_OFFLINE_RUNNING);
	processor_update_offline_state_locked(processor, PROCESSOR_OFFLINE_BEGIN_SHUTDOWN);

	if (!is_final_system_sleep) {
		sched_assert_not_last_online_cpu(processor->cpu_id);
	}

	pset_unlock(pset);
	simple_unlock(&sched_available_cores_lock);

	if (is_final_system_sleep) {
		assert(processor == current_processor());

#if HIBERNATION
		/*
		 * After this point, the system is now
		 * committed to hibernation and must
		 * not run any other thread that could take this lock.
		 */
		hibernate_vm_unlock();
#endif
	} else {
		/*
		 * Get onto the processor to shut down.
		 * The scheduler picks this thread naturally according to its
		 * priority.
		 * The processor can run any other thread if this one blocks.
		 * So, don't block.
		 */
		processor_t prev = thread_bind(processor);
		thread_block(THREAD_CONTINUE_NULL);

		/* interrupts still disabled */
		assert(ml_get_interrupts_enabled() == FALSE);

		assert(processor == current_processor());
		assert(processor->processor_inshutdown);

		thread_bind(prev);
		/* interrupts still disabled */
	}

	/*
	 * Continue processor shutdown on the processor's idle thread.
	 * The handoff won't fail because the idle thread has a reserved stack.
	 * Switching to the idle thread leaves interrupts disabled,
	 * so we can't accidentally take an interrupt after the context switch.
	 */
	thread_t shutdown_thread = processor->idle_thread;
	shutdown_thread->continuation = processor_offline;
	shutdown_thread->parameter = (void*)is_final_system_sleep;

	thread_run(current_thread(), THREAD_CONTINUE_NULL, NULL, shutdown_thread);

	/*
	 * After this point, we are in regular scheduled context on a remaining
	 * available CPU. Interrupts are still disabled.
	 */

	if (is_final_system_sleep) {
		/*
		 * We are coming out of system sleep here, so there won't be a
		 * corresponding processor_startup for this processor, so we
		 * need to put it back in the correct running state.
		 *
		 * There's nowhere to execute a call to CPU_EXITED during system
		 * sleep for the boot processor, and it's already been CPU_BOOTED
		 * by this point anyways, so skip the call.
		 */
		assert(current_processor() == master_processor);
		assert(processor->state == PROCESSOR_RUNNING);
		assert(processor->processor_inshutdown);
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_STARTED_NOT_WAITED);
		processor->processor_inshutdown = false;
		processor_update_offline_state(processor, PROCESSOR_OFFLINE_RUNNING);

		splx(s);
	} else {
		splx(s);

		cpu_exit_wait(processor->cpu_id);

		s = splsched();
		simple_lock(&sched_available_cores_lock, LCK_GRP_NULL);
		pset_lock(pset);
		assert(processor->processor_inshutdown);
		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_PENDING_OFFLINE);
		assert(processor->state == PROCESSOR_PENDING_OFFLINE);
		pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
		processor_update_offline_state_locked(processor, PROCESSOR_OFFLINE_CPU_OFFLINE);
		pset_unlock(pset);
		simple_unlock(&sched_available_cores_lock);
		splx(s);

		ml_broadcast_cpu_event(CPU_EXITED, processor->cpu_id);
		ml_cpu_power_disable(processor->cpu_id);

		assert(processor->processor_offline_state == PROCESSOR_OFFLINE_CPU_OFFLINE);
		processor_update_offline_state(processor, PROCESSOR_OFFLINE_FULLY_OFFLINE);
	}

	ml_cpu_end_state_transition(processor->cpu_id);
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
	bool is_final_system_sleep = (bool) parameter;
	processor_t processor = current_processor();
	thread_t self = current_thread();
	__assert_only thread_t old_thread = THREAD_NULL;

	assert(self->state & TH_IDLE);
	assert(processor->idle_thread == self);
	assert(ml_get_interrupts_enabled() == FALSE);
	assert(self->continuation == NULL);
	assert(processor->processor_online == true);
	assert(processor->running_timers_active == false);

	if (is_final_system_sleep) {
		assert(processor == current_processor());
		assert(processor == master_processor);
		assert(processor_avail_count == 1);
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PROCESSOR_SHUTDOWN) | DBG_FUNC_START, processor->cpu_id);

	bool enforce_quiesce_safety = gEnforcePlatformActionSafety;

	/*
	 * Scheduling is now disabled for this processor.
	 * Ensure that primitives that need scheduling (like mutexes) know this.
	 */
	if (enforce_quiesce_safety) {
		disable_preemption_without_measurements();
	}

#if CONFIG_DTRACE
	if (dtrace_cpu_state_changed_hook) {
		(*dtrace_cpu_state_changed_hook)(processor->cpu_id, FALSE);
	}
#endif

	smr_cpu_down(processor, SMR_CPU_REASON_OFFLINE);

	/* Drain pending IPIs for the last time here. */
	ml_cpu_down();

	sched_mark_processor_offline(processor, is_final_system_sleep);

	/*
	 * Switch to the interrupt stack and shut down the processor.
	 *
	 * When the processor comes back, it will eventually call load_context which
	 * restores the context saved by machine_processor_shutdown, returning here.
	 */
	old_thread = machine_processor_shutdown(self, processor_offline_intstack, processor);

	/*
	 * The processor is back. sched_mark_processor_online and
	 * friends have already run via processor_up.
	 */

	/* old_thread should be NULL because we got here through Load_context */
	assert(old_thread == THREAD_NULL);

	assert(processor == current_processor());
	assert(processor->idle_thread == current_thread());
	assert(processor->processor_online == true);

	assert(ml_get_interrupts_enabled() == FALSE);
	assert(self->continuation == NULL);

	/* Extract the machine_param value stashed by secondary_cpu_main */
	void * machine_param = self->parameter;
	self->parameter = NULL;

	processor_cpu_reinit(machine_param, true, is_final_system_sleep);

	if (enforce_quiesce_safety) {
		enable_preemption();
	}

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_PROCESSOR_SHUTDOWN) | DBG_FUNC_END, processor->cpu_id);

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

	smr_cpu_leave(processor, processor->last_dispatch);

	PMAP_DEACTIVATE_KERNEL(processor->cpu_id);

	cpu_sleep();
	panic("zombie processor");
	/*NOTREACHED*/
}

/*
 * Called on the idle thread with interrupts disabled to initialize a
 * secondary processor on boot or to reinitialize any processor on resume
 * from processor offline.
 */
void
processor_cpu_reinit(void* machine_param,
    __unused bool wait_for_cpu_signal,
    __assert_only bool is_final_system_sleep)
{
	/* Re-initialize the processor */
	machine_cpu_reinit(machine_param);

#if defined(__arm64__)
	/*
	 * See the comments for wait_while_mp_kdp_trap in processor_up().
	 *
	 * SIGPdisabled is cleared (to enable cpu_signal() to succeed with this processor)
	 * the first time we take an IPI.  This is triggered by machine_cpu_reinit(), above,
	 * which calls cpu_machine_init()->PE_cpu_machine_init()->PE_cpu_signal() which sends
	 * a self-IPI to ensure that happens when we enable interrupts.  So enable interrupts
	 * here so that cpu_signal() can succeed before we spin on mp_kdp_trap.
	 */
	assert_ml_cpu_signal_is_enabled(false);

	ml_set_interrupts_enabled(TRUE);

	if (wait_for_cpu_signal) {
		ml_wait_for_cpu_signal_to_enable();
	}

	ml_set_interrupts_enabled(FALSE);

	wait_while_mp_kdp_trap(true);

	/*
	 * At this point,
	 * if a stackshot or panic is in progress, we either spin on mp_kdp_trap
	 * or we sucessfully received a SIGPdebug signal which will cause us to
	 * break out of the spin on mp_kdp_trap and instead
	 * spin next time interrupts are enabled in idle_thread().
	 */
	if (wait_for_cpu_signal) {
		assert_ml_cpu_signal_is_enabled(true);
	}

	/*
	 * Now that we know SIGPdisabled is cleared, we can publish that
	 * this CPU has fully come out of offline state.
	 *
	 * Without wait_for_cpu_signal, we'll publish this earlier than
	 * cpu_signal is actually ready, but as long as it's ready by next S2R,
	 * it will be good enough.
	 */
	ml_cpu_up();
#endif

	/*
	 * Interrupts must be disabled while processor_start_state_lock is
	 * held to prevent a deadlock with CPU startup of other CPUs that
	 * may be proceeding in parallel to this CPU's reinitialization.
	 */
	spl_t s = splsched();
	processor_t processor = current_processor();

	simple_lock(&processor_start_state_lock, LCK_GRP_NULL);
	assert(processor->processor_instartup == true || is_final_system_sleep);
	processor->processor_instartup = false;
	simple_unlock(&processor_start_state_lock);

	splx(s);

	thread_wakeup((event_t)&processor->processor_instartup);
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

#if DEVELOPMENT || DEBUG
static const uint64_t TIMEBASE_TICKS_PER_USEC = 24000000ULL / USEC_PER_SEC;
static const uint64_t DEFAULT_TRACE_PHY_TIMEOUT = 100 * TIMEBASE_TICKS_PER_USEC;
#else
static const uint64_t DEFAULT_TRACE_PHY_TIMEOUT = 0;
#endif

// The MACHINE_TIMEOUT facility only exists on ARM.
MACHINE_TIMEOUT_DEV_WRITEABLE(report_phy_read_delay_to, "report-phy-read-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT_DEV_WRITEABLE(report_phy_write_delay_to, "report-phy-write-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT_DEV_WRITEABLE(trace_phy_read_delay_to, "trace-phy-read-delay", DEFAULT_TRACE_PHY_TIMEOUT, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT_DEV_WRITEABLE(trace_phy_write_delay_to, "trace-phy-write-delay", DEFAULT_TRACE_PHY_TIMEOUT, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

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
	 * The timeouts may be completely disabled via an override.
	 */
	if (kern_feature_override(KF_IO_TIMEOUT_OVRD)) {
		os_atomic_store(&report_phy_write_delay_to, 0, relaxed);
		os_atomic_store(&report_phy_read_delay_to, 0, relaxed);
		return;
	}

	/*
	 * There may be no interrupt masked timeout set.
	 */
	const uint64_t interrupt_masked_to = os_atomic_load(&interrupt_masked_timeout, relaxed);
	if (interrupt_masked_timeout == 0) {
		return;
	}

	/*
	 * Inherit from the interrupt masked timeout if smaller and the timeout
	 * hasn't been explicitly set via boot-arg.
	 */
	uint64_t arg = 0;

	if (!PE_parse_boot_argn("ml-timeout-report-phy-read-delay", &arg, sizeof(arg))) {
		uint64_t report_phy_read_delay = os_atomic_load(&report_phy_read_delay_to, relaxed);
		report_phy_read_delay = report_phy_read_delay == 0 ?
		    interrupt_masked_to :
		    MIN(report_phy_read_delay, interrupt_masked_to);
		os_atomic_store(&report_phy_read_delay_to, report_phy_read_delay, relaxed);
	}

	if (!PE_parse_boot_argn("ml-timeout-report-phy-write-delay", &arg, sizeof(arg))) {
		uint64_t report_phy_write_delay = os_atomic_load(&report_phy_write_delay_to, relaxed);
		report_phy_write_delay = report_phy_write_delay == 0 ?
		    interrupt_masked_to :
		    MIN(report_phy_write_delay, interrupt_masked_to);
		os_atomic_store(&report_phy_write_delay_to, report_phy_write_delay, relaxed);
	}
}

/*
 * It's important that this happens after machine timeouts have initialized so
 * the correct timeouts can be inherited.
 */
STARTUP(TIMEOUTS, STARTUP_RANK_SECOND, ml_io_init_timeouts);
#endif /* SCHED_HYGIENE_DEBUG */

extern pmap_paddr_t kvtophys(vm_offset_t va);
#endif /* !defined(__x86_64__) */

#if ML_IO_TIMEOUTS_ENABLED

static LCK_GRP_DECLARE(io_timeout_override_lock_grp, "io_timeout_override");
static LCK_SPIN_DECLARE(io_timeout_override_lock, &io_timeout_override_lock_grp);

struct io_timeout_override_entry {
	RB_ENTRY(io_timeout_override_entry) tree;

	uintptr_t ioaddr_base;
	unsigned int size;
	uint32_t read_timeout;
	uint32_t write_timeout;
};

static inline int
io_timeout_override_cmp(const struct io_timeout_override_entry *a, const struct io_timeout_override_entry *b)
{
	if (a->ioaddr_base < b->ioaddr_base) {
		return -1;
	} else if (a->ioaddr_base > b->ioaddr_base) {
		return 1;
	} else {
		return 0;
	}
}

static RB_HEAD(io_timeout_override, io_timeout_override_entry)
io_timeout_override_root_pa, io_timeout_override_root_va;

RB_PROTOTYPE_PREV(io_timeout_override, io_timeout_override_entry, tree, io_timeout_override_cmp);
RB_GENERATE_PREV(io_timeout_override, io_timeout_override_entry, tree, io_timeout_override_cmp);

static int
io_increase_timeouts(struct io_timeout_override *root, uintptr_t ioaddr_base,
    unsigned int size, uint32_t read_timeout_us, uint32_t write_timeout_us)
{
	const uint64_t MAX_TIMEOUT_ABS = UINT32_MAX;

	assert(preemption_enabled());

	int ret = KERN_SUCCESS;

	if (size == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	uintptr_t ioaddr_end;
	if (os_add_overflow(ioaddr_base, size - 1, &ioaddr_end)) {
		return KERN_INVALID_ARGUMENT;
	}

	uint64_t read_timeout_abs, write_timeout_abs;
	nanoseconds_to_absolutetime(NSEC_PER_USEC * read_timeout_us, &read_timeout_abs);
	nanoseconds_to_absolutetime(NSEC_PER_USEC * write_timeout_us, &write_timeout_abs);
	if (read_timeout_abs > MAX_TIMEOUT_ABS || write_timeout_abs > MAX_TIMEOUT_ABS) {
		return KERN_INVALID_ARGUMENT;
	}

	struct io_timeout_override_entry *node = kalloc_type(struct io_timeout_override_entry, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	node->ioaddr_base = ioaddr_base;
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
	if (RB_INSERT(io_timeout_override, root, node)) {
		ret = KERN_INVALID_ARGUMENT;
		goto out;
	}

	/* Check that this didn't create any new overlaps */
	struct io_timeout_override_entry *prev = RB_PREV(io_timeout_override, root, node);
	if (prev && (prev->ioaddr_base + prev->size) > node->ioaddr_base) {
		RB_REMOVE(io_timeout_override, root, node);
		ret = KERN_INVALID_ARGUMENT;
		goto out;
	}
	struct io_timeout_override_entry *next = RB_NEXT(io_timeout_override, root, node);
	if (next && (node->ioaddr_base + node->size) > next->ioaddr_base) {
		RB_REMOVE(io_timeout_override, root, node);
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
}

static int
io_reset_timeouts(struct io_timeout_override *root, uintptr_t ioaddr_base, unsigned int size)
{
	assert(preemption_enabled());

	struct io_timeout_override_entry key = { .ioaddr_base = ioaddr_base };

	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&io_timeout_override_lock);
	struct io_timeout_override_entry *node = RB_FIND(io_timeout_override, root, &key);
	if (node) {
		if (node->size == size) {
			RB_REMOVE(io_timeout_override, root, node);
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
	return KERN_SUCCESS;
}

static bool
io_override_timeout(struct io_timeout_override *root, uintptr_t addr,
    uint64_t *read_timeout, uint64_t *write_timeout)
{
	assert(!ml_get_interrupts_enabled());
	assert3p(read_timeout, !=, NULL);
	assert3p(write_timeout, !=, NULL);

	struct io_timeout_override_entry *node = RB_ROOT(root);

	lck_spin_lock(&io_timeout_override_lock);
	/* RB_FIND() doesn't support custom cmp functions, so we have to open-code our own */
	while (node) {
		if (node->ioaddr_base <= addr && addr < node->ioaddr_base + node->size) {
			*read_timeout = node->read_timeout;
			*write_timeout = node->write_timeout;
			lck_spin_unlock(&io_timeout_override_lock);
			return true;
		} else if (addr < node->ioaddr_base) {
			node = RB_LEFT(node, tree);
		} else {
			node = RB_RIGHT(node, tree);
		}
	}
	lck_spin_unlock(&io_timeout_override_lock);

	return false;
}

static bool
io_override_timeout_ss(uint64_t paddr, uint64_t *read_timeout, uint64_t *write_timeout)
{
#if defined(__arm64__)

	/*
	 * PCIe regions are marked with PMAP_IO_RANGE_STRONG_SYNC. Apply a
	 * timeout greater than two PCIe completion timeouts (90ms) as they can
	 * stack.
	 */
	#define STRONG_SYNC_TIMEOUT 2160000 /* 90ms */

	pmap_io_range_t *range = pmap_find_io_attr(paddr);
	if (range != NULL && (range->wimg & PMAP_IO_RANGE_STRONG_SYNC) != 0) {
		*read_timeout = STRONG_SYNC_TIMEOUT;
		*write_timeout = STRONG_SYNC_TIMEOUT;
		return true;
	}
#else
	(void)paddr;
	(void)read_timeout;
	(void)write_timeout;
#endif /* __arm64__ */
	return false;
}

/*
 * Return timeout override values for the read/write timeout for a given
 * address.
 * A virtual address (vaddr), physical address (paddr) or both may be passed.
 * Up to three separate timeout overrides can be found
 *  - A virtual address override
 *  - A physical address override
 *  - A strong sync override
 *  The largest override found is returned.
 */
void
override_io_timeouts(uintptr_t vaddr, uint64_t paddr, uint64_t *read_timeout,
    uint64_t *write_timeout)
{
	uint64_t rt_va = 0, wt_va = 0, rt_pa = 0, wt_pa = 0, rt_ss = 0, wt_ss = 0;

	if (vaddr != 0) {
		/* Override from virtual address. */
		io_override_timeout(&io_timeout_override_root_va, vaddr, &rt_va, &wt_va);
	}

	if (paddr != 0) {
		/* Override from physical address. */
		io_override_timeout(&io_timeout_override_root_pa, paddr, &rt_pa, &wt_pa);

		/* Override from strong sync range. */
		io_override_timeout_ss(paddr, &rt_ss, &wt_ss);
	}

	if (read_timeout != NULL) {
		*read_timeout =  MAX(MAX(rt_va, rt_pa), rt_ss);
	}

	if (write_timeout != NULL) {
		*write_timeout = MAX(MAX(wt_va, wt_pa), wt_ss);
	}
}

#endif /* ML_IO_TIMEOUTS_ENABLED */

int
ml_io_increase_timeouts(uintptr_t ioaddr_base, unsigned int size,
    uint32_t read_timeout_us, uint32_t write_timeout_us)
{
#if ML_IO_TIMEOUTS_ENABLED
	const size_t MAX_SIZE = 4096;

	if (size > MAX_SIZE) {
		return KERN_INVALID_ARGUMENT;
	}

	return io_increase_timeouts(&io_timeout_override_root_va, ioaddr_base,
	           size, read_timeout_us, write_timeout_us);
#else
	#pragma unused(ioaddr_base, size, read_timeout_us, write_timeout_us)
	return KERN_SUCCESS;
#endif /* ML_IO_TIMEOUTS_ENABLED */
}

int
ml_io_increase_timeouts_phys(vm_offset_t ioaddr_base, unsigned int size,
    uint32_t read_timeout_us, uint32_t write_timeout_us)
{
#if ML_IO_TIMEOUTS_ENABLED
	return io_increase_timeouts(&io_timeout_override_root_pa, ioaddr_base,
	           size, read_timeout_us, write_timeout_us);
#else
	#pragma unused(ioaddr_base, size, read_timeout_us, write_timeout_us)
	return KERN_SUCCESS;
#endif /* ML_IO_TIMEOUTS_ENABLED */
}

int
ml_io_reset_timeouts(uintptr_t ioaddr_base, unsigned int size)
{
#if ML_IO_TIMEOUTS_ENABLED
	return io_reset_timeouts(&io_timeout_override_root_va, ioaddr_base, size);
#else
	#pragma unused(ioaddr_base, size)
	return KERN_SUCCESS;
#endif /* ML_IO_TIMEOUTS_ENABLED */
}

int
ml_io_reset_timeouts_phys(vm_offset_t ioaddr_base, unsigned int size)
{
#if ML_IO_TIMEOUTS_ENABLED
	return io_reset_timeouts(&io_timeout_override_root_pa, ioaddr_base, size);
#else
	#pragma unused(ioaddr_base, size)
	return KERN_SUCCESS;
#endif /* ML_IO_TIMEOUTS_ENABLED */
}

unsigned long long
ml_io_read(uintptr_t vaddr, int size)
{
	unsigned long long result = 0;
	unsigned char s1;
	unsigned short s2;

#ifdef ML_IO_VERIFY_UNCACHEABLE
	uintptr_t paddr = pmap_verify_noncacheable(vaddr);
#elif defined(ML_IO_TIMEOUTS_ENABLED)
	uintptr_t paddr = 0;
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
		istate = ml_set_interrupts_enabled_with_debug(false, false);
		sabs = ml_io_timestamp();
		timeread = TRUE;
	}

#ifdef ML_IO_SIMULATE_STRETCHED_ENABLED
	if (__improbable(timeread && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* ML_IO_SIMULATE_STRETCHED_ENABLED */
#endif /* ML_IO_TIMEOUTS_ENABLED */

#if DEVELOPMENT || DEBUG
	boolean_t use_fences = !kern_feature_override(KF_IO_TIMEOUT_OVRD);
	if (use_fences) {
		ml_timebase_to_memory_fence();
	}
#endif

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

#if DEVELOPMENT || DEBUG
	if (use_fences) {
		ml_memory_to_timebase_fence();
	}
#endif

#ifdef ML_IO_TIMEOUTS_ENABLED
	if (__improbable(timeread == TRUE)) {
		eabs = ml_io_timestamp();


		/* Prevent the processor from calling iotrace during its
		 * initialization procedure. */
		if (current_processor()->state == PROCESSOR_RUNNING) {
			iotrace(IOTRACE_IO_READ, vaddr, paddr, size, result, sabs, eabs - sabs);
		}

		if (__improbable((eabs - sabs) > report_read_delay)) {
			if (paddr == 0) {
				paddr = kvtophys(vaddr);
			}

			DTRACE_PHYSLAT5(physioread, uint64_t, (eabs - sabs),
			    uint64_t, vaddr, uint32_t, size, uint64_t, paddr, uint64_t, result);

			uint64_t override = 0;
			override_io_timeouts(vaddr, paddr, &override, NULL);

			if (override != 0) {
#if SCHED_HYGIENE_DEBUG
				/*
				 * The IO timeout was overridden. If we were called in an
				 * interrupt handler context, that can lead to a timeout
				 * panic, so we need to abandon the measurement.
				 */
				if (interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
					ml_irq_debug_abandon();
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
		}

		if (__improbable(trace_phy_read_delay > 0 && (eabs - sabs) > trace_phy_read_delay)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_MMIO_READ),
			    (eabs - sabs), VM_KERNEL_UNSLIDE_OR_PERM(vaddr), paddr, result);
		}

		(void)ml_set_interrupts_enabled_with_debug(istate, false);
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
	uintptr_t paddr = pmap_verify_noncacheable(vaddr);
#elif defined(ML_IO_TIMEOUTS_ENABLED)
	uintptr_t paddr = 0;
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
		istate = ml_set_interrupts_enabled_with_debug(false, false);
		sabs = ml_io_timestamp();
		timewrite = TRUE;
	}

#ifdef ML_IO_SIMULATE_STRETCHED_ENABLED
	if (__improbable(timewrite && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* ML_IO_TIMEOUTS_ENABLED */

#if DEVELOPMENT || DEBUG
	boolean_t use_fences = !kern_feature_override(KF_IO_TIMEOUT_OVRD);
	if (use_fences) {
		ml_timebase_to_memory_fence();
	}
#endif

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

#if DEVELOPMENT || DEBUG
	if (use_fences) {
		ml_memory_to_timebase_fence();
	}
#endif

#ifdef ML_IO_TIMEOUTS_ENABLED
	if (__improbable(timewrite == TRUE)) {
		eabs = ml_io_timestamp();

		/* Prevent the processor from calling iotrace during its
		 * initialization procedure. */
		if (current_processor()->state == PROCESSOR_RUNNING) {
			iotrace(IOTRACE_IO_WRITE, vaddr, paddr, size, val, sabs, eabs - sabs);
		}


		if (__improbable((eabs - sabs) > report_write_delay)) {
			if (paddr == 0) {
				paddr = kvtophys(vaddr);
			}

			DTRACE_PHYSLAT5(physiowrite, uint64_t, (eabs - sabs),
			    uint64_t, vaddr, uint32_t, size, uint64_t, paddr, uint64_t, val);

			uint64_t override = 0;
			override_io_timeouts(vaddr, paddr, NULL, &override);

			if (override != 0) {
#if SCHED_HYGIENE_DEBUG
				/*
				 * The IO timeout was overridden. If we were called in an
				 * interrupt handler context, that can lead to a timeout
				 * panic, so we need to abandon the measurement.
				 */
				if (interrupt_masked_debug_mode == SCHED_HYGIENE_MODE_PANIC) {
					ml_irq_debug_abandon();
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
		}

		if (__improbable(trace_phy_write_delay > 0 && (eabs - sabs) > trace_phy_write_delay)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_MMIO_WRITE),
			    (eabs - sabs), VM_KERNEL_UNSLIDE_OR_PERM(vaddr), paddr, val);
		}

		(void)ml_set_interrupts_enabled_with_debug(istate, false);
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
	if (wdt == -1 || (spec->skip_predicate != NULL && spec->skip_predicate(spec))) {
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

	uint64_t scale = 1;
	uint32_t const *scale_data;
	unsigned int scale_size = sizeof(scale_data);

	/* If there is a scale factor /machine-timeouts/<name>-scale, apply it. */
	if (base != NULL && SecureDTGetProperty(base, scale_name, (const void **)&scale_data, &scale_size) == kSuccess) {
		if (scale_size != sizeof(*scale_data)) {
			panic("%s: unexpected machine timeout data_size %u for /machine-timeouts/%s-scale", __func__, scale_size, dt_name);
		}

		scale = *scale_data;
	}

	/* If there is a scale factor /chosen/machine-timeouts/<name>-scale, use that. */
	if (chosen != NULL && SecureDTGetProperty(chosen, scale_name, (const void **)&scale_data, &scale_size) == kSuccess) {
		if (scale_size != sizeof(*scale_data)) {
			panic("%s: unexpected machine timeout data_size %u for /chosen/machine-timeouts/%s-scale", __func__,
			    scale_size, dt_name);
		}

		scale = *scale_data;
	}

	/* Finally, a boot-arg ml-timeout-<name>-scale takes precedence. */
	if (PE_parse_boot_argn(boot_arg_scale_name, &boot_arg, sizeof(boot_arg))) {
		scale = boot_arg;
	}

	static bool global_scale_set;
	static uint64_t global_scale;

	if (!global_scale_set) {
		/* Apply /machine-timeouts/global-scale if present */
		if (SecureDTGetProperty(base, "global-scale", (const void **)&scale_data, &scale_size) == kSuccess) {
			if (scale_size != sizeof(*scale_data)) {
				panic("%s: unexpected machine timeout data_size %u for /machine-timeouts/global-scale", __func__,
				    scale_size);
			}

			global_scale = *scale_data;
			global_scale_set = true;
		}

		/* Use /chosen/machine-timeouts/global-scale if present */
		if (SecureDTGetProperty(chosen, "global-scale", (const void **)&scale_data, &scale_size) == kSuccess) {
			if (scale_size != sizeof(*scale_data)) {
				panic("%s: unexpected machine timeout data_size %u for /chosen/machine-timeouts/global-scale", __func__,
				    scale_size);
			}

			global_scale = *scale_data;
			global_scale_set = true;
		}

		/* Finally, the boot-arg ml-timeout-global-scale takes precedence. */
		if (PE_parse_boot_argn("ml-timeout-global-scale", &boot_arg, sizeof(boot_arg))) {
			global_scale = boot_arg;
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

#if DEVELOPMENT || DEBUG
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

	extern void preemption_disable_reset_max_durations(void);
	/*
	 * Reset the preemption disable stats, so that they are not
	 * polluted by long early boot code.
	 */
	preemption_disable_reset_max_durations();
#endif /* SCHED_HYGIENE_DEBUG */
}
#endif /* DEVELOPMENT || DEBUG */

#if ML_IO_TIMEOUTS_ENABLED && CONFIG_XNUPOST
#include <tests/xnupost.h>

extern kern_return_t ml_io_timeout_test(void);

static inline void
ml_io_timeout_test_get_timeouts(uintptr_t vaddr, uint64_t *read_timeout, uint64_t *write_timeout)
{
	*read_timeout = 0;
	*write_timeout = 0;

	vm_offset_t paddr = kvtophys(vaddr);

	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	override_io_timeouts(vaddr, paddr, read_timeout, write_timeout);
	ml_set_interrupts_enabled(istate);
}

static inline void
ml_io_timeout_test_get_timeouts_phys(vm_offset_t paddr, uint64_t *read_timeout, uint64_t *write_timeout)
{
	*read_timeout = 0;
	*write_timeout = 0;

	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	override_io_timeouts(0, paddr, read_timeout, write_timeout);
	ml_set_interrupts_enabled(istate);
}

kern_return_t
ml_io_timeout_test(void)
{
	const size_t SIZE = 16;
	/*
	 * Page align the base address to ensure that the regions are physically
	 * contiguous.
	 */
	const uintptr_t iovaddr_base1 = (uintptr_t)kernel_pmap & ~PAGE_MASK;

	const uintptr_t iovaddr_base2 = iovaddr_base1 + SIZE;
	const uintptr_t vaddr1 = iovaddr_base1 + SIZE / 2;
	const uintptr_t vaddr2 = iovaddr_base2 + SIZE / 2;

	const vm_offset_t iopaddr_base1 = kvtophys(iovaddr_base1);
	const vm_offset_t iopaddr_base2 = kvtophys(iovaddr_base2);
	const vm_offset_t paddr1 = iopaddr_base1 + SIZE / 2;
	const vm_offset_t paddr2 = iopaddr_base2 + SIZE / 2;

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

	err = ml_io_increase_timeouts_phys(iopaddr_base1, SIZE, READ_TIMEOUT1_US, WRITE_TIMEOUT1_US);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Setting timeout for first PA region should succeed");

	err = ml_io_increase_timeouts_phys(iopaddr_base2, SIZE, READ_TIMEOUT2_US, WRITE_TIMEOUT2_US);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Setting timeout for second PA region should succeed");

	ml_io_timeout_test_get_timeouts(vaddr1, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, read_timeout1_abs, "Read timeout for first region");
	T_EXPECT_EQ_ULLONG(write_timeout, write_timeout1_abs, "Write timeout for first region");

	ml_io_timeout_test_get_timeouts(vaddr2, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, read_timeout2_abs, "Read timeout for first region");
	T_EXPECT_EQ_ULLONG(write_timeout, write_timeout2_abs, "Write timeout for first region");

	ml_io_timeout_test_get_timeouts_phys(paddr1, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, read_timeout1_abs, "Read timeout for first region");
	T_EXPECT_EQ_ULLONG(write_timeout, write_timeout1_abs, "Write timeout for first region");

	ml_io_timeout_test_get_timeouts_phys(paddr2, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, read_timeout2_abs, "Read timeout for first physical region");
	T_EXPECT_EQ_ULLONG(write_timeout, write_timeout2_abs, "Write timeout for first physical region");

	err = ml_io_reset_timeouts_phys(iopaddr_base1, SIZE);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Resetting timeout for first PA region should succeed");

	err = ml_io_reset_timeouts_phys(iopaddr_base2, SIZE);
	T_EXPECT_EQ_INT(err, KERN_SUCCESS, "Resetting timeout for second PA region should succeed");

	ml_io_timeout_test_get_timeouts_phys(paddr1, &read_timeout, &write_timeout);
	T_EXPECT_EQ_ULLONG(read_timeout, 0, "Read timeout for reset region");
	T_EXPECT_EQ_ULLONG(write_timeout, 0, "Write timeout for reset region");

	return KERN_SUCCESS;
}
#endif /* CONFIG_XNUPOST */
