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

#include <kern/kern_types.h>
#include <kern/cpu_data.h>
#include <kern/cpu_quiesce.h>
#include <kern/ipc_host.h>
#include <kern/host.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <libkern/OSDebug.h>

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
	pset = processor->processor_set;
	pset_lock(pset);

	++pset->online_processor_count;
	pset_update_processor_state(pset, processor, PROCESSOR_RUNNING);
	os_atomic_inc(&processor_avail_count, relaxed);
	if (processor->is_recommended) {
		os_atomic_inc(&processor_avail_count_user, relaxed);
		SCHED(pset_made_schedulable)(processor, pset, false);
	}
	if (processor->processor_primary == processor) {
		os_atomic_inc(&primary_processor_avail_count, relaxed);
		if (processor->is_recommended) {
			os_atomic_inc(&primary_processor_avail_count_user, relaxed);
		}
	}
	commpage_update_active_cpus();
	pset_unlock(pset);
	ml_cpu_up();
	splx(s);

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

kern_return_t
processor_shutdown(
	processor_t                     processor)
{
	processor_set_t         pset;
	spl_t                           s;

	ml_cpu_begin_state_transition(processor->cpu_id);
	s = splsched();
	pset = processor->processor_set;
	pset_lock(pset);
	if (processor->state == PROCESSOR_OFF_LINE) {
		/*
		 * Success if already shutdown.
		 */
		pset_unlock(pset);
		splx(s);
		ml_cpu_end_state_transition(processor->cpu_id);

		return KERN_SUCCESS;
	}

	if (!ml_cpu_can_exit(processor->cpu_id)) {
		/*
		 * Failure if disallowed by arch code.
		 */
		pset_unlock(pset);
		splx(s);
		ml_cpu_end_state_transition(processor->cpu_id);

		return KERN_NOT_SUPPORTED;
	}

	if (processor->state == PROCESSOR_START) {
		/*
		 * Failure if currently being started.
		 */
		pset_unlock(pset);
		splx(s);

		return KERN_FAILURE;
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
	 * Success if already being shutdown.
	 */
	if (processor->state == PROCESSOR_SHUTDOWN) {
		pset_unlock(pset);
		splx(s);
		ml_cpu_end_state_transition(processor->cpu_id);

		return KERN_SUCCESS;
	}

	ml_broadcast_cpu_event(CPU_EXIT_REQUESTED, processor->cpu_id);
	pset_update_processor_state(pset, processor, PROCESSOR_SHUTDOWN);
	pset_unlock(pset);

	processor_doshutdown(processor);
	splx(s);

	cpu_exit_wait(processor->cpu_id);
	ml_cpu_end_state_transition(processor->cpu_id);
	ml_broadcast_cpu_event(CPU_EXITED, processor->cpu_id);

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

	ml_cpu_down();

#if HIBERNATION
	if (processor_avail_count < 2) {
		hibernate_vm_lock();
		hibernate_vm_unlock();
	}
#endif

	processor_set_t pset = processor->processor_set;

	pset_lock(pset);
	pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
	--pset->online_processor_count;
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

	bool enforce_quiesce_safety = gEnforceQuiesceSafety;

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

	timer_stop(processor->current_state, processor->last_dispatch);

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

#if CONFIG_DTRACE
#include <mach/sdt.h>
#endif


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
MACHINE_TIMEOUT32_WRITEABLE(report_phy_read_delay_to, "report-phy-read-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT32_WRITEABLE(report_phy_write_delay_to, "report-phy-write-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT32_WRITEABLE(trace_phy_read_delay_to, "trace-phy-read-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);
MACHINE_TIMEOUT32_WRITEABLE(trace_phy_write_delay_to, "trace-phy-write-delay", 0, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

unsigned int report_phy_read_osbt;
unsigned int report_phy_write_osbt;

extern pmap_paddr_t kvtophys(vm_offset_t va);
#endif

unsigned long long
ml_io_read(uintptr_t vaddr, int size)
{
	unsigned long long result = 0;
	unsigned char s1;
	unsigned short s2;

#ifdef ML_IO_VERIFY_UNCACHEABLE
	uintptr_t const paddr = pmap_verify_noncacheable(vaddr);
#endif /*  ML_IO_VERIFY_UNCACHEABLE */

#ifdef ML_IO_TIMEOUTS_ENABLED
	uint64_t sabs, eabs;
	boolean_t istate, timeread = FALSE;

#if !defined(__x86_64__)
	uint32_t const report_phy_read_delay = os_atomic_load(&report_phy_read_delay_to, relaxed);
	uint32_t const trace_phy_read_delay = os_atomic_load(&trace_phy_read_delay_to, relaxed);
#endif /* !defined(__x86_64__) */

	if (__improbable(report_phy_read_delay != 0)) {
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

#ifdef ML_IO_IOTRACE_ENABLED
		iotrace(IOTRACE_IO_READ, vaddr, paddr, size, result, sabs, eabs - sabs);
#endif /*  ML_IO_IOTRACE_ENABLED */

		if (__improbable((eabs - sabs) > report_phy_read_delay)) {
#ifndef ML_IO_VERIFY_UNCACHEABLE
			uintptr_t const paddr = kvtophys(vaddr);
#endif /* ML_IO_VERIFY_UNCACHEABLE */

			if (phy_read_panic && (machine_timeout_suspended() == FALSE)) {
#if defined(__x86_64__)
				panic_notify();
#endif /* defined(__x86_64__) */
				panic("Read from IO vaddr 0x%lx paddr 0x%lx took %llu ns, "
				    "result: 0x%llx (start: %llu, end: %llu), ceiling: %llu",
				    vaddr, paddr, (eabs - sabs), result, sabs, eabs,
				    (uint64_t)report_phy_read_delay);
			}

			(void)ml_set_interrupts_enabled(istate);

			if (report_phy_read_osbt) {
				OSReportWithBacktrace("ml_io_read(v=%p, p=%p) size %d result 0x%llx "
				    "took %lluus",
				    (void *)vaddr, (void *)paddr, size, result,
				    (eabs - sabs) / NSEC_PER_USEC);
			}
#if CONFIG_DTRACE
			DTRACE_PHYSLAT5(physioread, uint64_t, (eabs - sabs),
			    uint64_t, vaddr, uint32_t, size, uint64_t, paddr, uint64_t, result);
#endif /* CONFIG_DTRACE */
		} else if (__improbable(trace_phy_read_delay > 0 && (eabs - sabs) > trace_phy_read_delay)) {
#ifndef ML_IO_VERIFY_UNCACHEABLE
			uintptr_t const __unused paddr = kvtophys(vaddr);
#endif /* ML_IO_VERIFY_UNCACHEABLE */

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
#endif
#ifdef ML_IO_TIMEOUTS_ENABLED
	uint64_t sabs, eabs;
	boolean_t istate, timewrite = FALSE;
#if !defined(__x86_64__)
	uint32_t report_phy_write_delay = os_atomic_load(&report_phy_write_delay_to, relaxed);
	uint32_t trace_phy_write_delay = os_atomic_load(&trace_phy_write_delay_to, relaxed);
#endif /* !defined(__x86_64__) */
	if (__improbable(report_phy_write_delay != 0)) {
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

#ifdef ML_IO_IOTRACE_ENABLED
		iotrace(IOTRACE_IO_WRITE, vaddr, paddr, size, val, sabs, eabs - sabs);
#endif /* ML_IO_IOTRACE_ENABLED */

		if (__improbable((eabs - sabs) > report_phy_write_delay)) {
#ifndef ML_IO_VERIFY_UNCACHEABLE
			uintptr_t const paddr = kvtophys(vaddr);
#endif /* ML_IO_VERIFY_UNCACHEABLE */

			if (phy_write_panic && (machine_timeout_suspended() == FALSE)) {
#if defined(__x86_64__)
				panic_notify();
#endif /*  defined(__x86_64__) */
				panic("Write to IO vaddr %p paddr %p val 0x%llx took %llu ns,"
				    " (start: %llu, end: %llu), ceiling: %llu",
				    (void *)vaddr, (void *)paddr, val, (eabs - sabs), sabs, eabs,
				    (uint64_t)report_phy_write_delay);
			}

			(void)ml_set_interrupts_enabled(istate);

			if (report_phy_write_osbt) {
				OSReportWithBacktrace("ml_io_write size %d (v=%p, p=%p, 0x%llx) "
				    "took %lluus",
				    size, (void *)vaddr, (void *)paddr, val, (eabs - sabs) / NSEC_PER_USEC);
			}
#if CONFIG_DTRACE
			DTRACE_PHYSLAT5(physiowrite, uint64_t, (eabs - sabs),
			    uint64_t, vaddr, uint32_t, size, uint64_t, paddr, uint64_t, val);
#endif /* CONFIG_DTRACE */
		} else if (__improbable(trace_phy_write_delay > 0 && (eabs - sabs) > trace_phy_write_delay)) {
#ifndef ML_IO_VERIFY_UNCACHEABLE
			uintptr_t const __unused paddr = kvtophys(vaddr);
#endif /* ML_IO_VERIFY_UNCACHEABLE */

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
		if (spec->is32) {
			os_atomic_store((uint32_t*)spec->ptr, 0, relaxed);
		} else {
			os_atomic_store_wide((uint64_t*)spec->ptr, 0, relaxed);
		}
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

	if (spec->is32) {
		os_atomic_store((uint32_t*)spec->ptr, timeout > UINT32_MAX ? UINT32_MAX : (uint32_t)timeout, relaxed);
	} else {
		os_atomic_store_wide((uint64_t*)spec->ptr, timeout, relaxed);
	}
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
#if INTERRUPT_MASKED_DEBUG
	machine_timeout_init_with_suffix(MACHINE_TIMEOUT_SPEC_REF(interrupt_masked_timeout), mt_suffix);
#endif
#if SCHED_PREEMPTION_DISABLE_DEBUG
	machine_timeout_init_with_suffix(MACHINE_TIMEOUT_SPEC_REF(sched_preemption_disable_threshold_mt), mt_suffix);
#endif
}
