/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

extern "C" {
#include <kern/debug.h>
#include <pexpert/pexpert.h>
#include <pexpert/arm64/board_config.h>
};

#include <kern/bits.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kperf/kperf.h>
#include <machine/machine_routines.h>
#include <libkern/OSAtomic.h>
#include <libkern/c++/OSCollection.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformActions.h>
#include <IOKit/IOPMGR.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/PassthruInterruptController.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <Kernel/IOKitKernelInternal.h>

#if USE_APPLEARMSMP

// FIXME: These are in <kern/misc_protos.h> but that file has other deps that aren't being resolved
extern "C" void console_suspend();
extern "C" void console_resume();

static PassthruInterruptController *gCPUIC;
static IOPMGR *gPMGR;
static IOInterruptController *gAIC;
static bool aic_ipis = false;
static const ml_topology_info *topology_info;

// cpu_id of the boot processor
static unsigned int boot_cpu;

// array index is a cpu_id (so some elements may be NULL)
static processor_t *machProcessors;

bool cluster_power_supported = false;
static uint64_t cpu_power_state_mask;
static uint64_t all_clusters_mask;
static uint64_t online_clusters_mask;

static void
processor_idle_wrapper(cpu_id_t /*cpu_id*/, boolean_t enter, uint64_t *new_timeout_ticks)
{
	if (enter) {
		gPMGR->enterCPUIdle(new_timeout_ticks);
	} else {
		gPMGR->exitCPUIdle(new_timeout_ticks);
	}
}

static void
idle_timer_wrapper(void */*refCon*/, uint64_t *new_timeout_ticks)
{
	gPMGR->updateCPUIdle(new_timeout_ticks);
}

static OSDictionary *
matching_dict_for_cpu_id(unsigned int cpu_id)
{
	// The cpu-id property in EDT doesn't necessarily match the dynamically
	// assigned logical ID in XNU, so look up the cpu node by the physical
	// (cluster/core) ID instead.
	OSSymbolConstPtr cpuTypeSymbol = OSSymbol::withCString("cpu");
	OSSymbolConstPtr cpuIdSymbol = OSSymbol::withCString("reg");
	OSDataPtr cpuId = OSData::withValue(topology_info->cpus[cpu_id].phys_id);

	OSDictionary *propMatch = OSDictionary::withCapacity(4);
	propMatch->setObject(gIODTTypeKey, cpuTypeSymbol);
	propMatch->setObject(cpuIdSymbol, cpuId);

	OSDictionary *matching = IOService::serviceMatching("IOPlatformDevice");
	matching->setObject(gIOPropertyMatchKey, propMatch);

	propMatch->release();
	cpuTypeSymbol->release();
	cpuIdSymbol->release();
	cpuId->release();

	return matching;
}

static void
register_aic_handlers(const ml_topology_cpu *cpu_info,
    ipi_handler_t ipi_handler,
    perfmon_interrupt_handler_func pmi_handler)
{
	OSDictionary *matching = matching_dict_for_cpu_id(cpu_info->cpu_id);
	IOService *cpu = IOService::waitForMatchingService(matching, UINT64_MAX);
	matching->release();

	OSArray *irqs = (OSArray *) cpu->getProperty(gIOInterruptSpecifiersKey);
	if (!irqs) {
		panic("Error finding interrupts for CPU %d", cpu_info->cpu_id);
	}

	unsigned int irqcount = irqs->getCount();

	if (irqcount == 3) {
		// Legacy configuration, for !HAS_IPI chips (pre-Skye).
		if (cpu->registerInterrupt(0, NULL, (IOInterruptAction)ipi_handler, NULL) != kIOReturnSuccess ||
		    cpu->enableInterrupt(0) != kIOReturnSuccess ||
		    cpu->registerInterrupt(2, NULL, (IOInterruptAction)ipi_handler, NULL) != kIOReturnSuccess ||
		    cpu->enableInterrupt(2) != kIOReturnSuccess) {
			panic("Error registering IPIs");
		}
#if !defined(HAS_IPI)
		// Ideally this should be decided by EDT, but first we need to update EDT
		// to default to fast IPIs on modern platforms.
		aic_ipis = true;
#endif
	}

	// Conditional, because on Skye and later, we use an FIQ instead of an external IRQ.
	if (pmi_handler && irqcount == 1) {
		if (cpu->registerInterrupt(1, NULL, (IOInterruptAction)(void (*)(void))pmi_handler, NULL) != kIOReturnSuccess ||
		    cpu->enableInterrupt(1) != kIOReturnSuccess) {
			panic("Error registering PMI");
		}
	}
}

static void
cpu_boot_thread(void */*unused0*/, wait_result_t /*unused1*/)
{
	OSDictionary *matching = IOService::serviceMatching("IOPlatformExpert");
	IOService::waitForMatchingService(matching, UINT64_MAX);
	matching->release();

	gCPUIC = new PassthruInterruptController;
	if (!gCPUIC || !gCPUIC->init()) {
		panic("Can't initialize PassthruInterruptController");
	}
	gAIC = static_cast<IOInterruptController *>(gCPUIC->waitForChildController());

	ml_set_max_cpus(topology_info->max_cpu_id + 1);

#if XNU_CLUSTER_POWER_DOWN
	cluster_power_supported = true;
	/*
	 * If a boot-arg is set that allows threads to be bound
	 * to a cpu or cluster, cluster_power_supported must
	 * default to false.
	 */
#ifdef CONFIG_XNUPOST
	uint64_t kernel_post = 0;
	PE_parse_boot_argn("kernPOST", &kernel_post, sizeof(kernel_post));
	if (kernel_post != 0) {
		cluster_power_supported = false;
	}
#endif
	if (PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		cluster_power_supported = false;
	}
	if (PE_parse_boot_argn("enable_skstsct", NULL, 0)) {
		cluster_power_supported = false;
	}
#endif
	PE_parse_boot_argn("cluster_power", &cluster_power_supported, sizeof(cluster_power_supported));

	matching = IOService::serviceMatching("IOPMGR");
	gPMGR = OSDynamicCast(IOPMGR,
	    IOService::waitForMatchingService(matching, UINT64_MAX));
	matching->release();

	const size_t array_size = (topology_info->max_cpu_id + 1) * sizeof(*machProcessors);
	machProcessors = static_cast<processor_t *>(zalloc_permanent(array_size, ZALIGN_PTR));

	for (unsigned int cpu = 0; cpu < topology_info->num_cpus; cpu++) {
		const ml_topology_cpu *cpu_info = &topology_info->cpus[cpu];
		const unsigned int cpu_id = cpu_info->cpu_id;
		ml_processor_info_t this_processor_info;
		ipi_handler_t ipi_handler;
		perfmon_interrupt_handler_func pmi_handler;

		memset(&this_processor_info, 0, sizeof(this_processor_info));
		this_processor_info.cpu_id = reinterpret_cast<cpu_id_t>(cpu_id);
		this_processor_info.phys_id = cpu_info->phys_id;
		this_processor_info.log_id = cpu_id;
		this_processor_info.cluster_id = cpu_info->cluster_id;
		this_processor_info.cluster_type = cpu_info->cluster_type;
		this_processor_info.l2_cache_size = cpu_info->l2_cache_size;
		this_processor_info.l2_cache_id = cpu_info->l2_cache_id;
		this_processor_info.l3_cache_size = cpu_info->l3_cache_size;
		this_processor_info.l3_cache_id = cpu_info->l3_cache_id;

		gPMGR->initCPUIdle(&this_processor_info);
		this_processor_info.processor_idle = &processor_idle_wrapper;
		this_processor_info.idle_timer = &idle_timer_wrapper;

		kern_return_t result = ml_processor_register(&this_processor_info,
		    &machProcessors[cpu_id], &ipi_handler, &pmi_handler);
		if (result == KERN_FAILURE) {
			panic("ml_processor_register failed: %d", result);
		}
		register_aic_handlers(cpu_info, ipi_handler, pmi_handler);

		if (processor_start(machProcessors[cpu_id]) != KERN_SUCCESS) {
			panic("processor_start failed");
		}
	}
	ml_cpu_init_completed();
	IOService::publishResource(gIOAllCPUInitializedKey, kOSBooleanTrue);
}

void
IOCPUInitialize(void)
{
	topology_info = ml_get_topology_info();
	boot_cpu = topology_info->boot_cpu->cpu_id;

	for (unsigned int i = 0; i < topology_info->num_clusters; i++) {
		bit_set(all_clusters_mask, topology_info->clusters[i].cluster_id);
	}
	// iBoot powers up every cluster (at least for now)
	online_clusters_mask = all_clusters_mask;

	thread_t thread;
	kernel_thread_start(&cpu_boot_thread, NULL, &thread);
	thread_set_thread_name(thread, "cpu_boot_thread");
	thread_deallocate(thread);
}

static unsigned int
target_to_cpu_id(cpu_id_t in)
{
	return (unsigned int)(uintptr_t)in;
}

// Release a secondary CPU from reset.  Runs from a different CPU (obviously).
kern_return_t
PE_cpu_start(cpu_id_t target,
    vm_offset_t /*start_paddr*/, vm_offset_t /*arg_paddr*/)
{
	unsigned int cpu_id = target_to_cpu_id(target);

	if (cpu_id != boot_cpu) {
#if APPLEVIRTUALPLATFORM
		/* When running virtualized, the reset vector address must be passed to PMGR explicitly */
		extern unsigned int LowResetVectorBase;
		gPMGR->enableCPUCore(cpu_id, ml_vtophys((vm_offset_t)&LowResetVectorBase));
#else
		gPMGR->enableCPUCore(cpu_id, 0);
#endif
	}
	return KERN_SUCCESS;
}

// Initialize a CPU when it first comes up.  Runs on the target CPU.
// |bootb| is true on the initial boot, false on S2R resume.
void
PE_cpu_machine_init(cpu_id_t target, boolean_t bootb)
{
	unsigned int cpu_id = target_to_cpu_id(target);

	if (!bootb && cpu_id == boot_cpu && ml_is_quiescing()) {
		IOCPURunPlatformActiveActions();
	}

	ml_broadcast_cpu_event(CPU_BOOTED, cpu_id);

	// Send myself an IPI to clear SIGPdisabled.  Hang here if IPIs are broken.
	// (Probably only works on the boot CPU.)
	PE_cpu_signal(target, target);
	while (ml_get_interrupts_enabled() && !ml_cpu_signal_is_enabled()) {
		OSMemoryBarrier();
	}
}

void
PE_cpu_halt(cpu_id_t target)
{
	unsigned int cpu_id = target_to_cpu_id(target);
	processor_exit(machProcessors[cpu_id]);
}

void
PE_cpu_signal(cpu_id_t /*source*/, cpu_id_t target)
{
	struct ml_topology_cpu *cpu = &topology_info->cpus[target_to_cpu_id(target)];
	if (aic_ipis) {
		gAIC->sendIPI(cpu->cpu_id, false);
	} else {
		ml_cpu_signal(cpu->phys_id);
	}
}

void
PE_cpu_signal_deferred(cpu_id_t /*source*/, cpu_id_t target)
{
	struct ml_topology_cpu *cpu = &topology_info->cpus[target_to_cpu_id(target)];
	if (aic_ipis) {
		gAIC->sendIPI(cpu->cpu_id, true);
	} else {
		ml_cpu_signal_deferred(cpu->phys_id);
	}
}

void
PE_cpu_signal_cancel(cpu_id_t /*source*/, cpu_id_t target)
{
	struct ml_topology_cpu *cpu = &topology_info->cpus[target_to_cpu_id(target)];
	if (aic_ipis) {
		gAIC->cancelDeferredIPI(cpu->cpu_id);
	} else {
		ml_cpu_signal_retract(cpu->phys_id);
	}
}

// Brings down one CPU core for S2R.  Runs on the target CPU.
void
PE_cpu_machine_quiesce(cpu_id_t target)
{
	unsigned int cpu_id = target_to_cpu_id(target);

	if (cpu_id == boot_cpu) {
		IOCPURunPlatformQuiesceActions();
	} else {
		gPMGR->disableCPUCore(cpu_id);
	}

	ml_broadcast_cpu_event(CPU_DOWN, cpu_id);
	ml_arm_sleep();
}

static bool
is_cluster_powering_down(int cpu_id)
{
	// Don't kill the cluster power if any other CPUs in this cluster are still awake
	unsigned int target_cluster_id = topology_info->cpus[cpu_id].cluster_id;
	for (int i = 0; i < topology_info->num_cpus; i++) {
		if (topology_info->cpus[i].cluster_id == target_cluster_id &&
		    cpu_id != i &&
		    bit_test(cpu_power_state_mask, i)) {
			return false;
		}
	}
	return true;
}

// Takes one secondary CPU core offline at runtime.  Runs on the target CPU.
// Returns true if the platform code should go into deep sleep WFI, false otherwise.
bool
PE_cpu_down(cpu_id_t target)
{
	unsigned int cpu_id = target_to_cpu_id(target);
	assert(cpu_id != boot_cpu);
	gPMGR->disableCPUCore(cpu_id);
	ml_broadcast_cpu_event(CPU_DOWN, cpu_id);
	return cluster_power_supported && is_cluster_powering_down(cpu_id);
}

void
PE_handle_ext_interrupt(void)
{
	gCPUIC->externalInterrupt();
}

void
PE_cpu_power_disable(int cpu_id)
{
	bit_clear(cpu_power_state_mask, cpu_id);
	if (!cluster_power_supported || cpu_id == boot_cpu) {
		return;
	}

	// Don't kill the cluster power if any other CPUs in this cluster are still awake
	unsigned int target_cluster_id = topology_info->cpus[cpu_id].cluster_id;
	if (!is_cluster_powering_down(cpu_id)) {
		return;
	}

	if (processor_should_kprintf(machProcessors[cpu_id], false)) {
		kprintf("%s>turning off power to cluster %d\n", __FUNCTION__, target_cluster_id);
	}
	ml_broadcast_cpu_event(CLUSTER_EXIT_REQUESTED, target_cluster_id);
	bit_clear(online_clusters_mask, target_cluster_id);
	gPMGR->disableCPUCluster(target_cluster_id);
}

void
PE_cpu_power_enable(int cpu_id)
{
	bit_set(cpu_power_state_mask, cpu_id);
	if (!cluster_power_supported || cpu_id == boot_cpu) {
		return;
	}

	unsigned int cluster_id = topology_info->cpus[cpu_id].cluster_id;
	if (!bit_test(online_clusters_mask, cluster_id)) {
		if (processor_should_kprintf(machProcessors[cpu_id], true)) {
			kprintf("%s>turning on power to cluster %d\n", __FUNCTION__, cluster_id);
		}
		gPMGR->enableCPUCluster(cluster_id);
		bit_set(online_clusters_mask, cluster_id);
		ml_broadcast_cpu_event(CLUSTER_ACTIVE, cluster_id);
	}
}

void
IOCPUSleepKernel(void)
{
	IOPMrootDomain  *rootDomain = IOService::getPMRootDomain();
	unsigned int i;

	printf("IOCPUSleepKernel enter\n");
	sched_override_available_cores_for_sleep();

	rootDomain->tracePoint( kIOPMTracePointSleepPlatformActions );
	IOPlatformActionsPreSleep();
	rootDomain->tracePoint( kIOPMTracePointSleepCPUs );

	integer_t old_pri;
	thread_t self = current_thread();

	/*
	 * We need to boost this thread's priority to the maximum kernel priority to
	 * ensure we can urgently preempt ANY thread currently executing on the
	 * target CPU.  Note that realtime threads have their own mechanism to eventually
	 * demote their priority below MAXPRI_KERNEL if they hog the CPU for too long.
	 */
	old_pri = thread_kern_get_pri(self);
	thread_kern_set_pri(self, thread_kern_get_kernel_maxpri());

	// Sleep the non-boot CPUs.
	ml_set_is_quiescing(true);
	for (i = 0; i < topology_info->num_cpus; i++) {
		unsigned int cpu_id = topology_info->cpus[i].cpu_id;
		if (cpu_id != boot_cpu) {
			processor_exit(machProcessors[cpu_id]);
		}
	}

	console_suspend();

	rootDomain->tracePoint( kIOPMTracePointSleepPlatformDriver );
	rootDomain->stop_watchdog_timer();

	/*
	 * Now sleep the boot CPU, including calling the kQueueQuiesce actions.
	 * The system sleeps here.
	 */
	processor_exit(machProcessors[boot_cpu]);

	/*
	 * The system is now coming back from sleep on the boot CPU.
	 * The kQueueActive actions have already been called.
	 *
	 * The reconfig engine is programmed to power up all clusters on S2R resume.
	 */
	online_clusters_mask = all_clusters_mask;

	/*
	 * processor_start() never gets called for the boot CPU, so it needs to
	 * be explicitly marked as online here.
	 */
	PE_cpu_power_enable(boot_cpu);

	ml_set_is_quiescing(false);

	rootDomain->start_watchdog_timer();

	console_resume();

	rootDomain->tracePoint( kIOPMTracePointWakeCPUs );

	for (i = 0; i < topology_info->num_cpus; i++) {
		unsigned int cpu_id = topology_info->cpus[i].cpu_id;
		if (cpu_id != boot_cpu) {
			processor_start(machProcessors[cpu_id]);
		}
	}

	rootDomain->tracePoint( kIOPMTracePointWakePlatformActions );
	IOPlatformActionsPostResume();

	sched_restore_available_cores_after_sleep();

	thread_kern_set_pri(self, old_pri);
	printf("IOCPUSleepKernel exit\n");
}

#endif /* USE_APPLEARMSMP */
