/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 */

/*
 *	Mach kernel startup.
 */

#include <debug.h>
#include <mach_kdp.h>

#include <mach/boolean.h>
#include <mach/machine.h>
#include <mach/thread_act.h>
#include <mach/task_special_ports.h>
#include <mach/vm_param.h>
#include <kern/assert.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <kern/clock.h>
#include <kern/coalition.h>
#include <kern/cpu_number.h>
#include <kern/ledger.h>
#include <kern/machine.h>
#include <kern/processor.h>
#include <kern/restartable.h>
#include <kern/sched_prim.h>
#include <kern/turnstile.h>
#if CONFIG_SCHED_SFI
#include <kern/sfi.h>
#endif
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/timer.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <kern/debug.h>
#if KPERF
#include <kperf/kperf.h>
#endif /* KPERF */
#include <corpses/task_corpse.h>
#include <prng/random.h>
#include <console/serial_protos.h>
#include <vm/vm_kern.h>
#include <vm/vm_init.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_shared_region.h>
#include <machine/pmap.h>
#include <machine/commpage.h>
#include <machine/machine_routines.h>
#include <libkern/version.h>
#include <pexpert/device_tree.h>
#include <sys/codesign.h>
#include <sys/kdebug.h>
#include <sys/random.h>
#include <sys/ktrace.h>
#include <sys/trust_caches.h>
#include <sys/code_signing.h>
#include <libkern/section_keywords.h>

#include <kern/waitq.h>
#include <ipc/ipc_voucher.h>
#include <mach/host_info.h>
#include <pthread/workqueue_internal.h>

#if SOCKETS
extern void mbuf_tag_init(void);
#endif

#if CONFIG_XNUPOST
#include <tests/ktest.h>
#include <tests/xnupost.h>
#endif

#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

#if CONFIG_CSR
#include <sys/csr.h>
#endif

#if ALTERNATE_DEBUGGER
#include <arm64/alternate_debugger.h>
#endif

#if MACH_KDP
#include <kdp/kdp.h>
#endif

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#if CONFIG_VNGUARD
extern void vnguard_policy_init(void);
#endif
#endif

#if KPC
#include <kern/kpc.h>
#endif

#if HYPERVISOR
#include <kern/hv_support.h>
#endif

#if CONFIG_UBSAN_MINIMAL
#include <san/ubsan_minimal.h>
#endif

#include <san/kasan.h>

#include <i386/pmCPU.h>
static void             kernel_bootstrap_thread(void);

static void             load_context(
	thread_t        thread);

#if CONFIG_ECC_LOGGING
#include <kern/ecc.h>
#endif

#if (defined(__i386__) || defined(__x86_64__)) && CONFIG_VMX
#include <i386/vmx/vmx_cpu.h>
#endif

#if CONFIG_DTRACE
extern void dtrace_early_init(void);
extern void sdt_early_init(void);
#endif

// libkern/OSKextLib.cpp
extern void OSKextRemoveKextBootstrap(void);

void scale_setup(void);
extern void bsd_scale_setup(int);
extern unsigned int semaphore_max;
extern void stackshot_init(void);

/*
 *	Running in virtual memory, on the interrupt stack.
 */

extern struct startup_entry startup_entries[]
__SECTION_START_SYM(STARTUP_HOOK_SEGMENT, STARTUP_HOOK_SECTION);

extern struct startup_entry startup_entries_end[]
__SECTION_END_SYM(STARTUP_HOOK_SEGMENT, STARTUP_HOOK_SECTION);

static struct startup_entry *__startup_data startup_entry_cur = startup_entries;

SECURITY_READ_ONLY_LATE(startup_subsystem_id_t) startup_phase = STARTUP_SUB_NONE;

extern int serverperfmode;

TUNABLE(startup_debug_t, startup_debug, "startup_debug", 0);

static inline void
kernel_bootstrap_log(const char *message)
{
	if ((startup_debug & STARTUP_DEBUG_VERBOSE) &&
	    startup_phase >= STARTUP_SUB_KPRINTF) {
		kprintf("kernel_bootstrap: %s\n", message);
	}
	kernel_debug_string_early(message);
}

static inline void
kernel_bootstrap_thread_log(const char *message)
{
	if ((startup_debug & STARTUP_DEBUG_VERBOSE) &&
	    startup_phase >= STARTUP_SUB_KPRINTF) {
		kprintf("kernel_bootstrap_thread: %s\n", message);
	}
	kernel_debug_string_early(message);
}

extern void
qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

__startup_func
static int
startup_entry_cmp(const void *e1, const void *e2)
{
	const struct startup_entry *a = e1;
	const struct startup_entry *b = e2;
	if (a->subsystem == b->subsystem) {
		if (a->rank == b->rank) {
			return 0;
		}
		return a->rank > b->rank ? 1 : -1;
	}
	return a->subsystem > b->subsystem ? 1 : -1;
}

__startup_func
void
kernel_startup_bootstrap(void)
{
	/*
	 * Sort the various STARTUP() entries by subsystem/rank.
	 */
	size_t n = startup_entries_end - startup_entries;

	if (n == 0) {
		panic("Section %s,%s missing",
		    STARTUP_HOOK_SEGMENT, STARTUP_HOOK_SECTION);
	}
	if (((uintptr_t)startup_entries_end - (uintptr_t)startup_entries) %
	    sizeof(struct startup_entry)) {
		panic("Section %s,%s has invalid size",
		    STARTUP_HOOK_SEGMENT, STARTUP_HOOK_SECTION);
	}

	qsort(startup_entries, n, sizeof(struct startup_entry), startup_entry_cmp);

	/*
	 * Then initialize all tunables, timeouts, and locks
	 */
	kernel_startup_initialize_upto(STARTUP_SUB_LOCKS);
}

__startup_func
void
kernel_startup_tunable_init(const struct startup_tunable_spec *spec)
{
	if (spec->var_is_str) {
		PE_parse_boot_arg_str(spec->name, spec->var_addr, spec->var_len);
	} else if (PE_parse_boot_argn(spec->name, spec->var_addr, spec->var_len)) {
		if (spec->var_is_bool) {
			/* make sure bool's are valued in {0, 1} */
			*(bool *)spec->var_addr = *(uint8_t *)spec->var_addr;
		}
	}
}

__startup_func
void
kernel_startup_tunable_dt_init(const struct startup_tunable_dt_spec *spec)
{
	DTEntry base;

	if (SecureDTLookupEntry(NULL, spec->dt_base, &base) != kSuccess) {
		base = NULL;
	}

	bool found_in_chosen = false;

	if (spec->dt_chosen_override) {
		DTEntry chosen, chosen_base;

		if (SecureDTLookupEntry(NULL, "chosen", &chosen) != kSuccess) {
			chosen = NULL;
		}

		if (chosen != NULL && SecureDTLookupEntry(chosen, spec->dt_base, &chosen_base) == kSuccess) {
			base = chosen_base;
			found_in_chosen = true;
		}
	}

	uint64_t const *data;
	unsigned int data_size = spec->var_len;

	if (base != NULL && SecureDTGetProperty(base, spec->dt_name, (const void **)&data, &data_size) == kSuccess) {
		if (data_size != spec->var_len) {
			panic("unexpected tunable size %u in DT entry %s/%s/%s",
			    data_size, found_in_chosen ? "/chosen" : "", spec->dt_base, spec->dt_name);
		}

		/* No need to handle bools specially, they are 1 byte integers in the DT. */
		memcpy(spec->var_addr, data, spec->var_len);
	}

	/* boot-arg overrides. */

	if (PE_parse_boot_argn(spec->boot_arg_name, spec->var_addr, spec->var_len)) {
		if (spec->var_is_bool) {
			*(bool *)spec->var_addr = *(uint8_t *)spec->var_addr;
		}
	}
}

static void
kernel_startup_log(startup_subsystem_id_t subsystem)
{
	static const char *names[] = {
		[STARTUP_SUB_TUNABLES] = "tunables",
		[STARTUP_SUB_TIMEOUTS] = "timeouts",
		[STARTUP_SUB_LOCKS] = "locks",
		[STARTUP_SUB_KPRINTF] = "kprintf",

		[STARTUP_SUB_PMAP_STEAL] = "pmap_steal",
		[STARTUP_SUB_KMEM] = "kmem",
		[STARTUP_SUB_ZALLOC] = "zalloc",
		[STARTUP_SUB_PERCPU] = "percpu",
		[STARTUP_SUB_EVENT] = "event",

		[STARTUP_SUB_CODESIGNING] = "codesigning",
		[STARTUP_SUB_KTRACE] = "ktrace",
		[STARTUP_SUB_OSLOG] = "oslog",
		[STARTUP_SUB_MACH_IPC] = "mach_ipc",
		[STARTUP_SUB_THREAD_CALL] = "thread_call",
		[STARTUP_SUB_SYSCTL] = "sysctl",
		[STARTUP_SUB_EARLY_BOOT] = "early_boot",

		/* LOCKDOWN is special and its value won't fit here. */
	};
	static startup_subsystem_id_t logged = STARTUP_SUB_NONE;

	if (subsystem <= logged) {
		return;
	}

	if (subsystem < sizeof(names) / sizeof(names[0]) && names[subsystem]) {
		kernel_bootstrap_log(names[subsystem]);
	}
	logged = subsystem;
}

__startup_func
void
event_register_handler(struct event_hdr *hdr)
{
	struct event_hdr *head = hdr->next;

	hdr->next = head->next;
	head->next = hdr;
}

__startup_func
void
kernel_startup_initialize_upto(startup_subsystem_id_t upto)
{
	struct startup_entry *cur = startup_entry_cur;

	assert(startup_phase < upto);

	while (cur < startup_entries_end && cur->subsystem <= upto) {
		if ((startup_debug & STARTUP_DEBUG_VERBOSE) &&
		    startup_phase >= STARTUP_SUB_KPRINTF) {
			kprintf("%s[%d, rank %d]: %p(%p)\n", __func__,
			    cur->subsystem, cur->rank, cur->func, cur->arg);
		}
		startup_phase = cur->subsystem - 1;
		kernel_startup_log(cur->subsystem);
		cur->func(cur->arg);
		startup_entry_cur = ++cur;
	}
	kernel_startup_log(upto);

	if ((startup_debug & STARTUP_DEBUG_VERBOSE) &&
	    upto >= STARTUP_SUB_KPRINTF) {
		kprintf("%s: reached phase %d\n", __func__, upto);
	}
	startup_phase = upto;
}

void
kernel_bootstrap(void)
{
	kern_return_t   result;
	thread_t        thread;
	char            namep[16];

	printf("%s\n", version); /* log kernel version */

	scale_setup();

	kernel_bootstrap_log("vm_mem_bootstrap");
	vm_mem_bootstrap();

	machine_info.memory_size = (uint32_t)mem_size;
#if XNU_TARGET_OS_OSX
	machine_info.max_mem = max_mem_actual;
#else
	machine_info.max_mem = max_mem;
#endif /* XNU_TARGET_OS_OSX */
	machine_info.major_version = version_major;
	machine_info.minor_version = version_minor;

#if CONFIG_ATM
	/* Initialize the Activity Trace Resource Manager. */
	kernel_bootstrap_log("atm_init");
	atm_init();
#endif
	kernel_startup_initialize_upto(STARTUP_SUB_OSLOG);

#if CONFIG_UBSAN_MINIMAL
	kernel_bootstrap_log("UBSan minimal runtime init");
	ubsan_minimal_init();
#endif

#if KASAN
	kernel_bootstrap_log("kasan_late_init");
	kasan_late_init();
#endif

#if CONFIG_TELEMETRY
	kernel_bootstrap_log("telemetry_init");
	telemetry_init();
#endif

	if (PE_i_can_has_debugger(NULL)) {
		if (PE_parse_boot_argn("-show_pointers", &namep, sizeof(namep))) {
			doprnt_hide_pointers = FALSE;
		}
		if (PE_parse_boot_argn("-no_slto_panic", &namep, sizeof(namep))) {
			extern boolean_t spinlock_timeout_panic;
			spinlock_timeout_panic = FALSE;
		}
	}

	kernel_bootstrap_log("console_init");
	console_init();

	kernel_bootstrap_log("stackshot_init");
	stackshot_init();

	kernel_bootstrap_log("sched_init");
	sched_init();

#if CONFIG_MACF
	kernel_bootstrap_log("mac_policy_init");
	mac_policy_init();
#endif

	kernel_startup_initialize_upto(STARTUP_SUB_MACH_IPC);

	/*
	 * As soon as the virtual memory system is up, we record
	 * that this CPU is using the kernel pmap.
	 */
	kernel_bootstrap_log("PMAP_ACTIVATE_KERNEL");
	PMAP_ACTIVATE_KERNEL(master_cpu);

	kernel_bootstrap_log("mapping_free_prime");
	mapping_free_prime();                                           /* Load up with temporary mapping blocks */

	kernel_bootstrap_log("machine_init");
	machine_init();

	kernel_bootstrap_log("thread_machine_init_template");
	thread_machine_init_template();

	kernel_bootstrap_log("clock_init");
	clock_init();

	/*
	 *	Initialize the IPC, task, and thread subsystems.
	 */
#if CONFIG_THREAD_GROUPS
	kernel_bootstrap_log("thread_group_init");
	thread_group_init();
#endif

#if CONFIG_COALITIONS
	kernel_bootstrap_log("coalitions_init");
	coalitions_init();
#endif

	kernel_bootstrap_log("code_signing_init");
	code_signing_init();
	code_signing_configuration(NULL, NULL);

	kernel_bootstrap_log("task_init");
	task_init();

	kernel_bootstrap_log("thread_init");
	thread_init();

	kernel_bootstrap_log("restartable_init");
	restartable_init();

	kernel_bootstrap_log("workq_init");
	workq_init();

	kernel_bootstrap_log("turnstiles_init");
	turnstiles_init();

	kernel_bootstrap_log("mach_init_activity_id");
	mach_init_activity_id();

	/* initialize host_statistics */
	host_statistics_init();

	/* initialize exceptions */
	kernel_bootstrap_log("exception_init");
	exception_init();

#if CONFIG_SCHED_SFI
	kernel_bootstrap_log("sfi_init");
	sfi_init();
#endif

	/*
	 *	Create a kernel thread to execute the kernel bootstrap.
	 */

	kernel_bootstrap_log("kernel_thread_create");
	result = kernel_thread_create((thread_continue_t)kernel_bootstrap_thread, NULL, MAXPRI_KERNEL, &thread);

	if (result != KERN_SUCCESS) {
		panic("kernel_bootstrap: result = %08X", result);
	}

	/* TODO: do a proper thread_start() (without the thread_setrun()) */
	thread->state = TH_RUN;
	thread->last_made_runnable_time = mach_absolute_time();
	thread_set_thread_name(thread, "kernel_bootstrap_thread");

	thread_deallocate(thread);

	kernel_bootstrap_log("load_context - done");
	load_context(thread);
	/*NOTREACHED*/
}

SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_addrperm;
SECURITY_READ_ONLY_LATE(vm_offset_t) buf_kernel_addrperm;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_addrperm_ext;
SECURITY_READ_ONLY_LATE(uint64_t) vm_kernel_addrhash_salt;
SECURITY_READ_ONLY_LATE(uint64_t) vm_kernel_addrhash_salt_ext;

/*
 * Now running in a thread.  Kick off other services,
 * invoke user bootstrap, enter pageout loop.
 */
static void
kernel_bootstrap_thread(void)
{
	processor_t processor = current_processor();

#if (DEVELOPMENT || DEBUG)
	platform_stall_panic_or_spin(PLATFORM_STALL_XNU_LOCATION_KERNEL_BOOTSTRAP);
#endif

	kernel_bootstrap_thread_log("idle_thread_create");
	/*
	 * Create the idle processor thread.
	 */
	idle_thread_create(processor);

	/*
	 * N.B. Do not stick anything else
	 * before this point.
	 *
	 * Start up the scheduler services.
	 */
	kernel_bootstrap_thread_log("sched_startup");
	sched_startup();

	/*
	 * Thread lifecycle maintenance (teardown, stack allocation)
	 */
	kernel_bootstrap_thread_log("thread_daemon_init");
	thread_daemon_init();

	/*
	 * Thread callout service.
	 */
	kernel_startup_initialize_upto(STARTUP_SUB_THREAD_CALL);

	/*
	 * Remain on current processor as
	 * additional processors come online.
	 */
	kernel_bootstrap_thread_log("thread_bind");
	thread_bind(processor);

	/*
	 * Kick off memory mapping adjustments.
	 */
	kernel_bootstrap_thread_log("mapping_adjust");
	mapping_adjust();

	/*
	 *	Create the clock service.
	 */
	kernel_bootstrap_thread_log("clock_service_create");
	clock_service_create();

	/*
	 *	Create the device service.
	 */
	device_service_create();

	phys_carveout_init();

#if MACH_KDP
	kernel_bootstrap_log("kdp_init");
	kdp_init();
#endif

#if ALTERNATE_DEBUGGER
	alternate_debugger_init();
#endif

#if HYPERVISOR
	kernel_bootstrap_thread_log("hv_support_init");
	hv_support_init();
#endif

#if CONFIG_TELEMETRY
	kernel_bootstrap_log("bootprofile_init");
	bootprofile_init();
#endif

	kernel_startup_initialize_upto(STARTUP_SUB_SYSCTL);

	/*
	 * Initialize the globals used for permuting kernel
	 * addresses that may be exported to userland as tokens
	 * using VM_KERNEL_ADDRPERM()/VM_KERNEL_ADDRPERM_EXTERNAL().
	 * Force the random number to be odd to avoid mapping a non-zero
	 * word-aligned address to zero via addition.
	 */
	vm_kernel_addrperm = (vm_offset_t)(early_random() | 1);
	buf_kernel_addrperm = (vm_offset_t)(early_random() | 1);
	vm_kernel_addrperm_ext = (vm_offset_t)(early_random() | 1);
	vm_kernel_addrhash_salt = early_random();
	vm_kernel_addrhash_salt_ext = early_random();

#ifdef  IOKIT
	kernel_bootstrap_log("PE_init_iokit");
	PE_init_iokit();
#endif

	assert(ml_get_interrupts_enabled() == FALSE);

	/*
	 * Past this point, kernel subsystems that expect to operate with
	 * interrupts or preemption enabled may begin enforcement.
	 */
	kernel_startup_initialize_upto(STARTUP_SUB_EARLY_BOOT);

#if SCHED_HYGIENE_DEBUG
	// Reset interrupts masked timeout before we enable interrupts
	ml_spin_debug_clear_self();
#endif
	(void) spllo();         /* Allow interruptions */

	/*
	 * This will start displaying progress to the user, start as early as possible
	 */
	initialize_screen(NULL, kPEAcquireScreen);

	/*
	 *	Initialize the shared region module.
	 */
	vm_commpage_init();
	vm_commpage_text_init();

#if CONFIG_MACF
	kernel_bootstrap_log("mac_policy_initmach");
	mac_policy_initmach();
#if CONFIG_VNGUARD
	kernel_bootstrap_log("vnguard_policy_init");
	vnguard_policy_init();
#endif
#endif

#if CONFIG_DTRACE
	kernel_bootstrap_log("dtrace_early_init");
	dtrace_early_init();
	sdt_early_init();
#endif

#if CODE_SIGNING_MONITOR
	kernel_bootstrap_log("provisioning_profile_init");
	csm_initialize_provisioning_profiles();
#endif

#ifndef BCM2837
	kernel_bootstrap_log("trust_cache_init");

	/* Initialize the runtime for the trust cache interface */
	trust_cache_runtime_init();

	/* Load the static and engineering trust caches */
	load_static_trust_cache();
#endif

	kernel_startup_initialize_upto(STARTUP_SUB_LOCKDOWN);

	/*
	 * Get rid of segments used to bootstrap kext loading. This removes
	 * the KLD, PRELINK symtab, LINKEDIT, and symtab segments/load commands.
	 * Must be done prior to lockdown so that we can free (and possibly relocate)
	 * the static KVA mappings used for the jettisoned bootstrap segments.
	 */
	kernel_bootstrap_log("OSKextRemoveKextBootstrap");
	OSKextRemoveKextBootstrap();

#if SOCKETS
	/*
	 * Initialize callback table before machine lockdown
	 */
	mbuf_tag_init();
#endif

	/* No changes to kernel text and rodata beyond this point. */
	kernel_bootstrap_log("machine_lockdown");
	machine_lockdown();

#ifdef CONFIG_XNUPOST
	kern_return_t result = kernel_list_tests();
	result = kernel_do_post();
	if (result != KERN_SUCCESS) {
		panic("kernel_do_post: Tests failed with result = 0x%08x", result);
	}
	kernel_bootstrap_log("kernel_do_post - done");
#endif /* CONFIG_XNUPOST */

#ifdef  IOKIT
	kernel_bootstrap_log("PE_lockdown_iokit");
	PE_lockdown_iokit();
#endif
	/*
	 * max_cpus must be nailed down by the time PE_lockdown_iokit() finishes,
	 * at the latest
	 */
	vm_set_restrictions(machine_info.max_cpus);


#if KPERF
	kperf_init_early();
#endif

	/*
	 *	Start the user bootstrap.
	 */
#ifdef  MACH_BSD
	bsd_init();
#endif


	/*
	 * Get rid of pages used for early boot tracing.
	 */
	kdebug_free_early_buf();

	serial_keyboard_init();         /* Start serial keyboard if wanted */

	vm_page_init_local_q(machine_info.max_cpus);

	thread_bind(PROCESSOR_NULL);

	/*
	 * Now that all CPUs are available to run threads, this is essentially
	 * a background thread. Take this opportunity to initialize and free
	 * any remaining vm_pages that were delayed earlier by pmap_startup().
	 */
	vm_free_delayed_pages();

	/*
	 *	Become the pageout daemon.
	 */
	vm_pageout();
	/*NOTREACHED*/
}

/*
 *	slave_main:
 *
 *	Load the first thread to start a processor.
 *	This path will also be used by the master processor
 *	after being offlined.
 */
void
slave_main(void *machine_param)
{
	processor_t             processor = current_processor();
	thread_t                thread;

	/*
	 *	Use the idle processor thread if there
	 *	is no dedicated start up thread.
	 */
	if (processor->processor_offlined == true) {
		/* Return to the saved processor_offline context */
		assert(processor->startup_thread == THREAD_NULL);

		thread = processor->idle_thread;
		thread->parameter = machine_param;
	} else if (processor->startup_thread) {
		thread = processor->startup_thread;
		processor->startup_thread = THREAD_NULL;
	} else {
		thread = processor->idle_thread;
		thread->continuation = processor_start_thread;
		thread->parameter = machine_param;
	}

	load_context(thread);
	/*NOTREACHED*/
}

/*
 *	processor_start_thread:
 *
 *	First thread to execute on a started processor.
 *
 *	Called at splsched.
 */
void
processor_start_thread(void *machine_param,
    __unused wait_result_t result)
{
	processor_t             processor = current_processor();
	thread_t                self = current_thread();

	slave_machine_init(machine_param);

	/*
	 *	If running the idle processor thread,
	 *	reenter the idle loop, else terminate.
	 */
	if (self == processor->idle_thread) {
		thread_block(idle_thread);
	}

	thread_terminate(self);
	/*NOTREACHED*/
}

/*
 *	load_context:
 *
 *	Start the first thread on a processor.
 *	This may be the first thread ever run on a processor, or
 *	it could be a processor that was previously offlined.
 */
static void __attribute__((noreturn))
load_context(
	thread_t                thread)
{
	processor_t             processor = current_processor();


#define load_context_kprintf(x...) /* kprintf("load_context: " x) */

	load_context_kprintf("machine_set_current_thread\n");
	machine_set_current_thread(thread);

	load_context_kprintf("processor_up\n");

	PMAP_ACTIVATE_KERNEL(processor->cpu_id);

	/*
	 * Acquire a stack if none attached.  The panic
	 * should never occur since the thread is expected
	 * to have reserved stack.
	 */
	load_context_kprintf("thread %p, stack %lx, stackptr %lx\n", thread,
	    thread->kernel_stack, thread->machine.kstackptr);
	if (!thread->kernel_stack) {
		load_context_kprintf("stack_alloc_try\n");
		if (!stack_alloc_try(thread)) {
			panic("load_context");
		}
	}

	/*
	 * The idle processor threads are not counted as
	 * running for load calculations.
	 */
	if (!(thread->state & TH_IDLE)) {
		SCHED(run_count_incr)(thread);
	}

	processor->active_thread = thread;
	processor_state_update_explicit(processor, thread->sched_pri,
	    SFI_CLASS_KERNEL, PSET_SMP, thread_get_perfcontrol_class(thread), THREAD_URGENCY_NONE,
	    ((thread->state & TH_IDLE) || (thread->bound_processor != PROCESSOR_NULL)) ? TH_BUCKET_SCHED_MAX : thread->th_sched_bucket);
	processor->current_is_bound = thread->bound_processor != PROCESSOR_NULL;
	processor->current_is_NO_SMT = false;
	processor->current_is_eagerpreempt = false;
#if CONFIG_THREAD_GROUPS
	processor->current_thread_group = thread_group_get(thread);
#endif
	processor->starting_pri = thread->sched_pri;
	processor->deadline = UINT64_MAX;
	thread->last_processor = processor;
	processor_up(processor);
	struct recount_snap snap = { 0 };
	recount_snapshot(&snap);
	processor->last_dispatch = snap.rsn_time_mach;
	recount_processor_run(&processor->pr_recount, &snap);
	recount_update_snap(&snap);

	smr_cpu_join(processor, processor->last_dispatch);

	PMAP_ACTIVATE_USER(thread, processor->cpu_id);

	load_context_kprintf("machine_load_context\n");

#if KASAN_TBI
	__asan_handle_no_return();
#endif /* KASAN_TBI */

	machine_load_context(thread);
	/*NOTREACHED*/
}

void
scale_setup(void)
{
	int scale = 0;
#if defined(__LP64__)
	typeof(task_max) task_max_base = task_max;

	/* Raise limits for servers with >= 16G */
	if ((serverperfmode != 0) && ((uint64_t)max_mem_actual >= (uint64_t)(16 * 1024 * 1024 * 1024ULL))) {
		scale = (int)((uint64_t)sane_size / (uint64_t)(8 * 1024 * 1024 * 1024ULL));
		/* limit to 128 G */
		if (scale > 16) {
			scale = 16;
		}
		task_max_base = 2500;
		/* Raise limits for machines with >= 3GB */
	} else if ((uint64_t)max_mem_actual >= (uint64_t)(3 * 1024 * 1024 * 1024ULL)) {
		if ((uint64_t)max_mem_actual < (uint64_t)(8 * 1024 * 1024 * 1024ULL)) {
			scale = 2;
		} else {
			/* limit to 64GB */
			scale = MIN(16, (int)((uint64_t)max_mem_actual / (uint64_t)(4 * 1024 * 1024 * 1024ULL)));
		}
	}

	task_max = MAX(task_max, task_max_base * scale);

	if (scale != 0) {
		task_threadmax = task_max;
		thread_max = task_max * 5;
	}

#endif

	bsd_scale_setup(scale);
}
