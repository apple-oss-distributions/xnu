/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
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

#include <debug.h>
#include <mach_ldebug.h>
#include <mach_kdp.h>

#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/timer_queue.h>
#include <kern/processor.h>
#include <kern/startup.h>
#include <kern/debug.h>
#include <prng/random.h>
#include <kern/ecc.h>
#include <machine/machine_routines.h>
#include <machine/commpage.h>
#if HIBERNATION
#include <machine/pal_hibernate.h>
#endif /* HIBERNATION */
/* ARM64_TODO unify boot.h */
#if __arm64__
#include <pexpert/arm64/apple_arm64_common.h>
#include <pexpert/arm64/boot.h>
#else
#error Unsupported arch
#endif
#include <pexpert/arm/consistent_debug.h>
#include <pexpert/device_tree.h>
#include <arm64/proc_reg.h>
#include <arm/pmap.h>
#include <arm/caches_internal.h>
#include <arm/cpu_internal.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpuid_internal.h>
#include <arm/misc_protos.h>
#include <arm/machine_cpu.h>
#include <arm/rtclock.h>
#include <vm/vm_map.h>

#include <libkern/kernel_mach_header.h>
#include <libkern/stack_protector.h>
#include <libkern/section_keywords.h>
#include <san/kasan.h>
#include <sys/kdebug.h>

#include <pexpert/pexpert.h>

#include <console/serial_protos.h>

#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif
#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

#if KPERF
#include <kperf/kptimer.h>
#endif /* KPERF */

#if HIBERNATION
#include <IOKit/IOPlatformExpert.h>
#endif /* HIBERNATION */

extern void     patch_low_glo(void);
extern int      serial_init(void);
extern void sleep_token_buffer_init(void);

extern vm_offset_t intstack_top;
#if __arm64__
extern vm_offset_t excepstack_top;
#endif

extern const char version[];
extern const char version_variant[];
extern int      disableConsoleOutput;

int             pc_trace_buf[PC_TRACE_BUF_SIZE] = {0};
int             pc_trace_cnt = PC_TRACE_BUF_SIZE;
int             debug_task;

SECURITY_READ_ONLY_LATE(bool) static_kernelcache = false;

#if HAS_BP_RET
/* Enable both branch target retention (0x2) and branch direction retention (0x1) across sleep */
uint32_t bp_ret = 3;
extern void set_bp_ret(void);
#endif

#if SCHED_HYGIENE_DEBUG
boolean_t sched_hygiene_debug_pmc = 1;
#endif

#if SCHED_HYGIENE_DEBUG
TUNABLE_DT_WRITEABLE(sched_hygiene_mode_t, interrupt_masked_debug_mode,
    "machine-timeouts", "interrupt-masked-debug-mode",
    "interrupt-masked-debug-mode",
    SCHED_HYGIENE_MODE_PANIC,
    TUNABLE_DT_CHECK_CHOSEN);

MACHINE_TIMEOUT_WRITEABLE(interrupt_masked_timeout, "interrupt-masked",
    0xd0000, MACHINE_TIMEOUT_UNIT_TIMEBASE,  /* 35.499ms */
    NULL);
#if __arm64__
#define SSHOT_INTERRUPT_MASKED_TIMEOUT 0xf9999 /* 64-bit: 42.599ms */
#endif
MACHINE_TIMEOUT_WRITEABLE(stackshot_interrupt_masked_timeout, "sshot-interrupt-masked",
    SSHOT_INTERRUPT_MASKED_TIMEOUT, MACHINE_TIMEOUT_UNIT_TIMEBASE,
    NULL);
#undef SSHOT_INTERRUPT_MASKED_TIMEOUT
#endif

/*
 * A 6-second timeout will give the watchdog code a chance to run
 * before a panic is triggered by the xcall routine.
 */
#define XCALL_ACK_TIMEOUT_NS ((uint64_t) 6000000000)
uint64_t xcall_ack_timeout_abstime;

boot_args const_boot_args __attribute__((section("__DATA, __const")));
boot_args      *BootArgs __attribute__((section("__DATA, __const")));

TUNABLE(uint32_t, arm_diag, "diag", 0);
#ifdef  APPLETYPHOON
static unsigned cpus_defeatures = 0x0;
extern void cpu_defeatures_set(unsigned int);
#endif

#if __arm64__ && __ARM_GLOBAL_SLEEP_BIT__
extern volatile boolean_t arm64_stall_sleep;
#endif

extern boolean_t force_immediate_debug_halt;

#if HAS_APPLE_PAC
SECURITY_READ_ONLY_LATE(boolean_t) diversify_user_jop = TRUE;
#endif

SECURITY_READ_ONLY_LATE(uint64_t) gDramBase;
SECURITY_READ_ONLY_LATE(uint64_t) gDramSize;

SECURITY_READ_ONLY_LATE(bool) serial_console_enabled = false;
#ifdef XNU_ENABLE_PROCESSOR_EXIT
SECURITY_READ_ONLY_LATE(bool) enable_processor_exit = true;
#else
SECURITY_READ_ONLY_LATE(bool) enable_processor_exit = false;
#endif

/*
 * Forward definition
 */
void arm_init(boot_args * args);

#if __arm64__
unsigned int page_shift_user32; /* for page_size as seen by a 32-bit task */

extern void configure_misc_apple_boot_args(void);
extern void configure_misc_apple_regs(void);
extern void configure_timer_apple_regs(void);
#endif /* __arm64__ */


/*
 * JOP rebasing
 */

#define dyldLogFunc(msg, ...)
#include <mach/dyld_kernel_fixups.h>

extern uint32_t __thread_starts_sect_start[] __asm("section$start$__TEXT$__thread_starts");
extern uint32_t __thread_starts_sect_end[]   __asm("section$end$__TEXT$__thread_starts");
#if defined(HAS_APPLE_PAC)
extern void OSRuntimeSignStructors(kernel_mach_header_t * header);
extern void OSRuntimeSignStructorsInFileset(kernel_mach_header_t * header);
#endif /* defined(HAS_APPLE_PAC) */

extern vm_offset_t vm_kernel_slide;
extern vm_offset_t segLOWESTKC, segHIGHESTKC, segLOWESTROKC, segHIGHESTROKC;
extern vm_offset_t segLOWESTAuxKC, segHIGHESTAuxKC, segLOWESTROAuxKC, segHIGHESTROAuxKC;
extern vm_offset_t segLOWESTRXAuxKC, segHIGHESTRXAuxKC, segHIGHESTNLEAuxKC;

static void
arm_slide_rebase_and_sign_image(void)
{
	kernel_mach_header_t *k_mh, *kc_mh = NULL;
	kernel_segment_command_t *seg;
	uintptr_t slide;

	k_mh = &_mh_execute_header;
	if (kernel_mach_header_is_in_fileset(k_mh)) {
		/*
		 * The kernel is part of a MH_FILESET kernel collection, determine slide
		 * based on first segment's mach-o vmaddr (requires first kernel load
		 * command to be LC_SEGMENT_64 of the __TEXT segment)
		 */
		seg = (kernel_segment_command_t *)((uintptr_t)k_mh + sizeof(*k_mh));
		assert(seg->cmd == LC_SEGMENT_KERNEL);
		slide = (uintptr_t)k_mh - seg->vmaddr;

		/*
		 * The kernel collection linker guarantees that the boot collection mach
		 * header vmaddr is the hardcoded kernel link address (as specified to
		 * ld64 when linking the kernel).
		 */
		kc_mh = (kernel_mach_header_t*)(VM_KERNEL_LINK_ADDRESS + slide);
		assert(kc_mh->filetype == MH_FILESET);

		/*
		 * rebase and sign jops
		 * Note that we can't call any functions before this point, so
		 * we have to hard-code the knowledge that the base of the KC
		 * is the KC's mach-o header. This would change if any
		 * segment's VA started *before* the text segment
		 * (as the HIB segment does on x86).
		 */
		const void *collection_base_pointers[KCNumKinds] = {[0] = kc_mh, };
		kernel_collection_slide((struct mach_header_64 *)kc_mh, collection_base_pointers);

		PE_set_kc_header(KCKindPrimary, kc_mh, slide);

		/*
		 * iBoot doesn't slide load command vmaddrs in an MH_FILESET kernel
		 * collection, so adjust them now, and determine the vmaddr range
		 * covered by read-only segments for the CTRR rorgn.
		 */
		kernel_collection_adjust_mh_addrs((struct mach_header_64 *)kc_mh, slide, false,
		    (uintptr_t *)&segLOWESTKC, (uintptr_t *)&segHIGHESTKC,
		    (uintptr_t *)&segLOWESTROKC, (uintptr_t *)&segHIGHESTROKC,
		    NULL, NULL, NULL);
#if defined(HAS_APPLE_PAC)
		OSRuntimeSignStructorsInFileset(kc_mh);
#endif /* defined(HAS_APPLE_PAC) */
	} else {
		/*
		 * Static kernelcache: iBoot slid kernel MachO vmaddrs, determine slide
		 * using hardcoded kernel link address
		 */
		slide = (uintptr_t)k_mh - VM_KERNEL_LINK_ADDRESS;

		/* rebase and sign jops */
		static_kernelcache = &__thread_starts_sect_end[0] != &__thread_starts_sect_start[0];
		if (static_kernelcache) {
			rebase_threaded_starts( &__thread_starts_sect_start[0],
			    &__thread_starts_sect_end[0],
			    (uintptr_t)k_mh, (uintptr_t)k_mh - slide, slide);
		}
#if defined(HAS_APPLE_PAC)
		OSRuntimeSignStructors(&_mh_execute_header);
#endif /* defined(HAS_APPLE_PAC) */
	}


	/*
	 * Initialize slide global here to avoid duplicating this logic in
	 * arm_vm_init()
	 */
	vm_kernel_slide = slide;
}

void
arm_auxkc_init(void *mh, void *base)
{
	/*
	 * The kernel collection linker guarantees that the lowest vmaddr in an
	 * AuxKC collection is 0 (but note that the mach header is higher up since
	 * RW segments precede RO segments in the AuxKC).
	 */
	uintptr_t slide = (uintptr_t)base;
	kernel_mach_header_t *akc_mh = (kernel_mach_header_t*)mh;

	assert(akc_mh->filetype == MH_FILESET);
	PE_set_kc_header_and_base(KCKindAuxiliary, akc_mh, base, slide);

	/* rebase and sign jops */
	const void *collection_base_pointers[KCNumKinds];
	memcpy(collection_base_pointers, PE_get_kc_base_pointers(), sizeof(collection_base_pointers));
	kernel_collection_slide((struct mach_header_64 *)akc_mh, collection_base_pointers);

	kernel_collection_adjust_mh_addrs((struct mach_header_64 *)akc_mh, slide, false,
	    (uintptr_t *)&segLOWESTAuxKC, (uintptr_t *)&segHIGHESTAuxKC, (uintptr_t *)&segLOWESTROAuxKC,
	    (uintptr_t *)&segHIGHESTROAuxKC, (uintptr_t *)&segLOWESTRXAuxKC, (uintptr_t *)&segHIGHESTRXAuxKC,
	    (uintptr_t *)&segHIGHESTNLEAuxKC);
#if defined(HAS_APPLE_PAC)
	OSRuntimeSignStructorsInFileset(akc_mh);
#endif /* defined(HAS_APPLE_PAC) */
}

/*
 *	Routine:	arm_setup_pre_sign
 *	Function:	Perform HW initialization that must happen ahead of the first PAC sign
 *			operation.
 */
static void
arm_setup_pre_sign(void)
{
#if __arm64__
	/* DATA TBI, if enabled, affects the number of VA bits that contain the signature */
	arm_set_kernel_tbi();
#endif /* __arm64 */
}

/*
 *		Routine:		arm_init
 *		Function:		Runs on the boot CPU, once, on entry from iBoot.
 */

__startup_func
void
arm_init(
	boot_args       *args)
{
	unsigned int    maxmem;
	uint32_t        memsize;
	uint64_t        xmaxmem;
	thread_t        thread;
	DTEntry chosen = NULL;
	unsigned int dt_entry_size = 0;

	arm_setup_pre_sign();

	arm_slide_rebase_and_sign_image();

	/* If kernel integrity is supported, use a constant copy of the boot args. */
	const_boot_args = *args;
	BootArgs = args = &const_boot_args;

	cpu_data_init(&BootCpuData);
#if defined(HAS_APPLE_PAC)
	/* bootstrap cpu process dependent key for kernel has been loaded by start.s */
	BootCpuData.rop_key = ml_default_rop_pid();
	BootCpuData.jop_key = ml_default_jop_pid();
#endif /* defined(HAS_APPLE_PAC) */

	PE_init_platform(FALSE, args); /* Get platform expert set up */

#if __arm64__
	configure_timer_apple_regs();
	wfe_timeout_configure();
	wfe_timeout_init();

	configure_misc_apple_boot_args();
	configure_misc_apple_regs();

#if (DEVELOPMENT || DEBUG)
	unsigned long const *platform_stall_ptr = NULL;

	if (SecureDTLookupEntry(NULL, "/chosen", &chosen) != kSuccess) {
		panic("%s: Unable to find 'chosen' DT node", __FUNCTION__);
	}

	// Not usable TUNABLE here because TUNABLEs are parsed at a later point.
	if (SecureDTGetProperty(chosen, "xnu_platform_stall", (void const **)&platform_stall_ptr,
	    &dt_entry_size) == kSuccess) {
		xnu_platform_stall_value = *platform_stall_ptr;
	}

	platform_stall_panic_or_spin(PLATFORM_STALL_XNU_LOCATION_ARM_INIT);

	chosen = NULL; // Force a re-lookup later on since VM addresses are not final at this point
	dt_entry_size = 0;
#endif


	{
		/*
		 * Select the advertised kernel page size.
		 */
		if (args->memSize > 1ULL * 1024 * 1024 * 1024) {
			/*
			 * arm64 device with > 1GB of RAM:
			 * kernel uses 16KB pages.
			 */
			PAGE_SHIFT_CONST = PAGE_MAX_SHIFT;
		} else {
			/*
			 * arm64 device with <= 1GB of RAM:
			 * kernel uses hardware page size
			 * (4KB for H6/H7, 16KB for H8+).
			 */
			PAGE_SHIFT_CONST = ARM_PGSHIFT;
		}

		/* 32-bit apps always see 16KB page size */
		page_shift_user32 = PAGE_MAX_SHIFT;
#ifdef  APPLETYPHOON
		if (PE_parse_boot_argn("cpus_defeatures", &cpus_defeatures, sizeof(cpus_defeatures))) {
			if ((cpus_defeatures & 0xF) != 0) {
				cpu_defeatures_set(cpus_defeatures & 0xF);
			}
		}
#endif
	}
#endif

	ml_parse_cpu_topology();


	master_cpu = ml_get_boot_cpu_number();
	assert(master_cpu >= 0 && master_cpu <= ml_get_max_cpu_number());

	BootCpuData.cpu_number = (unsigned short)master_cpu;
	BootCpuData.intstack_top = (vm_offset_t) &intstack_top;
	BootCpuData.istackptr = BootCpuData.intstack_top;
#if __arm64__
	BootCpuData.excepstack_top = (vm_offset_t) &excepstack_top;
	BootCpuData.excepstackptr = BootCpuData.excepstack_top;
#endif
	CpuDataEntries[master_cpu].cpu_data_vaddr = &BootCpuData;
	CpuDataEntries[master_cpu].cpu_data_paddr = (void *)((uintptr_t)(args->physBase)
	    + ((uintptr_t)&BootCpuData
	    - (uintptr_t)(args->virtBase)));

	thread = thread_bootstrap();
	thread->machine.CpuDatap = &BootCpuData;
	thread->machine.pcpu_data_base = (vm_offset_t)0;
	machine_set_current_thread(thread);

	/*
	 * Preemption is enabled for this thread so that it can lock mutexes without
	 * tripping the preemption check. In reality scheduling is not enabled until
	 * this thread completes, and there are no other threads to switch to, so
	 * preemption level is not really meaningful for the bootstrap thread.
	 */
	thread->machine.preemption_count = 0;
	cpu_bootstrap();

	rtclock_early_init();

	kernel_debug_string_early("kernel_startup_bootstrap");
	kernel_startup_bootstrap();

	/*
	 * Initialize the timer callout world
	 */
	timer_call_init();

	cpu_init();

	processor_bootstrap();

	if (PE_parse_boot_argn("maxmem", &maxmem, sizeof(maxmem))) {
		xmaxmem = (uint64_t) maxmem * (1024 * 1024);
	} else if (PE_get_default("hw.memsize", &memsize, sizeof(memsize))) {
		xmaxmem = (uint64_t) memsize;
	} else {
		xmaxmem = 0;
	}

#if SCHED_HYGIENE_DEBUG
	{
		int wdt_boot_arg = 0;
		bool const wdt_disabled = (PE_parse_boot_argn("wdt", &wdt_boot_arg, sizeof(wdt_boot_arg)) && (wdt_boot_arg == -1));

		/* Disable if WDT is disabled */
		if (wdt_disabled || kern_feature_override(KF_INTERRUPT_MASKED_DEBUG_OVRD)) {
			interrupt_masked_debug_mode = SCHED_HYGIENE_MODE_OFF;
		} else if (kern_feature_override(KF_SCHED_HYGIENE_DEBUG_PMC_OVRD)) {
			/*
			 * The sched hygiene facility can, in adition to checking time, capture
			 * metrics provided by the cycle and instruction counters available in some
			 * systems. Check if we should enable this feature based on the validation
			 * overrides.
			 */
			sched_hygiene_debug_pmc = 0;
		}

		if (wdt_disabled) {
			sched_preemption_disable_debug_mode = SCHED_HYGIENE_MODE_OFF;
		}
	}
#endif /* SCHED_HYGIENE_DEBUG */

	nanoseconds_to_absolutetime(XCALL_ACK_TIMEOUT_NS, &xcall_ack_timeout_abstime);

#if HAS_BP_RET
	PE_parse_boot_argn("bpret", &bp_ret, sizeof(bp_ret));
	set_bp_ret(); // Apply branch predictor retention settings to boot CPU
#endif

	PE_parse_boot_argn("immediate_NMI", &force_immediate_debug_halt, sizeof(force_immediate_debug_halt));

#if __ARM_PAN_AVAILABLE__
	__builtin_arm_wsr("pan", 1);
#endif  /* __ARM_PAN_AVAILABLE__ */

	arm_vm_init(xmaxmem, args);

	if (debug_boot_arg) {
		patch_low_glo();
	}

#if __arm64__ && WITH_CLASSIC_S2R
	sleep_token_buffer_init();
#endif

	PE_consistent_debug_inherit();

	/* Setup debugging output. */
	const unsigned int serial_exists = serial_init();
	kernel_startup_initialize_upto(STARTUP_SUB_KPRINTF);
	kprintf("kprintf initialized\n");

	serialmode = 0;
	if (PE_parse_boot_argn("serial", &serialmode, sizeof(serialmode))) {
		/* Do we want a serial keyboard and/or console? */
		kprintf("Serial mode specified: %08X\n", serialmode);
		disable_iolog_serial_output = (serialmode & SERIALMODE_NO_IOLOG) != 0;
		enable_dklog_serial_output = (serialmode & SERIALMODE_DKLOG) != 0;
		int force_sync = serialmode & SERIALMODE_SYNCDRAIN;
		if (force_sync || PE_parse_boot_argn("drain_uart_sync", &force_sync, sizeof(force_sync))) {
			if (force_sync) {
				serialmode |= SERIALMODE_SYNCDRAIN;
				kprintf(
					"WARNING: Forcing uart driver to output synchronously."
					"printf()s/IOLogs will impact kernel performance.\n"
					"You are advised to avoid using 'drain_uart_sync' boot-arg.\n");
			}
		}
	}
	if (kern_feature_override(KF_SERIAL_OVRD)) {
		serialmode = 0;
	}

	/* Start serial if requested and a serial device was enumerated in serial_init(). */
	if ((serialmode & SERIALMODE_OUTPUT) && serial_exists) {
		serial_console_enabled = true;
		(void)switch_to_serial_console(); /* Switch into serial mode from video console */
		disableConsoleOutput = FALSE;     /* Allow printfs to happen */
	}
	PE_create_console();

	/* setup console output */
	PE_init_printf(FALSE);

#if __arm64__
#if DEBUG
	dump_kva_space();
#endif
#endif

	cpu_machine_idle_init(TRUE);

	PE_init_platform(TRUE, &BootCpuData);

#if __arm64__
	extern bool cpu_config_correct;
	if (!cpu_config_correct) {
		panic("The cpumask=N boot arg cannot be used together with cpus=N, and the boot CPU must be enabled");
	}

	ml_map_cpu_pio();
#endif

	cpu_timebase_init(TRUE);

#if KPERF
	/* kptimer_curcpu_up() must be called after cpu_timebase_init */
	kptimer_curcpu_up();
#endif /* KPERF */

	PE_init_cpu();
	fiq_context_init(TRUE);


#if HIBERNATION
	pal_hib_init();
#endif /* HIBERNATION */

	/*
	 * gPhysBase/Size only represent kernel-managed memory. These globals represent
	 * the actual DRAM base address and size as reported by iBoot through the
	 * device tree.
	 */
	unsigned long const *dram_base;
	unsigned long const *dram_size;

	if (SecureDTLookupEntry(NULL, "/chosen", &chosen) != kSuccess) {
		panic("%s: Unable to find 'chosen' DT node", __FUNCTION__);
	}

	if (SecureDTGetProperty(chosen, "dram-base", (void const **)&dram_base, &dt_entry_size) != kSuccess) {
		panic("%s: Unable to find 'dram-base' entry in the 'chosen' DT node", __FUNCTION__);
	}

	if (SecureDTGetProperty(chosen, "dram-size", (void const **)&dram_size, &dt_entry_size) != kSuccess) {
		panic("%s: Unable to find 'dram-size' entry in the 'chosen' DT node", __FUNCTION__);
	}

	gDramBase = *dram_base;
	gDramSize = *dram_size;

	/*
	 * Initialize the stack protector for all future calls
	 * to C code. Since kernel_bootstrap() eventually
	 * switches stack context without returning through this
	 * function, we do not risk failing the check even though
	 * we mutate the guard word during execution.
	 */
	__stack_chk_guard = (unsigned long)early_random();
	/* Zero a byte of the protector to guard
	 * against string vulnerabilities
	 */
	__stack_chk_guard &= ~(0xFFULL << 8);
	machine_startup(args);
}

/*
 * Routine:        arm_init_cpu
 * Function:
 *    Runs on S2R resume (all CPUs) and SMP boot (non-boot CPUs only).
 */

void
arm_init_cpu(
	cpu_data_t      *cpu_data_ptr)
{
#if __ARM_PAN_AVAILABLE__
	__builtin_arm_wsr("pan", 1);
#endif

#ifdef __arm64__
	configure_timer_apple_regs();
	configure_misc_apple_regs();
#endif

	cpu_data_ptr->cpu_flags &= ~SleepState;


	machine_set_current_thread(cpu_data_ptr->cpu_active_thread);

#if HIBERNATION
	if ((cpu_data_ptr == &BootCpuData) && (gIOHibernateState == kIOHibernateStateWakingFromHibernate)) {
		// the "normal" S2R code captures wake_abstime too early, so on a hibernation resume we fix it up here
		extern uint64_t wake_abstime;
		wake_abstime = gIOHibernateCurrentHeader->lastHibAbsTime;

		// since the hw clock stops ticking across hibernation, we need to apply an offset;
		// iBoot computes this offset for us and passes it via the hibernation header
		extern uint64_t hwclock_conttime_offset;
		hwclock_conttime_offset = gIOHibernateCurrentHeader->hwClockOffset;

		// during hibernation, we captured the idle thread's state from inside the PPL context, so we have to
		// fix up its preemption count
		unsigned int expected_preemption_count = (gEnforcePlatformActionSafety ? 2 : 1);
		if (cpu_data_ptr->cpu_active_thread->machine.preemption_count != expected_preemption_count) {
			panic("unexpected preemption count %u on boot cpu thread (should be %u)",
			    cpu_data_ptr->cpu_active_thread->machine.preemption_count,
			    expected_preemption_count);
		}
		cpu_data_ptr->cpu_active_thread->machine.preemption_count--;
	}
#endif /* HIBERNATION */

#if __arm64__
	wfe_timeout_init();
	pmap_clear_user_ttb();
	flush_mmu_tlb();
#endif

	cpu_machine_idle_init(FALSE);

	cpu_init();

#ifdef  APPLETYPHOON
	if ((cpus_defeatures & (0xF << 4 * cpu_data_ptr->cpu_number)) != 0) {
		cpu_defeatures_set((cpus_defeatures >> 4 * cpu_data_ptr->cpu_number) & 0xF);
	}
#endif
	/* Initialize the timebase before serial_init, as some serial
	 * drivers use mach_absolute_time() to implement rate control
	 */
	cpu_timebase_init(FALSE);

#if KPERF
	/* kptimer_curcpu_up() must be called after cpu_timebase_init */
	kptimer_curcpu_up();
#endif /* KPERF */

	if (cpu_data_ptr == &BootCpuData) {
#if __arm64__ && __ARM_GLOBAL_SLEEP_BIT__
		/*
		 * Prevent CPUs from going into deep sleep until all
		 * CPUs are ready to do so.
		 */
		arm64_stall_sleep = TRUE;
#endif
		serial_init();
		PE_init_platform(TRUE, NULL);
		commpage_update_timebase();
	}
	PE_init_cpu();

	fiq_context_init(TRUE);
	cpu_data_ptr->rtcPop = EndOfAllTime;
	timer_resync_deadlines();

	processor_t processor = PERCPU_GET_RELATIVE(processor, cpu_data, cpu_data_ptr);
	bool should_kprintf = processor_should_kprintf(processor, true);

#if DEVELOPMENT || DEBUG
	PE_arm_debug_enable_trace(should_kprintf);
#endif /* DEVELOPMENT || DEBUG */


	if (should_kprintf) {
		kprintf("arm_cpu_init(): cpu %d online\n", cpu_data_ptr->cpu_number);
	}

	if (cpu_data_ptr == &BootCpuData) {
		if (kdebug_enable == 0) {
			__kdebug_only uint64_t elapsed = kdebug_wake();
			KDBG(IOKDBG_CODE(DBG_HIBERNATE, 15), mach_absolute_time() - elapsed);
		}

#if CONFIG_TELEMETRY
		bootprofile_wake_from_sleep();
#endif /* CONFIG_TELEMETRY */
	}
#if MONOTONIC && defined(__arm64__)
	mt_wake_per_core();
#endif /* MONOTONIC && defined(__arm64__) */

#if defined(KERNEL_INTEGRITY_CTRR)
	if (ctrr_cluster_locked[cpu_data_ptr->cpu_cluster_id] != CTRR_LOCKED) {
		lck_spin_lock(&ctrr_cpu_start_lck);
		ctrr_cluster_locked[cpu_data_ptr->cpu_cluster_id] = CTRR_LOCKED;
		thread_wakeup(&ctrr_cluster_locked[cpu_data_ptr->cpu_cluster_id]);
		lck_spin_unlock(&ctrr_cpu_start_lck);
	}
#endif


	slave_main(NULL);
}

/*
 * Routine:		arm_init_idle_cpu
 * Function:	Resume from non-retention WFI.  Called from the reset vector.
 */
void __attribute__((noreturn))
arm_init_idle_cpu(
	cpu_data_t      *cpu_data_ptr)
{
#if __ARM_PAN_AVAILABLE__
	__builtin_arm_wsr("pan", 1);
#endif

	machine_set_current_thread(cpu_data_ptr->cpu_active_thread);

#if __arm64__
	wfe_timeout_init();
	pmap_clear_user_ttb();
	flush_mmu_tlb();
	/* Enable asynchronous exceptions */
	__builtin_arm_wsr("DAIFClr", DAIFSC_ASYNCF);
#endif

#ifdef  APPLETYPHOON
	if ((cpus_defeatures & (0xF << 4 * cpu_data_ptr->cpu_number)) != 0) {
		cpu_defeatures_set((cpus_defeatures >> 4 * cpu_data_ptr->cpu_number) & 0xF);
	}
#endif

	/*
	 * Update the active debug object to reflect that debug registers have been reset.
	 * This will force any thread with active debug state to resync the debug registers
	 * if it returns to userspace on this CPU.
	 */
	if (cpu_data_ptr->cpu_user_debug != NULL) {
		arm_debug_set(NULL);
	}

	fiq_context_init(FALSE);

	cpu_idle_exit(TRUE);
}
