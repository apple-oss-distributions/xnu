/*
 * Copyright (c) 2007-2020 Apple Inc. All rights reserved.
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

#include <debug.h>
#include <mach_kdp.h>

#include <kern/thread.h>
#include <machine/pmap.h>
#include <device/device_types.h>

#include <mach/vm_param.h>
#include <mach/clock_types.h>
#include <mach/machine.h>
#include <mach/kmod.h>
#include <pexpert/boot.h>
#include <pexpert/pexpert.h>

#include <ptrauth.h>

#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/debug.h>
#include <kern/processor.h>
#include <kdp/kdp_core.h>
#if ALTERNATE_DEBUGGER
#include <arm64/alternate_debugger.h>
#endif
#include <machine/atomic.h>
#include <machine/trap.h>
#include <kern/spl.h>
#include <pexpert/pexpert.h>
#include <kdp/kdp_callout.h>
#include <kdp/kdp_dyld.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_common.h>
#include <uuid/uuid.h>
#include <sys/codesign.h>
#include <sys/time.h>

#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitServer.h>

#include <mach/vm_prot.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <vm/vm_shared_region.h>
#include <mach/time_value.h>
#include <machine/machparam.h>  /* for btop */

#include <console/video_console.h>
#include <console/serial_protos.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>
#include <arm/misc_protos.h>
#include <libkern/OSKextLibPrivate.h>
#include <vm/vm_kern.h>
#include <kern/kern_cdata.h>
#include <kern/ledger.h>


#if DEVELOPMENT || DEBUG
#include <kern/ext_paniclog.h>
#endif

#if CONFIG_EXCLAVES
#include <kern/exclaves_panic.h>
#endif

#if     MACH_KDP
void    kdp_trap(unsigned int, struct arm_saved_state *);
#endif

extern kern_return_t    do_panic_stackshot(void *);
extern void                    kdp_snapshot_preflight(int pid, void * tracebuf,
    uint32_t tracebuf_size, uint64_t flags,
    kcdata_descriptor_t data_p,
    uint64_t since_timestamp, uint32_t pagetable_mask);
extern int              kdp_stack_snapshot_bytes_traced(void);
extern int              kdp_stack_snapshot_bytes_uncompressed(void);

/*
 * Increment the PANICLOG_VERSION if you change the format of the panic
 * log in any way.
 */
#define PANICLOG_VERSION 14
static struct kcdata_descriptor kc_panic_data;

extern char iBoot_version[];
#if defined(TARGET_OS_OSX) && defined(__arm64__)
extern char iBoot_Stage_2_version[];
#endif /* defined(TARGET_OS_OSX) && defined(__arm64__) */

extern volatile uint32_t        debug_enabled;
extern unsigned int         not_in_kdp;

extern int                              copyinframe(vm_address_t fp, uint32_t * frame);
extern void                             kdp_callouts(kdp_event_t event);

/* #include <sys/proc.h> */
#define MAXCOMLEN 16
struct proc;
extern int        proc_pid(struct proc *p);
extern void       proc_name_kdp(struct proc *, char *, int);

/*
 * Make sure there's enough space to include the relevant bits in the format required
 * within the space allocated for the panic version string in the panic header.
 * The format required by OSAnalytics/DumpPanic is 'Product Version (OS Version)'.
 */
#define PANIC_HEADER_VERSION_FMT_STR "%.14s (%.14s)"

extern const char version[];
extern char       osversion[];
extern char       osproductversion[];
extern char       osreleasetype[];

#if defined(XNU_TARGET_OS_BRIDGE)
extern char     macosproductversion[];
extern char     macosversion[];
#endif

extern uint8_t          gPlatformECID[8];
extern uint32_t         gPlatformMemoryID;

extern uint64_t         last_hwaccess_thread;

/*Choosing the size for gTargetTypeBuffer as 16 and size for gModelTypeBuffer as 32
 *  since the target name and model name typically  doesn't exceed this size */
extern char  gTargetTypeBuffer[16];
extern char  gModelTypeBuffer[32];

extern struct timeval    gIOLastSleepTime;
extern struct timeval    gIOLastWakeTime;
extern boolean_t                 is_clock_configured;
extern boolean_t kernelcache_uuid_valid;
extern uuid_t kernelcache_uuid;
extern uuid_string_t bootsessionuuid_string;

extern uint64_t roots_installed;

/* Definitions for frame pointers */
#define FP_ALIGNMENT_MASK      ((uint32_t)(0x3))
#define FP_LR_OFFSET           ((uint32_t)4)
#define FP_LR_OFFSET64         ((uint32_t)8)
#define FP_MAX_NUM_TO_EVALUATE (50)

/* Timeout for all processors responding to debug crosscall */
MACHINE_TIMEOUT(debug_ack_timeout, "debug-ack", 240000, MACHINE_TIMEOUT_UNIT_TIMEBASE, NULL);

/* Forward functions definitions */
void panic_display_times(void);
void panic_print_symbol_name(vm_address_t search);


/* Global variables */
static uint32_t       panic_bt_depth;
boolean_t             PanicInfoSaved = FALSE;
boolean_t             force_immediate_debug_halt = FALSE;
unsigned int          debug_ack_timeout_count = 0;
volatile unsigned int debugger_sync = 0;
volatile unsigned int mp_kdp_trap = 0; /* CPUs signalled by the debug CPU will spin on this */
volatile unsigned int debug_cpus_spinning = 0; /* Number of signalled CPUs still spinning on mp_kdp_trap (in DebuggerXCall). */
unsigned int          DebugContextCount = 0;

#if defined(__arm64__)
uint8_t PE_smc_stashed_x86_system_state = 0xFF;
uint8_t PE_smc_stashed_x86_power_state = 0xFF;
uint8_t PE_smc_stashed_x86_efi_boot_state = 0xFF;
uint8_t PE_smc_stashed_x86_shutdown_cause = 0xFF;
uint64_t PE_smc_stashed_x86_prev_power_transitions = UINT64_MAX;
uint32_t PE_pcie_stashed_link_state = UINT32_MAX;
uint64_t PE_nvram_stashed_x86_macos_slide = UINT64_MAX;
#endif


/*
 * Backtrace a single frame.
 */
static void
print_one_backtrace(pmap_t pmap, vm_offset_t topfp, const char *cur_marker,
    boolean_t is_64_bit, boolean_t print_kexts_in_backtrace)
{
	unsigned int    i = 0;
	addr64_t        lr = 0;
	addr64_t        fp = topfp;
	addr64_t        fp_for_ppn = 0;
	ppnum_t         ppn = (ppnum_t)NULL;
	vm_offset_t     raddrs[FP_MAX_NUM_TO_EVALUATE] = { 0 };
	bool            dump_kernel_stack = (fp >= VM_MIN_KERNEL_ADDRESS);

#if defined(HAS_APPLE_PAC)
	fp = (addr64_t)ptrauth_strip((void *)fp, ptrauth_key_frame_pointer);
#endif
	do {
		if ((fp == 0) || ((fp & FP_ALIGNMENT_MASK) != 0)) {
			break;
		}
		if (dump_kernel_stack && ((fp < VM_MIN_KERNEL_ADDRESS) || (fp > VM_MAX_KERNEL_ADDRESS))) {
			break;
		}
		if ((!dump_kernel_stack) && (fp >= VM_MIN_KERNEL_ADDRESS)) {
			break;
		}

		/*
		 * Check to see if current address will result in a different
		 * ppn than previously computed (to avoid recomputation) via
		 * (addr) ^ fp_for_ppn) >> PAGE_SHIFT)
		 */
		if ((((fp + FP_LR_OFFSET) ^ fp_for_ppn) >> PAGE_SHIFT) != 0x0U) {
			ppn = pmap_find_phys(pmap, fp + FP_LR_OFFSET);
			fp_for_ppn = fp + (is_64_bit ? FP_LR_OFFSET64 : FP_LR_OFFSET);
		}
		if (ppn != (ppnum_t)NULL) {
			if (is_64_bit) {
				lr = ml_phys_read_double_64(((((vm_offset_t)ppn) << PAGE_SHIFT)) | ((fp + FP_LR_OFFSET64) & PAGE_MASK));
#if defined(HAS_APPLE_PAC)
				/* return addresses on stack will be signed by arm64e ABI */
				lr = (addr64_t) ptrauth_strip((void *)lr, ptrauth_key_return_address);
#endif
			} else {
				lr = ml_phys_read_word(((((vm_offset_t)ppn) << PAGE_SHIFT)) | ((fp + FP_LR_OFFSET) & PAGE_MASK));
			}
		} else {
			if (is_64_bit) {
				paniclog_append_noflush("%s\t  Could not read LR from frame at 0x%016llx\n", cur_marker, fp + FP_LR_OFFSET64);
			} else {
				paniclog_append_noflush("%s\t  Could not read LR from frame at 0x%08x\n", cur_marker, (uint32_t)(fp + FP_LR_OFFSET));
			}
			break;
		}
		if (((fp ^ fp_for_ppn) >> PAGE_SHIFT) != 0x0U) {
			ppn = pmap_find_phys(pmap, fp);
			fp_for_ppn = fp;
		}
		if (ppn != (ppnum_t)NULL) {
			if (is_64_bit) {
				fp = ml_phys_read_double_64(((((vm_offset_t)ppn) << PAGE_SHIFT)) | (fp & PAGE_MASK));
#if defined(HAS_APPLE_PAC)
				/* frame pointers on stack will be signed by arm64e ABI */
				fp = (addr64_t) ptrauth_strip((void *)fp, ptrauth_key_frame_pointer);
#endif
			} else {
				fp = ml_phys_read_word(((((vm_offset_t)ppn) << PAGE_SHIFT)) | (fp & PAGE_MASK));
			}
		} else {
			if (is_64_bit) {
				paniclog_append_noflush("%s\t  Could not read FP from frame at 0x%016llx\n", cur_marker, fp);
			} else {
				paniclog_append_noflush("%s\t  Could not read FP from frame at 0x%08x\n", cur_marker, (uint32_t)fp);
			}
			break;
		}
		/*
		 * Counter 'i' may == FP_MAX_NUM_TO_EVALUATE when running one
		 * extra round to check whether we have all frames in order to
		 * indicate (in)complete backtrace below. This happens in a case
		 * where total frame count and FP_MAX_NUM_TO_EVALUATE are equal.
		 * Do not capture anything.
		 */
		if (i < FP_MAX_NUM_TO_EVALUATE && lr) {
			if (is_64_bit) {
				paniclog_append_noflush("%s\t  lr: 0x%016llx  fp: 0x%016llx\n", cur_marker, lr, fp);
			} else {
				paniclog_append_noflush("%s\t  lr: 0x%08x  fp: 0x%08x\n", cur_marker, (uint32_t)lr, (uint32_t)fp);
			}
			raddrs[i] = lr;
		}
	} while ((++i <= FP_MAX_NUM_TO_EVALUATE) && (fp != topfp));

	if (i > FP_MAX_NUM_TO_EVALUATE && fp != 0) {
		paniclog_append_noflush("Backtrace continues...\n");
	}

	if (print_kexts_in_backtrace && i > 0) {
		kmod_panic_dump(&raddrs[0], i);
	}
}

#define SANE_TASK_LIMIT 256
#define TOP_RUNNABLE_LIMIT 5
#define PANICLOG_UUID_BUF_SIZE 256

extern void panic_print_vnodes(void);

static void
panic_display_tpidrs(void)
{
#if defined(__arm64__)
	paniclog_append_noflush("TPIDRx_ELy = {1: 0x%016llx  0: 0x%016llx  0ro: 0x%016llx }\n",
	    __builtin_arm_rsr64("TPIDR_EL1"), __builtin_arm_rsr64("TPIDR_EL0"),
	    __builtin_arm_rsr64("TPIDRRO_EL0"));
#endif //defined(__arm64__)
}

static void
panic_display_hung_cpus_help(void)
{
#if defined(__arm64__)
	const uint32_t pcsr_offset = 0x90;

	/*
	 * Print some info that might help in cases where nothing
	 * else does
	 */
	const ml_topology_info_t *info = ml_get_topology_info();
	if (info) {
		unsigned i, retry;

		for (i = 0; i < info->num_cpus; i++) {
			if (!PE_cpu_power_check_kdp(i)) {
				paniclog_append_noflush("CORE %u is offline, skipping\n", i);
				continue;
			}
			if (info->cpus[i].cpu_UTTDBG_regs) {
				volatile uint64_t *pcsr = (volatile uint64_t*)(info->cpus[i].cpu_UTTDBG_regs + pcsr_offset);
				volatile uint32_t *pcsrTrigger = (volatile uint32_t*)pcsr;
				uint64_t pc = 0;

				// a number of retries are needed till this works
				for (retry = 1024; retry && !pc; retry--) {
					//a 32-bit read is required to make a PC sample be produced, else we'll only get a zero
					(void)*pcsrTrigger;
					pc = *pcsr;
				}

				//postprocessing (same as astris does)
				if (pc >> 48) {
					pc |= 0xffff000000000000ull;
				}
				paniclog_append_noflush("CORE %u recently retired instr at 0x%016llx\n", i, pc);
			}
		}
	}
#endif //defined(__arm64__)
}


static void
panic_display_pvhs_locked(void)
{
}

static void
panic_display_pvh_to_lock(void)
{
}

static void
panic_display_last_pc_lr(void)
{
#if defined(__arm64__)
	const int max_cpu = ml_get_max_cpu_number();

	for (int cpu = 0; cpu <= max_cpu; cpu++) {
		cpu_data_t *current_cpu_datap = cpu_datap(cpu);

		if (current_cpu_datap == NULL) {
			continue;
		}

		if (current_cpu_datap == getCpuDatap()) {
			/**
			 * Skip printing the PC/LR if this is the CPU
			 * that initiated the panic.
			 */
			paniclog_append_noflush("CORE %u is the one that panicked. Check the full backtrace for details.\n", cpu);
			continue;
		}

		paniclog_append_noflush("CORE %u: PC=0x%016llx, LR=0x%016llx, FP=0x%016llx\n", cpu,
		    current_cpu_datap->ipi_pc, (uint64_t)VM_KERNEL_STRIP_PTR(current_cpu_datap->ipi_lr),
		    (uint64_t)VM_KERNEL_STRIP_PTR(current_cpu_datap->ipi_fp));
	}
#endif
}

static void
do_print_all_backtraces(const char *message, uint64_t panic_options)
{
	int             logversion = PANICLOG_VERSION;
	thread_t        cur_thread = current_thread();
	uintptr_t       cur_fp;
	task_t          task;
	struct proc    *proc;
	int             print_vnodes = 0;
	const char *nohilite_thread_marker = "\t";

	/* end_marker_bytes set to 200 for printing END marker + stackshot summary info always */
	int bytes_traced = 0, bytes_remaining = 0, end_marker_bytes = 200;
	int bytes_uncompressed = 0;
	uint64_t bytes_used = 0ULL;
	int err = 0;
	char *stackshot_begin_loc = NULL;
	kc_format_t kc_format;
	bool filesetKC = false;
#if CONFIG_EXT_PANICLOG
	uint32_t ext_paniclog_bytes = 0;
#endif

#if defined(__arm64__)
	__asm__         volatile ("add %0, xzr, fp":"=r"(cur_fp));
#else
#error Unknown architecture.
#endif
	if (panic_bt_depth != 0) {
		return;
	}
	panic_bt_depth++;

	__unused bool result = PE_get_primary_kc_format(&kc_format);
	assert(result == true);
	filesetKC = kc_format == KCFormatFileset;

	/* Truncate panic string to 1200 bytes */
	paniclog_append_noflush("Debugger message: %.1200s\n", message);
	if (debug_enabled) {
		paniclog_append_noflush("Device: %s\n",
		    ('\0' != gTargetTypeBuffer[0]) ? gTargetTypeBuffer : "Not set yet");
		paniclog_append_noflush("Hardware Model: %s\n",
		    ('\0' != gModelTypeBuffer[0]) ? gModelTypeBuffer:"Not set yet");
		paniclog_append_noflush("ECID: %02X%02X%02X%02X%02X%02X%02X%02X\n", gPlatformECID[7],
		    gPlatformECID[6], gPlatformECID[5], gPlatformECID[4], gPlatformECID[3],
		    gPlatformECID[2], gPlatformECID[1], gPlatformECID[0]);
		if (last_hwaccess_thread) {
			paniclog_append_noflush("AppleHWAccess Thread: 0x%llx\n", last_hwaccess_thread);
		}
		paniclog_append_noflush("Boot args: %s\n", PE_boot_args());
	}
	paniclog_append_noflush("Memory ID: 0x%x\n", gPlatformMemoryID);
	paniclog_append_noflush("OS release type: %.256s\n",
	    ('\0' != osreleasetype[0]) ? osreleasetype : "Not set yet");
	paniclog_append_noflush("OS version: %.256s\n",
	    ('\0' != osversion[0]) ? osversion : "Not set yet");
#if defined(XNU_TARGET_OS_BRIDGE)
	paniclog_append_noflush("macOS version: %.256s\n",
	    ('\0' != macosversion[0]) ? macosversion : "Not set");
#endif
	paniclog_append_noflush("Kernel version: %.512s\n", version);

#if CONFIG_EXCLAVES
	exclaves_panic_append_info();
#endif

	if (kernelcache_uuid_valid) {
		if (filesetKC) {
			paniclog_append_noflush("Fileset Kernelcache UUID: ");
		} else {
			paniclog_append_noflush("KernelCache UUID: ");
		}
		for (size_t index = 0; index < sizeof(uuid_t); index++) {
			paniclog_append_noflush("%02X", kernelcache_uuid[index]);
		}
		paniclog_append_noflush("\n");
	}
	panic_display_kernel_uuid();

	if (bootsessionuuid_string[0] != '\0') {
		paniclog_append_noflush("Boot session UUID: %s\n", bootsessionuuid_string);
	} else {
		paniclog_append_noflush("Boot session UUID not yet initialized\n");
	}

	paniclog_append_noflush("iBoot version: %.128s\n", iBoot_version);
#if defined(TARGET_OS_OSX) && defined(__arm64__)
	paniclog_append_noflush("iBoot Stage 2 version: %.128s\n", iBoot_Stage_2_version);
#endif /* defined(TARGET_OS_OSX) && defined(__arm64__) */

	paniclog_append_noflush("secure boot?: %s\n", debug_enabled ? "NO": "YES");
	paniclog_append_noflush("roots installed: %lld\n", roots_installed);
#if defined(XNU_TARGET_OS_BRIDGE)
	paniclog_append_noflush("x86 EFI Boot State: ");
	if (PE_smc_stashed_x86_efi_boot_state != 0xFF) {
		paniclog_append_noflush("0x%x\n", PE_smc_stashed_x86_efi_boot_state);
	} else {
		paniclog_append_noflush("not available\n");
	}
	paniclog_append_noflush("x86 System State: ");
	if (PE_smc_stashed_x86_system_state != 0xFF) {
		paniclog_append_noflush("0x%x\n", PE_smc_stashed_x86_system_state);
	} else {
		paniclog_append_noflush("not available\n");
	}
	paniclog_append_noflush("x86 Power State: ");
	if (PE_smc_stashed_x86_power_state != 0xFF) {
		paniclog_append_noflush("0x%x\n", PE_smc_stashed_x86_power_state);
	} else {
		paniclog_append_noflush("not available\n");
	}
	paniclog_append_noflush("x86 Shutdown Cause: ");
	if (PE_smc_stashed_x86_shutdown_cause != 0xFF) {
		paniclog_append_noflush("0x%x\n", PE_smc_stashed_x86_shutdown_cause);
	} else {
		paniclog_append_noflush("not available\n");
	}
	paniclog_append_noflush("x86 Previous Power Transitions: ");
	if (PE_smc_stashed_x86_prev_power_transitions != UINT64_MAX) {
		paniclog_append_noflush("0x%llx\n", PE_smc_stashed_x86_prev_power_transitions);
	} else {
		paniclog_append_noflush("not available\n");
	}
	paniclog_append_noflush("PCIeUp link state: ");
	if (PE_pcie_stashed_link_state != UINT32_MAX) {
		paniclog_append_noflush("0x%x\n", PE_pcie_stashed_link_state);
	} else {
		paniclog_append_noflush("not available\n");
	}
	paniclog_append_noflush("macOS kernel slide: ");
	if (PE_nvram_stashed_x86_macos_slide != UINT64_MAX) {
		paniclog_append_noflush("%#llx\n", PE_nvram_stashed_x86_macos_slide);
	} else {
		paniclog_append_noflush("not available\n");
	}
#endif
	if (panic_data_buffers != NULL) {
		paniclog_append_noflush("%s data: ", panic_data_buffers->producer_name);
		uint8_t *panic_buffer_data = (uint8_t *) panic_data_buffers->buf;
		for (int i = 0; i < panic_data_buffers->len; i++) {
			paniclog_append_noflush("%02X", panic_buffer_data[i]);
		}
		paniclog_append_noflush("\n");
	}
	paniclog_append_noflush("Paniclog version: %d\n", logversion);

	panic_display_kernel_aslr();
	panic_display_times();
	panic_display_zalloc();
	panic_display_hung_cpus_help();
	panic_display_tpidrs();
	panic_display_pvhs_locked();
	panic_display_pvh_to_lock();
	panic_display_last_pc_lr();
#if CONFIG_ECC_LOGGING
	panic_display_ecc_errors();
#endif /* CONFIG_ECC_LOGGING */
	panic_display_compressor_stats();

#if DEVELOPMENT || DEBUG
	if (cs_debug_unsigned_exec_failures != 0 || cs_debug_unsigned_mmap_failures != 0) {
		paniclog_append_noflush("Unsigned code exec failures: %u\n", cs_debug_unsigned_exec_failures);
		paniclog_append_noflush("Unsigned code mmap failures: %u\n", cs_debug_unsigned_mmap_failures);
	}
#endif

	// Highlight threads that used high amounts of CPU in the panic log if requested (historically requested for watchdog panics)
	if (panic_options & DEBUGGER_OPTION_PRINT_CPU_USAGE_PANICLOG) {
		thread_t        top_runnable[5] = {0};
		thread_t        thread;
		int                     total_cpu_usage = 0;

		print_vnodes = 1;


		for (thread = (thread_t)queue_first(&threads);
		    PANIC_VALIDATE_PTR(thread) && !queue_end(&threads, (queue_entry_t)thread);
		    thread = (thread_t)queue_next(&thread->threads)) {
			total_cpu_usage += thread->cpu_usage;

			// Look for the 5 runnable threads with highest priority
			if (thread->state & TH_RUN) {
				int                     k;
				thread_t        comparison_thread = thread;

				for (k = 0; k < TOP_RUNNABLE_LIMIT; k++) {
					if (top_runnable[k] == 0) {
						top_runnable[k] = comparison_thread;
						break;
					} else if (comparison_thread->sched_pri > top_runnable[k]->sched_pri) {
						thread_t temp = top_runnable[k];
						top_runnable[k] = comparison_thread;
						comparison_thread = temp;
					} // if comparison thread has higher priority than previously saved thread
				} // loop through highest priority runnable threads
			} // Check if thread is runnable
		} // Loop through all threads

		// Print the relevant info for each thread identified
		paniclog_append_noflush("Total cpu_usage: %d\n", total_cpu_usage);
		paniclog_append_noflush("Thread task pri cpu_usage\n");

		for (int i = 0; i < TOP_RUNNABLE_LIMIT; i++) {
			if (top_runnable[i] &&
			    panic_get_thread_proc_task(top_runnable[i], &task, &proc) && proc) {
				char name[MAXCOMLEN + 1];
				proc_name_kdp(proc, name, sizeof(name));
				paniclog_append_noflush("%p %s %d %d\n",
				    top_runnable[i], name, top_runnable[i]->sched_pri, top_runnable[i]->cpu_usage);
			}
		} // Loop through highest priority runnable threads
		paniclog_append_noflush("\n");
	}

	// print current task info
	if (panic_get_thread_proc_task(cur_thread, &task, &proc)) {
		if (PANIC_VALIDATE_PTR(task->map) &&
		    PANIC_VALIDATE_PTR(task->map->pmap)) {
			ledger_amount_t resident = 0;
			if (task != kernel_task) {
				ledger_get_balance(task->ledger, task_ledgers.phys_mem, &resident);
				resident >>= VM_MAP_PAGE_SHIFT(task->map);
			}
			paniclog_append_noflush("Panicked task %p: %lld pages, %d threads: ",
			    task, resident, task->thread_count);
		} else {
			paniclog_append_noflush("Panicked task %p: %d threads: ",
			    task, task->thread_count);
		}

		if (proc) {
			char            name[MAXCOMLEN + 1];
			proc_name_kdp(proc, name, sizeof(name));
			paniclog_append_noflush("pid %d: %s", proc_pid(proc), name);
		} else {
			paniclog_append_noflush("unknown task");
		}

		paniclog_append_noflush("\n");
	}

	if (cur_fp < VM_MAX_KERNEL_ADDRESS) {
		paniclog_append_noflush("Panicked thread: %p, backtrace: 0x%llx, tid: %llu\n",
		    cur_thread, (addr64_t)cur_fp, thread_tid(cur_thread));
#if __LP64__
		print_one_backtrace(kernel_pmap, cur_fp, nohilite_thread_marker, TRUE, filesetKC);
#else
		print_one_backtrace(kernel_pmap, cur_fp, nohilite_thread_marker, FALSE, filesetKC);
#endif
	} else {
		paniclog_append_noflush("Could not print panicked thread backtrace:"
		    "frame pointer outside kernel vm.\n");
	}

	paniclog_append_noflush("\n");
	if (filesetKC) {
		kext_dump_panic_lists(&paniclog_append_noflush);
		paniclog_append_noflush("\n");
	}
	panic_info->eph_panic_log_len = PE_get_offset_into_panic_region(debug_buf_ptr) - panic_info->eph_panic_log_offset;
	/* set the os version data in the panic header in the format 'Product Version (OS Version)' (only if they have been set) */
	if ((osversion[0] != '\0') && (osproductversion[0] != '\0')) {
		snprintf((char *)&panic_info->eph_os_version, sizeof(panic_info->eph_os_version), PANIC_HEADER_VERSION_FMT_STR,
		    osproductversion, osversion);
	}
#if defined(XNU_TARGET_OS_BRIDGE)
	if ((macosversion[0] != '\0') && (macosproductversion[0] != '\0')) {
		snprintf((char *)&panic_info->eph_macos_version, sizeof(panic_info->eph_macos_version), PANIC_HEADER_VERSION_FMT_STR,
		    macosproductversion, macosversion);
	}
#endif
	if (bootsessionuuid_string[0] != '\0') {
		memcpy(panic_info->eph_bootsessionuuid_string, bootsessionuuid_string,
		    sizeof(panic_info->eph_bootsessionuuid_string));
	}
	panic_info->eph_roots_installed = roots_installed;

	if (debug_ack_timeout_count) {
		panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_DEBUGGERSYNC;
		panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
		paniclog_append_noflush("!! debugger synchronization failed, no stackshot !!\n");
	} else if (stackshot_active()) {
		panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_NESTED;
		panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
		paniclog_append_noflush("!! panicked during stackshot, skipping panic stackshot !!\n");
	} else {
		/* Align the stackshot buffer to an 8-byte address (especially important for armv7k devices) */
		debug_buf_ptr += (8 - ((uintptr_t)debug_buf_ptr % 8));
		stackshot_begin_loc = debug_buf_ptr;

		bytes_remaining = debug_buf_size - (unsigned int)((uintptr_t)stackshot_begin_loc - (uintptr_t)debug_buf_base);
		err = kcdata_memory_static_init(&kc_panic_data, (mach_vm_address_t)debug_buf_ptr,
		    KCDATA_BUFFER_BEGIN_COMPRESSED, bytes_remaining - end_marker_bytes,
		    KCFLAG_USE_MEMCOPY);
		if (err == KERN_SUCCESS) {
			uint64_t stackshot_flags = (STACKSHOT_GET_GLOBAL_MEM_STATS | STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT |
			    STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_FROM_PANIC | STACKSHOT_DO_COMPRESS |
			    STACKSHOT_DISABLE_LATENCY_INFO | STACKSHOT_NO_IO_STATS | STACKSHOT_THREAD_WAITINFO | STACKSHOT_GET_DQ |
			    STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT);

			err = kcdata_init_compress(&kc_panic_data, KCDATA_BUFFER_BEGIN_STACKSHOT, kdp_memcpy, KCDCT_ZLIB);
			if (err != KERN_SUCCESS) {
				panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_COMPRESS_FAILED;
				stackshot_flags &= ~STACKSHOT_DO_COMPRESS;
			}
			if (filesetKC) {
				stackshot_flags |= STACKSHOT_SAVE_KEXT_LOADINFO;
			}

			kdp_snapshot_preflight(-1, stackshot_begin_loc, bytes_remaining - end_marker_bytes,
			    stackshot_flags, &kc_panic_data, 0, 0);
			err = do_panic_stackshot(NULL);
			bytes_traced = kdp_stack_snapshot_bytes_traced();
			if (bytes_traced > 0 && !err) {
				debug_buf_ptr += bytes_traced;
				panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_SUCCEEDED;
				panic_info->eph_stackshot_offset = PE_get_offset_into_panic_region(stackshot_begin_loc);
				panic_info->eph_stackshot_len = bytes_traced;

				panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
				if (stackshot_flags & STACKSHOT_DO_COMPRESS) {
					panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_DATA_COMPRESSED;
					bytes_uncompressed = kdp_stack_snapshot_bytes_uncompressed();
					paniclog_append_noflush("\n** Stackshot Succeeded ** Bytes Traced %d (Uncompressed %d) **\n", bytes_traced, bytes_uncompressed);
				} else {
					paniclog_append_noflush("\n** Stackshot Succeeded ** Bytes Traced %d **\n", bytes_traced);
				}
			} else {
				bytes_used = kcdata_memory_get_used_bytes(&kc_panic_data);
				if (bytes_used > 0) {
					/* Zero out the stackshot data */
					bzero(stackshot_begin_loc, bytes_used);
					panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_INCOMPLETE;

					panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
					paniclog_append_noflush("\n** Stackshot Incomplete ** Bytes Filled %llu **\n", bytes_used);
				} else {
					bzero(stackshot_begin_loc, bytes_used);
					panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_ERROR;

					panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
					paniclog_append_noflush("\n!! Stackshot Failed !! Bytes Traced %d, err %d\n", bytes_traced, err);
				}
			}
		} else {
			panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_ERROR;
			panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
			paniclog_append_noflush("\n!! Stackshot Failed !!\nkcdata_memory_static_init returned %d", err);
		}
	}

#if CONFIG_EXT_PANICLOG
	// Write ext paniclog at the end of the paniclog region.
	ext_paniclog_bytes = ext_paniclog_write_panicdata();
	panic_info->eph_ext_paniclog_offset = (ext_paniclog_bytes != 0) ?
	    PE_get_offset_into_panic_region((debug_buf_base + debug_buf_size) - ext_paniclog_bytes) :
	    0;
	panic_info->eph_ext_paniclog_len = ext_paniclog_bytes;
#endif

	assert(panic_info->eph_other_log_offset != 0);

	if (print_vnodes != 0) {
		panic_print_vnodes();
	}

	panic_bt_depth--;
}

/*
 * Entry to print_all_backtraces is serialized by the debugger lock
 */
static void
print_all_backtraces(const char *message, uint64_t panic_options)
{
	unsigned int initial_not_in_kdp = not_in_kdp;

	cpu_data_t * cpu_data_ptr = getCpuDatap();

	assert(cpu_data_ptr->PAB_active == FALSE);
	cpu_data_ptr->PAB_active = TRUE;

	/*
	 * Because print all backtraces uses the pmap routines, it needs to
	 * avoid taking pmap locks.  Right now, this is conditionalized on
	 * not_in_kdp.
	 */
	not_in_kdp = 0;
	do_print_all_backtraces(message, panic_options);

	not_in_kdp = initial_not_in_kdp;

	cpu_data_ptr->PAB_active = FALSE;
}

void
panic_display_times()
{
	if (kdp_clock_is_locked()) {
		paniclog_append_noflush("Warning: clock is locked.  Can't get time\n");
		return;
	}

	extern lck_ticket_t clock_lock;
	extern lck_grp_t clock_lock_grp;

	if ((is_clock_configured) && (lck_ticket_lock_try(&clock_lock, &clock_lock_grp))) {
		clock_sec_t     secs, boot_secs;
		clock_usec_t    usecs, boot_usecs;

		lck_ticket_unlock(&clock_lock);

		clock_get_calendar_microtime(&secs, &usecs);
		clock_get_boottime_microtime(&boot_secs, &boot_usecs);

		paniclog_append_noflush("mach_absolute_time: 0x%llx\n", mach_absolute_time());
		paniclog_append_noflush("Epoch Time:        sec       usec\n");
		paniclog_append_noflush("  Boot    : 0x%08x 0x%08x\n", (unsigned int)boot_secs, (unsigned int)boot_usecs);
		paniclog_append_noflush("  Sleep   : 0x%08x 0x%08x\n", (unsigned int)gIOLastSleepTime.tv_sec, (unsigned int)gIOLastSleepTime.tv_usec);
		paniclog_append_noflush("  Wake    : 0x%08x 0x%08x\n", (unsigned int)gIOLastWakeTime.tv_sec, (unsigned int)gIOLastWakeTime.tv_usec);
		paniclog_append_noflush("  Calendar: 0x%08x 0x%08x\n\n", (unsigned int)secs, (unsigned int)usecs);
	}
}

void
panic_print_symbol_name(vm_address_t search)
{
#pragma unused(search)
	// empty stub. Really only used on x86_64.
	return;
}

void
SavePanicInfo(
	const char *message, __unused void *panic_data, uint64_t panic_options)
{
	/*
	 * This should be initialized by the time we get here, but
	 * if it is not, asserting about it will be of no use (it will
	 * come right back to here), so just loop right here and now.
	 * This prevents early-boot panics from becoming recursive and
	 * thus makes them easier to debug. If you attached to a device
	 * and see your PC here, look down a few frames to see your
	 * early-boot panic there.
	 */
	while (!panic_info || panic_info->eph_panic_log_offset == 0) {
		// rdar://87170225 (PanicHardening: audit panic code for naked spinloops)
		// rdar://88094367 (Add test hooks for panic at different stages in XNU)
		;
	}

	if (panic_options & DEBUGGER_OPTION_PANICLOGANDREBOOT) {
		panic_info->eph_panic_flags  |= EMBEDDED_PANIC_HEADER_FLAG_BUTTON_RESET_PANIC;
	}

	if (panic_options & DEBUGGER_OPTION_COPROC_INITIATED_PANIC) {
		panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_COPROC_INITIATED_PANIC;
	}

#if defined(XNU_TARGET_OS_BRIDGE)
	panic_info->eph_x86_power_state = PE_smc_stashed_x86_power_state;
	panic_info->eph_x86_efi_boot_state = PE_smc_stashed_x86_efi_boot_state;
	panic_info->eph_x86_system_state = PE_smc_stashed_x86_system_state;
#endif

	/*
	 * On newer targets, panic data is stored directly into the iBoot panic region.
	 * If we re-enter SavePanicInfo (e.g. on a double panic) on such a target, update the
	 * panic CRC so that iBoot can hopefully find *something* useful in the panic region.
	 */
	if (PanicInfoSaved && (debug_buf_base >= (char*)gPanicBase) && (debug_buf_base < (char*)gPanicBase + gPanicSize)) {
		unsigned int pi_size = (unsigned int)(debug_buf_ptr - gPanicBase);
		PE_update_panic_crc((unsigned char*)gPanicBase, &pi_size);
		PE_sync_panic_buffers(); // extra precaution; panic path likely isn't reliable if we're here
	}

	if (PanicInfoSaved || (debug_buf_size == 0)) {
		return;
	}

	PanicInfoSaved = TRUE;


	print_all_backtraces(message, panic_options);

	assert(panic_info->eph_panic_log_len != 0);
	panic_info->eph_other_log_len = PE_get_offset_into_panic_region(debug_buf_ptr) - panic_info->eph_other_log_offset;

	PEHaltRestart(kPEPanicSync);

	/*
	 * Notifies registered IOPlatformPanicAction callbacks
	 * (which includes one to disable the memcache) and flushes
	 * the buffer contents from the cache
	 */
	paniclog_flush();
}

void
paniclog_flush()
{
	unsigned int panicbuf_length = 0;

	panicbuf_length = (unsigned int)(debug_buf_ptr - gPanicBase);
	if (!debug_buf_ptr || !panicbuf_length) {
		return;
	}

	/*
	 * Updates the log length of the last part of the panic log.
	 */
	panic_info->eph_other_log_len = PE_get_offset_into_panic_region(debug_buf_ptr) - panic_info->eph_other_log_offset;

	/*
	 * Updates the metadata at the beginning of the panic buffer,
	 * updates the CRC.
	 */
	PE_update_panic_crc((unsigned char *)gPanicBase, &panicbuf_length);

	/*
	 * This is currently unused by platform KEXTs on embedded but is
	 * kept for compatibility with the published IOKit interfaces.
	 */
	PESavePanicInfo((unsigned char *)gPanicBase, panicbuf_length);

	PE_sync_panic_buffers();
}

/*
 * @function DebuggerXCallEnter
 *
 * @abstract IPI other cores so this core can run in a single-threaded context.
 *
 * @discussion This function should be called with the debugger lock held.  It
 * signals the other cores to go into a busy loop so this core can run in a
 * single-threaded context and inspect kernel memory.
 *
 * @param proceed_on_sync_failure If true, then go ahead and try to debug even
 * if we can't synch with the other cores.  This is inherently unsafe and should
 * only be used if the kernel is going down in flames anyway.
 *
 * @param is_stackshot If true, this is a stackshot request.
 *
 * @result returns KERN_OPERATION_TIMED_OUT if synchronization times out and
 * proceed_on_sync_failure is false.
 */
kern_return_t
DebuggerXCallEnter(
	boolean_t proceed_on_sync_failure, bool is_stackshot)
{
	uint64_t max_mabs_time, current_mabs_time;
	int cpu;
	int max_cpu;
	cpu_data_t      *target_cpu_datap;
	cpu_data_t      *cpu_data_ptr = getCpuDatap();

	/* Check for nested debugger entry. */
	cpu_data_ptr->debugger_active++;
	if (cpu_data_ptr->debugger_active != 1) {
		return KERN_SUCCESS;
	}

	/*
	 * If debugger_sync is not 0, someone responded excessively late to the last
	 * debug request (we zero the sync variable in the return function).  Zero it
	 * again here.  This should prevent us from getting out of sync (heh) and
	 * timing out on every entry to the debugger if we timeout once.
	 */

	debugger_sync = 0;
	mp_kdp_trap = 1;
	debug_cpus_spinning = 0;

#pragma unused(is_stackshot)

	/*
	 * Try to signal all CPUs (except ourselves, of course).  Use debugger_sync to
	 * synchronize with every CPU that we appeared to signal successfully (cpu_signal
	 * is not synchronous).
	 */
	max_cpu = ml_get_max_cpu_number();

	boolean_t immediate_halt = FALSE;
	if (proceed_on_sync_failure && force_immediate_debug_halt) {
		immediate_halt = TRUE;
	}

	if (!immediate_halt) {
		for (cpu = 0; cpu <= max_cpu; cpu++) {
			target_cpu_datap = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;

			if ((target_cpu_datap == NULL) || (target_cpu_datap == cpu_data_ptr)) {
				continue;
			}

			kern_return_t ret = cpu_signal(target_cpu_datap, SIGPdebug, (void *)NULL, NULL);
			if (ret == KERN_SUCCESS) {
				os_atomic_inc(&debugger_sync, relaxed);
				os_atomic_inc(&debug_cpus_spinning, relaxed);
			} else if (proceed_on_sync_failure) {
				kprintf("cpu_signal failed in DebuggerXCallEnter\n");
			}
		}

		max_mabs_time = os_atomic_load(&debug_ack_timeout, relaxed);

		if (max_mabs_time > 0) {
			current_mabs_time = mach_absolute_time();
			max_mabs_time += current_mabs_time;
			assert(max_mabs_time > current_mabs_time);
		}

		/*
		 * Wait for DEBUG_ACK_TIMEOUT ns for a response from everyone we IPI'd.  If we
		 * timeout, that is simply too bad; we don't have a true NMI, and one CPU may be
		 * uninterruptibly spinning on someone else.  The best we can hope for is that
		 * all other CPUs have either responded or are spinning in a context that is
		 * debugger safe.
		 */
		while ((debugger_sync != 0) && (max_mabs_time == 0 || current_mabs_time < max_mabs_time)) {
			current_mabs_time = mach_absolute_time();
		}
	}

	if (!proceed_on_sync_failure && (max_mabs_time > 0 && current_mabs_time >= max_mabs_time)) {
		__builtin_arm_dmb(DMB_ISH);
		for (cpu = 0; cpu <= max_cpu; cpu++) {
			target_cpu_datap = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;

			if ((target_cpu_datap == NULL) || (target_cpu_datap == cpu_data_ptr)) {
				continue;
			}
			if (!(target_cpu_datap->cpu_signal & SIGPdebug)) {
				continue;
			}
			if (processor_array[cpu]->state <= PROCESSOR_PENDING_OFFLINE) {
				/*
				 * This is a processor that was successfully sent a SIGPdebug signal
				 * but which hasn't acknowledged it because it went offline with
				 * interrupts disabled before the IPI was delivered, so count it
				 * here.
				 */
				os_atomic_dec(&debugger_sync, relaxed);
				kprintf("%s>found CPU %d offline, debugger_sync=%d\n", __FUNCTION__, cpu, debugger_sync);
				continue;
			}

			kprintf("%s>Debugger synch pending on cpu %d\n", __FUNCTION__, cpu);
		}

		if (debugger_sync == 0) {
			return KERN_SUCCESS;
		} else {
			DebuggerXCallReturn();
			kprintf("%s>returning KERN_OPERATION_TIMED_OUT\n", __FUNCTION__);
			return KERN_OPERATION_TIMED_OUT;
		}
	} else if (immediate_halt || (max_mabs_time > 0 && current_mabs_time >= max_mabs_time)) {
		/*
		 * For the moment, we're aiming for a timeout that the user shouldn't notice,
		 * but will be sufficient to let the other core respond.
		 */
		__builtin_arm_dmb(DMB_ISH);
		for (cpu = 0; cpu <= max_cpu; cpu++) {
			target_cpu_datap = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;

			if ((target_cpu_datap == NULL) || (target_cpu_datap == cpu_data_ptr)) {
				continue;
			}
			if (!(target_cpu_datap->cpu_signal & SIGPdebug) && !immediate_halt) {
				continue;
			}
			if (proceed_on_sync_failure) {
				paniclog_append_noflush("Attempting to forcibly halt cpu %d\n", cpu);
				dbgwrap_status_t halt_status = ml_dbgwrap_halt_cpu(cpu, 0);
				if (halt_status < 0) {
					paniclog_append_noflush("cpu %d failed to halt with error %d: %s\n", cpu, halt_status, ml_dbgwrap_strerror(halt_status));
				} else {
					if (halt_status > 0) {
						paniclog_append_noflush("cpu %d halted with warning %d: %s\n", cpu, halt_status, ml_dbgwrap_strerror(halt_status));
					}
					target_cpu_datap->halt_status = CPU_HALTED;
				}
			} else {
				kprintf("Debugger synch pending on cpu %d\n", cpu);
			}
		}
		if (proceed_on_sync_failure) {
			for (cpu = 0; cpu <= max_cpu; cpu++) {
				target_cpu_datap = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;

				if ((target_cpu_datap == NULL) || (target_cpu_datap == cpu_data_ptr) ||
				    (target_cpu_datap->halt_status == CPU_NOT_HALTED)) {
					continue;
				}
				dbgwrap_status_t halt_status = ml_dbgwrap_halt_cpu_with_state(cpu,
				    NSEC_PER_SEC, &target_cpu_datap->halt_state);
				if ((halt_status < 0) || (halt_status == DBGWRAP_WARN_CPU_OFFLINE)) {
					paniclog_append_noflush("Unable to obtain state for cpu %d with status %d: %s\n", cpu, halt_status, ml_dbgwrap_strerror(halt_status));
				} else {
					paniclog_append_noflush("cpu %d successfully halted\n", cpu);
					target_cpu_datap->halt_status = CPU_HALTED_WITH_STATE;
				}
			}
			if (immediate_halt) {
				paniclog_append_noflush("Immediate halt requested on all cores\n");
			} else {
				paniclog_append_noflush("Debugger synchronization timed out; waited %llu nanoseconds\n",
				    os_atomic_load(&debug_ack_timeout, relaxed));
			}
			debug_ack_timeout_count++;
			return KERN_SUCCESS;
		} else {
			DebuggerXCallReturn();
			return KERN_OPERATION_TIMED_OUT;
		}
	} else {
		return KERN_SUCCESS;
	}
}

/*
 * @function DebuggerXCallReturn
 *
 * @abstract Resume normal multicore operation after DebuggerXCallEnter()
 *
 * @discussion This function should be called with debugger lock held.
 */
void
DebuggerXCallReturn(
	void)
{
	cpu_data_t      *cpu_data_ptr = getCpuDatap();
	uint64_t max_mabs_time, current_mabs_time;

	cpu_data_ptr->debugger_active--;
	if (cpu_data_ptr->debugger_active != 0) {
		return;
	}

	mp_kdp_trap = 0;
	debugger_sync = 0;

	max_mabs_time = os_atomic_load(&debug_ack_timeout, relaxed);

	if (max_mabs_time > 0) {
		current_mabs_time = mach_absolute_time();
		max_mabs_time += current_mabs_time;
		assert(max_mabs_time > current_mabs_time);
	}

	/*
	 * Wait for other CPUs to stop spinning on mp_kdp_trap (see DebuggerXCall).
	 * It's possible for one or more CPUs to not decrement debug_cpus_spinning,
	 * since they may be stuck somewhere else with interrupts disabled.
	 * Wait for DEBUG_ACK_TIMEOUT ns for a response and move on if we don't get it.
	 *
	 * Note that the same is done in DebuggerXCallEnter, when we wait for other
	 * CPUS to update debugger_sync. If we time out, let's hope for all CPUs to be
	 * spinning in a debugger-safe context
	 */
	while ((os_atomic_load_exclusive(&debug_cpus_spinning, relaxed) != 0) &&
	    (max_mabs_time == 0 || current_mabs_time < max_mabs_time)) {
		__builtin_arm_wfe();
		current_mabs_time = mach_absolute_time();
	}
	os_atomic_clear_exclusive();
}

extern void wait_while_mp_kdp_trap(bool check_SIGPdebug);
/*
 * Spin while mp_kdp_trap is set.
 *
 * processor_offline() calls this with check_SIGPdebug=true
 * to break out of the spin loop if the cpu has SIGPdebug
 * pending.
 */
void
wait_while_mp_kdp_trap(bool check_SIGPdebug)
{
	bool found_mp_kdp_trap = false;
	bool found_SIGPdebug = false;

	while (os_atomic_load_exclusive(&mp_kdp_trap, relaxed) != 0) {
		found_mp_kdp_trap = true;
		if (check_SIGPdebug && cpu_has_SIGPdebug_pending()) {
			found_SIGPdebug = true;
			break;
		}
		__builtin_arm_wfe();
	}
	os_atomic_clear_exclusive();

	if (check_SIGPdebug && found_mp_kdp_trap) {
		kprintf("%s>found_mp_kdp_trap=true found_SIGPdebug=%s\n", __FUNCTION__, found_SIGPdebug ? "true" : "false");
	}
}

void
DebuggerXCall(
	void            *ctx)
{
	boolean_t               save_context = FALSE;
	vm_offset_t             kstackptr = 0;
	arm_saved_state_t       *regs = (arm_saved_state_t *) ctx;

	if (regs != NULL) {
#if defined(__arm64__)
		current_cpu_datap()->ipi_pc = (uint64_t)get_saved_state_pc(regs);
		current_cpu_datap()->ipi_lr = (uint64_t)get_saved_state_lr(regs);
		current_cpu_datap()->ipi_fp = (uint64_t)get_saved_state_fp(regs);
		save_context = PSR64_IS_KERNEL(get_saved_state_cpsr(regs));
#endif
	}

	kstackptr = (vm_offset_t)current_thread()->machine.kstackptr;

#if defined(__arm64__)
	arm_kernel_saved_state_t *state = (arm_kernel_saved_state_t *)kstackptr;

	if (save_context) {
		/* Save the interrupted context before acknowledging the signal */
		current_thread()->machine.kpcb = regs;
	} else if (regs) {
		/* zero old state so machine_trace_thread knows not to backtrace it */
		state->fp = 0;
		state->pc_was_in_userspace = true;
		state->lr = 0;
		state->sp = 0;
		state->ssbs = 0;
		state->uao = 0;
		state->dit = 0;
	}
#endif

	/*
	 * When running in serial mode, the core capturing the dump may hold interrupts disabled
	 * for a time longer than the timeout. That path includes logic to reset the timestamp
	 * so that we do not eventually trigger the interrupt timeout assert().
	 *
	 * Here we check whether other cores have already gone over the timeout at this point
	 * before spinning, so we at least cover the IPI reception path. After spinning, however,
	 * we reset the timestamp so as to avoid hitting the interrupt timeout assert().
	 */
	if ((serialmode & SERIALMODE_OUTPUT) || stackshot_active()) {
		INTERRUPT_MASKED_DEBUG_END();
	}

	os_atomic_dec(&debugger_sync, relaxed);


	wait_while_mp_kdp_trap(false);

	/**
	 * Alert the triggering CPU that this CPU is done spinning. The CPU that
	 * signalled all of the other CPUs will wait (in DebuggerXCallReturn) for
	 * all of the CPUs to exit the above loop before continuing.
	 */
	os_atomic_dec(&debug_cpus_spinning, relaxed);

#if SCHED_HYGIENE_DEBUG
	/*
	 * We also abandon the measurement for preemption disable
	 * timeouts, if any. Normally, time in interrupt handlers would be
	 * subtracted from preemption disable time, and this will happen
	 * up to this point here, but since we here "end" the interrupt
	 * handler prematurely (from the point of view of interrupt masked
	 * debugging), the time spinning would otherwise still be
	 * attributed to preemption disable time, and potentially trigger
	 * an event, which could be a panic.
	 */
	abandon_preemption_disable_measurement();
#endif /* SCHED_HYGIENE_DEBUG */

	if ((serialmode & SERIALMODE_OUTPUT) || stackshot_active()) {
		INTERRUPT_MASKED_DEBUG_START(current_thread()->machine.int_handler_addr, current_thread()->machine.int_type);
	}

#if defined(__arm64__)
	current_thread()->machine.kpcb = NULL;
#endif /* defined(__arm64__) */

	/* Any cleanup for our pushed context should go here */
}

void
DebuggerCall(
	unsigned int    reason,
	void            *ctx)
{
#if     !MACH_KDP
#pragma unused(reason,ctx)
#endif /* !MACH_KDP */

#if ALTERNATE_DEBUGGER
	alternate_debugger_enter();
#endif

#if     MACH_KDP
	kdp_trap(reason, (struct arm_saved_state *)ctx);
#else
	/* TODO: decide what to do if no debugger config */
#endif
}

boolean_t
bootloader_valid_page(ppnum_t ppn)
{
	return pmap_bootloader_page(ppn);
}
