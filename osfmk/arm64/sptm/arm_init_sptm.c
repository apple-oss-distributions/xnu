/**
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <arm64/lowglobals.h>
#include <kern/timer_queue.h>
#include <kern/monotonic.h>
#include <machine/commpage.h>
#include <pexpert/device_tree.h>
#include <arm/cpu_internal.h>
#include <arm/misc_protos.h>
#include <arm/machine_cpu.h>
#include <arm/rtclock.h>
#include <vm/vm_map.h>
#include <mach/vm_param.h>
#include <libkern/stack_protector.h>
#include <console/serial_protos.h>
#include <arm64/sptm/pmap/pmap_pt_geometry.h>
#include <arm64/sptm/sptm.h>
#include <sptm/sptm_common.h>

#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif /* CONFIG_TELEMETRY */

#if KPERF
#include <kperf/kptimer.h>
#endif /* KPERF */

#if HIBERNATION
#include <IOKit/IOPlatformExpert.h>
#endif /* HIBERNATION */

/**
 * Functions defined elsewhere that are required by this source file.
 */
extern void patch_low_glo(void);
extern int serial_init(void);
extern void sleep_token_buffer_init(void);

/**
 * Bootstrap stacks. Used on the cold boot path to set up the boot CPU's
 * per-CPU data structure.
 */
extern vm_offset_t intstack_top;
extern vm_offset_t excepstack_top;

/* First (inclusive) and last (exclusive) physical addresses */
extern pmap_paddr_t vm_first_phys;
extern pmap_paddr_t vm_last_phys;

int debug_task;

/**
 * Set according to what serial-related boot-args have been passed to XUN.
 */
extern int disableConsoleOutput;

/**
 * SPTM devices do not support static kernelcaches, but the rest of XNU
 * expects this variable to be defined. Set it to false at build time.
 */
SECURITY_READ_ONLY_LATE(bool) static_kernelcache = false;

/**
 * First physical address freely available to xnu.
 */
SECURITY_READ_ONLY_LATE(addr64_t) first_avail_phys = 0;

#if HAS_BP_RET
/* Enable both branch target retention (0x2) and branch direction retention (0x1) across sleep */
uint32_t bp_ret = 3;
extern void set_bp_ret(void);
#endif

#if SCHED_HYGIENE_DEBUG
boolean_t sched_hygiene_debug_pmc = 1;
#endif

#if SCHED_HYGIENE_DEBUG

#if XNU_PLATFORM_iPhoneOS
#define DEFAULT_INTERRUPT_MASKED_TIMEOUT 48000   /* 2ms */
#else
#define DEFAULT_INTERRUPT_MASKED_TIMEOUT 0xd0000 /* 35.499ms */
#endif /* XNU_PLATFORM_iPhoneOS */

TUNABLE_DT_WRITEABLE(sched_hygiene_mode_t, interrupt_masked_debug_mode,
    "machine-timeouts", "interrupt-masked-debug-mode",
    "interrupt-masked-debug-mode",
    SCHED_HYGIENE_MODE_PANIC,
    TUNABLE_DT_CHECK_CHOSEN);

MACHINE_TIMEOUT_DEV_WRITEABLE(interrupt_masked_timeout, "interrupt-masked",
    DEFAULT_INTERRUPT_MASKED_TIMEOUT, MACHINE_TIMEOUT_UNIT_TIMEBASE,
    NULL);
#if __arm64__
#define SSHOT_INTERRUPT_MASKED_TIMEOUT 0xf9999 /* 64-bit: 42.599ms */
#endif
MACHINE_TIMEOUT_DEV_WRITEABLE(stackshot_interrupt_masked_timeout, "sshot-interrupt-masked",
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

/**
 * The SPTM provides a second set of boot arguments, on top of those
 * provided by iBoot.
 */
SECURITY_READ_ONLY_LATE(sptm_bootstrap_args_xnu_t) const_sptm_args;
SECURITY_READ_ONLY_LATE(const sptm_bootstrap_args_xnu_t *) SPTMArgs;
SECURITY_READ_ONLY_LATE(const bool *) sptm_xnu_triggered_panic_ptr;

extern char osbuild_config[];

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
SECURITY_READ_ONLY_LATE(bool) enable_processor_exit = false;

/**
 * SPTM TODO: The following flag is set up based on the presence and
 *            configuration of the 'sptm_stability_hacks' boot-arg; this
 *            is used in certain codepaths that do not properly function
 *            today in SPTM systems to make the system more stable and fully
 *            able to boot to user space.
 */
SECURITY_READ_ONLY_LATE(bool) sptm_stability_hacks = false;

/*
 * Forward definition
 */
void arm_init(boot_args *args, sptm_bootstrap_args_xnu_t *sptm_args);

#if __arm64__
unsigned int page_shift_user32; /* for page_size as seen by a 32-bit task */

extern void configure_misc_apple_boot_args(void);
extern void configure_misc_apple_regs(bool is_boot_cpu);
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

void arm_slide_rebase_and_sign_image(void);
MARK_AS_FIXUP_TEXT void
arm_slide_rebase_and_sign_image(void)
{
	kernel_mach_header_t *k_mh, *kc_mh = NULL;
	kernel_segment_command_t *seg;
	uintptr_t slide;

	/*
	 * The kernel is part of a MH_FILESET kernel collection, determine slide
	 * based on first segment's mach-o vmaddr (requires first kernel load
	 * command to be LC_SEGMENT_64 of the __TEXT segment)
	 */
	k_mh = &_mh_execute_header;
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
 * boot kernelcache ranges; used for accounting.
 */
SECURITY_READ_ONLY_LATE(const arm_physrange_t *) arm_vm_kernelcache_ranges;
SECURITY_READ_ONLY_LATE(int) arm_vm_kernelcache_numranges;

#if __ARM_KERNEL_PROTECT__
/*
 * If we want to support __ARM_KERNEL_PROTECT__, we need a sufficient amount of
 * mappable space preceeding the kernel (as we unmap the kernel by cutting the
 * range covered by TTBR1 in half).  This must also cover the exception vectors.
 */
static_assert(KERNEL_PMAP_HEAP_RANGE_START > ARM_KERNEL_PROTECT_EXCEPTION_START);

/* The exception vectors and the kernel cannot share root TTEs. */
static_assert((KERNEL_PMAP_HEAP_RANGE_START & ~ARM_TT_ROOT_OFFMASK) > ARM_KERNEL_PROTECT_EXCEPTION_START);

/*
 * We must have enough space in the TTBR1_EL1 range to create the EL0 mapping of
 * the exception vectors.
 */
static_assert((((~ARM_KERNEL_PROTECT_EXCEPTION_START) + 1) * 2ULL) <= (ARM_TT_ROOT_SIZE + ARM_TT_ROOT_INDEX_MASK));
#endif /* __ARM_KERNEL_PROTECT__ */

#define ARM_DYNAMIC_TABLE_XN (ARM_TTE_TABLE_PXN | ARM_TTE_TABLE_XN)

#if KASAN
extern vm_offset_t shadow_pbase;
extern vm_offset_t shadow_ptop;
extern vm_offset_t physmap_vbase;
extern vm_offset_t physmap_vtop;
#endif

/*
 * We explicitly place this in const, as it is not const from a language
 * perspective, but it is only modified before we actually switch away from
 * the bootstrap page tables.
 */
SECURITY_READ_ONLY_LATE(uint8_t) bootstrap_pagetables[BOOTSTRAP_TABLE_SIZE] __attribute__((aligned(ARM_PGBYTES)));

/*
 * Denotes the end of xnu.
 */
extern void *last_kernel_symbol;

extern void arm64_replace_bootstack(cpu_data_t*);
extern void PE_slide_devicetree(vm_offset_t);

/*
 * KASLR parameters
 */
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_top;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kext_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kext_top;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_stext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_etext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_slide;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_slid_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_slid_top;

SECURITY_READ_ONLY_LATE(vm_image_offsets) vm_sptm_offsets;
SECURITY_READ_ONLY_LATE(vm_image_offsets) vm_txm_offsets;

SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_stext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_etext;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_sdata;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_edata;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_sinfo;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_prelink_einfo;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_slinkedit;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_elinkedit;

SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_builtinkmod_text;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernel_builtinkmod_text_end;

SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernelcache_base;
SECURITY_READ_ONLY_LATE(vm_offset_t) vm_kernelcache_top;

/* Used by <mach/arm/vm_param.h> */
SECURITY_READ_ONLY_LATE(unsigned long) gVirtBase;
SECURITY_READ_ONLY_LATE(unsigned long) gPhysBase;
SECURITY_READ_ONLY_LATE(unsigned long) gPhysSize;
SECURITY_READ_ONLY_LATE(unsigned long) gT0Sz = T0SZ_BOOT;
SECURITY_READ_ONLY_LATE(unsigned long) gT1Sz = T1SZ_BOOT;

/* 23543331 - step 1 of kext / kernel __TEXT and __DATA colocation is to move
 * all kexts before the kernel.  This is only for arm64 devices and looks
 * something like the following:
 * -- vmaddr order --
 * 0xffffff8004004000 __PRELINK_TEXT
 * 0xffffff8007004000 __TEXT (xnu)
 * 0xffffff80075ec000 __DATA (xnu)
 * 0xffffff80076dc000 __KLD (xnu)
 * 0xffffff80076e0000 __LAST (xnu)
 * 0xffffff80076e4000 __LINKEDIT (xnu)
 * 0xffffff80076e4000 __PRELINK_DATA (not used yet)
 * 0xffffff800782c000 __PRELINK_INFO
 * 0xffffff80078e4000 -- End of kernelcache
 */

/* 24921709 - make XNU ready for KTRR
 *
 * Two possible kernel cache layouts, depending on which kcgen is being used.
 * VAs increasing downwards.
 * Old KCGEN:
 *
 * __PRELINK_TEXT
 * __TEXT
 * __DATA_CONST
 * __TEXT_EXEC
 * __KLD
 * __LAST
 * __DATA
 * __PRELINK_DATA (expected empty)
 * __LINKEDIT
 * __PRELINK_INFO
 *
 * New kcgen:
 *
 * __PRELINK_TEXT    <--- First KTRR (ReadOnly) segment
 * __PLK_DATA_CONST
 * __PLK_TEXT_EXEC
 * __TEXT
 * __DATA_CONST
 * __TEXT_EXEC
 * __KLD
 * __LAST            <--- Last KTRR (ReadOnly) segment
 * __DATA
 * __BOOTDATA (if present)
 * __LINKEDIT
 * __PRELINK_DATA (expected populated now)
 * __PLK_LINKEDIT
 * __PRELINK_INFO
 *
 */

vm_offset_t mem_size;                             /* Size of actual physical memory present
                                                   * minus any performance buffer and possibly
                                                   * limited by mem_limit in bytes */
uint64_t    mem_actual;                           /* The "One True" physical memory size
                                                   * actually, it's the highest physical
                                                   * address + 1 */
uint64_t    max_mem;                              /* Size of physical memory (bytes), adjusted
                                                   * by maxmem */
uint64_t    max_mem_actual;                       /* Actual size of physical memory (bytes),
                                                   * adjusted by the maxmem boot-arg */
uint64_t    sane_size;                            /* Memory size to use for defaults
                                                   * calculations */
/* This no longer appears to be used; kill it? */
addr64_t    vm_last_addr = VM_MAX_KERNEL_ADDRESS; /* Highest kernel
                                                   * virtual address known
                                                   * to the VM system */

SECURITY_READ_ONLY_LATE(vm_offset_t)              segEXTRADATA;
SECURITY_READ_ONLY_LATE(unsigned long)            segSizeEXTRADATA;

/* Trust cache portion of EXTRADATA (if within it) */
SECURITY_READ_ONLY_LATE(vm_offset_t)              segTRUSTCACHE;
SECURITY_READ_ONLY_LATE(unsigned long)            segSizeTRUSTCACHE;

SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTTEXT;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWEST;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTRO;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTRO;

/* Only set when booted from MH_FILESET kernel collections */
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTROKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTROKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTAuxKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTAuxKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTROAuxKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTROAuxKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLOWESTRXAuxKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTRXAuxKC;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIGHESTNLEAuxKC;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segTEXTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeTEXT;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segDATACONSTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeDATACONST;

SECURITY_READ_ONLY_LATE(vm_offset_t)   segTEXTEXECB;
SECURITY_READ_ONLY_LATE(unsigned long) segSizeTEXTEXEC;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segDATAB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeDATA;

SECURITY_READ_ONLY_LATE(vm_offset_t)          segBOOTDATAB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizeBOOTDATA;
extern vm_offset_t                            intstack_low_guard;
extern vm_offset_t                            intstack_high_guard;
extern vm_offset_t                            excepstack_high_guard;

SECURITY_READ_ONLY_LATE(vm_offset_t)          segLINKB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeLINK;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segKLDB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizeKLD;
SECURITY_READ_ONLY_LATE(static vm_offset_t)   segKLDDATAB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeKLDDATA;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLASTB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizeLAST;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segLASTDATACONSTB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizeLASTDATACONST;

SECURITY_READ_ONLY_LATE(vm_offset_t)          sectHIBTEXTB;
SECURITY_READ_ONLY_LATE(unsigned long)        sectSizeHIBTEXT;
SECURITY_READ_ONLY_LATE(vm_offset_t)          segHIBDATAB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizeHIBDATA;
SECURITY_READ_ONLY_LATE(vm_offset_t)          sectHIBDATACONSTB;
SECURITY_READ_ONLY_LATE(unsigned long)        sectSizeHIBDATACONST;

SECURITY_READ_ONLY_LATE(vm_offset_t)          segPRELINKTEXTB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizePRELINKTEXT;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKTEXTEXECB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKTEXTEXEC;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKDATACONSTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKDATACONST;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPRELINKDATAB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePRELINKDATA;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKLLVMCOVB = 0;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKLLVMCOV = 0;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPLKLINKEDITB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePLKLINKEDIT;

SECURITY_READ_ONLY_LATE(static vm_offset_t)   segPRELINKINFOB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizePRELINKINFO;

/* Only set when booted from MH_FILESET primary kernel collection */
SECURITY_READ_ONLY_LATE(vm_offset_t)          segKCTEXTEXECB;
SECURITY_READ_ONLY_LATE(unsigned long)        segSizeKCTEXTEXEC;
SECURITY_READ_ONLY_LATE(static vm_offset_t)   segKCDATACONSTB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeKCDATACONST;
SECURITY_READ_ONLY_LATE(static vm_offset_t)   segKCDATAB;
SECURITY_READ_ONLY_LATE(static unsigned long) segSizeKCDATA;

SECURITY_READ_ONLY_LATE(static boolean_t) use_contiguous_hint = TRUE;

SECURITY_READ_ONLY_LATE(int) PAGE_SHIFT_CONST;

SECURITY_READ_ONLY_LATE(vm_offset_t) end_kern;
SECURITY_READ_ONLY_LATE(vm_offset_t) etext;
SECURITY_READ_ONLY_LATE(vm_offset_t) sdata;
SECURITY_READ_ONLY_LATE(vm_offset_t) edata;

SECURITY_READ_ONLY_LATE(static vm_offset_t) auxkc_mh, auxkc_base, auxkc_right_above;

pmap_paddr_t alloc_ptpage(sptm_pt_level_t level, bool map_static);
SECURITY_READ_ONLY_LATE(vm_offset_t) ropage_next;
extern int dtrace_keep_kernel_symbols(void);

/*
 * Bootstrap the system enough to run with virtual memory.
 * Map the kernel's code and data, and allocate the system page table.
 * Page_size must already be set.
 *
 * Parameters:
 * first_avail: first available physical page -
 *              after kernel page tables
 * avail_start: PA of first physical page
 * avail_end:   PA of last physical page
 */
SECURITY_READ_ONLY_LATE(vm_offset_t)     first_avail;
SECURITY_READ_ONLY_LATE(vm_offset_t)     static_memory_end;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)    avail_start;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)    avail_end;
SECURITY_READ_ONLY_LATE(pmap_paddr_t)    real_avail_end;
SECURITY_READ_ONLY_LATE(unsigned long)   real_phys_size;
SECURITY_READ_ONLY_LATE(vm_map_address_t) physmap_base = (vm_map_address_t)0;
SECURITY_READ_ONLY_LATE(vm_map_address_t) physmap_end = (vm_map_address_t)0;

typedef struct {
	pmap_paddr_t pa;
	vm_map_address_t va;
	vm_size_t len;
} ptov_table_entry;

SECURITY_READ_ONLY_LATE(static boolean_t)               kva_active = FALSE;


/**
 * sptm_supports_local_coredump is set in start_sptm.s when SPTM dispatch logic
 * calls into XNU to handle a panic from SPTM/TXM/cL4. If this variable is set
 * to false then osfmk/kern/debug.c:debugger_collect_diagnostic() will skip
 * taking a local core dump. This defaults to true since as long as the panic
 * doesn't occur within the SPTM, then the SPTM will support making calls during
 * the panic path to save the coredump. Only when the panic occurs from within
 * guarded mode do we let SPTM decide whether it supports local coredumps.
 */
bool sptm_supports_local_coredump = true;

/**
 * Entry point for systems that support an SPTM. Bootstrap stacks
 * have been set up by the SPTM by this point, and XNU is responsible
 * for rebasing and signing absolute addresses.
 */
void
arm_init(boot_args *args, sptm_bootstrap_args_xnu_t *sptm_boot_args)
{
	unsigned int maxmem;
	uint32_t memsize;
	uint64_t xmaxmem;
	thread_t thread;

	extern void xnu_return_to_gl2(void);
	const sptm_vaddr_t handler_addr = (sptm_vaddr_t) ptrauth_strip((void *)xnu_return_to_gl2, ptrauth_key_function_pointer);
	sptm_register_xnu_exc_return(handler_addr);

#if defined(HAS_APPLE_PAC)
	kernel_mach_header_t *kc_mh = PE_get_kc_header(KCKindPrimary);
	OSRuntimeSignStructorsInFileset(kc_mh);
#endif /* defined(HAS_APPLE_PAC) */

	/* If kernel integrity is supported, use a constant copy of the boot args. */
	const_boot_args = *args;
	BootArgs = args = &const_boot_args;
	const_sptm_args = *sptm_boot_args;
	SPTMArgs = sptm_boot_args = &const_sptm_args;
	sptm_xnu_triggered_panic_ptr = sptm_boot_args->xnu_triggered_panic;
	/*
	 * Initialize first_avail_phys from what the SPTM tells us.
	 * We're not using iBoot's topOfKernelData, as SPTM and other
	 * components have consumed pages themselves.
	 */
	first_avail_phys = sptm_boot_args->first_avail_phys;

	cpu_data_init(&BootCpuData);
#if defined(HAS_APPLE_PAC)
	/* bootstrap cpu process dependent key for kernel has been loaded by start.s */
	BootCpuData.rop_key = ml_default_rop_pid();
	BootCpuData.jop_key = ml_default_jop_pid();
#endif /* defined(HAS_APPLE_PAC) */

	PE_init_platform(FALSE, args); /* Get platform expert set up */

	/* Initialize SPTM helper library. */
	libsptm_init(&const_sptm_args.libsptm_state);

#if __arm64__
	configure_timer_apple_regs();
	wfe_timeout_configure();
	wfe_timeout_init();

	configure_misc_apple_boot_args();
	configure_misc_apple_regs(true);


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

	/* Enable SPTM stability hacks if requested */
	PE_parse_boot_argn("sptm_stability_hacks", &sptm_stability_hacks, sizeof(sptm_stability_hacks));

	ml_parse_cpu_topology();


	master_cpu = ml_get_boot_cpu_number();
	assert(master_cpu >= 0 && master_cpu <= ml_get_max_cpu_number());

	BootCpuData.cpu_number = (unsigned short)master_cpu;
	BootCpuData.intstack_top = (vm_offset_t) &intstack_top;
	BootCpuData.istackptr = &intstack_top;
	BootCpuData.excepstack_top = (vm_offset_t) &excepstack_top;
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

		if (wdt_disabled || kern_feature_override(KF_PREEMPTION_DISABLED_DEBUG_OVRD)) {
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

	/* Validate SPTM variant. */
	__typeof__(const_sptm_args.sptm_variant) expected_sptm_variant;
#if DEVELOPMENT || DEBUG
	expected_sptm_variant = SPTM_VARIANT_DEVELOPMENT;
#else /* RELEASE */
	expected_sptm_variant = SPTM_VARIANT_RELEASE;
#endif /* RELEASE */
	if (const_sptm_args.sptm_variant != expected_sptm_variant) {
		panic("arm_init: Mismatch between xnu variant (%s) and SPTM variant (0x%x)",
		    osbuild_config, const_sptm_args.sptm_variant);
	}

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
	DTEntry chosen;
	unsigned int dt_entry_size;
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
	configure_misc_apple_regs(false);
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
		unsigned int expected_preemption_count = (gEnforceQuiesceSafety ? 2 : 1);
		if (get_preemption_level_for_thread(cpu_data_ptr->cpu_active_thread) !=
		    expected_preemption_count) {
			panic("unexpected preemption count %u on boot cpu thread (should be %u)",
			    get_preemption_level_for_thread(cpu_data_ptr->cpu_active_thread),
			    expected_preemption_count);
		}
		cpu_data_ptr->cpu_active_thread->machine.preemption_count--;
	}
#endif /* HIBERNATION */

#if __arm64__
	wfe_timeout_init();
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

#if DEVELOPMENT || DEBUG
	PE_arm_debug_enable_trace(true);
#endif /* DEVELOPMENT || DEBUG */

	kprintf("arm_cpu_init(): cpu %d online\n", cpu_data_ptr->cpu_number);

	if (cpu_data_ptr == &BootCpuData) {
		if (kdebug_enable == 0) {
			__kdebug_only uint64_t elapsed = kdebug_wake();
			KDBG(IOKDBG_CODE(DBG_HIBERNATE, 15), mach_absolute_time() - elapsed);
		}

#if CONFIG_TELEMETRY
		bootprofile_wake_from_sleep();
#endif /* CONFIG_TELEMETRY */
	}
#if CONFIG_CPU_COUNTERS
	mt_wake_per_core();
#endif /* CONFIG_CPU_COUNTERS */

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

vm_map_address_t
phystokv(pmap_paddr_t pa)
{
	sptm_papt_t va;
	if (sptm_phystokv(pa, &va) != LIBSPTM_SUCCESS) {
		return 0;
	}
	return (vm_map_address_t)va;
}

vm_map_address_t
phystokv_range(pmap_paddr_t pa, vm_size_t *max_len)
{

	vm_size_t len;

	len = PAGE_SIZE - (pa & PAGE_MASK);
	if (*max_len > len) {
		*max_len = len;
	}

	return phystokv((sptm_paddr_t)pa);
}

vm_offset_t
ml_static_vtop(vm_offset_t va)
{
	return (vm_offset_t)kvtophys_nofail((sptm_papt_t)va);
}

#define ARM64_GRANULE_ALLOW_BLOCK (1 << 0)
#define ARM64_GRANULE_ALLOW_HINT (1 << 1)

// Populate seg...AuxKC and fixup AuxKC permissions
static bool
arm_vm_auxkc_init(void)
{
	if (auxkc_mh == 0 || auxkc_base == 0) {
		return false; // no auxKC.
	}

	/* Fixup AuxKC and populate seg*AuxKC globals used below */
	arm_auxkc_init((void*)auxkc_mh, (void*)auxkc_base);

	if (segLOWESTAuxKC != segLOWEST) {
		panic("segLOWESTAuxKC (%p) not equal to segLOWEST (%p). auxkc_mh: %p, auxkc_base: %p",
		    (void*)segLOWESTAuxKC, (void*)segLOWEST,
		    (void*)auxkc_mh, (void*)auxkc_base);
	}

	/*
	 * The AuxKC LINKEDIT segment needs to be covered by the RO region but is excluded
	 * from the RO address range returned by kernel_collection_adjust_mh_addrs().
	 * Ensure the highest non-LINKEDIT address in the AuxKC is the current end of
	 * its RO region before extending it.
	 */
	assert(segHIGHESTROAuxKC == segHIGHESTNLEAuxKC);
	assert(segHIGHESTAuxKC >= segHIGHESTROAuxKC);
	if (segHIGHESTAuxKC > segHIGHESTROAuxKC) {
		segHIGHESTROAuxKC = segHIGHESTAuxKC;
	}

	/*
	 * The AuxKC RO region must be right below the device tree/trustcache so that it can be covered
	 * by CTRR, and the AuxKC RX region must be within the RO region.
	 */
	assert(segHIGHESTROAuxKC == auxkc_right_above);
	assert(segHIGHESTRXAuxKC <= segHIGHESTROAuxKC);
	assert(segLOWESTRXAuxKC <= segHIGHESTRXAuxKC);
	assert(segLOWESTROAuxKC <= segLOWESTRXAuxKC);
	assert(segLOWESTAuxKC <= segLOWESTROAuxKC);

	return true;
}

/*
 * Looks up the set of properties that describe the physical load addresses and sizes of the boot
 * kernelcache's loaded segments in the device tree and returns (1) the number of segments found
 * in *arm_vm_kernelcache_numrangesp and (2) their starting/ending addresses as an array of type
 * arm_physrange_t in *arm_vm_kernelcache_rangesp.
 * The function returns the total number of pages across all loaded boot kernelcache segments.
 * If there is a problem looking up the /chosen/memory-map node in the DT, all arguments are
 * zeroed and the function returns 0.
 */
static unsigned int
arm_get_bootkc_ranges_from_DT(const arm_physrange_t **arm_vm_kernelcache_rangesp, int *arm_vm_kernelcache_numrangesp)
{
	DTEntry memory_map;
	int err;
	DTMemoryMapRange const *range;
	unsigned int rangeSize;
#define NUM_BOOTKC_RANGES 5
	static arm_physrange_t bootkc_physranges[NUM_BOOTKC_RANGES] = { {0, } };
	static int bootkc_numranges = 0;
	static unsigned int bootkc_total_pages = 0;

	assert(arm_vm_kernelcache_rangesp != NULL);
	assert(arm_vm_kernelcache_numrangesp != NULL);

	/* return cached values if previously computed */
	if (bootkc_numranges == 0) {
		err = SecureDTLookupEntry(NULL, "chosen/memory-map", &memory_map);
		if (err != kSuccess) {
			*arm_vm_kernelcache_numrangesp = 0;
			*arm_vm_kernelcache_rangesp = NULL;
			return 0;
		}

		/* We're looking for 5 ranges: BootKC-ro, BootKC-rx, BootKC-bx, BootKC-rw, and BootKC-le */
		const char *BootKC_Properties[NUM_BOOTKC_RANGES] = {
			"BootKC-ro", "BootKC-rx", "BootKC-bx", "BootKC-rw", "BootKC-le"
		};

		for (int i = 0; i < NUM_BOOTKC_RANGES; i++) {
			err = SecureDTGetProperty(memory_map, BootKC_Properties[i], (void const **)&range, &rangeSize);
			if (err == kSuccess && rangeSize == sizeof(DTMemoryMapRange)) {
				bootkc_physranges[i].start_phys = range->paddr;
				bootkc_physranges[i].end_phys = range->paddr + range->length;
				assert((bootkc_physranges[i].end_phys & PAGE_MASK) == 0);
				bootkc_numranges++;
				bootkc_total_pages += (unsigned int) atop_64(bootkc_physranges[i].end_phys - bootkc_physranges[i].start_phys);
			}
		}
	}

	*arm_vm_kernelcache_numrangesp = bootkc_numranges;
	*arm_vm_kernelcache_rangesp = &bootkc_physranges[0];
	return bootkc_total_pages;
}

void
arm_vm_prot_init(__unused boot_args * args)
{
	segLOWESTTEXT = UINT64_MAX;
	if (segSizePRELINKTEXT && (segPRELINKTEXTB < segLOWESTTEXT)) {
		segLOWESTTEXT = segPRELINKTEXTB;
	}
	assert(segSizeTEXT);
	if (segTEXTB < segLOWESTTEXT) {
		segLOWESTTEXT = segTEXTB;
	}
	assert(segLOWESTTEXT < UINT64_MAX);

	segEXTRADATA = 0;
	segSizeEXTRADATA = 0;
	segTRUSTCACHE = 0;
	segSizeTRUSTCACHE = 0;

	segLOWEST = segLOWESTTEXT;
	segLOWESTRO = segLOWESTTEXT;

	if (segLOWESTKC && segLOWESTKC < segLOWEST) {
		/*
		 * kernel collections have segments below the kernel. In particular the collection mach header
		 * is below PRELINK_TEXT and is not covered by any other segments already tracked.
		 */
		segLOWEST = segLOWESTKC;
		if (segLOWESTROKC && segLOWESTROKC < segLOWESTRO) {
			segLOWESTRO = segLOWESTROKC;
		}
		if (segHIGHESTROKC && segHIGHESTROKC > segHIGHESTRO) {
			segHIGHESTRO = segHIGHESTROKC;
		}
	}

	DTEntry memory_map;
	int err;

	// Device Tree portion of EXTRADATA
	if (SecureDTIsLockedDown()) {
		segEXTRADATA = (vm_offset_t)PE_state.deviceTreeHead;
		segSizeEXTRADATA = PE_state.deviceTreeSize;
	}

	// Trust Caches portion of EXTRADATA
	{
		DTMemoryMapRange const *trustCacheRange;
		unsigned int trustCacheRangeSize;

		err = SecureDTLookupEntry(NULL, "chosen/memory-map", &memory_map);
		assert(err == kSuccess);

		err = SecureDTGetProperty(memory_map, "TrustCache", (void const **)&trustCacheRange, &trustCacheRangeSize);
		if (err == kSuccess) {
			if (trustCacheRangeSize != sizeof(DTMemoryMapRange)) {
				panic("Unexpected /chosen/memory-map/TrustCache property size %u != %zu", trustCacheRangeSize, sizeof(DTMemoryMapRange));
			}

			vm_offset_t const trustCacheRegion = phystokv(trustCacheRange->paddr);
			if (trustCacheRegion < segLOWEST) {
				if (segEXTRADATA != 0) {
					if (trustCacheRegion != segEXTRADATA + segSizeEXTRADATA) {
						panic("Unexpected location of TrustCache region: %#lx != %#lx",
						    trustCacheRegion, segEXTRADATA + segSizeEXTRADATA);
					}
					segSizeEXTRADATA += trustCacheRange->length;
				} else {
					// Not all devices support CTRR device trees.
					segEXTRADATA = trustCacheRegion;
					segSizeEXTRADATA = trustCacheRange->length;
				}
			}
			segTRUSTCACHE = trustCacheRegion;
			segSizeTRUSTCACHE = trustCacheRange->length;
		}
	}

	if (segSizeEXTRADATA != 0) {
		if (segEXTRADATA <= segLOWEST) {
			segLOWEST = segEXTRADATA;
			if (segEXTRADATA <= segLOWESTRO) {
				segLOWESTRO = segEXTRADATA;
			}
		} else {
			panic("EXTRADATA is in an unexpected place: %#lx > %#lx", segEXTRADATA, segLOWEST);
		}
	}

	const DTMemoryMapRange *auxKC_range, *auxKC_header_range;
	unsigned int auxKC_range_size, auxKC_header_range_size;

	err = SecureDTGetProperty(memory_map, "AuxKC", (const void**)&auxKC_range,
	    &auxKC_range_size);
	if (err != kSuccess) {
		goto noAuxKC;
	}
	assert(auxKC_range_size == sizeof(DTMemoryMapRange));
	err = SecureDTGetProperty(memory_map, "AuxKC-mach_header",
	    (const void**)&auxKC_header_range, &auxKC_header_range_size);
	if (err != kSuccess) {
		goto noAuxKC;
	}
	assert(auxKC_header_range_size == sizeof(DTMemoryMapRange));

	if (auxKC_header_range->paddr == 0 || auxKC_range->paddr == 0) {
		goto noAuxKC;
	}

	auxkc_mh = phystokv(auxKC_header_range->paddr);
	auxkc_base = phystokv(auxKC_range->paddr);

	if (auxkc_base < segLOWEST) {
		auxkc_right_above = segLOWEST;
		segLOWEST = auxkc_base;
	} else {
		panic("auxkc_base (%p) not below segLOWEST (%p)", (void*)auxkc_base, (void*)segLOWEST);
	}

noAuxKC:
	/* Record the bounds of the kernelcache. */
	vm_kernelcache_base = segLOWEST;
	vm_kernelcache_top = end_kern;
}

/*
 * return < 0 for a < b
 *          0 for a == b
 *        > 0 for a > b
 */
typedef int (*cmpfunc_t)(const void *a, const void *b);

extern void
qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);

SECURITY_READ_ONLY_LATE(static unsigned int) ptov_index = 0;

#define ROUND_L1(addr) (((addr) + ARM_TT_L1_OFFMASK) & ~(ARM_TT_L1_OFFMASK))
#define ROUND_TWIG(addr) (((addr) + ARM_TT_TWIG_OFFMASK) & ~(ARM_TT_TWIG_OFFMASK))

void
arm_vm_prot_finalize(boot_args * args __unused)
{
	/*
	 * At this point, we are far enough along in the boot process that it will be
	 * safe to free up all of the memory preceeding the kernel.  It may in fact
	 * be safe to do this earlier.
	 *
	 * This keeps the memory in the V-to-P mapping, but advertises it to the VM
	 * as usable.
	 */

	/* Slide KLDDATA */
	sptm_slide_region(segKLDDATAB, (unsigned int)(segSizeKLDDATA >> PAGE_SHIFT));

	/*
	 * Replace the boot CPU's stacks with properly-guarded dynamically allocated stacks.
	 * This must happen prior to sliding segBOOTDATAB, which will effectively remove
	 * the existing boot stacks.
	 */
	cpu_stack_alloc(&BootCpuData);
	arm64_replace_bootstack(&BootCpuData);

	/* Slide early-boot data */
	sptm_slide_region(segBOOTDATAB, (unsigned int)(segSizeBOOTDATA >> PAGE_SHIFT));

	/* Slide linkedit, unless otherwise requested */
	bool keep_linkedit = false;
	PE_parse_boot_argn("keepsyms", &keep_linkedit, sizeof(keep_linkedit));
#if CONFIG_DTRACE
	if (dtrace_keep_kernel_symbols()) {
		keep_linkedit = true;
	}
#endif /* CONFIG_DTRACE */
#if KASAN_DYNAMIC_BLACKLIST
	/* KASAN's dynamic blacklist needs to query the LINKEDIT segment at runtime.  As such, the
	 * kext bootstrap code will not jettison LINKEDIT on kasan kernels, so don't bother to relocate it. */
	keep_linkedit = true;
#endif

	if (!keep_linkedit) {
		sptm_slide_region(segLINKB, (unsigned int)(segSizeLINK >> PAGE_SHIFT));
		if (segSizePLKLINKEDIT) {
			/* Prelinked kernel LINKEDIT */
			sptm_slide_region(segPLKLINKEDITB, (unsigned int)(segSizePLKLINKEDIT >> PAGE_SHIFT));
		}
	}

	/* Slide prelinked kernel plists */
	sptm_slide_region(segPRELINKINFOB, (unsigned int)(segSizePRELINKINFO >> PAGE_SHIFT));

	/*
	 * Free the portion of memory that precedes the first usable region, known
	 * as the physical slide.
	 */
	ml_static_mfree(SPTMArgs->phys_slide_papt, SPTMArgs->phys_slide_size);

	/*
	 * KTRR support means we will be mucking with these pages and trying to
	 * protect them; we cannot free the pages to the VM if we do this.
	 */
	if (!segSizePLKDATACONST && !segSizePLKTEXTEXEC && segSizePRELINKTEXT) {
		/* If new segments not present, PRELINK_TEXT is not dynamically sized, free DRAM between it and xnu TEXT */
		ml_static_mfree(segPRELINKTEXTB + segSizePRELINKTEXT, segTEXTB - (segPRELINKTEXTB + segSizePRELINKTEXT));
	}

	ml_static_mfree(segBOOTDATAB, segSizeBOOTDATA);

#if __ARM_KERNEL_PROTECT__
	arm_vm_populate_kernel_el0_mappings();
#endif /* __ARM_KERNEL_PROTECT__ */
}

/*
 * TBI (top-byte ignore) is an ARMv8 feature for ignoring the top 8 bits of
 * address accesses. It can be enabled separately for TTBR0 (user) and
 * TTBR1 (kernel).
 */
void
arm_set_kernel_tbi(void)
{
#if !__ARM_KERNEL_PROTECT__ && CONFIG_KERNEL_TBI
	uint64_t old_tcr, new_tcr;

	old_tcr = new_tcr = get_tcr();
	/*
	 * For kernel configurations that require TBI support on
	 * PAC systems, we enable DATA TBI only.
	 */
	new_tcr |= TCR_TBI1_TOPBYTE_IGNORED;
	new_tcr |= TCR_TBID1_ENABLE;

	if (old_tcr != new_tcr) {
		set_tcr(new_tcr);
		sysreg_restore.tcr_el1 = new_tcr;
	}
#endif /* !__ARM_KERNEL_PROTECT__ && CONFIG_KERNEL_TBI */
}

/* allocate a page for a page table: we support static and dynamic mappings.
 *
 * returns a physical address for the allocated page
 *
 * for static mappings, we allocate from the region ropagetable_begin to ro_pagetable_end-1,
 * which is defined in the DATA_CONST segment and will be protected RNX when vm_prot_finalize runs.
 *
 * for dynamic mappings, we allocate from avail_start, which should remain RWNX.
 */
pmap_paddr_t
alloc_ptpage(sptm_pt_level_t level, bool map_static)
{
	pmap_paddr_t paddr = 0;

#if !(defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR))
	map_static = FALSE;
#endif

	/* Set the next free ropage if this is the first call to this function */
	if (!ropage_next) {
		ropage_next = (vm_offset_t)&ropagetable_begin;
	}

	if (map_static) {
		/* This is a RO allocation. Make sure we have room in the ropagetable area */
		assert(ropage_next < (vm_offset_t)&ropagetable_end);

		/* Obtain physical address and increment the index into the ropagetable area */
		paddr = (pmap_paddr_t)kvtophys((sptm_papt_t)ropage_next);
		ropage_next += ARM_PGBYTES;
	} else {
		/* This is a RW allocation. Simply grab a page from [avail_start] */
		paddr = avail_start;
		avail_start += ARM_PGBYTES;
	}

	/* Retype the page to XNU_PAGE_TABLE, with the desired level */
	sptm_retype_params_t retype_params;
	retype_params.level = level;
	sptm_retype(paddr, XNU_DEFAULT, XNU_PAGE_TABLE, retype_params);

	return paddr;
}

/**
 * Initialize a vm_image_offsets structure with information obtained from a
 * Mach-O header for the wanted image.
 *
 * @param debug_header_entry The entry in the debug header images list to obtain
 *                           a pointer to the Mach-O header from. This must be
 *                           either the SPTM or TXM debug header entry.
 * @param offsets Output pointer of the vm_image_offsets structure to fill in.
 */
static void
init_image_offsets(size_t debug_header_entry, vm_image_offsets *offsets)
{
	assert(offsets != NULL);
	assert((debug_header_entry == DEBUG_HEADER_ENTRY_SPTM) ||
	    (debug_header_entry == DEBUG_HEADER_ENTRY_TXM));

	offsets->slid_base = (vm_offset_t)SPTMArgs->debug_header->image[debug_header_entry];
	kernel_mach_header_t *macho = (kernel_mach_header_t*)offsets->slid_base;
	offsets->unslid_base = (vm_offset_t)getsegbynamefromheader(macho, "__TEXT")->vmaddr;
	assert((offsets->slid_base != 0) && (offsets->unslid_base != 0));
	offsets->slide = offsets->slid_base - offsets->unslid_base;
	offsets->unslid_top = getlastaddr(macho);
	offsets->slid_top = offsets->unslid_top + offsets->slide;
}

#define ARM64_PHYSMAP_SLIDE_RANGE (1ULL << 30) // 1 GB
#define ARM64_PHYSMAP_SLIDE_MASK  (ARM64_PHYSMAP_SLIDE_RANGE - 1)

void
arm_vm_init(uint64_t memory_size, boot_args * args)
{
	vm_map_address_t va_l1, va_l1_end;
	tt_entry_t       *cpu_l1_tte;
	tt_entry_t       *cpu_l2_tte;
	vm_map_address_t va_l2, va_l2_end;
	vm_map_address_t dynamic_memory_begin;
	uint64_t         mem_segments;

	/* Get the virtual and physical kernel-managed memory base from boot_args */
	gVirtBase = args->virtBase;
	gPhysBase = args->physBase;

	/* Get the memory size */
#if KASAN
	real_phys_size = args->memSize + (shadow_ptop - shadow_pbase);
#else
	real_phys_size = args->memSize;
#endif

	/**
	 * Ensure the physical region we specify for the VM to manage ends on a
	 * software page boundary.  Note that the software page size (PAGE_SIZE)
	 * may be a multiple of the hardware page size specified in ARM_PGBYTES.
	 * We must round the reported memory size down to the nearest PAGE_SIZE
	 * boundary to ensure the VM does not try to manage a page it does not
	 * completely own.  The KASAN shadow region, if present, is managed entirely
	 * in units of the hardware page size and should not need similar treatment.
	 */
	gPhysSize = mem_size = ((gPhysBase + args->memSize) & ~PAGE_MASK) - gPhysBase;

	/* Obtain total memory size, including non-managed memory */
	mem_actual = args->memSizeActual ? args->memSizeActual : mem_size;

	if ((memory_size != 0) && (mem_size > memory_size)) {
		mem_size = memory_size;
		max_mem_actual = memory_size;
	} else {
		max_mem_actual = mem_actual;
	}

	/* Make sure the system does not have more physical memory than what can be mapped */
	if (mem_size >= ((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) / 2)) {
		panic("Unsupported memory configuration %lx", mem_size);
	}

	physmap_base = SPTMArgs->physmap_base;
	physmap_end = static_memory_end = SPTMArgs->physmap_end;

#if KASAN && !defined(ARM_LARGE_MEMORY)
	/* add the KASAN stolen memory to the physmap */
	dynamic_memory_begin = static_memory_end + (shadow_ptop - shadow_pbase);
#else
	dynamic_memory_begin = static_memory_end;
#endif

	if (dynamic_memory_begin > VM_MAX_KERNEL_ADDRESS) {
		panic("Unsupported memory configuration %lx", mem_size);
	}

	/*
	 * TODO: free bootstrap table memory back to allocator.
	 * on large memory systems bootstrap tables could be quite large.
	 * after bootstrap complete, xnu can warm start with a single 16KB page mapping
	 * to trampoline to KVA. this requires only 3 pages to stay resident.
	 */
	avail_start = first_avail_phys;

	/*
	 * Initialize l1 page table page.
	 *
	 * SPTM TODO: Have a separate root_table_paddr field in the sptm_args
	 *            instead of snooping the libsptm_state (XNU should not be
	 *            snooping the libsptm_state directly in general).
	 */
	cpu_ttep = (pmap_paddr_t)const_sptm_args.libsptm_state.root_table_paddr;
	cpu_tte = (tt_entry_t *)phystokv(cpu_ttep);
	avail_end = gPhysBase + mem_size;
	assert(!(avail_end & PAGE_MASK));

	/* These need to be set early so pa_valid() works */
	vm_first_phys = gPhysBase;
	vm_last_phys = trunc_page(avail_end);

#if KASAN
	real_avail_end = gPhysBase + real_phys_size;
#else
	real_avail_end = avail_end;
#endif

	/*
	 * Now retrieve addresses for various segments from kernel mach-o header
	 */
	segPRELINKTEXTB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_TEXT", &segSizePRELINKTEXT);
	segPLKDATACONSTB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_DATA_CONST", &segSizePLKDATACONST);
	segPLKTEXTEXECB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_TEXT_EXEC", &segSizePLKTEXTEXEC);
	segTEXTB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__TEXT", &segSizeTEXT);
	segDATACONSTB    = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__DATA_CONST", &segSizeDATACONST);
	segTEXTEXECB     = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__TEXT_EXEC", &segSizeTEXTEXEC);
	segDATAB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__DATA", &segSizeDATA);

	segBOOTDATAB     = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__BOOTDATA", &segSizeBOOTDATA);
	segLINKB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LINKEDIT", &segSizeLINK);
	segKLDB          = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__KLD", &segSizeKLD);
	segKLDDATAB      = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__KLDDATA", &segSizeKLDDATA);
	segPRELINKDATAB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_DATA", &segSizePRELINKDATA);
	segPRELINKINFOB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_INFO", &segSizePRELINKINFO);
	segPLKLLVMCOVB   = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_LLVM_COV", &segSizePLKLLVMCOV);
	segPLKLINKEDITB  = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PLK_LINKEDIT", &segSizePLKLINKEDIT);
	segLASTB         = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LAST", &segSizeLAST);
	segLASTDATACONSTB = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LASTDATA_CONST", &segSizeLASTDATACONST);

	sectHIBTEXTB     = (vm_offset_t) getsectdatafromheader(&_mh_execute_header, "__TEXT_EXEC", "__hib_text", &sectSizeHIBTEXT);
	sectHIBDATACONSTB = (vm_offset_t) getsectdatafromheader(&_mh_execute_header, "__DATA_CONST", "__hib_const", &sectSizeHIBDATACONST);
	segHIBDATAB      = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__HIBDATA", &segSizeHIBDATA);

	if (kernel_mach_header_is_in_fileset(&_mh_execute_header)) {
		kernel_mach_header_t *kc_mh = PE_get_kc_header(KCKindPrimary);

		// fileset has kext PLK_TEXT_EXEC under kernel collection TEXT_EXEC following kernel's LAST
		segKCTEXTEXECB = (vm_offset_t) getsegdatafromheader(kc_mh, "__TEXT_EXEC", &segSizeKCTEXTEXEC);
		assert(segPLKTEXTEXECB && !segSizePLKTEXTEXEC);                        // kernel PLK_TEXT_EXEC must be empty

		assert(segLASTB);                                                      // kernel LAST can be empty, but it must have
		                                                                       // a valid address for computations below.

		assert(segKCTEXTEXECB <= segLASTB);                                    // KC TEXT_EXEC must contain kernel LAST
		assert(segKCTEXTEXECB + segSizeKCTEXTEXEC >= segLASTB + segSizeLAST);
		segPLKTEXTEXECB = segLASTB + segSizeLAST;
		segSizePLKTEXTEXEC = segSizeKCTEXTEXEC - (segPLKTEXTEXECB - segKCTEXTEXECB);

		// fileset has kext PLK_DATA_CONST under kernel collection DATA_CONST following kernel's LASTDATA_CONST
		segKCDATACONSTB = (vm_offset_t) getsegdatafromheader(kc_mh, "__DATA_CONST", &segSizeKCDATACONST);
		assert(segPLKDATACONSTB && !segSizePLKDATACONST);                      // kernel PLK_DATA_CONST must be empty
		assert(segLASTDATACONSTB && segSizeLASTDATACONST);                     // kernel LASTDATA_CONST must be non-empty
		assert(segKCDATACONSTB <= segLASTDATACONSTB);                          // KC DATA_CONST must contain kernel LASTDATA_CONST
		assert(segKCDATACONSTB + segSizeKCDATACONST >= segLASTDATACONSTB + segSizeLASTDATACONST);
		segPLKDATACONSTB = segLASTDATACONSTB + segSizeLASTDATACONST;
		segSizePLKDATACONST = segSizeKCDATACONST - (segPLKDATACONSTB - segKCDATACONSTB);

		// fileset has kext PRELINK_DATA under kernel collection DATA following kernel's empty PRELINK_DATA
		segKCDATAB      = (vm_offset_t) getsegdatafromheader(kc_mh, "__DATA", &segSizeKCDATA);
		assert(segPRELINKDATAB && !segSizePRELINKDATA);                        // kernel PRELINK_DATA must be empty
		assert(segKCDATAB <= segPRELINKDATAB);                                 // KC DATA must contain kernel PRELINK_DATA
		assert(segKCDATAB + segSizeKCDATA >= segPRELINKDATAB + segSizePRELINKDATA);
		segSizePRELINKDATA = segSizeKCDATA - (segPRELINKDATAB - segKCDATAB);

		// fileset has consolidated PRELINK_TEXT, PRELINK_INFO and LINKEDIT at the kernel collection level
		assert(segPRELINKTEXTB && !segSizePRELINKTEXT);                        // kernel PRELINK_TEXT must be empty
		segPRELINKTEXTB = (vm_offset_t) getsegdatafromheader(kc_mh, "__PRELINK_TEXT", &segSizePRELINKTEXT);
		assert(segPRELINKINFOB && !segSizePRELINKINFO);                        // kernel PRELINK_INFO must be empty
		segPRELINKINFOB = (vm_offset_t) getsegdatafromheader(kc_mh, "__PRELINK_INFO", &segSizePRELINKINFO);
		segLINKB        = (vm_offset_t) getsegdatafromheader(kc_mh, "__LINKEDIT", &segSizeLINK);
	}

	/* if one of the new segments is present, the other one better be as well */
	if (segSizePLKDATACONST || segSizePLKTEXTEXEC) {
		assert(segSizePLKDATACONST && segSizePLKTEXTEXEC);
	}

	etext = (vm_offset_t) segTEXTB + segSizeTEXT;
	sdata = (vm_offset_t) segDATAB;
	edata = (vm_offset_t) segDATAB + segSizeDATA;
	end_kern = round_page(segHIGHESTKC ? segHIGHESTKC : getlastkerneladdr()); /* Force end to next page */

	vm_set_page_size();

	vm_kernel_base = segTEXTB;
	vm_kernel_top = (vm_offset_t) &last_kernel_symbol;
	vm_kext_base = segPRELINKTEXTB;
	vm_kext_top = vm_kext_base + segSizePRELINKTEXT;

	vm_prelink_stext = segPRELINKTEXTB;
	if (!segSizePLKTEXTEXEC && !segSizePLKDATACONST) {
		vm_prelink_etext = segPRELINKTEXTB + segSizePRELINKTEXT;
	} else {
		vm_prelink_etext = segPRELINKTEXTB + segSizePRELINKTEXT + segSizePLKDATACONST + segSizePLKTEXTEXEC;
	}
	vm_prelink_sinfo = segPRELINKINFOB;
	vm_prelink_einfo = segPRELINKINFOB + segSizePRELINKINFO;
	vm_slinkedit = segLINKB;
	vm_elinkedit = segLINKB + segSizeLINK;

	vm_prelink_sdata = segPRELINKDATAB;
	vm_prelink_edata = segPRELINKDATAB + segSizePRELINKDATA;

	arm_vm_prot_init(args);

	/**
	 * Count the number of pages the boot kernelcache occupies.  Additionally,
	 * ml_static_mfree() uses the BootKC ranges from the DT to account for freed kernelcache pages.
	 */
	vm_page_kernelcache_count = arm_get_bootkc_ranges_from_DT(&arm_vm_kernelcache_ranges, &arm_vm_kernelcache_numranges);

	assert(vm_page_kernelcache_count > 0);

#if KASAN
	/* record the extent of the physmap */
	physmap_vbase = physmap_base;
	physmap_vtop = physmap_end;
	kasan_init();
#endif /* KASAN */

#if CONFIG_CPU_COUNTERS
	mt_early_init();
#endif /* CONFIG_CPU_COUNTERS */

	kva_active = TRUE;

	if (arm_vm_auxkc_init()) {
		if (segLOWESTROAuxKC < segLOWESTRO) {
			segLOWESTRO = segLOWESTROAuxKC;
		}
		if (segHIGHESTROAuxKC > segHIGHESTRO) {
			segHIGHESTRO = segHIGHESTROAuxKC;
		}
		if (segLOWESTRXAuxKC < segLOWESTTEXT) {
			segLOWESTTEXT = segLOWESTRXAuxKC;
		}
		assert(segLOWEST == segLOWESTAuxKC);
	}

	sane_size = mem_size - (avail_start - gPhysBase);
	max_mem = mem_size;
	// vm_kernel_slide is set by arm_init()->arm_slide_rebase_and_sign_image()
	vm_kernel_slid_base = segLOWESTTEXT;
	vm_kernel_stext = segTEXTB;

	if (kernel_mach_header_is_in_fileset(&_mh_execute_header)) {
		vm_kernel_etext = segTEXTEXECB + segSizeTEXTEXEC;
		vm_kernel_slid_top = vm_slinkedit;
	} else {
		assert(segDATACONSTB == segTEXTB + segSizeTEXT);
		assert(segTEXTEXECB == segDATACONSTB + segSizeDATACONST);
		vm_kernel_etext = segTEXTB + segSizeTEXT + segSizeDATACONST + segSizeTEXTEXEC;
		vm_kernel_slid_top = vm_prelink_einfo;
	}

	/**
	 * Calculate the address ranges used to determine whether an address is an
	 * SPTM or TXM address, as well as the slides used to slide/unslide those
	 * addresses.
	 *
	 * The debug header contains pointers to the beginning of the images loaded
	 * up by iBoot (which always start with the Mach-O header). The __TEXT
	 * segment should be the first (and lowest) segment in both of these
	 * binaries (the addresses in the Mach-O header are all unslid).
	 */
	init_image_offsets(DEBUG_HEADER_ENTRY_SPTM, &vm_sptm_offsets);
	init_image_offsets(DEBUG_HEADER_ENTRY_TXM, &vm_txm_offsets);

	dynamic_memory_begin = ROUND_TWIG(dynamic_memory_begin);

	/* TODO: CONFIG_XNUPOST CTRR test */

	pmap_bootstrap(dynamic_memory_begin);

	disable_preemption();

	/*
	 * Initialize l3 page table pages :
	 *   cover this address range:
	 *    2MB + FrameBuffer size + 10MB for each 256MB segment
	 *
	 * Note: This does not allocate L3 page tables, since page tables for all static
	 *       memory is allocated and inserted into the hierarchy by the SPTM beforehand.
	 *       Instead, this code simply walks the page tables to find those pre-allocated
	 *       tables and allocates PTD objects for them.
	 */

	mem_segments = (mem_size + 0x0FFFFFFF) >> 28;

	va_l1 = dynamic_memory_begin;
	va_l1_end = va_l1 + ((2 + (mem_segments * 10)) << 20);
	va_l1_end += round_page(args->Video.v_height * args->Video.v_rowBytes);
	va_l1_end = (va_l1_end + 0x00000000007FFFFFULL) & 0xFFFFFFFFFF800000ULL;

	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while (va_l1 < va_l1_end) {
		va_l2 = va_l1;

		if (((va_l1 & ~ARM_TT_L1_OFFMASK) + ARM_TT_L1_SIZE) < va_l1) {
			/* If this is the last L1 entry, it must cover the last mapping. */
			va_l2_end = va_l1_end;
		} else {
			va_l2_end = MIN((va_l1 & ~ARM_TT_L1_OFFMASK) + ARM_TT_L1_SIZE, va_l1_end);
		}

		cpu_l2_tte = ((tt_entry_t *) phystokv(((*cpu_l1_tte) & ARM_TTE_TABLE_MASK))) + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);

		while (va_l2 < va_l2_end) {
			/* Obtain pre-allocated page and setup L3 Table TTE in L2 */
			tt_entry_t *ttp = pmap_tt2e(kernel_pmap, va_l2);
			pt_entry_t *ptp = (pt_entry_t *)phystokv(tte_to_pa(*ttp));
			pmap_init_pte_page(kernel_pmap, ptp, va_l2, 3, TRUE);

			va_l2 += ARM_TT_L2_SIZE;
			cpu_l2_tte++;
		}

		va_l1 = va_l2_end;
		cpu_l1_tte++;
	}

	/*
	 * Initialize l3 page table pages :
	 *   cover this address range:
	 *   ((VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK) - PE_EARLY_BOOT_VA) to VM_MAX_KERNEL_ADDRESS
	 *
	 * Note: This does not allocate L3 page tables, since page tables for all static
	 *       memory is allocated and inserted into the hierarchy by the SPTM beforehand.
	 *       Instead, this code simply walks the page tables to find those pre-allocated
	 *       tables and allocates PTD objects for them.
	 */
	va_l1 = (VM_MAX_KERNEL_ADDRESS & CPUWINDOWS_BASE_MASK) - PE_EARLY_BOOT_VA;
	va_l1_end = VM_MAX_KERNEL_ADDRESS;

	cpu_l1_tte = cpu_tte + ((va_l1 & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT);

	while (va_l1 < va_l1_end) {
		va_l2 = va_l1;

		if (((va_l1 & ~ARM_TT_L1_OFFMASK) + ARM_TT_L1_SIZE) < va_l1) {
			/* If this is the last L1 entry, it must cover the last mapping. */
			va_l2_end = va_l1_end;
		} else {
			va_l2_end = MIN((va_l1 & ~ARM_TT_L1_OFFMASK) + ARM_TT_L1_SIZE, va_l1_end);
		}

		cpu_l2_tte = ((tt_entry_t *) phystokv(((*cpu_l1_tte) & ARM_TTE_TABLE_MASK))) + ((va_l2 & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT);

		while (va_l2 < va_l2_end) {
			/* Obtain pre-allocated page and setup L3 Table TTE in L2 */
			tt_entry_t *ttp = pmap_tt2e(kernel_pmap, va_l2);
			pt_entry_t *ptp = (pt_entry_t *)phystokv(tte_to_pa(*ttp));
			pmap_init_pte_page(kernel_pmap, ptp, va_l2, 3, TRUE);

			va_l2 += ARM_TT_L2_SIZE;
			cpu_l2_tte++;
		}

		va_l1 = va_l2_end;
		cpu_l1_tte++;
	}

	/*
	 * Adjust avail_start so that the range that the VM owns
	 * starts on a PAGE_SIZE aligned boundary.
	 */
	avail_start = (avail_start + PAGE_MASK) & ~PAGE_MASK;

	/* TODO pmap_static_allocations_done() */

	first_avail = avail_start;
	patch_low_glo_static_region(first_avail_phys, avail_start - first_avail_phys);
	enable_preemption();
}

/*
 * Returns true if the address lies within __TEXT, __TEXT_EXEC or __DATA_CONST
 * segment range. This is what [vm_kernel_stext, vm_kernel_etext) used to cover.
 * The segments together may not make a continuous address space anymore and so
 * individual intervals are inspected.
 */
bool
kernel_text_contains(vm_offset_t addr)
{
	if (segTEXTB <= addr && addr < (segTEXTB + segSizeTEXT)) {
		return true;
	}
	if (segTEXTEXECB <= addr && addr < (segTEXTEXECB + segSizeTEXTEXEC)) {
		return true;
	}
	return segDATACONSTB <= addr && addr < (segDATACONSTB + segSizeDATACONST);
}
