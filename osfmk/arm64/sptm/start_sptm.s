/**
 * Copyright (c) 2022-2024 Apple Inc. All rights reserved.
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

#include <machine/asm.h>
#include <arm64/exception_asm.h>
#include <arm64/dwarf_unwind.h>
#include <sptm/sptm_xnu.h>

/**
 * XNU entry point.
 *
 * The SPTM jumps here as part of both the cold and warm boot paths, for all
 * CPUs. This entry point is also jumped to when the SPTM wants to trigger the
 * XNU panic path.
 *
 * @param x0 Sentinel value describing why we jumped to this entry point:
 *           SPTM_CPU_BOOT_COLD: Cold boot path.
 *           SPTM_CPU_BOOT_WARM: Warm boot path.
 *           SPTM_CPU_BOOT_SECONDARY: Secondary CPU boot path.
 *           SPTM_CPU_BOOT_HIB: Hibernation exit path.
 *           SPTM_CPU_PANIC: A panic condition was triggered in SPTM/TXM/cL4.
 *
 * The possible values of the rest of the argument registers are dependent on
 * the sentinel value in x0.
 *
 * If x0 is SPTM_CPU_PANIC:
 * @param x1 A pointer to the panic string.
 * @param x2 A boolean defining whether XNU should attempt a local coredump or
 *           not. If this is false, then the SPTM is in a state that trying to
 *           generate a coredump will most likely trigger more panics (seeing as
 *           the NVMe driver will need to call into the SPTM).
 *
 * Otherwise:
 * @param x1 iBoot boot arguments.
 * @param x2 SPTM boot arguments.
 *
 * @note The SPTM initially only maps the __TEXT_BOOT_EXEC segment
 *       as RX, and does not remap the rest of the code as RX until
 *       after the XNU fixups phase has been completed. Since this
 *       is the entry point, it must be made executable from the
 *       very start.
 */
	.section __TEXT_BOOT_EXEC, __bootcode, regular, pure_instructions
	.align 14
	.globl EXT(_start)
LEXT(_start)
	ARM64_PROLOG
	/**
	 * When SPTM/TXM/cL4 panics, it jumps to the XNU entry point with a special
	 * sentinel value placed into x0. Let's check for that and jump to the
	 * standard panic function if so.
	 */
	mov		x8, #SPTM_CPU_PANIC
	cmp		x0, x8
	b.ne	start_boot_path

	/**
	 * Set global variable to tell panic path whether the SPTM supports
	 * generating a local coredump. This can be disabled based on the SPTM's
	 * build flags or determined at runtime.
	 */
	adrp	x8, EXT(sptm_supports_local_coredump)@page
	strb	w2, [x8, EXT(sptm_supports_local_coredump)@pageoff]

	/* The panic string is in x1, but the panic function expects it as the first argument. */
	mov		x0, x1
	b		EXT(panic_from_sptm)

	/* Should never reach here as we should have panicked. */
	b		.

start_boot_path:
	/* Clear thread pointers */
	msr		TPIDR_EL1, xzr
	msr		TPIDRRO_EL0, xzr

#if HAS_CLUSTER && !NO_CPU_OVRD
	/* Unmask external IRQs if we're restarting from non-retention WFI */
	mrs		x9, CPU_OVRD
	and		x9, x9, #(~(ARM64_REG_CYC_OVRD_irq_mask | ARM64_REG_CYC_OVRD_fiq_mask))
	msr		CPU_OVRD, x9
#endif

	/* Jump to the correct start routine */
	mov		x20, #SPTM_CPU_BOOT_COLD
	cmp		x0, x20
	b.eq	start_cold
	/*
	 * Note that on hibernation resume, we take the warm boot path, as SPTM already
	 * initialized VBAR_EL1 in sptm_init_cpu_registers, called from sptm_resume_cpu.
	 */
	b		start_warm

/**
 * Cold boot path.
 */
start_cold:
	/* Set up exception stack */
	msr		SPSel, #1
	adrp	x10, EXT(excepstack_top)@page
	add		x10, x10, EXT(excepstack_top)@pageoff
	mov		sp, x10

	/* Set up IRQ stack */
	msr		SPSel, #0
	adrp	x10, EXT(intstack_top)@page
	add		x10, x10, EXT(intstack_top)@pageoff
	mov		sp, x10

	/* Save off boot arguments */
	mov x26, x1
	mov x27, x2

	/* Rebase and sign absolute addresses */
	bl EXT(arm_slide_rebase_and_sign_image)

	mov		x0, x26
	bl EXT(arm_static_if_init)

	/**
	 * Now setup final XNU exception vectors. This is the closest we can do this
	 * in XNU because after sending SPTM SPTM_FUNCTIONID_FIXUPS_COMPLETE, VBAR
	 * will be validated and locked.
	 */
	adrp	x9, EXT(ExceptionVectorsBase)@page
	add		x9, x9, EXT(ExceptionVectorsBase)@pageoff
	msr		VBAR_EL1, x9
	isb

	/**
	 * Call into the SPTM for the first time. This function traps to GL2 to
	 * signal the SPTM that the fixups phase has been completed.
	 */
	SPTM_LOAD_DISPATCH_ID SPTM_DOMAIN, SPTM_DISPATCH_TABLE_XNU_BOOTSTRAP, SPTM_FUNCTIONID_FIXUPS_COMPLETE
	SPTM_DOMAIN_ENTER	x16

	/**
	 * At this point, the SPTM has retyped the RX region to SPTM_XNU_CODE.
	 */

	/* Jump to handler */
	mov		x0, x26
	mov		x1, x27
#if KASAN
	b		EXT(arm_init_kasan)
#else
	b		EXT(arm_init)
#endif /* KASAN */

/**
 * Secondary CPU boot path.
 */
start_warm:
	/* Save the hibernation arguments pointer in x20 */
	mov		x20, x3

#if HAS_BP_RET
	bl		EXT(set_bp_ret)
#endif

	/**
	 * Search for the correct CPU Data entry.
	 * This works by iterating over the per-CPU data array,
	 * searching for the entry who's physical CPU ID matches
	 * the physical ID extracted from this CPU's MPIDR_EL1.
	 *
	 * x1 is initially set to the first entry in the per-CPU data
	 * array.
	 */

	/* Get CPU physical ID */
	mrs		x15, MPIDR_EL1
#if HAS_CLUSTER
	and		x0, x15, #(MPIDR_AFF0_MASK | MPIDR_AFF1_MASK)
#else
	and		x0, x15, #(MPIDR_AFF0_MASK)
#endif

	adrp	x1, EXT(CpuDataEntries)@page
	add		x1, x1, EXT(CpuDataEntries)@pageoff

	MOV64	x19, CPU_DATA_SIZE
	mov		x4, MAX_CPUS

	/* Set x3 to the end of the per-CPU data array (exclusive) */
	mul		x3, x19, x4
	add		x3, x1, x3

	/**
	 * Use x1 as the cursor, and stop when we have either found
	 * an entry, or when we have finished traversing the array.
	 */
check_cpu_data_entry:
	/* Load physical CPU data address */
	ldr		x21, [x1, CPU_DATA_VADDR]
	cbz		x21, .

	/* Attempt to match the physical CPU ID */
	ldr		w2, [x21, CPU_PHYS_ID]
	cmp		x0, x2
	b.eq	found_cpu_data_entry
next_cpu_data_entry:
	/* Move onto the next element in the array, if it exists */
	add		x1, x1, x19
	cmp		x1, x3
	b.eq	cpu_data_entry_not_found
	b		check_cpu_data_entry

/* An entry was found */
found_cpu_data_entry:
	/* Set up exception stack */
	msr		SPSel, #1
	ldr		x10, [x21, CPU_EXCEPSTACK_TOP]
	mov		sp, x10

	/* Set up IRQ stack */
	msr		SPSel, #0
	ldr		x10, [x21, CPU_INTSTACK_TOP]
	mov		sp, x10

	/* Set up input parameters to reset handler */
	mov		x0, x21
	mov		x1, x20

	/* Obtain reset handler */
	ldr		x2, [x21, CPU_RESET_HANDLER]
	cbz		x2, Lskip_cpu_reset_handler

	/* Validate that our handler is one of the two expected ones */
	adrp	x3, EXT(arm_init_cpu)@page
	add		x3, x3, EXT(arm_init_cpu)@pageoff
	cmp		x2, x3
	beq		1f

	adrp	x3, EXT(arm_init_idle_cpu)@page
	add		x3, x3, EXT(arm_init_idle_cpu)@pageoff
	cmp		x2, x3
	beq		2f

	/* No valid handler was found */
	b		Lskip_cpu_reset_handler

1:
	b		EXT(arm_init_cpu)
2:
	b		EXT(arm_init_idle_cpu)

/**
 * A valid reset handler was not found. This points to a bug in XNU.
 * It is unsafe to continue, so just spin here.
 */
Lskip_cpu_reset_handler:
	MOV64	x0, 0xDEADB001
	b		.

/**
 * An entry was not found. This points to a bug in XNU.
 * It is unsafe to continue, so just spin here.
 */
cpu_data_entry_not_found:
	MOV64	x0, 0xDEADB002
	b		.

/**
 * This is a stub function that calls the XNU panic entry point.
 * We push this frame onto the stack so that the LLDB unwinder
 * understands that the stack pointer has been changed when
 * unwinding a stack that has panicked in SPTM or TXM, for example.
 *
 * The SPTM_UNWIND_DIRECTIVES tell LLDB that the panic caller FP,
 * LR, SP, and PC are in a data structure pointed to by X21, which
 * is set by SPTM dispatch logic before handing control back to XNU
 * during a panic.
 */
	.section __TEXT_BOOT_EXEC, __bootcode, regular, pure_instructions
	.align 14
	.globl EXT(panic_from_sptm)
LEXT(panic_from_sptm)
TRAP_UNWIND_PROLOGUE
SPTM_UNWIND_DIRECTIVES
	ARM64_STACK_PROLOG
	PUSH_FRAME
	bl 		EXT(panic)
	b .
UNWIND_EPILOGUE
