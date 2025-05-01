/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <arm64/pac_asm.h>
#include <pexpert/arm64/board_config.h>
#include "assym.s"


#if XNU_MONITOR
/*
 * Exit path defines; for controlling PPL -> kernel transitions.
 * These should fit within a 32-bit integer, as the PPL trampoline packs them into a 32-bit field.
 */
#define PPL_EXIT_DISPATCH   0 /* This is a clean exit after a PPL request. */
#define PPL_EXIT_PANIC_CALL 1 /* The PPL has called panic. */
#define PPL_EXIT_BAD_CALL   2 /* The PPL request failed. */
#define PPL_EXIT_EXCEPTION  3 /* The PPL took an exception. */

#define KERNEL_MODE_ELR      ELR_GL11
#define KERNEL_MODE_FAR      FAR_GL11
#define KERNEL_MODE_ESR      ESR_GL11
#define KERNEL_MODE_SPSR     SPSR_GL11
#define KERNEL_MODE_VBAR     VBAR_GL11
#define KERNEL_MODE_TPIDR    TPIDR_GL11

#define GUARDED_MODE_ELR     ELR_EL1
#define GUARDED_MODE_FAR     FAR_EL1
#define GUARDED_MODE_ESR     ESR_EL1
#define GUARDED_MODE_SPSR    SPSR_EL1
#define GUARDED_MODE_VBAR    VBAR_EL1
#define GUARDED_MODE_TPIDR   TPIDR_EL1

/*
 * LOAD_PMAP_CPU_DATA
 *
 * Loads the PPL per-CPU data array entry for the current CPU.
 *   arg0 - Address of the PPL per-CPU data is returned through this
 *   arg1 - Scratch register
 *   arg2 - Scratch register
 *
 */
.macro LOAD_PMAP_CPU_DATA
	/* Get the CPU ID. */
	mrs		$0, MPIDR_EL1
	ubfx	$1, $0, MPIDR_AFF1_SHIFT, MPIDR_AFF1_WIDTH
	adrp	$2, EXT(cluster_offsets)@page
	add		$2, $2, EXT(cluster_offsets)@pageoff
	ldr		$1, [$2, $1, lsl #3]

	and		$0, $0, MPIDR_AFF0_MASK
	add		$0, $0, $1

	/* Get the PPL CPU data array. */
	adrp	$1, EXT(pmap_cpu_data_array)@page
	add		$1, $1, EXT(pmap_cpu_data_array)@pageoff

	/*
	 * Sanity check the CPU ID (this is not a panic because this pertains to
	 * the hardware configuration; this should only fail if our
	 * understanding of the hardware is incorrect).
	 */
	cmp		$0, MAX_CPUS
	b.hs	.

	mov		$2, PMAP_CPU_DATA_ARRAY_ENTRY_SIZE
	/* Get the PPL per-CPU data. */
	madd	$0, $0, $2, $1
.endmacro

/*
 * GET_PMAP_CPU_DATA
 *
 * Retrieves the PPL per-CPU data for the current CPU.
 *   arg0 - Address of the PPL per-CPU data is returned through this
 *   arg1 - Scratch register
 *   arg2 - Scratch register
 *
 */
.macro GET_PMAP_CPU_DATA
	LOAD_PMAP_CPU_DATA $0, $1, $2
.endmacro

#endif /* XNU_MONITOR */

/*
 * INIT_SAVED_STATE_FLAVORS
 *
 * Initializes the saved state flavors of a new saved state structure
 *  arg0 - saved state pointer
 *  arg1 - 32-bit scratch reg
 *  arg2 - 32-bit scratch reg
 */
.macro INIT_SAVED_STATE_FLAVORS
	mov		$1, ARM_SAVED_STATE64                                   // Set saved state to 64-bit flavor
	mov		$2, ARM_SAVED_STATE64_COUNT
	stp		$1, $2, [$0, SS_FLAVOR]
	mov		$1, ARM_NEON_SAVED_STATE64                              // Set neon state to 64-bit flavor
	str		$1, [$0, NS_FLAVOR]
	mov		$1, ARM_NEON_SAVED_STATE64_COUNT
	str		$1, [$0, NS_COUNT]
.endmacro

/*
 * SPILL_REGISTERS
 *
 * Spills the current set of registers (excluding x0, x1, sp as well as x2, x3
 * in KERNEL_MODE) to the specified save area.
 *
 * On CPUs with PAC, the kernel "A" keys are used to create a thread signature.
 * These keys are deliberately kept loaded into the CPU for later kernel use.
 *
 *   arg0 - KERNEL_MODE or HIBERNATE_MODE
 *   arg1 - ADD_THREAD_SIGNATURE or POISON_THREAD_SIGNATURE
 *   x0 - Address of the save area
 *   x25 - Return the value of FPCR
 */
#define KERNEL_MODE 0
#define HIBERNATE_MODE 1

/** When set, the thread will be given an invalid thread signature */
#define SPILL_REGISTERS_OPTION_POISON_THREAD_SIGNATURE_SHIFT	(0)
#define SPILL_REGISTERS_OPTION_POISON_THREAD_SIGNATURE \
	(1 << SPILL_REGISTERS_OPTION_POISON_THREAD_SIGNATURE_SHIFT)
/** When set, ELR and FAR will not be spilled */
#define SPILL_REGISTERS_OPTION_DONT_SPILL_ELR_FAR_SHIFT			(1)
#define SPILL_REGISTERS_OPTION_DONT_SPILL_ELR_FAR \
	(1 << SPILL_REGISTERS_OPTION_DONT_SPILL_ELR_FAR_SHIFT)

#define FLEH_DISPATCH64_OPTION_SYNC_EXCEPTION 0
#if CONFIG_SPTM
#undef FLEH_DISPATCH64_OPTION_SYNC_EXCEPTION
#define FLEH_DISPATCH64_OPTION_SYNC_EXCEPTION \
	(SPILL_REGISTERS_OPTION_DONT_SPILL_ELR_FAR)
#endif /* CONFIG_SPTM */

#define FLEH_DISPATCH64_OPTION_FATAL_EXCEPTION \
	(SPILL_REGISTERS_OPTION_POISON_THREAD_SIGNATURE)

#define FLEH_DISPATCH64_OPTION_FATAL_SYNC_EXCEPTION \
	(FLEH_DISPATCH64_OPTION_FATAL_EXCEPTION | \
	 FLEH_DISPATCH64_OPTION_SYNC_EXCEPTION)

#define FLEH_DISPATCH64_OPTION_NONE 0

.macro SPILL_REGISTERS	mode options_register=
	/* Spill remaining GPRs */
	.if \mode != KERNEL_MODE
	stp		x2, x3, [x0, SS64_X2]
	.endif
	stp		x4, x5, [x0, SS64_X4]
	stp		x6, x7, [x0, SS64_X6]
	stp		x8, x9, [x0, SS64_X8]
	stp		x10, x11, [x0, SS64_X10]
	stp		x12, x13, [x0, SS64_X12]
	stp		x14, x15, [x0, SS64_X14]
	stp		x16, x17, [x0, SS64_X16]
	stp		x18, x19, [x0, SS64_X18]
	stp		x20, x21, [x0, SS64_X20]
	stp		x22, x23, [x0, SS64_X22]
	stp		x24, x25, [x0, SS64_X24]
	stp		x26, x27, [x0, SS64_X26]
	stp		x28, fp,  [x0, SS64_X28]
	str		lr, [x0, SS64_LR]

	/* Save arm_neon_saved_state64 */
	stp		q0, q1, [x0, NS64_Q0]
	stp		q2, q3, [x0, NS64_Q2]
	stp		q4, q5, [x0, NS64_Q4]
	stp		q6, q7, [x0, NS64_Q6]
	stp		q8, q9, [x0, NS64_Q8]
	stp		q10, q11, [x0, NS64_Q10]
	stp		q12, q13, [x0, NS64_Q12]
	stp		q14, q15, [x0, NS64_Q14]
	stp		q16, q17, [x0, NS64_Q16]
	stp		q18, q19, [x0, NS64_Q18]
	stp		q20, q21, [x0, NS64_Q20]
	stp		q22, q23, [x0, NS64_Q22]
	stp		q24, q25, [x0, NS64_Q24]
	stp		q26, q27, [x0, NS64_Q26]
	stp		q28, q29, [x0, NS64_Q28]
	stp		q30, q31, [x0, NS64_Q30]
	mrs		x24, FPSR
	str		w24, [x0, NS64_FPSR]
	mrs		x25, FPCR
	str		w25, [x0, NS64_FPCR]
Lsave_neon_state_done_\@:

	mrs		x22, ELR_EL1                                                     // Get exception link register
	mrs		x23, SPSR_EL1                                                   // Load CPSR into var reg x23

#if defined(HAS_APPLE_PAC)
	.if \mode != HIBERNATE_MODE

.ifnb \options_register
	tbnz	\options_register, SPILL_REGISTERS_OPTION_POISON_THREAD_SIGNATURE_SHIFT, Lspill_registers_do_poison_\@
.endif /* options_register */

	/* Save x1 and LR to preserve across call */
	mov		x21, x1
	mov		x20, lr

	/*
	 * Create thread state signature
	 *
	 * Arg0: The ARM context pointer
	 * Arg1: The PC value to sign
	 * Arg2: The CPSR value to sign
	 * Arg3: The LR value to sign
	 * Arg4: The X16 value to sign
	 * Arg5: The X17 value to sign
	 */
	mov		x1, x22
	mov		w2, w23
	mov		x3, x20
	mov		x4, x16
	mov		x5, x17

	mrs		x19, SPSel
	msr		SPSel, #1
	bl		_ml_sign_thread_state
	/* ml_sign_thread_state has special ABI, overwrites x1, x2, x17 */
	mov		x17, x5
	msr		SPSel, x19
	mov		lr, x20
	mov		x1, x21
.ifnb \options_register
	b		Lspill_registers_poison_continue_\@

Lspill_registers_do_poison_\@:
	mov		x21, #-1
	str		x21, [x0, SS64_JOPHASH]

Lspill_registers_poison_continue_\@:
.endif /* options_register */

	.endif
#endif /* defined(HAS_APPLE_PAC) */

	mrs		x20, FAR_EL1
	mrs		x21, ESR_EL1

.ifnb \options_register
	tbnz	\options_register, SPILL_REGISTERS_OPTION_DONT_SPILL_ELR_FAR_SHIFT, Lspill_registers_skip_elr_far_\@
.endif /* options_register != NONE */

	str		x20, [x0, SS64_FAR]
	str		x22, [x0, SS64_PC]

.ifnb \options_register
Lspill_registers_skip_elr_far_\@:
.endif /* options_register != NONE */
	str		w21, [x0, SS64_ESR]
	str		w23, [x0, SS64_CPSR]
.endmacro

.macro DEADLOOP
	b	.
.endmacro

/**
 * Reloads SP with the current thread's interrupt stack.
 *
 * SP0 is expected to already be selected.  Clobbers x1 and tmp.
 */
.macro SWITCH_TO_INT_STACK	tmp
	mrs		x1, TPIDR_EL1
	LOAD_INT_STACK_THREAD	dst=x1, src=x1, tmp=\tmp
	mov		sp, x1			// Set the stack pointer to the interrupt stack
.endmacro

#if HAS_ARM_FEAT_SME
/*
 * LOAD_OR_STORE_Z_P_REGISTERS - loads or stores the Z and P register files
 *
 * instr: ldr or str
 * svl_b: register containing SVL_B
 * ss: register pointing to save area of size 34 * SVL_B (clobbered)
 */
.macro LOAD_OR_STORE_Z_P_REGISTERS	instr, svl_b, ss
	\instr	z0, [\ss, #0, mul vl]
	\instr	z1, [\ss, #1, mul vl]
	\instr	z2, [\ss, #2, mul vl]
	\instr	z3, [\ss, #3, mul vl]
	\instr	z4, [\ss, #4, mul vl]
	\instr	z5, [\ss, #5, mul vl]
	\instr	z6, [\ss, #6, mul vl]
	\instr	z7, [\ss, #7, mul vl]
	\instr	z8, [\ss, #8, mul vl]
	\instr	z9, [\ss, #9, mul vl]
	\instr	z10, [\ss, #10, mul vl]
	\instr	z11, [\ss, #11, mul vl]
	\instr	z12, [\ss, #12, mul vl]
	\instr	z13, [\ss, #13, mul vl]
	\instr	z14, [\ss, #14, mul vl]
	\instr	z15, [\ss, #15, mul vl]
	\instr	z16, [\ss, #16, mul vl]
	\instr	z17, [\ss, #17, mul vl]
	\instr	z18, [\ss, #18, mul vl]
	\instr	z19, [\ss, #19, mul vl]
	\instr	z20, [\ss, #20, mul vl]
	\instr	z21, [\ss, #21, mul vl]
	\instr	z22, [\ss, #22, mul vl]
	\instr	z23, [\ss, #23, mul vl]
	\instr	z24, [\ss, #24, mul vl]
	\instr	z25, [\ss, #25, mul vl]
	\instr	z26, [\ss, #26, mul vl]
	\instr	z27, [\ss, #27, mul vl]
	\instr	z28, [\ss, #28, mul vl]
	\instr	z29, [\ss, #29, mul vl]
	\instr	z30, [\ss, #30, mul vl]
	\instr	z31, [\ss, #31, mul vl]

	add		\ss, \ss, \svl_b, lsl #5
	\instr	p0, [\ss, #0, mul vl]
	\instr	p1, [\ss, #1, mul vl]
	\instr	p2, [\ss, #2, mul vl]
	\instr	p3, [\ss, #3, mul vl]
	\instr	p4, [\ss, #4, mul vl]
	\instr	p5, [\ss, #5, mul vl]
	\instr	p6, [\ss, #6, mul vl]
	\instr	p7, [\ss, #7, mul vl]
	\instr	p8, [\ss, #8, mul vl]
	\instr	p9, [\ss, #9, mul vl]
	\instr	p10, [\ss, #10, mul vl]
	\instr	p11, [\ss, #11, mul vl]
	\instr	p12, [\ss, #12, mul vl]
	\instr	p13, [\ss, #13, mul vl]
	\instr	p14, [\ss, #14, mul vl]
	\instr	p15, [\ss, #15, mul vl]
.endmacro
#endif /* HAS_ARM_FEAT_SME */
