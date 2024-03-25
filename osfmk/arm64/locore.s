/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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
#include <arm64/machine_machdep.h>
#include <arm64/machine_routines_asm.h>
#include <arm64/proc_reg.h>
#include <pexpert/arm64/board_config.h>
#include <mach/exception_types.h>
#include <mach_kdp.h>
#include <config_dtrace.h>
#include "assym.s"
#include <arm64/exception_asm.h>
#include "dwarf_unwind.h"

#if __ARM_KERNEL_PROTECT__
#include <arm/pmap.h>
#endif

#if XNU_MONITOR && !CONFIG_SPTM
/*
 * CHECK_EXCEPTION_RETURN_DISPATCH_PPL
 *
 * Checks if an exception was taken from the PPL, and if so, trampolines back
 * into the PPL.
 *   x26 - 0 if the exception was taken while in the kernel, 1 if the
 *         exception was taken while in the PPL.
 */
.macro CHECK_EXCEPTION_RETURN_DISPATCH_PPL
	cmp		x26, xzr
	b.eq		1f

	/* Return to the PPL. */
	mov		x15, #0
	mov		w10, #PPL_STATE_EXCEPTION
#error "XPRR configuration error"
1:
.endmacro


#endif /* XNU_MONITOR && !CONFIG_SPTM */

#if CONFIG_SPTM
#include <sptm/sptm_xnu.h>
#include <sptm/sptm_common.h>
/*
 * Panic lockdown is a security enhancement which makes certain types of
 * exceptions (generally, PAC failures and sync exceptions taken with async
 * exceptions masked) and panics fatal against attackers with kernel R/W. It
 * does this through a trapdoor panic bit protected by the SPTM. 
 * When this bit is set, TXM will refuse to authorize new code mappings which, 
 * ideally, renders the system unusable even if the attacker gains control over
 * XNU. Additionally, when this bit is set XNU will refuse to handle any sync
 * exceptions originating from user space. This makes implementing further stages
 * of an exploit challenging as it prevents user space from driving the kernel.
 */

/*
 * Inform the SPTM that XNU has (or, rather, must) panic. This is provided as a
 * macro rather than a function since it's just one instruction on release and 
 * it avoids the need to spill a return addresses unless the macro caller
 * explicitly needs to preserve LR.
 * 
 * This macro preserves callee saved registers but clobbers all others.
 */
.macro BEGIN_PANIC_LOCKDOWN
#if CONFIG_XNUPOST
	mrs		x8, TPIDR_EL1
	/* 
	 * If hitting this with a null TPIDR, it's likely that this was an unexpected
	 * exception in early boot rather than an expected one as a part of a test.
	 * Trigger lockdown.
	 */
	cbz		x8, 0f
	ldr		x8, [x8, TH_EXPECTED_FAULT_HANDLER]
	cbnz 	x8, 1f
0:
#endif /* CONFIG_XNUPOST */
	/*
	 * The sptm_xnu_panic_begin routine is guaranteed to unavoidably lead to
	 * the panic bit being set. 
	 */
	bl EXT(sptm_xnu_panic_begin)
#if CONFIG_XNUPOST
	b		2f
1:
	/* 
	 * We hit lockdown while an exception handler was installed. 
	 * This was likely an expected exception. Skip setting the panic bit (since 
	 * this will kill the system) and instead set a bit in the test handler.
	 */
	mov		w9, #1
	adrp	x8, EXT(xnu_post_panic_lockdown_did_fire)@page
	add		x8, x8, EXT(xnu_post_panic_lockdown_did_fire)@pageoff
	strb	w9, [x8]
	mov		lr, xzr // trash LR to ensure callers don't rely on it
2:
#endif /* CONFIG_XNUPOST */
.endmacro
#endif /* CONFIG_SPTM */

/*
 * MAP_KERNEL
 *
 * Restores the kernel EL1 mappings, if necessary.
 *
 * This may mutate x18.
 */
.macro MAP_KERNEL
#if __ARM_KERNEL_PROTECT__
	/* Switch to the kernel ASID (low bit set) for the task. */
	mrs		x18, TTBR0_EL1
	orr		x18, x18, #(1 << TTBR_ASID_SHIFT)
	msr		TTBR0_EL1, x18

	/*
	 * We eschew some barriers on Apple CPUs, as relative ordering of writes
	 * to the TTBRs and writes to the TCR should be ensured by the
	 * microarchitecture.
	 */
#if !defined(APPLE_ARM64_ARCH_FAMILY)
	isb		sy
#endif

	/*
	 * Update the TCR to map the kernel now that we are using the kernel
	 * ASID.
	 */
	MOV64		x18, TCR_EL1_BOOT
	msr		TCR_EL1, x18
	isb		sy
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro

/*
 * BRANCH_TO_KVA_VECTOR
 *
 * Branches to the requested long exception vector in the kernelcache.
 *   arg0 - The label to branch to
 *   arg1 - The index of the label in exc_vectors_tables
 *
 * This may mutate x18.
 */
.macro BRANCH_TO_KVA_VECTOR
#if __ARM_KERNEL_PROTECT__
	/*
	 * Find the kernelcache table for the exception vectors by accessing
	 * the per-CPU data.
	 */
	mrs		x18, TPIDR_EL1
	ldr		x18, [x18, ACT_CPUDATAP]
	ldr		x18, [x18, CPU_EXC_VECTORS]

	/*
	 * Get the handler for this exception and jump to it.
	 */
	ldr		x18, [x18, #($1 << 3)]
	br		x18
#else
	b		$0
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro

/*
 * CHECK_KERNEL_STACK
 *
 * Verifies that the kernel stack is aligned and mapped within an expected
 * stack address range. Note: happens before saving registers (in case we can't
 * save to kernel stack).
 *
 * Expects:
 *	{x0, x1} - saved
 *	x1 - Exception syndrome
 *	sp - Saved state
 *
 * Seems like we need an unused argument to the macro for the \@ syntax to work
 *
 */
.macro CHECK_KERNEL_STACK unused
	stp		x2, x3, [sp, #-16]!				// Save {x2-x3}
	and		x1, x1, #ESR_EC_MASK				// Mask the exception class
	mov		x2, #(ESR_EC_SP_ALIGN << ESR_EC_SHIFT)
	cmp		x1, x2								// If we have a stack alignment exception
	b.eq	Lcorrupt_stack_\@					// ...the stack is definitely corrupted
	mov		x2, #(ESR_EC_DABORT_EL1 << ESR_EC_SHIFT)
	cmp		x1, x2								// If we have a data abort, we need to
	b.ne	Lvalid_stack_\@						// ...validate the stack pointer
	mrs		x0, SP_EL0					// Get SP_EL0
	mrs		x1, TPIDR_EL1						// Get thread pointer
Ltest_kstack_\@:
	LOAD_KERN_STACK_TOP	dst=x2, src=x1, tmp=x3	// Get top of kernel stack
	sub		x3, x2, KERNEL_STACK_SIZE			// Find bottom of kernel stack
	cmp		x0, x2								// if (SP_EL0 >= kstack top)
	b.ge	Ltest_istack_\@						//    jump to istack test
	cmp		x0, x3								// if (SP_EL0 > kstack bottom)
	b.gt	Lvalid_stack_\@						//    stack pointer valid
Ltest_istack_\@:
	ldr		x1, [x1, ACT_CPUDATAP]				// Load the cpu data ptr
	ldr		x2, [x1, CPU_INTSTACK_TOP]			// Get top of istack
	sub		x3, x2, INTSTACK_SIZE_NUM			// Find bottom of istack
	cmp		x0, x2								// if (SP_EL0 >= istack top)
	b.ge	Lcorrupt_stack_\@					//    corrupt stack pointer
	cmp		x0, x3								// if (SP_EL0 > istack bottom)
	b.gt	Lvalid_stack_\@						//    stack pointer valid
Lcorrupt_stack_\@:
	ldp		x2, x3, [sp], #16
	ldp		x0, x1, [sp], #16
	sub		sp, sp, ARM_CONTEXT_SIZE			// Allocate exception frame
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to the exception frame
	stp		x2, x3, [sp, SS64_X2]				// Save x2, x3 to the exception frame
	mrs		x0, SP_EL0					// Get SP_EL0
	str		x0, [sp, SS64_SP]				// Save sp to the exception frame
	INIT_SAVED_STATE_FLAVORS sp, w0, w1
	mov		x0, sp								// Copy exception frame pointer to x0
	adrp	x1, fleh_invalid_stack@page			// Load address for fleh
	add		x1, x1, fleh_invalid_stack@pageoff	// fleh_dispatch64 will save register state before we get there
	b		fleh_dispatch64_noreturn
Lvalid_stack_\@:
	ldp		x2, x3, [sp], #16			// Restore {x2-x3}
.endmacro


#if __ARM_KERNEL_PROTECT__
	.section __DATA_CONST,__const
	.align 3
	.globl EXT(exc_vectors_table)
LEXT(exc_vectors_table)
	/* Table of exception handlers.
         * These handlers sometimes contain deadloops. 
         * It's nice to have symbols for them when debugging. */
	.quad el1_sp0_synchronous_vector_long
	.quad el1_sp0_irq_vector_long
	.quad el1_sp0_fiq_vector_long
	.quad el1_sp0_serror_vector_long
	.quad el1_sp1_synchronous_vector_long
	.quad el1_sp1_irq_vector_long
	.quad el1_sp1_fiq_vector_long
	.quad el1_sp1_serror_vector_long
	.quad el0_synchronous_vector_64_long
	.quad el0_irq_vector_64_long
	.quad el0_fiq_vector_64_long
	.quad el0_serror_vector_64_long
#endif /* __ARM_KERNEL_PROTECT__ */

	.text
#if __ARM_KERNEL_PROTECT__
	/*
	 * We need this to be on a page boundary so that we may avoiding mapping
	 * other text along with it.  As this must be on the VM page boundary
	 * (due to how the coredumping code currently works), this will be a
	 * 16KB page boundary.
	 */
	.align 14
#else
	.align 12
#endif /* __ARM_KERNEL_PROTECT__ */
	.globl EXT(ExceptionVectorsBase)
LEXT(ExceptionVectorsBase)
Lel1_sp0_synchronous_vector:
	BRANCH_TO_KVA_VECTOR el1_sp0_synchronous_vector_long, 0

	.text
	.align 7
Lel1_sp0_irq_vector:
	BRANCH_TO_KVA_VECTOR el1_sp0_irq_vector_long, 1

	.text
	.align 7
Lel1_sp0_fiq_vector:
	BRANCH_TO_KVA_VECTOR el1_sp0_fiq_vector_long, 2

	.text
	.align 7
Lel1_sp0_serror_vector:
	BRANCH_TO_KVA_VECTOR el1_sp0_serror_vector_long, 3

	.text
	.align 7
Lel1_sp1_synchronous_vector:
	BRANCH_TO_KVA_VECTOR el1_sp1_synchronous_vector_long, 4

	.text
	.align 7
Lel1_sp1_irq_vector:
	BRANCH_TO_KVA_VECTOR el1_sp1_irq_vector_long, 5

	.text
	.align 7
Lel1_sp1_fiq_vector:
	BRANCH_TO_KVA_VECTOR el1_sp1_fiq_vector_long, 6

	.text
	.align 7
Lel1_sp1_serror_vector:
	BRANCH_TO_KVA_VECTOR el1_sp1_serror_vector_long, 7

	.text
	.align 7
Lel0_synchronous_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR el0_synchronous_vector_64_long, 8

	.text
	.align 7
Lel0_irq_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR el0_irq_vector_64_long, 9

	.text
	.align 7
Lel0_fiq_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR el0_fiq_vector_64_long, 10

	.text
	.align 7
Lel0_serror_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR el0_serror_vector_64_long, 11

	/* Fill out the rest of the page */
	.align 12

/*********************************
 * END OF EXCEPTION VECTORS PAGE *
 *********************************/



.macro EL1_SP0_VECTOR
	msr		SPSel, #0							// Switch to SP0
	sub		sp, sp, ARM_CONTEXT_SIZE			// Create exception frame
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to exception frame
	add		x0, sp, ARM_CONTEXT_SIZE			// Calculate the original stack pointer
	str		x0, [sp, SS64_SP]					// Save stack pointer to exception frame
	INIT_SAVED_STATE_FLAVORS sp, w0, w1
	mov		x0, sp								// Copy saved state pointer to x0
.endmacro

.macro EL1_SP0_VECTOR_SWITCH_TO_INT_STACK
	// SWITCH_TO_INT_STACK requires a clobberable tmp register, but at this
	// point in the exception vector we can't spare the extra GPR.  Instead note
	// that EL1_SP0_VECTOR ends with x0 == sp and use this to unclobber x0.
	mrs		x1, TPIDR_EL1
	LOAD_INT_STACK	dst=x1, src=x1, tmp=x0
	mov		x0, sp
	mov		sp, x1
.endmacro

el1_sp0_synchronous_vector_long:
	stp		x0, x1, [sp, #-16]!				// Save x0 and x1 to the exception stack
	mrs		x1, ESR_EL1							// Get the exception syndrome
	/* If the stack pointer is corrupt, it will manifest either as a data abort
	 * (syndrome 0x25) or a misaligned pointer (syndrome 0x26). We can check
	 * these quickly by testing bit 5 of the exception class.
	 */
	tbz		x1, #(5 + ESR_EC_SHIFT), Lkernel_stack_valid
	CHECK_KERNEL_STACK
Lkernel_stack_valid:
	ldp		x0, x1, [sp], #16				// Restore x0 and x1 from the exception stack
	EL1_SP0_VECTOR
	adrp	x1, EXT(fleh_synchronous)@page			// Load address for fleh
	add		x1, x1, EXT(fleh_synchronous)@pageoff
	b		fleh_dispatch64

el1_sp0_irq_vector_long:
	EL1_SP0_VECTOR
	EL1_SP0_VECTOR_SWITCH_TO_INT_STACK
	adrp	x1, EXT(fleh_irq)@page					// Load address for fleh
	add		x1, x1, EXT(fleh_irq)@pageoff
	b		fleh_dispatch64

el1_sp0_fiq_vector_long:
	// ARM64_TODO write optimized decrementer
	EL1_SP0_VECTOR
	EL1_SP0_VECTOR_SWITCH_TO_INT_STACK
	adrp	x1, EXT(fleh_fiq)@page					// Load address for fleh
	add		x1, x1, EXT(fleh_fiq)@pageoff
	b		fleh_dispatch64

el1_sp0_serror_vector_long:
	EL1_SP0_VECTOR
	adrp	x1, EXT(fleh_serror)@page				// Load address for fleh
	add		x1, x1, EXT(fleh_serror)@pageoff
	b		fleh_dispatch64

.macro EL1_SP1_VECTOR
	sub		sp, sp, ARM_CONTEXT_SIZE			// Create exception frame
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to exception frame
	add		x0, sp, ARM_CONTEXT_SIZE			// Calculate the original stack pointer
	str		x0, [sp, SS64_SP]					// Save stack pointer to exception frame
	INIT_SAVED_STATE_FLAVORS sp, w0, w1
	mov		x0, sp								// Copy saved state pointer to x0
.endmacro

el1_sp1_synchronous_vector_long:
	b		check_exception_stack
Lel1_sp1_synchronous_valid_stack:
#if defined(KERNEL_INTEGRITY_KTRR)
	b		check_ktrr_sctlr_trap
Lel1_sp1_synchronous_vector_continue:
#endif
	EL1_SP1_VECTOR
	adrp	x1, fleh_synchronous_sp1@page
	add		x1, x1, fleh_synchronous_sp1@pageoff
	b		fleh_dispatch64_noreturn

el1_sp1_irq_vector_long:
	EL1_SP1_VECTOR
	adrp	x1, fleh_irq_sp1@page
	add		x1, x1, fleh_irq_sp1@pageoff
	b		fleh_dispatch64_noreturn

el1_sp1_fiq_vector_long:
	EL1_SP1_VECTOR
	adrp	x1, fleh_fiq_sp1@page
	add		x1, x1, fleh_fiq_sp1@pageoff
	b		fleh_dispatch64_noreturn

el1_sp1_serror_vector_long:
	EL1_SP1_VECTOR
	adrp	x1, fleh_serror_sp1@page
	add		x1, x1, fleh_serror_sp1@pageoff
	b		fleh_dispatch64_noreturn


.macro EL0_64_VECTOR guest_label
	stp		x0, x1, [sp, #-16]!					// Save x0 and x1 to the exception stack
#if __ARM_KERNEL_PROTECT__
	mov		x18, #0 						// Zero x18 to avoid leaking data to user SS
#endif
	mrs		x0, TPIDR_EL1						// Load the thread register
	LOAD_USER_PCB	dst=x0, src=x0, tmp=x1		// Load the user context pointer
	mrs		x1, SP_EL0							// Load the user stack pointer
	str		x1, [x0, SS64_SP]					// Store the user stack pointer in the user PCB
	msr		SP_EL0, x0							// Copy the user PCB pointer to SP0
	ldp		x0, x1, [sp], #16					// Restore x0 and x1 from the exception stack
	msr		SPSel, #0							// Switch to SP0
	stp		x0, x1, [sp, SS64_X0]				// Save x0, x1 to the user PCB
	mrs		x1, TPIDR_EL1						// Load the thread register



	mov		x0, sp								// Copy the user PCB pointer to x0
												// x1 contains thread register
.endmacro

.macro EL0_64_VECTOR_SWITCH_TO_INT_STACK
	// Similarly to EL1_SP0_VECTOR_SWITCH_TO_INT_STACK, we need to take
	// advantage of EL0_64_VECTOR ending with x0 == sp.  EL0_64_VECTOR also
	// populates x1 with the thread state, so we can skip reloading it.
	LOAD_INT_STACK	dst=x1, src=x1, tmp=x0
	mov		x0, sp
	mov		sp, x1
.endmacro

.macro EL0_64_VECTOR_SWITCH_TO_KERN_STACK
	LOAD_KERN_STACK_TOP	dst=x1, src=x1, tmp=x0
	mov		x0, sp
	mov		sp, x1
.endmacro

el0_synchronous_vector_64_long:
	EL0_64_VECTOR	sync
	EL0_64_VECTOR_SWITCH_TO_KERN_STACK
	adrp	x1, EXT(fleh_synchronous)@page			// Load address for fleh
	add		x1, x1, EXT(fleh_synchronous)@pageoff
	b		fleh_dispatch64

el0_irq_vector_64_long:
	EL0_64_VECTOR	irq
	EL0_64_VECTOR_SWITCH_TO_INT_STACK
	adrp	x1, EXT(fleh_irq)@page					// load address for fleh
	add		x1, x1, EXT(fleh_irq)@pageoff
	b		fleh_dispatch64

el0_fiq_vector_64_long:
	EL0_64_VECTOR	fiq
	EL0_64_VECTOR_SWITCH_TO_INT_STACK
	adrp	x1, EXT(fleh_fiq)@page					// load address for fleh
	add		x1, x1, EXT(fleh_fiq)@pageoff
	b		fleh_dispatch64

el0_serror_vector_64_long:
	EL0_64_VECTOR	serror
	EL0_64_VECTOR_SWITCH_TO_KERN_STACK
	adrp	x1, EXT(fleh_serror)@page				// load address for fleh
	add		x1, x1, EXT(fleh_serror)@pageoff
	b		fleh_dispatch64


/*
 * check_exception_stack
 *
 * Verifies that stack pointer at SP1 is within exception stack
 * If not, will simply hang as we have no more stack to fall back on.
 */
 
	.text
	.align 2
check_exception_stack:
	mrs		x18, TPIDR_EL1					// Get thread pointer
	cbz		x18, Lvalid_exception_stack			// Thread context may not be set early in boot
	ldr		x18, [x18, ACT_CPUDATAP]
	cbz		x18, Lcheck_exception_stack_fail	// If thread context is set, cpu data should be too
	ldr		x18, [x18, CPU_EXCEPSTACK_TOP]
	cmp		sp, x18
	b.gt	Lcheck_exception_stack_fail	// Hang if above exception stack top
	sub		x18, x18, EXCEPSTACK_SIZE_NUM			// Find bottom of exception stack
	cmp		sp, x18
	b.lt	Lcheck_exception_stack_fail	// Hang if below exception stack bottom
Lvalid_exception_stack:
	mov		x18, #0
	b		Lel1_sp1_synchronous_valid_stack

Lcheck_exception_stack_fail:
#if CONFIG_SPTM
	/*
	 * To prevent exceptions delivered on SP1 from being delayed indefinitely, 
	 * make recieving an exception on an invalid exception stack fatal.
	 */
	BEGIN_PANIC_LOCKDOWN
#endif /* CONFIG_SPTM */
1:  
	wfi
	b		1b		// Spin for debugger/watchdog

#if defined(KERNEL_INTEGRITY_KTRR)
	.text
	.align 2
check_ktrr_sctlr_trap:
/* We may abort on an instruction fetch on reset when enabling the MMU by
 * writing SCTLR_EL1 because the page containing the privileged instruction is
 * not executable at EL1 (due to KTRR). The abort happens only on SP1 which
 * would otherwise panic unconditionally. Check for the condition and return
 * safe execution to the caller on behalf of the faulting function.
 *
 * Expected register state:
 *  x22 - Kernel virtual base
 *  x23 - Kernel physical base
 */
	sub		sp, sp, ARM_CONTEXT_SIZE	// Make some space on the stack
	stp		x0, x1, [sp, SS64_X0]		// Stash x0, x1
	mrs		x0, ESR_EL1					// Check ESR for instr. fetch abort
	and		x0, x0, #0xffffffffffffffc0	// Mask off ESR.ISS.IFSC
	movz	w1, #0x8600, lsl #16
	movk	w1, #0x0000
	cmp		x0, x1
	mrs		x0, ELR_EL1					// Check for expected abort address
	adrp	x1, _pinst_set_sctlr_trap_addr@page
	add		x1, x1, _pinst_set_sctlr_trap_addr@pageoff
	sub		x1, x1, x22					// Convert to physical address
	add		x1, x1, x23
	ccmp	x0, x1, #0, eq
	ldp		x0, x1, [sp, SS64_X0]		// Restore x0, x1
	add		sp, sp, ARM_CONTEXT_SIZE	// Clean up stack
	b.ne	Lel1_sp1_synchronous_vector_continue
	msr		ELR_EL1, lr					// Return to caller
	ERET_CONTEXT_SYNCHRONIZING
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

/* 64-bit first level exception handler dispatcher.
 * Completes register context saving and branches to a non-returning FLEH.
 * FLEH can inspect the spilled thread state, but it contains an invalid
 * thread signature.
 *
 * Expects:
 *  {x0, x1, sp} - saved
 *  x0 - arm_context_t
 *  x1 - address of FLEH
 *  fp - previous stack frame if EL1
 *  lr - unused
 *  sp - kernel stack
 */
	.text
	.align 2
fleh_dispatch64_noreturn:
#if HAS_APPLE_PAC
	pacia	x1, sp
	/* Save arm_saved_state64 with invalid signature */
	SPILL_REGISTERS KERNEL_MODE, POISON_THREAD_SIGNATURE
	b	fleh_dispatch64_common
#else
	// Fall through to fleh_dispatch64
#endif

/* 64-bit first level exception handler dispatcher.
 * Completes register context saving and branches to FLEH.
 * Expects:
 *  {x0, x1, sp} - saved
 *  x0 - arm_context_t
 *  x1 - address of FLEH
 *  fp - previous stack frame if EL1
 *  lr - unused
 *  sp - kernel stack
 */
	.text
	.align 2
fleh_dispatch64:
#if HAS_APPLE_PAC
	pacia	x1, sp
#endif

	/* Save arm_saved_state64 */
	SPILL_REGISTERS KERNEL_MODE

fleh_dispatch64_common:
	/* If exception is from userspace, zero unused registers */
	and		x23, x23, #(PSR64_MODE_EL_MASK)
	cmp		x23, #(PSR64_MODE_EL0)
	bne		1f

	SANITIZE_FPCR x25, x2, 2 // x25 is set to current FPCR by SPILL_REGISTERS
2:
	mov		x2, #0
	mov		x3, #0
	mov		x4, #0
	mov		x5, #0
	mov		x6, #0
	mov		x7, #0
	mov		x8, #0
	mov		x9, #0
	mov		x10, #0
	mov		x11, #0
	mov		x12, #0
	mov		x13, #0
	mov		x14, #0
	mov		x15, #0
	mov		x16, #0
	mov		x17, #0
	mov		x18, #0
	mov		x19, #0
	mov		x20, #0
	/* x21, x22 cleared in common case below */
	mov		x23, #0
	mov		x24, #0
	mov		x25, #0
#if !XNU_MONITOR
	mov		x26, #0
#endif
	mov		x27, #0
	mov		x28, #0
	mov		fp, #0
	mov		lr, #0
1:

	mov		x21, x0								// Copy arm_context_t pointer to x21
	mov		x22, x1								// Copy handler routine to x22

#if XNU_MONITOR
	/* Zero x26 to indicate that this should not return to the PPL. */
	mov		x26, #0
#endif

#if PRECISE_USER_KERNEL_TIME
	tst		x23, PSR64_MODE_EL_KERNEL			// If interrupting this kernel, skip
	b.ne	1f                                  // precise time update.
	PUSH_FRAME
	bl		EXT(recount_leave_user)
	POP_FRAME_WITHOUT_LR
	mov		x0, x21								// Reload arm_context_t pointer
1:
#endif /* PRECISE_USER_KERNEL_TIME */

	/* Dispatch to FLEH */

#if HAS_APPLE_PAC
	braa	x22,sp
#else
	br		x22
#endif


	.text
	.align 2
	.global EXT(fleh_synchronous)
LEXT(fleh_synchronous)
	
UNWIND_PROLOGUE
UNWIND_DIRECTIVES	
	
	mrs		x1, ESR_EL1							// Load exception syndrome
	mrs		x2, FAR_EL1							// Load fault address

	/* At this point, the LR contains the value of ELR_EL1. In the case of an
	 * instruction prefetch abort, this will be the faulting pc, which we know
	 * to be invalid. This will prevent us from backtracing through the
	 * exception if we put it in our stack frame, so we load the LR from the
	 * exception saved state instead.
	 */
	and		w6, w1, #(ESR_EC_MASK)
	lsr		w6, w6, #(ESR_EC_SHIFT)
	mov		w4, #(ESR_EC_IABORT_EL1)
	cmp		w6, w4
	b.eq	Lfleh_sync_load_lr
Lvalid_link_register:

#if CONFIG_SPTM
	/* 
	 * Sync exceptions in the kernel are rare, so check that first.
	 * This check should be trivially predicted NT. We also take 
	 * the check out of line so, on the hot path, we don't add a 
	 * frontend redirect. 
	 */
	mov		x3, #0 // by default, do not signal panic lockdown to sleh
	mrs		x4, SPSR_EL1
	tst		x4, #(PSR64_MODE_EL_MASK)
	b.ne	Lfleh_synchronous_ool_check_exception_el1 /* Run ELn checks if we're EL!=0 (!Z) */
	/* EL0 -- check if we're blocking sync exceptions due to lockdown */
	adrp	x4, EXT(sptm_xnu_triggered_panic_ptr)@page
	ldr		x4, [x4, EXT(sptm_xnu_triggered_panic_ptr)@pageoff]
	ldrb	w4, [x4]
	cbnz	w4, Lblocked_user_sync_exception

Lfleh_synchronous_continue:
#endif /* CONFIG_SPTM */

	PUSH_FRAME
	bl		EXT(sleh_synchronous)
	POP_FRAME_WITHOUT_LR

#if XNU_MONITOR && !CONFIG_SPTM
	CHECK_EXCEPTION_RETURN_DISPATCH_PPL
#endif

	mov		x28, xzr		// Don't need to check PFZ if there are ASTs
	b		exception_return_dispatch

Lfleh_sync_load_lr:
	ldr		lr, [x0, SS64_LR]
	b Lvalid_link_register

#if CONFIG_SPTM
Lfleh_synchronous_ool_check_exception_el1:
	/* 
	 * We're in the kernel!
	 * 
	 * An SP0 sync exception is forced to be fatal if:
	 * (AND
	 * 	(SPSR.M[3:2] > 0) // Originates from kernel
	 * 	(OR
	 * 		(ESR.EC == ESR_EC_PAC_FAIL)    // FPAC failure
	 * 		(AND  // PAC BRK instruction (compiler generated traps)
	 * 			ESR.EC == ESR_EC_BRK_AARCH64
	 * 			ESR.ISS is in PTRAUTH_TRAPS
	 * 		)
	 *		(AND // Potential dPAC failure (poisoned VA)
	 *			(ESR.EC == ESR_EC_DABORT_EL1)
	 *			(XPACD(FAR) != FAR)
	 *			(NAND //outside copyio region
	 *				ELR >= copyio_fault_region_begin
	 *				ELR < copyio_fault_region_end
	 * 			)
	 *		)
	 *		(ESR.EC == ESR_EC_IABORT_EL1)  // Potential iPAC failure (poisoned PC)
	 * 		(AND 
	 * 			(AND SPSR.A SPSR.I SPSR.F) // Async exceptions were masked 
	 * 			(ESR.EC != ESR_EC_UNCATEGORIZED) // Not an undefined instruction (GDBTRAP for stackshots, etc.)
	 *			(NAND // brks other than PAC traps are permitted for non-fatal telemetry
	 *				(ESR.EC == ESR_EC_BRK_AARCH64)
	 *				(ESR.ISS is in PTRAUTH_TRAPS)
	 *			)
	 * 			(startup_phase < STARTUP_SUB_LOCKDOWN) // Not in early-boot
	 * 			(OR !CONFIG_XNUPOST (saved_expected_fault_handler == NULL)) // Not an expected, test exception
	 *			(NAND // copyio data aborts are permitted while exceptions are masked
	 *				ESR.EC == ESR_EC_DABORT_EL1
	 *				ELR >= copyio_fault_region_begin
	 *				ELR < copyio_fault_region_end
	 *			)
	 * 		)     
	 * 	)
	 * ) 
	 */

	/*
	 * Pre-compute some sub-expressions which will be used later
	 */
	mrs		x10, ELR_EL1
	adrp	x11, EXT(copyio_fault_region_begin)@page
	add		x11, x11, EXT(copyio_fault_region_begin)@pageoff
	adrp	x12, EXT(copyio_fault_region_end)@page
	add		x12, x12, EXT(copyio_fault_region_end)@pageoff

	/* in-copyio-region sub-expression */
	/* Are we after the start of the copyio region? */
	cmp		x10, x11
	/*
	 * If after the start (HS), test upper bounds.
	 * Otherwise (LO), fail forward (HS)
	 */
	ccmp	x10, x12, #0b0010 /* C/HS */, HS
	/*
	 * Spill "in-copyio-region" flag for later reuse
	 * x10=1 if ELR was in copyio region, 0 otherwise
	 */
	cset	x10, LO

#if __has_feature(ptrauth_calls)
	/* is-dPAC-poisoned-DABORT sub-expression */
	mrs		x5, FAR_EL1
	/*
	 * Is XPACD(FAR) == FAR?
	 * XPAC converts an arbitrary pointer like value into the canonical form
	 * that would be produced if the pointer were to successfully pass AUTx.
	 * If the pointer is canonical, this has no effect.
	 * If the pointer is non-canonical (such as due to PAC poisoning), the value
	 * will not match FAR.
	 */
	mov		x11, x5
	xpacd	x11
	/*
	 * If we're outside the copyio region (HS), set flags for whether FAR is
	 * clean (EQ) or has PAC poisoning (NE).
	 * Otherwise (LO), set EQ
	 */
	ccmp    x5, x11, #0b0100 /* Z/EQ */, HS
	/*
	 * If we were poisoned (NE), was this a data abort?
	 * Otherwise (EQ), pass NE
	 */
	mov		w5, #(ESR_EC_DABORT_EL1)
	ccmp	w6, w5, #0b0000 /* !Z/NE */, NE
	/* x11=1 when we had a DABORT with a poisoned VA outside the copyio region */
	cset	x11, EQ
#endif /* ptrauth_calls */

	/*
	 * Now let's check the rare but fast conditions that apply only to kernel
	 * sync exceptions.
	 */

	/*
	 * if ((ESR.EC == ESR_EC_BRK_AARCH64 && IS_PTRAUTH(ESR.ISS)) ||
	 * 		ESR.EC == ESR_EC_PAC_FAIL ||
	 *		ESR.EC == ESR_IABORT_EL1 ||
	 *		poisoned_dabort)
	 * 	goto Lfleh_synchronous_panic_lockdown
	 */
	cmp		w6, #(ESR_EC_BRK_AARCH64) // eq if this is a BRK instruction
	/* 
	 * Is this a PAC breakpoint? ESR.ISS in [0xC470, 0xC473], which is true when
	 * {ESR.ISS[24:2], 2'b00} == 0xC470
	 */
	mov		w5, #(0xC470)
	and		w7, w1, #0xfffc
	/*
	 * If we're not BRK, NE
	 * If we're BRK, set flags for ISS=PAC breakpoint
	 */
	ccmp	w7, w5, #0, EQ

	/* 
	 * If we aren't a PAC BRK (NE), set flags for ESR.EC==PAC_FAIL
	 * If we are a PAC BRK (EQ), pass EQ through.
	*/
	ccmp	w6, #(ESR_EC_PAC_FAIL), #0b0100 /* Z */, NE

	/*
	 * If !(PAC BRK || EC == PAC_FAIL) (NE), set flags for ESR.EC==IABORT
	 * If (PAC BRK || EC == PAC_FAIL) (EQ), pass lockdown request (EQ)
	 */
	mov		w5, #(ESR_EC_IABORT_EL1)
	ccmp	w6, w5, #0b0100 /* Z/EQ */, NE

#if __has_feature(ptrauth_calls)
	/*
	 * If !(PAC BRK || EC == PAC_FAIL || EC == IABORT) (NE), set flags for
	 * whether this was a posioned DABORT (previously computed in x11).
	 * If (PAC BRK || EC == PAC_FAIL || EC == IABORT) (EQ), pass lockdown
	 * request (EQ)
	 */
	ccmp	x11, #1, #0b0100 /* Z/EQ */, NE
#endif /* ptrauth_calls */

	b.eq	Lfleh_synchronous_panic_lockdown
	
	/*
	 * Most kernel exceptions won't be taken with exceptions masked but if they
	 * are they'll be stackshot traps or telemetry breakpoints. Check these
	 * first since they're cheap.
	 *
	 * if (!((PSTATE & DAIF_STANDARD_DISABLE) == DAIF_STANDARD_DISABLE
	 * 		&& ESR.EC != ESR_EC_UNCATEGORIZED
	 * 		&& ESR.EC != ESR_EC_BRK_AARCH64))
	 * 		goto Lfleh_synchronous_continue
	 */
	mov		w5, #(DAIF_STANDARD_DISABLE)
	bics	wzr, w5, w4 // (DAIF_STANDARD_DISABLE & (~PSTATE)). If !Z/NE, AIF wasn't (fully) masked.
	/*
	 * If AIF was masked (EQ), test EC =? fasttrap
	 * If AIF wasn't masked (NE), pass lockdown skip (EQ)
	 */
	ccmp	w6, #(ESR_EC_UNCATEGORIZED), #0b0100 /* Z/EQ */, EQ
	/*
	 * If AIF was masked AND EC != fasttrap (NE), test EC =? BRK
	 * If AIF wasn't masked OR EC == fasttrap (EQ), pass lockdown skip (EQ)
	 */
	mov		w5, #(ESR_EC_BRK_AARCH64)
	ccmp	w6, w5, #0b0100 /* Z/EQ */, NE
	/*
	 * AIF was masked AND EC != fasttrap AND EC != BRK (NE)
	 * AIF wasn't masked OR EC == fasttrap OR EC == BRK (EQ) -> skip lockdown!
	 */
	b.eq	Lfleh_synchronous_continue
	
	/* 
	 * Non-PAC/BRK/fasttrap exception taken with exceptions disabled.
	 * We're going down if the system IS NOT:
	 * 1) in early boot OR
	 * 2) handling an expected XNUPOST exception (handled in lockdown macro)
	 * 3) taking a copyio data abort
	 */
	adrp	x7, EXT(startup_phase)@page
	add		x7, x7, EXT(startup_phase)@pageoff
	ldr		w7, [x7]
	cmp		w7, #-1 // STARTUP_SUB_LOCKDOWN
	b.lo	Lfleh_synchronous_continue

	/* Was this a copyio data abort taken while exceptions were masked? */
	cmp		w6, #ESR_EC_DABORT_EL1
	/* x10=1 when ELR was in copyio range */
	ccmp	x10, #1, #0b0000 /* !Z/NE */, EQ
	b.eq	Lfleh_synchronous_continue

	/* FALLTHROUGH */
Lfleh_synchronous_panic_lockdown:
	/* Save off arguments for sleh as SPTM may clobber */
	mov x26, x0
	mov x27, x1
	mov x28, x2
	BEGIN_PANIC_LOCKDOWN
	mov x0, x26
	mov x1, x27
	mov x2, x28
	/* 
	 * A captain goes down with her ship; system is sunk but for telemetry 
	 * try to handle the crash normally.
	 */
	mov		x3, #1 // signal to sleh that we completed panic lockdown 
	b		Lfleh_synchronous_continue
#endif /* CONFIG_SPTM */
UNWIND_EPILOGUE

#if CONFIG_SPTM
	.text
	.align 2
	/* Make a global symbol so it's easier to pick out in backtraces */
	.global EXT(blocked_user_sync_exception)
LEXT(blocked_user_sync_exception)
Lblocked_user_sync_exception:
	UNWIND_PROLOGUE
	UNWIND_DIRECTIVES
	/*
	 * User space took a sync exception after panic lockdown had been initiated.
	 * The system is going to panic soon, so let's just re-enable FIQs and wait
	 * for debugger sync.
	 */
	msr		DAIFClr, #DAIFSC_FIQF
0:
	wfi
	b		0b
	UNWIND_EPILOGUE
#endif /* CONFIG_SPTM */
	
/* Shared prologue code for fleh_irq and fleh_fiq.
 * Does any interrupt booking we may want to do
 * before invoking the handler proper.
 * Expects:
 *  x0 - arm_context_t
 * x23 - CPSR
 *  fp - Undefined live value (we may push a frame)
 *  lr - Undefined live value (we may push a frame)
 *  sp - Interrupt stack for the current CPU
 */
.macro BEGIN_INTERRUPT_HANDLER
	mrs		x22, TPIDR_EL1
	ldr		x23, [x22, ACT_CPUDATAP]			// Get current cpu
	/* Update IRQ count; CPU_STAT_IRQ.* is required to be accurate for the WFE idle sequence  */
	ldr		w1, [x23, CPU_STAT_IRQ]
	add		w1, w1, #1							// Increment count
	str		w1, [x23, CPU_STAT_IRQ]				// Update  IRQ count
	ldr		w1, [x23, CPU_STAT_IRQ_WAKE]
	add		w1, w1, #1					// Increment count
	str		w1, [x23, CPU_STAT_IRQ_WAKE]			// Update post-wake IRQ count
	/* Increment preempt count */
	ldr		w1, [x22, ACT_PREEMPT_CNT]
	add		w1, w1, #1
	str		w1, [x22, ACT_PREEMPT_CNT]
	/* Store context in int state */
	str		x0, [x23, CPU_INT_STATE] 			// Saved context in cpu_int_state
.endmacro

/* Shared epilogue code for fleh_irq and fleh_fiq.
 * Cleans up after the prologue, and may do a bit more
 * bookkeeping (kdebug related).
 * Expects:
 * x22 - Live TPIDR_EL1 value (thread address)
 * x23 - Address of the current CPU data structure
 * w24 - 0 if kdebug is disbled, nonzero otherwise
 *  fp - Undefined live value (we may push a frame)
 *  lr - Undefined live value (we may push a frame)
 *  sp - Interrupt stack for the current CPU
 */
.macro END_INTERRUPT_HANDLER
	/* Clear int context */
	str		xzr, [x23, CPU_INT_STATE]
	/* Decrement preempt count */
	ldr		w0, [x22, ACT_PREEMPT_CNT]
	cbnz	w0, 1f								// Detect underflow
	b		preempt_underflow
1:
	sub		w0, w0, #1
	str		w0, [x22, ACT_PREEMPT_CNT]
	/* Switch back to kernel stack */
	LOAD_KERN_STACK_TOP	dst=x0, src=x22, tmp=x28
	mov		sp, x0
	/* Generate a CPU-local event to terminate a post-IRQ WFE */
	sevl
.endmacro

	.text
	.align 2
	.global EXT(fleh_irq)
LEXT(fleh_irq)
UNWIND_PROLOGUE
UNWIND_DIRECTIVES
	BEGIN_INTERRUPT_HANDLER
	PUSH_FRAME
	bl		EXT(sleh_irq)
	POP_FRAME_WITHOUT_LR
	END_INTERRUPT_HANDLER

#if XNU_MONITOR && !CONFIG_SPTM
	CHECK_EXCEPTION_RETURN_DISPATCH_PPL
#endif

	mov		x28, #1			// Set a bit to check PFZ if there are ASTs
	b		exception_return_dispatch
UNWIND_EPILOGUE

	.text
	.align 2
	.global EXT(fleh_fiq_generic)
LEXT(fleh_fiq_generic)
	PANIC_UNIMPLEMENTED

	.text
	.align 2
	.global EXT(fleh_fiq)
LEXT(fleh_fiq)
UNWIND_PROLOGUE
UNWIND_DIRECTIVES
	BEGIN_INTERRUPT_HANDLER
	PUSH_FRAME
	bl		EXT(sleh_fiq)
	POP_FRAME_WITHOUT_LR
	END_INTERRUPT_HANDLER

#if XNU_MONITOR && !CONFIG_SPTM
	CHECK_EXCEPTION_RETURN_DISPATCH_PPL
#endif

	mov		x28, #1			// Set a bit to check PFZ if there are ASTs
	b		exception_return_dispatch
UNWIND_EPILOGUE

	.text
	.align 2
	.global EXT(fleh_serror)
LEXT(fleh_serror)
UNWIND_PROLOGUE
UNWIND_DIRECTIVES
	mrs		x1, ESR_EL1							// Load exception syndrome
	mrs		x2, FAR_EL1							// Load fault address

	PUSH_FRAME
	bl		EXT(sleh_serror)
	POP_FRAME_WITHOUT_LR

#if XNU_MONITOR && !CONFIG_SPTM
	CHECK_EXCEPTION_RETURN_DISPATCH_PPL
#endif

	mov		x28, xzr		// Don't need to check PFZ If there are ASTs
	b		exception_return_dispatch
UNWIND_EPILOGUE

/*
 * Register state saved before we get here.
 */
	.text
	.align 2
fleh_invalid_stack:
#if CONFIG_SPTM
	/*
	 * Taking a data abort with an invalid kernel stack pointer is unrecoverable.
	 * Initiate lockdown.
	 */
	/* Save off x0 as SPTM may clobber */
	mov		x26, x0
	BEGIN_PANIC_LOCKDOWN
	mov		x0, x26
#endif /* CONFIG_SPTM */
	mrs		x1, ESR_EL1							// Load exception syndrome
	str		x1, [x0, SS64_ESR]
	mrs		x2, FAR_EL1							// Load fault address
	str		x2, [x0, SS64_FAR]
	PUSH_FRAME
	bl		EXT(sleh_invalid_stack)				// Shouldn't return!
	b 		.

	.text
	.align 2
fleh_synchronous_sp1:
	mrs		x1, ESR_EL1							// Load exception syndrome
	str		x1, [x0, SS64_ESR]
	mrs		x2, FAR_EL1							// Load fault address
	str		x2, [x0, SS64_FAR]

#if CONFIG_SPTM
	/*
	 * Without debugger intervention, all exceptions on SP1 (including debug
	 * trap instructions) are intended to be fatal. In order to not break
	 * self-hosted kernel debug, do not trigger lockdown for debug traps
	 * (unknown instructions/uncategorized exceptions). On release kernels, we
	 * don't support self-hosted kernel debug so unconditionally lockdown.
	 */
#if (DEVELOPMENT || DEBUG)
	tst		w1, #(ESR_EC_MASK)
	b.eq	Lfleh_synchronous_sp1_skip_panic_lockdown // ESR_EC_UNCATEGORIZED is 0, so skip lockdown if Z
#endif /* DEVELOPMENT || DEBUG */
	/* Save off arguments for sleh as SPTM may clobber */
	mov x26, x0
	mov x27, x1
	mov x28, x2
	BEGIN_PANIC_LOCKDOWN
	mov x0, x26
	mov x1, x27
	mov x2, x28
Lfleh_synchronous_sp1_skip_panic_lockdown:
#endif /* CONFIG_SPTM */

	PUSH_FRAME
	bl		EXT(sleh_synchronous_sp1)
	b 		.

	.text
	.align 2
fleh_irq_sp1:
	mov		x1, x0
	adr		x0, Lsp1_irq_str
	b		EXT(panic_with_thread_kernel_state)
Lsp1_irq_str:
	.asciz "IRQ exception taken while SP1 selected"

	.text
	.align 2
fleh_fiq_sp1:
	mov		x1, x0
	adr		x0, Lsp1_fiq_str
	b		EXT(panic_with_thread_kernel_state)
Lsp1_fiq_str:
	.asciz "FIQ exception taken while SP1 selected"

	.text
	.align 2
fleh_serror_sp1:
	mov		x1, x0
	adr		x0, Lsp1_serror_str
	b		EXT(panic_with_thread_kernel_state)
Lsp1_serror_str:
	.asciz "Asynchronous exception taken while SP1 selected"

	.text
	.align 2
exception_return_dispatch:
	ldr		w0, [x21, SS64_CPSR]
	tst		w0, PSR64_MODE_EL_MASK
	b.ne		EXT(return_to_kernel) // return to kernel if M[3:2] > 0
	b		return_to_user

#if CONFIG_SPTM
/**
 * XNU returns to this symbol whenever handling an interrupt that occurred
 * during SPTM, TXM or SK runtime. This code determines which domain the
 * XNU thread was executing in when the interrupt occurred and tells SPTM
 * which domain to resume.
 */
	.text
	.align 2
	.global EXT(xnu_return_to_gl2)
LEXT(xnu_return_to_gl2)
	/**
	 * If thread->txm_thread_stack is set, we need to tell SPTM dispatch to 
	 * resume the TXM thread in x0.
	 */
	mrs		x8, TPIDR_EL1
	ldr		x8, [x8, TH_TXM_THREAD_STACK]
	cbz		x8, 1f
	mov		x0, x8
	b		EXT(txm_resume)
	/* Unreachable */
	b .

#if CONFIG_EXCLAVES
	/**
	 * If thread->th_exclaves_intstate flag TH_EXCLAVES_EXECUTION is set
	 * we need to tell SPTM dispatch to resume the SK thread.
	 */
1:
	mrs		x8, TPIDR_EL1
	ldr		x9, [x8, TH_EXCLAVES_INTSTATE]
	and		x9, x9, TH_EXCLAVES_EXECUTION
	cbz		x9, 1f
	b		EXT(sk_resume)
	/* Unreachable */
	b .
#endif /* CONFIG_EXCLAVES */

	/**
	 * If neither the above checks succeeded, this must be a thread
	 * that was interrupted while running in SPTM. Tell SPTM to resume
	 * the interrupted SPTM call.
	 */
1:
	b		EXT(sptm_resume_from_exception)
	/* Unreachable */
	b .
#endif /* CONFIG_SPTM */

	.text
	.align 2
	.global EXT(return_to_kernel)
LEXT(return_to_kernel)
	tbnz	w0, #DAIF_IRQF_SHIFT, exception_return  // Skip AST check if IRQ disabled
	mrs		x3, TPIDR_EL1                           // Load thread pointer
	ldr		w1, [x3, ACT_PREEMPT_CNT]               // Load preemption count
	msr		DAIFSet, #DAIFSC_ALL                    // Disable exceptions
	cbnz	x1, exception_return_unint_tpidr_x3     // If preemption disabled, skip AST check
	ldr		x1, [x3, ACT_CPUDATAP]                  // Get current CPU data pointer
	ldr		w2, [x1, CPU_PENDING_AST]               // Get ASTs
	tst		w2, AST_URGENT                          // If no urgent ASTs, skip ast_taken
	b.eq	exception_return_unint_tpidr_x3
	mov		sp, x21                                 // Switch to thread stack for preemption
	PUSH_FRAME
	bl		EXT(ast_taken_kernel)                   // Handle AST_URGENT
	POP_FRAME_WITHOUT_LR
	b		exception_return

	.text
	.globl EXT(thread_bootstrap_return)
LEXT(thread_bootstrap_return)
#if CONFIG_DTRACE
	bl		EXT(dtrace_thread_bootstrap)
#endif
#if KASAN_TBI
	PUSH_FRAME
	bl		EXT(__asan_handle_no_return)
	POP_FRAME_WITHOUT_LR
#endif /* KASAN_TBI */
	b		EXT(arm64_thread_exception_return)

	.text
	.globl EXT(arm64_thread_exception_return)
LEXT(arm64_thread_exception_return)
	mrs		x0, TPIDR_EL1
	LOAD_USER_PCB	dst=x21, src=x0, tmp=x28
	mov		x28, xzr

	//
	// Fall Through to return_to_user from arm64_thread_exception_return.  
	// Note that if we move return_to_user or insert a new routine 
	// below arm64_thread_exception_return, the latter will need to change.
	//
	.text
/* x21 is always the machine context pointer when we get here
 * x28 is a bit indicating whether or not we should check if pc is in pfz */
return_to_user:
check_user_asts:
#if KASAN_TBI
	PUSH_FRAME
	bl		EXT(__asan_handle_no_return)
	POP_FRAME_WITHOUT_LR
#endif /* KASAN_TBI */
	mrs		x3, TPIDR_EL1					// Load thread pointer

	movn		w2, #0
	str		w2, [x3, TH_IOTIER_OVERRIDE]			// Reset IO tier override to -1 before returning to user

#if MACH_ASSERT
	ldr		w0, [x3, ACT_PREEMPT_CNT]
	cbnz		w0, preempt_count_notzero			// Detect unbalanced enable/disable preemption
#endif

	msr		DAIFSet, #DAIFSC_ALL				// Disable exceptions
	ldr		x4, [x3, ACT_CPUDATAP]				// Get current CPU data pointer
	ldr		w0, [x4, CPU_PENDING_AST]			// Get ASTs
	cbz		w0, no_asts							// If no asts, skip ahead

	cbz		x28, user_take_ast					// If we don't need to check PFZ, just handle asts

	/* At this point, we have ASTs and we need to check whether we are running in the
	 * preemption free zone (PFZ) or not. No ASTs are handled if we are running in
	 * the PFZ since we don't want to handle getting a signal or getting suspended
	 * while holding a spinlock in userspace.
	 *
	 * If userspace was in the PFZ, we know (via coordination with the PFZ code
	 * in commpage_asm.s) that it will not be using x15 and it is therefore safe
	 * to use it to indicate to userspace to come back to take a delayed
	 * preemption, at which point the ASTs will be handled. */
	mov		x28, xzr							// Clear the "check PFZ" bit so that we don't do this again
	mov		x19, x0								// Save x0 since it will be clobbered by commpage_is_in_pfz64

	ldr		x0, [x21, SS64_PC]					// Load pc from machine state
	bl		EXT(commpage_is_in_pfz64)			// pc in pfz?
	cbz		x0, restore_and_check_ast			// No, deal with other asts

	mov		x0, #1
	str		x0, [x21, SS64_X15]					// Mark x15 for userspace to take delayed preemption
	mov		x0, x19								// restore x0 to asts
	b		no_asts								// pretend we have no asts

restore_and_check_ast:
	mov		x0, x19								// restore x0
	b	user_take_ast							// Service pending asts
no_asts:


#if PRECISE_USER_KERNEL_TIME
	mov		x19, x3						// Preserve thread pointer across function call
	PUSH_FRAME
	bl		EXT(recount_enter_user)
	POP_FRAME_WITHOUT_LR
	mov		x3, x19
#endif /* PRECISE_USER_KERNEL_TIME */

#if (CONFIG_KERNEL_INTEGRITY && KERNEL_INTEGRITY_WT)
	/* Watchtower
	 *
	 * Here we attempt to enable NEON access for EL0. If the last entry into the
	 * kernel from user-space was due to an IRQ, the monitor will have disabled
	 * NEON for EL0 _and_ access to CPACR_EL1 from EL1 (1). This forces xnu to
	 * check in with the monitor in order to reenable NEON for EL0 in exchange
	 * for routing IRQs through the monitor (2). This way the monitor will
	 * always 'own' either IRQs or EL0 NEON.
	 *
	 * If Watchtower is disabled or we did not enter the kernel through an IRQ
	 * (e.g. FIQ or syscall) this is a no-op, otherwise we will trap to EL3
	 * here.
	 *
	 * EL0 user ________ IRQ                                            ______
	 * EL1 xnu              \   ______________________ CPACR_EL1     __/
	 * EL3 monitor           \_/                                \___/
	 *
	 *                       (1)                                 (2)
	 */

	mov		x0, #(CPACR_FPEN_ENABLE)
	msr		CPACR_EL1, x0
#endif

	/* Establish this thread's debug state as the live state on the selected CPU. */
	ldr		x4, [x3, ACT_CPUDATAP]				// Get current CPU data pointer
	ldr		x1, [x4, CPU_USER_DEBUG]			// Get Debug context
	ldr		x0, [x3, ACT_DEBUGDATA]
	cmp		x0, x1
	beq		L_skip_user_set_debug_state			// If active CPU debug state does not match thread debug state, apply thread state


	PUSH_FRAME
	bl		EXT(arm_debug_set)					// Establish thread debug state in live regs
	POP_FRAME_WITHOUT_LR
	mrs		x3, TPIDR_EL1						// Reload thread pointer
	ldr		x4, [x3, ACT_CPUDATAP]				// Reload CPU data pointer
L_skip_user_set_debug_state:


	ldrsh	x0, [x4, CPU_TPIDR_EL0]
	msr		TPIDR_EL0, x0


	b		exception_return_unint_tpidr_x3

exception_return:
	msr		DAIFSet, #DAIFSC_ALL				// Disable exceptions
exception_return_unint:
	mrs		x3, TPIDR_EL1					// Load thread pointer
exception_return_unint_tpidr_x3:
	mov		sp, x21						// Reload the pcb pointer

#if !__ARM_KERNEL_PROTECT__
	/*
	 * Restore x18 only if the task has the entitlement that allows
	 * usage. Those are very few, and can move to something else
	 * once we use x18 for something more global.
	 *
	 * This is not done here on devices with __ARM_KERNEL_PROTECT__, as
	 * that uses x18 as one of the global use cases (and will reset
	 * x18 later down below).
	 *
	 * It's also unconditionally skipped for translated threads,
	 * as those are another use case, one where x18 must be preserved.
	 */
	ldr		w0, [x3, TH_ARM_MACHINE_FLAGS]
	mov		x18, #0
	tbz		w0, ARM_MACHINE_THREAD_PRESERVE_X18_SHIFT, Lexception_return_restore_registers

exception_return_unint_tpidr_x3_restore_x18:
	ldr		x18, [sp, SS64_X18]

#else /* !__ARM_KERNEL_PROTECT__ */
	/*
	 * If we are going to eret to userspace, we must return through the EL0
	 * eret mapping.
	 */
	ldr		w1, [sp, SS64_CPSR]									// Load CPSR
	tbnz		w1, PSR64_MODE_EL_SHIFT, Lskip_el0_eret_mapping	// Skip if returning to EL1

	/* We need to switch to the EL0 mapping of this code to eret to EL0. */
	adrp		x0, EXT(ExceptionVectorsBase)@page				// Load vector base
	adrp		x1, Lexception_return_restore_registers@page	// Load target PC
	add		x1, x1, Lexception_return_restore_registers@pageoff
	MOV64		x2, ARM_KERNEL_PROTECT_EXCEPTION_START			// Load EL0 vector address
	sub		x1, x1, x0											// Calculate delta
	add		x0, x2, x1											// Convert KVA to EL0 vector address
	br		x0

Lskip_el0_eret_mapping:
#endif /* !__ARM_KERNEL_PROTECT__ */

Lexception_return_restore_registers:
	mov 	x0, sp								// x0 = &pcb
	// Loads authed $x0->ss_64.pc into x1 and $x0->ss_64.cpsr into w2
	AUTH_THREAD_STATE_IN_X0	x20, x21, x22, x23, x24, x25, el0_state_allowed=1

	msr		ELR_EL1, x1							// Load the return address into ELR
	msr		SPSR_EL1, x2						// Load the return CPSR into SPSR

/* Restore special register state */
	ldr		w3, [sp, NS64_FPSR]
	ldr		w4, [sp, NS64_FPCR]

	msr		FPSR, x3
	mrs		x5, FPCR
	CMSR FPCR, x5, x4, 1
1:



	/* Restore arm_neon_saved_state64 */
	ldp		q0, q1, [x0, NS64_Q0]
	ldp		q2, q3, [x0, NS64_Q2]
	ldp		q4, q5, [x0, NS64_Q4]
	ldp		q6, q7, [x0, NS64_Q6]
	ldp		q8, q9, [x0, NS64_Q8]
	ldp		q10, q11, [x0, NS64_Q10]
	ldp		q12, q13, [x0, NS64_Q12]
	ldp		q14, q15, [x0, NS64_Q14]
	ldp		q16, q17, [x0, NS64_Q16]
	ldp		q18, q19, [x0, NS64_Q18]
	ldp		q20, q21, [x0, NS64_Q20]
	ldp		q22, q23, [x0, NS64_Q22]
	ldp		q24, q25, [x0, NS64_Q24]
	ldp		q26, q27, [x0, NS64_Q26]
	ldp		q28, q29, [x0, NS64_Q28]
	ldp		q30, q31, [x0, NS64_Q30]

	/* Restore arm_saved_state64 */

	// Skip x0, x1 - we're using them
	ldp		x2, x3, [x0, SS64_X2]
	ldp		x4, x5, [x0, SS64_X4]
	ldp		x6, x7, [x0, SS64_X6]
	ldp		x8, x9, [x0, SS64_X8]
	ldp		x10, x11, [x0, SS64_X10]
	ldp		x12, x13, [x0, SS64_X12]
	ldp		x14, x15, [x0, SS64_X14]
	// Skip x16, x17 - already loaded + authed by AUTH_THREAD_STATE_IN_X0
	// Skip x18 - already restored or trashed above (below with __ARM_KERNEL_PROTECT__)
	ldr		x19, [x0, SS64_X19]
	ldp		x20, x21, [x0, SS64_X20]
	ldp		x22, x23, [x0, SS64_X22]
	ldp		x24, x25, [x0, SS64_X24]
	ldp		x26, x27, [x0, SS64_X26]
	ldr		x28, [x0, SS64_X28]
	ldr		fp, [x0, SS64_FP]
	// Skip lr - already loaded + authed by AUTH_THREAD_STATE_IN_X0

	// Restore stack pointer and our last two GPRs
	ldr		x1, [x0, SS64_SP]
	mov		sp, x1

#if __ARM_KERNEL_PROTECT__
	ldr		w18, [x0, SS64_CPSR]				// Stash CPSR
#endif /* __ARM_KERNEL_PROTECT__ */

	ldp		x0, x1, [x0, SS64_X0]				// Restore the GPRs

#if __ARM_KERNEL_PROTECT__
	/* If we are going to eret to userspace, we must unmap the kernel. */
	tbnz		w18, PSR64_MODE_EL_SHIFT, Lskip_ttbr1_switch

	/* Update TCR to unmap the kernel. */
	MOV64		x18, TCR_EL1_USER
	msr		TCR_EL1, x18

	/*
	 * On Apple CPUs, TCR writes and TTBR writes should be ordered relative to
	 * each other due to the microarchitecture.
	 */
#if !defined(APPLE_ARM64_ARCH_FAMILY)
	isb		sy
#endif

	/* Switch to the user ASID (low bit clear) for the task. */
	mrs		x18, TTBR0_EL1
	bic		x18, x18, #(1 << TTBR_ASID_SHIFT)
	msr		TTBR0_EL1, x18
	mov		x18, #0

	/* We don't need an ISB here, as the eret is synchronizing. */
Lskip_ttbr1_switch:
#endif /* __ARM_KERNEL_PROTECT__ */

	ERET_CONTEXT_SYNCHRONIZING

user_take_ast:
	PUSH_FRAME
	bl		EXT(ast_taken_user)							// Handle all ASTs, may return via continuation
	POP_FRAME_WITHOUT_LR
	b		check_user_asts								// Now try again

	.text
	.align 2
preempt_underflow:
	mrs		x0, TPIDR_EL1
	str		x0, [sp, #-16]!						// We'll print thread pointer
	adr		x0, L_underflow_str					// Format string
	CALL_EXTERN panic							// Game over

L_underflow_str:
	.asciz "Preemption count negative on thread %p"
.align 2

#if MACH_ASSERT
	.text
	.align 2
preempt_count_notzero:
	mrs		x0, TPIDR_EL1
	str		x0, [sp, #-16]!						// We'll print thread pointer
	ldr		w0, [x0, ACT_PREEMPT_CNT]
	str		w0, [sp, #8]
	adr		x0, L_preempt_count_notzero_str				// Format string
	CALL_EXTERN panic							// Game over

L_preempt_count_notzero_str:
	.asciz "preemption count not 0 on thread %p (%u)"
#endif /* MACH_ASSERT */

#if __ARM_KERNEL_PROTECT__
	/*
	 * This symbol denotes the end of the exception vector/eret range; we page
	 * align it so that we can avoid mapping other text in the EL0 exception
	 * vector mapping.
	 */
	.text
	.align 14
	.globl EXT(ExceptionVectorsEnd)
LEXT(ExceptionVectorsEnd)
#endif /* __ARM_KERNEL_PROTECT__ */

#if XNU_MONITOR && !CONFIG_SPTM

/*
 * Functions to preflight the fleh handlers when the PPL has taken an exception;
 * mostly concerned with setting up state for the normal fleh code.
 */
	.text
	.align 2
fleh_synchronous_from_ppl:
	/* Save x0. */
	mov		x15, x0

	/* Grab the ESR. */
	mrs		x1, ESR_EL1							// Get the exception syndrome

	/* If the stack pointer is corrupt, it will manifest either as a data abort
	 * (syndrome 0x25) or a misaligned pointer (syndrome 0x26). We can check
	 * these quickly by testing bit 5 of the exception class.
	 */
	tbz		x1, #(5 + ESR_EC_SHIFT), Lvalid_ppl_stack
	mrs		x0, SP_EL0							// Get SP_EL0

	/* Perform high level checks for stack corruption. */
	and		x1, x1, #ESR_EC_MASK				// Mask the exception class
	mov		x2, #(ESR_EC_SP_ALIGN << ESR_EC_SHIFT)
	cmp		x1, x2								// If we have a stack alignment exception
	b.eq	Lcorrupt_ppl_stack						// ...the stack is definitely corrupted
	mov		x2, #(ESR_EC_DABORT_EL1 << ESR_EC_SHIFT)
	cmp		x1, x2								// If we have a data abort, we need to
	b.ne	Lvalid_ppl_stack						// ...validate the stack pointer

Ltest_pstack:
	/* Bounds check the PPL stack. */
	adrp	x10, EXT(pmap_stacks_start)@page
	ldr		x10, [x10, #EXT(pmap_stacks_start)@pageoff]
	adrp	x11, EXT(pmap_stacks_end)@page
	ldr		x11, [x11, #EXT(pmap_stacks_end)@pageoff]
	cmp		x0, x10
	b.lo	Lcorrupt_ppl_stack
	cmp		x0, x11
	b.hi	Lcorrupt_ppl_stack

Lvalid_ppl_stack:
	/* Restore x0. */
	mov		x0, x15

	/* Switch back to the kernel stack. */
	msr		SPSel, #0
	GET_PMAP_CPU_DATA x5, x6, x7
	ldr		x6, [x5, PMAP_CPU_DATA_KERN_SAVED_SP]
	mov		sp, x6

	/* Hand off to the synch handler. */
	b		EXT(fleh_synchronous)

Lcorrupt_ppl_stack:
	/* Restore x0. */
	mov		x0, x15

	/* Hand off to the invalid stack handler. */
	b		fleh_invalid_stack

fleh_fiq_from_ppl:
	SWITCH_TO_INT_STACK	tmp=x25
	b		EXT(fleh_fiq)

fleh_irq_from_ppl:
	SWITCH_TO_INT_STACK	tmp=x25
	b		EXT(fleh_irq)

fleh_serror_from_ppl:
	GET_PMAP_CPU_DATA x5, x6, x7
	ldr		x6, [x5, PMAP_CPU_DATA_KERN_SAVED_SP]
	mov		sp, x6
	b		EXT(fleh_serror)




	// x15: ppl call number
	// w10: ppl_state
	// x20: gxf_enter caller's DAIF
	.globl EXT(ppl_trampoline_start)
LEXT(ppl_trampoline_start)


#error "XPRR configuration error"
	cmp		x14, x21
	b.ne	Lppl_fail_dispatch

	/* Verify the request ID. */
	cmp		x15, PMAP_COUNT
	b.hs	Lppl_fail_dispatch

	GET_PMAP_CPU_DATA	x12, x13, x14

	/* Mark this CPU as being in the PPL. */
	ldr		w9, [x12, PMAP_CPU_DATA_PPL_STATE]

	cmp		w9, #PPL_STATE_KERNEL
	b.eq		Lppl_mark_cpu_as_dispatching

	/* Check to see if we are trying to trap from within the PPL. */
	cmp		w9, #PPL_STATE_DISPATCH
	b.eq		Lppl_fail_dispatch_ppl


	/* Ensure that we are returning from an exception. */
	cmp		w9, #PPL_STATE_EXCEPTION
	b.ne		Lppl_fail_dispatch

	// where is w10 set?
	// in CHECK_EXCEPTION_RETURN_DISPATCH_PPL
	cmp		w10, #PPL_STATE_EXCEPTION
	b.ne		Lppl_fail_dispatch

	/* This is an exception return; set the CPU to the dispatching state. */
	mov		w9, #PPL_STATE_DISPATCH
	str		w9, [x12, PMAP_CPU_DATA_PPL_STATE]

	/* Find the save area, and return to the saved PPL context. */
	ldr		x0, [x12, PMAP_CPU_DATA_SAVE_AREA]
	mov		sp, x0
	b		EXT(return_to_ppl)

Lppl_mark_cpu_as_dispatching:
	cmp		w10, #PPL_STATE_KERNEL
	b.ne		Lppl_fail_dispatch

	/* Mark the CPU as dispatching. */
	mov		w13, #PPL_STATE_DISPATCH
	str		w13, [x12, PMAP_CPU_DATA_PPL_STATE]

	/* Switch to the regular PPL stack. */
	// TODO: switch to PPL_STACK earlier in gxf_ppl_entry_handler
	ldr		x9, [x12, PMAP_CPU_DATA_PPL_STACK]

	// SP0 is thread stack here
	mov		x21, sp
	// SP0 is now PPL stack
	mov		sp, x9

	/* Save the old stack pointer off in case we need it. */
	str		x21, [x12, PMAP_CPU_DATA_KERN_SAVED_SP]

	/* Get the handler for the request */
	adrp	x9, EXT(ppl_handler_table)@page
	add		x9, x9, EXT(ppl_handler_table)@pageoff
	add		x9, x9, x15, lsl #3
	ldr		x10, [x9]

	/* Branch to the code that will invoke the PPL request. */
	b		EXT(ppl_dispatch)

Lppl_fail_dispatch_ppl:
	/* Switch back to the kernel stack. */
	ldr		x10, [x12, PMAP_CPU_DATA_KERN_SAVED_SP]
	mov		sp, x10

Lppl_fail_dispatch:
	/* Indicate that we failed. */
	mov		x15, #PPL_EXIT_BAD_CALL

	/* Move the DAIF bits into the expected register. */
	mov		x10, x20

	/* Return to kernel mode. */
	b		ppl_return_to_kernel_mode

Lppl_dispatch_exit:

	/* Indicate that we are cleanly exiting the PPL. */
	mov		x15, #PPL_EXIT_DISPATCH

	/* Switch back to the original (kernel thread) stack. */
	mov		sp, x21

	/* Move the saved DAIF bits. */
	mov		x10, x20

	/* Clear the in-flight pmap pointer */
	add		x13, x12, PMAP_CPU_DATA_INFLIGHT_PMAP
	stlr		xzr, [x13]

	/* Clear the old stack pointer. */
	str		xzr, [x12, PMAP_CPU_DATA_KERN_SAVED_SP]

	/*
	 * Mark the CPU as no longer being in the PPL.  We spin if our state
	 * machine is broken.
	 */
	ldr		w9, [x12, PMAP_CPU_DATA_PPL_STATE]
	cmp		w9, #PPL_STATE_DISPATCH
	b.ne		.
	mov		w9, #PPL_STATE_KERNEL
	str		w9, [x12, PMAP_CPU_DATA_PPL_STATE]

	/* Return to the kernel. */
	b ppl_return_to_kernel_mode



	.text
ppl_exit:
	/*
	 * If we are dealing with an exception, hand off to the first level
	 * exception handler.
	 */
	cmp		x15, #PPL_EXIT_EXCEPTION
	b.eq	Ljump_to_fleh_handler

	/* If this was a panic call from the PPL, reinvoke panic. */
	cmp		x15, #PPL_EXIT_PANIC_CALL
	b.eq	Ljump_to_panic_trap_to_debugger

	/*
	 * Stash off the original DAIF in the high bits of the exit code register.
	 * We could keep this in a dedicated register, but that would require us to copy it to
	 * an additional callee-save register below (e.g. x22), which in turn would require that
	 * register to be saved/restored at PPL entry/exit.
	 */
	add		x15, x15, x10, lsl #32

	/* Load the preemption count. */
	mrs		x10, TPIDR_EL1
	ldr		w12, [x10, ACT_PREEMPT_CNT]

	/* Detect underflow */
	cbnz	w12, Lno_preempt_underflow
	b		preempt_underflow
Lno_preempt_underflow:

	/* Lower the preemption count. */
	sub		w12, w12, #1

#if SCHED_HYGIENE_DEBUG
	/* Collect preemption disable measurement if necessary. */

	/*
	 * Only collect measurement if this reenabled preemption,
	 * and SCHED_HYGIENE_MARKER is set.
	 */
	mov		x20, #SCHED_HYGIENE_MARKER
	cmp		w12, w20
	b.ne	Lskip_collect_measurement

	/* Stash our return value and return reason. */
	mov		x20, x0
	mov		x21, x15

	/* Collect measurement. */
	bl		EXT(_collect_preemption_disable_measurement)

	/* Restore the return value and the return reason. */
	mov		x0, x20
	mov		x15, x21
	/* ... and w12, which is now 0. */
	mov		w12, #0

	/* Restore the thread pointer into x10. */
	mrs		x10, TPIDR_EL1

Lskip_collect_measurement:
#endif /* SCHED_HYGIENE_DEBUG */

	/* Save the lowered preemption count. */
	str		w12, [x10, ACT_PREEMPT_CNT]

	/* Skip ASTs if the peemption count is not zero. */
	cbnz	x12, Lppl_skip_ast_taken

	/*
	 * Skip the AST check if interrupts were originally disabled.
	 * The original DAIF state prior to PPL entry is stored in the upper
	 * 32 bits of x15.
	 */
	tbnz		x15, #(DAIF_IRQF_SHIFT + 32), Lppl_skip_ast_taken

	/* IF there is no urgent AST, skip the AST. */
	ldr		x12, [x10, ACT_CPUDATAP]
	ldr		w14, [x12, CPU_PENDING_AST]
	tst		w14, AST_URGENT
	b.eq	Lppl_skip_ast_taken

	/* Stash our return value and return reason. */
	mov		x20, x0
	mov		x21, x15

	/* Handle the AST. */
	bl		EXT(ast_taken_kernel)

	/* Restore the return value and the return reason. */
	mov		x15, x21
	mov		x0, x20

Lppl_skip_ast_taken:

	/* Extract caller DAIF from high-order bits of exit code */
	ubfx	x10, x15, #32, #32
	bfc		x15, #32, #32
	msr		DAIF, x10

	/* Pop the stack frame. */
	ldp		x29, x30, [sp, #0x10]
	ldp		x20, x21, [sp], #0x20

	/* Check to see if this was a bad request. */
	cmp		x15, #PPL_EXIT_BAD_CALL
	b.eq	Lppl_bad_call

	/* Return. */
	ARM64_STACK_EPILOG

	.align 2
Ljump_to_fleh_handler:
	br	x25

	.align 2
Ljump_to_panic_trap_to_debugger:
	b		EXT(panic_trap_to_debugger)

Lppl_bad_call:
	/* Panic. */
	adrp	x0, Lppl_bad_call_panic_str@page
	add		x0, x0, Lppl_bad_call_panic_str@pageoff
	b		EXT(panic)

	.text
	.align 2
	.globl EXT(ppl_dispatch)
LEXT(ppl_dispatch)
	/*
	 * Save a couple of important registers (implementation detail; x12 has
	 * the PPL per-CPU data address; x13 is not actually interesting).
	 */
	stp		x12, x13, [sp, #-0x10]!

	/*
	 * Restore the original AIF state, force D set to mask debug exceptions
	 * while PPL code runs.
	 */
	orr		x8, x20, DAIF_DEBUGF
	msr		DAIF, x8

	/*
	 * Note that if the method is NULL, we'll blow up with a prefetch abort,
	 * but the exception vectors will deal with this properly.
	 */

	/* Invoke the PPL method. */
#ifdef HAS_APPLE_PAC
	blraa		x10, x9
#else
	blr		x10
#endif

	/* Disable DAIF. */
	msr		DAIFSet, #(DAIFSC_ALL)

	/* Restore those important registers. */
	ldp		x12, x13, [sp], #0x10

	/* Mark this as a regular return, and hand off to the return path. */
	b		Lppl_dispatch_exit

	.text
	.align 2
	.globl EXT(ppl_bootstrap_dispatch)
LEXT(ppl_bootstrap_dispatch)
	/* Verify the PPL request. */
	cmp		x15, PMAP_COUNT
	b.hs	Lppl_fail_bootstrap_dispatch

	/* Get the requested PPL routine. */
	adrp	x9, EXT(ppl_handler_table)@page
	add		x9, x9, EXT(ppl_handler_table)@pageoff
	add		x9, x9, x15, lsl #3
	ldr		x10, [x9]

	/* Invoke the requested PPL routine. */
#ifdef HAS_APPLE_PAC
	blraa		x10, x9
#else
	blr		x10
#endif
	LOAD_PMAP_CPU_DATA	x9, x10, x11

	/* Clear the in-flight pmap pointer */
	add		x9, x9, PMAP_CPU_DATA_INFLIGHT_PMAP
	stlr		xzr, [x9]

	/* Stash off the return value */
	mov		x20, x0
	/* Drop the preemption count */
	bl		EXT(_enable_preemption)
	mov		x0, x20

	/* Pop the stack frame. */
	ldp		x29, x30, [sp, #0x10]
	ldp		x20, x21, [sp], #0x20
#if __has_feature(ptrauth_returns)
	retab
#else
	ret
#endif

Lppl_fail_bootstrap_dispatch:
	/* Pop our stack frame and panic. */
	ldp		x29, x30, [sp, #0x10]
	ldp		x20, x21, [sp], #0x20
#if __has_feature(ptrauth_returns)
	autibsp
#endif
	adrp	x0, Lppl_bad_call_panic_str@page
	add		x0, x0, Lppl_bad_call_panic_str@pageoff
	b		EXT(panic)

	.text
	.align 2
	.globl EXT(ml_panic_trap_to_debugger)
LEXT(ml_panic_trap_to_debugger)
	mrs		x10, DAIF
	msr		DAIFSet, #(DAIFSC_STANDARD_DISABLE)

	adrp		x12, EXT(pmap_ppl_locked_down)@page
	ldr		w12, [x12, #EXT(pmap_ppl_locked_down)@pageoff]
	cbz		w12, Lnot_in_ppl_dispatch

	LOAD_PMAP_CPU_DATA	x11, x12, x13

	ldr		w12, [x11, PMAP_CPU_DATA_PPL_STATE]
	cmp		w12, #PPL_STATE_DISPATCH
	b.ne		Lnot_in_ppl_dispatch

	/* Indicate (for the PPL->kernel transition) that we are panicking. */
	mov		x15, #PPL_EXIT_PANIC_CALL

	/* Restore the old stack pointer as we can't push onto PPL stack after we exit PPL */
	ldr		x12, [x11, PMAP_CPU_DATA_KERN_SAVED_SP]
	mov		sp, x12

	mrs		x10, DAIF
	mov		w13, #PPL_STATE_PANIC
	str		w13, [x11, PMAP_CPU_DATA_PPL_STATE]

	/* Now we are ready to exit the PPL. */
	b		ppl_return_to_kernel_mode
Lnot_in_ppl_dispatch:
	msr		DAIF, x10
	ret

	.data
Lppl_bad_call_panic_str:
	.asciz "ppl_dispatch: failed due to bad arguments/state"
#else /* XNU_MONITOR && !CONFIG_SPTM */
	.text
	.align 2
	.globl EXT(ml_panic_trap_to_debugger)
LEXT(ml_panic_trap_to_debugger)
	ret
#endif /* XNU_MONITOR && !CONFIG_SPTM */

#if CONFIG_SPTM
	.text
	.align 2

	.globl EXT(_sptm_pre_entry_hook)
LEXT(_sptm_pre_entry_hook)
	/* Push a frame. */
	ARM64_STACK_PROLOG
	PUSH_FRAME
	stp		x20, x21, [sp, #-0x10]!

	/* Increase the preemption count. */
	mrs		x9, TPIDR_EL1
	cbz		x9, Lskip_preemption_check_sptmhook
	ldr		w10, [x9, ACT_PREEMPT_CNT]
	add		w10, w10, #1
	str		w10, [x9, ACT_PREEMPT_CNT]

#if SCHED_HYGIENE_DEBUG
	/* Prepare preemption disable measurement, if necessary. */

	/* Only prepare if we actually disabled preemption. */
	cmp		w10, #1
	b.ne	Lskip_prepare_measurement_sptmhook

	/* Don't prepare if measuring is off completely. */
	adrp	x10, _sched_preemption_disable_debug_mode@page
	add		x10, x10, _sched_preemption_disable_debug_mode@pageoff
	ldr		w10, [x10]
	cmp		w10, #0
	b.eq	Lskip_prepare_measurement_sptmhook

	/* Save arguments to SPTM function and SPTM function id. */
	mov		x20, x16
	stp		x0, x1, [sp, #-0x40]!
	stp		x2, x3, [sp, #0x10]
	stp		x4, x5, [sp, #0x20]
	stp		x6, x7, [sp, #0x30]

	/* Call prepare function with thread pointer as first arg. */
	bl		EXT(_prepare_preemption_disable_measurement)

	/* Restore arguments to SPTM function and SPTM function id. */
	ldp		x6, x7, [sp, #0x30]
	ldp		x4, x5, [sp, #0x20]
	ldp		x2, x3, [sp, #0x10]
	ldp		x0, x1, [sp]
	add		sp, sp, #0x40
	mov		x16, x20

Lskip_prepare_measurement_sptmhook:
#endif /* SCHED_HYGIENE_DEBUG */
Lskip_preemption_check_sptmhook:
	/* assert we're not calling from guarded mode */
	mrs		x14, CurrentG
	cmp		x14, #0
	b.ne	.

	ldp		x20, x21, [sp], #0x10
	POP_FRAME
	ARM64_STACK_EPILOG

	.align 2
	.globl EXT(_sptm_post_exit_hook)
LEXT(_sptm_post_exit_hook)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	stp		x20, x21, [sp, #-0x10]!

	/* Save SPTM return value(s) */
	stp		x0, x1, [sp, #-0x40]!
	stp		x2, x3, [sp, #0x10]
	stp		x4, x5, [sp, #0x20]
	stp		x6, x7, [sp, #0x30]

	/* Load the preemption count. */
	mrs		x0, TPIDR_EL1
	cbz		x0, Lsptm_skip_ast_taken_sptmhook
	ldr		w12, [x0, ACT_PREEMPT_CNT]

	/* Detect underflow */
	cbnz	w12, Lno_preempt_underflow_sptmhook
	/* No need to clean up the stack, as preempt_underflow calls panic */
	b		preempt_underflow
Lno_preempt_underflow_sptmhook:

	/* Lower the preemption count. */
	sub		w12, w12, #1

#if SCHED_HYGIENE_DEBUG
	/* Collect preemption disable measurement if necessary. */

	/*
	 * Only collect measurement if this reenabled preemption,
	 * and SCHED_HYGIENE_MARKER is set.
	 */
	mov		x20, #SCHED_HYGIENE_MARKER
	cmp		w12, w20
	b.ne	Lskip_collect_measurement_sptmhook

	/* Collect measurement. */
	bl		EXT(_collect_preemption_disable_measurement)

	/* Restore w12, which is now 0. */
	mov		w12, #0

	/* Restore x0 as the thread pointer */
	mrs		x0, TPIDR_EL1

Lskip_collect_measurement_sptmhook:
#endif /* SCHED_HYGIENE_DEBUG */

	/* Save the lowered preemption count. */
	str		w12, [x0, ACT_PREEMPT_CNT]

	/* Skip ASTs if the preemption count is not zero. */
	cbnz	w12, Lsptm_skip_ast_taken_sptmhook

	/**
	 * Skip the AST check if interrupts were originally disabled. The original
	 * DAIF value needs to be placed into a callee-saved register so that the
	 * value is preserved across the ast_taken_kernel() call.
	 */
	mrs		x20, DAIF
	tbnz	x20, #(DAIF_IRQF_SHIFT), Lsptm_skip_ast_taken_sptmhook

	/* IF there is no urgent AST, skip the AST. */
	ldr		x12, [x0, ACT_CPUDATAP]
	ldr		x14, [x12, CPU_PENDING_AST]
	tst		x14, AST_URGENT
	b.eq	Lsptm_skip_ast_taken_sptmhook

	/* Handle the AST. This call requires interrupts to be disabled. */
	msr		DAIFSet, #(DAIFSC_ALL)
	bl		EXT(ast_taken_kernel)
	msr		DAIF, x20

Lsptm_skip_ast_taken_sptmhook:

	/* Restore SPTM return value(s) */
	ldp		x6, x7, [sp, #0x30]
	ldp		x4, x5, [sp, #0x20]
	ldp		x2, x3, [sp, #0x10]
	ldp		x0, x1, [sp]
	add		sp, sp, #0x40

	/* Return. */
	ldp		x20, x21, [sp], 0x10
	POP_FRAME
	ARM64_STACK_EPILOG
#endif /* CONFIG_SPTM */

/* ARM64_TODO Is globals_asm.h needed? */
//#include	"globals_asm.h"

/* vim: set ts=4: */
