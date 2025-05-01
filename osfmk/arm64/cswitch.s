/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
#include <arm64/pac_asm.h>
#include <arm64/proc_reg.h>
#include "assym.s"

/*
 * save_general_registers
 *
 * Saves variable registers to kernel PCB.
 *   arg0 - thread_kernel_state pointer
 *   arg1 - Scratch register
 */

.macro	save_general_registers
/* AAPCS-64 Page 14
 *
 * A subroutine invocation must preserve the contents of the registers r19-r29
 * and SP.
 */
#if __has_feature(ptrauth_calls)
	paciasp
#endif
	stp		x19, x20, [$0, SS64_KERNEL_X19]
	stp		x21, x22, [$0, SS64_KERNEL_X21]
	stp		x23, x24, [$0, SS64_KERNEL_X23]
	stp		x25, x26, [$0, SS64_KERNEL_X25]
	stp		x27, x28, [$0, SS64_KERNEL_X27]
	stp		fp, lr, [$0, SS64_KERNEL_FP]
	strb	wzr, [$0, SS64_KERNEL_PC_WAS_IN_USER]
	mov		x$1, sp
	str		x$1, [$0, SS64_KERNEL_SP]
#if HAS_ARM_FEAT_SSBS2
#if APPLEVIRTUALPLATFORM
	adrp	x$1, EXT(gARM_FEAT_SSBS)@page
	ldrh	w$1, [x$1, EXT(gARM_FEAT_SSBS)@pageoff]
	cbz		x$1, 1f
#endif
	mrs		x$1, SSBS
	lsr     x$1, x$1, #0 + PSR64_SSBS_SHIFT_64
	strb	w$1, [$0, SS64_KERNEL_SSBS]
1:
#endif // HAS_ARM_FEAT_SSBS2
#if __ARM_ARCH_8_4__
	mrs		x$1, DIT
	lsr     x$1, x$1, #0 + PSR64_DIT_SHIFT
	strb	w$1, [$0, SS64_KERNEL_DIT]
#endif //__ARM_ARCH_8_4__
#if __ARM_ARCH_8_2__
	mrs		x$1, UAO
	lsr     x$1, x$1, #0 + PSR64_UAO_SHIFT
	strb	w$1, [$0, SS64_KERNEL_UAO]
#endif //__ARM_ARCH_8_2__

/* AAPCS-64 Page 14
 *
 * Registers d8-d15 (s8-s15) must be preserved by a callee across subroutine
 * calls; the remaining registers (v0-v7, v16-v31) do not need to be preserved
 * (or should be preserved by the caller).
 */
	str		d8,	[$0, NS64_KERNEL_D8]
	str		d9,	[$0, NS64_KERNEL_D9]
	str		d10,[$0, NS64_KERNEL_D10]
	str		d11,[$0, NS64_KERNEL_D11]
	str		d12,[$0, NS64_KERNEL_D12]
	str		d13,[$0, NS64_KERNEL_D13]
	str		d14,[$0, NS64_KERNEL_D14]
	str		d15,[$0, NS64_KERNEL_D15]

	mrs		x$1, FPCR
	str		w$1, [$0, NS64_KERNEL_FPCR]
.endmacro

/*
 * load_general_registers
 *
 * Loads variable registers from kernel PCB.
 *   arg0 - thread_kernel_state pointer
 *   arg1 - Scratch register
 */
.macro	load_general_registers
	ldr		w$1, [$0, NS64_KERNEL_FPCR]
	mrs		x19, FPCR
	CMSR FPCR, x19, x$1, 1
1:

	ldp		x19, x20, [$0, SS64_KERNEL_X19]
	ldp		x21, x22, [$0, SS64_KERNEL_X21]
	ldp		x23, x24, [$0, SS64_KERNEL_X23]
	ldp		x25, x26, [$0, SS64_KERNEL_X25]
	ldp		x27, x28, [$0, SS64_KERNEL_X27]
	ldp		fp, lr, [$0, SS64_KERNEL_FP]
	ldr		x$1, [$0, SS64_KERNEL_SP]
	mov		sp, x$1
#if HAS_ARM_FEAT_SSBS2
#if APPLEVIRTUALPLATFORM
	adrp	x$1, EXT(gARM_FEAT_SSBS)@page
	ldrh	w$1, [x$1, EXT(gARM_FEAT_SSBS)@pageoff]
	cbz		x$1, 1f
#endif // APPLEVIRTUALPLATFORM
	ldrb	w$1, [$0, SS64_KERNEL_SSBS]
	lsl     x$1, x$1, #0 + PSR64_SSBS_SHIFT_64
	msr		SSBS, x$1
1:
#endif // HAS_ARM_FEAT_SSBS2
#if __ARM_ARCH_8_2__
	ldrb	w$1, [$0, SS64_KERNEL_UAO]
	lsl     x$1, x$1, #0 + PSR64_UAO_SHIFT
	msr		UAO, x$1
#endif //__ARM_ARCH_8_2__
#if __ARM_ARCH_8_4__
	ldrb	w$1, [$0, SS64_KERNEL_DIT]
	lsl     x$1, x$1, #0 + PSR64_DIT_SHIFT
	msr		DIT, x$1
#endif //__ARM_ARCH_8_4__

	ldr		d8,	[$0, NS64_KERNEL_D8]
	ldr		d9,	[$0, NS64_KERNEL_D9]
	ldr		d10,[$0, NS64_KERNEL_D10]
	ldr		d11,[$0, NS64_KERNEL_D11]
	ldr		d12,[$0, NS64_KERNEL_D12]
	ldr		d13,[$0, NS64_KERNEL_D13]
	ldr		d14,[$0, NS64_KERNEL_D14]
	ldr		d15,[$0, NS64_KERNEL_D15]
.endmacro

/*
 * cswitch_epilogue
 *
 * Returns to the address reloaded into LR, authenticating if needed.
 */
.macro	cswitch_epilogue
#if __has_feature(ptrauth_calls)
	retaa
#else
	ret
#endif
.endm


/*
 * set_thread_registers
 *
 * Updates thread registers during context switch
 *  arg0 - New thread pointer
 *  arg1 - Scratch register
 *  arg2 - Scratch register
 */
.macro	set_thread_registers
	msr		TPIDR_EL1, $0						// Write new thread pointer to TPIDR_EL1
	ldr		$1, [$0, ACT_CPUDATAP]
	str		$0, [$1, CPU_ACTIVE_THREAD]

	ldr	    $2, [$1, CPU_TPIDR_EL0]             // Write encoded CPU info to TPIDR_EL0
	msr		TPIDR_EL0, $2

	ldr		$1, [$0, TH_CTH_SELF]				// Get cthread pointer
	msr		TPIDRRO_EL0, $1

	ldr		$1, [$0, TH_THREAD_ID]				// Save the bottom 32-bits of the thread ID into
	msr		CONTEXTIDR_EL1, $1					// CONTEXTIDR_EL1 (top 32-bits are RES0).
.endmacro

#define CSWITCH_ROP_KEYS	(HAS_APPLE_PAC && HAS_PARAVIRTUALIZED_PAC)
#define CSWITCH_JOP_KEYS	(HAS_APPLE_PAC && HAS_PARAVIRTUALIZED_PAC)

/*
 * set_process_dependent_keys_and_sync_context
 *
 * Updates process dependent keys and issues explicit context sync during context switch if necessary
 *  Per CPU Data rop_key is initialized in arm_init() for bootstrap processor
 *  and in cpu_data_init for slave processors
 *
 *  thread - New thread pointer
 *  new_key - Scratch register: New Thread Key
 *  tmp_key - Scratch register: Current CPU Key
 *  cpudatap - Scratch register: Current CPU Data pointer
 *  wsync - Half-width scratch register: CPU sync required flag
 *
 *  to save on ISBs, for ARMv8.5 we use the CPU_SYNC_ON_CSWITCH field, cached in wsync, for pre-ARMv8.5,
 *  we just use wsync to keep track of needing an ISB
 */
.macro set_process_dependent_keys_and_sync_context	thread, new_key, tmp_key, cpudatap, wsync


#if defined(ERET_IS_NOT_CONTEXT_SYNCHRONIZING) || defined(HAS_APPLE_PAC)
	ldr		\cpudatap, [\thread, ACT_CPUDATAP]
#endif /* defined(ERET_IS_NOT_CONTEXT_SYNCHRONIZING) || defined(HAS_APPLE_PAC) */

#if defined(ERET_IS_NOT_CONTEXT_SYNCHRONIZING)
	ldrb	\wsync, [\cpudatap, CPU_SYNC_ON_CSWITCH]
#else /* defined(ERET_IS_NOT_CONTEXT_SYNCHRONIZING) */
	mov		\wsync, #0
#endif

#if CSWITCH_ROP_KEYS
	ldr		\new_key, [\thread, TH_ROP_PID]
	REPROGRAM_ROP_KEYS	Lskip_rop_keys_\@, \new_key, \cpudatap, \tmp_key
#if HAS_PARAVIRTUALIZED_PAC
	/* xnu hypervisor guarantees context synchronization during guest re-entry */
	mov		\wsync, #0
#else
	mov		\wsync, #1
#endif
Lskip_rop_keys_\@:
#endif /* CSWITCH_ROP_KEYS */

#if CSWITCH_JOP_KEYS
	ldr		\new_key, [\thread, TH_JOP_PID]
	REPROGRAM_JOP_KEYS	Lskip_jop_keys_\@, \new_key, \cpudatap, \tmp_key
#if HAS_PARAVIRTUALIZED_PAC
	mov		\wsync, #0
#else
	mov		\wsync, #1
#endif
Lskip_jop_keys_\@:
#endif /* CSWITCH_JOP_KEYS */

	cbz		\wsync, 1f
	isb 	sy

#if HAS_PARAVIRTUALIZED_PAC
1:	/* guests need to clear the sync flag even after skipping the isb, in case they synced via hvc instead */
#endif
#if defined(ERET_IS_NOT_CONTEXT_SYNCHRONIZING)
	strb	wzr, [\cpudatap, CPU_SYNC_ON_CSWITCH]
#endif
1:
.endmacro

/*
 * void     machine_load_context(thread_t        thread)
 *
 * Load the context for the first thread to run on a
 * cpu, and go.
 */
	.text
	.align 2
	.globl	EXT(machine_load_context)

LEXT(machine_load_context)
	ARM64_PROLOG
	set_thread_registers 	x0, x1, x2
	LOAD_KERN_STACK_TOP	dst=x1, src=x0, tmp=x2	// Get top of kernel stack
	load_general_registers 	x1, 2
	set_process_dependent_keys_and_sync_context	x0, x1, x2, x3, w4
	mov		x0, #0								// Clear argument to thread_continue
	cswitch_epilogue

/*
 *  typedef void (*thread_continue_t)(void *param, wait_result_t)
 *
 *	void Call_continuation( thread_continue_t continuation,
 *	            			void *param,
 *				            wait_result_t wresult,
 *                          bool enable interrupts)
 */
	.text
	.align	5
	.globl	EXT(Call_continuation)

LEXT(Call_continuation)
	ARM64_PROLOG
	mrs		x4, TPIDR_EL1						// Get the current thread pointer

	/* ARM64_TODO arm loads the kstack top instead of arg4. What should we use? */
	LOAD_KERN_STACK_TOP	dst=x5, src=x4, tmp=x6
	mov		sp, x5								// Set stack pointer
	mov		fp, #0								// Clear the frame pointer

	set_process_dependent_keys_and_sync_context	x4, x5, x6, x7, w20

	mov x20, x0  //continuation
	mov x21, x1  //continuation parameter
	mov x22, x2  //wait result

	cbz x3, 1f
	mov x0, #1
	bl EXT(ml_set_interrupts_enabled)
1:

	mov		x0, x21								// Set the first parameter
	mov		x1, x22								// Set the wait result arg
#ifdef HAS_APPLE_PAC
	mov		x21, THREAD_CONTINUE_T_DISC
	blraa	x20, x21							// Branch to the continuation
#else
	blr		x20									// Branch to the continuation
#endif
	mrs		x0, TPIDR_EL1						// Get the current thread pointer
	b		EXT(thread_terminate)				// Kill the thread


/*
 *	thread_t Switch_context(thread_t	old,
 * 				void		(*cont)(void),
 *				thread_t	new)
 */
	.text
	.align 5
	.globl	EXT(Switch_context)

LEXT(Switch_context)
	ARM64_PROLOG
	cbnz	x1, Lswitch_threads					// Skip saving old state if blocking on continuation
	LOAD_KERN_STACK_TOP	dst=x3, src=x0, tmp=x4	// Get the old kernel stack top
	save_general_registers	x3, 4
Lswitch_threads:
	set_thread_registers	x2, x3, x4
	LOAD_KERN_STACK_TOP	dst=x3, src=x2, tmp=x4
	load_general_registers	x3, 4
	set_process_dependent_keys_and_sync_context	x2, x3, x4, x5, w6
	cswitch_epilogue

/*
 *	thread_t Shutdown_context(void (*doshutdown)(processor_t), processor_t processor)
 *
 */
	.text
	.align 5
	.globl	EXT(Shutdown_context)

LEXT(Shutdown_context)
	ARM64_PROLOG
	mrs		x10, TPIDR_EL1							// Get thread pointer
	LOAD_KERN_STACK_TOP	dst=x11, src=x10, tmp=x12	// Get the top of the kernel stack
	save_general_registers	x11, 12
	msr		DAIFSet, #(DAIFSC_STANDARD_DISABLE)	// Disable interrupts
	LOAD_INT_STACK_THREAD dst=x12, src=x10, tmp=x11
	mov		sp, x12
	b		EXT(cpu_doshutdown)

/*
 *	thread_t Idle_context(void)
 *
 */
	.text
	.align 5
	.globl	EXT(Idle_context)

LEXT(Idle_context)
	ARM64_PROLOG
	mrs		x0, TPIDR_EL1						// Get thread pointer
	LOAD_KERN_STACK_TOP	dst=x1, src=x0, tmp=x2	// Get the top of the kernel stack
	save_general_registers	x1, 2
	LOAD_INT_STACK_THREAD	dst=x2, src=x0, tmp=x1
	mov		sp, x2
	b		EXT(cpu_idle)

/*
 *	thread_t Idle_context(void)
 *
 */
	.text
	.align 5
	.globl	EXT(Idle_load_context)

LEXT(Idle_load_context)
	ARM64_PROLOG
	mrs		x0, TPIDR_EL1						// Get thread pointer
	LOAD_KERN_STACK_TOP	dst=x1, src=x0, tmp=x2	// Get the top of the kernel stack
	load_general_registers	x1, 2
	set_process_dependent_keys_and_sync_context	x0, x1, x2, x3, w4
	cswitch_epilogue

	.align	2
	.globl	EXT(machine_set_current_thread)
LEXT(machine_set_current_thread)
	ARM64_PROLOG
	set_thread_registers x0, x1, x2
	ret


/* vim: set ts=4: */
