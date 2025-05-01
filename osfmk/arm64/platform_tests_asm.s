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

#include <arm64/asm.h>
#include <pexpert/arm64/board_config.h>


#if CONFIG_SPTM
	.text
	.align 2
	.globl EXT(arm64_panic_lockdown_test_load)
LEXT(arm64_panic_lockdown_test_load)
	ARM64_PROLOG
	ldr		x0, [x0]
	ret

	.globl EXT(arm64_panic_lockdown_test_gdbtrap)
LEXT(arm64_panic_lockdown_test_gdbtrap)
	ARM64_PROLOG
	.long 0xe7ffdefe
	ret

#if __has_feature(ptrauth_calls)
	.globl EXT(arm64_panic_lockdown_test_pac_brk_c470)
LEXT(arm64_panic_lockdown_test_pac_brk_c470)
	ARM64_PROLOG
	brk		0xC470
	ret

	.globl EXT(arm64_panic_lockdown_test_pac_brk_c471)
LEXT(arm64_panic_lockdown_test_pac_brk_c471)
	ARM64_PROLOG
	brk		0xC471
	ret

	.globl EXT(arm64_panic_lockdown_test_pac_brk_c472)
LEXT(arm64_panic_lockdown_test_pac_brk_c472)
	ARM64_PROLOG
	brk		0xC472
	ret

	.globl EXT(arm64_panic_lockdown_test_pac_brk_c473)
LEXT(arm64_panic_lockdown_test_pac_brk_c473)
	ARM64_PROLOG
	brk		0xC473
	ret

	.globl EXT(arm64_panic_lockdown_test_telemetry_brk_ff00)
LEXT(arm64_panic_lockdown_test_telemetry_brk_ff00)
	ARM64_PROLOG
	brk		0xFF00
	ret

	.globl EXT(arm64_panic_lockdown_test_br_auth_fail)
LEXT(arm64_panic_lockdown_test_br_auth_fail)
	ARM64_PROLOG
	braaz	x0
	ret

	.globl EXT(arm64_panic_lockdown_test_ldr_auth_fail)
LEXT(arm64_panic_lockdown_test_ldr_auth_fail)
	ARM64_PROLOG
	ldraa	x0, [x0]
	ret
#endif /* ptrauth_calls  */

#if __ARM_ARCH_8_6__
	.globl EXT(arm64_panic_lockdown_test_fpac)
LEXT(arm64_panic_lockdown_test_fpac)
	ARM64_PROLOG
	autiza	x0
	ret
#endif /* __ARM_ARCH_8_6__ */

#if BTI_ENFORCED && CONFIG_BTI_TELEMETRY
	.globl EXT(arm64_panic_lockdown_test_bti_telemetry)
LEXT(arm64_panic_lockdown_test_bti_telemetry)
	ARM64_PROLOG
	/*
	 * Trigger a BTI exception on the first instruction *after* the landing pad.
	 */
0:
	nop
	adr		x0, 0b
	br		x0
#endif /* BTI_ENFORCED && CONFIG_BTI_TELEMETRY */

/*
 * SP1 Panic Lockdown Tests
 *
 * These tests are somewhat complex because we're round tripping through an
 * exception vector which is not intended to return. This means we'll lose a
 * fair amount of state. The only thing we can really rely on being preserved is
 * SP_EL0 as we stay on SP1 for the entire vector. As such, we need to save all
 * callee saved registers here.
 */

.macro SAVE_CALLEE_REGISTERS
	stp		x19, x20, [sp, #-(16 * 10)]!
	stp		x21, x22, [sp, #0x10]
	stp		x23, x24, [sp, #0x20]
	stp		x25, x26, [sp, #0x30]
	stp		x27, x28, [sp, #0x40]
	stp		x29, x30, [sp, #0x50]
	stp		q4, q5, [sp, #0x60]
	stp		q6, q7, [sp, #0x80]
.endmacro

.macro LOAD_CALLEE_REGISTERS
	ldp		x21, x22, [sp, #0x10]
	ldp		x23, x24, [sp, #0x20]
	ldp		x25, x26, [sp, #0x30]
	ldp		x27, x28, [sp, #0x40]
	ldp		x29, x30, [sp, #0x50]
	ldp		q4, q5, [sp, #0x60]
	ldp		q6, q7, [sp, #0x80]
	ldp		x19, x20, [sp], #(16*10)
.endmacro

/**
 * arm64_panic_lockdown_test_sp1_invalid_stack
 *
 * This test simulates a stack overflow/corruption
 */
	.globl EXT(arm64_panic_lockdown_test_sp1_invalid_stack)
LEXT(arm64_panic_lockdown_test_sp1_invalid_stack)
	ARM64_STACK_PROLOG
	SAVE_CALLEE_REGISTERS
	/* Spill the real SP1 to the stack and trash the old one */
	msr		SPSel, #1
	mov		x0, sp
	mov		x1, #0
	mov		sp, x1
	msr		SPSel, #0
	str		x0, [sp, #-16]!
	/* Take an exception on SP1 but outside the critical region */
	msr		SPSel, #1
	b		EXT(arm64_panic_lockdown_test_pac_brk_c470)

	.global EXT(arm64_panic_lockdown_test_sp1_invalid_stack_handler)
LEXT(arm64_panic_lockdown_test_sp1_invalid_stack_handler)
	ARM64_PROLOG
	/* If we made it here, the test passed. Fix the system up. */
	mrs		x0, SP_EL0
	ldr		x1, [x0], #16
	/* Restore the real SP1 */
	mov		sp, x1
	/* Update SP0 to prepare to return */
	msr		SPSel, #0
	mov		sp, x0
	/* Return 1 to indicate success */
	mov		x0, #1
	LOAD_CALLEE_REGISTERS
	ARM64_STACK_EPILOG

/**
 * arm64_panic_lockdown_test_sp1_exception_in_vector
 * This test simulates an exception in the SP1 critical region
 */
	.globl EXT(arm64_panic_lockdown_test_sp1_exception_in_vector)
LEXT(arm64_panic_lockdown_test_sp1_exception_in_vector)
	ARM64_STACK_PROLOG
	SAVE_CALLEE_REGISTERS
	/* Trigger an exception inside the vector on SP1 */
	msr		SPSel, #1
	b		EXT(el1_sp1_synchronous_raise_exception_in_vector)

	.globl EXT(arm64_panic_lockdown_test_sp1_exception_in_vector_handler)
LEXT(arm64_panic_lockdown_test_sp1_exception_in_vector_handler)
	ARM64_PROLOG
	/* Return to SP0 */
	msr		SPSel, #0
	/* Return 1 to indicate success */
	mov		x0, #1
	LOAD_CALLEE_REGISTERS
	ARM64_STACK_EPILOG

#endif /* CONFIG_SPTM */

#if BTI_ENFORCED
	.text
	.align 2
	.global EXT(arm64_bti_test_jump_shim)
LEXT(arm64_bti_test_jump_shim)
	ARM64_PROLOG
#if __has_feature(ptrauth_calls)
	braaz	x0
#else
	br		x0
#endif /* __has_feature(ptrauth_calls) */

	.global EXT(arm64_bti_test_call_shim)
LEXT(arm64_bti_test_call_shim)
	ARM64_STACK_PROLOG
	PUSH_FRAME
#if __has_feature(ptrauth_calls)
	blraaz	x0
#else
	blr		x0
#endif /* __has_feature(ptrauth_calls) */
	POP_FRAME
	ARM64_STACK_EPILOG

	.globl EXT(arm64_bti_test_func_with_no_landing_pad)
LEXT(arm64_bti_test_func_with_no_landing_pad)
	mov		x0, #1
	ret

	.globl EXT(arm64_bti_test_func_with_call_landing_pad)
LEXT(arm64_bti_test_func_with_call_landing_pad)
	bti		c
	mov		x0, #2
	ret

	.globl EXT(arm64_bti_test_func_with_jump_landing_pad)
LEXT(arm64_bti_test_func_with_jump_landing_pad)
	bti		j
	mov		x0, #3
	ret

	.globl EXT(arm64_bti_test_func_with_jump_call_landing_pad)
LEXT(arm64_bti_test_func_with_jump_call_landing_pad)
	bti		jc
	mov		x0, #4
	ret

#if __has_feature(ptrauth_returns)
	.globl EXT(arm64_bti_test_func_with_pac_landing_pad)
LEXT(arm64_bti_test_func_with_pac_landing_pad)
	pacibsp
	mov		x0, #5
	retab
#endif /* __has_feature(ptrauth_returns) */
#endif /* BTI_ENFORCED */
