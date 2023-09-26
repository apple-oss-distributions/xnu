/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <arm64/proc_reg.h>
#include <pexpert/arm64/board_config.h>
#include "assym.s"

#ifndef __ASSEMBLER__
#error "This header should only be used in .s files"
#endif

/**
 * Loads the following values from the thread_kernel_state pointer in x0:
 *
 * x1: $x0->ss_64.pc
 * w2: $x0->ss_64.cpsr
 * x16: $x0->ss_64.x16
 * x17: $x0->ss_64.x17
 * lr: $x0->ss_64.lr
 *
 * On CPUs with PAC support, this macro will auth the above values with ml_check_signed_state().
 *
 * tmp1 - scratch register 1
 * tmp2 - scratch register 2
 * tmp3 - scratch register 3
 * tmp4 - scratch register 4
 * tmp5 - scratch register 5
 * tmp6 - scratch register 6
 */
/* BEGIN IGNORE CODESTYLE */
.macro AUTH_THREAD_STATE_IN_X0 tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, el0_state_allowed=0
#if __has_feature(ptrauth_calls)
	msr		SPSel, #1
#endif
	ldr		w2, [x0, SS64_CPSR]
.if \el0_state_allowed==0
#if __has_feature(ptrauth_calls)
	// If testing for a canary CPSR value, ensure that we do not observe writes to other fields without it
	dmb		ld
#endif
.endif
	ldr		x1, [x0, SS64_PC]
	ldp		x16, x17, [x0, SS64_X16]

#if defined(HAS_APPLE_PAC)
	// Save x3-x6 to preserve across call
	mov		\tmp3, x3
	mov		\tmp4, x4
	mov		\tmp5, x5
	mov		\tmp6, x6

	/*
	* Arg0: The ARM context pointer (already in x0)
	* Arg1: PC to check (loaded above)
	* Arg2: CPSR to check (loaded above)
	* Arg3: the LR to check
	*
	* Stash saved state PC and CPSR in other registers to avoid reloading potentially unauthed
	* values from memory.  (ml_check_signed_state will clobber x1 and x2.)
	*/
	mov		\tmp1, x1
	mov		\tmp2, x2
	ldr		x3, [x0, SS64_LR]
	mov		x4, x16
	mov		x5, x17
	bl		EXT(ml_check_signed_state)
	mov		x1, \tmp1
	mov		x2, \tmp2
	msr		SPSel, #0

.if \el0_state_allowed==0
	and		\tmp2, \tmp2, #PSR64_MODE_MASK
	cbnz		\tmp2, 1f
	bl		EXT(ml_auth_thread_state_invalid_cpsr)
1:
.endif

	// LR was already loaded/authed earlier, if we reload it we might be loading a potentially unauthed value
	mov		lr, x3
	mov		x3, \tmp3
	mov		x4, \tmp4
	mov		x5, \tmp5
	mov		x6, \tmp6
#else
	ldr		lr, [x0, SS64_LR]
#endif /* defined(HAS_APPLE_PAC) */
.endmacro

#if !__ARM_ARCH_8_6__
.set BRK_AUTDA_FAILURE, 0xc472
#endif

/**
 * Loads and auths the top of a thread's kernel stack pointer.
 *
 * Faults on auth failure.  src and dst can be the same register, as long as
 * the caller doesn't mind clobbering the input.
 *
 * src (input): struct thread *
 * dst (output): ptrauth_auth(src->machine.kstackptr)
 * tmp: clobbered
 */
.macro LOAD_KERN_STACK_TOP	dst, src, tmp
	add		\tmp, \src, TH_KSTACKPTR
	ldr		\dst, [\tmp]
#if __has_feature(ptrauth_calls)
	movk		\tmp, TH_KSTACKPTR_DIVERSIFIER, lsl #48
	autda		\dst, \tmp
#if !__ARM_ARCH_8_6__
	mov		\tmp, \dst
	xpacd		\tmp
	cmp		\tmp, \dst
	b.eq		Lkstackptr_ok_\@
	brk		BRK_AUTDA_FAILURE
Lkstackptr_ok_\@:
#endif /* !__ARM_ARCH_8_6__ */
#endif /* __has_feature(ptrauth_calls) */
.endmacro

/**
 * Loads and auths a thread's user context data.
 *
 * Faults on auth failure.  src and dst can be the same register, as long as
 * the caller doesn't mind clobbering the input.
 *
 * src (input): struct thread *
 * dst (output): ptrauth_auth(src->machine.upcb)
 * tmp: clobbered
 */
.macro LOAD_USER_PCB	dst, src, tmp
	add		\tmp, \src, TH_UPCB
	ldr		\dst, [\tmp]
#if __has_feature(ptrauth_calls)
	movk		\tmp, TH_UPCB_DIVERSIFIER, lsl #48
	autda		\dst, \tmp
#if !__ARM_ARCH_8_6__
	mov		\tmp, \dst
	xpacd		\tmp
	cmp		\tmp, \dst
	b.eq		Lupcb_ok_\@
	brk		BRK_AUTDA_FAILURE
Lupcb_ok_\@:
#endif /* !__ARM_ARCH_8_6__ */
#endif /* __has_feature(ptrauth_calls) */
.endmacro

/**
 * Loads and auths a thread's interrupt stack pointer.
 *
 * Faults on auth failure.  src and dst can be the same register, as long as
 * the caller doesn't mind clobbering the input.
 *
 * src (input): struct thread *
 * dst (output): ptrauth_auth(src->cpuDataP.istackptr)
 * tmp: clobbered
 */
.macro LOAD_INT_STACK	dst, src, tmp
	ldr		\tmp, [\src, ACT_CPUDATAP]
	add		\tmp, \tmp, CPU_ISTACKPTR
	ldr		\dst, [\tmp]
#if __has_feature(ptrauth_calls)
	movk		\tmp, CPU_ISTACKPTR_DIVERSIFIER, lsl #48
	autda		\dst, \tmp
#if !__ARM_ARCH_8_6__
	mov		\tmp, \dst
	xpacd		\tmp
	cmp		\tmp, \dst
	b.eq		Listackptr_ok_\@
	brk		BRK_AUTDA_FAILURE
Listackptr_ok_\@:
#endif /* !__ARM_ARCH_8_6__ */
#endif /* __has_feature(ptrauth_calls) */
.endmacro
/* END IGNORE CODESTYLE */

/* vim: set ft=asm: */
