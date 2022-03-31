/*
 * Copyright (c) 2020-2021 Apple Inc. All rights reserved.
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
 * extern int os_memcmp_mask_{16,32,48,64,80}B(const uint8_t *src1,
 *     const uint8_t *src2, const uint8_t *mask);
 *
 * This module implements fixed-length memory compare with mask routines,
 * used mainly by the Skywalk networking subsystem.  Each routine is called
 * on every packet and therefore needs to be as efficient as possible.
 *
 * When used in the kernel, these routines save and restore XMM registers.
 */

#ifndef KERNEL
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#endif /* !KERNEL */

#define	src1		%rdi	/* 1st arg */
#define	src2		%rsi	/* 2nd arg */
#define	mask		%rdx	/* 3rd arg */

/*
 *  @abstract Compare 16-byte buffers src1 against src2, applying the byte
 *  masks to input data before comparison.
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *
 *  @param src1 first 16-byte input buffer
 *  @param src2 second 16-byte input buffer
 *  @param byte_mask 16-byte byte mask applied before comparision
 */
	.globl _os_memcmp_mask_16B
	.text
	.align	4
_os_memcmp_mask_16B:

	/* push callee-saved registers and set up base pointer */
	push	%rbp
	movq	%rsp, %rbp

#ifdef KERNEL
	/* allocate stack space and save xmm regs */
	sub	$2*16, %rsp
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
#endif /* KERNEL */

	movdqu	(src1), %xmm0
	movdqu  (src2), %xmm1
	pxor    %xmm0, %xmm1
	movdqu  (mask), %xmm0
	pand    %xmm1, %xmm0
	xorq    %rax, %rax
	ptest	%xmm0, %xmm0
	setne   %al

#ifdef KERNEL
	/* restore xmm regs and deallocate stack space */
	movdqa	0*16(%rsp), %xmm0
	movdqa	1*16(%rsp), %xmm1
	add	$2*16, %rsp
#endif /* KERNEL */

	/* restore callee-saved registers */
	pop	%rbp
	ret

/*
 *  @abstract Compare 32-byte buffers src1 against src2, applying the byte
 *  masks to input data before comparison.
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *
 *  @param src1 first 32-byte input buffer
 *  @param src2 second 32-byte input buffer
 *  @param byte_mask 32-byte byte mask applied before comparision
 */
	.globl _os_memcmp_mask_32B
	.text
	.align	4
_os_memcmp_mask_32B:

	/* push callee-saved registers and set up base pointer */
	push	%rbp
	movq	%rsp, %rbp

#ifdef KERNEL
	/* allocate stack space and save xmm regs */
	sub	$3*16, %rsp
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
	movdqa	%xmm2, 2*16(%rsp)
#endif /* KERNEL */

	movdqu	(src1), %xmm0
	movdqu	0x10(src1), %xmm1
	movdqu  (src2), %xmm2
	pxor    %xmm0, %xmm2
	movdqu  0x10(src2), %xmm0
	pxor    %xmm1, %xmm0
	movdqu  (mask), %xmm1
	pand    %xmm2, %xmm1
	movdqu  0x10(mask), %xmm2
	pand    %xmm0, %xmm2
	por     %xmm1, %xmm2
	xorq    %rax, %rax
	ptest   %xmm2, %xmm2
	setne   %al

#ifdef KERNEL
	/* restore xmm regs and deallocate stack space */
	movdqa	0*16(%rsp), %xmm0
	movdqa	1*16(%rsp), %xmm1
	movdqa	2*16(%rsp), %xmm2
	add	$3*16, %rsp
#endif /* KERNEL */

	/* restore callee-saved registers */
	pop	%rbp
	ret

/*
 *  @abstract Compare 48-byte buffers src1 against src2, applying the byte
 *  masks to input data before comparison.
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *
 *  @param src1 first 48-byte input buffer
 *  @param src2 second 48-byte input buffer
 *  @param byte_mask 48-byte byte mask applied before comparision
 */
	.globl _os_memcmp_mask_48B
	.text
	.align	4
_os_memcmp_mask_48B:

	/* push callee-saved registers and set up base pointer */
	push	%rbp
	movq	%rsp, %rbp

#ifdef KERNEL
	/* allocate stack space and save xmm regs */
	sub	$4*16, %rsp
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
	movdqa	%xmm2, 2*16(%rsp)
	movdqa	%xmm3, 3*16(%rsp)
#endif /* KERNEL */

	movdqu  (src1), %xmm0
	movdqu  0x10(src1), %xmm1
	movdqu  0x20(src1), %xmm2
	movdqu  (src2), %xmm3
	pxor    %xmm0, %xmm3
	movdqu  0x10(src2), %xmm0
	pxor    %xmm1, %xmm0
	movdqu  0x20(src2), %xmm1
	pxor    %xmm2, %xmm1
	movdqu  (mask), %xmm2
	pand    %xmm3, %xmm2
	movdqu  0x10(mask), %xmm3
	pand    %xmm0, %xmm3
	por     %xmm2, %xmm3
	movdqu  0x20(mask), %xmm0
	pand    %xmm1, %xmm0
	por     %xmm3, %xmm0
	xorq    %rax, %rax
	ptest   %xmm0, %xmm0
	setne   %al

#ifdef KERNEL
	/* restore xmm regs and deallocate stack space */
	movdqa	0*16(%rsp), %xmm0
	movdqa	1*16(%rsp), %xmm1
	movdqa	2*16(%rsp), %xmm2
	movdqa	3*16(%rsp), %xmm3
	add	$4*16, %rsp
#endif /* KERNEL */

	/* restore callee-saved registers */
	pop	%rbp
	ret

/*
 *  @abstract Compare 64-byte buffers src1 against src2, applying the byte
 *  masks to input data before comparison.
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *
 *  @param src1 first 64-byte input buffer
 *  @param src2 second 64-byte input buffer
 *  @param byte_mask 64-byte byte mask applied before comparision
 */
	.globl _os_memcmp_mask_64B
	.text
	.align	4
_os_memcmp_mask_64B:

	/* push callee-saved registers and set up base pointer */
	push	%rbp
	movq	%rsp, %rbp

#ifdef KERNEL
	/* allocate stack space and save xmm regs */
	sub	$5*16, %rsp
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
	movdqa	%xmm2, 2*16(%rsp)
	movdqa	%xmm3, 3*16(%rsp)
	movdqa	%xmm4, 4*16(%rsp)
#endif /* KERNEL */

	movdqu       (src1), %xmm0
	movdqu       0x10(src1), %xmm1
	movdqu       0x20(src1), %xmm2
	movdqu       0x30(src1), %xmm3
	movdqu       (src2), %xmm4
	pxor         %xmm0, %xmm4
	movdqu       0x10(src2), %xmm0
	pxor         %xmm1, %xmm0
	movdqu       0x20(src2), %xmm1
	pxor         %xmm2, %xmm1
	movdqu       0x30(src2), %xmm2
	pxor         %xmm3, %xmm2
	movdqu       (mask), %xmm3
	pand         %xmm4, %xmm3
	movdqu       0x10(mask), %xmm4
	pand         %xmm0, %xmm4
	por          %xmm3, %xmm4
	movdqu       0x20(mask), %xmm0
	pand         %xmm1, %xmm0
	movdqu       0x30(mask), %xmm1
	pand         %xmm2, %xmm1
	por          %xmm0, %xmm1
	por          %xmm4, %xmm1
	xorq         %rax, %rax
	ptest        %xmm1, %xmm1
	setne        %al

#ifdef KERNEL
	/* restore xmm regs and deallocate stack space */
	movdqa	0*16(%rsp), %xmm0
	movdqa	1*16(%rsp), %xmm1
	movdqa	2*16(%rsp), %xmm2
	movdqa	3*16(%rsp), %xmm3
	movdqa	4*16(%rsp), %xmm4
	add	$5*16, %rsp
#endif /* KERNEL */

	/* restore callee-saved registers */
	pop	%rbp
	ret

/*
 *  @abstract Compare 80-byte buffers src1 against src2, applying the byte
 *  masks to input data before comparison.
 *
 *  @discussion
 *  Returns zero if the two buffers are identical after applying the byte
 *  masks, otherwise non-zero.
 *
 *  @param src1 first 80-byte input buffer
 *  @param src2 second 80-byte input buffer
 *  @param byte_mask 80-byte byte mask applied before comparision
 */
	.globl _os_memcmp_mask_80B
	.text
	.align	4
_os_memcmp_mask_80B:

	/* push callee-saved registers and set up base pointer */
	push	%rbp
	movq	%rsp, %rbp

#ifdef KERNEL
	/* allocate stack space and save xmm regs */
	sub	$6*16, %rsp
	movdqa	%xmm0, 0*16(%rsp)
	movdqa	%xmm1, 1*16(%rsp)
	movdqa	%xmm2, 2*16(%rsp)
	movdqa	%xmm3, 3*16(%rsp)
	movdqa	%xmm4, 4*16(%rsp)
	movdqa	%xmm5, 5*16(%rsp)
#endif /* KERNEL */

	movdqu  (src1), %xmm0
	movdqu  0x10(src1), %xmm1
	movdqu  0x20(src1), %xmm2
	movdqu  0x30(src1), %xmm3
	movdqu  0x40(src1), %xmm4
	movdqu  (src2), %xmm5
	pxor    %xmm0, %xmm5
	movdqu  0x10(src2), %xmm0
	pxor    %xmm1, %xmm0
	movdqu  0x20(src2), %xmm1
	pxor    %xmm2, %xmm1
	movdqu  0x30(src2), %xmm2
	pxor    %xmm3, %xmm2
	movdqu  0x40(src2), %xmm3
	pxor    %xmm4, %xmm3
	movdqu  (mask), %xmm4
	pand    %xmm5, %xmm4
	movdqu  0x10(mask), %xmm5
	pand    %xmm0, %xmm5
	por     %xmm4, %xmm5
	movdqu  0x20(mask), %xmm0
	pand    %xmm1, %xmm0
	movdqu  0x30(mask), %xmm4
	pand    %xmm2, %xmm4
	por     %xmm0, %xmm4
	movdqu  0x40(mask), %xmm1
	pand    %xmm3, %xmm1
	por     %xmm5, %xmm4
	por     %xmm1, %xmm4
	xorq    %rax, %rax
	ptest   %xmm4, %xmm4
	setne   %al

#ifdef KERNEL
	/* restore xmm regs and deallocate stack space */
	movdqa	0*16(%rsp), %xmm0
	movdqa	1*16(%rsp), %xmm1
	movdqa	2*16(%rsp), %xmm2
	movdqa	3*16(%rsp), %xmm3
	movdqa	4*16(%rsp), %xmm4
	movdqa	5*16(%rsp), %xmm5
	add	$6*16, %rsp
#endif /* KERNEL */

	/* restore callee-saved registers */
	pop	%rbp
	ret
