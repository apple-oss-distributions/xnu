/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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
 *  extern uint32_t os_cpu_copy_in_cksum(const void *src, void *dst,
 *      uint32_t len, uint32_t sum0);
 *
 *  input :
 *      src : source starting address
 *      dst : destination starting address
 *      len : byte stream length
 *      sum0 : initial 32-bit sum
 *
 *  output :
 *      the source byte stream is copied into the destination buffer
 *      the function returns the partial 16-bit checksum accumulated
 *	in a 32-bit variable (without 1's complement); caller is
 *	responsible for folding the 32-bit sum into 16-bit and
 *	performing the 1's complement if applicable
 */

#define LITTLE_ENDIAN	1
#define BYTE_ORDER	LITTLE_ENDIAN

	.const
	.align	4

/*
 * a vector v0 = w3 : w2 : w1 : w0 will be using the following mask to
 * extract 0 : w2 : 0 : w0
 * then shift right quadword 32-bit to get 0 : w3 : 0 : w1
 * these two vectors are then accumulated to 4 quadword lanes in 2 vectors
 */
L_mask:
	.quad	0x00000000ffffffff
	.quad	0x00000000ffffffff

#define Lmask	L_mask(%rip)

	.globl	_os_cpu_copy_in_cksum
	.text
	.align	4
_os_cpu_copy_in_cksum:

#define	src		%rdi
#define	dst		%rsi
#define	len		%rdx
#define	sum		%rcx
#define need_swap	%r8
#define t		%r9
#define td		%r9d
#define tw		%r9w
#define tb		%r9b
#define partial		%r10
#define partiald	%r10d
#define partialw	%r10w
#define partialb	%r10b

/*
 * renaming vector registers
 */
#define v0		%xmm0
#define v1		%xmm1
#define v2		%xmm2
#define v3		%xmm3
#define v4		%xmm4
#define v5		%xmm5
#define v6		%xmm6
#define v7		%xmm7
#define v8		%xmm8
#define v9		%xmm9
#define v10		%xmm10
#define v11		%xmm11
#define v12		%xmm12
#define v13		%xmm13
#define v14		%xmm14
#define v15		%xmm15

	/* push callee-saved registers and set up base pointer */
	push	%rbp
	movq	%rsp, %rbp

	mov	$0, partial	// partial = 0;
	mov	$0, need_swap	// needs_swap = 0;

	cmp	$0, len
	je	L_len_0

/*
 * Deal with odd-addressed byte, use w7 to store temporary sum, deposit this
 * byte to high byte of 16-bit in w7
 *
 *	t = 0;
 *	if ((uintptr_t)src & 1) {
 *		t = *src << 8;
 *		*dst++ = *src++;
 *		--len;
 *	}
 */
	test	$1, src
	je	1f

	movzb	(src), partial
	add	$1, src
	movb	partialb, (dst)
	add	$1, dst
#if BYTE_ORDER == LITTLE_ENDIAN
	shl	$8, partial
#endif
	mov	$1, need_swap
	sub	$1, len
	jz	L_len_0
1:

#ifdef KERNEL
	/* allocate stack space and save xmm0-xmm15 */
	sub	$16*16, %rsp
	movdqa	v0, 0*16(%rsp)
	movdqa	v1, 1*16(%rsp)
	movdqa	v2, 2*16(%rsp)
	movdqa	v3, 3*16(%rsp)
	movdqa	v4, 4*16(%rsp)
	movdqa	v5, 5*16(%rsp)
	movdqa	v6, 6*16(%rsp)
	movdqa	v7, 7*16(%rsp)
	movdqa	v8, 8*16(%rsp)
	movdqa	v9, 9*16(%rsp)
	movdqa	v10, 10*16(%rsp)
	movdqa	v11, 11*16(%rsp)
	movdqa	v12, 12*16(%rsp)
	movdqa	v13, 13*16(%rsp)
	movdqa	v14, 14*16(%rsp)
	movdqa	v15, 15*16(%rsp)
#endif

	/*
	 * pre-decrement len by 8*16, and if less tha 8*16 bytes,
	 * try 4*16 bytes next
	 * v0,v1 will store temp result after we exit the L128 loop
	 */
	pxor	v0, v0
	pxor	v1, v1
	cmp	$(8*16), len
	movq	partial, v0	// move partial to 1st 64b lane in v0
	jl	L64_bytes

	/*
	 * accumulate 4 x 2 x 32-bit pairs into 8 lanes in v0-v3
	 * load 1st 4 vectors, and clear v0-v3
	 */
	pxor	v2, v2
	pxor	v3, v3
	movups	0*16(src), v4
	movups	1*16(src), v5
	movups	2*16(src), v6
	movups	3*16(src), v7
	movups	4*16(src), v8
	movups	5*16(src), v9
	movups	6*16(src), v10
	movups	7*16(src), v11
	add	$8*16, src

	/* branch to finish off if len<128 */
	sub	$2*8*16, len
	jl	L128_finishup

	/*
	 * loop for loading and accumulating 16 32-bit words into
	 * 8 8-byte accumulators per iteration
	 */
L128_loop:
	/*
	 * store v4-v7 to dst[0:3]
	 * copy v4-v7 to v12-v15
	 * extract w3:w1 in v4-v7
	 */
	movups	v4, 0*16(dst)
	movdqa	v4, v12
	psrlq	$32, v4

	movups	v5, 1*16(dst)
	movdqa	v5, v13
	psrlq	$32, v5

	movups	v6, 2*16(dst)
	movdqa	v6, v14
	psrlq	$32, v6

	movups	v7, 3*16(dst)
	movdqa	v7, v15
	psrlq	$32, v7

	/*
	 * store v8-v11 to dst[4:7]
	 * extract w2:w0 in v12-v15
	 * accumulate w3:w1 in v4-v7 to v0-v3
	 */
	movups	v8, 4*16(dst)
	pand	Lmask, v12
	paddq	v4, v0

	movups	v9, 5*16(dst)
	pand	Lmask, v13
	paddq	v5, v1

	movups	v10, 6*16(dst)
	pand	Lmask, v14
	paddq	v6, v2

	movups	v11, 7*16(dst)
	pand	Lmask, v15
	paddq	v7, v3

	add	$8*16, dst	// advance dst for next iteration

	/*
	 * accumulate w2:w0 in v12-v15 to v0-v3
	 * copy v8-v11 to v12-v15
	 * extract w3:w1 in v8-v11
	 */
	paddq	v12, v0
	movdqa	v8, v12
	psrlq	$32, v8

	paddq	v13, v1
	movdqa	v9, v13
	psrlq	$32, v9

	paddq	v14, v2
	movdqa	v10, v14
	psrlq	$32, v10

	paddq	v15, v3
	movdqa	v11, v15
	psrlq	$32, v11

	/*
	 * load src[0:3] to v4-v7
	 * accumulate w3:w1 in v8-v11 to v0-v3
	 * extract w2:w0 in v12-v15
	 */
	movups	0*16(src), v4
	paddq	v8, v0
	pand	Lmask, v12

	movups	1*16(src), v5
	paddq	v9, v1
	pand	Lmask, v13

	movups	2*16(src), v6
	paddq	v10, v2
	pand	Lmask, v14

	movups	3*16(src), v7
	paddq	v11, v3
	pand	Lmask, v15

	/*
	 * load src[4:7] to v8-v11
	 * accumulate w2:w0 in v12-v15 to v0-v3
	 */
	movups	4*16(src), v8
	paddq	v12, v0

	movups	5*16(src), v9
	paddq	v13, v1

	movups	6*16(src), v10
	paddq	v14, v2

	movups	7*16(src), v11
	paddq	v15, v3

	add	$8*16, src	// advance src for next iteration

	sub	$8*16, len
	jge	L128_loop

L128_finishup:
	movups	v4, 0*16(dst)
	movdqa	v4, v12
	psrlq	$32, v4

	movups	v5, 1*16(dst)
	movdqa	v5, v13
	psrlq	$32, v5

	movups	v6, 2*16(dst)
	movdqa	v6, v14
	psrlq	$32, v6

	movups	v7, 3*16(dst)
	movdqa	v7, v15
	psrlq	$32, v7

	pand	Lmask, v12
	paddq	v4, v0
	movups	v8, 4*16(dst)

	pand	Lmask, v13
	paddq	v5, v1
	movups	v9, 5*16(dst)

	pand	Lmask, v14
	paddq	v6, v2
	movups	v10, 6*16(dst)

	pand	Lmask, v15
	paddq	v7, v3
	movups	v11, 7*16(dst)

	add	$8*16, dst

	paddq	v12, v0
	movdqa	v8, v12
	psrlq	$32, v8

	paddq	v13, v1
	movdqa	v9, v13
	psrlq	$32, v9

	paddq	v14, v2
	movdqa	v10, v14
	psrlq	$32, v10

	paddq	v15, v3
	movdqa	v11, v15
	psrlq	$32, v11

	paddq	v8, v0
	pand	Lmask, v12

	paddq	v9, v1
	pand	Lmask, v13

	paddq	v10, v2
	pand	Lmask, v14

	paddq	v11, v3
	pand	Lmask, v15

	paddq	v12, v0
	paddq	v13, v1
	paddq	v14, v2
	paddq	v15, v3

	add	$8*16, len

	/* absorb v2-v3 into v0-v1 */
	paddq	v2, v0
	paddq	v3, v1

L64_bytes:
	cmp	$4*16, len
	jl	L32_bytes

	movups	0*16(src), v4
	movups	1*16(src), v5
	movups	2*16(src), v6
	movups	3*16(src), v7
	add	$4*16, src

	movups	v4, 0*16(dst)
	movups	v5, 1*16(dst)
	movups	v6, 2*16(dst)
	movups	v7, 3*16(dst)
	add	$4*16, dst

	movdqa	v4, v12
	psrlq	$32, v4
	movdqa	v5, v13
	psrlq	$32, v5
	movdqa	v6, v14
	psrlq	$32, v6
	movdqa	v7, v15
	psrlq	$32, v7

	pand	Lmask, v12
	paddq	v4, v0
	pand	Lmask, v13
	paddq	v5, v1
	pand	Lmask, v14
	paddq	v6, v0
	pand	Lmask, v15
	paddq	v7, v1

	paddq	v12, v0
	paddq	v13, v1
	paddq	v14, v0
	paddq	v15, v1

	sub	$4*16, len

L32_bytes:
	cmp	$2*16, len
	jl	L16_bytes
	movups	0*16(src), v4
	movups	1*16(src), v5
	add	$2*16, src

	movups	v4, 0*16(dst)
	movups	v5, 1*16(dst)
	add	$2*16, dst

	movdqa	v4, v12
	movdqa	v5, v13
	psrlq	$32, v4
	psrlq	$32, v5
	pand	Lmask, v12
	pand	Lmask, v13
	paddq	v4, v0
	paddq	v5, v1
	paddq	v12, v0
	paddq	v13, v1

	sub	$2*16, len

L16_bytes:
	paddq	v1, v0

	cmp	$16, len
	jl	L8_bytes

	movups	0*16(src), v4
	add	$1*16, src

	movups	v4, 0*16(dst)
	add	$1*16, dst

	movdqa	v4, v12
	psrlq	$32, v4
	pand	Lmask, v12
	paddq	v4, v0
	paddq	v12, v0

	sub	$16, len

L8_bytes:
	movq	v0, partial
	psrldq	$8, v0
	movq	v0, t
	add	t, partial

#ifdef KERNEL
	// restore xmm0-xmm15 and deallocate stack space
	movdqa	0*16(%rsp), v0
	movdqa	1*16(%rsp), v1
	movdqa	2*16(%rsp), v2
	movdqa	3*16(%rsp), v3
	movdqa	4*16(%rsp), v4
	movdqa	5*16(%rsp), v5
	movdqa	6*16(%rsp), v6
	movdqa	7*16(%rsp), v7
	movdqa	8*16(%rsp), v8
	movdqa	9*16(%rsp), v9
	movdqa	10*16(%rsp), v10
	movdqa	11*16(%rsp), v11
	movdqa	12*16(%rsp), v12
	movdqa	13*16(%rsp), v13
	movdqa	14*16(%rsp), v14
	movdqa	15*16(%rsp), v15
	add	$16*16, %rsp
#endif

	sub	$4, len
	jl	L2_bytes
0:
	movl	(src), td
	add	t, partial
	mov	td, (dst)
	add	$4, src
	add	$4, dst
	sub	$4, len
	jge	0b


L2_bytes:
	test	$2, len
	je	L_trailing_bytes

	movzwl	(src), td
	add	t, partial
	mov	tw, (dst)
	add	$2, src
	add	$2, dst

L_trailing_bytes:
	test	$1, len
	je	L0_bytes
	movzbl	(src), td
	mov	tb, (dst)
#if BYTE_ORDER != LITTLE_ENDIAN
	shl	$8, t	// partial <<= 8;
#endif
	add	t, partial

L0_bytes:
	/* partial = (partial >> 32) + (partial & 0xffffffff); */
	mov	partiald, %eax
	shr	$32, partial
	add	%rax, partial

	/* partial = (partial >> 16) + (partial & 0xffff); */
	movzwl	partialw, %eax
	shr	$16, partial
	add	%rax, partial

L_len_0:
	/*
	 * if (needs_swap)
	 *	partial = (partial << 8) + (partial >> 24);
	 */
	cmp	$0, need_swap
	je	1f
	mov	partial, %rax
	shl	$8, %rax
	shr	$24, partial
	add	%rax, partial
1:

	/* final_acc = (initial_sum >> 16) + (initial_sum & 0xffff); */
	movzwl	%cx, %eax
	shr	$16, %ecx
	add	%ecx, %eax

	/* final_acc += (partial >> 16) + (partial & 0xffff); */
	movzwl	partialw, %ecx
	shr	$16, partial
	add	%ecx, %eax
	add	partiald, %eax

	/* final_acc = (final_acc >> 16) + (final_acc & 0xffff); */
	movzwl	%ax, %ecx
	shr	$16, %eax
	add	%ecx, %eax

	/*
	 * One final fold in case of carry from the previous one.
	 * final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	 */
	movzwl	%ax, %ecx
	shr	$16, %eax
	add	%ecx, %eax

	/*
	 * return (~final_acc & 0xffff);
	 *
	 * not      %eax
	 * movzwl   %ax, %eax
	 */

	/* restore callee-saved registers */
	pop	%rbp
	ret
