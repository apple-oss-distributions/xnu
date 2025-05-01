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

#ifdef KERNEL
#include <arm64/asm.h>
#endif /* KERNEL */

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

/*
 * The following definitions default the implementation to little-endian
 * architectures.
 */
#define LITTLE_ENDIAN	1
#define BYTE_ORDER	LITTLE_ENDIAN

/*
 * ARM64 kernel mode -- just like user mode -- no longer requires saving
 * the vector registers, since it's done by the exception handler code.
 */
#define	SAVE_REGISTERS	0

	.globl	_os_cpu_copy_in_cksum
	.text
	.align	4
_os_cpu_copy_in_cksum:

#define	src		x0
#define	dst		x1
#define	len		x2
#define	sum		x3
#define need_swap	x5
#define t		x6
#define partial		x7
#define wpartial	w7

#ifdef KERNEL
	ARM64_PROLOG
#endif /* KERNEL */
	mov	partial, #0		// partial = 0;
	mov	need_swap, #0		// needs_swap = 0;

	cbz	len, L_len_0

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
	tst	src, #1
	b.eq	1f
	ldrb	wpartial, [src]
	add	src, src, #1
	strb	wpartial, [dst], #1
#if BYTE_ORDER == LITTLE_ENDIAN
	lsl	partial, partial, #8
#endif
	sub	len, len, #1
	mov	need_swap, #1
	cbz	len, L_len_0
1:

#if SAVE_REGISTERS
	/*
	 * we will always use v0-v3, and v4-v7/v16-v19 if len>=128
	 * so allocate 12*16 bytes in the stack, and store v0-v3 now,
	 * keep x11 as the pointer
	 */
	sub	sp, sp, #12*16
	mov	x11, sp
	st1.4s	{v0, v1, v2, v3}, [x11], #4*16
#endif

	/*
	 * pre-decrement len by 8*16, and if less tha 8*16 bytes, try
	 * 4*16 bytes next.
	 * v0,v1 will store temp result after we exit the L128 loop
	 */
	eor.16b	v0, v0, v0
	eor.16b	v1, v1, v1
	cmp	len, #8*16
	mov	v0.d[0], partial	// move partial to 1st 64b lane in v0
	b.lt	L64_bytes

#if SAVE_REGISTERS
	/* if we are here, we need to save v4-v7/v16-v19 for kernel mode */
	st1.4s	{v4, v5, v6, v7}, [x11], #4*16
	st1.4s	{v16, v17, v18, v19}, [x11], #4*16
#endif

	/*
	 * accumulate 4 x 2 x 32-bit pairs into 8 lanes in v0-v3
	 * load 1st 4 vectors, and clear v0-v3
	 */
	ldr	q4, [src], #8*16
	eor.16b	v2, v2, v2
	ldr	q5, [src, #-7*16]
	eor.16b	v3, v3, v3
	ldr	q6, [src, #-6*16]
	ldr	q7, [src, #-5*16]
	ldr	q16, [src, #-4*16]
	ldr	q17, [src, #-3*16]
	ldr	q18, [src, #-2*16]
	ldr	q19, [src, #-1*16]

	/* branch to finish off if len<128 */
	subs	len, len, #2*8*16
	b.lt	L128_finishup

	/*
	 * loop for loading and accumulating 16 32-bit words nto 8 8-byte
	 * accumulators per iteration
	 */
L128_loop:
	str		q4, [dst], #16*8
	uadalp.2d	v0, v4
	str		q5, [dst, #-7*16]
	uadalp.2d	v1, v5
	ldr		q4, [src], #16*8
	ldr		q5, [src, #-7*16]

	str		q6, [dst, #-6*16]
	uadalp.2d	v2, v6
	str		q7, [dst, #-5*16]
	uadalp.2d	v3, v7
	ldr		q6, [src, #-6*16]
	ldr		q7, [src, #-5*16]

	str		q16, [dst, #-4*16]
	uadalp.2d	v0, v16
	str		q17, [dst, #-3*16]
	uadalp.2d	v1, v17
	ldr		q16, [src, #-4*16]
	ldr		q17, [src, #-3*16]

	str		q18, [dst, #-2*16]
	uadalp.2d	v2, v18
	str		q19, [dst, #-1*16]
	uadalp.2d	v3, v19
	ldr		q18, [src, #-2*16]
	ldr		q19, [src, #-1*16]

	subs		len, len, #8*16
	b.ge		L128_loop

L128_finishup:
	str		q4, [dst], #16*8
	uadalp.2d	v0, v4
	str		q5, [dst, #-7*16]
	uadalp.2d	v1, v5
	str		q6, [dst, #-6*16]
	uadalp.2d	v2, v6
	str		q7, [dst, #-5*16]
	uadalp.2d	v3, v7

	str		q16, [dst, #-4*16]
	uadalp.2d	v0, v16
	str		q17, [dst, #-3*16]
	uadalp.2d	v1, v17
	str		q18, [dst, #-2*16]
	uadalp.2d	v2, v18
	str		q19, [dst, #-1*16]
	uadalp.2d	v3, v19

	add		len, len, #8*16

	add.2d		v0, v0, v2
	add.2d		v1, v1, v3

#if SAVE_REGISTERS
	/* restore v4-v7/v16-v19 as they won't be used any more */
	add		x11, sp, #4*16
	ld1.4s		{v4, v5, v6, v7}, [x11], #4*16
	ld1.4s		{v16, v17, v18, v19}, [x11], #4*16
#endif

L64_bytes:
	cmp		len, #4*16
	b.lt		L32_bytes

	ldr		q2, [src], #4*16
	ldr		q3, [src, #-3*16]
	str		q2, [dst], #4*16
	uadalp.2d	v0, v2
	str		q3, [dst, #-3*16]
	uadalp.2d	v1, v3

	ldr		q2, [src, #-2*16]
	ldr		q3, [src, #-1*16]
	str		q2, [dst, #-2*16]
	uadalp.2d	v0, v2
	str		q3, [dst, #-1*16]
	uadalp.2d	v1, v3
	sub		len, len, #4*16

L32_bytes:
	cmp		len, #2*16
	b.lt		L16_bytes
	ldr		q2, [src], #2*16
	ldr		q3, [src, #-1*16]
	str		q2, [dst], #2*16
	uadalp.2d	v0, v2
	str		q3, [dst, #-1*16]
	uadalp.2d	v1, v3
	sub		len, len, #2*16

L16_bytes:
	add.2d		v0, v0, v1
	cmp		len, #16
	b.lt		L8_bytes
	ldr		q2, [src], #16
	str		q2, [dst], #16
	uadalp.2d	v0, v2
	sub		len, len, #16

L8_bytes:
	eor.16b		v1, v1, v1
	eor.16b		v2, v2, v2
	eor.16b		v3, v3, v3

	tst		len, #8
	b.eq		L4_bytes
	ldr		d1,[src],#8
	str		d1,[dst],#8

L4_bytes:
	tst		len, #4
	b.eq		L2_bytes
	ldr		s2,[src],#4
	str		s2,[dst],#4

L2_bytes:
	uadalp.2d	v0, v1
	eor.16b		v1, v1, v1
	tst		len, #2
	b.eq		L_trailing_bytes
	ldr		h3,[src],#2
	str		h3,[dst],#2

L_trailing_bytes:
	tst		len, #1
	b.eq		L0_bytes
	ldr		b1,[src],#1
	str		b1,[dst],#1
#if BYTE_ORDER != LITTLE_ENDIAN
	shl.4h		v1, v1, #8	// partial <<= 8;
#endif

L0_bytes:
	uadalp.2d	v2, v3
	uadalp.2d	v0, v1
	uadalp.2d	v0, v2

	addp.2d		d0, v0
	fmov		partial, d0

#if SAVE_REGISTERS
	/* restore v0-v3 and deallocate stack space */
	ld1.4s	{v0, v1, v2, v3}, [sp]
	add	sp, sp, #12*16
#endif

	/* partial = (partial >> 32) + (partial & 0xffffffff); */
	and	t, partial, #0xffffffff
	add	partial, t, partial, lsr #32

	/* partial = (partial >> 16) + (partial & 0xffff); */
	and	t, partial, #0xffff
	add	partial, t, partial, lsr #16

L_len_0:
	/*
	 * if (needs_swap)
	 *	partial = (partial << 8) + (partial >> 24);
	 */
	cbz	need_swap, 1f
	lsl	t, partial, #8
	add	partial, t, partial, lsr #24
1:
	/* final_acc = (sum0 >> 16) + (sum0 & 0xffff); */
	and	x0, sum, #0xffff
	add	x0, x0, sum, lsr #16

	/* final_acc += (partial >> 16) + (partial & 0xffff); */
	add	x0, x0, partial, lsr #16
	and	partial, partial, #0xffff
	add	x0, x0, partial

	/* final_acc = (final_acc >> 16) + (final_acc & 0xffff); */
	and	t, x0, #0xffff
	add	x0, t, x0, lsr #16

	/*
	 * One final fold in case of carry from the previous one.
	 * final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	 */
	and	t, x0, #0xffff
	add	x0, t, x0, lsr #16

	/*
	 * return (~final_acc & 0xffff);
	 *
	 * mvn	w0, w0
	 * and	w0, w0, #0xffff
	 */

	ret	lr
