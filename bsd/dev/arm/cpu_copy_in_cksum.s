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

/*
 * the following definitions default the implementation to little-endian
 * architectures
 */
#define LITTLE_ENDIAN	1
#define BYTE_ORDER	LITTLE_ENDIAN

/*
 * renaming registers to ease code porting from arm64
 */
#define v0	q0
#define v1	q1
#define v2	q2
#define v3	q3
#define v8	q8
#define v9	q9
#define v10	q10
#define v11	q11
#define v12	q12
#define v13	q13
#define v14	q14
#define v15	q15

	.syntax	unified
	.align	2
	.code	16
	.thumb_func _os_cpu_copy_in_cksum
	.text

	.globl	_os_cpu_copy_in_cksum
_os_cpu_copy_in_cksum:

#define	src		r0
#define	dst		r1
#define	len		r2
#define	sum		r3
#define need_swap	r4
#define partial		r5
#define t		r12

	push	{r4,r5,r7,lr}
	add	r7, sp, #8	/* set up base pointer for debug tracing */

	cmp	len, #0
	mov	partial, #0	/* partial = 0; */
	mov	need_swap, #0	/* needs_swap = 0; */

	cbnz	len, 0f
	b	L_len_0
0:

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
	beq	1f
	ldrb	partial, [src]
	add	src, src, #1
	strb	partial, [dst], #1
#if BYTE_ORDER == LITTLE_ENDIAN
	lsl	partial, partial, #8
#endif
	subs	len, len, #1
	mov	need_swap, #1
	beq	L_len_0
1:

#ifdef KERNEL
	vpush	{v8-v15}
	vpush	{v0-v3}
#endif

	/*
	 * pre-decrement len by 8*16, and if less tha 8*16 bytes, try
	 * 4*16 bytes next.
	 * v0,v1 will store temp result after we exit the L128 loop
	 */
	veor	v0, v0, v0
	veor	v1, v1, v1
	cmp	len, #8*16
	vmov	s0, partial	/* move partial to 1st 64b lane in v0 */
	blt	L64_bytes

	/*
	 * accumulate 8 x 2 x 16-bit pairs into 16 lanes in v0-v3
	 * branch to finish off if len<128
	 */
	vld1.8	{q8,q9}, [src]!
	veor	v2, v2, v2
	vld1.8	{q10,q11}, [src]!
	veor	v3, v3, v3
	vld1.8	{q12,q13}, [src]!
	subs	len, len, #2*8*16
	vld1.8	{q14,q15}, [src]!
	blt	L128_finishup

	/*
	 * loop for loading and accumulating 16 32-bit words nto 8 8-byte
	 * accumulators per iteration
	 */
L128_loop:
	vpadal.u16	v0, v8
	vst1.8		{q8,q9}, [dst]!
	vpadal.u16	v1, v9
	vld1.8		{q8,q9}, [src]!

	vpadal.u16	v2, v10
	vst1.8		{q10,q11}, [dst]!
	vpadal.u16	v3, v11
	vld1.8		{q10,q11}, [src]!

	vpadal.u16	v0, v12
	vst1.8		{q12,q13}, [dst]!
	vpadal.u16	v1, v13
	vld1.8		{q12,q13}, [src]!

	vpadal.u16	v2, v14
	vst1.8		{q14,q15}, [dst]!
	vpadal.u16	v3, v15
	vld1.8		{q14,q15}, [src]!

	subs		len, len, #8*16
	bge		L128_loop

L128_finishup:
	vpadal.u16	v0, v8
	vst1.8		{q8,q9}, [dst]!
	vpadal.u16	v1, v9

	vpadal.u16	v2, v10
	vst1.8		{q10,q11}, [dst]!
	vpadal.u16	v3, v11

	vpadal.u16	v0, v12
	vst1.8		{q12,q13}, [dst]!
	vpadal.u16	v1, v13

	vpadal.u16	v2, v14
	vst1.8		{q14,q15}, [dst]!
	vpadal.u16	v3, v15

	add		len, len, #8*16

	vadd.i32	v0, v0, v2
	vadd.i32	v1, v1, v3

L64_bytes:
	cmp		len, #4*16
	blt		L32_bytes

	vld1.8		{q8,q9}, [src]!
	vld1.8		{q10,q11}, [src]!

	vpadal.u16	v0, v8
	vst1.8		{q8,q9}, [dst]!
	vpadal.u16	v1, v9

	vpadal.u16	v0, v10
	vst1.8		{q10,q11}, [dst]!
	vpadal.u16	v1, v11

	sub		len, len, #4*16

L32_bytes:
	cmp		len, #2*16
	blt		L16_bytes

	vld1.8		{q8,q9}, [src]!

	vpadal.u16	v0, v8
	vst1.8		{q8,q9}, [dst]!
	vpadal.u16	v1, v9

	sub		len, len, #2*16

L16_bytes:
	vadd.i32	v0, v0, v1

	cmp		len, #16
	blt		L8_bytes
	vld1.8		{q8}, [src]!
	vpadal.u16	v0, v8
	vst1.8		{q8}, [dst]!

	sub		len, len, #16

L8_bytes:
	veor		v1, v1, v1
	tst		len, #8
	beq		L4_bytes
	vld1.8		{d2}, [src]!
	vst1.8		{d2}, [dst]!
	vpadal.u16	v0, v1

L4_bytes:
	ands		len, len, #7
	vpadd.i32	d0, d0, d1
	vpadd.i32	d0, d0, d1
	vmov		partial, s0

#ifdef KERNEL
	vpop	{q0-q1}
	vpop	{q2-q3}
	vpop	{q8-q9}
	vpop	{q10-q11}
	vpop	{q12-q13}
	vpop	{q14-q15}
#endif

	beq	L_len_0

	subs	len, len, #2
	blt	L_trailing_bytes

L2_bytes:
	ldrh	t, [src], #2
	strh	t, [dst], #2
	add	partial, partial, t
	subs	len, len, #2
	bge	L2_bytes

L_trailing_bytes:
	tst	len, #1
	beq	L_len_0
	ldrb	t,[src],#1
	strb	t,[dst],#1
#if BYTE_ORDER != LITTLE_ENDIAN
	lsl	t, t, #8
#endif
	add	partial, partial, t

L_len_0:
	/*
	 * if (needs_swap)
	 *	partial = (partial << 8) + (partial >> 24);
	 */
	cbz	need_swap, 1f
	lsl	t, partial, #8
	add	partial, t, partial, lsr #24
1:
	movw	lr, #0xffff

	/* final_acc = (sum0 >> 16) + (sum0 & 0xffff); */
	and	r0, sum, lr
	add	r0, r0, sum, lsr #16

	/* final_acc += (partial >> 16) + (partial & 0xffff); */
	add	r0, r0, partial, lsr #16
	and	partial, partial, lr
	add	r0, r0, partial

	/* final_acc = (final_acc >> 16) + (final_acc & 0xffff); */
	and	t, r0, lr
	add	r0, t, r0, lsr #16

	/*
	 * One final fold in case of carry from the previous one.
	 * final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	 */
	and	t, r0, lr
	add	r0, t, r0, lsr #16

	/*
	 * return (~final_acc & 0xffff);
	 *
	 * mvn	r0, r0
	 * and	r0, r0, lr
	 */

	pop	{r4,r5,r7,pc}
