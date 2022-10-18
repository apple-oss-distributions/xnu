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
 * When used in the kernel, these routines save and restore vector registers.
 */

#ifdef KERNEL
#include "../../../osfmk/arm/arch.h"
#include "../../../osfmk/arm64/proc_reg.h"

#if __ARM_VFP__ < 3
#error "Unsupported: __ARM_VFP__ < 3"
#endif /* __ARM_VFP__ < 3 */
#else /* !KERNEL */
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#endif /* !KERNEL */

#define	src1		r0	/* 1st arg */
#define	src2		r1	/* 2nd arg */
#define	mask		r2	/* 3rd arg */

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
	.syntax	unified
	.globl _os_memcmp_mask_16B
	.text
	.align	4
_os_memcmp_mask_16B:

#ifdef KERNEL
	vpush		{q0-q2}
#endif /* KERNEL */

	vld1.8		{q0}, [src1]
	vld1.8		{q1}, [src2]
	vld1.8		{q2}, [mask]
	veor		q0, q0, q1
	vand		q0, q0, q2
	vorr.u32	d2, d0, d1
	vpmax.u32	d0, d2, d2
	vmov.u32	r0, d0[0]

#ifdef KERNEL
	vpop		{q0-q2}
#endif /* KERNEL */

	bx		lr

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
	.syntax	unified
	.globl _os_memcmp_mask_32B
	.text
	.align	4
_os_memcmp_mask_32B:

#ifdef KERNEL
	vpush		{q0-q5}
#endif /* KERNEL */

	vld1.8		{q0, q1}, [src1]
	vld1.8		{q2, q3}, [src2]
	vld1.8		{q4, q5}, [mask]
	veor		q0, q0, q2
	veor		q1, q1, q3
	vand		q0, q0, q4
	vand		q1, q1, q5
	vorr		q0, q0, q1
	vorr.u32	d2, d0, d1
	vpmax.u32	d0, d2, d2
	vmov.u32	r0, d0[0]

#ifdef KERNEL
	vpop		{q0-q5}
#endif /* KERNEL */

	bx		lr

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
	.syntax	unified
	.globl _os_memcmp_mask_48B
	.text
	.align	4
_os_memcmp_mask_48B:

#ifdef KERNEL
	vpush		{q0-q7}
	vpush		{q8}
#endif /* KERNEL */

	vld1.8		{q0, q1}, [src1]!
	vld1.8		q2, [src1]
	vld1.8		{q3, q4}, [src2]!
	vld1.8		q5, [src2]
	vld1.8		{q6, q7}, [mask]!
	vld1.8		q8, [mask]
	veor		q0, q0, q3
	veor		q1, q1, q4
	veor		q2, q2, q5
	vand		q0, q0, q6
	vand		q1, q1, q7
	vand		q2, q2, q8
	vorr		q0, q0, q1
	vorr		q0, q0, q2
	vorr.u32	d2, d0, d1
	vpmax.u32	d0, d2, d2
	vmov.u32	r0, d0[0]

#ifdef KERNEL
	vpop		{q8}
	vpop		{q0-q7}
#endif /* KERNEL */

	bx	lr

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
	.syntax	unified
	.globl _os_memcmp_mask_64B
	.text
	.align	4
_os_memcmp_mask_64B:

#ifdef KERNEL
	vpush		{q0-q7}
	vpush		{q8-q11}
#endif /* KERNEL */

	vld1.8		{q0, q1}, [src1]!
	vld1.8		{q2, q3}, [src1]
	vld1.8		{q4, q5}, [src2]!
	vld1.8		{q6, q7}, [src2]
	vld1.8		{q8, q9}, [mask]!
	vld1.8		{q10, q11}, [mask]
	veor		q0, q0, q4
	veor		q1, q1, q5
	veor		q2, q2, q6
	veor		q3, q3, q7
	vand		q0, q0, q8
	vand		q1, q1, q9
	vand		q2, q2, q10
	vand		q3, q3, q11
	vorr		q0, q0, q1
	vorr		q2, q2, q3
	vorr		q0, q0, q2
	vorr.u32	d2, d0, d1
	vpmax.u32	d0, d2, d2
	vmov.u32	r0, d0[0]

#ifdef KERNEL
	vpop		{q8-q11}
	vpop		{q0-q7}
#endif /* KERNEL */

	bx		lr

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
	.syntax	unified
	.globl _os_memcmp_mask_80B
	.text
	.align	4
_os_memcmp_mask_80B:

#ifdef KERNEL
	vpush		{q0-q7}
	vpush		{q8-q14}
#endif /* KERNEL */

	vld1.8		{q0, q1}, [src1]!
	vld1.8		{q2, q3}, [src1]!
	vld1.8		q4, [src1]
	vld1.8		{q5, q6}, [src2]!
	vld1.8		{q7, q8}, [src2]!
	vld1.8		q9, [src2]
	vld1.8		{q10, q11}, [mask]!
	vld1.8		{q12, q13}, [mask]!
	vld1.8		q14, [mask]
	veor		q0, q0, q5
	veor		q1, q1, q6
	veor		q2, q2, q7
	veor		q3, q3, q8
	veor		q4, q4, q9
	vand		q0, q0, q10
	vand		q1, q1, q11
	vand		q2, q2, q12
	vand		q3, q3, q13
	vand		q4, q4, q14
	vorr		q0, q0, q1
	vorr		q2, q2, q3
	vorr		q0, q0, q2
	vorr		q0, q0, q4
	vorr.u32	d2, d0, d1
	vpmax.u32	d0, d2, d2
	vmov.u32	r0, d0[0]

#ifdef KERNEL
	vpop		{q8-q14}
	vpop		{q0-q7}
#endif /* KERNEL */

	bx		lr
