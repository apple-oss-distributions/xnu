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
 * ARM64 kernel mode -- just like user mode -- no longer requires saving
 * the vector registers, since it's done by the exception handler code.
 */

#ifdef KERNEL
#include <arm64/asm.h>
#else
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#endif /* KERNEL */

#define	src1		x0	/* 1st arg */
#define	src2		x1	/* 2nd arg */
#define	mask		x2	/* 3rd arg */

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
#ifdef KERNEL
	ARM64_PROLOG
#endif /* KERNEL */
	ld1.16b  {v0}, [src1]
	ld1.16b  {v1}, [src2]
	ld1.16b  {v2}, [mask]
	eor.16b  v0, v0, v1
	and.16b  v0, v0, v2
	umaxv    b0, v0.16b
	umov     w0, v0.s[0]

	ret	lr

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
#ifdef KERNEL
	ARM64_PROLOG
#endif /* KERNEL */
	ld1.16b  {v0, v1}, [src1]
	ld1.16b  {v2, v3}, [src2]
	ld1.16b  {v4, v5}, [mask]
	eor.16b  v0, v0, v2
	eor.16b  v1, v1, v3
	and.16b  v0, v0, v4
	and.16b  v1, v1, v5
	orr.16b  v0, v0, v1
	umaxv    b0, v0.16b
	umov     w0, v0.s[0]

	ret	lr

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
#ifdef KERNEL
	ARM64_PROLOG
#endif /* KERNEL */
	ld1.16b  {v0, v1, v2}, [src1]
	ld1.16b  {v3, v4, v5}, [src2]
	ld1.16b  {v16, v17, v18}, [mask]
	eor.16b  v0, v0, v3
	eor.16b  v1, v1, v4
	eor.16b  v2, v2, v5
	and.16b  v0, v0, v16
	and.16b  v1, v1, v17
	and.16b  v2, v2, v18
	orr.16b  v0, v0, v1
	orr.16b  v0, v0, v2
	umaxv    b0, v0.16b
	umov     w0, v0.s[0]

	ret	lr

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
#ifdef KERNEL
	ARM64_PROLOG
#endif /* KERNEL */
	ld1.16b  {v0, v1, v2, v3}, [src1]
	ld1.16b  {v4, v5, v6, v7}, [src2]
	ld1.16b  {v16, v17, v18, v19}, [mask]
	eor.16b  v0, v0, v4
	eor.16b  v1, v1, v5
	eor.16b  v2, v2, v6
	eor.16b  v3, v3, v7
	and.16b  v0, v0, v16
	and.16b  v1, v1, v17
	and.16b  v2, v2, v18
	and.16b  v3, v3, v19
	orr.16b  v0, v0, v1
	orr.16b  v2, v2, v3
	orr.16b  v0, v0, v2
	umaxv    b0, v0.16b
	umov     w0, v0.s[0]

	ret	lr

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
#ifdef KERNEL
	ARM64_PROLOG
#endif /* KERNEL */
	ld1.16b  {v0, v1, v2, v3}, [src1], #64
	ld1.16b  {v4}, [src1]
	ld1.16b  {v16, v17, v18, v19}, [src2], #64
	ld1.16b  {v20}, [src2]
	ld1.16b  {v21, v22, v23, v24}, [mask], #64
	ld1.16b  {v25}, [mask]
	eor.16b  v0, v0, v16
	eor.16b  v1, v1, v17
	eor.16b  v2, v2, v18
	eor.16b  v3, v3, v19
	eor.16b  v4, v4, v20
	and.16b  v0, v0, v21
	and.16b  v1, v1, v22
	and.16b  v2, v2, v23
	and.16b  v3, v3, v24
	and.16b  v4, v4, v25
	orr.16b  v0, v0, v1
	orr.16b  v2, v2, v3
	orr.16b  v0, v0, v2
	orr.16b  v0, v0, v4
	umaxv    b0, v0.16b
	umov     w0, v0.s[0]

	ret	lr
