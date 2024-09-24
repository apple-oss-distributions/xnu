/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_COMPRESSOR_ALGORITHMS_INTERNAL_H_
#define _VM_COMPRESSOR_ALGORITHMS_INTERNAL_H_

#ifdef XNU_KERNEL_PRIVATE
#include <vm/vm_compressor_algorithms_xnu.h>

int metacompressor(const uint8_t *in, uint8_t *cdst, int32_t outbufsz,
    uint16_t *codec, void *cscratch, boolean_t *, uint32_t *pop_count_p);
bool metadecompressor(const uint8_t *source, uint8_t *dest, uint32_t csize,
    uint16_t ccodec, void *compressor_dscratch, uint32_t *pop_count_p);

typedef enum {
	CCWK = 0, // must be 0 or 1
	CCLZ4 = 1, //must be 0 or 1
	CINVALID = 0xFFFF
} vm_compressor_codec_t;

typedef enum {
	CMODE_WK = 0,
	CMODE_LZ4 = 1,
	CMODE_HYB = 2,
	VM_COMPRESSOR_DEFAULT_CODEC = 3,
	CMODE_INVALID = 4
} vm_compressor_mode_t;

void vm_compressor_algorithm_init(void);
int vm_compressor_algorithm(void);

#endif /* XNU_KERNEL_PRIVATE */
#endif  /* _VM_COMPRESSOR_ALGORITHMS_INTERNAL_H_ */
