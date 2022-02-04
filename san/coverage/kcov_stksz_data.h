/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifndef _KCOV_STKSZ_DATA_H_
#define _KCOV_STKSZ_DATA_H_

#include <stdbool.h>
#include <mach/vm_types.h>

#if KERNEL_PRIVATE

#if CONFIG_STKSZ

/*
 * Stack size monitor per-cpu data.
 */
typedef struct kcov_stksz_thread {
	vm_offset_t    kst_stack;       /* thread stack override */
	uintptr_t      kst_pc;          /* last seen program counter */
	uint32_t       kst_stksz;       /* last seen stack size */
	uint32_t       kst_stksz_prev;  /* previous known stack size */
	bool           kst_th_above;    /* threshold */
} kcov_stksz_thread_t;

#endif /* CONFIG_STKSZ */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_STKSZ_DATA_H_ */
