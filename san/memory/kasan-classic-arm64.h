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
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <mach/vm_param.h>
#include "kasan-classic.h"

#ifndef _KASAN_CLASSIC_ARM64_H_
#define _KASAN_CLASSIC_ARM64_H_

/*
 * ARM64 configuration for KASAN-CLASSIC.
 */

#define STOLEN_MEM_PERCENT      13UL
/* XXX this is for quarantine, should move to allocator-specific quarantine */
#define STOLEN_MEM_BYTES            MiB(40)

/* Defined in makedefs/MakeInc.def */
#ifndef KASAN_OFFSET_ARM64
#define KASAN_OFFSET_ARM64      0xe000000000000000ULL
#endif  /* KASAN_OFFSET_ARM64 */

#if defined(ARM_LARGE_MEMORY)
#define KASAN_SHADOW_MIN        (VM_MAX_KERNEL_ADDRESS+1)
#define KASAN_SHADOW_MAX        0xffffffffffffffffULL
#else
#define KASAN_SHADOW_MIN        0xfffffffc00000000ULL
#define KASAN_SHADOW_MAX        0xffffffff80000000ULL
#endif

#endif /* _KASAN_CLASSIC_ARM64_H_ */
