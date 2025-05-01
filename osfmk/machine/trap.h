/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#ifndef _MACHINE_TRAP_H
#define _MACHINE_TRAP_H

#if defined (__i386__) || defined (__x86_64__)
#include "i386/trap.h"
#elif defined (__arm__) || defined (__arm64__)
#include "arm/trap.h"
#else
#error architecture not supported
#endif

#define ml_trap_pin_value_1(a) ({ \
	register long _a __asm__(ML_TRAP_REGISTER_1) = (long)(a);               \
                                                                                \
	__asm__ __volatile__ ("" : "+r"(_a));                                   \
})
#define ml_trap_pin_value_2(a, b) ({ \
	register long _a __asm__(ML_TRAP_REGISTER_1) = (long)(a);               \
	register long _b __asm__(ML_TRAP_REGISTER_2) = (long)(b);               \
                                                                                \
	__asm__ __volatile__ ("" : "+r"(_a), "+r"(_b));                         \
})
#define ml_trap_pin_value_3(a, b, c) ({ \
	register long _a __asm__(ML_TRAP_REGISTER_1) = (long)(a);               \
	register long _b __asm__(ML_TRAP_REGISTER_2) = (long)(b);               \
	register long _c __asm__(ML_TRAP_REGISTER_3) = (long)(c);               \
                                                                                \
	__asm__ __volatile__ ("" : "+r"(_a), "+r"(_b), "+r"(_c));               \
})

#define ml_fatal_trap_with_value(code, a)  ({ \
	ml_trap_pin_value_1(a); \
	ml_fatal_trap(code); \
})

#define ml_fatal_trap_with_value2(code, a, b)  ({ \
	ml_trap_pin_value_2(a, b); \
	ml_fatal_trap(code); \
})

#define ml_fatal_trap_with_value3(code, a, b, c)  ({ \
	ml_trap_pin_value_3(a, b, c); \
	ml_fatal_trap(code); \
})

/*
 * Used for when `e` failed a linked list safe unlinking check.
 * On optimized builds, `e`'s value will be in:
 * - %rax for Intel
 * - x8 for arm64
 * - r8 on armv7
 */
__attribute__((cold, noreturn, always_inline))
static inline void
ml_fatal_trap_invalid_list_linkage(unsigned long e)
{
	ml_fatal_trap_with_value(/* XNU_HARD_TRAP_SAFE_UNLINK */ 0xbffd, e);
}

#endif /* _MACHINE_TRAP_H */
