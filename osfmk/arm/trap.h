/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#ifndef _ARM_TRAP_H_
#define _ARM_TRAP_H_

/*
 * Hardware trap vectors for ARM.
 */

#define T_RESET                 0
#define T_UNDEF                 1
#define T_SWI                   2
#define T_PREFETCH_ABT          3
#define T_DATA_ABT              4
#define T_IRQ                   6
#define T_FIQ                   7
#define T_PMU                   8


#define TRAP_NAMES "reset", "undefined instruction", "software interrupt", \
	           "prefetch abort", "data abort", "irq interrupt", \
	           "fast interrupt", "perfmon"

/*
 * Page-fault trap codes.
 */
#define T_PF_PROT               0x1             /* protection violation */
#define T_PF_WRITE              0x2             /* write access */
#define T_PF_USER               0x4             /* from user state */

#if !defined(ASSEMBLER)
#if __OPTIMIZE__
__attribute__((cold, always_inline))
static inline void
ml_recoverable_trap(unsigned int code)
__attribute__((diagnose_if(!__builtin_constant_p(code), "code must be constant", "error")))
{
	__asm__ volatile ("brk #%0" : : "i"(code));
}

__attribute__((cold, noreturn, always_inline))
static inline void
ml_fatal_trap(unsigned int code)
__attribute__((diagnose_if(!__builtin_constant_p(code), "code must be constant", "error")))
{
	__asm__ volatile ("brk #%0" : : "i"(code));
	__builtin_unreachable();
}
#else
#define ml_recoverable_trap(code) \
	__asm__ volatile ("brk #%0" : : "i"(code))
#define ml_fatal_trap(code)  ({ \
	__asm__ volatile ("brk #%0" : : "i"(code)); \
	__builtin_unreachable(); \
})
#endif

#if defined(XNU_KERNEL_PRIVATE)
/*
 * Unfortunately brk instruction only takes constant, so we have to unroll all the
 * cases and let compiler do the real work.  ¯\_(ツ)_/¯
 *
 * Codegen should be clean due to inlining which enables constant-folding.
 */
#define TRAP_CASE(code) \
	case code: \
	    ml_fatal_trap(0x5500 + code);

#define TRAP_5CASES(code) \
	TRAP_CASE(code) \
	TRAP_CASE(code + 1) \
	TRAP_CASE(code + 2) \
	TRAP_CASE(code + 3) \
	TRAP_CASE(code + 4)

/* For use by clang option -ftrap-function only */
__attribute__((cold, always_inline))
static inline void
ml_bound_chk_soft_trap(unsigned char code)
{
	switch (code) {
		/* 0 ~ 24 */
		TRAP_5CASES(0)
		TRAP_5CASES(5)
		TRAP_5CASES(10)
		TRAP_5CASES(15)
		TRAP_5CASES(20)
	case 25:         /* Bound check */
		/* code defined in kern/telemetry.h */
#if BOUND_CHECKS_DEBUG
		/*
		 * ml_recoverable_trap ensures that we get a separate trap instruction
		 * for each compiler-added check, and in BOUND_CHECKS_DEBUG we use it
		 * with the the fatal 0x5500 trap code. This makes it easier to
		 * understand what failed when you develop at desk.
		 */
		ml_recoverable_trap(0x5500 + 25);
#else /* BOUND_CHECKS_DEBUG */
		ml_recoverable_trap(0xFF00 + 25);
#endif /* BOUND_CHECKS_DEBUG */
		break;
	default:
		ml_fatal_trap(0x0);
	}
}
#endif /* XNU_KERNEL_PRIVATE */
#endif /* !ASSEMBLER */

#endif  /* _ARM_TRAP_H_ */
