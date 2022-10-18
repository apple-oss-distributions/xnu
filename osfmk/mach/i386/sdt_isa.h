/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MACH_I386_SDT_ISA_H
#define _MACH_I386_SDT_ISA_H

#include <stdint.h>

#if defined (__x86_64__)

/*
 * Only define when testing.  This makes the calls into actual calls to
 * test functions.
 */
/* #define DTRACE_CALL_TEST */

#define DTRACE_STRINGIFY(s) #s
#define DTRACE_TOSTRING(s) DTRACE_STRINGIFY(s)

#if defined(KERNEL)

/*
 * For the kernel, record probe site location in SDT section.
 */

#define DTRACE_LABEL(p, n)                                                          \
	".pushsection __DATA_CONST, __sdt_cstring, cstring_literals\n\t"                \
	"1: .ascii \"" DTRACE_STRINGIFY(p##___) "\\0\"\n\t"                             \
	"2: .ascii \"" DTRACE_STRINGIFY(n) "\\0\"\n\t"                                  \
	".popsection" "\n\t"                                                            \
	".pushsection __DATA_CONST, __sdt, regular, live_support\n\t"                   \
	".p2align	3\n\t"                                                              \
	"l3_%=:\n\t"                                                                    \
	".quad 4f" "\n\t"                                                               \
	".quad 1b" "\n\t"                                                               \
	".quad 2b" "\n\t"                                                               \
	".popsection" "\n\t"                                                            \
	"4:"

#else   /* !KERNEL */

#define DTRACE_LABEL(p, n)                                                                      \
	"__dtrace_probe$" DTRACE_TOSTRING(%=__LINE__) DTRACE_STRINGIFY(_##p##___##n) ":"	"\n\t"

#endif  /* !KERNEL */


/*
 * Testing mode that builds function call to the probe site instead of nops.
 */
#ifdef DTRACE_CALL_TEST

#define DTRACE_CALL_INSN(p, n)                                           \
	"call _dtracetest" DTRACE_STRINGIFY(_##p##_##n)	"\n\t"

#define DTRACE_CALL(p, n)        \
	DTRACE_LABEL(p,n)            \
	DTRACE_CALL_INSN(p,n)

#else /* DTRACE_CALL_TEST */

#define DTRACE_NOPS                     \
	"nop"                       "\n\t"  \
	"nop"                       "\n\t"  \
	"nop"                       "\n\t"

#define DTRACE_CALL(p, n)        \
	DTRACE_LABEL(p,n)            \
	DTRACE_NOPS

#endif /* DTRACE_CALL_TEST */

/*
 * Ensures that stack pointer is 16 byte aligned after allocation.
 * Assumes that %0 contains scratch register to be used as temporary.
 */
#define DTRACE_ALLOC_STACK(n)                \
	"movq %%rsp, %0"                 "\n\t"  \
	"subq $0x8, %0"                  "\n\t"  \
	"andq $-16, %0"                  "\n\t"  \
	"movq %%rsp, (%0)"               "\n\t"  \
	"movq %0, %%rsp"                 "\n\t"  \
	"subq\t$" #n ",%%rsp"            "\n\t"

#define DTRACE_DEALLOC_STACK(n)              \
	"addq\t$" #n ",%%rsp"             "\n\t" \
	"popq %%rsp"                      "\n\t"


#define DTRACE_PROBE(provider, name)                                                        \
	do {                                                                                    \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                :                                                                       \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE1(provider, name, arg0)                                                 \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                : "r" (__dtrace_a0)                                                     \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE2(provider, name, arg0, arg1)                                           \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1)                                  \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE3(provider, name, arg0, arg1, arg2)                                     \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        register uintptr_t __dtrace_a2 asm("rdx") = (uintptr_t) arg2;                   \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1), "r" (__dtrace_a2)               \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE4(provider, name, arg0, arg1, arg2, arg3)                               \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        register uintptr_t __dtrace_a2 asm("rdx") = (uintptr_t) arg2;                   \
	        register uintptr_t __dtrace_a3 asm("rcx") = (uintptr_t) arg3;                   \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1), "r" (__dtrace_a2),              \
	                  "r" (__dtrace_a3)                                                     \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE5(provider, name, arg0, arg1, arg2, arg3, arg4)                         \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        register uintptr_t __dtrace_a2 asm("rdx") = (uintptr_t) arg2;                   \
	        register uintptr_t __dtrace_a3 asm("rcx") = (uintptr_t) arg3;                   \
	        register uintptr_t __dtrace_a4 asm("r8") = (uintptr_t) arg4;                    \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1), "r" (__dtrace_a2),              \
	                  "r" (__dtrace_a3), "r" (__dtrace_a4)                                  \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE6(provider, name, arg0, arg1, arg2, arg3, arg4, arg5)                   \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        register uintptr_t __dtrace_a2 asm("rdx") = (uintptr_t) arg2;                   \
	        register uintptr_t __dtrace_a3 asm("rcx") = (uintptr_t) arg3;                   \
	        register uintptr_t __dtrace_a4 asm("r8") = (uintptr_t) arg4;                    \
	        register uintptr_t __dtrace_a5 asm("r9") = (uintptr_t) arg5;                    \
	        asm volatile (                                                                  \
	                DTRACE_CALL(provider, name)                                             \
	                :                                                                       \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1), "r" (__dtrace_a2),              \
	                  "r" (__dtrace_a3), "r" (__dtrace_a4), "r" (__dtrace_a5)               \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE7(provider, name, arg0, arg1, arg2, arg3, arg4, arg5, arg6)             \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        register uintptr_t __dtrace_a2 asm("rdx") = (uintptr_t) arg2;                   \
	        register uintptr_t __dtrace_a3 asm("rcx") = (uintptr_t) arg3;                   \
	        register uintptr_t __dtrace_a4 asm("r8") = (uintptr_t) arg4;                    \
	        register uintptr_t __dtrace_a5 asm("r9") = (uintptr_t) arg5;                    \
	        uintptr_t tmp;                                                                  \
	        asm volatile (                                                                  \
	                DTRACE_ALLOC_STACK(16)                                                  \
	                "movq\t%[a6],0x0(%%rsp)"                                        "\n\t"  \
	                DTRACE_CALL(provider, name)                                             \
	                DTRACE_DEALLOC_STACK(16)                                                \
	                : "=r" (tmp)                                                            \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1), "r" (__dtrace_a2),              \
	                  "r" (__dtrace_a3), "r" (__dtrace_a4), "r" (__dtrace_a5),              \
	                  [a6] "r" ((uintptr_t)arg6)                                            \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#define DTRACE_PROBE8(provider, name, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)       \
	do {                                                                                    \
	        register uintptr_t __dtrace_a0 asm("rdi") = (uintptr_t) arg0;                   \
	        register uintptr_t __dtrace_a1 asm("rsi") = (uintptr_t) arg1;                   \
	        register uintptr_t __dtrace_a2 asm("rdx") = (uintptr_t) arg2;                   \
	        register uintptr_t __dtrace_a3 asm("rcx") = (uintptr_t) arg3;                   \
	        register uintptr_t __dtrace_a4 asm("r8") = (uintptr_t) arg4;                    \
	        register uintptr_t __dtrace_a5 asm("r9") = (uintptr_t) arg5;                    \
	        uintptr_t tmp;                                                                  \
	        asm volatile (                                                                  \
	                DTRACE_ALLOC_STACK(16)                                                  \
	                "movq\t%[a6],0x0(%%rsp)"                                        "\n\t"  \
	                "movq\t%[a7],0x8(%%rsp)"                                        "\n\t"  \
	                DTRACE_CALL(provider, name)                                             \
	                DTRACE_DEALLOC_STACK(16)                                                \
	                : "=r" (tmp)                                                            \
	                : "r" (__dtrace_a0), "r" (__dtrace_a1), "r" (__dtrace_a2),              \
	                  "r" (__dtrace_a3), "r" (__dtrace_a4), "r" (__dtrace_a5),              \
	                  [a6] "r" ((uintptr_t)arg6), [a7] "r" ((uintptr_t) arg7)               \
	                : "memory"                                                              \
	        );                                                                              \
	} while(0)

#endif /* defined (__x86_64__) */

#endif  /* _MACH_I386_SDT_ISA_H */
