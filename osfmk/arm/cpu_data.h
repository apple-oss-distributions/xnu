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
 *
 */

#ifndef ARM_CPU_DATA
#define ARM_CPU_DATA

#ifdef  MACH_KERNEL_PRIVATE

#include <mach_assert.h>
#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <pexpert/pexpert.h>
#include <arm/thread.h>
#include <arm/proc_reg.h>

#include <mach/mach_types.h>
#include <machine/thread.h>

__ASSUME_PTR_ABI_SINGLE_BEGIN

static inline __attribute__((const)) thread_t
current_thread_fast(void)
{
#if defined(__arm64__)
	/*
	 * rdar://73762648 clang nowadays insists that this is not constant
	 *
	 *     __builtin_arm_rsr64("TPIDR_EL1")
	 *
	 * and ignores the "attribute const", so do it the "dumb" way.
	 */
	struct thread *__unsafe_indexable result;
	__asm__ ("mrs %0, TPIDR_EL1" : "=r" (result));
	return __unsafe_forge_single(result);
#else
	// TPIDRPRW
	return __unsafe_forge_single((thread_t)(__builtin_arm_mrc(15, 0, 13, 0, 4)));
#endif
}

/*
 * The "volatile" flavor of current_thread() is intended for use by
 * scheduler code which may need to update the thread pointer in the
 * course of a context switch.  Any call to current_thread() made
 * prior to the thread pointer update should be safe to optimize away
 * as it should be consistent with that thread's state to the extent
 * the compiler can reason about it.  Likewise, the context switch
 * path will eventually result in an arbitrary branch to the new
 * thread's pc, about which the compiler won't be able to reason.
 * Thus any compile-time optimization of current_thread() calls made
 * within the new thread should be safely encapsulated in its
 * register/stack state.  The volatile form therefore exists to cover
 * the window between the thread pointer update and the branch to
 * the new pc.
 */
static inline thread_t
current_thread_volatile(void)
{
	/*
	 * The compiler might decide to treat rsr64 as const (comes and goes),
	 * which can allow it to eliminate redundant calls, which we don't want
	 * here. Thus we use volatile asm. Which gives us control on semantics.
	 *
	 * The mrc used for arm32 should be treated as volatile however.
	 */
#if defined(__arm64__)
	struct thread *__unsafe_indexable result;
	__asm__ volatile ("mrs %0, TPIDR_EL1" : "=r" (result));
	return __unsafe_forge_single(result);
#else
	// TPIDRPRW
	return __unsafe_forge_single((thread_t)(__builtin_arm_mrc(15, 0, 13, 0, 4)));
#endif
}

#if defined(__arm64__)

static inline vm_offset_t
exception_stack_pointer(void)
{
	vm_offset_t result = 0;
	__asm__ volatile (
                 "msr		SPSel, #1  \n"
                 "mov		%0, sp     \n"
                 "msr		SPSel, #0  \n"
                 : "=r" (result));

	return result;
}

#endif /* defined(__arm64__) */

#define getCpuDatap()            current_thread()->machine.CpuDatap
#define current_cpu_datap()      getCpuDatap()

extern int                       get_preemption_level(void);

#define mp_disable_preemption()  _disable_preemption()
#define mp_enable_preemption()   _enable_preemption()

__ASSUME_PTR_ABI_SINGLE_END

#endif  /* MACH_KERNEL_PRIVATE */

#endif  /* ARM_CPU_DATA */
