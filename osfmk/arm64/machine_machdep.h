/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#ifndef _MACHINE_MACHDEP_H_
#define _MACHINE_MACHDEP_H_

#include <machine/types.h>

/* We cache the following in EL0 registers
 *     TPIDRRO_EL0
 *         - the current cthread pointer
 *     TPIDR_EL0
 *         - the current CPU number (12 bits)
 *         - the current logical cluster id (8 bits)
 *
 * NOTE: Keep this in sync with libsyscall/os/tsd.h,
 *       specifically _os_cpu_number(), _os_cpu_cluster_number()
 */
#define MACHDEP_TPIDR_CPUNUM_SHIFT      0
#define MACHDEP_TPIDR_CPUNUM_MASK       0x0000000000000fff
#define MACHDEP_TPIDR_CLUSTERID_SHIFT   12
#define MACHDEP_TPIDR_CLUSTERID_MASK    0x00000000000ff000

/* Mask and count of bits that are CPU-dependent instead of being restored from thread state. */
#define MACHDEP_TPIDR_CPU_DATA_MASK     (MACHDEP_TPIDR_CPUNUM_MASK | MACHDEP_TPIDR_CLUSTERID_MASK)
#define MACHDEP_TPIDR_CPU_DATA_COUNT    MACHDEP_TPIDR_CLUSTERID_SHIFT
/* Count of bits that are restored from thread state. */
#define MACHDEP_TPIDR_THREAD_DATA_COUNT (64 - MACHDEP_TPIDR_CPU_DATA_COUNT)

/* Do not smash x18 on context switch. This bit will only be honored
 * if the thread also has an entitlement allowing x18 to be preserved.
 * This bit is saved and restored during context switch through
 * ARM_MACHINE_THREAD_PRESERVE_X18_SAVE.
 */
#define MACHDEP_TPIDR_FLAG_PRESERVE_X18_SHIFT   48
#define MACHDEP_TPIDR_FLAG_PRESERVE_X18         0x0001000000000000ULL

/* Mask of bits that are restored from thread state. */
#define MACHDEP_TPIDR_THREAD_MASK               MACHDEP_TPIDR_FLAG_PRESERVE_X18

#if MACH_KERNEL_PRIVATE

#include <pexpert/arm64/board_config.h>

/*
 * Machine Thread Flags (machine_thread.flags)
 * Note that these are 32 bits wide.
 */

#if defined(HAS_APPLE_PAC)
#define ARM_MACHINE_THREAD_DISABLE_USER_JOP_SHIFT       0
#define ARM_MACHINE_THREAD_DISABLE_USER_JOP             (1U << ARM_MACHINE_THREAD_DISABLE_USER_JOP_SHIFT)
#endif /* HAS_APPLE_PAC */

/* Thread should use 1 GHz timebase */
#define ARM_MACHINE_THREAD_USES_1GHZ_TIMBASE_SHIFT      1
#define ARM_MACHINE_THREAD_USES_1GHZ_TIMBASE            (1U << ARM_MACHINE_THREAD_USES_1GHZ_TIMBASE_SHIFT)

/* Saved state of MACHDEP_TPIDR_FLAG_PRESERVE_X18. The bit in
 * TPIDR_EL0 will be saved and restored from this machine thread flag.
 */
#if !__ARM_KERNEL_PROTECT__
#define ARM_MACHINE_THREAD_PRESERVE_X18_SAVE_SHIFT      2
#define ARM_MACHINE_THREAD_PRESERVE_X18_SAVE            (1U << ARM_MACHINE_THREAD_PRESERVE_X18_SAVE_SHIFT)
#endif /* !__ARM_KERNEL_PROTECT__ */

/* The initial state of x18 preservation for a new thread. */
#if !__ARM_KERNEL_PROTECT__
#define ARM_MACHINE_THREAD_PRESERVE_X18_INITIAL_SHIFT   3
#define ARM_MACHINE_THREAD_PRESERVE_X18_INITIAL         (1U << ARM_MACHINE_THREAD_PRESERVE_X18_INITIAL_SHIFT)
#endif /* !__ARM_KERNEL_PROTECT__ */

#endif /* MACH_KERNEL_PRIVATE || ASSEMBLER */

#endif /* _MACHINE_MACHDEP_H_ */
