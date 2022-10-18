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
#ifndef _MACHDEP_INTERNAL_H_
#define _MACHDEP_INTERNAL_H_

#include <machine/types.h>

#include <pexpert/arm64/board_config.h>

/* We cache the current cthread pointer in TPIDRRO_EL0 and
 * the current CPU number in the low 12 bits of TPIDR_EL0.
 *
 * The cthread pointer must be aligned
 * sufficiently that the maximum CPU number will fit.
 *
 * NOTE: Keep this in sync with libsyscall/os/tsd.h, specifically _os_cpu_number()
 */
#define MACHDEP_TPIDR_CPUNUM_MASK       (0x0000000000000fff)

/*
 * Machine Thread Flags (machine_thread.flags)
 */

/* Thread is entitled to use x18, don't smash it when switching to thread. */
#if !__ARM_KERNEL_PROTECT__
#define ARM_MACHINE_THREAD_PRESERVE_X18_SHIFT           0
#define ARM_MACHINE_THREAD_PRESERVE_X18                 (1 << ARM_MACHINE_THREAD_PRESERVE_X18_SHIFT)
#endif /* !__ARM_KERNEL_PROTECT__ */

#if defined(HAS_APPLE_PAC)
#define ARM_MACHINE_THREAD_DISABLE_USER_JOP_SHIFT       1
#define ARM_MACHINE_THREAD_DISABLE_USER_JOP             (1 << ARM_MACHINE_THREAD_DISABLE_USER_JOP_SHIFT)
#endif

#endif /* _MACHDEP_INTERNAL_H_ */
