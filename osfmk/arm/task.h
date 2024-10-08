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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 * Machine dependent task fields
 */

#ifdef MACH_KERNEL_PRIVATE
/* Provide access to target-specific defintions which may be used by
 * consuming code, e.g. HYPERVISOR. */
#include <arm64/proc_reg.h>
#endif


#if defined(HAS_APPLE_PAC)
#define TASK_ADDITIONS_PAC \
	uint64_t rop_pid; \
	uint64_t jop_pid; \
	uint8_t disable_user_jop;
#else
#define TASK_ADDITIONS_PAC
#endif



#define TASK_ADDITIONS_UEXC uint64_t uexc[4];

#if !__ARM_KERNEL_PROTECT__
#define TASK_ADDITIONS_X18 bool preserve_x18;
#else
#define TASK_ADDITIONS_X18
#endif

#define TASK_ADDITIONS_APT

#define MACHINE_TASK \
	void * XNU_PTRAUTH_SIGNED_PTR("task.task_debug") task_debug; \
	TASK_ADDITIONS_PAC \
\
	TASK_ADDITIONS_UEXC \
	TASK_ADDITIONS_X18 \
	TASK_ADDITIONS_APT \
	bool uses_1ghz_timebase;
