/*
 * Copyright (c) 2000-2023 Apple Inc. All rights reserved.
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

#ifndef _I386_TRAP_INTERNAL_H_
#define _I386_TRAP_INTERNAL_H_

#include <i386/trap.h>
#include <i386/thread.h>

#define DEFAULT_PANIC_ON_TRAP_MASK ((1U << T_INVALID_OPCODE) |  \
	(1U << T_GENERAL_PROTECTION) |                          \
	(1U << T_PAGE_FAULT) |                                  \
	(1U << T_SEGMENT_NOT_PRESENT) |                         \
	(1U << T_STACK_FAULT))


extern void             i386_exception(
	int                     exc,
	mach_exception_code_t   code,
	mach_exception_subcode_t subcode);

extern void             sync_iss_to_iks(x86_saved_state_t *regs);

extern void             sync_iss_to_iks_unconditionally(
	x86_saved_state_t       *regs);

extern void             kernel_trap(x86_saved_state_t *regs, uintptr_t *lo_spp);

extern void             user_trap(x86_saved_state_t *regs);

extern void             interrupt(x86_saved_state_t *regs);

extern void             panic_double_fault64(x86_saved_state_t *regs) __abortlike;
extern void             panic_machine_check64(x86_saved_state_t *regs) __abortlike;

typedef kern_return_t (*perfCallback)(
	int                     trapno,
	void                    *regs,
	uintptr_t               *lo_spp,
	int);

extern void             panic_i386_backtrace(void *, int, const char *, boolean_t, x86_saved_state_t *);
extern void     print_one_backtrace(pmap_t pmap, vm_offset_t topfp, const char *cur_marker, boolean_t is_64_bit);
extern void     print_thread_num_that_crashed(task_t task);
extern void     print_tasks_user_threads(task_t task);
extern void     print_threads_registers(thread_t thread);
extern void     print_uuid_info(task_t task);
extern void     print_launchd_info(void);

#if MACH_KDP
extern boolean_t        kdp_i386_trap(
	unsigned int,
	x86_saved_state64_t *,
	kern_return_t,
	vm_offset_t);
#endif /* MACH_KDP */

#endif /* _I386_TRAP_INTERNAL_H_ */
