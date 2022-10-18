/*
 * Copyright (c) 2004-2012 Apple Inc. All rights reserved.
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
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		rtclock_asm.h
 *	Purpose:	Assembly routines for handling the machine dependent
 *				real-time clock.
 */

#ifndef _I386_RTCLOCK_H_
#define _I386_RTCLOCK_H_

#include <i386/pal_rtclock_asm.h>

/*
 * Update time on user trap entry.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define	TIME_TRAP_UENTRY CCALL(recount_leave_user)

/*
 * update time on user trap exit.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define	TIME_TRAP_UEXIT CCALL(recount_enter_user)

/*
 * Nanotime returned in %rax.
 * Computed from tsc based on the scale factor and an implicit 32 bit shift.
 * This code must match what _rtc_nanotime_read does in
 * machine_routines_asm.s.  Failure to do so can
 * result in "weird" timing results.
 *
 * Uses: %rsi, %rdi, %rdx, %rcx
 */
#define NANOTIME							       \
	movq	%gs:CPU_NANOTIME,%rdi					     ; \
	PAL_RTC_NANOTIME_READ_FAST()

/*
 * Check for vtimers for task.
 *   task_reg   is register pointing to current task
 *   thread_reg is register pointing to current thread
 */
#define TASK_VTIMER_CHECK(task_reg,thread_reg)				       \
	cmpl	$0,TASK_VTIMERS(task_reg)				     ; \
	jz	1f							     ; \
	orl	$(AST_BSD),%gs:CPU_PENDING_AST	/* Set pending AST */	     ; \
	lock								     ; \
	orl	$(AST_BSD),TH_AST(thread_reg)	/* Set thread AST  */	     ; \
1:									     ; \

#endif /* _I386_RTCLOCK_H_ */
