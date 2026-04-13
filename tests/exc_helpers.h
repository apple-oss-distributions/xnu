/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

#ifndef EXC_HELPERS_H
#define EXC_HELPERS_H

#include <mach/mach.h>
#include <mach/exception.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach/thread_status.h>

/**
 * Set verbose_exc_helper = true to log exception information with T_LOG().
 * The default is true.
 */
extern bool verbose_exc_helper;

/**
 * Callback invoked by run_exception_handler() when a Mach exception is
 * received.
 *
 * @param task      the task causing the exception
 * @param thread    the thread causing the exception
 * @param type      exception type received from the kernel
 * @param codes     exception codes received from the kernel
 * @param pc        the (ptrauth-stripped) program counter of the exception
 *
 * @return      how much the exception handler should advance the program
 *              counter, in bytes (in order to move past the code causing the
 *              exception); OR the special value EXC_HELPER_HALT to
 *              let the process crash instead of continuing.
 */

/* EXCEPTION_STATE_IDENTITY (the default for exc_helpers) */
typedef size_t (*exc_handler_callback_t)(
	mach_port_t task,
	mach_port_t thread,
	exception_type_t type,
	mach_exception_data_t codes,
	uint64_t pc);

/* EXCEPTION_STATE */
typedef size_t (*exc_handler_state_callback_t)(
	exception_type_t type,
	mach_exception_data_t codes,
	uint64_t pc,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count);

/* EXCEPTION_IDENTITY_PROTECTED */
typedef size_t (*exc_handler_protected_callback_t)(
	task_id_token_t token,
	uint64_t thread_id,
	exception_type_t type,
	mach_exception_data_t codes);

/* EXCEPTION_STATE_IDENTITY_PROTECTED */
typedef size_t (*exc_handler_state_protected_callback_t)(
	task_id_token_t token,
	uint64_t thread_id,
	exception_type_t type,
	mach_exception_data_t codes,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count);

/* MACH_EXCEPTION_BACKTRACE_PREFERRED */
typedef kern_return_t (*exc_handler_backtrace_callback_t)(
	kcdata_object_t kcdata_object,
	exception_type_t type,
	mach_exception_data_t codes);

#define EXC_HELPER_HALT ((size_t)INTPTR_MAX)

/**
 * Allocates a Mach port and configures it to receive exception messages,
 * and installs it as the exception handler for the current thread.
 *
 * @param exception_mask exception types that this Mach port should receive
 *
 * @return a newly-allocated and -configured Mach port
 */
mach_port_t
create_exception_port(exception_mask_t exception_mask);

mach_port_t
create_exception_port_behavior64(exception_mask_t exception_mask, exception_behavior_t behavior);

/**
 * Installs an exception port created with create_exception_port()
 * as the exception handler for the current thread.
 */
void
set_thread_exception_port(mach_port_t exc_port, exception_mask_t exception_mask);

void
set_thread_exception_port_behavior64(mach_port_t exc_port, exception_mask_t exception_mask, exception_behavior_t behavior);

/**
 * Handles one exception received on the provided Mach port, by running the
 * provided callback. The default behavior is EXCEPTION_STATE_IDENTITY.
 *
 * @param exc_port Mach port configured to receive exception messages
 * @param callback callback to run when an exception is received
 */
void
run_exception_handler(mach_port_t exc_port, exc_handler_callback_t callback);

void
run_exception_handler_behavior64(
	mach_port_t exc_port,
	const void *preferred_callback,
	const void *callback,
	exception_behavior_t behavior,
	bool run_once);

/**
 * Handles every exception received on the provided Mach port, by running the
 * provided callback. The default behavior is EXCEPTION_STATE_IDENTITY.
 *
 * @param exc_port Mach port configured to receive exception messages
 * @param callback callback to run when an exception is received
 */
void
repeat_exception_handler(mach_port_t exc_port, exc_handler_callback_t callback);

void
repeat_exception_handler_behavior64(
	mach_port_t exc_port,
	const void *callback,
	exception_behavior_t behavior);

#endif /* EXC_HELPERS_H */
