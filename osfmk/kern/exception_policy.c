/*
 * Copyright (c) 2025 Apple Computer, Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/task.h>

#include <IOKit/IOBSD.h> // IOTaskHasEntitlement

#include <ipc/port.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_service_port.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ux_handler.h>
#include <kern/exception_policy.h>

#include <sys/reason.h>
#include <sys/code_signing.h>

#pragma mark exception port policy


/*
 * Requires: Nothing locked
 */
static bool
contained_process_exception_port_allowed(
	mach_port_t target_port,
	ipc_object_type_t target_port_type,
	bool exception_port_is_report_crash,
	task_t exception_task,
	ipc_space_t space)
{
	assert(!is_ux_handler_port(target_port));

	if (ip_is_exception_port_type(target_port_type)) {
		return true;
	}

	/* We must respect debuggers using exception ports however they want */
	if (is_address_space_debugged(get_bsdtask_info(exception_task))) {
		return true;
	}

	/*
	 * The process might not yet be marked as debugged,
	 * such as in the debugserver attach flow.
	 * We should still respect debugging/test entitlements
	 */
	if (IOTaskHasEntitlement(current_task(), SET_EXCEPTION_ENTITLEMENT)) {
		return true;
	}

	/* Check if this is the ReportCrash service port */
	if (exception_port_is_report_crash) {
		return true;
	}

	/* Telemetry for contained process attempting to send exception to non-whitelisted port */
	ipc_triage_policy_violation_and_expect_continue(
		IPC_SEC_POLICY_RESTRICT_CONTAINED_EXCEPTION_PORT,
		space,
		0,
		0,
		target_port,
		0
		);

	return true;
}

/* Requires: Nothing Locked */
bool
ipc_is_valid_exception_port(
	task_t exception_task,
	ipc_port_t maybe_exc_port)
{
	assert(IP_VALID(maybe_exc_port));
	ipc_space_t space;
	ipc_space_policy_t policy;
	ipc_object_type_t maybe_exc_port_type;
	ipc_object_label_t maybe_exc_port_label;

	/* Host level exception port has seperate security policy */
	if (!exception_task) {
		return true;
	}

	/* the host-level ux_handler is a special (valid) exception port */
	if (is_ux_handler_port(maybe_exc_port)) {
		return true;
	}

	space = exception_task->itk_space;
	policy = ipc_space_policy(space);
	maybe_exc_port_label = ipc_port_lock_label_get(maybe_exc_port);
	maybe_exc_port_type = maybe_exc_port_label.io_type;
	bool exception_port_is_report_crash = ip_is_report_crash_service_port_locked(maybe_exc_port_label);
	ip_mq_unlock_label_put(maybe_exc_port, &maybe_exc_port_label);

	/* contained processes must abide by stricter subset of rules*/
	if (ipc_should_apply_policy(policy, IPC_SPACE_POLICY_CONTAINED) &&
	    !contained_process_exception_port_allowed(maybe_exc_port,
	    maybe_exc_port_type, exception_port_is_report_crash, exception_task, space)) {
		return false;
	}

	/* Collect telemetry for service port receving exceptions */
	if (ip_is_strong_service_port(maybe_exc_port) &&
	    ip_active(maybe_exc_port) &&
	    !exception_port_is_report_crash) {
		/* unlock maybe_exc_port before ipc_triage_policy_violation */
		if (ipc_should_apply_policy(policy, IPC_POLICY_ENHANCED_V2)) {
			ipc_triage_policy_violation_and_expect_continue(
				IPC_SEC_POLICY_RESTRICT_SERVICE_PORT_FOR_EXCEPTION,
				space,
				0,
				0,
				maybe_exc_port,
				0
				);
		}
		return true;
	}

	if (maybe_exc_port_type != IOT_PORT &&
	    !ip_is_exception_port_type(maybe_exc_port_type) &&
	    !ip_is_weak_service_port_type(maybe_exc_port_type) &&
	    !ip_is_strong_service_port_type(maybe_exc_port_type)) { /* Allowed for now - rdar://153108740 */
		/* Port is not one of the only valid exception port types */
		return false;
	}

	/*
	 * rdar://77996387
	 * Avoid exposing immovable ports send rights (kobjects) to `get_exception_ports`
	 */
	assert(ipc_can_stash_naked_send(maybe_exc_port));

	/* kobjects must never receive exceptions */
	assert(!ip_is_kobject(maybe_exc_port));

	return true;
}

/* Requires: Nothing Locked */
bool
ipc_exception_send_allowed(__assert_only mach_port_t target_port)
{
	return ipc_is_valid_exception_port(current_task(), target_port);
}
