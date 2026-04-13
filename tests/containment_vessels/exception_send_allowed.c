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
#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/task.h>
#include <mach/mach.h>
#include <mach/exception.h>
#include <pthread.h>
#include <signal.h>

#include "exc_helpers.h"
#include "../ipc/ipc_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

/* Exception handler callback that advances PC past the faulting instruction */
static size_t
exception_handler_callback(
	mach_port_t task,
	mach_port_t thread,
	exception_type_t type,
	mach_exception_data_t codes,
	uint64_t pc)
{
#pragma unused(task, thread, type, codes, pc)
	T_LOG("Exception received successfully");
	/* Advance PC by 4 bytes to skip the faulting instruction */
	return 4;
}

/* Trigger a bad access exception by dereferencing a null pointer */
static void
trigger_exception(void)
{
	T_LOG("Dereferencing null pointer...");
	*(volatile int *)0 = 0;
}

/*
 * Helper function to test exception handling with a specific port type.
 * This function registers a port of the given type as an exception handler,
 * triggers an exception, and verifies the process exits normally.
 */
static void
test_exception_with_port_type(ipc_test_port_type_t port_type)
{
	kern_return_t kr;
	mach_port_t exc_port;
	const port_type_desc_t *desc = ipc_get_port_type_desc(port_type);

	/* Create a port of the specified type */
	exc_port = ipc_create_port_with_type(port_type);
	T_QUIET; T_ASSERT_NE(exc_port, MACH_PORT_NULL, "Created %s", desc->port_type_name);

	/* Register the port as our exception handler */
	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_BAD_ACCESS,
	    exc_port,
	    EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
	    THREAD_STATE_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_set_exception_ports with %s", desc->port_type_name);

	/* Start exception handler in background */
	run_exception_handler_behavior64(exc_port, NULL,
	    (void*)exception_handler_callback,
	    EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES,
	    true);

	/* Trigger an exception - behavior depends on port type */
	T_LOG("Triggering exception with %s...", desc->port_type_name);
	trigger_exception();

	/* If we get here without being killed, the test passes */
	T_LOG("Exception was handled successfully with %s", desc->port_type_name);
}

/*
 * Test: Various port types used for exception handling in contained processes
 *
 * Port types tested:
 * - TEST_IOT_EXCEPTION_PORT: Allowed (ip_is_exception_port_type() returns true)
 * - TEST_IOT_PORT: Telemetry emitted (ipc_is_valid_exception_port() returns true)
 * - TEST_IOT_CONNECTION_PORT: DISALLOWED - process gets SIGKILL
 * - TEST_IOT_SERVICE_PORT: Telemetry emitted
 *
 * Connection ports are disallowed for exception handling and cause SIGKILL.
 * Other non-exception ports trigger telemetry but continue normally.
 */
#ifdef SET_EXCEPTION_ENTITLED
T_DECL(contained_process_exception_port_types_entitled,
    "Test exception handling with all port types in contained processes while you hold the entitlement",
    T_META_MAYFAIL("waiting for enforcement"))
#else
T_DECL(contained_process_exception_port_types,
    "Test exception handling with all port types in contained processes",
    T_META_MAYFAIL("waiting for enforcement"))
#endif
{
	/* Port types that are allowed (with or without telemetry) */
	ipc_test_port_type_t allowed_port_types[] = {
		TEST_IOT_EXCEPTION_PORT,  /* Explicitly allowed exception port type */
		TEST_IOT_PORT,            /* Regular port - emits telemetry */
		TEST_IOT_SERVICE_PORT,    /* Service port - emits telemetry */
	};

	/* Test allowed port types - should exit normally */
	for (size_t i = 0; i < countof(allowed_port_types); i++) {
		ipc_test_port_type_t port_type = allowed_port_types[i];
		const port_type_desc_t *desc = ipc_get_port_type_desc(port_type);
#ifdef SET_EXCEPTION_ENTITLED
/* The test will eventually fail without the entitlement and succeed with it,
 *  but for now both of them succeed while in telemetry mode */
#endif/* SET_EXCEPTION_ENTITLED */
		assert_normal_exit(^{
			test_exception_with_port_type(port_type);
		}, "exception handling with %s", desc->port_type_name);
	}

	/* Test connection port - should be killed with SIGKILL */
	const port_type_desc_t *conn_desc = ipc_get_port_type_desc(TEST_IOT_CONNECTION_PORT);
	expect_sigkill(^{
		test_exception_with_port_type(TEST_IOT_CONNECTION_PORT);
	}, "exception handling with %s (disallowed)", conn_desc->port_type_name);
}
