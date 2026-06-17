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
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../ipc/ipc_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TIMEOUT(20),
	T_META_IGNORECRASHES(".*containment_ipc_notification.*"),
	T_META_RUN_CONCURRENTLY(TRUE));

/*
 * Test that containment processes with IPC entitlements cannot register for
 * notifications on various port types.
 *
 * A containment process has the com.apple.private.security.container-required
 * entitlement which restricts certain IPC operations. This test verifies that
 * attempting to register for mach notifications on various port types fails
 * with SIGKILL as expected.
 */

static const mach_msg_id_t notification_types[] = {
	MACH_NOTIFY_PORT_DESTROYED,
	MACH_NOTIFY_NO_SENDERS,
	MACH_NOTIFY_SEND_POSSIBLE,
};

static const char*
get_notification_name(mach_msg_id_t notification_id)
{
	switch (notification_id) {
	case MACH_NOTIFY_PORT_DESTROYED:
		return "PORT_DESTROYED";
	case MACH_NOTIFY_NO_SENDERS:
		return "NO_SENDERS";
	case MACH_NOTIFY_SEND_POSSIBLE:
		return "SEND_POSSIBLE";
	default:
		return "UNKNOWN";
	}
}

/*
 * Helper function to test notification registration with a specific port type
 * and notification type combination.
 */
static void
test_notification_registration(ipc_test_port_type_t type, mach_msg_id_t notify_id)
{
	kern_return_t kr;
	mach_port_t port, notify_port, previous;
	const port_type_desc_t *desc = ipc_get_port_type_desc(type);

	/* Create a regular port to register notifications on */
	port = ipc_create_receive_port();
	T_QUIET; T_ASSERT_NE(port, MACH_PORT_NULL, "Created regular port");

	/* Create the port which will receive notifications */
	notify_port = ipc_create_port_with_type(type);
	T_QUIET; T_ASSERT_NE(notify_port, MACH_PORT_NULL,
	    "constructing port type %s", desc->port_type_name);

	/*
	 * Attempt to register for notifications.
	 * For containment processes with IPC entitlements,
	 * this should result in SIGKILL.
	 */
	kr = mach_port_request_notification(mach_task_self(),
	    port,
	    notify_id,
	    0,
	    notify_port,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE,
	    &previous);
	T_ASSERT_MACH_SUCCESS(kr, "%s successfully registered for notifications", desc->port_type_name);
}

T_DECL(containment_ipc_notification_registration,
    "Containment processes with IPC entitlements cannot register for notifications")
{
	/* Ensure mach port guard exceptions are fatal on bridgeOS */
	ipc_ensure_mach_port_guard_fatal();

	/*
	 * Iterate through all port types and all notification types.
	 * Each combination should result in SIGKILL for containment processes.
	 */
	for (ipc_test_port_type_t type = 0; type < TEST_PORT_TYPE_COUNT; type++) {
		const port_type_desc_t *desc = ipc_get_port_type_desc(type);
		if (type == TEST_IOT_REPLY_PORT) {
			/*
			 * skipping this port due to BATS difficulties with reply ports
			 * we rely on TEST_IOT_SPECIAL_REPLY_PORT for reply port coverage
			 */
			continue;
		}

		for (size_t j = 0; j < sizeof(notification_types) / sizeof(notification_types[0]); j++) {
			mach_msg_id_t notify_id = notification_types[j];

			if (ipc_containment_notification_causes_sigkill(type)) {
				expect_sigkill(^{
					test_notification_registration(type, notify_id);
				}, "Containment IPC: %s with %s notification:",
				desc->port_type_name,
				get_notification_name(notify_id));
			} else {
				assert_normal_exit(^{
					test_notification_registration(type, notify_id);
				}, "Containment IPC: %s with %s notification:",
				desc->port_type_name,
				get_notification_name(notify_id));
			}
		}
	}

	T_PASS("All port types correctly denied notification registration for containment process");
}
