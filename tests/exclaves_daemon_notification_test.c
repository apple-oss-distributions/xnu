/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/exclaves.h>
#include <dispatch/dispatch.h>
#include <servers/bootstrap.h>
#include <darwintest.h>
#include <darwintest_utils.h>

#if __has_include(<Tightbeam/tightbeam.h>)
#include <Tightbeam/tightbeam.h>
#include "ExclavesCHelloServer.tightbeam.h"
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.exclaves"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("Exclaves"),
	T_META_REQUIRES_SYSCTL_EQ("kern.exclaves_status", 1),
	T_META_TAG_VM_NOT_ELIGIBLE);

#define TEST_CONCLAVE_NAME "com.apple.kernel"
#define TEST_NOTIFICATION_NAME "com.apple.notification.hello"
#define TEST_SERVICE_NAME "com.apple.service.ExclavesCHelloServer"
#define TEST_QUEUE_NAME "com.apple.test.daemonnotif"
#define TEST_TIMEOUT_SECS 2

/*
 * This test validates end-to-end daemon notification functionality:
 * 1. Registers a receive right for daemon notifications with the kernel
 * 2. Looks up the ExclavesCHelloServer service to call callDaemonNotificationNotify()
 * 3. Verifies the notification message arrives via dispatch source
 */

#if defined(HAS_CALLDAEMONNOTIFICATIONNOTIFY)

static dispatch_semaphore_t notification_received_sem;
static bool notification_was_received = false;

/*
 * Helper function to create mach ports for daemon notifications.
 * Simulates what launchd does when setting up a daemon notification endpoint.
 * Returns the send port that should be registered with the kernel.
 */
static mach_port_t
simulate_launchd_endpoint_creation(mach_port_t *recv_port_out)
{
	kern_return_t kr;
	mach_port_t recv_port = MACH_PORT_NULL;
	mach_port_t send_port = MACH_PORT_NULL;

	// Allocate a mach port receive right
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate receive right");
	T_LOG("Created receive port: 0x%x", recv_port);

	// Create a send right from the receive right
	kr = mach_port_insert_right(mach_task_self(), recv_port, recv_port,
	    MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right send right");
	send_port = recv_port;
	T_LOG("Created send right for port: 0x%x", send_port);

	*recv_port_out = recv_port;
	return send_port;
}

/*
 * Helper function to clean up mach ports created for daemon notifications.
 * Simulates what launchd does when tearing down a daemon notification endpoint.
 */
static void
simulate_launchd_endpoint_cleanup(mach_port_t send_port, mach_port_t recv_port)
{
	kern_return_t kr;

	if (send_port != MACH_PORT_NULL) {
		kr = mach_port_mod_refs(mach_task_self(), send_port,
		    MACH_PORT_RIGHT_SEND, -1);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "Deallocate send right");
	}

	if (recv_port != MACH_PORT_NULL) {
		kr = mach_port_mod_refs(mach_task_self(), recv_port,
		    MACH_PORT_RIGHT_RECEIVE, -1);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "Deallocate receive right");
	}
}

/*
 * Helper function to trigger a daemon notification from the exclave.
 * Looks up the ExclavesCHelloServer service and calls callDaemonNotificationNotify().
 */
static void
tightbeam_call_daemon_notification_notify(void)
{
	kern_return_t kr;
	exclaves_id_t service_id;

	// Look up the ExclavesCHelloServer service
	T_LOG("Looking up exclave service: %s", TEST_SERVICE_NAME);
	kr = exclaves_lookup_service(MACH_PORT_NULL, TEST_SERVICE_NAME, &service_id);
	if (kr != KERN_SUCCESS) {
		T_SKIP("ExclavesCHelloServer service not available (kr=0x%x). "
		    "This test requires ExclavesCHelloServer with daemon notification support.", kr);
	}
	T_LOG("Found exclave service with ID: 0x%llx", (uint64_t)service_id);

	// Create Tightbeam client for the ExclavesCHelloServer service
	exclaveschelloserver_tests_s client;
	tb_darwin_transport_endpoint_t ep_d = calloc(1, sizeof(*ep_d));
	T_QUIET; T_ASSERT_NOTNULL(ep_d, "Allocate endpoint data");
	ep_d->port = MACH_PORT_NULL;
	ep_d->exclave_id = (uint64_t)service_id;

	tb_endpoint_t ep = tb_endpoint_create_with_data(TB_TRANSPORT_TYPE_DARWIN,
	    (tb_endpoint_data_t)ep_d, 0,
	    ^(tb_endpoint_data_t ep_data) {
		free(ep_data);
	});
	T_QUIET; T_ASSERT_NOTNULL(ep, "Create tightbeam endpoint");

	tb_error_t tb_result = exclaveschelloserver_tests__init(&client, ep);
	T_QUIET; T_EXPECT_EQ(tb_result, TB_ERROR_SUCCESS, "Init tightbeam client");

	// Call callDaemonNotificationNotify() on the exclave service to trigger the notification
	T_LOG("Calling callDaemonNotificationNotify() on exclave service...");
	tb_result = exclaveschelloserver_tests_calldaemonnotificationnotify(&client, ^(uint64_t result) {
		if (result != TB_ERROR_SUCCESS) {
		        T_FAIL("Exclave callDaemonNotificationNotify() returned error: %llu", result);
		}
	});
	T_EXPECT_EQ(tb_result, TB_ERROR_SUCCESS, "callDaemonNotificationNotify() tightbeam call");
}

#endif /* HAS_CALLDAEMONNOTIFICATIONNOTIFY */

T_DECL(exclaves_daemon_notification_basic,
    "Test daemon notification end-to-end",
    T_META_REQUIRES_SYSCTL_EQ("kern.exclaves_status", 1),
    T_META_ENABLED(true))
{
#if !defined(HAS_CALLDAEMONNOTIFICATIONNOTIFY)
	T_SKIP("callDaemonNotificationNotify() Tightbeam call not available");
#else
	kern_return_t kr;
	mach_port_t recv_port = MACH_PORT_NULL;
	mach_port_t send_port = MACH_PORT_NULL;
	dispatch_source_t dispatch_source = NULL;

	// Create semaphore for waiting for notification
	notification_received_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(notification_received_sem, "Create semaphore");

	// Create semaphore for waiting for cancel handler to complete
	dispatch_semaphore_t cancel_handler_sem = dispatch_semaphore_create(0);
	T_QUIET; T_ASSERT_NOTNULL(cancel_handler_sem, "Create cancel handler semaphore");

	// Create mach ports (simulates launchd _launch_domain_animate_endpoint)
	send_port = simulate_launchd_endpoint_creation(&recv_port);

	// Set up dispatch queue to listen for notifications
	// mirrors tb_daemon_notification_register in Tightbeam
	dispatch_queue_t queue = dispatch_queue_create(TEST_QUEUE_NAME, NULL);
	T_QUIET; T_ASSERT_NOTNULL(queue, "Create dispatch queue");

	dispatch_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, recv_port, 0, queue);
	T_QUIET; T_ASSERT_NOTNULL(dispatch_source, "Create dispatch source");

	dispatch_source_set_event_handler(dispatch_source, ^{
		// Drain the message from the port
		struct {
		        mach_msg_header_t header;
		        mach_msg_trailer_t trailer;
		} msg = {0};

		kern_return_t kr = mach_msg(&msg.header,
		MACH_RCV_MSG | MACH_RCV_TIMEOUT,
		0,
		sizeof(msg),
		recv_port,
		0, /* no timeout */
		MACH_PORT_NULL);

		if (kr == KERN_SUCCESS) {
		        T_LOG("Received mach message on notification port");
		        notification_was_received = true;
		} else {
		        T_LOG("mach_msg receive failed: 0x%x", kr);
		}
		dispatch_semaphore_signal(notification_received_sem);
	});

	dispatch_source_set_cancel_handler(dispatch_source, ^{
		T_LOG("Dispatch source cancelled");

		T_LOG("Deregistering daemon notification");
		kern_return_t kr = exclaves_daemon_notification_deregister(MACH_PORT_NULL,
		TEST_CONCLAVE_NAME, TEST_NOTIFICATION_NAME, send_port);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "exclaves_daemon_notification_deregister");

		// Clean up mach ports (simulates launchd _launch_domain_remove_endpoint)
		simulate_launchd_endpoint_cleanup(send_port, recv_port);

		// Verify the kernel released its reference to the port
		T_LOG("Verifying kernel released port reference...");
		mach_port_type_t type;
		kr = mach_port_type(mach_task_self(), send_port, &type);
		if (kr == KERN_INVALID_NAME) {
		        T_LOG("Port 0x%x correctly deallocated", send_port);
		} else if (kr == KERN_SUCCESS) {
		        T_FAIL("Port 0x%x still exists with type: 0x%x", send_port, type);
		} else {
		        T_FAIL("Port query returned unexpected error: 0x%x", kr);
		}

		dispatch_release(dispatch_source);

		// Signal that cancel handler has completed
		dispatch_semaphore_signal(cancel_handler_sem);
	});

	dispatch_activate(dispatch_source);
	T_LOG("Dispatch source activated");

	// Register the notification with the kernel
	// mirrors  _launch_domain_register_daemon_notification in libxpc
	T_LOG("Registering daemon notification: conclave='%s', name='%s'",
	    TEST_CONCLAVE_NAME, TEST_NOTIFICATION_NAME);
	kr = exclaves_daemon_notification_register(MACH_PORT_NULL,
	    TEST_CONCLAVE_NAME, TEST_NOTIFICATION_NAME, send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "exclaves_daemon_notification_register");
	T_LOG("Successfully registered daemon notification with kernel");

	// Call the notify function from ExclavesCHelloServerComponent
	tightbeam_call_daemon_notification_notify();

	// Wait for notification to arrive
	long result = dispatch_semaphore_wait(notification_received_sem,
	    dispatch_time(DISPATCH_TIME_NOW, TEST_TIMEOUT_SECS * NSEC_PER_SEC));

	T_EXPECT_EQ(result, 0L, "Dispatch source handler should be called within %d second timeout", TEST_TIMEOUT_SECS);
	T_EXPECT_TRUE(notification_was_received, "Dispatch source handler should receive message successfully");

	// Clean up
	if (dispatch_source) {
		dispatch_source_cancel(dispatch_source);

		// Wait for cancel handler to complete
		long cancel_result = dispatch_semaphore_wait(cancel_handler_sem,
		    dispatch_time(DISPATCH_TIME_NOW, TEST_TIMEOUT_SECS * NSEC_PER_SEC));
		T_EXPECT_EQ(cancel_result, 0L, "Dispatch source cancel handler should complete within %d second timeout", TEST_TIMEOUT_SECS);
	}

	dispatch_release(notification_received_sem);
	dispatch_release(cancel_handler_sem);
	dispatch_release(queue);

	if (notification_was_received) {
		T_PASS("Daemon notification test completed successfully");
	} else {
		T_FAIL("Daemon notification was not received");
	}
#endif /* HAS_CALLDAEMONNOTIFICATIONNOTIFY */
}
