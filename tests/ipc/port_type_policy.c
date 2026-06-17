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
#include <mach/mk_timer.h>
#include <mach/notify.h>
#include <sys/sysctl.h>
#include <sys/code_signing.h>
#include <mach/mk_timer.h>
#include <mach/task_info.h>
#include "ipc_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TIMEOUT(10),
	T_META_IGNORECRASHES(".*port_type_policy.*"),
	T_META_RUN_CONCURRENTLY(TRUE));

struct msg_complex_port {
	mach_msg_base_t         base;
	mach_msg_port_descriptor_t dsc;
	mach_msg_max_trailer_t  trailer;
};

#define OOL_PORT_COUNTS 2

struct msg_complex_port_array {
	mach_msg_base_t         base;
	mach_msg_ool_ports_descriptor_t dsc;
	mach_msg_max_trailer_t  trailer;
	mach_port_name_t        array[OOL_PORT_COUNTS];
};

struct msg_complex_port_two_arrays {
	mach_msg_header_t header;
	mach_msg_base_t         base;
	mach_msg_ool_ports_descriptor_t dsc1;
	mach_msg_ool_ports_descriptor_t dsc2;
	mach_msg_max_trailer_t  trailer;
	mach_port_name_t        array[OOL_PORT_COUNTS];
};

static kern_return_t
send_msg(
	mach_port_t       dest_port,
	mach_msg_header_t *msg,
	mach_msg_size_t   size)
{
	mach_msg_option64_t     opts;

	opts = MACH64_SEND_MSG | MACH64_SEND_MQ_CALL | MACH64_SEND_TIMEOUT;

	msg->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0,
	    MACH_MSGH_BITS_COMPLEX);
	msg->msgh_size = size;
	msg->msgh_remote_port = dest_port;
	msg->msgh_local_port = MACH_PORT_NULL;
	msg->msgh_voucher_port = MACH_PORT_NULL;
	msg->msgh_id = 42;
	return mach_msg2(msg, opts, *msg, size, 0, 0, 0, 0);
}

static kern_return_t
send_port_descriptor(
	mach_port_t             dest_port,
	mach_port_t             dsc_port,
	int                     disp)
{
	struct msg_complex_port complex_msg;
	mach_msg_header_t *msg;
	mach_msg_size_t size;

	complex_msg = (struct msg_complex_port){
		.base.body.msgh_descriptor_count = 1,
		.dsc = {
			.type        = MACH_MSG_PORT_DESCRIPTOR,
			.disposition = disp,
			.name        = dsc_port,
		},
	};

	msg = &complex_msg.base.header;
	size = (mach_msg_size_t)((char *)&complex_msg.trailer - (char *)&complex_msg.base);
	return send_msg(dest_port, msg, size);
}

static mach_port_t
recv_port_descriptor(mach_port_t dst_port)
{
	struct msg_complex_port msg;

	kern_return_t kr = mach_msg2(&msg, MACH64_RCV_MSG, MACH_MSG_HEADER_EMPTY,
	    0, sizeof(msg), dst_port, 0, 0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg2 receive port descriptor");

	/* extract and return the received port name */
	return msg.dsc.name;
}

static mach_port_t
get_send_receive_right(void)
{
	kern_return_t kr;
	mach_port_t port;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right");

	return port;
}

static kern_return_t
send_ool_port_array(
	mach_port_t dest_port,
	mach_msg_type_name_t disp)
{
	struct msg_complex_port_array complex_msg;
	mach_msg_header_t *msg;
	mach_msg_size_t size;

	complex_msg = (struct msg_complex_port_array){
		.base.body.msgh_descriptor_count = 1,
		.dsc = {
			.type        = MACH_MSG_OOL_PORTS_DESCRIPTOR,
			.disposition = disp,
			.address     = &complex_msg.array,
			.count       = OOL_PORT_COUNTS,
			.deallocate  = false,
		},
	};

	for (size_t i = 0; i < OOL_PORT_COUNTS; ++i) {
		complex_msg.array[i] = get_send_receive_right();
	}

	msg = &complex_msg.base.header;
	size = (mach_msg_size_t)((char *)&complex_msg.trailer - (char *)&complex_msg.base);
	return send_msg(dest_port, msg, size);
}

static kern_return_t
send_ool_port_multiple_arrays(
	mach_port_t dest_port,
	mach_msg_type_name_t disp)
{
	struct msg_complex_port_two_arrays complex_msg;
	mach_msg_header_t *msg;
	mach_msg_size_t size;

	complex_msg = (struct msg_complex_port_two_arrays){
		.base.body.msgh_descriptor_count = 2,
		.dsc1 = {
			.type        = MACH_MSG_OOL_PORTS_DESCRIPTOR,
			.disposition = disp,
			.address     = &complex_msg.array,
			.count       = OOL_PORT_COUNTS,
			.deallocate  = false,
		},
		.dsc2 = {
			.type        = MACH_MSG_OOL_PORTS_DESCRIPTOR,
			.disposition = disp,
			.address     = &complex_msg.array,
			.count       = OOL_PORT_COUNTS,
			.deallocate  = false,
		},
	};

	for (size_t i = 0; i < OOL_PORT_COUNTS; ++i) {
		complex_msg.array[i] = get_send_receive_right();
	}

	msg = &complex_msg.base.header;
	size = (mach_msg_size_t)((char *)&complex_msg.trailer - (char *)&complex_msg.base);
	return send_msg(dest_port, msg, size);
}


static void
destruct_generic_port(mach_port_t port)
{
	kern_return_t kr;
	mach_port_type_t type = 0;

	kr = mach_port_type(mach_task_self(), port, &type);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_type");

	kr = mach_port_destruct(mach_task_self(),
	    port,
	    (type & MACH_PORT_TYPE_SEND) ? -1 : 0,
	    0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");
}
/*
 * Helper functions and types to help making test output nice and readable.
 */
static const char*
get_disp_name(const mach_msg_type_name_t disp)
{
	switch (disp) {
	case MACH_MSG_TYPE_MOVE_SEND:
		return "MOVE_SEND";
	case MACH_MSG_TYPE_MAKE_SEND:
		return "MAKE_SEND";
	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		return "MOVE_SEND_ONCE";
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return "MAKE_SEND_ONCE";
	case MACH_MSG_TYPE_COPY_SEND:
		return "COPY_SEND";
	case MACH_MSG_TYPE_MOVE_RECEIVE:
		return "MOVE_RECEIVE";
	default:
		T_ASSERT_FAIL("Invalid disp");
	}
}

static const char*
get_notification_name(const mach_msg_id_t notification_id)
{
	switch (notification_id) {
	case MACH_NOTIFY_PORT_DESTROYED:
		return "PORT_DESTROY";
		break;
	case MACH_NOTIFY_NO_SENDERS:
		return "NO_MORE_SENDERS";
		break;
	case MACH_NOTIFY_SEND_POSSIBLE:
		return "SEND_POSSIBLE";
		break;
	default:
		T_ASSERT_FAIL("Invalid notification id");
	}
}

/* Use the shared port type descriptors from ipc_utils */
typedef port_type_desc_t port_type_desc;

/*
 * Helper functions to test MachIPC functionalities.
 */
static void
test_disallowed_register_mach_notification(
	const ipc_test_port_type_t port_type,
	const mach_msg_id_t notify_id)
{
	const port_type_desc *port_desc = ipc_get_port_type_desc(port_type);

	expect_sigkill(^{
		mach_port_t port, notify_port, previous;

		/* construct a receive right to send the port as descriptor to */
		notify_port = get_send_receive_right();

		port = ipc_create_port_with_type(port_type);
		(void)mach_port_request_notification(mach_task_self(),
		port,
		notify_id,
		0,
		notify_port,
		MACH_MSG_TYPE_MAKE_SEND_ONCE,
		&previous);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s failed with mach notification %s", port_desc->port_type_name, get_notification_name(notify_id));
}

/*
 * In this helper function we cover two properties:
 *     - we make sure these ports are immovable-receive by trying to
 *       send them in a message with MACH_MSG_PORT_DESCRIPTOR descriptor;
 *     - we attempt to register them for a PD notification.
 *
 * This seems redundent since it is not possible to register immovable-receive
 * ports to PD notification by construction. However, we want our tests
 * to cover everything, and this link between immovable-receive and
 * PD notifications, no matter how trivial, should be question as well.
 *
 * Note: this intentionally does NOT use get status trap
 *       and test for MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE,
 *       because the purpose of these tests is to ensure the overall security
 *       properties are respected (immovability, Guard, fatal exception, etc.).
 */
static void
test_receive_immovability(const ipc_test_port_type_t port_type)
{
	const port_type_desc *port_desc = ipc_get_port_type_desc(port_type);

	expect_sigkill(^{
		mach_port_t dst_port, port;

		/* construct a receive right to send the port as descriptor to */
		dst_port = get_send_receive_right();

		/*
		 * construct the port to test immovability, and send it as port
		 * descriptor with RECEIVE right.
		 */
		port = ipc_create_port_with_type(port_type);
		(void)send_port_descriptor(dst_port, port, MACH_MSG_TYPE_MOVE_RECEIVE);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s failed immovable-receive", port_desc->port_type_name);

	test_disallowed_register_mach_notification(port_type,
	    MACH_NOTIFY_PORT_DESTROYED);
}

/*
 * We have port types which their receive right is allowed to be move
 * ONCE, and then they become immovable-receive for the rest of their
 * lifetime.
 *
 * This helper function tests that property.
 */
static void
test_receive_immovability_move_once(const ipc_test_port_type_t port_type)
{
	expect_sigkill(^{
		kern_return_t kr;
		mach_port_t dst_port, port;
		const port_type_desc *port_desc;

		/* construct a receive right to send the port as descriptor to */
		dst_port = get_send_receive_right();

		/* construct the port for our test, and send it as port descriptor */
		port_desc = ipc_get_port_type_desc(port_type);
		port = ipc_create_port_with_type(port_type);
		kr = send_port_descriptor(dst_port, port, MACH_MSG_TYPE_MOVE_RECEIVE);
		T_ASSERT_MACH_SUCCESS(kr, "send_port_descriptor");

		/* we moved the receive right out of our IPC space */
		port = MACH_PORT_NULL;

		/*
		 * receive the port we sent to ourselves.
		 *
		 * From now on, this port is expected to be immovable-receive
		 * for the rest of its lifetime.
		 */
		port = recv_port_descriptor(dst_port);

		/*
		 * this should raise a fatal Guard exception
		 * on immovability violation
		 */
		(void)send_port_descriptor(dst_port, port, MACH_MSG_TYPE_MOVE_RECEIVE);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s is allowed to be move ONCE", ipc_get_port_type_desc(port_type)->port_type_name);
}

static void
test_send_immovability_move_so(const ipc_test_port_type_t port_type)
{
	expect_sigkill(^{
		mach_port_t dst_port, port, so_right;
		mach_msg_type_name_t disp;
		kern_return_t kr;
		const port_type_desc *port_desc;

		dst_port = get_send_receive_right();
		port_desc = ipc_get_port_type_desc(port_type);
		port = ipc_create_port_with_type(port_type);

		/* create a send-once right for the port */
		kr = mach_port_extract_right(mach_task_self(), port,
		MACH_MSG_TYPE_MAKE_SEND_ONCE, &so_right, &disp);

		T_ASSERT_MACH_SUCCESS(kr, "mach_port_extract_right with %s", port_desc->port_type_name);

		(void)send_port_descriptor(dst_port, so_right, MACH_MSG_TYPE_MOVE_SEND_ONCE);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s immovable-send failed with MOVE_SEND_ONCE", ipc_get_port_type_desc(port_type)->port_type_name);
}

static void
test_send_immovability(const ipc_test_port_type_t port_type)
{
	expect_sigkill(^{
		mach_msg_type_name_t disp;
		mach_port_name_t name;
		const port_type_desc *port_desc;

		port_desc = ipc_get_port_type_desc(port_type);
		mach_port_t port = ipc_create_port_with_type(port_type);
		(void)mach_port_extract_right(mach_task_self(), port,
		MACH_MSG_TYPE_MOVE_SEND, &name, &disp);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s immovable-send failed extract_right MOVE_SEND", ipc_get_port_type_desc(port_type)->port_type_name);

	expect_sigkill(^{
		mach_port_t dst_port, port;
		const port_type_desc *port_desc;

		/* construct a receive right to send the port as descriptor to */
		dst_port = get_send_receive_right();

		port_desc = ipc_get_port_type_desc(port_type);
		port = ipc_create_port_with_type(port_type);
		(void)send_port_descriptor(dst_port, port, MACH_MSG_TYPE_MOVE_SEND);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s immovable-send failed with MOVE_SEND", ipc_get_port_type_desc(port_type)->port_type_name);

	expect_sigkill(^{
		mach_port_t dst_port, port;
		const port_type_desc *port_desc;

		/* construct a receive right to send the port as descriptor to */
		dst_port = get_send_receive_right();

		port_desc = ipc_get_port_type_desc(port_type);
		port = ipc_create_port_with_type(port_type);
		(void)send_port_descriptor(dst_port, port, MACH_MSG_TYPE_COPY_SEND);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "%s immovable-send failed with COPY_SEND", ipc_get_port_type_desc(port_type)->port_type_name);

	/*
	 * Do not attempt to extract SEND_ONCE for reply port types. Such behavior
	 * should be covered by the reply_port_defense test.
	 */
	if (port_type != TEST_IOT_REPLY_PORT &&
	    port_type != TEST_IOT_SPECIAL_REPLY_PORT) {
		test_send_immovability_move_so(port_type);
	}
}

static void
test_ool_port_array(
	const ipc_test_port_type_t port_type,
	const mach_msg_type_name_t disp)
{
	expect_sigkill(^{
		mach_port_t dst_port;
		const port_type_desc *port_desc;

		/* construct a receive right to send the port as descriptor to */
		port_desc = ipc_get_port_type_desc(port_type);
		dst_port = ipc_create_port_with_type(port_type);

		(void)send_ool_port_array(dst_port, disp);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "sending OOL port array to %s with %s", ipc_get_port_type_desc(port_type)->port_type_name, get_disp_name(disp));
}

/*
 * Because of mach hardening opt out, group
 * reply port tests together and skip them.
 */
T_DECL(reply_port_policies,
    "Reply port policies tests") {
#if TARGET_OS_OSX || TARGET_OS_BRIDGE
	T_SKIP("Test disabled on macOS due to mach hardening opt out");
#endif /* TARGET_OS_OSX || TARGET_OS_BRIDGE */

	test_receive_immovability(TEST_IOT_REPLY_PORT);

	test_send_immovability(TEST_IOT_REPLY_PORT);

	test_disallowed_register_mach_notification(TEST_IOT_REPLY_PORT,
	    MACH_NOTIFY_NO_SENDERS);
}

T_DECL(immovable_receive_port_types,
    "Port types we expect to be immovable-receive") {
	/* Ensure mach port guard exceptions are fatal on bridgeOS */
	ipc_ensure_mach_port_guard_fatal();

	test_receive_immovability(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY);

	test_receive_immovability(TEST_IOT_EXCEPTION_PORT);

	test_receive_immovability(TEST_IOT_TIMER_PORT);

	test_receive_immovability(TEST_IOT_SPECIAL_REPLY_PORT);

	test_receive_immovability(TEST_IOT_SERVICE_PORT);

	test_receive_immovability(TEST_IOT_BOOTSTRAP_PORT);
}

T_DECL(immovable_receive_move_once_port_types,
    "Port types we expect to be immovable-receive") {
	test_receive_immovability_move_once(TEST_IOT_CONNECTION_PORT);
}

T_DECL(immovable_send_port_types,
    "Port types we expect to be immovable-send")
{
	/*
	 * connection port move_send is allowed when receive
	 * right is in space until rdar://164492988 is fixed
	 */
	/* test_send_immovability(TEST_IOT_CONNECTION_PORT); */

	test_send_immovability(TEST_IOT_SPECIAL_REPLY_PORT);
}

T_DECL(ool_port_array_policies,
    "OOL port array policies")
{
#if TARGET_OS_VISION
	T_SKIP("OOL port array enforcement is disabled");
#else
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}

	/*
	 * The only port type allowed to receive the MACH_MSG_OOL_PORTS_DESCRIPTOR
	 * descriptor is IOT_CONNECTION_PORT_WITH_PORT_ARRAY.
	 *
	 * Attempt sending MACH_MSG_OOL_PORTS_DESCRIPTOR to any other port type
	 * result in a fatal Guard exception.
	 */
	for (ipc_test_port_type_t port_type = 0; port_type < TEST_PORT_TYPE_COUNT; ++port_type) {
		if (port_type == TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY) {
			continue;
		}

		test_ool_port_array(port_type, MACH_MSG_TYPE_COPY_SEND);
	}

	/*
	 * Now try to send to IOT_CONNECTION_PORT_WITH_PORT_ARRAY ports,
	 * but use disallowed dispositions.
	 *
	 * The only allowed disposition is COPY_SEND.
	 */
	test_ool_port_array(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	    MACH_MSG_TYPE_MOVE_SEND);

	test_ool_port_array(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	    MACH_MSG_TYPE_MAKE_SEND);

	test_ool_port_array(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	    MACH_MSG_TYPE_MOVE_SEND_ONCE);

	test_ool_port_array(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE);

	test_ool_port_array(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	    MACH_MSG_TYPE_MOVE_RECEIVE);

	/*
	 * Finally, try sending OOL port array to IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	 * with (the only) allowed disposition, but send two arrays in one kmsg.
	 */
	expect_sigkill(^{
		mach_port_t dst_port;

		/* construct a receive right to send the port as descriptor to */
		dst_port = ipc_create_port_with_type(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY);

		(void)send_ool_port_multiple_arrays(dst_port, MACH_MSG_TYPE_COPY_SEND);

		/* Unreachable; ports will be destructed when IPC space is destroyed */
	}, "sending two OOL port arrays");
#endif /* TARGET_OS_VISION */
}

T_DECL(ool_port_array_policy_disabled_via_boot_arg,
    "Ensure the OOL port array policy can be disabled via boot arg",
    T_META_BOOTARGS_SET("ool_port_array_enforced=0")
    )
{
	/* Given we've booted with the `ool_port_array_enforced=0` boot arg */
	/*
	 * When we try to send two OOL port arrays in one kmsg,
	 * which is disallowed by the OOL array policy
	 */
	mach_port_t dst_port = ipc_create_port_with_type(TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY);
	(void)send_ool_port_multiple_arrays(dst_port, MACH_MSG_TYPE_COPY_SEND);
	/* Then we do not crash, because we've disabled the policy via a boot arg */
	/* (Note we don't bother to clean up this port but we're about to exit anyway) */
}


T_DECL(disallowed_no_more_senders_port_destroy_port_types,
    "Port types we disallow no-more-senders notifications for")
{
	test_disallowed_register_mach_notification(TEST_IOT_SPECIAL_REPLY_PORT,
	    MACH_NOTIFY_NO_SENDERS);
}

T_DECL(weak_reply_port,
    "Weak reply ports have no restrictions")
{
	mach_port_t prp, remote_port, recv_port;
	kern_return_t kr;

	prp = ipc_create_port_with_type(TEST_IOT_WEAK_REPLY_PORT);
	remote_port = get_send_receive_right();

	kr = mach_port_insert_right(mach_task_self(), prp, prp,
	    MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right");

	/* send a send right to the weak reply port*/
	kr = send_port_descriptor(remote_port, prp, MACH_MSG_TYPE_MOVE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "send_port_descriptor");

	/* receive that port descriptor, which has to have the same name */
	recv_port = recv_port_descriptor(remote_port);
	T_QUIET; T_ASSERT_EQ(prp, recv_port, "recv_port_descriptor send");

	/* drop only the send right of the weak reply port */
	kr = mach_port_mod_refs(mach_task_self(), prp, MACH_PORT_RIGHT_SEND, -1);

	/*
	 * Do not move receive right of a weak reply port as
	 * that triggers a non-fatal guard exception
	 */

	/* cleanup, destruct the ports we used */
	kr = mach_port_destruct(mach_task_self(), recv_port, 0, 0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct recv_port");

	kr = mach_port_destruct(mach_task_self(), remote_port, 0, 0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct remote_port");
}

T_DECL(mktimer_traps,
    "Test mktimer traps")
{
	kern_return_t kr;
	mach_port_t port;
	uint64_t result_time;

	/*
	 * Enumerate all port types, makes sure mk_timer_arm
	 * fails on every single one besides IOT_TIMER_PORT
	 */
	for (ipc_test_port_type_t i = 0; i < TEST_PORT_TYPE_COUNT; ++i) {
		if (i == TEST_IOT_TIMER_PORT) {
			continue;
		}

		/* Create a non-timer port type */
		port = ipc_create_port_with_type(i);

		kr = mk_timer_arm(port, 1);
		T_ASSERT_MACH_ERROR(kr,
		    KERN_INVALID_ARGUMENT,
		    "mk_timer_arm failed on non timer port type (%s)",
		    ipc_get_port_type_desc(i)->port_type_name);

		kr = mk_timer_cancel(port, &result_time);
		T_ASSERT_MACH_ERROR(kr,
		    KERN_INVALID_ARGUMENT,
		    "mk_timer_cancel failed on non timer port type (%s)",
		    ipc_get_port_type_desc(i)->port_type_name);

		kr = mk_timer_destroy(port);
		T_ASSERT_MACH_ERROR(kr,
		    KERN_INVALID_ARGUMENT,
		    "mk_timer_destroy failed on non timer port type (%s)",
		    ipc_get_port_type_desc(i)->port_type_name);

		/* Destroy the port we created */
		destruct_generic_port(port);
	}

	/* Verify mk_timer_arm succeed with actual timer */
	port = ipc_create_port_with_type(TEST_IOT_TIMER_PORT);

	kr = mk_timer_arm(port, 1);
	T_ASSERT_MACH_SUCCESS(kr, "mk_timer_arm on actual timer");

	kr = mk_timer_cancel(port, &result_time);
	T_ASSERT_MACH_SUCCESS(kr, "mk_timer_cancel on actual timer");

	kr = mk_timer_destroy(port);
	T_ASSERT_MACH_SUCCESS(kr, "mk_timer_destroy");
}

/*
 * Helper function to test exception port registration with a specific port type.
 * Returns true if the test passed, false otherwise.
 */
static void
test_exception_port_registration(const ipc_test_port_type_t port_type)
{
	const port_type_desc *port_desc = ipc_get_port_type_desc(port_type);
	kern_return_t kr;
	mach_port_t port;

	/* Create port and insert send right if needed */
	port = ipc_create_port_with_type(port_type);
	kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right for %s", port_desc->port_type_name);

	/* Try to set the exception port */
	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_ALL,
	    port,
	    EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES,
	    THREAD_STATE_NONE);

	/* Check the result based on port type */
	if (port_type == TEST_IOT_PORT ||
	    port_type == TEST_IOT_EXCEPTION_PORT ||
	    port_type == TEST_IOT_SERVICE_PORT ||
	    port_type == TEST_IOT_WEAK_SERVICE_PORT) {
		T_EXPECT_MACH_SUCCESS(kr,
		    "task_set_exception_ports should succeed for %s",
		    port_desc->port_type_name);
	} else {
		T_ASSERT_EQ(kr, KERN_INVALID_RIGHT,
		    "task_set_exception_ports should fail with KERN_INVALID_RIGHT for %s",
		    port_desc->port_type_name);
	}

	/* Clean up */
	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_ALL,
	    MACH_PORT_NULL,
	    EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES,
	    THREAD_STATE_NONE);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "clear exception ports");

	destruct_generic_port(port);
}

T_DECL(exception_port_registration_policies,
    "Exception port registration should only succeed for valid exception port types")
{
	/*
	 * Enumerate all port types, makes sure task_set_exception_ports
	 * succeeds only for valid exception port types.
	 */
	for (ipc_test_port_type_t port_type = 0; port_type < TEST_PORT_TYPE_COUNT; ++port_type) {
		if (port_type == TEST_IOT_REPLY_PORT) {
			/*
			 * skipping this port due to BATS difficulties with reply ports
			 * we rely on TEST_IOT_SPECIAL_REPLY_PORT for reply port coverage
			 */
			continue;
		}
		/* Reply ports cause SIGKILL when used as exception ports (with hardening enabled) */
		if (ipc_reply_port_causes_sigkill_as_exception_port(port_type)) {
			expect_sigkill(^{
				test_exception_port_registration(port_type);
			}, "task_set_exception_ports with %s (should cause SIGKILL)",
			ipc_get_port_type_desc(port_type)->port_type_name);
		} else {
			/* All other port types - test normally */
			assert_normal_exit(^{
				test_exception_port_registration(port_type);
			}, "task_set_exception_ports with %s",
			ipc_get_port_type_desc(port_type)->port_type_name);
		}
	}
}

static mach_port_t
create_report_crash_service_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.ReportCrash",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct ReportCrash service port");

	return port;
}

T_DECL(report_crash_exception_port,
    "ReportCrash service port should succeed as exception port")
{
	mach_port_t report_crash_port;
	kern_return_t kr;

	/* Create a ReportCrash service port */
	report_crash_port = create_report_crash_service_port();

	/* This should succeed since ReportCrash is a valid exception port */
	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_ALL,
	    report_crash_port,
	    EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES,
	    THREAD_STATE_NONE);
	T_ASSERT_MACH_SUCCESS(kr,
	    "task_set_exception_ports should succeed for com.apple.ReportCrash service port");

	/* Clean up */
	destruct_generic_port(report_crash_port);
}

/*
 * Helper function to test notification registration with a specific port type.
 */
static void
test_notification_with_port_type(ipc_test_port_type_t type, mach_msg_type_name_t disp)
{
	kern_return_t kr;
	mach_port_t port, notify_port, previous;
	const port_type_desc_t *desc = ipc_get_port_type_desc(type);

	/* Create the port to receive notifications */
	notify_port = ipc_create_port_with_type(type);
	T_QUIET; T_ASSERT_NE(notify_port, MACH_PORT_NULL, "Created %s", desc->port_type_name);

	/* Create a regular port to register notifications on */
	port = ipc_create_receive_port();
	T_QUIET; T_ASSERT_NE(port, MACH_PORT_NULL, "Created regular port");

	/* Attempt to register a notification using this port type */
	kr = mach_port_request_notification(mach_task_self(),
	    port,
	    MACH_NOTIFY_PORT_DESTROYED,
	    0,
	    notify_port,
	    disp,
	    &previous);

	if (type == TEST_IOT_TIMER_PORT) {
		if (disp == MACH_MSG_TYPE_MAKE_SEND) {
			T_QUIET; T_ASSERT_NE(kr, KERN_SUCCESS,
			    "%s registering for notifications disallowed with %s", desc->port_type_name, get_disp_name(disp));
		} else {
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
			    "%s registering for notifications allowed with %s", desc->port_type_name, get_disp_name(disp));
		}
	} else {
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
		    "%s successfully registered for notifications with %s", desc->port_type_name, get_disp_name(disp));
	}
	/* Clean up */
	ipc_deallocate_port(port);
	if (type == TEST_IOT_TIMER_PORT) {
		mk_timer_destroy(notify_port);
	} else if (type != TEST_IOT_REPLY_PORT &&
	    type != TEST_IOT_SPECIAL_REPLY_PORT) {
		ipc_deallocate_port(notify_port);
	}
}

T_DECL(notification_port_can_receive_notifications,
    "Test all port types for pol_can_receive_notifications",
    T_META_CHECK_LEAKS(false))
{
	/* Ensure mach port guard exceptions are fatal on bridgeOS */
	ipc_ensure_mach_port_guard_fatal();

	/*
	 * Iterate through all port types and verify that only those with
	 * pol_can_receive_notifications set can be used as notification ports.
	 * Test with both MAKE_SEND_ONCE and MAKE_SEND dispositions.
	 */
	for (ipc_test_port_type_t type = 0; type < TEST_PORT_TYPE_COUNT; type++) {
		if (type == TEST_IOT_REPLY_PORT) {
			/*
			 * skipping this port due to BATS difficulties with reply ports
			 * we rely on TEST_IOT_SPECIAL_REPLY_PORT for reply port coverage
			 */
			continue;
		}
		const port_type_desc_t *desc = ipc_get_port_type_desc(type);
		bool should_succeed = ipc_port_type_can_receive_notifications(type);

		if (should_succeed) {
			/* Port type should allow notification registration - expect normal exit */
			assert_normal_exit(^{
				test_notification_with_port_type(type, MACH_MSG_TYPE_MAKE_SEND_ONCE);
			}, "notification registration with %s (MAKE_SEND_ONCE)", desc->port_type_name);
		} else if (type == TEST_IOT_SPECIAL_REPLY_PORT ||
		    type == TEST_IOT_REPLY_PORT) {
			/* Reply ports and timer ports should crash - mach_port_request_notification requires make_so */
			expect_sigkill(^{
				test_notification_with_port_type(type, MACH_MSG_TYPE_MAKE_SEND_ONCE);
			}, "notification registration with %s MAKE_SEND_ONCE (disallowed)", desc->port_type_name);
			expect_sigkill(^{
				test_notification_with_port_type(type, MACH_MSG_TYPE_MAKE_SEND);
			}, "notification registration with %s MAKE_SEND (disallowed)", desc->port_type_name);
		} else if (type == TEST_IOT_TIMER_PORT) {
			assert_normal_exit(^{
				test_notification_with_port_type(type, MACH_MSG_TYPE_MAKE_SEND);
			}, "notification registration with %s MAKE_SEND", desc->port_type_name);
			assert_normal_exit(^{
				test_notification_with_port_type(type, MACH_MSG_TYPE_MAKE_SEND_ONCE);
			}, "notification registration with %s MAKE_SEND_ONCE", desc->port_type_name);
		} else {
			/* Port type should NOT allow notifications - expect exc_guard */
			expect_sigkill(^{
				test_notification_with_port_type(type, MACH_MSG_TYPE_MAKE_SEND_ONCE);
			}, "notification registration with %s MAKE_SEND_ONCE (disallowed)", desc->port_type_name);
		}
	}
}
