/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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
#include <mach/mach_port.h>
#include <kern/task.h>
#include <kern/waitq.h>
#include <mocks/dt_proxy.h>
#include <mocks/osfmk/mock_ipc.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <kern/ipc_kobject.h>

#include "ipc/utils/ipc_policy_helpers.h"
#include "ipc/utils/mach_port_construct_helpers.h"

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

#pragma mark - Mocks

T_MOCK_CALL_QUEUE(ipc_triage_policy_violation_and_expect_continue_call, {
	ipc_sec_policy_t expected_policy;
	int expected_maybe_ca_aux_data;
});

T_MOCK_SET_PERM_FUNC(void,
    ipc_triage_policy_violation_and_expect_continue,
    (ipc_sec_policy_t policy,
    ipc_space_t maybe_space,
    uint32_t maybe_exc_target,
    uint64_t maybe_exc_payload,
    ipc_port_t maybe_ca_violating_port,
    int maybe_ca_aux_data))
{
	ipc_triage_policy_violation_and_expect_continue_call call = dequeue_ipc_triage_policy_violation_and_expect_continue_call();
	T_ASSERT_EQ(policy, call.expected_policy, "expected policy %d == actual %d", call.expected_policy, policy);
	T_ASSERT_EQ(maybe_ca_aux_data, call.expected_maybe_ca_aux_data, "expected maybe_ca_aux_data %d == actual %d", call.expected_maybe_ca_aux_data, maybe_ca_aux_data);
}

#pragma mark - Utilities

static void
get_port_with_send_right_without_entry_in_current_space(
	ipc_port_t* out_port,
	mach_port_name_t* out_name)
{
	*out_port = ipc_create_port_with_type(TEST_IOT_PORT, out_name);
	T_QUIET; T_ASSERT_NE_PTR(*out_port, IP_NULL, "ipc_create_port_with_type");
	/* The port has a send right */
	ipc_port_t sright = ipc_port_make_send_any(*out_port);
	T_QUIET; T_ASSERT_EQ_PTR(sright, *out_port, "ipc_port_make_send_any");

	/* And the name is not allocated in the space */
	kern_return_t kr = mach_port_deallocate(current_space(), *out_name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");

	/* And copyin the receive right to remove it from the space */
	ipc_port_t rright = IP_NULL;
	kr = ipc_object_copyin(current_space(), *out_name,
	    MACH_MSG_TYPE_PORT_RECEIVE, IPC_OBJECT_COPYIN_FLAGS_NONE,
	    IPC_COPYIN_REASON_NONE, NULL, &rright);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyin");
	T_QUIET; T_ASSERT_EQ_PTR(rright, *out_port, "ipc_object_copyin should return the port");
}

static void
get_port_with_send_right_with_entry_in_current_space(
	ipc_port_t* out_port,
	mach_port_name_t* out_name)
{
	*out_port = ipc_create_port_with_type(TEST_IOT_PORT, out_name);
	T_QUIET; T_ASSERT_NE_PTR(*out_port, IP_NULL, "ipc_create_port_with_type");
	/* The port has a send right */
	ipc_port_t sright = ipc_port_make_send_any(*out_port);
	T_QUIET; T_ASSERT_EQ_PTR(sright, *out_port, "ipc_port_make_send_any");
	/* And the name is implicitly allocated in the space */
}

static void
get_port_with_send_right_with_rr_but_no_sr_in_current_space(
	ipc_port_t* out_port,
	mach_port_name_t* out_name)
{
	*out_port = ipc_create_port_with_type(TEST_IOT_PORT, out_name);
	T_QUIET; T_ASSERT_NE_PTR(*out_port, IP_NULL, "ipc_create_port_with_type");
	/* The port has a send right */
	ipc_port_t sright = ipc_port_make_send_any(*out_port);
	T_QUIET; T_ASSERT_EQ_PTR(sright, *out_port, "ipc_port_make_send_any");

	/* Remove the send right from the entry, leaving the receive right */
	kern_return_t kr = mach_port_mod_refs(current_space(), *out_name, MACH_PORT_RIGHT_SEND, -1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_mod_refs");
}

#pragma mark - Tests

T_DECL(unblessed_copyout_immovable_send_right_new_entry_emits_telemetry,
    "Ensure an unblessed copyout of an immovable send right to a new entry emits telemetry")
{
	kern_return_t kr;

	/* Given a port with a send right that's not present in the current space */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_without_entry_in_current_space(&port, &name);

	/* And the right should be immovable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return true;
	});

	/* When we copyout the send right to a new entry */
	/* And we don't specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	/* Then we expect telemetry to be emitted */
	enqueue_ipc_triage_policy_violation_and_expect_continue_call((ipc_triage_policy_violation_and_expect_continue_call){
		.expected_policy = IPC_SEC_POLICY_RESTRICT_IMMOVABLE_SEND_RIGHT_CREATION,
		.expected_maybe_ca_aux_data = 0,
	});

	/* And the copyout succeeds */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, &name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	/* Deallocate the send right held by the space */
	kr = mach_port_deallocate(current_space(), name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");
	/* Deallocate the receive right held by the kernel */
	ipc_port_release_receive(port);
}

T_DECL(blessed_copyout_immovable_send_right_new_entry_no_telemetry,
    "Ensure a blessed copyout of an immovable send right to a new entry does not telemetry")
{
	kern_return_t kr;

	/* Given a port with a send right that's not present in the current space */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_without_entry_in_current_space(&port, &name);

	/* And the right should be immovable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return true;
	});

	/* When we copyout the send right to a new entry */
	/* And we specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND,
	    NULL, &name);
	/* Then the copyout succeeds */
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* And no telemetry should be emitted */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	/* Deallocate the send right held by the space */
	kr = mach_port_deallocate(current_space(), name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");
	/* Deallocate the receive right held by the kernel */
	ipc_port_release_receive(port);
}

T_DECL(unblessed_copyout_immovable_send_right_existing_entry_no_telemetry,
    "Ensure an unblessed copyout of an immovable send right to an existing entry does not telemetry")
{
	kern_return_t kr;

	/* Given a port with a send right that is present in the current space */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_with_entry_in_current_space(&port, &name);

	/* And the right should be immovable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return true;
	});

	/* When we copyout the send right to a new entry */
	/* And we do not specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, &name);
	/* Then the copyout succeeds */
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* And no telemetry should be emitted */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	ipc_deallocate_port(
		TEST_IOT_PORT,
		port,
		name);
}

T_DECL(blessed_copyout_immovable_send_right_existing_entry_no_telemetry,
    "Ensure a blessed copyout of an immovable send right to an existing entry does not telemetry")
{
	kern_return_t kr;

	/* Given a port with a send right that is present in the current space */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_with_entry_in_current_space(&port, &name);

	/* And the right should be immovable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return true;
	});

	/* When we copyout the send right to a new entry */
	/* And we do not specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, &name);
	/* Then the copyout succeeds */
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* And no telemetry should be emitted */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	ipc_deallocate_port(
		TEST_IOT_PORT,
		port,
		name);
}

T_DECL(unblessed_copyout_movable_send_right_new_entry_no_telemetry,
    "Ensure an unblessed copyout of a movable send right to a new entry does not emit telemetry")
{
	kern_return_t kr;

	/* Given a port with a send right that is present in the current space */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_with_entry_in_current_space(&port, &name);

	/* And the right should be movable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return false;
	});

	/* When we copyout the send right to a new entry */
	/* And we do not specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, &name);
	/* Then the copyout succeeds */
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* And no telemetry should be emitted */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	ipc_deallocate_port(
		TEST_IOT_PORT,
		port,
		name);
}

T_DECL(blessed_copyout_movable_send_right_new_entry_no_telemetry,
    "Ensure a blessed copyout of a movable send right to a new entry does not emit telemetry")
{
	kern_return_t kr;

	/* Given a port with a send right that is present in the current space */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_with_entry_in_current_space(&port, &name);

	/* And the right should be movable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return false;
	});

	/* When we copyout the send right to a new entry */
	/* And we specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND,
	    NULL, &name);
	/* Then the copyout succeeds */
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* And no telemetry should be emitted */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	ipc_deallocate_port(
		TEST_IOT_PORT,
		port,
		name);
}

T_DECL(unblessed_copyout_immovable_send_right_and_entry_with_rr_no_telemetry,
    "Ensure an unblessed copyout of an immovable send right to an entry with a receive right does not emit telemetry")
{
	kern_return_t kr;

	/* Given a port with an entry containing the receive right but not the send right */
	ipc_port_t port;
	mach_port_name_t name;
	get_port_with_send_right_with_rr_but_no_sr_in_current_space(&port, &name);

	/* And the right should be immovable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send, bool,
	    (task_t curr_task,
	    ipc_port_t port,
	    ipc_object_label_t label),
	{
		return true;
	});

	/* When we copyout the send right */
	/* And we don't specify the IPC_OBJECT_COPYOUT_FLAGS_ALLOW_IMMOVABLE_SEND flag */
	/* Then the copyout succeeds */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, &name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* And no telemetry should be emitted */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	/* (Cleanup) */
	ipc_deallocate_port(
		TEST_IOT_PORT,
		port,
		name);
}

T_DECL(copyout_immovable_send_right_no_double_lock,
    "Ensure copyout of immovable send right doesn't double-lock (rdar://170035423)")
{
	kern_return_t kr;
	ipc_port_t port;
	mach_port_name_t name;

	/* Given a port with a send right but without an entry in the space */
	get_port_with_send_right_without_entry_in_current_space(&port, &name);
	/* And the send right should be immovable */
	T_MOCK_SET_CALLBACK(ipc_should_mark_immovable_send,
	    bool, (task_t curr_task, ipc_port_t p, ipc_object_label_t label), {
		return true;
	});

	/* And the policy violation handler is set up to detect double-lock attempts */
	T_MOCK_SET_CALLBACK(ipc_triage_policy_violation_and_expect_continue,
	    void, (ipc_sec_policy_t policy,
	    ipc_space_t maybe_space,
	    uint32_t maybe_exc_target,
	    uint64_t maybe_exc_payload,
	    ipc_port_t maybe_ca_violating_port,
	    int maybe_ca_aux_data), {
		/* Catch when we'd try and lock an already-locked port */
		if (IP_VALID(maybe_ca_violating_port) &&
		waitq_held(&maybe_ca_violating_port->ip_waitq)) {
		        T_FAIL("Detected a lock of an already locked port %p", maybe_ca_violating_port);
		}
	});

	/*
	 * When we copyout the immovable send right without specifying the
	 * permission flag, which should trigger a policy violation
	 */
	kr = ipc_object_copyout(current_space(), port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, &name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_object_copyout");

	/* Then we didn't hit a double port lock (as verified by the mock above) */

	/* (Cleanup) */
	kr = mach_port_deallocate(current_space(), name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");
	ipc_port_release_receive(port);
}
