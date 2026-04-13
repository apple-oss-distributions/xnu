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

#include "kern/host.h"
#include <darwintest.h>
#include <mach/mach_port.h>
#include <kern/task.h>
#include <mocks/dt_proxy.h>
#include <mocks/osfmk/mock_ipc.h>
#include <mach/mach_traps.h>

#include "ipc/utils/ipc_policy_helpers.h"
#include "ipc/utils/mach_port_construct_helpers.h"

#define UT_MODULE osfmk

/*
 * A test for regression rdar://168110786
 *
 * Ensure we only call out to ES and sandbox once per xpc connection port pair.
 * We only monitor the number of calls to mac_proc_notify_service_port_derive
 * in this test because unit test service ports don't have a sblabel due to
 * issues with copyin. This should be sufficient as we gate the callouts to
 * both ES and sandbox behind the same `is_forward_connection_channel` check.
 */

/* libxpc use `self` as context, here we use a constant */
#define MPO_CONTEXT 0xbeef

T_MOCK_CALL_QUEUE(mac_proc_notify_service_port_derive_call, {});

T_MOCK_SET_PERM_FUNC(void,
    mac_proc_notify_service_port_derive,
    (struct mach_service_port_info *sp_info))
{
	(void)dequeue_mac_proc_notify_service_port_derive_call();
}

/* Helper to destroy connection ports with guard */
static void
destroy_connection_port(
	mach_port_t __unused port,
	mach_port_name_t port_name,
	uint16_t srdelta)
{
	kern_return_t kr;

	/* Unguard the port first */
	kr = mach_port_unguard(current_space(), port_name, MPO_CONTEXT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_unguard");

	/* Deallocate send right if it exists */
	if (srdelta > 0) {
		kr = mach_port_deallocate(current_space(), port_name);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate send right");
	}

	/* Now we can remove the receive right */
	kr = mach_port_mod_refs(current_space(), port_name, MACH_PORT_RIGHT_RECEIVE, -1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_mod_refs receive right");
}

/* Mimic _xpc_connection_derive_connection_port */
static mach_port_t
connection_derive_connection_port(
	uint32_t mpo_flags,
	mach_port_name_t service_port_name,
	mach_port_name_t *out_port_name)
{
	kern_return_t kr;
	mach_port_name_t port_name;
	mach_port_options_t opts = {
		.flags = mpo_flags | MPO_CONNECTION_PORT,
		.service_port_name = service_port_name,
	};

	kr = mach_port_construct(current_space(), &opts, MPO_CONTEXT, &port_name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "connection_derive_connection_port");

	*out_port_name = port_name;

	return ipc_translate_and_unlock_port_name(port_name);
}

/* Mimic _xpc_connection_init_send_port for forward channel */
static mach_port_t
connection_init_send_port(mach_port_name_t service_port_name, mach_port_name_t *out_port_name)
{
	uint32_t mpo_flags = MPO_CONTEXT_AS_GUARD
	    | MPO_STRICT
	    | MPO_INSERT_SEND_RIGHT
	    | MPO_QLIMIT
	    | MPO_TEMPOWNER
	    | MPO_IMPORTANCE_RECEIVER
	    | MPO_ENFORCE_REPLY_PORT_SEMANTICS;
	return connection_derive_connection_port(mpo_flags, service_port_name, out_port_name);
}

/* Mimic _xpc_connection_init_recv_port for backward channel */
static mach_port_t
connection_init_recv_port(mach_port_name_t service_port_name, mach_port_name_t *out_port_name)
{
	uint32_t mpo_flags = MPO_CONTEXT_AS_GUARD
	    | MPO_STRICT
	    | MPO_QLIMIT
	    | MPO_IMPORTANCE_RECEIVER
	    | MPO_ENFORCE_REPLY_PORT_SEMANTICS
	    | MPO_IMMOVABLE_RECEIVE;
	return connection_derive_connection_port(mpo_flags, service_port_name, out_port_name);
}

T_DECL(xpc_connection_pair_only_call_mac_hook_once,
    "Ensure constructing a libxpc connection port pair only call into mac_proc_notify_service_port_derive hook once")
{
	mach_port_t send_port, recv_port, service_port;
	mach_port_name_t send_name, recv_name, service_port_name;

	enqueue_mac_proc_notify_service_port_derive_call((mac_proc_notify_service_port_derive_call){});

	/* Create a service port that the connection ports will derive from */
	service_port = create_strict_service_port(&service_port_name);
	T_QUIET; T_ASSERT_PORT_VALID(service_port, "service_port invalid");

	/* Create connection send recv port pair */
	send_port = connection_init_send_port(service_port_name, &send_name);
	T_QUIET; T_ASSERT_PORT_VALID(send_port, "send_port invalid");

	recv_port = connection_init_recv_port(service_port_name, &recv_name);
	T_QUIET; T_ASSERT_PORT_VALID(recv_port, "recv_port invalid");

	/* Check that we only called the mac hook once */
	assert_empty_mac_proc_notify_service_port_derive_call();
	T_LOG("creating connection pair only called into mac hook once");

	/* Clean up*/
	destroy_connection_port(send_port, send_name, -1);

	destroy_connection_port(recv_port, recv_name, 0);

	destroy_send_recv_port(service_port, service_port_name);
}
