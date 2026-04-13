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

#include "mach/kern_return.h"
#include "mocks/mock_dynamic.h"
#include "mocks/dt_proxy.h"
#include "unit_test_utils.h"
#include "mocks/osfmk/mock_ipc.h"

#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_space.h>
#include <kern/task.h>
#include <kern/waitq.h>
#include <kern/mach_filter.h>

/* Mock implementations for IPC entry */
T_MOCK_F(void,
ipc_entry_modified, (
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_entry_t             entry), (space, name, entry))
{
	return;
}

// T_MOCK_F(kern_return_t,
// ipc_entry_grow_table, (
//      ipc_space_t             space,
//      ipc_table_elems_t       target_count), (space, target_count))
// {
//      return KERN_NO_SPACE;
// }

/* Mock implementations for IPC object */
T_MOCK_F(bool,
ipc_object_lock_allow_invalid,
(ipc_object_t orig_io), (orig_io))
{
	struct waitq *wq = io_waitq(orig_io);
	waitq_lock(wq);
	return true;
}

/* Mock implementations for IPC policy */
T_MOCK(bool,
ipc_should_apply_policy, (
	const ipc_space_policy_t current_policy,
	const ipc_space_policy_t requested_level), (current_policy, requested_level));

T_MOCK(bool,
ipc_should_mark_immovable_send, (
	task_t curr_task,
	ipc_port_t port,
	ipc_object_label_t label), (curr_task, port, label));

/* Mock implementations for IPC space */
T_MOCK_F(ipc_space_t,
ipc_space_alloc, (void), ())
{
	/*!
	 * TODO: rdar://164107888
	 * need to initialize the ipc_space_zone in order to delete this mock
	 */
	ipc_space_t space = calloc(1, sizeof(struct ipc_space));
	PT_ASSERT_NOTNULL(space, "ipc_space calloc");

	lck_ticket_init(&space->is_lock, &ipc_lck_grp);

	return space;
}

/* Mock implementations for IPC security policy violation triage */
T_MOCK_F(void,
ipc_triage_policy_violation_and_expect_continue, (
	ipc_sec_policy_t policy,
	ipc_space_t maybe_space,
	uint32_t maybe_exc_target,
	uint64_t maybe_exc_payload,
	ipc_port_t maybe_ca_violating_port,
	int maybe_ca_aux_data), (
	policy,
	maybe_space,
	maybe_exc_target,
	maybe_exc_payload,
	maybe_ca_violating_port,
	maybe_ca_aux_data)) {
	/*
	 * This mock serves to ensure that this gets called as the entry-point for handling
	 * a detected policy violation.
	 * Generally, a test consuming this mock will ensure it's called with the specific
	 * violation the test expects.
	 */
};

/* Mock implementations for MAC hooks */
T_MOCK_F(void,
mac_proc_notify_service_port_derive, (
	struct mach_service_port_info *sp_info), (sp_info))
{
	/*
	 * This mock serves as a default implementation for the MAC hook.
	 * Tests can override this using T_MOCK_SET_PERM_FUNC to verify
	 * when and how this hook is called.
	 */
}

/* Mock for mach_msg_filter_at_least - always return true in unit tests */
T_MOCK_F(bool,
mach_msg_filter_at_least, (
	unsigned int version), (version))
{
	/* Always return true to enable filter-related code paths */
	return true;
}

/* Mock for ipc_service_port_string_name_is_empty - always return false in unit tests */
T_MOCK_F(bool,
ipc_service_port_string_name_is_empty, (
	struct mach_service_port_info *sp_info), (sp_info))
{
	/* Always return false so we don't skip mac hook calls */
	return false;
}
