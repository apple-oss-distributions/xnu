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

#pragma once

#include "mocks/mock_dynamic.h"
#include <ipc/ipc_policy.h>
#include <ipc/ipc_space.h>

/* Mock declarations for IPC policy */
T_MOCK_DECLARE(bool, ipc_should_apply_policy, (
	const ipc_space_policy_t current_policy,
	const ipc_space_policy_t requested_level));

T_MOCK_DECLARE(bool, ipc_should_mark_immovable_send, (
	task_t curr_task,
	ipc_port_t port,
	ipc_object_label_t label));

/* Mock declarations for IPC space */
T_MOCK_DECLARE(ipc_space_t, ipc_space_alloc, (void));

/* Mock declarations for IPC security policy violation triage */

T_MOCK_DECLARE(void, ipc_triage_policy_violation_and_expect_continue, (
	ipc_sec_policy_t policy,
	ipc_space_t maybe_space,
	uint32_t maybe_exc_target,
	uint64_t maybe_exc_payload,
	ipc_port_t maybe_ca_violating_port,
	int maybe_ca_aux_data));

/* Mock declarations for MAC hooks */
struct mach_service_port_info;

T_MOCK_DECLARE(void, mac_proc_notify_service_port_derive, (
	struct mach_service_port_info *sp_info));

/* Mock declarations for mach msg filtering */
T_MOCK_DECLARE(bool, mach_msg_filter_at_least, (
	unsigned int version));

/* Mock declarations for ipc_service_port_string_name_is_empty */
T_MOCK_DECLARE(bool, ipc_service_port_string_name_is_empty, (
	struct mach_service_port_info *sp_info));
