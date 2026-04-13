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
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/mach_error.h>
#include <sys/code_signing.h>

#include "task_security_config.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"));

/*
 * This test verifies that a process WITHOUT hardened runtime does NOT get
 * IPC_SPACE_POLICY_ENHANCED_V0 in its IPC policy.
 *
 * This binary is signed with regular code signing (no --options runtime).
 */

static void
check_no_enhanced_policy(void)
{
	struct task_ipc_space_policy_info space_info;
	mach_msg_type_number_t count = TASK_IPC_SPACE_POLICY_INFO_COUNT;
	kern_return_t kr;

	/* Get IPC space policy */
	kr = task_info(mach_task_self(), TASK_IPC_SPACE_POLICY_INFO,
	    (task_info_t)&space_info, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_IPC_SPACE_POLICY_INFO)");
	T_ASSERT_EQ_UINT(count, 1, "ipc space should return 1 value");

	/* Extract policy flags */
	uint32_t policy = space_info.space_policy;
	bool has_enhanced = (policy & IPC_SPACE_POLICY_ENHANCED) != 0;
	bool has_v0 = (policy & IPC_SPACE_POLICY_ENHANCED_VERSION_MASK) == IPC_SPACE_POLICY_ENHANCED_V0;
	bool has_v1 = (policy & IPC_SPACE_POLICY_ENHANCED_VERSION_MASK) == IPC_SPACE_POLICY_ENHANCED_V1;
	bool has_v2 = (policy & IPC_SPACE_POLICY_ENHANCED_VERSION_MASK) == IPC_SPACE_POLICY_ENHANCED_V3;

	T_LOG("IPC space policy: 0x%x", policy);

	/* This process should NOT have any enhanced IPC policies */
	T_MAYFAIL; T_EXPECT_FALSE(has_enhanced, "Non-hardened process should NOT have IPC_SPACE_POLICY_ENHANCED");
	T_MAYFAIL; T_EXPECT_FALSE(has_v0, "Non-hardened process should NOT have IPC_SPACE_POLICY_ENHANCED_V0");
	T_MAYFAIL; T_EXPECT_FALSE(has_v1, "Non-hardened process should NOT have IPC_SPACE_POLICY_ENHANCED_V1");
	T_MAYFAIL; T_EXPECT_FALSE(has_v2, "Non-hardened process should NOT have IPC_SPACE_POLICY_ENHANCED_V2");
}

T_DECL(non_hardened_runtime_ipc_policy,
    "Test that non-hardened runtime process does NOT get IPC_SPACE_POLICY_ENHANCED_V0")
{
	check_no_enhanced_policy();
}
