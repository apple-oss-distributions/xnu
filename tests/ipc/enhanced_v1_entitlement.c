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
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <mach/task.h>

#include "task_security_config.h"

/* IPC space policy constants for readability */
#define IPC_SPACE_POLICY_ENHANCED    0x0002
#define IPC_SPACE_POLICY_ENHANCED_V1 0x0200
#define IPC_SPACE_POLICY_VERSION_MASK 0x0700
#define IPC_SPACE_POLICY_V1_EXPECTED (IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V1)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_TAG_VM_PREFERRED);


T_DECL(test_enhanced_v1_entitlements,
    "entitlement should enable IPC_SPACE_POLICY_ENHANCED_V1 configuration",
    T_META_CHECK_LEAKS(false))
{
	struct task_security_config_info config;
	struct task_ipc_space_policy_info space_info;
	mach_msg_type_number_t count;
	kern_return_t kr;

	count = TASK_SECURITY_CONFIG_INFO_COUNT;
	kr = task_info(mach_task_self(), TASK_SECURITY_CONFIG_INFO, (task_info_t)&config, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SECURITY_CONFIG_INFO)");

	struct task_security_config *conf = (struct task_security_config*)&config;
	uint8_t vers = conf->platform_restrictions_version;
	T_MAYFAIL_WITH_RADAR(161527277);
	T_EXPECT_EQ_UINT(vers, 1, "Platform restrictions version should be 1");

	count = TASK_IPC_SPACE_POLICY_INFO_COUNT;
	kr = task_info(mach_task_self(), TASK_IPC_SPACE_POLICY_INFO, (task_info_t)&space_info, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_IPC_SPACE_POLICY_INFO)");
	T_ASSERT_EQ_UINT(count, 1, "ipc space should return 1 value");

	/*
	 * Check that the enhanced version is exactly V1
	 * (IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V1)
	 */
	T_MAYFAIL_WITH_RADAR(161527277);
	T_EXPECT_EQ_UINT(space_info.space_policy & IPC_SPACE_POLICY_VERSION_MASK, IPC_SPACE_POLICY_V1_EXPECTED,
	    "enhanced policy should be exactly V1");
}
