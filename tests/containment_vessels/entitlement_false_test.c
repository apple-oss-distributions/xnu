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

#include "task_security_config.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_TAG_VM_PREFERRED);

T_DECL(contained_process_entitlement_false,
    "Ensure a process with the containment vessel entitlement explicitly disabled is marked appropriately",
    T_META_CHECK_LEAKS(false))
{
	/* Given this binary is signed with com.apple.security.hardened-process.containment: false */

	/* When we query our security state */
	struct task_security_config_info config;
	mach_msg_type_number_t count = TASK_SECURITY_CONFIG_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_SECURITY_CONFIG_INFO, (task_info_t)&config, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SECURITY_CONFIG_INFO)");
	struct task_security_config* conf = (struct task_security_config*)&config;

	/* Then we're not marked as a containment vessel */
	T_EXPECT_FALSE(conf->ipc_containment_vessel, "Expect to not be marked as an IPC containment vessel");

	/* And the other security flags are disabled, because we're not eligible for any of those */
	T_EXPECT_FALSE(conf->reserved, "reserved bit should not be set");
	T_EXPECT_FALSE(conf->hardened_heap, "hardened heap bit should not be set");
}
