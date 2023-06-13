/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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


#include <unistd.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <drop_priv.h>
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(task_name_for_pid_entitlement, "Test that task_name_for_pid suceeds with entitlement",
    T_META_ASROOT(false),
    T_META_CHECK_LEAKS(false))
{
	kern_return_t kr;
	mach_port_t tname;
	pid_t pid;
	T_SETUPBEGIN;
	T_ASSERT_NE(getuid(), 0, "test should not be root uid");
	T_SETUPEND;
	// launchd has root uid/gid so we know that we must be hitting the entitlement check here.
	kr = task_name_for_pid(mach_task_self(), 1, &tname);
	T_ASSERT_MACH_SUCCESS(kr, "task_name_for_pid should succeed on launchd (pid 1)");
	pid_for_task(tname, &pid);
	T_ASSERT_EQ(pid, 1, "pid_for_task should return pid for launchd (pid 1)");

	mach_port_deallocate(mach_task_self(), tname);
}
