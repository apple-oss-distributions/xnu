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
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>

#include "test_utils.h"

#define ILP32_POINTER_BYTES (4)

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("jwilkey"));

T_DECL(bingrade_vm_force_arm64_32, "Test forced arm64_32 binary grading policy for VM",
    T_META_RUN_CONCURRENTLY(true),
    T_META_REQUIRES_SYSCTL_EQ("kern.hv_vmm_present", 1),
    T_META_BOOTARGS_SET("force-arm64-32=1"),
    T_META_ENABLED(TARGET_OS_WATCH),
    T_META_TAG_VM_PREFERRED)
{
	pid_t pid;
	int status;

	/* 32-bit process should succeed. */
	{
		char * const argv[] = {"bingrade_helper_arm32", NULL};
		const int rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(rc, "32-bit process should spawn.");
		pid = waitpid(pid, &status, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, NULL);
		T_QUIET; T_ASSERT_TRUE(WIFEXITED(status), NULL);
		T_ASSERT_EQ(WEXITSTATUS(status), ILP32_POINTER_BYTES, "32-bit process should succeed.");
	}

	/* 64-bit process should be rejected. */
	{
		char * const argv[] = {"bingrade_helper_arm64", NULL};
		const int rc = posix_spawn(NULL, argv[0], NULL, NULL, argv, NULL);
		T_ASSERT_EQ(rc, EBADARCH, "64-bit process should be rejected. Got %s", strerror(rc));
	}

	/* Fat binary should select 32-bit process. */
	{
		char * const argv[] = {"bingrade_helper_arm_fat", NULL};
		const int rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(rc, "Fat binary should spawn.");
		pid = waitpid(pid, &status, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, NULL);
		T_QUIET; T_ASSERT_TRUE(WIFEXITED(status), NULL);
		T_ASSERT_EQ(WEXITSTATUS(status), ILP32_POINTER_BYTES,
		    "Fat binary should select 32-bit process.");
	}
}

T_DECL(gestalt_vm_force_arm64_32, "Test forced arm64_32 mode host_info CPU architecture",
    T_META_RUN_CONCURRENTLY(true),
    T_META_REQUIRES_SYSCTL_EQ("kern.hv_vmm_present", 1),
    T_META_BOOTARGS_SET("force-arm64-32=1"),
    T_META_ENABLED(TARGET_OS_WATCH),
    T_META_TAG_VM_PREFERRED)
{
	mach_msg_type_number_t count = HOST_PREFERRED_USER_ARCH_COUNT;
	host_preferred_user_arch_data_t hi;
	kern_return_t kr;

	kr = host_info(mach_host_self(), HOST_PREFERRED_USER_ARCH, (host_info_t)&hi, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_info");
	T_QUIET; T_ASSERT_EQ(count, HOST_PREFERRED_USER_ARCH_COUNT, NULL);

	T_ASSERT_EQ(hi.cpu_type, CPU_TYPE_ARM64_32, NULL);
	T_ASSERT_EQ(hi.cpu_subtype, CPU_SUBTYPE_ARM64_32_V8, NULL);
}
