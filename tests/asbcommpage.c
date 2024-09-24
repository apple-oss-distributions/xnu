/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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
#include <pthread.h>
#include <machine/cpu_capabilities.h>
#include <sys/commpage.h>
#include <sys/sysctl.h>
#include <mach/vm_param.h>
#include <stdint.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("jeffrey_crowell"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(asb_comm_page_sanity,
    "Test that asb comm page values are sane.")
{
	int rv;
	uint64_t max_userspace_address = MACH_VM_MAX_ADDRESS;
	uint64_t target_address = COMM_PAGE_READ(uint64_t, ASB_TARGET_ADDRESS);

	uint64_t sysctl_min_kernel_address = 0;
	size_t min_kernel_address_size = sizeof(sysctl_min_kernel_address);
	rv = sysctlbyname("vm.vm_min_kernel_address", &sysctl_min_kernel_address, &min_kernel_address_size, NULL, 0);
	uint64_t kern_target_address = COMM_PAGE_READ(uint64_t, ASB_TARGET_KERN_ADDRESS);

	T_QUIET; T_ASSERT_GT(target_address, max_userspace_address, "check that asb target addresses are as expected");
	T_QUIET; T_ASSERT_LT(kern_target_address, sysctl_min_kernel_address, "check that asb target kernel addresses are as expected");
}
