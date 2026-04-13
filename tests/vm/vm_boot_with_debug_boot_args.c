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

/*
 * vm_boot_with_debug_boot_args.c
 * Test booting with vm's debugging boot-args set.
 */

#include <stdlib.h>
#include <os/bsd.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);

T_DECL(vm_boot_with_debug_boot_args,
    "boot with every vm debugging check enabled via boot-arg",
    T_META_BOOTARGS_SET("vm_debug=1"),
    T_META_TAG_VM_PREFERRED /* virtual machine reboots faster */ )
{
	char *bootargs;
	size_t bootargs_len;
	errno_t err;
	int64_t vm_debug;
	bool found;

	err = sysctlbyname_get_data_np("kern.bootargs", (void**)&bootargs, &bootargs_len);
	T_QUIET; T_ASSERT_POSIX_ZERO(err, "sysctlbyname_get_data_np(kern.bootargs)");

	found = os_parse_boot_arg_int("vm_debug", &vm_debug);
	T_ASSERT_TRUE(found, "boot-arg vm_debug must be set to an int "
	    "(boot-args='%.*s')", (int)bootargs_len, bootargs);
	T_ASSERT_EQ(vm_debug, (int64_t)1, "boot-arg vm_debug=1 "
	    "(boot-args='%.*s')", (int)bootargs_len, bootargs);

	free(bootargs);

	T_PASS("boot with boot-arg vm_debug=1");
}
