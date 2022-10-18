/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
#include <TargetConditionals.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

T_DECL(wire_copy_share,
    "test VM object wired, copied and shared")
{
	kern_return_t kr;
	mach_vm_address_t vmaddr1, vmaddr2, vmaddr3;
	mach_vm_size_t vmsize;
	char *cp;
	int i;
	vm_prot_t cur_prot, max_prot;
	int ret;

	/* allocate anonymous memory */
	vmaddr1 = 0;
	vmsize = 32 * PAGE_SIZE;
	kr = mach_vm_allocate(
		mach_task_self(),
		&vmaddr1,
		vmsize,
		VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	/* populate it */
	cp = (char *)(uintptr_t)vmaddr1;
	for (i = 0; i < vmsize; i += PAGE_SIZE) {
		cp[i] = i;
	}

	/* wire one page */
	ret = mlock(cp, PAGE_SIZE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mlock()");

	/* create a range to receive a copy */
	vmaddr2 = 0;
	kr = mach_vm_allocate(
		mach_task_self(),
		&vmaddr2,
		vmsize - PAGE_SIZE,
		VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate() for copy");

	/* copy the rest of the original object */
	kr = mach_vm_copy(
		mach_task_self(),
		vmaddr1 + PAGE_SIZE,
		vmsize - PAGE_SIZE,
		vmaddr2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_copy()");

	/* share the whole thing */
	vmaddr3 = 0;
	kr = mach_vm_remap(
		mach_task_self(),
		&vmaddr3,
		vmsize,
		0, /* mask */
		VM_FLAGS_ANYWHERE,
		mach_task_self(),
		vmaddr1,
		FALSE, /* copy */
		&cur_prot,
		&max_prot,
		VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
}
