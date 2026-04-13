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

#if __arm64__
#include <arm_acle.h>
#include <darwintest.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <sys/mman.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(
	XNU_T_META_SOC_SPECIFIC
	);

T_DECL(mte_alloc_from_unentitled,
    "Attempt to allocate tagged memory from MTE-disabled process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	vm_address_t address = 0;
	vm_size_t alloc_size = 16 * 1024;

	kern_return_t kr = vm_allocate(mach_task_self(), &address, alloc_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_EXPECT_MACH_ERROR_(kr, KERN_INVALID_ARGUMENT, "allocate tagged memory in unentitled process");

	if (kr == KERN_SUCCESS) {
		// cleanup if the test failed
		kr = vm_deallocate(mach_task_self(), address, alloc_size);
		T_ASSERT_MACH_SUCCESS(kr, "test cleanup");
	}
}

/* Here, "debugger" means an MTE-disabled process with access to tagged memory */
T_DECL(mte_debugger_untagged_copyio,
    "Test that debugger processes can do copyio operations without tag checks",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    /* Allow ourselves to act as a debugger */
    T_META_BOOTARGS_SET("amfi_unrestrict_task_for_pid=1"),
    T_META_ASROOT(true))
{
	__block kern_return_t kr;
	/* This is the debugger process (MTE disabled) */

	T_SETUPBEGIN;
	char *shm_name = "mte_debugger_untagged_copyio";
	const mach_vm_size_t ALLOC_SIZE = PAGE_SIZE;

	/* create shared memory descriptor for sending address */
	shm_unlink(shm_name);
	int fd = shm_open(shm_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_ASSERT_POSIX_SUCCESS(fd, "shm_open");

	int ret = ftruncate(fd, sizeof(vm_address_t));
	T_ASSERT_POSIX_SUCCESS(ret, "ftruncate");

	volatile vm_address_t *shm = mmap(NULL, sizeof(vm_address_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	T_ASSERT_NE(shm, MAP_FAILED, "mmap");
	/* tell the process being "debugged" how much memory to allocate */
	*shm = ALLOC_SIZE;
	T_SETUPEND;

	/* Launch the to-be-debugged process, which has the MTE code-signing entitlement */
	char *new_argv[] = { "arm_mte_debugger_helper", shm_name, NULL };
	pid_t child_pid;
	ret = posix_spawn(&child_pid, new_argv[0], NULL, NULL, new_argv, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	T_ASSERT_NE(child_pid, 0, "posix_spawn child_pid");

	/* Wait for the process to send the allocated address over */
	while (*shm == ALLOC_SIZE) {
		/* check that the process is still alive */
		ret = kill(child_pid, 0); // note: signal 0 does not affect the child

		/* fails with errno = ESRCH if the child process is dead */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kill");
	}

	vm_address_t child_addr = *shm;
	T_ASSERT_EQ(child_addr & MTE_TAG_MASK, 0ULL, "received untagged pointer");

	mach_port_t child_task;
	kr = task_for_pid(mach_task_self(), child_pid, &child_task);
	T_ASSERT_MACH_SUCCESS(kr, "fetch task_for_pid(child)");

	vm_address_t dest_addr = 0;
	vm_prot_t cur_prot = VM_PROT_DEFAULT, max_prot = VM_PROT_DEFAULT;
	/* remap the process' tagged memory into the debugger's address space */
	kr = vm_remap(mach_task_self(), &dest_addr, ALLOC_SIZE,
	    /* mask = */ 0, VM_FLAGS_ANYWHERE, child_task, child_addr,
	    /* copy = */ false, &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "remapped process' tagged memory into debugger");

	/* create a source region for copyio */
	vm_address_t src_addr = 0;
	kr = vm_allocate(mach_task_self(), &src_addr, ALLOC_SIZE, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate source region");
	memset((void*) src_addr, 'A', ALLOC_SIZE);

	/* make sure the debugger can copyio the tagged memory with its untagged pointer */
	expect_normal_exit(^{
		kr = mach_vm_copy(mach_task_self(), src_addr, ALLOC_SIZE, dest_addr);
		T_EXPECT_MACH_SUCCESS(kr, "copyio using untagged pointer from debugger");
	}, "copyio tagged memory from debugger");

	/* cleanup */
	T_SETUPBEGIN;
	ret = close(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "close");
	ret = shm_unlink(shm_name);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "shm_unlink");
	kr = mach_vm_deallocate(mach_task_self(), dest_addr, ALLOC_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate remapped memory");
	kr = mach_vm_deallocate(mach_task_self(), src_addr, ALLOC_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate source region");
	kr = mach_port_deallocate(mach_task_self(), child_task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate child task port");
	T_SETUPEND;
}
#endif /* __arm64__ */
