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
#include <darwintest_mach.h>
#include <darwintest_posix.h>
#include <mach/kern_return.h>
#include <mach/mach.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>
#include <mach/vm_param.h>
#include <sys/sysctl.h>
#include <semaphore.h>
#include <stdlib.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.mach.port_description"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ipc"));

// mach_debug/ipc_info.h
#define IKOT_NAMED_ENTRY   28 /* IPC_OTYPE_NAMED_ENTRY */
#define IKOT_THREAD_RESUME 54 /* IPC_OTYPE_THREAD_RESUME */

T_DECL(vm_named_entry,
    "test mach_port_kobject_description() on a named memory entry")
{
	kern_return_t kr;
	mach_vm_size_t size = vm_page_size;
	mach_port_t named_entry = MACH_PORT_NULL;
	natural_t object_type;
	mach_vm_address_t object_addr;
	kobject_description_t object_description;
	boolean_t dev_kern;
	size_t dev_kern_size = sizeof(dev_kern);
	int ret;

	ret = sysctlbyname("kern.development", &dev_kern, &dev_kern_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl(kern.development)");

	// Create a memory entry
	kr = mach_make_memory_entry_64(mach_task_self(), &size, 0ull,
	    MAP_MEM_NAMED_CREATE | VM_PROT_DEFAULT, &named_entry, MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64()");

	// Describe it
	kr = mach_port_kobject_description(mach_task_self(), named_entry,
	    &object_type, &object_addr, object_description);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_kobject_description()");

	T_LOG("Object Type: %d", object_type);
	T_EXPECT_EQ(object_type, IKOT_NAMED_ENTRY, "object has type IKOT_NAMED_ENTRY");

	T_LOG("Object Address: %llu", object_addr);
	if (dev_kern) {
		T_EXPECT_NE(object_addr, 0ull, "object address is populated on development kernel");
	} else {
		T_EXPECT_EQ(object_addr, 0ull, "object address is zero on release kernel");
	}

	T_LOG("Object Description: %s", object_description);
	T_EXPECT_NE_STR(object_description, "", "object description is populated");

	mach_port_deallocate(mach_task_self(), named_entry);
}

static thread_t
get_thread_for_pid(pid_t pid)
{
	kern_return_t kr;
	task_t task = TASK_NULL;
	thread_act_array_t threads = NULL;
	mach_msg_type_number_t thread_count = 0;

	kr = task_for_pid(mach_task_self(), pid, &task);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");
	T_QUIET; T_ASSERT_NE(task, TASK_NULL, "task_for_pid task");

	kr = task_threads(task, &threads, &thread_count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_threads");
	T_QUIET; T_ASSERT_NE(threads, NULL, "task_threads threads");

	T_QUIET; T_ASSERT_NE(threads[0], THREAD_NULL, "threads[0]");

	return threads[0];
}

T_DECL(thread_resume,
    "test mach_port_kobject_description() on a thread resume port",
    T_META_ASROOT(true))
{
	int ret;
	kern_return_t kr;
	pid_t pid;
	sem_t *sync_sem;
	char sem_name[32];
	thread_t thread;
	thread_suspension_token_t token;
	natural_t object_type;
	mach_vm_address_t object_addr;
	kobject_description_t object_description;

	/* Create a unique semaphore name */
	snprintf(sem_name, sizeof(sem_name), "/thread_resume_desc_%d", getpid());

	/* Create shared semaphore for parent-child synchronization */
	sem_unlink(sem_name); /* Clean up any stale semaphore */
	sync_sem = sem_open(sem_name, O_CREAT | O_EXCL, 0644, 0);
	T_QUIET; T_ASSERT_NE(sync_sem, SEM_FAILED, "sem_open");

	pid = fork();
	T_QUIET; T_ASSERT_NE(pid, -1, "fork");

	if (pid == 0) {
		T_LOG("Child waiting for parent to signal readiness");
		ret = sem_wait(sync_sem);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sem_wait");
		T_LOG("Child received signal from parent, exciting");
		exit(0);
	}

	/* Obtain suspension token */
	thread = get_thread_for_pid(pid);
	kr = thread_suspend2(thread, &token);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_QUIET; T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");

	/* Describe it */
	kr = mach_port_kobject_description(mach_task_self(), token,
	    &object_type, &object_addr, object_description);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_kobject_description()");

	T_LOG("Object Type: %d", object_type);
	T_EXPECT_EQ(object_type, IKOT_THREAD_RESUME, "object has type IKOT_THREAD_RESUME");

	T_LOG("Object Address: %llu", object_addr);
	T_EXPECT_NE(object_addr, 0ull, "object address is populated");

	T_LOG("Object Description: %s", object_description);
	T_EXPECT_EQ(atoi(object_description), pid, "object description == pid");

	/* Resume child */
	kr = thread_resume2(token);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume2");

	/* Signal child to exit */
	ret = sem_post(sync_sem);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sem_post");

	wait(NULL);

	sem_close(sync_sem);
	sem_unlink(sem_name);
}
