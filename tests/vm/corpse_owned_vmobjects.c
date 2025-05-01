/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <excserver.h>
#include <sys/mman.h>
#include <kern/exc_resource.h>
#include <TargetConditionals.h>
#include <mach/vm_page_size.h>
#include <sys/spawn_internal.h>
#include <mach/mach_vm.h>

#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>

/* internal */
#include <spawn_private.h>
#include <sys/kern_memorystatus.h>

#define TEST_MEMLIMIT_MB 10
#define SEM_TIMEOUT dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC)
#define OWNED_VMOBJECTS_SYSCTL "vm.get_owned_vmobjects"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.memorystatus"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

/* Globals */
static dispatch_semaphore_t sync_sema;
static pid_t child_pid;
static bool caught_crash = false, caught_corpse = false;
mach_port_t exception_port;

/* Exception  */
kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity_protected(
	mach_port_t exception_port,
	uint64_t thread_id,
	mach_port_t task_id_token,
	exception_type_t exception,
	mach_exception_data_t codes,
	mach_msg_type_number_t codeCnt,
	int * flavor,
	thread_state_t old_state,
	mach_msg_type_number_t old_state_count,
	thread_state_t new_state,
	mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread_id, task_id_token, exception, codes, codeCnt, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_identity_protected(
	mach_port_t               exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     codes,
	mach_msg_type_number_t    codeCnt)
{
#pragma unused(exception_port, thread_id, task_id_token, exception, codes, codeCnt)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

void
verify_owned_vmobjects(task_t task)
{
	int ret;
	size_t owned_vmobjects_len;

	ret = sysctlbyname(OWNED_VMOBJECTS_SYSCTL, NULL, &owned_vmobjects_len, &task, sizeof(task));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl " OWNED_VMOBJECTS_SYSCTL);
	T_EXPECT_GT((int) owned_vmobjects_len, 0, "owned vmobjects list is populated on %s", (task == mach_task_self()) ? "self" : "corpse");
}

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count)
{
#pragma unused(thread, task, code, code_count)
	T_QUIET; T_EXPECT_TRUE((exception == EXC_CRASH) || (exception == EXC_CORPSE_NOTIFY), "catch_mach_exception_raise() catches EXC_CRASH or EXC_CORPSE_NOTIFY");
	if (exception == EXC_CRASH) {
		caught_crash = true;
		return KERN_SUCCESS;
	} else if (exception == EXC_CORPSE_NOTIFY) {
		caught_corpse = true;
		verify_owned_vmobjects(task);
		dispatch_semaphore_signal(sync_sema);
		return KERN_SUCCESS;
	}
	return KERN_NOT_SUPPORTED;
}

/*
 * Background process that will allocate enough memory to push
 * itself over the threshold, hopefully triggering EXC_RESOURCE.
 */
T_HELPER_DECL(i_eat_memory_for_breakfast, "") {
	int ret, j, num_pages = 0;
	unsigned char *buf;

	if (argc == 1) {
		num_pages = atoi(argv[0]);
	} else {
		T_FAIL("No arguments passed to memory eater");
	}

	/* Allocate a purgeable buffer that will show up in owned vmobjects */
	mach_vm_address_t addr = 0;
	ret = mach_vm_allocate(mach_task_self(), &addr, vm_page_size, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "allocate purgeable buffer");
	T_QUIET; T_ASSERT_NE((int) addr, 0, "purgeable buffer not null");
	verify_owned_vmobjects(mach_task_self());

	/* Allocate and touch all our pages */
	T_LOG("Allocating %d pages...", num_pages);
	buf = mmap(NULL, vm_page_size * num_pages, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(buf, "mmap");
	for (j = 0; j < num_pages; j++) {
		((volatile unsigned char *)buf)[j * vm_page_size] = 1;
	}

	exit(0);
}

static void
kill_child(void)
{
	int ret = kill(child_pid, SIGKILL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kill");
}

static pid_t
launch_child(int num_pages)
{
	extern char **environ;
	int ret;
	char testpath[PATH_MAX];
	posix_spawnattr_t spawn_attrs;

	uint32_t testpath_buf_size = PATH_MAX;
	char num_pages_str[32] = {0};
	char *argv[5] = {testpath, "-n", "i_eat_memory_for_breakfast", num_pages_str, NULL};

	T_LOG("Spawning child process...");

	/* Fork so we can keep the exception port. */
	if ((child_pid = fork()) == 0) {
		ret = posix_spawnattr_init(&spawn_attrs);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");
		ret = posix_spawnattr_setjetsam_ext(&spawn_attrs, POSIX_SPAWN_JETSAM_MEMLIMIT_FATAL, JETSAM_PRIORITY_FOREGROUND, TEST_MEMLIMIT_MB, TEST_MEMLIMIT_MB);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setjetsam_ext");
		ret = posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_SETEXEC);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setflags");
		ret = snprintf(num_pages_str, sizeof(num_pages_str), "%d", num_pages);
		T_QUIET; T_ASSERT_LE((size_t) ret, sizeof(num_pages_str), "Don't allocate too many pages.");
		ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
		T_QUIET; T_ASSERT_EQ(ret, 0, "_NSGetExecutablePath");
		ret = posix_spawn(&child_pid, argv[0], NULL, &spawn_attrs, argv, environ);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	}

	T_ATEND(kill_child);

	return child_pid;
}

void*
exc_thread(void *arg)
{
#pragma unused(arg)
	kern_return_t kr;

	while (1) {
		kr = mach_msg_server(mach_exc_server, MACH_MSG_SIZE_RELIABLE, exception_port, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg_server");
	}
}

T_DECL(corpse_owned_vmobjects, "vm.get_owned_vmobjects sysctl on corpses",
    T_META_ASROOT(true),
    T_META_TAG_VM_PREFERRED
    )
{
	int ret;
	pthread_t handle_thread;
	task_t task;

	T_SETUPBEGIN;

	sync_sema = dispatch_semaphore_create(0);

	task = mach_task_self();
	T_QUIET; T_ASSERT_NE(task, MACH_PORT_NULL, "mach_task_self");

	/* Allocate a port for receiving EXC_CRASH and EXC_CORPSE_NOTIFY */
	ret = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exception_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "mach_port_allocate");
	ret = mach_port_insert_right(task, exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "mach_port_insert_right");
	ret = task_set_exception_ports(task, EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY, exception_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "task_set_exception_ports");

	T_SETUPEND;

	/* Spawn exception handling thread */
	ret = pthread_create(&handle_thread, NULL, exc_thread, 0);

	/* Spawn child to eat memory and trigger EXC_RESOURCE */
	launch_child((TEST_MEMLIMIT_MB * (1 << 20)) / vm_page_size);

	/* We should receive an exception */
	dispatch_semaphore_wait(sync_sema, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC));
	T_QUIET; T_EXPECT_EQ(caught_crash, true, "Caught EXC_CRASH");
	T_QUIET; T_EXPECT_EQ(caught_corpse, true, "Caught EXC_CORPSE_NOTIFY");
}
