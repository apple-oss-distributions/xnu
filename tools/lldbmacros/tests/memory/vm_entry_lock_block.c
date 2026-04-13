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

#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <pthread.h>

// This utility is meant for testing the different scenarios of lldb macro 'showvmentryowner'
// it uses debug sysctls to lock a range of a map, then block so that the state is visible in lldb.
//
// 1. build it with:
//      # clang vm_entry_lock_block.c -o vm_entry_lock_block -g
// 2. scp it to the machine to be tested
// 3. connect to the machine with lldb gdb-remote
// 4. run the utility:
//      # ./vm_entry_lock_block n-shared-1-exclusive-n-shared atomic
//      allocated: 0x104fb8000  pid=1768  main-tid=807b
//      ...
// 5. in lldb:
// (lldb) showpid <pid-from-output>
// (lldb) vm_page_lookup_in_map <vm-map-from-showpid> <address-from-output>
// (lldb) showvmentryowner <entry-from-vm_page_lookup_in_map>


// definitions for the sysctl vm.dbg_range_lock_block protocol
// from vm_map.c
__options_decl(dbg_vm_entry_lock_flags, uint32_t, {
	DBG_LCK_FLAG_EXCLUSIVE = 0x1,
	DBG_LCK_FLAG_SHARED = 0x2,
	DBG_LCK_FLAG_CALL_TYPE_MASK = 0x3,
	DBG_LCK_FLAG_ATOMIC = 0x4,
	DBG_LCK_FLAG_STREAM = 0x8
});

// from vm_unix.c
typedef struct {
	mach_vm_address_t address;
	uint64_t          size;
	pid_t             pid;
	uint32_t          flags;
} dbg_lock_range_args;

pid_t pid = 0;
vm_address_t address = 0;
vm_size_t sz = 0;
pthread_t wake_thread;

uint64_t
get_self_tid(void)
{
	uint64_t tid;
	pthread_threadid_np(NULL, &tid);
	return tid;
}

void
allocate_mem()
{
	address = 0;
	sz = PAGE_SIZE * 10;
	kern_return_t kr;
	kr = vm_allocate(mach_task_self(), &address, sz, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		printf("Failed vm_allocate: %d\n", kr);
		exit(1);
	}
	pid = getpid();
	printf("allocated: %p  pid=%d  main-tid=%llx\n", (void *)address, pid, get_self_tid());
}


void *
wake_thread_func(void *arg)
{
	printf("wakeup thread %llx, press Enter to continue...\n", get_self_tid());
	getchar();
	printf("waking up ...\n");
	int ret = sysctlbyname("vm.dbg_range_lock_wakeup", NULL, NULL, &pid, sizeof(pid));
	if (ret != 0) {
		printf("Failed sysctl vm.dbg_range_lock_wakeup: %s\n", strerror(errno));
	}
	return NULL;
}

void
start_wake_thread()
{
	int result = pthread_create(&wake_thread, NULL, wake_thread_func, NULL);
	if (result != 0) {
		printf("Error creating wake-thread\n");
		exit(1);
	}
}

void *
lock_block_thread(void *arg)
{
	uintptr_t flags = (uintptr_t)arg;
	dbg_lock_range_args args = { .address = address, .size = sz, .pid = pid, .flags = flags };
	printf("blocking thread %llx  flags=%lx ...\n", get_self_tid(), flags);
	int ret = sysctlbyname("vm.dbg_range_lock_block", NULL, NULL, &args, sizeof(args));
	if (ret != 0) {
		printf("Failed sysctl vm.dbg_range_lock_block: %s\n", strerror(errno));
		exit(1);
	}
	printf("unblocked\n");
	return NULL;
}

void
start_block_thread(dbg_vm_entry_lock_flags flags)
{
	pthread_t block_thread;
	int result = pthread_create(&block_thread, NULL, lock_block_thread, (void*)(uintptr_t)flags);
	if (result != 0) {
		printf("Error creating block-thread\n");
		exit(1);
	}
}


int
main(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Usage: %s <scenario> <mode>\n", argv[0]);
		return 1;
	}

	uint32_t flags = 0;
	if (strcmp(argv[2], "atomic") == 0) {
		flags = DBG_LCK_FLAG_ATOMIC;
	} else if (strcmp(argv[2], "stream") == 0) {
		flags = DBG_LCK_FLAG_STREAM;
	} else {
		printf("unknown mode: %s\n", argv[2]);
		return 1;
	}

	allocate_mem();
	start_wake_thread();

	if (strcmp(argv[1], "exclusive") == 0) {
		start_block_thread(DBG_LCK_FLAG_EXCLUSIVE | flags);
	} else if (strcmp(argv[1], "shared") == 0) {
		start_block_thread(DBG_LCK_FLAG_SHARED | flags);
	} else if (strcmp(argv[1], "n-shared") == 0) {
		for (int i = 0; i < 10; ++i) {
			start_block_thread(DBG_LCK_FLAG_SHARED | flags);
		}
	} else if (strcmp(argv[1], "n-shared-1-exclusive") == 0) {
		for (int i = 0; i < 5; ++i) {
			start_block_thread(DBG_LCK_FLAG_SHARED | flags);
		}
		usleep(500000);
		start_block_thread(DBG_LCK_FLAG_EXCLUSIVE | flags);
	} else if (strcmp(argv[1], "1-exclusive-n-shared") == 0) {
		start_block_thread(DBG_LCK_FLAG_EXCLUSIVE | flags);
		usleep(500000);
		for (int i = 0; i < 5; ++i) {
			start_block_thread(DBG_LCK_FLAG_SHARED | flags);
		}
	} else if (strcmp(argv[1], "n-shared-1-exclusive-n-shared") == 0) {
		for (int i = 0; i < 5; ++i) {
			start_block_thread(DBG_LCK_FLAG_SHARED | flags);
		}
		usleep(1000000);
		start_block_thread(DBG_LCK_FLAG_EXCLUSIVE | flags);
		usleep(1000000);
		for (int i = 0; i < 5; ++i) {
			start_block_thread(DBG_LCK_FLAG_SHARED | flags);
		}
	} else {
		printf("unknown scenario: %s\n", argv[1]);
		return 1;
	}

	pthread_join(wake_thread, NULL);
	return 0;
}
