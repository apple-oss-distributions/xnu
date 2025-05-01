/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/vm_map.h>
#include <machine/cpu_capabilities.h>

#include <sys/commpage.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true));


static const size_t kNumPages_4willneed = 16;
static vm_address_t vmaddr_4willneed = 0;
static void *fbaddr_4willneed = NULL;
static int fd_4willneed;

static void
willneed_tear_down(void)
{
	int ret;
	kern_return_t kr;
	vm_size_t vmsize_4willneed = PAGE_SIZE * kNumPages_4willneed;
	kr = vm_deallocate(mach_task_self(), vmaddr_4willneed, vmsize_4willneed);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate()");
	vmaddr_4willneed = 0;
	ret = munmap(fbaddr_4willneed, vmsize_4willneed);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");
	ret = close(fd_4willneed);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "close()");
}

T_DECL(madv_willneed, "test madvise(MADV_WILLNEED)")
{
	char tmpf[PATH_MAX] = {0};
	kern_return_t kr;
	int ret;
	vm_size_t vmsize_4willneed = PAGE_SIZE * kNumPages_4willneed;
	uint8_t pattern[4] = {0xFEu, 0xDCu, 0xBAu, 0x98u};
	char buf[vmsize_4willneed];
	char vec[kNumPages_4willneed] = {0};

	T_SETUPBEGIN;

	T_LOG("Allocating %lu anonymous pages", kNumPages_4willneed);
	kr = vm_allocate(mach_task_self(),
	    &vmaddr_4willneed,
	    vmsize_4willneed,
	    (VM_FLAGS_ANYWHERE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, "/willneed.txt", PATH_MAX);
	T_QUIET; T_ASSERT_LT(strlen(tmpf), (unsigned long)PATH_MAX, "path exceeds PATH_MAX");

	T_LOG("Opening file '%s'", tmpf);
	fd_4willneed = open(tmpf, (O_RDWR | O_CREAT));
	ret = fcntl(fd_4willneed, F_NOCACHE, TRUE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "fcntl(F_NOCACHE)");

	memset_pattern4(buf, pattern, vmsize_4willneed);
	write(fd_4willneed, buf, vmsize_4willneed);
	fsync(fd_4willneed);

	ret = fcntl(fd_4willneed, F_NOCACHE, FALSE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "fcntl(F_NOCACHE)");

	fbaddr_4willneed = mmap(NULL, vmsize_4willneed, PROT_READ, (MAP_FILE | MAP_SHARED), fd_4willneed, 0);

	T_ATEND(willneed_tear_down);

	T_SETUPEND;

	T_LOG("Checking anonymous residency (pre-madvise)");
	ret = mincore((void *)vmaddr_4willneed, vmsize_4willneed, vec);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	for (size_t i = 0; i < kNumPages_4willneed; i++) {
		T_QUIET; T_ASSERT_BITS_SET(vec[i], MINCORE_ANONYMOUS,
		    "pre-madvise pages should be anonymous");
		T_QUIET; T_ASSERT_BITS_NOTSET(vec[i], MINCORE_INCORE,
		    "pre-madvise pages must not be resident");
		T_QUIET; T_ASSERT_BITS_NOTSET(vec[i], MINCORE_REFERENCED,
		    "pre-madvise pages must not be referenced");
	}

	T_LOG("Advising anonymous memory...");
	ret = madvise((void *)vmaddr_4willneed, vmsize_4willneed, MADV_WILLNEED);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "madvise(MADV_WILLNEED)");

	T_LOG("Checking anonymous residency");
	ret = mincore((void *)vmaddr_4willneed, vmsize_4willneed, vec);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");

	for (size_t i = 0; i < kNumPages_4willneed; i++) {
		T_EXPECT_BITS_SET(vec[i], MINCORE_INCORE,
		    "madvised page %lu should be resident", i);
	}

	T_LOG("Checking file-backed residency (pre-madvise)");
	ret = mincore((void *)fbaddr_4willneed, vmsize_4willneed, vec);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	for (size_t i = 0; i < kNumPages_4willneed; i++) {
		T_QUIET; T_ASSERT_BITS_NOTSET(vec[i], MINCORE_INCORE,
		    "pre-madvise pages must not be resident");
		T_QUIET; T_ASSERT_BITS_NOTSET(vec[i], MINCORE_REFERENCED,
		    "pre-madvise pages must not be referenced");
		T_QUIET; T_ASSERT_BITS_NOTSET(vec[i], MINCORE_MODIFIED,
		    "pre-madvise pages must not be modified");
	}

	T_LOG("Advising file-backed memory...");
	ret = madvise(fbaddr_4willneed, vmsize_4willneed, MADV_WILLNEED);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "madvise(MADV_WILLNEED)");

	T_LOG("Checking file-backed residency (post-madvise)");
	ret = mincore((void *)fbaddr_4willneed, vmsize_4willneed, vec);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");

	for (size_t i = 0; i < kNumPages_4willneed; i++) {
		T_EXPECT_BITS_SET(vec[i], MINCORE_INCORE,
		    "madvised page %lu should be resident", i);
	}
}
