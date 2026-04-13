/*
 * Copyright (c) 2021-2025 Apple Inc. All rights reserved.
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
#include <darwintest_utils.h>
#include <TargetConditionals.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

#define FILENAME "test-77350114.data"
#define MAPSIZE (2*1024*1024)

T_DECL(mmap_resilient_media,
    "test mmap(MAP_RESILIENT_MEDIA)",
    T_META_ASROOT(true), T_META_TAG_VM_PREFERRED)
{
	int ret;
	int new_rate, old_rate1, old_rate2, old_rate3;
	size_t old_size;
	int fd;
	ssize_t nbytes;
	unsigned char *addr;
	int i;
	char tmpf[PATH_MAX] = "";

	/*
	 * SETUP
	 */
	/* save error injection rates and set new ones */
	old_size = sizeof(old_rate1);
	new_rate = 4;
	ret = sysctlbyname("vm.fault_resilient_media_inject_error1_rate",
	    &old_rate1, &old_size,
	    &new_rate, sizeof(new_rate));
	if (ret < 0) {
		T_LOG("sysctlbyname(vm.fault_resilient_media_inject_error1_rate) error %d (%s)",
		    errno, strerror(errno));
	}
	old_size = sizeof(old_rate2);
	new_rate = 6;
	ret = sysctlbyname("vm.fault_resilient_media_inject_error2_rate",
	    &old_rate2, &old_size,
	    &new_rate, sizeof(new_rate));
	if (ret < 0) {
		T_LOG("sysctlbyname(vm.fault_resilient_media_inject_error2_rate) error %d (%s)",
		    errno, strerror(errno));
	}
	old_size = sizeof(old_rate3);
	new_rate = 8;
	ret = sysctlbyname("vm.fault_resilient_media_inject_error3_rate",
	    &old_rate3, &old_size,
	    &new_rate, sizeof(new_rate));
	if (ret < 0) {
		T_LOG("sysctlbyname(vm.fault_resilient_media_inject_error3_rate) error %d (%s)",
		    errno, strerror(errno));
	}

	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, FILENAME, PATH_MAX);
	T_WITH_ERRNO;
	fd = open(tmpf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open(%s)", tmpf);
	T_WITH_ERRNO;
	nbytes = write(fd, "x", 1);
	T_QUIET; T_ASSERT_EQ(nbytes, (ssize_t)1, "write 1 byte");
	T_WITH_ERRNO;
	addr = mmap(NULL,
	    MAPSIZE,
	    PROT_READ | PROT_WRITE,
	    MAP_FILE | MAP_PRIVATE | MAP_RESILIENT_MEDIA,
	    fd,
	    0);
	T_QUIET; T_ASSERT_NE((void *)addr, MAP_FAILED, "mmap()");

	/*
	 * TEST
	 */
	T_ASSERT_EQ(addr[0], 'x', "first byte is 'x'");
	T_LOG("checking that the rest of the mapping is accessible...");
	for (i = 1; i < MAPSIZE; i++) {
		if (i % (2 * (int)vm_page_size) == 0) {
			/* trigger a write fault every other page */
			addr[i] = 'y';
			T_QUIET; T_ASSERT_EQ(addr[i], 'y', "byte #0x%x is 'y'", i);
		} else {
			T_QUIET; T_ASSERT_EQ(addr[i], 0, "byte #0x%x is 0", i);
		}
	}
	T_PASS("rest of resilient mapping is accessible");

	/*
	 * CLEANUP
	 */
	T_WITH_ERRNO;
	ret = close(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "close()");
	T_WITH_ERRNO;
	ret = unlink(tmpf);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "unlink(%s)", tmpf);
	/* restore old error injection rates */
	ret = sysctlbyname("vm.fault_resilient_media_inject_error1_rate",
	    NULL, NULL,
	    &old_rate1, sizeof(old_rate1));
	if (ret < 0) {
		T_LOG("sysctlbyname(vm.fault_resilient_media_inject_error1_rate) error %d (%s)",
		    errno, strerror(errno));
	}
	ret = sysctlbyname("vm.fault_resilient_media_inject_error2_rate",
	    NULL, NULL,
	    &old_rate2, sizeof(old_rate2));
	if (ret < 0) {
		T_LOG("sysctlbyname(vm.fault_resilient_media_inject_error2_rate) error %d (%s)",
		    errno, strerror(errno));
	}
	ret = sysctlbyname("vm.fault_resilient_media_inject_error3_rate",
	    NULL, NULL,
	    &old_rate3, sizeof(old_rate3));
	if (ret < 0) {
		T_LOG("sysctlbyname(vm.fault_resilient_media_inject_error2_rate) error %d (%s)",
		    errno, strerror(errno));
	}

	T_PASS("mmap(MAP_RESILIENT_MEDIA)");
}

static void
allow_signal(int signal, char *signal_name, void (*fn)(void), const char *msg)
{
	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		T_PASS("Child ran with no signal. This is allowed.\n");
		return;
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		T_EXPECT_TRUE(WIFSIGNALED(status), "%s: exited with signal", msg);
		if (WIFSIGNALED(status)) {
			T_EXPECT_EQ(WTERMSIG(status), signal, "%s is allowed to exit with %s", msg, signal_name);
		} else {
			T_PASS("Exited without a signal\n");
		}
	}
}


static void
mmap_resilient_media_cow_impl()
{
	int ret;
	int fd;
	unsigned char *addr;
	mach_vm_address_t remap_addr;
	vm_prot_t cur_prot, max_prot;
	kern_return_t kr;
	char tmpf[PATH_MAX] = "";

	/*
	 * SETUP
	 */
	T_SETUPBEGIN;

	strlcpy(tmpf, dt_tmpdir(), PATH_MAX);
	strlcat(tmpf, FILENAME, PATH_MAX);
	T_WITH_ERRNO;
	fd = open(tmpf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open(%s)", tmpf);
	T_WITH_ERRNO;
	addr = mmap(NULL,
	    MAPSIZE,
	    PROT_READ | PROT_WRITE,
	    MAP_FILE | MAP_PRIVATE | MAP_RESILIENT_MEDIA,
	    fd,
	    0);
	T_QUIET; T_ASSERT_NE((void *)addr, MAP_FAILED, "mmap()");

	remap_addr = 0;
	kr = mach_vm_remap(mach_task_self(), &remap_addr, PAGE_SIZE, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), (mach_vm_address_t)(uintptr_t)addr,
	    TRUE /* copy */, &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");

	T_SETUPEND;

	/*
	 * TEST
	 */
	*(uint32_t *)addr = 0x41414141;
	T_ASSERT_EQ(*(uint32_t *)remap_addr, 0, "writing to RESILIENT_MEDIA mapping should not affect its copy");
	*(uint32_t *)addr = 0x42424242;
	T_ASSERT_EQ(*(uint32_t *)remap_addr, 0, "writing to RESILIENT_MEDIA mapping again should still not affect its copy");

	/*
	 * CLEANUP
	 */
	T_WITH_ERRNO;
	ret = close(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "close()");
	T_WITH_ERRNO;
	ret = unlink(tmpf);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "unlink(%s)", tmpf);
}


T_DECL(mmap_resilient_media_cow,
    "test mmap(MAP_RESILIENT_MEDIA) and CoW",
    T_META_TAG_VM_PREFERRED,
    T_META_IGNORECRASHES(".*mmap_resilient_media.*"))
{
	/* Allow, but don't require a SIGBUS signal */
	allow_signal(SIGBUS, "SIGBUS", &mmap_resilient_media_cow_impl, "mmap_resilient_media_cow_impl");
}
