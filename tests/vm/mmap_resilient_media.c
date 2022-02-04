/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <mach/vm_page_size.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

#define FILENAME "/tmp/test-77350114.data"
#define MAPSIZE (2*1024*1024)

T_DECL(mmap_resilient_media,
    "test mmap(MAP_RESILIENT_MEDIA)",
    T_META_ASROOT(true))
{
	int ret;
	int new_rate, old_rate1, old_rate2, old_rate3;
	size_t old_size;
	int fd;
	ssize_t nbytes;
	unsigned char *addr;
	int i;

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
	T_WITH_ERRNO;
	fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, 0644);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open(%s)", FILENAME);
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
	ret = unlink(FILENAME);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "unlink(%s)", FILENAME);
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
