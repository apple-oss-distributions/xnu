/*
 * Copyright (c) 2019, 2025 Apple Inc. All rights reserved.
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio_private.h>
#include <mach/mach.h>
#include <errno.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("tpauly")
	);

T_DECL(test_ifnet_ordered,
    "test SIOCSIFORDER ioctl with invalid parameters",
    T_META_CHECK_LEAKS(false))
{
	int fd;
	struct if_order ifo;
	uint32_t data[2] = {1, 2};
	int ret;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_STREAM, 0)");

	ifo.ifo_ordered_indices = (mach_vm_address_t)data;

	/* Test with large ifo_count */
	T_LOG("Testing SIOCSIFORDER with ifo_count = 10000");
	ifo.ifo_count = 10000;
	ret = ioctl(fd, SIOCSIFORDER, &ifo);
	T_EXPECT_EQ(ret, -1, "ioctl should fail with large ifo_count");
	T_EXPECT_EQ(errno, EINVAL, "errno should be EINVAL");

	/* Reset ifo_count */
	ifo.ifo_count = 2;

	/* Test with NULL ordered indices */
	T_LOG("Testing SIOCSIFORDER with NULL ordered_indices");
	ifo.ifo_ordered_indices = 0;
	ret = ioctl(fd, SIOCSIFORDER, &ifo);
	T_EXPECT_EQ(ret, -1, "ioctl should fail with NULL ordered_indices");
	T_EXPECT_EQ(errno, EINVAL, "errno should be EINVAL");

	/* Reset ordered indices */
	ifo.ifo_ordered_indices = (mach_vm_address_t)data;

	/* Test with interface index 0 */
	T_LOG("Testing SIOCSIFORDER with interface index 0");
	data[0] = 0;
	ret = ioctl(fd, SIOCSIFORDER, &ifo);
	T_EXPECT_EQ(ret, -1, "ioctl should fail with index 0");
	T_EXPECT_EQ(errno, EINVAL, "errno should be EINVAL");

	/* Test with large interface index */
	T_LOG("Testing SIOCSIFORDER with interface index 10000");
	data[0] = 10000;
	ret = ioctl(fd, SIOCSIFORDER, &ifo);
	T_EXPECT_EQ(ret, -1, "ioctl should fail with large index");
	T_EXPECT_EQ(errno, EINVAL, "errno should be EINVAL");

	/* Test with duplicate indices */
	T_LOG("Testing SIOCSIFORDER with duplicate indices");
	data[0] = 2;
	data[1] = 2;
	ret = ioctl(fd, SIOCSIFORDER, &ifo);
	T_EXPECT_EQ(ret, -1, "ioctl should fail with duplicate indices");
	T_EXPECT_EQ(errno, EINVAL, "errno should be EINVAL");

	close(fd);

	T_PASS("test_ifnet_ordered completed");
}
