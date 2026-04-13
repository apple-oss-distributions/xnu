/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
 * Test for SIOCSIFADDR on lo0 and stf0 interfaces
 */

#include <darwintest.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vidhi_goel")
	);

#define IPPROTO_IP 0

T_DECL(test_set_ifaddr,
    "test SIOCSIFADDR ioctl on lo0 and stf0",
    T_META_CHECK_LEAKS(false))
{
	int s;
	struct ifreq ifr = {};
	int ret;

	s = socket(AF_SYSTEM, SOCK_DGRAM, IPPROTO_IP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_SYSTEM, SOCK_DGRAM, IPPROTO_IP)");

	/* Test lo0 */
	T_LOG("Testing SIOCSIFADDR on lo0");
	strlcpy(ifr.ifr_name, "lo0", sizeof(ifr.ifr_name));
	ret = ioctl(s, SIOCSIFADDR, (char *)&ifr);
	T_EXPECT_NE(ret, 0, "ioctl SIOCSIFADDR on lo0 should fail");
	T_LOG("SIOCSIFADDR on lo0 returned: %d", ret);

	/* Test stf0 */
	T_LOG("Testing SIOCSIFADDR on stf0");
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, "stf0", sizeof(ifr.ifr_name));
	ret = ioctl(s, SIOCSIFADDR, (char *)&ifr);
	T_EXPECT_NE(ret, 0, "ioctl SIOCSIFADDR on stf0 should fail");
	T_LOG("SIOCSIFADDR on stf0 returned: %d", ret);

	close(s);

	T_PASS("test_set_ifaddr completed");
}
