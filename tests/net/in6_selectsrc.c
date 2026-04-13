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

/*
 * Test for in6_pcbdetach race condition (rdar://49067962)
 */

#include <darwintest.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <netinet/in.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_OWNER("randall_meyer")
	);

#define IPPROTO_IP 0

T_DECL(in6_selectsrc,
    "test in6_pcbdetach with connect and setsockopt race (rdar://49067962)",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120))
{
	int s;
	struct sockaddr_in6 sa1 = {
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_family = AF_INET6,
		.sin6_port = 65000,
		.sin6_flowinfo = 3,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_scope_id = 0,
	};
	struct sockaddr_in6 sa2 = {
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_family = AF_INET6,
		.sin6_port = 65001,
		.sin6_flowinfo = 3,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_scope_id = 0,
	};
	unsigned char buffer[4] = {};
	int res;

	T_LOG("Starting 200 iterations of in6_selectsrc test");

	for (int iteration = 1; iteration <= 200; iteration++) {
		s = socket(AF_INET6, SOCK_RAW, IPPROTO_IP);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_RAW, IPPROTO_IP) iteration %d", iteration);

		res = connect(s, (const struct sockaddr *)&sa1, sizeof(sa1));

		res = setsockopt(s, 41, 50, buffer, sizeof(buffer));

		res = connect(s, (const struct sockaddr *)&sa2, sizeof(sa2));

		close(s);

		if (iteration % 50 == 0) {
			T_LOG("Progress: completed %d iterations", iteration);
		}
	}

	T_PASS("in6_selectsrc completed 200 iterations without crash");
}
