/*
 * Copyright (c) 2020, 2025 Apple Inc. All rights reserved.
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
 * Test Case: XNU: mptcp_usr_sosend local DoS to due unbounded length through sendto
 * rdar://60083434
 *
 * Chris Jarrett-Davies <chrisjd@apple.com>
 * SEAR Red Team / 2020-Mar-02
 */

#include <darwintest.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

#ifndef AF_MULTIPATH
#define AF_MULTIPATH 39
#endif

T_DECL(mptcp_sendto_dos,
    "test that sendto with large length doesn't cause DoS on MPTCP socket",
    T_META_CHECK_LEAKS(false))
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_len = sizeof(sin),
		.sin_addr = {
			.s_addr = inet_addr("127.0.0.1")
		},
		.sin_port = htons(22)
	};
	sa_endpoints_t sae = {
		.sae_dstaddr = (struct sockaddr *)&sin,
		.sae_dstaddrlen = sizeof(sin)
	};
	int s;
	ssize_t result;

	s = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP)");

	T_ASSERT_POSIX_SUCCESS(connectx(s, (const sa_endpoints_t *)&sae, 0, 0, NULL, 0, NULL, NULL),
	    "connectx");

	/* Attempt to trigger issue with unbounded length - should fail gracefully */
	result = sendto(s, "A", 0x80000000UL, 0, (const struct sockaddr *)&sin, sizeof(sin));
	T_EXPECT_EQ(result, (ssize_t)-1, "sendto with large length should fail");
	T_LOG("sendto failed with errno: %d (%s)", errno, strerror(errno));

	close(s);
}
