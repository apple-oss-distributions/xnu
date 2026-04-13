/*
 * test_fp_connectx
 * Copyright (c) 2017, 2025 Apple Inc. All rights reserved.
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
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vidhi_goel")
	);

T_DECL(test_fp_connectx,
    "test connectx with non-null iov parameter on UNIX domain socket",
    T_META_CHECK_LEAKS(false))
{
	sae_associd_t associd = SAE_ASSOCID_ANY;
	sa_endpoints_t endpoints;
	u_int32_t count = 2;

	while (count) {
		int sk;
		int ret;

		sk = socket(PF_UNIX, SOCK_DGRAM, 0);
		T_ASSERT_POSIX_SUCCESS(sk, "socket(PF_UNIX, SOCK_DGRAM, 0)");

		memset(&endpoints, 0, sizeof(endpoints));
		endpoints.sae_srcaddr = NULL;

		struct sockaddr_in6 dst = {
			.sin6_family = AF_INET6,
			.sin6_len = sizeof(struct sockaddr),
			.sin6_port = htons(3001),
			.sin6_flowinfo = 0,
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
			.sin6_scope_id = 0,
		};
		endpoints.sae_dstaddr = (struct sockaddr *)&dst;
		endpoints.sae_dstaddrlen = sizeof(struct sockaddr);

		/* Pass in a non-null IOV pointer */
		void *iov = (void *)0x1;
		ret = connectx(sk, &endpoints, associd, 0, iov, 0, 0, 0);
		T_QUIET;
		T_EXPECT_EQ(ret, -1, "connectx with invalid iov should fail");
		T_QUIET;
		T_LOG("connectx failed with errno: %d (%s)", errno, strerror(errno));

		close(sk);
		count--;
	}

	T_PASS("test_fp_connectx completed without crash");
}
