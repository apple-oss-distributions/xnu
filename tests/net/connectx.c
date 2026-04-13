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

#include <darwintest.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/socket.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

T_DECL(connectx_invalid_addrlen,
    "connectx should return ENAMETOOLONG for invalid address lengths",
    T_META_CHECK_LEAKS(false))
{
	struct sockaddr_in src;
	struct sockaddr_in dst;
	sa_endpoints_t sa;
	int fd, error;

	bzero(&src, sizeof(src));
	bzero(&dst, sizeof(dst));
	bzero(&sa, sizeof(sa));

	src.sin_len = dst.sin_len = sizeof(struct sockaddr_in);
	src.sin_family = dst.sin_family = AF_INET;
	src.sin_port = 0;
	dst.sin_port = htons(80);

	T_ASSERT_EQ(inet_aton("127.0.0.1", &src.sin_addr), 1, "inet_aton src");
	T_ASSERT_EQ(inet_aton("8.8.8.8", &dst.sin_addr), 1, "inet_aton dst");

	sa.sae_srcaddr = (struct sockaddr *)&src;
	sa.sae_dstaddr = (struct sockaddr *)&dst;

	/* Setting it to -1 to trigger rdar://problem/24420896 */
	sa.sae_srcaddrlen = -1;
	sa.sae_dstaddrlen = -1;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");

	error = connectx(fd, &sa, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL);
	T_ASSERT_EQ(error, -1, "connectx should fail with invalid addrlen");
	T_ASSERT_EQ(errno, ENAMETOOLONG, "errno should be ENAMETOOLONG");
}
