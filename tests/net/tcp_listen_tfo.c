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
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

#define CONNECT_RESUME_ON_READ_WRITE 0x1 /* resume connect() on read/write */

T_DECL(tcp_listen_tfo,
    "test connectx with CONNECT_RESUME_ON_READ_WRITE on listening socket",
    T_META_CHECK_LEAKS(false))
{
	int fd;
	struct sockaddr_in addr;
	struct sa_endpoints tt_end;
	struct sockaddr *sockaddr_dst;
	char tmp[0x100];
	ssize_t sent;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_STREAM, 0)");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(2333);

	T_ASSERT_POSIX_SUCCESS(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), "bind");
	T_ASSERT_POSIX_SUCCESS(listen(fd, 5), "listen");

	memset(&tt_end, '\x00', sizeof(struct sa_endpoints));
	sockaddr_dst = malloc(sizeof(struct sockaddr));
	T_ASSERT_NOTNULL(sockaddr_dst, "malloc sockaddr");

	memset(sockaddr_dst, 'A', sizeof(struct sockaddr));
	sockaddr_dst->sa_family = AF_INET;
	tt_end.sae_dstaddr = sockaddr_dst;
	tt_end.sae_dstaddrlen = sizeof(struct sockaddr);

	/* This should fail - can't call connectx on a listening socket */
	int ret = connectx(fd, &tt_end, 0, CONNECT_RESUME_ON_READ_WRITE, 0, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "connectx on listening socket should fail");
	T_LOG("connectx failed with errno: %d (%s)", errno, strerror(errno));

	memset(tmp, 'A', 0x100);
	sent = send(fd, &tmp, sizeof(tmp), 0);
	T_EXPECT_EQ(sent, (ssize_t)-1, "send after failed connectx should fail");
	T_LOG("send failed with errno: %d (%s)", errno, strerror(errno));

	free(sockaddr_dst);
	close(fd);
}
