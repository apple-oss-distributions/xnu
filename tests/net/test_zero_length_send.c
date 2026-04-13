/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_OWNER("vlubet")
	);

static void
create_sock_and_close(void)
{
	struct sockaddr_in addr = {};
	int fd;

	addr.sin_len = sizeof(struct sockaddr_in);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(2333);
	addr.sin_addr.s_addr = INADDR_ANY;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0) {
		T_LOG("socket(PF_INET, SOCK_DGRAM, IPPROTO_IP) failed");
		return;
	}
	if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		T_LOG("connect() failed");
	}
	close(fd);
}

T_DECL(test_zero_length_send,
    "test sending zero-length data with IP_HDRINCL",
    T_META_CHECK_LEAKS(false))
{
	static char buffer[1000];
	int fd;
	struct sockaddr_in addr = {};
	int optval = 1;
	ssize_t ret;

	fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)");

	addr.sin_len = sizeof(struct sockaddr_in);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	T_ASSERT_POSIX_SUCCESS(connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)),
	    "connect");

	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)),
	    "setsockopt(IP_HDRINCL)");

	/* Create and close many sockets to exercise socket garbage collection */
	for (int i = 0; i < 0x1000; i++) {
		create_sock_and_close();
	}

	/* Send zero-length buffer */
	ret = send(fd, buffer, 0, 0);
	if (ret < 0) {
		T_LOG("send() failed (expected with zero length): %s", strerror(errno));
	}

	close(fd);
	force_zone_gc();

	T_PASS("test_zero_length_send completed without crash");
}
