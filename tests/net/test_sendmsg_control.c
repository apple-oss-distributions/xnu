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
#include <netinet/in.h>
#include <sys/socket.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("plakhera")
	);

T_DECL(test_sendmsg_control,
    "test sendmsg with IP_PKTINFO control message",
    T_META_CHECK_LEAKS(false))
{
	int s;
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_len = sizeof(struct sockaddr_in),
		.sin_port = htons(1337),
		.sin_addr = {
			.s_addr = inet_addr("127.0.0.1")
		}
	};
	uint8_t data = 0;
	struct iovec iov = {
		.iov_base = &data,
		.iov_len = 1
	};

	union {
		struct cmsghdr cm;
		unsigned char control[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control_un;

	bzero(&control_un, sizeof(control_un));

	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_name = &dst,
		.msg_namelen = sizeof(dst),
		.msg_control = control_un.control,
		.msg_controllen = sizeof(control_un.control),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	struct in_pktinfo *pktinfo = NULL;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
	bzero(pktinfo, sizeof(struct in_pktinfo));

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)");

	if (sendmsg(s, &msg, 0) == -1) {
		T_LOG("sendmsg failed (expected): %s", strerror(errno));
	}

	close(s);
}
