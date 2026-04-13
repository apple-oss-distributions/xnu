/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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

#include <sys/socket.h>


#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

// Large enough to cause the create of an mbuf cluster
#define SEND_CTLBUFLEN 512

uint8_t ctrlbuf[1024];
uint8_t databuf[1024];

static void
test_unp_scm_rights_peek(bool with_data)
{
	int fds[2] = { -1, -1 };
	struct msghdr m1 = {0};
	struct msghdr m2 = {0};
	struct iovec iov = {0};
	struct cmsghdr *cm = (struct cmsghdr *)ctrlbuf;

	memset(ctrlbuf, 0, sizeof(ctrlbuf));

	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds),
	    "socketpair(AF_UNIX, SOCK_DGRAM, 0)");
	T_LOG("socketpair() fds: %d, %d\n", fds[0], fds[1]);

	m1.msg_control = cm;
	m1.msg_controllen = SEND_CTLBUFLEN;
	cm->cmsg_len = SEND_CTLBUFLEN;
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;

	m1.msg_iov = &iov;
	m1.msg_iovlen = 1;
	if (with_data) {
		iov.iov_base = databuf;
		iov.iov_len = sizeof(databuf);
	}
	T_ASSERT_POSIX_SUCCESS(sendmsg(fds[0], &m1, 0), "sendmsg");

	m2.msg_control = cm;

	m2.msg_iov = &iov;
	m2.msg_iovlen = 1;
	iov.iov_base = databuf;
	iov.iov_len = sizeof(databuf);

	T_ASSERT_POSIX_SUCCESS(recvmsg(fds[1], &m2, MSG_PEEK), "recvmsg MSG_PEEK");
	T_ASSERT_POSIX_SUCCESS(recvmsg(fds[1], &m2, 0), "recvmsg");

	close(fds[0]);
	close(fds[1]);
}

T_DECL(test_unp_scm_rights_peek_no_data, "UDS MSG_PEEK with SCM_RIGHTS without data)",
    T_META_ENABLED(false) /* rdar://150253879 */)
{
	test_unp_scm_rights_peek(false);
}

T_DECL(test_unp_scm_rights_peek_with_data, "UDS MSG_PEEK with SCM_RIGHTS with data)",
    T_META_ENABLED(false) /* rdar://150253879 */)
{
	test_unp_scm_rights_peek(true);
}
