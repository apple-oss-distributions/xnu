/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#include <sys/un.h>

#include <stdlib.h>
#include <unistd.h>

#include <darwintest.h>

#define MAX_SOCK 10

T_DECL(scm_rights_leak, "test leak of file pointers by peeking SCM_RIGHTS")
{
	int pair[2] = { -1, -1 };

	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, pair),
	    NULL);

	struct cmsghdr *cmsg = NULL;
	T_ASSERT_NOTNULL(cmsg = calloc(1, CMSG_SPACE(MAX_SOCK * sizeof(int))), "calloc");
	cmsg->cmsg_len = CMSG_LEN(MAX_SOCK * sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	T_LOG("send cmsg_len %u", cmsg->cmsg_len);

	int *sock_fds = (int *)(void *)CMSG_DATA(cmsg);
	for (int i = 0; i < MAX_SOCK; i++) {
		T_ASSERT_POSIX_SUCCESS(sock_fds[i] = socket(AF_UNIX, SOCK_DGRAM, 0), NULL);
	}
	for (int i = 0; i < MAX_SOCK; i++) {
		fprintf(stderr, "sock_fds[%d] %i\n", i, sock_fds[i]);
	}

	char data = 'x';
	struct iovec iovec = { .iov_base = &data, .iov_len = 1 };

	struct msghdr mh;
	mh.msg_name = 0;
	mh.msg_namelen = 0;
	mh.msg_iov = &iovec;
	mh.msg_iovlen = 1;
	mh.msg_control = cmsg;
	mh.msg_controllen = cmsg->cmsg_len;
	mh.msg_flags = 0;

	ssize_t ssize;
	ssize = sendmsg(pair[0], &mh, 0);
	T_ASSERT_EQ(ssize, (ssize_t)1, "sendmsg");

	/* Allocate twice the size of the worst case */
	socklen_t rcmsg_size = CMSG_SPACE(MAX_SOCK * 2 * sizeof(uintptr_t));
	struct cmsghdr *rcmsg = NULL;
	T_EXPECT_POSIX_SUCCESS_(rcmsg = calloc(1, rcmsg_size), "calloc");

	mh.msg_name = 0;
	mh.msg_namelen = 0;
	mh.msg_iov = &iovec;
	mh.msg_iovlen = 1;
	mh.msg_control = rcmsg;
	mh.msg_controllen = rcmsg_size;
	mh.msg_flags = 0;

	ssize = recvmsg(pair[1], &mh, MSG_PEEK);
	T_ASSERT_POSIX_SUCCESS(ssize, "recvmsg");
	T_LOG("recvmsg MSG_PEEK cmsg_len %u", rcmsg->cmsg_len);

	uintptr_t *r_ptrs = (uintptr_t *)(void *)CMSG_DATA(rcmsg);
	socklen_t nptrs = (rcmsg->cmsg_len - CMSG_LEN(0)) / sizeof(uintptr_t);
	for (socklen_t i = 0; i < nptrs; i++) {
		T_EXPECT_EQ(r_ptrs[i], (uintptr_t)0, "r_ptrs[%u] 0x%lx\n", i, r_ptrs[i]);
	}

	mh.msg_name = 0;
	mh.msg_namelen = 0;
	mh.msg_iov = &iovec;
	mh.msg_iovlen = 1;
	mh.msg_control = rcmsg;
	mh.msg_controllen = rcmsg_size;
	mh.msg_flags = 0;

	ssize = recvmsg(pair[1], &mh, 0);
	T_ASSERT_POSIX_SUCCESS(ssize, "recvmsg");
	T_LOG("recvmsg cmsg_len %u", rcmsg->cmsg_len);

	int *r_fds = (int *)(void *)CMSG_DATA(rcmsg);
	socklen_t nfds = (rcmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
	T_ASSERT_EQ(nfds, MAX_SOCK, "number received fds %u == %u", nfds, MAX_SOCK);
	for (socklen_t i = 0; i < nfds; i++) {
		T_EXPECT_NE(r_fds[i], 0, "r_fds[%d] %i\n", i, r_fds[i]);
	}

	free(cmsg);
	free(rcmsg);
	close(pair[0]);
	close(pair[1]);
}
