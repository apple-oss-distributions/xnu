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

#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <darwintest.h>
#include <darwintest_utils.h>

/* -*- compile-command: "xcrun --sdk macosx.internal make -C tests sendmsg_x_test" -*- */

T_GLOBAL_META(T_META_NAMESPACE("xnu.net"));

#define DATAGRAM_SIZE 64

T_DECL(sendmsg_x_test, "exercise sendmsg_x() return value")
{
	int socket_fds[2];

	T_EXPECT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_DGRAM, 0, socket_fds), "socketpair");

	/*
	 * The receive buffer size is too small for more than one datagram.
	 */
	int send_buffer_size = DATAGRAM_SIZE;
	int receive_buffer_size = DATAGRAM_SIZE + (DATAGRAM_SIZE >> 1);
	socklen_t opt_len = sizeof(int);

	T_EXPECT_POSIX_SUCCESS(setsockopt(socket_fds[0], SOL_SOCKET, SO_SNDBUF, &send_buffer_size, opt_len), "setsockopt() SO_SNDBUF");
	T_EXPECT_POSIX_SUCCESS(setsockopt(socket_fds[0], SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, opt_len), "setsockopt() SO_RCVBUF");
	T_EXPECT_POSIX_SUCCESS(setsockopt(socket_fds[1], SOL_SOCKET, SO_SNDBUF, &send_buffer_size, opt_len), "setsockopt() SO_SNDBUF");
	T_EXPECT_POSIX_SUCCESS(setsockopt(socket_fds[1], SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, opt_len), "setsockopt() SO_RCVBUF");

	/*
	 * Send two datagram at once, only one must be sent and received
	 */
	struct msghdr_x message_headers[2] = {};

	uint8_t buffer1[DATAGRAM_SIZE];
	memset(buffer1, 0x12, DATAGRAM_SIZE);

	struct iovec iovec1 = {
		.iov_base = buffer1,
		.iov_len = DATAGRAM_SIZE,
	};
	message_headers[0].msg_iov = &iovec1;
	message_headers[0].msg_iovlen = 1;

	uint8_t buffer2[DATAGRAM_SIZE];
	memset(buffer2, 0x34, DATAGRAM_SIZE);

	struct iovec iovec2 = {
		.iov_base = buffer2,
		.iov_len = DATAGRAM_SIZE,
	};

	message_headers[1].msg_iov = &iovec2;
	message_headers[1].msg_iovlen = 1;

	ssize_t sendmsg_x_result = sendmsg_x(socket_fds[0], message_headers, 2, 0);
	if (sendmsg_x_result < 0) {
		T_FAIL("sendmsg_x() failed: %s", strerror(errno));
	}
	if (sendmsg_x_result != 1) {
		T_FAIL("sendmsg_x() failed: return %zd instead of 1", sendmsg_x_result);
	}
	T_PASS("sendmsg_x() result: %zd == 1\n", sendmsg_x_result);

	/*
	 * Receive the datagram we expect
	 */
	uint8_t receive_buffer1[DATAGRAM_SIZE * 2];
	ssize_t recv_result = recv(socket_fds[1], receive_buffer1, sizeof(receive_buffer1), 0);
	T_EXPECT_POSIX_SUCCESS(recv_result, "first recv() recv_result %zd errno %d", recv_result, errno);

	if (recv_result != DATAGRAM_SIZE) {
		T_FAIL("recv() failed: return %zd instead of DATAGRAM_SIZE", recv_result);
	}
	T_PASS("recv() result: %zd == DATAGRAM_SIZE\n", recv_result);

	int i;
	for (i = 0; i < DATAGRAM_SIZE; i++) {
		if (receive_buffer1[i] != 0x12) {
			T_FAIL("receive_buffer1[%d] 0x%x == 0x12", i, receive_buffer1[i]);
		}
	}
	T_PASS("First datagram successfully received.\n");

	/*
	 * Set the receive socket as non-blocking and verify no more data is pending
	 */
	int flags = fcntl(socket_fds[1], F_GETFL, 0);
	T_EXPECT_POSIX_SUCCESS(fcntl(socket_fds[1], F_SETFL, flags | O_NONBLOCK), "fcntl() O_NONBLOCK");

	recv_result = recv(socket_fds[1], receive_buffer1, sizeof(receive_buffer1), 0);
	T_EXPECT_POSIX_ERROR(errno, EWOULDBLOCK, "second recv() recv_result %zd errno %d", recv_result, errno);

	close(socket_fds[0]);
	close(socket_fds[1]);
}
