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

/* -*- compile-command: "xcrun --sdk macosx.internal make -C tests recvmsg_x_iov_overflow" -*- */

/*
 * Test for rdar://169455889
 *
 * This test exploits a vulnerability in recvmsg_x() where the condition to
 * determine whether to reuse an existing uio structure was inverted.
 *
 * The bug was:
 *   if (auio->uio_max_iovs <= user_msg.msg_iovlen)
 *       reuse auio
 *
 * This meant if the auio was TOO SMALL (max_iovs <= new iovlen), it would
 * incorrectly reuse it, causing a buffer overflow when copying iovs.
 *
 * The test sends multiple messages with varying iov counts to trigger the
 * overflow condition where a small auio is reused for a message with more iovs.
 */

#include <sys/socket.h>
#include <sys/uio.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <darwintest.h>

#define SMALL_IOV_COUNT 2
#define LARGE_IOV_COUNT 16
#define BUFFER_SIZE     64

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet"),
	T_META_CHECK_LEAKS(false));

/*
 * This test reproduces the vulnerability by calling recvmsg_x with multiple
 * messages where the iov count increases from one message to the next.
 *
 * With the buggy condition (auio->uio_max_iovs <= user_msg.msg_iovlen),
 * the code would:
 *   1. Process first message with SMALL_IOV_COUNT iovs, creating auio with
 *      uio_max_iovs = SMALL_IOV_COUNT
 *   2. Process second message with LARGE_IOV_COUNT iovs
 *   3. Check: auio->uio_max_iovs (2) <= user_msg.msg_iovlen (16) = TRUE
 *   4. Incorrectly reuse the small auio via uio_reset_fast()
 *   5. Call copyin_user_iovec_array() to copy 16 iovs into space for 2
 *   6. Buffer overflow!
 */
T_DECL(recvmsg_x_iov_overflow,
    "Test for recvmsg_x() iov buffer overflow vulnerability (rdar://169455889)",
    T_META_TAG_VM_PREFERRED)
{
	int sockets[2];
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets),
	    "socketpair");

	/*
	 * Send two packets to be received by recvmsg_x
	 */
	char send_buffer[BUFFER_SIZE];
	memset(send_buffer, 'A', sizeof(send_buffer));

	T_ASSERT_POSIX_SUCCESS(write(sockets[0], send_buffer, sizeof(send_buffer)),
	    "write packet 1");
	T_ASSERT_POSIX_SUCCESS(write(sockets[0], send_buffer, sizeof(send_buffer)),
	    "write packet 2");

	/*
	 * Allocate receive buffers and iovecs
	 * First message uses SMALL_IOV_COUNT iovs
	 * Second message uses LARGE_IOV_COUNT iovs
	 */
	struct iovec *iovs_small = calloc(SMALL_IOV_COUNT, sizeof(struct iovec));
	T_QUIET; T_ASSERT_NOTNULL(iovs_small, "allocate small iovs");

	for (int i = 0; i < SMALL_IOV_COUNT; i++) {
		iovs_small[i].iov_base = malloc(BUFFER_SIZE / SMALL_IOV_COUNT);
		iovs_small[i].iov_len = BUFFER_SIZE / SMALL_IOV_COUNT;
		T_QUIET; T_ASSERT_NOTNULL(iovs_small[i].iov_base, "allocate small iov buffer");
	}

	struct iovec *iovs_large = calloc(LARGE_IOV_COUNT, sizeof(struct iovec));
	T_QUIET; T_ASSERT_NOTNULL(iovs_large, "allocate large iovs");

	for (int i = 0; i < LARGE_IOV_COUNT; i++) {
		iovs_large[i].iov_base = malloc(BUFFER_SIZE / LARGE_IOV_COUNT);
		iovs_large[i].iov_len = BUFFER_SIZE / LARGE_IOV_COUNT;
		T_QUIET; T_ASSERT_NOTNULL(iovs_large[i].iov_base, "allocate large iov buffer");
	}

	/*
	 * Set up two messages for recvmsg_x:
	 * Message 0: SMALL_IOV_COUNT iovs (causes allocation of small auio)
	 * Message 1: LARGE_IOV_COUNT iovs (triggers buggy reuse of small auio)
	 */
	struct msghdr_x msgs[2] = {
		{
			.msg_iov = iovs_small,
			.msg_iovlen = SMALL_IOV_COUNT,
			.msg_flags = 0,
		},
		{
			.msg_iov = iovs_large,
			.msg_iovlen = LARGE_IOV_COUNT,
			.msg_flags = 0,
		},
	};

	/*
	 * Call recvmsg_x with both messages at once.
	 *
	 * With the bug:
	 *   - First iteration processes msgs[0] with 2 iovs, creates auio(max=2)
	 *   - Second iteration processes msgs[1] with 16 iovs
	 *   - Bug checks: 2 <= 16 (TRUE), so reuses auio(max=2)
	 *   - copyin_user_iovec_array tries to copy 16 iovs into space for 2
	 *   - BUFFER OVERFLOW (or kernel panic if GuardMalloc/KASAN enabled)
	 *
	 * With the fix:
	 *   - First iteration processes msgs[0] with 2 iovs, creates auio(max=2)
	 *   - Second iteration processes msgs[1] with 16 iovs
	 *   - Fix checks: 2 >= 16 (FALSE), so frees old auio and creates new auio(max=16)
	 *   - copyin_user_iovec_array copies 16 iovs into space for 16
	 *   - Success!
	 */
	T_LOG("Calling recvmsg_x with messages having %d and %d iovs",
	    SMALL_IOV_COUNT, LARGE_IOV_COUNT);

	ssize_t received = recvmsg_x(sockets[1], msgs, 2, 0);

	T_ASSERT_GE(received, 0L, "recvmsg_x should succeed (no crash/overflow)");
	T_EXPECT_EQ(received, 2L, "should receive both packets");

	T_LOG("Successfully received %zd packets", received);
	T_LOG("Message 0: received %zu bytes with %u iovs",
	    msgs[0].msg_datalen, msgs[0].msg_iovlen);
	T_LOG("Message 1: received %zu bytes with %u iovs",
	    msgs[1].msg_datalen, msgs[1].msg_iovlen);

	/*
	 * Clean up
	 */
	for (int i = 0; i < SMALL_IOV_COUNT; i++) {
		free(iovs_small[i].iov_base);
	}
	free(iovs_small);

	for (int i = 0; i < LARGE_IOV_COUNT; i++) {
		free(iovs_large[i].iov_base);
	}
	free(iovs_large);

	close(sockets[0]);
	close(sockets[1]);

	T_PASS("Test completed without crash");
}

/*
 * Additional stress test that varies iov counts more aggressively
 * to ensure the fix handles all edge cases correctly.
 */
T_DECL(recvmsg_x_iov_varying_sizes,
    "Test recvmsg_x() with messages having varying iov counts",
    T_META_TAG_VM_PREFERRED)
{
	int sockets[2];
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets),
	    "socketpair");

	/*
	 * Test pattern: 2, 8, 4, 16, 1, 10 iovs
	 * This exercises both increasing and decreasing iov counts
	 */
	const int iov_counts[] = {2, 8, 4, 16, 1, 10};
	const int num_msgs = sizeof(iov_counts) / sizeof(iov_counts[0]);

	/*
	 * Send packets
	 */
	char send_buffer[BUFFER_SIZE];
	memset(send_buffer, 'B', sizeof(send_buffer));

	for (int i = 0; i < num_msgs; i++) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(
			write(sockets[0], send_buffer, sizeof(send_buffer)),
			"write packet");
	}

	/*
	 * Allocate messages with varying iov counts
	 */
	struct msghdr_x *msgs = calloc(num_msgs, sizeof(struct msghdr_x));
	T_ASSERT_NOTNULL(msgs, "allocate message array");

	for (int i = 0; i < num_msgs; i++) {
		int iov_count = iov_counts[i];
		struct iovec *iovs = calloc(iov_count, sizeof(struct iovec));
		T_QUIET; T_ASSERT_NOTNULL(iovs, "allocate iovs for message");

		for (int j = 0; j < iov_count; j++) {
			iovs[j].iov_base = malloc(BUFFER_SIZE / iov_count);
			iovs[j].iov_len = BUFFER_SIZE / iov_count;
			T_QUIET; T_ASSERT_NOTNULL(iovs[j].iov_base, "allocate iov buffer");
		}

		msgs[i].msg_iov = iovs;
		msgs[i].msg_iovlen = iov_count;
		msgs[i].msg_flags = 0;
	}

	/*
	 * Call recvmsg_x with all messages
	 */
	T_LOG("Calling recvmsg_x with %d messages having varying iov counts", num_msgs);

	ssize_t received = recvmsg_x(sockets[1], msgs, num_msgs, 0);

	T_ASSERT_GE(received, 0L, "recvmsg_x should succeed");
	T_LOG("Successfully received %zd packets", received);

	for (int i = 0; i < received; i++) {
		T_LOG("Message %d: received %zu bytes with %u iovs",
		    i, msgs[i].msg_datalen, msgs[i].msg_iovlen);
	}

	/*
	 * Clean up
	 */
	for (int i = 0; i < num_msgs; i++) {
		for (int j = 0; j < (int)msgs[i].msg_iovlen; j++) {
			free(msgs[i].msg_iov[j].iov_base);
		}
		free(msgs[i].msg_iov);
	}
	free(msgs);

	close(sockets[0]);
	close(sockets[1]);

	T_PASS("Stress test completed without crash");
}
