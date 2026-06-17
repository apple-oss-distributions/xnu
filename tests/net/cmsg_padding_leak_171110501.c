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

/*
 * Regression test for rdar://171110501
 *
 * sbcreatecontrol() and sbcreatecontrol_mbuf() were missing a bzero() before
 * memcpy()-ing the payload into the cmsghdr.  The control message buffer is
 * CMSG_SPACE(size) bytes long but only 'size' payload bytes were written,
 * leaving the alignment-padding bytes uninitialized with whatever happened to
 * be in the mbuf heap at the time.
 *
 * IP_RECVTOS and IP_RECVTTL are the most convenient triggers: both pass a
 * single u_char (1 byte) as the payload, while CMSG_SPACE(1) is 16 bytes on
 * all current Darwin platforms (12-byte aligned cmsghdr + 4-byte aligned
 * payload slot).  That means 3 bytes of uninitialized kernel heap were
 * readable by the recipient of every UDP datagram on a socket with
 * IP_RECVTOS or IP_RECVTTL enabled.
 *
 * The fix adds  bzero(cp, CMSG_SPACE(size))  before the memcpy in both
 * sbcreatecontrol() and sbcreatecontrol_mbuf().  This test verifies the fix
 * by confirming the padding bytes are zero.
 *
 * Test strategy
 * -------------
 *   1. Create a loopback UDP socket pair.
 *   2. Enable IP_RECVTOS and IP_RECVTTL on the receiver.
 *   3. Send a single byte payload from sender to receiver.
 *   4. recvmsg() on the receiver; walk every cmsghdr.
 *   5. For each cmsghdr, check that the bytes between
 *          CMSG_DATA(cm) + (cm->cmsg_len - CMSG_LEN(0))   (end of payload)
 *      and
 *          (uint8_t *)cm + CMSG_SPACE(cm->cmsg_len - CMSG_LEN(0))  (end of slot)
 *      are all zero.  Non-zero bytes in that range indicate a kernel heap leak.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

/*
 * Number of datagrams to send/receive.  Sending several messages gives the
 * allocator a chance to reuse mbufs with stale data, making the leak more
 * reliably detectable.
 */
#define NMSGS 64

/*
 * check_cmsg_padding - walk every cmsghdr in msg and verify that alignment
 * padding bytes following the payload are zero.
 *
 * Returns true if all padding bytes are zero (no leak), false otherwise.
 */
static bool
check_cmsg_padding(struct msghdr *msg, char *errbuf, size_t errbuflen)
{
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(msg);
	    cm != NULL;
	    cm = CMSG_NXTHDR(msg, cm)) {
		/*
		 * cmsg_len is CMSG_LEN(payload_size), i.e.
		 *   align32(sizeof(cmsghdr)) + payload_size
		 * So payload_size = cmsg_len - CMSG_LEN(0).
		 */
		if (cm->cmsg_len < CMSG_LEN(0)) {
			/* Malformed control message – skip. */
			continue;
		}
		size_t payload_size = cm->cmsg_len - CMSG_LEN(0);
		size_t slot_size    = CMSG_SPACE(payload_size);

		/*
		 * Bytes [cmsg_len .. slot_size) relative to the start of the
		 * cmsghdr are the alignment padding that must be zero.
		 */
		const uint8_t *base    = (const uint8_t *)cm;
		size_t         pad_off = cm->cmsg_len;   /* first padding byte */
		size_t         pad_end = slot_size;       /* one past last */

		for (size_t i = pad_off; i < pad_end; i++) {
			if (base[i] != 0) {
				snprintf(errbuf, errbuflen,
				    "cmsg level=%d type=%d: padding byte at "
				    "offset %zu (relative to cmsghdr) is 0x%02x, "
				    "expected 0x00 -- kernel heap leak",
				    cm->cmsg_level, cm->cmsg_type,
				    i, base[i]);
				return false;
			}
		}
	}
	return true;
}

static void
run_test(int opt, const char *opt_name)
{
	int sv = -1, rv = -1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port   = 0,
		.sin_addr   = { .s_addr = htonl(INADDR_LOOPBACK) },
	};
	socklen_t addrlen = sizeof(addr);

	/* ---- create sender and receiver ---------------------------------- */
	rv = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(rv, "socket(receiver)");
	int rsock = rv;

	sv = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(sv, "socket(sender)");
	int ssock = sv;

	/* Bind receiver to an ephemeral port on loopback. */
	T_ASSERT_POSIX_SUCCESS(
		bind(rsock, (struct sockaddr *)&addr, sizeof(addr)),
		"bind(receiver)");
	T_ASSERT_POSIX_SUCCESS(
		getsockname(rsock, (struct sockaddr *)&addr, &addrlen),
		"getsockname(receiver)");

	/* Enable the option under test on the receiver. */
	int one = 1;
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(rsock, IPPROTO_IP, opt, &one, sizeof(one)),
		"setsockopt(%s)", opt_name);

	/* ---- send / recv loop -------------------------------------------- */
	uint8_t sndbuf = 0xAB;  /* arbitrary payload byte */

	/*
	 * Control-message buffer sized for at least two CMSG_SPACE(sizeof(u_char))
	 * entries plus a bit of headroom.
	 */
	uint8_t ctrlbuf[256];
	char    errbuf[256];

	for (int i = 0; i < NMSGS; i++) {
		/* Send one byte to the receiver. */
		ssize_t nsent = sendto(ssock, &sndbuf, sizeof(sndbuf), 0,
		    (struct sockaddr *)&addr, addrlen);
		T_ASSERT_EQ((int)nsent, (int)sizeof(sndbuf), "sendto [%d]", i);

		/* Receive with control messages. */
		uint8_t       rcvbuf = 0;
		struct iovec  iov    = { .iov_base = &rcvbuf, .iov_len = sizeof(rcvbuf) };

		/*
		 * Poison the control buffer with 0xFF so that any uninitialized
		 * byte coming from the kernel is immediately distinguishable from
		 * a legitimately zeroed byte.
		 */
		memset(ctrlbuf, 0xFF, sizeof(ctrlbuf));

		struct msghdr msg = {
			.msg_iov        = &iov,
			.msg_iovlen     = 1,
			.msg_control    = ctrlbuf,
			.msg_controllen = sizeof(ctrlbuf),
		};

		ssize_t nrecv = recvmsg(rsock, &msg, 0);
		T_ASSERT_POSIX_SUCCESS((int)nrecv, "recvmsg [%d]", i);
		T_ASSERT_EQ((int)nrecv, (int)sizeof(rcvbuf),
		    "recvmsg returned expected payload length [%d]", i);

		/* Confirm we actually got a control message. */
		T_ASSERT_NOTNULL(CMSG_FIRSTHDR(&msg),
		    "recvmsg returned at least one cmsghdr [%d]", i);

		/* Check padding. */
		bool ok = check_cmsg_padding(&msg, errbuf, sizeof(errbuf));
		T_EXPECT_TRUE(ok, "cmsg padding zeroed [%d]: %s", i,
		    ok ? "ok" : errbuf);
	}

	close(rsock);
	close(ssock);
}

T_DECL(cmsg_padding_recvtos,
    "IP_RECVTOS cmsg padding must not leak kernel heap (rdar://171110501)",
    T_META_ASROOT(false))
{
	run_test(IP_RECVTOS, "IP_RECVTOS");
}

T_DECL(cmsg_padding_recvttl,
    "IP_RECVTTL cmsg padding must not leak kernel heap (rdar://171110501)",
    T_META_ASROOT(false))
{
	run_test(IP_RECVTTL, "IP_RECVTTL");
}
