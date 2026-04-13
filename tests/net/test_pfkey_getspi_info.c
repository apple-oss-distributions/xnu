/*
 * Copyright (c) 2020, 2025 Apple Inc. All rights reserved.
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
 * Test for PF_KEY SADB_GETSPI information disclosure vulnerability
 * (rdar://60632911)
 *
 * Tests that SADB_GETSPI responses do not leak uninitialized kernel memory
 * in the sadb_sa structure fields.
 */

#include <darwintest.h>

#include <net/pfkeyv2.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <netinet6/ipsec.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <unistd.h>
#include <string.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("fernandes")
	);

#define MAX_60632911_CHECK 10000

static int test_sock = -1;
static int counter = 0;
static dispatch_source_t pfkey_source = NULL;

static void
send_pfkey_message(int sock)
{
	uint8_t payload[MCLBYTES];
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	/* Build SADB_GETSPI message */
	struct sadb_msg *msg = (struct sadb_msg *)payload;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_GETSPI;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_satype = SADB_SATYPE_ESP;
	msg->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg->sadb_msg_reserved = 0;
	msg->sadb_msg_seq = 0;
	msg->sadb_msg_pid = getpid();
	tlen += sizeof(*msg);

	/* Add SA2 extension */
	struct sadb_x_sa2 *sa2 = (struct sadb_x_sa2 *)(payload + tlen);
	sa2->sadb_x_sa2_len = PFKEY_UNIT64(sizeof(*sa2));
	sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2->sadb_x_sa2_mode = IPSEC_MODE_TRANSPORT;
	sa2->sadb_x_sa2_reqid = 0;
	tlen += sizeof(*sa2);

	/* Add source address */
	struct sadb_address *src_addr = (struct sadb_address *)(payload + tlen);
	src_addr->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	src_addr->sadb_address_proto = IPSEC_ULPROTO_ANY;
	src_addr->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	src_addr->sadb_address_reserved = 0;
	tlen += sizeof(*src_addr);

	struct sockaddr_in *src = (struct sockaddr_in *)(payload + tlen);
	inet_pton(AF_INET, "192.168.2.2", &src->sin_addr);
	src->sin_family = AF_INET;
	src->sin_len = sizeof(*src);
	uint16_t len = sizeof(*src_addr) + PFKEY_ALIGN8(src->sin_len);
	src_addr->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(src->sin_len);

	/* Add destination address */
	struct sadb_address *dst_addr = (struct sadb_address *)(payload + tlen);
	dst_addr->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	dst_addr->sadb_address_proto = IPSEC_ULPROTO_ANY;
	dst_addr->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	dst_addr->sadb_address_reserved = 0;
	tlen += sizeof(*dst_addr);

	struct sockaddr_in *dst = (struct sockaddr_in *)(payload + tlen);
	inet_pton(AF_INET, "192.168.2.3", &dst->sin_addr);
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	len = sizeof(*dst_addr) + PFKEY_ALIGN8(dst->sin_len);
	dst_addr->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(dst->sin_len);

	/* Update total length */
	msg->sadb_msg_len = PFKEY_UNIT64(tlen);

	ssize_t ret = send(sock, payload, PFKEY_UNUNIT64(msg->sadb_msg_len), 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "send SADB_GETSPI message");
}

static void
process_pfkey_response(uint8_t **mhp)
{
	struct sadb_msg *msg = (struct sadb_msg *)mhp[0];

	/* Check for error messages from any PF_KEY message type */
	if (msg->sadb_msg_errno) {
		T_FAIL("PFKey message error (type %d): %s",
		    msg->sadb_msg_type, strerror(msg->sadb_msg_errno));
		if (pfkey_source) {
			dispatch_source_cancel(pfkey_source);
		}
		T_END;
	}

	/* Only process SADB_GETSPI responses to our messages */
	if (msg->sadb_msg_type != SADB_GETSPI ||
	    msg->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	/* Check SA extension for information disclosure */
	struct sadb_sa *sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	if (sa) {
		/* These fields should be zero in GETSPI response */
		T_QUIET;
		T_EXPECT_EQ(sa->sadb_sa_replay, 0, "sadb_sa_replay should be zero");
		T_QUIET;
		T_EXPECT_EQ(sa->sadb_sa_state, 0, "sadb_sa_state should be zero");
		T_QUIET;
		T_EXPECT_EQ(sa->sadb_sa_auth, 0, "sadb_sa_auth should be zero");
		T_QUIET;
		T_EXPECT_EQ(sa->sadb_sa_encrypt, 0, "sadb_sa_encrypt should be zero");
		T_QUIET;
		T_EXPECT_EQ(sa->sadb_sa_flags, 0, "sadb_sa_flags should be zero");

		if (sa->sadb_sa_replay != 0 ||
		    sa->sadb_sa_state != 0 ||
		    sa->sadb_sa_auth != 0 ||
		    sa->sadb_sa_encrypt != 0 ||
		    sa->sadb_sa_flags != 0) {
			T_FAIL("Information disclosure vulnerability rdar://60632911 detected");
			if (pfkey_source) {
				dispatch_source_cancel(pfkey_source);
			}
			T_END;
		}
	}

	counter++;
	if (counter < MAX_60632911_CHECK) {
		send_pfkey_message(test_sock);
	} else {
		T_PASS("No information disclosure detected after %d iterations", counter);
		if (pfkey_source) {
			dispatch_source_cancel(pfkey_source);
		}
		T_END;
	}
}

static int
pfkey_align(struct sadb_msg *msg, uint8_t **mhp, int mhp_size)
{
	struct sadb_ext *ext;

	caddr_t p;
	caddr_t ep;

	if (msg == NULL || mhp == NULL) {
		return -1;
	}

	/* Initialize */
	for (int i = 0; i < mhp_size; i++) {
		mhp[i] = NULL;
	}
	mhp[0] = (uint8_t *)msg;

	p = (caddr_t)msg;
	ep = p + PFKEY_UNUNIT64(msg->sadb_msg_len);
	p += sizeof(struct sadb_msg);

	while (p < ep) {
		ext = (struct sadb_ext *)p;
		if (ep < p + sizeof(*ext) || (size_t)PFKEY_EXTLEN(ext) < sizeof(*ext) ||
		    ep < p + PFKEY_EXTLEN(ext)) {
			break;
		}

		/* Check for duplicate extensions */
		/* XXX Are there duplication either KEY_AUTH or KEY_ENCRYPT ?*/
		if (ext->sadb_ext_type < mhp_size && mhp[ext->sadb_ext_type] != NULL) {
			T_LOG("Duplicate extension type %u", ext->sadb_ext_type);
			return -1;
		}

		/* Validate extension type */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_POLICY:
		case SADB_X_EXT_SA2:
		case SADB_EXT_SESSION_ID:
		case SADB_EXT_SASTAT:
#ifdef SADB_X_EXT_NAT_T_TYPE
		case SADB_X_EXT_NAT_T_TYPE:
		case SADB_X_EXT_NAT_T_SPORT:
		case SADB_X_EXT_NAT_T_DPORT:
		case SADB_X_EXT_NAT_T_OA:
#endif
#ifdef SADB_X_EXT_TAG
		case SADB_X_EXT_TAG:
#endif
#ifdef SADB_X_EXT_PACKET
		case SADB_X_EXT_PACKET:
#endif
		case SADB_X_EXT_IPSECIF:
		case SADB_X_EXT_ADDR_RANGE_SRC_START:
		case SADB_X_EXT_ADDR_RANGE_SRC_END:
		case SADB_X_EXT_ADDR_RANGE_DST_START:
		case SADB_X_EXT_ADDR_RANGE_DST_END:
#ifdef SADB_MIGRATE
		case SADB_EXT_MIGRATE_ADDRESS_SRC:
		case SADB_EXT_MIGRATE_ADDRESS_DST:
		case SADB_X_EXT_MIGRATE_IPSECIF:
#endif
			mhp[ext->sadb_ext_type] = (void *)ext;
			break;
		default:
			T_LOG("Invalid extension type %u", ext->sadb_ext_type);
			return -1;
		}

		p += PFKEY_EXTLEN(ext);
	}

	return (p != ep) ? -1 : 0;
}


static void
recv_pfkey_message(int sock)
{
	uint8_t buffer[8192];
	struct iovec iovecs[1] = {
		{ buffer, sizeof(buffer) },
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iovecs,
		.msg_iovlen = sizeof(iovecs) / sizeof(iovecs[0]),
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	ssize_t result;

	do {
		memset(buffer, 0, sizeof(buffer));
		result = recvmsg(sock, &msg, 0);

		if (result > 0) {
			if (result < (ssize_t)sizeof(struct sadb_msg)) {
				T_LOG("Invalid PFKey message size: %zd", result);
				continue;
			}

			struct sadb_msg *hdr = (struct sadb_msg *)buffer;
			uint8_t *mhp[SADB_EXT_MAX + 1];

			if (pfkey_align(hdr, mhp, SADB_EXT_MAX + 1) == 0) {
				process_pfkey_response(mhp);
			}
		} else if (result == 0) {
			break;
		} else {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				T_LOG("recv error: %s", strerror(errno));
			}
			break;
		}
	} while (result > 0);
}

T_DECL(test_pfkey_getspi_info,
    "test PF_KEY SADB_GETSPI information disclosure (rdar://60632911)",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120))
{
	int bufsiz;
	unsigned long oldmax, newmax;
	size_t oldmaxsize = sizeof(oldmax);
	const unsigned long newbufk = 1536;

	test_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	T_ASSERT_POSIX_SUCCESS(test_sock, "socket(PF_KEY, SOCK_RAW, PF_KEY_V2)");

	/* Try to increase socket buffer size */
	newmax = newbufk * (1024 + 128);
	if (sysctlbyname("kern.ipc.maxsockbuf", &oldmax, &oldmaxsize,
	    &newmax, sizeof(newmax)) != 0) {
		bufsiz = 233016;
	} else {
		bufsiz = newbufk * 1024;
	}

	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(setsockopt(test_sock, SOL_SOCKET, SO_SNDBUF,
	    &bufsiz, sizeof(bufsiz)), "set SO_SNDBUF");
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(setsockopt(test_sock, SOL_SOCKET, SO_RCVBUF,
	    &bufsiz, sizeof(bufsiz)), "set SO_RCVBUF");

	/* Set socket to non-blocking */
	int value = 1;
	T_ASSERT_POSIX_SUCCESS(ioctl(test_sock, FIONBIO, &value),
	    "set socket non-blocking");

	/* Create dispatch source for reading responses */
	pfkey_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
	    test_sock, 0, dispatch_get_main_queue());
	T_ASSERT_NOTNULL(pfkey_source, "dispatch_source_create");

	dispatch_source_set_cancel_handler(pfkey_source, ^{
		if (test_sock >= 0) {
		        close(test_sock);
		        test_sock = -1;
		}
	});

	dispatch_source_set_event_handler(pfkey_source, ^{
		recv_pfkey_message(test_sock);
	});

	dispatch_resume(pfkey_source);

	send_pfkey_message(test_sock);

	/* Run dispatch loop */
	dispatch_main();
}
