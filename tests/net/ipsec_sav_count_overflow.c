/*
 * Copyright (c) 2019, 2025 Apple Inc. All rights reserved.
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
 * Test case for rdar://53415037
 * Tests IPsec security association (SA) count overflow handling
 */

#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfkeyv2.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_OWNER("fernandes")
	);

typedef struct {
	struct sadb_msg hdr;

	/* Required options */
	struct sadb_sa sa; /* SADB_EXT_SA */

	struct sadb_address address_src; /* SADB_EXT_ADDRESS_SRC */
	struct sockaddr_in sockaddr_src; /* 0x10 bytes */
	struct sadb_address address_dst; /* SADB_EXT_ADDRESS_DST */
	struct sockaddr_in sockaddr_dst; /* 0x10 bytes */

	struct sadb_key key;
	char key_material[128 / 8];
} msg_sa_t;

static msg_sa_t *
get_msg_sa(void)
{
	msg_sa_t *msg = malloc(sizeof(msg_sa_t));
	T_QUIET;
	T_ASSERT_NOTNULL(msg, "malloc msg_sa_t");

	memset(msg, 0, sizeof(msg_sa_t));

	msg->hdr.sadb_msg_version = PF_KEY_V2;
	msg->hdr.sadb_msg_type = SADB_ADD;
	msg->hdr.sadb_msg_satype = SADB_SATYPE_AH;
	msg->hdr.sadb_msg_len = sizeof(msg_sa_t) >> 3;
	msg->hdr.sadb_msg_pid = getpid();

	/* SADB_EXT_SA */
	msg->sa.sadb_sa_len = sizeof(msg->sa) >> 3;
	msg->sa.sadb_sa_exttype = SADB_EXT_SA;
	msg->sa.sadb_sa_auth = SADB_AALG_MD5HMAC; /* 128 bit key size */

	/* SADB_EXT_ADDRESS_SRC */
	msg->address_src.sadb_address_len = (sizeof(msg->address_src) + sizeof(msg->sockaddr_src)) >> 3;
	msg->address_src.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;

	msg->sockaddr_src.sin_len = 0x10;
	msg->sockaddr_src.sin_family = AF_INET;
	msg->sockaddr_src.sin_port = 4142;
	T_QUIET;
	T_ASSERT_EQ(inet_pton(AF_INET, "10.10.10.10", &msg->sockaddr_src.sin_addr), 1,
	    "inet_pton src");

	/* SADB_EXT_ADDRESS_DST */
	msg->address_dst.sadb_address_len = (sizeof(msg->address_dst) + sizeof(msg->sockaddr_dst)) >> 3;
	msg->address_dst.sadb_address_exttype = SADB_EXT_ADDRESS_DST;

	msg->sockaddr_dst.sin_len = 0x10;
	msg->sockaddr_dst.sin_family = AF_INET;
	msg->sockaddr_dst.sin_port = 4243;
	T_QUIET;
	T_ASSERT_EQ(inet_pton(AF_INET, "10.10.10.10", &msg->sockaddr_dst.sin_addr), 1,
	    "inet_pton dst");

	msg->key.sadb_key_exttype = SADB_EXT_KEY_AUTH;
	msg->key.sadb_key_len = (sizeof(struct sadb_key) + sizeof(msg->key_material)) >> 3;
	msg->key.sadb_key_bits = 128;

	return msg;
}

T_DECL(ipsec_sav_count_overflow,
    "test IPsec SA count overflow handling",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(60))
{
	size_t amount_to_send;
	ssize_t result;
	int fd;

	fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_KEY, SOCK_RAW, PF_KEY_V2)");

	msg_sa_t *msg_sa = get_msg_sa();

	/* Add first SA with full key material */
	amount_to_send = msg_sa->hdr.sadb_msg_len << 3;
	msg_sa->sa.sadb_sa_spi = 1;
	result = write(fd, msg_sa, amount_to_send);
	T_QUIET;
	T_EXPECT_EQ((size_t)result, amount_to_send, "write initial SA");

	/* Add many more SAs without key material to trigger overflow */
	msg_sa->hdr.sadb_msg_len = (sizeof(msg_sa_t) - 16) >> 3;
	msg_sa->key.sadb_key_len = sizeof(struct sadb_key) >> 3;
	msg_sa->key.sadb_key_bits = 0;
	amount_to_send = msg_sa->hdr.sadb_msg_len << 3;

	T_LOG("Adding 999 more SAs to test count overflow handling...");
	for (unsigned int i = 2; i <= 1000; i++) {
		msg_sa->sa.sadb_sa_spi = i;
		result = write(fd, msg_sa, amount_to_send);
		/* Some writes may fail as we approach limits - this is expected */
	}

	free(msg_sa);
	close(fd);

	T_PASS("ipsec_sav_count_overflow completed without crash");
}
