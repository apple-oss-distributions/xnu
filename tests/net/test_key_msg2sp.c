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
 * Test for key_msg2sp IPsec policy parsing (rdar://54972804)
 */

#include <darwintest.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netinet6/ipsec.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

T_DECL(test_key_msg2sp,
    "test IP_IPSEC_POLICY with malformed sockaddr (rdar://54972804)",
    T_META_CHECK_LEAKS(false))
{
	int s;
	uint8_t buf[
		sizeof(struct sadb_x_policy) +
		sizeof(struct sadb_x_ipsecrequest) +
		8
	];
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)buf;
	struct sadb_x_ipsecrequest *xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);
	struct sockaddr *sa;
	int ret;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)");

	bzero(buf, sizeof(buf));

	/* xpl */
	xpl->sadb_x_policy_len = sizeof(buf) >> 3;
	xpl->sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	xpl->sadb_x_policy_type = IPSEC_POLICY_IPSEC;

	/* xisr */
	xisr->sadb_x_ipsecrequest_len = sizeof(buf) - sizeof(*xpl);
	xisr->sadb_x_ipsecrequest_proto = IPPROTO_ESP;
	xisr->sadb_x_ipsecrequest_mode = IPSEC_MODE_TRANSPORT;
	xisr->sadb_x_ipsecrequest_level = IPSEC_LEVEL_DEFAULT;

	/* src sockaddr */
	sa = (struct sockaddr *)(xisr + 1);
	sa->sa_len = 7;

	/* dst sockaddr */
	sa = (struct sockaddr *)((void *)(xisr + 1) + sa->sa_len);
	sa->sa_len = xisr->sadb_x_ipsecrequest_len - 7;

	T_LOG("Testing IP_IPSEC_POLICY with malformed sockaddr lengths");
	ret = setsockopt(s, IPPROTO_IP, IP_IPSEC_POLICY, buf, sizeof(buf));
	T_EXPECT_EQ(ret, -1, "setsockopt should fail with malformed sockaddr");

	/* Test with correct parameters */
	xpl->sadb_x_policy_len = (sizeof(*xpl) + sizeof(*xisr)) >> 3;
	xisr->sadb_x_ipsecrequest_len = sizeof(*xisr);

	T_LOG("Testing IP_IPSEC_POLICY with correct parameters");
	ret = setsockopt(s, IPPROTO_IP, IP_IPSEC_POLICY, buf, sizeof(*xpl) + sizeof(*xisr));
	T_EXPECT_EQ(ret, 0, "setsockopt should succeed with correct parameters");

	close(s);

	T_PASS("test_key_msg2sp completed");
}
