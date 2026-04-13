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

/*
 * This test ensures that we don't modify ipv6 options while doing ip6_output.
 * Otherwise the system will panic due to memory corruption. The earlier fix
 * was to return EBUSY which wasn't correct. So this test checks for that too.
 */

#include <darwintest.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vidhi_goel")
	);

static int s;

static void
set_ip6_option(void)
{
	int ret;
	static unsigned buf[0x100] = {0};
	struct cmsghdr *ch = (struct cmsghdr *)buf;
	struct ip6_rthdr *rthdr;

	rthdr = (struct ip6_rthdr *)CMSG_DATA(ch);

	ch->cmsg_level = IPPROTO_IPV6;
	ch->cmsg_type = 51 /*IPV6_RTHDR*/;
	ch->cmsg_len = CMSG_LEN(0);
	rthdr->ip6r_type = IPV6_RTHDR_TYPE_0;
	rthdr->ip6r_len = 2;
	rthdr->ip6r_segleft = 1;

	/* Trigger a fresh in6p_outputopts alloc */
	ret = setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, ch, ch->cmsg_len);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "setsockopt IPV6_2292PKTOPTIONS (initial)");

	/* Trigger in6p_outputopts FREE(), without a new allocation - should return EINVAL */
	ret = setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, ch, 1);
	T_QUIET;
	T_ASSERT_POSIX_FAILURE(ret, EINVAL, "setsockopt IPV6_2292PKTOPTIONS (invalid)");
}

T_DECL(test_ipopts_with_sending,
    "test that IPv6 options are not modified during ip6_output",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120))
{
	uint8_t content[0x100] = {0};
	struct sockaddr_in6 dest;
	int ret;
	int i;

	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
	dest.sin6_port = htons(6666);
	inet_pton(AF_INET6, "::1", &(dest.sin6_addr));

	/* Get a UDP IPv6 socket */
	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)");

	/* Fork 2^3 processes */
	for (i = 0; i < 3; i++) {
		pid_t pid = fork();
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(pid, "fork");
	}

	/* Alternate between send and setsockopt */
	for (i = 0; i < 1000; i++) {
		if (i % 2 == 0) {
			/* Send */
			ret = (int)sendto(s, content, sizeof(content), 0,
			    (struct sockaddr *)&dest,
			    (socklen_t)sizeof(dest));
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(ret, "sendto");
		} else {
			/* Set IPv6 option */
			set_ip6_option();
		}
	}

	close(s);
	T_PASS("test_ipopts_with_sending completed without panic");
}
