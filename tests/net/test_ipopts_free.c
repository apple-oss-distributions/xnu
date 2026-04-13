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
 * Test for IPv6 output options race condition
 *
 * This test races setsockopt() on IPv6_2292PKTOPTIONS with sendto()
 * to verify that in6p_outputopts is properly protected against use-after-free.
 */

#include <darwintest.h>

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <pthread.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vidhi_goel")
	);

static int s;

static void *
loop(void *arg)
{
	static unsigned buf[0x100] = {0};
	struct cmsghdr *ch = (struct cmsghdr *)buf;
	struct ip6_rthdr *rthdr;

	rthdr = (struct ip6_rthdr *)CMSG_DATA(ch);

	ch->cmsg_level = IPPROTO_IPV6;
	ch->cmsg_type = 51; /* IPV6_RTHDR */
	ch->cmsg_len = CMSG_LEN(0);
	rthdr->ip6r_type = IPV6_RTHDR_TYPE_0;
	rthdr->ip6r_len = 2;
	rthdr->ip6r_segleft = 1;

	for (int i = 0; i < 1000; i++) {
		/* Trigger fresh in6p_outputopts alloc */
		int ret = setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, ch, ch->cmsg_len);
		if (ret < 0) {
			T_LOG("setsockopt failed: %s", strerror(errno));
		}

		/* Trigger in6p_outputopts FREE() without new allocation */
		ret = setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, ch, 1);
		if (ret < 0 && errno != EINVAL) {
			T_LOG("setsockopt clear failed: %s", strerror(errno));
		}
	}

	return NULL;
}

T_DECL(test_ipopts_free,
    "test IPv6 output options racing with sendto",
    T_META_CHECK_LEAKS(false))
{
	uint8_t content[0x100] = {0};
	pthread_t other_thread;
	struct sockaddr_in6 sdest;

	/* Get a UDP IPv6 socket */
	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)");

	/* Spawn racing thread */
	T_ASSERT_POSIX_ZERO(pthread_create(&other_thread, NULL, loop, NULL), "pthread_create");

	/* Keep sending packets */
	T_LOG("Starting send loop...");
	for (int i = 0; i < 1000; i++) {
		memset(&sdest, 0, sizeof(sdest));
		sdest.sin6_family = AF_INET6;
		sdest.sin6_port = htons(6666);
		T_QUIET;
		T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &(sdest.sin6_addr)), 1, "inet_pton");

		/* Invoke kernel IP/UDP stack for sending */
		ssize_t ret = sendto(s, content, sizeof(content), 0,
		    (struct sockaddr *)&sdest, (socklen_t)sizeof(sdest));
		if (ret < 0) {
			T_LOG("sendto failed: %s", strerror(errno));
		}
	}

	T_ASSERT_POSIX_ZERO(pthread_join(other_thread, NULL), "pthread_join");

	close(s);

	T_PASS("test_ipopts_free completed without crash");
}
