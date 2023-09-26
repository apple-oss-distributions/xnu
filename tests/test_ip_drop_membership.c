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
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <netinet/in.h>

#include <err.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <darwintest.h>

/*
 * rdar://89640053 (Rome 22A201 - panic: assertion failed: RB_EMPTY(&imf->imf_sources))
 */

T_GLOBAL_META(T_META_NAMESPACE("xnu.net"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("networking"),
    T_META_ASROOT(true));

static void
print_mreq(const char *opt, struct ip_mreq *mreq)
{
	char *imr_multiaddr = strdup(inet_ntoa(mreq->imr_multiaddr));
	char *imr_interface = strdup(inet_ntoa(mreq->imr_interface));

	T_LOG("%s imr_multiaddr: %s imr_interface: %s",
	    opt, imr_multiaddr, imr_interface);

	free(imr_multiaddr);
	free(imr_interface);
}

static void
print_mreq_src(const char *opt, struct ip_mreq_source *mreq_src)
{
	char *imr_multiaddr = strdup(inet_ntoa(mreq_src->imr_multiaddr));
	char *imr_sourceaddr = strdup(inet_ntoa(mreq_src->imr_sourceaddr));
	char *imr_interface = strdup(inet_ntoa(mreq_src->imr_interface));

	T_LOG("%s imr_multiaddr: %s imr_sourceaddr: %s imr_interface: %s",
	    opt, imr_multiaddr, imr_sourceaddr, imr_interface);

	free(imr_multiaddr);
	free(imr_sourceaddr);
	free(imr_interface);
}

static void
test_ip_drop_membership(uint32_t max)
{
	uint32_t maddr = 0xef000000; /* 239.0.0.0 */
	int fd;

	if (max == 0) {
		max = 1;
	}

	fd = socket(AF_INET, SOCK_RAW, 1);
	if (fd < 0) {
		T_ASSERT_POSIX_SUCCESS(-1, "socket(AF_INET, SOCK_DGRAM, 1)");
	}

	for (uint32_t i = 0; i < max; i++) {
		struct ip_mreq mreq = {};
		struct ip_mreq_source mreq_src = {};

		maddr += 1;

		mreq.imr_multiaddr.s_addr = htonl(maddr);
		mreq.imr_interface.s_addr = htonl(INADDR_LOOPBACK);

		print_mreq("IP_ADD_MEMBERSHIP", &mreq);
		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) == -1) {
			/*
			 * The call is expected to fail when we reach the limit of membership
			 * and when the device does not have an IP address
			 */
			if (errno == ETOOMANYREFS || errno == EADDRNOTAVAIL || errno == ENOMEM) {
				T_LOG("setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP) %s", strerror(errno));
				break;
			}
			T_ASSERT_POSIX_SUCCESS(-1, "setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP)");
		}

		maddr += 1;

		mreq_src.imr_multiaddr.s_addr = htonl(maddr);
		mreq_src.imr_sourceaddr.s_addr = htonl(INADDR_LOOPBACK);
		mreq_src.imr_interface.s_addr = htonl(INADDR_LOOPBACK);

		print_mreq_src("IP_ADD_SOURCE_MEMBERSHIP", &mreq_src);

		if (setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, (void *)&mreq_src, sizeof(mreq_src)) == -1) {
			if (errno == ETOOMANYREFS || errno == EADDRNOTAVAIL || errno == ENOMEM) {
				T_LOG("setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP) %s", strerror(errno));
				break;
			}
			T_ASSERT_POSIX_SUCCESS(-1, "setsockopt(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP)");
		}

		print_mreq("IP_DROP_MEMBERSHIP", &mreq);
		if (setsockopt(fd, 0, IP_DROP_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) == -1) {
			T_ASSERT_POSIX_SUCCESS(-1, "setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP)");
		}

		print_mreq("IP_ADD_MEMBERSHIP", &mreq);
		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) == -1) {
			if (errno == ETOOMANYREFS || errno == EADDRNOTAVAIL) {
				T_LOG("setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP) %s", strerror(errno));
				break;
			}
			T_ASSERT_POSIX_SUCCESS(-1, "setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP)");
		}
	}
	close(fd);
}

T_DECL(ip_drop_membership, "test IP_DROP_MEMBERSHIP")
{
	test_ip_drop_membership(0xffff);

	T_PASS("ip_drop_membership");
}
