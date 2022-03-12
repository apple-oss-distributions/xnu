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

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <darwintest.h>

static in_port_t listener_port;

static void
tcp_listen(void)
{
	int s = -1;

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, 0), NULL);

	struct sockaddr_in6 sin6 = {};
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	T_ASSERT_POSIX_SUCCESS(bind(s, (struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	socklen_t solen = sizeof(sin6);
	T_ASSERT_POSIX_SUCCESS(getsockname(s, (struct sockaddr *)&sin6, &solen), NULL);

	listener_port = sin6.sin6_port;

	T_ASSERT_POSIX_SUCCESS(listen(s, 128), NULL);
}

static void
set_udp_kao_opt(int expected_errno, int domain, const char *domain_str,
    int type, const char *type_str,
    int proto, const char *proto_str)
{
	T_LOG("expect error %d for socket domain: %s type: %s protocol: %s",
	    expected_errno, domain_str, type_str, proto_str);

	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(domain, type, proto), NULL);

	union sockaddr_in_4_6 sa = {};

	if (domain == PF_INET) {
		sa.sin.sin_len = sizeof(struct sockaddr_in);
		sa.sin.sin_family = AF_INET;
		sa.sin.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
		sa.sin.sin_port = listener_port;
	} else {
		sa.sin6.sin6_len = sizeof(struct sockaddr_in6);
		sa.sin6.sin6_family = AF_INET6;
		sa.sin6.sin6_addr = in6addr_loopback;
		sa.sin6.sin6_port = listener_port;
	}

	/*
	 * Keep alive option needs a connected flow
	 */
	T_ASSERT_POSIX_SUCCESS(connect(s, &sa.sa, sa.sa.sa_len), NULL);

	/*
	 * UDP_KEEPALIVE_OFFLOAD should only succeed for UDP sockets
	 */
	struct udp_keepalive_offload keepAliveInfo = {};
	keepAliveInfo.ka_interval = 1;
	keepAliveInfo.ka_data_len = 1;
	keepAliveInfo.ka_type = UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY;

	if (expected_errno == 0) {
		T_ASSERT_POSIX_SUCCESS(setsockopt(s, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		    &keepAliveInfo, sizeof(keepAliveInfo)),
		    "setsockopt IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD");
	} else {
		T_ASSERT_POSIX_FAILURE(setsockopt(s, IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD,
		    &keepAliveInfo, sizeof(keepAliveInfo)), expected_errno,
		    "setsockopt IPPROTO_UDP, UDP_KEEPALIVE_OFFLOAD");
	}

	/*
	 * Verify that network layer options can be set
	 */
	int optval = 10;
	if (domain == PF_INET) {
		T_ASSERT_POSIX_SUCCESS(setsockopt(s, IPPROTO_IP, IP_TTL,
		    &optval, sizeof(optval)), "setsockopt IPPROTO_IP, IP_TTL");
	} else {
		T_ASSERT_POSIX_SUCCESS(setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
		    &optval, sizeof(optval)), "setsockopt IPPROTO_IPV6, IPV6_UNICAST_HOPS");
	}

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

#define SET_UDP_KAO_OPT(e, d, t, p) set_udp_kao_opt(e, d, #d, t, #t, p, #p)

T_DECL(test_udp_keep_alive_option, "TCP bind with a IPv6 multicast address")
{
	tcp_listen();

	SET_UDP_KAO_OPT(0, PF_INET6, SOCK_DGRAM, 0);
	SET_UDP_KAO_OPT(0, PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	SET_UDP_KAO_OPT(EINVAL, PF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	SET_UDP_KAO_OPT(EINVAL, PF_INET6, SOCK_STREAM, 0);

	SET_UDP_KAO_OPT(0, PF_INET, SOCK_DGRAM, 0);
	SET_UDP_KAO_OPT(0, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	SET_UDP_KAO_OPT(EINVAL, PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	SET_UDP_KAO_OPT(EINVAL, PF_INET, SOCK_STREAM, 0);
}
