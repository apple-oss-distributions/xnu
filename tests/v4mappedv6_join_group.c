/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
 *
 * Chris Jarrett-Davies <chrisjd@apple.com>
 * SEAR Red Team / 2024-Mar-20
 */

#include <darwintest.h>
#include <stdio.h>

#include <darwintest.h>

#include <string.h>
#include <strings.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ENABLED(!TARGET_OS_BRIDGE),
	T_META_CHECK_LEAKS(false));

T_DECL(v4mappedv6_join_group, "Tests setting IPV6_JOIN_GROUP on an IPv4-mapped IPv6 address")
{
	int s;
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_port = 1337
	};
	struct ipv6_mreq mreq = {};

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), "create socket");

	T_ASSERT_POSIX_SUCCESS(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), "inet_pton");
	T_ASSERT_POSIX_SUCCESS(connect(s, (const struct sockaddr *)&sin6, sizeof(sin6)), "connect");

	memset((unsigned char *)&mreq.ipv6mr_multiaddr, 0xff, 16);

	// This should now fail (but not panic)
	T_ASSERT_POSIX_FAILURE(setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)), EADDRNOTAVAIL, "setsockopt IPV6_JOIN_GROUP");
}
