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
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <darwintest.h>
#include <string.h>
#include <unistd.h>

const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
#define s6_addr32 __u6_addr.__u6_addr32

static void
init_sin_address(struct sockaddr_in *sin)
{
	memset(sin, 0, sizeof(struct sockaddr_in));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
}

static void
init_sin6_address(struct sockaddr_in6 *sin6)
{
	memset(sin6, 0, sizeof(struct sockaddr_in6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
}

#if 0
static void
setnonblocking(int fd)
{
	int flags;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(flags = fcntl(fd, F_GETFL, 0), NULL);
	flags |= O_NONBLOCK;
	T_QUIET; T_EXPECT_POSIX_SUCCESS(flags = fcntl(fd, F_SETFL, flags), NULL);
}
#endif

static int
tcp_connect_v4(int fd, struct sockaddr_in *sin_to, int expected_error)
{
	int listen_fd = -1;

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	struct sockaddr_in sin;
	init_sin_address(&sin);
	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)), NULL);

	socklen_t socklen = sizeof(sin);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin.sin_port));
	sin_to->sin_port = sin.sin_port;

	T_ASSERT_POSIX_SUCCESS(listen(listen_fd, 10), NULL);

	int val = 1;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &val, sizeof(val)), NULL);

	T_LOG("connecting to sin_len: %u sin_family: %u sin_port: %u sin_addr: 0x%08x expected_error: %d",
	    sin_to->sin_len, sin_to->sin_family, ntohs(sin_to->sin_port), ntohl(sin_to->sin_addr.s_addr), expected_error);

	if (expected_error == 0) {
		T_EXPECT_POSIX_SUCCESS(connect(fd, (struct sockaddr *)sin_to, sizeof(struct sockaddr_in)), NULL);
	} else {
		T_EXPECT_POSIX_FAILURE(connect(fd, (struct sockaddr *)sin_to, sizeof(struct sockaddr_in)), expected_error, NULL);
	}
	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

static int
tcp_connect_v6(int c, struct sockaddr_in6 *sin6_to, int expected_error)
{
	int listen_fd = -1;

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	int off = 0;
	T_ASSERT_POSIX_SUCCESS(setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)), NULL);

	struct sockaddr_in6 sin6;
	init_sin6_address(&sin6);
	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	socklen_t socklen = sizeof(sin6);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin6, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin6.sin6_port));
	sin6_to->sin6_port = sin6.sin6_port;

	T_ASSERT_POSIX_SUCCESS(listen(listen_fd, 10), NULL);

	int val = 2;
	T_ASSERT_POSIX_SUCCESS(setsockopt(c, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &val, sizeof(val)), NULL);

	if (expected_error == 0) {
		T_EXPECT_POSIX_SUCCESS(connect(c, (struct sockaddr *)sin6_to, sizeof(struct sockaddr_in6)), NULL);
	} else {
		T_EXPECT_POSIX_FAILURE(connect(c, (struct sockaddr *)sin6_to, sizeof(struct sockaddr_in6)), expected_error, NULL);
	}
	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

T_DECL(tcp_bind_ipv4_loopback, "TCP bind with a IPv4 loopback address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin, sizeof(sin)), 0, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_loopback, "TCP connect with a IPv4 loopback address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_multicast, "TCP bind with a IPv4 multicast address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "224.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin, sizeof(sin)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_multicast, "TCP connect with an IPv4 multicast address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "224.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4__broadcast, "TCP with the IPv4 broadcast address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "255.255.255.255", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin, sizeof(sin)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4__broadcast, "TCP with the IPv4 broadcast address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "255.255.255.255", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_null, "TCP bind with the null IPv4 address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "0.0.0.0", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin, sizeof(sin)), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_null, "TCP bind with the null IPv4 address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "0.0.0.0", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv6_loopback, "TCP bind with the IPv6 loopback address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	init_sin6_address(&sin6);
	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv6_loopback, "TCP connect with the IPv6 loopback address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv6_multicast, "TCP bind with a IPv6 multicast address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "ff01::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv6_multicast, "TCP connect with a IPv6 multicast address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "ff01::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_null_ipv6, "TCP bind with the IPv6 null address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_null_ipv6, "TCP connect with the IPv6 null address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_multicast_mapped_ipv6, "TCP bind with IPv4 multicast mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_multicast_mapped_ipv6, "TCP connect with IPv4 multicast mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_broadcast_mapped_ipv6, "TCP bind with IPv4 broadcast mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_broadcast_mapped_ipv6, "TCP connect with IPv4 broadcast mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_null_mapped_ipv6, "TCP bind with IPv4 null mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_null_mapped_ipv6, "TCP connect with IPv4 null mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_multicast_compatible_ipv6, "TCP bind with IPv4 multicast compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_multicast_compatible_ipv6, "TCP connect with IPv4 multicast compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_broadcast_compatible_ipv6, "TCP bind with IPv4 broadcast compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_POSIX_FAILURE(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), EAFNOSUPPORT, NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_broadcast_compatible_ipv6, "TCP connect with IPv4 broadcast compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_null_compatible_ipv6, "TCP bind with IPv4 null compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_null_compatible_ipv6, "TCP connect with IPv4 null compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}
