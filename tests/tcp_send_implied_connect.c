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

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <darwintest.h>
#include <string.h>
#include <unistd.h>

#define MAX_IPv6_STR_LEN        64

static char l_addr_str[MAX_IPv6_STR_LEN];
static char f_addr_str[MAX_IPv6_STR_LEN];

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

static int
tcp_send_implied_connect_v4(int client_fd, struct sockaddr_in *sin_to, int expected_error)
{
	int listen_fd = -1;
	socklen_t socklen;
	int val = 10;
	struct sockaddr_in sin_local = {};
	struct sockaddr_in sin_peer = {};
	struct sockaddr_in sin;

	init_sin_address(&sin);
	init_sin_address(&sin_local);
	init_sin_address(&sin_peer);

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)), NULL);

	socklen = sizeof(sin);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin.sin_port));
	sin_to->sin_port = sin.sin_port;

	T_ASSERT_POSIX_SUCCESS(listen(listen_fd, 10), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(client_fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &val, sizeof(val)), NULL);

	T_LOG("sendmsg with sin_len: %u sin_family: %u sin_port: %u sin_addr: 0x%08x expected_error: %d",
	    sin_to->sin_len, sin_to->sin_family, ntohs(sin_to->sin_port), ntohl(sin_to->sin_addr.s_addr), expected_error);

	struct iovec iovec = { .iov_base = "", .iov_len = 0 };
	struct msghdr msg = {};
	struct cmsghdr *cmsghdrp;
	char buf[CMSG_SPACE(sizeof(int))];

	msg.msg_name = sin_to;
	msg.msg_namelen = sin_to->sin_len;
	msg.msg_iov = &iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	cmsghdrp = CMSG_FIRSTHDR(&msg);
	cmsghdrp->cmsg_len = CMSG_LEN(sizeof(int));
	cmsghdrp->cmsg_level = SOL_SOCKET;
	cmsghdrp->cmsg_type = SCM_RIGHTS;

	memcpy(CMSG_DATA(cmsghdrp), &client_fd, sizeof(client_fd));

	ssize_t retval = sendmsg(client_fd, &msg, 0);

	if (expected_error == 0) {
		T_EXPECT_POSIX_SUCCESS(retval, "sendmsg(client_fd, &msg, 0)");
	} else {
		T_EXPECT_POSIX_FAILURE(retval, expected_error, "sendmsg(client_fd, &msg, 0)");
	}

	if (retval == 0) {
		socklen = sizeof(sin_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin_local, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_local.sin_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin_peer);
		T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin_peer, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_peer.sin_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin_local.sin_port),
		    f_addr_str, ntohs(sin_peer.sin_port));
	}

	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

static int
tcp_send_implied_connect_v6(int client_fd, struct sockaddr_in6 *sin6_to, int expected_error)
{
	int listen_fd = -1;
	socklen_t socklen;
	int off = 0;
	int val = 10;
	struct iovec iovec = { .iov_base = "", .iov_len = 0 };
	struct msghdr msg = {};
	struct cmsghdr *cmsghdrp;
	char buf[CMSG_SPACE(sizeof(int))];
	struct sockaddr_in6 sin6_local = {};
	struct sockaddr_in6 sin6_peer = {};
	struct sockaddr_in6 sin6;

	init_sin6_address(&sin6);
	init_sin6_address(&sin6_local);
	init_sin6_address(&sin6_peer);

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	socklen = sizeof(sin6);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin6, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin6.sin6_port));
	sin6_to->sin6_port = sin6.sin6_port;

	T_ASSERT_POSIX_SUCCESS(listen(listen_fd, 10), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(client_fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &val, sizeof(val)), NULL);

	msg.msg_name = sin6_to;
	msg.msg_namelen = sin6_to->sin6_len;
	msg.msg_iov = &iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	cmsghdrp = CMSG_FIRSTHDR(&msg);
	cmsghdrp->cmsg_len = CMSG_LEN(sizeof(int));
	cmsghdrp->cmsg_level = SOL_SOCKET;
	cmsghdrp->cmsg_type = SCM_RIGHTS;

	memcpy(CMSG_DATA(cmsghdrp), &client_fd, sizeof(client_fd));

	(void)inet_ntop(AF_INET6, &sin6_to->sin6_addr, l_addr_str, sizeof(l_addr_str));

	T_LOG("sendmsg with sin6_len: %u sin6_family: %u sin6_port: %u sin6_addr: %s expected_error: %d",
	    sin6_to->sin6_len, sin6_to->sin6_family, ntohs(sin6_to->sin6_port), l_addr_str, expected_error);

	ssize_t retval = sendmsg(client_fd, &msg, 0);

	if (expected_error == 0) {
		T_EXPECT_POSIX_SUCCESS(retval, "sendmsg(client_fd, &msg, 0)");
	} else {
		T_EXPECT_POSIX_FAILURE(retval, expected_error, "sendmsg(client_fd, &msg, 0)");
	}

	if (retval == 0) {
		socklen = sizeof(sin6_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin6_local, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_local.sin6_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin6_peer);
		T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin6_peer, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_peer.sin6_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin6_local.sin6_port),
		    f_addr_str, ntohs(sin6_peer.sin6_port));
	}

	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}


T_DECL(tcp_send_implied_connect_ipv4_loopback, "TCP send implied connect with a IPv4 loopback address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}


T_DECL(tcp_send_implied_connect_ipv4_multicast, "TCP send implied connect with an IPv4 multicast address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "224.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4__broadcast, "TCP send implied connect with the IPv4 broadcast address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "255.255.255.255", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_null, "TCP send implied connect with the null IPv4 address")
{
	int s = -1;
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "0.0.0.0", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv6_loopback, "TCP send implied connect with the IPv6 loopback address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv6_multicast, "TCP send implied connect with a IPv6 multicast address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "ff01::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_null_ipv6, "TCP send implied connect with the IPv6 null address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_multicast_mapped_ipv6, "TCP send implied connect with IPv4 multicast mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_broadcast_mapped_ipv6, "TCP send implied connect with IPv4 broadcast mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_null_mapped_ipv6, "TCP send implied connect with IPv4 null mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_multicast_compatible_ipv6, "TCP send implied connect with IPv4 multicast compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_broadcast_compatible_ipv6, "TCP send implied connect with IPv4 broadcast compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_send_implied_connect_ipv4_null_compatible_ipv6, "TCP send implied connect with IPv4 null compatible IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_send_implied_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}
