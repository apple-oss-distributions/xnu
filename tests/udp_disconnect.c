/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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
 * Disconnect should happen when passed a NULL address
 * Verify we can reconnect after a disconnect
 */

#include <sys/fcntl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

#define MAX_IPv6_STR_LEN        64

static char l_addr_str[MAX_IPv6_STR_LEN];
static char f_addr_str[MAX_IPv6_STR_LEN];

const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
#define s6_addr32 __u6_addr.__u6_addr32

#define RTM_BUFLEN (sizeof(struct rt_msghdr) + 6 * SOCK_MAXADDRLEN)

#define ROUNDUP(a) \
((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

static bool
has_v4_default_route(void)
{
	bool result = false;
	struct rt_msghdr *rtm = NULL;
	struct sockaddr_in sin = {};

	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;

	T_QUIET; T_ASSERT_NOTNULL(rtm = (struct rt_msghdr *)calloc(1, RTM_BUFLEN), NULL);

	rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_HOST;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = getpid();
	rtm->rtm_seq = 1;

	uint8_t *cp = (unsigned char *)(rtm + 1);

	bcopy(&sin, cp, sin.sin_len);
	cp += ROUNDUP(sin.sin_len);

	u_short len = (u_short)(cp - (uint8_t *)rtm);

	rtm->rtm_msglen = len;

	int fd;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd = socket(PF_ROUTE, SOCK_RAW, 0), NULL);

	ssize_t sent = send(fd, rtm, len, 0);
	if (sent == len) {
		result = true;
	} else {
		result = false;
	}

	(void) close(fd);
	free(rtm);

	return result;
}

static bool
has_v6_default_route(void)
{
	bool result = false;
	struct rt_msghdr *rtm = NULL;
	struct sockaddr_in6 sin6 = {};

	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;

	T_QUIET; T_ASSERT_NOTNULL(rtm = (struct rt_msghdr *)calloc(1, RTM_BUFLEN), NULL);

	rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_HOST;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = getpid();
	rtm->rtm_seq = 1;

	uint8_t *cp = (unsigned char *)(rtm + 1);

	bcopy(&sin6, cp, sin6.sin6_len);
	cp += ROUNDUP(sin6.sin6_len);

	u_short len = (u_short)(cp - (uint8_t *)rtm);

	rtm->rtm_msglen = len;

	int fd;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd = socket(PF_ROUTE, SOCK_RAW, 0), NULL);

	ssize_t sent = send(fd, rtm, len, 0);
	if (sent == len) {
		result = true;
	} else {
		result = false;
	}

	(void) close(fd);
	free(rtm);

	return result;
}


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

static void
udp_disconnect_v4(int client_fd, struct sockaddr_in *sin_null, int expected_error)
{
	if (expected_error == 0) {
		socklen_t socklen;
		struct sockaddr_in sin_local = {};
		struct sockaddr_in sin_peer = {};

		// Disconnect
		T_EXPECT_POSIX_FAILURE(connect(client_fd, (struct sockaddr *)sin_null, sizeof(struct sockaddr_in)), EADDRNOTAVAIL, NULL);

		socklen = sizeof(sin_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin_local, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_local.sin_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin_peer);
		T_EXPECT_POSIX_FAILURE(getpeername(client_fd, (struct sockaddr *)&sin_peer, &socklen), ENOTCONN, NULL);
		(void)inet_ntop(AF_INET, &sin_peer.sin_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("disconnected with %s:%u to %s:%u",
		    l_addr_str, ntohs(sin_local.sin_port),
		    f_addr_str, ntohs(sin_peer.sin_port));
	} else {
		T_EXPECT_POSIX_FAILURE(connect(client_fd, (struct sockaddr *)sin_null, sizeof(struct sockaddr_in)), expected_error, NULL);
	}
}

static void
udp_connect_v4(int client_fd, struct sockaddr_in *sin_to)
{
	int listen_fd = -1;
	socklen_t socklen;
	struct sockaddr_in sin_local = {};
	struct sockaddr_in sin_peer = {};
	struct sockaddr_in sin;

	init_sin_address(&sin);
	init_sin_address(&sin_local);
	init_sin_address(&sin_peer);

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)), NULL);

	socklen = sizeof(sin);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin.sin_port));
	sin_to->sin_port = sin.sin_port;

	T_LOG("connect with sin_len: %u sin_family: %u sin_port: %u sin_addr: 0x%08x",
	    sin_to->sin_len, sin_to->sin_family, ntohs(sin_to->sin_port), ntohl(sin_to->sin_addr.s_addr));

	T_EXPECT_POSIX_SUCCESS(connect(client_fd, (struct sockaddr *)sin_to, sizeof(struct sockaddr_in)), NULL);

	socklen = sizeof(sin_local);
	T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin_local, &socklen), NULL);
	(void)inet_ntop(AF_INET, &sin_local.sin_addr, l_addr_str, sizeof(l_addr_str));

	socklen = sizeof(sin_peer);
	T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin_peer, &socklen), NULL);
	(void)inet_ntop(AF_INET, &sin_peer.sin_addr, f_addr_str, sizeof(f_addr_str));

	T_LOG("connected with %s:%u to %s:%u",
	    l_addr_str, ntohs(sin_local.sin_port),
	    f_addr_str, ntohs(sin_peer.sin_port));

	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);
}

T_DECL(udp_disconnect_null_ipv4, "UDP connect with a IPv4 loopback address")
{
	struct sockaddr_in sin = {};
	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	struct sockaddr_in sin_null = {};
	init_sin_address(&sin_null);

	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), NULL);

	udp_connect_v4(s, &sin);
	udp_disconnect_v4(s, &sin_null, 0);
	udp_connect_v4(s, &sin);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

static void
udp_disconnect_v6(int client_fd,
    struct sockaddr_in6 *sin6_null, int expected_error)
{
	if (expected_error == 0) {
		socklen_t socklen;
		struct sockaddr_in6 sin6_local = {};
		struct sockaddr_in6 sin6_peer = {};

		// Disconnect
		T_EXPECT_POSIX_FAILURE(connect(client_fd, (struct sockaddr *)sin6_null, sizeof(struct sockaddr_in6)), EADDRNOTAVAIL, NULL);

		socklen = sizeof(sin6_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin6_local, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_local.sin6_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin6_peer);
		T_EXPECT_POSIX_FAILURE(getpeername(client_fd, (struct sockaddr *)&sin6_peer, &socklen), ENOTCONN, NULL);
		(void)inet_ntop(AF_INET6, &sin6_peer.sin6_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("re=connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin6_local.sin6_port),
		    f_addr_str, ntohs(sin6_peer.sin6_port));
	} else {
		T_EXPECT_POSIX_FAILURE(connect(client_fd, (struct sockaddr *)sin6_null, sizeof(struct sockaddr_in6)), expected_error, NULL);
	}
}

static void
udp_connect_v6(int client_fd, struct sockaddr_in6 *sin6_to)
{
	int listen_fd = -1;
	socklen_t socklen;
	int off = 0;
	struct sockaddr_in6 sin6_local = {};
	struct sockaddr_in6 sin6_peer = {};
	struct sockaddr_in6 sin6;

	init_sin6_address(&sin6);
	init_sin6_address(&sin6_local);
	init_sin6_address(&sin6_peer);

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin6, sizeof(sin6)), NULL);

	socklen = sizeof(sin6);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin6, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin6.sin6_port));
	sin6_to->sin6_port = sin6.sin6_port;

	(void)inet_ntop(AF_INET6, &sin6_to->sin6_addr, l_addr_str, sizeof(l_addr_str));
	T_LOG("connecting with sin6_len: %u sin6_family: %u sin6_port: %u sin6_addr: %s",
	    sin6_to->sin6_len, sin6_to->sin6_family, ntohs(sin6_to->sin6_port), l_addr_str);

	T_EXPECT_POSIX_SUCCESS(connect(client_fd, (struct sockaddr *)sin6_to, sizeof(struct sockaddr_in6)), NULL);

	socklen = sizeof(sin6_local);
	T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin6_local, &socklen), NULL);
	(void)inet_ntop(AF_INET6, &sin6_local.sin6_addr, l_addr_str, sizeof(l_addr_str));

	socklen = sizeof(sin6_peer);
	T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin6_peer, &socklen), NULL);
	(void)inet_ntop(AF_INET6, &sin6_peer.sin6_addr, f_addr_str, sizeof(f_addr_str));

	T_LOG("connected with %s:%u to %s:%u",
	    l_addr_str, ntohs(sin6_local.sin6_port),
	    f_addr_str, ntohs(sin6_peer.sin6_port));

	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);
}

T_DECL(udp_disconnect_null_ipv6, "UDP connect with IPv4 multicast mapped IPv6 address")
{
	if (!has_v6_default_route()) {
		T_SKIP("test require IPv4 default route");
	}

	int s = -1;
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	struct sockaddr_in6 sin6_null = {};
	init_sin6_address(&sin6_null);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), NULL);

	udp_connect_v6(s, &sin6);
	udp_disconnect_v6(s, &sin6_null, 0);
	udp_connect_v6(s, &sin6);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(udp_disconnect_null_ipv4_mapped_ipv6, "UDP connect with IPv4 multicast mapped IPv6 address")
{
	if (!has_v4_default_route()) {
		T_SKIP("test require IPv4 default route");
	}

	struct sockaddr_in6 sin6 = {};
	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	struct sockaddr_in6 sin6_null = {};
	init_sin6_address(&sin6_null);

	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), NULL);

	udp_connect_v6(s, &sin6);
	udp_disconnect_v6(s, &sin6_null, 0);
	udp_connect_v6(s, &sin6);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(udp_disconnect_mapped_ipv4_mapped_ipv6, "UDP connect with IPv4 multicast mapped IPv6 address")
{
	if (!has_v4_default_route()) {
		T_SKIP("test require IPv4 default route");
	}

	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), NULL);

	struct sockaddr_in6 sin6 = {};
	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	struct sockaddr_in6 sin6_null = {};
	init_sin6_address(&sin6_null);
	sin6_null.sin6_addr.s6_addr[10] = 0xff;
	sin6_null.sin6_addr.s6_addr[11] = 0xff;

	udp_connect_v6(s, &sin6);
	udp_disconnect_v6(s, &sin6_null, 0);
	udp_connect_v6(s, &sin6);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}
