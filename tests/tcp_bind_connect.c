/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false),
	T_META_ENABLED(!TARGET_OS_BRIDGE));


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
tcp_connect_v4(int client_fd, struct sockaddr_in *sin_to, int expected_error)
{
	int listen_fd = -1;
	socklen_t socklen;
	int val = 2;
	struct sockaddr_in sin_local = { 0 };
	struct sockaddr_in sin_peer = { 0 };
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

	T_LOG("connect with sin_len: %u sin_family: %u sin_port: %u sin_addr: 0x%08x expected_error: %d",
	    sin_to->sin_len, sin_to->sin_family, ntohs(sin_to->sin_port), ntohl(sin_to->sin_addr.s_addr), expected_error);

	if (expected_error == 0) {
		T_EXPECT_POSIX_SUCCESS(connect(client_fd, (struct sockaddr *)sin_to, sizeof(struct sockaddr_in)), NULL);

		socklen = sizeof(sin_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin_local, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_local.sin_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin_peer);
		T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin_peer, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_peer.sin_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin_local.sin_port),
		    f_addr_str, ntohs(sin_peer.sin_port));
	} else {
		T_EXPECT_POSIX_FAILURE(connect(client_fd, (struct sockaddr *)sin_to, sizeof(struct sockaddr_in)), expected_error, NULL);
	}
	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

static int
tcp_connect_v6(int client_fd, struct sockaddr_in6 *sin6_to, int expected_error)
{
	int listen_fd = -1;
	socklen_t socklen;
	int off = 0;
	int val = 30;
	struct sockaddr_in6 sin6_local = { 0 };
	struct sockaddr_in6 sin6_peer = { 0 };
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

	(void)inet_ntop(AF_INET6, &sin6_to->sin6_addr, l_addr_str, sizeof(l_addr_str));
	T_LOG("connect with sin6_len: %u sin6_family: %u sin6_port: %u sin6_addr: %s expected_error: %d",
	    sin6_to->sin6_len, sin6_to->sin6_family, ntohs(sin6_to->sin6_port), l_addr_str, expected_error);

	if (expected_error == 0) {
		T_EXPECT_POSIX_SUCCESS(connect(client_fd, (struct sockaddr *)sin6_to, sizeof(struct sockaddr_in6)), NULL);

		socklen = sizeof(sin6_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin6_local, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_local.sin6_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin6_peer);
		T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin6_peer, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_peer.sin6_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin6_local.sin6_port),
		    f_addr_str, ntohs(sin6_peer.sin6_port));
	} else {
		T_EXPECT_POSIX_FAILURE(connect(client_fd, (struct sockaddr *)sin6_to, sizeof(struct sockaddr_in6)), expected_error, NULL);
	}
	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

static int
tcp_connectx_v4(int client_fd, struct sockaddr_in *sin_to, struct sockaddr_in *sin_from, int expected_error)
{
	int listen_fd = -1;
	socklen_t socklen;
	int val = 30;
	struct sockaddr_in sin_listener;
	sa_endpoints_t sae = { 0 };

	init_sin_address(&sin_listener);

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin_listener, sizeof(sin_listener)), NULL);

	socklen = sizeof(sin_listener);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin_listener, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin_listener.sin_port));
	sin_to->sin_port = sin_listener.sin_port;

	T_ASSERT_POSIX_SUCCESS(listen(listen_fd, 10), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(client_fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &val, sizeof(val)), NULL);

	if (sin_from != NULL) {
		(void)inet_ntop(AF_INET, &sin_from->sin_addr, l_addr_str, sizeof(l_addr_str));
		sae.sae_srcaddr = (struct sockaddr *)sin_from;
		sae.sae_srcaddrlen = sin_from->sin_len;
	} else {
		snprintf(l_addr_str, sizeof(l_addr_str), "");
	}
	(void)inet_ntop(AF_INET, &sin_to->sin_addr, f_addr_str, sizeof(f_addr_str));
	sae.sae_dstaddr = (struct sockaddr *)sin_to;
	sae.sae_dstaddrlen = sin_to->sin_len;

	T_LOG("connectx expected_error: %d from %s:%u (len: %u fam: %u) to %s:%u (len: %u fam: %u)",
	    expected_error,
	    l_addr_str, sin_from != NULL ? ntohs(sin_from->sin_port) : 0,
	    sin_from != NULL ? sin_from->sin_len : 0, sin_from != NULL ? sin_from->sin_family : 0,
	    f_addr_str, ntohs(sin_to->sin_port), sin_to->sin_len, sin_to->sin_family);

	if (expected_error == 0) {
		struct sockaddr_in sin_local = { 0 };
		struct sockaddr_in sin_peer = { 0 };

		init_sin_address(&sin_local);
		init_sin_address(&sin_peer);

		T_EXPECT_POSIX_SUCCESS(connectx(client_fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL), NULL);

		socklen = sizeof(sin_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin_local, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_local.sin_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin_peer);
		T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin_peer, &socklen), NULL);
		(void)inet_ntop(AF_INET, &sin_peer.sin_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin_local.sin_port),
		    f_addr_str, ntohs(sin_peer.sin_port));
	} else {
		T_EXPECT_POSIX_FAILURE(connectx(client_fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL), expected_error, NULL);
	}
	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

static int
tcp_connectx_v6(int client_fd, struct sockaddr_in6 *sin6_to, struct sockaddr_in6 *sin6_from, int expected_error)
{
	int listen_fd = -1;
	socklen_t socklen;
	int off = 0;
	int val = 30;
	struct sockaddr_in6 sin6_listener;
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_listener);

	T_ASSERT_POSIX_SUCCESS(listen_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)), NULL);

	T_ASSERT_POSIX_SUCCESS(bind(listen_fd, (struct sockaddr *)&sin6_listener, sizeof(sin6_listener)), NULL);

	socklen = sizeof(sin6_listener);
	T_ASSERT_POSIX_SUCCESS(getsockname(listen_fd, (struct sockaddr *)&sin6_listener, &socklen), NULL);

	T_LOG("listening on port: %u", ntohs(sin6_listener.sin6_port));
	sin6_to->sin6_port = sin6_listener.sin6_port;

	T_ASSERT_POSIX_SUCCESS(listen(listen_fd, 10), NULL);

	T_ASSERT_POSIX_SUCCESS(setsockopt(client_fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &val, sizeof(val)), NULL);

	if (sin6_from != NULL) {
		(void)inet_ntop(AF_INET6, &sin6_from->sin6_addr, l_addr_str, sizeof(l_addr_str));
		sae.sae_srcaddr = (struct sockaddr *)sin6_from;
		sae.sae_srcaddrlen = sin6_from->sin6_len;
	} else {
		snprintf(l_addr_str, sizeof(l_addr_str), "");
	}
	(void)inet_ntop(AF_INET6, &sin6_to->sin6_addr, f_addr_str, sizeof(f_addr_str));
	sae.sae_dstaddr = (struct sockaddr *)sin6_to;
	sae.sae_dstaddrlen = sin6_to->sin6_len;

	T_LOG("connectx expected_error: %d from %s:%u (len: %u fam: %u) to %s:%u (len: %u fam: %u)",
	    expected_error,
	    l_addr_str, sin6_from != NULL ? ntohs(sin6_from->sin6_port) : 0,
	    sin6_from != NULL ? sin6_from->sin6_len : 0, sin6_from != NULL ? sin6_from->sin6_family : 0,
	    f_addr_str, ntohs(sin6_to->sin6_port), sin6_to->sin6_len, sin6_to->sin6_family);

	if (expected_error == 0) {
		struct sockaddr_in6 sin6_local = { 0 };
		struct sockaddr_in6 sin6_peer = { 0 };

		init_sin6_address(&sin6_local);
		init_sin6_address(&sin6_peer);

		T_EXPECT_POSIX_SUCCESS(connectx(client_fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL), NULL);

		socklen = sizeof(sin6_local);
		T_ASSERT_POSIX_SUCCESS(getsockname(client_fd, (struct sockaddr *)&sin6_local, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_local.sin6_addr, l_addr_str, sizeof(l_addr_str));

		socklen = sizeof(sin6_peer);
		T_ASSERT_POSIX_SUCCESS(getpeername(client_fd, (struct sockaddr *)&sin6_peer, &socklen), NULL);
		(void)inet_ntop(AF_INET6, &sin6_peer.sin6_addr, f_addr_str, sizeof(f_addr_str));

		T_LOG("connected from %s:%u to %s:%u",
		    l_addr_str, ntohs(sin6_local.sin6_port),
		    f_addr_str, ntohs(sin6_peer.sin6_port));
	} else {
		T_EXPECT_POSIX_FAILURE(connectx(client_fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL), expected_error, NULL);
	}
	T_ASSERT_POSIX_SUCCESS(close(listen_fd), NULL);

	return 0;
}

static int
tcp_bind_v4(int client_fd, struct sockaddr_in *sin, int expected_error)
{
	int retval = bind(client_fd, (const struct sockaddr *)sin, sin->sin_len);

	if (expected_error == 0) {
		if (retval == 0) {
			T_PASS("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == 0");
		} else if (errno == EADDRNOTAVAIL || errno == EAGAIN) {
			T_SKIP("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		} else {
			T_FAIL("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		}
	} else {
		if (retval == 0) {
			T_FAIL("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == 0, expected errno: %d - %s", expected_error, strerror(expected_error));
		} else if (errno == expected_error) {
			T_PASS("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1, expected errno: %d - %s", expected_error, strerror(expected_error));
		} else if (errno == EADDRNOTAVAIL || errno == EAGAIN) {
			T_SKIP("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		} else {
			T_FAIL("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		}
	}
	return 0;
}

static int
tcp_bind_v6(int client_fd, struct sockaddr_in6 *sin6, int expected_error)
{
	int retval = bind(client_fd, (const struct sockaddr *)sin6, sin6->sin6_len);

	if (expected_error == 0) {
		if (retval == 0) {
			T_PASS("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == 0");
		} else if (errno == EADDRNOTAVAIL || errno == EAGAIN) {
			T_SKIP("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		} else {
			T_FAIL("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		}
	} else {
		if (retval == 0) {
			T_FAIL("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == 0, expected errno: %d - %s", expected_error, strerror(expected_error));
		} else if (errno == expected_error) {
			T_PASS("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1, expected errno: %d - %s", expected_error, strerror(expected_error));
		} else if (errno == EADDRNOTAVAIL || errno == EAGAIN) {
			T_SKIP("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		} else {
			T_FAIL("bind(client_fd, (const struct sockaddr *)sin, sin->sin_len) == -1 errno: %d - %s", errno, strerror(errno));
		}
	}
	return 0;
}

T_DECL(tcp_bind_ipv4_loopback, "TCP bind with a IPv4 loopback address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_loopback, "TCP connect with a IPv4 loopback address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_multicast, "TCP bind with a IPv4 multicast address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "224.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_multicast, "TCP connect with an IPv4 multicast address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "224.0.0.1", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4__broadcast, "TCP bind with the IPv4 broadcast address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "255.255.255.255", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4__broadcast, "TCP connect with the IPv4 broadcast address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "255.255.255.255", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_null, "TCP bind with the null IPv4 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "0.0.0.0", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_null, "TCP connect with the null IPv4 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin = { 0 };

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "0.0.0.0", &sin.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v4(s, &sin, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv6_loopback, "TCP bind with the IPv6 loopback address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	init_sin6_address(&sin6);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv6_loopback, "TCP connect with the IPv6 loopback address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv6_multicast, "TCP bind with a IPv6 multicast address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "ff01::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv6_multicast, "TCP connect with a IPv6 multicast address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	sin6.sin6_scope_id = if_nametoindex("lo0");
	T_ASSERT_EQ(inet_pton(AF_INET6, "ff01::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_null_ipv6, "TCP bind with the IPv6 null address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_null_ipv6, "TCP connect with the IPv6 null address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_multicast_mapped_ipv6, "TCP bind with IPv4 multicast mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_multicast_mapped_ipv6, "TCP connect with IPv4 multicast mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_broadcast_mapped_ipv6, "TCP bind with IPv4 broadcast mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_broadcast_mapped_ipv6, "TCP connect with IPv4 broadcast mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_loobpack_mapped_ipv6, "TCP bind with IPv4 loopback mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_loobpack_mapped_ipv6, "TCP connect with IPv4 loopback mapped IPv6 address")
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_null_mapped_ipv6, "TCP bind with IPv4 null mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_null_mapped_ipv6, "TCP connect with IPv4 null mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_multicast_compatible_ipv6, "TCP bind with IPv4 multicast compatible IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_multicast_compatible_ipv6, "TCP connect with IPv4 multicast compatible IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::224.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_broadcast_compatible_ipv6, "TCP bind with IPv4 broadcast compatible IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_broadcast_compatible_ipv6, "TCP connect with IPv4 broadcast compatible IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::255.255.255.255", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_null_compatible_ipv6, "TCP bind with IPv4 null compatible IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_null_compatible_ipv6, "TCP connect with IPv4 null compatible IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::0.0.0.0", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connect_ipv4_mapped_ipv6_r77991079, "rdar://77991079", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	init_sin6_address(&sin6);
	sin6.sin6_port = htons(20001);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0.0.0.5", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_scope_id = (uint32_t)-1;

	connect(s, (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6));

	T_ASSERT_EQ(inet_pton(AF_INET6, "::", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_scope_id = 0xff;

	connect(s, (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6));
	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connectx_ipv4_loopback, "TCP connectx with the IPv6 loopback address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in sin_dst = { 0 };

	init_sin_address(&sin_dst);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin_dst.sin_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connectx_v4(s, &sin_dst, NULL, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connectx_ipv6_loopback, "TCP connectx with the IPv6 loopback address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6_dst = { 0 };

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6_dst.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connectx_v6(s, &sin6_dst, NULL, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_connectx_ipv6_loopback_src_port, "TCP connectx with the IPv6 loopback address with a source port", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6_dst = { 0 };
	struct sockaddr_in6 sin6_src = { 0 };

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6_dst.sin6_addr), 1, NULL);

	init_sin6_address(&sin6_src);
	sin6_src.sin6_port = htons(12345);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_connectx_v6(s, &sin6_dst, &sin6_src, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_mapped_connect_pv4_mapped, "TCP bind IPv4 mapped IPv6 address and connect to IPv4 mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv6_connect_pv6, "TCP bind IPv6 address and connect IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv4_mapped_connect_ipv6, "TCP bind IPv4 mapped IPv6 address and connect IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}

T_DECL(tcp_bind_ipv6_connect_ipv4_mapped, "TCP bind Pv6 address and connect IPv4 mapped IPv6 address", T_META_TAG_VM_PREFERRED)
{
	int s = -1;
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);

	T_EXPECT_NULL(tcp_bind_v6(s, &sin6, 0), NULL);

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	T_EXPECT_NULL(tcp_connect_v6(s, &sin6, EAFNOSUPPORT), NULL);

	T_ASSERT_POSIX_SUCCESS(close(s), NULL);
}
