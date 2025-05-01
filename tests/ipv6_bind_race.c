/*
 * Copyright (c) 2023-2024 Apple Inc. All rights reserved.
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
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

/*
 * The test is disabled on platforms that could be limited in term of CPU
 * or memory because this stress test that cycles rapidly through a lot of socket
 */
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false),
	T_META_ENABLED(TARGET_OS_OSX || TARGET_OS_IPHONE));

#define SECONDS_TO_SLEEP 3

#if 0

static int fd = -1;
static bool finished = false;
static bool is_tcp = false;

static void
init_sin6_address(struct sockaddr_in6 *sin6)
{
	memset(sin6, 0, sizeof(struct sockaddr_in6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
}

static void
setnonblocking(int s)
{
	int flags;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(flags = fcntl(s, F_GETFL, 0), NULL);

	flags |= O_NONBLOCK;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(flags = fcntl(s, F_SETFL, flags), NULL);
}

static void *
bind4_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(1234);

	while (finished == false) {
		(void)bind(fd, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
bind6_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(1234);

	while (finished == false) {
		(void)bind(fd, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
connect6_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(3456);

	while (finished == false) {
		(void)connect(fd, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
connect4_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(3456);

	while (finished == false) {
		(void)connect(fd, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
bind6_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)bind(fd, (struct sockaddr*)&sin6, sin6.sin6_len);

		close(fd);
	}
	return NULL;
}

static void *
bind4_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)bind(fd, (struct sockaddr*)&sin6, sin6.sin6_len);

		close(fd);
	}
	return NULL;
}

static void *
send6_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(3456);

	while (finished == false) {
		(void)sendto(fd, "", 1, 0, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
send4_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(3456);

	while (finished == false) {
		(void)sendto(fd, "", 1, 0, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
send6_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = { 0 };

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);
	sin6.sin6_port = htons(3456);

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)sendto(fd, "", 1, 0, (struct sockaddr*)&sin6, sin6.sin6_len);

		close(fd);
	}
	return NULL;
}

static void *
connectx6_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6_dst = { 0 };
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6_dst.sin6_addr), 1, NULL);
	sin6_dst.sin6_port = htons(3456);
	sae.sae_dstaddr = (struct sockaddr *)&sin6_dst;
	sae.sae_dstaddrlen = sin6_dst.sin6_len;

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)connectx(fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL);

		close(fd);
	}
	return NULL;
}

static void *
connectx4_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6_dst = { 0 };
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6_dst.sin6_addr), 1, NULL);
	sin6_dst.sin6_port = htons(3456);
	sae.sae_dstaddr = (struct sockaddr *)&sin6_dst;
	sae.sae_dstaddrlen = sin6_dst.sin6_len;

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)connectx(fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL);

		close(fd);
	}
	return NULL;
}

static void *
connectx6_binding_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6_src = { 0 };
	struct sockaddr_in6 sin6_dst = { 0 };
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_src);
	sin6_src.sin6_port = htons(1234);
	sae.sae_srcaddr = (struct sockaddr *)&sin6_src;
	sae.sae_srcaddrlen = sin6_src.sin6_len;

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6_dst.sin6_addr), 1, NULL);
	sin6_dst.sin6_port = htons(3456);
	sae.sae_dstaddr = (struct sockaddr *)&sin6_dst;
	sae.sae_dstaddrlen = sin6_dst.sin6_len;

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)connectx(fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL);

		close(fd);
	}
	return NULL;
}

static void *
connectx4_binding_leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6_src = { 0 };
	struct sockaddr_in6 sin6_dst = { 0 };
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_src);
	sin6_src.sin6_port = htons(1234);
	sae.sae_srcaddr = (struct sockaddr *)&sin6_src;
	sae.sae_srcaddrlen = sin6_src.sin6_len;

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6_dst.sin6_addr), 1, NULL);
	sin6_dst.sin6_port = htons(3456);
	sae.sae_dstaddr = (struct sockaddr *)&sin6_dst;
	sae.sae_dstaddrlen = sin6_dst.sin6_len;

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		(void)connectx(fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL);

		close(fd);
	}
	return NULL;
}

static void *
connectx6_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6_dst = { 0 };
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6_dst.sin6_addr), 1, NULL);
	sin6_dst.sin6_port = htons(3456);
	sae.sae_dstaddr = (struct sockaddr *)&sin6_dst;
	sae.sae_dstaddrlen = sin6_dst.sin6_len;

	while (finished == false) {
		(void)connectx(fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL);
	}
	return NULL;
}

static void *
connectx4_racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6_dst = { 0 };
	sa_endpoints_t sae = { 0 };

	init_sin6_address(&sin6_dst);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6_dst.sin6_addr), 1, NULL);
	sin6_dst.sin6_port = htons(3456);
	sae.sae_dstaddr = (struct sockaddr *)&sin6_dst;
	sae.sae_dstaddrlen = sin6_dst.sin6_len;

	while (finished == false) {
		(void)connectx(fd, &sae, SAE_ASSOCID_ANY, 0, NULL, 0, 0, NULL);
	}
	return NULL;
}

static void *
listen6_leader(void *arg)
{
#pragma unused(arg)

	while (finished == false) {
		int val = 1;

		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		/* Note: The following may fail of an IPv4 racer has won the bind race */
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));

		(void)listen(fd, 5);

		close(fd);
	}
	return NULL;
}

static void *
listen4_leader(void *arg)
{
#pragma unused(arg)

	while (finished == false) {
		int val = 0;

		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		setnonblocking(fd);

		/* Note: The following may fail of an IPv4 racer has won the bind race */
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));

		(void)listen(fd, 5);

		close(fd);
	}
	return NULL;
}

static void
do_bind_race(bool do_test_tcp, void *(*leader)(void *), void *(*racer)(void *))
{
	pthread_t runner1;
	pthread_t runner2;

	is_tcp = do_test_tcp;

	if (pthread_create(&runner1, NULL, leader, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	if (pthread_create(&runner2, NULL, racer, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	sleep(SECONDS_TO_SLEEP);

	finished = true;

	pthread_join(runner1, 0);
	pthread_join(runner2, 0);
}

T_DECL(ipv6_tcp_bind6_bind4_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, bind6_leader, bind4_racer);
}

T_DECL(ipv6_tcp_bind6_connect4_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, bind6_leader, connect4_racer);
}

T_DECL(ipv6_tcp_bind4_connect6_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, bind4_leader, connect6_racer);
}

T_DECL(ipv6_tcp_bind6_send4_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, bind6_leader, send4_racer);
}

T_DECL(ipv6_tcp_bind4_send6_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, bind4_leader, send6_racer);
}

T_DECL(ipv6_tcp_send6_send4_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, send6_leader, send4_racer);
}

T_DECL(ipv6_tcp_bind6_connectx4_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, bind6_leader, connectx4_racer);
}

T_DECL(ipv6_tcp_bind4_connectx6_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, bind4_leader, connectx6_racer);
}

T_DECL(ipv6_tcp_connectx4_bind6_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx4_leader, bind6_racer);
}

T_DECL(ipv6_tcp_connectx6_bind4_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx6_leader, bind4_racer);
}

T_DECL(ipv6_tcp_connectx4_connect6_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx4_leader, connect6_racer);
}

T_DECL(ipv6_tcp_connectx6_connect4_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx6_leader, connect4_racer);
}

T_DECL(ipv6_tcp_connectx4_binding_bind6_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx4_binding_leader, bind6_racer);
}

T_DECL(ipv6_tcp_connectx6_binding_bind4_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx6_binding_leader, bind4_racer);
}

T_DECL(ipv6_tcp_connectx4_binding_connect6_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx4_binding_leader, connect6_racer);
}

T_DECL(ipv6_tcp_connectx6_binding_connect4_race, "race bind calls with TCP sockets", T_META_ENABLED(false))
{
	do_bind_race(true, connectx6_binding_leader, connect4_racer);
}

T_DECL(ipv6_tcp_listen6_bind4_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, listen6_leader, bind4_racer);
}

T_DECL(ipv6_tcp_listen4_bind6_race, "race bind calls with TCP sockets")
{
	do_bind_race(true, listen4_leader, bind6_racer);
}


T_DECL(ipv6_udp_bind6_bind4_race, "race bind  calls with UDP sockets")
{
	do_bind_race(false, bind6_leader, bind4_racer);
}

T_DECL(ipv6_udp_bind6_connect4_race, "race bind calls with UDP sockets")
{
	do_bind_race(false, bind6_leader, connect4_racer);
}

T_DECL(ipv6_udp_bind4_connect6_race, "race bind calls with UDP sockets")
{
	do_bind_race(false, bind4_leader, connect6_racer);
}

T_DECL(ipv6_udp_bind6_send4_race, "race bind calls with UDP sockets")
{
	do_bind_race(false, bind6_leader, send4_racer);
}

T_DECL(ipv6_udp_bind4_send6_race, "race bind calls with UDP sockets")
{
	do_bind_race(false, bind4_leader, send6_racer);
}

T_DECL(ipv6_udp_send6_send4_race, "race bind calls with UDP sockets")
{
	do_bind_race(false, send6_leader, send4_racer);
}

T_DECL(ipv6_udp_bind6_connectx4_race, "race bind calls with UDP sockets", T_META_ENABLED(false))
{
	do_bind_race(false, bind6_leader, connectx4_racer);
}

T_DECL(ipv6_udp_bind4_connectx6_race, "race bind calls with UDP sockets", T_META_ENABLED(false))
{
	do_bind_race(false, bind4_leader, connectx6_racer);
}

T_DECL(ipv6_udp_connectx4_bind6_race, "race bind calls with UDP sockets", T_META_ENABLED(false))
{
	do_bind_race(false, connectx4_leader, bind6_racer);
}

T_DECL(ipv6_udp_connectx6_bind4_race, "race bind calls with UDP sockets", T_META_ENABLED(false))
{
	do_bind_race(false, connectx6_leader, bind4_racer);
}

T_DECL(ipv6_udp_connectx4_connect6_race, "race bind calls with UDP sockets", T_META_ENABLED(false))
{
	do_bind_race(false, connectx4_leader, connect6_racer);
}

T_DECL(ipv6_udp_connectx6_connect4_race, "race bind calls with UDP sockets", T_META_ENABLED(false))
{
	do_bind_race(false, connectx6_leader, connect4_racer);
}
#else

T_DECL(stub, "test suite disabled")
{
	T_EXPECT_TRUE(true, "disabled by rdar://137741815");
}

#endif /* 0 */
