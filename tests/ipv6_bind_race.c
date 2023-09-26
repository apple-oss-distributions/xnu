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

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));

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

static void *
racer(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr), 1, NULL);

	while (finished == false) {
		(void)bind(fd, (struct sockaddr*)&sin6, sin6.sin6_len);
	}
	return NULL;
}

static void *
leader(void *arg)
{
#pragma unused(arg)
	struct sockaddr_in6 sin6 = {};

	init_sin6_address(&sin6);
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);

	while (finished == false) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(fd = socket(AF_INET6, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0), "socket");

		(void)bind(fd, (struct sockaddr*)&sin6, sin6.sin6_len);

		close(fd);
	}
	return NULL;
}

T_DECL(ipv6_tcp_bind_race, "race bind calls with TCP sockets")
{
	pthread_t runner1;
	if (pthread_create(&runner1, NULL, leader, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	pthread_t runner2;
	if (pthread_create(&runner2, NULL, racer, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	sleep(5);

	finished = true;

	pthread_join(runner1, 0);
	pthread_join(runner2, 0);
}

T_DECL(ipv6_udp_bind_race, "race bind  calls with UDP sockets")
{
	is_tcp = false;

	pthread_t runner1;
	if (pthread_create(&runner1, NULL, leader, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	pthread_t runner2;
	if (pthread_create(&runner2, NULL, racer, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	sleep(5);

	finished = true;

	pthread_join(runner1, 0);
	pthread_join(runner2, 0);
}
