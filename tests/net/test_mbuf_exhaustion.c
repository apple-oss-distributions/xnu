/*
 * Copyright (c) 2020, 2025 Apple Inc. All rights reserved.
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
 * Creates many UDP sockets and sends data to them without reading.
 * The mbuf allocator should run out of memory and should defunct
 * these sockets.
 */

#include <darwintest.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/errno.h>
#include <mach/mach_host.h>
#include <mach/mach_error.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false),
	T_META_ENABLED(!TARGET_OS_BRIDGE),
	T_META_OWNER("rpaulo")
	);

T_DECL(test_mbuf_exhaustion,
    "test mbuf exhaustion and socket defuncting behavior",
    T_META_TIMEOUT(60))
{
	int s, i;
	struct sockaddr_in sin = {};
	struct rlimit rlimit = { .rlim_cur = 2000, .rlim_max = 2000 };

	T_ASSERT_POSIX_SUCCESS(setrlimit(RLIMIT_NOFILE, &rlimit), "setrlimit");

	/* Create 1000 UDP sockets and bind them */
	for (i = 0; i < 1000; i++) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(s, "socket");

		sin.sin_port = htons(6000 + i);
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(sin);
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(bind(s, (struct sockaddr *)&sin, sizeof(sin)), "bind");
	}

	/* Create a client socket and send data to fill mbuf pool */
	unsigned char buf_8k[8 * 1024] = {};
	int client = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(client, "socket (client)");

	int on = 1;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)),
	    "setsockopt(SO_NOSIGPIPE)");

	/* Send data to 100 of the bound sockets without reading */
	for (i = 0; i < 100; i++) {
		sin.sin_port = htons(6000 + i);
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(sin);
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");

		for (int j = 0; j < 10; j++) {
			/* Ignore errors - we expect some to fail when mbufs are exhausted */
			sendto(client, buf_8k, sizeof(buf_8k), 0,
			    (struct sockaddr *)&sin, sizeof(sin));
		}
	}

	T_LOG("Waiting for socket defuncting...");
	sleep(15);

	force_zone_gc();

	close(client);
	T_PASS("test_mbuf_exhaustion completed");
}
