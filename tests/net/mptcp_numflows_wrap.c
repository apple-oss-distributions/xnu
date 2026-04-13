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
 * Test Case: XNU: MPTCP: Subflow count overflow (local panic; may lead to UAF)
 * rdar://60273015
 *
 * Chris Jarrett-Davies <chrisjd@apple.com>
 * SEAR Red Team / 2020-Mar-10
 */

#include <darwintest.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false)
	);

#ifndef AF_MULTIPATH
#define AF_MULTIPATH 39
#endif

struct so_cidreq64 {
	uint32_t scr_aid;
	uint32_t scr_cnt;
	unsigned long scr_cidp __attribute__((aligned(8)));
};

#define SIOCGCONNIDS64 _IOWR('s', 151, struct so_cidreq64)
#define CONNECT_RESUME_ON_READ_WRITE 0x1

T_DECL(mptcp_numflows_wrap,
    "test that MPTCP subflow count doesn't overflow uint16_t",
    T_META_ASROOT(true),
    T_META_TIMEOUT(600))
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_len = sizeof(sin),
		.sin_addr = {
			.s_addr = inet_addr("127.0.0.1")
		},
		.sin_port = htons(31337)
	};
	sa_endpoints_t sae = {
		.sae_dstaddr = (const struct sockaddr *)&sin,
		.sae_dstaddrlen = sizeof(sin)
	};
	int s;
	int n;
	int yes = 1;
	struct so_cidreq64 ci64 = {};
	int listen_s;

	/* Create a socket to connect to */
	T_LOG("Creating a listening socket on 127.0.0.1:31337...");
	listen_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(listen_s, "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");

	T_ASSERT_POSIX_SUCCESS(bind(listen_s, (const struct sockaddr *)&sin, sizeof(sin)), "bind");
	T_ASSERT_POSIX_SUCCESS(listen(listen_s, 1), "listen");

	T_LOG("Setting up 65535 subflows...");
	s = socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_MULTIPATH, SOCK_STREAM, IPPROTO_TCP)");

	for (n = 0; n < 65535; ++n) {
		connectx(s, (const sa_endpoints_t *)&sae, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE, NULL, 0, NULL, NULL);
	}

	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGCONNIDS64, &ci64), "ioctl SIOCGCONNIDS64");
	T_LOG("num flows: %u", ci64.scr_cnt);

	/* Attempt to wrap the uint16_t to 0 */
	T_LOG("Attempting +1 subflow...");
	connectx(s, (const sa_endpoints_t *)&sae, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL);

	memset(&ci64, 0, sizeof(ci64));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGCONNIDS64, &ci64), "ioctl SIOCGCONNIDS64");
	T_LOG("num flows: %u", ci64.scr_cnt);

	/*
	 * Test that the counter doesn't wrap, which would cause mpte_numflows == 0
	 * while the list isn't empty, leading to a panic on SO_FLUSH
	 */
	T_LOG("Testing SO_FLUSH...");
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, 0x1103 /* SO_FLUSH */, &yes, sizeof(yes)),
	    "setsockopt SO_FLUSH");

	T_LOG("Closing sockets...");
	close(listen_s);
	close(s);

	T_PASS("mptcp_numflows_wrap completed without panic");
}
