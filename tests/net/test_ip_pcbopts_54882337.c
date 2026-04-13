/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
 * Test for rdar://54882337
 * Tests IP_OPTIONS setsockopt with specific sizes to ensure proper mbuf handling
 */

#include <darwintest.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false)
	);

#define NSOCKS 64
#define NCHILDREN 32

T_DECL(test_ip_pcbopts_54882337,
    "test IP_OPTIONS setsockopt with specific mbuf sizes",
    T_META_TIMEOUT(300))
{
	int s;
	uint8_t opts[
		256 /* MSIZE */
		- 32 /* - sizeof(struct m_hdr) */
		- 4 /* - sizeof(struct in_addr) */
		- 4 /* so we're not equal to MLEN */
	];
	uint8_t empty_opts[8];
	int n;
	pid_t child[NCHILDREN];
	int p;
	int r;

	memset(empty_opts, IPOPT_NOP, sizeof(empty_opts));

	bzero(opts, sizeof(opts));
	opts[0] = IPOPT_NOP;
	opts[1] = IPOPT_NOP;
	opts[2] = IPOPT_NOP;
	opts[3] = IPOPT_LSRR;
	opts[4] = sizeof(opts) - 3;

	for (r = 0; r < 16; ++r) {
		for (p = 0; p < NCHILDREN; ++p) {
			child[p] = fork();
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(child[p], "fork");

			if (child[p] == 0) {
				/* Child process */
				for (n = 0; n < NSOCKS - 3; ++n) {
					s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
					if (s == -1) {
						continue;
					}

					setsockopt(s, IPPROTO_IP, IP_OPTIONS, opts, sizeof(opts));

					/* Consume an mbuf */
					T_QUIET;
					T_ASSERT_POSIX_SUCCESS(setsockopt(s, IPPROTO_IP, IP_OPTIONS,
					    empty_opts, sizeof(empty_opts)),
					    "setsockopt IP_OPTIONS (empty)");

					close(s);
				}
				exit(0);
			}
		}

		for (p = 0; p < NCHILDREN; ++p) {
			int status;
			pid_t result = waitpid(child[p], &status, 0);
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(result, "waitpid");
			T_QUIET;
			T_ASSERT_TRUE(WIFEXITED(status), "child should exit normally");
			T_QUIET;
			T_ASSERT_EQ(WEXITSTATUS(status), 0, "child should exit with 0");
		}
	}

	T_PASS("test_ip_pcbopts_54882337 completed without panic");
}
