/*
 * Copyright (c) 2017, 2025 Apple Inc. All rights reserved.
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
 * Test for flow divert mbuf double free vulnerability
 *
 * SO_FLOW_DIVERT_TOKEN is a socket option on the SOL_SOCKET layer.
 * The implementation in flow_divert_token_set() has incorrect error handling:
 *
 * If soopt_mcopyin() fails (e.g., with an invalid userspace pointer),
 * it frees the mbuf. However, flow_divert_token_set() isn't aware of
 * these semantics and also calls mbuf_freem() on the same mbuf,
 * resulting in a double-free.
 *
 * This test verifies the fix by attempting to trigger the condition
 * that would have caused the double-free.
 */

#include <darwintest.h>
#include <sys/socket.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

#define SO_FLOW_DIVERT_TOKEN 0x1106

T_DECL(flow_divert_mbuf_double_free,
    "test SO_FLOW_DIVERT_TOKEN with invalid pointer does not double-free mbuf",
    T_META_CHECK_LEAKS(false))
{
	int sock;

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(sock, "socket(PF_INET, SOCK_DGRAM, 0)");

	T_LOG("Testing SO_FLOW_DIVERT_TOKEN with invalid userspace pointer");

	/* This should fail gracefully without causing a double-free */
	int ret = setsockopt(sock, SOL_SOCKET, SO_FLOW_DIVERT_TOKEN, (void *)0x424242424242ULL, 100);

	if (ret == 0) {
		T_LOG("setsockopt succeeded unexpectedly");
	} else {
		T_LOG("setsockopt failed as expected: %s", strerror(errno));
	}

	close(sock);

	T_PASS("flow_divert_mbuf_double_free completed without crash");
}
