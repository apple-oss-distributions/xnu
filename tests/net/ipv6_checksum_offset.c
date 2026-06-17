/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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
 * ipv6_checksum_offset.c
 *
 * Regression test for rdar://171644699:
 *
 * IPV6_CHECKSUM socket option must reject negative offset values.
 * A previous off-by-one fix changed the bounds check in rip6_output()
 * from (off + 1) to (off + sizeof(uint16_t)), which allowed the value
 * -2 to bypass the check (since -2 + 2 == 0, which is not > plen).
 * This could lead to the packet header being overwritten with a
 * computed checksum value.
 */

#include <darwintest.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ipv6"),
	T_META_RUN_CONCURRENTLY(true));

static int
set_ipv6_checksum(int s, int val)
{
	return setsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, &val, sizeof(val));
}

T_DECL(ipv6_checksum_offset_negative,
    "IPV6_CHECKSUM must reject negative offset values (rdar://171644699)")
{
	int s;

	s = socket(AF_INET6, SOCK_RAW, IPPROTO_NONE);
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_RAW, IPPROTO_NONE)");

	/* -2 was previously accepted due to an integer overflow in the
	 * bounds check in rip6_output(). */
	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, -2), EINVAL,
	    "IPV6_CHECKSUM = -2 should fail with EINVAL");

	/* Other negative even values must also be rejected. */
	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, -4), EINVAL,
	    "IPV6_CHECKSUM = -4 should fail with EINVAL");

	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, -100), EINVAL,
	    "IPV6_CHECKSUM = -100 should fail with EINVAL");

	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, INT32_MIN), EINVAL,
	    "IPV6_CHECKSUM = INT32_MIN should fail with EINVAL");

	/* Odd values (negative and positive) must also be rejected. */
	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, -1), EINVAL,
	    "IPV6_CHECKSUM = -1 should fail with EINVAL");

	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, 1), EINVAL,
	    "IPV6_CHECKSUM = 1 should fail with EINVAL");

	T_EXPECT_POSIX_FAILURE(set_ipv6_checksum(s, 3), EINVAL,
	    "IPV6_CHECKSUM = 3 should fail with EINVAL");

	/* Valid non-negative even offsets must be accepted. */
	T_EXPECT_POSIX_SUCCESS(set_ipv6_checksum(s, 0),
	    "IPV6_CHECKSUM = 0 should succeed");

	T_EXPECT_POSIX_SUCCESS(set_ipv6_checksum(s, 2),
	    "IPV6_CHECKSUM = 2 should succeed");

	T_EXPECT_POSIX_SUCCESS(set_ipv6_checksum(s, 40),
	    "IPV6_CHECKSUM = 40 should succeed");

	close(s);
}
