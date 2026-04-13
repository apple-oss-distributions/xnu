/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ndrv.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vidhi_goel")
	);

T_DECL(test_ndrv_multi,
    "test NDRV_ADDMULTICAST with invalid parameters",
    T_META_CHECK_LEAKS(false))
{
	int s;
	struct sockaddr_ndrv sa = {
		.snd_len = sizeof(sa)
	};
	char buf[] = {2, AF_LINK};
	int ret;

	s = socket(PF_NDRV, SOCK_RAW, NDRVPROTO_NDRV);
	T_ASSERT_POSIX_SUCCESS(s, "socket(PF_NDRV, SOCK_RAW, NDRVPROTO_NDRV)");

	strlcpy((char *)sa.snd_name, "lo0", sizeof(sa.snd_name));

	T_ASSERT_POSIX_SUCCESS(bind(s, (struct sockaddr *)&sa, sizeof(sa)), "bind to lo0");

	T_LOG("Testing NDRV_ADDMULTICAST with invalid buffer");
	ret = setsockopt(s, SOL_NDRVPROTO, NDRV_ADDMULTICAST, &buf, sizeof(buf));
	T_EXPECT_EQ(ret, -1, "setsockopt should fail");
	T_EXPECT_EQ(errno, EINVAL, "errno should be EINVAL");

	close(s);

	T_PASS("test_ndrv_multi completed");
}
