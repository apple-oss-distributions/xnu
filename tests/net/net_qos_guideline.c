/*
 * Copyright (c) 2018-2025 Apple Inc. All rights reserved.
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
 * Test for net_qos_guideline() API
 * Tests network quality of service guideline for different transfer sizes
 */

#include <darwintest.h>
#include <netinet/in_tclass.h>
#include <string.h>
#include <errno.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

T_DECL(net_qos_guideline,
    "test net_qos_guideline API for QoS recommendations",
    T_META_CHECK_LEAKS(false))
{
	struct net_qos_param param;
	int ret;

	bzero(&param, sizeof(param));

	/* Test 1: Use BK for non-expensive interface and more than 5MB size */
	param.nq_transfer_size = 10000000;
	param.nq_use_expensive = 0;
	param.nq_use_constrained = 0;
	param.nq_uplink = 1;

	T_LOG("Testing with 10MB transfer size on non-expensive interface");
	ret = net_qos_guideline(&param, sizeof(param));
	T_EXPECT_POSIX_SUCCESS(ret, "net_qos_guideline should succeed");
	T_EXPECT_EQ(ret, 1, "Expected QoS guideline to recommend background (1) for large transfer");

	/* Test 2: Use default QoS for smaller transfer size */
	param.nq_transfer_size = 4 * 1000 * 1000;

	T_LOG("Testing with 4MB transfer size on non-expensive interface");
	ret = net_qos_guideline(&param, sizeof(param));
	T_EXPECT_POSIX_SUCCESS(ret, "net_qos_guideline should succeed");
	T_EXPECT_EQ(ret, 0, "Expected QoS guideline to recommend default (0) for smaller transfer");

	T_PASS("net_qos_guideline tests completed");
}
