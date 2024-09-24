/*
 * Copyright (c) 2016-2024 Apple Inc. All rights reserved.
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

#include <assert.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"

/****************************************************************/

static int
skt_features_main(int argc, char *argv[])
{
	size_t len;
	uint64_t features;
	int error;

	features = 0;
	len = sizeof(features);
	error = sysctlbyname("kern.skywalk.features", &features, &len, NULL, 0);
	SKTC_ASSERT_ERR(error == 0);
	assert(len == sizeof(features));

	T_LOG("features = 0x%016"PRIx64, features);

	assert(features & SK_FEATURE_SKYWALK);
	assert(features & SK_FEATURE_NETNS);
	assert(features & SK_FEATURE_NEXUS_USER_PIPE);
	assert(features & SK_FEATURE_NEXUS_KERNEL_PIPE);
	assert(features & SK_FEATURE_NEXUS_MONITOR);
	assert(features & SK_FEATURE_NEXUS_FLOWSWITCH);
	assert(features & SK_FEATURE_NEXUS_NETIF);

	if (features & (SK_FEATURE_DEVELOPMENT | SK_FEATURE_DEBUG)) {
		assert(features & SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK);
		assert(features & SK_FEATURE_DEV_OR_DEBUG);
	} else {
		assert(!(features & SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK));
		assert(!(features & SK_FEATURE_DEV_OR_DEBUG));
	}

	return 0;
}

struct skywalk_test skt_features = {
	"features", "verifies skywalk features match kernel config", 0, skt_features_main,
};
