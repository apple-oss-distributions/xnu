/*
 * Copyright (c) 2020-2024 Apple Inc. All rights reserved.
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

/* <rdar://problem/58673168> Restricted port used by non-entitled process */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

static int
skt_reserve_restricted_port()
{
	int error;
	int old_first, old_last;
	int restricted_port = 55555;
	size_t size;

	size = sizeof(old_first);
	error = sysctlbyname("net.inet.ip.portrange.first", &old_first, &size, &restricted_port, sizeof(restricted_port));
	SKTC_ASSERT_ERR(!error);
	assert(size == sizeof(old_first));

	size = sizeof(old_last);
	error = sysctlbyname("net.inet.ip.portrange.last", &old_last, &size, &restricted_port, sizeof(restricted_port));
	SKTC_ASSERT_ERR(!error);
	assert(size == sizeof(old_last));

	struct sktc_nexus_handles handles;
	sktc_create_flowswitch(&handles, 0);

	uuid_t flow;

	/* try reserve one of the restricted ephemeral ports */
	uuid_generate_random(flow);
	error = sktc_bind_tcp4_flow(handles.controller, handles.fsw_nx_uuid,
	    0, NEXUS_PORT_FLOW_SWITCH_CLIENT, flow);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EADDRNOTAVAIL);
	uuid_clear(flow);

	sktc_cleanup_flowswitch(&handles);

	size = sizeof(old_first);
	error = sysctlbyname("net.inet.ip.portrange.first", NULL, NULL, &old_first, size);
	SKTC_ASSERT_ERR(!error);
	assert(size == sizeof(old_first));

	size = sizeof(old_last);
	error = sysctlbyname("net.inet.ip.portrange.last", NULL, NULL, &old_last, size);
	SKTC_ASSERT_ERR(!error);
	assert(size == sizeof(old_last));
	return 0;
}

int
skt_reserve_restricted_port_main(int argc, char *argv[])
{
	return skt_reserve_restricted_port();
}


struct skywalk_test skt_restricted_port = {
	"restricted_port", "test reserve a restricted ephemeral port",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_reserve_restricted_port_main, { NULL }, sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};
