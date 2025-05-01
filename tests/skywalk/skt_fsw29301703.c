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

/*
 * <rdar://problem/29301703> Skywalk: Add unit tests to check that flowswitch can grow beyond 64 ports
 *
 *   * create a flowswitch and ifattach a netif (feth0) underneath
 *   * open 63 channels from userland to the flowswitch
 *
 */

#include <assert.h>
#include <unistd.h>
#include <sys/resource.h>
#include <darwintest.h>

#include "skywalk_test_common.h"
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include <skywalk/os_nexus.h>

static int
skt_fsw29301703_common(int nchannels)
{
	int error;
	int result = 0;
	nexus_controller_t ncd;
	uuid_t netif_provider;
	uuid_t netif_instance;
	uuid_t netif_attach;
	uuid_t fsw_provider;
	uuid_t fsw_instance;
	uuid_t fsw_if_attach;
	channel_t channels[nchannels];
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	sktc_raise_file_limit(nchannels + 10);
	ncd = os_nexus_controller_create();
	assert(ncd);

	/* create the fsw */
	strncpy((char *)attr.name, "skt_fsw29301703", sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_FLOW_SWITCH;
	attr.anonymous = 1;
	sktc_build_nexus(ncd, &attr, &fsw_provider, &fsw_instance);

	/* Create a netif */
	strncpy((char *)attr.name, "skt_29301703_netif",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_NET_IF;
	sktc_build_nexus(ncd, &attr, &netif_provider, &netif_instance);

	error = __os_nexus_ifattach(ncd, netif_instance, FETH0_NAME, NULL,
	    false, &netif_attach);

	/* attach the netif to the fsw */
	error = __os_nexus_ifattach(ncd, fsw_instance, NULL, netif_instance,
	    false, &fsw_if_attach);
	SKTC_ASSERT_ERR(!error);

	/* must fail without user packet pool set (flow switch) */
	assert(sktu_channel_create_extended(fsw_instance, 2,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1) == NULL);

	/*
	 * Open many channels from userland to the flowswitch.
	 * Start with channel 2 because port 0 and 1 are reserved to kernel.
	 */
	for (int i = 0; i < sizeof(channels) / sizeof(channels[0]); i++) {
		channels[i] = sktu_channel_create_extended(fsw_instance, i + 2,
		    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
		    -1, -1, -1, -1, -1, -1, 1, 1, -1, -1);
		if (!channels[i]) {
			SKT_LOG("failed on channel %d errno %d\n", 1 + i, errno);
			result = 1;
			break;
		}
	}

	return result;
}

static int
skt_fsw29301703a_main(int argc, char *argv[])
{
	return skt_fsw29301703_common(63);
}

static int
skt_fsw29301703b_main(int argc, char *argv[])
{
	return skt_fsw29301703_common(200);
}

static int
skt_fsw29301703c_main(int argc, char *argv[])
{
	/*
	 * Expect failure
	 * The 4100 here is because NX_FSW_VP_MAX is currently 4096 in nx_flowswitch.h
	 */
	int error = skt_fsw29301703_common(4100);
	assert(error);
	return 0;
}


struct skywalk_test skt_fsw29301703a = {
	"fsw29301703a", "open 63 channels to a flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fsw29301703a_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fsw29301703b = {
	"fsw29301703b", "open 200 channels to a flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fsw29301703b_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_fsw29301703c = {
	"fsw29301703c", "open too many channels to a flow switch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fsw29301703c_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};
