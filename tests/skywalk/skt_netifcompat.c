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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <darwintest.h>

#include "skywalk_test_common.h"
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"

static channel_t channel;
static uuid_t if_uuid;

static void
skt_netifcompat_common(void)
{
	int error;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, "skywalk_test_net_if",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_NET_IF;
	attr.anonymous = 1;
	attr.userchannel = 1;

	sktc_setup_nexus(&attr);

	channel = sktu_channel_create_extended(sktc_instance_uuid, NEXUS_PORT_NET_IF_HOST,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(!channel);

	channel = sktu_channel_create_extended(sktc_instance_uuid, NEXUS_PORT_NET_IF_DEV,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(!channel);

	uuid_generate_random(if_uuid);
	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    sktc_instance_uuid, if_uuid);
	SKTC_ASSERT_ERR(error == -1);
	SKT_LOG("error %d errno %d\n", error, errno);
	SKTC_ASSERT_ERR(errno == ESRCH);

	uuid_clear(if_uuid);
	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    sktc_instance_uuid, if_uuid);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EINVAL);

	error = __os_nexus_ifattach(sktc_nexus_controller,
	    sktc_instance_uuid, FETH0_NAME, NULL, false, &if_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(sktc_instance_uuid, NEXUS_PORT_NET_IF_DEV,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	if (channel != NULL) {
		error = __os_nexus_ifdetach(sktc_nexus_controller,
		    sktc_instance_uuid, if_uuid);
		SKTC_ASSERT_ERR(error == -1);
		SKTC_ASSERT_ERR(errno == EBUSY);
	}
}

static int
skt_netifcompata_main(int argc, char *argv[])
{
	int error;

	skt_netifcompat_common();
	if (channel != NULL) {
		os_channel_destroy(channel);
	}

	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    sktc_instance_uuid, if_uuid);
	SKTC_ASSERT_ERR(!error);

	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    sktc_instance_uuid, if_uuid);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ESRCH);

	sktc_cleanup_nexus();

	return 0;
}

static int
skt_netifcompatb_main(int argc, char *argv[])
{
	skt_netifcompat_common();

	sktc_cleanup_nexus();

	/* Skip detach since controller is closed */
	if (channel != NULL) {
		os_channel_destroy(channel);
	}

	return 0;
}

static int
skt_netifcompatc_main(int argc, char *argv[])
{
	int error;
	skt_netifcompat_common();

	/* This is the guts of sktc_cleanup_nexus() expanded here
	 * so that we can detach and close after we've freed the instance
	 */
	assert(sktc_nexus_controller);
	assert(!uuid_is_null(sktc_provider_uuid));
	assert(!uuid_is_null(sktc_instance_uuid));

	error = os_nexus_controller_free_provider_instance(sktc_nexus_controller,
	    sktc_instance_uuid);
	SKTC_ASSERT_ERR(!error);

	/* We've freed the provider, but there's a channel still open to it.
	 * We can then no longer detach it, is that correct?
	 */
	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    sktc_instance_uuid, if_uuid);
	if (channel != NULL) {
		SKTC_ASSERT_ERR(error == -1);
		SKTC_ASSERT_ERR(errno == ENOENT);
	}
	error = os_nexus_controller_deregister_provider(sktc_nexus_controller,
	    sktc_provider_uuid);
	SKTC_ASSERT_ERR(!error);

	os_nexus_controller_destroy(sktc_nexus_controller);
	sktc_nexus_controller = NULL;
	if (channel != NULL) {
		os_channel_destroy(channel);
	}

	return 0;
}

struct skywalk_test skt_netifcompata = {
	"netifcompata", "setup and teardown netifcompat on feth0",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF,
	skt_netifcompata_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_netifcompatb = {
	"netifcompatb", "setup and teardown netifcompat on feth0 with deferred close channel",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF,
	skt_netifcompatb_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_netifcompatc = {
	"netifcompatc", "setup and teardown netifcompat on feth0 with deferred detach and close channel",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF,
	skt_netifcompatc_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

/****************************************************************/

static void
skt_fsw_common(const char *name)
{
	int error;
	uuid_t ms_provider;
	uuid_t ms_instance;
	uuid_t ms_attach;
	uuid_t scratch;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, name, sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_FLOW_SWITCH;
	attr.anonymous = 1;

	skt_netifcompat_common();

	sktc_build_nexus(sktc_nexus_controller, &attr, &ms_provider,
	    &ms_instance);

	if (channel != NULL) {
		/*
		 * There is a channel open to the net-if dev port, so this
		 * attach will fail
		 */
		error = __os_nexus_ifattach(sktc_nexus_controller,
		    ms_instance, NULL, sktc_instance_uuid, false, &ms_attach);
		SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__,
		    error, errno);
		SKTC_ASSERT_ERR(error == -1);
		SKTC_ASSERT_ERR(errno == EBUSY);

		/* Close the channel so the attach will succeed */
		os_channel_destroy(channel);
	}
	error = __os_nexus_ifattach(sktc_nexus_controller,
	    ms_instance, NULL, sktc_instance_uuid, false, &ms_attach);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);

	uuid_clear(scratch);
	error = __os_nexus_ifattach(sktc_nexus_controller,
	    ms_instance, NULL, sktc_instance_uuid, false, &scratch);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EEXIST);
	assert(uuid_is_null(scratch));

	/*
	 * flowswitch doesn't allow opening a channel without a flow bound
	 * to the port.
	 */
	uuid_t flow_id;
	uuid_generate(flow_id);
	error = sktc_bind_tcp4_flow(sktc_nexus_controller, ms_instance,
	    0, NEXUS_PORT_FLOW_SWITCH_CLIENT, flow_id);
	SKTC_ASSERT_ERR(error == 0);

	/* must fail without user packet pool set (flow switch) */
	assert(sktu_channel_create_extended(ms_instance, 2,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1) == NULL);

	/* Open and close channel to the flow switch */
	channel = sktu_channel_create_extended(ms_instance, 2,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, 1, 1, -1, -1);
	assert(channel);

	os_channel_destroy(channel);

	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    ms_instance, ms_attach);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);

	error = os_nexus_controller_free_provider_instance(sktc_nexus_controller,
	    ms_instance);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);
	uuid_clear(ms_instance);

	error = os_nexus_controller_deregister_provider(sktc_nexus_controller,
	    ms_provider);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);
	uuid_clear(ms_provider);

	sktc_cleanup_nexus();
}

static int
skt_netifms_main(int argc, char *argv[])
{
	skt_fsw_common("skywalk_test_fsw");
	return 0;
}

struct skywalk_test skt_netiffsw = {
	"netifms", "setup compat netif and attach to flowswitch",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_netifms_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

int
skt_netifdelete_main(int argc, char *argv[])
{
	uuid_t attach;
	int error;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, "skt_netifdelete_netif",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_NET_IF;
	attr.anonymous = 1;
	attr.userchannel = 1;

	sktc_ifnet_feth0_create();

	sktc_setup_nexus(&attr);

	error = __os_nexus_ifattach(sktc_nexus_controller,
	    sktc_instance_uuid, FETH0_NAME, NULL, false, &attach);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);

	sktc_ifnet_feth0_destroy();

	error = __os_nexus_ifdetach(sktc_nexus_controller,
	    sktc_instance_uuid, attach);
	SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);

	sktc_cleanup_nexus();

	return 0;
}

struct skywalk_test skt_netifdelete = {
	"netifdelete", "tear down an ifp while it's attached to a netif",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF,
	skt_netifdelete_main,
};
