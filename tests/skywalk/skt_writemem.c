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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <mach/vm_map.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int
skt_writeif_main(int argc, char *argv[])
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	*(char *)channel->chd_schema->csm_kern_name = 'X';

	return 1; // shouldn't be reached
}

struct skywalk_test skt_writeif = {
	.skt_testname = "writeif",
	.skt_testdesc = "writes to the read only channel if",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	.skt_main = skt_writeif_main,
	.skt_argv = SKTC_GENERIC_UPIPE_ARGV,
	.skt_init = sktc_generic_upipe_null_init,
	.skt_fini = sktc_generic_upipe_fini,
	.skt_expected_exception_code = 0xa100002,
	.skt_expected_exception_code_ignore = 0,
};

static int
skt_writering_main(int argc, char *argv[])
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	ring_id_t ringid;
	channel_ring_t ring;
	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	ring = os_channel_tx_ring(channel, ringid);
	assert(ring);

	assert((intptr_t)channel->chd_schema +
	    channel->chd_schema->csm_ring_ofs[0].ring_off ==
	    (intptr_t)ring->chrd_ring);

	/* Write garbage to ring descriptors */
	memset((void *)ring->chrd_ring, 0x5a, sizeof(*ring->chrd_ring));

	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	/* Expect failure (and a process crash) here */

	/*
	 * Sanity checks to localize failures, in case the crash doesn't
	 * succeed:
	 */
	SKTC_ASSERT_ERR(error);
	SKTC_ASSERT_ERR(errno == EFAULT);

	return 1;
}

struct skywalk_test skt_writering = {
	.skt_testname = "writering",
	.skt_testdesc = "writes to the writeable ring",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	.skt_main = skt_writering_main,
	.skt_argv = SKTC_GENERIC_UPIPE_ARGV,
	.skt_init = sktc_generic_upipe_null_init,
	.skt_fini = sktc_generic_upipe_fini,
	.skt_expected_exception_code = SIGABRT << 24,
	        .skt_expected_exception_code_ignore = 0,
};

static int
skt_readsmap_main(int argc, char *argv[])
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	uint8_t byte;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	//T_LOG("ch_if 0x%p offset 0x%llx pointer 0x%p\n",
	//	channel->chd_schema, channel->chd_schema->csm_ring_ofs[0].sd_off,
	//	(char *)channel->chd_schema+channel->chd_schema->csm_ring_ofs[0].sd_off);

	// Verify we can read it
	memcpy(&byte, (void *)channel->chd_schema + channel->chd_schema->csm_ring_ofs[0].sd_off, 1);

	return 0;
}

struct skywalk_test skt_readsmap = {
	.skt_testname = "readsmap",
	.skt_testdesc = "reads from the read only smap",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	.skt_main = skt_readsmap_main,
	.skt_argv = SKTC_GENERIC_UPIPE_ARGV,
	.skt_init = sktc_generic_upipe_null_init,
	.skt_fini = sktc_generic_upipe_fini,
};

static int
skt_writesmap_main(int argc, char *argv[])
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	uint8_t byte;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	//T_LOG("ch_if 0x%p offset 0x%llx pointer 0x%p\n",
	//	channel->chd_schema, channel->chd_schema->csm_ring_ofs[0].sd_off,
	//	(char *)channel->chd_schema+channel->chd_schema->csm_ring_ofs[0].sd_off);

	// Verify we can read it
	memcpy(&byte, (void *)channel->chd_schema + channel->chd_schema->csm_ring_ofs[0].sd_off, 1);

	// Now try to write it
	memcpy((void *)channel->chd_schema + channel->chd_schema->csm_ring_ofs[0].sd_off, &byte, 1);

	return 1; // shouldn't be reached
}

struct skywalk_test skt_writesmap = {
	.skt_testname = "writesmap",
	.skt_testdesc = "writes to the read only smap",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	.skt_main = skt_writesmap_main,
	.skt_argv = SKTC_GENERIC_UPIPE_ARGV,
	.skt_init = sktc_generic_upipe_null_init,
	.skt_fini = sktc_generic_upipe_fini,
	.skt_expected_exception_code = 0xa100002,
	.skt_expected_exception_code_ignore = 0,
};

/****************************************************************/

/*
 * Nexus region verification tests.
 */

struct sktc_nexus_handles ms_fsw_handle;
static uuid_string_t ms_fsw_uuid_string;
#define SKT_VERIFY_NXADV_REGION         1
#define SKT_VERIFY_NXADV_REGION_STR     "1"

static void
skt_ms_fsw_init(void)
{
	uuid_t flow_id;
	int error;

	sktc_ifnet_feth0_create();
	sktc_create_flowswitch(&ms_fsw_handle, 0);
	uuid_unparse(ms_fsw_handle.fsw_nx_uuid, ms_fsw_uuid_string);
	/*
	 * flowswitch doesn't allow opening a channel without a flow bound
	 * to the port.
	 */
	uuid_generate(flow_id);
	error = sktc_bind_tcp4_flow(ms_fsw_handle.controller,
	    ms_fsw_handle.fsw_nx_uuid, 0, NEXUS_PORT_FLOW_SWITCH_CLIENT,
	    flow_id);

	/* Don't assert as this is running in the test driver */
	if (error) {
		T_LOG("func %s sktc_bind_tcp4_flow returned error %d "
		    "errno %d: %s\n", __func__, error, errno, strerror(errno));
	}
}

static void
skt_ms_fsw_fini(void)
{
	sktc_cleanup_flowswitch(&ms_fsw_handle);
	sktc_ifnet_feth0_destroy();
}

static void
skt_verify_nxadv_region(channel_t channel)
{
	struct sk_nexusadv *region;
	uint64_t region_size;
	channel_attr_t attr;
	int error;

	attr = os_channel_attr_create();
	assert(attr != NULL);
	error = os_channel_read_attr(channel, attr);
	SKTC_ASSERT_ERR(!error);

	/* verify size of the region */
	os_channel_attr_get(attr, CHANNEL_ATTR_NEXUS_ADV_SIZE, &region_size);
	assert(region_size == sizeof(*region));

	/* verify version number */
	region = os_channel_get_advisory_region(channel);
	assert(region != NULL);
	assert(region->nxadv_ver == NX_ADVISORY_CURRENT_VERSION);

	/* write should fault as the region is mapped read-only */
	region->nxadv_ver = 0;

	/* shouldn't be reached */
	error = 1;
	SKTC_ASSERT_ERR(!error);
}

int
skt_nxregion_verify_main(int argc, char *argv[])
{
	int error;
	int test_id;
	uuid_t fsw_uuid;
	channel_t channel;

	error = uuid_parse(argv[3], fsw_uuid);
	SKTC_ASSERT_ERR(error == 0);
	test_id = atoi(argv[4]);

	T_LOG("opening channel %d on fsw %s\n",
	    NEXUS_PORT_FLOW_SWITCH_CLIENT, argv[3]);

	/* must fail without user packet pool set (flow switch) */
	assert(sktu_channel_create_extended(fsw_uuid,
	    NEXUS_PORT_FLOW_SWITCH_CLIENT, CHANNEL_DIR_TX_RX,
	    CHANNEL_RING_ID_ANY, NULL, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1) == NULL);

	channel = sktu_channel_create_extended(fsw_uuid,
	    NEXUS_PORT_FLOW_SWITCH_CLIENT, CHANNEL_DIR_TX_RX,
	    CHANNEL_RING_ID_ANY, NULL, -1, -1, -1, -1, -1, -1, 1, 1, -1, -1);
	assert(channel);

	switch (test_id) {
	case SKT_VERIFY_NXADV_REGION:
		skt_verify_nxadv_region(channel);
		break;

	default:
		assert(0);
	}

	os_channel_destroy(channel);
	return 0;
}

struct skywalk_test skt_verifynxadv = {
	.skt_testname = "verifynadv",
	.skt_testdesc = "verifies nexus advisory region",
	.skt_required_features = SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
    SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	.skt_main = skt_nxregion_verify_main,
	.skt_argv = { NULL, NULL, NULL, ms_fsw_uuid_string, SKT_VERIFY_NXADV_REGION_STR},
	.skt_init = skt_ms_fsw_init,
	.skt_fini = skt_ms_fsw_fini,
	.skt_expected_exception_code = 0xa100002,
	.skt_expected_exception_code_ignore = 0,
};
