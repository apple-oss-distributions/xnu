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

/* <rdar://problem/24849324> os_channel_{rx,tx}_ring() needs to check bounds of the ring index */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/event.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

#define NUM_TX_RINGS 4
#define NUM_RX_RINGS 4

static void
skt_ringid_init(void)
{
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, "skywalk_test_ringid_upipe",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_USER_PIPE;
	attr.ntxrings = NUM_TX_RINGS;
	attr.nrxrings = NUM_RX_RINGS;
	attr.anonymous = 1;

	sktc_setup_nexus(&attr);
}

static void
skt_ringid_fini(void)
{
	sktc_cleanup_nexus();
}

/****************************************************************/

static int
skt_ringid_main_common(int argc, char *argv[], uint32_t num,
    ring_id_type_t first, ring_id_type_t last,
    channel_ring_t (*get_ring)(const channel_t chd, const ring_id_t rid))
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	ring_id_t fringid, lringid, ringid;
	channel_ring_t ring;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	fringid = os_channel_ring_id(channel, first);
	lringid = os_channel_ring_id(channel, last);

	assert(lringid - fringid == num - 1);

	assert(fringid == 0); // XXX violates opaque abstraction

	/* Verify that we can get all the expected rings */
	for (ringid = fringid; ringid <= lringid; ringid++) {
		ring = (*get_ring)(channel, ringid);
		assert(ring);
	}

	/* And not a ring outside of the range */
	assert(ringid == lringid + 1);
	ring = (*get_ring)(channel, ringid);
	assert(!ring);

	os_channel_destroy(channel);

	/* Now reopen each channel with just a single ringid
	 * And verify that we can only get the expected ring id
	 */
	for (ringid = fringid; ringid <= lringid; ringid++) {
		ring_id_t ringid2;

		channel = sktu_channel_create_extended(channel_uuid, 0,
		    CHANNEL_DIR_TX_RX, ringid, NULL,
		    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
		assert(channel);

		ringid2 = os_channel_ring_id(channel, first);
		assert(ringid2 == ringid);

		ringid2 = os_channel_ring_id(channel, last);
		assert(ringid2 == ringid);

		for (ringid2 = fringid; ringid2 <= lringid + 1; ringid2++) {
			ring = (*get_ring)(channel, ringid2);
			assert(ringid2 != ringid || ring);
			assert(ringid2 == ringid || !ring); // This verifies rdar://problem/24849324
		}

		os_channel_destroy(channel);
	}

	/* Now try to reopen the channel with an invalid ringid */
	assert(ringid == lringid + 1);
	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, ringid, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(!channel);

	return 0;
}

/****************************************************************/

static int
skt_ringidtx_main(int argc, char *argv[])
{
	return skt_ringid_main_common(argc, argv,
	           NUM_TX_RINGS, CHANNEL_FIRST_TX_RING, CHANNEL_LAST_TX_RING,
	           &os_channel_tx_ring);
}

static int
skt_ringidrx_main(int argc, char *argv[])
{
	return skt_ringid_main_common(argc, argv,
	           NUM_RX_RINGS, CHANNEL_FIRST_RX_RING, CHANNEL_LAST_RX_RING,
	           &os_channel_rx_ring);
}

struct skywalk_test skt_ringidtx = {
	"ringidtx", "tests opening tx ringids",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_ringidtx_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_ringid_init, skt_ringid_fini,
};

struct skywalk_test skt_ringidrx = {
	"ringidrx", "tests opening rx ringids",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_ringidrx_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_ringid_init, skt_ringid_fini,
};

/****************************************************************/
