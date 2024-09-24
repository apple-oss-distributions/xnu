/*
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
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

/* Attempts to manually fill a upipe to force an a tx sync from rx
 * Both end of upipe are in the child process.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

#define NSLOTS 100

void
skt_fullupipe_init(void)
{
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, "skywalk_test_fullupipe",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_USER_PIPE;
	attr.ntxrings = 1;
	attr.nrxrings = 1;
	attr.ntxslots = NSLOTS;
	attr.nrxslots = NSLOTS;
	attr.anonymous = 1;
	attr.rejectonclose = 1;

	sktc_setup_nexus(&attr);
}

void
skt_fullupipe_fini(void)
{
	sktc_cleanup_nexus();
}

int
skt_fullupipe_main(int argc, char *argv[])
{
	int error;
	uuid_t instance_uuid;
	channel_t channel0, channel1;
	channel_ring_t txring0, rxring1;
	channel_slot_t txslot0, rxslot1;
	uint32_t txavail0, rxavail1;
	error = uuid_parse(argv[3], instance_uuid);
	SKTC_ASSERT_ERR(!error);

	channel0 = sktu_channel_create_extended(instance_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel0);
	channel1 = sktu_channel_create_extended(instance_uuid, 1,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel1);

	txring0 = os_channel_tx_ring(channel0, os_channel_ring_id(channel0, CHANNEL_FIRST_TX_RING));
	assert(txring0);
	rxring1 = os_channel_rx_ring(channel1, os_channel_ring_id(channel1, CHANNEL_FIRST_RX_RING));
	assert(rxring1);

	/* Iterate through the tx slots */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == NSLOTS - 1);
	txslot0 = NULL;
	while (txavail0--) {
		slot_prop_t props;
		txslot0 = os_channel_get_next_slot(txring0, txslot0, &props);
		assert(txslot0);
		os_channel_set_slot_properties(txring0, txslot0, &props);
	}
	assert(!os_channel_get_next_slot(txring0, txslot0, NULL));

	/* Verify there are no rx slots */
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);
	rxslot1 = NULL;
	assert(!os_channel_get_next_slot(rxring1, rxslot1, NULL));

	error = os_channel_advance_slot(txring0, txslot0);
	SKTC_ASSERT_ERR(!error);

	/* Double check that the tx queue is full and the rx queue is empty */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	/*
	 * Now try an rx sync, this shouldn't do anything since
	 * no packets have been synced to tx yet.
	 */
	error = os_channel_sync(channel1, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	/* The txqueue is still full and the rx queue is still empty */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	/*
	 * Now try a tx sync, this push slots into the rx queue
	 */
	error = os_channel_sync(channel0, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	/* The txqueue is now empty and the rx queue is full */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == NSLOTS - 1);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	/* Now fill up the tx slots again */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == NSLOTS - 1);
	txslot0 = NULL;
	while (txavail0--) {
		slot_prop_t props;
		txslot0 = os_channel_get_next_slot(txring0, txslot0, &props);
		assert(txslot0);
		os_channel_set_slot_properties(txring0, txslot0, &props);
	}
	assert(!os_channel_get_next_slot(txring0, txslot0, NULL));

	/* Verify there are no rx slots because
	 * we haven't done an rx sync yet
	 */
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);
	rxslot1 = NULL;
	assert(!os_channel_get_next_slot(rxring1, rxslot1, NULL));

	error = os_channel_advance_slot(txring0, txslot0);
	SKTC_ASSERT_ERR(!error);

	/* Both the tx and rx queues are now full, but we can't
	 * see the slots until we do an rx sync
	 */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	/*
	 * Now try a tx sync, there's no room in the rx queue
	 * so this won't move any slots, but it will make them
	 * visible to the kernel
	 */
	error = os_channel_sync(channel0, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	/* Still can't see any slots without an rx sync */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	error = os_channel_sync(channel1, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	/* Now we should see all the slots on rx */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == NSLOTS - 1);

	/* Now chew up some rx slots */
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == NSLOTS - 1);
	rxslot1 = NULL;
	while (rxavail1--) {
		rxslot1 = os_channel_get_next_slot(rxring1, rxslot1, NULL);
		assert(rxslot1);
	}
	assert(!os_channel_get_next_slot(rxring1, rxslot1, NULL));

	error = os_channel_advance_slot(rxring1, rxslot1);
	SKTC_ASSERT_ERR(!error);

	/* No more slots available until we sync */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	error = os_channel_sync(channel1, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	/* Now we should see all the slots on rx because it will
	 * reach over and get slots from the tx
	 */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == NSLOTS - 1);

	/* Now chew up some rx slots */
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == NSLOTS - 1);
	rxslot1 = NULL;
	while (rxavail1--) {
		rxslot1 = os_channel_get_next_slot(rxring1, rxslot1, NULL);
		assert(rxslot1);
	}
	assert(!os_channel_get_next_slot(rxring1, rxslot1, NULL));

	error = os_channel_advance_slot(rxring1, rxslot1);
	SKTC_ASSERT_ERR(!error);

	/* We haven't seen the new tx slots until we do a tx sync */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == 0);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	error = os_channel_sync(channel0, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	/* We now see the new slots because of the tx sync */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == NSLOTS - 1);
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == 0);

	os_channel_destroy(channel0);
	os_channel_destroy(channel1);

	return 0;
}

int
skt_upipepeerclosure_main(int argc, char *argv[])
{
	int error;
	uuid_t instance_uuid;
	channel_t channel0, channel1;
	channel_ring_t txring0, rxring1;
	channel_slot_t txslot0, rxslot1;
	uint32_t txavail0, rxavail1;
	error = uuid_parse(argv[3], instance_uuid);
	SKTC_ASSERT_ERR(!error);

	channel0 = sktu_channel_create_extended(instance_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel0);
	channel1 = sktu_channel_create_extended(instance_uuid, 1,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel1);

	txring0 = os_channel_tx_ring(channel0, os_channel_ring_id(channel0,
	    CHANNEL_FIRST_TX_RING));
	assert(txring0);
	rxring1 = os_channel_rx_ring(channel1, os_channel_ring_id(channel1,
	    CHANNEL_FIRST_RX_RING));
	assert(rxring1);

	/* Iterate through all the tx slots */
	txavail0 = os_channel_available_slot_count(txring0);
	assert(txavail0 == NSLOTS - 1);
	txslot0 = NULL;
	while (txavail0--) {
		slot_prop_t props;
		txslot0 = os_channel_get_next_slot(txring0, txslot0, &props);
		assert(txslot0);
		os_channel_set_slot_properties(txring0, txslot0, &props);
	}
	assert(!os_channel_get_next_slot(txring0, txslot0, NULL));
	error = os_channel_advance_slot(txring0, txslot0);
	SKTC_ASSERT_ERR(!error);

	error = os_channel_sync(channel0, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	error = os_channel_sync(channel1, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	/* Now we should see all the slots on rx */
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == NSLOTS - 1);

	/* Now chew up all rx slots */
	rxavail1 = os_channel_available_slot_count(rxring1);
	assert(rxavail1 == NSLOTS - 1);
	rxslot1 = NULL;
	while (rxavail1--) {
		rxslot1 = os_channel_get_next_slot(rxring1, rxslot1, NULL);
		assert(rxslot1);
	}
	assert(!os_channel_get_next_slot(rxring1, rxslot1, NULL));
	error = os_channel_advance_slot(rxring1, rxslot1);
	SKTC_ASSERT_ERR(!error);
	error = os_channel_sync(channel1, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	/* close channel1 */
	os_channel_destroy(channel1);

	/* this should throw an error as the peer channel is closed */
	error = os_channel_sync(channel0, CHANNEL_SYNC_TX);
	if (error == 0) {
		T_LOG("unexpected success\n");
		assert(0);
	} else if (errno != ENXIO) {
		SKT_LOG("unexpected errno: error %d "
		    "errno %d: %s\n", error, errno, strerror(errno));
		assert(0);
	}
	os_channel_destroy(channel0);
	return 0;
}

struct skywalk_test skt_fullupipe = {
	"fullupipe", "test rx on full tx pipe",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_fullupipe_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_fullupipe_init, skt_fullupipe_fini,
};

struct skywalk_test skt_upipepeerclosure = {
	"upipepeerclosure", "test channel operations on upipe with no peer",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_upipepeerclosure_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_fullupipe_init, skt_fullupipe_fini,
};
