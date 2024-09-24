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
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/select.h>
#include <poll.h>
#include <time.h>
#include <sys/event.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

/************************************************************************
 * Utility code
 */

struct context {
	uuid_t nexus_uuid;
	int argc;
	char **argv;

	int test_selector;

	struct stage_ctx stage;
};

static void
skt_kqueue_init(void)
{
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, "skywalk_test_kqueue_upipe",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_USER_PIPE;
	attr.ntxrings = 1;
	attr.nrxrings = 1;
	attr.ntxslots = 64;
	attr.nrxslots = 64;
	attr.anonymous = 1;

	sktc_setup_nexus(&attr);
}

static void
skt_kqueue_fini(void)
{
	sktc_cleanup_nexus();
}

enum kqueue_common_test_stage {
	SKT_KQUEUE_INIT=0,
};

static int
skt_kqueue_main(int argc, char *argv[], int test_selector,
    void *(rx_body)(void *), void *(tx_body)(void *))
{
	pthread_t rx_thread, tx_thread;
	struct context ctx;
	int error;

	test_stage_init(&ctx.stage, SKT_KQUEUE_INIT);
	ctx.argc = argc;
	ctx.argv = argv;
	ctx.test_selector = test_selector;

	error = uuid_parse(argv[3], ctx.nexus_uuid);
	SKTC_ASSERT_ERR(!error);

	error = pthread_create(&rx_thread, NULL, rx_body, &ctx);
	SKTC_ASSERT_ERR(!error);
	error = pthread_create(&tx_thread, NULL, tx_body, &ctx);
	SKTC_ASSERT_ERR(!error);

	pthread_join(rx_thread, NULL);
	pthread_join(tx_thread, NULL);

	test_stage_destroy(&ctx.stage);

	return 0;
}

/************************************************************************
 * Basic sweep test
 */

enum kqueue_basic_test_stage {
	SKT_KQUEUE_BASIC_RX_SWEEP_1=1,
	SKT_KQUEUE_BASIC_RX_SWEEP_2,
	SKT_KQUEUE_BASIC_TX_SWEEP_1,
	SKT_KQUEUE_BASIC_TX_SWEEP_2,
	SKT_KQUEUE_BASIC_TX_SWEEP_3,
};

static void *
skt_kqueue_basic_rx(void *ctx_)
{
	struct context *ctx = (struct context *)ctx_;
	channel_t channel;
	channel_ring_t rxring;
	channel_attr_t ch_attr;
	ring_dir_t ring_dir = CHANNEL_DIR_RX;
	ring_id_t ring_id = CHANNEL_RING_ID_ANY;
	uint32_t port = 0;
	int kq_fd;
	int error;
	int i;

	assert(ctx->stage.test_stage == SKT_KQUEUE_INIT);

	/* Initialize kqueue */
	kq_fd = kqueue();
	assert(kq_fd >= 0);

	/* Initialize channel */
	ch_attr = os_channel_attr_create();
	channel = sktu_channel_create_extended(
		ctx->nexus_uuid,
		port, ring_dir, ring_id,
		ch_attr,
		-1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel != NULL);

	ring_id = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	rxring = os_channel_rx_ring(channel, ring_id);
	assert(rxring);

	/* Wait before any data and confirm that the ring is reported as empty */
	error = wait_on_fd(kq_fd, EVFILT_READ, channel, 0, TIMEOUT_EXPECT);
	SKTC_ASSERT_ERR(!error);

	/* Test basic RX data reporting, sweep from 0 to slots-1 to make sure
	 * the ring pointers wrap at some point */
	test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_1);

	int lim = ch_attr->cha_rx_slots - 1;
	for (i = 1; i <= lim; i++) {
		test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_2);
#ifndef NDEBUG
		int result =
#endif
		wait_on_fd(kq_fd, EVFILT_READ, channel, 0, TIMEOUT_FAIL);
		assert(result == i);

		chew_slots(rxring, 0);

		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(!error);

		test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_1);
	}
	test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_2);

	/* Get ready for TX sweep part of the test */

	test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_1);

	/* Drain RX ring */
	test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_2);
	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);
	test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_1);

	/* Allow TX backlog to trickle in */
	for (i = 1; i <= lim; i++) {
		test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_2);

		chew_slots(rxring, 1);
		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(!error);

		test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_1);
	}

	os_channel_attr_destroy(ch_attr);
	os_channel_destroy(channel);
	return 0;
}

static void *
skt_kqueue_basic_tx(void *ctx_)
{
	struct context *ctx = (struct context *)ctx_;
	channel_t channel;
	channel_ring_t txring;
	channel_attr_t ch_attr;
	ring_dir_t ring_dir = CHANNEL_DIR_TX;
	ring_id_t ring_id = CHANNEL_RING_ID_ANY;
	uint32_t port = 1;
	int error;
	int kq_fd;
	int i, j;

	kq_fd = kqueue();
	assert(kq_fd >= 0);

	ch_attr = os_channel_attr_create();
	channel = sktu_channel_create_extended(
		ctx->nexus_uuid,
		port, ring_dir, ring_id,
		ch_attr,
		-1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel != NULL);

	ring_id = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	txring = os_channel_tx_ring(channel, ring_id);
	assert(txring);

	/* Wait for RX to initialize */
	test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_1);

	/* Test basic RX data reporting, sweep from 0 to slots-1 to make sure
	 * the ring pointers wrap at some point */
	int lim =  ch_attr->cha_tx_slots - 1;
	for (i = 1; i <= lim; i++) {
		while (os_channel_available_slot_count(txring) < i) {
			wait_on_fd(kq_fd, EVFILT_WRITE, channel, 0, TIMEOUT_DONT_CARE);

			/* Abort if we were woken up but there are no slots.
			 * This can happen if the channel is defuncted such as
			 * in the skywalk_shutdown tests and we'll get stuck.
			 */
			assert(os_channel_available_slot_count(txring));
		}

		for (j = 0; j < i; j++) {
			send_bytes(txring, i);
		}

		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(!error);

		test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_2);
		test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_1);
	}
	test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_2);

	/* Test TX data reporting - start by filling the RX ring */
	test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_1);

	for (j = 0; j < lim; j++) {
		send_bytes(txring, j);
	}
	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	/* Send more packets and confirm TX backs up */
	for (i = 0; i < lim; i++) {
		send_bytes(txring, 8);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(!error);
		assert(os_channel_available_slot_count(txring) == lim - i - 1);
	}

	/* Confirm we time out waiting for more slots */
	error = wait_on_fd(kq_fd, EVFILT_WRITE, channel, 0, TIMEOUT_EXPECT);
	SKTC_ASSERT_ERR(!error);

	/* Start draining the rings */
	test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_2);
	test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_1);
	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	/* Drain the rings and confirm reporting is accurate */
	for (i = 1; i <= lim; i++) {
		test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_2);
		test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_TX_SWEEP_1);
		error = wait_on_fd(kq_fd, EVFILT_WRITE, channel, 0, TIMEOUT_FAIL);
		SKTC_ASSERT_ERR(error == i);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(!error);
	}

	os_channel_attr_destroy(ch_attr);
	os_channel_destroy(channel);
	return 0;
}

static int
skt_kqueue_basic_main(int argc, char *argv[])
{
	return skt_kqueue_main(argc, argv, 0,
	           &skt_kqueue_basic_rx,
	           &skt_kqueue_basic_tx);
}

/************************************************************************
 * Basic lowat test
 */

#define LOWAT_TYPE                      0x00000001
#define LOWAT_TYPE_CHAN         0x00000000
#define LOWAT_TYPE_NOTE         0x00000001

#define LOWAT_UNIT                      0x00000010
#define LOWAT_UNIT_SLOTS        0x00000000
#define LOWAT_UNIT_BYTES        0x00000010

enum kqueue_lowat_basic_test_stage {
	SKT_KQUEUE_LOWAT_BASIC_1=1,
	SKT_KQUEUE_LOWAT_BASIC_2,
	SKT_KQUEUE_LOWAT_BASIC_3
};

static void *
skt_kqueue_lowat_basic_rx(void *ctx_)
{
	struct context *ctx = (struct context *)ctx_;
	channel_t channel;
	channel_ring_t rxring;
	channel_attr_t ch_attr;
	ring_dir_t ring_dir = CHANNEL_DIR_RX;
	ring_id_t ring_id = CHANNEL_RING_ID_ANY;
	uint32_t port = 0;
	int kq_fd;
	channel_threshold_unit_t lowat_unit;
	int lowat_val;
	int error;
	int i;

	assert(ctx->stage.test_stage == SKT_KQUEUE_INIT);

	/* Initialize kqueue */
	kq_fd = kqueue();
	assert(kq_fd >= 0);

	/* Initialize channel */
	ch_attr = os_channel_attr_create();
	channel = sktu_channel_create_extended(
		ctx->nexus_uuid,
		port, ring_dir, ring_id,
		ch_attr,
		-1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel != NULL);

	ring_id = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	rxring = os_channel_rx_ring(channel, ring_id);
	assert(rxring);

	/* Set up watermarks */
	if ((ctx->test_selector & LOWAT_UNIT) == LOWAT_UNIT_BYTES) {
		lowat_unit = CHANNEL_THRESHOLD_UNIT_BYTES;
	} else {
		lowat_unit = CHANNEL_THRESHOLD_UNIT_SLOTS;
	}
	if ((ctx->test_selector & LOWAT_TYPE) == LOWAT_TYPE_CHAN) {
		set_watermark(channel, false, lowat_unit, 10);
		set_watermark(channel, true, lowat_unit, 15);
		lowat_val = 0;
	} else {
		set_watermark(channel, false, lowat_unit, 1);
		set_watermark(channel, true, lowat_unit, 1);
		lowat_val = 10;
	}
	test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);

	/* The first N waits should time out (3 waits for slots, 1 wait for
	 * bytes) */
	int N;
	if (lowat_unit == CHANNEL_THRESHOLD_UNIT_SLOTS) {
		N = 3;
	} else {
		N = 1;
	}
	for (i = 0; i < N; i++) {
		error = wait_on_fd(kq_fd, EVFILT_READ, channel, lowat_val,
		    TIMEOUT_EXPECT);
		SKTC_ASSERT_ERR(error == 0);
		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(error == 0);
		test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
		test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);
	}

	/* The next wait should trigger */
	error = wait_on_fd(kq_fd, EVFILT_READ, channel, lowat_val, TIMEOUT_FAIL);
	SKTC_ASSERT_ERR(error == 12);
	chew_slots(rxring, 0);
	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(error == 0);
	test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
	test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);

	/* Do it all again, but make sure the TX thread transmits while
	 * we're waiting this time */
	/* (TODO: is there a better way to do this, without the TX thread
	 * sleeping an arbitrary amount of time?) */
	error = wait_on_fd(kq_fd, EVFILT_READ, channel, lowat_val, TIMEOUT_DISABLE);
	SKTC_ASSERT_ERR(error == 12);
	chew_slots(rxring, 0);
	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(error == 0);
	test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
	test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);

	/* Let the TX thread fill our RX ring up, to test TX watermarks */
	test_stage_wait(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_2);
	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(error == 0);

	/* Free up some slots for TX, enough to trigger its TX watermark but
	 * not its RX watermark */
	for (i = 0; i < 5; i++) {
		chew_slots(rxring, 1);
		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(error == 0);
	}

	test_stage_change(&ctx->stage, SKT_KQUEUE_BASIC_RX_SWEEP_1);
	test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);

	/* Chew more slots to wake TX up, but wait a bit first to make sure TX
	 * is really sleeping (TODO: better way to do this?) */
	usleep(50000);
	for (i = 0; i < 5; i++) {
		chew_slots(rxring, 1);
		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(error == 0);
	}

	os_channel_attr_destroy(ch_attr);
	os_channel_destroy(channel);
	return 0;
}

static void *
skt_kqueue_lowat_basic_tx(void *ctx_)
{
	struct context *ctx = (struct context *)ctx_;
	channel_t channel;
	channel_ring_t txring;
	channel_attr_t ch_attr;
	ring_dir_t ring_dir = CHANNEL_DIR_TX;
	ring_id_t ring_id = CHANNEL_RING_ID_ANY;
	uint32_t port = 1;
	int kq_fd;
	channel_threshold_unit_t lowat_unit;
	int lowat_val;
	int note_lowat_val;
	int slot_size;
	int error;
	int i;

	kq_fd = kqueue();
	assert(kq_fd >= 0);

	ch_attr = os_channel_attr_create();
	channel = sktu_channel_create_extended(
		ctx->nexus_uuid,
		port, ring_dir, ring_id,
		ch_attr,
		-1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel != NULL);

	slot_size = channel->chd_info->cinfo_nxprov_params.nxp_buf_size;

	ring_id = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	txring = os_channel_tx_ring(channel, ring_id);
	assert(txring);

	if ((ctx->test_selector & LOWAT_UNIT) == LOWAT_UNIT_BYTES) {
		lowat_unit = CHANNEL_THRESHOLD_UNIT_BYTES;
	} else {
		lowat_unit = CHANNEL_THRESHOLD_UNIT_SLOTS;
	}

	/* Wait for RX to initialize */
	test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);

	/* Send packets in bursts of 3 to allow RX to confirm its watermark is
	 * being respected */
	int N;
	if (lowat_unit == CHANNEL_THRESHOLD_UNIT_SLOTS) {
		N = 4;
	} else {
		N = 2;
	}
	for (i = 0; i < N; i++) {
		send_bytes(txring, 2);
		send_bytes(txring, 2);
		send_bytes(txring, 2);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
		test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
		test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);
	}

	/* Send packets in bursts of 3 again, but wait a bit to give the RX
	 * thread time to wait (TODO: is there a better way to do this, without
	 * sleeping an arbitrary amount of time?) */
	usleep(50000);
	for (i = 0; i < N; i++) {
		send_bytes(txring, 2);
		send_bytes(txring, 2);
		send_bytes(txring, 2);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
	}

	test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
	test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);
	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(error == 0);

	/* Test TX watermarks - start by filling the RX ring */
	int lim =  ch_attr->cha_tx_slots - 1;
	for (i = 0; i < lim; i++) {
		send_bytes(txring, 5);
	}
	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(error == 0);

	/* Send more packets and confirm TX backs up _almost_ all the way */
	for (i = 0; i < lim - 5; i++) {
		send_bytes(txring, 8);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
		assert(os_channel_available_slot_count(txring) == lim - i - 1);
	}

	/* Set up watermarks */
	lowat_val = 10;
	if (lowat_unit == CHANNEL_THRESHOLD_UNIT_BYTES) {
		lowat_val *= slot_size;
	}
	if ((ctx->test_selector & LOWAT_TYPE) == LOWAT_TYPE_CHAN) {
		set_watermark(channel, false, lowat_unit, lowat_val * 2);
		set_watermark(channel, true, lowat_unit, lowat_val);
		note_lowat_val = 0;
	} else {
		set_watermark(channel, false, lowat_unit, 1);
		set_watermark(channel, true, lowat_unit, 1);
		note_lowat_val = lowat_val;
	}

	/* Wait for TX slots, confirm that even though some are available
	 * there aren't enough to trigger the watermark */
	assert(os_channel_available_slot_count(txring) > 0);
	error = wait_on_fd(kq_fd, EVFILT_WRITE, channel, note_lowat_val,
	    TIMEOUT_EXPECT);
	SKTC_ASSERT_ERR(error == 0);

	/* Let the RX thread drain some slots and try again */
	test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
	test_stage_wait(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_1);

	error = wait_on_fd(kq_fd, EVFILT_WRITE, channel, note_lowat_val,
	    TIMEOUT_FAIL);
	assert(error == lowat_val);

	/* Do it all again, but make sure RX triggers the watermark _while_
	 * we're sleeping this time */
	/* TODO: is there a better way to do this than having the RX
	 * thread sleep? */
	lowat_val = 15;
	if (lowat_unit == CHANNEL_THRESHOLD_UNIT_BYTES) {
		lowat_val *= slot_size;
	}
	if ((ctx->test_selector & LOWAT_TYPE) == LOWAT_TYPE_CHAN) {
		set_watermark(channel, false, lowat_unit, lowat_val * 2);
		set_watermark(channel, true, lowat_unit, lowat_val);
		note_lowat_val = 0;
	} else {
		set_watermark(channel, false, lowat_unit, 1);
		set_watermark(channel, true, lowat_unit, 1);
		note_lowat_val = lowat_val;
	}
	test_stage_change(&ctx->stage, SKT_KQUEUE_LOWAT_BASIC_2);
	error = wait_on_fd(kq_fd, EVFILT_WRITE, channel, note_lowat_val,
	    TIMEOUT_DISABLE);
	SKTC_ASSERT_ERR(error == lowat_val);

	os_channel_attr_destroy(ch_attr);
	os_channel_destroy(channel);
	return 0;
}

static int
skt_kqueue_lowat_chan_bytes_main(int argc, char *argv[])
{
	return skt_kqueue_main(argc, argv, LOWAT_TYPE_CHAN | LOWAT_UNIT_BYTES,
	           &skt_kqueue_lowat_basic_rx,
	           &skt_kqueue_lowat_basic_tx);
}

static int
skt_kqueue_lowat_chan_slots_main(int argc, char *argv[])
{
	return skt_kqueue_main(argc, argv, LOWAT_TYPE_CHAN | LOWAT_UNIT_SLOTS,
	           &skt_kqueue_lowat_basic_rx,
	           &skt_kqueue_lowat_basic_tx);
}

static int
skt_kqueue_lowat_note_bytes_main(int argc, char *argv[])
{
	return skt_kqueue_main(argc, argv, LOWAT_TYPE_NOTE | LOWAT_UNIT_BYTES,
	           &skt_kqueue_lowat_basic_rx,
	           &skt_kqueue_lowat_basic_tx);
}

static int
skt_kqueue_lowat_note_slots_main(int argc, char *argv[])
{
	return skt_kqueue_main(argc, argv, LOWAT_TYPE_NOTE | LOWAT_UNIT_SLOTS,
	           &skt_kqueue_lowat_basic_rx,
	           &skt_kqueue_lowat_basic_tx);
}

/****************************************************************
 * TODO: Tests to write:
 *	- kqueue_selwakeup - Test that wakeups associated with one channel
 *		descriptor don't spuriously wake up other threads waiting on other
 *		channels, or on channel descriptors that don't include the rings
 *		relevant to the waking event
 *	- lowat_edge - Test edge cases related to low watermarks: changing the
 *		unit while running, wakeups as a result of that unit change, issuing
 *              the watermark in the knote vs the channel, etc
 */

struct skywalk_test skt_kqueue_basic = {
	"kqueue_basic", "tests kqueue return values",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_kqueue_basic_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_kqueue_init, skt_kqueue_fini,
};

struct skywalk_test skt_kqueue_lowat_chan_bytes = {
	"kqueue_lowat_chan_bytes", "tests kqueue low watermark (byte watermark on channel)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_kqueue_lowat_chan_bytes_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_kqueue_init, skt_kqueue_fini,
};

struct skywalk_test skt_kqueue_lowat_chan_slots = {
	"kqueue_lowat_chan_slots", "tests kqueue low watermark (slot watermark on channel)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_kqueue_lowat_chan_slots_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_kqueue_init, skt_kqueue_fini,
};

struct skywalk_test skt_kqueue_lowat_note_bytes = {
	"kqueue_lowat_note_bytes", "tests kqueue low watermark (byte watermark on knote)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_kqueue_lowat_note_bytes_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_kqueue_init, skt_kqueue_fini,
};

struct skywalk_test skt_kqueue_lowat_note_slots = {
	"kqueue_lowat_note_slots", "tests kqueue low watermark (slot watermark on knote)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_kqueue_lowat_note_slots_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_kqueue_init, skt_kqueue_fini,
};

/****************************************************************/
