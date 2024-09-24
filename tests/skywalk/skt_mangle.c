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
#include <sys/sysctl.h>
#include <err.h>
#include <sysexits.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

struct context {
	uuid_t nexus_uuid;
	int argc;
	char **argv;
	int test_selector;
	struct stage_ctx stage;
};

enum mangle_test_selector {
	SKT_CHANGE_LEN,
	SKT_BIG_LEN,
};

enum mangle_stage {
	SKT_INIT=0,
	SKT_TX_TURN,
	SKT_RX_TURN,
};

struct internalize_ctx {
	int utun_fd;
	struct sktc_nexus_handles handles;
	channel_port port;
	struct sktu_flow *flow;
	struct in_addr our_ip;
	struct in_addr dst_ip;
};

static void
skt_mangle_init(void)
{
	uint32_t disable_panic_on_sync_err = 1;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	sysctlbyname("kern.skywalk.disable_panic_on_sync_err",
	    NULL, 0, &disable_panic_on_sync_err,
	    sizeof(disable_panic_on_sync_err));

	strncpy((char *)attr.name, "skywalk_test_mangle_upipe",
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
skt_mangle_fini(void)
{
	uint32_t disable_panic_on_sync_err = 0;

	sysctlbyname("kern.skywalk.disable_panic_on_sync_err",
	    NULL, 0, &disable_panic_on_sync_err,
	    sizeof(disable_panic_on_sync_err));

	sktc_cleanup_nexus();
}

static void *
skt_mangle_verify_internalize_metadata(void *_ctx)
{
	struct internalize_ctx *ctx = _ctx;
	uint16_t sport;
	uint16_t dport;

	sport = ntohs(ctx->flow->nfr.nfr_saddr.sin.sin_port);
	dport = ntohs(ctx->flow->nfr.nfr_daddr.sin.sin_port);

	my_payload tx_payload;
	bzero(&tx_payload, sizeof(tx_payload));
	tx_payload.packet_number = 0;
	strlcpy(tx_payload.data, "udp_flow_send", sizeof(tx_payload.data));

	struct sktu_frame *tx_frame;
	sktu_create_udp_frames(&tx_frame, 1, IPVERSION,
	    &ctx->our_ip, &ctx->dst_ip, sport, dport, &tx_payload,
	    sizeof(tx_payload), 1500, CSUM_OFFLOAD);
	uuid_copy(tx_frame->flow_uuid, ctx->flow->nfr.nfr_flow_uuid);

	packet_t pkt = sktu_channel_port_frame_to_pkt(&ctx->port, tx_frame);

	uint32_t frame_length = os_packet_get_data_length(pkt);
	/* stuff_off to be greater than actual frame length */
	os_packet_set_inet_checksum(pkt, PACKET_CSUM_PARTIAL, sizeof(struct ip),
	    frame_length + 1);

	struct __user_quantum *uqum = SK_PTR_ADDR_UQUM(pkt);
	/* pkt_length to be greater than stuff_off + sizeof(csum) */
	uqum->qum_len = frame_length + 3;

	sktu_channel_port_tx_burst_pkt(&ctx->port, &pkt, 1);
	/*
	 * With the changes in rdar://problem/72632756, TX thread will crash
	 * after writing an invalid packet.
	 */

	sktu_frame_free(tx_frame);
	return 0;
}

static void *
skt_mangle_rx(void *ctx_)
{
	struct context *ctx = (struct context *)ctx_;
	channel_t channel;
	channel_ring_t rxring;
	ring_dir_t ring_dir = CHANNEL_DIR_RX;
	ring_id_t ring_id = CHANNEL_RING_ID_ANY;
	uint32_t port = 0;
	int kq_fd;
	int error;

	assert(ctx->stage.test_stage == SKT_INIT);

	/* Initialize kqueue */
	kq_fd = kqueue();
	assert(kq_fd >= 0);

	/* Initialize channel */
	channel = sktu_channel_create_extended(
		ctx->nexus_uuid,
		port, ring_dir, ring_id,
		NULL,
		-1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel != NULL);

	ring_id = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	rxring = os_channel_rx_ring(channel, ring_id);
	assert(rxring);

	/* Don't care about watermark, but set units to 'bytes' */
	set_watermark(channel, false, CHANNEL_THRESHOLD_UNIT_BYTES, 1);

	switch (ctx->test_selector) {
	case SKT_CHANGE_LEN:
		/* Let TX send one slot with 10 bytes */
		test_stage_change(&ctx->stage, SKT_TX_TURN);
		test_stage_wait(&ctx->stage, SKT_RX_TURN);

		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(!error);

		/* Receive that slot and mess with its length */
		channel_slot_t slot;
		struct slot_prop prop;
		slot = os_channel_get_next_slot(rxring, NULL, &prop);

		/*
		 * Try to trick the kernel into thinking there are 4 bytes
		 * less than there really are
		 */
		assert(slot);
		prop.sp_len = 6;
		os_channel_set_slot_properties(rxring, slot, &prop);

		error = os_channel_advance_slot(rxring, slot);
		SKTC_ASSERT_ERR(!error);

		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(!error);

		test_stage_change(&ctx->stage, SKT_TX_TURN);

		/*
		 * Get the kernel view of how many bytes are in the ring.
		 * should be the original count.
		 */
		error = wait_on_fd(kq_fd, EVFILT_READ, channel, 0, TIMEOUT_FAIL);
		SKTC_ASSERT_ERR(error == 10);
		break;

	case SKT_BIG_LEN:
		/* Let TX try to send an unreasonably large slot */
		test_stage_change(&ctx->stage, SKT_TX_TURN);

		/*
		 * With the changes in rdar://problem/72632756,
		 * TX side will crash after writing an invalid
		 * length packet.
		 * Hence the below code is commented out.
		 */
#if 0
		test_stage_wait(&ctx->stage, SKT_RX_TURN);

		/* Guarantee the data in the ring is less than what was requested */
		error = wait_on_fd(kq_fd, EVFILT_READ, channel, 0, TIMEOUT_FAIL);
		SKTC_ASSERT_ERR(error == 214);  /* 131 + 83 */
#endif

		break;
	}

	return 0;
}

static void *
skt_mangle_tx(void *ctx_)
{
	struct context *ctx = (struct context *)ctx_;
	channel_t channel;
	channel_ring_t txring;
	ring_dir_t ring_dir = CHANNEL_DIR_TX;
	ring_id_t ring_id = CHANNEL_RING_ID_ANY;
	uint32_t port = 1;
	int error;
	int kq_fd;

	kq_fd = kqueue();
	assert(kq_fd >= 0);

	channel = sktu_channel_create_extended(
		ctx->nexus_uuid,
		port, ring_dir, ring_id,
		NULL,
		-1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel != NULL);

	ring_id = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	txring = os_channel_tx_ring(channel, ring_id);
	assert(txring);

	switch (ctx->test_selector) {
	case SKT_CHANGE_LEN:
		/* Wait for RX to initialize */
		test_stage_wait(&ctx->stage, SKT_TX_TURN);

		/* Send 10 bytes */
		send_bytes(txring, 10);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
		test_stage_change(&ctx->stage, SKT_RX_TURN);
		test_stage_wait(&ctx->stage, SKT_TX_TURN);

		send_bytes(txring, 10);
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
		break;

	case SKT_BIG_LEN: {
		/* Wait for RX to initialize */
		test_stage_wait(&ctx->stage, SKT_TX_TURN);

		/*
		 * Write 3 slots; the one with an invalid length should
		 * be truncated by kernel (to 0 bytes), but not the
		 * other two.
		 */
		slot_prop_t prop;
		channel_slot_t slot = os_channel_get_next_slot(txring, NULL, &prop);
		assert(slot);

		/* Request the largest buffer the kernel structures will allow */
		prop.sp_len = 65535;
		os_channel_set_slot_properties(txring, slot, &prop);

		slot = os_channel_get_next_slot(txring, slot, &prop);
		assert(slot);
		prop.sp_len = 131;
		os_channel_set_slot_properties(txring, slot, &prop);

		slot = os_channel_get_next_slot(txring, slot, &prop);
		assert(slot);
		prop.sp_len = 83;
		os_channel_set_slot_properties(txring, slot, &prop);

		error = os_channel_advance_slot(txring, slot);
		SKTC_ASSERT_ERR(!error);

		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		/* Expect failure (and a process crash) here */

		/*
		 * Sanity checks to localize failures, in case the crash
		 * doesn't succeed:
		 */
		SKTC_ASSERT_ERR(error);
		SKTC_ASSERT_ERR(errno == EFAULT);

		//test_stage_change(&ctx->stage, SKT_RX_TURN);
		break;
	}
	}

	return 0;
}

static int
skt_mangle_main(int argc, char *argv[], int test_selector)
{
	pthread_t rx_thread, tx_thread;
	struct context ctx;
	int error;

	test_stage_init(&ctx.stage, SKT_INIT);
	ctx.argc = argc;
	ctx.argv = argv;
	ctx.test_selector = test_selector;

	error = uuid_parse(argv[3], ctx.nexus_uuid);
	SKTC_ASSERT_ERR(!error);

	error = pthread_create(&rx_thread, NULL, &skt_mangle_rx, &ctx);
	SKTC_ASSERT_ERR(!error);
	error = pthread_create(&tx_thread, NULL, &skt_mangle_tx, &ctx);
	SKTC_ASSERT_ERR(!error);

	pthread_join(rx_thread, NULL);
	pthread_join(tx_thread, NULL);

	test_stage_destroy(&ctx.stage);

	return 0;
}

static int
skt_change_len_main(int argc, char *argv[])
{
	return skt_mangle_main(argc, argv, SKT_CHANGE_LEN);
}

static int
skt_big_len_main(int argc, char *argv[])
{
	return skt_mangle_main(argc, argv, SKT_BIG_LEN);
}

static int
skt_mangle_verify_internalize_metadata_main(int argc, char *argv[])
{
#pragma unused (argc, argv)
	char *utun_addr_str = "10.0.250.1";
	char *peer_addr_str = "10.0.250.2";
	char *broad_addr_str = "10.0.250.255";
	char utun_ifname[IFNAMSIZ + 1];
	struct internalize_ctx ctx;
	struct in_addr broad_ip;
	struct in_addr mask;
	uint16_t sport = 0;
	uint16_t dport = 4321;
	int error;

	inet_pton(AF_INET, utun_addr_str, &ctx.our_ip);
	inet_pton(AF_INET, peer_addr_str, &ctx.dst_ip);
	inet_pton(AF_INET, broad_addr_str, &broad_ip);
	mask = sktc_make_in_addr(IN_CLASSC_NET);

	ctx.utun_fd = sktu_create_interface(SKTU_IFT_UTUN,
	    SKTU_IFF_ENABLE_NETIF | SKTU_IFF_NO_ATTACH_FSW);
	sktu_get_interface_name(SKTU_IFT_UTUN, ctx.utun_fd, utun_ifname);

	if (sktc_ifnet_add_addr(utun_ifname, &ctx.our_ip, &mask, &broad_ip) !=
	    0) {
		err(EX_OSERR, "Failed to add address for %s", utun_ifname);
	}

	if (sktc_ifnet_add_scoped_default_route(utun_ifname, ctx.our_ip) != 0) {
		err(EX_OSERR, "Failed to add default route for %s\n",
		    utun_ifname);
	}

	bzero(&ctx.handles, sizeof(ctx.handles));
	strlcpy(ctx.handles.netif_ifname, utun_ifname,
	    sizeof(ctx.handles.netif_ifname));
	ctx.handles.netif_addr = ctx.our_ip;
	ctx.handles.netif_mask = mask;
	sktc_create_flowswitch_no_address(&ctx.handles, -1, -1, -1, -1, 0);

	error =
	    os_nexus_controller_bind_provider_instance(ctx.handles.controller,
	    ctx.handles.fsw_nx_uuid, 3, getpid(), NULL, NULL, 0,
	    NEXUS_BIND_PID);
	SKTC_ASSERT_ERR(error == 0);

	sktu_channel_port_init(&ctx.port, ctx.handles.fsw_nx_uuid, 3, true,
	    false, false);
	assert(ctx.port.chan != NULL);
	assert(ctx.port.user_packet_pool);

	ctx.flow = sktu_create_nexus_flow(&ctx.handles, AF_INET, &ctx.our_ip,
	    &ctx.dst_ip, IPPROTO_UDP, sport, dport);

	pthread_t tx_thread;

	error = pthread_create(&tx_thread, NULL,
	    &skt_mangle_verify_internalize_metadata, &ctx);
	SKTC_ASSERT_ERR(!error);
	pthread_join(tx_thread, NULL);

	sktu_destroy_nexus_flow(ctx.flow);
	sktc_cleanup_flowswitch(&ctx.handles);
	close(ctx.utun_fd);
	return 0;
}

struct skywalk_test skt_change_len = {
	"change_len", "tests kernel resilience to modified slot lengths",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE |
	SK_FEATURE_DEV_OR_DEBUG,
	skt_change_len_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_mangle_init, skt_mangle_fini,
};

struct skywalk_test skt_big_len = {
	"big_len", "tests unrealistically large slot lengths",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE |
	SK_FEATURE_DEV_OR_DEBUG,
	skt_big_len_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_mangle_init, skt_mangle_fini, (SIGABRT << 24), 0,
};

struct skywalk_test skt_internalizemetdata = {
	.skt_testname = "internalizemetadata",
	.skt_testdesc = "Internalize packet metadata verification",
	.skt_required_features = SK_FEATURE_SKYWALK |
    SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NETNS,
	.skt_main = skt_mangle_verify_internalize_metadata_main,
	.skt_expected_exception_code = (SIGABRT << 24),
	.skt_expected_exception_code_ignore = 0,
};
