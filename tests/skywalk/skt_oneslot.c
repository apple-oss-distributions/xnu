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
#include <uuid/uuid.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int
skt_oneslot_common(int argc, char *argv[], int method, bool defunct)
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	ring_id_t ringid;
	channel_ring_t ring;
	channel_slot_t slot;
	uint32_t avail;
	slot_prop_t prop;
	int channelfd;
	fd_set rfdset, wfdset, efdset;
	struct pollfd fds;
	int kq;
	struct kevent kev;
	const char msg[] = "Time flies like an arrow;  fruit flies like a banana.";

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	if (defunct) {
		/*
		 * In this test case the other end of the user-pipe is not
		 * eligible for defunct, so this defunct call should have no
		 * impact on this channel and the data path should still work.
		 */
		error = pid_shutdown_sockets(getpid(),
		    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
		SKTC_ASSERT_ERR(!error);
	}

	switch (method) {
	case 0:
		FD_ZERO(&rfdset);
		FD_ZERO(&wfdset);
		FD_ZERO(&efdset);
		FD_SET(channelfd, &rfdset);
		FD_SET(channelfd, &wfdset);
		FD_SET(channelfd, &efdset);
		error = select(channelfd + 1, &rfdset, &wfdset, &efdset, NULL);
		SKTC_ASSERT_ERR(error != -1);
		assert(!FD_ISSET(channelfd, &rfdset));
		assert(FD_ISSET(channelfd, &wfdset));
		assert(!FD_ISSET(channelfd, &efdset));
		SKTC_ASSERT_ERR(error == 1);
		break;
	case 1:
		fds.fd = channelfd;
		fds.events = POLLWRNORM;
		fds.revents = 0;
		error = poll(&fds, 1, -1);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(fds.fd == channelfd);
		assert(fds.events == POLLWRNORM);
		assert(fds.revents == POLLWRNORM);
		break;
	case 2:
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kev, channelfd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
		error = kevent(kq, &kev, 1, &kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kev.filter == EVFILT_WRITE);
		assert(kev.ident == channelfd);
		assert(kev.udata == NULL);
		assert((kev.flags & EV_ERROR) == 0);
		close(kq);
		break;
	default:
		abort();
	}

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	ring = os_channel_tx_ring(channel, ringid);
	assert(ring);

	avail = os_channel_available_slot_count(ring);
	assert(avail);

	slot = os_channel_get_next_slot(ring, NULL, &prop);
	assert(slot);

	assert(prop.sp_buf_ptr);
	assert(prop.sp_len);

	memcpy((void *)prop.sp_buf_ptr, msg, sizeof(msg));
	prop.sp_len = sizeof(msg);
	os_channel_set_slot_properties(ring, slot, &prop);

	error = os_channel_advance_slot(ring, slot);
	SKTC_ASSERT_ERR(!error);

	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	switch (method) {
	case 0:
		FD_ZERO(&rfdset);
		FD_ZERO(&efdset);
		FD_SET(channelfd, &rfdset);
		FD_SET(channelfd, &efdset);
		error = select(channelfd + 1, &rfdset, NULL, &efdset, NULL);
		SKTC_ASSERT_ERR(error != -1);
		assert(!FD_ISSET(channelfd, &efdset));
		assert(FD_ISSET(channelfd, &wfdset));
		SKTC_ASSERT_ERR(error == 1);
		break;
	case 1:
		fds.fd = channelfd;
		fds.events = POLLRDNORM;
		fds.revents = 0;
		error = poll(&fds, 1, -1);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(fds.fd == channelfd);
		assert(fds.events == POLLRDNORM);
		assert(fds.revents == POLLRDNORM);
		break;
	case 2:
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kev, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
		error = kevent(kq, &kev, 1, &kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kev.filter == EVFILT_READ);
		assert(kev.ident == channelfd);
		assert(kev.udata == NULL);
		assert((kev.flags & EV_ERROR) == 0);
		close(kq);
		break;
	default:
		abort();
	}

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	ring = os_channel_rx_ring(channel, ringid);
	assert(ring);

	avail = os_channel_available_slot_count(ring);
	assert(avail);

	slot = os_channel_get_next_slot(ring, NULL, &prop);
	assert(slot);

	assert(prop.sp_buf_ptr);
	assert(!memcmp((void *)prop.sp_buf_ptr, msg, sizeof(msg)));
	assert(prop.sp_len == sizeof(msg));

	//T_LOG("Got message \"%s\" len %d\n", (char *)prop.sp_buf_ptr, prop.sp_len);

	// XXX test this?
	//prop.sp_len = 0;
	//os_channel_set_slot_properties(ring, slot, &prop);

	error = os_channel_advance_slot(ring, slot);
	SKTC_ASSERT_ERR(!error);

	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	os_channel_destroy(channel);

	return 0;
}

static int
skt_oneslot_select_main(int argc, char *argv[])
{
	return skt_oneslot_common(argc, argv, 0, false);
}

static int
skt_oneslot_poll_main(int argc, char *argv[])
{
	return skt_oneslot_common(argc, argv, 1, false);
}

static int
skt_oneslot_kqueue_main(int argc, char *argv[])
{
	return skt_oneslot_common(argc, argv, 2, false);
}

static int
skt_oneslot_kqueue_defunct_main(int argc, char *argv[])
{
	return skt_oneslot_common(argc, argv, 2, true);
}

void
skt_oneslot_upipe_echo_defunct_init(void)
{
	sktc_generic_upipe_nexus_init();
	sktc_setup_channel_worker(sktc_instance_uuid, 1, CHANNEL_RING_ID_ANY,
	    NULL, 0, true, false);
}

struct skywalk_test skt_oneslotus = {
	"oneslotus", "test sends one slot of data on user pipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_oneslot_select_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_oneslotks = {
	"oneslotks", "test sends one slot of data on kpipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_oneslot_select_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_oneslotup = {
	"oneslotup", "test sends one slot of data on user pipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_oneslot_poll_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_oneslotkp = {
	"oneslotkp", "test sends one slot of data on kpipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_oneslot_poll_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_oneslotuk = {
	"oneslotuk", "test sends one slot of data on user pipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_oneslot_kqueue_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_oneslotkk = {
	"oneslotkk", "test sends one slot of data on kpipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_oneslot_kqueue_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_oneslotuk_defunct = {
	"oneslotukd", "test sends one slot of data on user pipe loopback using kqueue with one end of the pipe defuncted",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_oneslot_kqueue_defunct_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_oneslot_upipe_echo_defunct_init, sktc_generic_upipe_fini,
};
