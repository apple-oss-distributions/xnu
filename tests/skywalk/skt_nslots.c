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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/event.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

int
skt_nslots_common(int argc, char *argv[], uint32_t nslots, uint32_t interval, int method)
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	ring_id_t ringid;
	channel_ring_t ring;
	channel_slot_t prev, slot;
	channel_attr_t attr;
	uint32_t avail;
	slot_prop_t prop;
	int channelfd;
	uint32_t sendcount;
	uint32_t recvcount;
	uint64_t slotsize;
	fd_set fdset, efdset;
	struct pollfd fds;
	int kq;
	struct kevent kev;
	time_t start = time(NULL);
	time_t now, then = start;

	sendcount = 0;
	recvcount = 0;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	switch (method) {
	case 0:
		FD_ZERO(&fdset);
		FD_ZERO(&efdset);
		break;
	case 1:
		fds.fd = channelfd;
		break;
	case 2:
		kq = kqueue();
		assert(kq != -1);
		break;
	default:
		abort();
	}

	attr = os_channel_attr_create();

	error = os_channel_read_attr(channel, attr);
	SKTC_ASSERT_ERR(!error);

	if (nslots == -1) {
		uint64_t attrval = -1;
		error = os_channel_attr_get(attr, CHANNEL_ATTR_TX_SLOTS, &attrval);
		SKTC_ASSERT_ERR(!error);
		assert(attrval != -1);
		nslots = attrval;
	}

	slotsize = -1;
	error = os_channel_attr_get(attr, CHANNEL_ATTR_SLOT_BUF_SIZE, &slotsize);
	SKTC_ASSERT_ERR(!error);
	assert(slotsize != -1);
	assert(slotsize >= sizeof(sendcount));

	os_channel_attr_destroy(attr);

	while (recvcount < nslots) {
		now = time(NULL);
		if (now > then) {
			T_LOG("time %ld send %d recv %d of %d (%2.2f%%, est %ld secs left)\n",
			    now - start, sendcount, recvcount, nslots,
			    (double)recvcount * 100 / nslots,
			    (long)((double)(now - start) * nslots / recvcount) - (now - start));
			then = now;
		}

		if (sendcount < nslots) {
			ringid = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
			ring = os_channel_tx_ring(channel, ringid);
			assert(ring);

			switch (method) {
			case 0:
				FD_SET(channelfd, &fdset);
				FD_SET(channelfd, &efdset);
				error = select(channelfd + 1, NULL, &fdset, &efdset, NULL);
				SKTC_ASSERT_ERR(error != -1);
				SKTC_ASSERT_ERR(error == 1);
				assert(FD_ISSET(channelfd, &fdset));
				assert(!FD_ISSET(channelfd, &efdset));
				break;
			case 1:
				fds.events = POLLWRNORM;
				error = poll(&fds, 1, -1);
				SKTC_ASSERT_ERR(error != -1);
				SKTC_ASSERT_ERR(error == 1);
				assert(fds.fd == channelfd);
				assert(fds.events == POLLWRNORM);
				assert(fds.revents == POLLWRNORM);
				break;
			case 2:
				EV_SET(&kev, channelfd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0, NULL);
				error = kevent(kq, &kev, 1, &kev, 1, NULL);
				SKTC_ASSERT_ERR(error != -1);
				SKTC_ASSERT_ERR(error == 1);
				assert(kev.filter == EVFILT_WRITE);
				assert(kev.ident == channelfd);
				assert(kev.udata == NULL);
				break;
			default:
				abort();
			}

			avail = os_channel_available_slot_count(ring);
			assert(avail);

			prev = NULL;
			slot = os_channel_get_next_slot(ring, NULL, &prop);
			assert(slot);

			for (uint32_t i = 0; i < avail; i++) {
				assert(slot);

				if (sendcount == nslots || i == interval) {
					slot = NULL;
					break;
				}

				assert(prop.sp_len == slotsize);
				memcpy((void *)prop.sp_buf_ptr, &sendcount, sizeof(sendcount));
				prop.sp_len = sizeof(sendcount);
				os_channel_set_slot_properties(ring, slot, &prop);
				sendcount++;

				prev = slot;
				slot = os_channel_get_next_slot(ring, slot, &prop);
			}
			assert(!slot);
			assert(prev);

			error = os_channel_advance_slot(ring, prev);
			SKTC_ASSERT_ERR(!error);

			error = os_channel_sync(channel, CHANNEL_SYNC_TX);
			SKTC_ASSERT_ERR(!error);
		}

		ringid = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
		ring = os_channel_rx_ring(channel, ringid);
		assert(ring);

		switch (method) {
		case 0:
			FD_SET(channelfd, &fdset);
			FD_SET(channelfd, &efdset);
			error = select(channelfd + 1, &fdset, NULL, &efdset, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);
			assert(FD_ISSET(channelfd, &fdset));
			assert(!FD_ISSET(channelfd, &efdset));
			break;
		case 1:
			fds.events = POLLRDNORM;
			error = poll(&fds, 1, -1);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);
			assert(fds.fd == channelfd);
			assert(fds.events == POLLRDNORM);
			assert(fds.revents == POLLRDNORM);
			break;
		case 2:
			EV_SET(&kev, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0, NULL);
			error = kevent(kq, &kev, 1, &kev, 1, NULL);
			SKTC_ASSERT_ERR(error != -1);
			SKTC_ASSERT_ERR(error == 1);
			assert(kev.filter == EVFILT_READ);
			assert(kev.ident == channelfd);
			assert(kev.udata == NULL);
			break;
		default:
			abort();
		}

		avail = os_channel_available_slot_count(ring);
		assert(avail);

		prev = NULL;
		slot = os_channel_get_next_slot(ring, NULL, &prop);

		for (uint32_t i = 0; i < avail; i++) {
			assert(slot);

			assert(prop.sp_len == sizeof(recvcount));
			uint32_t count;
			memcpy(&count, (void *)prop.sp_buf_ptr, sizeof(count));
			assert(!memcmp(&recvcount, (void *)prop.sp_buf_ptr, sizeof(recvcount)));
			recvcount++;

			prev = slot;
			slot = os_channel_get_next_slot(ring, slot, &prop);
		}
		assert(!slot);
		assert(prev);

		error = os_channel_advance_slot(ring, prev);
		SKTC_ASSERT_ERR(!error);

		//T_LOG("rx sync %d\n", avail);

		// Unnecessary
		//error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		//SKTC_ASSERT_ERR(!error);
	}

	now = time(NULL);
	T_LOG("total time %ld for %d slots (rate %.2f)\n",
	    now - start, nslots, (double)nslots / (now - start));

	switch (method) {
	case 0:
		break;
	case 1:
		break;
	case 2:
		error = close(kq);
		SKTC_ASSERT_ERR(!error);
		break;
	default:
		abort();
	}

	os_channel_destroy(channel);

	return 0;
}

int
skt_nslots_select_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, -1, -1, 0);
}

int
skt_nslots_poll_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, -1, -1, 1);
}

int
skt_nslots_kqueue_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, -1, -1, 2);
}

struct skywalk_test skt_nslotsus = {
	"nslotsus", "test sends TX_SLOTS of data on user pipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_nslots_select_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_nslotsks = {
	"nslotsks", "test sends TX_SLOTS of data on kpipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_nslots_select_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_nslotsup = {
	"nslotsup", "test sends TX_SLOTS of data on user pipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_nslots_poll_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_nslotskp = {
	"nslotskp", "test sends TX_SLOTS of data on kpipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_nslots_poll_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_nslotsuk = {
	"nslotsuk", "test sends TX_SLOTS of data on user pipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_nslots_kqueue_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_nslotskk = {
	"nslotskk", "test sends TX_SLOTS of data on kpipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_nslots_kqueue_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

/****************************************************************/
// <rdar://problem/25995625> Need skywalk unit test that streams packets over upipe for a long time

#define MSLOTS 1000000
int
skt_mslots_select_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, MSLOTS, -1, 0);
}

int
skt_mslots_poll_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, MSLOTS, -1, 1);
}

int
skt_mslots_kqueue_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, MSLOTS, -1, 2);
}

struct skywalk_test skt_mslotsus = {
	"mslotsus", "test sends 1000000 slots of data on user pipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_mslots_select_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_mslotsks = {
	"mslotsks", "test sends 1000000 slots of data on kpipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_mslots_select_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_mslotsup = {
	"mslotsup", "test sends 1000000 slots of data on user pipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_mslots_poll_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_mslotskp = {
	"mslotskp", "test sends 1000000 slots of data on kpipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_mslots_poll_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_mslotsuk = {
	"mslotsuk", "test sends 1000000 slots of data on user pipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_mslots_kqueue_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_mslotskk = {
	"mslotskk", "test sends 1000000 slots of data on kpipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_mslots_kqueue_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

/****************************************************************/

#define MMSLOTS 10000000
int
skt_mmslots_select_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, MMSLOTS, -1, 0);
}

int
skt_mmslots_poll_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, MMSLOTS, -1, 1);
}

int
skt_mmslots_kqueue_main(int argc, char *argv[])
{
	return skt_nslots_common(argc, argv, MMSLOTS, -1, 2);
}

struct skywalk_test skt_mmslotsus = {
	"mmslotsus", "test sends 10000000 slots of data on user pipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_mmslots_select_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_mmslotsks = {
	"mmslotsks", "test sends 10000000 slots of data on kpipe loopback using select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_mmslots_select_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_mmslotsup = {
	"mmslotsup", "test sends 10000000 slots of data on user pipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_mmslots_poll_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_mmslotskp = {
	"mmslotskp", "test sends 10000000 slots of data on kpipe loopback using poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_mmslots_poll_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_mmslotsuk = {
	"mmslotsuk", "test sends 10000000 slots of data on user pipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_mmslots_kqueue_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_echo_init, sktc_generic_upipe_fini,
};

struct skywalk_test skt_mmslotskk = {
	"mmslotskk", "test sends 10000000 slots of data on kpipe loopback using kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_mmslots_kqueue_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

/****************************************************************/
