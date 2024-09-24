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

/* Copied from skt_oneslot */

static int
skt_shutdown_common(int argc, char *argv[], int method)
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	ring_id_t ringid;
	channel_ring_t ring;
	channel_slot_t slot;
	uint32_t avail;
	slot_prop_t prop;
	int channelfd, sock_fd;
	fd_set rfdset, wfdset, efdset;
	struct pollfd fds, sock_fds;
	int kq;
	struct kevent kev, sock_kev;
	uint64_t ts;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	sock_fd = socket(PF_INET, SOCK_STREAM, 0);
	assert(sock_fd != -1);

	error = pid_shutdown_sockets(getpid(),
	    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
	SKTC_ASSERT_ERR(!error);

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
		SKTC_ASSERT_ERR(error == 1);
		assert(!FD_ISSET(channelfd, &rfdset));
		assert(!FD_ISSET(channelfd, &wfdset));
		assert(FD_ISSET(channelfd, &efdset));
		break;
	case 1:
		sock_fds.fd = sock_fd;
		fds.events = sock_fds.events = POLLWRNORM;
		fds.revents = sock_fds.revents = 0;
		/* socket */
		error = poll(&sock_fds, 1, -1);
		T_LOG("poll sock POLLWRNORM: error(%d) events(0x%x)"
		    " revents(0x%x)\n", error, sock_fds.events,
		    sock_fds.revents);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(sock_fds.fd == sock_fd);
		assert(sock_fds.events == POLLWRNORM);
		assert((sock_fds.revents & POLLHUP) != 0);
		/* channel */
		fds.fd = channelfd;
		error = poll(&fds, 1, -1);
		T_LOG("poll chan POLLWRNORM: error(%d) events(0x%x)"
		    " revents(0x%x)\n", error, fds.events, fds.revents);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		/* ensure that the return values match with socket */
		assert(fds.fd == channelfd);
		assert(fds.events == sock_fds.events);
		assert(fds.revents == sock_fds.revents);
		break;
	case 2:
		/* socket */
		kq = kqueue();
		assert(kq != -1);
		/* event registration */
		EV_SET(&sock_kev, sock_fd, EVFILT_WRITE, EV_ADD | EV_ENABLE,
		    0, 0, NULL);
		error = kevent(kq, &sock_kev, 1, &sock_kev, 1, NULL);
		T_LOG("kqueue sock EVFILT_WRITE: error(%d) "
		    "flags(0x%x) fflags(0x%x) data(0x%lx)\n",
		    error, sock_kev.flags, sock_kev.fflags, sock_kev.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(sock_kev.filter == EVFILT_WRITE);
		assert(sock_kev.ident == sock_fd);
		assert(sock_kev.udata == NULL);
		assert(sock_kev.flags & EV_ADD);
		assert(sock_kev.flags & EV_ENABLE);
		assert(sock_kev.flags & EV_EOF);
		/* event processing */
		error = kevent(kq, NULL, 0, &sock_kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(sock_kev.filter == EVFILT_WRITE);
		assert(sock_kev.ident == sock_fd);
		assert(sock_kev.udata == NULL);
		assert(sock_kev.flags & EV_ADD);
		assert(sock_kev.flags & EV_ENABLE);
		assert(sock_kev.flags & EV_EOF);
		close(kq);
		/* channel */
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kev, channelfd, EVFILT_WRITE, EV_ADD | EV_ENABLE,
		    0, 0, NULL);
		/*
		 * event registration on a defunct channel should
		 * return EV_EOF
		 */
		error = kevent(kq, &kev, 1, &kev, 1, NULL);
		T_LOG("kqueue chan EVFILT_WRITE: error(%d) "
		    "flags(0x%x) fflags(0x%x) data(0x%lx)\n",
		    error, kev.flags, kev.fflags, kev.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		/* ensure that the return values match with socket */
		assert(kev.filter == sock_kev.filter);
		assert(kev.ident == channelfd);
		assert(kev.udata == sock_kev.udata);
		assert(kev.flags == sock_kev.flags);
		assert(kev.data == 0);
		/*
		 * event processing on a defunct channel should
		 * return EV_EOF
		 */
		error = kevent(kq, NULL, 0, &kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		/* ensure that the return values match with socket */
		assert(kev.filter == sock_kev.filter);
		assert(kev.ident == channelfd);
		assert(kev.udata == sock_kev.udata);
		assert(kev.flags == sock_kev.flags);
		assert(kev.data == 0);
		close(kq);
		/* check EVFILT_NW_CHANNEL filter */
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kev, channelfd, EVFILT_NW_CHANNEL, EV_ADD | EV_ENABLE,
		    0, 0, NULL);
		error = kevent(kq, &kev, 1, &kev, 1, NULL);
		T_LOG("kqueue EVFILT_NW_CHANNEL: error(%d) "
		    "flags(0x%x) fflags(0x%x) data(0x%lx)\n",
		    error, kev.flags, kev.fflags, kev.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kev.filter == EVFILT_NW_CHANNEL);
		assert(kev.ident == channelfd);
		assert(kev.udata == NULL);
		assert(kev.flags & EV_ADD);
		assert(kev.flags & EV_ENABLE);
		assert(kev.flags & EV_EOF);
		assert(kev.data == 0);
		error = kevent(kq, NULL, 0, &kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kev.filter == EVFILT_NW_CHANNEL);
		assert(kev.udata == NULL);
		assert(kev.flags & EV_ADD);
		assert(kev.flags & EV_ENABLE);
		assert(kev.flags & EV_EOF);
		assert(kev.data == 0);
		break;
	default:
		abort();
	}

	error = os_channel_is_defunct(channel);
	assert(error != 0);

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	ring = os_channel_tx_ring(channel, ringid);
	assert(ring);

	avail = os_channel_available_slot_count(ring);
	assert(!avail);

	slot = os_channel_get_next_slot(ring, NULL, &prop);
	assert(!slot);

	error = os_channel_advance_slot(ring, slot);
	SKTC_ASSERT_ERR(error == ENXIO);

	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENXIO);

	error = os_channel_pending(ring);
	assert(error == 0);

	ts = os_channel_ring_sync_time(ring);
	assert(ts == 0);

	ts = os_channel_ring_notify_time(ring);
	assert(ts == 0);

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
		SKTC_ASSERT_ERR(error == 1);
		assert(!FD_ISSET(channelfd, &rfdset));
		assert(!FD_ISSET(channelfd, &wfdset));
		assert(FD_ISSET(channelfd, &efdset));
		break;
	case 1:
		sock_fds.fd = sock_fd;
		fds.events = sock_fds.events = POLLRDNORM;
		fds.revents = sock_fds.revents = 0;
		/* socket */
		error = poll(&sock_fds, 1, -1);
		T_LOG("poll sock POLLRDNORM: error(%d) events(0x%x)"
		    " revents(0x%x)\n", error, sock_fds.events,
		    sock_fds.revents);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(sock_fds.fd == sock_fd);
		assert(sock_fds.events == POLLRDNORM);
		assert((sock_fds.revents & POLLHUP) != 0);
		/* channel */
		fds.fd = channelfd;
		error = poll(&fds, 1, -1);
		T_LOG("poll chan POLLRDNORM: error(%d) events(0x%x)"
		    " revents(0x%x)\n", error, fds.events, fds.revents);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		/* ensure that the return values match with socket */
		assert(fds.fd == channelfd);
		assert(fds.events == sock_fds.events);
		assert(fds.revents == sock_fds.revents);
		break;
	case 2:
		/* socket */
		kq = kqueue();
		assert(kq != -1);
		/* event registration */
		EV_SET(&sock_kev, sock_fd, EVFILT_READ, EV_ADD | EV_ENABLE,
		    0, 0, NULL);
		error = kevent(kq, &sock_kev, 1, &sock_kev, 1, NULL);
		T_LOG("kqueue sock EVFILT_READ: error(%d) "
		    "flags(0x%x) fflags(0x%x) data(0x%lx)\n",
		    error, sock_kev.flags, sock_kev.fflags, sock_kev.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(sock_kev.filter == EVFILT_READ);
		assert(sock_kev.ident == sock_fd);
		assert(sock_kev.udata == NULL);
		assert(sock_kev.flags & EV_ADD);
		assert(sock_kev.flags & EV_ENABLE);
		assert(sock_kev.flags & EV_EOF);
		/* event processing */
		error = kevent(kq, NULL, 0, &sock_kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(sock_kev.filter == EVFILT_READ);
		assert(sock_kev.ident == sock_fd);
		assert(sock_kev.udata == NULL);
		assert(sock_kev.flags & EV_ADD);
		assert(sock_kev.flags & EV_ENABLE);
		assert(sock_kev.flags & EV_EOF);
		close(kq);
		/* channel */
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kev, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE,
		    0, 0, NULL);
		/*
		 * event registration on a defunct channel should
		 * return EV_EOF
		 */
		error = kevent(kq, &kev, 1, &kev, 1, NULL);
		T_LOG("kqueue chan EVFILT_READ: error(%d) "
		    "flags(0x%x) fflags(0x%x) data(0x%lx)\n",
		    error, kev.flags, kev.fflags, kev.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		/* ensure that the return values match with socket */
		assert(kev.filter == sock_kev.filter);
		assert(kev.ident == channelfd);
		assert(kev.udata == sock_kev.udata);
		assert(kev.flags == sock_kev.flags);
		assert(kev.data == 0);
		/*
		 * event processing on a defunct channel should
		 * return EV_EOF
		 */
		error = kevent(kq, NULL, 0, &kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		/* ensure that the return values match with socket */
		assert(kev.filter == sock_kev.filter);
		assert(kev.ident == channelfd);
		assert(kev.udata == sock_kev.udata);
		assert(kev.flags == sock_kev.flags);
		assert(kev.data == 0);
		close(kq);
		break;
	default:
		abort();
	}

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	ring = os_channel_rx_ring(channel, ringid);
	assert(ring);

	avail = os_channel_available_slot_count(ring);
	assert(!avail);

	slot = os_channel_get_next_slot(ring, NULL, &prop);
	assert(!slot);

	//T_LOG("Got message \"%s\" len %d\n", (char *)prop.sp_buf_ptr, prop.sp_len);

	// XXX test this?
	//prop.sp_len = 0;
	//os_channel_set_slot_properties(ring, slot, &prop);

	/* slot is NULL here */
	error = os_channel_advance_slot(ring, slot);
	SKTC_ASSERT_ERR(error == ENXIO);

	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENXIO);

	os_channel_destroy(channel);

	return 0;
}

static int
skt_shutdown_select_main(int argc, char *argv[])
{
	return skt_shutdown_common(argc, argv, 0);
}

static int
skt_shutdown_poll_main(int argc, char *argv[])
{
	return skt_shutdown_common(argc, argv, 1);
}

static int
skt_shutdown_kqueue_main(int argc, char *argv[])
{
	return skt_shutdown_common(argc, argv, 2);
}

struct skywalk_test skt_shutdownus = {
	"shutdownus", "shuts down channel on upipe and calls select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_shutdown_select_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_nexus_init, sktc_cleanup_nexus,
};

struct skywalk_test skt_shutdownks = {
	"shutdownks", "shuts down channel on kpipe and calls select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_shutdown_select_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_shutdownup = {
	"shutdownup", "shuts down channel on upipe and calls poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_shutdown_poll_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_nexus_init, sktc_cleanup_nexus,
};

struct skywalk_test skt_shutdownkp = {
	"shutdownkp", "shuts down channel on kpipe and calls poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_shutdown_poll_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_shutdownuk = {
	"shutdownuk", "shuts down channel on upipe and calls kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_shutdown_kqueue_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_nexus_init, sktc_cleanup_nexus,
};

struct skywalk_test skt_shutdownkk = {
	"shutdownkk", "shuts down channel on kpipe and calls kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_shutdown_kqueue_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};
