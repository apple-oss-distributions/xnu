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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/event.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int
skt_badringtx_common(int argc, char *argv[], int method)
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	fd_set rfdset, wfdset, efdset;
	struct pollfd fds;
	int kq;
	struct kevent kevin, kevout;
	ring_id_t ringid;
	channel_ring_t ring;
	int channelfd;
	struct timeval timeout;
	struct timespec ktimeout;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	ring = os_channel_tx_ring(channel, ringid);
	assert(ring);

	struct __user_channel_ring *cr = (struct __user_channel_ring *)ring->chrd_ring; // deconst

	cr->ring_head = -1;
	*(slot_idx_t *)(uintptr_t)&cr->ring_tail = -1;

	switch (method) {
	case 0:
		memset(&timeout, 0, sizeof(timeout));
		FD_ZERO(&rfdset);
		FD_SET(channelfd, &rfdset);
		FD_ZERO(&wfdset);
		FD_SET(channelfd, &wfdset);
		FD_ZERO(&efdset);
		FD_SET(channelfd, &efdset);
		error = select(channelfd + 1, &rfdset, &wfdset, &efdset, &timeout);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 2);
		assert(!FD_ISSET(channelfd, &rfdset));
		assert(FD_ISSET(channelfd, &wfdset));  // XXX is it correct to return writable as well as error?
		assert(FD_ISSET(channelfd, &efdset));
		break;
	case 1:
		fds.fd = channelfd;
		fds.events = POLLSTANDARD;
		fds.revents = 0;
		error = poll(&fds, 1, 0);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(fds.fd == channelfd);
		assert(fds.events == POLLSTANDARD);
		T_LOG("events 0x%x revents 0x%x check 0x%x\n", fds.events, fds.revents, (POLLWRNORM | POLLWRBAND | POLLERR));
		assert(fds.revents == POLLNVAL);
		/*
		 * XXX poll() can also fail with POLLERR, if the error condition occurs
		 * while waiting, instead of before - should find some way to test that
		 * scenario
		 */
		break;
	case 2:
		memset(&ktimeout, 0, sizeof(ktimeout));
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kevin, channelfd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
		memset(&kevout, 0, sizeof(kevout));
		error = kevent(kq, &kevin, 1, &kevout, 1, &ktimeout);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		T_LOG("error %d flags 0x%x data 0x%lx\n", error, kevout.flags, kevout.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kevout.filter == EVFILT_WRITE);
		assert(kevout.ident == channelfd);
		assert(kevout.udata == NULL);
		assert(kevout.flags & EV_ERROR);
		assert(kevout.data == EFAULT);
		close(kq);
		break;
	case 3:
		error = os_channel_sync(channel, CHANNEL_SYNC_TX);
		/* SHOULD NOT BE REACHED */

		T_LOG("error = %d\n", error);
		SKTC_ASSERT_ERR(error);
		SKTC_ASSERT_ERR(errno == EFAULT);
		break;
	default:
		abort();
	}

	return 1;
}

static int
skt_badringrx_common(int argc, char *argv[], int method)
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	fd_set rfdset, wfdset, efdset;
	struct pollfd fds;
	int kq;
	struct kevent kevin, kevout;
	ring_id_t ringid;
	channel_ring_t ring;
	int channelfd;
	struct timeval timeout;
	struct timespec ktimeout;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	ring = os_channel_rx_ring(channel, ringid);
	assert(ring);

	struct __user_channel_ring *cr = (struct __user_channel_ring *)ring->chrd_ring; // deconst

	cr->ring_head = -1;
	*(slot_idx_t *)(uintptr_t)&cr->ring_tail = -1;

	switch (method) {
	case 0:
		memset(&timeout, 0, sizeof(timeout));
		FD_ZERO(&rfdset);
		FD_SET(channelfd, &rfdset);
		FD_ZERO(&wfdset);
		FD_SET(channelfd, &wfdset);
		FD_ZERO(&efdset);
		FD_SET(channelfd, &efdset);
		error = select(channelfd + 1, &rfdset, &wfdset, &efdset, &timeout);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 2);
		assert(!FD_ISSET(channelfd, &rfdset));
		assert(FD_ISSET(channelfd, &wfdset));  // XXX is it correct to return writable as well as error?
		assert(FD_ISSET(channelfd, &efdset));
		break;
	case 1:
		fds.fd = channelfd;
		fds.events = POLLSTANDARD;
		fds.revents = 0;
		error = poll(&fds, 1, 0);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(fds.fd == channelfd);
		assert(fds.events == POLLSTANDARD);
		T_LOG("events 0x%x revents 0x%x\n", fds.events, fds.revents);
		assert(fds.revents == POLLNVAL);
		/*
		 * XXX poll() can also fail with POLLERR, if the error condition occurs
		 * while waiting, instead of before - should find some way to test that
		 * scenario
		 */
		break;
	case 2:
		memset(&ktimeout, 0, sizeof(ktimeout));
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kevin, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
		memset(&kevout, 0, sizeof(kevout));
		error = kevent(kq, &kevin, 1, &kevout, 1, &ktimeout);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		T_LOG("error %d flags 0x%x data 0x%lx\n", error, kevout.flags, kevout.data);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kevout.filter == EVFILT_READ);
		assert(kevout.ident == channelfd);
		assert(kevout.udata == NULL);
		assert(kevout.flags & EV_ERROR);
		assert(kevout.data == EFAULT);
		close(kq);
		break;
	case 3:
		error = os_channel_sync(channel, CHANNEL_SYNC_RX);
		/* SHOULD NOT BE REACHED */

		/*
		 * Sanity checks to localize failures, in case the crash doesn't
		 * succeed:
		 */
		SKTC_ASSERT_ERR(error);
		SKTC_ASSERT_ERR(errno == EFAULT);
		break;
	default:
		abort();
	}

	return 1;
}


static int
skt_badringtl_main(int argc, char *argv[])
{
	return skt_badringtx_common(argc, argv, 0);
}

struct skywalk_test skt_badringtl = {
	"badringtl", "calls select with bad tx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringtl_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringtp_main(int argc, char *argv[])
{
	return skt_badringtx_common(argc, argv, 1);
}

struct skywalk_test skt_badringtp = {
	"badringtp", "calls poll with bad tx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringtp_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringtk_main(int argc, char *argv[])
{
	return skt_badringtx_common(argc, argv, 2);
}

struct skywalk_test skt_badringtk = {
	"badringtk", "calls kqueue with bad tx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringtk_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringts_main(int argc, char *argv[])
{
	return skt_badringtx_common(argc, argv, 3);
}

struct skywalk_test skt_badringts = {
	"badringts", "calls sync with bad tx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringts_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringrl_main(int argc, char *argv[])
{
	return skt_badringrx_common(argc, argv, 0);
}

struct skywalk_test skt_badringrl = {
	"badringrl", "calls select with bad rx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringrl_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringrp_main(int argc, char *argv[])
{
	return skt_badringrx_common(argc, argv, 1);
}

struct skywalk_test skt_badringrp = {
	"badringrp", "calls poll with bad rx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringrp_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringrk_main(int argc, char *argv[])
{
	return skt_badringrx_common(argc, argv, 2);
}

struct skywalk_test skt_badringrk = {
	"badringrk", "calls kqueue with bad rx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringrk_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};

static int
skt_badringrs_main(int argc, char *argv[])
{
	return skt_badringrx_common(argc, argv, 3);
}

struct skywalk_test skt_badringrs = {
	"badringrs", "calls sync with bad rx ring pointers",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_badringrs_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	SIGABRT << 24, 0,
};


/***************************************************************/
