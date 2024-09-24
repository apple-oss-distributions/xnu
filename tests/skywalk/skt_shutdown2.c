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
#include <pthread.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

/* Gets channel waiting in kevent/poll/select and then shuts down channel */

static void *
thread1(void *unused)
{
	int error;
	usleep(100000); /* Make sure main thread gets into kevent */
	//sleep(5); /* Make sure main thread gets into kevent */
	T_LOG("shutdown sockets\n");
	error = pid_shutdown_sockets(getpid(), SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
	SKTC_ASSERT_ERR(!error);
	return NULL;
}

static int
skt_shutdown2_common(int argc, char *argv[], int method)
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	int channelfd;
	fd_set rfdset, efdset;
	struct pollfd fds;
	int kq;
	pthread_t thread;
	struct kevent kev;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	error = pthread_create(&thread, NULL, &thread1, NULL);
	SKTC_ASSERT_ERR(error == 0);

	switch (method) {
	case 0:
		FD_ZERO(&rfdset);
		FD_ZERO(&efdset);
		FD_SET(channelfd, &rfdset);
		FD_SET(channelfd, &efdset);
		error = select(channelfd + 1, &rfdset, NULL, &efdset, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(!FD_ISSET(channelfd, &rfdset));
		assert(FD_ISSET(channelfd, &efdset));
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
		assert(fds.revents == (POLLRDNORM | POLLHUP));
		break;
	case 2:
		kq = kqueue();
		assert(kq != -1);
		EV_SET(&kev, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
		    NULL);
		error = kevent(kq, &kev, 1, &kev, 1, NULL);
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error == 1);
		assert(kev.filter == EVFILT_READ);
		assert(kev.ident == channelfd);
		assert(kev.udata == NULL);
		assert(kev.flags & EV_EOF);
		assert(kev.data == 0);
		close(kq);
		break;
	default:
		abort();
	}

	os_channel_destroy(channel);

	error = pthread_join(thread, NULL);
	SKTC_ASSERT_ERR(error == 0);

	return 0;
}

static int
skt_shutdown2_select_main(int argc, char *argv[])
{
	return skt_shutdown2_common(argc, argv, 0);
}

static int
skt_shutdown2_poll_main(int argc, char *argv[])
{
	return skt_shutdown2_common(argc, argv, 1);
}

static int
skt_shutdown2_kqueue_main(int argc, char *argv[])
{
	return skt_shutdown2_common(argc, argv, 2);
}

struct skywalk_test skt_shutdown2us = {
	"shutdown2us", "shuts down channel on upipe while in select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_shutdown2_select_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_nexus_init, sktc_cleanup_nexus,
};

struct skywalk_test skt_shutdown2ks = {
	"shutdown2ks", "shuts down channel on kpipe while in select",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_shutdown2_select_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_shutdown2up = {
	"shutdown2up", "shuts down channel on upipe while in poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_shutdown2_poll_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_nexus_init, sktc_cleanup_nexus,
};

struct skywalk_test skt_shutdown2kp = {
	"shutdown2kp", "shuts down channel on kpipe while in poll",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_shutdown2_poll_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};

struct skywalk_test skt_shutdown2uk = {
	"shutdown2uk", "shuts down channel on upipe while in kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_shutdown2_kqueue_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_nexus_init, sktc_cleanup_nexus,
};

struct skywalk_test skt_shutdown2kk = {
	"shutdown2kk", "shuts down channel on kpipe while in kqueue",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE | SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_shutdown2_kqueue_main, SKTC_GENERIC_KPIPE_ARGV,
	sktc_generic_kpipe_init, sktc_generic_kpipe_fini,
};
