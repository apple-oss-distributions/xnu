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
#include <stdio.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int
skt_closecfd_main(int argc, char *argv[])
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	int channelfd;

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	error = close(channelfd); // expected guarded fd fail.
	SKTC_ASSERT_ERR(!error);

	return 1; // should not reach
}

struct skywalk_test skt_closecfd = {
	"closecfd", "test closing guarded channel fd",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_closecfd_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
	0x4000000100000000, 0xFFFFFFFF,
};

/****************************************************************/

static int
skt_writecfd_main(int argc, char *argv[])
{
	int error;
	ssize_t ret;
	channel_t channel;
	uuid_t channel_uuid;
	int channelfd;
	char buf[100];

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	ret = write(channelfd, buf, sizeof(buf));
	assert(ret == -1);
	SKTC_ASSERT_ERR(errno == EBADF);

	return 0;
}

struct skywalk_test skt_writecfd = {
	"writecfd", "test writing to channel fd",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_writecfd_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
};


/****************************************************************/

static int
skt_readcfd_main(int argc, char *argv[])
{
	int error;
	ssize_t ret;
	channel_t channel;
	uuid_t channel_uuid;
	int channelfd;
	char buf[100];

	error = uuid_parse(argv[3], channel_uuid);
	SKTC_ASSERT_ERR(!error);

	channel = sktu_channel_create_extended(channel_uuid, 0,
	    CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, -1, 1, -1, -1);
	assert(channel);

	channelfd = os_channel_get_fd(channel);
	assert(channelfd != -1);

	ret = read(channelfd, buf, sizeof(buf));
	assert(ret == -1);
	SKTC_ASSERT_ERR(errno == EBADF);

	return 0;
}

struct skywalk_test skt_readcfd = {
	"readcfd", "test reading from channel fd",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_readcfd_main, SKTC_GENERIC_UPIPE_ARGV,
	sktc_generic_upipe_null_init, sktc_generic_upipe_fini,
};

/****************************************************************/
