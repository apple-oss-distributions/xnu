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
#include <sys/sysctl.h>
#include <sys/event.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int old_debug_value;

static int
skt_debug_verify_main(int argc, char *argv[])
{
	int error;
	channel_t channel;
	uuid_t channel_uuid;
	ring_id_t ringid;
	channel_ring_t rxring, txring;
	channel_slot_t slot;
	uint32_t avail;
	slot_prop_t prop;
	int channelfd;
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

	kq = kqueue();
	assert(kq != -1);
	EV_SET(&kev, channelfd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, &kev, 1, NULL);
	SKTC_ASSERT_ERR(error != -1);
	SKTC_ASSERT_ERR(error == 1);
	assert(kev.filter == EVFILT_WRITE);
	assert(kev.ident == channelfd);
	assert(kev.udata == NULL);
	close(kq);

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_TX_RING);
	txring = os_channel_tx_ring(channel, ringid);
	assert(txring);

	avail = os_channel_available_slot_count(txring);
	assert(avail);

	slot = os_channel_get_next_slot(txring, NULL, &prop);
	assert(slot);

	assert(prop.sp_buf_ptr);
	assert(prop.sp_len);

	memcpy((void *)prop.sp_buf_ptr, msg, sizeof(msg));
	prop.sp_len = sizeof(msg);
	os_channel_set_slot_properties(txring, slot, &prop);

	error = os_channel_advance_slot(txring, slot);
	SKTC_ASSERT_ERR(!error);

	error = os_channel_sync(channel, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(!error);

	kq = kqueue();
	assert(kq != -1);
	EV_SET(&kev, channelfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, &kev, 1, NULL);
	SKTC_ASSERT_ERR(error != -1);
	SKTC_ASSERT_ERR(error == 1);
	assert(kev.filter == EVFILT_READ);
	assert(kev.ident == channelfd);
	assert(kev.udata == NULL);
	close(kq);

	ringid = os_channel_ring_id(channel, CHANNEL_FIRST_RX_RING);
	rxring = os_channel_rx_ring(channel, ringid);
	assert(rxring);

	avail = os_channel_available_slot_count(rxring);
	assert(avail);

	slot = os_channel_get_next_slot(rxring, NULL, &prop);
	assert(slot);

	assert(prop.sp_buf_ptr);
	assert(!memcmp((void *)prop.sp_buf_ptr, msg, sizeof(msg)));
	assert(prop.sp_len == sizeof(msg));

	/* Finish up */

	error = os_channel_advance_slot(rxring, slot);
	SKTC_ASSERT_ERR(!error);

	error = os_channel_sync(channel, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(!error);

	os_channel_destroy(channel);

	return 0;
}

/*
 * TODO: Right now, the flag macros for the skywalk.debug register are in a
 * private kernel header. Ideally we would specify SKF_VERIFY instead of the
 * direct value '1' here, and at some point should fix things up so we can.
 * See: <rdar://problem/26142697> Allow Skywalk unit tests to specify both
 * development and debug kernel compatibility
 */
void
skt_debug_verify_u_init(void)
{
	int error;

	int new_debug_value = 1;
	size_t old_size = sizeof(int);
	error = sysctlbyname("kern.skywalk.debug", &old_debug_value, &old_size,
	    &new_debug_value, sizeof(int));
	if (error) {
		T_LOG("%s: warning sysctl(\"kern.skywalk.debug\" returned %d: %s",
		    __func__, error, strerror(errno));
	}

	sktc_generic_upipe_echo_init();
}

void
skt_debug_verify_u_fini(void)
{
	int error;

	sktc_generic_upipe_fini();

	error = sysctlbyname("kern.skywalk.debug", NULL, 0, &old_debug_value,
	    sizeof(int));
	if (error) {
		T_LOG("%s: warning sysctl(\"kern.skywalk.debug\" returned %d: %s",
		    __func__, error, strerror(errno));
	}
}

void
skt_debug_verify_k_init(void)
{
	int error;

	int new_debug_value = 1;
	size_t old_size = sizeof(int);
	error = sysctlbyname("kern.skywalk.debug", &old_debug_value, &old_size,
	    &new_debug_value, sizeof(int));
	if (error) {
		T_LOG("%s: warning sysctl(\"kern.skywalk.debug\" returned %d: %s",
		    __func__, error, strerror(errno));
	}

	sktc_generic_kpipe_init();
}

void
skt_debug_verify_k_fini(void)
{
	int error;

	sktc_generic_kpipe_fini();

	error = sysctlbyname("kern.skywalk.debug", NULL, 0, &old_debug_value,
	    sizeof(int));
	if (error) {
		T_LOG("%s: warning sysctl(\"kern.skywalk.debug\" returned %d: %s",
		    __func__, error, strerror(errno));
	}
}

struct skywalk_test skt_debug_verify_u = {
	"debug_verify_u", "test confirms that skywalk is storing checksums of slots received on a upipe when in SKF_VERIFY debug mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_DEV_OR_DEBUG | SK_FEATURE_NEXUS_USER_PIPE,
	skt_debug_verify_main, SKTC_GENERIC_UPIPE_ARGV,
	skt_debug_verify_u_init, skt_debug_verify_u_fini,
};

struct skywalk_test skt_debug_verify_k = {
	"debug_verify_k", "test confirms that skywalk is storing checksums of slots received on a kpipe when in SKF_VERIFY debug mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_DEV_OR_DEBUG | SK_FEATURE_NEXUS_KERNEL_PIPE |
	SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK,
	skt_debug_verify_main, SKTC_GENERIC_KPIPE_ARGV,
	skt_debug_verify_k_init, skt_debug_verify_k_fini,
};


/****************************************************************/
