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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <darwintest.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static channel_t channel;
static int tunsock;
static pthread_t thread;

static void *
thread1(void *unused)
{
	int kq = kqueue();
	struct kevent kevin, kevout;
	int error;

	memset(&kevin, 0, sizeof(kevin));
	memset(&kevout, 0, sizeof(kevout));
	EV_SET(&kevin, os_channel_get_fd(channel), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kevin, 1, &kevout, 1, NULL);
	/* This shouldn't be reached, but if it does, dump some debug info */
	SKT_LOG("unexpeced kevent returned %d, errno %d\n", error, errno);
	T_LOG("kevin ident 0x%"PRIxPTR", filter %d, "
	    "flags 0x%04x fflags 0x%08x data 0x%"PRIxPTR" udata %p\n",
	    kevin.ident, kevin.filter, kevin.flags, kevin.fflags,
	    kevin.data, kevin.udata);
	T_LOG("kevout ident 0x%"PRIxPTR", filter %d, "
	    "flags 0x%04x fflags 0x%08x data 0x%"PRIxPTR" udata %p\n",
	    kevout.ident, kevout.filter, kevout.flags, kevout.fflags,
	    kevout.data, kevout.udata);
	assert(0);
}

static void
skt_utun27302538_common(void)
{
	tunsock = sktu_create_interface(SKTU_IFT_UTUN, SKTU_IFF_ENABLE_NETIF);
	assert(tunsock);

	usleep(100000);

	channel = sktu_create_interface_channel(SKTU_IFT_UTUN, tunsock);
	assert(channel);
}

/*
 * <rdar://problem/27302538> kernel panic during skywalk channel closure: panic in sk_free_rings()
 */

static int
skt_utun27302538a_main(int argc, char *argv[])
{
	int error;

	skt_utun27302538_common();

	error = pthread_create(&thread, NULL, &thread1, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Make sure pthread gets into kevent */
	usleep(100000);

	close(tunsock);

	os_channel_destroy(channel);

	/* Give thread1 some time to act if it happens to */
	usleep(100000);

	return 0;
}

static int
skt_utun27302538b_main(int argc, char *argv[])
{
	int error;

	skt_utun27302538_common();

	error = pthread_create(&thread, NULL, &thread1, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Make sure pthread gets into kevent */
	usleep(100000);

	close(tunsock);

	/* Give thread1 some time to act if it happens to */
	usleep(100000);

	return 0;
}

static int
skt_utun27302538c_main(int argc, char *argv[])
{
	int error;

	skt_utun27302538_common();

	close(tunsock);

	error = pthread_create(&thread, NULL, &thread1, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Make sure pthread gets into kevent */
	usleep(100000);

	os_channel_destroy(channel);

	/* Give thread1 some time to act if it happens to */
	usleep(100000);

	return 0;
}

static int
skt_utun27302538d_main(int argc, char *argv[])
{
	int error;

	skt_utun27302538_common();

	close(tunsock);

	error = pthread_create(&thread, NULL, &thread1, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Make sure pthread gets into kevent */
	usleep(100000);

	return 0;
}

struct skywalk_test skt_utun27302538a = {
	"utun27302538a", "test cleaning up utun kpipe while channel is in kevent (case a)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utun27302538a_main,
};

struct skywalk_test skt_utun27302538b = {
	"utun27302538b", "test cleaning up utun kpipe while channel is in kevent (case b)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utun27302538b_main,
};

struct skywalk_test skt_utun27302538c = {
	"utun27302538c", "test cleaning up utun kpipe while channel is in kevent (case c)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utun27302538c_main,
};

struct skywalk_test skt_utun27302538d = {
	"utun27302538d", "test cleaning up utun kpipe while channel is in kevent (case d)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utun27302538d_main,
};

/****************************************************************/
/*
 * <rdar://problem/27646755> cleanup if_utun pcb lock and fix race in utun disable channel
 */

static void *
thread2(void *unused)
{
	close(tunsock);
	return 0;
}

static int
skt_utun27646755_common(int iterations)
{
	int i;
	time_t start = time(NULL);
	time_t now, then = start;

	for (i = 0; i < iterations; i++) {
		int error;

		skt_utun27302538_common();

		error = pthread_create(&thread, NULL, &thread2, NULL);
		SKTC_ASSERT_ERR(error == 0);

		os_channel_destroy(channel);

		error = pthread_join(thread, NULL);
		SKTC_ASSERT_ERR(error == 0);

		now = time(NULL);
		if (now > then) {
			T_LOG("time %ld completed iteration %d of %d (%2.2f%% est %ld secs left)\n",
			    now - start, i + 1, iterations, (double)(i + 1) * 100 / iterations,
			    (long)((double)(now - start) * iterations / (i + 1)) - (now - start));
			then = now;
		}
	}

	return 0;
}

static int
skt_utun27646755_main(int argc, char *argv[])
{
	return skt_utun27646755_common(20);
}

static int
skt_utun27646755slow_main(int argc, char *argv[])
{
	return skt_utun27646755_common(1000);
}

struct skywalk_test skt_utun27646755 = {
	"utun27646755", "race cleaning up channel and utun socket (20 iterations)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utun27646755_main,
};

struct skywalk_test skt_utun27646755slow = {
	"utun27646755slow", "race cleaning up channel and utun socket (1000 iterations)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utun27646755slow_main,
};


/****************************************************************/
