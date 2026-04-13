/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

/*
 * Test case for rdar://54341785
 * Tests NDRV socket attachment race conditions
 */

#include <darwintest.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <net/ndrv.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

static volatile bool keep_running = true;

static void *
racer(__unused void *ignored)
{
	while (keep_running) {
		/* This should always fail - we're testing for race conditions/crashes */
		int ret = socketpair(PF_NDRV, SOCK_RAW, NDRVPROTO_NDRV, (void *)0xdeadbeef);
		T_QUIET;
		T_EXPECT_EQ(ret, -1, "socketpair(PF_NDRV) should fail");

		/* Brief yield to allow other threads to run */
		usleep(1);
	}
	return NULL;
}

T_DECL(test_ndrv_attach,
    "test NDRV socket attachment race conditions",
    T_META_CHECK_LEAKS(false))
{
	pthread_t threads[32];
	int i;

	/* Create 32 racing threads */
	for (i = 0; i < 32; i++) {
		T_QUIET;
		T_ASSERT_POSIX_ZERO(pthread_create(&threads[i], NULL, racer, NULL),
		    "pthread_create thread %d", i);
	}

	T_LOG("Racing threads created, sleeping for 30 seconds...");

	/* Let the threads race for 30 seconds */
	for (int sec = 1; sec <= 30; sec++) {
		sleep(1);
		if (sec % 5 == 0) {
			T_LOG("second %d", sec);
		}
	}

	/* Stop the threads */
	keep_running = false;
	T_LOG("Stopping threads...");

	/* Wait for all threads to finish */
	for (i = 0; i < 32; i++) {
		T_QUIET;
		T_ASSERT_POSIX_ZERO(pthread_join(threads[i], NULL),
		    "pthread_join thread %d", i);
	}

	T_PASS("test_ndrv_attach completed without crash");
}
