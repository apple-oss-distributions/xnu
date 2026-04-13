/*
 * Copyright (c) 2019, 2025 Apple Inc. All rights reserved.
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
 * Test case for rdar://54634374
 * XNU: AF_SYSTEM: Multiple race conditions leading to use-after-free memory
 * corruption and/or NULL pointer derefs
 *
 * Chris Jarrett-Davies <chrisjd@apple.com>
 * SEAR Red Team / 2019-Aug-22
 */

#include <darwintest.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true)
	);

#define IPSEC_CONTROL_NAME "com.apple.net.ipsec_control"

static struct sockaddr_ctl sa = {
	.sc_family = AF_SYSTEM,
	.sc_len = sizeof(sa),
	.sc_id = 0,
	.sc_unit = 0
};

static volatile bool keep_running = true;

static void *
racer(void *data)
{
	int s = *(int *)data;

	while (keep_running) {
		bind(s, (const struct sockaddr *)&sa, sizeof(sa));
	}
	return NULL;
}

T_DECL(test_ctl_bind_race,
    "test AF_SYSTEM control socket bind race conditions",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120),
    T_META_ENABLED(TARGET_OS_OSX || TARGET_OS_IOS || TARGET_OS_XR))
{
	int s;
	int zero = 0;
	int one = 1;
	pthread_t t;
	struct ctl_info ctl_info;

	s = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)");

	/* Get ipsec control ID */
	memset(&ctl_info, 0, sizeof(ctl_info));
	strncpy(ctl_info.ctl_name, IPSEC_CONTROL_NAME, sizeof(ctl_info.ctl_name));
	if (ioctl(s, CTLIOCGINFO, &ctl_info)) {
		T_SKIP("could not get id for kernel control %s", IPSEC_CONTROL_NAME);
	}
	sa.sc_id = ctl_info.ctl_id;
	T_LOG("Using control ID %u", sa.sc_id);

	T_ASSERT_POSIX_ZERO(pthread_create(&t, NULL, racer, &s), "pthread_create");

	/* Initial bind to ipsec control */
	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sa, sizeof(sa)),
	    "bind to ipsec control");

	/* Set options so connect fails */
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SYSPROTO_CONTROL, 8 /*IPSEC_OPT_ENABLE_CHANNEL*/,
	    &one, sizeof(one)), "setsockopt IPSEC_OPT_ENABLE_CHANNEL");
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SYSPROTO_CONTROL, 12 /*IPSEC_OPT_ENABLE_NETIF*/,
	    &zero, sizeof(zero)), "setsockopt IPSEC_OPT_ENABLE_NETIF");

	T_LOG("Starting race (100000 iterations)...");
	for (int i = 0; i < 100000; i++) {
		/* Force ctl_connect failure, thus setting kcb->kctl = NULL */
		connect(s, (const struct sockaddr *)&sa, sizeof(sa));
	}

	/* Stop the racer thread */
	keep_running = false;
	T_ASSERT_POSIX_ZERO(pthread_join(t, NULL), "pthread_join");

	close(s);
	force_zone_gc();

	T_PASS("test_ctl_bind_race completed without crash");
}
