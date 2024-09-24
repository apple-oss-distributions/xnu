/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <net/if_utun.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>

#include <darwintest.h>
#include <pthread.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));

#define SECONDS_TO_SLEEP 3

static int fd = -1;
static bool finished = false;

static void *
call_setsockopt(void *arg)
{
#pragma unused(arg)

	while (finished == false) {
		(void)setsockopt(fd, SYSPROTO_CONTROL, SO_DEFUNCTIT, 0, 0);
	}
	return NULL;
}

T_DECL(kctl_disconnect_race, "Race mutliple threads triggering ctl_disconnect")
{
	struct ctl_info ctl_info = { 0 };

	struct sockaddr_ctl sockaddr_ctl = {
		.sc_len = sizeof(struct sockaddr_ctl),
		.sc_family = AF_SYSTEM,
		.ss_sysaddr = AF_SYS_CONTROL,
		.sc_unit = 0
	};

	pthread_t runner1, runner2;

	T_ASSERT_POSIX_SUCCESS(fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	strlcpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(fd, CTLIOCGINFO, &ctl_info), NULL);

	sockaddr_ctl.sc_id = ctl_info.ctl_id;

	T_ASSERT_POSIX_SUCCESS(connect(fd, (const struct sockaddr *)&sockaddr_ctl, sizeof(struct sockaddr_ctl)), NULL);

	if (pthread_create(&runner1, NULL, call_setsockopt, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	if (pthread_create(&runner2, NULL, call_setsockopt, NULL)) {
		T_ASSERT_FAIL("pthread_create failed");
	}

	sleep(SECONDS_TO_SLEEP);

	finished = true;

	pthread_join(runner1, 0);
	pthread_join(runner2, 0);
}
