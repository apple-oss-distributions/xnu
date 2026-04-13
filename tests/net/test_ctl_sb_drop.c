/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <net/ntstat.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

T_DECL(test_ctl_sb_drop,
    "test control socket send after shutdown(SHUT_RD)",
    T_META_CHECK_LEAKS(false))
{
	int s;
	struct ctl_info ctl_info = {};
	struct sockaddr_ctl sac = {
		.sc_family = AF_SYSTEM,
		.sc_len = sizeof(sac),
		.sc_id = 0,
		.sc_unit = 0
	};
	const char *str = "this is a test";
	ssize_t n;

	s = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)");

	strncpy(ctl_info.ctl_name, NET_STAT_CONTROL_NAME, sizeof(ctl_info.ctl_name));

	T_ASSERT_POSIX_SUCCESS(ioctl(s, CTLIOCGINFO, &ctl_info), "ioctl(CTLIOCGINFO)");

	sac.sc_id = ctl_info.ctl_id;

	T_ASSERT_POSIX_SUCCESS(connect(s, (struct sockaddr *)&sac, sac.sc_len), "connect");

	T_ASSERT_POSIX_SUCCESS(shutdown(s, SHUT_RD), "shutdown(SHUT_RD)");

	/* Test sending after shutdown */
	n = send(s, str, strlen(str), 0);
	if (n < 0) {
		T_LOG("send() failed: %s", strerror(errno));
	} else {
		T_LOG("send() returned: %zd", n);
	}

	close(s);

	T_PASS("test_ctl_sb_drop completed");
}
