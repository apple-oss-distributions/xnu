/*
 * Copyright (c) 2018, 2025 Apple Inc. All rights reserved.
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
 * Test verifies the system can open all kinds of sockets when
 * the sysctl variable kern.ipc.maxsockbuf is set to a low value
 * (rdar://45251700)
 */

#include <darwintest.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ndrv.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

struct socket_args {
	int domain;
	int type;
	int protocol;
};

static struct socket_args socket_args_list[] = {
	{ .domain = AF_UNIX, .type = SOCK_STREAM, .protocol = 0},
	{ .domain = AF_UNIX, .type = SOCK_DGRAM, .protocol = 0},

	{ .domain = AF_INET, .type = SOCK_STREAM, .protocol = 0},
	{ .domain = AF_INET, .type = SOCK_DGRAM, .protocol = 0},
	{ .domain = AF_INET, .type = SOCK_RAW, .protocol = 0},

	{ .domain = AF_INET6, .type = SOCK_STREAM, .protocol = 0},
	{ .domain = AF_INET6, .type = SOCK_DGRAM, .protocol = 0},
	{ .domain = AF_INET6, .type = SOCK_RAW, .protocol = 0},

	{ .domain = AF_SYSTEM, .type = SOCK_STREAM, .protocol = SYSPROTO_CONTROL},
	{ .domain = AF_SYSTEM, .type = SOCK_DGRAM, .protocol = SYSPROTO_CONTROL},

	{ .domain = AF_SYSTEM, .type = SOCK_RAW, .protocol = SYSPROTO_EVENT},

	{ .domain = PF_NDRV, .type = SOCK_RAW, .protocol = NDRVPROTO_NDRV},

	{ .domain = PF_ROUTE, .type = SOCK_RAW, .protocol = NDRVPROTO_NDRV},

	{ .domain = PF_MULTIPATH, .type = SOCK_STREAM, .protocol = IPPROTO_TCP},

	{ .domain = PF_KEY, .type = SOCK_RAW, .protocol = PF_KEY_V2},

	{ .domain = -1, .type = -1, .protocol = -1},
};

static int saved_maxsockbuf = -1;

static void
restore_maxsockbuf(void)
{
	if (saved_maxsockbuf != -1) {
		int ret = sysctlbyname("kern.ipc.maxsockbuf", NULL, NULL,
		    &saved_maxsockbuf, sizeof(saved_maxsockbuf));
		if (ret != 0) {
			T_LOG("Failed to restore kern.ipc.maxsockbuf to %d", saved_maxsockbuf);
		}
	}
}

T_DECL(test_maxsockbuf,
    "test socket creation with low kern.ipc.maxsockbuf value (rdar://45251700)",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false))
{
	size_t oldlen = sizeof(saved_maxsockbuf);

	/* Get original value */
	T_ASSERT_POSIX_SUCCESS(
		sysctlbyname("kern.ipc.maxsockbuf", &saved_maxsockbuf, &oldlen, NULL, 0),
		"get original kern.ipc.maxsockbuf");
	T_LOG("Original kern.ipc.maxsockbuf: %d", saved_maxsockbuf);

	/* Register cleanup */
	T_ATEND(restore_maxsockbuf);

	/* Set to low value */
	int newval = 51200;
	T_ASSERT_POSIX_SUCCESS(
		sysctlbyname("kern.ipc.maxsockbuf", NULL, NULL, &newval, sizeof(newval)),
		"set kern.ipc.maxsockbuf to %d", newval);
	T_LOG("Set kern.ipc.maxsockbuf to: %d", newval);

	/* Try creating all socket types */
	for (struct socket_args *sa = socket_args_list; sa->domain != -1; sa++) {
		int fd = socket(sa->domain, sa->type, sa->protocol);
		T_EXPECT_POSIX_SUCCESS(fd, "socket(%d, %d, %d)",
		    sa->domain, sa->type, sa->protocol);
		if (fd != -1) {
			close(fd);
		}
	}

	T_PASS("All socket types created successfully with low maxsockbuf");
}
