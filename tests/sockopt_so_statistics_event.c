/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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
 * sockopt_so_statistics_event.c
 *
 * Regression test for rdar://172103496: SO_STATISTICS_EVENT was missing a
 * domain check, allowing it to be called on PF_LOCAL sockets. This caused
 * sotoinpcb() to cast a struct unpcb* to struct inpcb*, resulting in a
 * kernel type confusion and out-of-bounds heap read.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#ifndef SO_STATISTICS_EVENT
#define SO_STATISTICS_EVENT                     0x1123
#endif
#ifndef SO_STATISTICS_EVENT_ENTER_CELLFALLBACK
#define SO_STATISTICS_EVENT_ENTER_CELLFALLBACK  (1 << 0)
#endif

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net.sockopt"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * SO_STATISTICS_EVENT on a PF_LOCAL socket must return EINVAL.
 */
T_DECL(so_statistics_event_pf_local_einval,
    "SO_STATISTICS_EVENT on PF_LOCAL socket must return EINVAL (rdar://172103496)")
{
	int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_LOCAL, SOCK_STREAM, 0)");

	int64_t event = SO_STATISTICS_EVENT_ENTER_CELLFALLBACK;
	T_ASSERT_POSIX_FAILURE(setsockopt(fd, SOL_SOCKET, SO_STATISTICS_EVENT, &event, sizeof(event)),
	    EINVAL, "setsockopt(SO_STATISTICS_EVENT) on PF_LOCAL must return EINVAL");

	close(fd);
}

/*
 * SO_STATISTICS_EVENT on a PF_INET socket must succeed.
 */
T_DECL(so_statistics_event_pf_inet_succeeds,
    "SO_STATISTICS_EVENT on PF_INET socket must succeed")
{
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_STREAM, 0)");

	int64_t event = SO_STATISTICS_EVENT_ENTER_CELLFALLBACK;
	int rc = setsockopt(fd, SOL_SOCKET, SO_STATISTICS_EVENT, &event, sizeof(event));
	T_ASSERT_POSIX_SUCCESS(rc, "setsockopt(SO_STATISTICS_EVENT) on PF_INET must succeed");

	close(fd);
}

/*
 * SO_STATISTICS_EVENT on a PF_INET6 socket must succeed.
 */
T_DECL(so_statistics_event_pf_inet6_succeeds,
    "SO_STATISTICS_EVENT on PF_INET6 socket must succeed")
{
	int fd = socket(PF_INET6, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET6, SOCK_STREAM, 0)");

	int64_t event = SO_STATISTICS_EVENT_ENTER_CELLFALLBACK;
	int rc = setsockopt(fd, SOL_SOCKET, SO_STATISTICS_EVENT, &event, sizeof(event));
	T_ASSERT_POSIX_SUCCESS(rc, "setsockopt(SO_STATISTICS_EVENT) on PF_INET6 must succeed");

	close(fd);
}

/*
 * SO_STATISTICS_EVENT with an invalid event value must return EINVAL
 * regardless of socket domain. This exercises so_statistics_event_to_nstat_event().
 */
T_DECL(so_statistics_event_invalid_value,
    "SO_STATISTICS_EVENT with an unrecognised event value must return EINVAL")
{
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_STREAM, 0)");

	int64_t bad_event = 0xdeadbeef;
	T_ASSERT_POSIX_FAILURE(setsockopt(fd, SOL_SOCKET, SO_STATISTICS_EVENT, &bad_event, sizeof(bad_event)),
	    EINVAL, "setsockopt(SO_STATISTICS_EVENT) with bad event must return EINVAL");

	close(fd);
}
