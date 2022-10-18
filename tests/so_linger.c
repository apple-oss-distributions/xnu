/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <darwintest.h>

T_DECL(so_linger_negative, "SO_LINGER negative")
{
	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_LOCAL, SOCK_DGRAM, 0), "socket(AF_LOCAL, SOCK_DGRAM)");

	struct linger set_l = {};
	set_l.l_onoff = 1;
	set_l.l_linger = -1;
	T_LOG("l_linger %d", set_l.l_linger);
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER,
	    &get_l, &len),
	    "getsockopt SO_LINGER");

	T_EXPECT_EQ(set_l.l_linger, get_l.l_linger,
	    "SO_LINGER negative l_linger %d == %d", set_l.l_linger, get_l.l_linger);
}

T_DECL(so_linger_overflow, "SO_LINGER overflow")
{
	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_LOCAL, SOCK_DGRAM, 0), "socket(AF_LOCAL, SOCK_DGRAM)");

	struct linger set_l = {};
	set_l.l_onoff = 1;
	set_l.l_linger = SHRT_MAX + 1;
	T_LOG("l_linger %d", set_l.l_linger);
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER,
	    &get_l, &len),
	    "getsockopt SO_LINGER");

	/*
	 * Test passes based on the knowledge that l_linger is stored
	 * as a short signed integer
	 */
	T_EXPECT_EQ((short)set_l.l_linger, (short)get_l.l_linger,
	    "SO_LINGER overflow l_linger (short) %d == (short) %d",
	    set_l.l_linger, get_l.l_linger);
}

T_DECL(so_linger_500, "SO_LINGER 500")
{
	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_LOCAL, SOCK_DGRAM, 0), "socket(AF_LOCAL, SOCK_DGRAM)");

	struct clockinfo clkinfo;
	size_t oldlen = sizeof(struct clockinfo);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.clockrate", &clkinfo, &oldlen, NULL, 0),
	    "sysctlbyname(kern.clockrate)");

	struct linger set_l = {};
	set_l.l_onoff = 1;
	set_l.l_linger = 500;

	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER,
	    &get_l, &len),
	    "getsockopt SO_LINGER");

	T_EXPECT_EQ(set_l.l_linger, get_l.l_linger,
	    "SO_LINGER 500 l_linger %d == %d", set_l.l_linger, get_l.l_linger);
}

T_DECL(so_linger_sec_negative, "SO_LINGER_SEC negative")
{
	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_LOCAL, SOCK_DGRAM, 0), "socket(AF_LOCAL, SOCK_DGRAM)");

	struct clockinfo clkinfo;
	size_t oldlen = sizeof(struct clockinfo);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.clockrate", &clkinfo, &oldlen, NULL, 0),
	    "sysctlbyname(kern.clockrate)");

	struct linger set_l = {};
	set_l.l_onoff = 1;
	set_l.l_linger = -1;
	T_LOG("l_linger %d * clkinfo.hz %d = %d", set_l.l_linger, clkinfo.hz, (set_l.l_linger * clkinfo.hz));

	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER_SEC,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER_SEC");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER_SEC,
	    &get_l, &len),
	    "getsockopt SO_LINGER_SEC");

	T_EXPECT_EQ(set_l.l_linger, get_l.l_linger,
	    "SO_LINGER_SEC negative l_linger %d == %d", set_l.l_linger, get_l.l_linger);
}

T_DECL(so_linger_sec_5_seconds, "SO_LINGER_SEC 5 seconds")
{
	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_LOCAL, SOCK_DGRAM, 0), "socket(AF_LOCAL, SOCK_DGRAM)");

	struct clockinfo clkinfo;
	size_t oldlen = sizeof(struct clockinfo);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.clockrate", &clkinfo, &oldlen, NULL, 0),
	    "sysctlbyname(kern.clockrate)");

	struct linger set_l = {};
	set_l.l_onoff = 1;
	set_l.l_linger = 5;
	T_LOG("l_linger %d * clkinfo.hz %d = %d", set_l.l_linger, clkinfo.hz, (set_l.l_linger * clkinfo.hz));

	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER_SEC,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER_SEC");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER_SEC,
	    &get_l, &len),
	    "getsockopt SO_LINGER_SEC");

	T_EXPECT_EQ(set_l.l_linger, get_l.l_linger,
	    "SO_LINGER_SEC 5 seconds l_linger %d == %d", set_l.l_linger, get_l.l_linger);
}
