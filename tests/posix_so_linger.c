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

#include <darwintest.h>

#undef _DARWIN_C_SOURCE
#undef _NONSTD_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <string.h>

T_DECL(posix_so_linger, "POSIX SO_LINGER")
{
	T_LOG("POSIX SO_LINGER 0x%x", SO_LINGER);

	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, 0),
	    "socket(AF_INET, SOCK_DGRAM)");

	struct linger set_l = { .l_onoff = 1, .l_linger = 5 };
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER,
	    &get_l, &len),
	    "getsockopt SO_LINGER");

	T_EXPECT_EQ(set_l.l_onoff, get_l.l_onoff,
	    "POSIX SO_LINGER set l_onoff %d == get l_onoff %d",
	    set_l.l_onoff, get_l.l_onoff);
	T_EXPECT_EQ(set_l.l_linger, get_l.l_linger,
	    "POSIX SO_LINGER set l_linger %d == get l_linger %d",
	    set_l.l_linger, get_l.l_linger);
}

T_DECL(posix_so_linger_negative, "POSIX SO_LINGER negative")
{
	T_LOG("POSIX SO_LINGER 0x%x", SO_LINGER);

	int s = -1;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_STREAM, 0),
	    "socket(AF_INET, SOCK_DGRAM)");

	struct linger set_l = { .l_onoff = 0, .l_linger = -1 };
	T_ASSERT_POSIX_SUCCESS(setsockopt(s, SOL_SOCKET, SO_LINGER,
	    &set_l, sizeof(struct linger)),
	    "setsockopt SO_LINGER");

	struct linger get_l = {};
	socklen_t len = sizeof(struct linger);
	T_ASSERT_POSIX_SUCCESS(getsockopt(s, SOL_SOCKET, SO_LINGER,
	    &get_l, &len),
	    "getsockopt SO_LINGER");

	T_EXPECT_EQ(set_l.l_onoff, get_l.l_onoff,
	    "POSIX SO_LINGER set l_onoff %d == get l_onoff %d",
	    set_l.l_onoff, get_l.l_onoff);
	T_EXPECT_EQ(set_l.l_linger, get_l.l_linger,
	    "POSIX SO_LINGER set l_linger %d == get l_linger %d",
	    set_l.l_linger, get_l.l_linger);
}
