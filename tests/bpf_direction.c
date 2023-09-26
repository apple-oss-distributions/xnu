/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#include <sys/ioctl.h>

#include <net/bpf.h>

#include "bpflib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));

#ifdef BIOCGDIRECTION

static const char *
str_bpf_direction(u_int direction)
{
	switch (direction) {
	case BPF_D_NONE:
		return "BPF_D_NONE";
	case BPF_D_IN:
		return "BPF_D_IN";
	case BPF_D_OUT:
		return "BPF_D_OUT";
	case BPF_D_INOUT:
		return "BPF_D_INOUT";
	default:
		break;
	}
	return "<invalid>";
}

static void
test_set_direction(int fd, u_int direction)
{
	T_ASSERT_POSIX_SUCCESS(bpf_set_direction(fd, direction),
	    "bpf_set_direction(%d): %u (%s)", fd, direction, str_bpf_direction(direction));

	u_int get_direction = (u_int)(-2);
	T_ASSERT_POSIX_SUCCESS(bpf_get_direction(fd, &get_direction),
	    "bpf_get_direction(%d): %u (%s)", fd, get_direction, str_bpf_direction(get_direction));
	T_ASSERT_EQ(get_direction, direction, "get_direction %d == direction %d", get_direction, direction);
}

T_DECL(bpf_direction, "test BPF set and grep direction")
{
	int fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(fd, "bpf open fd %d", fd);

	u_int direction = (u_int)(-2); /* an invalid value */
	T_ASSERT_POSIX_SUCCESS(bpf_get_direction(fd, &direction),
	    "bpf_get_direction(%d): %u (%s)", fd, direction, str_bpf_direction(direction));
	T_ASSERT_EQ(direction, BPF_D_INOUT, "initial direction not BPF_D_INOUT");

	test_set_direction(fd, BPF_D_INOUT);
	test_set_direction(fd, BPF_D_IN);
	test_set_direction(fd, BPF_D_OUT);
	test_set_direction(fd, BPF_D_NONE);

	direction = 10;
	T_EXPECT_POSIX_FAILURE(bpf_set_direction(fd, direction), EINVAL,
	    "bpf_set_direction(%d): %u (%s)", fd, direction, str_bpf_direction(direction));
}

#else /* BIOCSETDIRECTION */

T_DECL(bpf_direction, "test BPF set and grep direction")
{
	T_SKIP("BIOCSETDIRECTION is not defined");
}

#endif /* BIOCSETDIRECTION */

T_DECL(bpf_seesent, "test BIOCGSEESENT and BIOCSSEESENT")
{
	int fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(fd, "bpf open fd %d", fd);

	u_int get_see_sent = (u_int) - 1;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCGSEESENT, &get_see_sent), "BIOCGSEESENT");;
	T_LOG("get_see_sent %u", get_see_sent);

	u_int set_see_sent = get_see_sent == 0 ? 1 : 0;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCSSEESENT, &set_see_sent), "BIOCSSEESENT");;
	T_LOG("set_see_sent %u", set_see_sent);

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCGSEESENT, &get_see_sent), "BIOCGSEESENT");;
	T_LOG("get_see_sent %u", set_see_sent);

	T_ASSERT_EQ(get_see_sent, set_see_sent, "get_see_sent == set_see_sent");

	set_see_sent = get_see_sent == 0 ? 1 : 0;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCSSEESENT, &set_see_sent), "BIOCSSEESENT");;
	T_LOG("set_see_sent %u", set_see_sent);

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCGSEESENT, &get_see_sent), "BIOCGSEESENT");;
	T_LOG("get_see_sent %u", get_see_sent);

	T_ASSERT_EQ(get_see_sent, set_see_sent, "get_see_sent == set_see_sent");
}
