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

T_DECL(bpf_no_timestamp, "test BIOCGNOTSTAMP and BIOCSNOTSTAMP")
{
	int fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(fd, "bpf open fd %d", fd);

	int get_no_timestamp = -1;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCGNOTSTAMP, &get_no_timestamp), "BIOCGNOTSTAMP");;
	T_LOG("BIOCGNOTSTAMP detault: %u", get_no_timestamp);

	int set_no_timestamp = 1;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCSNOTSTAMP, &set_no_timestamp), "BIOCSNOTSTAMP");;
	T_LOG("set_no_timestamp %u", set_no_timestamp);

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCGNOTSTAMP, &get_no_timestamp), "BIOCGNOTSTAMP");;
	T_LOG("BIOCGNOTSTAMP detault: %u", get_no_timestamp);

	T_ASSERT_EQ(get_no_timestamp, set_no_timestamp, "get_no_timestamp == set_no_timestamp");

	set_no_timestamp = 0;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCSNOTSTAMP, &set_no_timestamp), "BIOCSNOTSTAMP");;
	T_LOG("set_no_timestamp %u", set_no_timestamp);

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, BIOCGNOTSTAMP, &get_no_timestamp), "BIOCGNOTSTAMP");;
	T_LOG("get_no_timestamp %u", get_no_timestamp);

	T_ASSERT_EQ(get_no_timestamp, set_no_timestamp, "get_no_timestamp== set_no_timestamp");
}
