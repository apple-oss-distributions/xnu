/*
 * Copyright (c) 2022, 2025 Apple Inc. All rights reserved.
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
 * Test dummynet pipe configuration and cleanup
 */

#include <darwintest.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_dummynet.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

T_DECL(test_dummynet_configure,
    "test dummynet pipe configuration and flush",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false))
{
	int fd;
	unsigned short loop_max = 100;

	fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_RAW, IPPROTO_RAW)");

	T_LOG("Configuring %d dummynet pipes", loop_max);

	/* Configure dummynet pipes */
	for (unsigned short i = 0; i < loop_max; i++) {
		struct dn_pipe pipeData = {};

		pipeData.fs.fs_nr = i + 1;
		pipeData.fs.flags_fs = DN_IS_RED;
		pipeData.fs.parent_nr = i;
		pipeData.fs.max_th = 0x4141;

		int ret = setsockopt(fd, IPPROTO_IP, IP_DUMMYNET_CONFIGURE,
		    &pipeData, sizeof(struct dn_pipe));
		if (ret != 0) {
			T_LOG("setsockopt(IP_DUMMYNET_CONFIGURE) pipe %d: %s", i, strerror(errno));
		}
	}

	/* Flush all pipes */
	T_LOG("Flushing dummynet pipes");
	T_ASSERT_POSIX_SUCCESS(
		setsockopt(fd, IPPROTO_IP, IP_DUMMYNET_FLUSH, NULL, 0),
		"setsockopt(IP_DUMMYNET_FLUSH)");

	close(fd);

	T_PASS("Dummynet pipe configuration and flush completed");
}

T_DECL(test_dummynet_no_flush,
    "test dummynet pipe configuration without flush",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false))
{
	int fd;
	unsigned short loop_max = 100;

	fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_RAW, IPPROTO_RAW)");

	T_LOG("Configuring %d dummynet pipes (no flush)", loop_max);

	/* Configure dummynet pipes */
	for (unsigned short i = 0; i < loop_max; i++) {
		struct dn_pipe pipeData = {};

		pipeData.fs.fs_nr = i + 1;
		pipeData.fs.flags_fs = DN_IS_RED;
		pipeData.fs.parent_nr = i;
		pipeData.fs.max_th = 0x4141;

		int ret = setsockopt(fd, IPPROTO_IP, IP_DUMMYNET_CONFIGURE,
		    &pipeData, sizeof(struct dn_pipe));
		if (ret != 0) {
			T_LOG("setsockopt(IP_DUMMYNET_CONFIGURE) pipe %d: %s", i, strerror(errno));
		}
	}

	/* Do NOT flush - test cleanup behavior */
	T_LOG("Not flushing pipes - testing cleanup behavior");

	close(fd);

	T_PASS("Dummynet pipe configuration without flush completed");
}
