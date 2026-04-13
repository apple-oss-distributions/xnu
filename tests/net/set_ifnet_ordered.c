/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <mach/mach.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_OWNER("tpauly")
	);

T_DECL(set_ifnet_ordered,
    "test SIOCGIFORDER and SIOCSIFORDER ioctls",
    T_META_CHECK_LEAKS(false))
{
	uint32_t count = 0;
	int fd;
	struct if_order ifo = {};
	uint32_t *buffer;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(fd, "socket(PF_INET, SOCK_DGRAM, 0)");

	/* First get the number of ordered interface indices */
	if (ioctl(fd, SIOCGIFORDER, &ifo) < 0) {
		if (errno == ENOENT || errno == ENOTTY) {
			T_SKIP("SIOCGIFORDER not available");
		}
		T_ASSERT_POSIX_SUCCESS(ioctl(fd, SIOCGIFORDER, &ifo), "ioctl(SIOCGIFORDER) initial");
	}

	T_LOG("SIOCGIFORDER ifo_count %u", ifo.ifo_count);

	/* Use some safety margin to get the list */
	count = ifo.ifo_count + (ifo.ifo_count >> 2) + 1;

	ifo.ifo_count = count;
	T_LOG("SIOCGIFORDER with count %u", count);

	buffer = calloc(count, sizeof(uint32_t));
	T_ASSERT_NOTNULL(buffer, "calloc()");

	ifo.ifo_ordered_indices = (mach_vm_address_t)buffer;

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, SIOCGIFORDER, &ifo), "ioctl(SIOCGIFORDER)");

	/* Set immediately the same list */
	T_ASSERT_POSIX_SUCCESS(ioctl(fd, SIOCSIFORDER, &ifo), "ioctl(SIOCSIFORDER)");

	/* Display the list of ordered interface indices */
	for (uint32_t i = 0; i < ifo.ifo_count; i++) {
		char ifname[IFNAMSIZ];
		char *p = if_indextoname(buffer[i], ifname);

		T_LOG("%u: if index %u name %s", i, buffer[i], p != NULL ? p : "");
	}

	free(buffer);
	close(fd);

	T_PASS("set_ifnet_ordered completed");
}
