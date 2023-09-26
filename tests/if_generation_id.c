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

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_fake_var.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));

static char ifname1[IF_NAMESIZE];
static int s = -1;

static void
cleanup(void)
{
	if (s != -1) {
		(void)ifnet_destroy(s, ifname1, false);
		T_LOG("ifnet_destroy %s", ifname1);
	}
}

T_DECL(if_creation_generation_id, "network interface creation generation id")
{
	T_ATEND(cleanup);

#ifdef SIOCGIFGENERATIONID
	s = inet_dgram_socket();

	strlcpy(ifname1, FETH_NAME, sizeof(ifname1));
	T_ASSERT_POSIX_SUCCESS(ifnet_create_2(s, ifname1, sizeof(ifname1)), NULL);

	T_LOG("created %s", ifname1);

	struct ifreq ifr = {};

	strlcpy(ifr.ifr_name, ifname1, sizeof(ifr.ifr_name));

	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGIFGENERATIONID, &ifr), NULL);

	uint64_t if_generation_id = ifr.ifr_creation_generation_id;
	T_LOG("interface creation generation id: %llu", if_generation_id);

	(void)ifnet_destroy(s, ifname1, false);
	T_LOG("destroyed %s", ifname1);

	/* wait for the interface to be fully detached */
	sleep(1);

	T_ASSERT_POSIX_SUCCESS(ifnet_create(s, ifname1), NULL);

	T_LOG("re-created %s", ifname1);

	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGIFGENERATIONID, &ifr), NULL);

	T_LOG("interface creation generation id: %llu", ifr.ifr_creation_generation_id);

	T_ASSERT_NE_ULLONG(if_generation_id, ifr.ifr_creation_generation_id,
	    "interface generation id are different");
#else
	T_SKIP("SIOCGIFGENERATIONID does not exist");
#endif
}
