/*
 * Copyright (c) 2020, 2025 Apple Inc. All rights reserved.
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
 * Test for SIOCADDMULTI/SIOCDELMULTI kernel stack OOB read (rdar://58295021)
 *
 * SIOCADDMULTI and SIOCDELMULTI ioctls can be used to trigger an
 * attacker-controlled kernel stack out-of-bounds read when sdl_len
 * is set to an excessively large value.
 */

#include <darwintest.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("rpaulo")
	);

T_DECL(test_add_del_multi,
    "test SIOCADDMULTI/SIOCDELMULTI with excessive sdl_len (rdar://58295021)",
    T_META_CHECK_LEAKS(false))
{
	int s;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr = {
			.s_addr = inet_addr("0.0.0.0")
		}
	};
	struct ifreq ifr = {};
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr.ifr_addr;

	T_LOG("sizeof(struct ifreq): %zu bytes", sizeof(struct ifreq));

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)");

	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin, sizeof(sin)), "bind");

	strlcpy(ifr.ifr_name, "en0", sizeof(ifr.ifr_name));
	sdl->sdl_family = AF_LINK;
	sdl->sdl_len = 255;
	sdl->sdl_alen = 255 - (uintptr_t)&((struct sockaddr_dl *)0)->sdl_data;

	T_LOG("Triggering ioctl with excessive sdl_len...");

	/* This should not cause a kernel panic or OOB read */
	int ret = ioctl(s, SIOCADDMULTI, &ifr);

	if (ret == -1) {
		T_LOG("ioctl(SIOCADDMULTI) failed as expected: %s", strerror(errno));
	} else {
		T_LOG("ioctl(SIOCADDMULTI) returned %d", ret);
	}

	close(s);

	T_PASS("test_add_del_multi completed without crash");
}
