/*
 * Copyright (c) 2019, 2025 Apple Inc. All rights reserved.
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
 * Test Case: XNU: sysctl: net.inet6.icmp6.nd6_lookup_ipv6 kernel stack buffer overflow
 * rdar://50202771 (DEBUG/DEVELOPMENT only)
 *
 * Chris Jarrett-Davies <chrisjd@apple.com>
 * SEAR Red Team / 2019-Apr-25
 */

#include <darwintest.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("randall_meyer")
	);

struct nd6_lookup_ipv6_args {
	char ifname[IFNAMSIZ];
	struct sockaddr_in6 ip6_dest;
	uint32_t ll_dest_len;
	union {
		char buffer[256];
		struct sockaddr_dl _sdl;
	} ll_dest_;
};

T_DECL(nd6lookup,
    "test nd6_lookup_ipv6 sysctl with unbounded length",
    T_META_CHECK_LEAKS(false))
{
	struct nd6_lookup_ipv6_args in;
	struct nd6_lookup_ipv6_args out = {};
	size_t outlen = sizeof(out);
	int ret;

	/* Setup for stack overflow test */
	bzero(&in, sizeof(in));
	strcpy(in.ifname, "lo0");                /* must support multicast */
	in.ip6_dest.sin6_family = AF_INET6;      /* ipv6 lookup */
	in.ip6_dest.sin6_addr.s6_addr[0] = 0xff; /* multicast addr lookup */
	in.ll_dest_len = UINT_MAX;               /* unbounded length - should be validated */

	ret = sysctlbyname("net.inet6.icmp6.nd6_lookup_ipv6", &out, &outlen, &in, sizeof(in));

	/* The sysctl should either succeed (if fixed) or fail gracefully (not crash) */
	if (ret == -1) {
		T_LOG("sysctlbyname returned error (errno=%d), which is acceptable", errno);
	} else {
		T_LOG("sysctlbyname succeeded");
	}

	T_PASS("nd6lookup completed without crash");
}
