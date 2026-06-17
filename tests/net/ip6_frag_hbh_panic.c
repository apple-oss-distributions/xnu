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
 * ip6_frag_hbh_panic.c
 *
 * Sending an IPv6 packet whose unfragmentable extension headers (e.g. a
 * large Hop-by-Hop Options header) exceed the path MTU triggers an unsigned
 * integer underflow in ip6_do_fragmentation().  The underflow causes the
 * fragment loop to be skipped, leaving a NULL pointer that is subsequently
 * dereferenced, panicking the kernel.
 *
 * The fix adds a guard in ip6_do_fragmentation() that returns EMSGSIZE when
 * the unfragmentable part plus the fragment header cannot fit within the MTU.
 * This test verifies that sendto() returns EMSGSIZE (or another non-fatal
 * error) rather than crashing the kernel.
 */

#ifndef __APPLE_USE_RFC_3542
#define __APPLE_USE_RFC_3542 1
#endif

#include <darwintest.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ipv6"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_CHECK_LEAKS(false));

/*
 * IPv6 extension headers are aligned to 8-octet units.
 */
#define IPV6_EXT_UNIT   8

/*
 * 2048 bytes is the maximum hop-by-hop options header size (uint8_t length
 * field: (255 + 1) * 8 = 2048).  This exceeds IPV6_MMTU (1280), which is
 * the MTU used for multicast destinations.
 */
#define HBH_LEN 2048

static int test_sock = -1;
static uint8_t *hbh_buf = NULL;

static void
cleanup(void)
{
	if (test_sock >= 0) {
		close(test_sock);
		test_sock = -1;
	}
	free(hbh_buf);
	hbh_buf = NULL;
}

/*
 * Find a suitable non-loopback, IPv6-capable, multicast-enabled interface.
 * Returns the interface index, or 0 on failure.
 */
static unsigned int
find_v6_mcast_ifindex(void)
{
	struct ifaddrs *ifap = NULL;
	unsigned int ifindex = 0;

	if (getifaddrs(&ifap) != 0) {
		return 0;
	}

	for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		if ((ifa->ifa_flags & IFF_UP) == 0) {
			continue;
		}
		if (ifa->ifa_flags & IFF_LOOPBACK) {
			continue;
		}
		if ((ifa->ifa_flags & IFF_MULTICAST) == 0) {
			continue;
		}

		ifindex = if_nametoindex(ifa->ifa_name);
		if (ifindex != 0) {
			T_LOG("Using interface %s (index %u)", ifa->ifa_name,
			    ifindex);
			break;
		}
	}

	freeifaddrs(ifap);
	return ifindex;
}

/*
 * Build a hop-by-hop options header of HBH_LEN bytes, filled with PadN
 * options (implicitly, via calloc zeroing the buffer — the option type 0
 * is Pad1 and the zeroed body forms valid PadN padding).
 */
static uint8_t *
make_hbh_header(size_t len)
{
	uint8_t *buf;
	struct ip6_hbh *hbh;

	T_QUIET; T_ASSERT_EQ(len % IPV6_EXT_UNIT, (size_t)0,
	    "HBH length must be a multiple of 8");
	T_QUIET; T_ASSERT_GE(len, sizeof(*hbh),
	    "HBH length must be at least sizeof(ip6_hbh)");

	buf = calloc(1, len);
	T_ASSERT_NOTNULL(buf, "calloc(%zu)", len);

	hbh = (struct ip6_hbh *)(void *)buf;
	hbh->ip6h_nxt = 0;
	hbh->ip6h_len = (uint8_t)((len / IPV6_EXT_UNIT) - 1);

	return buf;
}

T_DECL(ip6_frag_hbh_panic,
    "IPv6 fragmentation must not panic when HBH options exceed MTU")
{
	unsigned int ifindex;
	struct sockaddr_in6 dst;
	ssize_t sent;

	T_ATEND(cleanup);

	/*
	 * Find a suitable interface.  Skip if none available (e.g. no
	 * network configured).
	 */
	ifindex = find_v6_mcast_ifindex();
	if (ifindex == 0) {
		T_SKIP("No suitable IPv6 multicast interface found");
	}

	/*
	 * Create a raw IPv6 socket with IPPROTO_NONE (no upper-layer
	 * protocol).  This means the kernel will send only the IPv6
	 * header plus any extension headers — no L4 payload.
	 */
	test_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_NONE);
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(test_sock,
	    "socket(AF_INET6, SOCK_RAW, IPPROTO_NONE)");

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(test_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		&ifindex, sizeof(ifindex)),
		"setsockopt(IPV6_MULTICAST_IF, ifindex=%u)", ifindex);

	/*
	 * Attach a 2048-byte hop-by-hop options header.  This makes the
	 * unfragmentable part 2048 + sizeof(ip6_hdr) (40) = 2088 bytes,
	 * which far exceeds the multicast MTU of 1280.
	 */
	hbh_buf = make_hbh_header(HBH_LEN);

	T_ASSERT_POSIX_SUCCESS(
		setsockopt(test_sock, IPPROTO_IPV6, IPV6_HOPOPTS,
		hbh_buf, (socklen_t)HBH_LEN),
		"setsockopt(IPV6_HOPOPTS, %d bytes)", HBH_LEN);

	/*
	 * Send a zero-byte payload to the all-nodes link-local multicast
	 * address.  The multicast destination forces mtu = IPV6_MMTU
	 * (1280).  With unfragpartlen (2088) > mtu (1280), the old code
	 * would underflow in ip6_do_fragmentation() and panic.
	 *
	 * After the fix, the kernel should return EMSGSIZE.
	 */
	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_len = sizeof(dst);
	dst.sin6_scope_id = ifindex;
	T_ASSERT_EQ(inet_pton(AF_INET6, "ff02::1", &dst.sin6_addr), 1,
	    "inet_pton(ff02::1)");

	T_LOG("Sending zero-byte payload with %d-byte HBH header to "
	    "ff02::1 (mtu=1280, unfragpartlen=%zu)",
	    HBH_LEN, HBH_LEN + sizeof(struct ip6_hdr));

	sent = sendto(test_sock, &(char){0}, 0, 0,
	    (struct sockaddr *)&dst, sizeof(dst));

	if (sent >= 0) {
		/*
		 * If the send succeeded (e.g. hardware fragmentation
		 * offload or the packet was small enough after all),
		 * that's also acceptable — the kernel didn't panic.
		 */
		T_PASS("sendto() succeeded (no panic)");
	} else {
		/*
		 * The expected result after the fix is EMSGSIZE.  Other
		 * non-fatal errors (ENETUNREACH, EHOSTUNREACH,
		 * EADDRNOTAVAIL, ENOBUFS) are also acceptable — the
		 * important thing is that the kernel did not panic.
		 */
		T_LOG("sendto() failed with errno %d (%s)", errno,
		    strerror(errno));

		T_ASSERT_TRUE(
			errno == EMSGSIZE ||
			errno == ENETUNREACH ||
			errno == EHOSTUNREACH ||
			errno == EADDRNOTAVAIL ||
			errno == ENOBUFS,
			"sendto() returned acceptable error (got %s, "
			"expected EMSGSIZE or network-related error)",
			strerror(errno));

		if (errno == EMSGSIZE) {
			T_PASS("sendto() correctly returned EMSGSIZE — "
			    "unfragmentable headers exceed MTU");
		} else {
			T_PASS("sendto() returned %s (no panic)",
			    strerror(errno));
		}
	}
}
