/*
 * Copyright (c) 2017, 2025 Apple Inc. All rights reserved.
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
 * Test for rdar://34054660
 * Tests ICMP unreachable message handling for both IPv4 and IPv6
 */

#define _IP_VHL 1

#include <darwintest.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_OWNER("vlubet")
	);

#define MAXBUFLEN 1500
#define LOOP_COUNT 5
#define WAIT_MS 50

static struct in6_addr in6addr_local;
static struct in6_addr in6addr_remote;
static struct in_addr in4addr_local;
static struct in_addr in4addr_remote;
static int cmp_id = 0;
static int _icmp_seq = 0;

static int
set_non_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(flags, "fcntl(F_GETFL)");

	flags |= O_NONBLOCK;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_SETFL, flags), "fcntl(F_SETFL)");

	return 0;
}

static unsigned short
ChecksumBuffer(unsigned short *buf, size_t len)
{
	register unsigned long sum = 0;

	while (len > 1) {
		sum += *buf++;
		len -= 2;
		if (sum & 0x80000000) {
			sum = (sum >> 16) + (sum & 0xFFFF);
		}
	}
	if (len == 1) {
		sum += (*(unsigned char *)buf) << 8;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}

	return ~sum;
}

static int
send_unreach_v4(int fd)
{
	unsigned char icmp_buffer[MAXBUFLEN];
	memset(icmp_buffer, 0, sizeof(icmp_buffer));

	struct icmp *icmp_outer = (struct icmp *)(icmp_buffer);
	struct ip *ip = (struct ip *)(icmp_buffer + ICMP_MINLEN);
	struct icmp *icmp_inner = (struct icmp *)(ip + 1);

	ip->ip_vhl = 0x45;
	ip->ip_tos = 0;
	ip->ip_len = htons(sizeof(struct ip) + ICMP_MINLEN);
	ip->ip_id = 1;
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_sum = 0;
	ip->ip_src = in4addr_local;
	ip->ip_dst = in4addr_remote;
	ip->ip_sum = ChecksumBuffer((unsigned short *)ip, sizeof(struct ip));

	icmp_inner->icmp_type = ICMP_ECHO;
	icmp_inner->icmp_code = 0;
	icmp_inner->icmp_cksum = 0;
	icmp_inner->icmp_id = cmp_id;
	icmp_inner->icmp_seq = ++_icmp_seq;
	icmp_inner->icmp_cksum = ChecksumBuffer((unsigned short *)icmp_inner, ICMP_MINLEN);

	icmp_outer->icmp_type = ICMP_UNREACH;
	icmp_outer->icmp_code = ICMP_UNREACH_HOST;
	icmp_outer->icmp_cksum = 0;
	icmp_outer->icmp_id = htons(cmp_id);
	icmp_outer->icmp_seq = htons(++_icmp_seq);
	icmp_outer->icmp_cksum = ChecksumBuffer((unsigned short *)icmp_outer,
	    sizeof(struct ip) + 2 * ICMP_MINLEN);

	ssize_t out_len = ICMP_MINLEN + sizeof(struct ip) + ICMP_MINLEN;
	ssize_t len = send(fd, icmp_buffer, out_len, 0);
	if (len != out_len && errno != EINTR && errno != EWOULDBLOCK) {
		T_ASSERT_POSIX_SUCCESS(len, "send IPv4");
	}

	return 0;
}

static int
recv_icmp_v4(int fd)
{
	socklen_t fromlen;
	struct sockaddr_in sin_from;
	unsigned char ip_buffer[MAXBUFLEN];
	ssize_t len;

	fromlen = sizeof(struct sockaddr_in);
	len = recvfrom(fd, ip_buffer, sizeof(ip_buffer), 0, (struct sockaddr *)&sin_from, &fromlen);
	if (len == -1 && errno != EINTR && errno != EWOULDBLOCK) {
		T_ASSERT_POSIX_SUCCESS(len, "recvfrom IPv4");
	}

	return 0;
}

static int
open_icmp_v4(bool is_remote)
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");

	int on = 1;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)),
	    "setsockopt(SO_NOSIGPIPE)");

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr = in4addr_local;

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bind(fd, (struct sockaddr *)&sin, sin.sin_len), "bind");

	sin.sin_addr = is_remote ? in4addr_local : in4addr_remote;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(connect(fd, (struct sockaddr *)&sin, sin.sin_len), "connect");

	set_non_blocking(fd);

	return fd;
}

static void
test_v4(void)
{
	int fd4_sndr, fd4_rcvr;
	int i;

	fd4_sndr = open_icmp_v4(true);
	fd4_rcvr = open_icmp_v4(false);

	for (i = 0; i < LOOP_COUNT; i++) {
		send_unreach_v4(fd4_sndr);
		usleep(WAIT_MS * 1000);
		recv_icmp_v4(fd4_sndr);
		recv_icmp_v4(fd4_rcvr);
	}

	close(fd4_sndr);
	close(fd4_rcvr);
}

static int
send_unreach_v6(int fd)
{
	unsigned char buffer[MAXBUFLEN];
	memset(buffer, 0, sizeof(buffer));

	struct icmp6_hdr *icmp6_outer = (struct icmp6_hdr *)(buffer);
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct icmp6_hdr));
	struct icmp6_hdr *icmp6_inner = (struct icmp6_hdr *)(ip6 + 1);

	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = htons(sizeof(struct icmp6_hdr));
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_src = in6addr_local;
	ip6->ip6_dst = in6addr_remote;

	icmp6_inner->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6_inner->icmp6_code = 0;
	icmp6_inner->icmp6_cksum = 0;
	icmp6_inner->icmp6_id = htons(cmp_id);
	icmp6_inner->icmp6_seq = htons(++_icmp_seq);
	icmp6_inner->icmp6_cksum = ChecksumBuffer((unsigned short *)icmp6_inner,
	    sizeof(struct icmp6_hdr));

	icmp6_outer->icmp6_type = ICMP6_DST_UNREACH;
	icmp6_outer->icmp6_code = ICMP6_DST_UNREACH_ADMIN;
	icmp6_outer->icmp6_cksum = 0;
	icmp6_outer->icmp6_cksum = ChecksumBuffer((unsigned short *)icmp6_outer,
	    sizeof(struct ip6_hdr) + 2 * sizeof(struct icmp6_hdr));

	ssize_t out_len = sizeof(struct ip6_hdr) + 2 * sizeof(struct icmp6_hdr);
	ssize_t len = send(fd, buffer, out_len, 0);
	if (len != out_len && errno != EINTR && errno != EWOULDBLOCK) {
		T_ASSERT_POSIX_SUCCESS(len, "send IPv6");
	}

	return 0;
}

static int
recv_icmp_v6(int fd)
{
	socklen_t fromlen;
	struct sockaddr_in6 sin6;
	unsigned char buffer[MAXBUFLEN];
	ssize_t len;

	fromlen = sizeof(struct sockaddr_in6);
	memset(&sin6, 0, fromlen);
	len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sin6, &fromlen);
	if (len == -1 && errno != EINTR && errno != EWOULDBLOCK) {
		T_ASSERT_POSIX_SUCCESS(len, "recvfrom IPv6");
	}

	return 0;
}

static int
open_icmp_v6(bool is_remote)
{
	int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");

	int on = 1;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)),
	    "setsockopt(SO_NOSIGPIPE)");

	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(struct sockaddr_in6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = is_remote ? in6addr_local : in6addr_remote;
	sin6.sin6_scope_id = if_nametoindex("lo0");

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(connect(fd, (struct sockaddr *)&sin6, sin6.sin6_len), "connect");

	set_non_blocking(fd);

	return fd;
}

static void
test_v6(void)
{
	int fd6_sndr, fd6_rcvr;
	int i;

	fd6_sndr = open_icmp_v6(true);
	fd6_rcvr = open_icmp_v6(false);

	for (i = 0; i < LOOP_COUNT; i++) {
		send_unreach_v6(fd6_sndr);
		usleep(WAIT_MS * 1000);
		recv_icmp_v6(fd6_sndr);
		recv_icmp_v6(fd6_rcvr);
	}

	close(fd6_sndr);
	close(fd6_rcvr);
}

T_DECL(unreach_icmp_34054660_v4,
    "test ICMP unreachable message handling for IPv4",
    T_META_CHECK_LEAKS(false))
{
	cmp_id = getpid();
	_icmp_seq = 0;

	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &in4addr_local), 1, "inet_pton local");
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.2", &in4addr_remote), 1, "inet_pton remote");

	test_v4();
	T_PASS("IPv4 ICMP unreachable test completed");
}

T_DECL(unreach_icmp_34054660_v6,
    "test ICMPv6 unreachable message handling for IPv6",
    T_META_CHECK_LEAKS(false))
{
	cmp_id = getpid();
	_icmp_seq = 0;

	T_ASSERT_EQ(inet_pton(AF_INET6, "fe80::1", &in6addr_local), 1, "inet_pton local");
	T_ASSERT_EQ(inet_pton(AF_INET6, "fe80::2", &in6addr_remote), 1, "inet_pton remote");

	test_v6();
	T_PASS("IPv6 ICMP unreachable test completed");
}
