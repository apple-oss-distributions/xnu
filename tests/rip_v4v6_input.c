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

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));


static void
udp_port_scan(void)
{
	int v4_udp_fd;

	T_ASSERT_POSIX_SUCCESS(v4_udp_fd = socket(AF_INET, SOCK_DGRAM, 0),
	    "fd %d = socket(AF_INET, SOCK_DGRAM)", v4_udp_fd);

	char *buffer = "hello";
	size_t len = strlen(buffer) + 1;

	for (in_port_t port = 1; port > 0 && port <= IPPORT_HILASTAUTO; port++) {
		struct sockaddr_in sin = {};
		sin.sin_len = sizeof(struct sockaddr_in);
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		ssize_t sent;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sent = sendto(v4_udp_fd, buffer, len, 0, (struct sockaddr *)&sin, sin.sin_len),
		    "sendto() to port %u", port);
	}

	close(v4_udp_fd);

	T_LOG("udp_port_scan done");
}

static int
open_raw_ipv4_socket(void)
{
	int fd;

	T_ASSERT_POSIX_SUCCESS(fd = socket(AF_INET, SOCK_RAW, 0),
	    "fd %d = socket(AF_INET, SOCK_RAW)", fd);

	return fd;
}

static int
open_raw_ipv6_socket(void)
{
	int fd;

	T_ASSERT_POSIX_SUCCESS(fd = socket(AF_INET6, SOCK_RAW, 0),
	    "fd %d = socket(AF_INET6, SOCK_RAW)", fd);

	int off = 0;
	T_ASSERT_POSIX_SUCCESS(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(int)),
	    "setsockopt(%d, IPPROTO_IPV6, IPV6_V6ONLY)", fd);

	return fd;
}

static void
close_raw_socket(int fd)
{
	int optval;
	socklen_t optlen = sizeof(optval);

	T_ASSERT_POSIX_SUCCESS(getsockopt(fd, SOL_SOCKET, SO_NUMRCVPKT, &optval, &optlen),
	    "getsockopt(%d, SOL_SOCKET, SO_NUMRCVPKT)", fd);

	T_LOG("fd %d SO_NUMRCVPKT %d", fd, optval);

	(void)close(fd);
}

T_DECL(rip_no_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	udp_port_scan();

	T_PASS("%s", __func__);
}

T_DECL(rip_v4_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v4_raw_fd1 = open_raw_ipv4_socket();

	udp_port_scan();

	close_raw_socket(v4_raw_fd1);

	T_PASS("%s", __func__);
}

T_DECL(rip_v6_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v6_raw_fd1 = open_raw_ipv6_socket();

	udp_port_scan();

	close_raw_socket(v6_raw_fd1);

	T_PASS("%s", __func__);
}

T_DECL(rip_v4v4_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v4_raw_fd1 = open_raw_ipv4_socket();
	int v4_raw_fd2 = open_raw_ipv4_socket();

	udp_port_scan();

	close_raw_socket(v4_raw_fd1);
	close_raw_socket(v4_raw_fd2);

	T_PASS("%s", __func__);
}

T_DECL(rip_v6v6_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v6_raw_fd1 = open_raw_ipv6_socket();
	int v6_raw_fd2 = open_raw_ipv6_socket();

	udp_port_scan();

	close_raw_socket(v6_raw_fd1);
	close_raw_socket(v6_raw_fd2);

	T_PASS("%s", __func__);
}

T_DECL(rip_v4v6_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v4_raw_fd1 = open_raw_ipv4_socket();
	int v6_raw_fd1 = open_raw_ipv6_socket();

	udp_port_scan();

	close_raw_socket(v4_raw_fd1);
	close_raw_socket(v6_raw_fd1);

	T_PASS("%s", __func__);
}

T_DECL(rip_v4v4v6_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v4_raw_fd1 = open_raw_ipv4_socket();
	int v4_raw_fd2 = open_raw_ipv4_socket();
	int v6_raw_fd = open_raw_ipv6_socket();

	udp_port_scan();

	close_raw_socket(v4_raw_fd1);
	close_raw_socket(v4_raw_fd2);
	close_raw_socket(v6_raw_fd);

	T_PASS("%s", __func__);
}

T_DECL(rip_v4v6v6_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v4_raw_fd1 = open_raw_ipv4_socket();
	int v6_raw_fd1 = open_raw_ipv6_socket();
	int v6_raw_fd2 = open_raw_ipv6_socket();

	udp_port_scan();

	close_raw_socket(v4_raw_fd1);
	close_raw_socket(v6_raw_fd1);
	close_raw_socket(v6_raw_fd2);

	T_PASS("%s", __func__);
}

T_DECL(rip_v4v4v6v6_input, "test reception of IPv4 packet on raw IPv6 socket ")
{
	int v4_raw_fd1 = open_raw_ipv4_socket();
	int v4_raw_fd2 = open_raw_ipv4_socket();
	int v6_raw_fd1 = open_raw_ipv6_socket();
	int v6_raw_fd2 = open_raw_ipv6_socket();

	udp_port_scan();

	close_raw_socket(v4_raw_fd1);
	close_raw_socket(v4_raw_fd2);
	close_raw_socket(v6_raw_fd1);
	close_raw_socket(v6_raw_fd2);

	T_PASS("%s", __func__);
}
