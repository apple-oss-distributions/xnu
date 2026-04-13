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
 * This test is an upgrade of test_ipopts_with_sending as it panicked the
 * device in a different codepath. In udp send path, we release the lock when
 * we do in_pcbconnect or in_pcbsetport in addition to ip_output. We have moved
 * inp->inp_sndinprog_cnt++ before we do the above lookup.
 */

#include <darwintest.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vidhi_goel")
	);

#define IPV6_RTHDR 51
/*
 *  struct ip6_rthdr {
 *       uint8_t ip6r_nxt;
 *       uint8_t ip6r_len;
 *       uint8_t ip6r_type;
 *       uint8_t ip6r_segleft;
 *  };
 */
static int g_opt_fd_v6 = -1;
static int g_opt_fd_v4 = -1;

static void
alloc_v6_pktoptions(int sock)
{
	uint32_t len = 0x100;
	char *buffer;
	struct cmsghdr *hdr;
	int ret;

	buffer = malloc(len);
	T_QUIET;
	T_ASSERT_NOTNULL(buffer, "malloc");

	memset(buffer, 'A', len);
	hdr = (struct cmsghdr *)buffer;
	hdr->cmsg_len = len;
	hdr->cmsg_level = 0x4141;
	hdr->cmsg_type = IPV6_2292PKTINFO;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, hdr, hdr->cmsg_len);
	if (ret < 0) {
		T_LOG("Set v6 socket options failed: %s", strerror(errno));
	}

	free(buffer);
}

static void
alloc_v4_pktoptions(int sock)
{
	int ret;
	uint8_t buf[0x100] = {0};
	struct cmsghdr *hdr = (struct cmsghdr *)buf;

	hdr->cmsg_len = 0x100;
	hdr->cmsg_level = IPPROTO_IP;
	hdr->cmsg_type = IP_PKTINFO;

	ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, hdr, hdr->cmsg_len);
	if (ret < 0) {
		T_LOG("Set v4 socket options failed: %s", strerror(errno));
	}
}

static void
set_sock_pkt_rthdr(int sock)
{
#define RTHDR_SIZE (CMSG_LEN(0) + 0xb8)

	char *buffer;
	struct cmsghdr *hdr;
	struct ip6_rthdr *rthdr;
	int ret;

	buffer = malloc(RTHDR_SIZE);
	T_QUIET;
	T_ASSERT_NOTNULL(buffer, "malloc");

	memset(buffer, 'A', RTHDR_SIZE);

	hdr = (struct cmsghdr *)buffer;
	hdr->cmsg_len = RTHDR_SIZE;
	hdr->cmsg_level = IPPROTO_IPV6;
	hdr->cmsg_type = IPV6_RTHDR;

	rthdr = (struct ip6_rthdr *)CMSG_DATA(hdr);
	rthdr->ip6r_nxt = 0;
	rthdr->ip6r_len = ((RTHDR_SIZE - CMSG_LEN(0)) >> 3) - 1;
	rthdr->ip6r_type = 0;
	rthdr->ip6r_segleft = rthdr->ip6r_len / 2;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, hdr, hdr->cmsg_len);
	if (ret < 0) {
		T_LOG("Set route header failed: %s", strerror(errno));
	}

	free(buffer);
}

static void
clear_v6_pktoptions(int sock)
{
	uint32_t len = CMSG_LEN(0);
	char *buffer;
	struct cmsghdr *hdr;
	int ret;

	buffer = malloc(len);
	T_QUIET;
	T_ASSERT_NOTNULL(buffer, "malloc");

	memset(buffer, 'A', len);
	hdr = (struct cmsghdr *)buffer;
	hdr->cmsg_len = len;
	hdr->cmsg_level = IPPROTO_IPV6;
	hdr->cmsg_type = 51;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, hdr, hdr->cmsg_len);
	if (ret < 0) {
		T_LOG("Clear v6 socket options failed: %s", strerror(errno));
	}
	free(buffer);
}

static void
clear_v4_pktoptions(int sock)
{
	uint32_t len = CMSG_LEN(0);
	char *buffer;
	struct cmsghdr *hdr;
	int ret;

	buffer = malloc(len);
	T_QUIET;
	T_ASSERT_NOTNULL(buffer, "malloc");

	memset(buffer, 0, len);
	hdr = (struct cmsghdr *)buffer;
	hdr->cmsg_len = len;
	hdr->cmsg_level = IPPROTO_IP;
	hdr->cmsg_type = IP_PKTINFO;

	ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, hdr, hdr->cmsg_len);
	if (ret < 0) {
		T_LOG("Clear v4 socket options failed: %s", strerror(errno));
	}

	free(buffer);
}

static void
send_msgv6(int sock)
{
	char *buffer;
	struct in6_addr remote_addr;
	struct sockaddr_in6 remote;
	ssize_t nwrite;

	buffer = malloc(0x100);
	T_QUIET;
	T_ASSERT_NOTNULL(buffer, "malloc");

	memset(buffer, 'B', 0x100);

	T_QUIET;
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &remote_addr), 1, "inet_pton");

	remote.sin6_family = AF_INET6;
	remote.sin6_len = sizeof(remote);
	remote.sin6_port = htons(8001);
	remote.sin6_addr = remote_addr;

	nwrite = sendto(sock, buffer, 0x100, 0, (struct sockaddr *)&remote, sizeof(remote));
	free(buffer);
	if (nwrite < 0) {
		T_LOG("Send message v6 failed: %s", strerror(errno));
	}
}

static void
send_msgv4(int sock)
{
	char *buffer;
	struct in_addr remote_addr;
	struct sockaddr_in remote;
	ssize_t nwrite;

	buffer = malloc(0x100);
	T_QUIET;
	T_ASSERT_NOTNULL(buffer, "malloc");

	memset(buffer, 'B', 0x100);

	T_QUIET;
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &remote_addr), 1, "inet_pton");

	remote.sin_family = AF_INET;
	remote.sin_len = sizeof(remote);
	remote.sin_port = htons(8001);
	remote.sin_addr = remote_addr;

	nwrite = sendto(sock, buffer, 0x100, 0, (struct sockaddr *)&remote, sizeof(remote));
	free(buffer);
	if (nwrite < 0) {
		T_LOG("Send message v4 failed: %s", strerror(errno));
	}
}

static void *
th_send_msg(void *arg)
{
	send_msgv6(g_opt_fd_v6);
	send_msgv4(g_opt_fd_v4);
	return NULL;
}

T_DECL(test_sockopts_with_send,
    "test socket options racing with send operations",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120))
{
	int ass_fd;
	int i = 0;

	ass_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(ass_fd, "socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)");

	while (i++ < 1000) {
		int opt_fd_v6, opt_fd_v4;
		pthread_t th;

		opt_fd_v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		opt_fd_v4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(opt_fd_v6, "socket v6");
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(opt_fd_v4, "socket v4");

		alloc_v6_pktoptions(opt_fd_v6);
		alloc_v4_pktoptions(opt_fd_v4);
		alloc_v6_pktoptions(ass_fd);

		g_opt_fd_v6 = opt_fd_v6;
		g_opt_fd_v4 = opt_fd_v4;

		T_QUIET;
		T_ASSERT_POSIX_ZERO(pthread_create(&th, NULL, th_send_msg, NULL),
		    "pthread_create");

		clear_v6_pktoptions(opt_fd_v6);
		clear_v4_pktoptions(opt_fd_v4);
		set_sock_pkt_rthdr(ass_fd);

		T_QUIET;
		T_ASSERT_POSIX_ZERO(pthread_join(th, NULL), "pthread_join");

		close(opt_fd_v6);
		close(opt_fd_v4);
		clear_v6_pktoptions(ass_fd);
	}

	close(ass_fd);
	force_zone_gc();

	T_PASS("test_sockopts_with_send completed without panic");
}
