/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp_log.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

static uint32_t saved_udp_log_enable = UINT32_MAX;

static void
enable_udp_logging(void)
{
	size_t oldlen = sizeof(saved_udp_log_enable);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("net.inet.udp.log.enable", &saved_udp_log_enable, &oldlen, NULL, 0),
	    "get net.inet.udp.log.enable");

	/* Enable UDP logs for bind on loopback */
	uint32_t newval = saved_udp_log_enable | ULEF_BIND | ULEF_CONNECT | ULEF_DST_LOOPBACK;

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("net.inet.udp.log.enable", NULL, NULL, &newval, sizeof(newval)),
	    "set net.inet.udp.log.enable");
}

static void
reset_udp_logging(void)
{
	if (saved_udp_log_enable != UINT32_MAX) {
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("net.inet.udp.log.enable", NULL, NULL, &saved_udp_log_enable, sizeof(saved_udp_log_enable)),
		    "restore net.inet.udp.log.enable");
	}
}

T_DECL(sonumrcvpkt,
    "test SO_NUMRCVPKT socket option returns correct packet count",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(30))
{
	int recv_fd, send_fd;
	struct sockaddr_in dst_sin = {};
	socklen_t socklen = sizeof(struct sockaddr_in);
	char buffer[INET6_ADDRSTRLEN];
	int num_sent_pkts = 0;
	ssize_t num_sent_bytes = 0;
	int so_num_rcv_pkt = 0;
	const char *test_strings[] = { "hello", "world", "test", "data", NULL };

	enable_udp_logging();
	T_ATEND(reset_udp_logging);

	/* Create a UDP listener */
	recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(recv_fd, "socket(AF_INET, SOCK_DGRAM, 0)");

	/* Bind to loopback ephemeral port */
	dst_sin.sin_len = sizeof(struct sockaddr_in);
	dst_sin.sin_family = AF_INET;
	dst_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	T_ASSERT_POSIX_SUCCESS(bind(recv_fd, (struct sockaddr *)&dst_sin, dst_sin.sin_len), "bind");

	T_ASSERT_POSIX_SUCCESS(getsockname(recv_fd, (struct sockaddr *)&dst_sin, &socklen), "getsockname");

	T_QUIET;
	T_ASSERT_NOTNULL(inet_ntop(AF_INET, &dst_sin.sin_addr.s_addr, buffer, sizeof(buffer)), "inet_ntop");

	T_LOG("Listening on %s port %u", buffer, ntohs(dst_sin.sin_port));

	/* Send test packets */
	send_fd = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(send_fd, "socket(AF_INET, SOCK_DGRAM, 0)");

	dst_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (int i = 0; test_strings[i] != NULL; i++) {
		ssize_t len = strlen(test_strings[i]);

		T_QUIET;
		T_ASSERT_EQ(sendto(send_fd, test_strings[i], len, 0, (struct sockaddr *)&dst_sin, dst_sin.sin_len), len, "sendto");

		num_sent_bytes += len;
		num_sent_pkts++;
		T_LOG("Sent packet %d: %s", i + 1, test_strings[i]);
	}

	/* Wait up to 1 second to receive all the packets */
	bool received_all = false;
	for (int i = 0; i < 100; i++) {
		struct stat stat;

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(fstat(recv_fd, &stat), "fstat");

		T_LOG("Iteration %d: stat.st_size = %lld", i, stat.st_size);

		if (stat.st_size == num_sent_bytes) {
			int nread;

			socklen = sizeof(so_num_rcv_pkt);
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(getsockopt(recv_fd, SOL_SOCKET, SO_NUMRCVPKT, &so_num_rcv_pkt, &socklen), "getsockopt SO_NUMRCVPKT");

			T_LOG("SO_NUMRCVPKT = %d", so_num_rcv_pkt);

			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(getsockopt(recv_fd, SOL_SOCKET, SO_NREAD, &nread, &socklen), "getsockopt SO_NREAD");

			T_LOG("SO_NREAD = %d", nread);

			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(ioctl(recv_fd, FIONREAD, &nread), "ioctl FIONREAD");

			T_LOG("FIONREAD = %d", nread);

			received_all = true;
			break;
		}
		usleep(10000);
	}

	T_ASSERT_TRUE(received_all, "Received all sent bytes");

	/* Read all pending packets */
	int num_received_pkts = 0;
	for (int i = 0; i < num_sent_pkts + 1; i++) {
		char recv_buffer[LINE_MAX];

		ssize_t len = recv(recv_fd, recv_buffer, sizeof(recv_buffer) - 1, MSG_DONTWAIT);
		if (len < 0) {
			if (errno != EWOULDBLOCK) {
				T_LOG("recv() failed: %s", strerror(errno));
			}
			break;
		}
		num_received_pkts++;
		recv_buffer[len] = '\0';
		T_LOG("Received packet %d: %s", i + 1, recv_buffer);
	}

	close(send_fd);
	close(recv_fd);

	/* Verify SO_NUMRCVPKT matches actual sent/received packets */
	T_EXPECT_EQ(so_num_rcv_pkt, num_sent_pkts, "SO_NUMRCVPKT matches number of sent packets");
	T_EXPECT_EQ(num_received_pkts, num_sent_pkts, "Number of received packets matches sent packets");

	if (so_num_rcv_pkt == num_sent_pkts && num_received_pkts == num_sent_pkts) {
		T_PASS("SO_NUMRCVPKT correctly reports %d packets", so_num_rcv_pkt);
	} else {
		T_FAIL("SO_NUMRCVPKT = %d, sent = %d, received = %d",
		    so_num_rcv_pkt, num_sent_pkts, num_received_pkts);
	}
}
