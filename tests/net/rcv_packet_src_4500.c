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
 * Test for rdar://55220057
 * Tests receiving packets from source port 4500
 *
 * Created by Delziel Fernandes on 9/20/19.
 */

#include <darwintest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("fernandes")
	);

#define SERVER_PORT 4501
#define CLIENT_PORT 4500

static const char buffer[] = "Send Ping";

static int
create_server_v4(void)
{
	int sock;
	struct sockaddr_in server = {};

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sock, "socket(AF_INET, SOCK_DGRAM, 0)");

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(SERVER_PORT);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bind(sock, (const struct sockaddr *)&server, sizeof(server)),
	    "bind server");

	return sock;
}

static int
start_client_v4(void)
{
	int sock;
	struct sockaddr_in server = {};
	struct sockaddr_in client = {};

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sock, "socket(AF_INET, SOCK_DGRAM, 0)");

	server.sin_family = AF_INET;
	server.sin_port = htons(SERVER_PORT);
	T_QUIET;
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &server.sin_addr), 1, "inet_pton");

	client.sin_family = AF_INET;
	client.sin_addr.s_addr = INADDR_ANY;
	client.sin_port = htons(CLIENT_PORT);

	if (bind(sock, (const struct sockaddr *)&client, sizeof(client)) != 0) {
		if (errno == EADDRINUSE) {
			T_SKIP("Port 4500 already in use (disconnect from VPN or stop IPsec services)");
		}
		T_ASSERT_POSIX_SUCCESS(-1, "bind client");
	}

	T_QUIET;
	T_ASSERT_EQ((ssize_t)sendto(sock, (const void *)buffer, strlen(buffer), 0,
	    (const struct sockaddr *)&server, sizeof(server)), (ssize_t)strlen(buffer),
	    "sendto");

	return sock;
}

static int
create_server_v6(void)
{
	int sock;
	struct sockaddr_in6 server = {};

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sock, "socket(AF_INET6, SOCK_DGRAM, 0)");

	server.sin6_family = AF_INET6;
	server.sin6_addr = in6addr_any;
	server.sin6_port = htons(SERVER_PORT);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bind(sock, (const struct sockaddr *)&server, sizeof(server)),
	    "bind server v6");

	return sock;
}

static int
start_client_v6(void)
{
	int sock;
	struct sockaddr_in6 server = {};
	struct sockaddr_in6 client = {};

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sock, "socket(AF_INET6, SOCK_DGRAM, 0)");

	server.sin6_family = AF_INET6;
	server.sin6_port = htons(SERVER_PORT);
	T_QUIET;
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &server.sin6_addr), 1, "inet_pton");

	client.sin6_family = AF_INET6;
	client.sin6_addr = in6addr_any;
	client.sin6_port = htons(CLIENT_PORT);

	if (bind(sock, (const struct sockaddr *)&client, sizeof(client)) != 0) {
		if (errno == EADDRINUSE) {
			T_SKIP("Port 4500 already in use (disconnect from VPN or stop IPsec services)");
		}
		T_ASSERT_POSIX_SUCCESS(-1, "bind client v6");
	}

	T_QUIET;
	T_ASSERT_EQ((ssize_t)sendto(sock, (const void *)buffer, strlen(buffer), 0,
	    (const struct sockaddr *)&server, sizeof(server)), (ssize_t)strlen(buffer),
	    "sendto v6");

	return sock;
}

T_DECL(rcv_packet_src_4500_v4,
    "test receiving packets from source port 4500 (IPv4)",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(15))
{
	int server_sock, client_sock;
	char recv_buffer[20] = {0};
	int n;

	server_sock = create_server_v4();
	client_sock = start_client_v4();

	n = recvfrom(server_sock, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);
	T_ASSERT_EQ(n, (int)strlen(buffer), "received correct number of bytes");
	T_ASSERT_EQ(strncmp(recv_buffer, buffer, strlen(buffer)), 0, "received correct string");

	T_LOG("received string: %s", recv_buffer);

	close(server_sock);
	close(client_sock);

	T_PASS("rcv_packet_src_4500_v4 completed");
}

T_DECL(rcv_packet_src_4500_v6,
    "test receiving packets from source port 4500 (IPv6)",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(15))
{
	int server_sock, client_sock;
	char recv_buffer[20] = {0};
	int n;

	server_sock = create_server_v6();
	client_sock = start_client_v6();

	n = recvfrom(server_sock, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);
	T_ASSERT_EQ(n, (int)strlen(buffer), "received correct number of bytes");
	T_ASSERT_EQ(strncmp(recv_buffer, buffer, strlen(buffer)), 0, "received correct string");

	T_LOG("received string: %s", recv_buffer);

	close(server_sock);
	close(client_sock);

	T_PASS("rcv_packet_src_4500_v6 completed");
}
