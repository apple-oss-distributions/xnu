/*
 * Copyright (c) 2018, 2025 Apple Inc. All rights reserved.
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
 * This test tries to connect to a server over the entire range
 * of ephemeral ports to make sure that we always use an unused port.
 * To do that, while we are traversing the range, we close all
 * connections but one (Port 49250). When it cycles back again, connect
 * should succeed using the next port (49251)
 */

#include <darwintest.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_RUN_CONCURRENTLY(false),
	T_META_OWNER("vidhi_goel"),
	T_META_ENABLED(!TARGET_OS_WATCH && !TARGET_OS_BRIDGE)
	);

static const char *server_name = "127.0.0.1";
static const char *port = "6000";
static const int client_port = 49250;

static pthread_mutex_t ready_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static bool server_ready = false;

static int
init_socket(int sockfd)
{
	int x = 1;
	struct linger so_linger;

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x)),
	    "setsockopt(SO_REUSEADDR)");

	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &so_linger,
	    sizeof(so_linger)), "setsockopt(SO_LINGER)");

	return 0;
}

static int
socket_connect(void)
{
	struct addrinfo *ai;
	int fd;
	struct sockaddr_in6 me;
	uint32_t len = sizeof(struct sockaddr_in6);

	T_QUIET;
	T_ASSERT_POSIX_ZERO(getaddrinfo(server_name, port, NULL, &ai), "getaddrinfo");

	fd = socket(ai->ai_family, SOCK_STREAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "socket");

	T_QUIET;
	T_ASSERT_POSIX_ZERO(init_socket(fd), "init_socket");

	int ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
	int saved_errno = errno;
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "connect (errno=%d: %s)", saved_errno, strerror(saved_errno));

	/* Make sure that connect doesn't fail with EADDRINUSE */
	T_QUIET;
	T_ASSERT_NE(saved_errno, EADDRINUSE, "connect should not fail with EADDRINUSE");

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(getsockname(fd, (struct sockaddr *)&me, &len), "getsockname");

	if (ntohs(me.sin6_port) != client_port) {
		close(fd);
	}

	freeaddrinfo(ai);
	return 0;
}

static void *
socket_listen(void *p)
{
	struct addrinfo *ai;
	int fd;
	struct sockaddr_in6 client;
	uint32_t client_len = sizeof(struct sockaddr_in6);

	T_QUIET;
	T_ASSERT_POSIX_ZERO(getaddrinfo(server_name, port, NULL, &ai), "getaddrinfo");

	fd = socket(ai->ai_family, SOCK_STREAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "socket");

	T_QUIET;
	T_ASSERT_POSIX_ZERO(init_socket(fd), "init_socket");

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bind(fd, ai->ai_addr, ai->ai_addrlen), "bind");

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(listen(fd, 128), "listen");

	freeaddrinfo(ai);

	/* Signal that the server is ready to accept connections */
	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_mutex_lock(&ready_mutex), "pthread_mutex_lock");
	server_ready = true;
	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_cond_signal(&ready_cond), "pthread_cond_signal");
	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_mutex_unlock(&ready_mutex), "pthread_mutex_unlock");

	while (1) {
		int accept_fd = accept(fd, (struct sockaddr *)&client, &client_len);
		if (accept_fd < 0) {
			continue;
		}
		if (ntohs(client.sin6_port) != client_port) {
			close(accept_fd);
		}
	}
	close(fd);
	return NULL;
}

T_DECL(test_connect_reuseaddr,
    "test connect with SO_REUSEADDR over ephemeral port range",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120))
{
	int hiport = 49352;
	int range;
	pthread_t listen_thread;
	int count = 0;

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("net.inet.ip.portrange.last", NULL, NULL,
	    &hiport, sizeof(hiport)), "sysctlbyname set last port");

	range = hiport - IPPORT_HIFIRSTAUTO;

	T_ASSERT_POSIX_ZERO(pthread_create(&listen_thread, NULL, socket_listen, NULL),
	    "pthread_create");

	/* Wait for the server to be ready before starting connections */
	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_mutex_lock(&ready_mutex), "pthread_mutex_lock");
	while (!server_ready) {
		T_QUIET;
		T_ASSERT_POSIX_ZERO(pthread_cond_wait(&ready_cond, &ready_mutex), "pthread_cond_wait");
	}
	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_mutex_unlock(&ready_mutex), "pthread_mutex_unlock");

	T_LOG("Connecting over port range (size %d), keeping port %d open", range, client_port);

	while (count < 2 * range) {
		int ret = socket_connect();
		if (ret != 0) {
			T_LOG("socket_connect failed, stopping at count %d", count);
			break;
		}
		count++;
	}

	T_LOG("Completed %d connections", count);

	/* Restore default port range */
	hiport = IPPORT_HILASTAUTO;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("net.inet.ip.portrange.last", NULL, NULL,
	    &hiport, sizeof(hiport)), "sysctlbyname restore last port");

	force_zone_gc();

	T_PASS("test_connect_reuseaddr completed");
}
