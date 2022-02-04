/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
 * inet_transfer.c
 * - perform IPv4/IPv6 UDP/TCP transfer tests
 */

#include <darwintest.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/event.h>
#include <net/if.h>
#define __APPLE_USE_RFC_3542 1
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/bootp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <net/bpf.h>
#include <net/if_bridgevar.h>
#include <net/if_fake_var.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sysexits.h>
#include <darwintest_utils.h>

#include "inet_transfer.h"

#define s6_addr16 __u6_addr.__u6_addr16

typedef union {
	struct sockaddr         sa;
	struct sockaddr_in      sin;
	struct sockaddr_in6     sin6;
} inet_sockaddr, *inet_sockaddr_t;

typedef struct {
	inet_sockaddr           addr;
	uint8_t                 proto;
	int                     sock_fd;
	int                     server_fd;
} inet_socket, *inet_socket_t;

static char error_string[2048];

#define set_error_string(__format, ...)                         \
	do {                                                            \
	        snprintf(error_string, sizeof(error_string),            \
	                 __format, ## __VA_ARGS__);                     \
	} while (0)

static void
inet_sockaddr_init(inet_sockaddr_t addr, uint8_t af)
{
	bzero(addr, sizeof(*addr));
	addr->sa.sa_family = af;
	if (af == AF_INET) {
		addr->sa.sa_len = sizeof(struct sockaddr_in);
	} else {
		addr->sa.sa_len = sizeof(struct sockaddr_in6);
	}
	return;
}

static void
inet_sockaddr_init_with_endpoint(inet_sockaddr_t addr, inet_endpoint_t endpoint)
{
	bzero(addr, sizeof(*addr));
	addr->sa.sa_family = endpoint->af;
	if (endpoint->af == AF_INET) {
		struct sockaddr_in *sin_p = &addr->sin;

		sin_p->sin_len = sizeof(*sin_p);
		sin_p->sin_addr = endpoint->addr.v4;
		if (endpoint->port != 0) {
			sin_p->sin_port = htons(endpoint->port);
		}
	} else {
		struct sockaddr_in6 *sin6_p = &addr->sin6;

		sin6_p->sin6_len = sizeof(*sin6_p);
		sin6_p->sin6_addr = endpoint->addr.v6;
		if (endpoint->port != 0) {
			sin6_p->sin6_port = htons(endpoint->port);
		}
	}
	return;
}

static uint8_t
inet_sockaddr_get_family(inet_sockaddr_t addr)
{
	return addr->sa.sa_family;
}

static void
inet_sockaddr_embed_scope(inet_sockaddr_t addr, int if_index)
{
	struct sockaddr_in6 *sin6_p;

	if (inet_sockaddr_get_family(addr) != AF_INET6) {
		return;
	}
	sin6_p = &addr->sin6;
	if (!IN6_IS_ADDR_LINKLOCAL(&sin6_p->sin6_addr)) {
		return;
	}
	sin6_p->sin6_addr.s6_addr16[1] = htons(if_index);
	return;
}

static bool
inet_endpoint_is_valid(inet_endpoint_t node)
{
	switch (node->af) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		set_error_string("invalid address family %d", node->af);
		return false;
	}
	switch (node->proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		set_error_string("invalid protocol %d", node->proto);
		return false;
	}
	return true;
}

static uint8_t
proto_get_socket_type(uint8_t proto)
{
	return (proto == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;
}

static const char *
af_get_string(uint8_t af)
{
	return (af == AF_INET) ? "AF_INET" : "AF_INET6";
}

static const char *
socket_type_get_string(uint8_t type)
{
	return (type == SOCK_DGRAM) ? "SOCK_DGRAM" : "SOCK_STREAM";
}

static bool
socket_bind_to_interface(const char * msg, int s, uint8_t af, int if_index)
{
	int     level;
	int     opt;

	/* bind to interface */
	if (af == AF_INET) {
		level = IPPROTO_IP;
		opt = IP_BOUND_IF;
	} else {
		level = IPPROTO_IPV6;
		opt = IPV6_BOUND_IF;
	}
	if (setsockopt(s, level, opt, &if_index, sizeof(if_index)) < 0) {
		set_error_string("%s: setsockopt(IP%s_BOUND_IF, %d) %s (%d)",
		    msg, (af == AF_INET) ? "" : "V6", if_index,
		    strerror(errno), errno);
		return false;
	}
	return true;
}

static bool
socket_setsockopt_int(const char * msg, int s, int level, int opt, int val)
{
	if (setsockopt(s, level, opt, &val, sizeof(val)) < 0) {
		set_error_string("%s: setsockopt(%d, %d, %d) %s (%d)",
		    msg, level, opt, val, strerror(errno), errno);
		return false;
	}
	return true;
}

static void
inet_socket_init(inet_socket_t sock)
{
	bzero(sock, sizeof(*sock));
	sock->server_fd = -1;
	sock->sock_fd = -1;
	return;
}

static void
inet_socket_close(inet_socket_t sock)
{
	if (sock->server_fd >= 0) {
		close(sock->server_fd);
	}
	if (sock->sock_fd >= 0) {
		close(sock->sock_fd);
	}
	return;
}

static bool
inet_socket_init_server(inet_socket_t server, inet_endpoint_t endpoint,
    int server_if_index)
{
	int     s;
	uint8_t socket_type = proto_get_socket_type(endpoint->proto);

	inet_sockaddr_init_with_endpoint(&server->addr, endpoint);
	inet_sockaddr_embed_scope(&server->addr, server_if_index);
	server->proto = endpoint->proto;
	s = socket(server->addr.sa.sa_family, socket_type, 0);
	if (s < 0) {
		set_error_string("%s: socket(%s, %s) failed %s (%d)",
		    __func__,
		    af_get_string(endpoint->af),
		    socket_type_get_string(socket_type),
		    strerror(errno), errno);
		return false;
	}
	if (!socket_setsockopt_int(__func__, s, SOL_SOCKET, SO_REUSEADDR, 1)) {
		return false;
	}
	if (!socket_setsockopt_int(__func__, s, SOL_SOCKET, SO_REUSEPORT, 1)) {
		return false;
	}

	/* bind to interface */
	if (!socket_bind_to_interface(__func__, s,
	    endpoint->af, server_if_index)) {
		return false;
	}

	/* bind to address */
	if (bind(s, &server->addr.sa, server->addr.sa.sa_len) < 0) {
		set_error_string("%s: bind(%s, %s, port=%d) failed %s (%d)",
		    __func__,
		    af_get_string(endpoint->af),
		    socket_type_get_string(socket_type),
		    endpoint->port, strerror(errno), errno);
		goto failed;
	}

	/* get the bound port */
	if (endpoint->port == 0) {
		inet_sockaddr   bound_sa;
		socklen_t       bound_sa_len = sizeof(bound_sa);
		uint16_t        port;

		if (getsockname(s, &bound_sa.sa, &bound_sa_len) < 0) {
			set_error_string("%s: getsockname(%s, %s) %s (%d)",
			    __func__,
			    af_get_string(endpoint->af),
			    socket_type_get_string(socket_type),
			    strerror(errno), errno);
			goto failed;
		}
		if (endpoint->af == AF_INET) {
			port = server->addr.sin.sin_port
			            = bound_sa.sin.sin_port;
		} else {
			port = server->addr.sin6.sin6_port
			            = bound_sa.sin6.sin6_port;
		}
		endpoint->port = ntohs(port);
	}

	/* listen (TCP) */
	if (endpoint->proto == IPPROTO_TCP && listen(s, 1) < 0) {
		set_error_string("%s: listen(%s, 1) failed %s (%d)",
		    __func__,
		    af_get_string(endpoint->af),
		    strerror(errno), errno);
		goto failed;
	}
	server->server_fd = s;
	return true;

failed:
	close(s);
	return false;
}

static bool
inet_socket_init_client(inet_socket_t client, int client_if_index,
    inet_endpoint_t endpoint)
{
	int     s;
	uint8_t socket_type = proto_get_socket_type(endpoint->proto);

	inet_sockaddr_init(&client->addr, endpoint->af);
	s = socket(endpoint->af, socket_type, 0);
	if (s < 0) {
		set_error_string("%s: socket(%s, %s) failed %s (%d)",
		    __func__,
		    af_get_string(endpoint->af),
		    socket_type_get_string(socket_type),
		    strerror(errno), errno);
		return false;
	}
	/* bind to interface */
	if (!socket_bind_to_interface(__func__,
	    s, endpoint->af, client_if_index)) {
		goto failed;
	}
	client->sock_fd = s;
	return true;

failed:
	close(s);
	return false;
}

static bool
inet_socket_client_connect(inet_socket_t client, int client_if_index,
    inet_endpoint_t endpoint)
{
	inet_sockaddr_init_with_endpoint(&client->addr, endpoint);
	inet_sockaddr_embed_scope(&client->addr, client_if_index);
	if (connect(client->sock_fd, &client->addr.sa, client->addr.sa.sa_len)
	    < 0) {
		set_error_string("%s: connect failed %s (%d)",
		    __func__, strerror(errno), errno);
		return false;
	}
	return true;
}

#if 0
static const char *
inet_sockaddr_ntop(inet_sockaddr_t addr, char * ntopbuf, u_int ntopbuf_size)
{
	const char *    ptr;

	if (addr->sa.sa_family == AF_INET) {
		ptr = (const char *)&addr->sin.sin_addr;
	} else {
		ptr = (const char *)&addr->sin6.sin6_addr;
	}
	return inet_ntop(addr->sa.sa_family, ptr, ntopbuf, ntopbuf_size);
}
#endif

static bool
inet_socket_server_accept(inet_socket_t server)
{
	inet_sockaddr   new_client;
	int             new_fd;
	socklen_t       socklen = sizeof(new_client);

	new_fd = accept(server->server_fd, &new_client.sa, &socklen);
	if (new_fd < 0) {
		set_error_string("%s: accept failed %s (%d)",
		    __func__, strerror(errno), errno);
		return false;
	}
	server->sock_fd = new_fd;
	return true;
}

static void
fill_with_random(uint8_t * buf, u_int len)
{
	u_int           i;
	u_int           n;
	uint8_t *       p;
	uint32_t        random;

	n = len / sizeof(random);
	for (i = 0, p = buf; i < n; i++, p += sizeof(random)) {
		random = arc4random();
		bcopy(&random, p, sizeof(random));
	}
	return;
}

static bool
wait_for_receive(int fd, bool * error)
{
	fd_set          readfds;
	int             n;
	struct timeval  tv;

	*error = false;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	tv.tv_sec = 0;
	tv.tv_usec = 200 * 1000;
	n = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
	if (n < 0) {
		*error = true;
		set_error_string("%s: select failed %s (%d)",
		    __func__, strerror(errno), errno);
	}
	return n > 0;
}

static bool
send_receive(const char * msg,
    int send_fd, int recv_fd, const uint8_t * data, uint16_t data_size,
    bool retry, bool need_connect)
{
	ssize_t         n;
	uint8_t         rbuf[2048];
	inet_sockaddr   sa;
	socklen_t       sa_len = sizeof(sa);
	int             try = 0;
	ssize_t         total = 0;

	/* send payload to receiver */
	bzero(&sa, sizeof(sa));
	do {
		bool            failed = false;

		n = send(send_fd, data, data_size, 0);
		if (n != data_size) {
			set_error_string("%s: %s %d bytes (actual %ld)"
			    " failed %s (%d)",
			    __func__, msg,
			    data_size, n, strerror(errno), errno);
			return false;
		}
#define MAX_TRY         2
		if (retry && !wait_for_receive(recv_fd, &failed)) {
			if (failed) {
				return false;
			}
			try++;
			if (try == MAX_TRY) {
				set_error_string("%s: %s max retry",
				    __func__, msg);
				return false;
			}
			continue;
		}
	} while (false);

	/* receive payload from sender */
	total = 0;
	while (total < data_size) {
		if (need_connect) {
			/* need originator's address to connect UDP socket */
			n = recvfrom(recv_fd, rbuf, sizeof(rbuf), 0,
			    &sa.sa, &sa_len);
		} else {
			n = recv(recv_fd, rbuf, sizeof(rbuf), 0);
		}
		if (n <= 0) {
			perror("recv");
			break;
		}
		total += n;
	}
	if (total != data_size) {
		set_error_string("%s: %s %d bytes (actual %ld)"
		    " failed %s (%d)",
		    __func__, msg,
		    data_size, total, strerror(errno),
		    errno);
		return false;
	}
	if (need_connect && connect(recv_fd, &sa.sa, sa_len) < 0) {
		set_error_string("%s: %s connect failed %s (%d)",
		    __func__, msg, strerror(errno), errno);
		return false;
	}
	return true;
}

typedef struct {
	uint16_t        start;
	uint16_t        end;
} uint16_range, *uint16_range_t;

static uint16_range
    data_sizes[] = { { 1, 15 },
		     { 39, 60 },
		     { 79, 100 },
		     { 215, 236 },
		     { 485, 506 },
		     { 985, 1006 },
		     { 1250, 1279 },
		     { 1461, 1500 }, /* this will result in IP fragmentation */
		     { 0, 0 }};

static bool
inet_transfer_loop(inet_socket_t server, inet_socket_t client)
{
	bool            need_connect;
	uint8_t         buf[2048];
	bool            retry;
	uint16_range_t  scan;
	int             server_fd;

	if (server->proto == IPPROTO_TCP) {
		server_fd = server->sock_fd;
		need_connect = false;
		retry = false;
		need_connect = false;
	} else {
		server_fd = server->server_fd;
		need_connect = true;
		retry = true; /* UDP is unreliable, retry if necessary */
		need_connect = true;
	}
	fill_with_random(buf, sizeof(buf));

	/*
	 * ping pong packets back and forth between the client and server.
	 */
	for (scan = data_sizes; scan->start != 0; scan++) {
		for (uint16_t data_size = scan->start;
		    data_size < scan->end; data_size++) {
			bool    success;

			/* Client to Server */
			success = send_receive("client send",
			    client->sock_fd, server_fd,
			    buf, data_size, retry,
			    need_connect);
			if (!success) {
				return false;
			}
			/* UDP socket only needs to be connect()'d first time */
			need_connect = false;

			/* Server to Client */
			success = send_receive("server send",
			    server_fd, client->sock_fd,
			    buf, data_size, retry,
			    false);
			if (!success) {
				return false;
			}
		}
	}
	return true;
}

bool
inet_transfer_local(inet_endpoint_t server_endpoint,
    int server_if_index, int client_if_index)
{
	inet_socket     client;
	inet_socket     server;
	bool            success = false;

	inet_socket_init(&server);
	inet_socket_init(&client);

	if (!inet_endpoint_is_valid(server_endpoint)) {
		return false;
	}
	if (!inet_socket_init_server(&server, server_endpoint,
	    server_if_index)) {
		goto failed;
	}
	if (!inet_socket_init_client(&client, client_if_index,
	    server_endpoint)) {
		goto failed;
	}
	if (!inet_socket_client_connect(&client, client_if_index,
	    server_endpoint)) {
		goto failed;
	}
	if (server.proto == IPPROTO_TCP
	    && !inet_socket_server_accept(&server)) {
		goto failed;
	}
	if (!inet_transfer_loop(&server, &client)) {
		goto failed;
	}
	success = true;

failed:
	inet_socket_close(&client);
	inet_socket_close(&server);
	return success;
}

const char *
inet_transfer_error_string(void)
{
	return error_string;
}


#ifdef TEST_INET_TRANSFER

static void
usage(const char * progname)
{
	fprintf(stderr,
	    "usage: %s -i <client-interface> -I <server-interface> "
	    "-s <server_ip> [ -p <port> ] [ -t | -u ]\n", progname);
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int                     client_if_index = 0;
	int                     server_if_index = 0;
	int                     ch;
	const char *            progname = argv[0];
	inet_endpoint           endpoint;

	bzero(&endpoint, sizeof(endpoint));
	while ((ch = getopt(argc, argv, "i:I:p:s:tu")) != EOF) {
		switch ((char)ch) {
		case 'i':
			if (client_if_index != 0) {
				usage(progname);
			}
			client_if_index = if_nametoindex(optarg);
			if (client_if_index == 0) {
				fprintf(stderr, "No such interface '%s'\n",
				    optarg);
				exit(EX_USAGE);
			}
			break;
		case 'I':
			if (server_if_index != 0) {
				usage(progname);
			}
			server_if_index = if_nametoindex(optarg);
			if (server_if_index == 0) {
				fprintf(stderr, "No such interface '%s'\n",
				    optarg);
				exit(EX_USAGE);
			}
			break;
		case 'p':
			if (endpoint.port != 0) {
				fprintf(stderr,
				    "port specified multiple times\n");
				usage(progname);
			}
			endpoint.port = strtoul(optarg, NULL, 0);
			if (endpoint.port == 0) {
				fprintf(stderr,
				    "Invalid port '%s'\n", optarg);
				usage(progname);
			}
			break;
		case 's':
			if (endpoint.af != 0) {
				fprintf(stderr,
				    "-s may only be specified once\n");
				usage(progname);
			}
			if (inet_pton(AF_INET, optarg,
			    &endpoint.addr) == 1) {
				endpoint.af = AF_INET;
			} else if (inet_pton(AF_INET6, optarg,
			    &endpoint.addr) == 1) {
				endpoint.af = AF_INET6;
			} else {
				fprintf(stderr, "invalid IP address '%s'\n",
				    optarg);
				exit(EX_USAGE);
			}
			break;
		case 't':
			if (endpoint.proto != 0) {
				fprintf(stderr,
				    "protocol specified multiple times\n");
				usage(progname);
			}
			endpoint.proto = IPPROTO_TCP;
			break;
		case 'u':
			if (endpoint.proto != 0) {
				fprintf(stderr,
				    "protocol specified multiple times\n");
				usage(progname);
			}
			endpoint.proto = IPPROTO_UDP;
			break;
		default:
			break;
		}
	}
	if (server_if_index == 0 || client_if_index == 0 || endpoint.af == 0) {
		usage(progname);
	}
	if (endpoint.proto == 0) {
		endpoint.proto = IPPROTO_TCP;
	}
	if (!inet_transfer_local(&endpoint, server_if_index, client_if_index)) {
		fprintf(stderr, "inet_transfer_local failed\n%s\n",
		    inet_transfer_error_string());
		exit(EX_OSERR);
	}
	exit(0);
	return 0;
}
#endif /* TEST_INET_TRANSFER */
