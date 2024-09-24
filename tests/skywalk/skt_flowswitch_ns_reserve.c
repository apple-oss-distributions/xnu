/*
 * Copyright (c) 2016-2024 Apple Inc. All rights reserved.
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

#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <uuid/uuid.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <arpa/inet.h>
#include <skywalk/os_nexus.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

#define SKT_TCP_MSL_DELAY       1 /* millisecond */
#define INVERT_PROTO(p) (((p) == IPPROTO_TCP) ? IPPROTO_UDP : IPPROTO_TCP)

#define MESSAGE_STRING  "1234567"
struct test_message {
	char tm_string[sizeof(MESSAGE_STRING)];
};
struct thread_arg {
	int ta_sock;
	int ta_proto;
};

typedef enum {
	kErrorFlagsAssert = 0x1,
	kErrorFlagsExpectFailure = 0x2,
} ErrorFlags;

#define ERROR_FLAGS_NO_ASSERT           0
#define ERROR_FLAGS_ASSERT_SUCCESS      kErrorFlagsAssert
#define ERROR_FLAGS_ASSERT_FAILURE                      \
	(kErrorFlagsAssert | kErrorFlagsExpectFailure)

static inline boolean_t
ErrorFlagsAreSet(ErrorFlags flags, ErrorFlags check)
{
	return (flags & check) != 0;
}

const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

static void *
reader_thread_bsd(void *arg)
{
	const struct thread_arg *ta = arg;
	struct test_message tm;
	struct sockaddr sa;
	socklen_t slen;
	ssize_t rv;

	if (ta->ta_proto == IPPROTO_TCP) {
		int fd;

		/* Accept the first (and only) connection */
		fd = accept(ta->ta_sock, &sa, &slen);
		assert(fd >= 0);

		/* Read the message */
		rv = read(fd, &tm, sizeof(tm));
		assert(rv == sizeof(tm));
		close(fd);
	} else {
		/* Wait for a message */
		rv = recv(ta->ta_sock, &tm, sizeof(tm), MSG_WAITALL);
		assert(rv == sizeof(tm));
	}

	if (strncmp(tm.tm_string, MESSAGE_STRING, sizeof(tm.tm_string))) {
		T_LOG("Unexpected message received");
		assert(0);
	}

	return NULL;
}

static void
skt_flowswitch_ns_bsd(struct sktc_nexus_handles *handles, int proto, void *addr)
{
	union sockaddr_in_4_6 saddr = *(union sockaddr_in_4_6 *)addr;
	union sockaddr_in_4_6 laddr;
	struct test_message tm;
	int error, lsock, wsock;
	int pf, stype;
	pthread_t thread;
	ssize_t rv;
	char buf0[32], buf1[32];
	uuid_string_t uuidstr;
	struct thread_arg ta;
	struct nx_flow_req nfr;
	socklen_t len = sizeof(saddr);

	bzero(&laddr, sizeof(laddr));
	laddr.sa.sa_family = saddr.sa.sa_family;
	laddr.sa.sa_len = saddr.sa.sa_len;
	stype = (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	if (saddr.sa.sa_family == AF_INET) {
		pf = PF_INET;
		inet_ntop(AF_INET, &saddr.sin.sin_addr, buf1, sizeof(buf1));
	} else {
		pf = PF_INET6;
		inet_ntop(AF_INET6, &saddr.sin6.sin6_addr, buf1, sizeof(buf1));
	}

	T_LOG("BSD: Testing %s over IPv%u %s\n",
	    (proto == IPPROTO_TCP) ? "TCP" : "UDP",
	    (saddr.sa.sa_family == AF_INET) ? 4 : 6,
	    buf1);

	/* create & bind a BSD socket to the requested port */
	lsock = socket(pf, stype, proto);
	assert(lsock >= 0);

	error = bind(lsock, &saddr.sa, saddr.sa.sa_len);
	SKTC_ASSERT_ERR(error == 0);

	/* retrieve the locally bound name of the socket */
	error = getsockname(lsock, &saddr.sa, &len);
	SKTC_ASSERT_ERR(error == 0);

	if (proto == IPPROTO_TCP) {
		/* Listen for incoming connections */
		error = listen(lsock, 1);
		SKTC_ASSERT_ERR(error == 0);
	}

	/* Create reader thread */
	ta.ta_sock = lsock;
	ta.ta_proto = proto;
	error = pthread_create(&thread, NULL, reader_thread_bsd, &ta);
	SKTC_ASSERT_ERR(error == 0);

	/* Create another socket for connecting to the first */
	wsock = socket(pf, stype, proto);
	assert(wsock >= 0);

	/* Establish the connection */
	error = connect(wsock, &saddr.sa, saddr.sa.sa_len);
	SKTC_ASSERT_ERR(error == 0);

	/* Write the message */
	strncpy(tm.tm_string, MESSAGE_STRING, sizeof(tm.tm_string));
	if (proto == IPPROTO_TCP) {
		rv = write(wsock, &tm, sizeof(tm));
	} else {
		rv = send(wsock, &tm, sizeof(tm), 0);
	}
	assert(rv == sizeof(tm));

	/* Reap the listener thread */
	error = pthread_join(thread, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Close our end of the connection */
	close(wsock);

	/* Attempt to bind to the same address/port via Skywalk */
	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = proto;
	nfr.nfr_nx_port = NEXUS_PORT_FLOW_SWITCH_CLIENT; /* first usable */
	memcpy(&nfr.nfr_saddr, &saddr, sizeof(nfr.nfr_saddr));
	uuid_generate_random(nfr.nfr_flow_uuid);

	/* 3-tuple bind should fail */
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);

	if (saddr.sa.sa_family == AF_INET) {
		(void) inet_ntop(AF_INET, &handles->netif_addr, buf0,
		    sizeof(buf0));
	} else {
#if 0
		(void) inet_ntop(AF_INET6, &handles->netif_addr6, buf0,
		    sizeof(buf0));
#else
		buf0[0] = '\0';
#endif
	}

	T_LOG("On %s (%s), reserve <%s,%u> through skywalk "
	    "(flow %s)\n", handles->netif_ifname, buf0, buf1,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles->controller,
	    handles->fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error != 0);

	/* 2-tuple bind should also fail */
	T_LOG("On %s (%s), reserve <ANY,%u> through skywalk "
	    "(flow %s)\n", handles->netif_ifname, buf0,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles->controller,
	    handles->fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error != 0);

	T_LOG(" %s done\n", __func__);
	/* Close the BSD listener socket */
	close(lsock);
}

static void
skt_flowswitch_ns_sky(struct sktc_nexus_handles *handles, int proto, void *addr)
{
	union sockaddr_in_4_6 saddr = *(union sockaddr_in_4_6 *)addr;
	int error, lsock;
	int pf, stype, is_wild;
	char buf1[32];
	uuid_string_t uuidstr;
	struct nx_flow_req nfr;
	nexus_port_t nx_port = 2;
	uuid_t listener_flow;
//	uuid_t connected_flow;
//	char buf0[32];

	stype = (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	if (saddr.sa.sa_family == AF_INET) {
		pf =  PF_INET;
		is_wild = (saddr.sin.sin_addr.s_addr == INADDR_ANY);
		(void) inet_ntop(AF_INET, &saddr.sin.sin_addr, buf1,
		    sizeof(buf1));
	} else {
		pf = PF_INET6;
		is_wild = IN6_IS_ADDR_UNSPECIFIED(&saddr.sin6.sin6_addr);
		(void) inet_ntop(AF_INET6, &saddr.sin6.sin6_addr, buf1,
		    sizeof(buf1));
	}

	T_LOG("Skywalk: Testing %s over IPv%u %s\n",
	    (proto == IPPROTO_TCP) ? "TCP" : "UDP",
	    (saddr.sa.sa_family == AF_INET) ? 4 : 6,
	    buf1);

	/* Bind to port via Skywalk */
	uuid_generate_random(listener_flow);
	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = proto;
	nfr.nfr_nx_port = nx_port;
	memcpy(&nfr.nfr_saddr, &saddr, sizeof(nfr.nfr_saddr));
	uuid_copy(nfr.nfr_flow_uuid, listener_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s, reserve <%s,%u> through skywalk "
	    "(flow %s)\n", handles->netif_ifname, buf1,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles->controller,
	    handles->fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);

	memcpy(&saddr, &nfr.nfr_saddr, sizeof(saddr));

// Currently doesn't work - No route to host
#if 0
	/* Test connecting a new flow from the listener */
	uuid_generate_random(connected_flow);
	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = proto;
	nfr.nfr_nx_port = nx_port;

	memcpy(&nfr.nfr_saddr, &saddr, sizeof(nfr.nfr_saddr));
	memcpy(&nfr.nfr_daddr, &saddr, sizeof(nfr.nfr_daddr));
	if (saddr.sa.sa_family == AF_INET) {
		nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		nfr.nfr_daddr.sin.sin_port += htons(16);
		if (is_wild) {
			nfr.nfr_daddr.sin.sin_addr = handles->netif_addr;
		}
		inet_ntop(AF_INET, &nfr.nfr_daddr.sin.sin_addr, buf0,
		    sizeof(buf0));
	} else {
		memcpy(&nfr.nfr_saddr.sin6.sin6_addr, &in6addr_any,
		    sizeof(nfr.nfr_saddr.sin6.sin6_addr));
		nfr.nfr_daddr.sin6.sin6_port += htons(16);
#if 0
		if (is_wild) {
			nfr.nfr_daddr.sin6.sin6_addr = handles->netif_addr6;
		}
#endif
		inet_ntop(AF_INET6, &nfr.nfr_daddr.sin6.sin6_addr, buf0,
		    sizeof(buf0));
	}

	uuid_copy(nfr.nfr_flow_uuid, connected_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s, connect <%s,%u> -> <%s,%u> "
	    "(flow %s)\n", handles->netif_ifname,
	    buf0, ntohs(nfr.nfr_daddr.sin.sin_port),
	    buf1, ntohs(nfr.nfr_saddr.sin.sin_port),
	    uuidstr);
	error = __os_nexus_flow_add(handles->controller, handles->fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);
#endif

	/* create & bind a BSD socket to the requested port */
	lsock = socket(pf, stype, proto);
	assert(lsock >= 0);

	/* BSD bind should fail */
	error = bind(lsock, &saddr.sa, saddr.sa.sa_len);
	SKTC_ASSERT_ERR(error != 0);

	if (is_wild) {
		if (saddr.sa.sa_family == AF_INET) {
			saddr.sin.sin_addr = handles->netif_addr;
		} else {
#if 0
			saddr.sin6.sin6_addr = handles->netif_addr6;
#endif
		}

		/* BSD bind from non-wildcard should fail */
		error = bind(lsock, &saddr.sa, saddr.sa.sa_len);
		SKTC_ASSERT_ERR(error != 0);
	}

	close(lsock);

	memset(&nfr, 0, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, listener_flow);

	error = __os_nexus_flow_del(handles->controller, handles->fsw_nx_uuid,
	    &nfr);
	SKTC_ASSERT_ERR(!error);

#if 0
	memset(&nfr, 0, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, connected_flow);

	error = __os_nexus_flow_del(handles->controller, handles->fsw_nx_uuid,
	    &nfr);
	SKTC_ASSERT_ERR(!error);
#endif
	T_LOG(" %s done\n", __func__);
}

static int
skt_ns_sky_bind(struct  sktc_nexus_handles *handles, int proto, void *addr,
    ErrorFlags error_flags, uuid_t flow, uint16_t *bound_port)
{
	union sockaddr_in_4_6 sky_saddr = *(union sockaddr_in_4_6 *)addr;
	int error;
	int is_wild;
	char buf[32];
	uuid_string_t uuidstr;
	struct nx_flow_req nfr;
	nexus_port_t nx_port = 2;
	uint16_t port;

	if (sky_saddr.sa.sa_family == AF_INET) {
		is_wild = (sky_saddr.sin.sin_addr.s_addr == INADDR_ANY);
		(void) inet_ntop(AF_INET, &sky_saddr.sin.sin_addr, buf,
		    sizeof(buf));
		port = sky_saddr.sin.sin_port;
	} else {
		is_wild = IN6_IS_ADDR_UNSPECIFIED(&sky_saddr.sin6.sin6_addr);
		(void) inet_ntop(AF_INET6, &sky_saddr.sin6.sin6_addr, buf,
		    sizeof(buf));
		port = sky_saddr.sin6.sin6_port;
	}

	T_LOG("Skywalk: nexus bind %s over IPv%u %s :%d\n",
	    (proto == IPPROTO_TCP) ? "TCP" : "UDP",
	    (sky_saddr.sa.sa_family == AF_INET) ? 4 : 6, buf, ntohs(port));

	/* Bind to port via Skywalk */
	uuid_generate_random(flow);
	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = proto;
	nfr.nfr_nx_port = nx_port;
	memcpy(&nfr.nfr_saddr, &sky_saddr, sizeof(nfr.nfr_saddr));
	uuid_copy(nfr.nfr_flow_uuid, flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s, reserve <%s,%u> through skywalk "
	    "(flow %s)\n", handles->netif_ifname, buf,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles->controller, handles->fsw_nx_uuid,
	    &nfr);
	*bound_port = nfr.nfr_saddr.sin.sin_port;
	if (ErrorFlagsAreSet(error_flags, kErrorFlagsAssert)) {
		if (ErrorFlagsAreSet(error_flags, kErrorFlagsExpectFailure)) {
			SKTC_ASSERT_ERR(error != 0);
		} else {
			SKTC_ASSERT_ERR(error == 0);
		}
	}
	return error;
}

static int
skt_ns_sock_bind(struct  sktc_nexus_handles *handles, int proto, void *addr,
    ErrorFlags error_flags, int *lsock, boolean_t ipv6_only,
    uint16_t *bound_port)
{
	char buf[32];
	int error;
	int on = 0;
	union sockaddr_in_4_6 bsd_saddr = *(union sockaddr_in_4_6 *)addr;
	socklen_t len = sizeof(bsd_saddr);
	uint16_t port;

	if (bsd_saddr.sa.sa_family == AF_INET) {
		(void) inet_ntop(AF_INET, &bsd_saddr.sin.sin_addr, buf,
		    sizeof(buf));
		port = bsd_saddr.sin.sin_port;
	} else {
		(void) inet_ntop(AF_INET6, &bsd_saddr.sin6.sin6_addr, buf,
		    sizeof(buf));
		port = bsd_saddr.sin6.sin6_port;
	}
	/* create & bind a BSD socket to the requested port */
	*lsock = socket(bsd_saddr.sa.sa_family,
	    (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM,
	    proto);
	assert(*lsock >= 0);

	T_LOG("Skywalk: socket bind %s over IPv%u %s :%d\n",
	    (proto == IPPROTO_TCP) ? "TCP" : "UDP",
	    (bsd_saddr.sa.sa_family == AF_INET) ? 4 : 6, buf, ntohs(port));

	if (bsd_saddr.sa.sa_family == AF_INET6) {
		if (ipv6_only) {
			on = 1;
		}
		error = setsockopt(*lsock, IPPROTO_IPV6, IPV6_V6ONLY, &on,
		    sizeof(on));
		SKTC_ASSERT_ERR(error == 0);
	}
	error = bind(*lsock, &bsd_saddr.sa, bsd_saddr.sa.sa_len);
	if (ErrorFlagsAreSet(error_flags, kErrorFlagsAssert)) {
		if (ErrorFlagsAreSet(error_flags, kErrorFlagsExpectFailure)) {
			SKTC_ASSERT_ERR(error != 0);
		} else {
			SKTC_ASSERT_ERR(error == 0);
		}
	}
	*bound_port = 0;
	if (error == 0) {
		/* retrieve the locally bound name of the socket */
		if (getsockname(*lsock, &bsd_saddr.sa, &len) == 0) {
			*bound_port = bsd_saddr.sin.sin_port;
		} else {
			assert(0);
		}
	}
	return error;
}

static void
skt_flowswitch_ns_sky_bsd(struct sktc_nexus_handles *handles, int proto,
    void *sky_addr, void* bsd_addr, boolean_t sky_bind_first,
    ErrorFlags sky_err_flags, ErrorFlags bsd_err_flags,
    boolean_t ipv6_only, boolean_t use_bound_port)
{
	int error;
	struct nx_flow_req nfr;
	uint16_t bound_port;
	uuid_t flow;
	int lsock;

	if (sky_bind_first) {
		skt_ns_sky_bind(handles, proto, sky_addr, sky_err_flags,
		    flow, &bound_port);
		if (use_bound_port) {
			((struct sockaddr_in *)bsd_addr)->sin_port = bound_port;
		}
		skt_ns_sock_bind(handles, proto, bsd_addr, bsd_err_flags,
		    &lsock, ipv6_only, &bound_port);
	} else {
		skt_ns_sock_bind(handles, proto, bsd_addr, bsd_err_flags,
		    &lsock, ipv6_only, &bound_port);
		/*
		 * sleep to account for inpcb garbage collection delay.
		 */
		sleep(1);
		if (use_bound_port) {
			((struct sockaddr_in *)sky_addr)->sin_port = bound_port;
		}
		skt_ns_sky_bind(handles, proto, sky_addr, sky_err_flags,
		    flow, &bound_port);
	}

	if (!ErrorFlagsAreSet(sky_err_flags, kErrorFlagsExpectFailure)) {
		memset(&nfr, 0, sizeof(nfr));
		uuid_copy(nfr.nfr_flow_uuid, flow);
		error = __os_nexus_flow_del(handles->controller,
		    handles->fsw_nx_uuid, &nfr);
		SKTC_ASSERT_ERR(!error);
	}
	close(lsock);
	T_LOG(" %s done\n", __func__);
}

static void
skt_flowswitch_ns_check_v4mappedv6addr(struct sktc_nexus_handles *handles,
    uint16_t port)
{
	union sockaddr_in_4_6 saddr, saddr2;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int sock, error, on = 0;
	struct nx_flow_req nfr;
	char ntopbuf[INET6_ADDRSTRLEN];
	uint16_t bound_port;
	uuid_t flow;

	memset(&saddr, 0, sizeof(saddr));
	sin = &saddr.sin;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	/* Bind a skywalk flow */
	skt_ns_sky_bind(handles, IPPROTO_TCP, sin, FALSE, flow, &bound_port);

	sin6 = &saddr2.sin6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = bound_port;
	sin6->sin6_addr = in6addr_any;

	/* create & bind a BSD socket */
	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	assert(sock >= 0);

	error = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	SKTC_ASSERT_ERR(error == 0);
	/*
	 * BSD bind should fail, if not we will attempt a connect on
	 * IPv4-mapped-IPv6 address which should trip assertion in stack
	 * when it tries to reserve the port in IPv4 domain.
	 */
	error = bind(sock, (struct sockaddr *)sin6, sin6->sin6_len);
	if (error == 0) {
		struct sockaddr_in6     daddr = {
			.sin6_len = sizeof(daddr),
			.sin6_family = AF_INET6,
			.sin6_addr = IN6ADDR_V4MAPPED_INIT,
		};
		uint16_t                dest_port;

		/* add mapped IPv4 address */
		daddr.sin6_addr.__u6_addr.__u6_addr32[3]
		        = handles->netif_addr.s_addr;
		dest_port = ntohs(bound_port);
		if (dest_port == 65535) {
			dest_port--;
		} else {
			dest_port++;
		}
		daddr.sin6_port = htons(dest_port);
		fcntl(sock, F_SETFL, O_NONBLOCK);
		T_LOG(
			"Skywalk: tcp socket connect to %s :%d (mapped)\n",
			inet_ntop(AF_INET6, &daddr.sin6_addr, ntopbuf,
			sizeof(ntopbuf)),
			ntohs(daddr.sin6_port));
		error = connect(sock, (struct sockaddr *)&daddr, sizeof(daddr));
	}
	SKTC_ASSERT_ERR(error != 0);
	memset(&nfr, 0, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow);
	error = __os_nexus_flow_del(handles->controller,
	    handles->fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);
	close(sock);
	T_LOG(" %s done\n", __func__);
}

static void
skt_flowswitch_ns_check_v4mappedv6addr2(struct sktc_nexus_handles *handles)
{
	struct sockaddr_in6     blank_sin6 = {
		.sin6_len = sizeof(blank_sin6),
		.sin6_family = AF_INET6,
	};
	uint16_t                bound_port;
	struct sockaddr_in6     daddr = {
		.sin6_len = sizeof(daddr),
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_V4MAPPED_INIT,
	};
	int                     error;
	uuid_t                  flow;
	int                     lsock;
	struct sockaddr_in6     nam = { 0 };
	socklen_t               nam_len;
	char                    ntopbuf[INET6_ADDRSTRLEN];
	struct sockaddr_in      sin = {
		.sin_len = sizeof(sin),
		.sin_family = AF_INET,
	};
	int                     sock;

	/* create and bind an IPv6 TCP socket */
	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	assert(sock >= 0);
	error = bind(sock, (struct sockaddr *)&blank_sin6, blank_sin6.sin6_len);
	assert(error == 0);

	/* get the port */
	nam_len = sizeof(nam);
	error = getsockname(sock, (struct sockaddr *)&nam, &nam_len);
	assert(error == 0);

	/* bind skywalk flow to same port in IPv4 namespace, this should fail */
	sin.sin_port = nam.sin6_port;
	error = skt_ns_sky_bind(handles, IPPROTO_TCP, &sin,
	    ERROR_FLAGS_NO_ASSERT, flow, &bound_port);
	if (error == 0) {
		/* this shouldn't have worked <rdar://problem/35525592> */
		T_LOG(
			"Binding port %d in skywalk should have failed!\n",
			ntohs(nam.sin6_port));
	}

	/* create and bind a listener socket and get the listening port */
	lsock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	assert(lsock >= 0);
	error = bind(lsock, (struct sockaddr *)&blank_sin6,
	    blank_sin6.sin6_len);
	assert(error == 0);
	error = listen(lsock, 1);
	SKTC_ASSERT_ERR(error == 0);
	nam_len = sizeof(nam);
	error = getsockname(lsock, (struct sockaddr *)&nam, &nam_len);
	assert(error == 0);

	/* connect the socket, will panic without <rdar://problem/35525592> */
	daddr.sin6_addr.__u6_addr.__u6_addr32[3] = handles->netif_addr.s_addr;
	daddr.sin6_port = nam.sin6_port; /* listener port */
	T_LOG("Skywalk: tcp socket connect to %s :%d (mapped)\n",
	    inet_ntop(AF_INET6, &daddr.sin6_addr, ntopbuf, sizeof(ntopbuf)),
	    ntohs(daddr.sin6_port));
	error = connect(sock, (struct sockaddr *)&daddr, sizeof(daddr));
	SKTC_ASSERT_ERR(error == 0);
	close(lsock);
	close(sock);
	T_LOG(" %s done\n", __func__);
}

static int
skt_flowswitch_ns_reserve_main2(int argc, char *argv[])
{
	struct sktc_nexus_handles handles;
	union sockaddr_in_4_6 saddr, saddr2;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	srandomdev();

	sktc_create_flowswitch(&handles, 0);

	/* Use ephemeral port for each step to avoid needing SO_REUSEADDR */

	/* Test IPv4 mapped IPv6 address binding */
	skt_flowswitch_ns_check_v4mappedv6addr(&handles, 0);

	/* Test IPv4-mapped-IPv6 address connect */
	skt_flowswitch_ns_check_v4mappedv6addr2(&handles);

	/* Test TCP IPv4 wildcard */
	memset(&saddr, 0, sizeof(saddr));
	sin = &saddr.sin;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	skt_flowswitch_ns_bsd(&handles, IPPROTO_TCP, sin);
	sin->sin_port = 0;
	skt_flowswitch_ns_sky(&handles, IPPROTO_TCP, sin);

	/* Test TCP IPv4 on feth */
	sin->sin_port = 0;
	sin->sin_addr = handles.netif_addr;
	skt_flowswitch_ns_bsd(&handles, IPPROTO_TCP, sin);
	sin->sin_port = 0;
	skt_flowswitch_ns_sky(&handles, IPPROTO_TCP, sin);

	/* Test TCP IPv6 wildcard */
	memset(&saddr, 0, sizeof(saddr));
	sin6 = &saddr.sin6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;
	memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(sin6->sin6_addr));
	skt_flowswitch_ns_bsd(&handles, IPPROTO_TCP, sin6);

	/* Test TCP IPv4/IPv6 wildcard */
	memset(&saddr, 0, sizeof(saddr));
	sin = &saddr.sin;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	memset(&saddr2, 0, sizeof(saddr2));
	sin6 = &saddr2.sin6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;
	sin6->sin6_addr = in6addr_any;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_TCP, sin, sin6, TRUE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    ERROR_FLAGS_ASSERT_FAILURE,
	    FALSE, TRUE);
	sin->sin_port = 0;
	sin6->sin6_port = 0;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_TCP, sin, sin6, FALSE,
	    ERROR_FLAGS_ASSERT_FAILURE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    FALSE, TRUE);
	sin->sin_port = 0;
	sin6->sin6_port = 0;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_TCP, sin, sin6, TRUE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    TRUE, TRUE);
	sin->sin_port = 0;
	sin6->sin6_port = 0;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_TCP, sin, sin6, FALSE,
	    ERROR_FLAGS_ASSERT_FAILURE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    TRUE, TRUE);

// Need IPv6 link-local support on feth
#if 0
	sin6->sin6_port = htons(port);
	skt_flowswitch_ns_sky(&handles, IPPROTO_TCP, sin6);
	port += 1;

	/* Test TCP IPv6 on feth */
	sin6->sin6_port = htons(port);
	memcpy(&sin6->sin6_addr, &handles->netif_addr6,
	    sizeof(sin6->sin6_addr));
	skt_flowswitch_ns_bsd(&handles, IPPROTO_TCP, sin6);
	port += 1;
	sin6->sin6_port = htons(port);
	skt_flowswitch_ns_sky(&handles, IPPROTO_TCP, sin6);
	port += 1;
#endif

	/* Test UDP IPv4 wildcard */
	memset(&saddr, 0, sizeof(saddr));
	sin = &saddr.sin;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	skt_flowswitch_ns_bsd(&handles, IPPROTO_UDP, sin);
	sin->sin_port = 0;
	skt_flowswitch_ns_sky(&handles, IPPROTO_UDP, sin);

	/* Test UDP IPv4 on feth */
	sin->sin_port = 0;
	sin->sin_addr = handles.netif_addr;
	skt_flowswitch_ns_bsd(&handles, IPPROTO_UDP, sin);
	sin->sin_port = 0;
	skt_flowswitch_ns_sky(&handles, IPPROTO_UDP, sin);

	/* Test UDP IPv6 wildcard */
	memset(&saddr, 0, sizeof(saddr));
	sin6 = &saddr.sin6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;
	memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(sin6->sin6_addr));
	skt_flowswitch_ns_bsd(&handles, IPPROTO_UDP, sin6);

	/* Test UDP IPv4/IPv6 wildcard */
	memset(&saddr, 0, sizeof(saddr));
	sin = &saddr.sin;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	memset(&saddr2, 0, sizeof(saddr2));
	sin6 = &saddr2.sin6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;
	sin6->sin6_addr = in6addr_any;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_UDP, sin, sin6, TRUE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    ERROR_FLAGS_ASSERT_FAILURE,
	    FALSE, TRUE);
	sin->sin_port = 0;
	sin6->sin6_port = 0;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_UDP, sin, sin6, FALSE,
	    ERROR_FLAGS_ASSERT_FAILURE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    FALSE, TRUE);
	sin->sin_port = 0;
	sin6->sin6_port = 0;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_UDP, sin, sin6, TRUE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    TRUE, TRUE);
	sin->sin_port = 0;
	sin6->sin6_port = 0;
	skt_flowswitch_ns_sky_bsd(&handles, IPPROTO_UDP, sin, sin6, FALSE,
	    ERROR_FLAGS_ASSERT_FAILURE,
	    ERROR_FLAGS_ASSERT_SUCCESS,
	    TRUE, TRUE);
// Need IPv6 link-local support on feth
#if 0
	sin6->sin6_port = htons(port);
	skt_flowswitch_ns_sky(&handles, IPPROTO_UDP, sin6);
	port += 1;

	/* Test UDP IPv6 feth */
	sin6->sin6_port = htons(port);
	memcpy(&sin6->sin6_addr, &handles.netif_addr6,
	    sizeof(sin6->sin6_addr));
	skt_flowswitch_ns_bsd(&handles, IPPROTO_UDP, sin6);
	port += 1;
	sin6->sin6_port = htons(port);
	skt_flowswitch_ns_sky(&handles, IPPROTO_UDP, sin6);
#endif

	sktc_cleanup_flowswitch(&handles);

	return 0;
}

#define SKTC_ASSERT_ERR_RETRY(_t, _counter, _retry_label) \
do {    \
	if (!(_t)) {     \
	        T_LOG(\
	            "ERROR: %s:%d " #_t ", retry\n", __FILE__, __LINE__);        \
	        _counter++;     \
	        goto _retry_label;     \
	}       \
} while (0);

#define RETRY_MAX 3

static int
skt_flowswitch_ns_reserve_main(int argc, char *argv[])
{
	char buf0[32], buf1[32];
	size_t retries = 0;
	int error;
	struct sktc_nexus_handles handles;
	struct sktc_nexus_handles handles2;
	uuid_string_t uuidstr;
	struct nx_flow_req nfr;
	uuid_t tcp_flow, udp_flow;

	struct sockaddr_in sa;
	int sock;

	srandomdev();

start:
	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = IPPROTO_TCP;
	nfr.nfr_nx_port = NEXUS_PORT_FLOW_SWITCH_CLIENT; /* first usable */
	nfr.nfr_saddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_saddr.sa.sa_family = AF_INET;
	nfr.nfr_saddr.sin.sin_port = 0; /* pick an ephemeral port */
	nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);

	T_LOG("--Testing with %s port %d\n",
	    (nfr.nfr_ip_protocol == IPPROTO_TCP) ? "tcp" : "udp",
	    ntohs(nfr.nfr_saddr.sin.sin_port));

	/* bind without flow uuid should fail */
	sktc_create_flowswitch(&handles, 0);
	(void) inet_ntop(AF_INET, &handles.netif_addr, buf0, sizeof(buf0));
	T_LOG("On %s (%s), reserve <ANY,%u> through skywalk "
	    "(no flow ID)\n", handles.netif_ifname, buf0,
	    ntohs(nfr.nfr_saddr.sin.sin_port));
	error = __os_nexus_flow_add(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == -1 && errno == EINVAL);

	uuid_generate_random(tcp_flow);
	uuid_generate_random(udp_flow);

	/* bind correctly called should succeed */
	uuid_copy(nfr.nfr_flow_uuid, tcp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s), reserve <ANY,%u> through skywalk "
	    "(flow %s)\n", handles.netif_ifname, buf0,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(!error);
	assert(htonl(INADDR_ANY) == nfr.nfr_saddr.sin.sin_addr.s_addr);

	/* duplicate 2 tuple bind should fail */
	(void) inet_ntop(AF_INET, &handles.netif_addr, buf0, sizeof(buf0));
	(void) inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr,
	    buf1, sizeof(buf1));
	uuid_generate_random(nfr.nfr_flow_uuid);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s), confirm <%s,%u> re-binding fails "
	    "(flow %s)\n", handles.netif_ifname, buf0, buf1,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error != 0 && (errno == EEXIST || errno == EADDRINUSE));

	/* 3 tuple bind sharing the same port should fail */
	nfr.nfr_saddr.sin.sin_addr = handles.netif_addr;
	(void) inet_ntop(AF_INET, &handles.netif_addr, buf0, sizeof(buf0));
	(void) inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr,
	    buf1, sizeof(buf1));
	uuid_generate_random(nfr.nfr_flow_uuid);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s), confirm <%s,%u> re-binding fails "
	    "(flow %s)\n", handles.netif_ifname, buf0, buf1,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error != 0 && (errno == EEXIST || errno == EADDRINUSE));

	/* testing with another fsw */
	/* bind the same port another fsw is not allowed */
	sktc_create_flowswitch(&handles2, 1);
	nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
	(void) inet_ntop(AF_INET, &handles2.netif_addr, buf0, sizeof(buf0));
	(void) inet_ntop(AF_INET, &nfr.nfr_saddr.sin.sin_addr,
	    buf1, sizeof(buf1));
	uuid_copy(nfr.nfr_flow_uuid, tcp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s), confirm <%s,%u> binding is not allowed "
	    "(flow %s)\n", handles2.netif_ifname, buf0, buf1,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles2.controller,
	    handles2.fsw_nx_uuid, &nfr);
	//XXX -- wshen2@apple.com
	// This behavior could change once we add more context(ifnet) into netns
	// so that netns becomes the single arbitrator of port resource across
	// all ifnet. Then we can allow binding of tuple <any_addr, a_port, if1>
	// and <anyaddr, same_port, if2> to go through.
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EEXIST || errno == EADDRINUSE);

	sktc_cleanup_flowswitch(&handles2);

	/* if bound through skywalk, BSD bind should fail */
	T_LOG("Confirm port is unavailable to BSD stack\n");
	sock = socket(PF_INET,
	    (nfr.nfr_ip_protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM,
	    nfr.nfr_ip_protocol);
	assert(sock != -1);

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = nfr.nfr_saddr.sin.sin_port;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(sock, (struct sockaddr *)&sa, sizeof sa);

	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EADDRINUSE);

	/* bind the same port on UDP, should succeed */
	(void) inet_ntop(AF_INET, &handles.netif_addr, buf0, sizeof(buf0));
	nfr.nfr_ip_protocol = INVERT_PROTO(nfr.nfr_ip_protocol);
	nfr.nfr_saddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
	uuid_copy(nfr.nfr_flow_uuid, udp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s) confirm port number %u is available "
	    "on other protocols (flow %s)\n", handles.netif_ifname, buf0,
	    ntohs(nfr.nfr_saddr.sin.sin_port), uuidstr);
	error = __os_nexus_flow_add(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR_RETRY(error == 0, retries, retry);

	/* release the UDP port binding, should succeed */
	uuid_copy(nfr.nfr_flow_uuid, udp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s) release port %u protocol %d (flow %s)\n",
	    handles.netif_ifname, buf0, ntohs(nfr.nfr_saddr.sin.sin_port),
	    nfr.nfr_ip_protocol, uuidstr);
	error = __os_nexus_flow_del(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);

	/* double release the UDP port binding, should fail */
	uuid_copy(nfr.nfr_flow_uuid, udp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s) confirm we can't double-release "
	    "port %u protocol %d (flow %s)\n", handles.netif_ifname, buf0,
	    ntohs(nfr.nfr_saddr.sin.sin_port), nfr.nfr_ip_protocol,
	    uuidstr);
	error = __os_nexus_flow_del(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	//SKTC_ASSERT_ERR(error != 0);

	/* Confirm same UDP port is now available on socket */
	T_LOG("Confirm port %u protocol %d is now available to "
	    "BSD stack\n", ntohs(nfr.nfr_saddr.sin.sin_port),
	    nfr.nfr_ip_protocol);
	sock = socket(PF_INET, (nfr.nfr_ip_protocol == IPPROTO_TCP) ?
	    SOCK_STREAM : SOCK_DGRAM, nfr.nfr_ip_protocol);
	SKTC_ASSERT_ERR_RETRY(sock != -1, retries, retry);

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = nfr.nfr_saddr.sin.sin_port;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	error = bind(sock, (struct sockaddr *)&sa, sizeof sa);
	SKTC_ASSERT_ERR(error == 0);
	close(sock);

	/* release the TCP port skywalk binding */
	nfr.nfr_ip_protocol = INVERT_PROTO(nfr.nfr_ip_protocol);
	uuid_copy(nfr.nfr_flow_uuid, tcp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s) release port %u protocol %d (flow %s)\n",
	    handles.netif_ifname, buf0, ntohs(nfr.nfr_saddr.sin.sin_port),
	    nfr.nfr_ip_protocol, uuidstr);
	error = __os_nexus_flow_del(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);

	/* double release the TCP port binding, should fail */
	uuid_copy(nfr.nfr_flow_uuid, tcp_flow);
	uuid_unparse_upper(nfr.nfr_flow_uuid, uuidstr);
	T_LOG("On %s (%s) confirm we can't double-release "
	    "port %u protocol %d (flow %s)\n", handles.netif_ifname, buf0,
	    ntohs(nfr.nfr_saddr.sin.sin_port), nfr.nfr_ip_protocol,
	    uuidstr);
	error = __os_nexus_flow_del(handles.controller,
	    handles.fsw_nx_uuid, &nfr);
	//SKTC_ASSERT_ERR(error != 0);

	/* Confirm same TCP port is now available on socket */
	T_LOG("Confirm port %u protocol %d is now available to "
	    "BSD stack\n", ntohs(nfr.nfr_saddr.sin.sin_port),
	    nfr.nfr_ip_protocol);
	sock = socket(PF_INET, (nfr.nfr_ip_protocol == IPPROTO_TCP) ?
	    SOCK_STREAM : SOCK_DGRAM, nfr.nfr_ip_protocol);
	SKTC_ASSERT_ERR_RETRY(sock != -1, retries, retry);

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = nfr.nfr_saddr.sin.sin_port;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	error = bind(sock, (struct sockaddr *)&sa, sizeof sa);
	SKTC_ASSERT_ERR(error == 0);

	close(sock);
	retries = 0;
retry:
	sktc_cleanup_flowswitch(&handles);
	if (retries > 0) {
		if (retries < RETRY_MAX) {
			goto start;
		}
		T_LOG("ERROR: exceeds max %d retries\n", RETRY_MAX);
		return -1;
	}
	return 0;
}

#undef SKTC_ASSERT_ERR_RETRY
#undef RETRY_MAX

static void
skt_flowswitch_ns_reserve_main2_init(void)
{
	sktc_ifnet_feth0_1_create();
	sktc_set_tcp_msl(SKT_TCP_MSL_DELAY);
}

static void
skt_flowswitch_ns_reserve_main2_cleanup(void)
{
	sktc_ifnet_feth0_1_destroy();
	sktc_restore_tcp_msl();
}

struct skywalk_test skt_flowswitch_ns_reserve = {
	"flowswitch_ns_reserve", "test confirms that flowswitches can reserve L4 ports",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_flowswitch_ns_reserve_main, { NULL },
	sktc_ifnet_feth0_1_create, sktc_ifnet_feth0_1_destroy,
};

struct skywalk_test skt_flowswitch_ns_reserve2 = {
	"flowswitch_ns_reserve2", "throrough test of netns for both BSD & flowswitch, IPv4/v6",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_flowswitch_ns_reserve_main2, { NULL },
	skt_flowswitch_ns_reserve_main2_init,
	skt_flowswitch_ns_reserve_main2_cleanup,
};

/****************************************************************/
