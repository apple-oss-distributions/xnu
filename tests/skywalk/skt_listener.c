/*
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
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
 * TODO: change the setup using two back-to-back feths (once ready) so we can
 * actually create some connected flows.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

const char * ifname;
struct in_addr our_ip, our_mask, peer_ip, zero_ip;
struct in6_addr zero_ip6;
struct sktc_nexus_handles handles;
uint16_t our_port;
uint16_t peer_port_1 = 8080;
uint16_t peer_port_2 = 8081;
nexus_port_t nx_port = 2;
int sock;
char sa_buf[128];
char flow_buf[128];

void
skt_listener_test_socket_listen(bool expect_success,
    struct in_addr *sip, in_port_t *sport)
{
	struct sockaddr_in listener_addr;
	int error;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	assert(sock >= 0);

	bzero((char *) &listener_addr, sizeof(listener_addr));
	listener_addr.sin_family = AF_INET;
	listener_addr.sin_addr = *sip;
	listener_addr.sin_port = htons(*sport);

	error = bind(sock, (struct sockaddr *)&listener_addr,
	    sizeof(listener_addr));

	if (!expect_success) {
		SKTC_ASSERT_ERR(error);
		return;
	}

	SKTC_ASSERT_ERR(!error);

	socklen_t addrLen = sizeof(listener_addr);
	error = getsockname(sock, (struct sockaddr *)&listener_addr, &addrLen);
	SKTC_ASSERT_ERR(!error);
	if (*sport == 0) {
		*sport = ntohs(listener_addr.sin_port);
	}

	return;
}

void
skt_listener_cleanup(uuid_t flow_id)
{
	struct nx_flow_req nfr;
	int error;

	memset(&nfr, 0, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_id);

	error = __os_nexus_flow_del(handles.controller, handles.fsw_nx_uuid,
	    &nfr);
	SKTC_ASSERT_ERR(!error);
}

int
skt_listener_main(int argc, char *argv[])
{
	struct sktu_flow *listener, *connection_1, *connection_2, *no_flow;
	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	peer_ip = sktc_feth1_in_addr();
	zero_ip.s_addr = htonl(INADDR_ANY);
	memset(&zero_ip6, 0, sizeof(zero_ip6));

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	/**********************************************************************/
	T_LOG("\nScenario 1. Starting with 2-tuple listener flow\n");

	/* SUCCESS: test creating a listener flow (let netns picks a ephemeral port for us)*/
	listener = sktu_create_nexus_flow(&handles, AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, 0, 0);
	assert(listener);

	our_port = ntohs(listener->nfr.nfr_saddr.sin.sin_port);

	/* FAILURE: try add duplicate 2-tuple listener flow (with same lport) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* FAILURE: try add duplicate 3-tuple listener flow (with same lport) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* test listening on BSD socket (on same port) */
	skt_listener_test_socket_listen(false, &zero_ip, &our_port);
	inet_ntop(AF_INET, &zero_ip.s_addr, sa_buf, sizeof(sa_buf));
	T_LOG("Rej socket bind tcp %s:%d\n", sa_buf, our_port);

	skt_listener_test_socket_listen(false, &our_ip, &our_port);
	inet_ntop(AF_INET, &our_ip.s_addr, sa_buf, sizeof(sa_buf));
	T_LOG("Rej socket bind tcp %s:%d\n", sa_buf, our_port);

	/* test connecting a new flow off the listener flow - 1 */
	connection_1 = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_1);
	assert(connection_1);

	/* test connecting a new flow off the listener flow - 2 */
	connection_2 = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_2);

	/* test connecting a duplicate connected flow off the listener flow */
	/* test connecting a new flow off the listener flow - 2 */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_2);
	assert(!no_flow);

	/* clean up */
	sktu_destroy_nexus_flow(listener);
	sktu_destroy_nexus_flow(connection_1);
	sktu_destroy_nexus_flow(connection_2);

	/**********************************************************************/
	T_LOG("\nScenario 2. Starting with 3-tuple listener flow\n");

	/* try add 3-tuple listener flow (with specified laddr) */
	listener = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &zero_ip, IPPROTO_TCP, 0, 0);
	assert(listener);

	our_port = ntohs(listener->nfr.nfr_saddr.sin.sin_port);

	/* try add duplicate 2-tuple listener flow (with same lport) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* test binding on BSD socket (on same port) */
	inet_ntop(AF_INET, &zero_ip.s_addr, sa_buf, sizeof(sa_buf));
	T_LOG("Rej socket bind tcp %s:%d\n", sa_buf, our_port);
	skt_listener_test_socket_listen(false, &zero_ip, &our_port);

	inet_ntop(AF_INET, &our_ip.s_addr, sa_buf, sizeof(sa_buf));
	T_LOG("Rej socket bind tcp %s:%d\n", sa_buf, our_port);
	skt_listener_test_socket_listen(false, &our_ip, &our_port);

	/* test connecting a new flow off the listener flow - 1 */
	connection_1 = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_1);
	assert(connection_1);

	/* test connecting a new flow off the listener flow - 2 */
	connection_2 = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_2);
	assert(connection_2);

	/* test connecting a duplicate connected flow off the listener flow */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_2);
	assert(!no_flow);

	/* clean up */
	sktu_destroy_nexus_flow(listener);
	sktu_destroy_nexus_flow(connection_1);
	sktu_destroy_nexus_flow(connection_2);

	/**********************************************************************/
	T_LOG("\nScenario 3. Starting with 5-tuple connected flow\n");

	/* test connecting a new connected flow */
	connection_1 = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, 0, peer_port_1);
	assert(connection_1);

	our_port = ntohs(connection_1->nfr.nfr_saddr.sin.sin_port);

	/* try add conflicting 2-tuple listener flow (with same lport ) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* try add conflicting 3-tuple listener flow (with same lport) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* test listening on BSD socket (on same port) */
	inet_ntop(AF_INET, &zero_ip.s_addr, sa_buf, sizeof(sa_buf));
	T_LOG("Rej socket bind tcp %s:%d\n", sa_buf, our_port);
	skt_listener_test_socket_listen(false, &zero_ip, &our_port);

	inet_ntop(AF_INET, &our_ip.s_addr, sa_buf, sizeof(sa_buf));
	T_LOG("Rej socket bind tcp %s:%d\n", sa_buf, our_port);
	skt_listener_test_socket_listen(false, &our_ip, &our_port);

	/* clean up */
	sktu_destroy_nexus_flow(connection_1);


	/**********************************************************************/
	T_LOG("\nScenario 4. v4/v6 Compatibility\n");
	/* test creating a v6 listener flow */
	listener = sktu_create_nexus_flow(&handles, AF_INET6, &zero_ip6, &zero_ip6, IPPROTO_TCP, 0, 0);
	assert(listener);

	our_port = ntohs(listener->nfr.nfr_saddr.sin.sin_port);

	/* test connecting a new v4 flow off the listener flow - 1 */
	connection_1 = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_1);
	assert(connection_1);

	/* clean up */
	sktu_destroy_nexus_flow(listener);
	sktu_destroy_nexus_flow(connection_1);


	/**********************************************************************/
	T_LOG("\nScenario 5. Starting with BSD socket\n");

	/* test listening on BSD socket */
	our_port = 0;
	inet_ntop(AF_INET, &our_ip.s_addr, sa_buf, sizeof(sa_buf));
	skt_listener_test_socket_listen(true, &our_ip, &our_port);
	T_LOG("Add socket bind tcp %s:%d\n", sa_buf, our_port);

	/* try add conflicting 2-tuple listener flow (with same lport ) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* try add conflicting 3-tuple listener flow (with same lport) */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &zero_ip, IPPROTO_TCP, our_port, 0);
	assert(!no_flow);

	/* try add connecting a skywalk flow off the BSD listener flow */
	no_flow = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, peer_port_1);
	assert(!no_flow);

	close(sock);

	/**********************************************************************/
	sktc_cleanup_flowswitch(&handles);

	return 0;
}

int
skt_listener_stress_main(int argc, char *argv[])
{
	struct sktu_flow *listener, *flows[511];
	int i;

	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	peer_ip = sktc_feth1_in_addr();
	zero_ip.s_addr = htonl(INADDR_ANY);

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	/**********************************************************************/
	T_LOG("\nScenario 1. Starting with 2-tuple listener flow\n");

	/* test creating a listener flow (let netns picks a ephemeral port for us)*/
	listener = sktu_create_nexus_flow(&handles, AF_INET, &zero_ip, &zero_ip, IPPROTO_TCP, 0, 0);
	assert(listener);

	/* stress connecting new flows off the listener flow */
	uint16_t our_port = ntohs(listener->nfr.nfr_saddr.sin.sin_port);
	/* count 511 due to (512 flowadv limit 512) - (1 listener flow) */
	for (i = 0; i < 511; i++) {
		flows[i] = sktu_create_nexus_flow(&handles, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, 10000 + i);
		assert(flows[i]);
	}

	return 0;
}

int
skt_listen_stress_main(int argc, char *argv[])
{
#define LISTEN_MAX INT16_MAX /* might exhaust socache zone due to late cache purge */
	for (int i = 0; i < LISTEN_MAX; i++) {
		struct sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		in_port_t last_port = 0;

		int listener = socket(AF_INET, SOCK_STREAM, 0);

		int error = bind(listener, (struct sockaddr *)&addr, sizeof(addr));
		if (error == 0) {
			error = listen(listener, 5);
			if (error == 0) {
				socklen_t size = sizeof(addr);
				getsockname(listener, (struct sockaddr *)&addr, &size);
				last_port = ntohs(addr.sin_port);
			} else {
				T_LOG("listen failed (last port %d)\n", last_port);
				SKTC_ASSERT_ERR(error);
			}
		} else {
			T_LOG("bind failed\n");
			SKTC_ASSERT_ERR(error);
		}

		close(listener);
	}
	return 0;
#undef LISTEN_MAX
}

int
skt_listener_reuse_main(int argc, char *argv[])
{
	ifname = FETH0_NAME;
	our_mask = sktc_make_in_addr(IN_CLASSC_NET);
	our_ip = sktc_feth0_in_addr();
	peer_ip = sktc_feth1_in_addr();
	zero_ip = (struct in_addr){.s_addr = htonl(INADDR_ANY)};
	bzero(&zero_ip6, sizeof(zero_ip6));

	bzero(&handles, sizeof(handles));
	strlcpy(handles.netif_ifname, ifname, sizeof(handles.netif_ifname));
	handles.netif_addr = our_ip;
	handles.netif_mask = our_mask;
	sktc_create_flowswitch_no_address(&handles, -1, -1, -1, -1, 0);

	struct sktu_flow *listener, *connection, *dup_listener;

	// 2 tuple TCP listener
	listener = _sktu_create_nexus_flow(&handles, NEXUS_PORT_ANY, AF_INET6, &zero_ip6, &zero_ip6, IPPROTO_TCP, 0, 0, NXFLOWREQF_REUSEPORT);
	assert(listener);

	our_port = ntohs(listener->nfr.nfr_saddr.sin.sin_port);

	// dup listen should fail
	dup_listener = _sktu_create_nexus_flow(&handles, NEXUS_PORT_ANY, AF_INET6, &zero_ip6, &zero_ip6, IPPROTO_TCP, our_port, 0, NXFLOWREQF_REUSEPORT);
	assert(!dup_listener);

	// 5 tuple TCP connection from listener
	connection = _sktu_create_nexus_flow(&handles, NEXUS_PORT_ANY, AF_INET, &our_ip, &peer_ip, IPPROTO_TCP, our_port, our_port, NXFLOWREQF_REUSEPORT);
	assert(connection);

	// kill listener
	sktu_destroy_nexus_flow(listener);

	// sock listener should fail(skywalk listener port could only be reused by skywalk)
	skt_listener_test_socket_listen(false, &zero_ip, &our_port);
	T_LOG("socket listener failed as expected\n");

	// restart listener
	listener = sktu_create_nexus_flow(&handles, AF_INET6, &zero_ip6, &zero_ip6, IPPROTO_TCP, our_port, 0);
	assert(listener);

	sktu_destroy_nexus_flow(listener);
	sktu_destroy_nexus_flow(connection);
	sktc_cleanup_flowswitch(&handles);

	return 0;
}

void
skt_listener_net_init(void)
{
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART);
}

void
skt_listener_net_fini(void)
{
	sktc_ifnet_feth_pair_destroy();
}

struct skywalk_test skt_listener = {
	"listener", "test skywalk listener flow creation check",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_listener_main, { NULL },
	skt_listener_net_init, skt_listener_net_fini,
};

struct skywalk_test skt_listen_stress = {
	"listen_stress", "stress posix socket listen",
	SK_FEATURE_SKYWALK | SK_FEATURE_NETNS,
	skt_listen_stress_main, { NULL },
	NULL, NULL,
};

struct skywalk_test skt_listener_stress = {
	"listener_stress", "stress skywalk listener flows",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_listener_stress_main, { NULL },
	skt_listener_net_init, skt_listener_net_fini,
};

struct skywalk_test skt_listener_reuse = {
	"listener_reuse", "test skywalk listener reuse",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_listener_reuse_main, { NULL },
	skt_listener_net_init, skt_listener_net_fini,
};
