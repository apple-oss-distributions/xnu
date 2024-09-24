/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
 * net_vlan.c
 * - test if_vlan.c functionality
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
#include <net/if_vlan_var.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <TargetConditionals.h>
#include <darwintest_utils.h>
#include <os/variant_private.h>

#include "net_test_lib.h"
#include "inet_transfer.h"
#include "bpflib.h"
#include "in_cksum.h"

#define VLAN_UNIT_START         200 /* start at vlan200 to avoid conflicts */
#define TEN_NET                 0x0a000000
#define TEN_1_NET               (TEN_NET | 0x010000)
#define VLAN_TAG_START          1

static void
get_ipv4_address(u_int unit, u_int addr_index, struct in_addr *ip)
{
	/* up to 255 units, 255 addresses */
	ip->s_addr = htonl(TEN_1_NET | (unit << 8) | addr_index);
	return;
}

/**
** interface management
**/

/**
** Test Main
**/
static network_interface_pair_list_t    S_feth_pairs;
static network_interface_pair_list_t    S_vlan_pairs;
static const char *                     S_bridge;

#define VLAN_SYSCTL                     "net.link.vlan"
#define VLAN_SYSCTL_ENABLED             VLAN_SYSCTL ".enabled"

#define FAKE_SYSCTL                     "net.link.fake"
#define FAKE_SYSCTL_BSD_MODE            FAKE_SYSCTL ".bsd_mode"
#define FAKE_SYSCTL_VLAN_TAGGING        FAKE_SYSCTL ".vlan_tagging"

static int fake_bsd_mode;
static bool fake_bsd_mode_was_set;
static int fake_vlan_tagging;
static bool fake_vlan_tagging_was_set;

static void
sysctl_set_integer(const char * name, int val, int * restore_val,
    bool * was_set)
{
	int     error;
	size_t  len;

	T_LOG("%s\n", __func__);
	len = sizeof(int);
	error = sysctlbyname(name, restore_val, &len, &val, sizeof(int));
	T_ASSERT_EQ(error, 0, "sysctl %s %d -> %d", name, *restore_val, val);
	*was_set = (*restore_val != val);
}

static void
sysctl_restore_integer(const char * name, int restore_val, bool was_set)
{
	if (was_set) {
		int     error;

		error = sysctlbyname(name, NULL, 0, &restore_val, sizeof(int));
		T_ASSERT_EQ(error, 0, "sysctl %s %d", name, restore_val);
	} else {
		T_LOG("sysctl %s not modified", name);
	}
}

static void
fake_set_bsd_mode(bool enable)
{
	sysctl_set_integer(FAKE_SYSCTL_BSD_MODE, enable ? 1 : 0,
	    &fake_bsd_mode, &fake_bsd_mode_was_set);
}

static void
fake_restore_bsd_mode(void)
{
	sysctl_restore_integer(FAKE_SYSCTL_BSD_MODE,
	    fake_bsd_mode, fake_bsd_mode_was_set);
}

static void
fake_set_vlan_tagging(bool enable)
{
	sysctl_set_integer(FAKE_SYSCTL_VLAN_TAGGING, enable ? 1 : 0,
	    &fake_vlan_tagging, &fake_vlan_tagging_was_set);
}

static void
fake_restore_vlan_tagging(void)
{
	sysctl_restore_integer(FAKE_SYSCTL_VLAN_TAGGING, fake_vlan_tagging,
	    fake_vlan_tagging_was_set);
}

#if !TARGET_OS_BRIDGE
#if !TARGET_OS_OSX
static bool
vlan_is_enabled(void)
{
	size_t  len = sizeof(int);
	int     val = 0;

	(void)sysctlbyname(VLAN_SYSCTL_ENABLED, &val, &len, NULL, 0);
	return val != 0;
}
#endif /* !TARGET_OS_OSX */
#endif /* !TARGET_OS_BRIDGE */

static void
cleanup_common(void)
{
	if (G_debug) {
		T_LOG("Sleeping for 5 seconds\n");
		sleep(5);
	}
	if (S_bridge != NULL) {
		ifnet_destroy(S_bridge, false);
	}
	fake_restore_bsd_mode();
	fake_restore_vlan_tagging();
	network_interface_pair_list_destroy(S_feth_pairs);
	network_interface_pair_list_destroy(S_vlan_pairs);
	return;
}

static void
cleanup(void)
{
	cleanup_common();
	return;
}

static void
sigint_handler(__unused int sig)
{
	cleanup_common();
	signal(SIGINT, SIG_DFL);
}

static void
test_traffic_for_network_interfaces(network_interface_t one,
    network_interface_t two,
    uint8_t af)
{
	inet_address    server;

	T_LOG("Testing %s -> %s\n",
	    one->if_name, two->if_name);
	if (af == AF_INET) {
		server.v4 = one->ip;
	} else {
		server.v6 = two->ip6;
	}
	inet_test_traffic(af, &server, one->if_name, one->if_index,
	    two->if_name, two->if_index);
}

static void
test_traffic_for_pair(network_interface_pair_t pair, uint8_t af)
{
	test_traffic_for_network_interfaces(&pair->one, &pair->two, af);
}

static void
test_traffic_for_af(uint8_t af)
{
	test_traffic_for_pair(S_feth_pairs->list, af);

	for (u_int i = 0; i < S_vlan_pairs->count; i++) {
		network_interface_pair_t        pair;

		pair = &S_vlan_pairs->list[i];
		test_traffic_for_pair(pair, af);
	}
}

static void
network_interface_assign_address(network_interface_t netif,
    unsigned int unit, unsigned int address_index)
{
	get_ipv4_address(unit, address_index, &netif->ip);
	ifnet_add_ip_address(netif->if_name, netif->ip,
	    inet_class_c_subnet_mask);
	route_add_inet_scoped_subnet(netif->if_name, netif->if_index,
	    netif->ip, inet_class_c_subnet_mask);
}

static void
initialize_feth_pairs(u_int n, bool need_address)
{
	network_interface_pair_t        scan;

	S_feth_pairs = network_interface_pair_list_alloc(n);
	scan = S_feth_pairs->list;
	for (unsigned int i = 0; i < n; i++, scan++) {
		network_interface_create(&scan->one, FETH_NAME);
		network_interface_create(&scan->two, FETH_NAME);
		if (need_address) {
			network_interface_assign_address(&scan->one, i, 1);
			network_interface_assign_address(&scan->two, i, 2);
		}
		fake_set_peer(scan->one.if_name, scan->two.if_name);
	}
}

static void
initialize_vlan_pairs(u_int n, bool need_address)
{
	network_interface_pair_t        feth_pair;
	network_interface_pair_t        scan;
	int                             vlan_unit = VLAN_UNIT_START;

	feth_pair = S_feth_pairs->list;
	S_vlan_pairs = network_interface_pair_list_alloc(n);
	scan = S_vlan_pairs->list;
	for (size_t i = 0; i < n; i++, scan++) {
		if_name_t       name;
		uint16_t        tag = (uint16_t)(i + VLAN_TAG_START);

		snprintf(name, sizeof(name), "%s%d", VLAN_NAME, vlan_unit++);
		network_interface_create(&scan->one, name);
		siocsifvlan(scan->one.if_name, feth_pair->one.if_name, tag);
		if (need_address) {
			network_interface_assign_address(&scan->one, tag, 1);
		}

		snprintf(name, sizeof(name), "%s%d", VLAN_NAME, vlan_unit++);
		network_interface_create(&scan->two, name);
		siocsifvlan(scan->two.if_name, feth_pair->two.if_name, tag);
		if (need_address) {
			network_interface_assign_address(&scan->two, tag, 2);
		}
	}
}

static void
vlan_send_short_packet(void)
{
	ether_addr_t                    eaddr;
	struct ether_vlan_header *      evl_p;
	int                             fd;
	size_t                          frame_length;
	const char *                    ifname;
	uint16_t *                      length;
	uint8_t *                       data;
	ssize_t                         n;
	int                             opt;
	ether_packet                    pkt;

	ifname = S_feth_pairs->list->one.if_name;
	fd = bpf_new();
	T_ASSERT_GE(fd, 0, "bpf_new() %d", fd);
	bpf_set_traffic_class(fd, SO_TC_CTL);
	opt = 1;
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ioctl(fd, FIONBIO, &opt), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(fd, 1), NULL);
	T_ASSERT_POSIX_SUCCESS(bpf_setif(fd, ifname), "bpf set if %s",
	    ifname);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(fd, 0), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(bpf_set_header_complete(fd, 1), NULL);
	T_QUIET;
	ifnet_get_lladdr(ifname, &eaddr);

#define VLAN_SHORT_PAYLOAD_LENGTH       6
	/* send broadcast 802.3 LLC frame of length 6 (rdar://129012466) */
	bzero(&pkt, sizeof(pkt));
	frame_length = sizeof(*evl_p) + VLAN_SHORT_PAYLOAD_LENGTH;
	evl_p = (struct ether_vlan_header *)&pkt;
	bcopy(&ether_broadcast, evl_p->evl_dhost, sizeof(evl_p->evl_dhost));
	bcopy(&eaddr, evl_p->evl_shost, sizeof(evl_p->evl_shost));
	evl_p->evl_tag = htons(VLAN_TAG_START);
	evl_p->evl_encap_proto = htons(ETHERTYPE_VLAN);
	length = (uint16_t *)&evl_p->evl_proto;
	*length = htons(VLAN_SHORT_PAYLOAD_LENGTH);
	/* make it an LLC frame so that it will decode as a valid packet */
	data = (uint8_t *)(length + 1);
	*data++ = 0x00;
	*data++ = 0x0a;
	*data++ = 0x00;
	*data++ = 0x06;
	*data++ = 0x00;
	*data++ = 0x01;
	n = write(fd, &pkt, frame_length);
	T_ASSERT_EQ((size_t)n, frame_length, "write");
	close(fd);
}

static void
vlan_test_check_skip(void)
{
#if TARGET_OS_BRIDGE
	T_SKIP("Skipping test on bridgeOS");
#else /* TARGET_OS_BRIDGE */
#if !TARGET_OS_OSX
#define XNU_TEST_NET_VLAN       "com.apple.xnu.test.net_vlan"
	if (!vlan_is_enabled()) {
		if (os_variant_is_darwinos(XNU_TEST_NET_VLAN)) {
			T_FAIL("darwinos should support VLAN");
		}
		if (os_variant_has_factory_content(XNU_TEST_NET_VLAN)) {
			T_FAIL("non-ui should support VLAN");
		}
		T_SKIP("VLAN is not available on this os variant");
	}
#endif /* !TARGET_OS_OSX */
#endif /* TARGET_OS_BRIDGE */
}


static void
vlan_test_traffic(bool hw_vlan)
{
	vlan_test_check_skip();

	signal(SIGINT, sigint_handler);
	T_ATEND(cleanup);
	T_LOG("VLAN test %s\n",
	    hw_vlan ? "hardware tagging" : "software tagging");
	fake_set_bsd_mode(true);
	fake_set_vlan_tagging(hw_vlan);
	initialize_feth_pairs(1, true);
	initialize_vlan_pairs(5, true);
	test_traffic_for_af(AF_INET6);
	test_traffic_for_af(AF_INET);
	if (G_debug) {
		T_LOG("Sleeping for 5 seconds\n");
		sleep(5);
	}
}

static void
vlan_test_bridged_traffic(bool hw_vlan)
{
	errno_t                         err;
	network_interface_pair_t        feth_pair;
	network_interface_pair_t        vlan_pair;

	vlan_test_check_skip();

	signal(SIGINT, sigint_handler);
	T_ATEND(cleanup);
	T_LOG("VLAN test bridged %s\n",
	    hw_vlan ? "hardware tagging" : "software tagging");
	fake_set_bsd_mode(true);
	fake_set_vlan_tagging(hw_vlan);
	initialize_feth_pairs(2, false);
	initialize_vlan_pairs(1, false);

	/* get the single VLAN pair */
	vlan_pair = S_vlan_pairs->list;

	/* get the second FETH pair */
	feth_pair = S_feth_pairs->list + 1;

	/* create a bridge */
	S_bridge = BRIDGE200;
	err = ifnet_create(S_bridge);
	T_ASSERT_EQ(err, 0, "ifnet_create %s", S_bridge);

	/* add first VLAN to bridge */
	err = bridge_add_member(S_bridge, vlan_pair->one.if_name);
	T_ASSERT_EQ(err, 0, "bridge_add_member(%s, %s)", S_bridge,
	    vlan_pair->one.if_name);

	/* assign address to second VLAN */
	network_interface_assign_address(&vlan_pair->two, 0, 1);

	/* add feth in second pair to bridge */
	err = bridge_add_member(S_bridge, feth_pair->one.if_name);
	T_ASSERT_EQ(err, 0, "bridge_add_member(%s, %s)", S_bridge,
	    feth_pair->one.if_name);

	/* assign address to second feth in second pair */
	network_interface_assign_address(&feth_pair->two, 0, 2);

	test_traffic_for_network_interfaces(&vlan_pair->two, &feth_pair->two,
	    AF_INET);
	test_traffic_for_network_interfaces(&vlan_pair->two, &feth_pair->two,
	    AF_INET6);
}

static void
vlan_test_short_packet(void)
{
	vlan_test_check_skip();

	signal(SIGINT, sigint_handler);
	T_ATEND(cleanup);
	T_LOG("VLAN test short packet\n");
	fake_set_bsd_mode(true);
	fake_set_vlan_tagging(false);

	initialize_feth_pairs(1, true);
	initialize_vlan_pairs(1, true);
	/* send VLAN packet over feth */
	vlan_send_short_packet();
	if (G_debug) {
		T_LOG("Sleeping for 5 seconds\n");
		sleep(5);
	}
}

T_DECL(net_if_vlan_test_software_tagging,
    "vlan test traffic software tagging",
    T_META_ASROOT(true))
{
	vlan_test_traffic(false);
}

T_DECL(net_if_vlan_test_hardware_tagging,
    "vlan test hardware tagging",
    T_META_ASROOT(true))
{
	vlan_test_traffic(true);
}

T_DECL(net_if_vlan_test_software_tagging_bridged,
    "vlan test traffic software tagging bridged",
    T_META_ASROOT(true))
{
	vlan_test_bridged_traffic(false);
}

T_DECL(net_if_vlan_test_hardware_tagging_bridged,
    "vlan test hardware tagging bridged",
    T_META_ASROOT(true))
{
	vlan_test_bridged_traffic(true);
}

T_DECL(net_if_vlan_test_short_packet,
    "vlan test short packet",
    T_META_ASROOT(true))
{
	vlan_test_short_packet();
}
