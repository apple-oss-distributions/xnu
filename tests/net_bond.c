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
 * net_bond.c
 * - test if_bond.c functionality
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
#include <net/if_fake_var.h>
#include <net/if_vlan_var.h>
#include <net/if_bond_var.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <TargetConditionals.h>
#include <darwintest_utils.h>

#include "net_test_lib.h"
#include "inet_transfer.h"
#include "bpflib.h"
#include "in_cksum.h"

#define TEN_NET                 0x0a000000
#define TEN_1_NET               (TEN_NET | 0x010000)

static void
get_ipv4_address(u_int unit, u_int addr_index, struct in_addr *ip)
{
	/* up to 255 units, 255 addresses */
	ip->s_addr = htonl(TEN_1_NET | (unit << 8) | addr_index);
	return;
}

/**
** Test Main
**/
static network_interface_pair           S_bond_pair;
static network_interface_pair_list_t    S_feth_pairs;
static network_interface_pair_list_t    S_vlan_pairs;


#define VLAN_UNIT_START                 200
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

static void
cleanup_common(void)
{
	if (G_debug) {
		T_LOG("Sleeping for 5 seconds\n");
		sleep(5);
	}
	fake_restore_bsd_mode();
	fake_restore_vlan_tagging();
	network_interface_destroy(&S_bond_pair.one);
	network_interface_destroy(&S_bond_pair.two);
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
test_traffic_for_pair(network_interface_pair_t pair, uint8_t af)
{
	inet_address    server;

	T_LOG("Testing %s -> %s\n",
	    pair->one.if_name, pair->two.if_name);
	if (af == AF_INET) {
		server.v4 = pair->one.ip;
	} else {
		server.v6 = pair->one.ip6;
	}
	inet_test_traffic(af, &server, pair->one.if_name, pair->one.if_index,
	    pair->two.if_name, pair->two.if_index);
}

static void
test_traffic_for_af(uint8_t af)
{
	test_traffic_for_pair(&S_bond_pair, af);

	for (u_int i = 0; i < S_vlan_pairs->count; i++) {
		network_interface_pair_t        pair;

		pair = &S_vlan_pairs->list[i];
		test_traffic_for_pair(pair, af);
	}
}

static void
network_interface_init(network_interface_t netif,
    const char * name, unsigned int unit,
    unsigned int address_index)
{
	network_interface_create(netif, name);
	get_ipv4_address(unit, address_index, &netif->ip);
	ifnet_add_ip_address(netif->if_name, netif->ip,
	    inet_class_c_subnet_mask);
	route_add_inet_scoped_subnet(netif->if_name, netif->if_index,
	    netif->ip, inet_class_c_subnet_mask);
}


#define BOND100_NAME    BOND_NAME "100"
#define BOND101_NAME    BOND_NAME "101"

static void
bond_add_member(if_name_t bond, if_name_t member)
{
	struct ifreq            ifr;
	struct if_bond_req      ibr;
	int                     result;
	int                     s = inet_dgram_socket_get();

	bzero(&ibr, sizeof(ibr));
	ibr.ibr_op = IF_BOND_OP_ADD_INTERFACE;
	strlcpy(ibr.ibr_ibru.ibru_if_name, member,
	    sizeof(ibr.ibr_ibru.ibru_if_name));

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, bond, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&ibr;
	result = ioctl(s, SIOCSIFBOND, &ifr);
	T_ASSERT_POSIX_SUCCESS(result, "SIOCSIFBOND(%s) %s",
	    bond, member);
}


static void
initialize_bond_pair(u_int n)
{
	network_interface_t             one;
	network_interface_t             two;
	network_interface_pair_t        scan;

	one = &S_bond_pair.one;
	network_interface_init(one, BOND100_NAME, 0, 1);

	two = &S_bond_pair.two;
	network_interface_init(two, BOND101_NAME, 0, 2);

	S_feth_pairs = network_interface_pair_list_alloc(n);
	scan = S_feth_pairs->list;
	for (size_t i = 0; i < n; i++, scan++) {
		network_interface_create(&scan->one, FETH_NAME);
		bond_add_member(one->if_name, scan->one.if_name);

		network_interface_create(&scan->two, FETH_NAME);
		fake_set_peer(scan->one.if_name, scan->two.if_name);
		bond_add_member(two->if_name, scan->two.if_name);
	}
}


static void
vlan_interface_init(network_interface_t netif, const if_name_t phys,
    const char * name, uint16_t unit,
    unsigned int address_index)
{
	network_interface_init(netif, name, unit, address_index);
	siocsifvlan(netif->if_name, phys, unit);
}

static void
initialize_vlan_pairs(u_int n)
{
	network_interface_pair_t        scan;
	int                             vlan_unit = VLAN_UNIT_START;

	S_vlan_pairs = network_interface_pair_list_alloc(n);
	scan = S_vlan_pairs->list;
	for (size_t i = 0; i < n; i++, scan++) {
		if_name_t       name;
		uint16_t        tag = (uint16_t)(i + 1);

		snprintf(name, sizeof(name), "%s%d", VLAN_NAME, vlan_unit++);
		vlan_interface_init(&scan->one, S_bond_pair.one.if_name,
		    name, tag, 1);
		snprintf(name, sizeof(name), "%s%d", VLAN_NAME, vlan_unit++);
		vlan_interface_init(&scan->two, S_bond_pair.two.if_name,
		    name, tag, 2);
	}
}

static void
bond_test_traffic(bool hw_vlan)
{
#if !TARGET_OS_OSX
	T_SKIP("bond is only available on macOS");
#else /* TARGET_OS_OSX */
	signal(SIGINT, sigint_handler);
	T_ATEND(cleanup);
	T_LOG("Bond test %s\n",
	    hw_vlan ? "hardware tagging" : "software tagging");
	fake_set_bsd_mode(true);
	fake_set_vlan_tagging(hw_vlan);
	initialize_bond_pair(4);
	initialize_vlan_pairs(5);
	test_traffic_for_af(AF_INET6);
	test_traffic_for_af(AF_INET);
	if (G_debug) {
		T_LOG("Sleeping for 5 seconds\n");
		sleep(5);
	}
#endif /* TARGET_OS_OSX */
}

T_DECL(net_if_bond_test_software_tagging,
    "bond test traffic software tagging",
    T_META_ASROOT(true))
{
	bond_test_traffic(false);
}

T_DECL(net_if_bond_test_hardware_tagging,
    "bond test hardware tagging",
    T_META_ASROOT(true))
{
	bond_test_traffic(true);
}
