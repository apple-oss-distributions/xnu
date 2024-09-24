/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

#define TEST_LPORT 12345
#define TEST_RPORT 45678
#define TEST_QSET_ID 0x0001

static void
fill_traffic_descriptor_v4(struct ifnet_traffic_descriptor_inet *td)
{
	struct in_addr feth0_addr, feth1_addr;

	bzero(td, sizeof(*td));

	td->inet_common.itd_type = IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET;
	td->inet_common.itd_len = sizeof(*td);
	td->inet_common.itd_flags = IFNET_TRAFFIC_DESCRIPTOR_FLAG_INBOUND |
	    IFNET_TRAFFIC_DESCRIPTOR_FLAG_OUTBOUND;

	td->inet_mask = IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT;

	td->inet_ipver = IPVERSION;
	td->inet_proto = IPPROTO_TCP;

	feth0_addr = sktc_feth0_in_addr();
	td->inet_laddr.iia_v4addr = feth0_addr.s_addr;
	feth1_addr = sktc_feth1_in_addr();
	td->inet_raddr.iia_v4addr = feth1_addr.s_addr;

	td->inet_lport = htons(TEST_LPORT);
	td->inet_rport = htons(TEST_RPORT);
}

static void
fill_traffic_descriptor_v6(struct ifnet_traffic_descriptor_inet *td)
{
	bzero(td, sizeof(*td));

	td->inet_common.itd_type = IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET;
	td->inet_common.itd_len = sizeof(*td);
	td->inet_common.itd_flags = IFNET_TRAFFIC_DESCRIPTOR_FLAG_INBOUND |
	    IFNET_TRAFFIC_DESCRIPTOR_FLAG_OUTBOUND;

	td->inet_mask = IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT |
	    IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT;

	td->inet_ipver = IPV6_VERSION;
	td->inet_proto = IPPROTO_TCP;

	sktc_feth0_inet6_addr((in6_addr_t *)&td->inet_laddr);
	sktc_feth1_inet6_addr((in6_addr_t *)&td->inet_raddr);
	td->inet_lport = htons(TEST_LPORT);
	td->inet_rport = htons(TEST_RPORT);
}

static void
fill_traffic_rule_action(struct ifnet_traffic_rule_action_steer *ra)
{
	bzero(ra, sizeof(*ra));

	ra->ras_common.ra_type = IFNET_TRAFFIC_RULE_ACTION_STEER;
	ra->ras_common.ra_len = sizeof(*ra);
	ra->ras_qset_id = TEST_QSET_ID;
}

static int
skt_steering_main(int argc, char *argv[])
{
	nexus_controller_t ctl;
	struct ifnet_traffic_descriptor_inet td;
	struct ifnet_traffic_rule_action_steer ra;
	uuid_t v4_rule, v6_rule;
	int err;

	ctl = os_nexus_controller_create();
	assert(ctl != NULL);

	fill_traffic_rule_action(&ra);

	fill_traffic_descriptor_v4(&td);
	err = os_nexus_controller_add_traffic_rule(ctl, FETH0_NAME,
	    (struct ifnet_traffic_descriptor_common *)&td,
	    (struct ifnet_traffic_rule_action *)&ra, 0, &v4_rule);
	assert(err == 0);

	fill_traffic_descriptor_v6(&td);
	err = os_nexus_controller_add_traffic_rule(ctl, FETH0_NAME,
	    (struct ifnet_traffic_descriptor_common *)&td,
	    (struct ifnet_traffic_rule_action *)&ra, 0, &v6_rule);
	assert(err == 0);

	err = os_nexus_controller_remove_traffic_rule(ctl, v4_rule);
	assert(err == 0);

	err = os_nexus_controller_remove_traffic_rule(ctl, v6_rule);
	assert(err == 0);

	os_nexus_controller_destroy(ctl);
	return 0;
}

static uint32_t skt_netif_nxctl_check;
static void
skt_steering_init(void)
{
	uint32_t nxctl_check = 1;
	size_t len = sizeof(skt_netif_nxctl_check);

	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_netif_nxctl_check, &len, &nxctl_check,
	    sizeof(nxctl_check)) == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE |
	    FETH_FLAGS_NXATTACH);
}

static void
skt_steering_fini(void)
{
	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    NULL, NULL, &skt_netif_nxctl_check,
	    sizeof(skt_netif_nxctl_check)) == 0);
	sktc_ifnet_feth_pair_destroy();
}

struct skywalk_test skt_steering = {
	"steering",
	"steering rules test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	skt_steering_main,
	{ NULL },
	skt_steering_init, skt_steering_fini,
};
