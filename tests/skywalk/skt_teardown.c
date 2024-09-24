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

/* This test sets up a complicated topology and then tears it down,
 * but allows us to completely permute the teardown sequence
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <darwintest.h>

#include "skywalk_test_common.h"
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"

static int check_failures;
static int print_failures;
static int print_permutation;

/* this could share same logic as SKTC_ASSERT_ERR() */
#define checkerr() do { \
	        if (print_failures && error) {                                                                                                                                                  \
	                SKT_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno); \
	        }                                                                                                                                                                                                                                                                               \
	        if (check_failures) {                                                                                                                                                                                           \
	                assert(!error);                                                                                                                                                                                                         \
	        }                                                                                                                                                                                                                                                                               \
	} while (0)

static void
skt_teardown_pass(int count, int *permute)
{
	int error;
	nexus_controller_t ncd;
	uuid_t feth0_attach, feth1_attach;
	uuid_t ms_provider, ms_instance;
	uuid_t nf_provider, nf_instance0, nf_attach0, nf_instance1, nf_attach1;
	channel_t channel;
	uuid_t flow_id;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	if (print_permutation) {
		static int p = 0;
		T_LOG("permute = {");
		for (int i = 0; i < count; i++) {
			T_LOG(" %d,", permute[i]);
		}
		T_LOG("} (%d)\n", p++);
	}

	uuid_clear(feth0_attach);
	uuid_clear(feth1_attach);
	uuid_clear(ms_provider);
	uuid_clear(ms_instance);
	uuid_clear(nf_provider);
	uuid_clear(nf_instance0);
	uuid_clear(nf_attach0);
	uuid_clear(nf_instance1);
	uuid_clear(nf_attach1);

	ncd = os_nexus_controller_create();
	assert(ncd);

	strncpy((char *)attr.name, "skt_teardown_netif",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_NET_IF;
	attr.anonymous = 1;
	sktc_build_nexus(ncd, &attr, &nf_provider, &nf_instance0);

	uuid_clear(feth0_attach);
	error = __os_nexus_ifattach(ncd, nf_instance0, FETH0_NAME, NULL, false, &feth0_attach);
	//T_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);
	assert(!uuid_is_null(feth0_attach));

	uuid_clear(nf_instance1);
	error = os_nexus_controller_alloc_provider_instance(ncd,
	    nf_provider, &nf_instance1);
	SKTC_ASSERT_ERR(!error);
	assert(!uuid_is_null(nf_instance1));

	uuid_clear(feth1_attach);
	error = __os_nexus_ifattach(ncd, nf_instance1, FETH1_NAME, NULL, false, &feth1_attach);
	SKTC_ASSERT_ERR(!error);
	assert(!uuid_is_null(feth1_attach));

	strncpy((char *)attr.name, "skt_teardown_flowswitch",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_FLOW_SWITCH;
	sktc_build_nexus(ncd, &attr, &ms_provider, &ms_instance);

	uuid_clear(nf_attach0);
	error = __os_nexus_ifattach(ncd, ms_instance, NULL, nf_instance0, false, &nf_attach0);
	//T_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	SKTC_ASSERT_ERR(!error);
	assert(!uuid_is_null(nf_attach0));

	/*
	 * flowswitch doesn't allow opening a channel without a flow bound
	 * to the port.
	 */
	uuid_generate(flow_id);
	error = sktc_bind_tcp4_flow(ncd, ms_instance, 0,
	    NEXUS_PORT_FLOW_SWITCH_CLIENT, flow_id);
	SKTC_ASSERT_ERR(error == 0);

	/* must fail without user packet pool set (flow switch) */
	assert(sktu_channel_create_extended(ms_instance,
	    NEXUS_PORT_FLOW_SWITCH_CLIENT, CHANNEL_DIR_TX_RX,
	    CHANNEL_RING_ID_ANY, NULL, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1) == NULL);

	channel = sktu_channel_create_extended(ms_instance,
	    NEXUS_PORT_FLOW_SWITCH_CLIENT, CHANNEL_DIR_TX_RX,
	    CHANNEL_RING_ID_ANY, NULL, -1, -1, -1, -1, -1, -1, 1, 1, -1, -1);
	assert(channel);

	/* Allow us to permute teardown steps */
	for (int i = 0; i < count; i++) {
		//T_LOG("Count %d step %d\n", i, permute[i]);
		switch (permute[i]) {
		case 8: {
			if (channel) {
				os_channel_destroy(channel);
				channel = NULL;
			}
		} break;
		case 7: {
			error = __os_nexus_ifdetach(ncd, ms_instance, nf_attach0);
			checkerr();
		} break;
		case 6: {
			error = os_nexus_controller_free_provider_instance(ncd, ms_instance);
			checkerr();
		} break;
		case 5: {
			error = os_nexus_controller_deregister_provider(ncd, ms_provider);
			checkerr();
		} break;
		case 4: {
			error = __os_nexus_ifdetach(ncd, nf_instance1, feth1_attach);
			checkerr();
		} break;
		case 3: {
			error = os_nexus_controller_free_provider_instance(ncd, nf_instance1);
			checkerr();
		} break;
		case 2: {
			error = __os_nexus_ifdetach(ncd, nf_instance0, feth0_attach);
			checkerr();
		} break;
		case 1: {
			error = os_nexus_controller_free_provider_instance(ncd, nf_instance0);
			checkerr();
		} break;
		case 0: {
			error = os_nexus_controller_deregister_provider(ncd, nf_provider);
			checkerr();
		} break;
		default:
			assert(0);
		}
	}

	os_nexus_controller_destroy(ncd);
}

static int
skt_teardown_main(int argc, char *argv[])
{
	int permute[9];
	for (int i = 0; i < 9; i++) {
		permute[i] = 8 - i;
	}
	check_failures = 1;
	print_permutation = 1;
	skt_teardown_pass(9, permute);
	return 0;
}

static int
skt_teardownb_main(int argc, char *argv[])
{
	int permute[9];
	for (int i = 0; i < 9; i++) {
		permute[i] = i;
	}
	print_permutation = 1;
	skt_teardown_pass(9, permute);
	return 0;
}

static int
skt_teardownr_main(int argc, char *argv[])
{
	int permute[9];
	for (int i = 0; i < 9; i++) {
		permute[i] = 8 - i;
	}
	//print_permutation = 1;
	permutefuncR(9, permute, skt_teardown_pass, 1000, 0);
	return 0;
}

static int
skt_teardownz_main(int argc, char *argv[])
{
	int permute[9];
	for (int i = 0; i < 9; i++) {
		permute[i] = 8 - i;
	}
	//print_permutation = 1;
	//print_failures = 1;
	permutefuncZ(9, permute, skt_teardown_pass);
	return 0;
}

struct skywalk_test skt_teardown = {
	"teardown", "setup complicated topology tear it down",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_teardown_main, { NULL },
	sktc_ifnet_feth0_1_create, sktc_ifnet_feth0_1_destroy,
};

struct skywalk_test skt_teardownb = {
	"teardownb", "setup complicated topology tear it down backwards",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_teardownb_main, { NULL },
	sktc_ifnet_feth0_1_create, sktc_ifnet_feth0_1_destroy,
};

struct skywalk_test skt_teardownr = {
	"teardownr", "setup complicated topology tear it down randomly (1000 iterations)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_teardownr_main, { NULL },
	sktc_ifnet_feth0_1_create, sktc_ifnet_feth0_1_destroy,
};

struct skywalk_test skt_teardownz = {
	"teardownz", "setup complicated topology tear it down with each stage in an out of order position",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_teardownz_main, { NULL },
	sktc_ifnet_feth0_1_create, sktc_ifnet_feth0_1_destroy,
};
