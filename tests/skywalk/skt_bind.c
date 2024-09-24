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

/*
 * This test exercises nexus port binding.
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

#define NRINGS  2

static channel_t ch00, ch01;    /* ch0 ring 0,1 */
static channel_t ch10, ch11;    /* ch1 ring 0,1 */
static channel_attr_t attr0, attr1;
static uuid_t key0, key1;
static uuid_t netif_provider, netif_instance, netif_attach;

static void
skt_bind_init(const char *name, nexus_type_t type, int anon, int add_netif)
{
	int error;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, name, sizeof(nexus_name_t) - 1);
	attr.type = type;
	attr.ntxrings = NRINGS;
	attr.nrxrings = NRINGS;
	attr.anonymous = anon;

	sktc_setup_nexus(&attr);

	assert(uuid_is_null(netif_provider));
	assert(uuid_is_null(netif_instance));
	assert(uuid_is_null(netif_attach));
	if (add_netif) {
		strncpy((char *)attr.name, "skt_netif_feth0",
		    sizeof(nexus_name_t) - 1);
		attr.type = NEXUS_TYPE_NET_IF;
		attr.ntxrings = -1;
		attr.nrxrings = -1;

		sktc_build_nexus(sktc_nexus_controller, &attr,
		    &netif_provider, &netif_instance);

		error = __os_nexus_ifattach(sktc_nexus_controller,
		    netif_instance, FETH0_NAME, NULL, false, &netif_attach);
		SKTC_ASSERT_ERR(error == 0);

		error = __os_nexus_ifattach(sktc_nexus_controller,
		    sktc_instance_uuid, NULL, netif_instance,
		    0, &netif_attach);
		SKTC_ASSERT_ERR(error == 0);
	}

	uuid_generate_random(key0);
	uuid_generate_random(key1);

	attr0 = os_channel_attr_create();
	assert(attr0 != NULL);
	attr1 = os_channel_attr_create();
	assert(attr1 != NULL);

	error = os_channel_attr_set_key(attr0, key0, sizeof(key0));
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_attr_set_key(attr1, key1, sizeof(key1));
	SKTC_ASSERT_ERR(error == 0);
}

static void
skt_bind_fini(void)
{
	if (ch00 != NULL) {
		os_channel_destroy(ch00);
		ch00 = NULL;
	}
	if (ch01 != NULL) {
		os_channel_destroy(ch01);
		ch01 = NULL;
	}

	if (ch10 != NULL) {
		os_channel_destroy(ch10);
		ch10 = NULL;
	}
	if (ch11 != NULL) {
		os_channel_destroy(ch11);
		ch11 = NULL;
	}

	if (attr0 != NULL) {
		os_channel_attr_destroy(attr0);
		attr0 = NULL;
	}
	if (attr1 != NULL) {
		os_channel_attr_destroy(attr1);
		attr1 = NULL;
	}
	uuid_clear(key0);
	uuid_clear(key1);

	if (!uuid_is_null(netif_attach)) {
		int error;

		error = __os_nexus_ifdetach(sktc_nexus_controller,
		    sktc_instance_uuid, netif_attach);
		SKTC_ASSERT_ERR(error == 0);
		uuid_clear(netif_attach);

		error = os_nexus_controller_free_provider_instance(
			sktc_nexus_controller, netif_instance);
		SKTC_ASSERT_ERR(error == 0);
		uuid_clear(netif_instance);

		error = os_nexus_controller_deregister_provider(
			sktc_nexus_controller, netif_provider);
		SKTC_ASSERT_ERR(error == 0);
		uuid_clear(netif_provider);
	}

	sktc_cleanup_nexus();
}

static void
skt_bind_common(nexus_type_t type, nexus_port_t port0, nexus_port_t port1)
{
	ring_id_t ringid;
	uuid_t flow_id;
	int error, upp;

	error = sktc_bind_nexus_key(port0, key0, sizeof(key0));
	SKTC_ASSERT_ERR(error == 0);

	/* this must fail since the port has now been bound */
	error = sktc_bind_nexus_key(port0, key0, sizeof(key0));
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EEXIST);

	error = sktc_bind_nexus_key(port1, key1, sizeof(key1));
	SKTC_ASSERT_ERR(error == 0);

	/* this must fail since the port has now been bound */
	error = sktc_bind_nexus_key(port1, key1, sizeof(key1));
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EEXIST);

	/*
	 * flowswitch doesn't allow opening a channel without a flow bound
	 * to the port.
	 */
	if (type == NEXUS_TYPE_FLOW_SWITCH) {
		uuid_generate(flow_id);
		error = sktc_bind_tcp4_flow(sktc_nexus_controller,
		    sktc_instance_uuid, 0, port0, flow_id);
		SKTC_ASSERT_ERR(error == 0);
		upp = 1;
	} else {
		upp = -1;
	}

	/* this must fail since the key attribute is missing */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/* this must work (key attributes match) */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 != NULL);

	/* we assume this won't change, so retrieve now */
	ringid = os_channel_ring_id(ch00, CHANNEL_FIRST_TX_RING);
	os_channel_destroy(ch00);

	if (type == NEXUS_TYPE_FLOW_SWITCH) {
		uuid_generate(flow_id);
		error = sktc_bind_tcp4_flow(sktc_nexus_controller,
		    sktc_instance_uuid, 0, port1, flow_id);
		SKTC_ASSERT_ERR(error == 0);
	}

	/* this must fail since the key attribute is missing */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, NULL,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/* this must work (key attributes match) */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 != NULL);

	os_channel_destroy(ch10);

	if (type == NEXUS_TYPE_FLOW_SWITCH) {
		error = sktc_bind_nexus_key(port0, key0, sizeof(key0));
		SKTC_ASSERT_ERR(error == 0);

		uuid_generate(flow_id);
		error = sktc_bind_tcp4_flow(sktc_nexus_controller,
		    sktc_instance_uuid, 0, port0, flow_id);
		SKTC_ASSERT_ERR(error == 0);
	}

	/* this must fail (key attributes swapped) */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/*
	 * repeat on a per ring basis.
	 * these all must fail since the key attribute is missing
	 */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, ringid, NULL,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	assert(ch01 == NULL);
	ch01 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, (ringid + 1), NULL,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch01 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/* these all must work (key attributes match) */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, ringid, attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 != NULL);

	ch01 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, (ringid + 1), attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch01 != NULL);

	os_channel_destroy(ch00);
	os_channel_destroy(ch01);

	if (type == NEXUS_TYPE_FLOW_SWITCH) {
		error = sktc_bind_nexus_key(port1, key1, sizeof(key1));
		SKTC_ASSERT_ERR(error == 0);
		uuid_generate(flow_id);
		error = sktc_bind_tcp4_flow(sktc_nexus_controller,
		    sktc_instance_uuid, 0, port1, flow_id);
		SKTC_ASSERT_ERR(error == 0);
	}

	/* this must fail (key attributes swapped) */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, CHANNEL_RING_ID_ANY, attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/*
	 * repeat on a per ring basis.
	 * these all must fail since the key attribute is missing
	 */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, ringid, NULL,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	assert(ch11 == NULL);
	ch11 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, (ringid + 1), NULL,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch11 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/* these all must work (key attributes match) */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, ringid, attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 != NULL);

	ch11 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, (ringid + 1), attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch11 != NULL);

	os_channel_destroy(ch10);
	os_channel_destroy(ch11);

	if (type == NEXUS_TYPE_FLOW_SWITCH) {
		error = sktc_bind_nexus_key(port0, key0, sizeof(key0));
		SKTC_ASSERT_ERR(error == 0);
		uuid_generate(flow_id);
		error = sktc_bind_tcp4_flow(sktc_nexus_controller,
		    sktc_instance_uuid, 0, port0, flow_id);
		SKTC_ASSERT_ERR(error == 0);
	}

	/* these all must fail (key attributes swapped) */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, ringid, attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	ch01 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, (ringid + 1), attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch01 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/* these all must work (key attributes match) */
	ch00 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, ringid, attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch00 != NULL);

	ch01 = sktu_channel_create_extended(sktc_instance_uuid,
	    port0, CHANNEL_DIR_TX_RX, (ringid + 1), attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch01 != NULL);

	os_channel_destroy(ch00);
	ch00 = NULL;
	os_channel_destroy(ch01);
	ch01 = NULL;

	if (type == NEXUS_TYPE_FLOW_SWITCH) {
		error = sktc_bind_nexus_key(port1, key1, sizeof(key1));
		SKTC_ASSERT_ERR(error == 0);
		uuid_generate(flow_id);
		error = sktc_bind_tcp4_flow(sktc_nexus_controller,
		    sktc_instance_uuid, 0, port1, flow_id);
		SKTC_ASSERT_ERR(error == 0);
	}

	/* these all must fail (key attributes swapped) */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, ringid, attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	ch11 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, (ringid + 1), attr0,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch11 == NULL);
	SKTC_ASSERT_ERR(errno == EACCES);

	/* these all must work (key attributes match) */
	ch10 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, ringid, attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch10 != NULL);

	ch11 = sktu_channel_create_extended(sktc_instance_uuid,
	    port1, CHANNEL_DIR_TX_RX, (ringid + 1), attr1,
	    -1, -1, -1, -1, -1, -1, upp, 1, -1, -1);
	assert(ch11 != NULL);

	os_channel_destroy(ch10);
	ch10 = NULL;
	os_channel_destroy(ch11);
	ch11 = NULL;
}

static int
skt_bindupipeanon_main(int argc, char *argv[])
{
	int error;

	skt_bind_init("skywalk_test_upipe_anon", NEXUS_TYPE_USER_PIPE, 1, 0);

	error = sktc_bind_nexus_key(NEXUS_PORT_USER_PIPE_CLIENT,
	    key0, sizeof(key0));
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENXIO);

	error = sktc_bind_nexus_key(NEXUS_PORT_USER_PIPE_SERVER,
	    key1, sizeof(key1));
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENXIO);

	skt_bind_fini();

	return 0;
}

static int
skt_bindupipekey_main(int argc, char *argv[])
{
	skt_bind_init("skywalk_test_upipe", NEXUS_TYPE_USER_PIPE, 0, 0);

	skt_bind_common(NEXUS_TYPE_USER_PIPE, NEXUS_PORT_USER_PIPE_CLIENT,
	    NEXUS_PORT_USER_PIPE_SERVER);

	skt_bind_fini();

	return 0;
}

static int
skt_bindfswanon_common(const char *name, int add_netif)
{
	int error;

	skt_bind_init(name, NEXUS_TYPE_FLOW_SWITCH, 1, add_netif);

	error = sktc_bind_nexus_key(NEXUS_PORT_FLOW_SWITCH_CLIENT,
	    key0, sizeof(key0));
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENXIO);

	error = sktc_bind_nexus_key((NEXUS_PORT_FLOW_SWITCH_CLIENT + 1),
	    key1, sizeof(key1));
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == ENXIO);

	skt_bind_fini();

	return 0;
}

static int
skt_bindfswkey_common(const char *name, int add_netif)
{
	skt_bind_init(name, NEXUS_TYPE_FLOW_SWITCH, 0, add_netif);

	skt_bind_common(NEXUS_TYPE_FLOW_SWITCH,
	    NEXUS_PORT_FLOW_SWITCH_CLIENT,
	    (NEXUS_PORT_FLOW_SWITCH_CLIENT + 1));

	skt_bind_fini();

	return 0;
}

static int
skt_bindnetifkey_common(const char *name, int add_netif)
{
	skt_bind_init(name, NEXUS_TYPE_FLOW_SWITCH, 0, 1);

	int error;
	for (int i = NEXUS_PORT_NET_IF_CLIENT; i < 128; i++) {
		error = os_nexus_controller_bind_provider_instance(
			sktc_nexus_controller, netif_instance, i,
			getpid(), NULL, key0, sizeof(key0),
			NEXUS_BIND_PID | NEXUS_BIND_KEY);
		if (error != 0) {
			T_LOG("failed early at %d", i);
		}
		SKTC_ASSERT_ERR(error == 0);
	}

	// 128 is NETIF DOM max, should reject
	error = os_nexus_controller_bind_provider_instance(
		sktc_nexus_controller, netif_instance, 128,
		getpid(), NULL, key0, sizeof(key0),
		NEXUS_BIND_PID | NEXUS_BIND_KEY);
	SKTC_ASSERT_ERR(error != 0);

	for (int i = NEXUS_PORT_NET_IF_CLIENT; i < 128; i++) {
		error = os_nexus_controller_unbind_provider_instance(
			sktc_nexus_controller, netif_instance, i);
		SKTC_ASSERT_ERR(error == 0);
	}

	return 0;
}

static int
skt_bindfswanon_main(int argc, char *argv[])
{
	return skt_bindfswanon_common("skywalk_test_fsw_anon", 1);
}

static int
skt_bindfswkey_main(int argc, char *argv[])
{
	return skt_bindfswkey_common("skywalk_test_fsw", 1);
}

static int
skt_bindnetifkey_main(int argc, char *argv[])
{
	return skt_bindnetifkey_common("skywalk_test_netif", 1);
}

struct skywalk_test skt_bindupipeanon = {
	"bindupipeanon", "bind a channel to an anonymous user pipe nexus",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_bindupipeanon_main,
};

struct skywalk_test skt_bindupipekey = {
	"bindupipekey", "bind a channel to a non-anonymous user pipe nexus",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_USER_PIPE,
	skt_bindupipekey_main,
};

struct skywalk_test skt_bindfswanon = {
	"bindfswanon",
	"bind a channel to an anonymous flow switch nexus",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_bindfswanon_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_bindfswkey = {
	"bindfswkey",
	"bind a channel to a non-anonymous flow switch nexus",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	skt_bindfswkey_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};

struct skywalk_test skt_bindnetifkey = {
	"bindnetifkey",
	"bind a channel to a non-anonymous netif nexus",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF,
	skt_bindnetifkey_main, { NULL },
	sktc_ifnet_feth0_create, sktc_ifnet_feth0_destroy,
};
