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

/* This test attaches a flow switch to itself.
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

static void
skt_fswloop_common(const char *name)
{
	uuid_t attach;
	int error;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	strncpy((char *)attr.name, name, sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_FLOW_SWITCH;
	attr.anonymous = 1;

	sktc_setup_nexus(&attr);

	error = __os_nexus_ifattach(sktc_nexus_controller, sktc_instance_uuid,
	    NULL, sktc_instance_uuid, false, &attach);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EINVAL);
}

static int
skt_fswloopfsw_main(int argc, char *argv[])
{
	skt_fswloop_common("skywalk_test_fswloop");
	return 0;
}

struct skywalk_test skt_fswloopfsw = {
	"fswloopfsw", "create a flow-switch and attach it to itself",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswloopfsw_main,
};

void
skt_fswloop2_common(boolean_t add_netif)
{
	int error;
	nexus_controller_t ncd;
	uuid_t provider0, instance0, provider1, instance1, attach;
	uuid_t feth0_attach, feth1_attach;
	uuid_t netif_provider, netif0_instance, netif1_instance;
	struct sktc_nexus_attr attr = SKTC_NEXUS_ATTR_INIT();

	ncd = os_nexus_controller_create();
	assert(ncd);

	strncpy((char *)attr.name, "skt_fswloop2_zero",
	    sizeof(nexus_name_t) - 1);
	attr.type = NEXUS_TYPE_FLOW_SWITCH;
	attr.anonymous = 1;
	sktc_build_nexus(ncd, &attr, &provider0, &instance0);

	strncpy((char *)attr.name, "skt_fswloop2_one",
	    sizeof(nexus_name_t) - 1);
	sktc_build_nexus(ncd, &attr, &provider1, &instance1);

	if (add_netif) {
		strncpy((char *)attr.name, "skt_netif_feth",
		    sizeof(nexus_name_t) - 1);
		attr.type = NEXUS_TYPE_NET_IF;
		sktc_build_nexus(ncd, &attr, &netif_provider, &netif0_instance);

		error = __os_nexus_ifattach(ncd, netif0_instance, FETH0_NAME,
		    NULL, false, &feth0_attach);
		SKTC_ASSERT_ERR(!error);

		error = os_nexus_controller_alloc_provider_instance(ncd,
		    netif_provider, &netif1_instance);
		SKTC_ASSERT_ERR(!error);

		error = __os_nexus_ifattach(ncd, netif1_instance, FETH1_NAME,
		    NULL, false, &feth1_attach);
		SKTC_ASSERT_ERR(!error);
	}

	error = __os_nexus_ifattach(ncd, instance1, NULL, instance0, false, &attach);
	//T_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	/* Can't attach a flowswitch to anything */
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EINVAL);

	/* Now also try to attach them the other way around */
	error = __os_nexus_ifattach(ncd, instance0, NULL, instance1, false, &attach);
	//T_LOG("%s:%d error %d errno %d\n", __func__, __LINE__, error, errno);
	/* Can't attach a flowswitch to anything */
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EINVAL);
}

int
skt_fswloop2ff_main(int argc, char *argv[])
{
	skt_fswloop2_common(false);
	return 0;
}

struct skywalk_test skt_fswloop2ff = {
	"fswloop2mm", "attach a flowswitch to a flowswitch without any netif",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswloop2ff_main,
};

int
skt_fswloop2nff_main(int argc, char *argv[])
{
	skt_fswloop2_common(true);
	return 0;
}

struct skywalk_test skt_fswloop2nmm = {
	"fswloop2nmm", "attach a flowswitch to a flowswitch and back to itself",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_NEXUS_FLOWSWITCH,
	skt_fswloop2nff_main, { NULL },
	sktc_ifnet_feth0_1_create, sktc_ifnet_feth0_1_destroy,
};
