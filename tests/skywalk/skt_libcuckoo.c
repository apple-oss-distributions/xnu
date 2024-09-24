/*
 * Copyright (c) 2018-2024 Apple Inc. All rights reserved.
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
#include <string.h>
#include <stdio.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int sktc_libcuckoo_test_was_enabled;

void
sktc_libcuckoo_init(void)
{
	size_t len = sizeof(sktc_libcuckoo_test_was_enabled);
	int enabled = 1;

	sysctlbyname("kern.skywalk.libcuckoo.test", &sktc_libcuckoo_test_was_enabled,
	    &len, &enabled, sizeof(enabled));
}

void
sktc_libcuckoo_fini(void)
{
	sysctlbyname("kern.skywalk.libcuckoo.test", NULL, 0,
	    &sktc_libcuckoo_test_was_enabled,
	    sizeof(sktc_libcuckoo_test_was_enabled));
}

static int
skt_libcuckoo_main(int argc, char *argv[])
{
#pragma unused(argc, argv)
	/*
	 * A failure for this test is indicated by either a panic or
	 * a hang; we rely on some external mechanism to detect the
	 * latter and take the appropriate actions.
	 */
	return 0;
}

struct skywalk_test skt_libcuckoo = {
	"libcuckoo", "Cuckoo hashtable library basic and advanced tests",
	SK_FEATURE_SKYWALK | SK_FEATURE_DEV_OR_DEBUG,
	skt_libcuckoo_main, { NULL },
	sktc_libcuckoo_init, sktc_libcuckoo_fini,
};
