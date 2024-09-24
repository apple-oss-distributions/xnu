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
 * Attempts to allocate as many utuns as it can and then cleans
 * them up.  It does this twice because we originally had a leak
 * when we hit the limit the first time so the second time
 * would get EBUSY intead of ENOMEM
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sys/types.h>

#include <skywalk/os_skywalk.h>
#include <darwintest.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

static int
skt_utunleak_main(int argc, char *argv[])
{
	int nchannels = 500;
	int utuns[nchannels];
	int error;

	sktc_raise_file_limit(nchannels + 10);

	for (int i = 0; i < nchannels; i++) {
		utuns[i] = -1;
	}

	for (int i = 0; i < nchannels; i++) {
		utuns[i] = sktu_create_interface(SKTU_IFT_UTUN, SKTU_IFF_ENABLE_NETIF);
		if (utuns[i] == -1) {
			SKT_LOG("Expected: Failed on count %d errno %d\n", i + 1, errno);
			assert(errno != EBUSY);
			assert(errno == ENOMEM);
			break;
		}
	}
	for (int i = 0; i < nchannels; i++) {
		if (utuns[i] != -1) {
			error = close(utuns[i]);
			SKTC_ASSERT_ERR(!error);
			utuns[i] = -1;
		}
	}

	/* Now try it a second time and verify it works the same */

	for (int i = 0; i < nchannels; i++) {
		utuns[i] = -1;
	}

	for (int i = 0; i < nchannels; i++) {
		utuns[i] = sktu_create_interface(SKTU_IFT_UTUN, SKTU_IFF_ENABLE_NETIF);
		if (utuns[i] == -1) {
			SKT_LOG("Expected: Failed on count %d errno %d\n", i + 1, errno);
			assert(errno != EBUSY);
			assert(errno == ENOMEM);
			break;
		}
	}

	for (int i = 0; i < nchannels; i++) {
		if (utuns[i] != -1) {
			error = close(utuns[i]);
			SKTC_ASSERT_ERR(!error);
			utuns[i] = -1;
		}
	}

	return 0;
}

struct skywalk_test skt_utunleak = {
	"utunleak", "allocate utuns until failure to reproduce a leak",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunleak_main,
};
