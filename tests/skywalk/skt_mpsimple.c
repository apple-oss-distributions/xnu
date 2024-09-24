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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"

/****************************************************************/

static int
skt_mp100noop_main(int argc, char *argv[])
{
	char buf[1] = { 0 };
	assert(!strcmp(argv[3], "--child"));
	ssize_t ret;

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s", strerror(errno));
		return 1;
	}
	assert(ret == 1);

	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s", strerror(errno));
		return 1;
	}
	assert(ret == 1);

	return 0;
}

struct skywalk_mptest skt_mp100noop = {
	"mp100noop", "test just returns true from 100 children", 0, 100, skt_mp100noop_main,
};
