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

#include <assert.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"

/****************************************************************/

static int
skt_noop_main(int argc, char *argv[])
{
	return 0;
}

struct skywalk_test skt_noop = {
	"noop", "test just returns true", 0, skt_noop_main,
};

/****************************************************************/

static int
skt_crash_main(int argc, char *argv[])
{
	*(volatile int *)0 = 1; // Crash
	return 1;
}

struct skywalk_test skt_crash = {
	"crash", "test expects a segfault",
	0, skt_crash_main, { NULL }, NULL, NULL, 0xb100001, 0,
};

/****************************************************************/

static int
skt_assert_main(int argc, char *argv[])
{
	assert(0);
	return 1;
}

struct skywalk_test skt_assert = {
	"assert", "test verifies that assert catches failure",
	0, skt_assert_main, { NULL }, NULL, NULL, 0x6000000, 0,
};

/****************************************************************/
