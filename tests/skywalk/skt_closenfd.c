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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"

static int
skt_closenfd_main(int argc, char *argv[])
{
	int error;
	nexus_controller_t ncd;
	int nfd;

	ncd = os_nexus_controller_create();
	assert(ncd);

	nfd = os_nexus_controller_get_fd(ncd);
	assert(nfd != -1);

	error = close(nfd); // expect guarded fd fail
	SKTC_ASSERT_ERR(!error);

	os_nexus_controller_destroy(ncd);

	return 1; // should not reach
}

struct skywalk_test skt_closenfd = {
	"closenfd", "test closing guarded nexus fd",
	SK_FEATURE_SKYWALK,
	skt_closenfd_main, { NULL }, NULL, NULL,
	0x4000000100000000, 0xFFFFFFFF,
};


/****************************************************************/

static int
skt_writenfd_main(int argc, char *argv[])
{
	nexus_controller_t ncd;
	int nfd;
	char buf[100] = { 0 };
	ssize_t ret;

	ncd = os_nexus_controller_create();
	assert(ncd);

	nfd = os_nexus_controller_get_fd(ncd);
	assert(nfd != -1);

	ret = write(nfd, buf, sizeof(buf));
	assert(ret == -1);
	assert(errno == EBADF);

	os_nexus_controller_destroy(ncd);

	return 0;
}

struct skywalk_test skt_writenfd = {
	"writenfd", "test writing to a guarded nexus fd",
	SK_FEATURE_SKYWALK,
	skt_writenfd_main, { NULL }, NULL, NULL, 0x9c00003, 0,
};

/****************************************************************/

static int
skt_readnfd_main(int argc, char *argv[])
{
	nexus_controller_t ncd;
	int nfd;
	char buf[100];
	ssize_t ret;

	ncd = os_nexus_controller_create();
	assert(ncd);

	nfd = os_nexus_controller_get_fd(ncd);
	assert(nfd != -1);

	ret = read(nfd, buf, sizeof(buf));
	assert(ret == -1);
	assert(errno == ENXIO);

	os_nexus_controller_destroy(ncd);

	return 0;
}

struct skywalk_test skt_readnfd = {
	"readnfd", "test reading from a guarded nexus fd",
	SK_FEATURE_SKYWALK,
	skt_readnfd_main, { NULL }, NULL, NULL,
};

/****************************************************************/
