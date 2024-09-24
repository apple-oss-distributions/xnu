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

/* <rdar://problem/25158037> [N56 14A207] BTServer crash during BT off/on in  Watchdog_TimerSettings
 * verify that closing the kqueue fd causes select/poll/kevent to return
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/event.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_common.h"

static int kq;

static void *
threadk(void *unused)
{
	struct kevent kev, refkev;
	int error;

	T_LOG("entering kevent in thread\n");

	memset(&kev, 0, sizeof(kev));
	refkev = kev;
	error = kevent(kq, NULL, 0, &kev, 1, NULL);
	SKTC_ASSERT_ERR(error == -1);
	SKTC_ASSERT_ERR(errno == EBADF || errno == EINTR);
	assert(!memcmp(&kev, &refkev, sizeof(refkev)));

	T_LOG("exiting thread\n");

	return NULL;
}

static int
skt_closekq_main_common(int argc, char *argv[], void * (*threadfunc)(void *unused))
{
	int error;
	pthread_t thread;

	kq = kqueue();
	assert(kq != -1);

	error = pthread_create(&thread, NULL, threadfunc, NULL);
	SKTC_ASSERT_ERR(!error);

	error = usleep(1000); // to make sure thread gets into select/poll/kevent
	SKTC_ASSERT_ERR(!error);

	T_LOG("closing kqueue in main\n");

	error = close(kq);
	SKTC_ASSERT_ERR(!error);

	T_LOG("joining thread in main\n");

	error = pthread_join(thread, NULL);
	SKTC_ASSERT_ERR(!error);

	T_LOG("exiting main\n");

	return 0;
}

static int
skt_closekqk_main(int argc, char *argv[])
{
	return skt_closekq_main_common(argc, argv, threadk);
}

struct skywalk_test skt_closekqk = {
	"closekqk", "test closing kqueue in kqueue",
	0, skt_closekqk_main, { NULL }, NULL, NULL,
};

/****************************************************************/
