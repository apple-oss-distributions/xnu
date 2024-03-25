/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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


#if DEBUG || DEVELOPMENT

#include <kern/testpoints.h>
#include <kern/exclaves_test_stackshot.h>
#include <kern/thread.h>

// this is set by sysctl
uint64_t tp_scenario;

#define TESTPOINT_COUNT 64
// array of blocked test points
static uint64_t tp_blocked_info[TESTPOINT_COUNT];

static LCK_GRP_DECLARE(tp_lck_grp, "testpoint lock group");
LCK_MTX_DECLARE(tp_mtx, &tp_lck_grp);

void
tp_block(tp_id_t testpoint)
{
	tp_blocked_info[testpoint] = 1;
}

void
tp_unblock(tp_id_t other_testpoint)
{
	tp_blocked_info[other_testpoint] = 0;
	thread_wakeup(&tp_blocked_info);
}


void
tp_wait(tp_id_t testpoint)
{
	wait_result_t wr = THREAD_AWAKENED;
	while ((tp_blocked_info[testpoint]) && wr <= 0) {
		wr = lck_mtx_sleep(&tp_mtx, LCK_SLEEP_DEFAULT, (event_t)&tp_blocked_info, THREAD_INTERRUPTIBLE);
	}
	if (wr > 0) {
		printf("tp_block(%hu) wait interrupted with error %d\n", testpoint, wr);
	}
}

void
tp_relay(tp_id_t testpoint, tp_id_t other_testpoint)
{
	tp_unblock(other_testpoint);
	tp_block(testpoint);
	tp_wait(testpoint);
}


void
tp_call(tp_id_t testpoint, tp_val_t val)
{
	switch (tp_scenario) {
	case TPS_NONE:
		break;
	case TPS_STACKSHOT_UPCALL:
		tp_call_stackshot_upcall(testpoint, val);
		break;
	case TPS_STACKSHOT_LONG_UPCALL:
		tp_call_stackshot_long_upcall(testpoint, val);
		break;
	default:
		panic("Invalid test point scenario value %llu", tp_scenario);
	}
}


static int
testpoint_handler(int64_t testpoint, int64_t *out)
{
	tp_sysctl_msg_t * msg = (tp_sysctl_msg_t*)&testpoint;
	tp_call(msg->id, msg->val);
	*out = 0;
	return 0;
}

SYSCTL_TEST_REGISTER(testpoint, testpoint_handler);

static int
tp_scenario_handler(int64_t scenario, int64_t *out)
{
	tps_id_t new_scenario = (tps_id_t)scenario;

	lck_mtx_lock(&tp_mtx);
	if (tp_scenario != new_scenario) {
		tp_scenario = new_scenario;
		bzero(&tp_blocked_info, sizeof(tp_blocked_info));
		thread_wakeup(&tp_blocked_info);
	}
	lck_mtx_unlock(&tp_mtx);

	printf("tp_scenario=%llu\n", new_scenario);
	*out = 0;
	return 0;
}

SYSCTL_TEST_REGISTER(tp_scenario, tp_scenario_handler);

#endif /* DEBUG || DEVELOPMENT */
