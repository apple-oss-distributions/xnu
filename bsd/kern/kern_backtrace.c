/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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

#include <kern/backtrace.h>
#include <kern/kalloc.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#if DEVELOPMENT || DEBUG

#define MAX_BACKTRACE  (128)

#define BACKTRACE_USER (0)
#define BACKTRACE_USER_RESUME (1)
static int backtrace_user_sysctl SYSCTL_HANDLER_ARGS;

#define BACKTRACE_KERN_TEST_PACK_UNPACK (0)
#define BACKTRACE_KERN_TEST_PACKED (1)
static int backtrace_kernel_sysctl SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(_kern, OID_AUTO, backtrace, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "backtrace");

SYSCTL_PROC(_kern_backtrace, OID_AUTO, user,
    CTLFLAG_RW | CTLFLAG_LOCKED, (void *)BACKTRACE_USER,
    sizeof(uint64_t), backtrace_user_sysctl, "O",
    "take user backtrace of current thread");

SYSCTL_PROC(_kern_backtrace, OID_AUTO, kernel_tests,
    CTLFLAG_RW | CTLFLAG_LOCKED, (void *)BACKTRACE_USER,
    sizeof(uint64_t), backtrace_kernel_sysctl, "O",
    "take user backtrace of current thread");

static int
backtrace_kernel_sysctl SYSCTL_HANDLER_ARGS
{
	unsigned int scenario = (unsigned int)req->newlen;
	uintptr_t *bt = NULL;
	uint8_t *packed_bt = NULL;
	uintptr_t *unpacked_bt = NULL;
	unsigned int bt_len = 0;
	size_t bt_size = 0;
	errno_t error = 0;

	bt_len = 24;
	bt_size = sizeof(bt[0]) * bt_len;
	bt = kalloc_data(bt_size, Z_WAITOK | Z_ZERO);
	packed_bt = kalloc_data(bt_size, Z_WAITOK | Z_ZERO);
	unpacked_bt = kalloc_data(bt_size, Z_WAITOK | Z_ZERO);
	if (!bt || !packed_bt || !unpacked_bt) {
		error = ENOBUFS;
		goto out;
	}
	backtrace_info_t info = BTI_NONE;
	unsigned int len = backtrace(bt, bt_len, NULL, &info);
	backtrace_info_t packed_info = BTI_NONE;
	size_t packed_size = 0;
	if (scenario == BACKTRACE_KERN_TEST_PACK_UNPACK) {
		packed_size = backtrace_pack(BTP_KERN_OFFSET_32, packed_bt, bt_size,
		    bt, len);
	} else {
		packed_size = backtrace_packed(BTP_KERN_OFFSET_32, packed_bt, bt_size,
		    NULL, &packed_info);
	}
	unsigned int unpacked_len = backtrace_unpack(BTP_KERN_OFFSET_32,
	    unpacked_bt, bt_len, packed_bt, packed_size);
	if (unpacked_len != len) {
		printf("backtrace_tests: length %u != %u unpacked\n", len,
		    unpacked_len);
		error = ERANGE;
		goto out;
	}
	for (unsigned int i = 0; i < len; i++) {
		if (unpacked_bt[i] != bt[i]) {
			printf("backtrace_tests: bad address %u: 0x%lx != 0x%lx unpacked",
			    i, bt[i], unpacked_bt[i]);
			error = EINVAL;
		}
	}

out:
	if (bt) {
		kfree_data(bt, bt_size);
	}
	if (packed_bt) {
		kfree_data(packed_bt, bt_size);
	}
	if (unpacked_bt) {
		kfree_data(unpacked_bt, bt_size);
	}
	return error;
}

static int
backtrace_user_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int scenario = (unsigned int)req->newlen;
	uintptr_t *bt = NULL;
	unsigned int bt_len = 0, bt_filled = 0, bt_space = 0;
	size_t bt_size = 0;
	errno_t error = 0;

	bool user_scenario = scenario == BACKTRACE_USER;
	bool resume_scenario = scenario == BACKTRACE_USER_RESUME;
	if (!user_scenario && !resume_scenario) {
		return ENOTSUP;
	}

	if (req->oldptr == USER_ADDR_NULL || req->oldlen == 0) {
		return EFAULT;
	}

	bt_len = req->oldlen > MAX_BACKTRACE ? MAX_BACKTRACE :
	    (unsigned int)req->oldlen;
	bt_size = sizeof(bt[0]) * bt_len;
	bt = kalloc_data(bt_size, Z_WAITOK | Z_ZERO);
	if (!bt) {
		return ENOBUFS;
	}
	bt_space = resume_scenario ? bt_len / 2 : bt_len;
	struct backtrace_user_info btinfo = BTUINFO_INIT;
	bt_filled = backtrace_user(bt, bt_space, NULL, &btinfo);
	error = btinfo.btui_error;
	if (error != 0) {
		goto out;
	}
	if (resume_scenario) {
		if (!(btinfo.btui_info & BTI_TRUNCATED)) {
			error = ENOSPC;
			goto out;
		}
		struct backtrace_control ctl = {
			.btc_frame_addr = btinfo.btui_next_frame_addr,
		};
		btinfo = BTUINFO_INIT;
		unsigned int bt_more = backtrace_user(bt + bt_filled, bt_space, &ctl,
		    &btinfo);
		error = btinfo.btui_error;
		if (error != 0) {
			goto out;
		}
		bt_filled += bt_more;
	}
	bt_filled = min(bt_filled, bt_len);
	if (btinfo.btui_async_frame_addr != 0 &&
	    btinfo.btui_async_start_index != 0) {
		// Put the async call stack inline after the real call stack.
		unsigned int start_index = btinfo.btui_async_start_index;
		uintptr_t frame_addr = btinfo.btui_async_frame_addr;
		unsigned int bt_left = bt_len - start_index;
		struct backtrace_control ctl = { .btc_frame_addr = frame_addr, };
		btinfo = BTUINFO_INIT;
		unsigned int async_filled = backtrace_user(bt + start_index, bt_left,
		    &ctl, &btinfo);
		error = btinfo.btui_error;
		if (error != 0) {
			goto out;
		}
		bt_filled = min(start_index + async_filled, bt_len);
	}

	error = copyout(bt, req->oldptr, sizeof(bt[0]) * bt_filled);
	if (error) {
		goto out;
	}
	req->oldidx = bt_filled;

out:
	kfree_data(bt, bt_size);
	return error;
}

#endif /* DEVELOPMENT || DEBUG */
