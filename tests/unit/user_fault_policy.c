/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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


#include <darwintest.h>
#include "mocks/bsd/mock_proc.h"
#include <sys/reason.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.user_fault_policy"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("s_musaev")
	);

/* This is copied from kern_exit.c */
#define OS_REASON_IFLAG_USER_FAULT 0x1

extern bool
abort_should_be_throttled(proc_t p,
    uint32_t reason_namespace, uint32_t internal_flags);
extern bool user_fault_prefers_backtrace(uint64_t reason_flags,
    bool platform_is_macosx);


T_DECL(abort_must_be_throttled_userfault, "Test user_fault throttling")
{
	/* create proc */
	proc_t proc = fake_alloc_init_proc_and_task();

	/* sanity check first - non user fault must be throttled instantly*/
	for (int reason = 0; reason <= OS_REASON_MAX_VALID_NAMESPACE; ++reason) {
		T_ASSERT_EQ(false,
		    abort_should_be_throttled(proc, reason, 0),
		    "Not passing OS_REASON_IFLAG_USER_FAULT must not be throttled");
	}

	proc_user_faults_template(proc, 0, 0);
	T_ASSERT_EQ(false,
	    abort_should_be_throttled(proc, OS_REASON_SECURITY_SOFT_TRAPS, OS_REASON_IFLAG_USER_FAULT),
	    "SECURITY namespace shouldn't be throttled while not reached the limit");
	T_ASSERT_EQ(false,
	    abort_should_be_throttled(proc, OS_REASON_SECINIT, OS_REASON_IFLAG_USER_FAULT),
	    "GLOBAL namespace shouldn't be throttled while not reached the limit");

	proc_user_faults_template(proc, 1, 1);
	T_ASSERT_EQ(true,
	    abort_should_be_throttled(proc, OS_REASON_SECURITY_SOFT_TRAPS, OS_REASON_IFLAG_USER_FAULT),
	    "SECURITY counter must've crossed limit already");
	T_ASSERT_EQ(true,
	    abort_should_be_throttled(proc, OS_REASON_SECINIT, OS_REASON_IFLAG_USER_FAULT),
	    "GLOBAL counter must've crossed limit already");



	proc_user_faults_template(proc, 1, 0);
	for (int reason = 0; reason <= OS_REASON_MAX_VALID_NAMESPACE; ++reason) {
		if (reason == OS_REASON_SECURITY_SOFT_TRAPS) {
			continue;
		}
		T_ASSERT_EQ(true,
		    abort_should_be_throttled(proc, reason, OS_REASON_IFLAG_USER_FAULT),
		    "GLOBAL counter must've crossed limit already");
	}
	T_ASSERT_EQ(false,
	    abort_should_be_throttled(proc, OS_REASON_SECURITY_SOFT_TRAPS, OS_REASON_IFLAG_USER_FAULT),
	    "SECURITY counter must be 0");

	for (int reason = 0; reason <= OS_REASON_MAX_VALID_NAMESPACE; ++reason) {
		if (reason == OS_REASON_SECURITY_SOFT_TRAPS) {
			continue;
		}
		proc_user_faults_template(proc, 0, 1);
		T_ASSERT_EQ(false,
		    abort_should_be_throttled(proc, reason, OS_REASON_IFLAG_USER_FAULT),
		    "GLOBAL counter has not reached the limit yet");
		/* reset counters */
	}
	T_ASSERT_EQ(true,
	    abort_should_be_throttled(proc, OS_REASON_SECURITY_SOFT_TRAPS, OS_REASON_IFLAG_USER_FAULT),
	    "SECURITY counter must've crossed the limit already");

	/* lets exhaust slots */
	proc_user_faults_template(proc, 0, 0);
	for (int i = 0; i < 10; ++i) {
		abort_should_be_throttled(proc, OS_REASON_SECINIT, OS_REASON_IFLAG_USER_FAULT);
	}
	/* must be throttled now */
	T_ASSERT_EQ(true,
	    abort_should_be_throttled(proc, OS_REASON_SECINIT, OS_REASON_IFLAG_USER_FAULT),
	    "GLOBAL counter must've crossed limit already");
	/* different namespace shouldn't be throttled */
	T_ASSERT_EQ(false,
	    abort_should_be_throttled(proc, OS_REASON_SECURITY_SOFT_TRAPS, OS_REASON_IFLAG_USER_FAULT),
	    "SECURITY counter hasn't been touched yet");

	/* dealloc proc */
	fake_dealloc_proc_and_task(proc);
}



T_DECL(user_fault_bt_only_policy_non_osx, "Test user fault bt only policy for non-MacOS")
{
	T_ASSERT_EQ(true, user_fault_prefers_backtrace(0, false),
	    "any reason on non-OSX must be LW corpse");
}

T_DECL(user_fault_bt_only_policy_osx, "Test user fault bt only policy for MacOS")
{
	T_ASSERT_EQ(false, user_fault_prefers_backtrace(0, true),
	    "any reason(except SECURITY) on OSX must be non LW corpse");
}
