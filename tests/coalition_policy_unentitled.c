/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <sys/coalition_private.h>

#include <mach/coalition.h>
#include <sys/coalition.h>
#include <libproc.h>

#include <sys/types.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/task.h>
#include <mach/task_policy.h>
#include <mach/mach.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(true));

static uint64_t
get_jet_id(void)
{
	T_LOG("uid: %d, pid %d", getuid(), getpid());

	struct proc_pidcoalitioninfo idinfo;

	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t res_id = idinfo.coalition_id[COALITION_TYPE_RESOURCE];
	uint64_t jet_id = idinfo.coalition_id[COALITION_TYPE_JETSAM];

	T_LOG("Resource coalition: %lld, Jetsam coalition: %lld", res_id, jet_id);

	return jet_id;
}

T_DECL(coalition_suppress_read_entitled, "COALITION_POLICY_SUPPRESS should not be readable without entitlement")
{
	uint64_t jet_id = get_jet_id();

	int suppress = coalition_policy_get(jet_id, COALITION_POLICY_SUPPRESS);
	T_ASSERT_POSIX_FAILURE(suppress, EPERM, "coalition_policy_get(%lld, COALITION_POLICY_SUPPRESS)", jet_id);
	T_LOG("suppress: %d", suppress);
}

T_DECL(coalition_suppress_set, "COALITION_POLICY_SUPPRESS should not be settable without entitlement")
{
	uint64_t jet_id = get_jet_id();

	T_ASSERT_POSIX_FAILURE(coalition_policy_set(jet_id, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_DARWIN_BG), EPERM,
	    "coalition_policy_set(%lld, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_DARWIN_BG)", jet_id);

	T_ASSERT_POSIX_FAILURE(coalition_policy_set(jet_id, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_NONE), EPERM,
	    "coalition_policy_set(%lld, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_NONE)", jet_id);
}
