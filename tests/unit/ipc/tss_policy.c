/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
#include <mach/mach_port.h>
#include <kern/task.h>
#include "mocks/dt_proxy.h"
#include <mach/message.h>
#include <ipc/ipc_policy.h>
#include <ipc/ipc_port.h>

#include "mocks/osfmk/mock_ipc.h"
#include "mocks/mock_dynamic.h"
#include "mocks/osfmk/mock_thread.h"

#include "ipc/utils/mach_port_construct_helpers.h"
#include "ipc/utils/ipc_policy_helpers.h"

#define UT_MODULE osfmk

extern size_t proc_struct_size;

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

extern bool
thread_set_state_allowed(
	thread_t                  thread,
	int                       flavor,
	thread_set_status_flags_t flags,
	audit_token_t             *audit);

T_DECL(
	thread_set_state_basic_policy,
	"Basic thread_set_state policy checks")
{
	bool allowed;
	int flavor = ARM_THREAD_STATE;
	thread_set_status_flags_t flags = TSSF_FLAGS_NONE;

	/* Kernel allowed always */
	allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "thread_set_state should be allowed from kernel");

	/* Everything allowed when no security policy set */
	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT);
	allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "thread_set_state should be allowed for thread with no security");

	/* Everything allowed when opted out */
	SET_IPC_POLICY(IPC_SPACE_POLICY_OPTED_OUT);
	allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "thread_set_state should be allowed for opted out");
}

T_DECL(
	thread_set_state_from_user_not_in_exception,
	"thread_set_state_from_user policy checks (NOT in mach exception)")
{
	bool allowed = false;
	int flavor = ARM_THREAD_STATE;
	thread_set_status_flags_t flags = TSSF_CHECK_ENTITLEMENT;

	/* 3P allowed thread_set_state_from_user */
	allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "thread_set_state_from_user is allowed for 3P");

	/* ES thread_set_state_from_user - allowed V0; disallowed >=V1 */
	for (int i = 0; i < ENHANCED_VERSION_COUNT; i++) {
		ipc_space_policy_t policy = enhanced_versions[i];
		SET_IPC_POLICY(policy);
		allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
		if (policy == IPC_POLICY_ENHANCED_V0) {
			T_EXPECT_TRUE(allowed, "thread_set_state_from_user should be allowed policy=%x", policy);
		} else {
			T_EXPECT_FALSE(allowed, "thread_set_state_from_user should be disallowed policy=%x", policy);
		}
	}
}

T_DECL(
	thread_set_state_from_user_in_exception,
	"thread_set_state_from_user policy checks (IN mach exception)")
{
	bool allowed = false;
	int flavor = ARM_THREAD_STATE;
	thread_set_status_flags_t flags = TSSF_CHECK_ENTITLEMENT;

	current_thread()->options |= TH_IN_MACH_EXCEPTION;

	/* allowed for 3P */
	allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "thread_set_state_from_user is allowed for 3P");

	/* Allowed (in telemetry mode) for all ES */
	for (int i = 0; i < ENHANCED_VERSION_COUNT; i++) {
		ipc_space_policy_t policy = enhanced_versions[i];
		SET_IPC_POLICY(policy);
		allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
		T_EXPECT_TRUE(allowed,
		    "thread_set_state_from_user while in mach exception "
		    "should be allowed policy=%x",
		    policy);
	}

	current_thread()->options &= ~TH_IN_MACH_EXCEPTION;
}

T_DECL(
	mach_exception_state_flavor,
	"Mach exception handler modifying thread state")
{
	bool allowed = false;
	int flavor = ARM_THREAD_STATE;
	thread_set_status_flags_t flags = TSSF_FLAGS_NONE;

	current_thread()->options |= TH_IN_MACH_EXCEPTION;

	/* 3P allowed setting via mach exception */
	allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "thread_set_state should be allowed for thread with no security");

	/* All ES allows setting via mach exception */
	for (int i = 0; i < ENHANCED_VERSION_COUNT; i++) {
		ipc_space_policy_t policy = enhanced_versions[i];
		SET_IPC_POLICY(policy);
		flags = TSSF_CHECK_ENTITLEMENT;
		allowed = thread_set_state_allowed(current_thread(), flavor, flags, NULL);
		T_EXPECT_TRUE(allowed,
		    "mach exception modifying thread state should be allowed policy=%x",
		    policy);
	}

	current_thread()->options &= ~TH_IN_MACH_EXCEPTION;
}

T_DECL(
	thread_set_state_cross_thread_in_exception,
	"Cross-thread thread_set_state_from_user policy checks (target thread IN mach exception)")
{
	bool allowed = false;
	int flavor = ARM_THREAD_STATE;
	thread_set_status_flags_t flags = TSSF_CHECK_ENTITLEMENT;

	/* Create a separate proc/task for the target thread */
	extern task_t proc_get_task_raw(void *proc);
	void *proctask = calloc(1, proc_struct_size + sizeof(struct task));
	T_ASSERT_NOTNULL(proctask, "proctask allocation");

	proc_t proc = (proc_t)proctask;
	task_t task = proc_get_task_raw(proc);
	fake_init_task(task);

	/* Manually create a thread structure linked to the separate task */
	thread_t target_thread = calloc(1, sizeof(struct thread));
	T_ASSERT_NOTNULL(target_thread, "target_thread allocation");

	target_thread->t_tro = calloc(1, sizeof(struct thread_ro));
	T_ASSERT_NOTNULL(target_thread->t_tro, "target_thread t_tro allocation");

	target_thread->t_tro->tro_owner = target_thread;
	target_thread->t_tro->tro_task = task;
	target_thread->t_tro->tro_proc = proc;

	/* Set target thread in mach exception */
	target_thread->options |= TH_IN_MACH_EXCEPTION;

	/* allowed for 3P */
	allowed = thread_set_state_allowed(target_thread, flavor, flags, NULL);
	T_EXPECT_TRUE(allowed, "cross-thread thread_set_state_from_user is allowed for 3P");

	/* Cross-thread: V0 allows, V1+ blocks (even in telemetry mode) */
	for (int i = 0; i < ENHANCED_VERSION_COUNT; i++) {
		ipc_space_policy_t policy = enhanced_versions[i];
		SET_IPC_POLICY(policy);
		allowed = thread_set_state_allowed(target_thread, flavor, flags, NULL);
		if (policy == IPC_POLICY_ENHANCED_V0 || policy == IPC_POLICY_ENHANCED_V1) {
			T_EXPECT_TRUE(allowed,
			    "cross-thread thread_set_state_from_user while target in mach exception "
			    "should be allowed for V0 policy=%x",
			    policy);
		} else {
			T_EXPECT_FALSE(allowed,
			    "cross-thread thread_set_state_from_user while target in mach exception "
			    "should be blocked for policy=%x",
			    policy);
		}
	}

	/* Clean up */
	free(target_thread->t_tro);
	free(target_thread);
	free(proctask);
}
