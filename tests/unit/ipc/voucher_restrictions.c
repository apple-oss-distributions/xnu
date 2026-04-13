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

#include "kern/host.h"
#include <darwintest.h>
#include <mach/mach_port.h>
#include <kern/task.h>
#include <mocks/dt_proxy.h>
#include <mocks/osfmk/mock_ipc.h>
#include <mach/mach_traps.h>

#include "ipc/utils/ipc_policy_helpers.h"

#define UT_MODULE osfmk

kern_return_t
host_create_mach_voucher(
	host_t host,
	mach_voucher_attr_raw_recipe_array_t recipes,
	mach_voucher_attr_raw_recipe_size_t recipe_size,
	ipc_voucher_t *new_voucher);

T_MOCK_CALL_QUEUE(ipc_triage_policy_violation_and_expect_continue_call, {
	ipc_sec_policy_t expected_policy;
	int expected_maybe_ca_aux_data;
});

T_MOCK_SET_PERM_FUNC(void,
    ipc_triage_policy_violation_and_expect_continue,
    (ipc_sec_policy_t policy,
    ipc_space_t maybe_space,
    uint32_t maybe_exc_target,
    uint64_t maybe_exc_payload,
    ipc_port_t maybe_ca_violating_port,
    int maybe_ca_aux_data))
{
	ipc_triage_policy_violation_and_expect_continue_call call = dequeue_ipc_triage_policy_violation_and_expect_continue_call();
	T_ASSERT_EQ(policy, call.expected_policy, "expected policy %d == actual %d", call.expected_policy, policy);
	T_ASSERT_EQ(maybe_ca_aux_data, call.expected_maybe_ca_aux_data, "expected maybe_ca_aux_data %d == actual %d", call.expected_maybe_ca_aux_data, maybe_ca_aux_data);
}

T_DECL(restricted_voucher_operation_emits_telemetry,
    "Ensure constructing a Mach voucher with restricted recipe operation emits telemetry")
{
	/* Given a Mach voucher containing a recipe command outside the allow-list */
	mach_voucher_attr_recipe_data_t recipe = {
		.key                = MACH_VOUCHER_ATTR_KEY_ALL,
		.command            = MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_DISALLOWED,
		.previous_voucher   = MACH_VOUCHER_NAME_NULL,
		.content_size       = 0,
	};

	/* When I create a Mach voucher with this recipe */
	/* Then we observe that we've emitted telemetry about the policy violation */
	enqueue_ipc_triage_policy_violation_and_expect_continue_call((ipc_triage_policy_violation_and_expect_continue_call){
		.expected_policy = IPC_SEC_POLICY_RESTRICT_VOUCHER_OPERATIONS,
		.expected_maybe_ca_aux_data = 7,
	});

	ipc_voucher_t voucher;
	kern_return_t kr = host_create_mach_voucher(host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&recipe,
	    sizeof(recipe), &voucher);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");

	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();
}

T_DECL(restricted_voucher_operation_non_esv3_does_not_emit_telemetry,
    "Ensure constructing a Mach voucher with restricted recipe operation does not telemetry if we're not ESv3")
{
	/* Given the current IPC space is less than ESv3 */
	SET_IPC_POLICY(IPC_POLICY_ENHANCED_V2);

	/* And a Mach voucher containing a recipe command outside the allow-list */
	mach_voucher_attr_recipe_data_t recipe = {
		.key                = MACH_VOUCHER_ATTR_KEY_ALL,
		.command            = MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_DISALLOWED,
		.previous_voucher   = MACH_VOUCHER_NAME_NULL,
		.content_size       = 0,
	};

	/* When I create a Mach voucher with this recipe */

	ipc_voucher_t voucher;
	kern_return_t kr = host_create_mach_voucher(host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&recipe,
	    sizeof(recipe), &voucher);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");

	/* Then no telemetry has been emitted, because the policy only applies to ESv3 spaces */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();
}

T_DECL(unrestricted_voucher_operation_does_not_emit_telemetry,
    "Ensure constructing a Mach voucher without a restricted recipe operation does not emit telemetry")
{
	/* Given a Mach voucher containing a recipe command inside the allow-list */
	mach_voucher_attr_recipe_data_t recipe = {
		.key                = MACH_VOUCHER_ATTR_KEY_ALL,
		.command            = MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_ALLOWED,
		.previous_voucher   = MACH_VOUCHER_NAME_NULL,
		.content_size       = 0,
	};

	/* When I create a Mach voucher with this recipe */
	ipc_voucher_t voucher;
	kern_return_t kr = host_create_mach_voucher(host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&recipe,
	    sizeof(recipe), &voucher);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");

	/* Then no telemetry has been emitted, because the recipe operation is allowed */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();
}

T_DECL(large_voucher_recipe_emits_telemetry,
    "Ensure constructing a Mach voucher with a large recipe emits telemetry")
{
	/*
	 * Given a Mach voucher containing a recipe size above the soft upper bound
	 * (Note that this size is more than we strictly need since
	 * the size of the attribute structure itself is also counted)
	 */
	size_t recipe_content_size = IPC_MACH_VOUCHER_RECIPE_SIZE_SOFT_LIMIT;
	size_t recipe_size = sizeof(mach_voucher_attr_recipe_data_t) + recipe_content_size;
	mach_voucher_attr_recipe_data_t* recipe = malloc(recipe_size);
	*recipe = (mach_voucher_attr_recipe_data_t){
		.key                = MACH_VOUCHER_ATTR_KEY_ALL,
		.command            = MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_ALLOWED,
		.previous_voucher   = MACH_VOUCHER_NAME_NULL,
		.content_size       = IPC_MACH_VOUCHER_RECIPE_SIZE_SOFT_LIMIT,
	};

	/* When I create a Mach voucher with this recipe */
	/* Then we observe that we've emitted telemetry about the policy violation */
	enqueue_ipc_triage_policy_violation_and_expect_continue_call((ipc_triage_policy_violation_and_expect_continue_call){
		.expected_policy = IPC_SEC_POLICY_RESTRICT_VOUCHER_RECIPE_SIZE,
		.expected_maybe_ca_aux_data = IPC_MACH_VOUCHER_RECIPE_SIZE_SOFT_LIMIT + sizeof(mach_voucher_attr_recipe_data_t),
	});

	ipc_voucher_t voucher;
	kern_return_t kr = host_create_mach_voucher(host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)recipe,
	    recipe_size, &voucher);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	free(recipe);
}

T_DECL(large_voucher_non_esv3_does_not_emit_telemetry,
    "Ensure constructing a Mach voucher with a large recipe does not telemetry if we're not ESv3")
{
	/* Given the current IPC space is less than ESv3 */
	SET_IPC_POLICY(IPC_POLICY_ENHANCED_V2);

	/*
	 * And a Mach voucher containing a recipe size above the soft upper bound
	 * (Note that this size is more than we strictly need since
	 * the size of the attribute structure itself is also counted)
	 */
	size_t recipe_content_size = IPC_MACH_VOUCHER_RECIPE_SIZE_SOFT_LIMIT;
	size_t recipe_size = sizeof(mach_voucher_attr_recipe_data_t) + recipe_content_size;
	mach_voucher_attr_recipe_data_t* recipe = malloc(recipe_size);
	*recipe = (mach_voucher_attr_recipe_data_t){
		.key                = MACH_VOUCHER_ATTR_KEY_ALL,
		.command            = MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_ALLOWED,
		.previous_voucher   = MACH_VOUCHER_NAME_NULL,
		.content_size       = IPC_MACH_VOUCHER_RECIPE_SIZE_SOFT_LIMIT,
	};

	/* When I create a Mach voucher with this recipe */
	ipc_voucher_t voucher;
	kern_return_t kr = host_create_mach_voucher(host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)recipe,
	    recipe_size, &voucher);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");

	/* Then no telemetry has been emitted, because the policy only applies to ESv3 spaces */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();

	free(recipe);
}

T_DECL(small_voucher_recipe_emits_telemetry,
    "Ensure constructing a Mach voucher with a small recipe does not emit telemetry")
{
	/* Given a Mach voucher containing a recipe size below the soft upper bound */
	mach_voucher_attr_recipe_data_t recipe = {
		.key                = MACH_VOUCHER_ATTR_KEY_ALL,
		.command            = MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_ALLOWED,
		.previous_voucher   = MACH_VOUCHER_NAME_NULL,
		.content_size       = 0,
	};

	/* When I create a Mach voucher with this recipe */
	ipc_voucher_t voucher;
	kern_return_t kr = host_create_mach_voucher(host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&recipe,
	    sizeof(recipe), &voucher);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");

	/* Then we do not observe telemetry, because the policy has not been violated */
	assert_empty_ipc_triage_policy_violation_and_expect_continue_call();
}
