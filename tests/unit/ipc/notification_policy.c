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
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/mock_dynamic.h"

#include "ipc/utils/mach_port_construct_helpers.h"
#include "ipc/utils/ipc_policy_helpers.h"

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

extern mach_msg_return_t
ipc_validate_local_port(
	mach_port_t         reply_port,
	mach_port_t         dest_port,
	mach_msg_option64_t opts);

/*
 * Test: Construct some port types and assert they are valid for a given security policy
 */
// T_DECL(port_destroyed_registration_policy,
//     "Test ipc_allow_register_pd_notification port destroyed registration security policy")
// {
//      mach_port_name_t name;
//      mach_port_t port = ipc_create_port_with_type(TEST_IOT_NOTIFICATION_PORT, &name);

//      kern_return_t kr = ipc_allow_register_pd_notification(port, MACH_PORT_NULL);
//      T_ASSERT_MACH_ERROR(KERN_INVALID_RIGHT, kr, "pd disallowed on ports without pol_notif_port_destroy");
// }

T_DECL(
	ipc_should_apply_policy_example,
	"example usage of SET_IPC_POLICY macro to control the current IPC security "
	"policy") {
	/* Array of all policy flags to test */
	ipc_space_policy_t all_policies[] = {
		IPC_SPACE_POLICY_DEFAULT,
		IPC_SPACE_POLICY_PLATFORM,
		IPC_SPACE_POLICY_CONTAINED,
		IPC_SPACE_POLICY_KERNEL,
		IPC_SPACE_POLICY_SIMULATED,
		IPC_SPACE_POLICY_TRANSLATED,
		IPC_SPACE_POLICY_OPTED_OUT,
		IPC_POLICY_ENHANCED_V0,
		IPC_POLICY_ENHANCED_V1,
		IPC_POLICY_ENHANCED_V2,
		IPC_POLICY_ENHANCED_V3,
	};

	const char *policy_names[] = {
		"IPC_SPACE_POLICY_DEFAULT",
		"IPC_SPACE_POLICY_PLATFORM",
		"IPC_SPACE_POLICY_CONTAINED",
		"IPC_SPACE_POLICY_KERNEL",
		"IPC_SPACE_POLICY_SIMULATED",
		"IPC_SPACE_POLICY_TRANSLATED",
		"IPC_SPACE_POLICY_OPTED_OUT",
		"IPC_POLICY_ENHANCED_V0",
		"IPC_POLICY_ENHANCED_V1",
		"IPC_POLICY_ENHANCED_V2",
		"IPC_POLICY_ENHANCED_V3",
	};

	size_t num_policies = countof(all_policies);

	/*
	 * For each policy, set it as the current policy and verify original and mock functionality:
	 * 1. ipc_should_apply_policy returns true when checking for that policy
	 * 2. ipc_should_apply_policy returns false for all other policies
	 * special cases exist for enhanced, simulated, translated, and opted-out
	 */
	for (size_t i = 0; i < num_policies; i++) {
		ipc_space_policy_t current_policy = all_policies[i];
		SET_IPC_POLICY(current_policy);

		for (size_t j = 0; j < num_policies; j++) {
			ipc_space_policy_t test_policy = all_policies[j];
			bool mock_ret = T_MOCK_MOCK(ipc_should_apply_policy)(current_policy, test_policy);
			bool actual_ret = T_MOCK_ORIGINAL(ipc_should_apply_policy)(IPC_SPACE_POLICY_DEFAULT | current_policy, test_policy);

			T_EXPECT_EQ(mock_ret, actual_ret,
			    "the mock implementation and the real implementation should "
			    "match cur=%s req=%s",
			    policy_names[i], policy_names[j]);

			if (current_policy == IPC_SPACE_POLICY_SIMULATED ||
			    current_policy == IPC_SPACE_POLICY_TRANSLATED ||
			    current_policy == IPC_SPACE_POLICY_OPTED_OUT) {
				/* Should return false for simulated, translated, opted out */
				T_EXPECT_FALSE(mock_ret, "%s should return false for %s",
				    policy_names[i], policy_names[j]);
			} else if (test_policy >= IPC_POLICY_ENHANCED_V0 &&
			    current_policy >= IPC_POLICY_ENHANCED_V0 &&
			    test_policy <= current_policy) {
				/* Should return true when asking for ENHANCED_Vx where x is less than or equal to the current policy */
				T_EXPECT_TRUE(mock_ret, "%s should return true for %s", policy_names[i],
				    policy_names[j]);
			} else if (test_policy == IPC_SPACE_POLICY_DEFAULT) {
				/* all spaces have IPC_SPACE_POLICY_DEFAULT */
				T_EXPECT_TRUE(mock_ret, "%s should return true for %s", policy_names[i],
				    policy_names[j]);
			} else if (i == j) {
				/* Should return true when testing the same policy that was set */
				T_EXPECT_TRUE(mock_ret, "%s should return true for %s", policy_names[i],
				    policy_names[j]);
			} else {
				/* Should return false when testing a different policy */
				T_EXPECT_FALSE(mock_ret, "%s should return false for %s",
				    policy_names[i], policy_names[j]);
			}
		}
	}
}

T_DECL(
	ipc_should_apply_policy_rejects_version_bits_without_enhanced,
	"ipc_should_apply_policy must panic if requested_level has version bits "
	"but not IPC_SPACE_POLICY_ENHANCED") {
	/*
	 * Passing a raw IPC_SPACE_POLICY_ENHANCED_V* constant (version bits only,
	 * no IPC_SPACE_POLICY_ENHANCED flag) is the classic caller mistake —
	 * the correct constants are IPC_POLICY_ENHANCED_V* which OR in the ENHANCED
	 * flag.  The assert at the top of ipc_should_apply_policy() must catch this.
	 */
	T_ASSERT_PANIC({
		T_MOCK_ORIGINAL(ipc_should_apply_policy)(
			IPC_SPACE_POLICY_DEFAULT,
			IPC_SPACE_POLICY_ENHANCED_V1);
	}, "passing version bits without IPC_SPACE_POLICY_ENHANCED should panic");

	T_ASSERT_PANIC({
		T_MOCK_ORIGINAL(ipc_should_apply_policy)(
			IPC_SPACE_POLICY_DEFAULT,
			IPC_SPACE_POLICY_ENHANCED_V2);
	}, "passing version bits without IPC_SPACE_POLICY_ENHANCED should panic");

	T_ASSERT_PANIC({
		T_MOCK_ORIGINAL(ipc_should_apply_policy)(
			IPC_SPACE_POLICY_DEFAULT,
			IPC_SPACE_POLICY_ENHANCED_V3);
	}, "passing version bits without IPC_SPACE_POLICY_ENHANCED should panic");
}

#define CONSTRUCTION_REQUIRE_ENTITLMENT(type) \
	(type) == TEST_IOT_WEAK_REPLY_PORT || \
	(type) == TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY

static void
iterate_dest_reply_combination(
	const port_type_desc_t *port_types,
	ipc_space_policy_t current_policy)
{
	mach_port_name_t reply_name, dest_name;
	mach_port_t reply_port, dest_port;
	mach_msg_return_t mr;

	for (ipc_test_port_type_t reply_type = 0; reply_type < TEST_PORT_TYPE_COUNT; reply_type++) {
		for (ipc_test_port_type_t dest_type = 0; dest_type < TEST_PORT_TYPE_COUNT; dest_type++) {
			if (CONSTRUCTION_REQUIRE_ENTITLMENT(reply_type) ||
			    CONSTRUCTION_REQUIRE_ENTITLMENT(dest_type)) {
				continue;
			}

			reply_port = ipc_create_port_with_type(reply_type, &reply_name);
			dest_port = ipc_create_port_with_type(dest_type, &dest_name);

			mr = ipc_validate_local_port(reply_port, dest_port, MACH64_MSG_OPTION_NONE);

			bool dest_enforces_reply_semantics = ip_has_reply_port_semantics(dest_port);
			bool reply_is_reply_port_type = ip_is_reply_port(reply_port) || ip_is_weak_reply_port(reply_port);
			bool should_fail = false;

			if (ip_is_kobject(dest_port)) {
				/* kobject enforcement - weak reply port aren't allowed */
				if (ipc_should_apply_policy(current_policy, IPC_POLICY_ENHANCED_V1) &&
				    !ip_is_reply_port(reply_port)) {
					should_fail = true;
				}
			} else if (ip_is_bootstrap_port(dest_port)) {
				/* bootstrap port enforcement */
				if (ipc_should_apply_policy(current_policy, IPC_POLICY_ENHANCED_V2) &&
				    !reply_is_reply_port_type) {
					should_fail = true;
				}
			} else if (dest_enforces_reply_semantics && !reply_is_reply_port_type) {
				/* general enforcement */
				should_fail = true;
			}

			if (should_fail) {
				T_EXPECT_EQ((mr), MACH_SEND_INVALID_REPLY,
				    "reply_port=%s dest_port=%s: reply semantics violation should fail",
				    port_types[reply_type].port_type_name,
				    port_types[dest_type].port_type_name);
			} else {
				T_EXPECT_EQ((mr), MACH_MSG_SUCCESS,
				    "reply_port=%s dest_port=%s: should be allowed",
				    port_types[reply_type].port_type_name,
				    port_types[dest_type].port_type_name);
			}

			ipc_deallocate_port(reply_type, reply_port, reply_name);
			reply_port = MACH_PORT_NULL;
			ipc_deallocate_port(dest_type, dest_port, dest_name);
			dest_port = MACH_PORT_NULL;
		}
	}
}


T_DECL(test_ipc_validate_local_port, "Test ipc_validate_local_port")
{
	mach_port_name_t reply_name, dest_name;
	mach_port_t reply_port, dest_port;
	mach_msg_return_t mr;

	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT);

	const port_type_desc_t *port_types = ipc_get_all_port_types();

	/* Test with null reply port first - should always succeed */
	for (ipc_test_port_type_t type = 0; type < TEST_PORT_TYPE_COUNT; type++) {
		dest_port = ipc_create_port_with_type(type, &dest_name);
		mr = ipc_validate_local_port(NULL, dest_port, MACH64_MSG_OPTION_NONE);
		T_EXPECT_EQ(mr, MACH_MSG_SUCCESS,
		    "null reply port should be ok for dest_port type: %s",
		    port_types[type].port_type_name);

		ipc_deallocate_port(type, dest_port, dest_name);
	}

	/* Test that simulated and translated processes are exempt from policy */
	mach_port_t service_port = ipc_create_port_with_type(TEST_IOT_SERVICE_PORT, &dest_name);

	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT);
	mr = ipc_validate_local_port(service_port, service_port, MACH64_MSG_OPTION_NONE);
	T_EXPECT_EQ(mr, MACH_SEND_INVALID_REPLY, "no reply port type with a service port should be invalid");

	SET_IPC_POLICY(IPC_SPACE_POLICY_SIMULATED);
	mr = ipc_validate_local_port(service_port, service_port, MACH64_MSG_OPTION_NONE);
	T_EXPECT_EQ(mr, MACH_MSG_SUCCESS, "simulated processes are exempt from such policy");

	SET_IPC_POLICY(IPC_SPACE_POLICY_TRANSLATED);
	mr = ipc_validate_local_port(service_port, service_port, MACH64_MSG_OPTION_NONE);
	T_EXPECT_EQ(mr, MACH_MSG_SUCCESS, "translated processes are exempt from such policy");
	ipc_deallocate_port(TEST_IOT_SERVICE_PORT, service_port, dest_name);
	service_port = MACH_PORT_NULL;

	/*
	 * Test all combinations of reply port types and destination port types.
	 * Expected behavior based on ipc_validate_local_port:
	 * - If dest_port does not have reply port semantic enforcement: SUCCESS
	 * - If dest_port does have reply port semantic enforcement:
	 *   - If reply_port is weak reply port: SUCCESS
	 *   - Otherwise: MACH_SEND_INVALID_REPLY
	 */

	T_LOG("Testing all combination for IPC_SPACE_POLICY_DEFAULT");
	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT);
	iterate_dest_reply_combination(port_types, IPC_SPACE_POLICY_DEFAULT);

	T_LOG("Testing all combination for IPC_POLICY_ENHANCED_V1");
	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT | IPC_POLICY_ENHANCED_V1);
	iterate_dest_reply_combination(port_types, IPC_POLICY_ENHANCED_V1);

	T_LOG("Testing all combination for IPC_POLICY_ENHANCED_V2");
	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT | IPC_POLICY_ENHANCED_V2);
	iterate_dest_reply_combination(port_types, IPC_POLICY_ENHANCED_V2);

	T_LOG("Testing all combination for IPC_POLICY_ENHANCED_V3");
	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT | IPC_POLICY_ENHANCED_V3);
	iterate_dest_reply_combination(port_types, IPC_POLICY_ENHANCED_V3);
}
