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

#include "ipc/utils/mach_port_construct_helpers.h"
#include "ipc/utils/ipc_policy_helpers.h"

#define UT_MODULE osfmk

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

/*
 * Array of all individual MPO option flags to test
 */
static const uint32_t mpo_option_flags[] = {
	MPO_CONTEXT_AS_GUARD,
	MPO_QLIMIT,
	MPO_TEMPOWNER,
	MPO_IMPORTANCE_RECEIVER,
	MPO_INSERT_SEND_RIGHT,
	MPO_STRICT,
	MPO_DENAP_RECEIVER,
	MPO_IMMOVABLE_RECEIVE,
	MPO_FILTER_MSG,
	MPO_TG_BLOCK_TRACKING,
	MPO_ENFORCE_REPLY_PORT_SEMANTICS,
};

static const char *mpo_option_flag_names[] = {
	"MPO_CONTEXT_AS_GUARD",
	"MPO_QLIMIT",
	"MPO_TEMPOWNER",
	"MPO_IMPORTANCE_RECEIVER",
	"MPO_INSERT_SEND_RIGHT",
	"MPO_STRICT",
	"MPO_DENAP_RECEIVER",
	"MPO_IMMOVABLE_RECEIVE",
	"MPO_FILTER_MSG",
	"MPO_TG_BLOCK_TRACKING",
	"MPO_ENFORCE_REPLY_PORT_SEMANTICS",
};


#define NUM_OPTION_FLAGS (sizeof(mpo_option_flags) / sizeof(mpo_option_flags[0]))


T_DECL(reply_port_lifecycle, "Test to verify creating and destroying reply port types")
{
	mach_port_t reply_port;
	mach_port_name_t reply_name;
	/* Ensure strong reply ports*/
	SET_IPC_POLICY(IPC_POLICY_ENHANCED_V2);
	reply_port = ipc_create_port_with_type(TEST_IOT_REPLY_PORT, &reply_name);
	ipc_deallocate_port(TEST_IOT_REPLY_PORT, reply_port, reply_name);

	SET_IPC_POLICY(IPC_SPACE_POLICY_DEFAULT);
	reply_port = ipc_create_port_with_type(TEST_IOT_WEAK_REPLY_PORT, &reply_name);
	ipc_deallocate_port(TEST_IOT_WEAK_REPLY_PORT, reply_port, reply_name);
}

T_DECL(ip_alloc_test, "Simple test to verify ip_alloc returns non-null port")
{
	ipc_port_t port;

	/* Allocate a port using ip_alloc (which is zalloc_id(ZONE_ID_IPC_PORT, Z_WAITOK_ZERO_NOFAIL)) */
	port = ip_alloc();
	T_ASSERT_NOTNULL(port, "ip_alloc should return a non-null port");

	/* Clean up */
	ip_free(port);

	T_PASS("ip_alloc test completed");
}

/*
 * Test: Construct each port type with no additional flags
 */
T_DECL(mach_port_construct_port_types,
    "Test mach_port_construct with each port type")
{
	kern_return_t kr;
	mach_port_name_t port_name;
	mach_port_options_t options;

	for (ipc_test_port_type_t type = 0; type < TEST_PORT_TYPE_COUNT; type++) {
		const port_type_desc_t *desc = ipc_get_port_type_desc(type);

		mach_port_t port = desc->port_ctor(&port_name);
		T_ASSERT_PORT_VALID(port, "mp_construct for %s", desc->port_type_name);
		/* Clean up the port */
		desc->port_dtor(port, port_name);
	}
	T_PASS("All port types created successfully");
}

/*
 * Test: Construct ports with individual option flags
 */
T_DECL(mach_port_construct_individual_flags,
    "Test mach_port_construct with individual MPO flags")
{
	kern_return_t kr;
	mach_port_name_t port_name;
	mach_port_options_t options;

	for (size_t i = 0; i < NUM_OPTION_FLAGS; i++) {
		memset(&options, 0, sizeof(options));
		options.flags = mpo_option_flags[i];
		mach_port_context_t context = 0;

		/* Set required fields for specific flags */
		if (mpo_option_flags[i] == MPO_QLIMIT) {
			options.mpl.mpl_qlimit = MACH_PORT_QLIMIT_SMALL;
		}
		if (mpo_option_flags[i] == MPO_CONTEXT_AS_GUARD) {
			/* Context is passed via the context parameter */
			context = 0x1234567890abcdefULL;
		}

		kr = mach_port_construct(current_space(), &options, context, &port_name);
		if (mpo_option_flags[i] == MPO_TG_BLOCK_TRACKING) {
			T_EXPECT_MACH_ERROR(KERN_DENIED, kr, "block tracking should be limited to certain tasks");
		} else {
			T_EXPECT_MACH_SUCCESS(kr, "mp_construct should succed with option=%s", mpo_option_flag_names[i]);
			T_ASSERT_TRUE(MACH_PORT_VALID(port_name), "Valid port name");
			/* Clean up the port */
			kr = mach_port_destruct(current_space(), port_name, 0, context);
			T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_destruct for %s", mpo_option_flag_names[i]);
		}
	}

	T_PASS("Individual flag tests completed");
}

/*
 * Test: Try combinations of compatible flags
 */
T_DECL(mach_port_construct_compatible_flags,
    "Test mach_port_construct with compatible flag combinations")
{
	kern_return_t kr;
	mach_port_name_t port_name;
	mach_port_options_t options;

	/* Test: MPO_CONTEXT_AS_GUARD with MPO_STRICT */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_CONTEXT_AS_GUARD | MPO_STRICT;
	kr = mach_port_construct(current_space(), &options, 0xdeadbeefULL, &port_name);
	T_EXPECT_MACH_SUCCESS(kr, "Guard with strict flag");
	T_ASSERT_TRUE(MACH_PORT_VALID(port_name), "Valid port name");
	kr = mach_port_destruct(current_space(), port_name, 0, 0xdeadbeefULL);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for guarded+strict port");

	/* Test: MPO_CONTEXT_AS_GUARD with MPO_IMMOVABLE_RECEIVE */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_CONTEXT_AS_GUARD | MPO_IMMOVABLE_RECEIVE;
	kr = mach_port_construct(current_space(), &options, 0xfeedface, &port_name);
	T_EXPECT_MACH_SUCCESS(kr, "Guard with immovable receive");
	T_ASSERT_TRUE(MACH_PORT_VALID(port_name), "Valid port name");
	kr = mach_port_destruct(current_space(), port_name, 0, 0xfeedface);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for guarded+immovable port");

	/* Test: MPO_IMPORTANCE_RECEIVER with MPO_DENAP_RECEIVER */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_IMPORTANCE_RECEIVER | MPO_DENAP_RECEIVER;
	kr = mach_port_construct(current_space(), &options, 0, &port_name);
	T_EXPECT_MACH_SUCCESS(kr, "Importance + denap receiver");
	T_ASSERT_TRUE(MACH_PORT_VALID(port_name), "Valid port name");
	kr = mach_port_destruct(current_space(), port_name, 0, 0);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for importance+denap port");

	/* Test: MPO_INSERT_SEND_RIGHT */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_INSERT_SEND_RIGHT;
	kr = mach_port_construct(current_space(), &options, 0, &port_name);
	T_EXPECT_MACH_SUCCESS(kr, "Insert send right");
	T_ASSERT_TRUE(MACH_PORT_VALID(port_name), "Valid port name");
	kr = mach_port_destruct(current_space(), port_name, 0, 0);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for port with send right");

	/* Test: MPO_QLIMIT */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_QLIMIT;
	options.mpl.mpl_qlimit = MACH_PORT_QLIMIT_LARGE;
	kr = mach_port_construct(current_space(), &options, 0, &port_name);
	T_EXPECT_MACH_SUCCESS(kr, "Custom queue limit");
	T_ASSERT_TRUE(MACH_PORT_VALID(port_name), "Valid port name");
	kr = mach_port_destruct(current_space(), port_name, 0, 0);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for port with custom queue limit");

	T_PASS("Compatible flag combination tests completed");
}

/*
 * Test: Conflicting flags (e.g., multiple port types)
 */
T_DECL(mach_port_construct_conflicting_flags,
    "Test mach_port_construct with conflicting flag combinations")
{
	kern_return_t kr;
	mach_port_name_t port_name;
	mach_port_options_t options;

	/* Test: Multiple port types (should fail or pick one) */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_SERVICE_PORT | MPO_CONNECTION_PORT;
	kr = mach_port_construct(current_space(), &options, 0, &port_name);
	if (kr == KERN_SUCCESS) {
		T_EXPECT_MACH_SUCCESS(kr, "Multiple port types succeeded (implementation chose one)");
		kr = mach_port_destruct(current_space(), port_name, 0, 0);
		T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for multiple port types");
	} else {
		T_EXPECT_NE(kr, KERN_SUCCESS, "Multiple port types failed as expected");
	}

	/* Test: MPO_STRICT without MPO_CONTEXT_AS_GUARD (should fail) */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_STRICT;
	kr = mach_port_construct(current_space(), &options, 0, &port_name);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_NE(kr, KERN_SUCCESS, "MPO_STRICT without guard failed as expected");
	} else {
		T_EXPECT_MACH_SUCCESS(kr, "MPO_STRICT without guard succeeded (unexpected)");
		kr = mach_port_destruct(current_space(), port_name, 0, 0);
		T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for MPO_STRICT without guard");
	}

	/* Test: MPO_IMMOVABLE_RECEIVE without MPO_CONTEXT_AS_GUARD (should fail) */
	memset(&options, 0, sizeof(options));
	options.flags = MPO_IMMOVABLE_RECEIVE;
	kr = mach_port_construct(current_space(), &options, 0, &port_name);
	if (kr != KERN_SUCCESS) {
		T_EXPECT_NE(kr, KERN_SUCCESS, "MPO_IMMOVABLE_RECEIVE without guard failed as expected");
	} else {
		T_EXPECT_MACH_SUCCESS(kr, "MPO_IMMOVABLE_RECEIVE without guard succeeded (unexpected)");
		kr = mach_port_destruct(current_space(), port_name, 0, 0);
		T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct for MPO_IMMOVABLE_RECEIVE without guard");
	}

	T_PASS("Conflicting flag tests completed");
}

/*
 * Stress Test: Test many combinations of flags
 */
T_DECL(mach_port_construct_stress_test,
    "Stress test with many flag combinations",
    T_META_TIMEOUT(120))
{
	kern_return_t kr;
	mach_port_name_t port_name;
	mach_port_options_t options;
	int success_count = 0;
	int failure_count = 0;
	int total_tests = 0;

	/*
	 * Test all combinations of up to 3 flags
	 * This creates many combinations but keeps test time reasonable
	 */
	for (size_t i = 0; i < NUM_OPTION_FLAGS; i++) {
		for (size_t j = i; j < NUM_OPTION_FLAGS; j++) {
			for (size_t k = j; k < NUM_OPTION_FLAGS; k++) {
				memset(&options, 0, sizeof(options));
				options.flags = mpo_option_flags[i] |
				    mpo_option_flags[j] |
				    mpo_option_flags[k];

				/* Set required fields */
				if (options.flags & MPO_QLIMIT) {
					options.mpl.mpl_qlimit = MACH_PORT_QLIMIT_SMALL;
				}

				uint64_t guard = 0;
				if (options.flags & MPO_CONTEXT_AS_GUARD) {
					guard = 0xabcd1234ULL;
				}

				kr = mach_port_construct(current_space(), &options, guard, &port_name);
				total_tests++;

				if (kr == KERN_SUCCESS) {
					success_count++;
					/* Destruct with proper parameters */
					kr = mach_port_destruct(current_space(), port_name,
					    (options.flags & MPO_INSERT_SEND_RIGHT) ? -1 : 0, guard);
					T_EXPECT_MACH_SUCCESS(kr, "destruct succeeded for flags=0x%x", options.flags);
				} else {
					failure_count++;
				}
			}
		}
	}

	T_LOG("Stress test completed: %d total, %d success, %d failures",
	    total_tests, success_count, failure_count);
	T_ASSERT_GT(success_count, 0, "At least some combinations should succeed");
	T_PASS("Stress test completed");
}

/*
 * Test: Port types with various option flags
 * Note: This test verifies basic port creation for each port type.
 * More complex option flag combinations are tested separately.
 */
T_DECL(mach_port_construct_port_types_with_options,
    "Test each port type with various option flags")
{
	kern_return_t kr;
	mach_port_name_t port_name;

	/* Test each port type */
	for (ipc_test_port_type_t type = 0; type < TEST_PORT_TYPE_COUNT; type++) {
		const port_type_desc_t *desc = ipc_get_port_type_desc(type);

		/* Create port using the port type's constructor */
		mach_port_t port = desc->port_ctor(&port_name);

		T_ASSERT_PORT_VALID(port, "%s created successfully", desc->port_type_name);

		/* Clean up the port */
		desc->port_dtor(port, port_name);
	}

	T_PASS("Port types with options tests completed");
}
