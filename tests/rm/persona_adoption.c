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
#include "persona_test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.rm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("RM"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ENABLED(!TARGET_OS_WATCH)
	);

T_HELPER_DECL(persona_with_matching_uid_can_be_adopted_helper,
    "helper to test persona with matching UID can be adopted")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	T_ASSERT_EQ(error, 0, "running in a persona");

	uid_t created_persona = persona_create(PERSONA_SYSTEM, info.persona_uid, "matching_uid");
	kern_return_t kr = persona_try_adopting(created_persona);
	T_ASSERT_MACH_SUCCESS(kr, "persona adoption with matching UID should succeed");

	uid_t current_persona = PERSONA_ID_NONE;
	T_ASSERT_EQ(kpersona_get(&current_persona), 0, "kpersona_get");
	T_ASSERT_EQ(current_persona, created_persona, "should be in created persona");

	T_ASSERT_EQ(kpersona_dealloc(created_persona), 0, "kpersona_dealloc");
}

T_DECL(persona_with_matching_uid_can_be_adopted,
    "persona with UID matching at-spawn value can be adopted",
    T_META_TAG_VM_PREFERRED, T_META_ASROOT(true))
{
	persona_test_setup(PERSONA_SYSTEM, "matching_uid_test");
	persona_spawn_helper("persona_with_matching_uid_can_be_adopted_helper");
}

T_HELPER_DECL(persona_with_mismatched_uid_cannot_be_adopted_helper,
    "helper to test persona with mismatched UID cannot be adopted")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	T_ASSERT_EQ(error, 0, "running in a persona");

	uid_t mismatched_uid = info.persona_uid + 1;
	uid_t created_persona = persona_create(PERSONA_SYSTEM, mismatched_uid, "mismatched_uid");
	kern_return_t kr = persona_try_adopting(created_persona);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "persona adoption with mismatched UID should fail");

	uid_t current_persona = PERSONA_ID_NONE;
	T_ASSERT_EQ(kpersona_get(&current_persona), 0, "kpersona_get");
	T_ASSERT_EQ(current_persona, info.persona_id, "should still be in original persona");

	T_ASSERT_EQ(kpersona_dealloc(created_persona), 0, "kpersona_dealloc");
}

T_DECL(persona_with_mismatched_uid_cannot_be_adopted,
    "persona with UID that doesn't match at-spawn value cannot be adopted",
    T_META_TAG_VM_PREFERRED, T_META_ASROOT(true))
{
	persona_test_setup(PERSONA_SYSTEM, "mismatched_uid_test");
	persona_spawn_helper("persona_with_mismatched_uid_cannot_be_adopted_helper");
}

#if !TARGET_OS_BRIDGE

T_HELPER_DECL(persona_adoption_helper,
    "helper process can adopt persona via voucher")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	T_ASSERT_EQ(error, 0, "running in a persona");

	kern_return_t kr = persona_try_adopting(info.persona_id);
	T_ASSERT_MACH_SUCCESS(kr, "process can adopt its own persona");

	uid_t target_persona = persona_create(PERSONA_SYSTEM, info.persona_uid, "adoption_target");
	T_LOG("Created target persona %u, attempting to adopt it", target_persona);

	kr = persona_try_adopting(target_persona);
	T_ASSERT_MACH_SUCCESS(kr, "persona adoption should succeed without no.inherit entitlement");

	uid_t check_persona = PERSONA_ID_NONE;
	T_ASSERT_EQ(kpersona_get(&check_persona), 0, "kpersona_get");
	T_ASSERT_EQ(check_persona, target_persona, "should now be in target persona");

	T_ASSERT_EQ(kpersona_dealloc(target_persona), 0, "kpersona_dealloc");
}

T_DECL(persona_adoption,
    "process can adopt persona via voucher",
    T_META_TAG_VM_PREFERRED, T_META_ASROOT(true))
{
	persona_test_setup(PERSONA_SYSTEM, "adoption_test");
	persona_spawn_helper("persona_adoption_helper");
}

#endif // TARGET_OS_BRIDGE
