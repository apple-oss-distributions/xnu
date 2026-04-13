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
	T_META_ENABLED(!TARGET_OS_WATCH && !TARGET_OS_BRIDGE)
	);

T_HELPER_DECL(persona_no_inherit_helper,
    "helper with no.inherit entitlement attempts persona adoption")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);

	/* Launch persona should still be active. */
	T_ASSERT_EQ(error, 0, "running in a persona");

	uid_t current_persona = info.persona_id;
	T_LOG("Helper running in persona %u", current_persona);

	uid_t target_persona = persona_create(PERSONA_SYSTEM, info.persona_uid, "no_inherit_target");
	T_LOG("Created target persona %u, attempting to adopt it", target_persona);

	/*
	 * Try to adopt the persona. The voucher adoption should still succeed as a whole,
	 * without adopting the persona. Therefore this should fail silently.
	 */
	kern_return_t kr = persona_try_adopting(target_persona);
	T_ASSERT_NE(kr, 0, "voucher adoption should succeed with no.inherit entitlement");

	/* Verify that the voucher adoption didn't have any effect. */
	uid_t check_persona = PERSONA_ID_NONE;
	T_ASSERT_EQ(kpersona_get(&check_persona), 0, "kpersona_get");
	T_ASSERT_EQ(check_persona, current_persona, "should still be in original persona");

	T_ASSERT_EQ(kpersona_dealloc(target_persona), 0, "kpersona_dealloc");
}

T_DECL(persona_adoption_no_inherit,
    "process with com.apple.private.personas.no.inherit entitlement cannot adopt persona",
    T_META_TAG_VM_PREFERRED, T_META_ASROOT(true))
{
	persona_test_setup(PERSONA_SYSTEM, "no_inherit_test");
	persona_spawn_helper("persona_no_inherit_helper");
}
