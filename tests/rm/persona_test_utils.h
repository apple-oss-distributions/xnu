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
#ifndef _PERSONA_TEST_UTILS_H_
#define _PERSONA_TEST_UTILS_H_

#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <darwintest_utils.h>
#include <xpc/xpc.h>
#include <bank/bank_types.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_voucher.h>
#include <mach/mach_voucher_types.h>
#include <os/voucher_private.h>
#include <sys/kauth.h>
#include <sys/persona.h>
#include <sys/proc_info.h>
#include <uuid/uuid.h>

/* Global persona state for cleanup */
static uid_t _test_persona = PERSONA_ID_NONE;

static inline uid_t
persona_create(int persona_type, uid_t persona_uid, const char *name_prefix)
{
	struct kpersona_info pinfo = {
		.persona_info_version = PERSONA_INFO_V2,
		.persona_type = persona_type,
		.persona_uid = persona_uid,
	};

	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	snprintf(pinfo.persona_name, MAXLOGNAME, "%s.%s", name_prefix, uuid_string);

	uid_t persona_id = 0;
	int ret = kpersona_alloc(&pinfo, &persona_id);
	T_WITH_ERRNO; T_ASSERT_EQ(ret, 0, "kpersona_alloc");
	T_ASSERT_GT(persona_id, 0, "persona_id > 0");

	return persona_id;
}

static inline kern_return_t
persona_try_adopting(uid_t persona_id)
{
	struct proc_uniqidentifierinfo uniqidinfo;
	int error = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo));
	T_ASSERT_GT(error, 0, "proc_pidinfo");

	struct persona_modify_info pmi = {
		.persona_id = persona_id,
		.unique_pid = uniqidinfo.p_uniqueid,
	};

	mach_voucher_t current_voucher = MACH_VOUCHER_NULL;
	kern_return_t kr = mach_voucher_persona_self(&current_voucher);
	T_ASSERT_MACH_SUCCESS(kr, "mach_voucher_persona_self");
	T_ASSERT_NE(current_voucher, MACH_VOUCHER_NULL, "current_voucher != NULL");

	char voucher_buf[sizeof(mach_voucher_attr_recipe_data_t) + sizeof(pmi)];

	mach_voucher_attr_recipe_t recipe = (mach_voucher_attr_recipe_t)&voucher_buf[0];
	recipe->key = MACH_VOUCHER_ATTR_KEY_BANK;
	recipe->command = MACH_VOUCHER_ATTR_BANK_MODIFY_PERSONA;
	recipe->content_size = sizeof(pmi);
	recipe->previous_voucher = current_voucher;
	memcpy(recipe->content, (void *)&pmi, sizeof(pmi));

	mach_voucher_attr_raw_recipe_size_t recipe_size = sizeof(mach_voucher_attr_recipe_data_t) + recipe->content_size;
	mach_voucher_attr_raw_recipe_array_t recipes = (mach_voucher_attr_raw_recipe_array_t)&voucher_buf[0];
	mach_voucher_t mach_voucher = MACH_VOUCHER_NULL;
	kr = host_create_mach_voucher(mach_host_self(), recipes, recipe_size, &mach_voucher);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	T_ASSERT_NE(mach_voucher, MACH_VOUCHER_NULL, "mach_voucher != NULL");

	/* Verify that persona is set on the voucher */
	uint32_t voucher_persona;
	mach_voucher_attr_content_t content_out = (mach_voucher_attr_content_t)&voucher_persona;
	mach_voucher_attr_content_size_t content_out_size = sizeof(voucher_persona);
	kr = mach_voucher_attr_command(mach_voucher, MACH_VOUCHER_ATTR_KEY_BANK, BANK_PERSONA_ID, NULL, 0, content_out, &content_out_size);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	T_ASSERT_EQ(voucher_persona, persona_id, "voucher has correct persona_id");

	kr = thread_set_mach_voucher(mach_thread_self(), mach_voucher);
	return kr;
}

static inline void
persona_cleanup(void)
{
	if (_test_persona != PERSONA_ID_NONE) {
		kpersona_dealloc(_test_persona);
	}
}

static inline uid_t
persona_test_setup(int persona_type, const char *name_prefix)
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	uid_t persona_uid = (error == 0) ? info.persona_uid : geteuid();

	_test_persona = persona_create(persona_type, persona_uid, name_prefix);
	T_ATEND(persona_cleanup);

	T_LOG("Created test persona %u", _test_persona);
	return _test_persona;
}

static inline void
persona_spawn_helper(const char *helper_name)
{
	xpc_object_t plist = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(plist, "RunAtLoad", true);
	xpc_dictionary_set_int64(plist, "PersonaEnterprise", _test_persona);
	dt_helper_t helper = dt_launchd_helper_plist(plist, helper_name, LAUNCH_SYSTEM_DOMAIN, NULL, NULL);

	dt_run_helpers(&helper, 1, 300);
}

#endif /* _PERSONA_TEST_UTILS_H_ */
