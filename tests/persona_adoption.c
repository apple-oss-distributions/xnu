#include <darwintest.h>
#include <darwintest_multiprocess.h>

#include <bank/bank_types.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_voucher.h>
#include <mach/mach_voucher_types.h>
#include <os/voucher_private.h>
#include <sys/kauth.h>
#include <sys/persona.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <uuid/uuid.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.persona_adoption"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ENABLED(!TARGET_OS_WATCH) // rdar://81809878
	);

static uid_t
_persona_create(int persona_type, uid_t persona_uid)
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
	snprintf(pinfo.persona_name, MAXLOGNAME, "persona_adoption_test.%s", uuid_string);

	uid_t persona_id = 0;
	int ret = kpersona_alloc(&pinfo, &persona_id);
	T_WITH_ERRNO; T_ASSERT_EQ(ret, 0, NULL);
	T_ASSERT_GT(persona_id, 0, NULL);

	return persona_id;
}

static kern_return_t
_persona_try_adopting(uid_t persona_id)
{
	struct proc_uniqidentifierinfo uniqidinfo;
	int error = proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo));
	T_ASSERT_GT(error, 0, NULL);

	struct persona_modify_info pmi = {
		.persona_id = persona_id,
		.unique_pid = uniqidinfo.p_uniqueid,
	};

	mach_voucher_t current_voucher = MACH_VOUCHER_NULL;
	kern_return_t kr = mach_voucher_persona_self(&current_voucher);
	T_ASSERT_EQ(kr, 0, NULL);
	T_ASSERT_NE(current_voucher, MACH_VOUCHER_NULL, NULL);

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
	if (kr != 0) {
		return kr;
	}
	T_ASSERT_NE(mach_voucher, MACH_VOUCHER_NULL, NULL);

	/* Verify that persona is set on the voucher */
	uint32_t voucher_persona;
	mach_voucher_attr_content_t content_out = (mach_voucher_attr_content_t)&voucher_persona;
	mach_voucher_attr_content_size_t content_out_size = sizeof(voucher_persona);
	kr = mach_voucher_attr_command(mach_voucher, MACH_VOUCHER_ATTR_KEY_BANK, BANK_PERSONA_ID, NULL, 0, content_out, &content_out_size);
	if (kr != 0) {
		return kr;
	}
	T_ASSERT_EQ(voucher_persona, persona_id, NULL);

	kr = thread_set_mach_voucher(mach_thread_self(), mach_voucher);
	return kr;
}

T_DECL(persona_with_matching_uid_can_be_adopted,
    "persona with UID matching at-spawn value can be adopted")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	if (error != 0) {
		T_SKIP("Test requrires to be running in a persona, skipping");
	}

	uid_t created_persona = _persona_create(PERSONA_MANAGED, info.persona_uid);
	kern_return_t kr = _persona_try_adopting(created_persona);
	T_ASSERT_EQ(kr, 0, NULL);

	uid_t current_persona = PERSONA_ID_NONE;
	T_ASSERT_EQ(kpersona_get(&current_persona), 0, NULL);
	T_ASSERT_EQ(current_persona, created_persona, NULL);

	T_ASSERT_EQ(kpersona_dealloc(created_persona), 0, NULL);
}

T_DECL(persona_with_mismatched_uid_cannot_be_adopted,
    "persona with UID that doesn't match at-spawn value cannot be adopted")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	if (error != 0) {
		T_SKIP("Test requrires to be running in a persona, skipping");
	}

	uid_t mismatched_uid = info.persona_uid + 1;
	uid_t created_persona = _persona_create(PERSONA_MANAGED, mismatched_uid);
	kern_return_t kr = _persona_try_adopting(created_persona);
	T_ASSERT_NE(kr, 0, NULL);

	uid_t current_persona = PERSONA_ID_NONE;
	T_ASSERT_EQ(kpersona_get(&current_persona), 0, NULL);
	T_ASSERT_EQ(current_persona, info.persona_id, NULL);

	T_ASSERT_EQ(kpersona_dealloc(created_persona), 0, NULL);
}

#if !TARGET_OS_BRIDGE // PersonaEnterprise is not supported on bridgeOS

static uid_t _helper_persona = PERSONA_ID_NONE;

static void
_run_helper_in_persona_cleanup(void)
{
	kpersona_dealloc(_helper_persona);
}

static void __attribute__((noreturn))
_run_helper_in_persona(const char *helper_name, int persona_type)
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	uid_t persona_uid = (error == 0) ? info.persona_uid : geteuid();
	_helper_persona = _persona_create(persona_type, persona_uid);
	T_ATEND(_run_helper_in_persona_cleanup);

	xpc_object_t plist = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(plist, "RunAtLoad", true);
	xpc_dictionary_set_int64(plist, "PersonaEnterprise", _helper_persona);
	dt_helper_t helper = dt_launchd_helper_plist(plist, helper_name, LAUNCH_SYSTEM_DOMAIN, NULL, NULL);

	dt_run_helpers(&helper, 1, 300);
}

T_HELPER_DECL(own_persona_can_be_adopted_impl,
    "own_persona_can_be_adopted helper spawned into persona type that prohibits adoption")
{
	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(0, &info);
	T_ASSERT_EQ(error, 0, NULL);

	kern_return_t kr = _persona_try_adopting(info.persona_id);
	T_ASSERT_EQ(kr, 0, NULL);
}

T_DECL(own_persona_can_be_adopted,
    "process spawned into a persona type that prohibits adoption can adopt own persona")
{
	_run_helper_in_persona("own_persona_can_be_adopted_impl", PERSONA_MANAGED);
}

#endif // TARGET_OS_BRIDGE
