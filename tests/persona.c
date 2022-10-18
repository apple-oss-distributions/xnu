#include <darwintest.h>

#include <sys/kauth.h>
#include <sys/persona.h>
#include <uuid/uuid.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.persona"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ENABLED(!TARGET_OS_WATCH) // rdar://81809878
	);

static uid_t
_create_persona(int persona_type, uint32_t persona_info_version)
{
	struct kpersona_info pinfo = {
		.persona_info_version = persona_info_version,
		.persona_type = persona_type,
	};

	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	snprintf(pinfo.persona_name, MAXLOGNAME, "persona_test.%s", uuid_string);

	uid_t persona_id = 0;
	int ret = kpersona_alloc(&pinfo, &persona_id);
	T_WITH_ERRNO; T_ASSERT_EQ(ret, 0, NULL);
	T_ASSERT_GT(persona_id, 0, NULL);

	return persona_id;
}

T_DECL(mutlipe_system_personas, "create multiple PERSONA_SYSTEM")
{
	uid_t first = _create_persona(PERSONA_SYSTEM, PERSONA_INFO_V1);
	uid_t second = _create_persona(PERSONA_SYSTEM, PERSONA_INFO_V1);

	T_ASSERT_NE(first, second, NULL);

	T_ASSERT_EQ(kpersona_dealloc(first), 0, NULL);
	T_ASSERT_EQ(kpersona_dealloc(second), 0, NULL);
}

T_DECL(mutlipe_system_proxy_personas, "create multiple PERSONA_SYSTEM_PROXY")
{
	uid_t first = _create_persona(PERSONA_SYSTEM_PROXY, PERSONA_INFO_V1);
	uid_t second = _create_persona(PERSONA_SYSTEM_PROXY, PERSONA_INFO_V1);

	T_ASSERT_NE(first, second, NULL);

	T_ASSERT_EQ(kpersona_dealloc(first), 0, NULL);
	T_ASSERT_EQ(kpersona_dealloc(second), 0, NULL);
}

T_DECL(persona_info_v2, "create and query persona PERSONA_INFO_V2")
{
	uid_t persona = _create_persona(PERSONA_MANAGED, PERSONA_INFO_V2);

	for (uint32_t version = PERSONA_INFO_V1; version <= PERSONA_INFO_V2; version++) {
		struct kpersona_info info = {
			.persona_info_version = version,
		};
		int error = kpersona_info(persona, &info);
		T_ASSERT_EQ(error, 0, "kpersona_info(v%d) error", version);
		T_ASSERT_EQ(info.persona_type, PERSONA_MANAGED, "kpersona_info(v%d) type", version);
		T_ASSERT_EQ(info.persona_info_version, version, "kpersona_info(v%d) version", version);
	}

	T_ASSERT_EQ(kpersona_dealloc(persona), 0, NULL);
}

T_DECL(persona_uid, "create a persona with a uid and fetch it")
{
	uid_t persona_uid = 501;
	struct kpersona_info pinfo = {
		.persona_info_version = PERSONA_INFO_V2,
		.persona_type = PERSONA_MANAGED,
		.persona_uid = persona_uid,
	};

	uuid_t uuid;
	uuid_generate(uuid);
	uuid_string_t uuid_string;
	uuid_unparse(uuid, uuid_string);
	snprintf(pinfo.persona_name, MAXLOGNAME, "persona_test.%s", uuid_string);

	uid_t persona_id = 0;
	int ret = kpersona_alloc(&pinfo, &persona_id);
	T_WITH_ERRNO; T_ASSERT_EQ(ret, 0, NULL);
	T_ASSERT_GT(persona_id, 0, NULL);

	struct kpersona_info fetched_persona = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(persona_id, &fetched_persona);
	T_ASSERT_EQ(error, 0, NULL);
	T_ASSERT_EQ(fetched_persona.persona_uid, persona_uid, NULL);

	T_ASSERT_EQ(kpersona_dealloc(persona_id), 0, NULL);
}

T_DECL(persona_v1_uid_is_unset, "create PERSONA_INFO_V1 and make sure its UID is unset")
{
	uid_t persona = _create_persona(PERSONA_MANAGED, PERSONA_INFO_V1);

	struct kpersona_info info = {
		.persona_info_version = PERSONA_INFO_V2,
	};
	int error = kpersona_info(persona, &info);

	T_ASSERT_EQ(error, 0, NULL);
	T_ASSERT_EQ(info.persona_uid, KAUTH_UID_NONE, NULL);
	T_ASSERT_EQ(kpersona_dealloc(persona), 0, NULL);
}
