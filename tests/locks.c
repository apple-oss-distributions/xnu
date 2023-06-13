#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.sync"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_CHECK_LEAKS(false),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("locks"));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(hw_lck_ticket_allow_invalid, "hw_lck_ticket_allow_invalid",
    T_META_RUN_CONCURRENTLY(false))
{
	T_EXPECT_EQ(1ll, run_sysctl_test("hw_lck_ticket_allow_invalid", 0), "test succeeded");
}

T_DECL(smr_hash_basic, "smr_hash basic test")
{
	T_EXPECT_EQ(1ll, run_sysctl_test("smr_hash_basic", 0), "test succeeded");
}

T_DECL(smr_shash_basic, "smr_shash basic test")
{
	T_EXPECT_EQ(1ll, run_sysctl_test("smr_shash_basic", 0), "test succeeded");
}
