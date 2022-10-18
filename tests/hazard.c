#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>

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
    T_META_NAMESPACE("xnu.sync"),
    T_META_CHECK_LEAKS(false))
{
	T_EXPECT_EQ(1ll, run_sysctl_test("hw_lck_ticket_allow_invalid", 0), "test succeeded");
}
