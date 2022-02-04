#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("zalloc"));

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

T_DECL(kalloc_type, "kalloc_type_test",
    T_META_CHECK_LEAKS(false))
{
	T_EXPECT_EQ(1ll, run_sysctl_test("kalloc_type", 85), "test succeeded");
}

T_DECL(kalloc, "kalloc_test",
    T_META_NAMESPACE("xnu.vm"),
    T_META_CHECK_LEAKS(false))
{
	T_EXPECT_EQ(1ll, run_sysctl_test("kalloc", 0), "test succeeded");
}
