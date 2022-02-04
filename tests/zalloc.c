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

T_DECL(basic_zone_test, "General zalloc test",
    T_META_CHECK_LEAKS(false))
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_basic_test", 0), "zone_basic_test");
}

T_DECL(read_only_zone_test, "Read-only zalloc test",
    T_META_CHECK_LEAKS(false))
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_ro_basic_test", 0), "zone_ro_basic_test");
}

T_DECL(zone_stress_test, "Zone stress test of edge cases",
    T_META_CHECK_LEAKS(false))
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_stress_test", 0), "zone_stress_test");
}
