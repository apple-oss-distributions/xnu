#include <sys/sysctl.h>
#include <time.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.iokit"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IOKit"),
	T_META_CHECK_LEAKS(false));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(symbol_basic, "Basic tests around OSSymbols")
{
	for (ssize_t size = 32; size <= 32 * 64 * 64; size *= 64) {
		T_EXPECT_EQ(1ll,
		    run_sysctl_test("iokit_symbol_basic", size),
		    "test succeeded");
	}
}
