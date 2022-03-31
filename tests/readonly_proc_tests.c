#include <darwintest.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.bsd"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("bsd"),
	T_META_OWNER("chrisjd")
	);

T_DECL(readonly_proc_tests, "invoke the read-only proc unit test",
    T_META_ASROOT(true), T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
	int64_t result = 0;
	int64_t value = 0;
	size_t s = sizeof(value);
	int ret;
	ret = sysctlbyname("debug.test.readonly_proc_test", &result, &s, &value, sizeof(value));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(\"debug.test.readonly_proc_test\"");
	T_EXPECT_EQ(1ull, result, "run readonly proc test");
}
