#include <darwintest.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("security"),
	T_META_OWNER("chrisjd")
	);

T_DECL(stack_chk_tests, "invoke the kernel stack check tests",
    T_META_ASROOT(true),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1),
    T_META_REQUIRES_SYSCTL_NE("kern.kasan.available", 1))
{
	int ret, dummy = 1;
	ret = sysctlbyname("kern.run_stack_chk_tests", NULL, NULL, &dummy, sizeof(dummy));

	if (ret == -1 && errno == ENOENT) {
		/* sysctl not present, so skip. */
		T_PASS("kern.run_stack_chk_tests not on this platform/configuration");
	} else {
		T_ASSERT_POSIX_SUCCESS(ret, "run stack check tests");
	}
}
