#include <darwintest.h>
#include <sys/types.h>
#include <sys/sysctl.h>

T_DECL(vm_analytics, "Report VM analytics",
    T_META_ASROOT(true),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1))
{
	int val = 1;
	int ret = sysctlbyname("vm.analytics_report", NULL, NULL, &val, sizeof(val));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "vm.analytics_report=1");
}
