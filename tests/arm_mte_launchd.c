#include <assert.h>
#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <darwintest_utils.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/proc_info_private.h>
#include <unistd.h>
#include <stdbool.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

#if (TARGET_OS_OSX || TARGET_OS_IOS) && defined(__arm64__)
#if !(TARGET_OS_XR || TARGET_OS_TV || TARGET_OS_WATCH || TARGET_OS_BRIDGE)
#define TARGET_SUPPORTS_MTE_EMULATION 1
#endif
#endif


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm.mte"),
	T_META_RADAR_COMPONENT_NAME("Darwin Testing"),
	T_META_RADAR_COMPONENT_VERSION("all"),
	T_META_OWNER("magarwal23"),
	T_META_RUN_CONCURRENTLY(false),
	T_META_IGNORECRASHES(".*arm_mte.*")
	);

static bool
_does_pid_have_mte(pid_t pid)
{
	struct proc_bsdinfowithuniqid info;
	int ret = proc_pidinfo(pid, PROC_PIDT_BSDINFOWITHUNIQID, 1, &info,
	    PROC_PIDT_BSDINFOWITHUNIQID_SIZE);
	if (ret == 0 || ret != sizeof(info)) {
		return false;
	}

	return (info.pbsd.pbi_flags & PROC_FLAG_SEC_ENABLED) != 0;
}
/* Case 1: Upon reboot (with no MTE disabling boot-arg), launchd should run
 *  as pid 1, and should be MTE enabled (launchctl procinfo 1 should show MTE
 *  enabled) */
T_DECL(check_launchd_mte_enabled, "launchd__test__1",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_REQUIRES_REBOOT(true),
    T_META_ASROOT(true)) {
	#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
	#else /* !__arm64__ */
	pid_t pid = 1;
	T_ASSERT_TRUE(_does_pid_have_mte(pid), "Checking mte flag for launchd with hardware checck for mte");
	#endif /* !__arm64__ */
}

/* Case 2: Upon reboot (with am MTE disabling boot-arg), launchd should
 *  run as pid 1, and should not be MTE enabled */
T_DECL(check_launchd_mte_disabled, "launchd__test__2",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1), XNU_T_META_SOC_SPECIFIC, T_META_BOOTARGS_SET("-disable_mte"), T_META_ASROOT(true)) {
	#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
	#else /* !__arm64__ */
	pid_t pid = 1;
	T_ASSERT_FALSE(_does_pid_have_mte(pid),
	    "Checking mte flag for (-disable_mte) launchd");
	#endif /* !__arm64__ */
}
