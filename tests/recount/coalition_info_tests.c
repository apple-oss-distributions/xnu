#include <darwintest.h>
#include <inttypes.h>
#include <mach/coalition.h>
#include <stdint.h>
#include <sys/coalition.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <unistd.h>

#include "test_utils.h"

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("RM"),
    T_META_OWNER("mwidmann"),
    T_META_RUN_CONCURRENTLY(true),
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false));

static void
skip_if_monotonic_unsupported(void)
{
	int r;
	int supported = 0;
	size_t supported_size = sizeof(supported);

	r = sysctlbyname("kern.monotonic.supported", &supported, &supported_size,
	    NULL, 0);
	if (r < 0) {
		T_WITH_ERRNO;
		T_SKIP("could not find \"kern.monotonic.supported\" sysctl");
	}

	if (!supported) {
		T_SKIP("monotonic is not supported on this platform");
	}
}

T_DECL(coalition_resource_info_counters,
    "ensure that coalition resource info produces valid counter data")
{
	skip_if_monotonic_unsupported();

	T_SETUPBEGIN;

	struct proc_pidcoalitioninfo idinfo = {};
	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t resid = idinfo.coalition_id[COALITION_TYPE_RESOURCE];

	struct coalition_resource_usage coalusage[2] = {};
	ret = coalition_info_resource_usage(resid, &coalusage[0],
	    sizeof(coalusage[0]));
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage()");

	T_SETUPEND;

	T_EXPECT_GT(coalusage[0].cpu_instructions, UINT64_C(0),
	    "instruction count is non-zero");
	T_EXPECT_GT(coalusage[0].cpu_cycles, UINT64_C(0),
	    "cycle count is non-zero");

	sleep(1);

	T_SETUPBEGIN;
	ret = coalition_info_resource_usage(resid, &coalusage[1],
	    sizeof(coalusage[1]));
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage()");
	T_SETUPEND;

	T_EXPECT_GE(coalusage[1].cpu_instructions, coalusage[0].cpu_instructions,
	    "instruction count is monotonically increasing (+%" PRIu64 ")",
	    coalusage[1].cpu_instructions - coalusage[0].cpu_instructions);
	T_EXPECT_GE(coalusage[1].cpu_cycles, coalusage[0].cpu_cycles,
	    "cycle count is monotonically increasing (+%" PRIu64 ")",
	    coalusage[1].cpu_cycles - coalusage[0].cpu_cycles);
}

T_DECL(coalition_resource_info_kernel_ptime_sane,
    "ensure that coalition resource info for the kernel has a sane P-CPU time")
{
	T_SETUPBEGIN;
	struct proc_pidcoalitioninfo idinfo = {};
	int ret = proc_pidinfo(0, PROC_PIDCOALITIONINFO, 0, &idinfo,
	    sizeof(idinfo));
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t resid = idinfo.coalition_id[COALITION_TYPE_RESOURCE];

	struct coalition_resource_usage coalusage = {};
	ret = coalition_info_resource_usage(resid, &coalusage,
	    sizeof(coalusage));
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage()");
	T_SETUPEND;

	uint64_t non_ptime = coalusage.cpu_time - coalusage.cpu_ptime;
	T_LOG("CPU time = %llu, P-CPU time = %llu (non-P-CPU time = %llu/%.2g%%)",
	    coalusage.cpu_time, coalusage.cpu_ptime, non_ptime,
	    (double)non_ptime / (double)coalusage.cpu_time * 100.0);
	T_EXPECT_GT(coalusage.cpu_time, UINT64_C(0), "CPU time is non-zero");
	T_EXPECT_GT(coalusage.cpu_time, coalusage.cpu_ptime,
	    "P-CPU time is <= CPU time");
}
