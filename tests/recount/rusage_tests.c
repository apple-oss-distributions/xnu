// Copyright 2021 (c) Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <darwintest_posix.h>
#include <libproc.h>
#include <stdint.h>
#include <sys/resource.h>
#include <unistd.h>

#include "test_utils.h"
#include "recount_test_utils.h"

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("RM"),
    T_META_OWNER("mwidmann"),
    T_META_CHECK_LEAKS(false));

T_DECL(rusage_kernel_cpu_time_sanity,
    "ensure the CPU time for kernel_task is sane", T_META_ASROOT(true))
{
	struct rusage_info_v5 usage_info = { 0 };
	T_SETUPBEGIN;
	int ret = proc_pid_rusage(0, RUSAGE_INFO_V5, (void *)&usage_info);
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage on kernel_task");
	T_SETUPEND;

	T_EXPECT_GT(usage_info.ri_system_time + usage_info.ri_user_time,
	    UINT64_C(0), "kernel CPU time should be non-zero");
	if (has_user_system_times()) {
		T_EXPECT_EQ(usage_info.ri_user_time,
		    UINT64_C(0), "kernel user CPU time should be zero");
	}
}

T_DECL(rusage_user_time_sanity,
    "ensure the user CPU time for a user space task is sane")
{
	struct rusage_info_v5 usage_info = { 0 };
	T_SETUPBEGIN;
	int ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V5, (void *)&usage_info);
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pid_rusage on self");
	T_SETUPEND;

	T_EXPECT_NE(usage_info.ri_user_time, UINT64_C(0),
	    "user space CPU time should be non-zero");
	if (has_user_system_times()) {
		T_EXPECT_GT(usage_info.ri_system_time, UINT64_C(0),
		    "system time should be non-zero");
	}
}
