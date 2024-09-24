/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <mach/coalition.h>
#include <sys/coalition.h>
#include <libproc.h>

#include <sys/types.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/task.h>
#include <mach/mach.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(false));

static uint64_t
get_res_id(void)
{
	struct proc_pidcoalitioninfo idinfo;

	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t res_id = idinfo.coalition_id[COALITION_TYPE_RESOURCE];
	uint64_t jet_id = idinfo.coalition_id[COALITION_TYPE_JETSAM];

	T_LOG("Resource coalition: %lld, Jetsam coalition: %lld", res_id, jet_id);

	return res_id;
}

static uint64_t
get_energy_id(void)
{
	int ret;
	uint64_t out_val = 0;
	size_t out_size = sizeof(out_val);

	uint64_t param[4] = {
		1,
	};

	ret = sysctlbyname("kern.coalition_gpu_energy_test",
	    &out_val, &out_size, param, sizeof(param));

	T_ASSERT_POSIX_SUCCESS(ret, "get_energy_id() = %lld", out_val);

	return out_val;
}

static int
test_task_id_token_to_energy_id(mach_port_name_t name, uint64_t *energy_id_out)
{
	int ret;
	uint64_t out_val = 0;
	size_t out_size = sizeof(out_val);

	uint64_t param[4] = {
		2,
		name,
	};

	ret = sysctlbyname("kern.coalition_gpu_energy_test",
	    &out_val, &out_size, param, sizeof(param));

	*energy_id_out = out_val;

	return ret;
}

static int
test_energy_id_report_energy(uint64_t self_id, uint64_t on_behalf_of_id, uint64_t energy)
{
	uint64_t out_val = 0;
	size_t out_size = sizeof(out_val);

	uint64_t param[4] = {
		3,
		self_id,
		on_behalf_of_id,
		energy,
	};

	return sysctlbyname("kern.coalition_gpu_energy_test",
	           &out_val, &out_size, param, sizeof(param));
}


T_DECL(current_energy_id, "current_energy_id returns res id")
{
	uint64_t res_id = get_res_id();
	uint64_t energy_id = get_energy_id();

	T_ASSERT_EQ(energy_id, res_id, "energy id is res id");
}


T_DECL(task_id_token_to_energy_id, "task_id_token_to_energy_id looks up energy id")
{
	uint64_t energy_id = get_energy_id();

	uint64_t energy_id_out = 0;

	task_id_token_t token;

	kern_return_t kr = task_create_identity_token(mach_task_self(), &token);
	T_ASSERT_MACH_SUCCESS(kr, "task_create_identity_token() = 0x%x", token);

	int ret = test_task_id_token_to_energy_id(token, &energy_id_out);
	T_ASSERT_POSIX_SUCCESS(ret, "task_id_token_to_energy_id(0x%x) = %lld", token, energy_id_out);

	T_EXPECT_EQ(energy_id_out, energy_id, "token energy id is self energy id");

	kr = mach_port_deallocate(mach_task_self(), token);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate(0x%x)", token);
}


T_DECL(energy_id_report_energy_time_bad_value, "energy_id_report_energy_time handles bad value")
{
	int ret = test_energy_id_report_energy((uint64_t)-1, 0, 1);
	T_ASSERT_POSIX_FAILURE(ret, ENOENT, "energy_id_report_energy(-1) = ENOENT");

	ret = test_energy_id_report_energy(0, 0, 1);
	T_ASSERT_POSIX_FAILURE(ret, EINVAL, "energy_id_report_energy(0) = EINVAL");

	uint64_t res_id = get_res_id();

	/* It ignores bad on_behalf_of_ids */
	ret = test_energy_id_report_energy(res_id, (uint64_t)-1, 1);
	T_ASSERT_POSIX_SUCCESS(ret, "energy_id_report_energy(%lld, -1)", res_id);
}


T_DECL(energy_id_report_energy_time_self, "energy_id_report_energy_time increments gpu energy for self")
{
	uint64_t res_id = get_res_id();
	uint64_t energy_id = get_energy_id();

	struct coalition_resource_usage coalusage_1 = {0};
	int ret = coalition_info_resource_usage(res_id, &coalusage_1, sizeof(coalusage_1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage() 1");

	T_LOG("before: gpu_energy_nj: %lld, gpu_energy_nj_billed_to_me: %lld, gpu_energy_nj_billed_to_others: %lld",
	    coalusage_1.gpu_energy_nj, coalusage_1.gpu_energy_nj_billed_to_me,
	    coalusage_1.gpu_energy_nj_billed_to_others);

	ret = test_energy_id_report_energy(energy_id, 0, 1);
	T_ASSERT_POSIX_SUCCESS(ret, "energy_id_report_energy(%lld, 0, 1)", energy_id);

	struct coalition_resource_usage coalusage_2 = {0};
	ret = coalition_info_resource_usage(res_id, &coalusage_2, sizeof(coalusage_2));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage() 2");

	T_LOG("after: gpu_energy_nj: %lld, gpu_energy_nj_billed_to_me: %lld, gpu_energy_nj_billed_to_others: %lld",
	    coalusage_2.gpu_energy_nj, coalusage_2.gpu_energy_nj_billed_to_me,
	    coalusage_2.gpu_energy_nj_billed_to_others);

	T_EXPECT_LT(coalusage_1.gpu_energy_nj, coalusage_2.gpu_energy_nj,
	    "gpu_energy_nj should have increased");
}


T_DECL(energy_id_report_energy_time_billed, "energy_id_report_energy_time increments billed energy")
{
	uint64_t res_id = get_res_id();
	uint64_t energy_id = get_energy_id();

	struct coalition_resource_usage coalusage_1 = {0};
	int ret = coalition_info_resource_usage(res_id, &coalusage_1, sizeof(coalusage_1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage() 1");

	T_LOG("before: gpu_energy_nj: %lld, gpu_energy_nj_billed_to_me: %lld, gpu_energy_nj_billed_to_others: %lld",
	    coalusage_1.gpu_energy_nj, coalusage_1.gpu_energy_nj_billed_to_me,
	    coalusage_1.gpu_energy_nj_billed_to_others);

	ret = test_energy_id_report_energy(energy_id, energy_id, 1);
	T_ASSERT_POSIX_SUCCESS(ret, "energy_id_report_energy(%lld, %lld, 1)", energy_id, energy_id);

	struct coalition_resource_usage coalusage_2 = {0};
	ret = coalition_info_resource_usage(res_id, &coalusage_2, sizeof(coalusage_2));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage() 2");

	T_LOG("after: gpu_energy_nj: %lld, gpu_energy_nj_billed_to_me: %lld, gpu_energy_nj_billed_to_others: %lld",
	    coalusage_2.gpu_energy_nj, coalusage_2.gpu_energy_nj_billed_to_me,
	    coalusage_2.gpu_energy_nj_billed_to_others);

	T_EXPECT_LT(coalusage_1.gpu_energy_nj, coalusage_2.gpu_energy_nj,
	    "gpu_energy_nj should have increased");
	T_EXPECT_LT(coalusage_1.gpu_energy_nj_billed_to_me, coalusage_2.gpu_energy_nj_billed_to_me,
	    "gpu_energy_nj_billed_to_me should have increased");
	T_EXPECT_LT(coalusage_1.gpu_energy_nj_billed_to_others, coalusage_2.gpu_energy_nj_billed_to_others,
	    "gpu_energy_nj_billed_to_others should have increased");
}
