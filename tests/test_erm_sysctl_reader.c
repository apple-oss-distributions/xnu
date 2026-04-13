/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <darwintest.h>

#include "test_utils.h"

#include "test_erm_sysctl.h"

ERM_GLOBAL_META
T_DECL(erm_sysctl_exists_on_ios_with_ERM,
    "ensure the ERM sysctl exists on iOS with ERM forced",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, NULL, 0);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl exists");
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}

#if PLATFORM_SUPPORTS_ERM
T_DECL(erm_sysctl_doesnt_exist_on_ios_withoutERM,
    "ensure the ERM sysctl doesn't exist on iOS without ERM")
{
	if (is_ERM_active()) {
		T_SKIP("Running with TrustedExecutionMonitor enabled, skipping...");
	} else {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, NULL, 0);
		T_ASSERT_POSIX_FAILURE(ret, ENOENT, "erm sysctl doesn't exist on iOS when ERM is not active");
	}
}
#endif

T_DECL(erm_sysctl_not_writable_by_non_entitled_program,
    "ensure the ERM sysctl can't be modified by non entitled program",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, (void*)sample_config, sample_config_len);
		T_ASSERT_POSIX_FAILURE(ret, EPERM, "erm sysctl should not be modified by non entitled program / ret");
		// T_EXPECT_EQ(errno, EPERM, "erm sysctl should not be modified by non entitled program / errno");
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}


// This function expects the sysctl to have previously stored a config and we check we retrieve it
void
test_one_config(const char* config_str)
{
	size_t config_str_len = strlen(config_str);

	size_t read_config1_len = 0;
	int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, &read_config1_len, NULL, 0);

	/* allocate the configuration with the size we received */
	char* read_config = (char*)malloc(read_config1_len);
	size_t read_config_len = read_config1_len;

	ret = sysctlbyname(ERM_SYSCTL_NAME, read_config, &read_config_len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could read config size");
	if (ret != 0) {
		free(read_config);
		return;
	}

	T_EXPECT_EQ(read_config_len, read_config1_len, "erm sysctl config sizes are equal");
	if (read_config_len != read_config1_len) {
		free(read_config);
		return;
	}
	T_EXPECT_EQ(read_config_len, config_str_len, "erm sysctl config size is good");
	if (read_config_len == config_str_len) {
		bool are_same = true;
		for (int i = 0; i < sample_config_len; ++i) {
			if (read_config[i] != config_str[i]) {
				are_same = false;
				break;
			}
		}
		T_EXPECT_EQ(are_same, true, "erm sysctl config data is good");
		if (!are_same) {
			free(read_config);
			return;
		}
	}
}


// ****************
// The following tests first execute a helper that will write the config (external program that
// has the required entitlement for writing things), then the actual test.
// Because we pass the "config" to the external program via its command line argument,
// it must be a string.

#define CONFIG0 "This_is_a_sample_config"
T_DECL(erm_sysctl_read0,
    "ensure the ERM sysctl can store and read config:<" CONFIG0 ">",
    ERM_ENABLED_META
    )
{
	if (!is_ERM_active()) {
		T_SKIP("Running without ERM enabled, skipping...");
	} else {
		system("./test_erm_sysctl_bin_helper " CONFIG0);
		test_one_config(CONFIG0);
	}
}

#define CONFIG1 "This_is_a_another_sample_config"
T_DECL(erm_sysctl_read1,
    "ensure the ERM sysctl can store and read config:<" CONFIG1 ">",
    ERM_ENABLED_META
    )
{
	if (!is_ERM_active()) {
		T_SKIP("Running without ERM enabled, skipping...");
	} else {
		system("./test_erm_sysctl_bin_helper " CONFIG1);
		test_one_config(CONFIG1);
	}
}
