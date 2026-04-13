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
#include <sys/code_signing.h>

#include "test_erm_sysctl.h"

ERM_GLOBAL_META
T_DECL(erm_sysctl_writer_can_write_when_ERM,
    "ensure the correctly entitled program can write the sysctl",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, (void*)sample_config, sample_config_len);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could be written");
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}


#if 0
// This test is removed because now TXM kills a process that is entitled for ERM when ERM is NOT active.
// I keep this code here (even if commented out), in order to keep track of this special behavior change.
T_DECL(erm_sysctl_writer_cant_write_when_no_ERM,
    "ensure the correctly entitled program can't write the sysctl when ERM is NOT active"
    )
{
	if (is_ERM_active()) {
		T_SKIP("Running with TrustedExecutionMonitor enabled, skipping...");
	} else {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, (void*)sample_config, sample_config_len);
		T_ASSERT_POSIX_FAILURE(ret, ENOENT, "erm sysctl could be written");
	}
}
#endif

T_DECL(erm_sysctl_writer_can_write_and_read,
    "ensure the correctly entitled program can write the sysctl then read it back",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, (void*)sample_config, sample_config_len);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could be written");

		size_t read_config_len = sample_config_len;
		void* read_config = malloc(read_config_len);
		ret = sysctlbyname(ERM_SYSCTL_NAME, read_config, &read_config_len, NULL, 0);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could be read");
		T_EXPECT_EQ(read_config_len, sample_config_len, "erm sysctl read correct size");
		T_EXPECT_EQ_ULONG(*(unsigned long*)read_config, *(unsigned long*)sample_config, "erm sysctl read correct data");
		free(read_config);
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}

T_DECL(erm_sysctl_writer_can_write_and_read_smaller_buffer,
    "ensure we handle correctly when user space provides a too small buffer",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, (void*)sample_config, sample_config_len);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could be written");

		// we provide a read buffer of only 2 bytes (the whole config is 8 bytes)
		const size_t read_config_small_len = sizeof(short);
		size_t read_config_len = read_config_small_len;
		void* read_config = malloc(read_config_len);
		ret = sysctlbyname(ERM_SYSCTL_NAME, read_config, &read_config_len, NULL, 0);
		T_ASSERT_POSIX_FAILURE(ret, ENOMEM, "erm sysctl couldn't be read");
		T_EXPECT_EQ(read_config_len, sample_config_len, "we should have received the actual config size");
		free(read_config);
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}

T_DECL(erm_sysctl_writer_can_write_and_read_bigger_buffer,
    "ensure we handle correctly when user space provides a too big buffer",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, (void*)sample_config, sample_config_len);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could be written");

		// we provide a read buffer that is bigger than necessary
		const size_t read_config_big_len = 2 * sizeof(long);
		size_t read_config_len = read_config_big_len;
		void* read_config = malloc(read_config_len);
		// this part will be overriten by the sysctl
		((long*)read_config)[0] = 0;
		// this part should not be touched
		unsigned long extra_data = 0x123456789abcdef0;
		((unsigned long*)read_config)[1] = extra_data;

		ret = sysctlbyname(ERM_SYSCTL_NAME, read_config, &read_config_len, NULL, 0);
		T_ASSERT_POSIX_SUCCESS(ret, "erm sysctl could be read");
		T_EXPECT_EQ(read_config_len, sample_config_len, "erm sysctl read correct size");
		T_EXPECT_EQ_ULONG(*(unsigned long*)read_config, *(unsigned long*)sample_config, "erm sysctl read correct data");
		T_EXPECT_EQ_ULONG(((unsigned long*)read_config)[1], extra_data, "erm sysctl doesn't touch this part of the buffer");

		free(read_config);
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}

T_DECL(erm_sysctl_writer_refuses_oversized_config,
    "check the sysctl doesn't accept oversized config",
    ERM_ENABLED_META)
{
	if (is_ERM_active()) {
		size_t big_buffer_len = 2 * PAGE_SIZE;
		void* big_buffer = malloc(big_buffer_len);
		int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, big_buffer, big_buffer_len);
		T_ASSERT_POSIX_FAILURE(ret, EINVAL, "erm sysctl refuses oversized buffers");
		free(big_buffer);
	} else {
		T_SKIP("Running without ERM enabled, skipping...");
	}
}
