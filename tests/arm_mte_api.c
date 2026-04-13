/*
 * Copyright (c) 2025 Apple Computer, Inc. All rights reserved.
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

#if __arm64__
#include <AppleFeatures/AppleFeatures.h>
#include <arm64/mte.h>
#include <os/security_config.h>
#include <darwintest.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_DECL(mte_api_test,
    "Test the API exposed in mte.h work in user space",
    /*
     * This test can only run if we decided to enable MTE at boot.
     * This is not always the case on MTE-supported hardware: for example
     * due to rdar://135805819 KASAN variants force MTE off.
     */
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	void *address;
	vm_size_t size;

	T_SETUPBEGIN;
	{
		/* verify that the process is running with MTE enabled */
		bool has_mte = os_security_config_get() & OS_SECURITY_CONFIG_MTE;
		T_QUIET; T_ASSERT_TRUE(has_mte, "Process should have MTE");

		size = PAGE_SIZE;
		address = allocate_tagged_memory(size, NULL);
	}
	T_SETUPEND;

	mte_exclude_mask_t m0 = mte_update_exclude_mask(address, 0);
	T_QUIET; T_ASSERT_EQ(__builtin_popcount(m0), 1, "mte_update_exclude_mask");
	void *t1 = mte_generate_random_tag(address, m0);
	mte_exclude_mask_t m1 = mte_update_exclude_mask(t1, m0);
	T_QUIET; T_ASSERT_EQ(__builtin_popcount(m1), 2, "mte_update_exclude_mask");

	mte_store_tag_16(t1);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), t1, "mte_load_tag (16)");
	mte_store_tag_16(address);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), address, "mte_load_tag (zero, 16)");

	mte_store_tag_32(t1);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), t1, "mte_load_tag (32, 0)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 16), t1 + 16, "mte_load_tag (32, 16)");
	mte_store_tag_32(address);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), address, "mte_load_tag (zero, 32, 0)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 16), address + 16, "mte_load_tag (zero, 32, 16)");

	mte_store_tag_64(t1);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), t1, "mte_load_tag (32, 0)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 16), t1 + 16, "mte_load_tag (32, 16)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 32), t1 + 32, "mte_load_tag (32, 32)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 48), t1 + 48, "mte_load_tag (32, 48)");
	mte_store_tag_64(address);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), address, "mte_load_tag (zero, 32, 0)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 16), address + 16, "mte_load_tag (zero, 32, 16)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 32), address + 32, "mte_load_tag (zero, 32, 32)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 48), address + 48, "mte_load_tag (zero, 32, 48)");

	mte_store_tag(t1, 1024);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), t1, "mte_load_tag (1024, 0)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 768), t1 + 768, "mte_load_tag (1024, 768)");
	mte_store_tag(address, 1024);
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1), address, "mte_load_tag (zero, 1024, 0)");
	T_QUIET; T_ASSERT_EQ(mte_load_tag(t1 + 768), address + 768, "mte_load_tag (zero, 1024, 768)");

	mte_store_tag(t1, 512);
	mte_disable_tag_checking();
	*(uint8_t *)address = 0xff;
	mte_enable_tag_checking();
	T_QUIET; T_ASSERT_EQ(*(uint8_t *)address, 0xff, "Write with TCO=1");

	mte_bzero_unchecked(address, 16);
	T_QUIET; T_ASSERT_EQ(*(uint8_t *)address, 0x00, "bzero with TCO=1");

	mte_bzero_fast_checked(t1, 512);
}
#endif /* __arm64__ */
