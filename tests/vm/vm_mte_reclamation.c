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

#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/sysctl.h>

#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.mteinfo"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG_VM_PREFERRED);

static int64_t
run_sysctl_test(const char *t, int64_t value, bool may_fail)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	if (may_fail) {
		T_MAYFAIL;
	}
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

/* HSC TODO: enable MTE */
T_DECL(vm_mte_ts_for_compressor_bootarg_on,
    "Use tag storage pages for the compressor pool",
    T_META_BOOTARGS_SET("mte_ts_compressor=1"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ_LLONG(1ll, run_sysctl_test("vm_mte_tag_storage_for_compressor",
	    1, true),
	    "didn't get tag storage pages for compressor pool");
}

T_DECL(vm_mte_ts_for_compressor_bootarg_off,
    "Use normal pages for the compressor pool",
    T_META_BOOTARGS_SET("mte_ts_compressor=0"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ_LLONG(1ll, run_sysctl_test("vm_mte_tag_storage_for_compressor",
	    0, true),
	    "didn't get normal pages for compressor pool");
}

T_DECL(vm_mte_ts_for_stack_bootarg_on,
    "Use tag storage for thread stacks",
    T_META_BOOTARGS_SET("mte_ts_vm_tag=30"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	struct {
		uint32_t vm_tag;
		bool mte;
		bool expect_ts;
	} args = {30, false, true};
	T_EXPECT_EQ_INT(1,
	    (int)run_sysctl_test("vm_mte_tag_storage_for_vm_tag", (int64_t)(&args),
	    false),
	    "didn't get tag storage page for allocation");
}

T_DECL(vm_mte_ts_for_stack_bootarg_off,
    "Use normal page for thread stacks",
    T_META_BOOTARGS_SET("mte_ts_vm_tag=1"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	struct {
		uint32_t vm_tag;
		bool mte;
		bool expect_ts;
	} args = {30, false, false};
	T_EXPECT_EQ_INT(1,
	    (int)run_sysctl_test("vm_mte_tag_storage_for_vm_tag", (int64_t)(&args),
	    false),
	    "didn't get normal page for allocation");
}

T_DECL(vm_mte_ts_for_untagged_malloc,
    "Use tag storage page for untagged malloc heap",
    T_META_BOOTARGS_SET("mte_ts_vm_tag=1_4,7_9,11_12"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	struct {
		uint32_t vm_tag;
		bool mte;
		bool expect_ts;
	} args = {2, false, true};
	T_EXPECT_EQ_INT(1,
	    (int)run_sysctl_test("vm_mte_tag_storage_for_vm_tag", (int64_t)(&args),
	    false),
	    "didn't get tag storage page for allocation");
}
