/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

#include <arm_acle.h>
#include <darwintest.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn_private.h>
#include <stdlib.h>
#include <sys/spawn_internal.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.arm.mte"),
    T_META_RADAR_COMPONENT_NAME("Darwin Testing"),
    T_META_RADAR_COMPONENT_VERSION("all"), T_META_OWNER("n_sabo"),
    T_META_RUN_CONCURRENTLY(false),
    T_META_IGNORECRASHES(".*knob.*"),
    T_META_CHECK_LEAKS(false));

static void
tag_violate_template(void)
{
	static const size_t ALLOC_SIZE = MTE_GRANULE_SIZE * 2;

	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, ALLOC_SIZE, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory");
	char *untagged_ptr = (char *) address;

	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
	T_ASSERT_EQ_UINT(orig_tag, 0U, "originally assigned tag is zero");

	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	T_ASSERT_EQ_LLONG(mask, (1LL << 0), "zero tag is excluded");

	char *random_tagged_ptr = NULL;
	for (unsigned int i = 0; i < NUM_MTE_TAGS * 4; i++) {
		random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
		T_QUIET; T_ASSERT_NE_PTR(orig_tagged_ptr, random_tagged_ptr,
		    "random tag was not taken from excluded tag set");

		ptrdiff_t diff = __arm_mte_ptrdiff(untagged_ptr, random_tagged_ptr);
		T_QUIET; T_ASSERT_EQ_ULONG(diff, (ptrdiff_t)0, "untagged %p and tagged %p have identical address bits",
		    untagged_ptr, random_tagged_ptr);
	}

	__arm_mte_set_tag(random_tagged_ptr);

	char *read_back = __arm_mte_get_tag(untagged_ptr);
	T_ASSERT_EQ_PTR(read_back, random_tagged_ptr, "tag was committed to memory correctly");

	random_tagged_ptr[0] = 't';
	random_tagged_ptr[1] = 'e';
	random_tagged_ptr[2] = 's';
	random_tagged_ptr[3] = 't';
	T_EXPECT_EQ_STR(random_tagged_ptr, "test", "read/write from tagged memory");

	void *next_granule_ptr = orig_tagged_ptr + MTE_GRANULE_SIZE;
	unsigned int next_granule_tag = extract_mte_tag(next_granule_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(next_granule_tag, 0U,
	    "next MTE granule still has its originally assigned tag");

	T_LOG("attempting out-of-bounds access to tagged memory");
	random_tagged_ptr[MTE_GRANULE_SIZE] = '!';
	T_LOG("bypass: survived OOB access");

	/* We should not just have survived, but also re-issued the instruction */
	T_ASSERT_EQ_CHAR(random_tagged_ptr[MTE_GRANULE_SIZE], '!', "faulting instruction wasn't re-issued correctly");

	__arm_mte_set_tag(orig_tagged_ptr);
	__arm_mte_set_tag(orig_tagged_ptr + MTE_GRANULE_SIZE);
	vm_deallocate(mach_task_self(), address, ALLOC_SIZE);
	exit(0);
}

T_HELPER_DECL(mte_tag_violate, "helper to trigger an MTE violation")
{
	tag_violate_template();
}

T_HELPER_DECL(mte_tag_violate_with_fork, "helper to trigger an MTE violation from a forked process")
{
	tag_violate_template();
	T_LOG("Knob enforced on main process\n");
	/* Now fork a child and verifying the knob was inherited */
	assert_normal_exit(^{
		tag_violate_template();
	}, "forked a child");
	T_LOG("Knob enforced on forked process\n");
}

static void
default_tag_check_bypass_template(
	posix_spawn_secflag_options flags,
	bool expect_mte,
	bool should_kill_child,
	char *helper_name
	)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	char *args[] = { path, "-n", helper_name, NULL};
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	posix_spawn_with_flags_and_assert_successful_exit(args, flags, expect_mte, should_kill_child);
}

T_DECL(test_posix_spawn_explicit_check_bypass_knob,
    "Test MTE tag check bypass works with posix_spawnattr and flag POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	default_tag_check_bypass_template(POSIX_SPAWN_SECFLAG_EXPLICIT_ENABLE | POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS, true, false, "mte_tag_violate");
}

T_DECL(test_explicit_never_check_enable_with_bypass_knobs,
    "Test that combining POSIX_SPAWN_SECFLAG_EXPLICIT_NEVER_CHECK_ENABLE &"
    "POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS results in relaxed enforcement "
    "on out of bounds memory access",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	default_tag_check_bypass_template(POSIX_SPAWN_SECFLAG_EXPLICIT_NEVER_CHECK_ENABLE | POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS, true, false, "mte_tag_violate");
}

T_DECL(test_posix_spawn_secflag_explict_check_bypass_knob_inherited_on_fork,
    "Test that POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS is inherited on fork",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	default_tag_check_bypass_template(POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS, true, false, "mte_tag_violate_with_fork");
}
