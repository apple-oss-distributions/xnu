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

#include <darwintest.h>
#include <stdbool.h>
#include <spawn_private.h>
#include <libproc.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

#if (TARGET_OS_OSX || TARGET_OS_IOS) && defined(__arm64__)
#if !(TARGET_OS_XR || TARGET_OS_TV || TARGET_OS_WATCH || TARGET_OS_BRIDGE)
#define TARGET_SUPPORTS_MTE_EMULATION 1
#endif
#endif

/*
 * These tests verify whether the expected MTE state is found on target processes,
 * exercising the various enablement rules and system APIs.
 * Kernel behavior is extensively documented in kern_exec.c, but we recap here
 * the key points:
 *
 * 1) MTE can be enabled on a target process, in order of preference, by inheritance,
 *    spawn flags and entitlements.
 *    1.1) Inheritance can only be enabled via the dedicated POSIX_SPAWN_SECFLAG_EXPLICIT_ENABLE_INHERIT
 *         flag.
 *    1.2) posix_spawn flags trump entitlements. Inheritance trumps posix_spawn flags.
 *    1.3) entitlements are the desired and expected way to enable MTE in production. With the
 *         exception of launchd, no other entity on the system is expected to use posix_spawn
 *         as an enablement vector. (XCode uses it to provide a run-as-MTE feature)
 *
 * 2) posix_spawnattr_set_use_sec_transition_shims_np() API predates several of the rules at (1)
 *    and is therefore maintained in its legacy behavior of enabling both MTE and INHERITANCE
 *    by default. They both can be switched off via disablement flags: POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE
 *    and POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE_INHERIT.
 *
 * 3) POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE is _not_ supported on RELEASE to prevent attackers from
 *    using the posix_spawn API to disable MTE on a target. POSIX_SPAWN_SECFLAG_EXPLICIT_NEVER_CHECK_ENABLE,
 *    POSIX_SPAWN_SECFLAG_EXPLICIT_VM_POLICY_BYPASS and POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS share the
 *    same destiny.
 *
 * Testing goals:
 * TG1 - ensure that, in absence of spawn flags, entitlements are respected downstream and no inheritance
 *       is present.
 * TG2 - ensure that posix_spawnattr_set_use_sec_transition_shims_np() still respects legacy behavior.
 * TG3 - ensure that posix_spawnattr_set_use_sec_transition_shims_np() is properly affected by
 *       POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE and POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE_INHERIT.
 *
 * <subject to rdar://145396237>
 * TG4 - ensure that the direct manipulation API works as expected.
 * <subject to having RELEASE behavior>
 * TG5 - ensure that on RELEASE POSIX_SPAWN_SECFLAG_EXPLICIT_NEVER_CHECK_ENABLE,
 *       POSIX_SPAWN_SECFLAG_EXPLICIT_VM_POLICY_BYPASS and POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS are
 *       correctly ignored.
 * TG6 - ensure that a first-party process signed with com.apple.developer.driverkit is
 *		 sufficient for the system to apply MTE.
 */

#define INITIAL_ITERATION "0"

T_GLOBAL_META(T_META_NAMESPACE("xnu.arm.mte"),
    T_META_RADAR_COMPONENT_NAME("Darwin Testing"),
    T_META_RADAR_COMPONENT_VERSION("all"), T_META_OWNER("n_sabo"),
    T_META_RUN_CONCURRENTLY(false));

#define MTE_TOTAL_ENABLEMENT_TESTS 3
struct _mte_entitlement_process_expectation {
	char *test_to_run;
	char *expected_state;
	char *test_name;
} mte_entitlement_process_expectation[MTE_TOTAL_ENABLEMENT_TESTS] = {
	{ MTE_ENABLEMENT_TEST_VANILLA_PROCESS_STR, DO_NOT_EXPECT_MTE, "vanilla" },
	{ MTE_ENABLEMENT_TEST_HARDENED_PROCESS_STR, EXPECT_MTE, "hardened-process"},
	{ MTE_ENABLEMENT_TEST_OPTED_OUT_PROCESS_STR, DO_NOT_EXPECT_MTE, "AMFI opt-out"},
};

static void
do_entitlement_test(char *binary_to_launch, char *expected_mte_state)
{
	for (int i = 0; i < MTE_TOTAL_ENABLEMENT_TESTS; i++) {
		T_LOG("Running %s that will spawn %s\n", binary_to_launch, mte_entitlement_process_expectation[i].test_name);
		char *test_argv[] = {
			binary_to_launch,
			expected_mte_state,
			mte_entitlement_process_expectation[i].test_to_run,
			mte_entitlement_process_expectation[i].expected_state,
			NULL
		};

		bool test_succeeded = fork_and_exec_new_process(test_argv);
		T_ASSERT_TRUE(test_succeeded, "fork/exec entitlement test");

		test_succeeded = posix_spawn_then_perform_action_from_process(test_argv, MTE_SPAWN_USE_VANILLA, 0);
		T_ASSERT_TRUE(test_succeeded, "vanilla posix_spawn + entitlements test");
	}
}

static void
do_spawn_flags_test(
	char *binary_to_launch,
	char *expected_mte_state,
	char *test_to_perform,
	char *expected_next_test_mte_state,
	uint16_t sec_flags)
{
	char *test_argv[] = {
		binary_to_launch,
		expected_mte_state,
		test_to_perform,
		expected_next_test_mte_state,
		NULL
	};

	bool test_succeeded = posix_spawn_then_perform_action_from_process(test_argv, MTE_SPAWN_USE_LEGACY_API, sec_flags);
	T_ASSERT_TRUE(test_succeeded, "vanilla posix_spawn + entitlements test");
}

/*
 * TG1.
 *
 * Start different entitled processes that execute the whole spectrum of entitlement possibilities in a process
 * tree and ensure that expectations are matched.
 */

T_DECL(non_mte_enabled_binary_enablement_test,
    "Verify enablement rules against a process tree that starts with "
    "a non-MTE enabled binary",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	do_entitlement_test(SPAWN_HELPER_WITHOUT_ENTITLEMENT, DO_NOT_EXPECT_MTE);
}

T_DECL(mte_enabled_binary_enablement_test,
    "Verify enablement rules against a process tree that starts with "
    "a MTE-enabled binary.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	do_entitlement_test(SPAWN_HELPER_WITH_ENTITLEMENT, EXPECT_MTE);
}

T_DECL(mte_opted_out_binary_enablement_test,
    "Verify enablement rules against a process tree that starts with "
    "a MTE-opted-out binary.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	T_SKIP("skip until Monorail doesn't resign binaries fooling our ID checks");
	do_entitlement_test(HARDENED_PROCESS_TOP_LEVEL_ONLY_AND_IN_AMFI_MTE_OPT_OUT_HELPER, DO_NOT_EXPECT_MTE);
}

/*
 * TG2.
 *
 * Verify that posix_spawnattr_set_use_sec_transition_shims_np() still maintains the original
 * behavior of enabling MTE and enabling inheritance whenever invoked without flags.
 */
T_DECL(mte_legacy_spawn_api_default_behavior,
    "Call posix_spawnattr_set_use_sec_transition_shims_np() and verify that "
    "MTE is enabled AND inheritance is present.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	/* spawn flags and inheritance take precedence over the entitlement state */
	for (int i = 0; i < MTE_TOTAL_ENABLEMENT_TESTS; i++) {
		do_spawn_flags_test(SPAWN_HELPER_WITHOUT_ENTITLEMENT, EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    EXPECT_MTE, 0);
		do_spawn_flags_test(SPAWN_HELPER_WITH_ENTITLEMENT, EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    EXPECT_MTE, 0);
#if MONORAIL_DOESNT_RESIGN
		do_spawn_flags_test(HARDENED_PROCESS_TOP_LEVEL_ONLY_AND_IN_AMFI_MTE_OPT_OUT_HELPER, EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    EXPECT_MTE, 0);
#endif /* MONORAIL_DOESNT_RESIGN */
	}
}

/*
 * TG3.
 *
 * Verify that posix_spawnattr_set_use_sec_transition_shims_np() correctly handles
 * POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE and POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE_INHERIT
 * for internal usecases.
 */
T_DECL(mte_legacy_spawn_api_disable_flag_development,
    "Call posix_spawnattr_set_use_sec_transition_shims_np() passing the"
    "POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE flag and verify that MTE is disabled.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL,
    XNU_T_META_SOC_SPECIFIC) {
	uint16_t sec_flags = POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE;

	T_LOG("posix_spawnattr_set_use_sec_transition_shims_np(POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE)\n");

	/* posix_spawnattr_set_use_sec_transition_shims_np(POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE) implies inheritance */
	for (int i = 0; i < MTE_TOTAL_ENABLEMENT_TESTS; i++) {
		do_spawn_flags_test(SPAWN_HELPER_WITHOUT_ENTITLEMENT, DO_NOT_EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    DO_NOT_EXPECT_MTE, sec_flags);
		do_spawn_flags_test(SPAWN_HELPER_WITH_ENTITLEMENT, DO_NOT_EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    DO_NOT_EXPECT_MTE, sec_flags);
#if MONORAIL_DOESNT_RESIGN
		do_spawn_flags_test(HARDENED_PROCESS_TOP_LEVEL_ONLY_AND_IN_AMFI_MTE_OPT_OUT_HELPER, DO_NOT_EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    DO_NOT_EXPECT_MTE, sec_flags);
#endif /* MONORAIL_DOESNT_RESIGN */
	}

	/* Now with inheritance disabled. */
	T_LOG("posix_spawnattr_set_use_sec_transition_shims_np(POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE_INHERIT|EXPLICIT_DISABLE)\n");
	sec_flags = POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE_INHERIT | POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE;
	for (int i = 0; i < MTE_TOTAL_ENABLEMENT_TESTS; i++) {
		do_spawn_flags_test(SPAWN_HELPER_WITHOUT_ENTITLEMENT, DO_NOT_EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    mte_entitlement_process_expectation[i].expected_state, sec_flags);
		do_spawn_flags_test(SPAWN_HELPER_WITH_ENTITLEMENT, DO_NOT_EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    mte_entitlement_process_expectation[i].expected_state, sec_flags);
#if MONORAIL_DOESNT_RESIGN
		do_spawn_flags_test(HARDENED_PROCESS_TOP_LEVEL_ONLY_AND_IN_AMFI_MTE_OPT_OUT_HELPER, DO_NOT_EXPECT_MTE, mte_entitlement_process_expectation[i].test_to_run,
		    mte_entitlement_process_expectation[i].expected_state, sec_flags);
#endif /* MONORAIL_DOESNT_RESIGN */
	}
}

T_DECL(mte_legacy_spawn_api_disable_flag_release,
    "Call posix_spawnattr_set_use_sec_transition_shims_np() passing the"
    "POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE flag and verify that on RELEASE we fail the call.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_REQUIRES_RELEASE_KERNEL,
    XNU_T_META_SOC_SPECIFIC) {
	posix_spawnattr_t attr;
	pid_t child_pid = 0;
	errno_t ret = posix_spawnattr_init(&attr);
	/* We should not get to execute the binary at all, so no need to have the right arguments. */
	char *args[] = { SPAWN_HELPER_WITH_ENTITLEMENT, NULL};
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_set_use_sec_transition_shims_np(&attr, POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_use_sec_transition_shims_np");

	ret = posix_spawn(&child_pid, args[0], NULL, &attr, args, NULL);
	T_ASSERT_POSIX_FAILURE(ret, EINVAL, "posix_spawn DISABLE on RELEASE");
}

/*
 * TG6.
 *
 * Verify that a first-party dext will get MTE out of the box.
 */
T_DECL(first_party_dext_spawns_with_mte,
    "Ensure first-party dexts receive MTE",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	/* Given a first-party binary signed with com.apple.developer.driverkit */
	pid_t target_pid;
	char* target_argv[] = {"arm_mte_driverkit_standin", NULL};

	/* When the binary is spawned */
	int ret = posix_spawn(&target_pid, target_argv[0], NULL, NULL, target_argv, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn(%s)", target_argv[0]);
	T_ASSERT_NE(target_pid, 0, "posix_spawn(%s)", target_argv[0]);

	/* And we interrogate its MTE state */
	struct proc_bsdinfowithuniqid info;
	ret = proc_pidinfo(target_pid, PROC_PIDT_BSDINFOWITHUNIQID, 1, &info,
	    PROC_PIDT_BSDINFOWITHUNIQID_SIZE);
	T_ASSERT_EQ(ret, (int)sizeof(info), "proc_pidinfo");
	bool is_proc_mte_enabled = (info.pbsd.pbi_flags & PROC_FLAG_SEC_ENABLED) != 0;

	/* Then we observe that the process is MTE-enabled, despite us not doing anything special */
	T_ASSERT_TRUE(is_proc_mte_enabled, "Expected 1p dexts to be MTE-enabled by default");
}

T_DECL(mte_double_entitlement_setting_failure,
    "Execute a binary which has both the com.apple.developer and com.apple.security"
    " set of entitlements and verify that we fail execution.",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	pid_t child_pid = 0;
	/* We should not get to execute the binary at all, so no need to have the right arguments. */
	char *args[] = { "arm_mte_spawn_client_with_invalid_entitlement_setting", NULL};

	int ret = posix_spawn(&child_pid, args[0], NULL, NULL, args, NULL);
	T_ASSERT_NE(0, ret, "poisx_spawn with double entitlement must fail");
}
