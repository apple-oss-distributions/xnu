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

#include <arm_acle.h>
#include <darwintest.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <spawn_private.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/spawn_internal.h>
#include <sys/sysctl.h>

#include "arm_mte_utilities.h"

void
kill_child(int child_pid)
{
	T_ASSERT_POSIX_ZERO(kill(child_pid, SIGKILL), "kill(child_pid, SIGKILL)");
	T_ASSERT_NE(signal(SIGALRM, SIG_DFL), SIG_ERR, NULL);
	T_ASSERT_POSIX_SUCCESS(alarm(1), NULL);
	int status = 0;
	T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid(child_pid)");
	// Ensure the child was killed
	T_ASSERT_TRUE(WIFSIGNALED(status), "exited due to signal");
	T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "killed with SIGKILL");
}

bool
validate_proc_pidinfo_mte_status(int child_pid,
    bool expect_mte_enabled)
{
	// Collect process info via PROC_PIDTBSDINFO
	struct proc_bsdinfo bsd_info;
	int ret =
	    proc_pidinfo(child_pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info));
	T_QUIET; T_ASSERT_EQ((unsigned long)ret, sizeof(bsd_info), "PROC_PIDTBSDINFO");

	// Collect process info via PROC_PIDT_SHORTBSDINFO
	struct proc_bsdshortinfo bsd_short_info;
	ret = proc_pidinfo(child_pid, PROC_PIDT_SHORTBSDINFO, 0, &bsd_short_info,
	    sizeof(bsd_short_info));
	T_QUIET; T_ASSERT_EQ((unsigned long)ret, sizeof(bsd_short_info),
	    "PROC_PIDT_SHORTBSDINFO");

	// Finally, ensure both mechanisms report the expected MTE status flag
	if (expect_mte_enabled) {
		T_QUIET; T_EXPECT_BITS_SET(bsd_info.pbi_flags, PROC_FLAG_SEC_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_ENABLED != 0");
		T_QUIET; T_EXPECT_BITS_SET(bsd_short_info.pbsi_flags, PROC_FLAG_SEC_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_ENABLED != 0");

		return (bsd_short_info.pbsi_flags & PROC_FLAG_SEC_ENABLED) && (bsd_info.pbi_flags & PROC_FLAG_SEC_ENABLED);
	} else {
		T_QUIET; T_EXPECT_BITS_NOTSET(bsd_info.pbi_flags, PROC_FLAG_SEC_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_ENABLED == 0");
		T_QUIET; T_EXPECT_BITS_NOTSET(bsd_short_info.pbsi_flags, PROC_FLAG_SEC_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_ENABLED == 0");

		return (bsd_info.pbi_flags & PROC_FLAG_SEC_ENABLED) == 0 && (bsd_info.pbi_flags & PROC_FLAG_SEC_ENABLED) == 0;
	}
}

bool
validate_proc_pidinfo_mte_soft_mode_status(int child_pid,
    bool expect_mte_soft_mode_enabled)
{
	// Collect process info via PROC_PIDTBSDINFO
	struct proc_bsdinfo bsd_info;
	int ret =
	    proc_pidinfo(child_pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info));
	T_QUIET; T_ASSERT_EQ((unsigned long)ret, sizeof(bsd_info), "PROC_PIDTBSDINFO");

	// Collect process info via PROC_PIDT_SHORTBSDINFO
	struct proc_bsdshortinfo bsd_short_info;
	ret = proc_pidinfo(child_pid, PROC_PIDT_SHORTBSDINFO, 0, &bsd_short_info,
	    sizeof(bsd_short_info));
	T_QUIET; T_ASSERT_EQ((unsigned long)ret, sizeof(bsd_short_info),
	    "PROC_PIDT_SHORTBSDINFO");

	// Finally, ensure both mechanisms report the expected MTE status flag
	if (expect_mte_soft_mode_enabled) {
		T_QUIET; T_EXPECT_BITS_SET(bsd_info.pbi_flags, PROC_FLAG_SEC_BYPASS_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED != 0");
		T_QUIET; T_EXPECT_BITS_SET(bsd_short_info.pbsi_flags, PROC_FLAG_SEC_BYPASS_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED != 0");

		return (bsd_short_info.pbsi_flags & PROC_FLAG_SEC_BYPASS_ENABLED) && (bsd_info.pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED);
	} else {
		T_QUIET; T_EXPECT_BITS_NOTSET(bsd_info.pbi_flags, PROC_FLAG_SEC_BYPASS_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED == 0");
		T_QUIET; T_EXPECT_BITS_NOTSET(bsd_short_info.pbsi_flags, PROC_FLAG_SEC_BYPASS_ENABLED,
		    "Expect pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED == 0");

		return (bsd_info.pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED) == 0 && (bsd_info.pbi_flags & PROC_FLAG_SEC_BYPASS_ENABLED) == 0;
	}
}

bool
wait_for_child(int pid)
{
	int status;
	if (waitpid(pid, &status, 0) == -1) {
		T_LOG(
			"wait_for_child: pid {%d} failed with WEXITSTATUS "
			"of %d and status %d\n",
			pid, WEXITSTATUS(status), status);
	} else if (WIFEXITED(status) && !WEXITSTATUS(status)) {
		// The program terminated normally and executed successfully from the
		// child process
		return true;
	}
	return false;
}

bool
fork_and_exec_new_process(char *new_argv[])
{
	pid_t pid = fork();

	if (pid == 0) { /* child process */
		execv(new_argv[0], new_argv);
		exit(127);
	} else { /* parent waits for child to exit */
		bool child_succeeded = wait_for_child(pid);
		return child_succeeded;
	}
}

/*
 * posix_spawn_then_perform_actions_from_process() will execute the
 * downstream defined process based on the setup rules and, if requested,
 * applying the desired flags.
 */
bool
posix_spawn_then_perform_action_from_process(char *new_argv[], uint8_t setup,
    uint16_t sec_flags)
{
	pid_t child_pid = 0;
	posix_spawnattr_t attr = NULL;
	errno_t ret = posix_spawnattr_init(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	switch (setup) {
	case MTE_SPAWN_USE_VANILLA:
		/* No further configuration for posix spawn expected */
		break;
	case MTE_SPAWN_USE_LEGACY_API:
		ret = posix_spawnattr_set_use_sec_transition_shims_np(&attr, sec_flags);
		T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_use_sec_transition_shims_np");
		break;
	default:
		T_FAIL("Unexpected setup op for posix_spawn_then_perform_action_from_process()");
		return false;
	}

	ret = posix_spawn(&child_pid, new_argv[0], NULL, &attr, new_argv, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn(%s)", new_argv[0]);
	T_ASSERT_NE(child_pid, 0, "posix_spawn(%s)", new_argv[0]);

	bool child_succeeded = wait_for_child(child_pid);

	// Cleanup
	ret = posix_spawnattr_destroy(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");

	// This is the return code of our primary executable
	// We need to return 0 to indicate everything went smoothly
	return child_succeeded;
}

int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

/*
 * note: arm_mte_utilities.h defines an expect_signal macro which automatically
 * stringifies signal instead of taking an explicit signal_name
 */
void
expect_signal_impl(int signal, char *signal_name, void (^fn)(void), const char *msg)
{
	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		T_FAIL("%s: did not receive %s", msg, signal_name);
		exit(1);
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		T_EXPECT_TRUE(WIFSIGNALED(status), "%s: exited with signal", msg);
		T_EXPECT_EQ(WTERMSIG(status), signal, "%s: exited with %s", msg, signal_name);
	}
}

void
expect_sigkill(void (^fn)(void), const char *msg)
{
	expect_signal(SIGKILL, fn, msg);
}

void
expect_normal_exit(void (^fn)(void), const char *msg)
{
	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		T_END;
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		if (WIFSIGNALED(status)) {
			T_FAIL("%s: exited with signal %d", msg, WTERMSIG(status));
		} else {
			T_PASS("%s: exited normally", msg);
			T_EXPECT_EQ(WEXITSTATUS(status), 0, "%s: exited with status 0", msg);
		}
	}
}

void
assert_normal_exit(void (^fn)(void), const char *msg)
{
	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		T_END;
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		if (WIFSIGNALED(status)) {
			T_ASSERT_FAIL("%s: exited with signal %d", msg, WTERMSIG(status));
		} else {
			T_PASS("%s: exited normally", msg);
			T_ASSERT_EQ(WEXITSTATUS(status), 0, "%s: exited with status 0", msg);
		}
	}
}

void *
allocate_tagged_memory(
	mach_vm_size_t size,
	uint64_t *mask)
{
	mach_vm_address_t addr = 0;
	T_LOG("Allocate tagged memory");
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&addr,
		size,
		VM_FLAGS_ANYWHERE | VM_FLAGS_MTE | VM_FLAGS_RANDOM_ADDR);
	T_ASSERT_MACH_SUCCESS(kr, "Allocated tagged page");
	T_QUIET; T_ASSERT_NE_ULLONG(0ULL, addr, "Allocated address is not null");

	void *untagged_ptr = (void *)addr;

	void *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(orig_tag, 0U,
	    "Originally assigned tag is zero, tag: %u", orig_tag);

	if (mask) {
		uint64_t local_mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
		T_QUIET; T_EXPECT_EQ_LLONG(local_mask, (1LL << 0), "Zero tag is excluded");
		*mask = local_mask;

		/* Generate random tag */
		void *tagged_ptr = NULL;
		tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, local_mask);
		T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, tagged_ptr,
		    "Random tag was not taken from excluded tag set");
	}
	return orig_tagged_ptr;
}

/*
 * tag: the tag value to tag the entire range with, or ~x to generate a random
 * tag excluding x as a valid value
 */
vm_address_t
allocate_and_tag_range(mach_vm_size_t size, uintptr_t tag)
{
	T_SETUPBEGIN;
	T_QUIET; T_ASSERT_EQ(size % MTE_GRANULE_SIZE, 0ULL, "can't tag part of an MTE granule");
	T_QUIET; T_ASSERT_TRUE((tag & ~0xFUL) == 0UL || (~tag & ~0xFUL) == 0UL, "tag must fit in four bits");

	void *untagged_ptr = allocate_tagged_memory(size, NULL);
	uint8_t *tagged_ptr;

	if ((tag & 0xFUL) != tag) {
		uintptr_t excluded = (uintptr_t) untagged_ptr | (~tag << MTE_TAG_SHIFT);
		uint64_t mask = __arm_mte_exclude_tag((void*)excluded, ~tag);
		tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
	} else {
		tagged_ptr = (uint8_t*)((uintptr_t) untagged_ptr | (tag << MTE_TAG_SHIFT));
	}

	for (mach_vm_size_t offset = 0; offset < size; offset += MTE_GRANULE_SIZE) {
		__arm_mte_set_tag(&tagged_ptr[offset]);
	}
	T_SETUPEND;
	return (vm_address_t) tagged_ptr;
}

/*
 * posix_spawn_with_flags_and_assert_successful_exit() will test the effect
 * of dedicated flags to the legacy posix_spawnattr_set_use_sec_transition_shims_np()
 * API. Pass: POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE to disable the default enablement of
 * MTE and POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE_INHERIT to disable the default
 * enablement of inheritance.
 */
void
posix_spawn_with_flags_and_assert_successful_exit(
	char *const*args,
	posix_spawn_secflag_options flags,
	bool expect_mte,
	bool should_kill_child)
{
	pid_t child_pid = 0;
	posix_spawnattr_t attr;
	errno_t ret = posix_spawnattr_init(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_set_use_sec_transition_shims_np(&attr, flags);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_use_sec_transition_shims_np");

	ret = posix_spawn(&child_pid, args[0], NULL, &attr, args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	T_ASSERT_NE(child_pid, 0, "posix_spawn");

	validate_proc_pidinfo_mte_status(child_pid, expect_mte);

	ret = posix_spawnattr_destroy(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");

	if (should_kill_child) {
		kill_child(child_pid);
	} else {
		int status = -1;
		T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid");
		T_EXPECT_TRUE(WIFEXITED(status), "exited successfully");
		T_EXPECT_TRUE(WEXITSTATUS(status) == 0, "exited with status %d", WEXITSTATUS(status));
	}
}

void *
allocate_untagged_memory(mach_vm_size_t size)
{
	mach_vm_address_t addr = 0;
	T_LOG("Allocate untagged memory");
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&addr,
		size,
		VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
	T_ASSERT_MACH_SUCCESS(kr, "Allocated untagged page");
	T_QUIET; T_ASSERT_NE_ULLONG(0ULL, addr, "Allocated address is not null");

	void *untagged_ptr = (void *)addr;

	void *still_untagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(still_untagged_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(orig_tag, 0U,
	    "Assigned tag is zero, tag: %u", orig_tag);

	return still_untagged_ptr;
}

uint64_t
sysctl_get_Q(const char *name)
{
	uint64_t v = 0;
	size_t sz = sizeof(v);
	int ret = sysctlbyname(name, &v, &sz, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "failed sysctl %s", name);
	return v;
}
