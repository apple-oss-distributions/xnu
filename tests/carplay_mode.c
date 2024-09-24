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

/* test that the header doesn't implicitly depend on others */
#include <sys/resource_private.h>
#include <sys/resource.h>

#include <mach/coalition.h>
#include <sys/coalition.h>
#include <libproc.h>

#include <sys/types.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

/* TODO: can this come from the right header? */
#define THREAD_GROUP_FLAGS_CARPLAY_MODE            0x1000

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(false));

static void
check_carplay_mode(bool expected_mode)
{
	int mode = getpriority(PRIO_DARWIN_CARPLAY_MODE, 0);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(mode, "getpriority(PRIO_DARWIN_CARPLAY_MODE)");

	T_LOG("pid %d: carplay mode is: %d", getpid(), mode);

	if (expected_mode) {
		T_QUIET;
		T_ASSERT_EQ(mode, PRIO_DARWIN_CARPLAY_MODE_ON, "should be on");
	} else {
		T_QUIET;
		T_ASSERT_EQ(mode, PRIO_DARWIN_CARPLAY_MODE_OFF, "should be off");
	}
}

T_DECL(entitled_carplay_mode, "carplay mode bit should be settable while entitled")
{
	T_LOG("uid: %d", getuid());

	check_carplay_mode(false);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON)");

	check_carplay_mode(true);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF)");

	check_carplay_mode(false);
}

T_DECL(entitled_carplay_mode_read_root, "carplay mode bit should be readable as root",
    T_META_ASROOT(true))
{
	T_LOG("uid: %d", getuid());

	check_carplay_mode(false);
}

T_DECL(entitled_carplay_mode_read_notroot, "carplay mode bit should be readable as not root but entitled",
    T_META_ASROOT(false))
{
	T_LOG("uid: %d", getuid());

	check_carplay_mode(false);
}

static struct coalinfo_debuginfo
get_coal_debuginfo(uint64_t coal_id, char* prefix)
{
	struct coalinfo_debuginfo coaldebuginfo = {};

	int ret = coalition_info_debug_info(coal_id, &coaldebuginfo, sizeof(coaldebuginfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_debug_info");

	T_LOG("coal(%s): %lld, carplay count %d, flags 0x%x (group 0x%llx, rec %d, focal: %d, nonfocal %d)",
	    prefix, coal_id,
	    coaldebuginfo.carplay_task_count, coaldebuginfo.thread_group_flags,
	    coaldebuginfo.thread_group_id, coaldebuginfo.thread_group_recommendation,
	    coaldebuginfo.focal_task_count, coaldebuginfo.nonfocal_task_count);

	return coaldebuginfo;
}

static void
check_carplay_mode_count(uint32_t expected_count)
{
	struct proc_pidcoalitioninfo idinfo = {};

	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t res_id = idinfo.coalition_id[COALITION_TYPE_RESOURCE];
	uint64_t jet_id = idinfo.coalition_id[COALITION_TYPE_JETSAM];

	struct coalinfo_debuginfo coaldebuginfo_res = get_coal_debuginfo(res_id, "res");
	struct coalinfo_debuginfo coaldebuginfo_jet = get_coal_debuginfo(jet_id, "jet");

	if (expected_count) {
		// see COALITION_FOCAL_TASKS_ACCOUNTING for this difference
#if TARGET_OS_OSX
		T_ASSERT_EQ(coaldebuginfo_res.carplay_task_count, expected_count, "should have carplay in res coalition");
		T_QUIET; T_ASSERT_EQ(coaldebuginfo_jet.carplay_task_count, 0, "should not have carplay in jet coalition");
#else
		T_QUIET; T_ASSERT_EQ(coaldebuginfo_res.carplay_task_count, 0, "should not have carplay in res coalition");
		T_ASSERT_EQ(coaldebuginfo_jet.carplay_task_count, expected_count, "should have carplay in jet coalition");
#endif
		T_ASSERT_BITS_SET(coaldebuginfo_jet.thread_group_flags, THREAD_GROUP_FLAGS_CARPLAY_MODE,
		    "should have carplay mode flag in jet coalition"); \
	} else {
#if TARGET_OS_OSX
		T_ASSERT_EQ(coaldebuginfo_res.carplay_task_count, 0, "should not have carplay in res coalition");
		T_QUIET; T_ASSERT_EQ(coaldebuginfo_jet.carplay_task_count, 0, "should not have carplay in jet coalition");
#else
		T_QUIET; T_ASSERT_EQ(coaldebuginfo_res.carplay_task_count, 0, "should not have carplay in res coalition");
		T_ASSERT_EQ(coaldebuginfo_jet.carplay_task_count, 0, "should not have carplay in jet coalition");
#endif
		T_ASSERT_BITS_NOTSET(coaldebuginfo_jet.thread_group_flags, THREAD_GROUP_FLAGS_CARPLAY_MODE,
		    "should not have carplay mode flag in jet coalition"); \
	}

	T_QUIET; T_ASSERT_BITS_NOTSET(coaldebuginfo_res.thread_group_flags, THREAD_GROUP_FLAGS_CARPLAY_MODE,
	    "should never have carplay mode flag in res coalition"); \
}

static void
skip_if_unsupported(void)
{
	int r;
	int supported = 0;
	size_t supported_size = sizeof(supported);

	r = sysctlbyname("kern.thread_groups_supported", &supported, &supported_size,
	    NULL, 0);
	if (r < 0) {
		T_WITH_ERRNO;
		T_SKIP("could not find \"kern.thread_groups_supported\" sysctl");
	}

	if (!supported) {
		T_SKIP("test was run even though kern.thread_groups_supported is not 1, see rdar://111297938");
	}

	r = sysctlbyname("kern.development", &supported, &supported_size,
	    NULL, 0);
	if (r < 0) {
		T_WITH_ERRNO;
		T_SKIP("could not find \"kern.development\" sysctl");
	}

	if (!supported) {
		T_SKIP("test was run even though kern.development is not 1, see rdar://111297938");
	}
}

T_DECL(entitled_carplay_mode_check_count, "carplay mode bit should affect coalition thread group flags",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1), T_META_REQUIRES_SYSCTL_EQ("kern.thread_groups_supported", 1))
{
	T_LOG("uid: %d", getuid());
	skip_if_unsupported();

	check_carplay_mode(false);
	check_carplay_mode_count(0);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE_ON)");

	check_carplay_mode(true);
	check_carplay_mode_count(1);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE_OFF)");

	check_carplay_mode(false);
	check_carplay_mode_count(0);
}

T_DECL(carplay_mode_child_exit, "carplay mode bit should disappear when child exits",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1), T_META_REQUIRES_SYSCTL_EQ("kern.thread_groups_supported", 1))
{
	T_LOG("uid: %d", getuid());
	skip_if_unsupported();

	check_carplay_mode(false);
	check_carplay_mode_count(0);

	T_LOG("Spawning child");

	pid_t child_pid = fork();

	if (child_pid == 0) {
		/* child process */

		check_carplay_mode(false);
		check_carplay_mode_count(0);

		T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
		    "setpriority(PRIO_DARWIN_CARPLAY_MODE_ON)");

		check_carplay_mode(true);
		check_carplay_mode_count(1);

		T_LOG("Exit pid %d with the caprlay mode bit on", getpid());

		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork, pid %d", child_pid);

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_carplay_mode(false);
	check_carplay_mode_count(0);
}


T_DECL(carplay_mode_double_set_and_child_exit, "carplay mode bit on parent should stay when carplay mode child exits",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1), T_META_REQUIRES_SYSCTL_EQ("kern.thread_groups_supported", 1))
{
	T_LOG("uid: %d", getuid());
	skip_if_unsupported();

	check_carplay_mode(false);
	check_carplay_mode_count(0);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE_ON)");

	check_carplay_mode(true);
	check_carplay_mode_count(1);

	pid_t child_pid = fork();

	if (child_pid == 0) {
		/* child process */

		check_carplay_mode(false);
		check_carplay_mode_count(1);

		T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
		    "setpriority(PRIO_DARWIN_CARPLAY_MODE_ON)");

		check_carplay_mode(true);
		check_carplay_mode_count(2);

		T_LOG("Exit pid %d with the carplay mode bit on", getpid());
		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork, pid %d", child_pid);

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_carplay_mode(true);
	check_carplay_mode_count(1);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE_OFF)");

	check_carplay_mode(false);
	check_carplay_mode_count(0);
}

T_DECL(carplay_mode_double_set_and_child_unset, "caprlay mode bit on parent should stay when carplay mode child unsets",
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1), T_META_REQUIRES_SYSCTL_EQ("kern.thread_groups_supported", 1))
{
	T_LOG("uid: %d", getuid());
	skip_if_unsupported();

	check_carplay_mode(false);
	check_carplay_mode_count(0);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE_ON)");

	check_carplay_mode(true);
	check_carplay_mode_count(1);

	pid_t child_pid = fork();

	if (child_pid == 0) {
		/* child process */

		check_carplay_mode(false);
		check_carplay_mode_count(1);

		T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_ON),
		    "setpriority(PRIO_DARWIN_CARPLAY_MODE_ON)");

		check_carplay_mode(true);
		check_carplay_mode_count(2);

		T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF),
		    "setpriority(PRIO_DARWIN_CARPLAY_MODE_OFF)");

		check_carplay_mode(false);
		check_carplay_mode_count(1);

		T_LOG("Exit pid %d with the carplay mode bit off", getpid());
		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork, pid %d", child_pid);

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_carplay_mode(true);
	check_carplay_mode_count(1);

	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_DARWIN_CARPLAY_MODE, 0, PRIO_DARWIN_CARPLAY_MODE_OFF),
	    "setpriority(PRIO_DARWIN_CARPLAY_MODE_OFF)");

	check_carplay_mode(false);
	check_carplay_mode_count(0);
}
