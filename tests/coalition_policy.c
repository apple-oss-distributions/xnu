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

#include <sys/coalition_private.h>

#include <mach/coalition.h>
#include <sys/coalition.h>
#include <libproc.h>

#include <sys/types.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/task.h>
#include <mach/task_policy.h>
#include <mach/mach.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"),
    T_META_OWNER("chimene"),
    T_META_RUN_CONCURRENTLY(false));

static uint64_t
get_jet_id(void)
{
	T_LOG("uid: %d, pid %d", getuid(), getpid());

	struct proc_pidcoalitioninfo idinfo;

	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t res_id = idinfo.coalition_id[COALITION_TYPE_RESOURCE];
	uint64_t jet_id = idinfo.coalition_id[COALITION_TYPE_JETSAM];

	T_LOG("Resource coalition: %lld, Jetsam coalition: %lld", res_id, jet_id);

	return jet_id;
}

static void
check_is_bg(bool wants_bg)
{
	kern_return_t kr;
	struct task_policy_state policy_state;

	mach_msg_type_number_t count = TASK_POLICY_STATE_COUNT;
	boolean_t get_default = FALSE;

	kr = task_policy_get(mach_task_self(), TASK_POLICY_STATE,
	    (task_policy_t)&policy_state, &count, &get_default);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_policy_get(TASK_POLICY_STATE)");

	/*
	 * A test reporting type=APPLICATION should have the live donor bit set.
	 * If this fails, the test may have been launched as a daemon instead.
	 */
	T_QUIET; T_ASSERT_BITS_SET(policy_state.flags, TASK_IMP_LIVE_DONOR, "test should be live donor enabled");

	/*
	 * The BG bit is updated via task_policy_update_internal_locked,
	 * checking this proves that the first phase update ran on this task.
	 */
	if (wants_bg) {
		T_ASSERT_BITS_SET(policy_state.effective, POLICY_EFF_DARWIN_BG, "%d: is BG", getpid());
	} else {
		T_ASSERT_BITS_NOTSET(policy_state.effective, POLICY_EFF_DARWIN_BG, "%d: is not BG", getpid());
	}

	/*
	 * The live donor bit is updated via task_policy_update_complete_unlocked,
	 * checking this proves that the second phase update ran on this task.
	 */
	if (wants_bg) {
		T_ASSERT_BITS_NOTSET(policy_state.flags, TASK_IMP_DONOR, "%d: is not live donor", getpid());
	} else {
		T_ASSERT_BITS_SET(policy_state.flags, TASK_IMP_DONOR, "%d: is live donor", getpid());
	}
}

static void
set_coalition_bg(uint64_t jet_id, bool set_bg)
{
	if (set_bg) {
		T_ASSERT_POSIX_SUCCESS(coalition_policy_set(jet_id, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_DARWIN_BG),
		    "coalition_policy_set(%lld, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_DARWIN_BG)", jet_id);
	} else {
		T_ASSERT_POSIX_SUCCESS(coalition_policy_set(jet_id, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_NONE),
		    "coalition_policy_set(%lld, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_NONE)", jet_id);
	}
}

static void
log_suppress(uint64_t jet_id)
{
	int suppress = coalition_policy_get(jet_id, COALITION_POLICY_SUPPRESS);
	T_ASSERT_POSIX_SUCCESS(suppress, "coalition_policy_get(%lld, COALITION_POLICY_SUPPRESS)", jet_id);
	T_LOG("suppress: %d", suppress);
}

static void
restore_coalition_state(void)
{
	struct proc_pidcoalitioninfo idinfo;

	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t jet_id = idinfo.coalition_id[COALITION_TYPE_JETSAM];

	T_QUIET; T_ASSERT_POSIX_SUCCESS(coalition_policy_set(jet_id, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_NONE),
	    "coalition_policy_set(%lld, COALITION_POLICY_SUPPRESS, COALITION_POLICY_SUPPRESS_NONE)", jet_id);
}


T_DECL(coalition_suppress_read_entitled, "COALITION_POLICY_SUPPRESS should be readable with entitlement")
{
	T_ATEND(restore_coalition_state);

	uint64_t jet_id = get_jet_id();

	int suppress = coalition_policy_get(jet_id, COALITION_POLICY_SUPPRESS);

	T_ASSERT_POSIX_SUCCESS(suppress, "coalition_policy_get(%lld, COALITION_POLICY_SUPPRESS)", jet_id);

	T_LOG("suppress: %d", suppress);
}

T_DECL(coalition_suppress_read_rsrc_coalition, "COALITION_POLICY_SUPPRESS shouldn't work on resource coalitions")
{
	T_ATEND(restore_coalition_state);

	T_LOG("uid: %d, pid %d", getuid(), getpid());

	struct proc_pidcoalitioninfo idinfo;

	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t res_id = idinfo.coalition_id[COALITION_TYPE_RESOURCE];
	uint64_t jet_id = idinfo.coalition_id[COALITION_TYPE_JETSAM];

	T_LOG("res_id: %lld, jet_id: %lld", res_id, jet_id);

	int suppress = coalition_policy_get(res_id, COALITION_POLICY_SUPPRESS);

	T_EXPECT_POSIX_FAILURE(suppress,
	    ENOTSUP, "coalition_policy_get(%lld, COALITION_POLICY_SUPPRESS)", res_id);

	T_LOG("suppress: %d", suppress);
}

T_DECL(coalition_suppress_set, "COALITION_POLICY_SUPPRESS should be settable with entitlement")
{
	T_ATEND(restore_coalition_state);

	uint64_t jet_id = get_jet_id();

	set_coalition_bg(jet_id, true);

	log_suppress(jet_id);

	set_coalition_bg(jet_id, false);

	log_suppress(jet_id);
}

T_DECL(coalition_suppress_set_check_task, "current task should become BG when coalition changes", T_META_ASROOT(true))
{
	T_ATEND(restore_coalition_state);

	uint64_t jet_id = get_jet_id();

	log_suppress(jet_id);

	check_is_bg(false);

	set_coalition_bg(jet_id, true);

	log_suppress(jet_id);

	check_is_bg(true);

	set_coalition_bg(jet_id, false);

	log_suppress(jet_id);

	check_is_bg(false);
}

T_DECL(coalition_suppress_child_bg, "child spawned into bg coalition should be bg", T_META_ASROOT(true))
{
	T_ATEND(restore_coalition_state);

	uint64_t jet_id = get_jet_id();

	check_is_bg(false);

	set_coalition_bg(jet_id, true);

	check_is_bg(true);

	T_LOG("Spawning child");

	pid_t child_pid = fork();

	if (child_pid == 0) {
		/* child process */

		//T_LOG("child pid %d sleeping", getpid());

		//sleep(10000);

		check_is_bg(true);

		T_LOG("Exit pid %d", getpid());

		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork returned, child pid %d", child_pid);

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 500000), /* TODO */
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_is_bg(true);

	set_coalition_bg(jet_id, false);

	check_is_bg(false);
}

T_DECL(coalition_suppress_child_change_bg, "child changing coalition to bg should affect parent", T_META_ASROOT(true))
{
	T_ATEND(restore_coalition_state);

	uint64_t jet_id = get_jet_id();

	check_is_bg(false);

	T_LOG("Spawning child");

	pid_t child_pid = fork();

	if (child_pid == 0) {
		/* child process */

		check_is_bg(false);

		set_coalition_bg(jet_id, true);

		check_is_bg(true);

		T_LOG("Exit pid %d", getpid());

		exit(0);
	} else {
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork returned, child pid %d", child_pid);

		/* wait for child process to exit */
		int exit_status = 0, signum = 0;

		T_ASSERT_TRUE(dt_waitpid(child_pid, &exit_status, &signum, 5),
		    "wait for child (%d) complete", child_pid);

		T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
		T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");
	}

	check_is_bg(true);

	set_coalition_bg(jet_id, false);

	check_is_bg(false);
}
