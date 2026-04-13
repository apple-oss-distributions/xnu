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
#include <stdlib.h>
#include <signal.h>
#include <spawn_private.h>
#include <sys/sysctl.h>
#include <sys/coalition.h>
#include <sys/spawn_internal.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.rm"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("RM"),
    T_META_OWNER("m_staveleytaylor"));

static uint64_t
create_coalition()
{
	uint64_t id = 0;
	uint32_t flags = 0;
	uint64_t param[2];
	int ret;

	COALITION_CREATE_FLAGS_SET_TYPE(flags, COALITION_TYPE_RESOURCE);
	ret = coalition_create(&id, flags);
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_create");
	T_QUIET;
	T_ASSERT_GE(id, 0ULL, "coalition_create returned a valid id");

	T_LOG("coalition has id %lld\n", id);

	/* disable notifications for this coalition so launchd doesn't freak out */
	param[0] = id;
	param[1] = 0;
	ret = sysctlbyname("kern.coalition_notify", NULL, NULL, param, sizeof(param));
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "kern.coalition_notify");

	return id;
}

static pid_t
spawn_helper_in_coalition(char *helper_name, uint64_t coal_id)
{
	int ret;
	posix_spawnattr_t attr;
	extern char **environ;
	pid_t new_pid = 0;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);

	T_QUIET;
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size),
	    "_NSGetExecutablePath");
	char *args[] = {path, "-n", helper_name, NULL};

	ret = posix_spawnattr_init(&attr);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setcoalition_np");
	ret = posix_spawnattr_setcoalition_np(&attr, coal_id,
	    COALITION_TYPE_RESOURCE,
	    COALITION_TASKROLE_LEADER);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setcoalition_np");

	T_LOG("posix_spawn %s %s %s", args[0], args[1], args[2]);
	ret = posix_spawn(&new_pid, path, NULL, &attr, args, environ);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");
	return new_pid;
}

static bool
has_unrestrict_coalitions()
{
	int ret, val;
	size_t val_sz;

	val = 0;
	val_sz = sizeof(val);
	ret = sysctlbyname("kern.unrestrict_coalitions", &val, &val_sz, NULL, 0);
	return ret >= 0;
}

static void
unrestrict_coalitions()
{
	int ret, val = 1;
	size_t val_sz;
	val_sz = sizeof(val);
	ret = sysctlbyname("kern.unrestrict_coalitions", NULL, 0, &val, val_sz);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.unrestrict_coalitions <- 1");
}

static void
restrict_coalitions()
{
	int ret, val = 0;
	size_t val_sz;
	val_sz = sizeof(val);
	ret = sysctlbyname("kern.unrestrict_coalitions", NULL, 0, &val, val_sz);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.unrestrict_coalitions <- 0");
}

static int
get_pid_list(uint64_t cid, pid_t *pids, int npids)
{
	size_t size = npids * sizeof(pid_t);
	memset(pids, 0, size);
	int ret = coalition_info_pid_list(cid, pids, &size);
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_pid_list");
	return size / sizeof(pid_t);
}

/* Check that big_list consists of those PIDs in small_list, followed by zeros */
static void
check_contains_exactly_pids_or_zeros(pid_t *big_list, int big_list_npids, pid_t *small_list, int small_list_npids)
{
	bool has_pid[small_list_npids];
	memset(has_pid, 0, sizeof(has_pid));

	/* Check that all our spawned PIDs are present in the list */
	for (size_t i = 0; i < small_list_npids; i++) {
		for (size_t j = 0; j < small_list_npids; j++) {
			has_pid[j] |= small_list[j] == big_list[i];
		}
	}
	for (size_t j = 0; j < small_list_npids; j++) {
		T_QUIET; T_ASSERT_TRUE(has_pid[j], "pid list has %d", small_list[j]);
	}

	/* Tail of the list should be zero */
	for (size_t i = small_list_npids; i < big_list_npids; i++) {
		T_QUIET; T_ASSERT_EQ(big_list[i], 0, "pid should be zero");
	}
}

T_HELPER_DECL(sleepy_helper, "")
{
	/* This should be long enough... right? */
	sleep(1000);
}

T_DECL(coalition_info_pid_list, "coalition_info_pid_list", T_META_ASROOT(true), T_META_RUN_CONCURRENTLY(false) /* due to unrestrict_coalitions */)
{
	if (!has_unrestrict_coalitions()) {
		T_SKIP("Unable to test coalitions on this kernel.");
	}
	unrestrict_coalitions();
	T_ATEND(restrict_coalitions);

#define NPIDS 32
	pid_t pids[NPIDS];
	memset(pids, 0, sizeof(pids));

	uint64_t test_coal = create_coalition();

	int pid_list_len = get_pid_list(test_coal, pids, NPIDS);
	T_ASSERT_EQ(pid_list_len, 0, "pid list size");

	for (size_t i = 0; i < NPIDS; i++) {
		T_QUIET; T_ASSERT_EQ(pids[i], 0, "pid should be zero");
	}

#define NSPAWNED 8
	pid_t spawned_pids[NSPAWNED];
	for (size_t j = 0; j < NSPAWNED; j++) {
		spawned_pids[j] = spawn_helper_in_coalition("sleepy_helper", test_coal);
	}

	/* Try zero length buffer */
	pid_list_len = get_pid_list(test_coal, pids, 0);
	T_ASSERT_EQ(pid_list_len, 0, "pid list size");

	/* Get one PID (buffer is smaller than actual ntasks) */
	pid_list_len = get_pid_list(test_coal, pids, 1);
	T_ASSERT_EQ(pid_list_len, 1, "pid list size");

	/* Get all PIDs (buffer is larger than actual ntasks) */
	pid_list_len = get_pid_list(test_coal, pids, NPIDS);
	T_ASSERT_EQ(pid_list_len, NSPAWNED, "pid list size");
	check_contains_exactly_pids_or_zeros(pids, pid_list_len, spawned_pids, NSPAWNED);

	/* Get all PIDs (buffer is larger than max possible ntasks) */
	pid_t *big_pid_list = calloc(COALITION_INFO_PID_LIST_MAX_PIDS * 2, sizeof(pid_t));
	pid_list_len = get_pid_list(test_coal, big_pid_list, COALITION_INFO_PID_LIST_MAX_PIDS * 2);
	T_ASSERT_EQ(pid_list_len, NSPAWNED, "pid list size");
	check_contains_exactly_pids_or_zeros(big_pid_list, pid_list_len, spawned_pids, NSPAWNED);
	free(big_pid_list);

	/* Gracefully wake helpers from their slumber, causing them to exit */
	for (size_t j = 0; j < NSPAWNED; j++) {
		pid_t pid = spawned_pids[j];
		kill(spawned_pids[j], SIGTERM);

		int status = 0;
		T_LOG("waiting for pid %d...", pid);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid %d", pid);
		T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "signaled");
		T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGTERM, "with SIGTERM");
	}

	/* Now the coal should be empty */
	pid_list_len = get_pid_list(test_coal, pids, NPIDS);
	T_ASSERT_EQ(pid_list_len, 0, "pid list size");

	for (size_t i = 0; i < NPIDS; i++) {
		T_QUIET; T_ASSERT_EQ(pids[i], 0, "pid should be zero");
	}
}
