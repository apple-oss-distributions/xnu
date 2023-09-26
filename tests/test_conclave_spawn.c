/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/exclaves.h>
#include <mach/exclaves_l4.h>
#include <libgen.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <removefile.h>
#include <spawn.h>
#include <spawn_private.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.exclaves"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", name);
	return result;
}

T_DECL(conclave_spawn, "Test the spawn api for conclave")
{
	posix_spawnattr_t attrs;
	char *test_prog_name = "conclave_process";
	char *test_prog_path = "./conclave_process";
	char *child_args[3];
	char *conclave_name = "com.apple.conclave.test1";
	pid_t child_pid;
	int64_t r = run_sysctl_test("exclaves_hello_exclave_test", 0);

	if (r == -1) {
		T_SKIP("Exclave not available");
		T_END;
	}

	/* Initialize posix_spawn attributes */
	posix_spawnattr_init(&attrs);

	int err = posix_spawnattr_set_conclave_id_np(&attrs, conclave_name);
	T_EXPECT_POSIX_SUCCESS(err, "posix_spawnattr_set_conclave_id_np");

	child_args[0] = test_prog_name;
	child_args[1] = conclave_name;
	child_args[2] = NULL;

	err = posix_spawn(&child_pid, test_prog_path, NULL, &attrs, &child_args[0], NULL);
	T_EXPECT_POSIX_SUCCESS(err, "posix_spawn");

	T_LOG("Child pid is %d\n", child_pid);

	int child_status;
	/* Wait for child and check for return value */
	if (-1 == waitpid(child_pid, &child_status, 0)) {
		T_FAIL("wait4: child mia with errno %d", errno);
	}

	if (WIFEXITED(child_status)) {
		T_EXPECT_EQ_INT(WEXITSTATUS(child_status), 0, "Check if child returned zero on exit");
	} else {
		T_FAIL("Child %d did not exit normally\n", child_pid);
	}
	T_END;
}
