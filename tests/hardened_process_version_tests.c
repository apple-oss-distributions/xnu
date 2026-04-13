/*
 * Copyright (c) 2026 Apple Computer, Inc. All rights reserved.
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
#include <stdarg.h>
#include <spawn_private.h>
#include <sys/reason.h>
#include <libproc.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"));

extern char **environ;
#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef struct {
	char *path;
	char *trace;
	bool expect_load_fail;
} hardened_process_version_test_t;

hardened_process_version_test_t tests[] = {
	{
		"./hardened_process_version_no_entitlement",
		"no version entitlement is set, version should be set to latest"
	},
	{
		"./hardened_process_version_string_entitlement_v1",
		"version should be set to the string entitlement value, which is 1"
	},
	{
		"./hardened_process_version_string_entitlement_v2",
		"version should be set to the string entitlement value, which is 2"
	},
	{
		"./hardened_process_version_string_entitlement_v255",
		"version should be set to the closest supported version to the integer entitlement"
	},
	{
		"./hardened_process_version_integer_entitlement_v1",
		"version should be set to the integer entitlement value, which is 1"
	},
	{
		"./hardened_process_version_integer_entitlement_v2",
		"version should be set to the integer entitlement value, which is 2"
	},
	{
		"./hardened_process_version_integer_entitlement_v255",
		"version should be set to the closest supported version to the integer entitlement"
	},
	{
		"./hardened_process_version_string_integer_entitlement_v2",
		"if both entitlements present, version should be set to the string entitlement value, which is 2"
	},
	{
		"./hardened_process_version_string_integer_entitlement_v1",
		"if both entitlements present, version should be set to the string entitlement value, which is 1"
	},
	{
		"./hardened_process_version_illegal_string_base_entitlement",
		"in the case of illegal string entitlement, we fail the load",
		.expect_load_fail = true
	},
	{
		"./hardened_process_version_illegal_string_type_entitlement",
		"in the case of illegal string entitlement, we fail the load",
		.expect_load_fail = true
	}
};

void
expect_sigkill(void (^fn)(void), const char *format_description, ...)
{
	char description[0x100];

	va_list args;
	va_start(args, format_description);
	vsnprintf(description, sizeof(description), format_description, args);
	va_end(args);

	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		exit(0);
	} else {
		int status = 0;
		struct proc_exitreasonbasicinfo exit_reason = {0};

		sleep(1);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(proc_pidinfo(pid,
		    PROC_PIDEXITREASONBASICINFO, 1, &exit_reason, sizeof(exit_reason)), "basic exit reason");

		T_ASSERT_EQ((int)(exit_reason.beri_flags & EXEC_EXIT_REASON_BAD_MACHO), 0, "%s",
		    format_description);
	}
}

T_DECL(test_hardened_process_version_entitlements,
    "Test combinations of integer and string entitlements for hardened process version")
{
	for (int i = 0; i < countof(tests); ++i) {
		hardened_process_version_test_t test = tests[i];

		T_LOG("Run %s", test.path);

		if (test.expect_load_fail) {
			expect_sigkill(^{
				char *args[2] = { test.path, NULL };
				execve(args[0], args, environ);
			}, "%s", test.trace);
		} else {
			posix_spawnattr_t attr;
			char *args[2] = { test.path, NULL };
			pid_t child_pid;
			int status;
			int ret;

			ret = posix_spawnattr_init(&attr);
			T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

			ret = posix_spawn(&child_pid, args[0], NULL, &attr, args, environ);
			T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "posix_spawn");

			ret = waitpid(child_pid, &status, 0);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "waitpid");

			T_EXPECT_TRUE(WIFEXITED(status), "exited successfully");
			T_EXPECT_TRUE(WEXITSTATUS(status) == 0, "%s", test.trace);
		}
	}
}
