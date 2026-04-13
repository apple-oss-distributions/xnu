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
#include <spawn.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/code_signing.h>

extern char **environ;

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ipc"),
	T_META_TAG_VM_PREFERRED);

#define VERSION_BUF_SIZE 32

typedef struct {
	const char* binary_name;
	bool should_exec_succeed;
	uint8_t expected_platform_restrictions_version;
} platform_restrictions_test_case_t;

static int
read_platform_version_from_pipe(int pipefd)
{
	char buf[VERSION_BUF_SIZE];
	ssize_t n = read(pipefd, buf, sizeof(buf) - 1);
	T_QUIET; T_ASSERT_GT((long)n, (long)0, "read platform version from child stdout");
	buf[n] = '\0';
	return atoi(buf);
}

static void
validate_platform_restrictions_version_and_kill_child(pid_t child_pid, int pipefd,
    platform_restrictions_test_case_t test, const char *method)
{
	int actual_version = read_platform_version_from_pipe(pipefd);
	T_EXPECT_EQ_INT(actual_version, test.expected_platform_restrictions_version,
	    "[%s] %s: expect version %d, got %d",
	    method, test.binary_name, test.expected_platform_restrictions_version, actual_version);

	close(pipefd);

	int status;
	if (waitpid(child_pid, &status, WNOHANG) == 0) {
		kill(child_pid, SIGKILL);
		waitpid(child_pid, &status, 0);
	}
}

static bool
is_running_with_amfi_overrides(void)
{
	code_signing_config_t cs_config = 0;
	size_t cs_config_size = sizeof(cs_config);
	int ret;

	ret = sysctlbyname("security.codesigning.config", &cs_config, &cs_config_size, NULL, 0);
	if (ret != 0) {
		T_FAIL("Failed to read security.codesigning.config");
		return false;
	}

	/* CS_CONFIG_GET_OUT_OF_MY_WAY causes everything to run as platform... */
	if (cs_config & CS_CONFIG_GET_OUT_OF_MY_WAY) {
		return true;
	}

	return false;
}

static void
test_under_posix_spawn(platform_restrictions_test_case_t test)
{
	char path[1024];
	pid_t child_pid = 0;
	int spawn_err;
	int pipefd[2];
	posix_spawn_file_actions_t file_actions;

	T_LOG("[posix_spawn] %s (should_exec_succeed=%d, expected_platform_restrictions_version=%d)",
	    test.binary_name, test.should_exec_succeed, test.expected_platform_restrictions_version);

	snprintf(path, sizeof(path), "./%s", test.binary_name);
	char *args[] = { path, NULL };

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(pipefd), "pipe");

	posix_spawn_file_actions_init(&file_actions);
	posix_spawn_file_actions_adddup2(&file_actions, pipefd[1], STDOUT_FILENO);
	posix_spawn_file_actions_addclose(&file_actions, pipefd[0]);
	posix_spawn_file_actions_addclose(&file_actions, pipefd[1]);

	spawn_err = posix_spawn(&child_pid, args[0], &file_actions, NULL, args, environ);
	posix_spawn_file_actions_destroy(&file_actions);

	close(pipefd[1]);

	if (test.should_exec_succeed) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(spawn_err, "posix_spawn(%s)", test.binary_name);
		validate_platform_restrictions_version_and_kill_child(child_pid, pipefd[0], test, "posix_spawn");
	} else {
		T_EXPECT_EQ_INT(spawn_err, EINVAL, "posix_spawn(%s) fails", test.binary_name);
		close(pipefd[0]);
	}
}

static void
test_under_exec(platform_restrictions_test_case_t test)
{
	char path[1024];
	pid_t child_pid;
	int pipefd[2];

	T_LOG("[exec] %s (should_exec_succeed=%d, expected_platform_restrictions_version=%d)",
	    test.binary_name, test.should_exec_succeed, test.expected_platform_restrictions_version);

	snprintf(path, sizeof(path), "./%s", test.binary_name);
	char *args[] = { path, NULL };

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(pipefd), "pipe");

	child_pid = fork();
	T_QUIET; T_ASSERT_NE(child_pid, -1, "fork");

	if (child_pid == 0) {
		/* (Child, exec into binary under test) */
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		execve(args[0], args, environ);
		exit(errno);
	}

	close(pipefd[1]);

	if (test.should_exec_succeed) {
		validate_platform_restrictions_version_and_kill_child(child_pid, pipefd[0], test, "exec");
	} else {
		close(pipefd[0]);
		int status;
		waitpid(child_pid, &status, 0);
		T_QUIET; T_EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
		    "[exec] %s receives SIGKILL", test.binary_name);
	}
}

T_DECL(validate_platform_restrictions_entitlements_parsing,
    "Parametrized test to validate the functionality of the platform-restrictions entitlements",
    T_META_IGNORECRASHES(".*platform-restrictions.*"))
{
	platform_restrictions_test_case_t test_cases[] = {
		/* *** Integer-based legacy entitlement *** */
		/* All inputs for the int entitlement should succeed and result in level == 2*/
		{"platform-restrictions-int-0", true, 2},
		{"platform-restrictions-int-1", true, 2},
		{"platform-restrictions-int-2", true, 2},
		{"platform-restrictions-int-255", true, 2},
		{"platform-restrictions-int-with-string-value", true, 2},
		{"platform-restrictions-int-with-bool-true-value", true, 2},
		{"platform-restrictions-int-with-bool-false-value", true, 2},

		/* *** New-style string-based entitlement *** */
		/* Invalid strings should fail to launch */
		{"platform-restrictions-str-empty", false, 0},
		{"platform-restrictions-str-invalid", false, 0},
		{"platform-restrictions-str-with-int-value", false, 0},
		{"platform-restrictions-str-with-bool-true-value", false, 0},
		{"platform-restrictions-str-with-bool-false-value", false, 0},
		{"platform-restrictions-str-with-trailing-bad-data", false, 0},
		/* Versions < 2 || >= 8 should fail to launch */
		{"platform-restrictions-str-0", false, 0},
		{"platform-restrictions-str-1", false, 0},
		{"platform-restrictions-str-8", false, 0},
		/* val == '2' should result in level 2 */
		{"platform-restrictions-str-2", true, 2},
		/* val == '7' should result in level 7 */
		{"platform-restrictions-str-7", true, 7},

		/* *** Special cases *** */
		/* In the presence of both the old and new entitlements, the new str-based entitlement should win */
		{"platform-restrictions-mixed", true, 5},
	};

	size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

	/*
	 * BATS compatibility: The BATS environment treats all binaries as platform due to
	 * the presence of `amfi_get_out_of_my_way=1`. Since `platform-version` is automatically`
	 * set to `3` on platform binaries, all our test binaries will receive version `3` in BATS.
	 */
	if (is_running_with_amfi_overrides()) {
		/* We expect all launches to succeed and receive restriction level `3` */
		T_LOG("Overriding expectations as we detected AMFI overrides, every launch should succeed and receive the highest platform version");
		for (size_t i = 0; i < num_tests; i++) {
			platform_restrictions_test_case_t* test_case = &test_cases[i];
			test_case->should_exec_succeed = true;
			test_case->expected_platform_restrictions_version = 3;
		}
	}

	for (size_t i = 0; i < num_tests; i++) {
		platform_restrictions_test_case_t test_case = test_cases[i];
		test_under_exec(test_case);
		test_under_posix_spawn(test_case);
	}
}
