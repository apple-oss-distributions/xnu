/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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

/*
 * tests for scheduler hygiene system call rejection feature
 */

#include <darwintest.h>
#include <darwintest_posix.h>
#include <darwintest_utils.h>

#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/kern_debug.h>
#include <sys/stat.h>

#include <mach-o/dyld.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.debug"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("julien_oster")
	);

static int const ALIVE = 0;
static int const DEAD = 1;

static int
helper(char **args)
{
	int ret = 0;
	int status = 0;
	int signal = 0;
	int timeout = 30;

	pid_t child_pid = 0;
	bool wait_ret = true;

	char binary_path[MAXPATHLEN], *binary_dir = NULL;
	uint32_t path_size = sizeof(binary_path);

	ret = _NSGetExecutablePath(binary_path, &path_size);
	T_QUIET; T_ASSERT_EQ(ret, 0, "_NSGetExecutablePath: %s, size: %d", binary_path, path_size);
	binary_dir = dirname(binary_path);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(binary_dir, "get binary directory: %s", binary_dir);

	char const *helper_binary = "debug_syscall_rejection_helper";
	snprintf(binary_path, MAXPATHLEN, "%s/%s", binary_dir, helper_binary);
	args[0] = binary_path;

	ret = dt_launch_tool(&child_pid, args, false, NULL, NULL);
	T_QUIET; T_ASSERT_EQ(ret, 0, "launch helper: %s", helper_binary);

	wait_ret = dt_waitpid(child_pid, &status, &signal, timeout);

	if (wait_ret) {
		// T_LOG("helper returned: %d", status);

		T_EXPECT_EQ(status, 0, "helper returned exit code %i", status);

		return 0;
	}

	// helper crashed (possibly expectedly)

	if (signal != 0) {
		// T_LOG("signal terminated helper: %d", signal);

		T_EXPECT_EQ(signal, SIGKILL, "helper terminated with signal %i", signal);
		return 1;
	}

	T_FAIL("helper terminated with unexpected condition (status: %i, signal: %i)", status, signal);
	return 2;
}

static void
do_test(char const *msg, int expectation, ...)
{
	size_t const arg_max_count = 128;
	char *args[arg_max_count] = {0};

	va_list ap;
	va_start(ap, expectation);

	char *arg;
	int i = 1;
	while ((arg = va_arg(ap, char *)) != NULL) {
		T_QUIET; T_ASSERT_LT(i, (int)arg_max_count, "no args overflow");
		args[i++] = arg;
	}

	va_end(ap);

	T_EXPECT_EQ(helper(args), expectation, "%s", msg);
}

#define ALLOW(pos, mask) "-a", "-s", #mask, "-i", #pos
#define DENY(pos, mask) "-d", "-s", #mask, "-i", #pos

T_DECL(debug_syscall_rejection_tests,
    "Verify that syscall rejection works",
    T_META_SYSCTL_INT("kern.debug_syscall_rejection_mode=1"),
    T_META_REQUIRES_SYSCTL_EQ("kern.debug_syscall_rejection_mode", 1))
{
	int old_mode;
	size_t old_mode_size = sizeof(old_mode);
	int new_mode = 2;

	// test syscall mode switching (even if already done by T_META_SYSCTL_INT)
	int ret = sysctlbyname("kern.debug_syscall_rejection_mode", &old_mode, &old_mode_size, &new_mode, sizeof(new_mode));
	if (ret != 0) {
		T_ASSERT_FAIL("Syscall rejection mode switching failed: ret %d, errno %d", ret, errno);
	}

	T_ASSERT_EQ(old_mode_size, sizeof(old_mode), "sysctl returns correct size");

	char * const set_mask_12 = "12: chdir debug_syscall_reject_config";
	size_t const set_mask_12_size = strlen(set_mask_12);
	T_EXPECT_POSIX_SUCCESS(sysctlbyname("kern.syscall_rejection_masks", NULL, NULL, set_mask_12, set_mask_12_size),
	    "set syscall rej test mask");

	do_test("default is disallow all", DEAD, NULL);
	do_test("disallow all dies", DEAD, DENY(0, 1), NULL);
	do_test("allow all lives", ALIVE, ALLOW(0, 1), NULL);
	do_test("allow testmask lives", ALIVE, ALLOW(0, 12), NULL);
	do_test("disallow testmask overrides dies", DEAD, ALLOW(0, 1), DENY(1, 12), NULL);

	// check that all slots work as expected
	int const slots = 16;
	for (int i = 0; i < slots - 1; i++) {
		size_t const max_pos_len = 16;
		char pos1[max_pos_len], pos2[max_pos_len];
		T_QUIET; T_ASSERT_GE_INT(snprintf(pos1, max_pos_len, "%u", i), 0, "creating pos1");
		T_QUIET; T_ASSERT_GE_INT(snprintf(pos2, max_pos_len, "%u", i + 1), 0, "creating pos2");

		char *args[] = {DENY(pos1, ALL), ALLOW(pos2, 12), NULL};
		T_EXPECT_EQ(helper(args), ALIVE, "pos %s/%s works (alive)", pos1, pos2);
		char *args_d[] = {ALLOW(pos1, ALL), DENY(pos2, 12), NULL};
		T_EXPECT_EQ(helper(args_d), DEAD, "pos %s/%s works (dead)", pos1, pos2);
	}

	// check non-fatal mode
	new_mode = 1;
	T_EXPECT_POSIX_SUCCESS(sysctlbyname("kern.debug_syscall_rejection_mode", NULL, NULL, &new_mode, sizeof(new_mode)),
	    "set syscall rej mode to non-fatal");

	do_test("non-fatal: default is disallow all", ALIVE, NULL);
	do_test("non-fatal: disallow all", ALIVE, DENY(0, 1), NULL);
	do_test("non-fatal: allow all", ALIVE, ALLOW(0, 1), NULL);
	do_test("non-fatal: allow testmask", ALIVE, ALLOW(0, 12), NULL);
	do_test("non-fatal: disallow testmask overrides", ALIVE, ALLOW(0, 1), DENY(1, 12), NULL);

	// check force-fatal override
	new_mode = 1;
	T_EXPECT_POSIX_SUCCESS(sysctlbyname("kern.debug_syscall_rejection_mode", NULL, NULL, &new_mode, sizeof(new_mode)),
	    "set syscall rej mode to non-fatal");

	do_test("force-fatal: default is disallow all", DEAD, "-F", NULL);
	do_test("force-fatal: disallow all", DEAD, DENY(0, 1), "-F", NULL);
	do_test("force-fatal: allow all", ALIVE, ALLOW(0, 1), "-F", NULL);
	do_test("force-fatal: allow testmask", ALIVE, ALLOW(0, 12), "-F", NULL);
	do_test("force-fatal: disallow testmask overrides", DEAD, ALLOW(0, 1), DENY(1, 12), "-F", NULL);
}

T_DECL(debug_enable_syscall_rejection_crash_count,
    "count syscall rejection crash reports",
    T_META_ENABLED(FALSE) /* currently a manual test */
    )
{
	syscall_rejection_selector_t masks[] = {
		SYSCALL_REJECTION_ALLOW(SYSCALL_REJECTION_ALL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_NULL),
		SYSCALL_REJECTION_DENY(2),
		SYSCALL_REJECTION_DENY(2),
		SYSCALL_REJECTION_DENY(2),
		SYSCALL_REJECTION_DENY(2),
		SYSCALL_REJECTION_DENY(2),
		SYSCALL_REJECTION_DENY(2),
		SYSCALL_REJECTION_DENY(2),
	};

	int ret = debug_syscall_reject_config(masks, sizeof(masks) / sizeof(masks[0]), SYSCALL_REJECTION_FLAGS_DEFAULT);

	T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "debug_syscall_reject_config");

	ret = chdir("/tmp");
	ret = chdir("/tmp");
	ret = chdir("/tmp");

	printf("chdir: %i\n", ret);

	ret = debug_syscall_reject_config(masks, sizeof(masks) / sizeof(masks[0]), SYSCALL_REJECTION_FLAGS_ONCE);

	T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "debug_syscall_reject_config once");

	ret = chdir("/tmp");
	ret = chdir("/tmp");
	ret = chdir("/tmp");

	printf("chdir once: %i\n", ret);

	ret = debug_syscall_reject_config(masks, sizeof(masks) / sizeof(masks[0]), SYSCALL_REJECTION_FLAGS_ONCE);

	T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "debug_syscall_reject_config once ignore");

	ret = chdir("/tmp");
	ret = chdir("/tmp");
	ret = chdir("/tmp");

	printf("chdir once ignore: %i\n", ret);

	ret = debug_syscall_reject_config(masks, sizeof(masks) / sizeof(masks[0]), SYSCALL_REJECTION_FLAGS_FORCE_FATAL);

	T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(ret, "debug_syscall_reject_config fatal");

	ret = chdir("/tmp");
	ret = chdir("/tmp");
	ret = chdir("/tmp");

	printf("chdir fatal: %i\n", ret); // unreached, but this is currently manual testing only

	/*
	 * Expected number of crash reports:
	 * Mode				Crashes		Reason
	 * Ignore (0)		1			force fatal causes final crash
	 * Guard (1)		5			3 without ONCE flag, 1 with ONCE flag, final forced fatal crash
	 * Fatal (2)		1			first crash is fatal
	 */
}
