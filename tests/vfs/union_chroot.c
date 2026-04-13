/*
 * Copyright (c) 2025 Apple Computer, Inc. All rights reserved.
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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o union_chroot union_chroot.c */

#include <darwintest.h>
#include <darwintest/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <TargetConditionals.h>

static char template[MAXPATHLEN];
static char *testdir = NULL;

struct tmpfs_mount_args {
	uint64_t max_pages;
	ino64_t max_nodes;
	uint64_t options;
};

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ENABLED(TARGET_OS_OSX),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (testdir) {
		char cleanup_cmd[MAXPATHLEN + 20];
		snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -rf %s", testdir);
		system(cleanup_cmd);
		testdir = NULL;
	}
}

T_DECL(union_chroot,
    "Check that MNT_UNION cannot be set on chroot mount point")
{
#if (!TARGET_OS_OSX)
	T_SKIP("Not macOS");
#endif

	char mount_path[MAXPATHLEN];
	char secret_file[MAXPATHLEN];
	char mounted_file[MAXPATHLEN];
	int fd;
	struct tmpfs_mount_args args = {
		.max_pages = 100,
		.max_nodes = 100,
		.options = 0,
	};

	T_ATEND(cleanup);
	T_SETUPBEGIN;

	/* Create test root dir */
	snprintf(template, sizeof(template), "%s/union_chroot-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");

	/* Setup paths */
	snprintf(mount_path, sizeof(mount_path), "%s/mount", testdir);
	snprintf(secret_file, sizeof(secret_file), "%s/secret", mount_path);
	snprintf(mounted_file, sizeof(mounted_file), "%s/visible", mount_path);

	/* Create the mount point directory */
	T_ASSERT_POSIX_SUCCESS(mkdir(mount_path, 0755),
	    "Setup: Creating mount directory %s", mount_path);

	/* Create a secret file that should not be accessible after chroot */
	T_ASSERT_POSIX_SUCCESS((fd = open(secret_file, O_CREAT | O_WRONLY, 0644)),
	    "Setup: Creating secret file %s", secret_file);

	T_ASSERT_POSIX_SUCCESS(write(fd, "1", 1),
	    "Setup: Writing to secret file");

	T_ASSERT_POSIX_SUCCESS(close(fd),
	    "Setup: Closing secret file");

	/* Mount tmpfs on the mount point */
	T_ASSERT_POSIX_SUCCESS(mount("tmpfs", mount_path, 0, &args),
	    "Setup: Initial tmpfs mount on %s", mount_path);

	/* Create a file in the mounted filesystem */
	T_ASSERT_POSIX_SUCCESS((fd = open(mounted_file, O_CREAT | O_WRONLY, 0644)),
	    "Setup: Creating visible file %s", mounted_file);

	T_ASSERT_POSIX_SUCCESS(write(fd, "3", 1),
	    "Setup: Writing to visible file");

	T_ASSERT_POSIX_SUCCESS(close(fd),
	    "Setup: Closing visible file");

	T_SETUPEND;

	/* Fork a child process to perform the chroot operations */
	pid_t child_pid = fork();
	T_ASSERT_POSIX_SUCCESS(child_pid, "Forking child process");

	if (child_pid == 0) {
		/* Child process: perform chroot and test the attack */

		/* Chroot into the mount point */
		if (chroot(mount_path) != 0) {
			T_LOG("Child: chroot failed: %s", strerror(errno));
			exit(2);  /* Exit code 2: chroot failed */
		}

		if (chdir("/") != 0) {
			T_LOG("Child: chdir failed: %s", strerror(errno));
			exit(3);  /* Exit code 3: chdir failed */
		}

		/* Verify we can see the visible file but not the secret file */
		if (access("visible", F_OK) != 0) {
			T_LOG("Child: visible file not accessible: %s", strerror(errno));
			exit(4);  /* Exit code 4: visible file access failed */
		}

		if (access("secret", F_OK) == 0) {
			T_LOG("Child: secret file should not be accessible");
			exit(5);  /* Exit code 5: secret file unexpectedly accessible */
		}

		/*
		 * Now attempt the attack: try to mount with MNT_UPDATE | MNT_UNION
		 * This should fail with EPERM due to our security fix
		 */
		if (mount("tmpfs", "/", MNT_UPDATE | MNT_UNION, &args) == 0) {
			T_LOG("Child: mount with MNT_UPDATE | MNT_UNION should have failed");
			exit(6);  /* Exit code 6: mount unexpectedly succeeded */
		}

		if (errno != EPERM) {
			T_LOG("Child: mount failed with wrong errno: %s (expected EPERM)", strerror(errno));
			exit(7);  /* Exit code 7: mount failed with wrong errno */
		}

		/* Verify the secret file is still not accessible */
		if (access("secret", F_OK) == 0) {
			T_LOG("Child: secret file should still not be accessible after failed attack");
			exit(8);  /* Exit code 8: secret file accessible after attack */
		}

		T_LOG("Child: All tests passed");
		exit(0);  /* Exit code 0: success */
	} else {
		/* Parent process: wait for child and check result */
		int status;
		T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "Waiting for child process");

		T_ASSERT_TRUE(WIFEXITED(status), "Child process should exit normally");

		int exit_code = WEXITSTATUS(status);
		switch (exit_code) {
		case 0:
			T_LOG("Child process completed successfully - all security tests passed");
			break;
		case 2:
			T_FAIL("Child process failed: chroot operation failed");
			break;
		case 3:
			T_FAIL("Child process failed: chdir operation failed");
			break;
		case 4:
			T_FAIL("Child process failed: visible file not accessible in chroot");
			break;
		case 5:
			T_FAIL("Child process failed: secret file unexpectedly accessible in chroot");
			break;
		case 6:
			T_FAIL("Child process failed: MNT_UNION attack unexpectedly succeeded");
			break;
		case 7:
			T_FAIL("Child process failed: mount failed with wrong errno (expected EPERM)");
			break;
		case 8:
			T_FAIL("Child process failed: secret file accessible after failed attack");
			break;
		default:
			T_FAIL("Child process failed with unexpected exit code: %d", exit_code);
			break;
		}

		T_ASSERT_EQ(exit_code, 0, "Child process should exit with status 0 (success)");

		/* Parent can now safely clean up */
		T_ASSERT_POSIX_SUCCESS(unmount(mount_path, 0),
		    "Cleanup: Unmounting tmpfs from parent process");
	}
}
