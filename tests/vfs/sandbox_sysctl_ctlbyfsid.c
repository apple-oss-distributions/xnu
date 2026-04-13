/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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

/* compile: xcrun -sdk macosx.internal clang -ldarwintest -lsandbox -o sandbox_sysctl_ctlbyfsid sandbox_sysctl_ctlbyfsid.c -g -Weverything */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sandbox/libsandbox.h>

#include <darwintest.h>
#include <darwintest/utils.h>

#define FSTYPE_DEVFS "devfs"
#define RUN_TEST     TARGET_OS_OSX

static char template[MAXPATHLEN];
static char *testdir = NULL;
static sandbox_params_t params = NULL;
static sandbox_profile_t profile = NULL;

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(true),
	T_META_ENABLED(RUN_TEST),
	T_META_CHECK_LEAKS(false));

static void
cleanup(void)
{
	if (profile) {
		sandbox_free_profile(profile);
	}
	if (params) {
		sandbox_free_params(params);
	}
	if (testdir) {
		rmdir(testdir);
	}
}

static void
create_profile_string(char *buff, size_t size, char *path)
{
	snprintf(buff, size, "(version 1) \n\
                          (allow default) \n\
                          (import \"system.sb\") \n\
                          (deny file-test-existence (path \"%s\")) \n",
	    path);
}

static int
getmntfsid(const char *name, fsid_t *fsid)
{
	int i;
	struct statfs *mntbuf = NULL;
	int mntsize = 0;

	if (mntbuf == NULL &&
	    (mntsize = getmntinfo(&mntbuf, MNT_NOWAIT)) == 0) {
		return -1;
	}

	for (i = mntsize - 1; i >= 0; i--) {
		if (!strcmp(mntbuf[i].f_mntonname, name)) {
			*fsid = mntbuf[i].f_fsid;
			return 0;
		}
	}
	return -1;
}

static int
sysctl_fsid(
	int op,
	fsid_t *fsid,
	void *oldp,
	size_t *oldlenp,
	void *newp,
	size_t newlen)
{
	int ctlname[CTL_MAXNAME + 2];
	size_t ctllen;
	const char *sysstr = "vfs.generic.ctlbyfsid";
	struct vfsidctl vc;

	ctllen = CTL_MAXNAME + 2;
	if (sysctlnametomib(sysstr, ctlname, &ctllen) == -1) {
		return -1;
	}
	;
	ctlname[ctllen] = op;

	bzero(&vc, sizeof(vc));
	vc.vc_vers = VFS_CTL_VERS1;
	vc.vc_fsid = *fsid;
	vc.vc_ptr = newp;
	vc.vc_len = newlen;
	return sysctl(ctlname, (u_int)(ctllen + 1), oldp, oldlenp, &vc, sizeof(vc));
}

static int
unmount_by_sysctl(char *path)
{
	int flag = 0;
	fsid_t fsid;

	if (getmntfsid(path, &fsid) < 0) {
		return -1;
	}

	if (sysctl_fsid(VFS_CTL_UMOUNT, &fsid, NULL, 0, &flag, sizeof(flag)) < 0) {
		return -1;
	}

	return 0;
}

T_DECL(sandbox_sysctl_ctlbyfsid,
    "Validate sysctl_vfs_ctlbyfsid respects `file-test-existence`")
{
#if (!RUN_TEST)
	T_SKIP("Not macOS");
#endif

	pid_t pid, res;
	int status, error;
	char *sberror = NULL;
	char profile_string[1000];
	char resolved_path[PATH_MAX];

	T_ATEND(cleanup);

	T_SETUPBEGIN;

	snprintf(template, sizeof(template), "%s/sandbox_sysctl_ctlbyfsid-XXXXXX", dt_tmpdir());
	T_ASSERT_POSIX_NOTNULL((testdir = mkdtemp(template)), "Creating test root dir");
	T_ASSERT_POSIX_NOTNULL(realpath(testdir, resolved_path), "Getting realpath of %s", testdir);

	/* Create sandbox variables */
	T_ASSERT_POSIX_NOTNULL(params = sandbox_create_params(), "Creating Sandbox params object");
	create_profile_string(profile_string, sizeof(profile_string), resolved_path);
	T_ASSERT_POSIX_NOTNULL(profile = sandbox_compile_string(profile_string, params, &sberror), "Creating Sandbox profile object");

	T_SETUPEND;

	/* Mount/Unmount validation */
	T_EXPECT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, resolved_path, MNT_RDONLY, NULL), "Mounting devfs mount -> Should PASS");
	T_EXPECT_POSIX_SUCCESS(unmount(resolved_path, MNT_FORCE), "Verify unmount() -> Should PASS");

	/* Mount/Unmount-by-sysctl validation */
	T_EXPECT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, resolved_path, MNT_RDONLY, NULL), "Mounting devfs mount -> Should PASS");
	T_EXPECT_POSIX_SUCCESS(unmount_by_sysctl(resolved_path), "Unmounting by sysctl -> Should PASS");

	/* Mount/Unmount with sandbox profile applied */
	T_EXPECT_POSIX_SUCCESS(mount(FSTYPE_DEVFS, resolved_path, MNT_RDONLY, NULL), "Mounting devfs mount -> Should PASS");

	/* Fork to apply profile to the child process */
	pid = fork();
	if (pid < -1) {
		T_FAIL("Failed to fork");
		return;
	}

	switch (pid) {
	case 0:

		/* Apply sandbox profile */
		error = sandbox_apply(profile);
		if (error) {
			exit(1);
		}

		/* Verify unmount() -> Should FAIL with EPERM */
		if (unmount(resolved_path, MNT_FORCE) != -1 || errno != EPERM) {
			exit(2);
		}

		/* Unmounting by sysctl -> Should FAIL with EPERM */
		if (unmount_by_sysctl(resolved_path) != -1 || errno != EPERM) {
			exit(3);
		}

		exit(0);
	default:
		do {
			res = waitpid(pid, &status, WUNTRACED);
		} while (res == -1 && errno == EINTR);

		if (res != pid) {
			T_FAIL("(res != pid");
			break;
		}

		if (!WIFEXITED(status)) {
			T_FAIL("Child process failed to unmount with exit code of %d", WIFEXITED(status));
			break;
		}

		if (WEXITSTATUS(status)) {
			T_FAIL("Child process failed to unmount with exit code of %d", WEXITSTATUS(status));
			break;
		}

		T_LOG("Verify unmount() -> Should FAIL with EPERM");
		T_LOG("Unmounting by sysctl -> Should FAIL with EPERM ");
		T_EXPECT_POSIX_SUCCESS(unmount(resolved_path, MNT_FORCE), "Verify unmount() -> Should PASS");
	}
}
