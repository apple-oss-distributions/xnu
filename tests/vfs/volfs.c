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

/* compile: xcrun -sdk macosx.internal clang -arch arm64e -arch x86_64 -ldarwintest -o volfs volfs.c */

#include <darwintest.h>
#include <darwintest/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ENABLED(TARGET_OS_OSX),
	T_META_CHECK_LEAKS(false));

T_DECL(volfs_at_shortcut,
    "Test the @ shortcut for device root directory with relative paths",
    T_META_ASROOT(false))
{
#if TARGET_OS_OSX
	int fd1, fd2;
	char root_volfs_numeric[MAXPATHLEN];
	char root_volfs_at[MAXPATHLEN];
	char relative_path_numeric[MAXPATHLEN];
	char relative_path_at[MAXPATHLEN];
	const char *root_path = "/";
	const char *test_file = "etc/hosts";  // A file that should exist on most systems
	struct stat root_stat, stat1, stat2;

	T_SETUPBEGIN;

	T_ASSERT_POSIX_SUCCESS(stat(root_path, &root_stat),
	    "Setup: Calling stat() on %s", root_path);

	// Create volfs paths using numeric and @ shortcuts
	T_ASSERT_POSIX_SUCCESS(snprintf(root_volfs_numeric, sizeof(root_volfs_numeric),
	    "/.vol/%d/2", root_stat.st_dev),
	    "Setup: Creating numeric root volfs path");

	T_ASSERT_POSIX_SUCCESS(snprintf(root_volfs_at, sizeof(root_volfs_at),
	    "/.vol/%d/@", root_stat.st_dev),
	    "Setup: Creating @ root volfs path");

	// Create relative paths using both methods
	T_ASSERT_POSIX_SUCCESS(snprintf(relative_path_numeric, sizeof(relative_path_numeric),
	    "/.vol/%d/2/%s", root_stat.st_dev, test_file),
	    "Setup: Creating numeric relative path");

	T_ASSERT_POSIX_SUCCESS(snprintf(relative_path_at, sizeof(relative_path_at),
	    "/.vol/%d/@/%s", root_stat.st_dev, test_file),
	    "Setup: Creating @ relative path");

	T_SETUPEND;

	// Test 1: Verify both @ and numeric shortcuts point to the same root
	T_ASSERT_POSIX_SUCCESS(stat(root_volfs_numeric, &stat1),
	    "Calling stat() on numeric root path %s", root_volfs_numeric);

	T_ASSERT_POSIX_SUCCESS(stat(root_volfs_at, &stat2),
	    "Calling stat() on @ root path %s", root_volfs_at);

	T_ASSERT_EQ(stat1.st_ino, stat2.st_ino,
	    "Verifying %s and %s point to the same inode",
	    root_volfs_numeric, root_volfs_at);

	T_ASSERT_EQ(stat1.st_dev, stat2.st_dev,
	    "Verifying %s and %s are on the same device",
	    root_volfs_numeric, root_volfs_at);

	// Test 2: Verify relative paths work with @ shortcut
	T_ASSERT_POSIX_SUCCESS(stat(relative_path_numeric, &stat1),
	    "Calling stat() on numeric relative path %s", relative_path_numeric);

	T_ASSERT_POSIX_SUCCESS(stat(relative_path_at, &stat2),
	    "Calling stat() on @ relative path %s", relative_path_at);

	T_ASSERT_EQ(stat1.st_ino, stat2.st_ino,
	    "Verifying %s and %s point to the same file",
	    relative_path_numeric, relative_path_at);

	// Test 3: Verify file access works with @ shortcut
	T_ASSERT_POSIX_SUCCESS((fd1 = open(relative_path_numeric, O_RDONLY)),
	    "Opening file via numeric path %s", relative_path_numeric);

	T_ASSERT_POSIX_SUCCESS((fd2 = open(relative_path_at, O_RDONLY)),
	    "Opening file via @ path %s", relative_path_at);

	T_ASSERT_POSIX_SUCCESS(fstat(fd1, &stat1), "fstat on numeric path fd");
	T_ASSERT_POSIX_SUCCESS(fstat(fd2, &stat2), "fstat on @ path fd");

	T_ASSERT_EQ(stat1.st_ino, stat2.st_ino,
	    "Verifying both file descriptors point to the same file");

	close(fd1);
	close(fd2);

	T_LOG("@ shortcut test completed successfully");
	T_LOG("Both /.vol/%d/2/%s and /.vol/%d/@/%s work correctly",
	    root_stat.st_dev, test_file, root_stat.st_dev, test_file);

#else
	T_SKIP("Not macOS");
#endif
}

#if TARGET_OS_OSX

/*
 * Test fixture for volfs symlink tests.
 *
 *   tmpdir/
 *     target/           <- directory
 *       file.txt        <- regular file
 *     symlink -> target <- symlink to the directory
 */

static char volfs_symlink_testdir[MAXPATHLEN];

static void
cleanup_volfs_symlink_fixture(void)
{
	char path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/target/file.txt", volfs_symlink_testdir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/target", volfs_symlink_testdir);
	rmdir(path);
	snprintf(path, sizeof(path), "%s/symlink", volfs_symlink_testdir);
	unlink(path);
	rmdir(volfs_symlink_testdir);
}

/*
 * Create the fixture and populate:
 *   volfs_symlink  - "/.vol/<dev>/<symlink_ino>"  (no trailing slash)
 *   symlink_inop   - inode of the symlink itself
 *   target_inop    - inode of the target directory
 *   file_inop      - inode of target/file.txt
 */
static void
setup_volfs_symlink_fixture(char volfs_symlink[MAXPATHLEN],
    ino_t *symlink_inop, ino_t *target_inop, ino_t *file_inop)
{
	char target_dir[MAXPATHLEN];
	char file_path[MAXPATHLEN];
	char symlink_path[MAXPATHLEN];
	struct stat sb;
	int fd;

	snprintf(volfs_symlink_testdir, sizeof(volfs_symlink_testdir),
	    "%s/volfs_symlink-XXXXXX", dt_tmpdir());
	T_QUIET; T_ASSERT_POSIX_NOTNULL(mkdtemp(volfs_symlink_testdir),
	    "create temp directory");

	snprintf(target_dir, sizeof(target_dir), "%s/target",
	    volfs_symlink_testdir);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdir(target_dir, 0755),
	    "create target directory");

	snprintf(file_path, sizeof(file_path), "%s/target/file.txt",
	    volfs_symlink_testdir);
	fd = open(file_path, O_CREAT | O_WRONLY, 0644);
	T_QUIET; T_ASSERT_GE(fd, 0, "create target/file.txt");
	close(fd);

	snprintf(symlink_path, sizeof(symlink_path), "%s/symlink",
	    volfs_symlink_testdir);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(symlink("target", symlink_path),
	    "create symlink -> target");

	/* Collect inode/dev from the symlink without following it. */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(lstat(symlink_path, &sb),
	    "lstat symlink");
	*symlink_inop = sb.st_ino;
	snprintf(volfs_symlink, MAXPATHLEN, "/.vol/%d/%llu",
	    (int)sb.st_dev, (unsigned long long)sb.st_ino);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(target_dir, &sb), "stat target/");
	*target_inop = sb.st_ino;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(file_path, &sb),
	    "stat target/file.txt");
	*file_inop = sb.st_ino;
}

/*
 * Test 1: stat() on /.vol/<dev>/<symlink_ino> follows the symlink and
 * returns the target directory's attributes.
 */
T_DECL(volfs_symlink_stat_follows,
    "stat() on a volfs path whose inode is a symlink follows the symlink",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	ino_t symlink_ino, target_ino, file_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_symlink_fixture);
	setup_volfs_symlink_fixture(volfs_symlink, &symlink_ino, &target_ino,
	    &file_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_symlink, &sb),
	    "stat %s", volfs_symlink);
	T_ASSERT_TRUE(S_ISDIR(sb.st_mode),
	    "stat on volfs symlink path returns directory type");
	T_ASSERT_EQ(sb.st_ino, target_ino,
	    "stat on volfs symlink path returns target directory inode");
}

/*
 * Test 2: lstat() on /.vol/<dev>/<symlink_ino> does not follow the symlink
 * and returns the symlink's own attributes.
 */
T_DECL(volfs_symlink_lstat_no_follow,
    "lstat() on a volfs path whose inode is a symlink returns the symlink itself",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	ino_t symlink_ino, target_ino, file_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_symlink_fixture);
	setup_volfs_symlink_fixture(volfs_symlink, &symlink_ino, &target_ino,
	    &file_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(lstat(volfs_symlink, &sb),
	    "lstat %s", volfs_symlink);
	T_ASSERT_TRUE(S_ISLNK(sb.st_mode),
	    "lstat on volfs symlink path returns symlink type");
	T_ASSERT_EQ(sb.st_ino, symlink_ino,
	    "lstat on volfs symlink path returns symlink inode");
}

/*
 * Test 3: lstat() on /.vol/<dev>/<symlink_ino>/ (trailing slash) follows
 * the symlink and returns the target directory's attributes — identical
 * to the stat() result.
 */
T_DECL(volfs_symlink_lstat_trailing_slash_follows,
    "lstat() on a volfs symlink path with a trailing slash follows the symlink",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	char volfs_symlink_trailing[MAXPATHLEN];
	ino_t symlink_ino, target_ino, file_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_symlink_fixture);
	setup_volfs_symlink_fixture(volfs_symlink, &symlink_ino, &target_ino,
	    &file_ino);
	snprintf(volfs_symlink_trailing, sizeof(volfs_symlink_trailing),
	    "%s/", volfs_symlink);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(lstat(volfs_symlink_trailing, &sb),
	    "lstat %s", volfs_symlink_trailing);
	T_ASSERT_TRUE(S_ISDIR(sb.st_mode),
	    "lstat on volfs symlink path with trailing slash returns directory type");
	T_ASSERT_EQ(sb.st_ino, target_ino,
	    "lstat on volfs symlink path with trailing slash returns target directory inode");
}

/*
 * Test 4: stat() on /.vol/<dev>/<symlink_ino>/file.txt resolves through
 * the symlink into the target directory and reaches the file inside it.
 */
T_DECL(volfs_symlink_relative_path,
    "A relative path appended to a volfs symlink inode resolves through the symlink",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	char volfs_symlink_file[MAXPATHLEN];
	ino_t symlink_ino, target_ino, file_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_symlink_fixture);
	setup_volfs_symlink_fixture(volfs_symlink, &symlink_ino, &target_ino,
	    &file_ino);
	snprintf(volfs_symlink_file, sizeof(volfs_symlink_file),
	    "%s/file.txt", volfs_symlink);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_symlink_file, &sb),
	    "stat %s", volfs_symlink_file);
	T_ASSERT_EQ(sb.st_ino, file_ino,
	    "stat on volfs symlink path with relative component returns correct file inode");
}

/*
 * Test fixture for volfs absolute-symlink tests.
 *
 *   tmpdir/
 *     symlink -> /tmp   <- absolute symlink pointing to /tmp
 *
 * A scratch subdirectory is also created inside /tmp so that a known name
 * can be resolved through the symlink in the relative-path test.
 */

static char volfs_abs_symlink_testdir[MAXPATHLEN];
static char volfs_abs_symlink_subdir[MAXPATHLEN];

static void
cleanup_volfs_abs_symlink_fixture(void)
{
	char path[MAXPATHLEN];

	if (volfs_abs_symlink_subdir[0] != '\0') {
		rmdir(volfs_abs_symlink_subdir);
	}
	snprintf(path, sizeof(path), "%s/symlink", volfs_abs_symlink_testdir);
	unlink(path);
	rmdir(volfs_abs_symlink_testdir);
}

/*
 * Create the fixture and populate:
 *   volfs_symlink  - "/.vol/<dev>/<symlink_ino>"  (no trailing slash)
 *   symlink_inop   - inode of the symlink itself
 *   tmp_inop       - inode of /tmp (the absolute target)
 *   volfs_subdir   - "/.vol/<dev>/<symlink_ino>/<subdir_name>"
 *   subdir_inop    - inode of the scratch subdir created inside /tmp
 */
static void
setup_volfs_abs_symlink_fixture(char volfs_symlink[MAXPATHLEN],
    ino_t *symlink_inop, ino_t *tmp_inop,
    char volfs_subdir[MAXPATHLEN], ino_t *subdir_inop)
{
	char symlink_path[MAXPATHLEN];
	const char *subdir_name;
	struct stat sb;

	snprintf(volfs_abs_symlink_testdir, sizeof(volfs_abs_symlink_testdir),
	    "%s/volfs_abs_symlink-XXXXXX", dt_tmpdir());
	T_QUIET; T_ASSERT_POSIX_NOTNULL(mkdtemp(volfs_abs_symlink_testdir),
	    "create temp directory");

	snprintf(symlink_path, sizeof(symlink_path), "%s/symlink",
	    volfs_abs_symlink_testdir);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(symlink("/tmp", symlink_path),
	    "create symlink -> /tmp");

	/* Collect inode/dev from the symlink without following it. */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(lstat(symlink_path, &sb),
	    "lstat symlink");
	*symlink_inop = sb.st_ino;
	snprintf(volfs_symlink, MAXPATHLEN, "/.vol/%d/%llu",
	    (int)sb.st_dev, (unsigned long long)sb.st_ino);

	/* /tmp is the absolute follow target. */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat("/tmp", &sb), "stat /tmp");
	*tmp_inop = sb.st_ino;

	/* Create a scratch subdirectory inside /tmp for the relative-path test. */
	snprintf(volfs_abs_symlink_subdir, sizeof(volfs_abs_symlink_subdir),
	    "/tmp/volfs_abs_subdir-XXXXXX");
	T_QUIET; T_ASSERT_POSIX_NOTNULL(mkdtemp(volfs_abs_symlink_subdir),
	    "create scratch subdir in /tmp");

	subdir_name = strrchr(volfs_abs_symlink_subdir, '/') + 1;
	snprintf(volfs_subdir, MAXPATHLEN, "%s/%s", volfs_symlink, subdir_name);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(volfs_abs_symlink_subdir, &sb),
	    "stat scratch subdir in /tmp");
	*subdir_inop = sb.st_ino;
}

/*
 * Test 5: stat() on /.vol/<dev>/<symlink_ino> where the symlink is an
 * absolute link to /tmp follows the symlink and returns /tmp's attributes.
 */
T_DECL(volfs_symlink_abs_stat_follows,
    "stat() on a volfs path whose inode is an absolute symlink to /tmp follows the symlink",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	char volfs_subdir[MAXPATHLEN];
	ino_t symlink_ino, tmp_ino, subdir_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_abs_symlink_fixture);
	setup_volfs_abs_symlink_fixture(volfs_symlink, &symlink_ino, &tmp_ino,
	    volfs_subdir, &subdir_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_symlink, &sb),
	    "stat %s", volfs_symlink);
	T_ASSERT_TRUE(S_ISDIR(sb.st_mode),
	    "stat on volfs absolute symlink path returns directory type");
	T_ASSERT_EQ(sb.st_ino, tmp_ino,
	    "stat on volfs absolute symlink path returns /tmp inode");
}

/*
 * Test 6: lstat() on /.vol/<dev>/<symlink_ino> does not follow the absolute
 * symlink and returns the symlink's own attributes.
 */
T_DECL(volfs_symlink_abs_lstat_no_follow,
    "lstat() on a volfs path whose inode is an absolute symlink returns the symlink itself",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	char volfs_subdir[MAXPATHLEN];
	ino_t symlink_ino, tmp_ino, subdir_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_abs_symlink_fixture);
	setup_volfs_abs_symlink_fixture(volfs_symlink, &symlink_ino, &tmp_ino,
	    volfs_subdir, &subdir_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(lstat(volfs_symlink, &sb),
	    "lstat %s", volfs_symlink);
	T_ASSERT_TRUE(S_ISLNK(sb.st_mode),
	    "lstat on volfs absolute symlink path returns symlink type");
	T_ASSERT_EQ(sb.st_ino, symlink_ino,
	    "lstat on volfs absolute symlink path returns symlink inode");
}

/*
 * Test 7: lstat() on /.vol/<dev>/<symlink_ino>/ (trailing slash) follows
 * the absolute symlink and returns /tmp's attributes.
 */
T_DECL(volfs_symlink_abs_lstat_trailing_slash_follows,
    "lstat() on a volfs absolute symlink path with a trailing slash follows the symlink",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	char volfs_symlink_trailing[MAXPATHLEN];
	char volfs_subdir[MAXPATHLEN];
	ino_t symlink_ino, tmp_ino, subdir_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_abs_symlink_fixture);
	setup_volfs_abs_symlink_fixture(volfs_symlink, &symlink_ino, &tmp_ino,
	    volfs_subdir, &subdir_ino);
	snprintf(volfs_symlink_trailing, sizeof(volfs_symlink_trailing),
	    "%s/", volfs_symlink);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(lstat(volfs_symlink_trailing, &sb),
	    "lstat %s", volfs_symlink_trailing);
	T_ASSERT_TRUE(S_ISDIR(sb.st_mode),
	    "lstat on volfs absolute symlink path with trailing slash returns directory type");
	T_ASSERT_EQ(sb.st_ino, tmp_ino,
	    "lstat on volfs absolute symlink path with trailing slash returns /tmp inode");
}

/*
 * Test 8: stat() on /.vol/<dev>/<symlink_ino>/<subdir> resolves through the
 * absolute symlink into /tmp and reaches the subdirectory created there.
 */
T_DECL(volfs_symlink_abs_relative_path,
    "A relative path appended to a volfs absolute symlink inode resolves through the symlink",
    T_META_ASROOT(false))
{
	char volfs_symlink[MAXPATHLEN];
	char volfs_subdir[MAXPATHLEN];
	ino_t symlink_ino, tmp_ino, subdir_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_abs_symlink_fixture);
	setup_volfs_abs_symlink_fixture(volfs_symlink, &symlink_ino, &tmp_ino,
	    volfs_subdir, &subdir_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_subdir, &sb),
	    "stat %s", volfs_subdir);
	T_ASSERT_EQ(sb.st_ino, subdir_ino,
	    "stat on volfs absolute symlink path with relative component returns correct subdir inode");
}

/*
 * Test fixture for volfs resource fork tests.
 *
 *   tmpdir/
 *     testfile   <- regular file (resource fork optionally created per test)
 */

static char volfs_rsrc_testdir[MAXPATHLEN];

static void
cleanup_volfs_rsrc_fixture(void)
{
	char path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/testfile", volfs_rsrc_testdir);
	unlink(path);
	rmdir(volfs_rsrc_testdir);
}

/*
 * Create the fixture and populate:
 *   volfs_rsrc_path - "/.vol/<dev>/<ino>/..namedfork/rsrc"
 *   file_path_out   - real filesystem path to testfile (for fork creation)
 */
static void
setup_volfs_rsrc_fixture(char volfs_rsrc_path[MAXPATHLEN],
    char file_path_out[MAXPATHLEN])
{
	struct stat sb;
	int fd;

	snprintf(volfs_rsrc_testdir, sizeof(volfs_rsrc_testdir),
	    "%s/volfs_rsrc-XXXXXX", dt_tmpdir());
	T_QUIET; T_ASSERT_POSIX_NOTNULL(mkdtemp(volfs_rsrc_testdir),
	    "create temp directory");

	snprintf(file_path_out, MAXPATHLEN, "%s/testfile",
	    volfs_rsrc_testdir);
	fd = open(file_path_out, O_CREAT | O_WRONLY, 0644);
	T_QUIET; T_ASSERT_GE(fd, 0, "create testfile");
	close(fd);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(file_path_out, &sb),
	    "stat testfile");
	snprintf(volfs_rsrc_path, MAXPATHLEN, "/.vol/%d/%llu/..namedfork/rsrc",
	    (int)sb.st_dev, (unsigned long long)sb.st_ino);
}

/*
 * Test 9: stat() on /.vol/<dev>/<ino>/..namedfork/rsrc succeeds when the
 * resource fork has been created.
 */
T_DECL(volfs_rsrc_fork_stat_exists,
    "stat() on a volfs resource fork path succeeds when the fork exists",
    T_META_ASROOT(false))
{
	char volfs_rsrc_path[MAXPATHLEN];
	char file_path[MAXPATHLEN];
	const char rsrc_data[] = "test resource fork data";
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_rsrc_fixture);
	setup_volfs_rsrc_fixture(volfs_rsrc_path, file_path);

	/* Write resource fork data so the fork exists. */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		setxattr(file_path, XATTR_RESOURCEFORK_NAME,
		rsrc_data, sizeof(rsrc_data), 0, 0),
		"create resource fork on %s", file_path);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_rsrc_path, &sb),
	    "stat resource fork via volfs path %s", volfs_rsrc_path);
	T_ASSERT_GE(sb.st_size, (off_t)sizeof(rsrc_data),
	    "resource fork size reflects written data");
}

/*
 * Test 10: stat() on /.vol/<dev>/<ino>/..namedfork/rsrc fails with ENOENT
 * or ENOATTR when the file has no resource fork.
 */
T_DECL(volfs_rsrc_fork_stat_missing,
    "stat() on a volfs resource fork path fails when the fork does not exist",
    T_META_ASROOT(false))
{
	char volfs_rsrc_path[MAXPATHLEN];
	char file_path[MAXPATHLEN];
	struct stat sb;
	int ret;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_rsrc_fixture);
	/* File is created with no resource fork. */
	setup_volfs_rsrc_fixture(volfs_rsrc_path, file_path);
	T_SETUPEND;

	ret = stat(volfs_rsrc_path, &sb);
	int l_errno = errno;
	T_ASSERT_EQ(ret, -1,
	    "stat on missing resource fork via volfs path %s should fail",
	    volfs_rsrc_path);
	T_ASSERT_TRUE(l_errno == ENOENT || l_errno == ENOATTR,
	    "errno is ENOENT or ENOATTR for missing resource fork, got %d (%s)",
	    l_errno, strerror(l_errno));
}

/*
 * Test fixture for volfs basic inode-access tests.
 *
 *   tmpdir/
 *     file.txt        <- regular file
 *     subdir/         <- directory
 *       nested.txt    <- regular file
 */

static char volfs_basic_testdir[MAXPATHLEN];

static void
cleanup_volfs_basic_fixture(void)
{
	char path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/subdir/nested.txt", volfs_basic_testdir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/subdir", volfs_basic_testdir);
	rmdir(path);
	snprintf(path, sizeof(path), "%s/file.txt", volfs_basic_testdir);
	unlink(path);
	rmdir(volfs_basic_testdir);
}

/*
 * Create the fixture and populate:
 *   volfs_file           - "/.vol/<dev>/<file_ino>"
 *   file_inop            - inode of file.txt
 *   volfs_dir            - "/.vol/<dev>/<subdir_ino>"
 *   dir_inop             - inode of subdir/
 *   volfs_path_component - "/.vol/<dev>/<tmpdir_ino>/subdir/nested.txt"
 *   nested_inop          - inode of subdir/nested.txt
 */
static void
setup_volfs_basic_fixture(char volfs_file[MAXPATHLEN], ino_t *file_inop,
    char volfs_dir[MAXPATHLEN], ino_t *dir_inop,
    char volfs_path_component[MAXPATHLEN], ino_t *nested_inop)
{
	char file_path[MAXPATHLEN];
	char subdir_path[MAXPATHLEN];
	char nested_path[MAXPATHLEN];
	struct stat sb;
	int fd;

	snprintf(volfs_basic_testdir, sizeof(volfs_basic_testdir),
	    "%s/volfs_basic-XXXXXX", dt_tmpdir());
	T_QUIET; T_ASSERT_POSIX_NOTNULL(mkdtemp(volfs_basic_testdir),
	    "create temp directory");

	/* Create file.txt */
	snprintf(file_path, sizeof(file_path), "%s/file.txt", volfs_basic_testdir);
	fd = open(file_path, O_CREAT | O_WRONLY, 0644);
	T_QUIET; T_ASSERT_GE(fd, 0, "create file.txt");
	close(fd);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(file_path, &sb), "stat file.txt");
	*file_inop = sb.st_ino;
	snprintf(volfs_file, MAXPATHLEN, "/.vol/%d/%llu",
	    (int)sb.st_dev, (unsigned long long)sb.st_ino);

	/* Create subdir/ */
	snprintf(subdir_path, sizeof(subdir_path), "%s/subdir", volfs_basic_testdir);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdir(subdir_path, 0755), "create subdir");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(subdir_path, &sb), "stat subdir");
	*dir_inop = sb.st_ino;
	snprintf(volfs_dir, MAXPATHLEN, "/.vol/%d/%llu",
	    (int)sb.st_dev, (unsigned long long)sb.st_ino);

	/* Create subdir/nested.txt */
	snprintf(nested_path, sizeof(nested_path), "%s/subdir/nested.txt",
	    volfs_basic_testdir);
	fd = open(nested_path, O_CREAT | O_WRONLY, 0644);
	T_QUIET; T_ASSERT_GE(fd, 0, "create subdir/nested.txt");
	close(fd);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(nested_path, &sb),
	    "stat subdir/nested.txt");
	*nested_inop = sb.st_ino;

	/*
	 * Build the path-component volfs path rooted at tmpdir:
	 *   /.vol/<dev>/<tmpdir_ino>/subdir/nested.txt
	 */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(stat(volfs_basic_testdir, &sb),
	    "stat tmpdir");
	snprintf(volfs_path_component, MAXPATHLEN,
	    "/.vol/%d/%llu/subdir/nested.txt",
	    (int)sb.st_dev, (unsigned long long)sb.st_ino);
}

/*
 * Test 11: stat() on /.vol/<dev>/<file_ino> returns the same inode as the
 * regular file it was created from.
 */
T_DECL(volfs_basic_file,
    "stat() on a volfs path for a regular file returns the correct inode",
    T_META_ASROOT(false))
{
	char volfs_file[MAXPATHLEN];
	char volfs_dir[MAXPATHLEN];
	char volfs_path_component[MAXPATHLEN];
	ino_t file_ino, dir_ino, nested_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_basic_fixture);
	setup_volfs_basic_fixture(volfs_file, &file_ino, volfs_dir, &dir_ino,
	    volfs_path_component, &nested_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_file, &sb),
	    "stat regular file via volfs path %s", volfs_file);
	T_ASSERT_TRUE(S_ISREG(sb.st_mode),
	    "stat via volfs path returns regular file type");
	T_ASSERT_EQ(sb.st_ino, file_ino,
	    "stat via volfs path returns the same inode as the original file");
}

/*
 * Test 12: stat() on /.vol/<dev>/<file_ino>/ (trailing slash on a regular
 * file) must fail with ENOTDIR.
 */
T_DECL(volfs_basic_file_trailing_slash,
    "stat() on a volfs path for a regular file with a trailing slash fails with ENOTDIR",
    T_META_ASROOT(false))
{
	char volfs_file[MAXPATHLEN];
	char volfs_file_trailing[MAXPATHLEN];
	char volfs_dir[MAXPATHLEN];
	char volfs_path_component[MAXPATHLEN];
	ino_t file_ino, dir_ino, nested_ino;
	struct stat sb;
	int ret;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_basic_fixture);
	setup_volfs_basic_fixture(volfs_file, &file_ino, volfs_dir, &dir_ino,
	    volfs_path_component, &nested_ino);
	snprintf(volfs_file_trailing, sizeof(volfs_file_trailing),
	    "%s/", volfs_file);
	T_SETUPEND;

	ret = stat(volfs_file_trailing, &sb);
	T_ASSERT_EQ(ret, -1,
	    "stat on regular file volfs path with trailing slash %s should fail",
	    volfs_file_trailing);
	T_ASSERT_EQ(errno, ENOTDIR,
	    "errno is ENOTDIR when trailing slash is used on a regular file volfs path");
}

/*
 * Test 13: stat() on /.vol/<dev>/<dir_ino> returns the same inode as the
 * directory it was created from.
 */
T_DECL(volfs_basic_dir,
    "stat() on a volfs path for a directory returns the correct inode",
    T_META_ASROOT(false))
{
	char volfs_file[MAXPATHLEN];
	char volfs_dir[MAXPATHLEN];
	char volfs_path_component[MAXPATHLEN];
	ino_t file_ino, dir_ino, nested_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_basic_fixture);
	setup_volfs_basic_fixture(volfs_file, &file_ino, volfs_dir, &dir_ino,
	    volfs_path_component, &nested_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_dir, &sb),
	    "stat directory via volfs path %s", volfs_dir);
	T_ASSERT_TRUE(S_ISDIR(sb.st_mode),
	    "stat via volfs path returns directory type");
	T_ASSERT_EQ(sb.st_ino, dir_ino,
	    "stat via volfs path returns the same inode as the original directory");
}

/*
 * Test 14: stat() on /.vol/<dev>/<dir_ino>/ (trailing slash on a directory)
 * succeeds and returns the directory's attributes.
 */
T_DECL(volfs_basic_dir_trailing_slash,
    "stat() on a volfs path for a directory with a trailing slash returns the correct inode",
    T_META_ASROOT(false))
{
	char volfs_file[MAXPATHLEN];
	char volfs_dir[MAXPATHLEN];
	char volfs_dir_trailing[MAXPATHLEN];
	char volfs_path_component[MAXPATHLEN];
	ino_t file_ino, dir_ino, nested_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_basic_fixture);
	setup_volfs_basic_fixture(volfs_file, &file_ino, volfs_dir, &dir_ino,
	    volfs_path_component, &nested_ino);
	snprintf(volfs_dir_trailing, sizeof(volfs_dir_trailing),
	    "%s/", volfs_dir);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_dir_trailing, &sb),
	    "stat directory via volfs path with trailing slash %s",
	    volfs_dir_trailing);
	T_ASSERT_TRUE(S_ISDIR(sb.st_mode),
	    "stat via volfs path with trailing slash returns directory type");
	T_ASSERT_EQ(sb.st_ino, dir_ino,
	    "stat via volfs path with trailing slash returns the same inode as the original directory");
}

/*
 * Test 15: stat() on /.vol/<dev>/<dir_ino>/subdir/nested.txt resolves a
 * multi-component path rooted at a volfs inode and returns the correct inode
 * of the nested file.
 */
T_DECL(volfs_basic_path_component,
    "stat() on a volfs path with appended path components resolves to the correct inode",
    T_META_ASROOT(false))
{
	char volfs_file[MAXPATHLEN];
	char volfs_dir[MAXPATHLEN];
	char volfs_path_component[MAXPATHLEN];
	ino_t file_ino, dir_ino, nested_ino;
	struct stat sb;

	T_SETUPBEGIN;
	T_ATEND(cleanup_volfs_basic_fixture);
	setup_volfs_basic_fixture(volfs_file, &file_ino, volfs_dir, &dir_ino,
	    volfs_path_component, &nested_ino);
	T_SETUPEND;

	T_ASSERT_POSIX_SUCCESS(stat(volfs_path_component, &sb),
	    "stat nested file via volfs path %s", volfs_path_component);
	T_ASSERT_TRUE(S_ISREG(sb.st_mode),
	    "stat via volfs path with components returns regular file type");
	T_ASSERT_EQ(sb.st_ino, nested_ino,
	    "stat via volfs path with components returns the correct nested file inode");
}

#endif /* TARGET_OS_OSX */
