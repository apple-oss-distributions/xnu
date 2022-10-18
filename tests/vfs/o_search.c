/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o o_search o_search.c -g -Weverything */

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/attr.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <dirent.h>

#ifndef O_EXEC
#define O_EXEC 0x40000000
#define O_SEARCH (O_EXEC | O_DIRECTORY)
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

#define TEST_FILE "testfile"
#define NUMDIRS 5

static char g_testfile[MAXPATHLEN];

extern ssize_t __getdirentries64(int, void *, size_t, off_t *);

static void
exit_cleanup(void)
{
	(void)unlink(g_testfile);
}

T_DECL(o_search,
    "test O_SEARCH for open",
    T_META_ASROOT(false))
{
	const char *tmpdir = dt_tmpdir();
	void *mapped = MAP_FAILED;
	off_t dirbyte = 0;
	int retval = 0;
	int fd = -1;
	int tmpdir_fd = -1;
	char namebuf[(sizeof(struct dirent) * (NUMDIRS + 2))];
	char attrbuf[256];

	T_SETUPBEGIN;

	atexit(exit_cleanup);

	T_ASSERT_POSIX_ZERO(chdir(tmpdir),
	    "Setup: changing to tmpdir: %s", tmpdir);

	snprintf(g_testfile, MAXPATHLEN, "%s/%s", tmpdir, TEST_FILE);

	T_ASSERT_POSIX_SUCCESS(fd = open(g_testfile, O_CREAT | O_RDWR, 0644), NULL);
	T_ASSERT_POSIX_SUCCESS(retval = (int)write(fd, g_testfile, sizeof(g_testfile)), "Write: %s", g_testfile);
	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);

	T_SETUPEND;

	T_WITH_ERRNO;
	tmpdir_fd = open(tmpdir, O_EXEC);
	T_ASSERT_TRUE((tmpdir_fd == -1) && (errno == EISDIR),
	    "Trying to open directory O_EXEC: %s, tmpdir_fd = %d, errno = %d", g_testfile, tmpdir_fd, errno);

	T_ASSERT_POSIX_SUCCESS(tmpdir_fd = open(tmpdir, O_RDONLY), NULL);
	T_ASSERT_POSIX_SUCCESS(retval = (int)__getdirentries64(tmpdir_fd, namebuf, sizeof(namebuf), &dirbyte), NULL);
	T_ASSERT_POSIX_SUCCESS(close(tmpdir_fd), NULL);

	T_ASSERT_POSIX_SUCCESS(tmpdir_fd = open(tmpdir, O_SEARCH), NULL);
	retval = (int)__getdirentries64(tmpdir_fd, namebuf, sizeof(namebuf), &dirbyte);
	T_ASSERT_TRUE((retval == -1) && (errno == EBADF),
	    "Trying to read directory opened with O_SEARCH: %s, retval = %d, errno = %d",
	    tmpdir, retval, errno);

	fd = openat(tmpdir_fd, TEST_FILE, O_EXEC);
	T_ASSERT_TRUE((fd == -1) && (errno == EACCES),
	    "Trying to open file for execute with perms 644: %s, retval = %d, errno = %d",
	    tmpdir, retval, errno);

	T_ASSERT_POSIX_SUCCESS(retval = fchmodat(tmpdir_fd, TEST_FILE, 0744, 0), NULL);

	fd = openat(tmpdir_fd, TEST_FILE, O_SEARCH);
	T_ASSERT_TRUE((fd == -1) && (errno == ENOTDIR),
	    "Trying to open file for execute with perms 644: %s, retval = %d, errno = %d",
	    tmpdir, retval, errno);

	T_ASSERT_POSIX_SUCCESS(fd = openat(tmpdir_fd, TEST_FILE, O_EXEC), NULL);

	retval = (int)read(fd, &attrbuf, 2);
	T_ASSERT_TRUE((retval == -1) && (errno == EBADF),
	    "Trying to read file opened with O_EXEC: %s, retval = %d, errno = %d",
	    g_testfile, retval, errno);

	retval = (int)write(fd, &attrbuf, 2);
	T_ASSERT_TRUE((retval == -1) && (errno == EBADF),
	    "Trying to write file opened with O_EXEC: %s, retval = %d, errno = %d",
	    g_testfile, retval, errno);

	mapped = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED,
	    fd, 0);
	T_ASSERT_TRUE((mapped == MAP_FAILED) && (errno == EACCES),
	    "Trying to mmap file for read opened with O_EXEC: %s, mapped = %ld, errno = %d",
	    g_testfile, (long)mapped, errno);

	mapped = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_SHARED,
	    fd, 0);
	T_ASSERT_TRUE((mapped == MAP_FAILED) && (errno == EACCES),
	    "Trying to mmap file for write opened with O_EXEC: %s, mapped = %ld, errno = %d",
	    g_testfile, (long)mapped, errno);

	T_ASSERT_POSIX_SUCCESS(close(fd), NULL);
	T_ASSERT_POSIX_SUCCESS(close(tmpdir_fd), NULL);
}
