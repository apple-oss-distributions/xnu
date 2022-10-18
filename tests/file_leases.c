/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o test_file_leases file_leases.c -g -Weverything */

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/clonefile.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/xattr.h>

#include "test_utils.h"


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs.lease"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_CHECK_LEAKS(false));

#define TEST_LEASE_DIR  "lease_dir"
#define TEST_LEASE_FILE "lease_file"

static char g_testfile[MAXPATHLEN];
static char g_testdir[MAXPATHLEN];

/*
 * This unit-test validates the behavior of file leasing (read and write leases)
 * by utilizing the file leasing API (fcntl's F_SETLEASE and F_GETLEASE
 * commands) provided by VFS.
 */


static void
exit_cleanup(void)
{
	uint32_t val, new_val;
	size_t val_len, new_val_len;

	(void)remove(g_testfile);
	(void)rmdir(g_testdir);

	new_val = 60;
	new_val_len = val_len = sizeof(uint32_t);
	(void)sysctlbyname("vfs.lease.break_timeout", &val, &val_len,
	    (void *)&new_val, new_val_len);
}


static void
create_test_file(void)
{
	const char *tmpdir = dt_tmpdir();
	int fd;

	T_SETUPBEGIN;

	/*
	 * Make sure dataless file manipulation is enabled for this
	 * process (children will inherit).
	 *
	 * See kpi_vfs.c:vfs_context_can_break_leases().
	 */
	T_ASSERT_POSIX_SUCCESS(
		setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
		IOPOL_SCOPE_PROCESS, IOPOL_MATERIALIZE_DATALESS_FILES_ON),
		"Setup: ensuring dataless file materialization is enabled");

	atexit(exit_cleanup);

	snprintf(g_testdir, MAXPATHLEN, "%s/%s", tmpdir, TEST_LEASE_DIR);

	T_ASSERT_POSIX_SUCCESS(mkdir(g_testdir, 0777),
	    "Setup: creating test dir: %s", g_testdir);

	snprintf(g_testfile, MAXPATHLEN, "%s/%s", g_testdir, TEST_LEASE_FILE);

	T_WITH_ERRNO;
	fd = open(g_testfile, O_CREAT | O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Create test fi1e: %s", g_testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", TEST_LEASE_FILE);

	T_SETUPEND;
}

#define HELPER_TIMEOUT_SECS     60
#define MAX_HELPERS             10

static void __attribute__((noreturn))
run_helpers(const char **helper_test_names, int num_helpers)
{
	dt_helper_t helpers[MAX_HELPERS];
	char *args[] = {g_testfile, g_testdir, NULL};
	int i;

	T_QUIET;
	T_ASSERT_LE(num_helpers, MAX_HELPERS, "too many helpers");

	for (i = 0; i < num_helpers; i++) {
		helpers[i] = dt_child_helper_args(helper_test_names[i], args);
	}
	dt_run_helpers(helpers, (size_t)num_helpers, HELPER_TIMEOUT_SECS);
}

T_HELPER_DECL(open_rdonly_acquire_read_lease_succeed, "Open file in O_RDONLY mode and acquire read lease succeeded")
{
	char *testfile = argv[0];
	int err, fd;

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Acquire read lease: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_RDLCK, "Retrieve lease: %s", testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", testfile);
}

T_HELPER_DECL(open_rdonly_acquire_read_lease_EAGAIN, "Open file in O_RDONLY mode and acquire read lease failed with EAGAIN")
{
	char *testfile = argv[0];
	int err, fd;

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_TRUE((err == -1) && (errno == EAGAIN), "Acquire read lease: %s",
	    testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", testfile);
}

T_HELPER_DECL(open_rdwr_acquire_write_lease_EAGAIN, "Open file in O_RDWR mode and acquire write lease failed with EAGAIN")
{
	char *testfile = argv[0];
	int err, fd;

	T_WITH_ERRNO;
	fd = open(testfile, O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDWR: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_TRUE((err == -1) && (errno == EAGAIN), "Acquire write lease: %s",
	    testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", testfile);
}

T_HELPER_DECL(open_rdonly_read_lease_release, "Open file in O_RDONLY mode, acquire read lease, and release lease upon NOTE_LEASE_RELEASE event")
{
	struct kevent lease_kevent;
	struct timespec kevent_timeout;
	char *testfile = argv[0];
	int err, fd, kq;

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Acquire read lease: %s", testfile);

	kq = kqueue();
	T_ASSERT_NE(kq, -1, "Create kqueue");

	kevent_timeout.tv_sec = kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, (EV_ADD | EV_ENABLE | EV_CLEAR),
	    (NOTE_LEASE_DOWNGRADE | NOTE_LEASE_RELEASE), 0, (void *)testfile);
	err = kevent(kq, &lease_kevent, 1, NULL, 0, &kevent_timeout);
	T_ASSERT_GE(err, 0, "Register lease event on kq: %d", kq);

	kevent_timeout.tv_sec = 60;
	kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, EV_CLEAR, 0, 0, 0);

	err = kevent(kq, NULL, 0, &lease_kevent, 1, &kevent_timeout);
	T_ASSERT_NE(err, -1, "Listen for lease event on kq: %d", kq);

	if (err > 0) {
		T_ASSERT_EQ(lease_kevent.fflags, NOTE_LEASE_RELEASE,
		    "Got lease event 0x%x", lease_kevent.fflags);

		T_WITH_ERRNO;
		err = fcntl(fd, F_SETLEASE, F_UNLCK);
		T_ASSERT_NE(err, -1, "Release lease: %s", testfile);
	} else {
		T_FAIL("Timedout listening for lease event on kq: %d", kq);
	}
}

T_HELPER_DECL(open_rdonly_write_lease_downgrade, "Open file in O_RDONLY mode, acquire a write lease, and downgrade lease upon NOTE_LEASE_DOWNGRADE event")
{
	struct kevent lease_kevent;
	struct timespec kevent_timeout;
	char *testfile = argv[0];
	int err, fd, kq;

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_NE(err, -1, "Acquire write lease: %s", testfile);

	kq = kqueue();
	T_ASSERT_NE(kq, -1, "Create kqueue");

	kevent_timeout.tv_sec = kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, (EV_ADD | EV_ENABLE | EV_CLEAR),
	    (NOTE_LEASE_DOWNGRADE | NOTE_LEASE_RELEASE), 0, (void *)testfile);
	err = kevent(kq, &lease_kevent, 1, NULL, 0, &kevent_timeout);
	T_ASSERT_GE(err, 0, "Register lease event on kq: %d", kq);

	kevent_timeout.tv_sec = 60;
	kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, EV_CLEAR, 0, 0, 0);

	err = kevent(kq, NULL, 0, &lease_kevent, 1, &kevent_timeout);
	T_ASSERT_NE(err, -1, "Listen for lease event on kq: %d", kq);

	if (err > 0) {
		T_ASSERT_EQ(lease_kevent.fflags, NOTE_LEASE_DOWNGRADE,
		    "Got lease event 0x%x", lease_kevent.fflags);

		T_WITH_ERRNO;
		err = fcntl(fd, F_SETLEASE, F_RDLCK);
		T_ASSERT_NE(err, -1, "Downgrade to read lease: %s", testfile);
	} else {
		T_FAIL("Timedout listening for lease event on kq: %d", kq);
	}
}

T_HELPER_DECL(open_rw_write_lease_downgrade, "Open file multiple times in O_RDWR mode, acquire a write lease, and downgrade lease upon NOTE_LEASE_DOWNGRADE event")
{
	struct kevent lease_kevent;
	struct timespec kevent_timeout;
	char *testfile = argv[0];
	int err, rw_fd1, rw_fd2, fd, kq;

	T_WITH_ERRNO;
	rw_fd1 = open(testfile, O_RDWR, 0666);
	T_ASSERT_NE(rw_fd1, -1, "Open test fi1e in O_RDWR: %s", testfile);

	T_WITH_ERRNO;
	rw_fd2 = open(testfile, O_RDWR, 0666);
	T_ASSERT_NE(rw_fd2, -1, "Open test fi1e in O_RDWR: %s", testfile);

	T_WITH_ERRNO;
	fd = open(testfile, O_EVTONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_EVTONLY: %s", testfile);

	T_WITH_ERRNO;
	/* Pass in the expected open counts when placing a write lease. */
	err = fcntl(fd, F_SETLEASE, F_SETLEASE_ARG(F_WRLCK, 3));
	T_ASSERT_NE(err, -1, "Acquire write lease: %s", testfile);

	kq = kqueue();
	T_ASSERT_NE(kq, -1, "Create kqueue");

	kevent_timeout.tv_sec = kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, (EV_ADD | EV_ENABLE | EV_CLEAR),
	    (NOTE_LEASE_DOWNGRADE | NOTE_LEASE_RELEASE), 0, (void *)testfile);
	err = kevent(kq, &lease_kevent, 1, NULL, 0, &kevent_timeout);
	T_ASSERT_GE(err, 0, "Register lease event on kq: %d", kq);

	kevent_timeout.tv_sec = 60;
	kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, EV_CLEAR, 0, 0, 0);

	err = kevent(kq, NULL, 0, &lease_kevent, 1, &kevent_timeout);
	T_ASSERT_NE(err, -1, "Listen for lease event on kq: %d", kq);

	if (err > 0) {
		T_ASSERT_EQ(lease_kevent.fflags, NOTE_LEASE_DOWNGRADE,
		    "Got lease event 0x%x", lease_kevent.fflags);

		T_WITH_ERRNO;
		/* Pass in the expected write counts when placing a read lease. */
		err = fcntl(fd, F_SETLEASE, F_SETLEASE_ARG(F_RDLCK, 2));
		T_ASSERT_NE(err, -1, "Downgrade to read lease: %s", testfile);
	} else {
		T_FAIL("Timedout listening for lease event on kq: %d", kq);
	}
}

T_HELPER_DECL(open_rdonly_read_lease_timedout, "Open file in O_RDONLY mode, acquire read lease, and hold lease beyond lease break timeout upon NOTE_LEASE_RELEASE event", T_META_ASROOT(true))
{
	struct kevent lease_kevent;
	struct timespec kevent_timeout;
	uint32_t val, new_val;
	size_t val_len, new_val_len;
	char *testfile = argv[0];
	int err, fd, kq;

	if (!is_development_kernel()) {
		T_SKIP("Skipping test on release kernel");
	}

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Acquire read lease: %s", testfile);

	new_val = 10;
	new_val_len = val_len = sizeof(uint32_t);
	err = sysctlbyname("vfs.lease.break_timeout", (void *)&val, &val_len,
	    (void *)&new_val, new_val_len);
	T_ASSERT_NE(err, -1, "Change vfs.lease.break_timeout to %d secs", new_val);

	kq = kqueue();
	T_ASSERT_NE(kq, -1, "Create kqueue");

	kevent_timeout.tv_sec = kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, (EV_ADD | EV_ENABLE | EV_CLEAR),
	    (NOTE_LEASE_DOWNGRADE | NOTE_LEASE_RELEASE), 0, (void *)testfile);
	err = kevent(kq, &lease_kevent, 1, NULL, 0, &kevent_timeout);
	T_ASSERT_GE(err, 0, "Register lease event on kq: %d", kq);

	kevent_timeout.tv_sec = 30;
	kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, fd, EVFILT_VNODE, EV_CLEAR, 0, 0, 0);

	err = kevent(kq, NULL, 0, &lease_kevent, 1, &kevent_timeout);
	T_ASSERT_NE(err, -1, "Listen for lease event on kq: %d", kq);

	if (err > 0) {
		T_ASSERT_EQ(lease_kevent.fflags, NOTE_LEASE_RELEASE,
		    "Got lease event 0x%x", lease_kevent.fflags);

		/* Sleep to force lease break timedout. */
		T_LOG("Sleep for %d secs to force lease break timedout", new_val + 5);
		sleep(new_val + 5);
	} else {
		T_FAIL("Timedout listening for lease event on kq: %d", kq);
	}
	T_ASSERT_NE(err, -1, "Change vfs.lease.break_timeout to %d secs", new_val);
}

T_HELPER_DECL(open_rdonly_dir_read_lease, "Open directory in O_RDONLY mode, acquire read lease, and release lease upon NOTE_LEASE_RELEASE event")
{
	struct kevent lease_kevent;
	struct timespec kevent_timeout;
	char *testdir = argv[1];
	int err, dir_fd, kq;

	T_WITH_ERRNO;
	dir_fd = open(testdir, O_RDONLY);
	T_ASSERT_NE(dir_fd, -1, "Open test dir in O_RDONLY: %s", testdir);

	kq = kqueue();
	T_ASSERT_NE(kq, -1, "Create kqueue");

retry:
	T_WITH_ERRNO;
	err = fcntl(dir_fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Acquire read lease: %s", testdir);

	kevent_timeout.tv_sec = kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, dir_fd, EVFILT_VNODE, (EV_ADD | EV_ENABLE | EV_CLEAR),
	    (NOTE_LEASE_DOWNGRADE | NOTE_LEASE_RELEASE), 0, (void *)testdir);
	err = kevent(kq, &lease_kevent, 1, NULL, 0, &kevent_timeout);
	T_ASSERT_GE(err, 0, "Register lease event on kq: %d", kq);

	kevent_timeout.tv_sec = 30;
	kevent_timeout.tv_nsec = 0;
	EV_SET(&lease_kevent, dir_fd, EVFILT_VNODE, EV_CLEAR, 0, 0, 0);

	err = kevent(kq, NULL, 0, &lease_kevent, 1, &kevent_timeout);
	T_ASSERT_NE(err, -1, "Listen for lease event on kq: %d", kq);

	if (err > 0) {
		T_ASSERT_EQ(lease_kevent.fflags, NOTE_LEASE_RELEASE,
		    "Got lease event 0x%x", lease_kevent.fflags);

		T_WITH_ERRNO;
		err = fcntl(dir_fd, F_SETLEASE, F_UNLCK);
		T_ASSERT_NE(err, -1, "Release lease: %s", testdir);

		/*
		 * Retry until we got no more events (kevent timedout) which means
		 * the other helper is done with all the tests.
		 */
		goto retry;
	} else {
		T_FAIL("Timedout listening for lease event on kq: %d", kq);
	}
}

T_HELPER_DECL(open_rdwr, "Open file in O_RDWR mode")
{
	char *testfile = argv[0];
	int fd;

	/* wait for the other helper to be in ready state */
	sleep(1);

	T_WITH_ERRNO;
	fd = open(testfile, O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDWR: %s", testfile);
}

T_HELPER_DECL(open_rdonly, "Open file in O_RDONLY mode")
{
	char *testfile = argv[0];
	int fd;

	/* wait for the other helper to be in ready state */
	sleep(1);

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);
}

T_HELPER_DECL(truncate, "Truncate file")
{
	char *testfile = argv[0];
	int err;

	/* wait for the other helper to be in ready state */
	sleep(1);

	T_WITH_ERRNO;
	err = truncate(testfile, 0);
	T_ASSERT_NE(err, -1, "Truncate test fi1e: %s", testfile);
}

T_HELPER_DECL(open_rdonly_request_read_range_lock, "Open file in O_RDONLY mode and request byte range lock")
{
	struct flock lreq;
	char *testfile = argv[0];
	int err, fd;

	/* wait for the other helper to be in ready state */
	sleep(1);

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	T_WITH_ERRNO;
	lreq.l_start = 0;
	lreq.l_len = 0;
	lreq.l_type = F_RDLCK;
	lreq.l_whence = 0;

	err = fcntl(fd, F_SETLK, &lreq);
	T_ASSERT_NE(err, -1, "Acquire read range lock on test fi1e: %s", testfile);

	T_WITH_ERRNO;
	lreq.l_start = 0;
	lreq.l_len = 0;
	lreq.l_type = F_UNLCK;
	lreq.l_whence = 0;

	err = fcntl(fd, F_SETLK, &lreq);
	T_ASSERT_NE(err, -1, "Release read range lock on test fi1e: %s", testfile);
}

T_HELPER_DECL(file_syscalls, "Call file syscalls")
{
	char destfile[MAXPATHLEN];
	struct attrlist attrlist;
	char *xattr_key = "com.apple.xattr_test";
	char xattr_val[] = "xattr_foo";
	char *testfile = argv[0];
	uint32_t flags;
	int err, fd;

	/* wait for the other helper to be in ready state */
	sleep(1);

	T_WITH_ERRNO;
	fd = open(testfile, O_RDWR | O_CREAT, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDWR|O_CREAT: %s", testfile);
	sleep(1);

	/* Test ftruncate (fd needs to be opened with write mode) */
	T_WITH_ERRNO;
	err = ftruncate(fd, 0);
	T_ASSERT_NE(err, -1, "fdtruncate: %s", testfile);
	sleep(1);

	/* Test (p)write. */
	T_WITH_ERRNO;
	err = (int)write(fd, destfile, sizeof(destfile));
	T_ASSERT_NE(err, -1, "write: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = (int)pwrite(fd, destfile, sizeof(destfile), sizeof(destfile));
	T_ASSERT_NE(err, -1, "write: %s", testfile);
	sleep(1);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", testfile);

	T_WITH_ERRNO;
	fd = open(testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", testfile);

	/* Test (f)chflags syscall */
	T_WITH_ERRNO;
	err = chflags(testfile, 0);
	T_ASSERT_NE(err, -1, "chflags: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = fchflags(fd, 0);
	T_ASSERT_NE(err, -1, "fchflags: %s", testfile);
	sleep(1);

	/* Test (f)chmod syscall */
	T_WITH_ERRNO;
	err = chmod(testfile, S_IRWXU);
	T_ASSERT_NE(err, -1, "chmod: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = fchmod(fd, S_IRWXU);
	T_ASSERT_NE(err, -1, "fchmod: %s", testfile);
	sleep(1);

	/* Test clonefile */
	snprintf(destfile, sizeof(destfile), "%s.%d", testfile, rand());
	T_WITH_ERRNO;
	err = clonefile(testfile, destfile, CLONE_NOFOLLOW);
	T_ASSERT_NE(err, -1, "clonefile src: %s dest: %s", testfile, destfile);
	sleep(1);

	/* Test copyfile */
	T_WITH_ERRNO;
	err = copyfile(testfile, destfile, NULL, COPYFILE_DATA | COPYFILE_STAT);
	T_ASSERT_NE(err, -1, "copyfile src: %s dest: %s", testfile, destfile);
	sleep(1);

	/* Test unlink */
	T_WITH_ERRNO;
	err = unlink(destfile);
	T_ASSERT_NE(err, -1, "unlink: %s", destfile);
	sleep(1);

	/* Test (f)setxattr and (f)removexattr */
	T_WITH_ERRNO;
	err = setxattr(testfile, xattr_key, &xattr_val[0], sizeof(xattr_val), 0, 0);
	T_ASSERT_NE(err, -1, "setxattr: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = removexattr(testfile, xattr_key, 0);
	T_ASSERT_NE(err, -1, "removexattr: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = fsetxattr(fd, xattr_key, &xattr_val[0], sizeof(xattr_val), 0, 0);
	T_ASSERT_NE(err, -1, "fsetxattr: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = fremovexattr(fd, xattr_key, 0);
	T_ASSERT_NE(err, -1, "fremovexattr: %s", testfile);
	sleep(1);

	/* Test (f)setattrlist */
	flags = 0;
	memset(&attrlist, 0, sizeof(attrlist));
	attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrlist.commonattr = (ATTR_CMN_FLAGS);

	T_WITH_ERRNO;
	err = setattrlist(testfile, &attrlist, &flags, sizeof(flags), 0);
	T_ASSERT_NE(err, -1, "setattrlist: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = fsetattrlist(fd, &attrlist, &flags, sizeof(flags), 0);
	T_ASSERT_NE(err, -1, "fsetattrlist: %s", testfile);
	sleep(1);

	/* Test truncate */
	T_WITH_ERRNO;
	err = truncate(testfile, 0);
	T_ASSERT_NE(err, -1, "truncate: %s", testfile);
	sleep(1);

	/* Test (f)utimes */
	T_WITH_ERRNO;
	err = utimes(testfile, NULL);
	T_ASSERT_NE(err, -1, "utimes: %s", testfile);
	sleep(1);

	T_WITH_ERRNO;
	err = futimes(fd, NULL);
	T_ASSERT_NE(err, -1, "futimes: %s", testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", testfile);
}

T_HELPER_DECL(file_syscalls_2, "Call file syscalls (mknod)", T_META_ASROOT(true))
{
	char destfile[MAXPATHLEN];
	char *testfile = argv[0];
	int err;

	snprintf(destfile, sizeof(destfile), "%s.%d", testfile, rand());

	/* wait for the other helper to be in ready state */
	sleep(1);

	/* Test mknod */
	T_WITH_ERRNO;
	err = mknod(destfile, (S_IFCHR | S_IRWXU), 0);
	T_ASSERT_NE(err, -1, "mknod: %s", destfile);
	sleep(1);

	/* Test unlink */
	T_WITH_ERRNO;
	err = unlink(destfile);
	T_ASSERT_NE(err, -1, "unlink: %s", destfile);
}

/*
 * Test acquire, downgrade, and release lease.
 * a. Process A opens the file in O_RDONLY mode
 * b. Process A acquires write lease
 * c. Process A downgrade from write to read lease
 * d. Process A release lease
 *
 * Result: Lease operations should succeed as expected.
 */
T_DECL(acquire_downgrade_release, "Test acquire, downgrade and release lease", T_META_ENABLED(TARGET_OS_OSX))
{
	int err, fd;

	create_test_file();

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_NE(err, -1, "Acquire write lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_WRLCK, "Retrieve lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Downgrade to read lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_RDLCK, "Retrieve lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_UNLCK);
	T_ASSERT_NE(err, -1, "Release lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease: %s", g_testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);
}

/*
 * Test acquire lease failure due to open conflicts.
 * a. Process A opens the file in O_RDWR mode
 * b. Process B opens the file in O_RDONLY mode
 * c. Process B tries to acquire read lease
 *
 * Result: Process B should fail to acquire read lease with EAGAIN due to the
 *         file has been opened with write mode (O_RDWR).
 */
T_DECL(open_conflict_1, "Test acquire read lease failure due to open conflicts", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_acquire_read_lease_EAGAIN"};
	int fd;

	create_test_file();

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDWR: %s", g_testfile);

	run_helpers(helper_test_names, 1);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);
}

/*
 * Test acquire lease failure due to open conflicts.
 * a. Process A opens the file in O_RDONLY mode
 * b. Process B opens the file in O_RDWR mode
 * c. Process B tries to acquire write lease
 *
 * Result: Process B should fail to acquire write lease with EAGAIN due to the
 *         file has been opened elsewhere.
 */
T_DECL(open_conflict_2, "Test acquire write lease failure due to open conflicts", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdwr_acquire_write_lease_EAGAIN"};
	int fd;

	create_test_file();

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", g_testfile);

	run_helpers(helper_test_names, 1);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);
}

/*
 * Test multiple processes put a read lease on the file.
 * a. Process A opens the file with O_RDONLY mode and place a read lease
 * b. Process B opens the file with O_RDONLY mode and place a read lease
 *
 * Result: Both processes should succeed in placing read lease on the file.
 */
T_DECL(multiple_read_leases, "Test multiple processes put a read lease on the file", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_acquire_read_lease_succeed",
		                           "open_rdonly_acquire_read_lease_succeed"};

	create_test_file();
	run_helpers(helper_test_names, 2);
}

/*
 * Test acquire and release lease when there is no lease is in place.
 *
 * Result: Acquire lease should succeed with F_UNLCK (no lease).
 *         Release lease should fail with ENOLCK.
 */
T_DECL(acquire_release_no_lease, "Test acquire and release lease when there is no lease is in place", T_META_ENABLED(TARGET_OS_OSX))
{
	int err, fd;

	create_test_file();

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDWR: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_UNLCK);
	T_ASSERT_TRUE((err == -1) && (errno == ENOLCK), "Release lease: %s",
	    g_testfile);
}

/*
 * Test acquire, release and retrieve lease on non-regular file.
 *
 * Result: Acquire, release and retrieve lease should fail with EBADF.
 */
T_DECL(acquire_release_retrieve_non_file, "Test acquire, release and retrieve lease on non-regular file", T_META_ENABLED(TARGET_OS_OSX))
{
	int err, fd;

	T_WITH_ERRNO;
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	T_ASSERT_NE(fd, -1, "Open socket");

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_TRUE((err == -1) && (errno == EBADF), "Acquire read lease on socket");

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_TRUE((err == -1) && (errno == EBADF), "Acquire write lease on socket");

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_UNLCK);
	T_ASSERT_TRUE((err == -1) && (errno == EBADF), "Release lease on socket");

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_TRUE((err == -1) && (errno == EBADF), "Retrieve lease on socket");

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close socket");
}

/*
 * Test retrieve and downgrade lease with duplicated fd created with dup(2).
 * a. Process A opens the file with O_RDONLY mode and place a write lease
 * b. Process A duplicates the existing file descriptor
 * c. Process A retrieves and downgrade lease with duplicated fd
 * d. Process A closes the original and duplicated fds to release lease.
 *
 * Result: Retrieve and downgrade with duplicated fd should succeed.
 *         When all fds are closed, lease should be released implicity.
 */
T_DECL(retrieve_downgrade_dup_fd, "Test retrieve and downgrade lease with duplicated fd created with dup()", T_META_ENABLED(TARGET_OS_OSX))
{
	int err, dup_fd, fd;

	create_test_file();

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_NE(err, -1, "Acquire write lease: %s", g_testfile);

	T_WITH_ERRNO;
	dup_fd = dup(fd);
	T_ASSERT_NE(dup_fd, -1, "Duplicate existing fd: %d", fd);

	T_WITH_ERRNO;
	err = fcntl(dup_fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_WRLCK, "Retrieve lease with dup fd: %d", dup_fd);

	T_WITH_ERRNO;
	err = fcntl(dup_fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Downgrade to read lease with dup fd: %d", dup_fd);

	T_WITH_ERRNO;
	err = fcntl(dup_fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_RDLCK, "Retrieve lease with dup fd: %d", dup_fd);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close original fd");
	T_ASSERT_POSIX_SUCCESS(close(dup_fd), "Close duplicated fd");

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease: %s", g_testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close fd");
}

/*
 * Test retrieve and release lease with duplicated fd created with fork(2).
 * a. Process A opens the file with O_RDONLY mode and place a write lease
 * b. Process A forks to create a child process
 * c. Child process retrieves and releases lease with duplicated fd
 * d. Child process exits
 * e. Process A verifies the lease has been released
 *
 * Result: Retrieve and release with duplicated fd should succeed.
 *         Child process should be able to release the leased placed by the
 *         parent process.
 */
T_DECL(retrieve_release_fork_fd, "Test retrieve and release lease with duplicated fd created with fork()", T_META_ENABLED(TARGET_OS_OSX))
{
	pid_t child_pid;
	int err, fd;

	create_test_file();

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in O_RDONLY: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease: %s", g_testfile);

	T_WITH_ERRNO;
	err = fcntl(fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_NE(err, -1, "Acquire write lease: %s", g_testfile);

	child_pid = fork();
	T_ASSERT_POSIX_SUCCESS(child_pid, "Fork process");

	if (child_pid == 0) {
		/* child process */
		err = fcntl(fd, F_GETLEASE);
		T_ASSERT_EQ(err, F_WRLCK, "Retrieve lease with fork fd: %d", fd);

		T_WITH_ERRNO;
		err = fcntl(fd, F_SETLEASE, F_UNLCK);
		T_ASSERT_NE(err, -1, "Release lease with fork fd: %d", fd);

		T_WITH_ERRNO;
		err = fcntl(fd, F_GETLEASE);
		T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease with fork fd: %d", fd);

		exit(0);
	} else {
		/* wait for child process to exit */
		if (dt_waitpid(child_pid, &err, NULL, 30) == false) {
			T_FAIL("dt_waitpid() failed on child pid %d", child_pid);
		}

		T_WITH_ERRNO;
		err = fcntl(fd, F_GETLEASE);
		T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease with parent fd: %d", fd);

		T_ASSERT_POSIX_SUCCESS(close(fd), "Close fd");
	}
}

/*
 * Test lease break release event.
 * a. Process A opens the file in O_RDONLY mode and place a read lease
 * b. Process B opens the file in O_RDWR mode and open syscall is blocked
 * c. Lease break release event is sent to Process A
 *
 * Result: Process A releases the lease and process B's open is unblocked
 */
T_DECL(lease_break_release_1, "Test lease break release event when file is opened in O_RDWR mode", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_read_lease_release", "open_rdwr"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

/*
 * Test lease break release event.
 * a. Process A opens the file in O_RDONLY mode and place a read lease
 * b. Process B truncates the file and truncate syscall is blocked
 * c. Lease break release event is sent to Process A
 *
 * Result: Process A releases the lease and process B's truncate is unblocked.
 */
T_DECL(lease_break_release_2, "Test lease break release event when file is truncated", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_read_lease_release", "truncate"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

/*
 * Test lease break release event.
 * a. Process A opens the file in O_RDONLY mode and place a read lease
 * b. Process B opens the file in O_RDONLY mode and requests byte range lock
 *    via fcntl(F_SETLK or F_OFD_SETLK)
 * c. Lease break release event is sent to Process A
 *
 * Result: Process A releases the lease and process B's fcntl call is unblocked.
 */
T_DECL(lease_break_release_3, "Test lease break release event when byte range lock is requested", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_read_lease_release", "open_rdonly_request_read_range_lock"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

/*
 * Test lease break release event.
 * a. Process A opens the file in O_RDONLY mode and place a read lease
 * a. Process B opens the file in O_RDONLY mode and place a read lease
 * b. Process C opens the file in O_RDWR mode and open syscall is blocked
 * c. Lease break release events are sent to Process A and B
 *
 * Result: Process A and B release the lease and process C's open is unblocked
 */
T_DECL(lease_break_release_4, "Test multiple lease break release events", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_read_lease_release",
		                           "open_rdonly_read_lease_release", "open_rdwr"};

	create_test_file();

	run_helpers(helper_test_names, 3);
}

/*
 * Test lease break downgrade event.
 * a. Process A opens the file in O_RDONLY mode and place a write lease
 * b. Process B opens the file in O_RDONLY mode and open syscall is blocked
 * c. Lease break downgrade event is sent to Process A
 *
 * Result: Process A downgrades the lease and process B's open is unblocked.
 */
T_DECL(lease_break_downgrade_1, "Test lease break downgrade event with read-only opens", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_write_lease_downgrade", "open_rdonly"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

/*
 * Test lease break downgrade event.
 * a. Process A opens the file multiple times in O_RDWR mode and place a
 *    write lease
 * b. Process B opens the file in O_RDONLY mode and open syscall is blocked
 * c. Lease break downgrade event is sent to Process A
 *
 * Result: Process A downgrades the lease and process B's open is unblocked.
 */
T_DECL(lease_break_downgrade_2, "Test lease break downgrade event with multiple read-write opens", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rw_write_lease_downgrade", "open_rdonly"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

/*
 * Test lease break timedout
 * a. Process A opens the file in O_RDONLY mode and place a read lease
 * b. Process B opens the file in O_RDWR mode and open syscall is blocked
 * c. Lease break release event is sent to Process A
 * d. Lease is not release within sysctl's 'vfs.lease.break_timeout'
 *
 * Result: Kernel forcibly breaks the lease and process B's open is unblocked.
 */
T_DECL(lease_break_timedout, "Test lease break timedout", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_read_lease_timedout", "open_rdwr"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

/*
 * Test acquire and release lease on directory.
 * a. Process A opens the directory in O_RDONLY mode
 * b. Process A acquires read lease
 * d. Process A release lease
 *
 * Result: Lease operations should succeed as expected.
 */
T_DECL(acquire_release_read_lease_dir, "Test acquire and release read lease", T_META_ENABLED(TARGET_OS_OSX))
{
	int err, dir_fd;

	create_test_file();

	T_WITH_ERRNO;
	dir_fd = open(g_testdir, O_RDONLY);
	T_ASSERT_NE(dir_fd, -1, "Open test dir in O_RDONLY: %s", g_testdir);

	T_WITH_ERRNO;
	err = fcntl(dir_fd, F_SETLEASE, F_RDLCK);
	T_ASSERT_NE(err, -1, "Acquire read lease: %s", g_testdir);

	T_WITH_ERRNO;
	err = fcntl(dir_fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_RDLCK, "Retrieve lease: %s", g_testdir);

	T_WITH_ERRNO;
	err = fcntl(dir_fd, F_SETLEASE, F_UNLCK);
	T_ASSERT_NE(err, -1, "Release lease: %s", g_testdir);

	T_WITH_ERRNO;
	err = fcntl(dir_fd, F_GETLEASE);
	T_ASSERT_EQ(err, F_UNLCK, "Retrieve lease: %s", g_testdir);

	T_ASSERT_POSIX_SUCCESS(close(dir_fd), "Close test dir: %s", g_testdir);
}

/*
 * Test acquire write lease on directory.
 *
 * Result: Acquire write lease should fail with EBADF.
 */
T_DECL(acquire_write_lease_dir, "Test acquire write lease on directory", T_META_ENABLED(TARGET_OS_OSX))
{
	int err, dir_fd;

	create_test_file();

	T_WITH_ERRNO;
	dir_fd = open(g_testdir, O_RDONLY);
	T_ASSERT_NE(dir_fd, -1, "Open test dir in O_RDONLY: %s", g_testdir);

	T_WITH_ERRNO;
	err = fcntl(dir_fd, F_SETLEASE, F_WRLCK);
	T_ASSERT_TRUE((err == -1) && (errno == ENOTSUP), "Acquire write lease on directory: %s", g_testdir);

	T_ASSERT_POSIX_SUCCESS(close(dir_fd), "Close test dir");
}

/*
 * Test lease break release event for directory read leasing.
 * a. Process A opens the directory in O_RDONLY mode and place a read lease
 * b. Process B performs various syscalls that can cause its directory contents
 *    (namespace) to change, modify contents or change attributes on the
 *    immediate files.
 *
 * Result: Process A releases the lease and process B's syscall is unblocked.
 */
T_DECL(read_lease_dir_1, "Test directory read leasing and lease break events", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_dir_read_lease", "file_syscalls"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}

T_DECL(read_lease_dir_2, "Test directory read leasing and lease break events", T_META_ENABLED(TARGET_OS_OSX))
{
	const char *helper_test_names[] = {"open_rdonly_dir_read_lease", "file_syscalls_2"};

	create_test_file();

	run_helpers(helper_test_names, 2);
}
