/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o iopolicy iopolicy.c -g -Weverything */

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

#ifndef IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY
#define IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY 10
#endif

#ifndef IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_OFF
#define IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_OFF 0
#endif

#ifndef IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON
#define IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON 1
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs.iopolicy"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_CHECK_LEAKS(false));

#define TEST_FILE "testfile"

static char g_testfile[MAXPATHLEN];
static char g_testdata[1024];

static void
exit_cleanup(void)
{
	(void)remove(g_testfile);
}

T_DECL(iopol_type_vfs_disallow_rw_for_o_evtonly,
    "test IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY policy")
{
	char attrbuf[256];
	struct attrlist attrlist;
	struct kevent vnode_kevent;
	struct timespec kevent_timeout;
	const char *tmpdir = dt_tmpdir();
	void *mapped;
	int err, fd, kq;

	T_SETUPBEGIN;

	atexit(exit_cleanup);

	T_ASSERT_POSIX_ZERO(chdir(tmpdir),
	    "Setup: changing to tmpdir: %s", tmpdir);

	snprintf(g_testfile, MAXPATHLEN, "%s/%s", tmpdir, TEST_FILE);

	T_WITH_ERRNO;
	fd = open(g_testfile, O_CREAT | O_RDWR, 0666);
	T_ASSERT_NE(fd, -1, "Create test file: %s", g_testfile);

	T_WITH_ERRNO;
	err = (int)write(fd, g_testfile, sizeof(g_testfile));
	T_ASSERT_NE(err, -1, "Write: %s", g_testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);

	kq = kqueue();
	T_ASSERT_NE(kq, -1, "Create kqueue");

	T_SETUPEND;

	T_WITH_ERRNO;
	err = setiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY,
	    IOPOL_SCOPE_THREAD, IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON);
	T_ASSERT_TRUE((err == -1) && (errno == EINVAL),
	    "setiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY, IOPOL_SCOPE_THREAD, 1)");

	T_WITH_ERRNO;
	err = setiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY,
	    IOPOL_SCOPE_PROCESS, IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON);
	T_ASSERT_NE(err, -1,
	    "setiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY, IOPOL_SCOPE_PROCESS, 1)");

	T_WITH_ERRNO;
	err = getiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY,
	    IOPOL_SCOPE_PROCESS);
	T_ASSERT_EQ(err, IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON,
	    "getiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY, IOPOL_SCOPE_PROCESS)");

	T_WITH_ERRNO;
	err = setiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY,
	    IOPOL_SCOPE_PROCESS, IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_OFF);
	T_ASSERT_TRUE((err == -1) && (errno == EINVAL),
	    "setiopolicy_np(IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY, IOPOL_SCOPE_PROCESS, 0)");

	T_WITH_ERRNO;
	fd = open(g_testfile, O_RDWR | O_EVTONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in 'O_RDW|O_EVTONLY': %s", g_testfile);

	T_WITH_ERRNO;
	err = (int)write(fd, g_testdata, sizeof(g_testdata));
	T_ASSERT_TRUE((err == -1) && (errno == EBADF),
	    "Trying to write: %s", g_testfile);

	T_WITH_ERRNO;
	err = (int)read(fd, g_testdata, sizeof(g_testdata));
	T_ASSERT_TRUE((err == -1) && (errno == EBADF),
	    "Trying to read: %s", g_testfile);

	T_WITH_ERRNO;
	mapped = mmap(NULL, sizeof(g_testdata), PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, 0);
	T_ASSERT_TRUE((err == -1) && (errno == EACCES),
	    "Trying to mmaped read/write: %s", g_testfile);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);

	T_WITH_ERRNO;
	fd = open(g_testfile, O_EVTONLY, 0666);
	T_ASSERT_NE(fd, -1, "Open test fi1e in 'O_EVTONLY': %s", g_testfile);

	T_WITH_ERRNO;
	err = (int)read(fd, g_testdata, sizeof(g_testdata));
	T_ASSERT_TRUE((err == -1) && (errno == EBADF),
	    "Trying to read: %s", g_testfile);

	T_WITH_ERRNO;
	memset(&attrlist, 0, sizeof(attrlist));
	attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrlist.commonattr = (ATTR_CMN_OBJTYPE | ATTR_CMN_OBJID | ATTR_CMN_MODTIME);

	err = fgetattrlist(fd, &attrlist, &attrbuf, sizeof(attrbuf), 0);
	T_ASSERT_NE(err, -1, "Perform getattrlist: %s", g_testfile);

	kevent_timeout.tv_sec = kevent_timeout.tv_nsec = 0;
	EV_SET(&vnode_kevent, fd, EVFILT_VNODE, (EV_ADD | EV_ENABLE | EV_CLEAR),
	    NOTE_WRITE, 0, (void *)g_testfile);
	err = kevent(kq, &vnode_kevent, 1, NULL, 0, &kevent_timeout);
	T_ASSERT_GE(err, 0, "Register vnode event on kq: %d", kq);

	kevent_timeout.tv_sec = 2;
	kevent_timeout.tv_nsec = 0;
	EV_SET(&vnode_kevent, fd, EVFILT_VNODE, EV_CLEAR, 0, 0, 0);

	err = kevent(kq, NULL, 0, &vnode_kevent, 1, &kevent_timeout);
	T_ASSERT_NE(err, -1, "Listen for vnode event on kq: %d", kq);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Close test file: %s", g_testfile);
}
