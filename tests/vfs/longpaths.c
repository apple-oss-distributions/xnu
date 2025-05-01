#include <sys/param.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <removefile.h>

#include <sys/xattr.h>
#include <sys/attr.h>
#include <sys/fsgetpath.h>
#include <sys/fsgetpath_private.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define MAXLONGPATHLEN 8192 /* From sys/syslimits.h */

#define nelem(x) (sizeof((x))/sizeof((x)[0]))

#define DEBUG 1
#define DPRINT(fmt, ...) do {\
	if (DEBUG) fprintf(stderr, "%s | " fmt "\n", __func__, ## __VA_ARGS__);\
}while(0)

#define onoffstr(x) ((x) ? "on" : "off")

// helpers for printing test context on errors
#define CTXFMT    "[len: %zd, pol: %s]"
#define CTXARGS   pathlen, onoffstr(policy)
#define CTXSTR    CTXFMT, CTXARGS

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"));

static void *
emalloc(size_t n)
{
	void *p = malloc(n);
	T_QUIET; T_ASSERT_NE(p, NULL, "malloced %zd bytes", n);
	return p;
}

static size_t
generatename(char *outstr, size_t maxlen, size_t depth)
{
	static char letters[] = {
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
	};

	T_QUIET; T_ASSERT_TRUE(depth >= 0 && depth < sizeof(letters),
	    "0 <= %zd < %zd", depth, sizeof(letters));

	size_t len = MIN(NAME_MAX, maxlen);
	memset(outstr, letters[depth], len);
	return len;
}

static char *
createpath(size_t pathlen, bool leafisdir, struct stat *st)
{
	// If we generate names exactly NAME_MAX long, the only difference between
	// paths of e.g. length 1023 and 1024 are the trailing slash.
	// NAME_MAX - 1 avoids that.
	enum {
		MAXINTERLEN = NAME_MAX - 1
	};

	char *path = emalloc(pathlen + 1);
	char *p = path;
	int dirfd = AT_FDCWD;
	size_t depth = 0;

	// Plus one below to account for the slash
	size_t intermediaries = pathlen / (MAXINTERLEN + 1);
	size_t leaflen = pathlen % (MAXINTERLEN + 1);
	if (leaflen == 0) {
		// Prevent trying to create an empty leaf when pathlen is an
		// exact divisor of MAXINTERLEN + 1
		leaflen = pathlen;
		intermediaries--;
	}

	// leaflen > MAXINTERLEN when pathlen is an exact divisor MAXINTERLEN + 1
	char name[MAX(MAXINTERLEN, leaflen) + 1];

	while (intermediaries-- > 0) {
		size_t n = generatename(name, MAXINTERLEN, depth);
		name[n] = '\0';
		memmove(p, name, n);
		p += n;
		*p++ = '/';
		depth++;

		T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdirat(dirfd, name, 0700),
		    "[len: %zd] failed to create dir '%s' at %.*s",
		    pathlen, name, (int)MAXINTERLEN, path);

		int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY);
		T_QUIET; T_ASSERT_GE(fd, 0,
		    "[len: %zd] failed to open dir %s: %s", pathlen, name, strerror(errno));
		if (dirfd != AT_FDCWD) {
			close(dirfd);
		}
		dirfd = fd;
	}

	size_t n = generatename(name, leaflen, depth);
	name[n] = '\0';
	memmove(p, name, n);
	p += n;
	*p = '\0';

	T_QUIET; T_ASSERT_TRUE(strlen(path) == pathlen, "%zd != %zd", strlen(path), pathlen);

	if (leafisdir) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdirat(dirfd, name, 0700),
		    "[len: %zd] failed to create leaf dir '%s' at '%s'", pathlen, name, path);

		if (st != NULL) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(fstatat(dirfd, name, st, 0),
			    "[len: %zd] failed to stat leaf dir '%s' at '%s'", pathlen, name, path);
		}
	} else {
		int fd = openat(dirfd, name, O_CREAT | O_TRUNC | O_WRONLY, 0600);
		T_QUIET; T_ASSERT_GE(fd, 0,
		    "[len: %zd] failed to create file '%s' leaf at '%s'", pathlen, name, path);

		if (st != NULL) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(fstat(fd, st),
			    "[len: %zd] failed to stat leaf file '%s' at '%s'", pathlen, name, path);
		}
		close(fd);
	}

	if (dirfd != AT_FDCWD) {
		close(dirfd);
	}
	return path;
}

static int
openlongpath(const char *path, int flag)
{
	const char *p = path;
	int dirfd = AT_FDCWD;
	int fd = -1;
	char *sep;

	while (p != NULL && *p != '\0' && (sep = strchr(p, '/')) != NULL) {
		size_t namelen = (size_t)(sep - p);
		T_QUIET; T_ASSERT_LT(namelen, (size_t)NAME_MAX, "%zd >= NAME_MAX", namelen);
		char name[NAME_MAX];
		strlcpy(name, p, namelen + 1);

		fd = openat(dirfd, name, O_EVTONLY);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "failed to open intermediate %s", name);
		close(dirfd);
		dirfd = fd;
		p = sep + 1;
	}

	fd = openat(dirfd, p, flag);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "failed to open final component %s", p);
	close(dirfd);
	return fd;
}

static char *
setup_test_dir(char *name)
{
	char *dir = NULL;
	asprintf(&dir, "%s/longpaths-%s-XXXXXX", dt_tmpdir(), name);
	T_QUIET; T_ASSERT_NOTNULL(mkdtemp(dir), NULL);
	T_LOG("test dir: %s", dir);
	chdir(dir);
	return dir;
}

static void
setup_case_dir(size_t pathlen, bool policy)
{
	char casedir[64];
	snprintf(casedir, sizeof(casedir), "len-%zd-policy-%s",
	    pathlen, onoffstr(policy));

	T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdir(casedir, 0700),
	    "failed to create case dir %s", casedir);
	chdir(casedir);
}

#ifndef IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS
#define IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS 13
#define IOPOL_VFS_SUPPORT_LONG_PATHS_DEFAULT 0
#define IOPOL_VFS_SUPPORT_LONG_PATHS_ON 1
#endif

T_DECL(longpaths_set_policy_test, "Test combinations of policy settings in process and thread")
{
	char *testdir = setup_test_dir("set_policy_test");

	char *path = createpath(MAXPATHLEN + 10, false, NULL);
	int fd = -1;

	// Enable policy for thread
	T_ASSERT_POSIX_SUCCESS(setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,
	    IOPOL_SCOPE_THREAD, IOPOL_VFS_SUPPORT_LONG_PATHS_ON),
	    "[thread: on, proc: off]");

	T_ASSERT_POSIX_SUCCESS(fd = open(path, O_EVTONLY), "open long path");
	close(fd);

	// Enable policy for process
	T_ASSERT_POSIX_SUCCESS(setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,
	    IOPOL_SCOPE_PROCESS, IOPOL_VFS_SUPPORT_LONG_PATHS_ON),
	    "[thread: on, proc: on]");

	T_ASSERT_POSIX_SUCCESS(fd = open(path, O_EVTONLY), "open long path");
	close(fd);

	// Disable policy for thread
	T_ASSERT_POSIX_SUCCESS(setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,
	    IOPOL_SCOPE_THREAD, IOPOL_VFS_SUPPORT_LONG_PATHS_DEFAULT),
	    "[thread: off, proc: on]");

	T_ASSERT_POSIX_SUCCESS(fd = open(path, O_EVTONLY), "open long path");
	close(fd);

	// Disable policy for process
	T_ASSERT_POSIX_SUCCESS(setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,
	    IOPOL_SCOPE_PROCESS, IOPOL_VFS_SUPPORT_LONG_PATHS_DEFAULT),
	    "[thread: off, proc: off]");

	T_ASSERT_POSIX_FAILURE(fd = open(path, O_EVTONLY), ENAMETOOLONG,
	    "ENAMETOOLONG when opening long path");

	free(path);
	removefile(testdir, NULL, REMOVEFILE_RECURSIVE | REMOVEFILE_ALLOW_LONG_PATHS);
	free(testdir);
}

static void
enable_policy(void)
{
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,
	    IOPOL_SCOPE_PROCESS, IOPOL_VFS_SUPPORT_LONG_PATHS_ON),
	    "failed to enable i/o policy");
}

static void
disable_policy(void)
{
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,
	    IOPOL_SCOPE_PROCESS, IOPOL_VFS_SUPPORT_LONG_PATHS_DEFAULT),
	    "failed to disable i/o policy");
}

static size_t pathlengths[] = {
	64,
	NAME_MAX,
	MAXPATHLEN - 1,
	MAXPATHLEN,
	MAXPATHLEN + 1,
	2 * MAXPATHLEN,
	2 * MAXPATHLEN + 64,
	MAXLONGPATHLEN - 1,
	MAXLONGPATHLEN,
	MAXLONGPATHLEN + 1,
	MAXLONGPATHLEN + MAXPATHLEN,
};

// Expected results for syscalls that return status code (0 or < 0)
static int common_errno_off[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ 0,
	/* MAXPATHLEN */ ENAMETOOLONG,
	/* MAXPATHLEN + 1 */ ENAMETOOLONG,
	/* 2 * MAXPATHLEN */ ENAMETOOLONG,
	/* 2 * MAXPATHLEN + 64 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN - 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + MAXPATHLEN */ ENAMETOOLONG,
};

static int common_errno_on[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ 0,
	/* MAXPATHLEN */ 0,
	/* MAXPATHLEN + 1 */ 0,
	/* 2 * MAXPATHLEN */ 0,
	/* 2 * MAXPATHLEN + 64 */ 0,
	/* MAXLONGPATHLEN - 1 */ 0,
	/* MAXLONGPATHLEN */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + MAXPATHLEN */ ENAMETOOLONG,
};

static void
test_access(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	int rc = access(path, F_OK);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_faccessat(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	int rc = faccessat(AT_FDCWD, path, F_OK, 0);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

// F_GETPATH must *not* consider the i/o policy
static int F_GETPATH_errno[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ ENOSPC,
	/* MAXPATHLEN */ ENOSPC,
	/* MAXPATHLEN + 1 */ ENOSPC,
	/* 2 * MAXPATHLEN */ ENOSPC,
	/* 2 * MAXPATHLEN + 64 */ ENOSPC,
	/* MAXLONGPATHLEN - 1 */ ENOSPC,
	/* MAXLONGPATHLEN */ ENOSPC,
	/* MAXLONGPATHLEN + 1 */ ENOSPC,
	/* MAXLONGPATHLEN + MAXPATHLEN */ ENOSPC,
};

static void
test_F_GETPATH(size_t pathlen, bool policy, int expected_errno)
{
	struct stat st;
	char *path = createpath(pathlen, false, &st);

	int fd = openlongpath(path, O_EVTONLY);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "failed to open path %s", path);
	free(path);

	char buf[PATH_MAX];
	int rc = fcntl(fd, F_GETPATH, buf);
	close(fd);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_fstatat(size_t pathlen, bool policy, int expected_errno)
{
	struct stat st;
	char *path = createpath(pathlen, false, NULL);
	int rc = fstatat(AT_FDCWD, path, &st, 0);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_getattrlist_fileID(size_t pathlen, bool policy, int expected_errno)
{
	struct stat st;
	char *path = createpath(pathlen, false, &st);

	struct {
		uint32_t size;
		uint64_t fileID;
	} __attribute__((aligned(4), packed)) buf;

	struct attrlist al = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_FILEID,
	};

	int rc = getattrlist(path, &al, &buf, sizeof(buf), FSOPT_ATTR_CMN_EXTENDED);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_getattrlist_fullpath(size_t pathlen, bool policy, int expected_errno)
{
	char *cwd = getcwd(NULL, 0);
	size_t cwdlen = strlen(cwd);

	if (pathlen + 1 <= cwdlen) {
		// Test dir is longer than pathlen + slash, no sense running the test
		return;
	}

	char *testrelpath = createpath(pathlen - cwdlen - 1, false, NULL); // -1 for the slash
	char *inpath = NULL;
	asprintf(&inpath, "%s/%s", cwd, testrelpath);
	free(cwd);
	free(testrelpath);
	T_QUIET; T_ASSERT_EQ(strlen(inpath), pathlen, CTXSTR);

	struct {
		uint32_t size;
		attrreference_t attr;
		char path[MAXLONGPATHLEN];
	} __attribute__((aligned(4), packed)) buf;

	struct attrlist al = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_FULLPATH,
	};

	int rc = getattrlist(inpath, &al, &buf, sizeof(buf), FSOPT_ATTR_CMN_EXTENDED);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);

		char *retpath = (char *)&buf.attr + buf.attr.attr_dataoffset;
		T_QUIET; T_ASSERT_LT(retpath, (char *)&buf + buf.size, CTXSTR);
		T_QUIET; T_ASSERT_LE(retpath + buf.attr.attr_length, (char *)&buf + buf.size, CTXSTR);
		T_QUIET; T_ASSERT_EQ(strcmp(retpath, inpath), 0, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
	free(inpath);
}

static void
test_getattrlist_relpath(size_t pathlen, bool policy, int expected_errno)
{
	char *cwd = getcwd(NULL, 0);
	size_t cwdlen = strlen(cwd);

	if (pathlen + 1 <= cwdlen) {
		// Test dir is longer than pathlen + slash, no sense running the test
		return;
	}

	struct stat st;
	char *testrelpath = createpath(pathlen - cwdlen - 1, false, &st); // -1 for the slash
	char *inpath = NULL;
	asprintf(&inpath, "%s/%s", cwd, testrelpath);
	free(cwd);
	free(testrelpath);
	T_QUIET; T_ASSERT_EQ(strlen(inpath), pathlen, NULL);

	struct {
		uint32_t size;
		dev_t dev;
		uint64_t fileID;
		attrreference_t attr;
		char path[MAXLONGPATHLEN];
	} __attribute__((aligned(4), packed)) buf;

	struct attrlist al = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_DEVID | ATTR_CMN_FILEID,
		.forkattr = ATTR_CMNEXT_RELPATH,
	};

	int rc = getattrlist(inpath, &al, &buf, sizeof(buf), FSOPT_ATTR_CMN_EXTENDED);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);

		char *retpath = (char *)&buf.attr + buf.attr.attr_dataoffset;
		T_QUIET; T_ASSERT_LT(retpath, (char *)&buf + buf.size, CTXSTR);
		T_QUIET; T_ASSERT_LE(retpath + buf.attr.attr_length, (char *)&buf + buf.size, CTXSTR);
		T_QUIET; T_ASSERT_TRUE(buf.dev == st.st_dev && buf.fileID == st.st_ino, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
	free(inpath);
}

static void
test_getattrlist_nofirmlinkpath(size_t pathlen, bool policy, int expected_errno)
{
#if !TARGET_OS_OSX
	T_QUIET; T_PASS(NULL);
	return;
#else
	char *cwd = getcwd(NULL, 0);
	size_t cwdlen = strlen(cwd);

	struct {
		uint32_t size;
		attrreference_t attr;
		char mtpt[MAXPATHLEN];
	} __attribute__((aligned(4), packed)) mtptbuf;

	struct attrlist mtptal = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.volattr = ATTR_VOL_MOUNTPOINT,
	};
	T_QUIET; T_ASSERT_POSIX_SUCCESS(getattrlist(cwd, &mtptal, &mtptbuf, sizeof(mtptbuf), 0), NULL);

	char *mtpt = (char *)&mtptbuf.attr + mtptbuf.attr.attr_dataoffset;
	size_t mtptlen = strlen(mtpt);

	if (pathlen + 1 <= mtptlen + cwdlen) {
		// Test dir + mount point is longer than pathlen + slash, no sense running the test
		return;
	}

	/*
	 * cwd already has a leading slash, so the -1 below is for the slash that will be put
	 * after cwd when build inpath
	 */
	char *testrelpath = createpath(pathlen - mtptlen - cwdlen - 1, false, NULL);
	char *inpath = NULL;
	asprintf(&inpath, "%s%s/%s", mtpt, cwd, testrelpath);
	free(cwd);
	free(testrelpath);
	T_QUIET; T_ASSERT_EQ(strlen(inpath), pathlen, CTXSTR);

	struct {
		uint32_t size;
		attrreference_t attr;
		char path[MAXLONGPATHLEN];
	} __attribute__((aligned(4), packed)) buf;

	struct attrlist al = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.forkattr = ATTR_CMNEXT_NOFIRMLINKPATH,
	};

	int rc = getattrlist(inpath, &al, &buf, sizeof(buf), FSOPT_ATTR_CMN_EXTENDED);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);

		char *retpath = (char *)&buf.attr + buf.attr.attr_dataoffset;
		T_QUIET; T_ASSERT_LT(retpath, (char *)&buf + buf.size, CTXSTR);
		T_QUIET; T_ASSERT_LE(retpath + buf.attr.attr_length, (char *)&buf + buf.size, CTXSTR);
		T_QUIET; T_ASSERT_EQ(strcmp(retpath, inpath), 0, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
	free(inpath);
#endif /* !TARGET_OS_OSX */
}

static void
test_lstat(size_t pathlen, bool policy, int expected_errno)
{
	struct stat st;
	char *path = createpath(pathlen, false, NULL);
	int rc = lstat(path, &st);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_mkdirat(size_t pathlen, bool policy, int expected_errno)
{
	char *name = "newdir";
	size_t parentlen = pathlen - strlen(name) - 1;
	char *parent = createpath(parentlen, true, NULL);
	char *path = NULL;
	asprintf(&path, "%s/%s", parent, name);

	int rc = mkdirat(AT_FDCWD, path, 0700);
	free(parent);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_open(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	int fd = open(path, O_EVTONLY);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
}

static void
test_open_create(size_t pathlen, bool policy, int expected_errno)
{
	char *name = "newfile";
	size_t parentlen = pathlen - strlen(name) - 1;
	char *parent = createpath(parentlen, true, NULL);
	char *path = NULL;
	asprintf(&path, "%s/%s", parent, name);

	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	free(parent);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
}

static void
test_open_volfs(size_t pathlen, bool policy, int expected_errno)
{
#if !TARGET_OS_OSX
	T_QUIET; T_PASS(NULL);
	return;
#else
	char *cwd = getcwd(NULL, 0);
	size_t cwdlen = strlen(cwd);
	free(cwd);

	if (pathlen + 1 <= cwdlen) {
		// Test dir is longer than pathlen + slash, no sense running the test
		return;
	}
	size_t relpathlen = pathlen - cwdlen - 1; // -1 for the slash

	struct stat st, volst;
	free(createpath(relpathlen, false, &st));

	char *path = NULL;
	asprintf(&path, "/.vol/%d/%llu", st.st_dev, st.st_ino);
	int fd = open(path, O_EVTONLY);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fstat(fd, &volst), CTXSTR);
		T_QUIET; T_ASSERT_TRUE(volst.st_dev == st.st_dev && volst.st_ino == st.st_ino,
		    CTXFMT " dev %d != %d, ino %llu != %llu",
		    CTXARGS, volst.st_dev, st.st_dev, volst.st_ino, st.st_ino);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
#endif /* !TARGET_OS_OSX */
}

static void
test_openat(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	int fd = openat(AT_FDCWD, path, O_EVTONLY);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
}

static void
test_openat_create(size_t pathlen, bool policy, int expected_errno)
{
	char *name = "newfile";
	size_t parentlen = pathlen - strlen(name) - 1;
	char *parent = createpath(parentlen, true, NULL);
	char *path = NULL;
	asprintf(&path, "%s/%s", parent, name);

	int fd = openat(AT_FDCWD, path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	free(parent);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
}

static int openbyid_errno_off[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ ENAMETOOLONG,
	/* MAXPATHLEN */ ENAMETOOLONG,
	/* MAXPATHLEN + 1 */ ENAMETOOLONG,
	/* 2 * MAXPATHLEN */ ENAMETOOLONG,
	/* 2 * MAXPATHLEN + 64 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN - 1 */ EINVAL,
	/* MAXLONGPATHLEN */ EINVAL,
	/* MAXLONGPATHLEN + 1 */ EINVAL,
	/* MAXLONGPATHLEN + MAXPATHLEN */ EINVAL,
};

static int openbyid_errno_on[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ 0,
	/* MAXPATHLEN */ 0,
	/* MAXPATHLEN + 1 */ 0,
	/* 2 * MAXPATHLEN */ 0,
	/* 2 * MAXPATHLEN + 64 */ 0,
	/* MAXLONGPATHLEN - 1 */ EINVAL,
	/* MAXLONGPATHLEN */ EINVAL,
	/* MAXLONGPATHLEN + 1 */ EINVAL,
	/* MAXLONGPATHLEN + MAXPATHLEN */ EINVAL,
};

static void
test_openbyid_np(size_t pathlen, bool policy, int expected_errno)
{
	struct stat st;
	char *path = createpath(pathlen, false, &st);
	free(path);

	fsid_t fsid = {st.st_dev, 0};
	uint64_t fsobjid = st.st_ino;
	int fd = openbyid_np(&fsid, (fsobj_id_t *)&fsobjid, O_EVTONLY);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
}

/*
 * The full paths here are length + strlen("link/") = length + 5
 */
static int path_after_link_errno_off[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ ENAMETOOLONG,
	/* MAXPATHLEN */ ENAMETOOLONG,
	/* MAXPATHLEN + 1 */ ENAMETOOLONG,
	/* 2 * MAXPATHLEN */ ENAMETOOLONG,
	/* 2 * MAXPATHLEN + 64 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN - 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + MAXPATHLEN */ ENAMETOOLONG,
};

static int path_after_link_errno_on[] = {
	/* 64 */ 0,
	/* NAME_MAX */ 0,
	/* MAXPATHLEN - 1 */ 0,
	/* MAXPATHLEN */ 0,
	/* MAXPATHLEN + 1 */ 0,
	/* 2 * MAXPATHLEN */ 0,
	/* 2 * MAXPATHLEN + 64 */ 0,
	/* MAXLONGPATHLEN - 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + 1 */ ENAMETOOLONG,
	/* MAXLONGPATHLEN + MAXPATHLEN */ ENAMETOOLONG,
};

static void
test_path_after_link(size_t remaininglen, bool policy, int expected_errno)
{
	/*
	 * Create path of the form link/... where ... has remaininglen length.
	 */

	T_QUIET; T_ASSERT_POSIX_SUCCESS(mkdir("base", 0700), CTXFMT, remaininglen, onoffstr(policy));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(symlink("base", "link"), CTXFMT, remaininglen, onoffstr(policy));

	chdir("base");
	struct stat origst;
	char *remainingpath = createpath(remaininglen - 1, false, &origst); // -1 for the slash
	chdir("..");

	char *path = NULL;
	asprintf(&path, "link/%s", remainingpath);
	free(remainingpath);

	struct stat st;
	int rc = fstatat(AT_FDCWD, path, &st, 0);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXFMT, remaininglen, onoffstr(policy));
		T_QUIET; T_ASSERT_TRUE(st.st_dev == origst.st_dev && st.st_ino == origst.st_ino,
		    CTXFMT, remaininglen, onoffstr(policy));
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXFMT, remaininglen, onoffstr(policy));
	}
}

static void
test_renameatx_np(size_t pathlen, bool policy, int expected_errno)
{
	char *src = createpath(pathlen, false, NULL);
	char *dst = strdup(src);

	// Change last character in name
	dst[pathlen - 1] = '9';

	int rc = renameatx_np(AT_FDCWD, src, AT_FDCWD, dst, 0);
	free(src);
	free(dst);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_symlink_long2long(size_t pathlen, bool policy, int expected_errno)
{
	char *linkname = "link";
	size_t parentlen = pathlen - strlen(linkname) - 1;
	char *parent = createpath(parentlen, true, NULL);
	char *linkpath = NULL;
	asprintf(&linkpath, "%s/%s", parent, linkname);
	char *targetpath = NULL;
	asprintf(&targetpath, "%s/xpto", parent);
	size_t targetlen = strlen(targetpath);

	int rc = symlink(targetpath, linkpath);
	free(parent);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);

		char *buf = emalloc(targetlen + 1);
		ssize_t linklen;

		T_QUIET; T_ASSERT_POSIX_SUCCESS((linklen = readlink(linkpath, buf, targetlen)), CTXSTR);
		T_QUIET; T_ASSERT_EQ((size_t)linklen, targetlen,
		    CTXFMT " linklen %zd", CTXARGS, (size_t)linklen);
		buf[linklen] = '\0';

		T_QUIET; T_ASSERT_EQ(strcmp(buf, targetpath), 0, CTXSTR);
		free(targetpath);
		free(linkpath);
		free(buf);
	} else {
		free(targetpath);
		free(linkpath);
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_symlink_long2short(size_t pathlen, bool policy, int expected_errno)
{
	char *name = "long-link";
	size_t parentlen = pathlen - strlen(name) - 1;
	char *parent = createpath(parentlen, true, NULL);
	char *path = NULL;
	asprintf(&path, "%s/%s", parent, name);

	char *targetname = "destination.txt";
	size_t targetlen = strlen(targetname);
	int rc = symlink(targetname, path);
	free(parent);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);

		char *buf = emalloc(targetlen + 1);
		ssize_t linklen;

		T_QUIET; T_ASSERT_POSIX_SUCCESS((linklen = readlink(path, buf, targetlen)), CTXSTR);
		T_QUIET; T_ASSERT_EQ((size_t)linklen, targetlen,
		    CTXFMT " linklen %zd", CTXARGS, (size_t)linklen);
		buf[linklen] = '\0';

		T_QUIET; T_ASSERT_EQ(strcmp(buf, targetname), 0, CTXSTR);
		free(path);
		free(buf);
	} else {
		free(path);
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_symlink_short2long(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	int rc = symlink(path, "short-link");

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);

		char *buf = emalloc(pathlen + 1);
		ssize_t linklen;

		T_QUIET; T_ASSERT_POSIX_SUCCESS((linklen = readlink("short-link", buf, pathlen)), CTXSTR);
		T_QUIET; T_ASSERT_EQ((size_t)linklen, pathlen,
		    CTXFMT " linklen %zd", CTXARGS, (size_t)linklen);
		buf[linklen] = '\0';

		T_QUIET; T_ASSERT_EQ(strcmp(buf, path), 0, CTXSTR);
		free(path);
		free(buf);
	} else {
		free(path);
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_symlink_intermediate(size_t pathlen, bool policy, int expected_errno)
{
	/*
	 * Create path with intermediate symlinks so that linked and original paths
	 * are of the same length.
	 */
	char *path = createpath(pathlen, false, NULL);

	// Find parent of path
	char *lastslash = strrchr(path, '/');
	if (lastslash == NULL || lastslash == path) {
		return;
	}

	size_t leaflen = strlen(lastslash + 1);

	char *p = lastslash - 1;
	while (p - 1 != path && *(p - 1) != '/') {
		p--;
	}

	size_t parentlen = (uintptr_t)(lastslash - p);
	char *parentname = emalloc(parentlen + 1);
	memmove(parentname, p, parentlen);
	parentname[parentlen] = '\0';

	// Find grandparent of path, which will be the base path where to create a symlink
	size_t baselen = pathlen - parentlen - 1 - 1 - leaflen;
	char *basepath = emalloc(baselen + 1);
	memmove(basepath, path, baselen);
	basepath[baselen] = '\0';

	// Create symlink
	char *linkname = emalloc(parentlen + 1);
	size_t n = generatename(linkname, parentlen, 49); // repeating Xs
	linkname[n] = '\0';

	char *linkpath = NULL;
	asprintf(&linkpath, "%s/%s", basepath, linkname);
	free(linkname);

	T_QUIET; T_ASSERT_EQ(strlen(linkpath) + 1 + leaflen, pathlen, NULL);

	int rc = symlink(parentname, linkpath);
	free(parentname);

	if (!policy) {
		if (strlen(linkpath) < MAXPATHLEN) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
		} else {
			T_QUIET; T_ASSERT_POSIX_FAILURE(rc, ENAMETOOLONG, CTXSTR);
		}
	} else {
		if (strlen(linkpath) < MAXLONGPATHLEN) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
		} else {
			T_QUIET; T_ASSERT_POSIX_FAILURE(rc, ENAMETOOLONG, CTXSTR);
		}
	}

	char *linkedpath = NULL;
	asprintf(&linkedpath, "%s/%s", linkpath, lastslash + 1);
	T_QUIET; T_ASSERT_EQ(strlen(linkedpath), pathlen, NULL);
	free(linkpath);

	int fd = open(linkedpath, O_EVTONLY);
	free(linkedpath);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(fd, expected_errno, CTXSTR);
	}
	if (fd >= 0) {
		close(fd);
	}
}

static void
test_unlinkat(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	int rc = unlinkat(AT_FDCWD, path, 0);
	free(path);

	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}
}

static void
test_xattr(size_t pathlen, bool policy, int expected_errno)
{
	char *path = createpath(pathlen, false, NULL);
	char *name = "lpattr";
	char *value = "xpto";
	ssize_t valuelen = strlen(value);

	int rc = setxattr(path, name, value, valuelen, 0, XATTR_CREATE);
	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(rc, expected_errno, CTXSTR);
	}

	char *buf = emalloc(valuelen);
	ssize_t attrlen = getxattr(path, name, buf, valuelen, 0, XATTR_CREATE);
	free(path);
	if (expected_errno == 0) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(attrlen, CTXSTR);
		T_QUIET; T_ASSERT_EQ(attrlen, valuelen, CTXSTR);
		T_QUIET; T_ASSERT_EQ(0, memcmp(buf, value, valuelen), CTXSTR);
	} else {
		T_QUIET; T_ASSERT_POSIX_FAILURE(attrlen, expected_errno, CTXSTR);
	}
	free(buf);
}

#define SYSCALL_TEST(name, expected_errno_off, expected_errno_on) \
T_DECL(longpaths_ ## name ## _test, "Test " #name " with long paths") \
{\
	char *testdir = setup_test_dir(#name);\
\
	disable_policy();\
	bool policy = false;\
	for (size_t i = 0; i < nelem(pathlengths); i++) {\
	        size_t pathlen = pathlengths[i];\
	        setup_case_dir(pathlen, policy);\
	        test_ ## name (pathlen, policy, (expected_errno_off)[i]);\
	        chdir("..");\
	}\
\
	enable_policy();\
	policy = true;\
	for (size_t i = 0; i < nelem(pathlengths); i++) {\
	        size_t pathlen = pathlengths[i];\
	        setup_case_dir(pathlen, policy);\
	        test_ ##name (pathlen, policy, (expected_errno_on)[i]);\
	        chdir("..");\
	}\
\
	removefile(testdir, NULL, REMOVEFILE_RECURSIVE | REMOVEFILE_ALLOW_LONG_PATHS);\
	free(testdir);\
}

SYSCALL_TEST(access, common_errno_off, common_errno_on)
SYSCALL_TEST(faccessat, common_errno_off, common_errno_on)
SYSCALL_TEST(fstatat, common_errno_off, common_errno_on)
SYSCALL_TEST(F_GETPATH, F_GETPATH_errno, F_GETPATH_errno)

SYSCALL_TEST(getattrlist_fileID, common_errno_off, common_errno_on)
SYSCALL_TEST(getattrlist_nofirmlinkpath, common_errno_off, common_errno_on)
SYSCALL_TEST(getattrlist_fullpath, common_errno_off, common_errno_on)
SYSCALL_TEST(getattrlist_relpath, common_errno_off, common_errno_on)

SYSCALL_TEST(lstat, common_errno_off, common_errno_on)
SYSCALL_TEST(mkdirat, common_errno_off, common_errno_on)

SYSCALL_TEST(open, common_errno_off, common_errno_on)
SYSCALL_TEST(open_create, common_errno_off, common_errno_on)
SYSCALL_TEST(open_volfs, common_errno_on, common_errno_on)

SYSCALL_TEST(openat, common_errno_off, common_errno_on)
SYSCALL_TEST(openat_create, common_errno_off, common_errno_on)

SYSCALL_TEST(openbyid_np, openbyid_errno_off, openbyid_errno_on)
SYSCALL_TEST(path_after_link, path_after_link_errno_off, path_after_link_errno_on)
SYSCALL_TEST(renameatx_np, common_errno_off, common_errno_on)

SYSCALL_TEST(symlink_intermediate, common_errno_off, common_errno_on)
// Even with the policy on, we should fail when symlinks target long paths
SYSCALL_TEST(symlink_long2long, common_errno_off, common_errno_off)
SYSCALL_TEST(symlink_long2short, common_errno_off, common_errno_on)
SYSCALL_TEST(symlink_short2long, common_errno_off, common_errno_off)

SYSCALL_TEST(unlinkat, common_errno_off, common_errno_on)
SYSCALL_TEST(xattr, common_errno_off, common_errno_on)
