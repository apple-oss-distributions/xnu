/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o getattrlist_fullpath getattrlist_fullpath.c -g -Weverything */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/attr.h>
#include <System/sys/fsgetpath.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define MAXLONGPATHLEN 4096

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("vfs"),
	T_META_ASROOT(false),
	T_META_CHECK_LEAKS(false));

static char *
fast_realpath(const char *path, unsigned int flags)
{
	struct {
		uint32_t        size;
		attrreference_t fullPathAttr;
		char            fullPathBuf[MAXLONGPATHLEN];
	} __attribute__((aligned(4), packed)) buf;

	struct attrlist al = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_FULLPATH,
	};

	if (getattrlist(path, &al, &buf, sizeof(buf), FSOPT_ATTR_CMN_EXTENDED | flags) < 0) {
		return NULL;
	}

	return strdup((char *)&buf.fullPathAttr + buf.fullPathAttr.attr_dataoffset);
}

static void
test_realpath(char *input, unsigned int flags, char *output)
{
	T_ASSERT_EQ_STR(fast_realpath(input, flags), output, "Testing input '%s' (0x%x), output '%s'", input, flags, output);
}

T_DECL(getattrlist_fullpath,
    "getattrlist ATTR_CMN_FULLPATH should preserve input path prefix in output")
{
	test_realpath("/private/etc/hosts", FSOPT_NOFOLLOW, "/private/etc/hosts");
	test_realpath("/etc/hosts", FSOPT_NOFOLLOW, "/private/etc/hosts");

	/* Test for .nofollow prefix */
	test_realpath("/.nofollow/etc/hosts", FSOPT_NOFOLLOW, NULL);
	test_realpath("/.nofollow/private/etc/hosts", FSOPT_NOFOLLOW, "/.nofollow/private/etc/hosts");

	/* Test for RESOLVE_NOFOLLOW_ANY resolve prefix */
	test_realpath("/.resolve/1/etc/hosts", FSOPT_NOFOLLOW, NULL);
	test_realpath("/.resolve/1/private/etc/hosts", FSOPT_NOFOLLOW, "/.resolve/1/private/etc/hosts");
}

T_DECL(getattrlist_fullpath_firmlinks,
    "getattrlist ATTR_CMN_FULLPATH with FSOPT_AUTOFIRMLINKPATH",
    T_META_ENABLED(TARGET_OS_OSX)) // test relies on macOS /System/Volumes/Data firmlink path
{
	remove("/tmp/symlinktoroot");
	T_ASSERT_POSIX_SUCCESS(symlink("/", "/tmp/symlinktoroot"), "create symlink to /");

	char *firmlink_path = fast_realpath("/private", 0);
	T_ASSERT_EQ_STR(firmlink_path, "/private", "/private firmlink path should be /private");

	char *nofirmlink_path = fast_realpath("/private", FSOPT_NOFIRMLINKPATH);
	T_ASSERT_EQ_STR(nofirmlink_path, "/System/Volumes/Data/private", "/private nofirmlink path should be /System/Volumes/Data/private");

	test_realpath("/private", FSOPT_AUTOFIRMLINKPATH, firmlink_path);
	test_realpath("/System/Volumes/Data/private", FSOPT_AUTOFIRMLINKPATH, nofirmlink_path);

	test_realpath("/tmp/symlinktoroot/private", FSOPT_AUTOFIRMLINKPATH, firmlink_path);
	test_realpath("/tmp/symlinktoroot/System/Volumes/Data/private", FSOPT_AUTOFIRMLINKPATH, nofirmlink_path);

	test_realpath("/System/Volumes/Data/private/tmp/symlinktoroot/private", FSOPT_AUTOFIRMLINKPATH, firmlink_path);
	test_realpath("/System/Volumes/Data/private/tmp/symlinktoroot/System/Volumes/Data/private", FSOPT_AUTOFIRMLINKPATH, nofirmlink_path);

	remove("/tmp/symlinktoroot");
}
