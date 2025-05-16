/* compile: xcrun -sdk macosx.internal clang -ldarwintest -o getattrlist_fullpath getattrlist_fullpath.c -g -Weverything */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/attr.h>

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
fast_realpath(const char *path, bool follow)
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

	unsigned int options = FSOPT_ATTR_CMN_EXTENDED;
	if (!follow) {
		options |= FSOPT_NOFOLLOW;
	}

	if (getattrlist(path, &al, &buf, sizeof(buf), options) < 0) {
		return NULL;
	}

	return strdup((char *)&buf.fullPathAttr + buf.fullPathAttr.attr_dataoffset);
}

static void
test_realpath(char *input, char *output)
{
	T_ASSERT_EQ_STR(fast_realpath(input, false), output, "Testing input '%s', output '%s'", input, output);
}

T_DECL(getattrlist_fullpath,
    "getattrlist ATTR_CMN_FULLPATH should preserve input path prefix in output")
{
	test_realpath("/private/etc/hosts", "/private/etc/hosts");
	test_realpath("/etc/hosts", "/private/etc/hosts");

	/* Test for .nofollow prefix */
	test_realpath("/.nofollow/etc/hosts", NULL);
	test_realpath("/.nofollow/private/etc/hosts", "/.nofollow/private/etc/hosts");

	/* Test for RESOLVE_NOFOLLOW_ANY resolve prefix */
	test_realpath("/.resolve/1/etc/hosts", NULL);
	test_realpath("/.resolve/1/private/etc/hosts", "/.resolve/1/private/etc/hosts");
}
