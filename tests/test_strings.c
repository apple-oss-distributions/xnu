#define _FORTIFY_SOURCE 0
#define __arch_memcmp_zero_ptr_aligned

/* must include first because otherwise header guard conflicts with SDK's
 * string.h (quite reasonably)
 */
#include "../osfmk/libsa/string.h"

char *strerror(int);
char *itoa(int, char *);

#include <darwintest.h>
#include <darwintest_utils.h>

#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wformat-pedantic"

#define DEVELOPMENT 0
#define DEBUG 0
#define XNU_KERNEL_PRIVATE 1

__printflike(1, 2) __attribute__((noreturn))
static void
panic(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	abort();
}

#include "../libkern/libkern/section_keywords.h"
#include "../osfmk/machine/string.h"
#include "../osfmk/device/subrs.c"

#pragma clang diagnostic ignored "-Wdeclaration-after-statement"
#pragma clang diagnostic ignored "-Wgnu-designator"

T_DECL(strbufcmp, "strbufcmp") {
#define T_COMPARE(A, AS, B, BS, EQ) T_ASSERT_EQ(strbufcmp_impl((A), (AS), (B), (BS)), (EQ), "compare '%s'.%zu, '%s'.%zu", (A), (AS), (B), (BS))
	// two identical strings
	char a[] = "hello";
	char b[] = "hello";
	T_COMPARE(a, sizeof(a), b, sizeof(b), 0);
	T_COMPARE(b, sizeof(b), a, sizeof(a), 0);

	// the same string
	T_COMPARE(a, sizeof(a), b, sizeof(b), 0);
	T_COMPARE(b, sizeof(b), a, sizeof(a), 0);

	// two different strings
	char c[] = "world";
	T_COMPARE(a, sizeof(a), c, sizeof(c), a[0] - c[0]);
	T_COMPARE(c, sizeof(c), a, sizeof(a), c[0] - a[0]);
	char d[] = "hellp";
	T_COMPARE(a, sizeof(a), d, sizeof(d), 'o' - 'p');
	T_COMPARE(d, sizeof(d), a, sizeof(a), 'p' - 'o');

	// strings of different size
	char e[] = "aaaa";
	char f[] = "aaaab";
	T_COMPARE(e, sizeof(e), f, sizeof(f), 0 - 'b');
	T_COMPARE(f, sizeof(f), e, sizeof(e), 'b' - 0);

	// strings that are not NUL-terminated
	T_COMPARE(a, sizeof(a) - 1, b, sizeof(b) - 1, 0);
	T_COMPARE(b, sizeof(b) - 1, a, sizeof(a) - 1, 0);
	T_COMPARE(a, sizeof(a) - 1, d, sizeof(d) - 1, 'o' - 'p');
	T_COMPARE(d, sizeof(d) - 1, a, sizeof(a) - 1, 'p' - 'o');
	T_COMPARE(e, sizeof(e) - 1, f, sizeof(f) - 1, 0 - 'b');
	T_COMPARE(f, sizeof(f) - 1, e, sizeof(e) - 1, 'b' - 0);
#undef T_COMPARE
}

T_DECL(strlcmp, "strlcmp") {
#define T_COMPARE(A, AS, B, EQ) T_ASSERT_EQ(strlcmp_impl((A), (B), (AS)), (EQ), "compare '%s'.%zu, '%s'", (A), (AS), (B))
	// two identical strings
	char a[] = "hello";
	char b[] = "hello";
	T_COMPARE(a, sizeof(a), b, 0);
	T_COMPARE(b, sizeof(b), a, 0);

	// the same string
	T_COMPARE(a, sizeof(a), b, 0);
	T_COMPARE(b, sizeof(b), a, 0);

	// two different strings
	char c[] = "world";
	T_COMPARE(a, sizeof(a), c, a[0] - c[0]);
	T_COMPARE(c, sizeof(c), a, c[0] - a[0]);
	char d[] = "hellp";
	T_COMPARE(a, sizeof(a), d, 'o' - 'p');
	T_COMPARE(d, sizeof(d), a, 'p' - 'o');

	// strings of different size
	char e[] = "aaaa";
	char f[] = "aaaab";
	T_COMPARE(e, sizeof(e), f, 0 - 'b');
	T_COMPARE(f, sizeof(f), e, 'b' - 0);

	// strings that are not NUL-terminated
	T_COMPARE(a, sizeof(a) - 1, b, 0);
	T_COMPARE(b, sizeof(b) - 1, a, 0);
	T_COMPARE(a, sizeof(a) - 1, d, 'o' - 'p');
	T_COMPARE(d, sizeof(d) - 1, a, 'p' - 'o');
	T_COMPARE(e, sizeof(e) - 1, f, 0 - 'b');
	T_COMPARE(f, sizeof(f) - 1, e, 'b' - 0);
#undef T_COMPARE
}

T_DECL(strbufcasecmp, "strbufcasecmp") {
#define T_COMPARE(A, AS, B, BS, EQ) T_ASSERT_EQ(strbufcasecmp_impl((A), (AS), (B), (BS)), (EQ), "case-insensitive compare '%s'.%zu, '%s'.%zu", (A), (AS), (B), (BS))
	// same tests as strcasecmp, then tests with individual characters
	// two identical strings
	char a[] = "hElLo";
	char b[] = "HeLlO";
	T_COMPARE(a, sizeof(a), b, sizeof(b), 0);
	T_COMPARE(b, sizeof(b), a, sizeof(a), 0);

	// the same string
	T_COMPARE(a, sizeof(a), b, sizeof(b), 0);
	T_COMPARE(b, sizeof(b), a, sizeof(a), 0);

	// two different strings
	char c[] = "world";
	T_COMPARE(a, sizeof(a), c, sizeof(c), a[0] - c[0]);
	T_COMPARE(c, sizeof(c), a, sizeof(a), c[0] - a[0]);
	char d[] = "hellp";
	T_COMPARE(a, sizeof(a), d, sizeof(d), 'o' - 'p');
	T_COMPARE(d, sizeof(d), a, sizeof(a), 'p' - 'o');

	// strings of different size
	char e[] = "aAaA";
	char f[] = "AaAaB";
	T_COMPARE(e, sizeof(e), f, sizeof(f), 0 - 'b');
	T_COMPARE(f, sizeof(f), e, sizeof(e), 'b' - 0);

	// strings that are not NUL-terminated
	T_COMPARE(a, sizeof(a) - 1, b, sizeof(b) - 1, 0);
	T_COMPARE(b, sizeof(b) - 1, a, sizeof(a) - 1, 0);
	T_COMPARE(a, sizeof(a) - 1, d, sizeof(d) - 1, 'o' - 'p');
	T_COMPARE(d, sizeof(d) - 1, a, sizeof(a) - 1, 'p' - 'o');
	T_COMPARE(e, sizeof(e) - 1, f, sizeof(f) - 1, 0 - 'b');
	T_COMPARE(f, sizeof(f) - 1, e, sizeof(e) - 1, 'b' - 0);
#undef T_COMPARE
}

T_DECL(strlcasecmp, "strlcasecmp") {
#define T_COMPARE(A, AS, B, EQ) T_ASSERT_EQ(strlcasecmp_impl((A), (B), (AS)), (EQ), "case-insensitive compare '%s'.%zu, '%s'", (A), (AS), (B))
	// same tests as strcasecmp, then tests with individual characters
	// two identical strings
	char a[] = "hElLo";
	char b[] = "HeLlO";
	T_COMPARE(a, sizeof(a), b, 0);
	T_COMPARE(b, sizeof(b), a, 0);

	// the same string
	T_COMPARE(a, sizeof(a), b, 0);
	T_COMPARE(b, sizeof(b), a, 0);

	// two different strings
	char c[] = "world";
	T_COMPARE(a, sizeof(a), c, a[0] - c[0]);
	T_COMPARE(c, sizeof(c), a, c[0] - a[0]);
	char d[] = "hellp";
	T_COMPARE(a, sizeof(a), d, 'o' - 'p');
	T_COMPARE(d, sizeof(d), a, 'p' - 'o');

	// strings of different size
	char e[] = "aAaA";
	char f[] = "AaAaB";
	T_COMPARE(e, sizeof(e), f, 0 - 'b');
	T_COMPARE(f, sizeof(f), e, 'b' - 0);

	// strings that are not NUL-terminated
	T_COMPARE(a, sizeof(a) - 1, b, 0);
	T_COMPARE(b, sizeof(b) - 1, a, 0);
	T_COMPARE(a, sizeof(a) - 1, d, 'o' - 'p');
	T_COMPARE(d, sizeof(d) - 1, a, 'p' - 'o');
	T_COMPARE(e, sizeof(e) - 1, f, 0 - 'b');
	T_COMPARE(f, sizeof(f) - 1, e, 'b' - 0);
#undef T_COMPARE
}

T_DECL(strbufcasecmp_all, "strbufcasecmp_all") {
#define T_CHAR_COMPARE(A, AS, B, BS, EQ) do { \
    int r = strbufcasecmp_impl((A), (AS), (B), (BS)); \
    if (r != (EQ)) T_FAIL("case-insensitive compare '0x%02hhx' to '0x%02hhx' was %i instead of %i", *(A), *(B), r, (EQ)); \
} while (0)
	// test each character
	char ga, gb, ha, hb;
	char nul = 0;
	for (int i = 0; i < 256; ++i) {
		ga = (char)(i);
		gb = (i >= 'A' && i <= 'Z') ? (char)(i - 'A' + 'a') : ga;
		T_CHAR_COMPARE(&ga, 1, &nul, 0, gb);
		T_CHAR_COMPARE(&nul, 0, &ga, 1, -gb);

		for (int j = 0; j < 256; ++j) {
			ha = (char)(j);
			hb = (j >= 'A' && j <= 'Z') ? (char)(j - 'A' + 'a') : ha;
			T_CHAR_COMPARE(&ga, 1, &ha, 1, gb - hb);
			T_CHAR_COMPARE(&ha, 1, &ga, 1, hb - gb);
		}
	}
	T_PASS("ASCII character case insensitivity");
}

T_DECL(strbufcpy, "strbufcpy") {
	char dst[32];
	// empty dest
	T_ASSERT_EQ(strbufcpy_impl(NULL, 0, "hello", 5), NULL, "0-length destination");

#define T_CPY(A, AS, B, BS) T_ASSERT_EQ(strbufcpy_impl((A), (AS), (B), (BS)), (char *)(A), "copy '%.*s'.%zu to dst.%zu", (int)(BS), (B), (size_t)(BS), (AS))
	// copy NUL terminated string that fits in dst
	char hello[] = "hello";
	memset(dst, 0, sizeof(dst));
	T_CPY(dst, sizeof(dst), hello, sizeof(hello));
	T_ASSERT_EQ(memcmp_impl(dst, (char[32]){"hello"}, sizeof(dst)), 0, "check result is 'hello'");

	// copy NUL terminated string that does not fit in dst
	char aaa[40] = {[0 ... 38] = 'a' };
	memset(dst, 0, sizeof(dst));
	T_CPY(dst, sizeof(dst), aaa, sizeof(aaa));
	T_ASSERT_EQ(memcmp_impl(aaa, dst, 31), 0, "check result is 'aaaaaa...'");
	T_ASSERT_EQ(dst[31], 0, "check result is NUL-terminated");

	// copy non-terminated string
	memset(dst, 0xff, sizeof(dst));
	T_CPY(dst, sizeof(dst), "bbb", 3);
	T_ASSERT_EQ(strcmp_impl(dst, "bbb"), 0, "check result is 'bbb'");

	// copy string over itself
	char hw1[32] = "hello world";
	T_CPY(hw1 + 6, sizeof(hw1) - 6, hw1, sizeof(hw1));
	T_ASSERT_EQ(strcmp_impl(hw1, "hello hello world"), 0, "check copy over self is 'hello hello world'");

	char hw2[32] = "hello world";
	T_CPY(hw2, sizeof(hw2), hw2 + 6, sizeof(hw2) - 6);
	T_ASSERT_EQ(strcmp_impl(hw2, "world"), 0, "check copy over self is 'world'");
#undef T_CPY
}

T_DECL(strbufcat, "strbufcat") {
	char dst[32] = {0};

	// empty dst
	T_ASSERT_EQ(strbufcat_impl(NULL, 0, "hello", 5), NULL, "check concatenation to 0-length destination");

#define T_CAT_RESULT(RESULT) \
    T_ASSERT_EQ(strcmp_impl(dst, (RESULT)), 0, "check result of concatenation is '%s'", (RESULT)); \

#define T_CAT(TO_CAT, RESULT) do { \
    T_ASSERT_EQ(strbufcat_impl(dst, sizeof(dst), (TO_CAT), sizeof(TO_CAT)), (char *)dst, "check concatenation of '%s'", (TO_CAT)); \
    T_CAT_RESULT(RESULT); \
} while (0)

	// append "hello "
	T_CAT("hello ", "hello ");

	// append "world!"
	T_CAT("world!", "hello world!");

	// append itself
	T_ASSERT_EQ(strbufcat_impl(dst, sizeof(dst), dst, sizeof(dst)), (char *)dst, "check concatenating self");
	T_CAT_RESULT("hello world!hello world!");

	// append bunch of 'a's
	T_ASSERT_EQ(strbufcat_impl(dst, sizeof(dst), "aaaaaaaaaa", 10), (char *)dst, "check concatenating 'aaaa...'");
	T_CAT_RESULT("hello world!hello world!aaaaaaa");

#undef T_CAT
#undef T_CAT_RESULT
}

T_DECL(libsa_overloads, "libsa_overloads") {
	char buf[32] = "hello, world";
	char buf2[32] = "world, hello";

	T_ASSERT_EQ(strbuflen(buf), (size_t)12, "strbuflen one argument");
	T_ASSERT_EQ(strbuflen(buf, sizeof(buf)), (size_t)12, "strbuflen two arguments");

	T_ASSERT_LT(strbufcmp(buf, buf2), 0, "strbufcmp two arguments");
	T_ASSERT_LT(strbufcmp(buf, sizeof(buf), buf2, sizeof(buf2)), 0, "strbufcmp four arguments");

	T_ASSERT_LT(strbufcasecmp(buf, buf2), 0, "strbufcasecmp two arguments");
	T_ASSERT_LT(strbufcasecmp(buf, sizeof(buf), buf2, sizeof(buf2)), 0, "strbufcasecmp four arguments");

	T_ASSERT_NE(strbufcpy(buf, buf2), NULL, "strbufcpy two arguments");
	T_ASSERT_NE(strbufcpy(buf, sizeof(buf), buf2, sizeof(buf2)), NULL, "strbufcpy four arguments");

	T_ASSERT_NE(strbufcat(buf, buf2), NULL, "strbufcat two arguments");
	T_ASSERT_NE(strbufcat(buf, sizeof(buf), buf2, sizeof(buf2)), NULL, "strbufcat four arguments");
}
