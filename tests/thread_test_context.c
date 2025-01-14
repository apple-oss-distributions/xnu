#include <darwintest.h>
#include <darwintest_utils.h>
#include <test_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.misc"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_CHECK_LEAKS(false),
	T_META_OWNER("gparker"));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(thread_test_context,
    "infrastructure for threads running kernel tests",
    XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL)
{
	int64_t bad_line = run_sysctl_test("thread_test_context", 0);
	/* return value is one or two line numbers in thread.c */
	int64_t bad_line_2 = bad_line >> 32;
	bad_line = (bad_line << 32) >> 32;

	if (bad_line_2) {
		T_FAIL("error at osfmk/kern/thread.c:%lld from thread.c:%lld",
		    bad_line_2, bad_line);
	} else if (bad_line) {
		T_FAIL("error at osfmk/kern/thread.c:%lld",
		    bad_line);
	} else {
		T_PASS("thread_test_context");
	}
}
