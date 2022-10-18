#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include <darwintest.h>
#include <darwintest_utils.h>

/*
 * We're going to inject ECC errors into shared library text, so don't
 * run with other tests.
 */
T_GLOBAL_META(T_META_RUN_CONCURRENTLY(false),
    T_META_OWNER("josephb_22"),
    T_META_NAMESPACE("xnu.vm"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("VM"));

/*
 * No system(3c) on watchOS, so provide our own.
 * returns -1 if fails to run
 * returns 0 if process exits normally.
 * returns +n if process exits due to signal N
 */
static int
my_system(const char *command, const char *arg)
{
	pid_t pid;
	int status = 0;
	int signal = 0;
	int ret;
	const char *argv[] = {
		command,
		/* "-v",           uncomment if debugging the tests */
		arg,
		NULL
	};

	if (dt_launch_tool(&pid, (char **)(void *)argv, FALSE, NULL, NULL)) {
		return -1;
	}

	ret = dt_waitpid(pid, &status, &signal, 100);
	if (signal != 0) {
		return signal;
	} else if (status != 0) {
		return status;
	}
	return 0;
}


/*
 * The tests are run in the following order:
 *
 * - call foo (i.e. private text page)
 * - Inject ECC error into foo, then call foo
 *
 * - call atan (i.e. shared text page)
 * - inject ecc error into atan, then call atan
 *
 * atan() was picked as a shared region function that isn't likely used by any normal daemons.
 *
 * - reference to clean data page
 * - reference to clean data page with injected error
 *
 * - reference to dirty data page
 * - reference to dirty data page with injected error
 *
 * - copyout to page
 * - copyout to a page with injected error
 */
static void
test_body(bool corrected)
{
	int ret;

	/*
	 * test of process text page
	 */
	ret = my_system("./ecc_test_helper", "foo");
	T_QUIET; T_ASSERT_EQ(ret, 0, "First call of foo");

	ret = my_system("./ecc_test_helper", "Xfoo");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from ECC to clean app text page");

	ret = my_system("./ecc_test_helper", "foo");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Fixed call of foo");

	/*
	 * test of shared library text page
	 */
	ret = my_system("./ecc_test_helper", "atan");
	T_QUIET; T_ASSERT_EQ(ret, 0, "First call of atan");

	ret = my_system("./ecc_test_helper", "Xatan");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from ECC to clean shared region page");

	ret = my_system("./ecc_test_helper", "atan");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Fixed call of atan");

	/*
	 * test of clean data page
	 */
	ret = my_system("./ecc_test_helper", "clean");
	T_QUIET; T_ASSERT_EQ(ret, 0, "First call of clean");

	ret = my_system("./ecc_test_helper", "Xclean");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from ECC to clean page");

	ret = my_system("./ecc_test_helper", "clean");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Fixed call of clean");

	/*
	 * test of dirty data page
	 */
	ret = my_system("./ecc_test_helper", "Xdirty");
	if (corrected) {
		T_QUIET; T_ASSERT_EQ(ret, 0, "Corrected ECC read of dirty failed");
	} else {
		T_QUIET; T_ASSERT_NE(ret, 0, "Read of Uncorrected ECC dirty data didn't fail");
	}

	/*
	 * test of ecc during copyout
	 */
	ret = my_system("./ecc_test_helper", "Xcopyout");
	if (corrected) {
		T_QUIET; T_ASSERT_EQ(ret, 0, "Corrected ECC copyout failed");
	} else {
		T_QUIET; T_ASSERT_NE(ret, 0, "Uncorrected ECC copyout didn't fail"); /* not recoverable */
	}
}

T_DECL(ecc_uncorrected_test, "test detection/recovery from ECC uncorrected errors",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(FALSE))  /* once other support lands, change to T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX) */
{
	int err;
	uint value = 0;
	size_t s = sizeof value;

	/*
	 * Only run on systems which support retired pages.
	 */
	err = sysctlbyname("vm.retired_pages_count", &value, &s, NULL, 0);
	if (err) {
		T_SKIP("ECC not supported");
	}

	/*
	 * Set testing mode to uncorrected.
	 */
	value = 0;
	err = sysctlbyname("vm.test_corrected_ecc", NULL, NULL, &value, s);
	if (err) {
		T_SKIP("Failed to set uncorrected mode");
	}

	test_body(false);
}

T_DECL(ecc_corrected_test, "test detection/recovery from ECC corrected errors",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(FALSE))  /* once other support lands, change to T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX) */
{
	int err;
	uint value = 0;
	size_t s = sizeof value;

	/*
	 * Only run on systems which support retired pages.
	 */
	err = sysctlbyname("vm.retired_pages_count", &value, &s, NULL, 0);
	if (err) {
		T_SKIP("ECC not supported");
	}

	/*
	 * Set testing mode to corrected.
	 */
	value = 1;
	err = sysctlbyname("vm.test_corrected_ecc", NULL, NULL, &value, s);
	if (err) {
		T_SKIP("Failed to set corrected mode");
	}

	test_body(true);
}
