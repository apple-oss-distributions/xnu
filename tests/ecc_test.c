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
    T_META_OWNER("josephb_22"), T_META_OWNER("y_feigelson"),
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
		"-v",
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

static int
run_helper(const char *arg)
{
	printf("\nNow running \"%s\":\n", arg);
	return my_system("./ecc_test_helper", arg);
}

static void
cleanup_after_injections(void)
{
	(void)sysctlbyname("vm.retired_pages_end_test", NULL, NULL, NULL, 0);
}


/*
 * The tests are run in the following order:
 *
 * - call foo (i.e. private TEXT page)
 * - Inject ECC error into foo, then call foo
 *
 * - call atan (i.e. shared TEXT page)
 * - inject ecc error into atan, then call atan
 *
 * atan() was picked as a shared region function that isn't likely used by any normal daemons.
 *
 * - reference to clean DATA page with injected error
 *
 * - reference to dirty DATA page with injected error
 *
 * - reference to clean private anonymous mmap'd page with injected error
 *
 * - reference to dirty private anonymous mmap'd page with injected error
 *
 * - copyout to a page with injected error
 */
static void
test_body(void)
{
	int ret;

	T_ATEND(cleanup_after_injections);

	/*
	 * test of process TEXT page
	 * since the page is not writeable (therefore clean), we expect to recover
	 */
	ret = run_helper("Yfoo");
	T_QUIET; T_ASSERT_EQ(ret, 0, "First call of foo");

	ret = run_helper("Xfoo");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from UE in clean app text page");

	ret = run_helper("Yfoo");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Fixed call of foo");

	/*
	 * test of shared library TEXT page
	 * since the page is not writeable (therefore clean), we expect to recover
	 */
	ret = run_helper("Yatan");
	T_QUIET; T_ASSERT_EQ(ret, 0, "First call of atan");

	ret = run_helper("Xatan");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from UE in clean shared region page");

	ret = run_helper("Yatan");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Fixed call of atan");

	/*
	 * test of clean DATA page
	 * since the page is clean, we expect to recover
	 */
	ret = run_helper("Xclean");
	T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from UE in clean page");

	/*
	 * test of dirty DATA page
	 * since the page is dirty, we expect the app to SIGBUS
	 */
	ret = run_helper("Xdirty");
	T_QUIET; T_ASSERT_NE(ret, 0, "Expected to fail from UE in dirty DATA page");

	/*
	 * test of clean dynamically allocated page
	 * since the page is clean, we expect to recover
	 *
	 * Test is disabled - rdar://124132874 (XNU ECC unit tests - "Xmmap_clean" fails)
	 */
	// ret = run_helper("Xmmap_clean");
	// T_QUIET; T_ASSERT_EQ(ret, 0, "Failed to recover from ECC to clean dynamically allocated page");

	/*
	 * test of dirty dynamically allocated page
	 * since the page is dirty, we expect the app to SIGBUS
	 */
	ret = run_helper("Xmmap_dirty");
	T_QUIET; T_ASSERT_NE(ret, 0, "Expected to fail from UE in dirty dynamically allocated page");

	/*
	 * test of ecc during copyout
	 *
	 * although the page is dirty, the page fault error is handled by failing
	 * the copyout syscall.
	 */
	ret = run_helper("Xcopyout");
	T_QUIET; T_ASSERT_NE(ret, 0, "Uncorrected ECC copyout didn't fail");
}

static void
cleanup_ecc_test(void)
{
	uint value;
	size_t s = sizeof value;

	// Set testing mode back to default(ACC)
	value = 0;
	(void)sysctlbyname("vm.test_ecc_dcs", NULL, NULL, &value, s);

	// Restore side effects to default(enabled)
	value = 1;
	(void)sysctlbyname("vm.test_ecc_sideeffects", NULL, NULL, &value, s);
}

static void
run_test(bool use_dcs)
{
	int err;
	uint value = 0;
	size_t s = sizeof value;

	T_ATEND(cleanup_ecc_test);

	// Set testing mode to ACC(0) or DCS(1)
	value = (uint)use_dcs;
	err = sysctlbyname("vm.test_ecc_dcs", NULL, NULL, &value, s);
	if (err) {
		T_SKIP("Failed to clear dcs mode");
	}

	// Set testing mode to uncorrected.
	value = 0;
	err = sysctlbyname("vm.test_corrected_ecc", NULL, NULL, &value, s);
	if (err) {
		T_SKIP("Failed to set uncorrected mode");
	}

	// Disable side effects for the duration of the test
	value = 0;
	err = sysctlbyname("vm.test_ecc_sideeffects", NULL, NULL, &value, s);
	if (err) {
		T_SKIP("Failed to disable side effects");
	}

	test_body();
}

T_DECL(ecc_uncorrected_test, "test detection and handling of non-fatal ECC uncorrected errors",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false /* TARGET_CPU_ARM64 && TARGET_OS_OSX */) /* rdar://133461215 */,
    T_META_REQUIRES_SYSCTL_EQ("vm.retired_pages_end_test", 0),
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_test(false);
}

/* DCS injection was fixed but then broke again..
 * Waiting on rdar://115998013 (WRDIS_DRAM_RAS_ERR needs to be disabled for dev fused units)
 */
#if 0
T_DECL(dcs_uncorrected_test, "test detection and handling from non-fatal ECC uncorrected errors (injected via DCS)",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(TARGET_CPU_ARM64 && TARGET_OS_OSX),
    T_META_REQUIRES_SYSCTL_EQ("vm.retired_pages_end_test", 0), T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_test(true);
}
#endif
