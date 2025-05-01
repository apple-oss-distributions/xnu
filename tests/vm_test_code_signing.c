#include <darwintest.h>
#include <darwintest_utils.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

#include <sys/stat.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

static int expected_code = 0;
static int panic_on_unsigned_orig = 0;

static void *
get_sysctl_value_byname(const char *name, size_t *len)
{
	int rc = -1;
	char *val = NULL;
	size_t val_len = 0;

	rc = sysctlbyname(name, NULL, &val_len, NULL, 0);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(rc, "retrieve sysctl length");
	if (T_RESULT == T_RESULT_FAIL) {
		return NULL;
	}

	T_WITH_ERRNO;
	val = malloc(val_len);
	T_QUIET;
	T_EXPECT_NOTNULL(val, "malloc fail for sysctl value");
	if (T_RESULT == T_RESULT_FAIL) {
		return NULL;
	}

	rc = sysctlbyname(name, (void *)val, &val_len, NULL, 0);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(rc, "retrieve sysctl byname");
	if (T_RESULT == T_RESULT_FAIL) {
		return NULL;
	} else {
		*len = val_len;
		return (void *)val;
	}
}

static bool
cs_enforcement_disabled(void)
{
	int *cs_enforcement = NULL;
	size_t sysctl_val_len = 0;
	bool cs_enforcement_disable = false;

	cs_enforcement = (int *)get_sysctl_value_byname("vm.cs_process_enforcement", &sysctl_val_len);
	T_EXPECT_NOTNULL(cs_enforcement, "sysctl vm.cs_process_enforcement");
	if (T_RESULT == T_RESULT_FAIL) {
		goto bail;
	}

	cs_enforcement_disable = (*cs_enforcement == 0);

bail:
	if (cs_enforcement) {
		free(cs_enforcement);
	}

	return cs_enforcement_disable;
}

static bool
pmap_cs_enabled(void)
{
	const char *unavailable_reason = "<unknown>";
	char *kern_version = NULL;
	char *bootargs = NULL;
	bool platform_arm64 = false;
	bool platform_macos = false;
	bool pmap_cs_enabled = false;
	size_t sysctl_val_len = 0;
	unsigned long i;

#if TARGET_CPU_ARM64
	platform_arm64 = true;
#endif

	if (platform_arm64 == false) {
		unavailable_reason = "not supported on Intel platform";
		goto exit;
	}

#if TARGET_OS_OSX
	platform_macos = true;
#endif

	if (platform_macos == true) {
		unavailable_reason = "not supported on macOS";
		goto exit;
	}

	/* PMAP_CS technology is not present on below SoCs */
	const char *pmap_cs_absent_platforms[] = {"T7000", "T7001", "S8000", "S8001", "S8003", "T8002", "T8004"};

	kern_version = (char *)get_sysctl_value_byname("kern.version", &sysctl_val_len);
	T_EXPECT_NOTNULL(kern_version, "sysctl kern.version(%s)", kern_version);
	if (T_RESULT == T_RESULT_FAIL) {
		unavailable_reason = "unable to query sysctl kern.version";
		goto exit;
	}

	for (i = 0; i < sizeof(pmap_cs_absent_platforms) / sizeof(pmap_cs_absent_platforms[0]); i++) {
		if (strstr(kern_version, pmap_cs_absent_platforms[i])) {
			unavailable_reason = "not supported on this SoC platform";
			goto exit;
		}
	}

	/*
	 * If we reach this point, it means the platform kernel has PMAP_CS code present. However
	 * the code is disabled by default on certain SoCs. Moreover, the code can be disabled
	 * through an explicit boot-arg as well.
	 */

	bootargs = (char *)get_sysctl_value_byname("kern.bootargs", &sysctl_val_len);
	T_EXPECT_NOTNULL(bootargs, "sysctl kern.bootargs(%s)", bootargs);
	if (T_RESULT == T_RESULT_FAIL) {
		unavailable_reason = "unable to query sysctl kern.bootargs";
		goto exit;
	}

	/* Disabled explicitly through boot-arg */
	if (strstr(bootargs, "pmap_cs=0")) {
		unavailable_reason = "disabled by explicit pmap_cs=0 boot-arg";
		goto exit;
	}

	/* PMAP_CS technology is disabled by default on below SoCs */
	const char *pmap_cs_disabled_platforms[] = {"T8010", "T8011", "T8012", "T8015"};

	for (i = 0; i < sizeof(pmap_cs_disabled_platforms) / sizeof(pmap_cs_disabled_platforms[0]); i++) {
		if (strstr(kern_version, pmap_cs_disabled_platforms[i]) && !strstr(bootargs, "pmap_cs=1")) {
			unavailable_reason = "disabled by default on this SoC platform";
			goto exit;
		}
	}

	/* If we reach here, it means PMAP_CS is enabled */
	pmap_cs_enabled = true;

exit:
	if (bootargs) {
		free(bootargs);
	}

	if (kern_version) {
		free(kern_version);
	}

	if (pmap_cs_enabled == false) {
		T_LOG("INFO: PMAP_CS is either not available or is disabled on this platform: %s", unavailable_reason);
	}
	return pmap_cs_enabled;
}

static bool
pmap_cs_unsigned_pages_allowed(void)
{
	char *bootargs = NULL;
	bool pmap_cs_unsigned_pages_allow = false;
	size_t sysctl_val_len = 0;

	bootargs = (char *)get_sysctl_value_byname("kern.bootargs", &sysctl_val_len);
	T_EXPECT_NOTNULL(bootargs, "sysctl kern.bootargs(%s)", bootargs);
	if (T_RESULT == T_RESULT_FAIL) {
		goto exit;
	}

	/*
	 * Checking for boot-args can be tricky, since `strstr` will return based on the
	 * first match for the boot-arg.
	 *
	 * For example: boot-args="pmap_cs_unrestrict_pmap_cs_disable=1 pmap_cs_unrestrict_pmap_cs_disable=0"
	 * The following code will only catch the first one, and believe the boot-arg is set, even though
	 * the kernel will parse both, and consider the latter as the actual value.
	 *
	 * This can be potentially fixed with `strrstr`, but that isn't standard in the C library,
	 * so we don't use it.
	 */

	if (strstr(bootargs, "pmap_cs_unrestrict_pmap_cs_disable=1")) {
		pmap_cs_unsigned_pages_allow = true;
		goto exit;
	} else if (strstr(bootargs, "amfi=1") || strstr(bootargs, "amfi=3") || strstr(bootargs, "amfi=-1")) {
		/* Any of these boot-args enable pmap_cs_unrestrict_pmap_cs_disable, but it can be overridden */
		if (!strstr(bootargs, "pmap_cs_unrestrict_pmap_cs_disable=0")) {
			/* Boot-arg is NOT overridden, so PMAP_CS will allow unsigned pages */
			pmap_cs_unsigned_pages_allow = true;
			goto exit;
		}
	}

	if (strstr(bootargs, "pmap_cs_allow_modified_code_pages=1")) {
		pmap_cs_unsigned_pages_allow = true;
		goto exit;
	} else if (cs_enforcement_disabled()) {
		/* cs_enforcement_disable enables pmap_cs_allow_modified_code_pages, but it can be overridden */
		if (!strstr(bootargs, "pmap_cs_allow_modified_code_pages=0")) {
			/* Boot-arg is NOT overridden, so PMAP_CS will allow unsigned pages */
			pmap_cs_unsigned_pages_allow = true;
			goto exit;
		}
	}

exit:
	if (bootargs) {
		free(bootargs);
	}

	return pmap_cs_unsigned_pages_allow;
}

static void
pre_test(void)
{
	bool end_test = false;
	int *panic_on_unsigned = NULL;
	size_t sysctl_val_len = 0;

	/* When the test helper executes unsigned code, it returns a 1 */
	expected_code = 1;

	if (pmap_cs_enabled()) {
		/*
		 * When PMAP_CS is enabled, VM layer delegates all executable code signing enforcement
		 * to it, and doesn't participate in executable code validation. If PMAP_CS isn't allowing
		 * unsigned code pages to execute, then we expect a SIGBUS error from the helper.
		 */
		if (!pmap_cs_unsigned_pages_allowed()) {
			expected_code = 10;
		} else {
			T_LOG("WANRING: PMAP_CS is present but allowing unsigned code pages");
		}
	} else {
		/*
		 * When PMAP_CS isn't enabled, VM layer handles all code signing enforcement, including
		 * that for executable code. If VM layer isn't allowing unsigned code pages to execute, then
		 * we expect a SIGKILL error from the helper.
		 */
		if (!cs_enforcement_disabled()) {
			expected_code = 9;
		} else {
			T_LOG("WANRING: unsigned code pages are allowed as code signing enforcement is disabled");
		}
	}

#if defined(__arm64__)
	panic_on_unsigned = (int *)get_sysctl_value_byname("vm.panic_on_unsigned_execute",
	    &sysctl_val_len);
	if (panic_on_unsigned) {
		if (*panic_on_unsigned == 1) {
			panic_on_unsigned_orig = 1;
			*panic_on_unsigned = 0;
			T_EXPECT_POSIX_SUCCESS(sysctlbyname("vm.panic_on_unsigned_execute", NULL, 0, panic_on_unsigned, sizeof(int)),
			    "set sysctl vm.panic_on_unsigned_execute to 0");
			if (T_RESULT == T_RESULT_FAIL) {
				end_test = true;
				goto bail;
			}
		}
	}
#endif /* defined(__arm64__) */

bail:
	if (panic_on_unsigned) {
		free(panic_on_unsigned);
	}

	if (end_test) {
		T_END;
	}

	return;
}

static void
post_test(void)
{
#if defined(__arm64__)
	if (panic_on_unsigned_orig == 1) {
		T_EXPECT_POSIX_SUCCESS(sysctlbyname("vm.panic_on_unsigned_execute", NULL, 0, &panic_on_unsigned_orig, sizeof(int)),
		    "restore sysctl vm.panic_on_unsigned_execute to 1");
	}
#endif
	return;
}

static void
check_executable(char *exec_path)
{
	int ret = -1;
	struct stat sb;

	ret = stat(exec_path, &sb);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "check executable %s", exec_path);
	T_QUIET;
	T_ASSERT_BITS_SET(sb.st_mode, S_IXUSR, "check %s EXEC permission", exec_path);
}

T_DECL(code_signing, "testing code siging with unsigned syscall code - \
    rdar://problem/23770418", T_META_RUN_CONCURRENTLY(true),
    T_META_IGNORECRASHES(".*vm_test_code_signing_helper.*"),
    T_META_ENABLED(false) /* rdar://98779213 */, T_META_TAG_VM_NOT_ELIGIBLE)
{
	int ret = 0;
	int exit_code = 0;
	int status = 0;
	int signal = 0;
	int timeout = 30;

	pid_t child_pid = 0;
	bool wait_ret = true;

	char binary_path[MAXPATHLEN], *binary_dir = NULL;
	uint32_t path_size = sizeof(binary_path);

	ret = _NSGetExecutablePath(binary_path, &path_size);
	T_QUIET;
	T_ASSERT_EQ(ret, 0, "_NSGetExecutablePath: %s, size: %d",
	    binary_path, path_size);
	binary_dir = dirname(binary_path);
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(binary_dir, "get binary directory: %s", binary_dir);

	char *helper_binary = "vm_test_code_signing_helper";
	snprintf(binary_path, MAXPATHLEN, "%s/%s", binary_dir, helper_binary);
	check_executable(binary_path);

	char *helper_args[] = {binary_path, NULL};

	pre_test();
	T_ATEND(post_test);

	ret = dt_launch_tool(&child_pid, helper_args, false, NULL, NULL);
	T_ASSERT_EQ(ret, 0, "launch helper: %s", helper_binary);

	wait_ret = dt_waitpid(child_pid, &status, &signal, timeout);
	if (wait_ret) {
		T_LOG("helper returned: %d", status);
		exit_code = status;
	} else {
		if (signal != 0) {
			T_LOG("signal terminated helper: %d", signal);
			exit_code = signal;
		}

		if (status != 0) {
			T_LOG("helper exited: %d", status);
			exit_code = status;
		}
	}

	T_ASSERT_EQ(exit_code, expected_code, "helper exits: %d, expected: %d",
	    exit_code, expected_code);
}
