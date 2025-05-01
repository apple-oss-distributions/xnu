#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>

#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/kern_memorystatus.h>

#include <crt_externs.h>
#include <mach-o/dyld.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <TargetConditionals.h>

#include "memorystatus_assertion_helpers.h"
#include "jumbo_va_spaces_common.h"

#define MAX_TASK_MEM "kern.max_task_pmem"

#if ENTITLED_DEBUGGING
// Keep aligned with kern_memorystatus.c:
#define MAX_TASK_MEM_ENTITLED "kern.entitled_dev_max_task_pmem"
#else
#if BINCOMPAT
#define MAX_TASK_MEM_ENTITLED "kern.entitled_bincompat_max_task_pmem"
#else // BINCOMPAT
#define MAX_TASK_MEM_ENTITLED "kern.entitled_max_task_pmem"
#endif // !BINCOMPAT
#endif // ENTITLED_DEBUGGING

#define ENTITLED_EXTRA_MEM 512

#if ENTITLED_DEBUGGING
#define TESTNAME                  entitlement_debugging_increased_memory_limit_entitled
#define SET_MEMLIMIT_TESTNAME     entitlement_debugging_increased_memory_limit_set_memlimit
#define CONVERT_MEMLIMIT_TESTNAME entitlement_debugging_increased_memory_limit_convert_memlimit_mb
#define LIMIT_WITH_SWAP_TESTNAME  entitlement_debugging_increased_memory_limit_with_swap
#define EXTRA_META
#elif ENTITLED
#if BINCOMPAT
#define TESTNAME                  entitlement_increased_memory_limit_entitled_bincompat
#define SET_MEMLIMIT_TESTNAME     entitlement_increased_memory_limit_set_memlimit_bincompat
#define CONVERT_MEMLIMIT_TESTNAME entitlement_increased_memory_limit_convert_memlimit_mb_bincompat
#define LIMIT_WITH_SWAP_TESTNAME  entitlement_increased_memory_limit_with_swap_bincompat
#else /* BINCOMPAT */
#define TESTNAME                  entitlement_increased_memory_limit_entitled
#define SET_MEMLIMIT_TESTNAME     entitlement_increased_memory_limit_set_memlimit
#define CONVERT_MEMLIMIT_TESTNAME entitlement_increased_memory_limit_convert_memlimit_mb
#define LIMIT_WITH_SWAP_TESTNAME  entitlement_increased_memory_limit_with_swap
#endif
#define EXTRA_META
#else /* ENTITLED, ENTITLED_DEBUGGING */
#define TESTNAME entitlement_increased_memory_limit_unentitled
/* rdar://133954365 */
#define EXTRA_META , T_META_ENABLED(false)
#endif /* ENTITLED */

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_TAG_VM_PREFERRED);

static int32_t old_entitled_max_task_pmem = 0;

static void
reset_old_entitled_max_task_mem(void)
{
	int ret;
	size_t size_old_entitled_max_task_pmem = sizeof(old_entitled_max_task_pmem);
	// Use sysctl to change entitled limit
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, NULL, 0, &old_entitled_max_task_pmem, size_old_entitled_max_task_pmem);
}

T_HELPER_DECL(child, "Child") {
	// Doesn't do anything. Will start suspended
	// so that its parent can check its memlimits
	// and then kill it.
	T_PASS("Child exiting");

	if (dt_64_bit_kernel()) {
#if ENTITLED || ENTITLED_DEBUGGING
		verify_jumbo_va(true);
#else /* ENTITLED || ENTITLED_DEBUGGING */
		verify_jumbo_va(false);
#endif /* ENTITLED || ENTITLED_DEBUGGING */
	}
}

static pid_t
spawn_child_with_memlimit(int32_t memlimit)
{
	posix_spawnattr_t attr;
	int ret;
	char **args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	pid_t pid;

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);
	args = (char *[]){
		testpath,
		"-n",
		"child",
		NULL
	};

	ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setflags() failed");
	ret = posix_spawnattr_setjetsam_ext(&attr,
	    0, JETSAM_PRIORITY_FOREGROUND, memlimit, memlimit);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setjetsam_ext");
	ret = posix_spawn(&pid, testpath, NULL, &attr, args, *_NSGetEnviron());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawn() failed");

	return pid;
}

static void
resume_child_and_verify_exit(pid_t pid)
{
	pid_t rc;
	bool signaled;
	int status, ret;

	// Resume the child. It should exit immediately.
	ret = kill(pid, SIGCONT);
	T_ASSERT_POSIX_SUCCESS(ret, "kill child");

	// Check child's exit code.
	while (true) {
		rc = waitpid(pid, &status, 0);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		T_ASSERT_EQ(rc, pid, "waitpid");
		signaled = WIFSIGNALED(status);
		T_ASSERT_FALSE(signaled, "Child exited cleanly");
		ret = WEXITSTATUS(status);
		T_ASSERT_EQ(ret, 0, "child exited with code 0.");
		break;
	}
}


T_DECL(TESTNAME,
    "Verify that entitled processes can allocate up to the entitled memory limit",
    T_META_CHECK_LEAKS(false) EXTRA_META)
{
	int32_t entitled_max_task_pmem = 0, max_task_pmem = 0, expected_limit;
	size_t size_entitled_max_task_pmem = sizeof(entitled_max_task_pmem);
	size_t size_old_entitled_max_task_pmem = sizeof(old_entitled_max_task_pmem);
	size_t size_max_task_pmem = sizeof(max_task_pmem);
	pid_t pid;
	memorystatus_memlimit_properties2_t mmprops;

	int ret = 0;

	// Get the unentitled limit
	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	// Use sysctl to change entitled limit
	entitled_max_task_pmem = max_task_pmem + ENTITLED_EXTRA_MEM;
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, &old_entitled_max_task_pmem, &size_old_entitled_max_task_pmem, &entitled_max_task_pmem, size_entitled_max_task_pmem);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to set entitled hardware mem size.");
	T_ATEND(reset_old_entitled_max_task_mem);

	if (max_task_pmem >= old_entitled_max_task_pmem) {
		T_SKIP("max_task_pmem (%lld) is larger than entitled value (%lld). Skipping test on this device.", max_task_pmem, old_entitled_max_task_pmem);
	}

	/*
	 * Spawn child with the normal task limit (just as launchd does for an app)
	 * The child will start suspended, so we can check its memlimit.
	 */

	pid = spawn_child_with_memlimit(max_task_pmem);
	T_ASSERT_POSIX_SUCCESS(pid, "spawn child with task limit");

	// Check its memlimt
	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
#if ENTITLED || ENTITLED_DEBUGGING
	expected_limit = entitled_max_task_pmem;
#else /* ENTITLED || ENTITLED_DEBUGGING */
	expected_limit = max_task_pmem;
#endif /* ENTITLED || ENTITLED_DEBUGGING */
	T_ASSERT_EQ(mmprops.v1.memlimit_active, expected_limit, "active limit");
	T_ASSERT_EQ(mmprops.v1.memlimit_inactive, expected_limit, "inactive limit");
	resume_child_and_verify_exit(pid);
}

#if ENTITLED || ENTITLED_DEBUGGING
T_DECL(SET_MEMLIMIT_TESTNAME,
    "set memlimit to -1 for entitled process should keep entitled limit.",
    T_META_CHECK_LEAKS(false))
{
	int ret;
	int32_t entitled_max_task_pmem = 0, max_task_pmem = 0;
	size_t size_entitled_max_task_pmem = sizeof(entitled_max_task_pmem);
	size_t size_old_entitled_max_task_pmem = sizeof(old_entitled_max_task_pmem);
	size_t size_max_task_pmem = sizeof(max_task_pmem);
	memorystatus_memlimit_properties2_t mmprops;
	pid_t pid;

	// Get the unentitled limit
	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	// Use sysctl to change entitled limit
	entitled_max_task_pmem = max_task_pmem + ENTITLED_EXTRA_MEM;
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, &old_entitled_max_task_pmem, &size_old_entitled_max_task_pmem, &entitled_max_task_pmem, size_entitled_max_task_pmem);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to set entitled hardware mem size.");
	T_ATEND(reset_old_entitled_max_task_mem);

	if (max_task_pmem >= old_entitled_max_task_pmem) {
		T_SKIP("max_task_pmem (%lld) is larger than entitled value (%lld). Skipping test on this device.", max_task_pmem, old_entitled_max_task_pmem);
	}

	pid = spawn_child_with_memlimit(-1);
	T_ASSERT_POSIX_SUCCESS(pid, "spawn child with task limit");

	// Check its memlimt
	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_ASSERT_EQ(mmprops.v1.memlimit_active, entitled_max_task_pmem, "active limit");
	T_ASSERT_EQ(mmprops.v1.memlimit_inactive, entitled_max_task_pmem, "inactive limit");

	mmprops.v1.memlimit_active = -1;
	mmprops.v1.memlimit_inactive = -1;
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops.v1, sizeof(mmprops.v1));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	// Check its memlimt
	ret = memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");

	T_ASSERT_EQ(mmprops.v1.memlimit_active, entitled_max_task_pmem, "active limit");
	T_ASSERT_EQ(mmprops.v1.memlimit_inactive, entitled_max_task_pmem, "inactive limit");

	resume_child_and_verify_exit(pid);
}

T_DECL(CONVERT_MEMLIMIT_TESTNAME,
    "convert_memlimit_mb returns entitled limit.")
{
	int ret;
	int32_t entitled_max_task_pmem = 0, max_task_pmem = 0;
	size_t size_entitled_max_task_pmem = sizeof(entitled_max_task_pmem);
	size_t size_old_entitled_max_task_pmem = sizeof(old_entitled_max_task_pmem);
	size_t size_max_task_pmem = sizeof(max_task_pmem);
	pid_t pid;

	// Get the unentitled limit
	ret = sysctlbyname(MAX_TASK_MEM, &max_task_pmem, &size_max_task_pmem, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");

	// Use sysctl to change entitled limit
	entitled_max_task_pmem = max_task_pmem + ENTITLED_EXTRA_MEM;
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, &old_entitled_max_task_pmem, &size_old_entitled_max_task_pmem, &entitled_max_task_pmem, size_entitled_max_task_pmem);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to set entitled hardware mem size.");
	T_ATEND(reset_old_entitled_max_task_mem);

	if (max_task_pmem >= old_entitled_max_task_pmem) {
		T_SKIP("max_task_pmem (%lld) is larger than entitled value (%lld). Skipping test on this device.", max_task_pmem, old_entitled_max_task_pmem);
	}

	pid = spawn_child_with_memlimit(0);
	T_ASSERT_POSIX_SUCCESS(pid, "spawn child with task limit");

	ret = memorystatus_control(MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB, pid, (uint32_t) -1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	T_QUIET; T_ASSERT_EQ(ret, entitled_max_task_pmem, "got entitled value");

	resume_child_and_verify_exit(pid);
}

T_DECL(LIMIT_WITH_SWAP_TESTNAME, "entitled memory limit equals dram size when swap is enabled.",
    T_META_ENABLED(!TARGET_OS_VISION),
    T_META_BOOTARGS_SET("kern.swap_all_apps=1"))
{
	int32_t entitled_max_task_pmem = 0;
	size_t size_entitled_max_task_pmem = sizeof(entitled_max_task_pmem);
	uint64_t memsize_physical;
	size_t size_memsize_physical = sizeof(memsize_physical);
	int ret;

	// Get the entitled limit
	ret = sysctlbyname(MAX_TASK_MEM_ENTITLED, &entitled_max_task_pmem, &size_entitled_max_task_pmem, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");
	// Get the dram size. Convert it to MB since entitled_max_task_pmem is in MB too and slight discrepancies can occur.
	ret = sysctlbyname("hw.memsize_physical", &memsize_physical, &size_memsize_physical, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory.");
	uint64_t memsize_physical_mb = (uint64_t) memsize_physical / (1ULL << 20);
	T_QUIET; T_ASSERT_EQ((uint64_t)entitled_max_task_pmem, memsize_physical_mb, "entitled limit == dram size");
}
#endif /* ENTITLED || ENTITLED_DEBUGGING */
