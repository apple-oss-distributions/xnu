#include <sys/sysctl.h>
#include <signal.h>
#include <mach/mach.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("zalloc"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(YES));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(basic_zone_test, "General zalloc test", T_META_TAG_VM_PREFERRED)
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_basic_test", 0), "zone_basic_test");
}

T_DECL(read_only_zone_test, "Read-only zalloc test", T_META_TAG_VM_PREFERRED)
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_ro_basic_test", 0), "zone_ro_basic_test");
}

T_DECL(zone_stress_test, "Zone stress test of edge cases", T_META_TAG_VM_PREFERRED)
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_stress_test", 0), "zone_stress_test");
}

T_DECL(zone_gc_stress_test, "stress test for zone_gc", T_META_TAG_VM_PREFERRED)
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_gc_stress_test", 10), "zone_gc_stress_test");
}

#define ZLOG_ZONE "data.kalloc.128"

T_DECL(zlog_smoke_test, "check that zlog and zone tagging function at all",
    T_META_REQUIRES_SYSCTL_NE("kern.kasan.available", 1),
    T_META_BOOTARGS_SET("-zt zlog1=" ZLOG_ZONE), T_META_TAG_VM_PREFERRED)
{
	char *cmd[] = { "/usr/local/bin/zlog", "-l", "-z", ZLOG_ZONE, NULL };
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	int status = 0;
	pid_t pid;

	pid = dt_launch_tool_pipe(cmd, false, NULL,
	    ^bool (char *d, size_t s, dt_pipe_data_handler_context_t *ctx) {
		(void)ctx;
		if (strstr(d, "active refs") && strstr(d, "operation type: ")) {
		        T_PASS("found line [%.*s]", (int)(s - 1), d);
		        dispatch_semaphore_signal(sema);
		}
		return false;
	}, ^bool (char *d, size_t s, dt_pipe_data_handler_context_t *ctx) {
		/* Forward errors to stderror for debugging */
		(void)ctx;
		fwrite(d, 1, s, stderr);
		return false;
	}, BUFFER_PATTERN_LINE, NULL);

	dt_waitpid(pid, &status, NULL, 0);
	if (WIFEXITED(status)) {
		T_LOG("waitpid for %d returned with status %d",
		    pid, WEXITSTATUS(status));
	} else {
		int sig = WTERMSIG(status);
		T_LOG("waitpid for %d killed by signal %d/%s",
		    pid, sig, sys_signame[sig]);
	}
	T_ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "zlog exited cleanly");

	/* work around rdar://84948713 */
	T_ASSERT_EQ(dispatch_semaphore_wait(sema,
	    dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)), 0L,
	    "found the line we wanted");
	dispatch_release(sema);
}

T_DECL(mach_memory_info_redacted_test, "Check that mach_memory_info_redacted always returns redacted zone info",
    T_META_TAG_VM_PREFERRED)
{
	kern_return_t kr;
	uint64_t i;
	mach_zone_name_t *name = NULL;
	unsigned int nameCnt = 0;
	mach_zone_info_t *info = NULL;
	unsigned int infoCnt = 0;
	mach_memory_info_t *wiredInfo = NULL;
	unsigned int wiredInfoCnt = 0;
	uint64_t zoneDataAggregate = 0;

	kr = mach_memory_info_redacted(mach_host_self(),
	    &name, &nameCnt, &info, &infoCnt,
	    &wiredInfo, &wiredInfoCnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_memory_info");
	T_QUIET; T_ASSERT_EQ(nameCnt, infoCnt, "zone name and info counts don't match");

	// Sanity check
	T_QUIET; T_ASSERT_GT(infoCnt, 0U, "Number of zones > 0");

	for (i = 0; i < infoCnt; i++) {
		T_QUIET; T_ASSERT_TRUE(info[i].mzi_cur_size == 0, "Zone current size correctly redacted");
		T_QUIET; T_ASSERT_TRUE(info[i].mzi_max_size == 0, "Zone max size correctly redacted");
		T_QUIET; T_ASSERT_TRUE(info[i].mzi_alloc_size == 0, "Zone alloc size correctly redacted");
		T_QUIET; T_ASSERT_TRUE(info[i].mzi_sum_size == 0, "Zone sum size correctly redacted");
		T_QUIET; T_ASSERT_TRUE(info[i].mzi_collectable == 0, "Zone collectable num correctly redacted");

		zoneDataAggregate += info[i].mzi_cur_size + info[i].mzi_max_size + info[i].mzi_alloc_size + info[i].mzi_sum_size + info[i].mzi_collectable;
	}

	T_ASSERT_TRUE(zoneDataAggregate == 0, "Zone info correctly redacted");

	// Cleanup
	if ((name != NULL) && (nameCnt != 0)) {
		kr = vm_deallocate(mach_task_self(), (vm_address_t) name,
		    (vm_size_t) (nameCnt * sizeof *name));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate name");
	}

	if ((info != NULL) && (infoCnt != 0)) {
		kr = vm_deallocate(mach_task_self(), (vm_address_t) info,
		    (vm_size_t) (infoCnt * sizeof *info));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate info");
	}

	if ((wiredInfo != NULL) && (wiredInfoCnt != 0)) {
		kr = vm_deallocate(mach_task_self(), (vm_address_t) wiredInfo,
		    (vm_size_t) (wiredInfoCnt * sizeof *wiredInfo));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate wiredInfo");
	}
}
