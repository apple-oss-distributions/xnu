#include <sys/sysctl.h>
#include <signal.h>
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

T_DECL(basic_zone_test, "General zalloc test")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_basic_test", 0), "zone_basic_test");
}

T_DECL(read_only_zone_test, "Read-only zalloc test")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_ro_basic_test", 0), "zone_ro_basic_test");
}

T_DECL(zone_stress_test, "Zone stress test of edge cases")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_stress_test", 0), "zone_stress_test");
}

T_DECL(zone_gc_stress_test, "stress test for zone_gc")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("zone_gc_stress_test", 10), "zone_gc_stress_test");
}

#define ZLOG_ZONE "data.kalloc.128"

T_DECL(zlog_smoke_test, "check that zlog functions at all",
    T_META_REQUIRES_SYSCTL_NE("kern.kasan.available", 1),
    T_META_BOOTARGS_SET("zlog1=" ZLOG_ZONE))
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
